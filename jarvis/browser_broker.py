"""Canonical broker-backed browser application service.

``BrowserSemanticBridge`` owns observations and stale-reference checks.  This
module owns the production execution seam: every browser operation is routed
through a dedicated registered ``Tool`` and therefore through the
``ToolRegistry``'s bound ``PermissionBroker`` before the trusted backend is
called.  The backend is never exposed to model, agent, or package callers.
"""

from __future__ import annotations

import asyncio
import logging
from collections.abc import Mapping
from dataclasses import dataclass
from enum import StrEnum
from typing import Any
from urllib.parse import urlsplit
from uuid import UUID, uuid4

from pydantic import BaseModel, ConfigDict, Field

from jarvis.browser import (
    BrowserAccessDenied,
    BrowserAction,
    BrowserAdapter,
    BrowserBridgeError,
    BrowserDocument,
    BrowserPermissionGate,
    BrowserReference,
    BrowserTab,
    StaleBrowserReference,
    _origin_for_url,
)
from jarvis.credentials import CredentialVault, CredentialVaultError
from jarvis.permissions.models import (
    ActionDescriptor,
    Permission,
    PermissionRequest,
    PermissionScope,
    Risk,
    SafeArgument,
    SafetyClass,
)
from jarvis.permissions.policy import normalize_scope
from jarvis.tools.base import Tool
from jarvis.tools.models import (
    SemanticVersion,
    ToolCaller,
    ToolEffectDisposition,
    ToolExecutionContext,
    ToolHealth,
    ToolHealthStatus,
    ToolManifest,
    ToolPlatform,
    ToolResult,
    ToolResultStatus,
)
from jarvis.tools.registry import ToolRegistry


class BrowserCapabilityUnavailable(RuntimeError):
    """The configured browser backend cannot provide the declared capability."""


class BrowserCapabilityStatus(StrEnum):
    """Application-visible browser capability state."""

    AVAILABLE = "available"
    DEGRADED = "degraded"
    UNAVAILABLE = "unavailable"


class BrowserBrokerInput(BaseModel):
    """Bounded typed request crossing the trusted browser tool boundary."""

    model_config = ConfigDict(extra="forbid", strict=True)

    action: BrowserAction
    tab_id: str = Field(min_length=1, max_length=256)
    document_generation: int = Field(ge=1, le=2_147_483_647)
    origin: str = Field(min_length=1, max_length=512)
    semantic_id: str | None = Field(default=None, max_length=256)
    url: str | None = Field(default=None, max_length=4_096)
    value: str | None = Field(default=None, max_length=16_384)
    credential_ref: str | None = Field(default=None, max_length=512)
    option: str | None = Field(default=None, max_length=512)
    query: str | None = Field(default=None, max_length=512)
    state: str | None = Field(default=None, max_length=256)
    timeout_seconds: float = Field(default=10.0, ge=0.1, le=60.0)


class BrowserBrokerOutput(BaseModel):
    """Trusted in-process result; browser documents never enter model text."""

    model_config = ConfigDict(arbitrary_types_allowed=True, extra="forbid")

    document: Any


_READ_ONLY_ACTIONS = frozenset(
    {
        BrowserAction.INSPECT,
        BrowserAction.SCROLL_FIND,
        BrowserAction.WAIT_FOR_STATE,
    }
)
_PERMISSIONS: dict[BrowserAction, Permission] = {
    BrowserAction.INSPECT: Permission.SCREEN_READ,
    BrowserAction.SCROLL_FIND: Permission.SCREEN_READ,
    BrowserAction.WAIT_FOR_STATE: Permission.SCREEN_READ,
    BrowserAction.NAVIGATE: Permission.NETWORK_REQUEST,
    BrowserAction.SEMANTIC_CLICK: Permission.COMPUTER_INPUT,
    BrowserAction.FILL: Permission.COMPUTER_INPUT,
    BrowserAction.FILL_CREDENTIAL: Permission.COMPUTER_INPUT,
    BrowserAction.SELECT: Permission.COMPUTER_INPUT,
    BrowserAction.SUBMIT: Permission.COMPUTER_INPUT,
}


def _host(origin: str) -> str:
    parsed = urlsplit(origin)
    if parsed.scheme not in {"http", "https"} or parsed.hostname is None:
        raise BrowserBridgeError("Browser origin is invalid")
    try:
        return parsed.hostname.encode("idna").decode("ascii").casefold()
    except UnicodeError as error:
        raise BrowserBridgeError("Browser origin host is invalid") from error


def _safe_argument(name: str, value: str | None) -> SafeArgument:
    if name in {"value", "credential_ref"}:
        return SafeArgument(name, "[REDACTED]" if name == "value" else "[OPAQUE_VAULT_REF]")
    return SafeArgument(name, value or "")


class _BrowserOperationTool(Tool[BrowserBrokerInput, BrowserBrokerOutput]):
    """One fixed-permission tool for one browser operation family."""

    def __init__(
        self,
        action: BrowserAction,
        backend: BrowserAdapter,
        vault: CredentialVault | None,
    ) -> None:
        self._action = action
        self._backend = backend
        self._vault = vault

    @property
    def manifest(self) -> ToolManifest:
        return ToolManifest(
            tool_id=f"browser.{self._action.value}",
            name=f"Browser {self._action.value}",
            description=(
                "Read-only semantic browser observation"
                if self._action in _READ_ONLY_ACTIONS
                else "Brokered semantic browser operation"
            ),
            version=SemanticVersion(1, 0, 0),
            capability_tags=frozenset({"browser.semantic", f"browser.{self._action.value}"}),
            input_schema=BrowserBrokerInput,
            output_schema=BrowserBrokerOutput,
            declared_permissions=frozenset({_PERMISSIONS[self._action]}),
            supported_platforms=frozenset(
                {ToolPlatform.WINDOWS, ToolPlatform.LINUX, ToolPlatform.MACOS}
            ),
            timeout_seconds=30.0,
            implementation_id="jarvis.browser.broker",
        )

    @property
    def input_model(self) -> type[BrowserBrokerInput]:
        return BrowserBrokerInput

    def _describe_action(
        self,
        context: ToolExecutionContext,
        validated_input: BrowserBrokerInput,
    ) -> ActionDescriptor:
        permission = _PERMISSIONS[self._action]
        scope = normalize_scope(
            PermissionScope(
                hosts=(_host(validated_input.origin),),
                tool_id=self.manifest.tool_id,
                task_id=context.task_id,
                duration_seconds=60,
            ),
            permission,
        )
        arguments: tuple[SafeArgument, ...] = (
            _safe_argument("tab_id", validated_input.tab_id),
            _safe_argument("document_generation", str(validated_input.document_generation)),
            _safe_argument("origin", validated_input.origin),
        )
        for name in ("semantic_id", "url", "value", "credential_ref", "option", "query", "state"):
            value = getattr(validated_input, name)
            if value is not None:
                arguments += (_safe_argument(name, value),)
        if self._action is BrowserAction.WAIT_FOR_STATE:
            arguments += (_safe_argument("timeout_seconds", str(validated_input.timeout_seconds)),)
        return ActionDescriptor(
            action=f"browser.{self._action.value}",
            arguments_summary=arguments,
            risk=Risk.MEDIUM if self._action in _READ_ONLY_ACTIONS else Risk.HIGH,
            permissions=(PermissionRequest(permission, scope),),
            safety_class=SafetyClass.ORDINARY,
        )

    async def _execute_authorized(
        self,
        context: ToolExecutionContext,
        validated_input: BrowserBrokerInput,
    ) -> ToolResult:
        reference = (
            None
            if validated_input.semantic_id is None
            else BrowserReference(
                validated_input.tab_id,
                validated_input.document_generation,
                validated_input.origin,
                validated_input.semantic_id,
            )
        )
        if (
            self._action
            in {
                BrowserAction.SEMANTIC_CLICK,
                BrowserAction.FILL,
                BrowserAction.FILL_CREDENTIAL,
                BrowserAction.SELECT,
                BrowserAction.SUBMIT,
            }
            and reference is None
        ):
            raise BrowserBridgeError("Effectful browser action requires a semantic reference")
        if self._action is BrowserAction.INSPECT:
            document = await self._backend.inspect(validated_input.tab_id)
        elif self._action is BrowserAction.NAVIGATE:
            if validated_input.url is None:
                raise BrowserBridgeError("Navigation requires a URL")
            document = await self._backend.navigate(validated_input.tab_id, validated_input.url)
        elif self._action is BrowserAction.SEMANTIC_CLICK:
            assert reference is not None
            document = await self._backend.semantic_click(reference)
        elif self._action is BrowserAction.FILL:
            assert reference is not None and validated_input.value is not None
            document = await self._backend.fill(reference, validated_input.value)
        elif self._action is BrowserAction.FILL_CREDENTIAL:
            assert reference is not None and validated_input.credential_ref is not None
            if self._vault is None:
                return ToolResult.failure(
                    ToolResultStatus.UNAVAILABLE,
                    "credential_vault_unavailable",
                    "Credential-backed browser fill requires the trusted vault",
                    effect_disposition=ToolEffectDisposition.NO_EFFECT,
                )
            credential_ref = validated_input.credential_ref
            if not credential_ref.startswith("vault:"):
                return ToolResult.failure(
                    ToolResultStatus.PERMISSION_DENIED,
                    "credential_reference_invalid",
                    "Browser credential references must be opaque vault references",
                    effect_disposition=ToolEffectDisposition.NO_EFFECT,
                )
            try:
                credential_id = UUID(credential_ref.removeprefix("vault:"))
                self._vault.metadata(credential_id)
            except (ValueError, CredentialVaultError):
                return ToolResult.failure(
                    ToolResultStatus.PERMISSION_DENIED,
                    "credential_reference_invalid",
                    "Browser credential reference is unavailable",
                    effect_disposition=ToolEffectDisposition.NO_EFFECT,
                )
            document = await self._backend.fill_credential(
                reference, validated_input.credential_ref
            )
        elif self._action is BrowserAction.SELECT:
            assert reference is not None and validated_input.option is not None
            document = await self._backend.select(reference, validated_input.option)
        elif self._action is BrowserAction.SUBMIT:
            assert reference is not None
            document = await self._backend.submit(reference)
        elif self._action is BrowserAction.SCROLL_FIND:
            if validated_input.query is None:
                raise BrowserBridgeError("Browser search requires a query")
            document = await self._backend.scroll_find(
                validated_input.tab_id, validated_input.query
            )
        elif self._action is BrowserAction.WAIT_FOR_STATE:
            if validated_input.state is None:
                raise BrowserBridgeError("Browser wait requires a state")
            document = await self._backend.wait_for_state(
                validated_input.tab_id,
                validated_input.state,
                validated_input.timeout_seconds,
            )
        else:  # pragma: no cover - enum exhaustiveness guard
            raise BrowserBridgeError("Unsupported browser action")
        if type(document) is not BrowserDocument:
            raise BrowserBridgeError("Browser adapter returned an invalid document")
        return ToolResult.success(BrowserBrokerOutput(document=document))

    async def health_check(self) -> ToolHealth:
        probe = getattr(self._backend, "health_check", None)
        if not callable(probe):
            return ToolHealth(ToolHealthStatus.AVAILABLE, "Configured browser backend")
        try:
            result = probe()
            if asyncio.iscoroutine(result):
                result = await result
            if result is False:
                return ToolHealth(ToolHealthStatus.UNAVAILABLE, "Browser backend unavailable")
        except Exception:
            return ToolHealth(ToolHealthStatus.UNAVAILABLE, "Browser backend health check failed")
        return ToolHealth(ToolHealthStatus.AVAILABLE, "Configured browser backend")


@dataclass(frozen=True, slots=True)
class BrowserBrokerAdapter(BrowserAdapter, BrowserPermissionGate):
    """Application-owned BrowserAdapter backed by registered brokered tools."""

    _registry: ToolRegistry
    _task_id: UUID
    _tools: Mapping[BrowserAction, _BrowserOperationTool]
    _tabs: dict[str, BrowserTab]

    def __init__(
        self,
        backend: BrowserAdapter,
        registry: ToolRegistry,
        *,
        task_id: UUID | None = None,
        vault: CredentialVault | None = None,
    ) -> None:
        if not isinstance(registry, ToolRegistry):
            raise TypeError("Browser broker adapter requires the canonical ToolRegistry")
        if backend is self or not all(
            callable(getattr(backend, name, None))
            for name in (
                "inspect",
                "navigate",
                "semantic_click",
                "fill",
                "fill_credential",
                "select",
                "submit",
                "scroll_find",
                "wait_for_state",
            )
        ):
            raise BrowserCapabilityUnavailable("Configured browser backend is unsupported")
        tools = {action: _BrowserOperationTool(action, backend, vault) for action in BrowserAction}
        for tool in tools.values():
            registry.register(tool)
        object.__setattr__(self, "_registry", registry)
        object.__setattr__(self, "_task_id", task_id or uuid4())
        object.__setattr__(self, "_tools", tools)
        object.__setattr__(self, "_tabs", {})

    async def authorize(
        self,
        *,
        action: BrowserAction,
        tab: BrowserTab,
        origin: str,
        target: BrowserReference | None,
        arguments: Mapping[str, str],
    ) -> None:
        """Validate bridge metadata; the subsequent tool call performs auth."""

        if not isinstance(action, BrowserAction) or type(tab) is not BrowserTab:
            raise BrowserAccessDenied("Browser request metadata is malformed")
        try:
            _origin_for_url(f"{origin}/")
        except BrowserBridgeError as error:
            raise BrowserAccessDenied("Browser request origin is invalid") from error
        if target is not None and (
            target.tab_id != tab.tab_id
            or target.origin != tab.origin
            or target.document_generation != tab.document_generation
        ):
            raise StaleBrowserReference("Browser target reference is stale")
        self._tabs[tab.tab_id] = tab
        if type(arguments) is not dict and not isinstance(arguments, Mapping):
            raise BrowserAccessDenied("Browser arguments are malformed")
        if action not in self._tools:
            raise BrowserCapabilityUnavailable("Browser action is unavailable")

    async def _invoke(
        self,
        action: BrowserAction,
        values: Mapping[str, object],
    ) -> BrowserDocument:
        tool = self._tools.get(action)
        if tool is None:
            raise BrowserCapabilityUnavailable("Browser action is unavailable")
        raw = {"action": action, **dict(values)}
        context = ToolExecutionContext(
            task_id=self._task_id,
            correlation_id=uuid4(),
            caller=ToolCaller.USER_INTERFACE,
            cancellation=asyncio.Event(),
            logger=logging.getLogger("jarvis.browser"),
        )
        result = await tool.invoke(context, raw, self._registry.permission_broker)
        if result.status is ToolResultStatus.UNAVAILABLE:
            raise BrowserCapabilityUnavailable("Browser backend is unavailable")
        if result.status is ToolResultStatus.PERMISSION_DENIED:
            raise BrowserAccessDenied("Browser permission was denied or requires approval")
        if not result.succeeded or not isinstance(result.output, BrowserBrokerOutput):
            raise BrowserBridgeError("Browser operation failed closed")
        document = result.output.document
        if type(document) is not BrowserDocument:
            raise BrowserBridgeError("Browser operation returned invalid state")
        return document

    async def inspect(self, tab_id: str) -> BrowserDocument:
        tab = self._tab(tab_id)
        return await self._invoke(
            BrowserAction.INSPECT,
            {
                "tab_id": tab_id,
                "document_generation": tab.document_generation,
                "origin": tab.origin,
            },
        )

    async def navigate(self, tab_id: str, url: str) -> BrowserDocument:
        tab = self._tab(tab_id)
        return await self._invoke(
            BrowserAction.NAVIGATE,
            {
                "tab_id": tab_id,
                "document_generation": tab.document_generation,
                "origin": _origin_for_url(url),
                "url": url,
            },
        )

    async def semantic_click(self, reference: BrowserReference) -> BrowserDocument:
        return await self._invoke(BrowserAction.SEMANTIC_CLICK, _reference_values(reference))

    async def fill(self, reference: BrowserReference, value: str) -> BrowserDocument:
        return await self._invoke(
            BrowserAction.FILL, {**_reference_values(reference), "value": value}
        )

    async def fill_credential(
        self, reference: BrowserReference, credential_ref: str
    ) -> BrowserDocument:
        return await self._invoke(
            BrowserAction.FILL_CREDENTIAL,
            {**_reference_values(reference), "credential_ref": credential_ref},
        )

    async def select(self, reference: BrowserReference, option: str) -> BrowserDocument:
        return await self._invoke(
            BrowserAction.SELECT, {**_reference_values(reference), "option": option}
        )

    async def submit(self, reference: BrowserReference) -> BrowserDocument:
        return await self._invoke(BrowserAction.SUBMIT, _reference_values(reference))

    async def scroll_find(self, tab_id: str, query: str) -> BrowserDocument:
        tab = self._tab(tab_id)
        return await self._invoke(
            BrowserAction.SCROLL_FIND,
            {
                "tab_id": tab_id,
                "document_generation": tab.document_generation,
                "origin": tab.origin,
                "query": query,
            },
        )

    async def wait_for_state(
        self, tab_id: str, state: str, timeout_seconds: float
    ) -> BrowserDocument:
        tab = self._tab(tab_id)
        return await self._invoke(
            BrowserAction.WAIT_FOR_STATE,
            {
                "tab_id": tab_id,
                "document_generation": tab.document_generation,
                "origin": tab.origin,
                "state": state,
                "timeout_seconds": timeout_seconds,
            },
        )

    async def health_check(self) -> ToolHealth:
        """Return the trusted backend health without dispatching a browser action."""

        return await self._tools[BrowserAction.INSPECT].health_check()

    def _tab(self, tab_id: str) -> BrowserTab:
        try:
            return self._tabs[tab_id]
        except KeyError as error:
            raise BrowserCapabilityUnavailable(
                "Browser operation requires a bridge-bound tab"
            ) from error


def _reference_values(reference: BrowserReference) -> dict[str, object]:
    return {
        "tab_id": reference.tab_id,
        "document_generation": reference.document_generation,
        "origin": reference.origin,
        "semantic_id": reference.semantic_id,
    }


__all__ = [
    "BrowserBrokerAdapter",
    "BrowserBrokerInput",
    "BrowserCapabilityStatus",
    "BrowserCapabilityUnavailable",
]
