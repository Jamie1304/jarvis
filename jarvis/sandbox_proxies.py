"""Narrow trusted host proxies for untrusted integration sandboxes.

The sandbox process never receives a broker, vault, policy object, filesystem
handle, or process launcher.  It submits typed requests to a trusted host-side
proxy.  The proxy validates the immutable package binding, declared capability,
and operation scope before obtaining a normal PermissionBroker receipt.
"""

from __future__ import annotations

import contextlib
import ipaddress
import json
import socket
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass, field
from enum import StrEnum
from pathlib import Path
from typing import Protocol
from urllib.parse import SplitResult, urljoin, urlsplit
from uuid import UUID

import httpx

from jarvis.credentials import CredentialVault, CredentialVaultError
from jarvis.permissions.broker import PermissionBroker
from jarvis.permissions.models import (
    ActionDescriptor,
    AuthorizationReceipt,
    DecisionReason,
    Permission,
    PermissionRequest,
    PermissionScope,
    Risk,
    SafeArgument,
)


class HostProxyError(RuntimeError):
    """Base class for trusted host proxy failures."""


class HostProxyDenied(HostProxyError):
    """A request did not satisfy a trusted boundary or policy."""


class HostProxyApprovalRequired(HostProxyDenied):
    """The broker paused the operation for trusted user approval."""

    def __init__(self, reason: DecisionReason, approvals: object) -> None:
        super().__init__(reason.value)
        self.reason = reason
        self.approvals = approvals


class HostProxyBoundExceeded(HostProxyError):
    """A request or response exceeded its declared bound."""


class HostProxyEffectUnknown(HostProxyError):
    """The host operation may have reached an external effect."""


class ProxyKind(StrEnum):
    NETWORK = "network"
    FILESYSTEM = "filesystem"
    PROCESS = "process"
    DEVICE = "device"


class FilesystemRootKind(StrEnum):
    PACKAGE_DATA = "package_data"
    APPROVED_USER = "approved_user"


class CredentialLocation(StrEnum):
    BEARER = "bearer"
    HEADER = "header"


_MAX_HEADERS = 64
_MAX_HEADER_BYTES = 16_384
_MAX_BODY_BYTES = 1_048_576
_MAX_ACTION_PAYLOAD_BYTES = 65_536
_FORBIDDEN_REQUEST_HEADERS = frozenset(
    {"authorization", "cookie", "host", "proxy-authorization", "set-cookie"}
)
_FORBIDDEN_PATH_COMPONENTS = frozenset({".git", ".hg", ".svn", "trusted_core"})


def _text(value: object, field: str, limit: int = 256) -> str:
    if (
        type(value) is not str
        or not value
        or len(value) > limit
        or "\x00" in value
        or any(ord(character) < 32 for character in value)
    ):
        raise HostProxyError(f"{field} is malformed")
    return value


def _identifier(value: object, field: str) -> str:
    value = _text(value, field, 128)
    if any(character not in "abcdefghijklmnopqrstuvwxyz0123456789._-" for character in value):
        raise HostProxyError(f"{field} is malformed")
    return value


def _sha256(value: object, field: str) -> str:
    value = _text(value, field, 64)
    if len(value) != 64 or any(character not in "0123456789abcdef" for character in value):
        raise HostProxyError(f"{field} is malformed")
    return value


def _json_value(value: object, *, depth: int = 0) -> object:
    if depth > 16:
        raise HostProxyBoundExceeded("Typed action payload is too deeply nested")
    if value is None or type(value) is bool or type(value) is int or type(value) is str:
        if type(value) is str and len(value) > _MAX_ACTION_PAYLOAD_BYTES:
            raise HostProxyBoundExceeded("Typed action payload is too large")
        return value
    if type(value) is float:
        if not value == value or value in {float("inf"), float("-inf")}:
            raise HostProxyError("Typed action payload contains an invalid number")
        return value
    if isinstance(value, Sequence) and not isinstance(value, str | bytes | bytearray):
        if len(value) > 256:
            raise HostProxyBoundExceeded("Typed action payload list is too large")
        return [_json_value(item, depth=depth + 1) for item in value]
    if isinstance(value, Mapping):
        if len(value) > 256:
            raise HostProxyBoundExceeded("Typed action payload object is too large")
        result: dict[str, object] = {}
        for key, item in value.items():
            _text(key, "Typed action payload key", 128)
            result[key] = _json_value(item, depth=depth + 1)
        encoded = json.dumps(result, ensure_ascii=False, separators=(",", ":"))
        if len(encoded.encode("utf-8")) > _MAX_ACTION_PAYLOAD_BYTES:
            raise HostProxyBoundExceeded("Typed action payload is too large")
        return result
    raise HostProxyError("Typed action payload is not JSON")


def _origin(url: str) -> tuple[str, SplitResult]:
    try:
        parsed = urlsplit(url)
        host = parsed.hostname
        port = parsed.port
    except ValueError as error:
        raise HostProxyDenied("Network URL is malformed") from error
    if (
        parsed.scheme not in {"http", "https"}
        or host is None
        or parsed.username is not None
        or parsed.password is not None
        or parsed.fragment
        or any(ord(character) < 32 for character in url)
    ):
        raise HostProxyDenied("Network URL is not an allowed origin URL")
    host = host.casefold().rstrip(".")
    if not host or "*" in host:
        raise HostProxyDenied("Network host is invalid")
    if port is None:
        port = 443 if parsed.scheme == "https" else 80
    normalized = f"{parsed.scheme}://{host}:{port}"
    return normalized, parsed


def _path_text(relative_path: str) -> tuple[str, ...]:
    relative_path = _text(relative_path, "Relative path", 1_024)
    if (
        relative_path.startswith(("/", "\\"))
        or ":" in relative_path
        or "\\" in relative_path
        or relative_path.endswith(("/", "\\"))
    ):
        raise HostProxyDenied("Filesystem path must be a portable relative path")
    parts = tuple(relative_path.split("/"))
    if any(not part or part in {".", ".."} for part in parts):
        raise HostProxyDenied("Filesystem traversal is denied")
    if any(part.casefold() in _FORBIDDEN_PATH_COMPONENTS for part in parts):
        raise HostProxyDenied("Protected filesystem path is denied")
    return parts


@dataclass(frozen=True, slots=True)
class ProxyCapability:
    capability_id: str
    kind: ProxyKind
    actions: tuple[str, ...]
    permission: Permission
    input_fields: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        _identifier(self.capability_id, "Capability ID")
        if not isinstance(self.kind, ProxyKind) or not isinstance(self.permission, Permission):
            raise HostProxyError("Capability declaration is malformed")
        if (
            not self.actions
            or len(set(self.actions)) != len(self.actions)
            or any(not _identifier(item, "Capability action") for item in self.actions)
            or len(set(self.input_fields)) != len(self.input_fields)
            or any(not _identifier(item, "Capability input field") for item in self.input_fields)
        ):
            raise HostProxyError("Capability declaration is malformed")


@dataclass(frozen=True, slots=True)
class FilesystemRoot:
    root_id: str
    path: Path
    kind: FilesystemRootKind
    writable: bool = False

    def __post_init__(self) -> None:
        _identifier(self.root_id, "Filesystem root ID")
        if not isinstance(self.path, Path) or not self.path.is_absolute():
            raise HostProxyError("Filesystem root must be absolute")
        if not isinstance(self.kind, FilesystemRootKind) or type(self.writable) is not bool:
            raise HostProxyError("Filesystem root declaration is malformed")
        if not self.path.is_dir() or _has_reparse(self.path):
            raise HostProxyError("Filesystem root must be an existing regular directory")


@dataclass(frozen=True, slots=True)
class CredentialBinding:
    binding_id: str
    association: str
    location: CredentialLocation
    allowed_scope: tuple[str, ...] = ()
    header_name: str | None = None

    def __post_init__(self) -> None:
        _identifier(self.binding_id, "Credential binding ID")
        _text(self.association, "Credential association")
        if not isinstance(self.location, CredentialLocation):
            raise HostProxyError("Credential location is malformed")
        if any(not _text(item, "Credential scope", 256) for item in self.allowed_scope):
            raise HostProxyError("Credential scope is malformed")
        if self.location is CredentialLocation.HEADER:
            if self.header_name is None or not self.header_name.strip():
                raise HostProxyError("Credential header name is required")
            _header_name(self.header_name)
        elif self.header_name is not None:
            raise HostProxyError("Bearer credentials cannot declare a header name")


@dataclass(frozen=True, slots=True)
class HostProxyManifest:
    integration_id: str
    package_version: str
    package_hash: str
    capabilities: tuple[ProxyCapability, ...]
    network_origins: tuple[str, ...] = ()
    filesystem_roots: tuple[FilesystemRoot, ...] = ()
    credential_bindings: tuple[CredentialBinding, ...] = ()
    allow_redirects: bool = False
    allow_private_addresses: bool = False
    timeout_seconds: float = 10.0
    max_response_bytes: int = 1_048_576
    max_redirects: int = 3

    def __post_init__(self) -> None:
        _identifier(self.integration_id, "Integration identity")
        _text(self.package_version, "Package version", 64)
        _sha256(self.package_hash, "Package hash")
        if (
            not self.capabilities
            or len({item.capability_id for item in self.capabilities}) != len(self.capabilities)
            or any(type(item) is not ProxyCapability for item in self.capabilities)
        ):
            raise HostProxyError("Manifest capabilities are malformed")
        normalized_origins = tuple(_origin(item)[0] for item in self.network_origins)
        if len(set(normalized_origins)) != len(normalized_origins):
            raise HostProxyError("Manifest network origins must be unique")
        if len({item.root_id for item in self.filesystem_roots}) != len(self.filesystem_roots):
            raise HostProxyError("Manifest filesystem roots must be unique")
        if len({item.binding_id for item in self.credential_bindings}) != len(
            self.credential_bindings
        ):
            raise HostProxyError("Manifest credential bindings must be unique")
        if (
            type(self.allow_redirects) is not bool
            or type(self.allow_private_addresses) is not bool
            or isinstance(self.timeout_seconds, bool)
            or not 0 < self.timeout_seconds <= 60
            or not isinstance(self.max_response_bytes, int)
            or not 1 <= self.max_response_bytes <= _MAX_BODY_BYTES
            or not isinstance(self.max_redirects, int)
            or not 0 <= self.max_redirects <= 5
        ):
            raise HostProxyError("Manifest host proxy bounds are malformed")

    def capability(self, capability_id: str, action: str, kind: ProxyKind) -> ProxyCapability:
        for capability in self.capabilities:
            if (
                capability.capability_id == capability_id
                and capability.kind is kind
                and action in capability.actions
            ):
                return capability
        raise HostProxyDenied("Capability or action is not declared")

    def origin_allowed(self, url: str) -> tuple[str, SplitResult]:
        normalized, parsed = _origin(url)
        if normalized not in {_origin(item)[0] for item in self.network_origins}:
            raise HostProxyDenied("Network origin is not declared")
        return normalized, parsed


@dataclass(frozen=True, slots=True)
class HostProxyRequest:
    request_id: UUID
    integration_id: str
    manifest_hash: str
    capability_id: str
    action: str
    task_id: UUID
    user_id: str | None = None

    def __post_init__(self) -> None:
        if not isinstance(self.request_id, UUID) or not isinstance(self.task_id, UUID):
            raise HostProxyDenied("Host proxy request identity is malformed")
        _identifier(self.integration_id, "Request integration identity")
        _sha256(self.manifest_hash, "Request manifest hash")
        _identifier(self.capability_id, "Request capability ID")
        _identifier(self.action, "Request action")
        if self.user_id is not None:
            _text(self.user_id, "Request user identity", 256)


@dataclass(frozen=True, slots=True)
class NetworkRequest:
    context: HostProxyRequest
    method: str
    url: str
    headers: Mapping[str, str] = field(default_factory=dict)
    body: bytes = b""
    credential_ref: UUID | None = None
    credential_binding_id: str | None = None
    credential_scope: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        if type(self.method) is not str or self.method.upper() not in {
            "GET",
            "HEAD",
            "POST",
            "PUT",
            "PATCH",
            "DELETE",
        }:
            raise HostProxyDenied("Network method is not allowed")
        _text(self.url, "Network URL", 8_192)
        if not isinstance(self.headers, Mapping) or len(self.headers) > _MAX_HEADERS:
            raise HostProxyBoundExceeded("Network headers are too large")
        for name, value in self.headers.items():
            _header_name(name)
            _text(value, "Network header value", 4_096)
            if name.casefold() in _FORBIDDEN_REQUEST_HEADERS:
                raise HostProxyDenied("Caller cannot supply protected network headers")
        if not isinstance(self.body, bytes) or len(self.body) > _MAX_BODY_BYTES:
            raise HostProxyBoundExceeded("Network request body is too large")
        if self.credential_ref is not None and not isinstance(self.credential_ref, UUID):
            raise HostProxyDenied("Credential reference is malformed")
        if self.credential_ref is None and (
            self.credential_binding_id is not None or self.credential_scope
        ):
            raise HostProxyDenied("Credential scope requires an opaque credential reference")
        if self.credential_binding_id is not None:
            _identifier(self.credential_binding_id, "Credential binding ID")
        if any(not _text(item, "Credential scope", 256) for item in self.credential_scope):
            raise HostProxyDenied("Credential scope is malformed")


@dataclass(frozen=True, slots=True)
class NetworkResponse:
    status_code: int
    url: str
    headers: tuple[tuple[str, str], ...]
    body: bytes


@dataclass(frozen=True, slots=True)
class FileReadRequest:
    context: HostProxyRequest
    root_id: str
    relative_path: str


@dataclass(frozen=True, slots=True)
class FileWriteRequest:
    context: HostProxyRequest
    root_id: str
    relative_path: str
    content: bytes


@dataclass(frozen=True, slots=True)
class FileListRequest:
    context: HostProxyRequest
    root_id: str
    relative_path: str = ""


@dataclass(frozen=True, slots=True)
class FileEntry:
    name: str
    directory: bool
    size: int


@dataclass(frozen=True, slots=True)
class TypedActionRequest:
    context: HostProxyRequest
    payload: Mapping[str, object]


class TypedActionExecutor(Protocol):
    async def __call__(
        self, action: str, payload: Mapping[str, object]
    ) -> Mapping[str, object]: ...


@dataclass(frozen=True, slots=True)
class HostProxyAuditEvent:
    request_id: UUID
    integration_id: str
    capability_id: str
    action: str
    task_id: UUID
    outcome: str
    scope: str


class HostProxyAudit(Protocol):
    async def record(self, event: HostProxyAuditEvent) -> None: ...


class InMemoryHostProxyAudit:
    """Test/reference adapter; production should forward to the authoritative audit service."""

    def __init__(self) -> None:
        self.events: list[HostProxyAuditEvent] = []

    async def record(self, event: HostProxyAuditEvent) -> None:
        self.events.append(event)


class HostProxy:
    """Trusted host-side facade shared by the typed proxy families."""

    def __init__(
        self,
        manifest: HostProxyManifest,
        broker: PermissionBroker,
        *,
        vault: CredentialVault | None = None,
        audit: HostProxyAudit | None = None,
        http_client: httpx.AsyncClient | None = None,
        resolver: Callable[[str], Sequence[str]] | None = None,
        forbidden_roots: Sequence[Path] = (),
    ) -> None:
        if type(manifest) is not HostProxyManifest or not isinstance(broker, PermissionBroker):
            raise HostProxyError("Host proxy composition is malformed")
        self.manifest = manifest
        self._broker = broker
        self._vault = vault
        self._audit = audit
        self._http = http_client
        self._owns_http = http_client is None
        self._resolver = resolver or _resolve_addresses
        self._forbidden_roots = tuple(_regular_root(item) for item in forbidden_roots)
        self._tools: dict[str, tuple[str, object]] = {}
        for capability in manifest.capabilities:
            tool_id = f"sandbox.{manifest.integration_id}.{capability.capability_id}"
            identity = object()
            self._broker.register_tool(tool_id, identity, frozenset({capability.permission}))
            self._tools[capability.capability_id] = (tool_id, identity)

    async def close(self) -> None:
        if self._owns_http and self._http is not None:
            await self._http.aclose()
            self._http = None
        with contextlib.suppress(RuntimeError):
            for tool_id, identity in self._tools.values():
                self._broker.unregister_tool(tool_id, identity)

    async def network(self, request: NetworkRequest) -> NetworkResponse:
        capability = self._validate_context(request.context, ProxyKind.NETWORK)
        normalized, parsed = self.manifest.origin_allowed(request.url)
        await self._validate_network_address(request.url)
        headers = dict(request.headers)
        await self._attach_credential(request, capability, headers)
        descriptor = self._descriptor(
            request.context,
            capability,
            PermissionScope(hosts=(parsed.hostname or "",)),
            (SafeArgument("method", request.method.upper()), SafeArgument("origin", normalized)),
        )
        _, receipt = await self._authorize(request.context, descriptor, {"origin": normalized})
        try:
            response = await self._network_request(request, headers)
        except httpx.HTTPError as error:
            await self._finish(receipt, "unknown_outcome")
            raise HostProxyEffectUnknown("Network outcome is unknown") from error
        except Exception:
            await self._finish(receipt, "pre_effect_failure")
            raise
        await self._finish(receipt, "effect_confirmed")
        await self._record(request.context, "effect_confirmed", normalized)
        return response

    async def read_file(self, request: FileReadRequest) -> bytes:
        capability = self._validate_context(request.context, ProxyKind.FILESYSTEM)
        path, scope = self._safe_path(request.root_id, request.relative_path, write=False)
        descriptor = self._descriptor(
            request.context,
            capability,
            PermissionScope(paths=(scope,)),
            (SafeArgument("root", request.root_id), SafeArgument("path", request.relative_path)),
        )
        _, receipt = await self._authorize(request.context, descriptor, {"path": scope})
        try:
            size = path.stat().st_size
            if size > self.manifest.max_response_bytes:
                raise HostProxyBoundExceeded("Filesystem response is too large")
            with path.open("rb") as stream:
                content = stream.read(self.manifest.max_response_bytes + 1)
            if len(content) > self.manifest.max_response_bytes:
                raise HostProxyBoundExceeded("Filesystem response is too large")
        except HostProxyBoundExceeded:
            await self._finish(receipt, "pre_effect_failure")
            raise
        except OSError as error:
            await self._finish(receipt, "pre_effect_failure")
            raise HostProxyError("Filesystem read failed") from error
        await self._finish(receipt, "effect_confirmed")
        await self._record(request.context, "effect_confirmed", scope)
        return content

    async def write_file(self, request: FileWriteRequest) -> None:
        capability = self._validate_context(request.context, ProxyKind.FILESYSTEM)
        if len(request.content) > self.manifest.max_response_bytes:
            raise HostProxyBoundExceeded("Filesystem write is too large")
        path, scope = self._safe_path(request.root_id, request.relative_path, write=True)
        descriptor = self._descriptor(
            request.context,
            capability,
            PermissionScope(paths=(scope,)),
            (SafeArgument("root", request.root_id), SafeArgument("path", request.relative_path)),
        )
        _, receipt = await self._authorize(request.context, descriptor, {"path": scope})
        try:
            path.parent.mkdir(parents=True, exist_ok=True)
            with path.open("xb") as stream:
                stream.write(request.content)
        except FileExistsError as error:
            await self._finish(receipt, "pre_effect_failure")
            raise HostProxyDenied("Trusted host proxy will not overwrite a file") from error
        except OSError as error:
            await self._finish(receipt, "pre_effect_failure")
            raise HostProxyError("Filesystem write failed") from error
        await self._finish(receipt, "effect_confirmed")
        await self._record(request.context, "effect_confirmed", scope)

    async def list_files(self, request: FileListRequest) -> tuple[FileEntry, ...]:
        capability = self._validate_context(request.context, ProxyKind.FILESYSTEM)
        path, scope = self._safe_path(
            request.root_id, request.relative_path, write=False, allow_empty=True
        )
        descriptor = self._descriptor(
            request.context,
            capability,
            PermissionScope(paths=(scope,)),
            (
                SafeArgument("root", request.root_id),
                SafeArgument("path", request.relative_path or "."),
            ),
        )
        _, receipt = await self._authorize(request.context, descriptor, {"path": scope})
        try:
            entries = []
            for child in path.iterdir():
                if _has_reparse(child) or child.name.casefold() in _FORBIDDEN_PATH_COMPONENTS:
                    continue
                entries.append(FileEntry(child.name, child.is_dir(), child.stat().st_size))
            if len(entries) > 1_024:
                raise HostProxyBoundExceeded("Filesystem listing is too large")
        except HostProxyBoundExceeded:
            await self._finish(receipt, "pre_effect_failure")
            raise
        except OSError as error:
            await self._finish(receipt, "pre_effect_failure")
            raise HostProxyError("Filesystem listing failed") from error
        await self._finish(receipt, "effect_confirmed")
        await self._record(request.context, "effect_confirmed", scope)
        return tuple(sorted(entries, key=lambda item: item.name.casefold()))

    async def invoke_typed(
        self,
        request: TypedActionRequest,
        *,
        kind: ProxyKind,
        executor: TypedActionExecutor,
    ) -> Mapping[str, object]:
        if kind not in {ProxyKind.PROCESS, ProxyKind.DEVICE}:
            raise HostProxyDenied("Only process and device typed actions use this endpoint")
        capability = self._validate_context(request.context, kind)
        payload = _json_value(request.payload)
        if not isinstance(payload, dict) or set(payload) - set(capability.input_fields):
            raise HostProxyDenied("Typed action payload is outside its declared schema")
        if kind is ProxyKind.PROCESS and any(
            key.casefold() in {"executable", "argv", "command", "shell", "cwd"} for key in payload
        ):
            raise HostProxyDenied("Arbitrary process spawning is not a host proxy action")
        descriptor = self._descriptor(
            request.context,
            capability,
            PermissionScope(applications=(capability.capability_id,)),
            (SafeArgument("capability", capability.capability_id),),
        )
        _, receipt = await self._authorize(
            request.context,
            descriptor,
            {"capability": capability.capability_id, "payload_keys": sorted(payload)},
        )
        try:
            result = await executor(request.context.action, payload)
            bounded = _json_value(result)
            if not isinstance(bounded, dict):
                raise HostProxyError("Typed action result must be an object")
        except HostProxyError:
            await self._finish(receipt, "pre_effect_failure")
            raise
        except Exception as error:
            await self._finish(receipt, "unknown_outcome")
            raise HostProxyEffectUnknown("Typed action outcome is unknown") from error
        await self._finish(receipt, "effect_confirmed")
        await self._record(request.context, "effect_confirmed", capability.capability_id)
        return bounded

    def _validate_context(self, request: HostProxyRequest, kind: ProxyKind) -> ProxyCapability:
        if type(request) is not HostProxyRequest:
            raise HostProxyDenied("Host proxy request type is not trusted")
        if request.integration_id != self.manifest.integration_id:
            raise HostProxyDenied("Integration identity does not match the trusted process")
        if request.manifest_hash != self.manifest.package_hash:
            raise HostProxyDenied("Package manifest binding does not match")
        return self.manifest.capability(request.capability_id, request.action, kind)

    def _descriptor(
        self,
        request: HostProxyRequest,
        capability: ProxyCapability,
        scope: PermissionScope,
        summary: tuple[SafeArgument, ...],
    ) -> ActionDescriptor:
        return ActionDescriptor(
            f"sandbox.{capability.kind.value}.{request.action}",
            summary,
            Risk.MEDIUM,
            (PermissionRequest(capability.permission, scope),),
        )

    async def _authorize(
        self,
        request: HostProxyRequest,
        descriptor: ActionDescriptor,
        normalized_arguments: Mapping[str, object],
    ) -> tuple[object, AuthorizationReceipt]:
        capability = next(
            (
                item
                for item in self.manifest.capabilities
                if item.capability_id == request.capability_id
            ),
            None,
        )
        if capability is None:
            raise HostProxyDenied("Capability is not registered")
        tool_id, identity = self._tools[capability.capability_id]
        result = await self._broker.authorize(
            tool_id=tool_id,
            tool_identity=identity,
            declared_permissions=frozenset({capability.permission}),
            task_id=request.task_id,
            user_id=request.user_id,
            descriptor=descriptor,
            normalized_arguments=normalized_arguments,
        )
        if not result.authorized or result.receipt is None:
            if result.approval_requests:
                raise HostProxyApprovalRequired(result.reason, result.approval_requests)
            raise HostProxyDenied(result.reason.value)
        begin_reason = await self._broker.begin_execution(result.receipt)
        if begin_reason is not None:
            raise HostProxyDenied(begin_reason.value)
        await self._record(request, "authorized", descriptor.action)
        return result, result.receipt

    async def _finish(self, receipt: AuthorizationReceipt, outcome: str) -> None:
        await self._broker.record_execution_outcome(receipt, outcome)

    async def _record(self, request: HostProxyRequest, outcome: str, scope: str) -> None:
        if self._audit is not None:
            await self._audit.record(
                HostProxyAuditEvent(
                    request.request_id,
                    request.integration_id,
                    request.capability_id,
                    request.action,
                    request.task_id,
                    outcome,
                    scope,
                )
            )

    async def _validate_network_address(self, url: str) -> None:
        _, parsed = self.manifest.origin_allowed(url)
        host = parsed.hostname
        if host is None or self.manifest.allow_private_addresses:
            return
        addresses = _literal_addresses(host)
        if addresses is None:
            try:
                addresses = tuple(self._resolver(host))
            except OSError as error:
                raise HostProxyDenied("Network host could not be resolved safely") from error
        for address in addresses:
            try:
                parsed_address = ipaddress.ip_address(address)
            except ValueError as error:
                raise HostProxyDenied("Network resolver returned an invalid address") from error
            if (
                parsed_address.is_private
                or parsed_address.is_loopback
                or parsed_address.is_link_local
                or parsed_address.is_reserved
                or parsed_address.is_multicast
                or parsed_address.is_unspecified
            ):
                raise HostProxyDenied("Private or special network address is denied")

    async def _network_request(
        self, request: NetworkRequest, headers: Mapping[str, str]
    ) -> NetworkResponse:
        client = self._http
        if client is None:
            client = httpx.AsyncClient(
                timeout=httpx.Timeout(self.manifest.timeout_seconds),
                follow_redirects=False,
                trust_env=False,
                limits=httpx.Limits(max_connections=4, max_keepalive_connections=2),
            )
            self._http = client
        current_url = request.url
        method = request.method.upper()
        for redirect_count in range(self.manifest.max_redirects + 1):
            self.manifest.origin_allowed(current_url)
            await self._validate_network_address(current_url)
            async with client.stream(
                method, current_url, headers=headers, content=request.body
            ) as response:
                if 300 <= response.status_code < 400 and response.headers.get("location"):
                    if (
                        not self.manifest.allow_redirects
                        or redirect_count >= self.manifest.max_redirects
                    ):
                        raise HostProxyDenied("Network redirect is not allowed")
                    current_url = urljoin(current_url, response.headers["location"])
                    continue
                body = bytearray()
                async for chunk in response.aiter_bytes():
                    body.extend(chunk)
                    if len(body) > self.manifest.max_response_bytes:
                        raise HostProxyBoundExceeded("Network response is too large")
                safe_headers = []
                header_bytes = 0
                for name, value in response.headers.multi_items():
                    _header_name(name)
                    _text(value, "Network response header", 4_096)
                    header_bytes += len(name) + len(value)
                    if header_bytes > _MAX_HEADER_BYTES:
                        raise HostProxyBoundExceeded("Network response headers are too large")
                    safe_headers.append((name, value))
                return NetworkResponse(
                    response.status_code, str(response.url), tuple(safe_headers), bytes(body)
                )
        raise HostProxyDenied("Network redirect limit exceeded")

    async def _attach_credential(
        self,
        request: NetworkRequest,
        capability: ProxyCapability,
        headers: dict[str, str],
    ) -> None:
        if request.credential_ref is None:
            return
        if self._vault is None or request.credential_binding_id is None:
            raise HostProxyDenied("Credential use requires a trusted vault binding")
        binding = next(
            (
                item
                for item in self.manifest.credential_bindings
                if item.binding_id == request.credential_binding_id
            ),
            None,
        )
        if binding is None or capability.permission is not Permission.NETWORK_REQUEST:
            raise HostProxyDenied("Credential binding is not declared for this capability")
        if binding.allowed_scope and not set(request.credential_scope).issubset(
            binding.allowed_scope
        ):
            raise HostProxyDenied("Credential scope exceeds its manifest binding")
        try:
            secret = self._vault.scoped_use(
                request.credential_ref,
                association=binding.association,
                scope=request.credential_scope,
            )
        except CredentialVaultError as error:
            raise HostProxyDenied("Credential reference is not valid for this binding") from error
        try:
            value = secret.decode("utf-8")
        except UnicodeDecodeError as error:
            raise HostProxyDenied("Credential cannot be used as a network token") from error
        if binding.location is CredentialLocation.BEARER:
            headers["Authorization"] = f"Bearer {value}"
        else:
            assert binding.header_name is not None
            headers[binding.header_name] = value

    def _safe_path(
        self,
        root_id: str,
        relative_path: str,
        *,
        write: bool,
        allow_empty: bool = False,
    ) -> tuple[Path, str]:
        root = next(
            (item for item in self.manifest.filesystem_roots if item.root_id == root_id), None
        )
        if root is None or (
            write
            and (
                not root.writable
                or root.kind is FilesystemRootKind.APPROVED_USER
                and not root.writable
            )
        ):
            raise HostProxyDenied("Filesystem root is not declared for this operation")
        if not relative_path and not allow_empty:
            raise HostProxyDenied("Filesystem path is required")
        parts = () if not relative_path and allow_empty else _path_text(relative_path)
        candidate = root.path.joinpath(*parts)
        resolved = candidate.resolve(strict=False)
        root_resolved = root.path.resolve(strict=True)
        if not _under(resolved, root_resolved) or any(
            _under(resolved, forbidden) or _under(root_resolved, forbidden)
            for forbidden in self._forbidden_roots
        ):
            raise HostProxyDenied("Filesystem path escapes its approved root")
        current = root.path
        for part in parts:
            current = current / part
            if current.exists() and _has_reparse(current):
                raise HostProxyDenied("Filesystem reparse or symlink path is denied")
        if candidate.exists() and candidate.is_dir() and write:
            raise HostProxyDenied("Filesystem write target must be a file")
        return candidate, str(resolved)


def _header_name(name: object) -> str:
    name = _text(name, "Header name", 128)
    if any(
        character
        not in "!#$%&'*+-.^_`|~0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ"
        for character in name
    ):
        raise HostProxyDenied("Network header name is malformed")
    return name


def _under(candidate: Path, root: Path) -> bool:
    try:
        candidate.relative_to(root)
        return True
    except ValueError:
        return False


def _has_reparse(path: Path) -> bool:
    junction = getattr(path, "is_junction", None)
    return path.is_symlink() or (callable(junction) and bool(junction()))


def _regular_root(path: Path) -> Path:
    if (
        not isinstance(path, Path)
        or not path.is_absolute()
        or not path.is_dir()
        or _has_reparse(path)
    ):
        raise HostProxyError("Forbidden root is malformed")
    return path.resolve(strict=True)


def _literal_addresses(host: str) -> tuple[str, ...] | None:
    try:
        ipaddress.ip_address(host)
    except ValueError:
        return None
    return (host,)


def _resolve_addresses(host: str) -> tuple[str, ...]:
    return tuple(
        {str(item[4][0]) for item in socket.getaddrinfo(host, None, type=socket.SOCK_STREAM)}
    )


__all__ = [
    "CredentialBinding",
    "CredentialLocation",
    "FileEntry",
    "FileListRequest",
    "FileReadRequest",
    "FileWriteRequest",
    "FilesystemRoot",
    "FilesystemRootKind",
    "HostProxy",
    "HostProxyApprovalRequired",
    "HostProxyAuditEvent",
    "HostProxyBoundExceeded",
    "HostProxyDenied",
    "HostProxyEffectUnknown",
    "HostProxyError",
    "HostProxyManifest",
    "HostProxyRequest",
    "InMemoryHostProxyAudit",
    "NetworkRequest",
    "NetworkResponse",
    "ProxyCapability",
    "ProxyKind",
    "TypedActionRequest",
    "TypedActionExecutor",
]
