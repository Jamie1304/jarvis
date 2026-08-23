"""Provider-neutral semantic browser bridge.

The bridge owns only bounded observations and stale-reference checks.  A browser
adapter is an implementation detail supplied by trusted composition; page text,
labels, URLs, and metadata remain untrusted data.  Every browser operation goes
through the injected permission gate before the adapter is called.
"""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass, replace
from enum import StrEnum
from typing import Protocol, cast
from urllib.parse import urlsplit
from uuid import uuid4

from jarvis.events import (
    BrowserMutated,
    BrowserNavigated,
    BrowserTabClosed,
    EventBus,
    EventEnvelope,
    EventPayload,
    EventType,
)


class BrowserBridgeError(ValueError):
    """Malformed or unsafe browser data failed closed."""


class BrowserAccessDenied(PermissionError):
    """The trusted application permission gate denied browser access."""


class StaleBrowserReference(BrowserBridgeError):
    """A tab, document, origin, or semantic target is no longer current."""


class SensitiveBrowserField(BrowserBridgeError):
    """A password control cannot be filled as a normal text field."""


class BrowserAction(StrEnum):
    INSPECT = "inspect"
    NAVIGATE = "navigate"
    SEMANTIC_CLICK = "semantic_click"
    FILL = "fill"
    FILL_CREDENTIAL = "fill_credential"
    SELECT = "select"
    SUBMIT = "submit"
    SCROLL_FIND = "scroll_find"
    WAIT_FOR_STATE = "wait_for_state"


def _text(
    value: object,
    field: str,
    limit: int,
    *,
    allow_lines: bool = False,
    allow_empty: bool = False,
) -> str:
    if type(value) is not str or (not allow_empty and not value.strip()) or len(value) > limit:
        raise BrowserBridgeError(f"{field} is invalid")
    allowed_controls = "\r\n\t" if allow_lines else ""
    if any(
        not character.isprintable() and character not in allowed_controls for character in value
    ):
        raise BrowserBridgeError(f"{field} contains unsafe controls")
    return value


def _origin_for_url(url: str) -> str:
    _text(url, "Browser URL", 4_096)
    try:
        parsed = urlsplit(url)
        hostname = parsed.hostname
        port = parsed.port
    except ValueError as error:
        raise BrowserBridgeError("Browser URL is malformed") from error
    if (
        parsed.scheme.casefold() not in {"http", "https"}
        or hostname is None
        or parsed.username is not None
        or parsed.password is not None
        or parsed.fragment
        or any(character.isspace() for character in url)
    ):
        raise BrowserBridgeError("Browser URL must be an http(s) URL without credentials")
    try:
        normalized_host = hostname.encode("idna").decode("ascii").casefold()
    except UnicodeError as error:
        raise BrowserBridgeError("Browser URL host is invalid") from error
    suffix = "" if port is None else f":{port}"
    return f"{parsed.scheme.casefold()}://{normalized_host}{suffix}"


@dataclass(frozen=True, slots=True)
class BrowserTab:
    tab_id: str
    url: str
    origin: str
    title: str
    document_generation: int
    closed: bool = False

    def __post_init__(self) -> None:
        _text(self.tab_id, "Browser tab ID", 256)
        if _origin_for_url(self.url) != self.origin:
            raise BrowserBridgeError("Browser tab origin does not match its URL")
        _text(self.origin, "Browser origin", 512)
        _text(self.title, "Browser title", 512, allow_lines=False, allow_empty=True)
        if type(self.document_generation) is not int or self.document_generation < 1:
            raise BrowserBridgeError("Browser document generation is invalid")
        if type(self.closed) is not bool:
            raise BrowserBridgeError("Browser tab closed state is invalid")


@dataclass(frozen=True, slots=True)
class BrowserReference:
    tab_id: str
    document_generation: int
    origin: str
    semantic_id: str

    def __post_init__(self) -> None:
        _text(self.tab_id, "Browser reference tab ID", 256)
        _text(self.origin, "Browser reference origin", 512)
        _text(self.semantic_id, "Browser semantic ID", 256)
        if type(self.document_generation) is not int or self.document_generation < 1:
            raise BrowserBridgeError("Browser reference generation is invalid")


@dataclass(frozen=True, slots=True)
class SemanticNode:
    semantic_id: str
    role: str
    label: str
    name: str
    input_type: str | None = None
    value: str | None = None
    options: tuple[str, ...] = ()
    origin: str | None = None
    children: tuple[str, ...] = ()
    password_redacted: bool = False

    def __post_init__(self) -> None:
        _text(self.semantic_id, "Semantic ID", 256)
        _text(self.role, "Semantic role", 128)
        _text(self.label, "Semantic label", 512)
        _text(self.name, "Semantic name", 512)
        if self.input_type is not None:
            _text(self.input_type, "Input type", 64)
        if self.value is not None:
            _text(self.value, "Control value", 16_384)
        if self.origin is not None:
            _text(self.origin, "Semantic origin", 512)
        if len(self.options) > 128 or any(
            type(item) is not str or not item.strip() or len(item) > 512 for item in self.options
        ):
            raise BrowserBridgeError("Semantic options are invalid")
        if len(self.children) > 256 or any(
            type(item) is not str or not item.strip() or len(item) > 256 for item in self.children
        ):
            raise BrowserBridgeError("Semantic children are invalid")
        is_password = self.input_type is not None and self.input_type.casefold() == "password"
        if is_password:
            object.__setattr__(self, "value", None)
            object.__setattr__(self, "password_redacted", True)
        elif type(self.password_redacted) is not bool:
            raise BrowserBridgeError("Password redaction metadata is invalid")


@dataclass(frozen=True, slots=True)
class BrowserForm:
    form_id: str
    action: str | None
    method: str
    controls: tuple[SemanticNode, ...]
    origin: str

    def __post_init__(self) -> None:
        _text(self.form_id, "Browser form ID", 256)
        if self.action is not None:
            _text(self.action, "Browser form action", 4_096)
        _text(self.method, "Browser form method", 16)
        _text(self.origin, "Browser form origin", 512)
        if len(self.controls) > 256 or any(
            type(item) is not SemanticNode for item in self.controls
        ):
            raise BrowserBridgeError("Browser form controls are invalid")


@dataclass(frozen=True, slots=True)
class BrowserFrame:
    frame_id: str
    origin: str
    semantic_nodes: tuple[SemanticNode, ...] = ()

    def __post_init__(self) -> None:
        _text(self.frame_id, "Browser frame ID", 256)
        _text(self.origin, "Browser frame origin", 512)
        if len(self.semantic_nodes) > 256 or any(
            type(item) is not SemanticNode for item in self.semantic_nodes
        ):
            raise BrowserBridgeError("Browser frame nodes are invalid")


@dataclass(frozen=True, slots=True)
class BrowserDocument:
    tab_id: str
    url: str
    origin: str
    title: str
    document_generation: int
    semantic_nodes: tuple[SemanticNode, ...]
    forms: tuple[BrowserForm, ...] = ()
    frames: tuple[BrowserFrame, ...] = ()
    untrusted_page_text: str = ""

    def __post_init__(self) -> None:
        _text(self.tab_id, "Browser document tab ID", 256)
        if _origin_for_url(self.url) != self.origin:
            raise BrowserBridgeError("Browser document origin does not match its URL")
        _text(self.origin, "Browser document origin", 512)
        _text(self.title, "Browser document title", 512, allow_empty=True)
        if type(self.document_generation) is not int or self.document_generation < 1:
            raise BrowserBridgeError("Browser document generation is invalid")
        if len(self.semantic_nodes) > 1_024 or any(
            type(item) is not SemanticNode for item in self.semantic_nodes
        ):
            raise BrowserBridgeError("Browser semantic structure is invalid")
        if len(self.forms) > 256 or any(type(item) is not BrowserForm for item in self.forms):
            raise BrowserBridgeError("Browser forms are invalid")
        if len(self.frames) > 128 or any(type(item) is not BrowserFrame for item in self.frames):
            raise BrowserBridgeError("Browser frames are invalid")
        _text(
            self.untrusted_page_text, "Untrusted page text", 1_000_000, allow_lines=True
        ) if self.untrusted_page_text else None
        safe_ids = {item.semantic_id for item in self.semantic_nodes}
        if len(safe_ids) != len(self.semantic_nodes):
            raise BrowserBridgeError("Semantic IDs must be unique per document")
        # Cross-origin content is retained only as frame metadata.  It is never
        # exposed as semantic nodes or form controls to the caller.
        filtered_nodes = tuple(
            item for item in self.semantic_nodes if item.origin in (None, self.origin)
        )
        filtered_forms = tuple(
            replace(
                form,
                controls=tuple(
                    item for item in form.controls if item.origin in (None, self.origin)
                ),
            )
            for form in self.forms
            if form.origin == self.origin
        )
        filtered_frames = tuple(
            frame if frame.origin == self.origin else replace(frame, semantic_nodes=())
            for frame in self.frames
        )
        object.__setattr__(self, "semantic_nodes", filtered_nodes)
        object.__setattr__(self, "forms", filtered_forms)
        object.__setattr__(self, "frames", filtered_frames)

    def reference(self, semantic_id: str) -> BrowserReference:
        if semantic_id not in {item.semantic_id for item in self.semantic_nodes}:
            raise StaleBrowserReference("Semantic target is not in the current document")
        return BrowserReference(
            self.tab_id,
            self.document_generation,
            self.origin,
            semantic_id,
        )


class BrowserAdapter(Protocol):
    async def inspect(self, tab_id: str) -> BrowserDocument: ...

    async def navigate(self, tab_id: str, url: str) -> BrowserDocument: ...

    async def semantic_click(self, reference: BrowserReference) -> BrowserDocument: ...

    async def fill(self, reference: BrowserReference, value: str) -> BrowserDocument: ...

    async def fill_credential(
        self, reference: BrowserReference, credential_ref: str
    ) -> BrowserDocument: ...

    async def select(self, reference: BrowserReference, option: str) -> BrowserDocument: ...

    async def submit(self, reference: BrowserReference) -> BrowserDocument: ...

    async def scroll_find(self, tab_id: str, query: str) -> BrowserDocument: ...

    async def wait_for_state(
        self, tab_id: str, state: str, timeout_seconds: float
    ) -> BrowserDocument: ...


class BrowserPermissionGate(Protocol):
    async def authorize(
        self,
        *,
        action: BrowserAction,
        tab: BrowserTab,
        origin: str,
        target: BrowserReference | None,
        arguments: Mapping[str, str],
    ) -> None: ...


class DenyBrowserPermissionGate:
    async def authorize(
        self,
        *,
        action: BrowserAction,
        tab: BrowserTab,
        origin: str,
        target: BrowserReference | None,
        arguments: Mapping[str, str],
    ) -> None:
        del action, tab, origin, target, arguments
        raise BrowserAccessDenied("Browser operations require trusted broker authorization")


class BrowserCredentialFiller(Protocol):
    async def fill_credential(
        self, reference: BrowserReference, credential_ref: str
    ) -> BrowserDocument: ...


class BrowserSemanticBridge:
    """Coordinate browser semantics without exposing browser authority or secrets."""

    def __init__(
        self,
        adapter: BrowserAdapter,
        *,
        permission_gate: BrowserPermissionGate | None = None,
        event_bus: EventBus | None = None,
    ) -> None:
        self._adapter = adapter
        self._permission_gate = permission_gate or DenyBrowserPermissionGate()
        self._event_bus = event_bus
        self._tabs: dict[str, BrowserTab] = {}
        self._documents: dict[str, BrowserDocument] = {}

    def attach_tab(self, tab: BrowserTab) -> None:
        if tab.tab_id in self._tabs and not self._tabs[tab.tab_id].closed:
            raise BrowserBridgeError("Browser tab is already attached")
        self._tabs[tab.tab_id] = tab
        self._documents.pop(tab.tab_id, None)

    def tab(self, tab_id: str) -> BrowserTab:
        tab = self._tabs.get(tab_id)
        if tab is None:
            raise StaleBrowserReference("Browser tab is unknown")
        return tab

    def document(self, tab_id: str) -> BrowserDocument:
        self.tab(tab_id)
        try:
            return self._documents[tab_id]
        except KeyError as error:
            raise StaleBrowserReference("Browser document has not been inspected") from error

    async def inspect(self, tab: BrowserReference | str) -> BrowserDocument:
        current = self._tab_for(tab)
        await self._authorize(BrowserAction.INSPECT, current, current.origin, None, {})
        return await self._accept(await self._adapter.inspect(current.tab_id))

    async def navigate(self, tab: BrowserReference | str, url: str) -> BrowserDocument:
        current = self._tab_for(tab)
        target_origin = _origin_for_url(url)
        await self._authorize(
            BrowserAction.NAVIGATE,
            current,
            target_origin,
            None,
            {"url": url, "origin": target_origin},
        )
        return await self._accept(await self._adapter.navigate(current.tab_id, url))

    async def semantic_click(self, reference: BrowserReference) -> BrowserDocument:
        current, _node = self._target(reference)
        await self._authorize(BrowserAction.SEMANTIC_CLICK, current, current.origin, reference, {})
        return await self._accept(await self._adapter.semantic_click(reference))

    async def fill(self, reference: BrowserReference, value: str) -> BrowserDocument:
        current, node = self._target(reference)
        if node.input_type is not None and node.input_type.casefold() == "password":
            raise SensitiveBrowserField("Password fields require trusted Vault filling")
        _text(value, "Browser field value", 16_384)
        await self._authorize(
            BrowserAction.FILL,
            current,
            current.origin,
            reference,
            {"value_length": str(len(value))},
        )
        return await self._accept(await self._adapter.fill(reference, value))

    async def fill_credential(
        self, reference: BrowserReference, credential_ref: str
    ) -> BrowserDocument:
        current, node = self._target(reference)
        if node.input_type is None or node.input_type.casefold() != "password":
            raise BrowserBridgeError("Credential filling requires a password control")
        _text(credential_ref, "Credential reference", 512)
        if not credential_ref.startswith("vault:") or any(
            character.isspace() for character in credential_ref
        ):
            raise BrowserBridgeError("Credential filling requires a Vault reference")
        await self._authorize(
            BrowserAction.FILL_CREDENTIAL,
            current,
            current.origin,
            reference,
            {"credential_ref": credential_ref},
        )
        return await self._accept(await self._adapter.fill_credential(reference, credential_ref))

    async def select(self, reference: BrowserReference, option: str) -> BrowserDocument:
        current, _node = self._target(reference)
        _text(option, "Browser select option", 512)
        await self._authorize(
            BrowserAction.SELECT,
            current,
            current.origin,
            reference,
            {"option": option},
        )
        return await self._accept(await self._adapter.select(reference, option))

    async def submit(self, reference: BrowserReference) -> BrowserDocument:
        current, _node = self._target(reference)
        await self._authorize(BrowserAction.SUBMIT, current, current.origin, reference, {})
        return await self._accept(await self._adapter.submit(reference))

    async def scroll_find(self, tab: BrowserReference | str, query: str) -> BrowserDocument:
        current = self._tab_for(tab)
        _text(query, "Browser find query", 512)
        await self._authorize(
            BrowserAction.SCROLL_FIND,
            current,
            current.origin,
            None,
            {"query": query},
        )
        return await self._accept(await self._adapter.scroll_find(current.tab_id, query))

    async def wait_for_state(
        self,
        tab: BrowserReference | str,
        state: str,
        *,
        timeout_seconds: float = 10.0,
    ) -> BrowserDocument:
        current = self._tab_for(tab)
        _text(state, "Browser state", 256)
        if not 0.1 <= timeout_seconds <= 60.0:
            raise BrowserBridgeError("Browser wait timeout is outside the safe bound")
        await self._authorize(
            BrowserAction.WAIT_FOR_STATE,
            current,
            current.origin,
            None,
            {"state": state, "timeout_seconds": str(timeout_seconds)},
        )
        return await self._accept(
            await self._adapter.wait_for_state(current.tab_id, state, timeout_seconds)
        )

    async def close_tab(self, tab_id: str) -> None:
        current = self.tab(tab_id)
        if current.closed:
            return
        self._tabs[tab_id] = replace(current, closed=True)
        self._documents.pop(tab_id, None)
        await self._publish(
            EventType.BROWSER_TAB_CLOSED,
            BrowserTabClosed(tab_id),
        )

    def references(self, tab_id: str) -> tuple[BrowserReference, ...]:
        document = self.document(tab_id)
        return tuple(document.reference(node.semantic_id) for node in document.semantic_nodes)

    def _tab_for(self, value: BrowserReference | str) -> BrowserTab:
        tab_id = value.tab_id if isinstance(value, BrowserReference) else value
        current = self.tab(tab_id)
        if current.closed:
            raise StaleBrowserReference("Browser tab is closed")
        if isinstance(value, BrowserReference):
            self._validate_tab_reference(value, current)
        return current

    def _target(self, reference: BrowserReference) -> tuple[BrowserTab, SemanticNode]:
        current = self._tab_for(reference)
        document = self.document(current.tab_id)
        try:
            node = next(
                item
                for item in document.semantic_nodes
                if item.semantic_id == reference.semantic_id
            )
        except StopIteration as error:
            raise StaleBrowserReference("Browser semantic target is stale") from error
        return current, node

    @staticmethod
    def _validate_tab_reference(reference: BrowserReference, current: BrowserTab) -> None:
        if (
            reference.tab_id != current.tab_id
            or reference.document_generation != current.document_generation
            or reference.origin != current.origin
        ):
            raise StaleBrowserReference("Browser reference is stale")

    async def _authorize(
        self,
        action: BrowserAction,
        tab: BrowserTab,
        origin: str,
        target: BrowserReference | None,
        arguments: Mapping[str, str],
    ) -> None:
        try:
            await self._permission_gate.authorize(
                action=action,
                tab=tab,
                origin=origin,
                target=target,
                arguments=arguments,
            )
        except BrowserAccessDenied:
            raise
        except Exception as error:
            raise BrowserAccessDenied("Browser permission gate failed closed") from error

    async def _accept(self, document: BrowserDocument) -> BrowserDocument:
        if type(document) is not BrowserDocument:
            raise BrowserBridgeError("Browser adapter returned an invalid document")
        current = self._tabs.get(document.tab_id)
        if current is None:
            current = BrowserTab(
                document.tab_id,
                document.url,
                document.origin,
                document.title,
                document.document_generation,
            )
        elif current.closed:
            raise StaleBrowserReference("Browser adapter returned a closed tab")
        elif document.document_generation < current.document_generation or (
            document.origin != current.origin
            and document.document_generation <= current.document_generation
        ):
            raise StaleBrowserReference("Browser adapter returned a stale document")
        previous = self._documents.get(document.tab_id)
        self._tabs[document.tab_id] = BrowserTab(
            document.tab_id,
            document.url,
            document.origin,
            document.title,
            document.document_generation,
        )
        self._documents[document.tab_id] = document
        if previous is not None:
            if previous.origin != document.origin:
                await self._publish(
                    EventType.BROWSER_NAVIGATED,
                    BrowserNavigated(
                        document.tab_id, document.origin, document.document_generation
                    ),
                )
            elif previous.document_generation != document.document_generation:
                await self._publish(
                    EventType.BROWSER_MUTATED,
                    BrowserMutated(document.tab_id, document.origin, document.document_generation),
                )
        return document

    async def _publish(self, event_type: EventType, payload: object) -> None:
        if self._event_bus is None:
            return
        if not isinstance(payload, BrowserNavigated | BrowserMutated | BrowserTabClosed):
            raise BrowserBridgeError("Browser event payload is invalid")
        event = EventEnvelope.create(
            event_type,
            payload,
            source="browser.semantic_bridge",
            correlation_id=uuid4(),
        )
        await self._event_bus.publish(cast(EventEnvelope[EventPayload], event))


BrowserBridge = BrowserSemanticBridge
BrowserSemanticNode = SemanticNode


__all__ = [
    "BrowserAccessDenied",
    "BrowserAction",
    "BrowserAdapter",
    "BrowserBridge",
    "BrowserBridgeError",
    "BrowserCredentialFiller",
    "BrowserDocument",
    "BrowserForm",
    "BrowserFrame",
    "BrowserPermissionGate",
    "BrowserReference",
    "BrowserSemanticBridge",
    "BrowserSemanticNode",
    "BrowserTab",
    "DenyBrowserPermissionGate",
    "SemanticNode",
    "SensitiveBrowserField",
    "StaleBrowserReference",
]
