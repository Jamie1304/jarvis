"""Derived ambient presence state built from canonical JARVIS events."""

from __future__ import annotations

import re
from collections.abc import Mapping
from dataclasses import dataclass, field
from datetime import UTC, datetime
from enum import StrEnum
from uuid import UUID

from jarvis.events import (
    EventBus,
    EventEnvelope,
    EventPayload,
    EventType,
    HealthChanged,
    RuntimeStateChanged,
    SystemError,
    TaskStateChanged,
    ToolCompleted,
    ToolFailed,
    ToolStarted,
    VoiceStateChanged,
)
from jarvis.presentation import PackageAssetReference


class PresenceError(RuntimeError):
    """Presence state or theme metadata is malformed."""


class PresenceState(StrEnum):
    IDLE = "idle"
    LISTENING = "listening"
    THINKING = "thinking"
    EXECUTING = "executing"
    WAITING_PERMISSION = "waiting_permission"
    VERIFYING = "verifying"
    SPEAKING = "speaking"
    DEGRADED = "degraded"
    ERROR = "error"
    SAFE_MODE = "safe_mode"


def _bounded_text(value: object, field: str, limit: int = 512) -> str:
    if type(value) is not str or not value.strip() or len(value) > limit or "\x00" in value:
        raise PresenceError(f"{field} is malformed")
    return value


@dataclass(frozen=True, slots=True)
class PresenceSignals:
    microphone_level: float | None = None
    speech_envelope: float | None = None
    activity_level: float | None = None
    alert_state: str | None = None

    def __post_init__(self) -> None:
        for value, field_name in (
            (self.microphone_level, "microphone level"),
            (self.speech_envelope, "speech envelope"),
            (self.activity_level, "activity level"),
        ):
            if value is not None and (type(value) is not float or not 0 <= value <= 1):
                raise PresenceError(f"{field_name} must be within [0, 1]")
        if self.alert_state is not None:
            _bounded_text(self.alert_state, "alert state", 128)


@dataclass(frozen=True, slots=True)
class PresenceSnapshot:
    state: PresenceState
    revision: int
    updated_at: datetime
    task_id: UUID | None
    source_event_id: UUID | None
    signals: PresenceSignals
    detail: str = ""

    def __post_init__(self) -> None:
        if not isinstance(self.state, PresenceState):
            raise PresenceError("Presence state is malformed")
        if type(self.revision) is not int or self.revision < 0:
            raise PresenceError("Presence revision is malformed")
        if self.updated_at.tzinfo is None:
            raise PresenceError("Presence timestamp must be timezone-aware")
        if self.task_id is not None and not isinstance(self.task_id, UUID):
            raise PresenceError("Presence task ID is malformed")
        if self.source_event_id is not None and not isinstance(self.source_event_id, UUID):
            raise PresenceError("Presence event ID is malformed")
        if not isinstance(self.signals, PresenceSignals):
            raise PresenceError("Presence signals are malformed")
        if self.detail:
            _bounded_text(self.detail, "presence detail")


_THEME_ID = re.compile(r"^[a-z0-9][a-z0-9._-]{0,127}$")
_FORBIDDEN_THEME_KEYS = frozenset(
    {"code", "eval", "exec", "html", "javascript", "path", "python", "script", "src"}
)


def _theme_data(value: object, *, field: str, depth: int = 0) -> object:
    if depth > 5:
        raise PresenceError(f"{field} is too deeply nested")
    if value is None or type(value) is bool or type(value) is int or type(value) is float:
        if type(value) is float and (value != value or value in {float("inf"), float("-inf")}):
            raise PresenceError(f"{field} contains a non-finite number")
        return value
    if type(value) is str:
        text = _bounded_text(value, field, 1_000)
        lowered = text.casefold()
        if "<script" in lowered or "javascript:" in lowered or "__import__" in lowered:
            raise PresenceError(f"{field} contains executable content")
        return text
    if isinstance(value, Mapping):
        if len(value) > 64:
            raise PresenceError(f"{field} has too many properties")
        result: dict[str, object] = {}
        for key, item in value.items():
            if type(key) is not str or not _THEME_ID.fullmatch(key) or key in _FORBIDDEN_THEME_KEYS:
                raise PresenceError(f"{field} contains an unsafe property")
            result[key] = _theme_data(item, field=f"{field}.{key}", depth=depth + 1)
        return result
    if isinstance(value, tuple | list):
        if len(value) > 64:
            raise PresenceError(f"{field} has too many items")
        return tuple(_theme_data(item, field=f"{field}[]", depth=depth + 1) for item in value)
    raise PresenceError(f"{field} contains unsupported data")


@dataclass(frozen=True, slots=True)
class PresenceThemeManifest:
    id: str
    name: str
    version: str
    supported_states: tuple[PresenceState, ...]
    layout: Mapping[str, object]
    animation_profile: Mapping[str, object]
    safe_asset_refs: tuple[PackageAssetReference, ...] = ()
    visual_parameters: Mapping[str, object] = field(default_factory=dict)

    def __post_init__(self) -> None:
        if type(self.id) is not str or not _THEME_ID.fullmatch(self.id):
            raise PresenceError("Presence theme ID is malformed")
        _bounded_text(self.name, "Presence theme name", 256)
        _bounded_text(self.version, "Presence theme version", 64)
        if (
            type(self.supported_states) is not tuple
            or not self.supported_states
            or any(not isinstance(state, PresenceState) for state in self.supported_states)
        ):
            raise PresenceError("Presence theme states are malformed")
        if len(set(self.supported_states)) != len(self.supported_states):
            raise PresenceError("Presence theme states are not unique")
        for value, field_name in (
            (self.layout, "layout"),
            (self.animation_profile, "animation profile"),
            (self.visual_parameters, "visual parameters"),
        ):
            validated = _theme_data(value, field=field_name)
            if not isinstance(validated, dict):
                raise PresenceError(f"Presence theme {field_name} must be an object")
            object.__setattr__(self, field_name.replace(" ", "_"), validated)
        if type(self.safe_asset_refs) is not tuple or any(
            not isinstance(item, PackageAssetReference) for item in self.safe_asset_refs
        ):
            raise PresenceError("Presence theme assets must be opaque package references")


class PresenceProjection:
    """Rebuildable ambient view; it never owns task, runtime, or permission state."""

    def __init__(
        self,
        event_bus: EventBus,
        *,
        safe_mode: bool = False,
        runtime_state: str | None = None,
    ) -> None:
        if not isinstance(safe_mode, bool):
            raise PresenceError("Safe-mode flag is malformed")
        self._event_bus = event_bus
        self._subscription_id: str | None = None
        self._revision = 0
        self._source_event_id: UUID | None = None
        self._task_states: dict[UUID, PresenceState] = {}
        self._voice_state: PresenceState | None = None
        self._runtime_state = runtime_state.casefold() if runtime_state else None
        self._safe_mode = safe_mode or self._runtime_state == PresenceState.SAFE_MODE.value
        self._signals = PresenceSignals()
        self._snapshot = self._make_snapshot()

    async def start(self) -> None:
        if self._subscription_id is None:
            self._subscription_id = await self._event_bus.subscribe(self._on_event)

    async def stop(self) -> None:
        if self._subscription_id is not None:
            subscription_id = self._subscription_id
            self._subscription_id = None
            await self._event_bus.unsubscribe(subscription_id)

    async def aclose(self) -> None:
        """Release the EventBus subscription when owned by a runtime container."""

        await self.stop()

    def snapshot(self) -> PresenceSnapshot:
        return self._snapshot

    def update_signals(self, signals: PresenceSignals) -> PresenceSnapshot:
        if not isinstance(signals, PresenceSignals):
            raise PresenceError("Presence signals are malformed")
        self._signals = signals
        self._revision += 1
        self._snapshot = self._make_snapshot()
        return self._snapshot

    async def _on_event(self, event: EventEnvelope[EventPayload]) -> None:
        if event.event_type is EventType.TASK_STATE_CHANGED and isinstance(
            event.payload, TaskStateChanged
        ):
            self._set_task_state(event.task_id, event.payload.to_state.casefold())
        elif event.event_type is EventType.VOICE_STATE_CHANGED and isinstance(
            event.payload, VoiceStateChanged
        ):
            self._voice_state = self._map_state(event.payload.state)
        elif event.event_type is EventType.RUNTIME_STATE_CHANGED and isinstance(
            event.payload, RuntimeStateChanged
        ):
            self._runtime_state = event.payload.state.casefold()
            self._safe_mode = self._runtime_state == PresenceState.SAFE_MODE.value
        elif event.event_type is EventType.PERMISSION_REQUESTED:
            self._set_task_state(event.task_id, PresenceState.WAITING_PERMISSION.value)
        elif event.event_type is EventType.TOOL_STARTED and isinstance(event.payload, ToolStarted):
            self._set_task_state(event.task_id, PresenceState.EXECUTING.value)
        elif event.event_type is EventType.TOOL_COMPLETED and isinstance(
            event.payload, ToolCompleted
        ):
            self._set_task_state(event.task_id, PresenceState.THINKING.value)
        elif event.event_type is EventType.TOOL_FAILED and isinstance(event.payload, ToolFailed):
            self._set_task_state(event.task_id, PresenceState.ERROR.value)
        elif event.event_type is EventType.HEALTH_CHANGED and isinstance(
            event.payload, HealthChanged
        ):
            if event.payload.status.casefold() not in {"healthy", "available", "ok"}:
                self._set_task_state(event.task_id, PresenceState.DEGRADED.value)
        elif event.event_type is EventType.SYSTEM_ERROR and isinstance(event.payload, SystemError):
            self._set_task_state(event.task_id, PresenceState.ERROR.value)
        else:
            return
        self._source_event_id = event.event_id
        self._revision += 1
        self._snapshot = self._make_snapshot(task_id=event.task_id)

    def _set_task_state(self, task_id: UUID | None, state: str) -> None:
        if task_id is None:
            self._voice_state = self._map_state(state)
            return
        self._task_states[task_id] = self._map_state(state)

    @staticmethod
    def _map_state(value: str) -> PresenceState:
        normalized = value.casefold()
        mapping = {
            "idle": PresenceState.IDLE,
            "created": PresenceState.THINKING,
            "planning": PresenceState.THINKING,
            "thinking": PresenceState.THINKING,
            "processing": PresenceState.THINKING,
            "listening": PresenceState.LISTENING,
            "executing": PresenceState.EXECUTING,
            "waiting": PresenceState.THINKING,
            "waiting_for_permission": PresenceState.WAITING_PERMISSION,
            "waiting_permission": PresenceState.WAITING_PERMISSION,
            "verifying": PresenceState.VERIFYING,
            "speaking": PresenceState.SPEAKING,
            "degraded": PresenceState.DEGRADED,
            "recovering": PresenceState.DEGRADED,
            "error": PresenceState.ERROR,
            "failed": PresenceState.ERROR,
            "cancelled": PresenceState.IDLE,
            "completed": PresenceState.IDLE,
            "safe_mode": PresenceState.SAFE_MODE,
        }
        return mapping.get(normalized, PresenceState.DEGRADED)

    def _make_snapshot(self, *, task_id: UUID | None = None) -> PresenceSnapshot:
        state = PresenceState.IDLE
        selected_task = task_id
        if self._safe_mode:
            state = PresenceState.SAFE_MODE
        elif self._runtime_state in {"error", "failed"}:
            state = PresenceState.ERROR
        else:
            priority = (
                PresenceState.ERROR,
                PresenceState.WAITING_PERMISSION,
                PresenceState.SPEAKING,
                PresenceState.VERIFYING,
                PresenceState.EXECUTING,
                PresenceState.THINKING,
                PresenceState.LISTENING,
                PresenceState.DEGRADED,
            )
            values = tuple(self._task_states.values())
            if self._voice_state is not None:
                values += (self._voice_state,)
            for candidate in priority:
                if candidate in values:
                    state = candidate
                    if selected_task is None and self._task_states:
                        selected_task = next(
                            (
                                item
                                for item, value in self._task_states.items()
                                if value is candidate
                            ),
                            None,
                        )
                    break
        detail = "safe mode" if state is PresenceState.SAFE_MODE else ""
        return PresenceSnapshot(
            state,
            self._revision,
            datetime.now(UTC),
            selected_task,
            self._source_event_id,
            self._signals,
            detail,
        )


__all__ = [
    "PresenceError",
    "PresenceProjection",
    "PresenceSignals",
    "PresenceSnapshot",
    "PresenceState",
    "PresenceThemeManifest",
]
