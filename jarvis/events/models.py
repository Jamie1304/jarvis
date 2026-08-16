"""Versioned, secret-safe event contracts.

Events are observational messages only.  They are never authorization receipts and
must not be used to mutate authoritative state.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import UTC, datetime
from enum import StrEnum
from typing import Generic, TypeVar
from uuid import UUID, uuid4


class EventType(StrEnum):
    TASK_CREATED = "task.created"
    TASK_STATE_CHANGED = "task.state_changed"
    PLAN_CREATED = "plan.created"
    PLAN_UPDATED = "plan.updated"
    STEP_STARTED = "step.started"
    STEP_COMPLETED = "step.completed"
    STEP_FAILED = "step.failed"
    PERMISSION_REQUESTED = "permission.requested"
    PERMISSION_GRANTED = "permission.granted"
    PERMISSION_DENIED = "permission.denied"
    TOOL_STARTED = "tool.started"
    TOOL_COMPLETED = "tool.completed"
    TOOL_FAILED = "tool.failed"
    CAMERA_STATE_CHANGED = "camera.state_changed"
    VOICE_STATE_CHANGED = "voice.state_changed"
    CAPABILITY_CHANGED = "capability.changed"
    SYSTEM_ERROR = "system.error"


class EventPayload:
    """Marker for trusted, bounded payloads."""


def _text(value: str, *, limit: int = 256) -> str:
    if not isinstance(value, str) or not value or len(value) > limit:
        raise ValueError("event text is invalid or too long")
    return value


@dataclass(frozen=True, slots=True)
class TaskCreated(EventPayload):
    goal: str

    def __post_init__(self) -> None:
        _text(self.goal, limit=512)


@dataclass(frozen=True, slots=True)
class TaskStateChanged(EventPayload):
    from_state: str
    to_state: str
    reason: str

    def __post_init__(self) -> None:
        _text(self.from_state)
        _text(self.to_state)
        _text(self.reason)


@dataclass(frozen=True, slots=True)
class PlanCreated(EventPayload):
    plan_id: UUID
    step_count: int

    def __post_init__(self) -> None:
        if not isinstance(self.plan_id, UUID) or self.step_count < 0:
            raise ValueError("invalid plan event")


@dataclass(frozen=True, slots=True)
class PlanUpdated(EventPayload):
    plan_id: UUID
    revision: int

    def __post_init__(self) -> None:
        if not isinstance(self.plan_id, UUID) or self.revision < 0:
            raise ValueError("invalid plan event")


@dataclass(frozen=True, slots=True)
class StepStarted(EventPayload):
    step_id: UUID
    tool_id: str

    def __post_init__(self) -> None:
        if not isinstance(self.step_id, UUID):
            raise ValueError("invalid step id")
        _text(self.tool_id)


@dataclass(frozen=True, slots=True)
class StepCompleted(EventPayload):
    step_id: UUID
    outcome: str

    def __post_init__(self) -> None:
        if not isinstance(self.step_id, UUID):
            raise ValueError("invalid step id")
        _text(self.outcome)


@dataclass(frozen=True, slots=True)
class StepFailed(EventPayload):
    step_id: UUID
    error_code: str

    def __post_init__(self) -> None:
        if not isinstance(self.step_id, UUID):
            raise ValueError("invalid step id")
        _text(self.error_code)


@dataclass(frozen=True, slots=True)
class PermissionRequested(EventPayload):
    request_id: UUID
    permission: str
    risk: str

    def __post_init__(self) -> None:
        if not isinstance(self.request_id, UUID):
            raise ValueError("invalid request id")
        _text(self.permission)
        _text(self.risk)


@dataclass(frozen=True, slots=True)
class PermissionGranted(EventPayload):
    request_id: UUID
    permission: str

    def __post_init__(self) -> None:
        if not isinstance(self.request_id, UUID):
            raise ValueError("invalid request id")
        _text(self.permission)


@dataclass(frozen=True, slots=True)
class PermissionDenied(EventPayload):
    request_id: UUID | None
    reason_code: str

    def __post_init__(self) -> None:
        if self.request_id is not None and not isinstance(self.request_id, UUID):
            raise ValueError("invalid request id")
        _text(self.reason_code)


@dataclass(frozen=True, slots=True)
class ToolStarted(EventPayload):
    tool_id: str

    def __post_init__(self) -> None:
        _text(self.tool_id)


@dataclass(frozen=True, slots=True)
class ToolCompleted(EventPayload):
    tool_id: str
    status: str

    def __post_init__(self) -> None:
        _text(self.tool_id)
        _text(self.status)


@dataclass(frozen=True, slots=True)
class ToolFailed(EventPayload):
    tool_id: str
    error_code: str

    def __post_init__(self) -> None:
        _text(self.tool_id)
        _text(self.error_code)


@dataclass(frozen=True, slots=True)
class CameraStateChanged(EventPayload):
    device_id: str
    state: str

    def __post_init__(self) -> None:
        _text(self.device_id)
        _text(self.state)


@dataclass(frozen=True, slots=True)
class VoiceStateChanged(EventPayload):
    state: str

    def __post_init__(self) -> None:
        _text(self.state)


@dataclass(frozen=True, slots=True)
class CapabilityChanged(EventPayload):
    capability: str
    available: bool

    def __post_init__(self) -> None:
        _text(self.capability)


@dataclass(frozen=True, slots=True)
class SystemError(EventPayload):
    code: str
    summary: str

    def __post_init__(self) -> None:
        _text(self.code)
        _text(self.summary)


PayloadT = TypeVar("PayloadT", bound=EventPayload)


@dataclass(frozen=True, slots=True)
class EventEnvelope(Generic[PayloadT]):
    event_id: UUID
    schema_version: int
    event_type: EventType
    timestamp: datetime
    source: str
    task_id: UUID | None
    correlation_id: UUID
    causation_id: UUID | None
    payload: PayloadT
    sequence: int = 0

    def __post_init__(self) -> None:
        if not isinstance(self.event_id, UUID) or self.schema_version != 1:
            raise ValueError("unsupported event envelope")
        if self.timestamp.tzinfo is None:
            raise ValueError("event timestamp must be timezone-aware")
        _text(self.source)
        if not isinstance(self.correlation_id, UUID) or not isinstance(self.payload, EventPayload):
            raise ValueError("event metadata/payload is not trusted")

    @classmethod
    def create(
        cls,
        event_type: EventType,
        payload: PayloadT,
        *,
        source: str,
        correlation_id: UUID,
        task_id: UUID | None = None,
        causation_id: UUID | None = None,
        timestamp: datetime | None = None,
    ) -> EventEnvelope[PayloadT]:
        return cls(
            uuid4(),
            1,
            event_type,
            timestamp or datetime.now(UTC),
            source,
            task_id,
            correlation_id,
            causation_id,
            payload,
        )
