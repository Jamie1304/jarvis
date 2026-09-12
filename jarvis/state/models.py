"""Immutable records and enums for the single application state machine."""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass, field
from datetime import UTC, datetime
from enum import StrEnum
from uuid import UUID


class ApplicationState(StrEnum):
    """States visible to the application/UI lifecycle."""

    IDLE = "idle"
    LISTENING = "listening"
    THINKING = "thinking"
    PROCESSING = "processing"  # transient voice transcription/normalization
    PLANNING = "planning"
    WAITING_FOR_PERMISSION = "waiting_for_permission"
    EXECUTING = "executing"
    VERIFYING = "verifying"
    WAITING = "waiting"
    SPEAKING = "speaking"
    ERROR = "error"
    RECOVERING = "recovering"
    UPDATING = "updating"
    RESTARTING = "restarting"


class TaskState(StrEnum):
    """Durable lifecycle state for one task, independent of global app state."""

    CREATED = "created"
    THINKING = "thinking"
    PLANNING = "planning"
    WAITING_FOR_PERMISSION = "waiting_for_permission"
    EXECUTING = "executing"
    VERIFYING = "verifying"
    WAITING = "waiting"
    RECOVERING = "recovering"
    COMPLETED = "completed"
    ERROR = "error"
    CANCELLED = "cancelled"


class TransitionEvent(StrEnum):
    TASK_CREATED = "task_created"
    TASK_THINKING = "task_thinking"
    PLAN_REQUESTED = "plan_requested"
    PLAN_READY = "plan_ready"
    PERMISSION_REQUIRED = "permission_required"
    PERMISSION_GRANTED = "permission_granted"
    EXECUTION_STARTED = "execution_started"
    EXECUTION_WAITING = "execution_waiting"
    VERIFICATION_STARTED = "verification_started"
    VERIFICATION_PASSED = "verification_passed"
    REPLAN_REQUESTED = "replan_requested"
    TASK_COMPLETED = "task_completed"
    TASK_FAILED = "task_failed"
    TASK_CANCELLED = "task_cancelled"
    RECOVERY_STARTED = "recovery_started"
    RECOVERY_SUCCEEDED = "recovery_succeeded"
    WAKE_DETECTED = "wake_detected"
    SPEECH_CAPTURED = "speech_captured"
    RESPONSE_STARTED = "response_started"
    RESPONSE_FINISHED = "response_finished"
    APP_UPDATE_REQUESTED = "app_update_requested"
    APP_RESTART_REQUESTED = "app_restart_requested"
    APP_READY = "app_ready"
    APP_ERROR = "app_error"


# Readable compatibility name; there is exactly one event enum.
StateEvent = TransitionEvent


def utc(value: datetime) -> datetime:
    if value.tzinfo is None:
        return value.replace(tzinfo=UTC)
    return value.astimezone(UTC)


def _bounded_text(value: str, name: str, limit: int = 2_000) -> None:
    if not value.strip() or len(value) > limit or "\x00" in value:
        raise ValueError(f"{name} must be bounded, non-empty, and NUL-free")


def _metadata(value: Mapping[str, str]) -> dict[str, str]:
    if len(value) > 32:
        raise ValueError("Transition metadata is too large")
    result = dict(value)
    if any(len(key) > 128 or len(item) > 1_000 for key, item in result.items()):
        raise ValueError("Transition metadata values are too large")
    if any("\x00" in key or "\x00" in item for key, item in result.items()):
        raise ValueError("Transition metadata cannot contain NUL bytes")
    return result


@dataclass(frozen=True, slots=True)
class StateTransition:
    """Auditable immutable transition event."""

    from_state: ApplicationState | TaskState
    to_state: ApplicationState | TaskState
    event: TransitionEvent
    task_id: UUID | None
    timestamp: datetime
    reason: str
    metadata: Mapping[str, str] = field(default_factory=dict)
    scope: str = "task"

    def __post_init__(self) -> None:
        if not isinstance(self.from_state, ApplicationState | TaskState):
            raise ValueError("Transition source state is unknown")
        if not isinstance(self.to_state, ApplicationState | TaskState):
            raise ValueError("Transition target state is unknown")
        if not isinstance(self.event, TransitionEvent):
            raise ValueError("Transition event is unknown")
        _bounded_text(self.reason, "Transition reason")
        if self.scope not in {"application", "task"}:
            raise ValueError("Transition scope must be application or task")
        object.__setattr__(self, "timestamp", utc(self.timestamp))
        object.__setattr__(self, "metadata", _metadata(self.metadata))


@dataclass(frozen=True, slots=True)
class TaskSnapshot:
    """Persisted task state needed to resume after restart."""

    task_id: UUID
    state: TaskState
    created_at: datetime
    updated_at: datetime
    cancellation_requested: bool = False
    plan_revision: int | None = None
    active_step_id: UUID | None = None
    recovery_count: int = 0
    metadata: Mapping[str, str] = field(default_factory=dict)

    def __post_init__(self) -> None:
        if not isinstance(self.state, TaskState):
            raise ValueError("Task state is unknown")
        if self.plan_revision is not None and self.plan_revision < 1:
            raise ValueError("Plan revision must be positive")
        if self.recovery_count < 0:
            raise ValueError("Recovery count cannot be negative")
        object.__setattr__(self, "created_at", utc(self.created_at))
        object.__setattr__(self, "updated_at", utc(self.updated_at))
        object.__setattr__(self, "metadata", _metadata(self.metadata))
