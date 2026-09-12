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
    GOAL_CREATED = "goal.created"
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
    INTEGRATION_CHANGED = "integration.changed"
    RUNTIME_STATE_CHANGED = "runtime.state_changed"
    HEALTH_CHANGED = "health.changed"
    AUTOMATION_STATE_CHANGED = "automation.state_changed"
    BROWSER_NAVIGATED = "browser.navigated"
    BROWSER_MUTATED = "browser.mutated"
    BROWSER_TAB_CLOSED = "browser.tab_closed"
    CREDENTIAL_CHANGED = "credential.changed"
    EFFECT_ATTESTATION_RECORDED = "effect_attestation.recorded"
    SYSTEM_ERROR = "system.error"
    ARTIFACT_CREATED = "artifact.created"


class EventPayload:
    """Marker for trusted, bounded payloads."""


@dataclass(frozen=True, slots=True)
class ArtifactCreated(EventPayload):
    artifact_id: UUID
    version: int
    workspace_id: str
    size: int

    def __post_init__(self) -> None:
        if not isinstance(self.artifact_id, UUID) or self.version < 1 or self.size < 0:
            raise ValueError("invalid artifact event")
        _text(self.workspace_id)


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
class GoalCreated(EventPayload):
    goal: str

    def __post_init__(self) -> None:
        _text(self.goal, limit=512)


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
class IntegrationChanged(EventPayload):
    integration: str
    state: str

    def __post_init__(self) -> None:
        _text(self.integration)
        _text(self.state)


@dataclass(frozen=True, slots=True)
class RuntimeStateChanged(EventPayload):
    state: str

    def __post_init__(self) -> None:
        _text(self.state)


@dataclass(frozen=True, slots=True)
class HealthChanged(EventPayload):
    component: str
    status: str

    def __post_init__(self) -> None:
        _text(self.component)
        _text(self.status)


@dataclass(frozen=True, slots=True)
class AutomationStateChanged(EventPayload):
    automation_id: UUID
    state: str

    def __post_init__(self) -> None:
        if not isinstance(self.automation_id, UUID):
            raise ValueError("invalid automation id")
        _text(self.state)


@dataclass(frozen=True, slots=True)
class BrowserNavigated(EventPayload):
    tab_id: str
    origin: str
    document_generation: int

    def __post_init__(self) -> None:
        _text(self.tab_id)
        _text(self.origin)
        if self.document_generation < 1:
            raise ValueError("invalid browser document generation")


@dataclass(frozen=True, slots=True)
class BrowserMutated(EventPayload):
    tab_id: str
    origin: str
    document_generation: int

    def __post_init__(self) -> None:
        _text(self.tab_id)
        _text(self.origin)
        if self.document_generation < 1:
            raise ValueError("invalid browser document generation")


@dataclass(frozen=True, slots=True)
class BrowserTabClosed(EventPayload):
    tab_id: str

    def __post_init__(self) -> None:
        _text(self.tab_id)


@dataclass(frozen=True, slots=True)
class CredentialChanged(EventPayload):
    credential_id: UUID
    status: str
    operation: str

    def __post_init__(self) -> None:
        if not isinstance(self.credential_id, UUID):
            raise ValueError("invalid credential id")
        _text(self.status)
        _text(self.operation)


@dataclass(frozen=True, slots=True)
class EffectAttestationRecorded(EventPayload):
    """Trusted broker observation/attestation metadata; never a secret/result body."""

    observation_id: UUID | None
    attestation_id: UUID | None
    integration_id: str
    integration_version: str
    activation_state: str
    status: str
    allowed: bool | None = None
    dispatched: bool | None = None

    def __post_init__(self) -> None:
        if self.observation_id is None and self.attestation_id is None:
            raise ValueError("effect attestation event requires an identity")
        if self.observation_id is not None and not isinstance(self.observation_id, UUID):
            raise ValueError("invalid observation id")
        if self.attestation_id is not None and not isinstance(self.attestation_id, UUID):
            raise ValueError("invalid attestation id")
        _text(self.integration_id)
        _text(self.integration_version)
        _text(self.activation_state)
        _text(self.status)
        if self.allowed is not None and type(self.allowed) is not bool:
            raise ValueError("invalid attestation authorization flag")
        if self.dispatched is not None and type(self.dispatched) is not bool:
            raise ValueError("invalid attestation dispatch flag")


@dataclass(frozen=True, slots=True)
class SystemError(EventPayload):
    code: str
    summary: str

    def __post_init__(self) -> None:
        _text(self.code)
        _text(self.summary)


_PAYLOAD_TYPES: dict[EventType, type[EventPayload]] = {
    EventType.TASK_CREATED: TaskCreated,
    EventType.TASK_STATE_CHANGED: TaskStateChanged,
    EventType.GOAL_CREATED: GoalCreated,
    EventType.PLAN_CREATED: PlanCreated,
    EventType.PLAN_UPDATED: PlanUpdated,
    EventType.STEP_STARTED: StepStarted,
    EventType.STEP_COMPLETED: StepCompleted,
    EventType.STEP_FAILED: StepFailed,
    EventType.PERMISSION_REQUESTED: PermissionRequested,
    EventType.PERMISSION_GRANTED: PermissionGranted,
    EventType.PERMISSION_DENIED: PermissionDenied,
    EventType.TOOL_STARTED: ToolStarted,
    EventType.TOOL_COMPLETED: ToolCompleted,
    EventType.TOOL_FAILED: ToolFailed,
    EventType.CAMERA_STATE_CHANGED: CameraStateChanged,
    EventType.VOICE_STATE_CHANGED: VoiceStateChanged,
    EventType.CAPABILITY_CHANGED: CapabilityChanged,
    EventType.INTEGRATION_CHANGED: IntegrationChanged,
    EventType.RUNTIME_STATE_CHANGED: RuntimeStateChanged,
    EventType.HEALTH_CHANGED: HealthChanged,
    EventType.AUTOMATION_STATE_CHANGED: AutomationStateChanged,
    EventType.BROWSER_NAVIGATED: BrowserNavigated,
    EventType.BROWSER_MUTATED: BrowserMutated,
    EventType.BROWSER_TAB_CLOSED: BrowserTabClosed,
    EventType.CREDENTIAL_CHANGED: CredentialChanged,
    EventType.EFFECT_ATTESTATION_RECORDED: EffectAttestationRecorded,
    EventType.SYSTEM_ERROR: SystemError,
    EventType.ARTIFACT_CREATED: ArtifactCreated,
}


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
        if (
            not isinstance(self.event_id, UUID)
            or not isinstance(self.event_type, EventType)
            or type(self.schema_version) is not int
            or self.schema_version != 1
        ):
            raise ValueError("unsupported event envelope")
        if not isinstance(self.timestamp, datetime) or self.timestamp.tzinfo is None:
            raise ValueError("event timestamp must be timezone-aware")
        _text(self.source)
        if (
            not isinstance(self.correlation_id, UUID)
            or (self.task_id is not None and not isinstance(self.task_id, UUID))
            or (self.causation_id is not None and not isinstance(self.causation_id, UUID))
            or type(self.payload) is not _PAYLOAD_TYPES[self.event_type]
            or type(self.sequence) is not int
            or self.sequence < 0
        ):
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
