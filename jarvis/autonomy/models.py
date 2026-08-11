"""Typed domain records for bounded single-agent task orchestration."""

from dataclasses import dataclass
from datetime import datetime
from enum import StrEnum
from uuid import UUID


class TaskStatus(StrEnum):
    """Lifecycle states controlled exclusively by application code."""

    CREATED = "created"
    PLANNING = "planning"
    EXECUTING = "executing"
    VERIFYING = "verifying"
    REPLANNING = "replanning"
    COMPLETED = "completed"
    FAILED = "failed"
    CANCELLED = "cancelled"
    TIMED_OUT = "timed_out"


class PlanStatus(StrEnum):
    """Lifecycle states for an explicit task plan."""

    PENDING = "pending"
    ACTIVE = "active"
    COMPLETED = "completed"
    FAILED = "failed"
    CANCELLED = "cancelled"


class StepStatus(StrEnum):
    """Lifecycle states for individual ordered plan steps."""

    PENDING = "pending"
    RUNNING = "running"
    VERIFIED = "verified"
    FAILED = "failed"


class VerificationStatus(StrEnum):
    """Explicit evidence-based verification outcomes."""

    SUCCEEDED = "succeeded"
    FAILED = "failed"
    UNVERIFIABLE = "unverifiable"


@dataclass(frozen=True, slots=True)
class StructuredTaskError:
    """Stable, observable task failure data safe for UI or storage."""

    code: str
    message: str
    detail: str | None = None


@dataclass(frozen=True, slots=True)
class TaskResult:
    """Final user-facing task result with explicit evidence."""

    summary: str
    evidence: tuple[str, ...] = ()


@dataclass(frozen=True, slots=True)
class Task:
    """A single user-requested orchestration unit."""

    task_id: UUID
    conversation_id: UUID
    user_request: str
    status: TaskStatus
    created_at: datetime
    updated_at: datetime
    current_step: UUID | None
    result: TaskResult | None
    error: StructuredTaskError | None
    cancellation_requested: bool
    correlation_id: UUID


@dataclass(frozen=True, slots=True)
class ToolArgument:
    """A schema-validated scalar parameter for a future tool invocation."""

    name: str
    value: str


@dataclass(frozen=True, slots=True)
class PlanStep:
    """An ordered, dependency-aware capability request."""

    step_id: UUID
    order: int
    capability: str
    action: str
    arguments: tuple[ToolArgument, ...]
    dependencies: tuple[UUID, ...]
    expected_outcome: str
    status: StepStatus = StepStatus.PENDING


@dataclass(frozen=True, slots=True)
class Plan:
    """A typed execution plan owned by the application, not the model."""

    plan_id: UUID
    task_id: UUID
    goal: str
    steps: tuple[PlanStep, ...]
    status: PlanStatus = PlanStatus.PENDING


@dataclass(frozen=True, slots=True)
class ToolObservation:
    """Observed tool output; it is not itself a success verdict."""

    summary: str
    evidence: tuple[str, ...] = ()


@dataclass(frozen=True, slots=True)
class VerificationResult:
    """Independent verification decision for an observed tool result."""

    status: VerificationStatus
    success_evidence: tuple[str, ...] = ()
    failure_evidence: tuple[str, ...] = ()
    detail: str | None = None
