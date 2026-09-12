"""Application-owned domain records for durable, bounded DAG plan execution."""

from __future__ import annotations

import json
import math
from dataclasses import dataclass
from datetime import UTC, datetime
from enum import StrEnum
from uuid import UUID

from jarvis.permissions.models import Permission


class PlanningTaskStatus(StrEnum):
    CREATED = "created"
    PLANNING = "planning"
    READY = "ready"
    EXECUTING = "executing"
    WAITING_FOR_PERMISSION = "waiting_for_permission"
    VERIFYING = "verifying"
    REPLANNING = "replanning"
    RECOVERING = "recovering"
    COMPLETED = "completed"
    FAILED = "failed"
    CANCELLED = "cancelled"
    BUDGET_EXHAUSTED = "budget_exhausted"


class OwnedPlanStatus(StrEnum):
    READY = "ready"
    ACTIVE = "active"
    WAITING_FOR_PERMISSION = "waiting_for_permission"
    COMPLETED = "completed"
    FAILED = "failed"
    CANCELLED = "cancelled"
    SUPERSEDED = "superseded"


class PlanningStepStatus(StrEnum):
    QUEUED = "queued"
    RUNNING = "running"
    WAITING_FOR_PERMISSION = "waiting_for_permission"
    VERIFYING = "verifying"
    SUCCEEDED = "succeeded"
    FAILED = "failed"
    CANCELLED = "cancelled"
    BLOCKED = "blocked"


class FailureKind(StrEnum):
    TRANSIENT = "transient"
    DETERMINISTIC = "deterministic"
    CANCELLED = "cancelled"
    UNKNOWN_OUTCOME = "unknown_outcome"


class StepExecutionStatus(StrEnum):
    SUCCEEDED = "succeeded"
    TRANSIENT_FAILURE = "transient_failure"
    DETERMINISTIC_FAILURE = "deterministic_failure"
    WAITING_FOR_PERMISSION = "waiting_for_permission"
    CANCELLED = "cancelled"
    UNKNOWN_OUTCOME = "unknown_outcome"


class EffectOutcome(StrEnum):
    """Trusted classification of an operation across its effect boundary."""

    PRE_EFFECT_FAILURE = "pre_effect_failure"
    SAFE_TO_RETRY = "safe_to_retry"
    EFFECT_CONFIRMED = "effect_confirmed"
    UNKNOWN_OUTCOME = "unknown_outcome"


def utc(value: datetime) -> datetime:
    if value.tzinfo is None:
        return value.replace(tzinfo=UTC)
    return value.astimezone(UTC)


def canonical_json(value: object) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), allow_nan=False)


def _bounded(value: str, name: str, limit: int = 4_000) -> None:
    if not value.strip() or len(value) > limit or "\x00" in value:
        raise ValueError(f"{name} must be bounded, non-empty, and NUL-free")


@dataclass(frozen=True, slots=True)
class ExecutionBudgets:
    max_steps: int = 32
    max_elapsed_seconds: float = 900
    max_model_calls: int = 3
    max_expensive_actions: int = 4
    max_retries: int = 4

    def __post_init__(self) -> None:
        if (
            self.max_steps <= 0
            or self.max_elapsed_seconds <= 0
            or not math.isfinite(self.max_elapsed_seconds)
        ):
            raise ValueError("Step and elapsed-time budgets must be positive")
        if min(self.max_model_calls, self.max_expensive_actions, self.max_retries) < 0:
            raise ValueError("Model, expensive-action, and retry budgets cannot be negative")


@dataclass(frozen=True, slots=True)
class BudgetUsage:
    executed_steps: int = 0
    model_calls: int = 0
    expensive_actions: int = 0
    retries: int = 0

    def __post_init__(self) -> None:
        if min(self.executed_steps, self.model_calls, self.expensive_actions, self.retries) < 0:
            raise ValueError("Budget usage cannot be negative")


@dataclass(frozen=True, slots=True)
class StepResult:
    output_json: str
    evidence: tuple[str, ...]

    def __post_init__(self) -> None:
        try:
            json.loads(self.output_json)
        except json.JSONDecodeError as error:
            raise ValueError("Step output must be valid JSON") from error
        if (
            len(self.output_json) > 16_000
            or len(self.evidence) > 32
            or any(not item.strip() or len(item) > 1_000 for item in self.evidence)
        ):
            raise ValueError("Step result evidence must be bounded")


@dataclass(frozen=True, slots=True)
class StepError:
    code: str
    message: str
    failure_kind: FailureKind
    evidence: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        _bounded(self.code, "Step error code", 128)
        _bounded(self.message, "Step error message")
        if not isinstance(self.failure_kind, FailureKind):
            raise ValueError("Step failure kind must be recognized")
        if len(self.evidence) > 32 or any(len(item) > 1_000 for item in self.evidence):
            raise ValueError("Step error evidence must be bounded")


@dataclass(frozen=True, slots=True)
class PlanningStep:
    """One exact node in an application-owned task graph."""

    step_id: UUID
    key: str
    tool_id: str
    capability: str
    input_json: str
    expected_output: str
    verification_rule: str
    expected_evidence: tuple[str, ...]
    dependencies: tuple[UUID, ...]
    required_permissions: tuple[Permission, ...]
    expensive_action: bool
    max_retries: int
    status: PlanningStepStatus = PlanningStepStatus.QUEUED
    attempts: int = 0
    result: StepResult | None = None
    error: StepError | None = None

    def __post_init__(self) -> None:
        for value, name, limit in (
            (self.key, "Step key", 128),
            (self.tool_id, "Tool ID", 128),
            (self.capability, "Capability", 128),
            (self.expected_output, "Expected output", 4_000),
            (self.verification_rule, "Verification rule", 1_000),
        ):
            _bounded(value, name, limit)
        try:
            parsed = json.loads(self.input_json)
        except json.JSONDecodeError as error:
            raise ValueError("Step input must be valid JSON") from error
        if not isinstance(parsed, dict) or len(self.input_json) > 16_000:
            raise ValueError("Step input must be a bounded JSON object")
        if (
            len(set(self.dependencies)) != len(self.dependencies)
            or self.step_id in self.dependencies
        ):
            raise ValueError("Step dependencies must be unique and cannot reference self")
        if any(not isinstance(permission, Permission) for permission in self.required_permissions):
            raise ValueError("Step permissions must be recognized")
        if tuple(sorted(set(self.required_permissions), key=lambda item: item.value)) != (
            self.required_permissions
        ):
            raise ValueError("Step permissions must be unique and sorted")
        if self.max_retries < 0 or self.attempts < 0:
            raise ValueError("Step retry and attempt counts cannot be negative")
        if len(self.expected_evidence) > 32 or any(
            not item.strip() or len(item) > 1_000 for item in self.expected_evidence
        ):
            raise ValueError("Expected evidence must be bounded and non-empty")


@dataclass(frozen=True, slots=True)
class OwnedPlan:
    """Validated plan owned by deterministic application code, never by the model."""

    plan_id: UUID
    task_id: UUID
    version: int
    goal: str
    assumptions: tuple[str, ...]
    constraints: tuple[str, ...]
    steps: tuple[PlanningStep, ...]
    required_capabilities: tuple[str, ...]
    required_permissions: tuple[Permission, ...]
    completion_criteria: tuple[str, ...]
    status: OwnedPlanStatus
    created_at: datetime
    updated_at: datetime
    provenance: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        _bounded(self.goal, "Plan goal")
        if self.version <= 0 or not self.steps:
            raise ValueError("Owned plans require a positive version and at least one step")
        if len({step.step_id for step in self.steps}) != len(self.steps):
            raise ValueError("Plan step IDs must be unique")
        if len({step.key for step in self.steps}) != len(self.steps):
            raise ValueError("Plan step keys must be unique")
        if not self.completion_criteria or any(
            not item.strip() or len(item) > 1_000 for item in self.completion_criteria
        ):
            raise ValueError("Plan completion criteria must be explicit")
        if not isinstance(self.status, OwnedPlanStatus):
            raise ValueError("Plan status must be recognized")
        object.__setattr__(self, "created_at", utc(self.created_at))
        object.__setattr__(self, "updated_at", utc(self.updated_at))
        if len(self.assumptions) > 32 or len(self.constraints) > 32:
            raise ValueError("Plan assumptions and constraints must be bounded")
        if any(
            not item.strip() or len(item) > 1_000 for item in (*self.assumptions, *self.constraints)
        ):
            raise ValueError("Plan assumptions and constraints must contain bounded text")
        if len(self.provenance) > 32 or any(
            not item.strip() or len(item) > 512 for item in self.provenance
        ):
            raise ValueError("Plan provenance must be bounded and non-empty")


@dataclass(frozen=True, slots=True)
class PlanningTask:
    """Durable single-agent task state and protected original constraints."""

    task_id: UUID
    goal: str
    original_assumptions: tuple[str, ...]
    original_constraints: tuple[str, ...]
    status: PlanningTaskStatus
    plan_id: UUID | None
    budgets: ExecutionBudgets
    usage: BudgetUsage
    created_at: datetime
    started_at: datetime
    deadline: datetime
    updated_at: datetime
    active_step_id: UUID | None = None
    waiting_request_ids: tuple[UUID, ...] = ()
    cancellation_requested: bool = False
    result_evidence: tuple[str, ...] = ()
    error: StepError | None = None

    def __post_init__(self) -> None:
        _bounded(self.goal, "Task goal")
        if not isinstance(self.status, PlanningTaskStatus):
            raise ValueError("Task status must be recognized")
        for field_name in ("created_at", "started_at", "deadline", "updated_at"):
            object.__setattr__(self, field_name, utc(getattr(self, field_name)))
        if self.deadline <= self.started_at:
            raise ValueError("Task deadline must follow its start time")
        if len(set(self.waiting_request_ids)) != len(self.waiting_request_ids):
            raise ValueError("Waiting permission request IDs must be unique")
        if len(self.original_assumptions) > 32 or len(self.original_constraints) > 32:
            raise ValueError("Task assumptions and constraints must be bounded")
        if any(
            not item.strip() or len(item) > 1_000
            for item in (*self.original_assumptions, *self.original_constraints)
        ):
            raise ValueError("Task assumptions and constraints must contain bounded text")


@dataclass(frozen=True, slots=True)
class StepExecutionResult:
    status: StepExecutionStatus
    output_json: str = "{}"
    evidence: tuple[str, ...] = ()
    error_code: str | None = None
    error_message: str | None = None
    approval_request_ids: tuple[UUID, ...] = ()
    effect_outcome: EffectOutcome | None = None

    def __post_init__(self) -> None:
        if not isinstance(self.status, StepExecutionStatus):
            raise ValueError("Execution status must be recognized")
        if self.effect_outcome is not None and not isinstance(self.effect_outcome, EffectOutcome):
            raise ValueError("Effect outcome must be recognized")
        if self.effect_outcome is None:
            default_outcome = {
                StepExecutionStatus.SUCCEEDED: EffectOutcome.EFFECT_CONFIRMED,
                StepExecutionStatus.TRANSIENT_FAILURE: EffectOutcome.SAFE_TO_RETRY,
                StepExecutionStatus.WAITING_FOR_PERMISSION: EffectOutcome.PRE_EFFECT_FAILURE,
                StepExecutionStatus.DETERMINISTIC_FAILURE: EffectOutcome.PRE_EFFECT_FAILURE,
                StepExecutionStatus.CANCELLED: EffectOutcome.UNKNOWN_OUTCOME,
                StepExecutionStatus.UNKNOWN_OUTCOME: EffectOutcome.UNKNOWN_OUTCOME,
            }[self.status]
            object.__setattr__(self, "effect_outcome", default_outcome)
        try:
            json.loads(self.output_json)
        except json.JSONDecodeError as error:
            raise ValueError("Execution output must be valid JSON") from error
        if self.status is StepExecutionStatus.WAITING_FOR_PERMISSION:
            if not self.approval_request_ids:
                raise ValueError("Permission pauses require broker approval request IDs")
        elif self.approval_request_ids:
            raise ValueError("Approval request IDs are valid only for permission pauses")
        if len(self.evidence) > 32 or any(len(item) > 1_000 for item in self.evidence):
            raise ValueError("Execution evidence must be bounded")


@dataclass(frozen=True, slots=True)
class StepVerification:
    succeeded: bool
    evidence: tuple[str, ...]
    reason: str


@dataclass(frozen=True, slots=True)
class GoalVerification:
    succeeded: bool
    evidence: tuple[str, ...]
    reason: str


@dataclass(frozen=True, slots=True)
class ReplanEvidence:
    original_goal: str
    original_assumptions: tuple[str, ...]
    original_constraints: tuple[str, ...]
    failed_step_key: str
    error: StepError
    observed_evidence: tuple[str, ...]
    prior_plan_version: int
