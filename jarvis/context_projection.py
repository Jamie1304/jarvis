"""Least-context role envelopes and trusted user-facing projections.

This module is deliberately a projection boundary.  It owns neither provider
selection nor persistence and never treats model output as lifecycle truth.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from enum import StrEnum
from typing import TYPE_CHECKING
from uuid import UUID

from jarvis.actor_persona import PersonaProfile
from jarvis.ai.models import PrivacyContext
from jarvis.goal_scheduler import GoalScheduleStatus, GoalScheduleView
from jarvis.goal_supervisor import GoalStatus, GoalSupervisorState
from jarvis.planning.models import (
    OwnedPlan,
    PlanningStepStatus,
    PlanningTask,
    PlanningTaskStatus,
)

if TYPE_CHECKING:
    from jarvis.agent_runtime import AgentContext

_MAX_ITEMS = 32
_MAX_TEXT = 4_000


def _bounded_text(value: str, field: str, limit: int = _MAX_TEXT) -> str:
    if type(value) is not str or not value.strip() or len(value) > limit or "\x00" in value:
        raise ValueError(f"{field} is malformed or unbounded")
    return value


def _bounded_strings(values: tuple[str, ...], field: str, limit: int = _MAX_ITEMS) -> None:
    if type(values) is not tuple or len(values) > limit:
        raise ValueError(f"{field} are malformed or unbounded")
    for value in values:
        _bounded_text(value, field)


@dataclass(frozen=True, slots=True)
class TrustedExecutionMetadata:
    """Application-only correlation facts; never included by model payloads."""

    conversation_id: UUID | None = None
    goal_id: UUID | None = None
    task_id: UUID | None = None
    plan_id: UUID | None = None
    step_id: UUID | None = None
    orchestration_attempt_id: UUID | None = None
    routing_decision_id: str | None = None
    approval_request_ids: tuple[UUID, ...] = ()
    reservation_ids: tuple[UUID, ...] = ()

    def __post_init__(self) -> None:
        if any(
            value is not None and not isinstance(value, UUID)
            for value in (
                self.conversation_id,
                self.goal_id,
                self.task_id,
                self.plan_id,
                self.step_id,
                self.orchestration_attempt_id,
            )
        ):
            raise ValueError("Trusted execution identity is malformed")
        for name, values in (
            ("approval request IDs", self.approval_request_ids),
            ("reservation IDs", self.reservation_ids),
        ):
            if (
                type(values) is not tuple
                or len(values) > _MAX_ITEMS
                or any(not isinstance(value, UUID) for value in values)
            ):
                raise ValueError(f"Trusted {name} are malformed")
        if self.routing_decision_id is not None:
            _bounded_text(self.routing_decision_id, "Routing decision ID", 256)


@dataclass(frozen=True, slots=True)
class ConversationContextEnvelope:
    """Bounded facts permitted for one Conversation Model turn."""

    user_turn: str
    relevant_history: tuple[str, ...] = ()
    selected_memory: tuple[str, ...] = ()
    persona: PersonaProfile = PersonaProfile()
    locale: str | None = None
    output_preferences: tuple[str, ...] = ()
    progress: tuple[ProgressProjection, ...] = ()
    result: tuple[ResultProjection, ...] = ()
    privacy_context: PrivacyContext = field(default_factory=PrivacyContext)
    trusted_metadata: TrustedExecutionMetadata = field(default_factory=TrustedExecutionMetadata)

    def __post_init__(self) -> None:
        _bounded_text(self.user_turn, "Conversation user turn")
        _bounded_strings(self.relevant_history, "Conversation history")
        _bounded_strings(self.selected_memory, "Selected memory")
        _bounded_strings(self.output_preferences, "Output preferences")
        if len(self.progress) > _MAX_ITEMS or len(self.result) > _MAX_ITEMS:
            raise ValueError("Conversation projections are unbounded")
        if not isinstance(self.persona, PersonaProfile):
            raise ValueError("Conversation persona is malformed")
        if self.locale is not None:
            _bounded_text(self.locale, "Conversation locale", 64)
        if not isinstance(self.privacy_context, PrivacyContext):
            raise ValueError("Conversation privacy context is malformed")
        if not isinstance(self.trusted_metadata, TrustedExecutionMetadata):
            raise ValueError("Conversation trusted metadata is malformed")

    def model_payload(self) -> dict[str, object]:
        """Return serializable, model-visible facts without trusted metadata."""

        return {
            "user_turn": self.user_turn,
            "relevant_history": self.relevant_history,
            "selected_memory": self.selected_memory,
            "persona": self.persona.as_dict(),
            "locale": self.locale,
            "output_preferences": self.output_preferences,
            "progress": tuple(item.model_payload() for item in self.progress),
            "result": tuple(item.model_payload() for item in self.result),
            "privacy_classification": self.privacy_context.classification.value,
        }

    def model_text(self) -> str:
        return json.dumps(self.model_payload(), sort_keys=True, separators=(",", ":"))


@dataclass(frozen=True, slots=True)
class OrchestrationContextEnvelope:
    """Goal-scoped orchestration facts without ordinary conversation history."""

    goal: str
    assumptions: tuple[str, ...] = ()
    constraints: tuple[str, ...] = ()
    decomposition_summaries: tuple[str, ...] = ()
    failure_evidence: tuple[str, ...] = ()
    capabilities: tuple[str, ...] = ()
    completion_requirements: tuple[str, ...] = ()
    budget_summary: tuple[str, ...] = ()
    privacy_context: PrivacyContext = field(default_factory=PrivacyContext)
    trusted_metadata: TrustedExecutionMetadata = field(default_factory=TrustedExecutionMetadata)

    def __post_init__(self) -> None:
        _bounded_text(self.goal, "Orchestration goal")
        for name in (
            "assumptions",
            "constraints",
            "decomposition_summaries",
            "failure_evidence",
            "capabilities",
            "completion_requirements",
            "budget_summary",
        ):
            _bounded_strings(getattr(self, name), name)
        if not isinstance(self.privacy_context, PrivacyContext):
            raise ValueError("Orchestration privacy context is malformed")

    def model_payload(self) -> dict[str, object]:
        return {
            "goal": self.goal,
            "assumptions": self.assumptions,
            "constraints": self.constraints,
            "decomposition_summaries": self.decomposition_summaries,
            "failure_evidence": self.failure_evidence,
            "capabilities": self.capabilities,
            "completion_requirements": self.completion_requirements,
            "budget_summary": self.budget_summary,
            "privacy_classification": self.privacy_context.classification.value,
        }


@dataclass(frozen=True, slots=True)
class WorkerContextEnvelope:
    """Narrow step context; it has no conversation-history field by design."""

    task_id: UUID
    step_id: UUID
    resolved_input_json: str
    required_capability: str
    verification_expectation: tuple[str, ...] = ()
    dependency_outputs: tuple[tuple[str, str], ...] = ()
    privacy_context: PrivacyContext = field(default_factory=PrivacyContext)
    trusted_metadata: TrustedExecutionMetadata = field(default_factory=TrustedExecutionMetadata)

    def __post_init__(self) -> None:
        if not isinstance(self.task_id, UUID) or not isinstance(self.step_id, UUID):
            raise ValueError("Worker identity is malformed")
        _bounded_text(self.resolved_input_json, "Resolved worker input", 16_000)
        _bounded_text(self.required_capability, "Worker capability", 256)
        _bounded_strings(self.verification_expectation, "Worker verification expectation")
        if type(self.dependency_outputs) is not tuple or len(self.dependency_outputs) > _MAX_ITEMS:
            raise ValueError("Worker dependency outputs are unbounded")
        for key, value in self.dependency_outputs:
            _bounded_text(key, "Worker dependency key", 256)
            _bounded_text(value, "Worker dependency output", 4_000)
        if not isinstance(self.privacy_context, PrivacyContext):
            raise ValueError("Worker privacy context is malformed")

    def model_payload(self) -> dict[str, object]:
        return {
            "task_id": str(self.task_id),
            "step_id": str(self.step_id),
            "resolved_input_json": self.resolved_input_json,
            "required_capability": self.required_capability,
            "verification_expectation": self.verification_expectation,
            "dependency_outputs": self.dependency_outputs,
            "privacy_classification": self.privacy_context.classification.value,
        }

    def model_text(self) -> str:
        return json.dumps(self.model_payload(), sort_keys=True, separators=(",", ":"))

    def to_agent_context(
        self,
        *,
        provider_context_limit: int = 4_096,
        reserved_output: int = 1_024,
    ) -> AgentContext:
        """Adapt one worker envelope into the existing AgentLoop seam."""

        from jarvis.agent_runtime import AgentContext

        return AgentContext(
            request=self.resolved_input_json,
            goal=self.required_capability,
            current_step=str(self.step_id),
            evidence=self.verification_expectation,
            tool_outputs=tuple(value for _, value in self.dependency_outputs),
            provider_context_limit=provider_context_limit,
            reserved_output=reserved_output,
            privacy_context=self.privacy_context,
            task_class="worker",
            responsibility="worker",
        )


class ProgressState(StrEnum):
    QUEUED = "queued"
    ANALYZING = "analyzing"
    PLANNING = "planning"
    EXECUTING = "executing"
    WAITING_FOR_PERMISSION = "waiting_for_permission"
    VERIFYING = "verifying"
    REPLANNING = "replanning"
    RECOVERING = "recovering"
    COMPLETED = "completed"
    BLOCKED = "blocked"
    FAILED = "failed"
    CANCELLED = "cancelled"
    BUDGET_EXHAUSTED = "budget_exhausted"


@dataclass(frozen=True, slots=True)
class ProgressProjection:
    """User-explainable lifecycle facts derived only from trusted state."""

    goal_id: UUID
    state: ProgressState
    task_id: UUID | None = None
    completed_steps: int = 0
    total_steps: int = 0
    pending_permission: bool = False
    terminal: bool = False
    reason: str | None = None

    def __post_init__(self) -> None:
        if not isinstance(self.goal_id, UUID) or (
            self.task_id is not None and not isinstance(self.task_id, UUID)
        ):
            raise ValueError("Progress identity is malformed")
        if (
            self.completed_steps < 0
            or self.total_steps < 0
            or self.completed_steps > self.total_steps
        ):
            raise ValueError("Progress step counts are invalid")
        if type(self.pending_permission) is not bool or type(self.terminal) is not bool:
            raise ValueError("Progress flags are invalid")
        if self.reason is not None:
            _bounded_text(self.reason, "Progress reason", 512)

    def model_payload(self) -> dict[str, object]:
        return {
            "goal_id": str(self.goal_id),
            "state": self.state.value,
            "task_id": str(self.task_id) if self.task_id is not None else None,
            "completed_steps": self.completed_steps,
            "total_steps": self.total_steps,
            "pending_permission": self.pending_permission,
            "terminal": self.terminal,
            "reason": self.reason,
        }


class ResultState(StrEnum):
    SUCCESS = "success"
    FAILURE = "failure"
    RECOVERING = "recovering"
    CANCELLED = "cancelled"
    BLOCKED = "blocked"
    BUDGET_EXHAUSTED = "budget_exhausted"


@dataclass(frozen=True, slots=True)
class ResultProjection:
    """Safe result facts; success requires trusted terminal verification."""

    goal_id: UUID
    state: ResultState
    verified: bool
    uncertain: bool
    evidence: tuple[str, ...] = ()
    reason: str | None = None

    def __post_init__(self) -> None:
        if not isinstance(self.goal_id, UUID) or type(self.verified) is not bool:
            raise ValueError("Result projection is malformed")
        if type(self.uncertain) is not bool:
            raise ValueError("Result uncertainty is malformed")
        _bounded_strings(self.evidence, "Result evidence")
        if self.reason is not None:
            _bounded_text(self.reason, "Result reason", 512)

    def model_payload(self) -> dict[str, object]:
        return {
            "goal_id": str(self.goal_id),
            "state": self.state.value,
            "verified": self.verified,
            "uncertain": self.uncertain,
            "evidence": self.evidence,
            "reason": self.reason,
        }


class RoleContextProjector:
    """Deterministic role partitioning without provider or persistence authority."""

    @staticmethod
    def conversation(
        user_turn: str,
        *,
        relevant_history: tuple[str, ...] = (),
        selected_memory: tuple[str, ...] = (),
        persona: PersonaProfile | None = None,
        locale: str | None = None,
        output_preferences: tuple[str, ...] = (),
        progress: tuple[ProgressProjection, ...] = (),
        result: tuple[ResultProjection, ...] = (),
        privacy_context: PrivacyContext | None = None,
        trusted_metadata: TrustedExecutionMetadata | None = None,
    ) -> ConversationContextEnvelope:
        return ConversationContextEnvelope(
            user_turn,
            relevant_history,
            selected_memory,
            persona or PersonaProfile.defaults(),
            locale,
            output_preferences,
            progress,
            result,
            privacy_context or PrivacyContext(),
            trusted_metadata or TrustedExecutionMetadata(),
        )

    @staticmethod
    def orchestration(
        goal: str,
        *,
        assumptions: tuple[str, ...] = (),
        constraints: tuple[str, ...] = (),
        decomposition_summaries: tuple[str, ...] = (),
        failure_evidence: tuple[str, ...] = (),
        capabilities: tuple[str, ...] = (),
        completion_requirements: tuple[str, ...] = (),
        budget_summary: tuple[str, ...] = (),
        privacy_context: PrivacyContext | None = None,
        trusted_metadata: TrustedExecutionMetadata | None = None,
    ) -> OrchestrationContextEnvelope:
        return OrchestrationContextEnvelope(
            goal,
            assumptions,
            constraints,
            decomposition_summaries,
            failure_evidence,
            capabilities,
            completion_requirements,
            budget_summary,
            privacy_context or PrivacyContext(),
            trusted_metadata or TrustedExecutionMetadata(),
        )

    @staticmethod
    def worker(
        task_id: UUID,
        step_id: UUID,
        resolved_input_json: str,
        required_capability: str,
        *,
        verification_expectation: tuple[str, ...] = (),
        dependency_outputs: tuple[tuple[str, str], ...] = (),
        privacy_context: PrivacyContext | None = None,
        trusted_metadata: TrustedExecutionMetadata | None = None,
    ) -> WorkerContextEnvelope:
        return WorkerContextEnvelope(
            task_id,
            step_id,
            resolved_input_json,
            required_capability,
            verification_expectation,
            dependency_outputs,
            privacy_context or PrivacyContext(),
            trusted_metadata or TrustedExecutionMetadata(),
        )


def _state_from_goal(status: GoalStatus) -> ProgressState:
    return ProgressState(status.value)


def _state_from_task(status: PlanningTaskStatus) -> ProgressState:
    mapping = {
        PlanningTaskStatus.CREATED: ProgressState.PLANNING,
        PlanningTaskStatus.PLANNING: ProgressState.PLANNING,
        PlanningTaskStatus.READY: ProgressState.PLANNING,
        PlanningTaskStatus.EXECUTING: ProgressState.EXECUTING,
        PlanningTaskStatus.WAITING_FOR_PERMISSION: ProgressState.WAITING_FOR_PERMISSION,
        PlanningTaskStatus.VERIFYING: ProgressState.VERIFYING,
        PlanningTaskStatus.REPLANNING: ProgressState.REPLANNING,
        PlanningTaskStatus.RECOVERING: ProgressState.RECOVERING,
        PlanningTaskStatus.COMPLETED: ProgressState.COMPLETED,
        PlanningTaskStatus.FAILED: ProgressState.FAILED,
        PlanningTaskStatus.CANCELLED: ProgressState.CANCELLED,
        PlanningTaskStatus.BUDGET_EXHAUSTED: ProgressState.BUDGET_EXHAUSTED,
    }
    return mapping[status]


def project_progress(
    goal_id: UUID,
    *,
    scheduler: GoalScheduleView | None = None,
    goal: GoalSupervisorState | None = None,
    task: PlanningTask | None = None,
    plan: OwnedPlan | None = None,
    pending_permission: bool = False,
) -> ProgressProjection:
    """Project one goal without consulting model output or event history."""

    if scheduler is not None and scheduler.goal_id != goal_id:
        raise ValueError("Scheduler goal identity does not match projection")
    if goal is not None and goal.intent.goal_id != goal_id:
        raise ValueError("Supervisor goal identity does not match projection")
    if task is not None and task.task_id != (goal.task_id if goal is not None else task.task_id):
        if goal is not None and goal.task_id != task.task_id:
            raise ValueError("Planning task identity does not match projection")
    task_id = (
        task.task_id
        if task is not None
        else goal.task_id
        if goal is not None
        else scheduler.task_id
        if scheduler
        else None
    )
    if task is not None:
        state = _state_from_task(task.status)
    elif goal is not None:
        state = _state_from_goal(goal.status)
    elif scheduler is not None:
        if scheduler.status is GoalScheduleStatus.QUEUED:
            state = ProgressState.QUEUED
        elif scheduler.status is GoalScheduleStatus.RUNNING:
            state = ProgressState.EXECUTING
        elif scheduler.status is GoalScheduleStatus.SUSPENDED:
            state = ProgressState.WAITING_FOR_PERMISSION
        else:
            state = (
                ProgressState.CANCELLED
                if scheduler.cancellation_requested
                else ProgressState.FAILED
            )
    else:
        raise ValueError("Trusted progress source is required")
    if pending_permission or state is ProgressState.WAITING_FOR_PERMISSION:
        state = ProgressState.WAITING_FOR_PERMISSION
    completed = (
        sum(step.status is PlanningStepStatus.SUCCEEDED for step in plan.steps) if plan else 0
    )
    total = len(plan.steps) if plan else 0
    terminal = state in {
        ProgressState.COMPLETED,
        ProgressState.BLOCKED,
        ProgressState.RECOVERING,
        ProgressState.FAILED,
        ProgressState.CANCELLED,
        ProgressState.BUDGET_EXHAUSTED,
    }
    reason = {
        ProgressState.WAITING_FOR_PERMISSION: (
            "Permission is required before execution can continue."
        ),
        ProgressState.RECOVERING: (
            "Operator resolution is required because the effect outcome is uncertain."
        ),
        ProgressState.CANCELLED: "The goal was cancelled by trusted application state.",
    }.get(state)
    return ProgressProjection(
        goal_id,
        state,
        task_id,
        completed,
        total,
        pending_permission or state is ProgressState.WAITING_FOR_PERMISSION,
        terminal,
        reason,
    )


def project_result(
    goal: GoalSupervisorState,
    task: PlanningTask,
    plan: OwnedPlan | None,
) -> ResultProjection:
    """Project a result only from trusted terminal task/goal and verified plan state."""

    if goal.intent.goal_id is None:
        raise ValueError("Goal identity is malformed")
    if goal.task_id != task.task_id:
        raise ValueError("Goal/task identity does not match result")
    unknown = goal.status is GoalStatus.RECOVERING or (
        task.error is not None and task.error.failure_kind.value == "unknown_outcome"
    )
    if unknown:
        return ResultProjection(
            goal.intent.goal_id,
            ResultState.RECOVERING,
            False,
            True,
            reason="The effect outcome is uncertain; operator resolution is required.",
        )
    verified = (
        goal.status is GoalStatus.COMPLETED
        and task.status is PlanningTaskStatus.COMPLETED
        and plan is not None
        and bool(plan.steps)
        and all(step.status is PlanningStepStatus.SUCCEEDED for step in plan.steps)
    )
    if verified:
        assert plan is not None
        evidence = tuple(
            item for step in plan.steps if step.result is not None for item in step.result.evidence
        )
        return ResultProjection(goal.intent.goal_id, ResultState.SUCCESS, True, False, evidence)
    state = {
        GoalStatus.CANCELLED: ResultState.CANCELLED,
        GoalStatus.BLOCKED: ResultState.BLOCKED,
        GoalStatus.BUDGET_EXHAUSTED: ResultState.BUDGET_EXHAUSTED,
    }.get(goal.status, ResultState.FAILURE)
    return ResultProjection(
        goal.intent.goal_id,
        state,
        False,
        False,
        reason="Trusted verification did not establish a successful terminal result.",
    )


__all__ = [
    "ConversationContextEnvelope",
    "OrchestrationContextEnvelope",
    "ProgressProjection",
    "ProgressState",
    "RoleContextProjector",
    "ResultProjection",
    "ResultState",
    "TrustedExecutionMetadata",
    "WorkerContextEnvelope",
    "project_progress",
    "project_result",
]
