"""Focused R3E-F context partition and trusted projection proofs."""

from __future__ import annotations

from dataclasses import FrozenInstanceError
from datetime import UTC, datetime, timedelta
from typing import cast
from uuid import uuid4

import pytest
from jarvis.actor_persona import PersonaProfile
from jarvis.agent_runtime import AgentContext, ContextManager
from jarvis.ai.models import MessageRole, PrivacyClassification, PrivacyContext
from jarvis.ai.providers import ProviderLocality, ProviderMetadata
from jarvis.context_projection import (
    ConversationContextEnvelope,
    OrchestrationContextEnvelope,
    ProgressProjection,
    ProgressState,
    ResultState,
    RoleContextProjector,
    TrustedExecutionMetadata,
    WorkerContextEnvelope,
    project_progress,
    project_result,
)
from jarvis.conversation.service import ConversationService
from jarvis.goal_scheduler import GoalScheduleStatus, GoalScheduleView
from jarvis.goal_supervisor import GoalBudget, GoalIntent, GoalStatus, GoalSupervisorState
from jarvis.planning.models import (
    BudgetUsage,
    ExecutionBudgets,
    FailureKind,
    OwnedPlan,
    OwnedPlanStatus,
    PlanningStep,
    PlanningStepStatus,
    PlanningTask,
    PlanningTaskStatus,
    StepError,
    StepResult,
)

from tests.fakes import FakeAIProvider


def _plan_and_task(
    *,
    step_status: PlanningStepStatus = PlanningStepStatus.SUCCEEDED,
    task_status: PlanningTaskStatus = PlanningTaskStatus.COMPLETED,
    goal_status: GoalStatus = GoalStatus.COMPLETED,
    error: StepError | None = None,
) -> tuple[GoalSupervisorState, PlanningTask, OwnedPlan]:
    goal_id = uuid4()
    task_id = uuid4()
    step_id = uuid4()
    now = datetime.now(UTC)
    result = StepResult('{"value":"verified"}', ("verified-result",))
    step = PlanningStep(
        step_id,
        "prepare",
        "prepare",
        "prepare",
        '{"value":"verified"}',
        "verified",
        "evidence_contains_all",
        ("verified-result",),
        (),
        (),
        False,
        0,
        step_status,
        1 if step_status is PlanningStepStatus.SUCCEEDED else 0,
        result if step_status is PlanningStepStatus.SUCCEEDED else None,
    )
    plan = OwnedPlan(
        uuid4(),
        task_id,
        1,
        "trusted goal",
        (),
        (),
        (step,),
        ("prepare",),
        (),
        ("verified-result",),
        (
            OwnedPlanStatus.COMPLETED
            if task_status is PlanningTaskStatus.COMPLETED
            else OwnedPlanStatus.ACTIVE
        ),
        now,
        now,
    )
    task = PlanningTask(
        task_id,
        "trusted goal",
        (),
        (),
        task_status,
        plan.plan_id,
        ExecutionBudgets(),
        BudgetUsage(executed_steps=1 if step_status is PlanningStepStatus.SUCCEEDED else 0),
        now,
        now,
        now + timedelta(minutes=5),
        now,
        error=error,
    )
    goal = GoalSupervisorState(
        GoalIntent("trusted goal", goal_id=goal_id),
        GoalBudget(),
        goal_status,
        now,
        now,
        task_id=task_id,
    )
    return goal, task, plan


def test_role_envelopes_are_bounded_and_worker_has_no_history_surface() -> None:
    worker = RoleContextProjector.worker(
        uuid4(),
        uuid4(),
        '{"value":"CONVERSATION_SECRET_SENTINEL"}',
        "prepare",
        privacy_context=PrivacyContext(PrivacyClassification.LOCAL_ONLY),
    )
    assert isinstance(worker, WorkerContextEnvelope)
    assert "relevant_history" not in worker.model_payload()
    assert "CONVERSATION_SECRET_SENTINEL" in worker.model_text()
    with pytest.raises(ValueError):
        RoleContextProjector.worker(
            uuid4(), uuid4(), "x", "x", dependency_outputs=(("x", "y" * 4_001),)
        )


def test_serialized_worker_context_excludes_unrelated_conversation_goal_and_authority() -> None:
    worker = RoleContextProjector.worker(
        uuid4(),
        uuid4(),
        '{"value":"exact-step-input"}',
        "prepare",
        dependency_outputs=(("verified-input", "bounded"),),
        trusted_metadata=TrustedExecutionMetadata(
            routing_decision_id="AUTHORITY_SENTINEL",
            reservation_ids=(uuid4(),),
        ),
    )
    serialized = worker.model_text()
    assert "exact-step-input" in serialized
    assert "CONVERSATION_SECRET_SENTINEL" not in serialized
    assert "OTHER_GOAL_SENTINEL" not in serialized
    assert "AUTHORITY_SENTINEL" not in serialized
    assert "reservation_ids" not in serialized


def test_conversation_and_orchestration_boundaries_are_explicit() -> None:
    progress = ProgressProjection(
        uuid4(), ProgressState.WAITING_FOR_PERMISSION, pending_permission=True
    )
    conversation = RoleContextProjector.conversation(
        "what happened",
        relevant_history=("bounded prior turn",),
        selected_memory=("selected safe memory",),
        persona=PersonaProfile(verbosity=4),
        progress=(progress,),
        privacy_context=PrivacyContext(PrivacyClassification.LOCAL_ONLY),
        trusted_metadata=TrustedExecutionMetadata(routing_decision_id="AUTHORITY_SENTINEL"),
    )
    orchestration = RoleContextProjector.orchestration(
        "trusted goal",
        constraints=("hard constraint",),
        decomposition_summaries=("child completed",),
        trusted_metadata=TrustedExecutionMetadata(goal_id=uuid4()),
    )
    assert isinstance(conversation, ConversationContextEnvelope)
    assert isinstance(orchestration, OrchestrationContextEnvelope)
    persona = cast(dict[str, int], conversation.model_payload()["persona"])
    assert persona["verbosity"] == 4
    assert "AUTHORITY_SENTINEL" not in conversation.model_text()
    assert "relevant_history" not in orchestration.model_payload()
    assert orchestration.model_payload()["constraints"] == ("hard constraint",)
    assert conversation.privacy_context.classification is PrivacyClassification.LOCAL_ONLY


def test_persona_and_language_are_presentation_only_and_envelopes_are_immutable() -> None:
    first = RoleContextProjector.worker(uuid4(), uuid4(), "{}", "prepare")
    second = RoleContextProjector.worker(
        first.task_id,
        first.step_id,
        first.resolved_input_json,
        first.required_capability,
        privacy_context=PrivacyContext(PrivacyClassification.LOCAL_ONLY),
    )
    assert first.task_id == second.task_id
    assert first.required_capability == second.required_capability
    with pytest.raises(FrozenInstanceError):
        first.__setattr__("required_capability", "other")


def test_context_manager_remains_the_capacity_and_compaction_owner() -> None:
    context = AgentContext(
        "turn",
        "goal",
        provider_context_limit=512,
        reserved_output=64,
        privacy_context=PrivacyContext(PrivacyClassification.LOCAL_ONLY),
    )
    manager = ContextManager()
    request = manager.prepare(
        context,
        (),
        conversation_id=uuid4(),
        model="local",
        context_limit=512,
    )
    assert request.context_limit == 512
    assert request.privacy_context.classification is PrivacyClassification.LOCAL_ONLY


def test_progress_maps_scheduler_states_and_keeps_goal_ids_distinct() -> None:
    first_id, second_id = uuid4(), uuid4()
    now = datetime.now(UTC)
    queued = GoalScheduleView(first_id, GoalScheduleStatus.QUEUED, 1, now)
    waiting = GoalScheduleView(
        second_id,
        GoalScheduleStatus.SUSPENDED,
        2,
        now,
        goal_status=GoalStatus.WAITING_FOR_PERMISSION,
        task_id=uuid4(),
    )
    first = project_progress(first_id, scheduler=queued)
    second = project_progress(second_id, scheduler=waiting, pending_permission=True)
    assert first.state is ProgressState.QUEUED
    assert second.state is ProgressState.WAITING_FOR_PERMISSION
    assert first.goal_id != second.goal_id
    assert second.task_id == waiting.task_id


def test_progress_step_count_is_verified_success_only() -> None:
    goal, task, plan = _plan_and_task()
    projection = project_progress(goal.intent.goal_id, goal=goal, task=task, plan=plan)
    assert projection.state is ProgressState.COMPLETED
    assert (projection.completed_steps, projection.total_steps) == (1, 1)
    _, running_task, running_plan = _plan_and_task(
        step_status=PlanningStepStatus.RUNNING,
        task_status=PlanningTaskStatus.EXECUTING,
        goal_status=GoalStatus.EXECUTING,
    )
    running = project_progress(goal.intent.goal_id, task=running_task, plan=running_plan)
    assert running.completed_steps == 0


def test_progress_recovering_is_explicit_and_not_collapsed() -> None:
    goal, task, plan = _plan_and_task(
        step_status=PlanningStepStatus.FAILED,
        task_status=PlanningTaskStatus.RECOVERING,
        goal_status=GoalStatus.RECOVERING,
        error=StepError("unknown", "unknown effect", FailureKind.UNKNOWN_OUTCOME),
    )
    projection = project_progress(goal.intent.goal_id, goal=goal, task=task, plan=plan)
    assert projection.state is ProgressState.RECOVERING
    assert projection.terminal
    assert "uncertain" in (projection.reason or "")


def test_verified_result_requires_terminal_verified_task_and_goal() -> None:
    goal, task, plan = _plan_and_task()
    result = project_result(goal, task, plan)
    assert result.state is ResultState.SUCCESS
    assert result.verified
    assert "verified-result" in result.evidence
    failed_goal, failed_task, failed_plan = _plan_and_task(goal_status=GoalStatus.FAILED)
    failed = project_result(failed_goal, failed_task, failed_plan)
    assert failed.state is ResultState.FAILURE
    assert not failed.verified


def test_unknown_outcome_cannot_project_success_or_cancelled_certainty() -> None:
    goal, task, plan = _plan_and_task(
        task_status=PlanningTaskStatus.RECOVERING,
        goal_status=GoalStatus.RECOVERING,
        error=StepError("unknown", "effect uncertain", FailureKind.UNKNOWN_OUTCOME),
    )
    result = project_result(goal, task, plan)
    assert result.state is ResultState.RECOVERING
    assert result.uncertain
    assert not result.verified


@pytest.mark.asyncio
async def test_conversation_receives_safe_progress_without_trusted_metadata() -> None:
    provider = FakeAIProvider(("ack",))
    service = ConversationService(
        provider,
        model="local-model",
        context_limit=1024,
        provider_metadata=ProviderMetadata(
            "local", "Local", "test", locality=ProviderLocality.LOCAL
        ),
    )
    conversation_id = service.create_conversation()
    context = RoleContextProjector.conversation(
        "show progress",
        progress=(ProgressProjection(uuid4(), ProgressState.EXECUTING),),
        trusted_metadata=TrustedExecutionMetadata(routing_decision_id="AUTHORITY_SENTINEL"),
        privacy_context=PrivacyContext(PrivacyClassification.LOCAL_ONLY),
    )
    updates = [
        item
        async for item in service.stream_reply(conversation_id, "show progress", context=context)
    ]
    assert "".join(item.content for item in updates) == "ack"
    serialized = provider.requests[0].messages[0].content
    assert "executing" in serialized
    assert "AUTHORITY_SENTINEL" not in serialized
    assert service.history(conversation_id)[-1].role is MessageRole.ASSISTANT


def test_raw_model_orchestration_facts_are_not_result_authority() -> None:
    goal, task, plan = _plan_and_task(goal_status=GoalStatus.BLOCKED)
    result = project_result(goal, task, plan)
    assert result.state is ResultState.BLOCKED
    assert not isinstance(result, str)
