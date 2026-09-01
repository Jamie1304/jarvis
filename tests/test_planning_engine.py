"""Deterministic control-plane tests for durable single-agent DAG planning."""

from __future__ import annotations

import asyncio
import json
import math
from collections.abc import Mapping, Sequence
from dataclasses import dataclass, replace
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import cast
from uuid import uuid4

import pytest
from jarvis.permissions.approval import TrustedApprovalAuthenticator
from jarvis.permissions.broker import PermissionBroker
from jarvis.permissions.models import (
    ActionDescriptor,
    ApprovalActorKind,
    ApprovalChoice,
    ApprovalIdentity,
    ApprovalSource,
    ApprovalStatus,
    Decision,
    DecisionReason,
    Permission,
    PermissionRequest,
    PermissionScope,
    PolicyRule,
    Risk,
    ScopeConstraint,
)
from jarvis.permissions.policy import PolicyEngine
from jarvis.planning import (
    BrokeredPlanningStepExecutor,
    BudgetUsage,
    CompletionCriteriaVerifier,
    EvidencePlanningStepVerifier,
    ExecutionBudgets,
    FailureKind,
    GoalVerification,
    OwnedPlanStatus,
    PlanAdvisor,
    PlanEdit,
    PlanEditError,
    PlanningEngine,
    PlanningEngineError,
    PlanningGoalVerifier,
    PlanningMigration,
    PlanningStep,
    PlanningStepExecutor,
    PlanningStepStatus,
    PlanningStoreError,
    PlanningTask,
    PlanningTaskStatus,
    PlanStepSpec,
    PlanValidationError,
    PlanValidator,
    ReplanEvidence,
    SQLitePlanningStore,
    StepError,
    StepExecutionResult,
    StepExecutionStatus,
    StepResult,
    StructuredStepEdit,
)
from jarvis.state import ApplicationStateMachine, TaskState, TransitionEvent
from jarvis.task_controller import PlanningTaskController
from jarvis.tools.base import Tool
from jarvis.tools.models import (
    SemanticVersion,
    ToolEvidence,
    ToolExecutionContext,
    ToolManifest,
    ToolPlatform,
    ToolResult,
    ToolResultStatus,
)
from jarvis.tools.registry import ToolRegistry
from pydantic import BaseModel, ConfigDict


class _Input(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)

    value: str


class _Output(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)

    value: str


class _Tool(Tool[_Input, _Output]):
    def __init__(self, tool_id: str, permissions: frozenset[Permission] = frozenset()) -> None:
        self._tool_id = tool_id
        self._permissions = permissions

    @property
    def manifest(self) -> ToolManifest:
        return ToolManifest(
            tool_id=self._tool_id,
            name=self._tool_id,
            description="Deterministic planning test tool",
            version=SemanticVersion(1, 0, 0),
            capability_tags=frozenset({self._tool_id}),
            input_schema=_Input,
            output_schema=_Output,
            declared_permissions=self._permissions,
            supported_platforms=frozenset(
                {ToolPlatform.WINDOWS, ToolPlatform.LINUX, ToolPlatform.MACOS}
            ),
            timeout_seconds=1,
        )

    @property
    def input_model(self) -> type[_Input]:
        return _Input

    async def _execute_authorized(
        self, context: ToolExecutionContext, validated_input: _Input
    ) -> ToolResult:
        del context
        return ToolResult.success(_Output(value=validated_input.value))


class _ResultTool(_Tool):
    def __init__(self, result: ToolResult) -> None:
        super().__init__("result-tool")
        self._result = result

    async def _execute_authorized(
        self, context: ToolExecutionContext, validated_input: _Input
    ) -> ToolResult:
        del context, validated_input
        return self._result


class _PermissionTool(_Tool):
    def __init__(self, root: Path) -> None:
        super().__init__("protected", frozenset({Permission.FILESYSTEM_READ}))
        self._root = root
        self.executed = False

    def _describe_action(
        self, context: ToolExecutionContext, validated_input: _Input
    ) -> ActionDescriptor:
        del validated_input
        return ActionDescriptor(
            action="invoke:protected",
            arguments_summary=(),
            risk=Risk.LOW,
            permissions=(
                PermissionRequest(
                    Permission.FILESYSTEM_READ,
                    PermissionScope(
                        paths=(str(self._root),),
                        tool_id="protected",
                        task_id=context.task_id,
                    ),
                ),
            ),
        )

    async def _execute_authorized(
        self, context: ToolExecutionContext, validated_input: _Input
    ) -> ToolResult:
        self.executed = True
        result = await super()._execute_authorized(context, validated_input)
        return replace(result, evidence=(ToolEvidence("test", "protected-ready"),))


class _Advisor(PlanAdvisor):
    def __init__(self, proposals: Sequence[object]) -> None:
        self._proposals = iter(proposals)
        self.replan_evidence: list[ReplanEvidence] = []

    async def propose(
        self, goal: str, assumptions: tuple[str, ...], constraints: tuple[str, ...]
    ) -> object:
        del goal, assumptions, constraints
        return next(self._proposals)

    async def replan(self, evidence: ReplanEvidence) -> object:
        self.replan_evidence.append(evidence)
        return next(self._proposals)


class _Executor(PlanningStepExecutor):
    def __init__(self, results: Sequence[StepExecutionResult]) -> None:
        self._results = iter(results)
        self.calls: list[str] = []

    async def execute(
        self, task: PlanningTask, step: PlanningStep, cancellation: asyncio.Event
    ) -> StepExecutionResult:
        del task, cancellation
        self.calls.append(step.key)
        return next(self._results)


class _BlockingExecutor(PlanningStepExecutor):
    def __init__(self) -> None:
        self.started = asyncio.Event()

    async def execute(
        self, task: PlanningTask, step: PlanningStep, cancellation: asyncio.Event
    ) -> StepExecutionResult:
        del task, step
        self.started.set()
        await cancellation.wait()
        return StepExecutionResult(StepExecutionStatus.CANCELLED)


class _RejectGoal(PlanningGoalVerifier):
    async def verify(self, task: PlanningTask, plan: object) -> GoalVerification:
        del task, plan
        return GoalVerification(False, ("steps-finished",), "Meeting readiness not observed")


class _Clock:
    def __init__(self) -> None:
        self.value = datetime(2026, 8, 11, 12, tzinfo=UTC)

    def __call__(self) -> datetime:
        return self.value


@dataclass(frozen=True)
class _Harness:
    store: SQLitePlanningStore
    advisor: _Advisor
    executor: PlanningStepExecutor
    engine: PlanningEngine


def _result(*evidence: str) -> StepExecutionResult:
    return StepExecutionResult(
        StepExecutionStatus.SUCCEEDED,
        output_json='{"value":"ok"}',
        evidence=evidence,
    )


def _step(
    key: str,
    *,
    dependencies: list[str] | None = None,
    permissions: list[str] | None = None,
    retries: int = 0,
    expensive: bool = False,
) -> dict[str, object]:
    return {
        "key": key,
        "tool_id": key,
        "capability": key,
        "input": {"value": key},
        "dependencies": dependencies or [],
        "required_permissions": permissions or [],
        "expected_output": f"{key} prepared",
        "verification_rule": "evidence_contains_all",
        "expected_evidence": [f"{key}-ready"],
        "expensive_action": expensive,
        "max_retries": retries,
    }


def _plan(
    *steps: dict[str, object],
    goal: str = "Prepare my system for a meeting",
    assumptions: list[str] | None = None,
    constraints: list[str] | None = None,
) -> dict[str, object]:
    capabilities = sorted({str(step["capability"]) for step in steps})
    permission_values: set[str] = set()
    for step in steps:
        raw_permissions = step["required_permissions"]
        assert isinstance(raw_permissions, list)
        permission_values.update(str(permission) for permission in raw_permissions)
    permissions = sorted(permission_values)
    return {
        "goal": goal,
        "assumptions": assumptions or [],
        "constraints": constraints or [],
        "required_capabilities": capabilities,
        "required_permissions": permissions,
        "completion_criteria": [f"{step['key']}-ready" for step in steps],
        "steps": list(steps),
    }


def _harness(
    tmp_path: Path,
    proposals: Sequence[object],
    results: Sequence[StepExecutionResult],
    *,
    tools: tuple[_Tool, ...] = (_Tool("prepare"),),
    goal_verifier: PlanningGoalVerifier | None = None,
    executor: PlanningStepExecutor | None = None,
    state_machine: ApplicationStateMachine | None = None,
) -> _Harness:
    registry = ToolRegistry(tools)
    advisor = _Advisor(proposals)
    store = SQLitePlanningStore(tmp_path / "planning.sqlite3")
    selected_executor = executor or _Executor(results)
    engine = PlanningEngine(
        store=store,
        advisor=advisor,
        validator=PlanValidator(registry, max_steps=16),
        executor=selected_executor,
        step_verifier=EvidencePlanningStepVerifier(),
        goal_verifier=goal_verifier or CompletionCriteriaVerifier(),
        state_machine=state_machine,
    )
    return _Harness(store, advisor, selected_executor, engine)


@pytest.mark.asyncio
async def test_simple_plan_completes_only_after_goal_verification(tmp_path: Path) -> None:
    harness = _harness(tmp_path, (_plan(_step("prepare")),), (_result("prepare-ready"),))

    task = await harness.engine.submit("Prepare my system for a meeting")

    assert task.status is PlanningTaskStatus.COMPLETED
    assert task.result_evidence == ("prepare-ready",)
    assert harness.store.load_plan(task.task_id).steps[0].attempts == 1  # type: ignore[union-attr]


@pytest.mark.asyncio
async def test_planner_publishes_authoritative_state_transitions(tmp_path: Path) -> None:
    state_machine = ApplicationStateMachine()
    harness = _harness(
        tmp_path,
        (_plan(_step("prepare")),),
        (_result("prepare-ready"),),
        state_machine=state_machine,
    )
    task = await harness.engine.submit("Prepare my system for a meeting")
    snapshot = state_machine.task(task.task_id)
    assert snapshot is not None
    assert snapshot.state.value == "completed"
    assert snapshot.plan_revision == 1
    assert state_machine.application_state.value == "idle"


@pytest.mark.asyncio
async def test_dag_runs_independent_nodes_before_dependent_node(tmp_path: Path) -> None:
    proposal = _plan(
        _step("calendar"),
        _step("documents"),
        _step("focus", dependencies=["calendar", "documents"]),
    )
    executor = _Executor(
        (_result("calendar-ready"), _result("documents-ready"), _result("focus-ready"))
    )
    harness = _harness(
        tmp_path,
        (proposal,),
        (),
        tools=(_Tool("calendar"), _Tool("documents"), _Tool("focus")),
        executor=executor,
    )

    task = await harness.engine.submit("Prepare my system for a meeting")

    assert task.status is PlanningTaskStatus.COMPLETED
    assert executor.calls == ["calendar", "documents", "focus"]


def test_validator_rejects_cycle_missing_capability_unknown_permission_and_bad_arguments() -> None:
    registry = ToolRegistry((_Tool("a"), _Tool("b")))
    validator = PlanValidator(registry, max_steps=4)
    task_id = uuid4()

    with pytest.raises(PlanValidationError, match="cycle"):
        validator.validate(
            _plan(_step("a", dependencies=["b"]), _step("b", dependencies=["a"])),
            task_id=task_id,
        )
    with pytest.raises(PlanValidationError, match="Unknown requested tool"):
        validator.validate(_plan(_step("missing")), task_id=task_id)
    with pytest.raises(PlanValidationError, match="unknown permission"):
        validator.validate(_plan(_step("a", permissions=["unknown.permission"])), task_id=task_id)
    malformed = _plan(_step("a"))
    malformed["steps"][0]["input"] = {"value": 4}  # type: ignore[index]
    with pytest.raises(PlanValidationError, match="input does not match"):
        validator.validate(malformed, task_id=task_id)
    with pytest.raises(PlanValidationError, match="cannot be resolved"):
        validator.validate(_plan(_step("a", dependencies=["missing"])), task_id=task_id)
    with pytest.raises(PlanValidationError, match="step-count"):
        PlanValidator(registry, max_steps=1).validate(
            _plan(_step("a"), _step("b")), task_id=task_id
        )


@pytest.mark.asyncio
async def test_brokered_executor_pauses_before_privileged_tool_execution(tmp_path: Path) -> None:
    root = tmp_path.resolve()
    tool = _PermissionTool(root)
    policy = PolicyEngine(
        (
            PolicyRule(
                policy_id="planning-approval",
                permission=Permission.FILESYSTEM_READ,
                decision=Decision.REQUIRE_APPROVAL,
                scope=ScopeConstraint(paths=(str(root),), tools=frozenset({"protected"})),
                actions=frozenset({"invoke:protected"}),
            ),
        )
    )
    registry = ToolRegistry((tool,), permission_broker=PermissionBroker(policy))
    store = SQLitePlanningStore(tmp_path / "brokered.sqlite3")
    proposal = _plan(
        _step("protected", permissions=[Permission.FILESYSTEM_READ.value]),
        goal="Read the protected planning fixture",
    )
    engine = PlanningEngine(
        store=store,
        advisor=_Advisor((proposal,)),
        validator=PlanValidator(registry, max_steps=4),
        executor=BrokeredPlanningStepExecutor(registry),
        step_verifier=EvidencePlanningStepVerifier(),
        goal_verifier=CompletionCriteriaVerifier(),
    )

    task = await engine.submit("Read the protected planning fixture")

    assert task.status is PlanningTaskStatus.WAITING_FOR_PERMISSION
    assert task.waiting_request_ids
    assert not tool.executed
    store.close()


@pytest.mark.asyncio
async def test_brokered_permission_approval_resumes_without_reusing_reservation(
    tmp_path: Path,
) -> None:
    root = tmp_path.resolve()
    tool = _PermissionTool(root)
    policy = PolicyEngine(
        (
            PolicyRule(
                policy_id="planning-approval",
                permission=Permission.FILESYSTEM_READ,
                decision=Decision.REQUIRE_APPROVAL,
                scope=ScopeConstraint(paths=(str(root),), tools=frozenset({"protected"})),
                actions=frozenset({"invoke:protected"}),
            ),
        )
    )
    authenticator = TrustedApprovalAuthenticator(ApprovalSource.TRUSTED_UI)
    broker = PermissionBroker(policy, approval_context_verifier=authenticator.verifier())
    registry = ToolRegistry((tool,), permission_broker=broker)
    store = SQLitePlanningStore(tmp_path / "brokered-resume.sqlite3")
    proposal = _plan(
        _step("protected", permissions=[Permission.FILESYSTEM_READ.value]),
        goal="Read the protected planning fixture",
    )
    engine = PlanningEngine(
        store=store,
        advisor=_Advisor((proposal,)),
        validator=PlanValidator(registry, max_steps=1),
        executor=BrokeredPlanningStepExecutor(registry),
        step_verifier=EvidencePlanningStepVerifier(),
        goal_verifier=CompletionCriteriaVerifier(),
    )
    paused = await engine.submit(
        "Read the protected planning fixture",
        budgets=ExecutionBudgets(max_steps=1),
    )
    request = (await broker.pending_approvals(paused.task_id))[0]
    decision = await broker.decide(
        authenticator.issue_context(
            request_id=request.request_id,
            choice=ApprovalChoice.APPROVE_ONCE,
            identity=ApprovalIdentity("local-user", ApprovalActorKind.TRUSTED_USER),
        )
    )

    resumed = await engine.resume(paused.task_id)
    plan = engine.inspect_plan(paused.task_id)

    assert decision.accepted
    assert resumed.status is PlanningTaskStatus.COMPLETED
    assert resumed.usage.executed_steps == 1
    assert tool.executed
    assert plan is not None and plan.steps[0].attempts == 1
    store.close()


@pytest.mark.asyncio
async def test_controller_cancellation_revokes_pending_approval_before_task_state(
    tmp_path: Path,
) -> None:
    root = tmp_path.resolve()
    tool = _PermissionTool(root)
    policy = PolicyEngine(
        (
            PolicyRule(
                policy_id="planning-approval",
                permission=Permission.FILESYSTEM_READ,
                decision=Decision.REQUIRE_APPROVAL,
                scope=ScopeConstraint(paths=(str(root),), tools=frozenset({"protected"})),
                actions=frozenset({"invoke:protected"}),
            ),
        )
    )
    authenticator = TrustedApprovalAuthenticator(ApprovalSource.TRUSTED_UI)
    broker = PermissionBroker(policy, approval_context_verifier=authenticator.verifier())
    registry = ToolRegistry((tool,), permission_broker=broker)
    store = SQLitePlanningStore(tmp_path / "brokered-cancel.sqlite3")
    engine = PlanningEngine(
        store=store,
        advisor=_Advisor(
            (
                _plan(
                    _step("protected", permissions=[Permission.FILESYSTEM_READ.value]),
                    goal="Read the protected planning fixture",
                ),
            )
        ),
        validator=PlanValidator(registry, max_steps=1),
        executor=BrokeredPlanningStepExecutor(registry),
        step_verifier=EvidencePlanningStepVerifier(),
        goal_verifier=CompletionCriteriaVerifier(),
    )
    controller = PlanningTaskController(engine, broker)
    paused = await controller.submit_task("Read the protected planning fixture")
    request = (await controller.pending_approvals(paused.task_id))[0]
    context = authenticator.issue_context(
        request_id=request.request_id,
        choice=ApprovalChoice.APPROVE_ONCE,
        identity=ApprovalIdentity("local-user", ApprovalActorKind.TRUSTED_USER),
    )

    cancelled = await controller.cancel_task(paused.task_id)
    decision = await controller.submit_approval_decision(context)
    stored_request = await broker.get_approval(request.request_id)

    assert cancelled.status is PlanningTaskStatus.CANCELLED
    assert cancelled.waiting_request_ids == ()
    assert await controller.pending_approvals(paused.task_id) == ()
    assert not decision.accepted
    assert decision.reason is DecisionReason.APPROVAL_CANCELLED
    assert stored_request is not None and stored_request.status is ApprovalStatus.CANCELLED
    with pytest.raises(PlanningEngineError, match="permission-paused"):
        await controller.resume_task(paused.task_id)
    assert not tool.executed
    store.close()


@pytest.mark.asyncio
async def test_permission_pause_persists_and_resumes_after_restart(tmp_path: Path) -> None:
    request_id = uuid4()
    proposal = _plan(_step("prepare"))
    first = _harness(
        tmp_path,
        (proposal,),
        (
            StepExecutionResult(
                StepExecutionStatus.WAITING_FOR_PERMISSION,
                approval_request_ids=(request_id,),
            ),
        ),
    )
    paused = await first.engine.submit("Prepare my system for a meeting")
    first.store.close()

    assert paused.status is PlanningTaskStatus.WAITING_FOR_PERMISSION
    assert paused.waiting_request_ids == (request_id,)

    registry = ToolRegistry((_Tool("prepare"),))
    reopened = SQLitePlanningStore(tmp_path / "planning.sqlite3")
    resumed_engine = PlanningEngine(
        store=reopened,
        advisor=_Advisor(()),
        validator=PlanValidator(registry, max_steps=16),
        executor=_Executor((_result("prepare-ready"),)),
        step_verifier=EvidencePlanningStepVerifier(),
        goal_verifier=CompletionCriteriaVerifier(),
    )
    resumed = await resumed_engine.resume(paused.task_id)

    assert resumed.status is PlanningTaskStatus.COMPLETED
    # Waiting for a pre-effect approval is not an execution attempt.
    assert reopened.load_plan(paused.task_id).steps[0].attempts == 1  # type: ignore[union-attr]
    reopened.close()


@pytest.mark.asyncio
async def test_cancellation_stops_active_action_and_marks_downstream_nodes(tmp_path: Path) -> None:
    blocker = _BlockingExecutor()
    proposal = _plan(_step("prepare"), _step("finish", dependencies=["prepare"]))
    harness = _harness(
        tmp_path,
        (proposal,),
        (),
        tools=(_Tool("prepare"), _Tool("finish")),
        executor=blocker,
    )
    created = await harness.engine.create_task("Prepare my system for a meeting")
    running = asyncio.create_task(harness.engine.run(created.task_id))

    await blocker.started.wait()
    harness.engine.cancel(created.task_id)
    cancelled = await running
    plan = harness.store.load_plan(created.task_id)

    assert cancelled.status is PlanningTaskStatus.CANCELLED
    assert plan is not None
    assert [step.status for step in plan.steps] == [
        PlanningStepStatus.CANCELLED,
        PlanningStepStatus.BLOCKED,
    ]


@pytest.mark.asyncio
async def test_transient_failure_retries_with_explicit_bounds(tmp_path: Path) -> None:
    proposal = _plan(_step("prepare", retries=1))
    executor = _Executor(
        (
            StepExecutionResult(
                StepExecutionStatus.TRANSIENT_FAILURE,
                error_code="temporary",
                error_message="Temporary provider failure",
            ),
            _result("prepare-ready"),
        )
    )
    harness = _harness(tmp_path, (proposal,), (), executor=executor)

    task = await harness.engine.submit("Prepare my system for a meeting")

    assert task.status is PlanningTaskStatus.COMPLETED
    assert task.usage.retries == 1
    assert task.usage.executed_steps == 2


@pytest.mark.asyncio
async def test_safe_retry_releases_only_the_reserved_no_effect_operation(
    tmp_path: Path,
) -> None:
    proposal = _plan(_step("prepare", retries=1, expensive=True))
    executor = _Executor(
        (
            StepExecutionResult(
                StepExecutionStatus.TRANSIENT_FAILURE,
                error_code="temporary_no_effect",
                error_message="The provider failed before the effect boundary",
            ),
            _result("prepare-ready"),
        )
    )
    harness = _harness(tmp_path, (proposal,), (), executor=executor)

    task = await harness.engine.submit(
        "Prepare my system for a meeting",
        budgets=ExecutionBudgets(max_steps=2, max_retries=1),
    )

    assert task.status is PlanningTaskStatus.COMPLETED
    assert task.usage.retries == 1
    assert task.usage.executed_steps == 2
    assert executor.calls == ["prepare", "prepare"]


@pytest.mark.asyncio
async def test_unknown_external_effect_requires_recovery_and_is_never_replanned(
    tmp_path: Path,
) -> None:
    proposal = _plan(_step("prepare", retries=2))
    executor = _Executor(
        (
            StepExecutionResult(
                StepExecutionStatus.UNKNOWN_OUTCOME,
                error_code="execution_outcome_unknown",
                error_message="Durable outcome evidence was unavailable",
            ),
        )
    )
    harness = _harness(tmp_path, (proposal,), (), executor=executor)

    task = await harness.engine.submit("Prepare my system for a meeting")
    inspected = harness.engine.get_task(task.task_id)
    rerun = await harness.engine.run(task.task_id)
    plan = harness.engine.inspect_plan(task.task_id)

    assert task.status is PlanningTaskStatus.RECOVERING
    assert inspected == task == rerun
    assert task.error is not None
    assert task.error.failure_kind is FailureKind.UNKNOWN_OUTCOME
    assert harness.advisor.replan_evidence == []
    assert executor.calls == ["prepare"]
    assert plan is not None
    assert plan.steps[0].status is PlanningStepStatus.RUNNING


@pytest.mark.asyncio
async def test_replan_consumes_failure_evidence_and_preserves_constraints(tmp_path: Path) -> None:
    assumptions = ["Calendar is locally available"]
    constraints = ["Do not contact attendees"]
    first = _plan(_step("prepare"), assumptions=assumptions, constraints=constraints)
    second = _plan(_step("prepare"), assumptions=assumptions, constraints=constraints)
    executor = _Executor(
        (
            StepExecutionResult(
                StepExecutionStatus.DETERMINISTIC_FAILURE,
                evidence=("window-not-found",),
                error_code="missing-window",
                error_message="Meeting window was not available",
            ),
            _result("prepare-ready"),
        )
    )
    harness = _harness(tmp_path, (first, second), (), executor=executor)

    task = await harness.engine.submit(
        "Prepare my system for a meeting",
        assumptions=tuple(assumptions),
        constraints=tuple(constraints),
    )

    assert task.status is PlanningTaskStatus.COMPLETED
    assert task.usage.model_calls == 2
    assert harness.advisor.replan_evidence[0].observed_evidence == ("window-not-found",)
    assert harness.advisor.replan_evidence[0].original_constraints == tuple(constraints)
    assert harness.store.load_plan(task.task_id).version == 2  # type: ignore[union-attr]


@pytest.mark.asyncio
async def test_replan_after_execution_failure_updates_state_projection(
    tmp_path: Path,
) -> None:
    """A failed effectless step may replan directly from the executing state."""

    first = _plan(_step("prepare"))
    second = _plan(_step("prepare"))
    state_machine = ApplicationStateMachine()
    executor = _Executor(
        (
            StepExecutionResult(
                StepExecutionStatus.DETERMINISTIC_FAILURE,
                error_code="missing-window",
                error_message="Meeting window was not available",
            ),
            _result("prepare-ready"),
        )
    )
    harness = _harness(
        tmp_path,
        (first, second),
        (),
        executor=executor,
        state_machine=state_machine,
    )

    task = await harness.engine.submit("Prepare my system for a meeting")

    assert task.status is PlanningTaskStatus.COMPLETED
    snapshot = state_machine.task(task.task_id)
    assert snapshot is not None
    assert snapshot.state is TaskState.COMPLETED
    assert any(
        transition.from_state is TaskState.EXECUTING
        and transition.to_state is TaskState.THINKING
        and transition.event is TransitionEvent.REPLAN_REQUESTED
        for transition in state_machine.history(task.task_id)
    )


@pytest.mark.asyncio
async def test_exhausted_runtime_budget_is_observable(tmp_path: Path) -> None:
    proposal = _plan(_step("prepare", retries=2))
    transient = StepExecutionResult(
        StepExecutionStatus.TRANSIENT_FAILURE,
        error_code="temporary",
        error_message="Temporary failure",
    )
    harness = _harness(tmp_path, (proposal,), (transient,))

    task = await harness.engine.submit(
        "Prepare my system for a meeting",
        budgets=ExecutionBudgets(max_steps=1, max_retries=2),
    )

    assert task.status is PlanningTaskStatus.BUDGET_EXHAUSTED
    assert task.error is not None
    assert task.error.code == "step_budget_exhausted"


@pytest.mark.asyncio
async def test_step_success_does_not_override_goal_verification_failure(tmp_path: Path) -> None:
    harness = _harness(
        tmp_path,
        (_plan(_step("prepare")),),
        (_result("prepare-ready"),),
        goal_verifier=_RejectGoal(),
    )

    task = await harness.engine.submit("Prepare my system for a meeting")

    assert task.status is PlanningTaskStatus.FAILED
    assert task.error is not None
    assert task.error.code == "goal_verification_failed"


def test_validator_rejects_manifest_mismatch_duplicate_declarations_and_unknown_rule() -> None:
    registry = ToolRegistry((_Tool("prepare"),))
    validator = PlanValidator(registry, max_steps=4)
    task_id = uuid4()

    wrong_capability = _plan(_step("prepare"))
    cast(dict[str, object], cast(list[object], wrong_capability["steps"])[0])["capability"] = (
        "missing-capability"
    )
    wrong_capability["required_capabilities"] = ["missing-capability"]
    with pytest.raises(PlanValidationError, match="does not provide capability"):
        validator.validate(wrong_capability, task_id=task_id)

    permission_mismatch = _plan(_step("prepare", permissions=[Permission.FILESYSTEM_READ.value]))
    with pytest.raises(PlanValidationError, match="manifest"):
        validator.validate(permission_mismatch, task_id=task_id)

    duplicate_keys = _plan(_step("prepare"), _step("prepare"))
    with pytest.raises(PlanValidationError, match="keys must be unique"):
        validator.validate(duplicate_keys, task_id=task_id)

    duplicate_permissions = _plan(_step("prepare"))
    duplicate_permissions["required_permissions"] = [
        Permission.FILESYSTEM_READ.value,
        Permission.FILESYSTEM_READ.value,
    ]
    with pytest.raises(PlanValidationError, match="permissions must be unique"):
        validator.validate(duplicate_permissions, task_id=task_id)

    unknown_rule = _plan(_step("prepare"))
    cast(dict[str, object], cast(list[object], unknown_rule["steps"])[0])["verification_rule"] = (
        "model_says_success"
    )
    with pytest.raises(PlanValidationError, match="unknown verification rule"):
        validator.validate(unknown_rule, task_id=task_id)


@pytest.mark.asyncio
async def test_invalid_initial_plan_and_zero_model_budget_fail_without_execution(
    tmp_path: Path,
) -> None:
    invalid = _harness(tmp_path, ({"goal": "bad", "steps": []},), ())
    task = await invalid.engine.submit("Prepare my system for a meeting")

    assert task.status is PlanningTaskStatus.FAILED
    assert task.error is not None and task.error.code == "plan_validation_failed"
    assert invalid.store.load_plan(task.task_id) is None
    invalid.store.close()

    zero = _harness(tmp_path / "zero", (_plan(_step("prepare")),), ())
    exhausted = await zero.engine.submit(
        "Prepare my system for a meeting",
        budgets=ExecutionBudgets(max_model_calls=0),
    )
    assert exhausted.status is PlanningTaskStatus.BUDGET_EXHAUSTED
    assert exhausted.error is not None
    assert exhausted.error.code == "model_call_budget_exhausted"


@pytest.mark.asyncio
async def test_replan_that_changes_original_constraints_is_rejected(tmp_path: Path) -> None:
    first = _plan(_step("prepare"), constraints=["Do not contact attendees"])
    changed = _plan(_step("prepare"), constraints=[])
    failure = StepExecutionResult(
        StepExecutionStatus.DETERMINISTIC_FAILURE,
        error_code="missing",
        error_message="Missing window",
        evidence=("window-missing",),
    )
    harness = _harness(tmp_path, (first, changed), (failure,))

    task = await harness.engine.submit(
        "Prepare my system for a meeting",
        constraints=("Do not contact attendees",),
    )

    assert task.status is PlanningTaskStatus.FAILED
    assert task.error is not None
    assert task.error.code == "replan_validation_failed"


@pytest.mark.asyncio
async def test_verification_failure_and_model_budget_exhaustion_are_observable(
    tmp_path: Path,
) -> None:
    harness = _harness(
        tmp_path,
        (_plan(_step("prepare")),),
        (_result("wrong-evidence"),),
    )

    task = await harness.engine.submit(
        "Prepare my system for a meeting",
        budgets=ExecutionBudgets(max_model_calls=1),
    )

    assert task.status is PlanningTaskStatus.BUDGET_EXHAUSTED
    assert task.error is not None
    assert task.error.code == "model_call_budget_exhausted"


@pytest.mark.asyncio
async def test_elapsed_and_expensive_action_budgets_fail_before_execution(tmp_path: Path) -> None:
    clock = _Clock()
    registry = ToolRegistry((_Tool("prepare"),))
    store = SQLitePlanningStore(tmp_path / "elapsed.sqlite3", clock=clock)
    executor = _Executor((_result("prepare-ready"),))
    engine = PlanningEngine(
        store=store,
        advisor=_Advisor((_plan(_step("prepare")),)),
        validator=PlanValidator(registry, max_steps=4, clock=clock),
        executor=executor,
        step_verifier=EvidencePlanningStepVerifier(),
        goal_verifier=CompletionCriteriaVerifier(),
        clock=clock,
    )
    created = await engine.create_task(
        "Prepare my system for a meeting",
        budgets=ExecutionBudgets(max_elapsed_seconds=1),
    )
    clock.value += timedelta(seconds=2)
    elapsed = await engine.run(created.task_id)
    assert elapsed.status is PlanningTaskStatus.BUDGET_EXHAUSTED
    assert elapsed.error is not None and elapsed.error.code == "elapsed_time_budget_exhausted"
    assert executor.calls == []
    store.close()

    expensive = _harness(
        tmp_path / "expensive",
        (_plan(_step("prepare", expensive=True)),),
        (_result("prepare-ready"),),
    )
    blocked = await expensive.engine.submit(
        "Prepare my system for a meeting",
        budgets=ExecutionBudgets(max_expensive_actions=0),
    )
    assert blocked.status is PlanningTaskStatus.BUDGET_EXHAUSTED
    assert blocked.error is not None
    assert blocked.error.code == "expensive_action_budget_exhausted"


@pytest.mark.asyncio
async def test_interrupted_and_blocked_persisted_graphs_fail_closed(tmp_path: Path) -> None:
    proposal = _plan(_step("prepare"), _step("finish", dependencies=["prepare"]))
    harness = _harness(
        tmp_path,
        (proposal,),
        (),
        tools=(_Tool("prepare"), _Tool("finish")),
    )
    task = await harness.engine.create_task("Prepare my system for a meeting")
    plan = harness.store.load_plan(task.task_id)
    assert plan is not None
    interrupted = replace(
        plan,
        steps=(replace(plan.steps[0], status=PlanningStepStatus.RUNNING), plan.steps[1]),
    )
    harness.store.save_state(task, interrupted)

    failed = await harness.engine.run(task.task_id)
    assert failed.status is PlanningTaskStatus.FAILED
    assert failed.error is not None
    assert failed.error.code == "interrupted_step_unknown_outcome"


@pytest.mark.asyncio
async def test_resume_and_missing_task_guards_are_explicit(tmp_path: Path) -> None:
    harness = _harness(tmp_path, (_plan(_step("prepare")),), (_result("prepare-ready"),))
    task = await harness.engine.submit("Prepare my system for a meeting")

    with pytest.raises(PlanningEngineError, match="permission-paused"):
        await harness.engine.resume(task.task_id)
    with pytest.raises(PlanningEngineError, match="does not exist"):
        await harness.engine.run(uuid4())
    assert harness.engine.cancel(task.task_id).status is PlanningTaskStatus.COMPLETED


@pytest.mark.asyncio
async def test_builtin_step_and_goal_verification_rules() -> None:
    registry = ToolRegistry((_Tool("prepare"),))
    step = (
        PlanValidator(registry, max_steps=2)
        .validate(_plan(_step("prepare")), task_id=uuid4())
        .steps[0]
    )
    verifier = EvidencePlanningStepVerifier()

    failed_execution = await verifier.verify(
        step,
        StepExecutionResult(
            StepExecutionStatus.DETERMINISTIC_FAILURE,
            error_code="failed",
            error_message="failed",
        ),
    )
    output_step = replace(step, verification_rule="output_contains", expected_output="ok")
    output_success = await verifier.verify(output_step, _result("anything"))
    unknown = await verifier.verify(
        replace(step, verification_rule="unknown"), _result("prepare-ready")
    )

    assert not failed_execution.succeeded
    assert output_success.succeeded
    assert not unknown.succeeded


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("tool_status", "expected"),
    (
        (ToolResultStatus.TIMEOUT, StepExecutionStatus.TRANSIENT_FAILURE),
        (ToolResultStatus.CANCELLED, StepExecutionStatus.CANCELLED),
        (ToolResultStatus.UNKNOWN_OUTCOME, StepExecutionStatus.UNKNOWN_OUTCOME),
        (ToolResultStatus.EXPECTED_FAILURE, StepExecutionStatus.DETERMINISTIC_FAILURE),
    ),
)
async def test_brokered_executor_classifies_tool_failures(
    tmp_path: Path, tool_status: ToolResultStatus, expected: StepExecutionStatus
) -> None:
    tool = _ResultTool(ToolResult.failure(tool_status, "fixture", "Fixture failure"))
    registry = ToolRegistry((tool,))
    store = SQLitePlanningStore(tmp_path / f"{tool_status.value}.sqlite3")
    proposal = _plan(
        {
            **_step("result-tool"),
            "expected_evidence": ["result-tool-ready"],
        },
        goal="Classify tool failure",
    )
    engine = PlanningEngine(
        store=store,
        advisor=_Advisor((proposal,)),
        validator=PlanValidator(registry, max_steps=2),
        executor=BrokeredPlanningStepExecutor(registry),
        step_verifier=EvidencePlanningStepVerifier(),
        goal_verifier=CompletionCriteriaVerifier(),
    )
    task = await engine.create_task("Classify tool failure")
    plan = store.load_plan(task.task_id)
    assert plan is not None

    result = await BrokeredPlanningStepExecutor(registry).execute(
        task, plan.steps[0], asyncio.Event()
    )

    assert result.status is expected
    store.close()


def test_planning_store_migrations_identity_and_atomic_state_guards(tmp_path: Path) -> None:
    with pytest.raises(ValueError, match="valid version"):
        PlanningMigration(0, "bad", "SELECT 1")
    with pytest.raises(PlanningStoreError, match="sequential"):
        SQLitePlanningStore(
            tmp_path / "bad.sqlite3",
            migrations=(PlanningMigration(2, "skip", "SELECT 1"),),
        )
    path = tmp_path / "planning.sqlite3"
    store = SQLitePlanningStore(path)
    assert store.database_path == path
    store.close()
    with pytest.raises(PlanningStoreError, match="identity mismatch"):
        SQLitePlanningStore(
            path,
            migrations=(PlanningMigration(1, "renamed", "SELECT 1"),),
        )


def test_planning_domain_models_reject_invalid_budgets_results_and_errors() -> None:
    with pytest.raises(ValueError, match="positive"):
        ExecutionBudgets(max_steps=0)
    with pytest.raises(ValueError, match="positive"):
        ExecutionBudgets(max_elapsed_seconds=math.nan)
    with pytest.raises(ValueError, match="cannot be negative"):
        BudgetUsage(retries=-1)
    with pytest.raises(ValueError, match="valid JSON"):
        StepResult("not-json", ())
    with pytest.raises(ValueError, match="failure kind"):
        StepError("code", "message", cast(FailureKind, "unknown"))
    with pytest.raises(ValueError, match="approval request IDs"):
        StepExecutionResult(StepExecutionStatus.WAITING_FOR_PERMISSION)
    with pytest.raises(ValueError, match="only for permission pauses"):
        StepExecutionResult(
            StepExecutionStatus.SUCCEEDED,
            approval_request_ids=(uuid4(),),
        )


def test_planning_domain_models_fail_closed_on_malformed_state() -> None:
    registry = ToolRegistry((_Tool("prepare"),))
    plan = PlanValidator(registry, max_steps=2).validate(_plan(_step("prepare")), task_id=uuid4())
    step = plan.steps[0]

    with pytest.raises(ValueError, match="cannot be negative"):
        ExecutionBudgets(max_model_calls=-1)
    with pytest.raises(ValueError, match="cannot be negative"):
        BudgetUsage(executed_steps=-1)
    with pytest.raises(ValueError, match="bounded"):
        StepResult("{}", ("x" * 1_001,))
    with pytest.raises(ValueError, match="bounded"):
        StepError("code", "message", FailureKind.DETERMINISTIC, ("x" * 1_001,))
    with pytest.raises(ValueError, match="valid JSON"):
        replace(step, input_json="{")
    with pytest.raises(ValueError, match="JSON object"):
        replace(step, input_json="[]")
    with pytest.raises(ValueError, match="cannot reference self"):
        replace(step, dependencies=(step.step_id,))
    with pytest.raises(ValueError, match="recognized"):
        replace(step, required_permissions=(cast(Permission, "unknown"),))
    with pytest.raises(ValueError, match="unique and sorted"):
        replace(
            step,
            required_permissions=(Permission.SCREEN_READ, Permission.FILESYSTEM_READ),
        )
    with pytest.raises(ValueError, match="cannot be negative"):
        replace(step, max_retries=-1)
    with pytest.raises(ValueError, match="Expected evidence"):
        replace(step, expected_evidence=("",))
    with pytest.raises(ValueError, match="at least one step"):
        replace(plan, steps=())
    with pytest.raises(ValueError, match="step IDs"):
        replace(plan, steps=(step, step))
    with pytest.raises(ValueError, match="completion criteria"):
        replace(plan, completion_criteria=())
    with pytest.raises(ValueError, match="status"):
        replace(plan, status=cast(OwnedPlanStatus, "unknown"))
    with pytest.raises(ValueError, match="assumptions and constraints"):
        replace(plan, assumptions=("",))
    with pytest.raises(ValueError, match="Execution status"):
        StepExecutionResult(cast(StepExecutionStatus, "unknown"))
    with pytest.raises(ValueError, match="valid JSON"):
        StepExecutionResult(StepExecutionStatus.SUCCEEDED, output_json="{")
    with pytest.raises(ValueError, match="bounded"):
        StepExecutionResult(StepExecutionStatus.SUCCEEDED, evidence=("x" * 1_001,))


@pytest.mark.asyncio
async def test_planning_task_model_rejects_corrupt_persisted_invariants(tmp_path: Path) -> None:
    harness = _harness(tmp_path, (_plan(_step("prepare")),), ())
    task = await harness.engine.create_task("Prepare my system for a meeting")

    with pytest.raises(ValueError, match="Task status"):
        replace(task, status=cast(PlanningTaskStatus, "unknown"))
    with pytest.raises(ValueError, match="deadline"):
        replace(task, deadline=task.started_at)
    request_id = uuid4()
    with pytest.raises(ValueError, match="request IDs"):
        replace(task, waiting_request_ids=(request_id, request_id))
    with pytest.raises(ValueError, match="assumptions and constraints"):
        replace(task, original_constraints=("",))

    naive = replace(
        task,
        created_at=task.created_at.replace(tzinfo=None),
        started_at=task.started_at.replace(tzinfo=None),
        deadline=task.deadline.replace(tzinfo=None),
        updated_at=task.updated_at.replace(tzinfo=None),
    )
    assert naive.created_at.tzinfo is UTC


@pytest.mark.asyncio
async def test_planning_store_rejects_duplicates_missing_rows_and_corruption(
    tmp_path: Path,
) -> None:
    harness = _harness(tmp_path, (_plan(_step("prepare")),), ())
    task = await harness.engine.create_task("Prepare my system for a meeting")
    plan = harness.store.load_plan(task.task_id)
    assert plan is not None

    with pytest.raises(PlanningStoreError, match="already exists"):
        harness.store.create_task(task)
    with pytest.raises(PlanningStoreError, match="does not exist"):
        harness.store.save_task(replace(task, task_id=uuid4()))
    with pytest.raises(PlanningStoreError, match="identity"):
        harness.store.save_state(task, replace(plan, task_id=uuid4()))

    missing_task = replace(task, task_id=uuid4(), plan_id=plan.plan_id)
    missing_plan = replace(plan, task_id=missing_task.task_id)
    with pytest.raises(PlanningStoreError, match="does not exist"):
        harness.store.save_state(missing_task, missing_plan)

    harness.store._connection.execute(
        "UPDATE planning_tasks SET task_json = ? WHERE task_id = ?",
        ("[]", str(task.task_id)),
    )
    harness.store._connection.commit()
    with pytest.raises(PlanningStoreError, match="must be an object"):
        harness.store.load_task(task.task_id)


@pytest.mark.asyncio
async def test_planning_store_rejects_non_boolean_persisted_flags(tmp_path: Path) -> None:
    harness = _harness(tmp_path, (_plan(_step("prepare")),), ())
    task = await harness.engine.create_task("Prepare my system for a meeting")
    row = harness.store._connection.execute(
        "SELECT task_json FROM planning_tasks WHERE task_id = ?", (str(task.task_id),)
    ).fetchone()
    assert row is not None
    payload = json.loads(str(row["task_json"]))
    payload["cancellation_requested"] = "false"
    harness.store._connection.execute(
        "UPDATE planning_tasks SET task_json = ? WHERE task_id = ?",
        (json.dumps(payload), str(task.task_id)),
    )
    harness.store._connection.commit()

    with pytest.raises(PlanningStoreError, match="boolean"):
        harness.store.load_task(task.task_id)


@pytest.mark.asyncio
async def test_planning_provider_exception_is_a_persisted_failure(tmp_path: Path) -> None:
    harness = _harness(tmp_path, (), ())

    task = await harness.engine.create_task("Prepare my system for a meeting")

    assert task.status is PlanningTaskStatus.FAILED
    assert task.error is not None
    assert task.error.code == "planning_provider_failed"


@pytest.mark.asyncio
async def test_concurrent_execution_of_one_task_is_rejected(tmp_path: Path) -> None:
    executor = _BlockingExecutor()
    harness = _harness(
        tmp_path,
        (_plan(_step("prepare")),),
        (),
        executor=executor,
    )
    task = await harness.engine.create_task("Prepare my system for a meeting")
    running = asyncio.create_task(harness.engine.run(task.task_id))
    await executor.started.wait()

    with pytest.raises(PlanningEngineError, match="already running"):
        await harness.engine.run(task.task_id)
    harness.engine.cancel(task.task_id)
    assert (await running).status is PlanningTaskStatus.CANCELLED


def test_planning_store_context_manager_and_failed_migration(tmp_path: Path) -> None:
    with SQLitePlanningStore(tmp_path / "context.sqlite3") as store:
        assert store.load_task(uuid4()) is None
        assert store.load_plan(uuid4()) is None

    with pytest.raises(PlanningStoreError, match="migration failed"):
        SQLitePlanningStore(
            tmp_path / "invalid.sqlite3",
            migrations=(PlanningMigration(1, "invalid", "NOT VALID SQL"),),
        )


@pytest.mark.asyncio
async def test_plan_inspection_edit_revision_and_restart_history(tmp_path: Path) -> None:
    harness = _harness(tmp_path, (_plan(_step("prepare")),), ())
    task = await harness.engine.create_task("Prepare my system for a meeting")

    inspection = harness.engine.inspect_plan_details(task.task_id)
    assert inspection is not None
    assert inspection.steps[0].dependencies == ()
    assert inspection.steps[0].verification == ("evidence_contains_all", "prepare-ready")
    assert "max_steps=32" in inspection.resource_estimates

    revision = await harness.engine.apply_plan_edit(
        task.task_id,
        PlanEdit(
            add_constraints=("Use the already configured local capability",),
            structured_steps=(StructuredStepEdit(key="prepare", input={"value": "revised"}),),
            provenance="trusted-ui.plan-editor",
        ),
    )
    assert revision.plan.version == 2
    assert revision.plan.provenance == ("trusted-ui.plan-editor",)
    assert revision.changed_fields == ("structured:prepare", "constraints")
    assert harness.engine.get_task(task.task_id).plan_id == revision.plan.plan_id  # type: ignore[union-attr]
    assert [plan.version for plan in harness.engine.list_plan_revisions(task.task_id)] == [1, 2]
    harness.store.close()

    reopened = SQLitePlanningStore(tmp_path / "planning.sqlite3")
    assert [plan.version for plan in reopened.list_plan_revisions(task.task_id)] == [1, 2]
    assert reopened.load_plan_revision(task.task_id, 1) is not None
    assert reopened.load_plan_revision(uuid4(), 1) is None
    assert reopened.list_plan_revisions(uuid4()) == ()
    with pytest.raises(PlanningStoreError, match="positive"):
        reopened.load_plan_revision(task.task_id, 0)
    assert reopened.load_plan(task.task_id).version == 2  # type: ignore[union-attr]
    reopened.close()


@pytest.mark.asyncio
async def test_invalid_plan_edit_cannot_remove_required_or_dependent_step(tmp_path: Path) -> None:
    proposal = _plan(_step("prepare"), _step("finish", dependencies=["prepare"]))
    harness = _harness(
        tmp_path,
        (proposal,),
        (),
        tools=(_Tool("prepare"), _Tool("finish")),
    )
    task = await harness.engine.create_task("Prepare my system for a meeting")

    with pytest.raises(PlanEditError, match="dependents"):
        await harness.engine.apply_plan_edit(
            task.task_id,
            PlanEdit(remove_optional_steps=("prepare",)),
        )

    with pytest.raises(PlanEditError, match="completion-evidence"):
        await harness.engine.apply_plan_edit(
            task.task_id,
            PlanEdit(remove_optional_steps=("finish",)),
        )


@pytest.mark.asyncio
async def test_optional_step_removal_and_user_replan_use_canonical_validator(
    tmp_path: Path,
) -> None:
    optional_plan = _plan(
        _step("prepare"),
        _step("optional"),
    )
    optional_plan["completion_criteria"] = ["prepare-ready"]
    harness = _harness(
        tmp_path / "optional",
        (optional_plan,),
        (),
        tools=(_Tool("prepare"), _Tool("optional")),
    )
    task = await harness.engine.create_task("Prepare my system for a meeting")
    removed = await harness.engine.apply_plan_edit(
        task.task_id,
        PlanEdit(remove_optional_steps=("optional",), pause_checkpoint=True),
    )
    assert tuple(step.key for step in removed.plan.steps) == ("prepare",)
    assert "pause_checkpoint" in removed.changed_fields

    first = _plan(_step("prepare"))
    second = _plan(_step("prepare"), constraints=["Keep the operation local"])
    replanning = _harness(tmp_path / "replan", (first, second), ())
    replanning_task = await replanning.engine.create_task("Prepare my system for a meeting")
    replanned = await replanning.engine.request_replan(
        replanning_task.task_id,
        additional_constraints=("Keep the operation local",),
    )
    assert replanned.plan.version == 2
    assert replanned.provenance == "user.requested_replan"
    assert replanning.advisor.replan_evidence[0].failed_step_key == "user_requested_replan"
    assert replanning.advisor.replan_evidence[0].original_constraints == (
        "Keep the operation local",
    )


@pytest.mark.asyncio
async def test_plan_edit_invalidates_approval_when_effect_fingerprint_changes(
    tmp_path: Path,
) -> None:
    root = tmp_path.resolve()
    tool = _PermissionTool(root)
    policy = PolicyEngine(
        (
            PolicyRule(
                policy_id="planning-approval",
                permission=Permission.FILESYSTEM_READ,
                decision=Decision.REQUIRE_APPROVAL,
                scope=ScopeConstraint(paths=(str(root),), tools=frozenset({"protected"})),
                actions=frozenset({"invoke:protected"}),
            ),
        )
    )
    broker = PermissionBroker(policy)
    registry = ToolRegistry((tool,), permission_broker=broker)
    store = SQLitePlanningStore(tmp_path / "approval-edit.sqlite3")
    engine = PlanningEngine(
        store=store,
        advisor=_Advisor(
            (
                _plan(
                    _step("protected", permissions=[Permission.FILESYSTEM_READ.value]),
                    goal="Read the protected planning fixture",
                ),
            )
        ),
        validator=PlanValidator(registry, max_steps=1),
        executor=BrokeredPlanningStepExecutor(registry),
        step_verifier=EvidencePlanningStepVerifier(),
        goal_verifier=CompletionCriteriaVerifier(),
        approval_invalidator=broker.invalidate_task_approvals,
    )
    paused = await engine.submit("Read the protected planning fixture")
    request = (await broker.pending_approvals(paused.task_id))[0]
    details = engine.inspect_plan_details(paused.task_id)
    assert details is not None
    assert details.steps[0].effect == "privileged_or_external"

    revision = await engine.apply_plan_edit(
        paused.task_id,
        PlanEdit(
            structured_steps=(StructuredStepEdit(key="protected", input={"value": "changed"}),)
        ),
    )

    assert revision.invalidated_approval_ids == (request.request_id,)
    assert (await broker.get_approval(request.request_id)).status is ApprovalStatus.CANCELLED  # type: ignore[union-attr]
    assert engine.get_task(paused.task_id).status is PlanningTaskStatus.READY  # type: ignore[union-attr]
    assert not tool.executed
    store.close()


@pytest.mark.asyncio
async def test_checkpoint_branch_inherits_only_confirmed_evidence(tmp_path: Path) -> None:
    proposal = _plan(_step("prepare"), _step("finish", dependencies=["prepare"]))
    harness = _harness(
        tmp_path,
        (proposal,),
        (),
        tools=(_Tool("prepare"), _Tool("finish")),
    )
    task = await harness.engine.create_task("Prepare my system for a meeting")
    plan = harness.engine.inspect_plan(task.task_id)
    assert plan is not None
    completed = replace(
        plan.steps[0],
        status=PlanningStepStatus.SUCCEEDED,
        attempts=1,
        result=StepResult('{"value":"ok"}', ("prepare-ready",)),
    )
    persisted_plan = replace(plan, steps=(completed, plan.steps[1]))
    persisted_task = replace(
        task,
        status=PlanningTaskStatus.READY,
        usage=replace(task.usage, executed_steps=1),
    )
    harness.store.save_state(persisted_task, persisted_plan)

    branch = await harness.engine.create_checkpoint_branch(
        task.task_id,
        PlanEdit(
            structured_steps=(StructuredStepEdit(key="finish", input={"value": "new-finish"}),),
            provenance="trusted-ui.checkpoint",
        ),
    )

    assert branch.checkpoint_branch
    assert branch.plan.steps[0].status is PlanningStepStatus.SUCCEEDED
    assert branch.plan.steps[0].result is not None
    assert branch.plan.steps[1].status is PlanningStepStatus.QUEUED
    assert branch.plan.version == 2
    assert isinstance(harness.executor, _Executor)
    assert harness.executor.calls == []  # checkpoint creation never executes


@pytest.mark.asyncio
async def test_checkpoint_branch_rejects_unknown_outcome(tmp_path: Path) -> None:
    harness = _harness(tmp_path, (_plan(_step("prepare")),), ())
    task = await harness.engine.create_task("Prepare my system for a meeting")
    plan = harness.engine.inspect_plan(task.task_id)
    assert plan is not None
    unknown = replace(
        plan.steps[0],
        status=PlanningStepStatus.RUNNING,
        error=StepError(
            "unknown",
            "Effect boundary was interrupted",
            FailureKind.UNKNOWN_OUTCOME,
        ),
    )
    harness.store.save_state(
        replace(
            task,
            status=PlanningTaskStatus.RECOVERING,
            usage=replace(task.usage, executed_steps=1),
            error=unknown.error,
        ),
        replace(plan, steps=(unknown,)),
    )

    with pytest.raises(PlanningEngineError, match="UNKNOWN_OUTCOME"):
        await harness.engine.create_checkpoint_branch(task.task_id, PlanEdit(pause_checkpoint=True))


def test_plan_edit_contract_rejects_malformed_metadata() -> None:
    with pytest.raises(PlanEditError, match="provenance"):
        PlanEdit(provenance=" ")
    with pytest.raises(PlanEditError, match="constraints"):
        PlanEdit(add_constraints=("x",) * 33)
    with pytest.raises(PlanEditError, match="bounded"):
        PlanEdit(add_constraints=(" ",))
    with pytest.raises(PlanEditError, match="unique"):
        PlanEdit(remove_optional_steps=("same", "same"))
    with pytest.raises(PlanEditError, match="key"):
        StructuredStepEdit(key=" ")
    with pytest.raises(PlanEditError, match="input"):
        StructuredStepEdit(key="step", input=cast(Mapping[str, object], []))
    with pytest.raises(PlanEditError, match="input"):
        PlanStepSpec(
            "step",
            "tool",
            "capability",
            cast(Mapping[str, object], []),
            (),
            (),
            "output",
            "evidence_contains_all",
            ("evidence",),
        )


@pytest.mark.asyncio
async def test_plan_editor_alternative_and_lifecycle_guards(tmp_path: Path) -> None:
    harness = _harness(tmp_path, (_plan(_step("prepare")),), (_result("prepare-ready"),))
    missing = harness.engine.inspect_plan_details(uuid4())
    assert missing is None
    task = await harness.engine.create_task("Prepare my system for a meeting")
    alternative = PlanStepSpec(
        "prepare",
        "prepare",
        "prepare",
        {"value": "alternative"},
        (),
        (),
        "prepare prepared",
        "evidence_contains_all",
        ("prepare-ready",),
        max_retries=2,
    )
    revised = await harness.engine.apply_plan_edit(
        task.task_id,
        PlanEdit(alternatives=(alternative,), provenance="trusted-ui.alternative"),
    )
    assert json.loads(revised.plan.steps[0].input_json)["value"] == "alternative"

    completed = await harness.engine.run(task.task_id)
    assert completed.status is PlanningTaskStatus.COMPLETED
    with pytest.raises(PlanningEngineError, match="terminal"):
        await harness.engine.apply_plan_edit(task.task_id, PlanEdit(pause_checkpoint=True))


@pytest.mark.asyncio
async def test_plan_editor_rejects_active_and_post_effect_edits(tmp_path: Path) -> None:
    blocking = _BlockingExecutor()
    harness = _harness(
        tmp_path / "active",
        (_plan(_step("prepare")),),
        (),
        executor=blocking,
    )
    task = await harness.engine.create_task("Prepare my system for a meeting")
    running = asyncio.create_task(harness.engine.run(task.task_id))
    await blocking.started.wait()
    with pytest.raises(PlanningEngineError, match="Active"):
        await harness.engine.create_checkpoint_branch(
            task.task_id,
            PlanEdit(pause_checkpoint=True),
        )
    harness.engine.cancel(task.task_id)
    await running

    completed_harness = _harness(tmp_path / "effect", (_plan(_step("prepare")),), ())
    completed_task = await completed_harness.engine.create_task("Prepare my system for a meeting")
    completed_plan = completed_harness.engine.inspect_plan(completed_task.task_id)
    assert completed_plan is not None
    completed_step = replace(
        completed_plan.steps[0],
        status=PlanningStepStatus.SUCCEEDED,
        attempts=1,
        result=StepResult('{"value":"ok"}', ("prepare-ready",)),
    )
    completed_harness.store.save_state(
        replace(
            completed_task,
            status=PlanningTaskStatus.READY,
            usage=replace(completed_task.usage, executed_steps=1),
        ),
        replace(completed_plan, steps=(completed_step,)),
    )
    with pytest.raises(PlanningEngineError, match="before execution"):
        await completed_harness.engine.apply_plan_edit(
            completed_task.task_id,
            PlanEdit(pause_checkpoint=True),
        )
    with pytest.raises(PlanningEngineError, match="before execution"):
        await completed_harness.engine.request_replan(completed_task.task_id)


@pytest.mark.asyncio
async def test_plan_editor_rejects_invalid_checkpoint_and_validator_output(
    tmp_path: Path,
) -> None:
    harness = _harness(
        tmp_path / "failed-checkpoint",
        (_plan(_step("prepare")),),
        (),
    )
    task = await harness.engine.create_task("Prepare my system for a meeting")
    plan = harness.engine.inspect_plan(task.task_id)
    assert plan is not None
    failed = replace(
        plan.steps[0],
        status=PlanningStepStatus.FAILED,
        error=StepError("failed", "not done", FailureKind.DETERMINISTIC),
    )
    harness.store.save_state(
        replace(task, usage=replace(task.usage, executed_steps=1)),
        replace(plan, steps=(failed,)),
    )
    with pytest.raises(PlanningEngineError, match="invalid prior evidence"):
        await harness.engine.create_checkpoint_branch(task.task_id, PlanEdit(pause_checkpoint=True))

    invalid = _harness(tmp_path / "invalid-edit", (_plan(_step("prepare")),), ())
    invalid_task = await invalid.engine.create_task("Prepare my system for a meeting")
    with pytest.raises(PlanEditError, match="PlanValidator"):
        await invalid.engine.apply_plan_edit(
            invalid_task.task_id,
            PlanEdit(structured_steps=(StructuredStepEdit(key="prepare", expected_output=""),)),
        )


@pytest.mark.asyncio
async def test_plan_editor_structured_fields_and_replan_budget_are_bounded(
    tmp_path: Path,
) -> None:
    harness = _harness(tmp_path / "fields", (_plan(_step("prepare")),), ())
    task = await harness.engine.create_task("Prepare my system for a meeting")
    edited = await harness.engine.apply_plan_edit(
        task.task_id,
        PlanEdit(
            structured_steps=(
                StructuredStepEdit(
                    key="prepare",
                    tool_id="prepare",
                    capability="prepare",
                    input={"value": "all-fields"},
                    dependencies=(),
                    required_permissions=(),
                    expected_output="all fields",
                    verification_rule="evidence_contains_all",
                    expected_evidence=("prepare-ready",),
                    expensive_action=True,
                    max_retries=2,
                ),
            )
        ),
    )
    assert edited.plan.steps[0].expensive_action is True
    assert edited.plan.steps[0].max_retries == 2

    first = _plan(_step("prepare"))
    too_large = _plan(_step("prepare"), _step("extra"))
    budget = _harness(
        tmp_path / "budget",
        (first, too_large),
        (),
        tools=(_Tool("prepare"), _Tool("extra")),
    )
    budget_task = await budget.engine.create_task(
        "Prepare my system for a meeting",
        budgets=ExecutionBudgets(max_steps=1),
    )
    with pytest.raises(PlanningEngineError, match="failed validation"):
        await budget.engine.request_replan(budget_task.task_id)


@pytest.mark.asyncio
async def test_replan_rejects_unbounded_constraints_and_invalid_proposal(tmp_path: Path) -> None:
    harness = _harness(tmp_path, (_plan(_step("prepare")),), ())
    task = await harness.engine.create_task("Prepare my system for a meeting")
    with pytest.raises(PlanEditError, match="malformed"):
        await harness.engine.request_replan(task.task_id, additional_constraints=("x",) * 33)

    invalid = _harness(
        tmp_path / "invalid",
        (_plan(_step("prepare")), {"invalid": True}),
        (),
    )
    invalid_task = await invalid.engine.create_task("Prepare my system for a meeting")
    with pytest.raises(PlanningEngineError, match="failed validation"):
        await invalid.engine.request_replan(invalid_task.task_id)


@pytest.mark.asyncio
async def test_task_controller_exposes_typed_plan_editing_only(tmp_path: Path) -> None:
    harness = _harness(tmp_path, (_plan(_step("prepare")),), ())
    broker = PermissionBroker(PolicyEngine())
    controller = PlanningTaskController(harness.engine, broker)
    task = await controller.create_task("Prepare my system for a meeting")

    assert controller.list_tasks() == (task,)
    assert controller.get_task(task.task_id) == task
    assert controller.get_status(task.task_id) is PlanningTaskStatus.READY
    assert controller.get_status(uuid4()) is None
    assert controller.inspect_plan(task.task_id) is not None
    assert controller.inspect_plan_details(task.task_id) is not None
    assert controller.list_plan_revisions(task.task_id)[0].version == 1
    assert controller.get_result(uuid4()) is None
    assert controller.get_result(task.task_id).evidence == ()  # type: ignore[union-attr]
    assert await controller.pending_approvals(task.task_id) == ()

    with pytest.raises(PlanEditError, match="no changes"):
        await controller.edit_plan(task.task_id, PlanEdit())

    revision = await controller.edit_plan(
        task.task_id,
        PlanEdit(
            structured_steps=(StructuredStepEdit(key="prepare", expected_output="new expectation"),)
        ),
    )
    assert revision.plan.version == 2
    checkpoint = await controller.checkpoint_plan(
        task.task_id,
        PlanEdit(pause_checkpoint=True),
    )
    assert checkpoint.plan.version == 3
