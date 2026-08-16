"""Deterministic owner of durable single-agent DAG execution and replanning."""

from __future__ import annotations

import asyncio
import json
import logging
from abc import ABC, abstractmethod
from collections.abc import Callable
from dataclasses import replace
from datetime import UTC, datetime, timedelta
from uuid import UUID, uuid4

from jarvis.events import (
    EventBus,
    EventEnvelope,
    EventType,
    PlanCreated,
    PlanUpdated,
    StepCompleted,
    StepFailed,
    StepStarted,
)
from jarvis.planning.models import (
    BudgetUsage,
    ExecutionBudgets,
    FailureKind,
    GoalVerification,
    OwnedPlan,
    OwnedPlanStatus,
    PlanningStep,
    PlanningStepStatus,
    PlanningTask,
    PlanningTaskStatus,
    ReplanEvidence,
    StepError,
    StepExecutionResult,
    StepExecutionStatus,
    StepResult,
    StepVerification,
)
from jarvis.planning.store import PlanningStore, PlanningStoreError
from jarvis.planning.validation import PlanValidationError, PlanValidator
from jarvis.state import ApplicationStateMachine
from jarvis.state.models import TaskState, TransitionEvent
from jarvis.tools.models import (
    ToolCaller,
    ToolExecutionContext,
    ToolResultStatus,
)
from jarvis.tools.registry import ToolRegistry


class PlanningEngineError(RuntimeError):
    pass


class PlanAdvisor(ABC):
    """A model may propose JSON but cannot own or execute the resulting plan."""

    @abstractmethod
    async def propose(
        self, goal: str, assumptions: tuple[str, ...], constraints: tuple[str, ...]
    ) -> object: ...

    @abstractmethod
    async def replan(self, evidence: ReplanEvidence) -> object: ...


class PlanningStepExecutor(ABC):
    @abstractmethod
    async def execute(
        self, task: PlanningTask, step: PlanningStep, cancellation: asyncio.Event
    ) -> StepExecutionResult: ...


class PlanningStepVerifier(ABC):
    @abstractmethod
    async def verify(
        self, step: PlanningStep, execution: StepExecutionResult
    ) -> StepVerification: ...


class PlanningGoalVerifier(ABC):
    @abstractmethod
    async def verify(self, task: PlanningTask, plan: OwnedPlan) -> GoalVerification: ...


class BrokeredPlanningStepExecutor(PlanningStepExecutor):
    """Invoke an exact registry tool through its mandatory bound PermissionBroker."""

    def __init__(self, registry: ToolRegistry, *, event_bus: EventBus | None = None) -> None:
        self._registry = registry
        self._event_bus = event_bus

    async def execute(
        self, task: PlanningTask, step: PlanningStep, cancellation: asyncio.Event
    ) -> StepExecutionResult:
        tool = self._registry.get(step.tool_id)
        context = ToolExecutionContext(
            task_id=task.task_id,
            correlation_id=task.task_id,
            caller=ToolCaller.AGENT,
            cancellation=cancellation,
            logger=logging.getLogger(f"jarvis.planning.{step.tool_id}"),
        )
        raw_input = json.loads(step.input_json)
        if not isinstance(raw_input, dict):
            return StepExecutionResult(
                StepExecutionStatus.DETERMINISTIC_FAILURE,
                error_code="malformed_owned_input",
                error_message="Owned step input is not an object",
            )
        result = await tool.invoke(
            context, raw_input, self._registry.permission_broker, event_bus=self._event_bus
        )
        evidence = tuple(item.value for item in result.evidence)
        if result.status is ToolResultStatus.SUCCESS and result.output is not None:
            return StepExecutionResult(
                StepExecutionStatus.SUCCEEDED,
                output_json=result.output.model_dump_json(),
                evidence=evidence,
            )
        if result.status is ToolResultStatus.PERMISSION_DENIED:
            request_ids: list[UUID] = []
            for item in result.metadata:
                if item.key == "approval_request_id":
                    try:
                        request_ids.append(UUID(item.value))
                    except ValueError:
                        return StepExecutionResult(
                            StepExecutionStatus.DETERMINISTIC_FAILURE,
                            error_code="malformed_approval_reference",
                            error_message=(
                                "Permission broker returned an invalid approval reference"
                            ),
                        )
            if request_ids:
                return StepExecutionResult(
                    StepExecutionStatus.WAITING_FOR_PERMISSION,
                    approval_request_ids=tuple(request_ids),
                )
        error_code = result.error.code if result.error else result.status.value
        error_message = result.error.message if result.error else "Tool execution failed"
        status = (
            StepExecutionStatus.TRANSIENT_FAILURE
            if result.status is ToolResultStatus.TIMEOUT
            else StepExecutionStatus.CANCELLED
            if result.status is ToolResultStatus.CANCELLED
            else StepExecutionStatus.DETERMINISTIC_FAILURE
        )
        return StepExecutionResult(status, error_code=error_code, error_message=error_message)


class EvidencePlanningStepVerifier(PlanningStepVerifier):
    """Apply only trusted built-in verification rules to observed execution evidence."""

    async def verify(self, step: PlanningStep, execution: StepExecutionResult) -> StepVerification:
        if execution.status is not StepExecutionStatus.SUCCEEDED:
            return StepVerification(False, execution.evidence, "Execution did not succeed")
        if step.verification_rule == "evidence_contains_all":
            missing = tuple(
                item for item in step.expected_evidence if item not in execution.evidence
            )
            return StepVerification(
                not missing,
                execution.evidence,
                "Expected evidence observed" if not missing else "Expected evidence was missing",
            )
        if step.verification_rule == "output_contains":
            succeeded = step.expected_output in execution.output_json
            return StepVerification(
                succeeded,
                execution.evidence,
                "Expected output observed" if succeeded else "Expected output was missing",
            )
        return StepVerification(False, execution.evidence, "Unknown verification rule")


class CompletionCriteriaVerifier(PlanningGoalVerifier):
    """Require every goal criterion to appear in independently verified step evidence."""

    async def verify(self, task: PlanningTask, plan: OwnedPlan) -> GoalVerification:
        del task
        observed = tuple(
            evidence
            for step in plan.steps
            if step.result is not None
            for evidence in step.result.evidence
        )
        missing = tuple(item for item in plan.completion_criteria if item not in observed)
        return GoalVerification(
            not missing,
            observed,
            "Goal completion criteria satisfied" if not missing else "Goal criteria were not met",
        )


def _now() -> datetime:
    return datetime.now(UTC)


class PlanningEngine:
    """Own plan state, sequencing, budgets, pause/resume, retries, and completion."""

    _TERMINAL = frozenset(
        {
            PlanningTaskStatus.COMPLETED,
            PlanningTaskStatus.FAILED,
            PlanningTaskStatus.CANCELLED,
            PlanningTaskStatus.BUDGET_EXHAUSTED,
        }
    )

    def __init__(
        self,
        *,
        store: PlanningStore,
        advisor: PlanAdvisor,
        validator: PlanValidator,
        executor: PlanningStepExecutor,
        step_verifier: PlanningStepVerifier,
        goal_verifier: PlanningGoalVerifier,
        clock: Callable[[], datetime] = _now,
        state_machine: ApplicationStateMachine | None = None,
        event_bus: EventBus | None = None,
    ) -> None:
        self._store = store
        self._advisor = advisor
        self._validator = validator
        self._executor = executor
        self._step_verifier = step_verifier
        self._goal_verifier = goal_verifier
        self._clock = clock
        self._state_machine = state_machine
        self._event_bus = event_bus
        self._cancellations: dict[UUID, asyncio.Event] = {}

    async def create_task(
        self,
        goal: str,
        *,
        assumptions: tuple[str, ...] = (),
        constraints: tuple[str, ...] = (),
        budgets: ExecutionBudgets | None = None,
    ) -> PlanningTask:
        budgets = budgets or ExecutionBudgets()
        now = self._clock()
        task = PlanningTask(
            task_id=uuid4(),
            goal=goal,
            original_assumptions=assumptions,
            original_constraints=constraints,
            status=PlanningTaskStatus.PLANNING,
            plan_id=None,
            budgets=budgets,
            usage=BudgetUsage(),
            created_at=now,
            started_at=now,
            deadline=now + timedelta(seconds=budgets.max_elapsed_seconds),
            updated_at=now,
        )
        self._store.create_task(task)
        self._publish_state(task)
        if budgets.max_model_calls < 1:
            return self._fail_budget(task, "model_call_budget_exhausted")
        try:
            raw = await self._advisor.propose(goal, assumptions, constraints)
            plan = self._validator.validate(
                raw,
                task_id=task.task_id,
                required_goal=goal,
                required_assumptions=assumptions,
                required_constraints=constraints,
            )
            if len(plan.steps) > budgets.max_steps:
                raise PlanValidationError("Plan exceeds this task's step budget")
        except (PlanValidationError, ValueError) as error:
            return self._fail(task, "plan_validation_failed", str(error))
        except Exception as error:
            return self._fail(
                task,
                "planning_provider_failed",
                f"Planning provider failed ({type(error).__name__})",
            )
        task = replace(
            task,
            status=PlanningTaskStatus.READY,
            plan_id=plan.plan_id,
            usage=replace(task.usage, model_calls=1),
            updated_at=self._clock(),
        )
        self._save_state(task, plan)
        if self._event_bus is not None:
            self._event_bus.publish_nowait(
                EventEnvelope.create(
                    EventType.PLAN_CREATED,
                    PlanCreated(plan.plan_id, len(plan.steps)),
                    source="planning.engine",
                    task_id=task.task_id,
                    correlation_id=task.task_id,
                )
            )
        return task

    async def submit(
        self,
        goal: str,
        *,
        assumptions: tuple[str, ...] = (),
        constraints: tuple[str, ...] = (),
        budgets: ExecutionBudgets | None = None,
    ) -> PlanningTask:
        budgets = budgets or ExecutionBudgets()
        task = await self.create_task(
            goal, assumptions=assumptions, constraints=constraints, budgets=budgets
        )
        if task.status in self._TERMINAL:
            return task
        return await self.run(task.task_id)

    async def run(self, task_id: UUID) -> PlanningTask:
        if task_id in self._cancellations:
            raise PlanningEngineError("Planning task is already running")
        task, plan = self._load_state(task_id)
        if (
            task.status in self._TERMINAL
            or task.status is PlanningTaskStatus.WAITING_FOR_PERMISSION
        ):
            return task
        interrupted = next(
            (
                step
                for step in plan.steps
                if step.status in {PlanningStepStatus.RUNNING, PlanningStepStatus.VERIFYING}
            ),
            None,
        )
        if interrupted is not None:
            return self._fail(
                task,
                "interrupted_step_unknown_outcome",
                f"Step {interrupted.key} was interrupted with an unknown outcome",
                plan=plan,
            )
        cancellation = asyncio.Event()
        if task.cancellation_requested:
            cancellation.set()
        self._cancellations[task_id] = cancellation
        try:
            return await self._run(task, plan, cancellation)
        finally:
            self._cancellations.pop(task_id, None)

    async def resume(self, task_id: UUID) -> PlanningTask:
        """Retry a paused step; the PermissionBroker, not this method, decides authorization."""

        task, plan = self._load_state(task_id)
        if task.status is not PlanningTaskStatus.WAITING_FOR_PERMISSION:
            raise PlanningEngineError("Only a permission-paused task can be resumed")
        steps = tuple(
            replace(step, status=PlanningStepStatus.QUEUED)
            if step.status is PlanningStepStatus.WAITING_FOR_PERMISSION
            else step
            for step in plan.steps
        )
        now = self._clock()
        plan = replace(plan, status=OwnedPlanStatus.ACTIVE, steps=steps, updated_at=now)
        task = replace(
            task,
            status=PlanningTaskStatus.READY,
            waiting_request_ids=(),
            active_step_id=None,
            updated_at=now,
        )
        self._save_state(task, plan)
        return await self.run(task_id)

    def cancel(self, task_id: UUID) -> PlanningTask:
        task, plan = self._load_state(task_id)
        if task.status in self._TERMINAL:
            return task
        event = self._cancellations.get(task_id)
        if event is not None:
            event.set()
        task = replace(task, cancellation_requested=True, updated_at=self._clock())
        self._save_state(task, plan)
        return task

    async def _run(
        self, task: PlanningTask, plan: OwnedPlan, cancellation: asyncio.Event
    ) -> PlanningTask:
        while True:
            if cancellation.is_set() or task.cancellation_requested:
                return self._cancelled(task, plan)
            budget_error = self._budget_error(task, None)
            if budget_error is not None:
                return self._fail_budget(task, budget_error, plan=plan)
            step = self._next_step(plan)
            if step is None:
                if all(item.status is PlanningStepStatus.SUCCEEDED for item in plan.steps):
                    return await self._verify_goal(task, plan)
                return self._fail(task, "task_graph_blocked", "No executable DAG node", plan=plan)
            budget_error = self._budget_error(task, step)
            if budget_error is not None:
                return self._fail_budget(task, budget_error, plan=plan)
            task, plan, step = self._begin_step(task, plan, step)
            self._emit_step(EventType.STEP_STARTED, task, step, "started")
            try:
                execution = await self._executor.execute(task, step, cancellation)
            except Exception as adapter_error:
                execution = StepExecutionResult(
                    StepExecutionStatus.DETERMINISTIC_FAILURE,
                    error_code="step_executor_failed",
                    error_message=(f"Step executor failed ({type(adapter_error).__name__})"),
                )
            if cancellation.is_set() or execution.status is StepExecutionStatus.CANCELLED:
                return self._cancelled(task, plan)
            if execution.status is StepExecutionStatus.WAITING_FOR_PERMISSION:
                return self._pause(task, plan, step, execution.approval_request_ids)
            if execution.status is StepExecutionStatus.TRANSIENT_FAILURE:
                self._emit_step(
                    EventType.STEP_FAILED, task, step, execution.error_code or "transient_failure"
                )
                step_error = self._execution_error(execution, FailureKind.TRANSIENT)
                if (
                    step.attempts <= step.max_retries
                    and task.usage.retries < task.budgets.max_retries
                ):
                    task = replace(
                        task,
                        usage=replace(task.usage, retries=task.usage.retries + 1),
                        active_step_id=None,
                        status=PlanningTaskStatus.READY,
                        updated_at=self._clock(),
                    )
                    plan = self._replace_step(
                        plan,
                        replace(step, status=PlanningStepStatus.QUEUED, error=step_error),
                    )
                    self._save_state(task, plan)
                    continue
                return await self._replan_or_fail(task, plan, step, step_error, execution.evidence)
            if execution.status is StepExecutionStatus.DETERMINISTIC_FAILURE:
                self._emit_step(
                    EventType.STEP_FAILED,
                    task,
                    step,
                    execution.error_code or "deterministic_failure",
                )
                step_error = self._execution_error(execution, FailureKind.DETERMINISTIC)
                return await self._replan_or_fail(task, plan, step, step_error, execution.evidence)

            task = replace(
                task,
                status=PlanningTaskStatus.VERIFYING,
                updated_at=self._clock(),
            )
            plan = self._replace_step(plan, replace(step, status=PlanningStepStatus.VERIFYING))
            self._save_state(task, plan)
            try:
                verification = await self._step_verifier.verify(step, execution)
            except Exception as adapter_error:
                verification = StepVerification(
                    False,
                    execution.evidence,
                    f"Step verifier failed ({type(adapter_error).__name__})",
                )
            if not verification.succeeded:
                self._emit_step(EventType.STEP_FAILED, task, step, "step_verification_failed")
                step_error = StepError(
                    "step_verification_failed",
                    verification.reason,
                    FailureKind.DETERMINISTIC,
                    verification.evidence,
                )
                return await self._replan_or_fail(
                    task, plan, step, step_error, verification.evidence
                )
            result = StepResult(execution.output_json, verification.evidence)
            plan = self._replace_step(
                plan,
                replace(
                    step,
                    status=PlanningStepStatus.SUCCEEDED,
                    result=result,
                    error=None,
                ),
            )
            task = replace(
                task,
                status=PlanningTaskStatus.READY,
                active_step_id=None,
                updated_at=self._clock(),
            )
            self._save_state(task, plan)
            self._emit_step(EventType.STEP_COMPLETED, task, step, "succeeded")

    def _begin_step(
        self, task: PlanningTask, plan: OwnedPlan, step: PlanningStep
    ) -> tuple[PlanningTask, OwnedPlan, PlanningStep]:
        usage = replace(
            task.usage,
            executed_steps=task.usage.executed_steps + 1,
            expensive_actions=task.usage.expensive_actions + int(step.expensive_action),
        )
        step = replace(
            step,
            status=PlanningStepStatus.RUNNING,
            attempts=step.attempts + 1,
            result=None,
        )
        now = self._clock()
        task = replace(
            task,
            status=PlanningTaskStatus.EXECUTING,
            active_step_id=step.step_id,
            usage=usage,
            updated_at=now,
        )
        plan = self._replace_step(replace(plan, status=OwnedPlanStatus.ACTIVE), step)
        self._save_state(task, plan)
        return task, plan, step

    async def _replan_or_fail(
        self,
        task: PlanningTask,
        plan: OwnedPlan,
        step: PlanningStep,
        error: StepError,
        evidence: tuple[str, ...],
    ) -> PlanningTask:
        failed_plan = self._replace_step(
            plan, replace(step, status=PlanningStepStatus.FAILED, error=error)
        )
        if task.usage.model_calls >= task.budgets.max_model_calls:
            return self._fail_budget(task, "model_call_budget_exhausted", plan=failed_plan)
        now = self._clock()
        task = replace(task, status=PlanningTaskStatus.REPLANNING, updated_at=now)
        self._save_state(task, failed_plan)
        replan_evidence = ReplanEvidence(
            original_goal=task.goal,
            original_assumptions=task.original_assumptions,
            original_constraints=task.original_constraints,
            failed_step_key=step.key,
            error=error,
            observed_evidence=evidence,
            prior_plan_version=plan.version,
        )
        try:
            raw = await self._advisor.replan(replan_evidence)
            replacement = self._validator.validate(
                raw,
                task_id=task.task_id,
                version=plan.version + 1,
                required_goal=task.goal,
                required_assumptions=task.original_assumptions,
                required_constraints=task.original_constraints,
            )
            if len(replacement.steps) > task.budgets.max_steps:
                raise PlanValidationError("Replan exceeds this task's step budget")
        except (PlanValidationError, ValueError) as validation_error:
            return self._fail(
                task,
                "replan_validation_failed",
                str(validation_error),
                plan=failed_plan,
            )
        except Exception as error:
            return self._fail(
                task,
                "replanning_provider_failed",
                f"Replanning provider failed ({type(error).__name__})",
                plan=failed_plan,
            )
        task = replace(
            task,
            status=PlanningTaskStatus.READY,
            plan_id=replacement.plan_id,
            active_step_id=None,
            usage=replace(task.usage, model_calls=task.usage.model_calls + 1),
            updated_at=self._clock(),
        )
        self._save_state(task, replacement)
        return await self._run(task, replacement, self._cancellations[task.task_id])

    async def _verify_goal(self, task: PlanningTask, plan: OwnedPlan) -> PlanningTask:
        task = replace(task, status=PlanningTaskStatus.VERIFYING, updated_at=self._clock())
        self._save_state(task, plan)
        try:
            verification = await self._goal_verifier.verify(task, plan)
        except Exception as error:
            return self._fail(
                task,
                "goal_verifier_failed",
                f"Goal verifier failed ({type(error).__name__})",
                plan=replace(plan, status=OwnedPlanStatus.FAILED),
            )
        if not verification.succeeded:
            return self._fail(
                task,
                "goal_verification_failed",
                verification.reason,
                plan=replace(plan, status=OwnedPlanStatus.FAILED),
                evidence=verification.evidence,
            )
        now = self._clock()
        plan = replace(plan, status=OwnedPlanStatus.COMPLETED, updated_at=now)
        task = replace(
            task,
            status=PlanningTaskStatus.COMPLETED,
            active_step_id=None,
            result_evidence=verification.evidence,
            error=None,
            updated_at=now,
        )
        self._save_state(task, plan)
        return task

    def _pause(
        self,
        task: PlanningTask,
        plan: OwnedPlan,
        step: PlanningStep,
        request_ids: tuple[UUID, ...],
    ) -> PlanningTask:
        now = self._clock()
        plan = self._replace_step(
            replace(plan, status=OwnedPlanStatus.WAITING_FOR_PERMISSION),
            replace(step, status=PlanningStepStatus.WAITING_FOR_PERMISSION),
        )
        task = replace(
            task,
            status=PlanningTaskStatus.WAITING_FOR_PERMISSION,
            active_step_id=step.step_id,
            waiting_request_ids=request_ids,
            updated_at=now,
        )
        self._save_state(task, plan)
        return task

    def _cancelled(self, task: PlanningTask, plan: OwnedPlan) -> PlanningTask:
        steps = tuple(
            replace(
                step,
                status=(
                    PlanningStepStatus.BLOCKED
                    if step.dependencies
                    else PlanningStepStatus.CANCELLED
                ),
                error=StepError(
                    "task_cancelled", "Task cancellation was requested", FailureKind.CANCELLED
                ),
            )
            if step.status not in {PlanningStepStatus.SUCCEEDED, PlanningStepStatus.FAILED}
            else step
            for step in plan.steps
        )
        now = self._clock()
        plan = replace(plan, status=OwnedPlanStatus.CANCELLED, steps=steps, updated_at=now)
        task = replace(
            task,
            status=PlanningTaskStatus.CANCELLED,
            cancellation_requested=True,
            active_step_id=None,
            waiting_request_ids=(),
            error=StepError(
                "task_cancelled", "Task cancellation was requested", FailureKind.CANCELLED
            ),
            updated_at=now,
        )
        self._save_state(task, plan)
        return task

    def _fail_budget(
        self, task: PlanningTask, code: str, *, plan: OwnedPlan | None = None
    ) -> PlanningTask:
        error = StepError(code, "Planning task budget was exhausted", FailureKind.DETERMINISTIC)
        return self._finish(task, PlanningTaskStatus.BUDGET_EXHAUSTED, error, plan)

    def _fail(
        self,
        task: PlanningTask,
        code: str,
        message: str,
        *,
        plan: OwnedPlan | None = None,
        evidence: tuple[str, ...] = (),
    ) -> PlanningTask:
        error = StepError(code, message, FailureKind.DETERMINISTIC, evidence)
        return self._finish(task, PlanningTaskStatus.FAILED, error, plan)

    def _finish(
        self,
        task: PlanningTask,
        status: PlanningTaskStatus,
        error: StepError,
        plan: OwnedPlan | None,
    ) -> PlanningTask:
        task = replace(
            task,
            status=status,
            active_step_id=None,
            waiting_request_ids=(),
            error=error,
            updated_at=self._clock(),
        )
        if plan is None:
            self._save_task(task)
        else:
            self._save_state(
                task,
                replace(
                    plan,
                    status=OwnedPlanStatus.FAILED,
                    updated_at=self._clock(),
                ),
            )
        return task

    def _budget_error(self, task: PlanningTask, step: PlanningStep | None) -> str | None:
        now = self._clock()
        if now >= task.deadline:
            return "elapsed_time_budget_exhausted"
        if task.usage.executed_steps >= task.budgets.max_steps:
            return "step_budget_exhausted"
        if (
            step is not None
            and step.expensive_action
            and task.usage.expensive_actions >= task.budgets.max_expensive_actions
        ):
            return "expensive_action_budget_exhausted"
        return None

    def _save_state(self, task: PlanningTask, plan: OwnedPlan) -> None:
        self._publish_state(task, plan_revision=plan.version)
        self._store.save_state(task, plan)
        if self._event_bus is not None:
            self._event_bus.publish_nowait(
                EventEnvelope.create(
                    EventType.PLAN_UPDATED,
                    PlanUpdated(plan.plan_id, plan.version),
                    source="planning.engine",
                    task_id=task.task_id,
                    correlation_id=task.task_id,
                )
            )

    def _emit_step(
        self, event_type: EventType, task: PlanningTask, step: PlanningStep, detail: str
    ) -> None:
        if self._event_bus is None:
            return
        payload: StepStarted | StepCompleted | StepFailed
        if event_type is EventType.STEP_STARTED:
            payload = StepStarted(step.step_id, step.tool_id)
        elif event_type is EventType.STEP_COMPLETED:
            payload = StepCompleted(step.step_id, detail)
        else:
            payload = StepFailed(step.step_id, detail)
        self._event_bus.publish_nowait(
            EventEnvelope.create(
                event_type,
                payload,
                source="planning.engine",
                task_id=task.task_id,
                correlation_id=task.task_id,
            )
        )

    def _save_task(self, task: PlanningTask) -> None:
        self._publish_state(task)
        self._store.save_task(task)

    def _publish_state(self, task: PlanningTask, *, plan_revision: int | None = None) -> None:
        """Publish planner progress through the authoritative coordinator."""

        if self._state_machine is None:
            return
        target = {
            PlanningTaskStatus.CREATED: TaskState.CREATED,
            PlanningTaskStatus.PLANNING: TaskState.PLANNING,
            PlanningTaskStatus.READY: TaskState.WAITING,
            PlanningTaskStatus.EXECUTING: TaskState.EXECUTING,
            PlanningTaskStatus.WAITING_FOR_PERMISSION: TaskState.WAITING_FOR_PERMISSION,
            PlanningTaskStatus.VERIFYING: TaskState.VERIFYING,
            PlanningTaskStatus.REPLANNING: TaskState.THINKING,
            PlanningTaskStatus.COMPLETED: TaskState.COMPLETED,
            PlanningTaskStatus.FAILED: TaskState.ERROR,
            PlanningTaskStatus.CANCELLED: TaskState.CANCELLED,
            PlanningTaskStatus.BUDGET_EXHAUSTED: TaskState.ERROR,
        }[task.status]
        events = {
            TaskState.THINKING: TransitionEvent.REPLAN_REQUESTED,
            TaskState.PLANNING: TransitionEvent.PLAN_REQUESTED,
            TaskState.WAITING: TransitionEvent.PLAN_READY,
            TaskState.WAITING_FOR_PERMISSION: TransitionEvent.PERMISSION_REQUIRED,
            TaskState.EXECUTING: TransitionEvent.EXECUTION_STARTED,
            TaskState.VERIFYING: TransitionEvent.VERIFICATION_STARTED,
            TaskState.COMPLETED: TransitionEvent.TASK_COMPLETED,
            TaskState.ERROR: TransitionEvent.TASK_FAILED,
            TaskState.CANCELLED: TransitionEvent.TASK_CANCELLED,
        }
        current = self._state_machine.task(task.task_id)
        if current is None:
            self._state_machine.create_task(task.task_id, reason="planner task created")
            current = self._state_machine.task(task.task_id)
        if current is None or current.state is target:
            return
        if current.state is TaskState.CREATED and target is TaskState.PLANNING:
            self._state_machine.transition_task(
                task.task_id,
                TaskState.THINKING,
                TransitionEvent.TASK_THINKING,
                reason="planner started thinking",
            )
            current = self._state_machine.task(task.task_id)
        if current is None or current.state is target:
            return
        self._state_machine.transition_task(
            task.task_id,
            target,
            events[target],
            reason=f"planner status: {task.status.value}",
            plan_revision=plan_revision,
            active_step_id=task.active_step_id,
        )

    def _load_state(self, task_id: UUID) -> tuple[PlanningTask, OwnedPlan]:
        task = self._store.load_task(task_id)
        if task is None:
            raise PlanningEngineError(f"Planning task does not exist: {task_id}")
        plan = self._store.load_plan(task_id)
        if plan is None or task.plan_id != plan.plan_id:
            raise PlanningStoreError("Planning task has no matching current plan")
        return task, plan

    @staticmethod
    def _next_step(plan: OwnedPlan) -> PlanningStep | None:
        succeeded = {
            step.step_id for step in plan.steps if step.status is PlanningStepStatus.SUCCEEDED
        }
        ready = tuple(
            step
            for step in plan.steps
            if step.status is PlanningStepStatus.QUEUED
            and all(dependency in succeeded for dependency in step.dependencies)
        )
        return min(ready, key=lambda item: item.key) if ready else None

    def _replace_step(self, plan: OwnedPlan, replacement: PlanningStep) -> OwnedPlan:
        return replace(
            plan,
            steps=tuple(
                replacement if step.step_id == replacement.step_id else step for step in plan.steps
            ),
            updated_at=self._clock(),
        )

    @staticmethod
    def _execution_error(execution: StepExecutionResult, kind: FailureKind) -> StepError:
        return StepError(
            execution.error_code or "step_execution_failed",
            execution.error_message or "Step execution failed",
            kind,
            execution.evidence,
        )
