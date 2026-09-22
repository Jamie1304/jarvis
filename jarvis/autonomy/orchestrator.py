"""Bounded single-agent task coordinator with application-owned state transitions."""

import asyncio
import logging
from collections.abc import Coroutine
from contextlib import suppress
from dataclasses import replace
from datetime import UTC, datetime
from typing import Any, TypeVar
from uuid import UUID, uuid4

from jarvis.autonomy.execution import (
    CapabilitySelector,
    ObservationService,
    StepVerifier,
    ToolExecutor,
)
from jarvis.autonomy.models import (
    Plan,
    PlanStatus,
    PlanStep,
    StepStatus,
    StructuredTaskError,
    Task,
    TaskStatus,
    ToolObservation,
    VerificationResult,
    VerificationStatus,
)
from jarvis.autonomy.planning import RequestInterpreter, TaskPlanner
from jarvis.autonomy.response import TaskResponseGenerator
from jarvis.autonomy.store import TaskStore
from jarvis.core.errors import (
    PlanningError,
    TaskCancelledError,
    TaskError,
    TaskTimeoutError,
    VerificationFailedError,
    VerificationUnverifiableError,
)
from jarvis.state import ApplicationStateMachine
from jarvis.state.models import TaskState, TransitionEvent
from jarvis.tools.base import Tool
from jarvis.tools.models import (
    ToolCaller,
    ToolExecutionContext,
    ToolResult,
)

ResultType = TypeVar("ResultType")


class AgentOrchestrator:
    """Coordinate one bounded task by delegating each orchestration responsibility."""

    def __init__(
        self,
        *,
        store: TaskStore,
        interpreter: RequestInterpreter,
        planner: TaskPlanner,
        selector: CapabilitySelector,
        executor: ToolExecutor,
        observer: ObservationService,
        verifier: StepVerifier,
        response_generator: TaskResponseGenerator,
        max_steps: int,
        timeout_seconds: float,
        max_replans: int,
        state_machine: ApplicationStateMachine | None = None,
    ) -> None:
        if max_steps < 1 or timeout_seconds <= 0 or max_replans < 0:
            raise ValueError(
                "Task execution limits must be positive and replans cannot be negative"
            )
        self._store = store
        self._interpreter = interpreter
        self._planner = planner
        self._selector = selector
        self._executor = executor
        self._observer = observer
        self._verifier = verifier
        self._response_generator = response_generator
        self._max_steps = max_steps
        self._timeout_seconds = timeout_seconds
        self._max_replans = max_replans
        self._state_machine = state_machine
        self._cancellations: dict[UUID, asyncio.Event] = {}

    async def create_task(
        self, conversation_id: UUID, user_request: str, correlation_id: UUID | None = None
    ) -> Task:
        """Create a task without starting its execution, allowing later cancellation."""

        now = datetime.now(UTC)
        task = Task(
            task_id=uuid4(),
            conversation_id=conversation_id,
            user_request=user_request,
            status=TaskStatus.CREATED,
            created_at=now,
            updated_at=now,
            current_step=None,
            result=None,
            error=None,
            cancellation_requested=False,
            correlation_id=correlation_id or uuid4(),
        )
        await self._store.create_task(task)
        self._publish_state(task)
        return task

    async def run(self, task_id: UUID) -> Task:
        """Execute a previously created task within fixed cancellation and time budgets."""

        task = await self._require_task(task_id)
        if task.status in self._terminal_statuses():
            return task
        cancellation = asyncio.Event()
        if task.cancellation_requested:
            cancellation.set()
        self._cancellations[task_id] = cancellation
        try:
            async with asyncio.timeout(self._timeout_seconds):
                return await self._run_bounded(task, cancellation)
        except TimeoutError:
            task = await self._require_task(task_id)
            return await self._finish_failure(
                task,
                TaskStatus.TIMED_OUT,
                TaskTimeoutError("Task exceeded its execution time budget"),
            )
        except TaskCancelledError as error:
            task = await self._require_task(task_id)
            return await self._finish_failure(task, TaskStatus.CANCELLED, error)
        except TaskError as error:
            task = await self._require_task(task_id)
            return await self._finish_failure(task, TaskStatus.FAILED, error)
        except Exception as error:
            task = await self._require_task(task_id)
            unexpected = TaskError("Unexpected task orchestration failure")
            return await self._finish_failure(
                task,
                TaskStatus.FAILED,
                unexpected,
                detail=str(error),
            )
        finally:
            self._cancellations.pop(task_id, None)

    async def submit(self, conversation_id: UUID, user_request: str) -> Task:
        """Create and run a task as one convenience operation."""

        task = await self.create_task(conversation_id, user_request)
        return await self.run(task.task_id)

    async def cancel(self, task_id: UUID) -> Task:
        """Persist cancellation and interrupt a currently active task when possible."""

        task = await self._require_task(task_id)
        if task.status in self._terminal_statuses():
            return task
        task = await self._save_task(replace(task, cancellation_requested=True))
        active = self._cancellations.get(task_id)
        if active is not None:
            active.set()
        return task

    async def _run_bounded(self, task: Task, cancellation: asyncio.Event) -> Task:
        self._raise_if_cancelled(task, cancellation)
        task = await self._save_task(replace(task, status=TaskStatus.PLANNING))
        intent = await self._await_or_cancel(self._interpreter.interpret(task), cancellation)
        plan = await self._await_or_cancel(self._planner.create_plan(task, intent), cancellation)
        self._validate_plan(task, plan)
        plan = replace(plan, status=PlanStatus.ACTIVE)
        await self._store.save_plan(plan)

        executed_steps = 0
        replans = 0
        while True:
            task = await self._require_task(task.task_id)
            self._raise_if_cancelled(task, cancellation)
            step = self._next_step(plan)
            if step is None:
                if all(item.status is StepStatus.VERIFIED for item in plan.steps):
                    return await self._complete(task, plan, cancellation)
                raise PlanningError(
                    "Plan cannot advance because dependency requirements are unsatisfied"
                )
            if executed_steps >= self._max_steps:
                raise TaskError("Task exceeded its maximum step count")

            task = await self._save_task(
                replace(task, status=TaskStatus.EXECUTING, current_step=step.step_id)
            )
            plan = await self._save_step(plan, replace(step, status=StepStatus.RUNNING))
            tool = self._selector.select(step)
            result = await self._execute_step(task, step, tool, cancellation)
            observation = await self._await_or_cancel(self._observer.observe(result), cancellation)

            task = await self._save_task(replace(task, status=TaskStatus.VERIFYING))
            verification = await self._await_or_cancel(
                self._verifier.verify(step, observation), cancellation
            )
            executed_steps += 1
            if verification.status is VerificationStatus.SUCCEEDED:
                plan = await self._save_step(plan, replace(step, status=StepStatus.VERIFIED))
                continue

            plan = await self._save_step(plan, replace(step, status=StepStatus.FAILED))
            failure = self._verification_error(step, observation, verification)
            if replans >= self._max_replans:
                if verification.status is VerificationStatus.FAILED:
                    raise VerificationFailedError(failure.message)
                raise VerificationUnverifiableError(failure.message)
            replans += 1
            task = await self._save_task(replace(task, status=TaskStatus.REPLANNING))
            plan = await self._await_or_cancel(
                self._planner.replan(task, intent, failure), cancellation
            )
            self._validate_plan(task, plan)
            plan = replace(plan, status=PlanStatus.ACTIVE)
            await self._store.save_plan(plan)

    async def _execute_step(
        self, task: Task, step: PlanStep, tool: Tool[Any, Any], cancellation: asyncio.Event
    ) -> ToolResult:
        context = ToolExecutionContext(
            task_id=task.task_id,
            correlation_id=task.correlation_id,
            caller=ToolCaller.AGENT,
            cancellation=cancellation,
            logger=logging.getLogger(f"jarvis.tools.{tool.manifest.tool_id}"),
        )
        raw_input: dict[str, object] = {
            argument.name: argument.value for argument in step.arguments
        }
        return await self._await_or_cancel(
            self._executor.execute(tool, context, raw_input), cancellation
        )

    async def _complete(self, task: Task, plan: Plan, cancellation: asyncio.Event) -> Task:
        result = await self._await_or_cancel(
            self._response_generator.generate(task, plan), cancellation
        )
        await self._store.save_plan(replace(plan, status=PlanStatus.COMPLETED))
        return await self._save_task(
            replace(task, status=TaskStatus.COMPLETED, current_step=None, result=result, error=None)
        )

    async def _finish_failure(
        self, task: Task, status: TaskStatus, error: TaskError, detail: str | None = None
    ) -> Task:
        structured = StructuredTaskError(code=error.code, message=str(error), detail=detail)
        return await self._save_task(
            replace(task, status=status, current_step=None, error=structured, result=None)
        )

    async def _save_task(self, task: Task) -> Task:
        current = await self._store.get_task(task.task_id)
        cancellation_requested = task.cancellation_requested or bool(
            current and current.cancellation_requested
        )
        updated = replace(
            task,
            cancellation_requested=cancellation_requested,
            updated_at=datetime.now(UTC),
        )
        await self._store.save_task(updated)
        self._publish_state(updated)
        return updated

    def _publish_state(self, task: Task) -> None:
        if self._state_machine is None:
            return
        target = {
            TaskStatus.CREATED: TaskState.CREATED,
            TaskStatus.PLANNING: TaskState.PLANNING,
            TaskStatus.EXECUTING: TaskState.EXECUTING,
            TaskStatus.VERIFYING: TaskState.VERIFYING,
            TaskStatus.REPLANNING: TaskState.THINKING,
            TaskStatus.COMPLETED: TaskState.COMPLETED,
            TaskStatus.FAILED: TaskState.ERROR,
            TaskStatus.CANCELLED: TaskState.CANCELLED,
            TaskStatus.TIMED_OUT: TaskState.ERROR,
        }[task.status]
        event = {
            TaskState.THINKING: TransitionEvent.REPLAN_REQUESTED,
            TaskState.PLANNING: TransitionEvent.PLAN_REQUESTED,
            TaskState.EXECUTING: TransitionEvent.EXECUTION_STARTED,
            TaskState.VERIFYING: TransitionEvent.VERIFICATION_STARTED,
            TaskState.COMPLETED: TransitionEvent.TASK_COMPLETED,
            TaskState.ERROR: TransitionEvent.TASK_FAILED,
            TaskState.CANCELLED: TransitionEvent.TASK_CANCELLED,
        }
        current = self._state_machine.task(task.task_id)
        if current is None:
            self._state_machine.create_task(task.task_id, reason="legacy task created")
            current = self._state_machine.task(task.task_id)
        if current is None or current.state is target:
            return
        if current.state is TaskState.CREATED and target is TaskState.PLANNING:
            self._state_machine.transition_task(
                task.task_id,
                TaskState.THINKING,
                TransitionEvent.TASK_THINKING,
                reason="task entered planning",
            )
            current = self._state_machine.task(task.task_id)
        if current is None or current.state is target:
            return
        self._state_machine.transition_task(
            task.task_id, target, event[target], reason=f"task status: {task.status.value}"
        )

    async def _save_step(self, plan: Plan, replacement: PlanStep) -> Plan:
        steps = tuple(
            replacement if step.step_id == replacement.step_id else step for step in plan.steps
        )
        updated = replace(plan, steps=steps)
        await self._store.save_plan(updated)
        return updated

    async def _require_task(self, task_id: UUID) -> Task:
        task = await self._store.get_task(task_id)
        if task is None:
            raise TaskError(f"Task does not exist: {task_id}")
        return task

    async def _await_or_cancel(
        self, work: Coroutine[Any, Any, ResultType], cancellation: asyncio.Event
    ) -> ResultType:
        if cancellation.is_set():
            raise TaskCancelledError("Task cancellation was requested")
        work_task = asyncio.create_task(work)
        cancellation_task = asyncio.create_task(cancellation.wait())
        try:
            done, _ = await asyncio.wait(
                {work_task, cancellation_task}, return_when=asyncio.FIRST_COMPLETED
            )
            if cancellation_task in done:
                raise TaskCancelledError("Task cancellation was requested")
            return await work_task
        finally:
            for pending in (work_task, cancellation_task):
                if not pending.done():
                    pending.cancel()
            with suppress(asyncio.CancelledError):
                await asyncio.gather(work_task, cancellation_task)

    @staticmethod
    def _next_step(plan: Plan) -> PlanStep | None:
        verified = {step.step_id for step in plan.steps if step.status is StepStatus.VERIFIED}
        for step in plan.steps:
            if step.status is StepStatus.PENDING and all(
                dependency in verified for dependency in step.dependencies
            ):
                return step
        return None

    @staticmethod
    def _validate_plan(task: Task, plan: Plan) -> None:
        if plan.task_id != task.task_id:
            raise PlanningError("Plan belongs to a different task")
        if not plan.steps:
            raise PlanningError("Plan must contain at least one step")
        seen_ids: set[UUID] = set()
        for expected_order, step in enumerate(plan.steps):
            if step.order != expected_order or step.step_id in seen_ids:
                raise PlanningError("Plan steps must have unique sequential ordering")
            if any(dependency not in seen_ids for dependency in step.dependencies):
                raise PlanningError("Plan dependencies must reference earlier steps")
            seen_ids.add(step.step_id)

    @staticmethod
    def _verification_error(
        step: PlanStep, observation: ToolObservation, verification: VerificationResult
    ) -> StructuredTaskError:
        detail = verification.detail or observation.summary
        if verification.status is VerificationStatus.FAILED:
            evidence = "; ".join(verification.failure_evidence)
            return StructuredTaskError(
                code="verification_failed",
                message=f"Verification failed for step: {step.expected_outcome}",
                detail=evidence or detail,
            )
        return StructuredTaskError(
            code="verification_unverifiable",
            message=f"Verification was not possible for step: {step.expected_outcome}",
            detail=detail,
        )

    @staticmethod
    def _raise_if_cancelled(task: Task, cancellation: asyncio.Event) -> None:
        if task.cancellation_requested or cancellation.is_set():
            raise TaskCancelledError("Task cancellation was requested")

    @staticmethod
    def _terminal_statuses() -> frozenset[TaskStatus]:
        return frozenset(
            {
                TaskStatus.COMPLETED,
                TaskStatus.FAILED,
                TaskStatus.CANCELLED,
                TaskStatus.TIMED_OUT,
            }
        )
