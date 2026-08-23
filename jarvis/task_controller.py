"""Stable application-facing task API backed only by the canonical PlanningEngine."""

from __future__ import annotations

import asyncio
from dataclasses import dataclass
from typing import Protocol
from uuid import UUID

from jarvis.permissions.approval import TrustedApprovalContext
from jarvis.permissions.broker import PermissionBroker
from jarvis.permissions.models import (
    ApprovalDecisionResult,
    ApprovalRequest,
)
from jarvis.planning.editing import PlanEdit, PlanInspection, PlanRevision
from jarvis.planning.engine import PlanningEngine
from jarvis.planning.models import (
    ExecutionBudgets,
    OwnedPlan,
    PlanningTask,
    PlanningTaskStatus,
    StepError,
)


@dataclass(frozen=True, slots=True)
class TaskResult:
    """Read-only result view assembled from authoritative planning records."""

    task_id: UUID
    status: PlanningTaskStatus
    evidence: tuple[str, ...]
    plan: OwnedPlan | None
    error: StepError | None


class TaskController(Protocol):
    async def create_task(
        self,
        goal: str,
        *,
        assumptions: tuple[str, ...] = (),
        constraints: tuple[str, ...] = (),
        budgets: ExecutionBudgets | None = None,
    ) -> PlanningTask: ...
    async def submit_task(
        self,
        goal: str,
        *,
        assumptions: tuple[str, ...] = (),
        constraints: tuple[str, ...] = (),
        budgets: ExecutionBudgets | None = None,
    ) -> PlanningTask: ...
    async def run_task(self, task_id: UUID) -> PlanningTask: ...
    def get_task(self, task_id: UUID) -> PlanningTask | None: ...
    def list_tasks(self) -> tuple[PlanningTask, ...]: ...
    def get_status(self, task_id: UUID) -> PlanningTaskStatus | None: ...
    def inspect_plan(self, task_id: UUID) -> OwnedPlan | None: ...
    def inspect_plan_details(self, task_id: UUID) -> PlanInspection | None: ...
    def list_plan_revisions(self, task_id: UUID) -> tuple[OwnedPlan, ...]: ...
    async def edit_plan(self, task_id: UUID, edit: PlanEdit) -> PlanRevision: ...
    async def checkpoint_plan(self, task_id: UUID, edit: PlanEdit) -> PlanRevision: ...
    async def replan_task(
        self, task_id: UUID, *, additional_constraints: tuple[str, ...] = ()
    ) -> PlanRevision: ...
    def get_result(self, task_id: UUID) -> TaskResult | None: ...
    async def resume_task(self, task_id: UUID) -> PlanningTask: ...
    async def cancel_task(self, task_id: UUID) -> PlanningTask: ...
    async def pending_approvals(
        self, task_id: UUID | None = None
    ) -> tuple[ApprovalRequest, ...]: ...
    async def submit_approval_decision(
        self,
        context: TrustedApprovalContext,
    ) -> ApprovalDecisionResult: ...


class PlanningTaskController:
    """Adapter that prevents application/UI code from selecting an execution engine."""

    def __init__(self, engine: PlanningEngine, broker: PermissionBroker) -> None:
        self._engine = engine
        self._broker = broker

    async def create_task(
        self,
        goal: str,
        *,
        assumptions: tuple[str, ...] = (),
        constraints: tuple[str, ...] = (),
        budgets: ExecutionBudgets | None = None,
    ) -> PlanningTask:
        return await self._engine.create_task(
            goal, assumptions=assumptions, constraints=constraints, budgets=budgets
        )

    async def submit_task(
        self,
        goal: str,
        *,
        assumptions: tuple[str, ...] = (),
        constraints: tuple[str, ...] = (),
        budgets: ExecutionBudgets | None = None,
    ) -> PlanningTask:
        return await self._engine.submit(
            goal, assumptions=assumptions, constraints=constraints, budgets=budgets
        )

    async def run_task(self, task_id: UUID) -> PlanningTask:
        return await self._engine.run(task_id)

    def get_task(self, task_id: UUID) -> PlanningTask | None:
        return self._engine.get_task(task_id)

    def list_tasks(self) -> tuple[PlanningTask, ...]:
        return self._engine.list_tasks()

    def get_status(self, task_id: UUID) -> PlanningTaskStatus | None:
        task = self._engine.get_task(task_id)
        return task.status if task is not None else None

    def inspect_plan(self, task_id: UUID) -> OwnedPlan | None:
        return self._engine.inspect_plan(task_id)

    def inspect_plan_details(self, task_id: UUID) -> PlanInspection | None:
        return self._engine.inspect_plan_details(task_id)

    def list_plan_revisions(self, task_id: UUID) -> tuple[OwnedPlan, ...]:
        return self._engine.list_plan_revisions(task_id)

    async def edit_plan(self, task_id: UUID, edit: PlanEdit) -> PlanRevision:
        return await self._engine.apply_plan_edit(task_id, edit)

    async def checkpoint_plan(self, task_id: UUID, edit: PlanEdit) -> PlanRevision:
        return await self._engine.create_checkpoint_branch(task_id, edit)

    async def replan_task(
        self, task_id: UUID, *, additional_constraints: tuple[str, ...] = ()
    ) -> PlanRevision:
        return await self._engine.request_replan(
            task_id, additional_constraints=additional_constraints
        )

    def get_result(self, task_id: UUID) -> TaskResult | None:
        task = self._engine.get_task(task_id)
        if task is None:
            return None
        plan = self._engine.inspect_plan(task_id)
        if task.result_evidence:
            evidence = task.result_evidence
        elif task.error is not None:
            evidence = task.error.evidence
        else:
            evidence = tuple(
                item
                for step in (plan.steps if plan is not None else ())
                if step.result is not None
                for item in step.result.evidence
            )
        return TaskResult(task.task_id, task.status, evidence, plan, task.error)

    async def resume_task(self, task_id: UUID) -> PlanningTask:
        return await self._engine.resume(task_id)

    async def cancel_task(self, task_id: UUID) -> PlanningTask:
        """Revoke pending authority before committing task cancellation."""

        try:
            await self._broker.cancel_task(task_id)
        except (Exception, asyncio.CancelledError):
            self._engine.cancel(task_id)
            raise
        return self._engine.cancel(task_id)

    async def pending_approvals(self, task_id: UUID | None = None) -> tuple[ApprovalRequest, ...]:
        return await self._broker.pending_approvals(task_id)

    async def submit_approval_decision(
        self,
        context: TrustedApprovalContext,
    ) -> ApprovalDecisionResult:
        return await self._broker.decide(context)
