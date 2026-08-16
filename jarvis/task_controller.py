"""Stable application-facing task API backed only by the canonical PlanningEngine."""

from __future__ import annotations

import asyncio
from typing import Protocol
from uuid import UUID

from jarvis.permissions.approval import TrustedApprovalContext
from jarvis.permissions.broker import PermissionBroker
from jarvis.permissions.models import (
    ApprovalDecisionResult,
    ApprovalRequest,
)
from jarvis.planning.engine import PlanningEngine
from jarvis.planning.models import ExecutionBudgets, OwnedPlan, PlanningTask


class TaskController(Protocol):
    async def create_task(
        self, goal: str, *, budgets: ExecutionBudgets | None = None
    ) -> PlanningTask: ...
    async def submit_task(
        self, goal: str, *, budgets: ExecutionBudgets | None = None
    ) -> PlanningTask: ...
    async def run_task(self, task_id: UUID) -> PlanningTask: ...
    def get_task(self, task_id: UUID) -> PlanningTask | None: ...
    def list_tasks(self) -> tuple[PlanningTask, ...]: ...
    def inspect_plan(self, task_id: UUID) -> OwnedPlan | None: ...
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
        self, goal: str, *, budgets: ExecutionBudgets | None = None
    ) -> PlanningTask:
        return await self._engine.create_task(goal, budgets=budgets)

    async def submit_task(
        self, goal: str, *, budgets: ExecutionBudgets | None = None
    ) -> PlanningTask:
        return await self._engine.submit(goal, budgets=budgets)

    async def run_task(self, task_id: UUID) -> PlanningTask:
        return await self._engine.run(task_id)

    def get_task(self, task_id: UUID) -> PlanningTask | None:
        return self._engine.get_task(task_id)

    def list_tasks(self) -> tuple[PlanningTask, ...]:
        return self._engine.list_tasks()

    def inspect_plan(self, task_id: UUID) -> OwnedPlan | None:
        return self._engine.inspect_plan(task_id)

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
