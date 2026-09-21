"""Process-local bounded scheduling above the durable GoalSupervisor."""

from __future__ import annotations

import asyncio
from collections import deque
from dataclasses import dataclass, replace
from datetime import UTC, datetime
from enum import StrEnum
from uuid import UUID

from jarvis.goal_supervisor import GoalBudget, GoalIntent, GoalStatus, GoalSupervisor


class GoalScheduleStatus(StrEnum):
    QUEUED = "queued"
    RUNNING = "running"
    SUSPENDED = "suspended"
    TERMINAL = "terminal"


@dataclass(frozen=True, slots=True)
class GoalSchedulerPolicy:
    max_active_goals: int = 2
    max_queued_goals: int = 64

    def __post_init__(self) -> None:
        if self.max_active_goals <= 0 or self.max_queued_goals <= 0:
            raise ValueError("Goal scheduler limits must be positive")


@dataclass(frozen=True, slots=True)
class GoalScheduleView:
    goal_id: UUID
    status: GoalScheduleStatus
    sequence: int
    submitted_at: datetime
    started_at: datetime | None = None
    stopped_at: datetime | None = None
    cancellation_requested: bool = False
    goal_status: GoalStatus | None = None
    task_id: UUID | None = None
    error: str | None = None


class GoalScheduler:
    """Own process-local FIFO admission while GoalSupervisor owns goal truth."""

    def __init__(
        self,
        supervisor: GoalSupervisor,
        *,
        policy: GoalSchedulerPolicy | None = None,
    ) -> None:
        self._supervisor = supervisor
        self._policy = policy or GoalSchedulerPolicy()
        self._lock = asyncio.Lock()
        self._changed = asyncio.Condition(self._lock)
        self._queue: deque[UUID] = deque()
        self._views: dict[UUID, GoalScheduleView] = {}
        self._inputs: dict[UUID, tuple[GoalIntent, GoalBudget]] = {}
        self._workers: dict[UUID, asyncio.Task[None]] = {}
        self._resuming: set[UUID] = set()
        self._active = 0
        self._sequence = 0
        self._accepting = True
        self._persistent = all(
            callable(getattr(supervisor, name, None))
            for name in (
                "ensure_durable",
                "save_schedule_record",
                "list_schedule_records",
                "durable_inputs",
                "reconcile_after_restart",
            )
        )
        if self._persistent:
            self._restore_durable_records()

    @property
    def policy(self) -> GoalSchedulerPolicy:
        return self._policy

    async def submit(self, intent: GoalIntent, budget: GoalBudget) -> GoalScheduleView:
        async with self._changed:
            if not self._accepting:
                raise RuntimeError("Goal scheduler is shut down")
            if intent.goal_id in self._views:
                raise ValueError("Goal is already durable and cannot be resubmitted")
            if len(self._queue) >= self._policy.max_queued_goals:
                raise RuntimeError("Goal scheduler queue is full")
            submitted_at = datetime.now(UTC)
            if self._persistent:
                durable_sequence = self._supervisor.ensure_durable(intent, budget, submitted_at)
                self._sequence = max(self._sequence, durable_sequence)
            else:
                self._sequence += 1
                durable_sequence = self._sequence
            view = GoalScheduleView(
                intent.goal_id,
                GoalScheduleStatus.QUEUED,
                durable_sequence,
                submitted_at,
            )
            self._views[intent.goal_id] = view
            self._inputs[intent.goal_id] = (intent, budget)
            self._queue.append(intent.goal_id)
            self._workers[intent.goal_id] = asyncio.create_task(self._run_goal(intent.goal_id))
            self._persist(view)
            self._changed.notify_all()
            return view

    async def inspect(self, goal_id: UUID) -> GoalScheduleView | None:
        async with self._lock:
            return self._views.get(goal_id)

    async def list(self) -> tuple[GoalScheduleView, ...]:
        async with self._lock:
            return tuple(sorted(self._views.values(), key=lambda item: item.sequence))

    async def wait(self, goal_id: UUID) -> GoalScheduleView:
        async with self._changed:
            while True:
                view = self._views.get(goal_id)
                if view is None:
                    raise KeyError(f"Unknown scheduled goal: {goal_id}")
                if view.status in {GoalScheduleStatus.SUSPENDED, GoalScheduleStatus.TERMINAL}:
                    return view
                await self._changed.wait()

    async def cancel(self, goal_id: UUID) -> GoalScheduleView:
        async with self._changed:
            view = self._views.get(goal_id)
            if view is None:
                raise KeyError(f"Unknown scheduled goal: {goal_id}")
            if view.status is GoalScheduleStatus.TERMINAL:
                return view
            intent, budget = self._inputs[goal_id]
            queued = view.status is GoalScheduleStatus.QUEUED
            if queued:
                self._queue.remove(goal_id)
            updated = replace(view, cancellation_requested=True)
            self._views[goal_id] = updated
            self._persist(updated)
            self._changed.notify_all()
        if queued:
            state = await self._supervisor.cancel(goal_id, intent=intent, budget=budget)
            return await self._finish(goal_id, state.status, None)
        state = await self._supervisor.cancel(goal_id)
        if view.status is GoalScheduleStatus.SUSPENDED:
            return await self._finish(goal_id, state.status, state.task_id)
        current_view = await self.inspect(goal_id)
        if current_view is None:  # pragma: no cover - the goal was validated above
            raise RuntimeError("Scheduled goal disappeared during cancellation")
        return current_view

    async def resume(self, goal_id: UUID) -> GoalScheduleView:
        async with self._changed:
            view = self._views.get(goal_id)
            if view is None or view.status is not GoalScheduleStatus.SUSPENDED:
                raise ValueError("Goal is not suspended")
            self._views[goal_id] = replace(view, status=GoalScheduleStatus.QUEUED)
            self._queue.append(goal_id)
            self._resuming.add(goal_id)
            self._workers[goal_id] = asyncio.create_task(self._run_goal(goal_id))
            self._persist(self._views[goal_id])
            self._changed.notify_all()
            return self._views[goal_id]

    async def shutdown(self) -> None:
        async with self._changed:
            self._accepting = False
            queued = tuple(self._queue)
            active = tuple(
                goal_id
                for goal_id, view in self._views.items()
                if view.status is GoalScheduleStatus.RUNNING
            )
            for goal_id in active:
                self._views[goal_id] = replace(self._views[goal_id], cancellation_requested=True)
            self._changed.notify_all()
        for goal_id in queued:
            await self.cancel(goal_id)
        for goal_id in active:
            await self._supervisor.cancel(goal_id)

    async def _run_goal(self, goal_id: UUID) -> None:
        await self._admit(goal_id)
        async with self._lock:
            if self._views[goal_id].status is GoalScheduleStatus.TERMINAL:
                return
            if goal_id not in self._inputs:
                return
            intent, budget = self._inputs[goal_id]
            resuming = goal_id in self._resuming
            self._resuming.discard(goal_id)
        try:
            state = (
                await self._supervisor.resume(goal_id)
                if resuming
                else await self._supervisor.start(intent, budget)
            )
            await self._finish(goal_id, state.status, state.task_id)
        except Exception as error:
            await self._finish(goal_id, GoalStatus.FAILED, None, str(error))
        finally:
            async with self._changed:
                self._workers.pop(goal_id, None)
                self._changed.notify_all()

    async def _admit(self, goal_id: UUID) -> None:
        async with self._changed:
            while True:
                if self._views[goal_id].status is GoalScheduleStatus.TERMINAL:
                    return
                if (
                    self._queue
                    and self._queue[0] == goal_id
                    and self._active < self._policy.max_active_goals
                ):
                    self._queue.popleft()
                    self._active += 1
                    current = self._views[goal_id]
                    self._views[goal_id] = replace(
                        current,
                        status=GoalScheduleStatus.RUNNING,
                        started_at=current.started_at or datetime.now(UTC),
                    )
                    self._persist(self._views[goal_id])
                    self._changed.notify_all()
                    return
                await self._changed.wait()

    async def _finish(
        self,
        goal_id: UUID,
        goal_status: GoalStatus,
        task_id: UUID | None,
        error: str | None = None,
    ) -> GoalScheduleView:
        async with self._changed:
            current = self._views[goal_id]
            if current.cancellation_requested and goal_status is not GoalStatus.RECOVERING:
                goal_status = GoalStatus.CANCELLED
            suspended = goal_status in {
                GoalStatus.WAITING_FOR_PERMISSION,
                GoalStatus.WAITING_FOR_RESOURCE,
                GoalStatus.RECOVERING,
            }
            self._active = max(0, self._active - 1)
            updated = replace(
                current,
                status=GoalScheduleStatus.SUSPENDED if suspended else GoalScheduleStatus.TERMINAL,
                stopped_at=datetime.now(UTC),
                goal_status=goal_status,
                task_id=task_id or current.task_id,
                error=error,
            )
            self._views[goal_id] = updated
            self._persist(updated)
            self._changed.notify_all()
            return updated

    def reconcile_after_restart(self) -> tuple[GoalScheduleView, ...]:
        """Reconstruct queue metadata without recreating process-owned workers."""

        if not self._persistent:
            return tuple(sorted(self._views.values(), key=lambda item: item.sequence))
        self._supervisor.reconcile_after_restart()
        self._queue.clear()
        self._workers.clear()
        self._resuming.clear()
        self._active = 0
        for goal_id, view in tuple(self._views.items()):
            state = self._supervisor.get(goal_id)
            if state is None:
                continue
            if view.status is GoalScheduleStatus.RUNNING and not state.terminal:
                state = self._supervisor.mark_recovering(goal_id)
            if state.status in {
                GoalStatus.COMPLETED,
                GoalStatus.BLOCKED,
                GoalStatus.FAILED,
                GoalStatus.CANCELLED,
                GoalStatus.BUDGET_EXHAUSTED,
            }:
                restored = replace(
                    view,
                    status=GoalScheduleStatus.TERMINAL,
                    goal_status=state.status,
                    task_id=state.task_id,
                    stopped_at=view.stopped_at or datetime.now(UTC),
                )
            elif state.status in {
                GoalStatus.RECOVERING,
                GoalStatus.WAITING_FOR_PERMISSION,
                GoalStatus.WAITING_FOR_RESOURCE,
            }:
                restored = replace(
                    view,
                    status=GoalScheduleStatus.SUSPENDED,
                    goal_status=state.status,
                    task_id=state.task_id,
                    stopped_at=view.stopped_at or datetime.now(UTC),
                )
            else:
                restored = replace(view, status=GoalScheduleStatus.QUEUED)
                self._queue.append(goal_id)
            self._views[goal_id] = restored
            self._persist(restored)
        return tuple(sorted(self._views.values(), key=lambda item: item.sequence))

    def _restore_durable_records(self) -> None:
        records = self._supervisor.list_schedule_records()
        for record in records:
            goal_id = UUID(str(record["goal_id"]))
            inputs = self._supervisor.durable_inputs(goal_id)
            if inputs is None:
                continue
            self._sequence = max(self._sequence, int(str(record["sequence"])))
            self._inputs[goal_id] = inputs
            self._views[goal_id] = GoalScheduleView(
                goal_id,
                GoalScheduleStatus(str(record["status"])),
                int(str(record["sequence"])),
                datetime.fromisoformat(str(record["submitted_at"])),
                datetime.fromisoformat(str(record["started_at"])) if record["started_at"] else None,
                datetime.fromisoformat(str(record["stopped_at"])) if record["stopped_at"] else None,
                bool(record["cancellation_requested"]),
                GoalStatus(str(record["goal_status"])) if record["goal_status"] else None,
                UUID(str(record["task_id"])) if record["task_id"] else None,
                str(record["error"]) if record["error"] else None,
            )

    def _persist(self, view: GoalScheduleView) -> None:
        if not self._persistent:
            return
        self._supervisor.save_schedule_record(
            {
                "goal_id": str(view.goal_id),
                "sequence": view.sequence,
                "status": view.status.value,
                "submitted_at": view.submitted_at.isoformat(),
                "started_at": view.started_at.isoformat() if view.started_at else None,
                "stopped_at": view.stopped_at.isoformat() if view.stopped_at else None,
                "cancellation_requested": view.cancellation_requested,
                "goal_status": view.goal_status.value if view.goal_status else None,
                "task_id": str(view.task_id) if view.task_id else None,
                "error": view.error,
            }
        )


__all__ = ["GoalScheduleStatus", "GoalScheduleView", "GoalScheduler", "GoalSchedulerPolicy"]
