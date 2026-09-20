"""Focused R3E-E multi-goal scheduling and cancellation regressions."""

from __future__ import annotations

import asyncio
from collections import defaultdict
from dataclasses import replace
from datetime import UTC, datetime
from typing import cast
from uuid import UUID

import pytest
from jarvis.goal_scheduler import (
    GoalScheduler,
    GoalSchedulerPolicy,
    GoalScheduleStatus,
)
from jarvis.goal_supervisor import (
    GoalBudget,
    GoalExecutionStatus,
    GoalIntent,
    GoalStatus,
    GoalSupervisor,
    GoalSupervisorState,
    PlanningGoalTaskRunner,
)
from jarvis.planning.models import PlanningTask, PlanningTaskStatus
from jarvis.task_controller import TaskController


def _intent(label: str) -> GoalIntent:
    return GoalIntent(label, constraints=("preserve outcome",))


class _FakeSupervisor:
    def __init__(self) -> None:
        self.started: list[UUID] = []
        self.cancelled: list[UUID] = []
        self.release: dict[UUID, asyncio.Event] = defaultdict(asyncio.Event)
        self.started_events: dict[UUID, asyncio.Event] = defaultdict(asyncio.Event)
        self.statuses: dict[UUID, GoalStatus] = {}

    async def start(self, intent: GoalIntent, budget: GoalBudget) -> GoalSupervisorState:
        del budget
        self.started.append(intent.goal_id)
        self.started_events[intent.goal_id].set()
        await self.release[intent.goal_id].wait()
        status = self.statuses.get(intent.goal_id, GoalStatus.COMPLETED)
        return GoalSupervisorState(
            intent,
            GoalBudget(),
            status,
            datetime.now(UTC),
            datetime.now(UTC),
        )

    async def resume(self, goal_id: UUID) -> GoalSupervisorState:
        intent = _intent("resumed")
        intent = GoalIntent(intent.original_outcome, goal_id=goal_id)
        return GoalSupervisorState(
            intent,
            GoalBudget(),
            GoalStatus.COMPLETED,
            datetime.now(UTC),
            datetime.now(UTC),
        )

    async def cancel(
        self,
        goal_id: UUID,
        *,
        intent: GoalIntent | None = None,
        budget: GoalBudget | None = None,
    ) -> GoalSupervisorState:
        del intent, budget
        self.cancelled.append(goal_id)
        return GoalSupervisorState(
            _intent("cancelled"),
            GoalBudget(),
            GoalStatus.CANCELLED,
            datetime.now(UTC),
            datetime.now(UTC),
        )


def _scheduler(fake: _FakeSupervisor, *, active: int = 2, queued: int = 64) -> GoalScheduler:
    return GoalScheduler(
        cast(GoalSupervisor, fake),
        policy=GoalSchedulerPolicy(max_active_goals=active, max_queued_goals=queued),
    )


@pytest.mark.asyncio
async def test_submit_returns_promptly_and_two_distinct_goals_overlap() -> None:
    fake = _FakeSupervisor()
    scheduler = _scheduler(fake, active=2)
    first, second = _intent("A"), _intent("B")

    first_view = await scheduler.submit(first, GoalBudget())
    second_view = await scheduler.submit(second, GoalBudget())
    assert first_view.status is GoalScheduleStatus.QUEUED
    assert second_view.status is GoalScheduleStatus.QUEUED

    await asyncio.wait_for(fake.started_events[first.goal_id].wait(), timeout=1)
    await asyncio.wait_for(fake.started_events[second.goal_id].wait(), timeout=1)
    assert set(fake.started) == {first.goal_id, second.goal_id}
    fake.release[first.goal_id].set()
    fake.release[second.goal_id].set()
    assert (await scheduler.wait(first.goal_id)).status is GoalScheduleStatus.TERMINAL
    assert (await scheduler.wait(second.goal_id)).status is GoalScheduleStatus.TERMINAL


@pytest.mark.asyncio
async def test_fifo_admission_and_bounded_active_slots() -> None:
    fake = _FakeSupervisor()
    scheduler = _scheduler(fake, active=1)
    goals = [_intent(label) for label in ("A", "B", "C")]
    for goal in goals:
        await scheduler.submit(goal, GoalBudget())
    await asyncio.wait_for(fake.started_events[goals[0].goal_id].wait(), timeout=1)
    assert fake.started == [goals[0].goal_id]
    fake.release[goals[0].goal_id].set()
    await asyncio.wait_for(fake.started_events[goals[1].goal_id].wait(), timeout=1)
    fake.release[goals[1].goal_id].set()
    await asyncio.wait_for(fake.started_events[goals[2].goal_id].wait(), timeout=1)
    fake.release[goals[2].goal_id].set()
    await scheduler.wait(goals[2].goal_id)
    assert fake.started == [goal.goal_id for goal in goals]


@pytest.mark.asyncio
async def test_queue_bound_duplicate_rejection_and_queued_cancellation() -> None:
    fake = _FakeSupervisor()
    scheduler = _scheduler(fake, active=1, queued=1)
    first, second, third = (_intent(label) for label in ("A", "B", "C"))
    await scheduler.submit(first, GoalBudget())
    await asyncio.wait_for(fake.started_events[first.goal_id].wait(), timeout=1)
    await scheduler.submit(second, GoalBudget())
    with pytest.raises(RuntimeError, match="queue is full"):
        await scheduler.submit(third, GoalBudget())
    with pytest.raises(ValueError, match="already"):
        await scheduler.submit(second, GoalBudget())
    cancelled = await scheduler.cancel(second.goal_id)
    assert cancelled.status is GoalScheduleStatus.TERMINAL
    assert second.goal_id not in fake.started
    fake.release[first.goal_id].set()
    await scheduler.wait(first.goal_id)


@pytest.mark.asyncio
async def test_early_task_binding_occurs_before_long_execution() -> None:
    from tests.test_goal_supervisor import _task

    bound = asyncio.Event()
    release = asyncio.Event()
    running = asyncio.Event()

    class Controller:
        async def create_task(self, *args: object, **kwargs: object) -> PlanningTask:
            del args, kwargs
            return _task(PlanningTaskStatus.READY)

        async def run_task(self, task_id: UUID) -> PlanningTask:
            assert task_id is not None
            running.set()
            await release.wait()
            return replace(_task(PlanningTaskStatus.COMPLETED), task_id=task_id)

    runner = PlanningGoalTaskRunner(cast(TaskController, Controller()))
    result = asyncio.create_task(
        runner.run_bound(_intent("bind"), GoalBudget(), on_task_bound=lambda _: bound.set())
    )
    await asyncio.wait_for(bound.wait(), timeout=1)
    await asyncio.wait_for(running.wait(), timeout=1)
    assert not result.done()
    release.set()
    report = await result
    assert report.status is GoalExecutionStatus.COMPLETED


@pytest.mark.asyncio
async def test_suspended_goal_releases_slot_and_resume_requeues_fairly() -> None:
    fake = _FakeSupervisor()
    first, second = _intent("A"), _intent("B")
    fake.statuses[first.goal_id] = GoalStatus.WAITING_FOR_PERMISSION
    scheduler = _scheduler(fake, active=1)
    await scheduler.submit(first, GoalBudget())
    await scheduler.submit(second, GoalBudget())
    await asyncio.wait_for(fake.started_events[first.goal_id].wait(), timeout=1)
    fake.release[first.goal_id].set()
    assert (await scheduler.wait(first.goal_id)).status is GoalScheduleStatus.SUSPENDED
    await asyncio.wait_for(fake.started_events[second.goal_id].wait(), timeout=1)
    fake.release[second.goal_id].set()
    await scheduler.wait(second.goal_id)
    resumed = await scheduler.resume(first.goal_id)
    assert resumed.status is GoalScheduleStatus.QUEUED
    await asyncio.wait_for(fake.started_events[first.goal_id].wait(), timeout=1)
    fake.release[first.goal_id].set()
    assert (await scheduler.wait(first.goal_id)).status is GoalScheduleStatus.TERMINAL


@pytest.mark.asyncio
async def test_recovering_goal_releases_slot_without_automatic_retry() -> None:
    fake = _FakeSupervisor()
    recovering, independent = _intent("recovering"), _intent("independent")
    fake.statuses[recovering.goal_id] = GoalStatus.RECOVERING
    scheduler = _scheduler(fake, active=1)
    await scheduler.submit(recovering, GoalBudget())
    await scheduler.submit(independent, GoalBudget())
    await asyncio.wait_for(fake.started_events[recovering.goal_id].wait(), timeout=1)
    fake.release[recovering.goal_id].set()
    assert (await scheduler.wait(recovering.goal_id)).status is GoalScheduleStatus.SUSPENDED
    await asyncio.wait_for(fake.started_events[independent.goal_id].wait(), timeout=1)
    fake.release[independent.goal_id].set()
    await scheduler.wait(independent.goal_id)
    assert fake.started.count(recovering.goal_id) == 1


@pytest.mark.asyncio
async def test_cancellation_isolated_to_one_active_goal() -> None:
    fake = _FakeSupervisor()
    first, second = _intent("A"), _intent("B")
    scheduler = _scheduler(fake, active=2)
    await scheduler.submit(first, GoalBudget())
    await scheduler.submit(second, GoalBudget())
    await asyncio.wait_for(fake.started_events[first.goal_id].wait(), timeout=1)
    await asyncio.wait_for(fake.started_events[second.goal_id].wait(), timeout=1)
    await scheduler.cancel(first.goal_id)
    assert fake.cancelled == [first.goal_id]
    second_view = await scheduler.inspect(second.goal_id)
    assert second_view is not None
    assert second_view.status is GoalScheduleStatus.RUNNING
    fake.release[first.goal_id].set()
    fake.release[second.goal_id].set()
    assert (await scheduler.wait(first.goal_id)).goal_status is GoalStatus.CANCELLED
    assert (await scheduler.wait(second.goal_id)).goal_status is GoalStatus.COMPLETED
