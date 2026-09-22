"""Direct R3E-E-R1 integration evidence for orchestration boundaries."""

from __future__ import annotations

import asyncio
from dataclasses import replace
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, cast
from uuid import UUID, uuid4

import pytest
from jarvis.ai.providers import ProviderLocality, ProviderMetadata
from jarvis.capabilities import CapabilityRegistry
from jarvis.conversation.service import ConversationService
from jarvis.goal_scheduler import GoalScheduler, GoalSchedulerPolicy, GoalScheduleStatus
from jarvis.goal_supervisor import (
    CapabilityAcquisitionReport,
    CapabilityAcquisitionRequest,
    GoalAnalysis,
    GoalBudget,
    GoalIntent,
    GoalResearch,
    GoalStatus,
    GoalSupervisor,
    GoalSupervisorState,
    GoalSupervisorStore,
    PlanningGoalTaskRunner,
)
from jarvis.permissions.approval import TrustedApprovalAuthenticator
from jarvis.permissions.broker import PermissionBroker
from jarvis.permissions.models import (
    ApprovalRequest,
    ApprovalSource,
    Decision,
    Permission,
    PolicyRule,
    ScopeConstraint,
)
from jarvis.permissions.policy import PolicyEngine
from jarvis.planning.engine import (
    BrokeredPlanningStepExecutor,
    CompletionCriteriaVerifier,
    EvidencePlanningStepVerifier,
    PlanningEngine,
    PlanningStepExecutor,
)
from jarvis.planning.models import PlanningTask
from jarvis.planning.store import SQLitePlanningStore
from jarvis.planning.validation import PlanValidator
from jarvis.resources import (
    ReservationReleaseReason,
    ResourceBudget,
    ResourceDecisionStatus,
    ResourceGovernor,
    ResourcePolicy,
    ResourcePriority,
    ResourceSnapshot,
)
from jarvis.task_controller import PlanningTaskController
from jarvis.tools.models import ToolEvidence, ToolResult

from tests.fakes import FakeAIProvider
from tests.test_planning_engine import (
    _Advisor,
    _Output,
    _PermissionTool,
    _plan,
    _ResultTool,
    _step,
    _Tool,
)


class _NoGapAnalyzer:
    async def analyze(self, intent: GoalIntent, registry: object) -> GoalAnalysis:
        del intent, registry
        return GoalAnalysis()


class _NoResearcher:
    async def research(
        self, intent: GoalIntent, analysis: GoalAnalysis, alternative: object | None = None
    ) -> GoalResearch:
        del intent, analysis, alternative
        return GoalResearch()


class _UnusedAcquirer:
    async def acquire(self, request: CapabilityAcquisitionRequest) -> CapabilityAcquisitionReport:
        raise AssertionError(f"unexpected capability acquisition: {request!r}")


class _RecordingBroker(PermissionBroker):
    def __init__(self) -> None:
        super().__init__(PolicyEngine())
        self.cancelled: list[UUID] = []

    async def cancel_task(self, task_id: UUID) -> tuple[ApprovalRequest, ...]:
        self.cancelled.append(task_id)
        return await super().cancel_task(task_id)


class _RecordingEngine(PlanningEngine):
    def __init__(self, **kwargs: Any) -> None:
        super().__init__(**kwargs)
        self.cancelled: list[UUID] = []

    def cancel(self, task_id: UUID) -> PlanningTask:
        self.cancelled.append(task_id)
        return super().cancel(task_id)


def _supervisor(
    tmp_path: Path,
    controller: PlanningTaskController,
    *,
    runner: PlanningGoalTaskRunner | None = None,
) -> GoalSupervisor:
    return GoalSupervisor(
        registry=CapabilityRegistry(),
        store=GoalSupervisorStore(tmp_path / "goals.sqlite3"),
        analyzer=_NoGapAnalyzer(),
        researcher=_NoResearcher(),
        acquirer=_UnusedAcquirer(),
        runner=runner or PlanningGoalTaskRunner(controller),
    )


def _planning_engine(
    tmp_path: Path,
    advisor: _Advisor,
    broker: PermissionBroker,
    tools: tuple[_Tool, ...],
    executor: PlanningStepExecutor,
    *,
    recording: bool = False,
) -> PlanningEngine:
    from jarvis.tools.registry import ToolRegistry

    registry = ToolRegistry(tools, permission_broker=broker)
    engine_type = _RecordingEngine if recording else PlanningEngine
    return engine_type(
        store=SQLitePlanningStore(tmp_path / "planning.sqlite3"),
        advisor=advisor,
        validator=PlanValidator(registry, max_steps=4),
        executor=executor,
        step_verifier=EvidencePlanningStepVerifier(),
        goal_verifier=CompletionCriteriaVerifier(),
    )


@pytest.mark.asyncio
async def test_direct_cancellation_chain_binds_one_task_and_finishes_cancelled(
    tmp_path: Path,
) -> None:
    from tests.test_planning_engine import _BlockingExecutor

    broker = _RecordingBroker()
    executor = _BlockingExecutor()
    recording_engine = cast(
        _RecordingEngine,
        _planning_engine(
            tmp_path,
            _Advisor((_plan(_step("prepare"), goal="cancel the long planning task"),)),
            broker,
            (_Tool("prepare"),),
            executor,
            recording=True,
        ),
    )
    controller = PlanningTaskController(recording_engine, broker)
    supervisor = _supervisor(tmp_path, controller)
    scheduler = GoalScheduler(supervisor)
    intent = GoalIntent("cancel the long planning task")

    await scheduler.submit(intent, GoalBudget())
    await asyncio.wait_for(executor.started.wait(), timeout=5)
    bound = supervisor.get(intent.goal_id)
    assert bound is not None and bound.task_id is not None
    task_id = bound.task_id

    requested = await scheduler.cancel(intent.goal_id)
    terminal = await scheduler.wait(intent.goal_id)

    assert requested.cancellation_requested
    assert terminal.status is GoalScheduleStatus.TERMINAL
    assert terminal.goal_status is GoalStatus.CANCELLED
    assert broker.cancelled == [task_id]
    assert recording_engine.cancelled == [task_id]
    assert len(recording_engine.list_tasks()) == 1
    assert recording_engine.get_task(task_id) is not None
    await scheduler.shutdown()


@pytest.mark.asyncio
async def test_direct_permission_wait_cancels_only_goal_a_and_preserves_goal_b(
    tmp_path: Path,
) -> None:
    root = tmp_path.resolve()
    tool_a = _PermissionTool(root)
    tool_b = _ResultTool(
        replace(
            ToolResult.success(_Output(value="result-tool prepared")),
            evidence=(ToolEvidence("r1", "result-tool-ready"),),
        )
    )
    policy = PolicyEngine(
        (
            PolicyRule(
                policy_id="r1-approval",
                permission=Permission.FILESYSTEM_READ,
                decision=Decision.REQUIRE_APPROVAL,
                scope=ScopeConstraint(paths=(str(root),), tools=frozenset({"protected"})),
                actions=frozenset({"invoke:protected"}),
            ),
        )
    )
    authenticator = TrustedApprovalAuthenticator(ApprovalSource.TRUSTED_UI)
    broker = PermissionBroker(policy, approval_context_verifier=authenticator.verifier())
    from jarvis.tools.registry import ToolRegistry

    registry = ToolRegistry((tool_a, tool_b), permission_broker=broker)
    engine = PlanningEngine(
        store=SQLitePlanningStore(tmp_path / "planning.sqlite3"),
        advisor=_Advisor(
            (
                _plan(
                    _step("protected", permissions=[Permission.FILESYSTEM_READ.value]),
                    goal="protected goal",
                ),
                _plan(_step("result-tool"), goal="ordinary goal"),
            )
        ),
        validator=PlanValidator(registry, max_steps=4),
        executor=BrokeredPlanningStepExecutor(registry),
        step_verifier=EvidencePlanningStepVerifier(),
        goal_verifier=CompletionCriteriaVerifier(),
    )
    controller = PlanningTaskController(engine, broker)
    supervisor = _supervisor(tmp_path, controller)
    scheduler = GoalScheduler(supervisor)
    goal_a = GoalIntent("protected goal")

    await scheduler.submit(goal_a, GoalBudget())
    suspended_a = await scheduler.wait(goal_a.goal_id)
    assert suspended_a.status is GoalScheduleStatus.SUSPENDED
    assert suspended_a.goal_status is GoalStatus.WAITING_FOR_PERMISSION
    assert suspended_a.task_id is not None
    requests = await broker.pending_approvals(suspended_a.task_id)
    assert len(requests) == 1, engine.get_task(suspended_a.task_id)
    assert requests[0].task_id == suspended_a.task_id

    goal_b = GoalIntent("ordinary goal")
    await scheduler.submit(goal_b, GoalBudget())
    terminal_b = await scheduler.wait(goal_b.goal_id)
    assert terminal_b.goal_status is GoalStatus.COMPLETED

    terminal_a = await scheduler.cancel(goal_a.goal_id)
    assert terminal_a.status is GoalScheduleStatus.TERMINAL
    assert terminal_a.goal_status is GoalStatus.CANCELLED
    assert await broker.pending_approvals(suspended_a.task_id) == ()
    assert not tool_a.executed
    assert tool_b is not None
    await scheduler.shutdown()


class _Telemetry:
    def __init__(self) -> None:
        self.current = ResourceSnapshot(
            datetime(2026, 9, 20, tzinfo=UTC),
            cpu_utilization=0.1,
            cpu_cores=4,
            ram_total_bytes=1_000,
            ram_available_bytes=1_000,
            gpu_vram_total_bytes=1_000,
            gpu_vram_available_bytes=1_000,
            disk_free_bytes=10_000,
            user_active=True,
        )

    def snapshot(self) -> ResourceSnapshot:
        return self.current


class _ResourceSupervisor:
    def __init__(self, governor: ResourceGovernor) -> None:
        self.governor = governor
        self.started: dict[UUID, asyncio.Event] = {}
        self.release: dict[UUID, asyncio.Event] = {}
        self.reservations: dict[UUID, UUID] = {}
        self.two_started = asyncio.Event()

    async def start(self, intent: GoalIntent, budget: GoalBudget) -> GoalSupervisorState:
        started = self.started.setdefault(intent.goal_id, asyncio.Event())
        release = self.release.setdefault(intent.goal_id, asyncio.Event())
        started.set()
        if len(self.reservations) == 2:
            self.two_started.set()
        await release.wait()
        now = datetime.now(UTC)
        return GoalSupervisorState(intent, budget, GoalStatus.COMPLETED, now, now)

    async def resume(self, goal_id: UUID) -> GoalSupervisorState:
        raise AssertionError(f"unexpected resume: {goal_id}")

    async def cancel(
        self,
        goal_id: UUID,
        *,
        intent: GoalIntent | None = None,
        budget: GoalBudget | None = None,
    ) -> GoalSupervisorState:
        del budget
        value = intent or GoalIntent("cancelled", goal_id=goal_id)
        now = datetime.now(UTC)
        return GoalSupervisorState(value, GoalBudget(), GoalStatus.CANCELLED, now, now)


@pytest.mark.asyncio
async def test_scheduler_multi_goal_context_uses_real_resource_reservations() -> None:
    governor = ResourceGovernor(
        _Telemetry(),
        policy=ResourcePolicy(
            low_disk_bytes=0,
            interactive_ram_reserve_bytes=0,
            interactive_vram_reserve_bytes=0,
            interactive_cpu_reserve_cores=0,
            interactive_concurrency_reserve=1,
            concurrency_capacity=2,
        ),
    )
    supervisor = _ResourceSupervisor(governor)
    scheduler = GoalScheduler(
        cast(GoalSupervisor, supervisor), policy=GoalSchedulerPolicy(max_active_goals=2)
    )
    goals = [GoalIntent(label) for label in ("resource-a", "resource-b", "resource-c")]
    for goal in goals:
        supervisor.started[goal.goal_id] = asyncio.Event()
        supervisor.release[goal.goal_id] = asyncio.Event()
    for goal in goals[:2]:
        decision = governor.reserve(
            str(goal.goal_id),
            ResourcePriority.USER_REQUESTED,
            ResourceBudget(ram_bytes=100, concurrency=1),
        )
        assert decision.allowed and decision.reservation_id is not None
        supervisor.reservations[goal.goal_id] = decision.reservation_id

    for goal in goals:
        await scheduler.submit(goal, GoalBudget())
    await asyncio.wait_for(supervisor.two_started.wait(), timeout=5)
    third = await scheduler.inspect(goals[2].goal_id)
    assert third is not None and third.status is GoalScheduleStatus.QUEUED
    denied = governor.decide(
        "resource-c",
        ResourcePriority.USER_REQUESTED,
        ResourceBudget(ram_bytes=100, concurrency=1),
    )
    assert denied.status is ResourceDecisionStatus.DENY
    assert len(governor.reservations(active_only=True)) == 2

    supervisor.release[goals[0].goal_id].set()
    supervisor.release[goals[1].goal_id].set()
    for goal in goals[:2]:
        governor.release(supervisor.reservations[goal.goal_id], ReservationReleaseReason.COMPLETE)
    assert (await scheduler.wait(goals[0].goal_id)).goal_status is GoalStatus.COMPLETED
    assert (await scheduler.wait(goals[1].goal_id)).goal_status is GoalStatus.COMPLETED
    admitted = governor.reserve(
        str(goals[2].goal_id),
        ResourcePriority.USER_REQUESTED,
        ResourceBudget(ram_bytes=100, concurrency=1),
    )
    assert admitted.allowed and admitted.reservation_id is not None
    supervisor.release[goals[2].goal_id].set()
    terminal_c = await scheduler.wait(goals[2].goal_id)
    assert terminal_c.goal_status is GoalStatus.COMPLETED
    governor.release(admitted.reservation_id, ReservationReleaseReason.COMPLETE)
    assert len(governor.reservations(active_only=True)) == 0
    await scheduler.shutdown()


class _ConversationSupervisor:
    def __init__(self) -> None:
        self.release: dict[UUID, asyncio.Event] = {}
        self.started: dict[UUID, asyncio.Event] = {}

    async def start(self, intent: GoalIntent, budget: GoalBudget) -> GoalSupervisorState:
        now = datetime.now(UTC)
        if intent.metadata and intent.metadata.get("wait") is True:
            return GoalSupervisorState(
                intent, budget, GoalStatus.WAITING_FOR_PERMISSION, now, now, task_id=uuid4()
            )
        self.started.setdefault(intent.goal_id, asyncio.Event()).set()
        await self.release.setdefault(intent.goal_id, asyncio.Event()).wait()
        return GoalSupervisorState(intent, budget, GoalStatus.COMPLETED, now, datetime.now(UTC))

    async def resume(self, goal_id: UUID) -> GoalSupervisorState:
        raise AssertionError(f"unexpected resume: {goal_id}")

    async def cancel(
        self,
        goal_id: UUID,
        *,
        intent: GoalIntent | None = None,
        budget: GoalBudget | None = None,
    ) -> GoalSupervisorState:
        value = intent or GoalIntent("cancelled", goal_id=goal_id)
        return GoalSupervisorState(
            value,
            budget or GoalBudget(),
            GoalStatus.CANCELLED,
            datetime.now(UTC),
            datetime.now(UTC),
        )


@pytest.mark.asyncio
async def test_actual_conversation_remains_independent_during_active_and_waiting_goals() -> None:
    supervisor = _ConversationSupervisor()
    scheduler = GoalScheduler(cast(GoalSupervisor, supervisor))
    active = [GoalIntent("active-a"), GoalIntent("active-b")]
    await asyncio.gather(*(scheduler.submit(item, GoalBudget()) for item in active))
    await asyncio.wait_for(
        asyncio.gather(*(supervisor.started[item.goal_id].wait() for item in active)), timeout=5
    )
    service = ConversationService(
        FakeAIProvider(("ordinary reply",)),
        model="local-model",
        context_limit=1024,
        provider_metadata=ProviderMetadata(
            "local-test",
            "Local test",
            "r1",
            locality=ProviderLocality.LOCAL,
        ),
    )
    conversation_id = service.create_conversation()
    updates = [
        item async for item in service.stream_reply(conversation_id, "ordinary conversation")
    ]
    assert "".join(item.content for item in updates) == "ordinary reply"
    assert len(await scheduler.list()) == 2

    for item in active:
        supervisor.release[item.goal_id].set()
    for item in active:
        assert (await scheduler.wait(item.goal_id)).goal_status is GoalStatus.COMPLETED

    waiting = GoalIntent("permission-wait", metadata={"wait": True})
    await scheduler.submit(waiting, GoalBudget())
    suspended = await scheduler.wait(waiting.goal_id)
    assert suspended.status is GoalScheduleStatus.SUSPENDED
    second = service.create_conversation()
    updates = [item async for item in service.stream_reply(second, "still ordinary")]
    assert "".join(item.content for item in updates) == "ordinary reply"
    listed = await scheduler.list()
    assert {item.goal_id for item in listed} == {
        active[0].goal_id,
        active[1].goal_id,
        waiting.goal_id,
    }
    await scheduler.shutdown()
