"""Permission waits remain non-terminal routing lifecycle state."""

from __future__ import annotations

from dataclasses import dataclass, replace
from pathlib import Path
from uuid import UUID

import pytest
from jarvis.ai.fitness import (
    CircuitState,
    RoutingFitnessProjection,
    RoutingFitnessStoreError,
    RoutingResilienceService,
    SQLiteRoutingFitnessStore,
)
from jarvis.autonomy.routing import ExecutionRouteSelector
from jarvis.permissions.approval import TrustedApprovalAuthenticator
from jarvis.permissions.broker import PermissionBroker
from jarvis.permissions.models import (
    ApprovalActorKind,
    ApprovalChoice,
    ApprovalIdentity,
    ApprovalSource,
    Decision,
    Permission,
    PolicyRule,
    ScopeConstraint,
)
from jarvis.permissions.policy import PolicyEngine
from jarvis.planning import (
    BrokeredPlanningStepExecutor,
    CompletionCriteriaVerifier,
    EvidencePlanningStepVerifier,
    PlanningEngine,
    PlanningTaskStatus,
    PlanValidator,
    SQLitePlanningStore,
)
from jarvis.tools.registry import ToolRegistry

from tests.test_planning_engine import _Advisor, _PermissionTool, _plan, _step


@dataclass(frozen=True)
class _Context:
    broker: PermissionBroker
    authenticator: TrustedApprovalAuthenticator
    tool: _PermissionTool
    planning_store: SQLitePlanningStore
    routing_store: SQLiteRoutingFitnessStore
    fitness: RoutingFitnessProjection
    resilience: RoutingResilienceService
    engine: PlanningEngine


def _context(
    root: Path,
    *,
    broker: PermissionBroker | None = None,
    authenticator: TrustedApprovalAuthenticator | None = None,
    tool: _PermissionTool | None = None,
    proposals: tuple[object, ...] = (),
) -> _Context:
    active_authenticator = authenticator or TrustedApprovalAuthenticator(ApprovalSource.TRUSTED_UI)
    active_broker = broker or PermissionBroker(
        PolicyEngine(
            (
                PolicyRule(
                    policy_id="r3d-r4-approval",
                    permission=Permission.FILESYSTEM_READ,
                    decision=Decision.REQUIRE_APPROVAL,
                    scope=ScopeConstraint(
                        paths=(str(root.resolve()),),
                        tools=frozenset({"protected"}),
                    ),
                    actions=frozenset({"invoke:protected"}),
                ),
            )
        ),
        approval_context_verifier=active_authenticator.verifier(),
    )
    active_tool = tool or _PermissionTool(root.resolve())
    registry = ToolRegistry((active_tool,), permission_broker=active_broker)
    planning_store = SQLitePlanningStore(root / "planning.sqlite3")
    routing_store = SQLiteRoutingFitnessStore(root / "routing-fitness.sqlite3")
    fitness = RoutingFitnessProjection(store=routing_store)
    resilience = RoutingResilienceService(fitness, store=routing_store)
    selector = ExecutionRouteSelector(
        model_router=None,
        tool_registry=registry,
        fitness=fitness,
        resilience=resilience,
        routing_store=routing_store,
    )
    engine = PlanningEngine(
        store=planning_store,
        advisor=_Advisor(proposals),
        validator=PlanValidator(registry, max_steps=1),
        executor=BrokeredPlanningStepExecutor(registry, route_selector=selector),
        step_verifier=EvidencePlanningStepVerifier(),
        goal_verifier=CompletionCriteriaVerifier(),
        routing_fitness=fitness,
        routing_resilience=resilience,
        routing_store=routing_store,
    )
    return _Context(
        active_broker,
        active_authenticator,
        active_tool,
        planning_store,
        routing_store,
        fitness,
        resilience,
        engine,
    )


def _proposal() -> object:
    return _plan(
        _step("protected", permissions=[Permission.FILESYSTEM_READ.value]),
        goal="Read the protected planning fixture",
    )


async def _decide(context: _Context, task_id: UUID, choice: ApprovalChoice) -> None:
    requests = await context.broker.pending_approvals(task_id)
    assert len(requests) == 1
    result = await context.broker.decide(
        context.authenticator.issue_context(
            request_id=requests[0].request_id,
            choice=choice,
            identity=ApprovalIdentity("local-user", ApprovalActorKind.TRUSTED_USER),
        )
    )
    assert result.accepted


def _close(context: _Context) -> None:
    context.planning_store.close()
    context.routing_store.close()


def _restart(context: _Context, root: Path) -> _Context:
    _close(context)
    return _context(
        root,
        broker=context.broker,
        authenticator=context.authenticator,
        tool=context.tool,
    )


@pytest.mark.asyncio
async def test_permission_wait_defers_terminal_outcome_until_approved_execution(
    tmp_path: Path,
) -> None:
    context = _context(tmp_path, proposals=(_proposal(),))
    paused = await context.engine.submit("Read the protected planning fixture")
    plan = context.engine.inspect_plan(paused.task_id)
    decisions_before = context.routing_store.decisions()
    key = context.resilience.key("protected", "tool", "protected", "orchestration")

    assert paused.status is PlanningTaskStatus.WAITING_FOR_PERMISSION
    assert plan is not None and plan.steps[0].attempts == 0
    assert len(decisions_before) == 1
    assert context.routing_store.decision_outcomes(decisions_before[0].decision_id) == ()
    assert context.routing_store.observations() == ()
    assert context.resilience.snapshot(key).state is CircuitState.CLOSED

    await _decide(context, paused.task_id, ApprovalChoice.APPROVE_ONCE)
    completed = await context.engine.resume(paused.task_id)
    decisions_after = context.routing_store.decisions()
    outcomes = tuple(
        outcome
        for decision in decisions_after
        for outcome in context.routing_store.decision_outcomes(decision.decision_id)
    )
    observations = context.routing_store.observations()

    assert completed.status is PlanningTaskStatus.COMPLETED
    assert context.tool.executed
    assert context.routing_store.decision(decisions_before[0].decision_id) == decisions_before[0]
    assert len(decisions_after) == 2
    assert len(outcomes) == 1
    assert outcomes[0].executed_identity == "protected"
    assert outcomes[0].operational_outcome == "succeeded"
    assert outcomes[0].semantic_outcome.value == "verified_success"
    assert len(observations) == 1
    assert observations[0].operational_outcome == "succeeded"
    assert observations[0].semantic_outcome.value == "verified_success"
    assert context.resilience.snapshot(key).state is CircuitState.CLOSED
    _close(context)


@pytest.mark.asyncio
async def test_permission_denial_has_no_effect_or_attributable_route_outcome(
    tmp_path: Path,
) -> None:
    context = _context(tmp_path, proposals=(_proposal(),))
    paused = await context.engine.submit("Read the protected planning fixture")
    await _decide(context, paused.task_id, ApprovalChoice.DENY_ONCE)
    denied = await context.engine.resume(paused.task_id)
    key = context.resilience.key("protected", "tool", "protected", "orchestration")

    assert denied.status is PlanningTaskStatus.WAITING_FOR_PERMISSION
    assert not context.tool.executed
    assert context.routing_store.observations() == ()
    assert all(
        context.routing_store.decision_outcomes(decision.decision_id) == ()
        for decision in context.routing_store.decisions()
    )
    snapshot = context.resilience.snapshot(key)
    assert snapshot.state is CircuitState.CLOSED
    assert snapshot.qualifying_failures == 0
    _close(context)


@pytest.mark.asyncio
@pytest.mark.parametrize("choice", (ApprovalChoice.APPROVE_ONCE, ApprovalChoice.DENY_ONCE))
async def test_permission_wait_restart_resolves_without_false_or_conflicting_outcome(
    tmp_path: Path, choice: ApprovalChoice
) -> None:
    first = _context(tmp_path, proposals=(_proposal(),))
    paused = await first.engine.submit("Read the protected planning fixture")
    assert first.routing_store.observations() == ()

    restarted = _restart(first, tmp_path)
    restored = restarted.engine.get_task(paused.task_id)
    assert restored is not None and restored.status is PlanningTaskStatus.WAITING_FOR_PERMISSION
    assert restarted.routing_store.observations() == ()

    await _decide(restarted, paused.task_id, choice)
    resolved = await restarted.engine.resume(paused.task_id)
    outcomes = tuple(
        outcome
        for decision in restarted.routing_store.decisions()
        for outcome in restarted.routing_store.decision_outcomes(decision.decision_id)
    )
    if choice is ApprovalChoice.APPROVE_ONCE:
        assert resolved.status is PlanningTaskStatus.COMPLETED
        assert restarted.tool.executed
        assert len(outcomes) == 1 and outcomes[0].operational_outcome == "succeeded"
        assert len(restarted.routing_store.observations()) == 1
    else:
        assert resolved.status is PlanningTaskStatus.WAITING_FOR_PERMISSION
        assert not restarted.tool.executed
        assert outcomes == ()
        assert restarted.routing_store.observations() == ()
    _close(restarted)


@pytest.mark.asyncio
async def test_terminal_outcome_duplicate_is_idempotent_and_conflict_fails_closed(
    tmp_path: Path,
) -> None:
    context = _context(tmp_path, proposals=(_proposal(),))
    paused = await context.engine.submit("Read the protected planning fixture")
    await _decide(context, paused.task_id, ApprovalChoice.APPROVE_ONCE)
    completed = await context.engine.resume(paused.task_id)
    outcomes = tuple(
        outcome
        for decision in context.routing_store.decisions()
        for outcome in context.routing_store.decision_outcomes(decision.decision_id)
    )

    assert completed.status is PlanningTaskStatus.COMPLETED
    assert len(outcomes) == 1
    assert not context.routing_store.record_decision_outcome(outcomes[0])
    with pytest.raises(RoutingFitnessStoreError, match="Conflicting routing outcome"):
        context.routing_store.record_decision_outcome(
            replace(outcomes[0], operational_outcome="deterministic_failure")
        )
    _close(context)
