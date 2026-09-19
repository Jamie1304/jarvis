from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest
from jarvis.ai.fitness import (
    CircuitState,
    ResiliencePolicy,
    RoutingFitnessProjection,
    RoutingResilienceService,
    SemanticOutcome,
    SQLiteRoutingFitnessStore,
    VerifiedRouteOutcome,
)
from jarvis.autonomy.routing import (
    EligibilityCode,
    ExecutionRouteSelector,
    ExecutionRouteStatus,
    ModelInferencePolicy,
    StepRequirements,
    StepRoutingContext,
)
from jarvis.planning import (
    BrokeredPlanningStepExecutor,
    CompletionCriteriaVerifier,
    EvidencePlanningStepVerifier,
    PlanningEngine,
    PlanningTaskStatus,
    PlanValidator,
    SQLitePlanningStore,
)
from jarvis.tools.catalog import create_safe_tool_registry

from tests.test_planning_engine import _Advisor, _plan, _step
from tests.test_r3d_b_execution_routing import step


class _Clock:
    def __init__(self) -> None:
        self.value = datetime(2026, 9, 19, tzinfo=UTC)

    def __call__(self) -> datetime:
        return self.value


def outcome(number: int, semantic: SemanticOutcome = SemanticOutcome.VERIFIED_SUCCESS):
    return VerifiedRouteOutcome(
        observation_id=f"d-route-{number}",
        route_identity="calculator",
        candidate_kind="tool",
        task_class="math",
        role="orchestration",
        observed_at=datetime(2026, 9, 19, tzinfo=UTC),
        operational_outcome="succeeded",
        semantic_outcome=semantic,
        verification_source="planning.step_verifier",
    )


def service(
    tmp_path: Path, clock: _Clock
) -> tuple[SQLiteRoutingFitnessStore, RoutingResilienceService]:
    store = SQLiteRoutingFitnessStore(tmp_path / "routing-fitness.sqlite3")
    projection = RoutingFitnessProjection(clock=clock, store=store)
    return store, RoutingResilienceService(
        projection,
        store=store,
        clock=clock,
        policy=ResiliencePolicy(failure_threshold=3, cooldown=timedelta(minutes=5)),
    )


def key(resilience: RoutingResilienceService):
    return resilience.key("calculator", "tool", "math", "orchestration")


def fail(resilience: RoutingResilienceService) -> None:
    resilience.record(
        key(resilience),
        operational_outcome="transient_failure",
        semantic_outcome=SemanticOutcome.UNVERIFIED,
        failure_class="transient_failure",
    )


def test_closed_threshold_and_non_attributable_failures(tmp_path: Path) -> None:
    clock = _Clock()
    store, resilience = service(tmp_path, clock)
    route_key = key(resilience)

    resilience.record(
        route_key,
        operational_outcome="waiting_for_permission",
        semantic_outcome=SemanticOutcome.UNVERIFIED,
        failure_class="permission_denied",
    )
    resilience.record(
        route_key,
        operational_outcome="cancelled",
        semantic_outcome=SemanticOutcome.UNVERIFIED,
        failure_class="cancelled",
    )
    assert resilience.snapshot(route_key).state is CircuitState.CLOSED
    fail(resilience)
    fail(resilience)
    assert resilience.snapshot(route_key).state is CircuitState.CLOSED
    fail(resilience)
    assert resilience.snapshot(route_key).state is CircuitState.OPEN
    store.close()


def test_open_state_restart_and_cooldown_half_open(tmp_path: Path) -> None:
    clock = _Clock()
    store, resilience = service(tmp_path, clock)
    route_key = key(resilience)
    for _ in range(3):
        fail(resilience)
    store.close()

    reopened, restarted = service(tmp_path, clock)
    assert restarted.snapshot(route_key).state is CircuitState.OPEN
    assert not restarted.admit(route_key)[0]
    clock.value += timedelta(minutes=6)
    assert restarted.snapshot(route_key).state is CircuitState.HALF_OPEN
    assert restarted.admit(route_key) == (True, True)
    assert restarted.admit(route_key) == (False, False)
    reopened.close()


def test_successful_probe_closes_and_failed_or_unknown_probe_reopens(tmp_path: Path) -> None:
    clock = _Clock()
    store, resilience = service(tmp_path, clock)
    route_key = key(resilience)
    for _ in range(3):
        fail(resilience)
    clock.value += timedelta(minutes=6)
    assert resilience.admit(route_key) == (True, True)
    resilience.record(
        route_key,
        operational_outcome="succeeded",
        semantic_outcome=SemanticOutcome.VERIFIED_SUCCESS,
    )
    assert resilience.snapshot(route_key).state is CircuitState.CLOSED
    for _ in range(3):
        fail(resilience)
    clock.value += timedelta(minutes=6)
    assert resilience.admit(route_key) == (True, True)
    resilience.record(
        route_key,
        operational_outcome="unknown_outcome",
        semantic_outcome=SemanticOutcome.UNKNOWN,
        failure_class="unknown_outcome",
    )
    assert resilience.snapshot(route_key).state is CircuitState.OPEN
    store.close()


def test_lkgr_is_task_scoped_and_derived_from_verified_fitness(tmp_path: Path) -> None:
    clock = _Clock()
    store = SQLiteRoutingFitnessStore(tmp_path / "routing-fitness.sqlite3")
    projection = RoutingFitnessProjection(clock=clock, store=store)
    resilience = RoutingResilienceService(projection, store=store, clock=clock)
    for number in range(1, 4):
        assert projection.record(outcome(number))

    assert resilience.is_lkgr(key(resilience))
    other = resilience.key("calculator", "tool", "writing", "orchestration")
    assert not resilience.is_lkgr(other)
    store.close()


def test_exploration_is_explicit_safe_and_not_for_high_consequence(tmp_path: Path) -> None:
    clock = _Clock()
    store = SQLiteRoutingFitnessStore(tmp_path / "routing-fitness.sqlite3")
    projection = RoutingFitnessProjection(clock=clock, store=store)
    resilience = RoutingResilienceService(projection, store=store, clock=clock)
    selector = ExecutionRouteSelector(
        model_router=None,
        tool_registry=create_safe_tool_registry(),
        fitness=projection,
        resilience=resilience,
    )
    safe = StepRequirements.from_step(
        step(),
        context=StepRoutingContext(
            model_inference=ModelInferencePolicy.FORBIDDEN,
            task_class="math",
            allow_exploration=True,
        ),
    )
    high = StepRequirements.from_step(
        step(),
        context=StepRoutingContext(
            model_inference=ModelInferencePolicy.FORBIDDEN,
            task_class="math",
            allow_exploration=True,
            high_consequence=True,
        ),
    )

    safe_decision = selector.route(safe)
    repeated_safe_decision = selector.route(safe)
    high_decision = selector.route(high)

    assert safe_decision.status is ExecutionRouteStatus.SELECTED
    assert EligibilityCode.EXPLORATION_SELECTED in safe_decision.primary.eligibility.codes
    assert repeated_safe_decision.status is ExecutionRouteStatus.NO_VALID_ROUTE
    assert high_decision.status is ExecutionRouteStatus.NO_VALID_ROUTE
    assert EligibilityCode.EXPLORATION_NOT_ALLOWED in high_decision.reasons
    store.close()


def test_open_exact_planned_tool_is_no_route_not_silent_substitution(tmp_path: Path) -> None:
    clock = _Clock()
    store, resilience = service(tmp_path, clock)
    for _ in range(3):
        fail(resilience)
    selector = ExecutionRouteSelector(
        model_router=None,
        tool_registry=create_safe_tool_registry(),
        fitness=RoutingFitnessProjection(clock=clock, store=store),
        resilience=resilience,
    )
    requirements = StepRequirements.from_step(
        step(),
        context=StepRoutingContext(
            model_inference=ModelInferencePolicy.FORBIDDEN,
            task_class="math",
            preferred_tool_id="calculator",
        ),
    )

    decision = selector.route(requirements)

    assert decision.status is ExecutionRouteStatus.NO_VALID_ROUTE
    assert EligibilityCode.CIRCUIT_OPEN in decision.reasons
    store.close()


@pytest.mark.asyncio
async def test_production_planning_path_honors_open_route(tmp_path: Path) -> None:
    clock = _Clock()
    store = SQLiteRoutingFitnessStore(tmp_path / "routing-fitness.sqlite3")
    projection = RoutingFitnessProjection(clock=clock, store=store)
    resilience = RoutingResilienceService(projection, store=store, clock=clock)
    production_key = resilience.key("calculator", "tool", "general", "orchestration")
    for _ in range(3):
        resilience.record(
            production_key,
            operational_outcome="transient_failure",
            semantic_outcome=SemanticOutcome.UNVERIFIED,
            failure_class="transient_failure",
        )
    registry = create_safe_tool_registry()
    proposal = _plan(_step("calculator"))
    proposal["steps"][0]["capability"] = "math"  # type: ignore[index]
    proposal["steps"][0]["input"] = {"expression": "2 + 2"}  # type: ignore[index]
    proposal["required_capabilities"] = ["math"]
    selector = ExecutionRouteSelector(
        model_router=None,
        tool_registry=registry,
        fitness=projection,
        resilience=resilience,
    )
    engine = PlanningEngine(
        store=SQLitePlanningStore(tmp_path / "planning.sqlite3"),
        advisor=_Advisor((proposal,)),
        validator=PlanValidator(registry, max_steps=2),
        executor=BrokeredPlanningStepExecutor(registry, route_selector=selector),
        step_verifier=EvidencePlanningStepVerifier(),
        goal_verifier=CompletionCriteriaVerifier(),
        routing_fitness=projection,
        routing_resilience=resilience,
    )

    task = await engine.submit("Prepare my system for a meeting")

    assert task.status is PlanningTaskStatus.FAILED
    assert task.error is not None
    assert task.error.code == "replanning_provider_failed"
    store.close()
