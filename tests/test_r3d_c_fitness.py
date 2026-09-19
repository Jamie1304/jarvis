from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest
from jarvis.ai.fitness import (
    FitnessEvidence,
    RoutingFitnessProjection,
    SemanticOutcome,
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
from jarvis.capabilities import CapabilityRegistry
from jarvis.permissions.broker import PermissionBroker
from jarvis.permissions.policy import PolicyEngine
from jarvis.planning import (
    BrokeredPlanningStepExecutor,
    CompletionCriteriaVerifier,
    EvidencePlanningStepVerifier,
    PlanningEngine,
    PlanValidator,
    SQLitePlanningStore,
)
from jarvis.tools.catalog import create_safe_tool_registry
from jarvis.tools.models import ToolEvidence, ToolResult
from jarvis.tools.registry import ToolRegistry

from tests.test_planning_engine import _Advisor, _Output, _plan, _ResultTool, _step
from tests.test_r3d_b_execution_routing import step

NOW = datetime(2026, 9, 19, tzinfo=UTC)


def observation(
    number: int,
    *,
    semantic: SemanticOutcome = SemanticOutcome.VERIFIED_SUCCESS,
    observed_at: datetime = NOW,
) -> VerifiedRouteOutcome:
    return VerifiedRouteOutcome(
        observation_id=f"observation-{number}",
        route_identity="calculator",
        candidate_kind="tool",
        task_class="math",
        role="orchestration",
        observed_at=observed_at,
        operational_outcome="succeeded",
        semantic_outcome=semantic,
        verification_source="planning.step_verifier"
        if semantic in {SemanticOutcome.VERIFIED_SUCCESS, SemanticOutcome.VERIFIED_FAILURE}
        else None,
        retry_count=number,
    )


def test_operational_success_does_not_imply_verified_success() -> None:
    projection = RoutingFitnessProjection(clock=lambda: NOW)
    projection.record(observation(1, semantic=SemanticOutcome.VERIFIED_FAILURE))

    view = projection.view("calculator", "math", now=NOW)

    assert view.operational_success_rate == 1.0
    assert view.verified_success_rate == 0.0
    assert view.semantic_verified_failure_count == 1


def test_unknown_and_unverified_are_not_quality_success() -> None:
    projection = RoutingFitnessProjection(clock=lambda: NOW)
    projection.record(observation(1, semantic=SemanticOutcome.UNKNOWN))
    projection.record(observation(2, semantic=SemanticOutcome.UNVERIFIED))

    view = projection.view("calculator", "math", now=NOW)

    assert view.unknown_outcome_count == 1
    assert view.unverified_count == 1
    assert view.verified_success_rate == 0.0
    assert view.evidence is FitnessEvidence.INSUFFICIENT


def test_duplicate_observation_is_ignored_and_projection_is_rebuildable() -> None:
    projection = RoutingFitnessProjection(clock=lambda: NOW)
    item = observation(1)

    assert projection.record(item)
    assert not projection.record(item)
    assert projection.view("calculator", "math", now=NOW).sample_count == 1
    assert (
        RoutingFitnessProjection(clock=lambda: NOW).view("calculator", "math", now=NOW).evidence
        is FitnessEvidence.UNKNOWN
    )


def test_quality_evidence_requires_three_recent_samples() -> None:
    projection = RoutingFitnessProjection(clock=lambda: NOW)
    for number in range(1, 4):
        assert projection.record(observation(number))

    view = projection.view("calculator", "math", now=NOW)

    assert view.evidence is FitnessEvidence.SUFFICIENT
    assert view.meets_quality_floor(0.8, NOW)


def test_stale_evidence_is_retained_but_not_eligible_for_floor() -> None:
    projection = RoutingFitnessProjection(clock=lambda: NOW)
    old = NOW - timedelta(days=31)
    for number in range(1, 4):
        projection.record(observation(number, observed_at=old))

    view = projection.view("calculator", "math", now=NOW)

    assert view.sample_count == 3
    assert view.evidence is FitnessEvidence.STALE
    assert not view.meets_quality_floor(0.0, NOW)


def test_quality_floor_is_hard_before_route_selection_and_preserves_owned_tool() -> None:
    projection = RoutingFitnessProjection(clock=lambda: NOW)
    for number in range(1, 4):
        projection.record(observation(number, semantic=SemanticOutcome.VERIFIED_FAILURE))
    requirements = StepRequirements.from_step(
        step(),
        context=StepRoutingContext(
            model_inference=ModelInferencePolicy.FORBIDDEN,
            task_class="math",
            preferred_tool_id="calculator",
            minimum_verified_reliability=0.8,
        ),
    )
    selector = ExecutionRouteSelector(
        model_router=None,
        tool_registry=create_safe_tool_registry(),
        capability_registry=CapabilityRegistry(),
        fitness=projection,
    )

    decision = selector.route(requirements)

    assert decision.status is ExecutionRouteStatus.NO_VALID_ROUTE
    assert decision.excluded[0].tool_id == "calculator"
    assert EligibilityCode.QUALITY_FLOOR_NOT_MET in decision.reasons


def test_route_attribution_is_partitioned_by_identity_and_task_class() -> None:
    projection = RoutingFitnessProjection(clock=lambda: NOW)
    for number in range(1, 4):
        projection.record(observation(number))

    assert projection.view("calculator", "math", now=NOW).sample_count == 3
    assert projection.view("other-tool", "math", now=NOW).evidence is FitnessEvidence.UNKNOWN
    assert projection.view("calculator", "writing", now=NOW).evidence is FitnessEvidence.UNKNOWN


@pytest.mark.asyncio
async def test_production_planning_path_records_only_after_semantic_verification(
    tmp_path: Path,
) -> None:
    projection = RoutingFitnessProjection(clock=lambda: NOW)
    tool = _ResultTool(
        ToolResult.success(
            _Output(value="ok"),
            evidence=(ToolEvidence("test", "result-tool-ready"),),
        )
    )
    registry = ToolRegistry((tool,), permission_broker=PermissionBroker(PolicyEngine()))
    selector = ExecutionRouteSelector(
        model_router=None,
        tool_registry=registry,
        fitness=projection,
    )
    engine = PlanningEngine(
        store=SQLitePlanningStore(tmp_path / "planning.sqlite3"),
        advisor=_Advisor((_plan(_step("result-tool")),)),
        validator=PlanValidator(registry, max_steps=4),
        executor=BrokeredPlanningStepExecutor(registry, route_selector=selector),
        step_verifier=EvidencePlanningStepVerifier(),
        goal_verifier=CompletionCriteriaVerifier(),
        routing_fitness=projection,
    )

    task = await engine.submit("Prepare my system for a meeting")
    view = projection.view("result-tool", "result-tool", now=NOW)

    assert task.status.value == "completed", task.error
    assert view.sample_count == 1
    assert view.semantic_verified_success_count == 1
