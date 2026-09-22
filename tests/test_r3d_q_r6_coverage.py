from dataclasses import replace
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any, TypeVar, cast

import pytest
from jarvis.ai.fitness import (
    CircuitState,
    FitnessEvidence,
    ResiliencePolicy,
    RouteFitnessView,
    RoutingDecisionOutcome,
    RoutingDecisionRecord,
    RoutingFitnessProjection,
    RoutingFitnessStoreError,
    RoutingResilienceService,
    SemanticOutcome,
    SQLiteRoutingFitnessStore,
    VerifiedRouteOutcome,
)
from jarvis.ai.knowledge import CookbookSummary, EvidenceSufficiency, ModelMeasurementView
from jarvis.ai.models import PrivacyClassification, PrivacyContext
from jarvis.ai.routing import (
    InferenceDispatcher,
    InferenceDispatchError,
    ProviderHealthSnapshot,
    ProviderRouter,
    RouteBenchmark,
    RouteRequest,
    RouteStatus,
    RoutingFeedbackRecorder,
    RoutingPolicy,
)
from jarvis.ai.usability import ModelUsabilityEvidence, UsabilityReason
from jarvis.autonomy.routing import (
    CandidateEligibility,
    ExecutionCandidate,
    ExecutionCandidateKind,
    ExecutionRouteSelector,
    ExecutionRouteStatus,
    LogicalRole,
    ModelInferencePolicy,
    RoleResolver,
    StepRequirements,
    StepRoutingContext,
)
from jarvis.capabilities import CapabilityRegistry
from jarvis.tools.catalog import create_safe_tool_registry

from tests.fakes import FakeAIProvider
from tests.test_capabilities import manifest
from tests.test_p3c_adaptive_routing import _knowledge as adaptive_knowledge
from tests.test_p3c_adaptive_routing import _registry as adaptive_registry
from tests.test_p3c_adaptive_routing import _request as adaptive_request
from tests.test_r3d_b_execution_routing import model_registry, step
from tests.test_routing import registry as routing_registry
from tests.test_routing import request as routing_request

NOW = datetime(2026, 9, 20, tzinfo=UTC)
_T = TypeVar("_T")


def _replace_fields(value: _T, **changes: object) -> _T:
    """Apply table-driven invalid values without weakening the typed fixtures."""
    return cast(_T, replace(cast(Any, value), **changes))


def _outcome() -> VerifiedRouteOutcome:
    return VerifiedRouteOutcome(
        observation_id="observation",
        route_identity="provider:model",
        candidate_kind="model",
        task_class="analysis",
        role="worker",
        observed_at=NOW,
        operational_outcome="succeeded",
        semantic_outcome=SemanticOutcome.VERIFIED_SUCCESS,
        verification_source="trusted.verifier",
        evidence_refs=("receipt:1",),
    )


@pytest.mark.parametrize(
    ("changes", "message"),
    [
        ({"failure_threshold": 0}, "failure policy"),
        ({"failure_window": timedelta(0)}, "failure policy"),
        ({"cooldown": timedelta(0)}, "cooldown policy"),
        ({"lkgr_min_samples": 0}, "cooldown policy"),
        ({"lkgr_min_verified_reliability": 1.1}, "reliability policy"),
        ({"exploration_max_attempts": 0}, "Exploration policy"),
    ],
)
def test_resilience_policy_rejects_invalid_public_configuration(
    changes: dict[str, object], message: str
) -> None:
    with pytest.raises(ValueError, match=message):
        cast(Any, ResiliencePolicy)(**changes)


@pytest.mark.parametrize(
    ("field", "value", "message"),
    [
        ("observation_id", "", "observation ID"),
        ("route_identity", "bad\x00route", "route identity"),
        ("candidate_kind", "x" * 65, "candidate kind"),
        ("task_class", "", "task class"),
        ("role", "", "role"),
        ("operational_outcome", "", "operational outcome"),
        ("semantic_outcome", "verified_success", "semantic outcome"),
        ("verification_source", "", "verification source"),
        ("observed_at", datetime(2026, 9, 20), "timezone-aware"),
        ("retry_count", -1, "retry count"),
        ("retry_count", True, "retry count"),
        ("latency_ms", -0.1, "latency"),
        ("latency_ms", "slow", "latency"),
        ("monetary_cost", -0.1, "cost"),
        ("evidence_refs", ["receipt"], "evidence references"),
        ("evidence_refs", ("",), "evidence reference"),
        ("evidence_refs", ("bad\x00reference",), "evidence reference"),
    ],
)
def test_verified_route_outcome_rejects_malformed_trusted_facts(
    field: str, value: object, message: str
) -> None:
    with pytest.raises(ValueError, match=message):
        _replace_fields(_outcome(), **{field: value})


def _decision() -> RoutingDecisionRecord:
    return RoutingDecisionRecord(
        decision_id="decision",
        decided_at=NOW,
        route_kind="model",
        selected_identity="provider:model",
        role="worker",
        task_class="analysis",
        policy="balanced",
        privacy_classification="internal",
    )


@pytest.mark.parametrize(
    ("field", "value", "message"),
    [
        ("decision_id", "", "decision ID"),
        ("route_kind", "", "route kind"),
        ("role", "", "role"),
        ("task_class", "", "task class"),
        ("policy", "", "policy"),
        ("privacy_classification", "", "privacy classification"),
        ("strategy", "", "strategy"),
        ("decided_at", datetime(2026, 9, 20), "timezone-aware"),
        ("selected_identity", "", "selected identity"),
        ("required_capabilities", [], "capabilities"),
        ("required_capabilities", ("",), "capabilities"),
        ("alternative_identities", ("a", "b", "c", "d", "e"), "alternatives"),
        ("fallback_identities", ("",), "fallbacks"),
        ("evidence_refs", ("x",) * 17, "evidence references"),
        ("exclusions", [("route", "reason")], "exclusions"),
        ("exclusions", (("", "reason"),), "exclusions"),
        ("sample_count", -1, "sample count"),
        ("sample_count", True, "sample count"),
        ("exploration", 1, "exploration flag"),
        ("quality_score", -0.1, "quality"),
        ("switching_cost_ms", "slow", "switching cost"),
        ("predicted_latency_ms", -1, "latency"),
        ("predicted_cost", -1, "cost"),
    ],
)
def test_routing_decision_record_rejects_unsafe_explainability_facts(
    field: str, value: object, message: str
) -> None:
    with pytest.raises(ValueError, match=message):
        _replace_fields(_decision(), **{field: value})


def _decision_outcome() -> RoutingDecisionOutcome:
    return RoutingDecisionOutcome(
        outcome_id="outcome",
        decision_id="decision",
        observed_at=NOW,
        executed_identity="provider:model",
        operational_outcome="succeeded",
        semantic_outcome=SemanticOutcome.UNVERIFIED,
    )


@pytest.mark.parametrize(
    ("field", "value", "message"),
    [
        ("outcome_id", "", "outcome ID"),
        ("decision_id", "", "decision ID"),
        ("executed_identity", "", "executed identity"),
        ("operational_outcome", "", "operational outcome"),
        ("observed_at", datetime(2026, 9, 20), "metadata"),
        ("semantic_outcome", "unknown", "metadata"),
        ("rerouted", 1, "state"),
        ("retry_count", -1, "state"),
        ("evidence_refs", [], "evidence references"),
        ("evidence_refs", ("x",) * 17, "evidence references"),
    ],
)
def test_routing_decision_outcome_rejects_malformed_execution_facts(
    field: str, value: object, message: str
) -> None:
    with pytest.raises(ValueError, match=message):
        _replace_fields(_decision_outcome(), **{field: value})


@pytest.mark.parametrize(
    ("changes", "message"),
    [
        ({"provider_id": ""}, "identity"),
        ({"model_id": ""}, "identity"),
        ({"measured_at": datetime(2026, 9, 20)}, "timezone-aware"),
        ({"quality_score": -0.1}, "quality"),
        ({"latency_ms": float("inf")}, "latency"),
        ({"input_cost_per_million": "free"}, "input cost"),
        ({"output_cost_per_million": -1}, "output cost"),
        ({"throughput": -1}, "throughput"),
        ({"load_latency_ms": -1}, "load latency"),
    ],
)
def test_route_benchmark_rejects_untrusted_measurements(
    changes: dict[str, object], message: str
) -> None:
    values: dict[str, object] = {
        "provider_id": "provider",
        "model_id": "model",
        "measured_at": NOW,
    }
    with pytest.raises(ValueError, match=message):
        cast(Any, RouteBenchmark)(**(values | changes))


@pytest.mark.parametrize(
    ("changes", "message"),
    [
        ({"provider_id": ""}, "identity"),
        ({"available": 1}, "Provider health is invalid"),
        ({"detail": 1}, "Provider health is invalid"),
    ],
)
def test_provider_health_snapshot_rejects_malformed_observations(
    changes: dict[str, object], message: str
) -> None:
    with pytest.raises(ValueError, match=message):
        cast(Any, ProviderHealthSnapshot)(
            **({"provider_id": "provider", "available": True} | changes)
        )


@pytest.mark.parametrize(
    ("field", "value", "message"),
    [
        ("task", "", "task"),
        ("profile", "", "profile"),
        ("modality", "bad\x00modality", "modality"),
        ("complexity", "", "complexity"),
        ("classification", "", "classification"),
        ("task_class", "", "task class"),
        ("responsibility", "", "responsibility"),
        ("role", "general", "context"),
        ("context_tokens", -1, "context"),
        ("context_tokens", True, "context"),
        ("concurrency", 0, "concurrency"),
        ("policy", "balanced", "policy"),
        ("requires_tools", 1, "tools flag"),
        ("requires_structured_output", 1, "structured output flag"),
        ("no_llm", 1, "no LLM flag"),
        ("allow_no_llm", 1, "allow no LLM flag"),
        ("latency_budget_ms", 0, "latency budget"),
        ("latency_budget_ms", float("inf"), "latency budget"),
        ("preferred_provider_id", "", "Preferred provider"),
        ("preferred_model_id", "", "Preferred model"),
        ("pinned_provider_id", "", "Pinned provider"),
        ("pinned_model_id", "", "Pinned model"),
        ("benchmarks", [], "benchmarks"),
        ("benchmarks", (object(),), "benchmarks"),
        ("provider_health", [], "health snapshots"),
        ("provider_health", (object(),), "health snapshots"),
        ("usability_evidence", [], "usability evidence"),
        ("usability", (object(),), "usability"),
        ("priority", "user", "resource priority"),
        ("privacy_context", object(), "privacy context"),
        ("required_capabilities", {"vision"}, "capabilities"),
        ("required_capabilities", frozenset({""}), "capabilities"),
        ("minimum_expected_reliability", 1.1, "reliability requirement"),
        ("minimum_expected_reliability", float("nan"), "reliability requirement"),
        ("max_cost_per_million", -1, "cost budget"),
        ("previous_failure", "timeout", "failure context"),
        ("excluded_identities", [], "exclusions"),
        ("current_identity", object(), "Current route identity"),
        ("warm_identities", (object(),), "Warm route identities"),
        ("current_quality", 1.1, "Current route quality"),
        ("switching_cost_budget_ms", -1, "switching budget"),
        ("minimum_quality_gain_to_switch", 1.1, "switching quality threshold"),
    ],
)
def test_route_request_rejects_malformed_public_routing_requirements(
    field: str, value: object, message: str
) -> None:
    with pytest.raises(ValueError, match=message):
        _replace_fields(RouteRequest("task", "profile"), **{field: value})


def test_route_request_privacy_projection_is_typed_and_unknown_fails_closed() -> None:
    explicit = PrivacyContext()
    assert (
        replace(
            RouteRequest("task", "profile"), privacy_context=explicit
        ).effective_privacy_context()
        is explicit
    )
    assert (
        RouteRequest("task", "profile", classification="not-known")
        .effective_privacy_context()
        .classification.value
        == "unknown"
    )


@pytest.mark.parametrize(
    ("field", "value", "message"),
    [
        ("role", "worker", "role must be typed"),
        ("task_class", "", "task class"),
        ("complexity", "", "complexity"),
        ("modality", "bad\x00value", "modality"),
        ("privacy_context", object(), "privacy context"),
        ("required_capabilities", {"tool"}, "capabilities"),
        ("required_capabilities", frozenset({""}), "capabilities"),
        ("context_tokens", -1, "context"),
        ("requires_structured_output", 1, "structured output flag"),
        ("requires_tools", 1, "tool use flag"),
        ("model_inference", "optional", "model policy"),
        ("policy", "balanced", "policy"),
        ("priority", "user", "priority"),
        ("concurrency", 0, "concurrency"),
        ("preferred_tool_id", "", "tool identity"),
        ("minimum_verified_reliability", 1.1, "quality floor"),
        ("allow_exploration", 1, "exploration flags"),
        ("high_consequence", 1, "exploration flags"),
        ("verification_available", 1, "verification flag"),
    ],
)
def test_step_routing_context_rejects_malformed_trusted_context(
    field: str, value: object, message: str
) -> None:
    with pytest.raises(ValueError, match=message):
        _replace_fields(StepRoutingContext(), **{field: value})


def test_role_resolution_and_typed_step_boundaries_fail_closed() -> None:
    assert RoleResolver.resolve(LogicalRole.WORKER).source == "typed"
    assert RoleResolver.resolve("WORKER").source == "normalized"
    assert RoleResolver.resolve(None).source == "step_default"
    with pytest.raises(ValueError, match="Unknown"):
        RoleResolver.resolve("administrator")
    with pytest.raises(ValueError, match="invalid"):
        RoleResolver.resolve(cast(Any, 1))
    with pytest.raises(ValueError, match="trusted PlanStep"):
        StepRequirements.from_step(cast(Any, object()))
    with pytest.raises(ValueError, match="trusted PlanningStep"):
        StepRequirements.from_planning_step(cast(Any, object()))


def test_candidate_and_selector_public_validation_rejects_invalid_owners() -> None:
    with pytest.raises(ValueError, match="Candidate eligibility is invalid"):
        CandidateEligibility(cast(Any, 1))
    with pytest.raises(ValueError, match="eligibility codes"):
        CandidateEligibility(True, cast(Any, ("bad",)))
    valid = ExecutionCandidate(
        "tool",
        ExecutionCandidateKind.TOOL,
        "registry",
        frozenset({"tool"}),
        "local",
        None,
        False,
        True,
        CandidateEligibility(True),
    )
    for field, value, message in (
        ("identity", "", "identity"),
        ("kind", "tool", "kind"),
        ("declared_capabilities", {"tool"}, "capabilities"),
        ("executable", 1, "state"),
        ("eligibility", object(), "state"),
    ):
        with pytest.raises(ValueError, match=message):
            _replace_fields(valid, **{field: value})

    registry = create_safe_tool_registry()
    with pytest.raises(TypeError, match="Model router"):
        ExecutionRouteSelector(model_router=cast(Any, object()), tool_registry=registry)
    with pytest.raises(TypeError, match="canonical registries"):
        ExecutionRouteSelector(model_router=None, tool_registry=cast(Any, object()))
    selector = ExecutionRouteSelector(model_router=None, tool_registry=registry)
    with pytest.raises(ValueError, match="Typed step requirements"):
        selector.route(cast(Any, object()))


def test_provider_router_rejects_malformed_runtime_configuration() -> None:
    registry = cast(Any, object())
    with pytest.raises(TypeError, match="Routing decision store"):
        ProviderRouter(registry, routing_store=cast(Any, object()))
    with pytest.raises(ValueError, match="usability evidence"):
        ProviderRouter(registry, usability_evidence=cast(Any, []))
    with pytest.raises(ValueError, match="cooldown"):
        ProviderRouter(registry, failure_cooldown_seconds=-1)


def test_provider_router_public_unknown_and_optional_surfaces_fail_closed() -> None:
    router = ProviderRouter(routing_registry())
    decision = router.route(routing_request())
    assert decision.status is RouteStatus.SELECTED
    assert decision.primary is not None
    candidate = decision.primary
    assert candidate.reliability is None
    assert not candidate.reliability_sufficient
    assert candidate.usability_status.value == "unknown"
    assert candidate.usability_reason.value == "unknown"
    assert router.routing_store is None
    assert router.decision_view("missing") is None
    assert router.persist_fusion_decision(routing_request(), decision, (candidate,)) is decision
    with pytest.raises(ValueError, match="hardware profile"):
        router.set_hardware_profile(cast(Any, object()))
    with pytest.raises(ValueError, match="usability evidence"):
        router.set_usability_evidence(cast(Any, object()))
    with pytest.raises(ValueError, match="failure identity"):
        router.record_failure(cast(Any, object()), cast(Any, "provider_outage"))

    wildcard = ModelUsabilityEvidence(model_id="remote-model", source="trusted-test")
    wildcard_router = ProviderRouter(routing_registry(), usability_evidence=(wildcard,))
    assert wildcard_router.usability_for("remote", "remote-model") == wildcard


def test_route_candidate_projects_trusted_measurement_and_cookbook_facts() -> None:
    decision = ProviderRouter(routing_registry()).route(routing_request())
    assert decision.primary is not None
    candidate = replace(
        decision.primary,
        measurement=ModelMeasurementView(
            decision.primary.identity,
            NOW,
            "trusted-measurement",
            "this_machine",
            load_seconds=0.25,
        ),
        cookbook=CookbookSummary(
            decision.primary.identity,
            "analysis",
            4,
            3,
            1,
            0,
            0,
            0,
            0,
            0,
            0,
            None,
            EvidenceSufficiency.SUFFICIENT,
        ),
        usability=None,
    )
    assert candidate.latency == 250.0
    assert candidate.reliability == 0.75
    assert candidate.reliability_sufficient
    assert candidate.usability_status.value == "unknown"
    assert candidate.usability_reason.value == "unknown"


def test_dispatcher_bounds_and_feedback_optional_router_are_explicit(tmp_path: Path) -> None:
    registry = routing_registry()
    router = ProviderRouter(registry)
    with pytest.raises(ValueError, match="attempts must be bounded"):
        InferenceDispatcher(router, registry, max_attempts=0)
    with pytest.raises(ValueError, match="cache bound"):
        InferenceDispatcher(router, registry, max_cached_providers=0)

    decision = router.route(routing_request())
    assert decision.primary is not None
    identity = decision.primary.identity
    knowledge = adaptive_knowledge(tmp_path, registry)
    detached = RoutingFeedbackRecorder(knowledge)
    assert detached.record_failure(identity, UsabilityReason.PROVIDER_OUTAGE) is None
    assert detached.record_success(identity) is None
    attached = RoutingFeedbackRecorder(knowledge, router=router)
    assert attached.record_failure(identity, UsabilityReason.PROVIDER_OUTAGE) is not None
    assert attached.record_success(identity) is not None


def test_execution_selector_reports_missing_and_descriptive_owners() -> None:
    registry = create_safe_tool_registry()
    selector = ExecutionRouteSelector(model_router=None, tool_registry=registry)
    required_model = StepRequirements.from_step(
        step(), context=StepRoutingContext(model_inference=ModelInferencePolicy.REQUIRED)
    )
    missing = selector.route(required_model)
    assert missing.status is ExecutionRouteStatus.NO_VALID_ROUTE
    assert missing.excluded[0].identity == "model-route"
    assert not missing.excluded[0].executable

    descriptive = CapabilityRegistry((manifest(capability_id="descriptive-r6"),))
    selector = ExecutionRouteSelector(
        model_router=ProviderRouter(model_registry()),
        tool_registry=registry,
        capability_registry=descriptive,
    )
    descriptive_result = selector.route(
        StepRequirements.from_step(
            step("descriptive-r6"),
            context=StepRoutingContext(model_inference=ModelInferencePolicy.FORBIDDEN),
        )
    )
    assert descriptive_result.status is ExecutionRouteStatus.NO_VALID_ROUTE
    assert descriptive_result.excluded[0].kind is ExecutionCandidateKind.CAPABILITY
    assert not descriptive_result.excluded[0].executable

    unknown_result = ExecutionRouteSelector(
        model_router=None,
        tool_registry=registry,
        capability_registry=CapabilityRegistry(()),
    ).route(
        StepRequirements.from_step(
            step("unknown-r6"),
            context=StepRoutingContext(model_inference=ModelInferencePolicy.FORBIDDEN),
        )
    )
    assert unknown_result.status is ExecutionRouteStatus.NO_VALID_ROUTE
    assert unknown_result.excluded == ()

    model_result = selector.route(
        StepRequirements.from_step(
            step(),
            context=StepRoutingContext(
                model_inference=ModelInferencePolicy.REQUIRED,
                privacy_context=PrivacyContext(PrivacyClassification.SAFE_PUBLIC),
            ),
        )
    )
    assert model_result.status is ExecutionRouteStatus.SELECTED
    assert model_result.primary is not None
    assert model_result.primary.kind is ExecutionCandidateKind.MODEL


def test_execution_selector_rejects_every_invalid_optional_owner() -> None:
    registry = create_safe_tool_registry()
    for keyword, message in (
        ({"capability_registry": object()}, "Capability registry"),
        ({"resource_governor": object()}, "Resource governor"),
        ({"fitness": object()}, "fitness projection"),
        ({"resilience": object()}, "resilience service"),
        ({"routing_store": object()}, "decision store"),
    ):
        with pytest.raises(TypeError, match=message):
            ExecutionRouteSelector(
                model_router=None,
                tool_registry=registry,
                **cast(Any, keyword),
            )


def test_routing_store_public_fail_closed_boundaries(tmp_path: Path) -> None:
    path = tmp_path / "routing.sqlite3"
    store = SQLiteRoutingFitnessStore(path)
    with pytest.raises(RoutingFitnessStoreError, match="outcome is malformed"):
        store.record(cast(Any, object()))
    with pytest.raises(RoutingFitnessStoreError, match="decision is malformed"):
        store.record_decision(cast(Any, object()))
    with pytest.raises(RoutingFitnessStoreError, match="limit is invalid"):
        store.decisions(limit=0)
    with pytest.raises(RoutingFitnessStoreError, match="outcome is malformed"):
        store.record_decision_outcome(cast(Any, object()))
    with pytest.raises(RoutingFitnessStoreError, match="decision is not durable"):
        store.record_decision_outcome(_decision_outcome())
    store.close()


def test_routing_store_rejects_malformed_durable_rows(tmp_path: Path) -> None:
    path = tmp_path / "routing.sqlite3"
    store = SQLiteRoutingFitnessStore(path)
    assert store.record(_outcome())
    assert store.record_decision(_decision())
    assert store.record_decision_outcome(_decision_outcome())
    store.close()

    import sqlite3

    connection = sqlite3.connect(path)
    connection.execute("UPDATE routing_fitness_observations SET evidence_refs_json = '{}'")
    connection.execute("UPDATE routing_decisions SET decision_json = '[]'")
    connection.execute("UPDATE routing_decision_outcomes SET evidence_refs_json = '{}'")
    connection.commit()
    connection.close()

    reopened = SQLiteRoutingFitnessStore(path)
    with pytest.raises(RoutingFitnessStoreError, match="Stored routing fitness is malformed"):
        reopened.observations()
    with pytest.raises(RoutingFitnessStoreError, match="Stored routing outcome is malformed"):
        reopened.decision_outcomes("decision")
    with pytest.raises(RoutingFitnessStoreError, match="Stored routing decision is malformed"):
        reopened.decision_view("decision")
    reopened.close()


def test_fitness_views_and_resilience_negative_paths_are_explicit() -> None:
    empty = RouteFitnessView(
        "route",
        "tool",
        "analysis",
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        None,
        FitnessEvidence.INSUFFICIENT,
        None,
    )
    assert empty.operational_success_rate is None
    assert empty.verified_success_rate is None
    assert empty.failure_rate is None
    assert not empty.meets_quality_floor(0.8, NOW)
    stale = replace(
        empty,
        sample_count=3,
        semantic_verified_success_count=3,
        evidence=FitnessEvidence.SUFFICIENT,
        last_observed_at=NOW - timedelta(days=31),
    )
    assert stale.failure_rate == 0.0
    assert not stale.meets_quality_floor(0.8, NOW)

    with pytest.raises(TypeError, match="fitness projection"):
        RoutingResilienceService(cast(Any, object()))
    with pytest.raises(TypeError, match="fitness store"):
        RoutingResilienceService(RoutingFitnessProjection(), store=cast(Any, object()))
    with pytest.raises(TypeError, match="fitness store"):
        RoutingFitnessProjection(store=cast(Any, object()))


def test_breaker_unknown_and_exploration_cooldown_remain_fail_closed() -> None:
    projection = RoutingFitnessProjection(clock=lambda: NOW)
    service = RoutingResilienceService(
        projection,
        clock=lambda: NOW,
        policy=ResiliencePolicy(exploration_max_attempts=2),
    )
    key = service.key("route", "tool", "analysis", "worker")
    service.record(
        key,
        operational_outcome="unknown_outcome",
        semantic_outcome=SemanticOutcome.UNKNOWN,
    )
    assert service.snapshot(key).state is CircuitState.CLOSED
    assert service.claim_exploration(
        key,
        allow_exploration=True,
        high_consequence=False,
        verification_available=True,
    )
    assert not service.claim_exploration(
        key,
        allow_exploration=True,
        high_consequence=False,
        verification_available=True,
    )
    for _ in range(3):
        service.record(
            key,
            operational_outcome="transient_failure",
            semantic_outcome=SemanticOutcome.UNVERIFIED,
            failure_class="transient_failure",
        )
    assert service.snapshot(key).state is CircuitState.OPEN
    assert not service.is_lkgr(key)
    assert not service.exploration_allowed(
        key,
        allow_exploration=True,
        high_consequence=False,
        verification_available=True,
    )


def test_ephemeral_projection_rejects_malformed_and_conflicting_replays() -> None:
    projection = RoutingFitnessProjection(clock=lambda: NOW)
    with pytest.raises(ValueError, match="outcome is malformed"):
        projection.record(cast(Any, object()))
    original = _outcome()
    assert projection.record(original)
    assert not projection.record(replace(original, observed_at=NOW + timedelta(seconds=1)))
    with pytest.raises(RoutingFitnessStoreError, match="Conflicting"):
        projection.record(replace(original, semantic_outcome=SemanticOutcome.VERIFIED_FAILURE))


class _ModelUnavailableError(RuntimeError):
    pass


class _DispatchErrorProvider(FakeAIProvider):
    def __init__(self, error: Exception) -> None:
        super().__init__()
        self._error = error

    async def generate(self, request: Any) -> Any:
        self.requests.append(request)
        raise self._error


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("error", "expected_status", "expected_reason"),
    [
        (TimeoutError("timeout"), RouteStatus.ATTEMPTS_EXHAUSTED, "network_unavailable"),
        (RuntimeError("429 too many requests"), RouteStatus.ATTEMPTS_EXHAUSTED, "rate_limited"),
        (RuntimeError("quota exhausted"), RouteStatus.ATTEMPTS_EXHAUSTED, "quota_exhausted"),
        (RuntimeError("payment required"), RouteStatus.ATTEMPTS_EXHAUSTED, "billing_blocked"),
        (
            RuntimeError("credential rejected 401"),
            RouteStatus.ATTEMPTS_EXHAUSTED,
            "invalid_credentials",
        ),
        (
            _ModelUnavailableError("model unavailable"),
            RouteStatus.ATTEMPTS_EXHAUSTED,
            "model_not_found",
        ),
        (RuntimeError("structured output malformed"), RouteStatus.ATTEMPTS_EXHAUSTED, None),
        (RuntimeError("tool call invalid"), RouteStatus.ATTEMPTS_EXHAUSTED, None),
        (
            RuntimeError("resource oom"),
            RouteStatus.ATTEMPTS_EXHAUSTED,
            "local_resource_blocked",
        ),
        (RuntimeError("verification failed"), RouteStatus.ATTEMPTS_EXHAUSTED, None),
        (RuntimeError("connect unavailable"), RouteStatus.UNKNOWN, None),
    ],
)
async def test_dispatch_failure_classes_remain_bounded_and_fail_closed(
    tmp_path: Path,
    error: Exception,
    expected_status: RouteStatus,
    expected_reason: str | None,
) -> None:
    remote = _DispatchErrorProvider(error)
    registry = adaptive_registry(remote, FakeAIProvider(("unused",)))
    dispatcher = InferenceDispatcher(
        ProviderRouter(registry, knowledge=adaptive_knowledge(tmp_path, registry)),
        registry,
        providers={"remote": remote},
        max_attempts=1,
    )
    intent = adaptive_request(policy=RoutingPolicy.QUALITY_FIRST)

    from jarvis.ai.models import GenerationRequest

    with pytest.raises(InferenceDispatchError) as failure:
        await dispatcher.generate(
            GenerationRequest((), "remote-model", 4096, intent.effective_privacy_context()),
            intent,
        )

    assert failure.value.decision.status is expected_status
    assert len(remote.requests) == 1
    evidence = dict(failure.value.decision.evidence)
    if expected_reason is None:
        assert "usability_failure_reason" not in evidence
    else:
        assert evidence["usability_failure_reason"] == expected_reason
    await dispatcher.aclose()
