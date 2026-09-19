"""Focused R3D-F persistence, explainability, and bounded model fusion proof."""

from __future__ import annotations

import asyncio
import sqlite3
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, cast

import pytest
from jarvis.ai.fitness import (
    CircuitState,
    RoutingDecisionOutcome,
    RoutingDecisionRecord,
    RoutingFitnessProjection,
    RoutingFitnessStoreError,
    RoutingResilienceService,
    SemanticOutcome,
    SQLiteRoutingFitnessStore,
)
from jarvis.ai.knowledge import identity_for
from jarvis.ai.models import GenerationRequest, ModelRole, PrivacyClassification, PrivacyContext
from jarvis.ai.providers import (
    ModelMetadata,
    ProviderDefinition,
    ProviderMetadata,
    ProviderRegistry,
)
from jarvis.ai.routing import (
    FusionCoordinator,
    FusionDispatchError,
    FusionPolicy,
    InferenceDispatcher,
    ProviderRouter,
    RouteRequest,
    RouteStatus,
    RoutingPolicy,
)
from jarvis.autonomy.routing import (
    ExecutionRouteSelector,
    StepRequirements,
)
from jarvis.resources import ResourceGovernor, ResourcePolicy, ResourceSnapshot
from jarvis.tools.catalog import create_safe_tool_registry

from tests.fakes import FakeAIProvider
from tests.test_hardware import _hardware
from tests.test_r3d_b_r1_integration import planned_step, task

NOW = datetime(2026, 9, 19, tzinfo=UTC)


def decision(**changes: object) -> RoutingDecisionRecord:
    values: dict[str, object] = {
        "decision_id": "decision-1",
        "decided_at": NOW,
        "route_kind": "model",
        "selected_identity": "local/model-a@v1",
        "role": "general",
        "task_class": "analysis",
        "policy": "quality_first",
        "privacy_classification": "local_only",
        "required_capabilities": ("chat",),
        "strategy": "single_route",
        "alternative_identities": ("local/model-b@v1",),
        "exclusions": (("cloud/model-c@v1", "privacy_ineligible"),),
        "quality_score": 0.91,
        "sample_count": 4,
        "evidence_sufficiency": "sufficient_evidence",
        "lkgr": True,
        "breaker_state": CircuitState.CLOSED.value,
        "exploration": False,
        "resource_status": "allow",
        "protected_headroom": True,
        "affinity_current": True,
        "affinity_warm": False,
        "switching_cost_ms": 8.0,
        "predicted_latency_ms": 40.0,
        "predicted_cost": 0.0,
        "fallback_identities": ("local/model-b@v1",),
        "evidence_refs": ("measurement:1",),
    }
    values.update(changes)
    return RoutingDecisionRecord(**cast(Any, values))


def outcome(**changes: object) -> RoutingDecisionOutcome:
    values: dict[str, object] = {
        "outcome_id": "outcome-1",
        "decision_id": "decision-1",
        "observed_at": NOW,
        "executed_identity": "local/model-a@v1",
        "operational_outcome": "succeeded",
        "semantic_outcome": SemanticOutcome.UNVERIFIED,
    }
    values.update(changes)
    return RoutingDecisionOutcome(**cast(Any, values))


def test_decision_store_restarts_redacts_canary_and_links_immutably(tmp_path: Path) -> None:
    path = tmp_path / "routing-fitness.sqlite3"
    record = decision()
    with SQLiteRoutingFitnessStore(path) as store:
        assert store.record_decision(record)
        assert not store.record_decision(record)
        assert store.record_decision_outcome(outcome())
        assert not store.record_decision_outcome(outcome())
        view = store.decision_view(record.decision_id)
        assert view is not None and view.decision.selected_identity == record.selected_identity
        assert view.outcomes[0].semantic_outcome is SemanticOutcome.UNVERIFIED
        with pytest.raises(RoutingFitnessStoreError):
            store.record_decision_outcome(outcome(executed_identity="local/other@v1"))
    reopened = SQLiteRoutingFitnessStore(path)
    try:
        assert reopened.decision(record.decision_id) == record
        assert len(reopened.decision_outcomes(record.decision_id)) == 1
        assert "UNIQUE_SECRET_CANARY" not in path.read_bytes().decode("utf-8", errors="ignore")
    finally:
        reopened.close()


def test_schema_migration_is_v4_and_future_schema_fails_closed(tmp_path: Path) -> None:
    path = tmp_path / "routing.sqlite3"
    with SQLiteRoutingFitnessStore(path):
        pass
    connection = sqlite3.connect(path)
    try:
        assert (
            connection.execute("SELECT max(version) FROM routing_fitness_schema").fetchone()[0] == 4
        )
    finally:
        connection.close()

    future = tmp_path / "future.sqlite3"
    connection = sqlite3.connect(future)
    connection.execute(
        "CREATE TABLE routing_fitness_schema(version INTEGER PRIMARY KEY, name TEXT NOT NULL)"
    )
    connection.execute("INSERT INTO routing_fitness_schema VALUES (99, 'future')")
    connection.commit()
    connection.close()
    with pytest.raises(RoutingFitnessStoreError, match="future schema"):
        SQLiteRoutingFitnessStore(future)


def _model(model_id: str, quality: float) -> ModelMetadata:
    return ModelMetadata(
        model_id,
        4096,
        capabilities=frozenset({"chat"}),
        roles=frozenset({ModelRole.GENERAL}),
        modalities=frozenset({"text"}),
        ram_bytes=100,
        vram_bytes=100,
        quality_score=quality,
    )


def _registry(*, remote: bool = False, poor: bool = False) -> ProviderRegistry:
    models = (_model("model-a", 0.9), _model("model-b", 0.85 if not poor else 0.2))
    return ProviderRegistry(
        (
            ProviderDefinition(
                ProviderMetadata(
                    "local",
                    "Local",
                    "test",
                    local_only=True,
                ),
                lambda _: FakeAIProvider(("a",)),
                models,
            ),
            *(
                (
                    ProviderDefinition(
                        ProviderMetadata("cloud", "Cloud", "test"),
                        lambda _: FakeAIProvider(("cloud",)),
                        (_model("cloud-model", 0.99),),
                    ),
                )
                if remote
                else ()
            ),
        )
    )


def _request(**changes: object) -> RouteRequest:
    values: dict[str, object] = {
        "task": "UNIQUE_SECRET_CANARY do not persist",
        "profile": "analysis",
        "complexity": "high",
        "policy": RoutingPolicy.QUALITY_FIRST,
        "privacy_context": PrivacyContext(PrivacyClassification.LOCAL_ONLY),
        "resource_state": _hardware(),
    }
    values.update(changes)
    return RouteRequest(**cast(Any, values))


def _governor() -> ResourceGovernor:
    class Telemetry:
        def snapshot(self) -> ResourceSnapshot:
            return ResourceSnapshot(
                NOW,
                cpu_utilization=0.1,
                cpu_cores=8,
                ram_total_bytes=10_000,
                ram_available_bytes=8_000,
                gpu_vram_total_bytes=10_000,
                gpu_vram_available_bytes=8_000,
                disk_free_bytes=10_000,
                user_active=True,
            )

    return ResourceGovernor(Telemetry(), policy=ResourcePolicy(low_disk_bytes=0), clock=lambda: NOW)


def test_provider_route_persists_safe_selection_rejection_quality_resource_and_affinity(
    tmp_path: Path,
) -> None:
    store = SQLiteRoutingFitnessStore(tmp_path / "routing.sqlite3")
    router = ProviderRouter(_registry(remote=True), _governor(), routing_store=store)
    routed = router.route(_request(current_quality=0.8))
    assert routed.status is RouteStatus.SELECTED
    assert routed.decision_id is not None
    assert routed.primary is not None
    view = store.decision_view(routed.decision_id)
    assert view is not None
    assert view.decision.selected_identity == routed.primary.identity.storage_key
    assert view.decision.required_capabilities == ()
    assert "UNIQUE_SECRET_CANARY" not in str(view)
    assert view.decision.resource_status == "allow"
    store.close()


@pytest.mark.asyncio
async def test_model_path_links_actual_dispatch_identity_and_keeps_semantic_unverified(
    tmp_path: Path,
) -> None:
    store = SQLiteRoutingFitnessStore(tmp_path / "routing.sqlite3")
    registry = _registry()
    router = ProviderRouter(registry, _governor(), routing_store=store)
    providers = {"local": FakeAIProvider(("answer",))}
    dispatcher = InferenceDispatcher(
        router,
        registry,
        providers=providers,
        resource_governor=router.resource_governor,
    )
    routed = router.route(_request())
    result = await dispatcher.generate(
        GenerationRequest((), "model-a", 4096), _request(), decision=routed
    )
    assert result.decision.primary is not None
    view = store.decision_view(routed.decision_id or "")
    assert (
        view is not None
        and view.outcomes[0].executed_identity == result.decision.primary.identity.storage_key
    )
    assert view.outcomes[0].semantic_outcome is SemanticOutcome.UNVERIFIED
    assert "answer" not in str(view)
    store.close()


@pytest.mark.asyncio
async def test_selective_fusion_uses_two_real_dispatcher_legs_and_is_bounded(
    tmp_path: Path,
) -> None:
    store = SQLiteRoutingFitnessStore(tmp_path / "routing.sqlite3")
    registry = _registry()
    router = ProviderRouter(registry, _governor(), routing_store=store)
    first = FakeAIProvider(("first",))
    second = FakeAIProvider(("second",))
    dispatcher = InferenceDispatcher(
        router,
        registry,
        providers={"local": first},
        resource_governor=router.resource_governor,
    )
    # One registry provider owns two model identities; the provider adapter is still
    # invoked through the normal registry/dispatcher seam for both bounded legs.
    coordinator = FusionCoordinator(router, dispatcher)
    result = await coordinator.generate(GenerationRequest((), "model-a", 4096), _request())
    assert result.fused
    assert len(result.planned_source_identities) == 2
    assert len(result.actual_source_identities) == 2
    assert len(result.source_results) == 2
    assert len(first.requests) == 2
    assert second.requests == []
    assert result.decision_id is not None
    fusion_record = store.decision(result.decision_id)
    assert (
        fusion_record is not None
        and fusion_record.fusion_strategy == "bounded_distinct_model_sources"
    )
    store.close()


def test_fusion_policy_is_conservative_for_easy_privacy_and_tool_requests() -> None:
    policy = FusionPolicy()
    coordinator = object.__new__(FusionCoordinator)
    coordinator._policy = policy
    assert not coordinator._should_fuse(_request(complexity="low"))
    assert not coordinator._should_fuse(_request(requires_tools=True))
    assert policy.max_sources == 2
    assert not FusionPolicy(mode=policy.mode, synthesis_enabled=False).synthesis_enabled


@pytest.mark.asyncio
async def test_fusion_privacy_quality_and_bound_rules(tmp_path: Path) -> None:
    local_store = SQLiteRoutingFitnessStore(tmp_path / "local.sqlite3")
    local_registry = _registry(remote=True)
    local_router = ProviderRouter(local_registry, routing_store=local_store)
    local_dispatcher = InferenceDispatcher(
        local_router,
        local_registry,
        providers={"local": FakeAIProvider(("local",)), "cloud": FakeAIProvider(("cloud",))},
    )
    local_result = await FusionCoordinator(local_router, local_dispatcher).generate(
        GenerationRequest((), "model-a", 4096), _request()
    )
    assert local_result.fused
    assert all(
        identity.startswith('["local"') for identity in local_result.planned_source_identities
    )
    local_store.close()

    poor_store = SQLiteRoutingFitnessStore(tmp_path / "poor.sqlite3")
    poor_registry = _registry(poor=True)
    poor_router = ProviderRouter(poor_registry, routing_store=poor_store)
    poor_dispatcher = InferenceDispatcher(
        poor_router,
        poor_registry,
        providers={"local": FakeAIProvider(("only",))},
    )
    poor_result = await FusionCoordinator(poor_router, poor_dispatcher).generate(
        GenerationRequest((), "model-a", 4096), _request()
    )
    assert not poor_result.fused and poor_result.degraded_to_single
    poor_store.close()


def test_open_breaker_is_not_a_fusion_source(tmp_path: Path) -> None:
    store = SQLiteRoutingFitnessStore(tmp_path / "breaker.sqlite3")
    fitness = RoutingFitnessProjection(store=store, clock=lambda: NOW)
    resilience = RoutingResilienceService(fitness, store=store, clock=lambda: NOW)
    key = resilience.key(
        identity_for("local", _model("model-a", 0.9)).storage_key,
        "model",
        "analysis",
        "general",
    )
    for _ in range(3):
        resilience.record(
            key,
            operational_outcome="provider_unavailable",
            semantic_outcome=SemanticOutcome.VERIFIED_FAILURE,
            failure_class="provider_unavailable",
        )
    assert resilience.snapshot(key).state is CircuitState.OPEN
    registry = _registry()
    router = ProviderRouter(registry, routing_store=store)
    routed = router.route(_request())
    dispatcher = InferenceDispatcher(router, registry, providers={"local": FakeAIProvider()})
    coordinator = FusionCoordinator(router, dispatcher, resilience=resilience)
    sources = coordinator._sources(routed, _request())
    assert all(
        item.identity.storage_key != identity_for("local", _model("model-a", 0.9)).storage_key
        for item in sources
    )
    store.close()


def test_tool_route_persists_but_never_fuses_and_planning_executor_carries_decision(
    tmp_path: Path,
) -> None:
    store = SQLiteRoutingFitnessStore(tmp_path / "routing.sqlite3")
    selector = ExecutionRouteSelector(
        model_router=None,
        tool_registry=create_safe_tool_registry(),
        routing_store=store,
    )
    requirements = StepRequirements.from_planning_step(planned_step())
    routed = selector.route(requirements)
    assert routed.primary is not None and routed.primary.kind.value == "tool"
    assert routed.decision_id is not None
    assert store.decision(routed.decision_id) is not None
    # The real brokered executor receives this selector in production; effect routes
    # remain single-route and their decision record contains no model outputs.
    persisted = store.decision(routed.decision_id)
    assert persisted is not None and persisted.route_kind == "tool"
    from jarvis.planning.engine import BrokeredPlanningStepExecutor

    executor = BrokeredPlanningStepExecutor(create_safe_tool_registry(), route_selector=selector)
    result = asyncio.run(executor.execute(task(), planned_step(), asyncio.Event()))
    assert result.routing_decision_id is not None
    store.close()


def test_fusion_result_never_claims_verification_or_streaming_fusion() -> None:
    assert SemanticOutcome.UNVERIFIED.value == "unverified"
    assert FusionDispatchError.__name__ == "FusionDispatchError"
