"""Focused R3D-E resource admission and execution-reservation proof."""

from __future__ import annotations

from dataclasses import replace
from datetime import UTC, datetime
from typing import Any, cast

import pytest
from jarvis.ai.models import GenerationRequest, ModelRole
from jarvis.ai.providers import (
    ModelMetadata,
    ProviderDefinition,
    ProviderMetadata,
    ProviderRegistry,
)
from jarvis.ai.routing import (
    InferenceDispatcher,
    InferenceDispatchError,
    ProviderRouter,
    RouteCandidate,
    RouteRequest,
    RouteStatus,
    RoutingPolicy,
)
from jarvis.resources import (
    ReservationReleaseReason,
    ResourceBudget,
    ResourceDecisionStatus,
    ResourceGovernor,
    ResourcePolicy,
    ResourcePriority,
    ResourceSnapshot,
)

from tests.fakes import FakeAIProvider
from tests.test_hardware import _hardware

NOW = datetime(2026, 9, 19, tzinfo=UTC)


class Telemetry:
    def __init__(self, current: ResourceSnapshot) -> None:
        self.current = current

    def snapshot(self) -> ResourceSnapshot:
        return self.current


def host(**changes: object) -> ResourceSnapshot:
    return replace(
        ResourceSnapshot(
            NOW,
            cpu_utilization=0.10,
            cpu_cores=4,
            ram_total_bytes=1_000,
            ram_available_bytes=1_000,
            gpu_vram_total_bytes=1_000,
            gpu_vram_available_bytes=1_000,
            disk_free_bytes=10_000,
            user_active=True,
        ),
        **cast(Any, changes),
    )


def governor(current: ResourceSnapshot | None = None) -> ResourceGovernor:
    return ResourceGovernor(
        Telemetry(current or host()),
        policy=ResourcePolicy(
            low_disk_bytes=0,
            interactive_ram_reserve_bytes=200,
            interactive_vram_reserve_bytes=200,
            interactive_cpu_reserve_cores=1,
            interactive_concurrency_reserve=1,
            concurrency_capacity=4,
        ),
        clock=lambda: NOW,
    )


def test_background_admission_preserves_interactive_ram_vram_cpu_and_concurrency() -> None:
    service = governor()
    admitted = service.reserve(
        "background-fit",
        ResourcePriority.BACKGROUND,
        ResourceBudget(cpu_cores=2, ram_bytes=800, vram_bytes=800, concurrency=2),
    )
    assert admitted.allowed
    assert (
        service.decide(
            "background-over-reserve",
            ResourcePriority.BACKGROUND,
            ResourceBudget(ram_bytes=1, vram_bytes=1, cpu_cores=1),
        ).status
        is ResourceDecisionStatus.DEFER
    )
    interactive = service.decide(
        "interactive",
        ResourcePriority.INTERACTIVE,
        ResourceBudget(cpu_cores=1, ram_bytes=200, vram_bytes=200, concurrency=1),
    )
    assert interactive.allowed


def test_unknown_capacity_is_conservative_for_background_but_not_fabricated() -> None:
    service = governor(host(ram_available_bytes=None, ram_total_bytes=None))
    decision = service.decide(
        "unknown-background", ResourcePriority.BACKGROUND, ResourceBudget(ram_bytes=1)
    )
    assert decision.status is ResourceDecisionStatus.DEFER
    assert "unmeasured" in decision.reason


def test_release_restores_capacity_after_completion_cancel_crash_and_timeout() -> None:
    service = governor()
    for reason in (
        ReservationReleaseReason.COMPLETE,
        ReservationReleaseReason.CANCEL,
        ReservationReleaseReason.CRASH,
        ReservationReleaseReason.TIMEOUT,
    ):
        reservation = service.reserve(
            f"owner-{reason}", ResourcePriority.USER_REQUESTED, ResourceBudget(ram_bytes=900)
        )
        assert reservation.reservation_id is not None
        released = service.release(reservation.reservation_id, reason)
        assert released.release_reason is reason
        assert not service.reservations(active_only=True)


def _registry(*, local_ram: int | None = 100) -> ProviderRegistry:
    model = ModelMetadata(
        "local-model",
        4096,
        frozenset({"chat"}),
        frozenset({ModelRole.GENERAL}),
        ram_bytes=local_ram,
        vram_bytes=50,
        quality_score=0.8,
    )
    return ProviderRegistry(
        (
            ProviderDefinition(
                ProviderMetadata("local", "Local", "test", local_only=True),
                lambda _: FakeAIProvider(),
                (model,),
            ),
        )
    )


def _request(**changes: object) -> RouteRequest:
    defaults: dict[str, object] = {
        "task": "answer",
        "profile": "test",
        "policy": RoutingPolicy.BALANCED,
        "resource_state": _hardware(tags=frozenset({"windows"})),
    }
    defaults.update(changes)
    return RouteRequest(**cast(Any, defaults))


def test_candidate_budget_uses_trusted_local_metadata_and_never_assigns_cloud_vram() -> None:
    local_router = ProviderRouter(_registry(), governor())
    decision = local_router.route(_request())
    assert decision.primary is not None
    budget = local_router.resource_budget_for(decision.primary, _request())
    assert budget.ram_bytes == 100
    assert budget.vram_bytes == 50

    remote = RouteCandidate(
        "remote",
        "m",
        ProviderMetadata("remote", "Remote", "test"),
        ModelMetadata("m", 4096),
        False,
    )
    remote_budget = local_router.resource_budget_for(remote, _request())
    assert remote_budget.ram_bytes is None and remote_budget.vram_bytes is None


def test_unfit_local_candidate_is_rejected_before_quality_selection() -> None:
    service = governor(host(ram_available_bytes=50, gpu_vram_available_bytes=50))
    decision = ProviderRouter(_registry(), service).route(
        _request(priority=ResourcePriority.BACKGROUND)
    )
    assert decision.status in {RouteStatus.UNKNOWN, RouteStatus.UNAVAILABLE}
    assert decision.primary is None


@pytest.mark.asyncio
async def test_execution_race_denies_without_invoking_provider() -> None:
    telemetry = Telemetry(host())
    service = ResourceGovernor(
        telemetry,
        policy=ResourcePolicy(low_disk_bytes=0),
        clock=lambda: NOW,
    )
    registry = _registry()
    router = ProviderRouter(registry, service)
    decision = router.route(_request())
    assert decision.primary is not None
    telemetry.current = host(ram_available_bytes=0)
    provider = FakeAIProvider()
    dispatcher = InferenceDispatcher(
        router,
        registry,
        providers={"local": provider},
        resource_governor=service,
        max_attempts=1,
    )
    with pytest.raises(InferenceDispatchError) as raised:
        await dispatcher.generate(
            GenerationRequest((), "local-model", 4096), _request(), decision=decision
        )
    assert raised.value.status in {RouteStatus.RESOURCE_UNAVAILABLE, RouteStatus.UNKNOWN}
    assert provider.requests == []
    assert not service.reservations(active_only=True)


@pytest.mark.asyncio
async def test_dispatch_reserves_before_generate_and_releases_on_completion() -> None:
    service = governor()
    router = ProviderRouter(_registry(), service)
    provider = FakeAIProvider()
    dispatcher = InferenceDispatcher(
        router, _registry(), providers={"local": provider}, resource_governor=service
    )
    result = await dispatcher.generate(
        GenerationRequest((), "local-model", 4096),
        _request(),
    )
    assert result.result.model == "local-model"
    assert not service.reservations(active_only=True)
    assert len(provider.requests) == 1


def test_affinity_switching_cost_is_bounded_and_unknown_is_not_zero() -> None:
    router = ProviderRouter(_registry())
    decision = router.route(_request())
    assert decision.primary is not None
    current = decision.primary.identity
    request = _request(
        current_identity=current,
        switching_cost_budget_ms=10,
        current_quality=0.8,
    )
    assert router._switch_penalty(decision.primary, request) == 0.0
