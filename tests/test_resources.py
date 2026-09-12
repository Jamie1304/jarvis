"""Deterministic system-wide resource admission tests."""

from __future__ import annotations

from dataclasses import replace
from datetime import UTC, datetime, timedelta
from typing import Any, cast
from uuid import uuid4

import pytest
from jarvis import resources as resources_module
from jarvis.resources import (
    ReservationReleaseReason,
    ReservationStatus,
    ResourceBudget,
    ResourceDecision,
    ResourceDecisionStatus,
    ResourceGovernor,
    ResourcePolicy,
    ResourcePriority,
    ResourceReservation,
    ResourceSnapshot,
    ResourceValidationError,
    SystemResourceTelemetry,
)

NOW = datetime(2026, 1, 1, tzinfo=UTC)


class FakeTelemetry:
    def __init__(self, snapshot: ResourceSnapshot) -> None:
        self.current = snapshot

    def snapshot(self) -> ResourceSnapshot:
        return self.current


def snapshot(**changes: object) -> ResourceSnapshot:
    base = ResourceSnapshot(
        observed_at=NOW,
        cpu_utilization=0.10,
        cpu_cores=8,
        ram_total_bytes=16_000,
        ram_available_bytes=12_000,
        gpu_vram_total_bytes=8_000,
        gpu_vram_available_bytes=6_000,
        disk_free_bytes=20_000,
        on_ac_power=True,
        battery_level=0.9,
        user_idle_seconds=1.0,
        user_active=True,
        heavy_foreground_workload=False,
    )
    return replace(base, **cast(Any, changes))


def make_governor(
    current: ResourceSnapshot | None = None,
) -> tuple[ResourceGovernor, FakeTelemetry]:
    telemetry = FakeTelemetry(current or snapshot())
    return ResourceGovernor(telemetry, clock=lambda: NOW), telemetry


def test_snapshot_rejects_malformed_or_inconsistent_telemetry() -> None:
    with pytest.raises(ResourceValidationError):
        ResourceSnapshot(NOW, battery_level=1.1)
    with pytest.raises(ResourceValidationError):
        ResourceSnapshot(NOW, ram_total_bytes=1, ram_available_bytes=2)
    with pytest.raises(ResourceValidationError):
        ResourceBudget(concurrency=0)
    with pytest.raises(ResourceValidationError):
        ResourcePolicy(pressure_concurrency=0)


@pytest.mark.parametrize(
    ("factory", "value"),
    (
        (lambda value: ResourceSnapshot(NOW, cpu_utilization=value), True),
        (lambda value: ResourceSnapshot(NOW, cpu_utilization=value), -0.1),
        (lambda value: ResourceSnapshot(NOW, cpu_cores=value), -1),
        (lambda value: ResourceSnapshot(NOW, disk_free_bytes=value), 1.5),
        (lambda value: ResourceSnapshot(NOW, on_ac_power=value), "yes"),
        (lambda value: ResourceBudget(ram_bytes=value), -1),
        (lambda value: ResourceBudget(network_bytes=value), 1.5),
        (lambda value: ResourceBudget(duration_seconds=value), 0),
        (lambda value: ResourcePolicy(cpu_pressure_threshold=value), 2.0),
        (lambda value: ResourcePolicy(defer_indexing_under_pressure=value), 1),
    ),
)
def test_resource_validation_rejects_invalid_values(factory: Any, value: object) -> None:
    with pytest.raises(ResourceValidationError):
        factory(value)


def test_resource_properties_and_budget_reduction_are_bounded() -> None:
    with pytest.raises(ResourceValidationError):
        ResourceBudget(concurrency=2).with_concurrency(3)
    with pytest.raises(ResourceValidationError):
        ResourceBudget(concurrency=2).with_concurrency(0)


def test_resource_reservation_and_decision_metadata_fail_closed() -> None:
    budget = ResourceBudget()
    with pytest.raises(ResourceValidationError):
        ResourceReservation(uuid4(), "owner", ResourcePriority.USER_REQUESTED, budget, NOW, NOW)
    with pytest.raises(ResourceValidationError):
        ResourceReservation(
            uuid4(),
            "owner",
            ResourcePriority.USER_REQUESTED,
            budget,
            NOW,
            NOW + timedelta(seconds=1),
            ReservationStatus.COMPLETED,
        )
    with pytest.raises(ResourceValidationError):
        ResourceDecision(
            uuid4(),
            "owner",
            ResourcePriority.USER_REQUESTED,
            ResourceDecisionStatus.ALLOW,
            budget,
            budget,
            snapshot(),
            "ok",
            reservation_id="forged",  # type: ignore[arg-type]
        )


def test_remaining_metadata_and_timestamp_validation_is_strict() -> None:
    with pytest.raises(ResourceValidationError):
        ResourceSnapshot("bad")  # type: ignore[arg-type]
    with pytest.raises(ResourceValidationError):
        ResourceSnapshot(NOW.replace(tzinfo=None))
    with pytest.raises(ResourceValidationError):
        ResourceSnapshot(NOW, gpu_vram_total_bytes=1, gpu_vram_available_bytes=2)
    with pytest.raises(ResourceValidationError):
        ResourcePolicy(low_disk_bytes=-1)
    with pytest.raises(ResourceValidationError):
        ResourceReservation(
            "bad",  # type: ignore[arg-type]
            "owner",
            ResourcePriority.USER_REQUESTED,
            ResourceBudget(),
            NOW,
            NOW,
        )
    with pytest.raises(ResourceValidationError):
        ResourceReservation(uuid4(), "owner", ResourcePriority.USER_REQUESTED, object(), NOW, NOW)  # type: ignore[arg-type]
    with pytest.raises(ResourceValidationError):
        ResourceReservation(
            uuid4(),
            "owner",
            ResourcePriority.USER_REQUESTED,
            ResourceBudget(),
            NOW.replace(tzinfo=None),
            NOW + timedelta(seconds=1),
        )
    with pytest.raises(ResourceValidationError):
        ResourceReservation(
            uuid4(),
            "owner",
            ResourcePriority.USER_REQUESTED,
            ResourceBudget(),
            NOW,
            NOW + timedelta(seconds=1),
            ReservationStatus.ACTIVE,
            NOW,
            ReservationReleaseReason.COMPLETE,
        )
    with pytest.raises(ResourceValidationError):
        ResourceReservation(
            uuid4(),
            "owner",
            ResourcePriority.USER_REQUESTED,
            ResourceBudget(),
            NOW,
            NOW + timedelta(seconds=1),
            "bad",  # type: ignore[arg-type]
            NOW,
            ReservationReleaseReason.COMPLETE,
        )
    with pytest.raises(ResourceValidationError):
        ResourceDecision(
            uuid4(),
            "owner",
            ResourcePriority.USER_REQUESTED,
            ResourceDecisionStatus.ALLOW,
            ResourceBudget(),
            ResourceBudget(),
            object(),  # type: ignore[arg-type]
            "ok",
        )
    with pytest.raises(ResourceValidationError):
        ResourceDecision(
            uuid4(),
            "owner",
            "bad",  # type: ignore[arg-type]
            ResourceDecisionStatus.ALLOW,
            ResourceBudget(),
            ResourceBudget(),
            snapshot(),
            "ok",
        )
    with pytest.raises(ResourceValidationError):
        ResourceDecision(
            uuid4(),
            "owner",
            ResourcePriority.USER_REQUESTED,
            ResourceDecisionStatus.ALLOW,
            object(),  # type: ignore[arg-type]
            ResourceBudget(),
            snapshot(),
            "ok",
        )
    with pytest.raises(ResourceValidationError):
        ResourceDecision(
            uuid4(),
            "owner",
            ResourcePriority.USER_REQUESTED,
            ResourceDecisionStatus.ALLOW,
            ResourceBudget(),
            ResourceBudget(),
            snapshot(),
            "ok",
            max_concurrency=0,
        )
    with pytest.raises(ResourceValidationError):
        ResourceDecision(
            uuid4(),
            "owner",
            ResourcePriority.USER_REQUESTED,
            ResourceDecisionStatus.ALLOW,
            ResourceBudget(),
            ResourceBudget(),
            snapshot(),
            "ok",
            max_concurrency=True,
        )
    with pytest.raises(ResourceValidationError):
        ResourceDecision(
            uuid4(),
            "owner",
            ResourcePriority.USER_REQUESTED,
            ResourceDecisionStatus.ALLOW,
            ResourceBudget(),
            ResourceBudget(),
            snapshot(),
            "ok",
            unload_cold_models=1,  # type: ignore[arg-type]
        )


def test_governor_rejects_bad_telemetry_requests_and_unknown_releases() -> None:
    class BadTelemetry:
        def snapshot(self) -> object:
            return object()

    with pytest.raises(ResourceValidationError):
        ResourceGovernor(object())  # type: ignore[arg-type]
    with pytest.raises(ResourceValidationError):
        ResourceGovernor(FakeTelemetry(snapshot()), policy=object())  # type: ignore[arg-type]
    bad = ResourceGovernor(BadTelemetry())  # type: ignore[arg-type]
    with pytest.raises(ResourceValidationError):
        bad.snapshot()
    good, _ = make_governor()
    with pytest.raises(ResourceValidationError):
        good.decide("", ResourcePriority.USER_REQUESTED, ResourceBudget())
    with pytest.raises(ResourceValidationError):
        good.decide("owner", "bad", ResourceBudget())  # type: ignore[arg-type]
    with pytest.raises(ResourceValidationError):
        good.reserve("owner", "bad", ResourceBudget())  # type: ignore[arg-type]
    with pytest.raises(ResourceValidationError):
        good.release("bad", ReservationReleaseReason.COMPLETE)  # type: ignore[arg-type]
    with pytest.raises(ResourceValidationError):
        good.release(uuid4(), "bad")  # type: ignore[arg-type]
    with pytest.raises(ResourceValidationError):
        good.release(uuid4(), ReservationReleaseReason.COMPLETE)
    assert good.inspect(uuid4()) is None
    assert good.policy.max_background_concurrency == 2


def test_priorities_defer_background_work_without_cancelling_foreground() -> None:
    governor, _ = make_governor(snapshot(cpu_utilization=0.99, heavy_foreground_workload=True))
    foreground = governor.reserve(
        "task.foreground",
        ResourcePriority.INTERACTIVE,
        ResourceBudget(ram_bytes=1000),
    )
    assert foreground.allowed
    foreground_reservation_id = foreground.reservation_id
    assert foreground_reservation_id is not None
    background = governor.decide(
        "research.background",
        ResourcePriority.BACKGROUND,
        ResourceBudget(concurrency=1),
    )
    assert background.status is ResourceDecisionStatus.DEFER
    assert governor.inspect(foreground_reservation_id) is not None


def test_battery_benchmark_and_pressure_indexing_are_deferred() -> None:
    governor, _ = make_governor(
        snapshot(
            on_ac_power=False,
            battery_level=0.5,
            ram_available_bytes=1_000,
            heavy_foreground_workload=False,
        )
    )
    benchmark = governor.decide("model.benchmark", ResourcePriority.BENCHMARK, ResourceBudget())
    indexing = governor.decide("knowledge", ResourcePriority.INDEXING, ResourceBudget())
    assert benchmark.status is ResourceDecisionStatus.DEFER
    assert indexing.status is ResourceDecisionStatus.DEFER


def test_low_disk_and_unknown_capacity_fail_closed_for_background() -> None:
    low_disk, _ = make_governor(snapshot(disk_free_bytes=500))
    download = low_disk.decide(
        "model.download",
        ResourcePriority.BACKGROUND,
        ResourceBudget(disk_bytes=600),
    )
    assert download.status is ResourceDecisionStatus.DEFER
    unknown, _ = make_governor(snapshot(ram_available_bytes=None, ram_total_bytes=None))
    decision = unknown.decide(
        "background.model", ResourcePriority.BACKGROUND, ResourceBudget(ram_bytes=1)
    )
    assert decision.status is ResourceDecisionStatus.DEFER


def test_disk_and_capacity_limits_cover_interactive_and_active_reservations() -> None:
    interactive_governor = ResourceGovernor(
        FakeTelemetry(snapshot(disk_free_bytes=100)),
        policy=ResourcePolicy(low_disk_bytes=1_000, large_download_bytes=50),
    )
    interactive = interactive_governor.decide(
        "download.interactive",
        ResourcePriority.INTERACTIVE,
        ResourceBudget(disk_bytes=80),
    )
    assert interactive.status is ResourceDecisionStatus.REDUCE
    governor = ResourceGovernor(
        FakeTelemetry(snapshot(disk_free_bytes=100)),
        policy=ResourcePolicy(low_disk_bytes=1_000, large_download_bytes=1_000),
    )
    first = governor.reserve(
        "first", ResourcePriority.USER_REQUESTED, ResourceBudget(disk_bytes=50)
    )
    assert first.allowed
    second = governor.decide(
        "second", ResourcePriority.USER_REQUESTED, ResourceBudget(disk_bytes=60)
    )
    assert second.status is ResourceDecisionStatus.DENY
    capacity, _ = make_governor(snapshot(ram_available_bytes=10, gpu_vram_available_bytes=10))
    held = capacity.reserve(
        "held",
        ResourcePriority.USER_REQUESTED,
        ResourceBudget(ram_bytes=8, vram_bytes=8, cpu_cores=7),
    )
    assert held.allowed
    assert (
        capacity.decide("ram", ResourcePriority.USER_REQUESTED, ResourceBudget(ram_bytes=3)).status
        is ResourceDecisionStatus.DENY
    )
    assert (
        capacity.decide(
            "vram", ResourcePriority.USER_REQUESTED, ResourceBudget(vram_bytes=3)
        ).status
        is ResourceDecisionStatus.DENY
    )
    assert (
        capacity.decide("cpu", ResourcePriority.USER_REQUESTED, ResourceBudget(cpu_cores=2)).status
        is ResourceDecisionStatus.DENY
    )


def test_unknown_gpu_and_disk_capacity_are_deferred_for_background() -> None:
    governor, _ = make_governor(snapshot(gpu_vram_available_bytes=None, disk_free_bytes=None))
    assert (
        governor.decide("gpu", ResourcePriority.BACKGROUND, ResourceBudget(vram_bytes=1)).status
        is ResourceDecisionStatus.DEFER
    )
    assert (
        governor.decide("disk", ResourcePriority.BACKGROUND, ResourceBudget(disk_bytes=1)).status
        is ResourceDecisionStatus.DEFER
    )


def test_pressure_reduces_concurrency_and_signals_model_degradation() -> None:
    governor, _ = make_governor(snapshot(ram_available_bytes=1_000))
    decision = governor.decide(
        "model.route",
        ResourcePriority.USER_REQUESTED,
        ResourceBudget(concurrency=4),
    )
    assert decision.status is ResourceDecisionStatus.REDUCE
    assert decision.effective_budget.concurrency == 1
    assert decision.unload_cold_models
    assert decision.choose_smaller_model


def test_reservation_accounting_and_all_terminal_release_paths() -> None:
    governor, _ = make_governor()
    reservations = []
    for reason, expected in (
        (ReservationReleaseReason.COMPLETE, ReservationStatus.COMPLETED),
        (ReservationReleaseReason.CANCEL, ReservationStatus.CANCELLED),
        (ReservationReleaseReason.CRASH, ReservationStatus.CRASHED),
        (ReservationReleaseReason.TIMEOUT, ReservationStatus.TIMED_OUT),
    ):
        decision = governor.reserve("worker", ResourcePriority.USER_REQUESTED, ResourceBudget())
        assert decision.reservation_id is not None
        reservations.append(decision.reservation_id)
        released = governor.release(decision.reservation_id, reason)
        assert released.status is expected
        assert governor.release(decision.reservation_id, reason) == released
    assert len(governor.reservations()) == len(reservations)


def test_expiry_releases_capacity_as_timeout() -> None:
    now = [NOW]
    governor = ResourceGovernor(FakeTelemetry(snapshot()), clock=lambda: now[0])
    decision = governor.reserve(
        "short", ResourcePriority.USER_REQUESTED, ResourceBudget(duration_seconds=1)
    )
    assert decision.reservation_id is not None
    now[0] = NOW + timedelta(seconds=2)
    expired = governor.expire()
    assert expired[0].status is ReservationStatus.TIMED_OUT
    assert not governor.reservations(active_only=True)
    assert governor.expire() == ()


def test_system_probe_preserves_unknown_optional_fields_and_uses_injected_probes() -> None:
    telemetry = SystemResourceTelemetry(
        clock=lambda: NOW,
        cpu_probe=lambda: None,
        idle_probe=lambda: 5.0,
        foreground_probe=lambda: True,
    )
    observed = telemetry.snapshot()
    assert observed.observed_at == NOW
    assert observed.cpu_utilization is None
    assert observed.user_idle_seconds == 5.0
    assert observed.heavy_foreground_workload is True


def test_optional_native_probe_fallbacks_preserve_unknown_values(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    private = cast(Any, resources_module)
    monkeypatch.setattr(private.os, "name", "posix")
    assert resources_module._battery_probe() == (None, None)
    assert resources_module._idle_probe() is None
    monkeypatch.setattr(private.os, "getloadavg", None, raising=False)
    assert resources_module._cpu_probe() is None
    assert resources_module._memory_probe()[0] is None or isinstance(
        resources_module._memory_probe()[0], int
    )


def test_policy_can_explicitly_allow_battery_benchmark() -> None:
    governor = ResourceGovernor(
        FakeTelemetry(snapshot(on_ac_power=False, battery_level=0.5)),
        policy=ResourcePolicy(benchmark_on_battery=True),
    )
    assert (
        governor.decide("benchmark", ResourcePriority.BENCHMARK, ResourceBudget()).status
        is ResourceDecisionStatus.ALLOW
    )


def test_low_priority_concurrency_reduction_and_disabled_pressure_policies() -> None:
    calm = snapshot(disk_free_bytes=10_000_000_000)
    governor = ResourceGovernor(
        FakeTelemetry(calm), policy=ResourcePolicy(max_background_concurrency=2)
    )
    reduced = governor.decide(
        "background", ResourcePriority.BACKGROUND, ResourceBudget(concurrency=4)
    )
    assert reduced.status is ResourceDecisionStatus.REDUCE
    assert reduced.effective_budget.concurrency == 2
    policy = ResourcePolicy(
        low_disk_bytes=0,
        defer_indexing_under_pressure=False,
        defer_background_under_pressure=False,
        unload_cold_models_on_pressure=False,
        choose_smaller_model_on_pressure=False,
    )
    pressured = ResourceGovernor(
        FakeTelemetry(snapshot(disk_free_bytes=1, cpu_utilization=0.99)), policy=policy
    )
    decision = pressured.decide("index", ResourcePriority.INDEXING, ResourceBudget(concurrency=1))
    assert decision.status is ResourceDecisionStatus.ALLOW
    assert not decision.unload_cold_models
    assert not decision.choose_smaller_model
