"""One deterministic process-wide resource admission and reservation service.

The governor is deliberately conservative: unavailable telemetry remains unknown,
and unknown capacity never becomes permission to perform a large background
operation.  It owns admission policy only; task, model, sandbox, and indexing
services retain ownership of their domain state.
"""

from __future__ import annotations

import ctypes
import ctypes.wintypes as wintypes
import math
import os
import shutil
import threading
from collections.abc import Callable
from dataclasses import dataclass, replace
from datetime import UTC, datetime, timedelta
from enum import StrEnum
from typing import Protocol, cast
from uuid import UUID, uuid4


class ResourceValidationError(ValueError):
    """Resource telemetry, policy, or reservation metadata is malformed."""


class ResourcePriority(StrEnum):
    INTERACTIVE = "interactive"
    USER_REQUESTED = "user_requested"
    BACKGROUND = "background"
    MAINTENANCE = "maintenance"
    BENCHMARK = "benchmark"
    INDEXING = "indexing"


class ResourceDecisionStatus(StrEnum):
    ALLOW = "allow"
    REDUCE = "reduce"
    DEFER = "defer"
    DENY = "deny"


class ReservationStatus(StrEnum):
    ACTIVE = "active"
    COMPLETED = "completed"
    CANCELLED = "cancelled"
    CRASHED = "crashed"
    TIMED_OUT = "timed_out"


class ReservationReleaseReason(StrEnum):
    COMPLETE = "complete"
    CANCEL = "cancel"
    CRASH = "crash"
    TIMEOUT = "timeout"


def _finite_optional(value: object, field: str, *, minimum: float = 0.0) -> None:
    if value is not None and (
        type(value) not in {int, float}
        or isinstance(value, bool)
        or not math.isfinite(float(cast(int | float, value)))
        or float(cast(int | float, value)) < minimum
    ):
        raise ResourceValidationError(f"{field} is invalid")


def _ratio_optional(value: object, field: str) -> None:
    _finite_optional(value, field, minimum=0.0)
    if value is not None and float(cast(int | float, value)) > 1.0:
        raise ResourceValidationError(f"{field} must be between zero and one")


def _bounded_text(value: object, field: str, limit: int = 256) -> str:
    if type(value) is not str or not value.strip() or len(value) > limit or "\x00" in value:
        raise ResourceValidationError(f"{field} is invalid")
    return value


def _optional_bool(value: object, field: str) -> None:
    if value is not None and type(value) is not bool:
        raise ResourceValidationError(f"{field} is invalid")


@dataclass(frozen=True, slots=True)
class ResourceSnapshot:
    """A point-in-time telemetry observation; ``None`` means unmeasured."""

    observed_at: datetime
    cpu_utilization: float | None = None
    cpu_cores: int | None = None
    ram_total_bytes: int | None = None
    ram_available_bytes: int | None = None
    gpu_vram_total_bytes: int | None = None
    gpu_vram_available_bytes: int | None = None
    disk_free_bytes: int | None = None
    on_ac_power: bool | None = None
    battery_level: float | None = None
    user_idle_seconds: float | None = None
    user_active: bool | None = None
    heavy_foreground_workload: bool | None = None

    def __post_init__(self) -> None:
        if not isinstance(self.observed_at, datetime) or self.observed_at.tzinfo is None:
            raise ResourceValidationError("Resource timestamp must be timezone-aware")
        _ratio_optional(self.cpu_utilization, "CPU utilization")
        for value, field in (
            (self.cpu_cores, "CPU cores"),
            (self.ram_total_bytes, "RAM total"),
            (self.ram_available_bytes, "RAM available"),
            (self.gpu_vram_total_bytes, "GPU VRAM total"),
            (self.gpu_vram_available_bytes, "GPU VRAM available"),
            (self.disk_free_bytes, "Disk free space"),
        ):
            if value is not None and (type(value) is not int or value < 0):
                raise ResourceValidationError(f"{field} is invalid")
        if self.ram_total_bytes is not None and self.ram_available_bytes is not None:
            if self.ram_available_bytes > self.ram_total_bytes:
                raise ResourceValidationError("RAM available exceeds RAM total")
        if self.gpu_vram_total_bytes is not None and self.gpu_vram_available_bytes is not None:
            if self.gpu_vram_available_bytes > self.gpu_vram_total_bytes:
                raise ResourceValidationError("GPU VRAM available exceeds GPU VRAM total")
        _optional_bool(self.on_ac_power, "AC power")
        _ratio_optional(self.battery_level, "Battery level")
        _finite_optional(self.user_idle_seconds, "User idle seconds")
        _optional_bool(self.user_active, "User active")
        _optional_bool(self.heavy_foreground_workload, "Foreground workload")


@dataclass(frozen=True, slots=True)
class ResourcePolicy:
    """Immutable admission thresholds shared by every resource consumer."""

    cpu_pressure_threshold: float = 0.90
    memory_pressure_ratio: float = 0.15
    gpu_pressure_ratio: float = 0.15
    low_disk_bytes: int = 2 * 1024**3
    large_download_bytes: int = 512 * 1024**2
    low_battery_ratio: float = 0.20
    max_background_concurrency: int = 2
    pressure_concurrency: int = 1
    benchmark_on_battery: bool = False
    defer_indexing_under_pressure: bool = True
    defer_background_under_pressure: bool = True
    unload_cold_models_on_pressure: bool = True
    choose_smaller_model_on_pressure: bool = True
    pause_background_research_under_pressure: bool = True

    def __post_init__(self) -> None:
        for value, field in (
            (self.cpu_pressure_threshold, "CPU pressure threshold"),
            (self.memory_pressure_ratio, "Memory pressure ratio"),
            (self.gpu_pressure_ratio, "GPU pressure ratio"),
            (self.low_battery_ratio, "Low battery ratio"),
        ):
            _ratio_optional(value, field)
        for value, field in (
            (self.low_disk_bytes, "Low disk threshold"),
            (self.large_download_bytes, "Large download threshold"),
        ):
            if type(value) is not int or value < 0:
                raise ResourceValidationError(f"{field} is invalid")
        for value, field in (
            (self.max_background_concurrency, "Background concurrency"),
            (self.pressure_concurrency, "Pressure concurrency"),
        ):
            if type(value) is not int or value < 1:
                raise ResourceValidationError(f"{field} is invalid")
        for value, field in (
            (self.benchmark_on_battery, "Benchmark battery policy"),
            (self.defer_indexing_under_pressure, "Indexing pressure policy"),
            (self.defer_background_under_pressure, "Background pressure policy"),
            (self.unload_cold_models_on_pressure, "Cold model policy"),
            (self.choose_smaller_model_on_pressure, "Smaller model policy"),
            (self.pause_background_research_under_pressure, "Research pressure policy"),
        ):
            if type(value) is not bool:
                raise ResourceValidationError(f"{field} is invalid")


@dataclass(frozen=True, slots=True)
class ResourceBudget:
    """A bounded request, not a permission and not a task budget."""

    cpu_cores: int | None = None
    ram_bytes: int | None = None
    vram_bytes: int | None = None
    disk_bytes: int | None = None
    network_bytes: int | None = None
    concurrency: int = 1
    duration_seconds: float = 60.0

    def __post_init__(self) -> None:
        for value, field in (
            (self.cpu_cores, "CPU cores"),
            (self.ram_bytes, "RAM bytes"),
            (self.vram_bytes, "VRAM bytes"),
            (self.disk_bytes, "Disk bytes"),
            (self.network_bytes, "Network bytes"),
        ):
            if value is not None and (type(value) is not int or value < 0):
                raise ResourceValidationError(f"{field} is invalid")
        if type(self.concurrency) is not int or not 1 <= self.concurrency <= 256:
            raise ResourceValidationError("Concurrency is invalid")
        _finite_optional(self.duration_seconds, "Duration", minimum=0.001)

    def with_concurrency(self, concurrency: int) -> ResourceBudget:
        if not 1 <= concurrency <= self.concurrency:
            raise ResourceValidationError("Reduced concurrency is invalid")
        return replace(self, concurrency=concurrency)


@dataclass(frozen=True, slots=True)
class ResourceReservation:
    reservation_id: UUID
    owner: str
    priority: ResourcePriority
    budget: ResourceBudget
    reserved_at: datetime
    expires_at: datetime
    status: ReservationStatus = ReservationStatus.ACTIVE
    released_at: datetime | None = None
    release_reason: ReservationReleaseReason | None = None

    def __post_init__(self) -> None:
        if not isinstance(self.reservation_id, UUID):
            raise ResourceValidationError("Reservation ID is invalid")
        _bounded_text(self.owner, "Reservation owner")
        if not isinstance(self.priority, ResourcePriority) or not isinstance(
            self.budget, ResourceBudget
        ):
            raise ResourceValidationError("Reservation metadata is invalid")
        if not isinstance(self.status, ReservationStatus):
            raise ResourceValidationError("Reservation status is invalid")
        if (
            not isinstance(self.reserved_at, datetime)
            or not isinstance(self.expires_at, datetime)
            or self.reserved_at.tzinfo is None
            or self.expires_at.tzinfo is None
        ):
            raise ResourceValidationError("Reservation times must be timezone-aware")
        if self.expires_at <= self.reserved_at:
            raise ResourceValidationError("Reservation expiry must be in the future")
        if self.status is ReservationStatus.ACTIVE and (
            self.released_at is not None or self.release_reason is not None
        ):
            raise ResourceValidationError("Active reservation cannot have release metadata")
        if self.status is not ReservationStatus.ACTIVE and (
            self.released_at is None or self.release_reason is None
        ):
            raise ResourceValidationError("Released reservation requires release metadata")
        if self.released_at is not None and (
            not isinstance(self.released_at, datetime) or self.released_at.tzinfo is None
        ):
            raise ResourceValidationError("Release time must be timezone-aware")
        if self.release_reason is not None and not isinstance(
            self.release_reason, ReservationReleaseReason
        ):
            raise ResourceValidationError("Release reason is invalid")


@dataclass(frozen=True, slots=True)
class ResourceDecision:
    decision_id: UUID
    owner: str
    priority: ResourcePriority
    status: ResourceDecisionStatus
    requested_budget: ResourceBudget
    effective_budget: ResourceBudget
    snapshot: ResourceSnapshot
    reason: str
    reservation_id: UUID | None = None
    max_concurrency: int | None = None
    unload_cold_models: bool = False
    choose_smaller_model: bool = False

    def __post_init__(self) -> None:
        if not isinstance(self.decision_id, UUID) or not isinstance(
            self.snapshot, ResourceSnapshot
        ):
            raise ResourceValidationError("Resource decision metadata is invalid")
        _bounded_text(self.owner, "Decision owner")
        if not isinstance(self.priority, ResourcePriority) or not isinstance(
            self.status, ResourceDecisionStatus
        ):
            raise ResourceValidationError("Resource decision type is invalid")
        if not isinstance(self.requested_budget, ResourceBudget) or not isinstance(
            self.effective_budget, ResourceBudget
        ):
            raise ResourceValidationError("Resource decision budgets are invalid")
        _bounded_text(self.reason, "Decision reason", 1_024)
        if self.reservation_id is not None and not isinstance(self.reservation_id, UUID):
            raise ResourceValidationError("Decision reservation ID is invalid")
        if self.max_concurrency is not None and (
            type(self.max_concurrency) is not int or not 1 <= self.max_concurrency <= 256
        ):
            raise ResourceValidationError("Decision concurrency is invalid")
        if type(self.unload_cold_models) is not bool or type(self.choose_smaller_model) is not bool:
            raise ResourceValidationError("Decision degradation flags are invalid")

    @property
    def allowed(self) -> bool:
        return self.status in {ResourceDecisionStatus.ALLOW, ResourceDecisionStatus.REDUCE}


class ResourceTelemetry(Protocol):
    def snapshot(self) -> ResourceSnapshot: ...


class SystemResourceTelemetry:
    """Best-effort host probe. Unsupported fields intentionally remain unknown."""

    def __init__(
        self,
        *,
        clock: Callable[[], datetime] | None = None,
        cpu_probe: Callable[[], float | None] | None = None,
        idle_probe: Callable[[], float | None] | None = None,
        foreground_probe: Callable[[], bool | None] | None = None,
    ) -> None:
        self._clock = clock or (lambda: datetime.now(UTC))
        self._cpu_probe = cpu_probe
        self._idle_probe = idle_probe
        self._foreground_probe = foreground_probe

    def snapshot(self) -> ResourceSnapshot:
        total, available = _memory_probe()
        disk_free: int | None = None
        with _suppress_probe_errors():
            disk_free = shutil.disk_usage(PathLikeRoot()).free
        on_ac, battery = _battery_probe()
        cpu = self._cpu_probe() if self._cpu_probe is not None else _cpu_probe()
        idle = self._idle_probe() if self._idle_probe is not None else _idle_probe()
        foreground = self._foreground_probe() if self._foreground_probe is not None else None
        return ResourceSnapshot(
            observed_at=self._clock(),
            cpu_utilization=cpu,
            cpu_cores=os.cpu_count(),
            ram_total_bytes=total,
            ram_available_bytes=available,
            disk_free_bytes=disk_free,
            on_ac_power=on_ac,
            battery_level=battery,
            user_idle_seconds=idle,
            user_active=None if idle is None else idle < 60.0,
            heavy_foreground_workload=foreground,
        )


class _suppress_probe_errors:
    def __enter__(self) -> _suppress_probe_errors:
        return self

    def __exit__(self, *_: object) -> bool:
        return True


class PathLikeRoot:
    """Small indirection so tests can replace the disk probe without pathlib globals."""

    def __fspath__(self) -> str:
        return os.getcwd()


def _memory_probe() -> tuple[int | None, int | None]:
    if os.name == "nt":

        class MemoryStatus(ctypes.Structure):
            _fields_ = [
                ("length", wintypes.DWORD),
                ("memory_load", wintypes.DWORD),
                ("total_phys", ctypes.c_ulonglong),
                ("avail_phys", ctypes.c_ulonglong),
                ("total_page", ctypes.c_ulonglong),
                ("avail_page", ctypes.c_ulonglong),
                ("total_virtual", ctypes.c_ulonglong),
                ("avail_virtual", ctypes.c_ulonglong),
                ("avail_extended", ctypes.c_ulonglong),
            ]

        status = MemoryStatus()
        status.length = ctypes.sizeof(status)
        try:
            if ctypes.windll.kernel32.GlobalMemoryStatusEx(ctypes.byref(status)):
                return status.total_phys, status.avail_phys
        except (AttributeError, OSError):
            pass
        return None, None
    try:
        values: dict[str, int] = {}
        with open("/proc/meminfo", encoding="ascii") as stream:
            for line in stream:
                key, _, raw = line.partition(":")
                if key in {"MemTotal", "MemAvailable"}:
                    values[key] = int(raw.strip().split()[0]) * 1024
        return values.get("MemTotal"), values.get("MemAvailable")
    except (OSError, ValueError):
        return None, None


def _cpu_probe() -> float | None:
    try:
        getloadavg = getattr(os, "getloadavg", None)
        if not callable(getloadavg):
            return None
        load = cast(Callable[[], tuple[float, ...]], getloadavg)()[0]
        cores = os.cpu_count()
        if cores:
            return float(min(1.0, max(0.0, load / cores)))
    except (AttributeError, OSError):
        pass
    return None


def _battery_probe() -> tuple[bool | None, float | None]:
    if os.name != "nt":
        return None, None

    class PowerStatus(ctypes.Structure):
        _fields_ = [
            ("ac_line", wintypes.BYTE),
            ("battery", wintypes.BYTE),
            ("percent", wintypes.BYTE),
            ("reserved", wintypes.BYTE),
            ("seconds", wintypes.DWORD),
            ("full_seconds", wintypes.DWORD),
        ]

    status = PowerStatus()
    try:
        if ctypes.windll.kernel32.GetSystemPowerStatus(ctypes.byref(status)):
            percent = int(status.percent)
            return (status.ac_line == 1, None if percent == 255 else percent / 100.0)
    except (AttributeError, OSError):
        pass
    return None, None


def _idle_probe() -> float | None:
    if os.name != "nt":
        return None

    class LastInput(ctypes.Structure):
        _fields_ = [("size", wintypes.UINT), ("tick", wintypes.DWORD)]

    value = LastInput()
    value.size = ctypes.sizeof(value)
    try:
        if ctypes.windll.user32.GetLastInputInfo(ctypes.byref(value)):
            now = ctypes.windll.kernel32.GetTickCount()
            return float(max(0.0, (now - value.tick) / 1000.0))
    except (AttributeError, OSError):
        pass
    return None


class ResourceGovernor:
    """The only live resource admission policy used by the runtime."""

    def __init__(
        self,
        telemetry: ResourceTelemetry,
        *,
        policy: ResourcePolicy | None = None,
        clock: Callable[[], datetime] | None = None,
    ) -> None:
        if not callable(getattr(telemetry, "snapshot", None)):
            raise ResourceValidationError("Resource telemetry is invalid")
        if policy is not None and not isinstance(policy, ResourcePolicy):
            raise ResourceValidationError("Resource policy is invalid")
        self._telemetry = telemetry
        self._policy = policy or ResourcePolicy()
        self._clock = clock or (lambda: datetime.now(UTC))
        self._lock = threading.RLock()
        self._reservations: dict[UUID, ResourceReservation] = {}

    @property
    def policy(self) -> ResourcePolicy:
        return self._policy

    def snapshot(self) -> ResourceSnapshot:
        value = self._telemetry.snapshot()
        if not isinstance(value, ResourceSnapshot):
            raise ResourceValidationError("Resource telemetry returned malformed snapshot")
        return value

    def decide(
        self,
        owner: str,
        priority: ResourcePriority,
        budget: ResourceBudget,
    ) -> ResourceDecision:
        owner = _bounded_text(owner, "Resource owner")
        if not isinstance(priority, ResourcePriority) or not isinstance(budget, ResourceBudget):
            raise ResourceValidationError("Resource request is malformed")
        with self._lock:
            snapshot = self.snapshot()
            active = self._active_locked()
            return self._decide_locked(owner, priority, budget, snapshot, active)

    def reserve(
        self,
        owner: str,
        priority: ResourcePriority,
        budget: ResourceBudget,
    ) -> ResourceDecision:
        owner = _bounded_text(owner, "Resource owner")
        if not isinstance(priority, ResourcePriority) or not isinstance(budget, ResourceBudget):
            raise ResourceValidationError("Resource request is malformed")
        with self._lock:
            snapshot = self.snapshot()
            decision = self._decide_locked(owner, priority, budget, snapshot, self._active_locked())
            if not decision.allowed:
                return decision
            now = self._clock()
            reservation_id = uuid4()
            reservation = ResourceReservation(
                reservation_id,
                owner,
                priority,
                decision.effective_budget,
                now,
                now + timedelta(seconds=decision.effective_budget.duration_seconds),
            )
            self._reservations[reservation_id] = reservation
            return replace(decision, reservation_id=reservation_id)

    def release(
        self, reservation_id: UUID, reason: ReservationReleaseReason
    ) -> ResourceReservation:
        if not isinstance(reservation_id, UUID) or not isinstance(reason, ReservationReleaseReason):
            raise ResourceValidationError("Reservation release is malformed")
        with self._lock:
            reservation = self._reservations.get(reservation_id)
            if reservation is None:
                raise ResourceValidationError("Unknown resource reservation")
            if reservation.status is not ReservationStatus.ACTIVE:
                return reservation
            status = {
                ReservationReleaseReason.COMPLETE: ReservationStatus.COMPLETED,
                ReservationReleaseReason.CANCEL: ReservationStatus.CANCELLED,
                ReservationReleaseReason.CRASH: ReservationStatus.CRASHED,
                ReservationReleaseReason.TIMEOUT: ReservationStatus.TIMED_OUT,
            }[reason]
            released = replace(
                reservation,
                status=status,
                released_at=self._clock(),
                release_reason=reason,
            )
            self._reservations[reservation_id] = released
            return released

    def expire(self) -> tuple[ResourceReservation, ...]:
        now = self._clock()
        expired: list[ResourceReservation] = []
        with self._lock:
            for reservation_id, reservation in tuple(self._reservations.items()):
                if reservation.status is ReservationStatus.ACTIVE and reservation.expires_at <= now:
                    expired.append(self.release(reservation_id, ReservationReleaseReason.TIMEOUT))
        return tuple(expired)

    def inspect(self, reservation_id: UUID) -> ResourceReservation | None:
        with self._lock:
            return self._reservations.get(reservation_id)

    def reservations(self, *, active_only: bool = False) -> tuple[ResourceReservation, ...]:
        with self._lock:
            values = tuple(self._reservations.values())
        if active_only:
            return tuple(item for item in values if item.status is ReservationStatus.ACTIVE)
        return values

    def _active_locked(self) -> tuple[ResourceReservation, ...]:
        now = self._clock()
        return tuple(
            item
            for item in self._reservations.values()
            if item.status is ReservationStatus.ACTIVE and item.expires_at > now
        )

    def _decide_locked(
        self,
        owner: str,
        priority: ResourcePriority,
        budget: ResourceBudget,
        snapshot: ResourceSnapshot,
        active: tuple[ResourceReservation, ...],
    ) -> ResourceDecision:
        pressure = self._is_pressure(snapshot)
        low_priority = priority in {
            ResourcePriority.BACKGROUND,
            ResourcePriority.MAINTENANCE,
            ResourcePriority.BENCHMARK,
            ResourcePriority.INDEXING,
        }
        if (
            priority is ResourcePriority.BENCHMARK
            and not self._policy.benchmark_on_battery
            and self._on_battery(snapshot)
        ):
            return self._decision(
                owner,
                priority,
                budget,
                snapshot,
                ResourceDecisionStatus.DEFER,
                "benchmarks are deferred on battery",
            )
        if (
            priority is ResourcePriority.INDEXING
            and pressure
            and self._policy.defer_indexing_under_pressure
        ):
            return self._decision(
                owner,
                priority,
                budget,
                snapshot,
                ResourceDecisionStatus.DEFER,
                "indexing is deferred under resource pressure",
            )
        if (
            priority is ResourcePriority.BACKGROUND
            and pressure
            and self._policy.defer_background_under_pressure
        ):
            return self._decision(
                owner,
                priority,
                budget,
                snapshot,
                ResourceDecisionStatus.DEFER,
                "background work is deferred under resource pressure",
            )
        if (
            priority is ResourcePriority.BACKGROUND
            and self._policy.pause_background_research_under_pressure
            and snapshot.heavy_foreground_workload
        ):
            return self._decision(
                owner,
                priority,
                budget,
                snapshot,
                ResourceDecisionStatus.DEFER,
                "background research yields to foreground workload",
            )
        if budget.disk_bytes is not None and snapshot.disk_free_bytes is not None:
            reserved_disk = sum(item.budget.disk_bytes or 0 for item in active)
            if budget.disk_bytes + reserved_disk > snapshot.disk_free_bytes:
                return self._decision(
                    owner,
                    priority,
                    budget,
                    snapshot,
                    ResourceDecisionStatus.DEFER if low_priority else ResourceDecisionStatus.DENY,
                    "requested disk capacity is unavailable",
                )
            if (
                snapshot.disk_free_bytes <= self._policy.low_disk_bytes
                and budget.disk_bytes >= self._policy.large_download_bytes
            ):
                return self._decision(
                    owner,
                    priority,
                    budget,
                    snapshot,
                    ResourceDecisionStatus.DEFER
                    if priority is not ResourcePriority.INTERACTIVE
                    else ResourceDecisionStatus.REDUCE,
                    "large disk operation avoided on low free space",
                )
        unknown_capacity = self._unknown_capacity(budget, snapshot)
        if unknown_capacity and low_priority:
            return self._decision(
                owner,
                priority,
                budget,
                snapshot,
                ResourceDecisionStatus.DEFER,
                "required resource capacity is unmeasured",
            )
        if self._capacity_exceeded(budget, snapshot, active):
            return self._decision(
                owner,
                priority,
                budget,
                snapshot,
                ResourceDecisionStatus.DEFER if low_priority else ResourceDecisionStatus.DENY,
                "requested capacity is already reserved or unavailable",
            )
        if pressure and budget.concurrency > self._policy.pressure_concurrency:
            reduced = budget.with_concurrency(self._policy.pressure_concurrency)
            return self._decision(
                owner,
                priority,
                budget,
                snapshot,
                ResourceDecisionStatus.REDUCE,
                "resource pressure reduced concurrency",
                effective=reduced,
                max_concurrency=reduced.concurrency,
                unload=self._policy.unload_cold_models_on_pressure,
                smaller=self._policy.choose_smaller_model_on_pressure,
            )
        if budget.concurrency > self._policy.max_background_concurrency and low_priority:
            reduced = budget.with_concurrency(self._policy.max_background_concurrency)
            return self._decision(
                owner,
                priority,
                budget,
                snapshot,
                ResourceDecisionStatus.REDUCE,
                "background concurrency was bounded",
                effective=reduced,
                max_concurrency=reduced.concurrency,
            )
        return self._decision(
            owner,
            priority,
            budget,
            snapshot,
            ResourceDecisionStatus.ALLOW,
            "resource request admitted",
            max_concurrency=budget.concurrency,
        )

    def _decision(
        self,
        owner: str,
        priority: ResourcePriority,
        requested: ResourceBudget,
        snapshot: ResourceSnapshot,
        status: ResourceDecisionStatus,
        reason: str,
        *,
        effective: ResourceBudget | None = None,
        max_concurrency: int | None = None,
        unload: bool = False,
        smaller: bool = False,
    ) -> ResourceDecision:
        return ResourceDecision(
            uuid4(),
            owner,
            priority,
            status,
            requested,
            effective or requested,
            snapshot,
            reason,
            max_concurrency=max_concurrency,
            unload_cold_models=unload,
            choose_smaller_model=smaller,
        )

    def _is_pressure(self, snapshot: ResourceSnapshot) -> bool:
        memory = (
            snapshot.ram_total_bytes is not None
            and snapshot.ram_available_bytes is not None
            and snapshot.ram_total_bytes > 0
            and snapshot.ram_available_bytes / snapshot.ram_total_bytes
            <= self._policy.memory_pressure_ratio
        )
        gpu = (
            snapshot.gpu_vram_total_bytes is not None
            and snapshot.gpu_vram_available_bytes is not None
            and snapshot.gpu_vram_total_bytes > 0
            and snapshot.gpu_vram_available_bytes / snapshot.gpu_vram_total_bytes
            <= self._policy.gpu_pressure_ratio
        )
        cpu = (
            snapshot.cpu_utilization is not None
            and snapshot.cpu_utilization >= self._policy.cpu_pressure_threshold
        )
        disk = (
            snapshot.disk_free_bytes is not None
            and snapshot.disk_free_bytes <= self._policy.low_disk_bytes
        )
        return bool(memory or gpu or cpu or disk or snapshot.heavy_foreground_workload)

    def _on_battery(self, snapshot: ResourceSnapshot) -> bool:
        if snapshot.on_ac_power is False:
            return True
        return (
            snapshot.battery_level is not None
            and snapshot.battery_level <= self._policy.low_battery_ratio
        )

    @staticmethod
    def _unknown_capacity(budget: ResourceBudget, snapshot: ResourceSnapshot) -> bool:
        return (
            (budget.ram_bytes is not None and snapshot.ram_available_bytes is None)
            or (budget.vram_bytes is not None and snapshot.gpu_vram_available_bytes is None)
            or (budget.disk_bytes is not None and snapshot.disk_free_bytes is None)
        )

    @staticmethod
    def _capacity_exceeded(
        budget: ResourceBudget,
        snapshot: ResourceSnapshot,
        active: tuple[ResourceReservation, ...],
    ) -> bool:
        reserved_ram = sum(item.budget.ram_bytes or 0 for item in active)
        reserved_vram = sum(item.budget.vram_bytes or 0 for item in active)
        reserved_cpu = sum(item.budget.cpu_cores or 0 for item in active)
        if (
            budget.ram_bytes is not None
            and snapshot.ram_available_bytes is not None
            and budget.ram_bytes + reserved_ram > snapshot.ram_available_bytes
        ):
            return True
        if (
            budget.vram_bytes is not None
            and snapshot.gpu_vram_available_bytes is not None
            and budget.vram_bytes + reserved_vram > snapshot.gpu_vram_available_bytes
        ):
            return True
        if (
            budget.cpu_cores is not None
            and snapshot.cpu_cores is not None
            and budget.cpu_cores + reserved_cpu > snapshot.cpu_cores
        ):
            return True
        return False


__all__ = [
    "ResourceBudget",
    "ResourceDecision",
    "ResourceDecisionStatus",
    "ResourceGovernor",
    "ResourcePolicy",
    "ResourcePriority",
    "ResourceReservation",
    "ResourceSnapshot",
    "ResourceTelemetry",
    "ResourceValidationError",
    "ReservationReleaseReason",
    "ReservationStatus",
    "SystemResourceTelemetry",
]
