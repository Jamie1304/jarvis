"""Empirical hardware inventory and resource-aware model selection.

This module records observations without guessing unavailable hardware facts.
The native probe is intentionally conservative; deterministic tests inject a
fake probe and never claim to measure the developer's machine.
"""

from __future__ import annotations

import ctypes
import math
import os
import platform
import shutil
from collections.abc import Callable, Iterable
from dataclasses import dataclass, replace
from datetime import UTC, datetime
from enum import StrEnum
from pathlib import Path
from typing import Protocol

from jarvis.ai.models import EvidenceKind, EvidenceRecord, ModelRole
from jarvis.ai.providers.registry import ModelMetadata


class HardwareInventoryError(ValueError):
    """Hardware or model inventory data failed validation."""


class FitStatus(StrEnum):
    COMPATIBLE = "compatible"
    INCOMPATIBLE = "incompatible"
    UNKNOWN = "unknown"


@dataclass(frozen=True, slots=True)
class GpuInfo:
    name: str
    vram_bytes: int | None = None
    driver_version: str | None = None

    def __post_init__(self) -> None:
        _text(self.name, "GPU name", 256)
        _nonnegative_optional(self.vram_bytes, "GPU VRAM")
        _optional_text(self.driver_version, "GPU driver version", 128)


@dataclass(frozen=True, slots=True)
class RuntimeInfo:
    name: str
    version: str

    def __post_init__(self) -> None:
        _text(self.name, "Runtime name", 128)
        _text(self.version, "Runtime version", 128)


@dataclass(frozen=True, slots=True)
class HardwareReading:
    """Raw probe output. ``None`` means that the probe did not establish a fact."""

    cpu_model: str | None = None
    cpu_physical_cores: int | None = None
    cpu_logical_cores: int | None = None
    ram_bytes: int | None = None
    gpu_devices: tuple[GpuInfo, ...] | None = None
    runtimes: tuple[RuntimeInfo, ...] = ()
    disk_free_bytes: int | None = None
    os_name: str | None = None
    os_version: str | None = None
    architecture: str | None = None
    concurrency_limit: int | None = None
    compatibility_tags: frozenset[str] = frozenset()

    def __post_init__(self) -> None:
        _optional_text(self.cpu_model, "CPU model", 256)
        _nonnegative_optional(self.cpu_physical_cores, "Physical CPU cores")
        _nonnegative_optional(self.cpu_logical_cores, "Logical CPU cores")
        _nonnegative_optional(self.ram_bytes, "RAM")
        if self.gpu_devices is not None and (
            type(self.gpu_devices) is not tuple
            or any(not isinstance(device, GpuInfo) for device in self.gpu_devices)
        ):
            raise HardwareInventoryError("GPU inventory is malformed")
        if type(self.runtimes) is not tuple or any(
            not isinstance(runtime, RuntimeInfo) for runtime in self.runtimes
        ):
            raise HardwareInventoryError("Runtime inventory is malformed")
        _nonnegative_optional(self.disk_free_bytes, "Free disk space")
        _optional_text(self.os_name, "Operating system", 128)
        _optional_text(self.os_version, "Operating-system version", 256)
        _optional_text(self.architecture, "Hardware architecture", 128)
        _nonnegative_optional(self.concurrency_limit, "Concurrency limit")
        if type(self.compatibility_tags) is not frozenset or any(
            type(tag) is not str or not tag.strip() or len(tag) > 128 or "\x00" in tag
            for tag in self.compatibility_tags
        ):
            raise HardwareInventoryError("Hardware compatibility tags are malformed")


@dataclass(frozen=True, slots=True)
class HardwareProfile:
    """A probe result with explicit measured-on-this-machine provenance."""

    reading: HardwareReading
    evidence: tuple[EvidenceRecord, ...]

    def __post_init__(self) -> None:
        if not isinstance(self.reading, HardwareReading):
            raise HardwareInventoryError("Hardware reading is malformed")
        if (
            type(self.evidence) is not tuple
            or not self.evidence
            or any(
                not isinstance(evidence, EvidenceRecord)
                or evidence.kind is not EvidenceKind.MEASURED_ON_THIS_MACHINE
                for evidence in self.evidence
            )
        ):
            raise HardwareInventoryError("Hardware profiles require measured evidence")

    @property
    def available_vram_bytes(self) -> int | None:
        if self.reading.gpu_devices is None:
            return None
        if any(device.vram_bytes is None for device in self.reading.gpu_devices):
            return None
        return sum(device.vram_bytes or 0 for device in self.reading.gpu_devices)


class HardwareProbe(Protocol):
    def read(self) -> HardwareReading: ...


class HardwareInventoryService:
    """Measure hardware through an injected probe and retain the last snapshot."""

    def __init__(
        self,
        probe: HardwareProbe,
        *,
        clock: Callable[[], datetime] = lambda: datetime.now(UTC),
    ) -> None:
        self._probe = probe
        self._clock = clock
        self._last: HardwareProfile | None = None

    def inspect(self) -> HardwareProfile:
        reading = self._probe.read()
        if not isinstance(reading, HardwareReading):
            raise HardwareInventoryError("Hardware probe returned malformed data")
        captured_at = self._clock()
        if not isinstance(captured_at, datetime) or captured_at.tzinfo is None:
            raise HardwareInventoryError("Hardware probe clock must be timezone-aware")
        profile = HardwareProfile(
            reading,
            (
                EvidenceRecord(
                    EvidenceKind.MEASURED_ON_THIS_MACHINE,
                    "native.hardware_probe",
                    "Values returned by the trusted local hardware probe",
                    captured_at=captured_at,
                    machine_scope="this_machine",
                ),
            ),
        )
        self._last = profile
        return profile

    @property
    def last(self) -> HardwareProfile | None:
        return self._last


class SystemHardwareProbe:
    """Conservative stdlib-only host probe; unavailable values remain unknown."""

    def __init__(self, *, disk_root: Path | None = None, concurrency_limit: int | None = None):
        self._disk_root = disk_root or Path.cwd()
        self._concurrency_limit = concurrency_limit

    def read(self) -> HardwareReading:
        system = platform.system() or "unknown"
        architecture = platform.machine() or None
        logical = os.cpu_count()
        compatibility = {system.casefold(), "cpu"}
        if architecture:
            compatibility.add(architecture.casefold())
        try:
            disk_free = shutil.disk_usage(self._disk_root).free
        except OSError:
            disk_free = None
        return HardwareReading(
            cpu_model=platform.processor() or architecture,
            cpu_logical_cores=logical,
            ram_bytes=_system_ram_bytes(),
            gpu_devices=None,
            runtimes=(RuntimeInfo("python", platform.python_version()),),
            disk_free_bytes=disk_free,
            os_name=system,
            os_version=platform.version() or None,
            architecture=architecture,
            concurrency_limit=self._concurrency_limit,
            compatibility_tags=frozenset(compatibility),
        )


@dataclass(frozen=True, slots=True)
class ModelMeasurement:
    """Measured benchmark output supplied by a trusted runtime harness."""

    model_id: str
    measured_at: datetime
    source: str
    storage_bytes: int | None = None
    peak_ram_bytes: int | None = None
    peak_vram_bytes: int | None = None
    load_seconds: float | None = None
    throughput: float | None = None
    concurrency: int | None = None

    def __post_init__(self) -> None:
        _text(self.model_id, "Measured model ID", 256)
        if not isinstance(self.measured_at, datetime) or self.measured_at.tzinfo is None:
            raise HardwareInventoryError("Model measurement timestamp must be timezone-aware")
        _text(self.source, "Model measurement source", 256)
        for name, value in (
            ("storage", self.storage_bytes),
            ("peak RAM", self.peak_ram_bytes),
            ("peak VRAM", self.peak_vram_bytes),
            ("concurrency", self.concurrency),
        ):
            _nonnegative_optional(value, f"Measured {name}")
        measurement_fields: tuple[tuple[str, float | None], ...] = (
            ("load time", self.load_seconds),
            ("throughput", self.throughput),
        )
        for field_name, field_value in measurement_fields:
            if field_value is not None and (
                type(field_value) not in {int, float} or not math.isfinite(field_value)
            ):
                raise HardwareInventoryError(f"Measured {field_name} is invalid")
            if field_value is not None and field_value < 0:
                raise HardwareInventoryError(f"Measured {field_name} cannot be negative")


class ModelInventory:
    """Registry for descriptive model metadata and trusted empirical updates."""

    def __init__(self, models: Iterable[ModelMetadata] = ()) -> None:
        self._models: dict[str, ModelMetadata] = {}
        for model in models:
            self.register(model)

    def register(self, model: ModelMetadata) -> None:
        if not isinstance(model, ModelMetadata):
            raise HardwareInventoryError("Model metadata is malformed")
        if model.model_id in self._models:
            raise HardwareInventoryError("Duplicate model ID")
        self._models[model.model_id] = model

    def inspect(self, model_id: str) -> ModelMetadata:
        try:
            return self._models[model_id]
        except KeyError as error:
            raise KeyError(f"Unknown model: {model_id}") from error

    def models(self, role: ModelRole | None = None) -> tuple[ModelMetadata, ...]:
        if role is not None and not isinstance(role, ModelRole):
            raise HardwareInventoryError("Model role is invalid")
        return tuple(
            model for model in self._models.values() if role is None or role in model.roles
        )

    def record_measurement(self, measurement: ModelMeasurement) -> ModelMetadata:
        current = self.inspect(measurement.model_id)
        metrics = tuple(
            (key, str(value))
            for key, value in (
                ("storage_bytes", measurement.storage_bytes),
                ("peak_ram_bytes", measurement.peak_ram_bytes),
                ("peak_vram_bytes", measurement.peak_vram_bytes),
                ("load_seconds", measurement.load_seconds),
                ("throughput", measurement.throughput),
                ("concurrency", measurement.concurrency),
            )
            if value is not None
        )
        evidence = EvidenceRecord(
            EvidenceKind.MEASURED_ON_THIS_MACHINE,
            measurement.source,
            "Trusted runtime harness measurement",
            captured_at=measurement.measured_at,
            machine_scope="this_machine",
            metrics=metrics,
        )
        updated = replace(
            current,
            storage_bytes=(
                measurement.storage_bytes
                if measurement.storage_bytes is not None
                else current.storage_bytes
            ),
            ram_bytes=(
                measurement.peak_ram_bytes
                if measurement.peak_ram_bytes is not None
                else current.ram_bytes
            ),
            vram_bytes=(
                measurement.peak_vram_bytes
                if measurement.peak_vram_bytes is not None
                else current.vram_bytes
            ),
            max_concurrency=(
                measurement.concurrency
                if measurement.concurrency is not None
                else current.max_concurrency
            ),
            evidence=(*current.evidence, evidence),
        )
        self._models[updated.model_id] = updated
        return updated


ModelRecord = ModelMetadata


@dataclass(frozen=True, slots=True)
class ModelCombinationRequest:
    roles: tuple[ModelRole, ...]
    max_concurrency: int = 1
    simultaneous: bool = True
    require_measured_evidence: bool = False

    def __post_init__(self) -> None:
        if type(self.roles) is not tuple or not self.roles or len(self.roles) > 10:
            raise HardwareInventoryError("Model roles must be a bounded non-empty tuple")
        if any(not isinstance(role, ModelRole) for role in self.roles):
            raise HardwareInventoryError("Model roles are invalid")
        if (
            type(self.max_concurrency) is not int
            or self.max_concurrency <= 0
            or self.max_concurrency > 64
        ):
            raise HardwareInventoryError("Model concurrency must be bounded and positive")
        if type(self.simultaneous) is not bool or type(self.require_measured_evidence) is not bool:
            raise HardwareInventoryError("Model combination flags are invalid")


@dataclass(frozen=True, slots=True)
class ModelFit:
    model_id: str
    status: FitStatus
    reasons: tuple[str, ...]


@dataclass(frozen=True, slots=True)
class ModelCombination:
    status: FitStatus
    assignments: tuple[tuple[ModelRole, str], ...]
    models: tuple[ModelMetadata, ...]
    reasons: tuple[str, ...]
    required_storage_bytes: int | None
    required_ram_bytes: int | None
    required_vram_bytes: int | None


class ModelPlanner:
    """Choose a bounded model combination without treating unknown as compatible."""

    def __init__(self, inventory: ModelInventory) -> None:
        self._inventory = inventory

    def assess(self, model: ModelMetadata, hardware: HardwareProfile) -> ModelFit:
        if not isinstance(model, ModelMetadata) or not isinstance(hardware, HardwareProfile):
            raise HardwareInventoryError("Model fit inputs are malformed")
        status, reasons = self._assess_model(model, hardware)
        return ModelFit(model.model_id, status, tuple(reasons))

    def plan(self, request: ModelCombinationRequest, hardware: HardwareProfile) -> ModelCombination:
        if not isinstance(request, ModelCombinationRequest) or not isinstance(
            hardware, HardwareProfile
        ):
            raise HardwareInventoryError("Model planning inputs are malformed")
        options: list[tuple[ModelMetadata, ...]] = []
        for role in request.roles:
            all_role_models = tuple(
                sorted(self._inventory.models(role), key=lambda item: item.model_id)
            )
            if not all_role_models:
                return self._incompatible(
                    request,
                    f"no model is registered for role {role.value}",
                )
            role_models = all_role_models
            if request.require_measured_evidence:
                role_models = tuple(
                    model
                    for model in role_models
                    if any(
                        evidence.kind is EvidenceKind.MEASURED_ON_THIS_MACHINE
                        for evidence in model.evidence
                    )
                )
            if not role_models:
                return self._unknown(
                    request,
                    f"no locally measured model is available for role {role.value}",
                )
            options.append(role_models[:32])

        unknown_reasons: list[str] = []
        for assignment in _bounded_product(options):
            models = _unique_models(assignment)
            model_statuses = [
                self._assess_model(
                    model,
                    hardware,
                    requested_concurrency=request.max_concurrency,
                )
                for model in models
            ]
            status, reasons, requirements = self._assess_combination(
                models, model_statuses, request, hardware
            )
            if status is FitStatus.COMPATIBLE:
                return ModelCombination(
                    status,
                    tuple(
                        (role, model.model_id)
                        for role, model in zip(request.roles, assignment, strict=True)
                    ),
                    models,
                    tuple(reasons),
                    *requirements,
                )
            if status is FitStatus.UNKNOWN:
                unknown_reasons.extend(reasons)
        if unknown_reasons:
            return self._unknown(request, *tuple(dict.fromkeys(unknown_reasons))[:8])
        return self._incompatible(request, "no model combination fits measured resources")

    def _assess_model(
        self,
        model: ModelMetadata,
        hardware: HardwareProfile,
        *,
        requested_concurrency: int | None = None,
    ) -> tuple[FitStatus, list[str]]:
        reasons: list[str] = []
        unknown = False
        tags = hardware.reading.compatibility_tags
        if model.compatibility and not tags:
            unknown = True
            reasons.append(f"hardware compatibility is unknown for {model.model_id}")
        elif model.compatibility and not model.compatibility.issubset(tags):
            return FitStatus.INCOMPATIBLE, [
                f"{model.model_id} is not compatible with this hardware"
            ]
        if (
            requested_concurrency is not None
            and model.max_concurrency is not None
            and requested_concurrency > model.max_concurrency
        ):
            return FitStatus.INCOMPATIBLE, [f"{model.model_id} cannot serve requested concurrency"]
        if unknown:
            return FitStatus.UNKNOWN, reasons
        return FitStatus.COMPATIBLE, reasons

    def _assess_combination(
        self,
        models: tuple[ModelMetadata, ...],
        model_statuses: list[tuple[FitStatus, list[str]]],
        request: ModelCombinationRequest,
        hardware: HardwareProfile,
    ) -> tuple[FitStatus, list[str], tuple[int | None, int | None, int | None]]:
        reasons = [reason for _status, model_reasons in model_statuses for reason in model_reasons]
        if any(status is FitStatus.INCOMPATIBLE for status, _ in model_statuses):
            return FitStatus.INCOMPATIBLE, reasons, (None, None, None)
        unknown = any(status is FitStatus.UNKNOWN for status, _ in model_statuses)
        required_storage = _sum_known(model.storage_bytes for model in models)
        required_ram = _aggregate_known((model.ram_bytes for model in models), request.simultaneous)
        required_vram = _aggregate_known(
            (model.vram_bytes for model in models), request.simultaneous
        )
        for label, required, available in (
            ("storage", required_storage, hardware.reading.disk_free_bytes),
            ("RAM", required_ram, hardware.reading.ram_bytes),
            ("VRAM", required_vram, hardware.available_vram_bytes),
        ):
            if required is None or available is None:
                unknown = True
                reasons.append(f"{label} capacity is unknown")
            elif required > available:
                return (
                    FitStatus.INCOMPATIBLE,
                    [f"required {label} exceeds available capacity"],
                    (
                        required_storage,
                        required_ram,
                        required_vram,
                    ),
                )
        concurrency = hardware.reading.concurrency_limit
        if concurrency is None:
            unknown = True
            reasons.append("hardware concurrency limit is unknown")
        elif request.max_concurrency > concurrency:
            return (
                FitStatus.INCOMPATIBLE,
                ["requested concurrency exceeds hardware limit"],
                (
                    required_storage,
                    required_ram,
                    required_vram,
                ),
            )
        return (
            FitStatus.UNKNOWN if unknown else FitStatus.COMPATIBLE,
            reasons,
            (required_storage, required_ram, required_vram),
        )

    @staticmethod
    def _incompatible(request: ModelCombinationRequest, reason: str) -> ModelCombination:
        return ModelCombination(
            FitStatus.INCOMPATIBLE,
            tuple((role, "") for role in request.roles),
            (),
            (reason,),
            None,
            None,
            None,
        )

    @staticmethod
    def _unknown(request: ModelCombinationRequest, *reasons: str) -> ModelCombination:
        return ModelCombination(
            FitStatus.UNKNOWN,
            tuple((role, "") for role in request.roles),
            (),
            reasons,
            None,
            None,
            None,
        )


def _bounded_product(
    options: list[tuple[ModelMetadata, ...]],
) -> Iterable[tuple[ModelMetadata, ...]]:
    if not options:
        return ()
    combinations: list[tuple[ModelMetadata, ...]] = [()]
    for role_options in options:
        combinations = [prefix + (model,) for prefix in combinations for model in role_options]
        if len(combinations) > 4_096:
            combinations = combinations[:4_096]
    return tuple(combinations)


def _unique_models(models: tuple[ModelMetadata, ...]) -> tuple[ModelMetadata, ...]:
    return tuple({model.model_id: model for model in models}.values())


def _sum_known(values: Iterable[int | None]) -> int | None:
    values = tuple(values)
    if any(value is None for value in values):
        return None
    return sum(value for value in values if value is not None)


def _aggregate_known(values: Iterable[int | None], simultaneous: bool) -> int | None:
    values = tuple(values)
    if any(value is None for value in values):
        return None
    known = tuple(value for value in values if value is not None)
    return sum(known) if simultaneous else max(known, default=0)


def _system_ram_bytes() -> int | None:
    if os.name == "nt":
        try:

            class MemoryStatusEx(ctypes.Structure):
                _fields_ = [
                    ("length", ctypes.c_ulong),
                    ("memory_load", ctypes.c_ulong),
                    ("total", ctypes.c_ulonglong),
                    ("available", ctypes.c_ulonglong),
                    ("total_page", ctypes.c_ulonglong),
                    ("available_page", ctypes.c_ulonglong),
                    ("total_virtual", ctypes.c_ulonglong),
                    ("available_virtual", ctypes.c_ulonglong),
                    ("available_extended", ctypes.c_ulonglong),
                ]

            status = MemoryStatusEx()
            status.length = ctypes.sizeof(MemoryStatusEx)
            if ctypes.windll.kernel32.GlobalMemoryStatusEx(ctypes.byref(status)):
                return int(status.total)
        except (AttributeError, OSError):
            return None
    if hasattr(os, "sysconf"):
        try:
            return int(os.sysconf("SC_PAGE_SIZE") * os.sysconf("SC_PHYS_PAGES"))
        except (ValueError, OSError):
            return None
    return None


def _text(value: str, name: str, limit: int) -> None:
    if type(value) is not str or not value.strip() or len(value) > limit or "\x00" in value:
        raise HardwareInventoryError(f"{name} is invalid")


def _optional_text(value: str | None, name: str, limit: int) -> None:
    if value is not None:
        _text(value, name, limit)


def _nonnegative_optional(value: int | None, name: str) -> None:
    if value is not None and (type(value) is not int or value < 0):
        raise HardwareInventoryError(f"{name} is invalid")
