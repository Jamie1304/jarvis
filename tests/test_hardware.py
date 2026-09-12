"""Deterministic hardware/model inventory tests; no real model is loaded."""

from datetime import UTC, datetime
from pathlib import Path
from typing import Any, cast

import pytest
from jarvis.ai.models import EvidenceKind, EvidenceRecord, ModelRole
from jarvis.ai.providers.registry import (
    ModelMetadata,
    ProviderDefinition,
    ProviderMetadata,
    ProviderRegistry,
)
from jarvis.hardware import (
    FitStatus,
    GpuInfo,
    HardwareInventoryError,
    HardwareInventoryService,
    HardwareProfile,
    HardwareReading,
    ModelCombinationRequest,
    ModelInventory,
    ModelMeasurement,
    ModelPlanner,
    RuntimeInfo,
    SystemHardwareProbe,
)

from tests.fakes import FakeAIProvider

NOW = datetime(2026, 1, 1, tzinfo=UTC)
GB = 1024**3


def _evidence(kind: EvidenceKind = EvidenceKind.PUBLISHED) -> EvidenceRecord:
    return EvidenceRecord(
        kind,
        "https://models.example.test/card",
        "Published model card",
        captured_at=NOW if kind is not EvidenceKind.PUBLISHED else None,
        machine_scope="this_machine" if kind is EvidenceKind.MEASURED_ON_THIS_MACHINE else None,
    )


def _hardware(
    *,
    ram: int | None = 16 * GB,
    vram: int | None = 8 * GB,
    disk: int | None = 32 * GB,
    concurrency: int | None = 4,
    tags: frozenset[str] = frozenset({"windows", "x86_64", "cpu", "cuda"}),
) -> HardwareProfile:
    devices = None if vram is None else (GpuInfo("Fixture GPU", vram, "fixture-driver"),)
    return HardwareProfile(
        HardwareReading(
            cpu_model="Fixture CPU",
            cpu_physical_cores=8,
            cpu_logical_cores=16,
            ram_bytes=ram,
            gpu_devices=devices,
            runtimes=(RuntimeInfo("cuda", "12.4"), RuntimeInfo("python", "3.13")),
            disk_free_bytes=disk,
            os_name="Windows",
            os_version="fixture",
            architecture="x86_64",
            concurrency_limit=concurrency,
            compatibility_tags=tags,
        ),
        (_evidence(EvidenceKind.MEASURED_ON_THIS_MACHINE),),
    )


def _model(
    model_id: str,
    roles: frozenset[ModelRole],
    *,
    storage: int | None = 1 * GB,
    ram: int | None = 2 * GB,
    vram: int | None = 0,
    compatibility: frozenset[str] = frozenset({"windows", "x86_64"}),
    evidence: tuple[EvidenceRecord, ...] = (),
) -> ModelMetadata:
    return ModelMetadata(
        model_id,
        8_192,
        frozenset({"structured-output"}),
        roles,
        "fixture-family",
        "1.0",
        "Q4",
        "fixture-runtime",
        "https://models.example.test/source",
        frozenset({"text"}),
        storage,
        ram,
        vram,
        "fixture-license",
        compatibility,
        evidence,
    )


class _FakeProbe:
    def __init__(self, reading: HardwareReading) -> None:
        self.reading = reading

    def read(self) -> HardwareReading:
        return self.reading


def test_hardware_inventory_wraps_fake_readings_as_measured() -> None:
    reading = _hardware().reading
    service = HardwareInventoryService(_FakeProbe(reading), clock=lambda: NOW)
    profile = service.inspect()

    assert profile.reading == reading
    assert profile.evidence[0].kind is EvidenceKind.MEASURED_ON_THIS_MACHINE
    assert profile.evidence[0].machine_scope == "this_machine"
    assert service.last == profile
    assert profile.available_vram_bytes == 8 * GB
    assert _hardware(vram=None).available_vram_bytes is None


def test_hardware_inventory_rejects_bad_probe_and_clock() -> None:
    with pytest.raises(HardwareInventoryError, match="probe"):
        HardwareInventoryService(_FakeProbe(cast(Any, object()))).inspect()
    with pytest.raises(HardwareInventoryError, match="clock"):
        HardwareInventoryService(
            _FakeProbe(_hardware().reading), clock=lambda: datetime(2026, 1, 1)
        ).inspect()


def test_system_probe_is_conservative_about_unknown_gpu_and_records_host_facts(
    tmp_path: Path,
) -> None:
    reading = SystemHardwareProbe(disk_root=tmp_path).read()
    assert reading.os_name
    assert reading.architecture
    assert reading.gpu_devices is None
    assert reading.runtimes[0].name == "python"
    assert reading.concurrency_limit is None


def test_model_metadata_tracks_roles_resources_license_and_provenance() -> None:
    model = _model(
        "vision",
        frozenset({ModelRole.VISION, ModelRole.GENERAL}),
        evidence=(_evidence(), _evidence(EvidenceKind.COMMUNITY)),
    )
    assert model.roles == frozenset({ModelRole.VISION, ModelRole.GENERAL})
    assert model.quantization == "Q4"
    assert model.storage_bytes == GB
    assert model.license == "fixture-license"
    assert {item.kind for item in model.evidence} == {
        EvidenceKind.PUBLISHED,
        EvidenceKind.COMMUNITY,
    }
    assert tuple(ModelRole) == (
        ModelRole.GENERAL,
        ModelRole.REASONING,
        ModelRole.CODING,
        ModelRole.TOOL_USE,
        ModelRole.VISION,
        ModelRole.EMBEDDING,
        ModelRole.RERANKING,
        ModelRole.STT,
        ModelRole.TTS,
        ModelRole.IMAGE_GENERATION,
    )


def test_measured_evidence_requires_timestamp_and_machine_scope() -> None:
    with pytest.raises(ValueError, match="machine"):
        EvidenceRecord(EvidenceKind.MEASURED_ON_THIS_MACHINE, "probe", "detail")
    with pytest.raises(ValueError, match="Only measured"):
        EvidenceRecord(EvidenceKind.COMMUNITY, "community", "detail", machine_scope="this_machine")
    with pytest.raises(ValueError, match="metrics"):
        EvidenceRecord(
            EvidenceKind.PUBLISHED,
            "source",
            "detail",
            metrics=cast(tuple[tuple[str, str], ...], [("x", "y")]),
        )

    with pytest.raises(ValueError, match="kind"):
        EvidenceRecord(cast(EvidenceKind, "published"), "source", "detail")
    with pytest.raises(ValueError, match="source"):
        EvidenceRecord(EvidenceKind.PUBLISHED, "", "detail")
    with pytest.raises(ValueError, match="detail"):
        EvidenceRecord(EvidenceKind.PUBLISHED, "source", "")
    with pytest.raises(ValueError, match="timestamp"):
        EvidenceRecord(EvidenceKind.PUBLISHED, "source", "detail", captured_at=datetime(2026, 1, 1))


def test_inventory_measurement_updates_only_measured_values() -> None:
    inventory = ModelInventory((_model("general", frozenset({ModelRole.GENERAL}), ram=None),))
    measurement = ModelMeasurement(
        "general",
        NOW,
        "trusted.fixture.benchmark",
        peak_ram_bytes=3 * GB,
        throughput=12.5,
        concurrency=2,
    )
    updated = inventory.record_measurement(measurement)

    assert updated.ram_bytes == 3 * GB
    assert updated.storage_bytes == GB
    assert updated.vram_bytes == 0
    assert updated.max_concurrency == 2
    assert updated.evidence[-1].kind is EvidenceKind.MEASURED_ON_THIS_MACHINE
    assert ("throughput", "12.5") in updated.evidence[-1].metrics
    assert inventory.inspect("general") == updated

    limited = ModelPlanner(ModelInventory((updated,))).plan(
        ModelCombinationRequest((ModelRole.GENERAL,), max_concurrency=3), _hardware()
    )
    assert limited.status is FitStatus.INCOMPATIBLE


def test_model_planner_selects_a_combination_with_measured_resources() -> None:
    inventory = ModelInventory(
        (
            _model("general", frozenset({ModelRole.GENERAL, ModelRole.CODING})),
            _model("vision", frozenset({ModelRole.VISION}), ram=3 * GB, vram=2 * GB),
            _model("embedding", frozenset({ModelRole.EMBEDDING}), ram=1 * GB),
        )
    )
    plan = ModelPlanner(inventory).plan(
        ModelCombinationRequest(
            (ModelRole.GENERAL, ModelRole.VISION, ModelRole.EMBEDDING),
            max_concurrency=3,
        ),
        _hardware(),
    )

    assert plan.status is FitStatus.COMPATIBLE
    assert plan.assignments == (
        (ModelRole.GENERAL, "general"),
        (ModelRole.VISION, "vision"),
        (ModelRole.EMBEDDING, "embedding"),
    )
    assert plan.required_ram_bytes == 6 * GB
    assert plan.required_vram_bytes == 2 * GB


def test_model_planner_honors_simultaneous_resources_and_concurrency() -> None:
    inventory = ModelInventory(
        (
            _model("general", frozenset({ModelRole.GENERAL}), ram=10 * GB),
            _model("vision", frozenset({ModelRole.VISION}), ram=10 * GB),
        )
    )
    planner = ModelPlanner(inventory)
    simultaneous = planner.plan(
        ModelCombinationRequest((ModelRole.GENERAL, ModelRole.VISION), max_concurrency=2),
        _hardware(ram=12 * GB),
    )
    sequential = planner.plan(
        ModelCombinationRequest(
            (ModelRole.GENERAL, ModelRole.VISION), max_concurrency=1, simultaneous=False
        ),
        _hardware(ram=12 * GB),
    )
    denied_concurrency = planner.plan(
        ModelCombinationRequest((ModelRole.GENERAL,), max_concurrency=8),
        _hardware(concurrency=4),
    )

    assert simultaneous.status is FitStatus.INCOMPATIBLE
    assert sequential.status is FitStatus.COMPATIBLE
    assert sequential.required_ram_bytes == 10 * GB
    assert denied_concurrency.status is FitStatus.INCOMPATIBLE


@pytest.mark.parametrize(
    "hardware",
    (
        _hardware(ram=None),
        _hardware(vram=None),
        _hardware(disk=None),
        _hardware(concurrency=None),
    ),
)
def test_model_planner_does_not_turn_unknown_capacity_into_compatibility(
    hardware: HardwareProfile,
) -> None:
    model = _model("vision", frozenset({ModelRole.VISION}), vram=2 * GB)
    result = ModelPlanner(ModelInventory((model,))).plan(
        ModelCombinationRequest((ModelRole.VISION,)), hardware
    )
    assert result.status is FitStatus.UNKNOWN


def test_model_planner_reports_unknown_model_resources_and_tags() -> None:
    unknown_model = _model(
        "unknown",
        frozenset({ModelRole.GENERAL}),
        storage=None,
        ram=None,
        vram=None,
    )
    planner = ModelPlanner(ModelInventory((unknown_model,)))
    unknown_resources = planner.plan(ModelCombinationRequest((ModelRole.GENERAL,)), _hardware())
    unknown_tags = planner.assess(
        _model("tagged", frozenset({ModelRole.GENERAL}), compatibility=frozenset({"cuda"})),
        _hardware(tags=frozenset()),
    )
    assert unknown_resources.status is FitStatus.UNKNOWN
    assert unknown_tags.status is FitStatus.UNKNOWN


@pytest.mark.asyncio
async def test_provider_model_fallback_and_definition_boundary() -> None:
    provider = FakeAIProvider()
    registry = ProviderRegistry(
        (
            ProviderDefinition(
                ProviderMetadata("fake", "Fake", "1"),
                lambda _configuration: provider,
            ),
        )
    )
    metadata = await registry.model("fake", provider)
    assert metadata.model_id == "fake-model"
    with pytest.raises(ValueError, match="definition"):
        ProviderDefinition(ProviderMetadata("fake", "Fake", "1"), cast(Any, None))


def test_model_planner_requires_local_measurements_when_requested() -> None:
    inventory = ModelInventory((_model("general", frozenset({ModelRole.GENERAL})),))
    planner = ModelPlanner(inventory)
    request = ModelCombinationRequest((ModelRole.GENERAL,), require_measured_evidence=True)
    assert planner.plan(request, _hardware()).status is FitStatus.UNKNOWN

    inventory.record_measurement(ModelMeasurement("general", NOW, "fixture", peak_ram_bytes=2 * GB))
    assert planner.plan(request, _hardware()).status is FitStatus.COMPATIBLE


def test_model_planner_reports_missing_roles_and_incompatible_tags() -> None:
    inventory = ModelInventory((_model("general", frozenset({ModelRole.GENERAL})),))
    planner = ModelPlanner(inventory)
    missing = planner.plan(
        ModelCombinationRequest((ModelRole.STT,)),
        _hardware(),
    )
    incompatible = planner.plan(
        ModelCombinationRequest((ModelRole.GENERAL,)),
        _hardware(tags=frozenset({"linux", "cpu"})),
    )

    assert missing.status is FitStatus.INCOMPATIBLE
    assert incompatible.status is FitStatus.INCOMPATIBLE
    assert planner.assess(inventory.inspect("general"), _hardware()).status is FitStatus.COMPATIBLE


def test_inventory_and_planner_fail_closed_on_malformed_boundaries() -> None:
    with pytest.raises(HardwareInventoryError):
        HardwareReading(cpu_logical_cores=-1)
    with pytest.raises(HardwareInventoryError):
        HardwareReading(compatibility_tags=cast(frozenset[str], {"cpu"}))
    with pytest.raises(HardwareInventoryError):
        HardwareReading(gpu_devices=cast(tuple[GpuInfo, ...], ("gpu",)))
    with pytest.raises(HardwareInventoryError):
        HardwareReading(runtimes=cast(tuple[RuntimeInfo, ...], ("runtime",)))
    with pytest.raises(HardwareInventoryError):
        HardwareProfile(_hardware().reading, cast(tuple[EvidenceRecord, ...], ("bad",)))
    with pytest.raises(HardwareInventoryError):
        GpuInfo("gpu", vram_bytes=-1)
    with pytest.raises(HardwareInventoryError):
        RuntimeInfo("", "1")
    with pytest.raises(HardwareInventoryError):
        ModelMeasurement("model", NOW, "fixture", throughput=float("nan"))
    with pytest.raises(HardwareInventoryError):
        ModelCombinationRequest((), max_concurrency=1)
    with pytest.raises(HardwareInventoryError):
        ModelCombinationRequest((ModelRole.GENERAL,), max_concurrency=0)
    with pytest.raises(HardwareInventoryError):
        ModelCombinationRequest((ModelRole.GENERAL,), max_concurrency=cast(Any, "2"))
    with pytest.raises(HardwareInventoryError):
        ModelCombinationRequest((ModelRole.GENERAL,), simultaneous=cast(Any, "yes"))
    with pytest.raises(HardwareInventoryError):
        ModelCombinationRequest((cast(ModelRole, "general"),))
    with pytest.raises(HardwareInventoryError):
        ModelInventory(
            (
                _model("duplicate", frozenset({ModelRole.GENERAL})),
                _model("duplicate", frozenset({ModelRole.GENERAL})),
            )
        )


def test_model_metadata_and_provider_fallback_reject_malformed_metadata() -> None:
    base = dict(
        model_id="model",
        context_limit=1,
        capabilities=frozenset(),
    )
    invalid = (
        {**base, "capabilities": cast(Any, {"x"})},
        {**base, "roles": cast(Any, {"general"})},
        {**base, "family": "\x00"},
        {**base, "modalities": cast(Any, {"text"})},
        {**base, "compatibility": cast(Any, {"windows"})},
        {**base, "storage_bytes": -1},
        {**base, "max_concurrency": 0},
        {**base, "evidence": cast(Any, [_evidence()])},
    )
    for values in invalid:
        with pytest.raises(ValueError):
            ModelMetadata(**values)

    with pytest.raises(ValueError, match="invalid"):
        ModelMetadata("", 1)
    with pytest.raises(ValueError, match="invalid"):
        ModelMetadata("model", 0)
