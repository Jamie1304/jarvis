"""Focused R3G stewardship composition and lifecycle tests."""

from __future__ import annotations

from datetime import UTC, datetime
from pathlib import Path
from typing import cast
from uuid import UUID

import pytest
from jarvis.acquisition import AcquisitionRequest, ResourceType
from jarvis.applications.manager import ApplicationManager
from jarvis.applications.models import ApplicationRecord, InstallationCandidate
from jarvis.applications.plans import InstallationPlanStore
from jarvis.applications.providers import ApplicationInventoryProvider, PackageProvider
from jarvis.applications.runtime import ApplicationRuntime as ManagedApplicationRuntime
from jarvis.computer.models import LaunchInfo
from jarvis.core.config import Settings
from jarvis.desktop_facade import DesktopApplicationFacade
from jarvis.resources import ResourceGovernor, ResourceSnapshot
from jarvis.runtime import ApplicationRuntime
from jarvis.storage import (
    FileCategory,
    FileClassification,
    FileOwnership,
    PlacementClass,
    ResourcePlacementRequest,
    RetentionState,
    StorageInventoryService,
    StoragePlanner,
    StoragePressurePolicy,
    StorageResourceType,
    VolumeDriveType,
    VolumeObservation,
)
from jarvis.system_stewardship import (
    AcquisitionStewardshipPlan,
    CleanupStewardshipPlan,
    MissingResourceRequirement,
    SecurityFinding,
    SecurityFindingState,
    SecurityHealthService,
    SoftwareHealthService,
    StaleStewardshipPlan,
    StartupEntryEvidence,
    StartupHealthService,
    StewardshipLifecycleState,
    StewardshipOperation,
    SystemStewardshipComposition,
    SystemStewardshipCoordinator,
    TrustedSecurityProviderRegistry,
    UnavailableSecurityProvider,
    UpdateCoordinator,
)

NOW = datetime(2026, 9, 21, tzinfo=UTC)


class EmptyInventory(ApplicationInventoryProvider):
    async def enumerate_installed(self) -> tuple[ApplicationRecord, ...]:
        return ()


class EmptyPackages(PackageProvider):
    async def search(self, semantic_name: str) -> tuple[InstallationCandidate, ...]:
        del semantic_name
        return ()

    async def find_update(self, record: ApplicationRecord) -> InstallationCandidate | None:
        del record
        return None

    async def install(self, candidate: InstallationCandidate, cancellation: object) -> None:
        del candidate, cancellation

    async def update(self, candidate: InstallationCandidate, cancellation: object) -> None:
        del candidate, cancellation


class EmptyRuntime(ManagedApplicationRuntime):
    async def can_launch(self, record: ApplicationRecord) -> bool:
        del record
        return False

    async def launch(self, record: ApplicationRecord) -> LaunchInfo:
        del record
        raise RuntimeError("no applications")

    async def close(self, application_id: str, process_id: int) -> None:
        del application_id, process_id


class SecurityFixture:
    provider_id = "controlled-security-fixture"

    async def observe(self) -> tuple[SecurityFinding, ...]:
        return (
            SecurityFinding(
                self.provider_id,
                "fixture",
                NOW,
                SecurityFindingState.HEALTHY,
                "fixture-result",
                "controlled trusted fixture",
                "fixture-evidence",
            ),
        )


class EmptyStartup:
    async def observe(self) -> tuple[StartupEntryEvidence, ...]:
        return ()


class Telemetry:
    def snapshot(self) -> ResourceSnapshot:
        return ResourceSnapshot(
            NOW,
            cpu_utilization=0.1,
            ram_total_bytes=16_000,
            ram_available_bytes=12_000,
            disk_free_bytes=80_000,
            user_active=False,
            heavy_foreground_workload=False,
        )


class LifecycleRecorder:
    def __init__(self) -> None:
        self.entries: list[tuple[str, dict[str, str]]] = []

    def record_lifecycle(self, kind: str, *, task_id: UUID | None, detail: dict[str, str]) -> None:
        del task_id
        self.entries.append((kind, detail))


def _volume(*, free: int = 50_000) -> VolumeObservation:
    return VolumeObservation(
        "fixture-volume",
        ("C:/fixture",),
        "fixturefs",
        100_000,
        100_000 - free,
        free,
        VolumeDriveType.FIXED,
        "fast",
        "healthy",
        None,
        False,
        True,
        False,
        False,
        NOW,
        "controlled-volume-fixture",
    )


def _coordinator(
    tmp_path: Path, volumes: list[VolumeObservation]
) -> tuple[SystemStewardshipCoordinator, LifecycleRecorder]:
    manager = ApplicationManager(
        EmptyInventory(), EmptyPackages(), EmptyRuntime(), InstallationPlanStore()
    )
    security = SecurityHealthService(
        TrustedSecurityProviderRegistry(
            (SecurityFixture(), UnavailableSecurityProvider("host", target="host"))
        ),
        clock=lambda: NOW,
    )
    system = SystemStewardshipComposition(
        SoftwareHealthService(manager),
        security,
        StartupHealthService(EmptyStartup(), clock=lambda: NOW),
        UpdateCoordinator(manager, clock=lambda: NOW),
    )
    inventory = StorageInventoryService(
        probe=lambda: tuple(volumes),
        pressure_policy=StoragePressurePolicy(
            watch_free_bytes=40_000,
            constrained_free_bytes=20_000,
            critical_free_bytes=5_000,
        ),
        clock=lambda: NOW,
    )
    root = tmp_path / "jarvis-owned"
    root.mkdir()
    candidate = root / "cache.bin"
    candidate.write_bytes(b"cache")

    def classify(path: Path) -> FileClassification:
        assert path == candidate
        return FileClassification(
            FileCategory.JARVIS_OWNED,
            FileOwnership.JARVIS,
            "controlled",
            True,
            False,
            None,
            "trusted-cache-cleanup",
            "regenerable cache",
            "FileSteward safe-delete recovery",
            RetentionState.SAFE_TO_REMOVE,
        )

    recorder = LifecycleRecorder()
    coordinator = SystemStewardshipCoordinator(
        system,
        storage_inventory=inventory,
        storage_planner=StoragePlanner(inventory),
        resource_governor=ResourceGovernor(Telemetry()),
        lifecycle_recorder=recorder,
        cleanup_roots=(root,),
        duplicate_roots=(root,),
        classifier=classify,
        clock=lambda: NOW,
    )
    return coordinator, recorder


@pytest.mark.asyncio
async def test_observation_cleanup_is_truthful_and_plan_is_inert(tmp_path: Path) -> None:
    coordinator, recorder = _coordinator(tmp_path, [_volume()])

    observation = await coordinator.observe()

    assert observation.lifecycle is StewardshipLifecycleState.CLASSIFIED
    assert observation.storage.detected_bytes == 5
    assert observation.storage.safe_candidate_bytes == 5
    assert len(observation.storage.duplicate_groups) == 0
    plan = coordinator.plan_cleanup(observation)
    assert plan.operation is StewardshipOperation.STORAGE_CLEANUP
    assert plan.lifecycle is StewardshipLifecycleState.PLANNED
    cleanup = cast(CleanupStewardshipPlan, plan.payload)
    assert cleanup.candidates[0].path.name == "cache.bin"
    assert recorder.entries[-1][1]["state"] == StewardshipLifecycleState.PLANNED.value


@pytest.mark.asyncio
async def test_stewardship_plan_rejects_changed_volume_evidence(tmp_path: Path) -> None:
    volumes = [_volume()]
    coordinator, _ = _coordinator(tmp_path, volumes)
    observation = await coordinator.observe()
    plan = coordinator.plan_relocation(
        observation,
        ResourcePlacementRequest(
            "cache",
            StorageResourceType.GENERIC,
            10,
            placement_class=PlacementClass.WARM,
        ),
    )
    assert plan.operation is StewardshipOperation.STORAGE_RELOCATION
    volumes[0] = _volume(free=1_000)
    with pytest.raises(StaleStewardshipPlan):
        await coordinator.assert_current(plan)


@pytest.mark.asyncio
async def test_formal_acquisition_plan_preserves_unknown_metadata(tmp_path: Path) -> None:
    coordinator, _ = _coordinator(tmp_path, [_volume()])
    observation = await coordinator.observe()
    request = AcquisitionRequest(
        "fixture-resource",
        ResourceType.DATA,
        "satisfy a trusted fixture requirement",
        source="https://example.invalid/fixture",
        target_location=str(tmp_path / "target.bin"),
        expected_benefit="UNKNOWN",
    )
    plan = coordinator.plan_acquisition(observation, request)
    assert plan.operation is StewardshipOperation.ACQUISITION
    acquisition = cast(AcquisitionStewardshipPlan, plan.payload)
    assert acquisition.presentation.source == request.source
    assert "UNKNOWN" in acquisition.presentation.enables
    assert not (tmp_path / "target.bin").exists()
    missing = MissingResourceRequirement(
        "capability:fixture-resource",
        "trusted-capability-registry",
        "capability-gap:fixture-resource",
        request,
    )
    prepared = coordinator.prepare_missing_resource(observation, missing)
    assert prepared.operation is StewardshipOperation.ACQUISITION


@pytest.mark.asyncio
async def test_runtime_exposes_system_health_projection_without_effects(tmp_path: Path) -> None:
    runtime = ApplicationRuntime.create(
        Settings(app_data_dir=tmp_path / "runtime-data", ai_provider="ollama")
    )
    try:
        facade = DesktopApplicationFacade(runtime)
        view = await facade.system_stewardship_view()
        assert view.lifecycle == StewardshipLifecycleState.CLASSIFIED.value
        assert view.detected_bytes >= view.safe_candidate_bytes
        assert view.observation_id
    finally:
        await runtime.aclose()
