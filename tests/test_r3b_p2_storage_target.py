from __future__ import annotations

import hashlib
import threading
from collections.abc import Iterator
from contextlib import contextmanager
from dataclasses import replace
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

import pytest
from jarvis.acquisition import (
    AcquisitionBroker,
    AcquisitionPolicy,
    AcquisitionPolicyMode,
    AcquisitionRequest,
    AcquisitionRisk,
    AcquisitionStaleTarget,
    ArtifactState,
    BoundedDownloadTransport,
    InMemoryAcquisitionLedger,
    PrivacyImpact,
    ProvenanceMetadata,
    ResourceType,
)
from jarvis.core.config import Settings
from jarvis.runtime import ApplicationRuntime
from jarvis.storage import (
    CleanupClassifier,
    CleanupState,
    FileCategory,
    FileClassifier,
    PlacementStatus,
    ResourcePlacementRequest,
    StoragePlanner,
    StoragePressurePolicy,
    StoragePressureState,
    StorageResourceType,
    VolumeDriveType,
    VolumeObservation,
    classify_storage_pressure,
)

PAYLOAD = b"r3b-p2-deterministic-bytes"


def _volume(
    volume_id: str,
    *,
    free: int,
    capacity: int,
    mount: str,
    system: bool = False,
    read_only: bool = False,
    network: bool = False,
    removable: bool = False,
) -> VolumeObservation:
    from datetime import UTC, datetime

    return VolumeObservation(
        volume_id,
        (mount,),
        "NTFS",
        capacity,
        capacity - free,
        free,
        VolumeDriveType.FIXED,
        "ssd",
        "healthy",
        "encrypted",
        removable,
        system,
        read_only,
        network,
        datetime.now(UTC),
        "p2-test",
    )


@contextmanager
def _source() -> Iterator[str]:
    class Handler(BaseHTTPRequestHandler):
        def do_GET(self) -> None:  # noqa: N802
            self.send_response(200)
            self.send_header("Content-Length", str(len(PAYLOAD)))
            self.end_headers()
            self.wfile.write(PAYLOAD)

        def log_message(self, *_args: object) -> None:
            return

    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield f"http://127.0.0.1:{server.server_port}/payload.bin"
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=5)


def _request(source: str, target: str) -> AcquisitionRequest:
    return AcquisitionRequest(
        "p2-resource",
        ResourceType.DATA,
        "bounded P2 storage acquisition",
        source=source,
        provenance=ProvenanceMetadata(source_identity=source, trusted_source=True),
        download_size_bytes=len(PAYLOAD),
        installed_size_bytes=len(PAYLOAD),
        target_location=target,
        expected_sha256=hashlib.sha256(PAYLOAD).hexdigest(),
        security_risk=AcquisitionRisk.LOW,
        privacy_impact=PrivacyImpact.LOCAL_ONLY,
        jarvis_owned=True,
    )


@pytest.mark.asyncio
async def test_p2_application_runtime_wires_live_target_revalidation_to_owned_storage(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    runtime = ApplicationRuntime.create(
        Settings(app_data_dir=tmp_path / "app-data", ai_provider="ollama")
    )
    assert runtime.container is not None
    container = runtime.container
    planner = container.storage_planner
    inventory = container.storage_inventory
    observed = (_volume("runtime-volume", free=900, capacity=1_000, mount="C:\\"),)
    calls: list[tuple[object, tuple[VolumeObservation, ...]]] = []

    def inspect_owned(service: object) -> tuple[VolumeObservation, ...]:
        assert service is inventory
        return observed

    def validate_owned(
        service: object,
        request: AcquisitionRequest,
        *,
        volumes: tuple[VolumeObservation, ...] | None = None,
    ) -> PlacementStatus:
        assert service is planner
        assert volumes is observed
        calls.append((request, volumes))
        return PlacementStatus.ALREADY_SUITABLE

    monkeypatch.setattr(type(inventory), "inspect", inspect_owned)
    monkeypatch.setattr(type(planner), "validate_acquisition_target", validate_owned)
    revalidator = container.acquisition_broker._target_revalidator  # noqa: SLF001
    assert revalidator is not None
    request = AcquisitionRequest(
        "runtime-bound-resource",
        ResourceType.DATA,
        "runtime-owned target revalidation",
        source="https://example.test/runtime-bound-resource",
        provenance=ProvenanceMetadata(
            source_identity="https://example.test/runtime-bound-resource",
            trusted_source=True,
        ),
        target_location="C:/JARVIS/acquisitions/runtime-bound-resource",
        target_volume_identity="runtime-volume",
        download_size_bytes=100,
        installed_size_bytes=100,
        target_required_headroom_bytes=25,
    )

    assert revalidator(request) is None
    assert calls == [(request, observed)]
    await runtime.aclose()


def test_p2_bound_target_rejects_headroom_identity_and_location_staleness() -> None:
    volume = _volume("system", free=100, capacity=1_000, mount="C:\\")
    planner = StoragePlanner((volume,))
    bound = replace(
        _request("https://example.test/payload", "C:/JARVIS/acquisitions/p2-resource"),
        target_volume_identity="system",
        target_required_headroom_bytes=50,
    )

    assert (
        planner.validate_acquisition_target(bound, volumes=(volume,))
        is PlacementStatus.ALREADY_SUITABLE
    )
    assert (
        planner.validate_acquisition_target(
            replace(bound, target_required_headroom_bytes=100), volumes=(volume,)
        )
        is PlacementStatus.STALE_PLAN
    )
    assert (
        planner.validate_acquisition_target(
            replace(bound, target_volume_identity="disappeared"), volumes=(volume,)
        )
        is PlacementStatus.STALE_PLAN
    )
    assert (
        planner.validate_acquisition_target(
            replace(bound, target_location="C:/JARVIS/acquisitions/other"), volumes=(volume,)
        )
        is PlacementStatus.STALE_PLAN
    )


def test_p2_pressure_placement_avoids_constrained_system_and_preserves_ample_current() -> None:
    policy = StoragePressurePolicy()
    constrained = _volume(
        "system", free=2 * 1024**3, capacity=128 * 1024**3, mount="C:\\", system=True
    )
    ample = _volume("capacity", free=900 * 1024**3, capacity=1024 * 1024**3, mount="E:\\")
    assert classify_storage_pressure(constrained, policy) in {
        StoragePressureState.CONSTRAINED,
        StoragePressureState.CRITICAL,
    }
    planner = StoragePlanner((constrained, ample))
    selected = planner.plan(
        ResourcePlacementRequest("large", StorageResourceType.DATASET, 100 * 1024**3)
    )
    assert selected.status is PlacementStatus.RECOMMENDED
    assert selected.target_volume_id == "capacity"
    assert any("free_bytes=" in item for item in selected.evidence)

    ample_system = _volume(
        "system", free=900 * 1024**3, capacity=1024 * 1024**3, mount="C:\\", system=True
    )
    current = planner.plan(
        ResourcePlacementRequest(
            "already-there", StorageResourceType.DATASET, 100, current_volume_id="system"
        ),
        volumes=(ample_system, ample),
    )
    assert current.status is PlacementStatus.ALREADY_SUITABLE
    assert current.target_volume_id == "system"


def test_p2_unknown_or_protected_volume_is_not_a_pressure_solution() -> None:
    planner = StoragePlanner(
        (
            _volume("system", free=10, capacity=100, mount="C:\\", system=True),
            _volume("readonly", free=900, capacity=1_000, mount="R:\\", read_only=True),
            _volume("network", free=900, capacity=1_000, mount="N:\\", network=True),
        )
    )
    plan = planner.plan(ResourcePlacementRequest("safe", StorageResourceType.DATASET, 50))
    assert plan.status is PlacementStatus.NO_COMPATIBLE_TARGET

    protected = Path("C:/Windows")
    classification = FileClassifier(protected_roots=(protected,)).classify(protected / "system.dll")
    assert classification.category is FileCategory.SYSTEM_CRITICAL
    assert classification.owner.value == "system"
    assert (
        CleanupClassifier().candidate(protected / "system.dll", classification).state
        is CleanupState.PROTECTED
    )


@pytest.mark.asyncio
async def test_p2_live_target_revalidation_has_zero_effect_and_positive_hash_verified_effect(
    tmp_path: Path,
) -> None:
    with _source() as source:
        state = {"valid": True}
        ledger = InMemoryAcquisitionLedger()
        broker = AcquisitionBroker(
            BoundedDownloadTransport(tmp_path / "trusted"),
            AcquisitionPolicy(
                AcquisitionPolicyMode.JARVIS_MANAGED, require_known_disk_capacity=False
            ),
            ledger,
            target_revalidator=lambda _request: None
            if state["valid"]
            else "free space is insufficient",
        )
        stale = _request(source, "resources/stale.bin")
        state["valid"] = False
        with pytest.raises(AcquisitionStaleTarget, match="free space"):
            await broker.acquire(stale, disk_free_bytes=10_000)
        assert not (tmp_path / "trusted" / "resources" / "stale.bin").exists()
        assert ledger.get(stale.fingerprint) is not None
        assert ledger.get(stale.fingerprint).state is ArtifactState.FAILED  # type: ignore[union-attr]

        state["valid"] = True
        positive = _request(source, "resources/positive.bin")
        result = await broker.acquire(positive, disk_free_bytes=10_000)
        assert result.materialized_path is not None
        assert result.materialized_path.read_bytes() == PAYLOAD
        assert result.integrity is not None and result.integrity.verified is True
        await broker.aclose()
