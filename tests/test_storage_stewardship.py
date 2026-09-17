"""Deterministic and real-bytes R3B storage/file stewardship acceptance."""

from __future__ import annotations

import asyncio
import hashlib
import json
import os
import subprocess
import sys
import time
from collections.abc import Coroutine
from dataclasses import replace
from datetime import UTC, datetime, timedelta
from pathlib import Path
from types import SimpleNamespace
from typing import Any, TypeVar, cast
from uuid import UUID, uuid4

import jarvis.storage as storage_module
import pytest
from jarvis.acquisition import (
    AcquisitionRequest,
    AcquisitionRisk,
    PrivacyImpact,
    ProvenanceMetadata,
    ResourceType,
)
from jarvis.permissions import (
    ApprovalActorKind,
    ApprovalChoice,
    ApprovalIdentity,
    ApprovalSource,
    Decision,
    Permission,
    PermissionBroker,
    PolicyEngine,
    PolicyRule,
    ScopeConstraint,
    TrustedApprovalAuthenticator,
)
from jarvis.permissions.audit import InMemoryAuditSink
from jarvis.storage import (
    CleanupClassifier,
    CleanupState,
    DownloadState,
    DuplicateDetector,
    EmergencyRecoveryPlanner,
    FileCategory,
    FileClassification,
    FileClassifier,
    FileOwnership,
    FileSteward,
    ForecastState,
    ManifestIntegrityError,
    MutationApprovalRequired,
    MutationConflict,
    MutationDenied,
    MutationItem,
    MutationManifestStore,
    MutationOperation,
    MutationState,
    MutationUnknownOutcome,
    PlacementClass,
    PlacementStatus,
    ResourcePlacementRequest,
    RetentionState,
    StalePlan,
    StorageDeferred,
    StorageError,
    StorageForecast,
    StorageHistorySnapshot,
    StorageHistoryStore,
    StorageInventoryService,
    StoragePlanner,
    StoragePressurePolicy,
    StoragePressureState,
    StorageResourceType,
    VolumeDriveType,
    VolumeObservation,
    classify_storage_pressure,
    forecast_storage_pressure,
)
from jarvis.vm.bridge import HostBridge, HostBridgeOperation, HostBridgeRequest


def _volume(
    volume_id: str,
    *,
    free: int = 100,
    capacity: int = 1_000,
    mount: str = "C:\\",
    system: bool | None = False,
    speed: str | None = None,
    read_only: bool | None = False,
    removable: bool | None = False,
    network: bool | None = False,
) -> VolumeObservation:
    return VolumeObservation(
        volume_id,
        (mount,),
        "NTFS",
        capacity,
        capacity - free,
        free,
        VolumeDriveType.FIXED,
        speed,
        None,
        None,
        removable,
        system,
        read_only,
        network,
        datetime.now(UTC),
        "test-trusted-volume-adapter",
    )


def _classification(
    category: FileCategory = FileCategory.JARVIS_OWNED,
    *,
    owner: FileOwnership = FileOwnership.JARVIS,
    active: bool | None = False,
    retention: RetentionState = RetentionState.SAFE_TO_REMOVE,
    mechanism: str | None = "steward.cleanup",
    recovery: str | None = "recovery-stage",
    intentional: bool = False,
) -> FileClassification:
    return FileClassification(
        category,
        owner,
        "trusted-test-evidence",
        True,
        active,
        datetime.now(UTC),
        mechanism,
        "regenerable acceptance-owned bytes",
        recovery,
        retention,
        intentional,
        ("acceptance-owned",),
    )


def _broker(root: Path) -> tuple[PermissionBroker, TrustedApprovalAuthenticator]:
    authenticator = TrustedApprovalAuthenticator(source=ApprovalSource.TRUSTED_UI)
    broker = PermissionBroker(
        PolicyEngine(
            (
                PolicyRule(
                    "storage.test-root",
                    Permission.FILESYSTEM_WRITE,
                    Decision.ALLOW,
                    ScopeConstraint(
                        paths=(str(root),),
                        tools=frozenset({"storage.file_steward"}),
                    ),
                    frozenset(
                        {
                            "storage.file.copy",
                            "storage.file.move",
                            "storage.file.rename",
                            "storage.file.safe_delete",
                            "storage.file.restore",
                        }
                    ),
                ),
            )
        ),
        approval_context_verifier=authenticator.verifier(),
    )
    return broker, authenticator


async def _approve_delete(
    broker: PermissionBroker,
    authenticator: TrustedApprovalAuthenticator,
    task_id: UUID,
) -> None:
    pending = await broker.pending_approvals(task_id)
    assert len(pending) == 1
    request = pending[0]
    context = authenticator.issue_context(
        request_id=request.request_id,
        choice=ApprovalChoice.APPROVE_ONCE,
        identity=ApprovalIdentity("acceptance-user", ApprovalActorKind.TRUSTED_USER),
    )
    decision = await broker.decide(context)
    assert decision.accepted is True


_Result = TypeVar("_Result")


def _run(coroutine: Coroutine[Any, Any, _Result]) -> _Result:
    return asyncio.run(coroutine)


def test_real_host_inventory_is_read_only_and_unknown_facts_stay_unknown() -> None:
    observations = StorageInventoryService().inspect()
    assert observations
    assert all(item.volume_id for item in observations)
    assert all(item.capacity_bytes is None or item.capacity_bytes >= 0 for item in observations)
    assert all(item.speed_class is None for item in observations)
    assert all(item.health is None for item in observations)
    assert all(item.encryption is None for item in observations)
    assert all(item.mount_points for item in observations)


def test_inventory_history_pressure_and_bounded_forecast(tmp_path: Path) -> None:
    history = StorageHistoryStore(tmp_path / "history.sqlite3", max_snapshots=3)
    first = _volume("volume-a", free=900)
    service = StorageInventoryService(
        probe=lambda: (first,),
        history=history,
        pressure_policy=StoragePressurePolicy(
            watch_free_bytes=300,
            constrained_free_bytes=200,
            critical_free_bytes=100,
            watch_free_ratio=0.3,
            constrained_free_ratio=0.2,
            critical_free_ratio=0.1,
        ),
    )
    assert service.inspect() == (first,)
    assert service.pressure("volume-a") is StoragePressureState.HEALTHY
    assert (
        classify_storage_pressure(
            VolumeObservation(
                "unknown",
                ("C:\\",),
                None,
                None,
                None,
                None,
                None,
                None,
                None,
                None,
                None,
                None,
                None,
                None,
                datetime.now(UTC),
                "test",
            ),
            StoragePressurePolicy(),
        )
        is StoragePressureState.UNKNOWN
    )
    now = datetime(2026, 1, 1, tzinfo=UTC)
    samples = tuple(
        StorageHistorySnapshot(
            "volume-a",
            now + timedelta(days=index),
            1_000,
            100 + index * 100,
            900 - index * 100,
            StoragePressureState.WATCH,
        )
        for index in range(3)
    )
    forecast = forecast_storage_pressure(samples, "volume-a", threshold_bytes=500)
    assert forecast.state is ForecastState.DECLINING
    assert forecast.threshold_crossing_at is not None
    assert forecast.evidence_count == 3
    assert (
        forecast_storage_pressure(samples[:1], "volume-a").state
        is ForecastState.INSUFFICIENT_EVIDENCE
    )
    assert (
        forecast_storage_pressure(samples, "new-volume").state
        is ForecastState.INSUFFICIENT_EVIDENCE
    )
    history.close()


def test_forecast_reclamation_discontinuity_and_stable_usage() -> None:
    now = datetime(2026, 1, 1, tzinfo=UTC)
    samples = (
        StorageHistorySnapshot("v", now, 1_000, 500, 500, StoragePressureState.WATCH),
        StorageHistorySnapshot(
            "v", now + timedelta(days=1), 1_000, 600, 400, StoragePressureState.WATCH
        ),
        StorageHistorySnapshot(
            "v", now + timedelta(days=2), 1_000, 300, 700, StoragePressureState.HEALTHY
        ),
        StorageHistorySnapshot(
            "v", now + timedelta(days=3), 1_000, 300, 700, StoragePressureState.HEALTHY
        ),
    )
    forecast = forecast_storage_pressure(samples, "v")
    assert forecast.state in {ForecastState.STABLE, ForecastState.DECLINING}
    assert "discontinuity" in forecast.reason


def test_pressure_uses_absolute_ratio_headroom_and_incoming_bytes() -> None:
    policy = StoragePressurePolicy(
        watch_free_bytes=300,
        constrained_free_bytes=200,
        critical_free_bytes=100,
        watch_free_ratio=0.3,
        constrained_free_ratio=0.2,
        critical_free_ratio=0.1,
        required_headroom_bytes=20,
    )
    assert classify_storage_pressure(_volume("v", free=500), policy) is StoragePressureState.HEALTHY
    assert classify_storage_pressure(_volume("v", free=250), policy) is StoragePressureState.WATCH
    assert (
        classify_storage_pressure(_volume("v", free=180), policy)
        is StoragePressureState.CONSTRAINED
    )
    assert (
        classify_storage_pressure(_volume("v", free=110), policy, incoming_bytes=20)
        is StoragePressureState.CRITICAL
    )


def test_storage_planner_selects_capacity_volume_and_preserves_unknown_routes() -> None:
    system = _volume("system", free=100, capacity=128, mount="C:\\", system=True, speed="fast")
    capacity = _volume("capacity", free=900, capacity=1_000, mount="E:\\", speed=None)
    planner = StoragePlanner((system, capacity))
    request = ResourcePlacementRequest(
        "archive-1", StorageResourceType.ARCHIVE, 200, PlacementClass.ARCHIVE
    )
    plan = planner.plan(request)
    assert plan.status is PlacementStatus.RECOMMENDED
    assert plan.target_volume_id == "capacity"
    assert plan.expected_free_after_bytes == 700
    hot = planner.plan(
        ResourcePlacementRequest("vm", StorageResourceType.VM_IMAGE, 10, PlacementClass.HOT, True)
    )
    assert hot.status is PlacementStatus.RECOMMENDED
    assert hot.target_volume_id == "system"
    app = planner.plan(
        ResourcePlacementRequest("app", StorageResourceType.GENERIC, 1, application_managed=True)
    )
    assert app.status is PlacementStatus.RELOCATION_UNSUPPORTED
    unknown = planner.plan(ResourcePlacementRequest("unknown", StorageResourceType.DATASET, None))
    assert unknown.status is PlacementStatus.UNKNOWN_COMPATIBILITY


def test_acquisition_target_binding_and_stale_target() -> None:
    root = Path("C:\\") if os.name == "nt" else Path("/")
    volume = _volume("capacity", free=10_000, capacity=20_000, mount=str(root))
    planner = StoragePlanner((volume,))
    request = AcquisitionRequest(
        "large-data",
        ResourceType.DATA,
        "acceptance acquisition",
        source="https://example.invalid/data",
        provenance=ProvenanceMetadata(trusted_source=True),
        download_size_bytes=100,
        installed_size_bytes=100,
        security_risk=AcquisitionRisk.LOW,
        privacy_impact=PrivacyImpact.LOCAL_ONLY,
        jarvis_owned=True,
    )
    plan = planner.plan_acquisition(request, required_headroom_bytes=100)
    bound = planner.bind_acquisition(request, plan)
    assert bound.target_volume_identity == "capacity"
    assert bound.target_location is not None
    assert planner.validate_acquisition_target(bound) is PlacementStatus.ALREADY_SUITABLE
    assert (
        planner.validate_acquisition_target(
            bound, volumes=(_volume("replacement", free=10_000, capacity=20_000),)
        )
        is PlacementStatus.STALE_PLAN
    )


def test_classifier_cleanup_and_download_hygiene_are_conservative(tmp_path: Path) -> None:
    owned = tmp_path / "owned"
    owned.mkdir()
    file = owned / "temp.bin"
    file.write_bytes(b"temp")
    classifier = CleanupClassifier()
    candidate = classifier.candidate(file, _classification())
    assert candidate.state is CleanupState.ELIGIBLE
    assert candidate.expected_reclaimed_bytes == 4
    assert classifier.candidate(file, _classification(active=None)).state is CleanupState.UNKNOWN
    assert (
        classifier.candidate(file, _classification(intentional=True)).state
        is CleanupState.PROTECTED
    )
    assert (
        classifier.candidate(file, _classification(FileCategory.MODEL_STORAGE)).state
        is CleanupState.DELEGATE
    )
    path_classifier = FileClassifier(jarvis_roots=(owned,))
    assert path_classifier.classify(file).category is FileCategory.JARVIS_OWNED
    assert classifier.downloads_state(active=True, age_days=100) is DownloadState.ACTIVE
    assert classifier.downloads_state(active=False, age_days=1) is DownloadState.RECENT
    assert classifier.downloads_state(active=False, age_days=40) is DownloadState.STALE
    assert classifier.downloads_state(active=None, age_days=40) is DownloadState.UNKNOWN
    assert (
        classifier.downloads_state(active=False, age_days=2, exact_duplicate=True)
        is DownloadState.DUPLICATE
    )


def test_duplicate_detector_requires_full_hash_and_does_not_count_hardlinks(tmp_path: Path) -> None:
    root = tmp_path / "dataset"
    root.mkdir()
    first = root / "one.bin"
    second = root / "two.bin"
    different = root / "same-name.bin"
    first.write_bytes(b"same bytes")
    second.write_bytes(b"same bytes")
    different.write_bytes(b"other data")
    hardlink = root / "hardlink.bin"
    try:
        os.link(first, hardlink)
    except OSError:
        hardlink = first
    detector = DuplicateDetector(max_files=20, max_bytes=1_000)
    groups = detector.scan(
        (root,),
        classifier=lambda path: _classification(
            FileCategory.JARVIS_OWNED if path.name != "same-name.bin" else FileCategory.USER_DATA
        ),
    )
    assert len(groups) == 1
    group = groups[0]
    assert group.exact is True
    assert group.content_hash == hashlib.sha256(b"same bytes").hexdigest()
    assert group.reclaimable_bytes == 10
    assert group.safe_reclaimable_bytes == 10
    assert all(item.content_hash for item in group.files)


def test_duplicate_detector_skips_reparse_paths_and_intentional_copies(tmp_path: Path) -> None:
    root = tmp_path / "dataset"
    outside = tmp_path / "outside"
    root.mkdir()
    outside.mkdir()
    (outside / "escape.bin").write_bytes(b"escape")
    (root / "copy-a").write_bytes(b"bytes")
    (root / "copy-b").write_bytes(b"bytes")
    link = root / "link"
    try:
        link.symlink_to(outside, target_is_directory=True)
    except OSError:
        link = root / "not-created"
    groups = DuplicateDetector().scan((root,), intentional_copies=(root / "copy-b",))
    assert all(item.path != outside / "escape.bin" for group in groups for item in group.files)
    if groups:
        assert groups[0].safe_reclaimable_bytes == 0


def test_emergency_plan_is_bounded_and_reports_shortfall(tmp_path: Path) -> None:
    path = tmp_path / "safe.tmp"
    path.write_bytes(b"x" * 10)
    candidate = CleanupClassifier().candidate(path, _classification(FileCategory.TEMPORARY))
    system = _volume("system", free=1, capacity=100, system=True)
    plan = EmergencyRecoveryPlanner().plan(system, (candidate,), target_bytes=100)
    assert plan.status == "SAFE_SHORTFALL"
    assert plan.expected_reclaimable_bytes == 10
    assert plan.shortfall_bytes == 90


def test_file_steward_real_copy_move_rename_delete_restore_and_manifest_restart(
    tmp_path: Path,
) -> None:
    root = tmp_path / "owned"
    root.mkdir()
    source = root / "source.txt"
    source.write_bytes(b"recovery-aware bytes")
    broker, authenticator = _broker(root)
    steward = FileSteward(root, permission_broker=broker, host_bridge=HostBridge())

    copied = steward.plan_copy(source, root / "copy.txt")
    copy_result = _run(steward.execute_async(copied))
    assert copy_result.success
    assert (root / "copy.txt").read_bytes() == source.read_bytes()

    movable = _classification(FileCategory.MOVABLE_USER_DATA, owner=FileOwnership.USER)
    moved = steward.plan_move(source, root / "moved.txt", classification=movable)
    move_result = _run(steward.execute_async(moved))
    assert move_result.success
    renamed = steward.plan_rename(root / "moved.txt", root / "renamed.txt", classification=movable)
    assert _run(steward.execute_async(renamed)).success

    delete = steward.plan_delete(root / "renamed.txt", classification=_classification())
    with pytest.raises(MutationApprovalRequired):
        _run(steward.execute_async(delete))
    _run(_approve_delete(broker, authenticator, delete.task_id))
    deleted = _run(steward.execute_async(delete))
    assert deleted.state is MutationState.COMPLETED
    assert not (root / "renamed.txt").exists()
    restored = _run(steward.restore_async(delete))
    assert restored.state is MutationState.RESTORED
    assert (root / "renamed.txt").read_bytes() == b"recovery-aware bytes"

    restarted_broker, _ = _broker(root)
    restarted = FileSteward(root, permission_broker=restarted_broker)
    assert restarted.reconcile_pending() == ()
    persisted = restarted.manifests.load(delete.plan_id)
    assert persisted.state is MutationState.RESTORED


def test_file_steward_denies_unknown_model_and_toctou(tmp_path: Path) -> None:
    root = tmp_path / "owned"
    root.mkdir()
    source = root / "source.txt"
    source.write_bytes(b"original")
    broker, _ = _broker(root)
    steward = FileSteward(root, permission_broker=broker, host_bridge=HostBridge())
    with pytest.raises(MutationDenied):
        steward.plan_delete(source)
    with pytest.raises(MutationDenied, match="MODEL_RETIREMENT"):
        steward.plan_delete(source, classification=_classification(FileCategory.MODEL_STORAGE))
    application = _classification(
        FileCategory.APPLICATION_MANAGED, owner=FileOwnership.APPLICATION, recovery=None
    )
    with pytest.raises(MutationDenied):
        steward.plan_move(source, root / "application-moved.txt", classification=application)
    plan = steward.plan_copy(source, root / "copy.txt")
    source.write_bytes(b"changed")
    with pytest.raises(StalePlan):
        _run(steward.execute_async(plan))
    assert steward.manifests.load(plan.plan_id).state is MutationState.STALE_PLAN


def test_file_steward_manifest_tamper_and_no_broker_fail_closed(tmp_path: Path) -> None:
    root = tmp_path / "owned"
    root.mkdir()
    source = root / "source.txt"
    source.write_bytes(b"bytes")
    no_broker = FileSteward(root)
    plan = no_broker.plan_copy(source, root / "copy.txt")
    with pytest.raises(MutationDenied):
        _run(no_broker.execute_async(plan))
    path = no_broker.manifests.path_for(plan.plan_id)
    raw = json.loads(path.read_text(encoding="utf-8"))
    raw["state"] = "completed"
    path.write_text(json.dumps(raw), encoding="utf-8")
    with pytest.raises(ManifestIntegrityError):
        no_broker.manifests.load(plan.plan_id)


def test_file_steward_interrupted_copy_reconciles_unknown_without_retry(tmp_path: Path) -> None:
    root = tmp_path / "owned"
    root.mkdir()
    source = root / "source.txt"
    source.write_bytes(b"interrupt me")
    broker, _ = _broker(root)

    def interrupt(boundary: str, _item: MutationItem) -> None:
        if boundary == "after_copy_before_finalize":
            raise RuntimeError("fault injection")

    steward = FileSteward(
        root,
        permission_broker=broker,
        host_bridge=HostBridge(),
        fault_injector=interrupt,
    )
    plan = steward.plan_copy(source, root / "copy.txt")
    with pytest.raises(MutationUnknownOutcome):
        _run(steward.execute_async(plan))
    result = steward.reconcile(plan)
    assert result.state is MutationState.UNKNOWN_OUTCOME
    assert (root / "copy.txt").exists() is False


def test_storage_contracts_reject_malformed_or_untrusted_facts(tmp_path: Path) -> None:
    base = _volume("volume")
    serialized = base.as_dict()
    assert serialized["volume_id"] == "volume"
    with pytest.raises(ValueError):
        replace(base, volume_id="")
    with pytest.raises(ValueError):
        replace(base, mount_points=())
    with pytest.raises(ValueError):
        replace(base, capacity_bytes=-1)
    with pytest.raises(ValueError):
        replace(base, capacity_bytes=10, free_bytes=11)
    with pytest.raises(ValueError):
        replace(base, observed_at=datetime.now())
    with pytest.raises(ValueError):
        replace(base, stable_identity=cast(Any, 1))
    assert base.pressure_ratio == 0.1
    assert replace(base, capacity_bytes=0, free_bytes=0).pressure_ratio is None

    with pytest.raises(ValueError):
        StoragePressurePolicy(watch_free_bytes=-1)
    with pytest.raises(ValueError):
        StoragePressurePolicy(watch_free_ratio=2.0)
    with pytest.raises(ValueError):
        StoragePressurePolicy(watch_free_bytes=1, constrained_free_bytes=2)
    with pytest.raises(ValueError):
        classify_storage_pressure(cast(Any, object()), StoragePressurePolicy())
    with pytest.raises(ValueError):
        classify_storage_pressure(base, StoragePressurePolicy(), incoming_bytes=-1)

    with pytest.raises(ValueError):
        StorageHistorySnapshot("v", datetime.now(), 1, 1, 1, StoragePressureState.HEALTHY)
    with pytest.raises(ValueError):
        StorageHistorySnapshot("v", datetime.now(UTC), -1, 1, 1, StoragePressureState.HEALTHY)
    with pytest.raises(ValueError):
        StorageHistorySnapshot("v", datetime.now(UTC), 1, 1, 1, cast(Any, "unknown"))
    with pytest.raises(ValueError):
        StorageHistoryStore(tmp_path / "history.sqlite3", max_snapshots=0)
    with pytest.raises(ValueError):
        StorageForecast("v", ForecastState.STABLE, None, None, None, -1, 0.0, "bad")
    with pytest.raises(ValueError):
        StorageForecast("v", ForecastState.STABLE, None, None, None, 1, 2.0, "bad")

    with pytest.raises(ValueError):
        ResourcePlacementRequest("bad", cast(Any, "not-a-resource-type"), 1)
    with pytest.raises(ValueError):
        ResourcePlacementRequest("bad", StorageResourceType.DATASET, -1)
    with pytest.raises(ValueError):
        ResourcePlacementRequest("bad", StorageResourceType.DATASET, 1, required_headroom_bytes=-1)
    with pytest.raises(ValueError):
        ResourcePlacementRequest(
            "bad",
            StorageResourceType.DATASET,
            1,
            performance_sensitive=cast(Any, 1),
        )
    with pytest.raises(ValueError):
        FileClassification(cast(Any, "not-a-category"))
    with pytest.raises(ValueError):
        FileClassification(FileCategory.CACHE, intentional_copy=cast(Any, 1))
    with pytest.raises(ValueError):
        FileClassification(FileCategory.CACHE, active_reference=cast(Any, "active"))


def test_storage_serialization_and_inventory_fallback_are_typed() -> None:
    observed = _volume("serial", free=500)
    inventory = StorageInventoryService(probe=lambda: (observed,))
    planner = StoragePlanner(inventory)
    selected = planner.plan(ResourcePlacementRequest("serial", StorageResourceType.DATASET, 1))
    assert selected.status is PlacementStatus.RECOMMENDED
    assert selected.target_location is not None
    assert selected.as_dict()["target_location"] == selected.target_location

    unavailable = planner.plan(
        ResourcePlacementRequest(
            "unavailable", StorageResourceType.DATASET, 1, compatible_volume_ids=("missing",)
        )
    )
    assert unavailable.target_location is None
    assert unavailable.as_dict()["target_location"] is None


def test_history_forecast_inventory_and_planner_unknown_routes(tmp_path: Path) -> None:
    now = datetime(2026, 2, 1, tzinfo=UTC)
    history = StorageHistoryStore(tmp_path / "bounded.sqlite3", max_snapshots=2)
    for index in range(3):
        history.record(
            StorageHistorySnapshot(
                "v",
                now + timedelta(days=index),
                1_000,
                100 + index,
                900 - index,
                StoragePressureState.HEALTHY,
            )
        )
    assert len(history.snapshots()) == 2
    assert len(history.snapshots("v")) == 2
    assert history.snapshots("missing") == ()
    history.close()

    malformed = StorageInventoryService(probe=lambda: (cast(Any, object()),))
    with pytest.raises(StorageError):
        malformed.inspect()
    observed = _volume("observed", free=500)
    service = StorageInventoryService(probe=lambda: (observed, observed))
    assert service.observe() == (observed,)
    assert service.last == (observed,)
    assert service.pressure("missing") is StoragePressureState.UNKNOWN

    same_time = (
        StorageHistorySnapshot("same", now, 100, 50, 50, StoragePressureState.HEALTHY),
        StorageHistorySnapshot("same", now, 100, 50, 50, StoragePressureState.HEALTHY),
    )
    assert forecast_storage_pressure(same_time, "same").state is ForecastState.UNKNOWN
    growing = (
        StorageHistorySnapshot("grow", now, 100, 20, 80, StoragePressureState.HEALTHY),
        StorageHistorySnapshot(
            "grow", now + timedelta(days=1), 100, 10, 90, StoragePressureState.HEALTHY
        ),
    )
    assert forecast_storage_pressure(growing, "grow").state is ForecastState.GROWING
    at_threshold = (
        StorageHistorySnapshot("decline", now, 100, 10, 90, StoragePressureState.HEALTHY),
        StorageHistorySnapshot(
            "decline", now + timedelta(days=1), 100, 50, 50, StoragePressureState.WATCH
        ),
    )
    assert (
        forecast_storage_pressure(at_threshold, "decline", threshold_bytes=50).threshold_crossing_at
        is None
    )

    system = _volume("system", free=100, capacity=100, system=True, speed="fast")
    unknown_free = replace(
        _volume("unknown-free"), capacity_bytes=None, used_bytes=None, free_bytes=None
    )
    readonly = _volume("readonly", free=500, read_only=True)
    network = _volume("network", free=500, network=True)
    slow = _volume("slow", free=500, speed="hdd")
    planner = StoragePlanner((system, unknown_free, readonly, network, slow))
    assert (
        planner.plan(
            ResourcePlacementRequest(
                "missing", StorageResourceType.DATASET, 1, compatible_volume_ids=("no",)
            )
        ).status
        is PlacementStatus.NO_COMPATIBLE_TARGET
    )
    assert (
        planner.plan(
            ResourcePlacementRequest(
                "unknown", StorageResourceType.DATASET, 1, performance_sensitive=True
            ),
            volumes=(unknown_free,),
        ).status
        is PlacementStatus.UNKNOWN_COMPATIBILITY
    )
    assert (
        planner.plan(
            ResourcePlacementRequest(
                "slow", StorageResourceType.DATASET, 1, performance_sensitive=True
            ),
            volumes=(slow,),
        ).status
        is PlacementStatus.NO_COMPATIBLE_TARGET
    )
    assert (
        planner.plan(
            ResourcePlacementRequest("ro", StorageResourceType.DATASET, 1),
            volumes=(readonly, network),
        ).status
        is PlacementStatus.NO_COMPATIBLE_TARGET
    )
    current = planner.plan(
        ResourcePlacementRequest(
            "current", StorageResourceType.DATASET, 1, current_volume_id="system"
        ),
        volumes=(system,),
    )
    assert current.status is PlacementStatus.ALREADY_SUITABLE
    app = planner.plan(
        ResourcePlacementRequest(
            "application",
            StorageResourceType.GENERIC,
            1,
            application_managed=True,
            relocation_mechanism="trusted.application.move",
        ),
        volumes=(system,),
    )
    assert app.status is PlacementStatus.RECOMMENDED
    assert app.target_location is not None
    with pytest.raises(StorageError):
        planner.plan(cast(Any, object()), volumes=(system,))
    with pytest.raises(StalePlan):
        planner.bind_acquisition(
            AcquisitionRequest(
                "bad-plan",
                ResourceType.DATA,
                "test",
                source="https://example.invalid/bad-plan",
                download_size_bytes=1,
            ),
            planner.plan(
                ResourcePlacementRequest(
                    "bad-plan", StorageResourceType.DATASET, 1, compatible_volume_ids=("none",)
                ),
                volumes=(system,),
            ),
        )


def test_classification_download_and_duplicate_policy_matrix(tmp_path: Path) -> None:
    root = tmp_path / "owned"
    protected = tmp_path / "protected"
    root.mkdir()
    protected.mkdir()
    file = root / "file.bin"
    file.write_bytes(b"bytes")
    protected_file = protected / "system.bin"
    protected_file.write_bytes(b"system")

    classifier = FileClassifier(protected_roots=(protected,), jarvis_roots=(root,))
    protected_result = classifier.classify(
        protected_file,
        active_reference=True,
        last_use_at=datetime.now(UTC),
        evidence=("trusted-system-root",),
    )
    assert protected_result.category is FileCategory.SYSTEM_CRITICAL
    assert protected_result.owner is FileOwnership.SYSTEM
    assert protected_result.retention is RetentionState.NEEDED_FOR_EVIDENCE
    assert classifier.classify(file).category is FileCategory.JARVIS_OWNED
    unknown = classifier.classify(
        tmp_path / "outside.bin", category=FileCategory.USER_DATA, owner=FileOwnership.USER
    )
    assert unknown.known

    cleanup = CleanupClassifier()
    assert (
        cleanup.candidate(file, _classification(FileCategory.SYSTEM_CRITICAL)).state
        is CleanupState.PROTECTED
    )
    assert (
        cleanup.candidate(
            file, _classification(FileCategory.USER_DATA, owner=FileOwnership.USER)
        ).state
        is CleanupState.PROTECTED
    )
    assert (
        cleanup.candidate(
            file, _classification(FileCategory.CACHE, owner=FileOwnership.UNKNOWN)
        ).state
        is CleanupState.UNKNOWN
    )
    assert (
        cleanup.candidate(root, _classification(FileCategory.CACHE)).expected_reclaimed_bytes == 0
    )
    assert (
        cleanup.downloads_state(active=False, age_days=2, installer_already_installed=True)
        is DownloadState.INSTALLER_ALREADY_INSTALLED
    )
    assert (
        cleanup.downloads_state(active=False, age_days=2, trusted_movable=True)
        is DownloadState.MOVABLE
    )
    assert (
        cleanup.downloads_state(active=False, age_days=2, exact_duplicate=True)
        is DownloadState.DUPLICATE
    )
    assert cleanup.downloads_state(active=False, age_days=10) is DownloadState.ARCHIVABLE
    assert cleanup.downloads_state(active=False, age_days=-1) is DownloadState.UNKNOWN

    first = root / "first.bin"
    second = root / "second.bin"
    first.write_bytes(b"duplicate")
    second.write_bytes(b"duplicate")

    class DenyingGovernor:
        def reserve(self, *_args: object, **_kwargs: object) -> object:
            return SimpleNamespace(allowed=False, reason="resource pressure", reservation_id=None)

    with pytest.raises(StorageDeferred):
        DuplicateDetector(resource_governor=cast(Any, DenyingGovernor())).scan((root,))

    class AllowingGovernor:
        def reserve(self, *_args: object, **_kwargs: object) -> object:
            return SimpleNamespace(allowed=True, reason="admitted", reservation_id=UUID(int=0))

        def release(self, *_args: object, **_kwargs: object) -> object:
            return SimpleNamespace()

    groups = DuplicateDetector(
        resource_governor=cast(Any, AllowingGovernor()), max_files=1, max_bytes=1_000
    ).scan((root,), active_reference=lambda _path: True)
    assert groups == ()


def test_file_steward_batch_scope_conflicts_and_authority_guards(tmp_path: Path) -> None:
    root = tmp_path / "owned"
    root.mkdir()
    source = root / "source.txt"
    second = root / "second.txt"
    source.write_bytes(b"source")
    second.write_bytes(b"second")
    broker, _ = _broker(root)
    steward = FileSteward(root, permission_broker=broker, host_bridge=HostBridge())

    with pytest.raises(MutationDenied):
        steward.plan_copy(root, root / "directory-copy")
    with pytest.raises(MutationDenied):
        steward.plan_copy(source, root / "too-small", max_affected_bytes=1)
    with pytest.raises(MutationConflict):
        steward.plan_copy(source, second)
    with pytest.raises(MutationDenied):
        steward.plan_move(
            source,
            root / "managed.txt",
            classification=FileClassification(
                FileCategory.APPLICATION_MANAGED,
                FileOwnership.APPLICATION,
                recovery_strategy="rollback-only",
            ),
        )
    relocation = FileClassification(
        FileCategory.APPLICATION_MANAGED,
        FileOwnership.APPLICATION,
        relocation_mechanism="trusted.app.relocate",
    )
    with pytest.raises(MutationDenied):
        steward.plan_move(source, root / "managed.txt", classification=relocation)
    source.write_bytes(b"source")

    with pytest.raises(MutationDenied):
        steward.plan_batch(
            MutationOperation.SAFE_DELETE,
            [
                (
                    second,
                    None,
                    _classification(FileCategory.MOVABLE_USER_DATA, owner=FileOwnership.USER),
                )
            ],
        )
    with pytest.raises(MutationDenied):
        steward.plan_batch(
            MutationOperation.MOVE,
            [
                (
                    source,
                    root / "managed-batch.txt",
                    FileClassification(FileCategory.APPLICATION_MANAGED),
                )
            ],
        )
    batch = steward.plan_batch(
        MutationOperation.COPY,
        [(source, root / "batch-a.txt", None), (second, root / "batch-b.txt", None)],
    )
    batch_result = _run(steward.execute_async(batch))
    assert batch_result.success
    assert (root / "batch-a.txt").read_bytes() == b"source"
    assert (root / "batch-b.txt").read_bytes() == b"second"

    active_plan = steward.plan_copy(
        source,
        root / "active.txt",
        classification=_classification(active=True),
    )
    with pytest.raises(MutationDenied):
        _run(steward.execute_async(active_plan))
    assert steward.manifests.load(active_plan.plan_id).state is MutationState.DENIED

    destination_race = steward.plan_copy(source, root / "race.txt")
    (root / "race.txt").write_bytes(b"race")
    with pytest.raises(MutationConflict):
        _run(steward.execute_async(destination_race))
    assert steward.manifests.load(destination_race.plan_id).state is MutationState.CONFLICT

    bridge_broker, _ = _broker(root)
    bridge_steward = FileSteward(root, permission_broker=bridge_broker, host_bridge=HostBridge())
    bridge_plan = bridge_steward.plan_copy(source, root / "bridge-denied.txt")
    assert _run(bridge_steward.execute_async(bridge_plan)).success


def test_file_steward_sync_api_manifest_reconciliation_and_restore_quarantine(
    tmp_path: Path,
) -> None:
    root = tmp_path / "owned"
    root.mkdir()
    source = root / "source.txt"
    source.write_bytes(b"sync and reconcile")
    broker, authenticator = _broker(root)
    steward = FileSteward(root, permission_broker=broker, host_bridge=HostBridge())

    sync_plan = steward.plan_copy(source, root / "sync.txt")
    assert steward.execute(sync_plan).success
    assert (root / "sync.txt").read_bytes() == source.read_bytes()

    async def execute_inside_loop() -> None:
        nested = steward.plan_copy(source, root / "nested.txt")
        with pytest.raises(RuntimeError):
            steward.execute(nested)

    _run(execute_inside_loop())

    copy_plan = steward.plan_copy(source, root / "reconciled-copy.txt")
    (root / "reconciled-copy.txt").write_bytes(source.read_bytes())
    steward.manifests.save(replace(copy_plan, state=MutationState.IN_PROGRESS))
    assert steward.reconcile(copy_plan).state is MutationState.COMPLETED

    move_source = root / "reconcile-move-source.txt"
    move_source.write_bytes(b"move evidence")
    move_plan = steward.plan_move(
        move_source, root / "reconcile-move-dest.txt", classification=_classification()
    )
    os.rename(move_source, root / "reconcile-move-dest.txt")
    steward.manifests.save(replace(move_plan, state=MutationState.IN_PROGRESS))
    moved = steward.reconcile(move_plan)
    assert moved.state is MutationState.COMPLETED
    assert moved.actual_moved_bytes == move_plan.expected_bytes

    delete_source = root / "reconcile-delete.txt"
    delete_source.write_bytes(b"delete evidence")
    delete_plan = steward.plan_delete(delete_source, classification=_classification())
    with pytest.raises(MutationApprovalRequired):
        _run(steward.execute_async(delete_plan))
    _run(_approve_delete(broker, authenticator, delete_plan.task_id))
    assert steward.execute(delete_plan).success
    in_progress_delete = replace(
        steward.manifests.load(delete_plan.plan_id), state=MutationState.IN_PROGRESS
    )
    steward.manifests.save(in_progress_delete)
    assert steward.reconcile_pending()[0].state is MutationState.COMPLETED

    tampered = root / "tampered.txt"
    tampered.write_bytes(b"tampered")
    tampered_plan = steward.plan_delete(tampered, classification=_classification())
    with pytest.raises(MutationApprovalRequired):
        _run(steward.execute_async(tampered_plan))
    _run(_approve_delete(broker, authenticator, tampered_plan.task_id))
    assert steward.execute(tampered_plan).success
    recovery = steward.manifests.load(tampered_plan.plan_id).items[0].recovery_path
    assert recovery is not None
    recovery.write_bytes(b"altered recovery")
    with pytest.raises(MutationUnknownOutcome):
        _run(steward.restore_async(tampered_plan))
    assert steward.manifests.load(tampered_plan.plan_id).state is MutationState.UNKNOWN_OUTCOME

    with pytest.raises(MutationDenied):
        _run(steward.restore_async(sync_plan))
    with pytest.raises(ManifestIntegrityError):
        MutationManifestStore(root / "missing-store").load(UUID(int=0))


def test_file_steward_delete_and_batch_bounds_are_fail_closed(tmp_path: Path) -> None:
    root = tmp_path / "owned"
    root.mkdir()
    source = root / "source.txt"
    source.write_bytes(b"bounded")
    broker, _ = _broker(root)
    steward = FileSteward(root, permission_broker=broker, host_bridge=HostBridge())

    for category, owner in (
        (FileCategory.SYSTEM_CRITICAL, FileOwnership.SYSTEM),
        (FileCategory.USER_DATA, FileOwnership.USER),
        (FileCategory.APPLICATION_MANAGED, FileOwnership.APPLICATION),
        (FileCategory.MOVABLE_USER_DATA, FileOwnership.USER),
        (FileCategory.ARCHIVE, FileOwnership.USER),
    ):
        with pytest.raises(MutationDenied):
            steward.plan_delete(source, classification=_classification(category, owner=owner))
    with pytest.raises(MutationDenied):
        steward.plan_delete(source, classification=_classification(active=True))
    with pytest.raises(MutationDenied):
        steward.plan_delete(
            source, classification=_classification(retention=RetentionState.UNKNOWN)
        )
    with pytest.raises(MutationDenied):
        steward.plan_batch(MutationOperation.RESTORE, [(source, None, None)])
    with pytest.raises(MutationDenied):
        steward.plan_batch(MutationOperation.COPY, [])
    with pytest.raises(MutationDenied):
        steward.plan_batch(MutationOperation.COPY, [(source, None, None)] * 257)
    with pytest.raises(MutationDenied):
        steward.plan_batch(
            MutationOperation.COPY,
            [(source, root / "bounded.txt", None)],
            max_affected_bytes=1,
        )
    with pytest.raises(MutationDenied):
        steward.plan_batch(
            MutationOperation.SAFE_DELETE,
            [(source, None, _classification(active=True))],
        )
    with pytest.raises(MutationDenied):
        steward.plan_batch(MutationOperation.COPY, [(root, root / "dir.txt", None)])
    existing = root / "existing.txt"
    existing.write_bytes(b"existing")
    with pytest.raises(MutationConflict):
        steward.plan_batch(MutationOperation.COPY, [(source, existing, None)])


def test_file_steward_copy_move_and_rename_effect_boundaries(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    root = tmp_path / "owned"
    root.mkdir()
    source = root / "source.txt"
    source.write_bytes(b"effect boundary")
    broker, _ = _broker(root)
    steward = FileSteward(root, permission_broker=broker, host_bridge=HostBridge())

    partial_plan = steward.plan_copy(source, root / "partial.txt")
    partial = root / f".partial.txt.{partial_plan.plan_id.hex}.partial"
    partial.write_bytes(b"stale partial")
    with pytest.raises(MutationConflict):
        _run(steward.execute_async(partial_plan))
    partial.unlink(missing_ok=True)

    def corrupt_copy(boundary: str, item: MutationItem) -> None:
        if boundary == "after_copy_before_finalize":
            assert item.destination is not None
            item.destination.with_name(
                f".{item.destination.name}.{copy_plan.plan_id.hex}.partial"
            ).write_bytes(b"corrupted")

    copy_plan = steward.plan_copy(source, root / "corrupt.txt")
    corrupt_steward = FileSteward(
        root,
        permission_broker=_broker(root)[0],
        host_bridge=HostBridge(),
        fault_injector=corrupt_copy,
    )
    with pytest.raises(StalePlan):
        _run(corrupt_steward.execute_async(copy_plan))
    assert corrupt_steward.manifests.load(copy_plan.plan_id).state is MutationState.STALE_PLAN

    def create_destination(boundary: str, item: MutationItem) -> None:
        if boundary == "after_copy_before_finalize":
            assert item.destination is not None
            item.destination.write_bytes(b"racing destination")

    race_plan = steward.plan_copy(source, root / "finalize-race.txt")
    race_steward = FileSteward(
        root,
        permission_broker=_broker(root)[0],
        host_bridge=HostBridge(),
        fault_injector=create_destination,
    )
    with pytest.raises(MutationConflict):
        _run(race_steward.execute_async(race_plan))

    cross_source = root / "cross-source.txt"
    cross_source.write_bytes(b"cross volume")
    cross_broker, _ = _broker(root)
    cross_steward = FileSteward(root, permission_broker=cross_broker, host_bridge=HostBridge())
    cross_plan = cross_steward.plan_move(
        cross_source, root / "cross-destination.txt", classification=_classification()
    )
    original_device_identity = storage_module._device_identity
    cross_source_device = original_device_identity(cross_source)

    def different_devices(path: Path) -> str:
        return cross_source_device if path == cross_source else "destination-device"

    monkeypatch.setattr(storage_module, "_device_identity", different_devices)
    assert _run(cross_steward.execute_async(cross_plan)).success
    monkeypatch.setattr(storage_module, "_device_identity", original_device_identity)

    rename_source = root / "rename-source.txt"
    rename_source.write_bytes(b"rename boundary")
    rename_broker, _ = _broker(root)
    rename_steward = FileSteward(root, permission_broker=rename_broker, host_bridge=HostBridge())
    rename_plan = rename_steward.plan_rename(
        rename_source, root / "rename-destination.txt", classification=_classification()
    )
    rename_source_device = original_device_identity(rename_source)
    monkeypatch.setattr(
        storage_module,
        "_device_identity",
        lambda path: rename_source_device if path == rename_source else "rename-destination",
    )
    with pytest.raises(MutationDenied):
        _run(rename_steward.execute_async(rename_plan))


def test_file_steward_restore_authority_and_reconcile_terminal_paths(tmp_path: Path) -> None:
    root = tmp_path / "owned"
    root.mkdir()
    source = root / "source.txt"
    source.write_bytes(b"restore branches")
    broker, authenticator = _broker(root)
    steward = FileSteward(root, permission_broker=broker, host_bridge=HostBridge())

    delete_plan = steward.plan_delete(source, classification=_classification())
    with pytest.raises(MutationApprovalRequired):
        _run(steward.execute_async(delete_plan))
    _run(_approve_delete(broker, authenticator, delete_plan.task_id))
    assert steward.execute(delete_plan).success

    no_broker = FileSteward(root)
    with pytest.raises(MutationDenied):
        _run(no_broker.restore_async(delete_plan))

    source.write_bytes(b"conflict")
    with pytest.raises(MutationConflict):
        _run(steward.restore_async(delete_plan))
    assert steward.manifests.load(delete_plan.plan_id).state is MutationState.CONFLICT

    missing_source = root / "missing-source.txt"
    missing_source.write_bytes(b"missing recovery")
    missing_plan = steward.plan_delete(missing_source, classification=_classification())
    with pytest.raises(MutationApprovalRequired):
        _run(steward.execute_async(missing_plan))
    _run(_approve_delete(broker, authenticator, missing_plan.task_id))
    assert steward.execute(missing_plan).success
    current = steward.manifests.load(missing_plan.plan_id)
    item = current.items[0]
    steward.manifests.save(replace(current, items=(replace(item, recovery_path=None),)))
    with pytest.raises(MutationUnknownOutcome):
        _run(steward.restore_async(missing_plan))
    assert steward.manifests.load(missing_plan.plan_id).state is MutationState.UNKNOWN_OUTCOME

    assert steward.reconcile(delete_plan).state is MutationState.CONFLICT


def test_storage_internal_fallbacks_and_manifest_integrity_are_explicit(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    naive = datetime(2026, 1, 1)
    assert storage_module._utc(naive).tzinfo is UTC
    with pytest.raises(MutationDenied):
        storage_module._canonical(Path("relative.txt"))
    assert storage_module._safe_root(tmp_path / "safe").is_dir()

    monkeypatch.setattr(storage_module, "_canonical", lambda path: path.absolute())
    monkeypatch.setattr(storage_module, "_has_reparse_ancestor", lambda _path: True)
    with pytest.raises(MutationDenied):
        storage_module._safe_root(tmp_path / "unsafe")
    monkeypatch.undo()

    assert storage_module._cloud_placeholder(cast(Any, SimpleNamespace(st_file_attributes=0x1000)))
    storage_any: Any = storage_module
    original_name = storage_any.os.name
    monkeypatch.setattr(storage_any.os, "name", "posix")
    assert storage_module._drive_type(tmp_path) is VolumeDriveType.FIXED
    assert storage_module._volume_identity(tmp_path)[0].startswith("device:")
    monkeypatch.setattr(storage_any.os, "name", original_name)

    class BrokenKernel:
        def GetLogicalDrives(self) -> int:
            raise OSError("probe failed")

        def GetDriveTypeW(self, _root: str) -> int:
            raise OSError("probe failed")

        def GetVolumeNameForVolumeMountPointW(self, *_args: object) -> int:
            raise OSError("probe failed")

        def GetVolumeInformationW(self, *_args: object) -> int:
            raise OSError("probe failed")

    monkeypatch.setattr(storage_any.ctypes, "windll", SimpleNamespace(kernel32=BrokenKernel()))
    assert storage_module._windows_mounts() == ()
    assert storage_module._drive_type(tmp_path) is VolumeDriveType.UNKNOWN
    assert storage_module._volume_identity(tmp_path)[0].startswith("mount:")
    monkeypatch.setattr(storage_module, "_windows_mounts", lambda: (tmp_path / "not-mounted",))
    assert storage_module._host_volumes() == ()

    root = tmp_path / "manifest-root"
    root.mkdir()
    source = root / "source.txt"
    source.write_bytes(b"manifest")
    broker, _ = _broker(root)
    steward = FileSteward(root, permission_broker=broker)
    plan = steward.plan_copy(source, root / "copy.txt")
    raw = plan.as_dict()
    raw["items"] = [{}]
    raw["integrity"] = hashlib.sha256(
        storage_module._json_bytes({key: value for key, value in raw.items() if key != "integrity"})
    ).hexdigest()
    steward.manifests.path_for(plan.plan_id).write_text(json.dumps(raw), encoding="utf-8")
    with pytest.raises(ManifestIntegrityError):
        steward.manifests.load(plan.plan_id)


def test_r1_reproduction_builder_rejects_missing_failed_and_stale_evidence(
    tmp_path: Path,
) -> None:
    head = "standalone-builder-test-source"
    tree = "standalone-builder-test-tree"
    system_evidence = tmp_path / "system.json"
    system_evidence.write_text(
        json.dumps(
            {
                "status": "passed",
                "exit_code": 0,
                "revision": head,
                "suite": "v1-acceptance",
            }
        ),
        encoding="utf-8",
    )

    def run_case(name: str, scenario: dict[str, object] | None) -> dict[str, object]:
        output = tmp_path / f"{name}.artifact.json"
        command = [
            sys.executable,
            "scripts/acceptance/build_v1_i_r3b_artifact.py",
            "--output",
            str(output),
            "--system-evidence",
            str(system_evidence),
            "--exact-coverage",
            "90.0",
            "--ending-commit",
            head,
            "--ending-parent",
            "standalone-builder-test-parent",
            "--ending-tree",
            tree,
            "--ending-branch",
            "standalone-builder-test-branch",
            "--hosted-ci-run-id",
            "test-run",
            "--hosted-ci-head-sha",
            head,
        ]
        if scenario is not None:
            evidence = tmp_path / f"{name}.scenario.json"
            evidence.write_text(
                json.dumps({"revision": head, "tree": tree, "tests": [scenario]}),
                encoding="utf-8",
            )
            command.extend(
                [
                    "--scenario-evidence",
                    str(evidence),
                    "--scenario-revision",
                    head,
                    "--scenario-tree",
                    tree,
                ]
            )
        result = subprocess.run(command, check=False, capture_output=True, text=True)
        assert result.returncode == 0, result.stderr
        return cast(dict[str, object], json.loads(output.read_text(encoding="utf-8")))

    missing = run_case("missing", None)
    missing_requirement = cast(dict[str, Any], missing["r1_requirements"])["requirements"][0]
    assert missing_requirement["status"] == "NOT_EXECUTED"

    failed = run_case(
        "failed",
        {
            "test_id": (
                "tests.test_storage_stewardship::"
                "test_r1_reproduction_partial_batch_does_not_complete_from_first_item"
            ),
            "name": "test_r1_reproduction_partial_batch_does_not_complete_from_first_item",
            "status": "FAIL",
            "exit_code": 1,
        },
    )
    failed_requirement = cast(dict[str, Any], failed["r1_requirements"])["requirements"][0]
    assert failed_requirement["status"] == "FAIL"

    stale = run_case(
        "stale",
        {
            "test_id": (
                "tests.test_storage_stewardship::"
                "test_r1_reproduction_partial_batch_does_not_complete_from_first_item"
            ),
            "name": "test_r1_reproduction_partial_batch_does_not_complete_from_first_item",
            "status": "PASS",
            "revision": "stale-source",
            "tree": "stale-tree",
            "exit_code": 0,
        },
    )
    stale_requirement = cast(dict[str, Any], stale["r1_requirements"])["requirements"][0]
    assert stale_requirement["status"] == "BLOCKING_NOT_PROVEN"


def test_r1_reproduction_partial_batch_does_not_complete_from_first_item(
    tmp_path: Path,
) -> None:
    root = tmp_path / "owned"
    root.mkdir()
    sources = tuple(root / f"source-{index}.txt" for index in range(1, 4))
    for index, source in enumerate(sources, start=1):
        source.write_bytes(f"item-{index}".encode())
    broker, _ = _broker(root)

    def interrupt(boundary: str, item: MutationItem) -> None:
        if boundary == "after_copy_before_finalize" and item.source == sources[1]:
            raise RuntimeError("interrupt second item")

    steward = FileSteward(
        root,
        permission_broker=broker,
        host_bridge=HostBridge(),
        fault_injector=interrupt,
    )
    plan = steward.plan_batch(
        MutationOperation.COPY,
        [(source, root / f"copy-{index}.txt", None) for index, source in enumerate(sources, 1)],
    )
    with pytest.raises(MutationUnknownOutcome):
        _run(steward.execute_async(plan))

    restarted = FileSteward(
        root,
        manifest_store=MutationManifestStore(root / ".mutation-state"),
    )
    result = restarted.reconcile(plan)

    assert result.state is not MutationState.COMPLETED
    assert (root / "copy-1.txt").read_bytes() == b"item-1"
    assert not (root / "copy-3.txt").exists()


def test_r1_reproduction_batch_restore_requires_all_items(tmp_path: Path) -> None:
    root = tmp_path / "owned"
    root.mkdir()
    sources = (root / "first.txt", root / "second.txt")
    sources[0].write_bytes(b"first")
    sources[1].write_bytes(b"second")
    broker, authenticator = _broker(root)
    steward = FileSteward(root, permission_broker=broker, host_bridge=HostBridge())
    plan = steward.plan_batch(
        MutationOperation.SAFE_DELETE,
        [(source, None, _classification()) for source in sources],
    )
    with pytest.raises(MutationApprovalRequired):
        _run(steward.execute_async(plan))
    _run(_approve_delete(broker, authenticator, plan.task_id))
    assert steward.execute(plan).success

    restored = _run(steward.restore_async(plan))

    assert restored.state is MutationState.RESTORED
    assert all(
        source.exists() and source.read_bytes() == expected
        for source, expected in zip(sources, (b"first", b"second"), strict=True)
    )


def test_r1_reproduction_partial_effect_is_not_a_not_executed_receipt(
    tmp_path: Path,
) -> None:
    root = tmp_path / "owned"
    root.mkdir()
    first = root / "first.txt"
    second = root / "second.txt"
    first.write_bytes(b"first")
    second.write_bytes(b"second")
    audit = InMemoryAuditSink()
    authenticator = TrustedApprovalAuthenticator(source=ApprovalSource.TRUSTED_UI)
    broker = PermissionBroker(
        PolicyEngine(
            (
                PolicyRule(
                    "storage.test-root",
                    Permission.FILESYSTEM_WRITE,
                    Decision.ALLOW,
                    ScopeConstraint(
                        paths=(str(root),),
                        tools=frozenset({"storage.file_steward"}),
                    ),
                    frozenset({"storage.file.copy"}),
                ),
            )
        ),
        audit_sink=audit,
        approval_context_verifier=authenticator.verifier(),
    )
    steward = FileSteward(root, permission_broker=broker, host_bridge=HostBridge())
    plan = steward.plan_batch(
        MutationOperation.COPY,
        [(first, root / "first-copy.txt", None), (second, root / "second-copy.txt", None)],
    )
    second.write_bytes(b"changed after planning")

    with pytest.raises(StalePlan):
        _run(steward.execute_async(plan))

    records = _run(audit.records())
    execution_outcomes = tuple(record.execution_outcome for record in records)
    assert (root / "first-copy.txt").read_bytes() == b"first"
    assert "not_executed" not in execution_outcomes


def test_r1_reproduction_missing_host_bridge_does_not_bypass_host_authority(
    tmp_path: Path,
) -> None:
    root = tmp_path / "owned"
    root.mkdir()
    source = root / "source.txt"
    destination = root / "destination.txt"
    source.write_bytes(b"host boundary")
    broker, _ = _broker(root)
    steward = FileSteward(root, permission_broker=broker)
    plan = steward.plan_copy(source, destination)

    with pytest.raises(MutationDenied):
        _run(steward.execute_async(plan))

    assert not destination.exists()


def test_r1_reproduction_cross_volume_finalization_preserves_conflict_and_source(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    root = tmp_path / "owned"
    root.mkdir()
    source = root / "source.txt"
    source.write_bytes(b"original")
    broker, _ = _broker(root)
    original_device_identity = storage_module._device_identity
    source_device = original_device_identity(source)

    monkeypatch.setattr(
        storage_module,
        "_device_identity",
        lambda path: source_device if path == source else "destination-device",
    )
    conflict_destination = root / "conflict.txt"

    def create_conflict(boundary: str, _item: MutationItem) -> None:
        if boundary == "after_cross_volume_copy":
            conflict_destination.write_bytes(b"sentinel")

    conflict_steward = FileSteward(
        root,
        permission_broker=broker,
        host_bridge=HostBridge(),
        fault_injector=create_conflict,
    )
    conflict_plan = conflict_steward.plan_move(
        source, conflict_destination, classification=_classification()
    )
    with pytest.raises(MutationConflict):
        _run(conflict_steward.execute_async(conflict_plan))
    assert conflict_destination.read_bytes() == b"sentinel"
    assert source.read_bytes() == b"original"

    race_source = root / "race-source.txt"
    race_source.write_bytes(b"race-original")
    race_destination = root / "race-destination.txt"
    monkeypatch.setattr(
        storage_module,
        "_device_identity",
        lambda path: source_device if path == race_source else "destination-device",
    )

    def change_source(boundary: str, item: MutationItem) -> None:
        if boundary == "after_cross_volume_copy":
            item.source.write_bytes(b"changed during finalization")

    race_broker, _ = _broker(root)
    race_steward = FileSteward(
        root,
        permission_broker=race_broker,
        host_bridge=HostBridge(),
        fault_injector=change_source,
    )
    race_plan = race_steward.plan_move(
        race_source, race_destination, classification=_classification()
    )
    with pytest.raises((StalePlan, MutationUnknownOutcome)):
        _run(race_steward.execute_async(race_plan))
    assert race_source.exists()
    assert race_source.read_bytes() == b"changed during finalization"


def test_r1_receipt_bound_host_bridge_covers_exact_batch_and_rejects_replays(
    tmp_path: Path,
) -> None:
    root = tmp_path / "owned"
    root.mkdir()
    source = root / "source.txt"
    source.write_bytes(b"receipt-bound")
    broker, _ = _broker(root)
    bridge = HostBridge()
    steward = FileSteward(root, permission_broker=broker, host_bridge=bridge)
    plan = steward.plan_copy(source, root / "destination.txt")
    receipt = _run(steward._authorize(plan, user_id=None))  # noqa: SLF001
    assert _run(broker.begin_execution(receipt)) is None
    operation = steward._effective_operation(plan)  # noqa: SLF001
    arguments = steward._authorization_arguments(plan)  # noqa: SLF001

    def request(**changes: Any) -> HostBridgeRequest:
        base = HostBridgeRequest(
            request_id=UUID(int=0),
            task_id=plan.task_id,
            instance_id=bridge.instance_id,
            operation=steward._bridge_operation(operation),  # noqa: SLF001
            resource=steward._bridge_resource(plan),  # noqa: SLF001
            scope=str(root),
            risk=steward._risk(plan),  # noqa: SLF001
            expires_at=receipt.expires_at,
            tool_id=steward._TOOL_ID,  # noqa: SLF001
            action=f"storage.file.{operation.value}",
            argument_fingerprint=receipt.argument_fingerprint,
            action_fingerprint=receipt.action_fingerprint,
            approval_identity=None,
            safety_class=steward._safety_class(plan),  # noqa: SLF001
        )
        return replace(base, **changes)

    def check(
        candidate: HostBridgeRequest,
        supplied_receipt: Any = receipt,
        supplied_arguments: Any = arguments,
    ) -> bool:
        return bridge.authorize_with_receipt(
            candidate,
            receipt=supplied_receipt,
            broker=broker,
            normalized_arguments=supplied_arguments,
            expected_instance_id=bridge.instance_id,
        ).allowed

    assert not check(request(expires_at=datetime.now(UTC) - timedelta(seconds=1)))
    assert not check(request(task_id=UUID(int=1)))
    assert not check(request(instance_id=UUID(int=1)))
    assert not check(request(resource="manifest:changed"))
    assert not check(request(operation=HostBridgeOperation.FILE_READ))
    assert not check(request(argument_fingerprint="wrong-fingerprint"))
    changed_arguments = dict(arguments)
    changed_arguments["items"] = ("out-of-scope-recovery-path",)
    assert not check(request(), supplied_arguments=changed_arguments)
    assert not check(request(), supplied_receipt=None)
    exact = request(request_id=uuid4())
    assert check(exact)
    assert not check(exact)
    assert _run(broker.record_execution_outcome(receipt, "binding_test")) is None
    assert not check(request(request_id=uuid4()))


def test_r1_restore_interruption_is_not_reconciled_as_delete(tmp_path: Path) -> None:
    root = tmp_path / "owned"
    root.mkdir()
    sources = (root / "first.txt", root / "second.txt")
    sources[0].write_bytes(b"first")
    sources[1].write_bytes(b"second")
    broker, authenticator = _broker(root)
    delete_steward = FileSteward(root, permission_broker=broker, host_bridge=HostBridge())
    plan = delete_steward.plan_batch(
        MutationOperation.SAFE_DELETE,
        [(source, None, _classification()) for source in sources],
    )
    with pytest.raises(MutationApprovalRequired):
        _run(delete_steward.execute_async(plan))
    _run(_approve_delete(broker, authenticator, plan.task_id))
    assert delete_steward.execute(plan).success

    def interrupt_restore(boundary: str, item: MutationItem) -> None:
        if boundary == "before_restore_finalize" and item.source == sources[1]:
            raise RuntimeError("restore interrupted")

    delete_steward.fault_injector = interrupt_restore
    restoring = delete_steward
    with pytest.raises(MutationUnknownOutcome):
        _run(restoring.restore_async(plan))
    interrupted = restoring.manifests.load(plan.plan_id)
    assert interrupted.phase.value == "restore"
    assert interrupted.state is MutationState.UNKNOWN_OUTCOME
    assert sources[0].read_bytes() == b"first"
    assert not sources[1].exists()

    restarted = FileSteward(
        root,
        manifest_store=MutationManifestStore(root / ".mutation-state"),
    )
    reconciled = restarted.reconcile(plan)
    assert reconciled.state is MutationState.UNKNOWN_OUTCOME
    assert reconciled.manifest.phase.value == "restore"


def test_r1_child_process_interruption_reconciles_without_replay(tmp_path: Path) -> None:
    root = tmp_path / "owned"
    root.mkdir()
    source = root / "source.txt"
    source.write_bytes(b"child interruption")
    broker, _ = _broker(root)
    steward = FileSteward(root, permission_broker=broker, host_bridge=HostBridge())
    plan = steward.plan_copy(source, root / "destination.txt")
    signal = tmp_path / "child-ready.signal"
    child = tmp_path / "interrupt_child.py"
    child.write_text(
        """
import asyncio
import sys
import time
from pathlib import Path
from uuid import UUID

from jarvis.permissions import (
    Decision,
    Permission,
    PermissionBroker,
    PolicyEngine,
    PolicyRule,
    ScopeConstraint,
)
from jarvis.storage import FileSteward, MutationItem
from jarvis.vm.bridge import HostBridge

root = Path(sys.argv[1])
plan_id = UUID(sys.argv[2])
signal = Path(sys.argv[3])

broker = PermissionBroker(PolicyEngine((PolicyRule(
    "child-storage",
    Permission.FILESYSTEM_WRITE,
    Decision.ALLOW,
    ScopeConstraint(paths=(str(root),), tools=frozenset({"storage.file_steward"})),
    frozenset({"storage.file.copy"}),
),)))

def pause(boundary: str, _item: MutationItem) -> None:
    if boundary == "after_copy_before_finalize":
        signal.write_text("effect boundary entered", encoding="utf-8")
        while True:
            time.sleep(0.1)

asyncio.run(FileSteward(
    root,
    permission_broker=broker,
    host_bridge=HostBridge(),
    fault_injector=pause,
).execute_async(plan_id))
""".strip()
        + "\n",
        encoding="utf-8",
    )
    child_environment = dict(os.environ)
    child_environment["PYTHONPATH"] = str(Path.cwd())
    process = subprocess.Popen(
        [sys.executable, str(child), str(root), str(plan.plan_id), str(signal)],
        cwd=str(Path.cwd()),
        env=child_environment,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )
    try:
        deadline = time.monotonic() + 15
        while not signal.exists() and time.monotonic() < deadline:
            if process.poll() is not None:
                stdout, stderr = process.communicate()
                raise AssertionError(f"child exited before interruption: {stdout}; {stderr}")
            time.sleep(0.05)
        assert signal.exists()
        process.terminate()
        process.wait(timeout=10)
    finally:
        if process.poll() is None:
            process.kill()
            process.wait(timeout=10)

    restarted = FileSteward(
        root,
        manifest_store=MutationManifestStore(root / ".mutation-state"),
    )
    result = restarted.reconcile(plan)
    assert result.state is MutationState.UNKNOWN_OUTCOME
    assert not (root / "destination.txt").exists()


def test_r1_live_protection_revalidation_denies_new_obligations(tmp_path: Path) -> None:
    root = tmp_path / "owned"
    root.mkdir()
    source = root / "source.txt"
    source.write_bytes(b"live protection")
    broker, authenticator = _broker(root)
    live = {"classification": _classification()}
    steward = FileSteward(
        root,
        permission_broker=broker,
        host_bridge=HostBridge(),
        live_protection_probe=lambda _path: live["classification"],
    )
    plan = steward.plan_delete(source, classification=_classification())
    live["classification"] = _classification(active=True)
    with pytest.raises(MutationApprovalRequired):
        _run(steward.execute_async(plan))
    _run(_approve_delete(broker, authenticator, plan.task_id))
    with pytest.raises(MutationDenied):
        _run(steward.execute_async(plan))
    assert source.exists()

    evidence_source = root / "evidence.txt"
    evidence_source.write_bytes(b"evidence")
    evidence_plan = steward.plan_delete(evidence_source, classification=_classification())
    live["classification"] = _classification(retention=RetentionState.NEEDED_FOR_EVIDENCE)
    with pytest.raises(MutationApprovalRequired):
        _run(steward.execute_async(evidence_plan))
    _run(_approve_delete(broker, authenticator, evidence_plan.task_id))
    with pytest.raises(MutationDenied):
        _run(steward.execute_async(evidence_plan))
    assert evidence_source.exists()


def test_r1_reproduction_builder_cannot_pass_without_scenario_evidence(tmp_path: Path) -> None:
    head = "standalone-builder-test-source"
    system_evidence = tmp_path / "system.json"
    system_evidence.write_text(
        json.dumps(
            {
                "status": "passed",
                "exit_code": 0,
                "revision": head,
                "suite": "v1-acceptance",
                "results": [{"name": "pytest:passed", "status": "passed", "detail": "1"}],
            }
        ),
        encoding="utf-8",
    )
    output = tmp_path / "artifact.json"
    result = subprocess.run(
        [
            sys.executable,
            "scripts/acceptance/build_v1_i_r3b_artifact.py",
            "--output",
            str(output),
            "--system-evidence",
            str(system_evidence),
            "--exact-coverage",
            "90.0",
            "--ending-commit",
            head,
            "--ending-parent",
            "standalone-builder-test-parent",
            "--ending-tree",
            "standalone-builder-test-tree",
            "--ending-branch",
            "standalone-builder-test-branch",
            "--hosted-ci-run-id",
            "test-run",
            "--hosted-ci-head-sha",
            head,
        ],
        check=False,
        capture_output=True,
        text=True,
    )
    assert result.returncode == 0, result.stderr
    artifact = json.loads(output.read_text(encoding="utf-8"))
    cases = artifact["acceptance_matrix"]["cases"]
    assert any(case["status"] != "PASS" for case in cases)
