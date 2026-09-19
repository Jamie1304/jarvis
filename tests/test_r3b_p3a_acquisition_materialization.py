from __future__ import annotations

import shutil
from collections.abc import Iterator
from contextlib import contextmanager
from dataclasses import replace
from datetime import UTC, datetime
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import cast
from uuid import uuid4

import jarvis.storage as storage_module
import pytest
from jarvis.acquisition import (
    AcquisitionBroker,
    AcquisitionPlacementApprovalRequired,
    AcquisitionPolicy,
    AcquisitionPolicyMode,
    AcquisitionStaleTarget,
    AcquisitionUnknownOutcome,
    ArtifactState,
    BoundedDownloadTransport,
    InMemoryAcquisitionLedger,
    ResourceType,
    SQLiteAcquisitionLedger,
)
from jarvis.permissions import (
    Decision,
    Permission,
    PermissionBroker,
    PolicyEngine,
    PolicyRule,
    ScopeConstraint,
)
from jarvis.storage import (
    FileSteward,
    FileStewardAcquisitionMaterializer,
    MutationDenied,
    MutationManifestStore,
    MutationOperation,
    MutationResult,
    MutationUnknownOutcome,
    PlacementPlan,
    PlacementStatus,
    ProvisionedPlacementRootResolver,
    ResourcePlacementRequest,
    StorageResourceType,
    TrustedPlacementRoot,
    VolumeDriveType,
    VolumeObservation,
)
from jarvis.vm.bridge import HostBridge

from tests.test_r3a_acquisition_portfolio import PAYLOAD, _request, _resource_server


@contextmanager
def _counting_source() -> Iterator[tuple[str, list[int]]]:
    counts = [0]

    class Handler(BaseHTTPRequestHandler):
        def do_GET(self) -> None:  # noqa: N802
            counts[0] += 1
            self.send_response(200)
            self.send_header("Content-Length", str(len(PAYLOAD)))
            self.end_headers()
            self.wfile.write(PAYLOAD)

        def log_message(self, *_args: object) -> None:
            return None

    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    thread = __import__("threading").Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield f"http://127.0.0.1:{server.server_port}/resource.bin", counts
    finally:
        server.shutdown()
        thread.join(timeout=5)
        server.server_close()


class _PauseOnceMaterializer:
    def __init__(self, destination: Path, *, pauses: int = 1) -> None:
        self.destination = destination
        self.pauses = pauses
        self.calls = 0

    async def materialize(self, request: object, staging_path: Path, **_: object) -> Path:
        self.calls += 1
        if self.calls <= self.pauses:
            raise AcquisitionPlacementApprovalRequired(("placement approval",))
        shutil.copy2(staging_path, self.destination)
        return self.destination


class _UnknownMaterializer:
    def __init__(self) -> None:
        self.calls = 0

    async def materialize(self, request: object, staging_path: Path, **_: object) -> Path:
        del request, staging_path
        self.calls += 1
        raise AcquisitionUnknownOutcome("placement terminal evidence unavailable")


class _SuccessfulMaterializerWithStagingDirectory:
    def __init__(self, destination: Path) -> None:
        self.destination = destination

    async def materialize(self, request: object, staging_path: Path, **_: object) -> Path:
        del request
        shutil.copy2(staging_path, self.destination)
        staging_path.unlink()
        staging_path.mkdir()
        return self.destination


def _volume(volume_id: str, mount: Path, *, network: bool = False) -> VolumeObservation:
    return VolumeObservation(
        volume_id,
        (str(mount),),
        "NTFS",
        10_000,
        1_000,
        9_000,
        VolumeDriveType.FIXED,
        "ssd",
        "healthy",
        "encrypted",
        False,
        False,
        False,
        network,
        datetime.now(UTC),
        "p3a-test",
        True,
    )


def test_p3a_trusted_root_requires_preprovisioning_and_exact_resource_child(
    tmp_path: Path,
) -> None:
    mount = tmp_path / "volume"
    root = mount / "JARVIS" / "acquisitions"
    root.mkdir(parents=True)
    observed = (_volume("volume-1", mount),)
    resolver = ProvisionedPlacementRootResolver()

    trusted = resolver.resolve(
        volume_id="volume-1",
        resource_id="resource.one",
        target_location=str(root / "resource_one"),
        volumes=observed,
    )
    assert trusted is not None and trusted.root == root.resolve()

    attacker_parent = tmp_path / "attacker"
    attacker_parent.mkdir()
    assert (
        resolver.resolve(
            volume_id="volume-1",
            resource_id="resource.one",
            target_location=str(attacker_parent / "resource_one"),
            volumes=observed,
        )
        is None
    )
    assert not any(
        candidate == attacker_parent.resolve()
        for candidate in FileSteward(tmp_path / "staging").trusted_roots
    )


def test_p3a_missing_root_is_not_created_and_unsafe_volume_is_rejected(tmp_path: Path) -> None:
    mount = tmp_path / "volume"
    observed = (_volume("volume-1", mount),)
    resolver = ProvisionedPlacementRootResolver()
    target = mount / "JARVIS" / "acquisitions" / "resource"
    assert (
        resolver.resolve(
            volume_id="volume-1",
            resource_id="resource",
            target_location=str(target),
            volumes=observed,
        )
        is None
    )

    assert (
        resolver.resolve(
            volume_id=None, resource_id="resource", target_location=str(target), volumes=observed
        )
        is None
    )
    assert (
        resolver.resolve(
            volume_id="volume-1", resource_id="resource", target_location=None, volumes=observed
        )
        is None
    )
    assert (
        resolver.resolve(
            volume_id="missing",
            resource_id="resource",
            target_location=str(target),
            volumes=observed,
        )
        is None
    )
    assert (
        resolver.resolve(
            volume_id="volume-1", resource_id="resource", target_location="\0", volumes=observed
        )
        is None
    )
    assert not (mount / "JARVIS").exists()
    (mount / "JARVIS" / "acquisitions").mkdir(parents=True)
    assert (
        resolver.resolve(
            volume_id="volume-1",
            resource_id="resource",
            target_location=str(target),
            volumes=(_volume("volume-1", mount, network=True),),
        )
        is None
    )


@pytest.mark.asyncio
async def test_p3a_stages_inside_transport_and_materializes_through_filesteward(
    tmp_path: Path,
) -> None:
    staging_root = tmp_path / "staging"
    placement_root = tmp_path / "approved-volume" / "JARVIS" / "acquisitions"
    placement_root.mkdir(parents=True)
    rule = PolicyRule(
        "p3a-file-placement",
        Permission.FILESYSTEM_WRITE,
        Decision.ALLOW,
        ScopeConstraint(
            paths=(str(staging_root), str(placement_root)),
            tools=frozenset({"storage.file_steward"}),
        ),
        frozenset({"storage.file.move"}),
    )
    steward = FileSteward(
        staging_root,
        trusted_roots=(placement_root,),
        permission_broker=PermissionBroker(PolicyEngine((rule,))),
        host_bridge=HostBridge(),
    )
    broker = AcquisitionBroker(
        BoundedDownloadTransport(staging_root),
        AcquisitionPolicy(
            mode=AcquisitionPolicyMode.JARVIS_MANAGED, require_known_disk_capacity=False
        ),
        InMemoryAcquisitionLedger(),
        materializer=FileStewardAcquisitionMaterializer(steward),
    )
    request = replace(
        _request("http://127.0.0.1:1/not-used", resource_type=ResourceType.FILE),
        target_location=str(placement_root / "resource.bin"),
        jarvis_owned=True,
    )
    with _resource_server() as (_server, source):
        result = await broker.acquire(replace(request, source=source), disk_free_bytes=10_000)
        assert result.materialized_path == placement_root / "resource.bin"
        assert result.materialized_path.read_bytes() == PAYLOAD
        assert not (staging_root / ".staging" / f"{request.fingerprint}.artifact").exists()
        assert result.artifact.state is ArtifactState.REGISTERED
        duplicate = await broker.acquire(replace(request, source=source), disk_free_bytes=10_000)
        assert duplicate.status.value == "duplicate"
        assert duplicate.materialized_path == placement_root / "resource.bin"


def test_p3a_file_steward_rejects_unregistered_final_root(tmp_path: Path) -> None:
    root = tmp_path / "staging"
    root.mkdir()
    source = root / "verified.bin"
    source.write_bytes(b"verified")
    steward = FileSteward(root)
    with pytest.raises(Exception, match="outside the trusted file scope"):
        steward.plan_move(source, tmp_path / "unapproved" / "final.bin")


def test_p3a_file_steward_registration_requires_resolver_evidence(tmp_path: Path) -> None:
    root = tmp_path / "staging"
    root.mkdir()
    steward = FileSteward(root)
    with pytest.raises(MutationDenied, match="evidence is malformed"):
        steward.register_provisioned_root(cast(TrustedPlacementRoot, object()))
    missing = tmp_path / "volume" / "JARVIS" / "acquisitions"
    with pytest.raises(MutationDenied, match="unavailable or unsafe"):
        steward.register_provisioned_root(
            TrustedPlacementRoot("volume", tmp_path / "volume", missing)
        )
    assert steward._is_safe_owned(root / "child")  # noqa: SLF001
    assert not steward._is_safe_owned(tmp_path / "outside")  # noqa: SLF001


def test_p3a_placement_plan_without_mount_has_no_target_location() -> None:
    plan = PlacementPlan(
        uuid4(),
        ResourcePlacementRequest("resource", StorageResourceType.DATASET, 1),
        PlacementStatus.NO_COMPATIBLE_TARGET,
        None,
        None,
        None,
        (),
        (),
    )
    assert plan.target_location is None
    assert str(replace(plan, target_mount_point="C:/safe").target_location).replace("\\", "/") == (
        "C:/safe/JARVIS/acquisitions/resource"
    )


def test_p3a_filesteward_rejects_reparse_trusted_root(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    extra = tmp_path / "placement"
    extra.mkdir()
    calls = [0]

    def report_reparse(_path: Path) -> bool:
        calls[0] += 1
        return calls[0] >= 7

    monkeypatch.setattr(storage_module, "_has_reparse_ancestor", report_reparse)
    with pytest.raises(MutationDenied, match="trusted placement root is unsafe"):
        FileSteward(tmp_path / "staging", trusted_roots=(extra,))


def test_p3a_manifest_lookup_skips_corrupt_durable_entries(tmp_path: Path) -> None:
    store = MutationManifestStore(tmp_path / "manifests")
    (store.manifest_root / "corrupt.json").write_text("{", encoding="utf-8")
    assert (
        store.find_planned_effect(
            uuid4(), cast(MutationOperation, object()), tmp_path / "a", tmp_path / "b"
        )
        is None
    )


def test_p3a_materializer_rejects_untrusted_request_and_invalid_owner() -> None:
    with pytest.raises(MutationDenied, match="FileSteward is required"):
        FileStewardAcquisitionMaterializer(cast(FileSteward, object()))


@pytest.mark.asyncio
async def test_p3a_materializer_rejects_non_owned_request(tmp_path: Path) -> None:
    steward = FileSteward(tmp_path / "staging")
    stage = steward.root / "verified.bin"
    stage.write_bytes(PAYLOAD)
    request = replace(
        _request("https://example.test/resource"),
        target_location=str(tmp_path / "final"),
        jarvis_owned=False,
    )
    with pytest.raises(MutationDenied, match="must be JARVIS-owned"):
        await FileStewardAcquisitionMaterializer(steward).materialize(
            request, stage, task_id=uuid4(), user_id=None
        )


@pytest.mark.asyncio
async def test_p3a_materializer_quarantines_unknown_steward_effect(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    steward = FileSteward(tmp_path / "staging")
    stage = steward.root / "verified.bin"
    stage.write_bytes(PAYLOAD)
    destination = steward.root / "final.bin"
    request = replace(
        _request("https://example.test/resource"),
        target_location=str(destination),
        jarvis_owned=True,
    )

    async def unknown(
        _self: FileSteward, _manifest: object, *, user_id: str | None = None
    ) -> MutationResult:
        del user_id
        raise MutationUnknownOutcome("effect boundary unavailable")

    monkeypatch.setattr(FileSteward, "execute_async", unknown)
    with pytest.raises(AcquisitionUnknownOutcome, match="requires reconciliation"):
        await FileStewardAcquisitionMaterializer(steward).materialize(
            request, stage, task_id=uuid4(), user_id=None
        )


@pytest.mark.asyncio
async def test_p3a_materializer_requires_independent_terminal_verification(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    steward = FileSteward(tmp_path / "staging")
    stage = steward.root / "verified.bin"
    stage.write_bytes(PAYLOAD)
    destination = steward.root / "final.bin"
    request = replace(
        _request("https://example.test/resource"),
        target_location=str(destination),
        jarvis_owned=True,
    )

    async def incomplete(
        _self: FileSteward, manifest: object, *, user_id: str | None = None
    ) -> MutationResult:
        del user_id
        return MutationResult(manifest, None, None, 0, 0)  # type: ignore[arg-type]

    monkeypatch.setattr(FileSteward, "execute_async", incomplete)
    with pytest.raises(AcquisitionUnknownOutcome, match="independently verified"):
        await FileStewardAcquisitionMaterializer(steward).materialize(
            request, stage, task_id=uuid4(), user_id=None
        )


@pytest.mark.asyncio
async def test_p3a_approval_resume_reuses_verified_staging_without_redownload(
    tmp_path: Path,
) -> None:
    with _counting_source() as (source, count):
        destination = tmp_path / "final.bin"
        materializer = _PauseOnceMaterializer(destination)
        broker = AcquisitionBroker(
            BoundedDownloadTransport(tmp_path / "download-root"),
            AcquisitionPolicy(
                mode=AcquisitionPolicyMode.JARVIS_MANAGED,
                require_known_disk_capacity=False,
            ),
            InMemoryAcquisitionLedger(),
            materializer=materializer,
        )
        request = replace(_request(source), jarvis_owned=True)
        with pytest.raises(AcquisitionPlacementApprovalRequired):
            await broker.acquire(request, disk_free_bytes=10_000)
        pending = broker.ledger.get(request.fingerprint)
        assert pending is not None and pending.state is ArtifactState.PLACEMENT_PENDING
        result = await broker.acquire(request, disk_free_bytes=10_000)
        assert result.materialized_path == destination
        assert destination.read_bytes() == PAYLOAD
        assert count[0] == 1
        assert materializer.calls == 2


@pytest.mark.asyncio
async def test_p3a_resume_approval_keeps_staging_and_never_redownloads(tmp_path: Path) -> None:
    with _counting_source() as (source, count):
        destination = tmp_path / "final.bin"
        materializer = _PauseOnceMaterializer(destination, pauses=2)
        broker = AcquisitionBroker(
            BoundedDownloadTransport(tmp_path / "download-root"),
            AcquisitionPolicy(
                mode=AcquisitionPolicyMode.JARVIS_MANAGED,
                require_known_disk_capacity=False,
            ),
            InMemoryAcquisitionLedger(),
            materializer=materializer,
        )
        request = replace(_request(source), jarvis_owned=True)
        with pytest.raises(AcquisitionPlacementApprovalRequired):
            await broker.acquire(request, disk_free_bytes=10_000)
        with pytest.raises(AcquisitionPlacementApprovalRequired):
            await broker.acquire(request, disk_free_bytes=10_000)
        result = await broker.acquire(request, disk_free_bytes=10_000)
        assert result.materialized_path == destination
        assert count[0] == 1
        assert materializer.calls == 3


@pytest.mark.asyncio
async def test_p3a_resume_staging_disposition_is_unknown_and_not_registered(tmp_path: Path) -> None:
    with _resource_server() as (_server, source):
        destination = tmp_path / "final.bin"
        approval = _PauseOnceMaterializer(destination)
        broker = AcquisitionBroker(
            BoundedDownloadTransport(tmp_path / "download-root"),
            AcquisitionPolicy(
                mode=AcquisitionPolicyMode.JARVIS_MANAGED,
                require_known_disk_capacity=False,
            ),
            InMemoryAcquisitionLedger(),
            materializer=approval,
        )
        request = replace(_request(source), jarvis_owned=True)
        with pytest.raises(AcquisitionPlacementApprovalRequired):
            await broker.acquire(request, disk_free_bytes=10_000)
        broker._materializer = _SuccessfulMaterializerWithStagingDirectory(destination)  # noqa: SLF001
        with pytest.raises(AcquisitionUnknownOutcome, match="staging disposition"):
            await broker.acquire(request, disk_free_bytes=10_000)
        record = broker.ledger.get(request.fingerprint)
        assert record is not None and record.state is ArtifactState.PLACEMENT_PENDING


@pytest.mark.asyncio
async def test_p3a_resume_target_revalidation_exception_is_unknown_and_no_second_effect(
    tmp_path: Path,
) -> None:
    with _resource_server() as (_server, source):
        destination = tmp_path / "final.bin"
        state = {"fail": False}
        materializer = _PauseOnceMaterializer(destination)
        broker = AcquisitionBroker(
            BoundedDownloadTransport(tmp_path / "download-root"),
            AcquisitionPolicy(
                mode=AcquisitionPolicyMode.JARVIS_MANAGED,
                require_known_disk_capacity=False,
            ),
            InMemoryAcquisitionLedger(),
            materializer=materializer,
            target_revalidator=lambda _request: (
                (_ for _ in ()).throw(RuntimeError("live probe")) if state["fail"] else None
            ),
        )
        request = replace(_request(source), jarvis_owned=True)
        with pytest.raises(AcquisitionPlacementApprovalRequired):
            await broker.acquire(request, disk_free_bytes=10_000)
        state["fail"] = True
        with pytest.raises(AcquisitionStaleTarget, match="RuntimeError"):
            await broker.acquire(request, disk_free_bytes=10_000)
        assert materializer.calls == 1


@pytest.mark.asyncio
async def test_p3a_unknown_placement_is_quarantined_across_restart_attempts(tmp_path: Path) -> None:
    with _counting_source() as (source, count):
        materializer = _UnknownMaterializer()
        ledger = InMemoryAcquisitionLedger()
        broker = AcquisitionBroker(
            BoundedDownloadTransport(tmp_path / "download-root"),
            AcquisitionPolicy(
                mode=AcquisitionPolicyMode.JARVIS_MANAGED,
                require_known_disk_capacity=False,
            ),
            ledger,
            materializer=materializer,
        )
        request = replace(_request(source), jarvis_owned=True)
        with pytest.raises(AcquisitionUnknownOutcome):
            await broker.acquire(request, disk_free_bytes=10_000)
        with pytest.raises(AcquisitionUnknownOutcome):
            await broker.acquire(request, disk_free_bytes=10_000)
        pending = ledger.get(request.fingerprint)
        assert pending is not None and pending.state is ArtifactState.PLACEMENT_PENDING
        assert count[0] == 1
        assert materializer.calls == 2


@pytest.mark.asyncio
async def test_p3a_unresolved_staging_disposition_is_not_registered(tmp_path: Path) -> None:
    with _resource_server() as (_server, source):
        destination = tmp_path / "final.bin"
        broker = AcquisitionBroker(
            BoundedDownloadTransport(tmp_path / "download-root"),
            AcquisitionPolicy(
                mode=AcquisitionPolicyMode.JARVIS_MANAGED,
                require_known_disk_capacity=False,
            ),
            InMemoryAcquisitionLedger(),
            materializer=_SuccessfulMaterializerWithStagingDirectory(destination),
        )
        request = replace(_request(source), jarvis_owned=True)
        with pytest.raises(AcquisitionUnknownOutcome, match="staging disposition"):
            await broker.acquire(request, disk_free_bytes=10_000)
        record = broker.ledger.get(request.fingerprint)
        assert record is not None and record.state is ArtifactState.VERIFIED_STAGED
        assert destination.read_bytes() == PAYLOAD


@pytest.mark.asyncio
async def test_p3a_live_target_revalidation_exception_fails_closed_without_effect(
    tmp_path: Path,
) -> None:
    with _counting_source() as (source, count):
        destination = tmp_path / "final.bin"
        materializer = _PauseOnceMaterializer(destination)
        broker = AcquisitionBroker(
            BoundedDownloadTransport(tmp_path / "download-root"),
            AcquisitionPolicy(
                mode=AcquisitionPolicyMode.JARVIS_MANAGED,
                require_known_disk_capacity=False,
            ),
            InMemoryAcquisitionLedger(),
            materializer=materializer,
            target_revalidator=lambda _request: (_ for _ in ()).throw(RuntimeError("probe")),
        )
        request = replace(_request(source), jarvis_owned=True)
        with pytest.raises(AcquisitionStaleTarget, match="RuntimeError"):
            await broker.acquire(request, disk_free_bytes=10_000)
        assert count[0] == 0
        assert materializer.calls == 0


@pytest.mark.asyncio
async def test_p3a_restart_resume_uses_durable_staging_without_redownload(tmp_path: Path) -> None:
    staging_root = tmp_path / "download-root"
    placement_root = tmp_path / "volume" / "JARVIS" / "acquisitions"
    placement_root.mkdir(parents=True)
    scope = ScopeConstraint(
        paths=(str(staging_root), str(placement_root)),
        tools=frozenset({"storage.file_steward"}),
    )
    actions = frozenset({"storage.file.move"})
    permission = Permission.FILESYSTEM_WRITE
    task_id = uuid4()
    request_target = placement_root / "resource.bin"
    with _counting_source() as (source, count):
        ledger_path = tmp_path / "acquisition.sqlite3"
        first_broker = PermissionBroker(
            PolicyEngine(
                (
                    PolicyRule(
                        "require-placement", permission, Decision.REQUIRE_APPROVAL, scope, actions
                    ),
                )
            )
        )
        first_steward = FileSteward(
            staging_root,
            trusted_roots=(placement_root,),
            permission_broker=first_broker,
            host_bridge=HostBridge(),
        )
        first = AcquisitionBroker(
            BoundedDownloadTransport(staging_root),
            AcquisitionPolicy(
                mode=AcquisitionPolicyMode.JARVIS_MANAGED,
                require_known_disk_capacity=False,
            ),
            SQLiteAcquisitionLedger(ledger_path),
            materializer=FileStewardAcquisitionMaterializer(first_steward),
        )
        request = replace(_request(source), target_location=str(request_target), jarvis_owned=True)
        with pytest.raises(AcquisitionPlacementApprovalRequired):
            await first.acquire(request, task_id=task_id, disk_free_bytes=10_000)
        pending = first.ledger.get(request.fingerprint)
        assert pending is not None and pending.state is ArtifactState.PLACEMENT_PENDING
        assert count[0] == 1
        assert not request_target.exists()
        await first.aclose()

        second_broker = PermissionBroker(
            PolicyEngine(
                (PolicyRule("allow-placement", permission, Decision.ALLOW, scope, actions),)
            )
        )
        second_steward = FileSteward(
            staging_root,
            trusted_roots=(placement_root,),
            permission_broker=second_broker,
            host_bridge=HostBridge(),
        )
        second = AcquisitionBroker(
            BoundedDownloadTransport(staging_root),
            AcquisitionPolicy(
                mode=AcquisitionPolicyMode.JARVIS_MANAGED,
                require_known_disk_capacity=False,
            ),
            SQLiteAcquisitionLedger(ledger_path),
            materializer=FileStewardAcquisitionMaterializer(second_steward),
        )
        result = await second.acquire(request, task_id=task_id, disk_free_bytes=10_000)
        assert result.materialized_path == request_target
        assert request_target.read_bytes() == PAYLOAD
        assert count[0] == 1
        second_record = second.ledger.get(request.fingerprint)
        assert second_record is not None and second_record.state is ArtifactState.REGISTERED
        await second.aclose()
