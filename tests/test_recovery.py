from __future__ import annotations

import hashlib
import json
from collections.abc import Callable
from datetime import UTC, datetime, timedelta
from pathlib import Path
from uuid import uuid4

import pytest
from jarvis.credentials import TestOnlyInMemorySecretBackend
from jarvis.recovery import (
    RecoveryCoordinator,
    RecoveryError,
    RecoveryEvidence,
    RecoveryManifest,
    RecoveryPhase,
    RecoveryStore,
    StartupAttemptStatus,
    TrustedRecoveryAuthority,
)


def _application_hash(revision: str) -> str:
    return hashlib.sha256(revision.encode("utf-8")).hexdigest()


def _store(
    root: Path,
    *,
    retention: int = 5,
    clock: Callable[[], datetime] | None = None,
) -> RecoveryStore:
    backend = TestOnlyInMemorySecretBackend()
    authority = TrustedRecoveryAuthority("synthetic-installation", backend)
    authority.initialize()
    return RecoveryStore(
        root,
        retention=retention,
        clock=clock,
        trusted_authority=authority,
    )


def _snapshot(store: RecoveryStore, tx: str | None = None) -> str:
    return store.create_snapshot(
        transaction_id=tx or str(uuid4()),
        app_revision="rev-1",
        application_hash=_application_hash("rev-1"),
        configuration={"voice": False},
        database_schema={"planning": 4},
        integration_versions={},
        migrations=("planning:4",),
        generated_package_state={"index": "clean"},
    ).snapshot_id


class FakeClock:
    def __init__(self) -> None:
        self.value = datetime(2026, 8, 24, 12, tzinfo=UTC)

    def __call__(self) -> datetime:
        return self.value


def _parse_deadline(value: str) -> datetime:
    parsed = datetime.fromisoformat(value)
    assert parsed.tzinfo is not None
    return parsed


def _build_pair(root: Path, clock: FakeClock) -> tuple[RecoveryStore, str, str, Path]:
    recovery_root = root / "recovery"
    state = recovery_root / "state.txt"
    state.parent.mkdir(parents=True)
    state.write_text("known-good", encoding="utf-8")
    store = _store(recovery_root, clock=clock)
    lkg = store.create_snapshot(
        transaction_id="lkg-tx",
        app_revision="build-lkg",
        application_hash=_application_hash("build-lkg"),
        configuration={"mode": "safe"},
        database_schema={"planning": 4},
        integration_versions={"core": "lkg"},
        migrations=("planning:4",),
        files=(state,),
    ).snapshot_id
    store.begin_start("lkg-tx", candidate_snapshot_id=lkg)
    store.commit_start("lkg-tx", lkg)
    state.write_text("candidate-state", encoding="utf-8")
    candidate = store.create_snapshot(
        transaction_id="candidate-tx",
        app_revision="build-candidate",
        application_hash=_application_hash("build-candidate"),
        configuration={"mode": "candidate"},
        database_schema={"planning": 5},
        integration_versions={"core": "candidate"},
        migrations=("planning:5",),
        files=(state,),
    ).snapshot_id
    return store, lkg, candidate, state


def test_snapshot_manifest_tracks_revision_schema_migrations_and_lkg(tmp_path: Path) -> None:
    store = _store(tmp_path / "recovery", retention=2)
    tx = str(uuid4())
    snapshot_id = _snapshot(store, tx)
    store.begin_start(tx)
    store.commit_start(tx, snapshot_id)

    manifest = store.load(snapshot_id)
    assert manifest.transaction_id == tx
    assert manifest.database_schema == {"planning": 4}
    assert store.last_known_good() == snapshot_id
    assert not store.active.exists()


def test_snapshot_copies_and_restores_selected_file(tmp_path: Path) -> None:
    root = tmp_path / "recovery"
    source = root / "state.txt"
    source.parent.mkdir(parents=True)
    source.write_text("known-good", encoding="utf-8")
    store = _store(root)
    manifest = store.create_snapshot(
        transaction_id="tx",
        app_revision="rev",
        application_hash=_application_hash("rev"),
        configuration={},
        database_schema={},
        integration_versions={},
        files=(source,),
    )
    destination = tmp_path / "restored" / "state.txt"
    source.write_text("changed", encoding="utf-8")
    store.restore(manifest.snapshot_id, destinations={"state.txt": destination})
    assert destination.read_text(encoding="utf-8") == "known-good"
    assert dict(manifest.file_hashes)["state.txt"]
    with pytest.raises(RecoveryError, match="regular file"):
        store.restore(manifest.snapshot_id, destinations={"state.txt": destination.parent})


def test_snapshot_file_tampering_is_rejected_before_restore(tmp_path: Path) -> None:
    root = tmp_path / "recovery"
    source = root / "state.txt"
    source.parent.mkdir(parents=True)
    source.write_text("known-good", encoding="utf-8")
    store = _store(root)
    manifest = store.create_snapshot(
        transaction_id="tx",
        app_revision="rev",
        application_hash=_application_hash("rev"),
        configuration={},
        database_schema={},
        integration_versions={},
        files=(source,),
    )
    stored = store.snapshots / manifest.snapshot_id / "files" / "state.txt"
    stored.write_text("tampered", encoding="utf-8")

    with pytest.raises(RecoveryError, match="integrity"):
        store.load(manifest.snapshot_id)


def test_snapshot_rejects_unsafe_sources_and_malformed_identifiers(tmp_path: Path) -> None:
    store = _store(tmp_path / "recovery")
    outside = tmp_path / "outside.txt"
    outside.write_text("no", encoding="utf-8")
    with pytest.raises(RecoveryError, match="escaped"):
        store.create_snapshot(
            transaction_id="tx",
            app_revision="rev",
            application_hash=_application_hash("rev"),
            configuration={},
            database_schema={},
            integration_versions={},
            files=(outside,),
        )
    with pytest.raises(ValueError, match="retention"):
        _store(tmp_path / "other", retention=0)
    with pytest.raises(RecoveryError, match="malformed"):
        store.load("../escape")


def test_snapshot_rejects_secret_metadata_and_future_schema(tmp_path: Path) -> None:
    store = _store(tmp_path / "recovery")
    with pytest.raises(RecoveryError):
        store.create_snapshot(
            transaction_id="tx",
            app_revision="rev",
            application_hash=_application_hash("rev"),
            configuration={"access_token": "never"},
            database_schema={},
            integration_versions={},
        )
    snapshot_id = _snapshot(store)
    manifest_path = store.snapshots / snapshot_id / "manifest.json"
    raw = json.loads(manifest_path.read_text(encoding="utf-8"))
    raw["schema_version"] = 99
    manifest_path.write_text(json.dumps(raw), encoding="utf-8")
    with pytest.raises(RecoveryError, match="future"):
        store.load(snapshot_id)
    manifest_path.write_text("not-json", encoding="utf-8")
    with pytest.raises(RecoveryError, match="malformed"):
        store.load(snapshot_id)


def test_restore_is_atomic_and_rejects_unlisted_file(tmp_path: Path) -> None:
    root = tmp_path / "recovery"
    source = root / "state.txt"
    source.parent.mkdir(parents=True)
    source.write_text("known-good", encoding="utf-8")
    store = _store(root)
    snapshot_id = _snapshot(store)
    # A snapshot without a file cannot be used to restore an arbitrary path.
    with pytest.raises(RecoveryError, match="absent"):
        store.restore(snapshot_id, destinations={"state.txt": tmp_path / "destination.txt"})


def test_failed_start_is_recorded_and_safe_mode_disables_effects(tmp_path: Path) -> None:
    store = _store(tmp_path / "recovery")
    coordinator = RecoveryCoordinator(store)
    assert store.begin_start("first") is False
    assert store.begin_start("second") is True
    coordinator.enter_safe_mode("second", "crash loop")
    assert not coordinator.can_privileged_mutate()
    assert not coordinator.can_activate_generated()
    assert not coordinator.can_self_update()
    assert not coordinator.can_schedule()
    assert coordinator.capabilities.diagnostics
    assert coordinator.capabilities.rollback
    entries = store.evidence.read_text(encoding="utf-8")
    assert RecoveryPhase.FAIL.value in entries
    assert RecoveryPhase.SAFE_MODE.value in entries


def test_crash_loop_threshold_and_malformed_evidence_fail_closed(tmp_path: Path) -> None:
    store = _store(tmp_path / "recovery")
    coordinator = RecoveryCoordinator(store, crash_loop_limit=2)
    assert coordinator.begin_start("one") is False
    assert coordinator.begin_start("two") is True
    assert coordinator.begin_start("three") is True
    assert coordinator.safe_mode
    with pytest.raises(ValueError, match="crash_loop_limit"):
        RecoveryCoordinator(store, crash_loop_limit=0)
    store.evidence.write_text("broken\n", encoding="utf-8")
    with pytest.raises(RecoveryError, match="evidence"):
        store.failed_start_count()


def test_successful_commit_resets_consecutive_crash_loop_count(tmp_path: Path) -> None:
    store = _store(tmp_path / "recovery")
    first = _snapshot(store, "first")
    store.record(
        RecoveryEvidence(
            "old-1", RecoveryPhase.FAIL, "failed_start", "old failure", None, _now_for_test()
        )
    )
    store.record(
        RecoveryEvidence(
            "old-2", RecoveryPhase.FAIL, "failed_start", "old failure", None, _now_for_test()
        )
    )
    assert store.failed_start_count() == 2
    store.begin_start("first")
    store.commit_start("first", first)
    assert store.failed_start_count() == 0


def _now_for_test() -> str:
    return datetime(2026, 8, 24, 12, tzinfo=UTC).isoformat()


def test_retention_keeps_lkg_restore_point(tmp_path: Path) -> None:
    store = _store(tmp_path / "recovery", retention=1)
    first = _snapshot(store, "one")
    store.begin_start("one")
    store.commit_start("one", first)
    second = _snapshot(store, "two")
    assert store.load(first).snapshot_id == first
    assert store.load(second).snapshot_id == second


def test_lkg_and_transaction_mismatches_fail_closed(tmp_path: Path) -> None:
    store = _store(tmp_path / "recovery")
    snapshot_id = _snapshot(store, "one")
    store.begin_start("one")
    with pytest.raises(RecoveryError, match="does not match"):
        store.commit_start("two", snapshot_id)
    store.lkg.write_text(json.dumps({"snapshot_id": "missing"}), encoding="utf-8")
    with pytest.raises(RecoveryError, match="last-known-good"):
        store.last_known_good()


def test_failure_rolls_back_lkg_and_safe_modes_on_bad_health(tmp_path: Path) -> None:
    root = tmp_path / "recovery"
    source = root / "state.txt"
    source.parent.mkdir(parents=True)
    source.write_text("good", encoding="utf-8")
    store = _store(root)
    manifest = store.create_snapshot(
        transaction_id="good-tx",
        app_revision="rev",
        application_hash=_application_hash("rev"),
        configuration={},
        database_schema={},
        integration_versions={},
        files=(source,),
    )
    store.begin_start("good-tx")
    store.commit_start("good-tx", manifest.snapshot_id)
    source.write_text("bad", encoding="utf-8")
    coordinator = RecoveryCoordinator(store)
    assert (
        coordinator.fail_and_restore(
            "bad-tx",
            failed_phase=RecoveryPhase.HEALTH_CHECK,
            detail="failed start",
            destinations={"state.txt": source},
            health_check=lambda: False,
        )
        == manifest.snapshot_id
    )
    assert source.read_text(encoding="utf-8") == "good"
    assert coordinator.safe_mode


def test_failure_without_lkg_enters_safe_mode(tmp_path: Path) -> None:
    coordinator = RecoveryCoordinator(_store(tmp_path / "recovery"))
    assert (
        coordinator.fail_and_restore("tx", failed_phase=RecoveryPhase.APPLY, detail="apply failed")
        is None
    )
    assert coordinator.safe_mode


def test_candidate_boot_commits_only_after_deadline_bounded_health(tmp_path: Path) -> None:
    clock = FakeClock()
    store, lkg, candidate, _state = _build_pair(tmp_path, clock)
    coordinator = RecoveryCoordinator(
        store,
        startup_deadline=timedelta(seconds=10),
        clock=clock,
    )
    started: list[str] = []

    result = coordinator.boot_candidate(
        "candidate-tx",
        candidate,
        start=lambda: started.append("candidate"),
        health_check=lambda: True,
    )

    assert result == candidate
    assert started == ["candidate"]
    assert store.last_known_good() == candidate
    assert not store.active.exists()
    assert store.failed_candidate_snapshot_ids() == frozenset()
    assert store.load(lkg).app_revision == "build-lkg"


def test_bad_candidate_restores_restarts_and_verifies_lkg(tmp_path: Path) -> None:
    clock = FakeClock()
    store, lkg, candidate, state = _build_pair(tmp_path, clock)
    coordinator = RecoveryCoordinator(store, clock=clock)
    calls: list[str] = []

    def restart_lkg(manifest: RecoveryManifest) -> bool:
        calls.append(manifest.app_revision)
        return True

    def reconcile_migrations(manifest: RecoveryManifest) -> bool:
        calls.append(",".join(manifest.migrations))
        return True

    result = coordinator.boot_candidate(
        "candidate-tx",
        candidate,
        start=lambda: calls.append("candidate-start"),
        health_check=lambda: False,
        lkg_health_check=lambda: True,
        restart_lkg=restart_lkg,
        migration_reconcile=reconcile_migrations,
        destinations={"state.txt": state},
        incident_evidence=("health:unavailable", "process:exit-1"),
    )

    assert result == lkg
    assert calls == ["candidate-start", "planning:4", "build-lkg"]
    assert state.read_text(encoding="utf-8") == "known-good"
    assert store.last_known_good() == lkg
    assert candidate in store.failed_candidate_snapshot_ids()
    assert not store.active.exists()
    evidence = store.evidence.read_text(encoding="utf-8")
    assert "health:unavailable" in evidence
    assert "build-candidate" in evidence
    assert "build-lkg" in evidence


def test_candidate_start_exception_is_recovered_once(tmp_path: Path) -> None:
    clock = FakeClock()
    store, lkg, candidate, state = _build_pair(tmp_path, clock)
    coordinator = RecoveryCoordinator(store, clock=clock)
    attempts = 0

    def bad_start() -> None:
        nonlocal attempts
        attempts += 1
        raise RuntimeError("bad build")

    assert (
        coordinator.boot_candidate(
            "candidate-tx",
            candidate,
            start=bad_start,
            health_check=lambda: True,
            restart_lkg=lambda _manifest: True,
            destinations={"state.txt": state},
        )
        == lkg
    )
    assert attempts == 1

    # A retry of the same failed candidate cannot start it again.
    assert (
        coordinator.boot_candidate(
            "bad-start-again",
            candidate,
            start=bad_start,
            health_check=lambda: True,
            restart_lkg=lambda _manifest: True,
            destinations={"state.txt": state},
        )
        == lkg
    )
    assert attempts == 1


def test_deadline_and_lkg_failure_enter_safe_mode(tmp_path: Path) -> None:
    clock = FakeClock()
    store, _lkg, candidate, state = _build_pair(tmp_path, clock)
    coordinator = RecoveryCoordinator(
        store,
        startup_deadline=timedelta(seconds=1),
        clock=clock,
    )

    def candidate_health() -> bool:
        clock.value += timedelta(seconds=2)
        return True

    assert (
        coordinator.boot_candidate(
            "candidate-tx",
            candidate,
            start=lambda: None,
            health_check=candidate_health,
            restart_lkg=lambda _manifest: False,
            destinations={"state.txt": state},
        )
        is None
    )
    assert coordinator.safe_mode
    assert not store.active.exists()


def test_corrupt_lkg_pointer_fails_closed_without_restart_loop(tmp_path: Path) -> None:
    clock = FakeClock()
    store, _lkg, candidate, _state = _build_pair(tmp_path, clock)
    store.lkg.write_text(json.dumps({"snapshot_id": "../missing"}), encoding="utf-8")
    coordinator = RecoveryCoordinator(store, clock=clock)

    assert (
        coordinator.boot_candidate(
            "candidate-tx",
            candidate,
            start=lambda: None,
            health_check=lambda: False,
        )
        is None
    )
    assert coordinator.safe_mode
    assert not store.active.exists()
    assert "lkg_failed" in store.evidence.read_text(encoding="utf-8")


def test_migration_reconciliation_failure_is_fail_closed(tmp_path: Path) -> None:
    clock = FakeClock()
    store, _lkg, candidate, state = _build_pair(tmp_path, clock)
    coordinator = RecoveryCoordinator(store, clock=clock)

    assert (
        coordinator.boot_candidate(
            "candidate-tx",
            candidate,
            start=lambda: None,
            health_check=lambda: False,
            restart_lkg=lambda _manifest: True,
            migration_reconcile=lambda _manifest: False,
            destinations={"state.txt": state},
        )
        is None
    )
    assert coordinator.safe_mode
    assert "LKG migration reconciliation failed" not in store.evidence.read_text(encoding="utf-8")
    assert "last-known-good recovery failed" in store.evidence.read_text(encoding="utf-8")


def test_malformed_active_marker_fails_closed(tmp_path: Path) -> None:
    clock = FakeClock()
    store = _store(tmp_path / "recovery", clock=clock)
    store.active.write_text("not-json", encoding="utf-8")
    with pytest.raises(RecoveryError, match="active startup marker"):
        RecoveryCoordinator(store, clock=clock).begin_start("tx")


def test_startup_attempt_records_build_lkg_deadline_and_migrations(tmp_path: Path) -> None:
    clock = FakeClock()
    store, _lkg, candidate, _state = _build_pair(tmp_path, clock)
    coordinator = RecoveryCoordinator(
        store,
        startup_deadline=timedelta(seconds=30),
        clock=clock,
    )
    coordinator.begin_start("inspect", candidate_snapshot_id=candidate)
    attempt = store.active_start()
    assert attempt.status is StartupAttemptStatus.STARTING
    assert attempt.candidate_snapshot_id == candidate
    assert attempt.candidate_build == "build-candidate"
    assert attempt.lkg_build == "build-lkg"
    assert attempt.migrations == ("planning:5",)
    assert attempt.health_deadline is not None
    assert _parse_deadline(attempt.health_deadline) == clock.value + timedelta(seconds=30)
