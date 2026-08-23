from __future__ import annotations

import json
from pathlib import Path
from uuid import uuid4

import pytest
from jarvis.recovery import (
    RecoveryCoordinator,
    RecoveryError,
    RecoveryPhase,
    RecoveryStore,
)


def _snapshot(store: RecoveryStore, tx: str | None = None) -> str:
    return store.create_snapshot(
        transaction_id=tx or str(uuid4()),
        app_revision="rev-1",
        configuration={"voice": False},
        database_schema={"planning": 4},
        integration_versions={},
        migrations=("planning:4",),
        generated_package_state={"index": "clean"},
    ).snapshot_id


def test_snapshot_manifest_tracks_revision_schema_migrations_and_lkg(tmp_path: Path) -> None:
    store = RecoveryStore(tmp_path / "recovery", retention=2)
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
    store = RecoveryStore(root)
    manifest = store.create_snapshot(
        transaction_id="tx",
        app_revision="rev",
        configuration={},
        database_schema={},
        integration_versions={},
        files=(source,),
    )
    destination = tmp_path / "restored" / "state.txt"
    source.write_text("changed", encoding="utf-8")
    store.restore(manifest.snapshot_id, destinations={"state.txt": destination})
    assert destination.read_text(encoding="utf-8") == "known-good"
    with pytest.raises(RecoveryError, match="regular file"):
        store.restore(manifest.snapshot_id, destinations={"state.txt": destination.parent})


def test_snapshot_rejects_unsafe_sources_and_malformed_identifiers(tmp_path: Path) -> None:
    store = RecoveryStore(tmp_path / "recovery")
    outside = tmp_path / "outside.txt"
    outside.write_text("no", encoding="utf-8")
    with pytest.raises(RecoveryError, match="escaped"):
        store.create_snapshot(
            transaction_id="tx",
            app_revision="rev",
            configuration={},
            database_schema={},
            integration_versions={},
            files=(outside,),
        )
    with pytest.raises(ValueError, match="retention"):
        RecoveryStore(tmp_path / "other", retention=0)
    with pytest.raises(RecoveryError, match="malformed"):
        store.load("../escape")


def test_snapshot_rejects_secret_metadata_and_future_schema(tmp_path: Path) -> None:
    store = RecoveryStore(tmp_path / "recovery")
    with pytest.raises(RecoveryError):
        store.create_snapshot(
            transaction_id="tx",
            app_revision="rev",
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
    store = RecoveryStore(root)
    snapshot_id = _snapshot(store)
    # A snapshot without a file cannot be used to restore an arbitrary path.
    with pytest.raises(RecoveryError, match="absent"):
        store.restore(snapshot_id, destinations={"state.txt": tmp_path / "destination.txt"})


def test_failed_start_is_recorded_and_safe_mode_disables_effects(tmp_path: Path) -> None:
    store = RecoveryStore(tmp_path / "recovery")
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
    store = RecoveryStore(tmp_path / "recovery")
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


def test_retention_keeps_lkg_restore_point(tmp_path: Path) -> None:
    store = RecoveryStore(tmp_path / "recovery", retention=1)
    first = _snapshot(store, "one")
    store.begin_start("one")
    store.commit_start("one", first)
    second = _snapshot(store, "two")
    assert store.load(first).snapshot_id == first
    assert store.load(second).snapshot_id == second


def test_lkg_and_transaction_mismatches_fail_closed(tmp_path: Path) -> None:
    store = RecoveryStore(tmp_path / "recovery")
    snapshot_id = _snapshot(store, "one")
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
    store = RecoveryStore(root)
    manifest = store.create_snapshot(
        transaction_id="good-tx",
        app_revision="rev",
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
    coordinator = RecoveryCoordinator(RecoveryStore(tmp_path / "recovery"))
    assert (
        coordinator.fail_and_restore("tx", failed_phase=RecoveryPhase.APPLY, detail="apply failed")
        is None
    )
    assert coordinator.safe_mode
