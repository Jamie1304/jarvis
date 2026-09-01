"""Synthetic tests for authenticated Recovery/LKG authority."""

from __future__ import annotations

import hashlib
import json
from dataclasses import replace
from pathlib import Path
from typing import Any, cast

import pytest
from jarvis.credentials import (
    CredentialNotFound,
    SecretBackendUnavailable,
    TestOnlyInMemorySecretBackend,
    UnavailableSecretBackend,
)
from jarvis.recovery import (
    RecoveryAuthenticationError,
    RecoveryAuthorityUnavailable,
    RecoveryCoordinator,
    RecoveryError,
    RecoveryManifest,
    RecoveryStore,
    TrustedRecoveryAuthority,
    TrustedRecoveryRecord,
    TrustedRecoveryStatus,
    compute_application_build_hash,
)


class _FailingBackend(TestOnlyInMemorySecretBackend):
    def __init__(
        self,
        *,
        get_error: Exception | None = None,
        put_error: Exception | None = None,
    ) -> None:
        super().__init__()
        self.get_error = get_error
        self.put_error = put_error

    def get(self, target: str) -> bytes:
        if self.get_error is not None:
            raise self.get_error
        return super().get(target)

    def put(self, target: str, secret: bytes) -> None:
        if self.put_error is not None:
            raise self.put_error
        super().put(target, secret)


class _GenerationFailureBackend(TestOnlyInMemorySecretBackend):
    def __init__(self, generation_target: str, error: Exception) -> None:
        super().__init__()
        self.generation_target = generation_target
        self.error = error

    def get(self, target: str) -> bytes:
        if target == self.generation_target:
            raise self.error
        return super().get(target)


def _hash(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def _authority(
    installation_id: str,
    backend: TestOnlyInMemorySecretBackend | None = None,
    *,
    allow_create: bool = True,
) -> tuple[TrustedRecoveryAuthority, TestOnlyInMemorySecretBackend]:
    selected = backend or TestOnlyInMemorySecretBackend()
    authority = TrustedRecoveryAuthority(installation_id, selected)
    authority.initialize(allow_create=allow_create)
    return authority, selected


def _snapshot(
    store: RecoveryStore,
    *,
    transaction_id: str = "tx-1",
    revision: str = "build-1",
) -> str:
    return store.create_snapshot(
        transaction_id=transaction_id,
        app_revision=revision,
        application_hash=_hash(revision),
        configuration={"environment": "test", "security_policy_version": 1},
        database_schema={"planning": "validated"},
        integration_versions={},
        generated_package_state={"activation": "disabled"},
    ).snapshot_id


def _commit(store: RecoveryStore, snapshot_id: str, transaction_id: str = "tx-1") -> None:
    store.begin_start(transaction_id, candidate_snapshot_id=snapshot_id)
    store.commit_start(transaction_id, snapshot_id)


def _record_fixture(
    tmp_path: Path,
) -> tuple[
    TrustedRecoveryAuthority,
    TestOnlyInMemorySecretBackend,
    RecoveryStore,
    RecoveryManifest,
    TrustedRecoveryRecord,
]:
    authority, backend = _authority("installation-verify")
    store = RecoveryStore(tmp_path / "recovery", trusted_authority=authority)
    snapshot = _snapshot(store)
    _commit(store, snapshot)
    record = store.last_known_good_record()
    assert record is not None
    return authority, backend, store, store.load(snapshot), record


def _resign(
    authority: TrustedRecoveryAuthority,
    record: TrustedRecoveryRecord,
    **changes: Any,
) -> TrustedRecoveryRecord:
    unsigned = replace(record, integrity="", **changes)
    return replace(unsigned, integrity=authority._integrity(unsigned))


def test_valid_record_binds_exact_build_snapshot_schema_and_transaction(tmp_path: Path) -> None:
    authority, backend = _authority("installation-a")
    store = RecoveryStore(tmp_path / "recovery", trusted_authority=authority)
    snapshot = _snapshot(store)
    _commit(store, snapshot)

    record = store.last_known_good_record()
    assert record is not None
    assert record.application_hash == _hash("build-1")
    assert record.snapshot_id == snapshot
    assert record.snapshot_manifest_hash == store.snapshot_manifest_hash(snapshot)
    assert record.transaction_id == "tx-1"
    assert record.generation == 1
    assert record.integrity
    assert backend.get(authority._key_target) != record.integrity.encode("ascii")


def test_authenticated_record_survives_restart_with_same_secure_backend(tmp_path: Path) -> None:
    authority, backend = _authority("installation-restart")
    root = tmp_path / "recovery"
    first = RecoveryStore(root, trusted_authority=authority)
    snapshot = _snapshot(first)
    _commit(first, snapshot)

    restarted_authority, _ = _authority("installation-restart", backend, allow_create=False)
    restarted = RecoveryStore(root, trusted_authority=restarted_authority)
    assert restarted.last_known_good() == snapshot


@pytest.mark.parametrize(
    ("field", "replacement"),
    (
        ("app_revision", "forged-build"),
        ("application_hash", "0" * 64),
        ("snapshot_id", "unrelated-snapshot"),
        ("snapshot_manifest_hash", "1" * 64),
        ("transaction_id", "unrelated-transaction"),
        ("status", "failed"),
        ("integrity", "2" * 64),
        ("required_schema_compatibility", [["database:planning", "forged"]]),
    ),
)
def test_modified_authenticated_record_fields_fail_closed(
    tmp_path: Path, field: str, replacement: object
) -> None:
    authority, _ = _authority("installation-tamper")
    store = RecoveryStore(tmp_path / "recovery", trusted_authority=authority)
    snapshot = _snapshot(store)
    _commit(store, snapshot)
    raw = json.loads(store.lkg.read_text(encoding="utf-8"))
    raw[field] = replacement
    store.lkg.write_text(json.dumps(raw), encoding="utf-8")

    with pytest.raises(RecoveryError, match="last-known-good record"):
        store.last_known_good()


def test_missing_key_or_secure_backend_never_creates_a_replacement_key(tmp_path: Path) -> None:
    authority, backend = _authority("installation-missing-key")
    store = RecoveryStore(tmp_path / "recovery", trusted_authority=authority)
    snapshot = _snapshot(store)
    _commit(store, snapshot)
    backend.delete(authority._key_target)

    replacement_backend = TestOnlyInMemorySecretBackend()
    replacement = TrustedRecoveryAuthority("installation-missing-key", replacement_backend)
    with pytest.raises(RecoveryAuthorityUnavailable):
        replacement.initialize(allow_create=False)

    with pytest.raises(RecoveryError, match="last-known-good record"):
        store.last_known_good()
    with pytest.raises(RecoveryAuthorityUnavailable):
        TrustedRecoveryAuthority("new-installation", UnavailableSecretBackend()).initialize()


def test_stale_generation_and_unrelated_installation_are_rejected(tmp_path: Path) -> None:
    authority, backend = _authority("installation-stale")
    store = RecoveryStore(tmp_path / "recovery", trusted_authority=authority)
    snapshot = _snapshot(store)
    _commit(store, snapshot)
    backend.put(authority._generation_target, b"2")
    with pytest.raises(RecoveryError, match="last-known-good record"):
        store.last_known_good()

    other_authority, _ = _authority("installation-other")
    other_store = RecoveryStore(tmp_path / "other", trusted_authority=other_authority)
    other_snapshot = _snapshot(other_store)
    _commit(other_store, other_snapshot)
    store.lkg.write_text(other_store.lkg.read_text(encoding="utf-8"), encoding="utf-8")
    with pytest.raises(RecoveryError, match="last-known-good record"):
        store.last_known_good()


def test_candidate_cannot_promote_without_trusted_startup_lifecycle(tmp_path: Path) -> None:
    authority, _ = _authority("installation-candidate")
    store = RecoveryStore(tmp_path / "recovery", trusted_authority=authority)
    candidate = _snapshot(store, transaction_id="candidate-tx", revision="candidate")

    assert not hasattr(authority, "mark_known_good")
    with pytest.raises(RecoveryError, match="active startup"):
        store.commit_start("candidate-tx", candidate)
    assert not store.lkg.exists()


@pytest.mark.parametrize(
    ("candidate_build", "candidate_application_hash", "message"),
    (
        ("other-build", None, "commit build"),
        (None, _hash("other-build"), "commit application hash"),
    ),
)
def test_commit_binds_active_startup_build_and_hash(
    tmp_path: Path,
    candidate_build: str | None,
    candidate_application_hash: str | None,
    message: str,
) -> None:
    authority, _ = _authority("installation-start-binding")
    store = RecoveryStore(tmp_path / "recovery", trusted_authority=authority)
    snapshot = _snapshot(store, revision="expected-build")
    store.begin_start(
        "tx-1",
        candidate_build=candidate_build,
        candidate_application_hash=candidate_application_hash,
    )

    with pytest.raises(RecoveryError, match=message):
        store.commit_start("tx-1", snapshot)
    assert not store.lkg.exists()


def test_trusted_record_chain_advances_generation_and_links_previous_record(
    tmp_path: Path,
) -> None:
    authority, _ = _authority("installation-chain")
    store = RecoveryStore(tmp_path / "recovery", trusted_authority=authority)
    first_snapshot = _snapshot(store, transaction_id="tx-1", revision="build-1")
    _commit(store, first_snapshot)
    first = store.last_known_good_record()
    assert first is not None

    second_snapshot = _snapshot(store, transaction_id="tx-2", revision="build-2")
    _commit(store, second_snapshot, "tx-2")
    second = store.last_known_good_record()
    assert second is not None
    assert second.generation == first.generation + 1
    assert second.previous_record_id == first.record_id


def test_record_constructor_and_decoder_reject_malformed_security_metadata(
    tmp_path: Path,
) -> None:
    authority, _backend, store, _manifest, record = _record_fixture(tmp_path)
    with pytest.raises(RecoveryAuthenticationError, match="status"):
        replace(record, status=cast(TrustedRecoveryStatus, "failed"))
    with pytest.raises(RecoveryAuthenticationError, match="generation"):
        replace(record, generation=0)
    with pytest.raises(RecoveryAuthenticationError, match="compatibility"):
        replace(record, required_schema_compatibility=cast(Any, [("only",)]))
    with pytest.raises(RecoveryAuthenticationError, match="fields"):
        TrustedRecoveryRecord.from_mapping({"unexpected": True})
    raw = record.payload()
    raw["required_schema_compatibility"] = "not-a-list"
    with pytest.raises(RecoveryAuthenticationError, match="compatibility"):
        TrustedRecoveryRecord.from_mapping(raw)
    raw = record.payload()
    raw["integrity"] = ""
    with pytest.raises(RecoveryAuthenticationError, match="unauthenticated"):
        TrustedRecoveryRecord.from_mapping(raw)
    assert store.last_known_good_record() is not None
    assert authority.authority_identity == TrustedRecoveryAuthority.AUTHORITY_IDENTITY


def test_authority_verifies_each_bound_field_after_valid_authentication(tmp_path: Path) -> None:
    authority, _backend, _store_instance, manifest, record = _record_fixture(tmp_path)
    snapshot_hash = record.snapshot_manifest_hash
    with pytest.raises(RecoveryAuthenticationError, match="transaction"):
        authority.verify(
            record, manifest=None, snapshot_manifest_hash=None, expected_transaction_id="other"
        )
    with pytest.raises(RecoveryAuthenticationError, match="snapshot reference"):
        authority.verify(
            _resign(authority, record, snapshot_id="other"),
            manifest=manifest,
            snapshot_manifest_hash=snapshot_hash,
        )
    with pytest.raises(RecoveryAuthenticationError, match="transaction linkage"):
        authority.verify(
            _resign(authority, record, transaction_id="other"),
            manifest=manifest,
            snapshot_manifest_hash=snapshot_hash,
        )
    with pytest.raises(RecoveryAuthenticationError, match="revision"):
        authority.verify(
            _resign(authority, record, app_revision="other"),
            manifest=manifest,
            snapshot_manifest_hash=snapshot_hash,
        )
    with pytest.raises(RecoveryAuthenticationError, match="application hash"):
        authority.verify(
            record,
            manifest=replace(manifest, application_hash=_hash("other")),
            snapshot_manifest_hash=snapshot_hash,
        )
    with pytest.raises(RecoveryAuthenticationError, match="schema compatibility"):
        authority.verify(
            record,
            manifest=replace(manifest, database_schema={"other": "schema"}),
            snapshot_manifest_hash=snapshot_hash,
        )
    with pytest.raises(RecoveryAuthenticationError, match="manifest hash"):
        authority.verify(record, manifest=manifest, snapshot_manifest_hash="0" * 64)
    other_authority = TrustedRecoveryAuthority(
        "installation-verify",
        _backend,
        authority_identity="other-authority",
    )
    with pytest.raises(RecoveryAuthenticationError, match="authority identity"):
        other_authority.verify(record, manifest=None, snapshot_manifest_hash=None)
    foreign_authority, _ = _authority("foreign-installation")
    with pytest.raises(RecoveryAuthenticationError, match="installation identity"):
        foreign_authority.verify(record, manifest=None, snapshot_manifest_hash=None)


def test_authority_rejects_invalid_backend_values_and_write_failures() -> None:
    with pytest.raises(RecoveryAuthenticationError, match="authentication key"):
        invalid = _FailingBackend()
        invalid.put("jarvis:credential:recovery-lkg:v1:ignored", b"bad")
        # The exact installation-scoped target is created by the authority;
        # seed it through the authority after construction for this fixture.
        invalid_authority = TrustedRecoveryAuthority("bad-key", invalid)
        invalid.put(invalid_authority._key_target, b"bad")
        invalid_authority.initialize()

    with pytest.raises(RecoveryAuthorityUnavailable, match="secure backend"):
        TrustedRecoveryAuthority(
            "get-unavailable",
            _FailingBackend(get_error=SecretBackendUnavailable("unavailable")),
        ).initialize()
    with pytest.raises(RecoveryAuthorityUnavailable, match="secure backend read"):
        TrustedRecoveryAuthority(
            "get-failed",
            _FailingBackend(get_error=RuntimeError("synthetic")),
        ).initialize()
    with pytest.raises(RecoveryAuthorityUnavailable, match="secure backend write"):
        TrustedRecoveryAuthority(
            "put-failed",
            _FailingBackend(
                get_error=CredentialNotFound("missing"), put_error=RuntimeError("synthetic")
            ),
        ).initialize()


def test_generation_backend_failures_and_malformed_floor_fail_closed() -> None:
    authority, backend = _authority("generation-invalid")
    backend.put(authority._generation_target, b"not-an-integer")
    with pytest.raises(RecoveryAuthenticationError, match="generation floor"):
        authority._read_generation_floor(create_if_missing=False)
    backend.put(authority._generation_target, b"-1")
    with pytest.raises(RecoveryAuthenticationError, match="generation floor"):
        authority._read_generation_floor(create_if_missing=False)

    generation_unavailable = _GenerationFailureBackend(
        "placeholder",
        SecretBackendUnavailable("unavailable"),
    )
    generation_authority = TrustedRecoveryAuthority(
        "generation-unavailable", generation_unavailable
    )
    generation_unavailable.generation_target = generation_authority._generation_target
    generation_unavailable.put(generation_authority._key_target, b"k" * 32)
    with pytest.raises(RecoveryAuthorityUnavailable, match="secure backend"):
        generation_authority.initialize(allow_create=False)


def test_promotion_rejects_legacy_manifest_transaction_and_chain_state(
    tmp_path: Path,
) -> None:
    authority, backend, store, manifest, _record = _record_fixture(tmp_path)
    with pytest.raises(RecoveryAuthenticationError, match="current snapshots"):
        authority._promote(
            manifest=replace(manifest, schema_version=2),
            snapshot_manifest_hash=store.snapshot_manifest_hash(manifest.snapshot_id),
            transaction_id=manifest.transaction_id,
            previous=None,
        )
    with pytest.raises(RecoveryAuthenticationError, match="transaction linkage"):
        authority._promote(
            manifest=manifest,
            snapshot_manifest_hash=store.snapshot_manifest_hash(manifest.snapshot_id),
            transaction_id="other",
            previous=None,
        )
    backend.put(authority._generation_target, b"2")
    with pytest.raises(RecoveryAuthenticationError, match="chain"):
        authority._promote(
            manifest=manifest,
            snapshot_manifest_hash=store.snapshot_manifest_hash(manifest.snapshot_id),
            transaction_id=manifest.transaction_id,
            previous=None,
        )


def test_application_build_hash_requires_real_trusted_tree(tmp_path: Path) -> None:
    with pytest.raises(RecoveryError, match="build package"):
        compute_application_build_hash(tmp_path)
    package_root = tmp_path / "package"
    (package_root / "jarvis" / "__pycache__").mkdir(parents=True)
    (package_root / "jarvis" / "module.py").write_text("value = 1", encoding="utf-8")
    (package_root / "jarvis" / "__pycache__" / "module.pyc").write_bytes(b"cache")
    first = compute_application_build_hash(package_root)
    (package_root / "jarvis" / "module.py").write_text("value = 2", encoding="utf-8")
    assert compute_application_build_hash(package_root) != first


def test_failed_health_does_not_promote_candidate(tmp_path: Path) -> None:
    authority, _ = _authority("installation-health")
    store = RecoveryStore(tmp_path / "recovery", trusted_authority=authority)
    known_good = _snapshot(store, transaction_id="good-tx", revision="good")
    _commit(store, known_good, "good-tx")
    candidate = _snapshot(store, transaction_id="candidate-tx", revision="candidate")
    coordinator = RecoveryCoordinator(store)

    assert (
        coordinator.boot_candidate(
            "candidate-tx",
            candidate,
            start=lambda: None,
            health_check=lambda: False,
            lkg_health_check=lambda: True,
        )
        == known_good
    )
    assert store.last_known_good() == known_good


def test_successful_update_promotes_only_after_health_and_commit(tmp_path: Path) -> None:
    authority, _ = _authority("installation-success")
    store = RecoveryStore(tmp_path / "recovery", trusted_authority=authority)
    known_good = _snapshot(store, transaction_id="good-tx", revision="good")
    _commit(store, known_good, "good-tx")
    candidate = _snapshot(store, transaction_id="candidate-tx", revision="candidate")
    coordinator = RecoveryCoordinator(store)

    assert (
        coordinator.boot_candidate(
            "candidate-tx",
            candidate,
            start=lambda: None,
            health_check=lambda: True,
        )
        == candidate
    )
    assert store.last_known_good() == candidate


def test_future_record_schema_fails_closed_during_boot_selection(tmp_path: Path) -> None:
    authority, _ = _authority("installation-future")
    store = RecoveryStore(tmp_path / "recovery", trusted_authority=authority)
    snapshot = _snapshot(store)
    _commit(store, snapshot)
    candidate = _snapshot(store, transaction_id="candidate-tx", revision="candidate")
    raw = json.loads(store.lkg.read_text(encoding="utf-8"))
    raw["schema_version"] = 99
    store.lkg.write_text(json.dumps(raw), encoding="utf-8")

    coordinator = RecoveryCoordinator(store)
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
