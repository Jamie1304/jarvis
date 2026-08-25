from __future__ import annotations

import sqlite3
from dataclasses import replace
from pathlib import Path

import pytest
from jarvis.capability_lifecycle import (
    CapabilityLifecycleConcurrencyError,
    CapabilityLifecycleError,
    LifecycleMetadata,
    SQLiteCapabilityLifecycleStore,
)
from jarvis.integration_package import IntegrationPackage
from jarvis.package_activation import (
    ActivationRecord,
    ActivationRequest,
    ActivationState,
    ActivationValidationError,
    PackageActivationService,
)
from jarvis.package_reviewer import PackageSourceFile
from jarvis.package_runtime import HotLoadManager

from tests.test_package_activation import Factory, Surface, setup


def _durable_fixture(
    tmp_path: Path,
) -> tuple[
    PackageActivationService,
    IntegrationPackage,
    PackageSourceFile,
    ActivationRecord,
    SQLiteCapabilityLifecycleStore,
]:
    service, item, source = setup()
    record = service.record_for(item.package_id, item.version)
    store = SQLiteCapabilityLifecycleStore(tmp_path / "capability-lifecycle.sqlite3")
    store.create(record)
    return service, item, source, record, store


def test_certified_lifecycle_survives_restart_without_implicit_activation(
    tmp_path: Path,
) -> None:
    service, item, source, record, store = _durable_fixture(tmp_path)
    loaded = store.load(item.package_id, str(item.version))
    assert loaded is not None
    assert loaded.record.state is ActivationState.CERTIFIED
    store.close()

    reopened = SQLiteCapabilityLifecycleStore(tmp_path / "capability-lifecycle.sqlite3")
    restored = reopened.load(item.package_id, str(item.version))
    assert restored is not None
    assert restored.record.state is ActivationState.CERTIFIED
    assert restored.record.package_hash == item.package_hash
    assert restored.metadata.rollback_target == record.certification.rollback_target
    assert service.record_for(item.package_id, item.version).state is ActivationState.CERTIFIED
    reopened.close()


def test_adoption_attestation_uses_existing_lifecycle_provenance_owner(tmp_path: Path) -> None:
    _, item, _, record, store = _durable_fixture(tmp_path)
    reference = "adoption-attestation:" + "a" * 36
    bound = store.bind_adoption_attestation(
        record,
        attestation_reference=reference,
        expected_revision=1,
    )
    assert reference in bound.metadata.provenance_reference
    duplicate = store.bind_adoption_attestation(
        bound.record,
        attestation_reference=reference,
        expected_revision=bound.revision,
    )
    assert duplicate.revision == bound.revision
    store.close()


def test_shadow_canary_active_and_quarantine_are_durable(tmp_path: Path) -> None:
    original, item, source, record, store = _durable_fixture(tmp_path)
    manager = HotLoadManager(Factory(), Surface(), lifecycle_store=store)
    service = type(original)(
        manager,
        original._hooks,
        attestation_store=original._attestations,
        lifecycle_store=store,
    )
    request = ActivationRequest(
        item,
        record.certification,
        (source,),
        original._sessions[(item.package_id, item.version)].request.canary_limits,
    )
    service.restore(request)
    assert service.run_shadow(item.package_id, item.version).state is ActivationState.SHADOW
    assert service.run_canary(item.package_id, item.version).state is ActivationState.CANARY
    assert service.promote(item.package_id, item.version).state is ActivationState.ACTIVE

    store.close()
    reopened = SQLiteCapabilityLifecycleStore(tmp_path / "capability-lifecycle.sqlite3")
    loaded = reopened.load(item.package_id, str(item.version))
    assert loaded is not None
    assert loaded.record.state is ActivationState.ACTIVE
    reopened.close()


def test_active_runtime_requires_exact_restore_and_restarts_after_rehydration(
    tmp_path: Path,
) -> None:
    original, item, source, record, store = _durable_fixture(tmp_path)
    service = type(original)(
        HotLoadManager(Factory(), Surface(), lifecycle_store=store),
        original._hooks,
        attestation_store=original._attestations,
        lifecycle_store=store,
    )
    request = ActivationRequest(
        item,
        record.certification,
        (source,),
        original._sessions[(item.package_id, item.version)].request.canary_limits,
    )
    service.restore(request)
    service.run_shadow(item.package_id, item.version)
    service.run_canary(item.package_id, item.version)
    service.promote(item.package_id, item.version)
    store.close()

    reopened_store = SQLiteCapabilityLifecycleStore(tmp_path / "capability-lifecycle.sqlite3")
    restarted = type(original)(
        HotLoadManager(Factory(), Surface(), lifecycle_store=reopened_store),
        original._hooks,
        attestation_store=original._attestations,
        lifecycle_store=reopened_store,
    )
    assert restarted.restore(request).state is ActivationState.ACTIVE
    assert restarted.restart(item.package_id, item.version).state is ActivationState.ACTIVE
    reopened_store.close()


def test_incomplete_runtime_swap_is_recovering_after_restart(tmp_path: Path) -> None:
    _, item, _, record, store = _durable_fixture(tmp_path)
    canary = replace(
        record,
        state=ActivationState.CANARY,
        history=record.history
        + (
            replace(
                record.history[-1],
                from_state=ActivationState.CERTIFIED,
                to_state=ActivationState.CANARY,
            ),
        ),
    )
    shadow = replace(
        record,
        state=ActivationState.SHADOW,
        history=record.history
        + (
            replace(
                record.history[-1],
                from_state=ActivationState.CERTIFIED,
                to_state=ActivationState.SHADOW,
            ),
        ),
    )
    shadow_stored = store.save(shadow, expected_revision=1)
    stored = store.save(canary, expected_revision=shadow_stored.revision)
    pending = store.begin_runtime_swap(canary, expected_revision=stored.revision)
    assert pending.transaction_state == "RECOVERING"
    store.close()

    reopened = SQLiteCapabilityLifecycleStore(tmp_path / "capability-lifecycle.sqlite3")
    recovered = reopened.load(item.package_id, str(item.version))
    assert recovered is not None
    assert recovered.transaction_state == "RECOVERING"
    assert recovered.pending_target == ActivationState.ACTIVE.value
    assert recovered.record.state is ActivationState.CANARY
    reopened.close()


def test_changed_package_hash_cannot_reattach_existing_lifecycle(tmp_path: Path) -> None:
    original, item, source, record, store = _durable_fixture(tmp_path)
    request = original._sessions[(item.package_id, item.version)].request
    changed = replace(item, package_hash="f" * 64)
    with pytest.raises(ValueError):
        original.restore(replace(request, package=changed))
    store.close()


def test_invalid_certification_is_rejected_on_startup(tmp_path: Path) -> None:
    _, item, _, _, store = _durable_fixture(tmp_path)
    database = tmp_path / "capability-lifecycle.sqlite3"
    store.close()
    with sqlite3.connect(database) as connection:
        connection.execute(
            "UPDATE capability_lifecycle SET certification_json=? WHERE integration_id=?",
            ('{"package_id":"tampered"}', item.package_id),
        )
        connection.commit()
    with pytest.raises((CapabilityLifecycleError, ValueError, KeyError, TypeError)):
        SQLiteCapabilityLifecycleStore(database)


def test_concurrent_transition_rejects_stale_revision(tmp_path: Path) -> None:
    _, item, _, record, first = _durable_fixture(tmp_path)
    second = SQLiteCapabilityLifecycleStore(tmp_path / "capability-lifecycle.sqlite3")
    first_record = first.load(item.package_id, str(item.version))
    second_record = second.load(item.package_id, str(item.version))
    assert first_record is not None and second_record is not None
    first.save(record, expected_revision=first_record.revision)
    with pytest.raises(CapabilityLifecycleConcurrencyError):
        second.save(record, expected_revision=second_record.revision)
    first.close()
    second.close()


def test_future_lifecycle_schema_is_refused(tmp_path: Path) -> None:
    database = tmp_path / "future.sqlite3"
    with sqlite3.connect(database) as connection:
        connection.execute(
            "CREATE TABLE capability_lifecycle_schema("
            "version INTEGER PRIMARY KEY, name TEXT NOT NULL)"
        )
        connection.execute(
            "INSERT INTO capability_lifecycle_schema(version, name) VALUES (99, 'future')"
        )
        connection.commit()
    with pytest.raises(CapabilityLifecycleError, match="future schema"):
        SQLiteCapabilityLifecycleStore(database)


def test_raw_credential_metadata_is_rejected(tmp_path: Path) -> None:
    _, item, _, record, store = _durable_fixture(tmp_path)
    with pytest.raises(CapabilityLifecycleError):
        store.create(
            replace(record, activation_id=record.activation_id + "-other"),
            metadata=LifecycleMetadata(credential_reference_metadata=("token=raw",)),
        )
    store.close()


def test_previous_known_good_version_is_bound_to_lifecycle_record(tmp_path: Path) -> None:
    _, item, _, record, store = _durable_fixture(tmp_path)
    prior = replace(record, previous_version=type(item.version)(0, 9, 0))
    saved = store.save(prior, expected_revision=1)
    assert saved.record.previous_version == type(item.version)(0, 9, 0)
    loaded = store.load(item.package_id, str(item.version))
    assert loaded is not None
    assert loaded.record.previous_version == type(item.version)(0, 9, 0)
    store.close()


def test_lifecycle_store_rejects_invalid_creation_and_duplicate_versions(tmp_path: Path) -> None:
    _, item, _, record, store = _durable_fixture(tmp_path)
    with pytest.raises(CapabilityLifecycleError):
        store.create(record)
    with pytest.raises(CapabilityLifecycleError):
        store.create(replace(record, state=ActivationState.SHADOW))
    with pytest.raises(ActivationValidationError):
        store.create(replace(record, package_hash="f" * 64))
    with pytest.raises(CapabilityLifecycleError):
        store.create(record)
    assert store.load("missing", str(item.version)) is None
    assert len(store.list()) == 1
    store.close()


def test_lifecycle_metadata_validation_is_fail_closed(tmp_path: Path) -> None:
    _, _, _, record, store = _durable_fixture(tmp_path)
    invalid = (
        object(),
        LifecycleMetadata(provenance_reference=("",)),
        LifecycleMetadata(provenance_reference=("token=raw",)),
        LifecycleMetadata(permission_manifest_reference="x" * 513),
        LifecycleMetadata(configuration_version="x" * 257),
        LifecycleMetadata(health_state=""),
        LifecycleMetadata(rollback_target="x" * 513),
    )
    for metadata in invalid:
        with pytest.raises(CapabilityLifecycleError):
            store.create(record, metadata=metadata)  # type: ignore[arg-type]
    store.close()


def test_lifecycle_transition_and_runtime_swap_guards(tmp_path: Path) -> None:
    _, item, _, record, store = _durable_fixture(tmp_path)
    stored = store.load(item.package_id, str(item.version))
    assert stored is not None
    shadow = store.save(
        replace(record, state=ActivationState.SHADOW), expected_revision=stored.revision
    )
    with pytest.raises(CapabilityLifecycleError):
        store.save(record, expected_revision=shadow.revision)
    with pytest.raises(ActivationValidationError):
        store.save(replace(shadow.record, package_id="other"), expected_revision=shadow.revision)
    with pytest.raises(CapabilityLifecycleError):
        store.save(shadow.record, expected_revision=shadow.revision, transaction_state="PENDING")
    with pytest.raises(CapabilityLifecycleConcurrencyError):
        store.begin_runtime_swap(record, expected_revision=shadow.revision)
    canary = replace(shadow.record, state=ActivationState.CANARY)
    canary_stored = store.save(canary, expected_revision=shadow.revision)
    pending = store.begin_runtime_swap(canary, expected_revision=canary_stored.revision)
    assert pending.transaction_state == "RECOVERING"
    aborted = store.abort_runtime_swap(canary, expected_revision=pending.revision)
    assert aborted.transaction_state == "STABLE"
    with pytest.raises(CapabilityLifecycleError):
        store.abort_runtime_swap(canary, expected_revision=aborted.revision)
    store.close()
