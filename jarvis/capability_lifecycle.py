"""Durable authority for certified integration lifecycle state.

The package registry, activation service, and hot-load manager are projections
and runtime caches.  This module is the one durable owner for their lifecycle
truth.  It deliberately stores certification metadata and references, never
package secrets or executable package contents.
"""

from __future__ import annotations

import json
import sqlite3
import threading
from collections.abc import Iterable
from dataclasses import dataclass, replace
from datetime import datetime
from pathlib import Path
from typing import TYPE_CHECKING, cast

from jarvis.tools.models import SemanticVersion

if TYPE_CHECKING:
    from jarvis.package_activation import ActivationRecord


class CapabilityLifecycleError(RuntimeError):
    """Durable lifecycle state is unavailable or invalid."""


class CapabilityLifecycleConcurrencyError(CapabilityLifecycleError):
    """A lifecycle update was based on a stale durable revision."""


@dataclass(frozen=True, slots=True)
class LifecycleMetadata:
    """Non-secret package references persisted beside an activation record."""

    provenance_reference: tuple[str, ...] = ()
    permission_manifest_reference: str = ""
    credential_reference_metadata: tuple[str, ...] = ()
    configuration_version: str = ""
    health_state: str = "UNKNOWN"
    behavior_baseline_reference: tuple[str, ...] = ()
    rollback_target: str = ""


@dataclass(frozen=True, slots=True)
class StoredLifecycleRecord:
    record: ActivationRecord
    revision: int
    transaction_state: str
    pending_target: str | None
    metadata: LifecycleMetadata


class SQLiteCapabilityLifecycleStore:
    """SQLite-backed, transactional owner of package lifecycle truth.

    A record is keyed by ``(integration_id, version)``.  A package version is
    inserted in CERTIFIED state and can never inherit another version's state.
    Updates use an optimistic revision, so two lifecycle coordinators cannot
    silently overwrite each other.  A pending runtime swap is durable and is
    reconciled as RECOVERING on the next startup.
    """

    _SCHEMA_VERSION = 1
    _MIGRATION_NAME = "create_capability_lifecycle"

    def __init__(self, database_path: str | Path) -> None:
        self._path = str(database_path)
        if self._path != ":memory:":
            Path(self._path).parent.mkdir(parents=True, exist_ok=True)
        self._connection = sqlite3.connect(self._path, timeout=5.0, check_same_thread=False)
        self._connection.execute("PRAGMA foreign_keys=ON")
        self._connection.execute("PRAGMA busy_timeout=5000")
        self._connection.execute("PRAGMA journal_mode=WAL")
        self._lock = threading.RLock()
        try:
            self._migrate()
            self._reconcile_pending()
            for row in self._connection.execute(
                "SELECT integration_id, version, package_hash, provenance_reference_json, "
                "certification_status, certification_json, certification_hash, "
                "environment_compatibility_json, activation_state, "
                "permission_manifest_reference, credential_reference_metadata_json, "
                "configuration_version, health_state, behavior_baseline_reference_json, "
                "rollback_target, record_json, revision, transaction_state, "
                "pending_target, updated_at FROM capability_lifecycle"
            ).fetchall():
                _stored_from_row(row)
        except (sqlite3.DatabaseError, ValueError, TypeError) as error:
            self.close()
            if isinstance(error, CapabilityLifecycleError):
                raise
            raise CapabilityLifecycleError(
                "Capability lifecycle database is unavailable"
            ) from error

    def _migrate(self) -> None:
        with self._connection:
            self._connection.execute(
                "CREATE TABLE IF NOT EXISTS capability_lifecycle_schema "
                "(version INTEGER PRIMARY KEY, name TEXT NOT NULL)"
            )
            rows = self._connection.execute(
                "SELECT version, name FROM capability_lifecycle_schema"
            ).fetchall()
            versions = {int(row[0]): str(row[1]) for row in rows}
            if any(version > self._SCHEMA_VERSION for version in versions):
                raise CapabilityLifecycleError("Capability lifecycle database uses a future schema")
            if not versions:
                self._connection.execute(
                    """CREATE TABLE capability_lifecycle (
                    integration_id TEXT NOT NULL,
                    version TEXT NOT NULL,
                    package_hash TEXT NOT NULL,
                    provenance_reference_json TEXT NOT NULL,
                    certification_status TEXT NOT NULL,
                    certification_json TEXT NOT NULL,
                    certification_hash TEXT NOT NULL,
                    environment_compatibility_json TEXT NOT NULL,
                    activation_state TEXT NOT NULL,
                    permission_manifest_reference TEXT NOT NULL,
                    credential_reference_metadata_json TEXT NOT NULL,
                    configuration_version TEXT NOT NULL,
                    health_state TEXT NOT NULL,
                    behavior_baseline_reference_json TEXT NOT NULL,
                    rollback_target TEXT NOT NULL,
                    record_json TEXT NOT NULL,
                    revision INTEGER NOT NULL,
                    transaction_state TEXT NOT NULL,
                    pending_target TEXT,
                    updated_at TEXT NOT NULL,
                    PRIMARY KEY (integration_id, version)
                    )"""
                )
                self._connection.execute(
                    "INSERT INTO capability_lifecycle_schema(version, name) VALUES (?, ?)",
                    (self._SCHEMA_VERSION, self._MIGRATION_NAME),
                )
            elif versions.get(1) != self._MIGRATION_NAME:
                raise CapabilityLifecycleError("Capability lifecycle migration identity mismatch")

    def _reconcile_pending(self) -> None:
        with self._connection:
            self._connection.execute(
                "UPDATE capability_lifecycle SET transaction_state='RECOVERING' "
                "WHERE transaction_state='PENDING'"
            )

    def create(
        self,
        record: ActivationRecord,
        *,
        metadata: LifecycleMetadata | None = None,
    ) -> StoredLifecycleRecord:
        from jarvis.package_activation import ActivationState

        self._validate_record(record)
        if record.state is not ActivationState.CERTIFIED:
            raise CapabilityLifecycleError("A new package version must start CERTIFIED")
        lifecycle_metadata = metadata or LifecycleMetadata(
            health_state=record.certification.health[-1]
            if record.certification.health
            else "UNKNOWN",
            behavior_baseline_reference=record.certification.expected_behavior_baseline,
            rollback_target=record.certification.rollback_target,
        )
        self._validate_metadata(lifecycle_metadata)
        payload = _record_to_json(record)
        certification_payload = _certification_to_json(record.certification)
        with self._lock:
            try:
                self._connection.execute(
                    """INSERT INTO capability_lifecycle (
                    integration_id, version, package_hash, provenance_reference_json,
                    certification_status, certification_json, certification_hash,
                    environment_compatibility_json, activation_state,
                    permission_manifest_reference, credential_reference_metadata_json,
                    configuration_version, health_state, behavior_baseline_reference_json,
                    rollback_target, record_json, revision, transaction_state,
                    pending_target, updated_at
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                    self._row_values(record, lifecycle_metadata, certification_payload, payload),
                )
                self._connection.commit()
            except sqlite3.IntegrityError as error:
                self._connection.rollback()
                raise CapabilityLifecycleError(
                    "Package version already has durable lifecycle state"
                ) from error
            except sqlite3.DatabaseError as error:
                self._connection.rollback()
                raise CapabilityLifecycleError(
                    "Capability lifecycle record could not be created"
                ) from error
        return StoredLifecycleRecord(record, 1, "STABLE", None, lifecycle_metadata)

    def load(self, integration_id: str, version: str) -> StoredLifecycleRecord | None:
        row = self._fetch(integration_id, version)
        return _stored_from_row(row) if row is not None else None

    def list(self) -> tuple[StoredLifecycleRecord, ...]:
        with self._lock:
            rows = self._connection.execute(
                "SELECT integration_id, version, package_hash, provenance_reference_json, "
                "certification_status, certification_json, certification_hash, "
                "environment_compatibility_json, activation_state, "
                "permission_manifest_reference, credential_reference_metadata_json, "
                "configuration_version, health_state, behavior_baseline_reference_json, "
                "rollback_target, record_json, revision, transaction_state, "
                "pending_target, updated_at "
                "FROM capability_lifecycle ORDER BY integration_id, version"
            ).fetchall()
        return tuple(_stored_from_row(row) for row in rows)

    def bind_adoption_attestation(
        self,
        record: ActivationRecord,
        *,
        attestation_reference: str,
        expected_revision: int,
    ) -> StoredLifecycleRecord:
        """Bind adoption evidence to an existing package lifecycle record.

        This reuses the lifecycle store's provenance column rather than
        creating a competing adoption database. The reference is evidence
        only; certification, activation, and PermissionBroker rules remain
        unchanged.
        """

        if (
            type(attestation_reference) is not str
            or not attestation_reference.startswith("adoption-attestation:")
            or len(attestation_reference) > 512
        ):
            raise CapabilityLifecycleError("Adoption attestation reference is malformed")
        existing = self.load(record.package_id, str(record.version))
        if existing is None:
            raise CapabilityLifecycleError("Package version has no durable lifecycle state")
        if attestation_reference in existing.metadata.provenance_reference:
            return existing
        metadata = replace(
            existing.metadata,
            provenance_reference=existing.metadata.provenance_reference + (attestation_reference,),
        )
        return self.save(record, expected_revision=expected_revision, metadata=metadata)

    def save(
        self,
        record: ActivationRecord,
        *,
        expected_revision: int,
        metadata: LifecycleMetadata | None = None,
        transaction_state: str = "STABLE",
        pending_target: str | None = None,
    ) -> StoredLifecycleRecord:
        self._validate_record(record)
        if type(expected_revision) is not int or expected_revision < 1:
            raise CapabilityLifecycleError("Lifecycle revision is malformed")
        if transaction_state not in {"STABLE", "RECOVERING"}:
            raise CapabilityLifecycleError("Lifecycle transaction state is invalid")
        existing = self.load(record.package_id, str(record.version))
        if existing is None:
            raise CapabilityLifecycleError("Package version has no durable lifecycle state")
        if existing.revision != expected_revision:
            raise CapabilityLifecycleConcurrencyError("Lifecycle revision is stale")
        self._validate_transition(existing.record, record)
        lifecycle_metadata = metadata or existing.metadata
        self._validate_metadata(lifecycle_metadata)
        payload = _record_to_json(record)
        certification_payload = _certification_to_json(record.certification)
        values = self._row_values(record, lifecycle_metadata, certification_payload, payload)
        with self._lock:
            cursor = self._connection.execute(
                """UPDATE capability_lifecycle SET
                package_hash=?, provenance_reference_json=?, certification_status=?,
                certification_json=?, certification_hash=?, environment_compatibility_json=?,
                activation_state=?, permission_manifest_reference=?,
                credential_reference_metadata_json=?, configuration_version=?, health_state=?,
                behavior_baseline_reference_json=?, rollback_target=?, record_json=?,
                revision=revision+1, transaction_state=?, pending_target=?, updated_at=?
                WHERE integration_id=? AND version=? AND revision=?""",
                (
                    values[2],
                    values[3],
                    values[4],
                    values[5],
                    values[6],
                    values[7],
                    values[8],
                    values[9],
                    values[10],
                    values[11],
                    values[12],
                    values[13],
                    values[14],
                    values[15],
                    transaction_state,
                    pending_target,
                    values[19],
                    record.package_id,
                    str(record.version),
                    expected_revision,
                ),
            )
            if cursor.rowcount != 1:
                self._connection.rollback()
                raise CapabilityLifecycleConcurrencyError("Lifecycle revision is stale")
            self._connection.commit()
        return StoredLifecycleRecord(
            record, expected_revision + 1, transaction_state, pending_target, lifecycle_metadata
        )

    def begin_runtime_swap(
        self, record: ActivationRecord, *, expected_revision: int
    ) -> StoredLifecycleRecord:
        from jarvis.package_activation import ActivationState

        existing = self.load(record.package_id, str(record.version))
        if (
            existing is None
            or existing.record.package_id != record.package_id
            or existing.record.version != record.version
            or existing.record.package_hash != record.package_hash
            or existing.record.state is not record.state
        ):
            raise CapabilityLifecycleConcurrencyError("Runtime swap record is stale")
        if record.state is not ActivationState.CANARY:
            raise CapabilityLifecycleError("Only a canary may prepare an ACTIVE runtime swap")
        return self.save(
            record,
            expected_revision=expected_revision,
            transaction_state="RECOVERING",
            pending_target=ActivationState.ACTIVE.value,
        )

    def abort_runtime_swap(
        self, record: ActivationRecord, *, expected_revision: int
    ) -> StoredLifecycleRecord:
        existing = self.load(record.package_id, str(record.version))
        if (
            existing is None
            or existing.record.package_id != record.package_id
            or existing.record.version != record.version
            or existing.record.package_hash != record.package_hash
            or existing.record.state is not record.state
        ):
            raise CapabilityLifecycleConcurrencyError("Runtime swap record is stale")
        if existing.transaction_state != "RECOVERING":
            raise CapabilityLifecycleError("No runtime swap is pending")
        return self.save(record, expected_revision=expected_revision)

    def close(self) -> None:
        with self._lock:
            self._connection.close()

    def _fetch(self, integration_id: str, version: str) -> tuple[object, ...] | None:
        with self._lock:
            return cast(
                tuple[object, ...] | None,
                self._connection.execute(
                    "SELECT integration_id, version, package_hash, provenance_reference_json, "
                    "certification_status, certification_json, certification_hash, "
                    "environment_compatibility_json, activation_state, "
                    "permission_manifest_reference, credential_reference_metadata_json, "
                    "configuration_version, health_state, behavior_baseline_reference_json, "
                    "rollback_target, record_json, revision, transaction_state, "
                    "pending_target, updated_at "
                    "FROM capability_lifecycle WHERE integration_id=? AND version=?",
                    (integration_id, version),
                ).fetchone(),
            )

    @staticmethod
    def _row_values(
        record: ActivationRecord,
        metadata: LifecycleMetadata,
        certification_payload: str,
        payload: str,
    ) -> tuple[object, ...]:
        return (
            record.package_id,
            str(record.version),
            record.package_hash,
            json.dumps(metadata.provenance_reference, sort_keys=True),
            "CERTIFIED",
            certification_payload,
            _certification_hash(certification_payload),
            json.dumps(record.certification.environment_compatibility, sort_keys=True),
            record.state.value,
            metadata.permission_manifest_reference,
            json.dumps(metadata.credential_reference_metadata, sort_keys=True),
            metadata.configuration_version,
            metadata.health_state,
            json.dumps(metadata.behavior_baseline_reference, sort_keys=True),
            metadata.rollback_target,
            payload,
            1,
            "STABLE",
            None,
            record.updated_at.isoformat(),
        )

    @staticmethod
    def _validate_metadata(metadata: LifecycleMetadata) -> None:
        if not isinstance(metadata, LifecycleMetadata):
            raise CapabilityLifecycleError("Lifecycle metadata is malformed")
        values: Iterable[str] = (
            *metadata.provenance_reference,
            *metadata.credential_reference_metadata,
            *metadata.behavior_baseline_reference,
        )
        if any(
            type(value) is not str or not value.strip() or len(value) > 2_000 for value in values
        ):
            raise CapabilityLifecycleError("Lifecycle metadata is malformed")
        if any(
            token in value.casefold()
            for value in values
            for token in ("secret=", "password=", "token=")
        ):
            raise CapabilityLifecycleError("Raw credential material is not lifecycle metadata")
        if (
            type(metadata.permission_manifest_reference) is not str
            or len(metadata.permission_manifest_reference) > 512
        ):
            raise CapabilityLifecycleError("Permission manifest reference is malformed")
        if (
            type(metadata.configuration_version) is not str
            or len(metadata.configuration_version) > 256
        ):
            raise CapabilityLifecycleError("Configuration version is malformed")
        if (
            type(metadata.health_state) is not str
            or not metadata.health_state.strip()
            or len(metadata.health_state) > 256
        ):
            raise CapabilityLifecycleError("Health state is malformed")
        if type(metadata.rollback_target) is not str or len(metadata.rollback_target) > 512:
            raise CapabilityLifecycleError("Rollback target is malformed")

    @staticmethod
    def _validate_record(record: ActivationRecord) -> None:
        from jarvis.package_activation import ActivationRecord, ActivationState

        if not isinstance(record, ActivationRecord):
            raise CapabilityLifecycleError("Lifecycle record is malformed")
        if (
            record.certification.package_id != record.package_id
            or record.certification.version != record.version
        ):
            raise CapabilityLifecycleError("Certification identity does not match lifecycle record")
        if record.certification.package_hash != record.package_hash:
            raise CapabilityLifecycleError("Certification hash does not match package hash")
        if record.state is ActivationState.ACTIVE and (
            not record.certification.stages
            or record.certification.stages[-1].stage.value != "CERTIFIED"
            or not record.certification.shadow_eligible
            or not record.certification.canary_eligible
        ):
            raise CapabilityLifecycleError("ACTIVE requires valid completed certification")

    @staticmethod
    def _validate_transition(previous: ActivationRecord, current: ActivationRecord) -> None:
        from jarvis.package_activation import ActivationState

        if previous.package_id != current.package_id or previous.version != current.version:
            raise CapabilityLifecycleError("Lifecycle identity cannot change")
        allowed = {
            ActivationState.CERTIFIED: {
                ActivationState.CERTIFIED,
                ActivationState.SHADOW,
                ActivationState.QUARANTINED,
                ActivationState.ROLLED_BACK,
            },
            ActivationState.SHADOW: {
                ActivationState.SHADOW,
                ActivationState.CANARY,
                ActivationState.QUARANTINED,
                ActivationState.ROLLED_BACK,
            },
            ActivationState.CANARY: {
                ActivationState.CANARY,
                ActivationState.ACTIVE,
                ActivationState.QUARANTINED,
                ActivationState.ROLLED_BACK,
            },
            ActivationState.ACTIVE: {
                ActivationState.ACTIVE,
                ActivationState.DEGRADED,
                ActivationState.QUARANTINED,
                ActivationState.ROLLED_BACK,
            },
            ActivationState.DEGRADED: {
                ActivationState.DEGRADED,
                ActivationState.ACTIVE,
                ActivationState.QUARANTINED,
                ActivationState.ROLLED_BACK,
            },
            ActivationState.QUARANTINED: {ActivationState.QUARANTINED},
            ActivationState.ROLLED_BACK: {ActivationState.ROLLED_BACK},
        }
        if current.state not in allowed[previous.state]:
            raise CapabilityLifecycleError(
                f"Invalid lifecycle transition {previous.state.value}->{current.state.value}"
            )


def _certification_to_json(record: object) -> str:
    from jarvis.package_certification import CertificationRecord, CertificationStageEvidence

    if not isinstance(record, CertificationRecord):
        raise CapabilityLifecycleError("Certification record is malformed")

    def stage(value: CertificationStageEvidence) -> dict[str, object]:
        return {
            "stage": value.stage.value,
            "passed": value.passed,
            "evidence": list(value.evidence),
            "recorded_at": value.recorded_at.isoformat() if value.recorded_at else None,
        }

    return json.dumps(
        {
            "package_id": record.package_id,
            "version": str(record.version),
            "package_hash": record.package_hash,
            "source_hash": record.source_hash,
            "dependency_hash": record.dependency_hash,
            "manifest_hash": record.manifest_hash,
            "test_evidence": [stage(item) for item in record.test_evidence],
            "audit": [stage(item) for item in record.audit],
            "permissions": [item.value for item in record.permissions],
            "approval_ref": record.approval_ref,
            "environment_compatibility": list(record.environment_compatibility),
            "health": list(record.health),
            "verification": list(record.verification),
            "rollback_target": record.rollback_target,
            "shadow_eligible": record.shadow_eligible,
            "canary_eligible": record.canary_eligible,
            "expected_behavior_baseline": list(record.expected_behavior_baseline),
            "stages": [stage(item) for item in record.stages],
            "certified_at": record.certified_at.isoformat(),
            "ui_simulation_attestation_ref": record.ui_simulation_attestation_ref,
            "ui_simulation_attestation_digest": record.ui_simulation_attestation_digest,
        },
        sort_keys=True,
    )


def _certification_hash(payload: str) -> str:
    from hashlib import sha256

    return sha256(payload.encode("utf-8")).hexdigest()


def _record_to_json(record: ActivationRecord) -> str:
    return json.dumps(
        {
            "activation_id": record.activation_id,
            "package_id": record.package_id,
            "version": str(record.version),
            "package_hash": record.package_hash,
            "certification": json.loads(_certification_to_json(record.certification)),
            "state": record.state.value,
            "predictions": list(record.predictions),
            "broker_behavior": list(record.broker_behavior),
            "canary_effects": list(record.canary_effects),
            "verification": list(record.verification),
            "promotion_decision": record.promotion_decision,
            "rollback_evidence": list(record.rollback_evidence),
            "history": [
                {
                    "from_state": item.from_state.value if item.from_state else None,
                    "to_state": item.to_state.value,
                    "detail": item.detail,
                    "recorded_at": item.recorded_at.isoformat(),
                }
                for item in record.history
            ],
            "created_at": record.created_at.isoformat(),
            "updated_at": record.updated_at.isoformat(),
            "attestation_ids": [str(item) for item in record.attestation_ids],
            "previous_version": str(record.previous_version) if record.previous_version else None,
            "sandbox_security_mode": record.sandbox_security_mode,
        },
        sort_keys=True,
    )


def _stored_from_row(row: tuple[object, ...]) -> StoredLifecycleRecord:
    from uuid import UUID

    from jarvis.package_activation import ActivationRecord, ActivationState, ActivationTransition
    from jarvis.package_certification import (
        CertificationRecord,
        CertificationStage,
        CertificationStageEvidence,
    )
    from jarvis.permissions.models import Permission

    persisted_certification = json.loads(str(row[5]))
    data = json.loads(str(row[15]))
    cert_data = data["certification"]
    if persisted_certification != cert_data:
        raise CapabilityLifecycleError("Persisted certification projection is inconsistent")
    if str(row[2]) != str(data["package_hash"]):
        raise CapabilityLifecycleError("Persisted package hash projection is inconsistent")
    if str(row[8]) != str(data["state"]):
        raise CapabilityLifecycleError("Persisted activation projection is inconsistent")
    if str(row[6]) != _certification_hash(str(row[5])):
        raise CapabilityLifecycleError("Persisted certification hash is invalid")

    def stage(value: object) -> CertificationStageEvidence:
        item = value
        if not isinstance(item, dict):
            raise CapabilityLifecycleError("Persisted certification evidence is malformed")
        recorded = item.get("recorded_at")
        return CertificationStageEvidence(
            CertificationStage(str(item["stage"])),
            bool(item["passed"]),
            tuple(str(x) for x in item.get("evidence", [])),
            datetime.fromisoformat(str(recorded)) if recorded else None,
        )

    certification = CertificationRecord(
        str(cert_data["package_id"]),
        _version(str(cert_data["version"])),
        str(cert_data["package_hash"]),
        str(cert_data["source_hash"]),
        str(cert_data["dependency_hash"]),
        str(cert_data["manifest_hash"]),
        tuple(stage(item) for item in cert_data["test_evidence"]),
        tuple(stage(item) for item in cert_data["audit"]),
        tuple(
            sorted(
                (Permission(str(item)) for item in cert_data["permissions"]), key=lambda x: x.value
            )
        ),
        str(cert_data["approval_ref"]) if cert_data.get("approval_ref") else None,
        tuple(str(item) for item in cert_data["environment_compatibility"]),
        tuple(str(item) for item in cert_data["health"]),
        tuple(str(item) for item in cert_data["verification"]),
        str(cert_data["rollback_target"]),
        bool(cert_data["shadow_eligible"]),
        bool(cert_data["canary_eligible"]),
        tuple(str(item) for item in cert_data["expected_behavior_baseline"]),
        tuple(stage(item) for item in cert_data["stages"]),
        datetime.fromisoformat(str(cert_data["certified_at"])),
        cert_data.get("ui_simulation_attestation_ref"),
        cert_data.get("ui_simulation_attestation_digest"),
    )
    history = tuple(
        ActivationTransition(
            ActivationState(str(item["from_state"])) if item.get("from_state") else None,
            ActivationState(str(item["to_state"])),
            str(item["detail"]),
            datetime.fromisoformat(str(item["recorded_at"])),
        )
        for item in data["history"]
    )
    record = ActivationRecord(
        str(data["activation_id"]),
        str(data["package_id"]),
        _version(str(data["version"])),
        str(data["package_hash"]),
        certification,
        ActivationState(str(data["state"])),
        tuple(str(item) for item in data["predictions"]),
        tuple(str(item) for item in data["broker_behavior"]),
        tuple(str(item) for item in data["canary_effects"]),
        tuple(str(item) for item in data["verification"]),
        str(data["promotion_decision"]),
        tuple(str(item) for item in data["rollback_evidence"]),
        history,
        datetime.fromisoformat(str(data["created_at"])),
        datetime.fromisoformat(str(data["updated_at"])),
        tuple(UUID(str(item)) for item in data["attestation_ids"]),
        previous_version=(
            _version(str(data["previous_version"])) if data.get("previous_version") else None
        ),
        sandbox_security_mode=str(data.get("sandbox_security_mode", "not-provided")),
    )
    metadata = LifecycleMetadata(
        tuple(str(item) for item in json.loads(str(row[3]))),
        str(row[9]),
        tuple(str(item) for item in json.loads(str(row[10]))),
        str(row[11]),
        str(row[12]),
        tuple(str(item) for item in json.loads(str(row[13]))),
        str(row[14]),
    )
    return StoredLifecycleRecord(
        record,
        int(str(row[16])),
        str(row[17]),
        str(row[18]) if row[18] else None,
        metadata,
    )


def _version(value: str) -> SemanticVersion:
    parts = value.split(".")
    if len(parts) != 3:
        raise CapabilityLifecycleError("Persisted semantic version is malformed")
    try:
        parsed = tuple(int(part) for part in parts)
    except ValueError as error:
        raise CapabilityLifecycleError("Persisted semantic version is malformed") from error
    if any(part < 0 for part in parsed):
        raise CapabilityLifecycleError("Persisted semantic version is malformed")
    return SemanticVersion(*parsed)


__all__ = [
    "CapabilityLifecycleConcurrencyError",
    "CapabilityLifecycleError",
    "LifecycleMetadata",
    "SQLiteCapabilityLifecycleStore",
    "StoredLifecycleRecord",
]
