"""Durable provider/model knowledge and empirical cookbook facts.

This module is a knowledge plane only.  It records bounded descriptive
observations and exposes read-only projections; it does not grant authority,
download models, or choose an execution route.
"""

from __future__ import annotations

import hashlib
import json
import sqlite3
import threading
from dataclasses import dataclass, replace
from datetime import UTC, datetime, timedelta
from enum import StrEnum
from pathlib import Path
from typing import Any, Protocol

from jarvis.ai.models import EvidenceKind, EvidenceRecord, ModelRole
from jarvis.ai.providers.registry import (
    ModelMetadata,
    ProviderLocality,
    ProviderMetadata,
    ProviderRegistry,
)
from jarvis.hardware import ModelMeasurement


class ModelKnowledgeError(ValueError):
    """Knowledge input or durable knowledge state is malformed."""


class KnowledgeAvailability(StrEnum):
    KNOWN = "known"
    CURRENTLY_UNAVAILABLE = "currently_unavailable"
    STALE = "stale"
    UNKNOWN = "unknown"


class EvidenceFreshness(StrEnum):
    FRESH = "fresh"
    STALE = "stale"
    UNKNOWN = "unknown"


class CookbookOutcome(StrEnum):
    VERIFIED_SUCCESS = "verified_success"
    FAILURE = "failure"
    ESCALATION = "escalation"
    UNKNOWN_OUTCOME = "unknown_outcome"


class VerifierAgreement(StrEnum):
    MODEL_SELF_CLAIM = "model_self_claim"
    MODEL_REVIEW = "model_review"
    INDEPENDENT_MODEL_REVIEW = "independent_model_review"
    DETERMINISTIC_VERIFICATION = "deterministic_verification"
    USER_CONFIRMED = "user_confirmed"
    UNKNOWN = "unknown"


class EvidenceSufficiency(StrEnum):
    INSUFFICIENT = "insufficient_evidence"
    SUFFICIENT = "sufficient_evidence"


def _bounded_text(value: object, name: str, limit: int, *, allow_empty: bool = False) -> str:
    if (
        type(value) is not str
        or (not allow_empty and not value.strip())
        or len(value) > limit
        or "\x00" in value
    ):
        raise ModelKnowledgeError(f"{name} is malformed")
    return value


def _timestamp(value: object, name: str) -> datetime:
    if not isinstance(value, datetime) or value.tzinfo is None:
        raise ModelKnowledgeError(f"{name} must be timezone-aware")
    return value.astimezone(UTC)


@dataclass(frozen=True, slots=True)
class ModelIdentity:
    """Collision-safe provider/model identity, including material variants."""

    provider_id: str
    model_id: str
    version: str = ""
    quantization: str = ""
    runtime: str = ""

    def __post_init__(self) -> None:
        _bounded_text(self.provider_id, "Provider ID", 256)
        object.__setattr__(self, "provider_id", self.provider_id.casefold())
        _bounded_text(self.model_id, "Model ID", 256)
        for name, value, limit in (
            ("Model version", self.version, 128),
            ("Model quantization", self.quantization, 128),
            ("Model runtime", self.runtime, 128),
        ):
            _bounded_text(value, name, limit, allow_empty=True)

    @property
    def provider_model(self) -> str:
        return f"{self.provider_id}/{self.model_id}"

    @property
    def storage_key(self) -> str:
        return json.dumps(
            [self.provider_id, self.model_id, self.version, self.quantization, self.runtime],
            ensure_ascii=False,
            separators=(",", ":"),
        )


def identity_for(provider_id: str, metadata: ModelMetadata) -> ModelIdentity:
    if not isinstance(metadata, ModelMetadata):
        raise ModelKnowledgeError("Model metadata is malformed")
    return ModelIdentity(
        provider_id,
        metadata.model_id,
        metadata.version,
        metadata.quantization,
        metadata.runtime,
    )


@dataclass(frozen=True, slots=True)
class ModelObservation:
    identity: ModelIdentity
    metadata: ModelMetadata
    observed_at: datetime
    source: str
    evidence_kind: EvidenceKind = EvidenceKind.PROVIDER_REPORTED
    evidence_detail: str = ""
    availability: KnowledgeAvailability = KnowledgeAvailability.KNOWN
    machine_scope: str | None = None

    def __post_init__(self) -> None:
        if not isinstance(self.identity, ModelIdentity) or not isinstance(
            self.metadata, ModelMetadata
        ):
            raise ModelKnowledgeError("Model observation identity or metadata is malformed")
        if self.identity.model_id != self.metadata.model_id:
            raise ModelKnowledgeError("Model observation identity does not match metadata")
        _timestamp(self.observed_at, "Model observation timestamp")
        _bounded_text(self.source, "Model observation source", 512)
        _bounded_text(self.evidence_detail, "Model evidence detail", 2_000, allow_empty=True)
        if not isinstance(self.evidence_kind, EvidenceKind):
            raise ModelKnowledgeError("Model evidence kind is invalid")
        if not isinstance(self.availability, KnowledgeAvailability):
            raise ModelKnowledgeError("Model availability is invalid")
        if self.machine_scope is not None:
            _bounded_text(self.machine_scope, "Machine scope", 256)
            if self.evidence_kind is not EvidenceKind.MEASURED_ON_THIS_MACHINE:
                raise ModelKnowledgeError("Only machine measurements may use machine scope")
            if self.machine_scope != "this_machine":
                raise ModelKnowledgeError("Machine measurements must use this_machine scope")


@dataclass(frozen=True, slots=True)
class ProviderCatalogSnapshot:
    provider: ProviderMetadata
    models: tuple[ModelObservation, ...]
    observed_at: datetime
    source: str
    available: bool | None = None
    detail: str = ""

    def __post_init__(self) -> None:
        if not isinstance(self.provider, ProviderMetadata):
            raise ModelKnowledgeError("Provider catalog metadata is malformed")
        if type(self.models) is not tuple or len(self.models) > 1_024:
            raise ModelKnowledgeError("Provider catalog models are malformed")
        if any(
            not isinstance(item, ModelObservation)
            or item.identity.provider_id != self.provider.provider_id.casefold()
            for item in self.models
        ):
            raise ModelKnowledgeError("Provider catalog model identity is malformed")
        if len({item.identity.storage_key for item in self.models}) != len(self.models):
            raise ModelKnowledgeError("Provider catalog contains duplicate model identities")
        _timestamp(self.observed_at, "Provider observation timestamp")
        _bounded_text(self.source, "Provider observation source", 512)
        _bounded_text(self.detail, "Provider observation detail", 2_000, allow_empty=True)
        if self.available is not None and type(self.available) is not bool:
            raise ModelKnowledgeError("Provider availability is invalid")


class ProviderModelDiscovery(Protocol):
    async def discover(self) -> ProviderCatalogSnapshot:
        """Return one bounded provider catalog snapshot."""


@dataclass(frozen=True, slots=True)
class ProviderKnowledgeView:
    metadata: ProviderMetadata
    availability: KnowledgeAvailability
    available: bool | None
    detail: str
    source: str | None
    last_observed: datetime | None
    freshness: EvidenceFreshness


@dataclass(frozen=True, slots=True)
class ModelKnowledgeView:
    identity: ModelIdentity
    metadata: ModelMetadata
    availability: KnowledgeAvailability
    first_seen: datetime | None
    last_seen: datetime | None
    source: str | None
    evidence_count: int
    measurement_count: int
    freshness: EvidenceFreshness


@dataclass(frozen=True, slots=True)
class CookbookObservation:
    identity: ModelIdentity
    task_class: str
    outcome: CookbookOutcome
    observed_at: datetime
    operation_class: str = ""
    role: ModelRole | None = None
    environment: str = ""
    locality: ProviderLocality = ProviderLocality.UNKNOWN
    machine_scope: str | None = None
    input_size_bucket: str = ""
    verified: bool | None = None
    latency_ms: float | None = None
    token_usage: int | None = None
    monetary_cost: float | None = None
    structured_output_valid: bool | None = None
    tool_call_valid: bool | None = None
    retry_count: int = 0
    escalation_required: bool = False
    failure_class: str = ""
    verifier_agreement: VerifierAgreement = VerifierAgreement.UNKNOWN
    evidence_refs: tuple[str, ...] = ()
    observation_id: str = ""

    def __post_init__(self) -> None:
        if not isinstance(self.identity, ModelIdentity):
            raise ModelKnowledgeError("Cookbook identity is malformed")
        _bounded_text(self.task_class, "Task class", 128)
        _bounded_text(self.operation_class, "Operation class", 128, allow_empty=True)
        _bounded_text(self.environment, "Execution environment", 256, allow_empty=True)
        _bounded_text(self.input_size_bucket, "Input-size bucket", 128, allow_empty=True)
        _bounded_text(self.failure_class, "Failure class", 256, allow_empty=True)
        _timestamp(self.observed_at, "Cookbook timestamp")
        if not isinstance(self.outcome, CookbookOutcome):
            raise ModelKnowledgeError("Cookbook outcome is invalid")
        if self.role is not None and not isinstance(self.role, ModelRole):
            raise ModelKnowledgeError("Cookbook role is invalid")
        if not isinstance(self.locality, ProviderLocality):
            raise ModelKnowledgeError("Cookbook locality is invalid")
        if self.machine_scope is not None:
            _bounded_text(self.machine_scope, "Cookbook machine scope", 256)
        for name, value in (
            ("latency", self.latency_ms),
            ("cost", self.monetary_cost),
        ):
            if value is not None and (type(value) not in {int, float} or value < 0):
                raise ModelKnowledgeError(f"Cookbook {name} is invalid")
        if self.token_usage is not None and (
            type(self.token_usage) is not int or self.token_usage < 0
        ):
            raise ModelKnowledgeError("Cookbook token usage is invalid")
        if type(self.retry_count) is not int or not 0 <= self.retry_count <= 1_000:
            raise ModelKnowledgeError("Cookbook retry count is invalid")
        if type(self.escalation_required) is not bool:
            raise ModelKnowledgeError("Cookbook escalation flag is invalid")
        for name, value in (
            ("verified", self.verified),
            ("structured output validity", self.structured_output_valid),
            ("tool validity", self.tool_call_valid),
        ):
            if value is not None and type(value) is not bool:
                raise ModelKnowledgeError(f"Cookbook {name} is invalid")
        if not isinstance(self.verifier_agreement, VerifierAgreement):
            raise ModelKnowledgeError("Cookbook verifier agreement is invalid")
        if (
            type(self.evidence_refs) is not tuple
            or len(self.evidence_refs) > 32
            or any(
                type(value) is not str or not value.strip() or len(value) > 256 or "\x00" in value
                for value in self.evidence_refs
            )
        ):
            raise ModelKnowledgeError("Cookbook evidence references are invalid")
        _bounded_text(self.observation_id, "Cookbook observation ID", 256, allow_empty=True)

    @property
    def dedupe_key(self) -> str:
        payload = {
            "identity": self.identity.storage_key,
            "task_class": self.task_class,
            "operation_class": self.operation_class,
            "role": self.role.value if self.role else None,
            "environment": self.environment,
            "locality": self.locality.value,
            "machine_scope": self.machine_scope,
            "input_size_bucket": self.input_size_bucket,
            "outcome": self.outcome.value,
            "observed_at": _timestamp(self.observed_at, "Cookbook timestamp").isoformat(),
            "verified": self.verified,
            "latency_ms": self.latency_ms,
            "token_usage": self.token_usage,
            "monetary_cost": self.monetary_cost,
            "structured_output_valid": self.structured_output_valid,
            "tool_call_valid": self.tool_call_valid,
            "retry_count": self.retry_count,
            "escalation_required": self.escalation_required,
            "failure_class": self.failure_class,
            "verifier_agreement": self.verifier_agreement.value,
            "evidence_refs": self.evidence_refs,
        }
        return (
            self.observation_id
            or hashlib.sha256(
                json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")
            ).hexdigest()
        )


@dataclass(frozen=True, slots=True)
class CookbookSummary:
    identity: ModelIdentity
    task_class: str
    sample_count: int
    verified_success_count: int
    failure_count: int
    escalation_count: int
    unknown_outcome_count: int
    structured_sample_count: int
    structured_valid_count: int
    tool_sample_count: int
    tool_valid_count: int
    mean_latency_ms: float | None
    evidence_sufficiency: EvidenceSufficiency

    @property
    def verified_success_rate(self) -> float | None:
        return self.verified_success_count / self.sample_count if self.sample_count else None

    @property
    def escalation_rate(self) -> float | None:
        return self.escalation_count / self.sample_count if self.sample_count else None

    @property
    def structured_output_reliability(self) -> float | None:
        return (
            self.structured_valid_count / self.structured_sample_count
            if self.structured_sample_count
            else None
        )

    @property
    def tool_reliability(self) -> float | None:
        return self.tool_valid_count / self.tool_sample_count if self.tool_sample_count else None


class ModelKnowledgeStore:
    """Versioned SQLite store for bounded descriptive model knowledge."""

    _SCHEMA_VERSION = 1
    _MIGRATION_NAME = "create_model_knowledge"

    def __init__(self, path: Path) -> None:
        if not isinstance(path, Path):
            raise ModelKnowledgeError("Knowledge database path is invalid")
        path.parent.mkdir(parents=True, exist_ok=True)
        self._connection = sqlite3.connect(path, timeout=5.0, check_same_thread=False)
        self._connection.execute("PRAGMA busy_timeout=5000")
        self._connection.execute("PRAGMA foreign_keys=ON")
        self._connection.execute("PRAGMA journal_mode=WAL")
        self._lock = threading.RLock()
        try:
            self._migrate()
        except (sqlite3.DatabaseError, ModelKnowledgeError) as error:
            self._connection.close()
            if isinstance(error, ModelKnowledgeError):
                raise
            raise ModelKnowledgeError("Model knowledge database is unavailable") from error

    def _migrate(self) -> None:
        with self._connection:
            self._connection.execute(
                "CREATE TABLE IF NOT EXISTS model_knowledge_schema "
                "(version INTEGER PRIMARY KEY, name TEXT NOT NULL)"
            )
            rows = self._connection.execute(
                "SELECT version, name FROM model_knowledge_schema"
            ).fetchall()
            versions = {int(row[0]): str(row[1]) for row in rows}
            if any(version > self._SCHEMA_VERSION for version in versions):
                raise ModelKnowledgeError("Model knowledge database uses a future schema")
            if versions and versions.get(1) != self._MIGRATION_NAME:
                raise ModelKnowledgeError("Model knowledge migration identity mismatch")
            if not versions:
                self._connection.executescript(
                    """
                    CREATE TABLE providers (
                        provider_id TEXT PRIMARY KEY,
                        metadata_json TEXT NOT NULL,
                        availability TEXT NOT NULL,
                        available INTEGER,
                        detail TEXT NOT NULL,
                        source TEXT,
                        last_observed TEXT
                    );
                    CREATE TABLE models (
                        provider_id TEXT NOT NULL,
                        model_id TEXT NOT NULL,
                        model_version TEXT NOT NULL,
                        quantization TEXT NOT NULL,
                        runtime TEXT NOT NULL,
                        metadata_json TEXT NOT NULL,
                        availability TEXT NOT NULL,
                        first_seen TEXT,
                        last_seen TEXT,
                        last_source TEXT,
                        last_evidence_kind TEXT,
                        stale_since TEXT,
                        PRIMARY KEY(provider_id, model_id, model_version, quantization, runtime),
                        FOREIGN KEY(provider_id) REFERENCES providers(provider_id)
                    );
                    CREATE TABLE model_observations (
                        observation_key TEXT PRIMARY KEY,
                        provider_id TEXT NOT NULL,
                        model_id TEXT NOT NULL,
                        model_version TEXT NOT NULL,
                        quantization TEXT NOT NULL,
                        runtime TEXT NOT NULL,
                        metadata_json TEXT NOT NULL,
                        observed_at TEXT NOT NULL,
                        source TEXT NOT NULL,
                        evidence_kind TEXT NOT NULL,
                        evidence_detail TEXT NOT NULL,
                        availability TEXT NOT NULL,
                        machine_scope TEXT
                    );
                    CREATE TABLE model_evidence (
                        evidence_key TEXT PRIMARY KEY,
                        provider_id TEXT NOT NULL,
                        model_id TEXT NOT NULL,
                        model_version TEXT NOT NULL,
                        quantization TEXT NOT NULL,
                        runtime TEXT NOT NULL,
                        evidence_json TEXT NOT NULL
                    );
                    CREATE TABLE model_measurements (
                        measurement_key TEXT PRIMARY KEY,
                        provider_id TEXT NOT NULL,
                        model_id TEXT NOT NULL,
                        model_version TEXT NOT NULL,
                        quantization TEXT NOT NULL,
                        runtime TEXT NOT NULL,
                        measured_at TEXT NOT NULL,
                        source TEXT NOT NULL,
                        machine_scope TEXT NOT NULL,
                        metrics_json TEXT NOT NULL
                    );
                    CREATE TABLE cookbook_observations (
                        observation_id TEXT PRIMARY KEY,
                        provider_id TEXT NOT NULL,
                        model_id TEXT NOT NULL,
                        model_version TEXT NOT NULL,
                        quantization TEXT NOT NULL,
                        runtime TEXT NOT NULL,
                        task_class TEXT NOT NULL,
                        observation_json TEXT NOT NULL
                    );
                    CREATE INDEX cookbook_identity_task ON cookbook_observations(
                        provider_id, model_id, model_version, quantization, runtime, task_class
                    );
                    INSERT INTO model_knowledge_schema(version, name)
                    VALUES (1, 'create_model_knowledge');
                    """
                )

    def register_provider(
        self,
        metadata: ProviderMetadata,
        *,
        observed_at: datetime | None = None,
        available: bool | None = None,
        source: str | None = None,
        detail: str = "",
    ) -> None:
        _validate_provider(metadata)
        provider_id = metadata.provider_id.casefold()
        if available is not None and type(available) is not bool:
            raise ModelKnowledgeError("Provider availability is invalid")
        if source is not None:
            _bounded_text(source, "Provider source", 512)
        _bounded_text(detail, "Provider detail", 2_000, allow_empty=True)
        timestamp = _timestamp(observed_at, "Provider timestamp") if observed_at else None
        status = (
            KnowledgeAvailability.KNOWN
            if available is True
            else KnowledgeAvailability.CURRENTLY_UNAVAILABLE
            if available is False
            else KnowledgeAvailability.UNKNOWN
        )
        with self._lock, self._connection:
            existing = self._connection.execute(
                "SELECT availability, available, detail, source, last_observed "
                "FROM providers WHERE provider_id=?",
                (provider_id,),
            ).fetchone()
            if available is None and existing is not None:
                status_value = str(existing[0])
                available_value = existing[1]
                detail_value = str(existing[2])
                source_value = str(existing[3]) if existing[3] is not None else None
                timestamp_value = str(existing[4]) if existing[4] is not None else None
            else:
                status_value = status.value
                available_value = None if available is None else int(available)
                detail_value = detail
                source_value = source
                timestamp_value = timestamp.isoformat() if timestamp else None
            self._connection.execute(
                """INSERT INTO providers(provider_id, metadata_json, availability, available,
                   detail, source, last_observed) VALUES (?, ?, ?, ?, ?, ?, ?)
                   ON CONFLICT(provider_id) DO UPDATE SET metadata_json=excluded.metadata_json,
                   availability=excluded.availability, available=excluded.available,
                   detail=excluded.detail, source=excluded.source,
                   last_observed=excluded.last_observed""",
                (
                    provider_id,
                    json.dumps(_provider_json(metadata), sort_keys=True),
                    status_value,
                    available_value,
                    detail_value,
                    source_value,
                    timestamp_value,
                ),
            )

    def refresh(self, snapshot: ProviderCatalogSnapshot) -> None:
        if not isinstance(snapshot, ProviderCatalogSnapshot):
            raise ModelKnowledgeError("Provider catalog snapshot is malformed")
        self.register_provider(
            snapshot.provider,
            observed_at=snapshot.observed_at,
            available=snapshot.available,
            source=snapshot.source,
            detail=snapshot.detail,
        )
        current = {item.identity.storage_key for item in snapshot.models}
        with self._lock, self._connection:
            rows = self._connection.execute(
                "SELECT provider_id, model_id, model_version, quantization, runtime "
                "FROM models WHERE provider_id=?",
                (snapshot.provider.provider_id.casefold(),),
            ).fetchall()
            for row in rows:
                identity = ModelIdentity(*[str(value) for value in row])
                if identity.storage_key not in current:
                    self._connection.execute(
                        "UPDATE models SET availability=?, stale_since=COALESCE(stale_since, ?) "
                        "WHERE provider_id=? AND model_id=? AND model_version=? "
                        "AND quantization=? AND runtime=?",
                        (
                            KnowledgeAvailability.STALE.value,
                            _timestamp(snapshot.observed_at, "Refresh timestamp").isoformat(),
                            identity.provider_id,
                            identity.model_id,
                            identity.version,
                            identity.quantization,
                            identity.runtime,
                        ),
                    )
            for observation in snapshot.models:
                self._record_model_observation_locked(observation)

    def record_model_observation(self, observation: ModelObservation) -> None:
        if not isinstance(observation, ModelObservation):
            raise ModelKnowledgeError("Model observation is malformed")
        with self._lock, self._connection:
            self._record_model_observation_locked(observation)

    def _record_model_observation_locked(self, observation: ModelObservation) -> None:
        identity = observation.identity
        provider = self._connection.execute(
            "SELECT 1 FROM providers WHERE provider_id=?", (identity.provider_id,)
        ).fetchone()
        if provider is None:
            raise ModelKnowledgeError("Provider must be registered before model observation")
        observed = _timestamp(observation.observed_at, "Model observation timestamp")
        evidence = EvidenceRecord(
            observation.evidence_kind,
            observation.source,
            observation.evidence_detail or "Model knowledge observation",
            captured_at=observed,
            machine_scope=observation.machine_scope,
        )
        observation_key = hashlib.sha256(
            json.dumps(
                {
                    "identity": identity.storage_key,
                    "metadata": _metadata_json(observation.metadata),
                    "observed_at": observed.isoformat(),
                    "source": observation.source,
                    "evidence": _evidence_json(evidence),
                    "availability": observation.availability.value,
                },
                sort_keys=True,
                separators=(",", ":"),
            ).encode("utf-8")
        ).hexdigest()
        self._connection.execute(
            """INSERT OR IGNORE INTO model_observations VALUES (
               ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?
            )""",
            (
                observation_key,
                identity.provider_id,
                identity.model_id,
                identity.version,
                identity.quantization,
                identity.runtime,
                json.dumps(_metadata_json(observation.metadata), sort_keys=True),
                observed.isoformat(),
                observation.source,
                observation.evidence_kind.value,
                observation.evidence_detail,
                observation.availability.value,
                observation.machine_scope,
            ),
        )
        self._connection.execute(
            "INSERT OR IGNORE INTO model_evidence VALUES (?, ?, ?, ?, ?, ?, ?)",
            (
                observation_key,
                identity.provider_id,
                identity.model_id,
                identity.version,
                identity.quantization,
                identity.runtime,
                json.dumps(_evidence_json(evidence), sort_keys=True),
            ),
        )
        key_args = (
            identity.provider_id,
            identity.model_id,
            identity.version,
            identity.quantization,
            identity.runtime,
        )
        current = self._connection.execute(
            "SELECT first_seen, last_seen, last_evidence_kind, last_source FROM models "
            "WHERE provider_id=? AND model_id=? AND model_version=? "
            "AND quantization=? AND runtime=?",
            key_args,
        ).fetchone()
        replace_current = current is None or _observation_wins(observation, current)
        if current is None:
            self._connection.execute(
                """INSERT INTO models VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                (
                    *key_args,
                    json.dumps(_metadata_json(observation.metadata), sort_keys=True),
                    observation.availability.value,
                    observed.isoformat(),
                    observed.isoformat(),
                    observation.source,
                    observation.evidence_kind.value,
                    observed.isoformat()
                    if observation.availability is KnowledgeAvailability.STALE
                    else None,
                ),
            )
        elif replace_current:
            self._connection.execute(
                """UPDATE models SET metadata_json=?, availability=?, last_seen=?, last_source=?,
                   last_evidence_kind=?, stale_since=?
                   WHERE provider_id=? AND model_id=? AND model_version=?
                   AND quantization=? AND runtime=?""",
                (
                    json.dumps(_metadata_json(observation.metadata), sort_keys=True),
                    observation.availability.value,
                    observed.isoformat(),
                    observation.source,
                    observation.evidence_kind.value,
                    observed.isoformat()
                    if observation.availability is KnowledgeAvailability.STALE
                    else None,
                    *key_args,
                ),
            )

    def record_measurement(
        self, identity: ModelIdentity, measurement: ModelMeasurement, *, machine_scope: str
    ) -> None:
        if not isinstance(identity, ModelIdentity) or not isinstance(measurement, ModelMeasurement):
            raise ModelKnowledgeError("Model measurement is malformed")
        if measurement.model_id != identity.model_id:
            raise ModelKnowledgeError("Model measurement identity does not match")
        _bounded_text(machine_scope, "Machine scope", 256)
        if machine_scope != "this_machine":
            raise ModelKnowledgeError("Machine measurements must use this_machine scope")
        measured = _timestamp(measurement.measured_at, "Measurement timestamp")
        metrics = {
            name: value
            for name, value in (
                ("storage_bytes", measurement.storage_bytes),
                ("peak_ram_bytes", measurement.peak_ram_bytes),
                ("peak_vram_bytes", measurement.peak_vram_bytes),
                ("load_seconds", measurement.load_seconds),
                ("throughput", measurement.throughput),
                ("concurrency", measurement.concurrency),
            )
            if value is not None
        }
        measurement_key = hashlib.sha256(
            json.dumps(
                [
                    identity.storage_key,
                    measured.isoformat(),
                    measurement.source,
                    machine_scope,
                    metrics,
                ],
                sort_keys=True,
                separators=(",", ":"),
            ).encode("utf-8")
        ).hexdigest()
        with self._lock, self._connection:
            exists = self._connection.execute(
                "SELECT 1 FROM models WHERE provider_id=? AND model_id=? AND model_version=? "
                "AND quantization=? AND runtime=?",
                (
                    identity.provider_id,
                    identity.model_id,
                    identity.version,
                    identity.quantization,
                    identity.runtime,
                ),
            ).fetchone()
            if exists is None:
                raise ModelKnowledgeError("Model must be known before recording measurement")
            self._connection.execute(
                "INSERT OR IGNORE INTO model_measurements VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                (
                    measurement_key,
                    identity.provider_id,
                    identity.model_id,
                    identity.version,
                    identity.quantization,
                    identity.runtime,
                    measured.isoformat(),
                    measurement.source,
                    machine_scope,
                    json.dumps(metrics, sort_keys=True),
                ),
            )
            evidence = EvidenceRecord(
                EvidenceKind.MEASURED_ON_THIS_MACHINE,
                measurement.source,
                "Trusted local model runtime measurement",
                captured_at=measured,
                machine_scope=machine_scope,
                metrics=tuple((key, str(value)) for key, value in metrics.items()),
            )
            evidence_key = hashlib.sha256(
                json.dumps(
                    [identity.storage_key, _evidence_json(evidence)], sort_keys=True
                ).encode()
            ).hexdigest()
            self._connection.execute(
                "INSERT OR IGNORE INTO model_evidence VALUES (?, ?, ?, ?, ?, ?, ?)",
                (
                    evidence_key,
                    identity.provider_id,
                    identity.model_id,
                    identity.version,
                    identity.quantization,
                    identity.runtime,
                    json.dumps(_evidence_json(evidence), sort_keys=True),
                ),
            )
            current_metadata = self._connection.execute(
                "SELECT metadata_json FROM models WHERE provider_id=? AND model_id=? "
                "AND model_version=? AND quantization=? AND runtime=?",
                (
                    identity.provider_id,
                    identity.model_id,
                    identity.version,
                    identity.quantization,
                    identity.runtime,
                ),
            ).fetchone()
            if current_metadata is not None:
                metadata = _metadata_from_json(json.loads(str(current_metadata[0])))
                if measurement.storage_bytes is not None:
                    metadata = replace(metadata, storage_bytes=measurement.storage_bytes)
                if measurement.peak_ram_bytes is not None:
                    metadata = replace(metadata, ram_bytes=measurement.peak_ram_bytes)
                if measurement.peak_vram_bytes is not None:
                    metadata = replace(metadata, vram_bytes=measurement.peak_vram_bytes)
                if measurement.concurrency and measurement.concurrency > 0:
                    metadata = replace(metadata, max_concurrency=measurement.concurrency)
                if any(
                    value is not None
                    for value in (
                        measurement.storage_bytes,
                        measurement.peak_ram_bytes,
                        measurement.peak_vram_bytes,
                        measurement.concurrency,
                    )
                ):
                    self._connection.execute(
                        "UPDATE models SET metadata_json=? WHERE provider_id=? "
                        "AND model_id=? AND model_version=? AND quantization=? "
                        "AND runtime=?",
                        (
                            json.dumps(_metadata_json(metadata), sort_keys=True),
                            identity.provider_id,
                            identity.model_id,
                            identity.version,
                            identity.quantization,
                            identity.runtime,
                        ),
                    )

    def providers(self, *, as_of: datetime | None = None) -> tuple[ProviderKnowledgeView, ...]:
        cutoff = _timestamp(as_of, "Query timestamp") if as_of else datetime.now(UTC)
        with self._lock:
            rows = self._connection.execute(
                "SELECT metadata_json, availability, available, detail, source, last_observed "
                "FROM providers ORDER BY provider_id"
            ).fetchall()
        return tuple(
            ProviderKnowledgeView(
                _provider_from_json(json.loads(str(row[0]))),
                KnowledgeAvailability(str(row[1])),
                None if row[2] is None else bool(row[2]),
                str(row[3]),
                str(row[4]) if row[4] is not None else None,
                datetime.fromisoformat(str(row[5])) if row[5] else None,
                _freshness(datetime.fromisoformat(str(row[5])) if row[5] else None, cutoff),
            )
            for row in rows
        )

    def models(
        self,
        *,
        provider_id: str | None = None,
        role: ModelRole | None = None,
        capability: str | None = None,
        modality: str | None = None,
        include_stale: bool = False,
        limit: int = 256,
        as_of: datetime | None = None,
    ) -> tuple[ModelKnowledgeView, ...]:
        if provider_id is not None:
            _bounded_text(provider_id, "Provider ID", 256)
        if role is not None and not isinstance(role, ModelRole):
            raise ModelKnowledgeError("Model role filter is invalid")
        if capability is not None:
            _bounded_text(capability, "Capability filter", 128)
        if modality is not None:
            _bounded_text(modality, "Modality filter", 128)
        if type(limit) is not int or not 1 <= limit <= 1_024:
            raise ModelKnowledgeError("Model query limit is invalid")
        cutoff = _timestamp(as_of, "Query timestamp") if as_of else datetime.now(UTC)
        query = (
            "SELECT provider_id, model_id, model_version, quantization, runtime, "
            "metadata_json, availability, first_seen, last_seen, last_source FROM models"
        )
        args: list[object] = []
        if provider_id:
            query += " WHERE provider_id=?"
            args.append(provider_id)
        query += " ORDER BY provider_id, model_id, model_version, quantization, runtime LIMIT 1024"
        with self._lock:
            rows = self._connection.execute(query, args).fetchall()
            result: list[ModelKnowledgeView] = []
            for row in rows:
                metadata = _metadata_from_json(json.loads(str(row[5])))
                availability = KnowledgeAvailability(str(row[6]))
                if not include_stale and availability is KnowledgeAvailability.STALE:
                    continue
                if role is not None and role not in metadata.roles:
                    continue
                if capability is not None and capability not in metadata.capabilities:
                    continue
                if modality is not None and modality not in metadata.modalities:
                    continue
                identity = ModelIdentity(
                    str(row[0]), str(row[1]), str(row[2]), str(row[3]), str(row[4])
                )
                evidence_count = self._connection.execute(
                    "SELECT COUNT(*) FROM model_evidence WHERE provider_id=? AND model_id=? "
                    "AND model_version=? AND quantization=? AND runtime=?",
                    (
                        identity.provider_id,
                        identity.model_id,
                        identity.version,
                        identity.quantization,
                        identity.runtime,
                    ),
                ).fetchone()[0]
                measurement_count = self._connection.execute(
                    "SELECT COUNT(*) FROM model_measurements WHERE provider_id=? AND model_id=? "
                    "AND model_version=? AND quantization=? AND runtime=?",
                    (
                        identity.provider_id,
                        identity.model_id,
                        identity.version,
                        identity.quantization,
                        identity.runtime,
                    ),
                ).fetchone()[0]
                last_seen = datetime.fromisoformat(str(row[8])) if row[8] else None
                result.append(
                    ModelKnowledgeView(
                        identity,
                        metadata,
                        availability,
                        datetime.fromisoformat(str(row[7])) if row[7] else None,
                        last_seen,
                        str(row[9]) if row[9] is not None else None,
                        int(evidence_count),
                        int(measurement_count),
                        _freshness(last_seen, cutoff),
                    )
                )
                if len(result) >= limit:
                    break
        return tuple(result)

    def inspect_model(self, identity: ModelIdentity) -> ModelKnowledgeView:
        matches = self.models(provider_id=identity.provider_id, include_stale=True, limit=1_024)
        for item in matches:
            if item.identity == identity:
                return item
        raise KeyError(identity.storage_key)

    def evidence(self, identity: ModelIdentity) -> tuple[EvidenceRecord, ...]:
        if not isinstance(identity, ModelIdentity):
            raise ModelKnowledgeError("Model identity is malformed")
        with self._lock:
            rows = self._connection.execute(
                "SELECT evidence_json FROM model_evidence WHERE provider_id=? AND model_id=? "
                "AND model_version=? AND quantization=? AND runtime=? ORDER BY evidence_key",
                (
                    identity.provider_id,
                    identity.model_id,
                    identity.version,
                    identity.quantization,
                    identity.runtime,
                ),
            ).fetchall()
        return tuple(_evidence_from_json(json.loads(str(row[0]))) for row in rows)

    def record_cookbook(self, observation: CookbookObservation) -> bool:
        if not isinstance(observation, CookbookObservation):
            raise ModelKnowledgeError("Cookbook observation is malformed")
        payload = _cookbook_json(observation)
        with self._lock, self._connection:
            known = self._connection.execute(
                "SELECT 1 FROM models WHERE provider_id=? AND model_id=? "
                "AND model_version=? AND quantization=? AND runtime=?",
                (
                    observation.identity.provider_id,
                    observation.identity.model_id,
                    observation.identity.version,
                    observation.identity.quantization,
                    observation.identity.runtime,
                ),
            ).fetchone()
            if known is None:
                raise ModelKnowledgeError("Cookbook model must be known")
            cursor = self._connection.execute(
                "INSERT OR IGNORE INTO cookbook_observations VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
                (
                    observation.dedupe_key,
                    observation.identity.provider_id,
                    observation.identity.model_id,
                    observation.identity.version,
                    observation.identity.quantization,
                    observation.identity.runtime,
                    observation.task_class,
                    json.dumps(payload, sort_keys=True),
                ),
            )
            return cursor.rowcount == 1

    def cookbook_summary(
        self, identity: ModelIdentity, *, task_class: str | None = None
    ) -> CookbookSummary:
        if not isinstance(identity, ModelIdentity):
            raise ModelKnowledgeError("Model identity is malformed")
        if task_class is not None:
            _bounded_text(task_class, "Task class", 128)
        query = (
            "SELECT observation_json FROM cookbook_observations WHERE provider_id=? "
            "AND model_id=? AND model_version=? AND quantization=? AND runtime=?"
        )
        args: list[object] = [
            identity.provider_id,
            identity.model_id,
            identity.version,
            identity.quantization,
            identity.runtime,
        ]
        if task_class is not None:
            query += " AND task_class=?"
            args.append(task_class)
        query += " ORDER BY observation_id"
        with self._lock:
            rows = self._connection.execute(query, args).fetchall()
        observations = [_cookbook_from_json(json.loads(str(row[0]))) for row in rows]
        task = task_class or (observations[0].task_class if observations else "")
        if any(item.task_class != task for item in observations):
            raise ModelKnowledgeError("A summary requires one task class")
        structured = [item for item in observations if item.structured_output_valid is not None]
        tools = [item for item in observations if item.tool_call_valid is not None]
        latencies = [float(item.latency_ms) for item in observations if item.latency_ms is not None]
        return CookbookSummary(
            identity,
            task,
            len(observations),
            sum(item.outcome is CookbookOutcome.VERIFIED_SUCCESS for item in observations),
            sum(item.outcome is CookbookOutcome.FAILURE for item in observations),
            sum(
                item.outcome is CookbookOutcome.ESCALATION or item.escalation_required
                for item in observations
            ),
            sum(item.outcome is CookbookOutcome.UNKNOWN_OUTCOME for item in observations),
            len(structured),
            sum(item.structured_output_valid is True for item in structured),
            len(tools),
            sum(item.tool_call_valid is True for item in tools),
            sum(latencies) / len(latencies) if latencies else None,
            EvidenceSufficiency.SUFFICIENT
            if len(observations) >= 3
            else EvidenceSufficiency.INSUFFICIENT,
        )

    def close(self) -> None:
        with self._lock:
            self._connection.close()


class ModelKnowledgeService:
    """Application-owned facade over the durable model knowledge plane."""

    def __init__(self, store: ModelKnowledgeStore) -> None:
        if not isinstance(store, ModelKnowledgeStore):
            raise ModelKnowledgeError("Knowledge store is malformed")
        self._store = store

    @property
    def store(self) -> ModelKnowledgeStore:
        return self._store

    def refresh(self, snapshot: ProviderCatalogSnapshot) -> None:
        self._store.refresh(snapshot)

    async def refresh_from(self, discovery: ProviderModelDiscovery) -> ProviderCatalogSnapshot:
        snapshot = await discovery.discover()
        self.refresh(snapshot)
        return snapshot

    def refresh_registry(
        self,
        registry: ProviderRegistry,
        *,
        observed_at: datetime,
        source: str = "provider_registry",
    ) -> None:
        if not isinstance(registry, ProviderRegistry):
            raise ModelKnowledgeError("Provider registry is malformed")
        for _, definition in registry.definitions():
            self.refresh(
                ProviderCatalogSnapshot(
                    definition.metadata,
                    tuple(
                        ModelObservation(
                            identity_for(definition.metadata.provider_id, model),
                            model,
                            observed_at,
                            source,
                            EvidenceKind.PROVIDER_REPORTED,
                            "Provider registry metadata; not machine measurement",
                        )
                        for model in definition.models
                    ),
                    observed_at,
                    source,
                )
            )

    def observe_provider_health(
        self,
        provider: ProviderMetadata,
        available: bool,
        *,
        observed_at: datetime,
        source: str,
        detail: str,
    ) -> None:
        self._store.register_provider(
            provider, observed_at=observed_at, available=available, source=source, detail=detail
        )

    def record_measurement(
        self,
        identity: ModelIdentity,
        measurement: ModelMeasurement,
        *,
        machine_scope: str = "this_machine",
    ) -> None:
        self._store.record_measurement(identity, measurement, machine_scope=machine_scope)

    def record_model_observation(self, observation: ModelObservation) -> None:
        self._store.record_model_observation(observation)

    def record_cookbook(self, observation: CookbookObservation) -> bool:
        return self._store.record_cookbook(observation)

    def providers(self, *, as_of: datetime | None = None) -> tuple[ProviderKnowledgeView, ...]:
        return self._store.providers(as_of=as_of)

    def models(
        self,
        *,
        provider_id: str | None = None,
        role: ModelRole | None = None,
        capability: str | None = None,
        modality: str | None = None,
        include_stale: bool = False,
        limit: int = 256,
        as_of: datetime | None = None,
    ) -> tuple[ModelKnowledgeView, ...]:
        return self._store.models(
            provider_id=provider_id,
            role=role,
            capability=capability,
            modality=modality,
            include_stale=include_stale,
            limit=limit,
            as_of=as_of,
        )

    def inspect_model(self, identity: ModelIdentity) -> ModelKnowledgeView:
        return self._store.inspect_model(identity)

    def evidence(self, identity: ModelIdentity) -> tuple[EvidenceRecord, ...]:
        return self._store.evidence(identity)

    def cookbook_summary(
        self, identity: ModelIdentity, *, task_class: str | None = None
    ) -> CookbookSummary:
        return self._store.cookbook_summary(identity, task_class=task_class)

    def close(self) -> None:
        self._store.close()


def _validate_provider(metadata: ProviderMetadata) -> None:
    if not isinstance(metadata, ProviderMetadata):
        raise ModelKnowledgeError("Provider metadata is malformed")
    _bounded_text(metadata.provider_id, "Provider ID", 256)
    _bounded_text(metadata.display_name, "Provider display name", 256)
    _bounded_text(metadata.version, "Provider version", 128)


def _observation_wins(observation: ModelObservation, current: tuple[object, ...]) -> bool:
    current_seen = datetime.fromisoformat(str(current[1])) if current[1] else None
    observed = _timestamp(observation.observed_at, "Model observation timestamp")
    if current_seen is None or observed > current_seen:
        return True
    if observed < current_seen:
        return False
    rank = {
        EvidenceKind.PUBLISHED: 1,
        EvidenceKind.COMMUNITY: 2,
        EvidenceKind.PROVIDER_REPORTED: 3,
        EvidenceKind.MEASURED_ON_THIS_MACHINE: 4,
    }
    current_rank = rank.get(EvidenceKind(str(current[2])), 0) if current[2] else 0
    return (rank[observation.evidence_kind], observation.source) > (
        current_rank,
        str(current[3] or ""),
    )


def _freshness(value: datetime | None, as_of: datetime) -> EvidenceFreshness:
    if value is None:
        return EvidenceFreshness.UNKNOWN
    return (
        EvidenceFreshness.FRESH if as_of - value <= timedelta(hours=24) else EvidenceFreshness.STALE
    )


def _provider_json(metadata: ProviderMetadata) -> dict[str, object]:
    return {
        "provider_id": metadata.provider_id.casefold(),
        "display_name": metadata.display_name,
        "version": metadata.version,
        "local_only": metadata.local_only,
        "locality": metadata.locality.value,
    }


def _provider_from_json(value: dict[str, Any]) -> ProviderMetadata:
    return ProviderMetadata(
        str(value["provider_id"]),
        str(value["display_name"]),
        str(value["version"]),
        bool(value["local_only"]),
        ProviderLocality(str(value["locality"])),
    )


def _metadata_json(metadata: ModelMetadata) -> dict[str, object]:
    return {
        "model_id": metadata.model_id,
        "context_limit": metadata.context_limit,
        "capabilities": sorted(metadata.capabilities),
        "roles": sorted(role.value for role in metadata.roles),
        "family": metadata.family,
        "version": metadata.version,
        "quantization": metadata.quantization,
        "runtime": metadata.runtime,
        "source": metadata.source,
        "modalities": sorted(metadata.modalities),
        "storage_bytes": metadata.storage_bytes,
        "ram_bytes": metadata.ram_bytes,
        "vram_bytes": metadata.vram_bytes,
        "license": metadata.license,
        "compatibility": sorted(metadata.compatibility),
        "max_concurrency": metadata.max_concurrency,
        "quality_score": metadata.quality_score,
        "latency_ms": metadata.latency_ms,
        "input_cost_per_million": metadata.input_cost_per_million,
        "output_cost_per_million": metadata.output_cost_per_million,
    }


def _metadata_from_json(value: dict[str, Any]) -> ModelMetadata:
    return ModelMetadata(
        str(value["model_id"]),
        int(value["context_limit"]),
        frozenset(str(item) for item in value["capabilities"]),
        frozenset(ModelRole(str(item)) for item in value["roles"]),
        str(value["family"]),
        str(value["version"]),
        str(value["quantization"]),
        str(value["runtime"]),
        str(value["source"]),
        frozenset(str(item) for item in value["modalities"]),
        value["storage_bytes"] if value["storage_bytes"] is None else int(value["storage_bytes"]),
        value["ram_bytes"] if value["ram_bytes"] is None else int(value["ram_bytes"]),
        value["vram_bytes"] if value["vram_bytes"] is None else int(value["vram_bytes"]),
        str(value["license"]),
        frozenset(str(item) for item in value["compatibility"]),
        (),
        value["max_concurrency"]
        if value["max_concurrency"] is None
        else int(value["max_concurrency"]),
        value["quality_score"] if value["quality_score"] is None else float(value["quality_score"]),
        value["latency_ms"] if value["latency_ms"] is None else float(value["latency_ms"]),
        value["input_cost_per_million"]
        if value["input_cost_per_million"] is None
        else float(value["input_cost_per_million"]),
        value["output_cost_per_million"]
        if value["output_cost_per_million"] is None
        else float(value["output_cost_per_million"]),
    )


def _evidence_json(evidence: EvidenceRecord) -> dict[str, object]:
    return {
        "kind": evidence.kind.value,
        "source": evidence.source,
        "detail": evidence.detail,
        "captured_at": evidence.captured_at.isoformat() if evidence.captured_at else None,
        "machine_scope": evidence.machine_scope,
        "metrics": evidence.metrics,
    }


def _evidence_from_json(value: dict[str, Any]) -> EvidenceRecord:
    return EvidenceRecord(
        EvidenceKind(str(value["kind"])),
        str(value["source"]),
        str(value["detail"]),
        datetime.fromisoformat(str(value["captured_at"])) if value["captured_at"] else None,
        str(value["machine_scope"]) if value["machine_scope"] else None,
        tuple((str(key), str(metric)) for key, metric in value["metrics"]),
    )


def _cookbook_json(observation: CookbookObservation) -> dict[str, object]:
    return {
        "identity": [
            observation.identity.provider_id,
            observation.identity.model_id,
            observation.identity.version,
            observation.identity.quantization,
            observation.identity.runtime,
        ],
        "task_class": observation.task_class,
        "operation_class": observation.operation_class,
        "role": observation.role.value if observation.role else None,
        "environment": observation.environment,
        "locality": observation.locality.value,
        "machine_scope": observation.machine_scope,
        "input_size_bucket": observation.input_size_bucket,
        "outcome": observation.outcome.value,
        "observed_at": _timestamp(observation.observed_at, "Cookbook timestamp").isoformat(),
        "verified": observation.verified,
        "latency_ms": observation.latency_ms,
        "token_usage": observation.token_usage,
        "monetary_cost": observation.monetary_cost,
        "structured_output_valid": observation.structured_output_valid,
        "tool_call_valid": observation.tool_call_valid,
        "retry_count": observation.retry_count,
        "escalation_required": observation.escalation_required,
        "failure_class": observation.failure_class,
        "verifier_agreement": observation.verifier_agreement.value,
        "evidence_refs": observation.evidence_refs,
        "observation_id": observation.dedupe_key,
    }


def _cookbook_from_json(value: dict[str, Any]) -> CookbookObservation:
    identity_values = [str(item) for item in value["identity"]]
    return CookbookObservation(
        ModelIdentity(*identity_values),
        str(value["task_class"]),
        CookbookOutcome(str(value["outcome"])),
        datetime.fromisoformat(str(value["observed_at"])),
        str(value["operation_class"]),
        ModelRole(str(value["role"])) if value["role"] else None,
        str(value["environment"]),
        ProviderLocality(str(value["locality"])),
        str(value["machine_scope"]) if value["machine_scope"] else None,
        str(value["input_size_bucket"]),
        value["verified"] if value["verified"] is None else bool(value["verified"]),
        value["latency_ms"] if value["latency_ms"] is None else float(value["latency_ms"]),
        value["token_usage"] if value["token_usage"] is None else int(value["token_usage"]),
        value["monetary_cost"] if value["monetary_cost"] is None else float(value["monetary_cost"]),
        value["structured_output_valid"]
        if value["structured_output_valid"] is None
        else bool(value["structured_output_valid"]),
        value["tool_call_valid"]
        if value["tool_call_valid"] is None
        else bool(value["tool_call_valid"]),
        int(value["retry_count"]),
        bool(value["escalation_required"]),
        str(value["failure_class"]),
        VerifierAgreement(str(value["verifier_agreement"])),
        tuple(str(item) for item in value["evidence_refs"]),
        str(value["observation_id"]),
    )
