"""Derived, provider-neutral routing fitness from trusted verified outcomes."""

from __future__ import annotations

import json
import sqlite3
from collections.abc import Callable
from dataclasses import dataclass, replace
from datetime import UTC, datetime, timedelta
from enum import StrEnum
from pathlib import Path
from threading import RLock
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from jarvis.planning.models import (
        PlanningStep,
        PlanningTask,
        StepExecutionResult,
        StepVerification,
    )


class SemanticOutcome(StrEnum):
    VERIFIED_SUCCESS = "verified_success"
    VERIFIED_FAILURE = "verified_failure"
    UNVERIFIED = "unverified"
    UNKNOWN = "unknown"


class FitnessEvidence(StrEnum):
    UNKNOWN = "unknown"
    INSUFFICIENT = "insufficient_evidence"
    SUFFICIENT = "sufficient_evidence"
    STALE = "stale"


class CircuitState(StrEnum):
    CLOSED = "closed"
    OPEN = "open"
    HALF_OPEN = "half_open"


@dataclass(frozen=True, slots=True)
class RouteResilienceKey:
    route_identity: str
    candidate_kind: str
    task_class: str
    role: str

    @property
    def storage_key(self) -> str:
        return "|".join((self.route_identity, self.candidate_kind, self.task_class, self.role))


@dataclass(frozen=True, slots=True)
class CircuitSnapshot:
    key: RouteResilienceKey
    state: CircuitState = CircuitState.CLOSED
    qualifying_failures: int = 0
    window_started_at: datetime | None = None
    opened_at: datetime | None = None
    cooldown_until: datetime | None = None
    probe_claimed: bool = False
    exploration_attempts: int = 0
    exploration_last_at: datetime | None = None


@dataclass(frozen=True, slots=True)
class ResiliencePolicy:
    failure_threshold: int = 3
    failure_window: timedelta = timedelta(minutes=10)
    cooldown: timedelta = timedelta(minutes=5)
    lkgr_min_samples: int = 3
    lkgr_min_verified_reliability: float = 0.8
    exploration_max_attempts: int = 1

    def __post_init__(self) -> None:
        if self.failure_threshold < 1 or self.failure_window <= timedelta(0):
            raise ValueError("Circuit failure policy is invalid")
        if self.cooldown <= timedelta(0) or self.lkgr_min_samples < 1:
            raise ValueError("Circuit cooldown policy is invalid")
        if not 0.0 <= self.lkgr_min_verified_reliability <= 1.0:
            raise ValueError("LKGR reliability policy is invalid")
        if self.exploration_max_attempts < 1:
            raise ValueError("Exploration policy is invalid")


@dataclass(frozen=True, slots=True)
class VerifiedRouteOutcome:
    """One trusted, bounded route observation; no prompt or response content."""

    observation_id: str
    route_identity: str
    candidate_kind: str
    task_class: str
    role: str
    observed_at: datetime
    operational_outcome: str
    semantic_outcome: SemanticOutcome
    verification_source: str | None = None
    retry_count: int = 0
    failure_class: str | None = None
    latency_ms: float | None = None
    monetary_cost: float | None = None
    evidence_refs: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        for name, value, limit in (
            ("observation ID", self.observation_id, 256),
            ("route identity", self.route_identity, 256),
            ("candidate kind", self.candidate_kind, 64),
            ("task class", self.task_class, 128),
            ("role", self.role, 64),
            ("operational outcome", self.operational_outcome, 64),
        ):
            if type(value) is not str or not value.strip() or len(value) > limit or "\x00" in value:
                raise ValueError(f"Route outcome {name} is invalid")
        if not isinstance(self.semantic_outcome, SemanticOutcome):
            raise ValueError("Route semantic outcome is invalid")
        if self.verification_source is not None and (
            type(self.verification_source) is not str
            or not self.verification_source.strip()
            or len(self.verification_source) > 128
        ):
            raise ValueError("Route verification source is invalid")
        if self.observed_at.tzinfo is None:
            raise ValueError("Route outcome timestamp must be timezone-aware")
        if type(self.retry_count) is not int or self.retry_count < 0:
            raise ValueError("Route outcome retry count is invalid")
        for name, metric in (
            ("latency", self.latency_ms),
            ("cost", self.monetary_cost),
        ):
            if metric is not None and (type(metric) not in {int, float} or metric < 0):
                raise ValueError(f"Route outcome {name} is invalid")
        if type(self.evidence_refs) is not tuple or len(self.evidence_refs) > 16:
            raise ValueError("Route outcome evidence references are invalid")
        if any(
            type(reference) is not str
            or not reference.strip()
            or len(reference) > 256
            or "\x00" in reference
            for reference in self.evidence_refs
        ):
            raise ValueError("Route outcome evidence reference is invalid")


@dataclass(frozen=True, slots=True)
class RoutingDecisionRecord:
    """Safe immutable routing facts; prompts and model output are excluded."""

    decision_id: str
    decided_at: datetime
    route_kind: str
    selected_identity: str | None
    role: str
    task_class: str
    policy: str
    privacy_classification: str
    required_capabilities: tuple[str, ...] = ()
    strategy: str = "single_route"
    alternative_identities: tuple[str, ...] = ()
    exclusions: tuple[tuple[str, str], ...] = ()
    quality_score: float | None = None
    sample_count: int | None = None
    evidence_sufficiency: str | None = None
    lkgr: bool | None = None
    breaker_state: str | None = None
    exploration: bool = False
    resource_status: str | None = None
    protected_headroom: bool | None = None
    affinity_current: bool | None = None
    affinity_warm: bool | None = None
    switching_cost_ms: float | None = None
    predicted_latency_ms: float | None = None
    predicted_cost: float | None = None
    fallback_identities: tuple[str, ...] = ()
    evidence_refs: tuple[str, ...] = ()
    fusion_strategy: str | None = None

    def __post_init__(self) -> None:
        for name, value, limit in (
            ("decision ID", self.decision_id, 128),
            ("route kind", self.route_kind, 64),
            ("role", self.role, 64),
            ("task class", self.task_class, 128),
            ("policy", self.policy, 64),
            ("privacy classification", self.privacy_classification, 64),
            ("strategy", self.strategy, 64),
        ):
            if type(value) is not str or not value.strip() or len(value) > limit:
                raise ValueError(f"Routing decision {name} is invalid")
        if self.decided_at.tzinfo is None:
            raise ValueError("Routing decision timestamp must be timezone-aware")
        if self.selected_identity is not None and (
            type(self.selected_identity) is not str or not self.selected_identity.strip()
        ):
            raise ValueError("Routing decision selected identity is invalid")
        for name, values, limit in (
            ("capabilities", self.required_capabilities, 32),
            ("alternatives", self.alternative_identities, 4),
            ("fallbacks", self.fallback_identities, 4),
            ("evidence references", self.evidence_refs, 16),
        ):
            if type(values) is not tuple or len(values) > limit:
                raise ValueError(f"Routing decision {name} are invalid")
            if any(type(item) is not str or not item.strip() or len(item) > 256 for item in values):
                raise ValueError(f"Routing decision {name} are invalid")
        if type(self.exclusions) is not tuple or len(self.exclusions) > 8:
            raise ValueError("Routing decision exclusions are invalid")
        if any(
            type(identity) is not str
            or not identity.strip()
            or type(reason) is not str
            or not reason.strip()
            for identity, reason in self.exclusions
        ):
            raise ValueError("Routing decision exclusions are invalid")
        if self.sample_count is not None and (
            type(self.sample_count) is not int or self.sample_count < 0
        ):
            raise ValueError("Routing decision sample count is invalid")
        if type(self.exploration) is not bool:
            raise ValueError("Routing decision exploration flag is invalid")
        for metric_name, metric_value in (
            ("quality", self.quality_score),
            ("switching cost", self.switching_cost_ms),
            ("latency", self.predicted_latency_ms),
            ("cost", self.predicted_cost),
        ):
            if metric_value is not None and (
                type(metric_value) not in {int, float} or metric_value < 0
            ):
                raise ValueError(f"Routing decision {metric_name} is invalid")


@dataclass(frozen=True, slots=True)
class RoutingDecisionOutcome:
    """Trusted execution facts linked after an immutable routing decision."""

    outcome_id: str
    decision_id: str
    observed_at: datetime
    executed_identity: str
    operational_outcome: str
    semantic_outcome: SemanticOutcome
    rerouted: bool = False
    retry_count: int = 0
    evidence_refs: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        for name, value in (
            ("outcome ID", self.outcome_id),
            ("decision ID", self.decision_id),
            ("executed identity", self.executed_identity),
            ("operational outcome", self.operational_outcome),
        ):
            if type(value) is not str or not value.strip() or len(value) > 256:
                raise ValueError(f"Routing outcome {name} is invalid")
        if self.observed_at.tzinfo is None or not isinstance(
            self.semantic_outcome, SemanticOutcome
        ):
            raise ValueError("Routing outcome metadata is invalid")
        if (
            type(self.rerouted) is not bool
            or type(self.retry_count) is not int
            or self.retry_count < 0
        ):
            raise ValueError("Routing outcome state is invalid")
        if type(self.evidence_refs) is not tuple or len(self.evidence_refs) > 16:
            raise ValueError("Routing outcome evidence references are invalid")


@dataclass(frozen=True, slots=True)
class RoutingDecisionView:
    """Bounded explainability projection with no prompt or response content."""

    decision: RoutingDecisionRecord
    outcomes: tuple[RoutingDecisionOutcome, ...] = ()


class RoutingFitnessStoreError(RuntimeError):
    """Durable routing-fitness state is malformed or unavailable."""


def _format_time(value: datetime | None) -> str | None:
    return value.astimezone(UTC).isoformat() if value is not None else None


def _parse_time(value: object) -> datetime | None:
    return datetime.fromisoformat(str(value)) if value is not None else None


class SQLiteRoutingFitnessStore:
    """Durable bounded history for non-model route observations."""

    _SCHEMA_VERSION = 4
    _MIGRATION_NAME = "create_routing_fitness_observations"

    def __init__(self, database_path: Path) -> None:
        if not isinstance(database_path, Path):
            raise RoutingFitnessStoreError("Routing fitness database path is invalid")
        database_path.parent.mkdir(parents=True, exist_ok=True)
        self._path = database_path
        self._connection = sqlite3.connect(database_path, timeout=5.0, check_same_thread=False)
        self._connection.row_factory = sqlite3.Row
        self._connection.execute("PRAGMA foreign_keys = ON")
        self._connection.execute("PRAGMA busy_timeout = 5000")
        self._connection.execute("PRAGMA journal_mode = WAL")
        self._lock = RLock()
        try:
            self._integrity_check()
            self._migrate()
        except RoutingFitnessStoreError:
            self._connection.close()
            raise
        except sqlite3.DatabaseError as error:
            self._connection.close()
            raise RoutingFitnessStoreError("Routing fitness database is unavailable") from error

    @property
    def database_path(self) -> Path:
        return self._path

    def close(self) -> None:
        with self._lock:
            self._connection.close()

    def __enter__(self) -> SQLiteRoutingFitnessStore:
        return self

    def __exit__(self, _type: object, _value: object, _traceback: object) -> None:
        self.close()

    def _integrity_check(self) -> None:
        try:
            row = self._connection.execute("PRAGMA integrity_check").fetchone()
        except sqlite3.DatabaseError as error:
            raise RoutingFitnessStoreError("Routing fitness integrity check failed") from error
        if row is None or str(row[0]).casefold() != "ok":
            raise RoutingFitnessStoreError("Routing fitness database is corrupt")

    def _migrate(self) -> None:
        try:
            with self._connection:
                self._connection.execute(
                    "CREATE TABLE IF NOT EXISTS routing_fitness_schema "
                    "(version INTEGER PRIMARY KEY, name TEXT NOT NULL)"
                )
                rows = self._connection.execute(
                    "SELECT version, name FROM routing_fitness_schema"
                ).fetchall()
                versions = {int(row[0]): str(row[1]) for row in rows}
                if any(version > self._SCHEMA_VERSION for version in versions):
                    raise RoutingFitnessStoreError("Routing fitness database uses a future schema")
                if versions and versions.get(1) != self._MIGRATION_NAME:
                    raise RoutingFitnessStoreError("Routing fitness migration identity mismatch")
                if 2 in versions and versions[2] != "add_routing_fitness_breakers":
                    raise RoutingFitnessStoreError("Routing fitness migration identity mismatch")
                if 3 in versions and versions[3] != "add_routing_fitness_budget":
                    raise RoutingFitnessStoreError("Routing fitness migration identity mismatch")
                if 4 in versions and versions[4] != "add_routing_decisions":
                    raise RoutingFitnessStoreError("Routing fitness migration identity mismatch")
                if not versions:
                    self._connection.executescript(
                        """
                        CREATE TABLE routing_fitness_observations (
                            observation_id TEXT PRIMARY KEY,
                            route_identity TEXT NOT NULL,
                            candidate_kind TEXT NOT NULL,
                            task_class TEXT NOT NULL,
                            role TEXT NOT NULL,
                            observed_at TEXT NOT NULL,
                            operational_outcome TEXT NOT NULL,
                            semantic_outcome TEXT NOT NULL,
                            verification_source TEXT,
                            retry_count INTEGER NOT NULL,
                            failure_class TEXT,
                            latency_ms REAL,
                            monetary_cost REAL,
                            evidence_refs_json TEXT NOT NULL
                        );
                        CREATE INDEX routing_fitness_route_task
                            ON routing_fitness_observations(
                                route_identity, candidate_kind, task_class
                            );
                        INSERT INTO routing_fitness_schema(version, name)
                        VALUES (1, 'create_routing_fitness_observations');
                        """
                    )
                    versions[1] = "create_routing_fitness_observations"
                if 2 not in versions:
                    self._connection.executescript(
                        """
                        CREATE TABLE routing_fitness_breakers (
                            breaker_key TEXT PRIMARY KEY,
                            route_identity TEXT NOT NULL,
                            candidate_kind TEXT NOT NULL,
                            task_class TEXT NOT NULL,
                            role TEXT NOT NULL,
                            state TEXT NOT NULL,
                            qualifying_failures INTEGER NOT NULL,
                            window_started_at TEXT,
                            opened_at TEXT,
                            cooldown_until TEXT,
                            probe_claimed INTEGER NOT NULL
                        );
                        INSERT INTO routing_fitness_schema(version, name)
                        VALUES (2, 'add_routing_fitness_breakers');
                        """
                    )
                    versions[2] = "add_routing_fitness_breakers"
                if 3 not in versions:
                    self._connection.execute(
                        "ALTER TABLE routing_fitness_breakers ADD COLUMN "
                        "exploration_attempts INTEGER NOT NULL DEFAULT 0"
                    )
                    self._connection.execute(
                        "ALTER TABLE routing_fitness_breakers ADD COLUMN exploration_last_at TEXT"
                    )
                    self._connection.execute(
                        "INSERT INTO routing_fitness_schema(version, name) "
                        "VALUES (3, 'add_routing_fitness_budget')"
                    )
                if 4 not in versions:
                    self._connection.executescript(
                        """
                        CREATE TABLE routing_decisions (
                            decision_id TEXT PRIMARY KEY,
                            decided_at TEXT NOT NULL,
                            route_kind TEXT NOT NULL,
                            decision_json TEXT NOT NULL
                        );
                        CREATE TABLE routing_decision_outcomes (
                            outcome_id TEXT PRIMARY KEY,
                            decision_id TEXT NOT NULL,
                            observed_at TEXT NOT NULL,
                            executed_identity TEXT NOT NULL,
                            operational_outcome TEXT NOT NULL,
                            semantic_outcome TEXT NOT NULL,
                            rerouted INTEGER NOT NULL,
                            retry_count INTEGER NOT NULL,
                            evidence_refs_json TEXT NOT NULL,
                            FOREIGN KEY(decision_id) REFERENCES routing_decisions(decision_id)
                        );
                        CREATE INDEX routing_decision_outcomes_decision
                            ON routing_decision_outcomes(decision_id, observed_at, outcome_id);
                        INSERT INTO routing_fitness_schema(version, name)
                        VALUES (4, 'add_routing_decisions');
                        """
                    )
        except sqlite3.DatabaseError as error:
            raise RoutingFitnessStoreError("Routing fitness migration failed") from error

    def record(self, outcome: VerifiedRouteOutcome) -> bool:
        if not isinstance(outcome, VerifiedRouteOutcome):
            raise RoutingFitnessStoreError("Route outcome is malformed")
        values = (
            outcome.observation_id,
            outcome.route_identity,
            outcome.candidate_kind,
            outcome.task_class,
            outcome.role,
            outcome.observed_at.astimezone(UTC).isoformat(),
            outcome.operational_outcome,
            outcome.semantic_outcome.value,
            outcome.verification_source,
            outcome.retry_count,
            outcome.failure_class,
            outcome.latency_ms,
            outcome.monetary_cost,
            json.dumps(outcome.evidence_refs, separators=(",", ":")),
        )
        with self._lock:
            try:
                self._connection.execute(
                    """
                    INSERT INTO routing_fitness_observations(
                        observation_id, route_identity, candidate_kind, task_class,
                        role, observed_at, operational_outcome, semantic_outcome,
                        verification_source, retry_count, failure_class, latency_ms,
                        monetary_cost, evidence_refs_json
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    values,
                )
                self._connection.commit()
                return True
            except sqlite3.IntegrityError:
                self._connection.rollback()
                row = self._connection.execute(
                    "SELECT * FROM routing_fitness_observations WHERE observation_id = ?",
                    (outcome.observation_id,),
                ).fetchone()
                if row is None:
                    raise RoutingFitnessStoreError(
                        "Routing fitness duplicate was ambiguous"
                    ) from None
                existing = self._outcome_from_row(row)
                if not _same_attempt_facts(existing, outcome):
                    raise RoutingFitnessStoreError(
                        "Conflicting routing fitness observation is rejected"
                    ) from None
                return False
            except sqlite3.DatabaseError as error:
                self._connection.rollback()
                raise RoutingFitnessStoreError("Routing fitness observation failed") from error

    def observations(self) -> tuple[VerifiedRouteOutcome, ...]:
        with self._lock:
            try:
                rows = self._connection.execute(
                    "SELECT * FROM routing_fitness_observations "
                    "ORDER BY observed_at, observation_id"
                ).fetchall()
            except sqlite3.DatabaseError as error:
                raise RoutingFitnessStoreError("Routing fitness read failed") from error
        try:
            return tuple(self._outcome_from_row(row) for row in rows)
        except (KeyError, TypeError, ValueError, json.JSONDecodeError) as error:
            raise RoutingFitnessStoreError("Stored routing fitness is malformed") from error

    def load_breaker(self, key: RouteResilienceKey) -> CircuitSnapshot:
        with self._lock:
            row = self._connection.execute(
                "SELECT * FROM routing_fitness_breakers WHERE breaker_key = ?",
                (key.storage_key,),
            ).fetchone()
        if row is None:
            return CircuitSnapshot(key)
        try:
            return CircuitSnapshot(
                key=key,
                state=CircuitState(str(row["state"])),
                qualifying_failures=int(row["qualifying_failures"]),
                window_started_at=_parse_time(row["window_started_at"]),
                opened_at=_parse_time(row["opened_at"]),
                cooldown_until=_parse_time(row["cooldown_until"]),
                probe_claimed=bool(row["probe_claimed"]),
                exploration_attempts=int(row["exploration_attempts"]),
                exploration_last_at=_parse_time(row["exploration_last_at"]),
            )
        except (KeyError, TypeError, ValueError) as error:
            raise RoutingFitnessStoreError("Stored routing breaker is malformed") from error

    def save_breaker(self, snapshot: CircuitSnapshot) -> None:
        key = snapshot.key
        with self._lock:
            try:
                self._connection.execute(
                    """
                    INSERT INTO routing_fitness_breakers(
                        breaker_key, route_identity, candidate_kind, task_class, role,
                        state, qualifying_failures, window_started_at, opened_at,
                        cooldown_until, probe_claimed, exploration_attempts,
                        exploration_last_at
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    ON CONFLICT(breaker_key) DO UPDATE SET
                        state=excluded.state,
                        qualifying_failures=excluded.qualifying_failures,
                        window_started_at=excluded.window_started_at,
                        opened_at=excluded.opened_at,
                        cooldown_until=excluded.cooldown_until,
                        probe_claimed=excluded.probe_claimed,
                        exploration_attempts=excluded.exploration_attempts,
                        exploration_last_at=excluded.exploration_last_at
                    """,
                    (
                        key.storage_key,
                        key.route_identity,
                        key.candidate_kind,
                        key.task_class,
                        key.role,
                        snapshot.state.value,
                        snapshot.qualifying_failures,
                        _format_time(snapshot.window_started_at),
                        _format_time(snapshot.opened_at),
                        _format_time(snapshot.cooldown_until),
                        int(snapshot.probe_claimed),
                        snapshot.exploration_attempts,
                        _format_time(snapshot.exploration_last_at),
                    ),
                )
                self._connection.commit()
            except sqlite3.DatabaseError as error:
                self._connection.rollback()
                raise RoutingFitnessStoreError("Routing breaker persistence failed") from error

    def record_decision(self, decision: RoutingDecisionRecord) -> bool:
        if not isinstance(decision, RoutingDecisionRecord):
            raise RoutingFitnessStoreError("Routing decision is malformed")
        payload = json.dumps(
            {
                "decision_id": decision.decision_id,
                "decided_at": decision.decided_at.astimezone(UTC).isoformat(),
                "route_kind": decision.route_kind,
                "selected_identity": decision.selected_identity,
                "role": decision.role,
                "task_class": decision.task_class,
                "policy": decision.policy,
                "privacy_classification": decision.privacy_classification,
                "required_capabilities": decision.required_capabilities,
                "strategy": decision.strategy,
                "alternative_identities": decision.alternative_identities,
                "exclusions": decision.exclusions,
                "quality_score": decision.quality_score,
                "sample_count": decision.sample_count,
                "evidence_sufficiency": decision.evidence_sufficiency,
                "lkgr": decision.lkgr,
                "breaker_state": decision.breaker_state,
                "exploration": decision.exploration,
                "resource_status": decision.resource_status,
                "protected_headroom": decision.protected_headroom,
                "affinity_current": decision.affinity_current,
                "affinity_warm": decision.affinity_warm,
                "switching_cost_ms": decision.switching_cost_ms,
                "predicted_latency_ms": decision.predicted_latency_ms,
                "predicted_cost": decision.predicted_cost,
                "fallback_identities": decision.fallback_identities,
                "evidence_refs": decision.evidence_refs,
                "fusion_strategy": decision.fusion_strategy,
            },
            separators=(",", ":"),
        )
        with self._lock:
            try:
                self._connection.execute(
                    "INSERT INTO routing_decisions("
                    "decision_id, decided_at, route_kind, decision_json) "
                    "VALUES (?, ?, ?, ?)",
                    (
                        decision.decision_id,
                        decision.decided_at.astimezone(UTC).isoformat(),
                        decision.route_kind,
                        payload,
                    ),
                )
                self._connection.commit()
                return True
            except sqlite3.IntegrityError:
                self._connection.rollback()
                row = self._connection.execute(
                    "SELECT decision_json FROM routing_decisions WHERE decision_id = ?",
                    (decision.decision_id,),
                ).fetchone()
                if row is None:
                    raise RoutingFitnessStoreError(
                        "Routing decision duplicate was ambiguous"
                    ) from None
                existing = self._decision_from_payload(str(row[0]))
                if existing != decision:
                    raise RoutingFitnessStoreError(
                        "Conflicting routing decision replay is rejected"
                    ) from None
                return False
            except sqlite3.DatabaseError as error:
                self._connection.rollback()
                raise RoutingFitnessStoreError("Routing decision persistence failed") from error

    def decision(self, decision_id: str) -> RoutingDecisionRecord | None:
        with self._lock:
            row = self._connection.execute(
                "SELECT decision_json FROM routing_decisions WHERE decision_id = ?",
                (decision_id,),
            ).fetchone()
        return None if row is None else self._decision_from_payload(str(row[0]))

    def decisions(self, *, limit: int = 128) -> tuple[RoutingDecisionRecord, ...]:
        if type(limit) is not int or not 1 <= limit <= 512:
            raise RoutingFitnessStoreError("Routing decision limit is invalid")
        with self._lock:
            rows = self._connection.execute(
                "SELECT decision_json FROM routing_decisions "
                "ORDER BY decided_at, decision_id LIMIT ?",
                (limit,),
            ).fetchall()
        return tuple(self._decision_from_payload(str(row[0])) for row in rows)

    def record_decision_outcome(self, outcome: RoutingDecisionOutcome) -> bool:
        if not isinstance(outcome, RoutingDecisionOutcome):
            raise RoutingFitnessStoreError("Routing decision outcome is malformed")
        with self._lock:
            try:
                if (
                    self._connection.execute(
                        "SELECT 1 FROM routing_decisions WHERE decision_id = ?",
                        (outcome.decision_id,),
                    ).fetchone()
                    is None
                ):
                    raise RoutingFitnessStoreError("Routing decision is not durable")
                self._connection.execute(
                    "INSERT INTO routing_decision_outcomes("
                    "outcome_id, decision_id, observed_at, executed_identity, "
                    "operational_outcome, semantic_outcome, rerouted, retry_count, "
                    "evidence_refs_json) "
                    "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
                    (
                        outcome.outcome_id,
                        outcome.decision_id,
                        outcome.observed_at.astimezone(UTC).isoformat(),
                        outcome.executed_identity,
                        outcome.operational_outcome,
                        outcome.semantic_outcome.value,
                        int(outcome.rerouted),
                        outcome.retry_count,
                        json.dumps(outcome.evidence_refs, separators=(",", ":")),
                    ),
                )
                self._connection.commit()
                return True
            except sqlite3.IntegrityError:
                self._connection.rollback()
                row = self._connection.execute(
                    "SELECT * FROM routing_decision_outcomes WHERE outcome_id = ?",
                    (outcome.outcome_id,),
                ).fetchone()
                if row is None:
                    raise RoutingFitnessStoreError(
                        "Routing outcome duplicate was ambiguous"
                    ) from None
                existing = self._outcome_from_decision_row(row)
                if existing != outcome:
                    raise RoutingFitnessStoreError(
                        "Conflicting routing outcome replay is rejected"
                    ) from None
                return False
            except RoutingFitnessStoreError:
                self._connection.rollback()
                raise
            except sqlite3.DatabaseError as error:
                self._connection.rollback()
                raise RoutingFitnessStoreError("Routing outcome persistence failed") from error

    def decision_outcomes(self, decision_id: str) -> tuple[RoutingDecisionOutcome, ...]:
        with self._lock:
            rows = self._connection.execute(
                "SELECT * FROM routing_decision_outcomes WHERE decision_id = "
                "? ORDER BY observed_at, outcome_id",
                (decision_id,),
            ).fetchall()
        return tuple(self._outcome_from_decision_row(row) for row in rows)

    def decision_view(self, decision_id: str) -> RoutingDecisionView | None:
        record = self.decision(decision_id)
        return (
            None
            if record is None
            else RoutingDecisionView(record, self.decision_outcomes(decision_id))
        )

    @staticmethod
    def _decision_from_payload(payload: str) -> RoutingDecisionRecord:
        try:
            values = json.loads(payload)
            if not isinstance(values, dict):
                raise ValueError("Routing decision payload is not an object")
            values["decided_at"] = datetime.fromisoformat(str(values["decided_at"]))
            values["required_capabilities"] = tuple(values["required_capabilities"])
            values["alternative_identities"] = tuple(values["alternative_identities"])
            values["exclusions"] = tuple(tuple(item) for item in values["exclusions"])
            values["fallback_identities"] = tuple(values["fallback_identities"])
            values["evidence_refs"] = tuple(values["evidence_refs"])
            return RoutingDecisionRecord(**values)
        except (KeyError, TypeError, ValueError, json.JSONDecodeError) as error:
            raise RoutingFitnessStoreError("Stored routing decision is malformed") from error

    @staticmethod
    def _outcome_from_decision_row(row: sqlite3.Row) -> RoutingDecisionOutcome:
        try:
            refs = json.loads(str(row["evidence_refs_json"]))
            if not isinstance(refs, list):
                raise ValueError("Routing outcome references are malformed")
            return RoutingDecisionOutcome(
                outcome_id=str(row["outcome_id"]),
                decision_id=str(row["decision_id"]),
                observed_at=datetime.fromisoformat(str(row["observed_at"])),
                executed_identity=str(row["executed_identity"]),
                operational_outcome=str(row["operational_outcome"]),
                semantic_outcome=SemanticOutcome(str(row["semantic_outcome"])),
                rerouted=bool(row["rerouted"]),
                retry_count=int(row["retry_count"]),
                evidence_refs=tuple(str(item) for item in refs),
            )
        except (KeyError, TypeError, ValueError, json.JSONDecodeError) as error:
            raise RoutingFitnessStoreError("Stored routing outcome is malformed") from error

    @staticmethod
    def _outcome_from_row(row: sqlite3.Row) -> VerifiedRouteOutcome:
        raw_refs = json.loads(str(row["evidence_refs_json"]))
        if not isinstance(raw_refs, list):
            raise ValueError("Stored routing evidence references are malformed")
        return VerifiedRouteOutcome(
            observation_id=str(row["observation_id"]),
            route_identity=str(row["route_identity"]),
            candidate_kind=str(row["candidate_kind"]),
            task_class=str(row["task_class"]),
            role=str(row["role"]),
            observed_at=datetime.fromisoformat(str(row["observed_at"])),
            operational_outcome=str(row["operational_outcome"]),
            semantic_outcome=SemanticOutcome(str(row["semantic_outcome"])),
            verification_source=(
                str(row["verification_source"]) if row["verification_source"] is not None else None
            ),
            retry_count=int(row["retry_count"]),
            failure_class=(str(row["failure_class"]) if row["failure_class"] is not None else None),
            latency_ms=(float(row["latency_ms"]) if row["latency_ms"] is not None else None),
            monetary_cost=(
                float(row["monetary_cost"]) if row["monetary_cost"] is not None else None
            ),
            evidence_refs=tuple(str(item) for item in raw_refs),
        )


def _same_attempt_facts(existing: VerifiedRouteOutcome, incoming: VerifiedRouteOutcome) -> bool:
    """Treat callback-clock drift as a replay, not contradictory evidence."""

    return replace(existing, observed_at=incoming.observed_at) == incoming


@dataclass(frozen=True, slots=True)
class RouteFitnessView:
    route_identity: str
    candidate_kind: str
    task_class: str
    sample_count: int
    operational_success_count: int
    semantic_verified_success_count: int
    semantic_verified_failure_count: int
    unknown_outcome_count: int
    unverified_count: int
    retry_count: int
    last_observed_at: datetime | None
    evidence: FitnessEvidence
    mean_latency_ms: float | None

    @property
    def operational_success_rate(self) -> float | None:
        return self.operational_success_count / self.sample_count if self.sample_count else None

    @property
    def verified_success_rate(self) -> float | None:
        return (
            self.semantic_verified_success_count / self.sample_count if self.sample_count else None
        )

    @property
    def failure_rate(self) -> float | None:
        return (
            self.semantic_verified_failure_count / self.sample_count if self.sample_count else None
        )

    def meets_quality_floor(self, minimum_verified_reliability: float, now: datetime) -> bool:
        if self.evidence is not FitnessEvidence.SUFFICIENT:
            return False
        if self.last_observed_at is None or now - self.last_observed_at > timedelta(days=30):
            return False
        rate = self.verified_success_rate
        return rate is not None and rate >= minimum_verified_reliability


class RoutingResilienceService:
    """Durable route-scoped LKGR and circuit-breaker policy."""

    _NON_ATTRIBUTABLE = frozenset(
        {"permission_denied", "policy_block", "privacy_block", "cancelled", "unknown_outcome"}
    )
    _QUALIFYING_OPERATIONAL = frozenset(
        {
            "transient_failure",
            "deterministic_failure",
            "provider_unavailable",
            "timeout",
            "route_unavailable",
            "execution_route_unavailable",
            "execution_route_kind_unsupported",
            "resource_failure",
        }
    )

    def __init__(
        self,
        fitness: RoutingFitnessProjection,
        *,
        store: SQLiteRoutingFitnessStore | None = None,
        clock: Callable[[], datetime] | None = None,
        policy: ResiliencePolicy | None = None,
    ) -> None:
        if not isinstance(fitness, RoutingFitnessProjection):
            raise TypeError("Routing fitness projection is invalid")
        if store is not None and not isinstance(store, SQLiteRoutingFitnessStore):
            raise TypeError("Routing fitness store is invalid")
        self._fitness = fitness
        self._store = store
        self._clock = clock or fitness.now
        self._policy = policy or ResiliencePolicy()
        self._lock = RLock()
        self._breakers: dict[str, CircuitSnapshot] = {}

    def key(
        self, route_identity: str, candidate_kind: str, task_class: str, role: str
    ) -> RouteResilienceKey:
        return RouteResilienceKey(route_identity, candidate_kind, task_class, role)

    def snapshot(self, key: RouteResilienceKey) -> CircuitSnapshot:
        with self._lock:
            snapshot = self._load(key)
            if (
                snapshot.state is CircuitState.OPEN
                and snapshot.cooldown_until is not None
                and self._clock() >= snapshot.cooldown_until
            ):
                snapshot = replace(snapshot, state=CircuitState.HALF_OPEN, probe_claimed=False)
                self._save(snapshot)
            return snapshot

    def admit(self, key: RouteResilienceKey) -> tuple[bool, bool]:
        """Return (allowed, is_half_open_probe), claiming at most one probe."""

        with self._lock:
            snapshot = self.snapshot(key)
            if snapshot.state is CircuitState.CLOSED:
                return True, False
            if snapshot.state is CircuitState.OPEN:
                return False, False
            if snapshot.probe_claimed:
                return False, False
            self._save(replace(snapshot, probe_claimed=True))
            return True, True

    def is_lkgr(self, key: RouteResilienceKey) -> bool:
        if self.snapshot(key).state is CircuitState.OPEN:
            return False
        view = self._fitness.view(
            key.route_identity,
            key.task_class,
            candidate_kind=key.candidate_kind,
            now=self._clock(),
        )
        return (
            view.evidence is FitnessEvidence.SUFFICIENT
            and view.sample_count >= self._policy.lkgr_min_samples
            and (view.verified_success_rate or 0.0) >= self._policy.lkgr_min_verified_reliability
        )

    def exploration_allowed(
        self,
        key: RouteResilienceKey,
        *,
        allow_exploration: bool,
        high_consequence: bool,
        verification_available: bool,
    ) -> bool:
        if not allow_exploration or high_consequence or not verification_available:
            return False
        if self.snapshot(key).state is not CircuitState.CLOSED:
            return False
        evidence = self._fitness.view(
            key.route_identity,
            key.task_class,
            candidate_kind=key.candidate_kind,
            now=self._clock(),
        ).evidence
        return evidence in {FitnessEvidence.UNKNOWN, FitnessEvidence.INSUFFICIENT}

    def claim_exploration(
        self,
        key: RouteResilienceKey,
        *,
        allow_exploration: bool,
        high_consequence: bool,
        verification_available: bool,
    ) -> bool:
        if not self.exploration_allowed(
            key,
            allow_exploration=allow_exploration,
            high_consequence=high_consequence,
            verification_available=verification_available,
        ):
            return False
        with self._lock:
            snapshot = self._load(key)
            now = self._clock()
            if snapshot.exploration_attempts >= self._policy.exploration_max_attempts:
                return False
            if (
                snapshot.exploration_last_at is not None
                and now - snapshot.exploration_last_at < self._policy.cooldown
            ):
                return False
            self._save(
                replace(
                    snapshot,
                    exploration_attempts=snapshot.exploration_attempts + 1,
                    exploration_last_at=now,
                )
            )
            return True

    def record(
        self,
        key: RouteResilienceKey,
        *,
        operational_outcome: str,
        semantic_outcome: SemanticOutcome,
        failure_class: str | None = None,
    ) -> None:
        with self._lock:
            now = self._clock()
            snapshot = self.snapshot(key)
            if semantic_outcome is SemanticOutcome.VERIFIED_SUCCESS:
                self._save(CircuitSnapshot(key))
                return
            if snapshot.state is CircuitState.HALF_OPEN:
                self._save(self._opened(snapshot, now))
                return
            if semantic_outcome is SemanticOutcome.UNKNOWN:
                return
            failure = (failure_class or operational_outcome).casefold()
            if failure in self._NON_ATTRIBUTABLE:
                return
            qualifying = semantic_outcome is SemanticOutcome.VERIFIED_FAILURE or failure in (
                self._QUALIFYING_OPERATIONAL
            )
            if not qualifying:
                return
            window_start = snapshot.window_started_at
            count = snapshot.qualifying_failures
            if window_start is None or now - window_start > self._policy.failure_window:
                window_start, count = now, 0
            updated = replace(
                snapshot,
                qualifying_failures=count + 1,
                window_started_at=window_start,
            )
            if updated.qualifying_failures >= self._policy.failure_threshold:
                updated = self._opened(updated, now)
            self._save(updated)

    def _opened(self, snapshot: CircuitSnapshot, now: datetime) -> CircuitSnapshot:
        return replace(
            snapshot,
            state=CircuitState.OPEN,
            opened_at=now,
            cooldown_until=now + self._policy.cooldown,
            probe_claimed=False,
        )

    def _load(self, key: RouteResilienceKey) -> CircuitSnapshot:
        if key.storage_key not in self._breakers:
            self._breakers[key.storage_key] = (
                self._store.load_breaker(key) if self._store is not None else CircuitSnapshot(key)
            )
        return self._breakers[key.storage_key]

    def _save(self, snapshot: CircuitSnapshot) -> None:
        self._breakers[snapshot.key.storage_key] = snapshot
        if self._store is not None:
            self._store.save_breaker(snapshot)


class RoutingFitnessProjection:
    """Fitness view backed by durable observations or an explicitly ephemeral map."""

    def __init__(
        self,
        *,
        clock: Callable[[], datetime] | None = None,
        store: SQLiteRoutingFitnessStore | None = None,
    ) -> None:
        self._clock = clock or (lambda: datetime.now(UTC))
        if store is not None and not isinstance(store, SQLiteRoutingFitnessStore):
            raise TypeError("Routing fitness store is invalid")
        self._store = store
        self._lock = RLock()
        self._observations: dict[str, VerifiedRouteOutcome] = (
            {item.observation_id: item for item in store.observations()}
            if store is not None
            else {}
        )

    def now(self) -> datetime:
        return self._clock()

    def record(self, outcome: VerifiedRouteOutcome) -> bool:
        if not isinstance(outcome, VerifiedRouteOutcome):
            raise ValueError("Route outcome is malformed")
        if self._store is not None:
            inserted = self._store.record(outcome)
            if not inserted:
                return False
        with self._lock:
            if outcome.observation_id in self._observations:
                if not _same_attempt_facts(self._observations[outcome.observation_id], outcome):
                    raise RoutingFitnessStoreError(
                        "Conflicting routing fitness observation is rejected"
                    )
                return False
            self._observations[outcome.observation_id] = outcome
            return True

    def record_planning_step(
        self,
        task: PlanningTask,
        step: PlanningStep,
        execution: StepExecutionResult,
        verification: StepVerification | None,
    ) -> bool:
        """Record only trusted PlanningEngine execution/verification facts."""

        if verification is None:
            semantic = (
                SemanticOutcome.UNKNOWN
                if execution.status.value == "unknown_outcome"
                else SemanticOutcome.UNVERIFIED
            )
            source = None
        else:
            semantic = (
                SemanticOutcome.VERIFIED_SUCCESS
                if verification.succeeded
                else SemanticOutcome.VERIFIED_FAILURE
            )
            source = "planning.step_verifier"
        outcome = VerifiedRouteOutcome(
            observation_id=f"{task.task_id}:{step.step_id}:{step.attempts}",
            route_identity=step.tool_id,
            candidate_kind="tool",
            task_class=step.capability,
            role="orchestration",
            observed_at=self._clock(),
            operational_outcome=execution.status.value,
            semantic_outcome=semantic,
            verification_source=source,
            retry_count=step.attempts,
            failure_class=execution.error_code,
            evidence_refs=(f"task:{task.task_id}", f"step:{step.step_id}"),
        )
        return self.record(outcome)

    def view(
        self,
        route_identity: str,
        task_class: str,
        *,
        candidate_kind: str = "tool",
        now: datetime | None = None,
    ) -> RouteFitnessView:
        with self._lock:
            observations = tuple(
                item
                for item in self._observations.values()
                if item.route_identity == route_identity
                and item.task_class == task_class
                and item.candidate_kind == candidate_kind
            )
        latest = max((item.observed_at for item in observations), default=None)
        sample_count = len(observations)
        if not observations:
            evidence = FitnessEvidence.UNKNOWN
        elif sample_count < 3:
            evidence = FitnessEvidence.INSUFFICIENT
        else:
            reference = now or self._clock()
            evidence = (
                FitnessEvidence.STALE
                if latest is not None and reference - latest > timedelta(days=30)
                else FitnessEvidence.SUFFICIENT
            )
        latencies = [item.latency_ms for item in observations if item.latency_ms is not None]
        return RouteFitnessView(
            route_identity,
            candidate_kind,
            task_class,
            sample_count,
            sum(item.operational_outcome == "succeeded" for item in observations),
            sum(item.semantic_outcome is SemanticOutcome.VERIFIED_SUCCESS for item in observations),
            sum(item.semantic_outcome is SemanticOutcome.VERIFIED_FAILURE for item in observations),
            sum(item.semantic_outcome is SemanticOutcome.UNKNOWN for item in observations),
            sum(item.semantic_outcome is SemanticOutcome.UNVERIFIED for item in observations),
            sum(item.retry_count for item in observations),
            latest,
            evidence,
            sum(latencies) / len(latencies) if latencies else None,
        )


__all__ = [
    "CircuitSnapshot",
    "CircuitState",
    "FitnessEvidence",
    "ResiliencePolicy",
    "RouteFitnessView",
    "RouteResilienceKey",
    "RoutingDecisionOutcome",
    "RoutingDecisionRecord",
    "RoutingDecisionView",
    "RoutingFitnessProjection",
    "RoutingResilienceService",
    "RoutingFitnessStoreError",
    "SemanticOutcome",
    "SQLiteRoutingFitnessStore",
    "VerifiedRouteOutcome",
]
