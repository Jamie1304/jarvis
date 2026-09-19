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


class RoutingFitnessStoreError(RuntimeError):
    """Durable routing-fitness state is malformed or unavailable."""


class SQLiteRoutingFitnessStore:
    """Durable bounded history for non-model route observations."""

    _SCHEMA_VERSION = 1
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
    "FitnessEvidence",
    "RouteFitnessView",
    "RoutingFitnessProjection",
    "RoutingFitnessStoreError",
    "SemanticOutcome",
    "SQLiteRoutingFitnessStore",
    "VerifiedRouteOutcome",
]
