"""Durable, restart-safe state for the canonical component repair loop.

This module contains persistence only.  It deliberately has no callback or
executable-code fields: bindings remain owned by the application composition
root and are re-established on every process start.
"""

from __future__ import annotations

import hashlib
import sqlite3
import threading
from dataclasses import dataclass, replace
from datetime import UTC, datetime
from enum import StrEnum
from pathlib import Path
from typing import Any, cast
from uuid import UUID, uuid4


class RepairStoreError(RuntimeError):
    """The repair store is corrupt, unavailable, or contains invalid state."""


class RepairCaseStatus(StrEnum):
    DIAGNOSIS_PENDING = "diagnosis_pending"
    AUTHORITY_PENDING = "authority_pending"
    PERMISSION_REQUIRED = "permission_required"
    EFFECT_IN_PROGRESS = "effect_in_progress"
    VERIFICATION_PENDING = "verification_pending"
    VERIFIED_REPAIRED = "verified_repaired"
    DEGRADED_FALLBACK = "degraded_fallback"
    FAILED = "failed"
    QUARANTINED = "quarantined"


_ACTIVE = frozenset(
    {
        RepairCaseStatus.DIAGNOSIS_PENDING,
        RepairCaseStatus.AUTHORITY_PENDING,
        RepairCaseStatus.PERMISSION_REQUIRED,
        RepairCaseStatus.EFFECT_IN_PROGRESS,
        RepairCaseStatus.VERIFICATION_PENDING,
    }
)
_TERMINAL = frozenset(
    {
        RepairCaseStatus.VERIFIED_REPAIRED,
        RepairCaseStatus.DEGRADED_FALLBACK,
        RepairCaseStatus.FAILED,
        RepairCaseStatus.QUARANTINED,
    }
)


def _text(value: object, name: str, limit: int = 512, *, allow_empty: bool = False) -> str:
    if (
        type(value) is not str
        or len(value) > limit
        or "\x00" in value
        or (not allow_empty and not value.strip())
    ):
        raise RepairStoreError(f"{name} is malformed")
    return value.strip()


def _time(value: datetime, name: str) -> datetime:
    if not isinstance(value, datetime) or value.tzinfo is None:
        raise RepairStoreError(f"{name} must be timezone-aware")
    return value.astimezone(UTC)


def _iso(value: datetime) -> str:
    return _time(value, "timestamp").isoformat()


def _parse_time(value: object, name: str) -> datetime:
    if type(value) is not str:
        raise RepairStoreError(f"{name} is malformed")
    try:
        return _time(datetime.fromisoformat(value), name)
    except (TypeError, ValueError) as error:
        raise RepairStoreError(f"{name} is malformed") from error


@dataclass(frozen=True, slots=True)
class RepairCase:
    case_id: UUID
    case_key: str
    component_id: str
    owner: str
    failure_code: str | None
    component_version: str | None
    opened_at: datetime
    status: RepairCaseStatus
    attempt_budget: int = 2
    attempt_count: int = 0
    latest_diagnosis: str | None = None
    selected_action: str | None = None
    effect_outcome: str | None = None
    verification_reference: str | None = None
    fallback: str | None = None
    terminal_reason: str | None = None
    updated_at: datetime | None = None

    def __post_init__(self) -> None:
        if not isinstance(self.case_id, UUID):
            raise RepairStoreError("Repair case ID is malformed")
        _text(self.case_key, "Repair case key", 128)
        _text(self.component_id, "Repair component", 256)
        _text(self.owner, "Repair owner", 64)
        if self.failure_code is not None:
            _text(self.failure_code, "Repair failure code", 256)
        if self.component_version is not None:
            _text(self.component_version, "Repair component version", 256)
        if not isinstance(self.status, RepairCaseStatus):
            raise RepairStoreError("Repair case status is malformed")
        if type(self.attempt_budget) is not int or not 1 <= self.attempt_budget <= 3:
            raise RepairStoreError("Repair attempt budget is malformed")
        if type(self.attempt_count) is not int or not 0 <= self.attempt_count <= 3:
            raise RepairStoreError("Repair attempt count is malformed")
        for value, name in (
            (self.latest_diagnosis, "diagnosis"),
            (self.selected_action, "action"),
            (self.effect_outcome, "effect outcome"),
            (self.verification_reference, "verification reference"),
            (self.fallback, "fallback"),
            (self.terminal_reason, "terminal reason"),
        ):
            if value is not None:
                _text(value, name, 2_000)
        object.__setattr__(self, "opened_at", _time(self.opened_at, "opened_at"))
        if self.updated_at is None:
            object.__setattr__(self, "updated_at", self.opened_at)
        else:
            object.__setattr__(self, "updated_at", _time(self.updated_at, "updated_at"))


@dataclass(frozen=True, slots=True)
class RepairAttemptRecord:
    case_id: UUID
    number: int
    state: str
    outcome: str | None
    detail: str
    started_at: datetime
    finished_at: datetime | None = None
    verification_reference: str | None = None

    def __post_init__(self) -> None:
        if not isinstance(self.case_id, UUID) or type(self.number) is not int or self.number < 1:
            raise RepairStoreError("Repair attempt identity is malformed")
        _text(self.state, "Repair attempt state", 64)
        if self.outcome is not None:
            _text(self.outcome, "Repair attempt outcome", 64)
        _text(self.detail, "Repair attempt detail", 2_000)
        _time(self.started_at, "attempt start")
        if self.finished_at is not None:
            _time(self.finished_at, "attempt finish")
        if self.verification_reference is not None:
            _text(self.verification_reference, "attempt verification", 256)


def repair_case_key(
    component_id: str,
    owner: str,
    failure_code: str | None,
    component_version: str | None = None,
) -> str:
    """Build an opaque stable key from trusted facts, never model prose."""

    material = "\x1f".join(
        (
            _text(component_id, "component", 256),
            _text(owner, "owner", 64),
            failure_code or "<none>",
            component_version or "<none>",
        )
    ).encode()
    return hashlib.sha256(material).hexdigest()


class SQLiteRepairStore:
    """Bounded SQLite owner for repair cases and factual attempt history."""

    _SCHEMA_VERSION = 1

    def __init__(self, path: Path) -> None:
        if not isinstance(path, Path):
            raise RepairStoreError("Repair store path is malformed")
        self._path = path
        self._lock = threading.RLock()
        self._connection: sqlite3.Connection | None = None
        try:
            path.parent.mkdir(parents=True, exist_ok=True)
            self._connection = sqlite3.connect(path, check_same_thread=False)
            self._conn.row_factory = sqlite3.Row
            self._conn.execute("PRAGMA foreign_keys=ON")
            self._conn.execute("PRAGMA busy_timeout=5000")
            self._conn.execute("PRAGMA journal_mode=WAL")
            self._migrate()
            self._integrity_check()
            self.reconcile_startup()
        except (OSError, sqlite3.DatabaseError, RepairStoreError) as error:
            try:
                if self._connection is not None:
                    self._connection.close()
            except Exception:
                pass
            if isinstance(error, RepairStoreError):
                raise
            raise RepairStoreError("Repair store is unavailable") from error

    @property
    def database_path(self) -> Path:
        return self._path

    @property
    def _conn(self) -> sqlite3.Connection:
        if self._connection is None:
            raise RepairStoreError("Repair store is unavailable")
        return self._connection

    def _migrate(self) -> None:
        self._conn.execute(
            "CREATE TABLE IF NOT EXISTS repair_schema "
            "(version INTEGER PRIMARY KEY, name TEXT NOT NULL)"
        )
        rows = self._conn.execute("SELECT version, name FROM repair_schema").fetchall()
        versions = {int(row["version"]): str(row["name"]) for row in rows}
        if any(version > self._SCHEMA_VERSION for version in versions):
            raise RepairStoreError("Repair store has a future schema")
        if not versions:
            self._conn.executescript(
                """
                CREATE TABLE repair_cases (
                    case_id TEXT PRIMARY KEY,
                    case_key TEXT NOT NULL,
                    component_id TEXT NOT NULL,
                    owner TEXT NOT NULL,
                    failure_code TEXT,
                    component_version TEXT,
                    opened_at TEXT NOT NULL,
                    status TEXT NOT NULL,
                    attempt_budget INTEGER NOT NULL,
                    attempt_count INTEGER NOT NULL,
                    latest_diagnosis TEXT,
                    selected_action TEXT,
                    effect_outcome TEXT,
                    verification_reference TEXT,
                    fallback TEXT,
                    terminal_reason TEXT,
                    updated_at TEXT NOT NULL
                );
                CREATE INDEX repair_cases_key ON repair_cases(case_key, updated_at, case_id);
                CREATE TABLE repair_attempts (
                    case_id TEXT NOT NULL REFERENCES repair_cases(case_id) ON DELETE CASCADE,
                    number INTEGER NOT NULL,
                    state TEXT NOT NULL,
                    outcome TEXT,
                    detail TEXT NOT NULL,
                    started_at TEXT NOT NULL,
                    finished_at TEXT,
                    verification_reference TEXT,
                    PRIMARY KEY(case_id, number)
                );
                """
            )
            self._conn.execute(
                "INSERT INTO repair_schema(version, name) VALUES (?, ?)",
                (self._SCHEMA_VERSION, "repair-cases-v1"),
            )
            self._conn.commit()
        elif versions.get(1) != "repair-cases-v1":
            raise RepairStoreError("Repair store migration identity mismatch")

    def _integrity_check(self) -> None:
        row = self._conn.execute("PRAGMA integrity_check").fetchone()
        if row is None or str(row[0]).casefold() != "ok":
            raise RepairStoreError("Repair store is corrupt")

    def open_case(
        self,
        *,
        component_id: str,
        owner: str,
        failure_code: str | None,
        component_version: str | None,
        attempt_budget: int,
        now: datetime,
    ) -> tuple[RepairCase, bool]:
        key = repair_case_key(component_id, owner, failure_code, component_version)
        with self._lock:
            row = self._conn.execute(
                "SELECT * FROM repair_cases WHERE case_key=? "
                "ORDER BY updated_at DESC, case_id DESC LIMIT 1",
                (key,),
            ).fetchone()
            if row is not None:
                existing = self._case(row)
                if existing.status in _ACTIVE or existing.status is RepairCaseStatus.QUARANTINED:
                    return existing, False
            case = RepairCase(
                uuid4(),
                key,
                component_id,
                owner,
                failure_code,
                component_version,
                now,
                RepairCaseStatus.DIAGNOSIS_PENDING,
                attempt_budget,
            )
            self._write_case(case)
            return case, True

    def save_case(self, case: RepairCase) -> RepairCase:
        if not isinstance(case, RepairCase):
            raise RepairStoreError("Repair case is malformed")
        with self._lock:
            self._write_case(case)
        return case

    def update(self, case: RepairCase, **changes: object) -> RepairCase:
        updated = cast(
            RepairCase,
            replace(cast(Any, case), **changes, updated_at=datetime.now(UTC)),
        )
        return self.save_case(updated)

    def load(self, case_id: UUID) -> RepairCase | None:
        if not isinstance(case_id, UUID):
            raise RepairStoreError("Repair case ID is malformed")
        with self._lock:
            row = self._conn.execute(
                "SELECT * FROM repair_cases WHERE case_id=?", (str(case_id),)
            ).fetchone()
        return None if row is None else self._case(row)

    def latest(self, case_key: str) -> RepairCase | None:
        _text(case_key, "Repair case key", 128)
        with self._lock:
            row = self._conn.execute(
                "SELECT * FROM repair_cases WHERE case_key=? "
                "ORDER BY updated_at DESC, case_id DESC LIMIT 1",
                (case_key,),
            ).fetchone()
        return None if row is None else self._case(row)

    def cases(self, *, limit: int = 64) -> tuple[RepairCase, ...]:
        if type(limit) is not int or not 1 <= limit <= 256:
            raise RepairStoreError("Repair case read bound is malformed")
        with self._lock:
            rows = self._conn.execute(
                "SELECT * FROM repair_cases ORDER BY updated_at DESC, case_id DESC LIMIT ?",
                (limit,),
            ).fetchall()
        return tuple(self._case(row) for row in rows)

    def save_attempt(self, attempt: RepairAttemptRecord) -> None:
        if not isinstance(attempt, RepairAttemptRecord):
            raise RepairStoreError("Repair attempt is malformed")
        with self._lock:
            try:
                self._conn.execute(
                    "INSERT OR REPLACE INTO repair_attempts "
                    "(case_id, number, state, outcome, detail, started_at, finished_at, "
                    "verification_reference) "
                    "VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
                    (
                        str(attempt.case_id),
                        attempt.number,
                        attempt.state,
                        attempt.outcome,
                        attempt.detail,
                        _iso(attempt.started_at),
                        None if attempt.finished_at is None else _iso(attempt.finished_at),
                        attempt.verification_reference,
                    ),
                )
                self._conn.commit()
            except sqlite3.DatabaseError as error:
                self._conn.rollback()
                raise RepairStoreError("Repair attempt could not be stored") from error

    def attempts(self, case_id: UUID) -> tuple[RepairAttemptRecord, ...]:
        with self._lock:
            rows = self._conn.execute(
                "SELECT * FROM repair_attempts WHERE case_id=? ORDER BY number", (str(case_id),)
            ).fetchall()
        return tuple(
            RepairAttemptRecord(
                UUID(str(row["case_id"])),
                int(row["number"]),
                str(row["state"]),
                None if row["outcome"] is None else str(row["outcome"]),
                str(row["detail"]),
                _parse_time(row["started_at"], "attempt start"),
                None
                if row["finished_at"] is None
                else _parse_time(row["finished_at"], "attempt finish"),
                None
                if row["verification_reference"] is None
                else str(row["verification_reference"]),
            )
            for row in rows
        )

    def reconcile_startup(self) -> tuple[RepairCase, ...]:
        """Quarantine in-flight effects before any application callback binds."""

        reconciled: list[RepairCase] = []
        with self._lock:
            rows = self._conn.execute(
                "SELECT * FROM repair_cases WHERE status=?",
                (RepairCaseStatus.EFFECT_IN_PROGRESS.value,),
            ).fetchall()
            for row in rows:
                current = self._case(row)
                updated = replace(
                    current,
                    status=RepairCaseStatus.QUARANTINED,
                    effect_outcome="unknown_outcome",
                    terminal_reason="Process restarted without a trusted terminal effect receipt",
                    updated_at=datetime.now(UTC),
                )
                self._write_case(updated)
                reconciled.append(updated)
        return tuple(reconciled)

    def close(self) -> None:
        with self._lock:
            self._conn.close()

    def _write_case(self, case: RepairCase) -> None:
        try:
            self._conn.execute(
                "INSERT OR REPLACE INTO repair_cases "
                "(case_id, case_key, component_id, owner, failure_code, component_version, "
                "opened_at, status, "
                "attempt_budget, attempt_count, latest_diagnosis, selected_action, effect_outcome, "
                "verification_reference, fallback, terminal_reason, updated_at) VALUES "
                "(?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                (
                    str(case.case_id),
                    case.case_key,
                    case.component_id,
                    case.owner,
                    case.failure_code,
                    case.component_version,
                    _iso(case.opened_at),
                    case.status.value,
                    case.attempt_budget,
                    case.attempt_count,
                    case.latest_diagnosis,
                    case.selected_action,
                    case.effect_outcome,
                    case.verification_reference,
                    case.fallback,
                    case.terminal_reason,
                    _iso(case.updated_at or case.opened_at),
                ),
            )
            self._conn.commit()
        except sqlite3.DatabaseError as error:
            self._conn.rollback()
            raise RepairStoreError("Repair case could not be stored") from error

    @staticmethod
    def _case(row: sqlite3.Row) -> RepairCase:
        try:
            return RepairCase(
                UUID(str(row["case_id"])),
                str(row["case_key"]),
                str(row["component_id"]),
                str(row["owner"]),
                None if row["failure_code"] is None else str(row["failure_code"]),
                None if row["component_version"] is None else str(row["component_version"]),
                _parse_time(row["opened_at"], "opened_at"),
                RepairCaseStatus(str(row["status"])),
                int(row["attempt_budget"]),
                int(row["attempt_count"]),
                None if row["latest_diagnosis"] is None else str(row["latest_diagnosis"]),
                None if row["selected_action"] is None else str(row["selected_action"]),
                None if row["effect_outcome"] is None else str(row["effect_outcome"]),
                None
                if row["verification_reference"] is None
                else str(row["verification_reference"]),
                None if row["fallback"] is None else str(row["fallback"]),
                None if row["terminal_reason"] is None else str(row["terminal_reason"]),
                _parse_time(row["updated_at"], "updated_at"),
            )
        except (KeyError, TypeError, ValueError, RepairStoreError) as error:
            if isinstance(error, RepairStoreError):
                raise
            raise RepairStoreError("Stored repair case is malformed") from error


__all__ = [
    "RepairAttemptRecord",
    "RepairCase",
    "RepairCaseStatus",
    "RepairStoreError",
    "SQLiteRepairStore",
    "repair_case_key",
]
