"""Secret-safe append-only audit sink interfaces."""

import asyncio
import json
import sqlite3
from abc import ABC, abstractmethod
from dataclasses import asdict
from datetime import UTC, datetime
from pathlib import Path
from threading import RLock
from uuid import UUID

from jarvis.permissions.models import AuditRecord


class AuditStoreError(RuntimeError):
    """A durable audit database is unavailable or not compatible."""


class AuditSink(ABC):
    """Destination for broker-generated records, never raw tool arguments."""

    @abstractmethod
    async def append(self, record: AuditRecord) -> None:
        """Append one immutable audit event."""


class InMemoryAuditSink(AuditSink):
    """Deterministic process-local sink for tests and local composition."""

    def __init__(self) -> None:
        self._records: list[AuditRecord] = []
        self._lock = asyncio.Lock()

    async def append(self, record: AuditRecord) -> None:
        async with self._lock:
            self._records.append(record)

    async def records(self) -> tuple[AuditRecord, ...]:
        async with self._lock:
            return tuple(self._records)


class SQLiteAuditSink(AuditSink):
    """Append-only local audit sink; serialized records remain secret-safe broker output."""

    def __init__(self, database_path: Path) -> None:
        database_path.parent.mkdir(parents=True, exist_ok=True)
        self._connection = sqlite3.connect(database_path, check_same_thread=False)
        try:
            self._connection.execute("PRAGMA foreign_keys = ON")
            self._connection.execute("PRAGMA busy_timeout = 5000")
            self._connection.execute("PRAGMA journal_mode = WAL")
            result = self._connection.execute("PRAGMA integrity_check").fetchone()
            if result is None or result[0] != "ok":
                raise AuditStoreError("Audit database integrity check failed")
            self._migrate()
        except sqlite3.DatabaseError as error:
            self._connection.close()
            raise AuditStoreError("Audit database is unavailable") from error
        self._lock = asyncio.Lock()
        self._sync_lock = RLock()

    def _migrate(self) -> None:
        self._connection.execute(
            "CREATE TABLE IF NOT EXISTS audit_schema_migrations (version INTEGER PRIMARY KEY)"
        )
        versions = {
            int(row[0])
            for row in self._connection.execute(
                "SELECT version FROM audit_schema_migrations"
            ).fetchall()
        }
        if any(version > 1 for version in versions):
            raise AuditStoreError("Audit database uses a future schema")
        self._connection.execute(
            "CREATE TABLE IF NOT EXISTS permission_audit "
            "(sequence INTEGER PRIMARY KEY AUTOINCREMENT, record_json TEXT NOT NULL)"
        )
        self._connection.execute(
            "CREATE TABLE IF NOT EXISTS lifecycle_audit "
            "(sequence INTEGER PRIMARY KEY AUTOINCREMENT, time TEXT NOT NULL, kind TEXT NOT NULL, "
            "task_id TEXT, detail_json TEXT NOT NULL)"
        )
        if not versions:
            self._connection.execute("INSERT INTO audit_schema_migrations(version) VALUES (1)")
        self._connection.commit()

    async def append(self, record: AuditRecord) -> None:
        payload = json.dumps(asdict(record), default=str, sort_keys=True, separators=(",", ":"))
        async with self._lock:
            self._connection.execute(
                "INSERT INTO permission_audit(record_json) VALUES (?)", (payload,)
            )
            self._connection.commit()

    def record_lifecycle(self, kind: str, *, task_id: UUID | None, detail: dict[str, str]) -> None:
        """Append bounded non-secret lifecycle evidence after durable task writes."""

        if (
            not kind
            or len(kind) > 128
            or any(len(key) > 128 or len(value) > 512 for key, value in detail.items())
        ):
            raise ValueError("Audit lifecycle record is malformed")
        payload = json.dumps(detail, sort_keys=True, separators=(",", ":"))
        with self._sync_lock:
            self._connection.execute(
                "INSERT INTO lifecycle_audit(time, kind, task_id, detail_json) VALUES (?, ?, ?, ?)",
                (datetime.now(UTC).isoformat(), kind, str(task_id) if task_id else None, payload),
            )
            self._connection.commit()

    def lifecycle_entries(self) -> tuple[tuple[str, str, str | None, str], ...]:
        with self._sync_lock:
            rows = self._connection.execute(
                "SELECT time, kind, task_id, detail_json FROM lifecycle_audit ORDER BY sequence"
            ).fetchall()
        return tuple((str(row[0]), str(row[1]), row[2], str(row[3])) for row in rows)

    def close(self) -> None:
        self._connection.close()
