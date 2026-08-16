"""Secret-safe append-only audit sink interfaces."""

import asyncio
import json
import sqlite3
from abc import ABC, abstractmethod
from pathlib import Path

from jarvis.permissions.models import AuditRecord


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
        self._connection.execute(
            "CREATE TABLE IF NOT EXISTS permission_audit "
            "(sequence INTEGER PRIMARY KEY AUTOINCREMENT, record_json TEXT NOT NULL)"
        )
        self._connection.commit()
        self._lock = asyncio.Lock()

    async def append(self, record: AuditRecord) -> None:
        payload = json.dumps(record, default=str, sort_keys=True, separators=(",", ":"))
        async with self._lock:
            self._connection.execute(
                "INSERT INTO permission_audit(record_json) VALUES (?)", (payload,)
            )
            self._connection.commit()

    def close(self) -> None:
        self._connection.close()
