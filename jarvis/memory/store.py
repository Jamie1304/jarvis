"""SQLite-backed durable memory store with explicit, ordered migrations."""

from __future__ import annotations

import json
import re
import sqlite3
import threading
from collections.abc import Callable, Sequence
from dataclasses import dataclass, replace
from datetime import UTC, datetime
from pathlib import Path
from uuid import UUID

from jarvis.memory.models import (
    DurableMemoryHit,
    MemoryProvenance,
    MemoryRecord,
    MemorySource,
    MemoryType,
    RetentionPolicy,
    Sensitivity,
)
from jarvis.memory.policy import contains_secret

_TOKEN = re.compile(r"[a-z0-9_./-]+")


class MemoryMigrationError(RuntimeError):
    """A migration cannot be safely applied or the database is not at its declared version."""


@dataclass(frozen=True, slots=True)
class MemoryMigration:
    version: int
    name: str
    sql: str

    def __post_init__(self) -> None:
        if self.version <= 0 or not self.name.strip() or not self.sql.strip():
            raise ValueError("Memory migrations require a positive version, name, and SQL")
        if "\x00" in self.sql:
            raise ValueError("Memory migration SQL cannot contain NUL")


DEFAULT_MIGRATIONS: tuple[MemoryMigration, ...] = (
    MemoryMigration(
        1,
        "create_durable_memory",
        """
        CREATE TABLE memories (
            memory_id TEXT PRIMARY KEY,
            memory_type TEXT NOT NULL,
            content TEXT NOT NULL,
            data_json TEXT NOT NULL,
            created_at TEXT NOT NULL,
            provenance_json TEXT NOT NULL,
            confidence REAL,
            retention TEXT NOT NULL,
            sensitivity TEXT NOT NULL,
            expires_at TEXT,
            updated_at TEXT NOT NULL,
            last_accessed_at TEXT
        );
        CREATE INDEX memories_by_type_expiry ON memories(memory_type, expires_at);
        """,
    ),
)


def _utc_now() -> datetime:
    return datetime.now(UTC)


class SQLiteMemoryStore:
    """A local-only durable store; callers must use policy services before persistence."""

    def __init__(
        self,
        database_path: Path,
        *,
        migrations: Sequence[MemoryMigration] = DEFAULT_MIGRATIONS,
        clock: Callable[[], datetime] = _utc_now,
    ) -> None:
        self._path = database_path
        self._clock = clock
        self._migrations = tuple(migrations)
        self._validate_migrations()
        database_path.parent.mkdir(parents=True, exist_ok=True)
        self._connection = sqlite3.connect(database_path, check_same_thread=False)
        self._connection.row_factory = sqlite3.Row
        self._lock = threading.RLock()
        self.apply_migrations()

    @property
    def database_path(self) -> Path:
        return self._path

    def close(self) -> None:
        with self._lock:
            self._connection.close()

    def __enter__(self) -> SQLiteMemoryStore:
        return self

    def __exit__(self, _type: object, _value: object, _traceback: object) -> None:
        self.close()

    def apply_migrations(self) -> None:
        """Apply only trusted sequential migrations inside one SQLite transaction."""

        with self._lock:
            try:
                self._connection.execute(
                    "CREATE TABLE IF NOT EXISTS memory_schema_migrations "
                    "(version INTEGER PRIMARY KEY, name TEXT NOT NULL, applied_at TEXT NOT NULL)"
                )
                applied = {
                    int(row["version"]): str(row["name"])
                    for row in self._connection.execute(
                        "SELECT version, name FROM memory_schema_migrations"
                    )
                }
                for migration in self._migrations:
                    existing = applied.get(migration.version)
                    if existing is not None:
                        if existing != migration.name:
                            raise MemoryMigrationError("Migration version/name mismatch")
                        continue
                    self._connection.executescript(migration.sql)
                    self._connection.execute(
                        "INSERT INTO memory_schema_migrations(version, name, applied_at) "
                        "VALUES (?, ?, ?)",
                        (migration.version, migration.name, self._iso(self._clock())),
                    )
                self._connection.commit()
            except (sqlite3.DatabaseError, ValueError) as error:
                self._connection.rollback()
                raise MemoryMigrationError("Memory migration failed") from error

    def schema_version(self) -> int:
        with self._lock:
            row = self._connection.execute(
                "SELECT COALESCE(MAX(version), 0) AS version FROM memory_schema_migrations"
            ).fetchone()
        return int(row["version"] if row is not None else 0)

    def put(self, record: MemoryRecord) -> None:
        """Insert one validated non-secret durable record; duplicate IDs fail closed."""

        self._reject_secret(record)
        canonical_data = json.dumps(record.data_object, sort_keys=True, separators=(",", ":"))
        provenance = json.dumps(
            {
                "source": record.provenance.source.value,
                "source_reference": record.provenance.source_reference,
                "received_at": self._iso(record.provenance.received_at),
                "untrusted_content": record.provenance.untrusted_content,
            },
            sort_keys=True,
            separators=(",", ":"),
        )
        with self._lock:
            try:
                self._connection.execute(
                    "INSERT INTO memories(memory_id, memory_type, content, data_json, created_at, "
                    "provenance_json, confidence, retention, sensitivity, expires_at, updated_at, "
                    "last_accessed_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                    (
                        str(record.memory_id),
                        record.memory_type.value,
                        record.content,
                        canonical_data,
                        self._iso(record.created_at),
                        provenance,
                        record.confidence,
                        record.retention.value,
                        record.sensitivity.value,
                        self._iso(record.expires_at) if record.expires_at else None,
                        self._iso(record.updated_at),
                        self._iso(record.last_accessed_at) if record.last_accessed_at else None,
                    ),
                )
                self._connection.commit()
            except sqlite3.IntegrityError as error:
                self._connection.rollback()
                raise ValueError("Memory ID already exists") from error

    def get(self, memory_id: UUID) -> MemoryRecord | None:
        """Read a non-expired record and update its last-accessed timestamp."""

        now = self._clock()
        with self._lock:
            row = self._connection.execute(
                "SELECT * FROM memories WHERE memory_id = ?", (str(memory_id),)
            ).fetchone()
            if row is None:
                return None
            record = self._record(row)
            if record.is_expired(now):
                self._connection.execute(
                    "DELETE FROM memories WHERE memory_id = ?", (str(memory_id),)
                )
                self._connection.commit()
                return None
            accessed = self._iso(now)
            self._connection.execute(
                "UPDATE memories SET last_accessed_at = ? WHERE memory_id = ?",
                (accessed, str(memory_id)),
            )
            self._connection.commit()
        return replace(record, last_accessed_at=now)

    def search(
        self, query: str, memory_type: MemoryType, *, limit: int = 10
    ) -> tuple[DurableMemoryHit, ...]:
        """Use deterministic local lexical search; expired records are never returned."""

        if not isinstance(memory_type, MemoryType) or limit <= 0:
            return ()
        terms = set(_TOKEN.findall(query.casefold()))
        if not terms:
            return ()
        self.cleanup_expired()
        with self._lock:
            rows = tuple(
                self._connection.execute(
                    "SELECT * FROM memories WHERE memory_type = ?", (memory_type.value,)
                )
            )
        hits: list[DurableMemoryHit] = []
        for row in rows:
            record = self._record(row)
            content_terms = set(_TOKEN.findall((record.content + " " + record.data).casefold()))
            score = len(terms & content_terms)
            if score:
                hits.append(DurableMemoryHit(record, score, record.provenance.untrusted_content))
        hits.sort(key=lambda hit: (-hit.score, hit.record.created_at, str(hit.record.memory_id)))
        return tuple(hits[:limit])

    def list(self, memory_type: MemoryType | None = None) -> tuple[MemoryRecord, ...]:
        """Inspect durable records without merging sources or exposing expired entries."""

        self.cleanup_expired()
        query = "SELECT * FROM memories"
        params: tuple[str, ...] = ()
        if memory_type is not None:
            if not isinstance(memory_type, MemoryType):
                raise ValueError("Memory type must be recognized")
            query += " WHERE memory_type = ?"
            params = (memory_type.value,)
        query += " ORDER BY created_at, memory_id"
        with self._lock:
            rows = tuple(self._connection.execute(query, params))
        return tuple(self._record(row) for row in rows)

    def delete(self, memory_id: UUID) -> bool:
        with self._lock:
            cursor = self._connection.execute(
                "DELETE FROM memories WHERE memory_id = ?", (str(memory_id),)
            )
            self._connection.commit()
        return cursor.rowcount == 1

    def delete_category(self, memory_type: MemoryType) -> int:
        if not isinstance(memory_type, MemoryType):
            raise ValueError("Memory type must be recognized")
        with self._lock:
            cursor = self._connection.execute(
                "DELETE FROM memories WHERE memory_type = ?", (memory_type.value,)
            )
            self._connection.commit()
        return cursor.rowcount

    def cleanup_expired(self) -> int:
        with self._lock:
            cursor = self._connection.execute(
                "DELETE FROM memories WHERE expires_at IS NOT NULL AND expires_at <= ?",
                (self._iso(self._clock()),),
            )
            self._connection.commit()
        return cursor.rowcount

    def _validate_migrations(self) -> None:
        expected = 1
        for migration in self._migrations:
            if migration.version != expected:
                raise MemoryMigrationError("Memory migrations must be complete and sequential")
            expected += 1

    @staticmethod
    def _iso(value: datetime) -> str:
        if value.tzinfo is None:
            value = value.replace(tzinfo=UTC)
        return value.astimezone(UTC).isoformat()

    @staticmethod
    def _reject_secret(record: MemoryRecord) -> None:
        if record.sensitivity is Sensitivity.SECRET or contains_secret(
            record.content + "\n" + record.data
        ):
            raise ValueError("Secret-like content must use a dedicated secret store")

    @staticmethod
    def _record(row: sqlite3.Row) -> MemoryRecord:
        provenance = json.loads(str(row["provenance_json"]))
        if not isinstance(provenance, dict):
            raise MemoryMigrationError("Stored provenance is malformed")
        return MemoryRecord(
            memory_id=UUID(str(row["memory_id"])),
            memory_type=MemoryType(str(row["memory_type"])),
            content=str(row["content"]),
            data=str(row["data_json"]),
            created_at=datetime.fromisoformat(str(row["created_at"])),
            provenance=MemoryProvenance(
                source=MemorySource(str(provenance["source"])),
                source_reference=str(provenance["source_reference"]),
                received_at=datetime.fromisoformat(str(provenance["received_at"])),
                untrusted_content=bool(provenance["untrusted_content"]),
            ),
            confidence=float(row["confidence"]) if row["confidence"] is not None else None,
            retention=RetentionPolicy(str(row["retention"])),
            sensitivity=Sensitivity(str(row["sensitivity"])),
            expires_at=datetime.fromisoformat(str(row["expires_at"]))
            if row["expires_at"]
            else None,
            updated_at=datetime.fromisoformat(str(row["updated_at"])),
            last_accessed_at=(
                datetime.fromisoformat(str(row["last_accessed_at"]))
                if row["last_accessed_at"]
                else None
            ),
        )
