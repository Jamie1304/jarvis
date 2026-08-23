"""SQLite-backed durable memory store with explicit, ordered migrations."""

from __future__ import annotations

import json
import re
import sqlite3
import threading
from collections.abc import Callable, Sequence
from dataclasses import dataclass, replace
from datetime import UTC, datetime, timedelta
from pathlib import Path
from uuid import UUID, uuid4

from jarvis.memory.models import (
    DurableMemoryHit,
    MemoryConfidenceEvent,
    MemoryConflictKind,
    MemoryConflictRecord,
    MemoryConflictStatus,
    MemoryProvenance,
    MemoryRecord,
    MemoryRevalidation,
    MemorySource,
    MemoryType,
    RetentionPolicy,
    Sensitivity,
)
from jarvis.memory.policy import contains_prompt_injection, contains_secret

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
    MemoryMigration(
        2,
        "memory_consistency_state",
        """
        ALTER TABLE memories ADD COLUMN last_revalidated_at TEXT;
        ALTER TABLE memories ADD COLUMN quarantined INTEGER NOT NULL DEFAULT 0;
        ALTER TABLE memories ADD COLUMN quarantine_reason TEXT;
        ALTER TABLE memories ADD COLUMN quarantined_at TEXT;
        ALTER TABLE memories ADD COLUMN superseded_by TEXT;
        CREATE INDEX memories_retrievable ON memories(memory_type, quarantined, superseded_by);
        CREATE TABLE memory_conflicts (
            conflict_id TEXT PRIMARY KEY,
            kind TEXT NOT NULL,
            memory_ids_json TEXT NOT NULL,
            detected_at TEXT NOT NULL,
            reason TEXT NOT NULL,
            evidence_json TEXT NOT NULL,
            status TEXT NOT NULL,
            resolved_at TEXT,
            resolution TEXT
        );
        CREATE INDEX memory_conflicts_by_status ON memory_conflicts(status, detected_at);
        CREATE TABLE memory_confidence_events (
            event_id TEXT PRIMARY KEY,
            memory_id TEXT NOT NULL,
            occurred_at TEXT NOT NULL,
            previous_confidence REAL,
            current_confidence REAL NOT NULL,
            provenance_json TEXT NOT NULL,
            evidence_json TEXT NOT NULL
        );
        CREATE INDEX memory_confidence_by_memory
            ON memory_confidence_events(memory_id, occurred_at);
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
        self._connection.execute("PRAGMA foreign_keys = ON")
        self._connection.execute("PRAGMA busy_timeout = 5000")
        self._connection.execute("PRAGMA journal_mode = WAL")
        self._lock = threading.RLock()
        self._integrity_check()
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
                if any(version > len(self._migrations) for version in applied):
                    raise MemoryMigrationError("Memory database uses a future schema")
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

    def _integrity_check(self) -> None:
        try:
            row = self._connection.execute("PRAGMA integrity_check").fetchone()
        except sqlite3.DatabaseError as error:
            raise MemoryMigrationError("Memory database integrity check failed") from error
        if row is None or str(row[0]).casefold() != "ok":
            raise MemoryMigrationError("Memory database is corrupt")

    def schema_version(self) -> int:
        with self._lock:
            row = self._connection.execute(
                "SELECT COALESCE(MAX(version), 0) AS version FROM memory_schema_migrations"
            ).fetchone()
        return int(row["version"] if row is not None else 0)

    def put(self, record: MemoryRecord) -> None:
        """Insert one validated non-secret durable record; duplicate IDs fail closed."""

        self._reject_secret(record)
        automatic_quarantine = self._automatic_quarantine_reason(record, self._clock())
        quarantined = record.quarantined or automatic_quarantine is not None
        quarantine_reason = record.quarantine_reason or automatic_quarantine
        quarantined_at = record.quarantined_at or (self._clock() if quarantined else None)
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
                    "last_accessed_at, last_revalidated_at, quarantined, quarantine_reason, "
                    "quarantined_at, superseded_by) VALUES "
                    "(?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
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
                        self._iso(record.last_revalidated_at)
                        if record.last_revalidated_at
                        else None,
                        int(quarantined),
                        quarantine_reason,
                        self._iso(quarantined_at) if quarantined_at else None,
                        str(record.superseded_by) if record.superseded_by else None,
                    ),
                )
                self._connection.commit()
            except sqlite3.IntegrityError as error:
                self._connection.rollback()
                raise ValueError("Memory ID already exists") from error

    def get(self, memory_id: UUID, *, include_inactive: bool = False) -> MemoryRecord | None:
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
            if not include_inactive and not record.is_retrievable:
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
            if not record.is_retrievable:
                continue
            content_terms = set(_TOKEN.findall((record.content + " " + record.data).casefold()))
            score = len(terms & content_terms)
            if score:
                hits.append(DurableMemoryHit(record, score, record.provenance.untrusted_content))
        hits.sort(key=lambda hit: (-hit.score, hit.record.created_at, str(hit.record.memory_id)))
        return tuple(hits[:limit])

    def list(
        self, memory_type: MemoryType | None = None, *, include_inactive: bool = False
    ) -> tuple[MemoryRecord, ...]:
        """Inspect durable records without merging sources or exposing expired entries."""

        self.cleanup_expired()
        query = "SELECT * FROM memories"
        params: tuple[str, ...] = ()
        if memory_type is not None:
            if not isinstance(memory_type, MemoryType):
                raise ValueError("Memory type must be recognized")
            query += " WHERE memory_type = ?"
            params = (memory_type.value,)
        if not include_inactive:
            query += " AND " if " WHERE " in query else " WHERE "
            query += "quarantined = 0 AND superseded_by IS NULL"
        query += " ORDER BY created_at, memory_id"
        with self._lock:
            rows = tuple(self._connection.execute(query, params))
        return tuple(self._record(row) for row in rows)

    def quarantine(
        self, memory_id: UUID, reason: str, *, now: datetime | None = None
    ) -> MemoryRecord | None:
        """Remove a record from ordinary retrieval without destroying evidence."""

        if not isinstance(memory_id, UUID) or not reason.strip() or len(reason) > 256:
            raise ValueError("Memory quarantine request is invalid")
        if contains_secret(reason):
            raise PermissionError("Memory quarantine reason cannot contain credentials")
        timestamp = now or self._clock()
        with self._lock:
            row = self._connection.execute(
                "SELECT * FROM memories WHERE memory_id = ?", (str(memory_id),)
            ).fetchone()
            if row is None:
                return None
            record = self._record(row)
            if record.quarantined:
                return record
            self._connection.execute(
                "UPDATE memories SET quarantined=1, quarantine_reason=?, quarantined_at=?, "
                "updated_at=? WHERE memory_id=?",
                (reason, self._iso(timestamp), self._iso(timestamp), str(memory_id)),
            )
            self._connection.commit()
            return self._record(
                self._connection.execute(
                    "SELECT * FROM memories WHERE memory_id = ?", (str(memory_id),)
                ).fetchone()
            )

    def apply_revalidation(self, request: MemoryRevalidation) -> MemoryRecord:
        """Apply typed evidence and append confidence history atomically."""

        if not isinstance(request, MemoryRevalidation):
            raise ValueError("Revalidation must use the typed request")
        if any(contains_secret(value) for value in request.evidence):
            raise PermissionError("Revalidation evidence cannot contain credentials")
        now = request.now or self._clock()
        with self._lock:
            row = self._connection.execute(
                "SELECT * FROM memories WHERE memory_id = ?", (str(request.memory_id),)
            ).fetchone()
            if row is None:
                raise KeyError("Memory record does not exist")
            record = self._record(row)
            if record.is_expired(now):
                raise KeyError("Memory record has expired")
            if record.superseded_by is not None:
                raise ValueError("Superseded memory cannot be revalidated")
            updated = replace(
                record,
                confidence=request.confidence,
                updated_at=now,
                last_revalidated_at=now,
                quarantined=False,
                quarantine_reason=None,
                quarantined_at=None,
            )
            event = MemoryConfidenceEvent(
                event_id=uuid4(),
                memory_id=record.memory_id,
                occurred_at=now,
                previous_confidence=record.confidence,
                current_confidence=request.confidence,
                provenance=request.provenance,
                evidence=request.evidence,
            )
            self._update_record_locked(updated)
            self._insert_confidence_event_locked(event)
            self._connection.commit()
            return updated

    def supersede(
        self,
        memory_id: UUID,
        replacement_id: UUID,
        *,
        reason: str,
        now: datetime | None = None,
    ) -> MemoryRecord:
        """Mark an old record as superseded; never silently merge its value."""

        if not isinstance(memory_id, UUID) or not isinstance(replacement_id, UUID):
            raise ValueError("Memory supersession IDs must be UUIDs")
        if memory_id == replacement_id or not reason.strip() or len(reason) > 512:
            raise ValueError("Memory supersession request is invalid")
        if contains_secret(reason):
            raise PermissionError("Memory supersession reason cannot contain credentials")
        timestamp = now or self._clock()
        with self._lock:
            old_row = self._connection.execute(
                "SELECT * FROM memories WHERE memory_id = ?", (str(memory_id),)
            ).fetchone()
            replacement_row = self._connection.execute(
                "SELECT * FROM memories WHERE memory_id = ?", (str(replacement_id),)
            ).fetchone()
            if old_row is None or replacement_row is None:
                raise KeyError("Memory supersession record does not exist")
            old = self._record(old_row)
            replacement = self._record(replacement_row)
            if old.memory_type is not replacement.memory_type:
                raise ValueError("Memory supersession types must match")
            if not replacement.is_retrievable:
                raise ValueError("Memory supersession replacement must be active")
            if old.superseded_by is not None:
                raise ValueError("Memory record is already superseded")
            updated = replace(old, superseded_by=replacement_id, updated_at=timestamp)
            self._update_record_locked(updated)
            self._connection.commit()
            return updated

    def put_conflict(self, conflict: MemoryConflictRecord) -> None:
        """Persist one bounded consistency finding; duplicate IDs fail closed."""

        if not isinstance(conflict, MemoryConflictRecord):
            raise ValueError("Memory conflict must use the typed record")
        if any(contains_secret(value) for value in (conflict.reason, *conflict.evidence)):
            raise PermissionError("Memory conflicts cannot contain credentials")
        with self._lock:
            try:
                self._connection.execute(
                    "INSERT INTO memory_conflicts "
                    "(conflict_id, kind, memory_ids_json, detected_at, reason, evidence_json, "
                    "status, resolved_at, resolution) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
                    (
                        str(conflict.conflict_id),
                        conflict.kind.value,
                        json.dumps([str(value) for value in conflict.memory_ids]),
                        self._iso(conflict.detected_at),
                        conflict.reason,
                        json.dumps(list(conflict.evidence)),
                        conflict.status.value,
                        self._iso(conflict.resolved_at) if conflict.resolved_at else None,
                        conflict.resolution,
                    ),
                )
                self._connection.commit()
            except sqlite3.IntegrityError as error:
                self._connection.rollback()
                raise ValueError("Memory conflict ID already exists") from error

    def find_open_conflict(
        self, kind: MemoryConflictKind, memory_ids: tuple[UUID, ...]
    ) -> MemoryConflictRecord | None:
        if not isinstance(kind, MemoryConflictKind):
            raise ValueError("Memory conflict kind must be recognized")
        normalized = tuple(sorted(memory_ids, key=str))
        for conflict in self.list_conflicts(status=MemoryConflictStatus.OPEN):
            if conflict.kind is kind and tuple(sorted(conflict.memory_ids, key=str)) == normalized:
                return conflict
        return None

    def list_conflicts(
        self,
        *,
        memory_id: UUID | None = None,
        status: MemoryConflictStatus | None = None,
    ) -> tuple[MemoryConflictRecord, ...]:
        if memory_id is not None and not isinstance(memory_id, UUID):
            raise ValueError("Memory conflict filter ID must be a UUID")
        if status is not None and not isinstance(status, MemoryConflictStatus):
            raise ValueError("Memory conflict status must be recognized")
        query = "SELECT * FROM memory_conflicts"
        params: list[str] = []
        conditions: list[str] = []
        if status is not None:
            conditions.append("status = ?")
            params.append(status.value)
        if conditions:
            query += " WHERE " + " AND ".join(conditions)
        query += " ORDER BY detected_at, conflict_id"
        with self._lock:
            rows = tuple(self._connection.execute(query, tuple(params)))
        conflicts = tuple(self._conflict(row) for row in rows)
        if memory_id is None:
            return conflicts
        return tuple(conflict for conflict in conflicts if memory_id in conflict.memory_ids)

    def resolve_conflict(
        self,
        conflict_id: UUID,
        status: MemoryConflictStatus,
        resolution: str,
        *,
        now: datetime | None = None,
    ) -> MemoryConflictRecord:
        if not isinstance(conflict_id, UUID) or not isinstance(status, MemoryConflictStatus):
            raise ValueError("Memory conflict resolution is invalid")
        if status is MemoryConflictStatus.OPEN or not resolution.strip():
            raise ValueError("Conflict resolution must close the conflict with evidence")
        if len(resolution) > 512 or contains_secret(resolution):
            raise PermissionError("Conflict resolution is invalid or contains credentials")
        timestamp = now or self._clock()
        with self._lock:
            row = self._connection.execute(
                "SELECT * FROM memory_conflicts WHERE conflict_id = ?", (str(conflict_id),)
            ).fetchone()
            if row is None:
                raise KeyError("Memory conflict does not exist")
            current = self._conflict(row)
            resolved = replace(
                current,
                status=status,
                resolved_at=timestamp,
                resolution=resolution,
            )
            self._connection.execute(
                "UPDATE memory_conflicts SET status=?, resolved_at=?, resolution=? "
                "WHERE conflict_id=?",
                (
                    resolved.status.value,
                    self._iso(timestamp),
                    resolved.resolution,
                    str(conflict_id),
                ),
            )
            self._connection.commit()
            return resolved

    def confidence_history(self, memory_id: UUID) -> tuple[MemoryConfidenceEvent, ...]:
        if not isinstance(memory_id, UUID):
            raise ValueError("Confidence history ID must be a UUID")
        with self._lock:
            rows = tuple(
                self._connection.execute(
                    "SELECT * FROM memory_confidence_events WHERE memory_id=? "
                    "ORDER BY occurred_at, event_id",
                    (str(memory_id),),
                )
            )
        return tuple(self._confidence_event(row) for row in rows)

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

    @staticmethod
    def _automatic_quarantine_reason(record: MemoryRecord, now: datetime) -> str | None:
        """Apply only deterministic safety quarantine at the storage boundary."""

        text = record.content + "\n" + record.data
        if contains_prompt_injection(text):
            return "prompt-injection pattern in memory content"
        received_at = record.provenance.received_at
        normalized_now = now.astimezone(UTC) if now.tzinfo else now.replace(tzinfo=UTC)
        if received_at > normalized_now + timedelta(minutes=5):
            return "provenance received time is in the future"
        if record.memory_type is MemoryType.LONG_TERM and (
            record.provenance.source is not MemorySource.USER or record.provenance.untrusted_content
        ):
            return "long-term memory has non-user or untrusted provenance"
        if (
            record.memory_type is MemoryType.LONG_TERM
            and record.confidence is not None
            and record.confidence < 0.5
        ):
            return "long-term memory confidence is below the safe threshold"
        if record.provenance.source in {MemorySource.WEB, MemorySource.TOOL} and not (
            record.provenance.untrusted_content
        ):
            return "external provenance is not marked untrusted"
        return None

    def _update_record_locked(self, record: MemoryRecord) -> None:
        self._connection.execute(
            "UPDATE memories SET confidence=?, updated_at=?, last_accessed_at=?, "
            "last_revalidated_at=?, quarantined=?, quarantine_reason=?, quarantined_at=?, "
            "superseded_by=? WHERE memory_id=?",
            (
                record.confidence,
                self._iso(record.updated_at),
                self._iso(record.last_accessed_at) if record.last_accessed_at else None,
                self._iso(record.last_revalidated_at) if record.last_revalidated_at else None,
                int(record.quarantined),
                record.quarantine_reason,
                self._iso(record.quarantined_at) if record.quarantined_at else None,
                str(record.superseded_by) if record.superseded_by else None,
                str(record.memory_id),
            ),
        )

    def _insert_confidence_event_locked(self, event: MemoryConfidenceEvent) -> None:
        provenance = json.dumps(
            {
                "source": event.provenance.source.value,
                "source_reference": event.provenance.source_reference,
                "received_at": self._iso(event.provenance.received_at),
                "untrusted_content": event.provenance.untrusted_content,
            },
            sort_keys=True,
            separators=(",", ":"),
        )
        self._connection.execute(
            "INSERT INTO memory_confidence_events "
            "(event_id, memory_id, occurred_at, previous_confidence, current_confidence, "
            "provenance_json, evidence_json) VALUES (?, ?, ?, ?, ?, ?, ?)",
            (
                str(event.event_id),
                str(event.memory_id),
                self._iso(event.occurred_at),
                event.previous_confidence,
                event.current_confidence,
                provenance,
                json.dumps(list(event.evidence)),
            ),
        )

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
        try:
            quarantine_value = row["quarantined"]
            if quarantine_value not in (0, 1):
                raise ValueError("Stored quarantine flag is malformed")
            provenance = json.loads(str(row["provenance_json"]))
            if not isinstance(provenance, dict):
                raise ValueError("Stored provenance is malformed")
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
                    untrusted_content=provenance["untrusted_content"],
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
                last_revalidated_at=(
                    datetime.fromisoformat(str(row["last_revalidated_at"]))
                    if row["last_revalidated_at"]
                    else None
                ),
                quarantined=bool(quarantine_value),
                quarantine_reason=(
                    str(row["quarantine_reason"]) if row["quarantine_reason"] else None
                ),
                quarantined_at=(
                    datetime.fromisoformat(str(row["quarantined_at"]))
                    if row["quarantined_at"]
                    else None
                ),
                superseded_by=(UUID(str(row["superseded_by"])) if row["superseded_by"] else None),
            )
        except (KeyError, TypeError, ValueError, json.JSONDecodeError) as error:
            raise MemoryMigrationError("Stored memory record is malformed") from error

    @staticmethod
    def _conflict(row: sqlite3.Row) -> MemoryConflictRecord:
        try:
            memory_ids = json.loads(str(row["memory_ids_json"]))
            evidence = json.loads(str(row["evidence_json"]))
            if not isinstance(memory_ids, list) or not isinstance(evidence, list):
                raise ValueError("Stored memory conflict arrays are malformed")
            return MemoryConflictRecord(
                conflict_id=UUID(str(row["conflict_id"])),
                kind=MemoryConflictKind(str(row["kind"])),
                memory_ids=tuple(UUID(str(value)) for value in memory_ids),
                detected_at=datetime.fromisoformat(str(row["detected_at"])),
                reason=str(row["reason"]),
                evidence=tuple(str(value) for value in evidence),
                status=MemoryConflictStatus(str(row["status"])),
                resolved_at=(
                    datetime.fromisoformat(str(row["resolved_at"])) if row["resolved_at"] else None
                ),
                resolution=str(row["resolution"]) if row["resolution"] else None,
            )
        except (KeyError, TypeError, ValueError, json.JSONDecodeError) as error:
            raise MemoryMigrationError("Stored memory conflict is malformed") from error

    @staticmethod
    def _confidence_event(row: sqlite3.Row) -> MemoryConfidenceEvent:
        try:
            provenance = json.loads(str(row["provenance_json"]))
            evidence = json.loads(str(row["evidence_json"]))
            if not isinstance(provenance, dict) or not isinstance(evidence, list):
                raise ValueError("Stored confidence event is malformed")
            return MemoryConfidenceEvent(
                event_id=UUID(str(row["event_id"])),
                memory_id=UUID(str(row["memory_id"])),
                occurred_at=datetime.fromisoformat(str(row["occurred_at"])),
                previous_confidence=(
                    float(row["previous_confidence"])
                    if row["previous_confidence"] is not None
                    else None
                ),
                current_confidence=float(row["current_confidence"]),
                provenance=MemoryProvenance(
                    source=MemorySource(str(provenance["source"])),
                    source_reference=str(provenance["source_reference"]),
                    received_at=datetime.fromisoformat(str(provenance["received_at"])),
                    untrusted_content=provenance["untrusted_content"],
                ),
                evidence=tuple(str(value) for value in evidence),
            )
        except (KeyError, TypeError, ValueError, json.JSONDecodeError) as error:
            raise MemoryMigrationError("Stored memory confidence event is malformed") from error
