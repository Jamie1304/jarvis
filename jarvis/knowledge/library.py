"""Authoritative, local documentary knowledge libraries.

This module deliberately does not use the generated project index.  A personal
library is an app-owned index of explicitly approved sources; it never scans a
machine implicitly and it never treats document text as policy or instructions.
"""

from __future__ import annotations

import hashlib
import json
import math
import mimetypes
import re
import sqlite3
import threading
from collections.abc import Callable, Iterable, Mapping, Sequence
from dataclasses import dataclass, field
from datetime import UTC, datetime
from enum import StrEnum
from pathlib import Path
from urllib.parse import urlsplit
from uuid import UUID, uuid4

from jarvis.memory.policy import contains_secret
from jarvis.multi_agent.models import DataClassification


class KnowledgeLibraryMigrationError(RuntimeError):
    """The documentary index cannot be safely opened or migrated."""


class KnowledgeSourceKind(StrEnum):
    APPROVED_DIRECTORY = "approved_directory"
    APPROVED_FILE = "approved_file"
    INTEGRATION = "integration"


class KnowledgeSyncStatus(StrEnum):
    NEVER = "never"
    INDEXED = "indexed"
    DEGRADED = "degraded"
    FAILED = "failed"


class KnowledgeRetrievalMode(StrEnum):
    KEYWORD = "keyword"
    SEMANTIC = "semantic"
    HYBRID = "hybrid"


KnowledgeClassification = DataClassification


@dataclass(frozen=True, slots=True)
class KnowledgeSource:
    """An explicit source grant. Registration does not grant permissions."""

    kind: KnowledgeSourceKind
    location: str
    workspace_id: str
    classification: DataClassification = DataClassification.INTERNAL
    source_id: UUID = field(default_factory=uuid4)
    recursive: bool = True
    enabled: bool = True
    metadata: tuple[tuple[str, str], ...] = ()
    provenance: tuple[tuple[str, str], ...] = ()
    created_at: datetime = field(default_factory=lambda: datetime.now(UTC))
    updated_at: datetime = field(default_factory=lambda: datetime.now(UTC))

    def __post_init__(self) -> None:
        if not isinstance(self.kind, KnowledgeSourceKind):
            raise ValueError("Knowledge source kind is invalid")
        _bounded(self.location, "Knowledge source location", 2_000)
        _bounded(self.workspace_id, "Knowledge workspace", 256)
        if self.classification is DataClassification.SECRET:
            raise ValueError("Secret-classified sources cannot be indexed")
        _pairs(self.metadata, "Knowledge source metadata")
        _pairs(self.provenance, "Knowledge source provenance")
        _utc(self.created_at, "Knowledge source created_at")
        _utc(self.updated_at, "Knowledge source updated_at")
        if self.kind is KnowledgeSourceKind.INTEGRATION:
            parsed = urlsplit(self.location)
            if not parsed.scheme or parsed.username or parsed.password or parsed.query:
                raise ValueError("Integration sources require credential-free bounded URIs")


@dataclass(frozen=True, slots=True)
class IndexedDocument:
    document_id: UUID
    source_id: UUID
    workspace_id: str
    source_identity: str
    relative_path: str
    name: str
    mime_type: str
    size: int
    content_hash: str
    modified_at: datetime
    classification: DataClassification
    provenance: tuple[tuple[str, str], ...] = ()
    metadata: tuple[tuple[str, str], ...] = ()
    indexed_at: datetime = field(default_factory=lambda: datetime.now(UTC))
    deleted: bool = False

    def __post_init__(self) -> None:
        for value, name, limit in (
            (self.workspace_id, "Document workspace", 256),
            (self.source_identity, "Document source identity", 2_000),
            (self.relative_path, "Document relative path", 2_000),
            (self.name, "Document name", 512),
            (self.mime_type, "Document MIME type", 256),
            (self.content_hash, "Document hash", 128),
        ):
            _bounded(value, name, limit)
        if self.size < 0 or self.size > MAX_DOCUMENT_BYTES:
            raise ValueError("Document size is outside the safe bound")
        if self.classification is DataClassification.SECRET:
            raise ValueError("Secret-classified documents cannot be indexed")
        _pairs(self.provenance, "Document provenance")
        _pairs(self.metadata, "Document metadata")
        _utc(self.modified_at, "Document modified_at")
        _utc(self.indexed_at, "Document indexed_at")


@dataclass(frozen=True, slots=True)
class DocumentChunk:
    chunk_id: UUID
    document_id: UUID
    ordinal: int
    text: str
    content_hash: str
    start_offset: int
    end_offset: int
    untrusted_content: bool = True

    def __post_init__(self) -> None:
        if type(self.text) is not str or len(self.text) > MAX_CHUNK_CHARS or "\x00" in self.text:
            raise ValueError("Document chunk must be bounded and NUL-free")
        _bounded(self.content_hash, "Chunk hash", 128)
        if self.ordinal < 0 or self.start_offset < 0 or self.end_offset < self.start_offset:
            raise ValueError("Document chunk offsets are invalid")
        if self.end_offset - self.start_offset != len(self.text):
            raise ValueError("Document chunk offsets do not match text")


@dataclass(frozen=True, slots=True)
class KnowledgeCitation:
    citation_id: UUID
    document_id: UUID
    chunk_id: UUID
    source_id: UUID
    source_identity: str
    location: str
    content_hash: str
    excerpt: str
    untrusted_content: bool = True

    def __post_init__(self) -> None:
        for value, name, limit in (
            (self.source_identity, "Citation source identity", 2_000),
            (self.location, "Citation location", 2_000),
            (self.content_hash, "Citation hash", 128),
        ):
            _bounded(value, name, limit)
        _bounded(self.excerpt, "Citation excerpt", 1_000)


@dataclass(frozen=True, slots=True)
class SyncState:
    source_id: UUID
    status: KnowledgeSyncStatus = KnowledgeSyncStatus.NEVER
    last_sync_at: datetime | None = None
    indexed_count: int = 0
    updated_count: int = 0
    unchanged_count: int = 0
    deleted_count: int = 0
    error: str | None = None

    def __post_init__(self) -> None:
        for name in ("indexed_count", "updated_count", "unchanged_count", "deleted_count"):
            if getattr(self, name) < 0:
                raise ValueError("Sync counters cannot be negative")
        if self.error is not None:
            _bounded(self.error, "Sync error", 1_000)
        if self.last_sync_at is not None:
            _utc(self.last_sync_at, "Sync timestamp")


@dataclass(frozen=True, slots=True)
class KnowledgeSyncResult:
    source_id: UUID
    indexed: int = 0
    updated: int = 0
    unchanged: int = 0
    deleted: int = 0
    skipped: int = 0
    errors: tuple[str, ...] = ()


@dataclass(frozen=True, slots=True)
class KnowledgeSearchHit:
    document: IndexedDocument
    chunk: DocumentChunk
    citation: KnowledgeCitation
    score: float
    keyword_score: float
    semantic_score: float


@dataclass(frozen=True, slots=True)
class KnowledgeMigration:
    version: int
    name: str
    sql: str


MAX_DOCUMENT_BYTES = 8 * 1024 * 1024
MAX_CHUNK_CHARS = 4_000
MAX_CHUNKS_PER_DOCUMENT = 4_096
MAX_RESULT_TEXT = 1_000
_TOKEN = re.compile(r"[a-z0-9_./-]+")
_SAFE_SUFFIXES = {
    ".txt",
    ".md",
    ".markdown",
    ".rst",
    ".csv",
    ".json",
    ".yaml",
    ".yml",
    ".toml",
    ".log",
}


DEFAULT_KNOWLEDGE_MIGRATIONS: tuple[KnowledgeMigration, ...] = (
    KnowledgeMigration(
        1,
        "create_knowledge_library",
        """
        CREATE TABLE knowledge_sources (
            source_id TEXT PRIMARY KEY,
            kind TEXT NOT NULL,
            location TEXT NOT NULL,
            workspace_id TEXT NOT NULL,
            classification TEXT NOT NULL,
            recursive INTEGER NOT NULL,
            enabled INTEGER NOT NULL,
            metadata_json TEXT NOT NULL,
            provenance_json TEXT NOT NULL,
            created_at TEXT NOT NULL,
            updated_at TEXT NOT NULL
        );
        CREATE TABLE indexed_documents (
            document_id TEXT PRIMARY KEY,
            source_id TEXT NOT NULL REFERENCES knowledge_sources(source_id) ON DELETE CASCADE,
            workspace_id TEXT NOT NULL,
            source_identity TEXT NOT NULL,
            relative_path TEXT NOT NULL,
            name TEXT NOT NULL,
            mime_type TEXT NOT NULL,
            size INTEGER NOT NULL,
            content_hash TEXT NOT NULL,
            modified_at TEXT NOT NULL,
            classification TEXT NOT NULL,
            provenance_json TEXT NOT NULL,
            metadata_json TEXT NOT NULL,
            indexed_at TEXT NOT NULL,
            deleted INTEGER NOT NULL DEFAULT 0,
            UNIQUE(source_id, source_identity)
        );
        CREATE TABLE document_chunks (
            chunk_id TEXT PRIMARY KEY,
            document_id TEXT NOT NULL REFERENCES indexed_documents(document_id) ON DELETE CASCADE,
            ordinal INTEGER NOT NULL,
            text TEXT NOT NULL,
            content_hash TEXT NOT NULL,
            start_offset INTEGER NOT NULL,
            end_offset INTEGER NOT NULL,
            untrusted_content INTEGER NOT NULL DEFAULT 1,
            UNIQUE(document_id, ordinal)
        );
        CREATE TABLE knowledge_sync_states (
            source_id TEXT PRIMARY KEY REFERENCES knowledge_sources(source_id) ON DELETE CASCADE,
            status TEXT NOT NULL,
            last_sync_at TEXT,
            indexed_count INTEGER NOT NULL,
            updated_count INTEGER NOT NULL,
            unchanged_count INTEGER NOT NULL,
            deleted_count INTEGER NOT NULL,
            error TEXT
        );
        CREATE INDEX indexed_documents_by_scope
            ON indexed_documents(workspace_id, classification, deleted);
        CREATE INDEX indexed_documents_by_source
            ON indexed_documents(source_id, deleted);
        CREATE INDEX document_chunks_by_document
            ON document_chunks(document_id, ordinal);
        """,
    ),
)


def _bounded(value: str, name: str, limit: int) -> None:
    if type(value) is not str or not value.strip() or len(value) > limit or "\x00" in value:
        raise ValueError(f"{name} must be bounded, non-empty, and NUL-free")


def _pairs(values: tuple[tuple[str, str], ...], name: str) -> None:
    if type(values) is not tuple or len(values) > 64:
        raise ValueError(f"{name} must be a bounded tuple")
    keys: set[str] = set()
    for pair in values:
        if type(pair) is not tuple or len(pair) != 2:
            raise ValueError(f"{name} must contain key/value pairs")
        key, value = pair
        _bounded(key, f"{name} key", 128)
        _bounded(value, f"{name} value", 2_000)
        if key in keys:
            raise ValueError(f"{name} keys must be unique")
        keys.add(key)


def _utc(value: datetime, name: str) -> None:
    if value.tzinfo is None or value.utcoffset() is None:
        raise ValueError(f"{name} must be timezone-aware")


def _iso(value: datetime | None) -> str | None:
    return value.astimezone(UTC).isoformat() if value is not None else None


def _parse_time(value: str | None) -> datetime | None:
    return datetime.fromisoformat(value) if value is not None else None


def _json_pairs(values: tuple[tuple[str, str], ...]) -> str:
    return json.dumps(dict(values), sort_keys=True, separators=(",", ":"))


def _pairs_from_json(value: str) -> tuple[tuple[str, str], ...]:
    payload = json.loads(value)
    if not isinstance(payload, dict):
        raise ValueError("Knowledge metadata must be an object")
    return tuple(sorted((str(key), str(item)) for key, item in payload.items()))


def _sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _tokens(value: str) -> set[str]:
    return set(_TOKEN.findall(value.casefold()))


class KnowledgeLibrary:
    """The sole authoritative owner of a personal documentary index.

    Only sources explicitly registered with a workspace root can be synced.
    The source file is never modified or removed by this class.
    """

    def __init__(
        self,
        database_path: Path,
        *,
        workspace_roots: Mapping[str, Path] | None = None,
        migrations: Sequence[KnowledgeMigration] = DEFAULT_KNOWLEDGE_MIGRATIONS,
        clock: Callable[[], datetime] = lambda: datetime.now(UTC),
    ) -> None:
        self._path = database_path
        self._roots = {
            str(key): Path(value).expanduser() for key, value in (workspace_roots or {}).items()
        }
        self._clock = clock
        self._migrations = tuple(migrations)
        self._validate_migrations(self._migrations)
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

    def __enter__(self) -> KnowledgeLibrary:
        return self

    def __exit__(self, _type: object, _value: object, _traceback: object) -> None:
        self.close()

    def schema_version(self) -> int:
        with self._lock:
            row = self._connection.execute(
                "SELECT COALESCE(MAX(version), 0) AS version FROM knowledge_schema_migrations"
            ).fetchone()
        return int(row["version"] if row else 0)

    def apply_migrations(self) -> None:
        with self._lock:
            try:
                self._connection.execute(
                    "CREATE TABLE IF NOT EXISTS knowledge_schema_migrations "
                    "(version INTEGER PRIMARY KEY, name TEXT NOT NULL, applied_at TEXT NOT NULL)"
                )
                applied = {
                    int(row["version"]): str(row["name"])
                    for row in self._connection.execute(
                        "SELECT version, name FROM knowledge_schema_migrations"
                    )
                }
                known = {migration.version: migration.name for migration in self._migrations}
                if any(version not in known for version in applied):
                    raise KnowledgeLibraryMigrationError("Knowledge database uses a future schema")
                for migration in self._migrations:
                    if (
                        migration.version in applied
                        and applied[migration.version] != migration.name
                    ):
                        raise KnowledgeLibraryMigrationError(
                            "Knowledge migration identity mismatch"
                        )
                for migration in self._migrations:
                    if migration.version in applied:
                        continue
                    self._connection.executescript(migration.sql)
                    self._connection.execute(
                        "INSERT INTO knowledge_schema_migrations(version, name, applied_at) "
                        "VALUES (?, ?, ?)",
                        (migration.version, migration.name, _iso(self._clock())),
                    )
                self._connection.commit()
            except KnowledgeLibraryMigrationError:
                self._connection.rollback()
                raise
            except (sqlite3.DatabaseError, ValueError) as error:
                self._connection.rollback()
                raise KnowledgeLibraryMigrationError("Knowledge migration failed") from error

    def register_source(self, source: KnowledgeSource) -> KnowledgeSource:
        normalized = self._normalize_source(source)
        with self._lock:
            try:
                self._connection.execute(
                    "INSERT INTO knowledge_sources VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                    (
                        str(normalized.source_id),
                        normalized.kind.value,
                        normalized.location,
                        normalized.workspace_id,
                        normalized.classification.value,
                        int(normalized.recursive),
                        int(normalized.enabled),
                        _json_pairs(normalized.metadata),
                        _json_pairs(normalized.provenance),
                        _iso(normalized.created_at),
                        _iso(normalized.updated_at),
                    ),
                )
                self._connection.execute(
                    "INSERT INTO knowledge_sync_states "
                    "(source_id, status, indexed_count, updated_count, unchanged_count, "
                    "deleted_count) "
                    "VALUES (?, ?, 0, 0, 0, 0)",
                    (str(normalized.source_id), KnowledgeSyncStatus.NEVER.value),
                )
                self._connection.commit()
            except sqlite3.IntegrityError as error:
                self._connection.rollback()
                raise ValueError("Knowledge source ID already exists") from error
        return normalized

    def get_source(self, source_id: UUID) -> KnowledgeSource | None:
        with self._lock:
            row = self._connection.execute(
                "SELECT * FROM knowledge_sources WHERE source_id = ?", (str(source_id),)
            ).fetchone()
        return self._source_from_row(row) if row else None

    def list_sources(self, *, workspace_id: str | None = None) -> tuple[KnowledgeSource, ...]:
        query = "SELECT * FROM knowledge_sources"
        values: tuple[str, ...] = ()
        if workspace_id is not None:
            _bounded(workspace_id, "Knowledge workspace", 256)
            query += " WHERE workspace_id = ?"
            values = (workspace_id,)
        query += " ORDER BY workspace_id, location, source_id"
        with self._lock:
            rows = self._connection.execute(query, values).fetchall()
        return tuple(self._source_from_row(row) for row in rows)

    def sync(self, source_id: UUID) -> KnowledgeSyncResult:
        source = self.get_source(source_id)
        if source is None:
            raise KeyError("Unknown knowledge source")
        if not source.enabled:
            return KnowledgeSyncResult(source_id, skipped=1, errors=("source_disabled",))
        if source.kind is KnowledgeSourceKind.INTEGRATION:
            self._record_sync(
                source_id, KnowledgeSyncStatus.DEGRADED, error="integration_adapter_required"
            )
            return KnowledgeSyncResult(source_id, errors=("integration_adapter_required",))
        try:
            candidates = self._discover_files(source)
        except (OSError, ValueError) as error:
            message = f"source_unavailable:{type(error).__name__}"
            self._record_sync(source_id, KnowledgeSyncStatus.FAILED, error=message)
            return KnowledgeSyncResult(source_id, errors=(message,))
        existing = self._documents_for_source(source_id)
        found: set[str] = set()
        indexed = updated = unchanged = skipped = 0
        errors: list[str] = []
        with self._lock:
            try:
                self._connection.execute("BEGIN")
                for path in candidates:
                    identity = self._source_identity(source, path)
                    try:
                        document, chunks = self._extract_document(source, path, identity)
                    except (OSError, UnicodeError, ValueError) as error:
                        skipped += 1
                        errors.append(f"document_skipped:{path.name}:{type(error).__name__}")
                        continue
                    found.add(identity)
                    previous = existing.get(identity)
                    if previous is not None and (
                        not previous.deleted
                        and previous.content_hash == document.content_hash
                        and previous.size == document.size
                        and previous.modified_at == document.modified_at
                    ):
                        unchanged += 1
                        continue
                    if previous is None:
                        indexed += 1
                        self._insert_document(document, chunks)
                    else:
                        updated += 1
                        self._replace_document(document, chunks)
                deleted = 0
                for identity, document in existing.items():
                    if identity not in found and not document.deleted:
                        deleted += 1
                        self._connection.execute(
                            "UPDATE indexed_documents SET deleted = 1, indexed_at = ? "
                            "WHERE document_id = ?",
                            (_iso(self._clock()), str(document.document_id)),
                        )
                        self._connection.execute(
                            "DELETE FROM document_chunks WHERE document_id = ?",
                            (str(document.document_id),),
                        )
                self._connection.execute(
                    "UPDATE knowledge_sync_states SET status = ?, last_sync_at = ?, "
                    "indexed_count = ?, updated_count = ?, unchanged_count = ?, "
                    "deleted_count = ?, error = ? "
                    "WHERE source_id = ?",
                    (
                        KnowledgeSyncStatus.INDEXED.value
                        if not errors
                        else KnowledgeSyncStatus.DEGRADED.value,
                        _iso(self._clock()),
                        indexed,
                        updated,
                        unchanged,
                        deleted,
                        ";".join(errors)[:1_000] if errors else None,
                        str(source_id),
                    ),
                )
                self._connection.commit()
            except Exception:
                self._connection.rollback()
                raise
        return KnowledgeSyncResult(
            source_id, indexed, updated, unchanged, deleted, skipped, tuple(errors)
        )

    def sync_all(self, *, workspace_id: str | None = None) -> tuple[KnowledgeSyncResult, ...]:
        return tuple(
            self.sync(source.source_id) for source in self.list_sources(workspace_id=workspace_id)
        )

    def get_sync_state(self, source_id: UUID) -> SyncState | None:
        with self._lock:
            row = self._connection.execute(
                "SELECT * FROM knowledge_sync_states WHERE source_id = ?", (str(source_id),)
            ).fetchone()
        if row is None:
            return None
        return SyncState(
            source_id,
            KnowledgeSyncStatus(str(row["status"])),
            _parse_time(row["last_sync_at"]),
            int(row["indexed_count"]),
            int(row["updated_count"]),
            int(row["unchanged_count"]),
            int(row["deleted_count"]),
            str(row["error"]) if row["error"] else None,
        )

    def list_documents(
        self,
        *,
        source_id: UUID | None = None,
        workspace_id: str | None = None,
        include_deleted: bool = False,
    ) -> tuple[IndexedDocument, ...]:
        clauses: list[str] = []
        values: list[object] = []
        if source_id is not None:
            clauses.append("source_id = ?")
            values.append(str(source_id))
        if workspace_id is not None:
            _bounded(workspace_id, "Knowledge workspace", 256)
            clauses.append("workspace_id = ?")
            values.append(workspace_id)
        if not include_deleted:
            clauses.append("deleted = 0")
        query = "SELECT * FROM indexed_documents"
        if clauses:
            query += " WHERE " + " AND ".join(clauses)
        query += " ORDER BY source_identity"
        with self._lock:
            rows = self._connection.execute(query, tuple(values)).fetchall()
        return tuple(self._document_from_row(row) for row in rows)

    def retrieve(
        self,
        query: str,
        *,
        workspace_id: str,
        mode: KnowledgeRetrievalMode = KnowledgeRetrievalMode.HYBRID,
        allowed_classifications: Iterable[DataClassification] | None = None,
        metadata: Mapping[str, str] | None = None,
        source_ids: Iterable[UUID] = (),
        mime_types: Iterable[str] = (),
        limit: int = 10,
    ) -> tuple[KnowledgeSearchHit, ...]:
        _bounded(query, "Knowledge query", 4_000)
        _bounded(workspace_id, "Knowledge workspace", 256)
        if limit <= 0 or limit > 100:
            raise ValueError("Knowledge result limit must be between 1 and 100")
        allowed = frozenset(
            allowed_classifications
            or (
                DataClassification.PUBLIC,
                DataClassification.INTERNAL,
                DataClassification.SENSITIVE,
                DataClassification.CONFIDENTIAL,
            )
        )
        if DataClassification.SECRET in allowed:
            raise ValueError("Secret classification cannot be retrieved")
        source_filter = tuple(str(value) for value in source_ids)
        mime_filter = tuple(str(value) for value in mime_types)
        terms = _tokens(query)
        if not terms:
            return ()
        clauses = ["d.workspace_id = ?", "d.deleted = 0"]
        values: list[object] = [workspace_id]
        classifications = tuple(item.value for item in allowed)
        clauses.append("d.classification IN (" + ",".join("?" for _ in classifications) + ")")
        values.extend(classifications)
        if source_filter:
            clauses.append("d.source_id IN (" + ",".join("?" for _ in source_filter) + ")")
            values.extend(source_filter)
        if mime_filter:
            clauses.append("d.mime_type IN (" + ",".join("?" for _ in mime_filter) + ")")
            values.extend(mime_filter)
        with self._lock:
            rows = self._connection.execute(
                "SELECT d.*, c.* FROM indexed_documents d "
                "JOIN document_chunks c ON c.document_id = d.document_id WHERE "
                + " AND ".join(clauses)
                + " ORDER BY d.source_identity, c.ordinal",
                tuple(values),
            ).fetchall()
        hits: list[KnowledgeSearchHit] = []
        metadata_filter = dict(metadata or {})
        for row in rows:
            document = self._document_from_row(row)
            if any(
                dict(document.metadata).get(key) != value for key, value in metadata_filter.items()
            ):
                continue
            chunk = self._chunk_from_row(row)
            keyword_score = float(len(terms & _tokens(chunk.text)) * 2)
            keyword_score += float(len(terms & _tokens(document.name)))
            semantic_score = self._semantic_score(terms, chunk.text)
            if keyword_score <= 0 and semantic_score <= 0:
                continue
            score = keyword_score if mode is KnowledgeRetrievalMode.KEYWORD else semantic_score
            if mode is KnowledgeRetrievalMode.HYBRID:
                score = keyword_score * 0.7 + semantic_score * 0.3
            citation = self._citation(document, chunk)
            hits.append(
                KnowledgeSearchHit(document, chunk, citation, score, keyword_score, semantic_score)
            )
        hits.sort(key=lambda hit: (-hit.score, hit.document.source_identity, hit.chunk.ordinal))
        return tuple(hits[:limit])

    search = retrieve

    def delete_index(self, source_id: UUID) -> int:
        """Remove indexed rows only; this never deletes or changes source files."""

        with self._lock:
            rows = self._connection.execute(
                "SELECT document_id FROM indexed_documents WHERE source_id = ?", (str(source_id),)
            ).fetchall()
            self._connection.execute(
                "DELETE FROM indexed_documents WHERE source_id = ?", (str(source_id),)
            )
            self._connection.execute(
                "UPDATE knowledge_sync_states SET status = ?, last_sync_at = NULL, "
                "indexed_count = 0, updated_count = 0, unchanged_count = 0, "
                "deleted_count = 0, error = NULL "
                "WHERE source_id = ?",
                (KnowledgeSyncStatus.NEVER.value, str(source_id)),
            )
            self._connection.commit()
        return len(rows)

    def remove_source(self, source_id: UUID) -> bool:
        """Remove source metadata and its index, never the source itself."""

        with self._lock:
            cursor = self._connection.execute(
                "DELETE FROM knowledge_sources WHERE source_id = ?", (str(source_id),)
            )
            self._connection.commit()
        return cursor.rowcount > 0

    def _normalize_source(self, source: KnowledgeSource) -> KnowledgeSource:
        if source.kind is KnowledgeSourceKind.INTEGRATION:
            return source
        root = self._workspace_root(source.workspace_id)
        location = self._safe_path(
            Path(source.location),
            root,
            allow_directory=source.kind is KnowledgeSourceKind.APPROVED_DIRECTORY,
        )
        if source.kind is KnowledgeSourceKind.APPROVED_FILE and not location.is_file():
            raise ValueError("Approved file source is not a regular file")
        if source.kind is KnowledgeSourceKind.APPROVED_DIRECTORY and not location.is_dir():
            raise ValueError("Approved directory source is not a directory")
        return KnowledgeSource(
            kind=source.kind,
            location=str(location),
            workspace_id=source.workspace_id,
            classification=source.classification,
            source_id=source.source_id,
            recursive=source.recursive,
            enabled=source.enabled,
            metadata=source.metadata,
            provenance=source.provenance,
            created_at=source.created_at,
            updated_at=source.updated_at,
        )

    def _workspace_root(self, workspace_id: str) -> Path:
        root = self._roots.get(workspace_id)
        if root is None:
            raise ValueError("Workspace has no explicitly approved root")
        if not root.is_absolute():
            raise ValueError("Workspace root must be absolute")
        if _has_reparse(root):
            raise ValueError("Workspace root uses a reparse point")
        resolved = root.resolve(strict=True)
        if not resolved.is_dir() or resolved == Path(resolved.anchor):
            raise ValueError("Workspace root is not a bounded directory")
        if _has_reparse(resolved):
            raise ValueError("Workspace root uses a reparse point")
        return resolved

    def _safe_path(self, path: Path, root: Path, *, allow_directory: bool) -> Path:
        if not path.is_absolute() or ".." in path.parts:
            raise ValueError("Knowledge source path must be absolute and traversal-free")
        if _has_reparse(path):
            raise ValueError("Knowledge source uses a reparse point")
        resolved = path.resolve(strict=True)
        try:
            resolved.relative_to(root)
        except ValueError as error:
            raise ValueError("Knowledge source escaped its approved workspace root") from error
        if _has_reparse(resolved):
            raise ValueError("Knowledge source uses a reparse point")
        if allow_directory and not resolved.is_dir():
            raise ValueError("Knowledge source is not a directory")
        if not allow_directory and not resolved.is_file():
            raise ValueError("Knowledge source is not a file")
        return resolved

    def _discover_files(self, source: KnowledgeSource) -> tuple[Path, ...]:
        root = self._workspace_root(source.workspace_id)
        location = self._safe_path(
            Path(source.location),
            root,
            allow_directory=source.kind is KnowledgeSourceKind.APPROVED_DIRECTORY,
        )
        if source.kind is KnowledgeSourceKind.APPROVED_FILE:
            return (location,)
        iterator = location.rglob("*") if source.recursive else location.glob("*")
        files: list[Path] = []
        for candidate in iterator:
            if not candidate.is_file() or candidate.is_symlink() or _has_reparse(candidate):
                continue
            resolved = candidate.resolve(strict=True)
            try:
                resolved.relative_to(location)
            except ValueError:
                continue
            if resolved.suffix.casefold() in _SAFE_SUFFIXES:
                files.append(resolved)
        return tuple(sorted(files, key=lambda item: str(item).casefold()))

    def _source_identity(self, source: KnowledgeSource, path: Path) -> str:
        location = Path(source.location)
        relative = (
            path.name
            if source.kind is KnowledgeSourceKind.APPROVED_FILE
            else str(path.relative_to(location))
        )
        return f"{source.source_id}:{relative.replace(chr(92), '/')}"

    def _extract_document(
        self, source: KnowledgeSource, path: Path, identity: str
    ) -> tuple[IndexedDocument, tuple[DocumentChunk, ...]]:
        stat = path.stat()
        if stat.st_size > MAX_DOCUMENT_BYTES:
            raise ValueError("document_too_large")
        raw = path.read_bytes()
        if len(raw) != stat.st_size or len(raw) > MAX_DOCUMENT_BYTES:
            raise ValueError("document_size_changed")
        text = raw.decode("utf-8")
        if "\x00" in text or contains_secret(text):
            raise ValueError("document_rejected_sensitive_content")
        digest = _sha256(raw)
        modified = datetime.fromtimestamp(stat.st_mtime, UTC)
        relative = (
            path.name
            if source.kind is KnowledgeSourceKind.APPROVED_FILE
            else str(path.relative_to(Path(source.location)))
        )
        mime = mimetypes.guess_type(path.name)[0] or "text/plain"
        now = self._clock()
        document = IndexedDocument(
            uuid4(),
            source.source_id,
            source.workspace_id,
            identity,
            relative,
            path.name,
            mime,
            len(raw),
            digest,
            modified,
            source.classification,
            source.provenance + (("source", str(source.source_id)),),
            source.metadata,
            now,
        )
        chunks: list[DocumentChunk] = []
        for ordinal, start in enumerate(range(0, len(text), MAX_CHUNK_CHARS)):
            if ordinal >= MAX_CHUNKS_PER_DOCUMENT:
                raise ValueError("document_has_too_many_chunks")
            chunk_text = text[start : start + MAX_CHUNK_CHARS]
            chunks.append(
                DocumentChunk(
                    uuid4(),
                    document.document_id,
                    ordinal,
                    chunk_text,
                    _sha256(chunk_text.encode("utf-8")),
                    start,
                    start + len(chunk_text),
                )
            )
        if not chunks:
            chunks.append(DocumentChunk(uuid4(), document.document_id, 0, " ", _sha256(b" "), 0, 1))
        return document, tuple(chunks)

    def _documents_for_source(self, source_id: UUID) -> dict[str, IndexedDocument]:
        with self._lock:
            rows = self._connection.execute(
                "SELECT * FROM indexed_documents WHERE source_id = ?", (str(source_id),)
            ).fetchall()
        return {
            document.source_identity: document
            for document in (self._document_from_row(row) for row in rows)
        }

    def _insert_document(
        self, document: IndexedDocument, chunks: tuple[DocumentChunk, ...]
    ) -> None:
        self._connection.execute(
            "INSERT INTO indexed_documents VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
            self._document_values(document),
        )
        self._insert_chunks(chunks)

    def _replace_document(
        self, document: IndexedDocument, chunks: tuple[DocumentChunk, ...]
    ) -> None:
        previous = self._connection.execute(
            "SELECT document_id FROM indexed_documents WHERE source_id = ? AND source_identity = ?",
            (str(document.source_id), document.source_identity),
        ).fetchone()
        if previous is None:
            self._insert_document(document, chunks)
            return
        self._connection.execute(
            "DELETE FROM document_chunks WHERE document_id = ?", (str(previous["document_id"]),)
        )
        values = self._document_values(document)
        self._connection.execute(
            "UPDATE indexed_documents SET document_id = ?, workspace_id = ?, relative_path = ?, "
            "name = ?, mime_type = ?, size = ?, content_hash = ?, modified_at = ?, "
            "classification = ?, provenance_json = ?, metadata_json = ?, indexed_at = ?, "
            "deleted = ? "
            "WHERE source_id = ? AND source_identity = ?",
            (
                *values[0:1],
                values[2],
                *values[4:],
                str(document.source_id),
                document.source_identity,
            ),
        )
        self._insert_chunks(chunks)

    def _insert_chunks(self, chunks: tuple[DocumentChunk, ...]) -> None:
        self._connection.executemany(
            "INSERT INTO document_chunks VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
            [
                (
                    str(chunk.chunk_id),
                    str(chunk.document_id),
                    chunk.ordinal,
                    chunk.text,
                    chunk.content_hash,
                    chunk.start_offset,
                    chunk.end_offset,
                    int(chunk.untrusted_content),
                )
                for chunk in chunks
            ],
        )

    def _document_values(self, document: IndexedDocument) -> tuple[object, ...]:
        return (
            str(document.document_id),
            str(document.source_id),
            document.workspace_id,
            document.source_identity,
            document.relative_path,
            document.name,
            document.mime_type,
            document.size,
            document.content_hash,
            _iso(document.modified_at),
            document.classification.value,
            _json_pairs(document.provenance),
            _json_pairs(document.metadata),
            _iso(document.indexed_at),
            int(document.deleted),
        )

    def _record_sync(
        self, source_id: UUID, status: KnowledgeSyncStatus, *, error: str | None
    ) -> None:
        with self._lock:
            self._connection.execute(
                "UPDATE knowledge_sync_states SET status = ?, last_sync_at = ?, error = ? "
                "WHERE source_id = ?",
                (status.value, _iso(self._clock()), error, str(source_id)),
            )
            self._connection.commit()

    @staticmethod
    def _semantic_score(terms: set[str], text: str) -> float:
        content_terms = _tokens(text)
        if not content_terms:
            return 0.0
        overlap = len(terms & content_terms)
        return float(overlap) / math.sqrt(float(len(terms | content_terms)))

    def _citation(self, document: IndexedDocument, chunk: DocumentChunk) -> KnowledgeCitation:
        return KnowledgeCitation(
            uuid4(),
            document.document_id,
            chunk.chunk_id,
            document.source_id,
            document.source_identity,
            document.relative_path,
            chunk.content_hash,
            chunk.text[:MAX_RESULT_TEXT],
            chunk.untrusted_content,
        )

    @staticmethod
    def _validate_migrations(migrations: Sequence[KnowledgeMigration]) -> None:
        versions = [migration.version for migration in migrations]
        if versions != list(range(1, len(versions) + 1)):
            raise KnowledgeLibraryMigrationError("Knowledge migrations must be contiguous")
        if any(not migration.name.strip() or not migration.sql.strip() for migration in migrations):
            raise KnowledgeLibraryMigrationError("Knowledge migration is incomplete")

    def _source_from_row(self, row: sqlite3.Row) -> KnowledgeSource:
        return KnowledgeSource(
            KnowledgeSourceKind(str(row["kind"])),
            str(row["location"]),
            str(row["workspace_id"]),
            DataClassification(str(row["classification"])),
            UUID(str(row["source_id"])),
            bool(row["recursive"]),
            bool(row["enabled"]),
            _pairs_from_json(str(row["metadata_json"])),
            _pairs_from_json(str(row["provenance_json"])),
            datetime.fromisoformat(str(row["created_at"])),
            datetime.fromisoformat(str(row["updated_at"])),
        )

    @staticmethod
    def _document_from_row(row: sqlite3.Row) -> IndexedDocument:
        return IndexedDocument(
            UUID(str(row["document_id"])),
            UUID(str(row["source_id"])),
            str(row["workspace_id"]),
            str(row["source_identity"]),
            str(row["relative_path"]),
            str(row["name"]),
            str(row["mime_type"]),
            int(row["size"]),
            str(row["content_hash"]),
            datetime.fromisoformat(str(row["modified_at"])),
            DataClassification(str(row["classification"])),
            _pairs_from_json(str(row["provenance_json"])),
            _pairs_from_json(str(row["metadata_json"])),
            datetime.fromisoformat(str(row["indexed_at"])),
            bool(row["deleted"]),
        )

    @staticmethod
    def _chunk_from_row(row: sqlite3.Row) -> DocumentChunk:
        return DocumentChunk(
            UUID(str(row["chunk_id"])),
            UUID(str(row["document_id"])),
            int(row["ordinal"]),
            str(row["text"]),
            str(row["content_hash"]),
            int(row["start_offset"]),
            int(row["end_offset"]),
            bool(row["untrusted_content"]),
        )

    def _integrity_check(self) -> None:
        row = self._connection.execute("PRAGMA integrity_check").fetchone()
        if row is None or str(row[0]).casefold() != "ok":
            raise KnowledgeLibraryMigrationError("Knowledge database integrity check failed")


def _has_reparse(path: Path) -> bool:
    if path.is_symlink() or bool(getattr(path, "is_junction", lambda: False)()):
        return True
    current = path
    while current.parent != current:
        if current.is_symlink() or bool(getattr(current, "is_junction", lambda: False)()):
            return True
        current = current.parent
    return False


SQLiteKnowledgeLibrary = KnowledgeLibrary


__all__ = [
    "DEFAULT_KNOWLEDGE_MIGRATIONS",
    "DocumentChunk",
    "IndexedDocument",
    "KnowledgeCitation",
    "KnowledgeClassification",
    "KnowledgeLibrary",
    "KnowledgeLibraryMigrationError",
    "KnowledgeMigration",
    "KnowledgeRetrievalMode",
    "KnowledgeSearchHit",
    "KnowledgeSource",
    "KnowledgeSourceKind",
    "KnowledgeSyncResult",
    "KnowledgeSyncStatus",
    "SQLiteKnowledgeLibrary",
    "SyncState",
]
