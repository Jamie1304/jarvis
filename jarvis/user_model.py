"""Canonical local user facts and preferences.

The user model is deliberately separate from conversation, episodic memory, and
task truth.  It accepts structured records only; it is not a transcript store,
credential store, permission source, or execution policy.
"""

from __future__ import annotations

import hashlib
import json
import math
import sqlite3
import threading
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass, replace
from datetime import UTC, datetime
from enum import StrEnum
from pathlib import Path
from typing import Final
from uuid import UUID, uuid4

from jarvis.memory.models import RetentionPolicy, Sensitivity
from jarvis.memory.policy import contains_secret


class UserModelMigrationError(RuntimeError):
    """The user-model database cannot be safely opened or migrated."""


class UserModelKind(StrEnum):
    FACT = "fact"
    PREFERENCE = "preference"


class UserModelSource(StrEnum):
    USER = "user"
    APPLICATION = "application"
    MODEL = "model"
    IMPORT = "import"


class UserModelOrigin(StrEnum):
    EXPLICIT = "explicit"
    INFERRED = "inferred"


class UserModelAuditAction(StrEnum):
    CREATED = "created"
    CORRECTED = "corrected"
    VERIFIED = "verified"
    DELETED = "deleted"
    PURGED = "purged"


_SAFE_SENSITIVITIES: Final[frozenset[Sensitivity]] = frozenset(
    {Sensitivity.PUBLIC, Sensitivity.PRIVATE, Sensitivity.SENSITIVE}
)
_SECRET_KEY_WORDS: Final[frozenset[str]] = frozenset(
    {
        "api_key",
        "apikey",
        "authorization",
        "credential",
        "password",
        "private_key",
        "secret",
        "token",
    }
)
_RAW_UTTERANCE_KEYS: Final[frozenset[str]] = frozenset(
    {"conversation", "raw_text", "transcript", "utterance"}
)


def _utc(value: datetime) -> datetime:
    if value.tzinfo is None:
        return value.replace(tzinfo=UTC)
    return value.astimezone(UTC)


def _now() -> datetime:
    return datetime.now(UTC)


def _text(value: str, name: str, limit: int) -> None:
    if type(value) is not str or not value.strip() or len(value) > limit or "\x00" in value:
        raise ValueError(f"{name} must be bounded, non-empty, and NUL-free")
    if "\r" in value or "\n" in value:
        raise ValueError(f"{name} must be single-line")


def _workspace(value: str | None) -> None:
    if value is not None:
        _text(value, "Workspace ID", 128)


def _secret_key(key: str) -> bool:
    normalized = key.casefold().replace("-", "_").replace(" ", "_")
    return normalized in _SECRET_KEY_WORDS or any(
        word in normalized.split("_") for word in _SECRET_KEY_WORDS
    )


def _validate_json(value: object, *, depth: int = 0) -> None:
    if depth > 6:
        raise ValueError("User-model value is too deeply nested")
    if value is None or isinstance(value, bool) or isinstance(value, int):
        return
    if isinstance(value, float):
        if not math.isfinite(value):
            raise ValueError("User-model value contains a non-finite number")
        return
    if isinstance(value, str):
        if len(value) > 4_000 or "\x00" in value or contains_secret(value):
            raise PermissionError("Credential-like user-model content is not stored")
        return
    if isinstance(value, Mapping):
        if len(value) > 64:
            raise ValueError("User-model object has too many fields")
        for key, child in value.items():
            if type(key) is not str:
                raise ValueError("User-model object keys must be strings")
            _text(key, "User-model value key", 128)
            if _secret_key(key):
                raise PermissionError("Credential-like user-model fields are not stored")
            if key.casefold() in _RAW_UTTERANCE_KEYS:
                raise ValueError("Raw utterances are not user-model records")
            _validate_json(child, depth=depth + 1)
        return
    if isinstance(value, list | tuple):
        if len(value) > 64:
            raise ValueError("User-model value array is too large")
        for child in value:
            _validate_json(child, depth=depth + 1)
        return
    raise ValueError("User-model value must be JSON data")


def _canonical_value(value: object) -> object:
    _validate_json(value)
    try:
        encoded = json.dumps(value, sort_keys=True, separators=(",", ":"), allow_nan=False)
        canonical = json.loads(encoded)
    except (TypeError, ValueError, json.JSONDecodeError) as error:
        raise ValueError("User-model value must be canonical JSON") from error
    if len(encoded) > 16_000:
        raise ValueError("User-model value is too large")
    return canonical


@dataclass(frozen=True, slots=True)
class UserModelRelationship:
    """A bounded, non-authoritative link to another application entity."""

    relation: str
    target_id: str

    def __post_init__(self) -> None:
        _text(self.relation, "User-model relationship", 64)
        _text(self.target_id, "User-model relationship target", 256)
        if contains_secret(self.target_id):
            raise PermissionError("Credential-like relationship targets are not stored")


@dataclass(frozen=True, slots=True)
class UserModelRecord:
    """The current structured value for one user-model key in one workspace."""

    record_id: UUID
    workspace_id: str | None
    key: str
    kind: UserModelKind
    category: str
    value: object
    source: UserModelSource
    source_reference: str
    confidence: float
    created_at: datetime
    updated_at: datetime
    last_verified_at: datetime | None
    sensitivity: Sensitivity
    retention: RetentionPolicy
    origin: UserModelOrigin
    relationships: tuple[UserModelRelationship, ...] = ()
    revision: int = 1
    active: bool = True

    def __post_init__(self) -> None:
        if not isinstance(self.record_id, UUID):
            raise ValueError("User-model record ID must be a UUID")
        _workspace(self.workspace_id)
        _text(self.key, "User-model key", 128)
        if not isinstance(self.kind, UserModelKind):
            raise ValueError("User-model kind must be recognized")
        _text(self.category, "User-model category", 128)
        if not isinstance(self.source, UserModelSource):
            raise ValueError("User-model source must be recognized")
        _text(self.source_reference, "User-model source reference", 256)
        if contains_secret(self.source_reference):
            raise PermissionError("Credential-like source references are not stored")
        if not isinstance(self.origin, UserModelOrigin):
            raise ValueError("User-model origin must be recognized")
        if self.origin is UserModelOrigin.EXPLICIT and self.source is not UserModelSource.USER:
            raise PermissionError("Only the user source may create explicit user-model values")
        if not 0 <= self.confidence <= 1:
            raise ValueError("User-model confidence must be between zero and one")
        if not isinstance(self.sensitivity, Sensitivity) or self.sensitivity is Sensitivity.SECRET:
            raise PermissionError("Secret user-model sensitivity requires CredentialVault")
        if not isinstance(self.retention, RetentionPolicy):
            raise ValueError("User-model retention must be recognized")
        if not isinstance(self.relationships, tuple) or len(self.relationships) > 32:
            raise ValueError("User-model relationships must be a bounded tuple")
        if any(not isinstance(item, UserModelRelationship) for item in self.relationships):
            raise ValueError("User-model relationships must be typed")
        if self.revision < 1 or type(self.active) is not bool:
            raise ValueError("User-model revision or active state is invalid")
        created = _utc(self.created_at)
        updated = _utc(self.updated_at)
        verified = _utc(self.last_verified_at) if self.last_verified_at is not None else None
        if updated < created or (verified is not None and verified < created):
            raise ValueError("User-model timestamps are inconsistent")
        object.__setattr__(self, "created_at", created)
        object.__setattr__(self, "updated_at", updated)
        object.__setattr__(self, "last_verified_at", verified)
        object.__setattr__(self, "value", _canonical_value(self.value))

    @property
    def explicit(self) -> bool:
        """Compatibility-friendly view; origin remains the persisted source of truth."""

        return self.origin is UserModelOrigin.EXPLICIT

    @property
    def expires_at(self) -> datetime | None:
        return self.retention.expiry(self.created_at)

    @property
    def value_json(self) -> str:
        return json.dumps(self.value, sort_keys=True, separators=(",", ":"), allow_nan=False)


@dataclass(frozen=True, slots=True)
class UserModelAuditEntry:
    """Tamper-evident lifecycle evidence without retaining old sensitive values."""

    audit_id: UUID
    record_id: UUID
    action: UserModelAuditAction
    occurred_at: datetime
    actor: str
    reason: str
    revision: int
    old_value_hash: str | None
    new_value_hash: str | None

    def __post_init__(self) -> None:
        if not isinstance(self.audit_id, UUID) or not isinstance(self.record_id, UUID):
            raise ValueError("User-model audit IDs must be UUIDs")
        if not isinstance(self.action, UserModelAuditAction):
            raise ValueError("User-model audit action must be recognized")
        _text(self.actor, "User-model audit actor", 128)
        _text(self.reason, "User-model audit reason", 512)
        if self.revision < 1:
            raise ValueError("User-model audit revision must be positive")
        if _invalid_hash(self.old_value_hash) or _invalid_hash(self.new_value_hash):
            raise ValueError("User-model audit value hashes must be lowercase SHA-256 values")
        object.__setattr__(self, "occurred_at", _utc(self.occurred_at))


def _invalid_hash(value: str | None) -> bool:
    return value is not None and (
        len(value) != 64 or any(character not in "0123456789abcdef" for character in value)
    )


@dataclass(frozen=True, slots=True)
class UserModelContextPolicy:
    """Explicit retrieval policy; it is a data filter, never a permission grant."""

    workspace_id: str
    allowed_sensitivities: frozenset[Sensitivity] = frozenset(_SAFE_SENSITIVITIES)
    categories: tuple[str, ...] = ()
    keys: tuple[str, ...] = ()
    include_inferred: bool = True
    allow_cloud: bool = False
    limit: int = 32

    def __post_init__(self) -> None:
        _text(self.workspace_id, "Context workspace ID", 128)
        if not self.allowed_sensitivities <= _SAFE_SENSITIVITIES:
            raise PermissionError("User-model cloud/context policy cannot include secrets")
        if len(self.categories) > 64 or len(self.keys) > 64:
            raise ValueError("User-model context filters are bounded")
        for value in (*self.categories, *self.keys):
            _text(value, "User-model context filter", 128)
        if self.limit < 1 or self.limit > 256:
            raise ValueError("User-model context limit is invalid")
        if type(self.include_inferred) is not bool or type(self.allow_cloud) is not bool:
            raise ValueError("User-model context policy flags are invalid")

    @classmethod
    def local(cls, workspace_id: str, *, limit: int = 32) -> UserModelContextPolicy:
        return cls(workspace_id, limit=limit)

    @classmethod
    def cloud_public(cls, workspace_id: str, *, limit: int = 32) -> UserModelContextPolicy:
        return cls(
            workspace_id,
            allowed_sensitivities=frozenset({Sensitivity.PUBLIC}),
            allow_cloud=True,
            limit=limit,
        )


@dataclass(frozen=True, slots=True)
class UserModelContext:
    """A bounded, labeled view suitable for a provider; no direct network behavior."""

    workspace_id: str
    records: tuple[UserModelRecord, ...]
    cloud_allowed: bool

    def export_for_cloud(self) -> tuple[dict[str, object], ...]:
        if not self.cloud_allowed:
            raise PermissionError("Cloud export requires an explicit cloud context policy")
        return tuple(
            {
                "key": record.key,
                "kind": record.kind.value,
                "category": record.category,
                "value": record.value,
                "confidence": record.confidence,
                "origin": record.origin.value,
                "last_verified_at": (
                    record.last_verified_at.isoformat() if record.last_verified_at else None
                ),
            }
            for record in self.records
        )


@dataclass(frozen=True, slots=True)
class UserModelMigration:
    version: int
    name: str
    sql: str

    def __post_init__(self) -> None:
        if self.version <= 0:
            raise ValueError("User-model migration version must be positive")
        _text(self.name, "User-model migration name", 128)
        if not self.sql.strip() or "\x00" in self.sql:
            raise ValueError("User-model migration SQL is invalid")


DEFAULT_USER_MODEL_MIGRATIONS: tuple[UserModelMigration, ...] = (
    UserModelMigration(
        1,
        "create_user_model",
        """
        CREATE TABLE user_model_records (
            record_id TEXT PRIMARY KEY,
            workspace_id TEXT NOT NULL,
            model_key TEXT NOT NULL,
            kind TEXT NOT NULL,
            category TEXT NOT NULL,
            value_json TEXT NOT NULL,
            source TEXT NOT NULL,
            source_reference TEXT NOT NULL,
            confidence REAL NOT NULL,
            created_at TEXT NOT NULL,
            updated_at TEXT NOT NULL,
            last_verified_at TEXT,
            sensitivity TEXT NOT NULL,
            retention TEXT NOT NULL,
            origin TEXT NOT NULL,
            relationships_json TEXT NOT NULL,
            revision INTEGER NOT NULL,
            active INTEGER NOT NULL
        );
        CREATE INDEX user_model_records_scope ON user_model_records(workspace_id, active);
        CREATE UNIQUE INDEX user_model_active_key
            ON user_model_records(workspace_id, model_key, kind) WHERE active = 1;
        CREATE TABLE user_model_audit (
            audit_id TEXT PRIMARY KEY,
            record_id TEXT NOT NULL,
            action TEXT NOT NULL,
            occurred_at TEXT NOT NULL,
            actor TEXT NOT NULL,
            reason TEXT NOT NULL,
            revision INTEGER NOT NULL,
            old_value_hash TEXT,
            new_value_hash TEXT,
            FOREIGN KEY(record_id) REFERENCES user_model_records(record_id)
        );
        CREATE INDEX user_model_audit_record ON user_model_audit(record_id, occurred_at);
        """,
    ),
)


class UserModelStore:
    """The sole durable owner for structured user facts and preferences."""

    def __init__(
        self,
        database_path: Path,
        *,
        migrations: Sequence[UserModelMigration] = DEFAULT_USER_MODEL_MIGRATIONS,
        clock: Callable[[], datetime] = _now,
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
        self._closed = False
        self._integrity_check()
        self.apply_migrations()

    @property
    def database_path(self) -> Path:
        return self._path

    def __enter__(self) -> UserModelStore:
        return self

    def __exit__(self, _type: object, _value: object, _traceback: object) -> None:
        self.close()

    def close(self) -> None:
        with self._lock:
            if not self._closed:
                self._connection.close()
                self._closed = True

    def schema_version(self) -> int:
        self._ensure_open()
        with self._lock:
            row = self._connection.execute(
                "SELECT COALESCE(MAX(version), 0) AS version FROM user_model_schema_migrations"
            ).fetchone()
        return int(row["version"] if row is not None else 0)

    def apply_migrations(self) -> None:
        self._ensure_open()
        with self._lock:
            try:
                self._connection.execute(
                    "CREATE TABLE IF NOT EXISTS user_model_schema_migrations "
                    "(version INTEGER PRIMARY KEY, name TEXT NOT NULL, applied_at TEXT NOT NULL)"
                )
                applied = {
                    int(row["version"]): str(row["name"])
                    for row in self._connection.execute(
                        "SELECT version, name FROM user_model_schema_migrations"
                    )
                }
                if any(version > len(self._migrations) for version in applied):
                    raise UserModelMigrationError("User-model database uses a future schema")
                for migration in self._migrations:
                    existing = applied.get(migration.version)
                    if existing is not None:
                        if existing != migration.name:
                            raise UserModelMigrationError("User-model migration identity mismatch")
                        continue
                    self._connection.executescript(migration.sql)
                    self._connection.execute(
                        "INSERT INTO user_model_schema_migrations(version, name, applied_at) "
                        "VALUES (?, ?, ?)",
                        (migration.version, migration.name, self._iso(self._clock())),
                    )
                self._connection.commit()
            except (sqlite3.DatabaseError, ValueError, UserModelMigrationError) as error:
                self._connection.rollback()
                if isinstance(error, UserModelMigrationError):
                    raise
                raise UserModelMigrationError("User-model migration failed") from error

    def create(self, record: UserModelRecord) -> UserModelRecord:
        """Create a structured record; corrections use :meth:`correct`."""

        self._ensure_open()
        self._validate_record(record)
        with self._lock:
            try:
                self._connection.execute(
                    "INSERT INTO user_model_records VALUES "
                    "(?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                    self._record_values(record),
                )
                self._audit_locked(
                    record,
                    UserModelAuditAction.CREATED,
                    actor=record.source.value,
                    reason="record created",
                    old_value=None,
                )
                self._connection.commit()
            except sqlite3.IntegrityError as error:
                self._connection.rollback()
                raise ValueError("An active user-model key already exists") from error
        return record

    put = create

    def get(self, record_id: UUID, *, include_deleted: bool = False) -> UserModelRecord | None:
        self._ensure_open()
        self.cleanup_expired()
        with self._lock:
            query = "SELECT * FROM user_model_records WHERE record_id = ?"
            params: tuple[object, ...] = (str(record_id),)
            if not include_deleted:
                query += " AND active = 1"
            row = self._connection.execute(query, params).fetchone()
        return self._record(row) if row is not None else None

    def correct(
        self,
        record_id: UUID,
        *,
        value: object,
        source_reference: str,
        now: datetime | None = None,
        sensitivity: Sensitivity | None = None,
        retention: RetentionPolicy | None = None,
        relationships: tuple[UserModelRelationship, ...] | None = None,
        reason: str = "user correction",
    ) -> UserModelRecord:
        """Apply an explicit user correction while preserving revision/audit history."""

        self._ensure_open()
        current = self.get(record_id)
        if current is None:
            raise KeyError("Unknown or deleted user-model record")
        timestamp = _utc(now or self._clock())
        updated = replace(
            current,
            value=value,
            source=UserModelSource.USER,
            source_reference=source_reference,
            origin=UserModelOrigin.EXPLICIT,
            sensitivity=sensitivity or current.sensitivity,
            retention=retention or current.retention,
            relationships=relationships if relationships is not None else current.relationships,
            updated_at=timestamp,
            last_verified_at=timestamp,
            revision=current.revision + 1,
        )
        _text(reason, "User-model correction reason", 512)
        self._validate_record(updated)
        with self._lock:
            self._connection.execute(
                "UPDATE user_model_records SET value_json=?, source=?, source_reference=?, "
                "confidence=?, updated_at=?, last_verified_at=?, sensitivity=?, retention=?, "
                "origin=?, relationships_json=?, revision=?, active=1 WHERE record_id=?",
                (
                    updated.value_json,
                    updated.source.value,
                    updated.source_reference,
                    updated.confidence,
                    self._iso(updated.updated_at),
                    self._iso(updated.last_verified_at) if updated.last_verified_at else None,
                    updated.sensitivity.value,
                    updated.retention.value,
                    updated.origin.value,
                    self._relationships_json(updated.relationships),
                    updated.revision,
                    str(record_id),
                ),
            )
            self._audit_locked(
                updated,
                UserModelAuditAction.CORRECTED,
                actor=UserModelSource.USER.value,
                reason=reason,
                old_value=current,
            )
            self._connection.commit()
        return updated

    def verify(self, record_id: UUID, *, now: datetime | None = None) -> UserModelRecord:
        self._ensure_open()
        current = self.get(record_id)
        if current is None:
            raise KeyError("Unknown or deleted user-model record")
        timestamp = _utc(now or self._clock())
        updated = replace(current, updated_at=timestamp, last_verified_at=timestamp)
        with self._lock:
            self._connection.execute(
                "UPDATE user_model_records SET updated_at=?, last_verified_at=? WHERE record_id=?",
                (self._iso(timestamp), self._iso(timestamp), str(record_id)),
            )
            self._audit_locked(
                updated,
                UserModelAuditAction.VERIFIED,
                actor=UserModelSource.APPLICATION.value,
                reason="record verified",
                old_value=current,
            )
            self._connection.commit()
        return updated

    def delete(self, record_id: UUID, *, reason: str = "user deletion") -> bool:
        self._ensure_open()
        _text(reason, "User-model deletion reason", 512)
        current = self.get(record_id)
        if current is None:
            return False
        timestamp = _utc(self._clock())
        with self._lock:
            self._connection.execute(
                "UPDATE user_model_records SET active=0, updated_at=? WHERE record_id=?",
                (self._iso(timestamp), str(record_id)),
            )
            deleted = replace(current, active=False, updated_at=timestamp)
            self._audit_locked(
                deleted,
                UserModelAuditAction.DELETED,
                actor=UserModelSource.USER.value,
                reason=reason,
                old_value=current,
            )
            self._connection.commit()
        return True

    def list(
        self,
        *,
        workspace_id: str | None = None,
        include_global: bool = True,
        include_inferred: bool = True,
    ) -> tuple[UserModelRecord, ...]:
        self._ensure_open()
        if workspace_id is not None:
            _workspace(workspace_id)
        self.cleanup_expired()
        clauses = ["active = 1"]
        params: list[object] = []
        if workspace_id is not None:
            if include_global:
                clauses.append("workspace_id IN (?, ?)")
                params.extend([workspace_id, ""])
            else:
                clauses.append("workspace_id = ?")
                params.append(workspace_id)
        if not include_inferred:
            clauses.append("origin = ?")
            params.append(UserModelOrigin.EXPLICIT.value)
        with self._lock:
            rows = tuple(
                self._connection.execute(
                    "SELECT * FROM user_model_records WHERE "
                    + " AND ".join(clauses)
                    + " ORDER BY updated_at DESC, record_id",
                    tuple(params),
                )
            )
        return tuple(self._record(row) for row in rows)

    def query(self, policy: UserModelContextPolicy) -> tuple[UserModelRecord, ...]:
        if not isinstance(policy, UserModelContextPolicy):
            raise ValueError("User-model query requires a typed context policy")
        records = self.list(
            workspace_id=policy.workspace_id,
            include_global=True,
            include_inferred=policy.include_inferred,
        )
        selected = [
            record
            for record in records
            if record.sensitivity in policy.allowed_sensitivities
            and (not policy.categories or record.category in policy.categories)
            and (not policy.keys or record.key in policy.keys)
        ]
        selected.sort(
            key=lambda record: (
                record.key,
                0 if record.explicit else 1,
                -record.confidence,
                record.updated_at,
                str(record.record_id),
            )
        )
        return tuple(selected[: policy.limit])

    def context_for(self, policy: UserModelContextPolicy) -> UserModelContext:
        return UserModelContext(policy.workspace_id, self.query(policy), policy.allow_cloud)

    def audit(self, record_id: UUID | None = None) -> tuple[UserModelAuditEntry, ...]:
        self._ensure_open()
        query = "SELECT * FROM user_model_audit"
        params: tuple[object, ...] = ()
        if record_id is not None:
            query += " WHERE record_id = ?"
            params = (str(record_id),)
        query += " ORDER BY occurred_at, rowid"
        with self._lock:
            rows = tuple(self._connection.execute(query, params))
        return tuple(self._audit(row) for row in rows)

    def purge_expired(self, *, now: datetime | None = None) -> int:
        self._ensure_open()
        timestamp = _utc(now or self._clock())
        with self._lock:
            rows = tuple(
                self._connection.execute(
                    "SELECT * FROM user_model_records WHERE active=1 AND retention != ?",
                    (RetentionPolicy.UNTIL_DELETED.value,),
                )
            )
            purged = 0
            for row in rows:
                record = self._record(row)
                if record.expires_at is None or record.expires_at > timestamp:
                    continue
                deleted = replace(record, active=False, updated_at=timestamp)
                self._connection.execute(
                    "UPDATE user_model_records SET active=0, updated_at=? WHERE record_id=?",
                    (self._iso(timestamp), str(record.record_id)),
                )
                self._audit_locked(
                    deleted,
                    UserModelAuditAction.PURGED,
                    actor="retention",
                    reason="retention expiry",
                    old_value=record,
                )
                purged += 1
            self._connection.commit()
        return purged

    def cleanup_expired(self) -> int:
        return self.purge_expired()

    def _validate_record(self, record: UserModelRecord) -> None:
        if not isinstance(record, UserModelRecord):
            raise ValueError("User-model store accepts typed records only")
        if (
            record.active
            and record.expires_at is not None
            and record.expires_at <= _utc(self._clock())
        ):
            raise ValueError("Expired user-model records cannot be created")

    def _ensure_open(self) -> None:
        if self._closed:
            raise RuntimeError("User-model store is closed")

    def _integrity_check(self) -> None:
        try:
            row = self._connection.execute("PRAGMA integrity_check").fetchone()
        except sqlite3.DatabaseError as error:
            raise UserModelMigrationError("User-model integrity check failed") from error
        if row is None or str(row[0]).casefold() != "ok":
            raise UserModelMigrationError("User-model database is corrupt")

    def _validate_migrations(self) -> None:
        expected = 1
        for migration in self._migrations:
            if migration.version != expected:
                raise UserModelMigrationError("User-model migrations must be sequential")
            expected += 1

    @staticmethod
    def _db_workspace(value: str | None) -> str:
        return value or ""

    def _record_values(self, record: UserModelRecord) -> tuple[object, ...]:
        return (
            str(record.record_id),
            self._db_workspace(record.workspace_id),
            record.key,
            record.kind.value,
            record.category,
            record.value_json,
            record.source.value,
            record.source_reference,
            record.confidence,
            self._iso(record.created_at),
            self._iso(record.updated_at),
            self._iso(record.last_verified_at) if record.last_verified_at else None,
            record.sensitivity.value,
            record.retention.value,
            record.origin.value,
            self._relationships_json(record.relationships),
            record.revision,
            int(record.active),
        )

    @staticmethod
    def _relationships_json(values: tuple[UserModelRelationship, ...]) -> str:
        return json.dumps(
            [{"relation": value.relation, "target_id": value.target_id} for value in values],
            sort_keys=True,
            separators=(",", ":"),
        )

    def _audit_locked(
        self,
        record: UserModelRecord,
        action: UserModelAuditAction,
        *,
        actor: str,
        reason: str,
        old_value: UserModelRecord | None,
    ) -> None:
        entry = UserModelAuditEntry(
            uuid4(),
            record.record_id,
            action,
            _utc(self._clock()),
            actor,
            reason,
            record.revision,
            self._value_hash(old_value) if old_value else None,
            self._value_hash(record) if record.active else None,
        )
        self._connection.execute(
            "INSERT INTO user_model_audit VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
            (
                str(entry.audit_id),
                str(entry.record_id),
                entry.action.value,
                self._iso(entry.occurred_at),
                entry.actor,
                entry.reason,
                entry.revision,
                entry.old_value_hash,
                entry.new_value_hash,
            ),
        )

    @staticmethod
    def _value_hash(record: UserModelRecord) -> str:
        return hashlib.sha256(record.value_json.encode("utf-8")).hexdigest()

    @staticmethod
    def _iso(value: datetime) -> str:
        return _utc(value).isoformat()

    @staticmethod
    def _record(row: sqlite3.Row) -> UserModelRecord:
        try:
            relationships_raw = json.loads(str(row["relationships_json"]))
            if not isinstance(relationships_raw, list):
                raise ValueError("relationships are not a list")
            relationships = tuple(
                UserModelRelationship(str(item["relation"]), str(item["target_id"]))
                for item in relationships_raw
                if isinstance(item, dict) and "relation" in item and "target_id" in item
            )
            if len(relationships) != len(relationships_raw):
                raise ValueError("relationships are malformed")
            return UserModelRecord(
                record_id=UUID(str(row["record_id"])),
                workspace_id=str(row["workspace_id"]) or None,
                key=str(row["model_key"]),
                kind=UserModelKind(str(row["kind"])),
                category=str(row["category"]),
                value=json.loads(str(row["value_json"])),
                source=UserModelSource(str(row["source"])),
                source_reference=str(row["source_reference"]),
                confidence=float(row["confidence"]),
                created_at=datetime.fromisoformat(str(row["created_at"])),
                updated_at=datetime.fromisoformat(str(row["updated_at"])),
                last_verified_at=(
                    datetime.fromisoformat(str(row["last_verified_at"]))
                    if row["last_verified_at"]
                    else None
                ),
                sensitivity=Sensitivity(str(row["sensitivity"])),
                retention=RetentionPolicy(str(row["retention"])),
                origin=UserModelOrigin(str(row["origin"])),
                relationships=relationships,
                revision=int(row["revision"]),
                active=bool(row["active"]),
            )
        except (KeyError, TypeError, ValueError, json.JSONDecodeError) as error:
            raise UserModelMigrationError("Stored user-model record is malformed") from error

    @staticmethod
    def _audit(row: sqlite3.Row) -> UserModelAuditEntry:
        try:
            return UserModelAuditEntry(
                UUID(str(row["audit_id"])),
                UUID(str(row["record_id"])),
                UserModelAuditAction(str(row["action"])),
                datetime.fromisoformat(str(row["occurred_at"])),
                str(row["actor"]),
                str(row["reason"]),
                int(row["revision"]),
                str(row["old_value_hash"]) if row["old_value_hash"] else None,
                str(row["new_value_hash"]) if row["new_value_hash"] else None,
            )
        except (KeyError, TypeError, ValueError) as error:
            raise UserModelMigrationError("Stored user-model audit is malformed") from error


SQLiteUserModelStore = UserModelStore


__all__ = [
    "DEFAULT_USER_MODEL_MIGRATIONS",
    "SQLiteUserModelStore",
    "UserModelAuditAction",
    "UserModelAuditEntry",
    "UserModelContext",
    "UserModelContextPolicy",
    "UserModelKind",
    "UserModelMigration",
    "UserModelMigrationError",
    "UserModelOrigin",
    "UserModelRecord",
    "UserModelRelationship",
    "UserModelSource",
    "UserModelStore",
]
