"""Canonical immutable artifact metadata and content store."""

from __future__ import annotations

import hashlib
import json
import os
import re
import sqlite3
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from enum import StrEnum
from pathlib import Path
from typing import BinaryIO, cast
from uuid import UUID, uuid4

from jarvis.events import EventBus, EventEnvelope, EventType
from jarvis.events.models import ArtifactCreated


class ArtifactClassification(StrEnum):
    PUBLIC = "public"
    INTERNAL = "internal"
    SENSITIVE = "sensitive"
    CONFIDENTIAL = "confidential"
    CREDENTIAL_SECRET = "credential_secret"


class ArtifactRetention(StrEnum):
    UNTIL_DELETED = "until_deleted"
    DAYS_7 = "7_days"
    DAYS_30 = "30_days"
    DAYS_365 = "365_days"


@dataclass(frozen=True, slots=True)
class ArtifactRetentionPolicy:
    policy: ArtifactRetention = ArtifactRetention.UNTIL_DELETED
    expires_at: datetime | None = None
    max_versions: int | None = None

    def __post_init__(self) -> None:
        if not isinstance(self.policy, ArtifactRetention):
            raise ValueError("Artifact retention policy is invalid")
        if self.max_versions is not None and self.max_versions < 1:
            raise ValueError("Artifact max_versions must be positive")

    def expiry(self, created_at: datetime) -> datetime | None:
        if self.expires_at is not None:
            return _utc(self.expires_at)
        days = {
            ArtifactRetention.DAYS_7: 7,
            ArtifactRetention.DAYS_30: 30,
            ArtifactRetention.DAYS_365: 365,
        }.get(self.policy)
        return created_at + timedelta(days=days) if days is not None else None


@dataclass(frozen=True, slots=True)
class ArtifactReference:
    artifact_id: UUID
    version: int
    workspace_id: str
    storage_reference: str


@dataclass(frozen=True, slots=True)
class ArtifactVersion:
    artifact_id: UUID
    version: int
    parent: ArtifactReference | None
    name: str
    mime_type: str
    size: int
    content_hash: str
    classification: ArtifactClassification
    producer: str
    provenance: tuple[str, ...]
    created_at: datetime
    retention: ArtifactRetentionPolicy
    reference: ArtifactReference


@dataclass(frozen=True, slots=True)
class ArtifactRecord:
    artifact_id: UUID
    goal_id: UUID | None
    task_id: UUID | None
    workspace_id: str
    created_at: datetime
    versions: tuple[ArtifactVersion, ...]


class ArtifactStore:
    """Single owner for durable artifact metadata and bytes."""

    _SCHEMA_VERSION = 1
    _MIGRATION_NAME = "create_artifacts"

    def __init__(self, root: Path, *, event_bus: EventBus | None = None) -> None:
        self._root = _safe_root(root)
        self._content_root = self._root / "content"
        self._content_root.mkdir(parents=True, exist_ok=True)
        _assert_safe_path(self._root, self._content_root)
        self._connection = sqlite3.connect(self._root / "artifacts.sqlite3", timeout=5.0)
        self._connection.execute("PRAGMA journal_mode=WAL")
        self._connection.execute("PRAGMA busy_timeout=5000")
        self._connection.execute("PRAGMA foreign_keys=ON")
        try:
            self._migrate()
        except Exception:
            self._connection.close()
            raise
        self._connection.execute(
            """
            CREATE TABLE IF NOT EXISTS artifacts (
                artifact_id TEXT PRIMARY KEY,
                goal_id TEXT,
                task_id TEXT,
                workspace_id TEXT NOT NULL,
                created_at TEXT NOT NULL
            )
            """
        )
        self._connection.execute(
            """
            CREATE TABLE IF NOT EXISTS artifact_versions (
                artifact_id TEXT NOT NULL REFERENCES artifacts(artifact_id),
                version INTEGER NOT NULL,
                parent_artifact_id TEXT,
                parent_version INTEGER,
                name TEXT NOT NULL,
                mime_type TEXT NOT NULL,
                size INTEGER NOT NULL,
                content_hash TEXT NOT NULL,
                classification TEXT NOT NULL,
                producer TEXT NOT NULL,
                provenance TEXT NOT NULL,
                created_at TEXT NOT NULL,
                retention TEXT NOT NULL,
                expires_at TEXT,
                max_versions INTEGER,
                storage_reference TEXT NOT NULL UNIQUE,
                PRIMARY KEY (artifact_id, version)
            )
            """
        )
        self._connection.commit()
        self._event_bus = event_bus

    def _migrate(self) -> None:
        """Version the metadata schema and refuse unknown future layouts."""

        self._connection.execute(
            "CREATE TABLE IF NOT EXISTS artifact_schema_migrations "
            "(version INTEGER PRIMARY KEY, name TEXT NOT NULL)"
        )
        rows = self._connection.execute(
            "SELECT version, name FROM artifact_schema_migrations"
        ).fetchall()
        versions = {int(row[0]): str(row[1]) for row in rows}
        if any(version > self._SCHEMA_VERSION for version in versions):
            raise OSError("Artifact database uses a future schema")
        if versions and versions.get(1) != self._MIGRATION_NAME:
            raise OSError("Artifact migration identity mismatch")
        if not versions:
            # Existing pre-versioned tables are preserved by IF NOT EXISTS;
            # the marker records their compatible baseline as version 1.
            self._connection.execute(
                "INSERT INTO artifact_schema_migrations(version, name) VALUES (?, ?)",
                (self._SCHEMA_VERSION, self._MIGRATION_NAME),
            )
        self._connection.commit()

    def put(
        self,
        *,
        workspace_id: str,
        name: str,
        content: bytes,
        mime_type: str,
        classification: ArtifactClassification,
        producer: str,
        provenance: tuple[str, ...] = (),
        goal_id: UUID | None = None,
        task_id: UUID | None = None,
        retention: ArtifactRetentionPolicy | None = None,
    ) -> ArtifactReference:
        self._validate_input(
            workspace_id, name, content, mime_type, classification, producer, provenance
        )
        policy = retention or ArtifactRetentionPolicy()
        artifact_id = uuid4()
        created_at = datetime.now(UTC)
        reference = self._write_version(
            artifact_id,
            1,
            workspace_id,
            name,
            content,
            mime_type,
            classification,
            producer,
            provenance,
            created_at,
            policy,
            goal_id,
            task_id,
            None,
        )
        return reference

    def derive(
        self,
        parent: ArtifactReference,
        *,
        workspace_id: str,
        name: str,
        content: bytes,
        mime_type: str,
        classification: ArtifactClassification,
        producer: str,
        provenance: tuple[str, ...] = (),
        retention: ArtifactRetentionPolicy | None = None,
    ) -> ArtifactReference:
        self._assert_reference(parent, workspace_id)
        self._validate_input(
            workspace_id, name, content, mime_type, classification, producer, provenance
        )
        row = self._connection.execute(
            "SELECT workspace_id FROM artifacts WHERE artifact_id=?", (str(parent.artifact_id),)
        ).fetchone()
        if row is None or str(row[0]) != workspace_id:
            raise PermissionError("Artifact is outside the requested workspace")
        next_version = self._connection.execute(
            "SELECT COALESCE(MAX(version), 0) + 1 FROM artifact_versions WHERE artifact_id=?",
            (str(parent.artifact_id),),
        ).fetchone()[0]
        return self._write_version(
            parent.artifact_id,
            int(next_version),
            workspace_id,
            name,
            content,
            mime_type,
            classification,
            producer,
            provenance,
            datetime.now(UTC),
            retention or ArtifactRetentionPolicy(),
            None,
            None,
            parent,
        )

    def read(self, reference: ArtifactReference, *, workspace_id: str) -> bytes:
        self._assert_reference(reference, workspace_id)
        row = self._connection.execute(
            """
            SELECT storage_reference, content_hash
            FROM artifact_versions WHERE artifact_id=? AND version=?
            """,
            (str(reference.artifact_id), reference.version),
        ).fetchone()
        if row is None or str(row[0]) != reference.storage_reference:
            raise KeyError("Unknown artifact version")
        path = self._content_root / str(row[0])
        _assert_safe_path(self._content_root, path)
        content = _read_owned_bytes(self._content_root, path)
        if hashlib.sha256(content).hexdigest() != str(row[1]):
            raise OSError("Artifact content integrity check failed")
        return content

    def get_version(self, reference: ArtifactReference, *, workspace_id: str) -> ArtifactVersion:
        self._assert_reference(reference, workspace_id)
        row = self._connection.execute(
            "SELECT * FROM artifact_versions WHERE artifact_id=? AND version=?",
            (str(reference.artifact_id), reference.version),
        ).fetchone()
        if row is None:
            raise KeyError("Unknown artifact version")
        return self._version_from_row(row, reference)

    def get_record(self, artifact_id: UUID, *, workspace_id: str) -> ArtifactRecord:
        row = self._connection.execute(
            "SELECT * FROM artifacts WHERE artifact_id=? AND workspace_id=?",
            (str(artifact_id), workspace_id),
        ).fetchone()
        if row is None:
            raise KeyError("Unknown artifact or workspace")
        versions = self._connection.execute(
            "SELECT * FROM artifact_versions WHERE artifact_id=? ORDER BY version",
            (str(artifact_id),),
        ).fetchall()
        return ArtifactRecord(
            artifact_id,
            UUID(str(row[1])) if row[1] else None,
            UUID(str(row[2])) if row[2] else None,
            workspace_id,
            datetime.fromisoformat(str(row[4])),
            tuple(
                self._version_from_row(
                    item,
                    ArtifactReference(artifact_id, int(str(item[1])), workspace_id, str(item[15])),
                )
                for item in versions
            ),
        )

    def purge_expired(self, *, now: datetime | None = None) -> int:
        current = _utc(now or datetime.now(UTC))
        rows = self._connection.execute(
            """
            SELECT artifact_id, version, storage_reference, expires_at
            FROM artifact_versions
            WHERE expires_at IS NOT NULL
            """
        ).fetchall()
        removed = 0
        for artifact_id, version, storage_reference, expires_at in rows:
            if datetime.fromisoformat(str(expires_at)) > current:
                continue
            path = self._content_root / str(storage_reference)
            _assert_safe_path(self._content_root, path)
            _unlink_owned(self._content_root, path, missing_ok=True)
            self._connection.execute(
                "DELETE FROM artifact_versions WHERE artifact_id=? AND version=?",
                (str(artifact_id), int(version)),
            )
            removed += 1
        self._connection.commit()
        return removed

    def close(self) -> None:
        self._connection.close()

    def _write_version(
        self,
        artifact_id: UUID,
        version: int,
        workspace_id: str,
        name: str,
        content: bytes,
        mime_type: str,
        classification: ArtifactClassification,
        producer: str,
        provenance: tuple[str, ...],
        created_at: datetime,
        retention: ArtifactRetentionPolicy,
        goal_id: UUID | None,
        task_id: UUID | None,
        parent: ArtifactReference | None,
    ) -> ArtifactReference:
        storage_reference = f"{artifact_id.hex}-{version}-{uuid4().hex}.bin"
        path = self._content_root / storage_reference
        _assert_safe_path(self._content_root, path)
        with _open_exclusive(path) as handle:
            handle.write(content)
        _assert_safe_path(self._content_root, path)
        reference = ArtifactReference(artifact_id, version, workspace_id, storage_reference)
        try:
            if version == 1:
                self._connection.execute(
                    "INSERT INTO artifacts VALUES (?, ?, ?, ?, ?)",
                    (
                        str(artifact_id),
                        _uuid(goal_id),
                        _uuid(task_id),
                        workspace_id,
                        created_at.isoformat(),
                    ),
                )
            expiry = retention.expiry(created_at)
            self._connection.execute(
                """
                INSERT INTO artifact_versions VALUES
                (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    str(artifact_id),
                    version,
                    str(parent.artifact_id) if parent else None,
                    parent.version if parent else None,
                    name,
                    mime_type,
                    len(content),
                    hashlib.sha256(content).hexdigest(),
                    classification.value,
                    producer,
                    _json_strings(provenance),
                    created_at.isoformat(),
                    retention.policy.value,
                    expiry.isoformat() if expiry else None,
                    retention.max_versions,
                    storage_reference,
                ),
            )
            self._connection.commit()
        except Exception:
            self._connection.rollback()
            _unlink_owned(self._content_root, path, missing_ok=True)
            raise
        if retention.max_versions is not None:
            self._trim_versions(artifact_id, retention.max_versions)
        if self._event_bus is not None:
            self._event_bus.publish_nowait(
                EventEnvelope.create(
                    EventType.ARTIFACT_CREATED,
                    ArtifactCreated(artifact_id, version, workspace_id, len(content)),
                    source="artifact.store",
                    task_id=task_id,
                    correlation_id=task_id or artifact_id,
                )
            )
        return reference

    def _trim_versions(self, artifact_id: UUID, max_versions: int) -> None:
        rows = self._connection.execute(
            """
            SELECT version, storage_reference FROM artifact_versions
            WHERE artifact_id=? ORDER BY version DESC
            """,
            (str(artifact_id),),
        ).fetchall()
        for version, storage_reference in rows[max_versions:]:
            path = self._content_root / str(storage_reference)
            _assert_safe_path(self._content_root, path)
            _unlink_owned(self._content_root, path, missing_ok=True)
            self._connection.execute(
                "DELETE FROM artifact_versions WHERE artifact_id=? AND version=?",
                (str(artifact_id), int(str(version))),
            )
        self._connection.commit()

    def _assert_reference(self, reference: ArtifactReference, workspace_id: str) -> None:
        if reference.workspace_id != workspace_id:
            raise PermissionError("Cross-workspace artifact access denied")
        if not _STORAGE_REFERENCE.fullmatch(reference.storage_reference):
            raise ValueError("Artifact storage reference is malformed")
        row = self._connection.execute(
            """
            SELECT v.storage_reference, a.workspace_id
            FROM artifact_versions AS v
            JOIN artifacts AS a ON a.artifact_id = v.artifact_id
            WHERE v.artifact_id=? AND v.version=?
            """,
            (str(reference.artifact_id), reference.version),
        ).fetchone()
        if row is None or str(row[0]) != reference.storage_reference or str(row[1]) != workspace_id:
            raise KeyError("Unknown artifact version")

    @staticmethod
    def _validate_input(
        workspace_id: str,
        name: str,
        content: bytes,
        mime_type: str,
        classification: ArtifactClassification,
        producer: str,
        provenance: tuple[str, ...],
    ) -> None:
        if not isinstance(workspace_id, str) or not workspace_id.strip() or len(workspace_id) > 128:
            raise ValueError("Artifact workspace is invalid")
        if (
            not isinstance(classification, ArtifactClassification)
            or not isinstance(provenance, tuple)
            or not all(isinstance(item, str) and item.strip() for item in provenance)
        ):
            raise ValueError("Artifact classification or provenance is invalid")
        if (
            not name.strip()
            or len(name) > 255
            or Path(name).name != name
            or name in {".", ".."}
            or "\\" in name
            or "/" in name
        ):
            raise ValueError("Artifact filename is unsafe")
        if (
            not isinstance(content, bytes)
            or not isinstance(mime_type, str)
            or not mime_type.strip()
        ):
            raise ValueError("Artifact content metadata is invalid")
        if classification is ArtifactClassification.CREDENTIAL_SECRET:
            raise PermissionError("Credential secrets cannot be stored as artifacts")
        if not producer.strip() or len(producer) > 256 or len(provenance) > 64:
            raise ValueError("Artifact provenance is invalid")

    def _version_from_row(
        self, row: tuple[object, ...], reference: ArtifactReference
    ) -> ArtifactVersion:
        expiry = datetime.fromisoformat(str(row[13])) if row[13] else None
        retention = ArtifactRetentionPolicy(
            ArtifactRetention(str(row[12])),
            expiry,
            int(str(row[14])) if row[14] else None,
        )
        parent = (
            ArtifactReference(
                UUID(str(row[2])),
                int(str(row[3])),
                reference.workspace_id,
                str(
                    self._connection.execute(
                        """
                        SELECT storage_reference FROM artifact_versions
                        WHERE artifact_id=? AND version=?
                        """,
                        (str(row[2]), int(str(row[3]))),
                    ).fetchone()[0]
                ),
            )
            if row[2] and row[3]
            else None
        )
        return ArtifactVersion(
            reference.artifact_id,
            int(str(row[1])),
            parent,
            str(row[4]),
            str(row[5]),
            int(str(row[6])),
            str(row[7]),
            ArtifactClassification(str(row[8])),
            str(row[9]),
            _strings_from_json(str(row[10])),
            datetime.fromisoformat(str(row[11])),
            retention,
            reference,
        )


_STORAGE_REFERENCE = re.compile(r"^[0-9a-f]{32}-[0-9]+-[0-9a-f]{32}\.bin$")


def _safe_root(root: Path) -> Path:
    candidate = root.expanduser().absolute()
    if _has_reparse_ancestor(candidate):
        raise OSError("Artifact root cannot contain a reparse point")
    resolved = candidate.resolve(strict=False)
    if _has_reparse_ancestor(resolved):
        raise OSError("Artifact root cannot contain a reparse point")
    resolved.mkdir(parents=True, exist_ok=True)
    return resolved


def _assert_safe_path(root: Path, path: Path) -> None:
    if _has_reparse_ancestor(root) or _has_reparse_ancestor(path):
        raise OSError("Artifact path contains a reparse point")
    resolved = path.resolve(strict=False)
    if _has_reparse_ancestor(resolved) or not resolved.is_relative_to(root):
        raise OSError("Artifact path escapes its owned root")


def _has_reparse_ancestor(path: Path) -> bool:
    current = path.expanduser().absolute()
    while True:
        junction = getattr(current, "is_junction", None)
        if current.is_symlink() or (callable(junction) and bool(junction())):
            return True
        if current == current.parent:
            return False
        current = current.parent


def _open_exclusive(path: Path) -> BinaryIO:
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    flags |= getattr(os, "O_BINARY", 0) | getattr(os, "O_NOFOLLOW", 0)
    descriptor = os.open(path, flags, 0o600)
    return os.fdopen(descriptor, "wb")


def _read_owned_bytes(root: Path, path: Path) -> bytes:
    _assert_safe_path(root, path)
    flags = os.O_RDONLY | getattr(os, "O_BINARY", 0) | getattr(os, "O_NOFOLLOW", 0)
    descriptor = os.open(path, flags)
    try:
        handle = cast(BinaryIO, os.fdopen(descriptor, "rb"))
        descriptor = -1
        try:
            return handle.read()
        finally:
            handle.close()
    finally:
        if descriptor >= 0:
            os.close(descriptor)


def _unlink_owned(root: Path, path: Path, *, missing_ok: bool = False) -> None:
    _assert_safe_path(root, path)
    if not path.exists():
        if missing_ok:
            return
        raise FileNotFoundError(path)
    _assert_safe_path(root, path)
    path.unlink()


def _utc(value: datetime) -> datetime:
    return value.replace(tzinfo=UTC) if value.tzinfo is None else value.astimezone(UTC)


def _uuid(value: UUID | None) -> str | None:
    return str(value) if value else None


def _json_strings(values: tuple[str, ...]) -> str:
    return json.dumps(values)


def _strings_from_json(value: str) -> tuple[str, ...]:
    return tuple(str(item) for item in json.loads(value))
