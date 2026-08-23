"""Trusted, local snapshot and startup-recovery coordinator.

Recovery records are evidence and restore metadata.  They never grant
permission, activate integrations, or replace the planning/policy stores.
"""

from __future__ import annotations

import json
import os
import shutil
import tempfile
from collections.abc import Callable
from dataclasses import asdict, dataclass
from datetime import UTC, datetime
from enum import StrEnum
from pathlib import Path
from typing import Any, cast
from uuid import UUID, uuid4


class RecoveryError(RuntimeError):
    """Recovery metadata or a restore operation was unsafe or unavailable."""


class RecoveryPhase(StrEnum):
    PREPARE = "prepare"
    SNAPSHOT = "snapshot"
    APPLY = "apply"
    START = "start"
    HEALTH_CHECK = "health_check"
    COMMIT = "commit"
    FAIL = "fail"
    ROLLBACK = "rollback"
    RESTORE_LAST_KNOWN_GOOD = "restore_last_known_good"
    SAFE_MODE = "safe_mode"


@dataclass(frozen=True, slots=True)
class RecoveryManifest:
    snapshot_id: str
    transaction_id: str
    created_at: str
    app_revision: str
    configuration: dict[str, Any]
    database_schema: dict[str, Any]
    integration_versions: dict[str, str]
    migrations: tuple[str, ...]
    generated_package_state: dict[str, Any]
    files: tuple[str, ...]
    schema_version: int = 1


@dataclass(frozen=True, slots=True)
class RecoveryEvidence:
    transaction_id: str
    phase: RecoveryPhase
    outcome: str
    detail: str
    snapshot_id: str | None
    timestamp: str


@dataclass(frozen=True, slots=True)
class SafeModeCapabilities:
    diagnostics: bool = True
    audit: bool = True
    rollback: bool = True
    safe_ui: bool = True
    privileged_mutations: bool = False
    generated_integration_activation: bool = False
    autonomous_self_update: bool = False
    scheduler_effects: bool = False


class RecoveryStore:
    """The only owner of recovery snapshots, markers, LKG, and evidence."""

    CURRENT_SCHEMA = 1
    _MAX_TEXT = 512

    def __init__(self, root: Path, *, retention: int = 5) -> None:
        if retention < 1 or retention > 100:
            raise ValueError("retention must be between 1 and 100")
        root = root.expanduser()
        if root.is_symlink() or root.is_junction() or (root.exists() and not root.is_dir()):
            raise RecoveryError("recovery root is not a private directory")
        self.root = root.resolve()
        self.snapshots = self.root / "snapshots"
        self.evidence = self.root / "evidence.jsonl"
        self.active = self.root / "active-start.json"
        self.lkg = self.root / "last-known-good.json"
        self.retention = retention
        self.root.mkdir(parents=True, exist_ok=True)
        self.snapshots.mkdir(exist_ok=True)

    def create_snapshot(
        self,
        *,
        transaction_id: UUID | str,
        app_revision: str,
        configuration: dict[str, Any],
        database_schema: dict[str, Any],
        integration_versions: dict[str, str],
        migrations: tuple[str, ...] = (),
        generated_package_state: dict[str, Any] | None = None,
        files: tuple[Path, ...] = (),
    ) -> RecoveryManifest:
        tx = _bounded_text(str(transaction_id), "transaction_id")
        snapshot_id = str(uuid4())
        safe_files: list[str] = []
        for source in files:
            source = source.expanduser().resolve(strict=True)
            try:
                relative = source.relative_to(self.root)
            except ValueError as error:
                raise RecoveryError("snapshot source escaped recovery root") from error
            if not source.is_file() or source.is_symlink():
                raise RecoveryError("snapshot source is not a regular file")
            safe_files.append(relative.as_posix())
        manifest = RecoveryManifest(
            snapshot_id=snapshot_id,
            transaction_id=tx,
            created_at=datetime.now(UTC).isoformat(),
            app_revision=_bounded_text(app_revision, "app_revision"),
            configuration=_safe_json_mapping(configuration, "configuration"),
            database_schema=_safe_json_mapping(database_schema, "database_schema"),
            integration_versions=_safe_string_mapping(integration_versions),
            migrations=tuple(_bounded_text(item, "migration") for item in migrations),
            generated_package_state=_safe_json_mapping(
                generated_package_state or {}, "generated_package_state"
            ),
            files=tuple(safe_files),
        )
        destination = self.snapshots / snapshot_id
        destination.mkdir()
        try:
            for source, relative_name in zip(files, safe_files, strict=True):
                target = destination / "files" / relative_name
                target.parent.mkdir(parents=True, exist_ok=True)
                shutil.copy2(source, target)
            _atomic_json(destination / "manifest.json", asdict(manifest))
        except Exception:
            shutil.rmtree(destination, ignore_errors=True)
            raise
        self._retain()
        return manifest

    def load(self, snapshot_id: str) -> RecoveryManifest:
        path = self._snapshot_path(snapshot_id) / "manifest.json"
        try:
            raw = json.loads(path.read_text(encoding="utf-8"))
            if raw.get("schema_version") != self.CURRENT_SCHEMA:
                raise RecoveryError("snapshot schema is unsupported or from the future")
            manifest = RecoveryManifest(**raw)
            _safe_json_mapping(manifest.configuration, "configuration")
            return manifest
        except RecoveryError:
            raise
        except (OSError, ValueError, TypeError, json.JSONDecodeError) as error:
            raise RecoveryError("snapshot manifest is malformed") from error

    def restore(self, snapshot_id: str, *, destinations: dict[str, Path]) -> RecoveryManifest:
        manifest = self.load(snapshot_id)
        source_root = self._snapshot_path(snapshot_id) / "files"
        for relative, destination in destinations.items():
            if relative not in manifest.files:
                raise RecoveryError("restore requested a file absent from the manifest")
            target = destination.expanduser()
            if target.is_symlink() or (target.exists() and not target.is_file()):
                raise RecoveryError("restore destination is not a regular file")
            target = target.resolve(strict=False)
            target.parent.mkdir(parents=True, exist_ok=True)
            source = (source_root / relative).resolve(strict=True)
            if source_root.resolve() not in source.parents or not source.is_file():
                raise RecoveryError("snapshot file escaped its source root")
            fd, temporary = tempfile.mkstemp(prefix=".restore-", dir=target.parent)
            os.close(fd)
            try:
                shutil.copy2(source, temporary)
                os.replace(temporary, target)
            finally:
                if os.path.exists(temporary):
                    os.unlink(temporary)
        return manifest

    def begin_start(self, transaction_id: UUID | str) -> bool:
        """Mark startup intent; return true when an uncommitted start was found."""

        previous = self.active.exists()
        if previous:
            self.record(
                RecoveryEvidence(
                    str(transaction_id),
                    RecoveryPhase.FAIL,
                    "failed_start",
                    "previous start did not commit",
                    None,
                    _now(),
                )
            )
        _atomic_json(self.active, {"transaction_id": str(transaction_id), "started_at": _now()})
        return previous

    def failed_start_count(self) -> int:
        if not self.evidence.exists():
            return 0
        count = 0
        for line in self.evidence.read_text(encoding="utf-8").splitlines()[-100:]:
            try:
                if json.loads(line).get("outcome") == "failed_start":
                    count += 1
            except (json.JSONDecodeError, TypeError):
                raise RecoveryError("recovery evidence is malformed") from None
        return count

    def commit_start(self, transaction_id: UUID | str, snapshot_id: str) -> None:
        manifest = self.load(snapshot_id)
        if manifest.transaction_id != str(transaction_id):
            raise RecoveryError("commit transaction does not match snapshot")
        _atomic_json(self.lkg, {"snapshot_id": snapshot_id, "transaction_id": str(transaction_id)})
        self.active.unlink(missing_ok=True)
        self.record(
            RecoveryEvidence(
                str(transaction_id),
                RecoveryPhase.COMMIT,
                "success",
                "startup committed",
                snapshot_id,
                _now(),
            )
        )

    def last_known_good(self) -> str | None:
        if not self.lkg.exists():
            return None
        try:
            value = json.loads(self.lkg.read_text(encoding="utf-8"))["snapshot_id"]
            if not isinstance(value, str):
                raise RecoveryError("last-known-good identifier is malformed")
            self.load(value)
            return value
        except (
            OSError,
            KeyError,
            TypeError,
            ValueError,
            json.JSONDecodeError,
            RecoveryError,
        ) as error:
            raise RecoveryError("last-known-good pointer is invalid") from error

    def record(self, evidence: RecoveryEvidence) -> None:
        line = json.dumps(asdict(evidence), sort_keys=True, separators=(",", ":"))
        with self.evidence.open("a", encoding="utf-8") as handle:
            handle.write(line + "\n")

    def _snapshot_path(self, snapshot_id: str) -> Path:
        if not snapshot_id or Path(snapshot_id).name != snapshot_id:
            raise RecoveryError("snapshot identifier is malformed")
        path = (self.snapshots / snapshot_id).resolve()
        if self.snapshots.resolve() not in path.parents:
            raise RecoveryError("snapshot escaped recovery root")
        return path

    def _retain(self) -> None:
        entries = sorted(
            (path for path in self.snapshots.iterdir() if path.is_dir()),
            key=lambda path: path.stat().st_mtime,
            reverse=True,
        )
        keep = set(entries[: self.retention])
        lkg = self.last_known_good() if self.lkg.exists() else None
        if lkg:
            keep.add(self._snapshot_path(lkg))
        for entry in entries:
            if entry not in keep:
                shutil.rmtree(entry)


class RecoveryCoordinator:
    """Lifecycle policy for apply/start/health/rollback orchestration."""

    def __init__(self, store: RecoveryStore, *, crash_loop_limit: int = 3) -> None:
        if crash_loop_limit < 1:
            raise ValueError("crash_loop_limit must be positive")
        self.store = store
        self.crash_loop_limit = crash_loop_limit
        self.safe_mode = False
        self.capabilities = SafeModeCapabilities()

    def begin_start(self, transaction_id: UUID | str) -> bool:
        previous = self.store.begin_start(transaction_id)
        if self.store.failed_start_count() >= self.crash_loop_limit:
            self.enter_safe_mode(transaction_id, "crash-loop threshold reached")
        return previous

    def enter_safe_mode(self, transaction_id: UUID | str, detail: str) -> None:
        self.safe_mode = True
        self.store.record(
            RecoveryEvidence(
                str(transaction_id),
                RecoveryPhase.SAFE_MODE,
                "entered",
                _bounded_text(detail, "detail"),
                None,
                _now(),
            )
        )

    def fail_and_restore(
        self,
        transaction_id: UUID | str,
        *,
        failed_phase: RecoveryPhase,
        detail: str,
        destinations: dict[str, Path] | None = None,
        health_check: Callable[[], bool] | None = None,
    ) -> str | None:
        """Record failure, restore LKG, and Safe Mode on failed verification."""

        transaction = str(transaction_id)
        self.store.record(
            RecoveryEvidence(
                transaction,
                RecoveryPhase.FAIL,
                failed_phase.value,
                _bounded_text(detail, "detail"),
                None,
                _now(),
            )
        )
        lkg = self.store.last_known_good()
        if lkg is None:
            self.enter_safe_mode(transaction, "no last-known-good restore point")
            return None
        self.store.record(
            RecoveryEvidence(
                transaction,
                RecoveryPhase.ROLLBACK,
                "started",
                "restoring LKG",
                lkg,
                _now(),
            )
        )
        self.store.restore(lkg, destinations=destinations or {})
        self.store.record(
            RecoveryEvidence(
                transaction,
                RecoveryPhase.RESTORE_LAST_KNOWN_GOOD,
                "success",
                "LKG restored",
                lkg,
                _now(),
            )
        )
        healthy = health_check() if health_check is not None else True
        self.store.record(
            RecoveryEvidence(
                transaction,
                RecoveryPhase.HEALTH_CHECK,
                "success" if healthy else "failed",
                "restored state verification",
                lkg,
                _now(),
            )
        )
        if not healthy:
            self.enter_safe_mode(transaction, "restored state failed health verification")
        return lkg

    def can_privileged_mutate(self) -> bool:
        return not self.safe_mode

    def can_activate_generated(self) -> bool:
        return not self.safe_mode

    def can_self_update(self) -> bool:
        return not self.safe_mode

    def can_schedule(self) -> bool:
        return not self.safe_mode


def _now() -> str:
    return datetime.now(UTC).isoformat()


def _bounded_text(value: str, label: str) -> str:
    if (
        not isinstance(value, str)
        or not value
        or len(value) > RecoveryStore._MAX_TEXT
        or any(ord(char) < 32 for char in value)
    ):
        raise RecoveryError(f"{label} is malformed")
    return value


def _safe_json_mapping(value: dict[str, Any], label: str) -> dict[str, Any]:
    if not isinstance(value, dict) or len(value) > 128:
        raise RecoveryError(f"{label} is malformed")
    try:
        encoded = json.dumps(value, sort_keys=True, separators=(",", ":"))
        decoded = json.loads(encoded)
    except (TypeError, ValueError, json.JSONDecodeError) as error:
        raise RecoveryError(f"{label} is not JSON data") from error
    if any("secret" in str(key).casefold() or "token" in str(key).casefold() for key in value):
        raise RecoveryError(f"{label} contains secret-like metadata")
    return cast(dict[str, Any], decoded)


def _safe_string_mapping(value: dict[str, str]) -> dict[str, str]:
    if not isinstance(value, dict):
        raise RecoveryError("integration_versions is malformed")
    return {
        _bounded_text(key, "integration"): _bounded_text(item, "version")
        for key, item in value.items()
    }


def _atomic_json(path: Path, value: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, temporary = tempfile.mkstemp(prefix=f".{path.name}.", dir=path.parent)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            json.dump(value, handle, sort_keys=True, separators=(",", ":"))
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, path)
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)
