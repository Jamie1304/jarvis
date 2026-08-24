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
from datetime import UTC, datetime, timedelta
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


class StartupAttemptStatus(StrEnum):
    STARTING = "starting"
    HEALTH_CHECK = "health_check"
    COMMITTED = "committed"
    FAILED = "failed"
    ROLLING_BACK = "rolling_back"
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
class StartupAttempt:
    """Durable identity and deadline for one candidate or recovery boot."""

    attempt_id: str
    transaction_id: str
    candidate_snapshot_id: str | None
    candidate_build: str | None
    lkg_snapshot_id: str | None
    lkg_build: str | None
    started_at: str
    health_deadline: str | None
    migrations: tuple[str, ...] = ()
    status: StartupAttemptStatus = StartupAttemptStatus.STARTING

    def __post_init__(self) -> None:
        _bounded_text(self.attempt_id, "attempt_id")
        _bounded_text(self.transaction_id, "transaction_id")
        for value, label in (
            (self.candidate_snapshot_id, "candidate_snapshot_id"),
            (self.candidate_build, "candidate_build"),
            (self.lkg_snapshot_id, "lkg_snapshot_id"),
            (self.lkg_build, "lkg_build"),
            (self.health_deadline, "health_deadline"),
        ):
            if value is not None:
                _bounded_text(value, label)
        _bounded_text(self.started_at, "started_at")
        if (
            not isinstance(self.migrations, tuple)
            or len(self.migrations) > 128
            or any(not isinstance(item, str) for item in self.migrations)
        ):
            raise RecoveryError("startup migrations are malformed")
        if not isinstance(self.status, StartupAttemptStatus):
            raise RecoveryError("startup attempt status is malformed")


@dataclass(frozen=True, slots=True)
class RecoveryEvidence:
    transaction_id: str
    phase: RecoveryPhase
    outcome: str
    detail: str
    snapshot_id: str | None
    timestamp: str
    candidate_build: str | None = None
    lkg_snapshot_id: str | None = None
    lkg_build: str | None = None
    migration_refs: tuple[str, ...] = ()
    incident_evidence: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        _bounded_text(self.transaction_id, "transaction_id")
        if not isinstance(self.phase, RecoveryPhase):
            raise RecoveryError("recovery phase is malformed")
        _bounded_text(self.outcome, "outcome")
        _bounded_text(self.detail, "detail")
        for value, label in (
            (self.snapshot_id, "snapshot_id"),
            (self.candidate_build, "candidate_build"),
            (self.lkg_snapshot_id, "lkg_snapshot_id"),
            (self.lkg_build, "lkg_build"),
            (self.timestamp, "timestamp"),
        ):
            if value is not None:
                _bounded_text(value, label)
        _bounded_sequence(self.migration_refs, "migration_refs")
        _bounded_sequence(self.incident_evidence, "incident_evidence")


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

    def __init__(
        self,
        root: Path,
        *,
        retention: int = 5,
        clock: Callable[[], datetime] | None = None,
    ) -> None:
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
        self._clock = clock or (lambda: datetime.now(UTC))
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
            if not isinstance(raw, dict):
                raise RecoveryError("snapshot manifest is malformed")
            if raw.get("schema_version") != self.CURRENT_SCHEMA:
                raise RecoveryError("snapshot schema is unsupported or from the future")
            migrations = raw.get("migrations", ())
            files = raw.get("files", ())
            if not isinstance(migrations, list | tuple) or not isinstance(files, list | tuple):
                raise RecoveryError("snapshot manifest is malformed")
            if any(not isinstance(item, str) for item in tuple(migrations) + tuple(files)):
                raise RecoveryError("snapshot manifest is malformed")
            raw["migrations"] = tuple(migrations)
            raw["files"] = tuple(files)
            manifest = RecoveryManifest(**raw)
            for value, label in (
                (manifest.snapshot_id, "snapshot_id"),
                (manifest.transaction_id, "transaction_id"),
                (manifest.app_revision, "app_revision"),
                (manifest.created_at, "created_at"),
            ):
                _bounded_text(value, label)
            _parse_time(manifest.created_at)
            _safe_json_mapping(manifest.configuration, "configuration")
            _safe_json_mapping(manifest.database_schema, "database_schema")
            _safe_json_mapping(manifest.generated_package_state, "generated_package_state")
            _safe_string_mapping(manifest.integration_versions)
            _bounded_sequence(manifest.migrations, "migrations")
            _bounded_sequence(manifest.files, "files")
            for file_name in manifest.files:
                file_path = Path(file_name)
                if file_path.is_absolute() or ".." in file_path.parts:
                    raise RecoveryError("snapshot manifest contains an unsafe file path")
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

    def begin_start(
        self,
        transaction_id: UUID | str,
        *,
        candidate_snapshot_id: str | None = None,
        candidate_build: str | None = None,
        health_deadline: datetime | None = None,
        migrations: tuple[str, ...] = (),
    ) -> bool:
        """Mark startup intent; return true when an uncommitted start was found."""

        previous = self.active.exists()
        if previous:
            previous_attempt = self.active_start()
            self.record(
                RecoveryEvidence(
                    str(transaction_id),
                    RecoveryPhase.FAIL,
                    "failed_start",
                    "previous start did not commit",
                    previous_attempt.candidate_snapshot_id,
                    _now(self._clock),
                    candidate_build=previous_attempt.candidate_build,
                    lkg_snapshot_id=previous_attempt.lkg_snapshot_id,
                    lkg_build=previous_attempt.lkg_build,
                    migration_refs=previous_attempt.migrations,
                )
            )
        candidate_manifest = (
            self.load(candidate_snapshot_id) if candidate_snapshot_id is not None else None
        )
        if candidate_manifest is not None:
            if candidate_build is not None and candidate_build != candidate_manifest.app_revision:
                raise RecoveryError("candidate build does not match its snapshot")
            candidate_build = candidate_manifest.app_revision
            if migrations and migrations != candidate_manifest.migrations:
                raise RecoveryError("candidate migrations do not match its snapshot")
            migrations = candidate_manifest.migrations
            if candidate_snapshot_id in self.failed_candidate_snapshot_ids():
                raise RecoveryError("candidate build was previously marked failed")
        lkg_snapshot_id = self.last_known_good() if self.lkg.exists() else None
        lkg_build = self.load(lkg_snapshot_id).app_revision if lkg_snapshot_id else None
        deadline = _deadline_text(health_deadline)
        attempt = StartupAttempt(
            attempt_id=str(uuid4()),
            transaction_id=str(transaction_id),
            candidate_snapshot_id=candidate_snapshot_id,
            candidate_build=candidate_build,
            lkg_snapshot_id=lkg_snapshot_id,
            lkg_build=lkg_build,
            started_at=_now(self._clock),
            health_deadline=deadline,
            migrations=tuple(_bounded_text(item, "migration") for item in migrations),
        )
        _atomic_json(self.active, asdict(attempt))
        self.record(
            RecoveryEvidence(
                str(transaction_id),
                RecoveryPhase.START,
                "started",
                "startup attempt started",
                candidate_snapshot_id,
                _now(self._clock),
                candidate_build=candidate_build,
                lkg_snapshot_id=lkg_snapshot_id,
                lkg_build=lkg_build,
                migration_refs=attempt.migrations,
            )
        )
        return previous

    def active_start(self) -> StartupAttempt:
        """Load the active startup marker, failing closed when it is malformed."""

        if not self.active.exists():
            raise RecoveryError("no active startup attempt")
        try:
            raw = json.loads(self.active.read_text(encoding="utf-8"))
            if not isinstance(raw, dict):
                raise RecoveryError("active startup marker is malformed")
            transaction_id = _raw_marker_text(raw, "transaction_id", required=True)
            attempt_id = _raw_marker_text(raw, "attempt_id", required=False)
            migrations = raw.get("migrations", ())
            if not isinstance(migrations, list | tuple):
                raise RecoveryError("active startup marker is malformed")
            status = raw.get("status", StartupAttemptStatus.STARTING.value)
            if not isinstance(status, str):
                raise RecoveryError("active startup marker is malformed")
            started_at = _raw_marker_text(raw, "started_at", required=True)
            assert transaction_id is not None and started_at is not None
            if attempt_id is None:
                attempt_id = transaction_id
            return StartupAttempt(
                attempt_id=attempt_id,
                transaction_id=transaction_id,
                candidate_snapshot_id=_raw_marker_text(
                    raw, "candidate_snapshot_id", required=False
                ),
                candidate_build=_raw_marker_text(raw, "candidate_build", required=False),
                lkg_snapshot_id=_raw_marker_text(raw, "lkg_snapshot_id", required=False),
                lkg_build=_raw_marker_text(raw, "lkg_build", required=False),
                started_at=started_at,
                health_deadline=_raw_marker_text(raw, "health_deadline", required=False),
                migrations=tuple(migrations),
                status=StartupAttemptStatus(status),
            )
        except RecoveryError:
            raise
        except (OSError, KeyError, TypeError, ValueError, json.JSONDecodeError) as error:
            raise RecoveryError("active startup marker is malformed") from error

    def clear_active(self, transaction_id: UUID | str | None = None) -> None:
        if not self.active.exists():
            return
        attempt = self.active_start()
        if transaction_id is not None and attempt.transaction_id != str(transaction_id):
            raise RecoveryError("active startup transaction does not match")
        self.active.unlink(missing_ok=True)

    def failed_candidate_snapshot_ids(self) -> frozenset[str]:
        """Return candidate snapshots that have a durable failed-build record."""

        if not self.evidence.exists():
            return frozenset()
        failed: set[str] = set()
        try:
            lines = self.evidence.read_text(encoding="utf-8").splitlines()[-500:]
            for line in lines:
                raw = json.loads(line)
                if not isinstance(raw, dict):
                    raise RecoveryError("recovery evidence is malformed")
                if raw.get("phase") == RecoveryPhase.FAIL.value and isinstance(
                    raw.get("snapshot_id"), str
                ):
                    failed.add(str(raw["snapshot_id"]))
        except (OSError, json.JSONDecodeError, TypeError, RecoveryError) as error:
            if isinstance(error, RecoveryError):
                raise
            raise RecoveryError("recovery evidence is malformed") from error
        return frozenset(failed)

    def failed_start_count(self) -> int:
        if not self.evidence.exists():
            return 0
        count = 0
        # Crash-loop protection concerns consecutive failed startup/recovery
        # evidence.  A later committed startup proves that the previous failure
        # sequence ended and must reset the counter; historical incidents
        # remain in the evidence log but cannot permanently force Safe Mode.
        lines = self.evidence.read_text(encoding="utf-8").splitlines()[-100:]
        for line in reversed(lines):
            try:
                raw = json.loads(line)
                if not isinstance(raw, dict):
                    raise RecoveryError("recovery evidence is malformed")
                if raw.get("phase") == RecoveryPhase.COMMIT.value:
                    break
                if raw.get("phase") == RecoveryPhase.FAIL.value:
                    count += 1
            except (json.JSONDecodeError, TypeError):
                raise RecoveryError("recovery evidence is malformed") from None
        return count

    def commit_start(self, transaction_id: UUID | str, snapshot_id: str) -> None:
        manifest = self.load(snapshot_id)
        if manifest.transaction_id != str(transaction_id):
            raise RecoveryError("commit transaction does not match snapshot")
        if self.active.exists():
            attempt = self.active_start()
            if attempt.transaction_id != str(transaction_id):
                raise RecoveryError("commit transaction does not match active startup")
            if (
                attempt.candidate_snapshot_id is not None
                and attempt.candidate_snapshot_id != snapshot_id
            ):
                raise RecoveryError("commit snapshot does not match candidate startup")
            if (
                attempt.health_deadline is not None
                and _parse_time(attempt.health_deadline) < self._clock()
            ):
                raise RecoveryError("startup health deadline expired")
        _atomic_json(self.lkg, {"snapshot_id": snapshot_id, "transaction_id": str(transaction_id)})
        self.active.unlink(missing_ok=True)
        self.record(
            RecoveryEvidence(
                str(transaction_id),
                RecoveryPhase.COMMIT,
                "success",
                "startup committed",
                snapshot_id,
                _now(self._clock),
                candidate_build=manifest.app_revision,
                migration_refs=manifest.migrations,
            )
        )

    def mark_failed(
        self,
        transaction_id: UUID | str,
        *,
        failed_phase: RecoveryPhase,
        detail: str,
        incident_evidence: tuple[str, ...] = (),
    ) -> None:
        """Persist a candidate failure with build, LKG, and migration references."""

        attempt = self.active_start() if self.active.exists() else None
        candidate_snapshot_id = attempt.candidate_snapshot_id if attempt else None
        candidate_build = attempt.candidate_build if attempt else None
        lkg_snapshot_id = attempt.lkg_snapshot_id if attempt else None
        lkg_build = attempt.lkg_build if attempt else None
        migrations = attempt.migrations if attempt else ()
        self.record(
            RecoveryEvidence(
                str(transaction_id),
                RecoveryPhase.FAIL,
                "failed",
                _bounded_text(detail, "detail"),
                candidate_snapshot_id,
                _now(self._clock),
                candidate_build=candidate_build,
                lkg_snapshot_id=lkg_snapshot_id,
                lkg_build=lkg_build,
                migration_refs=migrations,
                incident_evidence=incident_evidence,
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

    def __init__(
        self,
        store: RecoveryStore,
        *,
        crash_loop_limit: int = 3,
        startup_deadline: timedelta = timedelta(seconds=60),
        clock: Callable[[], datetime] | None = None,
    ) -> None:
        if crash_loop_limit < 1:
            raise ValueError("crash_loop_limit must be positive")
        if startup_deadline <= timedelta(0) or startup_deadline > timedelta(hours=1):
            raise ValueError("startup_deadline must be positive and bounded")
        self.store = store
        self.crash_loop_limit = crash_loop_limit
        self.startup_deadline = startup_deadline
        self._clock = clock or (lambda: datetime.now(UTC))
        self.safe_mode = False
        self.capabilities = SafeModeCapabilities()

    def begin_start(
        self,
        transaction_id: UUID | str,
        *,
        candidate_snapshot_id: str | None = None,
        candidate_build: str | None = None,
        migrations: tuple[str, ...] = (),
    ) -> bool:
        previous = self.store.begin_start(
            transaction_id,
            candidate_snapshot_id=candidate_snapshot_id,
            candidate_build=candidate_build,
            health_deadline=self._clock() + self.startup_deadline,
            migrations=migrations,
        )
        if self.store.failed_start_count() >= self.crash_loop_limit:
            self.enter_safe_mode(transaction_id, "crash-loop threshold reached")
        return previous

    def boot_candidate(
        self,
        transaction_id: UUID | str,
        candidate_snapshot_id: str,
        *,
        start: Callable[[], None],
        health_check: Callable[[], bool],
        restart_lkg: Callable[[RecoveryManifest], bool] | None = None,
        lkg_health_check: Callable[[], bool] | None = None,
        migration_reconcile: Callable[[RecoveryManifest], bool] | None = None,
        destinations: dict[str, Path] | None = None,
        incident_evidence: tuple[str, ...] = (),
    ) -> str | None:
        """Boot a candidate once and perform one bounded LKG recovery attempt.

        The callbacks are trusted composition-root hooks.  This coordinator never
        executes a build, migration, restart, or privileged operation itself.
        """

        candidate = self.store.load(candidate_snapshot_id)
        try:
            self.begin_start(
                transaction_id,
                candidate_snapshot_id=candidate_snapshot_id,
                candidate_build=candidate.app_revision,
                migrations=candidate.migrations,
            )
            if self.safe_mode:
                return None
            start()
            self._assert_deadline()
            self.store.record(
                RecoveryEvidence(
                    str(transaction_id),
                    RecoveryPhase.HEALTH_CHECK,
                    "started",
                    "candidate health check started",
                    candidate_snapshot_id,
                    _now(self._clock),
                    candidate_build=candidate.app_revision,
                    migration_refs=candidate.migrations,
                )
            )
            healthy = health_check()
            attempt = self.store.active_start()
            self.store.record(
                RecoveryEvidence(
                    str(transaction_id),
                    RecoveryPhase.HEALTH_CHECK,
                    "success" if healthy else "failed",
                    "candidate health verification",
                    candidate_snapshot_id,
                    _now(self._clock),
                    candidate_build=candidate.app_revision,
                    lkg_snapshot_id=attempt.lkg_snapshot_id,
                    lkg_build=attempt.lkg_build,
                    migration_refs=candidate.migrations,
                    incident_evidence=incident_evidence,
                )
            )
            if not healthy:
                raise RecoveryError("candidate health check failed")
            self._assert_deadline()
            self.store.commit_start(transaction_id, candidate_snapshot_id)
            return candidate_snapshot_id
        except Exception as error:
            self.store.mark_failed(
                transaction_id,
                failed_phase=RecoveryPhase.HEALTH_CHECK,
                detail=f"candidate boot failed: {type(error).__name__}",
                incident_evidence=incident_evidence,
            )
            return self._recover_lkg(
                transaction_id,
                destinations=destinations,
                restart_lkg=restart_lkg,
                health_check=lkg_health_check or health_check,
                migration_reconcile=migration_reconcile,
                incident_evidence=incident_evidence,
            )

    def enter_safe_mode(self, transaction_id: UUID | str, detail: str) -> None:
        self.safe_mode = True
        self.store.record(
            RecoveryEvidence(
                str(transaction_id),
                RecoveryPhase.SAFE_MODE,
                "entered",
                _bounded_text(detail, "detail"),
                None,
                _now(self._clock),
            )
        )
        self.store.clear_active()

    def _assert_deadline(self) -> None:
        if not self.store.active.exists():
            raise RecoveryError("startup attempt is not active")
        attempt = self.store.active_start()
        if (
            attempt.health_deadline is not None
            and _parse_time(attempt.health_deadline) < self._clock()
        ):
            raise RecoveryError("startup health deadline expired")

    def _recover_lkg(
        self,
        transaction_id: UUID | str,
        *,
        destinations: dict[str, Path] | None,
        restart_lkg: Callable[[RecoveryManifest], bool] | None,
        health_check: Callable[[], bool],
        migration_reconcile: Callable[[RecoveryManifest], bool] | None,
        incident_evidence: tuple[str, ...],
    ) -> str | None:
        """Restore, restart, and verify LKG exactly once; failure enters Safe Mode."""

        lkg: str | None = None
        manifest: RecoveryManifest | None = None
        try:
            lkg = self.store.last_known_good()
            if lkg is None:
                self.enter_safe_mode(str(transaction_id), "no last-known-good restore point")
                return None
            manifest = self.store.load(lkg)
            self.store.record(
                RecoveryEvidence(
                    str(transaction_id),
                    RecoveryPhase.ROLLBACK,
                    "started",
                    "restoring last-known-good build",
                    lkg,
                    _now(self._clock),
                    candidate_build=manifest.app_revision,
                    lkg_snapshot_id=lkg,
                    lkg_build=manifest.app_revision,
                    migration_refs=manifest.migrations,
                    incident_evidence=incident_evidence,
                )
            )
            self.store.restore(lkg, destinations=destinations or {})
            if migration_reconcile is not None and not migration_reconcile(manifest):
                raise RecoveryError("LKG migration reconciliation failed")
            self.store.record(
                RecoveryEvidence(
                    str(transaction_id),
                    RecoveryPhase.RESTORE_LAST_KNOWN_GOOD,
                    "success",
                    "last-known-good state restored",
                    lkg,
                    _now(self._clock),
                    candidate_build=manifest.app_revision,
                    lkg_snapshot_id=lkg,
                    lkg_build=manifest.app_revision,
                    migration_refs=manifest.migrations,
                    incident_evidence=incident_evidence,
                )
            )
            self.store.clear_active()
            # A snapshot is transaction-bound.  Reboot the LKG under the
            # transaction that produced that snapshot; do not forge a new
            # transaction identity for a different build.
            recovery_transaction = manifest.transaction_id
            self.begin_start(
                recovery_transaction,
                candidate_snapshot_id=lkg,
                candidate_build=manifest.app_revision,
                migrations=manifest.migrations,
            )
            if self.safe_mode:
                return None
            if restart_lkg is not None and not restart_lkg(manifest):
                raise RecoveryError("LKG restart failed")
            self._assert_deadline()
            healthy = health_check()
            self.store.record(
                RecoveryEvidence(
                    recovery_transaction,
                    RecoveryPhase.HEALTH_CHECK,
                    "success" if healthy else "failed",
                    "LKG health verification",
                    lkg,
                    _now(self._clock),
                    candidate_build=manifest.app_revision,
                    lkg_snapshot_id=lkg,
                    lkg_build=manifest.app_revision,
                    migration_refs=manifest.migrations,
                    incident_evidence=incident_evidence,
                )
            )
            if not healthy:
                raise RecoveryError("LKG health verification failed")
            self._assert_deadline()
            self.store.commit_start(recovery_transaction, lkg)
            return lkg
        except Exception as error:
            self.store.record(
                RecoveryEvidence(
                    str(transaction_id),
                    RecoveryPhase.FAIL,
                    "lkg_failed",
                    f"LKG recovery failed: {type(error).__name__}",
                    lkg,
                    _now(self._clock),
                    candidate_build=manifest.app_revision if manifest is not None else None,
                    lkg_snapshot_id=lkg,
                    lkg_build=manifest.app_revision if manifest is not None else None,
                    migration_refs=manifest.migrations if manifest is not None else (),
                    incident_evidence=incident_evidence,
                )
            )
            self.enter_safe_mode(str(transaction_id), "last-known-good recovery failed")
            return None

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


def _now(clock: Callable[[], datetime] | None = None) -> str:
    value = clock() if clock is not None else datetime.now(UTC)
    if value.tzinfo is None:
        raise RecoveryError("recovery clock must be timezone-aware")
    return value.astimezone(UTC).isoformat()


def _deadline_text(value: datetime | None) -> str | None:
    return _now(lambda: value) if value is not None else None


def _parse_time(value: str) -> datetime:
    try:
        parsed = datetime.fromisoformat(value)
    except ValueError as error:
        raise RecoveryError("recovery timestamp is malformed") from error
    if parsed.tzinfo is None:
        raise RecoveryError("recovery timestamp must be timezone-aware")
    return parsed.astimezone(UTC)


def _bounded_text(value: str, label: str) -> str:
    if (
        not isinstance(value, str)
        or not value
        or len(value) > RecoveryStore._MAX_TEXT
        or any(ord(char) < 32 for char in value)
    ):
        raise RecoveryError(f"{label} is malformed")
    return value


def _raw_marker_text(marker: dict[str, Any], key: str, *, required: bool) -> str | None:
    value = marker.get(key)
    if value is None:
        if required:
            raise RecoveryError("active startup marker is malformed")
        return None
    if not isinstance(value, str):
        raise RecoveryError("active startup marker is malformed")
    return value


def _bounded_sequence(values: tuple[str, ...], label: str) -> None:
    if (
        not isinstance(values, tuple)
        or len(values) > 128
        or any(
            not isinstance(value, str)
            or not value
            or len(value) > RecoveryStore._MAX_TEXT
            or any(ord(char) < 32 for char in value)
            for value in values
        )
    ):
        raise RecoveryError(f"{label} is malformed")


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
    if not isinstance(value, dict) or len(value) > 128:
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
