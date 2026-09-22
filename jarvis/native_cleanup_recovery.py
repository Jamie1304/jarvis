"""Trusted, bounded reconciliation for durable native sandbox cleanup receipts.

This module is intentionally parent-owned.  A receipt is treated as untrusted
data even though the trusted parent wrote it: every resource, profile, SID, and
baseline is validated against current installation policy before a native
mutation is considered.
"""

from __future__ import annotations

import base64
import contextlib
import hashlib
import json
import os
import re
import shutil
import threading
import time
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass
from enum import StrEnum
from pathlib import Path
from queue import Queue
from typing import Any, Protocol
from uuid import UUID, uuid4

from jarvis.windows_sandbox import _AppContainerAclLease, _AppContainerProfile


class NativeCleanupRecoveryError(RuntimeError):
    """A trusted recovery receipt or native observation is unsafe to use."""


class RecoveryState(StrEnum):
    REQUIRED = "RECONCILIATION_REQUIRED"
    RECONCILING = "RECONCILING"
    CONFIRMED = "CLEANUP_CONFIRMED"
    BLOCKED = "RECOVERY_BLOCKED"
    METADATA_INVALID = "RECOVERY_METADATA_INVALID"


@dataclass(frozen=True, slots=True)
class RecoveryEvidence:
    """Bounded machine evidence returned by one reconciliation attempt."""

    receipt: Path
    operation_id: str | None
    state: RecoveryState
    final_state: str
    timed_out: bool = False
    live_owner: bool = False
    metadata_valid: bool = True
    mutation_performed: bool = False
    detail: str = ""
    observations: tuple[Mapping[str, object], ...] = ()

    def as_dict(self) -> dict[str, object]:
        return {
            "receipt": str(self.receipt),
            "operation_id": self.operation_id,
            "state": self.state.value,
            "final_state": self.final_state,
            "timed_out": self.timed_out,
            "live_owner": self.live_owner,
            "metadata_valid": self.metadata_valid,
            "mutation_performed": self.mutation_performed,
            "detail": self.detail[:256],
            "observations": [dict(item) for item in self.observations[:32]],
        }


@dataclass(frozen=True, slots=True)
class _AclResource:
    path: Path
    resource_kind: str
    baseline: bytes
    temporary_sid: str


@dataclass(frozen=True, slots=True)
class _ValidatedReceipt:
    path: Path
    root: Path
    operation_id: str
    owner_instance_id: str
    owner_pid: int
    profile_name: str
    profile_sid: str
    acl: tuple[_AclResource, ...]
    raw: dict[str, object]


class RecoveryOperations(Protocol):
    """Native operations used by the trusted coordinator.

    The injection seam is parent-side test infrastructure only.  Generated
    package code never receives this object or the coordinator.
    """

    def observe_acl(
        self, path: str, baseline: bytes, temporary_sid: bytes
    ) -> Mapping[str, object]: ...

    def restore_acl(self, path: str, baseline: bytes) -> None: ...

    def profile_sid_bytes(self, profile_name: str, expected_sid: str) -> bytes: ...

    def reconcile_profile(self, profile_name: str, expected_sid: str) -> tuple[str, bytes]: ...


class _WindowsRecoveryOperations:
    def observe_acl(self, path: str, baseline: bytes, temporary_sid: bytes) -> Mapping[str, object]:
        return _AppContainerAclLease.observe(path, baseline, temporary_sid)

    def restore_acl(self, path: str, baseline: bytes) -> None:
        _AppContainerAclLease.restore(path, baseline)

    def profile_sid_bytes(self, profile_name: str, expected_sid: str) -> bytes:
        profile = _AppContainerProfile.derive(profile_name)
        try:
            if profile.sid_text() != expected_sid:
                raise NativeCleanupRecoveryError("profile SID binding mismatch")
            return profile.sid_bytes()
        finally:
            with contextlib.suppress(Exception):
                profile.close(delete=False)

    def reconcile_profile(self, profile_name: str, expected_sid: str) -> tuple[str, bytes]:
        profile = _AppContainerProfile.derive(profile_name)
        try:
            observed_sid = profile.sid_text()
            if observed_sid != expected_sid:
                raise NativeCleanupRecoveryError("profile SID binding mismatch")
            sid_bytes = profile.sid_bytes()
            result = profile.close()
            return result, sid_bytes
        except NativeCleanupRecoveryError:
            with contextlib.suppress(Exception):
                profile.close(delete=False)
            raise


_RECEIPT_SCHEMA = 2
_MAX_RECEIPT_BYTES = 256 * 1024
_MAX_ACL_RESOURCES = 32
_PROFILE_NAME = re.compile(r"^JARVIS-[0-9a-f]{32}$")
_SANDBOX_NAME = re.compile(r"^jarvis-sandbox-[0-9a-f]{16}-[0-9a-f]{32}$")
_SID = re.compile(r"^S-1-15-2(?:-[0-9]+){1,15}$")
_RESOURCE_KINDS = frozenset(
    {
        "sandbox_root",
        "runtime_root",
        "dependency_root",
        "package_root",
        "worker_root",
        "traversal_parent",
    }
)

# This identity changes on a true interpreter restart.  It is deliberately
# persisted alongside, rather than replaced by, the PID.
PROCESS_INSTANCE_ID = uuid4().hex
_LIVE_CLEANUP_OWNERS: set[tuple[str, str]] = set()
_LIVE_LOCK = threading.Lock()
_HELD_LOCK_PATHS: set[str] = set()
_HELD_LOCK_GUARD = threading.Lock()


def mark_live_cleanup_owner(operation_id: str) -> None:
    with _LIVE_LOCK:
        _LIVE_CLEANUP_OWNERS.add((PROCESS_INSTANCE_ID, operation_id))


def clear_live_cleanup_owner(operation_id: str) -> None:
    with _LIVE_LOCK:
        _LIVE_CLEANUP_OWNERS.discard((PROCESS_INSTANCE_ID, operation_id))


def is_live_cleanup_owner(instance_id: str, operation_id: str) -> bool:
    with _LIVE_LOCK:
        return (instance_id, operation_id) in _LIVE_CLEANUP_OWNERS


def _canonical(path: Path) -> Path:
    if not path.is_absolute():
        raise NativeCleanupRecoveryError("recovery path is not absolute")
    if path.is_symlink() or bool(getattr(path, "is_junction", lambda: False)()):
        raise NativeCleanupRecoveryError("recovery path is a reparse point")
    resolved = path.resolve(strict=False)
    if os.path.normcase(os.fspath(resolved)) != os.path.normcase(os.fspath(path)):
        raise NativeCleanupRecoveryError("recovery path identity changed")
    return resolved


def _text(value: object, field: str, maximum: int = 4096) -> str:
    if type(value) is not str or not value or len(value) > maximum or "\x00" in value:
        raise NativeCleanupRecoveryError(f"receipt {field} is malformed")
    return value


def _mapping(value: object, field: str) -> Mapping[str, object]:
    if not isinstance(value, Mapping) or any(type(key) is not str for key in value):
        raise NativeCleanupRecoveryError(f"receipt {field} is malformed")
    return value


def _strict_baseline(value: object, expected_hash: object, field: str) -> bytes:
    encoded = _text(value, field, 1_398_104)
    try:
        baseline = base64.b64decode(encoded.encode("ascii"), validate=True)
    except (ValueError, UnicodeError) as error:
        raise NativeCleanupRecoveryError(f"receipt {field} is not base64") from error
    if not 8 <= len(baseline) <= 1_048_576:
        raise NativeCleanupRecoveryError(f"receipt {field} has an invalid size")
    if type(expected_hash) is not str or hashlib.sha256(baseline).hexdigest() != expected_hash:
        raise NativeCleanupRecoveryError(f"receipt {field} fingerprint mismatch")
    return baseline


def _is_under(path: Path, root: Path) -> bool:
    try:
        path.relative_to(root)
    except ValueError:
        return False
    return True


def _validate_resource_path(
    path: Path,
    kind: str,
    *,
    root: Path,
    trusted_roots: tuple[Path, ...],
    prior_paths: tuple[Path, ...],
) -> None:
    if kind == "sandbox_root":
        if path != root:
            raise NativeCleanupRecoveryError("sandbox ACL resource is not the owned root")
        return
    if kind == "traversal_parent":
        if path != root.parent and not any(path == item.parent for item in prior_paths):
            raise NativeCleanupRecoveryError("ACL traversal parent is not derived from a target")
        return
    if kind not in _RESOURCE_KINDS:
        raise NativeCleanupRecoveryError("ACL resource class is not allowed")
    if not any(path == trusted or _is_under(path, trusted) for trusted in trusted_roots):
        raise NativeCleanupRecoveryError("ACL resource is outside trusted roots")


def validate_receipt(
    receipt_path: Path,
    *,
    sandbox_parent: Path,
    trusted_roots: Sequence[Path] = (),
    integrity_verifier: Callable[[Mapping[str, object], str], bool] | None = None,
) -> _ValidatedReceipt:
    """Parse and independently bind one receipt without performing mutation."""

    parent = _canonical(sandbox_parent)
    receipt = _canonical(receipt_path)
    if receipt.name != "native-cleanup-recovery.json" or receipt.parent.parent != parent:
        raise NativeCleanupRecoveryError("receipt is outside the trusted sandbox parent")
    root = receipt.parent
    if not _SANDBOX_NAME.fullmatch(root.name):
        raise NativeCleanupRecoveryError("sandbox root identity is invalid")
    if not root.is_dir():
        raise NativeCleanupRecoveryError("sandbox root is unavailable")
    try:
        raw_bytes = receipt.read_bytes()
        if not raw_bytes or len(raw_bytes) > _MAX_RECEIPT_BYTES:
            raise NativeCleanupRecoveryError("receipt size is invalid")
        decoded = json.loads(raw_bytes.decode("utf-8"))
    except NativeCleanupRecoveryError:
        raise
    except (OSError, UnicodeError, ValueError, json.JSONDecodeError) as error:
        raise NativeCleanupRecoveryError("receipt is unreadable") from error
    if not isinstance(decoded, dict) or decoded.get("schema") != _RECEIPT_SCHEMA:
        raise NativeCleanupRecoveryError("receipt schema is unsupported")
    raw = dict(decoded)
    unsigned = dict(raw)
    integrity = unsigned.pop("integrity", None)
    if (
        type(integrity) is not str
        or integrity_verifier is None
        or not integrity_verifier(unsigned, integrity)
    ):
        raise NativeCleanupRecoveryError("receipt integrity validation failed")
    operation_id = _text(raw.get("operation_id"), "operation_id", 64)
    try:
        UUID(operation_id)
    except (ValueError, AttributeError) as error:
        raise NativeCleanupRecoveryError("receipt operation ID is invalid") from error
    owner = _mapping(raw.get("owner"), "owner")
    owner_instance_id = _text(owner.get("instance_id"), "owner.instance_id", 64)
    try:
        UUID(owner_instance_id)
    except (ValueError, AttributeError) as error:
        raise NativeCleanupRecoveryError("receipt owner generation is invalid") from error
    owner_pid = owner.get("pid")
    if type(owner_pid) is not int or not 1 <= owner_pid <= 2**32 - 1:
        raise NativeCleanupRecoveryError("receipt owner PID is invalid")
    binding = _mapping(raw.get("resource_binding"), "resource_binding")
    if binding.get("class") != "JARVIS_NATIVE_SANDBOX":
        raise NativeCleanupRecoveryError("receipt resource class is invalid")
    stored_parent = _canonical(Path(_text(binding.get("sandbox_parent"), "sandbox_parent")))
    stored_root = _canonical(Path(_text(binding.get("sandbox_root"), "sandbox_root")))
    if stored_parent != parent or stored_root != root:
        raise NativeCleanupRecoveryError("receipt sandbox ownership binding mismatch")
    profile = _mapping(binding.get("profile"), "profile")
    profile_name = _text(profile.get("name"), "profile.name", 50)
    profile_sid = _text(profile.get("sid"), "profile.sid", 256)
    if not _PROFILE_NAME.fullmatch(profile_name) or not _SID.fullmatch(profile_sid):
        raise NativeCleanupRecoveryError("receipt profile identity is invalid")
    acl_raw = binding.get("acl")
    if not isinstance(acl_raw, list) or not 1 <= len(acl_raw) <= _MAX_ACL_RESOURCES:
        raise NativeCleanupRecoveryError("receipt ACL resource set is invalid")
    allowed = tuple(_canonical(Path(item)) for item in trusted_roots)
    resources: list[_AclResource] = []
    for index, item in enumerate(acl_raw):
        resource = _mapping(item, f"acl[{index}]")
        resource_kind = _text(resource.get("resource_kind"), f"acl[{index}].resource_kind", 64)
        path = _canonical(Path(_text(resource.get("path"), f"acl[{index}].path")))
        baseline = _strict_baseline(
            resource.get("baseline_b64"),
            resource.get("baseline_sha256"),
            f"acl[{index}].baseline_b64",
        )
        temporary_sid = _text(resource.get("temporary_sid"), f"acl[{index}].temporary_sid", 256)
        if temporary_sid != profile_sid:
            raise NativeCleanupRecoveryError("receipt ACL/profile SID binding mismatch")
        _validate_resource_path(
            path,
            resource_kind,
            root=root,
            trusted_roots=allowed,
            prior_paths=tuple(item.path for item in resources),
        )
        resources.append(_AclResource(path, resource_kind, baseline, temporary_sid))
    evidence = raw.get("evidence")
    if evidence is not None and not isinstance(evidence, Mapping):
        raise NativeCleanupRecoveryError("receipt evidence is malformed")
    if isinstance(evidence, Mapping) and evidence.get("cleanup_operation_id") not in {
        None,
        operation_id,
    }:
        raise NativeCleanupRecoveryError("receipt operation evidence is mismatched")
    return _ValidatedReceipt(
        receipt,
        root,
        operation_id,
        owner_instance_id,
        owner_pid,
        profile_name,
        profile_sid,
        tuple(resources),
        raw,
    )


class _TransactionLock:
    """Non-blocking OS file lock; handle lifetime makes stale locks recoverable."""

    def __init__(self, path: Path) -> None:
        self.path = path
        self._handle: Any | None = None

    def acquire(self) -> bool:
        key = os.fspath(self.path.resolve(strict=False))
        with _HELD_LOCK_GUARD:
            if key in _HELD_LOCK_PATHS:
                return False
            _HELD_LOCK_PATHS.add(key)
        try:
            self._handle = self.path.open("a+b")
            if os.name == "nt":
                import msvcrt

                self._handle.seek(0)
                self._handle.write(b"0")
                self._handle.flush()
                self._handle.seek(0)
                msvcrt.locking(self._handle.fileno(), msvcrt.LK_NBLCK, 1)
            else:
                fcntl: Any = __import__("fcntl")
                fcntl.flock(self._handle.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
            return True
        except (OSError, BlockingIOError):
            if self._handle is not None:
                self._handle.close()
            self._handle = None
            with _HELD_LOCK_GUARD:
                _HELD_LOCK_PATHS.discard(key)
            return False

    def release(self) -> None:
        handle, self._handle = self._handle, None
        if handle is None:
            return
        with contextlib.suppress(OSError):
            if os.name == "nt":
                import msvcrt

                handle.seek(0)
                msvcrt.locking(handle.fileno(), msvcrt.LK_UNLCK, 1)
            else:
                fcntl: Any = __import__("fcntl")
                fcntl.flock(handle.fileno(), fcntl.LOCK_UN)
        handle.close()
        with _HELD_LOCK_GUARD:
            _HELD_LOCK_PATHS.discard(os.fspath(self.path.resolve(strict=False)))


class NativeCleanupRecoveryCoordinator:
    """One trusted startup/recovery authority for native sandbox receipts."""

    def __init__(
        self,
        sandbox_parent: Path,
        *,
        trusted_roots: Sequence[Path] = (),
        foreground_deadline_seconds: float = 15.0,
        operations: RecoveryOperations | None = None,
        integrity_verifier: Callable[[Mapping[str, object], str], bool] | None = None,
        integrity_signer: Callable[[Mapping[str, object]], str] | None = None,
    ) -> None:
        if (
            not isinstance(foreground_deadline_seconds, int | float)
            or not 0 < foreground_deadline_seconds <= 300
        ):
            raise ValueError("foreground_deadline_seconds is invalid")
        self.sandbox_parent = _canonical(sandbox_parent)
        self.trusted_roots = tuple(_canonical(Path(item)) for item in trusted_roots)
        self.foreground_deadline_seconds = float(foreground_deadline_seconds)
        self.operations = operations or _WindowsRecoveryOperations()
        self.integrity_verifier = integrity_verifier
        self.integrity_signer = integrity_signer

    def discover(self) -> tuple[Path, ...]:
        """Discover actual child receipts without following sandbox reparses."""

        if not self.sandbox_parent.is_dir():
            return ()
        receipts: list[Path] = []
        for root in self.sandbox_parent.glob("jarvis-sandbox-*"):
            if (
                not root.is_dir()
                or root.is_symlink()
                or bool(getattr(root, "is_junction", lambda: False)())
            ):
                continue
            receipt = root / "native-cleanup-recovery.json"
            if receipt.is_file() and not receipt.is_symlink():
                receipts.append(receipt)
        return tuple(sorted(receipts, key=os.fspath))

    def reconcile_all(self) -> tuple[RecoveryEvidence, ...]:
        return tuple(self.reconcile(item) for item in self.discover())

    def reconcile(self, receipt_path: Path) -> RecoveryEvidence:
        lock: _TransactionLock | None = _TransactionLock(
            receipt_path.with_name(".native-cleanup-recovery.lock")
        )
        assert lock is not None
        if not lock.acquire():
            return RecoveryEvidence(
                receipt_path,
                None,
                RecoveryState.BLOCKED,
                RecoveryState.BLOCKED.value,
                live_owner=True,
                detail="another trusted reconciler owns the transaction",
            )
        try:
            try:
                receipt = validate_receipt(
                    receipt_path,
                    sandbox_parent=self.sandbox_parent,
                    trusted_roots=self.trusted_roots,
                    integrity_verifier=self.integrity_verifier,
                )
            except NativeCleanupRecoveryError as error:
                return RecoveryEvidence(
                    receipt_path,
                    None,
                    RecoveryState.METADATA_INVALID,
                    RecoveryState.METADATA_INVALID.value,
                    metadata_valid=False,
                    detail=str(error),
                )
            if is_live_cleanup_owner(receipt.owner_instance_id, receipt.operation_id):
                return RecoveryEvidence(
                    receipt_path,
                    receipt.operation_id,
                    RecoveryState.BLOCKED,
                    RecoveryState.BLOCKED.value,
                    live_owner=True,
                    detail="cleanup owner is still live in this process generation",
                )
            if receipt.raw.get("state") == "CLEANUP_CONFIRMED":
                return RecoveryEvidence(
                    receipt.path,
                    receipt.operation_id,
                    RecoveryState.CONFIRMED,
                    RecoveryState.CONFIRMED.value,
                    detail="terminal trusted cleanup receipt already present",
                )
            self._write_state(receipt, RecoveryState.RECONCILING, {"phase": "reconciling"})
            result_queue: Queue[RecoveryEvidence] = Queue(maxsize=1)
            timed_out = threading.Event()
            worker_lock = lock

            def worker() -> None:
                try:
                    result = self._reconcile_validated(receipt)
                    result_queue.put(result)
                except Exception as error:  # native boundary is fail closed
                    blocked = RecoveryEvidence(
                        receipt.path,
                        receipt.operation_id,
                        RecoveryState.BLOCKED,
                        RecoveryState.BLOCKED.value,
                        mutation_performed=False,
                        detail=f"trusted reconciliation failed: {type(error).__name__}",
                    )
                    with contextlib.suppress(Exception):
                        self._write_state(receipt, RecoveryState.BLOCKED, {"error": blocked.detail})
                    result_queue.put(blocked)
                finally:
                    if timed_out.is_set():
                        assert worker_lock is not None
                        worker_lock.release()

            thread = threading.Thread(
                target=worker,
                name="jarvis-native-cleanup-reconciliation",
                daemon=True,
            )
            thread.start()
            thread.join(self.foreground_deadline_seconds)
            if thread.is_alive():
                timed_out.set()
                self._write_state(
                    receipt,
                    RecoveryState.BLOCKED,
                    {
                        "phase": "deadline_exceeded",
                        "deadline_seconds": self.foreground_deadline_seconds,
                    },
                )
                # The worker retains the OS lock until its native call returns;
                # another reconciler therefore cannot race a late mutation.
                lock = None
                return RecoveryEvidence(
                    receipt.path,
                    receipt.operation_id,
                    RecoveryState.BLOCKED,
                    RecoveryState.BLOCKED.value,
                    timed_out=True,
                    detail="reconciliation foreground deadline exceeded",
                )
            return result_queue.get_nowait()
        finally:
            if lock is not None:
                lock.release()

    def _reconcile_validated(self, receipt: _ValidatedReceipt) -> RecoveryEvidence:
        observations: list[Mapping[str, object]] = []
        mutation_performed = False
        profile_sid_bytes = self.operations.profile_sid_bytes(
            receipt.profile_name,
            receipt.profile_sid,
        )
        for resource in receipt.acl:
            if resource.resource_kind == "sandbox_root" and not resource.path.exists():
                observations.append(
                    {"resource_kind": resource.resource_kind, "path_exists": False, "clean": True}
                )
                continue
            observed = self.operations.observe_acl(
                os.fspath(resource.path),
                resource.baseline,
                profile_sid_bytes,
            )
            observations.append(dict(observed))
            if (
                observed.get("baseline_matches") is True
                and observed.get("temporary_sid_present") is False
            ):
                continue
            self.operations.restore_acl(os.fspath(resource.path), resource.baseline)
            mutation_performed = True
            verified = self.operations.observe_acl(
                os.fspath(resource.path),
                resource.baseline,
                profile_sid_bytes,
            )
            observations.append(dict(verified))
            if (
                verified.get("baseline_matches") is not True
                or verified.get("temporary_sid_present") is not False
            ):
                raise NativeCleanupRecoveryError("ACL semantic postcondition failed")
        profile_result, deleted_sid_bytes = self.operations.reconcile_profile(
            receipt.profile_name,
            receipt.profile_sid,
        )
        if deleted_sid_bytes != profile_sid_bytes:
            raise NativeCleanupRecoveryError("profile SID changed during reconciliation")
        observations.append({"profile": receipt.profile_name, "profile_result": profile_result})
        self._remove_owned_disposable_children(receipt.root)
        self._write_state(
            receipt,
            RecoveryState.CONFIRMED,
            {
                "phase": "confirmed",
                "mutation_performed": mutation_performed,
                "observations": [dict(item) for item in observations[:32]],
            },
        )
        return RecoveryEvidence(
            receipt.path,
            receipt.operation_id,
            RecoveryState.CONFIRMED,
            RecoveryState.CONFIRMED.value,
            mutation_performed=mutation_performed,
            observations=tuple(observations[:32]),
            detail="trusted OS state reconciled and reverified",
        )

    @staticmethod
    def _remove_owned_disposable_children(root: Path) -> None:
        for name in ("work", "data"):
            child = root / name
            if not child.exists():
                continue
            if child.is_symlink() or bool(getattr(child, "is_junction", lambda: False)()):
                raise NativeCleanupRecoveryError("owned sandbox child is a reparse point")
            shutil.rmtree(child)

    def _write_state(
        self,
        receipt: _ValidatedReceipt,
        state: RecoveryState,
        evidence: Mapping[str, object],
    ) -> None:
        raw = dict(receipt.raw)
        raw["state"] = state.value
        raw["updated_monotonic_ns"] = time.monotonic_ns()
        raw["reconciliation"] = {str(key): value for key, value in list(evidence.items())[:16]}
        raw.pop("integrity", None)
        if self.integrity_signer is None:
            raise NativeCleanupRecoveryError("trusted receipt signer is unavailable")
        raw["integrity"] = self.integrity_signer(raw)
        encoded = json.dumps(raw, sort_keys=True, separators=(",", ":")).encode("utf-8")
        if len(encoded) > _MAX_RECEIPT_BYTES:
            raise NativeCleanupRecoveryError("reconciliation receipt exceeded its bound")
        temporary = receipt.path.with_name(f".{receipt.path.name}.{uuid4().hex}.tmp")
        try:
            with temporary.open("xb") as handle:
                handle.write(encoded)
                handle.flush()
                os.fsync(handle.fileno())
            os.replace(temporary, receipt.path)
        finally:
            with contextlib.suppress(FileNotFoundError):
                temporary.unlink()


def reconcile_pending_native_cleanup(
    sandbox_parent: Path,
    *,
    trusted_roots: Sequence[Path] = (),
    foreground_deadline_seconds: float = 15.0,
    operations: RecoveryOperations | None = None,
    integrity_verifier: Callable[[Mapping[str, object], str], bool] | None = None,
    integrity_signer: Callable[[Mapping[str, object]], str] | None = None,
) -> tuple[RecoveryEvidence, ...]:
    """Run the one trusted startup reconciliation pass."""

    return NativeCleanupRecoveryCoordinator(
        sandbox_parent,
        trusted_roots=trusted_roots,
        foreground_deadline_seconds=foreground_deadline_seconds,
        operations=operations,
        integrity_verifier=integrity_verifier,
        integrity_signer=integrity_signer,
    ).reconcile_all()


__all__ = [
    "NativeCleanupRecoveryCoordinator",
    "NativeCleanupRecoveryError",
    "PROCESS_INSTANCE_ID",
    "RecoveryEvidence",
    "RecoveryOperations",
    "RecoveryState",
    "clear_live_cleanup_owner",
    "is_live_cleanup_owner",
    "mark_live_cleanup_owner",
    "reconcile_pending_native_cleanup",
    "validate_receipt",
]
