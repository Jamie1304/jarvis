"""Out-of-process execution boundary for untrusted integration code.

The parent process exposes only bounded JSON messages over stdio.  It never
passes a broker, policy, vault, audit writer, runtime container, or ambient
environment into the child.  On Windows, the default executable launch uses
a capability-free AppContainer, scoped ACLs, an explicit standard-handle list,
and a Job Object for process-tree/resource ownership.  Restricted-token and
Job-only modes remain explicit compatibility/diagnostic modes and do not meet
the generated executable activation contract.  The actual guarantees and
limitations are documented in ``docs/security/windows-integration-isolation.md``.
"""

from __future__ import annotations

import asyncio
import contextlib
import ctypes
import ctypes.wintypes as wintypes
import json
import os
import re
import shutil
import signal
import sys
import threading
import time
from collections.abc import Callable, Mapping
from dataclasses import dataclass, field, replace
from hashlib import sha256
from pathlib import Path
from typing import Any
from uuid import UUID, uuid4

from jarvis.capability_flight_recorder import CapabilityFlightRecorder
from jarvis.computer.process import ProcessIdentityError, resolve_trusted_executable
from jarvis.native_cleanup_recovery import (
    PROCESS_INSTANCE_ID,
    clear_live_cleanup_owner,
    mark_live_cleanup_owner,
)
from jarvis.resources import (
    ReservationReleaseReason,
    ResourceBudget,
    ResourceGovernor,
    ResourcePriority,
)
from jarvis.windows_sandbox import (
    NativeCleanupState,
    SandboxSecurityStatus,
    WindowsAppContainerLauncher,
    WindowsContainmentMode,
    WindowsNativeProcessError,
    WindowsRestrictedLauncher,
)

SANDBOX_PROTOCOL_VERSION = 1
DEFAULT_MAX_MESSAGE_BYTES = 65_536
MAX_TRACE_FRAMES = 32
MAX_TRACE_BYTES = 8_192
MAX_TRACE_METADATA_BYTES = 1_024
_IDENTIFIER_CHARS = frozenset("abcdefghijklmnopqrstuvwxyz0123456789._-")


class SandboxError(RuntimeError):
    """Base class for isolated-process failures."""


class SandboxConfigurationError(SandboxError, ValueError):
    """A trusted composition supplied unsafe or unsupported sandbox settings."""


class SandboxProtocolError(SandboxError):
    """The child sent malformed, forged, or oversized IPC data."""


class SandboxProcessError(SandboxError):
    """The child could not start, crashed, or stopped unexpectedly."""

    def __init__(
        self,
        message: str,
        *,
        diagnostics: SandboxStartupDiagnostics | None = None,
    ) -> None:
        super().__init__(message)
        self.diagnostics = diagnostics


@dataclass(frozen=True, slots=True)
class SandboxStartupDiagnostics:
    """Bounded, non-secret evidence for a child that failed to become ready."""

    containment_mode: WindowsContainmentMode
    executable: str
    bootstrap: str
    pipes_established: bool
    job_assigned: bool
    readiness_reached: bool
    process_id: int | None
    exit_code: int | None
    stderr_tail: str | None = None


@dataclass(frozen=True, slots=True)
class SandboxProtocolDiagnostics:
    """Bounded observational evidence for one request/response exchange."""

    phase: str
    classification: str | None
    request_id: str | None
    integration_id: str
    pid: int | None
    process_alive: bool
    exit_code: int | None
    response_received: bool
    response_length: int | None
    stderr_tail: str
    timing_ms: Mapping[str, float]
    predicates: Mapping[str, object]
    job: Mapping[str, object] = field(default_factory=dict)
    child_events: tuple[Mapping[str, object], ...] = ()
    parent_flight_recorder: Mapping[str, object] = field(default_factory=dict)

    def as_dict(self) -> dict[str, object]:
        return {
            "phase": self.phase,
            "classification": self.classification,
            "request_id": self.request_id,
            "integration_id": self.integration_id,
            "pid": self.pid,
            "process_alive": self.process_alive,
            "exit_code": self.exit_code,
            "response_received": self.response_received,
            "response_length": self.response_length,
            "stderr_tail": self.stderr_tail,
            "timing_ms": dict(self.timing_ms),
            "predicates": dict(self.predicates),
            "job": dict(self.job),
            "child_events": [dict(item) for item in self.child_events],
            "parent_flight_recorder": dict(self.parent_flight_recorder),
        }


_DIAGNOSTIC_SECRET = re.compile(
    r"(?i)(api[_-]?key|authorization|bearer|credential|password|secret|token)"
)


def _redact_diagnostic(value: str) -> str:
    value = _DIAGNOSTIC_SECRET.sub(r"\1=[REDACTED]", value)
    return value[-8_192:] if len(value) > 8_192 else value


class SandboxStartupError(SandboxProcessError):
    """The child exited before returning a valid protocol response."""


class SandboxTimeout(SandboxProcessError):
    """A request exceeded its bounded execution time."""


class SandboxCancelled(SandboxProcessError):
    """A trusted caller cancelled an in-flight sandbox request."""


class SandboxIsolationUnavailable(SandboxError):
    """The requested native process containment could not be established."""


class SandboxCleanupError(SandboxError):
    """Owned sandbox data could not be removed safely."""


class SandboxCleanupOutcomeUnknown(SandboxCleanupError):
    """Native cleanup exceeded the foreground deadline and is quarantined."""


def _identifier(value: str, field: str) -> str:
    if (
        type(value) is not str
        or not 1 <= len(value) <= 64
        or value[0] not in _IDENTIFIER_CHARS - {".", "-"}
        or any(character not in _IDENTIFIER_CHARS for character in value)
    ):
        raise SandboxConfigurationError(f"{field} is invalid")
    return value


def _bounded_text(value: str, field: str, limit: int) -> str:
    if (
        type(value) is not str
        or not value
        or len(value) > limit
        or "\x00" in value
        or any(ord(character) < 32 for character in value)
    ):
        raise SandboxConfigurationError(f"{field} is invalid")
    return value


def _json_value(value: object, *, depth: int = 0) -> object:
    """Copy only finite, bounded JSON values; never accept arbitrary objects."""

    if depth > 32:
        raise SandboxProtocolError("IPC payload nesting is too deep")
    if value is None or type(value) is bool or type(value) is int or type(value) is str:
        return value
    if type(value) is float:
        if not -1e308 < value < 1e308:
            raise SandboxProtocolError("IPC payload contains an invalid number")
        return value
    if isinstance(value, list | tuple):
        if len(value) > 4_096:
            raise SandboxProtocolError("IPC payload list is too large")
        return [_json_value(item, depth=depth + 1) for item in value]
    if isinstance(value, Mapping):
        if len(value) > 4_096:
            raise SandboxProtocolError("IPC payload object is too large")
        normalized: dict[str, object] = {}
        for key, item in value.items():
            if type(key) is not str or len(key) > 256 or "\x00" in key:
                raise SandboxProtocolError("IPC payload key is invalid")
            normalized[key] = _json_value(item, depth=depth + 1)
        return normalized
    raise SandboxProtocolError("IPC payload contains a non-JSON value")


@dataclass(frozen=True, slots=True)
class SandboxMessage:
    """Strict, versioned IPC envelope; serialization is JSON only."""

    request_id: UUID
    integration_id: str
    kind: str
    payload: Mapping[str, object]
    response: bool = False
    version: int = SANDBOX_PROTOCOL_VERSION
    lifecycle_run_id: str | None = None
    diagnostics: bool = False
    diagnostic_mode: str | None = None

    def __post_init__(self) -> None:
        if not isinstance(self.request_id, UUID):
            raise SandboxProtocolError("IPC request ID is invalid")
        _identifier(self.integration_id, "Integration ID")
        _bounded_text(self.kind, "IPC message kind", 128)
        if not isinstance(self.payload, Mapping):
            raise SandboxProtocolError("IPC payload must be an object")
        if type(self.response) is not bool or type(self.version) is not int:
            raise SandboxProtocolError("IPC envelope metadata is invalid")
        if self.version != SANDBOX_PROTOCOL_VERSION:
            raise SandboxProtocolError("IPC protocol version is unsupported")
        if self.lifecycle_run_id is not None:
            _bounded_text(self.lifecycle_run_id, "Lifecycle run ID", 128)
        if type(self.diagnostics) is not bool:
            raise SandboxProtocolError("IPC diagnostics flag is invalid")
        if self.diagnostic_mode is not None:
            _bounded_text(self.diagnostic_mode, "Diagnostic mode", 64)
        _json_value(self.payload)

    def encode(self, *, max_bytes: int = DEFAULT_MAX_MESSAGE_BYTES) -> bytes:
        if not isinstance(max_bytes, int) or max_bytes < 128:
            raise SandboxConfigurationError("IPC message bound is invalid")
        body = {
            "version": self.version,
            "request_id": str(self.request_id),
            "integration_id": self.integration_id,
            "kind": self.kind,
            "response": self.response,
            "payload": _json_value(self.payload),
        }
        if self.lifecycle_run_id is not None:
            body["lifecycle_run_id"] = self.lifecycle_run_id
        if self.diagnostics:
            body["diagnostics"] = True
        if self.diagnostic_mode is not None:
            body["diagnostic_mode"] = self.diagnostic_mode
        try:
            encoded = json.dumps(
                body,
                ensure_ascii=True,
                allow_nan=False,
                separators=(",", ":"),
            ).encode("utf-8")
        except (TypeError, UnicodeError, ValueError) as error:
            raise SandboxProtocolError("IPC envelope cannot be serialized") from error
        if len(encoded) + 1 > max_bytes:
            raise SandboxProtocolError("IPC message exceeds its bound")
        return encoded + b"\n"

    @classmethod
    def decode(cls, raw: bytes, *, max_bytes: int = DEFAULT_MAX_MESSAGE_BYTES) -> SandboxMessage:
        if not isinstance(raw, bytes) or len(raw) > max_bytes or not raw.endswith(b"\n"):
            raise SandboxProtocolError("IPC frame is malformed or oversized")
        try:
            value = json.loads(raw[:-1].decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError) as error:
            raise SandboxProtocolError("IPC frame is not valid JSON") from error
        if (
            type(value) is not dict
            or not set(value).issubset(
                {
                    "version",
                    "request_id",
                    "integration_id",
                    "kind",
                    "response",
                    "payload",
                    "lifecycle_run_id",
                    "diagnostics",
                    "diagnostic_mode",
                }
            )
            or not {
                "version",
                "request_id",
                "integration_id",
                "kind",
                "response",
                "payload",
            }.issubset(value)
        ):
            raise SandboxProtocolError("IPC envelope fields are invalid")
        if type(value["version"]) is not int:
            raise SandboxProtocolError("IPC version is invalid")
        if type(value["request_id"]) is not str:
            raise SandboxProtocolError("IPC request ID is invalid")
        try:
            request_id = UUID(value["request_id"])
        except (AttributeError, TypeError, ValueError) as error:
            raise SandboxProtocolError("IPC request ID is invalid") from error
        if type(value["integration_id"]) is not str or type(value["kind"]) is not str:
            raise SandboxProtocolError("IPC identity fields are invalid")
        if type(value["response"]) is not bool or type(value["payload"]) is not dict:
            raise SandboxProtocolError("IPC response fields are invalid")
        lifecycle_run_id = value.get("lifecycle_run_id")
        if lifecycle_run_id is not None and type(lifecycle_run_id) is not str:
            raise SandboxProtocolError("IPC lifecycle run ID is invalid")
        diagnostics = value.get("diagnostics", False)
        if type(diagnostics) is not bool:
            raise SandboxProtocolError("IPC diagnostics flag is invalid")
        payload = _json_value(value["payload"])
        if not isinstance(payload, dict):
            raise SandboxProtocolError("IPC payload is invalid")
        return cls(
            request_id,
            value["integration_id"],
            value["kind"],
            payload,
            value["response"],
            value["version"],
            lifecycle_run_id,
            diagnostics,
            value.get("diagnostic_mode"),
        )


@dataclass(frozen=True, slots=True)
class SandboxLimits:
    """Bounds enforced by the manager; Windows applies the native limits."""

    timeout_seconds: float = 30.0
    max_message_bytes: int = DEFAULT_MAX_MESSAGE_BYTES
    max_processes: int = 1
    max_memory_bytes: int = 256 * 1024 * 1024
    max_restarts: int = 3
    native_cleanup_foreground_deadline_seconds: float = 15.0
    windows_containment: WindowsContainmentMode = WindowsContainmentMode.APPCONTAINER
    appcontainer_runtime_root: Path | None = None
    appcontainer_dependency_roots: tuple[Path, ...] = ()

    def __post_init__(self) -> None:
        if (
            isinstance(self.timeout_seconds, bool)
            or not isinstance(self.timeout_seconds, int | float)
            or not 0 < self.timeout_seconds <= 300
            or not isinstance(self.max_message_bytes, int)
            or not 1_024 <= self.max_message_bytes <= 1_048_576
            or not isinstance(self.max_processes, int)
            or not 1 <= self.max_processes <= 64
            or not isinstance(self.max_memory_bytes, int)
            or not 16 * 1024 * 1024 <= self.max_memory_bytes <= 4 * 1024 * 1024 * 1024
            or not isinstance(self.max_restarts, int)
            or not 0 <= self.max_restarts <= 8
            or isinstance(self.native_cleanup_foreground_deadline_seconds, bool)
            or not isinstance(self.native_cleanup_foreground_deadline_seconds, int | float)
            or not 0 < self.native_cleanup_foreground_deadline_seconds <= 300
            or not isinstance(self.windows_containment, WindowsContainmentMode)
            or (
                self.appcontainer_runtime_root is not None
                and (
                    not isinstance(self.appcontainer_runtime_root, Path)
                    or not self.appcontainer_runtime_root.is_absolute()
                )
            )
            or type(self.appcontainer_dependency_roots) is not tuple
            or any(
                not isinstance(root, Path) or not root.is_absolute()
                for root in self.appcontainer_dependency_roots
            )
        ):
            raise SandboxConfigurationError("Sandbox resource bounds are invalid")

    @property
    def native_resource_controls(self) -> bool:
        return sys.platform == "win32"


def _is_reparse(path: Path) -> bool:
    junction = getattr(path, "is_junction", None)
    return path.is_symlink() or (callable(junction) and bool(junction()))


def _owned_directory(path: Path, *, create: bool) -> Path:
    if not isinstance(path, Path) or not path.is_absolute():
        raise SandboxConfigurationError("Sandbox directory must be absolute")
    if create:
        with contextlib.suppress(FileExistsError):
            path.mkdir(parents=True, exist_ok=True)
    if not path.is_dir() or _is_reparse(path) or path.resolve(strict=True) != path:
        raise SandboxConfigurationError("Sandbox directory is not an owned regular directory")
    return path


@dataclass(frozen=True, slots=True)
class SandboxPaths:
    """Dedicated work/data paths created and owned by one sandbox instance."""

    root: Path
    work: Path
    data: Path

    @classmethod
    def create(cls, parent: Path, integration_id: str) -> SandboxPaths:
        parent = _owned_directory(parent, create=True)
        integration_id = _identifier(integration_id, "Integration ID")
        # Keep the AppContainer working directory below legacy Win32 path
        # limits even when a caller's owned root is nested by a test harness.
        # The full integration identity stays in protocol/audit data; the
        # directory token is collision-resistant ownership metadata only.
        directory_identity = sha256(integration_id.encode("utf-8")).hexdigest()[:16]
        for _ in range(16):
            root = parent / f"jarvis-sandbox-{directory_identity}-{uuid4().hex}"
            try:
                root.mkdir()
            except FileExistsError:
                continue
            try:
                work = root / "work"
                data = root / "data"
                work.mkdir()
                data.mkdir()
                result = cls(root, work, data)
                for path in (result.root, result.work, result.data):
                    _owned_directory(path, create=False)
                return result
            except Exception:
                shutil.rmtree(root, ignore_errors=True)
                raise
        raise SandboxConfigurationError("Could not allocate a unique sandbox directory")

    def validate(self) -> None:
        root = _owned_directory(self.root, create=False)
        for child in (self.work, self.data):
            if child.parent != root or child.name not in {"work", "data"}:
                raise SandboxConfigurationError("Sandbox child path is not owned")
            _owned_directory(child, create=False)

    def cleanup(self) -> None:
        self.validate()
        parent = self.root.parent
        if not self.root.name.startswith("jarvis-sandbox-"):
            raise SandboxCleanupError("Sandbox root identity is invalid")
        if self.root.parent != parent or self.root.resolve(strict=True).parent != parent:
            raise SandboxCleanupError("Sandbox root escaped its owner")
        try:
            shutil.rmtree(self.root)
        except OSError as error:
            raise SandboxCleanupError("Sandbox cleanup failed") from error

    @property
    def cleanup_receipt(self) -> Path:
        """Return the durable trusted receipt retained for uncertain cleanup."""

        return self.root / "native-cleanup-recovery.json"


_NATIVE_CLEANUP_RECEIPT_SCHEMA = 2


def _write_native_cleanup_receipt(path: Path, record: Mapping[str, object]) -> None:
    """Atomically retain a bounded, non-secret native-cleanup observation."""

    encoded = json.dumps(record, sort_keys=True, separators=(",", ":")).encode("utf-8")
    temporary = path.with_name(f".{path.name}.{uuid4().hex}.tmp")
    try:
        with temporary.open("xb") as handle:
            handle.write(encoded)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, path)
    finally:
        with contextlib.suppress(FileNotFoundError):
            temporary.unlink()


def _pending_native_cleanup_receipts(parent: Path) -> tuple[Path, ...]:
    """Find unfinished trusted receipts without following untrusted reparse points."""

    pending: list[Path] = []
    for root in parent.glob("jarvis-sandbox-*"):
        receipt = root / "native-cleanup-recovery.json"
        try:
            if _is_reparse(root) or not root.is_dir() or not receipt.is_file():
                continue
            raw = json.loads(receipt.read_text(encoding="utf-8"))
            if (
                not isinstance(raw, dict)
                or raw.get("schema") not in {1, _NATIVE_CLEANUP_RECEIPT_SCHEMA}
                or raw.get("state") != NativeCleanupState.CONFIRMED.value
            ):
                pending.append(receipt)
        except (OSError, ValueError, json.JSONDecodeError):
            # An unreadable receipt is security-relevant uncertainty, not a
            # reason to permit a new AppContainer ACL transaction.
            pending.append(receipt)
    return tuple(pending)


def _sandbox_environment() -> dict[str, str]:
    """Return only host values required to start a bounded child process."""

    allowed = ("SYSTEMROOT", "WINDIR", "SYSTEMDRIVE", "TEMP", "TMP")
    result = {key: os.environ[key] for key in allowed if key in os.environ}
    result.update({"PYTHONIOENCODING": "utf-8", "PYTHONUTF8": "1", "JARVIS_SANDBOX": "1"})
    mode = os.environ.get("JARVIS_R4R_TRACE_MODE")
    if mode in {
        "BASELINE_OFF",
        "COMPUTE_ONLY",
        "FLUSH_ONLY",
        "YIELD_ONLY",
        "UNIFIED_READER_NO_TRACE",
        "TRACE_ON",
    }:
        result["JARVIS_R4R_TRACE_MODE"] = mode
    return result


@dataclass(frozen=True, slots=True)
class _OwnedWindowsProcess:
    """A PID bound to its creation time, preventing PID-reuse cleanup mistakes."""

    process_id: int
    creation_time: int
    parent_process_id: int | None = None
    executable: str | None = None


class _WindowsProcessEntry(ctypes.Structure):
    """Stable Toolhelp entry type shared by the ownership monitor threads."""

    _fields_ = [
        ("dwSize", wintypes.DWORD),
        ("cntUsage", wintypes.DWORD),
        ("th32ProcessID", wintypes.DWORD),
        ("th32DefaultHeapID", ctypes.c_size_t),
        ("th32ModuleID", wintypes.DWORD),
        ("cntThreads", wintypes.DWORD),
        ("th32ParentProcessID", wintypes.DWORD),
        ("pcPriClassBase", wintypes.LONG),
        ("dwFlags", wintypes.DWORD),
        ("szExeFile", wintypes.WCHAR * 260),
    ]


class _WindowsProcessBasicInformation(ctypes.Structure):
    """The minimal native process identity needed to validate a parent edge."""

    _fields_ = [
        ("reserved_1", ctypes.c_void_p),
        ("peb_base_address", ctypes.c_void_p),
        ("reserved_2", ctypes.c_void_p * 2),
        ("process_id", ctypes.c_void_p),
        ("parent_process_id", ctypes.c_void_p),
    ]


class _WindowsJobBasicAccountingInformation(ctypes.Structure):
    """Win32 ``JOBOBJECT_BASIC_ACCOUNTING_INFORMATION``.

    ``ActiveProcesses`` is Windows' accounting source for the number of
    processes currently associated with a Job.  A Job handle's signalled state
    has different semantics and must never be treated as an empty-Job test.
    """

    _fields_ = [
        ("TotalUserTime", ctypes.c_longlong),  # LARGE_INTEGER
        ("TotalKernelTime", ctypes.c_longlong),  # LARGE_INTEGER
        ("ThisPeriodTotalUserTime", ctypes.c_longlong),  # LARGE_INTEGER
        ("ThisPeriodTotalKernelTime", ctypes.c_longlong),  # LARGE_INTEGER
        ("TotalPageFaultCount", wintypes.DWORD),
        ("TotalProcesses", wintypes.DWORD),
        ("ActiveProcesses", wintypes.DWORD),
        ("TotalTerminatedProcesses", wintypes.DWORD),
    ]


class _WindowsJob:  # pragma: no cover - opt-in native Windows integration
    """Small native Job Object wrapper for process-tree and resource ownership."""

    _JOB_OBJECT_EXTENDED_LIMIT_INFORMATION = 9
    _JOB_OBJECT_BASIC_ACCOUNTING_INFORMATION = 1
    _JOB_OBJECT_LIMIT_ACTIVE_PROCESS = 0x00000008
    _JOB_OBJECT_LIMIT_PROCESS_MEMORY = 0x00000100
    _JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE = 0x00002000
    _PROCESS_SET_QUOTA = 0x0100
    _PROCESS_TERMINATE = 0x0001
    _PROCESS_QUERY_LIMITED_INFORMATION = 0x1000
    _STILL_ACTIVE = 259
    _OWNERSHIP_POLL_SECONDS = 0.01
    _ACTIVE_PROCESS_POLL_SECONDS = 0.025

    def __init__(self, handle: int, library: Any, native_library: Any) -> None:
        self._handle = handle
        self._evidence_id = str(uuid4())
        self._created_monotonic_ns = time.monotonic_ns()
        self._closed_monotonic_ns: int | None = None
        self._library = library
        self._native_library = native_library
        self._root_process_id: int | None = None
        self._owned_processes: dict[int, _OwnedWindowsProcess] = {}
        self._ownership_lock = threading.Lock()
        self._ownership_stop = threading.Event()
        self._ownership_thread: threading.Thread | None = None
        self._ownership_error: str | None = None
        self._terminated = False
        self._lifecycle_lock = threading.RLock()
        self._maximum_active_process_count = 0
        self._last_evidence: dict[str, object] = {}

    @classmethod
    def create(cls, limits: SandboxLimits) -> _WindowsJob:
        if sys.platform != "win32":
            raise SandboxIsolationUnavailable("Windows Job Objects are unavailable")
        try:
            library = ctypes.WinDLL("kernel32.dll", use_last_error=True)
            library.CreateJobObjectW.argtypes = [ctypes.c_void_p, wintypes.LPCWSTR]
            library.CreateJobObjectW.restype = ctypes.c_void_p
            library.SetInformationJobObject.argtypes = [
                ctypes.c_void_p,
                wintypes.INT,
                ctypes.c_void_p,
                wintypes.DWORD,
            ]
            library.SetInformationJobObject.restype = wintypes.BOOL
            library.QueryInformationJobObject.argtypes = [
                ctypes.c_void_p,
                wintypes.INT,
                ctypes.c_void_p,
                wintypes.DWORD,
                ctypes.POINTER(wintypes.DWORD),
            ]
            library.QueryInformationJobObject.restype = wintypes.BOOL
            library.OpenProcess.argtypes = [wintypes.DWORD, wintypes.BOOL, wintypes.DWORD]
            library.OpenProcess.restype = ctypes.c_void_p
            library.GetProcessTimes.argtypes = [
                ctypes.c_void_p,
                ctypes.POINTER(wintypes.FILETIME),
                ctypes.POINTER(wintypes.FILETIME),
                ctypes.POINTER(wintypes.FILETIME),
                ctypes.POINTER(wintypes.FILETIME),
            ]
            library.GetProcessTimes.restype = wintypes.BOOL
            library.GetExitCodeProcess.argtypes = [ctypes.c_void_p, ctypes.POINTER(wintypes.DWORD)]
            library.GetExitCodeProcess.restype = wintypes.BOOL
            library.QueryFullProcessImageNameW.argtypes = [
                ctypes.c_void_p,
                wintypes.DWORD,
                wintypes.LPWSTR,
                ctypes.POINTER(wintypes.DWORD),
            ]
            library.QueryFullProcessImageNameW.restype = wintypes.BOOL
            library.CreateToolhelp32Snapshot.argtypes = [wintypes.DWORD, wintypes.DWORD]
            library.CreateToolhelp32Snapshot.restype = ctypes.c_void_p
            library.Process32FirstW.argtypes = [
                ctypes.c_void_p,
                ctypes.POINTER(_WindowsProcessEntry),
            ]
            library.Process32FirstW.restype = wintypes.BOOL
            library.Process32NextW.argtypes = [
                ctypes.c_void_p,
                ctypes.POINTER(_WindowsProcessEntry),
            ]
            library.Process32NextW.restype = wintypes.BOOL
            library.AssignProcessToJobObject.argtypes = [ctypes.c_void_p, ctypes.c_void_p]
            library.AssignProcessToJobObject.restype = wintypes.BOOL
            library.TerminateJobObject.argtypes = [ctypes.c_void_p, wintypes.UINT]
            library.TerminateJobObject.restype = wintypes.BOOL
            library.WaitForSingleObject.argtypes = [ctypes.c_void_p, wintypes.DWORD]
            library.WaitForSingleObject.restype = wintypes.DWORD
            library.CloseHandle.argtypes = [ctypes.c_void_p]
            library.CloseHandle.restype = wintypes.BOOL
            native_library = ctypes.WinDLL("ntdll.dll", use_last_error=True)
            native_library.NtQueryInformationProcess.argtypes = [
                ctypes.c_void_p,
                wintypes.ULONG,
                ctypes.c_void_p,
                wintypes.ULONG,
                ctypes.POINTER(wintypes.ULONG),
            ]
            native_library.NtQueryInformationProcess.restype = wintypes.LONG
            handle = library.CreateJobObjectW(None, None)
            if not handle:
                raise OSError(ctypes.get_last_error(), "CreateJobObjectW failed")
            job = cls(int(handle), library, native_library)
            try:
                job._set_limits(limits)
            except Exception:
                job.close()
                raise
            return job
        except (AttributeError, OSError, TypeError) as error:
            raise SandboxIsolationUnavailable("Windows Job Object setup failed") from error

    def _set_limits(self, limits: SandboxLimits) -> None:
        class Basic(ctypes.Structure):
            _fields_ = [
                ("PerProcessUserTime", ctypes.c_longlong),
                ("PerJobUserTime", ctypes.c_longlong),
                ("LimitFlags", wintypes.DWORD),
                ("MinimumWorkingSetSize", ctypes.c_size_t),
                ("MaximumWorkingSetSize", ctypes.c_size_t),
                ("ActiveProcessLimit", wintypes.DWORD),
                ("Affinity", ctypes.c_size_t),
                ("PriorityClass", wintypes.DWORD),
                ("SchedulingClass", wintypes.DWORD),
            ]

        class IoCounters(ctypes.Structure):
            _fields_ = [
                (name, ctypes.c_ulonglong)
                for name in (
                    "ReadOperationCount",
                    "WriteOperationCount",
                    "OtherOperationCount",
                    "ReadTransferCount",
                    "WriteTransferCount",
                    "OtherTransferCount",
                )
            ]

        class Extended(ctypes.Structure):
            _fields_ = [
                ("BasicLimitInformation", Basic),
                ("IoInfo", IoCounters),
                ("ProcessMemoryLimit", ctypes.c_size_t),
                ("JobMemoryLimit", ctypes.c_size_t),
                ("PeakProcessMemoryUsed", ctypes.c_size_t),
                ("PeakJobMemoryUsed", ctypes.c_size_t),
            ]

        info = Extended()
        info.BasicLimitInformation.LimitFlags = (
            self._JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE
            | self._JOB_OBJECT_LIMIT_ACTIVE_PROCESS
            | self._JOB_OBJECT_LIMIT_PROCESS_MEMORY
        )
        info.BasicLimitInformation.ActiveProcessLimit = limits.max_processes
        info.ProcessMemoryLimit = limits.max_memory_bytes
        if not self._library.SetInformationJobObject(
            self._handle,
            self._JOB_OBJECT_EXTENDED_LIMIT_INFORMATION,
            ctypes.byref(info),
            ctypes.sizeof(info),
        ):
            raise OSError(ctypes.get_last_error(), "SetInformationJobObject failed")

    def assign(self, process_id: int) -> None:
        handle = self._library.OpenProcess(
            self._PROCESS_SET_QUOTA
            | self._PROCESS_TERMINATE
            | self._PROCESS_QUERY_LIMITED_INFORMATION,
            False,
            process_id,
        )
        if not handle:
            raise SandboxIsolationUnavailable("Sandbox process handle could not be opened")
        try:
            self.assign_handle(handle, process_id)
        finally:
            self._library.CloseHandle(handle)

    def assign_handle(self, process_handle: int, process_id: int | None = None) -> None:
        """Assign a suspended process before it is allowed to execute."""

        if not self._library.AssignProcessToJobObject(self._handle, process_handle):
            raise SandboxIsolationUnavailable("Sandbox process could not join its Job Object")
        if process_id is not None:
            self._root_process_id = process_id
            self._record_process_handle(process_handle, process_id)
            self._start_ownership_monitor()

    @property
    def evidence_id(self) -> str:
        return self._evidence_id

    def configured_limits(self) -> dict[str, object]:
        """Query the applied Job limit rather than trusting caller settings."""

        with self._lifecycle_lock:
            if not self._handle:
                return {"state": "CLOSED"}

            class Basic(ctypes.Structure):
                _fields_ = [
                    ("PerProcessUserTime", ctypes.c_longlong),
                    ("PerJobUserTime", ctypes.c_longlong),
                    ("LimitFlags", wintypes.DWORD),
                    ("MinimumWorkingSetSize", ctypes.c_size_t),
                    ("MaximumWorkingSetSize", ctypes.c_size_t),
                    ("ActiveProcessLimit", wintypes.DWORD),
                    ("Affinity", ctypes.c_size_t),
                    ("PriorityClass", wintypes.DWORD),
                    ("SchedulingClass", wintypes.DWORD),
                ]

            class IoCounters(ctypes.Structure):
                _fields_ = [
                    (name, ctypes.c_ulonglong)
                    for name in (
                        "ReadOperationCount",
                        "WriteOperationCount",
                        "OtherOperationCount",
                        "ReadTransferCount",
                        "WriteTransferCount",
                        "OtherTransferCount",
                    )
                ]

            class Extended(ctypes.Structure):
                _fields_ = [
                    ("BasicLimitInformation", Basic),
                    ("IoInfo", IoCounters),
                    ("ProcessMemoryLimit", ctypes.c_size_t),
                    ("JobMemoryLimit", ctypes.c_size_t),
                    ("PeakProcessMemoryUsed", ctypes.c_size_t),
                    ("PeakJobMemoryUsed", ctypes.c_size_t),
                ]

            info = Extended()
            returned_length = wintypes.DWORD()
            if not self._library.QueryInformationJobObject(
                self._handle,
                self._JOB_OBJECT_EXTENDED_LIMIT_INFORMATION,
                ctypes.byref(info),
                ctypes.sizeof(info),
                ctypes.byref(returned_length),
            ):
                raise SandboxIsolationUnavailable("Windows Job limit query failed")
            return {
                "active_process_limit": int(info.BasicLimitInformation.ActiveProcessLimit),
                "limit_flags": int(info.BasicLimitInformation.LimitFlags),
                "process_memory_limit": int(info.ProcessMemoryLimit),
            }

    def evidence_snapshot(self) -> dict[str, object]:
        """Capture this Job and only its exact owned process ledger."""

        with self._lifecycle_lock:
            if not self._handle:
                return dict(self._last_evidence)
            active_count: int | str
            try:
                active_count = self.active_process_count()
                limits = self.configured_limits()
                state = "OPEN"
            except Exception as error:
                active_count = "UNKNOWN"
                limits = {"state": "UNKNOWN", "error": type(error).__name__}
                state = "UNKNOWN"
            with self._ownership_lock:
                owned = tuple(self._owned_processes.values())
            processes: list[dict[str, object]] = []
            for item in owned:
                alive: bool | str
                exit_code: int | str
                try:
                    handle = self._library.OpenProcess(
                        self._PROCESS_QUERY_LIMITED_INFORMATION, False, item.process_id
                    )
                    if not handle:
                        alive, exit_code = False, "UNKNOWN"
                    else:
                        try:
                            same_identity = self._creation_time(handle) == item.creation_time
                            code = wintypes.DWORD()
                            queried = self._library.GetExitCodeProcess(handle, ctypes.byref(code))
                            if not same_identity or not queried:
                                alive, exit_code = "UNKNOWN", "UNKNOWN"
                            else:
                                exit_code = int(code.value)
                                alive = exit_code == self._STILL_ACTIVE
                        finally:
                            self._library.CloseHandle(handle)
                except Exception:
                    alive, exit_code = "UNKNOWN", "UNKNOWN"
                processes.append(
                    {
                        "pid": item.process_id,
                        "parent_pid": item.parent_process_id,
                        "executable": item.executable,
                        "creation_time": item.creation_time,
                        "alive": alive,
                        "exit_code": exit_code,
                    }
                )
            snapshot = {
                "evidence_id": self._evidence_id,
                "state": state,
                "created_monotonic_ns": self._created_monotonic_ns,
                "closed_monotonic_ns": self._closed_monotonic_ns,
                "configured_limits": limits,
                "active_process_count": active_count,
                "maximum_active_process_count": self._maximum_active_process_count,
                "assigned_pids": [item["pid"] for item in processes],
                "processes": processes,
                "empty": active_count == 0,
            }
            self._last_evidence = snapshot
            return dict(snapshot)

    def terminate(self) -> None:
        """End the Job and every exact descendant observed while its root lived.

        Windows normally assigns child processes to their parent's Job Object.
        The owned ledger is an additional fail-closed safeguard for supported
        breakaway/nesting edge cases: it records only descendants observed from
        the assigned root while that root is alive, bound to creation time, and
        never expands to a process-name-wide or ambient process search.
        """

        errors: list[str] = []
        try:
            self._capture_owned_tree()
        except Exception as error:
            errors.append(f"ownership_capture:{type(error).__name__}")
        try:
            self._stop_ownership_monitor()
        except Exception as error:
            errors.append(f"ownership_monitor:{type(error).__name__}")
        if self._ownership_error is not None:
            errors.append("ownership_monitor:failed")
        try:
            active_processes = self.active_process_count()
        except Exception as error:
            errors.append(f"job_accounting:{type(error).__name__}")
            active_processes = None
        if active_processes and not self._terminated:
            if not self._library.TerminateJobObject(self._handle, 1):
                errors.append("job_terminate:failed")
            else:
                self._terminated = True
        try:
            self._terminate_recorded_processes()
        except Exception as error:
            errors.append(f"owned_process_cleanup:{type(error).__name__}")
        if errors:
            raise SandboxIsolationUnavailable("; ".join(sorted(set(errors))))

    def active_process_count(self) -> int:
        """Return authoritative Windows Job membership accounting.

        A query failure is containment evidence failure, never proof that the
        Job is empty.  The lifecycle lock prevents a concurrent close from
        invalidating the native handle while the accounting call is active.
        """

        with self._lifecycle_lock:
            if not self._handle:
                raise SandboxIsolationUnavailable("Windows Job Object is already closed")
            accounting = _WindowsJobBasicAccountingInformation()
            returned_length = wintypes.DWORD()
            try:
                succeeded = self._library.QueryInformationJobObject(
                    self._handle,
                    self._JOB_OBJECT_BASIC_ACCOUNTING_INFORMATION,
                    ctypes.byref(accounting),
                    ctypes.sizeof(accounting),
                    ctypes.byref(returned_length),
                )
            except (AttributeError, OSError, TypeError, ValueError) as error:
                raise SandboxIsolationUnavailable("Windows Job accounting query failed") from error
            if not succeeded:
                raise SandboxIsolationUnavailable("Windows Job accounting query failed")
            if returned_length.value not in {0, ctypes.sizeof(accounting)}:
                raise SandboxIsolationUnavailable(
                    "Windows Job accounting query returned invalid data"
                )
            count = int(accounting.ActiveProcesses)
            self._maximum_active_process_count = max(self._maximum_active_process_count, count)
            return count

    def _start_ownership_monitor(self) -> None:
        if self._ownership_thread is not None:
            return
        monitor = threading.Thread(
            target=self._monitor_owned_tree,
            name="jarvis-windows-job-ownership",
            daemon=True,
        )
        self._ownership_thread = monitor
        monitor.start()

    def _monitor_owned_tree(self) -> None:
        while not self._ownership_stop.wait(self._OWNERSHIP_POLL_SECONDS):
            try:
                self._capture_owned_tree()
            except Exception as error:
                self._ownership_error = (
                    f"Windows owned-process observation failed: {type(error).__name__}: {error}"
                )
                self._ownership_stop.set()
                return

    def _stop_ownership_monitor(self) -> None:
        self._ownership_stop.set()
        monitor = self._ownership_thread
        if monitor is not None and monitor is not threading.current_thread():
            monitor.join(timeout=1.0)
            if monitor.is_alive():
                raise SandboxIsolationUnavailable("Windows owned-process observation did not stop")

    def _capture_owned_tree(self) -> None:
        root = self._root_process_id
        if root is None:
            return
        with self._ownership_lock:
            known = dict(self._owned_processes)
        active = {
            process_id
            for process_id, owned in known.items()
            if self._owned_process_is_active(owned)
        }
        if root not in active:
            return
        parents = self._process_parents()
        frontier = set(active)
        seen: set[int] = set()
        while frontier:
            parent_process_id = frontier.pop()
            children = {
                process_id
                for process_id, observed_parent in parents.items()
                if observed_parent == parent_process_id and process_id not in seen
            }
            seen.update(children)
            for process_id in children:
                if self._record_descendant(process_id, parent_process_id):
                    frontier.add(process_id)

    def _record_descendant(self, process_id: int, expected_parent_process_id: int) -> bool:
        with self._ownership_lock:
            parent = self._owned_processes.get(expected_parent_process_id)
        if parent is None or not self._owned_process_is_active(parent):
            return False
        handle = self._library.OpenProcess(
            self._PROCESS_QUERY_LIMITED_INFORMATION,
            False,
            process_id,
        )
        if not handle:
            return False
        try:
            # The Toolhelp snapshot can race process exit and PID reuse.  The
            # current native parent edge must still lead to an active exact
            # owner before this PID enters the ledger.
            if self._parent_process_id(handle) != expected_parent_process_id:
                return False
            return self._record_process_handle(handle, process_id)
        finally:
            self._library.CloseHandle(handle)

    def _record_process_handle(self, process_handle: int, process_id: int) -> bool:
        creation_time = self._creation_time(process_handle)
        try:
            parent_process_id = self._parent_process_id(process_handle)
        except Exception:
            parent_process_id = None
        try:
            buffer = ctypes.create_unicode_buffer(1024)
            length = wintypes.DWORD(len(buffer))
            executable = (
                buffer.value
                if self._library.QueryFullProcessImageNameW(
                    process_handle, 0, buffer, ctypes.byref(length)
                )
                else None
            )
        except Exception:
            executable = None
        with self._ownership_lock:
            existing = self._owned_processes.get(process_id)
            if existing is None:
                self._owned_processes[process_id] = _OwnedWindowsProcess(
                    process_id,
                    creation_time,
                    parent_process_id,
                    executable,
                )
                return True
            # The original identity remains authoritative.  A reused PID is
            # an unrelated process and must never be absorbed into or killed
            # by this Job's exact ownership ledger.
            return existing.creation_time == creation_time

    def _parent_process_id(self, process_handle: int) -> int:
        information = _WindowsProcessBasicInformation()
        status = self._native_library.NtQueryInformationProcess(
            process_handle,
            0,
            ctypes.byref(information),
            ctypes.sizeof(information),
            None,
        )
        if status != 0:
            raise OSError(f"NtQueryInformationProcess failed with NTSTATUS {status}")
        return int(information.parent_process_id or 0)

    def _creation_time(self, process_handle: int) -> int:
        creation = wintypes.FILETIME()
        exit_time = wintypes.FILETIME()
        kernel_time = wintypes.FILETIME()
        user_time = wintypes.FILETIME()
        if not self._library.GetProcessTimes(
            process_handle,
            ctypes.byref(creation),
            ctypes.byref(exit_time),
            ctypes.byref(kernel_time),
            ctypes.byref(user_time),
        ):
            raise OSError(ctypes.get_last_error(), "GetProcessTimes failed")
        return (int(creation.dwHighDateTime) << 32) | int(creation.dwLowDateTime)

    def _owned_process_is_active(self, owned: _OwnedWindowsProcess) -> bool:
        handle = self._library.OpenProcess(
            self._PROCESS_QUERY_LIMITED_INFORMATION,
            False,
            owned.process_id,
        )
        if not handle:
            return False
        try:
            if self._creation_time(handle) != owned.creation_time:
                return False
            exit_code = wintypes.DWORD()
            if not self._library.GetExitCodeProcess(handle, ctypes.byref(exit_code)):
                raise OSError(ctypes.get_last_error(), "GetExitCodeProcess failed")
            return int(exit_code.value) == self._STILL_ACTIVE
        finally:
            self._library.CloseHandle(handle)

    def _terminate_recorded_processes(self) -> None:
        with self._ownership_lock:
            owned_processes = tuple(self._owned_processes.values())
        for _ in range(20):
            active = tuple(
                owned for owned in owned_processes if self._owned_process_is_active(owned)
            )
            if not active:
                return
            termination_failed = False
            for owned in active:
                handle = self._library.OpenProcess(
                    self._PROCESS_TERMINATE | self._PROCESS_QUERY_LIMITED_INFORMATION,
                    False,
                    owned.process_id,
                )
                if not handle:
                    continue
                try:
                    if self._creation_time(handle) != owned.creation_time:
                        continue
                    if not self._library.TerminateProcess(handle, 1):
                        termination_failed = True
                finally:
                    self._library.CloseHandle(handle)
            if termination_failed:
                active = tuple(owned for owned in active if self._owned_process_is_active(owned))
                if active:
                    raise SandboxIsolationUnavailable("Windows owned-process termination failed")
            time.sleep(0.05)
        active = tuple(owned for owned in owned_processes if self._owned_process_is_active(owned))
        if active:
            raise SandboxIsolationUnavailable("Windows owned process survived Job cleanup")

    def _descendant_processes(self, root_process_id: int) -> set[int]:
        entries = self._process_parents()
        result: set[int] = set()
        frontier = {root_process_id}
        while frontier:
            children = {
                process_id
                for process_id, parent_id in entries.items()
                if parent_id in frontier and process_id not in result
            }
            result.update(children)
            frontier = children
        return result

    def _process_parents(self) -> dict[int, int]:
        snapshot = self._library.CreateToolhelp32Snapshot(0x00000002, 0)
        if not snapshot or int(snapshot) == -1:
            return {}
        try:
            entries: dict[int, int] = {}
            entry = _WindowsProcessEntry()
            entry.dwSize = ctypes.sizeof(_WindowsProcessEntry)
            if self._library.Process32FirstW(snapshot, ctypes.byref(entry)):
                while True:
                    entries[int(entry.th32ProcessID)] = int(entry.th32ParentProcessID)
                    if not self._library.Process32NextW(snapshot, ctypes.byref(entry)):
                        break
            return entries
        finally:
            self._library.CloseHandle(snapshot)

    async def wait_for_empty(self, timeout_seconds: float) -> bool:
        """Boundedly observe ``ActiveProcesses == 0`` through Job accounting."""

        if (
            isinstance(timeout_seconds, bool)
            or not isinstance(timeout_seconds, int | float)
            or timeout_seconds < 0
        ):
            raise SandboxIsolationUnavailable("Windows Job empty-wait timeout is invalid")
        deadline = time.monotonic() + float(timeout_seconds)
        while True:
            if await asyncio.to_thread(self.active_process_count) == 0:
                return True
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                return False
            await asyncio.sleep(min(self._ACTIVE_PROCESS_POLL_SECONDS, remaining))

    def close(self) -> None:
        with self._lifecycle_lock:
            if not self._handle:
                return
            termination_error: Exception | None = None
            try:
                # This preserves kill-on-close as the final native backstop.
                # ``terminate()`` only calls TerminateJobObject when accounting
                # still reports active Job members, so normal root completion
                # is not needlessly terminated.
                self.terminate()
            except Exception as error:
                termination_error = error
            handle, self._handle = self._handle, 0
            if not self._library.CloseHandle(handle):
                raise SandboxIsolationUnavailable("Sandbox Job Object cleanup failed")
            self._closed_monotonic_ns = time.monotonic_ns()
            self._last_evidence = {
                **self._last_evidence,
                "state": "CLOSED",
                "closed_monotonic_ns": self._closed_monotonic_ns,
                "empty": self._last_evidence.get("active_process_count") == 0,
            }
            if termination_error is not None:
                raise termination_error


def create_owned_windows_job(*, max_processes: int, max_memory_bytes: int) -> _WindowsJob:
    """Create the shared native Job Object used for trusted child ownership.

    The function intentionally exposes lifecycle containment only.  Generated
    executable integrations still require the stronger AppContainer launch
    path in :class:`SandboxProcess`; callers must assign a suspended root
    process before it is resumed.
    """

    limits = SandboxLimits(
        max_processes=max_processes,
        max_memory_bytes=max_memory_bytes,
        windows_containment=WindowsContainmentMode.JOB_OBJECT_ONLY,
    )
    return _WindowsJob.create(limits)


class SandboxProcess:
    """Own one generated integration process and its complete request lifecycle."""

    def __init__(
        self,
        executable: Path,
        arguments: tuple[str, ...],
        *,
        integration_id: str,
        parent_directory: Path,
        recovery_integrity_signer: Callable[[Mapping[str, object]], str] | None = None,
        limits: SandboxLimits | None = None,
        resource_governor: ResourceGovernor | None = None,
        resource_priority: ResourcePriority = ResourcePriority.USER_REQUESTED,
        flight_recorder: Any | None = None,
        diagnostics_enabled: bool = False,
        diagnostic_mode: str | None = None,
        parent_only_recorder: bool = False,
    ) -> None:
        try:
            self._executable = resolve_trusted_executable(os.fspath(executable))
        except (ProcessIdentityError, TypeError) as error:
            raise SandboxConfigurationError("Sandbox executable identity is invalid") from error
        if (
            not isinstance(arguments, tuple)
            or len(arguments) > 128
            or any(
                type(argument) is not str
                or not argument
                or len(argument) > 4_096
                or "\x00" in argument
                for argument in arguments
            )
        ):
            raise SandboxConfigurationError("Sandbox executable arguments are invalid")
        self._integration_id = _identifier(integration_id, "Integration ID")
        self._parent_directory = _owned_directory(parent_directory, create=True)
        self._recovery_integrity_signer = recovery_integrity_signer
        self._limits = limits or SandboxLimits()
        if not isinstance(resource_priority, ResourcePriority):
            raise SandboxConfigurationError("Sandbox resource priority is invalid")
        self._arguments = arguments
        self._resource_governor = resource_governor
        self._resource_priority = resource_priority
        self._resource_reservation_id: UUID | None = None
        self._process: Any | None = None
        self._job: _WindowsJob | None = None
        self._security_status: SandboxSecurityStatus | None = None
        self._paths: SandboxPaths | None = None
        self._cleanup_quarantined = False
        self._cleanup_observations: list[Mapping[str, object]] = []
        self._lock = asyncio.Lock()
        self._closed = False
        self._restart_count = 0
        self._protocol_ready = False
        self._pipes_established = False
        self._job_assigned = False
        self._flight_recorder = flight_recorder
        self._diagnostics_enabled = diagnostics_enabled
        if diagnostic_mode is not None and diagnostic_mode not in {
            "BASELINE_OFF",
            "COMPUTE_ONLY",
            "FLUSH_ONLY",
            "YIELD_ONLY",
            "UNIFIED_READER_NO_TRACE",
            "TRACE_ON",
        }:
            raise SandboxConfigurationError("Diagnostic mode is invalid")
        self._diagnostic_mode = diagnostic_mode
        self._parent_recorder = (
            CapabilityFlightRecorder(uuid4(), capability_id=integration_id)
            if parent_only_recorder
            else None
        )
        self._launch_monotonic_ns: int | None = None
        self._lifecycle_run_id = (
            str(flight_recorder.lifecycle_run_id)
            if flight_recorder is not None and getattr(flight_recorder, "lifecycle_run_id", None)
            else None
        )
        self._stderr_task: asyncio.Task[None] | None = None
        self._stderr_buffer = bytearray()
        self._child_events: list[Mapping[str, object]] = []
        self._protocol_diagnostics = SandboxProtocolDiagnostics(
            "NOT_STARTED",
            None,
            None,
            self._integration_id,
            None,
            False,
            None,
            False,
            None,
            "",
            {},
            {},
            {},
            (),
        )

    @property
    def paths(self) -> SandboxPaths:
        if self._paths is None:
            raise SandboxProcessError("Sandbox has not started")
        return self._paths

    @property
    def is_running(self) -> bool:
        return self._process is not None and self._process.returncode is None

    @property
    def restart_count(self) -> int:
        return self._restart_count

    @property
    def security_status(self) -> SandboxSecurityStatus | None:
        """Return the observable containment established by the active launch."""

        return self._security_status

    @property
    def protocol_diagnostics(self) -> SandboxProtocolDiagnostics:
        return self._protocol_diagnostics

    @property
    def cleanup_observations(self) -> tuple[Mapping[str, object], ...]:
        """Return parent-owned native cleanup observations for qualification."""

        return tuple(dict(item) for item in self._cleanup_observations)

    def _phase(self, phase: str, *, state: Mapping[str, object] | None = None) -> None:
        process = self._process
        self._protocol_diagnostics = replace(
            self._protocol_diagnostics,
            phase=phase,
            pid=getattr(process, "pid", None) if process is not None else None,
            process_alive=bool(process is not None and process.returncode is None),
            exit_code=getattr(process, "returncode", None) if process is not None else None,
            stderr_tail=_redact_diagnostic(bytes(self._stderr_buffer).decode("utf-8", "replace")),
            job=self._job_snapshot(),
            child_events=tuple(self._child_events),
            parent_flight_recorder=(
                self._parent_recorder.as_dict() if self._parent_recorder is not None else {}
            ),
        )
        if self._flight_recorder is not None:
            self._flight_recorder.record(
                component="sandbox_protocol",
                stage=phase,
                operation="health_protocol_phase",
                resource_identity={
                    "pid": self._protocol_diagnostics.pid,
                    "integration_id": self._integration_id,
                },
                state_after=state or self._protocol_diagnostics.as_dict(),
            )
        if self._parent_recorder is not None:
            self._parent_recorder.record(
                component="sandbox_parent",
                stage=phase,
                operation="parent_protocol_phase",
                resource_identity={"pid": self._protocol_diagnostics.pid},
                state_after=self._owned_state(),
            )

        phase_aliases = {
            "PROCESS_CREATE_REQUESTED": "PROCESS_CREATE_BEGIN",
            "PROCESS_CREATED": "PROCESS_CREATED",
            "PROCESS_CONFIRMED_ALIVE": "PROCESS_ALIVE_PRE_REQUEST",
            "HEALTH_REQUEST_SERIALIZED": "REQUEST_SERIALIZED",
            "HEALTH_REQUEST_WRITE_BEGIN": "REQUEST_WRITE_BEGIN",
            "HEALTH_REQUEST_WRITE_COMPLETE": "REQUEST_WRITE_COMPLETE",
            "HEALTH_REQUEST_FLUSH_COMPLETE": "REQUEST_FLUSH_OR_DRAIN_COMPLETE",
            "HEALTH_RESPONSE_WAIT_BEGIN": "RESPONSE_WAIT_BEGIN",
            "HEALTH_RESPONSE_BYTES_OR_LINE_RECEIVED": "RESPONSE_DATA_RECEIVED",
            "HEALTH_RESPONSE_PARSED": "RESPONSE_PARSED",
            "PROTOCOL_VALIDATED": "PROTOCOL_VALIDATED",
            "REQUEST_ID_VALIDATED": "REQUEST_ID_VALIDATED",
            "INTEGRATION_ID_VALIDATED": "INTEGRATION_ID_VALIDATED",
            "HEALTH_STATUS_VALIDATED": "STATUS_VALIDATED",
        }
        if self._parent_recorder is not None and phase in phase_aliases:
            self._parent_recorder.record(
                component="sandbox_parent",
                stage=phase_aliases[phase],
                operation="parent_lifecycle_phase",
                resource_identity={"pid": self._protocol_diagnostics.pid},
                state_after=self._owned_state(),
            )

    def _owned_state(self) -> dict[str, object]:
        process = self._process
        state: dict[str, object] = {
            "pid": getattr(process, "pid", None) if process is not None else None,
            "alive": bool(process is not None and process.returncode is None),
            "exit_code": getattr(process, "returncode", None) if process is not None else None,
            "job": self._job_snapshot(),
        }
        if self._launch_monotonic_ns is not None:
            state["elapsed_ms"] = round(
                (time.monotonic_ns() - self._launch_monotonic_ns) / 1_000_000, 3
            )
        return state

    def _parent_phase(self, phase: str) -> None:
        if self._parent_recorder is not None:
            self._parent_recorder.record(
                component="sandbox_parent",
                stage=phase,
                operation="parent_lifecycle_phase",
                resource_identity={"pid": getattr(self._process, "pid", None)},
                state_after=self._owned_state(),
            )
            self._protocol_diagnostics = replace(
                self._protocol_diagnostics,
                parent_flight_recorder=self._parent_recorder.as_dict(),
            )

    def _parent_observation(
        self,
        stage: str,
        *,
        process: Any | None = None,
        job: _WindowsJob | None = None,
        state: Mapping[str, object] | None = None,
    ) -> None:
        """Record exact owned native state without affecting lifecycle control."""

        if self._parent_recorder is None:
            return
        observed_process = process if process is not None else self._process
        process_state: dict[str, object] = {
            "pid": getattr(observed_process, "pid", None),
            "alive": (
                getattr(observed_process, "returncode", None) is None
                if observed_process is not None
                else False
            ),
            "exit_code": getattr(observed_process, "returncode", None),
        }
        if observed_process is not None:
            cleanup = getattr(observed_process, "cleanup_evidence", None)
            if isinstance(cleanup, Mapping):
                process_state["security_cleanup"] = dict(cleanup)
        job_state = job.evidence_snapshot() if job is not None else {"state": "NONE"}
        self._parent_recorder.record(
            component="sandbox_parent",
            stage=stage,
            operation="owned_native_lifecycle_observation",
            resource_identity={
                "pid": process_state["pid"],
                "job_evidence_id": job_state.get("evidence_id"),
            },
            state_after={
                "process": process_state,
                "job": job_state,
                **(dict(state) if state is not None else {}),
            },
        )
        self._protocol_diagnostics = replace(
            self._protocol_diagnostics,
            parent_flight_recorder=self._parent_recorder.as_dict(),
        )

    def _job_snapshot(self) -> dict[str, object]:
        snapshot: dict[str, object] = {
            "configured_active_process_limit": self._limits.max_processes,
            "job_assigned": self._job_assigned,
        }
        if self._job is not None:
            try:
                snapshot["active_process_count"] = self._job.active_process_count()
            except Exception:
                snapshot["active_process_count"] = "unavailable"
        return snapshot

    async def _capture_stderr(self, stream: Any) -> None:
        try:
            while True:
                chunk = await stream.read(2048)
                if not chunk:
                    return
                self._stderr_buffer.extend(chunk)
                if len(self._stderr_buffer) > 8_192:
                    del self._stderr_buffer[:-8_192]
                for line in chunk.decode("utf-8", "replace").splitlines():
                    if line.startswith("JARVIS_SANDBOX_TRACE "):
                        with contextlib.suppress(json.JSONDecodeError):
                            event = json.loads(line[21:])
                            if isinstance(event, dict) and len(self._child_events) < 128:
                                self._child_events.append(event)
        except (asyncio.CancelledError, AttributeError, OSError):
            return

    @staticmethod
    def _safe_trace(value: object, *, key: str = "") -> object:
        if _DIAGNOSTIC_SECRET.search(key):
            return "[REDACTED]"
        if isinstance(value, str):
            return _redact_diagnostic(value[:MAX_TRACE_METADATA_BYTES])
        if isinstance(value, Mapping):
            return {
                str(item_key)[:128]: SandboxProcess._safe_trace(item, key=str(item_key))
                for item_key, item in list(value.items())[:32]
            }
        if isinstance(value, list | tuple):
            return [SandboxProcess._safe_trace(item) for item in list(value)[:32]]
        if isinstance(value, int | float | bool) or value is None:
            return value
        return str(value)[:MAX_TRACE_METADATA_BYTES]

    def _accept_trace(self, trace: SandboxMessage, *, sequence: int) -> int:
        if trace.response or trace.kind != "trace":
            raise SandboxProtocolError("Sandbox diagnostic frame is not a trace")
        if trace.request_id != UUID(self._protocol_diagnostics.request_id or str(trace.request_id)):
            self._protocol_diagnostics = replace(
                self._protocol_diagnostics, classification="TRACE_IDENTITY_MISMATCH"
            )
            return sequence
        if trace.integration_id != self._integration_id or (
            trace.lifecycle_run_id is not None and trace.lifecycle_run_id != self._lifecycle_run_id
        ):
            self._protocol_diagnostics = replace(
                self._protocol_diagnostics, classification="TRACE_IDENTITY_MISMATCH"
            )
            return sequence
        payload = trace.payload
        observed_sequence = payload.get("sequence")
        stage = payload.get("stage")
        if type(observed_sequence) is not int or not 0 <= observed_sequence <= 1_000_000:
            self._protocol_diagnostics = replace(
                self._protocol_diagnostics, classification="TRACE_SEQUENCE_INVALID"
            )
            return sequence
        if observed_sequence <= sequence:
            self._protocol_diagnostics = replace(
                self._protocol_diagnostics, classification="TRACE_SEQUENCE_INVALID"
            )
            return sequence
        if type(stage) is not str or not 1 <= len(stage) <= 128:
            self._protocol_diagnostics = replace(
                self._protocol_diagnostics, classification="TRACE_STAGE_INVALID"
            )
            return sequence
        safe_payload = self._safe_trace(payload)
        if (
            len(json.dumps(safe_payload, separators=(",", ":"), ensure_ascii=True))
            > MAX_TRACE_METADATA_BYTES
        ):
            self._protocol_diagnostics = replace(
                self._protocol_diagnostics, classification="TRACE_METADATA_BOUNDED"
            )
            safe_payload = {
                "sequence": observed_sequence,
                "stage": stage,
                "metadata": "[TRUNCATED]",
            }
        if len(self._child_events) < MAX_TRACE_FRAMES:
            self._child_events.append(safe_payload if isinstance(safe_payload, Mapping) else {})
            if self._flight_recorder is not None:
                self._flight_recorder.record(
                    component="sandbox_child",
                    stage=stage,
                    operation="in_band_trace",
                    resource_identity={
                        "request_id": str(trace.request_id),
                        "integration_id": trace.integration_id,
                        "lifecycle_run_id": trace.lifecycle_run_id or self._lifecycle_run_id,
                    },
                    state_after=safe_payload if isinstance(safe_payload, Mapping) else {},
                )
        else:
            self._protocol_diagnostics = replace(
                self._protocol_diagnostics, classification="TRACE_OVERFLOW"
            )
        return observed_sequence

    def _startup_diagnostics(self) -> SandboxStartupDiagnostics:
        """Build bounded launch evidence without retaining command arguments."""

        return SandboxStartupDiagnostics(
            containment_mode=(
                self._security_status.mode
                if self._security_status is not None
                else self._limits.windows_containment
            ),
            executable=os.fspath(self._executable),
            bootstrap=(
                "windows-native-launcher"
                if sys.platform == "win32"
                and self._limits.windows_containment
                in {
                    WindowsContainmentMode.APPCONTAINER,
                    WindowsContainmentMode.RESTRICTED_TOKEN,
                }
                else "bounded-subprocess"
            ),
            pipes_established=self._pipes_established,
            job_assigned=self._job_assigned,
            readiness_reached=self._protocol_ready,
            process_id=(getattr(self._process, "pid", None) if self._process is not None else None),
            exit_code=(
                getattr(self._process, "returncode", None) if self._process is not None else None
            ),
            stderr_tail=_redact_diagnostic(bytes(self._stderr_buffer).decode("utf-8", "replace")),
        )

    async def start(self) -> None:
        async with self._lock:
            await self._start_locked()

    async def _start_locked(self) -> None:
        if self._closed:
            raise SandboxProcessError("Sandbox is closed")
        pending_receipts = _pending_native_cleanup_receipts(self._parent_directory)
        if pending_receipts:
            raise SandboxCleanupOutcomeUnknown(
                "Native security cleanup recovery is pending; sandbox reuse is denied"
            )
        if self._cleanup_quarantined:
            raise SandboxCleanupOutcomeUnknown(
                "Native security cleanup outcome is unknown; sandbox reuse is denied"
            )
        if self.is_running:
            raise SandboxProcessError("Sandbox is already running")
        if self._process is not None:
            self._release_resource(ReservationReleaseReason.CRASH)
            await self._stop_locked()
        if self._paths is not None:
            self._cleanup_paths_locked()
        self._launch_monotonic_ns = time.monotonic_ns()
        self._phase("PROCESS_CREATE_REQUESTED")
        self._security_status = None
        self._protocol_ready = False
        self._pipes_established = False
        self._job_assigned = False
        if self._resource_governor is not None:
            decision = self._resource_governor.reserve(
                f"sandbox.{self._integration_id}",
                self._resource_priority,
                ResourceBudget(
                    ram_bytes=self._limits.max_memory_bytes,
                    concurrency=self._limits.max_processes,
                    duration_seconds=self._limits.timeout_seconds,
                ),
            )
            if not decision.allowed or decision.reservation_id is None:
                raise SandboxProcessError(f"Sandbox resource admission denied: {decision.reason}")
            self._resource_reservation_id = decision.reservation_id
        paths = SandboxPaths.create(self._parent_directory, self._integration_id)
        job: _WindowsJob | None = None
        process: Any | None = None
        try:
            if sys.platform == "win32":
                job = _WindowsJob.create(self._limits)
                if self._limits.windows_containment is WindowsContainmentMode.APPCONTAINER:
                    if job is None:  # pragma: no cover - defensive invariant
                        raise SandboxIsolationUnavailable("Sandbox Job Object was not created")
                    runtime_root = self._limits.appcontainer_runtime_root
                    if runtime_root is None:
                        raise SandboxIsolationUnavailable(
                            "AppContainer runtime root is required for executable isolation"
                        )
                    runtime_root = _owned_directory(runtime_root, create=False)
                    dependency_roots = tuple(
                        _owned_directory(root, create=False)
                        for root in self._limits.appcontainer_dependency_roots
                    )
                    try:
                        self._executable.relative_to(runtime_root)
                    except ValueError as error:
                        raise SandboxIsolationUnavailable(
                            "Sandbox executable is outside the AppContainer runtime root"
                        ) from error
                    profile_name = (
                        "JARVIS-"
                        + sha256(f"{self._integration_id}:{uuid4().hex}".encode()).hexdigest()[:32]
                    )
                    process, self._security_status = await WindowsAppContainerLauncher.launch(
                        os.fspath(self._executable),
                        self._arguments,
                        cwd=os.fspath(paths.work),
                        environment=_sandbox_environment(),
                        limit=self._limits.max_message_bytes + 1,
                        job=job,
                        profile_name=profile_name,
                        runtime_root=os.fspath(runtime_root),
                        allowed_roots=(*(os.fspath(root) for root in dependency_roots),),
                        writable_roots=(os.fspath(paths.root),),
                    )
                    set_owner = getattr(process, "set_cleanup_owner", None)
                    if callable(set_owner):
                        set_owner(PROCESS_INSTANCE_ID)
                    self._pipes_established = True
                    self._job_assigned = True
                elif self._limits.windows_containment is WindowsContainmentMode.RESTRICTED_TOKEN:
                    if job is None:  # pragma: no cover - defensive invariant
                        raise SandboxIsolationUnavailable("Sandbox Job Object was not created")
                    process, self._security_status = await WindowsRestrictedLauncher.launch(
                        os.fspath(self._executable),
                        self._arguments,
                        cwd=os.fspath(paths.work),
                        environment=_sandbox_environment(),
                        limit=self._limits.max_message_bytes + 1,
                        job=job,
                    )
                    self._pipes_established = True
                    self._job_assigned = True
                else:
                    flags = 0x00000200 | 0x08000000 | 0x00000400
                    process = await asyncio.create_subprocess_exec(
                        os.fspath(self._executable),
                        *self._arguments,
                        stdin=asyncio.subprocess.PIPE,
                        stdout=asyncio.subprocess.PIPE,
                        stderr=(
                            asyncio.subprocess.PIPE
                            if self._diagnostics_enabled
                            else asyncio.subprocess.DEVNULL
                        ),
                        cwd=os.fspath(paths.work),
                        env=_sandbox_environment(),
                        creationflags=flags,
                        start_new_session=False,
                        limit=self._limits.max_message_bytes + 1,
                    )
                    self._pipes_established = True
                    self._security_status = SandboxSecurityStatus(
                        mode=WindowsContainmentMode.JOB_OBJECT_ONLY,
                        token_restricted=False,
                        disabled_privileges=False,
                        explicit_handle_list=False,
                        inherited_handle_count=0,
                        job_object=True,
                        filesystem_acl_restricted=False,
                        network_restricted=False,
                        detail="explicit degraded mode; lifecycle containment only",
                    )
            else:
                process = await asyncio.create_subprocess_exec(
                    os.fspath(self._executable),
                    *self._arguments,
                    stdin=asyncio.subprocess.PIPE,
                    stdout=asyncio.subprocess.PIPE,
                    stderr=(
                        asyncio.subprocess.PIPE
                        if self._diagnostics_enabled
                        else asyncio.subprocess.DEVNULL
                    ),
                    cwd=os.fspath(paths.work),
                    env=_sandbox_environment(),
                    start_new_session=True,
                    limit=self._limits.max_message_bytes + 1,
                )
                self._pipes_established = True
                self._security_status = SandboxSecurityStatus(
                    mode=WindowsContainmentMode.PROCESS_GROUP_ONLY,
                    token_restricted=False,
                    disabled_privileges=False,
                    explicit_handle_list=False,
                    inherited_handle_count=0,
                    job_object=False,
                    filesystem_acl_restricted=False,
                    network_restricted=False,
                    detail="POSIX process-group lifecycle containment only",
                )
            if self._security_status is not None:
                self._security_status = replace(
                    self._security_status,
                    max_processes=self._limits.max_processes,
                    max_memory_bytes=self._limits.max_memory_bytes,
                )
            self._process = process
            self._paths = paths
            stderr = getattr(process, "stderr", None)
            if stderr is not None:
                self._stderr_task = asyncio.create_task(self._capture_stderr(stderr))
            if job is not None and self._limits.windows_containment not in {
                WindowsContainmentMode.RESTRICTED_TOKEN,
                WindowsContainmentMode.APPCONTAINER,
            }:
                job.assign(process.pid)
                self._job_assigned = True
                self._job = job
                job = None
            elif job is not None:
                self._job = job
                job = None
            self._phase("PROCESS_CREATED")
            self._parent_observation("PROCESS_CREATED")
            self._phase("PROCESS_CONFIRMED_ALIVE")
            self._parent_observation("PROCESS_CONFIRMED_ALIVE")
        except Exception as error:
            self._release_resource(ReservationReleaseReason.CRASH)
            self._process = self._process or process
            self._paths = paths
            await self._stop_locked()
            if job is not None:
                job.close()
            with contextlib.suppress(Exception):
                paths.cleanup()
            if self._paths is paths:
                self._paths = None
            if isinstance(error, SandboxIsolationUnavailable):
                raise
            if isinstance(error, WindowsNativeProcessError):
                raise SandboxIsolationUnavailable(
                    "Mandatory Windows sandbox containment is unavailable"
                ) from error
            raise SandboxProcessError("Sandbox process could not start") from error

    async def request(
        self,
        kind: str,
        payload: Mapping[str, object],
        *,
        cancellation: asyncio.Event | None = None,
    ) -> dict[str, object]:
        async with self._lock:
            if not self.is_running or self._process is None:
                raise SandboxProcessError("Sandbox process is not running")
            if cancellation is not None and cancellation.is_set():
                raise SandboxCancelled("Sandbox request was cancelled before send")
            self._phase("HEALTH_REQUEST_SERIALIZED")
            started = time.monotonic_ns()
            message = SandboxMessage(
                uuid4(),
                self._integration_id,
                kind,
                payload,
                lifecycle_run_id=self._lifecycle_run_id,
                diagnostics=self._diagnostics_enabled,
                diagnostic_mode=self._diagnostic_mode,
            )
            encoded = message.encode(max_bytes=self._limits.max_message_bytes)
            self._protocol_diagnostics = replace(
                self._protocol_diagnostics,
                request_id=str(message.request_id),
                timing_ms={"process_to_request": 0.0},
            )
            try:
                assert self._process.stdin is not None
                self._phase("HEALTH_REQUEST_WRITE_BEGIN")
                self._process.stdin.write(encoded)
                self._phase("HEALTH_REQUEST_WRITE_COMPLETE")
                await self._process.stdin.drain()
                self._phase("HEALTH_REQUEST_FLUSH_COMPLETE")
                self._phase("HEALTH_RESPONSE_WAIT_BEGIN")
                response = await self._read_response(message, cancellation)
                return dict(response.payload)
            except SandboxError as error:
                if isinstance(error, SandboxTimeout):
                    self._parent_phase("RESPONSE_TIMEOUT")
                elif self._protocol_diagnostics.phase == "HEALTH_RESPONSE_BYTES_OR_LINE_RECEIVED":
                    self._parent_phase("RESPONSE_EOF")
                classification = self._protocol_diagnostics.classification
                self._protocol_diagnostics = replace(
                    self._protocol_diagnostics,
                    classification=classification
                    or (
                        "RESPONSE_TIMEOUT"
                        if isinstance(error, SandboxTimeout)
                        else "STDOUT_EOF"
                        if isinstance(error, SandboxStartupError)
                        else "MALFORMED_RESPONSE"
                        if isinstance(error, SandboxProtocolError)
                        else "REQUEST_CANCELLED"
                    ),
                    timing_ms={
                        "request_to_failure": round((time.monotonic_ns() - started) / 1_000_000, 3)
                    },
                )
                self._phase(self._protocol_diagnostics.phase)
                reason = (
                    ReservationReleaseReason.TIMEOUT
                    if isinstance(error, SandboxTimeout)
                    else ReservationReleaseReason.CANCEL
                    if isinstance(error, SandboxCancelled)
                    else ReservationReleaseReason.CRASH
                )
                self._release_resource(reason)
                await self._stop_locked()
                raise
            except (BrokenPipeError, ConnectionError, OSError) as error:
                self._protocol_diagnostics = replace(
                    self._protocol_diagnostics, classification="REQUEST_WRITE_FAILED"
                )
                self._phase("HEALTH_REQUEST_WRITE_FAILED")
                self._release_resource(ReservationReleaseReason.CRASH)
                await self._stop_locked()
                raise SandboxProcessError("Sandbox IPC write failed") from error

    async def _read_response(
        self,
        request: SandboxMessage,
        cancellation: asyncio.Event | None,
    ) -> SandboxMessage:
        if self._process is None or self._process.stdout is None:
            raise SandboxProcessError("Sandbox IPC is unavailable")
        cancel_task = asyncio.create_task(cancellation.wait()) if cancellation is not None else None
        deadline = time.monotonic() + self._limits.timeout_seconds
        trace_sequence = 0
        trace_bytes = 0
        try:
            while True:
                read_task = asyncio.create_task(self._process.stdout.readuntil(b"\n"))
                tasks: set[asyncio.Task[object]] = {read_task}
                if cancel_task is not None:
                    tasks.add(cancel_task)
                timeout = max(0.0, deadline - time.monotonic())
                done, pending = await asyncio.wait(
                    tasks, timeout=timeout, return_when=asyncio.FIRST_COMPLETED
                )
                for task in pending:
                    task.cancel()
                if not done:
                    self._protocol_diagnostics = replace(
                        self._protocol_diagnostics, classification="RESPONSE_TIMEOUT"
                    )
                    raise SandboxTimeout("Sandbox request timed out")
                if cancel_task is not None and cancel_task in done and cancel_task.result():
                    raise SandboxCancelled("Sandbox request was cancelled")
                try:
                    raw = read_task.result()
                except asyncio.IncompleteReadError as error:
                    if not error.partial:
                        with contextlib.suppress(TimeoutError):
                            await asyncio.wait_for(self._process.wait(), timeout=0.1)
                        if self._process.returncode is not None:
                            diagnostics = self._startup_diagnostics()
                            error_type: type[SandboxProcessError] = (
                                SandboxStartupError
                                if not diagnostics.readiness_reached
                                else SandboxProcessError
                            )
                            raise error_type(
                                "Sandbox process exited before responding", diagnostics=diagnostics
                            ) from error
                    self._protocol_diagnostics = replace(
                        self._protocol_diagnostics, classification="STDOUT_EOF"
                    )
                    raise SandboxProtocolError("Sandbox response frame is malformed") from error
                except (asyncio.LimitOverrunError, ValueError) as error:
                    self._protocol_diagnostics = replace(
                        self._protocol_diagnostics, classification="MALFORMED_RESPONSE"
                    )
                    raise SandboxProtocolError("Sandbox response frame is malformed") from error
                self._protocol_diagnostics = replace(
                    self._protocol_diagnostics, response_length=len(raw)
                )
                self._phase("HEALTH_RESPONSE_BYTES_OR_LINE_RECEIVED")
                try:
                    response = SandboxMessage.decode(raw, max_bytes=self._limits.max_message_bytes)
                except SandboxProtocolError:
                    with contextlib.suppress(UnicodeDecodeError, json.JSONDecodeError):
                        observed = json.loads(raw[:-1].decode("utf-8"))
                        if (
                            isinstance(observed, dict)
                            and observed.get("version") != SANDBOX_PROTOCOL_VERSION
                        ):
                            self._protocol_diagnostics = replace(
                                self._protocol_diagnostics,
                                classification="PROTOCOL_VERSION_MISMATCH",
                                predicates={
                                    "protocol_version": {
                                        "expected": SANDBOX_PROTOCOL_VERSION,
                                        "observed": observed.get("version"),
                                    }
                                },
                            )
                    raise
                self._phase("HEALTH_RESPONSE_PARSED")
                if response.kind == "trace":
                    trace_bytes += len(raw)
                    if trace_bytes > MAX_TRACE_BYTES:
                        self._protocol_diagnostics = replace(
                            self._protocol_diagnostics, classification="TRACE_OVERFLOW"
                        )
                        raise SandboxProtocolError("Sandbox diagnostic frames exceed their bound")
                    trace_sequence = self._accept_trace(response, sequence=trace_sequence)
                    continue
                self._protocol_diagnostics = replace(
                    self._protocol_diagnostics, response_received=True
                )
                break
            if not response.response:
                self._protocol_diagnostics = replace(
                    self._protocol_diagnostics, classification="UNEXPECTED_FRAME"
                )
                raise SandboxProtocolError("Sandbox response identity does not match request")
            self._phase("PROTOCOL_VALIDATED")
            if response.request_id != request.request_id:
                self._protocol_diagnostics = replace(
                    self._protocol_diagnostics,
                    classification="REQUEST_ID_MISMATCH",
                    predicates={
                        "request_id": {
                            "expected": str(request.request_id),
                            "observed": str(response.request_id),
                        }
                    },
                )
                raise SandboxProtocolError("Sandbox response request ID does not match request")
            self._phase("REQUEST_ID_VALIDATED")
            if response.integration_id != self._integration_id:
                self._protocol_diagnostics = replace(
                    self._protocol_diagnostics, classification="INTEGRATION_ID_MISMATCH"
                )
                raise SandboxProtocolError("Sandbox response integration does not match request")
            self._phase("INTEGRATION_ID_VALIDATED")
            if response.version != SANDBOX_PROTOCOL_VERSION:
                self._protocol_diagnostics = replace(
                    self._protocol_diagnostics, classification="PROTOCOL_VERSION_MISMATCH"
                )
                raise SandboxProtocolError("Sandbox response protocol version does not match")
            self._phase("HEALTH_STATUS_VALIDATED")
            self._protocol_ready = True
            self._phase("HEALTH_COMPLETE")
            return response
        finally:
            if cancel_task is not None and not cancel_task.done():
                cancel_task.cancel()

    async def restart(self) -> None:
        async with self._lock:
            if self._restart_count >= self._limits.max_restarts:
                raise SandboxProcessError("Sandbox restart limit was exhausted")
            self._release_resource(ReservationReleaseReason.CRASH)
            try:
                await self._stop_locked()
            finally:
                self._cleanup_paths_locked()
            self._restart_count += 1
            await self._start_locked()

    async def stop(self) -> None:
        async with self._lock:
            self._release_resource(ReservationReleaseReason.CANCEL)
            await self._stop_locked()

    async def close(self) -> None:
        async with self._lock:
            if self._closed:
                return
            self._closed = True
            self._release_resource(ReservationReleaseReason.CANCEL)
            try:
                await self._stop_locked()
            finally:
                self._cleanup_paths_locked()

    async def _stop_locked(self) -> None:
        self._parent_phase("CLEANUP_BEGIN")
        process = self._process
        job = self._job
        native_cleanup_error: Exception | None = None
        native_cleanup_cause: Exception | None = None
        job_cleanup_error: Exception | None = None
        self._parent_observation("CLEANUP_BEGIN", process=process, job=job)
        self._process = None
        self._job = None
        stderr_task, self._stderr_task = self._stderr_task, None
        if stderr_task is not None and not stderr_task.done():
            stderr_task.cancel()
        if stderr_task is not None:
            with contextlib.suppress(asyncio.CancelledError):
                await stderr_task
        if process is not None:
            close_streams = getattr(process, "close_streams", None)
            if callable(close_streams):
                with contextlib.suppress(Exception):
                    close_streams()
            else:
                with contextlib.suppress(Exception):
                    if process.stdin is not None:
                        process.stdin.close()
            if process.returncode is None:
                if job is not None:
                    job.terminate()
                elif sys.platform == "win32":
                    process.terminate()
                else:
                    with contextlib.suppress(ProcessLookupError):
                        os.killpg(process.pid, signal.SIGTERM)
                try:
                    await asyncio.wait_for(process.wait(), timeout=2)
                except TimeoutError:
                    if job is not None:
                        job.terminate()
                    elif sys.platform == "win32":
                        process.kill()
                    else:
                        with contextlib.suppress(ProcessLookupError):
                            os.killpg(process.pid, signal.SIGKILL)
                with contextlib.suppress(Exception):
                    await asyncio.wait_for(process.wait(), timeout=2)
            if self._parent_recorder is not None:
                self._parent_observation(
                    "PROCESS_TERMINAL",
                    process=process,
                    job=job,
                    state={"terminal": getattr(process, "returncode", None) is not None},
                )
            if job is not None:
                try:
                    empty = await job.wait_for_empty(2)
                    self._parent_observation(
                        "JOB_EMPTY_WAIT", process=process, job=job, state={"empty": empty}
                    )
                except Exception as error:
                    self._parent_observation(
                        "JOB_EMPTY_WAIT_UNKNOWN",
                        process=process,
                        job=job,
                        state={"empty": "UNKNOWN", "error": type(error).__name__},
                    )
            for stream in (process.stdin, process.stdout):
                transport = getattr(stream, "_transport", None)
                if transport is not None:
                    transport.close()
            close_native = getattr(process, "close", None)
            if callable(close_native):
                native_state = getattr(process, "cleanup_state", None)
                if isinstance(native_state, NativeCleanupState):
                    self._record_native_cleanup_receipt(native_state, process)
                    set_observer = getattr(process, "set_cleanup_observer", None)
                    if callable(set_observer):
                        set_observer(
                            lambda state, evidence: self._record_native_cleanup_receipt(
                                state, process, evidence
                            )
                        )
                try:
                    cleanup_limits = getattr(self, "_limits", SandboxLimits())
                    close_native(
                        cleanup_deadline_seconds=cleanup_limits.native_cleanup_foreground_deadline_seconds
                    )
                except TypeError:
                    # Compatibility-only launch adapters used by unit tests do
                    # not expose the native deadline parameter.
                    close_native()
                except Exception as error:
                    native_cleanup_cause = error
                    native_cleanup_error = SandboxCleanupError(
                        "Native sandbox security cleanup failed"
                    )
                cleanup_error = getattr(process, "cleanup_error", None)
                cleanup_state = getattr(process, "cleanup_state", None)
                if native_cleanup_error is not None:
                    self._cleanup_quarantined = True
                elif cleanup_state is NativeCleanupState.OUTCOME_UNKNOWN:
                    self._cleanup_quarantined = True
                    self._record_native_cleanup_receipt(cleanup_state, process)
                    native_cleanup_error = SandboxCleanupOutcomeUnknown(
                        "Native sandbox security cleanup outcome is unknown"
                    )
                    self._parent_observation(
                        "SECURITY_CLEANUP_OUTCOME_UNKNOWN", process=process, job=job
                    )
                elif isinstance(cleanup_error, Exception):
                    native_cleanup_cause = cleanup_error
                    native_cleanup_error = SandboxCleanupError(
                        "Native sandbox security cleanup failed"
                    )
                    self._cleanup_quarantined = True
                    if isinstance(cleanup_state, NativeCleanupState):
                        self._record_native_cleanup_receipt(cleanup_state, process)
                    self._parent_observation("SECURITY_CLEANUP_FAILED", process=process, job=job)
                else:
                    if cleanup_state is NativeCleanupState.CONFIRMED:
                        self._record_native_cleanup_receipt(cleanup_state, process)
                    self._parent_observation("SECURITY_CLEANUP_COMPLETE", process=process, job=job)
        if job is not None:
            try:
                job.close()
            except Exception as error:
                job_cleanup_error = error
            finally:
                self._parent_observation("JOB_CLOSED", process=process, job=job)
        self._parent_phase("PROCESS_EXIT_OBSERVED")
        self._parent_phase("CLEANUP_COMPLETE")
        if native_cleanup_error is not None:
            raise native_cleanup_error from native_cleanup_cause
        if job_cleanup_error is not None:
            raise job_cleanup_error

    def _cleanup_paths_locked(self) -> None:
        if getattr(self, "_cleanup_quarantined", False):
            return
        paths, self._paths = self._paths, None
        if paths is not None:
            paths.cleanup()

    def _record_native_cleanup_receipt(
        self,
        state: NativeCleanupState,
        process: object,
        evidence: Mapping[str, object] | None = None,
    ) -> None:
        """Persist cleanup intent/outcome before allowing later lifecycle work.

        The receipt carries only bounded trusted native state.  Generated
        content cannot create, alter, or consume it.  A non-terminal receipt
        blocks later sandbox allocation until reconciliation has independently
        observed and, if necessary, restored the native state.
        """

        paths = getattr(self, "_paths", None)
        if paths is None:
            return
        process_evidence = evidence
        if process_evidence is None:
            candidate = getattr(process, "cleanup_evidence", {})
            process_evidence = candidate if isinstance(candidate, Mapping) else {}
        cleanup_evidence = {
            key: value
            for key, value in process_evidence.items()
            if key
            in {
                "profile",
                "profile_sid",
                "profile_created",
                "profile_deleted",
                "acl_lease_count",
                "acl_resources",
                "acl_restored",
                "leases_released",
                "cleanup_terminal",
                "cleanup_deadline_exceeded",
                "cleanup_completed_monotonic_ns",
                "cleanup_operation_id",
                "owner_instance_id",
                "owner_pid",
            }
        }
        operation_id = getattr(process, "cleanup_operation_id", None)
        if not isinstance(operation_id, str) or not operation_id:
            operation_id = cleanup_evidence.get("cleanup_operation_id")
        if not isinstance(operation_id, str) or not operation_id:
            operation_id = uuid4().hex
        owner_instance_id = cleanup_evidence.get("owner_instance_id", PROCESS_INSTANCE_ID)
        if not isinstance(owner_instance_id, str) or not owner_instance_id:
            owner_instance_id = PROCESS_INSTANCE_ID
        owner_pid = cleanup_evidence.get("owner_pid", getattr(process, "pid", os.getpid()))
        if type(owner_pid) is not int or owner_pid <= 0:
            owner_pid = getattr(process, "pid", os.getpid())
        profile_name = cleanup_evidence.get("profile")
        profile_sid = cleanup_evidence.get("profile_sid")
        acl_resources = cleanup_evidence.get("acl_resources", ())
        if not isinstance(acl_resources, list):
            acl_resources = []
        if state in {
            NativeCleanupState.REQUESTED,
            NativeCleanupState.RUNNING,
            NativeCleanupState.OUTCOME_UNKNOWN,
        }:
            mark_live_cleanup_owner(operation_id)
        else:
            clear_live_cleanup_owner(operation_id)
        record = {
            "schema": _NATIVE_CLEANUP_RECEIPT_SCHEMA,
            "operation_id": operation_id,
            "state": state.value,
            "updated_monotonic_ns": time.monotonic_ns(),
            "owner": {
                "instance_id": owner_instance_id,
                "pid": owner_pid,
            },
            "resource_binding": {
                "class": "JARVIS_NATIVE_SANDBOX",
                "integration_id": self._integration_id,
                "sandbox_parent": str(paths.root.parent),
                "sandbox_root": str(paths.root),
                "profile": {
                    "name": profile_name if isinstance(profile_name, str) else "",
                    "sid": profile_sid if isinstance(profile_sid, str) else "",
                },
                "acl": acl_resources,
                "filesystem": {"owned_root": str(paths.root)},
            },
            "evidence": cleanup_evidence,
        }
        self._cleanup_observations.append(
            {
                "operation_id": operation_id,
                "state": state.value,
                "evidence": dict(cleanup_evidence),
            }
        )
        del self._cleanup_observations[:-32]
        signer = self._recovery_integrity_signer
        if callable(signer):
            record["integrity"] = signer(record)
        else:
            # Unsigned direct compatibility callers remain fail-closed for
            # post-restart reconciliation; production composition supplies the
            # existing TrustedRecoveryAuthority signer.
            record["integrity"] = None
        _write_native_cleanup_receipt(paths.cleanup_receipt, record)

    def _release_resource(self, reason: ReservationReleaseReason) -> None:
        reservation_id, self._resource_reservation_id = (
            self._resource_reservation_id,
            None,
        )
        if reservation_id is not None and self._resource_governor is not None:
            self._resource_governor.release(reservation_id, reason)


__all__ = [
    "DEFAULT_MAX_MESSAGE_BYTES",
    "SANDBOX_PROTOCOL_VERSION",
    "SandboxCancelled",
    "SandboxCleanupError",
    "SandboxCleanupOutcomeUnknown",
    "create_owned_windows_job",
    "SandboxConfigurationError",
    "SandboxError",
    "SandboxIsolationUnavailable",
    "SandboxLimits",
    "SandboxMessage",
    "SandboxProtocolDiagnostics",
    "SandboxPaths",
    "SandboxProcess",
    "SandboxProcessError",
    "SandboxStartupDiagnostics",
    "SandboxStartupError",
    "SandboxProtocolError",
    "SandboxSecurityStatus",
    "SandboxTimeout",
    "WindowsContainmentMode",
]
