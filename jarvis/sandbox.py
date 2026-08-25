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
import shutil
import signal
import sys
import time
from collections.abc import Mapping
from dataclasses import dataclass, replace
from hashlib import sha256
from pathlib import Path
from typing import Any
from uuid import UUID, uuid4

from jarvis.computer.process import ProcessIdentityError, resolve_trusted_executable
from jarvis.resources import (
    ReservationReleaseReason,
    ResourceBudget,
    ResourceGovernor,
    ResourcePriority,
)
from jarvis.windows_sandbox import (
    SandboxSecurityStatus,
    WindowsAppContainerLauncher,
    WindowsContainmentMode,
    WindowsNativeProcessError,
    WindowsRestrictedLauncher,
)

SANDBOX_PROTOCOL_VERSION = 1
DEFAULT_MAX_MESSAGE_BYTES = 65_536
_IDENTIFIER_CHARS = frozenset("abcdefghijklmnopqrstuvwxyz0123456789._-")


class SandboxError(RuntimeError):
    """Base class for isolated-process failures."""


class SandboxConfigurationError(SandboxError, ValueError):
    """A trusted composition supplied unsafe or unsupported sandbox settings."""


class SandboxProtocolError(SandboxError):
    """The child sent malformed, forged, or oversized IPC data."""


class SandboxProcessError(SandboxError):
    """The child could not start, crashed, or stopped unexpectedly."""


class SandboxTimeout(SandboxProcessError):
    """A request exceeded its bounded execution time."""


class SandboxCancelled(SandboxProcessError):
    """A trusted caller cancelled an in-flight sandbox request."""


class SandboxIsolationUnavailable(SandboxError):
    """The requested native process containment could not be established."""


class SandboxCleanupError(SandboxError):
    """Owned sandbox data could not be removed safely."""


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
        if type(value) is not dict or set(value) != {
            "version",
            "request_id",
            "integration_id",
            "kind",
            "response",
            "payload",
        }:
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
        )


@dataclass(frozen=True, slots=True)
class SandboxLimits:
    """Bounds enforced by the manager; Windows applies the native limits."""

    timeout_seconds: float = 30.0
    max_message_bytes: int = DEFAULT_MAX_MESSAGE_BYTES
    max_processes: int = 1
    max_memory_bytes: int = 256 * 1024 * 1024
    max_restarts: int = 3
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
        for _ in range(16):
            root = parent / f"jarvis-sandbox-{integration_id}-{uuid4().hex}"
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


def _sandbox_environment() -> dict[str, str]:
    """Return only host values required to start a bounded child process."""

    allowed = ("SYSTEMROOT", "WINDIR", "SYSTEMDRIVE", "TEMP", "TMP")
    result = {key: os.environ[key] for key in allowed if key in os.environ}
    result.update({"PYTHONIOENCODING": "utf-8", "PYTHONUTF8": "1", "JARVIS_SANDBOX": "1"})
    return result


class _WindowsJob:  # pragma: no cover - opt-in native Windows integration
    """Small native Job Object wrapper for process-tree and resource ownership."""

    _JOB_OBJECT_EXTENDED_LIMIT_INFORMATION = 9
    _JOB_OBJECT_LIMIT_ACTIVE_PROCESS = 0x00000008
    _JOB_OBJECT_LIMIT_PROCESS_MEMORY = 0x00000100
    _JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE = 0x00002000
    _PROCESS_SET_QUOTA = 0x0100
    _PROCESS_TERMINATE = 0x0001
    _PROCESS_QUERY_LIMITED_INFORMATION = 0x1000

    def __init__(self, handle: int, library: Any) -> None:
        self._handle = handle
        self._library = library
        self._root_process_id: int | None = None

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
            library.OpenProcess.argtypes = [wintypes.DWORD, wintypes.BOOL, wintypes.DWORD]
            library.OpenProcess.restype = ctypes.c_void_p
            library.AssignProcessToJobObject.argtypes = [ctypes.c_void_p, ctypes.c_void_p]
            library.AssignProcessToJobObject.restype = wintypes.BOOL
            library.TerminateJobObject.argtypes = [ctypes.c_void_p, wintypes.UINT]
            library.TerminateJobObject.restype = wintypes.BOOL
            library.WaitForSingleObject.argtypes = [ctypes.c_void_p, wintypes.DWORD]
            library.WaitForSingleObject.restype = wintypes.DWORD
            library.CloseHandle.argtypes = [ctypes.c_void_p]
            library.CloseHandle.restype = wintypes.BOOL
            handle = library.CreateJobObjectW(None, None)
            if not handle:
                raise OSError(ctypes.get_last_error(), "CreateJobObjectW failed")
            job = cls(int(handle), library)
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

    def terminate(self) -> None:
        self._library.TerminateJobObject(self._handle, 1)
        self._terminate_unowned_descendants()

    def _terminate_unowned_descendants(self) -> None:
        """Best-effort cleanup for children that explicitly broke away.

        A normal child is covered by the Job Object.  This narrow cleanup is
        not an authority boundary: it exists only to avoid leaving a locally
        owned process behind if a child used a supported Windows breakaway
        path.  The descendant set is re-read a few times to bound PID-race
        exposure and cleanup latency.
        """

        root = getattr(self, "_root_process_id", None)
        if root is None:
            return
        # A child can be created just as the root is terminated.  Keep the
        # cleanup bounded, but allow enough time for that local process-tree
        # observation to become visible before removing the owned directory.
        for _ in range(20):
            descendants = self._descendant_processes(root)
            if not descendants:
                return
            for process_id in descendants:
                handle = self._library.OpenProcess(
                    self._PROCESS_TERMINATE | self._PROCESS_QUERY_LIMITED_INFORMATION,
                    False,
                    process_id,
                )
                if handle:
                    with contextlib.suppress(Exception):
                        self._library.TerminateProcess(handle, 1)
                    self._library.CloseHandle(handle)
            time.sleep(0.05)

    def _descendant_processes(self, root_process_id: int) -> set[int]:
        class ProcessEntry(ctypes.Structure):
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

        self._library.CreateToolhelp32Snapshot.argtypes = [wintypes.DWORD, wintypes.DWORD]
        self._library.CreateToolhelp32Snapshot.restype = ctypes.c_void_p
        self._library.Process32FirstW.argtypes = [
            ctypes.c_void_p,
            ctypes.POINTER(ProcessEntry),
        ]
        self._library.Process32FirstW.restype = wintypes.BOOL
        self._library.Process32NextW.argtypes = [
            ctypes.c_void_p,
            ctypes.POINTER(ProcessEntry),
        ]
        self._library.Process32NextW.restype = wintypes.BOOL
        snapshot = self._library.CreateToolhelp32Snapshot(0x00000002, 0)
        if not snapshot or int(snapshot) == -1:
            return set()
        try:
            entries: dict[int, int] = {}
            entry = ProcessEntry()
            entry.dwSize = ctypes.sizeof(ProcessEntry)
            if self._library.Process32FirstW(snapshot, ctypes.byref(entry)):
                while True:
                    entries[int(entry.th32ProcessID)] = int(entry.th32ParentProcessID)
                    if not self._library.Process32NextW(snapshot, ctypes.byref(entry)):
                        break
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
        finally:
            self._library.CloseHandle(snapshot)

    async def wait_for_empty(self, timeout_seconds: float) -> bool:
        """Wait until all descendants have left the Job Object."""

        milliseconds = max(1, min(30_000, int(timeout_seconds * 1_000)))
        result = await asyncio.to_thread(
            self._library.WaitForSingleObject,
            self._handle,
            milliseconds,
        )
        return bool(result == 0)

    def close(self) -> None:
        if self._handle:
            self._library.CloseHandle(self._handle)
            self._handle = 0


class SandboxProcess:
    """Own one generated integration process and its complete request lifecycle."""

    def __init__(
        self,
        executable: Path,
        arguments: tuple[str, ...],
        *,
        integration_id: str,
        parent_directory: Path,
        limits: SandboxLimits | None = None,
        resource_governor: ResourceGovernor | None = None,
        resource_priority: ResourcePriority = ResourcePriority.USER_REQUESTED,
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
        self._lock = asyncio.Lock()
        self._closed = False
        self._restart_count = 0

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

    async def start(self) -> None:
        async with self._lock:
            await self._start_locked()

    async def _start_locked(self) -> None:
        if self._closed:
            raise SandboxProcessError("Sandbox is closed")
        if self.is_running:
            raise SandboxProcessError("Sandbox is already running")
        if self._process is not None:
            self._release_resource(ReservationReleaseReason.CRASH)
            await self._stop_locked()
        if self._paths is not None:
            self._cleanup_paths_locked()
        self._security_status = None
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
                else:
                    flags = 0x00000200 | 0x08000000 | 0x00000400
                    process = await asyncio.create_subprocess_exec(
                        os.fspath(self._executable),
                        *self._arguments,
                        stdin=asyncio.subprocess.PIPE,
                        stdout=asyncio.subprocess.PIPE,
                        stderr=asyncio.subprocess.DEVNULL,
                        cwd=os.fspath(paths.work),
                        env=_sandbox_environment(),
                        creationflags=flags,
                        start_new_session=False,
                        limit=self._limits.max_message_bytes + 1,
                    )
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
                    stderr=asyncio.subprocess.DEVNULL,
                    cwd=os.fspath(paths.work),
                    env=_sandbox_environment(),
                    start_new_session=True,
                    limit=self._limits.max_message_bytes + 1,
                )
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
            if job is not None and self._limits.windows_containment not in {
                WindowsContainmentMode.RESTRICTED_TOKEN,
                WindowsContainmentMode.APPCONTAINER,
            }:
                job.assign(process.pid)
                self._job = job
                job = None
            elif job is not None:
                self._job = job
                job = None
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
            message = SandboxMessage(uuid4(), self._integration_id, kind, payload)
            encoded = message.encode(max_bytes=self._limits.max_message_bytes)
            try:
                assert self._process.stdin is not None
                self._process.stdin.write(encoded)
                await self._process.stdin.drain()
                response = await self._read_response(message, cancellation)
                return dict(response.payload)
            except SandboxError as error:
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
        read_task = asyncio.create_task(self._process.stdout.readuntil(b"\n"))
        cancel_task = asyncio.create_task(cancellation.wait()) if cancellation is not None else None
        tasks: set[asyncio.Task[object]] = {read_task}
        if cancel_task is not None:
            tasks.add(cancel_task)
        try:
            done, pending = await asyncio.wait(
                tasks,
                timeout=self._limits.timeout_seconds,
                return_when=asyncio.FIRST_COMPLETED,
            )
            for task in pending:
                task.cancel()
            if not done:
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
                        raise SandboxProcessError(
                            "Sandbox process exited before responding"
                        ) from error
                raise SandboxProtocolError("Sandbox response frame is malformed") from error
            except (asyncio.LimitOverrunError, ValueError) as error:
                raise SandboxProtocolError("Sandbox response frame is malformed") from error
            response = SandboxMessage.decode(raw, max_bytes=self._limits.max_message_bytes)
            if (
                not response.response
                or response.request_id != request.request_id
                or response.integration_id != self._integration_id
                or response.version != SANDBOX_PROTOCOL_VERSION
            ):
                raise SandboxProtocolError("Sandbox response identity does not match request")
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
        process, self._process = self._process, None
        job, self._job = self._job, None
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
            if job is not None:
                with contextlib.suppress(Exception):
                    await job.wait_for_empty(2)
            for stream in (process.stdin, process.stdout):
                transport = getattr(stream, "_transport", None)
                if transport is not None:
                    transport.close()
            close_native = getattr(process, "close", None)
            if callable(close_native):
                with contextlib.suppress(Exception):
                    close_native()
                cleanup_error = getattr(process, "cleanup_error", None)
                if cleanup_error is not None:
                    raise SandboxCleanupError(
                        "Native sandbox security cleanup failed"
                    ) from cleanup_error
        if job is not None:
            job.close()

    def _cleanup_paths_locked(self) -> None:
        paths, self._paths = self._paths, None
        if paths is not None:
            paths.cleanup()

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
    "SandboxConfigurationError",
    "SandboxError",
    "SandboxIsolationUnavailable",
    "SandboxLimits",
    "SandboxMessage",
    "SandboxPaths",
    "SandboxProcess",
    "SandboxProcessError",
    "SandboxProtocolError",
    "SandboxSecurityStatus",
    "SandboxTimeout",
    "WindowsContainmentMode",
]
