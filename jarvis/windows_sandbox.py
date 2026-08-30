"""Native Windows launch support for generated integration processes.

The production boundary is an AppContainer process with no declared network
or device capabilities, an explicit standard-handle list, and a caller-owned
Job Object.  Restricted-token launch remains available as an explicit
diagnostic/compatibility mode, but it is not an acceptable executable
integration boundary because it does not isolate same-user resources.

The module is imported on every platform, but native entry points fail closed
when called anywhere except Windows.
"""

from __future__ import annotations

import asyncio
import contextlib
import ctypes
import ctypes.wintypes as wintypes
import os
import subprocess
import sys
from dataclasses import dataclass
from enum import StrEnum
from typing import Any, Protocol


class WindowsContainmentMode(StrEnum):
    """The explicit containment contract requested for a child process."""

    APPCONTAINER = "appcontainer"
    RESTRICTED_TOKEN = "restricted_token"
    JOB_OBJECT_ONLY = "job_object_only"
    PROCESS_GROUP_ONLY = "process_group_only"


@dataclass(frozen=True, slots=True)
class SandboxSecurityStatus:
    """Observable security posture for one sandbox launch.

    False values are intentional: a launch must report only the native
    controls that were actually established.
    """

    mode: WindowsContainmentMode
    token_restricted: bool
    disabled_privileges: bool
    explicit_handle_list: bool
    inherited_handle_count: int
    job_object: bool
    filesystem_acl_restricted: bool
    network_restricted: bool
    detail: str
    max_processes: int | None = None
    max_memory_bytes: int | None = None
    appcontainer_profile: str | None = None
    runtime_root: str | None = None

    @property
    def executable_isolation(self) -> bool:
        """Whether this status satisfies the generated-code v1 boundary."""

        return (
            self.mode is WindowsContainmentMode.APPCONTAINER
            and self.token_restricted is True
            and self.disabled_privileges is True
            and self.explicit_handle_list is True
            and type(self.inherited_handle_count) is int
            and self.inherited_handle_count == 3
            and self.job_object is True
            and self.filesystem_acl_restricted is True
            and self.network_restricted is True
            and bool(self.appcontainer_profile)
            and bool(self.runtime_root)
        )


class WindowsNativeProcessError(RuntimeError):
    """A native restricted-token process could not be created safely."""


class _JobAssignment(Protocol):
    def assign_handle(self, process_handle: int, process_id: int | None = None) -> None:
        """Assign a suspended process handle to the Job Object."""


if sys.platform == "win32":  # pragma: no cover - exercised by Windows CI/manual tests
    _HANDLE = ctypes.c_void_p
    _LPSECURITY_ATTRIBUTES = ctypes.c_void_p
    _CREATE_SUSPENDED = 0x00000004
    _CREATE_NEW_PROCESS_GROUP = 0x00000200
    _CREATE_NO_WINDOW = 0x08000000
    _CREATE_UNICODE_ENVIRONMENT = 0x00000400
    _EXTENDED_STARTUPINFO_PRESENT = 0x00080000
    _PROC_THREAD_ATTRIBUTE_HANDLE_LIST = 0x00020002
    _PROC_THREAD_ATTRIBUTE_SECURITY_CAPABILITIES = 0x00020009
    _HANDLE_FLAG_INHERIT = 0x00000001
    _STARTF_USESTDHANDLES = 0x00000100
    _INFINITE = 0xFFFFFFFF
    _STILL_ACTIVE = 259
    _ERROR_INSUFFICIENT_BUFFER = 122
    _ERROR_SUCCESS = 0
    _ERROR_ALREADY_EXISTS = 183
    _HRESULT_ALREADY_EXISTS = 0x800700B7
    _TOKEN_DUPLICATE = 0x0002
    _TOKEN_QUERY = 0x0008
    _TOKEN_ASSIGN_PRIMARY = 0x0001
    _TOKEN_ADJUST_DEFAULT = 0x0080
    _DISABLE_MAX_PRIVILEGE = 0x00000001
    _TOKEN_GROUP_ATTRIBUTES = 0

    class _SidAndAttributes(ctypes.Structure):
        _fields_ = [("Sid", ctypes.c_void_p), ("Attributes", wintypes.DWORD)]

    class _SecurityCapabilities(ctypes.Structure):
        _fields_ = [
            ("AppContainerSid", ctypes.c_void_p),
            ("Capabilities", ctypes.POINTER(_SidAndAttributes)),
            ("CapabilityCount", wintypes.DWORD),
            ("Reserved", wintypes.DWORD),
        ]

    class _LuidAndAttributes(ctypes.Structure):
        _fields_ = [("Luid", ctypes.c_ulonglong), ("Attributes", wintypes.DWORD)]

    class _ProcessInformation(ctypes.Structure):
        _fields_ = [
            ("hProcess", ctypes.c_void_p),
            ("hThread", ctypes.c_void_p),
            ("dwProcessId", wintypes.DWORD),
            ("dwThreadId", wintypes.DWORD),
        ]

    class _StartupInfo(ctypes.Structure):
        _fields_ = [
            ("cb", wintypes.DWORD),
            ("lpReserved", wintypes.LPWSTR),
            ("lpDesktop", wintypes.LPWSTR),
            ("lpTitle", wintypes.LPWSTR),
            ("dwX", wintypes.DWORD),
            ("dwY", wintypes.DWORD),
            ("dwXSize", wintypes.DWORD),
            ("dwYSize", wintypes.DWORD),
            ("dwXCountChars", wintypes.DWORD),
            ("dwYCountChars", wintypes.DWORD),
            ("dwFillAttribute", wintypes.DWORD),
            ("dwFlags", wintypes.DWORD),
            ("wShowWindow", wintypes.WORD),
            ("cbReserved2", wintypes.WORD),
            ("lpReserved2", ctypes.POINTER(ctypes.c_byte)),
            ("hStdInput", ctypes.c_void_p),
            ("hStdOutput", ctypes.c_void_p),
            ("hStdError", ctypes.c_void_p),
        ]

    class _StartupInfoEx(ctypes.Structure):
        _fields_ = [
            ("StartupInfo", _StartupInfo),
            ("lpAttributeList", ctypes.c_void_p),
        ]


def _last_error(message: str) -> WindowsNativeProcessError:
    error = ctypes.get_last_error()
    return WindowsNativeProcessError(f"{message} (WinError {error})")


class _RestrictedToken:
    """Own one primary token derived from the trusted parent token."""

    _HIGH_RISK_GROUPS = (
        "S-1-5-32-544",  # Administrators
        "S-1-5-32-547",  # Power Users
        "S-1-5-32-551",  # Backup Operators
        "S-1-5-32-549",  # System Operators
    )

    def __init__(self, handle: int, advapi: Any, kernel32: Any) -> None:
        self.handle = handle
        self._advapi = advapi
        self._kernel32 = kernel32

    @classmethod
    def create(cls) -> _RestrictedToken:
        if sys.platform != "win32":
            raise WindowsNativeProcessError("Restricted Windows tokens are unavailable")
        try:
            advapi = ctypes.WinDLL("advapi32.dll", use_last_error=True)
            kernel32 = ctypes.WinDLL("kernel32.dll", use_last_error=True)
            advapi.OpenProcessToken.argtypes = [
                ctypes.c_void_p,
                wintypes.DWORD,
                ctypes.POINTER(ctypes.c_void_p),
            ]
            advapi.OpenProcessToken.restype = wintypes.BOOL
            advapi.CreateRestrictedToken.argtypes = [
                ctypes.c_void_p,
                wintypes.DWORD,
                wintypes.DWORD,
                ctypes.POINTER(_SidAndAttributes),
                wintypes.DWORD,
                ctypes.POINTER(_LuidAndAttributes),
                wintypes.DWORD,
                ctypes.POINTER(_SidAndAttributes),
                ctypes.POINTER(ctypes.c_void_p),
            ]
            advapi.CreateRestrictedToken.restype = wintypes.BOOL
            advapi.ConvertStringSidToSidW.argtypes = [
                wintypes.LPCWSTR,
                ctypes.POINTER(ctypes.c_void_p),
            ]
            advapi.ConvertStringSidToSidW.restype = wintypes.BOOL
            kernel32.GetCurrentProcess.argtypes = []
            kernel32.GetCurrentProcess.restype = ctypes.c_void_p
            kernel32.CloseHandle.argtypes = [ctypes.c_void_p]
            kernel32.CloseHandle.restype = wintypes.BOOL
            kernel32.LocalFree.argtypes = [ctypes.c_void_p]
            kernel32.LocalFree.restype = ctypes.c_void_p
            source = ctypes.c_void_p()
            access = _TOKEN_DUPLICATE | _TOKEN_QUERY | _TOKEN_ASSIGN_PRIMARY | _TOKEN_ADJUST_DEFAULT
            if not advapi.OpenProcessToken(
                kernel32.GetCurrentProcess(), access, ctypes.byref(source)
            ):
                raise _last_error("OpenProcessToken failed")
            sid_buffers: list[ctypes.c_void_p] = []
            try:
                groups = (_SidAndAttributes * len(cls._HIGH_RISK_GROUPS))()
                for index, sid_text in enumerate(cls._HIGH_RISK_GROUPS):
                    sid = ctypes.c_void_p()
                    if not advapi.ConvertStringSidToSidW(sid_text, ctypes.byref(sid)):
                        raise _last_error("ConvertStringSidToSidW failed")
                    sid_buffers.append(sid)
                    groups[index] = _SidAndAttributes(sid, _TOKEN_GROUP_ATTRIBUTES)
                restricted = ctypes.c_void_p()
                if not advapi.CreateRestrictedToken(
                    source,
                    _DISABLE_MAX_PRIVILEGE,
                    len(groups),
                    groups,
                    0,
                    None,
                    0,
                    None,
                    ctypes.byref(restricted),
                ):
                    raise _last_error("CreateRestrictedToken failed")
                if restricted.value is None:
                    raise WindowsNativeProcessError("CreateRestrictedToken returned no token")
                return cls(int(restricted.value), advapi, kernel32)
            finally:
                for sid in sid_buffers:
                    kernel32.LocalFree(sid)
                kernel32.CloseHandle(source)
        except WindowsNativeProcessError:
            raise
        except (AttributeError, OSError, TypeError, ValueError) as error:
            raise WindowsNativeProcessError("Restricted token setup failed") from error

    def close(self) -> None:
        if self.handle:
            self._kernel32.CloseHandle(self.handle)
            self.handle = 0


class _AppContainerProfile:
    """Own a unique AppContainer profile and its native SID."""

    def __init__(self, name: str, sid: int, userenv: Any, kernel32: Any) -> None:
        self.name = name
        self.sid = sid
        self._userenv = userenv
        self._kernel32 = kernel32

    @classmethod
    def create(cls, name: str) -> _AppContainerProfile:
        if sys.platform != "win32":
            raise WindowsNativeProcessError("AppContainer is unavailable")
        if not isinstance(name, str) or not name or len(name) > 50:
            raise WindowsNativeProcessError("AppContainer profile name is invalid")
        try:
            userenv = ctypes.WinDLL("userenv.dll", use_last_error=True)
            kernel32 = ctypes.WinDLL("kernel32.dll", use_last_error=True)
            userenv.CreateAppContainerProfile.argtypes = [
                wintypes.LPCWSTR,
                wintypes.LPCWSTR,
                wintypes.LPCWSTR,
                ctypes.POINTER(_SidAndAttributes),
                wintypes.DWORD,
                ctypes.POINTER(ctypes.c_void_p),
            ]
            userenv.CreateAppContainerProfile.restype = ctypes.c_long
            userenv.DeriveAppContainerSidFromAppContainerName.argtypes = [
                wintypes.LPCWSTR,
                ctypes.POINTER(ctypes.c_void_p),
            ]
            userenv.DeriveAppContainerSidFromAppContainerName.restype = ctypes.c_long
            userenv.DeleteAppContainerProfile.argtypes = [wintypes.LPCWSTR]
            userenv.DeleteAppContainerProfile.restype = ctypes.c_long
            kernel32.LocalFree.argtypes = [ctypes.c_void_p]
            kernel32.LocalFree.restype = ctypes.c_void_p
            sid = ctypes.c_void_p()
            result = (
                int(
                    userenv.CreateAppContainerProfile(
                        name,
                        name,
                        "JARVIS generated integration sandbox",
                        None,
                        0,
                        ctypes.byref(sid),
                    )
                )
                & 0xFFFFFFFF
            )
            if result == _HRESULT_ALREADY_EXISTS:
                result = (
                    int(userenv.DeriveAppContainerSidFromAppContainerName(name, ctypes.byref(sid)))
                    & 0xFFFFFFFF
                )
            if result != _ERROR_SUCCESS or not sid.value:
                raise _last_error("AppContainer profile creation failed")
            return cls(name, int(sid.value), userenv, kernel32)
        except WindowsNativeProcessError:
            raise
        except (AttributeError, OSError, TypeError, ValueError) as error:
            raise WindowsNativeProcessError("AppContainer profile setup failed") from error

    def close(self, *, delete: bool = True) -> None:
        if self.sid:
            self._kernel32.LocalFree(self.sid)
            self.sid = 0
        if delete:
            result = int(self._userenv.DeleteAppContainerProfile(self.name)) & 0xFFFFFFFF
            if result not in {_ERROR_SUCCESS, 0x80070490}:  # profile already absent
                raise _last_error("AppContainer profile cleanup failed")

    def folder_path(self) -> str:
        """Return the OS-owned LOCALAPPDATA root for this profile."""

        advapi = ctypes.WinDLL("advapi32.dll", use_last_error=True)
        ole32 = ctypes.WinDLL("ole32.dll", use_last_error=True)
        advapi.ConvertSidToStringSidW.argtypes = [
            ctypes.c_void_p,
            ctypes.POINTER(ctypes.c_void_p),
        ]
        advapi.ConvertSidToStringSidW.restype = wintypes.BOOL
        self._userenv.GetAppContainerFolderPath.argtypes = [
            wintypes.LPCWSTR,
            ctypes.POINTER(ctypes.c_void_p),
        ]
        self._userenv.GetAppContainerFolderPath.restype = ctypes.c_long
        self._kernel32.LocalFree.argtypes = [ctypes.c_void_p]
        self._kernel32.LocalFree.restype = ctypes.c_void_p
        ole32.CoTaskMemFree.argtypes = [ctypes.c_void_p]
        ole32.CoTaskMemFree.restype = None
        sid_text = ctypes.c_void_p()
        folder = ctypes.c_void_p()
        if not advapi.ConvertSidToStringSidW(self.sid, ctypes.byref(sid_text)):
            raise _last_error("ConvertSidToStringSidW failed")
        try:
            if sid_text.value is None:
                raise WindowsNativeProcessError("AppContainer SID text is unavailable")
            sid_value = ctypes.wstring_at(int(sid_text.value))
            result = (
                int(self._userenv.GetAppContainerFolderPath(sid_value, ctypes.byref(folder)))
                & 0xFFFFFFFF
            )
            if result != _ERROR_SUCCESS or not folder.value:
                raise _last_error("GetAppContainerFolderPath failed")
            return ctypes.wstring_at(folder.value)
        finally:
            if sid_text.value:
                self._kernel32.LocalFree(sid_text)
            if folder.value:
                ole32.CoTaskMemFree(folder)


class _AppContainerAclLease:
    """Temporarily grant an AppContainer SID access to a trusted root.

    The runtime root is restored before the process lease is released.  The
    per-run sandbox root is disposable, but it is restored as well so a failed
    cleanup never leaves a broader ACL behind on an existing path.
    """

    _SE_FILE_OBJECT = 1
    _DACL_SECURITY_INFORMATION = 0x00000004
    _GRANT_ACCESS = 1
    _SUB_CONTAINERS_AND_OBJECTS_INHERIT = 0x00000003
    _FILE_GENERIC_READ = 0x00120089
    _FILE_GENERIC_WRITE = 0x00120116
    _FILE_GENERIC_EXECUTE = 0x001200A0
    _FILE_GENERIC_ALL = 0x001F01FF
    _FILE_TRAVERSE = 0x00000020
    _TRUSTEE_IS_SID = 0
    _TRUSTEE_IS_WELL_KNOWN_GROUP = 5

    def __init__(
        self,
        path: str,
        security_descriptor: int,
        old_dacl: int,
        advapi: Any,
        kernel32: Any,
    ) -> None:
        self.path = path
        self._security_descriptor = security_descriptor
        self._old_dacl = old_dacl
        self._advapi = advapi
        self._kernel32 = kernel32
        self._released = False

    @classmethod
    def grant(
        cls,
        path: str,
        sid: int,
        *,
        access: int,
        advapi: Any | None = None,
        kernel32: Any | None = None,
    ) -> _AppContainerAclLease:
        if sys.platform != "win32":
            raise WindowsNativeProcessError("AppContainer ACLs are unavailable")
        try:
            advapi = advapi or ctypes.WinDLL("advapi32.dll", use_last_error=True)
            kernel32 = kernel32 or ctypes.WinDLL("kernel32.dll", use_last_error=True)

            class _Trustee(ctypes.Structure):
                _fields_ = [
                    ("pMultipleTrustee", ctypes.c_void_p),
                    ("MultipleTrusteeOperation", wintypes.DWORD),
                    ("TrusteeForm", wintypes.DWORD),
                    ("TrusteeType", wintypes.DWORD),
                    ("ptstrName", ctypes.c_void_p),
                ]

            class _ExplicitAccess(ctypes.Structure):
                _fields_ = [
                    ("grfAccessPermissions", wintypes.DWORD),
                    ("grfAccessMode", wintypes.DWORD),
                    ("grfInheritance", wintypes.DWORD),
                    ("Trustee", _Trustee),
                ]

            advapi.GetNamedSecurityInfoW.argtypes = [
                wintypes.LPCWSTR,
                wintypes.DWORD,
                wintypes.DWORD,
                ctypes.POINTER(ctypes.c_void_p),
                ctypes.POINTER(ctypes.c_void_p),
                ctypes.POINTER(ctypes.c_void_p),
                ctypes.POINTER(ctypes.c_void_p),
                ctypes.POINTER(ctypes.c_void_p),
            ]
            advapi.GetNamedSecurityInfoW.restype = wintypes.DWORD
            advapi.SetEntriesInAclW.argtypes = [
                wintypes.DWORD,
                ctypes.POINTER(_ExplicitAccess),
                ctypes.c_void_p,
                ctypes.POINTER(ctypes.c_void_p),
            ]
            advapi.SetEntriesInAclW.restype = wintypes.DWORD
            advapi.SetNamedSecurityInfoW.argtypes = [
                wintypes.LPWSTR,
                wintypes.DWORD,
                wintypes.DWORD,
                ctypes.c_void_p,
                ctypes.c_void_p,
                ctypes.c_void_p,
                ctypes.c_void_p,
            ]
            advapi.SetNamedSecurityInfoW.restype = wintypes.DWORD
            kernel32.LocalFree.argtypes = [ctypes.c_void_p]
            kernel32.LocalFree.restype = ctypes.c_void_p

            owner = ctypes.c_void_p()
            group = ctypes.c_void_p()
            old_dacl = ctypes.c_void_p()
            sacl = ctypes.c_void_p()
            descriptor = ctypes.c_void_p()
            result = advapi.GetNamedSecurityInfoW(
                path,
                cls._SE_FILE_OBJECT,
                cls._DACL_SECURITY_INFORMATION,
                ctypes.byref(owner),
                ctypes.byref(group),
                ctypes.byref(old_dacl),
                ctypes.byref(sacl),
                ctypes.byref(descriptor),
            )
            if result != _ERROR_SUCCESS or not descriptor.value:
                raise WindowsNativeProcessError("AppContainer ACL inspection failed")
            trustee = _Trustee(
                None,
                0,
                cls._TRUSTEE_IS_SID,
                cls._TRUSTEE_IS_WELL_KNOWN_GROUP,
                ctypes.c_void_p(sid),
            )
            entry = _ExplicitAccess(
                access,
                cls._GRANT_ACCESS,
                cls._SUB_CONTAINERS_AND_OBJECTS_INHERIT,
                trustee,
            )
            new_dacl = ctypes.c_void_p()
            result = advapi.SetEntriesInAclW(
                1,
                ctypes.byref(entry),
                old_dacl,
                ctypes.byref(new_dacl),
            )
            if result != _ERROR_SUCCESS or not new_dacl.value:
                kernel32.LocalFree(descriptor)
                raise WindowsNativeProcessError("AppContainer ACL construction failed")
            result = advapi.SetNamedSecurityInfoW(
                path,
                cls._SE_FILE_OBJECT,
                cls._DACL_SECURITY_INFORMATION,
                None,
                None,
                new_dacl,
                None,
            )
            kernel32.LocalFree(new_dacl)
            if result != _ERROR_SUCCESS:
                kernel32.LocalFree(descriptor)
                raise WindowsNativeProcessError("AppContainer ACL application failed")
            return cls(path, int(descriptor.value), int(old_dacl.value or 0), advapi, kernel32)
        except WindowsNativeProcessError:
            raise
        except (AttributeError, OSError, TypeError, ValueError) as error:
            raise WindowsNativeProcessError("AppContainer ACL setup failed") from error

    def release(self) -> None:
        if self._released:
            return
        self._released = True
        try:
            result = self._advapi.SetNamedSecurityInfoW(
                self.path,
                self._SE_FILE_OBJECT,
                self._DACL_SECURITY_INFORMATION,
                None,
                None,
                self._old_dacl or None,
                None,
            )
            if result != _ERROR_SUCCESS:
                raise WindowsNativeProcessError("AppContainer ACL restoration failed")
        finally:
            self._kernel32.LocalFree(self._security_descriptor)


class WindowsNativeProcess:
    """Async stream/process adapter around a suspended native process."""

    def __init__(
        self,
        process_handle: int,
        thread_handle: int,
        process_id: int,
        kernel32: Any,
        cleanup: Any | None = None,
    ) -> None:
        self._process_handle = process_handle
        self._thread_handle = thread_handle
        self._kernel32 = kernel32
        self.pid = process_id
        self._returncode: int | None = None
        self.stdin: asyncio.StreamWriter | None = None
        self.stdout: asyncio.StreamReader | None = None
        self.stderr: asyncio.StreamReader | None = None
        self._read_transport: Any = None
        self._stderr_transport: Any = None
        self._write_transport: Any = None
        self._cleanup = cleanup
        self._cleanup_done = False
        self._cleanup_error: Exception | None = None

    @property
    def cleanup_error(self) -> Exception | None:
        """Return a native profile/ACL cleanup error, if one occurred."""

        return self._cleanup_error

    @property
    def returncode(self) -> int | None:
        if self._returncode is not None or not self._process_handle:
            return self._returncode
        code = wintypes.DWORD()
        if (
            self._kernel32.GetExitCodeProcess(self._process_handle, ctypes.byref(code))
            and code.value != _STILL_ACTIVE
        ):
            self._returncode = int(code.value)
        return self._returncode

    def resume(self) -> None:
        result = self._kernel32.ResumeThread(self._thread_handle)
        if result == 0xFFFFFFFF:
            raise _last_error("ResumeThread failed")

    async def connect_streams(
        self,
        stdin_handle: int,
        stdout_handle: int,
        limit: int,
        stderr_handle: int | None = None,
    ) -> None:
        from asyncio import windows_utils

        loop = asyncio.get_running_loop()
        write_pipe = windows_utils.PipeHandle(stdin_handle)
        read_pipe = windows_utils.PipeHandle(stdout_handle)
        error_pipe = windows_utils.PipeHandle(stderr_handle) if stderr_handle is not None else None
        reader = asyncio.StreamReader(limit=limit)
        read_protocol = asyncio.StreamReaderProtocol(reader, loop=loop)
        try:
            self._read_transport, _ = await loop.connect_read_pipe(
                lambda: read_protocol,
                read_pipe,
            )
            if error_pipe is not None:
                error_reader = asyncio.StreamReader(limit=limit)
                error_protocol = asyncio.StreamReaderProtocol(error_reader, loop=loop)
                self._stderr_transport, _ = await loop.connect_read_pipe(
                    lambda: error_protocol,
                    error_pipe,
                )
                self.stderr = error_reader
            write_protocol = asyncio.streams.FlowControlMixin(loop=loop)
            self._write_transport, _ = await loop.connect_write_pipe(
                lambda: write_protocol,
                write_pipe,
            )
            self.stdin = asyncio.StreamWriter(self._write_transport, write_protocol, None, loop)
            self.stdout = reader
        except Exception:
            read_pipe.close()
            if error_pipe is not None:
                error_pipe.close()
            write_pipe.close()
            self.close_streams()
            raise

    def terminate(self) -> None:
        if self._process_handle and not self._kernel32.TerminateProcess(self._process_handle, 1):
            if self.returncode is None:
                raise _last_error("TerminateProcess failed")

    kill = terminate

    async def wait(self) -> int:
        if self._returncode is None and self._process_handle:
            await asyncio.to_thread(self._wait_native)
        return self._returncode if self._returncode is not None else 0

    def _wait_native(self) -> None:
        result = self._kernel32.WaitForSingleObject(self._process_handle, _INFINITE)
        if result != 0:
            raise _last_error("WaitForSingleObject failed")
        code = wintypes.DWORD()
        if not self._kernel32.GetExitCodeProcess(self._process_handle, ctypes.byref(code)):
            raise _last_error("GetExitCodeProcess failed")
        self._returncode = int(code.value)
        self._close_native_handles()

    def close_streams(self) -> None:
        if self.stdin is not None:
            self.stdin.close()
        for transport in (self._read_transport, self._stderr_transport, self._write_transport):
            if transport is not None:
                transport.close()
        self.stdin = None
        self.stdout = None
        self.stderr = None
        self._read_transport = None
        self._stderr_transport = None
        self._write_transport = None

    def _close_native_handles(self) -> None:
        for attribute in ("_thread_handle", "_process_handle"):
            handle = getattr(self, attribute)
            if handle:
                self._kernel32.CloseHandle(handle)
                setattr(self, attribute, 0)
        if self._cleanup is not None and not self._cleanup_done:
            self._cleanup_done = True
            cleanup, self._cleanup = self._cleanup, None
            try:
                cleanup()
            except Exception as error:
                self._cleanup_error = error

    def close(self) -> None:
        self.close_streams()
        self._close_native_handles()


class WindowsJobProcessLauncher:
    """Launch a trusted local child into a caller-owned Job before execution.

    This launcher deliberately provides lifecycle containment only.  It is for
    trusted, catalogued local processes such as the controlled test runner; it
    is not the generated IntegrationPackage isolation boundary.  The root is
    created suspended, receives only explicit standard handles, joins the Job,
    and is then resumed, eliminating the root/descendant ownership race.
    """

    @classmethod
    async def launch(
        cls,
        executable: str,
        arguments: tuple[str, ...],
        *,
        cwd: str,
        environment: dict[str, str],
        limit: int,
        job: _JobAssignment,
    ) -> WindowsNativeProcess:
        if sys.platform != "win32":
            raise WindowsNativeProcessError("Windows Job launch is unavailable")
        try:
            native, stdin_handle, stdout_handle, stderr_handle = await asyncio.to_thread(
                cls._launch_sync,
                executable,
                arguments,
                cwd,
                environment,
                job,
            )
        except WindowsNativeProcessError:
            raise
        except Exception as error:
            raise WindowsNativeProcessError("Native Windows Job launch failed") from error
        try:
            await native.connect_streams(stdin_handle, stdout_handle, limit, stderr_handle)
        except Exception as error:
            with contextlib.suppress(Exception):
                native.terminate()
            with contextlib.suppress(Exception):
                native.close()
            if isinstance(error, WindowsNativeProcessError):
                raise
            raise WindowsNativeProcessError("Native Windows Job stream setup failed") from error
        return native

    @classmethod
    def _launch_sync(
        cls,
        executable: str,
        arguments: tuple[str, ...],
        cwd: str,
        environment: dict[str, str],
        job: _JobAssignment,
    ) -> tuple[WindowsNativeProcess, int, int, int]:
        if sys.platform != "win32":
            raise WindowsNativeProcessError("Windows Job launch is unavailable")
        from asyncio import windows_utils

        kernel32 = ctypes.WinDLL("kernel32.dll", use_last_error=True)
        advapi = ctypes.WinDLL("advapi32.dll", use_last_error=True)
        WindowsRestrictedLauncher._configure_libraries(kernel32, advapi)
        kernel32.CreateProcessW.argtypes = [
            wintypes.LPCWSTR,
            wintypes.LPWSTR,
            ctypes.c_void_p,
            ctypes.c_void_p,
            wintypes.BOOL,
            wintypes.DWORD,
            ctypes.c_void_p,
            wintypes.LPCWSTR,
            ctypes.c_void_p,
            ctypes.POINTER(_ProcessInformation),
        ]
        kernel32.CreateProcessW.restype = wintypes.BOOL
        handles: list[int] = []
        native: WindowsNativeProcess | None = None
        try:
            child_stdin, parent_stdin = windows_utils.pipe(duplex=True)
            parent_stdout, child_stdout = windows_utils.pipe(duplex=True)
            parent_stderr, child_stderr = windows_utils.pipe(duplex=True)
            handles.extend(
                [
                    child_stdin,
                    parent_stdin,
                    parent_stdout,
                    child_stdout,
                    parent_stderr,
                    child_stderr,
                ]
            )
            for handle in (child_stdin, child_stdout, child_stderr):
                WindowsRestrictedLauncher._set_inheritable(kernel32, handle, True)
            for handle in (parent_stdin, parent_stdout, parent_stderr):
                WindowsRestrictedLauncher._set_inheritable(kernel32, handle, False)
            startup, _attribute_buffer = WindowsRestrictedLauncher._startup_info(
                kernel32,
                [child_stdin, child_stdout, child_stderr],
            )
            command = ctypes.create_unicode_buffer(
                subprocess.list2cmdline((executable, *arguments))
            )
            drive = cwd[:2] if len(cwd) >= 2 and cwd[1] == ":" else ""
            drive_environment = f"={drive}={cwd}\0" if drive else ""
            environment_block = ctypes.create_unicode_buffer(
                drive_environment
                + "".join(f"{key}={environment[key]}\0" for key in sorted(environment))
                + "\0"
            )
            application = ctypes.create_unicode_buffer(executable)
            working_directory = ctypes.create_unicode_buffer(cwd)
            process_info = _ProcessInformation()
            creation_flags = (
                _CREATE_SUSPENDED
                | _CREATE_NEW_PROCESS_GROUP
                | _CREATE_NO_WINDOW
                | _CREATE_UNICODE_ENVIRONMENT
                | _EXTENDED_STARTUPINFO_PRESENT
            )
            try:
                created = kernel32.CreateProcessW(
                    application,
                    command,
                    None,
                    None,
                    True,
                    creation_flags,
                    environment_block,
                    working_directory,
                    ctypes.cast(ctypes.byref(startup), ctypes.c_void_p),
                    ctypes.byref(process_info),
                )
            finally:
                kernel32.DeleteProcThreadAttributeList(startup.lpAttributeList)
                startup.lpAttributeList = None
            if not created:
                raise _last_error("CreateProcessW Job launch failed")
            native = WindowsNativeProcess(
                int(process_info.hProcess),
                int(process_info.hThread),
                int(process_info.dwProcessId),
                kernel32,
            )
            job.assign_handle(native._process_handle, native.pid)
            native.resume()
            for handle in (child_stdin, child_stdout, child_stderr):
                WindowsRestrictedLauncher._close_handle(kernel32, handle)
            handles = [parent_stdin, parent_stdout, parent_stderr]
            return native, parent_stdin, parent_stdout, parent_stderr
        except Exception:
            if native is not None:
                with contextlib.suppress(Exception):
                    native.terminate()
                with contextlib.suppress(Exception):
                    native.close()
            for handle in handles:
                WindowsRestrictedLauncher._close_handle(kernel32, handle)
            raise


class WindowsRestrictedLauncher:
    """Create a suspended child with a reduced token and explicit handles."""

    @classmethod
    async def launch(
        cls,
        executable: str,
        arguments: tuple[str, ...],
        *,
        cwd: str,
        environment: dict[str, str],
        limit: int,
        job: _JobAssignment,
    ) -> tuple[WindowsNativeProcess, SandboxSecurityStatus]:
        if sys.platform != "win32":
            raise WindowsNativeProcessError("Restricted Windows launch is unavailable")
        try:
            native, status, stdin_handle, stdout_handle = await asyncio.to_thread(
                cls._launch_sync,
                executable,
                arguments,
                cwd,
                environment,
                limit,
                job,
            )
        except WindowsNativeProcessError:
            raise
        except Exception as error:
            raise WindowsNativeProcessError("Native restricted launch setup failed") from error
        try:
            await native.connect_streams(stdin_handle, stdout_handle, limit)
        except Exception as error:
            with contextlib.suppress(Exception):
                native.terminate()
            with contextlib.suppress(Exception):
                native.close()
            if isinstance(error, WindowsNativeProcessError):
                raise
            raise WindowsNativeProcessError("Native sandbox IPC setup failed") from error
        return native, status

    @classmethod
    def _launch_sync(
        cls,
        executable: str,
        arguments: tuple[str, ...],
        cwd: str,
        environment: dict[str, str],
        limit: int,
        job: _JobAssignment,
    ) -> tuple[WindowsNativeProcess, SandboxSecurityStatus, int, int]:
        if sys.platform != "win32":
            raise WindowsNativeProcessError("Restricted Windows launch is unavailable")
        from asyncio import windows_utils

        kernel32 = ctypes.WinDLL("kernel32.dll", use_last_error=True)
        advapi = ctypes.WinDLL("advapi32.dll", use_last_error=True)
        cls._configure_libraries(kernel32, advapi)
        token = _RestrictedToken.create()
        handles: list[Any] = []
        native: WindowsNativeProcess | None = None
        try:
            # Proactor write transports perform a read-side close probe, so
            # both endpoints must be duplex named-pipe handles even though
            # each endpoint is used in only one direction by the child.
            child_stdin, parent_stdin = windows_utils.pipe(duplex=True)
            parent_stdout, child_stdout = windows_utils.pipe(duplex=True)
            handles.extend([child_stdin, parent_stdin, parent_stdout, child_stdout])
            cls._set_inheritable(kernel32, child_stdin, True)
            cls._set_inheritable(kernel32, child_stdout, True)
            cls._set_inheritable(kernel32, parent_stdin, False)
            cls._set_inheritable(kernel32, parent_stdout, False)
            null_handle = cls._open_null(kernel32)
            handles.append(null_handle)
            cls._set_inheritable(kernel32, null_handle, True)
            startup, attribute_buffer = cls._startup_info(
                kernel32,
                [child_stdin, child_stdout, null_handle],
            )
            command = ctypes.create_unicode_buffer(
                subprocess.list2cmdline((executable, *arguments))
            )
            current_drive = cwd[:2] if len(cwd) >= 2 and cwd[1] == ":" else ""
            drive_environment = f"={current_drive}={cwd}\0" if current_drive else ""
            environment_block = ctypes.create_unicode_buffer(
                drive_environment
                + "".join(f"{key}={environment[key]}\0" for key in sorted(environment))
                + "\0"
            )
            application = ctypes.create_unicode_buffer(executable)
            working_directory = ctypes.create_unicode_buffer(cwd)
            process_info = _ProcessInformation()
            creation_flags = (
                _CREATE_SUSPENDED
                | _CREATE_NEW_PROCESS_GROUP
                | _CREATE_NO_WINDOW
                | _CREATE_UNICODE_ENVIRONMENT
                | _EXTENDED_STARTUPINFO_PRESENT
            )
            try:
                created, create_api = cls._create_process(
                    advapi,
                    token.handle,
                    application,
                    command,
                    creation_flags,
                    environment_block,
                    working_directory,
                    startup,
                    ctypes.byref(process_info),
                )
            finally:
                kernel32.DeleteProcThreadAttributeList(startup.lpAttributeList)
                startup.lpAttributeList = None
            if not created:
                raise _last_error("CreateProcess with restricted token failed")
            native = WindowsNativeProcess(
                int(process_info.hProcess),
                int(process_info.hThread),
                int(process_info.dwProcessId),
                kernel32,
            )
            job.assign_handle(native._process_handle, native.pid)
            native.resume()
            # Parent copies of child-side handles can now be closed.  The
            # returned parent handles remain owned by WindowsNativeProcess.
            cls._close_handle(kernel32, child_stdin)
            cls._close_handle(kernel32, child_stdout)
            cls._close_handle(kernel32, null_handle)
            handles = [parent_stdin, parent_stdout]
            status = SandboxSecurityStatus(
                mode=WindowsContainmentMode.RESTRICTED_TOKEN,
                token_restricted=True,
                disabled_privileges=True,
                explicit_handle_list=True,
                inherited_handle_count=3,
                job_object=True,
                filesystem_acl_restricted=False,
                network_restricted=False,
                detail=(
                    "restricted primary token; high-risk local groups disabled; "
                    f"explicit stdio handle list; Job Object assigned before resume ({create_api})"
                ),
            )
            return native, status, parent_stdin, parent_stdout
        except Exception:
            if native is not None:
                native.terminate()
                native.close()
            for handle in handles:
                cls._close_handle(kernel32, handle)
            raise
        finally:
            token.close()

    @staticmethod
    def _configure_libraries(kernel32: Any, advapi: Any) -> None:
        kernel32.CloseHandle.argtypes = [ctypes.c_void_p]
        kernel32.CloseHandle.restype = wintypes.BOOL
        kernel32.SetHandleInformation.argtypes = [ctypes.c_void_p, wintypes.DWORD, wintypes.DWORD]
        kernel32.SetHandleInformation.restype = wintypes.BOOL
        kernel32.CreateFileW.argtypes = [
            wintypes.LPCWSTR,
            wintypes.DWORD,
            wintypes.DWORD,
            ctypes.c_void_p,
            wintypes.DWORD,
            wintypes.DWORD,
            ctypes.c_void_p,
        ]
        kernel32.CreateFileW.restype = ctypes.c_void_p
        kernel32.ResumeThread.argtypes = [ctypes.c_void_p]
        kernel32.ResumeThread.restype = wintypes.DWORD
        kernel32.WaitForSingleObject.argtypes = [ctypes.c_void_p, wintypes.DWORD]
        kernel32.WaitForSingleObject.restype = wintypes.DWORD
        kernel32.GetExitCodeProcess.argtypes = [ctypes.c_void_p, ctypes.POINTER(wintypes.DWORD)]
        kernel32.GetExitCodeProcess.restype = wintypes.BOOL
        kernel32.TerminateProcess.argtypes = [ctypes.c_void_p, wintypes.UINT]
        kernel32.TerminateProcess.restype = wintypes.BOOL
        advapi.CreateProcessAsUserW.restype = wintypes.BOOL
        advapi.CreateProcessWithTokenW.restype = wintypes.BOOL

    @staticmethod
    def _set_inheritable(kernel32: Any, handle: int, enabled: bool) -> None:
        if not kernel32.SetHandleInformation(
            handle,
            _HANDLE_FLAG_INHERIT,
            _HANDLE_FLAG_INHERIT if enabled else 0,
        ):
            raise _last_error("SetHandleInformation failed")

    @staticmethod
    def _open_null(kernel32: Any) -> int:
        handle = kernel32.CreateFileW(
            "NUL",
            0x40000000,
            0x00000003,
            None,
            3,
            0x00000080,
            None,
        )
        if not handle:
            raise _last_error("NUL handle creation failed")
        return int(handle)

    @staticmethod
    def _close_handle(kernel32: Any, handle: int) -> None:
        if handle:
            kernel32.CloseHandle(handle)

    @staticmethod
    def _startup_info(
        kernel32: Any,
        handles: list[int],
        security_capabilities: Any | None = None,
    ) -> tuple[Any, Any]:
        size = ctypes.c_size_t()
        kernel32.InitializeProcThreadAttributeList.argtypes = [
            ctypes.c_void_p,
            wintypes.DWORD,
            wintypes.DWORD,
            ctypes.POINTER(ctypes.c_size_t),
        ]
        kernel32.InitializeProcThreadAttributeList.restype = wintypes.BOOL
        kernel32.UpdateProcThreadAttribute.argtypes = [
            ctypes.c_void_p,
            wintypes.DWORD,
            ctypes.c_size_t,
            ctypes.c_void_p,
            ctypes.c_size_t,
            ctypes.c_void_p,
            ctypes.POINTER(ctypes.c_size_t),
        ]
        kernel32.UpdateProcThreadAttribute.restype = wintypes.BOOL
        kernel32.DeleteProcThreadAttributeList.argtypes = [ctypes.c_void_p]
        kernel32.DeleteProcThreadAttributeList.restype = None
        attribute_count = 1 + (1 if security_capabilities is not None else 0)
        kernel32.InitializeProcThreadAttributeList(None, attribute_count, 0, ctypes.byref(size))
        if size.value == 0 or ctypes.get_last_error() not in {0, _ERROR_INSUFFICIENT_BUFFER}:
            raise _last_error("InitializeProcThreadAttributeList sizing failed")
        buffer = ctypes.create_string_buffer(size.value)
        attribute_list = ctypes.cast(buffer, ctypes.c_void_p)
        if not kernel32.InitializeProcThreadAttributeList(
            attribute_list, attribute_count, 0, ctypes.byref(size)
        ):
            raise _last_error("InitializeProcThreadAttributeList failed")
        handle_array = (ctypes.c_void_p * len(handles))(*handles)
        if not kernel32.UpdateProcThreadAttribute(
            attribute_list,
            0,
            _PROC_THREAD_ATTRIBUTE_HANDLE_LIST,
            handle_array,
            ctypes.sizeof(handle_array),
            None,
            None,
        ):
            kernel32.DeleteProcThreadAttributeList(attribute_list)
            raise _last_error("UpdateProcThreadAttribute handle list failed")
        if security_capabilities is not None and not kernel32.UpdateProcThreadAttribute(
            attribute_list,
            0,
            _PROC_THREAD_ATTRIBUTE_SECURITY_CAPABILITIES,
            ctypes.byref(security_capabilities),
            ctypes.sizeof(security_capabilities),
            None,
            None,
        ):
            kernel32.DeleteProcThreadAttributeList(attribute_list)
            raise _last_error("UpdateProcThreadAttribute security capabilities failed")
        startup = _StartupInfoEx()
        startup.StartupInfo.cb = ctypes.sizeof(_StartupInfoEx)
        startup.StartupInfo.dwFlags = _STARTF_USESTDHANDLES
        startup.StartupInfo.hStdInput = handles[0]
        startup.StartupInfo.hStdOutput = handles[1]
        startup.StartupInfo.hStdError = handles[2]
        startup.lpAttributeList = attribute_list
        # Keep both the allocation and array alive through CreateProcess.
        startup._attribute_buffer = buffer
        startup._handle_array = handle_array
        startup._security_capabilities = security_capabilities
        return startup, buffer

    @staticmethod
    def _create_process(
        advapi: Any,
        token: int,
        application: Any,
        command: Any,
        creation_flags: int,
        environment: Any,
        cwd: Any,
        startup: Any,
        process_info: Any,
    ) -> tuple[bool, str]:
        startup_pointer = ctypes.cast(ctypes.byref(startup), ctypes.c_void_p)
        result = advapi.CreateProcessAsUserW(
            token,
            application,
            command,
            None,
            None,
            True,
            creation_flags,
            environment,
            cwd,
            startup_pointer,
            process_info,
        )
        if result:
            return True, "CreateProcessAsUserW"
        first_error = ctypes.get_last_error()
        result = advapi.CreateProcessWithTokenW(
            token,
            0,
            application,
            command,
            creation_flags,
            environment,
            cwd,
            startup_pointer,
            process_info,
        )
        if result:
            return True, "CreateProcessWithTokenW"
        ctypes.set_last_error(first_error)
        return False, "none"


class WindowsAppContainerLauncher:
    """Launch a child in a capability-free Windows AppContainer.

    The caller must provide an explicit runtime root.  JARVIS grants the
    AppContainer read/execute access to that root for the duration of the
    launch and full access only to the disposable per-run sandbox root.  No
    AppContainer capabilities are declared, so direct network/device access
    is not part of this launch contract; real effects still require brokers.
    """

    @classmethod
    async def launch(
        cls,
        executable: str,
        arguments: tuple[str, ...],
        *,
        cwd: str,
        environment: dict[str, str],
        limit: int,
        job: _JobAssignment,
        profile_name: str,
        runtime_root: str,
        allowed_roots: tuple[str, ...] = (),
        writable_roots: tuple[str, ...] = (),
    ) -> tuple[WindowsNativeProcess, SandboxSecurityStatus]:
        if sys.platform != "win32":
            raise WindowsNativeProcessError("AppContainer launch is unavailable")
        try:
            native, status, stdin_handle, stdout_handle = await asyncio.to_thread(
                cls._launch_sync,
                executable,
                arguments,
                cwd,
                environment,
                limit,
                job,
                profile_name,
                runtime_root,
                allowed_roots,
                writable_roots,
            )
        except WindowsNativeProcessError:
            raise
        except Exception as error:
            raise WindowsNativeProcessError("Native AppContainer setup failed") from error
        try:
            await native.connect_streams(stdin_handle, stdout_handle, limit)
        except Exception as error:
            with contextlib.suppress(Exception):
                native.terminate()
            with contextlib.suppress(Exception):
                native.close()
            if isinstance(error, WindowsNativeProcessError):
                raise
            raise WindowsNativeProcessError("Native AppContainer IPC setup failed") from error
        return native, status

    @classmethod
    def _launch_sync(
        cls,
        executable: str,
        arguments: tuple[str, ...],
        cwd: str,
        environment: dict[str, str],
        limit: int,
        job: _JobAssignment,
        profile_name: str,
        runtime_root: str,
        allowed_roots: tuple[str, ...],
        writable_roots: tuple[str, ...],
    ) -> tuple[WindowsNativeProcess, SandboxSecurityStatus, int, int]:
        if sys.platform != "win32":
            raise WindowsNativeProcessError("AppContainer launch is unavailable")
        from asyncio import windows_utils

        if not isinstance(runtime_root, str) or not runtime_root:
            raise WindowsNativeProcessError("AppContainer runtime root is required")
        kernel32 = ctypes.WinDLL("kernel32.dll", use_last_error=True)
        advapi = ctypes.WinDLL("advapi32.dll", use_last_error=True)
        WindowsRestrictedLauncher._configure_libraries(kernel32, advapi)
        kernel32.CreateProcessW.argtypes = [
            wintypes.LPCWSTR,
            wintypes.LPWSTR,
            ctypes.c_void_p,
            ctypes.c_void_p,
            wintypes.BOOL,
            wintypes.DWORD,
            ctypes.c_void_p,
            wintypes.LPCWSTR,
            ctypes.c_void_p,
            ctypes.POINTER(_ProcessInformation),
        ]
        kernel32.CreateProcessW.restype = wintypes.BOOL
        profile = _AppContainerProfile.create(profile_name)
        leases: list[_AppContainerAclLease] = []
        native: WindowsNativeProcess | None = None
        handles: list[Any] = []
        cleanup_registered = False

        def cleanup_profile() -> None:
            cleanup_error: Exception | None = None
            for lease in reversed(leases):
                try:
                    lease.release()
                except Exception as error:
                    if cleanup_error is None:
                        cleanup_error = error
            try:
                profile.close()
            except Exception as error:
                if cleanup_error is None:
                    cleanup_error = error
            if cleanup_error is not None:
                raise WindowsNativeProcessError(
                    "AppContainer security cleanup failed"
                ) from cleanup_error

        try:
            roots = tuple(dict.fromkeys((runtime_root, *allowed_roots, *writable_roots)))
            writable = {
                os.path.normcase(os.path.abspath(root)).rstrip("\\/") for root in writable_roots
            }
            for root in roots:
                if not isinstance(root, str) or not root:
                    raise WindowsNativeProcessError("AppContainer ACL root is invalid")
                normalized_root = os.path.normcase(os.path.abspath(root)).rstrip("\\/")
                system_root = os.environ.get("SystemRoot", "C:\\Windows")
                packaged_root = os.path.normcase(
                    os.path.abspath(
                        os.path.join(os.path.dirname(system_root), "Program Files", "WindowsApps")
                    )
                ).rstrip("\\/")
                packaged_runtime = normalized_root.startswith(packaged_root + "\\")
                if packaged_runtime and root == runtime_root:
                    # Microsoft Store/package roots already carry the OS-owned
                    # AppContainer ACE and reject application ACL mutation.
                    continue
                leases.append(
                    _AppContainerAclLease.grant(
                        root,
                        profile.sid,
                        access=(
                            _AppContainerAclLease._FILE_GENERIC_ALL
                            if normalized_root in writable
                            else _AppContainerAclLease._FILE_GENERIC_READ
                            | _AppContainerAclLease._FILE_GENERIC_EXECUTE
                        ),
                        advapi=advapi,
                        kernel32=kernel32,
                    )
                )
                parent = os.path.dirname(root.rstrip("\\/"))
                if parent and parent != root:
                    leases.append(
                        _AppContainerAclLease.grant(
                            parent,
                            profile.sid,
                            access=_AppContainerAclLease._FILE_TRAVERSE,
                            advapi=advapi,
                            kernel32=kernel32,
                        )
                    )

            app_data_root = profile.folder_path()
            app_temp = os.path.join(app_data_root, "Temp")
            os.makedirs(app_temp, exist_ok=True)
            child_environment = dict(environment)
            child_environment.update(
                {
                    "LOCALAPPDATA": app_data_root,
                    "TEMP": app_temp,
                    "TMP": app_temp,
                }
            )

            child_stdin, parent_stdin = windows_utils.pipe(duplex=True)
            parent_stdout, child_stdout = windows_utils.pipe(duplex=True)
            handles.extend([child_stdin, parent_stdin, parent_stdout, child_stdout])
            WindowsRestrictedLauncher._set_inheritable(kernel32, child_stdin, True)
            WindowsRestrictedLauncher._set_inheritable(kernel32, child_stdout, True)
            WindowsRestrictedLauncher._set_inheritable(kernel32, parent_stdin, False)
            WindowsRestrictedLauncher._set_inheritable(kernel32, parent_stdout, False)
            null_handle = WindowsRestrictedLauncher._open_null(kernel32)
            handles.append(null_handle)
            WindowsRestrictedLauncher._set_inheritable(kernel32, null_handle, True)
            startup, attribute_buffer = WindowsRestrictedLauncher._startup_info(
                kernel32,
                [child_stdin, child_stdout, null_handle],
                _SecurityCapabilities(profile.sid, None, 0, 0),
            )
            command = ctypes.create_unicode_buffer(
                subprocess.list2cmdline((executable, *arguments))
            )
            drive_directories: dict[str, str] = {}
            for directory in (cwd, runtime_root):
                drive = directory[:2] if len(directory) >= 2 and directory[1] == ":" else ""
                if drive:
                    drive_directories[drive.upper()] = directory
            drive_environment = "".join(
                f"={drive}={drive_directories[drive]}\0" for drive in sorted(drive_directories)
            )
            environment_block = ctypes.create_unicode_buffer(
                drive_environment
                + "".join(f"{key}={child_environment[key]}\0" for key in sorted(child_environment))
                + "\0"
            )
            application = ctypes.create_unicode_buffer(executable)
            working_directory = ctypes.create_unicode_buffer(cwd)
            process_info = _ProcessInformation()
            creation_flags = (
                _CREATE_SUSPENDED
                | _CREATE_NEW_PROCESS_GROUP
                | _CREATE_NO_WINDOW
                | _CREATE_UNICODE_ENVIRONMENT
                | _EXTENDED_STARTUPINFO_PRESENT
            )
            try:
                created = kernel32.CreateProcessW(
                    application,
                    command,
                    None,
                    None,
                    True,
                    creation_flags,
                    environment_block,
                    working_directory,
                    ctypes.cast(ctypes.byref(startup), ctypes.c_void_p),
                    ctypes.byref(process_info),
                )
            finally:
                kernel32.DeleteProcThreadAttributeList(startup.lpAttributeList)
                startup.lpAttributeList = None
            if not created:
                raise _last_error("CreateProcessW AppContainer launch failed")
            native = WindowsNativeProcess(
                int(process_info.hProcess),
                int(process_info.hThread),
                int(process_info.dwProcessId),
                kernel32,
                cleanup=cleanup_profile,
            )
            cleanup_registered = True
            job.assign_handle(native._process_handle, native.pid)
            native.resume()
            WindowsRestrictedLauncher._close_handle(kernel32, child_stdin)
            WindowsRestrictedLauncher._close_handle(kernel32, child_stdout)
            WindowsRestrictedLauncher._close_handle(kernel32, null_handle)
            handles = [parent_stdin, parent_stdout]
            status = SandboxSecurityStatus(
                mode=WindowsContainmentMode.APPCONTAINER,
                token_restricted=True,
                disabled_privileges=True,
                explicit_handle_list=True,
                inherited_handle_count=3,
                job_object=True,
                filesystem_acl_restricted=True,
                network_restricted=True,
                detail=(
                    "capability-free AppContainer; scoped runtime/package ACLs; "
                    "explicit stdio handle list; Job Object assigned before resume"
                ),
                appcontainer_profile=profile_name,
                runtime_root=runtime_root,
            )
            return native, status, parent_stdin, parent_stdout
        except Exception:
            if native is not None:
                with contextlib.suppress(Exception):
                    native.terminate()
                with contextlib.suppress(Exception):
                    native.close()
            for handle in handles:
                WindowsRestrictedLauncher._close_handle(kernel32, handle)
            if not cleanup_registered:
                cleanup_profile()
            raise

    @staticmethod
    def available() -> bool:
        """Return whether the host exposes the mandatory AppContainer APIs."""

        if sys.platform != "win32":
            return False
        try:
            userenv = ctypes.WinDLL("userenv.dll", use_last_error=True)
            kernel32 = ctypes.WinDLL("kernel32.dll", use_last_error=True)
            return all(
                hasattr(userenv, name)
                for name in (
                    "CreateAppContainerProfile",
                    "DeriveAppContainerSidFromAppContainerName",
                    "DeleteAppContainerProfile",
                )
            ) and hasattr(kernel32, "CreateProcessW")
        except (AttributeError, OSError):
            return False


__all__ = [
    "SandboxSecurityStatus",
    "WindowsContainmentMode",
    "WindowsJobProcessLauncher",
    "WindowsNativeProcess",
    "WindowsNativeProcessError",
    "WindowsAppContainerLauncher",
    "WindowsRestrictedLauncher",
]
