"""Synthetic unit coverage for the local Windows containment adapter."""

from __future__ import annotations

import ctypes
import sys
from typing import Any, cast

import jarvis.windows_sandbox as native
import pytest

pytestmark = pytest.mark.skipif(sys.platform != "win32", reason="Windows native containment tests")


class FakeFunction:
    def __init__(self, result: object = True) -> None:
        self.result = result
        self.argtypes: object = None
        self.restype: object = None

    def __call__(self, *args: object) -> object:
        if callable(self.result):
            return self.result(*args)
        return self.result


class FakeLibrary:
    def __init__(self) -> None:
        self._functions: dict[str, FakeFunction] = {}

    def __getattr__(self, name: str) -> FakeFunction:
        function = self._functions.setdefault(name, FakeFunction())
        return function


def token_libraries(
    *,
    open_token: bool = True,
    convert_sid_ok: bool = True,
    create_token: object = True,
) -> tuple[Any, Any]:
    advapi: Any = FakeLibrary()
    kernel32: Any = FakeLibrary()

    def open_process_token(*args: object) -> bool:
        del args
        return open_token

    def convert_sid_fn(*args: object) -> bool:
        if convert_sid_ok:
            cast(Any, args[-1])._obj.value = 1234
        return convert_sid_ok

    def restricted(*args: object) -> object:
        if create_token and callable(create_token):
            return create_token(*args)
        if create_token:
            cast(Any, args[-1])._obj.value = 4321
        return create_token

    advapi.OpenProcessToken = FakeFunction(open_process_token)
    advapi.ConvertStringSidToSidW = FakeFunction(convert_sid_fn)
    advapi.CreateRestrictedToken = FakeFunction(restricted)
    kernel32.GetCurrentProcess = FakeFunction(99)
    kernel32.CloseHandle = FakeFunction(True)
    kernel32.LocalFree = FakeFunction(0)
    return advapi, kernel32


def patch_token_libraries(monkeypatch: pytest.MonkeyPatch, advapi: Any, kernel32: Any) -> None:
    def load(name: str, **kwargs: object) -> Any:
        del kwargs
        return advapi if "advapi" in name else kernel32

    monkeypatch.setattr(ctypes, "WinDLL", load)


def test_native_error_and_restricted_token_failures(monkeypatch: pytest.MonkeyPatch) -> None:
    with pytest.raises(native.WindowsNativeProcessError):
        raise native._last_error("synthetic")

    advapi, kernel32 = token_libraries(open_token=False)
    patch_token_libraries(monkeypatch, advapi, kernel32)
    with pytest.raises(native.WindowsNativeProcessError, match="OpenProcessToken"):
        native._RestrictedToken.create()

    advapi, kernel32 = token_libraries(convert_sid_ok=False)
    patch_token_libraries(monkeypatch, advapi, kernel32)
    with pytest.raises(native.WindowsNativeProcessError, match="ConvertStringSidToSidW"):
        native._RestrictedToken.create()

    advapi, kernel32 = token_libraries(create_token=False)
    patch_token_libraries(monkeypatch, advapi, kernel32)
    with pytest.raises(native.WindowsNativeProcessError, match="CreateRestrictedToken"):
        native._RestrictedToken.create()

    advapi, kernel32 = token_libraries(create_token=lambda *_: True)
    patch_token_libraries(monkeypatch, advapi, kernel32)
    with pytest.raises(native.WindowsNativeProcessError, match="no token"):
        native._RestrictedToken.create()

    monkeypatch.setattr(ctypes, "WinDLL", lambda *args, **kwargs: (_ for _ in ()).throw(OSError()))
    with pytest.raises(native.WindowsNativeProcessError, match="setup failed"):
        native._RestrictedToken.create()


@pytest.mark.asyncio
async def test_native_process_error_paths_and_cleanup() -> None:
    kernel32: Any = FakeLibrary()

    def exit_code(value: int, output: Any) -> bool:
        del value
        output._obj.value = 7
        return True

    kernel32.GetExitCodeProcess = FakeFunction(exit_code)
    kernel32.CloseHandle = FakeFunction(True)
    process = native.WindowsNativeProcess(1, 2, 3, kernel32)
    assert process.returncode == 7

    kernel32.ResumeThread = FakeFunction(0xFFFFFFFF)
    with pytest.raises(native.WindowsNativeProcessError, match="ResumeThread"):
        process.resume()

    kernel32.TerminateProcess = FakeFunction(False)

    def still_active(value: int, output: Any) -> bool:
        del value
        output._obj.value = 259
        return True

    kernel32.GetExitCodeProcess = FakeFunction(still_active)
    process = native.WindowsNativeProcess(1, 2, 3, kernel32)
    with pytest.raises(native.WindowsNativeProcessError, match="TerminateProcess"):
        process.terminate()

    kernel32.WaitForSingleObject = FakeFunction(1)
    with pytest.raises(native.WindowsNativeProcessError, match="WaitForSingleObject"):
        process._wait_native()

    kernel32.WaitForSingleObject = FakeFunction(0)
    kernel32.GetExitCodeProcess = FakeFunction(False)
    with pytest.raises(native.WindowsNativeProcessError, match="GetExitCodeProcess"):
        process._wait_native()

    def exited(value: int, output: Any) -> bool:
        del value
        output._obj.value = 4
        return True

    kernel32.GetExitCodeProcess = FakeFunction(exited)
    assert await process.wait() == 4
    process.close()


def test_native_startup_and_handle_setup_errors() -> None:
    kernel32: Any = FakeLibrary()
    kernel32.SetHandleInformation = FakeFunction(False)
    with pytest.raises(native.WindowsNativeProcessError, match="SetHandleInformation"):
        native.WindowsRestrictedLauncher._set_inheritable(kernel32, 1, True)

    kernel32.CreateFileW = FakeFunction(0)
    with pytest.raises(native.WindowsNativeProcessError, match="NUL"):
        native.WindowsRestrictedLauncher._open_null(kernel32)

    def initial_size(*args: object) -> bool:
        cast(Any, args[-1])._obj.value = 64
        ctypes.set_last_error(122)
        return False

    kernel32.InitializeProcThreadAttributeList = FakeFunction(initial_size)
    with pytest.raises(
        native.WindowsNativeProcessError, match="InitializeProcThreadAttributeList failed"
    ):
        native.WindowsRestrictedLauncher._startup_info(kernel32, [1, 2, 3])

    calls = 0

    def initialize_then_update(*args: object) -> bool:
        nonlocal calls
        calls += 1
        if calls == 1:
            cast(Any, args[-1])._obj.value = 64
            ctypes.set_last_error(122)
            return False
        return True

    kernel32.InitializeProcThreadAttributeList = FakeFunction(initialize_then_update)
    kernel32.UpdateProcThreadAttribute = FakeFunction(False)
    kernel32.DeleteProcThreadAttributeList = FakeFunction(None)
    with pytest.raises(native.WindowsNativeProcessError, match="UpdateProcThreadAttribute"):
        native.WindowsRestrictedLauncher._startup_info(kernel32, [1, 2, 3])

    calls = 0

    def initialize_with_security_failure(*args: object) -> bool:
        nonlocal calls
        calls += 1
        if calls == 1:
            cast(Any, args[-1])._obj.value = 64
            ctypes.set_last_error(122)
            return False
        return True

    kernel32.InitializeProcThreadAttributeList = FakeFunction(initialize_with_security_failure)
    updates = 0

    def update_handle_then_security(*args: object) -> bool:
        nonlocal updates
        del args
        updates += 1
        return updates == 1

    kernel32.UpdateProcThreadAttribute = FakeFunction(update_handle_then_security)
    with pytest.raises(native.WindowsNativeProcessError, match="security capabilities"):
        native.WindowsRestrictedLauncher._startup_info(
            kernel32,
            [1, 2, 3],
            native._SecurityCapabilities(123, None, 0, 0),
        )


def test_appcontainer_profile_and_acl_error_paths(monkeypatch: pytest.MonkeyPatch) -> None:
    userenv: Any = FakeLibrary()
    kernel32: Any = FakeLibrary()
    advapi: Any = FakeLibrary()
    ole32: Any = FakeLibrary()
    sid_buffer = ctypes.create_unicode_buffer("S-1-15-2-123")
    folder_buffer = ctypes.create_unicode_buffer("C:\\AppContainerData")

    def create_profile(*args: object) -> int:
        cast(Any, args[-1])._obj.value = 4321
        return native._ERROR_SUCCESS

    def derive_profile(*args: object) -> int:
        cast(Any, args[-1])._obj.value = 4322
        return native._ERROR_SUCCESS

    def sid_string(*args: object) -> bool:
        cast(Any, args[-1])._obj.value = ctypes.addressof(sid_buffer)
        return True

    def folder_path(*args: object) -> int:
        cast(Any, args[-1])._obj.value = ctypes.addressof(folder_buffer)
        return native._ERROR_SUCCESS

    userenv.CreateAppContainerProfile = FakeFunction(create_profile)
    userenv.DeriveAppContainerSidFromAppContainerName = FakeFunction(derive_profile)
    userenv.GetAppContainerFolderPath = FakeFunction(folder_path)
    userenv.DeleteAppContainerProfile = FakeFunction(native._ERROR_SUCCESS)
    advapi.ConvertSidToStringSidW = FakeFunction(sid_string)
    kernel32.LocalFree = FakeFunction(0)
    ole32.CoTaskMemFree = FakeFunction(None)

    def load(name: str, **kwargs: object) -> Any:
        del kwargs
        if "userenv" in name:
            return userenv
        if "advapi" in name:
            return advapi
        if "ole32" in name:
            return ole32
        return kernel32

    monkeypatch.setattr(ctypes, "WinDLL", load)
    profile = native._AppContainerProfile.create("JARVIS-profile")
    assert profile.sid == 4321
    assert profile.folder_path() == "C:\\AppContainerData"
    profile.close()
    assert profile.sid == 0
    profile.close()

    profile = native._AppContainerProfile("JARVIS-no-delete", 4321, userenv, kernel32)
    profile.close(delete=False)
    assert profile.sid == 0

    profile = native._AppContainerProfile("JARVIS-folder-errors", 4321, userenv, kernel32)
    advapi.ConvertSidToStringSidW = FakeFunction(False)
    with pytest.raises(native.WindowsNativeProcessError, match="ConvertSid"):
        profile.folder_path()
    advapi.ConvertSidToStringSidW = FakeFunction(sid_string)
    userenv.GetAppContainerFolderPath = FakeFunction(5)
    with pytest.raises(native.WindowsNativeProcessError, match="GetAppContainerFolder"):
        profile.folder_path()
    userenv.GetAppContainerFolderPath = FakeFunction(folder_path)
    profile.close()

    userenv.CreateAppContainerProfile = FakeFunction(native._HRESULT_ALREADY_EXISTS)
    profile = native._AppContainerProfile.create("JARVIS-existing")
    assert profile.sid == 4322
    profile.close()
    with pytest.raises(native.WindowsNativeProcessError, match="profile name"):
        native._AppContainerProfile.create("")

    def get_security_info(*args: object) -> int:
        cast(Any, args[-2])._obj.value = 22
        cast(Any, args[-1])._obj.value = 11
        return native._ERROR_SUCCESS

    def set_entries(*args: object) -> int:
        cast(Any, args[-1])._obj.value = 33
        return native._ERROR_SUCCESS

    advapi.GetNamedSecurityInfoW = FakeFunction(get_security_info)
    advapi.SetEntriesInAclW = FakeFunction(set_entries)
    advapi.SetNamedSecurityInfoW = FakeFunction(native._ERROR_SUCCESS)
    lease = native._AppContainerAclLease.grant(
        "C:\\owned",
        123,
        access=native._AppContainerAclLease._FILE_GENERIC_ALL,
        advapi=advapi,
        kernel32=kernel32,
    )
    lease.release()
    lease.release()

    advapi.GetNamedSecurityInfoW = FakeFunction(5)
    with pytest.raises(native.WindowsNativeProcessError, match="inspection"):
        native._AppContainerAclLease.grant(
            "C:\\owned",
            123,
            access=native._AppContainerAclLease._FILE_GENERIC_ALL,
            advapi=advapi,
            kernel32=kernel32,
        )

    advapi.GetNamedSecurityInfoW = FakeFunction(get_security_info)
    advapi.SetEntriesInAclW = FakeFunction(5)
    with pytest.raises(native.WindowsNativeProcessError, match="construction"):
        native._AppContainerAclLease.grant(
            "C:\\owned",
            123,
            access=native._AppContainerAclLease._FILE_GENERIC_ALL,
            advapi=advapi,
            kernel32=kernel32,
        )

    advapi.SetEntriesInAclW = FakeFunction(set_entries)
    advapi.SetNamedSecurityInfoW = FakeFunction(5)
    with pytest.raises(native.WindowsNativeProcessError, match="application"):
        native._AppContainerAclLease.grant(
            "C:\\owned",
            123,
            access=native._AppContainerAclLease._FILE_GENERIC_ALL,
            advapi=advapi,
            kernel32=kernel32,
        )

    advapi.GetNamedSecurityInfoW = None
    with pytest.raises(native.WindowsNativeProcessError, match="ACL setup"):
        native._AppContainerAclLease.grant(
            "C:\\owned",
            123,
            access=native._AppContainerAclLease._FILE_GENERIC_ALL,
            advapi=advapi,
            kernel32=kernel32,
        )

    advapi.GetNamedSecurityInfoW = FakeFunction(get_security_info)
    advapi.SetEntriesInAclW = FakeFunction(set_entries)
    advapi.SetNamedSecurityInfoW = FakeFunction(native._ERROR_SUCCESS)
    lease = native._AppContainerAclLease.grant(
        "C:\\owned",
        123,
        access=native._AppContainerAclLease._FILE_GENERIC_ALL,
        advapi=advapi,
        kernel32=kernel32,
    )
    advapi.SetNamedSecurityInfoW = FakeFunction(5)
    with pytest.raises(native.WindowsNativeProcessError, match="restoration"):
        lease.release()


def test_appcontainer_profile_failures(monkeypatch: pytest.MonkeyPatch) -> None:
    userenv: Any = FakeLibrary()
    kernel32: Any = FakeLibrary()

    userenv.CreateAppContainerProfile = FakeFunction(5)
    userenv.DeriveAppContainerSidFromAppContainerName = FakeFunction(5)
    userenv.DeleteAppContainerProfile = FakeFunction(5)
    kernel32.LocalFree = FakeFunction(0)

    def load(name: str, **kwargs: object) -> Any:
        del kwargs
        return userenv if "userenv" in name else kernel32

    monkeypatch.setattr(ctypes, "WinDLL", load)
    with pytest.raises(native.WindowsNativeProcessError, match="creation failed"):
        native._AppContainerProfile.create("JARVIS-failure")

    userenv.CreateAppContainerProfile = FakeFunction(native._ERROR_SUCCESS)
    with pytest.raises(native.WindowsNativeProcessError, match="no token|creation failed"):
        native._AppContainerProfile.create("JARVIS-no-sid")

    profile = native._AppContainerProfile("JARVIS-profile", 1, userenv, kernel32)
    with pytest.raises(native.WindowsNativeProcessError, match="cleanup failed"):
        profile.close()


def test_platform_unavailable_paths(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(sys, "platform", "linux")
    with pytest.raises(native.WindowsNativeProcessError, match="Restricted Windows"):
        native._RestrictedToken.create()
    with pytest.raises(native.WindowsNativeProcessError, match="AppContainer"):
        native._AppContainerProfile.create("JARVIS-profile")
    with pytest.raises(native.WindowsNativeProcessError, match="AppContainer ACL"):
        native._AppContainerAclLease.grant(
            "C:\\owned",
            123,
            access=native._AppContainerAclLease._FILE_GENERIC_ALL,
        )
    assert not native.WindowsAppContainerLauncher.available()


def test_native_cleanup_failure_is_observable() -> None:
    kernel32: Any = FakeLibrary()

    def fail_cleanup() -> None:
        raise RuntimeError("synthetic cleanup failure")

    process = native.WindowsNativeProcess(0, 0, 1, kernel32, cleanup=fail_cleanup)
    process.close()
    assert process.cleanup_error is not None


@pytest.mark.asyncio
async def test_appcontainer_launch_failures_are_typed(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def fail_sync(*args: object) -> None:
        del args
        raise RuntimeError("synthetic setup failure")

    monkeypatch.setattr(
        native.WindowsAppContainerLauncher,
        "_launch_sync",
        classmethod(lambda cls, *args: fail_sync(*args)),
    )
    with pytest.raises(native.WindowsNativeProcessError, match="setup failed"):
        await native.WindowsAppContainerLauncher.launch(
            "python.exe",
            (),
            cwd="C:\\owned",
            environment={},
            limit=1024,
            job=cast(Any, object()),
            profile_name="JARVIS-failure",
            runtime_root="C:\\runtime",
        )


@pytest.mark.asyncio
async def test_native_launch_setup_and_stream_failures_are_contained(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def fail_restricted(*args: object) -> None:
        del args
        raise RuntimeError("synthetic restricted setup failure")

    monkeypatch.setattr(
        native.WindowsRestrictedLauncher,
        "_launch_sync",
        staticmethod(fail_restricted),
    )
    with pytest.raises(native.WindowsNativeProcessError, match="restricted launch setup"):
        await native.WindowsRestrictedLauncher.launch(
            "python.exe",
            (),
            cwd="C:\\owned",
            environment={},
            limit=1024,
            job=cast(Any, object()),
        )

    class FakeProcess:
        def __init__(self, error: Exception) -> None:
            self.error = error
            self.terminated = False
            self.closed = False

        async def connect_streams(self, *args: object) -> None:
            del args
            raise self.error

        def terminate(self) -> None:
            self.terminated = True

        def close(self) -> None:
            self.closed = True

    status = native.SandboxSecurityStatus(
        native.WindowsContainmentMode.APPCONTAINER,
        True,
        True,
        True,
        3,
        True,
        True,
        True,
        "synthetic",
        appcontainer_profile="JARVIS-profile",
        runtime_root="C:\\runtime",
    )
    app_process = FakeProcess(RuntimeError("synthetic AppContainer pipe failure"))
    monkeypatch.setattr(
        native.WindowsAppContainerLauncher,
        "_launch_sync",
        staticmethod(lambda *args: (app_process, status, 1, 2)),
    )
    with pytest.raises(native.WindowsNativeProcessError, match="AppContainer IPC"):
        await native.WindowsAppContainerLauncher.launch(
            "python.exe",
            (),
            cwd="C:\\owned",
            environment={},
            limit=1024,
            job=cast(Any, object()),
            profile_name="JARVIS-profile",
            runtime_root="C:\\runtime",
        )
    assert app_process.terminated and app_process.closed

    restricted_process = FakeProcess(
        native.WindowsNativeProcessError("synthetic restricted pipe failure")
    )
    monkeypatch.setattr(
        native.WindowsRestrictedLauncher,
        "_launch_sync",
        staticmethod(lambda *args: (restricted_process, status, 1, 2)),
    )
    with pytest.raises(native.WindowsNativeProcessError, match="restricted pipe failure"):
        await native.WindowsRestrictedLauncher.launch(
            "python.exe",
            (),
            cwd="C:\\owned",
            environment={},
            limit=1024,
            job=cast(Any, object()),
        )


@pytest.mark.asyncio
async def test_job_launcher_is_typed_and_reaps_stream_setup_failure(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The controlled-test Job launcher must not leak a half-started native child."""

    async def launch() -> native.WindowsNativeProcess:
        return await native.WindowsJobProcessLauncher.launch(
            "python.exe",
            ("-c", "pass"),
            cwd="C:\\owned",
            environment={"PYTHONUTF8": "1"},
            limit=1024,
            job=cast(Any, object()),
        )

    monkeypatch.setattr(sys, "platform", "linux")
    with pytest.raises(native.WindowsNativeProcessError, match="Job launch is unavailable"):
        await launch()

    monkeypatch.setattr(sys, "platform", "win32")

    def unexpected_sync(cls: object, *args: object) -> object:
        del cls, args
        raise RuntimeError("synthetic Job startup failure")

    monkeypatch.setattr(
        native.WindowsJobProcessLauncher,
        "_launch_sync",
        classmethod(unexpected_sync),
    )
    with pytest.raises(native.WindowsNativeProcessError, match="Job launch failed"):
        await launch()

    def native_sync(cls: object, *args: object) -> object:
        del cls, args
        raise native.WindowsNativeProcessError("synthetic native Job failure")

    monkeypatch.setattr(
        native.WindowsJobProcessLauncher,
        "_launch_sync",
        classmethod(native_sync),
    )
    with pytest.raises(native.WindowsNativeProcessError, match="synthetic native Job failure"):
        await launch()

    class _Process:
        def __init__(self, error: Exception | None = None) -> None:
            self._error = error
            self.connected = False
            self.terminated = False
            self.closed = False

        async def connect_streams(self, *args: object) -> None:
            del args
            if self._error is not None:
                raise self._error
            self.connected = True

        def terminate(self) -> None:
            self.terminated = True

        def close(self) -> None:
            self.closed = True

    failing = _Process(RuntimeError("synthetic Job pipe failure"))
    monkeypatch.setattr(
        native.WindowsJobProcessLauncher,
        "_launch_sync",
        classmethod(lambda cls, *args: (failing, 1, 2, 3)),
    )
    with pytest.raises(native.WindowsNativeProcessError, match="Job stream setup failed"):
        await launch()
    assert failing.terminated and failing.closed

    typed_failure = _Process(native.WindowsNativeProcessError("synthetic Job pipe typed failure"))
    monkeypatch.setattr(
        native.WindowsJobProcessLauncher,
        "_launch_sync",
        classmethod(lambda cls, *args: (typed_failure, 1, 2, 3)),
    )
    with pytest.raises(native.WindowsNativeProcessError, match="synthetic Job pipe typed failure"):
        await launch()
    assert typed_failure.terminated and typed_failure.closed

    successful = _Process()
    monkeypatch.setattr(
        native.WindowsJobProcessLauncher,
        "_launch_sync",
        classmethod(lambda cls, *args: (successful, 1, 2, 3)),
    )
    assert await launch() is cast(native.WindowsNativeProcess, successful)
    assert successful.connected


@pytest.mark.asyncio
async def test_native_connect_streams_closes_pipe_handles_on_failure(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    import asyncio

    class Pipe:
        def __init__(self, handle: int) -> None:
            self.handle = handle
            self.closed = False

        def close(self) -> None:
            self.closed = True

    class Loop:
        def create_future(self) -> object:
            return asyncio.get_event_loop().create_future()

        async def connect_read_pipe(self, *args: object) -> None:
            del args
            raise RuntimeError("synthetic read pipe failure")

    read_pipe = Pipe(1)
    write_pipe = Pipe(2)
    monkeypatch.setattr(asyncio, "get_running_loop", lambda: Loop())
    monkeypatch.setattr(
        asyncio.windows_utils, "PipeHandle", lambda handle: read_pipe if handle == 1 else write_pipe
    )
    process = native.WindowsNativeProcess(0, 0, 1, FakeLibrary())
    with pytest.raises(RuntimeError, match="read pipe failure"):
        await process.connect_streams(1, 2, 1_024)
    assert read_pipe.closed and write_pipe.closed


def test_create_process_fallback_paths() -> None:
    advapi: Any = FakeLibrary()
    advapi.CreateProcessAsUserW = FakeFunction(False)
    advapi.CreateProcessWithTokenW = FakeFunction(True)
    result, api = native.WindowsRestrictedLauncher._create_process(
        advapi,
        1,
        "app",
        "command",
        0,
        "env",
        "cwd",
        ctypes.c_int(),
        ctypes.c_int(),
    )
    assert result and api == "CreateProcessWithTokenW"

    advapi.CreateProcessWithTokenW = FakeFunction(False)
    result, api = native.WindowsRestrictedLauncher._create_process(
        advapi,
        1,
        "app",
        "command",
        0,
        "env",
        "cwd",
        ctypes.c_int(),
        ctypes.c_int(),
    )
    assert not result and api == "none"


@pytest.mark.asyncio
async def test_launch_stream_connection_failure_is_contained(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    class FakeProcess:
        def __init__(self) -> None:
            self.terminated = False
            self.closed = False

        async def connect_streams(self, *args: object) -> None:
            del args
            raise RuntimeError("synthetic pipe failure")

        def terminate(self) -> None:
            self.terminated = True

        def close(self) -> None:
            self.closed = True

    process = FakeProcess()
    status = native.SandboxSecurityStatus(
        native.WindowsContainmentMode.RESTRICTED_TOKEN,
        True,
        True,
        True,
        3,
        True,
        False,
        False,
        "synthetic",
    )
    monkeypatch.setattr(
        native.WindowsRestrictedLauncher,
        "_launch_sync",
        staticmethod(lambda *args: (process, status, 1, 2)),
    )
    with pytest.raises(native.WindowsNativeProcessError, match="Native sandbox IPC setup failed"):
        await native.WindowsRestrictedLauncher.launch(
            "python.exe",
            (),
            cwd="C:\\owned",
            environment={},
            limit=1024,
            job=cast(Any, object()),
        )
    assert process.terminated and process.closed
