"""Narrow runtime boundary for launches and tracked closes of managed applications."""

import asyncio
import os
import subprocess
import sys
from abc import ABC, abstractmethod

from jarvis.applications.models import ApplicationManagerError, ApplicationRecord
from jarvis.computer.models import LaunchInfo
from jarvis.computer.process import (
    ProcessIdentityError,
    resolve_trusted_executable,
    trusted_process_environment,
)


class ApplicationRuntime(ABC):
    """Launch only records resolved by ApplicationManager, never a caller path."""

    @abstractmethod
    async def can_launch(self, record: ApplicationRecord) -> bool:
        """Check launch capability without starting a process."""

    @abstractmethod
    async def launch(self, record: ApplicationRecord) -> LaunchInfo:
        """Start the verified executable associated with a resolved record."""

    @abstractmethod
    async def close(self, application_id: str, process_id: int) -> None:
        """Close only a process previously launched by this runtime."""


class WindowsApplicationRuntime(ApplicationRuntime):  # pragma: no cover
    """Windows process runtime with argument vectors and an owned-process table."""

    def __init__(self) -> None:
        self._processes: dict[tuple[str, int], subprocess.Popen[bytes]] = {}

    async def can_launch(self, record: ApplicationRecord) -> bool:
        return self._valid_executable(record.executable_path)

    async def launch(self, record: ApplicationRecord) -> LaunchInfo:
        if sys.platform != "win32":
            raise ApplicationManagerError("Managed application runtime is Windows-only")
        executable = self._resolved_executable(record)
        try:
            process = await asyncio.to_thread(
                subprocess.Popen,
                [executable],
                shell=False,
                stdin=subprocess.DEVNULL,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                env=trusted_process_environment(),
            )
        except OSError as error:
            raise ApplicationManagerError("Managed application could not be launched") from error
        self._processes[(record.application_id, process.pid)] = process
        return LaunchInfo(record.application_id, process.pid)

    async def close(self, application_id: str, process_id: int) -> None:
        try:
            process = self._processes.pop((application_id, process_id))
        except KeyError as error:
            raise ApplicationManagerError("Process is not owned by the managed runtime") from error
        if process.poll() is None:
            process.terminate()
            try:
                await asyncio.wait_for(asyncio.to_thread(process.wait), timeout=5)
            except TimeoutError:
                process.kill()
                await asyncio.to_thread(process.wait)

    @staticmethod
    def _valid_executable(value: str | None) -> bool:
        if value is None:
            return False
        try:
            path = resolve_trusted_executable(value)
        except (OSError, ProcessIdentityError):
            return False
        return path.is_file()

    def _resolved_executable(self, record: ApplicationRecord) -> str:
        if not self._valid_executable(record.executable_path):
            raise ApplicationManagerError("Managed application executable is unavailable")
        assert record.executable_path is not None
        try:
            return os.fspath(resolve_trusted_executable(record.executable_path))
        except ProcessIdentityError as error:
            raise ApplicationManagerError("Managed application executable is ambiguous") from error
