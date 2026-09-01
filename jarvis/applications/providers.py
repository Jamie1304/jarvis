"""Inventory and package-provider abstractions for managed applications."""

from __future__ import annotations

import asyncio
import hashlib
import json
import os
import re
import shutil
import sys
from abc import ABC, abstractmethod
from collections.abc import Iterable
from pathlib import Path
from typing import Any

from jarvis.applications.models import (
    ApplicationRecord,
    ApplicationStatus,
    InstallationCandidate,
    PackageOperationError,
)
from jarvis.computer.process import (
    ProcessIdentityError,
    resolve_trusted_executable,
    trusted_process_environment,
)

_PACKAGE_TOKEN = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$")
_VERSION_TOKEN = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._+-]{0,63}$")


class ApplicationInventoryProvider(ABC):
    """Read installed application evidence without granting lifecycle authority."""

    @abstractmethod
    async def enumerate_installed(self) -> tuple[ApplicationRecord, ...]:
        """Return normalized current inventory evidence."""


class PackageProvider(ABC):
    """Repository-specific candidate selection and fixed package operations."""

    @abstractmethod
    async def search(self, semantic_name: str) -> tuple[InstallationCandidate, ...]:
        """Return trusted provider candidates; this must not install anything."""

    @abstractmethod
    async def find_update(self, record: ApplicationRecord) -> InstallationCandidate | None:
        """Return a provider-issued update candidate for one installed application."""

    @abstractmethod
    async def install(self, candidate: InstallationCandidate, cancellation: asyncio.Event) -> None:
        """Install exactly the provider-issued candidate."""

    @abstractmethod
    async def update(self, candidate: InstallationCandidate, cancellation: asyncio.Event) -> None:
        """Update exactly the provider-issued candidate."""


class WindowsRegistryInventoryProvider(ApplicationInventoryProvider):  # pragma: no cover
    """Read normal Windows uninstall registry entries and safely expose executable evidence."""

    async def enumerate_installed(self) -> tuple[ApplicationRecord, ...]:
        if sys.platform != "win32":
            raise PackageOperationError("Windows application inventory is unavailable on this host")
        return await asyncio.to_thread(self._enumerate)

    @staticmethod
    def _enumerate() -> tuple[ApplicationRecord, ...]:
        import winreg

        locations = (
            (winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall", 0),
            (
                winreg.HKEY_LOCAL_MACHINE,
                r"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall",
                winreg.KEY_WOW64_32KEY,
            ),
            (winreg.HKEY_CURRENT_USER, r"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall", 0),
        )
        records: dict[str, ApplicationRecord] = {}
        for hive, key_path, view in locations:
            try:
                root = winreg.OpenKey(hive, key_path, 0, winreg.KEY_READ | view)
            except OSError:
                continue
            with root:
                index = 0
                while True:
                    try:
                        subkey_name = winreg.EnumKey(root, index)
                    except OSError:
                        break
                    index += 1
                    try:
                        subkey = winreg.OpenKey(root, subkey_name, 0, winreg.KEY_READ | view)
                    except OSError:
                        continue
                    with subkey:
                        values = {
                            name: WindowsRegistryInventoryProvider._value(subkey, name)
                            for name in (
                                "DisplayName",
                                "DisplayVersion",
                                "Publisher",
                                "DisplayIcon",
                                "InstallLocation",
                                "UninstallString",
                            )
                        }
                    name = values["DisplayName"]
                    if not name:
                        continue
                    digest_input = f"{hive}:{view}:{key_path}:{subkey_name}"
                    digest = hashlib.sha256(digest_input.encode()).hexdigest()
                    stable = f"registry:{digest[:24]}"
                    executable = WindowsRegistryInventoryProvider._launch_evidence(
                        values["DisplayIcon"],
                        values["InstallLocation"],
                        values["UninstallString"],
                    )
                    status = (
                        ApplicationStatus.INSTALLED
                        if executable is not None
                        else ApplicationStatus.BROKEN
                    )
                    records[stable] = ApplicationRecord(
                        stable,
                        name,
                        values["DisplayVersion"],
                        values["Publisher"],
                        executable,
                        "windows-registry",
                        status,
                    )
        return tuple(
            sorted(
                records.values(),
                key=lambda record: (record.name.casefold(), record.application_id),
            )
        )

    @staticmethod
    def _value(key: Any, name: str) -> str | None:
        import winreg

        try:
            value, _ = winreg.QueryValueEx(key, name)
        except OSError:
            return None
        return value if isinstance(value, str) and value.strip() else None

    @staticmethod
    def _safe_executable(display_icon: str | None) -> str | None:
        if not display_icon:
            return None
        path_text = display_icon.split(",", maxsplit=1)[0].strip().strip('"')
        try:
            path = Path(path_text).resolve(strict=True)
        except OSError:
            return None
        if not path.is_file() or path.suffix.casefold() != ".exe":
            return None
        return os.path.normcase(os.fspath(path))

    @classmethod
    def _launch_evidence(
        cls,
        display_icon: str | None,
        install_location: str | None,
        uninstall_string: str | None,
    ) -> str | None:
        """Use read-only registry evidence; never infer a path from a display name."""

        for candidate in (display_icon, uninstall_string):
            executable = cls._safe_executable(candidate)
            if executable is not None:
                return executable
        if not install_location:
            return None
        try:
            location = Path(install_location).resolve(strict=True)
        except OSError:
            return None
        if not location.is_dir():
            return None
        # A lone root executable is evidence; selecting among multiple files would
        # be an unsafe guess and remains BROKEN until a reviewed catalog resolves it.
        executables = tuple(location.glob("*.exe"))
        if len(executables) != 1:
            return None
        return cls._safe_executable(str(executables[0]))


class WingetPackageProvider(PackageProvider):  # pragma: no cover
    """Optional package provider with a trusted candidate catalog and no shell strings."""

    def __init__(
        self,
        candidates: Iterable[InstallationCandidate],
        *,
        executable: str | None = None,
        timeout_seconds: float = 300.0,
    ) -> None:
        self._candidates = tuple(candidates)
        if (
            type(timeout_seconds) not in {int, float}
            or isinstance(timeout_seconds, bool)
            or not 0 < timeout_seconds <= 1_800
        ):
            raise ValueError("Winget timeout is outside the safe bound")
        if executable is None:
            self._executable = None
        else:
            try:
                self._executable = resolve_trusted_executable(executable)
            except (OSError, RuntimeError, ProcessIdentityError) as error:
                raise ValueError("Winget executable must be an absolute regular file") from error
        self._timeout_seconds = float(timeout_seconds)
        for candidate in self._candidates:
            if candidate.source.casefold() != "winget":
                raise ValueError("Winget provider candidates must use the winget source")
            self._validate_candidate(candidate)

    @staticmethod
    async def available() -> bool:
        """Read-only availability check; it does not query, install, or update packages."""

        return (
            sys.platform == "win32"
            and await asyncio.to_thread(shutil.which, "winget.exe") is not None
        )

    async def search(self, semantic_name: str) -> tuple[InstallationCandidate, ...]:
        query = semantic_name.casefold().strip()
        return tuple(
            candidate
            for candidate in self._candidates
            if query in candidate.name.casefold() or query == candidate.package_id.casefold()
        )

    async def find_update(self, record: ApplicationRecord) -> InstallationCandidate | None:
        matches = [
            candidate
            for candidate in self._candidates
            if candidate.verification.application_name.casefold() == record.name.casefold()
            and (
                candidate.verification.publisher is None
                or candidate.verification.publisher.casefold()
                == (record.publisher or "").casefold()
            )
        ]
        return matches[0] if len(matches) == 1 else None

    async def install(self, candidate: InstallationCandidate, cancellation: asyncio.Event) -> None:
        await self._run("install", candidate, cancellation)

    async def update(self, candidate: InstallationCandidate, cancellation: asyncio.Event) -> None:
        await self._run("upgrade", candidate, cancellation)

    async def _run(
        self, operation: str, candidate: InstallationCandidate, cancellation: asyncio.Event
    ) -> None:
        self._validate_candidate(candidate)
        if candidate not in self._candidates:
            raise PackageOperationError("Package candidate was not issued by this provider")
        if self._executable is None:
            raise PackageOperationError(
                "Winget executable must be explicitly configured with a trusted file identity"
            )
        arguments = (
            operation,
            "--id",
            candidate.package_id,
            "--exact",
            "--source",
            candidate.source,
            "--version",
            candidate.version,
            "--accept-source-agreements",
            "--accept-package-agreements",
            "--disable-interactivity",
        )
        try:
            process = await asyncio.create_subprocess_exec(
                os.fspath(self._executable),
                *arguments,
                stdin=asyncio.subprocess.DEVNULL,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
                env=trusted_process_environment(),
            )
        except OSError as error:
            raise PackageOperationError("Windows package manager is unavailable") from error
        wait_task = asyncio.create_task(process.communicate())
        cancelled_task = asyncio.create_task(cancellation.wait())
        try:
            done, _ = await asyncio.wait(
                {wait_task, cancelled_task},
                timeout=self._timeout_seconds,
                return_when=asyncio.FIRST_COMPLETED,
            )
            if cancelled_task in done:
                if process.returncode is None:
                    process.kill()
                await wait_task
                raise asyncio.CancelledError
            if wait_task not in done:
                if process.returncode is None:
                    process.kill()
                await wait_task
                raise PackageOperationError("Windows package manager timed out")
            _, stderr = await wait_task
            if process.returncode != 0:
                detail = stderr.decode("utf-8", errors="replace")[:512]
                raise PackageOperationError(f"Package manager failed: {detail}")
        except asyncio.CancelledError:
            if process.returncode is None:
                process.kill()
            await asyncio.gather(wait_task, return_exceptions=True)
            raise
        finally:
            for task in (wait_task, cancelled_task):
                if not task.done():
                    task.cancel()
            await asyncio.gather(wait_task, cancelled_task, return_exceptions=True)

    @staticmethod
    def _validate_candidate(candidate: InstallationCandidate) -> None:
        if (
            not _PACKAGE_TOKEN.fullmatch(candidate.package_id)
            or not _PACKAGE_TOKEN.fullmatch(candidate.source)
            or not _VERSION_TOKEN.fullmatch(candidate.version)
        ):
            raise PackageOperationError("Package identity, source, or version is malformed")
        json.dumps(
            {
                "id": candidate.package_id,
                "source": candidate.source,
                "version": candidate.version,
            },
            ensure_ascii=True,
        )
