"""Inventory and package-provider abstractions for managed applications."""

from __future__ import annotations

import asyncio
import hashlib
import json
import os
import re
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
                            )
                        }
                    name = values["DisplayName"]
                    if not name:
                        continue
                    digest_input = f"{hive}:{view}:{key_path}:{subkey_name}"
                    digest = hashlib.sha256(digest_input.encode()).hexdigest()
                    stable = f"registry:{digest[:24]}"
                    executable = WindowsRegistryInventoryProvider._safe_executable(
                        values["DisplayIcon"]
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


class WingetPackageProvider(PackageProvider):  # pragma: no cover
    """Optional package provider with a trusted candidate catalog and no shell strings."""

    def __init__(self, candidates: Iterable[InstallationCandidate]) -> None:
        self._candidates = tuple(candidates)
        for candidate in self._candidates:
            if candidate.source.casefold() != "winget":
                raise ValueError("Winget provider candidates must use the winget source")
            self._validate_candidate(candidate)

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
                "winget.exe",
                *arguments,
                stdin=asyncio.subprocess.DEVNULL,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
        except OSError as error:
            raise PackageOperationError("Windows package manager is unavailable") from error
        wait_task = asyncio.create_task(process.communicate())
        cancelled_task = asyncio.create_task(cancellation.wait())
        try:
            done, _ = await asyncio.wait(
                {wait_task, cancelled_task}, return_when=asyncio.FIRST_COMPLETED
            )
            if cancelled_task in done:
                if process.returncode is None:
                    process.terminate()
                await wait_task
                raise asyncio.CancelledError
            _, stderr = await wait_task
            if process.returncode != 0:
                detail = stderr.decode("utf-8", errors="replace")[:512]
                raise PackageOperationError(f"Package manager failed: {detail}")
        except asyncio.CancelledError:
            if process.returncode is None:
                process.terminate()
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
