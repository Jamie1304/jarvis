"""Shared process identity and environment rules for generic host primitives."""

from __future__ import annotations

import os
from pathlib import Path


class ProcessIdentityError(ValueError):
    """A configured executable is not a stable, trusted file identity."""


def resolve_trusted_executable(value: str) -> Path:
    """Resolve an absolute regular executable without following an ambiguous link."""

    if not isinstance(value, str) or not value:
        raise ProcessIdentityError("Executable identity is missing")
    path = Path(value)
    if not path.is_absolute() or path.is_symlink() or path.is_junction():
        raise ProcessIdentityError("Executable identity must be an absolute regular path")
    try:
        resolved = path.resolve(strict=True)
    except (OSError, RuntimeError) as error:
        raise ProcessIdentityError("Executable identity is unavailable") from error
    if (
        not resolved.is_file()
        or path.is_junction()
        or os.path.normcase(os.fspath(resolved)) != os.path.normcase(os.fspath(path))
    ):
        raise ProcessIdentityError("Executable identity changed or is ambiguous")
    return resolved


def trusted_process_environment() -> dict[str, str]:
    """Return a minimal environment without credentials, hooks, or PATH lookup."""

    allowed = (
        "SYSTEMROOT",
        "WINDIR",
        "SYSTEMDRIVE",
        "TEMP",
        "TMP",
        "LOCALAPPDATA",
        "PROGRAMDATA",
    )
    environment = {name: os.environ[name] for name in allowed if name in os.environ}
    environment["PYTHONIOENCODING"] = "utf-8"
    environment["PYTHONUTF8"] = "1"
    return environment
