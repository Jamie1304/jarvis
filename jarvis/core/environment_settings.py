"""Trusted `.env` configuration read/write service for desktop settings."""

from __future__ import annotations

import os
import tempfile
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from jarvis.core.config import Settings, default_app_data_dir, resolve_environment_file

_SECRET_MARKERS = ("TOKEN", "PASSWORD", "SECRET", "API_KEY", "PRIVATE_KEY", "KEY")
_RESTART_REQUIRED = frozenset(Settings.model_fields) - {"log_level", "log_json"}


@dataclass(frozen=True, slots=True)
class EnvironmentSettingDescriptor:
    """A masked, typed setting view with effective-value provenance."""

    name: str
    value: object
    saved_value: object | None
    source: str
    restart_required: bool
    secret: bool = False
    editable: bool = True


class EnvironmentSettingsService:
    """Load, validate, and atomically persist JARVIS `.env` configuration."""

    def __init__(
        self,
        *,
        project_root: Path | None = None,
        app_data_dir: Path | None = None,
        env_file: Path | None = None,
    ) -> None:
        self._project_root = project_root
        self._app_data_dir = app_data_dir or default_app_data_dir()
        resolved_env_file = env_file or resolve_environment_file(
            project_root=project_root, app_data_dir=self._app_data_dir
        )
        self._env_file: Path = (
            resolved_env_file or (project_root or Path(__file__).resolve().parents[2]) / ".env"
        )

    @property
    def path(self) -> Path:
        return self._env_file

    def descriptors(self) -> tuple[EnvironmentSettingDescriptor, ...]:
        saved = self._saved_values(include_unknown=True)
        effective = Settings(_env_file=self._env_file if self._env_file.exists() else None)
        descriptors: list[EnvironmentSettingDescriptor] = []
        for name in Settings.model_fields:
            environment_key = self._environment_key(name)
            source = (
                "process environment"
                if environment_key in os.environ
                else "env file"
                if environment_key in saved
                else "default"
            )
            secret = self._is_secret(environment_key)
            saved_value = saved.get(environment_key)
            descriptors.append(
                EnvironmentSettingDescriptor(
                    name,
                    self._masked(getattr(effective, name), secret),
                    self._masked(saved_value, secret),
                    source,
                    name in _RESTART_REQUIRED,
                    secret,
                )
            )
        known = {self._environment_key(name) for name in Settings.model_fields}
        unknown_keys = set(saved) | {name for name in os.environ if name.startswith("JARVIS_")}
        for environment_key in sorted(unknown_keys - known):
            if not self._is_secret(environment_key):
                continue
            saved_value = saved.get(environment_key)
            effective_value = os.environ.get(environment_key, saved_value)
            descriptors.append(
                EnvironmentSettingDescriptor(
                    environment_key,
                    self._masked(effective_value, True),
                    self._masked(saved_value, True),
                    "process environment" if environment_key in os.environ else "env file",
                    True,
                    True,
                    False,
                )
            )
        return tuple(descriptors)

    def save(self, updates: dict[str, object]) -> tuple[EnvironmentSettingDescriptor, ...]:
        """Validate all recognized values before atomically replacing the file."""

        if not updates or any(name not in Settings.model_fields for name in updates):
            raise ValueError("Settings update contains an unknown field")
        current = self._saved_values()
        candidate = dict(current)
        for name, value in updates.items():
            environment_key = self._environment_key(name)
            if value is None:
                candidate.pop(environment_key, None)
            else:
                candidate[environment_key] = self._serialize(value)
        typed = {
            name: candidate[self._environment_key(name)]
            for name in Settings.model_fields
            if self._environment_key(name) in candidate
        }
        Settings.model_validate(typed)
        self._atomic_write(self._render(candidate))
        return self.descriptors()

    def reset_to_default(self, name: str) -> tuple[EnvironmentSettingDescriptor, ...]:
        if name not in Settings.model_fields:
            raise ValueError("Setting name is unknown")
        values = self._saved_values()
        values.pop(self._environment_key(name), None)
        self._atomic_write(self._render(values))
        return self.descriptors()

    def _saved_values(self, *, include_unknown: bool = False) -> dict[str, str]:
        values: dict[str, str] = {}
        if not self._env_file.exists():
            return values
        known = {self._environment_key(name) for name in Settings.model_fields}
        for line in self._env_file.read_text(encoding="utf-8").splitlines():
            if "=" not in line or line.lstrip().startswith("#"):
                continue
            key, value = line.split("=", 1)
            if include_unknown or key in known:
                values[key] = value
        return values

    def _render(self, values: dict[str, str]) -> str:
        original = (
            self._env_file.read_text(encoding="utf-8").splitlines()
            if self._env_file.exists()
            else []
        )
        output: list[str] = []
        emitted: set[str] = set()
        known = {self._environment_key(name) for name in Settings.model_fields}
        for line in original:
            key = line.split("=", 1)[0] if "=" in line else ""
            if key in known:
                if key in values:
                    output.append(f"{key}={values[key]}")
                    emitted.add(key)
            else:
                output.append(line)
        output.extend(f"{key}={value}" for key, value in values.items() if key not in emitted)
        return "\n".join(output).rstrip() + "\n"

    def _atomic_write(self, content: str) -> None:
        self._env_file.parent.mkdir(parents=True, exist_ok=True)
        descriptor, temporary = tempfile.mkstemp(prefix=".jarvis-env-", dir=self._env_file.parent)
        try:
            with os.fdopen(descriptor, "w", encoding="utf-8", newline="\n") as handle:
                handle.write(content)
                handle.flush()
                os.fsync(handle.fileno())
            os.replace(temporary, self._env_file)
        finally:
            if os.path.exists(temporary):
                os.unlink(temporary)

    @staticmethod
    def _environment_key(name: str) -> str:
        return f"JARVIS_{name.upper()}"

    @staticmethod
    def _is_secret(environment_key: str) -> bool:
        return any(marker in environment_key for marker in _SECRET_MARKERS)

    @staticmethod
    def _masked(value: Any, secret: bool) -> object:
        return "********" if secret and value not in (None, "") else value

    @staticmethod
    def _serialize(value: object) -> str:
        if isinstance(value, bool):
            return str(value).lower()
        return str(value)
