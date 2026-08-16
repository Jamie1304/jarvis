"""Pre-side-effect validation for the canonical production runtime."""

from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path
from urllib.parse import urlsplit

from jarvis.security.integrity import SECURITY_POLICY_VERSION, RepositoryIntegrityClassifier
from jarvis.security.models import (
    IntegrityClass,
    SecurityViolation,
    SecurityViolationCode,
    StartupSecurityReport,
)


@dataclass(frozen=True, slots=True)
class StartupSecurityConfiguration:
    policy_version: int
    app_data_dir: Path
    project_root: Path
    ai_provider: str
    ai_endpoint: str
    computer_enabled: bool
    camera_enabled: bool
    application_management_enabled: bool
    package_installation_enabled: bool
    voice_enabled: bool
    stt_enabled: bool
    tts_enabled: bool
    multi_agent_enabled: bool
    improvement_enabled: bool
    remote_approval_enabled: bool
    autonomous_scheduling_enabled: bool


class StartupSecurityValidator:
    """Validate compiled v1 policy and requested capabilities before startup I/O."""

    _FLAG_CODES = (
        ("computer_enabled", SecurityViolationCode.UNSUPPORTED_COMPUTER_CONTROL),
        ("camera_enabled", SecurityViolationCode.UNSUPPORTED_CAMERA),
        (
            "application_management_enabled",
            SecurityViolationCode.UNSUPPORTED_APPLICATION_MANAGEMENT,
        ),
        (
            "package_installation_enabled",
            SecurityViolationCode.UNSUPPORTED_PACKAGE_INSTALLATION,
        ),
        ("voice_enabled", SecurityViolationCode.UNSUPPORTED_VOICE),
        ("multi_agent_enabled", SecurityViolationCode.UNSUPPORTED_MULTI_AGENT),
        ("improvement_enabled", SecurityViolationCode.UNSUPPORTED_IMPROVEMENT),
        ("remote_approval_enabled", SecurityViolationCode.REMOTE_APPROVAL_FORBIDDEN),
        (
            "autonomous_scheduling_enabled",
            SecurityViolationCode.AUTONOMOUS_SCHEDULING_FORBIDDEN,
        ),
    )

    def validate(self, config: StartupSecurityConfiguration) -> StartupSecurityReport:
        violations: list[SecurityViolation] = []
        if config.policy_version != SECURITY_POLICY_VERSION:
            violations.append(
                SecurityViolation(
                    SecurityViolationCode.POLICY_VERSION_UNSUPPORTED,
                    "The configured security-policy version is not supported",
                )
            )
        if not self._classification_is_valid():
            violations.append(
                SecurityViolation(
                    SecurityViolationCode.POLICY_CLASSIFICATION_INVALID,
                    "The compiled integrity classification is incomplete",
                )
            )
        for field_name, code in self._FLAG_CODES:
            value = getattr(config, field_name)
            if not isinstance(value, bool) or value:
                violations.append(
                    SecurityViolation(
                        code, "A capability without a trusted production path was enabled"
                    )
                )
        if config.ai_provider.casefold() != "ollama":
            violations.append(
                SecurityViolation(
                    SecurityViolationCode.MODEL_PROVIDER_UNSUPPORTED,
                    "The configured model provider is outside the v1 trusted policy",
                )
            )
        if not local_model_endpoint_is_safe(config.ai_endpoint):
            violations.append(
                SecurityViolation(
                    SecurityViolationCode.MODEL_ENDPOINT_NOT_LOCAL,
                    "The model endpoint must be an unambiguous loopback HTTP endpoint",
                )
            )
        resolved_project_root, resolved_app_data_dir = _validated_runtime_paths(
            config.app_data_dir, config.project_root
        )
        if resolved_app_data_dir is None:
            violations.append(
                SecurityViolation(
                    SecurityViolationCode.APP_DATA_PATH_UNSAFE,
                    "The application-data path is ambiguous or uses an unsafe filesystem object",
                )
            )
        return StartupSecurityReport(
            config.policy_version,
            tuple(violations),
            resolved_app_data_dir,
            resolved_project_root,
        )

    @staticmethod
    def _classification_is_valid() -> bool:
        classifier = RepositoryIntegrityClassifier()
        required = (
            "jarvis/security/integrity.py",
            "jarvis/permissions/broker.py",
            "jarvis/tools/base.py",
            "jarvis/runtime.py",
            "jarvis/api.py",
            "jarvis/improvement/workspace.py",
            "docs/security-constitution.md",
            "scripts/quality.py",
            "pyproject.toml",
        )
        try:
            return all(
                classifier.classify(path).integrity_class is IntegrityClass.TRUSTED_CORE
                for path in required
            )
        except ValueError:
            return False


def local_model_endpoint_is_safe(value: str) -> bool:
    """Accept only one unambiguous literal-loopback Ollama origin."""

    if not isinstance(value, str) or value != value.strip() or len(value) > 512:
        return False
    try:
        parsed = urlsplit(value)
        port = parsed.port
    except ValueError:
        return False
    return bool(
        parsed.scheme == "http"
        and parsed.hostname in {"127.0.0.1", "::1"}
        and parsed.username is None
        and parsed.password is None
        and parsed.query == ""
        and parsed.fragment == ""
        and parsed.path in {"", "/"}
        and (port is None or 1 <= port <= 65535)
    )


_WINDOWS_RESERVED_NAMES = frozenset(
    {
        "aux",
        "clock$",
        "con",
        "conin$",
        "conout$",
        "nul",
        "prn",
        *(f"com{index}" for index in range(1, 10)),
        *(f"lpt{index}" for index in range(1, 10)),
    }
)
_WINDOWS_INVALID_PRINTABLE = frozenset('<>"|?*')


def _validated_runtime_paths(value: Path, project_root: Path) -> tuple[Path | None, Path | None]:
    """Return canonical trusted paths after lexical and existing-object checks."""

    if not _path_text_is_safe(project_root) or not project_root.is_absolute():
        return None, None
    if not _existing_path_chain_is_safe(project_root):
        return None, None
    try:
        resolved_project = project_root.resolve(strict=True)
    except (OSError, RuntimeError):
        return None, None
    if not resolved_project.is_dir() or _is_filesystem_root(resolved_project):
        return None, None

    default_root = value == Path(".jarvis")
    if not default_root and not value.is_absolute():
        return resolved_project, None
    candidate = resolved_project / ".jarvis" if default_root else value
    if not _path_text_is_safe(candidate) or not _existing_path_chain_is_safe(candidate):
        return resolved_project, None
    try:
        resolved = candidate.resolve(strict=False)
    except (OSError, RuntimeError):
        return resolved_project, None
    if (
        _is_filesystem_root(resolved)
        or not _path_text_is_safe(resolved)
        or (resolved.exists() and not resolved.is_dir())
    ):
        return resolved_project, None

    approved_project_data = resolved_project / ".jarvis"
    if _paths_overlap(resolved, resolved_project) and resolved != approved_project_data:
        return resolved_project, None
    git_metadata = resolved_project / ".git"
    if git_metadata.exists() and _paths_overlap(resolved, git_metadata):
        return resolved_project, None
    return resolved_project, resolved


def _path_text_is_safe(value: Path) -> bool:
    raw = os.fspath(value)
    normalized_slashes = raw.replace("\\", "/")
    if (
        not raw
        or any(ord(character) < 32 for character in raw)
        or any(character in _WINDOWS_INVALID_PRINTABLE for character in raw)
        or raw.startswith("~")
        or normalized_slashes.startswith("//")
    ):
        return False
    colon_offsets = tuple(index for index, character in enumerate(raw) if character == ":")
    if colon_offsets and not (
        len(colon_offsets) == 1 and colon_offsets[0] == 1 and raw[0].isalpha()
    ):
        return False
    path_without_drive = normalized_slashes[2:] if colon_offsets else normalized_slashes
    for part in (item for item in path_without_drive.split("/") if item):
        stem = part.split(".", 1)[0].casefold()
        if part in {".", ".."} or part.endswith((" ", ".")) or stem in _WINDOWS_RESERVED_NAMES:
            return False
    return True


def _existing_path_chain_is_safe(value: Path) -> bool:
    """Inspect lexical ancestors without resolving away links or junctions."""

    if not value.is_absolute():
        return False
    anchor = Path(value.anchor)
    current = anchor
    try:
        for part in value.parts[1:]:
            current /= part
            if current.is_symlink() or current.is_junction():
                return False
            if not current.exists():
                return True
            if current != value and not current.is_dir():
                return False
        return not value.exists() or value.is_dir()
    except OSError:
        return False


def _is_filesystem_root(value: Path) -> bool:
    return value.parent == value


def _paths_overlap(first: Path, second: Path) -> bool:
    try:
        common = Path(os.path.commonpath((os.fspath(first), os.fspath(second))))
    except ValueError:
        return False
    return common in {first, second}
