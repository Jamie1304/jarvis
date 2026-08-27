"""Pre-side-effect validation for the canonical production runtime."""

from __future__ import annotations

import base64
import csv
import hashlib
import io
import os
from collections.abc import Callable
from dataclasses import dataclass
from importlib import metadata, resources
from pathlib import Path
from urllib.parse import urlsplit

from jarvis.security.integrity import (
    SECURITY_POLICY_VERSION,
    RepositoryIntegrityClassifier,
    normalize_repository_path,
)
from jarvis.security.models import (
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
    ai_provider_local_only: bool = True


class IntegrityEvidenceError(ValueError):
    """Trusted startup evidence is missing, malformed, or inconsistent."""


class IntegrityEvidenceProvider:
    """Provide integrity evidence for one explicit composition context."""

    def validate(self) -> None:
        raise NotImplementedError


_SOURCE_INTEGRITY_FILES = (
    "jarvis/api.py",
    "jarvis/improvement/workspace.py",
    "jarvis/permissions/broker.py",
    "jarvis/recovery.py",
    "jarvis/runtime.py",
    "jarvis/security/integrity.py",
    "jarvis/security/startup.py",
    "jarvis/tools/base.py",
    "docs/security-constitution.md",
    "scripts/quality.py",
    "pyproject.toml",
)
_INSTALLED_INTEGRITY_FILES = (
    "jarvis/api.py",
    "jarvis/improvement/workspace.py",
    "jarvis/permissions/broker.py",
    "jarvis/recovery.py",
    "jarvis/runtime.py",
    "jarvis/security/integrity.py",
    "jarvis/security/startup.py",
    "jarvis/tools/base.py",
)


class SourceCheckoutIntegrityEvidenceProvider(IntegrityEvidenceProvider):
    """Validate repository evidence used by source and CI composition."""

    def __init__(self, root: Path) -> None:
        if not isinstance(root, Path):
            raise ValueError("Source integrity root is invalid")
        self._root = root

    def validate(self) -> None:
        try:
            root = self._root.expanduser().resolve(strict=True)
        except (OSError, RuntimeError) as error:
            raise IntegrityEvidenceError("source integrity root is unavailable") from error
        if not root.is_dir() or root.is_symlink() or root.is_junction():
            raise IntegrityEvidenceError("source integrity root is unsafe")
        classifier = RepositoryIntegrityClassifier()
        for relative in _SOURCE_INTEGRITY_FILES:
            normalized = normalize_repository_path(relative)
            path = root.joinpath(*normalized.split("/"))
            try:
                resolved = path.resolve(strict=True)
            except (OSError, RuntimeError) as error:
                raise IntegrityEvidenceError(
                    f"source integrity evidence is missing: {normalized}"
                ) from error
            if (
                not resolved.is_file()
                or path.is_symlink()
                or path.is_junction()
                or not resolved.is_relative_to(root)
                or _has_reparse_ancestor(path, root)
            ):
                raise IntegrityEvidenceError(f"source integrity evidence is unsafe: {normalized}")
            try:
                classified = classifier.classify(normalized)
            except ValueError as error:
                raise IntegrityEvidenceError(
                    f"source integrity evidence is not classifiable: {normalized}"
                ) from error
            if classified.integrity_class.value != "trusted_core":
                raise IntegrityEvidenceError(
                    f"source integrity evidence is not trusted core: {normalized}"
                )


class InstalledDistributionIntegrityEvidenceProvider(IntegrityEvidenceProvider):
    """Validate immutable evidence that exists in an installed distribution.

    Package resources and ``RECORD`` establish installed-file consistency and
    completeness.  They do not authenticate the publisher; release signing
    and the recovery/update authority remain separate controls.
    """

    def __init__(
        self,
        distribution_loader: Callable[[str], metadata.Distribution] | None = None,
    ) -> None:
        self._distribution_loader = distribution_loader or metadata.distribution

    def validate(self) -> None:
        try:
            distribution = self._distribution_loader("jarvis")
            if distribution.version != _package_version():
                raise IntegrityEvidenceError("installed package version is inconsistent")
            files = distribution.files
            if files is None:
                raise IntegrityEvidenceError("installed package file inventory is unavailable")
            file_names = {path.as_posix() for path in files}
            if not any(name.endswith(".dist-info/RECORD") for name in file_names):
                raise IntegrityEvidenceError("installed package RECORD is missing")
            record_text = distribution.read_text("RECORD")
            if not isinstance(record_text, str):
                raise IntegrityEvidenceError("installed package RECORD is unreadable")
            record = _record_hashes(record_text)
            package_root = resources.files("jarvis")
            for relative in _INSTALLED_INTEGRITY_FILES:
                package_path = relative.removeprefix("jarvis/")
                resource = package_root.joinpath(*package_path.split("/"))
                if not resource.is_file():
                    raise IntegrityEvidenceError(
                        f"installed integrity resource is missing: {relative}"
                    )
                if relative not in file_names:
                    raise IntegrityEvidenceError(
                        f"installed integrity resource is absent from RECORD: {relative}"
                    )
                expected_hash, expected_size = record.get(relative, (None, None))
                if expected_hash is None or expected_size is None:
                    raise IntegrityEvidenceError(
                        f"installed integrity resource has no RECORD hash: {relative}"
                    )
                content = resource.read_bytes()
                actual_hash = (
                    base64.urlsafe_b64encode(hashlib.sha256(content).digest())
                    .rstrip(b"=")
                    .decode("ascii")
                )
                if actual_hash != expected_hash or len(content) != expected_size:
                    raise IntegrityEvidenceError(
                        f"installed integrity resource failed RECORD validation: {relative}"
                    )
        except IntegrityEvidenceError:
            raise
        except (ImportError, KeyError, OSError, TypeError, ValueError) as error:
            raise IntegrityEvidenceError("installed integrity evidence is malformed") from error


def _record_hashes(value: str) -> dict[str, tuple[str | None, int | None]]:
    """Parse the CSV RECORD inventory for required package members."""

    result: dict[str, tuple[str | None, int | None]] = {}
    try:
        rows = csv.reader(io.StringIO(value, newline=""))
        for row in rows:
            if len(row) != 3 or not row[0] or row[0] in result:
                raise IntegrityEvidenceError("installed package RECORD is malformed")
            digest = row[1]
            if not digest.startswith("sha256="):
                result[row[0]] = (None, None)
            else:
                encoded = digest.removeprefix("sha256=")
                if not encoded:
                    raise IntegrityEvidenceError("installed package RECORD hash is malformed")
                size = int(row[2])
                if size < 0:
                    raise IntegrityEvidenceError("installed package RECORD size is malformed")
                result[row[0]] = (encoded, size)
    except (csv.Error, ValueError) as error:
        raise IntegrityEvidenceError("installed package RECORD is malformed") from error
    return result


def _package_version() -> str:
    """Resolve version from the package itself, never from the repository."""

    from jarvis.version import __version__

    return __version__


def _has_reparse_ancestor(path: Path, root: Path) -> bool:
    """Reject symlink/junction components between a checkout root and file."""

    current = path
    while current != root:
        if current.is_symlink() or current.is_junction():
            return True
        current = current.parent
    return root.is_symlink() or root.is_junction()


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

    def __init__(self, integrity_evidence: IntegrityEvidenceProvider | None = None) -> None:
        if integrity_evidence is not None and not isinstance(
            integrity_evidence, IntegrityEvidenceProvider
        ):
            raise ValueError("Integrity evidence provider is invalid")
        self._integrity_evidence = integrity_evidence

    def validate(self, config: StartupSecurityConfiguration) -> StartupSecurityReport:
        violations: list[SecurityViolation] = []
        if config.policy_version != SECURITY_POLICY_VERSION:
            violations.append(
                SecurityViolation(
                    SecurityViolationCode.POLICY_VERSION_UNSUPPORTED,
                    "The configured security-policy version is not supported",
                )
            )
        evidence = self._integrity_evidence or SourceCheckoutIntegrityEvidenceProvider(
            Path(__file__).resolve().parents[2]
        )
        try:
            evidence.validate()
        except IntegrityEvidenceError:
            violations.append(
                SecurityViolation(
                    SecurityViolationCode.POLICY_CLASSIFICATION_INVALID,
                    "Trusted integrity evidence is unavailable or inconsistent",
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
        if config.ai_provider.casefold() != "ollama" and not config.ai_provider_local_only:
            violations.append(
                SecurityViolation(
                    SecurityViolationCode.MODEL_PROVIDER_UNSUPPORTED,
                    "The configured model provider is not declared local-only by the "
                    "trusted provider registry",
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
