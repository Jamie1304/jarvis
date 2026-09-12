"""Pre-side-effect validation for the canonical production runtime."""

from __future__ import annotations

import base64
import csv
import hashlib
import io
import os
import re
from collections.abc import Callable
from dataclasses import dataclass
from email.parser import Parser
from importlib import metadata
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
    """Validate the complete installed JARVIS wheel inventory against ``RECORD``.

    This is an installed-file consistency check, not a publisher-authentication
    mechanism: an attacker who can coherently replace both a member and RECORD
    still requires the separate update/recovery trust controls to be stopped.
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
            layout = _installed_distribution_layout(distribution, _package_version())
            record = _parse_installed_record(layout.record_path.read_text(encoding="utf-8"))
            _validate_installed_record_layout(record, layout)
            actual = _installed_distribution_files(layout)
            _validate_installed_record_members(record, actual, layout)
        except IntegrityEvidenceError:
            raise
        except (ImportError, KeyError, OSError, TypeError, ValueError, UnicodeError) as error:
            raise IntegrityEvidenceError("installed integrity evidence is malformed") from error


@dataclass(frozen=True, slots=True)
class _InstalledRecordEntry:
    """One strictly parsed member of the installed wheel RECORD."""

    original_path: str
    normalized_path: str
    digest: str | None
    size: int | None


@dataclass(frozen=True, slots=True)
class _InstalledDistributionLayout:
    """Canonical physical locations for the installed JARVIS distribution."""

    site_packages_root: Path
    package_root: Path
    dist_info_root: Path
    record_path: Path
    dist_info_name: str


def _installed_distribution_layout(
    distribution: metadata.Distribution,
    package_version: str,
) -> _InstalledDistributionLayout:
    """Resolve one unambiguous, non-reparse installed JARVIS distribution."""

    root = Path(str(distribution.locate_file("")))
    try:
        site_packages_root = root.resolve(strict=True)
    except (OSError, RuntimeError) as error:
        raise IntegrityEvidenceError("installed package root is unavailable") from error
    if (
        not site_packages_root.is_dir()
        or _is_reparse_point(site_packages_root)
        or _has_reparse_ancestor(site_packages_root, site_packages_root)
    ):
        raise IntegrityEvidenceError("installed package root is unsafe")

    package_candidates = [
        child
        for child in _safe_directory_children(site_packages_root)
        if child.name.casefold() == "jarvis"
    ]
    if len(package_candidates) != 1 or package_candidates[0].name != "jarvis":
        raise IntegrityEvidenceError("installed package directory is ambiguous")
    package_root = package_candidates[0]
    if not package_root.is_dir():
        raise IntegrityEvidenceError("installed package directory is invalid")

    matching_dist_infos: list[Path] = []
    for child in _safe_directory_children(site_packages_root):
        if not child.name.casefold().endswith(".dist-info"):
            continue
        metadata_path = child / "METADATA"
        if not _safe_regular_file(metadata_path, child):
            continue
        try:
            package_metadata = Parser().parsestr(metadata_path.read_text(encoding="utf-8"))
        except (OSError, UnicodeError) as error:
            raise IntegrityEvidenceError("installed package METADATA is unreadable") from error
        name = package_metadata.get("Name")
        version = package_metadata.get("Version")
        if (
            name is not None
            and name.casefold().replace("-", "_") == "jarvis"
            and version == package_version
        ):
            matching_dist_infos.append(child)
    if len(matching_dist_infos) != 1:
        raise IntegrityEvidenceError("installed package dist-info is ambiguous")
    dist_info_root = matching_dist_infos[0]
    record_path = dist_info_root / "RECORD"
    if not _safe_regular_file(record_path, dist_info_root):
        raise IntegrityEvidenceError("installed package RECORD is missing or unsafe")
    return _InstalledDistributionLayout(
        site_packages_root=site_packages_root,
        package_root=package_root,
        dist_info_root=dist_info_root,
        record_path=record_path,
        dist_info_name=dist_info_root.name,
    )


def _parse_installed_record(value: str) -> dict[str, _InstalledRecordEntry]:
    """Parse canonical RECORD rows without accepting lossy or ambiguous forms."""

    result: dict[str, _InstalledRecordEntry] = {}
    try:
        rows = csv.reader(io.StringIO(value, newline=""))
        for row in rows:
            if len(row) != 3:
                raise IntegrityEvidenceError("installed package RECORD is malformed")
            normalized = _normalize_installed_record_path(row[0])
            comparison_key = normalized.casefold()
            if comparison_key in result:
                raise IntegrityEvidenceError("installed package RECORD has duplicate paths")
            digest, size = _parse_installed_record_integrity(row[1], row[2])
            result[comparison_key] = _InstalledRecordEntry(
                original_path=row[0],
                normalized_path=normalized,
                digest=digest,
                size=size,
            )
    except (csv.Error, ValueError) as error:
        raise IntegrityEvidenceError("installed package RECORD is malformed") from error
    if not result:
        raise IntegrityEvidenceError("installed package RECORD is empty")
    return result


def _parse_installed_record_integrity(value: str, size_value: str) -> tuple[str | None, int | None]:
    """Require SHA-256 plus size for ordinary files and blank both for exceptions."""

    if not value and not size_value:
        return None, None
    if not value or not size_value or not value.startswith("sha256="):
        raise IntegrityEvidenceError("installed package RECORD integrity fields are malformed")
    encoded_digest = value.removeprefix("sha256=")
    if (
        not encoded_digest
        or "=" in encoded_digest
        or not re.fullmatch(r"[A-Za-z0-9_-]+", encoded_digest)
    ):
        raise IntegrityEvidenceError("installed package RECORD hash is malformed")
    try:
        decoded = base64.urlsafe_b64decode(encoded_digest + "=" * (-len(encoded_digest) % 4))
    except (ValueError, UnicodeError) as error:
        raise IntegrityEvidenceError("installed package RECORD hash is malformed") from error
    if len(decoded) != hashlib.sha256().digest_size:
        raise IntegrityEvidenceError("installed package RECORD hash is malformed")
    if not size_value.isdecimal():
        raise IntegrityEvidenceError("installed package RECORD size is malformed")
    size = int(size_value)
    if size < 0:
        raise IntegrityEvidenceError("installed package RECORD size is malformed")
    return encoded_digest, size


def _normalize_installed_record_path(value: str) -> str:
    """Normalize the Windows-permitted RECORD separator form, rejecting escapes."""

    if not value or len(value) > 1024 or any(ord(character) < 32 for character in value):
        raise IntegrityEvidenceError("installed package RECORD path is malformed")
    normalized = value.replace("\\", "/")
    if (
        normalized.startswith("/")
        or normalized.startswith("//")
        or re.match(r"^[A-Za-z]:", normalized) is not None
        or ":" in normalized
    ):
        raise IntegrityEvidenceError("installed package RECORD path is unsafe")
    parts = normalized.split("/")
    if any(not part or part in {".", ".."} for part in parts):
        raise IntegrityEvidenceError("installed package RECORD path is unsafe")
    for part in parts:
        stem = part.split(".", 1)[0].casefold()
        if (
            part != part.strip()
            or part.endswith((" ", "."))
            or any(character in _WINDOWS_INVALID_PRINTABLE for character in part)
            or stem in _WINDOWS_RESERVED_NAMES
        ):
            raise IntegrityEvidenceError("installed package RECORD path is unsafe")
    return "/".join(parts)


def _validate_installed_record_layout(
    record: dict[str, _InstalledRecordEntry],
    layout: _InstalledDistributionLayout,
) -> None:
    """Restrict RECORD to the exact JARVIS package and its dist-info tree."""

    record_path = f"{layout.dist_info_name}/RECORD"
    self_entry = record.get(record_path.casefold())
    if (
        self_entry is None
        or self_entry.normalized_path != record_path
        or self_entry.digest is not None
        or self_entry.size is not None
    ):
        raise IntegrityEvidenceError("installed package RECORD self-entry is invalid")
    allowed_prefixes = ("jarvis/", f"{layout.dist_info_name}/")
    for entry in record.values():
        if not entry.normalized_path.startswith(allowed_prefixes):
            raise IntegrityEvidenceError("installed package RECORD references an external path")


def _installed_distribution_files(layout: _InstalledDistributionLayout) -> dict[str, Path]:
    """Inventory actual package/dist-info files independently from RECORD."""

    result: dict[str, Path] = {}
    for root in (layout.package_root, layout.dist_info_root):
        for path in _safe_tree_files(root):
            relative = path.relative_to(layout.site_packages_root).as_posix()
            normalized = _normalize_installed_record_path(relative)
            key = normalized.casefold()
            if key in result:
                raise IntegrityEvidenceError("installed package filesystem is ambiguous")
            result[key] = path
    return result


def _validate_installed_record_members(
    record: dict[str, _InstalledRecordEntry],
    actual: dict[str, Path],
    layout: _InstalledDistributionLayout,
) -> None:
    """Enforce exact non-pyc inventory and bounded optional Python bytecode."""

    record_self_key = f"{layout.dist_info_name}/RECORD".casefold()
    for key, entry in record.items():
        if key == record_self_key:
            continue
        path = actual.get(key)
        if path is None:
            if _is_optional_recorded_pyc(entry.normalized_path, record):
                continue
            raise IntegrityEvidenceError("installed package RECORD member is missing")
        if entry.digest is None or entry.size is None:
            if _is_optional_recorded_pyc(entry.normalized_path, record):
                continue
            raise IntegrityEvidenceError("installed package RECORD member has no integrity data")
        content = path.read_bytes()
        actual_digest = (
            base64.urlsafe_b64encode(hashlib.sha256(content).digest()).rstrip(b"=").decode("ascii")
        )
        if actual_digest != entry.digest or len(content) != entry.size:
            raise IntegrityEvidenceError("installed package RECORD member failed validation")

    for key, path in actual.items():
        if key in record:
            continue
        normalized = _normalize_installed_record_path(
            path.relative_to(layout.site_packages_root).as_posix()
        )
        if not _is_optional_unrecorded_pyc(normalized, record):
            raise IntegrityEvidenceError("installed package filesystem has an unrecorded member")

    for relative in _INSTALLED_INTEGRITY_FILES:
        critical_entry = record.get(relative.casefold())
        if (
            critical_entry is None
            or critical_entry.digest is None
            or critical_entry.size is None
            or relative.casefold() not in actual
        ):
            raise IntegrityEvidenceError("installed trusted-core integrity member is absent")


def _is_optional_recorded_pyc(
    relative: str,
    record: dict[str, _InstalledRecordEntry],
) -> bool:
    """RECORD may list optional cache bytecode that is absent after install."""

    return relative.casefold() not in record or _is_optional_unrecorded_pyc(relative, record)


def _is_optional_unrecorded_pyc(
    relative: str,
    record: dict[str, _InstalledRecordEntry],
) -> bool:
    """Permit only normal package ``__pycache__`` entries tied to a recorded .py file."""

    parts = relative.split("/")
    if (
        len(parts) < 3
        or parts[0] != "jarvis"
        or parts[-2] != "__pycache__"
        or not parts[-1].endswith(".pyc")
    ):
        return False
    source_stem = parts[-1].split(".", 1)[0]
    if not source_stem:
        return False
    source_relative = "/".join((*parts[:-2], f"{source_stem}.py"))
    source = record.get(source_relative.casefold())
    return source is not None and source.digest is not None and source.size is not None


def _safe_directory_children(root: Path) -> tuple[Path, ...]:
    """List one safe directory level without following links or junctions."""

    if not root.is_dir() or _is_reparse_point(root):
        raise IntegrityEvidenceError("installed package directory is unsafe")
    try:
        children = tuple(root.iterdir())
    except OSError as error:
        raise IntegrityEvidenceError("installed package directory is unreadable") from error
    if any(_is_reparse_point(child) for child in children):
        raise IntegrityEvidenceError("installed package contains a reparse point")
    return children


def _safe_tree_files(root: Path) -> tuple[Path, ...]:
    """Return regular files while rejecting reparse points and special objects."""

    pending = [root]
    result: list[Path] = []
    while pending:
        current = pending.pop()
        for child in _safe_directory_children(current):
            if child.is_dir():
                pending.append(child)
            elif child.is_file():
                result.append(child)
            else:
                raise IntegrityEvidenceError("installed package contains an unsafe object")
    return tuple(result)


def _safe_regular_file(path: Path, root: Path) -> bool:
    """Check a required file without resolving through a reparse point."""

    try:
        return (
            path.is_file() and not _is_reparse_point(path) and not _has_reparse_ancestor(path, root)
        )
    except OSError:
        return False


def _is_reparse_point(path: Path) -> bool:
    """Use pathlib's platform-aware link/junction predicates defensively."""

    try:
        return path.is_symlink() or path.is_junction()
    except OSError:
        return True


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
