"""Validated contract for a generic JARVIS Integration Package.

This module describes package contents and data boundaries.  It intentionally
does not discover packages, install them, execute them, or create an
integration catalog.
"""

from __future__ import annotations

import re
from collections.abc import Iterable
from dataclasses import dataclass
from enum import StrEnum

from jarvis.permissions.models import Permission
from jarvis.tools.models import SemanticVersion


class PackageContractError(ValueError):
    """Package metadata or a package boundary is invalid."""


class PackageBoundary(StrEnum):
    PACKAGE_CODE = "package_code"
    USER_CONFIG = "user_config"
    PACKAGE_DATA = "package_data"
    CREDENTIALS = "credentials"
    GENERATED_CACHE = "generated_cache"


class PackageLifecycle(StrEnum):
    DISCOVERED = "discovered"
    VALIDATED = "validated"
    CONFIGURED = "configured"
    STARTING = "starting"
    HEALTHY = "healthy"
    DEGRADED = "degraded"
    STOPPED = "stopped"
    FAILED = "failed"
    UNINSTALLED = "uninstalled"


def _permissions(values: Iterable[Permission]) -> None:
    values = tuple(values)
    if any(not isinstance(value, Permission) for value in values):
        raise PackageContractError("Package permissions are invalid")
    if tuple(sorted(set(values), key=lambda item: item.value)) != values:
        raise PackageContractError("Package permissions must be unique and sorted")


def _labels(values: Iterable[str], name: str, limit: int) -> None:
    values = tuple(values)
    if len(values) > limit or any(
        type(value) is not str or not value.strip() or len(value) > 512 or "\x00" in value
        for value in values
    ):
        raise PackageContractError(f"{name} are invalid")


def _bounded(value: str, name: str, limit: int) -> None:
    if type(value) is not str or not value.strip() or len(value) > limit or "\x00" in value:
        raise PackageContractError(f"{name} is invalid")


def _hash(value: str, name: str) -> None:
    if not re.fullmatch(r"[0-9a-fA-F]{64}", value):
        raise PackageContractError(f"{name} must be a SHA-256 hexadecimal digest")


@dataclass(frozen=True, slots=True)
class PackageLayout:
    manifest_path: str = "manifest.json"
    code_root: str = "code"
    user_config_root: str = "config"
    package_data_root: str = "data"
    generated_cache_root: str = "cache"
    assets_root: str = "assets"

    def __post_init__(self) -> None:
        paths = (
            self.manifest_path,
            self.code_root,
            self.user_config_root,
            self.package_data_root,
            self.generated_cache_root,
            self.assets_root,
        )
        for path in paths:
            validate_package_path(path)
        if len(set(paths)) != len(paths):
            raise PackageContractError("Package layout roots must be distinct")


@dataclass(frozen=True, slots=True)
class PackageProvenance:
    source: str
    revision: str
    license: str
    notice_reference: str = ""
    verified_by: str = ""

    def __post_init__(self) -> None:
        _bounded(self.source, "Package provenance source", 512)
        _bounded(self.revision, "Package provenance revision", 256)
        _bounded(self.license, "Package provenance license", 256)
        if self.notice_reference:
            _bounded(self.notice_reference, "Package notice reference", 512)
        if self.verified_by:
            _bounded(self.verified_by, "Package provenance verifier", 256)


@dataclass(frozen=True, slots=True)
class PackageEntry:
    kind: str
    path: str
    boundary: PackageBoundary
    content_hash: str
    provenance: PackageProvenance
    immutable: bool = True

    def __post_init__(self) -> None:
        _bounded(self.kind, "Package entry kind", 128)
        validate_package_path(self.path)
        _hash(self.content_hash, "Package entry hash")
        if self.boundary in {PackageBoundary.USER_CONFIG, PackageBoundary.CREDENTIALS}:
            raise PackageContractError(
                "User config and credentials are external to package entries"
            )


@dataclass(frozen=True, slots=True)
class SecretSchema:
    name: str
    description: str
    vault_reference_only: bool = True

    def __post_init__(self) -> None:
        _bounded(self.name, "Secret schema name", 128)
        _bounded(self.description, "Secret schema description", 1_000)
        if not self.vault_reference_only:
            raise PackageContractError("Package secrets must be Vault references only")


@dataclass(frozen=True, slots=True)
class PackageAsset:
    asset_id: str
    package_path: str | None = None
    artifact_ref: str | None = None

    def __post_init__(self) -> None:
        _bounded(self.asset_id, "Package asset ID", 128)
        if (self.package_path is None) == (self.artifact_ref is None):
            raise PackageContractError("An asset must be package-owned or an opaque ArtifactRef")
        if self.package_path is not None:
            validate_package_path(self.package_path)
        if self.artifact_ref is not None:
            _bounded(self.artifact_ref, "ArtifactRef", 256)
            if not self.artifact_ref.startswith("artifact:"):
                raise PackageContractError("UI artifact assets must use opaque ArtifactRefs")


@dataclass(frozen=True, slots=True)
class DiagnosticFailureSignature:
    signature: str
    description: str

    def __post_init__(self) -> None:
        _bounded(self.signature, "Diagnostic signature", 256)
        _bounded(self.description, "Diagnostic description", 2_000)


@dataclass(frozen=True, slots=True)
class DiagnosticProbe:
    probe_id: str
    description: str
    safe_read_only: bool = True
    required_permissions: tuple[Permission, ...] = ()

    def __post_init__(self) -> None:
        _bounded(self.probe_id, "Diagnostic probe ID", 128)
        _bounded(self.description, "Diagnostic probe description", 2_000)
        if not self.safe_read_only:
            raise PackageContractError("Package diagnostic probes must be read-only")
        _permissions(self.required_permissions)


@dataclass(frozen=True, slots=True)
class SafeRepairAction:
    action_id: str
    description: str
    required_permissions: tuple[Permission, ...] = ()
    requires_approval: bool = True

    def __post_init__(self) -> None:
        _bounded(self.action_id, "Repair action ID", 128)
        _bounded(self.description, "Repair action description", 2_000)
        _permissions(self.required_permissions)
        if not self.requires_approval:
            raise PackageContractError("Package repair actions cannot bypass approval")


@dataclass(frozen=True, slots=True)
class DiagnosticsContract:
    known_failure_signatures: tuple[DiagnosticFailureSignature, ...] = ()
    probes: tuple[DiagnosticProbe, ...] = ()
    safe_repairs: tuple[SafeRepairAction, ...] = ()
    fallback_hints: tuple[str, ...] = ()
    fallback_strategy: tuple[str, ...] = ()
    expected_repair_verification: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        _labels(self.fallback_hints, "Diagnostic fallback hints", 32)
        _labels(self.fallback_strategy, "Diagnostic fallback strategy", 32)
        _labels(
            self.expected_repair_verification,
            "Diagnostic repair verification",
            32,
        )
        if len({probe.probe_id for probe in self.probes}) != len(self.probes):
            raise PackageContractError("Diagnostic probe IDs must be unique")
        if len({repair.action_id for repair in self.safe_repairs}) != len(self.safe_repairs):
            raise PackageContractError("Repair action IDs must be unique")


@dataclass(frozen=True, slots=True)
class PackageOperationPolicy:
    preserve_user_config: bool = True
    preserve_package_data: bool = True
    preserve_generated_cache: bool = True
    removable_boundaries: frozenset[PackageBoundary] = frozenset(
        {PackageBoundary.PACKAGE_CODE, PackageBoundary.GENERATED_CACHE}
    )

    def __post_init__(self) -> None:
        if not self.preserve_user_config or not self.preserve_package_data:
            raise PackageContractError("Package operations cannot delete user-owned config or data")
        if PackageBoundary.USER_CONFIG in self.removable_boundaries:
            raise PackageContractError("User configuration is never removable by package lifecycle")
        if PackageBoundary.PACKAGE_DATA in self.removable_boundaries:
            raise PackageContractError("Package data is never removable by package lifecycle")
        if PackageBoundary.CREDENTIALS in self.removable_boundaries:
            raise PackageContractError("Package lifecycle cannot remove Vault credentials")


@dataclass(frozen=True, slots=True)
class IntegrationPackage:
    package_id: str
    version: SemanticVersion
    layout: PackageLayout
    entries: tuple[PackageEntry, ...]
    tools: tuple[str, ...] = ()
    mcp: tuple[str, ...] = ()
    api_adapters: tuple[str, ...] = ()
    services: tuple[str, ...] = ()
    events: tuple[str, ...] = ()
    skills: tuple[str, ...] = ()
    profiles: tuple[str, ...] = ()
    ui_assets: tuple[PackageAsset, ...] = ()
    settings_schema: tuple[str, ...] = ()
    permissions: tuple[Permission, ...] = ()
    secret_schema: tuple[SecretSchema, ...] = ()
    health_contract: tuple[str, ...] = ()
    tests: tuple[str, ...] = ()
    migrations: tuple[str, ...] = ()
    lifecycle: PackageLifecycle = PackageLifecycle.DISCOVERED
    diagnostics: DiagnosticsContract = DiagnosticsContract()
    provenance: PackageProvenance | None = None
    dependency_lock: tuple[str, ...] = ()
    package_hash: str = ""
    operation_policy: PackageOperationPolicy = PackageOperationPolicy()
    ui_manifest_hash: str = ""

    def __post_init__(self) -> None:
        _bounded(self.package_id, "Package ID", 128)
        if not self.entries:
            raise PackageContractError("Package must declare immutable/versioned entries")
        _labels(
            self.tools,
            "Package tools",
            64,
        )
        for field_name in (
            "mcp",
            "api_adapters",
            "services",
            "events",
            "skills",
            "profiles",
            "settings_schema",
            "health_contract",
            "tests",
            "migrations",
            "dependency_lock",
        ):
            _labels(getattr(self, field_name), f"Package {field_name}", 64)
        _permissions(self.permissions)
        if len({entry.path for entry in self.entries}) != len(self.entries):
            raise PackageContractError("Package entry paths must be unique")
        code_entries = [
            entry for entry in self.entries if entry.boundary is PackageBoundary.PACKAGE_CODE
        ]
        if any(not entry.immutable for entry in code_entries):
            raise PackageContractError("Package code entries must be immutable")
        if any(entry.boundary is PackageBoundary.USER_CONFIG for entry in self.entries):
            raise PackageContractError("User configuration is external to package source")
        roots = {
            PackageBoundary.PACKAGE_CODE: (self.layout.code_root, self.layout.assets_root),
            PackageBoundary.PACKAGE_DATA: (self.layout.package_data_root,),
            PackageBoundary.GENERATED_CACHE: (self.layout.generated_cache_root,),
        }
        for entry in self.entries:
            if entry.boundary not in roots:
                raise PackageContractError("Unsupported package entry boundary")
            if not any(entry.path.startswith(f"{root}/") for root in roots[entry.boundary]):
                raise PackageContractError("Package entry is outside its declared data boundary")
        if self.package_hash:
            _hash(self.package_hash, "Package hash")
        if self.ui_manifest_hash:
            _hash(self.ui_manifest_hash, "UI manifest hash")
        if self.provenance is None:
            raise PackageContractError("Package provenance is required")
        declared_permissions = set(self.permissions)
        probe_permissions = {
            permission
            for probe in self.diagnostics.probes
            for permission in probe.required_permissions
        }
        repair_permissions = {
            permission
            for repair in self.diagnostics.safe_repairs
            for permission in repair.required_permissions
        }
        if not probe_permissions | repair_permissions <= declared_permissions:
            raise PackageContractError("Diagnostic permissions must be declared by the package")

    def entry_for(self, path: str) -> PackageEntry:
        validate_package_path(path)
        for entry in self.entries:
            if entry.path == path:
                return entry
        raise KeyError("Unknown package entry")

    def validate_asset(self, asset: PackageAsset) -> None:
        if asset.package_path is not None:
            if not asset.package_path.startswith(f"{self.layout.assets_root}/"):
                raise PackageContractError("Package UI asset is outside the asset root")
            try:
                entry = self.entry_for(asset.package_path)
            except KeyError as error:
                raise PackageContractError("Package UI asset is not declared") from error
            if entry.boundary is not PackageBoundary.PACKAGE_CODE:
                raise PackageContractError(
                    "Package UI asset must be immutable package-owned content"
                )

    @property
    def requires_executable_isolation(self) -> bool:
        """Whether activation would execute package-owned code.

        Declarative UI assets are not executable package code.  Unknown code
        entry kinds are treated conservatively as executable so a new package
        format cannot silently bypass the Windows isolation gate.
        """

        declarative_kinds = frozenset({"asset", "image", "theme", "stylesheet"})
        return any(
            entry.boundary is PackageBoundary.PACKAGE_CODE
            and entry.kind.casefold() not in declarative_kinds
            for entry in self.entries
        )


def validate_package_path(path: str) -> str:
    """Validate a portable package-relative path and return its normalized form."""

    if (
        type(path) is not str
        or not path
        or path.startswith(("/", "\\"))
        or "\\" in path
        or ":" in path
        or "\x00" in path
    ):
        raise PackageContractError("Package paths must be relative portable paths")
    parts = path.split("/")
    if any(part in {"", ".", ".."} for part in parts):
        raise PackageContractError("Package paths cannot contain traversal or empty segments")
    if any(not re.fullmatch(r"[A-Za-z0-9_.-]+", part) for part in parts):
        raise PackageContractError("Package paths contain an unsafe segment")
    return "/".join(parts)
