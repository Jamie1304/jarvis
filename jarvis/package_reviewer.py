"""Fail-closed static review of generated integration packages.

The reviewer consumes package metadata and source as untrusted data.  It never
imports, executes, installs, registers, or authorizes a package.  A positive
result is only a static gate; the normal certification, PermissionBroker,
Shadow, and Canary gates still own activation.
"""

from __future__ import annotations

import re
from collections.abc import Iterable
from dataclasses import dataclass
from datetime import UTC, datetime
from enum import StrEnum
from hashlib import sha256
from ipaddress import ip_address
from typing import Protocol
from urllib.parse import urlsplit

from jarvis.integration_package import (
    IntegrationPackage,
    PackageBoundary,
    PackageContractError,
    PackageLifecycle,
    validate_package_path,
)
from jarvis.permissions.models import Permission


class ReviewDecision(StrEnum):
    PASS = "PASS"
    PASS_WITH_RESTRICTIONS = "PASS_WITH_RESTRICTIONS"
    MANUAL_REVIEW_REQUIRED = "MANUAL_REVIEW_REQUIRED"
    REJECT = "REJECT"


class ReviewSeverity(StrEnum):
    RESTRICTION = "restriction"
    MANUAL = "manual"
    REJECT = "reject"


@dataclass(frozen=True, slots=True)
class PackageSourceFile:
    """A bounded source snapshot supplied for inspection, never executed."""

    path: str
    content: str


@dataclass(frozen=True, slots=True)
class CredentialScope:
    """An opaque Vault reference and the narrow operations it may request."""

    reference: str
    scopes: tuple[str, ...]


@dataclass(frozen=True, slots=True)
class PackageReviewSurface:
    """Untrusted declarations not yet represented by IntegrationPackage."""

    install_hooks: tuple[str, ...] = ()
    binaries: tuple[str, ...] = ()
    network_destinations: tuple[str, ...] = ()
    credential_scopes: tuple[CredentialScope, ...] = ()
    persistence_paths: tuple[str, ...] = ()
    ui_actions: tuple[str, ...] = ()


@dataclass(frozen=True, slots=True)
class PackageReviewPolicy:
    """Static-review policy; it cannot grant package authority."""

    allowed_network_hosts: frozenset[str] = frozenset()
    trusted_provenance_sources: frozenset[str] = frozenset()


class _AddFinding(Protocol):
    def __call__(
        self,
        category: str,
        code: str,
        severity: ReviewSeverity,
        message: str,
        path: str | None = None,
    ) -> None: ...


_DEFAULT_SURFACE = PackageReviewSurface()
_DEFAULT_POLICY = PackageReviewPolicy()


@dataclass(frozen=True, slots=True)
class ReviewFinding:
    category: str
    code: str
    severity: ReviewSeverity
    message: str
    path: str | None = None


@dataclass(frozen=True, slots=True)
class GeneratedPackageReview:
    package_id: str
    version: str
    decision: ReviewDecision
    findings: tuple[ReviewFinding, ...]
    reviewed_at: datetime
    reviewer_version: str = "1"

    @property
    def restrictions(self) -> tuple[str, ...]:
        return tuple(
            finding.message
            for finding in self.findings
            if finding.severity is ReviewSeverity.RESTRICTION
        )


_MAX_SOURCES = 128
_MAX_SOURCE_BYTES = 512 * 1024
_MAX_FINDINGS = 256
_EXACT_DEPENDENCY = re.compile(r"^[A-Za-z0-9_.-]+==[^\s;]+$")
_HASHED_DEPENDENCY = re.compile(r"^[A-Za-z0-9_.-]+@sha256:[0-9a-fA-F]{64}$")
_HOST = re.compile(r"^[a-z0-9.-]+$")
_SECRET_WORD = r"(?:secret|token|password|passwd|api[_-]?key|credential|private[_-]?key)"


class GeneratedPackageReviewer:
    """Review a package without giving it an execution or policy pathway."""

    def review(
        self,
        package: IntegrationPackage,
        *,
        source_files: Iterable[PackageSourceFile] = (),
        surface: PackageReviewSurface = _DEFAULT_SURFACE,
        policy: PackageReviewPolicy = _DEFAULT_POLICY,
    ) -> GeneratedPackageReview:
        findings: list[ReviewFinding] = []

        def add(
            category: str,
            code: str,
            severity: ReviewSeverity,
            message: str,
            path: str | None = None,
        ) -> None:
            if len(findings) < _MAX_FINDINGS:
                findings.append(ReviewFinding(category, code, severity, message, path))

        if not isinstance(package, IntegrationPackage):
            return self._result(
                "unknown",
                "unknown",
                [
                    ReviewFinding(
                        "manifest",
                        "wrong_type",
                        ReviewSeverity.REJECT,
                        "Package type is invalid",
                    )
                ],
            )

        if not self._validate_review_inputs(surface, policy, add):
            return self._result(package.package_id, str(package.version), findings)

        try:
            self._validate_contract(package)
        except (AttributeError, KeyError, PackageContractError, TypeError, ValueError) as error:
            add("manifest", "invalid_contract", ReviewSeverity.REJECT, str(error)[:512])
            return self._result(package.package_id, str(package.version), findings)

        try:
            self._review_provenance(package, policy, add)
            self._review_dependencies(package, add)
            self._review_operations(package, add)
            self._review_metadata(package, surface, policy, add)
            sources = tuple(source_files)
            self._review_entries(package, sources, add)
            self._review_sources(package, sources, add)
        except Exception:
            # Generated metadata is hostile input. Never propagate an input
            # error or include its value in a finding that could leak a secret.
            add(
                "schema",
                "review_failed_closed",
                ReviewSeverity.REJECT,
                "Package review failed closed",
            )
        decision = self._decision(findings)
        return GeneratedPackageReview(
            package.package_id,
            str(package.version),
            decision,
            tuple(findings),
            datetime.now(UTC),
        )

    @staticmethod
    def _validate_review_inputs(
        surface: PackageReviewSurface,
        policy: PackageReviewPolicy,
        add: _AddFinding,
    ) -> bool:
        if not isinstance(surface, PackageReviewSurface) or not isinstance(
            policy, PackageReviewPolicy
        ):
            add(
                "schema",
                "invalid_review_input",
                ReviewSeverity.REJECT,
                "Review input type is invalid",
            )
            return False
        for name in (
            "install_hooks",
            "binaries",
            "network_destinations",
            "persistence_paths",
            "ui_actions",
        ):
            values = getattr(surface, name)
            if (
                not isinstance(values, tuple)
                or len(values) > 128
                or any(
                    type(value) is not str or not value or len(value) > 2_000 or "\x00" in value
                    for value in values
                )
            ):
                add(
                    "schema",
                    "invalid_review_input",
                    ReviewSeverity.REJECT,
                    f"Surface {name} is invalid",
                )
                return False
        if not isinstance(surface.credential_scopes, tuple) or len(surface.credential_scopes) > 64:
            add(
                "schema",
                "invalid_review_input",
                ReviewSeverity.REJECT,
                "Credential scope metadata is invalid",
            )
            return False
        for credential in surface.credential_scopes:
            if not isinstance(credential, CredentialScope) or type(credential.reference) is not str:
                add(
                    "schema",
                    "invalid_review_input",
                    ReviewSeverity.REJECT,
                    "Credential scope metadata is invalid",
                )
                return False
            if not isinstance(credential.scopes, tuple) or any(
                type(scope) is not str or not scope or len(scope) > 256
                for scope in credential.scopes
            ):
                add(
                    "schema",
                    "invalid_review_input",
                    ReviewSeverity.REJECT,
                    "Credential scope metadata is invalid",
                )
                return False
        if (
            not isinstance(policy.allowed_network_hosts, frozenset)
            or not isinstance(policy.trusted_provenance_sources, frozenset)
            or not all(type(host) is str and host for host in policy.allowed_network_hosts)
            or not all(
                type(source) is str and source for source in policy.trusted_provenance_sources
            )
        ):
            add(
                "schema", "invalid_review_input", ReviewSeverity.REJECT, "Network policy is invalid"
            )
            return False
        return True

    @staticmethod
    def _result(
        package_id: str,
        version: str,
        findings: list[ReviewFinding],
    ) -> GeneratedPackageReview:
        return GeneratedPackageReview(
            package_id,
            version,
            GeneratedPackageReviewer._decision(findings),
            tuple(findings),
            datetime.now(UTC),
        )

    @staticmethod
    def _validate_contract(package: IntegrationPackage) -> None:
        """Re-check the immutable contract, including objects forged at runtime."""

        if package.lifecycle not in {PackageLifecycle.DISCOVERED, PackageLifecycle.VALIDATED}:
            raise PackageContractError("Generated package is already beyond static review")
        if not package.package_hash:
            raise PackageContractError("Package hash is required before static review")
        if len(package.entries) > 256:
            raise PackageContractError("Package has too many entries")
        for entry in package.entries:
            if entry.boundary is PackageBoundary.CREDENTIALS:
                raise PackageContractError("Credentials cannot be package entries")

    @staticmethod
    def _review_provenance(
        package: IntegrationPackage,
        policy: PackageReviewPolicy,
        add: _AddFinding,
    ) -> None:
        emit = add
        provenance = package.provenance
        if provenance is None:
            emit("provenance", "missing", ReviewSeverity.REJECT, "Package provenance is required")
            return
        if not provenance.verified_by:
            emit(
                "provenance",
                "unverified",
                ReviewSeverity.MANUAL,
                "Provenance has no trusted verifier identity",
            )
        if (
            policy.trusted_provenance_sources
            and provenance.source not in policy.trusted_provenance_sources
        ):
            emit(
                "provenance",
                "source_not_trusted",
                ReviewSeverity.MANUAL,
                "Package source is outside the configured provenance allowlist",
            )
        for entry in package.entries:
            if entry.provenance != provenance:
                emit(
                    "provenance",
                    "entry_mismatch",
                    ReviewSeverity.MANUAL,
                    "Entry provenance differs from the package provenance",
                    entry.path,
                )

    @staticmethod
    def _review_dependencies(package: IntegrationPackage, add: _AddFinding) -> None:
        emit = add
        for dependency in package.dependency_lock:
            if dependency.startswith(("-e ", "git+", "http://", "https://", "file:")):
                emit(
                    "dependencies",
                    "untrusted_source",
                    ReviewSeverity.REJECT,
                    "Editable, URL, or source dependency is not permitted",
                )
            elif not (
                _EXACT_DEPENDENCY.fullmatch(dependency) or _HASHED_DEPENDENCY.fullmatch(dependency)
            ):
                emit(
                    "dependencies",
                    "unpinned",
                    ReviewSeverity.MANUAL,
                    "Dependency is not pinned to an exact version or content hash",
                )

    @staticmethod
    def _review_operations(package: IntegrationPackage, add: _AddFinding) -> None:
        operation_policy = package.operation_policy
        forbidden = {
            PackageBoundary.USER_CONFIG,
            PackageBoundary.PACKAGE_DATA,
            PackageBoundary.CREDENTIALS,
        }
        if (
            not operation_policy.preserve_user_config
            or not operation_policy.preserve_package_data
            or not operation_policy.preserve_generated_cache
            or operation_policy.removable_boundaries & forbidden
        ):
            add(
                "lifecycle",
                "unsafe_uninstall_policy",
                ReviewSeverity.REJECT,
                "Install/update/uninstall policy does not preserve user-owned boundaries",
            )
        for description in (
            *(probe.description for probe in package.diagnostics.probes),
            *(repair.description for repair in package.diagnostics.safe_repairs),
        ):
            if _contains_authority_bypass(description):
                add(
                    "diagnostics",
                    "diagnostic_authority_spoof",
                    ReviewSeverity.REJECT,
                    "Diagnostic metadata attempts to bypass trusted policy",
                )

    @classmethod
    def _review_metadata(
        cls,
        package: IntegrationPackage,
        surface: PackageReviewSurface,
        policy: PackageReviewPolicy,
        add: _AddFinding,
    ) -> None:
        emit = add
        if surface.install_hooks:
            emit(
                "installation",
                "install_hooks",
                ReviewSeverity.REJECT,
                "Generated packages cannot run arbitrary install hooks",
            )
        if surface.binaries:
            emit(
                "installation",
                "opaque_binary",
                ReviewSeverity.MANUAL,
                "Binary payload requires manual provenance and platform review",
            )
        if package.services or package.mcp:
            emit(
                "runtime",
                "external_runtime",
                ReviewSeverity.MANUAL,
                "Service or MCP runtime declarations require manual isolation review",
            )
        if package.migrations:
            emit(
                "persistence",
                "migration",
                ReviewSeverity.MANUAL,
                "Migrations require manual idempotency and rollback review",
            )
        if package.diagnostics.safe_repairs:
            emit(
                "diagnostics",
                "repair_approval",
                ReviewSeverity.RESTRICTION,
                "Repair actions remain disabled until trusted policy and approval gates run",
            )
        elevated = {
            Permission.TERMINAL_EXECUTE,
            Permission.CODE_MODIFY,
            Permission.SYSTEM_POWER,
            Permission.APPLICATION_INSTALL,
        }
        if set(package.permissions) & elevated:
            emit(
                "permissions",
                "elevated_permission",
                ReviewSeverity.MANUAL,
                "Elevated permissions require manual least-privilege review",
            )
        elif package.permissions:
            emit(
                "permissions",
                "brokered_permission",
                ReviewSeverity.RESTRICTION,
                "All declared effects remain subject to PermissionBroker and policy",
            )
        cls._review_network(surface.network_destinations, policy, emit)
        cls._review_credentials(surface.credential_scopes, emit)
        for path in surface.persistence_paths:
            try:
                normalized = validate_package_path(path)
            except PackageContractError:
                emit(
                    "persistence",
                    "unsafe_path",
                    ReviewSeverity.REJECT,
                    "Persistence path is unsafe",
                    path,
                )
                continue
            if not normalized.startswith(("data/", "cache/")):
                emit(
                    "persistence",
                    "outside_owned_roots",
                    ReviewSeverity.REJECT,
                    "Persistence path is outside package data/cache roots",
                    path,
                )
        for action in surface.ui_actions:
            if _contains_authority_bypass(action):
                emit(
                    "ui",
                    "approval_spoof",
                    ReviewSeverity.REJECT,
                    "UI metadata attempts to present or bypass trusted approval",
                )

    @staticmethod
    def _review_network(
        destinations: Iterable[str],
        policy: PackageReviewPolicy,
        add: _AddFinding,
    ) -> None:
        emit = add
        for destination in destinations:
            parsed = urlsplit(destination)
            host = parsed.hostname
            if parsed.scheme != "https" or host is None or parsed.username or parsed.password:
                emit(
                    "network",
                    "unsafe_destination",
                    ReviewSeverity.REJECT,
                    "Network destination must be an HTTPS origin without embedded credentials",
                )
                continue
            host = host.casefold().rstrip(".")
            try:
                address = ip_address(host)
            except ValueError:
                address = None
            if address is not None and (
                address.is_private or address.is_loopback or address.is_link_local
            ):
                emit(
                    "network",
                    "private_destination",
                    ReviewSeverity.REJECT,
                    "Private, loopback, or link-local network destination is forbidden",
                )
            elif not _HOST.fullmatch(host) or host not in policy.allowed_network_hosts:
                emit(
                    "network",
                    "destination_review",
                    ReviewSeverity.MANUAL,
                    "Network destination is not in the exact trusted host allowlist",
                )
            else:
                emit(
                    "network",
                    "brokered_destination",
                    ReviewSeverity.RESTRICTION,
                    "Network access remains limited to the exact host through a trusted proxy",
                )

    @staticmethod
    def _review_credentials(scopes: Iterable[CredentialScope], add: _AddFinding) -> None:
        emit = add
        for credential in scopes:
            if not credential.reference.startswith(("vault:", "credential:")) or _looks_like_secret(
                credential.reference
            ):
                emit(
                    "credentials",
                    "raw_or_invalid_reference",
                    ReviewSeverity.REJECT,
                    "Credential access must use an opaque Vault reference",
                )
                continue
            if not credential.scopes or any(
                scope.casefold() in {"*", "all", "admin", "root"} for scope in credential.scopes
            ):
                emit(
                    "credentials",
                    "broad_scope",
                    ReviewSeverity.REJECT,
                    "Credential scope is empty or broader than the declared operation",
                )
            else:
                emit(
                    "credentials",
                    "scoped_reference",
                    ReviewSeverity.RESTRICTION,
                    "Credential use remains opaque and must be resolved by trusted code",
                )

    @staticmethod
    def _review_entries(
        package: IntegrationPackage,
        source_files: Iterable[PackageSourceFile],
        add: _AddFinding,
    ) -> None:
        emit = add
        sources = tuple(source_files)
        if len(sources) > _MAX_SOURCES:
            emit(
                "schema",
                "too_many_sources",
                ReviewSeverity.REJECT,
                "Too many source files supplied",
            )
        valid_sources = tuple(
            source
            for source in sources
            if isinstance(source, PackageSourceFile) and type(source.path) is str
        )
        if len(valid_sources) != len(sources):
            emit("schema", "invalid_source", ReviewSeverity.REJECT, "Source input type is invalid")
        source_paths = {source.path for source in valid_sources}
        for entry in package.entries:
            if entry.boundary is PackageBoundary.PACKAGE_CODE and entry.path not in source_paths:
                emit(
                    "source",
                    "source_not_reviewed",
                    ReviewSeverity.MANUAL,
                    "Package code has no supplied source snapshot for static review",
                    entry.path,
                )
            if entry.kind.casefold() in {"binary", "executable", "dll", "native"}:
                emit(
                    "installation",
                    "executable_entry",
                    ReviewSeverity.MANUAL,
                    "Executable package entry requires manual binary review",
                    entry.path,
                )

    @classmethod
    def _review_sources(
        cls,
        package: IntegrationPackage,
        source_files: Iterable[PackageSourceFile],
        add: _AddFinding,
    ) -> None:
        emit = add
        entries = {entry.path: entry for entry in package.entries}
        seen: set[str] = set()
        for source in tuple(source_files)[:_MAX_SOURCES]:
            if not isinstance(source, PackageSourceFile):
                continue
            path = source.path
            if type(path) is not str:
                emit(
                    "schema", "invalid_source", ReviewSeverity.REJECT, "Source path type is invalid"
                )
                continue
            if path in seen:
                emit(
                    "schema",
                    "duplicate_source",
                    ReviewSeverity.REJECT,
                    "Source path is duplicated",
                    path,
                )
                continue
            seen.add(path)
            try:
                normalized = validate_package_path(path)
            except PackageContractError:
                emit(
                    "schema",
                    "unsafe_source_path",
                    ReviewSeverity.REJECT,
                    "Source path is unsafe",
                    path,
                )
                continue
            entry = entries.get(normalized)
            if entry is None:
                emit(
                    "source",
                    "undeclared_source",
                    ReviewSeverity.REJECT,
                    "Source is not a package entry",
                    path,
                )
                continue
            if type(source.content) is not str:
                emit(
                    "source",
                    "invalid_source",
                    ReviewSeverity.REJECT,
                    "Source content type is invalid",
                    path,
                )
                continue
            try:
                encoded = source.content.encode("utf-8")
            except UnicodeError:
                emit(
                    "source",
                    "invalid_source",
                    ReviewSeverity.REJECT,
                    "Source encoding is invalid",
                    path,
                )
                continue
            if len(encoded) > _MAX_SOURCE_BYTES:
                emit(
                    "source",
                    "source_too_large",
                    ReviewSeverity.REJECT,
                    "Source exceeds review bound",
                    path,
                )
                continue
            if sha256(encoded).hexdigest() != entry.content_hash.casefold():
                emit(
                    "source",
                    "hash_mismatch",
                    ReviewSeverity.REJECT,
                    "Source hash does not match manifest",
                    path,
                )
            cls._scan_source(source.content, path, emit)

    @staticmethod
    def _scan_source(content: str, path: str, add: _AddFinding) -> None:
        emit = add
        checks: tuple[tuple[str, str, ReviewSeverity, re.Pattern[str]], ...] = (
            (
                "execution",
                "dynamic_execution",
                ReviewSeverity.REJECT,
                re.compile(r"\b(?:eval|exec)\s*\("),
            ),
            (
                "execution",
                "dynamic_import",
                ReviewSeverity.REJECT,
                re.compile(r"(?:__import__|importlib\.)"),
            ),
            (
                "deserialization",
                "unsafe_deserialization",
                ReviewSeverity.REJECT,
                re.compile(r"(?:pickle|marshal|dill|jsonpickle)|yaml\.load\s*\("),
            ),
            (
                "process",
                "process_spawn",
                ReviewSeverity.REJECT,
                re.compile(
                    r"(?:subprocess\b|os\.system\s*\(|os\.popen\s*\(|shell\s*=\s*True|cmd\.exe|powershell)"
                ),
            ),
            (
                "paths",
                "path_traversal",
                ReviewSeverity.REJECT,
                re.compile(r"(?:\.\./|\.\.\\\\)"),
            ),
            (
                "secrets",
                "secret_logging",
                ReviewSeverity.REJECT,
                re.compile(r"(?:print|logging\.|logger\.|log\.)[^\n]{0,240}" + _SECRET_WORD, re.I),
            ),
            (
                "authority",
                "authority_bypass",
                ReviewSeverity.REJECT,
                re.compile(
                    r"(?:bypass\s*permissions|disable[_ -]?(?:policy|approval)|"
                    r"skip[_ -]?(?:review|approval)|"
                    r"(?:reviewer|policy|permissionbroker|policyengine).{0,80}(?:set|write|disable|bypass|grant))",
                    re.I,
                ),
            ),
            (
                "network",
                "direct_network",
                ReviewSeverity.REJECT,
                re.compile(r"(?:requests\.|httpx\.|urllib\.|socket\.|urlopen\s*\()"),
            ),
            (
                "persistence",
                "direct_filesystem_mutation",
                ReviewSeverity.MANUAL,
                re.compile(
                    r"(?:open\s*\(|write_text\s*\(|write_bytes\s*\(|unlink\s*\(|rmtree\s*\()"
                ),
            ),
        )
        for category, code, severity, pattern in checks:
            if pattern.search(content):
                emit(category, code, severity, f"Static source check matched {code}", path)
        if _contains_authority_bypass(content):
            emit(
                "ui",
                "approval_spoof",
                ReviewSeverity.REJECT,
                "Source attempts to speak for or alter trusted approval",
                path,
            )

    @staticmethod
    def _decision(findings: Iterable[ReviewFinding]) -> ReviewDecision:
        severities = {finding.severity for finding in findings}
        if ReviewSeverity.REJECT in severities:
            return ReviewDecision.REJECT
        if ReviewSeverity.MANUAL in severities:
            return ReviewDecision.MANUAL_REVIEW_REQUIRED
        if ReviewSeverity.RESTRICTION in severities:
            return ReviewDecision.PASS_WITH_RESTRICTIONS
        return ReviewDecision.PASS


def _looks_like_secret(value: str) -> bool:
    lowered = value.casefold()
    return any(marker in lowered for marker in ("=", "bearer ", "sk-", "password", "token_value"))


def _contains_authority_bypass(value: str) -> bool:
    return bool(
        re.search(
            r"(?:bypass\s*permissions|disable[_ -]?(?:policy|approval)|"
            r"skip[_ -]?(?:review|approval)|"
            r"fake\s+approval|trusted\s+approval\s*=|approval\s*[:=]\s*true)",
            value,
            re.I,
        )
    )
