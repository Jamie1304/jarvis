"""Staged certification for generated integration packages.

Certification is trusted application evidence, not package behavior.  This
module never imports or executes package code.  It coordinates injected build,
test, authority, install, health, and verification boundaries and emits an
immutable record that is distinct from ACTIVE runtime registration.
"""

from __future__ import annotations

import json
from collections.abc import Callable, Iterable, Mapping
from dataclasses import dataclass, fields, is_dataclass
from datetime import UTC, datetime
from enum import StrEnum
from hashlib import sha256

from jarvis.integration_package import IntegrationPackage, PackageLifecycle
from jarvis.package_reviewer import (
    GeneratedPackageReview,
    GeneratedPackageReviewer,
    PackageReviewPolicy,
    PackageReviewSurface,
    PackageSourceFile,
    ReviewDecision,
)
from jarvis.permissions.models import Permission
from jarvis.tools.models import SemanticVersion
from jarvis.ui_simulation import (
    UISimulationAttestation,
    UISimulationAttestationStatus,
)
from jarvis.windows_sandbox import SandboxSecurityStatus


class CertificationError(RuntimeError):
    """A package could not complete staged certification."""


class CertificationValidationError(CertificationError, ValueError):
    """Certification metadata or evidence is malformed."""


class CertificationStage(StrEnum):
    BUILD = "BUILD"
    STATIC_AUDIT = "STATIC_AUDIT"
    UNIT_TESTS = "UNIT_TESTS"
    SANDBOX_INTEGRATION_TEST = "SANDBOX_INTEGRATION_TEST"
    PERMISSION_DIFF = "PERMISSION_DIFF"
    AUTHORITY_DECISION = "AUTHORITY_DECISION"
    INSTALL = "INSTALL"
    HEALTHCHECK = "HEALTHCHECK"
    VERIFICATION = "VERIFICATION"
    CERTIFIED = "CERTIFIED"


@dataclass(frozen=True, slots=True)
class CertificationStageEvidence:
    stage: CertificationStage
    passed: bool
    evidence: tuple[str, ...] = ()
    recorded_at: datetime | None = None

    def __post_init__(self) -> None:
        if not isinstance(self.stage, CertificationStage) or type(self.passed) is not bool:
            raise CertificationValidationError("Certification stage evidence is malformed")
        _labels(self.evidence, "Stage evidence", 64, 2_000)
        if self.recorded_at is not None and self.recorded_at.tzinfo is None:
            raise CertificationValidationError("Stage evidence timestamp must be timezone-aware")


@dataclass(frozen=True, slots=True)
class CertificationStageResult:
    """Trusted application result returned by one injected certification boundary."""

    passed: bool
    evidence: tuple[str, ...] = ()
    approval_ref: str | None = None
    shadow_eligible: bool = False
    canary_eligible: bool = False
    health: tuple[str, ...] = ()
    verification: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        if type(self.passed) is not bool:
            raise CertificationValidationError("Certification stage result is malformed")
        _labels(self.evidence, "Stage result evidence", 64, 2_000)
        _labels(self.health, "Health evidence", 64, 2_000)
        _labels(self.verification, "Verification evidence", 64, 2_000)
        if self.approval_ref is not None:
            _text(self.approval_ref, "Approval reference", 512)
        if type(self.shadow_eligible) is not bool or type(self.canary_eligible) is not bool:
            raise CertificationValidationError("Shadow/Canary eligibility is malformed")


_DEFAULT_REVIEW_SURFACE = PackageReviewSurface()
_DEFAULT_REVIEW_POLICY = PackageReviewPolicy()


@dataclass(frozen=True, slots=True)
class BuiltPackage:
    """Build output containing only immutable package data and source snapshots."""

    package: IntegrationPackage
    source_files: tuple[PackageSourceFile, ...]

    def __post_init__(self) -> None:
        if not isinstance(self.package, IntegrationPackage) or type(self.source_files) is not tuple:
            raise CertificationValidationError("Build output is malformed")
        if self.package.lifecycle not in {PackageLifecycle.DISCOVERED, PackageLifecycle.VALIDATED}:
            raise CertificationValidationError("Build output is already active or certified")
        if any(not isinstance(source, PackageSourceFile) for source in self.source_files):
            raise CertificationValidationError("Build source snapshots are malformed")


@dataclass(frozen=True, slots=True)
class CertificationRequest:
    package: IntegrationPackage
    rollback_target: str
    environment_compatibility: tuple[str, ...]
    expected_behavior_baseline: tuple[str, ...]
    review_surface: PackageReviewSurface = _DEFAULT_REVIEW_SURFACE
    review_policy: PackageReviewPolicy = _DEFAULT_REVIEW_POLICY
    ui_simulation_harness_available: bool = False
    ui_simulation_evidence: tuple[str, ...] = ()
    sandbox_security_status: SandboxSecurityStatus | None = None

    def __post_init__(self) -> None:
        if not isinstance(self.package, IntegrationPackage):
            raise CertificationValidationError("Certification package is malformed")
        _text(self.rollback_target, "Rollback target", 512)
        _labels(self.environment_compatibility, "Environment compatibility", 64, 512)
        _labels(self.expected_behavior_baseline, "Expected behavior baseline", 64, 2_000)
        if not isinstance(self.review_surface, PackageReviewSurface) or not isinstance(
            self.review_policy, PackageReviewPolicy
        ):
            raise CertificationValidationError("Package review configuration is malformed")
        if type(self.ui_simulation_harness_available) is not bool:
            raise CertificationValidationError("UI simulation harness flag is malformed")
        _labels(self.ui_simulation_evidence, "UI simulation evidence", 64, 2_000)
        if self.sandbox_security_status is not None and not isinstance(
            self.sandbox_security_status, SandboxSecurityStatus
        ):
            raise CertificationValidationError("Sandbox security status is malformed")


StageHook = Callable[[IntegrationPackage], CertificationStageResult]


@dataclass(frozen=True, slots=True)
class CertificationHooks:
    """Trusted composition hooks; generated package code cannot supply these."""

    build: Callable[[IntegrationPackage], BuiltPackage]
    unit_tests: StageHook
    sandbox_integration_test: StageHook
    permission_diff: StageHook
    authority_decision: StageHook
    install: StageHook
    healthcheck: StageHook
    verification: StageHook
    ui_simulation: Callable[[IntegrationPackage, str], UISimulationAttestation] | None = None


@dataclass(frozen=True, slots=True)
class CertificationRecord:
    """Immutable evidence that one exact package revision completed certification."""

    package_id: str
    version: SemanticVersion
    package_hash: str
    source_hash: str
    dependency_hash: str
    manifest_hash: str
    test_evidence: tuple[CertificationStageEvidence, ...]
    audit: tuple[CertificationStageEvidence, ...]
    permissions: tuple[Permission, ...]
    approval_ref: str | None
    environment_compatibility: tuple[str, ...]
    health: tuple[str, ...]
    verification: tuple[str, ...]
    rollback_target: str
    shadow_eligible: bool
    canary_eligible: bool
    expected_behavior_baseline: tuple[str, ...]
    stages: tuple[CertificationStageEvidence, ...]
    certified_at: datetime
    ui_simulation_attestation_ref: str | None = None
    ui_simulation_attestation_digest: str | None = None

    def __post_init__(self) -> None:
        _text(self.package_id, "Certification package ID", 128)
        if not isinstance(self.version, SemanticVersion):
            raise CertificationValidationError("Certification version is malformed")
        for value, name in (
            (self.package_hash, "Package hash"),
            (self.source_hash, "Source hash"),
            (self.dependency_hash, "Dependency hash"),
            (self.manifest_hash, "Manifest hash"),
        ):
            _validate_digest(value, name)
        if (
            type(self.permissions) is not tuple
            or len(self.permissions) > 64
            or any(not isinstance(permission, Permission) for permission in self.permissions)
        ):
            raise CertificationValidationError("Certification permissions are malformed")
        if tuple(sorted(set(self.permissions), key=lambda item: item.value)) != self.permissions:
            raise CertificationValidationError(
                "Certification permissions must be unique and sorted"
            )
        if self.approval_ref is not None:
            _text(self.approval_ref, "Approval reference", 512)
        _labels(self.environment_compatibility, "Environment compatibility", 64, 512)
        _labels(self.health, "Certification health", 64, 2_000)
        _labels(self.verification, "Certification verification", 64, 2_000)
        _text(self.rollback_target, "Rollback target", 512)
        _labels(self.expected_behavior_baseline, "Expected behavior baseline", 64, 2_000)
        if type(self.shadow_eligible) is not bool or type(self.canary_eligible) is not bool:
            raise CertificationValidationError("Shadow/Canary eligibility is malformed")
        if not self.stages or self.stages[-1].stage is not CertificationStage.CERTIFIED:
            raise CertificationValidationError("Certification stages are incomplete")
        if not all(stage.passed for stage in self.stages):
            raise CertificationValidationError("Certification record contains a failed stage")
        if self.certified_at.tzinfo is None:
            raise CertificationValidationError("Certification timestamp must be timezone-aware")
        if (self.ui_simulation_attestation_ref is None) != (
            self.ui_simulation_attestation_digest is None
        ):
            raise CertificationValidationError("UI simulation attestation binding is incomplete")
        if self.ui_simulation_attestation_ref is not None:
            _text(self.ui_simulation_attestation_ref, "UI simulation attestation reference", 512)
            _validate_digest(
                self.ui_simulation_attestation_digest,
                "UI simulation attestation digest",
            )

    def matches(
        self,
        package: IntegrationPackage,
        source_files: Iterable[PackageSourceFile],
    ) -> bool:
        """Return false when code, dependencies, manifest, version, or permissions changed."""

        if (
            not isinstance(package, IntegrationPackage)
            or package.package_id != self.package_id
            or package.version != self.version
            or package.package_hash != self.package_hash
            or tuple(package.permissions) != self.permissions
        ):
            return False
        try:
            source_hash, dependency_hash, manifest_hash = package_fingerprints(
                package, source_files
            )
        except (CertificationValidationError, TypeError, ValueError):
            return False
        return (
            source_hash == self.source_hash
            and dependency_hash == self.dependency_hash
            and manifest_hash == self.manifest_hash
        )


class CertificationFailure(CertificationError):
    """A named stage failed; later stages were not executed."""

    def __init__(self, stage: CertificationStage, evidence: tuple[CertificationStageEvidence, ...]):
        super().__init__(f"Package certification failed at {stage.value}")
        self.stage = stage
        self.evidence = evidence


class PackageCertifier:
    """Run the exact staged certification order under trusted composition."""

    def __init__(
        self,
        reviewer: GeneratedPackageReviewer | None = None,
        *,
        clock: Callable[[], datetime] | None = None,
        require_executable_isolation: bool = False,
        sandbox_security_status_provider: Callable[[], SandboxSecurityStatus | None] | None = None,
    ) -> None:
        self._reviewer = reviewer or GeneratedPackageReviewer()
        self._clock = clock or (lambda: datetime.now(UTC))
        if type(require_executable_isolation) is not bool:
            raise CertificationValidationError("Executable isolation policy is malformed")
        self._require_executable_isolation = require_executable_isolation
        if sandbox_security_status_provider is not None and not callable(
            sandbox_security_status_provider
        ):
            raise CertificationValidationError("Sandbox security status provider is malformed")
        self._sandbox_security_status_provider = sandbox_security_status_provider

    def certify(
        self,
        request: CertificationRequest,
        hooks: CertificationHooks,
    ) -> CertificationRecord:
        if not isinstance(request, CertificationRequest) or not isinstance(
            hooks, CertificationHooks
        ):
            raise CertificationValidationError("Certification inputs are malformed")
        evidence: list[CertificationStageEvidence] = []
        built = self._run_build(request, hooks, evidence)
        package = built.package

        review = self._reviewer.review(
            package,
            source_files=built.source_files,
            surface=request.review_surface,
            policy=request.review_policy,
        )
        static_passed = review.decision in {
            ReviewDecision.PASS,
            ReviewDecision.PASS_WITH_RESTRICTIONS,
        }
        self._record_or_fail(
            CertificationStage.STATIC_AUDIT,
            static_passed,
            _review_evidence(review),
            evidence,
        )
        self._run_hook(CertificationStage.UNIT_TESTS, hooks.unit_tests, package, evidence)
        if (
            self._require_executable_isolation
            and package.requires_executable_isolation
            and self._sandbox_security_status_provider is None
        ):
            status = request.sandbox_security_status
            if status is None or not status.executable_isolation:
                self._record_or_fail(
                    CertificationStage.SANDBOX_INTEGRATION_TEST,
                    False,
                    (
                        "Executable package requires a trusted capability-free "
                        "Windows AppContainer launch with scoped ACLs and Job Object",
                    ),
                    evidence,
                )
        self._run_hook(
            CertificationStage.SANDBOX_INTEGRATION_TEST,
            hooks.sandbox_integration_test,
            package,
            evidence,
        )
        if self._require_executable_isolation and package.requires_executable_isolation:
            status = (
                self._sandbox_security_status_provider()
                if self._sandbox_security_status_provider is not None
                else request.sandbox_security_status
            )
            if status is None or not status.executable_isolation:
                self._record_or_fail(
                    CertificationStage.SANDBOX_INTEGRATION_TEST,
                    False,
                    (
                        "Executable package requires a trusted capability-free "
                        "Windows AppContainer launch with scoped ACLs and Job Object",
                    ),
                    evidence,
                )
        self._run_hook(
            CertificationStage.PERMISSION_DIFF,
            hooks.permission_diff,
            package,
            evidence,
        )
        authority = self._run_hook(
            CertificationStage.AUTHORITY_DECISION,
            hooks.authority_decision,
            package,
            evidence,
        )
        if package.permissions and authority.approval_ref is None:
            self._record_or_fail(
                CertificationStage.AUTHORITY_DECISION,
                False,
                ("Privileged package lacks a trusted approval reference",),
                evidence,
            )
        self._run_hook(CertificationStage.INSTALL, hooks.install, package, evidence)
        health = self._run_hook(
            CertificationStage.HEALTHCHECK,
            hooks.healthcheck,
            package,
            evidence,
        )
        verification = self._run_hook(
            CertificationStage.VERIFICATION,
            hooks.verification,
            package,
            evidence,
        )
        ui_attestation = self._run_ui_simulation(
            request, hooks, package, built.source_files, evidence
        )
        verification_evidence = verification.verification
        if ui_attestation is not None:
            verification_evidence += ui_attestation.certification_strings()
        final = CertificationStageEvidence(
            CertificationStage.CERTIFIED,
            True,
            ("All certification stages passed; package remains inactive",),
            self._clock(),
        )
        evidence.append(final)
        source_hash, dependency_hash, manifest_hash = package_fingerprints(
            package, built.source_files
        )
        return CertificationRecord(
            package_id=package.package_id,
            version=package.version,
            package_hash=package.package_hash,
            source_hash=source_hash,
            dependency_hash=dependency_hash,
            manifest_hash=manifest_hash,
            test_evidence=(evidence[2], evidence[3]),
            audit=(evidence[1],),
            permissions=package.permissions,
            approval_ref=authority.approval_ref,
            environment_compatibility=request.environment_compatibility,
            health=health.health,
            verification=verification_evidence,
            rollback_target=request.rollback_target,
            shadow_eligible=authority.shadow_eligible,
            canary_eligible=authority.canary_eligible,
            expected_behavior_baseline=request.expected_behavior_baseline,
            stages=tuple(evidence),
            certified_at=self._clock(),
            ui_simulation_attestation_ref=(
                ui_attestation.certification_reference() if ui_attestation is not None else None
            ),
            ui_simulation_attestation_digest=(
                ui_attestation.attestation_digest if ui_attestation is not None else None
            ),
        )

    def _run_ui_simulation(
        self,
        request: CertificationRequest,
        hooks: CertificationHooks,
        package: IntegrationPackage,
        source_files: tuple[PackageSourceFile, ...],
        evidence: list[CertificationStageEvidence],
    ) -> UISimulationAttestation | None:
        """Require fresh trusted harness evidence for data-bearing UI packages."""

        if not (package.ui_assets or package.profiles):
            return None
        if not package.ui_manifest_hash:
            self._record_or_fail(
                CertificationStage.VERIFICATION,
                False,
                ("UI-bearing package lacks a validated UI manifest hash",),
                evidence,
            )
            raise CertificationError("UI manifest binding did not terminate")
        if hooks.ui_simulation is None:
            self._record_or_fail(
                CertificationStage.VERIFICATION,
                False,
                ("UI-bearing package requires a trusted simulation-harness attestation",),
                evidence,
            )
            raise CertificationError("UI simulation hook is unavailable")
        source_hash, _, _ = package_fingerprints(package, source_files)
        simulation_hook = hooks.ui_simulation
        if simulation_hook is None:
            raise CertificationError("UI simulation hook is unavailable")
        try:
            attestation = simulation_hook(package, source_hash)
            if not isinstance(attestation, UISimulationAttestation):
                raise CertificationValidationError("UI simulation hook returned malformed evidence")
            if not attestation.valid_for(package, source_hash):
                raise CertificationValidationError(
                    "UI simulation attestation is stale, failed, or not package-bound"
                )
            if attestation.result not in {
                UISimulationAttestationStatus.PASS,
                UISimulationAttestationStatus.PASS_WITH_RESTRICTIONS,
            }:
                raise CertificationValidationError("UI simulation attestation did not pass")
        except Exception as error:
            self._record_or_fail(
                CertificationStage.VERIFICATION,
                False,
                (f"UI simulation attestation rejected: {type(error).__name__}",),
                evidence,
            )
            raise CertificationError("UI simulation stage did not terminate") from None
        if not evidence or evidence[-1].stage is not CertificationStage.VERIFICATION:
            raise CertificationValidationError("UI evidence is not attached to verification")
        evidence[-1] = CertificationStageEvidence(
            CertificationStage.VERIFICATION,
            True,
            evidence[-1].evidence + attestation.certification_strings(),
            evidence[-1].recorded_at,
        )
        return attestation

    def _run_build(
        self,
        request: CertificationRequest,
        hooks: CertificationHooks,
        evidence: list[CertificationStageEvidence],
    ) -> BuiltPackage:
        try:
            built = hooks.build(request.package)
            if not isinstance(built, BuiltPackage):
                raise CertificationValidationError("Build hook returned malformed output")
        except Exception as error:
            self._record_or_fail(
                CertificationStage.BUILD,
                False,
                ("Build failed: " + type(error).__name__,),
                evidence,
            )
            raise CertificationError("Build stage did not terminate") from None
        evidence.append(
            CertificationStageEvidence(
                CertificationStage.BUILD,
                True,
                ("Build produced an inactive package revision",),
                self._clock(),
            )
        )
        return built

    def _run_hook(
        self,
        stage: CertificationStage,
        hook: StageHook,
        package: IntegrationPackage,
        evidence: list[CertificationStageEvidence],
    ) -> CertificationStageResult:
        try:
            result = hook(package)
            if not isinstance(result, CertificationStageResult):
                raise CertificationValidationError("Stage hook returned malformed evidence")
        except Exception as error:
            self._record_or_fail(
                stage,
                False,
                ("Stage failed: " + type(error).__name__,),
                evidence,
            )
            raise CertificationError("Certification stage did not terminate") from None
        self._record_or_fail(stage, result.passed, result.evidence, evidence)
        return result

    def _record_or_fail(
        self,
        stage: CertificationStage,
        passed: bool,
        details: Iterable[str],
        evidence: list[CertificationStageEvidence],
    ) -> None:
        item = CertificationStageEvidence(stage, passed, tuple(details), self._clock())
        evidence.append(item)
        if not passed:
            raise CertificationFailure(stage, tuple(evidence))


def package_fingerprints(
    package: IntegrationPackage,
    source_files: Iterable[PackageSourceFile],
) -> tuple[str, str, str]:
    """Return source, dependency, and manifest hashes for exact invalidation."""

    if not isinstance(package, IntegrationPackage):
        raise CertificationValidationError("Package fingerprint input is malformed")
    normalized_sources: list[dict[str, str]] = []
    for source in source_files:
        if not isinstance(source, PackageSourceFile) or type(source.path) is not str:
            raise CertificationValidationError("Source fingerprint input is malformed")
        if type(source.content) is not str:
            raise CertificationValidationError("Source fingerprint content is malformed")
        normalized_sources.append({"path": source.path, "content": source.content})
    source_hash = _hash_value(normalized_sources)
    dependency_hash = _hash_value(package.dependency_lock)
    normalized_package = _normalize(package)
    if not isinstance(normalized_package, dict):
        raise CertificationValidationError("Manifest fingerprint is malformed")
    normalized_package.pop("package_hash", None)
    return source_hash, dependency_hash, _hash_value(normalized_package)


def _review_evidence(review: GeneratedPackageReview) -> tuple[str, ...]:
    details = [f"Static decision: {review.decision.value}"]
    details.extend(f"{finding.code}: {finding.message}" for finding in review.findings)
    return tuple(details) or ("Static audit passed",)


def _normalize(value: object) -> object:
    if isinstance(value, StrEnum):
        return value.value
    if is_dataclass(value) and not isinstance(value, type):
        return {item.name: _normalize(getattr(value, item.name)) for item in fields(value)}
    if isinstance(value, Mapping):
        return {
            str(key): _normalize(item)
            for key, item in sorted(value.items(), key=lambda item: str(item[0]))
        }
    if isinstance(value, tuple | list | set | frozenset):
        values = [_normalize(item) for item in value]
        return sorted(values, key=lambda item: json.dumps(item, sort_keys=True, default=str))
    if isinstance(value, datetime):
        return value.isoformat()
    return value


def _hash_value(value: object) -> str:
    encoded = json.dumps(
        _normalize(value), sort_keys=True, separators=(",", ":"), default=str
    ).encode()
    return sha256(encoded).hexdigest()


def _text(value: object, name: str, limit: int) -> None:
    if type(value) is not str or not value.strip() or len(value) > limit or "\x00" in value:
        raise CertificationValidationError(f"{name} is malformed")


def _labels(values: object, name: str, limit: int, item_limit: int) -> None:
    if (
        type(values) is not tuple
        or len(values) > limit
        or any(
            type(value) is not str
            or not value.strip()
            or len(value) > item_limit
            or "\x00" in value
            for value in values
        )
    ):
        raise CertificationValidationError(f"{name} are malformed")


def _validate_digest(value: object, name: str) -> None:
    if (
        type(value) is not str
        or len(value) != 64
        or any(character not in "0123456789abcdefABCDEF" for character in value)
    ):
        raise CertificationValidationError(f"{name} must be a SHA-256 digest")


__all__ = [
    "BuiltPackage",
    "CertificationError",
    "CertificationFailure",
    "CertificationHooks",
    "CertificationRecord",
    "CertificationRequest",
    "CertificationStage",
    "CertificationStageEvidence",
    "CertificationStageResult",
    "CertificationValidationError",
    "PackageCertifier",
    "package_fingerprints",
]
