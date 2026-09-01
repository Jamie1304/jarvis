"""Trusted, application-owned preview metadata for controlled updates.

This module deliberately does not apply updates.  It turns validated facts from
the trusted update/recovery pipeline into a human preview and binds any later
approval to the exact candidate hash and preview fingerprint.  Model prose is
kept as optional, non-authoritative context and is excluded from all decisions
and fingerprints.
"""

from __future__ import annotations

import hashlib
import hmac
import json
from collections.abc import Iterable
from dataclasses import asdict, dataclass
from datetime import UTC, datetime
from enum import StrEnum
from typing import Any

from jarvis.security.modification_policy import (
    ModificationTrustClassification,
    ModificationTrustClassifier,
    ModificationTrustLevel,
)


class UpdatePreviewError(ValueError):
    """The trusted update preview input or approval is malformed/stale."""


class UpdateRiskLevel(StrEnum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class UpdateGateStatus(StrEnum):
    PASSED = "passed"
    FAILED = "failed"
    NOT_RUN = "not_run"
    NOT_APPLICABLE = "not_applicable"


class UpdateGateName(StrEnum):
    QUALITY = "quality"
    SECURITY = "security"
    GOLDEN_WORKFLOW = "golden_workflow"
    WINDOWS_ACCEPTANCE = "windows_acceptance"


@dataclass(frozen=True, slots=True)
class UpdateGateResult:
    """Trusted result metadata from an independently owned update gate."""

    name: UpdateGateName
    status: UpdateGateStatus
    evidence_digest: str

    def __post_init__(self) -> None:
        if not isinstance(self.name, UpdateGateName) or not isinstance(
            self.status, UpdateGateStatus
        ):
            raise UpdatePreviewError("Update gate metadata is malformed")
        _sha256(self.evidence_digest, "Update gate evidence digest")


@dataclass(frozen=True, slots=True)
class UpdateChangeSummary:
    """Exact change metadata; prose descriptions are not accepted as facts."""

    changed_paths: tuple[str, ...]
    changed_subsystems: tuple[str, ...]
    dependency_changes: tuple[str, ...] = ()
    package_changes: tuple[str, ...] = ()
    user_data_changes: tuple[str, ...] = ()
    integration_changes: tuple[str, ...] = ()
    diff_digest: str = ""

    def __post_init__(self) -> None:
        _bounded_unique(self.changed_paths, "changed paths", 256)
        _bounded_unique(self.changed_subsystems, "changed subsystems", 128)
        for field_name, values in (
            ("dependency changes", self.dependency_changes),
            ("package changes", self.package_changes),
            ("user-data changes", self.user_data_changes),
            ("integration changes", self.integration_changes),
        ):
            _bounded_unique(values, field_name, 128, allow_empty=True)
        _sha256(self.diff_digest, "Diff digest")


@dataclass(frozen=True, slots=True)
class UpdateSecurityImpact:
    """Security-sensitive change facts derived from the trusted classifier."""

    trust_level: ModificationTrustLevel
    trusted_core_changed: bool
    permission_broker_changed: bool
    credential_vault_changed: bool
    recovery_or_updater_changed: bool
    sandbox_or_broker_changed: bool
    permission_surface_changed: bool
    classification_rules: tuple[str, ...]

    def __post_init__(self) -> None:
        if not isinstance(self.trust_level, ModificationTrustLevel):
            raise UpdatePreviewError("Trust classification is malformed")
        for name in (
            "trusted_core_changed",
            "permission_broker_changed",
            "credential_vault_changed",
            "recovery_or_updater_changed",
            "sandbox_or_broker_changed",
            "permission_surface_changed",
        ):
            if type(getattr(self, name)) is not bool:
                raise UpdatePreviewError(f"{name} must be boolean")
        _bounded_unique(self.classification_rules, "classification rules", 256)


@dataclass(frozen=True, slots=True)
class UpdateMigrationSummary:
    database_schema_changed: bool = False
    user_data_changed: bool = False
    integration_data_changed: bool = False
    migration_ids: tuple[str, ...] = ()
    reversible: bool = True

    def __post_init__(self) -> None:
        for name in (
            "database_schema_changed",
            "user_data_changed",
            "integration_data_changed",
            "reversible",
        ):
            if type(getattr(self, name)) is not bool:
                raise UpdatePreviewError(f"{name} must be boolean")
        _bounded_unique(self.migration_ids, "migration IDs", 128, allow_empty=True)
        if self.migration_ids and not (
            self.database_schema_changed or self.user_data_changed or self.integration_data_changed
        ):
            raise UpdatePreviewError("Migration IDs require a declared migration change")


@dataclass(frozen=True, slots=True)
class UpdateRollbackSummary:
    snapshot_available: bool
    rollback_target: str | None
    lkg_revision: str | None
    restart_required: bool
    rollback_available: bool

    def __post_init__(self) -> None:
        if type(self.snapshot_available) is not bool or type(self.restart_required) is not bool:
            raise UpdatePreviewError("Rollback flags are malformed")
        if type(self.rollback_available) is not bool:
            raise UpdatePreviewError("Rollback availability is malformed")
        for value, label in ((self.rollback_target, "rollback target"),):
            if value is not None:
                _label(value, label, 256)
        if self.lkg_revision is not None:
            _revision(self.lkg_revision, "LKG revision")
        if self.rollback_available and not (self.snapshot_available and self.rollback_target):
            raise UpdatePreviewError("A rollback claim requires a snapshot and target")


@dataclass(frozen=True, slots=True)
class UpdateRiskSummary:
    level: UpdateRiskLevel
    reasons: tuple[str, ...]
    approval_required: bool

    def __post_init__(self) -> None:
        if not isinstance(self.level, UpdateRiskLevel) or type(self.approval_required) is not bool:
            raise UpdatePreviewError("Update risk summary is malformed")
        _bounded_unique(self.reasons, "risk reasons", 64, allow_empty=True)


@dataclass(frozen=True, slots=True)
class UpdatePreviewView:
    """Safe declarative view emitted by trusted application presentation code."""

    preview_fingerprint: str
    identity: tuple[tuple[str, str], ...]
    changes: tuple[tuple[str, tuple[str, ...]], ...]
    security: tuple[tuple[str, str], ...]
    migration: tuple[tuple[str, str | tuple[str, ...]], ...]
    gates: tuple[tuple[str, str], ...]
    recovery: tuple[tuple[str, str], ...]
    risk: tuple[tuple[str, str | tuple[str, ...]], ...]

    def __post_init__(self) -> None:
        _sha256(self.preview_fingerprint, "Rendered preview fingerprint")


@dataclass(frozen=True, slots=True)
class UpdateApprovalBinding:
    """The exact values a trusted approval surface must return to the broker."""

    candidate_hash: str
    preview_fingerprint: str
    approval_reference: str
    expires_at: datetime

    def __post_init__(self) -> None:
        _sha256(self.candidate_hash, "Approval candidate hash")
        _sha256(self.preview_fingerprint, "Approval preview fingerprint")
        _label(self.approval_reference, "Approval reference", 256)
        _aware(self.expires_at, "Approval expiry")


@dataclass(frozen=True, slots=True)
class UpdatePreview:
    """Application-owned human update preview, derived from trusted facts."""

    current_version: str
    current_revision: str
    candidate_version: str
    candidate_revision: str
    candidate_hash: str
    changes: UpdateChangeSummary
    security: UpdateSecurityImpact
    migration: UpdateMigrationSummary
    gates: tuple[UpdateGateResult, ...]
    rollback: UpdateRollbackSummary
    risk: UpdateRiskSummary
    preview_fingerprint: str
    created_at: datetime
    model_explanation: str | None = None

    def __post_init__(self) -> None:
        _label(self.current_version, "Current version", 128)
        _revision(self.current_revision, "Current revision")
        _label(self.candidate_version, "Candidate version", 128)
        _revision(self.candidate_revision, "Candidate revision")
        _sha256(self.candidate_hash, "Candidate hash")
        if not isinstance(self.changes, UpdateChangeSummary):
            raise UpdatePreviewError("Change summary is malformed")
        if not isinstance(self.security, UpdateSecurityImpact):
            raise UpdatePreviewError("Security summary is malformed")
        if not isinstance(self.migration, UpdateMigrationSummary):
            raise UpdatePreviewError("Migration summary is malformed")
        if not isinstance(self.rollback, UpdateRollbackSummary):
            raise UpdatePreviewError("Rollback summary is malformed")
        if not isinstance(self.risk, UpdateRiskSummary):
            raise UpdatePreviewError("Risk summary is malformed")
        if len(self.gates) > 16 or any(
            not isinstance(item, UpdateGateResult) for item in self.gates
        ):
            raise UpdatePreviewError("Gate summary is malformed")
        if len({item.name for item in self.gates}) != len(self.gates):
            raise UpdatePreviewError("Each update gate may appear only once")
        _aware(self.created_at, "Preview creation time")
        if self.model_explanation is not None:
            _label(self.model_explanation, "Model explanation", 2_000)
        _sha256(self.preview_fingerprint, "Preview fingerprint")
        expected = self.compute_fingerprint()
        if not hmac.compare_digest(expected, self.preview_fingerprint):
            raise UpdatePreviewError("Preview fingerprint does not match trusted facts")

    @property
    def gate_map(self) -> dict[UpdateGateName, UpdateGateResult]:
        return {item.name: item for item in self.gates}

    @property
    def gates_passed(self) -> bool:
        required = (
            UpdateGateName.QUALITY,
            UpdateGateName.SECURITY,
            UpdateGateName.GOLDEN_WORKFLOW,
        )
        values = self.gate_map
        if any(
            values.get(name) is None or values[name].status is not UpdateGateStatus.PASSED
            for name in required
        ):
            return False
        windows = values.get(UpdateGateName.WINDOWS_ACCEPTANCE)
        return windows is None or windows.status in {
            UpdateGateStatus.PASSED,
            UpdateGateStatus.NOT_APPLICABLE,
        }

    def compute_fingerprint(self) -> str:
        return _compute_fingerprint(
            current_version=self.current_version,
            current_revision=self.current_revision,
            candidate_version=self.candidate_version,
            candidate_revision=self.candidate_revision,
            candidate_hash=self.candidate_hash,
            changes=self.changes,
            security=self.security,
            migration=self.migration,
            gates=self.gates,
            rollback=self.rollback,
            risk=self.risk,
            created_at=self.created_at,
        )

    def approval_binding(
        self,
        *,
        approval_reference: str,
        expires_at: datetime,
    ) -> UpdateApprovalBinding:
        """Create the exact handoff payload for the trusted approval authority."""

        if not self.gates_passed:
            raise UpdatePreviewError("Updates with failed or missing gates cannot be approved")
        if expires_at <= self.created_at:
            raise UpdatePreviewError("Approval expiry must follow the preview")
        return UpdateApprovalBinding(
            self.candidate_hash,
            self.preview_fingerprint,
            approval_reference,
            expires_at,
        )

    def assert_current(self, candidate_hash: str) -> None:
        _sha256(candidate_hash, "Current candidate hash")
        if not hmac.compare_digest(candidate_hash, self.candidate_hash):
            raise UpdatePreviewError("Candidate changed; preview and approval are stale")

    def render_trusted(self) -> UpdatePreviewView:
        """Render only trusted facts for a trusted desktop/update surface.

        The optional model explanation is intentionally absent.  Callers must
        not substitute provider or generated UI text for this view.
        """

        return UpdatePreviewView(
            self.preview_fingerprint,
            (
                ("current_version", self.current_version),
                ("current_revision", self.current_revision),
                ("candidate_version", self.candidate_version),
                ("candidate_revision", self.candidate_revision),
                ("candidate_hash", self.candidate_hash),
            ),
            (
                ("paths", self.changes.changed_paths),
                ("subsystems", self.changes.changed_subsystems),
                ("dependencies", self.changes.dependency_changes),
                ("packages", self.changes.package_changes),
                ("user_data", self.changes.user_data_changes),
                ("integrations", self.changes.integration_changes),
                ("diff_digest", (self.changes.diff_digest,)),
            ),
            (
                ("trust_level", self.security.trust_level.name),
                ("trusted_core_changed", str(self.security.trusted_core_changed)),
                ("permission_broker_changed", str(self.security.permission_broker_changed)),
                ("credential_vault_changed", str(self.security.credential_vault_changed)),
                ("recovery_or_updater_changed", str(self.security.recovery_or_updater_changed)),
                ("sandbox_or_broker_changed", str(self.security.sandbox_or_broker_changed)),
                ("permission_surface_changed", str(self.security.permission_surface_changed)),
            ),
            (
                ("database_schema_changed", str(self.migration.database_schema_changed)),
                ("user_data_changed", str(self.migration.user_data_changed)),
                ("integration_data_changed", str(self.migration.integration_data_changed)),
                ("migration_ids", self.migration.migration_ids),
                ("reversible", str(self.migration.reversible)),
            ),
            tuple((item.name.value, item.status.value) for item in self.gates),
            (
                ("snapshot_available", str(self.rollback.snapshot_available)),
                ("rollback_target", self.rollback.rollback_target or "unavailable"),
                ("lkg_revision", self.rollback.lkg_revision or "unavailable"),
                ("restart_required", str(self.rollback.restart_required)),
                ("rollback_available", str(self.rollback.rollback_available)),
            ),
            (
                ("level", self.risk.level.value),
                ("reasons", self.risk.reasons),
                ("approval_required", str(self.risk.approval_required)),
            ),
        )


class ControlledSelfUpdate:
    """Trusted preview/approval boundary; actual mutation stays with a release owner."""

    def __init__(
        self,
        *,
        classifier: ModificationTrustClassifier | None = None,
        clock: Any | None = None,
    ) -> None:
        self._classifier = classifier or ModificationTrustClassifier()
        self._clock = clock or (lambda: datetime.now(UTC))
        self._preview: UpdatePreview | None = None

    @property
    def preview(self) -> UpdatePreview | None:
        return self._preview

    def prepare_preview(
        self,
        *,
        current_version: str,
        current_revision: str,
        candidate_version: str,
        candidate_revision: str,
        candidate_hash: str,
        changed_paths: Iterable[str],
        diff_digest: str,
        changed_subsystems: tuple[str, ...],
        dependency_changes: tuple[str, ...] = (),
        package_changes: tuple[str, ...] = (),
        user_data_changes: tuple[str, ...] = (),
        integration_changes: tuple[str, ...] = (),
        migration: UpdateMigrationSummary | None = None,
        gates: tuple[UpdateGateResult, ...] = (),
        rollback: UpdateRollbackSummary | None = None,
        model_explanation: str | None = None,
        windows_acceptance_applicable: bool = False,
    ) -> UpdatePreview:
        """Build a preview from trusted inspection/gate metadata.

        The path classifier is rerun here.  A caller-provided risk or trust
        label is intentionally not accepted.
        """

        normalized_paths = tuple(changed_paths)
        if type(windows_acceptance_applicable) is not bool:
            raise UpdatePreviewError("Windows acceptance applicability is malformed")
        classification = self._classifier.classify(normalized_paths)
        impact = _security_impact(classification)
        change = UpdateChangeSummary(
            changed_paths=classification.paths,
            changed_subsystems=changed_subsystems,
            dependency_changes=dependency_changes,
            package_changes=package_changes,
            user_data_changes=user_data_changes,
            integration_changes=integration_changes,
            diff_digest=diff_digest,
        )
        migration = migration or UpdateMigrationSummary()
        rollback = rollback or UpdateRollbackSummary(False, None, None, True, False)
        gate_values = list(gates)
        if windows_acceptance_applicable and not any(
            item.name is UpdateGateName.WINDOWS_ACCEPTANCE for item in gate_values
        ):
            raise UpdatePreviewError("Windows acceptance result is required when applicable")
        risk = _risk_summary(change, impact, migration, rollback, tuple(gate_values))
        created_at = _aware(self._clock(), "Preview creation time")
        preview = UpdatePreview(
            current_version,
            current_revision,
            candidate_version,
            candidate_revision,
            candidate_hash,
            change,
            impact,
            migration,
            tuple(gate_values),
            rollback,
            risk,
            _compute_fingerprint(
                current_version=current_version,
                current_revision=current_revision,
                candidate_version=candidate_version,
                candidate_revision=candidate_revision,
                candidate_hash=candidate_hash,
                changes=change,
                security=impact,
                migration=migration,
                gates=tuple(gate_values),
                rollback=rollback,
                risk=risk,
                created_at=created_at,
            ),
            created_at,
            model_explanation,
        )
        self._preview = preview
        return preview

    def validate_approval(
        self,
        binding: UpdateApprovalBinding,
        *,
        current_candidate_hash: str,
        now: datetime | None = None,
    ) -> None:
        """Validate exact trusted handoff metadata before the release owner acts."""

        if self._preview is None:
            raise UpdatePreviewError("No update preview is awaiting approval")
        self._preview.assert_current(current_candidate_hash)
        if not isinstance(binding, UpdateApprovalBinding):
            raise UpdatePreviewError("Approval binding is malformed")
        if not hmac.compare_digest(binding.candidate_hash, self._preview.candidate_hash):
            raise UpdatePreviewError("Approval candidate hash does not match preview")
        if not hmac.compare_digest(binding.preview_fingerprint, self._preview.preview_fingerprint):
            raise UpdatePreviewError("Approval preview is stale or does not match")
        checked_at = _aware(now or self._clock(), "Approval time")
        if checked_at >= binding.expires_at:
            raise UpdatePreviewError("Update approval has expired")
        if not self._preview.gates_passed:
            raise UpdatePreviewError("Update gates are not all passed")


def _compute_fingerprint(
    *,
    current_version: str,
    current_revision: str,
    candidate_version: str,
    candidate_revision: str,
    candidate_hash: str,
    changes: UpdateChangeSummary,
    security: UpdateSecurityImpact,
    migration: UpdateMigrationSummary,
    gates: tuple[UpdateGateResult, ...],
    rollback: UpdateRollbackSummary,
    risk: UpdateRiskSummary,
    created_at: datetime,
) -> str:
    payload = _canonical(
        {
            "current_version": current_version,
            "current_revision": current_revision,
            "candidate_version": candidate_version,
            "candidate_revision": candidate_revision,
            "candidate_hash": candidate_hash,
            "changes": asdict(changes),
            "security": asdict(security),
            "migration": asdict(migration),
            "gates": [asdict(item) for item in gates],
            "rollback": asdict(rollback),
            "risk": asdict(risk),
            "created_at": created_at,
        }
    )
    return hashlib.sha256(
        json.dumps(payload, sort_keys=True, separators=(",", ":"), allow_nan=False).encode()
    ).hexdigest()


def _security_impact(
    classification: ModificationTrustClassification,
) -> UpdateSecurityImpact:
    paths = classification.paths
    folded = " ".join(paths)
    permission = any(token in folded for token in ("permission", "approval", "policy"))
    vault = any(token in folded for token in ("credential", "vault"))
    recovery = classification.level >= ModificationTrustLevel.UPDATER_RECOVERY_ROOT_OF_TRUST
    sandbox = any(token in folded for token in ("sandbox", "broker", "network"))
    trusted = classification.level >= ModificationTrustLevel.PERMISSION_BROKER_SECURITY
    return UpdateSecurityImpact(
        classification.level,
        trusted,
        permission or classification.level >= ModificationTrustLevel.PERMISSION_BROKER_SECURITY,
        vault,
        recovery,
        sandbox,
        permission,
        classification.matched_rules,
    )


def _risk_summary(
    changes: UpdateChangeSummary,
    security: UpdateSecurityImpact,
    migration: UpdateMigrationSummary,
    rollback: UpdateRollbackSummary,
    gates: tuple[UpdateGateResult, ...],
) -> UpdateRiskSummary:
    reasons: list[str] = []
    if security.trust_level >= ModificationTrustLevel.UPDATER_RECOVERY_ROOT_OF_TRUST:
        reasons.append("root_of_trust_change")
    elif security.trust_level >= ModificationTrustLevel.PERMISSION_BROKER_SECURITY:
        reasons.append("trusted_security_surface_change")
    if security.permission_surface_changed:
        reasons.append("permission_surface_change")
    if security.credential_vault_changed:
        reasons.append("credential_boundary_change")
    if security.sandbox_or_broker_changed:
        reasons.append("sandbox_or_broker_change")
    if changes.dependency_changes:
        reasons.append("dependency_change")
    if changes.package_changes:
        reasons.append("package_change")
    if changes.user_data_changes or changes.integration_changes:
        reasons.append("data_or_integration_change")
    if (
        migration.database_schema_changed
        or migration.user_data_changed
        or migration.integration_data_changed
    ):
        reasons.append("migration_change")
    if not migration.reversible:
        reasons.append("non_reversible_migration")
    if not rollback.rollback_available:
        reasons.append("rollback_unavailable")
    if any(
        item.status not in {UpdateGateStatus.PASSED, UpdateGateStatus.NOT_APPLICABLE}
        for item in gates
    ):
        reasons.append("gate_not_passed")
    if security.trust_level >= ModificationTrustLevel.UPDATER_RECOVERY_ROOT_OF_TRUST:
        level = UpdateRiskLevel.CRITICAL
    elif (
        security.trust_level >= ModificationTrustLevel.PERMISSION_BROKER_SECURITY
        or not rollback.rollback_available
    ):
        level = UpdateRiskLevel.HIGH
    elif reasons:
        level = UpdateRiskLevel.MEDIUM
    else:
        level = UpdateRiskLevel.LOW
    return UpdateRiskSummary(level, tuple(reasons), level is not UpdateRiskLevel.LOW)


def _bounded_unique(
    values: tuple[str, ...], label: str, maximum: int, *, allow_empty: bool = False
) -> None:
    if not isinstance(values, tuple) or (not allow_empty and not values) or len(values) > maximum:
        raise UpdatePreviewError(f"{label} are malformed")
    if len(values) != len(set(values)):
        raise UpdatePreviewError(f"{label} must be unique")
    for value in values:
        _label(value, label, 512)


def _label(value: str, label: str, maximum: int) -> None:
    if (
        type(value) is not str
        or not value
        or len(value) > maximum
        or value != value.strip()
        or any(not character.isprintable() for character in value)
    ):
        raise UpdatePreviewError(f"{label} is malformed")


def _sha256(value: str, label: str) -> None:
    if (
        type(value) is not str
        or len(value) != 64
        or any(character not in "0123456789abcdef" for character in value)
    ):
        raise UpdatePreviewError(f"{label} must be lowercase SHA-256")


def _revision(value: str, label: str) -> None:
    if (
        type(value) is not str
        or len(value) not in {40, 64}
        or any(character not in "0123456789abcdef" for character in value)
    ):
        raise UpdatePreviewError(f"{label} must be an immutable hexadecimal revision")


def _aware(value: Any, label: str) -> datetime:
    if not isinstance(value, datetime) or value.tzinfo is None:
        raise UpdatePreviewError(f"{label} must be timezone-aware")
    return value.astimezone(UTC)


def _canonical(value: Any) -> Any:
    if isinstance(value, StrEnum):
        return value.value
    if isinstance(value, datetime):
        return value.isoformat()
    if isinstance(value, dict):
        return {str(key): _canonical(item) for key, item in value.items()}
    if isinstance(value, tuple | list):
        return [_canonical(item) for item in value]
    return value


__all__ = [
    "ControlledSelfUpdate",
    "UpdateApprovalBinding",
    "UpdateChangeSummary",
    "UpdateGateName",
    "UpdateGateResult",
    "UpdateGateStatus",
    "UpdateMigrationSummary",
    "UpdatePreview",
    "UpdatePreviewError",
    "UpdatePreviewView",
    "UpdateRiskLevel",
    "UpdateRiskSummary",
    "UpdateRollbackSummary",
    "UpdateSecurityImpact",
]
