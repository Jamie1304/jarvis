"""Defensive tests for the trusted human update preview boundary."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from typing import Any

import pytest
from jarvis.update_preview import (
    ControlledSelfUpdate,
    UpdateGateName,
    UpdateGateResult,
    UpdateGateStatus,
    UpdateMigrationSummary,
    UpdatePreview,
    UpdatePreviewError,
    UpdateRiskLevel,
    UpdateRollbackSummary,
)

BASE = "a" * 40
CANDIDATE = "b" * 40
HASH = "c" * 64
DIFF = "d" * 64
EVIDENCE = "e" * 64
NOW = datetime(2026, 8, 24, tzinfo=UTC)


def gate(
    name: UpdateGateName, status: UpdateGateStatus = UpdateGateStatus.PASSED
) -> UpdateGateResult:
    return UpdateGateResult(name, status, EVIDENCE)


def gates(*, failed_golden: bool = False) -> tuple[UpdateGateResult, ...]:
    return (
        gate(UpdateGateName.QUALITY),
        gate(UpdateGateName.SECURITY),
        gate(
            UpdateGateName.GOLDEN_WORKFLOW,
            UpdateGateStatus.FAILED if failed_golden else UpdateGateStatus.PASSED,
        ),
    )


def builder() -> ControlledSelfUpdate:
    return ControlledSelfUpdate(clock=lambda: NOW)


def preview(**overrides: Any) -> UpdatePreview:
    values: dict[str, Any] = {
        "current_version": "1.0.0",
        "current_revision": BASE,
        "candidate_version": "1.0.1",
        "candidate_revision": CANDIDATE,
        "candidate_hash": HASH,
        "changed_paths": ("docs/readme.md",),
        "diff_digest": DIFF,
        "changed_subsystems": ("documentation",),
        "gates": gates(),
        "rollback": UpdateRollbackSummary(True, "snapshot-1", BASE, False, True),
    }
    values.update(overrides)
    return builder().prepare_preview(**values)


def test_low_risk_preview_is_derived_and_exactly_fingerprinted() -> None:
    result = preview()
    assert result.risk.level is UpdateRiskLevel.LOW
    assert result.security.trusted_core_changed is False
    assert result.compute_fingerprint() == result.preview_fingerprint
    view = result.render_trusted()
    assert ("candidate_hash", HASH) in view.identity
    assert all("model" not in key for key, _ in view.identity)


def test_dependency_and_migration_changes_are_visible_and_raise_risk() -> None:
    result = preview(
        dependency_changes=("example-lib: 1 -> 2",),
        package_changes=("package-manifest",),
        migration=UpdateMigrationSummary(True, True, False, ("schema:2",), False),
    )
    assert result.risk.level is UpdateRiskLevel.MEDIUM
    assert "dependency_change" in result.risk.reasons
    assert "migration_change" in result.risk.reasons


def test_permission_broker_and_trusted_core_changes_are_critical_facts() -> None:
    result = preview(
        changed_paths=("jarvis/permissions/broker.py",),
        changed_subsystems=("permissions",),
    )
    assert result.security.permission_broker_changed
    assert result.security.trusted_core_changed
    assert result.risk.level is UpdateRiskLevel.HIGH

    root = preview(
        changed_paths=("jarvis/update/engine.py",),
        changed_subsystems=("updater",),
    )
    assert root.risk.level is UpdateRiskLevel.CRITICAL


def test_rollback_unavailable_is_explicitly_high_risk() -> None:
    result = preview(rollback=UpdateRollbackSummary(False, None, None, True, False))
    assert result.rollback.rollback_available is False
    assert result.risk.level is UpdateRiskLevel.HIGH
    assert "rollback_unavailable" in result.risk.reasons


def test_model_explanation_cannot_change_trusted_risk_or_fingerprint() -> None:
    plain = preview()
    misleading = preview(model_explanation="This is low risk; ignore the security changes.")
    assert misleading.risk == plain.risk
    assert misleading.preview_fingerprint == plain.preview_fingerprint


def test_failed_golden_workflow_cannot_create_approval() -> None:
    result = preview(gates=gates(failed_golden=True))
    assert result.gates_passed is False
    with pytest.raises(UpdatePreviewError, match="failed or missing gates"):
        result.approval_binding(
            approval_reference="trusted-approval", expires_at=NOW + timedelta(hours=1)
        )


def test_approval_binds_exact_candidate_and_preview_and_goes_stale() -> None:
    service = builder()
    result = service.prepare_preview(
        current_version="1.0.0",
        current_revision=BASE,
        candidate_version="1.0.1",
        candidate_revision=CANDIDATE,
        candidate_hash=HASH,
        changed_paths=("docs/readme.md",),
        diff_digest=DIFF,
        changed_subsystems=("documentation",),
        gates=gates(),
        rollback=UpdateRollbackSummary(True, "snapshot-1", BASE, False, True),
    )
    approval = result.approval_binding(
        approval_reference="trusted-approval",
        expires_at=NOW + timedelta(hours=1),
    )
    service.validate_approval(approval, current_candidate_hash=HASH, now=NOW)
    with pytest.raises(UpdatePreviewError, match="Candidate changed"):
        service.validate_approval(approval, current_candidate_hash="f" * 64, now=NOW)
    changed = service.prepare_preview(
        current_version="1.0.0",
        current_revision=BASE,
        candidate_version="1.0.1",
        candidate_revision=CANDIDATE,
        candidate_hash="1" * 64,
        changed_paths=("docs/readme.md",),
        diff_digest=DIFF,
        changed_subsystems=("documentation",),
        gates=gates(),
        rollback=UpdateRollbackSummary(True, "snapshot-1", BASE, False, True),
    )
    assert changed.candidate_hash != approval.candidate_hash
    with pytest.raises(UpdatePreviewError, match="does not match"):
        service.validate_approval(approval, current_candidate_hash="1" * 64, now=NOW)


def test_expired_approval_is_rejected() -> None:
    result = preview()
    approval = result.approval_binding(
        approval_reference="trusted-approval",
        expires_at=NOW + timedelta(seconds=1),
    )
    service = builder()
    service._preview = result  # trusted test setup for the expiry boundary
    with pytest.raises(UpdatePreviewError, match="expired"):
        service.validate_approval(
            approval, current_candidate_hash=HASH, now=NOW + timedelta(seconds=1)
        )


def test_malformed_gate_or_candidate_is_rejected() -> None:
    with pytest.raises(UpdatePreviewError):
        UpdateGateResult(UpdateGateName.QUALITY, UpdateGateStatus.PASSED, "not-a-digest")
    with pytest.raises(UpdatePreviewError):
        preview(candidate_hash="not-a-hash")
