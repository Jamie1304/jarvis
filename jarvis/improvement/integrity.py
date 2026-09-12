"""Canonical fingerprints for exact, non-reusable improvement proposals."""

from __future__ import annotations

import hashlib
import json
from dataclasses import asdict
from datetime import datetime
from enum import Enum
from pathlib import Path
from typing import Any
from uuid import UUID

from jarvis.improvement.models import (
    ChangeSpecification,
    DependencyAssessment,
    EvaluationResult,
    GateResult,
    ImprovementCandidate,
    IsolatedWorkspace,
    ModificationResult,
    ProposalStatus,
    RollbackMetadata,
)


def compute_proposal_fingerprint(
    *,
    proposal_id: str,
    task_id: UUID,
    candidate: ImprovementCandidate,
    specification: ChangeSpecification,
    workspace: IsolatedWorkspace,
    modification: ModificationResult,
    dependency_assessment: DependencyAssessment,
    gates: tuple[GateResult, ...],
    evaluation: EvaluationResult,
    rollback: RollbackMetadata,
    created_at: datetime,
    expires_at: datetime,
    status: ProposalStatus = ProposalStatus.AWAITING_TRUSTED_APPROVAL,
) -> str:
    """Bind every displayed, execution, evaluation, and rollback field."""

    payload = {
        "proposal_id": proposal_id,
        "task_id": task_id,
        "candidate": asdict(candidate),
        "specification": asdict(specification),
        "workspace": asdict(workspace),
        "modification": asdict(modification),
        "dependency_assessment": asdict(dependency_assessment),
        "gates": [asdict(item) for item in sorted(gates, key=lambda gate: gate.kind.value)],
        "evaluation": asdict(evaluation),
        "rollback": asdict(rollback),
        "created_at": created_at,
        "expires_at": expires_at,
        "status": status,
    }
    encoded = json.dumps(
        _canonical(payload),
        sort_keys=True,
        separators=(",", ":"),
        allow_nan=False,
    ).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


def _canonical(value: Any) -> Any:
    if isinstance(value, Enum):
        return value.value
    if isinstance(value, UUID):
        return str(value)
    if isinstance(value, datetime):
        return value.isoformat()
    if isinstance(value, Path):
        return str(value)
    if isinstance(value, dict):
        return {str(key): _canonical(item) for key, item in value.items()}
    if isinstance(value, tuple | list):
        return [_canonical(item) for item in value]
    if isinstance(value, set | frozenset):
        return sorted((_canonical(item) for item in value), key=repr)
    return value
