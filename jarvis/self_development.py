"""Trusted, recovery-safe activation for tested self-development proposals.

The improvement subsystem deliberately stops at a proposal.  This module is
the separate application-owned boundary that may consume such a proposal.  It
does not expose a model tool: callers must provide trusted approval, current
gate evidence, and the existing PermissionBroker/Recovery authorities.
"""

from __future__ import annotations

import hashlib
import inspect
import json
import os
import shutil
import sqlite3
import subprocess
import tempfile
from collections.abc import Awaitable, Callable, Mapping, Sequence
from dataclasses import asdict, dataclass, replace
from datetime import UTC, datetime
from enum import StrEnum
from pathlib import Path
from typing import Any, Protocol
from uuid import UUID, uuid4, uuid5

from jarvis.improvement.integrity import compute_proposal_fingerprint
from jarvis.improvement.models import (
    MergeDeploymentProposal,
    ProposalStatus,
)
from jarvis.permissions.approval import ApprovalContextVerifier, TrustedApprovalContext
from jarvis.permissions.broker import PermissionBroker
from jarvis.permissions.models import (
    ActionDescriptor,
    ApprovalChoice,
    AuthorizationResult,
    Permission,
    PermissionRequest,
    PermissionScope,
    Risk,
    SafeArgument,
    SafetyClass,
)
from jarvis.recovery import RecoveryCoordinator, RecoveryError
from jarvis.security.modification_policy import (
    ModificationTrustClassification,
    ModificationTrustClassifier,
    ModificationTrustLevel,
)
from jarvis.update_preview import (
    ControlledSelfUpdate,
    UpdateGateResult,
    UpdateMigrationSummary,
    UpdatePreview,
)


class ActivationError(RuntimeError):
    """A trusted activation was rejected or could not be completed safely."""


class ActivationStatus(StrEnum):
    AWAITING_APPROVAL = "awaiting_approval"
    APPROVED = "approved"
    PREPARING = "preparing"
    SNAPSHOT_CREATED = "snapshot_created"
    APPLY_INTENT_PERSISTED = "apply_intent_persisted"
    APPLYING = "applying"
    APPLIED = "applied"
    STARTING = "starting"
    VERIFYING = "verifying"
    COMMITTED = "committed"
    DENIED = "denied"
    EXPIRED = "expired"
    STALE = "stale"
    FAILED = "failed"
    ROLLED_BACK = "rolled_back"
    QUARANTINED = "quarantined"
    SAFE_MODE_REQUIRED = "safe_mode_required"


@dataclass(frozen=True, slots=True)
class GateEvidence:
    """Trusted, independently produced activation-gate evidence."""

    name: str
    passed: bool
    evidence_digest: str

    def __post_init__(self) -> None:
        if not self.name or any(character.isspace() for character in self.name):
            raise ValueError("Gate name is malformed")
        if type(self.passed) is not bool or len(self.evidence_digest) != 64:
            raise ValueError("Gate evidence is malformed")
        int(self.evidence_digest, 16)


@dataclass(frozen=True, slots=True)
class ActivationRecord:
    activation_id: str
    proposal_id: str
    proposal_fingerprint: str
    task_id: UUID
    base_revision: str
    candidate_revision: str
    candidate_hash: str
    candidate_tree_digest: str
    candidate_diff_digest: str
    changed_paths: tuple[str, ...]
    trust_level: int
    required_gates: tuple[str, ...]
    preview_fingerprint: str
    created_at: datetime
    expires_at: datetime
    status: ActivationStatus = ActivationStatus.AWAITING_APPROVAL
    approval_actor: str | None = None
    approval_expires_at: datetime | None = None
    recovery_transaction_id: str | None = None
    recovery_snapshot_id: str | None = None
    candidate_snapshot_id: str | None = None
    effect_receipt_id: str | None = None
    failure_reason: str | None = None

    def __post_init__(self) -> None:
        if not self.activation_id or not self.proposal_id:
            raise ValueError("Activation identity is required")
        for value in (
            self.proposal_fingerprint,
            self.candidate_hash,
            self.candidate_tree_digest,
            self.candidate_diff_digest,
            self.preview_fingerprint,
        ):
            if len(value) != 64:
                raise ValueError("Activation digest is malformed")
            int(value, 16)
        if not isinstance(self.task_id, UUID) or not isinstance(self.status, ActivationStatus):
            raise ValueError("Activation typed state is malformed")
        if self.created_at.tzinfo is None or self.expires_at.tzinfo is None:
            raise ValueError("Activation timestamps must be timezone-aware")
        if self.expires_at <= self.created_at:
            raise ValueError("Activation expiry must follow creation")
        if not self.changed_paths or len(set(self.changed_paths)) != len(self.changed_paths):
            raise ValueError("Activation paths must be unique")
        if self.trust_level not in {1, 2, 3}:
            raise ValueError("Routine self-development only accepts trust levels 1 to 3")


class ActivationStateStore:
    """Small durable store for activation intent and terminal evidence."""

    def __init__(self, path: Path) -> None:
        self.path = path.expanduser().resolve()
        self.path.parent.mkdir(parents=True, exist_ok=True)
        with sqlite3.connect(self.path) as connection:
            connection.execute(
                "CREATE TABLE IF NOT EXISTS activations "
                "(activation_id TEXT PRIMARY KEY, payload TEXT NOT NULL)"
            )

    def put(self, record: ActivationRecord) -> None:
        payload = json.dumps(_record_to_json(record), sort_keys=True, separators=(",", ":"))
        with sqlite3.connect(self.path) as connection:
            connection.execute(
                "INSERT INTO activations(activation_id,payload) VALUES(?,?) "
                "ON CONFLICT(activation_id) DO UPDATE SET payload=excluded.payload",
                (record.activation_id, payload),
            )

    def get(self, activation_id: str) -> ActivationRecord | None:
        with sqlite3.connect(self.path) as connection:
            row = connection.execute(
                "SELECT payload FROM activations WHERE activation_id=?", (activation_id,)
            ).fetchone()
        return None if row is None else _record_from_json(json.loads(str(row[0])))


class ProposalLoader(Protocol):
    def __call__(self, proposal_id: str) -> MergeDeploymentProposal | None: ...


GateVerifier = Callable[
    [MergeDeploymentProposal, ModificationTrustClassification],
    Mapping[str, GateEvidence] | Awaitable[Mapping[str, GateEvidence]],
]
GoldenRunner = Callable[[], object | Awaitable[object]]
HealthCheck = Callable[[], bool]

_APPROVAL_BINDING_NAMESPACE = UUID("7b6eb5c1-5fd3-5ae6-a1ab-15b4e5a98eaf")


class TrustedSelfDevelopmentActivator:
    """Application-owned composition root for exact local candidate activation."""

    TOOL_ID = "trusted.self-development-activation"

    def __init__(
        self,
        *,
        production_root: Path,
        installation_root: Path,
        recovery: RecoveryCoordinator,
        activation_store: ActivationStateStore,
        permission_broker: PermissionBroker,
        approval_verifier: ApprovalContextVerifier,
        proposal_loader: ProposalLoader,
        gate_verifier: GateVerifier,
        golden_runner: GoldenRunner,
        clock: Callable[[], datetime] | None = None,
    ) -> None:
        self.production_root = _directory(production_root, "production root")
        self.installation_root = _directory(installation_root, "installation root")
        if self.production_root == self.installation_root:
            raise ActivationError("live production checkout cannot be the activation target")
        self.recovery = recovery
        self.store = activation_store
        self.broker = permission_broker
        self._approval_verifier = approval_verifier
        self._proposal_loader = proposal_loader
        self._gate_verifier = gate_verifier
        self._golden_runner = golden_runner
        self._clock = clock or (lambda: datetime.now(UTC))
        self._preview: dict[str, UpdatePreview] = {}
        self._identity = object()
        self.broker.register_tool(
            self.TOOL_ID,
            self._identity,
            frozenset({Permission.CODE_MODIFY, Permission.FILESYSTEM_WRITE}),
        )

    def prepare(
        self,
        proposal: MergeDeploymentProposal,
        *,
        current_version: str,
        candidate_version: str,
        changed_subsystems: tuple[str, ...],
        preview_gates: tuple[UpdateGateResult, ...],
        migration: UpdateMigrationSummary | None = None,
    ) -> ActivationRecord:
        """Create a durable awaiting-approval activation from trusted facts."""

        self._assert_proposal_identity(proposal)
        classification = ModificationTrustClassifier().classify(proposal.modification.changed_paths)
        self._assert_routine_eligible(proposal, classification)
        candidate_hash = _candidate_hash(proposal)
        workspace = _candidate_workspace(proposal)
        tree_digest = _tree_digest(workspace)
        if tree_digest != proposal.modification.tree_digest:
            raise ActivationError("candidate tree does not match tested proposal")
        diff_digest = _git_diff_digest(
            workspace, proposal.workspace.base_revision, proposal.modification.changed_paths
        )
        preview = ControlledSelfUpdate(clock=self._clock).prepare_preview(
            current_version=current_version,
            current_revision=proposal.workspace.base_revision,
            candidate_version=candidate_version,
            candidate_revision=proposal.modification.candidate_revision or candidate_hash,
            candidate_hash=candidate_hash,
            changed_paths=proposal.modification.changed_paths,
            diff_digest=proposal.modification.diff_digest,
            changed_subsystems=changed_subsystems,
            dependency_changes=tuple(
                change.name for change in proposal.dependency_assessment.changes
            ),
            migration=migration,
            gates=preview_gates,
            model_explanation=None,
        )
        now = _aware(self._clock())
        record = ActivationRecord(
            activation_id=str(uuid4()),
            proposal_id=proposal.proposal_id,
            proposal_fingerprint=proposal.proposal_fingerprint,
            task_id=proposal.task_id,
            base_revision=proposal.workspace.base_revision,
            candidate_revision=proposal.modification.candidate_revision or candidate_hash,
            candidate_hash=candidate_hash,
            candidate_tree_digest=tree_digest,
            candidate_diff_digest=diff_digest,
            changed_paths=proposal.modification.changed_paths,
            trust_level=int(classification.level),
            required_gates=classification.required_gates,
            preview_fingerprint=preview.preview_fingerprint,
            created_at=now,
            expires_at=proposal.expires_at,
        )
        self.store.put(record)
        self._preview[record.activation_id] = preview
        return record

    async def approve(
        self, activation_id: str, context: TrustedApprovalContext
    ) -> ActivationRecord:
        """Consume one authenticated trusted-user approval for this activation."""

        record = self._require(activation_id)
        if record.status is not ActivationStatus.AWAITING_APPROVAL:
            if record.status is ActivationStatus.DENIED:
                return record
            raise ActivationError("activation is not awaiting approval")
        proposal = self._proposal_loader(record.proposal_id)
        if proposal is None:
            return self._fail(record, ActivationStatus.STALE, "proposal unavailable")
        try:
            self._revalidate(record, proposal)
        except ActivationError as error:
            return self._fail(record, _activation_failure_status(str(error)), str(error))
        if context.request_id != approval_request_id(record):
            raise ActivationError("approval is bound to a different exact candidate")
        verification = self._approval_verifier.verify_and_consume(context)
        if not verification.accepted or verification.context is None:
            raise ActivationError(f"trusted approval rejected: {verification.reason.value}")
        verified = verification.context
        if verified.choice is not ApprovalChoice.APPROVE_ONCE:
            return self._fail(
                record,
                ActivationStatus.DENIED,
                f"trusted approval choice is not approve_once: {verified.choice.value}",
            )
        if verified.expires_at > record.expires_at:
            raise ActivationError("approval exceeds proposal expiry")
        updated = replace(
            record,
            status=ActivationStatus.APPROVED,
            approval_actor=verified.identity.identity_id,
            approval_expires_at=verified.expires_at,
        )
        self.store.put(updated)
        return updated

    async def activate(
        self,
        activation_id: str,
        *,
        start_candidate: Callable[[], None] | None = None,
        health_check: HealthCheck | None = None,
        security_check: HealthCheck | None = None,
        lkg_health_check: HealthCheck | None = None,
        permission_context: TrustedApprovalContext | None = None,
        permission_contexts: tuple[TrustedApprovalContext, ...] = (),
    ) -> ActivationRecord:
        """Revalidate, authorize, apply once, verify, and promote or recover."""

        record = self._require(activation_id)
        if record.status is ActivationStatus.DENIED:
            return record
        proposal = self._proposal_loader(record.proposal_id)
        if proposal is None:
            return self._fail(record, ActivationStatus.STALE, "proposal unavailable")
        try:
            self._revalidate(record, proposal)
            record = self._require_approved(record)
            evidence = await _maybe(self._gate_verifier(proposal, self._classification(proposal)))
            self._require_gates(record.required_gates, evidence)
            golden = await _maybe(self._golden_runner())
            if golden is not True:
                raise ActivationError("SELF_IMPROVEMENT GoldenWorkflow did not pass")
            record = self._transition(record, ActivationStatus.PREPARING)
            transaction_id = str(uuid4())
            snapshot_id = self._snapshot_current(transaction_id, record.changed_paths, proposal)
            record = self._transition(
                record,
                ActivationStatus.SNAPSHOT_CREATED,
                recovery_transaction_id=transaction_id,
                recovery_snapshot_id=snapshot_id,
            )
            authorization = await self._authorize_effect(record)
            supplied_permission_contexts = permission_contexts + (
                (permission_context,) if permission_context is not None else ()
            )
            if not authorization.authorized or authorization.receipt is None:
                for pending in authorization.approval_requests:
                    context = next(
                        (
                            item
                            for item in supplied_permission_contexts
                            if item.request_id == pending.request_id
                        ),
                        None,
                    )
                    if context is None:
                        raise ActivationError(
                            "PermissionBroker approval is required for every exact effect scope"
                        )
                    decision = await self.broker.decide(context)
                    if not decision.accepted:
                        raise ActivationError(
                            f"PermissionBroker approval rejected: {decision.reason.value}"
                        )
                if authorization.approval_requests:
                    authorization = await self._authorize_effect(record)
                if not authorization.authorized or authorization.receipt is None:
                    raise ActivationError(
                        f"PermissionBroker denied effect: {authorization.reason.value}"
                    )
            record = self._transition(
                record,
                ActivationStatus.APPLY_INTENT_PERSISTED,
                effect_receipt_id=str(authorization.receipt.receipt_id),
            )
            begin_reason = await self.broker.begin_execution(authorization.receipt)
            if begin_reason is not None:
                raise ActivationError(f"effect receipt unavailable: {begin_reason.value}")
            record = self._transition(record, ActivationStatus.APPLYING)
            try:
                self._apply_exact(proposal)
            except Exception as error:
                await self.broker.record_execution_outcome(authorization.receipt, "unknown_outcome")
                return self._fail(
                    record,
                    ActivationStatus.QUARANTINED,
                    f"apply outcome unknown: {type(error).__name__}",
                )
            await self.broker.record_execution_outcome(authorization.receipt, "success")
            if _installed_candidate_hash(proposal, self.installation_root) != record.candidate_hash:
                raise ActivationError("installed candidate hash does not match exact candidate")
            record = self._transition(record, ActivationStatus.APPLIED)
            candidate_snapshot = self._snapshot_candidate(
                record.recovery_transaction_id or transaction_id, record.changed_paths, proposal
            )
            record = self._transition(
                record,
                ActivationStatus.STARTING,
                candidate_snapshot_id=candidate_snapshot,
            )
            coordinator = self.recovery
            result = coordinator.boot_candidate(
                record.recovery_transaction_id or transaction_id,
                candidate_snapshot,
                start=start_candidate or (lambda: None),
                health_check=lambda: bool(
                    (health_check or (lambda: True))() and (security_check or (lambda: True))()
                ),
                lkg_health_check=lkg_health_check or (lambda: True),
                destinations={
                    path: self.installation_root / Path(path) for path in record.changed_paths
                },
            )
            if result == candidate_snapshot:
                return self._transition(record, ActivationStatus.COMMITTED)
            if coordinator.safe_mode:
                return self._fail(
                    record,
                    ActivationStatus.SAFE_MODE_REQUIRED,
                    "rollback could not establish known-good",
                )
            return self._fail(record, ActivationStatus.ROLLED_BACK, "candidate verification failed")
        except (ActivationError, RecoveryError) as error:
            detail = str(error)
            terminal = _activation_failure_status(detail)
            return self._fail(record, terminal, detail)
        except Exception as error:
            return self._fail(
                record,
                ActivationStatus.QUARANTINED,
                f"activation failed closed: {type(error).__name__}",
            )

    async def resume(
        self,
        activation_id: str,
        *,
        start_candidate: Callable[[], None] | None = None,
        health_check: HealthCheck | None = None,
        security_check: HealthCheck | None = None,
        lkg_health_check: HealthCheck | None = None,
    ) -> ActivationRecord:
        """Reconstruct durable state and reconcile an interrupted effect.

        APPLYING is never copied again.  A matching installed candidate resumes
        verification; contradictory state is quarantined.
        """

        record = self._require(activation_id)
        if record.status is ActivationStatus.DENIED:
            return record
        proposal = self._proposal_loader(record.proposal_id)
        if proposal is None:
            return self._fail(
                record, ActivationStatus.QUARANTINED, "proposal unavailable during recovery"
            )
        if record.status not in {
            ActivationStatus.APPLYING,
            ActivationStatus.APPLY_INTENT_PERSISTED,
            ActivationStatus.APPLIED,
        }:
            return record
        try:
            current = _installed_candidate_hash(proposal, self.installation_root)
            if current != record.candidate_hash:
                old = _known_good_candidate_hash(self.recovery, proposal)
                if old is not None and current == old:
                    return self._fail(
                        record, ActivationStatus.FAILED, "effect did not start; no automatic retry"
                    )
                return self._fail(
                    record, ActivationStatus.QUARANTINED, "ambiguous activation state"
                )
            if record.candidate_snapshot_id is None:
                snapshot = self._snapshot_candidate(
                    record.recovery_transaction_id or str(uuid4()), record.changed_paths, proposal
                )
                record = self._transition(
                    record, ActivationStatus.APPLIED, candidate_snapshot_id=snapshot
                )
            candidate_snapshot_id = record.candidate_snapshot_id
            if candidate_snapshot_id is None:
                raise ActivationError("candidate snapshot is unavailable during recovery")
            result = self.recovery.boot_candidate(
                record.recovery_transaction_id or str(uuid4()),
                candidate_snapshot_id,
                start=start_candidate or (lambda: None),
                health_check=lambda: bool(
                    (health_check or (lambda: True))() and (security_check or (lambda: True))()
                ),
                lkg_health_check=lkg_health_check or (lambda: True),
                destinations={
                    path: self.installation_root / Path(path) for path in record.changed_paths
                },
            )
            if result == candidate_snapshot_id:
                return self._transition(record, ActivationStatus.COMMITTED)
            if self.recovery.safe_mode:
                return self._fail(
                    record, ActivationStatus.SAFE_MODE_REQUIRED, "recovery failed during resume"
                )
            return self._fail(
                record, ActivationStatus.ROLLED_BACK, "candidate verification failed during resume"
            )
        except Exception as error:
            return self._fail(
                record,
                ActivationStatus.QUARANTINED,
                f"reconciliation failed: {type(error).__name__}",
            )

    def _assert_proposal_identity(self, proposal: MergeDeploymentProposal) -> None:
        expected = compute_proposal_fingerprint(
            proposal_id=proposal.proposal_id,
            task_id=proposal.task_id,
            candidate=proposal.candidate,
            specification=proposal.specification,
            workspace=proposal.workspace,
            modification=proposal.modification,
            dependency_assessment=proposal.dependency_assessment,
            gates=proposal.gates,
            evaluation=proposal.evaluation,
            rollback=proposal.rollback,
            created_at=proposal.created_at,
            expires_at=proposal.expires_at,
            status=proposal.status,
        )
        if (
            expected != proposal.proposal_fingerprint
            or proposal.status is not ProposalStatus.AWAITING_TRUSTED_APPROVAL
        ):
            raise ActivationError("proposal fingerprint or status is not trusted")

    def _assert_routine_eligible(
        self, proposal: MergeDeploymentProposal, classification: ModificationTrustClassification
    ) -> None:
        if classification.level > ModificationTrustLevel.CORE_AGENT_RUNTIME:
            raise ActivationError("Level 4/5 candidate requires trusted release authority")
        if proposal.dependency_assessment.changes:
            raise ActivationError("dependency-changing self-activation is blocked")

    def _classification(self, proposal: MergeDeploymentProposal) -> ModificationTrustClassification:
        classification = ModificationTrustClassifier().classify(proposal.modification.changed_paths)
        self._assert_routine_eligible(proposal, classification)
        return classification

    def _revalidate(self, record: ActivationRecord, proposal: MergeDeploymentProposal) -> None:
        now = _aware(self._clock())
        if now >= record.expires_at or now >= proposal.expires_at:
            raise ActivationError("proposal has expired")
        if (
            proposal.proposal_id != record.proposal_id
            or proposal.proposal_fingerprint != record.proposal_fingerprint
        ):
            raise ActivationError("proposal fingerprint is stale")
        self._assert_proposal_identity(proposal)
        classification = self._classification(proposal)
        if (
            int(classification.level) != record.trust_level
            or classification.required_gates != record.required_gates
        ):
            raise ActivationError("trusted classification changed")
        expected_revision = proposal.modification.candidate_revision or _candidate_hash(proposal)
        if expected_revision != record.candidate_revision:
            raise ActivationError("candidate revision changed")
        if proposal.expires_at != record.expires_at:
            raise ActivationError("proposal expiry changed")
        if tuple(proposal.modification.changed_paths) != record.changed_paths:
            raise ActivationError("changed paths are stale")
        workspace = _candidate_workspace(proposal)
        if _git_head(workspace) != record.base_revision:
            raise ActivationError("candidate base revision changed")
        if _git_head(self.production_root) != record.base_revision:
            raise ActivationError("production base revision drifted")
        if _tree_digest(workspace) != record.candidate_tree_digest:
            raise ActivationError("candidate tree changed after testing")
        if (
            _git_diff_digest(workspace, record.base_revision, record.changed_paths)
            != record.candidate_diff_digest
        ):
            raise ActivationError("candidate diff changed after testing")
        if _candidate_hash(proposal) != record.candidate_hash:
            raise ActivationError("candidate hash changed")
        if record.status is ActivationStatus.APPROVED:
            if record.approval_expires_at is None or now >= record.approval_expires_at:
                raise ActivationError("trusted approval has expired")

    def _require_approved(self, record: ActivationRecord) -> ActivationRecord:
        if record.status is not ActivationStatus.APPROVED:
            raise ActivationError("trusted approval is required")
        return record

    def _require_gates(self, required: Sequence[str], evidence: Mapping[str, GateEvidence]) -> None:
        for name in required:
            item = evidence.get(name)
            if item is None or item.name != name or not item.passed:
                raise ActivationError(f"required gate did not pass: {name}")

    async def _authorize_effect(self, record: ActivationRecord) -> AuthorizationResult:
        paths = tuple(
            str((self.installation_root / Path(path)).resolve()) for path in record.changed_paths
        )
        scope = PermissionScope(paths=paths, tool_id=self.TOOL_ID, task_id=record.task_id)
        descriptor = ActionDescriptor(
            "activate_exact_self_development",
            tuple(
                SafeArgument(name, value)
                for name, value in (("activation_id", record.activation_id),)
            ),
            Risk.CRITICAL,
            tuple(
                PermissionRequest(permission, scope)
                for permission in (Permission.CODE_MODIFY, Permission.FILESYSTEM_WRITE)
            ),
            SafetyClass.SELF_MODIFICATION,
        )
        return await self.broker.authorize(
            tool_id=self.TOOL_ID,
            tool_identity=self._identity,
            declared_permissions=frozenset({Permission.CODE_MODIFY, Permission.FILESYSTEM_WRITE}),
            task_id=record.task_id,
            user_id=record.approval_actor,
            descriptor=descriptor,
            normalized_arguments={
                "activation_id": record.activation_id,
                "candidate_hash": record.candidate_hash,
            },
        )

    def _snapshot_current(
        self, transaction_id: str, paths: tuple[str, ...], proposal: MergeDeploymentProposal
    ) -> str:
        return self._snapshot(transaction_id, paths, proposal, candidate=False)

    def _snapshot_candidate(
        self, transaction_id: str, paths: tuple[str, ...], proposal: MergeDeploymentProposal
    ) -> str:
        return self._snapshot(transaction_id, paths, proposal, candidate=True)

    def _snapshot(
        self,
        transaction_id: str,
        paths: tuple[str, ...],
        proposal: MergeDeploymentProposal,
        *,
        candidate: bool,
    ) -> str:
        copied: list[Path] = []
        for relative in paths:
            source = self.installation_root / Path(relative)
            if source.exists():
                if not source.is_file() or source.is_symlink() or source.is_junction():
                    raise ActivationError("installation contains a non-regular file")
                target = self.recovery.store.root / Path(relative)
                if Path(relative).parts and Path(relative).parts[0].casefold() in {
                    "snapshots",
                    "evidence.jsonl",
                    "active-start.json",
                    "last-known-good.json",
                }:
                    raise ActivationError("activation path overlaps recovery metadata")
                target.parent.mkdir(parents=True, exist_ok=True)
                shutil.copy2(source, target)
                copied.append(target)
        try:
            manifest = self.recovery.store.create_snapshot(
                transaction_id=transaction_id,
                app_revision=(
                    proposal.modification.candidate_revision
                    if candidate
                    else proposal.workspace.base_revision
                )
                or record_revision(proposal),
                application_hash=_tree_digest(self.installation_root),
                configuration={},
                database_schema={},
                integration_versions={},
                files=tuple(copied),
            )
            return manifest.snapshot_id
        finally:
            for source in reversed(copied):
                source.unlink(missing_ok=True)

    def _apply_exact(self, proposal: MergeDeploymentProposal) -> None:
        workspace = _candidate_workspace(proposal)
        for relative in proposal.modification.changed_paths:
            source = workspace / Path(relative)
            target = self.installation_root / Path(relative)
            _contained_regular_target(target, self.installation_root)
            if source.exists():
                if not source.is_file() or source.is_symlink() or source.is_junction():
                    raise ActivationError("candidate changed path is not a regular file")
                target.parent.mkdir(parents=True, exist_ok=True)
                with tempfile.NamedTemporaryFile(dir=target.parent, delete=False) as handle:
                    temporary = Path(handle.name)
                    handle.write(source.read_bytes())
                try:
                    os.replace(temporary, target)
                finally:
                    temporary.unlink(missing_ok=True)
            else:
                if target.exists():
                    target.unlink()

    def _require(self, activation_id: str) -> ActivationRecord:
        record = self.store.get(activation_id)
        if record is None:
            raise ActivationError("activation record is unavailable")
        return record

    def _transition(
        self, record: ActivationRecord, status: ActivationStatus, **changes: Any
    ) -> ActivationRecord:
        updated = replace(record, status=status, **changes)
        self.store.put(updated)
        return updated

    def _fail(
        self, record: ActivationRecord, status: ActivationStatus, reason: str
    ) -> ActivationRecord:
        return self._transition(record, status, failure_reason=reason)


def record_revision(proposal: MergeDeploymentProposal) -> str:
    return proposal.modification.candidate_revision or proposal.workspace.base_revision


def approval_binding_fingerprint(record: ActivationRecord) -> str:
    """Return the canonical digest of the exact candidate approval facts."""

    payload = {
        "activation_id": record.activation_id,
        "task_id": str(record.task_id),
        "proposal_id": record.proposal_id,
        "proposal_fingerprint": record.proposal_fingerprint,
        "base_revision": record.base_revision,
        "candidate_revision": record.candidate_revision,
        "candidate_hash": record.candidate_hash,
        "candidate_tree_digest": record.candidate_tree_digest,
        "candidate_diff_digest": record.candidate_diff_digest,
        "changed_paths": list(record.changed_paths),
        "trust_level": record.trust_level,
        "required_gates": list(record.required_gates),
        "preview_fingerprint": record.preview_fingerprint,
        "activation_expires_at": record.expires_at.astimezone(UTC).isoformat(),
        "proposal_expires_at": record.expires_at.astimezone(UTC).isoformat(),
    }
    encoded = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


def approval_request_id(record: ActivationRecord) -> UUID:
    """Derive the opaque trusted approval request from exact typed state."""

    return uuid5(_APPROVAL_BINDING_NAMESPACE, approval_binding_fingerprint(record))


def _activation_failure_status(detail: str) -> ActivationStatus:
    return (
        ActivationStatus.EXPIRED
        if "expired" in detail
        else ActivationStatus.STALE
        if any(
            marker in detail
            for marker in ("stale", "changed", "drift", "fingerprint", "classification")
        )
        else ActivationStatus.FAILED
    )


def _directory(path: Path, label: str) -> Path:
    resolved = path.expanduser().resolve()
    if not resolved.is_dir() or resolved.is_symlink() or resolved.is_junction():
        raise ActivationError(f"{label} is not a regular directory")
    return resolved


def _candidate_workspace(proposal: MergeDeploymentProposal) -> Path:
    root = proposal.workspace.root.expanduser().resolve()
    if not root.is_dir() or root.is_symlink() or root.is_junction():
        raise ActivationError("retained candidate workspace is unavailable")
    return root


def _contained_regular_target(path: Path, root: Path) -> None:
    resolved_root = root.resolve()
    candidate = path.resolve(strict=False)
    if resolved_root not in (candidate, *candidate.parents):
        raise ActivationError("activation target escaped installation root")
    current = resolved_root
    for part in candidate.relative_to(resolved_root).parts:
        current = current / part
        if current.is_symlink() or current.is_junction():
            raise ActivationError("activation target contains a link")


def _tree_digest(root: Path) -> str:
    digest = hashlib.sha256()
    for path in sorted(root.rglob("*"), key=lambda item: item.as_posix().casefold()):
        relative = path.relative_to(root).as_posix()
        if relative == ".git" or relative.startswith(".git/"):
            continue
        if path.is_symlink() or path.is_junction():
            raise ActivationError("links and junctions are forbidden")
        if path.is_dir():
            continue
        if not path.is_file():
            raise ActivationError("candidate tree contains a non-regular file")
        digest.update(relative.encode("utf-8"))
        digest.update(b"\x00")
        digest.update(hashlib.sha256(path.read_bytes()).digest())
    return digest.hexdigest()


def _git_head(root: Path) -> str:
    result = subprocess.run(
        ["git", "-C", str(root), "rev-parse", "HEAD"],
        check=False,
        capture_output=True,
        text=True,
        timeout=30,
    )
    if result.returncode != 0:
        raise ActivationError("candidate or production Git identity is unavailable")
    return result.stdout.strip()


def _git_diff_digest(root: Path, base: str, paths: Sequence[str]) -> str:
    result = subprocess.run(
        ["git", "-C", str(root), "diff", "--binary", base, "--", *paths],
        check=False,
        capture_output=True,
        timeout=30,
    )
    if result.returncode != 0:
        raise ActivationError("candidate diff identity is unavailable")
    return hashlib.sha256(result.stdout).hexdigest()


def _candidate_hash(proposal: MergeDeploymentProposal) -> str:
    root = _candidate_workspace(proposal)
    digest = hashlib.sha256()
    for relative in proposal.modification.changed_paths:
        source = root / Path(relative)
        digest.update(relative.encode("utf-8"))
        digest.update(b"\x00")
        if source.exists():
            if not source.is_file() or source.is_symlink() or source.is_junction():
                raise ActivationError("candidate changed path is not a regular file")
            digest.update(hashlib.sha256(source.read_bytes()).digest())
        else:
            digest.update(b"<missing>")
    return digest.hexdigest()


def _installed_candidate_hash(proposal: MergeDeploymentProposal, root: Path) -> str:
    digest = hashlib.sha256()
    for relative in proposal.modification.changed_paths:
        source = root / Path(relative)
        digest.update(relative.encode("utf-8"))
        digest.update(b"\x00")
        if source.exists():
            if not source.is_file() or source.is_symlink() or source.is_junction():
                raise ActivationError("installation changed path is not a regular file")
            digest.update(hashlib.sha256(source.read_bytes()).digest())
        else:
            digest.update(b"<missing>")
    return digest.hexdigest()


def _known_good_candidate_hash(
    recovery: RecoveryCoordinator, proposal: MergeDeploymentProposal
) -> str | None:
    record = recovery.store.last_known_good_record()
    if record is None:
        return None
    manifest = recovery.store.load(record.snapshot_id)
    hashes = dict(manifest.file_hashes)
    digest = hashlib.sha256()
    for relative in proposal.modification.changed_paths:
        digest.update(relative.encode("utf-8"))
        digest.update(b"\x00")
        expected = hashes.get(relative)
        digest.update(bytes.fromhex(expected) if expected is not None else b"<missing>")
    return digest.hexdigest()


def _activation_uuid(value: str) -> UUID:
    try:
        return UUID(value)
    except ValueError as error:
        raise ActivationError("activation identity is not a UUID") from error


def _aware(value: datetime) -> datetime:
    if value.tzinfo is None:
        raise ActivationError("activation clock must be timezone-aware")
    return value.astimezone(UTC)


def _record_to_json(record: ActivationRecord) -> dict[str, Any]:
    value = asdict(record)
    for key in ("task_id",):
        value[key] = str(value[key])
    for key in ("created_at", "expires_at", "approval_expires_at"):
        if value[key] is not None:
            value[key] = value[key].isoformat()
    value["status"] = record.status.value
    return value


def _record_from_json(value: Mapping[str, Any]) -> ActivationRecord:
    decoded = dict(value)
    decoded["task_id"] = UUID(str(decoded["task_id"]))
    for key in ("created_at", "expires_at", "approval_expires_at"):
        if decoded.get(key) is not None:
            decoded[key] = datetime.fromisoformat(str(decoded[key]))
    decoded["status"] = ActivationStatus(str(decoded["status"]))
    decoded["changed_paths"] = tuple(decoded["changed_paths"])
    decoded["required_gates"] = tuple(decoded["required_gates"])
    return ActivationRecord(**decoded)


async def _maybe(value: object) -> Any:
    if inspect.isawaitable(value):
        return await value
    return value


__all__ = [
    "ActivationError",
    "ActivationRecord",
    "ActivationStateStore",
    "ActivationStatus",
    "GateEvidence",
    "TrustedSelfDevelopmentActivator",
    "approval_binding_fingerprint",
    "approval_request_id",
]
