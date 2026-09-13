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
import sys
import tempfile
from collections.abc import Awaitable, Callable, Mapping, Sequence
from dataclasses import asdict, dataclass, fields, replace
from datetime import UTC, datetime, timedelta
from enum import StrEnum
from pathlib import Path
from typing import Any, Protocol, cast
from uuid import UUID, uuid4, uuid5

from jarvis.improvement.adapters import ProposalStore
from jarvis.improvement.integrity import compute_proposal_fingerprint
from jarvis.improvement.models import (
    ChangeSpecification,
    DependencyAssessment,
    DependencyChange,
    DependencyRecord,
    EvaluationDirection,
    EvaluationResult,
    EvaluationScenario,
    EvaluationStatus,
    GateKind,
    GateResult,
    GateStatus,
    ImprovementCandidate,
    ImprovementEvidence,
    ImprovementSource,
    IsolatedWorkspace,
    MergeDeploymentProposal,
    ModificationResult,
    ProposalStatus,
    Reversibility,
    RollbackMetadata,
    ScenarioResult,
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
from jarvis.recovery import (
    RecoveryCoordinator,
    RecoveryError,
    RecoveryManifest,
    compute_application_build_hash,
)
from jarvis.security.modification_policy import (
    ModificationTrustClassification,
    ModificationTrustClassifier,
    ModificationTrustLevel,
)
from jarvis.testing.golden import (
    ExpectedResult,
    Fixture,
    GoldenChangeKind,
    GoldenExecutor,
    GoldenGateError,
    GoldenWorkflow,
    GoldenWorkflowClass,
    GoldenWorkflowService,
    GoldenWorkflowStore,
    Version,
)
from jarvis.update_preview import (
    ControlledSelfUpdate,
    UpdateGateResult,
    UpdateMigrationSummary,
    UpdatePreview,
)
from jarvis.verification import EvidenceRecord, EvidenceType, VerificationLevel


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
    candidate_application_hash: str
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
    previous_lkg_snapshot_id: str | None = None
    previous_lkg_application_hash: str | None = None
    previous_lkg_revision: str | None = None

    def __post_init__(self) -> None:
        if not self.activation_id or not self.proposal_id:
            raise ValueError("Activation identity is required")
        for value in (
            self.proposal_fingerprint,
            self.candidate_hash,
            self.candidate_application_hash,
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


class DurableProposalStore(ProposalStore):
    """Trusted JSON-backed owner for proposals that outlive one service object."""

    def __init__(self, path: Path) -> None:
        self.path = path.expanduser().resolve()
        self.path.parent.mkdir(parents=True, exist_ok=True)
        with sqlite3.connect(self.path) as connection:
            connection.execute(
                "CREATE TABLE IF NOT EXISTS self_development_proposals "
                "(proposal_id TEXT PRIMARY KEY, fingerprint TEXT NOT NULL, payload TEXT NOT NULL)"
            )

    def put(self, proposal: MergeDeploymentProposal) -> None:
        self.add(proposal)

    def add(self, proposal: MergeDeploymentProposal) -> None:
        _assert_proposal_fingerprint(proposal)
        payload = json.dumps(_proposal_to_json(proposal), sort_keys=True, separators=(",", ":"))
        with sqlite3.connect(self.path) as connection:
            existing = connection.execute(
                "SELECT fingerprint,payload FROM self_development_proposals WHERE proposal_id=?",
                (proposal.proposal_id,),
            ).fetchone()
            if existing is not None:
                if (
                    str(existing[0]) == proposal.proposal_fingerprint
                    and str(existing[1]) == payload
                ):
                    raise ValueError("Proposal ID already exists")
                raise ValueError("Proposal ID already exists with different contents")
            duplicate = connection.execute(
                "SELECT proposal_id FROM self_development_proposals WHERE fingerprint=?",
                (proposal.proposal_fingerprint,),
            ).fetchone()
            if duplicate is not None:
                raise ValueError("Exact change already has an awaiting proposal")
            connection.execute(
                "INSERT INTO self_development_proposals(proposal_id,fingerprint,payload) "
                "VALUES(?,?,?)",
                (proposal.proposal_id, proposal.proposal_fingerprint, payload),
            )

    def remove_unapproved(self, proposal_id: str, fingerprint: str) -> None:
        with sqlite3.connect(self.path) as connection:
            row = connection.execute(
                "SELECT fingerprint,payload FROM self_development_proposals WHERE proposal_id=?",
                (proposal_id,),
            ).fetchone()
            if row is None or str(row[0]) != fingerprint:
                raise ValueError("Only the exact awaiting proposal can be rolled back from storage")
            proposal = _proposal_from_json(json.loads(str(row[1])))
            if proposal.status is not ProposalStatus.AWAITING_TRUSTED_APPROVAL:
                raise ValueError("Only an awaiting proposal can be removed")
            connection.execute(
                "DELETE FROM self_development_proposals WHERE proposal_id=? AND fingerprint=?",
                (proposal_id, fingerprint),
            )

    def get(self, proposal_id: str) -> MergeDeploymentProposal | None:
        with sqlite3.connect(self.path) as connection:
            row = connection.execute(
                "SELECT fingerprint,payload FROM self_development_proposals WHERE proposal_id=?",
                (proposal_id,),
            ).fetchone()
        if row is None:
            return None
        proposal = _proposal_from_json(json.loads(str(row[1])))
        if proposal.proposal_fingerprint != str(row[0]):
            raise ActivationError("durable proposal fingerprint mismatch")
        _assert_proposal_fingerprint(proposal)
        return proposal

    def __call__(self, proposal_id: str) -> MergeDeploymentProposal | None:
        return self.get(proposal_id)


class ProposalLoader(Protocol):
    def __call__(self, proposal_id: str) -> MergeDeploymentProposal | None: ...


GateVerifier = Callable[
    [MergeDeploymentProposal, ModificationTrustClassification],
    Mapping[str, GateEvidence] | Awaitable[Mapping[str, GateEvidence]],
]


class UnavailableSelfDevelopmentGateVerifier:
    """Trusted fail-closed gate owner for runtimes without a gate provider."""

    def __call__(
        self, proposal: MergeDeploymentProposal, classification: ModificationTrustClassification
    ) -> Mapping[str, GateEvidence]:
        del proposal, classification
        return {}


class GoldenWorkflowOwner:
    """Bind self-improvement activation to the canonical GoldenWorkflow owner."""

    def __init__(self, service: GoldenWorkflowService, executor: GoldenExecutor) -> None:
        self._service = service
        self._executor = executor

    async def __call__(self) -> bool:
        result = await self._service.require_before(
            GoldenChangeKind.SELF_IMPROVEMENT,
            self._executor,
        )
        return result.passed

    def for_candidate(self, *, root: Path, proposal_fingerprint: str) -> GoldenWorkflowOwner:
        bind = getattr(self._executor, "for_candidate", None)
        if not callable(bind):
            return self
        return GoldenWorkflowOwner(
            self._service,
            bind(root=root, proposal_fingerprint=proposal_fingerprint),
        )


GoldenRunner = Callable[[], object | Awaitable[object]]

_APPROVAL_BINDING_NAMESPACE = UUID("7b6eb5c1-5fd3-5ae6-a1ab-15b4e5a98eaf")


class CandidateStartOutcome(StrEnum):
    STARTED = "STARTED"
    PROCESS_TIMEOUT = "PROCESS_TIMEOUT"
    NONZERO_EXIT = "NONZERO_EXIT"
    MALFORMED_PAYLOAD = "MALFORMED_PAYLOAD"
    NOT_READY = "NOT_READY"
    ROOT_MISMATCH = "ROOT_MISMATCH"
    TREE_HASH_MISMATCH = "TREE_HASH_MISMATCH"
    RECOVERY_AUTH_MISMATCH = "RECOVERY_AUTH_MISMATCH"
    UNSAFE_ENVIRONMENT = "UNSAFE_ENVIRONMENT"
    SHUTDOWN_FAILED = "SHUTDOWN_FAILED"
    STARTUP_DEADLINE_EXCEEDED = "STARTUP_DEADLINE_EXCEEDED"


@dataclass(frozen=True, slots=True)
class CandidateStartEvidence:
    """Trusted observation that the exact installed candidate was started."""

    started: bool
    observed_revision: str
    observed_application_hash: str
    evidence_digest: str
    outcome: CandidateStartOutcome = CandidateStartOutcome.STARTED
    observed_root: str = ""
    snapshot_id: str = ""
    detail: str = ""

    def __post_init__(self) -> None:
        if type(self.started) is not bool or len(self.observed_application_hash) != 64:
            raise ValueError("Candidate start evidence is malformed")
        int(self.observed_application_hash, 16)
        if len(self.evidence_digest) != 64:
            raise ValueError("Candidate start evidence digest is malformed")
        int(self.evidence_digest, 16)
        if not isinstance(self.outcome, CandidateStartOutcome):
            raise ValueError("Candidate start outcome is malformed")
        if len(self.observed_root) > 1_024 or len(self.snapshot_id) > 128 or len(self.detail) > 512:
            raise ValueError("Candidate start detail is malformed")


@dataclass(frozen=True, slots=True)
class RuntimeVerificationEvidence:
    """One independently observed trusted runtime verification fact."""

    passed: bool
    evidence_digest: str
    detail: str = ""

    def __post_init__(self) -> None:
        if type(self.passed) is not bool or len(self.evidence_digest) != 64:
            raise ValueError("Runtime verification evidence is malformed")
        int(self.evidence_digest, 16)


class SelfDevelopmentRuntimeVerifier(Protocol):
    """Application-owned observer for candidate and LKG lifecycle facts."""

    def start_candidate(
        self, *, installation_root: Path, expected_revision: str, expected_hash: str
    ) -> CandidateStartEvidence: ...

    def observe_candidate_health(
        self, *, installation_root: Path, expected_hash: str
    ) -> RuntimeVerificationEvidence: ...

    def observe_candidate_security(
        self, *, installation_root: Path, expected_hash: str
    ) -> RuntimeVerificationEvidence: ...

    def observe_lkg_health(self, *, installation_root: Path) -> RuntimeVerificationEvidence: ...


class UnavailableSelfDevelopmentRuntimeVerifier:
    """Fail-closed runtime seam used when no trusted candidate host is configured."""

    _DIGEST = hashlib.sha256(b"trusted-self-development-runtime-unavailable").hexdigest()

    def start_candidate(
        self, *, installation_root: Path, expected_revision: str, expected_hash: str
    ) -> CandidateStartEvidence:
        del installation_root, expected_revision
        return CandidateStartEvidence(
            False,
            "unavailable",
            expected_hash,
            self._DIGEST,
            CandidateStartOutcome.RECOVERY_AUTH_MISMATCH,
            detail="candidate runtime observer unavailable",
        )

    def observe_candidate_health(
        self, *, installation_root: Path, expected_hash: str
    ) -> RuntimeVerificationEvidence:
        del installation_root, expected_hash
        return RuntimeVerificationEvidence(
            False, self._DIGEST, "candidate runtime observer unavailable"
        )

    def observe_candidate_security(
        self, *, installation_root: Path, expected_hash: str
    ) -> RuntimeVerificationEvidence:
        del installation_root, expected_hash
        return RuntimeVerificationEvidence(
            False, self._DIGEST, "candidate security observer unavailable"
        )

    def observe_lkg_health(self, *, installation_root: Path) -> RuntimeVerificationEvidence:
        del installation_root
        return RuntimeVerificationEvidence(False, self._DIGEST, "LKG observer unavailable")


class SelfDevelopmentSupport(StrEnum):
    SUPPORTED_SOURCE_INSTALLATION = "supported_source_installation"
    UNSUPPORTED_PACKAGED_SELF_UPDATE = "unsupported_packaged_self_update"
    UNSUPPORTED_READ_ONLY_INSTALLATION = "unsupported_read_only_installation"
    UNSAFE_INSTALLATION_IDENTITY = "unsafe_installation_identity"


@dataclass(frozen=True, slots=True)
class SelfDevelopmentSupportResult:
    status: SelfDevelopmentSupport
    detail: str
    production_root: Path


class SelfDevelopmentSupportDetector:
    """Deterministically classify the installation before composing update owners."""

    def detect(
        self, production_root: Path, installation_root: Path
    ) -> SelfDevelopmentSupportResult:
        raw_root = production_root.expanduser()
        raw_target = installation_root.expanduser()
        root = raw_root.resolve()
        target = raw_target.resolve()
        if getattr(sys, "frozen", False):
            return SelfDevelopmentSupportResult(
                SelfDevelopmentSupport.UNSUPPORTED_PACKAGED_SELF_UPDATE,
                "frozen executable replacement is not supported",
                root,
            )
        if (
            root == target
            or raw_root.is_symlink()
            or raw_root.is_junction()
            or raw_target.is_symlink()
            or raw_target.is_junction()
            or root.is_relative_to(target)
            or target.is_relative_to(root)
        ):
            return SelfDevelopmentSupportResult(
                SelfDevelopmentSupport.UNSAFE_INSTALLATION_IDENTITY,
                "production and candidate roots must be distinct regular directories",
                root,
            )
        required = (root / "jarvis" / "runtime.py", root / "jarvis" / "bootstrap.py")
        if not root.is_dir() or any(not item.is_file() for item in required):
            return SelfDevelopmentSupportResult(
                SelfDevelopmentSupport.UNSAFE_INSTALLATION_IDENTITY,
                "source installation identity is incomplete",
                root,
            )
        try:
            target.mkdir(parents=True, exist_ok=True)
            probe = target / ".support-probe"
            probe.write_text("trusted-support-probe", encoding="utf-8")
            probe.unlink()
        except OSError:
            return SelfDevelopmentSupportResult(
                SelfDevelopmentSupport.UNSUPPORTED_READ_ONLY_INSTALLATION,
                "candidate installation root is not writable",
                root,
            )
        return SelfDevelopmentSupportResult(
            SelfDevelopmentSupport.SUPPORTED_SOURCE_INSTALLATION,
            "trusted source installation and writable candidate root verified",
            root,
        )


@dataclass(frozen=True, slots=True)
class CandidateInstallation:
    root: Path
    snapshot_id: str
    tree_digest: str
    identity: str

    @property
    def application_hash(self) -> str:
        return self.tree_digest


class CandidateInstaller(Protocol):
    def stage(
        self, proposal: MergeDeploymentProposal, record: ActivationRecord
    ) -> CandidateInstallation: ...


class ProductionCandidateInstaller:
    """Build a complete immutable candidate and bind it to an authenticated snapshot."""

    _EXCLUDED_DIRECTORIES = frozenset(
        {
            ".git",
            ".jarvis",
            ".venv",
            "__pycache__",
            "artifacts",
            "cache",
            "data",
            "logs",
            "models",
            "tmp",
            "build",
            "dist",
            ".pytest_cache",
            ".mypy_cache",
            ".ruff_cache",
            "jarvis.egg-info",
        }
    )
    _EXCLUDED_FILES = frozenset({".env", ".env.local", ".coverage"})

    def __init__(
        self, production_root: Path, installation_root: Path, recovery: RecoveryCoordinator
    ) -> None:
        self.production_root = _directory(production_root, "production root")
        self.installation_root = _directory(installation_root, "installation root")
        self.recovery = recovery

    def _identity(self, record: ActivationRecord) -> str:
        identity_material = "\x1f".join(
            (
                record.proposal_fingerprint,
                record.candidate_hash,
                record.candidate_application_hash,
                record.candidate_revision,
                record.candidate_tree_digest,
            )
        )
        return hashlib.sha256(identity_material.encode("utf-8")).hexdigest()

    def planned_root(self, record: ActivationRecord) -> Path:
        """Return the exact versioned namespace authorized before materialization."""

        identity = self._identity(record)
        root = self.installation_root / f".staging-{identity}"
        _contained_directory_target(root, self.installation_root)
        return root

    def effect_paths(self, record: ActivationRecord) -> tuple[str, ...]:
        del record
        return (str(self.installation_root),)

    def stage(
        self, proposal: MergeDeploymentProposal, record: ActivationRecord
    ) -> CandidateInstallation:
        identity = self._identity(record)
        staging = self.planned_root(record)
        if staging.exists():
            raise ActivationError("candidate identity is already staged")
        staging.mkdir(parents=True)
        try:
            self._copy_tree(self.production_root, staging)
            workspace = _candidate_workspace(proposal)
            for relative in proposal.modification.changed_paths:
                source = workspace / Path(relative)
                target = staging / Path(relative)
                _contained_regular_target(target, staging)
                if source.exists():
                    if not source.is_file() or source.is_symlink() or source.is_junction():
                        raise ActivationError("candidate changed path is not a regular file")
                    target.parent.mkdir(parents=True, exist_ok=True)
                    shutil.copy2(source, target)
                else:
                    target.unlink(missing_ok=True)
            application_hash = compute_application_build_hash(staging)
            if application_hash != record.candidate_application_hash:
                raise ActivationError("materialized candidate application hash mismatches record")
            manifest = self.recovery.store.create_snapshot(
                transaction_id=record.recovery_transaction_id or str(uuid4()),
                app_revision=record.candidate_revision,
                application_hash=application_hash,
                configuration={
                    "candidate_identity": identity,
                    "candidate_application_hash": application_hash,
                },
                database_schema={},
                integration_versions={},
                files=(),
            )
            staged_root = self.installation_root / manifest.snapshot_id
            _contained_directory_target(staged_root, self.installation_root)
            staging.rename(staged_root)
            return CandidateInstallation(
                staged_root, manifest.snapshot_id, application_hash, identity
            )
        except Exception:
            shutil.rmtree(staging, ignore_errors=True)
            raise

    def _copy_tree(
        self,
        source_root: Path,
        target_root: Path,
        seen_files: dict[tuple[int, int], Path] | None = None,
    ) -> None:
        source_root = source_root.resolve()
        if source_root.is_symlink() or source_root.is_junction() or not source_root.is_dir():
            raise ActivationError("candidate source root is unsafe")
        seen_files = seen_files if seen_files is not None else {}
        target_root.mkdir(parents=True, exist_ok=True)
        for source in source_root.iterdir():
            if source.name in self._EXCLUDED_DIRECTORIES or source.name in self._EXCLUDED_FILES:
                continue
            if source.is_symlink() or source.is_junction():
                raise ActivationError("candidate source contains a link")
            target = target_root / source.name
            if source.is_dir():
                self._copy_tree(source, target, seen_files)
            elif source.is_file() and source.suffix in {".sqlite3", ".pyc", ".pyo"}:
                continue
            elif source.is_file() and source.suffix not in {".sqlite3", ".pyc", ".pyo"}:
                stat = source.stat()
                identity = (stat.st_dev, stat.st_ino)
                if identity in seen_files:
                    raise ActivationError("candidate source contains an unexpected hard link")
                seen_files[identity] = source
                target.parent.mkdir(parents=True, exist_ok=True)
                shutil.copy2(source, target)
            else:
                raise ActivationError("candidate source contains a non-regular file")


class ProductionCurrentGateExecutor:
    """Run host-owned current gates and return only observed typed outcomes."""

    _DANGEROUS = (
        "-----BEGIN ",
        "os.system(",
        "eval(",
        "exec(",
        "password =",
        "api_key =",
        "token =",
    )
    _COMMANDS = {
        "sandbox_tests": (sys.executable, "-m", "compileall", "-q", "jarvis"),
        "quality": (sys.executable, "scripts/quality.py"),
        "integration_tests": (sys.executable, "-m", "pytest", "-q"),
        "protected_regression": (sys.executable, "-m", "pytest", "-q", "tests/trusted_core"),
    }
    _POST_START = frozenset({"startup_health", "post_start_security", "runtime_integrity"})
    _NON_GATE_FACTS = frozenset(
        {"trusted_approval", "recovery_point", "change_control_record", "dual_control_approval"}
    )

    def __init__(self, *, timeout_seconds: float = 900.0) -> None:
        self.timeout_seconds = timeout_seconds

    def __call__(
        self, proposal: MergeDeploymentProposal, classification: ModificationTrustClassification
    ) -> Mapping[str, GateEvidence]:
        workspace = _candidate_workspace(proposal)
        evidence: dict[str, GateEvidence] = {}
        for name in classification.required_gates:
            if name in self._POST_START:
                continue
            if name in self._NON_GATE_FACTS:
                continue
            if name in {"static_security", "security_review", "trusted_core_security"}:
                passed, detail = self._static_security(workspace, proposal)
            elif name == "package_certification":
                passed, detail = self._package_certification(workspace)
            else:
                command = self._COMMANDS.get(name)
                if command is None:
                    raise ActivationError(f"current trusted gate owner unavailable: {name}")
                passed, detail = self._run_command(workspace, command)
            digest = hashlib.sha256(
                "\x1f".join(
                    (
                        proposal.proposal_fingerprint,
                        proposal.workspace.base_revision,
                        proposal.modification.tree_digest,
                        name,
                        str(passed),
                        detail,
                    )
                ).encode("utf-8")
            ).hexdigest()
            evidence[name] = GateEvidence(name, passed, digest)
            if not passed:
                break
            if _tree_digest(workspace) != proposal.modification.tree_digest:
                raise ActivationError("candidate changed during current gate execution")
        return evidence

    def _static_security(
        self, workspace: Path, proposal: MergeDeploymentProposal
    ) -> tuple[bool, str]:
        for relative in proposal.modification.changed_paths:
            path = workspace / Path(relative)
            if not path.is_file() or path.is_symlink() or path.is_junction():
                return False, "changed path is unavailable or non-regular"
            text = path.read_text(encoding="utf-8", errors="replace").casefold()
            if any(marker.casefold() in text for marker in self._DANGEROUS):
                return False, "static security scanner rejected candidate content"
        return True, "trusted static security scanner completed"

    @staticmethod
    def _package_certification(workspace: Path) -> tuple[bool, str]:
        try:
            digest = compute_application_build_hash(workspace)
        except (OSError, RecoveryError):
            return False, "candidate application package is not certifiable"
        return bool(digest), "candidate application package was independently hashed"

    def _run_command(self, workspace: Path, command: tuple[str, ...]) -> tuple[bool, str]:
        environment = _sanitized_candidate_environment(workspace)
        coverage_file: Path | None = None
        if command[:2] == (sys.executable, "scripts/quality.py"):
            descriptor, filename = tempfile.mkstemp(prefix="jarvis-quality-", suffix=".coverage")
            os.close(descriptor)
            coverage_file = Path(filename)
            environment["COVERAGE_FILE"] = str(coverage_file)
        try:
            result = subprocess.run(
                command,
                cwd=workspace,
                env=environment,
                capture_output=True,
                text=True,
                timeout=self.timeout_seconds,
                check=False,
            )
        except subprocess.TimeoutExpired:
            return False, "trusted gate process timed out"
        except OSError:
            return False, "trusted gate process was unavailable"
        finally:
            if coverage_file is not None:
                coverage_file.unlink(missing_ok=True)
        return result.returncode == 0, (
            "trusted gate process passed"
            if result.returncode == 0
            else "trusted gate process returned nonzero"
        )


class ProductionSelfDevelopmentGateVerifier:
    """Fresh structural verifier followed by an independently owned gate run."""

    def __init__(
        self,
        executor: Callable[
            [MergeDeploymentProposal, ModificationTrustClassification],
            Mapping[str, GateEvidence],
        ]
        | None = None,
    ) -> None:
        self._executor = executor or ProductionCurrentGateExecutor()

    def __call__(
        self, proposal: MergeDeploymentProposal, classification: ModificationTrustClassification
    ) -> Mapping[str, GateEvidence]:
        if classification != ModificationTrustClassifier().classify(
            proposal.modification.changed_paths
        ):
            raise ActivationError("current trusted gate classification is stale")
        _assert_proposal_fingerprint(proposal)
        workspace = _candidate_workspace(proposal)
        if _tree_digest(workspace) != proposal.modification.tree_digest:
            raise ActivationError("current candidate tree gate failed")
        if _git_head(workspace) != proposal.workspace.base_revision:
            raise ActivationError("current candidate base gate failed")
        if _git_changed_paths(workspace, proposal.workspace.base_revision) != set(
            proposal.modification.changed_paths
        ):
            raise ActivationError("candidate changed-path set is broader than the proposal")
        if (
            _git_diff_digest(
                workspace, proposal.workspace.base_revision, proposal.modification.changed_paths
            )
            != proposal.modification.diff_digest
        ):
            raise ActivationError("current candidate diff gate failed")
        if proposal.dependency_assessment.changes:
            raise ActivationError("dependency-changing candidate gate failed")
        return self._executor(proposal, classification)


def register_production_self_development_golden(store: object) -> GoldenWorkflow:
    """Register one deterministic trusted self-improvement Golden workflow."""

    workflow = GoldenWorkflow(
        "jarvis-production-self-development",
        "Production self-development readiness",
        Version(1, 0, 0),
        GoldenWorkflowClass.DETERMINISTIC,
        (
            Fixture(
                "candidate-ready",
                "Candidate runtime readiness",
                {"criterion": "candidate_ready"},
                ExpectedResult("Verify trusted candidate readiness", ("candidate_ready",)),
            ),
        ),
        frozenset({GoldenChangeKind.SELF_IMPROVEMENT}),
        provenance=("trusted:jarvis-production-self-development",),
    )
    return cast(GoldenWorkflowStore, store).register(workflow)


class ProductionGoldenExecutor:
    """Application-owned Golden executor backed by an observed candidate process."""

    def __init__(
        self, *, root: Path | None = None, proposal_fingerprint: str | None = None
    ) -> None:
        self._root = root.resolve() if root is not None else None
        self._proposal_fingerprint = proposal_fingerprint

    def for_candidate(self, *, root: Path, proposal_fingerprint: str) -> ProductionGoldenExecutor:
        if len(proposal_fingerprint) != 64:
            raise GoldenGateError("Golden candidate binding is malformed")
        return ProductionGoldenExecutor(root=root, proposal_fingerprint=proposal_fingerprint)

    def __call__(self, workflow: GoldenWorkflow, fixture: Fixture) -> Sequence[EvidenceRecord]:
        if (
            workflow.workflow_id != "jarvis-production-self-development"
            or fixture.fixture_id != "candidate-ready"
        ):
            raise GoldenGateError("production self-development Golden workflow is unknown")
        root = self._root
        if root is None or self._proposal_fingerprint is None:
            raise GoldenGateError("production Golden candidate context is unavailable")
        try:
            expected_hash = compute_application_build_hash(root)
            app_data = Path(tempfile.mkdtemp(prefix="jarvis-golden-data-"))
            command = [sys.executable, "-m", "jarvis.self_development_host", str(app_data)]
            environment = _sanitized_candidate_environment(root)
            child = subprocess.Popen(
                command,
                cwd=root,
                env=environment,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
            )
            try:
                stdout, _stderr = child.communicate(timeout=45)
            except subprocess.TimeoutExpired:
                child.kill()
                child.communicate()
                raise GoldenGateError("production Golden candidate timed out") from None
            payload = _candidate_host_payload(stdout)
            observed = (
                child.returncode == 0
                and payload is not None
                and payload.get("status") == "ready"
                and payload.get("root") == str(root)
                and payload.get("environment_isolated") is True
                and payload.get("shutdown_clean") is True
                and payload.get("application_hash") == expected_hash
            )
            observation_digest = hashlib.sha256(
                json.dumps(
                    {
                        "proposal_fingerprint": self._proposal_fingerprint,
                        "root": str(root),
                        "returncode": child.returncode,
                        "application_hash": payload.get("application_hash")
                        if payload is not None
                        else None,
                        "status": payload.get("status") if payload is not None else None,
                        "environment_isolated": payload.get("environment_isolated")
                        if payload is not None
                        else None,
                    },
                    sort_keys=True,
                    separators=(",", ":"),
                ).encode("utf-8")
            ).hexdigest()
        except (OSError, RecoveryError) as error:
            raise GoldenGateError("production Golden candidate was unavailable") from error
        finally:
            if "app_data" in locals():
                shutil.rmtree(app_data, ignore_errors=True)
        now = datetime.now(UTC)
        return (
            EvidenceRecord(
                EvidenceType.CUSTOM,
                f"trusted.production-self-development-golden:{observation_digest}",
                now,
                timedelta(minutes=5),
                1.0 if observed else 0.0,
                "candidate_ready",
                "candidate_ready" if observed else "candidate_not_ready",
                level=VerificationLevel.AUTOMATED_TESTED,
            ),
        )


class TrustedSelfDevelopmentBootSelector:
    """Resolve boot code only from authenticated RecoveryStore known-good state."""

    def __init__(
        self, production_root: Path, installation_root: Path, recovery: RecoveryCoordinator
    ) -> None:
        self.production_root = _directory(production_root, "production root")
        self.installation_root = _directory(installation_root, "installation root")
        self.recovery = recovery

    def select(self) -> Path:
        record = self.recovery.store.last_known_good_record()
        if record is None:
            return self.production_root
        manifest = self.recovery.store.load(record.snapshot_id)
        candidate = self.installation_root / record.snapshot_id
        if (
            candidate.is_dir()
            and compute_application_build_hash(candidate) == manifest.application_hash
        ):
            return candidate
        if compute_application_build_hash(self.production_root) == manifest.application_hash:
            return self.production_root
        raise ActivationError("authenticated known-good candidate installation is unavailable")


class ProductionSelfDevelopmentRuntimeVerifier:
    """Trusted bounded Windows process observer for complete candidate roots."""

    def __init__(
        self,
        production_root: Path,
        boot_selector: TrustedSelfDevelopmentBootSelector,
        *,
        startup_deadline_seconds: float = 60.0,
        safety_margin_seconds: float = 5.0,
    ) -> None:
        if startup_deadline_seconds <= safety_margin_seconds or safety_margin_seconds <= 0:
            raise ValueError("candidate startup deadline margin is invalid")
        self.production_root = _directory(production_root, "production root")
        self.boot_selector = boot_selector
        self._host_timeout_seconds = startup_deadline_seconds - safety_margin_seconds
        self._safety_margin_seconds = safety_margin_seconds
        self._observations: dict[Path, tuple[int, Mapping[str, object] | None, str]] = {}
        self._last_start_evidence: CandidateStartEvidence | None = None

    @property
    def last_start_evidence(self) -> CandidateStartEvidence | None:
        return self._last_start_evidence

    def start_candidate(
        self, *, installation_root: Path, expected_revision: str, expected_hash: str
    ) -> CandidateStartEvidence:
        root = _directory(installation_root, "candidate installation root")
        tree_digest = compute_application_build_hash(root)
        manifest = self._authenticated_manifest(root)
        if manifest is None:
            return self._evidence(
                root,
                CandidateStartOutcome.RECOVERY_AUTH_MISMATCH,
                "authenticated candidate manifest unavailable",
                tree_digest,
            )
        if (
            manifest.app_revision != expected_revision
            or manifest.application_hash != expected_hash
            or manifest.application_hash != tree_digest
        ):
            return self._evidence(
                root,
                CandidateStartOutcome.RECOVERY_AUTH_MISMATCH,
                "authenticated candidate manifest does not match the request",
                tree_digest,
                observed_revision=manifest.app_revision,
                snapshot_id=manifest.snapshot_id,
            )
        timeout = self._remaining_host_timeout()
        if timeout <= 0:
            return self._evidence(
                root,
                CandidateStartOutcome.STARTUP_DEADLINE_EXCEEDED,
                "Recovery startup deadline already expired",
                tree_digest,
                observed_revision=manifest.app_revision,
                snapshot_id=manifest.snapshot_id,
            )
        app_data = Path(tempfile.mkdtemp(prefix="jarvis-candidate-data-"))
        env = _sanitized_candidate_environment(root)
        command = [sys.executable, "-m", "jarvis.self_development_host", str(app_data)]
        returncode = -1
        stdout = ""
        stderr = ""
        outcome = CandidateStartOutcome.NONZERO_EXIT
        detail = "candidate host returned nonzero"
        try:
            child = subprocess.Popen(
                command,
                cwd=root,
                env=env,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
            )
            try:
                stdout, stderr = child.communicate(timeout=timeout)
            except subprocess.TimeoutExpired:
                child.kill()
                stdout, stderr = child.communicate()
                outcome = CandidateStartOutcome.PROCESS_TIMEOUT
                detail = "candidate host exceeded the bounded Recovery startup budget"
            returncode = child.returncode
            if len(stdout) > 16_384:
                outcome = CandidateStartOutcome.MALFORMED_PAYLOAD
                detail = "candidate host payload exceeded its bound"
            payload = _candidate_host_payload(stdout)
            self._observations[root] = (returncode, payload, tree_digest)
            if outcome is not CandidateStartOutcome.PROCESS_TIMEOUT:
                if returncode != 0:
                    outcome = CandidateStartOutcome.NONZERO_EXIT
                    detail = "candidate host returned nonzero"
                elif payload is None:
                    outcome = CandidateStartOutcome.MALFORMED_PAYLOAD
                    detail = "candidate host payload was not valid bounded JSON"
                elif payload.get("root") != str(root):
                    outcome = CandidateStartOutcome.ROOT_MISMATCH
                    detail = "candidate host reported a different root"
                elif payload.get("environment_isolated") is not True:
                    outcome = CandidateStartOutcome.UNSAFE_ENVIRONMENT
                    detail = "candidate host environment was not isolated"
                elif payload.get("shutdown_clean") is not True:
                    outcome = CandidateStartOutcome.SHUTDOWN_FAILED
                    detail = "candidate host shutdown was not clean"
                elif payload.get("application_hash") != tree_digest:
                    outcome = CandidateStartOutcome.TREE_HASH_MISMATCH
                    detail = "candidate host reported a different application hash"
                elif payload.get("status") != "ready":
                    outcome = CandidateStartOutcome.NOT_READY
                    detail = "candidate host did not report READY"
                elif self._authenticated_tree_digest(root) != tree_digest:
                    outcome = CandidateStartOutcome.RECOVERY_AUTH_MISMATCH
                    detail = "authenticated candidate tree changed during startup"
                else:
                    outcome = CandidateStartOutcome.STARTED
                    detail = "candidate host and authenticated manifest observed"
            if outcome is CandidateStartOutcome.STARTED and self._remaining_host_timeout() <= 0:
                outcome = CandidateStartOutcome.STARTUP_DEADLINE_EXCEEDED
                detail = "Recovery startup deadline expired before candidate observation completed"
            return self._evidence(
                root,
                outcome,
                detail,
                tree_digest,
                observed_revision=manifest.app_revision,
                snapshot_id=manifest.snapshot_id,
                pid=child.pid,
                returncode=returncode,
                stderr=stderr,
            )
        except OSError:
            return self._evidence(
                root,
                CandidateStartOutcome.NONZERO_EXIT,
                "candidate host process was unavailable",
                tree_digest,
                observed_revision=manifest.app_revision,
                snapshot_id=manifest.snapshot_id,
                returncode=returncode,
            )
        finally:
            shutil.rmtree(app_data, ignore_errors=True)

    def observe_candidate_health(
        self, *, installation_root: Path, expected_hash: str
    ) -> RuntimeVerificationEvidence:
        observed = self._observations.get(installation_root.resolve())
        payload = observed[1] if observed is not None else None
        passed = (
            observed is not None
            and observed[0] == 0
            and payload is not None
            and payload.get("status") == "ready"
            and payload.get("root") == str(installation_root.resolve())
            and payload.get("environment_isolated") is True
            and payload.get("application_hash") == observed[2]
            and observed[2] == expected_hash
            and self._authenticated_tree_digest(installation_root.resolve()) == observed[2]
        )
        return RuntimeVerificationEvidence(
            passed,
            hashlib.sha256(
                f"health:{installation_root}:{observed[2] if observed else ''}:{passed}".encode()
            ).hexdigest(),
            "real candidate ApplicationRuntime startup observed"
            if passed
            else "candidate runtime was not READY",
        )

    def observe_candidate_security(
        self, *, installation_root: Path, expected_hash: str
    ) -> RuntimeVerificationEvidence:
        root = installation_root.resolve()
        observed = self._observations.get(root)
        passed = (
            observed is not None
            and observed[0] == 0
            and observed[2] == compute_application_build_hash(root)
            and observed[2] == expected_hash
            and self._authenticated_tree_digest(root) == observed[2]
        )
        return RuntimeVerificationEvidence(
            passed,
            hashlib.sha256(
                f"security:{root}:{observed[2] if observed else ''}:{passed}".encode()
            ).hexdigest(),
            "candidate root identity and complete tree are unchanged"
            if passed
            else "candidate integrity observation failed",
        )

    def observe_lkg_health(self, *, installation_root: Path) -> RuntimeVerificationEvidence:
        root = self.boot_selector.select()
        manifest = self._authenticated_manifest(root)
        if manifest is None:
            return RuntimeVerificationEvidence(
                False,
                hashlib.sha256(f"lkg-missing:{root}".encode()).hexdigest(),
                "authenticated known-good manifest unavailable",
            )
        evidence = self.start_candidate(
            installation_root=root,
            expected_revision=manifest.app_revision,
            expected_hash=manifest.application_hash,
        )
        if not evidence.started:
            return RuntimeVerificationEvidence(
                False,
                hashlib.sha256(f"lkg-start:{root}:{evidence.evidence_digest}".encode()).hexdigest(),
                "authenticated known-good runtime did not start",
            )
        health = self.observe_candidate_health(
            installation_root=root, expected_hash=evidence.observed_application_hash
        )
        return RuntimeVerificationEvidence(
            health.passed,
            hashlib.sha256(f"lkg:{root}:{health.evidence_digest}".encode()).hexdigest(),
            "authenticated known-good runtime health observed"
            if health.passed
            else "known-good runtime health failed",
        )

    def _authenticated_manifest(self, root: Path) -> RecoveryManifest | None:
        root = root.resolve()
        if root == self.production_root:
            record = self.boot_selector.recovery.store.last_known_good_record()
            if record is None:
                return None
            return self.boot_selector.recovery.store.load(record.snapshot_id)
        if root.parent != self.boot_selector.installation_root:
            return None
        try:
            return self.boot_selector.recovery.store.load(root.name)
        except RecoveryError:
            return None

    def _remaining_host_timeout(self) -> float:
        try:
            attempt = self.boot_selector.recovery.store.active_start()
            if attempt.health_deadline is None:
                return self._host_timeout_seconds
            deadline = datetime.fromisoformat(attempt.health_deadline)
            now = self.boot_selector.recovery._clock()
            remaining = (deadline - now).total_seconds()
            return min(self._host_timeout_seconds, remaining - self._safety_margin_seconds)
        except (RecoveryError, ValueError):
            return self._host_timeout_seconds

    def _evidence(
        self,
        root: Path,
        outcome: CandidateStartOutcome,
        detail: str,
        tree_digest: str,
        *,
        observed_revision: str = "unobserved",
        snapshot_id: str = "",
        pid: int = 0,
        returncode: int = -1,
        stderr: str = "",
    ) -> CandidateStartEvidence:
        sanitized_stderr = hashlib.sha256(stderr.encode("utf-8", errors="replace")).hexdigest()
        digest = hashlib.sha256(
            f"{pid}:{root}:{returncode}:{tree_digest}:{outcome.value}:{sanitized_stderr}".encode()
        ).hexdigest()
        evidence = CandidateStartEvidence(
            outcome is CandidateStartOutcome.STARTED,
            observed_revision,
            tree_digest,
            digest,
            outcome,
            str(root),
            snapshot_id,
            detail,
        )
        self._last_start_evidence = evidence
        return evidence

    def _authenticated_tree_digest(self, root: Path) -> str | None:
        manifest = self._authenticated_manifest(root)
        return manifest.application_hash if manifest is not None else None


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
        runtime_verifier: SelfDevelopmentRuntimeVerifier,
        candidate_installer: CandidateInstaller | None = None,
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
        self._runtime_verifier = runtime_verifier
        self._candidate_installer = candidate_installer
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
        candidate_application_hash = compute_application_build_hash(workspace)
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
            candidate_application_hash=candidate_application_hash,
            candidate_tree_digest=tree_digest,
            candidate_diff_digest=diff_digest,
            changed_paths=proposal.modification.changed_paths,
            trust_level=int(classification.level),
            required_gates=classification.required_gates,
            preview_fingerprint=preview.preview_fingerprint,
            created_at=now,
            expires_at=proposal.expires_at,
        )
        if self._candidate_installer is not None:
            record = self._bind_previous_lkg(
                record,
                str(uuid4()),
                proposal,
                transition=False,
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
            golden = await self._run_golden(proposal)
            if golden is not True:
                raise ActivationError("SELF_IMPROVEMENT GoldenWorkflow did not pass")
            record = self._transition(record, ActivationStatus.PREPARING)
            transaction_id = str(uuid4())
            record = replace(record, recovery_transaction_id=transaction_id)
            self.store.put(record)
            if self._candidate_installer is None:
                snapshot_id = self._snapshot_current(transaction_id, record.changed_paths, proposal)
                record = self._transition(
                    record,
                    ActivationStatus.SNAPSHOT_CREATED,
                    recovery_snapshot_id=snapshot_id,
                )
            else:
                record = self._bind_previous_lkg(record, transaction_id, proposal)
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
            candidate_installation = None
            if self._candidate_installer is not None:
                try:
                    candidate_installation = self._candidate_installer.stage(proposal, record)
                    if candidate_installation.identity != self._candidate_identity(record):
                        raise ActivationError("candidate installation identity is not exact")
                    if candidate_installation.tree_digest != record.candidate_application_hash:
                        raise ActivationError(
                            "candidate installation application hash is not exact"
                        )
                except Exception as error:
                    await self.broker.record_execution_outcome(
                        authorization.receipt, "unknown_outcome"
                    )
                    return self._fail(
                        record,
                        ActivationStatus.QUARANTINED,
                        f"materialization outcome unknown: {type(error).__name__}",
                    )
            else:
                try:
                    self._apply_exact(proposal)
                except Exception as error:
                    await self.broker.record_execution_outcome(
                        authorization.receipt, "unknown_outcome"
                    )
                    return self._fail(
                        record,
                        ActivationStatus.QUARANTINED,
                        f"apply outcome unknown: {type(error).__name__}",
                    )
            await self.broker.record_execution_outcome(authorization.receipt, "success")
            if (
                candidate_installation is None
                and _installed_candidate_hash(proposal, self.installation_root)
                != record.candidate_hash
            ):
                raise ActivationError("installed candidate hash does not match exact candidate")
            record = self._transition(record, ActivationStatus.APPLIED)
            candidate_root = (
                candidate_installation.root
                if candidate_installation is not None
                else self.installation_root
            )
            candidate_snapshot = (
                candidate_installation.snapshot_id
                if candidate_installation is not None
                else self._snapshot_candidate(
                    record.recovery_transaction_id or transaction_id, record.changed_paths, proposal
                )
            )
            record = self._transition(
                record,
                ActivationStatus.STARTING,
                candidate_snapshot_id=candidate_snapshot,
            )
            coordinator = self.recovery

            start_evidence: CandidateStartEvidence | None = None

            def start() -> None:
                nonlocal start_evidence
                start_evidence = self._runtime_verifier.start_candidate(
                    installation_root=candidate_root,
                    expected_revision=record.candidate_revision,
                    expected_hash=record.candidate_application_hash,
                )
                if (
                    not start_evidence.started
                    or start_evidence.observed_revision != record.candidate_revision
                    or start_evidence.observed_application_hash != record.candidate_application_hash
                    or (
                        self._candidate_installer is not None
                        and (
                            start_evidence.observed_root != str(candidate_root.resolve())
                            or start_evidence.snapshot_id != candidate_snapshot
                        )
                    )
                ):
                    raise ActivationError(
                        "trusted candidate start did not observe exact candidate: "
                        f"outcome={start_evidence.outcome.value};detail={start_evidence.detail}"
                    )

            def verify_candidate() -> bool:
                health = self._runtime_verifier.observe_candidate_health(
                    installation_root=candidate_root,
                    expected_hash=record.candidate_application_hash,
                )
                if not health.passed:
                    return False
                security = self._runtime_verifier.observe_candidate_security(
                    installation_root=candidate_root,
                    expected_hash=record.candidate_application_hash,
                )
                return security.passed

            def verify_lkg() -> bool:
                return self._runtime_verifier.observe_lkg_health(
                    installation_root=self.installation_root
                ).passed

            result = coordinator.boot_candidate(
                record.recovery_transaction_id or transaction_id,
                candidate_snapshot,
                start=start,
                health_check=verify_candidate,
                lkg_health_check=verify_lkg,
                destinations=(
                    {}
                    if self._candidate_installer is not None
                    else {
                        path: self.installation_root / Path(path) for path in record.changed_paths
                    }
                ),
            )
            if result == candidate_snapshot:
                return self._transition(record, ActivationStatus.COMMITTED)
            if start_evidence is not None:
                return self._fail(
                    record,
                    ActivationStatus.SAFE_MODE_REQUIRED
                    if coordinator.safe_mode
                    else ActivationStatus.ROLLED_BACK,
                    self._start_failure_detail(start_evidence),
                )
            if coordinator.safe_mode:
                return self._fail(
                    record,
                    ActivationStatus.SAFE_MODE_REQUIRED,
                    "rollback could not establish known-good",
                )
            return self._fail(record, ActivationStatus.ROLLED_BACK, "candidate verification failed")
        except (ActivationError, GoldenGateError, RecoveryError) as error:
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
            self._revalidate(record, proposal)
            if self._candidate_installer is not None:
                candidate_snapshot_id = record.candidate_snapshot_id
                if candidate_snapshot_id is None:
                    return self._fail(
                        record,
                        ActivationStatus.QUARANTINED,
                        "versioned candidate snapshot is unavailable during recovery",
                    )
                candidate_root = self.installation_root / candidate_snapshot_id
                _contained_directory_target(candidate_root, self.installation_root)
                manifest = self.recovery.store.load(candidate_snapshot_id)
                current = compute_application_build_hash(candidate_root)
                if (
                    manifest.app_revision != record.candidate_revision
                    or manifest.application_hash != record.candidate_application_hash
                    or current != record.candidate_application_hash
                ):
                    return self._fail(
                        record,
                        ActivationStatus.QUARANTINED,
                        "versioned candidate identity is contradictory",
                    )
            else:
                current = _installed_candidate_hash(proposal, self.installation_root)
                if current != record.candidate_hash:
                    old = _known_good_candidate_hash(self.recovery, proposal)
                    if old is not None and current == old:
                        return self._fail(
                            record,
                            ActivationStatus.FAILED,
                            "effect did not start; no automatic retry",
                        )
                    return self._fail(
                        record, ActivationStatus.QUARANTINED, "ambiguous activation state"
                    )
                if record.candidate_snapshot_id is None:
                    snapshot = self._snapshot_candidate(
                        record.recovery_transaction_id or str(uuid4()),
                        record.changed_paths,
                        proposal,
                    )
                    record = self._transition(
                        record, ActivationStatus.APPLIED, candidate_snapshot_id=snapshot
                    )
            candidate_snapshot_id = record.candidate_snapshot_id
            if candidate_snapshot_id is None:
                raise ActivationError("candidate snapshot is unavailable during recovery")
            candidate_root = (
                self.installation_root / candidate_snapshot_id
                if self._candidate_installer is not None
                else self.installation_root
            )
            start_evidence: CandidateStartEvidence | None = None

            def start() -> None:
                nonlocal start_evidence
                evidence = self._runtime_verifier.start_candidate(
                    installation_root=candidate_root,
                    expected_revision=record.candidate_revision,
                    expected_hash=record.candidate_application_hash,
                )
                start_evidence = evidence
                if (
                    not evidence.started
                    or evidence.observed_revision != record.candidate_revision
                    or evidence.observed_application_hash != record.candidate_application_hash
                    or (
                        self._candidate_installer is not None
                        and (
                            evidence.observed_root != str(candidate_root.resolve())
                            or evidence.snapshot_id != candidate_snapshot_id
                        )
                    )
                ):
                    raise ActivationError(
                        "trusted candidate start did not observe exact candidate: "
                        f"outcome={evidence.outcome.value};detail={evidence.detail}"
                    )

            def verify_candidate() -> bool:
                health = self._runtime_verifier.observe_candidate_health(
                    installation_root=candidate_root,
                    expected_hash=record.candidate_application_hash,
                )
                if not health.passed:
                    return False
                security = self._runtime_verifier.observe_candidate_security(
                    installation_root=candidate_root,
                    expected_hash=record.candidate_application_hash,
                )
                return security.passed

            def verify_lkg() -> bool:
                return self._runtime_verifier.observe_lkg_health(
                    installation_root=self.installation_root
                ).passed

            result = self.recovery.boot_candidate(
                record.recovery_transaction_id or str(uuid4()),
                candidate_snapshot_id,
                start=start,
                health_check=verify_candidate,
                lkg_health_check=verify_lkg,
                destinations=(
                    {}
                    if self._candidate_installer is not None
                    else {
                        path: self.installation_root / Path(path) for path in record.changed_paths
                    }
                ),
            )
            if result == candidate_snapshot_id:
                return self._transition(record, ActivationStatus.COMMITTED)
            if start_evidence is not None:
                return self._fail(
                    record,
                    ActivationStatus.SAFE_MODE_REQUIRED
                    if self.recovery.safe_mode
                    else ActivationStatus.ROLLED_BACK,
                    self._start_failure_detail(start_evidence),
                )
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
        if compute_application_build_hash(workspace) != record.candidate_application_hash:
            raise ActivationError("candidate application identity changed after testing")
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
            if name in {
                "trusted_approval",
                "recovery_point",
                "startup_health",
                "runtime_integrity",
            }:
                continue
            item = evidence.get(name)
            if item is None or item.name != name or not item.passed:
                raise ActivationError(f"required gate did not pass: {name}")

    async def _run_golden(self, proposal: MergeDeploymentProposal) -> bool:
        runner = self._golden_runner
        bind = getattr(runner, "for_candidate", None)
        if callable(bind):
            runner = bind(
                root=_candidate_workspace(proposal),
                proposal_fingerprint=proposal.proposal_fingerprint,
            )
        return bool(await _maybe(runner()))

    async def _authorize_effect(self, record: ActivationRecord) -> AuthorizationResult:
        if self._candidate_installer is not None:
            paths = self._candidate_effect_paths(record)
        else:
            paths = tuple(
                str((self.installation_root / Path(path)).resolve())
                for path in record.changed_paths
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
                "candidate_application_hash": record.candidate_application_hash,
                "effect_paths": paths,
            },
        )

    def _candidate_identity(self, record: ActivationRecord) -> str:
        installer = self._candidate_installer
        identity = getattr(installer, "_identity", None)
        if not callable(identity):
            return hashlib.sha256(
                "\x1f".join(
                    (
                        record.proposal_fingerprint,
                        record.candidate_hash,
                        record.candidate_application_hash,
                        record.candidate_revision,
                        record.candidate_tree_digest,
                    )
                ).encode("utf-8")
            ).hexdigest()
        return str(identity(record))

    def _candidate_effect_paths(self, record: ActivationRecord) -> tuple[str, ...]:
        paths = getattr(self._candidate_installer, "effect_paths", None)
        if not callable(paths):
            raise ActivationError("candidate installer lacks an exact materialization plan")
        return tuple(str(Path(path).resolve()) for path in paths(record))

    def _bind_previous_lkg(
        self,
        record: ActivationRecord,
        transaction_id: str,
        proposal: MergeDeploymentProposal,
        *,
        transition: bool = True,
    ) -> ActivationRecord:
        trusted = self.recovery.store.last_known_good_record()
        bound_lkg = (
            record.previous_lkg_snapshot_id,
            record.previous_lkg_application_hash,
            record.previous_lkg_revision,
        )
        if any(item is not None for item in bound_lkg) and not all(
            item is not None for item in bound_lkg
        ):
            raise ActivationError("authenticated LKG binding is incomplete")
        if all(item is not None for item in bound_lkg):
            if trusted is None or (
                trusted.snapshot_id != record.previous_lkg_snapshot_id
                or trusted.application_hash != record.previous_lkg_application_hash
                or trusted.app_revision != record.previous_lkg_revision
            ):
                raise ActivationError("authenticated LKG changed after exact approval")
        if trusted is None:
            application_hash = compute_application_build_hash(self.production_root)
            snapshot = self.recovery.store.create_snapshot(
                transaction_id=transaction_id,
                app_revision=proposal.workspace.base_revision,
                application_hash=application_hash,
                configuration={"source_root": str(self.production_root)},
                database_schema={},
                integration_versions={},
                files=(),
            )
            self.recovery.begin_start(
                transaction_id,
                candidate_snapshot_id=snapshot.snapshot_id,
                candidate_build=proposal.workspace.base_revision,
                candidate_application_hash=application_hash,
            )
            if self.recovery.safe_mode:
                raise ActivationError("Recovery entered safe mode while binding initial LKG")
            self.recovery.store.commit_start(transaction_id, snapshot.snapshot_id)
            trusted = self.recovery.store.last_known_good_record()
            if trusted is None:
                raise ActivationError("initial authenticated LKG could not be established")
        manifest = self.recovery.store.load(trusted.snapshot_id)
        if manifest.application_hash != trusted.application_hash:
            raise ActivationError("authenticated LKG manifest identity is inconsistent")
        changes: dict[str, Any] = {
            "recovery_snapshot_id": trusted.snapshot_id,
            "previous_lkg_snapshot_id": trusted.snapshot_id,
            "previous_lkg_application_hash": trusted.application_hash,
            "previous_lkg_revision": trusted.app_revision,
        }
        if not transition:
            return replace(record, **changes)
        return self._transition(record, ActivationStatus.SNAPSHOT_CREATED, **changes)

    def _start_failure_detail(self, evidence: CandidateStartEvidence) -> str:
        return (
            "candidate start failed: "
            f"outcome={evidence.outcome.value};detail={evidence.detail};"
            f"root={evidence.observed_root};snapshot={evidence.snapshot_id};"
            f"application_hash={evidence.observed_application_hash}"
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


def _assert_proposal_fingerprint(proposal: MergeDeploymentProposal) -> None:
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
    if expected != proposal.proposal_fingerprint:
        raise ActivationError("proposal fingerprint is not trusted")


def _proposal_to_json(proposal: MergeDeploymentProposal) -> dict[str, object]:
    return cast(dict[str, object], _json_value(proposal))


def _json_value(value: object) -> object:
    if hasattr(value, "__dataclass_fields__"):
        return {
            item.name: _json_value(getattr(value, item.name))
            for item in fields(value)  # type: ignore[arg-type]
        }
    if isinstance(value, StrEnum):
        return value.value
    if isinstance(value, UUID | Path):
        return str(value)
    if isinstance(value, datetime):
        return value.isoformat()
    if isinstance(value, tuple):
        return [_json_value(item) for item in value]
    if isinstance(value, list):
        return [_json_value(item) for item in value]
    if isinstance(value, dict):
        return {str(key): _json_value(item) for key, item in value.items()}
    return value


def _proposal_from_json(value: Mapping[str, object]) -> MergeDeploymentProposal:
    candidate_value = _mapping(value, "candidate")
    candidate = ImprovementCandidate(
        str(candidate_value["candidate_id"]),
        ImprovementSource(str(candidate_value["source"])),
        tuple(
            ImprovementEvidence(
                str(item["source_reference"]),
                str(item["summary"]),
                int(cast(Any, item.get("occurrence_count", 1))),
                str(item["content_digest"]) if item.get("content_digest") else None,
                bool(item.get("external_untrusted", False)),
            )
            for item in _mappings(candidate_value, "evidence")
        ),
        str(candidate_value["proposed_objective"]),
        str(candidate_value["expected_benefit"]),
        tuple(str(item) for item in _sequence(candidate_value, "affected_components")),
        Risk(str(candidate_value["risk"])),
        Reversibility(str(candidate_value["reversibility"])),
        tuple(
            EvaluationScenario(
                str(item["scenario_id"]),
                str(item["description"]),
                str(item["metric"]),
                EvaluationDirection(str(item["direction"])),
                float(cast(Any, item["baseline_value"])),
                float(cast(Any, item["required_delta"])),
            )
            for item in _mappings(candidate_value, "evaluation_plan")
        ),
        int(cast(Any, candidate_value["impact"])),
        int(cast(Any, candidate_value["frequency"])),
        int(cast(Any, candidate_value["confidence"])),
        int(cast(Any, candidate_value["implementation_cost"])),
        int(cast(Any, candidate_value["user_relevance"])),
    )
    specification_value = _mapping(value, "specification")
    specification = ChangeSpecification(
        str(specification_value["specification_id"]),
        str(specification_value["candidate_id"]),
        str(specification_value["problem"]),
        str(specification_value["intended_behavior"]),
        tuple(str(item) for item in _sequence(specification_value, "boundaries")),
        tuple(str(item) for item in _sequence(specification_value, "likely_affected_paths")),
        tuple(str(item) for item in _sequence(specification_value, "required_tests")),
        str(specification_value["rollback_plan"]),
    )
    workspace_value = _mapping(value, "workspace")
    workspace = IsolatedWorkspace(
        str(workspace_value["workspace_id"]),
        Path(str(workspace_value["root"])),
        str(workspace_value["branch"]),
        str(workspace_value["base_revision"]),
        datetime.fromisoformat(str(workspace_value["created_at"])),
    )
    modification_value = _mapping(value, "modification")
    modification = ModificationResult(
        str(modification_value["workspace_id"]),
        tuple(str(item) for item in _sequence(modification_value, "changed_paths")),
        str(modification_value["diff_digest"]),
        str(modification_value["tree_digest"]),
        str(modification_value["candidate_revision"])
        if modification_value.get("candidate_revision") is not None
        else None,
    )
    gates = tuple(
        GateResult(
            GateKind(str(item["kind"])),
            GateStatus(str(item["status"])),
            str(item["summary"]),
            str(item["evidence_digest"]),
        )
        for item in _mappings(value, "gates")
    )
    evaluation_value = _mapping(value, "evaluation")
    evaluation = EvaluationResult(
        EvaluationStatus(str(evaluation_value["status"])),
        tuple(
            ScenarioResult(
                str(item["scenario_id"]),
                float(cast(Any, item["baseline_value"])),
                float(cast(Any, item["candidate_value"])),
                float(cast(Any, item["observed_delta"])),
                bool(item["passed"]),
            )
            for item in _mappings(evaluation_value, "scenarios")
        ),
        str(evaluation_value["reason_code"]),
    )
    dependency_value = _mapping(value, "dependency_assessment")
    dependency = DependencyAssessment(
        bool(dependency_value["allowed"]),
        str(dependency_value["reason_code"]),
        tuple(
            DependencyChange(
                str(item["name"]),
                _dependency_record(item.get("previous")),
                _dependency_record(item.get("proposed")),
                str(item["risk_analysis"]) if item.get("risk_analysis") is not None else None,
            )
            for item in _mappings(dependency_value, "changes")
        ),
    )
    rollback_value = _mapping(value, "rollback")
    rollback = RollbackMetadata(
        str(rollback_value["previous_known_good_revision"]),
        str(rollback_value["candidate_revision"])
        if rollback_value.get("candidate_revision") is not None
        else None,
        tuple(str(item) for item in _sequence(rollback_value, "changed_paths")),
        tuple(str(item) for item in _sequence(rollback_value, "restoration_steps")),
    )
    return MergeDeploymentProposal(
        str(value["proposal_id"]),
        UUID(str(value["task_id"])),
        candidate,
        specification,
        workspace,
        modification,
        gates,
        evaluation,
        dependency,
        rollback,
        str(value["proposal_fingerprint"]),
        datetime.fromisoformat(str(value["created_at"])),
        datetime.fromisoformat(str(value["expires_at"])),
    )


def _mapping(value: Mapping[str, object], key: str) -> Mapping[str, object]:
    item = value.get(key)
    if not isinstance(item, Mapping):
        raise ActivationError(f"durable proposal field is malformed: {key}")
    return item


def _mappings(value: Mapping[str, object], key: str) -> tuple[Mapping[str, object], ...]:
    return tuple(_mapping_item(item, key) for item in _sequence(value, key))


def _mapping_item(value: object, key: str) -> Mapping[str, object]:
    if not isinstance(value, Mapping):
        raise ActivationError(f"durable proposal collection is malformed: {key}")
    return value


def _sequence(value: Mapping[str, object], key: str) -> tuple[object, ...]:
    item = value.get(key)
    if not isinstance(item, list):
        raise ActivationError(f"durable proposal collection is malformed: {key}")
    return tuple(item)


def _dependency_record(value: object) -> DependencyRecord | None:
    if value is None:
        return None
    if not isinstance(value, Mapping):
        raise ActivationError("durable dependency record is malformed")
    return DependencyRecord(str(value["name"]), str(value["version"]), str(value["source"]))


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
        "candidate_application_hash": record.candidate_application_hash,
        "candidate_tree_digest": record.candidate_tree_digest,
        "candidate_diff_digest": record.candidate_diff_digest,
        "changed_paths": list(record.changed_paths),
        "trust_level": record.trust_level,
        "required_gates": list(record.required_gates),
        "preview_fingerprint": record.preview_fingerprint,
        "activation_expires_at": record.expires_at.astimezone(UTC).isoformat(),
        "proposal_expires_at": record.expires_at.astimezone(UTC).isoformat(),
        "previous_lkg_snapshot_id": record.previous_lkg_snapshot_id,
        "previous_lkg_application_hash": record.previous_lkg_application_hash,
        "previous_lkg_revision": record.previous_lkg_revision,
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
    candidate = path.expanduser()
    if candidate.is_symlink() or candidate.is_junction():
        raise ActivationError(f"{label} is not a regular directory")
    resolved = candidate.resolve()
    if not resolved.is_dir() or resolved.is_symlink() or resolved.is_junction():
        raise ActivationError(f"{label} is not a regular directory")
    return resolved


def _sanitized_candidate_environment(root: Path) -> dict[str, str]:
    """Build the candidate allowlist without inheriting test or secret state."""

    environment: dict[str, str] = {}
    for name in ("SystemRoot", "SYSTEMROOT", "WINDIR", "TEMP", "TMP", "PATH"):
        value = os.environ.get(name)
        if value:
            environment[name] = value
    environment.update(
        {
            "PYTHONNOUSERSITE": "1",
            "PYTHONDONTWRITEBYTECODE": "1",
            "PYTHONUNBUFFERED": "1",
            "PYTHONPATH": str(root),
        }
    )
    return environment


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


def _contained_directory_target(path: Path, root: Path) -> None:
    """Validate a versioned directory namespace before any materialization."""

    resolved_root = _directory(root, "installation root")
    candidate = path.expanduser()
    if candidate.is_symlink() or candidate.is_junction():
        raise ActivationError("activation namespace contains a link")
    resolved = candidate.resolve(strict=False)
    if resolved == resolved_root or resolved_root not in resolved.parents:
        raise ActivationError("activation namespace is not a child of installation root")
    current = resolved_root
    for part in resolved.relative_to(resolved_root).parts:
        current = current / part
        if current.is_symlink() or current.is_junction():
            raise ActivationError("activation namespace contains a link")


def _tree_digest(root: Path) -> str:
    digest = hashlib.sha256()
    transient_directories = frozenset({".mypy_cache", ".pytest_cache", ".ruff_cache"})
    for path in sorted(root.rglob("*"), key=lambda item: item.as_posix().casefold()):
        relative = path.relative_to(root).as_posix()
        if relative == ".git" or relative.startswith(".git/"):
            continue
        if any(part in transient_directories for part in path.parts) or path.name == ".coverage":
            continue
        if "__pycache__" in path.parts or path.suffix in {".pyc", ".pyo"}:
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


def _candidate_host_payload(stdout: str) -> Mapping[str, object] | None:
    try:
        value = json.loads(stdout.strip().splitlines()[-1])
    except (IndexError, json.JSONDecodeError):
        return None
    return value if isinstance(value, Mapping) else None


def _git_changed_paths(root: Path, base: str) -> set[str]:
    result = subprocess.run(
        ["git", "-C", str(root), "diff", "--name-only", base, "--"],
        check=False,
        capture_output=True,
        text=True,
        timeout=30,
    )
    if result.returncode != 0:
        raise ActivationError("candidate changed-path identity is unavailable")
    changed = {line.strip() for line in result.stdout.splitlines() if line.strip()}
    untracked = subprocess.run(
        ["git", "-C", str(root), "ls-files", "--others", "--exclude-standard"],
        check=False,
        capture_output=True,
        text=True,
        timeout=30,
    )
    if untracked.returncode != 0:
        raise ActivationError("candidate untracked-path identity is unavailable")
    changed.update(line.strip() for line in untracked.stdout.splitlines() if line.strip())
    return changed


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
    if "candidate_application_hash" not in decoded:
        raise ActivationError(
            "durable activation lacks candidate application identity; re-prepare is required"
        )
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
    "CandidateStartOutcome",
    "CandidateStartEvidence",
    "CandidateInstallation",
    "CandidateInstaller",
    "DurableProposalStore",
    "GateEvidence",
    "GoldenWorkflowOwner",
    "RuntimeVerificationEvidence",
    "ProductionCandidateInstaller",
    "ProductionCurrentGateExecutor",
    "ProductionGoldenExecutor",
    "ProductionSelfDevelopmentGateVerifier",
    "ProductionSelfDevelopmentRuntimeVerifier",
    "SelfDevelopmentSupport",
    "SelfDevelopmentSupportDetector",
    "SelfDevelopmentSupportResult",
    "SelfDevelopmentRuntimeVerifier",
    "TrustedSelfDevelopmentBootSelector",
    "TrustedSelfDevelopmentActivator",
    "UnavailableSelfDevelopmentGateVerifier",
    "UnavailableSelfDevelopmentRuntimeVerifier",
    "approval_binding_fingerprint",
    "approval_request_id",
]
