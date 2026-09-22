"""Adversarial tests for the trusted self-development activation boundary."""

from __future__ import annotations

import hashlib
import json
import os
import runpy
import shutil
import sqlite3
import subprocess
import sys
from dataclasses import replace
from datetime import UTC, datetime, timedelta
from pathlib import Path
from types import SimpleNamespace
from typing import Any, cast
from uuid import UUID

import jarvis.self_development as self_development
import jarvis.self_development_host as self_development_host
import pytest
from jarvis.credentials import (
    CredentialNotFound,
    EphemeralQualificationSecretBackend,
    TestOnlyInMemorySecretBackend,
)
from jarvis.improvement.integrity import compute_proposal_fingerprint
from jarvis.improvement.models import (
    ChangeSpecification,
    DependencyAssessment,
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
from jarvis.permissions.approval import TrustedApprovalAuthenticator
from jarvis.permissions.broker import PermissionBroker
from jarvis.permissions.models import (
    ApprovalActorKind,
    ApprovalChoice,
    ApprovalIdentity,
    ApprovalSource,
    Decision,
    Permission,
    PolicyRule,
    Risk,
    ScopeConstraint,
)
from jarvis.permissions.policy import PolicyEngine
from jarvis.recovery import (
    RecoveryCoordinator,
    RecoveryStore,
    TrustedRecoveryAuthority,
    compute_application_build_hash,
)
from jarvis.runtime import RuntimeStatus
from jarvis.security.modification_policy import ModificationTrustClassifier
from jarvis.self_development import (
    ActivationError,
    ActivationRecord,
    ActivationStateStore,
    ActivationStatus,
    CandidateInstallation,
    CandidateStartEvidence,
    CandidateStartOutcome,
    DurableProposalStore,
    GateEvidence,
    GoldenWorkflowOwner,
    ProductionCandidateInstaller,
    ProductionCurrentGateExecutor,
    ProductionGoldenExecutor,
    ProductionSelfDevelopmentGateVerifier,
    ProductionSelfDevelopmentRuntimeVerifier,
    RuntimeVerificationEvidence,
    SelfDevelopmentSupport,
    SelfDevelopmentSupportDetector,
    TrustedSelfDevelopmentActivator,
    TrustedSelfDevelopmentBootSelector,
    UnavailableSelfDevelopmentGateVerifier,
    UnavailableSelfDevelopmentRuntimeVerifier,
    _activation_uuid,
    _aware,
    _candidate_hash,
    _candidate_host_payload,
    _candidate_workspace,
    _contained_regular_target,
    _directory,
    _git_diff_digest,
    _git_head,
    _installed_candidate_hash,
    _known_good_candidate_hash,
    _maybe,
    _tree_digest,
    approval_binding_fingerprint,
    approval_request_id,
    register_production_self_development_golden,
)
from jarvis.testing.golden import (
    ExpectedResult,
    Fixture,
    GoldenChangeKind,
    GoldenGateError,
    GoldenWorkflow,
    GoldenWorkflowClass,
    GoldenWorkflowService,
    GoldenWorkflowStore,
    Version,
)
from jarvis.update_preview import UpdateGateName, UpdateGateResult, UpdateGateStatus
from jarvis.verification import EvidenceRecord, EvidenceType, VerificationLevel

NOW = datetime(2026, 9, 12, 14, 0, tzinfo=UTC)
REVISION = "a" * 40
TASK_ID = UUID("00000000-0000-0000-0000-000000000011")


class _TestRuntimeVerifier:
    def __init__(self, *, health: bool = True, security: bool = True, lkg: bool = True) -> None:
        self.health = health
        self.security = security
        self.lkg = lkg
        self.calls: list[str] = []

    def start_candidate(
        self, *, installation_root: Path, expected_revision: str, expected_hash: str
    ) -> CandidateStartEvidence:
        del installation_root
        self.calls.append("start")
        return CandidateStartEvidence(
            True, expected_revision, expected_hash, hashlib.sha256(b"start").hexdigest()
        )

    def observe_candidate_health(
        self, *, installation_root: Path, expected_hash: str
    ) -> RuntimeVerificationEvidence:
        del installation_root, expected_hash
        self.calls.append("health")
        return RuntimeVerificationEvidence(
            self.health, hashlib.sha256(b"health").hexdigest(), "test health observation"
        )

    def observe_candidate_security(
        self, *, installation_root: Path, expected_hash: str
    ) -> RuntimeVerificationEvidence:
        del installation_root, expected_hash
        self.calls.append("security")
        return RuntimeVerificationEvidence(
            self.security, hashlib.sha256(b"security").hexdigest(), "test security observation"
        )

    def observe_lkg_health(self, *, installation_root: Path) -> RuntimeVerificationEvidence:
        del installation_root
        self.calls.append("lkg")
        return RuntimeVerificationEvidence(
            self.lkg, hashlib.sha256(b"lkg").hexdigest(), "test LKG observation"
        )


class _MissingHealthVerifier:
    def __init__(self) -> None:
        self._delegate = _TestRuntimeVerifier()

    def __getattr__(self, name: str) -> object:
        if name == "observe_candidate_health":
            raise AttributeError(name)
        return getattr(self._delegate, name)


class _ProcessRuntimeVerifier(_TestRuntimeVerifier):
    """Disposable Windows process boundary used by the composition test."""

    def start_candidate(
        self, *, installation_root: Path, expected_revision: str, expected_hash: str
    ) -> CandidateStartEvidence:
        subprocess.run(
            [
                sys.executable,
                "-c",
                "from pathlib import Path; assert Path('jarvis/example.py').is_file()",
            ],
            cwd=installation_root,
            check=True,
        )
        self.calls.append("start")
        return CandidateStartEvidence(
            True,
            expected_revision,
            expected_hash,
            hashlib.sha256(b"process-start").hexdigest(),
        )

    def observe_candidate_health(
        self, *, installation_root: Path, expected_hash: str
    ) -> RuntimeVerificationEvidence:
        del expected_hash
        result = subprocess.run(
            [
                sys.executable,
                "-c",
                "from pathlib import Path; "
                "assert 'VALUE = 2' in Path('jarvis/example.py').read_text()",
            ],
            cwd=installation_root,
            check=False,
        )
        self.calls.append("health")
        return RuntimeVerificationEvidence(
            result.returncode == 0,
            hashlib.sha256(b"process-health").hexdigest(),
            "disposable candidate process health",
        )

    def observe_candidate_security(
        self, *, installation_root: Path, expected_hash: str
    ) -> RuntimeVerificationEvidence:
        candidate_file = installation_root / "jarvis/example.py"
        self.calls.append("security")
        return RuntimeVerificationEvidence(
            candidate_file.is_file()
            and not candidate_file.is_symlink()
            and len(expected_hash) == 64,
            hashlib.sha256(b"process-security").hexdigest(),
            "disposable candidate identity and regular-file check",
        )

    def observe_lkg_health(self, *, installation_root: Path) -> RuntimeVerificationEvidence:
        result = subprocess.run(
            [
                sys.executable,
                "-c",
                "from pathlib import Path; "
                "assert 'VALUE = 1' in Path('jarvis/example.py').read_text()",
            ],
            cwd=installation_root,
            check=False,
        )
        self.calls.append("lkg")
        return RuntimeVerificationEvidence(
            result.returncode == 0,
            hashlib.sha256(b"process-lkg-health").hexdigest(),
            "disposable LKG process health",
        )


def _golden_owner(path: Path, *, passed: bool = True) -> GoldenWorkflowOwner:
    store = GoldenWorkflowStore(path)
    store.register(
        GoldenWorkflow(
            "self-development-test",
            "Self-development test workflow",
            Version(1, 0, 0),
            GoldenWorkflowClass.DETERMINISTIC,
            (
                Fixture(
                    "fixture-1",
                    "Synthetic self-development fixture",
                    {"case": "self-development"},
                    ExpectedResult("Verify activation", ("activation_observed",)),
                ),
            ),
            frozenset({GoldenChangeKind.SELF_IMPROVEMENT}),
            provenance=("test:trusted-golden-owner",),
        )
    )
    service = GoldenWorkflowService(store, clock=lambda: NOW)

    def execute(_workflow: object, _fixture: object) -> tuple[EvidenceRecord, ...]:
        observed = "activation_observed" if passed else "activation_failed"
        return (
            EvidenceRecord(
                EvidenceType.CUSTOM,
                "trusted.test-golden-observer",
                NOW,
                timedelta(minutes=5),
                1.0,
                "activation_observed",
                observed,
                level=VerificationLevel.AUTOMATED_TESTED,
            ),
        )

    return GoldenWorkflowOwner(service, execute)


def _git(root: Path, *args: str) -> str:
    result = subprocess.run(
        ["git", "-C", str(root), *args],
        check=True,
        capture_output=True,
        text=True,
    )
    return result.stdout.strip()


def _tree(root: Path) -> str:
    return _tree_digest(root)


def _make_proposal(
    root: Path, *, protected: bool = False
) -> tuple[MergeDeploymentProposal, Path, Path, Path]:
    production = root / "production"
    production.mkdir(parents=True)
    (production / "jarvis").mkdir()
    (production / "jarvis" / "example.py").write_text("VALUE = 1\n", encoding="utf-8")
    _git(production, "init", "-q")
    _git(production, "config", "user.email", "test@example.invalid")
    _git(production, "config", "user.name", "JARVIS test")
    _git(production, "add", ".")
    _git(production, "commit", "-qm", "base")
    base = _git(production, "rev-parse", "HEAD")
    candidate = root / "candidate"
    shutil.copytree(production, candidate)
    relative = "jarvis/permissions/example.py" if protected else "jarvis/example.py"
    candidate_path = candidate / Path(relative)
    candidate_path.parent.mkdir(parents=True, exist_ok=True)
    candidate_path.write_text("VALUE = 2\n", encoding="utf-8")
    installation = root / "installation"
    installation.mkdir()
    target = installation / Path(relative)
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text("VALUE = 1\n", encoding="utf-8")
    diff = subprocess.run(
        ["git", "-C", str(candidate), "diff", "--binary", base, "--", relative],
        check=True,
        capture_output=True,
    ).stdout
    now = NOW - timedelta(minutes=1)
    candidate_model = ImprovementCandidate(
        "candidate-1",
        ImprovementSource.REPEATED_ERROR,
        (ImprovementEvidence("telemetry:repeat", "Repeated deterministic failure"),),
        "Improve the deterministic example",
        "The example becomes more reliable",
        (relative,),
        Risk.LOW,
        Reversibility.FULL,
        (
            EvaluationScenario(
                "scenario-1", "basic result", "result", EvaluationDirection.INCREASE, 1.0, 0.5
            ),
        ),
        80,
        80,
        80,
        10,
        80,
    )
    specification = ChangeSpecification(
        "spec-1",
        "candidate-1",
        "A bounded test improvement",
        "The exact file changes behavior",
        ("Only the named file may change",),
        (relative,),
        ("Run the protected regression",),
        "Restore the previous known-good file",
    )
    workspace = IsolatedWorkspace("workspace-1", candidate, "detached/test", base, now)
    modification = ModificationResult(
        workspace.workspace_id,
        (relative,),
        hashlib.sha256(diff).hexdigest(),
        _tree(candidate),
    )
    gates = tuple(
        GateResult(
            kind, GateStatus.PASSED, "passed", hashlib.sha256(kind.value.encode()).hexdigest()
        )
        for kind in GateKind
    )
    evaluation = EvaluationResult(
        EvaluationStatus.IMPROVED,
        (ScenarioResult("scenario-1", 1.0, 2.0, 1.0, True),),
        "protected_scenarios_improved",
    )
    dependency = DependencyAssessment(True, "no_dependency_change", ())
    rollback = RollbackMetadata(base, None, (relative,), ("restore the exact snapshot",))
    proposal_id = "proposal-1"
    expires = NOW + timedelta(hours=1)
    fingerprint = compute_proposal_fingerprint(
        proposal_id=proposal_id,
        task_id=TASK_ID,
        candidate=candidate_model,
        specification=specification,
        workspace=workspace,
        modification=modification,
        dependency_assessment=dependency,
        gates=gates,
        evaluation=evaluation,
        rollback=rollback,
        created_at=now,
        expires_at=expires,
    )
    return (
        MergeDeploymentProposal(
            proposal_id,
            TASK_ID,
            candidate_model,
            specification,
            workspace,
            modification,
            gates,
            evaluation,
            dependency,
            rollback,
            fingerprint,
            now,
            expires,
        ),
        production,
        candidate,
        installation,
    )


def _recovery(
    root: Path, installation: Path
) -> tuple[RecoveryCoordinator, TrustedApprovalAuthenticator]:
    backend = TestOnlyInMemorySecretBackend()
    authority = TrustedRecoveryAuthority("test-installation", backend)
    authority.initialize()
    store = RecoveryStore(root / "recovery", trusted_authority=authority, clock=lambda: NOW)
    capture_root = store.root
    captured: list[Path] = []
    for source in installation.rglob("*"):
        if source.is_file():
            capture = capture_root / source.relative_to(installation)
            capture.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(source, capture)
            captured.append(capture)
    transaction = "00000000-0000-0000-0000-000000000099"
    snapshot = store.create_snapshot(
        transaction_id=transaction,
        app_revision=REVISION,
        application_hash=_tree(installation),
        configuration={},
        database_schema={},
        integration_versions={},
        files=tuple(captured),
    )
    store.begin_start(
        transaction,
        candidate_snapshot_id=snapshot.snapshot_id,
        candidate_build=REVISION,
        candidate_application_hash=snapshot.application_hash,
    )
    store.commit_start(transaction, snapshot.snapshot_id)
    approval = TrustedApprovalAuthenticator(ApprovalSource.TRUSTED_LOCAL_API, clock=lambda: NOW)
    return RecoveryCoordinator(store, clock=lambda: NOW), approval


def _activator(
    tmp_path: Path,
    *,
    protected: bool = False,
    runtime_verifier: _TestRuntimeVerifier | None = None,
    versioned: bool = False,
) -> tuple[
    TrustedSelfDevelopmentActivator,
    MergeDeploymentProposal,
    Path,
    TrustedApprovalAuthenticator,
    PermissionBroker,
]:
    proposal, production, candidate, installation = _make_proposal(tmp_path, protected=protected)
    recovery, approval = _recovery(tmp_path, installation)
    task = proposal.task_id
    target = (
        installation.resolve()
        if versioned
        else (installation / Path(proposal.modification.changed_paths[0])).resolve()
    )
    rules = tuple(
        PolicyRule(
            f"self-{permission.value}",
            permission,
            Decision.ALLOW,
            ScopeConstraint(
                paths=(str(target),),
                tools=frozenset({TrustedSelfDevelopmentActivator.TOOL_ID}),
                tasks=frozenset({task}),
            ),
            frozenset({"activate_exact_self_development"}),
        )
        for permission in (Permission.CODE_MODIFY, Permission.FILESYSTEM_WRITE)
    )
    broker = PermissionBroker(
        PolicyEngine(rules), approval_context_verifier=approval.verifier(), clock=lambda: NOW
    )
    store = ActivationStateStore(tmp_path / "activation.sqlite3")
    evidence = {
        name: GateEvidence(name, True, hashlib.sha256(name.encode()).hexdigest())
        for name in (
            "static_security",
            "sandbox_tests",
            "package_certification",
            "quality",
            "integration_tests",
            "protected_regression",
            "trusted_approval",
            "startup_health",
            "security_review",
        )
    }
    service = TrustedSelfDevelopmentActivator(
        production_root=production,
        installation_root=installation,
        recovery=recovery,
        activation_store=store,
        permission_broker=broker,
        approval_verifier=approval.verifier(),
        proposal_loader=lambda proposal_id: proposal
        if proposal_id == proposal.proposal_id
        else None,
        gate_verifier=lambda _proposal, _classification: evidence,
        golden_runner=_golden_owner(tmp_path / "golden.sqlite3"),
        runtime_verifier=runtime_verifier or _TestRuntimeVerifier(),
        candidate_installer=(
            ProductionCandidateInstaller(production, installation, recovery) if versioned else None
        ),
        clock=lambda: NOW,
    )
    return service, proposal, installation, approval, broker


def _preview_gates() -> tuple[UpdateGateResult, ...]:
    digest = hashlib.sha256(b"gate").hexdigest()
    return tuple(UpdateGateResult(name, UpdateGateStatus.PASSED, digest) for name in UpdateGateName)


@pytest.mark.asyncio
async def test_exact_activation_promotes_only_after_recovery_verification(tmp_path: Path) -> None:
    service, proposal, installation, approval, _broker = _activator(tmp_path)
    record = service.prepare(
        proposal,
        current_version="1",
        candidate_version="2",
        changed_subsystems=("jarvis",),
        preview_gates=_preview_gates(),
    )
    context = approval.issue_context(
        request_id=approval_request_id(record),
        choice=ApprovalChoice.APPROVE_ONCE,
        identity=ApprovalIdentity("trusted-user", ApprovalActorKind.TRUSTED_USER),
    )
    record = await service.approve(record.activation_id, context)
    pending = await service._authorize_effect(record)
    permission_contexts = tuple(
        approval.issue_context(
            request_id=request.request_id,
            choice=ApprovalChoice.APPROVE_ONCE,
            identity=ApprovalIdentity("trusted-user", ApprovalActorKind.TRUSTED_USER),
        )
        for request in pending.approval_requests
    )
    final = await service.activate(record.activation_id, permission_contexts=permission_contexts)
    assert final.status is ActivationStatus.COMMITTED
    assert cast(_TestRuntimeVerifier, service._runtime_verifier).calls == [
        "start",
        "health",
        "security",
    ]
    assert (installation / "jarvis/example.py").read_text(encoding="utf-8") == "VALUE = 2\n"
    assert service.store.get(record.activation_id) == final


@pytest.mark.asyncio
async def test_versioned_candidate_binds_application_identity_and_brokered_materialization(
    tmp_path: Path,
) -> None:
    events: list[str] = []

    class VersionedRuntimeVerifier(_TestRuntimeVerifier):
        def start_candidate(
            self, *, installation_root: Path, expected_revision: str, expected_hash: str
        ) -> CandidateStartEvidence:
            self.boot_root = installation_root.resolve()
            events.append("start")
            self.calls.append("start")
            return CandidateStartEvidence(
                True,
                expected_revision,
                expected_hash,
                hashlib.sha256(b"versioned-start").hexdigest(),
                observed_root=str(installation_root.resolve()),
                snapshot_id=installation_root.name,
            )

    verifier = VersionedRuntimeVerifier()
    service, proposal, installation, approval, broker = _activator(
        tmp_path, versioned=True, runtime_verifier=verifier
    )
    record = service.prepare(
        proposal,
        current_version="1",
        candidate_version="2",
        changed_subsystems=("jarvis",),
        preview_gates=_preview_gates(),
    )
    assert record.candidate_application_hash != record.candidate_hash
    request_before = approval_request_id(record)
    installer = cast(ProductionCandidateInstaller, service._candidate_installer)
    assert not installer.planned_root(record).exists()
    assert verifier.calls == []
    context = approval.issue_context(
        request_id=request_before,
        choice=ApprovalChoice.APPROVE_ONCE,
        identity=ApprovalIdentity("trusted-user", ApprovalActorKind.TRUSTED_USER),
    )
    record = await service.approve(record.activation_id, context)
    assert approval_request_id(record) == request_before
    pending = await service._authorize_effect(record)
    authorized_root = Path(pending.approval_requests[0].scope.paths[0]).resolve()
    permission_contexts = tuple(
        approval.issue_context(
            request_id=request.request_id,
            choice=ApprovalChoice.APPROVE_ONCE,
            identity=ApprovalIdentity("trusted-user", ApprovalActorKind.TRUSTED_USER),
        )
        for request in pending.approval_requests
    )
    authorize = broker.authorize
    begin = broker.begin_execution
    stage = installer.stage
    record_outcome = broker.record_execution_outcome

    async def observed_authorize(*args: Any, **kwargs: Any) -> Any:
        events.append("authorize")
        return await authorize(*args, **kwargs)

    async def observed_begin(*args: Any, **kwargs: Any) -> Any:
        events.append("begin_execution")
        return await begin(*args, **kwargs)

    def observed_stage(*args: Any, **kwargs: Any) -> CandidateInstallation:
        events.append("materialize")
        return stage(*args, **kwargs)

    async def observed_outcome(*args: Any, **kwargs: Any) -> Any:
        events.append(str(args[-1] if args else kwargs.get("outcome")))
        return await record_outcome(*args, **kwargs)

    broker.__dict__["authorize"] = observed_authorize
    broker.__dict__["begin_execution"] = observed_begin
    broker.__dict__["record_execution_outcome"] = observed_outcome
    installer.__dict__["stage"] = observed_stage
    final = await service.activate(record.activation_id, permission_contexts=permission_contexts)

    assert final.status is ActivationStatus.COMMITTED
    assert final.candidate_snapshot_id is not None
    candidate_root = installation / final.candidate_snapshot_id
    assert compute_application_build_hash(candidate_root) == record.candidate_application_hash
    assert authorized_root == installation.resolve()
    destinations = (candidate_root, *candidate_root.rglob("*"))
    assert all(
        destination.resolve() == authorized_root or authorized_root in destination.resolve().parents
        for destination in destinations
    )
    assert installer.planned_root(record).resolve().parent == authorized_root
    assert verifier.boot_root == candidate_root.resolve()
    assert (installation / "jarvis" / "example.py").read_text(encoding="utf-8") == "VALUE = 1\n"
    assert events.index("authorize") < events.index("begin_execution") < events.index("materialize")
    assert events.index("materialize") < events.index("success") < events.index("start")
    assert approval_request_id(final) == request_before
    assert final.previous_lkg_snapshot_id is not None
    assert final.previous_lkg_application_hash is not None


@pytest.mark.asyncio
async def test_versioned_materialization_failure_is_unknown_and_quarantined(tmp_path: Path) -> None:
    service, proposal, _installation, approval, _broker = _activator(tmp_path, versioned=True)
    record = service.prepare(
        proposal,
        current_version="1",
        candidate_version="2",
        changed_subsystems=("jarvis",),
        preview_gates=_preview_gates(),
    )
    context = approval.issue_context(
        request_id=approval_request_id(record),
        choice=ApprovalChoice.APPROVE_ONCE,
        identity=ApprovalIdentity("trusted-user", ApprovalActorKind.TRUSTED_USER),
    )
    record = await service.approve(record.activation_id, context)
    pending = await service._authorize_effect(record)
    permission_contexts = tuple(
        approval.issue_context(
            request_id=request.request_id,
            choice=ApprovalChoice.APPROVE_ONCE,
            identity=ApprovalIdentity("trusted-user", ApprovalActorKind.TRUSTED_USER),
        )
        for request in pending.approval_requests
    )
    installer = cast(ProductionCandidateInstaller, service._candidate_installer)

    def fail_stage(*_args: Any, **_kwargs: Any) -> CandidateInstallation:
        raise OSError("materialization probe")

    installer.__dict__["stage"] = fail_stage
    final = await service.activate(record.activation_id, permission_contexts=permission_contexts)
    assert final.status is ActivationStatus.QUARANTINED
    assert final.failure_reason == "materialization outcome unknown: OSError"


@pytest.mark.asyncio
async def test_versioned_permission_denial_has_zero_candidate_effect(tmp_path: Path) -> None:
    verifier = _TestRuntimeVerifier()
    service, proposal, installation, approval, _broker = _activator(
        tmp_path, versioned=True, runtime_verifier=verifier
    )
    record = service.prepare(
        proposal,
        current_version="1",
        candidate_version="2",
        changed_subsystems=("jarvis",),
        preview_gates=_preview_gates(),
    )
    context = approval.issue_context(
        request_id=approval_request_id(record),
        choice=ApprovalChoice.APPROVE_ONCE,
        identity=ApprovalIdentity("trusted-user", ApprovalActorKind.TRUSTED_USER),
    )
    approved = await service.approve(record.activation_id, context)
    installer = cast(ProductionCandidateInstaller, service._candidate_installer)
    final = await service.activate(approved.activation_id)

    assert final.status is ActivationStatus.FAILED
    assert not installer.planned_root(approved).exists()
    assert tuple(path for path in installation.iterdir() if path.name != "jarvis") == ()
    assert (installation / "jarvis" / "example.py").read_text(encoding="utf-8") == "VALUE = 1\n"
    assert verifier.calls == []


@pytest.mark.asyncio
async def test_versioned_binding_establishes_an_initial_authenticated_lkg(tmp_path: Path) -> None:
    service, proposal, installation, approval, _broker = _activator(tmp_path, versioned=True)
    authority = TrustedRecoveryAuthority("initial-lkg", TestOnlyInMemorySecretBackend())
    authority.initialize()
    fresh_store = RecoveryStore(
        tmp_path / "fresh-recovery", trusted_authority=authority, clock=lambda: NOW
    )
    service.recovery = RecoveryCoordinator(fresh_store, clock=lambda: NOW)
    record = service.prepare(
        proposal,
        current_version="1",
        candidate_version="2",
        changed_subsystems=("jarvis",),
        preview_gates=_preview_gates(),
    )
    request_before = approval_request_id(record)
    installer = cast(ProductionCandidateInstaller, service._candidate_installer)
    assert record.previous_lkg_snapshot_id is not None
    assert record.previous_lkg_application_hash == compute_application_build_hash(
        service.production_root
    )
    assert record.previous_lkg_revision == proposal.workspace.base_revision
    assert fresh_store.last_known_good_record() is not None
    assert not installer.planned_root(record).exists()
    assert tuple(path for path in installation.iterdir() if path.name != "jarvis") == ()
    context = approval.issue_context(
        request_id=request_before,
        choice=ApprovalChoice.APPROVE_ONCE,
        identity=ApprovalIdentity("trusted-user", ApprovalActorKind.TRUSTED_USER),
    )
    approved = await service.approve(record.activation_id, context)
    assert approval_request_id(approved) == request_before


@pytest.mark.asyncio
async def test_versioned_lkg_drift_after_approval_fails_closed(tmp_path: Path) -> None:
    verifier = _TestRuntimeVerifier()
    service, proposal, _installation, approval, _broker = _activator(
        tmp_path, versioned=True, runtime_verifier=verifier
    )
    record = service.prepare(
        proposal,
        current_version="1",
        candidate_version="2",
        changed_subsystems=("jarvis",),
        preview_gates=_preview_gates(),
    )
    request_before = approval_request_id(record)
    context = approval.issue_context(
        request_id=request_before,
        choice=ApprovalChoice.APPROVE_ONCE,
        identity=ApprovalIdentity("trusted-user", ApprovalActorKind.TRUSTED_USER),
    )
    approved = await service.approve(record.activation_id, context)
    store = service.recovery.store
    drift = store.create_snapshot(
        transaction_id="00000000-0000-0000-0000-000000000303",
        app_revision="different-authenticated-lkg",
        application_hash=compute_application_build_hash(service.production_root),
        configuration={},
        database_schema={},
        integration_versions={},
        files=(),
    )
    service.recovery.begin_start(
        "00000000-0000-0000-0000-000000000303",
        candidate_snapshot_id=drift.snapshot_id,
        candidate_build=drift.app_revision,
        candidate_application_hash=drift.application_hash,
    )
    service.recovery.store.commit_start("00000000-0000-0000-0000-000000000303", drift.snapshot_id)

    final = await service.activate(approved.activation_id)

    assert final.status is ActivationStatus.STALE
    assert final.failure_reason == "authenticated LKG changed after exact approval"
    assert approval_request_id(final) == request_before
    assert verifier.calls == []


@pytest.mark.asyncio
async def test_versioned_resume_verifies_the_authenticated_candidate_snapshot(
    tmp_path: Path,
) -> None:
    class VersionedRuntimeVerifier(_TestRuntimeVerifier):
        def start_candidate(
            self, *, installation_root: Path, expected_revision: str, expected_hash: str
        ) -> CandidateStartEvidence:
            self.calls.append("start")
            return CandidateStartEvidence(
                True,
                expected_revision,
                expected_hash,
                hashlib.sha256(b"resume-start").hexdigest(),
                observed_root=str(installation_root.resolve()),
                snapshot_id=installation_root.name,
            )

    service, proposal, installation, _approval, _broker = _activator(
        tmp_path, versioned=True, runtime_verifier=VersionedRuntimeVerifier()
    )
    record = service.prepare(
        proposal,
        current_version="1",
        candidate_version="2",
        changed_subsystems=("jarvis",),
        preview_gates=_preview_gates(),
    )
    transaction_id = "00000000-0000-0000-0000-000000000202"
    record = replace(record, recovery_transaction_id=transaction_id)
    installer = cast(ProductionCandidateInstaller, service._candidate_installer)
    candidate = installer.stage(proposal, record)
    interrupted = replace(
        record,
        status=ActivationStatus.APPLYING,
        candidate_snapshot_id=candidate.snapshot_id,
    )
    service.store.put(interrupted)
    final = await service.resume(record.activation_id)
    assert final.status is ActivationStatus.COMMITTED
    assert (installation / candidate.snapshot_id).is_dir()


@pytest.mark.asyncio
async def test_disposable_windows_candidate_process_is_verified_before_commit(
    tmp_path: Path,
) -> None:
    verifier = _ProcessRuntimeVerifier()
    service, proposal, installation, approval, _broker = _activator(
        tmp_path, runtime_verifier=verifier
    )
    record = service.prepare(
        proposal,
        current_version="1",
        candidate_version="2",
        changed_subsystems=("jarvis",),
        preview_gates=_preview_gates(),
    )
    context = approval.issue_context(
        request_id=approval_request_id(record),
        choice=ApprovalChoice.APPROVE_ONCE,
        identity=ApprovalIdentity("trusted-user", ApprovalActorKind.TRUSTED_USER),
    )
    record = await service.approve(record.activation_id, context)
    pending = await service._authorize_effect(record)
    permission_contexts = tuple(
        approval.issue_context(
            request_id=request.request_id,
            choice=ApprovalChoice.APPROVE_ONCE,
            identity=ApprovalIdentity("trusted-user", ApprovalActorKind.TRUSTED_USER),
        )
        for request in pending.approval_requests
    )

    final = await service.activate(record.activation_id, permission_contexts=permission_contexts)

    assert final.status is ActivationStatus.COMMITTED
    assert verifier.calls == ["start", "health", "security"]
    assert installation.joinpath("jarvis/example.py").read_text(encoding="utf-8") == "VALUE = 2\n"


@pytest.mark.asyncio
async def test_unavailable_runtime_verifier_fails_closed_to_safe_mode(tmp_path: Path) -> None:
    verifier = UnavailableSelfDevelopmentRuntimeVerifier()
    service, proposal, _installation, approval, _broker = _activator(
        tmp_path, runtime_verifier=cast(Any, verifier)
    )
    record = service.prepare(
        proposal,
        current_version="1",
        candidate_version="2",
        changed_subsystems=("jarvis",),
        preview_gates=_preview_gates(),
    )
    context = approval.issue_context(
        request_id=approval_request_id(record),
        choice=ApprovalChoice.APPROVE_ONCE,
        identity=ApprovalIdentity("trusted-user", ApprovalActorKind.TRUSTED_USER),
    )
    record = await service.approve(record.activation_id, context)
    pending = await service._authorize_effect(record)
    permission_contexts = tuple(
        approval.issue_context(
            request_id=request.request_id,
            choice=ApprovalChoice.APPROVE_ONCE,
            identity=ApprovalIdentity("trusted-user", ApprovalActorKind.TRUSTED_USER),
        )
        for request in pending.approval_requests
    )

    final = await service.activate(record.activation_id, permission_contexts=permission_contexts)

    assert final.status is ActivationStatus.SAFE_MODE_REQUIRED


@pytest.mark.asyncio
async def test_missing_health_observer_cannot_commit(tmp_path: Path) -> None:
    service, proposal, _installation, approval, _broker = _activator(
        tmp_path, runtime_verifier=cast(Any, _MissingHealthVerifier())
    )
    record = service.prepare(
        proposal,
        current_version="1",
        candidate_version="2",
        changed_subsystems=("jarvis",),
        preview_gates=_preview_gates(),
    )
    context = approval.issue_context(
        request_id=approval_request_id(record),
        choice=ApprovalChoice.APPROVE_ONCE,
        identity=ApprovalIdentity("trusted-user", ApprovalActorKind.TRUSTED_USER),
    )
    record = await service.approve(record.activation_id, context)
    pending = await service._authorize_effect(record)
    contexts = tuple(
        approval.issue_context(
            request_id=request.request_id,
            choice=ApprovalChoice.APPROVE_ONCE,
            identity=ApprovalIdentity("trusted-user", ApprovalActorKind.TRUSTED_USER),
        )
        for request in pending.approval_requests
    )

    final = await service.activate(record.activation_id, permission_contexts=contexts)

    assert final.status is ActivationStatus.ROLLED_BACK
    assert (service.installation_root / "jarvis/example.py").read_text(
        encoding="utf-8"
    ) == "VALUE = 1\n"


@pytest.mark.asyncio
async def test_changed_candidate_becomes_stale_without_effect(tmp_path: Path) -> None:
    service, proposal, installation, approval, _broker = _activator(tmp_path)
    record = service.prepare(
        proposal,
        current_version="1",
        candidate_version="2",
        changed_subsystems=("jarvis",),
        preview_gates=_preview_gates(),
    )
    context = approval.issue_context(
        request_id=approval_request_id(record),
        choice=ApprovalChoice.APPROVE_ONCE,
        identity=ApprovalIdentity("trusted-user", ApprovalActorKind.TRUSTED_USER),
    )
    await service.approve(record.activation_id, context)
    (proposal.workspace.root / "jarvis/example.py").write_text("MUTATED\n", encoding="utf-8")
    final = await service.activate(record.activation_id)
    assert final.status is ActivationStatus.STALE
    assert (installation / "jarvis/example.py").read_text(encoding="utf-8") == "VALUE = 1\n"


def test_durable_activation_state_reconstructs_after_store_restart(tmp_path: Path) -> None:
    digest = hashlib.sha256(b"record").hexdigest()
    from jarvis.self_development import ActivationRecord

    record = ActivationRecord(
        "00000000-0000-0000-0000-000000000001",
        "proposal-1",
        digest,
        TASK_ID,
        REVISION,
        REVISION,
        digest,
        digest,
        digest,
        digest,
        ("jarvis/example.py",),
        2,
        ("quality",),
        digest,
        NOW,
        NOW + timedelta(hours=1),
    )
    first = ActivationStateStore(tmp_path / "state.sqlite3")
    first.put(record)
    restarted = ActivationStateStore(tmp_path / "state.sqlite3")
    assert restarted.get(record.activation_id) == record
    durable = self_development._record_to_json(record)
    durable.pop("candidate_application_hash")
    with pytest.raises(ActivationError, match="application identity"):
        self_development._record_from_json(durable)


def test_durable_proposal_owner_reconstructs_typed_proposal(tmp_path: Path) -> None:
    proposal, _production, _candidate, _installation = _make_proposal(tmp_path)
    first = DurableProposalStore(tmp_path / "self-development.sqlite3")
    first.put(proposal)
    restarted = DurableProposalStore(tmp_path / "self-development.sqlite3")
    assert restarted.get(proposal.proposal_id) == proposal


def test_durable_proposal_owner_rejects_duplicates_and_removes_exact_pending_row(
    tmp_path: Path,
) -> None:
    proposal, _production, _candidate, _installation = _make_proposal(tmp_path / "first")
    other, _production, _candidate, _installation = _make_proposal(tmp_path / "second")
    store = DurableProposalStore(tmp_path / "self-development.sqlite3")
    store.add(proposal)
    with pytest.raises(ValueError, match="Proposal ID already exists"):
        store.add(proposal)
    with pytest.raises(ValueError, match="Proposal ID already exists with different contents"):
        store.add(other)
    store.remove_unapproved(proposal.proposal_id, proposal.proposal_fingerprint)
    assert store.get(proposal.proposal_id) is None


def test_durable_proposal_owner_rejects_missing_and_tampered_rows(tmp_path: Path) -> None:
    proposal, _production, _candidate, _installation = _make_proposal(tmp_path)
    store = DurableProposalStore(tmp_path / "self-development.sqlite3")
    assert store.get("missing-proposal") is None
    store.put(proposal)
    with sqlite3.connect(store.path) as connection:
        connection.execute(
            "UPDATE self_development_proposals SET fingerprint=? WHERE proposal_id=?",
            ("0" * 64, proposal.proposal_id),
        )
    with pytest.raises(ActivationError, match="fingerprint mismatch"):
        store.get(proposal.proposal_id)


def test_production_support_and_current_gate_are_fail_closed(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    production = tmp_path / "source"
    (production / "jarvis").mkdir(parents=True)
    (production / "jarvis" / "runtime.py").write_text("runtime\n", encoding="utf-8")
    (production / "jarvis" / "bootstrap.py").write_text("bootstrap\n", encoding="utf-8")
    installation = tmp_path / "candidates"
    support = SelfDevelopmentSupportDetector().detect(production, installation)
    assert support.status is SelfDevelopmentSupport.SUPPORTED_SOURCE_INSTALLATION
    assert SelfDevelopmentSupportDetector().detect(production, production).status is (
        SelfDevelopmentSupport.UNSAFE_INSTALLATION_IDENTITY
    )
    blocked = tmp_path / "blocked"
    blocked.write_text("not a directory", encoding="utf-8")
    assert SelfDevelopmentSupportDetector().detect(production, blocked).status is (
        SelfDevelopmentSupport.UNSUPPORTED_READ_ONLY_INSTALLATION
    )
    monkeypatch.setattr(sys, "frozen", True, raising=False)
    assert SelfDevelopmentSupportDetector().detect(production, installation).status is (
        SelfDevelopmentSupport.UNSUPPORTED_PACKAGED_SELF_UPDATE
    )
    monkeypatch.delattr(sys, "frozen", raising=False)
    proposal, _old_production, candidate, _installation = _make_proposal(tmp_path / "proposal")
    classification = ModificationTrustClassifier().classify(proposal.modification.changed_paths)
    evidence = ProductionSelfDevelopmentGateVerifier(
        lambda _proposal, current: {
            name: GateEvidence(name, True, "a" * 64)
            for name in current.required_gates
            if name
            not in {
                "trusted_approval",
                "recovery_point",
                "startup_health",
                "runtime_integrity",
            }
        }
    )(proposal, classification)
    assert set(evidence).issubset(classification.required_gates)
    assert "trusted_approval" not in evidence
    assert "startup_health" not in evidence
    candidate_path = candidate / "jarvis/example.py"
    candidate_path.write_text("VALUE = 3\n", encoding="utf-8")
    with pytest.raises(ActivationError, match="tree gate"):
        ProductionSelfDevelopmentGateVerifier()(proposal, classification)


def test_production_support_rejects_incomplete_source(tmp_path: Path) -> None:
    source = tmp_path / "incomplete"
    source.mkdir()
    result = SelfDevelopmentSupportDetector().detect(source, tmp_path / "install")
    assert result.status is SelfDevelopmentSupport.UNSAFE_INSTALLATION_IDENTITY


def test_production_gate_executor_observes_each_pre_start_gate(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    proposal, _production, candidate, _installation = _make_proposal(tmp_path)
    classification = ModificationTrustClassifier().classify(proposal.modification.changed_paths)
    executor = ProductionCurrentGateExecutor()
    assert executor._static_security(candidate, proposal)[0]
    assert executor._package_certification(candidate)[0]
    monkeypatch.setattr(executor, "_static_security", lambda _root, _proposal: (True, "scan"))
    monkeypatch.setattr(executor, "_package_certification", lambda _root: (True, "package"))
    calls: list[tuple[Path, tuple[str, ...]]] = []

    def run_command(root: Path, command: tuple[str, ...]) -> tuple[bool, str]:
        calls.append((root, command))
        return True, "executed"

    monkeypatch.setattr(executor, "_run_command", run_command)
    evidence = executor(proposal, classification)
    assert set(evidence) == {
        "static_security",
        "sandbox_tests",
        "package_certification",
        "quality",
        "integration_tests",
        "protected_regression",
    }
    assert len(calls) == 4
    assert all(root == candidate for root, _command in calls)
    assert all(item.passed for item in evidence.values())


def test_production_gate_executor_rejects_actual_security_and_command_failures(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    proposal, _production, candidate, _installation = _make_proposal(tmp_path)
    candidate_file = candidate / Path(proposal.modification.changed_paths[0])
    candidate_file.write_text("exec('untrusted')\n", encoding="utf-8")
    executor = ProductionCurrentGateExecutor()
    passed, detail = executor._static_security(candidate, proposal)
    assert not passed
    assert "rejected" in detail
    candidate_file.write_text("VALUE = 2\n", encoding="utf-8")
    monkeypatch.setattr(executor, "_static_security", lambda _root, _proposal: (True, "scan"))
    monkeypatch.setattr(executor, "_package_certification", lambda _root: (True, "package"))
    monkeypatch.setattr(executor, "_run_command", lambda _root, _command: (False, "failed"))
    classification = ModificationTrustClassifier().classify(proposal.modification.changed_paths)
    evidence = executor(proposal, classification)
    assert evidence["sandbox_tests"].passed is False
    assert "quality" not in evidence


def test_candidate_start_typed_failures_are_fail_closed(tmp_path: Path) -> None:
    service, proposal, installation, _approval, _broker = _activator(tmp_path)
    record = service.prepare(
        proposal,
        current_version="1",
        candidate_version="2",
        changed_subsystems=("jarvis",),
        preview_gates=_preview_gates(),
    )
    candidate = ProductionCandidateInstaller(
        proposal.workspace.root, installation, service.recovery
    ).stage(proposal, record)
    selector = TrustedSelfDevelopmentBootSelector(
        Path(__file__).resolve().parents[1], installation, service.recovery
    )
    verifier = ProductionSelfDevelopmentRuntimeVerifier(
        Path(__file__).resolve().parents[1], selector
    )
    result = verifier.start_candidate(
        installation_root=candidate.root,
        expected_revision="wrong-revision",
        expected_hash=record.candidate_application_hash,
    )
    assert result.started is False
    assert result.outcome is CandidateStartOutcome.RECOVERY_AUTH_MISMATCH
    assert result.observed_application_hash == candidate.tree_digest


def test_ephemeral_qualification_backend_is_not_persistent(tmp_path: Path) -> None:
    backend = EphemeralQualificationSecretBackend()
    backend.put("jarvis:test", b"value")
    assert backend.get("jarvis:test") == b"value"
    backend.delete("jarvis:test")
    with pytest.raises(CredentialNotFound, match="unavailable"):
        backend.get("jarvis:test")


def test_candidate_environment_proof_rejects_parent_test_state(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("PYTHONPATH", str(tmp_path))
    monkeypatch.setenv("PYTEST_CURRENT_TEST", "parent-controlled")
    assert self_development_host._environment_isolated(tmp_path) is False


def test_runtime_observer_and_golden_fail_closed_without_authenticated_context(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    service, _proposal, _installation, _approval, _broker = _activator(tmp_path)
    source = Path(__file__).resolve().parents[1]
    selector = TrustedSelfDevelopmentBootSelector(
        source, service.installation_root, service.recovery
    )
    verifier = ProductionSelfDevelopmentRuntimeVerifier(source, selector)
    assert (
        verifier.observe_candidate_health(installation_root=tmp_path, expected_hash="a" * 64).passed
        is False
    )
    assert (
        verifier.observe_candidate_security(
            installation_root=tmp_path, expected_hash="a" * 64
        ).passed
        is False
    )
    with pytest.raises(ActivationError, match="known-good candidate"):
        verifier.observe_lkg_health(installation_root=tmp_path)
    workflow_store = GoldenWorkflowStore(tmp_path / "golden.sqlite3")
    workflow = register_production_self_development_golden(workflow_store)
    fixture = workflow.fixtures[0]
    with pytest.raises(GoldenGateError, match="context"):
        ProductionGoldenExecutor()(workflow, fixture)
    assert ProductionCurrentGateExecutor()._package_certification(tmp_path)[0] is False

    class TimeoutProcess:
        pid = 202
        returncode = -1
        timed_out = False

        def communicate(self, **_kwargs: Any) -> tuple[str, str]:
            if self.timed_out:
                return "", ""
            self.timed_out = True
            raise subprocess.TimeoutExpired("golden", 1)

        def kill(self) -> None:
            return None

    monkeypatch.setattr(subprocess, "Popen", lambda *a, **k: TimeoutProcess())
    bound = ProductionGoldenExecutor().for_candidate(root=source, proposal_fingerprint="b" * 64)
    with pytest.raises(GoldenGateError, match="timed out"):
        bound(workflow, fixture)


def test_runtime_lkg_observation_requires_an_authenticated_manifest(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    source = Path(__file__).resolve().parents[1]
    installation = tmp_path / "installation"
    installation.mkdir()
    authority = TrustedRecoveryAuthority("empty-lkg", TestOnlyInMemorySecretBackend())
    authority.initialize()
    store = RecoveryStore(tmp_path / "recovery", trusted_authority=authority)
    recovery = RecoveryCoordinator(store)
    selector = TrustedSelfDevelopmentBootSelector(source, installation, recovery)
    verifier = ProductionSelfDevelopmentRuntimeVerifier(source, selector)
    assert verifier._authenticated_manifest(tmp_path) is None
    evidence = verifier.observe_lkg_health(installation_root=tmp_path)
    assert evidence.passed is False
    assert "manifest" in evidence.detail

    source_snapshot = store.create_snapshot(
        transaction_id="00000000-0000-0000-0000-000000000201",
        app_revision=REVISION,
        application_hash=compute_application_build_hash(source),
        configuration={},
        database_schema={},
        integration_versions={},
        files=(),
    )
    store.begin_start("00000000-0000-0000-0000-000000000201")
    store.commit_start("00000000-0000-0000-0000-000000000201", source_snapshot.snapshot_id)

    class ReadyProcess:
        pid = 303
        returncode = 0

        def communicate(self, **_kwargs: Any) -> tuple[str, str]:
            return (
                json.dumps(
                    {
                        "application_hash": compute_application_build_hash(source),
                        "environment_isolated": True,
                        "shutdown_clean": True,
                        "root": str(source),
                        "status": "ready",
                    }
                ),
                "",
            )

    monkeypatch.setattr(subprocess, "Popen", lambda *a, **k: ReadyProcess())
    healthy = verifier.observe_lkg_health(installation_root=source)
    assert healthy.passed is True


def test_production_gate_command_outcomes_are_typed_and_sanitized(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    executor = ProductionCurrentGateExecutor(timeout_seconds=1)
    calls: list[tuple[tuple[str, ...], dict[str, str]]] = []

    def success(command: tuple[str, ...], **kwargs: Any) -> SimpleNamespace:
        calls.append((command, cast(dict[str, str], kwargs["env"])))
        return SimpleNamespace(returncode=0)

    monkeypatch.setattr(subprocess, "run", success)
    passed, detail = executor._run_command(tmp_path, (sys.executable, "-m", "probe"))
    assert passed and "passed" in detail
    assert calls[-1][1]["PYTHONPATH"] == str(tmp_path)
    assert "PYTEST_CURRENT_TEST" not in calls[-1][1]
    passed, _detail = executor._run_command(tmp_path, (sys.executable, "scripts/quality.py"))
    assert passed
    monkeypatch.setattr(
        subprocess,
        "run",
        lambda *_args, **_kwargs: SimpleNamespace(returncode=1),
    )
    assert executor._run_command(tmp_path, (sys.executable, "-m", "probe"))[0] is False
    monkeypatch.setattr(
        subprocess,
        "run",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(subprocess.TimeoutExpired("probe", 1)),
    )
    assert executor._run_command(tmp_path, (sys.executable, "-m", "probe"))[0] is False
    monkeypatch.setattr(
        subprocess,
        "run",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(OSError("unavailable")),
    )
    assert executor._run_command(tmp_path, (sys.executable, "-m", "probe"))[0] is False


def test_candidate_host_failure_taxonomy_does_not_echo_expected_inputs(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    service, proposal, installation, _approval, _broker = _activator(tmp_path)
    record = service.prepare(
        proposal,
        current_version="1",
        candidate_version="2",
        changed_subsystems=("jarvis",),
        preview_gates=_preview_gates(),
    )
    candidate = ProductionCandidateInstaller(
        proposal.workspace.root, installation, service.recovery
    ).stage(proposal, record)
    selector = TrustedSelfDevelopmentBootSelector(
        Path(__file__).resolve().parents[1], installation, service.recovery
    )
    verifier = ProductionSelfDevelopmentRuntimeVerifier(
        Path(__file__).resolve().parents[1], selector
    )
    application_hash = compute_application_build_hash(candidate.root)

    class FakeProcess:
        pid = 101
        returncode = 0

        def communicate(self, **_kwargs: Any) -> tuple[str, str]:
            return (
                json.dumps(
                    {
                        "application_hash": application_hash,
                        "environment_isolated": True,
                        "shutdown_clean": True,
                        "root": str(candidate.root),
                        "status": "ready",
                    }
                ),
                "",
            )

        def kill(self) -> None:
            return None

    monkeypatch.setattr(subprocess, "Popen", lambda *a, **k: FakeProcess())
    observed = verifier.start_candidate(
        installation_root=candidate.root,
        expected_revision=record.candidate_revision,
        expected_hash="f" * 64,
    )
    assert not observed.started
    assert observed.outcome is CandidateStartOutcome.RECOVERY_AUTH_MISMATCH
    assert observed.observed_application_hash == application_hash
    assert observed.observed_application_hash != "f" * 64
    assert verifier.last_start_evidence == observed

    class WrongRootProcess(FakeProcess):
        def communicate(self, **_kwargs: Any) -> tuple[str, str]:
            value, stderr = super().communicate()
            payload = json.loads(value)
            payload["root"] = "C:\\wrong-candidate"
            return json.dumps(payload), stderr

    monkeypatch.setattr(subprocess, "Popen", lambda *a, **k: WrongRootProcess())
    wrong_root = verifier.start_candidate(
        installation_root=candidate.root,
        expected_revision=record.candidate_revision,
        expected_hash=record.candidate_application_hash,
    )
    assert wrong_root.outcome is CandidateStartOutcome.ROOT_MISMATCH

    class NonzeroProcess(FakeProcess):
        returncode = 1

    monkeypatch.setattr(subprocess, "Popen", lambda *a, **k: NonzeroProcess())
    assert (
        verifier.start_candidate(
            installation_root=candidate.root,
            expected_revision=record.candidate_revision,
            expected_hash=record.candidate_application_hash,
        ).outcome
        is CandidateStartOutcome.NONZERO_EXIT
    )

    class PayloadProcess(FakeProcess):
        payload_changes: dict[str, object] = {}

        def communicate(self, **_kwargs: Any) -> tuple[str, str]:
            value, stderr = super().communicate()
            payload = json.loads(value)
            payload.update(self.payload_changes)
            return json.dumps(payload), stderr

    for changes, expected in (
        ({"environment_isolated": False}, CandidateStartOutcome.UNSAFE_ENVIRONMENT),
        ({"application_hash": "f" * 64}, CandidateStartOutcome.TREE_HASH_MISMATCH),
        ({"status": "starting"}, CandidateStartOutcome.NOT_READY),
        ({"shutdown_clean": False}, CandidateStartOutcome.SHUTDOWN_FAILED),
    ):
        process_type = type("PayloadVariant", (PayloadProcess,), {"payload_changes": changes})
        monkeypatch.setattr(
            subprocess, "Popen", lambda *a, process_type=process_type, **k: process_type()
        )
        assert (
            verifier.start_candidate(
                installation_root=candidate.root,
                expected_revision=record.candidate_revision,
                expected_hash=record.candidate_application_hash,
            ).outcome
            is expected
        )

    class MalformedProcess(FakeProcess):
        def communicate(self, **_kwargs: Any) -> tuple[str, str]:
            return "not-json", ""

    monkeypatch.setattr(subprocess, "Popen", lambda *a, **k: MalformedProcess())
    assert (
        verifier.start_candidate(
            installation_root=candidate.root,
            expected_revision=record.candidate_revision,
            expected_hash=record.candidate_application_hash,
        ).outcome
        is CandidateStartOutcome.MALFORMED_PAYLOAD
    )

    class ChangedManifestVerifier(ProductionSelfDevelopmentRuntimeVerifier):
        def _authenticated_tree_digest(self, _root: Path) -> str | None:
            return "f" * 64

    changed_verifier = ChangedManifestVerifier(Path(__file__).resolve().parents[1], selector)
    monkeypatch.setattr(subprocess, "Popen", lambda *a, **k: FakeProcess())
    assert (
        changed_verifier.start_candidate(
            installation_root=candidate.root,
            expected_revision=record.candidate_revision,
            expected_hash=record.candidate_application_hash,
        ).outcome
        is CandidateStartOutcome.RECOVERY_AUTH_MISMATCH
    )

    class OversizedProcess(FakeProcess):
        def communicate(self, **_kwargs: Any) -> tuple[str, str]:
            return "x" * 16_385, ""

    monkeypatch.setattr(subprocess, "Popen", lambda *a, **k: OversizedProcess())
    assert (
        verifier.start_candidate(
            installation_root=candidate.root,
            expected_revision=record.candidate_revision,
            expected_hash=record.candidate_application_hash,
        ).outcome
        is CandidateStartOutcome.MALFORMED_PAYLOAD
    )

    normal_timeout = verifier._remaining_host_timeout
    remaining = iter((10.0, 0.0))
    monkeypatch.setattr(verifier, "_remaining_host_timeout", lambda: next(remaining))
    monkeypatch.setattr(subprocess, "Popen", lambda *a, **k: FakeProcess())
    assert (
        verifier.start_candidate(
            installation_root=candidate.root,
            expected_revision=record.candidate_revision,
            expected_hash=record.candidate_application_hash,
        ).outcome
        is CandidateStartOutcome.STARTUP_DEADLINE_EXCEEDED
    )
    monkeypatch.setattr(verifier, "_remaining_host_timeout", normal_timeout)

    class TimeoutProcess(FakeProcess):
        def communicate(self, **kwargs: Any) -> tuple[str, str]:
            if "timeout" in kwargs:
                raise subprocess.TimeoutExpired("candidate", 1)
            return "", ""

    monkeypatch.setattr(subprocess, "Popen", lambda *a, **k: TimeoutProcess())
    assert (
        verifier.start_candidate(
            installation_root=candidate.root,
            expected_revision=record.candidate_revision,
            expected_hash=record.candidate_application_hash,
        ).outcome
        is CandidateStartOutcome.PROCESS_TIMEOUT
    )

    monkeypatch.setattr(subprocess, "Popen", lambda *a, **k: (_ for _ in ()).throw(OSError()))
    assert (
        verifier.start_candidate(
            installation_root=candidate.root,
            expected_revision=record.candidate_revision,
            expected_hash=record.candidate_application_hash,
        ).outcome
        is CandidateStartOutcome.NONZERO_EXIT
    )


def test_candidate_host_entrypoint_is_bounded_and_typed(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    class ReadyRuntime:
        status = RuntimeStatus.READY

        async def aclose(self) -> None:
            return None

    class FailedRuntime:
        status = RuntimeStatus.ERROR

    monkeypatch.setattr(
        cast(Any, self_development_host).ApplicationRuntime,
        "create",
        lambda *a, **k: ReadyRuntime(),
    )
    monkeypatch.setattr(
        self_development_host,
        "compute_application_build_hash",
        lambda _root: "a" * 64,
    )
    assert self_development_host.main([str(tmp_path / "app-data")]) == 0
    assert self_development_host.main([]) == 2
    monkeypatch.setattr(
        cast(Any, self_development_host).ApplicationRuntime,
        "create",
        lambda *a, **k: FailedRuntime(),
    )
    assert self_development_host.main([str(tmp_path / "app-data")]) == 1

    class ShutdownFailureRuntime:
        status = RuntimeStatus.READY

        async def aclose(self) -> None:
            raise RuntimeError("shutdown")

    monkeypatch.setattr(
        cast(Any, self_development_host).ApplicationRuntime,
        "create",
        lambda *a, **k: ShutdownFailureRuntime(),
    )
    assert self_development_host.main([str(tmp_path / "shutdown-data")]) == 1


def test_unavailable_runtime_and_boot_identity_paths_fail_closed(tmp_path: Path) -> None:
    digest = "a" * 64
    verifier = UnavailableSelfDevelopmentRuntimeVerifier()
    start = verifier.start_candidate(
        installation_root=tmp_path,
        expected_revision="revision",
        expected_hash=digest,
    )
    assert not start.started
    assert (
        verifier.observe_candidate_health(installation_root=tmp_path, expected_hash=digest).passed
        is False
    )
    assert (
        verifier.observe_candidate_security(installation_root=tmp_path, expected_hash=digest).passed
        is False
    )
    assert verifier.observe_lkg_health(installation_root=tmp_path).passed is False
    assert self_development_host.main([str(tmp_path / "data"), "extra"]) == 2

    service, _proposal, _installation, _approval, _broker = _activator(tmp_path / "service")
    candidate_root = service.installation_root / "candidates"
    candidate_root.mkdir()
    authority = TrustedRecoveryAuthority(
        "test-selector-installation", TestOnlyInMemorySecretBackend()
    )
    authority.initialize()
    empty_store = RecoveryStore(tmp_path / "empty-recovery", trusted_authority=authority)
    selector = TrustedSelfDevelopmentBootSelector(
        service.installation_root,
        candidate_root,
        RecoveryCoordinator(empty_store),
    )
    assert selector.select() == service.installation_root
    assert _candidate_host_payload("") is None
    assert _candidate_host_payload("not-json") is None
    assert _candidate_host_payload("[]") is None


def test_production_gate_rechecks_each_current_candidate_identity(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    proposal, _production, _candidate, _installation = _make_proposal(tmp_path)
    classification = ModificationTrustClassifier().classify(proposal.modification.changed_paths)
    verifier = ProductionSelfDevelopmentGateVerifier()
    expected_tree = proposal.modification.tree_digest
    monkeypatch.setattr(self_development, "_tree_digest", lambda _root: expected_tree)
    monkeypatch.setattr(self_development, "_git_head", lambda _root: "wrong-base")
    with pytest.raises(ActivationError, match="base gate"):
        verifier(proposal, classification)
    monkeypatch.setattr(
        self_development, "_git_head", lambda _root: proposal.workspace.base_revision
    )
    monkeypatch.setattr(self_development, "_git_changed_paths", lambda _root, _base: set())
    with pytest.raises(ActivationError, match="changed-path set"):
        verifier(proposal, classification)
    monkeypatch.setattr(
        self_development,
        "_git_changed_paths",
        lambda _root, _base: set(proposal.modification.changed_paths),
    )
    monkeypatch.setattr(self_development, "_git_diff_digest", lambda _root, _base, _paths: "b" * 64)
    with pytest.raises(ActivationError, match="diff gate"):
        verifier(proposal, classification)
    monkeypatch.setattr(
        self_development,
        "_git_diff_digest",
        lambda _root, _base, _paths: proposal.modification.diff_digest,
    )


def test_durable_owner_requires_exact_removal_identity_and_is_callable(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    proposal, _production, _candidate, _installation = _make_proposal(tmp_path)
    store = DurableProposalStore(tmp_path / "self-development.sqlite3")
    store.put(proposal)
    assert store(proposal.proposal_id) == proposal
    with pytest.raises(ValueError, match="exact awaiting proposal"):
        store.remove_unapproved(proposal.proposal_id, "b" * 64)
    monkeypatch.setattr(
        self_development,
        "_proposal_from_json",
        lambda _value: cast(Any, SimpleNamespace(status=ProposalStatus.DENIED)),
    )
    with pytest.raises(ValueError, match="Only an awaiting proposal"):
        store.remove_unapproved(proposal.proposal_id, proposal.proposal_fingerprint)


def test_production_installer_rejects_duplicate_staging_and_excludes_runtime_data(
    tmp_path: Path,
) -> None:
    proposal, production, candidate, _installation = _make_proposal(tmp_path / "proposal")
    service, _unused_proposal, _unused_installation, _approval, _broker = _activator(
        tmp_path / "service"
    )
    record = service.prepare(
        proposal,
        current_version="1",
        candidate_version="2",
        changed_subsystems=("jarvis",),
        preview_gates=_preview_gates(),
    )
    installer = ProductionCandidateInstaller(
        production, service.installation_root, service.recovery
    )
    staging = installer.planned_root(record)
    staging.mkdir()
    with pytest.raises(ActivationError, match="already staged"):
        installer.stage(proposal, record)
    staging.rmdir()
    with pytest.raises(ActivationError, match="application hash"):
        installer.stage(proposal, replace(record, candidate_application_hash="f" * 64))
    changed_path = candidate / Path(proposal.modification.changed_paths[0])
    changed_path.unlink()
    changed_path.mkdir()
    with pytest.raises(ActivationError, match="regular file"):
        installer.stage(proposal, record)

    source = tmp_path / "copy-source"
    target = tmp_path / "copy-target"
    source.mkdir()
    (source / "kept.txt").write_text("kept", encoding="utf-8")
    for name in ("ignored.sqlite3", "ignored.pyc", "ignored.pyo"):
        (source / name).write_bytes(b"ignored")
    installer._copy_tree(source, target)
    assert (target / "kept.txt").read_text(encoding="utf-8") == "kept"
    assert not (target / "ignored.sqlite3").exists()
    os.link(source / "kept.txt", source / "duplicate.txt")
    with pytest.raises(ActivationError, match="hard link"):
        installer._copy_tree(source, tmp_path / "hard-link-target")


def test_production_gate_and_host_module_reject_stale_identity(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    proposal, _production, _candidate, _installation = _make_proposal(tmp_path / "gate")
    verifier = ProductionSelfDevelopmentGateVerifier()
    stale = ModificationTrustClassifier().classify(("jarvis/bootstrap.py",))
    current = ModificationTrustClassifier().classify(proposal.modification.changed_paths)
    assert stale != current
    with pytest.raises(ActivationError, match="classification is stale"):
        verifier(proposal, stale)
    monkeypatch.setattr(sys, "argv", ["jarvis.self_development_host"])
    with pytest.raises(SystemExit) as raised:
        runpy.run_path(
            str(Path(__file__).resolve().parents[1] / "jarvis" / "self_development_host.py"),
            run_name="__main__",
        )
    assert raised.value.code == 2


def test_authenticated_boot_can_fall_back_to_production_root(tmp_path: Path) -> None:
    production = tmp_path / "production"
    installation = tmp_path / "installation"
    production.mkdir()
    installation.mkdir()
    (production / "jarvis").mkdir()
    (production / "jarvis" / "runtime.py").write_text("runtime", encoding="utf-8")
    authority = TrustedRecoveryAuthority("fallback-installation", TestOnlyInMemorySecretBackend())
    authority.initialize()
    store = RecoveryStore(tmp_path / "recovery", trusted_authority=authority)
    transaction = "00000000-0000-0000-0000-000000000201"
    snapshot = store.create_snapshot(
        transaction_id=transaction,
        app_revision=REVISION,
        application_hash=compute_application_build_hash(production),
        configuration={},
        database_schema={},
        integration_versions={},
        files=(),
    )
    store.begin_start(transaction, candidate_snapshot_id=snapshot.snapshot_id)
    store.commit_start(transaction, snapshot.snapshot_id)
    selector = TrustedSelfDevelopmentBootSelector(
        production, installation, RecoveryCoordinator(store)
    )
    assert selector.select() == production


@pytest.mark.asyncio
async def test_production_golden_workflow_uses_trusted_executor(tmp_path: Path) -> None:
    store = GoldenWorkflowStore(tmp_path / "golden.sqlite3")
    workflow = register_production_self_development_golden(store)
    owner = GoldenWorkflowOwner(
        GoldenWorkflowService(store), ProductionGoldenExecutor()
    ).for_candidate(
        root=Path(__file__).resolve().parents[1],
        proposal_fingerprint="a" * 64,
    )
    assert workflow.workflow_id == "jarvis-production-self-development"
    assert await owner() is True


def test_production_candidate_is_complete_and_recovery_selects_only_authenticated_root(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("PYTEST_CURRENT_TEST", "polluted-parent-test")
    monkeypatch.setenv("JARVIS_ENVIRONMENT", "test")
    monkeypatch.setenv("PYTHONPATH", str(tmp_path / "wrong-source-root"))
    service, proposal, installation, _approval, _broker = _activator(tmp_path)
    record = service.prepare(
        proposal,
        current_version="1",
        candidate_version="2",
        changed_subsystems=("jarvis",),
        preview_gates=_preview_gates(),
    )
    record = replace(record, recovery_transaction_id="00000000-0000-0000-0000-000000000102")
    source = Path(__file__).resolve().parents[1]
    store = service.recovery.store
    source_snapshot = store.create_snapshot(
        transaction_id="00000000-0000-0000-0000-000000000101",
        app_revision=REVISION,
        application_hash=compute_application_build_hash(source),
        configuration={},
        database_schema={},
        integration_versions={},
        files=(),
    )
    store.begin_start("00000000-0000-0000-0000-000000000101")
    store.commit_start("00000000-0000-0000-0000-000000000101", source_snapshot.snapshot_id)
    installer = ProductionCandidateInstaller(source, installation, service.recovery)
    expected_candidate = tmp_path / "expected-candidate"
    shutil.copytree(source, expected_candidate)
    (expected_candidate / "jarvis" / "example.py").write_text("VALUE = 2\n", encoding="utf-8")
    record = replace(
        record, candidate_application_hash=compute_application_build_hash(expected_candidate)
    )
    candidate = installer.stage(proposal, record)
    assert isinstance(candidate, CandidateInstallation)
    assert (candidate.root / "jarvis" / "runtime.py").is_file()
    assert (candidate.root / "jarvis" / "bootstrap.py").is_file()
    assert not (candidate.root / ".env").exists()
    selector = TrustedSelfDevelopmentBootSelector(source, installation, service.recovery)
    verifier = ProductionSelfDevelopmentRuntimeVerifier(source, selector)

    def start() -> None:
        evidence = verifier.start_candidate(
            installation_root=candidate.root,
            expected_revision=record.candidate_revision,
            expected_hash=record.candidate_application_hash,
        )
        assert evidence.started, (
            f"candidate start failed: outcome={evidence.outcome} "
            f"detail={evidence.detail} digest={evidence.evidence_digest}"
        )

    def health() -> bool:
        return (
            verifier.observe_candidate_health(
                installation_root=candidate.root, expected_hash=record.candidate_application_hash
            ).passed
            and verifier.observe_candidate_security(
                installation_root=candidate.root, expected_hash=record.candidate_application_hash
            ).passed
        )

    result = service.recovery.boot_candidate(
        record.recovery_transaction_id or "00000000-0000-0000-0000-000000000102",
        candidate.snapshot_id,
        start=start,
        health_check=health,
        lkg_health_check=lambda: verifier.observe_lkg_health(installation_root=source).passed,
    )
    assert result == candidate.snapshot_id
    assert selector.select() == candidate.root
    (candidate.root / "jarvis" / "runtime.py").write_text("tampered\n", encoding="utf-8")
    with pytest.raises(ActivationError, match="known-good candidate"):
        selector.select()


def test_trusted_runtime_evidence_types_and_unavailable_gate_fail_closed() -> None:
    digest = hashlib.sha256(b"evidence").hexdigest()
    with pytest.raises(ValueError, match="Candidate start"):
        CandidateStartEvidence(cast(Any, "yes"), REVISION, digest, digest)
    with pytest.raises(ValueError, match="Candidate start"):
        CandidateStartEvidence(False, REVISION, "bad", digest)
    with pytest.raises(ValueError, match="Candidate start"):
        CandidateStartEvidence(False, REVISION, digest, "bad")
    with pytest.raises(ValueError, match="Runtime verification"):
        RuntimeVerificationEvidence(cast(Any, 1), digest)
    with pytest.raises(ValueError, match="Runtime verification"):
        RuntimeVerificationEvidence(True, "bad")
    assert UnavailableSelfDevelopmentGateVerifier()(cast(Any, object()), cast(Any, object())) == {}


def test_level_four_candidate_is_rejected_before_preview_or_activation(tmp_path: Path) -> None:
    service, proposal, _installation, _approval, _broker = _activator(tmp_path, protected=True)
    with pytest.raises(Exception, match="Level 4/5"):
        service.prepare(
            proposal,
            current_version="1",
            candidate_version="2",
            changed_subsystems=("permissions",),
            preview_gates=_preview_gates(),
        )


def test_typed_activation_records_and_gate_evidence_fail_closed() -> None:
    digest = hashlib.sha256(b"record").hexdigest()
    with pytest.raises(ValueError):
        GateEvidence("bad name", True, digest)
    with pytest.raises(ValueError):
        GateEvidence("gate", True, "bad")
    with pytest.raises(ValueError):
        CandidateStartEvidence(
            False,
            REVISION,
            digest,
            digest,
            cast(Any, "invalid-outcome"),
        )
    values: dict[str, Any] = dict(
        activation_id="a",
        proposal_id="p",
        proposal_fingerprint=digest,
        task_id=TASK_ID,
        base_revision=REVISION,
        candidate_revision=REVISION,
        candidate_hash=digest,
        candidate_application_hash=digest,
        candidate_tree_digest=digest,
        candidate_diff_digest=digest,
        changed_paths=("a.py",),
        trust_level=2,
        required_gates=("quality",),
        preview_fingerprint=digest,
        created_at=NOW,
        expires_at=NOW + timedelta(hours=1),
    )
    assert ActivationRecord(**cast(Any, values)).status is ActivationStatus.AWAITING_APPROVAL
    for change in (
        {
            "activation_id": "",
        },
        {"candidate_hash": "bad"},
        {"trust_level": 4},
        {"changed_paths": ("a.py", "a.py")},
        {"created_at": NOW.replace(tzinfo=None)},
        {"expires_at": NOW},
    ):
        with pytest.raises(ValueError):
            ActivationRecord(**cast(Any, {**values, **change}))


def test_helpers_reject_untrusted_paths_and_malformed_identity(tmp_path: Path) -> None:
    with pytest.raises(ActivationError):
        _directory(tmp_path / "missing", "directory")
    with pytest.raises(ActivationError):
        _activation_uuid("not-a-uuid")
    with pytest.raises(ActivationError):
        _aware(datetime(2026, 1, 1))
    root = tmp_path / "root"
    root.mkdir()
    with pytest.raises(ActivationError):
        _contained_regular_target(tmp_path / "outside", root)
    with pytest.raises(ActivationError):
        _git_head(root)


def test_prepare_and_constructor_reject_tree_or_target_identity_drift(tmp_path: Path) -> None:
    service, proposal, _installation, _approval, _broker = _activator(tmp_path)
    bad_modification = replace(proposal.modification, tree_digest="b" * 64)
    bad_fingerprint = compute_proposal_fingerprint(
        proposal_id=proposal.proposal_id,
        task_id=proposal.task_id,
        candidate=proposal.candidate,
        specification=proposal.specification,
        workspace=proposal.workspace,
        modification=bad_modification,
        dependency_assessment=proposal.dependency_assessment,
        gates=proposal.gates,
        evaluation=proposal.evaluation,
        rollback=proposal.rollback,
        created_at=proposal.created_at,
        expires_at=proposal.expires_at,
    )
    with pytest.raises(ActivationError, match="tree"):
        service.prepare(
            replace(proposal, modification=bad_modification, proposal_fingerprint=bad_fingerprint),
            current_version="1",
            candidate_version="2",
            changed_subsystems=("jarvis",),
            preview_gates=_preview_gates(),
        )
    with pytest.raises(ActivationError, match="target"):
        TrustedSelfDevelopmentActivator(
            production_root=service.installation_root,
            installation_root=service.installation_root,
            recovery=service.recovery,
            activation_store=service.store,
            permission_broker=service.broker,
            approval_verifier=service._approval_verifier,
            proposal_loader=service._proposal_loader,
            gate_verifier=service._gate_verifier,
            golden_runner=service._golden_runner,
            runtime_verifier=service._runtime_verifier,
        )


@pytest.mark.asyncio
async def test_approval_state_and_activation_expiry_are_terminal(tmp_path: Path) -> None:
    service, proposal, _installation, approval, _broker = _activator(tmp_path)
    record = service.prepare(
        proposal,
        current_version="1",
        candidate_version="2",
        changed_subsystems=("jarvis",),
        preview_gates=_preview_gates(),
    )
    context = approval.issue_context(
        request_id=approval_request_id(record),
        choice=ApprovalChoice.APPROVE_ONCE,
        identity=ApprovalIdentity("trusted-user", ApprovalActorKind.TRUSTED_USER),
    )
    await service.approve(record.activation_id, context)
    with pytest.raises(ActivationError, match="awaiting"):
        await service.approve(record.activation_id, context)

    service2, proposal2, _installation2, approval2, _broker2 = _activator(tmp_path / "expiry")
    record2 = service2.prepare(
        proposal2,
        current_version="1",
        candidate_version="2",
        changed_subsystems=("jarvis",),
        preview_gates=_preview_gates(),
    )
    context2 = approval2.issue_context(
        request_id=approval_request_id(record2),
        choice=ApprovalChoice.APPROVE_ONCE,
        identity=ApprovalIdentity("trusted-user", ApprovalActorKind.TRUSTED_USER),
    )
    service2.store.put(replace(record2, expires_at=NOW + timedelta(seconds=1)))
    service2._clock = lambda: NOW + timedelta(seconds=2)
    expired = await service2.approve(record2.activation_id, context2)
    assert expired.status is ActivationStatus.EXPIRED


@pytest.mark.asyncio
async def test_activation_missing_proposal_and_permission_policy_fail_closed(
    tmp_path: Path,
) -> None:
    service, proposal, _installation, approval, _broker = _activator(tmp_path)
    record = service.prepare(
        proposal,
        current_version="1",
        candidate_version="2",
        changed_subsystems=("jarvis",),
        preview_gates=_preview_gates(),
    )
    service._proposal_loader = lambda _proposal_id: None
    missing = await service.activate(record.activation_id)
    assert missing.status is ActivationStatus.STALE

    service2, proposal2, _installation2, approval2, _broker2 = _activator(tmp_path / "denied")
    record2 = service2.prepare(
        proposal2,
        current_version="1",
        candidate_version="2",
        changed_subsystems=("jarvis",),
        preview_gates=_preview_gates(),
    )
    context2 = approval2.issue_context(
        request_id=approval_request_id(record2),
        choice=ApprovalChoice.APPROVE_ONCE,
        identity=ApprovalIdentity("trusted-user", ApprovalActorKind.TRUSTED_USER),
    )
    await service2.approve(record2.activation_id, context2)
    denied = await service2.activate(record2.activation_id)
    assert denied.status is ActivationStatus.FAILED


@pytest.mark.asyncio
async def test_health_failure_rolls_back_without_known_good_promotion(tmp_path: Path) -> None:
    verifier = _TestRuntimeVerifier(health=False)
    service, proposal, installation, approval, _broker = _activator(
        tmp_path, runtime_verifier=verifier
    )
    record = service.prepare(
        proposal,
        current_version="1",
        candidate_version="2",
        changed_subsystems=("jarvis",),
        preview_gates=_preview_gates(),
    )
    context = approval.issue_context(
        request_id=approval_request_id(record),
        choice=ApprovalChoice.APPROVE_ONCE,
        identity=ApprovalIdentity("trusted-user", ApprovalActorKind.TRUSTED_USER),
    )
    record = await service.approve(record.activation_id, context)
    pending = await service._authorize_effect(record)
    permission_contexts = tuple(
        approval.issue_context(
            request_id=request.request_id,
            choice=ApprovalChoice.APPROVE_ONCE,
            identity=ApprovalIdentity("trusted-user", ApprovalActorKind.TRUSTED_USER),
        )
        for request in pending.approval_requests
    )
    failed = await service.activate(
        record.activation_id,
        permission_contexts=permission_contexts,
    )
    assert failed.status is ActivationStatus.ROLLED_BACK
    assert verifier.calls == ["start", "health", "lkg"]
    assert (installation / "jarvis/example.py").read_text(encoding="utf-8") == "VALUE = 1\n"


@pytest.mark.asyncio
async def test_security_failure_rolls_back_and_lkg_is_verified(tmp_path: Path) -> None:
    verifier = _TestRuntimeVerifier(security=False)
    service, proposal, installation, approval, _broker = _activator(
        tmp_path, runtime_verifier=verifier
    )
    record = service.prepare(
        proposal,
        current_version="1",
        candidate_version="2",
        changed_subsystems=("jarvis",),
        preview_gates=_preview_gates(),
    )
    context = approval.issue_context(
        request_id=approval_request_id(record),
        choice=ApprovalChoice.APPROVE_ONCE,
        identity=ApprovalIdentity("trusted-user", ApprovalActorKind.TRUSTED_USER),
    )
    record = await service.approve(record.activation_id, context)
    pending = await service._authorize_effect(record)
    permission_contexts = tuple(
        approval.issue_context(
            request_id=request.request_id,
            choice=ApprovalChoice.APPROVE_ONCE,
            identity=ApprovalIdentity("trusted-user", ApprovalActorKind.TRUSTED_USER),
        )
        for request in pending.approval_requests
    )

    final = await service.activate(record.activation_id, permission_contexts=permission_contexts)

    assert final.status is ActivationStatus.ROLLED_BACK
    assert verifier.calls == ["start", "health", "security", "lkg"]
    assert (installation / "jarvis/example.py").read_text(encoding="utf-8") == "VALUE = 1\n"


@pytest.mark.asyncio
async def test_lkg_verification_failure_requires_safe_mode(tmp_path: Path) -> None:
    verifier = _TestRuntimeVerifier(health=False, lkg=False)
    service, proposal, _installation, approval, _broker = _activator(
        tmp_path, runtime_verifier=verifier
    )
    record = service.prepare(
        proposal,
        current_version="1",
        candidate_version="2",
        changed_subsystems=("jarvis",),
        preview_gates=_preview_gates(),
    )
    context = approval.issue_context(
        request_id=approval_request_id(record),
        choice=ApprovalChoice.APPROVE_ONCE,
        identity=ApprovalIdentity("trusted-user", ApprovalActorKind.TRUSTED_USER),
    )
    record = await service.approve(record.activation_id, context)
    pending = await service._authorize_effect(record)
    permission_contexts = tuple(
        approval.issue_context(
            request_id=request.request_id,
            choice=ApprovalChoice.APPROVE_ONCE,
            identity=ApprovalIdentity("trusted-user", ApprovalActorKind.TRUSTED_USER),
        )
        for request in pending.approval_requests
    )

    final = await service.activate(record.activation_id, permission_contexts=permission_contexts)

    assert final.status is ActivationStatus.SAFE_MODE_REQUIRED
    assert verifier.calls == ["start", "health", "lkg"]


@pytest.mark.asyncio
async def test_resume_ambiguous_state_is_quarantined_and_never_retried(tmp_path: Path) -> None:
    service, proposal, _installation, _approval, _broker = _activator(tmp_path)
    record = service.prepare(
        proposal,
        current_version="1",
        candidate_version="2",
        changed_subsystems=("jarvis",),
        preview_gates=_preview_gates(),
    )
    applying = service._transition(record, ActivationStatus.APPLYING)
    reconciled = await service.resume(applying.activation_id)
    assert reconciled.status is ActivationStatus.FAILED


def test_hash_and_diff_helpers_cover_missing_content(tmp_path: Path) -> None:
    proposal, production, candidate, installation = _make_proposal(tmp_path)
    (candidate / "jarvis/example.py").unlink()
    assert len(_candidate_hash(proposal)) == 64
    (installation / "jarvis/example.py").unlink()
    assert len(_installed_candidate_hash(proposal, installation)) == 64
    with pytest.raises(ActivationError):
        _git_diff_digest(candidate, "not-a-revision", proposal.modification.changed_paths)


def test_candidate_identity_helpers_cover_regular_and_missing_files(tmp_path: Path) -> None:
    proposal, production, candidate, installation = _make_proposal(tmp_path)
    assert _candidate_workspace(proposal) == candidate.resolve()
    assert len(_candidate_hash(proposal)) == 64
    assert len(_installed_candidate_hash(proposal, installation)) == 64
    assert (
        len(_git_diff_digest(candidate, _git_head(production), proposal.modification.changed_paths))
        == 64
    )
    (candidate / "jarvis/example.py").unlink()
    (candidate / "jarvis/example.py").mkdir()
    with pytest.raises(ActivationError):
        _candidate_hash(proposal)
    assert len(_installed_candidate_hash(proposal, installation)) == 64


@pytest.mark.asyncio
async def test_stale_gates_golden_and_permission_authority_fail_closed(tmp_path: Path) -> None:
    service, proposal, _installation, approval, _broker = _activator(tmp_path)
    record = service.prepare(
        proposal,
        current_version="1",
        candidate_version="2",
        changed_subsystems=("jarvis",),
        preview_gates=_preview_gates(),
    )
    approval_context = approval.issue_context(
        request_id=approval_request_id(record),
        choice=ApprovalChoice.APPROVE_ONCE,
        identity=ApprovalIdentity("trusted-user", ApprovalActorKind.TRUSTED_USER),
    )
    record = await service.approve(record.activation_id, approval_context)
    service._gate_verifier = lambda _proposal, _classification: {}
    failed = await service.activate(record.activation_id)
    assert failed.status is ActivationStatus.FAILED

    service2, proposal2, _installation2, approval2, _broker2 = _activator(tmp_path / "second")
    record2 = service2.prepare(
        proposal2,
        current_version="1",
        candidate_version="2",
        changed_subsystems=("jarvis",),
        preview_gates=_preview_gates(),
    )
    context2 = approval2.issue_context(
        request_id=approval_request_id(record2),
        choice=ApprovalChoice.APPROVE_ONCE,
        identity=ApprovalIdentity("trusted-user", ApprovalActorKind.TRUSTED_USER),
    )
    await service2.approve(record2.activation_id, context2)
    service2._golden_runner = _golden_owner(tmp_path / "golden-fail.sqlite3", passed=False)
    golden_failed = await service2.activate(record2.activation_id)
    assert golden_failed.status is ActivationStatus.FAILED


@pytest.mark.asyncio
async def test_approval_binding_and_proposal_integrity_reject_tampering(tmp_path: Path) -> None:
    service, proposal, _installation, approval, _broker = _activator(tmp_path)
    record = service.prepare(
        proposal,
        current_version="1",
        candidate_version="2",
        changed_subsystems=("jarvis",),
        preview_gates=_preview_gates(),
    )
    wrong = approval.issue_context(
        request_id=UUID("00000000-0000-0000-0000-000000000099"),
        choice=ApprovalChoice.APPROVE_ONCE,
        identity=ApprovalIdentity("trusted-user", ApprovalActorKind.TRUSTED_USER),
    )
    with pytest.raises(ActivationError, match="different exact candidate"):
        await service.approve(record.activation_id, wrong)
    bad_modification = replace(proposal.modification, tree_digest="b" * 64)
    bad_fingerprint = compute_proposal_fingerprint(
        proposal_id=proposal.proposal_id,
        task_id=proposal.task_id,
        candidate=proposal.candidate,
        specification=proposal.specification,
        workspace=proposal.workspace,
        modification=bad_modification,
        dependency_assessment=proposal.dependency_assessment,
        gates=proposal.gates,
        evaluation=proposal.evaluation,
        rollback=proposal.rollback,
        created_at=proposal.created_at,
        expires_at=proposal.expires_at,
    )
    tampered = replace(
        proposal, modification=bad_modification, proposal_fingerprint=bad_fingerprint
    )
    service._proposal_loader = lambda _proposal_id: tampered
    stale = await service.activate(record.activation_id)
    assert stale.status is ActivationStatus.STALE


@pytest.mark.asyncio
async def test_resume_reconciles_candidate_without_copying_again(tmp_path: Path) -> None:
    service, proposal, installation, _approval, _broker = _activator(tmp_path)
    record = service.prepare(
        proposal,
        current_version="1",
        candidate_version="2",
        changed_subsystems=("jarvis",),
        preview_gates=_preview_gates(),
    )
    service._apply_exact(proposal)
    tx = "00000000-0000-0000-0000-000000000077"
    record = service._transition(
        record,
        ActivationStatus.APPLYING,
        recovery_transaction_id=tx,
    )
    resumed = await service.resume(record.activation_id)
    assert resumed.status is ActivationStatus.COMMITTED
    assert (installation / "jarvis/example.py").read_text(encoding="utf-8") == "VALUE = 2\n"


@pytest.mark.asyncio
async def test_resume_unknown_or_missing_proposal_fails_closed(tmp_path: Path) -> None:
    service, proposal, _installation, _approval, _broker = _activator(tmp_path)
    record = service.prepare(
        proposal,
        current_version="1",
        candidate_version="2",
        changed_subsystems=("jarvis",),
        preview_gates=_preview_gates(),
    )
    service._proposal_loader = lambda _proposal_id: None
    missing = await service.resume(record.activation_id)
    assert missing.status is ActivationStatus.QUARANTINED
    assert await _maybe(True) is True


@pytest.mark.asyncio
async def test_edge_authority_rejections_and_async_evidence_are_covered(tmp_path: Path) -> None:
    service, proposal, _installation, approval, _broker = _activator(tmp_path)
    record = service.prepare(
        proposal,
        current_version="1",
        candidate_version="2",
        changed_subsystems=("jarvis",),
        preview_gates=_preview_gates(),
    )
    forged_authenticator = TrustedApprovalAuthenticator(
        ApprovalSource.TRUSTED_LOCAL_API, clock=lambda: NOW
    )
    forged = forged_authenticator.issue_context(
        request_id=approval_request_id(record),
        choice=ApprovalChoice.APPROVE_ONCE,
        identity=ApprovalIdentity("trusted-user", ApprovalActorKind.TRUSTED_USER),
    )
    with pytest.raises(ActivationError, match="rejected"):
        await service.approve(record.activation_id, forged)

    invalid = {
        "activation_id": record.activation_id,
        "proposal_id": record.proposal_id,
        "proposal_fingerprint": record.proposal_fingerprint,
        "task_id": record.task_id,
        "base_revision": record.base_revision,
        "candidate_revision": record.candidate_revision,
        "candidate_hash": record.candidate_hash,
        "candidate_application_hash": record.candidate_application_hash,
        "candidate_tree_digest": record.candidate_tree_digest,
        "candidate_diff_digest": record.candidate_diff_digest,
        "changed_paths": record.changed_paths,
        "trust_level": record.trust_level,
        "required_gates": record.required_gates,
        "preview_fingerprint": record.preview_fingerprint,
        "created_at": record.created_at,
        "expires_at": record.expires_at,
        "status": "not-a-status",
    }
    with pytest.raises(ValueError):
        ActivationRecord(**cast(Any, invalid))

    with pytest.raises(ActivationError, match="unavailable"):
        service._require("missing")
    broken_proposal = replace(
        proposal,
        workspace=replace(proposal.workspace, root=tmp_path / "gone"),
    )
    with pytest.raises(ActivationError, match="unavailable"):
        _candidate_workspace(broken_proposal)

    async def evidence() -> bool:
        return True

    assert await _maybe(evidence()) is True


def test_private_gate_and_approval_guards_fail_closed(tmp_path: Path) -> None:
    service, proposal, _installation, _approval, _broker = _activator(tmp_path)
    record = service.prepare(
        proposal,
        current_version="1",
        candidate_version="2",
        changed_subsystems=("jarvis",),
        preview_gates=_preview_gates(),
    )
    with pytest.raises(ActivationError, match="required gate"):
        service._require_gates(("quality",), {})
    with pytest.raises(ActivationError, match="trusted approval"):
        service._require_approved(record)


def test_revalidation_rejects_each_bound_identity_change(tmp_path: Path) -> None:
    service, proposal, _installation, _approval, _broker = _activator(tmp_path)
    record = service.prepare(
        proposal,
        current_version="1",
        candidate_version="2",
        changed_subsystems=("jarvis",),
        preview_gates=_preview_gates(),
    )
    expired = replace(record, expires_at=NOW + timedelta(seconds=1))
    service._clock = lambda: NOW + timedelta(seconds=2)
    with pytest.raises(ActivationError, match="expired"):
        service._revalidate(expired, proposal)
    service._clock = lambda: NOW
    cases = (
        (replace(record, base_revision="b" * 40), "base revision"),
        (replace(record, trust_level=1), "classification"),
        (replace(record, changed_paths=("other.py",)), "changed paths"),
        (replace(record, candidate_tree_digest="b" * 64), "tree"),
        (replace(record, candidate_diff_digest="b" * 64), "diff"),
        (replace(record, candidate_hash="b" * 64), "hash"),
    )
    for changed, message in cases:
        with pytest.raises(ActivationError, match=message):
            service._revalidate(changed, proposal)


def test_apply_deletion_and_recovery_metadata_paths_are_guarded(tmp_path: Path) -> None:
    service, proposal, _installation, _approval, _broker = _activator(tmp_path)
    (proposal.workspace.root / "jarvis/example.py").unlink()
    service._apply_exact(proposal)
    assert not (service.installation_root / "jarvis/example.py").exists()

    metadata_file = service.installation_root / "snapshots" / "unexpected.py"
    metadata_file.parent.mkdir(parents=True)
    metadata_file.write_text("must not snapshot", encoding="utf-8")
    with pytest.raises(ActivationError, match="recovery metadata"):
        service._snapshot(
            "00000000-0000-0000-0000-000000000088",
            ("snapshots/unexpected.py",),
            proposal,
            candidate=False,
        )


@pytest.mark.asyncio
async def test_resume_noop_and_known_good_hash_are_durable(tmp_path: Path) -> None:
    service, proposal, _installation, _approval, _broker = _activator(tmp_path)
    record = service.prepare(
        proposal,
        current_version="1",
        candidate_version="2",
        changed_subsystems=("jarvis",),
        preview_gates=_preview_gates(),
    )
    assert await service.resume(record.activation_id) == record
    known_good = _known_good_candidate_hash(service.recovery, proposal)
    assert known_good is not None and len(known_good) == 64


@pytest.mark.asyncio
async def test_r1_deny_context_is_persisted_as_denial(
    tmp_path: Path,
) -> None:
    """A real signed denial never becomes self-development authority."""

    service, proposal, _installation, approval, _broker = _activator(tmp_path)
    record = service.prepare(
        proposal,
        current_version="1",
        candidate_version="2",
        changed_subsystems=("jarvis",),
        preview_gates=_preview_gates(),
    )
    denial = approval.issue_context(
        request_id=approval_request_id(record),
        choice=ApprovalChoice.DENY_ONCE,
        identity=ApprovalIdentity("trusted-user", ApprovalActorKind.TRUSTED_USER),
    )

    result = await service.approve(record.activation_id, denial)

    assert result.status is ActivationStatus.DENIED
    assert await service.activate(record.activation_id) == result


@pytest.mark.asyncio
async def test_r1_preview_binding_can_be_changed_after_context_mint(
    tmp_path: Path,
) -> None:
    """Changing preview facts rejects the old context."""

    service, proposal, _installation, approval, _broker = _activator(tmp_path)
    record = service.prepare(
        proposal,
        current_version="1",
        candidate_version="2",
        changed_subsystems=("jarvis",),
        preview_gates=_preview_gates(),
    )
    context = approval.issue_context(
        request_id=approval_request_id(record),
        choice=ApprovalChoice.APPROVE_ONCE,
        identity=ApprovalIdentity("trusted-user", ApprovalActorKind.TRUSTED_USER),
    )
    service.store.put(replace(record, preview_fingerprint="b" * 64))

    with pytest.raises(ActivationError, match="different exact candidate"):
        await service.approve(record.activation_id, context)


@pytest.mark.asyncio
async def test_r1_limited_context_is_not_self_development_authority(tmp_path: Path) -> None:
    service, proposal, _installation, approval, _broker = _activator(tmp_path)
    record = service.prepare(
        proposal,
        current_version="1",
        candidate_version="2",
        changed_subsystems=("jarvis",),
        preview_gates=_preview_gates(),
    )
    limited = approval.issue_context(
        request_id=approval_request_id(record),
        choice=ApprovalChoice.APPROVE_LIMITED,
        remember_for_seconds=30,
        identity=ApprovalIdentity("trusted-user", ApprovalActorKind.TRUSTED_USER),
    )

    result = await service.approve(record.activation_id, limited)

    assert result.status is ActivationStatus.DENIED


def test_r1_binding_fingerprint_is_canonical_and_fact_bound(tmp_path: Path) -> None:
    service, proposal, _installation, _approval, _broker = _activator(tmp_path)
    record = service.prepare(
        proposal,
        current_version="1",
        candidate_version="2",
        changed_subsystems=("jarvis",),
        preview_gates=_preview_gates(),
    )
    original = approval_binding_fingerprint(record)

    assert len(original) == 64
    assert approval_request_id(record) == approval_request_id(record)
    assert approval_binding_fingerprint(replace(record, candidate_hash="b" * 64)) != original
    assert (
        approval_binding_fingerprint(
            replace(record, task_id=UUID("00000000-0000-0000-0000-000000000012"))
        )
        != original
    )


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "field", ("candidate_hash", "candidate_tree_digest", "candidate_diff_digest")
)
async def test_r1_candidate_fact_change_rejects_old_context(tmp_path: Path, field: str) -> None:
    service, proposal, _installation, approval, _broker = _activator(tmp_path)
    record = service.prepare(
        proposal,
        current_version="1",
        candidate_version="2",
        changed_subsystems=("jarvis",),
        preview_gates=_preview_gates(),
    )
    context = approval.issue_context(
        request_id=approval_request_id(record),
        choice=ApprovalChoice.APPROVE_ONCE,
        identity=ApprovalIdentity("trusted-user", ApprovalActorKind.TRUSTED_USER),
    )
    if field == "candidate_hash":
        changed = replace(record, candidate_hash="b" * 64)
    elif field == "candidate_tree_digest":
        changed = replace(record, candidate_tree_digest="b" * 64)
    else:
        changed = replace(record, candidate_diff_digest="b" * 64)
    service.store.put(changed)

    stale = await service.approve(record.activation_id, context)
    assert stale.status is ActivationStatus.STALE
    stored = service.store.get(record.activation_id)
    assert stored is not None and stored.status is ActivationStatus.STALE


@pytest.mark.asyncio
async def test_r1_production_base_drift_rejects_old_context(tmp_path: Path) -> None:
    service, proposal, _installation, approval, _broker = _activator(tmp_path)
    record = service.prepare(
        proposal,
        current_version="1",
        candidate_version="2",
        changed_subsystems=("jarvis",),
        preview_gates=_preview_gates(),
    )
    context = approval.issue_context(
        request_id=approval_request_id(record),
        choice=ApprovalChoice.APPROVE_ONCE,
        identity=ApprovalIdentity("trusted-user", ApprovalActorKind.TRUSTED_USER),
    )
    (service.production_root / "jarvis/example.py").write_text("BASE = 2\n", encoding="utf-8")
    _git(service.production_root, "add", ".")
    _git(service.production_root, "commit", "-qm", "drift")

    stale = await service.approve(record.activation_id, context)

    assert stale.status is ActivationStatus.STALE
    stored = service.store.get(record.activation_id)
    assert stored is not None and stored.status is ActivationStatus.STALE


@pytest.mark.asyncio
async def test_r1_expired_trusted_context_is_rejected(tmp_path: Path) -> None:
    service, proposal, _installation, _approval, _broker = _activator(tmp_path)
    record = service.prepare(
        proposal,
        current_version="1",
        candidate_version="2",
        changed_subsystems=("jarvis",),
        preview_gates=_preview_gates(),
    )
    now = [NOW]
    expiring = TrustedApprovalAuthenticator(
        ApprovalSource.TRUSTED_LOCAL_API,
        context_ttl_seconds=1,
        clock=lambda: now[0],
    )
    service._approval_verifier = expiring.verifier()
    context = expiring.issue_context(
        request_id=approval_request_id(record),
        choice=ApprovalChoice.APPROVE_ONCE,
        identity=ApprovalIdentity("trusted-user", ApprovalActorKind.TRUSTED_USER),
    )
    now[0] = NOW + timedelta(seconds=2)

    with pytest.raises(ActivationError, match="approval_expired"):
        await service.approve(record.activation_id, context)
