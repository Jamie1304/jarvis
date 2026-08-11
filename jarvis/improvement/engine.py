"""Proposal-and-test orchestration for bounded JARVIS self-improvement."""

from __future__ import annotations

import asyncio
import hashlib
import json
from collections.abc import Callable
from datetime import UTC, datetime, timedelta
from uuid import UUID, uuid4

from jarvis.improvement.adapters import (
    CodingAgent,
    CodingEvidence,
    ProposalStore,
    ProtectedRegressionEvaluator,
    SandboxedMandatoryGateRunner,
    SecurityChecker,
    TrustedCodingContext,
)
from jarvis.improvement.analysis import (
    ImprovementPrioritizer,
    ImprovementRiskClassifier,
    ObservedImprovementSignal,
    StructuredCandidateGenerator,
    TrustedTemplateSpecifier,
)
from jarvis.improvement.dependencies import ManifestDependencyGuard
from jarvis.improvement.integrity import compute_proposal_fingerprint
from jarvis.improvement.models import (
    MANDATORY_GATE_KINDS,
    DependencyAssessment,
    EvaluationResult,
    EvaluationStatus,
    GateKind,
    GateResult,
    GateStatus,
    ImprovementCandidate,
    ImprovementMode,
    ImprovementRunResult,
    ImprovementRunStatus,
    IsolatedWorkspace,
    MergeDeploymentProposal,
    PriorityOutcome,
    RollbackMetadata,
)
from jarvis.improvement.workspace import (
    GitWorktreeManager,
    TrustedWorkspaceChangeApplier,
    WorkspaceDisposition,
    WorkspaceSecurityError,
)


class ImprovementEngine:
    """Run isolated experiments and stop at an immutable approval proposal."""

    def __init__(
        self,
        *,
        candidate_generator: StructuredCandidateGenerator,
        prioritizer: ImprovementPrioritizer,
        risk_classifier: ImprovementRiskClassifier,
        specifier: TrustedTemplateSpecifier,
        workspace_manager: GitWorktreeManager,
        coding_agent: CodingAgent,
        change_applier: TrustedWorkspaceChangeApplier,
        dependency_guard: ManifestDependencyGuard,
        gate_runner: SandboxedMandatoryGateRunner,
        security_checker: SecurityChecker,
        evaluator: ProtectedRegressionEvaluator,
        proposal_store: ProposalStore,
        mode: ImprovementMode = ImprovementMode.PROPOSE_AND_TEST,
        proposal_lifetime: timedelta = timedelta(hours=24),
        clock: Callable[[], datetime] | None = None,
        uuid_factory: Callable[[], UUID] | None = None,
    ) -> None:
        if mode is not ImprovementMode.PROPOSE_AND_TEST:
            raise ValueError("Autonomous deployment mode does not exist in Phase 11")
        if proposal_lifetime <= timedelta(0):
            raise ValueError("Proposal lifetime must be positive")
        self._candidate_generator = candidate_generator
        self._prioritizer = prioritizer
        self._risk_classifier = risk_classifier
        self._specifier = specifier
        self._workspaces = workspace_manager
        self._coding_agent = coding_agent
        self._applier = change_applier
        self._dependencies = dependency_guard
        self._gates = gate_runner
        self._security = security_checker
        self._evaluator = evaluator
        self._proposals = proposal_store
        self._mode = mode
        self._proposal_lifetime = proposal_lifetime
        self._clock = clock or (lambda: datetime.now(UTC))
        self._uuid_factory = uuid_factory or uuid4

    @property
    def mode(self) -> ImprovementMode:
        return self._mode

    async def run(
        self,
        task_id: UUID,
        signals: tuple[ObservedImprovementSignal, ...],
        cancellation: asyncio.Event | None = None,
    ) -> ImprovementRunResult:
        cancellation = cancellation or asyncio.Event()
        if cancellation.is_set():
            raise asyncio.CancelledError
        generated = await self._candidate_generator.generate(signals)
        candidates = tuple(self._risk_classifier.assess_candidate(item) for item in generated)
        prioritization = self._prioritizer.prioritize(candidates)
        if prioritization.outcome is PriorityOutcome.NO_WORTHWHILE_IMPROVEMENT:
            return ImprovementRunResult(
                ImprovementRunStatus.NO_WORTHWHILE_IMPROVEMENT,
                prioritization.reason,
                prioritization,
            )

        assert prioritization.selected is not None
        candidate = prioritization.selected.candidate
        specification = self._specifier.specify(candidate)
        try:
            workspace = await self._workspaces.create(candidate.candidate_id, cancellation)
        except WorkspaceSecurityError:
            return ImprovementRunResult(
                ImprovementRunStatus.WORKSPACE_REJECTED,
                "isolated_workspace_creation_rejected",
                prioritization,
                candidate=candidate,
                specification=specification,
            )

        try:
            dependency_baseline = await self._dependencies.capture(workspace, cancellation)
            evaluation_baseline = await self._evaluator.capture_baseline(
                candidate, workspace, cancellation
            )
            await self._workspaces.assert_pristine(workspace, cancellation)
        except asyncio.CancelledError:
            self._quarantine_if_active(workspace)
            raise
        except Exception:
            self._quarantine_if_active(workspace)
            return ImprovementRunResult(
                ImprovementRunStatus.EVALUATION_FAILED,
                "trusted_baseline_capture_failed",
                prioritization,
                candidate=candidate,
                specification=specification,
                workspace=workspace,
            )

        context = _coding_context(candidate)
        try:
            change_set = await self._coding_agent.propose_changes(
                specification, context, cancellation
            )
            modification = await self._applier.apply(
                workspace, specification, change_set, cancellation
            )
        except asyncio.CancelledError:
            self._quarantine_if_active(workspace)
            raise
        except Exception:
            self._quarantine_if_active(workspace)
            return ImprovementRunResult(
                ImprovementRunStatus.MODIFICATION_REJECTED,
                "coding_output_or_workspace_write_rejected",
                prioritization,
                candidate=candidate,
                specification=specification,
                workspace=workspace,
            )

        if not self._risk_classifier.permits_paths(candidate.risk, modification.changed_paths):
            self._quarantine_if_active(workspace)
            return ImprovementRunResult(
                ImprovementRunStatus.MODIFICATION_REJECTED,
                "changed_paths_exceed_analyzed_risk",
                prioritization,
                candidate=candidate,
                specification=specification,
                workspace=workspace,
                modification=modification,
            )

        try:
            dependency_assessment = await self._dependencies.assess(
                workspace, dependency_baseline, cancellation
            )
        except asyncio.CancelledError:
            self._quarantine_if_active(workspace)
            raise
        except Exception:
            dependency_assessment = DependencyAssessment(False, "dependency_assessment_invalid", ())
        if not dependency_assessment.allowed:
            self._quarantine_if_active(workspace)
            return ImprovementRunResult(
                ImprovementRunStatus.DEPENDENCY_REJECTED,
                dependency_assessment.reason_code,
                prioritization,
                candidate,
                specification,
                workspace,
                modification,
                dependency_assessment,
            )

        try:
            security_preflight = await self._security.check(
                specification, change_set, modification, cancellation
            )
        except asyncio.CancelledError:
            self._quarantine_if_active(workspace)
            raise
        except Exception:
            self._quarantine_if_active(workspace)
            return ImprovementRunResult(
                ImprovementRunStatus.GATE_FAILED,
                "security_preflight_failed_closed",
                prioritization,
                candidate,
                specification,
                workspace,
                modification,
                dependency_assessment,
            )
        if (
            security_preflight.kind is not GateKind.SECURITY
            or security_preflight.status is not GateStatus.PASSED
        ):
            self._quarantine_if_active(workspace)
            return ImprovementRunResult(
                ImprovementRunStatus.GATE_FAILED,
                "security_preflight_rejected",
                prioritization,
                candidate,
                specification,
                workspace,
                modification,
                dependency_assessment,
                (security_preflight,),
            )

        try:
            executable_gates = await self._gates.run(
                workspace, specification, modification, cancellation
            )
            await self._applier.verify_unchanged(workspace, modification, cancellation)
        except asyncio.CancelledError:
            self._quarantine_if_active(workspace)
            raise
        except Exception:
            self._quarantine_if_active(workspace)
            return ImprovementRunResult(
                ImprovementRunStatus.GATE_FAILED,
                "gate_execution_integrity_failed",
                prioritization,
                candidate,
                specification,
                workspace,
                modification,
                dependency_assessment,
            )
        if not _executable_gates_passed(executable_gates):
            self._quarantine_if_active(workspace)
            return ImprovementRunResult(
                ImprovementRunStatus.GATE_FAILED,
                "mandatory_gate_failed_or_missing",
                prioritization,
                candidate,
                specification,
                workspace,
                modification,
                dependency_assessment,
                executable_gates,
            )

        try:
            security = await self._security.check(
                specification, change_set, modification, cancellation
            )
            await self._applier.verify_unchanged(workspace, modification, cancellation)
            if security.kind is not GateKind.SECURITY or security.status is not GateStatus.PASSED:
                self._quarantine_if_active(workspace)
                return ImprovementRunResult(
                    ImprovementRunStatus.GATE_FAILED,
                    "post_test_security_gate_failed",
                    prioritization,
                    candidate,
                    specification,
                    workspace,
                    modification,
                    dependency_assessment,
                    (*executable_gates, security),
                )
            evaluation = await self._evaluator.evaluate(
                candidate, workspace, evaluation_baseline, cancellation
            )
            await self._applier.verify_unchanged(workspace, modification, cancellation)
            await self._workspaces.assert_production_unchanged(workspace, cancellation)
        except asyncio.CancelledError:
            self._quarantine_if_active(workspace)
            raise
        except Exception:
            self._quarantine_if_active(workspace)
            return ImprovementRunResult(
                ImprovementRunStatus.EVALUATION_FAILED,
                "evaluation_integrity_check_failed",
                prioritization,
                candidate,
                specification,
                workspace,
                modification,
                dependency_assessment,
                (security, *executable_gates),
            )
        regression_gate = _regression_gate(evaluation)
        all_gates = (security, *executable_gates, regression_gate)
        if evaluation.status is not EvaluationStatus.IMPROVED:
            self._quarantine_if_active(workspace)
            return ImprovementRunResult(
                ImprovementRunStatus.EVALUATION_FAILED,
                evaluation.reason_code,
                prioritization,
                candidate,
                specification,
                workspace,
                modification,
                dependency_assessment,
                all_gates,
                evaluation,
            )
        if not _all_gates_passed(all_gates):
            self._quarantine_if_active(workspace)
            return ImprovementRunResult(
                ImprovementRunStatus.GATE_FAILED,
                "mandatory_gate_set_invalid",
                prioritization,
                candidate,
                specification,
                workspace,
                modification,
                dependency_assessment,
                all_gates,
                evaluation,
            )

        now = self._clock()
        rollback = RollbackMetadata(
            previous_known_good_revision=workspace.base_revision,
            candidate_revision=modification.candidate_revision,
            changed_paths=modification.changed_paths,
            restoration_steps=(
                "Keep production pinned to the previous known-good revision",
                "Discard the retained candidate worktree after trusted review",
            ),
        )
        proposal_id = f"proposal-{self._uuid_factory().hex}"
        expires_at = now + self._proposal_lifetime
        fingerprint = compute_proposal_fingerprint(
            proposal_id=proposal_id,
            task_id=task_id,
            candidate=candidate,
            specification=specification,
            workspace=workspace,
            modification=modification,
            dependency_assessment=dependency_assessment,
            gates=all_gates,
            evaluation=evaluation,
            rollback=rollback,
            created_at=now,
            expires_at=expires_at,
        )
        stored = False
        try:
            proposal = MergeDeploymentProposal(
                proposal_id=proposal_id,
                task_id=task_id,
                candidate=candidate,
                specification=specification,
                workspace=workspace,
                modification=modification,
                gates=all_gates,
                evaluation=evaluation,
                dependency_assessment=dependency_assessment,
                rollback=rollback,
                proposal_fingerprint=fingerprint,
                created_at=now,
                expires_at=expires_at,
            )
            self._proposals.add(proposal)
            stored = True
            self._workspaces.retain_for_proposal(workspace)
        except Exception:
            if stored:
                try:
                    self._proposals.remove_unapproved(proposal_id, fingerprint)
                except (KeyError, ValueError):
                    pass
            self._quarantine_if_active(workspace)
            return ImprovementRunResult(
                ImprovementRunStatus.MODIFICATION_REJECTED,
                "proposal_storage_rejected",
                prioritization,
                candidate,
                specification,
                workspace,
                modification,
                dependency_assessment,
                all_gates,
                evaluation,
            )
        return ImprovementRunResult(
            ImprovementRunStatus.PROPOSAL_READY,
            "trusted_approval_required",
            prioritization,
            candidate,
            specification,
            workspace,
            modification,
            dependency_assessment,
            all_gates,
            evaluation,
            proposal,
        )

    def _quarantine_if_active(self, workspace: IsolatedWorkspace) -> None:
        try:
            if self._workspaces.disposition(workspace) is WorkspaceDisposition.ACTIVE:
                self._workspaces.quarantine(workspace)
        except WorkspaceSecurityError:
            return


def _coding_context(candidate: ImprovementCandidate) -> TrustedCodingContext:
    return TrustedCodingContext(
        candidate_id=candidate.candidate_id,
        effective_risk=candidate.risk.value,
        evidence=tuple(
            CodingEvidence(
                evidence.source_reference,
                evidence.summary,
                evidence.content_digest,
                evidence.external_untrusted,
            )
            for evidence in candidate.evidence
        ),
    )


def _executable_gates_passed(results: tuple[GateResult, ...]) -> bool:
    kinds = tuple(result.kind for result in results)
    expected = MANDATORY_GATE_KINDS - {GateKind.SECURITY, GateKind.REGRESSION}
    return (
        len(kinds) == len(set(kinds))
        and set(kinds) == expected
        and all(result.status is GateStatus.PASSED for result in results)
    )


def _all_gates_passed(results: tuple[GateResult, ...]) -> bool:
    kinds = tuple(result.kind for result in results)
    return (
        len(kinds) == len(set(kinds))
        and set(kinds) == MANDATORY_GATE_KINDS
        and all(result.status is GateStatus.PASSED for result in results)
    )


def _regression_gate(evaluation: EvaluationResult) -> GateResult:
    payload = json.dumps(
        {
            "status": evaluation.status.value,
            "reason": evaluation.reason_code,
            "scenarios": [
                {
                    "id": item.scenario_id,
                    "baseline": item.baseline_value,
                    "candidate": item.candidate_value,
                    "delta": item.observed_delta,
                    "passed": item.passed,
                }
                for item in evaluation.scenarios
            ],
        },
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")
    status = (
        GateStatus.PASSED if evaluation.status is EvaluationStatus.IMPROVED else GateStatus.FAILED
    )
    return GateResult(
        GateKind.REGRESSION,
        status,
        f"regression:{status.value}",
        hashlib.sha256(payload).hexdigest(),
    )
