"""Separated coding, sandboxed gate, security, evaluation, and proposal adapters."""

from __future__ import annotations

import asyncio
import hashlib
import hmac
import math
import os
import re
from abc import ABC, abstractmethod
from dataclasses import dataclass
from pathlib import Path

from jarvis.improvement.integrity import compute_proposal_fingerprint
from jarvis.improvement.models import (
    BaselineMeasurement,
    ChangeSpecification,
    EvaluationBaseline,
    EvaluationDirection,
    EvaluationResult,
    EvaluationStatus,
    GateKind,
    GateResult,
    GateStatus,
    ImprovementCandidate,
    IsolatedWorkspace,
    MergeDeploymentProposal,
    ModificationResult,
    ProposedChangeSet,
    ScenarioResult,
)

EXECUTABLE_GATE_KINDS = frozenset(
    {
        GateKind.FORMAT_LINT,
        GateKind.TYPE_CHECK,
        GateKind.UNIT_TESTS,
        GateKind.INTEGRATION_TESTS,
        GateKind.STARTUP_HEALTH,
    }
)


@dataclass(frozen=True, slots=True)
class CodingEvidence:
    source_reference: str
    safe_summary: str
    content_digest: str | None
    external_untrusted: bool


@dataclass(frozen=True, slots=True)
class TrustedCodingContext:
    """Only trusted structured evidence crosses into the coding-agent boundary."""

    candidate_id: str
    effective_risk: str
    evidence: tuple[CodingEvidence, ...]


class CodingAgent(ABC):
    """Reason about source changes, but never receive a filesystem or command primitive."""

    @abstractmethod
    async def propose_changes(
        self,
        specification: ChangeSpecification,
        context: TrustedCodingContext,
        cancellation: asyncio.Event,
    ) -> ProposedChangeSet:
        """Return typed untrusted changes for a trusted applier."""


@dataclass(frozen=True, slots=True)
class GateDefinition:
    kind: GateKind
    executable: Path
    arguments: tuple[str, ...]
    timeout_seconds: float

    def __post_init__(self) -> None:
        if not isinstance(self.kind, GateKind) or self.kind not in EXECUTABLE_GATE_KINDS:
            raise ValueError("Security and regression gates use independent adapters")
        if (
            not isinstance(self.executable, Path)
            or not self.executable.is_absolute()
            or "\x00" in os.fspath(self.executable)
        ):
            raise ValueError("Gate executable must be a trusted absolute path")
        if (
            not isinstance(self.timeout_seconds, int | float)
            or self.timeout_seconds <= 0
            or isinstance(self.timeout_seconds, bool)
            or not math.isfinite(float(self.timeout_seconds))
            or not isinstance(self.arguments, tuple)
            or any(
                not isinstance(argument, str) or "\x00" in argument for argument in self.arguments
            )
        ):
            raise ValueError("Gate arguments and timeout must be bounded")


@dataclass(frozen=True, slots=True)
class SandboxAttestation:
    workspace_write_only: bool
    production_inaccessible: bool
    shared_git_inaccessible: bool
    network_disabled: bool
    secrets_removed: bool
    process_tree_cancellation: bool
    source_tree_immutable: bool

    @property
    def secure(self) -> bool:
        values = (
            self.workspace_write_only,
            self.production_inaccessible,
            self.shared_git_inaccessible,
            self.network_disabled,
            self.secrets_removed,
            self.process_tree_cancellation,
            self.source_tree_immutable,
        )
        return all(isinstance(value, bool) and value for value in values)


@dataclass(frozen=True, slots=True)
class SandboxExecutionResult:
    exit_code: int | None
    stdout: str
    stderr: str
    attestation: SandboxAttestation
    timed_out: bool = False
    cancelled: bool = False

    def __post_init__(self) -> None:
        if (
            (self.exit_code is not None and not isinstance(self.exit_code, int))
            or not isinstance(self.stdout, str)
            or not isinstance(self.stderr, str)
            or not isinstance(self.attestation, SandboxAttestation)
            or not isinstance(self.timed_out, bool)
            or not isinstance(self.cancelled, bool)
        ):
            raise ValueError("Sandbox result must use trusted structured types")
        if len(self.stdout) > 65_536 or len(self.stderr) > 65_536:
            raise ValueError("Sandbox output must be bounded before crossing the adapter")


class SandboxedProcessAdapter(ABC):
    """OS isolation boundary; no permissive in-process implementation is provided."""

    @abstractmethod
    async def execute(
        self,
        workspace: IsolatedWorkspace,
        definition: GateDefinition,
        cancellation: asyncio.Event,
    ) -> SandboxExecutionResult:
        """Execute fixed argv in an independently confined process tree."""


class SandboxedMandatoryGateRunner:
    """Run host-owned gate definitions and fail if sandbox evidence is incomplete."""

    def __init__(
        self,
        definitions: tuple[GateDefinition, ...],
        adapter: SandboxedProcessAdapter,
    ) -> None:
        kinds = tuple(definition.kind for definition in definitions)
        if len(kinds) != len(set(kinds)) or set(kinds) != EXECUTABLE_GATE_KINDS:
            raise ValueError("Every executable mandatory gate must be defined exactly once")
        self._definitions = definitions
        self._adapter = adapter

    async def run(
        self,
        workspace: IsolatedWorkspace,
        specification: ChangeSpecification,
        modification: ModificationResult,
        cancellation: asyncio.Event,
    ) -> tuple[GateResult, ...]:
        if modification.workspace_id != workspace.workspace_id:
            raise ValueError("Gate evidence belongs to another workspace")
        results: list[GateResult] = []
        for definition in self._definitions:
            if cancellation.is_set():
                results.append(_gate_result(definition.kind, GateStatus.CANCELLED, b"cancelled"))
                break
            execution = await self._adapter.execute(workspace, definition, cancellation)
            evidence = _execution_evidence(
                execution, definition, workspace, specification, modification
            )
            if execution.cancelled:
                status = GateStatus.CANCELLED
            elif (
                execution.timed_out or not execution.attestation.secure or execution.exit_code != 0
            ):
                status = GateStatus.FAILED
            else:
                status = GateStatus.PASSED
            results.append(_gate_result(definition.kind, status, evidence))
            if status is not GateStatus.PASSED:
                break
        return tuple(results)


class SecurityChecker(ABC):
    @abstractmethod
    async def check(
        self,
        specification: ChangeSpecification,
        change_set: ProposedChangeSet,
        modification: ModificationResult,
        cancellation: asyncio.Event,
    ) -> GateResult:
        """Inspect candidate content independently of its generated tests."""


class StaticChangeSecurityChecker(SecurityChecker):
    """Small fail-closed preflight; production may compose additional scanners."""

    _DANGEROUS = re.compile(
        r"-----BEGIN [A-Z ]*PRIVATE KEY-----|"
        r"(?i:aws_secret_access_key\s*=)|"
        r"(?i:(?:api[_-]?key|password|token)\s*=\s*['\"][^'\"]+)|"
        r"(?i:shell\s*=\s*true)|"
        r"(?<![a-zA-Z_])(?:eval|exec|os\.system)\s*\("
    )

    async def check(
        self,
        specification: ChangeSpecification,
        change_set: ProposedChangeSet,
        modification: ModificationResult,
        cancellation: asyncio.Event,
    ) -> GateResult:
        del specification
        if cancellation.is_set():
            return _gate_result(GateKind.SECURITY, GateStatus.CANCELLED, b"cancelled")
        paths_match = (
            tuple(change.path for change in change_set.changes) == modification.changed_paths
        )
        unsafe = not paths_match or any(
            change.content is not None and self._DANGEROUS.search(change.content)
            for change in change_set.changes
        )
        marker = b"static-security-rejected" if unsafe else b"static-security-passed"
        return _gate_result(
            GateKind.SECURITY,
            GateStatus.FAILED if unsafe else GateStatus.PASSED,
            marker,
        )


class ProtectedMetricProvider(ABC):
    """Trusted evaluator measurement boundary, independent of generated tests."""

    @abstractmethod
    async def measure(
        self,
        scenario_id: str,
        metric: str,
        workspace: IsolatedWorkspace,
        cancellation: asyncio.Event,
    ) -> ProtectedMeasurement:
        """Measure one protected scenario in a sandboxed evaluation environment."""


@dataclass(frozen=True, slots=True)
class ProtectedMeasurement:
    value: float
    attestation: SandboxAttestation


class ProtectedRegressionEvaluator:
    def __init__(self, provider: ProtectedMetricProvider) -> None:
        self._provider = provider

    async def capture_baseline(
        self,
        candidate: ImprovementCandidate,
        workspace: IsolatedWorkspace,
        cancellation: asyncio.Event,
    ) -> EvaluationBaseline:
        measurements: list[BaselineMeasurement] = []
        for scenario in candidate.evaluation_plan:
            measurement = await self._provider.measure(
                scenario.scenario_id,
                scenario.metric,
                workspace,
                cancellation,
            )
            if not measurement.attestation.secure or not math.isfinite(measurement.value):
                raise ValueError("Baseline measurement lacks secure sandbox evidence")
            measurements.append(BaselineMeasurement(scenario.scenario_id, measurement.value))
        return EvaluationBaseline(
            workspace.workspace_id,
            workspace.base_revision,
            candidate.candidate_id,
            tuple(measurements),
        )

    async def evaluate(
        self,
        candidate: ImprovementCandidate,
        workspace: IsolatedWorkspace,
        baseline: EvaluationBaseline,
        cancellation: asyncio.Event,
    ) -> EvaluationResult:
        if (
            baseline.workspace_id != workspace.workspace_id
            or baseline.base_revision != workspace.base_revision
            or baseline.candidate_id != candidate.candidate_id
        ):
            return EvaluationResult(EvaluationStatus.INCONCLUSIVE, (), "baseline_binding_mismatch")
        by_scenario = {item.scenario_id: item.value for item in baseline.measurements}
        if set(by_scenario) != {item.scenario_id for item in candidate.evaluation_plan}:
            return EvaluationResult(
                EvaluationStatus.INCONCLUSIVE, (), "baseline_scenarios_mismatch"
            )
        output: list[ScenarioResult] = []
        regressed = False
        for scenario in candidate.evaluation_plan:
            measurement = await self._provider.measure(
                scenario.scenario_id,
                scenario.metric,
                workspace,
                cancellation,
            )
            if not measurement.attestation.secure:
                return EvaluationResult(
                    EvaluationStatus.INCONCLUSIVE, tuple(output), "evaluation_sandbox_insecure"
                )
            measured = measurement.value
            base = by_scenario[scenario.scenario_id]
            if not math.isfinite(measured) or not math.isfinite(base):
                return EvaluationResult(
                    EvaluationStatus.INCONCLUSIVE, tuple(output), "non_finite_measurement"
                )
            if scenario.direction is EvaluationDirection.INCREASE:
                observed = measured - base
            elif scenario.direction is EvaluationDirection.DECREASE:
                observed = base - measured
            else:
                return EvaluationResult(
                    EvaluationStatus.INCONCLUSIVE, tuple(output), "unknown_metric_direction"
                )
            passed = observed >= scenario.required_delta
            regressed = regressed or observed < 0
            output.append(ScenarioResult(scenario.scenario_id, base, measured, observed, passed))
        if output and all(result.passed for result in output):
            status = EvaluationStatus.IMPROVED
            reason = "protected_scenarios_improved"
        elif regressed:
            status = EvaluationStatus.REGRESSION
            reason = "protected_scenario_regressed"
        else:
            status = EvaluationStatus.NO_CHANGE
            reason = "required_improvement_not_observed"
        return EvaluationResult(status, tuple(output), reason)


class ProposalStore(ABC):
    @abstractmethod
    def add(self, proposal: MergeDeploymentProposal) -> None:
        """Persist an awaiting-approval record without approving or executing it."""

    @abstractmethod
    def remove_unapproved(self, proposal_id: str, fingerprint: str) -> None:
        """Roll back a failed proposal transaction using its exact fingerprint."""


class InMemoryProposalStore(ProposalStore):
    def __init__(self) -> None:
        self._proposals: dict[str, MergeDeploymentProposal] = {}

    def add(self, proposal: MergeDeploymentProposal) -> None:
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
        if not hmac.compare_digest(expected, proposal.proposal_fingerprint):
            raise ValueError("Proposal fingerprint does not match its exact contents")
        if proposal.proposal_id in self._proposals:
            raise ValueError("Proposal ID already exists")
        if any(
            existing.proposal_fingerprint == proposal.proposal_fingerprint
            for existing in self._proposals.values()
        ):
            raise ValueError("Exact change already has an awaiting proposal")
        self._proposals[proposal.proposal_id] = proposal

    def remove_unapproved(self, proposal_id: str, fingerprint: str) -> None:
        proposal = self._proposals.get(proposal_id)
        if proposal is None or not hmac.compare_digest(proposal.proposal_fingerprint, fingerprint):
            raise ValueError("Only the exact awaiting proposal can be rolled back from storage")
        del self._proposals[proposal_id]

    def get(self, proposal_id: str) -> MergeDeploymentProposal | None:
        return self._proposals.get(proposal_id)


def _execution_evidence(
    result: SandboxExecutionResult,
    definition: GateDefinition,
    workspace: IsolatedWorkspace,
    specification: ChangeSpecification,
    modification: ModificationResult,
) -> bytes:
    digest = hashlib.sha256()
    digest.update(definition.kind.value.encode("ascii"))
    digest.update(os.fspath(definition.executable).encode("utf-8"))
    digest.update("\x1f".join(definition.arguments).encode("utf-8"))
    digest.update(str(definition.timeout_seconds).encode("ascii"))
    digest.update(workspace.workspace_id.encode("ascii"))
    digest.update(workspace.base_revision.encode("ascii"))
    digest.update(specification.specification_id.encode("ascii"))
    digest.update(modification.diff_digest.encode("ascii"))
    digest.update(modification.tree_digest.encode("ascii"))
    digest.update(str(result.exit_code).encode("ascii"))
    digest.update(result.stdout.encode("utf-8", errors="replace"))
    digest.update(result.stderr.encode("utf-8", errors="replace"))
    digest.update(str(result.attestation).encode("utf-8"))
    digest.update(str(result.timed_out).encode("ascii"))
    digest.update(str(result.cancelled).encode("ascii"))
    return digest.digest()


def _gate_result(kind: GateKind, status: GateStatus, evidence: bytes) -> GateResult:
    return GateResult(
        kind=kind,
        status=status,
        summary=f"{kind.value}:{status.value}",
        evidence_digest=hashlib.sha256(evidence).hexdigest(),
    )
