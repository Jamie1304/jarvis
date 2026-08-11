"""Typed, data-only records for proposal-only JARVIS improvements."""

from __future__ import annotations

import math
from dataclasses import dataclass
from datetime import datetime
from enum import StrEnum
from pathlib import Path, PurePosixPath
from uuid import UUID

from jarvis.permissions.models import Risk

EXTERNAL_EVIDENCE_SUMMARY = "External content retained only as untrusted evidence"


class ImprovementMode(StrEnum):
    """Phase 11 deliberately exposes no autonomous deployment mode."""

    PROPOSE_AND_TEST = "propose_and_test"


class ImprovementSource(StrEnum):
    REPEATED_ERROR = "repeated_error"
    FAILED_WORKFLOW = "failed_workflow"
    PERFORMANCE_METRIC = "performance_metric"
    CAPABILITY_GAP = "capability_gap"
    DEPENDENCY_PROBLEM = "dependency_problem"
    EVALUATION_REGRESSION = "evaluation_regression"


class Reversibility(StrEnum):
    FULL = "full"
    PARTIAL = "partial"
    NONE = "none"


class ChangeOperation(StrEnum):
    CREATE = "create"
    MODIFY = "modify"
    DELETE = "delete"


class EvaluationDirection(StrEnum):
    INCREASE = "increase"
    DECREASE = "decrease"


class PriorityOutcome(StrEnum):
    SELECTED = "selected"
    NO_WORTHWHILE_IMPROVEMENT = "no_worthwhile_improvement"


class GateKind(StrEnum):
    FORMAT_LINT = "format_lint"
    TYPE_CHECK = "type_check"
    UNIT_TESTS = "unit_tests"
    INTEGRATION_TESTS = "integration_tests"
    SECURITY = "security"
    REGRESSION = "regression"
    STARTUP_HEALTH = "startup_health"


MANDATORY_GATE_KINDS = frozenset(GateKind)


class GateStatus(StrEnum):
    PASSED = "passed"
    FAILED = "failed"
    CANCELLED = "cancelled"


class EvaluationStatus(StrEnum):
    IMPROVED = "improved"
    NO_CHANGE = "no_change"
    REGRESSION = "regression"
    INCONCLUSIVE = "inconclusive"


class ProposalStatus(StrEnum):
    AWAITING_TRUSTED_APPROVAL = "awaiting_trusted_approval"
    APPROVED = "approved"
    DENIED = "denied"
    EXPIRED = "expired"
    CANCELLED = "cancelled"


class ImprovementRunStatus(StrEnum):
    NO_WORTHWHILE_IMPROVEMENT = "no_worthwhile_improvement"
    WORKSPACE_REJECTED = "workspace_rejected"
    MODIFICATION_REJECTED = "modification_rejected"
    DEPENDENCY_REJECTED = "dependency_rejected"
    GATE_FAILED = "gate_failed"
    EVALUATION_FAILED = "evaluation_failed"
    PROPOSAL_READY = "proposal_ready"


@dataclass(frozen=True, slots=True)
class ImprovementEvidence:
    """Safe evidence metadata; raw external content is intentionally absent."""

    source_reference: str
    summary: str
    occurrence_count: int = 1
    content_digest: str | None = None
    external_untrusted: bool = False

    def __post_init__(self) -> None:
        _single_line(self.source_reference, "Evidence source reference", maximum=512)
        _bounded_text(self.summary, "Evidence summary", maximum=1_000)
        if isinstance(self.occurrence_count, bool) or self.occurrence_count <= 0:
            raise ValueError("Evidence occurrence count must be positive")
        if self.content_digest is not None and not _is_sha256(self.content_digest):
            raise ValueError("Evidence digest must be lowercase SHA-256")
        if self.external_untrusted and self.content_digest is None:
            raise ValueError("External evidence requires a content digest")
        if self.external_untrusted and self.summary != EXTERNAL_EVIDENCE_SUMMARY:
            raise ValueError("Raw external descriptions cannot enter improvement evidence")
        if self.external_untrusted and not (
            self.source_reference.startswith("external:")
            and _is_sha256(self.source_reference.removeprefix("external:"))
        ):
            raise ValueError("External source references must be opaque SHA-256 tokens")


@dataclass(frozen=True, slots=True)
class EvaluationScenario:
    scenario_id: str
    description: str
    metric: str
    direction: EvaluationDirection
    baseline_value: float
    required_delta: float

    def __post_init__(self) -> None:
        _label(self.scenario_id, "Scenario ID")
        _bounded_text(self.description, "Scenario description")
        _label(self.metric, "Metric")
        if not isinstance(self.direction, EvaluationDirection):
            raise ValueError("Evaluation direction must be a known enum value")
        if not _finite_number(self.baseline_value) or not _finite_number(self.required_delta):
            raise ValueError("Evaluation values must be finite numbers")
        if self.required_delta <= 0:
            raise ValueError("An improvement scenario requires a positive target delta")


@dataclass(frozen=True, slots=True)
class ImprovementCandidate:
    candidate_id: str
    source: ImprovementSource
    evidence: tuple[ImprovementEvidence, ...]
    proposed_objective: str
    expected_benefit: str
    affected_components: tuple[str, ...]
    risk: Risk
    reversibility: Reversibility
    evaluation_plan: tuple[EvaluationScenario, ...]
    impact: int
    frequency: int
    confidence: int
    implementation_cost: int
    user_relevance: int

    def __post_init__(self) -> None:
        _label(self.candidate_id, "Candidate ID")
        if not isinstance(self.source, ImprovementSource):
            raise ValueError("Candidate source must be known")
        if not isinstance(self.risk, Risk) or not isinstance(self.reversibility, Reversibility):
            raise ValueError("Candidate risk and reversibility must be known enum values")
        if not self.evidence:
            raise ValueError("An improvement candidate requires evidence")
        _bounded_text(self.proposed_objective, "Proposed objective")
        _bounded_text(self.expected_benefit, "Expected benefit")
        if not self.affected_components:
            raise ValueError("Affected components must be explicit")
        for component in self.affected_components:
            _relative_path(component, "Affected component")
        if not self.evaluation_plan:
            raise ValueError("An improvement candidate requires an evaluation plan")
        for name, value in (
            ("impact", self.impact),
            ("frequency", self.frequency),
            ("confidence", self.confidence),
            ("implementation cost", self.implementation_cost),
            ("user relevance", self.user_relevance),
        ):
            _score(value, name)


@dataclass(frozen=True, slots=True)
class PriorityFactor:
    name: str
    score: int
    weight: float
    explanation: str

    def __post_init__(self) -> None:
        _label(self.name, "Priority factor")
        _score(self.score, "priority factor")
        if not _finite_number(self.weight) or not 0 <= self.weight <= 1:
            raise ValueError("Priority weight must be between zero and one")
        _bounded_text(self.explanation, "Priority explanation", maximum=500)


@dataclass(frozen=True, slots=True)
class PrioritizedCandidate:
    candidate: ImprovementCandidate
    score: int
    factors: tuple[PriorityFactor, ...]


@dataclass(frozen=True, slots=True)
class PrioritizationResult:
    outcome: PriorityOutcome
    ranked: tuple[PrioritizedCandidate, ...]
    selected: PrioritizedCandidate | None
    reason: str

    def __post_init__(self) -> None:
        if not isinstance(self.outcome, PriorityOutcome):
            raise ValueError("Prioritization outcome must be known")
        if (self.outcome is PriorityOutcome.SELECTED) is (self.selected is None):
            raise ValueError("Selected prioritization outcomes require exactly one candidate")


@dataclass(frozen=True, slots=True)
class ChangeSpecification:
    specification_id: str
    candidate_id: str
    problem: str
    intended_behavior: str
    boundaries: tuple[str, ...]
    likely_affected_paths: tuple[str, ...]
    required_tests: tuple[str, ...]
    rollback_plan: str

    def __post_init__(self) -> None:
        _label(self.specification_id, "Specification ID")
        _label(self.candidate_id, "Candidate ID")
        _bounded_text(self.problem, "Problem")
        _bounded_text(self.intended_behavior, "Intended behavior")
        if not self.boundaries or not self.likely_affected_paths or not self.required_tests:
            raise ValueError("Change boundaries, affected paths, and tests are mandatory")
        for boundary in self.boundaries:
            _bounded_text(boundary, "Change boundary", maximum=500)
        for path in self.likely_affected_paths:
            _relative_path(path, "Likely affected path")
        for test in self.required_tests:
            _bounded_text(test, "Required test", maximum=500)
        _bounded_text(self.rollback_plan, "Rollback plan")


@dataclass(frozen=True, slots=True)
class IsolatedWorkspace:
    workspace_id: str
    root: Path
    branch: str
    base_revision: str
    created_at: datetime

    def __post_init__(self) -> None:
        _label(self.workspace_id, "Workspace ID")
        if not self.root.is_absolute():
            raise ValueError("Workspace root must be absolute")
        _label(self.branch, "Workspace branch", maximum=200)
        if not _is_revision(self.base_revision):
            raise ValueError("Base revision must be an immutable hexadecimal Git revision")
        if not isinstance(self.created_at, datetime):
            raise ValueError("Workspace creation time must be trusted datetime data")


@dataclass(frozen=True, slots=True)
class ModificationResult:
    workspace_id: str
    changed_paths: tuple[str, ...]
    diff_digest: str
    tree_digest: str
    candidate_revision: str | None = None

    def __post_init__(self) -> None:
        _label(self.workspace_id, "Workspace ID")
        if not self.changed_paths:
            raise ValueError("A modification result requires changed paths")
        for path in self.changed_paths:
            _relative_path(path, "Changed path")
        if not _is_sha256(self.diff_digest):
            raise ValueError("Diff digest must be lowercase SHA-256")
        if not _is_sha256(self.tree_digest):
            raise ValueError("Workspace tree digest must be lowercase SHA-256")
        if self.candidate_revision is not None and not _is_revision(self.candidate_revision):
            raise ValueError("Candidate revision must be hexadecimal")


@dataclass(frozen=True, slots=True)
class ProposedFileChange:
    """Untrusted coding-agent output for a trusted workspace applier."""

    path: str
    operation: ChangeOperation
    content: str | None
    expected_base_digest: str | None = None

    def __post_init__(self) -> None:
        _relative_path(self.path, "Proposed change path")
        if not isinstance(self.operation, ChangeOperation):
            raise ValueError("Change operation must be known")
        if self.operation in {ChangeOperation.CREATE, ChangeOperation.MODIFY}:
            if self.content is None or "\x00" in self.content:
                raise ValueError("Created or modified text files require NUL-free content")
            if len(self.content.encode("utf-8")) > 1_000_000:
                raise ValueError("One proposed text file cannot exceed one megabyte")
        elif self.content is not None:
            raise ValueError("Deleted files cannot include replacement content")
        if self.operation in {ChangeOperation.MODIFY, ChangeOperation.DELETE}:
            if self.expected_base_digest is None or not _is_sha256(self.expected_base_digest):
                raise ValueError("Existing-file changes require an exact base digest")
        elif self.expected_base_digest is not None:
            raise ValueError("New files cannot claim a base digest")


@dataclass(frozen=True, slots=True)
class ProposedChangeSet:
    specification_id: str
    changes: tuple[ProposedFileChange, ...]

    def __post_init__(self) -> None:
        _label(self.specification_id, "Specification ID")
        if not self.changes:
            raise ValueError("Coding agent must propose at least one file change")
        paths = tuple(change.path.casefold() for change in self.changes)
        if len(paths) != len(set(paths)):
            raise ValueError("A change set cannot contain duplicate paths")
        if len(self.changes) > 100:
            raise ValueError("A change set cannot contain more than 100 files")
        total_bytes = sum(len((change.content or "").encode("utf-8")) for change in self.changes)
        if total_bytes > 5_000_000:
            raise ValueError("A change set cannot exceed five megabytes")
        if sum(change.operation is ChangeOperation.DELETE for change in self.changes) > 25:
            raise ValueError("Bulk deletion is forbidden in propose-and-test mode")


@dataclass(frozen=True, slots=True)
class DependencyRecord:
    name: str
    version: str
    source: str

    def __post_init__(self) -> None:
        _label(self.name, "Dependency name")
        _single_line(self.version, "Dependency version", maximum=200)
        _single_line(self.source, "Dependency source", maximum=500)


@dataclass(frozen=True, slots=True)
class DependencyChange:
    name: str
    previous: DependencyRecord | None
    proposed: DependencyRecord | None
    risk_analysis: str | None = None

    def __post_init__(self) -> None:
        _label(self.name, "Dependency change name")
        records = tuple(item for item in (self.previous, self.proposed) if item is not None)
        if not records or any(item.name.casefold() != self.name.casefold() for item in records):
            raise ValueError("Dependency change identity must match its records")
        if self.previous is None and not (self.risk_analysis or "").strip():
            raise ValueError("A new dependency requires explicit risk analysis")


@dataclass(frozen=True, slots=True)
class DependencyAssessment:
    allowed: bool
    reason_code: str
    changes: tuple[DependencyChange, ...]

    def __post_init__(self) -> None:
        if not isinstance(self.allowed, bool):
            raise ValueError("Dependency assessment decision must be boolean")
        _label(self.reason_code, "Dependency decision reason")


@dataclass(frozen=True, slots=True)
class GateResult:
    kind: GateKind
    status: GateStatus
    summary: str
    evidence_digest: str

    def __post_init__(self) -> None:
        if not isinstance(self.kind, GateKind) or not isinstance(self.status, GateStatus):
            raise ValueError("Gate kind and status must be known enum values")
        _bounded_text(self.summary, "Gate summary", maximum=1_000)
        if not _is_sha256(self.evidence_digest):
            raise ValueError("Gate evidence digest must be lowercase SHA-256")


@dataclass(frozen=True, slots=True)
class ScenarioResult:
    scenario_id: str
    baseline_value: float
    candidate_value: float
    observed_delta: float
    passed: bool

    def __post_init__(self) -> None:
        _label(self.scenario_id, "Scenario ID")
        if not all(
            _finite_number(value)
            for value in (self.baseline_value, self.candidate_value, self.observed_delta)
        ) or not isinstance(self.passed, bool):
            raise ValueError("Scenario result values must be finite and passed must be boolean")


@dataclass(frozen=True, slots=True)
class EvaluationResult:
    status: EvaluationStatus
    scenarios: tuple[ScenarioResult, ...]
    reason_code: str

    def __post_init__(self) -> None:
        if not isinstance(self.status, EvaluationStatus):
            raise ValueError("Evaluation status must be known")
        _label(self.reason_code, "Evaluation reason")


@dataclass(frozen=True, slots=True)
class BaselineMeasurement:
    scenario_id: str
    value: float

    def __post_init__(self) -> None:
        _label(self.scenario_id, "Scenario ID")
        if not _finite_number(self.value):
            raise ValueError("Baseline measurement must be finite")


@dataclass(frozen=True, slots=True)
class EvaluationBaseline:
    workspace_id: str
    base_revision: str
    candidate_id: str
    measurements: tuple[BaselineMeasurement, ...]

    def __post_init__(self) -> None:
        _label(self.workspace_id, "Workspace ID")
        _label(self.candidate_id, "Candidate ID")
        if not _is_revision(self.base_revision):
            raise ValueError("Evaluation baseline must bind a full immutable revision")
        if not self.measurements:
            raise ValueError("Evaluation baseline requires protected measurements")
        scenario_ids = tuple(item.scenario_id for item in self.measurements)
        if len(scenario_ids) != len(set(scenario_ids)):
            raise ValueError("Evaluation baseline scenarios must be unique")


@dataclass(frozen=True, slots=True)
class RollbackMetadata:
    previous_known_good_revision: str
    candidate_revision: str | None
    changed_paths: tuple[str, ...]
    restoration_steps: tuple[str, ...]

    def __post_init__(self) -> None:
        if not _is_revision(self.previous_known_good_revision):
            raise ValueError("Rollback revision must be immutable and hexadecimal")
        if self.candidate_revision is not None and not _is_revision(self.candidate_revision):
            raise ValueError("Candidate revision must be hexadecimal")
        if not self.changed_paths or not self.restoration_steps:
            raise ValueError("Rollback metadata requires paths and restoration steps")
        for path in self.changed_paths:
            _relative_path(path, "Rollback path")
        for step in self.restoration_steps:
            _bounded_text(step, "Restoration step", maximum=500)


@dataclass(frozen=True, slots=True)
class MergeDeploymentProposal:
    proposal_id: str
    task_id: UUID
    candidate: ImprovementCandidate
    specification: ChangeSpecification
    workspace: IsolatedWorkspace
    modification: ModificationResult
    gates: tuple[GateResult, ...]
    evaluation: EvaluationResult
    dependency_assessment: DependencyAssessment
    rollback: RollbackMetadata
    proposal_fingerprint: str
    created_at: datetime
    expires_at: datetime
    status: ProposalStatus = ProposalStatus.AWAITING_TRUSTED_APPROVAL

    def __post_init__(self) -> None:
        _label(self.proposal_id, "Proposal ID")
        if not isinstance(self.task_id, UUID):
            raise ValueError("Proposal task identity must be trusted UUID data")
        if not _is_sha256(self.proposal_fingerprint):
            raise ValueError("Proposal fingerprint must be lowercase SHA-256")
        if not isinstance(self.status, ProposalStatus):
            raise ValueError("Proposal status must be known")
        if self.status is not ProposalStatus.AWAITING_TRUSTED_APPROVAL:
            raise ValueError("New engine proposals must await trusted approval")
        if not isinstance(self.created_at, datetime) or not isinstance(self.expires_at, datetime):
            raise ValueError("Proposal timestamps must be trusted datetime data")
        if self.created_at.tzinfo is None or self.expires_at.tzinfo is None:
            raise ValueError("Proposal timestamps must be timezone-aware")
        if self.expires_at <= self.created_at:
            raise ValueError("Proposal expiry must follow creation")
        kinds = tuple(result.kind for result in self.gates)
        if len(kinds) != len(set(kinds)) or set(kinds) != MANDATORY_GATE_KINDS:
            raise ValueError("Proposal must contain every mandatory gate exactly once")
        if any(result.status is not GateStatus.PASSED for result in self.gates):
            raise ValueError("Failed gates cannot enter a merge/deployment proposal")
        if self.evaluation.status is not EvaluationStatus.IMPROVED:
            raise ValueError("Only independently evaluated improvements may be proposed")
        if not self.dependency_assessment.allowed:
            raise ValueError("Rejected dependency changes cannot be proposed")
        if self.rollback.previous_known_good_revision != self.workspace.base_revision:
            raise ValueError("Rollback metadata must identify the workspace base revision")
        if self.candidate.candidate_id != self.specification.candidate_id:
            raise ValueError("Proposal specification belongs to another candidate")
        if self.modification.workspace_id != self.workspace.workspace_id:
            raise ValueError("Proposal modification belongs to another workspace")
        if self.rollback.changed_paths != self.modification.changed_paths:
            raise ValueError("Rollback paths must match the exact proposed change")


@dataclass(frozen=True, slots=True)
class ImprovementRunResult:
    status: ImprovementRunStatus
    reason_code: str
    prioritization: PrioritizationResult
    candidate: ImprovementCandidate | None = None
    specification: ChangeSpecification | None = None
    workspace: IsolatedWorkspace | None = None
    modification: ModificationResult | None = None
    dependency_assessment: DependencyAssessment | None = None
    gates: tuple[GateResult, ...] = ()
    evaluation: EvaluationResult | None = None
    proposal: MergeDeploymentProposal | None = None


def _bounded_text(value: str, label: str, *, maximum: int = 2_000) -> None:
    if not isinstance(value, str) or not value.strip() or "\x00" in value or len(value) > maximum:
        raise ValueError(f"{label} must be non-empty and bounded")


def _single_line(value: str, label: str, *, maximum: int) -> None:
    _bounded_text(value, label, maximum=maximum)
    if "\n" in value or "\r" in value:
        raise ValueError(f"{label} must be a single line")


def _label(value: str, label: str, *, maximum: int = 128) -> None:
    _single_line(value, label, maximum=maximum)
    if value != value.strip() or any(character.isspace() for character in value):
        raise ValueError(f"{label} must be a compact label")


def _relative_path(value: str, label: str) -> None:
    _single_line(value, label, maximum=500)
    normalized = value.replace("\\", "/")
    path = PurePosixPath(normalized)
    if (
        path.is_absolute()
        or any(part in {".", ".."} for part in path.parts)
        or normalized != path.as_posix()
        or ":" in value
        or value.startswith(("/", "\\"))
    ):
        raise ValueError(f"{label} must remain relative to the isolated workspace")


def _score(value: int, label: str) -> None:
    if not isinstance(value, int) or isinstance(value, bool) or not 0 <= value <= 100:
        raise ValueError(f"{label} score must be between 0 and 100")


def _is_sha256(value: object) -> bool:
    return (
        isinstance(value, str)
        and len(value) == 64
        and all(character in "0123456789abcdef" for character in value)
    )


def _is_revision(value: object) -> bool:
    return (
        isinstance(value, str)
        and len(value) in {40, 64}
        and all(character in "0123456789abcdef" for character in value)
    )


def _finite_number(value: object) -> bool:
    return (
        isinstance(value, int | float)
        and not isinstance(value, bool)
        and math.isfinite(float(value))
    )
