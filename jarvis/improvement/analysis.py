"""Trusted candidate generation, risk classification, prioritization, and specification."""

from __future__ import annotations

import hashlib
import math
from dataclasses import dataclass, replace

from jarvis.improvement.models import (
    EXTERNAL_EVIDENCE_SUMMARY,
    ChangeSpecification,
    EvaluationDirection,
    EvaluationScenario,
    ImprovementCandidate,
    ImprovementEvidence,
    ImprovementSource,
    PrioritizationResult,
    PrioritizedCandidate,
    PriorityFactor,
    PriorityOutcome,
    Reversibility,
)
from jarvis.permissions.models import Risk


@dataclass(frozen=True, slots=True)
class ObservedImprovementSignal:
    """Structured host evidence; `external_content` is never propagated downstream."""

    signal_code: str
    source: ImprovementSource
    source_reference: str
    trusted_summary: str
    occurrence_count: int
    affected_component: str
    expected_benefit: str
    metric: str
    baseline_value: float
    target_delta: float
    direction: EvaluationDirection
    declared_risk: Risk
    reversibility: Reversibility
    impact: int
    confidence: int
    implementation_cost: int
    user_relevance: int
    external_content: str | None = None

    def __post_init__(self) -> None:
        if not isinstance(self.source, ImprovementSource):
            raise ValueError("Signal source must be known")
        if not isinstance(self.direction, EvaluationDirection):
            raise ValueError("Signal evaluation direction must be known")
        if not isinstance(self.declared_risk, Risk) or not isinstance(
            self.reversibility, Reversibility
        ):
            raise ValueError("Signal risk and reversibility must be known")
        if not _compact_code(self.signal_code):
            raise ValueError("Signal code must be a compact host-owned identifier")
        if (
            not isinstance(self.source_reference, str)
            or not self.source_reference.strip()
            or self.source_reference != self.source_reference.strip()
            or len(self.source_reference) > 512
            or any(character in self.source_reference for character in ("\x00", "\n", "\r"))
        ):
            raise ValueError("Signal source reference must be bounded single-line metadata")
        if not _compact_code(self.metric):
            raise ValueError("Metric must be a compact host-owned identifier")
        if (
            not isinstance(self.occurrence_count, int)
            or isinstance(self.occurrence_count, bool)
            or self.occurrence_count <= 0
        ):
            raise ValueError("Signal occurrence count must be positive")
        if (
            not all(
                isinstance(value, int | float)
                and not isinstance(value, bool)
                and math.isfinite(float(value))
                for value in (self.baseline_value, self.target_delta)
            )
            or self.target_delta <= 0
        ):
            raise ValueError("Signal evaluation values must be finite with a positive target")
        if self.external_content is not None and not isinstance(self.external_content, str):
            raise ValueError("External evidence content must be text")


class ImprovementRiskClassifier:
    """Raise risk from trusted component rules; candidate labels can never lower it."""

    _CRITICAL_PREFIXES = (
        ".github/",
        "jarvis/bootstrap.py",
        "jarvis/improvement/",
        "jarvis/permissions/",
        "jarvis/tools/",
        "package-lock.json",
        "package.json",
        "pipfile",
        "pipfile.lock",
        "pnpm-lock.yaml",
        "poetry.lock",
        "pyproject.toml",
        "requirements-dev.lock",
        "requirements.lock",
        "scripts/quality.py",
        "setup.cfg",
        "setup.py",
        "tests/",
        "uv.lock",
        "yarn.lock",
    )
    _HIGH_PREFIXES = (
        "jarvis/applications/",
        "jarvis/autonomy/",
        "jarvis/camera/",
        "jarvis/computer/",
        "jarvis/vision/",
    )
    _ORDER = {Risk.LOW: 0, Risk.MEDIUM: 1, Risk.HIGH: 2, Risk.CRITICAL: 3}

    def classify(self, components: tuple[str, ...], declared: Risk) -> Risk:
        normalized = tuple(component.replace("\\", "/").casefold() for component in components)
        classified = Risk.MEDIUM
        if normalized and all(
            component.startswith(("docs/", "tests/")) for component in normalized
        ):
            classified = Risk.LOW
        if any(
            _scope_reaches(component, prefix)
            for component in normalized
            for prefix in self._HIGH_PREFIXES
        ):
            classified = Risk.HIGH
        if any(
            _scope_reaches(component, prefix)
            for component in normalized
            for prefix in self._CRITICAL_PREFIXES
        ):
            classified = Risk.CRITICAL
        if any(_dependency_or_gate_control(component) for component in normalized):
            classified = Risk.CRITICAL
        return max((declared, classified), key=self._ORDER.__getitem__)

    def assess_candidate(self, candidate: ImprovementCandidate) -> ImprovementCandidate:
        effective = self.classify(candidate.affected_components, candidate.risk)
        return candidate if effective is candidate.risk else replace(candidate, risk=effective)

    def permits_paths(self, risk: Risk, paths: tuple[str, ...]) -> bool:
        required = self.classify(paths, Risk.LOW)
        return self._ORDER[required] <= self._ORDER[risk]


class StructuredCandidateGenerator:
    """Map structured signals to candidates using trusted templates, never raw prose."""

    def __init__(self, classifier: ImprovementRiskClassifier | None = None) -> None:
        self._classifier = classifier or ImprovementRiskClassifier()

    async def generate(
        self, signals: tuple[ObservedImprovementSignal, ...]
    ) -> tuple[ImprovementCandidate, ...]:
        return tuple(self._candidate(signal) for signal in signals)

    def _candidate(self, signal: ObservedImprovementSignal) -> ImprovementCandidate:
        digest = None
        summary = signal.trusted_summary
        source_reference = signal.source_reference
        expected_benefit = signal.expected_benefit
        external_untrusted = signal.external_content is not None
        if signal.external_content is not None:
            digest = hashlib.sha256(signal.external_content.encode("utf-8")).hexdigest()
            summary = EXTERNAL_EVIDENCE_SUMMARY
            source_reference = (
                f"external:{hashlib.sha256(signal.source_reference.encode()).hexdigest()}"
            )
            expected_benefit = "Improve the protected evidence-linked scenario"
        identity_material = "\x1f".join(
            (
                signal.source.value,
                signal.signal_code,
                source_reference,
                signal.affected_component,
            )
        )
        candidate_id = f"improvement-{hashlib.sha256(identity_material.encode()).hexdigest()[:16]}"
        scenario_id = f"scenario-{hashlib.sha256(identity_material.encode()).hexdigest()[16:32]}"
        classified_risk = self._classifier.classify(
            (signal.affected_component,), signal.declared_risk
        )
        return ImprovementCandidate(
            candidate_id=candidate_id,
            source=signal.source,
            evidence=(
                ImprovementEvidence(
                    source_reference=source_reference,
                    summary=summary,
                    occurrence_count=signal.occurrence_count,
                    content_digest=digest,
                    external_untrusted=external_untrusted,
                ),
            ),
            proposed_objective=(
                f"Address {signal.source.value} signal {signal.signal_code} "
                "in the bounded component"
            ),
            expected_benefit=expected_benefit,
            affected_components=(signal.affected_component,),
            risk=classified_risk,
            reversibility=signal.reversibility,
            evaluation_plan=(
                EvaluationScenario(
                    scenario_id=scenario_id,
                    description=f"Measure trusted signal {signal.signal_code} against its baseline",
                    metric=signal.metric,
                    direction=signal.direction,
                    baseline_value=signal.baseline_value,
                    required_delta=signal.target_delta,
                ),
            ),
            impact=signal.impact,
            frequency=min(100, signal.occurrence_count),
            confidence=signal.confidence,
            implementation_cost=signal.implementation_cost,
            user_relevance=signal.user_relevance,
        )


class ImprovementPrioritizer:
    """Explainably select a worthwhile candidate without treating score as authority."""

    def __init__(self, minimum_score: int = 60) -> None:
        if not 0 <= minimum_score <= 100:
            raise ValueError("Minimum priority score must be between 0 and 100")
        self._minimum = minimum_score

    def prioritize(self, candidates: tuple[ImprovementCandidate, ...]) -> PrioritizationResult:
        ranked = tuple(
            sorted(
                (self._score(candidate) for candidate in candidates),
                key=lambda item: (-item.score, item.candidate.candidate_id),
            )
        )
        if not ranked or ranked[0].score < self._minimum:
            return PrioritizationResult(
                PriorityOutcome.NO_WORTHWHILE_IMPROVEMENT,
                ranked,
                None,
                "no_candidate_meets_priority_threshold",
            )
        return PrioritizationResult(
            PriorityOutcome.SELECTED,
            ranked,
            ranked[0],
            "highest_explainable_priority_score",
        )

    @staticmethod
    def _score(candidate: ImprovementCandidate) -> PrioritizedCandidate:
        inverse_risk = {
            Risk.LOW: 100,
            Risk.MEDIUM: 75,
            Risk.HIGH: 35,
            Risk.CRITICAL: 0,
        }[candidate.risk]
        values = (
            ("impact", candidate.impact, 0.25, "Expected effect if the change succeeds"),
            ("frequency", candidate.frequency, 0.20, "Observed occurrence frequency"),
            ("confidence", candidate.confidence, 0.15, "Confidence in evidence and diagnosis"),
            (
                "user_relevance",
                candidate.user_relevance,
                0.20,
                "Relevance to explicit user goals",
            ),
            ("risk", inverse_risk, 0.15, f"Inverse of {candidate.risk.value} effective risk"),
            (
                "implementation_cost",
                100 - candidate.implementation_cost,
                0.05,
                "Inverse estimated implementation cost",
            ),
        )
        factors = tuple(PriorityFactor(*value) for value in values)
        score = round(sum(factor.score * factor.weight for factor in factors))
        return PrioritizedCandidate(candidate, score, factors)


class TrustedTemplateSpecifier:
    """Produce a concrete bounded spec before a coding adapter is invoked."""

    def specify(self, candidate: ImprovementCandidate) -> ChangeSpecification:
        evidence_summary = "; ".join(evidence.summary for evidence in candidate.evidence)
        digest = hashlib.sha256(candidate.candidate_id.encode()).hexdigest()[:16]
        return ChangeSpecification(
            specification_id=f"spec-{digest}",
            candidate_id=candidate.candidate_id,
            problem=evidence_summary,
            intended_behavior=candidate.proposed_objective,
            boundaries=(
                "Modify only manager-approved paths in the isolated workspace",
                "Do not add dependencies, alter trusted gates, merge, deploy, or access production",
            ),
            likely_affected_paths=candidate.affected_components,
            required_tests=tuple(
                f"Evaluate {scenario.scenario_id} using protected metric {scenario.metric}"
                for scenario in candidate.evaluation_plan
            ),
            rollback_plan="Discard the isolated worktree and retain the known-good base revision",
        )


def _scope_reaches(component: str, protected_prefix: str) -> bool:
    protected = protected_prefix.rstrip("/")
    return (
        component == protected
        or component.startswith(f"{protected}/")
        or protected.startswith(f"{component.rstrip('/')}/")
    )


def _compact_code(value: str) -> bool:
    return (
        isinstance(value, str)
        and 0 < len(value) <= 64
        and value == value.strip()
        and value[0].isalnum()
        and all(character.isalnum() or character in "._-" for character in value)
    )


def _dependency_or_gate_control(component: str) -> bool:
    name = component.rsplit("/", 1)[-1]
    return (
        name
        in {
            ".coveragerc",
            ".ruff.toml",
            "cargo.lock",
            "cargo.toml",
            "conda-lock.yml",
            "conftest.py",
            "environment.yaml",
            "environment.yml",
            "go.mod",
            "go.sum",
            "mypy.ini",
            "package-lock.json",
            "package.json",
            "pipfile",
            "pipfile.lock",
            "pnpm-lock.yaml",
            "poetry.lock",
            "pyproject.toml",
            "pytest.ini",
            "ruff.toml",
            "setup.cfg",
            "setup.py",
            "tox.ini",
            "uv.lock",
            "yarn.lock",
        }
        or name.startswith("requirements")
        or name.startswith("constraints")
    )
