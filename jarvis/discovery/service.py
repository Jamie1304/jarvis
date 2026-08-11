"""Explainable capability-gap detection, candidate evaluation, and data-only scaffolding."""

import asyncio
from dataclasses import dataclass

from jarvis.discovery.models import (
    ArchitectureFit,
    CandidateEvaluation,
    CapabilityGap,
    CapabilityRecommendation,
    DiscoveryCandidate,
    EvaluationFactor,
    MaintenanceStatus,
    RecommendationClass,
    SetupNeedKind,
    Testability,
    ToolAdapterSpecification,
)
from jarvis.discovery.providers import DiscoveryProvider
from jarvis.permissions.models import Permission


class CapabilityGapDetector:
    """Create a typed gap only when trusted available capabilities do not satisfy a request."""

    def __init__(self, available_capabilities: frozenset[str]) -> None:
        self._available = frozenset(item.casefold() for item in available_capabilities)

    def detect(self, gap: CapabilityGap) -> CapabilityGap | None:
        desired = gap.desired_capability.casefold()
        if any(desired in capability or capability in desired for capability in self._available):
            return None
        return gap


class CandidateEvaluator:
    """Rank candidate evidence without turning a score into authorization."""

    def evaluate(self, candidate: DiscoveryCandidate) -> CandidateEvaluation:
        factors = (
            EvaluationFactor(
                "functional_fit",
                round(candidate.confidence * 100),
                "Provider confidence for the requested capability",
            ),
            EvaluationFactor(
                "trust_source_quality",
                self._trust_score(candidate),
                self._trust_reason(candidate),
            ),
            EvaluationFactor(
                "required_privileges",
                self._privilege_score(candidate),
                self._privilege_reason(candidate),
            ),
            EvaluationFactor(
                "maintenance_risk",
                self._maintenance_score(candidate),
                f"Maintenance status is {candidate.maintenance_status.value}",
            ),
            EvaluationFactor(
                "compatibility",
                self._compatibility_score(candidate),
                f"Architecture fit is {candidate.architecture_fit.value}",
            ),
            EvaluationFactor(
                "reversibility",
                self._reversibility_score(candidate),
                "Setup requirements are evaluated independently from authorization",
            ),
            EvaluationFactor(
                "testability",
                self._testability_score(candidate),
                f"Testability is {candidate.testability.value}",
            ),
        )
        scores = {factor.criterion: factor.score for factor in factors}
        score = round(
            scores["functional_fit"] * 0.30
            + scores["trust_source_quality"] * 0.20
            + scores["required_privileges"] * 0.15
            + scores["maintenance_risk"] * 0.10
            + scores["compatibility"] * 0.15
            + scores["reversibility"] * 0.05
            + scores["testability"] * 0.05
        )
        if (
            candidate.architecture_fit is ArchitectureFit.INCOMPATIBLE
            or scores["required_privileges"] == 0
        ):
            classification = RecommendationClass.REJECTED
        elif candidate.source.value == "controlled_web_research":
            classification = RecommendationClass.CAUTION
        elif score >= 75:
            classification = RecommendationClass.RECOMMENDED
        else:
            classification = RecommendationClass.CAUTION
        reason = (
            "Compatible candidate with explainable evidence; user/policy decision still required"
            if classification is RecommendationClass.RECOMMENDED
            else "Candidate is advisory only and requires explicit user/policy review"
            if classification is RecommendationClass.CAUTION
            else "Candidate is incompatible or requires excessive privileges"
        )
        return CandidateEvaluation(candidate, classification, score, factors, reason)

    @staticmethod
    def _trust_score(candidate: DiscoveryCandidate) -> int:
        base = {
            "internal_tool_catalog": 100,
            "plugin_catalog": 75,
            "integration_catalog": 75,
            "software_catalog": 70,
            "controlled_web_research": 30,
        }[candidate.source.value]
        return min(100, base + (10 if candidate.provenance.owner_verified else 0))

    @staticmethod
    def _trust_reason(candidate: DiscoveryCandidate) -> str:
        return (
            f"Source is {candidate.source.value}; provenance verification is "
            f"{str(candidate.provenance.owner_verified).lower()}"
        )

    @staticmethod
    def _privilege_score(candidate: DiscoveryCandidate) -> int:
        permissions = set(candidate.required_permissions)
        if permissions & {Permission.SYSTEM_POWER, Permission.CODE_MODIFY} or len(permissions) > 2:
            return 0
        if Permission.APPLICATION_INSTALL in permissions:
            return 25
        if permissions:
            return 60
        return 100

    @staticmethod
    def _privilege_reason(candidate: DiscoveryCandidate) -> str:
        if not candidate.required_permissions:
            return "No additional privileged JARVIS capability is proposed"
        return "Proposed permissions remain subject to a separate broker/policy decision"

    @staticmethod
    def _maintenance_score(candidate: DiscoveryCandidate) -> int:
        return {
            MaintenanceStatus.ACTIVE: 100,
            MaintenanceStatus.MAINTAINED: 80,
            MaintenanceStatus.UNKNOWN: 50,
            MaintenanceStatus.UNMAINTAINED: 10,
        }[candidate.maintenance_status]

    @staticmethod
    def _compatibility_score(candidate: DiscoveryCandidate) -> int:
        return {
            ArchitectureFit.COMPATIBLE: 100,
            ArchitectureFit.ADAPTABLE: 60,
            ArchitectureFit.INCOMPATIBLE: 0,
        }[candidate.architecture_fit]

    @staticmethod
    def _reversibility_score(candidate: DiscoveryCandidate) -> int:
        if not candidate.setup_needs:
            return 100
        if any(not need.reversible for need in candidate.setup_needs):
            return 10
        if any(need.kind is SetupNeedKind.INSTALL for need in candidate.setup_needs):
            return 50
        return 75

    @staticmethod
    def _testability_score(candidate: DiscoveryCandidate) -> int:
        return {
            Testability.DETERMINISTIC: 100,
            Testability.MOCKABLE: 85,
            Testability.MANUAL_ONLY: 45,
            Testability.UNKNOWN: 25,
        }[candidate.testability]


@dataclass(slots=True)
class CapabilityDiscoveryService:
    providers: tuple[DiscoveryProvider, ...]
    evaluator: CandidateEvaluator

    async def recommend(self, gap: CapabilityGap) -> CapabilityRecommendation:
        """Collect evidence in parallel and return a ranking with no side effect beyond reads."""

        discovered = await asyncio.gather(*(provider.discover(gap) for provider in self.providers))
        unique: dict[tuple[str, str], DiscoveryCandidate] = {}
        for candidates in discovered:
            for candidate in candidates:
                unique.setdefault((candidate.source.value, candidate.identity), candidate)
        evaluated = tuple(self.evaluator.evaluate(candidate) for candidate in unique.values())
        ranked = tuple(
            sorted(
                evaluated,
                key=lambda item: (
                    -item.score,
                    item.candidate.source.value,
                    item.candidate.identity,
                ),
            )
        )
        return CapabilityRecommendation(gap, ranked)


class ToolAdapterScaffolder:
    """Generate an inspectable specification only; source generation/execution is forbidden."""

    def propose(self, evaluation: CandidateEvaluation) -> ToolAdapterSpecification | None:
        if evaluation.classification is RecommendationClass.REJECTED:
            return None
        candidate = evaluation.candidate
        tool_id = _tool_id(candidate.capability_provided, candidate.identity)
        return ToolAdapterSpecification(
            capability=candidate.capability_provided,
            candidate_identity=candidate.identity,
            proposed_tool_id=tool_id,
            required_permissions=candidate.required_permissions,
            provider_contract=(
                "Provider interface must be injected by trusted composition",
                "No generated source may be imported or executed dynamically",
            ),
            validation_requirements=(
                "Strict typed input and output schemas",
                "Trusted action descriptor for every privileged operation",
                "Explicit PermissionBroker policy and approval review",
            ),
            test_requirements=(
                "Fake-provider success and failure coverage",
                "Permission denial before provider invocation",
                "No automatic installation, setup, or execution",
            ),
        )


def _tool_id(capability: str, identity: str) -> str:
    tokens = "".join(
        character if character.isalnum() else "-" for character in capability.casefold()
    )
    compact = "-".join(part for part in tokens.split("-") if part)[:48] or "capability"
    suffix = "".join(character for character in identity.casefold() if character.isalnum())[:12]
    return f"proposed.{compact}.{suffix or 'candidate'}"
