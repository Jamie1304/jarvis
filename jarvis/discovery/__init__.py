"""Advisory capability-gap discovery; discovery never authorizes or executes a candidate."""

from jarvis.discovery.models import (
    ArchitectureFit,
    CandidateEvaluation,
    CapabilityGap,
    CapabilityRecommendation,
    DiscoveryCandidate,
    DiscoveryEvidence,
    DiscoverySource,
    MaintenanceStatus,
    RecommendationClass,
    SetupNeed,
    SetupNeedKind,
    Testability,
    ToolAdapterSpecification,
)
from jarvis.discovery.providers import (
    DiscoveryProvider,
    InternalToolCatalogProvider,
    ResearchEvidenceDiscoveryProvider,
    ResearchEvidenceRecord,
    StaticCatalogDiscoveryProvider,
)
from jarvis.discovery.service import (
    CandidateEvaluator,
    CapabilityDiscoveryService,
    CapabilityGapDetector,
    ToolAdapterScaffolder,
)

__all__ = [
    "ArchitectureFit",
    "CandidateEvaluation",
    "CandidateEvaluator",
    "CapabilityDiscoveryService",
    "CapabilityGap",
    "CapabilityGapDetector",
    "CapabilityRecommendation",
    "DiscoveryCandidate",
    "DiscoveryEvidence",
    "DiscoveryProvider",
    "DiscoverySource",
    "InternalToolCatalogProvider",
    "MaintenanceStatus",
    "RecommendationClass",
    "ResearchEvidenceDiscoveryProvider",
    "ResearchEvidenceRecord",
    "SetupNeed",
    "SetupNeedKind",
    "StaticCatalogDiscoveryProvider",
    "Testability",
    "ToolAdapterScaffolder",
    "ToolAdapterSpecification",
]
