"""Data-only capability-gap and discovery records; none grants execution authority."""

from dataclasses import dataclass
from datetime import datetime
from enum import StrEnum

from jarvis.permissions.models import Permission, Risk


class DiscoverySource(StrEnum):
    WINDOWS_LOCAL = "windows_local"
    USB = "usb"
    BLUETOOTH_BLE = "bluetooth_ble"
    MDNS_DNS_SD = "mdns_dns_sd"
    SSDP = "ssdp"
    SAFE_ADVERTISEMENT = "safe_advertisement"
    INTERNAL_TOOL_CATALOG = "internal_tool_catalog"
    PLUGIN_CATALOG = "plugin_catalog"
    INTEGRATION_CATALOG = "integration_catalog"
    SOFTWARE_CATALOG = "software_catalog"
    CONTROLLED_WEB_RESEARCH = "controlled_web_research"


class ArchitectureFit(StrEnum):
    COMPATIBLE = "compatible"
    ADAPTABLE = "adaptable"
    INCOMPATIBLE = "incompatible"


class Testability(StrEnum):
    __test__ = False

    DETERMINISTIC = "deterministic"
    MOCKABLE = "mockable"
    MANUAL_ONLY = "manual_only"
    UNKNOWN = "unknown"


class MaintenanceStatus(StrEnum):
    ACTIVE = "active"
    MAINTAINED = "maintained"
    UNKNOWN = "unknown"
    UNMAINTAINED = "unmaintained"


class RecommendationClass(StrEnum):
    RECOMMENDED = "recommended"
    CAUTION = "caution"
    REJECTED = "rejected"


class SetupNeedKind(StrEnum):
    NONE = "none"
    INSTALL = "install"
    CREDENTIAL = "credential"
    CONFIGURATION = "configuration"
    USER_SETUP = "user_setup"


@dataclass(frozen=True, slots=True)
class DiscoveryEvidence:
    """Safe evidence metadata; never a command or instruction channel."""

    source_reference: str
    summary: str
    content_digest: str | None = None
    external_untrusted: bool = False


@dataclass(frozen=True, slots=True)
class CapabilityGap:
    desired_capability: str
    current_task: str
    missing_requirements: tuple[str, ...]
    known_alternatives: tuple[str, ...]
    risk: Risk
    evidence: tuple[DiscoveryEvidence, ...]

    def __post_init__(self) -> None:
        if not self.desired_capability.strip() or not self.current_task.strip():
            raise ValueError("Capability gaps require a desired capability and current task")
        if any("\x00" in value for value in (*self.missing_requirements, *self.known_alternatives)):
            raise ValueError("Capability gap labels cannot contain NUL characters")


@dataclass(frozen=True, slots=True)
class CandidateProvenance:
    source: DiscoverySource
    reference: str
    retrieved_at: datetime | None
    evidence: tuple[DiscoveryEvidence, ...]
    owner_verified: bool = False


@dataclass(frozen=True, slots=True)
class SetupNeed:
    kind: SetupNeedKind
    detail: str
    reversible: bool


@dataclass(frozen=True, slots=True)
class DiscoveryCandidate:
    """A prospective capability only; identity is not an install/execution request."""

    capability_provided: str
    source: DiscoverySource
    identity: str
    provenance: CandidateProvenance
    publisher_or_owner: str | None
    required_permissions: tuple[Permission, ...]
    setup_needs: tuple[SetupNeed, ...]
    architecture_fit: ArchitectureFit
    confidence: float
    testability: Testability
    maintenance_status: MaintenanceStatus

    def __post_init__(self) -> None:
        if (
            not self.capability_provided.strip()
            or not self.identity.strip()
            or "\x00" in self.identity
            or "\n" in self.identity
            or "\r" in self.identity
        ):
            raise ValueError("Discovery candidates require a bounded single-line identity")
        if self.source is not self.provenance.source:
            raise ValueError("Candidate source must match provenance source")
        if not 0.0 <= self.confidence <= 1.0:
            raise ValueError("Candidate confidence must be between zero and one")
        if any(not isinstance(permission, Permission) for permission in self.required_permissions):
            raise ValueError("Candidate permissions must be known granular permissions")


@dataclass(frozen=True, slots=True)
class EvaluationFactor:
    criterion: str
    score: int
    explanation: str


@dataclass(frozen=True, slots=True)
class CandidateEvaluation:
    candidate: DiscoveryCandidate
    classification: RecommendationClass
    score: int
    factors: tuple[EvaluationFactor, ...]
    selected_reason: str


@dataclass(frozen=True, slots=True)
class CapabilityRecommendation:
    gap: CapabilityGap
    evaluated_candidates: tuple[CandidateEvaluation, ...]


@dataclass(frozen=True, slots=True)
class ToolAdapterSpecification:
    """A future implementation proposal, deliberately not executable source code."""

    capability: str
    candidate_identity: str
    proposed_tool_id: str
    required_permissions: tuple[Permission, ...]
    provider_contract: tuple[str, ...]
    validation_requirements: tuple[str, ...]
    test_requirements: tuple[str, ...]
