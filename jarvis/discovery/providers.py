"""Provider-neutral, evidence-only discovery sources."""

from __future__ import annotations

import hashlib
from abc import ABC, abstractmethod
from dataclasses import dataclass

from jarvis.discovery.models import (
    ArchitectureFit,
    CandidateProvenance,
    CapabilityGap,
    DiscoveryCandidate,
    DiscoveryEvidence,
    DiscoverySource,
    MaintenanceStatus,
    Testability,
)
from jarvis.tools.registry import ToolRegistry


class DiscoveryProvider(ABC):
    """Find prospective candidates; implementations must not install or execute them."""

    @property
    @abstractmethod
    def source(self) -> DiscoverySource:
        """Return the provider's evidence source category."""

    @abstractmethod
    async def discover(self, gap: CapabilityGap) -> tuple[DiscoveryCandidate, ...]:
        """Return candidates relevant to the gap without performing host mutations."""


class StaticCatalogDiscoveryProvider(DiscoveryProvider):
    """Trusted-composition catalog for plugins, integrations, or software candidates."""

    def __init__(self, source: DiscoverySource, candidates: tuple[DiscoveryCandidate, ...]) -> None:
        if source is DiscoverySource.CONTROLLED_WEB_RESEARCH:
            raise ValueError("Use ResearchEvidenceDiscoveryProvider for web evidence")
        if any(candidate.source is not source for candidate in candidates):
            raise ValueError("Catalog candidates must match their provider source")
        self._source = source
        self._candidates = candidates

    @property
    def source(self) -> DiscoverySource:
        return self._source

    async def discover(self, gap: CapabilityGap) -> tuple[DiscoveryCandidate, ...]:
        requested = gap.desired_capability.casefold()
        return tuple(
            candidate
            for candidate in self._candidates
            if requested in candidate.capability_provided.casefold()
            or candidate.capability_provided.casefold() in requested
        )


class InternalToolCatalogProvider(DiscoveryProvider):
    """Read the trusted registered manifest catalog without dynamically importing tools."""

    def __init__(self, registry: ToolRegistry) -> None:
        self._registry = registry

    @property
    def source(self) -> DiscoverySource:
        return DiscoverySource.INTERNAL_TOOL_CATALOG

    async def discover(self, gap: CapabilityGap) -> tuple[DiscoveryCandidate, ...]:
        requested = gap.desired_capability.casefold()
        candidates: list[DiscoveryCandidate] = []
        for manifest in self._registry.manifests():
            tags = " ".join(manifest.capability_tags)
            if requested not in tags.casefold() and requested not in manifest.name.casefold():
                continue
            evidence = DiscoveryEvidence(
                source_reference=f"tool:{manifest.tool_id}",
                summary="Registered tool manifest from trusted local catalog",
            )
            candidates.append(
                DiscoveryCandidate(
                    capability_provided=manifest.name,
                    source=DiscoverySource.INTERNAL_TOOL_CATALOG,
                    identity=manifest.tool_id,
                    provenance=CandidateProvenance(
                        DiscoverySource.INTERNAL_TOOL_CATALOG,
                        f"tool:{manifest.tool_id}",
                        None,
                        (evidence,),
                        owner_verified=True,
                    ),
                    publisher_or_owner="JARVIS trusted composition",
                    required_permissions=tuple(sorted(manifest.declared_permissions)),
                    setup_needs=(),
                    architecture_fit=_fit_for_manifest(manifest.supported_platforms),
                    confidence=1.0,
                    testability=_testability_for_manifest(manifest.optional_dependencies),
                    maintenance_status=_maintenance_for_manifest(manifest.enabled),
                )
            )
        return tuple(candidates)


@dataclass(frozen=True, slots=True)
class ResearchEvidenceRecord:
    """Already-authorized external research with raw text isolated from recommendations."""

    candidate: DiscoveryCandidate
    reference: str
    untrusted_content: str


class ResearchEvidenceDiscoveryProvider(DiscoveryProvider):
    """Use externally gathered evidence without executing its text or fetching the web."""

    def __init__(self, records: tuple[ResearchEvidenceRecord, ...]) -> None:
        if any(
            record.candidate.source is not DiscoverySource.CONTROLLED_WEB_RESEARCH
            for record in records
        ):
            raise ValueError("Research records must be labelled as controlled web research")
        self._records = records

    @property
    def source(self) -> DiscoverySource:
        return DiscoverySource.CONTROLLED_WEB_RESEARCH

    async def discover(self, gap: CapabilityGap) -> tuple[DiscoveryCandidate, ...]:
        requested = gap.desired_capability.casefold()
        output: list[DiscoveryCandidate] = []
        for record in self._records:
            candidate = record.candidate
            if requested not in candidate.capability_provided.casefold():
                continue
            digest = hashlib.sha256(record.untrusted_content.encode("utf-8")).hexdigest()
            external_evidence = DiscoveryEvidence(
                source_reference=record.reference,
                summary="External research content retained only as untrusted evidence",
                content_digest=digest,
                external_untrusted=True,
            )
            output.append(
                DiscoveryCandidate(
                    capability_provided=candidate.capability_provided,
                    source=candidate.source,
                    identity=candidate.identity,
                    provenance=CandidateProvenance(
                        source=candidate.provenance.source,
                        reference=record.reference,
                        retrieved_at=candidate.provenance.retrieved_at,
                        evidence=(*candidate.provenance.evidence, external_evidence),
                        owner_verified=candidate.provenance.owner_verified,
                    ),
                    publisher_or_owner=candidate.publisher_or_owner,
                    required_permissions=candidate.required_permissions,
                    setup_needs=candidate.setup_needs,
                    architecture_fit=candidate.architecture_fit,
                    confidence=candidate.confidence,
                    testability=candidate.testability,
                    maintenance_status=candidate.maintenance_status,
                )
            )
        return tuple(output)


def _fit_for_manifest(platforms: frozenset[object]) -> ArchitectureFit:
    import sys

    from jarvis.tools.models import ToolPlatform

    current = (
        ToolPlatform.WINDOWS
        if sys.platform.startswith("win")
        else ToolPlatform.MACOS
        if sys.platform == "darwin"
        else ToolPlatform.LINUX
    )
    return ArchitectureFit.COMPATIBLE if current in platforms else ArchitectureFit.INCOMPATIBLE


def _testability_for_manifest(optional_dependencies: tuple[str, ...]) -> Testability:
    return Testability.MOCKABLE if optional_dependencies else Testability.DETERMINISTIC


def _maintenance_for_manifest(enabled: bool) -> MaintenanceStatus:
    return MaintenanceStatus.ACTIVE if enabled else MaintenanceStatus.UNKNOWN
