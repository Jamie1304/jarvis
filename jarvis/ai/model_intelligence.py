"""Secret-safe Model Intelligence page projection over real runtime owners."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import UTC, datetime

from jarvis.ai.governance import PolicyEngine
from jarvis.ai.knowledge import ModelKnowledgeService
from jarvis.ai.providers.catalog import provider_manifest
from jarvis.ai.providers.intelligence import ModelPolicy, ProviderPackageManifest
from jarvis.ai.providers.registry import ModelMetadata, ProviderRegistry
from jarvis.ai.usability import ModelUsabilityEvidence


@dataclass(frozen=True, slots=True)
class ProviderIntelligenceRow:
    provider_id: str
    display_name: str
    locality: str
    package_lifecycle: str
    policy: str
    configured: bool
    model_count: int
    dynamic_discovery: bool
    support_status: str = "unknown"
    authentication: str = "unknown"
    connection_status: str = "unknown"


@dataclass(frozen=True, slots=True)
class ModelIntelligenceRow:
    provider_id: str
    model_id: str
    route_key: str
    lifecycle: str
    policy: str
    usability: str
    cost: str
    capabilities: tuple[str, ...]
    discovered_at: datetime | None
    endpoint: str = "unknown"
    region: str = "unknown"
    deployment: str = "unknown"
    inference_kind: str = "generative"
    learned_state: str = "unknown"


@dataclass(frozen=True, slots=True)
class ModelIntelligencePage:
    observed_at: datetime
    providers: tuple[ProviderIntelligenceRow, ...]
    models: tuple[ModelIntelligenceRow, ...]


class ModelIntelligenceProjection:
    """Build UI data from registry/policy/usability evidence, never mock data."""

    def __init__(
        self,
        registry: ProviderRegistry,
        policies: PolicyEngine | None = None,
        usability: tuple[ModelUsabilityEvidence, ...] = (),
        knowledge: ModelKnowledgeService | None = None,
    ) -> None:
        if not isinstance(registry, ProviderRegistry):
            raise ValueError("Model intelligence registry is invalid")
        if policies is not None and not isinstance(policies, PolicyEngine):
            raise ValueError("Model intelligence policy engine is invalid")
        if knowledge is not None and not isinstance(knowledge, ModelKnowledgeService):
            raise ValueError("Model intelligence knowledge service is invalid")
        self._registry = registry
        self._policies = policies
        self._knowledge = knowledge
        self._usability = {
            (item.provider_id.casefold(), item.model_id.casefold()): item
            for item in usability
            if item.provider_id is not None and item.model_id is not None
        }

    def page(self) -> ModelIntelligencePage:
        providers: list[ProviderIntelligenceRow] = []
        models: list[ModelIntelligenceRow] = []
        definitions = dict(self._registry.definitions())
        package_ids = {provider_id for provider_id, _ in self._registry.packages()}
        for provider_id in sorted((*package_ids, *definitions)):
            definition = definitions.get(provider_id)
            manifest = self._manifest_or_unknown(provider_id)
            provider_policy = (
                self._policies.store.provider_policy(provider_id).value
                if self._policies is not None
                else "enabled"
            )
            providers.append(
                ProviderIntelligenceRow(
                    provider_id,
                    definition.metadata.display_name
                    if definition is not None
                    else manifest.display_name,
                    definition.metadata.locality.value
                    if definition is not None
                    else manifest.locality.value,
                    manifest.lifecycle.value,
                    provider_policy,
                    definition is not None,
                    len(definition.models) if definition is not None else 0,
                    manifest.dynamic_model_discovery,
                    manifest.support_status.value,
                    manifest.authentication.value,
                    "configured" if definition is not None else "not_configured",
                )
            )
            if definition is not None:
                for metadata in definition.models:
                    models.append(self._model_row(provider_id, metadata))
        return ModelIntelligencePage(datetime.now(UTC), tuple(providers), tuple(models))

    def _model_row(self, provider_id: str, metadata: ModelMetadata) -> ModelIntelligenceRow:
        from jarvis.ai.knowledge import identity_for

        identity = identity_for(provider_id, metadata)
        policy = (
            self._policies.effective_policy(identity, metadata).value
            if self._policies is not None
            else ModelPolicy.AUTO_ALLOWED.value
        )
        evidence = self._usability.get((provider_id.casefold(), metadata.model_id.casefold()))
        return ModelIntelligenceRow(
            provider_id,
            metadata.model_id,
            identity.storage_key,
            metadata.lifecycle.value,
            policy,
            evidence.status.value if evidence is not None else "unknown",
            "known"
            if metadata.input_cost_per_million is not None
            and metadata.output_cost_per_million is not None
            else "cost_unknown",
            tuple(sorted(metadata.capabilities)),
            metadata.discovered_at,
            metadata.endpoint or "unknown",
            metadata.region or "unknown",
            metadata.deployment or "unknown",
            metadata.inference_kind or "generative",
            "unknown",
        )

    @staticmethod
    def _manifest_or_unknown(provider_id: str) -> ProviderPackageManifest:
        try:
            return provider_manifest(provider_id)
        except KeyError:
            from jarvis.ai.providers.intelligence import (
                IntelligenceKind,
                ProviderLifecycle,
                ProviderPackageManifest,
            )

            return ProviderPackageManifest(
                provider_id,
                provider_id,
                frozenset({IntelligenceKind.GENERATIVE}),
                lifecycle=ProviderLifecycle.UNKNOWN,
            )
