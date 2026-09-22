"""Secret-safe Model Intelligence page projection over real runtime owners."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import UTC, datetime

from jarvis.ai.governance import PolicyEngine
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
    ) -> None:
        if not isinstance(registry, ProviderRegistry):
            raise ValueError("Model intelligence registry is invalid")
        if policies is not None and not isinstance(policies, PolicyEngine):
            raise ValueError("Model intelligence policy engine is invalid")
        self._registry = registry
        self._policies = policies
        self._usability = {
            (item.provider_id.casefold(), item.model_id.casefold()): item
            for item in usability
            if item.provider_id is not None and item.model_id is not None
        }

    def page(self) -> ModelIntelligencePage:
        providers: list[ProviderIntelligenceRow] = []
        models: list[ModelIntelligenceRow] = []
        for provider_id, definition in self._registry.definitions():
            manifest = self._manifest_or_unknown(provider_id)
            provider_policy = (
                self._policies.store.provider_policy(provider_id).value
                if self._policies is not None
                else "enabled"
            )
            providers.append(
                ProviderIntelligenceRow(
                    provider_id,
                    definition.metadata.display_name,
                    definition.metadata.locality.value,
                    manifest.lifecycle.value,
                    provider_policy,
                    True,
                    len(definition.models),
                    manifest.dynamic_model_discovery,
                )
            )
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
