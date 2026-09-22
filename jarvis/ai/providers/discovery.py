"""Bounded dynamic model discovery over the existing registry/knowledge owners."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import UTC, datetime

from jarvis.ai.knowledge import ModelKnowledgeService, ProviderCatalogSnapshot
from jarvis.ai.providers.base import IntelligenceProvider
from jarvis.ai.providers.registry import ModelMetadata, ProviderRegistry


@dataclass(frozen=True, slots=True)
class DiscoveryResult:
    provider_id: str
    discovered_model_ids: tuple[str, ...]
    registered_model_ids: tuple[str, ...]
    observed_at: datetime
    source: str


class ModelDiscoveryService:
    """Register exact provider observations without a Core model allow-list."""

    MAX_MODELS = 1_024

    def __init__(
        self, registry: ProviderRegistry, knowledge: ModelKnowledgeService | None = None
    ) -> None:
        if not isinstance(registry, ProviderRegistry):
            raise ValueError("Discovery registry is invalid")
        self._registry = registry
        self._knowledge = knowledge

    def register_snapshot(self, snapshot: ProviderCatalogSnapshot) -> DiscoveryResult:
        if not isinstance(snapshot, ProviderCatalogSnapshot):
            raise ValueError("Discovery snapshot is invalid")
        if len(snapshot.models) > self.MAX_MODELS:
            raise ValueError("Discovery snapshot exceeds model bound")
        models = tuple(item.metadata for item in snapshot.models)
        provider_key = snapshot.provider.provider_id.casefold()
        if (
            provider_key in self._registry.intelligence_provider_ids()
            and provider_key not in self._registry.provider_ids()
        ):
            self._registry.replace_intelligence_models(snapshot.provider.provider_id, models)
        else:
            self._registry.replace_models(snapshot.provider.provider_id, models)
        if self._knowledge is not None:
            self._knowledge.refresh(snapshot)
        return DiscoveryResult(
            snapshot.provider.provider_id,
            tuple(item.identity.model_id for item in snapshot.models),
            tuple(model.model_id for model in models),
            snapshot.observed_at,
            snapshot.source,
        )

    async def discover(
        self,
        provider_id: str,
        provider: IntelligenceProvider,
        *,
        source: str = "provider_discovery",
    ) -> DiscoveryResult:
        if not isinstance(provider, IntelligenceProvider):
            raise ValueError("Discovery provider is invalid")
        raw = await provider.discover_models()
        if not isinstance(raw, ProviderCatalogSnapshot):
            raise ValueError("Provider does not return a catalog snapshot")
        if raw.provider.provider_id.casefold() != provider_id.casefold():
            raise ValueError("Discovery provider identity does not match")
        snapshot = (
            raw
            if raw.source == source
            else ProviderCatalogSnapshot(
                raw.provider,
                raw.models,
                raw.observed_at,
                source,
                raw.available,
                raw.detail,
            )
        )
        return self.register_snapshot(snapshot)

    def register_unknown_model(
        self,
        provider_id: str,
        model_id: str,
        *,
        source: str = "provider_discovery",
        observed_at: datetime | None = None,
    ) -> DiscoveryResult:
        """Fixture/helper path proving a new ID needs no Core source edit."""

        if type(model_id) is not str or not model_id.strip() or len(model_id) > 256:
            raise ValueError("Discovered model ID is invalid")
        definition = self._registry.definition(provider_id)
        timestamp = observed_at or datetime.now(UTC)
        metadata = ModelMetadata(model_id, 1, source=source)
        from jarvis.ai.knowledge import ModelObservation, ProviderCatalogSnapshot, identity_for

        snapshot = ProviderCatalogSnapshot(
            definition.metadata,
            (ModelObservation(identity_for(provider_id, metadata), metadata, timestamp, source),),
            timestamp,
            source,
            True,
        )
        return self.register_snapshot(snapshot)
