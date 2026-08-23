"""Provider registry and provider-neutral metadata contracts."""

from __future__ import annotations

from collections.abc import Callable, Mapping
from dataclasses import dataclass
from typing import Any

from jarvis.ai.models import ModelInfo, ProviderHealth
from jarvis.ai.providers.base import AIProvider

Provider = AIProvider
ProviderFactory = Callable[[Mapping[str, Any]], Provider]


@dataclass(frozen=True, slots=True)
class ProviderMetadata:
    provider_id: str
    display_name: str
    version: str
    local_only: bool = False


@dataclass(frozen=True, slots=True)
class ModelMetadata:
    model_id: str
    context_limit: int
    capabilities: frozenset[str] = frozenset()

    def __post_init__(self) -> None:
        if not self.model_id.strip() or self.context_limit <= 0:
            raise ValueError("Model metadata is invalid")


@dataclass(frozen=True, slots=True)
class ProviderDefinition:
    metadata: ProviderMetadata
    factory: ProviderFactory
    models: tuple[ModelMetadata, ...] = ()

    def __post_init__(self) -> None:
        if not self.metadata.provider_id.strip() or not callable(self.factory):
            raise ValueError("Provider definition is invalid")


class ProviderRegistry:
    """Resolve configured providers through data, not provider-specific branches."""

    def __init__(self, definitions: tuple[ProviderDefinition, ...] = ()) -> None:
        self._definitions: dict[str, ProviderDefinition] = {}
        for definition in definitions:
            self.register(definition)

    def register(self, definition: ProviderDefinition) -> None:
        provider_id = definition.metadata.provider_id.casefold()
        if provider_id in self._definitions:
            raise ValueError(f"Provider is already registered: {provider_id}")
        self._definitions[provider_id] = definition

    def definition(self, provider_id: str) -> ProviderDefinition:
        try:
            return self._definitions[provider_id.casefold()]
        except KeyError as error:
            raise KeyError(f"Unknown AI provider: {provider_id}") from error

    def provider_ids(self) -> tuple[str, ...]:
        return tuple(sorted(self._definitions))

    def create(self, provider_id: str, configuration: Mapping[str, Any]) -> Provider:
        return self.definition(provider_id).factory(configuration)

    async def health(self, provider_id: str, provider: Provider) -> ProviderHealth:
        self.definition(provider_id)
        return await provider.health_check()

    async def model(self, provider_id: str, provider: Provider) -> ModelMetadata:
        definition = self.definition(provider_id)
        info: ModelInfo = await provider.model_info()
        for model in definition.models:
            if model.model_id == info.model:
                return model
        return ModelMetadata(info.model, info.context_limit)
