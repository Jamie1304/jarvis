"""Provider registry and provider-neutral metadata contracts."""

from __future__ import annotations

import math
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from enum import StrEnum
from typing import Any

from jarvis.ai.models import EvidenceRecord, ModelInfo, ModelRole, ProviderHealth
from jarvis.ai.providers.base import AIProvider
from jarvis.speech.stt import SttProvider
from jarvis.speech.tts import TtsProvider

Provider = AIProvider
ProviderFactory = Callable[[Mapping[str, Any]], Provider]
VoiceProvider = SttProvider | TtsProvider
VoiceProviderFactory = Callable[[Mapping[str, Any]], VoiceProvider]


class VoiceProviderKind(StrEnum):
    STT = "stt"
    TTS = "tts"


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
    roles: frozenset[ModelRole] = frozenset()
    family: str = ""
    version: str = ""
    quantization: str = ""
    runtime: str = ""
    source: str = ""
    modalities: frozenset[str] = frozenset()
    storage_bytes: int | None = None
    ram_bytes: int | None = None
    vram_bytes: int | None = None
    license: str = ""
    compatibility: frozenset[str] = frozenset()
    evidence: tuple[EvidenceRecord, ...] = ()
    max_concurrency: int | None = None
    quality_score: float | None = None
    latency_ms: float | None = None
    input_cost_per_million: float | None = None
    output_cost_per_million: float | None = None

    def __post_init__(self) -> None:
        if (
            type(self.model_id) is not str
            or not self.model_id.strip()
            or type(self.context_limit) is not int
            or self.context_limit <= 0
        ):
            raise ValueError("Model metadata is invalid")
        if type(self.capabilities) is not frozenset or any(
            type(value) is not str or not value.strip() or "\x00" in value
            for value in self.capabilities
        ):
            raise ValueError("Model capabilities are invalid")
        if type(self.roles) is not frozenset or any(
            not isinstance(value, ModelRole) for value in self.roles
        ):
            raise ValueError("Model roles are invalid")
        text_fields: tuple[tuple[str, str, int], ...] = (
            ("Model family", self.family, 256),
            ("Model version", self.version, 128),
            ("Model quantization", self.quantization, 128),
            ("Model runtime", self.runtime, 128),
            ("Model source", self.source, 512),
            ("Model license", self.license, 256),
        )
        for name, value, limit in text_fields:
            if type(value) is not str or len(value) > limit or "\x00" in value:
                raise ValueError(f"{name} is invalid")
        if type(self.modalities) is not frozenset or any(
            type(value) is not str or not value.strip() or "\x00" in value
            for value in self.modalities
        ):
            raise ValueError("Model modalities are invalid")
        if type(self.compatibility) is not frozenset or any(
            type(value) is not str or not value.strip() or "\x00" in value
            for value in self.compatibility
        ):
            raise ValueError("Model compatibility metadata is invalid")
        resource_fields: tuple[tuple[str, int | None], ...] = (
            ("storage", self.storage_bytes),
            ("RAM", self.ram_bytes),
            ("VRAM", self.vram_bytes),
        )
        for field_name, field_value in resource_fields:
            if field_value is not None and (type(field_value) is not int or field_value < 0):
                raise ValueError(f"Model {field_name} requirement is invalid")
        if self.max_concurrency is not None and (
            type(self.max_concurrency) is not int or self.max_concurrency <= 0
        ):
            raise ValueError("Model concurrency requirement is invalid")
        for metric_name, metric_value in (
            ("quality score", self.quality_score),
            ("latency", self.latency_ms),
            ("input token cost", self.input_cost_per_million),
            ("output token cost", self.output_cost_per_million),
        ):
            if metric_value is not None and (
                type(metric_value) not in {int, float}
                or not math.isfinite(metric_value)
                or metric_value < 0
            ):
                raise ValueError(f"Model {metric_name} metadata is invalid")
        if type(self.evidence) is not tuple or any(
            not isinstance(value, EvidenceRecord) for value in self.evidence
        ):
            raise ValueError("Model evidence is invalid")


@dataclass(frozen=True, slots=True)
class ProviderDefinition:
    metadata: ProviderMetadata
    factory: ProviderFactory
    models: tuple[ModelMetadata, ...] = ()

    def __post_init__(self) -> None:
        if not self.metadata.provider_id.strip() or not callable(self.factory):
            raise ValueError("Provider definition is invalid")


@dataclass(frozen=True, slots=True)
class VoiceProviderDefinition:
    """Provider-neutral STT/TTS registration; no vendor is special-cased."""

    kind: VoiceProviderKind
    metadata: ProviderMetadata
    factory: VoiceProviderFactory
    models: tuple[ModelMetadata, ...] = ()

    def __post_init__(self) -> None:
        if not isinstance(self.kind, VoiceProviderKind):
            raise ValueError("Voice provider kind is invalid")
        if not self.metadata.provider_id.strip() or not callable(self.factory):
            raise ValueError("Voice provider definition is invalid")
        if type(self.models) is not tuple or any(
            not isinstance(model, ModelMetadata) for model in self.models
        ):
            raise ValueError("Voice provider models are invalid")


class ProviderRegistry:
    """Resolve configured providers through data, not provider-specific branches."""

    def __init__(self, definitions: tuple[ProviderDefinition, ...] = ()) -> None:
        self._definitions: dict[str, ProviderDefinition] = {}
        self._voice_definitions: dict[VoiceProviderKind, dict[str, VoiceProviderDefinition]] = {
            kind: {} for kind in VoiceProviderKind
        }
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

    def definitions(self) -> tuple[tuple[str, ProviderDefinition], ...]:
        """Return deterministic provider definitions for routing metadata."""

        return tuple(sorted(self._definitions.items()))

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

    def register_voice(self, definition: VoiceProviderDefinition) -> None:
        provider_id = definition.metadata.provider_id.casefold()
        definitions = self._voice_definitions[definition.kind]
        if provider_id in definitions:
            raise ValueError(f"Voice provider is already registered: {provider_id}")
        definitions[provider_id] = definition

    def voice_provider_ids(self, kind: VoiceProviderKind) -> tuple[str, ...]:
        if not isinstance(kind, VoiceProviderKind):
            raise ValueError("Voice provider kind is invalid")
        return tuple(sorted(self._voice_definitions[kind]))

    def voice_definitions(
        self, kind: VoiceProviderKind
    ) -> tuple[tuple[str, VoiceProviderDefinition], ...]:
        if not isinstance(kind, VoiceProviderKind):
            raise ValueError("Voice provider kind is invalid")
        return tuple(sorted(self._voice_definitions[kind].items()))

    def voice_definition(
        self, kind: VoiceProviderKind, provider_id: str
    ) -> VoiceProviderDefinition:
        if not isinstance(kind, VoiceProviderKind):
            raise ValueError("Voice provider kind is invalid")
        try:
            return self._voice_definitions[kind][provider_id.casefold()]
        except (KeyError, AttributeError) as error:
            raise KeyError(f"Unknown {kind.value} provider: {provider_id}") from error

    def create_voice(
        self, kind: VoiceProviderKind, provider_id: str, configuration: Mapping[str, Any]
    ) -> VoiceProvider:
        provider = self.voice_definition(kind, provider_id).factory(configuration)
        if kind is VoiceProviderKind.STT and not isinstance(provider, SttProvider):
            raise TypeError("STT factory returned a non-STT provider")
        if kind is VoiceProviderKind.TTS and not isinstance(provider, TtsProvider):
            raise TypeError("TTS factory returned a non-TTS provider")
        return provider
