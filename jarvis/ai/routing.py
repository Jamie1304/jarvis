"""Provider-neutral inference and voice routing under explicit resource policy."""

from __future__ import annotations

import math
from collections.abc import Mapping
from dataclasses import dataclass, replace
from datetime import datetime
from enum import StrEnum

from jarvis.ai.models import ModelRole
from jarvis.ai.providers.registry import (
    ModelMetadata,
    ProviderMetadata,
    ProviderRegistry,
    VoiceProviderKind,
)
from jarvis.hardware import FitStatus, HardwareProfile
from jarvis.resources import (
    ResourceBudget,
    ResourceDecision,
    ResourceDecisionStatus,
    ResourceGovernor,
    ResourcePriority,
)
from jarvis.speech.stt import AudioData, SttProvider, Transcription
from jarvis.speech.tts import TextToSpeechService, TtsProvider


class RoutingPolicy(StrEnum):
    LOCAL_ONLY = "local_only"
    PREFER_LOCAL = "prefer_local"
    QUALITY_FIRST = "quality_first"
    SPEED_FIRST = "speed_first"
    LOWEST_COST = "lowest_cost"
    BALANCED = "balanced"
    PRIVACY_STRICT = "privacy_strict"


class RouteStatus(StrEnum):
    SELECTED = "selected"
    NO_LLM = "no_llm"
    UNAVAILABLE = "unavailable"
    UNKNOWN = "unknown"


@dataclass(frozen=True, slots=True)
class RouteBenchmark:
    provider_id: str
    model_id: str
    measured_at: datetime
    quality_score: float | None = None
    latency_ms: float | None = None
    input_cost_per_million: float | None = None
    output_cost_per_million: float | None = None
    throughput: float | None = None

    def __post_init__(self) -> None:
        for value in (self.provider_id, self.model_id):
            if type(value) is not str or not value.strip() or len(value) > 256:
                raise ValueError("Benchmark identity is invalid")
        if self.measured_at.tzinfo is None:
            raise ValueError("Benchmark timestamp must be timezone-aware")
        for metric_name, metric_value in (
            ("quality", self.quality_score),
            ("latency", self.latency_ms),
            ("input cost", self.input_cost_per_million),
            ("output cost", self.output_cost_per_million),
            ("throughput", self.throughput),
        ):
            if metric_value is not None and (
                type(metric_value) not in {int, float}
                or not math.isfinite(metric_value)
                or metric_value < 0
            ):
                raise ValueError(f"Benchmark {metric_name} is invalid")


@dataclass(frozen=True, slots=True)
class ProviderHealthSnapshot:
    provider_id: str
    available: bool
    detail: str = ""

    def __post_init__(self) -> None:
        if type(self.provider_id) is not str or not self.provider_id.strip():
            raise ValueError("Provider health identity is invalid")
        if type(self.available) is not bool or type(self.detail) is not str:
            raise ValueError("Provider health is invalid")


@dataclass(frozen=True, slots=True)
class RouteRequest:
    task: str
    profile: str
    role: ModelRole = ModelRole.GENERAL
    modality: str = "text"
    complexity: str = "medium"
    classification: str = "internal"
    context_tokens: int = 0
    requires_tools: bool = False
    requires_structured_output: bool = False
    latency_budget_ms: float | None = None
    resource_state: HardwareProfile | None = None
    concurrency: int = 1
    policy: RoutingPolicy = RoutingPolicy.BALANCED
    preferred_provider_id: str | None = None
    allow_no_llm: bool = False
    no_llm: bool = False
    benchmarks: tuple[RouteBenchmark, ...] = ()
    provider_health: tuple[ProviderHealthSnapshot, ...] = ()
    priority: ResourcePriority = ResourcePriority.USER_REQUESTED

    def __post_init__(self) -> None:
        for name, value, limit in (
            ("task", self.task, 4_000),
            ("profile", self.profile, 128),
            ("modality", self.modality, 64),
            ("complexity", self.complexity, 64),
            ("classification", self.classification, 64),
        ):
            if type(value) is not str or not value.strip() or len(value) > limit or "\x00" in value:
                raise ValueError(f"Route {name} is invalid")
        if (
            type(self.role) is not ModelRole
            or type(self.context_tokens) is not int
            or not 0 <= self.context_tokens <= 2_000_000
        ):
            raise ValueError("Route context is invalid")
        if type(self.concurrency) is not int or not 1 <= self.concurrency <= 64:
            raise ValueError("Route concurrency is invalid")
        if not isinstance(self.policy, RoutingPolicy):
            raise ValueError("Route policy is invalid")
        for flag_name, flag_value in (
            ("tools", self.requires_tools),
            ("structured output", self.requires_structured_output),
            ("no LLM", self.no_llm),
            ("allow no LLM", self.allow_no_llm),
        ):
            if type(flag_value) is not bool:
                raise ValueError(f"Route {flag_name} flag is invalid")
        if self.latency_budget_ms is not None and (
            type(self.latency_budget_ms) not in {int, float}
            or not math.isfinite(self.latency_budget_ms)
            or self.latency_budget_ms <= 0
        ):
            raise ValueError("Route latency budget is invalid")
        if self.preferred_provider_id is not None and (
            type(self.preferred_provider_id) is not str or not self.preferred_provider_id.strip()
        ):
            raise ValueError("Preferred provider is invalid")
        if type(self.benchmarks) is not tuple or any(
            not isinstance(item, RouteBenchmark) for item in self.benchmarks
        ):
            raise ValueError("Route benchmarks are invalid")
        if type(self.provider_health) is not tuple or any(
            not isinstance(item, ProviderHealthSnapshot) for item in self.provider_health
        ):
            raise ValueError("Route health snapshots are invalid")
        if not isinstance(self.priority, ResourcePriority):
            raise ValueError("Route resource priority is invalid")


@dataclass(frozen=True, slots=True)
class RouteCandidate:
    provider_id: str
    model_id: str
    provider: ProviderMetadata
    model: ModelMetadata
    local: bool
    voice_kind: VoiceProviderKind | None = None
    benchmark: RouteBenchmark | None = None

    @property
    def quality(self) -> float | None:
        if self.benchmark is not None and self.benchmark.quality_score is not None:
            return self.benchmark.quality_score
        return self.model.quality_score

    @property
    def latency(self) -> float | None:
        if self.benchmark is not None and self.benchmark.latency_ms is not None:
            return self.benchmark.latency_ms
        return self.model.latency_ms

    @property
    def cost(self) -> float | None:
        input_cost = (
            self.benchmark.input_cost_per_million
            if self.benchmark is not None and self.benchmark.input_cost_per_million is not None
            else self.model.input_cost_per_million
        )
        output_cost = (
            self.benchmark.output_cost_per_million
            if self.benchmark is not None and self.benchmark.output_cost_per_million is not None
            else self.model.output_cost_per_million
        )
        return None if input_cost is None or output_cost is None else input_cost + output_cost


@dataclass(frozen=True, slots=True)
class RouteDecision:
    status: RouteStatus
    primary: RouteCandidate | None
    fallbacks: tuple[RouteCandidate, ...] = ()
    reasons: tuple[str, ...] = ()
    resource_decision: ResourceDecision | None = None


class ProviderRouter:
    """Select configured providers without provider-specific conditionals."""

    def __init__(
        self, registry: ProviderRegistry, resource_governor: ResourceGovernor | None = None
    ) -> None:
        self._registry = registry
        self._resource_governor = resource_governor

    def route(self, request: RouteRequest) -> RouteDecision:
        if not isinstance(request, RouteRequest):
            raise ValueError("Route request is malformed")
        if request.no_llm:
            return self._no_llm(request, "caller disabled model inference")
        request, resource_decision = self._resource_gate(request)
        if resource_decision is not None and not resource_decision.allowed:
            if request.allow_no_llm:
                return self._no_llm(
                    request, resource_decision.reason, resource_decision=resource_decision
                )
            status = (
                RouteStatus.UNKNOWN
                if resource_decision.status is ResourceDecisionStatus.DEFER
                else RouteStatus.UNAVAILABLE
            )
            return RouteDecision(status, None, (), (resource_decision.reason,), resource_decision)
        candidates = [
            RouteCandidate(
                provider_id,
                model.model_id,
                definition.metadata,
                model,
                definition.metadata.local_only,
            )
            for provider_id, definition in self._registry.definitions()
            for model in definition.models
        ]
        return self._select(candidates, request, resource_decision)

    def route_voice(self, kind: VoiceProviderKind, request: RouteRequest) -> RouteDecision:
        if not isinstance(kind, VoiceProviderKind):
            raise ValueError("Voice provider kind is invalid")
        if request.no_llm:
            return self._no_llm(request, "caller disabled voice inference")
        request, resource_decision = self._resource_gate(request)
        if resource_decision is not None and not resource_decision.allowed:
            if request.allow_no_llm:
                return self._no_llm(
                    request, resource_decision.reason, resource_decision=resource_decision
                )
            status = (
                RouteStatus.UNKNOWN
                if resource_decision.status is ResourceDecisionStatus.DEFER
                else RouteStatus.UNAVAILABLE
            )
            return RouteDecision(status, None, (), (resource_decision.reason,), resource_decision)
        candidates = [
            RouteCandidate(
                provider_id,
                model.model_id,
                definition.metadata,
                model,
                definition.metadata.local_only,
                kind,
            )
            for provider_id, definition in self._registry.voice_definitions(kind)
            for model in definition.models
        ]
        return self._select(candidates, request, resource_decision)

    def _resource_gate(self, request: RouteRequest) -> tuple[RouteRequest, ResourceDecision | None]:
        if self._resource_governor is None:
            return request, None
        decision = self._resource_governor.decide(
            f"model-router.{request.profile}",
            request.priority,
            ResourceBudget(concurrency=request.concurrency, duration_seconds=120),
        )
        if not decision.allowed:
            return request, decision
        if decision.effective_budget.concurrency != request.concurrency:
            request = replace(request, concurrency=decision.effective_budget.concurrency)
        return request, decision

    def create_voice_provider(
        self, decision: RouteDecision, configuration: Mapping[str, object]
    ) -> SttProvider | TtsProvider:
        if decision.primary is None or decision.primary.voice_kind is None:
            raise ValueError("A selected voice route is required")
        return self._registry.create_voice(
            decision.primary.voice_kind, decision.primary.provider_id, configuration
        )

    def create_stt_provider(
        self, decision: RouteDecision, configurations: Mapping[str, Mapping[str, object]]
    ) -> SttProvider | None:
        candidates = self._voice_candidates(decision, VoiceProviderKind.STT)
        providers: list[SttProvider] = []
        for candidate in candidates:
            provider = self._registry.create_voice(
                VoiceProviderKind.STT,
                candidate.provider_id,
                configurations.get(candidate.provider_id, {}),
            )
            if not isinstance(provider, SttProvider):
                raise TypeError("STT route returned a non-STT provider")
            providers.append(provider)
        if not providers:
            return None
        if len(providers) == 1:
            return providers[0]
        return FailoverSttProvider(tuple(providers))

    def create_tts_service(
        self,
        decision: RouteDecision,
        configurations: Mapping[str, Mapping[str, object]],
        *,
        enabled: bool,
    ) -> TextToSpeechService | None:
        candidates = self._voice_candidates(decision, VoiceProviderKind.TTS)
        providers: list[TtsProvider] = []
        for candidate in candidates:
            provider = self._registry.create_voice(
                VoiceProviderKind.TTS,
                candidate.provider_id,
                configurations.get(candidate.provider_id, {}),
            )
            if not isinstance(provider, TtsProvider):
                raise TypeError("TTS route returned a non-TTS provider")
            providers.append(provider)
        if not providers:
            return None
        primary, *fallbacks = providers
        return TextToSpeechService(primary, enabled=enabled, fallbacks=tuple(fallbacks))

    @staticmethod
    def _voice_candidates(
        decision: RouteDecision, kind: VoiceProviderKind
    ) -> tuple[RouteCandidate, ...]:
        candidates = (() if decision.primary is None else (decision.primary,)) + decision.fallbacks
        return tuple(candidate for candidate in candidates if candidate.voice_kind is kind)

    def _select(
        self,
        candidates: list[RouteCandidate],
        request: RouteRequest,
        resource_decision: ResourceDecision | None = None,
    ) -> RouteDecision:
        viable: list[RouteCandidate] = []
        unknown: list[str] = []
        rejected: list[str] = []
        benchmarks = {
            (item.provider_id.casefold(), item.model_id): item for item in request.benchmarks
        }
        health = {item.provider_id.casefold(): item for item in request.provider_health}
        for candidate in candidates:
            candidate = RouteCandidate(
                candidate.provider_id,
                candidate.model_id,
                candidate.provider,
                candidate.model,
                candidate.local,
                candidate.voice_kind,
                benchmarks.get((candidate.provider_id.casefold(), candidate.model_id)),
            )
            reason, is_unknown = self._eligibility(candidate, request, health)
            if reason is None:
                viable.append(candidate)
            elif is_unknown:
                unknown.append(f"{candidate.provider_id}/{candidate.model_id}: {reason}")
            else:
                rejected.append(f"{candidate.provider_id}/{candidate.model_id}: {reason}")
        if viable:
            viable.sort(key=lambda item: self._sort_key(item, request))
            if resource_decision is not None and resource_decision.choose_smaller_model:
                viable.sort(
                    key=lambda item: (self._resource_size(item), self._sort_key(item, request))
                )
            return RouteDecision(
                RouteStatus.SELECTED,
                viable[0],
                tuple(viable[1:]),
                (),
                resource_decision,
            )
        if request.allow_no_llm:
            return self._no_llm(request, *(unknown or rejected or ("no compatible provider",)))
        return RouteDecision(
            RouteStatus.UNKNOWN if unknown else RouteStatus.UNAVAILABLE,
            None,
            (),
            tuple((unknown or rejected or ["no compatible provider"])[:8]),
            resource_decision,
        )

    @staticmethod
    def _resource_size(candidate: RouteCandidate) -> tuple[float, float, float]:
        return (
            candidate.model.ram_bytes if candidate.model.ram_bytes is not None else math.inf,
            candidate.model.vram_bytes if candidate.model.vram_bytes is not None else math.inf,
            candidate.model.storage_bytes
            if candidate.model.storage_bytes is not None
            else math.inf,
        )

    def _eligibility(
        self,
        candidate: RouteCandidate,
        request: RouteRequest,
        health: dict[str, ProviderHealthSnapshot],
    ) -> tuple[str | None, bool]:
        model = candidate.model
        if request.policy in {RoutingPolicy.LOCAL_ONLY, RoutingPolicy.PRIVACY_STRICT} or (
            request.classification.casefold() in {"secret", "restricted"} and not candidate.local
        ):
            if not candidate.local:
                return "policy requires a local provider", False
        status = health.get(candidate.provider_id.casefold())
        if status is not None and not status.available:
            return "provider health is unavailable", False
        if model.roles and request.role not in model.roles:
            return "model role does not match", False
        if model.modalities and request.modality.casefold() not in {
            value.casefold() for value in model.modalities
        }:
            return "model modality does not match", False
        if request.context_tokens > model.context_limit:
            return "context exceeds model limit", False
        if request.requires_tools and not (
            ModelRole.TOOL_USE in model.roles or "tool_use" in model.capabilities
        ):
            return "structured tool use is not declared", False
        if request.requires_structured_output and "structured_output" not in model.capabilities:
            return "structured output is not declared", False
        if model.max_concurrency is not None and request.concurrency > model.max_concurrency:
            return "model concurrency limit exceeded", False
        if request.resource_state is None and any(
            value is not None for value in (model.storage_bytes, model.ram_bytes, model.vram_bytes)
        ):
            return "hardware resource state is unknown", True
        if request.resource_state is not None:
            fit = _resource_fit(model, request.resource_state, request.concurrency)
            if fit is FitStatus.INCOMPATIBLE:
                return "measured resource limit exceeded", False
            if fit is FitStatus.UNKNOWN:
                return "required hardware capacity is unmeasured", True
        latency = candidate.latency
        if request.latency_budget_ms is not None:
            if latency is None:
                return "latency benchmark is unknown", True
            if latency > request.latency_budget_ms:
                return "latency budget exceeded", False
        return None, False

    @staticmethod
    def _sort_key(candidate: RouteCandidate, request: RouteRequest) -> tuple[float, ...]:
        preferred = (
            0.0
            if request.preferred_provider_id
            and candidate.provider_id.casefold() == request.preferred_provider_id.casefold()
            else 1.0
        )
        local = 0.0 if candidate.local else 1.0
        quality = -(candidate.quality if candidate.quality is not None else -1.0)
        latency = candidate.latency if candidate.latency is not None else math.inf
        cost = candidate.cost if candidate.cost is not None else math.inf
        if request.policy is RoutingPolicy.QUALITY_FIRST:
            return preferred, local, quality, latency
        if request.policy is RoutingPolicy.SPEED_FIRST:
            return latency, preferred, local, quality
        if request.policy is RoutingPolicy.LOWEST_COST:
            return cost, preferred, local, quality
        if request.policy in {
            RoutingPolicy.LOCAL_ONLY,
            RoutingPolicy.PRIVACY_STRICT,
            RoutingPolicy.PREFER_LOCAL,
        }:
            return local, preferred, quality, latency
        return preferred, local, quality, latency

    @staticmethod
    def _no_llm(
        request: RouteRequest,
        *reasons: str,
        resource_decision: ResourceDecision | None = None,
    ) -> RouteDecision:
        del request
        return RouteDecision(RouteStatus.NO_LLM, None, (), tuple(reasons), resource_decision)


class FailoverSttProvider(SttProvider):
    """Provider-neutral STT fallback chain; failures never alter permission policy."""

    def __init__(self, providers: tuple[SttProvider, ...]) -> None:
        if not providers:
            raise ValueError("At least one STT provider is required")
        self._providers = providers

    async def transcribe(self, audio: AudioData) -> Transcription:
        last_error: BaseException | None = None
        for provider in self._providers:
            try:
                return await provider.transcribe(audio)
            except Exception as error:
                last_error = error
        assert last_error is not None
        raise last_error

    async def aclose(self) -> None:
        for provider in self._providers:
            await provider.aclose()


def _resource_fit(model: ModelMetadata, hardware: HardwareProfile, concurrency: int) -> FitStatus:
    reading = hardware.reading
    unknown = False
    if model.storage_bytes is not None:
        if reading.disk_free_bytes is None:
            unknown = True
        elif model.storage_bytes > reading.disk_free_bytes:
            return FitStatus.INCOMPATIBLE
    if model.ram_bytes is not None:
        if reading.ram_bytes is None:
            unknown = True
        elif model.ram_bytes > reading.ram_bytes:
            return FitStatus.INCOMPATIBLE
    if model.vram_bytes is not None:
        if hardware.available_vram_bytes is None:
            unknown = True
        elif model.vram_bytes > hardware.available_vram_bytes:
            return FitStatus.INCOMPATIBLE
    if reading.concurrency_limit is not None and concurrency > reading.concurrency_limit:
        return FitStatus.INCOMPATIBLE
    return FitStatus.UNKNOWN if unknown else FitStatus.COMPATIBLE
