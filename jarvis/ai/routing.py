"""Provider-neutral inference and voice routing under explicit resource policy."""

from __future__ import annotations

import asyncio
import math
from collections.abc import AsyncIterator, Mapping
from dataclasses import dataclass, replace
from datetime import datetime
from enum import StrEnum
from typing import Any

from jarvis.ai.knowledge import (
    CookbookObservation,
    CookbookOutcome,
    CookbookSummary,
    EvidenceSufficiency,
    KnowledgeAvailability,
    ModelIdentity,
    ModelKnowledgeService,
    ModelKnowledgeView,
    ModelMeasurementView,
    VerifierAgreement,
    identity_for,
)
from jarvis.ai.models import (
    GenerationChunk,
    GenerationRequest,
    GenerationResult,
    ModelRole,
    PrivacyClassification,
    PrivacyContext,
)
from jarvis.ai.privacy import PrivacyGuardedProvider
from jarvis.ai.providers.registry import (
    ModelMetadata,
    ProviderLocality,
    ProviderMetadata,
    ProviderRegistry,
    VoiceProviderKind,
)
from jarvis.core.errors import PrivacyBlockedError
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
    NO_ELIGIBLE_MODEL = "no_eligible_model"
    INSUFFICIENT_EVIDENCE = "insufficient_evidence"
    PRIVACY_BLOCKED = "privacy_blocked"
    PROVIDER_UNAVAILABLE = "provider_unavailable"
    RESOURCE_UNAVAILABLE = "resource_unavailable"
    CANCELLED = "cancelled"
    ATTEMPTS_EXHAUSTED = "attempts_exhausted"


class RouteFailureClass(StrEnum):
    PROVIDER_UNAVAILABLE = "provider_unavailable"
    TIMEOUT = "timeout"
    MALFORMED_STRUCTURED_OUTPUT = "malformed_structured_output"
    INVALID_TOOL_CALL = "invalid_tool_call"
    RESOURCE_OOM = "resource_oom"
    VERIFICATION_FAILURE = "verification_failure"
    PRIVACY_BLOCK = "privacy_block"
    CANCELLED = "cancelled"
    UNKNOWN_OUTCOME = "unknown_outcome"


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
    task_class: str = "general"
    responsibility: str = "conversation"
    privacy_context: PrivacyContext | None = None
    required_capabilities: frozenset[str] = frozenset()
    minimum_expected_reliability: float | None = None
    max_cost_per_million: float | None = None
    previous_failure: RouteFailureClass | None = None
    excluded_identities: tuple[ModelIdentity, ...] = ()

    def __post_init__(self) -> None:
        for name, value, limit in (
            ("task", self.task, 4_000),
            ("profile", self.profile, 128),
            ("modality", self.modality, 64),
            ("complexity", self.complexity, 64),
            ("classification", self.classification, 64),
            ("task class", self.task_class, 128),
            ("responsibility", self.responsibility, 128),
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
        if self.privacy_context is not None and not isinstance(
            self.privacy_context, PrivacyContext
        ):
            raise ValueError("Route privacy context is invalid")
        if type(self.required_capabilities) is not frozenset or any(
            type(value) is not str or not value.strip() or len(value) > 128 or "\x00" in value
            for value in self.required_capabilities
        ):
            raise ValueError("Route capabilities are invalid")
        if self.minimum_expected_reliability is not None and (
            type(self.minimum_expected_reliability) not in {int, float}
            or not math.isfinite(self.minimum_expected_reliability)
            or not 0.0 <= self.minimum_expected_reliability <= 1.0
        ):
            raise ValueError("Route reliability requirement is invalid")
        if self.max_cost_per_million is not None and (
            type(self.max_cost_per_million) not in {int, float}
            or not math.isfinite(self.max_cost_per_million)
            or self.max_cost_per_million < 0
        ):
            raise ValueError("Route cost budget is invalid")
        if self.previous_failure is not None and not isinstance(
            self.previous_failure, RouteFailureClass
        ):
            raise ValueError("Route failure context is invalid")
        if type(self.excluded_identities) is not tuple or any(
            not isinstance(item, ModelIdentity) for item in self.excluded_identities
        ):
            raise ValueError("Route exclusions are invalid")

    def effective_privacy_context(self) -> PrivacyContext:
        """Return typed privacy input, adapting only legacy callers."""
        if self.privacy_context is not None:
            return self.privacy_context
        try:
            classification = PrivacyClassification(self.classification.casefold())
        except ValueError:
            classification = PrivacyClassification.UNKNOWN
        return PrivacyContext(classification)


@dataclass(frozen=True, slots=True)
class RouteCandidate:
    provider_id: str
    model_id: str
    provider: ProviderMetadata
    model: ModelMetadata
    local: bool
    voice_kind: VoiceProviderKind | None = None
    benchmark: RouteBenchmark | None = None
    knowledge: ModelKnowledgeView | None = None
    measurement: ModelMeasurementView | None = None
    cookbook: CookbookSummary | None = None

    @property
    def identity(self) -> ModelIdentity:
        return identity_for(self.provider_id, self.model)

    @property
    def quality(self) -> float | None:
        if self.benchmark is not None and self.benchmark.quality_score is not None:
            return self.benchmark.quality_score
        return self.model.quality_score

    @property
    def latency(self) -> float | None:
        if self.cookbook is not None and self.cookbook.mean_latency_ms is not None:
            return self.cookbook.mean_latency_ms
        if self.measurement is not None and self.measurement.load_seconds is not None:
            return self.measurement.load_seconds * 1000.0
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

    @property
    def reliability(self) -> float | None:
        if self.cookbook is None:
            return None
        return self.cookbook.verified_success_rate

    @property
    def reliability_sufficient(self) -> bool:
        return self.cookbook is not None and (
            self.cookbook.evidence_sufficiency is EvidenceSufficiency.SUFFICIENT
        )


@dataclass(frozen=True, slots=True)
class RouteDecision:
    status: RouteStatus
    primary: RouteCandidate | None
    fallbacks: tuple[RouteCandidate, ...] = ()
    reasons: tuple[str, ...] = ()
    resource_decision: ResourceDecision | None = None
    evidence: tuple[tuple[str, str], ...] = ()


class ProviderRouter:
    """Select configured providers without provider-specific conditionals."""

    def __init__(
        self,
        registry: ProviderRegistry,
        resource_governor: ResourceGovernor | None = None,
        knowledge: ModelKnowledgeService | None = None,
    ) -> None:
        self._registry = registry
        self._resource_governor = resource_governor
        self._knowledge = knowledge

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
                definition.metadata.explicitly_local,
            )
            for provider_id, definition in self._registry.definitions()
            for model in definition.models
        ]
        candidates = self._enrich_candidates(candidates, request)
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
                definition.metadata.explicitly_local,
                kind,
            )
            for provider_id, definition in self._registry.voice_definitions(kind)
            for model in definition.models
        ]
        candidates = self._enrich_candidates(candidates, request)
        return self._select(candidates, request, resource_decision)

    def _enrich_candidates(
        self, candidates: list[RouteCandidate], request: RouteRequest
    ) -> list[RouteCandidate]:
        """Attach read-only P3B facts without making knowledge executable authority."""

        if self._knowledge is None:
            return candidates
        providers = {
            item.metadata.provider_id.casefold(): item for item in self._knowledge.providers()
        }
        enriched: list[RouteCandidate] = []
        for candidate in candidates:
            identity = candidate.identity
            try:
                model_knowledge = self._knowledge.inspect_model(identity)
            except KeyError:
                model_knowledge = None
            measurement = self._knowledge.latest_measurement(identity)
            cookbook = self._knowledge.cookbook_summary(identity, task_class=request.task_class)
            provider_knowledge = providers.get(candidate.provider_id.casefold())
            enriched.append(
                replace(
                    candidate,
                    knowledge=model_knowledge,
                    measurement=measurement,
                    cookbook=cookbook,
                    benchmark=None,
                    provider=(
                        candidate.provider
                        if provider_knowledge is None
                        else provider_knowledge.metadata
                    ),
                )
            )
        return enriched

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
        if self._knowledge is not None:
            for item in self._knowledge.providers():
                health.setdefault(
                    item.metadata.provider_id.casefold(),
                    ProviderHealthSnapshot(
                        item.metadata.provider_id,
                        item.available is True and item.availability is KnowledgeAvailability.KNOWN,
                        item.detail or item.availability.value,
                    ),
                )
        for candidate in candidates:
            candidate = RouteCandidate(
                candidate.provider_id,
                candidate.model_id,
                candidate.provider,
                candidate.model,
                candidate.local,
                candidate.voice_kind,
                (
                    None
                    if self._knowledge is not None
                    else benchmarks.get((candidate.provider_id.casefold(), candidate.model_id))
                ),
                candidate.knowledge,
                candidate.measurement,
                candidate.cookbook,
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
                tuple(
                    f"selected {viable[0].identity.storage_key}",
                ),
                resource_decision,
                evidence=self._evidence(viable[0]),
            )
        if request.allow_no_llm:
            return self._no_llm(request, *(unknown or rejected or ("no compatible provider",)))
        status = RouteStatus.UNKNOWN if unknown else RouteStatus.UNAVAILABLE
        if self._knowledge is not None and request.minimum_expected_reliability is not None:
            status = RouteStatus.INSUFFICIENT_EVIDENCE if unknown else status
        elif (
            self._knowledge is not None
            and not unknown
            and rejected
            and all("privacy classification" in item for item in rejected)
        ):
            status = RouteStatus.PRIVACY_BLOCKED
        return RouteDecision(
            status,
            None,
            (),
            tuple((unknown or rejected or ["no compatible provider"])[:8]),
            resource_decision,
        )

    @staticmethod
    def _evidence(candidate: RouteCandidate) -> tuple[tuple[str, str], ...]:
        evidence: list[tuple[str, str]] = [("identity", candidate.identity.storage_key)]
        if candidate.knowledge is not None:
            evidence.extend(
                (
                    ("knowledge_availability", candidate.knowledge.availability.value),
                    ("knowledge_freshness", candidate.knowledge.freshness.value),
                )
            )
        if candidate.measurement is not None:
            evidence.extend(
                (
                    ("measurement_source", candidate.measurement.source),
                    ("measurement_scope", candidate.measurement.machine_scope),
                )
            )
        if candidate.cookbook is not None:
            evidence.extend(
                (
                    ("task_class", candidate.cookbook.task_class),
                    ("sample_count", str(candidate.cookbook.sample_count)),
                    ("evidence_sufficiency", candidate.cookbook.evidence_sufficiency.value),
                )
            )
        return tuple(evidence)

    @staticmethod
    def _resource_size(candidate: RouteCandidate) -> tuple[float, float, float]:
        return (
            _resource_value(_effective_model(candidate).ram_bytes),
            _resource_value(_effective_model(candidate).vram_bytes),
            _resource_value(_effective_model(candidate).storage_bytes),
        )

    def _eligibility(
        self,
        candidate: RouteCandidate,
        request: RouteRequest,
        health: dict[str, ProviderHealthSnapshot],
    ) -> tuple[str | None, bool]:
        model = _effective_model(candidate)
        privacy = request.effective_privacy_context()
        if request.policy in {RoutingPolicy.LOCAL_ONLY, RoutingPolicy.PRIVACY_STRICT}:
            if not candidate.local:
                return "policy requires a local provider", False
        if not candidate.local and privacy.classification in {
            PrivacyClassification.LOCAL_ONLY,
            PrivacyClassification.SECRET,
            PrivacyClassification.UNKNOWN,
        }:
            return "privacy classification forbids remote inference", False
        status = health.get(candidate.provider_id.casefold())
        if status is not None and not status.available:
            if status.detail in {
                KnowledgeAvailability.UNKNOWN.value,
                KnowledgeAvailability.STALE.value,
            }:
                return "provider health is unknown", True
            return "provider health is unavailable", False
        if candidate.knowledge is not None and candidate.knowledge.availability in {
            KnowledgeAvailability.CURRENTLY_UNAVAILABLE,
        }:
            return "model is currently unavailable", False
        if candidate.knowledge is not None and candidate.knowledge.availability in {
            KnowledgeAvailability.UNKNOWN,
            KnowledgeAvailability.STALE,
        }:
            return "model knowledge is not current", True
        if not request.required_capabilities.issubset(
            {value.casefold() for value in model.capabilities}
        ):
            return "required model capability is not declared", False
        if candidate.identity in request.excluded_identities:
            return "model was excluded after a prior failure", False
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
        if request.max_cost_per_million is not None:
            cost = candidate.cost
            if cost is None:
                return "cost benchmark is unknown", True
            if cost > request.max_cost_per_million:
                return "cost budget exceeded", False
        if request.minimum_expected_reliability is not None:
            reliability = _failure_aware_reliability(candidate, request.previous_failure)
            if not candidate.reliability_sufficient or reliability is None:
                return "task reliability evidence is insufficient", True
            if reliability < request.minimum_expected_reliability:
                return "task reliability threshold is not met", False
        return None, False

    @staticmethod
    def _sort_key(candidate: RouteCandidate, request: RouteRequest) -> tuple[object, ...]:
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
        reliability_value = _failure_aware_reliability(candidate, request.previous_failure)
        reliability_sufficient = candidate.reliability_sufficient and reliability_value is not None
        reliability_tier = (
            0.0 if reliability_sufficient else 1.0 if reliability_value is not None else 2.0
        )
        reliability = -(reliability_value if reliability_value is not None else -1.0)
        identity = (
            candidate.identity.provider_id,
            candidate.identity.model_id,
            candidate.identity.version,
            candidate.identity.quantization,
            candidate.identity.runtime,
        )
        if request.minimum_expected_reliability is not None:
            if request.policy is RoutingPolicy.LOWEST_COST:
                return cost, latency, local, reliability, quality, identity
            if request.policy is RoutingPolicy.SPEED_FIRST:
                return latency, cost, local, reliability, quality, identity
            if request.policy is RoutingPolicy.PREFER_LOCAL:
                return local, cost, latency, reliability, quality, identity
            if request.policy is RoutingPolicy.BALANCED:
                return (
                    local,
                    cost,
                    latency,
                    ProviderRouter._resource_size(candidate),
                    reliability,
                    identity,
                )
        if request.policy is RoutingPolicy.QUALITY_FIRST:
            return reliability_tier, reliability, preferred, quality, local, latency, identity
        if request.policy is RoutingPolicy.SPEED_FIRST:
            return reliability_tier, reliability, latency, preferred, local, quality, identity
        if request.policy is RoutingPolicy.LOWEST_COST:
            return reliability_tier, reliability, cost, preferred, local, quality, identity
        if request.policy in {
            RoutingPolicy.LOCAL_ONLY,
            RoutingPolicy.PRIVACY_STRICT,
            RoutingPolicy.PREFER_LOCAL,
        }:
            return reliability_tier, reliability, local, preferred, quality, latency, identity
        return reliability_tier, reliability, preferred, local, quality, latency, identity

    @staticmethod
    def _no_llm(
        request: RouteRequest,
        *reasons: str,
        resource_decision: ResourceDecision | None = None,
    ) -> RouteDecision:
        del request
        return RouteDecision(RouteStatus.NO_LLM, None, (), tuple(reasons), resource_decision)


class InferenceDispatchError(RuntimeError):
    """Inference could not complete under the selected route and retry bound."""

    def __init__(self, message: str, decision: RouteDecision) -> None:
        super().__init__(message)
        self.decision = decision
        self.status = decision.status


@dataclass(frozen=True, slots=True)
class DispatchResult:
    result: GenerationResult
    decision: RouteDecision
    rerouted: bool = False


@dataclass(frozen=True, slots=True)
class DispatchChunk:
    chunk: GenerationChunk
    decision: RouteDecision
    rerouted: bool = False


class InferenceDispatcher:
    """Execute the router's decision through registry-owned provider factories."""

    def __init__(
        self,
        router: ProviderRouter,
        registry: ProviderRegistry,
        *,
        configurations: Mapping[str, Mapping[str, Any]] | None = None,
        providers: Mapping[str, Any] | None = None,
        max_attempts: int = 2,
        max_cached_providers: int = 16,
    ) -> None:
        if max_attempts < 1 or max_attempts > 4:
            raise ValueError("Inference attempts must be bounded")
        if max_cached_providers < 1 or max_cached_providers > 64:
            raise ValueError("Provider cache bound is invalid")
        self._router = router
        self._registry = registry
        self._configurations = {
            str(provider_id).casefold(): dict(configuration)
            for provider_id, configuration in (configurations or {}).items()
        }
        self._providers = {
            str(provider_id).casefold(): provider
            for provider_id, provider in (providers or {}).items()
        }
        self._owned: dict[str, PrivacyGuardedProvider] = {}
        self._max_attempts = max_attempts
        self._max_cached_providers = max_cached_providers

    def route(self, intent: RouteRequest) -> RouteDecision:
        return self._router.route(intent)

    async def generate(
        self,
        request: GenerationRequest,
        intent: RouteRequest,
        *,
        decision: RouteDecision | None = None,
    ) -> DispatchResult:
        if not isinstance(request, GenerationRequest) or not isinstance(intent, RouteRequest):
            raise ValueError("Inference dispatch input is malformed")
        current_intent = intent
        current_decision = decision or self.route(current_intent)
        rerouted = False
        for attempt in range(self._max_attempts):
            candidate = current_decision.primary
            if candidate is None:
                raise InferenceDispatchError("No eligible inference model", current_decision)
            current_request = self._request_for(request, candidate)
            provider = self._provider_for(candidate)
            try:
                result = await provider.generate(current_request)
                return DispatchResult(
                    GenerationResult(result.content, candidate.model_id),
                    current_decision,
                    rerouted,
                )
            except PrivacyBlockedError as error:
                if attempt + 1 >= self._max_attempts:
                    blocked = RouteDecision(
                        RouteStatus.PRIVACY_BLOCKED,
                        None,
                        current_decision.fallbacks,
                        ("P3A privacy boundary blocked the outbound request",),
                        current_decision.resource_decision,
                        current_decision.evidence,
                    )
                    raise InferenceDispatchError(
                        "Inference blocked by privacy boundary", blocked
                    ) from error
                current_intent = replace(
                    current_intent,
                    policy=RoutingPolicy.LOCAL_ONLY,
                    privacy_context=PrivacyContext(PrivacyClassification.LOCAL_ONLY),
                    excluded_identities=(*current_intent.excluded_identities, candidate.identity),
                )
            except asyncio.CancelledError:
                raise
            except Exception as error:
                failure = _failure_class(error)
                if failure is RouteFailureClass.UNKNOWN_OUTCOME:
                    unknown = RouteDecision(
                        RouteStatus.UNKNOWN,
                        None,
                        current_decision.fallbacks,
                        ("provider outcome is unknown; adaptive reroute is forbidden",),
                        current_decision.resource_decision,
                        (("failure_class", failure.value), *current_decision.evidence),
                    )
                    raise InferenceDispatchError(
                        "Inference outcome is unknown; no fallback was attempted", unknown
                    ) from error
                if attempt + 1 >= self._max_attempts:
                    exhausted = RouteDecision(
                        RouteStatus.ATTEMPTS_EXHAUSTED,
                        None,
                        current_decision.fallbacks,
                        (f"inference attempt failed: {type(error).__name__}",),
                        current_decision.resource_decision,
                        current_decision.evidence,
                    )
                    raise InferenceDispatchError(
                        "Inference attempts exhausted", exhausted
                    ) from error
                current_intent = replace(
                    current_intent,
                    previous_failure=failure,
                    excluded_identities=(*current_intent.excluded_identities, candidate.identity),
                )
            current_decision = self.route(current_intent)
            rerouted = True
        raise AssertionError("bounded inference loop escaped")

    async def stream(
        self,
        request: GenerationRequest,
        intent: RouteRequest,
        *,
        decision: RouteDecision | None = None,
    ) -> AsyncIterator[DispatchChunk]:
        if not isinstance(request, GenerationRequest) or not isinstance(intent, RouteRequest):
            raise ValueError("Inference dispatch input is malformed")
        current_intent = intent
        current_decision = decision or self.route(current_intent)
        rerouted = False
        for attempt in range(self._max_attempts):
            candidate = current_decision.primary
            if candidate is None:
                raise InferenceDispatchError("No eligible inference model", current_decision)
            provider = self._provider_for(candidate)
            yielded = False
            try:
                async for chunk in provider.stream(self._request_for(request, candidate)):
                    yielded = True
                    yield DispatchChunk(chunk, current_decision, rerouted)
                return
            except PrivacyBlockedError as error:
                if yielded or attempt + 1 >= self._max_attempts:
                    blocked = RouteDecision(
                        RouteStatus.PRIVACY_BLOCKED,
                        None,
                        current_decision.fallbacks,
                        ("P3A privacy boundary blocked the outbound request",),
                        current_decision.resource_decision,
                        current_decision.evidence,
                    )
                    raise InferenceDispatchError(
                        "Inference blocked by privacy boundary", blocked
                    ) from error
                current_intent = replace(
                    current_intent,
                    policy=RoutingPolicy.LOCAL_ONLY,
                    privacy_context=PrivacyContext(PrivacyClassification.LOCAL_ONLY),
                    excluded_identities=(*current_intent.excluded_identities, candidate.identity),
                )
            except asyncio.CancelledError:
                raise
            except Exception as error:
                failure = _failure_class(error)
                if failure is RouteFailureClass.UNKNOWN_OUTCOME:
                    unknown = RouteDecision(
                        RouteStatus.UNKNOWN,
                        None,
                        current_decision.fallbacks,
                        ("provider outcome is unknown; adaptive reroute is forbidden",),
                        current_decision.resource_decision,
                        (("failure_class", failure.value), *current_decision.evidence),
                    )
                    raise InferenceDispatchError(
                        "Streaming outcome is unknown; no fallback was attempted", unknown
                    ) from error
                if yielded or attempt + 1 >= self._max_attempts:
                    exhausted = RouteDecision(
                        RouteStatus.ATTEMPTS_EXHAUSTED,
                        None,
                        current_decision.fallbacks,
                        (f"stream attempt failed: {type(error).__name__}",),
                        current_decision.resource_decision,
                        current_decision.evidence,
                    )
                    raise InferenceDispatchError(
                        "Streaming inference attempts exhausted", exhausted
                    ) from error
                current_intent = replace(
                    current_intent,
                    previous_failure=failure,
                    excluded_identities=(*current_intent.excluded_identities, candidate.identity),
                )
            current_decision = self.route(current_intent)
            rerouted = True
        raise AssertionError("bounded streaming loop escaped")

    async def aclose(self) -> None:
        for provider in tuple(self._owned.values()):
            await provider.aclose()
        self._owned.clear()

    def _provider_for(self, candidate: RouteCandidate) -> PrivacyGuardedProvider:
        key = candidate.identity.storage_key
        cached = self._owned.get(key)
        if cached is not None:
            return cached
        raw = self._providers.get(candidate.provider_id.casefold())
        owned = False
        if raw is None:
            if len(self._owned) >= self._max_cached_providers:
                raise RuntimeError("bounded provider cache is exhausted")
            configuration = dict(self._configurations.get(candidate.provider_id.casefold(), {}))
            configuration.update(
                {
                    "model": candidate.model_id,
                    "context_limit": candidate.model.context_limit,
                }
            )
            raw = self._registry.create(candidate.provider_id, configuration)
            owned = True
        provider = (
            raw
            if isinstance(raw, PrivacyGuardedProvider)
            else PrivacyGuardedProvider(raw, candidate.provider)
        )
        if owned:
            self._owned[key] = provider
        return provider

    @staticmethod
    def _request_for(request: GenerationRequest, candidate: RouteCandidate) -> GenerationRequest:
        return GenerationRequest(
            request.messages,
            candidate.model_id,
            min(request.context_limit, candidate.model.context_limit),
            request.privacy_context,
        )


def _effective_model(candidate: RouteCandidate) -> ModelMetadata:
    """Overlay only trusted machine measurements on executable registry metadata."""

    measurement = candidate.measurement
    if measurement is None:
        return candidate.model
    return replace(
        candidate.model,
        storage_bytes=(
            measurement.storage_bytes
            if measurement.storage_bytes is not None
            else candidate.model.storage_bytes
        ),
        ram_bytes=(
            measurement.peak_ram_bytes
            if measurement.peak_ram_bytes is not None
            else candidate.model.ram_bytes
        ),
        vram_bytes=(
            measurement.peak_vram_bytes
            if measurement.peak_vram_bytes is not None
            else candidate.model.vram_bytes
        ),
        max_concurrency=(
            measurement.concurrency
            if measurement.concurrency is not None
            else candidate.model.max_concurrency
        ),
        latency_ms=(
            measurement.load_seconds * 1000.0
            if measurement.load_seconds is not None
            else candidate.model.latency_ms
        ),
    )


def _resource_value(value: int | None) -> float:
    return float(value) if value is not None else math.inf


def _failure_aware_reliability(
    candidate: RouteCandidate, failure: RouteFailureClass | None
) -> float | None:
    cookbook = candidate.cookbook
    if cookbook is None:
        return None
    if failure is RouteFailureClass.MALFORMED_STRUCTURED_OUTPUT:
        return cookbook.structured_output_reliability
    if failure is RouteFailureClass.INVALID_TOOL_CALL:
        return cookbook.tool_reliability
    return cookbook.verified_success_rate


def _failure_class(error: BaseException) -> RouteFailureClass:
    name = type(error).__name__.casefold()
    if "timeout" in name:
        return RouteFailureClass.TIMEOUT
    if "privacy" in name:
        return RouteFailureClass.PRIVACY_BLOCK
    if "unavailable" in name or "connect" in name:
        return RouteFailureClass.PROVIDER_UNAVAILABLE
    return RouteFailureClass.UNKNOWN_OUTCOME


class RoutingFeedbackRecorder:
    """Record bounded factual outcomes for the P3B cookbook.

    This interface intentionally accepts no prompt, memory, credential, or
    model-response text. Verification remains an explicit caller-owned fact.
    """

    def __init__(
        self,
        knowledge: ModelKnowledgeService,
        *,
        provider_locality: Mapping[str, ProviderLocality] | None = None,
    ) -> None:
        self._knowledge = knowledge
        self._locality = {key.casefold(): value for key, value in (provider_locality or {}).items()}

    def record(
        self,
        identity: ModelIdentity,
        task_class: str,
        outcome: CookbookOutcome,
        *,
        observed_at: datetime,
        operation_class: str = "inference",
        role: ModelRole | None = None,
        verified: bool | None = None,
        verifier_agreement: VerifierAgreement = VerifierAgreement.UNKNOWN,
        latency_ms: float | None = None,
        token_usage: int | None = None,
        monetary_cost: float | None = None,
        structured_output_valid: bool | None = None,
        tool_call_valid: bool | None = None,
        retry_count: int = 0,
        escalation_required: bool = False,
        failure_class: str = "",
    ) -> bool:
        if not isinstance(identity, ModelIdentity):
            raise ValueError("Feedback identity is malformed")
        locality = self._locality.get(identity.provider_id, ProviderLocality.UNKNOWN)
        return self._knowledge.record_cookbook(
            CookbookObservation(
                identity=identity,
                task_class=task_class,
                outcome=outcome,
                observed_at=observed_at,
                operation_class=operation_class,
                role=role,
                locality=locality,
                verified=verified,
                verifier_agreement=verifier_agreement,
                latency_ms=latency_ms,
                token_usage=token_usage,
                monetary_cost=monetary_cost,
                structured_output_valid=structured_output_valid,
                tool_call_valid=tool_call_valid,
                retry_count=retry_count,
                escalation_required=escalation_required,
                failure_class=failure_class,
            )
        )


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
