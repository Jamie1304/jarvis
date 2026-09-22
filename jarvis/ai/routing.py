"""Provider-neutral inference and voice routing under explicit resource policy."""

from __future__ import annotations

import asyncio
import math
from collections.abc import AsyncIterator, Callable, Mapping
from dataclasses import dataclass, replace
from datetime import UTC, datetime
from enum import StrEnum
from typing import Any, Protocol
from uuid import uuid4

from jarvis.ai.fitness import (
    RoutingDecisionOutcome,
    RoutingDecisionRecord,
    RoutingDecisionView,
    SemanticOutcome,
    SQLiteRoutingFitnessStore,
)
from jarvis.ai.governance import BudgetLedger, GuardedApproval, PolicyEngine, TaskQuarantine
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
    ModelLifecycle,
    ModelMetadata,
    ProviderLocality,
    ProviderMetadata,
    ProviderRegistry,
    VoiceProviderKind,
)
from jarvis.ai.usability import (
    ModelUsabilityEvidence,
    ModelUsabilityStatus,
    UsabilityReason,
    evidence_for_failure,
    evidence_for_success,
    merge_usability_evidence,
)
from jarvis.core.errors import PrivacyBlockedError
from jarvis.hardware import FitStatus, HardwareProfile
from jarvis.resources import (
    ReservationReleaseReason,
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
    AUTHENTICATION = "authentication"
    QUOTA = "quota"
    BILLING = "billing"
    RATE_LIMITED = "rate_limited"
    MODEL_UNAVAILABLE = "model_unavailable"
    NETWORK_UNAVAILABLE = "network_unavailable"
    PROVIDER_OUTAGE = "provider_outage"
    POLICY_BLOCK = "policy_block"
    RESOURCE_BLOCK = "resource_block"
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
    load_latency_ms: float | None = None

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
            ("load latency", self.load_latency_ms),
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
    preferred_model_id: str | None = None
    pinned_provider_id: str | None = None
    pinned_model_id: str | None = None
    allow_no_llm: bool = False
    no_llm: bool = False
    benchmarks: tuple[RouteBenchmark, ...] = ()
    provider_health: tuple[ProviderHealthSnapshot, ...] = ()
    usability_evidence: tuple[ModelUsabilityEvidence, ...] = ()
    usability: tuple[ModelUsabilityEvidence, ...] = ()
    priority: ResourcePriority = ResourcePriority.USER_REQUESTED
    task_class: str = "general"
    responsibility: str = "conversation"
    privacy_context: PrivacyContext | None = None
    required_capabilities: frozenset[str] = frozenset()
    minimum_expected_reliability: float | None = None
    max_cost_per_million: float | None = None
    previous_failure: RouteFailureClass | None = None
    excluded_identities: tuple[ModelIdentity, ...] = ()
    current_identity: ModelIdentity | None = None
    warm_identities: tuple[ModelIdentity, ...] = ()
    current_quality: float | None = None
    switching_cost_budget_ms: float | None = None
    minimum_quality_gain_to_switch: float = 0.05
    explicit_selection: bool = False
    actor_id: str = "system"
    purpose: str = "inference"
    approval_scope: str = "inference"
    guarded_approval: GuardedApproval | None = None
    estimated_cost: float | None = None
    budget_ledger: BudgetLedger | None = None

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
        if self.preferred_model_id is not None and (
            type(self.preferred_model_id) is not str or not self.preferred_model_id.strip()
        ):
            raise ValueError("Preferred model is invalid")
        if self.pinned_provider_id is not None and (
            type(self.pinned_provider_id) is not str or not self.pinned_provider_id.strip()
        ):
            raise ValueError("Pinned provider is invalid")
        if self.pinned_model_id is not None and (
            type(self.pinned_model_id) is not str or not self.pinned_model_id.strip()
        ):
            raise ValueError("Pinned model is invalid")
        if type(self.benchmarks) is not tuple or any(
            not isinstance(item, RouteBenchmark) for item in self.benchmarks
        ):
            raise ValueError("Route benchmarks are invalid")
        if type(self.provider_health) is not tuple or any(
            not isinstance(item, ProviderHealthSnapshot) for item in self.provider_health
        ):
            raise ValueError("Route health snapshots are invalid")
        for name, values in (
            ("usability evidence", self.usability_evidence),
            ("usability", self.usability),
        ):
            if type(values) is not tuple or any(
                not isinstance(item, ModelUsabilityEvidence) for item in values
            ):
                raise ValueError(f"Route {name} is invalid")
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
        if self.current_identity is not None and not isinstance(
            self.current_identity, ModelIdentity
        ):
            raise ValueError("Current route identity is invalid")
        if type(self.warm_identities) is not tuple or any(
            not isinstance(item, ModelIdentity) for item in self.warm_identities
        ):
            raise ValueError("Warm route identities are invalid")
        if self.current_quality is not None and (
            type(self.current_quality) not in {int, float}
            or not math.isfinite(self.current_quality)
            or not 0.0 <= self.current_quality <= 1.0
        ):
            raise ValueError("Current route quality is invalid")
        if self.switching_cost_budget_ms is not None and (
            type(self.switching_cost_budget_ms) not in {int, float}
            or not math.isfinite(self.switching_cost_budget_ms)
            or self.switching_cost_budget_ms < 0
        ):
            raise ValueError("Route switching budget is invalid")
        if (
            type(self.minimum_quality_gain_to_switch) not in {int, float}
            or not math.isfinite(self.minimum_quality_gain_to_switch)
            or not 0.0 <= self.minimum_quality_gain_to_switch <= 1.0
        ):
            raise ValueError("Route switching quality threshold is invalid")
        if type(self.explicit_selection) is not bool:
            raise ValueError("Route selection mode is invalid")
        for name, value, limit in (
            ("actor ID", self.actor_id, 256),
            ("route purpose", self.purpose, 256),
            ("approval scope", self.approval_scope, 256),
        ):
            if type(value) is not str or not value.strip() or len(value) > limit or "\x00" in value:
                raise ValueError(f"Route {name} is invalid")
        if self.guarded_approval is not None and not isinstance(
            self.guarded_approval, GuardedApproval
        ):
            raise ValueError("Route guarded approval is invalid")
        if self.estimated_cost is not None and (
            type(self.estimated_cost) not in {int, float}
            or not math.isfinite(self.estimated_cost)
            or self.estimated_cost < 0
        ):
            raise ValueError("Route estimated cost is invalid")
        if self.budget_ledger is not None and not isinstance(self.budget_ledger, BudgetLedger):
            raise ValueError("Route budget ledger is invalid")

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
    usability: ModelUsabilityEvidence | None = None

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

    @property
    def usability_status(self) -> ModelUsabilityStatus:
        if self.usability is None:
            return ModelUsabilityStatus.UNKNOWN
        return self.usability.status

    @property
    def usability_reason(self) -> UsabilityReason:
        if self.usability is None:
            return UsabilityReason.UNKNOWN
        return self.usability.effective_reason


@dataclass(frozen=True, slots=True)
class RouteDecision:
    status: RouteStatus
    primary: RouteCandidate | None
    fallbacks: tuple[RouteCandidate, ...] = ()
    reasons: tuple[str, ...] = ()
    resource_decision: ResourceDecision | None = None
    evidence: tuple[tuple[str, str], ...] = ()
    decision_id: str | None = None


class InferenceLifecycle(Protocol):
    """Optional generic lifecycle bridge used by the dispatcher."""

    async def prepare_for_inference(
        self, candidate: RouteCandidate, intent: RouteRequest | None = None
    ) -> object: ...

    def begin_inference(self, candidate: RouteCandidate) -> None: ...

    def end_inference(self, candidate: RouteCandidate) -> None: ...

    async def recover_provider(self, provider_id: str) -> bool: ...


class ProviderRouter:
    """Select configured providers without provider-specific conditionals."""

    def __init__(
        self,
        registry: ProviderRegistry,
        resource_governor: ResourceGovernor | None = None,
        knowledge: ModelKnowledgeService | None = None,
        hardware_profile: HardwareProfile | None = None,
        *,
        usability_evidence: tuple[ModelUsabilityEvidence, ...] = (),
        clock: Callable[[], datetime] | None = None,
        failure_cooldown_seconds: float = 300.0,
        rate_limit_cooldown_seconds: float = 30.0,
        routing_store: SQLiteRoutingFitnessStore | None = None,
        policy_engine: PolicyEngine | None = None,
        budget_ledger: BudgetLedger | None = None,
        task_quarantine: TaskQuarantine | None = None,
    ) -> None:
        self._registry = registry
        self._resource_governor = resource_governor
        self._knowledge = knowledge
        if routing_store is not None and not isinstance(routing_store, SQLiteRoutingFitnessStore):
            raise TypeError("Routing decision store is invalid")
        self._routing_store = routing_store
        if policy_engine is not None and not isinstance(policy_engine, PolicyEngine):
            raise TypeError("Routing policy engine is invalid")
        self._policy_engine = policy_engine
        if budget_ledger is not None and not isinstance(budget_ledger, BudgetLedger):
            raise TypeError("Routing budget ledger is invalid")
        if task_quarantine is not None and not isinstance(task_quarantine, TaskQuarantine):
            raise TypeError("Routing task quarantine is invalid")
        self._budget_ledger = budget_ledger
        self._task_quarantine = task_quarantine
        self._hardware_profile = hardware_profile
        if type(usability_evidence) is not tuple or any(
            not isinstance(item, ModelUsabilityEvidence) for item in usability_evidence
        ):
            raise ValueError("Router usability evidence is malformed")
        if (
            type(failure_cooldown_seconds) not in {int, float}
            or failure_cooldown_seconds < 0
            or type(rate_limit_cooldown_seconds) not in {int, float}
            or rate_limit_cooldown_seconds < 0
        ):
            raise ValueError("Router usability cooldown is invalid")
        self._clock = clock or (lambda: datetime.now(UTC))
        self._failure_cooldown_seconds = float(failure_cooldown_seconds)
        self._rate_limit_cooldown_seconds = float(rate_limit_cooldown_seconds)
        self._usability: dict[tuple[str, str | None], ModelUsabilityEvidence] = {}
        for evidence in usability_evidence:
            self.set_usability_evidence(evidence)

    def set_hardware_profile(self, profile: HardwareProfile | None) -> None:
        if profile is not None and not isinstance(profile, HardwareProfile):
            raise ValueError("Router hardware profile is malformed")
        self._hardware_profile = profile

    def set_usability_evidence(self, evidence: ModelUsabilityEvidence) -> None:
        """Install one current observation for provider or provider/model."""

        if not isinstance(evidence, ModelUsabilityEvidence):
            raise ValueError("Router usability evidence is malformed")
        if evidence.provider_id is None:
            key = ("*", evidence.model_id.casefold() if evidence.model_id else None)
        else:
            key = (
                evidence.provider_id.casefold(),
                evidence.model_id.casefold() if evidence.model_id else None,
            )
        self._usability[key] = evidence

    def usability_for(
        self, provider_id: str, model_id: str | None = None
    ) -> ModelUsabilityEvidence:
        """Return the canonical current/unknown evidence for a route identity."""

        provider_key = provider_id.casefold()
        model_key = model_id.casefold() if model_id is not None else None
        values = [
            self._usability[key]
            for key in (
                ("*", None),
                ("*", model_key),
                (provider_key, None),
                (provider_key, model_key),
            )
            if key in self._usability
        ]
        return merge_usability_evidence(*values)

    async def refresh_usability(
        self, provider_id: str, configuration: Mapping[str, Any]
    ) -> ModelUsabilityEvidence:
        """Perform one on-demand adapter probe and publish its evidence."""

        evidence = await self._registry.probe_usability(provider_id, configuration)
        self.set_usability_evidence(evidence)
        return evidence

    def record_failure(
        self,
        identity: ModelIdentity,
        reason: UsabilityReason,
        *,
        detail: str = "trusted provider failure feedback",
    ) -> ModelUsabilityEvidence:
        """Update bounded operational evidence without creating a failure DB."""

        if not isinstance(identity, ModelIdentity):
            raise ValueError("Routing failure identity is malformed")
        cooldown = (
            self._rate_limit_cooldown_seconds
            if reason is UsabilityReason.RATE_LIMITED
            else self._failure_cooldown_seconds
        )
        model_scoped = reason in {
            UsabilityReason.MODEL_NOT_ENTITLED,
            UsabilityReason.MODEL_UNAVAILABLE,
            UsabilityReason.MODEL_NOT_FOUND,
            UsabilityReason.RATE_LIMITED,
            UsabilityReason.LOCAL_RESOURCE_BLOCKED,
        }
        evidence = evidence_for_failure(
            identity.provider_id,
            reason,
            model_id=identity.model_id if model_scoped else None,
            observed_at=self._clock(),
            cooldown_seconds=cooldown,
            detail=detail,
        )
        self.set_usability_evidence(evidence)
        if model_scoped:
            return evidence
        return evidence

    def record_success(self, identity: ModelIdentity) -> ModelUsabilityEvidence:
        """Record only operational facts justified by a completed inference."""

        if not isinstance(identity, ModelIdentity):
            raise ValueError("Routing success identity is malformed")
        evidence = evidence_for_success(
            identity.provider_id,
            identity.model_id,
            observed_at=self._clock(),
        )
        current = self.usability_for(identity.provider_id, identity.model_id)
        merged = merge_usability_evidence(current, evidence)
        self.set_usability_evidence(merged)
        return merged

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

    @property
    def routing_store(self) -> SQLiteRoutingFitnessStore | None:
        return self._routing_store

    @property
    def registry(self) -> ProviderRegistry:
        """Expose the existing registry to read-only application projections."""

        return self._registry

    @property
    def policy_engine(self) -> PolicyEngine | None:
        return self._policy_engine

    def decision_view(self, decision_id: str) -> RoutingDecisionView | None:
        return (
            None if self._routing_store is None else self._routing_store.decision_view(decision_id)
        )

    def record_execution_outcome(
        self,
        decision: RouteDecision,
        *,
        executed_identity: str,
        operational_outcome: str,
        semantic_outcome: SemanticOutcome,
        rerouted: bool = False,
        retry_count: int = 0,
        evidence_refs: tuple[str, ...] = (),
    ) -> bool:
        if self._routing_store is None or decision.decision_id is None:
            return False
        return self._routing_store.record_decision_outcome(
            RoutingDecisionOutcome(
                outcome_id=(
                    f"{decision.decision_id}:{retry_count}:"
                    f"{executed_identity}:{operational_outcome}"
                )[:256],
                decision_id=decision.decision_id,
                observed_at=self._clock(),
                executed_identity=executed_identity,
                operational_outcome=operational_outcome,
                semantic_outcome=semantic_outcome,
                rerouted=rerouted,
                retry_count=retry_count,
                evidence_refs=evidence_refs,
            )
        )

    def persist_fusion_decision(
        self,
        request: RouteRequest,
        decision: RouteDecision,
        sources: tuple[RouteCandidate, ...],
    ) -> RouteDecision:
        if self._routing_store is None:
            return decision
        return self._persist_decision(
            request,
            replace(decision, primary=sources[0], fallbacks=sources[1:]),
            (),
            strategy="fusion",
            fusion_strategy="bounded_distinct_model_sources",
        )

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
        if request.resource_state is None and self._hardware_profile is not None:
            request = replace(request, resource_state=self._hardware_profile)
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
        rejected_evidence: list[tuple[str, str]] = []
        rejected_facts: list[tuple[str, str]] = []
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
            candidate = replace(
                candidate,
                benchmark=(
                    None
                    if self._knowledge is not None
                    else benchmarks.get((candidate.provider_id.casefold(), candidate.model_id))
                ),
                usability=self._candidate_usability(candidate, request, health),
            )
            reason, is_unknown = self._eligibility(candidate, request, health)
            resource_reason: str | None = None
            resource_unknown = False
            if reason is None and self._resource_governor is not None:
                resource_budget = self.resource_budget_for(candidate, request)
                low_priority = request.priority in {
                    ResourcePriority.BACKGROUND,
                    ResourcePriority.MAINTENANCE,
                    ResourcePriority.BENCHMARK,
                    ResourcePriority.INDEXING,
                }
                if (
                    candidate.local
                    and low_priority
                    and resource_budget.ram_bytes is None
                    and resource_budget.vram_bytes is None
                ):
                    resource_reason = "local model memory requirement is unmeasured"
                    resource_unknown = True
                else:
                    candidate_resource = self._resource_governor.decide(
                        f"model-candidate.{candidate.identity.storage_key}",
                        request.priority,
                        resource_budget,
                    )
                    if not candidate_resource.allowed:
                        resource_reason = candidate_resource.reason
                        resource_unknown = candidate_resource.status is ResourceDecisionStatus.DEFER
                if resource_reason is not None:
                    reason = resource_reason
                    is_unknown = resource_unknown
            if reason is None:
                viable.append(
                    replace(
                        candidate,
                        usability=(
                            candidate.usability.with_request_eligibility()
                            if candidate.usability is not None
                            else None
                        ),
                    )
                )
            elif is_unknown:
                unknown.append(f"{candidate.provider_id}/{candidate.model_id}: {reason}")
            else:
                rejected.append(f"{candidate.provider_id}/{candidate.model_id}: {reason}")
            if reason is not None:
                rejected_facts.append((candidate.identity.storage_key, reason[:128]))
            if reason is not None and candidate.usability is not None:
                rejected_evidence.extend(
                    (
                        ("rejected_identity", candidate.identity.storage_key),
                        ("rejected_usability_status", candidate.usability.status.value),
                        ("rejected_usability_reason", candidate.usability.effective_reason.value),
                        (
                            "rejected_usability_source",
                            _safe_usability_source(candidate.usability.source),
                        ),
                        ("rejected_usability_freshness", candidate.usability.freshness.value),
                    )
                )
        if viable:
            viable.sort(key=lambda item: self._sort_key(item, request))
            if resource_decision is not None and resource_decision.choose_smaller_model:
                viable.sort(
                    key=lambda item: (self._resource_size(item), self._sort_key(item, request))
                )
            return self._persist_decision(
                request,
                RouteDecision(
                    RouteStatus.SELECTED,
                    viable[0],
                    tuple(viable[1:]),
                    (f"selected {viable[0].identity.storage_key}",),
                    resource_decision,
                    evidence=self._evidence(viable[0]),
                ),
                tuple(rejected_facts),
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
        return self._persist_decision(
            request,
            RouteDecision(
                status,
                None,
                (),
                tuple((unknown or rejected or ["no compatible provider"])[:8]),
                resource_decision,
                evidence=tuple(rejected_evidence[:40]),
            ),
            tuple(rejected_facts),
        )

    def _persist_decision(
        self,
        request: RouteRequest,
        decision: RouteDecision,
        exclusions: tuple[tuple[str, str], ...],
        *,
        strategy: str | None = None,
        fusion_strategy: str | None = None,
    ) -> RouteDecision:
        if self._routing_store is None:
            return decision
        selected = decision.primary
        record = RoutingDecisionRecord(
            decision_id=str(uuid4()),
            decided_at=self._clock(),
            route_kind="model",
            selected_identity=(selected.identity.storage_key if selected is not None else None),
            role=request.role.value,
            task_class=request.task_class,
            policy=request.policy.value,
            privacy_classification=request.effective_privacy_context().classification.value,
            required_capabilities=tuple(sorted(request.required_capabilities)),
            strategy=strategy or request.policy.value,
            alternative_identities=tuple(
                candidate.identity.storage_key for candidate in decision.fallbacks[:4]
            ),
            exclusions=exclusions[:8],
            quality_score=selected.quality if selected is not None else None,
            sample_count=(
                selected.cookbook.sample_count if selected and selected.cookbook else None
            ),
            evidence_sufficiency=(
                selected.cookbook.evidence_sufficiency.value
                if selected is not None and selected.cookbook is not None
                else None
            ),
            resource_status=(
                decision.resource_decision.status.value
                if decision.resource_decision is not None
                else None
            ),
            protected_headroom=(
                request.priority
                in {
                    ResourcePriority.BACKGROUND,
                    ResourcePriority.MAINTENANCE,
                    ResourcePriority.BENCHMARK,
                    ResourcePriority.INDEXING,
                }
                if decision.resource_decision is not None
                else None
            ),
            affinity_current=(
                selected is not None
                and request.current_identity is not None
                and selected.identity == request.current_identity
            ),
            affinity_warm=(selected is not None and selected.identity in request.warm_identities),
            switching_cost_ms=(
                selected.measurement.load_seconds * 1000.0
                if selected is not None
                and selected.measurement is not None
                and selected.measurement.load_seconds is not None
                else selected.benchmark.load_latency_ms
                if selected is not None
                and selected.benchmark is not None
                and selected.benchmark.load_latency_ms is not None
                else None
            ),
            predicted_latency_ms=selected.latency if selected is not None else None,
            predicted_cost=selected.cost if selected is not None else None,
            fallback_identities=tuple(
                candidate.identity.storage_key for candidate in decision.fallbacks[:4]
            ),
            fusion_strategy=fusion_strategy,
        )
        self._routing_store.record_decision(record)
        return replace(decision, decision_id=record.decision_id)

    def resource_budget_for(
        self, candidate: RouteCandidate, request: RouteRequest
    ) -> ResourceBudget:
        """Return the trusted candidate-specific execution budget."""

        if not isinstance(candidate, RouteCandidate) or not isinstance(request, RouteRequest):
            raise ValueError("Resource budget input is malformed")
        measurement_ram = (
            candidate.measurement.peak_ram_bytes if candidate.measurement is not None else None
        )
        measurement_vram = (
            candidate.measurement.peak_vram_bytes if candidate.measurement is not None else None
        )
        return ResourceBudget(
            ram_bytes=measurement_ram
            if measurement_ram is not None
            else candidate.model.ram_bytes
            if candidate.local
            else None,
            vram_bytes=measurement_vram
            if measurement_vram is not None
            else candidate.model.vram_bytes
            if candidate.local
            else None,
            concurrency=(
                min(request.concurrency, candidate.model.max_concurrency)
                if candidate.model.max_concurrency is not None
                else request.concurrency
            ),
            duration_seconds=120.0,
        )

    @property
    def resource_governor(self) -> ResourceGovernor | None:
        return self._resource_governor

    @staticmethod
    def _evidence(candidate: RouteCandidate) -> tuple[tuple[str, str], ...]:
        evidence: list[tuple[str, str]] = [("identity", candidate.identity.storage_key)]
        if candidate.usability is not None:
            usability = candidate.usability
            observed_at = (
                usability.observed_at.isoformat()
                if usability.observed_at is not None
                else "unknown"
            )
            expires_at = (
                usability.expires_at.isoformat() if usability.expires_at is not None else "none"
            )
            evidence.extend(
                (
                    ("usability_status", usability.status.value),
                    ("usability_reason", usability.effective_reason.value),
                    ("usability_source", _safe_usability_source(usability.source)),
                    ("usability_freshness", usability.freshness.value),
                    ("usability_observed_at", observed_at),
                    ("usability_expires_at", expires_at),
                )
            )
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

    def _candidate_usability(
        self,
        candidate: RouteCandidate,
        request: RouteRequest,
        health: dict[str, ProviderHealthSnapshot],
    ) -> ModelUsabilityEvidence:
        """Compose provider, model, and request evidence in one contract."""

        provider_id = candidate.provider_id.casefold()
        model_id = candidate.model_id.casefold()
        values: list[ModelUsabilityEvidence] = [
            ModelUsabilityEvidence(
                configured=True,
                provider_id=candidate.provider_id,
                model_id=candidate.model_id,
                source="provider_registry",
                detail="registry configuration proves configuration only",
            )
        ]
        status = health.get(provider_id)
        if status is not None:
            health_known = status.available or status.detail not in {
                KnowledgeAvailability.UNKNOWN.value,
                KnowledgeAvailability.STALE.value,
            }
            values.append(
                ModelUsabilityEvidence(
                    connected=status.available if health_known else None,
                    reachable=status.available if health_known else None,
                    reason=(
                        UsabilityReason.UNKNOWN
                        if status.available or not health_known
                        else UsabilityReason.PROVIDER_OUTAGE
                    ),
                    provider_id=candidate.provider_id,
                    source="provider_health",
                    detail="provider health observation",
                )
            )
        values.append(self.usability_for(candidate.provider_id, candidate.model_id))
        for item in (*request.usability_evidence, *request.usability):
            if item.provider_id is not None and item.provider_id.casefold() != provider_id:
                continue
            if item.model_id is not None and item.model_id.casefold() != model_id:
                continue
            values.append(item)
        return merge_usability_evidence(*values)

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
        if model.lifecycle is ModelLifecycle.RETIRED:
            return "model lifecycle is retired", False
        if request.pinned_provider_id is not None and (
            candidate.provider_id.casefold() != request.pinned_provider_id.casefold()
        ):
            return "provider is excluded by the per-step provider pin", False
        if request.pinned_model_id is not None and (
            candidate.model_id.casefold() != request.pinned_model_id.casefold()
        ):
            return "model is excluded by the per-step model pin", False
        if self._policy_engine is not None:
            policy_decision = self._policy_engine.evaluate(
                candidate.identity,
                model,
                explicit_selection=request.explicit_selection,
                approval=request.guarded_approval,
                actor_id=request.actor_id,
                task_id=request.task_class,
                purpose=request.purpose,
                scope=request.approval_scope,
                estimated_cost=candidate.cost,
                unverified=not candidate.reliability_sufficient,
                now=self._clock(),
            )
            if not policy_decision.allowed:
                return policy_decision.reason, False
        if self._task_quarantine is not None and self._task_quarantine.is_quarantined(
            candidate.identity, request.task_class
        ):
            return "route is quarantined for this task family", False
        budget = request.budget_ledger or self._budget_ledger
        if budget is not None:
            estimated = request.estimated_cost
            if estimated is None:
                estimated = candidate.cost
            if not budget.estimated_allowed(estimated, now=self._clock()):
                return "cloud budget gate rejected route", False
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
        usability = candidate.usability
        if (
            usability is not None
            and usability.status_at(self._clock()) is ModelUsabilityStatus.NOT_USABLE
        ):
            return (
                f"provider/model is not currently usable: {usability.effective_reason.value}",
                False,
            )
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
        preferred_model = (
            0.0
            if request.preferred_model_id
            and candidate.model_id.casefold() == request.preferred_model_id.casefold()
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
        switch_penalty = ProviderRouter._switch_penalty(candidate, request)
        if request.minimum_expected_reliability is not None:
            if request.policy is RoutingPolicy.LOWEST_COST:
                return (
                    switch_penalty,
                    preferred_model,
                    cost,
                    latency,
                    local,
                    reliability,
                    quality,
                    identity,
                )
            if request.policy is RoutingPolicy.SPEED_FIRST:
                return (
                    switch_penalty,
                    preferred_model,
                    latency,
                    cost,
                    local,
                    reliability,
                    quality,
                    identity,
                )
            if request.policy is RoutingPolicy.PREFER_LOCAL:
                return (
                    switch_penalty,
                    preferred_model,
                    local,
                    cost,
                    latency,
                    reliability,
                    quality,
                    identity,
                )
            if request.policy is RoutingPolicy.BALANCED:
                return (
                    switch_penalty,
                    preferred_model,
                    local,
                    cost,
                    latency,
                    ProviderRouter._resource_size(candidate),
                    reliability,
                    identity,
                )
        if request.policy is RoutingPolicy.QUALITY_FIRST:
            return (
                reliability_tier,
                reliability,
                switch_penalty,
                preferred_model,
                preferred,
                quality,
                local,
                latency,
                identity,
            )
        if request.policy is RoutingPolicy.SPEED_FIRST:
            return (
                reliability_tier,
                reliability,
                switch_penalty,
                preferred_model,
                latency,
                preferred,
                local,
                quality,
                identity,
            )
        if request.policy is RoutingPolicy.LOWEST_COST:
            return (
                reliability_tier,
                reliability,
                switch_penalty,
                preferred_model,
                cost,
                preferred,
                local,
                quality,
                identity,
            )
        if request.policy in {
            RoutingPolicy.LOCAL_ONLY,
            RoutingPolicy.PRIVACY_STRICT,
            RoutingPolicy.PREFER_LOCAL,
        }:
            return (
                reliability_tier,
                reliability,
                switch_penalty,
                preferred_model,
                local,
                preferred,
                quality,
                latency,
                identity,
            )
        return (
            reliability_tier,
            reliability,
            switch_penalty,
            preferred_model,
            preferred,
            local,
            quality,
            latency,
            identity,
        )

    @staticmethod
    def _switch_penalty(candidate: RouteCandidate, request: RouteRequest) -> float:
        current = request.current_identity
        if (
            current is None
            or candidate.identity == current
            or candidate.identity in request.warm_identities
        ):
            return 0.0
        if request.switching_cost_budget_ms is None:
            return 0.0
        benchmark_load = (
            candidate.benchmark.load_latency_ms if candidate.benchmark is not None else None
        )
        measurement_load = (
            candidate.measurement.load_seconds * 1000.0
            if candidate.measurement is not None and candidate.measurement.load_seconds is not None
            else None
        )
        load_latency = benchmark_load if benchmark_load is not None else measurement_load
        if load_latency is None:
            load_latency = math.inf
        quality_gain = (
            candidate.quality - request.current_quality
            if candidate.quality is not None and request.current_quality is not None
            else None
        )
        if load_latency > request.switching_cost_budget_ms and (
            quality_gain is None or quality_gain < request.minimum_quality_gain_to_switch
        ):
            return 1.0
        return 0.0

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


class FusionMode(StrEnum):
    NEVER = "never"
    AUTO = "auto"
    REQUIRE = "require"


@dataclass(frozen=True, slots=True)
class FusionPolicy:
    """Conservative model-only fusion policy."""

    mode: FusionMode = FusionMode.AUTO
    max_sources: int = 2
    minimum_complexity: str = "high"
    minimum_quality_score: float | None = 0.70
    allow_quality_first: bool = True
    allow_exploration: bool = False
    synthesis_enabled: bool = False

    def __post_init__(self) -> None:
        if not isinstance(self.mode, FusionMode) or not 1 <= self.max_sources <= 2:
            raise ValueError("Fusion policy is invalid")
        if self.minimum_complexity not in {"medium", "high", "critical"}:
            raise ValueError("Fusion complexity threshold is invalid")
        if self.minimum_quality_score is not None and not 0.0 <= self.minimum_quality_score <= 1.0:
            raise ValueError("Fusion quality threshold is invalid")
        if type(self.allow_quality_first) is not bool or type(self.allow_exploration) is not bool:
            raise ValueError("Fusion policy flags are invalid")
        if self.synthesis_enabled:
            raise ValueError("V1 synthesis is intentionally unsupported")


@dataclass(frozen=True, slots=True)
class FusionDispatchResult:
    final_result: GenerationResult | None
    source_results: tuple[DispatchResult, ...]
    planned_source_identities: tuple[str, ...]
    actual_source_identities: tuple[str, ...]
    fused: bool
    degraded_to_single: bool
    synthesis_result: GenerationResult | None = None
    decision_id: str | None = None


class FusionDispatchError(RuntimeError):
    """Fusion could not produce a safe bounded result."""


class FusionCoordinator:
    """Coordinate bounded model legs through the ordinary dispatcher only."""

    def __init__(
        self,
        router: ProviderRouter,
        dispatcher: InferenceDispatcher,
        *,
        policy: FusionPolicy | None = None,
        resilience: Any | None = None,
    ) -> None:
        if not isinstance(router, ProviderRouter) or not isinstance(
            dispatcher, InferenceDispatcher
        ):
            raise TypeError("Fusion requires the canonical router and dispatcher")
        self._router = router
        self._dispatcher = dispatcher
        self._policy = policy or FusionPolicy()
        self._resilience = resilience

    @property
    def policy(self) -> FusionPolicy:
        return self._policy

    async def generate(
        self,
        request: GenerationRequest,
        intent: RouteRequest,
        *,
        decision: RouteDecision | None = None,
    ) -> FusionDispatchResult:
        if not isinstance(request, GenerationRequest) or not isinstance(intent, RouteRequest):
            raise ValueError("Fusion input is malformed")
        selected = decision or self._router.route(intent)
        sources = self._sources(selected, intent)
        if not self._should_fuse(intent):
            result = await self._dispatcher.generate(request, intent, decision=selected)
            actual_identity = (
                result.decision.primary.identity.storage_key
                if result.decision.primary is not None
                else None
            )
            return FusionDispatchResult(
                result.result,
                (result,),
                (selected.primary.identity.storage_key,) if selected.primary is not None else (),
                (actual_identity,) if actual_identity is not None else (),
                False,
                False,
                decision_id=selected.decision_id,
            )
        if len(sources) < 2:
            if not sources:
                raise FusionDispatchError("No independently eligible fusion source remains")
            single_decision = replace(selected, primary=sources[0], fallbacks=())
            result = await self._dispatcher.generate(request, intent, decision=single_decision)
            actual_identity = (
                result.decision.primary.identity.storage_key
                if result.decision.primary is not None
                else None
            )
            return FusionDispatchResult(
                result.result,
                (result,),
                (sources[0].identity.storage_key,),
                (actual_identity,) if actual_identity is not None else (),
                False,
                True,
                decision_id=selected.decision_id,
            )
        fusion_decision = self._router.persist_fusion_decision(intent, selected, sources)
        successes: list[DispatchResult] = []
        unknown_failure = False
        for source in sources:
            leg_decision = replace(
                fusion_decision,
                primary=source,
                fallbacks=(),
            )
            try:
                successes.append(
                    await self._dispatcher.generate(request, intent, decision=leg_decision)
                )
            except InferenceDispatchError as error:
                unknown_failure = unknown_failure or error.status is RouteStatus.UNKNOWN
        actual_identities = tuple(
            dict.fromkeys(
                result.decision.primary.identity.storage_key
                for result in successes
                if result.decision.primary is not None
            )
        )
        if len(actual_identities) < 2:
            if not successes:
                raise FusionDispatchError(
                    "No fusion source completed safely"
                    + ("; source outcome is unknown" if unknown_failure else "")
                )
            return FusionDispatchResult(
                successes[0].result,
                tuple(successes),
                tuple(source.identity.storage_key for source in sources),
                actual_identities,
                False,
                True,
                decision_id=fusion_decision.decision_id,
            )
        return FusionDispatchResult(
            successes[0].result,
            tuple(successes),
            tuple(source.identity.storage_key for source in sources),
            actual_identities,
            True,
            False,
            decision_id=fusion_decision.decision_id,
        )

    def _should_fuse(self, intent: RouteRequest) -> bool:
        if self._policy.mode is FusionMode.NEVER or not self._policy.allow_quality_first:
            return False
        if intent.requires_tools or intent.role is ModelRole.TOOL_USE:
            return False
        rank = {"low": 0, "medium": 1, "high": 2, "critical": 3}
        qualifies = (
            rank.get(intent.complexity.casefold(), 0) >= rank[self._policy.minimum_complexity]
        )
        return qualifies or (
            self._policy.mode is FusionMode.REQUIRE and intent.policy is RoutingPolicy.QUALITY_FIRST
        )

    def _sources(self, decision: RouteDecision, intent: RouteRequest) -> tuple[RouteCandidate, ...]:
        candidates = (() if decision.primary is None else (decision.primary,)) + decision.fallbacks
        valid: list[RouteCandidate] = []
        identities: set[str] = set()
        for candidate in candidates:
            identity = candidate.identity.storage_key
            if identity in identities:
                continue
            if self._policy.minimum_quality_score is not None and (
                candidate.quality is None or candidate.quality < self._policy.minimum_quality_score
            ):
                continue
            if self._resilience is not None:
                key = self._resilience.key(identity, "model", intent.task_class, intent.role.value)
                allowed, _probe = self._resilience.admit(key)
                if (
                    not allowed
                    or not self._policy.allow_exploration
                    and not self._resilience.is_lkgr(key)
                ):
                    # A closed route with insufficient evidence is valid for ordinary routing,
                    # but experimental exploration is not compounded with fusion.
                    snapshot = self._resilience.snapshot(key)
                    if snapshot.state.value != "closed" or not self._resilience.is_lkgr(key):
                        continue
            identities.add(identity)
            valid.append(candidate)
            if len(valid) >= self._policy.max_sources:
                break
        return tuple(valid)


class InferenceDispatcher:
    """Execute the router's decision through registry-owned provider factories."""

    def __init__(
        self,
        router: ProviderRouter,
        registry: ProviderRegistry,
        *,
        configurations: Mapping[str, Mapping[str, Any]] | None = None,
        providers: Mapping[str, Any] | None = None,
        lifecycle: InferenceLifecycle | None = None,
        resource_governor: ResourceGovernor | None = None,
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
        self._lifecycle = lifecycle
        self._resource_governor = (
            resource_governor
            if resource_governor is not None
            else getattr(router, "resource_governor", None)
        )
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
        recovered_providers: set[str] = set()
        for attempt in range(self._max_attempts):
            candidate = current_decision.primary
            if candidate is None:
                raise InferenceDispatchError("No eligible inference model", current_decision)
            in_use = False
            reservation_id = None
            release_reason = ReservationReleaseReason.COMPLETE
            if self._resource_governor is not None:
                admission = self._resource_governor.reserve(
                    f"inference.{candidate.identity.storage_key}",
                    current_intent.priority,
                    self._router.resource_budget_for(candidate, current_intent),
                )
                if not admission.allowed:
                    if attempt + 1 >= self._max_attempts:
                        blocked = replace(
                            current_decision,
                            status=(
                                RouteStatus.UNKNOWN
                                if admission.status is ResourceDecisionStatus.DEFER
                                else RouteStatus.RESOURCE_UNAVAILABLE
                            ),
                            primary=None,
                            reasons=(admission.reason,),
                            resource_decision=admission,
                        )
                        raise InferenceDispatchError("Inference resource admission failed", blocked)
                    current_intent = replace(
                        current_intent,
                        excluded_identities=(
                            *current_intent.excluded_identities,
                            candidate.identity,
                        ),
                    )
                    current_decision = self.route(current_intent)
                    rerouted = True
                    continue
                reservation_id = admission.reservation_id
            try:
                if self._lifecycle is not None:
                    await self._lifecycle.prepare_for_inference(candidate, current_intent)
                    self._lifecycle.begin_inference(candidate)
                    in_use = True
                current_request = self._request_for(request, candidate)
                provider = self._provider_for(candidate)
                result = await provider.generate(current_request)
                if not isinstance(result, GenerationResult) or result.model != candidate.model_id:
                    raise RuntimeError("provider/model identity mismatch")
                self._router.record_success(candidate.identity)
                self._router.record_execution_outcome(
                    current_decision,
                    executed_identity=candidate.identity.storage_key,
                    operational_outcome="succeeded",
                    semantic_outcome=SemanticOutcome.UNVERIFIED,
                    rerouted=rerouted,
                    retry_count=attempt,
                )
                return DispatchResult(
                    result,
                    current_decision,
                    rerouted,
                )
            except PrivacyBlockedError as error:
                release_reason = ReservationReleaseReason.CRASH
                self._router.record_execution_outcome(
                    current_decision,
                    executed_identity=candidate.identity.storage_key,
                    operational_outcome="privacy_block",
                    semantic_outcome=SemanticOutcome.UNKNOWN,
                    rerouted=rerouted,
                    retry_count=attempt,
                )
                self._router.record_failure(
                    candidate.identity,
                    UsabilityReason.PRIVACY_BLOCKED,
                    detail="privacy gateway rejected the outbound request",
                )
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
                release_reason = ReservationReleaseReason.CANCEL
                raise
            except Exception as error:
                failure = _failure_class(error)
                release_reason = (
                    ReservationReleaseReason.TIMEOUT
                    if failure is RouteFailureClass.TIMEOUT
                    else ReservationReleaseReason.CRASH
                )
                usability_reason = _usability_reason(error)
                self._router.record_execution_outcome(
                    current_decision,
                    executed_identity=candidate.identity.storage_key,
                    operational_outcome=failure.value,
                    semantic_outcome=(
                        SemanticOutcome.UNKNOWN
                        if failure is RouteFailureClass.UNKNOWN_OUTCOME
                        else SemanticOutcome.UNVERIFIED
                    ),
                    rerouted=rerouted,
                    retry_count=attempt,
                )
                if usability_reason is not None:
                    self._router.record_failure(candidate.identity, usability_reason)
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
                if (
                    failure is RouteFailureClass.PROVIDER_UNAVAILABLE
                    and candidate.provider_id.casefold() not in recovered_providers
                ):
                    recovered_providers.add(candidate.provider_id.casefold())
                    if self._lifecycle is not None:
                        await self._lifecycle.recover_provider(candidate.provider_id)
                if attempt + 1 >= self._max_attempts:
                    exhausted = RouteDecision(
                        RouteStatus.ATTEMPTS_EXHAUSTED,
                        None,
                        current_decision.fallbacks,
                        (f"inference attempt failed: {type(error).__name__}",),
                        current_decision.resource_decision,
                        _failure_evidence(current_decision, usability_reason),
                    )
                    raise InferenceDispatchError(
                        "Inference attempts exhausted", exhausted
                    ) from error
                current_intent = replace(
                    current_intent,
                    previous_failure=failure,
                    excluded_identities=(*current_intent.excluded_identities, candidate.identity),
                )
            finally:
                if in_use and self._lifecycle is not None:
                    self._lifecycle.end_inference(candidate)
                if reservation_id is not None and self._resource_governor is not None:
                    self._resource_governor.release(reservation_id, release_reason)
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
        recovered_providers: set[str] = set()
        for attempt in range(self._max_attempts):
            candidate = current_decision.primary
            if candidate is None:
                raise InferenceDispatchError("No eligible inference model", current_decision)
            yielded = False
            in_use = False
            reservation_id = None
            release_reason = ReservationReleaseReason.COMPLETE
            if self._resource_governor is not None:
                admission = self._resource_governor.reserve(
                    f"inference.{candidate.identity.storage_key}",
                    current_intent.priority,
                    self._router.resource_budget_for(candidate, current_intent),
                )
                if not admission.allowed:
                    if attempt + 1 >= self._max_attempts:
                        blocked = replace(
                            current_decision,
                            status=(
                                RouteStatus.UNKNOWN
                                if admission.status is ResourceDecisionStatus.DEFER
                                else RouteStatus.RESOURCE_UNAVAILABLE
                            ),
                            primary=None,
                            reasons=(admission.reason,),
                            resource_decision=admission,
                        )
                        raise InferenceDispatchError("Streaming resource admission failed", blocked)
                    current_intent = replace(
                        current_intent,
                        excluded_identities=(
                            *current_intent.excluded_identities,
                            candidate.identity,
                        ),
                    )
                    current_decision = self.route(current_intent)
                    rerouted = True
                    continue
                reservation_id = admission.reservation_id
            try:
                if self._lifecycle is not None:
                    await self._lifecycle.prepare_for_inference(candidate, current_intent)
                    self._lifecycle.begin_inference(candidate)
                    in_use = True
                provider = self._provider_for(candidate)
                async for chunk in provider.stream(self._request_for(request, candidate)):
                    yielded = True
                    yield DispatchChunk(chunk, current_decision, rerouted)
                self._router.record_success(candidate.identity)
                self._router.record_execution_outcome(
                    current_decision,
                    executed_identity=candidate.identity.storage_key,
                    operational_outcome="succeeded",
                    semantic_outcome=SemanticOutcome.UNVERIFIED,
                    rerouted=rerouted,
                    retry_count=attempt,
                )
                return
            except PrivacyBlockedError as error:
                release_reason = ReservationReleaseReason.CRASH
                self._router.record_execution_outcome(
                    current_decision,
                    executed_identity=candidate.identity.storage_key,
                    operational_outcome="privacy_block",
                    semantic_outcome=SemanticOutcome.UNKNOWN,
                    rerouted=rerouted,
                    retry_count=attempt,
                )
                self._router.record_failure(
                    candidate.identity,
                    UsabilityReason.PRIVACY_BLOCKED,
                    detail="privacy gateway rejected the outbound request",
                )
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
                release_reason = ReservationReleaseReason.CANCEL
                raise
            except Exception as error:
                failure = _failure_class(error)
                release_reason = (
                    ReservationReleaseReason.TIMEOUT
                    if failure is RouteFailureClass.TIMEOUT
                    else ReservationReleaseReason.CRASH
                )
                usability_reason = _usability_reason(error)
                self._router.record_execution_outcome(
                    current_decision,
                    executed_identity=candidate.identity.storage_key,
                    operational_outcome=failure.value,
                    semantic_outcome=(
                        SemanticOutcome.UNKNOWN
                        if failure is RouteFailureClass.UNKNOWN_OUTCOME
                        else SemanticOutcome.UNVERIFIED
                    ),
                    rerouted=rerouted,
                    retry_count=attempt,
                )
                if usability_reason is not None:
                    self._router.record_failure(candidate.identity, usability_reason)
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
                if (
                    failure is RouteFailureClass.PROVIDER_UNAVAILABLE
                    and candidate.provider_id.casefold() not in recovered_providers
                ):
                    recovered_providers.add(candidate.provider_id.casefold())
                    if self._lifecycle is not None:
                        await self._lifecycle.recover_provider(candidate.provider_id)
                if yielded or attempt + 1 >= self._max_attempts:
                    exhausted = RouteDecision(
                        RouteStatus.ATTEMPTS_EXHAUSTED,
                        None,
                        current_decision.fallbacks,
                        (f"stream attempt failed: {type(error).__name__}",),
                        current_decision.resource_decision,
                        _failure_evidence(current_decision, usability_reason),
                    )
                    raise InferenceDispatchError(
                        "Streaming inference attempts exhausted", exhausted
                    ) from error
                current_intent = replace(
                    current_intent,
                    previous_failure=failure,
                    excluded_identities=(*current_intent.excluded_identities, candidate.identity),
                )
            finally:
                if in_use and self._lifecycle is not None:
                    self._lifecycle.end_inference(candidate)
                if reservation_id is not None and self._resource_governor is not None:
                    self._resource_governor.release(reservation_id, release_reason)
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
        configured_model: object | None = None
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
        else:
            configured_model = self._configurations.get(candidate.provider_id.casefold(), {}).get(
                "model"
            )
        if (
            raw is not None
            and configured_model is not None
            and candidate.model_id != configured_model
            and not isinstance(raw, PrivacyGuardedProvider)
        ):
            # A provider instance configured for model A cannot execute a route
            # claiming model B.  Recreate it through the registry-owned factory.
            if len(self._owned) >= self._max_cached_providers:
                raise RuntimeError("bounded provider cache is exhausted")
            configuration = dict(self._configurations.get(candidate.provider_id.casefold(), {}))
            configuration.update(
                {"model": candidate.model_id, "context_limit": candidate.model.context_limit}
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
    detail = str(error).casefold()
    if "timeout" in name:
        return RouteFailureClass.TIMEOUT
    if "privacy" in name:
        return RouteFailureClass.PRIVACY_BLOCK
    if "rate" in name or "429" in detail or "too many requests" in detail:
        return RouteFailureClass.RATE_LIMITED
    if "quota" in name or "credit" in detail or "quota" in detail:
        return RouteFailureClass.QUOTA
    if "billing" in name or "payment" in detail or "subscription" in detail:
        return RouteFailureClass.BILLING
    if "auth" in name or "credential" in detail or "401" in detail:
        return RouteFailureClass.AUTHENTICATION
    if "model" in name and "unavailable" in name:
        return RouteFailureClass.MODEL_UNAVAILABLE
    if "structured" in name or "structured" in detail:
        return RouteFailureClass.MALFORMED_STRUCTURED_OUTPUT
    if "tool" in name or "tool" in detail:
        return RouteFailureClass.INVALID_TOOL_CALL
    if "oom" in name or "outofmemory" in name or "resource" in detail:
        return RouteFailureClass.RESOURCE_OOM
    if "verification" in name or "verification" in detail:
        return RouteFailureClass.VERIFICATION_FAILURE
    if "unavailable" in name or "connect" in name:
        return RouteFailureClass.PROVIDER_UNAVAILABLE
    return RouteFailureClass.UNKNOWN_OUTCOME


def _usability_reason(error: BaseException) -> UsabilityReason | None:
    """Classify only provider failures supported by trusted typed evidence."""

    name = type(error).__name__.casefold()
    detail = str(error).casefold()
    code = str(getattr(error, "code", "")).casefold()
    combined = f"{name} {detail} {code}"
    if "privacy" in combined:
        return UsabilityReason.PRIVACY_BLOCKED
    if "rate" in combined or "429" in combined or "too many requests" in combined:
        return UsabilityReason.RATE_LIMITED
    if "quota" in combined or "credit" in combined or "usage limit" in combined:
        return UsabilityReason.QUOTA_EXHAUSTED
    if "billing" in combined or "payment" in combined or "subscription" in combined:
        return UsabilityReason.BILLING_BLOCKED
    if "budget" in combined:
        return UsabilityReason.BUDGET_EXHAUSTED
    if "credential" in combined or "unauth" in combined or "401" in combined:
        return UsabilityReason.INVALID_CREDENTIALS
    if "entitl" in combined or "access denied" in combined or "403" in combined:
        return UsabilityReason.MODEL_NOT_ENTITLED
    if "not found" in combined or "modelunavailable" in combined:
        return UsabilityReason.MODEL_NOT_FOUND
    if "model" in combined and "unavailable" in combined:
        return UsabilityReason.MODEL_UNAVAILABLE
    if "oom" in combined or "outofmemory" in combined or "resource" in combined:
        return UsabilityReason.LOCAL_RESOURCE_BLOCKED
    if "timeout" in combined:
        return UsabilityReason.NETWORK_UNAVAILABLE
    if "unavailable" in combined or "connect" in combined or "outage" in combined:
        return UsabilityReason.PROVIDER_OUTAGE
    return None


def _failure_evidence(
    decision: RouteDecision, reason: UsabilityReason | None
) -> tuple[tuple[str, str], ...]:
    if reason is None:
        return decision.evidence
    return (("usability_failure_reason", reason.value), *decision.evidence)


def _safe_usability_source(source: str) -> str:
    """Keep route projections descriptive without echoing credential material."""

    lowered = source.casefold()
    if any(token in lowered for token in ("secret", "token", "password", "credential", "api_key")):
        return "redacted"
    return source[:128]


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
        router: ProviderRouter | None = None,
    ) -> None:
        self._knowledge = knowledge
        self._locality = {key.casefold(): value for key, value in (provider_locality or {}).items()}
        self._router = router

    def record_failure(
        self,
        identity: ModelIdentity,
        reason: UsabilityReason,
        *,
        detail: str = "trusted provider failure feedback",
    ) -> ModelUsabilityEvidence | None:
        """Forward typed operational feedback to the existing router state."""

        if self._router is None:
            return None
        return self._router.record_failure(identity, reason, detail=detail)

    def record_success(self, identity: ModelIdentity) -> ModelUsabilityEvidence | None:
        """Forward positive operational feedback without inventing quota facts."""

        if self._router is None:
            return None
        return self._router.record_success(identity)

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
