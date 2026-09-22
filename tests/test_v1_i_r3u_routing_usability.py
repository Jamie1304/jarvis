from __future__ import annotations

from datetime import UTC, datetime, timedelta
from typing import Any, cast
from uuid import uuid4

import httpx
import pytest
from jarvis.ai.knowledge import ModelIdentity
from jarvis.ai.models import (
    ChatMessage,
    GenerationRequest,
    GenerationResult,
    MessageRole,
    ModelRole,
    PrivacyClassification,
    PrivacyContext,
)
from jarvis.ai.portfolio import ModelUsabilityEvidence as PortfolioUsabilityEvidence
from jarvis.ai.providers.ollama import OllamaProvider
from jarvis.ai.providers.registry import (
    ModelMetadata,
    ProviderDefinition,
    ProviderLocality,
    ProviderMetadata,
    ProviderRegistry,
    VoiceProviderDefinition,
    VoiceProviderKind,
)
from jarvis.ai.routing import (
    InferenceDispatcher,
    ProviderHealthSnapshot,
    ProviderRouter,
    RouteRequest,
    RouteStatus,
    RoutingPolicy,
)
from jarvis.ai.usability import (
    ModelUsabilityEvidence,
    ModelUsabilityStatus,
    UsabilityFreshness,
    UsabilityReason,
    UsabilityValidationError,
    evidence_for_failure,
    evidence_for_success,
    merge_usability_evidence,
)
from jarvis.core.errors import ProviderError

from tests.fakes import FakeAIProvider


def _model(
    model_id: str,
    *,
    quality: float = 0.5,
    input_cost: float = 1.0,
    output_cost: float = 1.0,
) -> ModelMetadata:
    return ModelMetadata(
        model_id,
        8_192,
        roles=frozenset({ModelRole.GENERAL}),
        modalities=frozenset({"text"}),
        quality_score=quality,
        input_cost_per_million=input_cost,
        output_cost_per_million=output_cost,
    )


def _registry(
    *providers: tuple[str, tuple[ModelMetadata, ...]], local: frozenset[str] = frozenset()
) -> ProviderRegistry:
    definitions = tuple(
        ProviderDefinition(
            ProviderMetadata(
                provider_id,
                provider_id.title(),
                "r3u-fixture",
                local_only=provider_id in local,
                locality=(
                    ProviderLocality.LOCAL if provider_id in local else ProviderLocality.REMOTE
                ),
            ),
            lambda _configuration: FakeAIProvider(),
            models,
        )
        for provider_id, models in providers
    )
    return ProviderRegistry(definitions)


def _request(**values: Any) -> RouteRequest:
    defaults: dict[str, Any] = {
        "task": "answer",
        "profile": "r3u",
        "classification": "safe_public",
        "policy": RoutingPolicy.BALANCED,
    }
    defaults.update(values)
    return RouteRequest(**defaults)


def _usable(
    provider_id: str,
    model_id: str | None = None,
    *,
    observed_at: datetime | None = None,
    expires_at: datetime | None = None,
) -> ModelUsabilityEvidence:
    return ModelUsabilityEvidence(
        configured=True,
        connected=True,
        reachable=True,
        authenticated=True,
        entitled=True,
        quota_usable=True,
        capacity_usable=True,
        model_usable=True,
        policy_eligible=True,
        resource_eligible=True,
        request_usable=True,
        provider_id=provider_id,
        model_id=model_id,
        source="r3u.deterministic",
        observed_at=observed_at,
        expires_at=expires_at,
        detail="deterministic provider-neutral evidence",
    )


def test_shared_contract_is_one_concept_and_unknown_is_not_proven() -> None:
    assert PortfolioUsabilityEvidence is ModelUsabilityEvidence
    assert (
        ModelUsabilityEvidence(configured=True, connected=True).status
        is ModelUsabilityStatus.UNKNOWN
    )
    assert _usable("provider", "model").proven_usable
    assert evidence_for_success("provider", "model").quota_usable is None, (
        "success must not invent remaining credits"
    )


def test_reason_taxonomy_and_failure_dimensions_are_provider_neutral() -> None:
    reasons = (
        UsabilityReason.INVALID_CREDENTIALS,
        UsabilityReason.AUTHENTICATION_UNAVAILABLE,
        UsabilityReason.QUOTA_EXHAUSTED,
        UsabilityReason.BILLING_BLOCKED,
        UsabilityReason.BUDGET_EXHAUSTED,
        UsabilityReason.MODEL_NOT_ENTITLED,
        UsabilityReason.MODEL_UNAVAILABLE,
        UsabilityReason.MODEL_NOT_FOUND,
        UsabilityReason.RATE_LIMITED,
        UsabilityReason.PROVIDER_CAPACITY_EXHAUSTED,
        UsabilityReason.PROVIDER_OUTAGE,
        UsabilityReason.NETWORK_UNAVAILABLE,
        UsabilityReason.POLICY_BLOCKED,
        UsabilityReason.PRIVACY_BLOCKED,
        UsabilityReason.LOCAL_RESOURCE_BLOCKED,
        UsabilityReason.TEMPORARILY_DEGRADED,
        UsabilityReason.UNKNOWN,
    )
    assert len({reason.value for reason in reasons}) == len(reasons)
    quota = evidence_for_failure(
        "provider",
        UsabilityReason.QUOTA_EXHAUSTED,
        model_id="model",
        cooldown_seconds=None,
    )
    assert quota.quota_usable is False
    assert quota.request_usable is False
    assert quota.effective_reason is UsabilityReason.QUOTA_EXHAUSTED
    timeout = evidence_for_failure(
        "provider", UsabilityReason.NETWORK_UNAVAILABLE, model_id="model"
    )
    assert timeout.reachable is False
    assert timeout.quota_usable is None
    for reason in reasons:
        evidence = evidence_for_failure("provider", reason, cooldown_seconds=0)
        assert evidence.request_usable is False
        assert evidence.reason is reason


def test_usability_contract_validates_typed_boundaries_and_composes_hard_gates() -> None:
    now = datetime.now(UTC)
    current = _usable(
        "provider",
        "model",
        observed_at=now,
        expires_at=now + timedelta(minutes=1),
    )
    assert current.freshness_at(now) is UsabilityFreshness.CURRENT
    assert current.effective_dimensions_at(now) == current.dimensions
    assert (
        current.with_request_eligibility(
            policy_eligible=False,
            resource_eligible=False,
            request_usable=False,
        ).status_at(now)
        is ModelUsabilityStatus.NOT_USABLE
    )

    already_blocked = ModelUsabilityEvidence(
        policy_eligible=False,
        resource_eligible=False,
        request_usable=False,
        provider_id="provider",
        model_id="model",
        detail="hard gate already denied",
    )
    composed = already_blocked.with_request_eligibility()
    assert composed.policy_eligible is False
    assert composed.resource_eligible is False
    assert composed.request_usable is False

    unknown_failure = ModelUsabilityEvidence(
        model_usable=False,
        provider_id="provider",
        model_id="model",
        detail="model was not usable",
    )
    assert unknown_failure.effective_reason is UsabilityReason.MODEL_UNAVAILABLE
    assert unknown_failure.merge(current).model_usable is True
    assert merge_usability_evidence().status is ModelUsabilityStatus.UNKNOWN

    with pytest.raises(UsabilityValidationError):
        ModelUsabilityEvidence(provider_id="")
    with pytest.raises(UsabilityValidationError):
        ModelUsabilityEvidence(provider_id=cast(Any, 7))
    with pytest.raises(UsabilityValidationError):
        ModelUsabilityEvidence(observed_at=datetime.now())
    with pytest.raises(UsabilityValidationError):
        ModelUsabilityEvidence(configured=cast(Any, "yes"))
    with pytest.raises(UsabilityValidationError):
        ModelUsabilityEvidence(reason=cast(Any, "unknown"))
    with pytest.raises(UsabilityValidationError):
        ModelUsabilityEvidence(source=" ")
    with pytest.raises(UsabilityValidationError):
        ModelUsabilityEvidence(observed_at=now, expires_at=now - timedelta(seconds=1))
    with pytest.raises(UsabilityValidationError):
        merge_usability_evidence(cast(Any, object()))
    with pytest.raises(UsabilityValidationError):
        evidence_for_failure("provider", cast(Any, "quota_exhausted"))
    with pytest.raises(UsabilityValidationError):
        evidence_for_failure("provider", UsabilityReason.UNKNOWN, cooldown_seconds=-1)


@pytest.mark.parametrize(
    ("reason", "field"),
    [
        (UsabilityReason.INVALID_CREDENTIALS, "authenticated"),
        (UsabilityReason.AUTHENTICATION_UNAVAILABLE, "authenticated"),
        (UsabilityReason.QUOTA_EXHAUSTED, "quota_usable"),
        (UsabilityReason.BILLING_BLOCKED, "quota_usable"),
        (UsabilityReason.BUDGET_EXHAUSTED, "policy_eligible"),
        (UsabilityReason.MODEL_NOT_ENTITLED, "entitled"),
        (UsabilityReason.MODEL_UNAVAILABLE, "model_usable"),
        (UsabilityReason.MODEL_NOT_FOUND, "model_usable"),
        (UsabilityReason.RATE_LIMITED, "capacity_usable"),
        (UsabilityReason.PROVIDER_CAPACITY_EXHAUSTED, "capacity_usable"),
        (UsabilityReason.PROVIDER_OUTAGE, "connected"),
        (UsabilityReason.NETWORK_UNAVAILABLE, "reachable"),
        (UsabilityReason.POLICY_BLOCKED, "policy_eligible"),
        (UsabilityReason.PRIVACY_BLOCKED, "policy_eligible"),
        (UsabilityReason.LOCAL_RESOURCE_BLOCKED, "resource_eligible"),
    ],
)
def test_known_not_usable_is_eliminated_before_ranking(reason: UsabilityReason, field: str) -> None:
    values: dict[str, bool | None] = {
        name: True
        for name in (
            "configured",
            "connected",
            "reachable",
            "authenticated",
            "entitled",
            "quota_usable",
            "capacity_usable",
            "model_usable",
            "policy_eligible",
            "resource_eligible",
            "request_usable",
        )
    }
    values[field] = False
    evidence = ModelUsabilityEvidence(
        **cast(Any, values),
        provider_id="provider",
        model_id="model",
        reason=reason,
        source="r3u.matrix",
        detail="deterministic rejection evidence",
    )
    decision = ProviderRouter(
        _registry(("provider", (_model("model", input_cost=0, output_cost=0),)))
    ).route(_request(usability_evidence=(evidence,), policy=RoutingPolicy.LOWEST_COST))
    assert decision.status is RouteStatus.UNAVAILABLE
    assert decision.primary is None
    assert reason.value in " ".join(decision.reasons)


def test_health_and_availability_do_not_prove_quota_or_model_usability() -> None:
    registry = _registry(("provider", (_model("model"),)))
    decision = ProviderRouter(registry).route(
        _request(provider_health=(ProviderHealthSnapshot("provider", True, "reachable"),))
    )
    assert decision.status is RouteStatus.SELECTED
    assert decision.primary is not None
    assert decision.primary.usability_status is ModelUsabilityStatus.UNKNOWN
    assert decision.primary.usability is not None
    assert not decision.primary.usability.proven_usable


def test_cross_provider_fallback_excludes_known_quota_exhausted_cheapest_route() -> None:
    registry = _registry(
        ("provider-a", (_model("cheap", quality=1.0, input_cost=0, output_cost=0),)),
        ("provider-b", (_model("available", quality=0.5, input_cost=4, output_cost=4),)),
    )
    quota = evidence_for_failure(
        "provider-a",
        UsabilityReason.QUOTA_EXHAUSTED,
        model_id="cheap",
        cooldown_seconds=None,
    )
    decision = ProviderRouter(registry).route(
        _request(policy=RoutingPolicy.LOWEST_COST, usability_evidence=(quota,))
    )
    assert decision.status is RouteStatus.SELECTED
    assert decision.primary is not None
    assert decision.primary.provider_id == "provider-b"
    assert all(item.provider_id != "provider-a" for item in decision.fallbacks)


def test_quality_first_also_excludes_known_unusable_high_quality_route() -> None:
    registry = _registry(
        ("provider-a", (_model("premium", quality=1.0),)),
        ("provider-b", (_model("standard", quality=0.5),)),
    )
    blocked = evidence_for_failure(
        "provider-a",
        UsabilityReason.BILLING_BLOCKED,
        model_id="premium",
        cooldown_seconds=None,
    )
    decision = ProviderRouter(registry).route(
        _request(policy=RoutingPolicy.QUALITY_FIRST, usability_evidence=(blocked,))
    )
    assert decision.primary is not None and decision.primary.provider_id == "provider-b"


def test_same_provider_model_entitlement_failure_does_not_block_alternative_model() -> None:
    registry = _registry(
        (
            "provider",
            (
                _model("premium", quality=1.0),
                _model("standard", quality=0.5),
            ),
        )
    )
    blocked = evidence_for_failure(
        "provider",
        UsabilityReason.MODEL_NOT_ENTITLED,
        model_id="premium",
        cooldown_seconds=None,
    )
    decision = ProviderRouter(registry).route(
        _request(policy=RoutingPolicy.QUALITY_FIRST, usability_evidence=(blocked,))
    )
    assert decision.primary is not None
    assert decision.primary.model_id == "standard"


def test_model_missing_is_distinct_from_reachable_provider() -> None:
    registry = _registry(("local", (_model("missing"),)), local=frozenset({"local"}))
    missing = evidence_for_failure(
        "local", UsabilityReason.MODEL_NOT_FOUND, model_id="missing", cooldown_seconds=None
    )
    decision = ProviderRouter(registry).route(
        _request(
            usability_evidence=(missing,), provider_health=(ProviderHealthSnapshot("local", True),)
        )
    )
    assert decision.status is RouteStatus.UNAVAILABLE
    assert "model_not_found" in " ".join(decision.reasons)


def test_unknown_and_stale_evidence_are_bounded_attempts_not_proven_success() -> None:
    now = datetime.now(UTC)
    registry = _registry(("provider", (_model("model"),)))
    unknown = ModelUsabilityEvidence(
        configured=True,
        connected=True,
        reachable=True,
        authenticated=True,
        model_usable=True,
        provider_id="provider",
        model_id="model",
        source="r3u.unknown-quota",
        observed_at=now,
        detail="quota endpoint is not available",
    )
    router = ProviderRouter(registry)
    decision = router.route(_request(usability_evidence=(unknown,)))
    assert decision.primary is not None
    assert decision.primary.usability_status is ModelUsabilityStatus.UNKNOWN
    assert decision.primary.usability is not None
    assert not decision.primary.usability.proven_usable

    stale_positive = _usable(
        "provider",
        "model",
        observed_at=now - timedelta(minutes=5),
        expires_at=now - timedelta(seconds=1),
    )
    stale_decision = router.route(_request(usability_evidence=(stale_positive,)))
    assert stale_decision.primary is not None
    assert stale_decision.primary.usability is not None
    assert stale_decision.primary.usability.freshness is UsabilityFreshness.STALE
    assert stale_decision.primary.usability.status is ModelUsabilityStatus.UNKNOWN


def test_stale_negative_does_not_permanently_blacklist_and_refresh_restores_proof() -> None:
    now = datetime.now(UTC)
    registry = _registry(("provider", (_model("model"),)))
    router = ProviderRouter(registry)
    stale_negative = evidence_for_failure(
        "provider",
        UsabilityReason.QUOTA_EXHAUSTED,
        model_id="model",
        observed_at=now - timedelta(minutes=5),
        cooldown_seconds=1,
    )
    router.set_usability_evidence(stale_negative)
    assert router.route(_request()).primary is not None
    refreshed = _usable("provider", "model", observed_at=now)
    router.set_usability_evidence(refreshed)
    decision = router.route(_request())
    assert decision.primary is not None
    assert decision.primary.usability_status is ModelUsabilityStatus.USABLE


def test_rate_limit_has_bounded_cooldown_and_does_not_blacklist_forever() -> None:
    now = [datetime.now(UTC)]
    registry = _registry(("provider", (_model("model"),)))
    router = ProviderRouter(
        registry,
        clock=lambda: now[0],
        rate_limit_cooldown_seconds=5,
    )
    identity = ModelIdentity("provider", "model")
    recorded = router.record_failure(identity, UsabilityReason.RATE_LIMITED)
    assert recorded.freshness is UsabilityFreshness.CURRENT
    assert router.route(_request()).primary is None
    now[0] += timedelta(seconds=6)
    decision = router.route(_request())
    assert decision.primary is not None
    assert decision.primary.usability is not None
    assert decision.primary.usability.expires_at == recorded.expires_at


def test_pinned_unusable_route_fails_truthfully_without_silent_fallback() -> None:
    registry = _registry(
        ("provider-a", (_model("a"),)),
        ("provider-b", (_model("b"),)),
    )
    blocked = evidence_for_failure(
        "provider-a", UsabilityReason.QUOTA_EXHAUSTED, model_id="a", cooldown_seconds=None
    )
    decision = ProviderRouter(registry).route(
        _request(
            pinned_provider_id="provider-a",
            pinned_model_id="a",
            usability_evidence=(blocked,),
        )
    )
    assert decision.primary is None
    assert decision.status is RouteStatus.UNAVAILABLE
    assert "quota_exhausted" in " ".join(decision.reasons)


def test_privacy_and_local_only_filters_are_composed_with_usability() -> None:
    registry = _registry(
        ("local", (_model("local"),)),
        ("cloud", (_model("cloud", quality=1.0),)),
        local=frozenset({"local"}),
    )
    local_blocked = evidence_for_failure(
        "local", UsabilityReason.LOCAL_RESOURCE_BLOCKED, model_id="local", cooldown_seconds=None
    )
    decision = ProviderRouter(registry).route(
        _request(
            policy=RoutingPolicy.LOCAL_ONLY,
            privacy_context=PrivacyContext(PrivacyClassification.LOCAL_ONLY),
            usability_evidence=(local_blocked,),
        )
    )
    assert decision.primary is None
    assert decision.status is RouteStatus.UNAVAILABLE
    assert "local_resource_blocked" in " ".join(decision.reasons)


def test_route_decision_exposes_safe_usability_evidence_without_detail_or_secrets() -> None:
    evidence = _usable("provider", "model", observed_at=datetime.now(UTC))
    decision = ProviderRouter(_registry(("provider", (_model("model"),)))).route(
        _request(usability_evidence=(evidence,))
    )
    assert decision.primary is not None
    keys = {key for key, _value in decision.evidence}
    assert {
        "usability_status",
        "usability_reason",
        "usability_source",
        "usability_freshness",
        "usability_observed_at",
        "usability_expires_at",
    }.issubset(keys)
    assert all("secret" not in value.casefold() for _key, value in decision.evidence)


class _QuotaProvider(FakeAIProvider):
    def __init__(self) -> None:
        super().__init__()
        self.calls = 0

    async def generate(self, request: GenerationRequest) -> GenerationResult:
        self.calls += 1
        raise ProviderError("quota exhausted")


class _RecordingProvider(FakeAIProvider):
    def __init__(self) -> None:
        super().__init__()
        self.calls = 0

    async def generate(self, request: GenerationRequest) -> GenerationResult:
        self.calls += 1
        return await super().generate(request)


def _generation_request() -> GenerationRequest:
    return GenerationRequest(
        messages=(
            ChatMessage(
                id=uuid4(),
                conversation_id=uuid4(),
                role=MessageRole.USER,
                content="hello",
                created_at=datetime.now(UTC),
            ),
        ),
        model="initial",
        context_limit=4_096,
        privacy_context=PrivacyContext(PrivacyClassification.SAFE_PUBLIC),
    )


@pytest.mark.asyncio
async def test_dispatcher_records_quota_failure_and_executes_exact_fallback_identity() -> None:
    registry = _registry(
        ("provider-a", (_model("premium", quality=1.0),)),
        ("provider-b", (_model("standard", quality=0.5),)),
    )
    primary = _QuotaProvider()
    fallback = _RecordingProvider()
    router = ProviderRouter(registry)
    dispatcher = InferenceDispatcher(
        router,
        registry,
        providers={"provider-a": primary, "provider-b": fallback},
        max_attempts=2,
    )
    result = await dispatcher.generate(
        _generation_request(),
        _request(policy=RoutingPolicy.QUALITY_FIRST),
    )
    assert result.result.model == "standard"
    assert result.decision.primary is not None
    assert result.decision.primary.provider_id == "provider-b"
    assert result.decision.primary.model_id == result.result.model
    assert primary.calls == 1
    assert fallback.calls == 1
    observed = router.usability_for("provider-a", "premium")
    assert observed.quota_usable is False
    assert observed.reason is UsabilityReason.QUOTA_EXHAUSTED
    await dispatcher.aclose()


def test_success_feedback_does_not_promote_quota_or_future_capacity() -> None:
    router = ProviderRouter(_registry(("provider", (_model("model"),))))
    evidence = router.record_success(ModelIdentity("provider", "model"))
    assert evidence.connected is True
    assert evidence.authenticated is True
    assert evidence.model_usable is True
    assert evidence.request_usable is True
    assert evidence.quota_usable is None
    assert evidence.capacity_usable is True
    assert evidence.expires_at is not None
    assert evidence.entitled is None


@pytest.mark.asyncio
async def test_registry_probe_fallback_keeps_unproven_dimensions_unknown() -> None:
    registry = _registry(("provider", (_model("model"),)))
    evidence = await registry.probe_usability("provider", {"model": "model", "endpoint": "unused"})
    assert evidence.connected is True
    assert evidence.reachable is True
    assert evidence.quota_usable is None
    assert evidence.model_usable is None
    assert evidence.source == "provider.health_check"


@pytest.mark.asyncio
async def test_ollama_probe_distinguishes_reachable_missing_model() -> None:
    def tags(_request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json={"models": [{"name": "installed:latest"}]})

    client = httpx.AsyncClient(transport=httpx.MockTransport(tags))
    provider = OllamaProvider(
        model="missing:latest",
        endpoint="http://ollama.test",
        timeout_seconds=1,
        context_limit=4_096,
        client=client,
    )
    evidence = await provider.probe_usability()
    assert evidence.connected is True
    assert evidence.reachable is True
    assert evidence.model_usable is False
    assert evidence.reason is UsabilityReason.MODEL_NOT_FOUND
    assert evidence.quota_usable is True
    await client.aclose()


def test_registry_rejects_malformed_advertisements_and_voice_boundaries() -> None:
    model = _model("model")
    registry = _registry(("provider", (model,)))
    with pytest.raises(ValueError, match="advertisement is malformed"):
        registry.replace_models("provider", cast(Any, [model]))
    with pytest.raises(ValueError, match="contains duplicates"):
        registry.replace_models("provider", (model, model))

    metadata = ProviderMetadata("voice", "Voice", "r3u")
    with pytest.raises(ValueError, match="Voice provider definition"):
        VoiceProviderDefinition(VoiceProviderKind.STT, metadata, cast(Any, "not callable"))

    invalid_stt = VoiceProviderDefinition(
        VoiceProviderKind.STT, metadata, cast(Any, lambda _configuration: object())
    )
    registry.register_voice(invalid_stt)
    with pytest.raises(ValueError, match="already registered"):
        registry.register_voice(invalid_stt)
    with pytest.raises(TypeError, match="non-STT"):
        registry.create_voice(VoiceProviderKind.STT, "voice", {})

    invalid_tts = VoiceProviderDefinition(
        VoiceProviderKind.TTS,
        ProviderMetadata("tts", "TTS", "r3u"),
        cast(Any, lambda _configuration: object()),
    )
    registry.register_voice(invalid_tts)
    with pytest.raises(TypeError, match="non-TTS"):
        registry.create_voice(VoiceProviderKind.TTS, "tts", {})
    with pytest.raises(ValueError, match="Voice provider kind"):
        registry.voice_definitions(cast(Any, "stt"))
    with pytest.raises(ValueError, match="Voice provider kind"):
        registry.voice_definition(cast(Any, "stt"), "voice")
    with pytest.raises(KeyError, match="Unknown stt provider"):
        registry.voice_definition(VoiceProviderKind.STT, "missing")
