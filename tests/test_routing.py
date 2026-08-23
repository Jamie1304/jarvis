"""Provider-neutral routing tests with fake models and voice providers."""

from datetime import UTC, datetime
from typing import Any, cast

import pytest
from jarvis.ai.models import ModelRole
from jarvis.ai.providers import (
    ModelMetadata,
    ProviderDefinition,
    ProviderMetadata,
    ProviderRegistry,
    VoiceProviderDefinition,
    VoiceProviderKind,
)
from jarvis.ai.routing import (
    FailoverSttProvider,
    ProviderHealthSnapshot,
    ProviderRouter,
    RouteBenchmark,
    RouteRequest,
    RouteStatus,
    RoutingPolicy,
)
from jarvis.core.errors import SpeechError
from jarvis.resources import (
    ResourceGovernor,
    ResourcePolicy,
    ResourcePriority,
    ResourceSnapshot,
)
from jarvis.speech.stt import AudioData, SttProvider, Transcription
from jarvis.speech.tts import TtsProvider

from tests.fakes import FakeAIProvider
from tests.test_hardware import _hardware


def model(
    model_id: str,
    role: ModelRole,
    *,
    quality: float | None = None,
    latency: float | None = None,
    input_cost: float | None = None,
    output_cost: float | None = None,
    local_resource: bool = False,
) -> ModelMetadata:
    return ModelMetadata(
        model_id,
        8_192,
        frozenset({"chat", "tool_use", "structured_output"}),
        frozenset({role}),
        quality_score=quality,
        latency_ms=latency,
        input_cost_per_million=input_cost,
        output_cost_per_million=output_cost,
        modalities=frozenset({"text", "audio"}),
        storage_bytes=1 if local_resource else None,
        ram_bytes=1 if local_resource else None,
        compatibility=frozenset({"windows"}) if local_resource else frozenset(),
    )


def registry() -> ProviderRegistry:
    return ProviderRegistry(
        (
            ProviderDefinition(
                ProviderMetadata("remote", "Remote", "fixture", local_only=False),
                lambda _: FakeAIProvider(),
                (
                    model(
                        "remote-model", ModelRole.GENERAL, quality=0.99, latency=250, input_cost=1
                    ),
                ),
            ),
            ProviderDefinition(
                ProviderMetadata("local", "Local", "fixture", local_only=True),
                lambda _: FakeAIProvider(),
                (
                    model(
                        "local-model",
                        ModelRole.GENERAL,
                        quality=0.8,
                        latency=40,
                        input_cost=0,
                        local_resource=True,
                    ),
                ),
            ),
        )
    )


def request(**values: Any) -> RouteRequest:
    defaults: dict[str, Any] = {
        "task": "answer",
        "profile": "default",
        "resource_state": _hardware(tags=frozenset({"windows"})),
    }
    defaults.update(values)
    return RouteRequest(**defaults)


def test_quality_preference_and_local_privacy_policy() -> None:
    router = ProviderRouter(registry())
    preferred = router.route(
        request(policy=RoutingPolicy.QUALITY_FIRST, preferred_provider_id="remote")
    )
    assert preferred.status is RouteStatus.SELECTED
    assert preferred.primary is not None and preferred.primary.provider_id == "remote"

    private = router.route(request(policy=RoutingPolicy.PRIVACY_STRICT))
    assert private.primary is not None and private.primary.provider_id == "local"
    secret = router.route(request(classification="secret", policy=RoutingPolicy.BALANCED))
    assert secret.primary is not None and secret.primary.provider_id == "local"


def test_speed_cost_and_tool_structured_output_routing() -> None:
    router = ProviderRouter(registry())
    speed = router.route(request(policy=RoutingPolicy.SPEED_FIRST))
    assert speed.primary is not None and speed.primary.provider_id == "local"
    cheapest = router.route(request(policy=RoutingPolicy.LOWEST_COST))
    assert cheapest.primary is not None and cheapest.primary.provider_id == "local"
    tool = router.route(request(requires_tools=True, requires_structured_output=True))
    assert tool.status is RouteStatus.SELECTED


def test_routing_respects_health_concurrency_resources_and_unknown_capacity() -> None:
    router = ProviderRouter(registry())
    unhealthy = router.route(
        request(provider_health=(ProviderHealthSnapshot("local", False, "offline"),))
    )
    assert unhealthy.primary is not None and unhealthy.primary.provider_id == "remote"
    denied = router.route(request(concurrency=5))
    assert denied.status is RouteStatus.UNAVAILABLE


def test_router_uses_one_governor_for_priority_and_model_degradation() -> None:
    class Telemetry:
        def snapshot(self) -> ResourceSnapshot:
            return ResourceSnapshot(
                datetime.now(UTC),
                cpu_utilization=0.99,
                cpu_cores=8,
                ram_total_bytes=100,
                ram_available_bytes=10,
                disk_free_bytes=10_000_000_000,
            )

    governor = ResourceGovernor(
        Telemetry(), policy=ResourcePolicy(low_disk_bytes=0, pressure_concurrency=1)
    )
    router = ProviderRouter(registry(), governor)
    reduced = router.route(request(concurrency=2))
    assert reduced.status is RouteStatus.SELECTED
    assert reduced.resource_decision is not None
    assert reduced.resource_decision.effective_budget.concurrency == 1
    assert reduced.primary is not None and reduced.primary.provider_id == "local"
    deferred = router.route(request(priority=ResourcePriority.BACKGROUND))
    assert deferred.status is RouteStatus.UNKNOWN


def test_router_resource_denial_can_degrade_to_no_llm() -> None:
    class Telemetry:
        def snapshot(self) -> ResourceSnapshot:
            return ResourceSnapshot(datetime.now(UTC), on_ac_power=False)

    governor = ResourceGovernor(Telemetry())
    router = ProviderRouter(registry(), governor)
    result = router.route(request(priority=ResourcePriority.BENCHMARK, allow_no_llm=True))
    assert result.status is RouteStatus.NO_LLM
    assert result.resource_decision is not None
    unknown = router.route(request(resource_state=None, policy=RoutingPolicy.LOCAL_ONLY))
    assert unknown.status is RouteStatus.UNKNOWN
    no_llm = router.route(
        request(resource_state=None, policy=RoutingPolicy.LOCAL_ONLY, allow_no_llm=True)
    )
    assert no_llm.status is RouteStatus.NO_LLM


def test_latency_budget_and_benchmark_override_are_explicit() -> None:
    router = ProviderRouter(registry())
    denied = router.route(request(latency_budget_ms=10))
    assert denied.status is RouteStatus.UNAVAILABLE
    measured = router.route(
        request(
            policy=RoutingPolicy.SPEED_FIRST,
            latency_budget_ms=10,
            benchmarks=(
                RouteBenchmark(
                    "remote", "remote-model", datetime.now(UTC), latency_ms=5, quality_score=1
                ),
            ),
        )
    )
    assert measured.primary is not None and measured.primary.provider_id == "remote"


class FailingTts(TtsProvider):
    async def speak(self, text: str) -> None:
        del text
        raise SpeechError("provider failed")

    async def stop(self) -> None:
        return None


class RecordingTts(TtsProvider):
    def __init__(self) -> None:
        self.spoken: list[str] = []

    async def speak(self, text: str) -> None:
        self.spoken.append(text)

    async def stop(self) -> None:
        return None


class FailingStt(SttProvider):
    async def transcribe(self, audio: AudioData) -> Transcription:
        del audio
        raise RuntimeError("provider failed")


class RecordingStt(SttProvider):
    async def transcribe(self, audio: AudioData) -> Transcription:
        del audio
        return Transcription("fallback result")


class AlwaysFailStt(SttProvider):
    async def transcribe(self, audio: AudioData) -> Transcription:
        del audio
        raise SpeechError("all providers failed")


@pytest.mark.asyncio
async def test_voice_registry_is_provider_neutral_and_falls_back() -> None:
    registry_instance = registry()
    registry_instance.register_voice(
        VoiceProviderDefinition(
            VoiceProviderKind.TTS,
            ProviderMetadata("preferred", "Preferred", "fixture", local_only=False),
            lambda _: FailingTts(),
            (model("preferred-tts", ModelRole.TTS, quality=1, latency=10),),
        )
    )
    registry_instance.register_voice(
        VoiceProviderDefinition(
            VoiceProviderKind.TTS,
            ProviderMetadata("local-tts", "Local TTS", "fixture", local_only=True),
            lambda _: RecordingTts(),
            (model("local-tts-model", ModelRole.TTS, quality=0.8, latency=20),),
        )
    )
    assert registry_instance.voice_provider_ids(VoiceProviderKind.TTS) == (
        "local-tts",
        "preferred",
    )
    assert registry_instance.voice_definitions(VoiceProviderKind.STT) == ()
    with pytest.raises(ValueError):
        registry_instance.voice_provider_ids(cast(Any, "tts"))
    registry_instance.register_voice(
        VoiceProviderDefinition(
            VoiceProviderKind.STT,
            ProviderMetadata("stt-one", "STT One", "fixture", local_only=True),
            lambda _: FailingStt(),
            (model("stt-one-model", ModelRole.STT, quality=1),),
        )
    )
    registry_instance.register_voice(
        VoiceProviderDefinition(
            VoiceProviderKind.STT,
            ProviderMetadata("stt-two", "STT Two", "fixture", local_only=True),
            lambda _: RecordingStt(),
            (model("stt-two-model", ModelRole.STT, quality=0.5),),
        )
    )
    router = ProviderRouter(registry_instance)
    voice_request = request(
        role=ModelRole.TTS,
        modality="audio",
        policy=RoutingPolicy.QUALITY_FIRST,
        preferred_provider_id="preferred",
    )
    decision = router.route_voice(VoiceProviderKind.TTS, voice_request)
    assert decision.primary is not None and decision.primary.provider_id == "preferred"
    assert decision.fallbacks[0].provider_id == "local-tts"
    assert isinstance(router.create_voice_provider(decision, {}), FailingTts)
    service = router.create_tts_service(
        decision,
        {"preferred": {}, "local-tts": {}},
        enabled=True,
    )
    assert service is not None
    await service.speak("fallback text")
    assert service.available

    stt_decision = router.route_voice(
        VoiceProviderKind.STT,
        request(role=ModelRole.STT, modality="audio", policy=RoutingPolicy.QUALITY_FIRST),
    )
    stt = router.create_stt_provider(stt_decision, {"stt-one": {}, "stt-two": {}})
    assert isinstance(stt, FailoverSttProvider)
    result = await stt.transcribe(AudioData((0.1,), 16_000, datetime.now(UTC)))
    assert result.text == "fallback result"
    await service.aclose()
    await stt.aclose()


def test_privacy_strict_voice_route_has_no_text_only_authority() -> None:
    router = ProviderRouter(registry())
    decision = router.route_voice(
        VoiceProviderKind.TTS,
        request(
            role=ModelRole.TTS,
            modality="audio",
            policy=RoutingPolicy.PRIVACY_STRICT,
            allow_no_llm=True,
        ),
    )
    assert decision.status is RouteStatus.NO_LLM
    assert router.create_tts_service(decision, {}, enabled=True) is None


def test_route_validation_and_candidate_constraints_fail_closed() -> None:
    with pytest.raises(ValueError):
        RouteBenchmark("provider", "model", datetime(2026, 1, 1))
    with pytest.raises(ValueError):
        RouteBenchmark("provider", "model", datetime.now(UTC), quality_score=float("nan"))
    with pytest.raises(ValueError):
        ProviderHealthSnapshot("", True)
    with pytest.raises(ValueError):
        RouteRequest("", "profile")
    with pytest.raises(ValueError):
        RouteRequest("task", "profile", context_tokens=-1)
    with pytest.raises(ValueError):
        RouteRequest("task", "profile", latency_budget_ms=0)
    with pytest.raises(ValueError):
        RouteRequest("task", "profile", provider_health=(object(),))  # type: ignore[arg-type]

    router = ProviderRouter(registry())
    for values in (
        {"role": ModelRole.CODING},
        {"modality": "vision"},
        {"context_tokens": 9_000},
        {"requires_tools": True, "role": ModelRole.VISION},
    ):
        assert router.route(request(**values)).status is RouteStatus.UNAVAILABLE
    with pytest.raises(ValueError):
        router.route(cast(Any, object()))
    with pytest.raises(ValueError):
        router.route_voice(cast(Any, "tts"), request())
    with pytest.raises(ValueError):
        router.create_voice_provider(router.route(request(no_llm=True)), {})


def test_unknown_latency_and_declared_capability_constraints() -> None:
    unknown_registry = ProviderRegistry(
        (
            ProviderDefinition(
                ProviderMetadata("unknown", "Unknown", "fixture", local_only=True),
                lambda _: FakeAIProvider(),
                (
                    ModelMetadata(
                        "unknown-model",
                        100,
                        frozenset(),
                        frozenset({ModelRole.GENERAL}),
                        modalities=frozenset({"text"}),
                    ),
                ),
            ),
        )
    )
    router = ProviderRouter(unknown_registry)
    decision = router.route(
        request(
            resource_state=_hardware(tags=frozenset()),
            latency_budget_ms=10,
            policy=RoutingPolicy.SPEED_FIRST,
        )
    )
    assert decision.status is RouteStatus.UNKNOWN
    declared = router.route(request(role=ModelRole.GENERAL, requires_structured_output=True))
    assert declared.status is RouteStatus.UNAVAILABLE


@pytest.mark.asyncio
async def test_voice_factory_rejects_empty_and_all_failed_fallback_chains() -> None:
    with pytest.raises(ValueError):
        FailoverSttProvider(())
    provider = FailoverSttProvider((AlwaysFailStt(),))
    with pytest.raises(SpeechError, match="all providers"):
        await provider.transcribe(AudioData((0.1,), 16_000, datetime.now(UTC)))
    await provider.aclose()
