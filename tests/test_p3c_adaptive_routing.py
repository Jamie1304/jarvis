"""Application-level proofs for the bounded P3C routing seam."""

import asyncio
from collections.abc import AsyncIterator, Mapping
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any
from uuid import uuid4

import pytest
from jarvis.agent_runtime import AgentContext, AgentLoop, ContextManager
from jarvis.ai.knowledge import (
    CookbookObservation,
    CookbookOutcome,
    ModelKnowledgeService,
    ModelKnowledgeStore,
    VerifierAgreement,
    identity_for,
)
from jarvis.ai.models import (
    ChatMessage,
    GenerationChunk,
    GenerationRequest,
    GenerationResult,
    MessageRole,
    ModelRole,
    PrivacyClassification,
    PrivacyContext,
)
from jarvis.ai.providers.base import AIProvider
from jarvis.ai.providers.registry import (
    ModelMetadata,
    ProviderDefinition,
    ProviderLocality,
    ProviderMetadata,
    ProviderRegistry,
)
from jarvis.ai.routing import (
    DispatchChunk,
    InferenceDispatcher,
    InferenceDispatchError,
    ProviderRouter,
    RouteFailureClass,
    RouteRequest,
    RouteStatus,
    RoutingFeedbackRecorder,
    RoutingPolicy,
)
from jarvis.ai.sessions import AgentSessionStore
from jarvis.conversation.service import ConversationService
from jarvis.core.errors import PrivacyBlockedError, ProviderUnavailableError
from jarvis.tools.registry import ToolRegistry

from tests.fakes import FakeAIProvider


def _known_multi_model_registry(
    models: tuple[tuple[str, str, int, float | None, float | None, float | None], ...],
) -> ProviderRegistry:
    definitions: list[ProviderDefinition] = []
    for provider_id, model_id, context_limit, quality, latency, cost in models:
        provider = FakeAIProvider((f"{provider_id}-response",))
        metadata = ModelMetadata(
            model_id,
            context_limit,
            frozenset({"structured_output", "tool_use"}),
            frozenset({ModelRole.GENERAL, ModelRole.TOOL_USE}),
            version="v1",
            quantization="q4",
            runtime="fixture",
            modalities=frozenset({"text"}),
            quality_score=quality,
            latency_ms=latency,
            input_cost_per_million=cost,
            output_cost_per_million=0 if cost is not None else None,
        )

        def factory(
            _configuration: Mapping[str, Any], selected: AIProvider = provider
        ) -> AIProvider:
            return selected

        definitions.append(
            ProviderDefinition(
                ProviderMetadata(
                    provider_id, provider_id, "fixture", locality=ProviderLocality.REMOTE
                ),
                factory,
                (metadata,),
            )
        )
    return ProviderRegistry(tuple(definitions))


def _record_reliability(
    knowledge: ModelKnowledgeService,
    registry: ProviderRegistry,
    provider_id: str,
    model_id: str,
    success_count: int,
    *,
    latency_ms: float | None = None,
) -> None:
    definition = registry.definition(provider_id)
    model = definition.models[0]
    identity = identity_for(provider_id, model)
    observed_at = datetime.now(UTC)
    for index in range(100):
        success = index < success_count
        knowledge.record_cookbook(
            CookbookObservation(
                identity,
                "conversation",
                CookbookOutcome.VERIFIED_SUCCESS if success else CookbookOutcome.FAILURE,
                observed_at + timedelta(microseconds=index),
                verified=True if success else None,
                verifier_agreement=(
                    VerifierAgreement.DETERMINISTIC_VERIFICATION
                    if success
                    else VerifierAgreement.UNKNOWN
                ),
                latency_ms=latency_ms,
                observation_id=f"{provider_id}-{model_id}-{index}",
            )
        )


def _model(model_id: str, quality: float, *, local: bool = False) -> ModelMetadata:
    return ModelMetadata(
        model_id,
        4096,
        frozenset({"structured_output", "tool_use"}),
        frozenset({ModelRole.GENERAL, ModelRole.TOOL_USE}),
        version="v1",
        quantization="q4",
        runtime="fixture",
        modalities=frozenset({"text"}),
        quality_score=quality,
        latency_ms=100 if local else 200,
        input_cost_per_million=0 if local else 1,
        output_cost_per_million=0 if local else 1,
    )


def _registry(
    remote: AIProvider | None = None, local: AIProvider | None = None
) -> ProviderRegistry:
    return ProviderRegistry(
        (
            ProviderDefinition(
                ProviderMetadata("remote", "Remote", "fixture", locality=ProviderLocality.REMOTE),
                lambda _: remote or FakeAIProvider(("remote",)),
                (_model("remote-model", 0.99),),
            ),
            ProviderDefinition(
                ProviderMetadata("local", "Local", "fixture", local_only=True),
                lambda _: local or FakeAIProvider(("local",)),
                (_model("local-model", 0.80, local=True),),
            ),
        )
    )


def _knowledge(tmp_path: Path, registry: ProviderRegistry) -> ModelKnowledgeService:
    service = ModelKnowledgeService(ModelKnowledgeStore(tmp_path / "knowledge.sqlite3"))
    now = datetime.now(UTC)
    service.refresh_registry(registry, observed_at=now, source="fixture-catalog")
    for _provider_id, definition in registry.definitions():
        service.observe_provider_health(
            definition.metadata,
            True,
            observed_at=now,
            source="fixture-health",
            detail="reachable",
        )
    return service


def _request(**values: object) -> RouteRequest:
    defaults: dict[str, Any] = {
        "task": "answer",
        "profile": "test",
        "task_class": "conversation",
        "privacy_context": PrivacyContext(PrivacyClassification.SAFE_PUBLIC),
    }
    defaults.update(values)
    return RouteRequest(**defaults)


def test_typed_privacy_and_unknown_health_fail_closed(tmp_path: Path) -> None:
    registry = _registry()
    knowledge = ModelKnowledgeService(ModelKnowledgeStore(tmp_path / "knowledge.sqlite3"))
    knowledge.refresh_registry(registry, observed_at=datetime.now(UTC), source="fixture-catalog")
    router = ProviderRouter(registry, knowledge=knowledge)
    unknown = RouteRequest(
        "answer", "test", privacy_context=PrivacyContext(PrivacyClassification.UNKNOWN)
    )
    decision = router.route(unknown)
    assert decision.primary is None
    assert decision.status is RouteStatus.UNKNOWN
    assert all("unknown" in reason for reason in decision.reasons)


def test_knowledge_is_authoritative_and_identity_is_full(tmp_path: Path) -> None:
    registry = _registry()
    knowledge = _knowledge(tmp_path, registry)
    router = ProviderRouter(registry, knowledge=knowledge)
    decision = router.route(_request(policy=RoutingPolicy.QUALITY_FIRST))
    assert decision.primary is not None
    assert decision.primary.identity.version == "v1"
    assert decision.primary.knowledge is not None
    assert decision.primary.measurement is None
    assert decision.evidence


def test_trusted_feedback_requires_independent_verification(tmp_path: Path) -> None:
    registry = _registry()
    knowledge = _knowledge(tmp_path, registry)
    recorder = RoutingFeedbackRecorder(knowledge)
    identity = next(iter(knowledge.models(provider_id="remote"))).identity
    now = datetime.now(UTC)
    recorder.record(
        identity,
        "conversation",
        CookbookOutcome.VERIFIED_SUCCESS,
        observed_at=now,
        verified=True,
        verifier_agreement=VerifierAgreement.DETERMINISTIC_VERIFICATION,
    )
    with pytest.raises(ValueError):
        recorder.record(
            identity,
            "conversation",
            CookbookOutcome.VERIFIED_SUCCESS,
            observed_at=now + timedelta(seconds=1),
            verified=True,
            verifier_agreement=VerifierAgreement.MODEL_SELF_CLAIM,
        )


class _FailingProvider(FakeAIProvider):
    async def generate(self, request: GenerationRequest) -> GenerationResult:
        self.requests.append(request)
        raise ProviderUnavailableError("fixture unavailable")

    async def stream(self, request: GenerationRequest) -> AsyncIterator[GenerationChunk]:
        self.requests.append(request)
        raise ProviderUnavailableError("fixture unavailable")
        yield GenerationChunk("unreachable")


@pytest.mark.asyncio
async def test_dispatcher_reroutes_bounded_failure_before_stream_output(tmp_path: Path) -> None:
    remote = _FailingProvider()
    local = FakeAIProvider(("local",))
    registry = _registry(remote, local)
    knowledge = _knowledge(tmp_path, registry)
    dispatcher = InferenceDispatcher(
        ProviderRouter(registry, knowledge=knowledge),
        registry,
        providers={"remote": remote, "local": local},
    )
    message = ChatMessage(uuid4(), uuid4(), MessageRole.USER, "hello", datetime.now(UTC))
    intent = _request(policy=RoutingPolicy.QUALITY_FIRST)
    chunks = [
        item
        async for item in dispatcher.stream(
            GenerationRequest((message,), "remote-model", 4096, intent.effective_privacy_context()),
            intent,
        )
    ]
    assert chunks and all(isinstance(item, DispatchChunk) for item in chunks)
    assert chunks[0].rerouted is True
    assert chunks[0].decision.primary is not None
    assert chunks[0].decision.primary.provider_id == "local"


@pytest.mark.asyncio
async def test_dispatcher_does_not_stitch_after_partial_stream(tmp_path: Path) -> None:
    class Partial(FakeAIProvider):
        async def stream(self, request: GenerationRequest) -> AsyncIterator[GenerationChunk]:
            self.requests.append(request)
            yield GenerationChunk("partial", False)
            raise ProviderUnavailableError("after output")

    remote = Partial()
    local = FakeAIProvider(("fallback",))
    registry = _registry(remote, local)
    knowledge = _knowledge(tmp_path, registry)
    dispatcher = InferenceDispatcher(
        ProviderRouter(registry, knowledge=knowledge),
        registry,
        providers={"remote": remote, "local": local},
    )
    intent = _request(policy=RoutingPolicy.QUALITY_FIRST)
    stream = dispatcher.stream(
        GenerationRequest((), "remote-model", 4096, intent.effective_privacy_context()), intent
    )
    assert (await anext(stream)).chunk.content == "partial"
    with pytest.raises(InferenceDispatchError):
        await anext(stream)
    assert not local.requests


def test_failure_context_and_no_llm_are_explicit(tmp_path: Path) -> None:
    registry = _registry()
    knowledge = _knowledge(tmp_path, registry)
    router = ProviderRouter(registry, knowledge=knowledge)
    decision = router.route(
        _request(previous_failure=RouteFailureClass.MALFORMED_STRUCTURED_OUTPUT)
    )
    assert decision.status is RouteStatus.SELECTED
    no_llm = router.route(_request(no_llm=True))
    assert no_llm.status is RouteStatus.NO_LLM


@pytest.mark.asyncio
async def test_conversation_binds_route_transition_to_new_session(tmp_path: Path) -> None:
    remote = FakeAIProvider(("remote",))
    local = FakeAIProvider(("local",))
    registry = _registry(remote, local)
    knowledge = _knowledge(tmp_path, registry)
    dispatcher = InferenceDispatcher(
        ProviderRouter(registry, knowledge=knowledge),
        registry,
        providers={"remote": remote, "local": local},
    )
    store = AgentSessionStore(tmp_path / "sessions.sqlite3")
    conversation = ConversationService(
        local,
        model="local-model",
        context_limit=4096,
        session_store=store,
        provider_id="local",
        dispatcher=dispatcher,
        provider_metadata=registry.definition("local").metadata,
        routing_policy=RoutingPolicy.QUALITY_FIRST,
    )
    conversation_id = conversation.create_conversation()
    updates = [
        update
        async for update in conversation.stream_reply(
            conversation_id,
            "hello",
            privacy_context=PrivacyContext(PrivacyClassification.SAFE_PUBLIC),
        )
    ]
    assert "remote" in "".join(update.content for update in updates)
    session_id = conversation.session_id(conversation_id)
    assert session_id is not None
    session = store.get(session_id)
    assert session is not None and session.provider_id == "remote"
    await dispatcher.aclose()
    store.close()


@pytest.mark.asyncio
async def test_agent_loop_routes_each_inference_segment_through_dispatcher(tmp_path: Path) -> None:
    remote = FakeAIProvider(('{"kind":"response","content":"done"}',))
    local = FakeAIProvider(("local",))
    registry = _registry(remote, local)
    knowledge = _knowledge(tmp_path, registry)
    dispatcher = InferenceDispatcher(
        ProviderRouter(registry, knowledge=knowledge),
        registry,
        providers={"remote": remote, "local": local},
    )
    loop = AgentLoop(
        local,
        ToolRegistry(()),
        model="local-model",
        context_limit=4096,
        dispatcher=dispatcher,
    )
    result = await loop.run(
        uuid4(),
        "answer",
        context=AgentContext(
            request="answer",
            goal="answer",
            provider_context_limit=4096,
            privacy_context=PrivacyContext(PrivacyClassification.SAFE_PUBLIC),
            routing_policy=RoutingPolicy.QUALITY_FIRST,
        ),
    )
    assert result.proposed_result == "done"
    assert remote.requests and remote.requests[0].model == "remote-model"
    await dispatcher.aclose()


def test_threshold_filters_before_lowest_cost_and_quality_policies(tmp_path: Path) -> None:
    registry = _known_multi_model_registry(
        (
            ("expensive", "expensive-model", 4096, 0.99, 300, 10),
            ("cheap", "cheap-model", 4096, 0.90, 200, 1),
            ("unreliable", "unreliable-model", 4096, 0.80, 100, 1),
        )
    )
    knowledge = _knowledge(tmp_path, registry)
    _record_reliability(knowledge, registry, "expensive", "expensive-model", 96)
    _record_reliability(knowledge, registry, "cheap", "cheap-model", 95)
    _record_reliability(knowledge, registry, "unreliable", "unreliable-model", 70)
    router = ProviderRouter(registry, knowledge=knowledge)

    cheapest = router.route(
        _request(policy=RoutingPolicy.LOWEST_COST, minimum_expected_reliability=0.90)
    )
    assert cheapest.primary is not None and cheapest.primary.provider_id == "cheap"
    assert {candidate.provider_id for candidate in cheapest.fallbacks} == {"expensive"}

    quality = router.route(
        _request(policy=RoutingPolicy.QUALITY_FIRST, minimum_expected_reliability=0.90)
    )
    assert quality.primary is not None and quality.primary.provider_id == "expensive"

    rejected = router.route(
        _request(policy=RoutingPolicy.LOWEST_COST, minimum_expected_reliability=0.90)
    )
    assert rejected.primary is not None
    assert all(
        candidate.provider_id != "unreliable"
        for candidate in (rejected.primary, *rejected.fallbacks)
    )


def test_speed_balanced_unknown_efficiency_metrics_are_deterministic(tmp_path: Path) -> None:
    registry = _known_multi_model_registry(
        (
            ("slow", "slow-model", 4096, 0.95, 500, 1),
            ("fast", "fast-model", 4096, 0.94, 100, 10),
            ("unknown", "unknown-model", 4096, 0.93, None, None),
        )
    )
    knowledge = _knowledge(tmp_path, registry)
    _record_reliability(knowledge, registry, "slow", "slow-model", 95)
    _record_reliability(knowledge, registry, "fast", "fast-model", 94)
    _record_reliability(knowledge, registry, "unknown", "unknown-model", 93)
    router = ProviderRouter(registry, knowledge=knowledge)

    speed = router.route(
        _request(policy=RoutingPolicy.SPEED_FIRST, minimum_expected_reliability=0.90)
    )
    assert speed.primary is not None and speed.primary.provider_id == "fast"
    balanced = router.route(
        _request(policy=RoutingPolicy.BALANCED, minimum_expected_reliability=0.90)
    )
    assert balanced.primary is not None and balanced.primary.provider_id == "slow"
    assert balanced.fallbacks[-1].provider_id == "unknown"


class _AmbiguousProvider(FakeAIProvider):
    async def generate(self, request: GenerationRequest) -> GenerationResult:
        self.requests.append(request)
        raise RuntimeError("synthetic ambiguous provider failure")

    async def stream(self, request: GenerationRequest) -> AsyncIterator[GenerationChunk]:
        self.requests.append(request)
        raise RuntimeError("synthetic ambiguous provider failure")
        yield GenerationChunk("unreachable")


class _TimeoutProvider(FakeAIProvider):
    async def generate(self, request: GenerationRequest) -> GenerationResult:
        self.requests.append(request)
        raise TimeoutError("synthetic timeout")

    async def stream(self, request: GenerationRequest) -> AsyncIterator[GenerationChunk]:
        self.requests.append(request)
        raise TimeoutError("synthetic timeout")
        yield GenerationChunk("unreachable")


class _CancelledProvider(FakeAIProvider):
    async def generate(self, request: GenerationRequest) -> GenerationResult:
        self.requests.append(request)
        raise asyncio.CancelledError()

    async def stream(self, request: GenerationRequest) -> AsyncIterator[GenerationChunk]:
        self.requests.append(request)
        raise asyncio.CancelledError()
        yield GenerationChunk("unreachable")


class _PrivacyBlockingProvider(FakeAIProvider):
    async def generate(self, request: GenerationRequest) -> GenerationResult:
        self.requests.append(request)
        raise PrivacyBlockedError("synthetic outbound privacy block")

    async def stream(self, request: GenerationRequest) -> AsyncIterator[GenerationChunk]:
        self.requests.append(request)
        raise PrivacyBlockedError("synthetic outbound privacy block")
        yield GenerationChunk("unreachable")


@pytest.mark.asyncio
async def test_unknown_provider_failure_does_not_reroute(tmp_path: Path) -> None:
    remote = _AmbiguousProvider()
    local = FakeAIProvider(("local-success",))
    registry = _registry(remote, local)
    knowledge = _knowledge(tmp_path, registry)
    dispatcher = InferenceDispatcher(
        ProviderRouter(registry, knowledge=knowledge),
        registry,
        providers={"remote": remote, "local": local},
    )
    with pytest.raises(InferenceDispatchError) as raised:
        await dispatcher.generate(
            GenerationRequest(
                (), "remote-model", 4096, PrivacyContext(PrivacyClassification.SAFE_PUBLIC)
            ),
            _request(policy=RoutingPolicy.QUALITY_FIRST),
        )
    assert raised.value.__cause__ is not None
    assert len(remote.requests) == 1
    assert not local.requests
    await dispatcher.aclose()


@pytest.mark.asyncio
async def test_timeout_reroutes_but_cancellation_does_not(tmp_path: Path) -> None:
    timed_out = _TimeoutProvider()
    fallback = FakeAIProvider(("timeout-fallback",))
    registry = _registry(timed_out, fallback)
    knowledge = _knowledge(tmp_path, registry)
    dispatcher = InferenceDispatcher(
        ProviderRouter(registry, knowledge=knowledge),
        registry,
        providers={"remote": timed_out, "local": fallback},
    )
    intent = _request(policy=RoutingPolicy.QUALITY_FIRST)
    result = await dispatcher.generate(
        GenerationRequest((), "remote-model", 4096, intent.effective_privacy_context()), intent
    )
    assert result.decision.primary is not None
    assert result.decision.primary.provider_id == "local"
    assert len(timed_out.requests) == 1 and len(fallback.requests) == 1
    await dispatcher.aclose()

    cancelled = _CancelledProvider()
    untouched = FakeAIProvider(("must-not-run",))
    cancel_registry = _registry(cancelled, untouched)
    cancel_knowledge = _knowledge(tmp_path / "cancel", cancel_registry)
    cancel_dispatcher = InferenceDispatcher(
        ProviderRouter(cancel_registry, knowledge=cancel_knowledge),
        cancel_registry,
        providers={"remote": cancelled, "local": untouched},
    )
    with pytest.raises(asyncio.CancelledError):
        await cancel_dispatcher.generate(
            GenerationRequest((), "remote-model", 4096, intent.effective_privacy_context()),
            _request(policy=RoutingPolicy.QUALITY_FIRST),
        )
    assert not untouched.requests
    with pytest.raises(asyncio.CancelledError):
        stream = cancel_dispatcher.stream(
            GenerationRequest((), "remote-model", 4096, intent.effective_privacy_context()),
            _request(policy=RoutingPolicy.QUALITY_FIRST),
        )
        await anext(stream)
    assert len(cancelled.requests) == 2 and not untouched.requests
    await cancel_dispatcher.aclose()


@pytest.mark.asyncio
async def test_privacy_failure_re_evaluates_local_only(tmp_path: Path) -> None:
    remote = _PrivacyBlockingProvider()
    local = FakeAIProvider(("local-only",))
    registry = _registry(remote, local)
    knowledge = _knowledge(tmp_path, registry)
    dispatcher = InferenceDispatcher(
        ProviderRouter(registry, knowledge=knowledge),
        registry,
        providers={"remote": remote, "local": local},
    )
    intent = _request(policy=RoutingPolicy.QUALITY_FIRST)
    result = await dispatcher.generate(
        GenerationRequest((), "remote-model", 4096, intent.effective_privacy_context()), intent
    )
    assert result.decision.primary is not None
    assert result.decision.primary.provider_id == "local"
    assert len(remote.requests) == 1 and len(local.requests) == 1
    await dispatcher.aclose()


def test_reserved_output_overflow_is_rejected_before_provider_use() -> None:
    context = AgentContext(
        request="answer",
        goal="answer",
        provider_context_limit=4096,
        reserved_output=2048,
    )
    with pytest.raises(ValueError, match="Reserved output"):
        ContextManager().prepare(
            context,
            (),
            conversation_id=uuid4(),
            model="small-model",
            context_limit=2048,
        )


def test_first_turn_tool_requirement_uses_trusted_routing_intent() -> None:
    provider = FakeAIProvider()
    registry = ProviderRegistry(
        (
            ProviderDefinition(
                ProviderMetadata("plain", "Plain", "fixture", locality=ProviderLocality.LOCAL),
                lambda _: provider,
                (
                    ModelMetadata(
                        "plain-model",
                        4096,
                        frozenset({"structured_output"}),
                        frozenset({ModelRole.GENERAL}),
                    ),
                ),
            ),
        )
    )
    decision = ProviderRouter(registry).route(
        _request(
            requires_tools=True,
            required_capabilities=frozenset({"tool_use"}),
            privacy_context=PrivacyContext(PrivacyClassification.UNKNOWN),
        )
    )
    assert decision.primary is None


def test_unrecognized_legacy_privacy_is_unknown_and_local_compatibility_remains() -> None:
    remote = FakeAIProvider()
    remote_registry = ProviderRegistry(
        (
            ProviderDefinition(
                ProviderMetadata("remote", "Remote", "fixture", locality=ProviderLocality.REMOTE),
                lambda _: remote,
                (_model("remote-model", 0.99),),
            ),
        )
    )
    remote_decision = ProviderRouter(remote_registry).route(
        RouteRequest("answer", "test", classification="internal")
    )
    assert remote_decision.primary is None
    assert (
        RouteRequest("answer", "test", classification="internal")
        .effective_privacy_context()
        .classification
        is PrivacyClassification.UNKNOWN
    )

    local = FakeAIProvider()
    local_registry = ProviderRegistry(
        (
            ProviderDefinition(
                ProviderMetadata("local", "Local", "fixture", local_only=True),
                lambda _: local,
                (_model("local-model", 0.99, local=True),),
            ),
        )
    )
    local_decision = ProviderRouter(local_registry).route(
        RouteRequest("answer", "test", classification="internal")
    )
    assert local_decision.primary is not None and local_decision.primary.provider_id == "local"


@pytest.mark.asyncio
async def test_conversation_session_tracks_actual_pre_output_failover(tmp_path: Path) -> None:
    remote = _FailingProvider()
    local = FakeAIProvider(("local-final",))
    registry = _registry(remote, local)
    knowledge = _knowledge(tmp_path, registry)
    dispatcher = InferenceDispatcher(
        ProviderRouter(registry, knowledge=knowledge),
        registry,
        providers={"remote": remote, "local": local},
    )
    store = AgentSessionStore(tmp_path / "sessions.sqlite3")
    service = ConversationService(
        local,
        model="local-model",
        context_limit=4096,
        session_store=store,
        provider_id="local",
        provider_metadata=registry.definition("local").metadata,
        dispatcher=dispatcher,
        routing_policy=RoutingPolicy.QUALITY_FIRST,
    )
    conversation_id = service.create_conversation()
    initial_session_id = service.session_id(conversation_id)
    assert initial_session_id is not None
    initial_session = store.get(initial_session_id)
    assert initial_session is not None
    updates = [
        item
        async for item in service.stream_reply(
            conversation_id,
            "hello",
            privacy_context=PrivacyContext(PrivacyClassification.SAFE_PUBLIC),
        )
    ]
    session_id = service.session_id(conversation_id)
    assert session_id is not None
    session = store.get(session_id)
    assert "".join(item.content for item in updates) == "local-final"
    assert session is not None and session.provider_id == "local"
    assert session.model_id == "local-model" and session.usage_tokens > 0
    assert initial_session.provider_id == "local"
    archived_initial = store.get(initial_session_id)
    assert archived_initial is not None and archived_initial.archived
    assert len(remote.requests) == 1 and len(local.requests) == 1
    await dispatcher.aclose()
    store.close()


@pytest.mark.asyncio
async def test_agent_loop_accepts_smaller_selected_context_and_rejects_overflow(
    tmp_path: Path,
) -> None:
    remote = FakeAIProvider(('{"kind":"response","content":"small-context"}',))
    registry = ProviderRegistry(
        (
            ProviderDefinition(
                ProviderMetadata("remote", "Remote", "fixture", locality=ProviderLocality.REMOTE),
                lambda _: remote,
                (
                    ModelMetadata(
                        "small-model",
                        2048,
                        frozenset({"structured_output", "tool_use"}),
                        frozenset({ModelRole.GENERAL, ModelRole.TOOL_USE}),
                        version="v1",
                        quantization="q4",
                        runtime="fixture",
                        modalities=frozenset({"text"}),
                        quality_score=0.99,
                    ),
                ),
            ),
        )
    )
    knowledge = _knowledge(tmp_path, registry)
    dispatcher = InferenceDispatcher(
        ProviderRouter(registry, knowledge=knowledge),
        registry,
        providers={"remote": remote},
    )
    loop = AgentLoop(
        remote,
        ToolRegistry(()),
        model="fallback",
        context_limit=4096,
        dispatcher=dispatcher,
    )
    result = await loop.run(
        uuid4(),
        "answer",
        context=AgentContext(
            request="answer",
            goal="answer",
            provider_context_limit=4096,
            reserved_output=512,
            token_estimate=16,
            privacy_context=PrivacyContext(PrivacyClassification.SAFE_PUBLIC),
            routing_policy=RoutingPolicy.QUALITY_FIRST,
        ),
    )
    assert result.proposed_result == "small-context"
    assert remote.requests[0].model == "small-model"
    assert remote.requests[0].context_limit == 2048

    oversized = ProviderRouter(registry, knowledge=knowledge).route(
        _request(
            context_tokens=4096, privacy_context=PrivacyContext(PrivacyClassification.SAFE_PUBLIC)
        )
    )
    assert oversized.primary is None
    await dispatcher.aclose()
