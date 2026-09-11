"""Application-level proofs for the bounded P3C routing seam."""

from collections.abc import AsyncIterator
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any
from uuid import uuid4

import pytest
from jarvis.agent_runtime import AgentContext, AgentLoop
from jarvis.ai.knowledge import (
    CookbookOutcome,
    ModelKnowledgeService,
    ModelKnowledgeStore,
    VerifierAgreement,
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
from jarvis.core.errors import ProviderUnavailableError
from jarvis.tools.registry import ToolRegistry

from tests.fakes import FakeAIProvider


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
