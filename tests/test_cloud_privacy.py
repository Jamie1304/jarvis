from __future__ import annotations

from collections.abc import AsyncIterator
from dataclasses import replace
from datetime import UTC, datetime
from typing import Any, cast
from uuid import uuid4

import pytest
from jarvis.agent_runtime import AgentContext, AgentLoop, AgentTerminationReason
from jarvis.ai.models import (
    ChatMessage,
    GenerationChunk,
    GenerationRequest,
    GenerationResult,
    MessageRole,
    ModelInfo,
    PrivacyClassification,
    PrivacyContext,
    ProviderHealth,
)
from jarvis.ai.privacy import (
    CloudTaskEnvelope,
    PrivacyBoundary,
    PrivacyDecisionStatus,
    PrivacyGuardedProvider,
)
from jarvis.ai.providers.base import AIProvider
from jarvis.ai.providers.registry import (
    ProviderDefinition,
    ProviderLocality,
    ProviderMetadata,
    ProviderRegistry,
    VoiceProviderDefinition,
    VoiceProviderKind,
)
from jarvis.conversation.service import ConversationService
from jarvis.core.errors import PrivacyBlockedError, RemoteOutputRejectedError
from jarvis.tools.registry import ToolRegistry


class CapturingProvider(AIProvider):
    def __init__(self, response: str = "ok") -> None:
        self.requests: list[GenerationRequest] = []
        self.response = response

    async def generate(self, request: GenerationRequest) -> GenerationResult:
        self.requests.append(request)
        return GenerationResult(self.response, request.model)

    async def stream(self, request: GenerationRequest) -> AsyncIterator[GenerationChunk]:
        self.requests.append(request)
        yield GenerationChunk(self.response, True)

    async def health_check(self) -> ProviderHealth:
        return ProviderHealth(True, "capture")

    async def model_info(self) -> ModelInfo:
        return ModelInfo("capture", "capture", 4096)

    async def aclose(self) -> None:
        return None


def _request(content: str, context: PrivacyContext) -> GenerationRequest:
    return GenerationRequest(
        (ChatMessage(uuid4(), uuid4(), MessageRole.USER, content, datetime.now(UTC)),),
        "remote-model",
        4096,
        context,
    )


def _remote(provider: AIProvider) -> PrivacyGuardedProvider:
    return PrivacyGuardedProvider(
        provider,
        ProviderMetadata(
            "capture",
            "Capturing remote provider",
            "test",
            locality=ProviderLocality.REMOTE,
        ),
    )


@pytest.mark.asyncio
async def test_public_remote_payload_is_exactly_captured_and_allowed() -> None:
    provider = CapturingProvider()
    guarded = _remote(provider)

    await guarded.generate(
        _request(
            "Summarize this public sentence.", PrivacyContext(PrivacyClassification.SAFE_PUBLIC)
        )
    )

    assert provider.requests[0].messages[0].content == "Summarize this public sentence."
    assert provider.requests[0].privacy_context.known_private_values == ()
    assert guarded.boundary.last_decision is not None
    assert guarded.boundary.last_decision.status is PrivacyDecisionStatus.ALLOWED_REMOTE


@pytest.mark.asyncio
async def test_known_private_values_are_sanitized_and_restored_locally() -> None:
    provider = CapturingProvider("Hello <PERSON_1>!")
    guarded = _remote(provider)
    request = _request(
        "Write a greeting to Jamie Example.",
        PrivacyContext(PrivacyClassification.SANITIZABLE, ("Jamie Example",)),
    )

    result = await guarded.generate(request)

    captured = provider.requests[0].messages[0].content
    assert "Jamie Example" not in captured
    assert "<PERSON_1>" in captured
    assert result.content == "Hello Jamie Example!"


@pytest.mark.asyncio
async def test_email_canary_and_secret_never_cross_remote_boundary() -> None:
    provider = CapturingProvider()
    guarded = _remote(provider)
    email = "private-user-771@example.test"
    result = await guarded.generate(
        _request(
            f"Dutch: mijn email is {email}",
            PrivacyContext(PrivacyClassification.SANITIZABLE, (email,)),
        )
    )
    assert email not in provider.requests[0].messages[0].content
    assert result.content == "ok"
    with pytest.raises(PrivacyBlockedError) as error:
        await guarded.generate(
            _request(
                "Send password=synthetic-secret to the model.",
                PrivacyContext(PrivacyClassification.SANITIZABLE),
            )
        )
    assert error.value.code == "CLOUD_ROUTE_BLOCKED_PRIVACY"
    assert len(provider.requests) == 1


@pytest.mark.asyncio
async def test_unknown_locality_fails_closed_for_unknown_and_local_only_context() -> None:
    provider = CapturingProvider()
    guarded = PrivacyGuardedProvider(provider, ProviderMetadata("unknown", "Unknown", "test"))
    for classification in (
        PrivacyClassification.UNKNOWN,
        PrivacyClassification.LOCAL_ONLY,
        PrivacyClassification.SECRET,
    ):
        with pytest.raises(PrivacyBlockedError):
            await guarded.generate(_request("private", PrivacyContext(classification)))
    assert provider.requests == []


@pytest.mark.asyncio
async def test_local_provider_passes_private_nonsecret_text_without_cloud_sanitization() -> None:
    provider = CapturingProvider()
    guarded = PrivacyGuardedProvider(
        provider, ProviderMetadata("local", "Local", "test", local_only=True)
    )
    await guarded.generate(
        _request(
            "BLUE-ORCHID-92814",
            PrivacyContext(PrivacyClassification.LOCAL_ONLY, ("BLUE-ORCHID-92814",)),
        )
    )
    assert provider.requests[0].messages[0].content == "BLUE-ORCHID-92814"
    assert guarded.boundary.last_decision is not None
    assert guarded.boundary.last_decision.status is PrivacyDecisionStatus.LOCAL_PASS_THROUGH


@pytest.mark.asyncio
async def test_conversation_does_not_send_process_local_history() -> None:
    provider = CapturingProvider()
    service = ConversationService(
        provider,
        model="remote-model",
        context_limit=1024,
        provider_metadata=ProviderMetadata(
            "remote", "Remote", "test", locality=ProviderLocality.REMOTE
        ),
    )
    conversation_id = service.create_conversation()
    await anext(
        service.stream_reply(
            conversation_id,
            "private-user-771@example.test",
            privacy_context=PrivacyContext(PrivacyClassification.SANITIZABLE),
        )
    )
    [
        update
        async for update in service.stream_reply(
            conversation_id,
            "Rewrite this sentence.",
            privacy_context=PrivacyContext(PrivacyClassification.SAFE_PUBLIC),
        )
    ]

    assert len(provider.requests) == 2
    assert all(
        "private-user-771@example.test" not in message.content
        for request in provider.requests
        for message in request.messages
    )
    assert service.history(conversation_id)[0].content == "private-user-771@example.test"


@pytest.mark.asyncio
async def test_agent_context_and_tool_outputs_are_sanitized_before_remote_capture() -> None:
    provider = CapturingProvider('{"kind":"response","content":"done"}')
    loop = AgentLoop(
        provider,
        ToolRegistry(()),
        model="remote-model",
        context_limit=4096,
        provider_metadata=ProviderMetadata(
            "remote", "Remote", "test", locality=ProviderLocality.REMOTE
        ),
    )
    result = await loop.run(
        uuid4(),
        "rewrite",
        context=AgentContext(
            request="rewrite",
            goal="rewrite",
            selected_memory=("BLUE-ORCHID-92814",),
            tool_outputs=("private-contact-284@example.test",),
            provider_context_limit=4096,
            privacy_context=PrivacyContext(PrivacyClassification.SANITIZABLE),
        ),
    )

    assert result.termination_reason is AgentTerminationReason.COMPLETED
    captured = "\n".join(message.content for message in provider.requests[0].messages)
    assert "BLUE-ORCHID-92814" not in captured
    assert "private-contact-284@example.test" not in captured


@pytest.mark.asyncio
async def test_missing_conversation_metadata_is_unknown_and_blocks_synthetic_private_text() -> None:
    provider = CapturingProvider()
    service = ConversationService(provider, model="remote-model", context_limit=4096)
    conversation_id = service.create_conversation()

    with pytest.raises(PrivacyBlockedError):
        await anext(
            service.stream_reply(
                conversation_id,
                "BLUE-ORCHID-92814",
            )
        )

    assert provider.requests == []


@pytest.mark.asyncio
async def test_missing_agent_metadata_is_unknown_and_blocks_before_provider_invocation() -> None:
    provider = CapturingProvider('{"kind":"response","content":"done"}')
    loop = AgentLoop(provider, ToolRegistry(()), model="remote-model", context_limit=4096)

    result = await loop.run(
        uuid4(),
        "BLUE-ORCHID-92814",
        context=AgentContext(
            request="BLUE-ORCHID-92814",
            goal="GOAL-BLUE-ORCHID-92814",
            provider_context_limit=4096,
        ),
    )

    assert result.termination_reason is AgentTerminationReason.PRIVACY_BLOCKED
    assert provider.requests == []


@pytest.mark.asyncio
async def test_remote_conversation_requires_explicit_privacy_classification() -> None:
    provider = CapturingProvider()
    service = ConversationService(
        provider,
        model="remote-model",
        context_limit=4096,
        provider_metadata=ProviderMetadata(
            "remote", "Remote", "test", locality=ProviderLocality.REMOTE
        ),
    )
    conversation_id = service.create_conversation()

    with pytest.raises(PrivacyBlockedError):
        await anext(service.stream_reply(conversation_id, "BLUE-ORCHID-92814"))

    assert provider.requests == []


@pytest.mark.asyncio
async def test_explicit_remote_safe_public_conversation_remains_allowed() -> None:
    provider = CapturingProvider()
    service = ConversationService(
        provider,
        model="remote-model",
        context_limit=4096,
        provider_metadata=ProviderMetadata(
            "remote", "Remote", "test", locality=ProviderLocality.REMOTE
        ),
    )
    conversation_id = service.create_conversation()

    [
        update
        async for update in service.stream_reply(
            conversation_id,
            "The public release is scheduled for Friday.",
            privacy_context=PrivacyContext(PrivacyClassification.SAFE_PUBLIC),
        )
    ]

    assert (
        provider.requests[0].messages[-1].content == "The public release is scheduled for Friday."
    )


@pytest.mark.asyncio
async def test_explicit_remote_sanitizable_conversation_protects_known_synthetic_value() -> None:
    provider = CapturingProvider()
    service = ConversationService(
        provider,
        model="remote-model",
        context_limit=4096,
        provider_metadata=ProviderMetadata(
            "remote", "Remote", "test", locality=ProviderLocality.REMOTE
        ),
    )
    conversation_id = service.create_conversation()

    [
        update
        async for update in service.stream_reply(
            conversation_id,
            "Please summarize BLUE-ORCHID-92814.",
            privacy_context=PrivacyContext(
                PrivacyClassification.SANITIZABLE, ("BLUE-ORCHID-92814",)
            ),
        )
    ]

    captured = provider.requests[0].messages[-1].content
    assert "BLUE-ORCHID-92814" not in captured
    assert "<PRIVATE_1>" in captured


@pytest.mark.asyncio
async def test_explicit_remote_agent_sanitizes_request_goal_and_constraints() -> None:
    provider = CapturingProvider('{"kind":"response","content":"done"}')
    loop = AgentLoop(
        provider,
        ToolRegistry(()),
        model="remote-model",
        context_limit=4096,
        provider_metadata=ProviderMetadata(
            "remote", "Remote", "test", locality=ProviderLocality.REMOTE
        ),
    )
    values = (
        "BLUE-ORCHID-92814",
        "GOAL-BLUE-ORCHID-92814",
        "CONSTRAINT-BLUE-ORCHID-92814",
    )
    result = await loop.run(
        uuid4(),
        values[0],
        context=AgentContext(
            request=values[0],
            goal=values[1],
            constraints=(values[2],),
            provider_context_limit=4096,
            privacy_context=PrivacyContext(PrivacyClassification.SANITIZABLE, values),
        ),
    )

    captured = "\n".join(message.content for message in provider.requests[0].messages)
    assert result.termination_reason is AgentTerminationReason.COMPLETED
    assert all(value not in captured for value in values)


@pytest.mark.asyncio
async def test_explicit_local_conversation_and_agent_allow_private_nonsecret_text() -> None:
    metadata = ProviderMetadata("local", "Local", "test", locality=ProviderLocality.LOCAL)
    conversation_provider = CapturingProvider()
    service = ConversationService(
        conversation_provider,
        model="local-model",
        context_limit=4096,
        provider_metadata=metadata,
    )
    conversation_id = service.create_conversation()
    [update async for update in service.stream_reply(conversation_id, "BLUE-ORCHID-92814")]
    assert conversation_provider.requests[0].messages[-1].content == "BLUE-ORCHID-92814"

    agent_provider = CapturingProvider('{"kind":"response","content":"done"}')
    result = await AgentLoop(
        agent_provider,
        ToolRegistry(()),
        model="local-model",
        context_limit=4096,
        provider_metadata=metadata,
    ).run(uuid4(), "BLUE-ORCHID-92814")
    assert result.termination_reason is AgentTerminationReason.COMPLETED
    assert "BLUE-ORCHID-92814" in agent_provider.requests[0].messages[0].content


@pytest.mark.asyncio
async def test_known_private_value_is_checked_on_inbound_even_without_outbound_placeholder() -> (
    None
):
    provider = CapturingProvider("BLUE-ORCHID-92814")
    with pytest.raises(RemoteOutputRejectedError):
        await _remote(provider).generate(
            _request(
                "A public sentence.",
                PrivacyContext(PrivacyClassification.SANITIZABLE, ("BLUE-ORCHID-92814",)),
            )
        )


@pytest.mark.asyncio
async def test_secret_generic_model_context_remains_blocked_for_explicit_local_agent() -> None:
    provider = CapturingProvider('{"kind":"response","content":"done"}')
    loop = AgentLoop(
        provider,
        ToolRegistry(()),
        model="local-model",
        context_limit=4096,
        provider_metadata=ProviderMetadata(
            "local", "Local", "test", locality=ProviderLocality.LOCAL
        ),
    )
    result = await loop.run(
        uuid4(),
        "safe task",
        context=AgentContext(
            request="safe task",
            goal="safe task",
            security_context=(("credential", "password=synthetic-secret"),),
            provider_context_limit=4096,
        ),
    )
    assert result.termination_reason is AgentTerminationReason.PRIVACY_BLOCKED
    assert provider.requests == []


@pytest.mark.asyncio
async def test_invented_placeholder_is_not_restored_and_original_remote_output_is_rejected() -> (
    None
):
    invented_provider = CapturingProvider("<PERSON_99>")
    result = await _remote(invented_provider).generate(
        _request(
            "greet Jamie Example",
            PrivacyContext(PrivacyClassification.SANITIZABLE, ("Jamie Example",)),
        )
    )
    assert result.content == "<PERSON_99>"
    with pytest.raises(RemoteOutputRejectedError):
        await _remote(CapturingProvider("Jamie Example")).generate(
            _request(
                "greet Jamie Example",
                PrivacyContext(PrivacyClassification.SANITIZABLE, ("Jamie Example",)),
            )
        )


def test_malformed_envelope_is_rejected_and_cloud_envelope_is_bounded() -> None:
    with pytest.raises(ValueError):
        CloudTaskEnvelope("", "public")
    boundary = PrivacyBoundary(
        ProviderMetadata("remote", "Remote", "test", locality=ProviderLocality.REMOTE)
    )
    with pytest.raises(PrivacyBlockedError):
        boundary.prepare(_request("x" * 16_001, PrivacyContext(PrivacyClassification.SAFE_PUBLIC)))


@pytest.mark.asyncio
async def test_privacy_envelope_validation_and_provider_facade_bounds() -> None:
    provider = CapturingProvider("ok")
    guarded = _remote(provider)
    boundary = guarded.boundary
    with pytest.raises(PrivacyBlockedError):
        boundary.prepare(
            replace(
                _request("public", PrivacyContext(PrivacyClassification.SAFE_PUBLIC)),
                privacy_context=cast(Any, object()),
            )
        )
    await guarded.generate(
        replace(
            _request(
                "a@example.test and a@example.test",
                PrivacyContext(PrivacyClassification.SANITIZABLE),
            ),
            model="public-model",
        )
    )
    envelope = boundary.envelope(
        _request("public", PrivacyContext(PrivacyClassification.SAFE_PUBLIC))
    )
    assert envelope.objective == "text-inference"
    assert (await guarded.model_info()).provider == "capture"

    with pytest.raises(PrivacyBlockedError):
        boundary.prepare(
            replace(
                _request(
                    "public",
                    PrivacyContext(PrivacyClassification.SANITIZABLE, ("private-model",)),
                ),
                model="private-model",
            )
        )
    with pytest.raises(PrivacyBlockedError):
        boundary.prepare(
            replace(
                _request("public", PrivacyContext(PrivacyClassification.SAFE_PUBLIC)),
                model="password=synthetic-secret",
            )
        )

    with pytest.raises(RemoteOutputRejectedError):
        await _remote(CapturingProvider("x" * 1_000_001)).generate(
            _request("public", PrivacyContext(PrivacyClassification.SAFE_PUBLIC))
        )


def test_privacy_value_contracts_reject_malformed_values() -> None:
    with pytest.raises(ValueError):
        PrivacyContext(cast(Any, "unknown"))
    with pytest.raises(ValueError):
        PrivacyContext(PrivacyClassification.SAFE_PUBLIC, cast(Any, ["private"]))
    with pytest.raises(ValueError):
        PrivacyContext(PrivacyClassification.SAFE_PUBLIC, ("",))
    with pytest.raises(ValueError):
        PrivacyContext(PrivacyClassification.SAFE_PUBLIC, (), cast(Any, ("id",)))
    with pytest.raises(ValueError):
        CloudTaskEnvelope("objective", "input", constraints=("",))
    with pytest.raises(ValueError):
        CloudTaskEnvelope("objective", "input", public_references=("",))
    with pytest.raises(ValueError):
        CloudTaskEnvelope("objective", "input", correlation_ref="")


def test_provider_locality_and_voice_contracts_fail_closed() -> None:
    with pytest.raises(ValueError):
        ProviderMetadata("provider", "Provider", "test", locality=cast(Any, "local"))
    with pytest.raises(ValueError):
        ProviderMetadata("provider", "Provider", "test", True, ProviderLocality.REMOTE)
    metadata = ProviderMetadata("provider", "Provider", "test", local_only=True)
    with pytest.raises(ValueError):
        VoiceProviderDefinition(cast(Any, "tts"), metadata, cast(Any, lambda _: object()))
    with pytest.raises(ValueError):
        VoiceProviderDefinition(
            VoiceProviderKind.TTS, metadata, cast(Any, lambda _: object()), cast(Any, [])
        )
    registry = ProviderRegistry()
    registry.register(ProviderDefinition(metadata, cast(Any, lambda _: CapturingProvider())))
    assert registry.definition("provider").metadata.explicitly_local
