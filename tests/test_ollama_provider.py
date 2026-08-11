from datetime import UTC, datetime
from uuid import uuid4

import httpx
import pytest
from jarvis.ai.models import ChatMessage, GenerationRequest, MessageRole
from jarvis.ai.providers.ollama import OllamaProvider
from jarvis.core.errors import ProviderUnavailableError, StreamingInterruptedError

from tests.fakes import FakeAIProvider


def request() -> GenerationRequest:
    conversation_id = uuid4()
    return GenerationRequest(
        messages=(
            ChatMessage(
                id=uuid4(),
                conversation_id=conversation_id,
                role=MessageRole.USER,
                content="hello",
                created_at=datetime.now(UTC),
            ),
        ),
        model="test-model",
        context_limit=1024,
    )


@pytest.mark.asyncio
async def test_provider_abstraction_streams_fake_response() -> None:
    provider = FakeAIProvider(("hel", "lo"))
    chunks = [chunk async for chunk in provider.stream(request())]

    assert "".join(chunk.content for chunk in chunks) == "hello"
    assert chunks[-1].done is True


@pytest.mark.asyncio
async def test_ollama_provider_reports_failed_connection() -> None:
    def fail(request: httpx.Request) -> httpx.Response:
        raise httpx.ConnectError("offline", request=request)

    client = httpx.AsyncClient(transport=httpx.MockTransport(fail))
    provider = OllamaProvider(
        model="missing-model",
        endpoint="http://ollama.test",
        timeout_seconds=1,
        context_limit=1024,
        client=client,
    )

    health = await provider.health_check()
    assert health.available is False
    with pytest.raises(ProviderUnavailableError):
        await provider.generate(request())
    await client.aclose()


@pytest.mark.asyncio
async def test_ollama_provider_rejects_interrupted_stream() -> None:
    def incomplete(_: httpx.Request) -> httpx.Response:
        return httpx.Response(200, content=b'{"message":{"content":"partial"}}\n')

    client = httpx.AsyncClient(transport=httpx.MockTransport(incomplete))
    provider = OllamaProvider(
        model="test-model",
        endpoint="http://ollama.test",
        timeout_seconds=1,
        context_limit=1024,
        client=client,
    )

    with pytest.raises(StreamingInterruptedError):
        _ = [chunk async for chunk in provider.stream(request())]
    await client.aclose()
