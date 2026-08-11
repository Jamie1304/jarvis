import pytest
from jarvis.conversation.service import ConversationService
from jarvis.core.errors import ConversationCancelledError

from tests.fakes import FakeAIProvider


@pytest.mark.asyncio
async def test_conversation_keeps_typed_process_local_history() -> None:
    provider = FakeAIProvider(("200",))
    service = ConversationService(provider, model="fake-model", context_limit=1024)
    conversation_id = service.create_conversation("Be concise")

    updates = [
        update async for update in service.stream_reply(conversation_id, "What is 25% of 800?")
    ]
    history = service.history(conversation_id)

    assert "".join(update.content for update in updates) == "200"
    assert [message.role.value for message in history] == ["system", "user", "assistant"]
    assert history[-1].content == "200"


@pytest.mark.asyncio
async def test_conversation_cancellation_stops_stream() -> None:
    provider = FakeAIProvider(("first", "second"))
    service = ConversationService(provider, model="fake-model", context_limit=1024)
    conversation_id = service.create_conversation()
    stream = service.stream_reply(conversation_id, "cancel me")

    first = await anext(stream)
    service.cancel(conversation_id)

    assert first.content == "first"
    with pytest.raises(ConversationCancelledError):
        await anext(stream)
    assert len(service.history(conversation_id)) == 1
