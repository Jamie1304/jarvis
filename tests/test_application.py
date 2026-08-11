import pytest
from jarvis.application import AssistantEventKind, JarvisAssistantService
from jarvis.conversation.service import ConversationService
from jarvis.speech.tts import TextToSpeechService

from tests.fakes import FakeAIProvider, FakeTtsProvider


@pytest.mark.asyncio
async def test_ui_facing_service_normalizes_streams_and_speaks() -> None:
    provider = FakeAIProvider(("25% van 800 is ", "200."))
    tts_provider = FakeTtsProvider()
    service = JarvisAssistantService(
        ConversationService(provider, model="fake-model", context_limit=1024),
        tts=TextToSpeechService(tts_provider, enabled=True),
    )
    conversation_id = service.create_conversation()

    events = [
        event
        async for event in service.stream_text(
            conversation_id, "Jarvis, hoeveel is 25 procent van 800?"
        )
    ]

    text = "".join(event.content for event in events if event.kind is AssistantEventKind.TEXT)
    assert text == "25% van 800 is 200."
    assert tts_provider.spoken == [text]
    assert provider.requests[0].messages[-1].content == "hoeveel is 25 procent van 800?"
    assert events[-1].done is True
