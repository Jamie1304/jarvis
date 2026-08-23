import asyncio
from collections.abc import AsyncIterable, AsyncIterator
from datetime import UTC, datetime

import pytest
from jarvis.core.errors import SpeechError
from jarvis.speech.stt import AudioData, SpeechToTextService
from jarvis.speech.tts import SpeakableChunker, TextToSpeechService, TtsProvider

from tests.fakes import FakeRecorder, FakeSttProvider, FakeTtsProvider


class PersistentFakeTts(TtsProvider):
    def __init__(self) -> None:
        self.open_count = 0
        self.spoken: list[str] = []
        self.first = asyncio.Event()
        self.release = asyncio.Event()

    async def speak(self, text: str) -> None:
        self.spoken.append(text)

    async def speak_chunks(self, chunks: AsyncIterable[str]) -> None:
        self.open_count += 1
        async for chunk in chunks:
            self.spoken.append(chunk)
            self.first.set()
            await self.release.wait()

    async def stop(self) -> None:
        self.release.set()


class FailingTts(TtsProvider):
    async def speak(self, text: str) -> None:
        del text
        raise SpeechError("primary failed")

    async def stop(self) -> None:
        return None


@pytest.mark.asyncio
async def test_stt_service_records_then_transcribes_with_fake_audio() -> None:
    audio = AudioData(samples=(0.1, -0.1), sample_rate=16_000, captured_at=datetime.now(UTC))
    recorder = FakeRecorder(audio)
    provider = FakeSttProvider("hallo jarvis")
    service = SpeechToTextService(recorder, provider)

    await service.start_recording()
    result = await service.stop_and_transcribe()

    assert recorder.started is False
    assert provider.received == audio
    assert result.text == "hallo jarvis"


@pytest.mark.asyncio
async def test_tts_lifecycle_tracks_playback_and_stop() -> None:
    provider = FakeTtsProvider()
    service = TextToSpeechService(provider, enabled=True)

    await service.speak("200")
    await service.stop()

    assert provider.spoken == ["200"]
    assert provider.stopped is True
    assert service.is_speaking is False


def test_speakable_chunker_holds_incomplete_markup_and_emits_sentences() -> None:
    chunker = SpeakableChunker()
    assert chunker.feed("Hello. ") == ("Hello.",)
    assert chunker.feed('<tool_call>{"x": 1') == ()
    assert chunker.feed("}</tool_call>") == ()
    assert chunker.finish() == ()


@pytest.mark.asyncio
async def test_incremental_tts_uses_one_persistent_output_stream() -> None:
    provider = PersistentFakeTts()
    service = TextToSpeechService(provider, enabled=True)

    async def chunks() -> AsyncIterator[str]:
        yield "First sentence."
        await provider.first.wait()
        yield "Second sentence."

    task = asyncio.create_task(service.speak_incremental(chunks()))
    await provider.first.wait()
    assert provider.spoken == ["First sentence."]
    provider.release.set()
    await task
    assert provider.open_count == 1
    assert provider.spoken == ["First sentence.", "Second sentence."]


@pytest.mark.asyncio
async def test_tts_barge_in_invalidates_queued_old_response() -> None:
    provider = PersistentFakeTts()
    service = TextToSpeechService(provider, enabled=True)

    async def chunks() -> AsyncIterator[str]:
        yield "Old sentence."
        await asyncio.sleep(0)
        yield "Stale sentence."

    task = service.start_incremental(chunks())
    await provider.first.wait()
    await service.stop()
    provider.release.set()
    await asyncio.gather(task, return_exceptions=True)
    assert provider.spoken == ["Old sentence."]


@pytest.mark.asyncio
async def test_tts_falls_back_then_degrades_to_text_only() -> None:
    fallback = FakeTtsProvider()
    service = TextToSpeechService(FailingTts(), enabled=True, fallback=fallback)

    await service.speak("fallback")

    assert fallback.spoken == ["fallback"]
    assert service.available is True
