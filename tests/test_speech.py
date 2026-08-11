from datetime import UTC, datetime

import pytest
from jarvis.speech.stt import AudioData, SpeechToTextService
from jarvis.speech.tts import TextToSpeechService

from tests.fakes import FakeRecorder, FakeSttProvider, FakeTtsProvider


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
