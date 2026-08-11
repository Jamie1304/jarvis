"""Deterministic local voice activation tests; no microphone hardware is used."""

import asyncio
from collections.abc import AsyncIterator
from datetime import UTC, datetime, timedelta
from uuid import UUID, uuid4

import pytest
from jarvis.speech.stt import AudioData, SttProvider, Transcription
from jarvis.speech.tts import TextToSpeechService, TtsProvider
from jarvis.voice import (
    AudioFrame,
    AudioSource,
    InterruptionCommand,
    LocalVoiceController,
    VADProvider,
    VoiceConfig,
    VoiceState,
    VoiceTaskHandle,
    VoiceTaskOutcome,
    VoiceTaskRunner,
    WakeDetection,
    WakeWordProvider,
)


def frame(marker: float, offset: int = 0) -> AudioFrame:
    return AudioFrame(
        (marker,),
        16_000,
        datetime.now(UTC) + timedelta(seconds=offset),
    )


class FakeWake(WakeWordProvider):
    def __init__(self, confidence: float = 1.0) -> None:
        self.confidence = confidence
        self.calls = 0

    async def detect(self, frame: AudioFrame, wake_word: str) -> WakeDetection:
        self.calls += 1
        return WakeDetection(frame.samples[0] == 0.9, self.confidence, wake_word)


class FakeVad(VADProvider):
    def is_speech(self, frame: AudioFrame) -> bool:
        return frame.samples[0] == 0.5

    def is_end(self, frame: AudioFrame) -> bool:
        return frame.samples[0] == -0.5


class FakeStt(SttProvider):
    def __init__(self, text: str) -> None:
        self.text = text
        self.calls = 0

    async def transcribe(self, audio: AudioData) -> Transcription:
        assert audio.samples
        self.calls += 1
        return Transcription(self.text)


class FakeRunner(VoiceTaskRunner):
    def __init__(self, outcome: VoiceTaskOutcome | None = None) -> None:
        self.started: list[str] = []
        self.cancelled: list[UUID] = []
        self.outcome = outcome or VoiceTaskOutcome(uuid4(), "completed", "done")

    async def start(self, conversation_id: UUID, request: str) -> VoiceTaskHandle:
        del conversation_id
        self.started.append(request)
        task_id = self.outcome.task_id
        return VoiceTaskHandle(task_id, asyncio.create_task(asyncio.sleep(0, result=self.outcome)))

    async def cancel(self, task_id: UUID) -> None:
        self.cancelled.append(task_id)


class FakeTts(TtsProvider):
    def __init__(self) -> None:
        self.spoken: list[str] = []
        self.stopped = 0
        self.started = asyncio.Event()
        self.release = asyncio.Event()

    async def speak(self, text: str) -> None:
        self.spoken.append(text)
        self.started.set()
        await self.release.wait()

    async def stop(self) -> None:
        self.stopped += 1
        self.release.set()


async def drive(controller: LocalVoiceController) -> None:
    await controller.handle_frame(frame(0.9))
    await controller.handle_frame(frame(0.5))
    await controller.handle_frame(frame(-0.5))


@pytest.mark.asyncio
async def test_wake_speech_task_response_state_loop() -> None:
    runner = FakeRunner()
    tts_provider = FakeTts()
    tts_provider.release.set()
    controller = LocalVoiceController(
        FakeWake(),
        FakeVad(),
        FakeStt("prepare my meeting"),
        task_runner=runner,
        tts=TextToSpeechService(tts_provider, enabled=True),
        config=VoiceConfig(cooldown_seconds=0),
    )

    outcome = await drive_and_get(controller)

    assert outcome is not None and outcome.status == "completed"
    assert runner.started == ["prepare my meeting"]
    assert tts_provider.spoken == ["done"]
    assert [item.state for item in controller.history] == [
        VoiceState.IDLE,
        VoiceState.LISTENING,
        VoiceState.PROCESSING,
        VoiceState.SPEAKING,
        VoiceState.IDLE,
    ]


async def drive_and_get(controller: LocalVoiceController) -> VoiceTaskOutcome | None:
    await controller.handle_frame(frame(0.9))
    await controller.handle_frame(frame(0.5))
    return await controller.handle_frame(frame(-0.5))


@pytest.mark.asyncio
async def test_no_wake_and_false_trigger_stay_idle_without_stt() -> None:
    stt = FakeStt("should not run")
    controller = LocalVoiceController(
        FakeWake(confidence=0.2), FakeVad(), stt, config=VoiceConfig()
    )
    await controller.handle_frame(frame(0.0))
    await controller.handle_frame(frame(0.9))
    assert controller.status.state.name == VoiceState.IDLE.name
    assert stt.calls == 0


@pytest.mark.asyncio
async def test_cancel_transcription_never_starts_a_task() -> None:
    runner = FakeRunner()
    controller = LocalVoiceController(
        FakeWake(),
        FakeVad(),
        FakeStt("cancel"),
        task_runner=runner,
        config=VoiceConfig(cooldown_seconds=0),
    )
    await drive(controller)
    assert runner.started == []
    assert controller.status.state is VoiceState.IDLE


@pytest.mark.asyncio
async def test_tts_interruption_stops_playback_and_cancels_central_task() -> None:
    runner = FakeRunner()
    tts_provider = FakeTts()
    controller = LocalVoiceController(
        FakeWake(),
        FakeVad(),
        FakeStt("do work"),
        task_runner=runner,
        tts=TextToSpeechService(tts_provider, enabled=True),
        config=VoiceConfig(cooldown_seconds=0),
    )
    speaking = asyncio.create_task(drive_and_get(controller))
    await tts_provider.started.wait()
    assert controller.status.state == VoiceState.SPEAKING
    assert await controller.interrupt("stop") is InterruptionCommand.STOP
    await speaking
    assert runner.cancelled == [runner.outcome.task_id]
    assert tts_provider.stopped >= 1
    assert controller.status.state.name == VoiceState.IDLE.name


@pytest.mark.asyncio
async def test_microphone_source_is_closed_on_exhaustion() -> None:
    class Source(AudioSource):
        def __init__(self) -> None:
            self.started = False
            self.stopped = False

        async def start(self) -> None:
            self.started = True

        async def stop(self) -> None:
            self.stopped = True

        async def _frames(self) -> AsyncIterator[AudioFrame]:
            yield frame(0.0)

        def frames(self) -> AsyncIterator[AudioFrame]:
            return self._frames()

    source = Source()
    controller = LocalVoiceController(FakeWake(), FakeVad(), FakeStt("unused"))
    await controller.run(source)
    assert source.started and source.stopped
