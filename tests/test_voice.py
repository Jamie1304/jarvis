"""Deterministic local voice activation tests; no microphone hardware is used."""

import asyncio
from collections.abc import AsyncIterator
from datetime import UTC, datetime, timedelta
from uuid import UUID, uuid4

import pytest
from jarvis.permissions import ApprovalChannelClass, ApprovalChannelPolicy, Risk
from jarvis.speech.stt import AudioData, SttProvider, Transcription
from jarvis.speech.tts import TextToSpeechService, TtsProvider
from jarvis.state import ApplicationStateMachine
from jarvis.voice import (
    AudioFrame,
    AudioSource,
    InterruptionCommand,
    LocalVoiceController,
    MicrophoneMode,
    PushToTalkController,
    VADProvider,
    VoiceConfig,
    VoiceState,
    VoiceTaskHandle,
    VoiceTaskOutcome,
    VoiceTaskRunner,
    VoiceWarmup,
    WakeDetection,
    WakeWordProvider,
)
from jarvis.voice.providers import SoundDeviceAudioSource


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


class RecordingStt(FakeStt):
    def __init__(self, text: str = "request") -> None:
        super().__init__(text)
        self.audio: AudioData | None = None

    async def transcribe(self, audio: AudioData) -> Transcription:
        self.audio = audio
        return await super().transcribe(audio)


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
    await controller.handle_frame(frame(0.5))
    await controller.handle_frame(frame(-0.5))
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
    await controller.handle_frame(frame(0.5))
    await controller.handle_frame(frame(-0.5))
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
async def test_capture_preroll_tail_and_noise_rejection() -> None:
    stt = RecordingStt()
    controller = LocalVoiceController(
        FakeWake(),
        FakeVad(),
        stt,
        config=VoiceConfig(
            cooldown_seconds=0,
            preroll_frames=2,
            speech_start_frames=2,
            min_speech_frames=2,
            post_speech_tail_frames=2,
        ),
    )
    await controller.handle_frame(frame(0.9))
    await controller.handle_frame(frame(0.1))
    await controller.handle_frame(frame(0.5))
    await controller.handle_frame(frame(0.5))
    await controller.handle_frame(frame(-0.5))
    await controller.handle_frame(frame(-0.5))

    assert stt.audio is not None
    assert stt.audio.samples == (0.1, 0.5, 0.5, -0.5, -0.5)

    noise_stt = RecordingStt()
    noise = LocalVoiceController(
        FakeWake(),
        FakeVad(),
        noise_stt,
        config=VoiceConfig(cooldown_seconds=0, speech_start_frames=1, min_speech_frames=2),
    )
    await noise.handle_frame(frame(0.9))
    await noise.handle_frame(frame(0.5))
    await noise.handle_frame(frame(-0.5))
    await noise.handle_frame(frame(-0.5))
    assert noise_stt.audio is None


@pytest.mark.asyncio
async def test_ptt_key_repeat_is_edge_triggered() -> None:
    presses: list[str] = []
    ptt = PushToTalkController(
        lambda: _record(presses, "down"),
        lambda: _record(presses, "up"),
    )

    assert await ptt.key_down() is True
    assert await ptt.key_down() is False
    assert await ptt.key_up() is True
    assert await ptt.key_up() is False
    assert presses == ["down", "up"]
    assert ptt.held is False


async def _record(values: list[str], value: str) -> None:
    values.append(value)


def test_microphone_modes_are_explicit_and_not_authority_modes() -> None:
    for mode in MicrophoneMode:
        config = VoiceConfig(microphone_mode=mode)
        assert config.microphone_mode is mode
        assert ApprovalChannelPolicy.classify(Risk.HIGH) is ApprovalChannelClass.PRIVILEGED_APPROVAL


def test_voice_input_models_and_capture_bounds_fail_closed() -> None:
    with pytest.raises(ValueError):
        VoiceConfig(wake_word=" ")
    with pytest.raises(ValueError):
        VoiceConfig(wake_confidence_threshold=1.1)
    with pytest.raises(ValueError):
        VoiceConfig(speech_timeout_seconds=0)
    with pytest.raises(ValueError):
        VoiceConfig(preroll_frames=-1)
    with pytest.raises(ValueError):
        VoiceConfig(interruption_commands=("",))
    with pytest.raises(ValueError):
        AudioFrame((1.1,), 16_000)
    with pytest.raises(ValueError):
        AudioFrame((), 0)
    with pytest.raises(ValueError):
        WakeDetection(False, -0.1, "Jarvis")


@pytest.mark.asyncio
async def test_voice_interruption_commands_cancel_wait_and_ignore_ambiguous_text() -> None:
    runner = FakeRunner()
    tts_provider = FakeTts()
    tts_provider.release.set()
    controller = LocalVoiceController(
        FakeWake(),
        FakeVad(),
        FakeStt("do work"),
        task_runner=runner,
        tts=TextToSpeechService(tts_provider, enabled=True),
        config=VoiceConfig(cooldown_seconds=0),
    )
    await drive_and_get(controller)
    assert await controller.interrupt("maybe") is None
    assert await controller.interrupt("wait") is InterruptionCommand.WAIT
    assert await controller.interrupt("cancel") is InterruptionCommand.CANCEL
    assert runner.cancelled == []


@pytest.mark.asyncio
async def test_voice_capture_without_task_and_stream_failure_degrade_safely() -> None:
    controller = LocalVoiceController(FakeWake(), FakeVad(), FakeStt(""))
    await controller.handle_frame(frame(0.9))
    await controller.handle_frame(frame(0.5))
    await controller.handle_frame(frame(0.5))
    await controller.handle_frame(frame(-0.5))
    await controller.handle_frame(frame(-0.5))
    assert controller.status.state is VoiceState.IDLE

    class BrokenSource(AudioSource):
        async def start(self) -> None:
            pass

        def frames(self) -> AsyncIterator[AudioFrame]:
            async def broken() -> AsyncIterator[AudioFrame]:
                raise RuntimeError("synthetic stream failure")
                yield frame(0.0)

            return broken()

        async def stop(self) -> None:
            pass

    await controller.run(BrokenSource())
    assert controller.status.state.name == VoiceState.ERROR.name


@pytest.mark.asyncio
async def test_voice_close_cancels_pending_task_and_tts() -> None:
    runner = FakeRunner()
    tts_provider = FakeTts()
    controller = LocalVoiceController(
        FakeWake(),
        FakeVad(),
        FakeStt("work"),
        task_runner=runner,
        tts=TextToSpeechService(tts_provider, enabled=True),
        config=VoiceConfig(cooldown_seconds=0),
    )
    await controller.handle_frame(frame(0.9))
    controller._task_handle = VoiceTaskHandle(
        uuid4(), asyncio.create_task(asyncio.sleep(10, result=runner.outcome))
    )
    await controller.aclose()
    assert tts_provider.stopped >= 1
    assert runner.cancelled


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


@pytest.mark.asyncio
async def test_open_mic_failure_degrades_to_ptt() -> None:
    class BrokenSource(AudioSource):
        async def start(self) -> None:
            raise RuntimeError("no microphone")

        def frames(self) -> AsyncIterator[AudioFrame]:
            return iter(())  # type: ignore[return-value]

        async def stop(self) -> None:
            raise AssertionError("failed source must not be stopped as active")

    controller = LocalVoiceController(FakeWake(), FakeVad(), FakeStt("unused"))
    await controller.run(BrokenSource())
    assert controller.microphone_mode is MicrophoneMode.PUSH_TO_TALK
    assert controller.status.state is VoiceState.ERROR


@pytest.mark.asyncio
async def test_voice_warmup_is_non_blocking_and_best_effort() -> None:
    called: list[str] = []

    async def microphone() -> None:
        called.append("microphone")

    async def broken() -> None:
        raise RuntimeError("wake model unavailable")

    warmup = VoiceWarmup((("microphone", microphone), ("wake", broken)))
    results = await warmup.start()
    await warmup.aclose()
    assert called == ["microphone"]
    assert results[0].ready is True
    assert results[1].ready is False


@pytest.mark.asyncio
async def test_sounddevice_stop_terminates_frames_when_queue_is_full() -> None:
    source = SoundDeviceAudioSource()

    class Stream:
        def stop(self) -> None:
            pass

        def close(self) -> None:
            pass

    source._stream = Stream()
    for _ in range(8):
        source._queue.put_nowait(frame(0.0))

    iterator = source.frames()
    await source.stop()

    with pytest.raises(StopAsyncIteration):
        await iterator.__anext__()


@pytest.mark.asyncio
async def test_sounddevice_stale_callback_cannot_resurrect_after_stop() -> None:
    source = SoundDeviceAudioSource()

    class Stream:
        def stop(self) -> None:
            pass

        def close(self) -> None:
            pass

    source._stream = Stream()
    old_generation = source._generation
    await source.stop()
    source._stream = object()
    source._drain_queue()
    source._offer(old_generation, frame(0.9))

    assert source._queue.empty()


@pytest.mark.asyncio
async def test_voice_can_publish_to_authoritative_application_state() -> None:
    tts_provider = FakeTts()
    tts_provider.release.set()
    state_machine = ApplicationStateMachine()
    controller = LocalVoiceController(
        FakeWake(),
        FakeVad(),
        FakeStt("do work"),
        task_runner=FakeRunner(),
        tts=TextToSpeechService(tts_provider, enabled=True),
        config=VoiceConfig(cooldown_seconds=0),
        state_machine=state_machine,
    )
    await drive_and_get(controller)
    assert state_machine.application_state.name == "IDLE"
    assert [item.to_state.name for item in state_machine.history() if item.task_id is None] == [
        "LISTENING",
        "PROCESSING",
        "SPEAKING",
        "IDLE",
    ]
