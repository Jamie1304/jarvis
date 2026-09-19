"""Controlled, local-first voice activation.

Idle audio is offered only to the configured wake-word provider.  No STT, cloud
provider, task, or durable storage is touched until a wake is accepted.
"""

import asyncio
import re
from abc import ABC, abstractmethod
from collections import deque
from collections.abc import AsyncIterator, Awaitable, Callable
from dataclasses import dataclass, field
from datetime import UTC, datetime
from enum import StrEnum
from typing import Protocol
from uuid import UUID, uuid4

from jarvis.ai.sessions import AgentSessionStore, AgentSessionType
from jarvis.autonomy.models import Task, TaskStatus
from jarvis.autonomy.orchestrator import AgentOrchestrator
from jarvis.events import EventBus, EventEnvelope, EventType, VoiceStateChanged
from jarvis.speech.stt import AudioData, SttProvider
from jarvis.speech.tts import TextToSpeechService
from jarvis.state import ApplicationStateMachine
from jarvis.state.models import ApplicationState, TransitionEvent
from jarvis.task_controller import TaskController

# Compatibility name for UI clients; application state is authoritative.
VoiceState = ApplicationState


class InterruptionCommand(StrEnum):
    STOP = "stop"
    CANCEL = "cancel"
    WAIT = "wait"


class MicrophoneMode(StrEnum):
    """Capture policy; it never changes permission or approval policy."""

    PUSH_TO_TALK = "push_to_talk"
    WAKE_WORD = "wake_word"
    OPEN_MIC = "open_mic"


@dataclass(frozen=True, slots=True)
class VoiceConfig:
    """Bounded voice behavior; idle wake processing remains local by contract."""

    wake_word: str = "Jarvis"
    wake_confidence_threshold: float = 0.8
    cooldown_seconds: float = 1.0
    max_utterance_seconds: float = 15.0
    speech_timeout_seconds: float = 5.0
    interruption_commands: tuple[str, ...] = ("stop", "cancel", "wait")
    microphone_mode: MicrophoneMode = MicrophoneMode.WAKE_WORD
    preroll_frames: int = 3
    speech_start_frames: int = 2
    min_speech_frames: int = 2
    post_speech_tail_frames: int = 2

    def __post_init__(self) -> None:
        word = " ".join(self.wake_word.split()).strip()
        if not word:
            raise ValueError("wake_word must not be empty")
        if not 0 <= self.wake_confidence_threshold <= 1:
            raise ValueError("wake_confidence_threshold must be between zero and one")
        if self.cooldown_seconds < 0 or self.max_utterance_seconds <= 0:
            raise ValueError("voice timing limits are invalid")
        if self.speech_timeout_seconds <= 0:
            raise ValueError("speech_timeout_seconds must be positive")
        if not isinstance(self.microphone_mode, MicrophoneMode):
            raise ValueError("microphone_mode is invalid")
        if (
            min(
                self.preroll_frames,
                self.speech_start_frames,
                self.min_speech_frames,
                self.post_speech_tail_frames,
            )
            < 0
            or self.speech_start_frames < 1
            or self.min_speech_frames < 1
        ):
            raise ValueError("voice capture frame bounds are invalid")
        commands = tuple(" ".join(item.casefold().split()) for item in self.interruption_commands)
        if not commands or any(not item for item in commands):
            raise ValueError("interruption_commands must not contain empty values")
        object.__setattr__(self, "wake_word", word)
        object.__setattr__(self, "interruption_commands", commands)


@dataclass(frozen=True, slots=True)
class AudioFrame:
    """Transient microphone data.  Implementations must not persist it."""

    samples: tuple[float, ...]
    sample_rate: int
    captured_at: datetime = field(default_factory=lambda: datetime.now(UTC))

    def __post_init__(self) -> None:
        if self.sample_rate <= 0:
            raise ValueError("sample_rate must be positive")
        if any(not -1.0 <= sample <= 1.0 for sample in self.samples):
            raise ValueError("audio samples must be normalized")


@dataclass(frozen=True, slots=True)
class WakeDetection:
    detected: bool
    confidence: float
    wake_word: str

    def __post_init__(self) -> None:
        if not 0 <= self.confidence <= 1:
            raise ValueError("wake confidence must be between zero and one")


@dataclass(frozen=True, slots=True)
class VoiceStatus:
    state: VoiceState
    wake_monitoring: bool
    session_id: UUID | None
    reason: str
    changed_at: datetime


@dataclass(frozen=True, slots=True)
class VoiceTaskOutcome:
    task_id: UUID
    status: str
    response: str | None = None
    error: str | None = None


@dataclass(frozen=True, slots=True)
class VoiceTaskHandle:
    task_id: UUID
    completion: asyncio.Task[VoiceTaskOutcome]


class WakeWordProvider(ABC):
    """Provider called for every idle frame; it must be local-only in idle mode."""

    @abstractmethod
    async def detect(self, frame: AudioFrame, wake_word: str) -> WakeDetection:
        """Return a bounded detection without sending audio to a service."""


class VADProvider(ABC):
    @abstractmethod
    def is_speech(self, frame: AudioFrame) -> bool:
        """Identify speech in a transient frame."""

    @abstractmethod
    def is_end(self, frame: AudioFrame) -> bool:
        """Identify an end-of-utterance marker."""


class AudioSource(ABC):
    """On-demand source lifecycle; no always-on cloud stream is implied."""

    @abstractmethod
    async def start(self) -> None:
        """Open the local capture source."""

    @abstractmethod
    def frames(self) -> AsyncIterator[AudioFrame]:
        """Yield transient frames until stopped."""

    @abstractmethod
    async def stop(self) -> None:
        """Close the source and discard buffers."""


class VoiceTaskRunner(Protocol):
    async def start(self, conversation_id: UUID, request: str) -> VoiceTaskHandle:
        """Create a task through the central task controller."""

    async def cancel(self, task_id: UUID) -> None:
        """Delegate cancellation to the central task controller."""


class PushToTalkController:
    """Edge-triggered PTT adapter; repeated key-down events are ignored."""

    def __init__(
        self,
        on_pressed: Callable[[], Awaitable[None]],
        on_released: Callable[[], Awaitable[None]],
    ) -> None:
        self._on_pressed = on_pressed
        self._on_released = on_released
        self._held = False

    @property
    def held(self) -> bool:
        return self._held

    async def key_down(self) -> bool:
        if self._held:
            return False
        self._held = True
        try:
            await self._on_pressed()
        except BaseException:
            self._held = False
            raise
        return True

    async def key_up(self) -> bool:
        if not self._held:
            return False
        self._held = False
        await self._on_released()
        return True

    async def reset(self) -> None:
        if self._held:
            await self.key_up()


class OrchestratorVoiceTaskRunner:
    """Deprecated compatibility adapter; production must use PlanningVoiceTaskRunner."""

    def __init__(self, orchestrator: AgentOrchestrator) -> None:
        self._orchestrator = orchestrator

    async def start(self, conversation_id: UUID, request: str) -> VoiceTaskHandle:
        task = await self._orchestrator.create_task(conversation_id, request)
        completion = asyncio.create_task(self._run(task))
        return VoiceTaskHandle(task.task_id, completion)

    async def cancel(self, task_id: UUID) -> None:
        await self._orchestrator.cancel(task_id)

    async def _run(self, task: Task) -> VoiceTaskOutcome:
        result = await self._orchestrator.run(task.task_id)
        return VoiceTaskOutcome(
            task_id=result.task_id,
            status=result.status.value,
            response=result.result.summary if result.result else None,
            error=result.error.message if result.error else None,
        )


class PlanningVoiceTaskRunner:
    """Voice adapter for the canonical TaskController, never AgentOrchestrator."""

    def __init__(
        self,
        controller: TaskController,
        *,
        session_store: AgentSessionStore | None = None,
        provider_id: str = "default",
        model_id: str = "default",
    ) -> None:
        self._controller = controller
        self._session_store = session_store
        self._provider_id = provider_id
        self._model_id = model_id
        self._sessions: dict[UUID, UUID] = {}
        self._task_sessions: dict[UUID, UUID] = {}

    def session_id(self, conversation_id: UUID) -> UUID | None:
        return self._sessions.get(conversation_id)

    async def start(self, conversation_id: UUID, request: str) -> VoiceTaskHandle:
        session_id = self._ensure_session(conversation_id)
        task = await self._controller.create_task(request)
        if session_id is not None:
            self._task_sessions[task.task_id] = session_id
        completion = asyncio.create_task(self._run(task.task_id))
        return VoiceTaskHandle(task.task_id, completion)

    async def cancel(self, task_id: UUID) -> None:
        session_id = self._task_sessions.get(task_id)
        if session_id is not None and self._session_store is not None:
            self._session_store.mark_synchronized(session_id, False)
        await self._controller.cancel_task(task_id)

    async def _run(self, task_id: UUID) -> VoiceTaskOutcome:
        result = await self._controller.run_task(task_id)
        session_id = self._task_sessions.pop(task_id, None)
        if session_id is not None and self._session_store is not None:
            self._session_store.mark_synchronized(session_id, result.status.value == "completed")
        return VoiceTaskOutcome(
            task_id,
            result.status.value,
            response=None,
            error=result.error.code if result.error is not None else None,
        )

    def _ensure_session(self, conversation_id: UUID) -> UUID | None:
        if self._session_store is None:
            return None
        session_id = self._sessions.get(conversation_id)
        if session_id is None:
            session = self._session_store.create(
                AgentSessionType.VOICE,
                self._provider_id,
                self._model_id,
                context_metadata=(("conversation_id", str(conversation_id)),),
            )
        else:
            current = self._session_store.get(session_id)
            if current is None:
                session = self._session_store.create(
                    AgentSessionType.VOICE, self._provider_id, self._model_id
                )
            elif current.archived or not current.synchronized:
                session = self._session_store.rebuild(session_id)
            else:
                session = current
        self._sessions[conversation_id] = session.session_id
        return session.session_id


class LocalVoiceController:
    """Single state machine for wake, capture, task execution, and response."""

    def __init__(
        self,
        wake_provider: WakeWordProvider,
        vad: VADProvider,
        stt: SttProvider,
        *,
        task_runner: VoiceTaskRunner | None = None,
        tts: TextToSpeechService | None = None,
        response_canceller: Callable[[], Awaitable[None]] | None = None,
        config: VoiceConfig | None = None,
        state_machine: ApplicationStateMachine | None = None,
        event_bus: EventBus | None = None,
    ) -> None:
        self._wake = wake_provider
        self._vad = vad
        self._stt = stt
        self._runner = task_runner
        self._tts = tts
        self._response_canceller = response_canceller
        self._config = config or VoiceConfig()
        self._microphone_mode = self._config.microphone_mode
        self._state_machine = state_machine
        self._event_bus = event_bus
        self._status = VoiceStatus(VoiceState.IDLE, True, None, "ready", datetime.now(UTC))
        self._history: list[VoiceStatus] = [self._status]
        self._session_id: UUID | None = None
        self._frames: list[AudioFrame] = []
        self._pre_roll: deque[AudioFrame] = deque(maxlen=self._config.preroll_frames)
        self._speech_candidate: list[AudioFrame] = []
        self._speech_seen = False
        self._speech_frames = 0
        self._tail_remaining = 0
        self._task_handle: VoiceTaskHandle | None = None
        self._cooldown_until = 0.0
        self._listening_started = 0.0
        self._last_speech_at = 0.0

    @property
    def status(self) -> VoiceStatus:
        return self._status

    @property
    def history(self) -> tuple[VoiceStatus, ...]:
        return tuple(self._history)

    @property
    def microphone_mode(self) -> MicrophoneMode:
        return self._microphone_mode

    def set_microphone_mode(self, mode: MicrophoneMode) -> None:
        """Change capture behavior only; broker policy is deliberately untouched."""

        if not isinstance(mode, MicrophoneMode):
            raise ValueError("microphone mode is invalid")
        self._microphone_mode = mode

    async def handle_frame(self, frame: AudioFrame) -> VoiceTaskOutcome | None:
        """Process exactly one frame; callers own source lifecycle and scheduling."""

        now = asyncio.get_running_loop().time()
        if self._status.state is VoiceState.SPEAKING and self._vad.is_speech(frame):
            await self._barge_in("speech detected during response")
            self._session_id = uuid4()
            self._listening_started = now
            self._last_speech_at = now
            self._transition(VoiceState.LISTENING, "barge-in accepted")
        if self._status.state is VoiceState.IDLE:
            if now < self._cooldown_until:
                return None
            try:
                detection = await self._wake.detect(frame, self._config.wake_word)
            except Exception:
                self._microphone_mode = MicrophoneMode.PUSH_TO_TALK
                self._transition(VoiceState.ERROR, "wake-word provider unavailable")
                return None
            if (
                detection.detected
                and detection.confidence >= self._config.wake_confidence_threshold
            ):
                self._session_id = uuid4()
                self._frames = []
                self._speech_seen = False
                self._listening_started = now
                self._last_speech_at = now
                self._transition(VoiceState.LISTENING, "wake word accepted")
            return None
        if self._status.state is not VoiceState.LISTENING:
            return None
        if now - self._listening_started > self._config.max_utterance_seconds:
            self._frames = []
            self._speech_seen = False
            self._transition(VoiceState.IDLE, "utterance limit reached")
            self._cooldown_until = now + self._config.cooldown_seconds
            return None
        speech = self._vad.is_speech(frame)
        end = self._vad.is_end(frame)
        if speech:
            if not self._speech_seen:
                self._speech_candidate.append(frame)
                if len(self._speech_candidate) < self._config.speech_start_frames:
                    return None
                self._frames.extend(self._pre_roll)
                self._frames.extend(self._speech_candidate)
                self._speech_candidate.clear()
                self._speech_seen = True
                self._speech_frames = self._config.speech_start_frames
            else:
                self._frames.append(frame)
                self._speech_frames += 1
            self._tail_remaining = self._config.post_speech_tail_frames
            self._last_speech_at = now
        elif self._speech_seen:
            if self._tail_remaining > 0:
                self._frames.append(frame)
                self._tail_remaining -= 1
            if (
                self._tail_remaining == 0
                or now - self._last_speech_at > self._config.speech_timeout_seconds
            ):
                return await self._finish_capture()
        else:
            self._pre_roll.append(frame)
            self._speech_candidate.clear()
            if end:
                self._pre_roll.clear()
        return None

    async def interrupt(self, text: str) -> InterruptionCommand | None:
        """Handle a bounded interruption without treating speech as authorization."""

        command = self._command(text)
        if command is None:
            return None
        if self._task_handle is not None and command in {
            InterruptionCommand.STOP,
            InterruptionCommand.CANCEL,
        }:
            await self._barge_in(f"{command.value} requested")
            if self._runner is not None:
                await self._runner.cancel(self._task_handle.task_id)
            self._transition(VoiceState.IDLE, f"{command.value} requested")
            self._cooldown_until = asyncio.get_running_loop().time() + self._config.cooldown_seconds
        elif command is InterruptionCommand.WAIT:
            if self._tts is not None:
                await self._tts.stop()
            if self._status.state is VoiceState.SPEAKING:
                self._transition(VoiceState.IDLE, "wait requested")
        return command

    async def _barge_in(self, reason: str) -> None:
        if self._response_canceller is not None:
            await self._response_canceller()
        if self._tts is not None:
            await self._tts.stop()

    async def run(self, source: AudioSource) -> None:
        """Run a source until exhaustion, always closing the microphone."""

        try:
            await source.start()
        except Exception:
            self._microphone_mode = MicrophoneMode.PUSH_TO_TALK
            self._transition(VoiceState.ERROR, "microphone unavailable; PTT remains available")
            return
        try:
            async for frame in source.frames():
                await self.handle_frame(frame)
        except Exception:
            self._transition(VoiceState.ERROR, "microphone stream failed")
        finally:
            await source.stop()

    async def aclose(self) -> None:
        if self._tts is not None:
            await self._tts.stop()
        if self._task_handle is not None and not self._task_handle.completion.done():
            if self._runner is not None:
                await self._runner.cancel(self._task_handle.task_id)
            self._task_handle.completion.cancel()
        await self._stt.aclose()

    async def _finish_capture(self) -> VoiceTaskOutcome | None:
        frames, session_id = tuple(self._frames), self._session_id
        speech_frames = self._speech_frames
        self._frames = []
        self._pre_roll.clear()
        self._speech_candidate.clear()
        self._speech_seen = False
        self._speech_frames = 0
        self._tail_remaining = 0
        if len(frames) == 0 or speech_frames < self._config.min_speech_frames:
            self._transition(VoiceState.IDLE, "ultrashort noise rejected")
            return None
        if session_id is None:
            self._transition(VoiceState.IDLE, "capture without session")
            return None
        self._transition(VoiceState.PROCESSING, "speech captured")
        audio = AudioData(
            samples=tuple(sample for frame in frames for sample in frame.samples),
            sample_rate=frames[0].sample_rate,
            captured_at=frames[0].captured_at,
        )
        transcription = await self._stt.transcribe(audio)
        command = self._command(transcription.text)
        if command is not None:
            # No task exists yet, so the command still must close the
            # listening/processing session explicitly.
            await self.interrupt(transcription.text)
            if self._status.state is VoiceState.PROCESSING:
                self._transition(VoiceState.IDLE, f"{command.value} requested")
            return None
        if not transcription.text.strip() or self._runner is None:
            self._transition(VoiceState.IDLE, "no task request")
            return None
        self._task_handle = await self._runner.start(session_id, transcription.text.strip())
        outcome = await self._task_handle.completion
        if (
            outcome.status == TaskStatus.COMPLETED.value
            and outcome.response
            and self._tts is not None
        ):
            self._transition(VoiceState.SPEAKING, "task response")
            await self._tts.speak(outcome.response)
        self._transition(VoiceState.IDLE, "response complete")
        self._cooldown_until = asyncio.get_running_loop().time() + self._config.cooldown_seconds
        self._task_handle = None
        return outcome

    def _transition(self, state: VoiceState, reason: str) -> None:
        if self._state_machine is not None and state is not self._state_machine.application_state:
            event = {
                VoiceState.LISTENING: TransitionEvent.WAKE_DETECTED,
                VoiceState.PROCESSING: TransitionEvent.SPEECH_CAPTURED,
                VoiceState.SPEAKING: TransitionEvent.RESPONSE_STARTED,
                VoiceState.IDLE: TransitionEvent.RESPONSE_FINISHED,
                VoiceState.ERROR: TransitionEvent.APP_ERROR,
            }.get(state, TransitionEvent.TASK_THINKING)
            self._state_machine.transition_application(state, event, reason=reason)
        self._status = VoiceStatus(
            state, state is VoiceState.IDLE, self._session_id, reason, datetime.now(UTC)
        )
        self._history.append(self._status)
        if self._event_bus is not None:
            self._event_bus.publish_nowait(
                EventEnvelope.create(
                    EventType.VOICE_STATE_CHANGED,
                    VoiceStateChanged(state.value),
                    source="voice.controller",
                    task_id=self._task_handle.task_id if self._task_handle is not None else None,
                    correlation_id=self._session_id or UUID(int=0),
                )
            )

    def _command(self, text: str) -> InterruptionCommand | None:
        normalized = " ".join(text.casefold().split())
        for command in self._config.interruption_commands:
            if re.fullmatch(re.escape(command), normalized):
                return InterruptionCommand(command)
        return None
