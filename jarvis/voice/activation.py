"""Controlled, local-first voice activation.

Idle audio is offered only to the configured wake-word provider.  No STT, cloud
provider, task, or durable storage is touched until a wake is accepted.
"""

import asyncio
import re
from abc import ABC, abstractmethod
from collections.abc import AsyncIterator
from dataclasses import dataclass, field
from datetime import UTC, datetime
from enum import StrEnum
from typing import Protocol
from uuid import UUID, uuid4

from jarvis.autonomy.models import Task, TaskStatus
from jarvis.autonomy.orchestrator import AgentOrchestrator
from jarvis.speech.stt import AudioData, SttProvider
from jarvis.speech.tts import TextToSpeechService
from jarvis.state import ApplicationStateMachine
from jarvis.state.models import ApplicationState, TransitionEvent

# Compatibility name for UI clients; application state is authoritative.
VoiceState = ApplicationState


class InterruptionCommand(StrEnum):
    STOP = "stop"
    CANCEL = "cancel"
    WAIT = "wait"


@dataclass(frozen=True, slots=True)
class VoiceConfig:
    """Bounded voice behavior; idle wake processing remains local by contract."""

    wake_word: str = "Jarvis"
    wake_confidence_threshold: float = 0.8
    cooldown_seconds: float = 1.0
    max_utterance_seconds: float = 15.0
    speech_timeout_seconds: float = 5.0
    interruption_commands: tuple[str, ...] = ("stop", "cancel", "wait")

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


class OrchestratorVoiceTaskRunner:
    """Adapter preserving AgentOrchestrator ownership of task state/cancellation."""

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
        config: VoiceConfig | None = None,
        state_machine: ApplicationStateMachine | None = None,
    ) -> None:
        self._wake = wake_provider
        self._vad = vad
        self._stt = stt
        self._runner = task_runner
        self._tts = tts
        self._config = config or VoiceConfig()
        self._state_machine = state_machine
        self._status = VoiceStatus(VoiceState.IDLE, True, None, "ready", datetime.now(UTC))
        self._history: list[VoiceStatus] = [self._status]
        self._session_id: UUID | None = None
        self._frames: list[AudioFrame] = []
        self._speech_seen = False
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

    async def handle_frame(self, frame: AudioFrame) -> VoiceTaskOutcome | None:
        """Process exactly one frame; callers own source lifecycle and scheduling."""

        now = asyncio.get_running_loop().time()
        if self._status.state is VoiceState.IDLE:
            if now < self._cooldown_until:
                return None
            detection = await self._wake.detect(frame, self._config.wake_word)
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
        if self._vad.is_speech(frame):
            self._frames.append(frame)
            self._speech_seen = True
            self._last_speech_at = now
        elif self._speech_seen and now - self._last_speech_at > self._config.speech_timeout_seconds:
            return await self._finish_capture()
        if self._vad.is_end(frame) and self._speech_seen:
            return await self._finish_capture()
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
            if self._runner is not None:
                await self._runner.cancel(self._task_handle.task_id)
            if self._tts is not None:
                await self._tts.stop()
            self._transition(VoiceState.IDLE, f"{command.value} requested")
            self._cooldown_until = asyncio.get_running_loop().time() + self._config.cooldown_seconds
        elif command is InterruptionCommand.WAIT:
            if self._tts is not None:
                await self._tts.stop()
            if self._status.state is VoiceState.SPEAKING:
                self._transition(VoiceState.IDLE, "wait requested")
        return command

    async def run(self, source: AudioSource) -> None:
        """Run a source until exhaustion, always closing the microphone."""

        await source.start()
        try:
            async for frame in source.frames():
                await self.handle_frame(frame)
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
        self._frames = []
        self._speech_seen = False
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

    def _command(self, text: str) -> InterruptionCommand | None:
        normalized = " ".join(text.casefold().split())
        for command in self._config.interruption_commands:
            if re.fullmatch(re.escape(command), normalized):
                return InterruptionCommand(command)
        return None
