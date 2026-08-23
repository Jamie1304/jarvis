"""UI-facing application service for bounded conversational flows."""

import asyncio
from collections.abc import AsyncIterator, Awaitable, Callable, Iterable
from dataclasses import dataclass
from enum import StrEnum
from uuid import UUID

from jarvis.ai.models import ProviderHealth
from jarvis.conversation.service import ConversationService
from jarvis.core.errors import ConversationError, ServiceUnavailableError, SpeechDisabledError
from jarvis.desktop_shell import (
    FirstRunWizard,
    LaunchProfile,
    LaunchProfileRegistry,
    LaunchProfileSelection,
    OnboardingResult,
    StartupWarmupRegistry,
    TestDriveRegistry,
    TestDriveReport,
    WarmupResult,
)
from jarvis.planning.models import PlanningTask
from jarvis.setup_conductor import SetupContext
from jarvis.speech.stt import SpeechToTextService, Transcription
from jarvis.speech.tts import SpeakableChunker, TextToSpeechService
from jarvis.state import ApplicationStateMachine
from jarvis.state.models import ApplicationState
from jarvis.task_controller import TaskController
from jarvis.voice.activation import AudioFrame, LocalVoiceController, VoiceStatus


class AssistantEventKind(StrEnum):
    """Events a desktop client can render without knowing provider details."""

    TEXT = "text"
    STREAMING = "streaming"
    TTS = "tts"


@dataclass(frozen=True, slots=True)
class AssistantEvent:
    """An application-service event intended for UI adapters."""

    kind: AssistantEventKind
    content: str
    done: bool = False


class InputNormalizer:
    """Normalize direct text and transcription output before model inference."""

    def normalize(self, text: str) -> str:
        normalized = " ".join(text.strip().split())
        if normalized.casefold().startswith("jarvis,"):
            normalized = normalized[len("jarvis,") :].strip()
        if not normalized:
            raise ConversationError("A message must contain text")
        return normalized


class JarvisAssistantService:
    """Coordinates text, optional speech, and conversation without exposing providers to UI."""

    def __init__(
        self,
        conversation: ConversationService,
        *,
        normalizer: InputNormalizer | None = None,
        stt: SpeechToTextService | None = None,
        tts: TextToSpeechService | None = None,
        task_controller: TaskController | None = None,
        voice: LocalVoiceController | None = None,
        state_machine: ApplicationStateMachine | None = None,
        response_session_rebuilder: Callable[[], Awaitable[None]] | None = None,
        onboarding: FirstRunWizard | None = None,
        test_drive: TestDriveRegistry | None = None,
        startup_warmup: StartupWarmupRegistry | None = None,
        launch_profiles: LaunchProfileRegistry | None = None,
    ) -> None:
        self._conversation = conversation
        self._normalizer = normalizer or InputNormalizer()
        self._stt = stt
        self._tts = tts
        self._task_controller = task_controller
        self._voice = voice
        self._state_machine = state_machine
        self._response_session_rebuilder = response_session_rebuilder
        self._onboarding = onboarding
        self._test_drive = test_drive
        self._startup_warmup = startup_warmup
        self._launch_profiles = launch_profiles or LaunchProfileRegistry()

    @property
    def launch_profiles(self) -> LaunchProfileRegistry:
        """Expose profile selection without changing security policy."""

        return self._launch_profiles

    def select_launch_profile(self, profile: LaunchProfile) -> LaunchProfileSelection:
        return self._launch_profiles.select(profile)

    async def run_onboarding(
        self,
        context: SetupContext,
        *,
        run_id: UUID | None = None,
        cancellation: asyncio.Event | None = None,
    ) -> OnboardingResult:
        if self._onboarding is None:
            raise ServiceUnavailableError("First-run onboarding is not configured")
        if not isinstance(context, SetupContext):
            raise ConversationError("Onboarding context is malformed")
        return await self._onboarding.run(context, run_id=run_id, cancellation=cancellation)

    async def run_test_drive(self, *, skip: Iterable[str] = ()) -> TestDriveReport:
        if self._test_drive is None:
            raise ServiceUnavailableError("Test-drive checks are not configured")
        if not isinstance(self._test_drive, TestDriveRegistry):
            raise ServiceUnavailableError("Test-drive checks are malformed")
        return await self._test_drive.run(skip=skip)

    def start_startup_warmup(self) -> asyncio.Task[tuple[WarmupResult, ...]]:
        if self._startup_warmup is None:
            raise ServiceUnavailableError("Startup warmup is not configured")
        return self._startup_warmup.start()

    def create_conversation(self, system_prompt: str | None = None) -> UUID:
        """Create a UI conversation with optional system context."""

        return self._conversation.create_conversation(system_prompt)

    def cancel(self, conversation_id: UUID) -> None:
        """Cancel an active response safely from the UI thread."""

        self._conversation.cancel(conversation_id)

    async def provider_status(self) -> ProviderHealth:
        """Get UI-safe provider connectivity information."""

        return await self._conversation.provider_health()

    @property
    def stt_enabled(self) -> bool:
        return self._stt is not None

    @property
    def tts_enabled(self) -> bool:
        return self._tts is not None and self._tts.enabled

    @property
    def voice_status(self) -> VoiceStatus | None:
        """Return the UI-safe voice state, when optional voice is configured."""

        return self._voice.status if self._voice is not None else None

    @property
    def application_state(self) -> ApplicationState:
        """Read-only global lifecycle state for UI rendering."""

        return (
            self._state_machine.application_state
            if self._state_machine is not None
            else ApplicationState.IDLE
        )

    async def handle_voice_frame(self, frame: AudioFrame) -> None:
        """Forward one transient frame to the configured voice state machine."""

        if self._voice is None:
            raise SpeechDisabledError("Voice activation is disabled")
        await self._voice.handle_frame(frame)

    async def interrupt_voice(self, text: str) -> None:
        """Apply an explicit voice interruption through the central task adapter."""

        if self._voice is None:
            raise SpeechDisabledError("Voice activation is disabled")
        await self._voice.interrupt(text)

    async def start_recording(self) -> None:
        """Start transient microphone recording."""

        if self._stt is None:
            raise SpeechDisabledError("Speech-to-text is disabled")
        await self._stt.start_recording()

    async def stop_recording(self) -> Transcription:
        """Stop recording and return the local transcription."""

        if self._stt is None:
            raise SpeechDisabledError("Speech-to-text is disabled")
        return await self._stt.stop_and_transcribe()

    async def create_task(self, conversation_id: UUID, user_request: str) -> PlanningTask:
        """Create a canonical persisted plan; conversation identity remains UI context only."""

        del conversation_id
        return await self._require_task_controller().create_task(
            self._normalizer.normalize(user_request)
        )

    async def run_task(self, task_id: UUID) -> PlanningTask:
        """Run a previously created canonical task."""

        return await self._require_task_controller().run_task(task_id)

    async def submit_task(self, conversation_id: UUID, user_request: str) -> PlanningTask:
        """Create and execute a canonical persisted task."""

        del conversation_id
        return await self._require_task_controller().submit_task(
            self._normalizer.normalize(user_request)
        )

    async def cancel_task(self, task_id: UUID) -> PlanningTask:
        """Request clean cancellation of a running task."""

        return await self._require_task_controller().cancel_task(task_id)

    async def stream_text(self, conversation_id: UUID, text: str) -> AsyncIterator[AssistantEvent]:
        """Stream text and begin TTS as soon as a safe sentence is available."""

        normalized = self._normalizer.normalize(text)
        yield AssistantEvent(AssistantEventKind.STREAMING, "Assistant is responding")
        response = ""
        tts_queue: asyncio.Queue[str | None] | None = None
        tts_task: asyncio.Task[None] | None = None
        if self._tts is not None and self._tts.enabled:
            tts_queue = asyncio.Queue(maxsize=8)

            async def speakable_chunks() -> AsyncIterator[str]:
                chunker = SpeakableChunker()
                while True:
                    item = await tts_queue.get()
                    if item is None:
                        for chunk in chunker.finish():
                            yield chunk
                        return
                    for chunk in chunker.feed(item):
                        yield chunk

            tts_task = self._tts.start_incremental(speakable_chunks())
        try:
            async for update in self._conversation.stream_reply(conversation_id, normalized):
                response += update.content
                if tts_queue is not None:
                    await tts_queue.put(update.content)
                yield AssistantEvent(AssistantEventKind.TEXT, update.content, done=update.done)
            if tts_queue is not None:
                await tts_queue.put(None)
            if tts_task is not None:
                await tts_task
            if response and self._tts is not None and self._tts.available:
                yield AssistantEvent(AssistantEventKind.TTS, "Speaking response")
                yield AssistantEvent(AssistantEventKind.TTS, "TTS idle", done=True)
            yield AssistantEvent(AssistantEventKind.STREAMING, "Assistant ready", done=True)
        except BaseException:
            if self._tts is not None:
                await self._tts.stop()
            raise

    async def barge_in(self, conversation_id: UUID) -> None:
        """Stop output and invalidate the current response generation."""

        self._conversation.cancel(conversation_id)
        if self._tts is not None:
            await self._tts.stop()
        if self._response_session_rebuilder is not None:
            await self._response_session_rebuilder()

    async def aclose(self) -> None:
        """Release local speech resources when the UI exits."""

        if self._voice is not None:
            await self._voice.aclose()
        else:
            if self._stt is not None:
                await self._stt.aclose()
            if self._tts is not None:
                await self._tts.aclose()
        await self._conversation.aclose()

    def _require_task_controller(self) -> TaskController:
        if self._task_controller is None:
            raise ServiceUnavailableError("Canonical task controller is not configured")
        return self._task_controller
