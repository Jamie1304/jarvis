"""UI-facing application service for the limited Phase 1 conversation flow."""

from collections.abc import AsyncIterator
from dataclasses import dataclass
from enum import StrEnum
from uuid import UUID

from jarvis.ai.models import ProviderHealth
from jarvis.autonomy.models import Task
from jarvis.autonomy.orchestrator import AgentOrchestrator
from jarvis.conversation.service import ConversationService
from jarvis.core.errors import ConversationError, ServiceUnavailableError, SpeechDisabledError
from jarvis.speech.stt import SpeechToTextService, Transcription
from jarvis.speech.tts import TextToSpeechService
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
        orchestrator: AgentOrchestrator | None = None,
        voice: LocalVoiceController | None = None,
    ) -> None:
        self._conversation = conversation
        self._normalizer = normalizer or InputNormalizer()
        self._stt = stt
        self._tts = tts
        self._orchestrator = orchestrator
        self._voice = voice

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

    async def create_task(self, conversation_id: UUID, user_request: str) -> Task:
        """Create a bounded agent task without changing ordinary chat behavior."""

        return await self._require_orchestrator().create_task(
            conversation_id, self._normalizer.normalize(user_request)
        )

    async def run_task(self, task_id: UUID) -> Task:
        """Run a previously created bounded task."""

        return await self._require_orchestrator().run(task_id)

    async def submit_task(self, conversation_id: UUID, user_request: str) -> Task:
        """Create and execute a bounded task as one operation."""

        return await self._require_orchestrator().submit(
            conversation_id, self._normalizer.normalize(user_request)
        )

    async def cancel_task(self, task_id: UUID) -> Task:
        """Request clean cancellation of a running task."""

        return await self._require_orchestrator().cancel(task_id)

    async def stream_text(self, conversation_id: UUID, text: str) -> AsyncIterator[AssistantEvent]:
        """Normalize text and stream a response, optionally speaking after completion."""

        normalized = self._normalizer.normalize(text)
        yield AssistantEvent(AssistantEventKind.STREAMING, "Assistant is responding")
        response = ""
        async for update in self._conversation.stream_reply(conversation_id, normalized):
            response += update.content
            yield AssistantEvent(AssistantEventKind.TEXT, update.content, done=update.done)
        if self._tts is not None and self._tts.enabled and response:
            yield AssistantEvent(AssistantEventKind.TTS, "Speaking response")
            await self._tts.speak(response)
            yield AssistantEvent(AssistantEventKind.TTS, "TTS idle", done=True)
        yield AssistantEvent(AssistantEventKind.STREAMING, "Assistant ready", done=True)

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

    def _require_orchestrator(self) -> AgentOrchestrator:
        if self._orchestrator is None:
            raise ServiceUnavailableError("Task orchestration is not configured")
        return self._orchestrator
