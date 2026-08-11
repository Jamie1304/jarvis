"""Application composition root; concrete providers are selected only here."""

from jarvis.ai.providers.base import AIProvider
from jarvis.ai.providers.ollama import OllamaProvider
from jarvis.application import JarvisAssistantService
from jarvis.autonomy.orchestrator import AgentOrchestrator
from jarvis.conversation.service import ConversationService
from jarvis.core.config import Settings
from jarvis.core.errors import ConfigurationError
from jarvis.speech.stt import (
    FasterWhisperSttProvider,
    SoundDeviceRecorder,
    SpeechToTextService,
)
from jarvis.speech.tts import DisabledTtsProvider, Pyttsx3TtsProvider, TextToSpeechService
from jarvis.state import ApplicationStateMachine


def create_ai_provider(settings: Settings) -> AIProvider:
    """Create the configured model adapter while validating supported providers."""

    if settings.ai_provider.casefold() != "ollama":
        raise ConfigurationError(f"Unsupported AI provider: {settings.ai_provider}")
    return OllamaProvider(
        model=settings.ai_model,
        endpoint=settings.ai_endpoint,
        timeout_seconds=settings.ai_timeout_seconds,
        context_limit=settings.ai_context_limit,
    )


def create_assistant_service(
    settings: Settings, *, orchestrator: AgentOrchestrator | None = None
) -> JarvisAssistantService:
    """Build the UI-facing service graph without exposing concrete providers to UI code."""

    provider = create_ai_provider(settings)
    conversation = ConversationService(
        provider,
        model=settings.ai_model,
        context_limit=settings.ai_context_limit,
    )
    stt = None
    if settings.stt_enabled:
        stt = SpeechToTextService(
            SoundDeviceRecorder(device=settings.stt_device, sample_rate=settings.stt_sample_rate),
            FasterWhisperSttProvider(
                settings.stt_model,
                device=settings.stt_compute_device,
                compute_type=settings.stt_compute_type,
            ),
        )
    tts = TextToSpeechService(
        Pyttsx3TtsProvider(voice=settings.tts_voice)
        if settings.tts_enabled
        else DisabledTtsProvider(),
        enabled=settings.tts_enabled,
    )
    return JarvisAssistantService(
        conversation,
        stt=stt,
        tts=tts,
        orchestrator=orchestrator,
        state_machine=ApplicationStateMachine(),
    )
