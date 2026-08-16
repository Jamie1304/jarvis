"""Application composition root; concrete providers are selected only here."""

from __future__ import annotations

from typing import TYPE_CHECKING

from jarvis.ai.providers.base import AIProvider
from jarvis.ai.providers.ollama import OllamaProvider
from jarvis.application import JarvisAssistantService
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
from jarvis.task_controller import TaskController

if TYPE_CHECKING:
    from jarvis.runtime import ApplicationRuntime


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
    settings: Settings, *, task_controller: TaskController | None = None
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
        task_controller=task_controller,
        state_machine=ApplicationStateMachine(),
    )


def create_application_runtime(settings: Settings) -> ApplicationRuntime:
    """Construct the one canonical runtime container used by production entry points."""

    from jarvis.runtime import ApplicationRuntime

    return ApplicationRuntime.create(settings)


def create_assistant_from_runtime(runtime: ApplicationRuntime) -> JarvisAssistantService:
    """Expose the runtime-owned services to UI code without rebuilding dependencies."""

    if runtime.container is None:
        raise ConfigurationError("Application runtime is not ready")
    container = runtime.container
    return JarvisAssistantService(
        container.conversation,
        task_controller=container.task_controller,
        state_machine=container.state_machine,
    )
