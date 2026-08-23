"""Application composition root; concrete providers are selected only here."""

from __future__ import annotations

from collections.abc import Mapping
from typing import TYPE_CHECKING, Any

from jarvis.ai.providers.base import AIProvider
from jarvis.ai.providers.ollama import OllamaProvider
from jarvis.ai.providers.registry import ProviderDefinition, ProviderMetadata, ProviderRegistry
from jarvis.application import JarvisAssistantService
from jarvis.conversation.service import ConversationService
from jarvis.core.config import Settings
from jarvis.core.errors import ConfigurationError
from jarvis.security import local_model_endpoint_is_safe
from jarvis.speech.tts import DisabledTtsProvider, TextToSpeechService
from jarvis.state import ApplicationStateMachine
from jarvis.task_controller import TaskController

if TYPE_CHECKING:
    from jarvis.runtime import ApplicationRuntime


def _ollama_factory(configuration: Mapping[str, Any]) -> AIProvider:
    endpoint = str(configuration["endpoint"])
    if not local_model_endpoint_is_safe(endpoint):
        raise ConfigurationError("Ollama endpoint must use a literal local loopback address")
    return OllamaProvider(
        model=str(configuration["model"]),
        endpoint=endpoint,
        timeout_seconds=float(configuration["timeout_seconds"]),
        context_limit=int(configuration["context_limit"]),
    )


def create_provider_registry() -> ProviderRegistry:
    """Return the native registry; integrations register definitions, not branches."""

    return ProviderRegistry(
        (
            ProviderDefinition(
                metadata=ProviderMetadata("ollama", "Ollama", "native", local_only=True),
                factory=_ollama_factory,
            ),
        )
    )


def create_ai_provider(settings: Settings) -> AIProvider:
    """Create the configured provider through the provider registry."""

    registry = create_provider_registry()
    try:
        return registry.create(
            settings.ai_provider,
            {
                "model": settings.ai_model,
                "endpoint": settings.ai_endpoint,
                "timeout_seconds": settings.ai_timeout_seconds,
                "context_limit": settings.ai_context_limit,
            },
        )
    except KeyError as error:
        raise ConfigurationError(f"Unsupported AI provider: {settings.ai_provider}") from error


def create_assistant_service(
    settings: Settings, *, task_controller: TaskController | None = None
) -> JarvisAssistantService:
    """Build the legacy non-privileged UI service for compatibility tests only.

    Hardware activation belongs to the canonical brokered runtime.  This helper
    deliberately refuses settings that would otherwise create a microphone or
    speech-output path outside that runtime.
    """

    if settings.stt_enabled or settings.tts_enabled or settings.voice_enabled:
        raise ConfigurationError(
            "Privileged speech capabilities require the canonical application runtime"
        )

    provider = create_ai_provider(settings)
    conversation = ConversationService(
        provider,
        model=settings.ai_model,
        context_limit=settings.ai_context_limit,
    )
    stt = None
    tts = TextToSpeechService(DisabledTtsProvider(), enabled=False)
    return JarvisAssistantService(
        conversation,
        stt=stt,
        tts=tts,
        task_controller=task_controller,
        state_machine=ApplicationStateMachine(),
    )


def create_application_runtime(settings: Settings | None = None) -> ApplicationRuntime:
    """Construct the one canonical runtime container used by production entry points."""

    from jarvis.runtime import ApplicationRuntime

    if settings is None:
        return ApplicationRuntime.create_from_environment()
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
        test_drive=container.test_drive,
        startup_warmup=container.startup_warmup,
        launch_profiles=container.launch_profiles,
    )
