"""Local wake-word voice activation with bounded task and audio lifecycles."""

from jarvis.voice.activation import (
    AudioFrame,
    AudioSource,
    InterruptionCommand,
    LocalVoiceController,
    OrchestratorVoiceTaskRunner,
    VADProvider,
    VoiceConfig,
    VoiceState,
    VoiceStatus,
    VoiceTaskHandle,
    VoiceTaskOutcome,
    VoiceTaskRunner,
    WakeDetection,
    WakeWordProvider,
)

__all__ = [
    "AudioFrame",
    "AudioSource",
    "InterruptionCommand",
    "LocalVoiceController",
    "OrchestratorVoiceTaskRunner",
    "VADProvider",
    "VoiceConfig",
    "VoiceState",
    "VoiceStatus",
    "WakeDetection",
    "WakeWordProvider",
    "VoiceTaskHandle",
    "VoiceTaskOutcome",
    "VoiceTaskRunner",
]
