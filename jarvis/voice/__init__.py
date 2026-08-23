"""Local wake-word voice activation with bounded task and audio lifecycles."""

from jarvis.voice.activation import (
    AudioFrame,
    AudioSource,
    InterruptionCommand,
    LocalVoiceController,
    MicrophoneMode,
    OrchestratorVoiceTaskRunner,
    PushToTalkController,
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
from jarvis.voice.providers import EnergyVADProvider, OpenWakeWordProvider, SoundDeviceAudioSource
from jarvis.voice.warmup import VoiceWarmup, WarmupResult

__all__ = [
    "AudioFrame",
    "AudioSource",
    "EnergyVADProvider",
    "InterruptionCommand",
    "LocalVoiceController",
    "MicrophoneMode",
    "OrchestratorVoiceTaskRunner",
    "OpenWakeWordProvider",
    "PushToTalkController",
    "SoundDeviceAudioSource",
    "VADProvider",
    "VoiceConfig",
    "VoiceState",
    "VoiceStatus",
    "WakeDetection",
    "WakeWordProvider",
    "VoiceTaskHandle",
    "VoiceTaskOutcome",
    "VoiceTaskRunner",
    "VoiceWarmup",
    "WarmupResult",
]
