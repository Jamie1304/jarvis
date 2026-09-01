"""Provider interfaces and adapters."""

from jarvis.ai.models import EvidenceKind, EvidenceRecord, ModelRole
from jarvis.ai.providers.base import AIProvider
from jarvis.ai.providers.registry import (
    ModelMetadata,
    Provider,
    ProviderDefinition,
    ProviderMetadata,
    ProviderRegistry,
    VoiceProviderDefinition,
    VoiceProviderKind,
)

__all__ = [
    "AIProvider",
    "EvidenceKind",
    "EvidenceRecord",
    "ModelMetadata",
    "ModelRole",
    "Provider",
    "ProviderDefinition",
    "ProviderMetadata",
    "ProviderRegistry",
    "VoiceProviderDefinition",
    "VoiceProviderKind",
]
