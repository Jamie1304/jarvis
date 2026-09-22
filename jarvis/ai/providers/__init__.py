"""Provider interfaces, packages, and adapters."""

from jarvis.ai.models import EvidenceKind, EvidenceRecord, ModelRole
from jarvis.ai.providers.base import AIProvider, IntelligenceProvider
from jarvis.ai.providers.intelligence import (
    AuthenticationType,
    CostEvidence,
    CostStatus,
    DecisionProvider,
    DecisionRequest,
    DecisionResult,
    ExactRouteIdentity,
    IntelligenceKind,
    LearnedModelState,
    ModelPolicy,
    ModelRouteIdentity,
    PackageSupportStatus,
    ProtocolFamily,
    ProviderLifecycle,
    ProviderPackageManifest,
    ProviderPolicy,
    ProviderSetupField,
    RemoteIntelligencePrivacyGateway,
    RemoteSafePayload,
    UsageReceipt,
)
from jarvis.ai.providers.registry import (
    ModelLifecycle,
    ModelMetadata,
    Provider,
    ProviderDefinition,
    ProviderLocality,
    ProviderMetadata,
    ProviderRegistry,
    VoiceProviderDefinition,
    VoiceProviderKind,
)


def __getattr__(name: str) -> object:
    """Load optional catalog/discovery adapters without creating import cycles."""

    if name in {
        "JevDecisionProvider",
        "OpenAICompatibleConfiguration",
        "OpenAICompatibleProvider",
        "STANDARD_PROVIDER_MANIFESTS",
        "provider_manifest",
        "standard_provider_catalog",
    }:
        from importlib import import_module

        return getattr(import_module("jarvis.ai.providers.catalog"), name)
    if name in {"DiscoveryResult", "ModelDiscoveryService"}:
        from importlib import import_module

        return getattr(import_module("jarvis.ai.providers.discovery"), name)
    raise AttributeError(name)


__all__ = [
    "AIProvider",
    "AuthenticationType",
    "CostEvidence",
    "CostStatus",
    "DecisionProvider",
    "DecisionRequest",
    "DecisionResult",
    "DiscoveryResult",
    "EvidenceKind",
    "EvidenceRecord",
    "ExactRouteIdentity",
    "IntelligenceKind",
    "IntelligenceProvider",
    "JevDecisionProvider",
    "LearnedModelState",
    "ModelDiscoveryService",
    "ModelLifecycle",
    "ModelMetadata",
    "ModelPolicy",
    "ModelRouteIdentity",
    "ModelRole",
    "OpenAICompatibleConfiguration",
    "OpenAICompatibleProvider",
    "PackageSupportStatus",
    "ProtocolFamily",
    "Provider",
    "ProviderDefinition",
    "ProviderLifecycle",
    "ProviderLocality",
    "ProviderMetadata",
    "ProviderPackageManifest",
    "ProviderPolicy",
    "ProviderRegistry",
    "ProviderSetupField",
    "RemoteIntelligencePrivacyGateway",
    "RemoteSafePayload",
    "STANDARD_PROVIDER_MANIFESTS",
    "UsageReceipt",
    "VoiceProviderDefinition",
    "VoiceProviderKind",
    "provider_manifest",
    "standard_provider_catalog",
]
