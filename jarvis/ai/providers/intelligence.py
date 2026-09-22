"""The provider-neutral intelligence fabric.

This module is the common control-plane contract for generative, decision,
embedding, reranking, vision, and audio adapters.  Vendor behavior belongs in
provider packages; the application only consumes these typed descriptions.

The contracts are intentionally conservative: discovery is bounded, unknown
facts stay unknown, decision output is advice rather than authority, and a
remote provider receives only a caller-prepared bounded payload.
"""

from __future__ import annotations

import math
import re
from abc import ABC, abstractmethod
from collections.abc import Awaitable, Mapping
from dataclasses import dataclass
from datetime import UTC, datetime
from enum import StrEnum
from typing import Any, Protocol

from jarvis.ai.models import PrivacyClassification, PrivacyContext
from jarvis.ai.providers.base import IntelligenceProvider
from jarvis.ai.providers.registry import ProviderLocality


class IntelligenceKind(StrEnum):
    GENERATIVE = "generative"
    DECISION = "decision"
    EMBEDDING = "embedding"
    RERANKING = "reranking"
    VISION = "vision"
    AUDIO = "audio"


class ProviderLifecycle(StrEnum):
    AVAILABLE = "available"
    DISABLED = "disabled"
    DEPRECATED = "deprecated"
    RETIRED = "retired"
    UNKNOWN = "unknown"


class ProviderPolicy(StrEnum):
    ENABLED = "enabled"
    ROUTING_DISABLED = "routing_disabled"
    BLOCKED = "blocked"


class ModelPolicy(StrEnum):
    AUTO_ALLOWED = "auto_allowed"
    GUARDED = "guarded"
    MANUAL_ONLY = "manual_only"
    BLOCKED = "blocked"


class AuthenticationType(StrEnum):
    NONE = "none"
    API_KEY = "api_key"
    API_TOKEN = "api_token"
    OAUTH = "oauth"
    SERVICE_ACCOUNT = "service_account"
    CONFIGURATION = "configuration"
    UNKNOWN = "unknown"


class ProtocolFamily(StrEnum):
    NATIVE = "native"
    OPENAI_COMPATIBLE = "openai_compatible"
    ANTHROPIC_MESSAGES = "anthropic_messages"
    GOOGLE_GEMINI = "google_gemini"
    AWS_BEDROCK = "aws_bedrock"
    AZURE_AI = "azure_ai"
    DECISION_TYPED = "decision_typed"
    UNKNOWN = "unknown"


class PackageSupportStatus(StrEnum):
    CONTRACT_ONLY = "contract_only"
    CONTROLLED_FIXTURE = "controlled_fixture"
    PHYSICAL_VALIDATED = "physical_validated"
    EXTERNAL_PROTOCOL_FACT_NOT_PROVEN = "external_protocol_fact_not_proven"


class CostStatus(StrEnum):
    KNOWN = "known"
    COST_UNKNOWN = "cost_unknown"


class LearnedModelState(StrEnum):
    NORMAL = "normal"
    DEPRIORITIZED = "deprioritized"
    TASK_QUARANTINED = "task_quarantined"
    GLOBAL_QUARANTINED = "global_quarantined"
    UNVERIFIED = "unverified"


_SAFE_ID = re.compile(r"^[^\x00-\x1f\x7f]{1,256}$")


def _text(value: object, name: str, limit: int, *, empty: bool = False) -> str:
    if (
        type(value) is not str
        or (not empty and not value.strip())
        or len(value) > limit
        or "\x00" in value
    ):
        raise ValueError(f"{name} is invalid")
    return value


@dataclass(frozen=True, slots=True)
class ExactRouteIdentity:
    """Execution identity; aliases and same weights at another endpoint differ."""

    provider_id: str
    endpoint: str
    model_id: str
    region: str = ""
    version: str = ""
    deployment: str = ""
    account_scope: str = ""
    inference_kind: IntelligenceKind = IntelligenceKind.GENERATIVE
    quantization: str = ""
    runtime: str = ""

    def __post_init__(self) -> None:
        for value, name, limit in (
            (self.provider_id, "Route provider", 256),
            (self.endpoint, "Route endpoint", 2_048),
            (self.model_id, "Route model", 256),
        ):
            _text(value, name, limit)
        for value, name, limit in (
            (self.region, "Route region", 128),
            (self.version, "Route version", 128),
            (self.deployment, "Route deployment", 256),
            (self.account_scope, "Route account scope", 256),
            (self.quantization, "Route quantization", 128),
            (self.runtime, "Route runtime", 128),
        ):
            _text(value, name, limit, empty=True)
        if not isinstance(self.inference_kind, IntelligenceKind):
            raise ValueError("Route intelligence kind is invalid")

    @property
    def storage_key(self) -> str:
        import json

        return json.dumps(
            (
                self.provider_id.casefold(),
                self.endpoint,
                self.region,
                self.model_id,
                self.version,
                self.deployment,
                self.account_scope,
                self.inference_kind.value,
                self.quantization,
                self.runtime,
            ),
            ensure_ascii=False,
            separators=(",", ":"),
        )


ModelRouteIdentity = ExactRouteIdentity


@dataclass(frozen=True, slots=True)
class ProviderSetupField:
    """One provider-specific setup field shown by onboarding/UI."""

    name: str
    label: str
    required: bool = True
    secret: bool = False
    description: str = ""
    value_kind: str = "text"

    def __post_init__(self) -> None:
        _text(self.name, "Setup field name", 128)
        _text(self.label, "Setup field label", 256)
        _text(self.description, "Setup field description", 1_000, empty=True)
        _text(self.value_kind, "Setup field value kind", 64)
        if type(self.required) is not bool or type(self.secret) is not bool:
            raise ValueError("Setup field flags are invalid")


@dataclass(frozen=True, slots=True)
class ProviderPackageManifest:
    """Descriptive, versioned package metadata; it does not grant authority."""

    provider_id: str
    display_name: str
    kinds: frozenset[IntelligenceKind]
    locality: ProviderLocality = ProviderLocality.REMOTE
    authentication: AuthenticationType = AuthenticationType.UNKNOWN
    required_fields: tuple[ProviderSetupField, ...] = ()
    optional_fields: tuple[ProviderSetupField, ...] = ()
    official_website: str | None = None
    developer_console: str | None = None
    credential_management_url: str | None = None
    key_creation_instructions: str | None = None
    billing_prerequisites: str | None = None
    rotation_instructions: str | None = None
    revoke_instructions: str | None = None
    protocol_family: ProtocolFamily = ProtocolFamily.UNKNOWN
    dynamic_model_discovery: bool = False
    usability_probe: bool = False
    region_or_account_limits: str | None = None
    lifecycle: ProviderLifecycle = ProviderLifecycle.AVAILABLE
    support_status: PackageSupportStatus = PackageSupportStatus.CONTRACT_ONLY
    package_version: str = "1"

    def __post_init__(self) -> None:
        _text(self.provider_id, "Provider ID", 128)
        if not _SAFE_ID.fullmatch(self.provider_id):
            raise ValueError("Provider ID contains control characters")
        _text(self.display_name, "Provider display name", 256)
        if (
            type(self.kinds) is not frozenset
            or not self.kinds
            or any(not isinstance(kind, IntelligenceKind) for kind in self.kinds)
        ):
            raise ValueError("Provider intelligence kinds are invalid")
        if not isinstance(self.locality, ProviderLocality):
            raise ValueError("Provider locality is invalid")
        if not isinstance(self.authentication, AuthenticationType):
            raise ValueError("Provider authentication is invalid")
        for name, fields in (
            ("required", self.required_fields),
            ("optional", self.optional_fields),
        ):
            if type(fields) is not tuple or any(
                not isinstance(item, ProviderSetupField) for item in fields
            ):
                raise ValueError(f"Provider {name} setup fields are invalid")
        names = {field.name for field in self.required_fields}
        if names & {field.name for field in self.optional_fields}:
            raise ValueError("Provider setup fields overlap")
        for name, value in (
            ("official website", self.official_website),
            ("developer console", self.developer_console),
            ("credential management URL", self.credential_management_url),
        ):
            if value is not None:
                _text(value, name, 2_048)
                if not value.startswith(("https://", "http://")):
                    raise ValueError(f"Provider {name} must be an URL")
        for name, value in (
            ("key creation instructions", self.key_creation_instructions),
            ("billing prerequisites", self.billing_prerequisites),
            ("rotation instructions", self.rotation_instructions),
            ("revoke instructions", self.revoke_instructions),
            ("region/account limits", self.region_or_account_limits),
        ):
            if value is not None:
                _text(value, name, 4_000)
        if type(self.dynamic_model_discovery) is not bool or type(self.usability_probe) is not bool:
            raise ValueError("Provider capability flags are invalid")
        if not isinstance(self.lifecycle, ProviderLifecycle) or not isinstance(
            self.support_status, PackageSupportStatus
        ):
            raise ValueError("Provider lifecycle metadata is invalid")
        _text(self.package_version, "Provider package version", 64)


@dataclass(frozen=True, slots=True)
class CostEvidence:
    """A price observation with explicit provenance and freshness."""

    status: CostStatus = CostStatus.COST_UNKNOWN
    input_per_million: float | None = None
    output_per_million: float | None = None
    currency: str = "USD"
    source: str = "unknown"
    observed_at: datetime | None = None
    expires_at: datetime | None = None
    user_override: bool = False

    def __post_init__(self) -> None:
        if not isinstance(self.status, CostStatus):
            raise ValueError("Cost status is invalid")
        for name, value in (
            ("input cost", self.input_per_million),
            ("output cost", self.output_per_million),
        ):
            if value is not None and (
                type(value) not in {int, float} or not math.isfinite(value) or value < 0
            ):
                raise ValueError(f"{name} is invalid")
        _text(self.currency, "Cost currency", 16)
        _text(self.source, "Cost source", 512)
        for timestamp in (self.observed_at, self.expires_at):
            if timestamp is not None and timestamp.tzinfo is None:
                raise ValueError("Cost timestamp must be timezone-aware")
        if self.observed_at and self.expires_at and self.expires_at < self.observed_at:
            raise ValueError("Cost expiry precedes observation")
        if type(self.user_override) is not bool:
            raise ValueError("Cost override flag is invalid")

    @property
    def total_per_million(self) -> float | None:
        if self.status is CostStatus.COST_UNKNOWN:
            return None
        if self.input_per_million is None or self.output_per_million is None:
            return None
        return self.input_per_million + self.output_per_million


@dataclass(frozen=True, slots=True)
class DecisionRequest:
    """Bounded input for a decision provider; no permission authority fields."""

    task: str
    inputs: tuple[tuple[str, str], ...]
    task_class: str = "general"
    output_schema: str = "label_and_score"
    privacy_context: PrivacyContext = PrivacyContext(PrivacyClassification.UNKNOWN)
    correlation_id: str | None = None

    def __post_init__(self) -> None:
        _text(self.task, "Decision task", 4_000)
        _text(self.task_class, "Decision task class", 128)
        _text(self.output_schema, "Decision output schema", 256)
        if type(self.inputs) is not tuple or len(self.inputs) > 128:
            raise ValueError("Decision inputs are invalid")
        for key, value in self.inputs:
            _text(key, "Decision input key", 128)
            _text(value, "Decision input value", 8_000)
        if not isinstance(self.privacy_context, PrivacyContext):
            raise ValueError("Decision privacy context is invalid")
        if self.correlation_id is not None:
            _text(self.correlation_id, "Decision correlation ID", 128)


_AUTHORITY_FIELDS = frozenset(
    {
        "permission_granted",
        "security_override",
        "update_approved",
        "release_approved",
        "effect_verified",
        "identity_verified",
    }
)


@dataclass(frozen=True, slots=True)
class DecisionResult:
    """Typed advisory output.  It can inform Core, never authorize Core."""

    label: str
    confidence: float | None = None
    scores: tuple[tuple[str, float], ...] = ()
    recommendation: str | None = None
    evidence: tuple[str, ...] = ()
    provider_id: str | None = None
    model_id: str | None = None
    observed_at: datetime | None = None

    def __post_init__(self) -> None:
        _text(self.label, "Decision label", 256)
        if self.confidence is not None and (
            type(self.confidence) not in {int, float}
            or not math.isfinite(self.confidence)
            or not 0.0 <= self.confidence <= 1.0
        ):
            raise ValueError("Decision confidence is invalid")
        if type(self.scores) is not tuple or len(self.scores) > 256:
            raise ValueError("Decision scores are invalid")
        for name, score in self.scores:
            _text(name, "Decision score name", 256)
            if type(score) not in {int, float} or not math.isfinite(score):
                raise ValueError("Decision score is invalid")
        if self.recommendation is not None:
            _text(self.recommendation, "Decision recommendation", 1_000)
            if self.recommendation.casefold() in _AUTHORITY_FIELDS:
                raise ValueError("Decision output cannot contain authority")
        if type(self.evidence) is not tuple or any(
            type(item) is not str or not item.strip() or len(item) > 1_000 for item in self.evidence
        ):
            raise ValueError("Decision evidence is invalid")
        for name, value in (("provider ID", self.provider_id), ("model ID", self.model_id)):
            if value is not None:
                _text(value, name, 256)
        if self.observed_at is not None and self.observed_at.tzinfo is None:
            raise ValueError("Decision timestamp must be timezone-aware")

    @classmethod
    def from_mapping(cls, value: Mapping[str, Any], **identity: str) -> DecisionResult:
        """Parse untrusted adapter output without accepting authority claims."""

        if not isinstance(value, Mapping):
            raise ValueError("Decision output is not an object")
        if _AUTHORITY_FIELDS & {str(key).casefold() for key in value}:
            raise ValueError("Decision output attempted to assert authority")
        raw_scores = value.get("scores", ())
        if isinstance(raw_scores, Mapping):
            scores = tuple((str(key), float(score)) for key, score in raw_scores.items())
        else:
            scores = tuple((str(key), float(score)) for key, score in raw_scores)
        return cls(
            str(value.get("label", "unknown")),
            None if value.get("confidence") is None else float(value["confidence"]),
            scores,
            None if value.get("recommendation") is None else str(value["recommendation"]),
            tuple(str(item) for item in value.get("evidence", ())),
            identity.get("provider_id"),
            identity.get("model_id"),
            datetime.now(UTC),
        )


class DecisionProvider(IntelligenceProvider, ABC):
    """Typed decision capability; it is not a generative chat provider."""

    @property
    def intelligence_kinds(self) -> frozenset[str]:
        return frozenset({IntelligenceKind.DECISION.value})

    @abstractmethod
    async def decide(self, request: DecisionRequest) -> DecisionResult:
        """Return bounded advice; the caller retains all authority."""


class ModelDiscoveryAdapter(Protocol):
    async def discover_models(self) -> object:
        """Return a bounded provider catalog snapshot."""


class IntelligenceAdapter(Protocol):
    manifest: ProviderPackageManifest
    provider: IntelligenceProvider


@dataclass(frozen=True, slots=True)
class RemoteSafePayload:
    """The only payload shape accepted by the remote privacy gateway."""

    kind: IntelligenceKind
    fields: tuple[tuple[str, str], ...]
    classification: PrivacyClassification
    correlation_id: str | None = None

    def __post_init__(self) -> None:
        if not isinstance(self.kind, IntelligenceKind):
            raise ValueError("Remote payload kind is invalid")
        if self.classification in {PrivacyClassification.LOCAL_ONLY, PrivacyClassification.SECRET}:
            raise ValueError("Private data cannot become a remote-safe payload")
        if type(self.fields) is not tuple or len(self.fields) > 128:
            raise ValueError("Remote payload fields are invalid")
        for key, value in self.fields:
            _text(key, "Remote payload field", 128)
            _text(value, "Remote payload value", 8_000)


class RemoteIntelligencePrivacyGateway:
    """Generalized privacy boundary for non-generative remote intelligence."""

    def __init__(self, *, local_values: tuple[str, ...] = ()) -> None:
        if type(local_values) is not tuple or any(
            not isinstance(item, str) for item in local_values
        ):
            raise ValueError("Private value inventory is invalid")
        self._local_values = tuple(dict.fromkeys(value for value in local_values if value))

    def prepare(
        self,
        kind: IntelligenceKind,
        fields: Mapping[str, str],
        privacy: PrivacyContext,
        *,
        correlation_id: str | None = None,
    ) -> RemoteSafePayload:
        if not isinstance(kind, IntelligenceKind) or not isinstance(privacy, PrivacyContext):
            raise ValueError("Remote intelligence input is invalid")
        if privacy.classification in {
            PrivacyClassification.LOCAL_ONLY,
            PrivacyClassification.SECRET,
        }:
            raise PermissionError("remote intelligence is blocked for private data")
        if privacy.classification is PrivacyClassification.UNKNOWN:
            raise PermissionError("remote intelligence privacy is unknown")
        result: list[tuple[str, str]] = []
        for key, raw in fields.items():
            _text(str(key), "Remote field", 128)
            value = _text(str(raw), "Remote value", 8_000)
            for private in self._local_values:
                value = value.replace(private, "<LOCAL_PRIVATE>")
            result.append((str(key), value))
        payload = RemoteSafePayload(kind, tuple(result), privacy.classification, correlation_id)
        serialized = "\n".join(f"{key}={value}" for key, value in payload.fields)
        if any(private in serialized for private in self._local_values):
            raise PermissionError("remote payload retained local private data")
        return payload

    def validate_inbound(
        self, result: DecisionResult | str, privacy: PrivacyContext
    ) -> DecisionResult | str:
        if not isinstance(privacy, PrivacyContext):
            raise ValueError("Inbound privacy context is invalid")
        if isinstance(result, DecisionResult):
            return result
        if type(result) is not str or len(result) > 1_000_000:
            raise ValueError("Remote output is invalid")
        if any(private in result for private in self._local_values):
            raise ValueError("Remote output exposed local private data")
        return result


@dataclass(frozen=True, slots=True)
class UsageReceipt:
    """Post-call usage evidence; it never rewrites the pre-call estimate."""

    route_key: str
    input_tokens: int | None = None
    output_tokens: int | None = None
    actual_cost: float | None = None
    currency: str = "USD"
    observed_at: datetime = datetime.min.replace(tzinfo=UTC)
    source: str = "provider_receipt"

    def __post_init__(self) -> None:
        _text(self.route_key, "Usage route key", 1_024)
        for name, value in (
            ("input tokens", self.input_tokens),
            ("output tokens", self.output_tokens),
        ):
            if value is not None and (type(value) is not int or value < 0):
                raise ValueError(f"Usage {name} are invalid")
        if self.actual_cost is not None and (
            type(self.actual_cost) not in {int, float}
            or not math.isfinite(self.actual_cost)
            or self.actual_cost < 0
        ):
            raise ValueError("Actual usage cost is invalid")
        _text(self.currency, "Usage currency", 16)
        _text(self.source, "Usage source", 256)
        if self.observed_at.tzinfo is None:
            raise ValueError("Usage timestamp must be timezone-aware")


class DecisionCallable(Protocol):
    def __call__(self, request: DecisionRequest) -> Awaitable[DecisionResult]: ...


class CallableDecisionProvider(DecisionProvider):
    """Small adapter used by deterministic local/fixture decision paths."""

    def __init__(self, callback: DecisionCallable, provider_id: str = "local-decision") -> None:
        if not callable(callback):
            raise ValueError("Decision callback is invalid")
        self._callback = callback
        self.provider_id = _text(provider_id, "Decision provider ID", 256)

    async def decide(self, request: DecisionRequest) -> DecisionResult:
        result = await self._callback(request)
        if not isinstance(result, DecisionResult):
            raise ValueError("Decision callback returned an invalid result")
        return result
