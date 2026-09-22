"""Standard provider package catalog and shared protocol-family adapters."""

from __future__ import annotations

from collections.abc import AsyncIterator, Awaitable, Callable, Mapping
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Protocol
from urllib.parse import urlsplit

from jarvis.ai.knowledge import ModelObservation, ProviderCatalogSnapshot, identity_for
from jarvis.ai.models import (
    GenerationChunk,
    GenerationRequest,
    GenerationResult,
    ModelInfo,
    ModelRole,
    ProviderHealth,
)
from jarvis.ai.providers.base import AIProvider
from jarvis.ai.providers.intelligence import (
    AuthenticationType,
    DecisionProvider,
    DecisionRequest,
    DecisionResult,
    IntelligenceKind,
    PackageSupportStatus,
    ProtocolFamily,
    ProviderPackageManifest,
    ProviderSetupField,
)
from jarvis.ai.providers.registry import ProviderLocality, ProviderMetadata
from jarvis.security import local_model_endpoint_is_safe


def _key(name: str, label: str = "API credential") -> ProviderSetupField:
    return ProviderSetupField(name, label, secret=True, value_kind="credential_ref")


def _manifest(
    provider_id: str,
    display_name: str,
    *,
    kinds: frozenset[IntelligenceKind] = frozenset({IntelligenceKind.GENERATIVE}),
    auth: AuthenticationType = AuthenticationType.API_KEY,
    protocol: ProtocolFamily = ProtocolFamily.UNKNOWN,
    fields: tuple[ProviderSetupField, ...] = (),
    website: str | None = None,
    console: str | None = None,
    dynamic: bool = False,
    probe: bool = False,
    status: PackageSupportStatus = PackageSupportStatus.CONTRACT_ONLY,
) -> ProviderPackageManifest:
    # A catalog declaration is descriptive.  Only the generic openai-compatible
    # package has a bounded source adapter in this candidate; all other remote
    # packages remain honest contract metadata until an adapter is installed and
    # tested for that protocol family.
    executable_discovery = provider_id == "openai-compatible"
    return ProviderPackageManifest(
        provider_id,
        display_name,
        kinds,
        authentication=auth,
        required_fields=fields,
        official_website=website,
        developer_console=console,
        credential_management_url=console,
        protocol_family=protocol,
        dynamic_model_discovery=dynamic and executable_discovery,
        usability_probe=probe and executable_discovery,
        support_status=status,
    )


_OPENAI_FIELDS = (_key("api_credential"),)
_OPENAI_COMPATIBLE_FIELDS = (
    ProviderSetupField("base_url", "Base URL", value_kind="url"),
    _key("api_credential"),
)


STANDARD_PROVIDER_MANIFESTS: tuple[ProviderPackageManifest, ...] = (
    _manifest(
        "openai",
        "OpenAI",
        protocol=ProtocolFamily.OPENAI_COMPATIBLE,
        fields=_OPENAI_FIELDS,
        website="https://platform.openai.com/docs",
        console="https://platform.openai.com/api-keys",
        dynamic=True,
        probe=True,
    ),
    _manifest(
        "anthropic",
        "Anthropic / Claude",
        protocol=ProtocolFamily.ANTHROPIC_MESSAGES,
        fields=_OPENAI_FIELDS,
        website="https://docs.anthropic.com",
        console="https://console.anthropic.com",
        dynamic=True,
        probe=True,
    ),
    _manifest(
        "google-gemini",
        "Google Gemini API",
        protocol=ProtocolFamily.GOOGLE_GEMINI,
        fields=_OPENAI_FIELDS,
        website="https://ai.google.dev/gemini-api/docs",
        console="https://aistudio.google.com/apikey",
        dynamic=True,
        probe=True,
    ),
    _manifest(
        "xai-grok",
        "xAI / Grok",
        protocol=ProtocolFamily.OPENAI_COMPATIBLE,
        fields=_OPENAI_FIELDS,
        website="https://docs.x.ai",
        console="https://console.x.ai",
        dynamic=True,
        probe=True,
    ),
    _manifest(
        "mistral",
        "Mistral AI",
        protocol=ProtocolFamily.OPENAI_COMPATIBLE,
        fields=_OPENAI_FIELDS,
        website="https://docs.mistral.ai",
        console="https://console.mistral.ai",
        dynamic=True,
        probe=True,
    ),
    _manifest(
        "deepseek",
        "DeepSeek",
        protocol=ProtocolFamily.OPENAI_COMPATIBLE,
        fields=_OPENAI_FIELDS,
        website="https://api-docs.deepseek.com",
        dynamic=True,
        probe=True,
    ),
    _manifest(
        "cohere",
        "Cohere",
        kinds=frozenset(
            {IntelligenceKind.GENERATIVE, IntelligenceKind.EMBEDDING, IntelligenceKind.RERANKING}
        ),
        protocol=ProtocolFamily.NATIVE,
        fields=_OPENAI_FIELDS,
        website="https://docs.cohere.com",
        console="https://dashboard.cohere.com",
        dynamic=True,
        probe=True,
    ),
    _manifest(
        "ai21",
        "AI21",
        protocol=ProtocolFamily.NATIVE,
        fields=_OPENAI_FIELDS,
        website="https://docs.ai21.com",
        console="https://studio.ai21.com",
        dynamic=True,
        probe=True,
    ),
    _manifest(
        "typesafe-jev",
        "TypeSafe AI / Jev",
        kinds=frozenset({IntelligenceKind.DECISION}),
        auth=AuthenticationType.API_KEY,
        protocol=ProtocolFamily.DECISION_TYPED,
        fields=_OPENAI_FIELDS,
        website="https://docs.typesafe.ai",
        dynamic=True,
        probe=True,
        status=PackageSupportStatus.EXTERNAL_PROTOCOL_FACT_NOT_PROVEN,
    ),
    _manifest(
        "openrouter",
        "OpenRouter",
        protocol=ProtocolFamily.OPENAI_COMPATIBLE,
        fields=_OPENAI_FIELDS,
        website="https://openrouter.ai/docs",
        console="https://openrouter.ai/settings/keys",
        dynamic=True,
        probe=True,
    ),
    _manifest(
        "groqcloud",
        "GroqCloud",
        protocol=ProtocolFamily.OPENAI_COMPATIBLE,
        fields=_OPENAI_FIELDS,
        website="https://console.groq.com/docs",
        console="https://console.groq.com/keys",
        dynamic=True,
        probe=True,
    ),
    _manifest(
        "together-ai",
        "Together AI",
        protocol=ProtocolFamily.OPENAI_COMPATIBLE,
        fields=_OPENAI_FIELDS,
        website="https://docs.together.ai",
        console="https://api.together.ai/settings/api-keys",
        dynamic=True,
        probe=True,
    ),
    _manifest(
        "fireworks-ai",
        "Fireworks AI",
        protocol=ProtocolFamily.OPENAI_COMPATIBLE,
        fields=_OPENAI_FIELDS,
        website="https://docs.fireworks.ai",
        console="https://fireworks.ai/account/api-keys",
        dynamic=True,
        probe=True,
    ),
    _manifest(
        "cerebras-cloud",
        "Cerebras Cloud",
        protocol=ProtocolFamily.OPENAI_COMPATIBLE,
        fields=_OPENAI_FIELDS,
        website="https://inference-docs.cerebras.ai",
        console="https://cloud.cerebras.ai",
        dynamic=True,
        probe=True,
    ),
    _manifest(
        "sambanova-cloud",
        "SambaNova Cloud",
        protocol=ProtocolFamily.OPENAI_COMPATIBLE,
        fields=_OPENAI_FIELDS,
        website="https://docs.sambanova.ai",
        console="https://cloud.sambanova.ai",
        dynamic=True,
        probe=True,
    ),
    _manifest(
        "nvidia-nim",
        "NVIDIA hosted NIM / API Catalog",
        protocol=ProtocolFamily.OPENAI_COMPATIBLE,
        fields=_OPENAI_FIELDS,
        website="https://docs.api.nvidia.com",
        console="https://build.nvidia.com",
        dynamic=True,
        probe=True,
    ),
    _manifest(
        "perplexity",
        "Perplexity API",
        protocol=ProtocolFamily.OPENAI_COMPATIBLE,
        fields=_OPENAI_FIELDS,
        website="https://docs.perplexity.ai",
        console="https://www.perplexity.ai/settings/api",
        dynamic=True,
        probe=True,
    ),
    _manifest(
        "alibaba-dashscope",
        "Alibaba Cloud DashScope / Qwen",
        protocol=ProtocolFamily.NATIVE,
        fields=_OPENAI_FIELDS,
        website="https://www.alibabacloud.com/help/en/model-studio",
        dynamic=True,
        probe=True,
    ),
    _manifest(
        "moonshot-kimi",
        "Moonshot AI / Kimi",
        protocol=ProtocolFamily.OPENAI_COMPATIBLE,
        fields=_OPENAI_FIELDS,
        website="https://platform.moonshot.cn/docs",
        dynamic=True,
        probe=True,
    ),
    _manifest(
        "zhipu-glm",
        "Zhipu AI / GLM",
        protocol=ProtocolFamily.OPENAI_COMPATIBLE,
        fields=_OPENAI_FIELDS,
        website="https://open.bigmodel.cn/dev/api",
        dynamic=True,
        probe=True,
    ),
    _manifest(
        "minimax",
        "MiniMax",
        protocol=ProtocolFamily.NATIVE,
        fields=_OPENAI_FIELDS,
        website="https://www.minimaxi.com/document",
        dynamic=True,
        probe=True,
    ),
    _manifest(
        "baidu-qianfan",
        "Baidu / ERNIE / Qianfan",
        protocol=ProtocolFamily.NATIVE,
        fields=_OPENAI_FIELDS,
        website="https://cloud.baidu.com/doc/WENXINWORKSHOP",
        dynamic=True,
        probe=True,
    ),
    _manifest(
        "tencent-hunyuan",
        "Tencent / Hunyuan",
        protocol=ProtocolFamily.NATIVE,
        fields=_OPENAI_FIELDS,
        website="https://cloud.tencent.com/document/product/1729",
        dynamic=True,
        probe=True,
    ),
    _manifest(
        "bytedance-volcengine",
        "ByteDance / Volcano Engine / Doubao",
        protocol=ProtocolFamily.NATIVE,
        fields=_OPENAI_FIELDS,
        website="https://www.volcengine.com/docs/82379",
        dynamic=True,
        probe=True,
    ),
    _manifest(
        "azure-openai",
        "Microsoft Azure OpenAI / Azure AI Foundry",
        protocol=ProtocolFamily.AZURE_AI,
        fields=(
            ProviderSetupField("endpoint", "Endpoint", value_kind="url"),
            ProviderSetupField("deployment", "Deployment"),
            ProviderSetupField("tenant", "Tenant", required=False),
            _key("api_credential"),
        ),
        website="https://learn.microsoft.com/azure/ai-services/openai",
        dynamic=True,
        probe=True,
    ),
    _manifest(
        "amazon-bedrock",
        "Amazon Bedrock",
        auth=AuthenticationType.SERVICE_ACCOUNT,
        protocol=ProtocolFamily.AWS_BEDROCK,
        fields=(
            ProviderSetupField("region", "AWS region"),
            ProviderSetupField("role", "Role or profile", required=False),
        ),
        website="https://docs.aws.amazon.com/bedrock",
        dynamic=True,
        probe=True,
    ),
    _manifest(
        "google-vertex",
        "Google Vertex AI",
        auth=AuthenticationType.SERVICE_ACCOUNT,
        protocol=ProtocolFamily.GOOGLE_GEMINI,
        fields=(
            ProviderSetupField("project", "Google Cloud project"),
            ProviderSetupField("region", "Region"),
            ProviderSetupField(
                "service_account",
                "Service-account reference",
                secret=True,
                value_kind="credential_ref",
            ),
        ),
        website="https://cloud.google.com/vertex-ai/docs",
        dynamic=True,
        probe=True,
    ),
    _manifest(
        "openai-compatible",
        "OpenAI-compatible provider",
        protocol=ProtocolFamily.OPENAI_COMPATIBLE,
        fields=_OPENAI_COMPATIBLE_FIELDS,
        website=None,
        dynamic=True,
        probe=True,
    ),
)


@dataclass(frozen=True, slots=True)
class ProviderSupportRecord:
    """Truthful support facts; catalog presence never implies execution."""

    provider_id: str
    intelligence_kinds: tuple[str, ...]
    protocol_family: str
    catalog_present: bool
    source_adapter_present: bool
    controlled_protocol_tested: bool
    discovery_mode: str
    credential_type: str
    required_fields: tuple[str, ...]
    external_protocol_status: str
    physical_status: str


def provider_support_matrix() -> tuple[ProviderSupportRecord, ...]:
    """Return the complete 28-entry provider support classification."""

    return tuple(
        ProviderSupportRecord(
            manifest.provider_id,
            tuple(sorted(kind.value for kind in manifest.kinds)),
            manifest.protocol_family.value,
            True,
            manifest.provider_id == "openai-compatible",
            manifest.provider_id == "openai-compatible",
            "bounded_dynamic" if manifest.dynamic_model_discovery else "not_implemented",
            manifest.authentication.value,
            tuple(field.name for field in manifest.required_fields),
            "PROVEN"
            if manifest.provider_id == "openai-compatible"
            else "EXTERNAL_PROTOCOL_FACT_NOT_PROVEN",
            "PHYSICAL_VALIDATION_REQUIRED",
        )
        for manifest in STANDARD_PROVIDER_MANIFESTS
    )


_ALIASES = {
    "google": "google-gemini",
    "gemini": "google-gemini",
    "xai": "xai-grok",
    "groq": "groqcloud",
    "together": "together-ai",
    "fireworks": "fireworks-ai",
    "jev": "typesafe-jev",
    "azure": "azure-openai",
    "bedrock": "amazon-bedrock",
    "vertex": "google-vertex",
    "openai_compatible_provider": "openai-compatible",
}


def standard_provider_catalog() -> tuple[ProviderPackageManifest, ...]:
    """Return the immutable standard catalog in deterministic order."""

    return STANDARD_PROVIDER_MANIFESTS


def provider_manifest(provider_id: str) -> ProviderPackageManifest:
    key = _ALIASES.get(provider_id.casefold(), provider_id.casefold())
    for manifest in STANDARD_PROVIDER_MANIFESTS:
        if manifest.provider_id == key:
            return manifest
    raise KeyError(f"Unknown provider package: {provider_id}")


class OpenAICompatibleTransport(Protocol):
    async def request(
        self,
        method: str,
        path: str,
        payload: Mapping[str, object] | None,
        headers: Mapping[str, str],
    ) -> Mapping[str, object]: ...


@dataclass(frozen=True, slots=True)
class OpenAICompatibleConfiguration:
    """Safe custom endpoint configuration; executable hooks are impossible."""

    provider_id: str
    base_url: str
    model: str
    locality: ProviderLocality = ProviderLocality.REMOTE
    organization: str | None = None
    project: str | None = None
    credential_ref: object | None = None

    def __post_init__(self) -> None:
        if (
            type(self.provider_id) is not str
            or type(self.model) is not str
            or not self.provider_id.strip()
            or not self.model.strip()
            or len(self.provider_id) > 128
            or len(self.model) > 256
        ):
            raise ValueError("OpenAI-compatible identity is invalid")
        if type(self.base_url) is not str or len(self.base_url) > 2_048:
            raise ValueError("OpenAI-compatible base URL is invalid")
        parsed = urlsplit(self.base_url)
        if (
            "\x00" in self.base_url
            or parsed.scheme not in {"https", "http"}
            or not parsed.hostname
            or parsed.username is not None
            or parsed.password is not None
            or parsed.query
            or parsed.fragment
        ):
            raise ValueError("OpenAI-compatible base URL is invalid")
        if not isinstance(self.locality, ProviderLocality):
            raise ValueError("OpenAI-compatible locality is invalid")
        if self.locality is ProviderLocality.LOCAL and not local_model_endpoint_is_safe(
            self.base_url
        ):
            raise ValueError("LOCAL endpoint must be a trusted literal loopback")
        if self.locality is not ProviderLocality.LOCAL and parsed.hostname.casefold() in {
            "localhost",
            "127.0.0.1",
            "::1",
        }:
            raise ValueError("Loopback endpoint requires trusted LOCAL metadata")
        if self.locality is ProviderLocality.REMOTE and parsed.scheme != "https":
            raise ValueError("Remote OpenAI-compatible routes require HTTPS")
        object.__setattr__(self, "base_url", self.base_url.rstrip("/"))


class OpenAICompatibleProvider(AIProvider):
    """Shared transport adapter for OpenAI-shaped provider packages."""

    def __init__(
        self,
        configuration: OpenAICompatibleConfiguration,
        transport: OpenAICompatibleTransport,
        *,
        credential_resolver: Callable[[object], Awaitable[str | bytes]] | None = None,
    ) -> None:
        self.configuration = configuration
        self._transport = transport
        self._credential_resolver = credential_resolver

    @property
    def intelligence_kinds(self) -> frozenset[str]:
        return frozenset({IntelligenceKind.GENERATIVE.value})

    async def _headers(self) -> dict[str, str]:
        headers = {"accept": "application/json", "content-type": "application/json"}
        ref = self.configuration.credential_ref
        if ref is not None:
            if self._credential_resolver is None:
                raise PermissionError("Credential resolver is required")
            secret = await self._credential_resolver(ref)
            headers["authorization"] = (
                f"Bearer {secret.decode() if isinstance(secret, bytes) else secret}"
            )
        if self.configuration.organization:
            headers["openai-organization"] = self.configuration.organization
        if self.configuration.project:
            headers["openai-project"] = self.configuration.project
        return headers

    async def generate(self, request: GenerationRequest) -> GenerationResult:
        payload = {
            "model": request.model,
            "messages": [
                {"role": message.role.value, "content": message.content}
                for message in request.messages
            ],
        }
        response = await self._transport.request(
            "POST", "/chat/completions", payload, await self._headers()
        )
        try:
            choices = response["choices"]
            content = choices[0]["message"]["content"]  # type: ignore[index]
            model = str(response.get("model", request.model))
        except (KeyError, IndexError, TypeError) as error:
            raise ValueError("OpenAI-compatible response is malformed") from error
        if type(content) is not str or len(content) > 1_000_000:
            raise ValueError("OpenAI-compatible response content is invalid")
        return GenerationResult(content, model)

    async def stream(self, request: GenerationRequest) -> AsyncIterator[GenerationChunk]:
        result = await self.generate(request)
        yield GenerationChunk(result.content, True)

    async def health_check(self) -> ProviderHealth:
        try:
            await self._transport.request("GET", "/models", None, await self._headers())
        except Exception as error:
            return ProviderHealth(False, type(error).__name__[:128])
        return ProviderHealth(True, "model endpoint reachable")

    async def model_info(self) -> ModelInfo:
        return ModelInfo(self.configuration.provider_id, self.configuration.model, 1)

    async def discover_models(self) -> ProviderCatalogSnapshot:
        response = await self._transport.request("GET", "/models", None, await self._headers())
        raw_models = response.get("data")
        if not isinstance(raw_models, list) or len(raw_models) > 1_024:
            raise ValueError("Model discovery response is malformed or oversized")
        observations: list[ModelObservation] = []
        now = datetime.now(UTC)
        provider = ProviderMetadata(
            self.configuration.provider_id,
            self.configuration.provider_id,
            "discovery",
            locality=self.configuration.locality,
        )
        for item in raw_models:
            if not isinstance(item, Mapping):
                raise ValueError("Model discovery item is malformed")
            model_id = item.get("id")
            if (
                type(model_id) is not str
                or not model_id.strip()
                or len(model_id) > 256
                or any(ord(char) < 32 for char in model_id)
            ):
                raise ValueError("Model discovery model ID is invalid")
            from jarvis.ai.providers.registry import ModelMetadata

            metadata = ModelMetadata(
                model_id,
                1,
                roles=frozenset({ModelRole.GENERAL}),
                modalities=frozenset({"text"}),
                source="provider_discovery",
                endpoint=self.configuration.base_url,
                region="unknown",
                deployment="unknown",
                account_scope="unknown",
                inference_kind=IntelligenceKind.GENERATIVE.value,
            )
            observations.append(
                ModelObservation(
                    identity_for(provider.provider_id, metadata),
                    metadata,
                    now,
                    "provider_discovery",
                )
            )
        return ProviderCatalogSnapshot(
            provider, tuple(observations), now, "provider_discovery", True
        )


class JevDecisionProvider(DecisionProvider):
    """Typed Jev adapter boundary; transport is injected and optional offline."""

    def __init__(
        self, transport: Callable[[DecisionRequest], Awaitable[DecisionResult]] | None = None
    ) -> None:
        self._transport = transport

    @property
    def provider_id(self) -> str:
        return "typesafe-jev"

    async def decide(self, request: DecisionRequest) -> DecisionResult:
        if self._transport is None:
            raise ConnectionError("Jev decision provider is unavailable")
        result = await self._transport(request)
        if not isinstance(result, DecisionResult):
            raise ValueError("Jev returned malformed decision output")
        return result

    async def health_check(self) -> bool:
        return self._transport is not None
