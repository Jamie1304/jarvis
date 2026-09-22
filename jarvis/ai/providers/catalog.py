"""Standard provider package catalog and shared protocol-family adapters."""

from __future__ import annotations

import hashlib
import hmac
import json
import re
from collections.abc import AsyncIterator, Awaitable, Callable, Mapping, Sequence
from dataclasses import dataclass, field, replace
from datetime import UTC, datetime
from enum import StrEnum
from typing import Protocol, cast
from urllib.parse import quote, unquote, urlsplit

import httpx

from jarvis.ai.knowledge import ModelObservation, ProviderCatalogSnapshot, identity_for
from jarvis.ai.models import (
    GenerationChunk,
    GenerationRequest,
    GenerationResult,
    ModelInfo,
    ModelRole,
    ProviderHealth,
)
from jarvis.ai.providers.base import AIProvider, IntelligenceProvider
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
from jarvis.ai.providers.registry import ModelMetadata, ProviderLocality, ProviderMetadata
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
    optional_fields: tuple[ProviderSetupField, ...] = (),
    website: str | None = None,
    console: str | None = None,
    dynamic: bool = False,
    probe: bool = False,
    status: PackageSupportStatus = PackageSupportStatus.CONTRACT_ONLY,
    adapter_owner: str = "",
    discovery_mode: str = "NOT_SUPPORTED",
    sources: tuple[str, ...] = (),
) -> ProviderPackageManifest:
    return ProviderPackageManifest(
        provider_id,
        display_name,
        kinds,
        authentication=auth,
        required_fields=fields,
        optional_fields=optional_fields,
        official_website=website,
        developer_console=console,
        credential_management_url=console,
        protocol_family=protocol,
        dynamic_model_discovery=dynamic,
        usability_probe=probe,
        support_status=status,
        adapter_owner=adapter_owner,
        discovery_mode=discovery_mode,
        official_protocol_sources=sources,
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
        kinds=frozenset({IntelligenceKind.GENERATIVE}),
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
        protocol=ProtocolFamily.OPENAI_COMPATIBLE,
        fields=_OPENAI_FIELDS,
        optional_fields=(ProviderSetupField("model", "Model"),),
        website="https://docs.ai21.com",
        console="https://studio.ai21.com",
        dynamic=False,
        probe=False,
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
        protocol=ProtocolFamily.OPENAI_COMPATIBLE,
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
        protocol=ProtocolFamily.OPENAI_COMPATIBLE,
        fields=_OPENAI_FIELDS,
        website="https://cloud.baidu.com/doc/WENXINWORKSHOP",
        dynamic=True,
        probe=True,
    ),
    _manifest(
        "tencent-hunyuan",
        "Tencent / Hunyuan",
        protocol=ProtocolFamily.OPENAI_COMPATIBLE,
        fields=_OPENAI_FIELDS,
        website="https://cloud.tencent.com/document/product/1729",
        dynamic=True,
        probe=True,
    ),
    _manifest(
        "bytedance-volcengine",
        "ByteDance / Volcano Engine / Doubao",
        protocol=ProtocolFamily.OPENAI_COMPATIBLE,
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
        optional_fields=(ProviderSetupField("api_version", "API version"),),
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


# These are the protocol facts used by the source adapters below.  The URLs
# are metadata only; they never become runtime network destinations.  Runtime
# destinations are fixed by the package presets or typed enterprise fields.
_SOURCE_EXECUTABLE_IDS = frozenset(
    {
        "openai",
        "anthropic",
        "google-gemini",
        "cohere",
        "ai21",
        "xai-grok",
        "mistral",
        "deepseek",
        "openrouter",
        "groqcloud",
        "together-ai",
        "fireworks-ai",
        "cerebras-cloud",
        "sambanova-cloud",
        "nvidia-nim",
        "perplexity",
        "alibaba-dashscope",
        "moonshot-kimi",
        "zhipu-glm",
        "baidu-qianfan",
        "tencent-hunyuan",
        "bytedance-volcengine",
        "azure-openai",
        "amazon-bedrock",
        "google-vertex",
        "openai-compatible",
    }
)

_PROTOCOL_SOURCES: dict[str, tuple[str, ...]] = {
    "openai": ("https://platform.openai.com/docs/api-reference/models",),
    "anthropic": ("https://platform.claude.com/docs/en/api/overview",),
    "google-gemini": ("https://ai.google.dev/api/models",),
    "cohere": (
        "https://docs.cohere.com/reference/list-models",
        "https://docs.cohere.com/reference/chat",
    ),
    "ai21": ("https://docs.ai21.com/reference",),
    "xai-grok": ("https://docs.x.ai/developers/rest-api-reference/inference/models",),
    "mistral": ("https://docs.mistral.ai/api/endpoint/models",),
    "deepseek": ("https://api-docs.deepseek.com/",),
    "openrouter": ("https://openrouter.ai/docs/api/api-reference/models/get-models",),
    "groqcloud": ("https://console.groq.com/docs/api-reference",),
    "together-ai": ("https://docs.together.ai/reference/list-models",),
    "fireworks-ai": ("https://docs.fireworks.ai/api-reference/list-models",),
    "cerebras-cloud": ("https://inference-docs.cerebras.ai/api-reference/models",),
    "sambanova-cloud": ("https://docs.sambanova.ai/docs/api-reference",),
    "nvidia-nim": ("https://docs.api.nvidia.com/nim/reference",),
    "perplexity": ("https://docs.perplexity.ai/api-reference/models",),
    "alibaba-dashscope": (
        "https://www.alibabacloud.com/help/en/model-studio/compatibility-of-openai-with-dashscope",
    ),
    "moonshot-kimi": ("https://platform.moonshot.cn/docs/api",),
    "zhipu-glm": ("https://open.bigmodel.cn/dev/api",),
    "baidu-qianfan": ("https://cloud.baidu.com/doc/qianfan-api/s/Dmba8k71y",),
    "tencent-hunyuan": ("https://cloud.tencent.com/document/product/1729/111007",),
    "bytedance-volcengine": ("https://docs.volcengine.com/docs/ark/chat-api",),
    "azure-openai": ("https://learn.microsoft.com/azure/ai-services/openai/reference",),
    "amazon-bedrock": ("https://docs.aws.amazon.com/bedrock/latest/APIReference/",),
    "google-vertex": ("https://cloud.google.com/vertex-ai/docs/reference/rest",),
    "openai-compatible": ("https://platform.openai.com/docs/api-reference/chat",),
}

_ADAPTER_OWNERS: dict[str, str] = {
    "cohere": "CohereProvider",
    "ai21": "AI21Provider",
    "azure-openai": "AzureOpenAIProvider",
    "amazon-bedrock": "BedrockProvider",
    "google-vertex": "VertexAIProvider",
}


def _finalize_manifests(
    manifests: tuple[ProviderPackageManifest, ...],
) -> tuple[ProviderPackageManifest, ...]:
    result: list[ProviderPackageManifest] = []
    for manifest in manifests:
        if manifest.provider_id in _SOURCE_EXECUTABLE_IDS:
            result.append(
                replace(
                    manifest,
                    support_status=PackageSupportStatus.CONTROLLED_PROTOCOL_TESTED,
                    adapter_owner=_ADAPTER_OWNERS.get(
                        manifest.provider_id,
                        (
                            "OpenAICompatibleProvider"
                            if manifest.protocol_family is ProtocolFamily.OPENAI_COMPATIBLE
                            else f"{manifest.protocol_family.value}:Provider"
                        ),
                    ),
                    discovery_mode="DYNAMIC"
                    if manifest.dynamic_model_discovery
                    else "NOT_SUPPORTED",
                    official_protocol_sources=_PROTOCOL_SOURCES.get(manifest.provider_id, ()),
                )
            )
        else:
            result.append(
                replace(
                    manifest,
                    support_status=(
                        PackageSupportStatus.EXTERNAL_PROTOCOL_FACT_NOT_PROVEN
                        if manifest.provider_id == "typesafe-jev"
                        else PackageSupportStatus.CATALOG_ONLY
                    ),
                    dynamic_model_discovery=False,
                    usability_probe=False,
                    adapter_owner="",
                    discovery_mode="NOT_SUPPORTED",
                    official_protocol_sources=_PROTOCOL_SOURCES.get(
                        manifest.provider_id,
                        (manifest.official_website,) if manifest.official_website else (),
                    ),
                )
            )
    return tuple(result)


STANDARD_PROVIDER_MANIFESTS = _finalize_manifests(STANDARD_PROVIDER_MANIFESTS)


@dataclass(frozen=True, slots=True)
class ProviderSupportRecord:
    """Truthful support facts; catalog presence never implies execution."""

    provider_id: str
    intelligence_kinds: tuple[str, ...]
    protocol_family: str
    catalog_present: bool
    package_present: bool
    source_adapter_present: bool
    adapter_implementation_owner: str
    controlled_protocol_tested: bool
    discovery_mode: str
    credential_type: str
    required_fields: tuple[str, ...]
    external_protocol_status: str
    source_support_level: str
    official_documentation_evidence: tuple[str, ...]
    physical_status: str


def provider_support_matrix() -> tuple[ProviderSupportRecord, ...]:
    """Return the complete 28-entry provider support classification."""

    return tuple(
        ProviderSupportRecord(
            manifest.provider_id,
            tuple(sorted(kind.value for kind in manifest.kinds)),
            manifest.protocol_family.value,
            True,
            True,
            manifest.support_status is PackageSupportStatus.CONTROLLED_PROTOCOL_TESTED,
            manifest.adapter_owner,
            manifest.support_status is PackageSupportStatus.CONTROLLED_PROTOCOL_TESTED,
            manifest.discovery_mode,
            manifest.authentication.value,
            tuple(field.name for field in manifest.required_fields if field.required),
            "PROVEN"
            if manifest.provider_id in _SOURCE_EXECUTABLE_IDS
            else manifest.support_status.value,
            manifest.support_status.value,
            manifest.official_protocol_sources,
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


class ProviderErrorReason(StrEnum):
    """Bounded provider failure classes; remote text is never trusted."""

    AUTHENTICATION_FAILED = "AUTHENTICATION_FAILED"
    RATE_LIMITED = "RATE_LIMITED"
    QUOTA_UNAVAILABLE = "QUOTA_UNAVAILABLE"
    MODEL_NOT_FOUND = "MODEL_NOT_FOUND"
    PROVIDER_UNAVAILABLE = "PROVIDER_UNAVAILABLE"
    TIMEOUT = "TIMEOUT"
    MALFORMED_RESPONSE = "MALFORMED_RESPONSE"
    REDIRECT_BLOCKED = "REDIRECT_BLOCKED"
    UNKNOWN = "UNKNOWN"


class ProviderAdapterError(RuntimeError):
    """Safe adapter error with a stable reason and no provider response body."""

    def __init__(
        self,
        reason: ProviderErrorReason,
        *,
        status_code: int | None = None,
        detail: str = "",
    ) -> None:
        self.reason = reason
        self.status_code = status_code
        safe_detail = re.sub(r"[\r\n\x00-\x1f]", " ", detail)[:256]
        super().__init__(
            f"{reason.value}{f' ({status_code})' if status_code else ''}: {safe_detail}"
        )


def _classify_status(status_code: int) -> ProviderErrorReason:
    return {
        401: ProviderErrorReason.AUTHENTICATION_FAILED,
        403: ProviderErrorReason.AUTHENTICATION_FAILED,
        404: ProviderErrorReason.MODEL_NOT_FOUND,
        408: ProviderErrorReason.TIMEOUT,
        409: ProviderErrorReason.QUOTA_UNAVAILABLE,
        429: ProviderErrorReason.RATE_LIMITED,
    }.get(
        status_code,
        ProviderErrorReason.PROVIDER_UNAVAILABLE
        if status_code >= 500
        else ProviderErrorReason.UNKNOWN,
    )


@dataclass(frozen=True, slots=True)
class ProviderExecutionRecord:
    """P1-P28 acceptance states; each plane is reported independently."""

    acceptance_id: str
    provider_id: str
    catalog: str
    package: str
    adapter: str
    controlled_protocol: str
    discovery: str
    onboarding: str
    routing: str
    physical: str


def provider_execution_matrix() -> tuple[ProviderExecutionRecord, ...]:
    """Return the deterministic P1-P28 package execution matrix."""

    rows: list[ProviderExecutionRecord] = []
    for index, manifest in enumerate(STANDARD_PROVIDER_MANIFESTS, start=1):
        executable = manifest.support_status is PackageSupportStatus.CONTROLLED_PROTOCOL_TESTED
        blocked = "PASS" if executable else "BLOCKED"
        rows.append(
            ProviderExecutionRecord(
                f"P{index}",
                manifest.provider_id,
                "PASS",
                "PASS",
                blocked,
                "PASS" if executable else "NOT_PROVEN",
                manifest.discovery_mode,
                blocked,
                blocked,
                "NOT_VALIDATED",
            )
        )
    return tuple(rows)


class HttpxJSONTransport:
    """Bounded HTTPS transport used by source packages in production.

    Redirects are disabled so a credential-bearing request cannot silently
    move to a different destination.  Tests inject a transport implementing
    the small protocol above and therefore exercise the same adapter code.
    """

    def __init__(
        self,
        base_url: str,
        *,
        timeout_seconds: float = 15.0,
        client: httpx.AsyncClient | None = None,
        allowed_host: str | None = None,
        allow_http_loopback: bool = False,
    ) -> None:
        parsed = urlsplit(base_url)
        if (
            parsed.scheme not in {"https", "http"}
            or not parsed.hostname
            or parsed.query
            or parsed.fragment
            or (
                parsed.scheme == "http"
                and (
                    not allow_http_loopback
                    or parsed.hostname.casefold() not in {"localhost", "127.0.0.1", "::1"}
                )
            )
        ):
            raise ValueError("Provider transport requires fixed HTTPS or trusted loopback HTTP")
        if not 0.1 <= timeout_seconds <= 120.0:
            raise ValueError("Provider timeout is outside the bounded range")
        self.base_url = base_url.rstrip("/")
        self._timeout_seconds = timeout_seconds
        self._allowed_host = (allowed_host or parsed.hostname).casefold()
        self._client = client
        self._owns_client = client is None

    async def request(
        self,
        method: str,
        path: str,
        payload: Mapping[str, object] | None,
        headers: Mapping[str, str],
    ) -> Mapping[str, object]:
        if not path.startswith("/") or "\x00" in path or len(path) > 2_048:
            raise ProviderAdapterError(ProviderErrorReason.UNKNOWN, detail="invalid provider path")
        client = self._client
        owns_client = client is None
        if owns_client:
            client = httpx.AsyncClient(
                base_url=self.base_url,
                timeout=httpx.Timeout(self._timeout_seconds),
                follow_redirects=False,
                trust_env=False,
            )
        assert client is not None
        try:
            if payload is not None:
                response = await client.request(
                    method,
                    path,
                    content=_json_payload_bytes(payload),
                    headers=dict(headers),
                )
            else:
                response = await client.request(method, path, headers=dict(headers))
            if response.is_redirect or response.status_code in {301, 302, 303, 307, 308}:
                location = response.headers.get("location", "")
                target = urlsplit(location)
                if not target.hostname or target.hostname.casefold() != self._allowed_host:
                    raise ProviderAdapterError(
                        ProviderErrorReason.REDIRECT_BLOCKED, detail="redirect blocked"
                    )
                raise ProviderAdapterError(
                    ProviderErrorReason.REDIRECT_BLOCKED, detail="redirect not followed"
                )
            if response.status_code >= 400:
                raise ProviderAdapterError(
                    _classify_status(response.status_code),
                    status_code=response.status_code,
                    detail="provider request failed",
                )
            try:
                value = response.json()
            except ValueError as error:
                raise ProviderAdapterError(
                    ProviderErrorReason.MALFORMED_RESPONSE, detail="provider response is not JSON"
                ) from error
            if not isinstance(value, Mapping):
                raise ProviderAdapterError(
                    ProviderErrorReason.MALFORMED_RESPONSE,
                    detail="provider response is not an object",
                )
            return value
        except httpx.TimeoutException as error:
            raise ProviderAdapterError(
                ProviderErrorReason.TIMEOUT, detail="provider timeout"
            ) from error
        except httpx.HTTPError as error:
            raise ProviderAdapterError(
                ProviderErrorReason.PROVIDER_UNAVAILABLE, detail="provider transport unavailable"
            ) from error
        finally:
            if owns_client:
                await client.aclose()

    async def aclose(self) -> None:
        if self._owns_client and self._client is not None:
            await self._client.aclose()


def _bounded_positive_int(value: object) -> int | None:
    if type(value) is int and 0 < value <= 2_000_000:
        return value
    return None


def _json_payload_bytes(payload: Mapping[str, object]) -> bytes:
    return json.dumps(payload, ensure_ascii=False, separators=(",", ":")).encode("utf-8")


def _capabilities_from_model_item(item: Mapping[str, object]) -> frozenset[str]:
    values: set[str] = set()
    raw_capabilities = item.get("capabilities")
    if isinstance(raw_capabilities, Mapping):
        values.update(
            str(key)
            for key, enabled in raw_capabilities.items()
            if isinstance(key, str) and enabled is True and len(key) <= 128
        )
    for key in ("capabilities", "supported_generation_methods", "supported_actions"):
        raw = item.get(key)
        if isinstance(raw, Sequence) and not isinstance(raw, str | bytes):
            values.update(str(value) for value in raw if type(value) is str and value.strip())
    return frozenset(values)


def _modalities_from_model_item(item: Mapping[str, object]) -> frozenset[str]:
    raw_architecture = item.get("architecture")
    if isinstance(raw_architecture, Mapping):
        raw = raw_architecture.get("input_modalities")
        if isinstance(raw, Sequence) and not isinstance(raw, str | bytes):
            return frozenset(str(value) for value in raw if type(value) is str and value.strip())
    return frozenset()


@dataclass(frozen=True, slots=True)
class OpenAICompatibleConfiguration:
    """Safe custom endpoint configuration; executable hooks are impossible."""

    provider_id: str
    base_url: str
    model: str = ""
    locality: ProviderLocality = ProviderLocality.REMOTE
    organization: str | None = None
    project: str | None = None
    credential_ref: object | None = None
    models_path: str = "/models"
    chat_path: str = "/chat/completions"
    credential_header: str = "authorization"
    credential_prefix: str = "Bearer"
    extra_headers: tuple[tuple[str, str], ...] = ()
    page_limit: int = 1000

    def __post_init__(self) -> None:
        if (
            type(self.provider_id) is not str
            or type(self.model) is not str
            or not self.provider_id.strip()
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
        if not self.model.strip() and self.model != "":
            raise ValueError("OpenAI-compatible model is invalid")
        for path, name in ((self.models_path, "models path"), (self.chat_path, "chat path")):
            if (
                type(path) is not str
                or not path.startswith("/")
                or "\x00" in path
                or len(path) > 512
            ):
                raise ValueError(f"OpenAI-compatible {name} is invalid")
        for name, value in (
            ("credential header", self.credential_header),
            ("credential prefix", self.credential_prefix),
        ):
            if (
                type(value) is not str
                or (name == "credential header" and not value.strip())
                or len(value) > 128
                or "\x00" in value
            ):
                raise ValueError(f"OpenAI-compatible {name} is invalid")
        if type(self.extra_headers) is not tuple or any(
            type(key) is not str
            or type(value) is not str
            or not key.strip()
            or "\x00" in key + value
            for key, value in self.extra_headers
        ):
            raise ValueError("OpenAI-compatible headers are invalid")
        if type(self.page_limit) is not int or not 1 <= self.page_limit <= 1_000:
            raise ValueError("OpenAI-compatible page limit is invalid")
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
            raw = secret.decode() if isinstance(secret, bytes) else secret
            if not raw or len(raw) > 16_384 or any(ord(char) < 32 for char in raw):
                raise PermissionError("Credential material is invalid")
            headers[self.configuration.credential_header] = (
                f"{self.configuration.credential_prefix} {raw}".strip()
            )
        if self.configuration.organization:
            headers["openai-organization"] = self.configuration.organization
        if self.configuration.project:
            headers["openai-project"] = self.configuration.project
        headers.update(dict(self.configuration.extra_headers))
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
            "POST", self.configuration.chat_path, payload, await self._headers()
        )
        try:
            choices = response["choices"]
            content = choices[0]["message"]["content"]  # type: ignore[index]
            model = str(response.get("model", request.model))
        except (KeyError, IndexError, TypeError) as error:
            raise ProviderAdapterError(
                ProviderErrorReason.MALFORMED_RESPONSE,
                detail="OpenAI-compatible response is malformed",
            ) from error
        if type(content) is not str or len(content) > 1_000_000:
            raise ProviderAdapterError(
                ProviderErrorReason.MALFORMED_RESPONSE,
                detail="OpenAI-compatible response content is invalid",
            )
        return GenerationResult(content, model)

    async def stream(self, request: GenerationRequest) -> AsyncIterator[GenerationChunk]:
        result = await self.generate(request)
        yield GenerationChunk(result.content, True)

    async def health_check(self) -> ProviderHealth:
        try:
            await self._transport.request(
                "GET", self.configuration.models_path, None, await self._headers()
            )
        except ProviderAdapterError as error:
            return ProviderHealth(False, error.reason.value)
        except Exception:
            return ProviderHealth(False, ProviderErrorReason.UNKNOWN.value)
        return ProviderHealth(True, "model endpoint reachable")

    async def model_info(self) -> ModelInfo:
        return ModelInfo(self.configuration.provider_id, self.configuration.model or "unknown", 1)

    async def discover_models(self) -> ProviderCatalogSnapshot:
        response = await self._transport.request(
            "GET", self.configuration.models_path, None, await self._headers()
        )
        raw_models = response.get("data")
        if not isinstance(raw_models, list) or len(raw_models) > 1_024:
            raise ProviderAdapterError(
                ProviderErrorReason.MALFORMED_RESPONSE,
                detail="model list is malformed or oversized",
            )
        pages = [raw_models]
        next_cursor = response.get("next_cursor")
        if next_cursor is None and response.get("has_more") is True:
            next_cursor = response.get("last_id")
        while next_cursor is not None:
            if type(next_cursor) is not str or not next_cursor or len(next_cursor) > 256:
                raise ProviderAdapterError(
                    ProviderErrorReason.MALFORMED_RESPONSE,
                    detail="model pagination cursor is invalid",
                )
            page = await self._transport.request(
                "GET",
                f"{self.configuration.models_path}?after={quote(next_cursor, safe='')}",
                None,
                await self._headers(),
            )
            items = page.get("data")
            if not isinstance(items, list) or len(items) > self.configuration.page_limit:
                raise ProviderAdapterError(
                    ProviderErrorReason.MALFORMED_RESPONSE,
                    detail="model page is malformed or oversized",
                )
            pages.append(items)
            next_cursor = page.get("next_cursor")
            if next_cursor is None and page.get("has_more") is True:
                next_cursor = page.get("last_id")
            if sum(len(item) for item in pages) > 1_024:
                raise ProviderAdapterError(
                    ProviderErrorReason.MALFORMED_RESPONSE, detail="model inventory exceeds bound"
                )
        observations: list[ModelObservation] = []
        now = datetime.now(UTC)
        provider = ProviderMetadata(
            self.configuration.provider_id,
            self.configuration.provider_id,
            "discovery",
            locality=self.configuration.locality,
        )
        for item in (item for page in pages for item in page):
            if not isinstance(item, Mapping):
                raise ProviderAdapterError(
                    ProviderErrorReason.MALFORMED_RESPONSE, detail="model item is malformed"
                )
            model_id = item.get("id")
            if (
                type(model_id) is not str
                or not model_id.strip()
                or len(model_id) > 256
                or any(ord(char) < 32 for char in model_id)
            ):
                raise ProviderAdapterError(
                    ProviderErrorReason.MALFORMED_RESPONSE, detail="model ID is invalid"
                )
            context_limit = (
                _bounded_positive_int(item.get("context_length"))
                or _bounded_positive_int(item.get("max_context_length"))
                or 1
            )
            capabilities = _capabilities_from_model_item(item)
            roles = frozenset({ModelRole.GENERAL})
            if "embedding" in capabilities:
                roles = frozenset({ModelRole.EMBEDDING})
            from jarvis.ai.providers.registry import ModelMetadata

            metadata = ModelMetadata(
                model_id,
                context_limit,
                capabilities=capabilities,
                roles=roles,
                modalities=_modalities_from_model_item(item),
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

    async def aclose(self) -> None:
        close = getattr(self._transport, "aclose", None)
        if callable(close):
            result = close()
            if hasattr(result, "__await__"):
                await result
        await super().aclose()


class AI21Provider(OpenAICompatibleProvider):
    """AI21 Jamba package using its documented OpenAI-shaped chat route.

    AI21's public Studio surface does not expose the same dynamic model-list
    contract as the providers above.  The package therefore requires a model
    selection and projects that configured route without inventing discovery.
    """

    async def health_check(self) -> ProviderHealth:
        if not self.configuration.model:
            return ProviderHealth(False, "configured model is required")
        return ProviderHealth(True, "configured model route available")

    async def discover_models(self) -> ProviderCatalogSnapshot:
        model_id = self.configuration.model
        if not model_id:
            raise ProviderAdapterError(
                ProviderErrorReason.MALFORMED_RESPONSE,
                detail="AI21 requires a configured model because dynamic listing is unavailable",
            )
        now = datetime.now(UTC)
        metadata = ModelMetadata(
            model_id,
            1,
            roles=frozenset({ModelRole.GENERAL}),
            source="configured_model",
            endpoint=self.configuration.base_url,
            inference_kind=IntelligenceKind.GENERATIVE.value,
        )
        provider = ProviderMetadata(
            "ai21", "AI21", "standard", locality=self.configuration.locality
        )
        return ProviderCatalogSnapshot(
            provider,
            (ModelObservation(identity_for("ai21", metadata), metadata, now, "configured_model"),),
            now,
            "configured_model",
            False,
        )


@dataclass(frozen=True, slots=True)
class CohereConfiguration:
    provider_id: str = "cohere"
    base_url: str = "https://api.cohere.com"
    model: str = ""
    credential_ref: object | None = None
    page_limit: int = 100


class CohereProvider(AIProvider):
    """Cohere v2 Chat package with bounded v1 model discovery."""

    def __init__(
        self,
        configuration: CohereConfiguration,
        transport: OpenAICompatibleTransport,
        *,
        credential_resolver: CredentialResolver | None = None,
    ) -> None:
        self.configuration = configuration
        self._transport = transport
        self._credential_resolver = credential_resolver

    async def _headers(self) -> dict[str, str]:
        headers = {"accept": "application/json", "content-type": "application/json"}
        ref = self.configuration.credential_ref
        if ref is not None:
            if self._credential_resolver is None:
                raise PermissionError("Credential resolver is required")
            secret = await self._credential_resolver(ref)
            raw = secret.decode() if isinstance(secret, bytes) else secret
            if not raw or len(raw) > 16_384 or any(ord(char) < 32 for char in raw):
                raise PermissionError("Credential material is invalid")
            headers["authorization"] = f"Bearer {raw}"
        return headers

    async def generate(self, request: GenerationRequest) -> GenerationResult:
        payload = {
            "model": request.model,
            "messages": [
                {"role": message.role.value, "content": message.content}
                for message in request.messages
            ],
            "stream": False,
        }
        response = await self._transport.request("POST", "/v2/chat", payload, await self._headers())
        message = response.get("message")
        content = message.get("content") if isinstance(message, Mapping) else None
        if isinstance(content, str):
            text = content
        elif isinstance(content, list):
            text = "".join(
                str(item.get("text"))
                for item in content
                if isinstance(item, Mapping) and type(item.get("text")) is str
            )
        else:
            text = ""
        if not text or len(text) > 1_000_000:
            raise ProviderAdapterError(
                ProviderErrorReason.MALFORMED_RESPONSE,
                detail="Cohere response content is malformed",
            )
        return GenerationResult(text, str(response.get("model", request.model)))

    async def stream(self, request: GenerationRequest) -> AsyncIterator[GenerationChunk]:
        result = await self.generate(request)
        yield GenerationChunk(result.content, True)

    async def health_check(self) -> ProviderHealth:
        try:
            await self._transport.request(
                "GET", "/v1/models?page_size=1", None, await self._headers()
            )
        except ProviderAdapterError as error:
            return ProviderHealth(False, error.reason.value)
        except Exception:
            return ProviderHealth(False, ProviderErrorReason.UNKNOWN.value)
        return ProviderHealth(True, "model endpoint reachable")

    async def model_info(self) -> ModelInfo:
        return ModelInfo("cohere", self.configuration.model or "unknown", 1)

    async def discover_models(self) -> ProviderCatalogSnapshot:
        observations: list[ModelObservation] = []
        page_token: str | None = None
        now = datetime.now(UTC)
        for _ in range(10):
            path = "/v1/models?page_size=100"
            if page_token:
                path += f"&page_token={quote(page_token, safe='')}"
            response = await self._transport.request("GET", path, None, await self._headers())
            raw_models = response.get("models")
            if not isinstance(raw_models, list) or len(raw_models) > self.configuration.page_limit:
                raise ProviderAdapterError(
                    ProviderErrorReason.MALFORMED_RESPONSE,
                    detail="Cohere model list is malformed",
                )
            for item in raw_models:
                if not isinstance(item, Mapping) or type(item.get("name")) is not str:
                    raise ProviderAdapterError(
                        ProviderErrorReason.MALFORMED_RESPONSE,
                        detail="Cohere model item is malformed",
                    )
                model_id = str(item["name"])
                metadata = ModelMetadata(
                    model_id,
                    _bounded_positive_int(item.get("context_length")) or 1,
                    capabilities=_capabilities_from_model_item(item),
                    roles=frozenset({ModelRole.GENERAL}),
                    source="provider_discovery",
                    endpoint=self.configuration.base_url,
                    inference_kind=IntelligenceKind.GENERATIVE.value,
                )
                observations.append(
                    ModelObservation(
                        identity_for("cohere", metadata), metadata, now, "provider_discovery"
                    )
                )
            raw_next = response.get("next_page_token")
            if raw_next is None:
                break
            if type(raw_next) is not str or not raw_next or len(raw_next) > 512:
                raise ProviderAdapterError(
                    ProviderErrorReason.MALFORMED_RESPONSE,
                    detail="Cohere pagination is malformed",
                )
            page_token = raw_next
        else:
            raise ProviderAdapterError(
                ProviderErrorReason.MALFORMED_RESPONSE,
                detail="Cohere pagination exceeds bound",
            )
        provider = ProviderMetadata(
            "cohere", "Cohere", "standard", locality=ProviderLocality.REMOTE
        )
        return ProviderCatalogSnapshot(
            provider, tuple(observations), now, "provider_discovery", True
        )

    async def aclose(self) -> None:
        close = getattr(self._transport, "aclose", None)
        if callable(close):
            result = close()
            if hasattr(result, "__await__"):
                await result
        await super().aclose()


CredentialResolver = Callable[[object], Awaitable[str | bytes]]


@dataclass(frozen=True, slots=True)
class StandardOpenAIPreset:
    """Fixed, reviewed defaults for one named OpenAI-compatible package."""

    provider_id: str
    base_url: str
    help_url: str
    credential_header: str = "authorization"
    credential_prefix: str = "Bearer"
    models_path: str = "/models"
    chat_path: str = "/chat/completions"
    extra_headers: tuple[tuple[str, str], ...] = ()


STANDARD_OPENAI_PRESETS: dict[str, StandardOpenAIPreset] = {
    "openai": StandardOpenAIPreset(
        "openai", "https://api.openai.com/v1", "https://platform.openai.com/docs"
    ),
    "xai-grok": StandardOpenAIPreset("xai-grok", "https://api.x.ai/v1", "https://docs.x.ai"),
    "mistral": StandardOpenAIPreset(
        "mistral", "https://api.mistral.ai/v1", "https://docs.mistral.ai"
    ),
    "deepseek": StandardOpenAIPreset(
        "deepseek", "https://api.deepseek.com", "https://api-docs.deepseek.com"
    ),
    "openrouter": StandardOpenAIPreset(
        "openrouter", "https://openrouter.ai/api/v1", "https://openrouter.ai/docs"
    ),
    "groqcloud": StandardOpenAIPreset(
        "groqcloud", "https://api.groq.com/openai/v1", "https://console.groq.com/docs"
    ),
    "together-ai": StandardOpenAIPreset(
        "together-ai", "https://api.together.xyz/v1", "https://docs.together.ai"
    ),
    "fireworks-ai": StandardOpenAIPreset(
        "fireworks-ai", "https://api.fireworks.ai/inference/v1", "https://docs.fireworks.ai"
    ),
    "cerebras-cloud": StandardOpenAIPreset(
        "cerebras-cloud", "https://api.cerebras.ai/v1", "https://inference-docs.cerebras.ai"
    ),
    "sambanova-cloud": StandardOpenAIPreset(
        "sambanova-cloud", "https://api.sambanova.ai/v1", "https://docs.sambanova.ai"
    ),
    "nvidia-nim": StandardOpenAIPreset(
        "nvidia-nim", "https://integrate.api.nvidia.com/v1", "https://docs.api.nvidia.com/nim"
    ),
    "perplexity": StandardOpenAIPreset(
        "perplexity", "https://api.perplexity.ai", "https://docs.perplexity.ai"
    ),
    "alibaba-dashscope": StandardOpenAIPreset(
        "alibaba-dashscope",
        "https://dashscope.aliyuncs.com/compatible-mode/v1",
        "https://www.alibabacloud.com/help/en/model-studio/compatibility-of-openai-with-dashscope",
    ),
    "moonshot-kimi": StandardOpenAIPreset(
        "moonshot-kimi", "https://api.moonshot.cn/v1", "https://platform.moonshot.cn/docs/api"
    ),
    "zhipu-glm": StandardOpenAIPreset(
        "zhipu-glm", "https://open.bigmodel.cn/api/paas/v4", "https://open.bigmodel.cn/dev/api"
    ),
    "baidu-qianfan": StandardOpenAIPreset(
        "baidu-qianfan",
        "https://qianfan.baidubce.com/v2",
        "https://cloud.baidu.com/doc/qianfan-api/s/Dmba8k71y",
    ),
    "tencent-hunyuan": StandardOpenAIPreset(
        "tencent-hunyuan",
        "https://api.hunyuan.cloud.tencent.com/v1",
        "https://cloud.tencent.com/document/product/1729/111007",
    ),
    "bytedance-volcengine": StandardOpenAIPreset(
        "bytedance-volcengine",
        "https://ark.cn-beijing.volces.com/api/v3",
        "https://docs.volcengine.com/docs/ark/chat-api",
    ),
}


def _credential_ref(configuration: Mapping[str, object]) -> object | None:
    if any(
        key in configuration
        for key in (
            "api_key",
            "api_token",
            "secret",
            "credential",
            "access_key_id",
            "secret_access_key",
            "session_token",
            "service_account",
        )
    ):
        raise PermissionError("Raw provider credentials must be stored in CredentialVault")
    return configuration.get("credential_ref")


def _transport_for(
    base_url: str,
    configuration: Mapping[str, object],
    transport: OpenAICompatibleTransport | None,
) -> OpenAICompatibleTransport:
    if transport is not None:
        return transport
    timeout = configuration.get("timeout_seconds", 15.0)
    if type(timeout) not in {int, float}:
        raise ValueError("Provider timeout is invalid")
    locality = configuration.get("locality", ProviderLocality.REMOTE)
    if not isinstance(locality, ProviderLocality):
        raise ValueError("Provider locality is invalid")
    return HttpxJSONTransport(
        base_url,
        timeout_seconds=float(cast(float, timeout)),
        allow_http_loopback=locality is ProviderLocality.LOCAL,
    )


def _standard_openai_provider(
    provider_id: str,
    configuration: Mapping[str, object],
    *,
    transport: OpenAICompatibleTransport | None,
    credential_resolver: CredentialResolver | None,
) -> OpenAICompatibleProvider:
    preset = STANDARD_OPENAI_PRESETS[provider_id]
    model = configuration.get("model", "")
    if type(model) is not str:
        raise ValueError("Provider model is invalid")
    provider = OpenAICompatibleProvider(
        OpenAICompatibleConfiguration(
            provider_id,
            preset.base_url,
            model,
            credential_ref=_credential_ref(configuration),
            models_path=preset.models_path,
            chat_path=preset.chat_path,
            credential_header=preset.credential_header,
            credential_prefix=preset.credential_prefix,
            extra_headers=preset.extra_headers,
        ),
        _transport_for(preset.base_url, configuration, transport),
        credential_resolver=credential_resolver,
    )
    return provider


@dataclass(frozen=True, slots=True)
class AnthropicConfiguration:
    provider_id: str = "anthropic"
    base_url: str = "https://api.anthropic.com"
    model: str = ""
    credential_ref: object | None = None
    api_version: str = "2023-06-01"
    page_limit: int = 100


class AnthropicTransport(Protocol):
    async def request(
        self,
        method: str,
        path: str,
        payload: Mapping[str, object] | None,
        headers: Mapping[str, str],
    ) -> Mapping[str, object]: ...


class AnthropicProvider(AIProvider):
    """Typed Anthropic Messages family adapter."""

    def __init__(
        self,
        configuration: AnthropicConfiguration,
        transport: AnthropicTransport,
        *,
        credential_resolver: CredentialResolver | None = None,
    ) -> None:
        self.configuration = configuration
        self._transport = transport
        self._credential_resolver = credential_resolver

    async def _headers(self) -> dict[str, str]:
        headers = {
            "accept": "application/json",
            "content-type": "application/json",
            "anthropic-version": self.configuration.api_version,
        }
        if self.configuration.credential_ref is not None:
            if self._credential_resolver is None:
                raise PermissionError("Credential resolver is required")
            secret = await self._credential_resolver(self.configuration.credential_ref)
            raw = secret.decode() if isinstance(secret, bytes) else secret
            if not raw or len(raw) > 16_384 or any(ord(char) < 32 for char in raw):
                raise PermissionError("Credential material is invalid")
            headers["x-api-key"] = raw
        return headers

    @property
    def intelligence_kinds(self) -> frozenset[str]:
        return frozenset({IntelligenceKind.GENERATIVE.value})

    async def generate(self, request: GenerationRequest) -> GenerationResult:
        system = "\n\n".join(
            message.content for message in request.messages if message.role.value == "system"
        )
        messages = [
            {"role": message.role.value, "content": message.content}
            for message in request.messages
            if message.role.value != "system"
        ]
        payload: dict[str, object] = {
            "model": request.model,
            "max_tokens": max(1, min(request.context_limit, 16_384)),
            "messages": messages,
        }
        if system:
            payload["system"] = system
        response = await self._transport.request(
            "POST", "/v1/messages", payload, await self._headers()
        )
        content = response.get("content")
        if not isinstance(content, list):
            raise ProviderAdapterError(
                ProviderErrorReason.MALFORMED_RESPONSE, detail="Anthropic content is malformed"
            )
        text = "".join(
            str(item.get("text"))
            for item in content
            if isinstance(item, Mapping)
            and item.get("type") == "text"
            and type(item.get("text")) is str
        )
        if not text:
            raise ProviderAdapterError(
                ProviderErrorReason.MALFORMED_RESPONSE, detail="Anthropic text is missing"
            )
        return GenerationResult(text, str(response.get("model", request.model)))

    async def stream(self, request: GenerationRequest) -> AsyncIterator[GenerationChunk]:
        result = await self.generate(request)
        yield GenerationChunk(result.content, True)

    async def health_check(self) -> ProviderHealth:
        try:
            await self._transport.request("GET", "/v1/models", None, await self._headers())
        except ProviderAdapterError as error:
            return ProviderHealth(False, error.reason.value)
        except Exception:
            return ProviderHealth(False, ProviderErrorReason.UNKNOWN.value)
        return ProviderHealth(True, "model endpoint reachable")

    async def model_info(self) -> ModelInfo:
        return ModelInfo("anthropic", self.configuration.model or "unknown", 1)

    async def discover_models(self) -> ProviderCatalogSnapshot:
        observations: list[ModelObservation] = []
        path = "/v1/models"
        pages = 0
        now = datetime.now(UTC)
        while True:
            response = await self._transport.request("GET", path, None, await self._headers())
            raw_models = response.get("data")
            if not isinstance(raw_models, list) or len(raw_models) > self.configuration.page_limit:
                raise ProviderAdapterError(
                    ProviderErrorReason.MALFORMED_RESPONSE,
                    detail="Anthropic model list is malformed",
                )
            for item in raw_models:
                if (
                    not isinstance(item, Mapping)
                    or type(item.get("id")) is not str
                    or not str(item["id"]).strip()
                ):
                    raise ProviderAdapterError(
                        ProviderErrorReason.MALFORMED_RESPONSE,
                        detail="Anthropic model item is malformed",
                    )
                model_id = str(item["id"])
                metadata = ModelMetadata(
                    model_id,
                    _bounded_positive_int(item.get("max_input_tokens")) or 1,
                    roles=frozenset({ModelRole.GENERAL}),
                    source="provider_discovery",
                    endpoint=self.configuration.base_url,
                    inference_kind=IntelligenceKind.GENERATIVE.value,
                )
                observations.append(
                    ModelObservation(
                        identity_for("anthropic", metadata), metadata, now, "provider_discovery"
                    )
                )
            pages += 1
            if pages >= 10 or not response.get("has_more"):
                break
            last_id = response.get("last_id")
            if type(last_id) is not str or not last_id:
                raise ProviderAdapterError(
                    ProviderErrorReason.MALFORMED_RESPONSE,
                    detail="Anthropic pagination is malformed",
                )
            path = f"/v1/models?after_id={quote(last_id, safe='')}"
        provider = ProviderMetadata(
            "anthropic", "Anthropic", "standard", locality=ProviderLocality.REMOTE
        )
        return ProviderCatalogSnapshot(
            provider, tuple(observations), now, "provider_discovery", True
        )


@dataclass(frozen=True, slots=True)
class GeminiConfiguration:
    provider_id: str = "google-gemini"
    base_url: str = "https://generativelanguage.googleapis.com/v1beta"
    model: str = ""
    credential_ref: object | None = None
    credential_header: str = "x-goog-api-key"
    credential_prefix: str = ""
    page_limit: int = 50


class GeminiProvider(AIProvider):
    """Google Gemini generateContent and models.list family adapter."""

    def __init__(
        self,
        configuration: GeminiConfiguration,
        transport: AnthropicTransport,
        *,
        credential_resolver: CredentialResolver | None = None,
    ) -> None:
        self.configuration = configuration
        self._transport = transport
        self._credential_resolver = credential_resolver

    async def _headers(self) -> dict[str, str]:
        headers = {"accept": "application/json", "content-type": "application/json"}
        if self.configuration.credential_ref is not None:
            if self._credential_resolver is None:
                raise PermissionError("Credential resolver is required")
            secret = await self._credential_resolver(self.configuration.credential_ref)
            raw = secret.decode() if isinstance(secret, bytes) else secret
            if not raw or len(raw) > 16_384 or any(ord(char) < 32 for char in raw):
                raise PermissionError("Credential material is invalid")
            headers[self.configuration.credential_header] = (
                f"{self.configuration.credential_prefix} {raw}".strip()
            )
        return headers

    @property
    def intelligence_kinds(self) -> frozenset[str]:
        return frozenset({IntelligenceKind.GENERATIVE.value})

    async def generate(self, request: GenerationRequest) -> GenerationResult:
        contents = [
            {
                "role": "model" if message.role.value == "assistant" else "user",
                "parts": [{"text": message.content}],
            }
            for message in request.messages
            if message.role.value != "system"
        ]
        payload: dict[str, object] = {"contents": contents}
        system = [message.content for message in request.messages if message.role.value == "system"]
        if system:
            payload["systemInstruction"] = {"parts": [{"text": "\n\n".join(system)}]}
        response = await self._transport.request(
            "POST",
            f"/models/{quote(request.model, safe='')}:generateContent",
            payload,
            await self._headers(),
        )
        candidates = response.get("candidates")
        if (
            not isinstance(candidates, list)
            or not candidates
            or not isinstance(candidates[0], Mapping)
        ):
            raise ProviderAdapterError(
                ProviderErrorReason.MALFORMED_RESPONSE, detail="Gemini candidates are malformed"
            )
        content = candidates[0].get("content")
        parts = content.get("parts") if isinstance(content, Mapping) else None
        text = "".join(
            str(part.get("text"))
            for part in parts or ()
            if isinstance(part, Mapping) and type(part.get("text")) is str
        )
        if not text:
            raise ProviderAdapterError(
                ProviderErrorReason.MALFORMED_RESPONSE, detail="Gemini text is missing"
            )
        return GenerationResult(text, request.model)

    async def stream(self, request: GenerationRequest) -> AsyncIterator[GenerationChunk]:
        result = await self.generate(request)
        yield GenerationChunk(result.content, True)

    async def health_check(self) -> ProviderHealth:
        try:
            await self._transport.request("GET", "/models", None, await self._headers())
        except ProviderAdapterError as error:
            return ProviderHealth(False, error.reason.value)
        except Exception:
            return ProviderHealth(False, ProviderErrorReason.UNKNOWN.value)
        return ProviderHealth(True, "model endpoint reachable")

    async def model_info(self) -> ModelInfo:
        return ModelInfo(self.configuration.provider_id, self.configuration.model or "unknown", 1)

    async def discover_models(self) -> ProviderCatalogSnapshot:
        observations: list[ModelObservation] = []
        path = "/models"
        pages = 0
        now = datetime.now(UTC)
        while True:
            response = await self._transport.request("GET", path, None, await self._headers())
            raw_models = response.get("models")
            if not isinstance(raw_models, list) or len(raw_models) > self.configuration.page_limit:
                raise ProviderAdapterError(
                    ProviderErrorReason.MALFORMED_RESPONSE, detail="Gemini model list is malformed"
                )
            for item in raw_models:
                if not isinstance(item, Mapping) or type(item.get("name")) is not str:
                    raise ProviderAdapterError(
                        ProviderErrorReason.MALFORMED_RESPONSE,
                        detail="Gemini model item is malformed",
                    )
                raw_name = str(item["name"])
                model_id = str(item.get("baseModelId") or raw_name.removeprefix("models/"))
                methods = item.get("supportedGenerationMethods")
                capabilities = (
                    frozenset(str(value) for value in methods if type(value) is str)
                    if isinstance(methods, list)
                    else frozenset()
                )
                metadata = ModelMetadata(
                    model_id,
                    _bounded_positive_int(item.get("inputTokenLimit")) or 1,
                    capabilities=capabilities,
                    roles=frozenset({ModelRole.GENERAL}),
                    modalities=frozenset({"text"}),
                    source="provider_discovery",
                    endpoint=self.configuration.base_url,
                    inference_kind=IntelligenceKind.GENERATIVE.value,
                )
                observations.append(
                    ModelObservation(
                        identity_for(self.configuration.provider_id, metadata),
                        metadata,
                        now,
                        "provider_discovery",
                    )
                )
            pages += 1
            token = response.get("nextPageToken")
            if pages >= 10 or not token:
                break
            if type(token) is not str or len(token) > 512:
                raise ProviderAdapterError(
                    ProviderErrorReason.MALFORMED_RESPONSE, detail="Gemini pagination is malformed"
                )
            path = f"/models?pageToken={quote(token, safe='')}"
        provider = ProviderMetadata(
            self.configuration.provider_id,
            "Google Gemini",
            "standard",
            locality=ProviderLocality.REMOTE,
        )
        return ProviderCatalogSnapshot(
            provider, tuple(observations), now, "provider_discovery", True
        )


@dataclass(frozen=True, slots=True)
class AzureOpenAIConfiguration:
    endpoint: str
    deployment: str
    api_version: str = "2024-10-21"
    model: str = ""
    credential_ref: object | None = None


class AzureOpenAIProvider(OpenAICompatibleProvider):
    """Azure deployment-aware OpenAI family package."""

    def __init__(
        self,
        configuration: AzureOpenAIConfiguration,
        transport: OpenAICompatibleTransport,
        *,
        credential_resolver: CredentialResolver | None = None,
    ) -> None:
        endpoint = configuration.endpoint.rstrip("/")
        super().__init__(
            OpenAICompatibleConfiguration(
                "azure-openai",
                endpoint,
                configuration.model,
                credential_ref=configuration.credential_ref,
                models_path=(
                    f"/openai/models?api-version={quote(configuration.api_version, safe='')}"
                ),
                chat_path=(
                    f"/openai/deployments/{quote(configuration.deployment, safe='')}"
                    f"/chat/completions?api-version={quote(configuration.api_version, safe='')}"
                ),
                credential_header="api-key",
                credential_prefix="",
            ),
            transport,
            credential_resolver=credential_resolver,
        )


@dataclass(frozen=True, slots=True)
class VertexAIConfiguration:
    project: str
    region: str
    model: str = ""
    credential_ref: object | None = None


class VertexAIProvider(GeminiProvider):
    """Vertex publisher-model package using OAuth bearer credentials."""

    def __init__(
        self,
        configuration: VertexAIConfiguration,
        transport: AnthropicTransport,
        *,
        token_resolver: CredentialResolver | None = None,
    ) -> None:
        base_url = (
            f"https://{configuration.region}-aiplatform.googleapis.com/v1/"
            f"projects/{quote(configuration.project, safe='')}/"
            f"locations/{quote(configuration.region, safe='')}"
            "/publishers/google"
        )
        super().__init__(
            GeminiConfiguration(
                provider_id="google-vertex",
                base_url=base_url,
                model=configuration.model,
                credential_ref=configuration.credential_ref,
                credential_header="authorization",
                credential_prefix="Bearer",
            ),
            transport,
            credential_resolver=None,
        )
        self._token_resolver = token_resolver

    async def _headers(self) -> dict[str, str]:
        headers = {"accept": "application/json", "content-type": "application/json"}
        ref = self.configuration.credential_ref
        if ref is not None:
            if self._token_resolver is None:
                raise PermissionError("Vertex OAuth token resolver is required")
            token = await self._token_resolver(ref)
            raw = token.decode() if isinstance(token, bytes) else token
            if not raw or len(raw) > 16_384 or any(ord(char) < 32 for char in raw):
                raise PermissionError("Vertex OAuth token is invalid")
            headers["authorization"] = f"Bearer {raw}"
        return headers


class BedrockSigner(Protocol):
    """Trusted SigV4 seam; raw AWS keys never enter provider metadata."""

    def sign(
        self, method: str, path: str, payload: Mapping[str, object] | None
    ) -> Mapping[str, str]: ...


@dataclass(frozen=True, slots=True)
class AwsSigV4Credentials:
    """Vault-resolved AWS signing material kept out of provider metadata."""

    access_key_id: str
    secret_access_key: str = field(repr=False)
    session_token: str | None = field(default=None, repr=False)


class AwsSigV4Signer:
    """Concrete AWS Signature Version 4 signer for Bedrock runtime calls."""

    def __init__(
        self,
        region: str,
        host: str,
        credentials: AwsSigV4Credentials,
        *,
        service: str = "bedrock-runtime",
        clock: Callable[[], datetime] | None = None,
    ) -> None:
        parsed_host = urlsplit(f"https://{host}")
        if (
            not region
            or not service
            or not parsed_host.hostname
            or parsed_host.path not in {"", "/"}
            or parsed_host.query
            or parsed_host.fragment
        ):
            raise ValueError("AWS SigV4 signer identity is invalid")
        if (
            not credentials.access_key_id
            or not credentials.secret_access_key
            or any(
                ord(char) < 32 for char in credentials.access_key_id + credentials.secret_access_key
            )
            or credentials.session_token is not None
            and any(ord(char) < 32 for char in credentials.session_token)
        ):
            raise ValueError("AWS signing credentials are invalid")
        self._region = region
        self._host = parsed_host.hostname
        self._service = service
        self._credentials = credentials
        self._clock = clock or (lambda: datetime.now(UTC))

    def sign(
        self, method: str, path: str, payload: Mapping[str, object] | None
    ) -> Mapping[str, str]:
        parsed = urlsplit(path)
        if (
            not method
            or not parsed.path.startswith("/")
            or parsed.fragment
            or any(ord(char) < 32 for char in path)
        ):
            raise ValueError("AWS signing request path is invalid")
        now = self._clock()
        if now.tzinfo is None:
            raise ValueError("AWS signing clock must be timezone-aware")
        now = now.astimezone(UTC)
        amz_date = now.strftime("%Y%m%dT%H%M%SZ")
        date_stamp = now.strftime("%Y%m%d")
        body = _json_payload_bytes(payload) if payload is not None else b""
        payload_hash = hashlib.sha256(body).hexdigest()
        canonical_uri = quote(unquote(parsed.path), safe="/-_.~%")
        canonical_query = "&".join(
            f"{quote(key, safe='-_.~')}={quote(value, safe='-_.~')}"
            for key, value in sorted(
                (part.split("=", 1) + [""])[:2] for part in parsed.query.split("&") if part
            )
        )
        headers = {
            "accept": "application/json",
            "content-type": "application/json",
            "host": self._host,
            "x-amz-content-sha256": payload_hash,
            "x-amz-date": amz_date,
        }
        if self._credentials.session_token:
            headers["x-amz-security-token"] = self._credentials.session_token
        canonical_headers = "".join(
            f"{key}:{' '.join(value.strip().split())}\n" for key, value in sorted(headers.items())
        )
        signed_headers = ";".join(sorted(headers))
        canonical_request = "\n".join(
            (
                method.upper(),
                canonical_uri,
                canonical_query,
                canonical_headers,
                signed_headers,
                payload_hash,
            )
        )
        scope = f"{date_stamp}/{self._region}/{self._service}/aws4_request"
        string_to_sign = "\n".join(
            (
                "AWS4-HMAC-SHA256",
                amz_date,
                scope,
                hashlib.sha256(canonical_request.encode()).hexdigest(),
            )
        )
        date_key = hmac.new(
            ("AWS4" + self._credentials.secret_access_key).encode(),
            date_stamp.encode(),
            hashlib.sha256,
        ).digest()
        region_key = hmac.new(date_key, self._region.encode(), hashlib.sha256).digest()
        service_key = hmac.new(region_key, self._service.encode(), hashlib.sha256).digest()
        signing_key = hmac.new(service_key, b"aws4_request", hashlib.sha256).digest()
        signature = hmac.new(signing_key, string_to_sign.encode(), hashlib.sha256).hexdigest()
        headers["authorization"] = (
            f"AWS4-HMAC-SHA256 Credential={self._credentials.access_key_id}/{scope}, "
            f"SignedHeaders={signed_headers}, Signature={signature}"
        )
        return headers


@dataclass(frozen=True, slots=True)
class BedrockConfiguration:
    region: str
    model: str = ""
    credential_ref: object | None = None
    endpoint: str | None = None


class BedrockProvider(AIProvider):
    """Amazon Bedrock Converse adapter with an injected trusted SigV4 signer."""

    def __init__(
        self,
        configuration: BedrockConfiguration,
        transport: AnthropicTransport,
        signer: BedrockSigner | None,
    ) -> None:
        self.configuration = configuration
        self._transport = transport
        self._signer = signer

    @property
    def intelligence_kinds(self) -> frozenset[str]:
        return frozenset({IntelligenceKind.GENERATIVE.value})

    def _headers(
        self, method: str, path: str, payload: Mapping[str, object] | None
    ) -> Mapping[str, str]:
        if self._signer is None:
            raise PermissionError("Bedrock requires the trusted SigV4 signer seam")
        headers = self._signer.sign(method, path, payload)
        if (
            any(type(key) is not str or type(value) is not str for key, value in headers.items())
            or not headers.get("authorization", "").startswith("AWS4-HMAC-SHA256 ")
            or not headers.get("x-amz-date")
            or not headers.get("host")
        ):
            raise PermissionError("Bedrock signer did not provide SigV4 authorization")
        return headers

    async def generate(self, request: GenerationRequest) -> GenerationResult:
        payload = {
            "messages": [
                {
                    "role": "assistant" if message.role.value == "assistant" else "user",
                    "content": [{"text": message.content}],
                }
                for message in request.messages
                if message.role.value != "system"
            ]
        }
        path = f"/model/{quote(request.model, safe='')}/converse"
        response = await self._transport.request(
            "POST", path, payload, self._headers("POST", path, payload)
        )
        output = response.get("output")
        message = output.get("message") if isinstance(output, Mapping) else None
        content = message.get("content") if isinstance(message, Mapping) else None
        text = "".join(
            str(item.get("text"))
            for item in content or ()
            if isinstance(item, Mapping) and type(item.get("text")) is str
        )
        if not text:
            raise ProviderAdapterError(
                ProviderErrorReason.MALFORMED_RESPONSE, detail="Bedrock response is malformed"
            )
        return GenerationResult(text, request.model)

    async def stream(self, request: GenerationRequest) -> AsyncIterator[GenerationChunk]:
        result = await self.generate(request)
        yield GenerationChunk(result.content, True)

    async def health_check(self) -> ProviderHealth:
        try:
            await self._transport.request(
                "GET", "/foundation-models", None, self._headers("GET", "/foundation-models", None)
            )
        except ProviderAdapterError as error:
            return ProviderHealth(False, error.reason.value)
        except Exception:
            return ProviderHealth(False, ProviderErrorReason.UNKNOWN.value)
        return ProviderHealth(True, "model endpoint reachable")

    async def model_info(self) -> ModelInfo:
        return ModelInfo("amazon-bedrock", self.configuration.model or "unknown", 1)

    async def discover_models(self) -> ProviderCatalogSnapshot:
        path = "/foundation-models"
        response = await self._transport.request(
            "GET", path, None, self._headers("GET", path, None)
        )
        raw_models = response.get("modelSummaries")
        if not isinstance(raw_models, list) or len(raw_models) > 1_024:
            raise ProviderAdapterError(
                ProviderErrorReason.MALFORMED_RESPONSE, detail="Bedrock model list is malformed"
            )
        now = datetime.now(UTC)
        observations: list[ModelObservation] = []
        for item in raw_models:
            if not isinstance(item, Mapping) or type(item.get("modelId")) is not str:
                raise ProviderAdapterError(
                    ProviderErrorReason.MALFORMED_RESPONSE, detail="Bedrock model item is malformed"
                )
            model_id = str(item["modelId"])
            metadata = ModelMetadata(
                model_id,
                1,
                roles=frozenset({ModelRole.GENERAL}),
                source="provider_discovery",
                endpoint=self.configuration.endpoint
                or f"https://bedrock-runtime.{self.configuration.region}.amazonaws.com",
                region=self.configuration.region,
                inference_kind=IntelligenceKind.GENERATIVE.value,
            )
            observations.append(
                ModelObservation(
                    identity_for("amazon-bedrock", metadata), metadata, now, "provider_discovery"
                )
            )
        provider = ProviderMetadata(
            "amazon-bedrock", "Amazon Bedrock", "standard", locality=ProviderLocality.REMOTE
        )
        return ProviderCatalogSnapshot(
            provider, tuple(observations), now, "provider_discovery", True
        )


def create_standard_provider(
    provider_id: str,
    configuration: Mapping[str, object],
    *,
    transport: OpenAICompatibleTransport | None = None,
    credential_resolver: CredentialResolver | None = None,
    token_resolver: CredentialResolver | None = None,
    signer: BedrockSigner | None = None,
) -> AIProvider:
    """Resolve a named standard package through typed, reviewed factories."""

    if transport is None:
        raw_transport = configuration.get("transport")
        if callable(getattr(raw_transport, "request", None)):
            transport = cast(OpenAICompatibleTransport, raw_transport)
    if credential_resolver is None:
        raw_resolver = configuration.get("credential_resolver")
        if callable(raw_resolver):
            credential_resolver = cast(CredentialResolver, raw_resolver)
    if token_resolver is None:
        raw_token_resolver = configuration.get("token_resolver")
        if callable(raw_token_resolver):
            token_resolver = cast(CredentialResolver, raw_token_resolver)
    if signer is None:
        raw_signer = configuration.get("signer")
        if hasattr(raw_signer, "sign"):
            signer = cast(BedrockSigner, raw_signer)

    manifest = provider_manifest(provider_id)
    if manifest.support_status is not PackageSupportStatus.CONTROLLED_PROTOCOL_TESTED:
        raise ValueError(f"Provider package is not source-executable: {manifest.provider_id}")
    key = manifest.provider_id
    if key in STANDARD_OPENAI_PRESETS:
        return _standard_openai_provider(
            key, configuration, transport=transport, credential_resolver=credential_resolver
        )
    if key == "ai21":
        model = configuration.get("model", "")
        if type(model) is not str:
            raise ValueError("AI21 model is invalid")
        base_url = "https://api.ai21.com/studio/v1"
        return AI21Provider(
            OpenAICompatibleConfiguration(
                key,
                base_url,
                model,
                credential_ref=_credential_ref(configuration),
                models_path="/models",
                chat_path="/chat/completions",
            ),
            _transport_for(base_url, configuration, transport),
            credential_resolver=credential_resolver,
        )
    if key == "cohere":
        model = configuration.get("model", "")
        if type(model) is not str:
            raise ValueError("Cohere model is invalid")
        base_url = "https://api.cohere.com"
        return CohereProvider(
            CohereConfiguration(model=model, credential_ref=_credential_ref(configuration)),
            _transport_for(base_url, configuration, transport),
            credential_resolver=credential_resolver,
        )
    if key == "openai-compatible":
        generic_base_url: object = configuration.get("base_url")
        if type(generic_base_url) is not str:
            raise ValueError("OpenAI-compatible providers require an explicit base URL")
        generic_model: object = configuration.get("model", "")
        locality = configuration.get("locality", ProviderLocality.REMOTE)
        if not isinstance(locality, ProviderLocality):
            raise ValueError("OpenAI-compatible locality is invalid")
        return OpenAICompatibleProvider(
            OpenAICompatibleConfiguration(
                key,
                generic_base_url,
                str(generic_model),
                locality,
                credential_ref=_credential_ref(configuration),
            ),
            _transport_for(generic_base_url, configuration, transport),
            credential_resolver=credential_resolver,
        )
    if key == "anthropic":
        model = configuration.get("model", "")
        if type(model) is not str:
            raise ValueError("Anthropic model is invalid")
        base_url = "https://api.anthropic.com"
        return AnthropicProvider(
            AnthropicConfiguration(model=model, credential_ref=_credential_ref(configuration)),
            _transport_for(base_url, configuration, transport),
            credential_resolver=credential_resolver,
        )
    if key == "google-gemini":
        model = configuration.get("model", "")
        if type(model) is not str:
            raise ValueError("Gemini model is invalid")
        base_url = "https://generativelanguage.googleapis.com/v1beta"
        return GeminiProvider(
            GeminiConfiguration(model=model, credential_ref=_credential_ref(configuration)),
            _transport_for(base_url, configuration, transport),
            credential_resolver=credential_resolver,
        )
    if key == "azure-openai":
        endpoint = configuration.get("endpoint")
        deployment = configuration.get("deployment")
        api_version = configuration.get("api_version", "2024-10-21")
        if type(endpoint) is not str or type(deployment) is not str or type(api_version) is not str:
            raise ValueError("Azure OpenAI configuration is invalid")
        return AzureOpenAIProvider(
            AzureOpenAIConfiguration(
                endpoint,
                deployment,
                api_version,
                str(configuration.get("model", "")),
                _credential_ref(configuration),
            ),
            _transport_for(endpoint.rstrip("/"), configuration, transport),
            credential_resolver=credential_resolver,
        )
    if key == "google-vertex":
        project = configuration.get("project")
        region = configuration.get("region")
        if type(project) is not str or type(region) is not str or not project or not region:
            raise ValueError("Vertex configuration is invalid")
        vertex = VertexAIConfiguration(
            project, region, str(configuration.get("model", "")), _credential_ref(configuration)
        )
        base_url = (
            f"https://{region}-aiplatform.googleapis.com/v1/projects/{quote(project, safe='')}/"
            f"locations/{quote(region, safe='')}/publishers/google"
        )
        return VertexAIProvider(
            vertex,
            _transport_for(base_url, configuration, transport),
            token_resolver=token_resolver,
        )
    if key == "amazon-bedrock":
        region = configuration.get("region")
        if type(region) is not str or not region.strip():
            raise ValueError("Bedrock region is required")
        endpoint = str(
            configuration.get("endpoint", f"https://bedrock-runtime.{region}.amazonaws.com")
        )
        provider = BedrockProvider(
            BedrockConfiguration(
                region,
                str(configuration.get("model", "")),
                _credential_ref(configuration),
                endpoint,
            ),
            _transport_for(endpoint, configuration, transport),
            signer,
        )
        return provider
    raise ValueError(f"No source adapter exists for {key}")


def register_standard_provider_factories(registry: object) -> None:
    """Install all source-executable package factories into one registry owner."""

    from jarvis.ai.providers.registry import ProviderRegistry

    if not isinstance(registry, ProviderRegistry):
        raise ValueError("Provider registry is invalid")
    for manifest in STANDARD_PROVIDER_MANIFESTS:
        if manifest.support_status is not PackageSupportStatus.CONTROLLED_PROTOCOL_TESTED:
            continue
        if manifest.provider_id in registry.intelligence_provider_ids():
            continue
        provider_id = manifest.provider_id

        def factory(
            configuration: Mapping[str, object],
            selected_provider_id: str = provider_id,
        ) -> IntelligenceProvider:
            raw_transport = configuration.get("transport")
            selected_transport = (
                cast(OpenAICompatibleTransport, raw_transport)
                if callable(getattr(raw_transport, "request", None))
                else None
            )
            raw_resolver = configuration.get("credential_resolver")
            selected_resolver = (
                cast(CredentialResolver, raw_resolver) if callable(raw_resolver) else None
            )
            raw_signer = configuration.get("signer")
            selected_signer = (
                cast(BedrockSigner, raw_signer) if hasattr(raw_signer, "sign") else None
            )
            return create_standard_provider(
                selected_provider_id,
                configuration,
                transport=selected_transport,
                credential_resolver=selected_resolver,
                token_resolver=(
                    cast(CredentialResolver, configuration.get("token_resolver"))
                    if callable(configuration.get("token_resolver"))
                    else None
                ),
                signer=selected_signer,
            )

        registry.register_intelligence(provider_id, factory)


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
