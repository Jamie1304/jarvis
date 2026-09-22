"""R3H-R4 behavioral coverage for the standard intelligence adapters.

These cases deliberately use the production provider objects with deterministic
transports.  The transport is the external-server seam; normalization,
validation, routing metadata, and failure policy remain production behavior.
"""

from collections.abc import Mapping
from datetime import UTC, datetime
from typing import Any, cast
from uuid import uuid4

import httpx
import pytest
from jarvis.ai.knowledge import (
    ModelKnowledgeService,
    ModelKnowledgeStore,
    ModelObservation,
    ProviderCatalogSnapshot,
    identity_for,
)
from jarvis.ai.model_intelligence import ModelIntelligenceProjection
from jarvis.ai.models import ChatMessage, GenerationRequest, MessageRole, ModelRole, ProviderHealth
from jarvis.ai.onboarding import ProviderOnboardingService
from jarvis.ai.providers import catalog as catalog_module
from jarvis.ai.providers.base import AIProvider, IntelligenceProvider
from jarvis.ai.providers.catalog import (
    STANDARD_OPENAI_PRESETS,
    AnthropicConfiguration,
    AnthropicProvider,
    AwsSigV4Credentials,
    AwsSigV4Signer,
    BedrockConfiguration,
    BedrockProvider,
    CohereConfiguration,
    CohereProvider,
    GeminiConfiguration,
    GeminiProvider,
    HttpxJSONTransport,
    JevConfiguration,
    JevDecisionProvider,
    OpenAICompatibleConfiguration,
    OpenAICompatibleProvider,
    ProviderAdapterError,
    ProviderErrorReason,
    VertexAIConfiguration,
    VertexAIProvider,
    create_standard_provider,
    provider_support_matrix,
    register_standard_provider_factories,
)
from jarvis.ai.providers.discovery import ModelDiscoveryService
from jarvis.ai.providers.intelligence import (
    AuthenticationType,
    CallableDecisionProvider,
    CostEvidence,
    CostStatus,
    DecisionRequest,
    DecisionResult,
    ExactRouteIdentity,
    IntelligenceKind,
    ModelPolicy,
    PackageSupportStatus,
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
    ProviderDefinition,
    ProviderLocality,
    ProviderMetadata,
    ProviderRegistry,
    VoiceProviderDefinition,
    VoiceProviderKind,
)
from jarvis.ai.usability import ModelUsabilityEvidence, UsabilityReason
from jarvis.credentials import CredentialVault, TestOnlyInMemorySecretBackend
from jarvis.speech.stt import DisabledSttProvider
from jarvis.speech.tts import DisabledTtsProvider

from tests.test_r3h_r2_provider_execution import FixtureTransport, _credential, _request


class ScriptedTransport:
    """A deterministic external-server fixture that preserves request shapes."""

    def __init__(self, steps: list[tuple[str, str, object]]) -> None:
        self.steps = steps
        self.calls: list[tuple[str, str, Mapping[str, str], Mapping[str, object] | None]] = []

    async def request(
        self,
        method: str,
        path: str,
        payload: Mapping[str, object] | None,
        headers: Mapping[str, str],
    ) -> Mapping[str, object]:
        self.calls.append((method, path, headers, payload))
        assert self.steps, f"unexpected provider request: {method} {path}"
        expected_method, expected_path, result = self.steps.pop(0)
        assert (method, path) == (expected_method, expected_path)
        if isinstance(result, BaseException):
            raise result
        assert isinstance(result, Mapping)
        return result


class ProbeStub(IntelligenceProvider):
    def __init__(
        self,
        available: bool,
        snapshot: ProviderCatalogSnapshot | None = None,
        discovery_error: BaseException | None = None,
    ) -> None:
        self._available = available
        self._snapshot = snapshot
        self._discovery_error = discovery_error

    async def health_check(self) -> ProviderHealth:
        return ProviderHealth(self._available, "fixture")

    async def discover_models(self) -> ProviderCatalogSnapshot | None:
        if self._discovery_error is not None:
            raise self._discovery_error
        return self._snapshot


def _snapshot(provider_id: str, model_id: str = "fixture-model") -> ProviderCatalogSnapshot:
    metadata = ModelMetadata(model_id, 1024, source="fixture")
    observed_at = datetime(2026, 9, 22, tzinfo=UTC)
    provider = ProviderMetadata(provider_id, provider_id, "fixture")
    observation = ModelObservation(
        identity_for(provider_id, metadata), metadata, observed_at, "fixture"
    )
    return ProviderCatalogSnapshot(provider, (observation,), observed_at, "fixture", True)


def _httpx_transport(
    response: httpx.Response | None = None,
    *,
    error: BaseException | None = None,
) -> HttpxJSONTransport:
    async def handler(request: httpx.Request) -> httpx.Response:
        del request
        if error is not None:
            raise error
        assert response is not None
        return response

    client = httpx.AsyncClient(
        base_url="https://provider.example",
        transport=httpx.MockTransport(handler),
        follow_redirects=False,
    )
    return HttpxJSONTransport("https://provider.example", client=client)


@pytest.mark.parametrize(
    ("base_url", "timeout"),
    (
        ("ftp://provider.example", 15.0),
        ("https://provider.example?query=1", 15.0),
        ("http://provider.example", 15.0),
        ("https://provider.example", 0.09),
        ("https://provider.example", 120.1),
    ),
)
def test_httpx_transport_rejects_untrusted_destination_and_timeout(
    base_url: str, timeout: float
) -> None:
    with pytest.raises(ValueError):
        HttpxJSONTransport(base_url, timeout_seconds=timeout)


@pytest.mark.asyncio
async def test_httpx_transport_normalizes_payload_and_rejects_response_shapes() -> None:
    observed: list[tuple[str, bytes, str]] = []

    async def handler(request: httpx.Request) -> httpx.Response:
        observed.append((request.method, await request.aread(), request.headers["authorization"]))
        return httpx.Response(200, json={"ok": True})

    client = httpx.AsyncClient(
        base_url="https://provider.example",
        transport=httpx.MockTransport(handler),
        follow_redirects=False,
    )
    transport = HttpxJSONTransport("https://provider.example", client=client)
    assert await transport.request(
        "POST", "/v1/chat", {"text": "héllo"}, {"authorization": "Bearer fixture"}
    ) == {"ok": True}
    assert observed == [("POST", b'{"text":"h\xc3\xa9llo"}', "Bearer fixture")]
    await client.aclose()

    invalid_path = HttpxJSONTransport("https://provider.example", client=httpx.AsyncClient())
    with pytest.raises(ProviderAdapterError) as path_error:
        await invalid_path.request("GET", "relative", None, {})
    assert path_error.value.reason is ProviderErrorReason.UNKNOWN
    await invalid_path._client.aclose()  # type: ignore[union-attr]

    for response in (
        httpx.Response(200, content=b"not-json"),
        httpx.Response(200, json=["not", "an object"]),
        httpx.Response(200, json={"ok": True}, headers={"content-length": "not-a-number"}),
        httpx.Response(200, json={"ok": True}, headers={"content-length": "5000000"}),
    ):
        case = _httpx_transport(response)
        with pytest.raises(ProviderAdapterError) as error:
            await case.request("GET", "/models", None, {})
        assert error.value.reason is ProviderErrorReason.MALFORMED_RESPONSE
        await case._client.aclose()  # type: ignore[union-attr]


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "status,reason",
    (
        (401, ProviderErrorReason.AUTHENTICATION_FAILED),
        (404, ProviderErrorReason.MODEL_NOT_FOUND),
        (408, ProviderErrorReason.TIMEOUT),
        (409, ProviderErrorReason.QUOTA_UNAVAILABLE),
        (429, ProviderErrorReason.RATE_LIMITED),
        (500, ProviderErrorReason.PROVIDER_UNAVAILABLE),
        (418, ProviderErrorReason.UNKNOWN),
    ),
)
async def test_httpx_transport_classifies_provider_failures(
    status: int, reason: ProviderErrorReason
) -> None:
    case = _httpx_transport(httpx.Response(status, json={"error": "fixture"}))
    with pytest.raises(ProviderAdapterError) as error:
        await case.request("GET", "/models", None, {})
    assert error.value.reason is reason
    assert error.value.status_code == status
    await case._client.aclose()  # type: ignore[union-attr]


@pytest.mark.asyncio
async def test_httpx_transport_blocks_same_host_redirect_and_normalizes_transport_errors() -> None:
    redirect = _httpx_transport(
        httpx.Response(302, headers={"location": "https://provider.example/other"})
    )
    with pytest.raises(ProviderAdapterError) as redirect_error:
        await redirect.request("GET", "/models", None, {"authorization": "Bearer secret"})
    assert redirect_error.value.reason is ProviderErrorReason.REDIRECT_BLOCKED
    assert "secret" not in str(redirect_error.value)
    await redirect._client.aclose()  # type: ignore[union-attr]

    for exception, reason in (
        (httpx.ReadTimeout("timed out"), ProviderErrorReason.TIMEOUT),
        (httpx.ConnectError("offline"), ProviderErrorReason.PROVIDER_UNAVAILABLE),
    ):
        case = _httpx_transport(error=exception)
        with pytest.raises(ProviderAdapterError) as error:
            await case.request("GET", "/models", None, {})
        assert error.value.reason is reason
        await case._client.aclose()  # type: ignore[union-attr]


@pytest.mark.asyncio
async def test_httpx_transport_owns_and_closes_its_default_client(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    class OwnedClient:
        def __init__(self) -> None:
            self.closed = 0

        async def request(
            self,
            method: str,
            path: str,
            **kwargs: object,
        ) -> httpx.Response:
            assert method == "GET" and path == "/models"
            assert kwargs["headers"] == {}
            return httpx.Response(200, json={"models": []})

        async def aclose(self) -> None:
            self.closed += 1

    owned = OwnedClient()
    monkeypatch.setattr(httpx, "AsyncClient", lambda **kwargs: owned)
    transport = HttpxJSONTransport("https://provider.example")
    assert await transport.request("GET", "/models", None, {}) == {"models": []}
    assert owned.closed == 1
    transport._client = owned  # type: ignore[assignment]
    await transport.aclose()
    assert owned.closed == 2


@pytest.mark.parametrize(
    "changes",
    (
        {"provider_id": ""},
        {"model": " "},
        {"base_url": "https://user:pass@provider.example"},
        {"models_path": "models"},
        {"credential_header": ""},
        {"page_limit": 0},
        {"credential_required": 1},
        {"locality": ProviderLocality.LOCAL, "base_url": "https://provider.example"},
        {"locality": ProviderLocality.REMOTE, "base_url": "http://127.0.0.1:11434"},
    ),
)
def test_openai_configuration_rejects_invalid_route_metadata(changes: dict[str, object]) -> None:
    values: dict[str, Any] = {
        "provider_id": "fixture",
        "base_url": "https://provider.example/v1",
        "model": "fixture-model",
    }
    values.update(changes)
    with pytest.raises(ValueError):
        OpenAICompatibleConfiguration(**values)


def test_standard_factory_rejects_untyped_timeout_locality_model_and_credentials() -> None:
    with pytest.raises(ValueError):
        create_standard_provider("openai", {"timeout_seconds": "slow"})
    with pytest.raises(ValueError):
        create_standard_provider("openai", {"locality": "remote"})
    with pytest.raises(ValueError):
        create_standard_provider("openai", {"model": 3})
    with pytest.raises(PermissionError):
        create_standard_provider("openai", {"credential": "raw-secret"})


@pytest.mark.parametrize(
    ("provider_id", "configuration"),
    (
        ("typesafe-jev", {"model": 1}),
        ("ai21", {"model": 1}),
        ("cohere", {"model": 1}),
        ("openai-compatible", {}),
        ("openai-compatible", {"base_url": "https://provider.example", "locality": "remote"}),
        ("anthropic", {"model": 1}),
        ("google-gemini", {"model": 1}),
        ("azure-openai", {"endpoint": 1, "deployment": "deploy"}),
        ("google-vertex", {"project": "", "region": "region"}),
        ("amazon-bedrock", {"region": ""}),
    ),
)
def test_standard_factory_rejects_provider_specific_invalid_configuration(
    provider_id: str, configuration: dict[str, object]
) -> None:
    with pytest.raises((ValueError, PermissionError)):
        create_standard_provider(provider_id, configuration)


@pytest.mark.asyncio
async def test_openai_compatible_discovery_paginates_and_projects_model_capabilities() -> None:
    transport = ScriptedTransport(
        [
            (
                "GET",
                "/models",
                {
                    "data": [
                        {
                            "id": "embedder",
                            "context_length": 8192,
                            "capabilities": {"embedding": True, "chat": False},
                            "supported_actions": ["embed", " ", 1],
                            "architecture": {"input_modalities": ["text", "image", 1]},
                        },
                        {"id": "text-only", "architecture": {"input_modalities": "text"}},
                    ],
                    "has_more": True,
                    "last_id": "cursor/one",
                },
            ),
            (
                "GET",
                "/models?after=cursor%2Fone",
                {"data": [{"id": "chat-model", "max_context_length": 4096}]},
            ),
        ]
    )
    provider = OpenAICompatibleProvider(
        OpenAICompatibleConfiguration(
            "fixture",
            "https://provider.example/v1",
            credential_ref="ref",
            organization="org",
            project="project",
            extra_headers=(("x-fixture", "yes"),),
            credential_required=True,
        ),
        transport,
        credential_resolver=_credential,
    )
    snapshot = await provider.discover_models()
    assert [model.identity.model_id for model in snapshot.models] == [
        "embedder",
        "text-only",
        "chat-model",
    ]
    assert snapshot.models[0].metadata.roles
    assert snapshot.models[0].metadata.capabilities == frozenset({"embedding", "embed"})
    assert snapshot.models[0].metadata.modalities == frozenset({"text", "image"})
    assert snapshot.models[1].metadata.modalities == frozenset()
    assert transport.calls[0][2]["openai-organization"] == "org"
    assert transport.calls[0][2]["openai-project"] == "project"
    assert transport.calls[0][2]["x-fixture"] == "yes"


@pytest.mark.asyncio
async def test_openai_compatible_failures_and_health_are_bounded() -> None:
    malformed = ScriptedTransport(
        [("POST", "/chat/completions", {"choices": [{"message": {"content": 3}}]})]
    )
    provider = OpenAICompatibleProvider(
        OpenAICompatibleConfiguration("fixture", "https://provider.example/v1", model="fixture"),
        malformed,
    )
    with pytest.raises(ProviderAdapterError) as error:
        await provider.generate(_request("fixture"))
    assert error.value.reason is ProviderErrorReason.MALFORMED_RESPONSE
    missing_credential = await OpenAICompatibleProvider(
        OpenAICompatibleConfiguration(
            "fixture", "https://provider.example/v1", credential_required=True
        ),
        ScriptedTransport([]),
    ).health_check()
    assert missing_credential.available is False

    health_error = OpenAICompatibleProvider(
        OpenAICompatibleConfiguration("fixture", "https://provider.example/v1"),
        ScriptedTransport(
            [("GET", "/models", ProviderAdapterError(ProviderErrorReason.RATE_LIMITED))]
        ),
    )
    health = await health_error.health_check()
    assert health.available is False and health.detail == ProviderErrorReason.RATE_LIMITED.value


@pytest.mark.asyncio
async def test_openai_compatible_stream_health_info_and_discovery_bounds() -> None:
    transport = ScriptedTransport(
        [
            ("POST", "/chat/completions", {"choices": [{"message": {"content": "streamed"}}]}),
            ("GET", "/models", {"data": "not-a-list"}),
        ]
    )
    provider = OpenAICompatibleProvider(
        OpenAICompatibleConfiguration("fixture", "https://provider.example/v1", model="fixture"),
        transport,
    )
    chunks = [chunk async for chunk in provider.stream(_request("fixture"))]
    assert chunks[0].content == "streamed" and chunks[0].done is True
    assert (await provider.model_info()).model == "fixture"
    with pytest.raises(ProviderAdapterError):
        await provider.discover_models()

    paged = OpenAICompatibleProvider(
        OpenAICompatibleConfiguration("fixture", "https://provider.example/v1"),
        ScriptedTransport(
            [
                ("GET", "/models", {"data": [], "has_more": True, "last_id": "one"}),
                ("GET", "/models?after=one", {"data": [], "has_more": True, "last_id": "two"}),
                ("GET", "/models?after=two", {"data": []}),
            ]
        ),
    )
    assert (await paged.discover_models()).models == ()
    item_error = OpenAICompatibleProvider(
        OpenAICompatibleConfiguration("fixture", "https://provider.example/v1"),
        ScriptedTransport([("GET", "/models", {"data": [3]})]),
    )
    with pytest.raises(ProviderAdapterError):
        await item_error.discover_models()

    for bad in (
        {"models_path": "/" + "x" * 512},
        {"credential_header": "\x00"},
        {"extra_headers": (("", "value"),)},
        {"page_limit": 0},
    ):
        values: dict[str, Any] = {
            "provider_id": "fixture",
            "base_url": "https://provider.example/v1",
        }
        values.update(bad)
        with pytest.raises(ValueError):
            OpenAICompatibleConfiguration(**values)


@pytest.mark.asyncio
async def test_openai_discovery_rejects_invalid_cursors_pages_items_and_inventory_size() -> None:
    cases: tuple[list[tuple[str, str, object]], ...] = (
        [("GET", "/models", {"data": [], "next_cursor": ""})],
        [
            ("GET", "/models", {"data": [], "next_cursor": "cursor"}),
            ("GET", "/models?after=cursor", {"data": "bad"}),
        ],
        [
            ("GET", "/models", {"data": [], "has_more": True, "last_id": "cursor"}),
            ("GET", "/models?after=cursor", {"data": [{"id": 3}]}),
        ],
        [("GET", "/models", {"data": [{"not_id": "bad"}]})],
        [("GET", "/models", {"data": [{"id": "bad\x00id"}]})],
    )
    for steps in cases:
        provider = OpenAICompatibleProvider(
            OpenAICompatibleConfiguration("fixture", "https://provider.example/v1"),
            ScriptedTransport(steps),
        )
        with pytest.raises(ProviderAdapterError):
            await provider.discover_models()

    first_page = [{"id": f"first-{index}"} for index in range(25)]
    second_page = [{"id": f"model-{index}"} for index in range(1000)]
    provider = OpenAICompatibleProvider(
        OpenAICompatibleConfiguration("fixture", "https://provider.example/v1", page_limit=1000),
        ScriptedTransport(
            [
                ("GET", "/models", {"data": first_page, "next_cursor": "cursor"}),
                ("GET", "/models?after=cursor", {"data": second_page}),
            ]
        ),
    )
    with pytest.raises(ProviderAdapterError):
        await provider.discover_models()


@pytest.mark.asyncio
async def test_openai_transport_and_adapter_credential_and_resource_guards() -> None:
    oversized = _httpx_transport(
        httpx.Response(200, content=b"x" * (HttpxJSONTransport.MAX_RESPONSE_BYTES + 1))
    )
    with pytest.raises(ProviderAdapterError):
        await oversized.request("GET", "/models", None, {})
    await oversized.aclose()
    oversized_body = _httpx_transport(
        httpx.Response(
            200,
            headers={"content-length": "1"},
            content=b"x" * (HttpxJSONTransport.MAX_RESPONSE_BYTES + 1),
        )
    )
    with pytest.raises(ProviderAdapterError):
        await oversized_body.request("GET", "/models", None, {})
    await oversized_body.aclose()

    for values in (
        {"base_url": 3},
        {"locality": "remote"},
        {"base_url": "http://provider.example"},
    ):
        configuration: dict[str, Any] = {
            "provider_id": "fixture",
            "base_url": "https://provider.example/v1",
        }
        configuration.update(values)
        with pytest.raises(ValueError):
            OpenAICompatibleConfiguration(**configuration)

    missing_resolver = OpenAICompatibleProvider(
        OpenAICompatibleConfiguration(
            "fixture", "https://provider.example/v1", credential_ref="ref"
        ),
        ScriptedTransport([]),
    )
    with pytest.raises(PermissionError):
        await missing_resolver.generate(_request("fixture"))

    healthy = OpenAICompatibleProvider(
        OpenAICompatibleConfiguration("fixture", "https://provider.example/v1", model="fixture"),
        ScriptedTransport([("GET", "/models", {"data": []})]),
    )
    assert (await healthy.health_check()).available is True
    assert (await healthy.model_info()).model == "fixture"


@pytest.mark.asyncio
async def test_anthropic_pagination_system_prompt_and_malformed_contracts() -> None:
    transport = ScriptedTransport(
        [
            (
                "GET",
                "/v1/models",
                {
                    "data": [{"id": "claude-a", "max_input_tokens": 2048}],
                    "has_more": True,
                    "last_id": "a",
                },
            ),
            ("GET", "/v1/models?after_id=a", {"data": [{"id": "claude-b"}]}),
            (
                "POST",
                "/v1/messages",
                {"model": "claude-a", "content": [{"type": "text", "text": "done"}]},
            ),
        ]
    )
    provider = AnthropicProvider(
        AnthropicConfiguration(model="claude-a", credential_ref="ref"),
        transport,
        credential_resolver=_credential,
    )
    discovered = await provider.discover_models()
    result = await provider.generate(_request("claude-a"))
    assert [model.identity.model_id for model in discovered.models] == ["claude-a", "claude-b"]
    assert result.content == "done"
    assert transport.calls[-1][3] is not None
    assert "system" not in transport.calls[-1][3]

    broken = AnthropicProvider(
        AnthropicConfiguration(model="x"),
        ScriptedTransport([("POST", "/v1/messages", {"content": []})]),
    )
    with pytest.raises(ProviderAdapterError) as error:
        await broken.generate(_request("x"))
    assert error.value.reason is ProviderErrorReason.MALFORMED_RESPONSE

    bad_page = AnthropicProvider(
        AnthropicConfiguration(model="x"),
        ScriptedTransport([("GET", "/v1/models", {"data": [], "has_more": True, "last_id": 3})]),
    )
    with pytest.raises(ProviderAdapterError):
        await bad_page.discover_models()


@pytest.mark.asyncio
async def test_gemini_pagination_system_instruction_and_unknown_model_shape() -> None:
    transport = ScriptedTransport(
        [
            (
                "GET",
                "/models",
                {
                    "models": [{"name": "models/gemini-a", "supportedGenerationMethods": "bad"}],
                    "nextPageToken": "next",
                },
            ),
            ("GET", "/models?pageToken=next", {"models": [{"name": "models/gemini-b"}]}),
            (
                "POST",
                "/models/gemini-a:generateContent",
                {"candidates": [{"content": {"parts": [{"text": "answer"}]}}]},
            ),
        ]
    )
    provider = GeminiProvider(
        GeminiConfiguration(model="gemini-a", credential_ref="ref"),
        transport,
        credential_resolver=_credential,
    )
    snapshot = await provider.discover_models()
    result = await provider.generate(_request("gemini-a"))
    assert [model.identity.model_id for model in snapshot.models] == ["gemini-a", "gemini-b"]
    assert snapshot.models[0].metadata.capabilities == frozenset()
    assert result.content == "answer"

    bad_token = GeminiProvider(
        GeminiConfiguration(),
        ScriptedTransport([("GET", "/models", {"models": [], "nextPageToken": 4})]),
    )
    with pytest.raises(ProviderAdapterError):
        await bad_token.discover_models()


@pytest.mark.asyncio
async def test_cohere_pagination_and_content_normalization_are_not_silent() -> None:
    transport = ScriptedTransport(
        [
            (
                "GET",
                "/v1/models?page_size=100",
                {"models": [{"name": "command-a", "context_length": 100}], "next_page_token": "p1"},
            ),
            (
                "GET",
                "/v1/models?page_size=100&page_token=p1",
                {"models": [{"name": "command-b"}]},
            ),
            (
                "POST",
                "/v2/chat",
                {
                    "model": "command-a",
                    "message": {"content": [{"text": "co", "type": "text"}, {"text": "here"}]},
                },
            ),
        ]
    )
    provider = CohereProvider(
        CohereConfiguration(model="command-a", credential_ref="ref"),
        transport,
        credential_resolver=_credential,
    )
    snapshot = await provider.discover_models()
    result = await provider.generate(_request("command-a"))
    assert [model.identity.model_id for model in snapshot.models] == ["command-a", "command-b"]
    assert result.content == "cohere"

    malformed = CohereProvider(
        CohereConfiguration(model="x"),
        ScriptedTransport([("POST", "/v2/chat", {"message": {"content": {}}})]),
    )
    with pytest.raises(ProviderAdapterError):
        await malformed.generate(_request("x"))


@pytest.mark.asyncio
async def test_ai21_and_cohere_health_discovery_failures_remain_explicit() -> None:
    ai21 = create_standard_provider("ai21", {}, transport=ScriptedTransport([]))
    assert (await ai21.health_check()).available is False
    with pytest.raises(ProviderAdapterError):
        await ai21.discover_models()

    cohere = CohereProvider(
        CohereConfiguration(model="x"),
        ScriptedTransport(
            [("GET", "/v1/models?page_size=1", ProviderAdapterError(ProviderErrorReason.TIMEOUT))]
        ),
    )
    assert (await cohere.health_check()).detail == ProviderErrorReason.TIMEOUT.value
    bad_token = CohereProvider(
        CohereConfiguration(),
        ScriptedTransport(
            [("GET", "/v1/models?page_size=100", {"models": [], "next_page_token": 4})]
        ),
    )
    with pytest.raises(ProviderAdapterError):
        await bad_token.discover_models()


@pytest.mark.asyncio
async def test_ai21_cohere_and_family_stream_contracts_cover_success_and_failure_paths() -> None:
    ai21 = create_standard_provider(
        "ai21",
        {"model": "jamba"},
        transport=ScriptedTransport([]),
    )
    assert (await ai21.health_check()).available is True
    assert (await ai21.model_info()).model == "jamba"
    cohere_transport = ScriptedTransport(
        [
            ("GET", "/v1/models?page_size=1", {"models": []}),
            ("POST", "/v2/chat", {"message": {"content": "plain text"}}),
            ("POST", "/v2/chat", {"message": {"content": "plain text"}}),
        ]
    )
    cohere = CohereProvider(CohereConfiguration(model="command"), cohere_transport)
    assert (await cohere.health_check()).available is True
    assert (await cohere.model_info()).model == "command"
    assert (await cohere.generate(_request("command"))).content == "plain text"
    chunks = [chunk async for chunk in cohere.stream(_request("command"))]
    assert chunks[0].done is True

    for provider, path, response in (
        (
            CohereProvider(
                CohereConfiguration(),
                ScriptedTransport([("GET", "/v1/models?page_size=100", {"models": "bad"})]),
            ),
            "discover",
            None,
        ),
        (
            CohereProvider(
                CohereConfiguration(),
                ScriptedTransport(
                    [("GET", "/v1/models?page_size=100", {"models": [{"bad": True}]})]
                ),
            ),
            "discover",
            None,
        ),
    ):
        del path, response
        with pytest.raises(ProviderAdapterError):
            await provider.discover_models()

    missing_resolver = CohereProvider(
        CohereConfiguration(credential_ref="ref"), ScriptedTransport([])
    )
    assert (await missing_resolver.health_check()).available is False
    invalid_credential = CohereProvider(
        CohereConfiguration(credential_ref="ref"),
        ScriptedTransport([]),
        credential_resolver=_invalid_secret,
    )
    with pytest.raises(PermissionError):
        await invalid_credential.generate(_request("command"))

    class RepeatingCohereTransport(ScriptedTransport):
        async def request(
            self,
            method: str,
            path: str,
            payload: Mapping[str, object] | None,
            headers: Mapping[str, str],
        ) -> Mapping[str, object]:
            self.calls.append((method, path, headers, payload))
            return {"models": [], "next_page_token": "again"}

    with pytest.raises(ProviderAdapterError):
        await CohereProvider(CohereConfiguration(), RepeatingCohereTransport([])).discover_models()


@pytest.mark.asyncio
async def test_anthropic_and_gemini_system_payloads_and_discovery_error_shapes() -> None:
    request = GenerationRequest(
        (
            ChatMessage(uuid4(), uuid4(), MessageRole.SYSTEM, "system", datetime.now(UTC)),
            ChatMessage(uuid4(), uuid4(), MessageRole.USER, "question", datetime.now(UTC)),
        ),
        "model",
        32,
    )
    anthropic_transport = ScriptedTransport(
        [("POST", "/v1/messages", {"model": "model", "content": [{"type": "text", "text": "ok"}]})]
    )
    anthropic = AnthropicProvider(AnthropicConfiguration(), anthropic_transport)
    assert (await anthropic.generate(request)).content == "ok"
    assert anthropic_transport.calls[0][3] is not None
    assert anthropic_transport.calls[0][3]["system"] == "system"
    assert anthropic.intelligence_kinds
    assert (await anthropic.model_info()).model == "unknown"
    assert (await anthropic.health_check()).available is False
    anthropic_stream = AnthropicProvider(
        AnthropicConfiguration(),
        ScriptedTransport(
            [
                (
                    "POST",
                    "/v1/messages",
                    {"content": [{"type": "text", "text": "ok"}]},
                )
            ]
        ),
    )
    assert [chunk async for chunk in anthropic_stream.stream(request)][0].done is True
    with pytest.raises(ProviderAdapterError):
        await AnthropicProvider(
            AnthropicConfiguration(),
            ScriptedTransport([("POST", "/v1/messages", {"content": "bad"})]),
        ).generate(request)
    assert (
        await AnthropicProvider(
            AnthropicConfiguration(),
            ScriptedTransport([("GET", "/v1/models", {"data": []})]),
        ).health_check()
    ).available is True

    for provider, operation in (
        (
            AnthropicProvider(
                AnthropicConfiguration(),
                ScriptedTransport([("GET", "/v1/models", {"data": [{"id": 3}]})]),
            ),
            "anthropic",
        ),
        (
            GeminiProvider(
                GeminiConfiguration(),
                ScriptedTransport([("GET", "/models", {"models": [{"name": 3}]})]),
            ),
            "gemini",
        ),
    ):
        del operation
        with pytest.raises(ProviderAdapterError):
            await provider.discover_models()

    gemini_transport = ScriptedTransport(
        [
            (
                "POST",
                "/models/model:generateContent",
                {"candidates": [{"content": {"parts": [{"text": "ok"}]}}]},
            ),
            ("GET", "/models", {"models": []}),
        ]
    )
    gemini = GeminiProvider(GeminiConfiguration(model="model"), gemini_transport)
    assert (await gemini.generate(request)).content == "ok"
    assert gemini_transport.calls[0][3] is not None
    assert "systemInstruction" in gemini_transport.calls[0][3]
    assert (await gemini.health_check()).available is True
    assert (await gemini.model_info()).model == "model"
    gemini_stream = GeminiProvider(
        GeminiConfiguration(model="model"),
        ScriptedTransport(
            [
                (
                    "POST",
                    "/models/model:generateContent",
                    {"candidates": [{"content": {"parts": [{"text": "ok"}]}}]},
                )
            ]
        ),
    )
    assert [chunk async for chunk in gemini_stream.stream(request)][0].done is True
    with pytest.raises(ProviderAdapterError):
        await GeminiProvider(
            GeminiConfiguration(),
            ScriptedTransport(
                [
                    (
                        "POST",
                        "/models/model:generateContent",
                        {"candidates": [{"content": {"parts": []}}]},
                    )
                ]
            ),
        ).generate(request)


@pytest.mark.asyncio
async def test_provider_close_hooks_and_discovery_item_bounds_are_enforced() -> None:
    class CloseTransport(ScriptedTransport):
        def __init__(self, steps: list[tuple[str, str, object]]) -> None:
            super().__init__(steps)
            self.closed = 0

        async def aclose(self) -> None:
            self.closed += 1

    transports = (
        (
            CohereProvider(
                CohereConfiguration(),
                CloseTransport([("GET", "/v1/models?page_size=100", {"models": [{"name": 3}]})]),
            ),
            ProviderAdapterError,
        ),
    )
    for provider, error_type in transports:
        with pytest.raises(error_type):
            await provider.discover_models()
        close_transport = provider._transport
        await provider.aclose()
        assert close_transport.closed == 1  # type: ignore[attr-defined]

    openai_close = CloseTransport([("GET", "/models", {"data": [{"id": 3}]})])
    openai = OpenAICompatibleProvider(
        OpenAICompatibleConfiguration("fixture", "https://provider.example/v1"), openai_close
    )
    with pytest.raises(ProviderAdapterError):
        await openai.discover_models()
    await openai.aclose()
    assert openai_close.closed == 1

    class SyncCloseTransport(CloseTransport):
        def aclose(self) -> None:  # type: ignore[override]
            self.closed += 1

    sync_close = SyncCloseTransport([])
    await OpenAICompatibleProvider(
        OpenAICompatibleConfiguration("fixture", "https://provider.example/v1"), sync_close
    ).aclose()
    assert sync_close.closed == 1
    await CohereProvider(CohereConfiguration(), ScriptedTransport([])).aclose()

    class SyncCohereTransport(CloseTransport):
        def aclose(self) -> None:  # type: ignore[override]
            self.closed += 1

    sync_cohere = SyncCohereTransport([])
    await CohereProvider(CohereConfiguration(), sync_cohere).aclose()
    assert sync_cohere.closed == 1


@pytest.mark.asyncio
async def test_enterprise_adapters_preserve_route_identity_and_signing_policy() -> None:
    azure_transport = FixtureTransport(
        {
            ("POST", "/openai/deployments/deploy/chat/completions?api-version=2025-01-01"): {
                "model": "deploy",
                "choices": [{"message": {"content": "azure"}}],
            }
        }
    )
    azure = create_standard_provider(
        "azure-openai",
        {
            "endpoint": "https://resource.example/",
            "deployment": "deploy",
            "api_version": "2025-01-01",
            "credential_ref": "ref",
        },
        transport=azure_transport,
        credential_resolver=_credential,
    )
    assert (await azure.generate(_request("deploy"))).content == "azure"
    assert azure_transport.calls[0][2]["api-key"] == "fixture-secret"

    signer = AwsSigV4Signer(
        "eu-west-1",
        "bedrock-runtime.eu-west-1.amazonaws.com",
        AwsSigV4Credentials("AKID", "secret", "session"),
        clock=lambda: datetime(2026, 9, 22, 12, 0, tzinfo=UTC),
    )
    signed = signer.sign("POST", "/model/a%20b/converse?b=2&a=1", {"x": "y"})
    assert signed["x-amz-security-token"] == "session"
    assert "secret" not in str(signed)
    with pytest.raises(ValueError):
        signer.sign("GET", "relative", None)

    bedrock_transport = FixtureTransport(
        {
            ("POST", "/model/amazon.model/converse"): {
                "output": {"message": {"content": [{"text": "bedrock"}]}}
            },
            ("GET", "/foundation-models"): {"modelSummaries": []},
        }
    )
    bedrock = BedrockProvider(
        BedrockConfiguration("eu-west-1", "amazon.model"), bedrock_transport, signer
    )
    assert (await bedrock.generate(_request("amazon.model"))).content == "bedrock"
    assert (await bedrock.discover_models()).available is True

    missing_signer = await BedrockProvider(
        BedrockConfiguration("eu-west-1"), bedrock_transport, None
    ).health_check()
    assert missing_signer.available is False

    assert (await bedrock.health_check()).available is True
    assert (await bedrock.model_info()).model == "amazon.model"
    bedrock_stream_transport = FixtureTransport(
        {
            ("POST", "/model/amazon.model/converse"): {
                "output": {"message": {"content": [{"text": "bedrock"}]}}
            }
        }
    )
    bedrock_stream = BedrockProvider(
        BedrockConfiguration("eu-west-1", "amazon.model"), bedrock_stream_transport, signer
    )
    assert [chunk async for chunk in bedrock_stream.stream(_request("amazon.model"))][
        0
    ].done is True
    for invalid in (
        ("", "host", AwsSigV4Credentials("a", "b")),
        ("region", "host/path", AwsSigV4Credentials("a", "b")),
        ("region", "host", AwsSigV4Credentials("", "b")),
    ):
        with pytest.raises(ValueError):
            AwsSigV4Signer(invalid[0], invalid[1], invalid[2])
    with pytest.raises(ValueError):
        AwsSigV4Signer(
            "region",
            "host",
            AwsSigV4Credentials("a", "b"),
            clock=lambda: datetime(2026, 9, 22),
        ).sign("GET", "/models", None)

    malformed_discovery = BedrockProvider(
        BedrockConfiguration("eu-west-1"),
        FixtureTransport({("GET", "/foundation-models"): {"modelSummaries": [{"bad": True}]}}),
        signer,
    )
    with pytest.raises(ProviderAdapterError):
        await malformed_discovery.discover_models()


@pytest.mark.asyncio
async def test_anthropic_gemini_and_bedrock_health_and_malformed_outputs() -> None:
    for provider in (
        AnthropicProvider(
            AnthropicConfiguration(),
            ScriptedTransport(
                [
                    (
                        "GET",
                        "/v1/models",
                        ProviderAdapterError(ProviderErrorReason.AUTHENTICATION_FAILED),
                    )
                ]
            ),
        ),
        GeminiProvider(
            GeminiConfiguration(),
            ScriptedTransport([("GET", "/models", RuntimeError("offline"))]),
        ),
    ):
        health = await provider.health_check()
        assert health.available is False

    anthropic_bad = AnthropicProvider(
        AnthropicConfiguration(),
        ScriptedTransport([("POST", "/v1/messages", {"content": [{"type": "image"}]})]),
    )
    with pytest.raises(ProviderAdapterError):
        await anthropic_bad.generate(_request("claude"))
    gemini_bad = GeminiProvider(
        GeminiConfiguration(),
        ScriptedTransport([("POST", "/models/gemini:generateContent", {"candidates": []})]),
    )
    with pytest.raises(ProviderAdapterError):
        await gemini_bad.generate(_request("gemini"))
    bedrock_bad = BedrockProvider(
        BedrockConfiguration("eu-west-1"),
        ScriptedTransport([("POST", "/model/model/converse", {"output": {}})]),
        AwsSigV4Signer(
            "eu-west-1",
            "bedrock-runtime.eu-west-1.amazonaws.com",
            AwsSigV4Credentials("AKID", "secret"),
            clock=lambda: datetime(2026, 9, 22, 12, 0, tzinfo=UTC),
        ),
    )
    with pytest.raises(ProviderAdapterError):
        await bedrock_bad.generate(_request("model"))


@pytest.mark.asyncio
async def test_provider_headers_reject_missing_or_invalid_credential_material() -> None:
    for provider in (
        AnthropicProvider(AnthropicConfiguration(credential_ref="ref"), ScriptedTransport([])),
        GeminiProvider(GeminiConfiguration(credential_ref="ref"), ScriptedTransport([])),
    ):
        assert (await provider.health_check()).available is False

    invalid = OpenAICompatibleProvider(
        OpenAICompatibleConfiguration(
            "fixture", "https://provider.example/v1", credential_ref="ref"
        ),
        ScriptedTransport([]),
        credential_resolver=_invalid_secret,
    )
    with pytest.raises(PermissionError):
        await invalid.generate(_request("fixture"))
    vertex_missing = VertexAIProvider(
        VertexAIConfiguration("project", "region", credential_ref="ref"),
        ScriptedTransport([]),
    )
    assert (await vertex_missing.health_check()).available is False
    vertex_invalid = VertexAIProvider(
        VertexAIConfiguration("project", "region", credential_ref="ref"),
        ScriptedTransport([]),
        token_resolver=_invalid_secret,
    )
    assert (await vertex_invalid.health_check()).available is False
    vertex_no_credential = VertexAIProvider(
        VertexAIConfiguration("project", "region"),
        ScriptedTransport([("GET", "/models", {"models": []})]),
    )
    assert (await vertex_no_credential.health_check()).available is True


@pytest.mark.asyncio
async def test_standard_adapters_cover_error_normalization_and_factory_boundaries(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    invalid_anthropic = AnthropicProvider(
        AnthropicConfiguration(model="claude", credential_ref="ref"),
        ScriptedTransport([]),
        credential_resolver=_invalid_secret,
    )
    with pytest.raises(PermissionError):
        await invalid_anthropic.generate(_request("claude"))
    malformed_anthropic = AnthropicProvider(
        AnthropicConfiguration(), ScriptedTransport([("GET", "/v1/models", {"data": "bad"})])
    )
    with pytest.raises(ProviderAdapterError):
        await malformed_anthropic.discover_models()

    invalid_gemini = GeminiProvider(
        GeminiConfiguration(model="gemini", credential_ref="ref"),
        ScriptedTransport([]),
        credential_resolver=_invalid_secret,
    )
    with pytest.raises(PermissionError):
        await invalid_gemini.generate(_request("gemini"))
    assert invalid_gemini.intelligence_kinds
    gemini_error = GeminiProvider(
        GeminiConfiguration(),
        ScriptedTransport([("GET", "/models", ProviderAdapterError(ProviderErrorReason.TIMEOUT))]),
    )
    assert (await gemini_error.health_check()).detail == ProviderErrorReason.TIMEOUT.value
    malformed_gemini = GeminiProvider(
        GeminiConfiguration(), ScriptedTransport([("GET", "/models", {"models": "bad"})])
    )
    with pytest.raises(ProviderAdapterError):
        await malformed_gemini.discover_models()

    class InvalidSigner:
        def sign(
            self, method: str, path: str, payload: Mapping[str, object] | None
        ) -> Mapping[str, str]:
            del method, path, payload
            return {}

    bedrock_invalid_signer = BedrockProvider(
        BedrockConfiguration("eu-west-1", "model"), ScriptedTransport([]), InvalidSigner()
    )
    assert bedrock_invalid_signer.intelligence_kinds
    with pytest.raises(PermissionError):
        await bedrock_invalid_signer.generate(_request("model"))
    valid_bedrock_signer = AwsSigV4Signer(
        "eu-west-1",
        "bedrock-runtime.eu-west-1.amazonaws.com",
        AwsSigV4Credentials("AKID", "secret"),
        clock=lambda: datetime(2026, 9, 22, 12, 0, tzinfo=UTC),
    )
    bedrock_error = BedrockProvider(
        BedrockConfiguration("eu-west-1"),
        ScriptedTransport(
            [("GET", "/foundation-models", ProviderAdapterError(ProviderErrorReason.TIMEOUT))]
        ),
        valid_bedrock_signer,
    )
    assert (await bedrock_error.health_check()).detail == ProviderErrorReason.TIMEOUT.value
    malformed_bedrock = BedrockProvider(
        BedrockConfiguration("eu-west-1"),
        ScriptedTransport([("GET", "/foundation-models", {"modelSummaries": "bad"})]),
        valid_bedrock_signer,
    )
    with pytest.raises(ProviderAdapterError):
        await malformed_bedrock.discover_models()

    assert isinstance(
        create_standard_provider("anthropic", {"model": "claude"}, transport=ScriptedTransport([])),
        AnthropicProvider,
    )
    assert isinstance(
        create_standard_provider(
            "google-gemini", {"model": "gemini"}, transport=ScriptedTransport([])
        ),
        GeminiProvider,
    )
    assert isinstance(
        create_standard_provider(
            "google-vertex",
            {"project": "fixture", "region": "eu", "token_resolver": _credential},
            transport=ScriptedTransport([]),
        ),
        VertexAIProvider,
    )
    assert isinstance(
        create_standard_provider(
            "google-vertex",
            {"project": "fixture", "region": "eu"},
            transport=ScriptedTransport([]),
            token_resolver=_credential,
        ),
        VertexAIProvider,
    )
    assert isinstance(
        create_standard_provider(
            "amazon-bedrock",
            {"region": "eu-west-1", "signer": valid_bedrock_signer},
            transport=ScriptedTransport([]),
        ),
        BedrockProvider,
    )
    assert isinstance(
        create_standard_provider(
            "amazon-bedrock",
            {"region": "eu-west-1"},
            transport=ScriptedTransport([]),
            signer=valid_bedrock_signer,
        ),
        BedrockProvider,
    )

    def custom_manifest(provider_id: str) -> ProviderPackageManifest:
        support = (
            PackageSupportStatus.CATALOG_ONLY
            if provider_id == "catalog-only"
            else PackageSupportStatus.CONTROLLED_PROTOCOL_TESTED
        )
        return ProviderPackageManifest(
            provider_id,
            provider_id,
            frozenset({IntelligenceKind.GENERATIVE}),
            support_status=support,
        )

    monkeypatch.setattr(catalog_module, "provider_manifest", custom_manifest)
    with pytest.raises(ValueError, match="not source-executable"):
        create_standard_provider("catalog-only", {})
    with pytest.raises(ValueError, match="No source adapter"):
        create_standard_provider("unhandled", {})
    catalog_only = ProviderPackageManifest(
        "catalog-only",
        "Catalog only",
        frozenset({IntelligenceKind.GENERATIVE}),
        support_status=PackageSupportStatus.CATALOG_ONLY,
    )
    monkeypatch.setattr(catalog_module, "STANDARD_PROVIDER_MANIFESTS", (catalog_only,))
    registry = ProviderRegistry()
    register_standard_provider_factories(registry)
    assert registry.intelligence_provider_ids() == ()


async def _invalid_secret(reference: object) -> str:
    del reference
    return "bad\x00secret"


@pytest.mark.parametrize(
    "configuration",
    (
        {"provider_id": "wrong"},
        {"base_url": "https://other.example"},
        {"model": "\x00"},
        {"page_limit": 0},
    ),
)
def test_jev_configuration_rejects_mutable_identity(configuration: dict[str, object]) -> None:
    values: dict[str, object] = {
        "provider_id": "typesafe-jev",
        "base_url": "https://api.typesafe.ai",
    }
    values.update(configuration)
    with pytest.raises(ValueError):
        JevConfiguration(**values)  # type: ignore[arg-type]


def test_standard_provider_factory_registration_captures_provider_identity() -> None:
    registry = ProviderRegistry()
    register_standard_provider_factories(registry)
    executable = [
        row.provider_id for row in provider_support_matrix() if row.source_adapter_present
    ]
    assert set(registry.intelligence_provider_ids()) == set(executable)
    for provider_id in STANDARD_OPENAI_PRESETS:
        provider = registry.create_intelligence(
            provider_id,
            {
                "model": "fixture",
                "credential_ref": "ref",
                "transport": FixtureTransport({("GET", "/models"): {"data": []}}),
                "credential_resolver": _credential,
            },
        )
        assert isinstance(provider, OpenAICompatibleProvider)
        assert provider.configuration.provider_id == provider_id
        assert provider.intelligence_kinds == frozenset({IntelligenceKind.GENERATIVE.value})
    with pytest.raises(ValueError):
        register_standard_provider_factories(object())
    register_standard_provider_factories(registry)


def test_provider_package_lazy_exports_resolve_catalog_and_discovery_adapters() -> None:
    import jarvis.ai.providers as providers

    assert providers.JevConfiguration is JevConfiguration
    assert providers.OpenAICompatibleProvider is OpenAICompatibleProvider
    assert providers.ModelDiscoveryService is ModelDiscoveryService
    with pytest.raises(AttributeError):
        getattr(providers, "not-a-provider")


@pytest.mark.asyncio
async def test_jev_invalid_questions_health_and_discovery_fail_closed() -> None:
    provider = JevDecisionProvider(JevConfiguration(model="jev"), None)
    with pytest.raises(ValueError):
        await provider.decide(DecisionRequest("task", (), output_schema="unsupported"))
    assert (await provider.health_check()).available is False
    with pytest.raises(ConnectionError):
        await provider.discover_models()

    duplicate_models = JevDecisionProvider(
        JevConfiguration(model="jev", credential_ref="ref"),
        ScriptedTransport(
            [("GET", "/v1/models", {"models": [{"name": "same"}, {"name": "same"}]})]
        ),
        credential_resolver=_credential,
    )
    with pytest.raises(ProviderAdapterError):
        await duplicate_models.discover_models()


@pytest.mark.asyncio
async def test_jev_schema_validation_legacy_and_error_normalization() -> None:
    for request in (
        DecisionRequest("task", (("criteria", "not-json"),), output_schema="noul"),
        DecisionRequest("task", (("criteria", '["not-an-object"]'),), output_schema="noul"),
    ):
        provider = JevDecisionProvider(
            JevConfiguration(model="jev", credential_ref="ref"),
            ScriptedTransport([]),
            credential_resolver=_credential,
        )
        with pytest.raises(ValueError):
            await provider.decide(request)

    class ErrorTransport(ScriptedTransport):
        pass

    for response in (
        {
            "model": "jev",
            "answers": {
                "decision": {
                    "type": "choice",
                    "choice": "other",
                    "confidence": 0.5,
                    "probabilities": {"yes": 1.0},
                }
            },
        },
        {
            "model": "jev",
            "answers": {
                "decision": {
                    "type": "score",
                    "score": 9,
                    "confidence": 0.5,
                    "probabilities": {"0": 1.0},
                }
            },
        },
    ):
        provider = JevDecisionProvider(
            JevConfiguration(model="jev", credential_ref="ref"),
            ErrorTransport([("POST", "/v1/systemone", response)]),
            credential_resolver=_credential,
        )
        with pytest.raises(ValueError):
            await provider.decide(
                DecisionRequest("task", (("choices", '["yes"]'),), output_schema="choice")
            )

    async def legacy(request: DecisionRequest) -> DecisionResult:
        return DecisionResult("legacy", provider_id="legacy")

    legacy_provider = JevDecisionProvider(legacy_transport=legacy)
    assert (await legacy_provider.decide(DecisionRequest("task", ()))).label == "legacy"
    assert (await legacy_provider.health_check()).available is True

    async def bad_legacy(request: DecisionRequest) -> object:
        del request
        return object()

    with pytest.raises(ValueError):
        await JevDecisionProvider(legacy_transport=bad_legacy).decide(DecisionRequest("task", ()))  # type: ignore[arg-type]

    valid_score = JevDecisionProvider(
        JevConfiguration(model="jev", credential_ref="ref"),
        ScriptedTransport(
            [
                (
                    "POST",
                    "/v1/systemone",
                    {
                        "model": "jev",
                        "answers": {
                            "decision": {
                                "type": "score",
                                "score": 1,
                                "confidence": 1.0,
                                "probabilities": {"0": 0.0, "1": 1.0, "2": 0.0},
                            }
                        },
                    },
                )
            ]
        ),
        credential_resolver=_credential,
    )
    assert (
        await valid_score.decide(
            DecisionRequest("task", (("criteria", "low,medium,high"),), output_schema="score")
        )
    ).label == "score"
    choice_not_in_criteria = {
        "model": "jev",
        "answers": {
            "decision": {
                "type": "choice",
                "choice": "yes",
                "confidence": 0.5,
                "probabilities": {"no": 1.0},
            }
        },
    }
    with pytest.raises(ValueError):
        await JevDecisionProvider(
            JevConfiguration(model="jev", credential_ref="ref"),
            ScriptedTransport([("POST", "/v1/systemone", choice_not_in_criteria)]),
            credential_resolver=_credential,
        ).decide(DecisionRequest("task", (("choices", '["yes"]'),), output_schema="choice"))
    choice_extra = {
        "model": "jev",
        "answers": {
            "decision": {
                "type": "choice",
                "choice": "yes",
                "confidence": 0.5,
                "probabilities": {"yes": 1.0, "no": 0.0},
                "extra": True,
            }
        },
    }
    with pytest.raises(ValueError):
        await JevDecisionProvider(
            JevConfiguration(model="jev", credential_ref="ref"),
            ScriptedTransport([("POST", "/v1/systemone", choice_extra)]),
            credential_resolver=_credential,
        ).decide(DecisionRequest("task", (("choices", '["yes"]'),), output_schema="choice"))

    fallback = JevDecisionProvider(
        JevConfiguration(model="jev", credential_ref="ref"),
        ScriptedTransport(
            [
                (
                    "POST",
                    "/v1/systemone",
                    {
                        "model": "jev",
                        "answers": {
                            "decision": {
                                "type": "choice",
                                "choice": "a",
                                "confidence": 1.0,
                                "probabilities": {"a": 1.0, "b": 0.0},
                            }
                        },
                    },
                )
            ]
        ),
        credential_resolver=_credential,
    )
    assert (
        await fallback.decide(
            DecisionRequest("task", (("choices", "a,b"),), output_schema="choice")
        )
    ).label == "a"
    with pytest.raises(ValueError):
        await fallback.decide(
            DecisionRequest("task", (("choices", '["a", "a"]'),), output_schema="choice")
        )
    noul_transport = ScriptedTransport(
        [
            (
                "POST",
                "/v1/systemone",
                {"model": "jev", "answers": {"decision": {"type": "noul", "noul": 0.6}}},
            )
        ]
    )
    noul = JevDecisionProvider(
        JevConfiguration(model="jev", credential_ref="ref"),
        noul_transport,
        credential_resolver=_credential,
    )
    assert (
        await noul.decide(
            DecisionRequest("task", (("criteria", '{"true":"yes"}'),), output_schema="noul")
        )
    ).label == "yes"


@pytest.mark.asyncio
async def test_jev_health_and_transport_failures_remain_normalized() -> None:
    invalid_secret = JevDecisionProvider(
        JevConfiguration(credential_ref="ref"),
        ScriptedTransport([]),
        credential_resolver=_invalid_secret,
    )
    assert (
        await invalid_secret.health_check()
    ).detail == ProviderErrorReason.AUTHENTICATION_FAILED.value
    timeout = JevDecisionProvider(
        JevConfiguration(credential_ref="ref"),
        ScriptedTransport(
            [("GET", "/v1/models", ProviderAdapterError(ProviderErrorReason.TIMEOUT))]
        ),
        credential_resolver=_credential,
    )
    assert (await timeout.health_check()).detail == ProviderErrorReason.TIMEOUT.value
    unavailable = JevDecisionProvider(
        JevConfiguration(credential_ref="ref"),
        ScriptedTransport([("GET", "/v1/models", RuntimeError("offline"))]),
        credential_resolver=_credential,
    )
    assert (
        await unavailable.health_check()
    ).detail == ProviderErrorReason.PROVIDER_UNAVAILABLE.value
    malformed = JevDecisionProvider(
        JevConfiguration(credential_ref="ref"),
        ScriptedTransport([("GET", "/v1/models", {"models": [3]})]),
        credential_resolver=_credential,
    )
    with pytest.raises(ProviderAdapterError):
        await malformed.discover_models()

    with pytest.raises(ValueError):
        await malformed.decide(object())  # type: ignore[arg-type]
    timeout_decision = JevDecisionProvider(
        JevConfiguration(credential_ref="ref"),
        ScriptedTransport(
            [
                (
                    "POST",
                    "/v1/systemone",
                    ProviderAdapterError(ProviderErrorReason.TIMEOUT),
                )
            ]
        ),
        credential_resolver=_credential,
    )
    with pytest.raises(TimeoutError):
        await timeout_decision.decide(DecisionRequest("task", (), output_schema="noul"))
    out_of_range = JevDecisionProvider(
        JevConfiguration(credential_ref="ref"),
        ScriptedTransport(
            [
                (
                    "POST",
                    "/v1/systemone",
                    {
                        "model": "jev",
                        "answers": {
                            "decision": {
                                "type": "score",
                                "score": 99,
                                "confidence": 0.5,
                                "probabilities": {"0": 1.0},
                            }
                        },
                    },
                )
            ]
        ),
        credential_resolver=_credential,
    )
    with pytest.raises(ValueError):
        await out_of_range.decide(DecisionRequest("task", (), output_schema="score"))

    class CloseFixture(ScriptedTransport):
        def __init__(self) -> None:
            super().__init__([])
            self.closed = False

        async def aclose(self) -> None:
            self.closed = True

    close_fixture = CloseFixture()
    close_provider = JevDecisionProvider(
        JevConfiguration(credential_ref="ref"), close_fixture, credential_resolver=_credential
    )
    assert close_provider.intelligence_kinds == frozenset({IntelligenceKind.DECISION.value})
    await close_provider.aclose()
    assert close_fixture.closed is True
    await JevDecisionProvider(
        JevConfiguration(credential_ref="ref"),
        ScriptedTransport([]),
        credential_resolver=_credential,
    ).aclose()

    class SyncCloseFixture(ScriptedTransport):
        def __init__(self) -> None:
            super().__init__([])
            self.closed = False

        def aclose(self) -> None:
            self.closed = True

    sync_close_fixture = SyncCloseFixture()
    await JevDecisionProvider(
        JevConfiguration(credential_ref="ref"),
        sync_close_fixture,
        credential_resolver=_credential,
    ).aclose()
    assert sync_close_fixture.closed is True

    no_credential = JevDecisionProvider(
        JevConfiguration(), ScriptedTransport([("GET", "/v1/models", {"models": []})])
    )
    assert (await no_credential.health_check()).available is False
    healthy = JevDecisionProvider(
        JevConfiguration(credential_ref="ref"),
        ScriptedTransport([("GET", "/v1/models", {"models": []})]),
        credential_resolver=_credential,
    )
    assert (await healthy.health_check()).available is True
    with pytest.raises(PermissionError):
        await JevDecisionProvider(
            JevConfiguration(credential_ref="ref"),
            ScriptedTransport([]),
        ).discover_models()
    with pytest.raises(ProviderAdapterError):
        await JevDecisionProvider(
            JevConfiguration(credential_ref="ref"),
            ScriptedTransport(
                [("GET", "/v1/models", ProviderAdapterError(ProviderErrorReason.TIMEOUT))]
            ),
            credential_resolver=_credential,
        ).discover_models()

    class NonMappingTransport:
        async def request(
            self,
            method: str,
            path: str,
            payload: Mapping[str, object] | None,
            headers: Mapping[str, str],
        ) -> object:
            del method, path, payload, headers
            return object()

    with pytest.raises(ValueError, match="response is malformed"):
        await JevDecisionProvider(
            JevConfiguration(credential_ref="ref"),
            NonMappingTransport(),  # type: ignore[arg-type]
            credential_resolver=_credential,
        ).decide(DecisionRequest("task", (), output_schema="noul"))

    for response, output_schema in (
        (
            {
                "model": "jev",
                "answers": {
                    "decision": {
                        "type": "score",
                        "score": "bad",
                        "confidence": 0.5,
                        "probabilities": {"0": 1.0},
                    }
                },
            },
            "score",
        ),
        (
            {
                "model": "jev",
                "answers": {
                    "decision": {
                        "type": "noul",
                        "noul": 2.0,
                    }
                },
            },
            "noul",
        ),
        (
            {
                "model": "",
                "answers": {
                    "decision": {
                        "type": "noul",
                        "noul": 0.5,
                    }
                },
            },
            "noul",
        ),
    ):
        with pytest.raises(ValueError):
            await JevDecisionProvider(
                JevConfiguration(credential_ref="ref"),
                ScriptedTransport([("POST", "/v1/systemone", response)]),
                credential_resolver=_credential,
            ).decide(DecisionRequest("task", (), output_schema=output_schema))
    with pytest.raises(ValueError):
        await JevDecisionProvider(
            JevConfiguration(credential_ref="ref"),
            ScriptedTransport(
                [
                    (
                        "POST",
                        "/v1/systemone",
                        {
                            "model": "jev",
                            "answers": {
                                "decision": {
                                    "type": "choice",
                                    "choice": "yes",
                                    "confidence": 0.5,
                                    "probabilities": {"yes": 1.0, "no": 0.0},
                                }
                            },
                        },
                    )
                ]
            ),
            credential_resolver=_credential,
        ).decide(DecisionRequest("task", (("choices", "{}"),), output_schema="choice"))
    malformed_answers = JevDecisionProvider(
        JevConfiguration(credential_ref="ref"),
        ScriptedTransport(
            [
                (
                    "POST",
                    "/v1/systemone",
                    {
                        "model": "jev",
                        "answers": {
                            "decision": {
                                "type": "score",
                                "score": 1,
                                "confidence": 0.5,
                                "probabilities": {"0": 1.0},
                            }
                        },
                    },
                )
            ]
        ),
        credential_resolver=_credential,
    )
    with pytest.raises(ValueError):
        await malformed_answers.decide(DecisionRequest("task", (), output_schema="score"))
    authority_response = JevDecisionProvider(
        JevConfiguration(credential_ref="ref"),
        ScriptedTransport(
            [
                (
                    "POST",
                    "/v1/systemone",
                    {
                        "model": "jev",
                        "nested": [{"permission": "approved"}],
                        "answers": {"decision": {"type": "noul", "noul": 0.5}},
                    },
                )
            ]
        ),
        credential_resolver=_credential,
    )
    with pytest.raises(ValueError):
        await authority_response.decide(DecisionRequest("task", (), output_schema="noul"))
    with pytest.raises(ProviderAdapterError):
        await JevDecisionProvider(
            JevConfiguration(credential_ref="ref"),
            ScriptedTransport(
                [("GET", "/v1/models", ProviderAdapterError(ProviderErrorReason.TIMEOUT))]
            ),
            credential_resolver=_credential,
        ).discover_models()
    with pytest.raises(ProviderAdapterError):
        await JevDecisionProvider(
            JevConfiguration(credential_ref="ref"),
            ScriptedTransport([("GET", "/v1/models", {"models": "bad"})]),
            credential_resolver=_credential,
        ).discover_models()


def test_provider_support_matrix_retains_truthful_28_package_contract() -> None:
    rows = provider_support_matrix()
    assert len(rows) == 28
    assert all(row.catalog_present and row.package_present for row in rows)
    assert all(row.physical_status == "PHYSICAL_VALIDATION_REQUIRED" for row in rows)
    assert all("secret" not in str(row).casefold() for row in rows)
    by_id = {row.provider_id: row for row in rows}
    assert by_id["ai21"].discovery_mode == "NOT_SUPPORTED"
    assert by_id["typesafe-jev"].intelligence_kinds == ("decision",)
    assert by_id["amazon-bedrock"].credential_type == "service_account"
    assert by_id["openai-compatible"].protocol_family == "openai_compatible"


def test_catalog_aliases_and_catalog_only_finalization_remain_truthful() -> None:
    assert catalog_module.provider_manifest("google") is catalog_module.provider_manifest(
        "google-gemini"
    )
    assert (
        catalog_module.provider_manifest("openai_compatible_provider").provider_id
        == "openai-compatible"
    )
    with pytest.raises(KeyError):
        catalog_module.provider_manifest("does-not-exist")
    future = ProviderPackageManifest(
        "future-package",
        "Future package",
        frozenset({IntelligenceKind.GENERATIVE}),
        official_website="https://future.example/docs",
        dynamic_model_discovery=True,
        usability_probe=True,
    )
    finalized = catalog_module._finalize_manifests((future,))
    assert finalized[0].support_status is PackageSupportStatus.CATALOG_ONLY
    assert finalized[0].dynamic_model_discovery is False
    assert finalized[0].official_protocol_sources == ("https://future.example/docs",)


def test_provider_contract_validation_rejects_untrusted_metadata() -> None:
    with pytest.raises(ValueError):
        ProviderSetupField("name", "label", required="yes")  # type: ignore[arg-type]
    with pytest.raises(ValueError):
        ProviderPackageManifest(
            "fixture",
            "Fixture",
            frozenset({IntelligenceKind.GENERATIVE}),
            required_fields=(ProviderSetupField("same", "Required"),),
            optional_fields=(ProviderSetupField("same", "Optional"),),
        )
    with pytest.raises(ValueError):
        ProviderPackageManifest(
            "fixture",
            "Fixture",
            frozenset({IntelligenceKind.GENERATIVE}),
            official_website="javascript:unsafe",
        )
    with pytest.raises(ValueError):
        ProviderPackageManifest(
            "fixture",
            "Fixture",
            frozenset({IntelligenceKind.GENERATIVE}),
            dynamic_model_discovery=1,  # type: ignore[arg-type]
        )
    with pytest.raises(ValueError):
        ProviderPackageManifest(
            "fixture",
            "Fixture",
            frozenset({IntelligenceKind.GENERATIVE}),
            key_creation_instructions="x" * 4_001,
        )
    with pytest.raises(ValueError):
        ProviderPackageManifest(
            "fixture",
            "Fixture",
            frozenset({IntelligenceKind.GENERATIVE}),
            lifecycle="available",  # type: ignore[arg-type]
        )
    executable = ProviderPackageManifest(
        "fixture",
        "Fixture",
        frozenset({IntelligenceKind.GENERATIVE}),
        support_status=PackageSupportStatus.CONTROLLED_PROTOCOL_TESTED,
    )
    assert executable.package_present is True
    assert executable.adapter_present is True
    assert executable.source_executable is True

    now = datetime(2026, 9, 22, tzinfo=UTC)
    assert (
        CostEvidence(CostStatus.KNOWN, 1.0, 2.0, observed_at=now, expires_at=now).total_per_million
        == 3.0
    )
    assert CostEvidence().total_per_million is None
    assert CostEvidence(CostStatus.KNOWN, 1.0, None).total_per_million is None
    with pytest.raises(ValueError):
        CostEvidence(status="known")  # type: ignore[arg-type]
    for invalid in (
        float("nan"),
        float("inf"),
        -1.0,
    ):
        with pytest.raises(ValueError):
            CostEvidence(CostStatus.KNOWN, invalid, 1.0)
    with pytest.raises(ValueError):
        CostEvidence(
            CostStatus.KNOWN,
            1.0,
            1.0,
            observed_at=now,
            expires_at=datetime(2026, 9, 21, tzinfo=UTC),
        )
    with pytest.raises(ValueError):
        CostEvidence(CostStatus.KNOWN, observed_at=datetime(2026, 9, 22))
    with pytest.raises(ValueError):
        CostEvidence(CostStatus.KNOWN, user_override=1)  # type: ignore[arg-type]
    with pytest.raises(ValueError):
        UsageReceipt("route", input_tokens=-1)
    with pytest.raises(ValueError):
        UsageReceipt("route", actual_cost=float("inf"))
    with pytest.raises(ValueError):
        UsageReceipt("route", observed_at=datetime(2026, 9, 22))
    with pytest.raises(ValueError):
        ProviderPackageManifest("bad\x00id", "Fixture", frozenset({IntelligenceKind.GENERATIVE}))
    with pytest.raises(ValueError):
        ProviderPackageManifest("fixture", "Fixture", frozenset())
    with pytest.raises(ValueError):
        ProviderPackageManifest(
            "fixture",
            "Fixture",
            frozenset({"generative"}),  # type: ignore[arg-type]
        )
    with pytest.raises(ValueError):
        ProviderPackageManifest(
            "fixture",
            "Fixture",
            frozenset({IntelligenceKind.GENERATIVE}),
            locality="remote",  # type: ignore[arg-type]
        )
    with pytest.raises(ValueError):
        ProviderPackageManifest(
            "fixture",
            "Fixture",
            frozenset({IntelligenceKind.GENERATIVE}),
            authentication="api_key",  # type: ignore[arg-type]
        )
    with pytest.raises(ValueError):
        ProviderPackageManifest(
            "fixture",
            "Fixture",
            frozenset({IntelligenceKind.GENERATIVE}),
            required_fields=(object(),),  # type: ignore[arg-type]
        )


def test_decision_contracts_preserve_advisory_and_privacy_boundaries() -> None:
    with pytest.raises(ValueError):
        DecisionRequest("task", (("key", "value"),), correlation_id="\x00")
    with pytest.raises(ValueError):
        DecisionResult("label", confidence=float("nan"))
    with pytest.raises(ValueError):
        DecisionResult("label", recommendation="permission_granted")
    assert (
        DecisionResult.from_mapping(
            {"label": "yes", "scores": {"yes": 0.8}, "evidence": ["fixture"]},
            provider_id="fixture",
        ).provider_id
        == "fixture"
    )
    assert (
        DecisionResult.from_mapping(
            {"label": "no", "scores": (("no", 1.0),)}, model_id="model"
        ).model_id
        == "model"
    )
    with pytest.raises(ValueError):
        DecisionResult.from_mapping({"permission_granted": True})

    privacy = RemoteIntelligencePrivacyGateway(local_values=("secret", "secret"))
    from jarvis.ai.models import PrivacyClassification, PrivacyContext

    payload = privacy.prepare(
        IntelligenceKind.DECISION,
        {"text": "public secret"},
        PrivacyContext(PrivacyClassification.SANITIZABLE),
        correlation_id="corr",
    )
    assert payload.fields == (("text", "public <LOCAL_PRIVATE>"),)
    with pytest.raises(PermissionError):
        privacy.prepare(
            IntelligenceKind.DECISION,
            {"text": "<LOCAL_PRIVATE>"},
            PrivacyContext(PrivacyClassification.UNKNOWN),
        )
    with pytest.raises(PermissionError):
        privacy.prepare(
            IntelligenceKind.DECISION,
            {"text": "secret"},
            PrivacyContext(PrivacyClassification.SECRET),
        )
    assert (
        privacy.validate_inbound("safe output", PrivacyContext(PrivacyClassification.SAFE_PUBLIC))
        == "safe output"
    )
    validated = privacy.validate_inbound(
        DecisionResult("safe"), PrivacyContext(PrivacyClassification.SAFE_PUBLIC)
    )
    assert isinstance(validated, DecisionResult)
    assert validated.label == "safe"
    with pytest.raises(ValueError):
        privacy.validate_inbound("secret output", PrivacyContext(PrivacyClassification.SAFE_PUBLIC))

    route = catalog_module.provider_manifest("openai")
    assert route.provider_id == "openai"
    with pytest.raises(ValueError):
        RemoteIntelligencePrivacyGateway(local_values=["not-a-tuple"])  # type: ignore[arg-type]
    with pytest.raises(ValueError):
        RemoteIntelligencePrivacyGateway().prepare(
            cast(Any, "decision"),
            {},
            PrivacyContext(PrivacyClassification.SAFE_PUBLIC),
        )
    with pytest.raises(ValueError):
        RemoteIntelligencePrivacyGateway().validate_inbound(
            "safe",
            object(),  # type: ignore[arg-type]
        )
    with pytest.raises(ValueError):
        RemoteIntelligencePrivacyGateway(local_values=("secret",)).validate_inbound(
            "secret", PrivacyContext(PrivacyClassification.SAFE_PUBLIC)
        )

    route_identity = ExactRouteIdentity("provider", "https://provider.example", "model")
    assert '"provider"' in route_identity.storage_key
    with pytest.raises(ValueError):
        ExactRouteIdentity("provider", "https://provider.example", "model", inference_kind="bad")  # type: ignore[arg-type]
    with pytest.raises(ValueError):
        ExactRouteIdentity.from_model_identity(object())
    with pytest.raises(ValueError):
        RemoteSafePayload("bad", (), PrivacyClassification.SAFE_PUBLIC)  # type: ignore[arg-type]
    with pytest.raises(ValueError):
        RemoteSafePayload(IntelligenceKind.DECISION, (), PrivacyClassification.SECRET)
    with pytest.raises(ValueError):
        RemoteSafePayload(
            IntelligenceKind.DECISION, (("key", "value"),) * 129, PrivacyClassification.SAFE_PUBLIC
        )
    gateway = RemoteIntelligencePrivacyGateway(local_values=("<LOCAL_PRIVATE>",))
    with pytest.raises(PermissionError):
        gateway.prepare(
            IntelligenceKind.DECISION,
            {"text": "<LOCAL_PRIVATE>"},
            PrivacyContext(PrivacyClassification.SANITIZABLE),
        )
    with pytest.raises(ValueError):
        gateway.validate_inbound("x" * 1_000_001, PrivacyContext(PrivacyClassification.SAFE_PUBLIC))
    with pytest.raises(ValueError):
        UsageReceipt("route", observed_at=datetime(2026, 9, 22))
    with pytest.raises(ValueError):
        UsageReceipt("route", currency="")
    with pytest.raises(ValueError):
        UsageReceipt("route", receipt_id="\x00")


def test_remaining_decision_and_manifest_validation_edges_are_explicit() -> None:
    with pytest.raises(ValueError):
        ProviderPackageManifest("bad\x7f", "Fixture", frozenset({IntelligenceKind.GENERATIVE}))
    with pytest.raises(ValueError):
        ProviderPackageManifest(
            "fixture",
            "Fixture",
            frozenset({IntelligenceKind.GENERATIVE}),
            official_protocol_sources=("not-a-url",),
        )
    with pytest.raises(ValueError):
        DecisionRequest(
            "task",
            cast(Any, []),
        )
    with pytest.raises(ValueError):
        DecisionRequest("task", (), privacy_context=cast(Any, object()))
    with pytest.raises(ValueError):
        DecisionResult("label", scores=[("score", 1.0)])  # type: ignore[arg-type]
    with pytest.raises(ValueError):
        DecisionResult("label", scores=(("score", float("inf")),))
    assert DecisionResult("label", recommendation="ordinary advice").label == "label"
    with pytest.raises(ValueError):
        DecisionResult("label", evidence=("",))
    with pytest.raises(ValueError):
        DecisionResult("label", observed_at=datetime(2026, 9, 22))
    with pytest.raises(ValueError):
        DecisionResult.from_mapping(object())  # type: ignore[arg-type]


@pytest.mark.asyncio
async def test_callable_decision_provider_validates_callback_results() -> None:
    async def callback(request: DecisionRequest) -> DecisionResult:
        assert request.task == "classify"
        return DecisionResult("safe")

    provider = CallableDecisionProvider(callback, "local-fixture")
    assert (await provider.decide(DecisionRequest("classify", ()))).label == "safe"

    async def bad_callback(request: DecisionRequest) -> object:
        del request
        return "not a decision"

    with pytest.raises(ValueError):
        await CallableDecisionProvider(bad_callback).decide(DecisionRequest("classify", ()))  # type: ignore[arg-type]
    with pytest.raises(ValueError):
        CallableDecisionProvider(None)  # type: ignore[arg-type]
    assert provider.intelligence_kinds == frozenset({IntelligenceKind.DECISION.value})


def test_registry_validates_and_owns_dynamic_provider_metadata() -> None:
    provider = OpenAICompatibleProvider(
        OpenAICompatibleConfiguration("fixture", "https://provider.example/v1", model="fixture"),
        ScriptedTransport([("GET", "/models", {"data": []})]),
    )
    model = ModelMetadata(
        "fixture",
        2048,
        capabilities=frozenset({"chat"}),
        roles=frozenset({ModelRole.GENERAL}),
        source="fixture",
        lifecycle=ModelLifecycle.ACTIVE,
    )
    definition = ProviderDefinition(
        ProviderMetadata("fixture", "Fixture", "1", locality=ProviderLocality.LOCAL),
        lambda configuration: provider,
        (model,),
    )
    registry = ProviderRegistry((definition,))
    assert registry.provider_ids() == ("fixture",)
    assert registry.definition("FIXTURE").models == (model,)
    assert registry.definitions()[0][0] == "fixture"
    with pytest.raises(ValueError):
        registry.register(definition)
    with pytest.raises(ValueError):
        registry.replace_models("fixture", (model, model))
    with pytest.raises(ValueError):
        registry.replace_models("fixture", (object(),))  # type: ignore[arg-type]

    registry.register_intelligence("decision-fixture", lambda configuration: ProbeStub(True))
    with pytest.raises(ValueError):
        registry.register_intelligence("decision-fixture", lambda configuration: ProbeStub(True))
    with pytest.raises(KeyError):
        registry.create_intelligence("missing", {})
    registry.register_intelligence("bad", lambda configuration: object())
    with pytest.raises(TypeError):
        registry.create_intelligence("bad", {})
    registry.replace_intelligence_models("decision-fixture", (model,))
    with pytest.raises(ValueError):
        registry.replace_intelligence_models("decision-fixture", (model, model))

    package = ProviderPackageManifest(
        "fixture-package",
        "Fixture package",
        frozenset({IntelligenceKind.GENERATIVE}),
        support_status=PackageSupportStatus.CONTRACT_ONLY,
    )
    registry.register_package(package)
    assert registry.package("FIXTURE-PACKAGE") == package
    with pytest.raises(ValueError):
        registry.register_package(package)
    with pytest.raises(KeyError):
        registry.package("missing")


def test_registry_voice_and_locality_contracts_are_typed() -> None:
    registry = ProviderRegistry()
    voice = VoiceProviderDefinition(
        VoiceProviderKind.STT,
        ProviderMetadata("fixture-stt", "Fixture STT", "1", locality=ProviderLocality.LOCAL),
        lambda configuration: DisabledSttProvider(),
    )
    registry.register_voice(voice)
    assert registry.voice_provider_ids(VoiceProviderKind.STT) == ("fixture-stt",)
    assert registry.voice_definitions(VoiceProviderKind.STT)[0][0] == "fixture-stt"
    assert isinstance(
        registry.create_voice(VoiceProviderKind.STT, "fixture-stt", {}), DisabledSttProvider
    )
    with pytest.raises(ValueError):
        registry.voice_provider_ids("stt")  # type: ignore[arg-type]
    with pytest.raises(KeyError):
        registry.voice_definition(VoiceProviderKind.TTS, "missing")
    with pytest.raises(ValueError):
        ProviderMetadata(
            "remote-local", "bad", "1", local_only=True, locality=ProviderLocality.REMOTE
        )

    tts = VoiceProviderDefinition(
        VoiceProviderKind.TTS,
        ProviderMetadata("fixture-tts", "Fixture TTS", "1", locality=ProviderLocality.LOCAL),
        lambda configuration: DisabledTtsProvider(),
    )
    registry.register_voice(tts)
    assert isinstance(
        registry.create_voice(VoiceProviderKind.TTS, "fixture-tts", {}), DisabledTtsProvider
    )
    with pytest.raises(ValueError):
        registry.register_voice(voice)
    wrong_stt = VoiceProviderDefinition(
        VoiceProviderKind.STT,
        ProviderMetadata("wrong-stt", "Wrong", "1"),
        lambda configuration: DisabledTtsProvider(),
    )
    registry.register_voice(wrong_stt)
    with pytest.raises(TypeError):
        registry.create_voice(VoiceProviderKind.STT, "wrong-stt", {})
    wrong_tts = VoiceProviderDefinition(
        VoiceProviderKind.TTS,
        ProviderMetadata("wrong-tts", "Wrong", "1"),
        lambda configuration: DisabledSttProvider(),
    )
    registry.register_voice(wrong_tts)
    with pytest.raises(TypeError):
        registry.create_voice(VoiceProviderKind.TTS, "wrong-tts", {})

    with pytest.raises(ValueError):
        ProviderMetadata("invalid", "bad", "1", locality="remote")  # type: ignore[arg-type]


@pytest.mark.parametrize(
    "changes",
    (
        {"model_id": ""},
        {"context_limit": 0},
        {"capabilities": frozenset({""})},
        {"roles": frozenset({"general"})},
        {"storage_bytes": -1},
        {"max_concurrency": 0},
        {"quality_score": float("nan")},
        {"lifecycle": "active"},
        {"endpoint": "\x00"},
        {"discovered_at": datetime(2026, 9, 22)},
    ),
)
def test_model_metadata_rejects_invalid_resource_cost_and_route_facts(
    changes: dict[str, object],
) -> None:
    values: dict[str, object] = {"model_id": "fixture", "context_limit": 1024}
    values.update(changes)
    with pytest.raises(ValueError):
        ModelMetadata(**values)  # type: ignore[arg-type]


def test_registry_definition_and_advertisement_validation_is_fail_closed() -> None:
    with pytest.raises(ValueError):
        ProviderDefinition(
            ProviderMetadata("", "Empty", "1"), lambda configuration: cast(Any, object())
        )
    with pytest.raises(ValueError):
        ProviderDefinition(ProviderMetadata("fixture", "Fixture", "1"), None)  # type: ignore[arg-type]
    with pytest.raises(ValueError):
        VoiceProviderDefinition(
            cast(Any, "stt"),
            ProviderMetadata("voice", "Voice", "1"),
            lambda configuration: DisabledSttProvider(),
        )
    with pytest.raises(ValueError):
        VoiceProviderDefinition(
            VoiceProviderKind.STT,
            ProviderMetadata("voice", "Voice", "1"),
            lambda configuration: DisabledSttProvider(),
            models=(object(),),  # type: ignore[arg-type]
        )
    registry = ProviderRegistry()
    with pytest.raises(ValueError):
        registry.register_intelligence("", lambda configuration: ProbeStub(True))
    with pytest.raises(ValueError):
        registry.register_intelligence("fixture", object())  # type: ignore[arg-type]
    registry.register_intelligence("fixture", lambda configuration: ProbeStub(True))
    with pytest.raises(KeyError):
        registry.replace_intelligence_models("missing", ())
    registry2 = ProviderRegistry(
        (
            ProviderDefinition(
                ProviderMetadata("fixture", "Fixture", "1"),
                lambda configuration: cast(Any, object()),
            ),
        )
    )
    registry2.register_intelligence("fixture", lambda configuration: ProbeStub(True))
    with pytest.raises(KeyError):
        registry2.replace_intelligence_models("fixture", ())
    with pytest.raises(ValueError):
        ModelMetadata("fixture", 1024, family="x" * 257)
    with pytest.raises(ValueError):
        ModelMetadata("fixture", 1024, modalities=frozenset({""}))
    with pytest.raises(ValueError):
        ModelMetadata("fixture", 1024, compatibility=frozenset({"\x00"}))
    with pytest.raises(ValueError):
        ModelMetadata("fixture", 1024, evidence=(object(),))  # type: ignore[arg-type]
    with pytest.raises(ValueError):
        ModelMetadata("fixture", 1024, verified_at=datetime(2026, 9, 22))
    with pytest.raises(ValueError):
        registry.register_package(object())
    package_registry = ProviderRegistry()
    package_registry.register_package(catalog_module.provider_manifest("openai"))
    created = package_registry.create("openai", {"model": "fixture"})
    assert isinstance(created, OpenAICompatibleProvider)
    assert created.configuration.provider_id == "openai"
    with pytest.raises(ValueError):
        registry.voice_definitions("stt")  # type: ignore[arg-type]
    with pytest.raises(ValueError):
        registry.voice_definition("stt", "fixture-stt")  # type: ignore[arg-type]
    with pytest.raises(ValueError):
        VoiceProviderDefinition(
            VoiceProviderKind.STT,
            ProviderMetadata("voice-invalid", "Voice", "1"),
            None,  # type: ignore[arg-type]
        )


@pytest.mark.asyncio
async def test_registry_health_usability_model_and_create_routes_are_owned_by_definitions(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def make_provider(configuration: Mapping[str, object]) -> AIProvider:
        return OpenAICompatibleProvider(
            OpenAICompatibleConfiguration(
                "fixture",
                "https://provider.example/v1",
                model=str(configuration.get("model", "fixture")),
            ),
            ScriptedTransport([("GET", "/models", {"data": []})]),
        )

    model = ModelMetadata("fixture", 1024)
    registry = ProviderRegistry(
        (ProviderDefinition(ProviderMetadata("fixture", "Fixture", "1"), make_provider, (model,)),)
    )
    provider = registry.create("fixture", {"model": "fixture"})
    assert (await registry.health("fixture", provider)).available is True
    evidence = await registry.probe_usability("fixture", {"model": "fixture"})
    assert evidence.provider_id == "fixture" and evidence.model_id == "fixture"

    async def native_probe(self: OpenAICompatibleProvider) -> ModelUsabilityEvidence:
        return ModelUsabilityEvidence(
            configured=True,
            connected=True,
            reachable=True,
            provider_id=self.configuration.provider_id,
            model_id=self.configuration.model,
            reason=UsabilityReason.UNKNOWN,
            source="fixture.native_probe",
        )

    monkeypatch.setattr(OpenAICompatibleProvider, "probe_usability", native_probe)
    native_evidence = await registry.probe_usability("fixture", {"model": "fixture"})
    assert native_evidence.source == "fixture.native_probe"
    assert (await registry.model("fixture", provider)).model_id == "fixture"
    unknown = await registry.model("fixture", make_provider({"model": "new-model"}))
    assert unknown.model_id == "new-model"

    intelligence_provider = OpenAICompatibleProvider(
        OpenAICompatibleConfiguration("intelligence", "https://provider.example/v1"),
        ScriptedTransport([]),
    )
    registry.register_intelligence("intelligence", lambda configuration: intelligence_provider)
    assert registry.create("intelligence", {}) is intelligence_provider
    registry.register_intelligence("not-generative", lambda configuration: ProbeStub(True))
    with pytest.raises(TypeError):
        registry.create("not-generative", {})
    with pytest.raises(KeyError):
        registry.definition("missing")


def test_model_discovery_updates_generative_and_decision_owners() -> None:
    generative = ProviderDefinition(
        ProviderMetadata("fixture", "Fixture", "1"),
        cast(Any, lambda configuration: ProbeStub(True)),
    )
    registry = ProviderRegistry((generative,))
    service = ModelDiscoveryService(registry)
    result = service.register_snapshot(_snapshot("fixture"))
    assert result.registered_model_ids == ("fixture-model",)
    assert registry.definition("fixture").models[0].model_id == "fixture-model"
    service.register_unknown_model(
        "fixture", "future-model", observed_at=datetime(2026, 9, 22, tzinfo=UTC)
    )
    assert registry.definition("fixture").models[0].model_id == "future-model"

    registry.register_intelligence("decision", lambda configuration: ProbeStub(True))
    decision_result = service.register_snapshot(_snapshot("decision", "decision-model"))
    assert decision_result.registered_model_ids == ("decision-model",)
    assert dict(registry.intelligence_models())["decision"][0].model_id == "decision-model"
    with pytest.raises(ValueError):
        ModelDiscoveryService(object())  # type: ignore[arg-type]
    with pytest.raises(ValueError):
        service.register_snapshot(object())  # type: ignore[arg-type]
    with pytest.raises(ValueError):
        service.register_unknown_model("fixture", "")


@pytest.mark.asyncio
async def test_model_discovery_rewrites_source_and_rejects_identity_mismatch() -> None:
    registry = ProviderRegistry(
        (
            ProviderDefinition(
                ProviderMetadata("fixture", "Fixture", "1"),
                cast(Any, lambda configuration: ProbeStub(True)),
            ),
        )
    )
    service = ModelDiscoveryService(registry)
    provider = ProbeStub(True, _snapshot("fixture"))
    result = await service.discover("fixture", provider, source="manual_fixture")
    assert result.source == "manual_fixture"
    with pytest.raises(ValueError):
        await service.discover("other", provider)
    with pytest.raises(ValueError):
        await service.discover("fixture", object())  # type: ignore[arg-type]


@pytest.mark.asyncio
async def test_model_discovery_bounds_malformed_snapshots_and_refreshes_knowledge(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Any
) -> None:
    registry = ProviderRegistry(
        (
            ProviderDefinition(
                ProviderMetadata("fixture", "Fixture", "1"),
                cast(Any, lambda configuration: ProbeStub(True)),
            ),
        )
    )
    store = ModelKnowledgeStore(tmp_path / "knowledge.sqlite3")
    try:
        knowledge = ModelKnowledgeService(store)
        service = ModelDiscoveryService(registry, knowledge)
        monkeypatch.setattr(service, "MAX_MODELS", 0)
        with pytest.raises(ValueError, match="exceeds model bound"):
            service.register_snapshot(_snapshot("fixture"))
        monkeypatch.setattr(service, "MAX_MODELS", 1_024)

        class MalformedDiscoveryProvider(ProbeStub):
            async def discover_models(self) -> ProviderCatalogSnapshot | None:
                return cast(ProviderCatalogSnapshot | None, object())

        with pytest.raises(ValueError, match="catalog snapshot"):
            await service.discover("fixture", MalformedDiscoveryProvider(True))
        snapshot = _snapshot("fixture")
        result = service.register_snapshot(snapshot)
        assert result.registered_model_ids == ("fixture-model",)
        assert knowledge.store.inspect_model(snapshot.models[0].identity) is not None
    finally:
        store.close()


@pytest.mark.asyncio
async def test_onboarding_persists_secret_free_connections_and_probe_states(tmp_path: Any) -> None:
    vault = CredentialVault(
        tmp_path / "credentials.sqlite3", backend=TestOnlyInMemorySecretBackend()
    )
    connection_path = tmp_path / "provider-connections.sqlite3"
    service = ProviderOnboardingService(vault, path=connection_path)
    assert len(service.catalog()) == 28
    assert service.help("openai").provider_id == "openai"
    assert service.validate_configuration("openai", {}) == ("api_credential",)
    with pytest.raises(ValueError):
        service.validate_configuration("openai", {"unexpected": "value"})
    with pytest.raises(ValueError):
        service.validate_configuration("openai-compatible", {"base_url": "ftp://bad"})
    with pytest.raises(ValueError):
        service.validate_configuration("openai", {"api_credential": "raw"}, secret_provided=True)

    connected = service.connect(
        "openai", configuration={}, secret="fixture-secret", label="fixture"
    )
    assert connected.authentication_state == "credential_stored"
    assert connected.configuration == ()
    assert service.credential_status("openai") is not None
    restarted = ProviderOnboardingService(vault, path=connection_path)
    assert restarted.connection("openai") == connected
    blocked = restarted.set_routing_policy("openai", ProviderPolicy.BLOCKED)
    assert blocked.routing_policy is ProviderPolicy.BLOCKED
    assert restarted.record_authentication("openai", authenticated=False).usable is False
    assert restarted.record_discovery("openai", usable=False).discovery_state == "discovered"
    deleted = restarted.delete_credential("openai")
    assert deleted.credential_id is None and restarted.credential_status("openai") is None
    disconnected = restarted.disconnect("openai")
    assert disconnected.routing_policy is ProviderPolicy.ROUTING_DISABLED

    with pytest.raises(ValueError):
        ProviderOnboardingService(object())  # type: ignore[arg-type]


@pytest.mark.asyncio
async def test_onboarding_probe_distinguishes_auth_failure_discovery_failure_and_success(
    tmp_path: Any,
) -> None:
    vault = CredentialVault(
        tmp_path / "credentials.sqlite3", backend=TestOnlyInMemorySecretBackend()
    )
    registry = ProviderRegistry(
        (
            ProviderDefinition(
                ProviderMetadata("openai", "OpenAI", "1"),
                cast(Any, lambda configuration: ProbeStub(True)),
            ),
        )
    )
    discovery = ModelDiscoveryService(registry)
    service = ProviderOnboardingService(vault, registry=registry, discovery=discovery)
    service.connect("openai", configuration={}, secret="fixture-secret")
    failed_auth = await service.probe("openai", ProbeStub(False))
    assert failed_auth.authentication_state == "failed"
    failed_discovery = await service.probe(
        "openai", ProbeStub(True, discovery_error=RuntimeError("fixture discovery failure"))
    )
    assert failed_discovery.discovery_state == "discovered" and failed_discovery.usable is False
    successful = await service.probe("openai", ProbeStub(True, _snapshot("openai")))
    assert successful.authentication_state == "authenticated" and successful.usable is True
    no_discovery_service = ProviderOnboardingService(vault, registry=registry)
    no_discovery_service.connect("openai", configuration={}, secret="fixture-secret")
    no_discovery = await no_discovery_service.probe("openai", ProbeStub(True))
    assert no_discovery.discovery_state == "discovered" and no_discovery.usable is None

    class HealthErrorProvider(IntelligenceProvider):
        async def health_check(self) -> ProviderHealth:
            raise RuntimeError("fixture health failure")

    health_failure = await service.probe("openai", HealthErrorProvider())
    assert health_failure.authentication_state == "failed"
    with pytest.raises(ValueError):
        await service.probe("openai", object())  # type: ignore[arg-type]
    empty_service = ProviderOnboardingService(vault)
    with pytest.raises(KeyError):
        await empty_service.probe("openai", ProbeStub(False))


def test_onboarding_handles_authentication_modes_and_revocation_lifecycle(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Any
) -> None:
    vault = CredentialVault(
        tmp_path / "credentials.sqlite3", backend=TestOnlyInMemorySecretBackend()
    )
    service = ProviderOnboardingService(vault)

    def manifest_for(provider_id: str) -> ProviderPackageManifest:
        if provider_id == "no-auth":
            return ProviderPackageManifest(
                "no-auth",
                "No Auth",
                frozenset({IntelligenceKind.GENERATIVE}),
                authentication=AuthenticationType.NONE,
                support_status=PackageSupportStatus.CONTROLLED_PROTOCOL_TESTED,
            )
        return ProviderPackageManifest(
            "api-auth",
            "API Auth",
            frozenset({IntelligenceKind.GENERATIVE}),
            authentication=AuthenticationType.API_KEY,
            support_status=PackageSupportStatus.CONTROLLED_PROTOCOL_TESTED,
        )

    monkeypatch.setattr("jarvis.ai.onboarding.provider_manifest", manifest_for)
    no_auth = service.connect("no-auth", configuration={})
    assert no_auth.credential_id is None
    assert no_auth.authentication_state == "not_required"
    assert service.delete_credential("no-auth").credential_id is None
    with pytest.raises(ValueError, match="credential is required"):
        service.connect("api-auth", configuration={})

    connected = service.connect("api-auth", configuration={}, secret="fixture-secret")
    assert connected.credential_id is not None
    disconnected = service.disconnect("api-auth")
    assert disconnected.authentication_state == "revoked"
    deleted = service.delete_credential("api-auth")
    assert deleted.credential_id is None


def test_onboarding_rejects_invalid_configuration_and_unconnected_transitions(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Any,
) -> None:
    vault = CredentialVault(
        tmp_path / "credentials.sqlite3", backend=TestOnlyInMemorySecretBackend()
    )
    service = ProviderOnboardingService(vault)
    with pytest.raises(ValueError):
        ProviderOnboardingService(vault, discovery=object())  # type: ignore[arg-type]
    with pytest.raises(ValueError):
        service.validate_configuration("openai-compatible", {"base_url": 3})
    with pytest.raises(ValueError):
        service.validate_configuration("openai-compatible", {"base_url": "ftp://bad"})
    with pytest.raises(ValueError):
        service.connect("amazon-bedrock", configuration={"region": "eu-west-1"})
    service.connect("openai", configuration={}, secret="fixture-secret")
    with pytest.raises(ValueError):
        service.set_routing_policy("openai", "blocked")  # type: ignore[arg-type]
    monkeypatch.setattr(
        "jarvis.ai.onboarding.provider_manifest",
        lambda provider_id: ProviderPackageManifest(
            provider_id,
            "Catalog only",
            frozenset({IntelligenceKind.GENERATIVE}),
            support_status=PackageSupportStatus.CATALOG_ONLY,
        ),
    )
    with pytest.raises(ValueError):
        service.connect("catalog-only", configuration={})

    empty = ProviderOnboardingService(vault)
    with pytest.raises(KeyError):
        empty.disconnect("openai")
    with pytest.raises(KeyError):
        empty.delete_credential("openai")
    with pytest.raises(KeyError):
        empty.record_authentication("openai", authenticated=True)
    with pytest.raises(KeyError):
        empty.record_discovery("openai")


@pytest.mark.asyncio
async def test_onboarding_probe_requires_a_health_probe(tmp_path: Any) -> None:
    vault = CredentialVault(
        tmp_path / "credentials.sqlite3", backend=TestOnlyInMemorySecretBackend()
    )
    service = ProviderOnboardingService(vault)
    service.connect("openai", configuration={}, secret="fixture-secret")
    with pytest.raises(ValueError):
        await service.probe("openai", IntelligenceProvider())


def test_model_intelligence_projection_exposes_unknown_and_exact_route_state() -> None:
    registry = ProviderRegistry()
    registry.register_package(
        ProviderPackageManifest(
            "fixture-package",
            "Fixture Package",
            frozenset({IntelligenceKind.GENERATIVE}),
            authentication=AuthenticationType.API_KEY,
            required_fields=(ProviderSetupField("base_url", "Base URL"),),
        )
    )
    registry.register_intelligence("unknown-provider", lambda configuration: ProbeStub(True))
    metadata = ModelMetadata(
        "future-model",
        4096,
        capabilities=frozenset({"chat"}),
        source="fixture",
        lifecycle=ModelLifecycle.RETIRED,
        endpoint="https://fixture.example/v1",
        region="eu-west-1",
        deployment="deploy",
        inference_kind="generative",
    )
    registry.replace_intelligence_models("unknown-provider", (metadata,))
    page = ModelIntelligenceProjection(registry).page()
    unknown = next(row for row in page.providers if row.provider_id == "unknown-provider")
    model = next(row for row in page.models if row.provider_id == "unknown-provider")
    assert unknown.package_lifecycle == ProviderLifecycle.UNKNOWN.value
    assert model.lifecycle == ModelLifecycle.RETIRED.value
    assert model.policy == ModelPolicy.AUTO_ALLOWED.value
    assert model.cost == "cost_unknown"
    assert model.endpoint == "https://fixture.example/v1"
    with pytest.raises(ValueError):
        ModelIntelligenceProjection(object())  # type: ignore[arg-type]
    with pytest.raises(ValueError):
        ModelIntelligenceProjection(registry, policies=object())  # type: ignore[arg-type]
    with pytest.raises(ValueError):
        ModelIntelligenceProjection(registry, knowledge=object())  # type: ignore[arg-type]
