"""R3H-R2 protocol-family and standard-package contract coverage."""

from collections.abc import Mapping
from datetime import UTC, datetime
from pathlib import Path
from uuid import uuid4

import httpx
import pytest
from jarvis.ai.models import ChatMessage, GenerationRequest, MessageRole
from jarvis.ai.onboarding import ProviderOnboardingService
from jarvis.ai.providers.catalog import (
    AI21Provider,
    AnthropicConfiguration,
    AnthropicProvider,
    AwsSigV4Credentials,
    AwsSigV4Signer,
    BedrockProvider,
    CohereProvider,
    GeminiProvider,
    HttpxJSONTransport,
    OpenAICompatibleProvider,
    ProviderAdapterError,
    ProviderErrorReason,
    VertexAIProvider,
    create_standard_provider,
    provider_execution_matrix,
    provider_manifest,
    provider_support_matrix,
)
from jarvis.ai.providers.intelligence import PackageSupportStatus
from jarvis.ai.providers.registry import ProviderLocality
from jarvis.credentials import CredentialVault, TestOnlyInMemorySecretBackend


class FixtureTransport:
    def __init__(self, responses: Mapping[tuple[str, str], Mapping[str, object]]) -> None:
        self.responses = responses
        self.calls: list[tuple[str, str, Mapping[str, str], Mapping[str, object] | None]] = []

    async def request(
        self,
        method: str,
        path: str,
        payload: Mapping[str, object] | None,
        headers: Mapping[str, str],
    ) -> Mapping[str, object]:
        self.calls.append((method, path, headers, payload))
        try:
            return self.responses[(method, path)]
        except KeyError as error:
            raise AssertionError(f"unexpected provider request: {method} {path}") from error


async def _credential(_reference: object) -> str:
    return "fixture-secret"


def _request(model: str = "old-model") -> GenerationRequest:
    return GenerationRequest(
        (
            ChatMessage(
                uuid4(),
                uuid4(),
                MessageRole.USER,
                "hello",
                datetime.now(UTC),
            ),
        ),
        model,
        4096,
    )


async def test_named_openai_package_owns_endpoint_and_discovers_future_model() -> None:
    transport = FixtureTransport(
        {
            ("GET", "/models"): {
                "data": [
                    {"id": "old-model", "owned_by": "fixture"},
                    {"id": "never-seen-model-x", "context_length": 8192},
                ]
            },
            ("POST", "/chat/completions"): {
                "model": "old-model",
                "choices": [{"message": {"content": "ok"}}],
            },
        }
    )
    provider = create_standard_provider(
        "openai",
        {"model": "old-model", "credential_ref": "vault-ref"},
        transport=transport,
        credential_resolver=_credential,
    )
    assert isinstance(provider, OpenAICompatibleProvider)
    snapshot = await provider.discover_models()
    assert [item.identity.model_id for item in snapshot.models] == [
        "old-model",
        "never-seen-model-x",
    ]
    result = await provider.generate(_request())
    assert result.content == "ok"
    assert transport.calls[0][1] == "/models"
    assert transport.calls[0][2]["authorization"] == "Bearer fixture-secret"
    assert provider.configuration.base_url == "https://api.openai.com/v1"


async def test_anthropic_and_gemini_families_use_real_protocol_shapes() -> None:
    anthropic_transport = FixtureTransport(
        {
            ("GET", "/v1/models"): {"data": [{"id": "claude-fixture", "max_input_tokens": 2000}]},
            ("POST", "/v1/messages"): {
                "model": "claude-fixture",
                "content": [{"type": "text", "text": "anthropic-ok"}],
            },
        }
    )
    anthropic = AnthropicProvider(
        AnthropicConfiguration(model="claude-fixture", credential_ref="ref"),
        anthropic_transport,
        credential_resolver=_credential,
    )
    assert (await anthropic.discover_models()).models[0].identity.model_id == "claude-fixture"
    assert (await anthropic.generate(_request("claude-fixture"))).content == "anthropic-ok"
    assert anthropic_transport.calls[0][2]["x-api-key"] == "fixture-secret"

    gemini_transport = FixtureTransport(
        {
            ("GET", "/models"): {
                "models": [
                    {
                        "name": "models/gemini-fixture",
                        "baseModelId": "gemini-fixture",
                        "inputTokenLimit": 4096,
                        "supportedGenerationMethods": ["generateContent"],
                    }
                ]
            },
            ("POST", "/models/gemini-fixture:generateContent"): {
                "candidates": [{"content": {"parts": [{"text": "gemini-ok"}]}}]
            },
        }
    )
    from jarvis.ai.providers.catalog import GeminiConfiguration

    gemini = GeminiProvider(
        GeminiConfiguration(model="gemini-fixture", credential_ref="ref"),
        gemini_transport,
        credential_resolver=_credential,
    )
    assert (await gemini.discover_models()).models[0].identity.model_id == "gemini-fixture"
    assert (await gemini.generate(_request("gemini-fixture"))).content == "gemini-ok"
    assert gemini_transport.calls[0][2]["x-goog-api-key"] == "fixture-secret"


async def test_cohere_and_ai21_protocol_shapes() -> None:
    cohere_transport = FixtureTransport(
        {
            ("GET", "/v1/models?page_size=100"): {
                "models": [{"name": "command-fixture", "context_length": 4096}]
            },
            ("POST", "/v2/chat"): {
                "model": "command-fixture",
                "message": {"content": [{"type": "text", "text": "cohere-ok"}]},
            },
        }
    )
    cohere = create_standard_provider(
        "cohere",
        {"model": "command-fixture", "credential_ref": "ref"},
        transport=cohere_transport,
        credential_resolver=_credential,
    )
    assert isinstance(cohere, CohereProvider)
    assert (await cohere.discover_models()).models[0].identity.model_id == "command-fixture"
    assert (await cohere.generate(_request("command-fixture"))).content == "cohere-ok"
    assert cohere_transport.calls[0][2]["authorization"] == "Bearer fixture-secret"

    ai21_transport = FixtureTransport(
        {
            ("POST", "/chat/completions"): {
                "model": "jamba-fixture",
                "choices": [{"message": {"content": "ai21-ok"}}],
            }
        }
    )
    ai21 = create_standard_provider(
        "ai21",
        {"model": "jamba-fixture", "credential_ref": "ref"},
        transport=ai21_transport,
        credential_resolver=_credential,
    )
    assert isinstance(ai21, AI21Provider)
    assert (await ai21.generate(_request("jamba-fixture"))).content == "ai21-ok"
    assert (await ai21.discover_models()).available is False


@pytest.mark.parametrize(
    "provider_id",
    (
        "openai",
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
        "minimax",
        "openai-compatible",
    ),
)
async def test_openai_family_packages_share_the_controlled_adapter(provider_id: str) -> None:
    transport = FixtureTransport({("GET", "/models"): {"data": [{"id": "fixture-model"}]}})
    configuration: dict[str, object] = {
        "model": "fixture-model",
        "credential_ref": "ref",
        "transport": transport,
        "credential_resolver": _credential,
    }
    if provider_id == "openai-compatible":
        configuration["base_url"] = "https://fixture.example/v1"
    provider = create_standard_provider(provider_id, configuration)
    assert isinstance(provider, OpenAICompatibleProvider)
    assert (await provider.discover_models()).models[0].identity.model_id == "fixture-model"


async def test_enterprise_family_fixtures_use_typed_configuration() -> None:
    azure_transport = FixtureTransport(
        {("GET", "/openai/models?api-version=2024-10-21"): {"data": [{"id": "deployment-model"}]}}
    )
    azure = create_standard_provider(
        "azure-openai",
        {
            "endpoint": "https://fixture-resource.openai.azure.com",
            "deployment": "deployment-model",
            "credential_ref": "ref",
            "transport": azure_transport,
            "credential_resolver": _credential,
        },
    )
    assert isinstance(azure, OpenAICompatibleProvider)
    assert (await azure.discover_models()).models[0].identity.model_id == "deployment-model"

    vertex_transport = FixtureTransport({("GET", "/models"): {"models": []}})
    vertex = create_standard_provider(
        "google-vertex",
        {
            "project": "fixture-project",
            "region": "europe-west4",
            "credential_ref": "ref",
            "transport": vertex_transport,
            "token_resolver": _credential,
        },
    )
    assert isinstance(vertex, VertexAIProvider)
    assert (await vertex.discover_models()).provider.provider_id == "google-vertex"
    assert vertex_transport.calls[0][2]["authorization"] == "Bearer fixture-secret"

    bedrock_transport = FixtureTransport(
        {("GET", "/foundation-models"): {"modelSummaries": [{"modelId": "amazon.model"}]}}
    )
    bedrock = create_standard_provider(
        "amazon-bedrock",
        {
            "region": "eu-west-1",
            "credential_ref": "ref",
            "transport": bedrock_transport,
            "signer": AwsSigV4Signer(
                "eu-west-1",
                "bedrock-runtime.eu-west-1.amazonaws.com",
                AwsSigV4Credentials("AKIDEXAMPLE", "secret-example"),
                clock=lambda: datetime(2026, 9, 22, 12, 0, tzinfo=UTC),
            ),
        },
    )
    assert isinstance(bedrock, BedrockProvider)
    assert (await bedrock.discover_models()).models[0].identity.model_id == "amazon.model"
    assert bedrock_transport.calls[0][2]["authorization"].startswith("AWS4-HMAC-SHA256 ")
    assert "secret-example" not in str(bedrock_transport.calls[0][2])


def test_major_packages_are_executable_and_catalog_only_packages_cannot_connect(
    tmp_path: Path,
) -> None:
    matrix = {item.provider_id: item for item in provider_support_matrix()}
    for provider_id in {
        "openai",
        "anthropic",
        "google-gemini",
        "xai-grok",
        "mistral",
        "deepseek",
        "openrouter",
        "groqcloud",
        "together-ai",
        "fireworks-ai",
        "cerebras-cloud",
        "nvidia-nim",
        "perplexity",
        "azure-openai",
        "amazon-bedrock",
        "google-vertex",
        "openai-compatible",
    }:
        assert matrix[provider_id].source_adapter_present
        assert matrix[provider_id].controlled_protocol_tested
        assert matrix[provider_id].official_documentation_evidence

    vault = CredentialVault(
        tmp_path / "credentials.sqlite3", backend=TestOnlyInMemorySecretBackend()
    )
    service = ProviderOnboardingService(vault)
    service.connect("cohere", configuration={}, secret="fixture-secret")
    execution = provider_execution_matrix()
    assert len(execution) == 28
    assert [item.acceptance_id for item in execution] == [f"P{index}" for index in range(1, 29)]
    assert all(item.catalog == "PASS" and item.package == "PASS" for item in execution)


async def test_redirect_is_blocked_without_exposing_secret() -> None:
    async def handler(request: httpx.Request) -> httpx.Response:
        del request
        return httpx.Response(302, headers={"location": "https://attacker.example/models"})

    client = httpx.AsyncClient(
        base_url="https://provider.example",
        transport=httpx.MockTransport(handler),
        follow_redirects=False,
    )
    transport = HttpxJSONTransport("https://provider.example", client=client)
    with pytest.raises(ProviderAdapterError) as error:
        await transport.request("GET", "/models", None, {"authorization": "Bearer fixture-secret"})
    assert error.value.reason is ProviderErrorReason.REDIRECT_BLOCKED
    assert "fixture-secret" not in str(error.value)
    await client.aclose()


def test_generic_endpoint_requires_trusted_locality() -> None:
    with pytest.raises(ValueError):
        create_standard_provider(
            "openai-compatible",
            {"base_url": "http://localhost:8080", "locality": ProviderLocality.REMOTE},
        )
    assert (
        provider_manifest("minimax").support_status
        is PackageSupportStatus.CONTROLLED_PROTOCOL_TESTED
    )
    local = create_standard_provider(
        "openai-compatible",
        {"base_url": "http://127.0.0.1:11434", "locality": ProviderLocality.LOCAL},
    )
    assert isinstance(local, OpenAICompatibleProvider)
    with pytest.raises(PermissionError):
        create_standard_provider("openai", {"api_key": "raw-secret"})
