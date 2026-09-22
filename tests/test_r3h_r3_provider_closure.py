"""R3H-R3 controlled protocol closure for Jev and MiniMax."""

from collections.abc import Mapping
from dataclasses import replace
from datetime import UTC, datetime, timedelta
from pathlib import Path

import httpx
import pytest
from jarvis.ai.decision import DecisionRouteCandidate, DecisionRouter
from jarvis.ai.governance import GuardedApproval, PolicyEngine, PolicyStore
from jarvis.ai.knowledge import ModelIdentity, identity_for
from jarvis.ai.model_intelligence import ModelIntelligenceProjection
from jarvis.ai.models import GenerationRequest, ModelRole, PrivacyClassification, PrivacyContext
from jarvis.ai.onboarding import ProviderOnboardingService
from jarvis.ai.providers import (
    DecisionRequest,
    DecisionResult,
    ExactRouteIdentity,
    IntelligenceKind,
    ModelPolicy,
    PackageSupportStatus,
    RemoteIntelligencePrivacyGateway,
)
from jarvis.ai.providers.catalog import (
    HttpxJSONTransport,
    JevConfiguration,
    JevDecisionProvider,
    OpenAICompatibleProvider,
    ProviderAdapterError,
    ProviderErrorReason,
    create_standard_provider,
    provider_execution_matrix,
    provider_manifest,
    provider_support_matrix,
)
from jarvis.ai.providers.discovery import ModelDiscoveryService
from jarvis.ai.providers.registry import (
    ModelMetadata,
    ProviderDefinition,
    ProviderLocality,
    ProviderMetadata,
    ProviderRegistry,
)
from jarvis.ai.routing import (
    InferenceDispatcher,
    InferenceDispatchError,
    ProviderRouter,
    RouteRequest,
)
from jarvis.bootstrap import create_provider_registry
from jarvis.credentials import CredentialVault, TestOnlyInMemorySecretBackend

from tests.test_r3h_r2_provider_execution import FixtureTransport, _credential, _request


class JevTransport:
    def __init__(self) -> None:
        self.calls: list[tuple[str, str, Mapping[str, object] | None, Mapping[str, str]]] = []
        self.models = [{"name": "jev-A", "description": "fixture", "release_date": "2026-09-15"}]

    async def request(
        self,
        method: str,
        path: str,
        payload: Mapping[str, object] | None,
        headers: Mapping[str, str],
    ) -> Mapping[str, object]:
        self.calls.append((method, path, payload, headers))
        if path == "/v1/models":
            return {"models": list(self.models)}
        assert method == "POST" and path == "/v1/systemone" and payload is not None
        questions = payload["questions"]
        assert isinstance(questions, Mapping)
        question = questions["decision"]
        assert isinstance(question, Mapping)
        kind = question["type"]
        if kind == "choice":
            return {
                "model": "jev-A",
                "answers": {
                    "decision": {
                        "type": "choice",
                        "choice": "allow",
                        "confidence": 0.9,
                        "probabilities": {"allow": 0.9, "deny": 0.1},
                    }
                },
                "usage": {"input_tokens": 1, "output_tokens": 1},
            }
        if kind == "score":
            return {
                "model": "jev-A",
                "answers": {
                    "decision": {
                        "type": "score",
                        "score": 1.5,
                        "confidence": 0.8,
                        "legend": {"0": "low", "1": "medium", "2": "high"},
                        "probabilities": {"0": 0.1, "1": 0.3, "2": 0.6},
                    }
                },
                "usage": {"input_tokens": 1, "output_tokens": 1},
            }
        return {
            "model": "jev-A",
            "answers": {"decision": {"type": "noul", "noul": 0.75}},
            "usage": {"input_tokens": 1, "output_tokens": 1},
        }


async def test_jev_choice_score_noul_use_concrete_protocol_and_vault_bearer() -> None:
    transport = JevTransport()
    provider = JevDecisionProvider(
        JevConfiguration(model="jev-A", credential_ref="vault-ref"),
        transport,
        credential_resolver=_credential,
    )
    discovered = await provider.discover_models()
    assert [item.identity.model_id for item in discovered.models] == ["jev-A"]
    assert discovered.models[0].identity.inference_kind == IntelligenceKind.DECISION.value
    assert discovered.models[0].identity.endpoint == "https://api.typesafe.ai"
    assert ExactRouteIdentity.from_model_identity(
        discovered.models[0].identity
    ) == ExactRouteIdentity(
        "typesafe-jev",
        "https://api.typesafe.ai",
        "jev-A",
        region="unknown",
        version="2026-09-15",
        deployment="unknown",
        account_scope="unknown",
        inference_kind=IntelligenceKind.DECISION,
    )

    choice = await provider.decide(
        DecisionRequest(
            "Choose an action",
            (("choices", '["allow", "deny"]'), ("text", "public")),
            output_schema="choice",
            privacy_context=PrivacyContext(PrivacyClassification.SAFE_PUBLIC),
        )
    )
    score = await provider.decide(
        DecisionRequest(
            "Rate urgency",
            (("criteria", '["low", "medium", "high"]'), ("text", "public")),
            output_schema="score",
            privacy_context=PrivacyContext(PrivacyClassification.SAFE_PUBLIC),
        )
    )
    noul = await provider.decide(
        DecisionRequest(
            "Is this safe?",
            (("text", "public"),),
            output_schema="noul",
            privacy_context=PrivacyContext(PrivacyClassification.SAFE_PUBLIC),
        )
    )
    assert choice.label == "allow" and choice.confidence == 0.9
    assert score.label == "score" and dict(score.scores)["score"] == 1.5
    assert noul.label == "yes" and dict(noul.scores)["yes"] == 0.75
    assert all(call[3]["authorization"] == "Bearer fixture-secret" for call in transport.calls)
    assert all("fixture-secret" not in str(call[2]) for call in transport.calls)


async def test_jev_dynamic_model_and_router_privacy_are_concrete() -> None:
    transport = JevTransport()
    provider = JevDecisionProvider(
        JevConfiguration(model="jev-A", credential_ref="vault-ref"),
        transport,
        credential_resolver=_credential,
    )
    transport.models.append({"name": "jev-new-X", "description": "new", "release_date": ""})
    discovered = await provider.discover_models()
    assert {item.identity.model_id for item in discovered.models} == {"jev-A", "jev-new-X"}

    gateway = RemoteIntelligencePrivacyGateway(local_values=("private",))
    router = DecisionRouter(
        (DecisionRouteCandidate("typesafe-jev", provider, False, 0),),
        privacy_gateway=gateway,
    )
    result = await router.decide(
        DecisionRequest(
            "Classify this",
            (("text", "public private"),),
            output_schema="noul",
            privacy_context=PrivacyContext(PrivacyClassification.SANITIZABLE, ("private",)),
        )
    )
    assert result.provider_id == "typesafe-jev"
    post = next(call for call in transport.calls if call[0] == "POST")
    assert "private" not in str(post[2])
    assert (
        ExactRouteIdentity(
            "typesafe-jev",
            "https://api.typesafe.ai",
            "jev-A",
            inference_kind=IntelligenceKind.DECISION,
        ).inference_kind
        is IntelligenceKind.DECISION
    )

    registry = create_provider_registry()
    discovery = ModelDiscoveryService(registry)
    registered = await discovery.discover("typesafe-jev", provider)
    assert registered.registered_model_ids == ("jev-A", "jev-new-X")
    assert dict(registry.intelligence_models())["typesafe-jev"][1].model_id == "jev-new-X"
    page = ModelIntelligenceProjection(registry).page()
    jev_row = next(row for row in page.providers if row.provider_id == "typesafe-jev")
    assert (
        jev_row.model_count == 2
        and jev_row.configured is False
        and jev_row.connectable is True
        and jev_row.support_status == PackageSupportStatus.CONTROLLED_PROTOCOL_TESTED.value
    )
    assert {row.model_id for row in page.models if row.provider_id == "typesafe-jev"} == {
        "jev-A",
        "jev-new-X",
    }


async def test_generative_discovery_remains_definition_owned() -> None:
    registry = create_provider_registry()
    provider = create_standard_provider(
        "minimax",
        {"model": "MiniMax-M3", "credential_ref": "ref"},
        transport=FixtureTransport({("GET", "/models"): {"data": [{"id": "MiniMax-M3"}]}}),
        credential_resolver=_credential,
    )
    registered = await ModelDiscoveryService(registry).discover("minimax", provider)
    assert registered.registered_model_ids == ("MiniMax-M3",)
    assert registry.definition("minimax").models[0].model_id == "MiniMax-M3"
    assert dict(registry.intelligence_models())["typesafe-jev"] == ()


def test_jev_is_registered_as_decision_intelligence_not_chat() -> None:
    registry = create_provider_registry()
    assert "typesafe-jev" not in registry.provider_ids()
    assert "typesafe-jev" in registry.intelligence_provider_ids()
    assert isinstance(registry.create_intelligence("typesafe-jev", {}), JevDecisionProvider)


def test_zero_cloud_startup_does_not_call_any_standard_remote_package(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    calls: list[str] = []

    async def forbidden_request(
        self: object,
        method: str,
        path: str,
        payload: Mapping[str, object] | None,
        headers: Mapping[str, str],
    ) -> Mapping[str, object]:
        del self, method, path, payload, headers
        calls.append("remote")
        raise AssertionError("startup made an unexpected remote provider call")

    monkeypatch.setattr(HttpxJSONTransport, "request", forbidden_request)
    registry = create_provider_registry()
    assert len(registry.packages()) == 28
    assert calls == []


@pytest.mark.parametrize(
    "response",
    (
        {"model": "jev-A", "answers": {}, "usage": {}},
        {
            "model": "jev-A",
            "answers": {"unexpected": {"type": "noul", "noul": 0.5}},
            "usage": {},
        },
        {
            "model": "jev-A",
            "answers": {"decision": {"type": "noul", "noul": float("nan")}},
            "usage": {},
        },
    ),
)
async def test_jev_malformed_typed_output_fails_closed(response: Mapping[str, object]) -> None:
    class MalformedTransport(JevTransport):
        async def request(
            self,
            method: str,
            path: str,
            payload: Mapping[str, object] | None,
            headers: Mapping[str, str],
        ) -> Mapping[str, object]:
            if method == "POST":
                return response
            return await super().request(method, path, payload, headers)

    provider = JevDecisionProvider(
        JevConfiguration(model="jev-A", credential_ref="ref"),
        MalformedTransport(),
        credential_resolver=_credential,
    )
    with pytest.raises((ValueError, ProviderAdapterError)):
        await provider.decide(
            DecisionRequest(
                "Is this safe?",
                (),
                output_schema="noul",
                privacy_context=PrivacyContext(PrivacyClassification.SAFE_PUBLIC),
            )
        )


async def test_jev_authority_attempt_and_offline_fallback_do_not_change_authority() -> None:
    class AuthorityTransport(JevTransport):
        async def request(
            self,
            method: str,
            path: str,
            payload: Mapping[str, object] | None,
            headers: Mapping[str, str],
        ) -> Mapping[str, object]:
            if method == "POST":
                return {
                    "model": "jev-A",
                    "answers": {"decision": {"type": "noul", "noul": 0.5, "approval": True}},
                    "usage": {},
                }
            return await super().request(method, path, payload, headers)

    async def local(_request: DecisionRequest) -> DecisionResult:
        return DecisionResult("local_fallback", confidence=0.0)

    provider = JevDecisionProvider(
        JevConfiguration(model="jev-A", credential_ref="ref"),
        AuthorityTransport(),
        credential_resolver=_credential,
    )
    router = DecisionRouter(
        (
            DecisionRouteCandidate("typesafe-jev", provider, False, 0),
            DecisionRouteCandidate("local", JevDecisionProvider(legacy_transport=local), True, 1),
        ),
        privacy_gateway=RemoteIntelligencePrivacyGateway(),
    )
    result = await router.decide(
        DecisionRequest(
            "Is this safe?",
            (),
            output_schema="noul",
            privacy_context=PrivacyContext(PrivacyClassification.SAFE_PUBLIC),
        )
    )
    assert result.provider_id == "local"
    assert result.used_offline_fallback is True


async def test_jev_concrete_provider_unavailable_falls_back_to_local() -> None:
    class UnavailableTransport:
        async def request(
            self,
            method: str,
            path: str,
            payload: Mapping[str, object] | None,
            headers: Mapping[str, str],
        ) -> Mapping[str, object]:
            del method, path, payload, headers
            raise ProviderAdapterError(ProviderErrorReason.PROVIDER_UNAVAILABLE)

    async def local(_request: DecisionRequest) -> DecisionResult:
        return DecisionResult("local", confidence=1.0)

    provider = JevDecisionProvider(
        JevConfiguration(model="jev-A", credential_ref="ref"),
        UnavailableTransport(),
        credential_resolver=_credential,
    )
    result = await DecisionRouter(
        (
            DecisionRouteCandidate("typesafe-jev", provider, False, 0),
            DecisionRouteCandidate("local", JevDecisionProvider(legacy_transport=local), True, 1),
        ),
        privacy_gateway=RemoteIntelligencePrivacyGateway(),
    ).decide(
        DecisionRequest(
            "Is this safe?",
            (),
            output_schema="noul",
            privacy_context=PrivacyContext(PrivacyClassification.SAFE_PUBLIC),
        )
    )
    assert result.provider_id == "local"
    assert result.used_offline_fallback is True


async def test_minimax_openai_compatible_package_owns_endpoint_and_discovers_models() -> None:
    transport = FixtureTransport(
        {
            ("GET", "/models"): {
                "object": "list",
                "data": [{"id": "MiniMax-M3"}, {"id": "MiniMax-M2.7"}],
            },
            ("POST", "/chat/completions"): {
                "model": "MiniMax-M3",
                "choices": [{"message": {"content": "minimax-ok"}}],
            },
        }
    )
    provider = create_standard_provider(
        "minimax",
        {"model": "MiniMax-M3", "credential_ref": "ref"},
        transport=transport,
        credential_resolver=_credential,
    )
    assert isinstance(provider, OpenAICompatibleProvider)
    assert provider.configuration.base_url == "https://api.minimax.io/v1"
    assert [item.identity.model_id for item in (await provider.discover_models()).models] == [
        "MiniMax-M3",
        "MiniMax-M2.7",
    ]
    assert (await provider.generate(_request("MiniMax-M3"))).content == "minimax-ok"
    assert [call[1] for call in transport.calls] == ["/models", "/chat/completions"]


@pytest.mark.parametrize(
    ("status", "reason"),
    (
        (401, ProviderErrorReason.AUTHENTICATION_FAILED),
        (404, ProviderErrorReason.MODEL_NOT_FOUND),
        (408, ProviderErrorReason.TIMEOUT),
        (429, ProviderErrorReason.RATE_LIMITED),
        (503, ProviderErrorReason.PROVIDER_UNAVAILABLE),
    ),
)
async def test_minimax_error_normalization_is_bounded_and_secret_free(
    status: int,
    reason: ProviderErrorReason,
) -> None:
    async def handler(request: httpx.Request) -> httpx.Response:
        del request
        return httpx.Response(status, json={"error": "mini-secret"})

    client = httpx.AsyncClient(
        base_url="https://api.minimax.io/v1",
        transport=httpx.MockTransport(handler),
        follow_redirects=False,
    )
    transport = HttpxJSONTransport("https://api.minimax.io/v1", client=client)
    try:
        with pytest.raises(ProviderAdapterError) as error:
            await transport.request("GET", "/models", None, {"authorization": "Bearer mini-secret"})
        assert error.value.reason is reason
        assert "mini-secret" not in str(error.value)
    finally:
        await client.aclose()


async def test_minimax_malformed_generation_response_fails_closed() -> None:
    provider = create_standard_provider(
        "minimax",
        {"model": "MiniMax-M3", "credential_ref": "ref"},
        transport=FixtureTransport({("POST", "/chat/completions"): {"choices": []}}),
        credential_resolver=_credential,
    )
    assert isinstance(provider, OpenAICompatibleProvider)
    with pytest.raises(ProviderAdapterError) as error:
        await provider.generate(_request("MiniMax-M3"))
    assert error.value.reason is ProviderErrorReason.MALFORMED_RESPONSE


async def test_minimax_without_credential_never_calls_remote_transport() -> None:
    transport = FixtureTransport({("GET", "/models"): {"data": []}})
    provider = create_standard_provider(
        "minimax",
        {"model": "MiniMax-M3"},
        transport=transport,
    )
    assert isinstance(provider, OpenAICompatibleProvider)
    with pytest.raises(PermissionError):
        await provider.discover_models()
    with pytest.raises(PermissionError):
        await provider.generate(_request("MiniMax-M3"))
    assert transport.calls == []


async def test_minimax_oversized_response_fails_closed() -> None:
    async def handler(request: httpx.Request) -> httpx.Response:
        del request
        return httpx.Response(200, content=b"{" + b"a" * (4 * 1024 * 1024) + b"}")

    client = httpx.AsyncClient(
        base_url="https://api.minimax.io/v1",
        transport=httpx.MockTransport(handler),
        follow_redirects=False,
    )
    transport = HttpxJSONTransport("https://api.minimax.io/v1", client=client)
    try:
        with pytest.raises(ProviderAdapterError) as error:
            await transport.request("GET", "/models", None, {})
        assert error.value.reason is ProviderErrorReason.MALFORMED_RESPONSE
    finally:
        await client.aclose()


def _minimax_policy_fixture() -> tuple[
    FixtureTransport,
    OpenAICompatibleProvider,
    ProviderRegistry,
    ModelIdentity,
    PolicyStore,
]:
    transport = FixtureTransport(
        {
            ("POST", "/chat/completions"): {
                "model": "MiniMax-M3",
                "choices": [{"message": {"content": "authorized"}}],
            }
        }
    )
    provider = create_standard_provider(
        "minimax",
        {"model": "MiniMax-M3", "credential_ref": "ref"},
        transport=transport,
        credential_resolver=_credential,
    )
    assert isinstance(provider, OpenAICompatibleProvider)
    model = ModelMetadata(
        "MiniMax-M3",
        4096,
        capabilities=frozenset({"chat"}),
        roles=frozenset({ModelRole.GENERAL}),
        endpoint="https://api.minimax.io/v1",
        input_cost_per_million=0.1,
        output_cost_per_million=0.1,
    )
    registry = ProviderRegistry(
        (
            ProviderDefinition(
                ProviderMetadata("minimax", "MiniMax", "1", locality=ProviderLocality.REMOTE),
                lambda _: provider,
                (model,),
            ),
        )
    )
    policies = PolicyStore()
    return transport, provider, registry, identity_for("minimax", model), policies


async def test_minimax_guarded_policy_requires_approval_and_calls_once() -> None:
    transport, provider, registry, identity, policies = _minimax_policy_fixture()
    policies.set_model_policy(identity, ModelPolicy.GUARDED)
    dispatcher = InferenceDispatcher(
        ProviderRouter(registry, policy_engine=PolicyEngine(policies)),
        registry,
        providers={"minimax": provider},
    )
    intent = RouteRequest(
        "answer",
        "test",
        preferred_provider_id="minimax",
        explicit_selection=True,
        actor_id="actor",
        task_class="general",
        purpose="inference",
        approval_scope="inference",
        privacy_context=PrivacyContext(PrivacyClassification.SAFE_PUBLIC),
    )
    with pytest.raises(InferenceDispatchError):
        await dispatcher.generate(
            GenerationRequest(
                (),
                "MiniMax-M3",
                4096,
                privacy_context=PrivacyContext(PrivacyClassification.SAFE_PUBLIC),
            ),
            intent,
        )
    assert transport.calls == []
    approval = GuardedApproval(
        "actor",
        "general",
        identity.storage_key,
        "inference",
        1.0,
        "inference",
        datetime.now(UTC) + timedelta(minutes=5),
    )
    result = await dispatcher.generate(
        GenerationRequest(
            (),
            "MiniMax-M3",
            4096,
            privacy_context=PrivacyContext(PrivacyClassification.SAFE_PUBLIC),
        ),
        replace(intent, guarded_approval=approval),
    )
    assert result.result.model == "MiniMax-M3"
    assert len(transport.calls) == 1


async def test_minimax_blocked_policy_excludes_route_before_transport() -> None:
    transport, provider, registry, identity, policies = _minimax_policy_fixture()
    policies.set_model_policy(identity, ModelPolicy.BLOCKED)
    dispatcher = InferenceDispatcher(
        ProviderRouter(registry, policy_engine=PolicyEngine(policies)),
        registry,
        providers={"minimax": provider},
    )
    with pytest.raises(InferenceDispatchError):
        await dispatcher.generate(
            GenerationRequest(
                (),
                "MiniMax-M3",
                4096,
                privacy_context=PrivacyContext(PrivacyClassification.SAFE_PUBLIC),
            ),
            RouteRequest(
                "answer",
                "test",
                preferred_provider_id="minimax",
                explicit_selection=True,
                privacy_context=PrivacyContext(PrivacyClassification.SAFE_PUBLIC),
            ),
        )
    assert transport.calls == []


def test_minimax_onboarding_requires_only_vault_key_and_all_28_rows_are_complete(
    tmp_path: Path,
) -> None:
    manifest = provider_manifest("minimax")
    assert manifest.support_status is PackageSupportStatus.CONTROLLED_PROTOCOL_TESTED
    assert manifest.discovery_mode == "DYNAMIC"
    assert "base_url" not in {
        field.name for field in (*manifest.required_fields, *manifest.optional_fields)
    }
    matrix = {row.provider_id: row for row in provider_support_matrix()}
    execution = {row.provider_id: row for row in provider_execution_matrix()}
    assert len(matrix) == len(execution) == 28
    assert all(
        row.source_adapter_present and row.controlled_protocol_tested for row in matrix.values()
    )
    assert all(row.adapter == "PASS" and row.onboarding == "PASS" for row in execution.values())
    service = ProviderOnboardingService(
        CredentialVault(tmp_path / "credentials.sqlite3", backend=TestOnlyInMemorySecretBackend())
    )
    connection = service.connect("minimax", configuration={}, secret="mini-secret")
    assert connection.configuration == ()


async def test_jev_safe_mode_shape_has_no_remote_execution() -> None:
    provider = JevDecisionProvider()
    health = await provider.health_check()
    assert health.available is False
    with pytest.raises(ConnectionError):
        await provider.decide(
            DecisionRequest(
                "offline",
                (),
                output_schema="noul",
                privacy_context=PrivacyContext(PrivacyClassification.SAFE_PUBLIC),
            )
        )
