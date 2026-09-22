from __future__ import annotations

from collections.abc import Mapping
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest
from jarvis.ai.decision import DecisionRouteCandidate, DecisionRouter
from jarvis.ai.governance import (
    BudgetLedger,
    BudgetPolicy,
    BulkPolicyRule,
    GuardedApproval,
    PolicyEngine,
    PolicyStore,
    TaskQuarantine,
)
from jarvis.ai.knowledge import ModelIdentity
from jarvis.ai.model_intelligence import ModelIntelligenceProjection
from jarvis.ai.models import PrivacyClassification, PrivacyContext
from jarvis.ai.onboarding import ProviderOnboardingService
from jarvis.ai.providers import (
    CostEvidence,
    CostStatus,
    DecisionResult,
    ExactRouteIdentity,
    IntelligenceKind,
    ModelLifecycle,
    ModelMetadata,
    ModelPolicy,
    PackageSupportStatus,
    ProviderDefinition,
    ProviderLocality,
    ProviderMetadata,
    ProviderPolicy,
    ProviderRegistry,
    RemoteIntelligencePrivacyGateway,
)
from jarvis.ai.providers.catalog import (
    JevDecisionProvider,
    OpenAICompatibleConfiguration,
    OpenAICompatibleProvider,
    standard_provider_catalog,
)
from jarvis.ai.providers.discovery import ModelDiscoveryService
from jarvis.ai.providers.intelligence import CallableDecisionProvider, DecisionRequest
from jarvis.ai.routing import ProviderRouter, RouteRequest, RouteStatus
from jarvis.credentials import CredentialVault, TestOnlyInMemorySecretBackend

from tests.fakes import FakeAIProvider


def _identity(provider: str = "fixture", model: str = "model") -> ModelIdentity:
    return ModelIdentity(provider, model, "v1", "", "remote")


def _metadata(
    model: str = "model", *, lifecycle: ModelLifecycle = ModelLifecycle.ACTIVE
) -> ModelMetadata:
    return ModelMetadata(
        model,
        4096,
        frozenset({"chat"}),
        lifecycle=lifecycle,
        family="fixture",
        modalities=frozenset({"text"}),
    )


def test_standard_catalog_is_complete_and_provider_neutral() -> None:
    catalog = standard_provider_catalog()
    ids = {item.provider_id for item in catalog}
    assert len(catalog) >= 28
    assert {"openai", "anthropic", "google-gemini", "typesafe-jev", "openai-compatible"} <= ids
    assert all(
        item.support_status is not PackageSupportStatus.PHYSICAL_VALIDATED for item in catalog
    )
    assert all(
        item.required_fields or item.authentication.value == "service_account" for item in catalog
    )


def test_exact_route_identity_and_aliases_are_not_collapsed() -> None:
    first = ExactRouteIdentity("openrouter", "https://openrouter.ai", "qwen", region="us")
    second = ExactRouteIdentity("together-ai", "https://api.together.ai", "qwen", region="us")
    assert first.storage_key != second.storage_key
    assert first.inference_kind is IntelligenceKind.GENERATIVE


def test_dynamic_unknown_model_registers_without_core_change() -> None:
    registry = ProviderRegistry(
        (
            ProviderDefinition(
                ProviderMetadata("fixture", "Fixture", "1", locality=ProviderLocality.REMOTE),
                lambda _: FakeAIProvider(),
                (_metadata("old"),),
            ),
        )
    )
    result = ModelDiscoveryService(registry).register_unknown_model("fixture", "new-model-xyz")
    assert result.registered_model_ids == ("new-model-xyz",)
    assert registry.definition("fixture").models[0].model_id == "new-model-xyz"


async def test_openai_compatible_discovery_registers_full_fixture_inventory() -> None:
    class Transport:
        async def request(
            self,
            method: str,
            path: str,
            payload: Mapping[str, object] | None,
            headers: Mapping[str, str],
        ) -> Mapping[str, object]:
            assert method == "GET"
            assert path == "/models"
            return {"data": [{"id": "old-model"}, {"id": "new-specialized-model"}]}

    provider = OpenAICompatibleProvider(
        OpenAICompatibleConfiguration(
            "fixture-openai-compatible", "https://provider.example.test", "old-model"
        ),
        Transport(),
    )
    snapshot = await provider.discover_models()
    assert tuple(item.identity.model_id for item in snapshot.models) == (
        "old-model",
        "new-specialized-model",
    )


def test_policy_is_most_restrictive_and_applies_to_future_models() -> None:
    store = PolicyStore()
    store.set_bulk_policy(BulkPolicyRule("frontier", ModelPolicy.GUARDED, family="fixture"))
    engine = PolicyEngine(store)
    identity = _identity()
    metadata = _metadata()
    decision = engine.evaluate(identity, metadata)
    assert decision.policy is ModelPolicy.GUARDED
    assert not decision.allowed and decision.requires_approval
    store.set_model_policy(identity, ModelPolicy.BLOCKED)
    assert not engine.evaluate(identity, metadata).allowed


def test_policy_state_survives_restart_without_secret_material(tmp_path: Path) -> None:
    path = tmp_path / "policies.sqlite"
    identity = _identity()
    store = PolicyStore(path)
    store.set_provider_policy("fixture", ProviderPolicy.ROUTING_DISABLED)
    store.set_model_policy(identity, ModelPolicy.BLOCKED)
    reopened = PolicyStore(path)
    assert reopened.provider_policy("fixture") is ProviderPolicy.ROUTING_DISABLED
    assert reopened.model_policy(identity) is ModelPolicy.BLOCKED
    assert b"super-secret" not in path.read_bytes()


def test_guarded_approval_is_exactly_bound_and_expired() -> None:
    store = PolicyStore()
    identity = _identity()
    store.set_model_policy(identity, ModelPolicy.GUARDED)
    engine = PolicyEngine(store)
    expiry = datetime.now(UTC) + timedelta(minutes=5)
    approval = GuardedApproval(
        "actor", "task", identity.storage_key, "inference", 2.0, "chat", expiry
    )
    assert engine.evaluate(
        identity,
        _metadata(),
        approval=approval,
        actor_id="actor",
        task_id="task",
        scope="chat",
        estimated_cost=1.0,
    ).allowed
    assert not engine.evaluate(
        identity,
        _metadata(),
        approval=approval,
        actor_id="other",
        task_id="task",
        scope="chat",
        estimated_cost=1.0,
    ).allowed


def test_retired_route_cannot_execute_but_unknown_cost_is_not_free() -> None:
    store = PolicyStore()
    engine = PolicyEngine(store)
    assert not engine.evaluate(_identity(), _metadata(lifecycle=ModelLifecycle.RETIRED)).allowed
    unknown = CostEvidence()
    assert unknown.status is CostStatus.COST_UNKNOWN
    assert unknown.total_per_million is None
    ledger = BudgetLedger(BudgetPolicy(max_request_cost=1.0))
    assert not ledger.estimated_allowed(None)
    assert not ledger.estimated_allowed(2.0)


def test_task_quarantine_is_narrow_not_global() -> None:
    quarantine = TaskQuarantine(threshold=2)
    identity = _identity()
    quarantine.record_failure(identity, "architecture")
    state = quarantine.record_failure(identity, "architecture")
    assert state.state.value == "task_quarantined"
    assert quarantine.is_quarantined(identity, "architecture")
    assert not quarantine.is_quarantined(identity, "extraction")


def test_decision_provider_output_cannot_claim_authority() -> None:
    with pytest.raises(ValueError, match="authority"):
        DecisionResult.from_mapping({"label": "allow", "permission_granted": True})


async def test_jev_offline_fails_over_to_local_decision_path() -> None:
    async def local_decision(request: DecisionRequest) -> DecisionResult:
        return DecisionResult("local", 0.9)

    registry = ProviderRegistry()
    registry.register_intelligence("typesafe-jev", lambda _: JevDecisionProvider())
    assert registry.intelligence_provider_ids() == ("typesafe-jev",)
    router = DecisionRouter(
        (
            DecisionRouteCandidate("typesafe-jev", JevDecisionProvider(), False, 0),
            DecisionRouteCandidate("local", CallableDecisionProvider(local_decision), True, 1),
        ),
        privacy_gateway=RemoteIntelligencePrivacyGateway(local_values=("private",)),
    )
    result = await router.decide(
        DecisionRequest(
            "classify",
            (("text", "public"),),
            privacy_context=PrivacyContext(PrivacyClassification.SAFE_PUBLIC),
        )
    )
    assert result.provider_id == "local"
    assert result.used_offline_fallback is True
    assert result.attempted_provider_ids == ("typesafe-jev", "local")


def test_remote_decision_payload_is_minimized_and_redacted() -> None:
    gateway = RemoteIntelligencePrivacyGateway(
        local_values=("secret@example.test", "private-value")
    )
    payload = gateway.prepare(
        IntelligenceKind.DECISION,
        {"text": "classify private-value", "email": "secret@example.test"},
        PrivacyContext(PrivacyClassification.SANITIZABLE, ("secret@example.test", "private-value")),
    )
    assert all(
        value not in dict(payload.fields).values()
        for value in ("secret@example.test", "private-value")
    )
    with pytest.raises(PermissionError):
        gateway.prepare(
            IntelligenceKind.DECISION, {"text": "x"}, PrivacyContext(PrivacyClassification.SECRET)
        )


def test_openai_compatible_remote_endpoint_requires_tls() -> None:
    with pytest.raises(ValueError, match="HTTPS"):
        OpenAICompatibleConfiguration("openai-compatible", "http://example.test", "model")
    with pytest.raises(ValueError, match="Loopback"):
        OpenAICompatibleConfiguration(
            "openai-compatible", "http://localhost:8080", "model", ProviderLocality.REMOTE
        )


def test_onboarding_keeps_secret_out_of_connection_configuration(tmp_path: Path) -> None:
    backend = TestOnlyInMemorySecretBackend()
    vault = CredentialVault(tmp_path / "credentials.sqlite", backend=backend)
    service = ProviderOnboardingService(vault)
    connection = service.connect(
        "openai",
        configuration={},
        secret="super-secret",
    )
    assert all(
        "secret" not in value and "credential" not in key for key, value in connection.configuration
    )
    status = service.credential_status("openai")
    assert status is not None and status.value == "active"
    service.disconnect("openai")
    status = service.credential_status("openai")
    assert status is not None and status.value == "revoked"


def test_model_intelligence_projection_reads_registry_state() -> None:
    registry = ProviderRegistry(
        (
            ProviderDefinition(
                ProviderMetadata("ollama", "Ollama", "native", local_only=True),
                lambda _: FakeAIProvider(),
                (_metadata("local-model"),),
            ),
        )
    )
    page = ModelIntelligenceProjection(registry).page()
    assert page.providers[0].provider_id == "ollama"
    assert page.models[0].model_id == "local-model"
    assert page.models[0].policy == "auto_allowed"


def test_blocked_route_is_excluded_before_router_optimization() -> None:
    identity = ModelIdentity("fixture", "blocked")
    store = PolicyStore()
    store.set_model_policy(identity, ModelPolicy.BLOCKED)
    registry = ProviderRegistry(
        (
            ProviderDefinition(
                ProviderMetadata("fixture", "Fixture", "1", locality=ProviderLocality.REMOTE),
                lambda _: FakeAIProvider(("must-not-run",)),
                (_metadata("blocked"),),
            ),
        )
    )
    router = ProviderRouter(registry, policy_engine=PolicyEngine(store))
    decision = router.route(
        RouteRequest(
            "classify",
            "test",
            classification="safe_public",
            privacy_context=PrivacyContext(PrivacyClassification.SAFE_PUBLIC),
        )
    )
    assert decision.status is RouteStatus.UNAVAILABLE
    assert decision.primary is None


def test_router_budget_and_task_quarantine_are_hard_gates() -> None:
    registry = ProviderRegistry(
        (
            ProviderDefinition(
                ProviderMetadata("fixture", "Fixture", "1", local_only=True),
                lambda _: FakeAIProvider(),
                (_metadata("model"),),
            ),
        )
    )
    ledger = BudgetLedger(BudgetPolicy(max_request_cost=0.5))
    router = ProviderRouter(registry, budget_ledger=ledger)
    budget_decision = router.route(
        RouteRequest("answer", "test", estimated_cost=1.0, budget_ledger=ledger)
    )
    assert budget_decision.primary is None
    quarantine = TaskQuarantine(threshold=2)
    quarantine.record_failure(ModelIdentity("fixture", "model"), "general")
    quarantine.record_failure(ModelIdentity("fixture", "model"), "general")
    quarantined = ProviderRouter(registry, task_quarantine=quarantine).route(
        RouteRequest("answer", "test", task_class="general")
    )
    assert quarantined.primary is None
