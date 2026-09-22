"""Independent R3H review closure cases.

These tests deliberately exercise the durable/application seams instead of
accepting the development evidence artifact as proof.
"""

import json
import sqlite3
from dataclasses import replace
from datetime import UTC, datetime, timedelta
from pathlib import Path
from uuid import uuid4

import pytest
from jarvis.ai.governance import (
    BudgetLedger,
    BudgetPolicy,
    BulkPolicyRule,
    GuardedApproval,
    PolicyEngine,
    PolicyStore,
    TaskQuarantine,
)
from jarvis.ai.knowledge import (
    ModelIdentity,
    ModelKnowledgeError,
    ModelKnowledgeStore,
    ModelObservation,
    ProviderCatalogSnapshot,
    identity_for,
)
from jarvis.ai.model_intelligence import ModelIntelligenceProjection
from jarvis.ai.models import (
    ChatMessage,
    EvidenceKind,
    GenerationRequest,
    GenerationResult,
    MessageRole,
    ModelRole,
    PrivacyClassification,
    PrivacyContext,
)
from jarvis.ai.onboarding import ProviderOnboardingService
from jarvis.ai.providers.catalog import create_standard_provider, provider_support_matrix
from jarvis.ai.providers.discovery import ModelDiscoveryService
from jarvis.ai.providers.intelligence import (
    CostEvidence,
    CostStatus,
    DecisionRequest,
    ModelPolicy,
    ProviderPolicy,
    UsageReceipt,
)
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
    RouteStatus,
    RoutingPolicy,
)
from jarvis.ai.usability import evidence_for_success
from jarvis.core.config import Settings
from jarvis.credentials import CredentialVault, TestOnlyInMemorySecretBackend
from jarvis.runtime import ApplicationRuntime, RuntimeStatus

from tests.fakes import FakeAIProvider

NOW = datetime(2026, 9, 22, 12, 0, tzinfo=UTC)


def _provider() -> ProviderMetadata:
    return ProviderMetadata("fixture", "Fixture", "1", locality=ProviderLocality.REMOTE)


def _model(model_id: str, *, endpoint: str = "https://one.example") -> ModelMetadata:
    return ModelMetadata(
        model_id,
        4096,
        frozenset({"chat", "structured_output"}),
        frozenset({ModelRole.GENERAL}),
        family="fixture",
        version="1",
        quantization="q4",
        runtime="remote",
        source="fixture",
        modalities=frozenset({"text"}),
        endpoint=endpoint,
        region="eu",
        deployment="blue",
        account_scope="acct-a",
        input_cost_per_million=1.0,
        output_cost_per_million=1.0,
    )


def _snapshot(*models: ModelMetadata) -> ProviderCatalogSnapshot:
    return ProviderCatalogSnapshot(
        _provider(),
        tuple(
            ModelObservation(
                identity_for("fixture", model),
                model,
                NOW,
                "fixture",
                EvidenceKind.PROVIDER_REPORTED,
            )
            for model in models
        ),
        NOW,
        "fixture",
        True,
    )


def test_exact_route_identity_roundtrips_and_keeps_two_endpoints_distinct(tmp_path: Path) -> None:
    path = tmp_path / "knowledge.sqlite3"
    store = ModelKnowledgeStore(path)
    one = _model("same", endpoint="https://one.example")
    two = _model("same", endpoint="https://two.example")
    store.refresh(_snapshot(one))
    store.refresh(
        ProviderCatalogSnapshot(
            _provider(),
            (
                ModelObservation(
                    identity_for("fixture", two), two, NOW + timedelta(minutes=1), "fixture"
                ),
            ),
            NOW + timedelta(minutes=1),
            "fixture",
            True,
        )
    )
    identities = {item.identity for item in store.models(include_stale=True)}
    assert len(identities) == 2
    assert {item.identity.endpoint for item in store.models(include_stale=True)} == {
        "https://one.example",
        "https://two.example",
    }
    store.close()
    reopened = ModelKnowledgeStore(path)
    assert {item.identity.endpoint for item in reopened.models(include_stale=True)} == {
        "https://one.example",
        "https://two.example",
    }
    reopened.close()


def _create_v1_database(path: Path) -> None:
    connection = sqlite3.connect(path)
    connection.executescript(
        """
        CREATE TABLE model_knowledge_schema(version INTEGER PRIMARY KEY, name TEXT NOT NULL);
        INSERT INTO model_knowledge_schema VALUES (1, 'create_model_knowledge');
        CREATE TABLE providers(provider_id TEXT PRIMARY KEY, metadata_json TEXT NOT NULL,
            availability TEXT NOT NULL, available INTEGER, detail TEXT NOT NULL,
            source TEXT, last_observed TEXT);
        CREATE TABLE models(provider_id TEXT NOT NULL, model_id TEXT NOT NULL,
            model_version TEXT NOT NULL, quantization TEXT NOT NULL, runtime TEXT NOT NULL,
            metadata_json TEXT NOT NULL, availability TEXT NOT NULL, first_seen TEXT,
            last_seen TEXT, last_source TEXT, last_evidence_kind TEXT, stale_since TEXT,
            PRIMARY KEY(provider_id, model_id, model_version, quantization, runtime));
        CREATE TABLE model_observations(observation_key TEXT PRIMARY KEY, provider_id TEXT NOT NULL,
            model_id TEXT NOT NULL, model_version TEXT NOT NULL, quantization TEXT NOT NULL,
            runtime TEXT NOT NULL, metadata_json TEXT NOT NULL, observed_at TEXT NOT NULL,
            source TEXT NOT NULL, evidence_kind TEXT NOT NULL, evidence_detail TEXT NOT NULL,
            availability TEXT NOT NULL, machine_scope TEXT);
        CREATE TABLE model_evidence(evidence_key TEXT PRIMARY KEY, provider_id TEXT NOT NULL,
            model_id TEXT NOT NULL, model_version TEXT NOT NULL, quantization TEXT NOT NULL,
            runtime TEXT NOT NULL, evidence_json TEXT NOT NULL);
        CREATE TABLE model_measurements(measurement_key TEXT PRIMARY KEY, provider_id TEXT NOT NULL,
            model_id TEXT NOT NULL, model_version TEXT NOT NULL, quantization TEXT NOT NULL,
            runtime TEXT NOT NULL, measured_at TEXT NOT NULL, source TEXT NOT NULL,
            machine_scope TEXT NOT NULL, metrics_json TEXT NOT NULL);
        CREATE TABLE cookbook_observations(
            observation_id TEXT PRIMARY KEY, provider_id TEXT NOT NULL,
            model_id TEXT NOT NULL, model_version TEXT NOT NULL, quantization TEXT NOT NULL,
            runtime TEXT NOT NULL, task_class TEXT NOT NULL, observation_json TEXT NOT NULL);
        """
    )
    provider = {
        "provider_id": "fixture",
        "display_name": "Fixture",
        "version": "1",
        "local_only": False,
        "locality": "remote",
    }
    model = {
        "model_id": "legacy",
        "context_limit": 4096,
        "capabilities": ["chat"],
        "roles": ["general"],
        "family": "fixture",
        "version": "1",
        "quantization": "q4",
        "runtime": "remote",
        "source": "legacy",
        "modalities": ["text"],
        "storage_bytes": None,
        "ram_bytes": None,
        "vram_bytes": None,
        "license": "",
        "compatibility": [],
        "max_concurrency": None,
        "quality_score": None,
        "latency_ms": None,
        "input_cost_per_million": None,
        "output_cost_per_million": None,
        "lifecycle": "unknown",
        "endpoint": "",
        "region": "",
        "deployment": "",
        "account_scope": "",
        "inference_kind": "generative",
        "alias_target": "",
        "discovered_at": None,
        "verified_at": None,
    }
    timestamp = NOW.isoformat()
    connection.execute(
        "INSERT INTO providers VALUES (?, ?, ?, ?, ?, ?, ?)",
        ("fixture", json.dumps(provider), "known", 1, "", "legacy", timestamp),
    )
    connection.execute(
        "INSERT INTO models VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
        (
            "fixture",
            "legacy",
            "1",
            "q4",
            "remote",
            json.dumps(model),
            "known",
            timestamp,
            timestamp,
            "legacy",
            "provider_reported",
            None,
        ),
    )
    connection.commit()
    connection.close()


def test_v1_model_knowledge_migrates_unknown_route_components_atomically(tmp_path: Path) -> None:
    path = tmp_path / "legacy.sqlite3"
    _create_v1_database(path)
    store = ModelKnowledgeStore(path)
    view = store.models(include_stale=True)[0]
    assert view.identity.endpoint == "unknown"
    assert view.identity.region == "unknown"
    assert (
        store._connection.execute(
            "SELECT name FROM model_knowledge_schema WHERE version=2"
        ).fetchone()[0]
        == "exact_route_identity"
    )
    store.close()


def test_knowledge_rejects_future_schema_and_rolls_back_failed_migration(tmp_path: Path) -> None:
    future = tmp_path / "future.sqlite3"
    with sqlite3.connect(future) as connection:
        connection.execute(
            "CREATE TABLE model_knowledge_schema(version INTEGER PRIMARY KEY, name TEXT NOT NULL)"
        )
        connection.execute("INSERT INTO model_knowledge_schema VALUES (99, 'future')")
    with pytest.raises(ModelKnowledgeError, match="future schema"):
        ModelKnowledgeStore(future)

    malformed = tmp_path / "malformed.sqlite3"
    _create_v1_database(malformed)
    with sqlite3.connect(malformed) as connection:
        connection.execute("DROP TABLE model_evidence")
    with pytest.raises(ModelKnowledgeError):
        ModelKnowledgeStore(malformed)
    with sqlite3.connect(malformed) as connection:
        assert connection.execute(
            "SELECT 1 FROM sqlite_master WHERE type='table' AND name='models'"
        ).fetchone()
        assert (
            connection.execute(
                "SELECT 1 FROM sqlite_master WHERE type='table' AND name='models_v1'"
            ).fetchone()
            is None
        )


def test_governance_persists_policy_budget_and_idempotent_receipt(tmp_path: Path) -> None:
    policy_path = tmp_path / "policy.sqlite3"
    policies = PolicyStore(policy_path)
    identity = ModelIdentity("fixture", "model")
    policies.set_provider_policy("fixture", ProviderPolicy.ROUTING_DISABLED)
    policies.set_model_policy(identity, ModelPolicy.GUARDED)
    reopened = PolicyStore(policy_path)
    assert reopened.provider_policy("fixture") is ProviderPolicy.ROUTING_DISABLED
    assert reopened.model_policy(identity) is ModelPolicy.GUARDED

    budget_path = tmp_path / "budget.sqlite3"
    ledger = BudgetLedger(BudgetPolicy(daily_cloud_budget=3.0), budget_path)
    receipt = UsageReceipt("route", actual_cost=2.0, observed_at=NOW, receipt_id="r1")
    ledger.record(receipt)
    ledger.record(receipt)
    reloaded = BudgetLedger(BudgetPolicy(daily_cloud_budget=3.0), budget_path)
    assert reloaded.actual_total() == 2.0
    ledger.set_policy(BudgetPolicy(daily_cloud_budget=4.0, approval_threshold=2.0))
    assert BudgetLedger(BudgetPolicy(), budget_path).policy.daily_cloud_budget == 4.0
    with pytest.raises(ValueError):
        BudgetPolicy(daily_cloud_budget=float("nan"))

    quarantine = TaskQuarantine(path=tmp_path / "quarantine.sqlite3", threshold=2)
    quarantine.record_failure(identity, "SECURITY_REVIEW")
    quarantine.record_failure(identity, "SECURITY_REVIEW")
    restarted = TaskQuarantine(path=tmp_path / "quarantine.sqlite3", threshold=2)
    assert restarted.is_quarantined(identity, "SECURITY_REVIEW")
    assert not restarted.is_quarantined(identity, "EXTRACTION")


def test_disconnect_and_delete_credential_are_distinct(tmp_path: Path) -> None:
    backend = TestOnlyInMemorySecretBackend()
    vault = CredentialVault(tmp_path / "credentials.sqlite3", backend=backend)
    service = ProviderOnboardingService(vault, path=tmp_path / "connections.sqlite3")
    connection = service.connect("openai", configuration={}, secret="synthetic-secret")
    disabled = service.set_routing_policy("openai", ProviderPolicy.ROUTING_DISABLED)
    assert disabled.credential_id == connection.credential_id
    enabled = service.set_routing_policy("openai", ProviderPolicy.ENABLED)
    assert enabled.credential_id == connection.credential_id
    disabled = service.set_routing_policy("openai", ProviderPolicy.ROUTING_DISABLED)
    assert disabled.credential_id == connection.credential_id
    credential_status = service.credential_status("openai")
    assert credential_status is not None and credential_status.value == "active"
    service.disconnect("openai")
    credential_status = service.credential_status("openai")
    assert credential_status is not None and credential_status.value == "revoked"
    service.connect("openai", configuration={}, secret="synthetic-secret-2")
    deleted = service.delete_credential("openai")
    assert deleted.credential_id is None
    assert service.credential_status("openai") is None
    assert "synthetic-secret" not in json.dumps(deleted.configuration)


def test_provider_matrix_is_complete_and_reports_source_execution_truthfully() -> None:
    matrix = provider_support_matrix()
    assert len(matrix) == 28
    assert all(item.catalog_present for item in matrix)
    assert all(item.physical_status == "PHYSICAL_VALIDATION_REQUIRED" for item in matrix)
    assert sum(item.source_adapter_present for item in matrix) >= 17
    assert all(item.source_adapter_present == item.controlled_protocol_tested for item in matrix)
    assert all(
        item.source_adapter_present
        or item.source_support_level
        in {
            "catalog_only",
            "external_protocol_fact_not_proven",
        }
        for item in matrix
    )


async def test_manual_only_has_zero_autonomous_calls_and_allows_exact_selection() -> None:
    provider = FakeAIProvider()
    registry = ProviderRegistry(
        (
            ProviderDefinition(
                ProviderMetadata("fixture", "Fixture", "1", local_only=True),
                lambda _: provider,
                (_model("manual"),),
            ),
        )
    )
    identity = identity_for("fixture", _model("manual"))
    policies = PolicyStore()
    policies.set_model_policy(identity, ModelPolicy.MANUAL_ONLY)
    dispatcher = InferenceDispatcher(
        ProviderRouter(registry, policy_engine=PolicyEngine(policies)),
        registry,
        providers={"fixture": provider},
    )
    intent = RouteRequest(
        "answer", "test", privacy_context=PrivacyContext(PrivacyClassification.SAFE_PUBLIC)
    )
    with pytest.raises(InferenceDispatchError):
        await dispatcher.generate(GenerationRequest((), "manual", 4096), intent)
    assert provider.requests == []
    result = await dispatcher.generate(
        GenerationRequest((), "manual", 4096), replace(intent, explicit_selection=True)
    )
    assert result.result.model == "manual"
    assert len(provider.requests) == 1


async def test_h2_one_key_setup_runs_vault_probe_discovery_and_registration(
    tmp_path: Path,
) -> None:
    class NamedOpenAITransport:
        async def request(
            self,
            method: str,
            path: str,
            payload: dict[str, object] | None,
            headers: dict[str, str],
        ) -> dict[str, object]:
            del headers
            if method == "GET" and path == "/models":
                return {"data": [{"id": "discovered", "context_length": 4096}]}
            if method == "POST" and path == "/chat/completions":
                return {"model": "discovered", "choices": [{"message": {"content": "ok"}}]}
            raise AssertionError(f"unexpected named OpenAI request: {method} {path} {payload}")

    async def resolve_async(_reference: object) -> str:
        return "synthetic-key"

    registry = ProviderRegistry(
        (
            ProviderDefinition(
                ProviderMetadata("openai", "OpenAI", "1", locality=ProviderLocality.REMOTE),
                lambda configuration: create_standard_provider("openai", configuration),
            ),
        )
    )
    vault = CredentialVault(
        tmp_path / "credentials.sqlite3", backend=TestOnlyInMemorySecretBackend()
    )
    policies = PolicyStore(tmp_path / "policies.sqlite3")
    service = ProviderOnboardingService(
        vault,
        registry=registry,
        policies=policies,
        path=tmp_path / "connections.sqlite3",
        discovery=ModelDiscoveryService(registry),
    )
    connection = service.connect(
        "openai",
        configuration={},
        secret="synthetic-key",
    )
    assert connection.credential_id is not None
    provider = registry.create(
        "openai",
        {
            "model": "discovered",
            "credential_ref": connection.credential_id,
            "transport": NamedOpenAITransport(),
            "credential_resolver": resolve_async,
        },
    )
    probed = await service.probe("openai", provider)
    assert probed.authentication_state == "authenticated"
    assert probed.discovery_state == "discovered"
    assert probed.usable is True
    assert registry.definition("openai").models[0].model_id == "discovered"
    await provider.generate(
        GenerationRequest(
            (ChatMessage(uuid4(), uuid4(), MessageRole.USER, "hello", datetime.now(UTC)),),
            "discovered",
            4096,
        )
    )
    decision = ProviderRouter(registry).route(
        RouteRequest(
            "answer",
            "test",
            privacy_context=PrivacyContext(PrivacyClassification.SAFE_PUBLIC),
            usability_evidence=(evidence_for_success("openai", "discovered"),),
        )
    )
    assert decision.primary is not None
    assert decision.primary.provider_id == "openai"


def test_old_cheap_route_wins_over_premium_when_both_clear_quality_floor() -> None:
    old = replace(
        _model("old"),
        quality_score=0.80,
        input_cost_per_million=0.10,
        output_cost_per_million=0.10,
    )
    premium = replace(
        _model("premium"),
        quality_score=0.90,
        input_cost_per_million=5.0,
        output_cost_per_million=5.0,
    )
    registry = ProviderRegistry(
        (
            ProviderDefinition(
                ProviderMetadata("old-route", "Old", "1", local_only=True),
                lambda _: FakeAIProvider(),
                (old,),
            ),
            ProviderDefinition(
                ProviderMetadata("premium-route", "Premium", "1", local_only=True),
                lambda _: FakeAIProvider(),
                (premium,),
            ),
        )
    )
    decision = ProviderRouter(registry).route(
        RouteRequest("answer", "test", policy=RoutingPolicy.LOWEST_COST)
    )
    assert decision.status is RouteStatus.SELECTED
    assert decision.primary is not None and decision.primary.model_id == "old"


def test_dynamic_cost_history_is_durable_and_current_price_drives_routing(tmp_path: Path) -> None:
    model = replace(_model("model"), input_cost_per_million=10.0, output_cost_per_million=10.0)
    identity = identity_for("fixture", model)
    path = tmp_path / "budget.sqlite3"
    ledger = BudgetLedger(BudgetPolicy(), path)
    old = CostEvidence(
        CostStatus.KNOWN,
        10.0,
        10.0,
        observed_at=NOW,
        expires_at=NOW + timedelta(days=1),
        source="trusted-old",
    )
    current = CostEvidence(
        CostStatus.KNOWN,
        1.0,
        1.0,
        observed_at=NOW + timedelta(hours=1),
        expires_at=NOW + timedelta(days=2),
        source="trusted-current",
    )
    ledger.record_cost(identity, old)
    ledger.record_cost(identity, current)
    reopened = BudgetLedger(BudgetPolicy(), path)
    assert len(reopened.cost_history(identity)) == 2
    assert reopened.current_price(identity, now=NOW + timedelta(hours=2)) == current
    assert reopened.current_price(identity, now=NOW + timedelta(days=3)) is None

    registry = ProviderRegistry(
        (
            ProviderDefinition(
                ProviderMetadata("fixture", "Fixture", "1", local_only=True),
                lambda _: FakeAIProvider(),
                (model,),
            ),
        )
    )
    decision = ProviderRouter(
        registry, budget_ledger=reopened, clock=lambda: NOW + timedelta(hours=2)
    ).route(RouteRequest("answer", "test", policy=RoutingPolicy.LOWEST_COST))
    assert decision.primary is not None and decision.primary.cost == 2.0


def test_hundreds_of_models_remain_bounded_and_projectable() -> None:
    registry = ProviderRegistry(
        (
            ProviderDefinition(
                ProviderMetadata("fixture", "Fixture", "1", local_only=True),
                lambda _: FakeAIProvider(),
            ),
        )
    )
    models = tuple(_model(f"model-{index}") for index in range(1_024))
    registry.replace_models("fixture", models)
    page = ModelIntelligenceProjection(registry).page()
    assert len(page.models) == 1_024


async def test_h1_zero_cloud_runtime_keeps_local_decision_core(tmp_path: Path) -> None:
    runtime = ApplicationRuntime.create(
        Settings(app_data_dir=tmp_path / "data", ai_provider="ollama", ollama_autostart=False)
    )
    try:
        assert runtime.status is RuntimeStatus.READY
        assert runtime.container is not None
        result = await runtime.container.decision_router.decide(
            DecisionRequest(
                "classify", (), privacy_context=PrivacyContext(PrivacyClassification.SAFE_PUBLIC)
            )
        )
        assert result.provider_id == "local-decision"
        assert runtime.container.provider_onboarding.connection("openai") is None
    finally:
        await runtime.aclose()


def test_h24_full_r3h_state_reopens_without_identity_collapse(tmp_path: Path) -> None:
    backend = TestOnlyInMemorySecretBackend()
    vault = CredentialVault(tmp_path / "credentials.sqlite3", backend=backend)
    connections_path = tmp_path / "connections.sqlite3"
    policies_path = tmp_path / "policies.sqlite3"
    budget_path = tmp_path / "budget.sqlite3"
    quarantine_path = tmp_path / "quarantine.sqlite3"
    knowledge_path = tmp_path / "knowledge.sqlite3"

    model = _model("restart-model", endpoint="https://restart.example")
    identity = identity_for("fixture", model)
    onboarding = ProviderOnboardingService(vault, path=connections_path)
    connection = onboarding.connect("openai", configuration={}, secret="restart-secret")
    policies = PolicyStore(policies_path)
    policies.set_provider_policy("fixture", ProviderPolicy.ROUTING_DISABLED)
    policies.set_model_policy(identity, ModelPolicy.GUARDED)
    policies.set_bulk_policy(
        BulkPolicyRule("fixture-family", ModelPolicy.MANUAL_ONLY, family="fixture")
    )
    ledger = BudgetLedger(BudgetPolicy(daily_cloud_budget=8.0), budget_path)
    ledger.record(UsageReceipt(identity.storage_key, actual_cost=1.0, observed_at=NOW))
    quarantine = TaskQuarantine(threshold=2, path=quarantine_path)
    quarantine.record_failure(identity, "SECURITY_REVIEW")
    quarantine.record_failure(identity, "SECURITY_REVIEW")
    knowledge = ModelKnowledgeStore(knowledge_path)
    knowledge.refresh(_snapshot(model))
    knowledge.close()

    reopened_onboarding = ProviderOnboardingService(vault, path=connections_path)
    reopened_policies = PolicyStore(policies_path)
    reopened_ledger = BudgetLedger(BudgetPolicy(), budget_path)
    reopened_quarantine = TaskQuarantine(path=quarantine_path, threshold=2)
    reopened_knowledge = ModelKnowledgeStore(knowledge_path)
    reopened_connection = reopened_onboarding.connection("openai")
    assert reopened_connection is not None
    assert reopened_connection.credential_id == connection.credential_id
    assert reopened_policies.provider_policy("fixture") is ProviderPolicy.ROUTING_DISABLED
    assert reopened_policies.model_policy(identity) is ModelPolicy.GUARDED
    assert reopened_ledger.actual_total() == 1.0
    assert reopened_quarantine.is_quarantined(identity, "SECURITY_REVIEW")
    assert reopened_knowledge.models()[0].identity == identity
    assert b"restart-secret" not in connections_path.read_bytes()
    reopened_knowledge.close()


async def test_h29_guarded_failover_never_calls_unapproved_fallback() -> None:
    class FailingProvider(FakeAIProvider):
        async def generate(self, request: GenerationRequest) -> GenerationResult:
            del request
            raise ConnectionError("synthetic primary outage")

    primary = FailingProvider()
    fallback = FakeAIProvider()
    primary_model = replace(
        _model("primary"),
        quality_score=0.9,
        input_cost_per_million=0.1,
        output_cost_per_million=0.1,
    )
    fallback_model = replace(
        _model("fallback"),
        quality_score=0.8,
        input_cost_per_million=0.1,
        output_cost_per_million=0.1,
    )
    registry = ProviderRegistry(
        (
            ProviderDefinition(
                ProviderMetadata("primary", "Primary", "1", local_only=True),
                lambda _: primary,
                (primary_model,),
            ),
            ProviderDefinition(
                ProviderMetadata("fallback", "Fallback", "1", local_only=True),
                lambda _: fallback,
                (fallback_model,),
            ),
        )
    )
    policies = PolicyStore()
    fallback_identity = identity_for("fallback", fallback_model)
    policies.set_model_policy(fallback_identity, ModelPolicy.GUARDED)
    dispatcher = InferenceDispatcher(
        ProviderRouter(registry, policy_engine=PolicyEngine(policies)),
        registry,
        providers={"primary": primary, "fallback": fallback},
    )
    intent = RouteRequest(
        "answer",
        "test",
        preferred_provider_id="primary",
        explicit_selection=True,
        actor_id="actor",
        task_class="general",
        purpose="inference",
        approval_scope="inference",
        estimated_cost=1.0,
        privacy_context=PrivacyContext(PrivacyClassification.SAFE_PUBLIC),
    )
    with pytest.raises(InferenceDispatchError):
        await dispatcher.generate(GenerationRequest((), "primary", 4096), intent)
    assert fallback.requests == []
    approval = GuardedApproval(
        "actor",
        "general",
        fallback_identity.storage_key,
        "inference",
        1.0,
        "inference",
        NOW + timedelta(minutes=5),
    )
    approved = await dispatcher.generate(
        GenerationRequest((), "primary", 4096), replace(intent, guarded_approval=approval)
    )
    assert approved.result.model == "fallback"
    assert len(fallback.requests) == 1
