"""Focused durable model-knowledge and empirical cookbook coverage."""

import json
from concurrent.futures import ThreadPoolExecutor
from dataclasses import replace
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any, cast

import pytest
from jarvis.ai.knowledge import (
    CookbookObservation,
    CookbookOutcome,
    CookbookSummary,
    EvidenceFreshness,
    EvidenceSufficiency,
    KnowledgeAvailability,
    ModelIdentity,
    ModelKnowledgeError,
    ModelKnowledgeService,
    ModelKnowledgeStore,
    ModelObservation,
    ProviderCatalogSnapshot,
    VerifierAgreement,
    identity_for,
)
from jarvis.ai.model_manager import (
    LocalModelManager,
    LocalModelSpec,
    ModelArtifact,
)
from jarvis.ai.models import EvidenceKind, ModelRole
from jarvis.ai.providers.registry import (
    ModelMetadata,
    ProviderDefinition,
    ProviderLocality,
    ProviderMetadata,
    ProviderRegistry,
)
from jarvis.hardware import ModelMeasurement

from tests.fakes import FakeAIProvider

NOW = datetime(2026, 9, 11, 12, 0, tzinfo=UTC)


def metadata(
    model_id: str,
    *,
    version: str = "1",
    roles: frozenset[ModelRole] = frozenset({ModelRole.GENERAL}),
    capabilities: frozenset[str] = frozenset({"chat"}),
    storage_bytes: int | None = None,
    ram_bytes: int | None = None,
    vram_bytes: int | None = None,
    max_concurrency: int | None = None,
) -> ModelMetadata:
    return ModelMetadata(
        model_id,
        8_192,
        capabilities,
        roles,
        family="fixture-family",
        version=version,
        quantization="q4",
        runtime="fixture-runtime",
        source="fixture-catalog",
        modalities=frozenset({"text"}),
        storage_bytes=storage_bytes,
        ram_bytes=ram_bytes,
        vram_bytes=vram_bytes,
        max_concurrency=max_concurrency,
    )


def provider() -> ProviderMetadata:
    return ProviderMetadata("Fixture", "Fixture Provider", "1", locality=ProviderLocality.LOCAL)


def observation(
    model: ModelMetadata,
    *,
    observed_at: datetime = NOW,
    source: str = "fixture-catalog",
    evidence_kind: EvidenceKind = EvidenceKind.PUBLISHED,
    availability: KnowledgeAvailability = KnowledgeAvailability.KNOWN,
    machine_scope: str | None = None,
) -> ModelObservation:
    return ModelObservation(
        identity_for(provider().provider_id, model),
        model,
        observed_at,
        source,
        evidence_kind,
        "bounded fixture evidence",
        availability,
        machine_scope,
    )


def snapshot(*models: ModelMetadata, observed_at: datetime = NOW) -> ProviderCatalogSnapshot:
    return ProviderCatalogSnapshot(
        provider(),
        tuple(observation(model, observed_at=observed_at) for model in models),
        observed_at,
        "fixture-catalog",
    )


def test_identity_is_provider_and_variant_safe() -> None:
    base = ModelIdentity("FIXTURE", "same-model", "1", "q4", "runtime-a")
    assert base.provider_id == "fixture"
    assert base != ModelIdentity("other", "same-model", "1", "q4", "runtime-a")
    assert base != ModelIdentity("fixture", "same-model", "2", "q4", "runtime-a")
    assert base != ModelIdentity("fixture", "same-model", "1", "q8", "runtime-a")
    assert base != ModelIdentity("fixture", "same-model", "1", "q4", "runtime-b")
    assert base.provider_model == "fixture/same-model"


def test_malformed_knowledge_inputs_fail_closed() -> None:
    model = metadata("valid")
    identity = identity_for("fixture", model)
    with pytest.raises(ModelKnowledgeError):
        ModelIdentity("", "model")
    with pytest.raises(ModelKnowledgeError):
        ModelIdentity("fixture", "model", version="\x00")
    with pytest.raises(ModelKnowledgeError):
        identity_for("fixture", cast(Any, object()))
    with pytest.raises(ModelKnowledgeError):
        ModelObservation(cast(Any, object()), model, NOW, "source")
    with pytest.raises(ModelKnowledgeError):
        ModelObservation(ModelIdentity("fixture", "other"), model, NOW, "source")
    with pytest.raises(ModelKnowledgeError):
        ModelObservation(identity, model, cast(Any, datetime.now()), "source")
    with pytest.raises(ModelKnowledgeError):
        replace(ModelObservation(identity, model, NOW, "source"), evidence_kind=cast(Any, "bad"))
    with pytest.raises(ModelKnowledgeError):
        replace(ModelObservation(identity, model, NOW, "source"), availability=cast(Any, "bad"))
    with pytest.raises(ModelKnowledgeError):
        replace(
            ModelObservation(identity, model, NOW, "source"),
            machine_scope="this_machine",
        )
    with pytest.raises(ModelKnowledgeError):
        replace(
            ModelObservation(
                identity,
                model,
                NOW,
                "source",
                EvidenceKind.MEASURED_ON_THIS_MACHINE,
                machine_scope="this_machine",
            ),
            machine_scope="other_machine",
        )

    valid_snapshot = snapshot(model)
    with pytest.raises(ModelKnowledgeError):
        ProviderCatalogSnapshot(cast(Any, object()), (), NOW, "source")
    with pytest.raises(ModelKnowledgeError):
        ProviderCatalogSnapshot(provider(), cast(Any, []), NOW, "source")
    with pytest.raises(ModelKnowledgeError):
        ProviderCatalogSnapshot(
            provider(), (valid_snapshot.models[0], valid_snapshot.models[0]), NOW, "source"
        )
    with pytest.raises(ModelKnowledgeError):
        ProviderCatalogSnapshot(provider(), (), NOW, "source", available=cast(Any, "yes"))

    cookbook = CookbookObservation(identity, "chat", CookbookOutcome.UNKNOWN_OUTCOME, NOW)
    invalid_values = (
        {"identity": cast(Any, object())},
        {"outcome": cast(Any, "bad")},
        {"role": cast(Any, "bad")},
        {"locality": cast(Any, "bad")},
        {"latency_ms": -1.0},
        {"token_usage": -1},
        {"retry_count": -1},
        {"escalation_required": cast(Any, "yes")},
        {"structured_output_valid": cast(Any, "yes")},
        {"verifier_agreement": cast(Any, "bad")},
        {"evidence_refs": ("",)},
    )
    for values in invalid_values:
        with pytest.raises(ModelKnowledgeError):
            replace(cookbook, **values)
    with pytest.raises(ModelKnowledgeError):
        replace(cookbook, monetary_cost=-1.0)
    with pytest.raises(ModelKnowledgeError):
        replace(cookbook, tool_call_valid=cast(Any, "yes"))
    with pytest.raises(ModelKnowledgeError):
        replace(cookbook, machine_scope="\x00")

    empty_summary = CookbookSummary(
        identity,
        "chat",
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        None,
        EvidenceSufficiency.INSUFFICIENT,
    )
    assert empty_summary.verified_success_rate is None
    assert empty_summary.escalation_rate is None
    assert empty_summary.structured_output_reliability is None
    assert empty_summary.tool_reliability is None


def test_refresh_discovers_future_models_and_preserves_stale_history(tmp_path: Path) -> None:
    store = ModelKnowledgeStore(tmp_path / "knowledge.sqlite3")
    alpha = metadata("alpha")
    beta = metadata("beta", version="2")
    store.refresh(snapshot(alpha, observed_at=NOW))
    store.refresh(snapshot(alpha, beta, observed_at=NOW + timedelta(hours=1)))
    assert [item.identity.model_id for item in store.models()] == ["alpha", "beta"]

    store.refresh(snapshot(alpha, observed_at=NOW + timedelta(hours=2)))
    current = store.models()
    stale = store.models(include_stale=True)
    assert [item.identity.model_id for item in current] == ["alpha"]
    stale_beta = next(item for item in stale if item.identity.model_id == "beta")
    assert stale_beta.availability is KnowledgeAvailability.STALE
    assert stale_beta.first_seen == NOW + timedelta(hours=1)
    assert stale_beta.evidence_count == 1


@pytest.mark.parametrize(
    ("verified", "agreement"),
    [
        (False, VerifierAgreement.MODEL_SELF_CLAIM),
        (None, VerifierAgreement.UNKNOWN),
        (True, VerifierAgreement.MODEL_SELF_CLAIM),
        (True, VerifierAgreement.MODEL_REVIEW),
        (True, VerifierAgreement.UNKNOWN),
    ],
)
def test_verified_success_requires_trusted_consistency(
    tmp_path: Path, verified: bool | None, agreement: VerifierAgreement
) -> None:
    store = ModelKnowledgeStore(tmp_path / "knowledge.sqlite3")
    model = metadata("self-certifying")
    store.refresh(snapshot(model))
    identity = identity_for("fixture", model)

    with pytest.raises(ModelKnowledgeError):
        store.record_cookbook(
            CookbookObservation(
                identity,
                "chat",
                CookbookOutcome.VERIFIED_SUCCESS,
                NOW,
                verified=verified,
                verifier_agreement=agreement,
                observation_id="ineligible-verification",
            )
        )
    store.close()


@pytest.mark.parametrize(
    "agreement",
    [
        VerifierAgreement.DETERMINISTIC_VERIFICATION,
        VerifierAgreement.INDEPENDENT_MODEL_REVIEW,
        VerifierAgreement.USER_CONFIRMED,
    ],
)
def test_eligible_verified_success_is_counted(tmp_path: Path, agreement: VerifierAgreement) -> None:
    store = ModelKnowledgeStore(tmp_path / "knowledge.sqlite3")
    model = metadata("eligible-verification")
    store.refresh(snapshot(model))
    identity = identity_for("fixture", model)
    observation = CookbookObservation(
        identity,
        "chat",
        CookbookOutcome.VERIFIED_SUCCESS,
        NOW,
        verified=True,
        verifier_agreement=agreement,
        observation_id=agreement.value,
    )
    assert store.record_cookbook(observation)
    assert not store.record_cookbook(observation)
    assert store.cookbook_summary(identity, task_class="chat").verified_success_count == 1
    store.close()


def test_legacy_invalid_cookbook_row_cannot_inflate_summary(tmp_path: Path) -> None:
    store = ModelKnowledgeStore(tmp_path / "knowledge.sqlite3")
    model = metadata("legacy-cookbook")
    store.refresh(snapshot(model))
    identity = identity_for("fixture", model)
    valid = CookbookObservation(
        identity,
        "chat",
        CookbookOutcome.VERIFIED_SUCCESS,
        NOW,
        verified=True,
        verifier_agreement=VerifierAgreement.DETERMINISTIC_VERIFICATION,
        observation_id="legacy-row",
    )
    assert store.record_cookbook(valid)
    row = store._connection.execute(
        "SELECT observation_json FROM cookbook_observations WHERE observation_id=?",
        ("legacy-row",),
    ).fetchone()
    assert row is not None
    payload = json.loads(str(row[0]))
    payload["verified"] = False
    payload["verifier_agreement"] = VerifierAgreement.MODEL_SELF_CLAIM.value
    store._connection.execute(
        "UPDATE cookbook_observations SET observation_json=? WHERE observation_id=?",
        (json.dumps(payload), "legacy-row"),
    )
    store._connection.commit()
    summary = store.cookbook_summary(identity, task_class="chat")
    assert summary.sample_count == 0
    assert summary.verified_success_count == 0
    store.close()


def test_measurements_remain_separate_latest_bounded_and_restart_safe(
    tmp_path: Path,
) -> None:
    store = ModelKnowledgeStore(tmp_path / "knowledge.sqlite3")
    model_a = metadata(
        "measurement-projection",
        storage_bytes=10,
        ram_bytes=10,
        vram_bytes=11,
        max_concurrency=1,
    )
    store.refresh(snapshot(model_a, observed_at=NOW))
    identity = identity_for("fixture", model_a)
    measurement = ModelMeasurement(
        model_a.model_id,
        NOW + timedelta(minutes=1),
        "trusted-runtime",
        storage_bytes=20,
        peak_ram_bytes=20,
        peak_vram_bytes=21,
        concurrency=2,
    )
    store.record_measurement(identity, measurement, machine_scope="this_machine")

    model_c = metadata(
        "measurement-projection",
        storage_bytes=30,
        ram_bytes=30,
        vram_bytes=31,
        max_concurrency=3,
    )
    store.refresh(snapshot(model_c, observed_at=NOW + timedelta(minutes=2)))
    view = store.inspect_model(identity)

    assert view.metadata.storage_bytes == 30
    assert view.metadata.ram_bytes == 30
    assert view.metadata.vram_bytes == 31
    assert view.metadata.max_concurrency == 3
    assert view.source == "fixture-catalog"
    assert view.measurement_count == 1
    latest = store.latest_measurement(identity)
    assert latest is not None
    assert latest.identity == identity
    assert latest.measured_at == measurement.measured_at
    assert latest.source == "trusted-runtime"
    assert latest.machine_scope == "this_machine"
    assert latest.evidence_kind is EvidenceKind.MEASURED_ON_THIS_MACHINE
    assert latest.storage_bytes == 20
    assert latest.peak_ram_bytes == 20
    assert latest.peak_vram_bytes == 21
    assert latest.concurrency == 2
    assert latest.load_seconds is None
    assert latest.throughput is None
    assert any(
        item.kind is EvidenceKind.MEASURED_ON_THIS_MACHINE for item in store.evidence(identity)
    )
    unmeasured = metadata("unmeasured")
    store.refresh(snapshot(model_c, unmeasured, observed_at=NOW + timedelta(minutes=2)))
    assert store.latest_measurement(identity_for("fixture", unmeasured)) is None

    newer = ModelMeasurement(
        model_a.model_id,
        NOW + timedelta(minutes=3),
        "trusted-runtime-newer",
        peak_ram_bytes=40,
        throughput=12.5,
    )
    store.record_measurement(identity, newer, machine_scope="this_machine")
    store.record_measurement(identity, newer, machine_scope="this_machine")
    latest = store.latest_measurement(identity)
    assert latest is not None
    assert latest.measured_at == newer.measured_at
    assert latest.source == newer.source
    assert latest.peak_ram_bytes == 40
    assert latest.throughput == 12.5
    assert store.inspect_model(identity).measurement_count == 2
    tie_time = NOW + timedelta(minutes=4)
    store.record_measurement(
        identity,
        ModelMeasurement(model_a.model_id, tie_time, "z-runtime", throughput=1.0),
        machine_scope="this_machine",
    )
    store.record_measurement(
        identity,
        ModelMeasurement(model_a.model_id, tie_time, "a-runtime", throughput=2.0),
        machine_scope="this_machine",
    )
    tied = store.measurements(identity, limit=2)
    assert [item.source for item in tied] == ["a-runtime", "z-runtime"]
    tied_latest = store.latest_measurement(identity)
    assert tied_latest is not None
    assert tied_latest.source == "a-runtime"
    assert len(store.measurements(identity, limit=1)) == 1
    with pytest.raises(ModelKnowledgeError):
        store.measurements(identity, limit=0)
    with pytest.raises(ModelKnowledgeError):
        store.measurements(identity, machine_scope="other-machine")
    store.close()

    restarted = ModelKnowledgeStore(tmp_path / "knowledge.sqlite3")
    restarted_latest = restarted.latest_measurement(identity)
    assert restarted_latest is not None
    assert restarted_latest.measured_at == tie_time
    assert restarted_latest.source == "a-runtime"
    assert len(restarted.measurements(identity, limit=32)) == 4
    with pytest.raises(ModelKnowledgeError):
        restarted.record_measurement(identity, newer, machine_scope="machine-serial")
    restarted.close()


def test_dynamic_registry_update_and_provider_availability_are_observable(
    tmp_path: Path,
) -> None:
    store = ModelKnowledgeStore(tmp_path / "knowledge.sqlite3")
    service = ModelKnowledgeService(store)
    alpha = metadata("alpha")
    beta = metadata("beta")
    registry = ProviderRegistry(
        (ProviderDefinition(provider(), lambda _: FakeAIProvider(), (alpha,)),)
    )
    service.refresh_registry(registry, observed_at=NOW, source="registry-alpha")
    assert [item.identity.model_id for item in service.models()] == ["alpha"]
    registry.replace_models("fixture", (alpha, beta))
    service.refresh_registry(
        registry, observed_at=NOW + timedelta(minutes=1), source="registry-beta"
    )
    assert [item.identity.model_id for item in service.models()] == ["alpha", "beta"]

    service.observe_provider_health(
        provider(),
        False,
        observed_at=NOW + timedelta(minutes=2),
        source="health-check",
        detail="provider unavailable",
    )
    unavailable = service.providers()[0]
    assert unavailable.availability is KnowledgeAvailability.CURRENTLY_UNAVAILABLE
    service.observe_provider_health(
        provider(),
        True,
        observed_at=NOW + timedelta(minutes=3),
        source="health-check",
        detail="provider available",
    )
    assert service.providers()[0].availability is KnowledgeAvailability.KNOWN
    service.close()


def test_capability_role_modality_unknown_and_deterministic_bounds(tmp_path: Path) -> None:
    store = ModelKnowledgeStore(tmp_path / "knowledge.sqlite3")
    store.refresh(
        snapshot(
            metadata("general", roles=frozenset({ModelRole.GENERAL})),
            metadata(
                "vision",
                roles=frozenset({ModelRole.VISION}),
                capabilities=frozenset({"vision"}),
            ),
        )
    )
    assert [item.identity.model_id for item in store.models(role=ModelRole.VISION)] == ["vision"]
    assert [item.identity.model_id for item in store.models(capability="missing")] == []
    assert [item.identity.model_id for item in store.models(modality="audio")] == []
    assert len(store.models(limit=1)) == 1
    with pytest.raises(ModelKnowledgeError):
        store.models(limit=0)
    store.close()


def test_provenance_precedence_freshness_and_machine_scope(tmp_path: Path) -> None:
    store = ModelKnowledgeStore(tmp_path / "knowledge.sqlite3")
    model = metadata("measured")
    store.refresh(snapshot(model))
    identity = identity_for(provider().provider_id, model)
    measurement = ModelMeasurement(
        model.model_id,
        NOW + timedelta(minutes=1),
        "local-benchmark",
        storage_bytes=123,
        peak_ram_bytes=456,
        peak_vram_bytes=789,
        concurrency=2,
    )
    store.record_measurement(identity, measurement, machine_scope="this_machine")
    view = store.inspect_model(identity)
    assert view.source == "fixture-catalog"
    assert view.metadata.storage_bytes is None
    assert view.metadata.vram_bytes is None
    assert view.measurement_count == 1
    latest = store.latest_measurement(identity)
    assert latest is not None
    assert latest.storage_bytes == 123
    assert latest.peak_vram_bytes == 789
    assert any(
        item.kind is EvidenceKind.MEASURED_ON_THIS_MACHINE for item in store.evidence(identity)
    )
    assert view.freshness is EvidenceFreshness.FRESH
    old = store.models(as_of=NOW + timedelta(days=2))[0]
    assert old.freshness is EvidenceFreshness.STALE
    with pytest.raises(ModelKnowledgeError):
        store.record_measurement(identity, measurement, machine_scope="machine-serial")
    store.close()


def test_store_and_service_reject_bad_or_unknown_queries(tmp_path: Path) -> None:
    with pytest.raises(ModelKnowledgeError):
        ModelKnowledgeStore(cast(Any, "not-a-path"))
    with pytest.raises(ModelKnowledgeError):
        ModelKnowledgeService(cast(Any, object()))

    store = ModelKnowledgeStore(tmp_path / "knowledge.sqlite3")
    model = metadata("known")
    store.refresh(snapshot(model))
    identity = identity_for("fixture", model)
    service = ModelKnowledgeService(store)
    measurement = ModelMeasurement(model.model_id, NOW, "fixture")
    cookbook = CookbookObservation(identity, "chat", CookbookOutcome.UNKNOWN_OUTCOME, NOW)
    service.record_measurement(identity, measurement)
    assert service.record_cookbook(cookbook)
    assert service.evidence(identity)
    assert service.cookbook_summary(identity, task_class="chat").sample_count == 1

    with pytest.raises(ModelKnowledgeError):
        store.record_model_observation(cast(Any, object()))
    with pytest.raises(ModelKnowledgeError):
        store.record_model_observation(
            ModelObservation(identity_for("missing", model), model, NOW, "source")
        )
    with pytest.raises(ModelKnowledgeError):
        store.record_measurement(cast(Any, object()), measurement, machine_scope="this_machine")
    with pytest.raises(ModelKnowledgeError):
        store.record_measurement(
            ModelIdentity("fixture", "unknown"),
            measurement,
            machine_scope="this_machine",
        )
    with pytest.raises(ModelKnowledgeError):
        store.models(role=cast(Any, "bad"))
    with pytest.raises(ModelKnowledgeError):
        store.evidence(cast(Any, object()))
    with pytest.raises(KeyError):
        store.inspect_model(ModelIdentity("fixture", "unknown"))
    with pytest.raises(ModelKnowledgeError):
        store.record_cookbook(cast(Any, object()))
    with pytest.raises(ModelKnowledgeError):
        store.record_cookbook(
            CookbookObservation(
                ModelIdentity("fixture", "unknown"),
                "chat",
                CookbookOutcome.UNKNOWN_OUTCOME,
                NOW,
            )
        )
    with pytest.raises(ModelKnowledgeError):
        store.cookbook_summary(cast(Any, object()))
    store.close()

    unknown_store = ModelKnowledgeStore(tmp_path / "unknown.sqlite3")
    unknown_store.register_provider(provider())
    assert unknown_store.providers(as_of=NOW)[0].freshness is EvidenceFreshness.UNKNOWN
    unknown_store.close()


def test_local_model_registration_enters_knowledge_without_raw_content(tmp_path: Path) -> None:
    store = ModelKnowledgeStore(tmp_path / "knowledge.sqlite3")
    service = ModelKnowledgeService(store)
    service.refresh(snapshot())
    model = metadata("manager-model")
    manager = LocalModelManager(
        tmp_path / "models",
        knowledge=service,
        provider_id="fixture",
        clock=lambda: NOW,
    )
    manager.register(LocalModelSpec(model.model_id, model, ModelArtifact("catalog", "a" * 64, 1)))
    assert service.inspect_model(identity_for("fixture", model)).evidence_count >= 1
    assert not hasattr(manager, "prompt")
    service.close()


def test_cookbook_outcomes_summary_duplicate_restart_and_no_prompt_field(tmp_path: Path) -> None:
    path = tmp_path / "knowledge.sqlite3"
    store = ModelKnowledgeStore(path)
    model = metadata("cookbook")
    store.refresh(snapshot(model))
    identity = identity_for("fixture", model)

    def record(index: int, outcome: CookbookOutcome) -> bool:
        return store.record_cookbook(
            CookbookObservation(
                identity,
                "structured_tool",
                outcome,
                NOW + timedelta(minutes=index),
                operation_class="bounded-test",
                role=ModelRole.TOOL_USE,
                environment="local-test",
                locality=ProviderLocality.LOCAL,
                machine_scope="this_machine",
                input_size_bucket="small",
                verified=outcome is CookbookOutcome.VERIFIED_SUCCESS,
                latency_ms=10 + index,
                structured_output_valid=index != 1,
                tool_call_valid=index == 0,
                escalation_required=outcome is CookbookOutcome.ESCALATION,
                failure_class="fixture" if outcome is CookbookOutcome.FAILURE else "",
                verifier_agreement=VerifierAgreement.DETERMINISTIC_VERIFICATION,
                observation_id=f"observation-{index}",
            )
        )

    assert record(0, CookbookOutcome.VERIFIED_SUCCESS)
    assert not record(0, CookbookOutcome.VERIFIED_SUCCESS)
    assert record(1, CookbookOutcome.FAILURE)
    assert record(2, CookbookOutcome.ESCALATION)
    assert record(3, CookbookOutcome.UNKNOWN_OUTCOME)
    summary = store.cookbook_summary(identity, task_class="structured_tool")
    assert summary.sample_count == 4
    assert summary.verified_success_count == 1
    assert summary.failure_count == 1
    assert summary.escalation_count == 1
    assert summary.unknown_outcome_count == 1
    assert summary.structured_sample_count == 4
    assert summary.tool_sample_count == 4
    assert summary.evidence_sufficiency is EvidenceSufficiency.SUFFICIENT
    assert "prompt" not in {field for field in summary.__dataclass_fields__}
    store.close()

    restarted = ModelKnowledgeStore(path)
    assert restarted.cookbook_summary(identity, task_class="structured_tool").sample_count == 4
    assert not restarted.record_cookbook(
        CookbookObservation(
            identity,
            "structured_tool",
            CookbookOutcome.VERIFIED_SUCCESS,
            NOW,
            verified=True,
            verifier_agreement=VerifierAgreement.DETERMINISTIC_VERIFICATION,
            observation_id="observation-0",
        )
    )
    restarted.close()


def test_cookbook_concurrent_ingestion_is_bounded_and_deterministic(tmp_path: Path) -> None:
    store = ModelKnowledgeStore(tmp_path / "knowledge.sqlite3")
    model = metadata("concurrent")
    store.refresh(snapshot(model))
    identity = identity_for("fixture", model)

    def ingest(index: int) -> bool:
        return store.record_cookbook(
            CookbookObservation(
                identity,
                "chat",
                CookbookOutcome.UNKNOWN_OUTCOME,
                NOW + timedelta(seconds=index),
                observation_id=f"concurrent-{index}",
            )
        )

    with ThreadPoolExecutor(max_workers=8) as executor:
        results = list(executor.map(ingest, range(32)))
    assert all(results)
    assert store.cookbook_summary(identity, task_class="chat").sample_count == 32
    store.close()
