from __future__ import annotations

import sqlite3
from concurrent.futures import ThreadPoolExecutor
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

import pytest
from jarvis.bootstrap import create_provider_registry
from jarvis.human_adaptation import (
    AdaptivePersonaMode,
    BehavioralAggregateEvent,
    HumanAdaptationMigrationError,
    HumanAdaptationService,
    HumanAdaptationStore,
    Localizer,
    PersonalizationMode,
)


def _service(path: Path, **kwargs: Any) -> HumanAdaptationService:
    return HumanAdaptationService(HumanAdaptationStore(path), cooldown=timedelta(0), **kwargs)


def test_store_transaction_rolls_back_and_reopens(tmp_path: Path) -> None:
    path = tmp_path / "human.sqlite3"
    with HumanAdaptationStore(path) as store:
        with pytest.raises(RuntimeError):
            with store.transaction():
                store.set_state("rollback_probe", {"value": 1})
                raise RuntimeError("forced rollback")
        assert store.get_state("rollback_probe") is None
        assert store.schema_version() == 1
    with HumanAdaptationStore(path) as reopened:
        assert reopened.schema_version() == 1


def test_future_and_incomplete_schemas_fail_closed(tmp_path: Path) -> None:
    future = tmp_path / "future.sqlite3"
    connection = sqlite3.connect(future)
    connection.execute(
        "CREATE TABLE schema_versions("
        "version INTEGER PRIMARY KEY, name TEXT NOT NULL, applied_at TEXT NOT NULL)"
    )
    connection.execute(
        "INSERT INTO schema_versions VALUES (99, 'future', '2026-09-21T00:00:00+00:00')"
    )
    connection.commit()
    connection.close()
    with pytest.raises(HumanAdaptationMigrationError):
        HumanAdaptationStore(future)

    incomplete = tmp_path / "incomplete.sqlite3"
    connection = sqlite3.connect(incomplete)
    connection.execute(
        "CREATE TABLE schema_versions("
        "version INTEGER PRIMARY KEY, name TEXT NOT NULL, applied_at TEXT NOT NULL)"
    )
    connection.execute(
        "INSERT INTO schema_versions VALUES "
        "(1, 'initial human adaptation schema', '2026-09-21T00:00:00+00:00')"
    )
    connection.commit()
    connection.close()
    with pytest.raises(HumanAdaptationMigrationError):
        HumanAdaptationStore(incomplete)

    wrong_identity = tmp_path / "wrong-identity.sqlite3"
    connection = sqlite3.connect(wrong_identity)
    connection.execute(
        "CREATE TABLE schema_versions("
        "version INTEGER PRIMARY KEY, name TEXT NOT NULL, applied_at TEXT NOT NULL)"
    )
    connection.execute(
        "INSERT INTO schema_versions VALUES "
        "(1, 'not-the-initial-migration', '2026-09-21T00:00:00+00:00')"
    )
    connection.commit()
    connection.close()
    with pytest.raises(HumanAdaptationMigrationError):
        HumanAdaptationStore(wrong_identity)


def test_concurrent_aggregate_updates_are_serialized(tmp_path: Path) -> None:
    service = _service(tmp_path / "human.sqlite3")
    service.configure_personalization(
        mode=PersonalizationMode.DEEP.value,
        behavioral_learning=True,
    )

    with ThreadPoolExecutor(max_workers=8) as executor:
        results = list(
            executor.map(
                lambda _: service.record_behavior_event(
                    BehavioralAggregateEvent("composer", keystroke_count=1)
                ),
                range(100),
            )
        )

    assert all(results)
    aggregates = service.behavioral_aggregates()
    assert isinstance(aggregates["composer"], dict)
    assert aggregates["composer"]["events"] == 100
    assert aggregates["composer"]["keystrokes"] == 100
    service.store.close()


def test_evidence_window_and_reset_do_not_reuse_stale_learning(tmp_path: Path) -> None:
    now = [datetime(2026, 9, 21, tzinfo=UTC)]
    service = _service(
        tmp_path / "human.sqlite3",
        clock=lambda: now[0],
        evidence_window=timedelta(hours=1),
    )
    service.configure_personalization(
        mode=PersonalizationMode.COMMUNICATION.value,
        adaptive_persona=AdaptivePersonaMode.ADAPTIVE.value,
    )
    assert not service.record_persona_evidence("formality", 4, confidence=1.0)
    assert not service.record_persona_evidence("formality", 4, confidence=1.0)
    now[0] += timedelta(hours=2)
    assert not service.record_persona_evidence("formality", 4, confidence=1.0)
    assert not service.record_persona_evidence("formality", 4, confidence=1.0)
    assert service.record_persona_evidence("formality", 4, confidence=1.0)

    service.reset_adaptations()
    assert not service.record_persona_evidence("formality", 0, confidence=1.0)
    service.store.close()


def test_reset_learning_clears_hidden_routine_counters(tmp_path: Path) -> None:
    service = _service(tmp_path / "human.sqlite3")
    service.configure_personalization(
        mode=PersonalizationMode.CONTEXTUAL.value,
        routine_learning=True,
    )
    assert service.observe_routine("open.dashboard", "suggest dashboard") is None
    assert service.observe_routine("open.dashboard", "suggest dashboard") is None
    service.reset_learning()
    assert service.observe_routine("open.dashboard", "suggest dashboard") is None
    assert service.observe_routine("open.dashboard", "suggest dashboard") is None
    assert service.routine_candidates() == ()
    service.store.close()


def test_deep_to_off_stops_every_learning_surface(tmp_path: Path) -> None:
    service = _service(tmp_path / "human.sqlite3")
    service.configure_personalization(
        mode=PersonalizationMode.DEEP.value,
        adaptive_persona=AdaptivePersonaMode.ADAPTIVE.value,
        routine_learning=True,
        behavioral_learning=True,
    )
    service.configure_personalization(mode=PersonalizationMode.OFF.value)
    assert not service.record_persona_evidence("formality", 4, confidence=1.0)
    assert (
        service.record_expression_feedback("tone", "informal", confidence=1.0, provenance="test")
        is None
    )
    assert not service.record_behavior_event(BehavioralAggregateEvent("composer"))
    assert service.observe_routine("open.dashboard", "suggest dashboard") is None
    service.store.close()


def test_style_fidelity_keeps_semantic_intent_unchanged(tmp_path: Path) -> None:
    service = _service(tmp_path / "human.sqlite3")
    service.configure_personalization(style_fidelity="maximum")
    decline = service.render_style("Decline invitation.", relationship="friend")
    payment = service.render_style("Do not approve payment.", relationship="business")
    assert "Decline invitation." in decline
    assert "Do not approve payment." in payment
    service.store.close()


def test_secure_expression_and_unbounded_style_canary_never_persist(tmp_path: Path) -> None:
    canary = "R3F_PRIVATE_RAW_STYLE_CANARY_7c9b"
    service = _service(tmp_path / "human.sqlite3")
    service.configure_personalization(mode=PersonalizationMode.COMMUNICATION.value)
    assert (
        service.record_expression_feedback(
            "tone",
            canary,
            confidence=1.0,
            provenance="secure-entry",
            secure_input=True,
        )
        is None
    )
    with pytest.raises(ValueError):
        service.record_expression_feedback("tone", canary, confidence=1.0, provenance="untrusted")
    assert service.expression_profile() == ()
    assert canary not in repr(service.cloud_style_projection())
    service.store.close()


def test_personalization_rejects_unknown_state_fields(tmp_path: Path) -> None:
    with HumanAdaptationStore(tmp_path / "human.sqlite3") as store:
        service = HumanAdaptationService(store)
        with pytest.raises(ValueError):
            service.configure_personalization(raw_secret="R3F_PRIVATE_RAW_STYLE_CANARY_7c9b")


def test_localizer_rejects_format_expressions_and_malformed_resources() -> None:
    with pytest.raises(ValueError):
        Localizer({"en": {"message": "{value!r}"}})
    with pytest.raises(ValueError):
        Localizer({"en": {"message": "{value.__class__}"}})
    with pytest.raises(ValueError):
        Localizer({"en": {"message": "x" * 4097}})
    with pytest.raises(ValueError):
        Localizer({"en": {"message": "{value}"}}).translate("message", "en", value="\n")


def test_default_registry_does_not_claim_dutch_for_arbitrary_models() -> None:
    default = create_provider_registry(model_id="arbitrary-model")
    capabilities = default.definition("ollama").models[0].capabilities
    assert "language:en" in capabilities
    assert "language:nl" not in capabilities
    declared = create_provider_registry(
        model_id="measured-dutch-model",
        declared_language_capabilities=frozenset({"language:en", "language:nl"}),
    )
    assert "language:nl" in declared.definition("ollama").models[0].capabilities
