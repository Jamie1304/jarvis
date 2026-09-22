from __future__ import annotations

from datetime import timedelta
from pathlib import Path

from jarvis.human_adaptation import (
    AdaptivePersonaMode,
    BehavioralAggregateEvent,
    HumanAdaptationService,
    HumanAdaptationStore,
    ObservationScope,
    PersonalizationMode,
)


def _service(tmp_path: Path) -> HumanAdaptationService:
    return HumanAdaptationService(
        HumanAdaptationStore(tmp_path / "human.sqlite3"), cooldown=timedelta(0)
    )


def test_off_and_explicit_only_do_not_learn_behavior(tmp_path: Path) -> None:
    service = _service(tmp_path)
    assert not service.record_behavior_event(
        BehavioralAggregateEvent("composer", keystroke_count=4)
    )
    assert (
        service.record_expression_feedback("tone", "informal", confidence=1.0, provenance="test")
        is None
    )
    service.configure_personalization(mode=PersonalizationMode.EXPLICIT_ONLY.value)
    assert service.record_persona_evidence("formality", 0, confidence=1.0) is False
    assert service.expression_profile() == ()
    service.store.close()


def test_adaptation_is_thresholded_gradual_and_explicit_correction_wins(tmp_path: Path) -> None:
    service = _service(tmp_path)
    service.configure_personalization(
        mode=PersonalizationMode.COMMUNICATION.value,
        adaptive_persona=AdaptivePersonaMode.ADAPTIVE.value,
    )
    assert service.record_persona_evidence("formality", 4, confidence=0.9) is False
    assert service.record_persona_evidence("formality", 4, confidence=0.9) is False
    assert service.record_persona_evidence("formality", 4, confidence=0.9) is True
    assert service.adaptive_persona()["formality"] == 3
    assert service.record_persona_evidence("formality", 4, confidence=0.9) is False
    service.mark_explicit_persona_update({"formality": 0})
    assert "formality" in service.pinned_persona_traits()
    assert service.record_persona_evidence("formality", 4, confidence=1.0) is False
    assert (
        service.effective_persona_projection(
            {"formality": 0, **{key: 2 for key in service.adaptive_persona() if key != "formality"}}
        )["formality"]
        == 0
    )
    service.store.close()


def test_freeze_pin_secure_input_routines_and_restart(tmp_path: Path) -> None:
    path = tmp_path / "human.sqlite3"
    store = HumanAdaptationStore(path)
    service = HumanAdaptationService(store, cooldown=timedelta(0))
    service.configure_personalization(
        mode=PersonalizationMode.DEEP.value,
        adaptive_persona=AdaptivePersonaMode.ADAPTIVE.value,
        routine_learning=True,
        behavioral_learning=True,
        observation_scope=ObservationScope.JARVIS_ONLY.value,
    )
    secure = BehavioralAggregateEvent("composer", keystroke_count=10, secure_input=True)
    assert service.record_behavior_event(secure) is False
    assert (
        service.record_behavior_event(BehavioralAggregateEvent("composer", keystroke_count=10))
        is True
    )
    assert "composer" in service.behavioral_aggregates()
    assert service.observe_routine("open.dashboard", "suggest dashboard") is None
    assert service.observe_routine("open.dashboard", "suggest dashboard") is None
    candidate = service.observe_routine("open.dashboard", "suggest dashboard")
    assert candidate is not None and candidate.suggestion_only
    service.freeze_adaptive_persona()
    service.pause_learning()
    service.store.close()

    with HumanAdaptationStore(path) as restarted_store:
        restarted = HumanAdaptationService(restarted_store)
        assert restarted.personalization_settings()["learning_paused"] is True
        assert restarted.routine_candidates()[0].proposed_action == "suggest dashboard"
        assert restarted.observation_status()["scope"] == ObservationScope.JARVIS_ONLY.value


def test_relationship_style_and_cloud_projection_are_bounded(tmp_path: Path) -> None:
    service = _service(tmp_path)
    service.configure_personalization(
        mode=PersonalizationMode.COMMUNICATION.value, style_fidelity="high"
    )
    service.record_expression_feedback(
        "tone", "informal", confidence=0.9, provenance="correction", relationship="friend"
    )
    friend = service.render_style("Please review the draft.", relationship="friend")
    business = service.render_style("Please review the draft.", relationship="business")
    assert friend != business
    projection = service.cloud_style_projection(relationship="friend")
    assert set(projection) >= {"tone", "length", "directness", "relationship"}
    assert "Please review" not in repr(projection)
    service.store.close()
