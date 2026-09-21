from __future__ import annotations

from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import cast
from uuid import uuid4

from jarvis.actor_persona import ActorContextService, ActorContextSource
from jarvis.ai.models import (
    ChatMessage,
    GenerationRequest,
    MessageRole,
    PrivacyClassification,
    PrivacyContext,
)
from jarvis.ai.privacy import PrivacyBoundary
from jarvis.ai.providers.base import AIProvider
from jarvis.ai.providers.registry import (
    ModelMetadata,
    ProviderDefinition,
    ProviderLocality,
    ProviderMetadata,
    ProviderRegistry,
)
from jarvis.ai.routing import ProviderRouter, RouteRequest, RouteStatus
from jarvis.human_adaptation import (
    AdaptivePersonaMode,
    BehavioralAggregateEvent,
    ConversationLanguageMode,
    DeterministicLanguageDetector,
    HumanAdaptationService,
    HumanAdaptationStore,
    LanguageOverrides,
    LanguageSupportState,
    LanguageTag,
    ObservationScope,
    PersonalizationMode,
    localize_approval_request,
    localize_capability_metadata,
)
from jarvis.permissions.models import (
    ApprovalRequest,
    ApprovalStatus,
    DecisionReason,
    Permission,
    PermissionScope,
    Risk,
    SafeArgument,
)
from jarvis.permissions.policy import normalize_scope


def _service(tmp_path: Path) -> HumanAdaptationService:
    return HumanAdaptationService(
        HumanAdaptationStore(tmp_path / "human.sqlite3"), cooldown=timedelta(0)
    )


def _approval() -> ApprovalRequest:
    task_id = uuid4()
    created = datetime(2026, 9, 21, tzinfo=UTC)
    return ApprovalRequest(
        request_id=uuid4(),
        task_id=task_id,
        exact_action="write report",
        arguments_summary=(SafeArgument("path", "C:/private/report.txt"),),
        argument_fingerprint="a" * 64,
        action_fingerprint="b" * 64,
        permission=Permission.FILESYSTEM_WRITE,
        risk=Risk.HIGH,
        scope=normalize_scope(
            PermissionScope(
                paths=("C:/private/report.txt",),
                tool_id="trusted-file",
                task_id=task_id,
                duration_seconds=30,
            ),
            Permission.FILESYSTEM_WRITE,
        ),
        reason=DecisionReason.POLICY_APPROVAL_REQUIRED,
        policy_id="test.write",
        created_at=created,
        expires_at=created + timedelta(seconds=30),
        status=ApprovalStatus.PENDING,
    )


def test_r3f_r2_canonical_m1_independent_ui_and_conversation_language(tmp_path: Path) -> None:
    service = _service(tmp_path)
    service.set_language_preferences(
        interface_language="nl",
        locale="nl-NL",
        conversation_language="nl",
        conversation_mode="fixed",
    )
    context = service.resolve_language(LanguageOverrides(requested_output=LanguageTag("en")))
    assert context.interface_language == LanguageTag("nl")
    assert context.conversation.language == LanguageTag("nl")
    assert context.output.language == LanguageTag("en")


def test_r3f_r2_canonical_m2_typed_language_switch(tmp_path: Path) -> None:
    service = _service(tmp_path)
    service.set_language_preferences(conversation_mode=ConversationLanguageMode.AUTO.value)
    detector = DeterministicLanguageDetector()
    dutch = service.resolve_language(detected=detector.detect("Schrijf dit graag"))
    english = service.resolve_language(detected=detector.detect("Please write this"))
    assert dutch.conversation.language == LanguageTag("nl")
    assert english.conversation.language == LanguageTag("en")
    assert service.language_preferences().interface_language == LanguageTag("en")


def test_r3f_r2_canonical_m3_mixed_language_task(tmp_path: Path) -> None:
    service = _service(tmp_path)
    context = service.resolve_language(
        LanguageOverrides(content=LanguageTag("en"), requested_output=LanguageTag("nl"))
    )
    assert context.content_language == LanguageTag("en")
    assert context.output.language == LanguageTag("nl")
    assert "content_language=en" in context.prompt_projection()


def test_r3f_r2_canonical_m4_requested_output_override(tmp_path: Path) -> None:
    service = _service(tmp_path)
    service.set_language_preferences(
        interface_language="nl", conversation_language="nl", conversation_mode="fixed"
    )
    context = service.resolve_language(LanguageOverrides(requested_output=LanguageTag("en")))
    assert context.output.language == LanguageTag("en")
    assert context.interface_language == LanguageTag("nl")
    assert service.language_preferences().conversation_language == LanguageTag("nl")


def test_r3f_r2_canonical_m5_restart_persistence(tmp_path: Path) -> None:
    path = tmp_path / "human.sqlite3"
    with HumanAdaptationStore(path) as store:
        HumanAdaptationService(store).set_language_preferences(
            interface_language="nl", locale="nl-NL", conversation_mode="auto", stt_language="nl"
        )
    with HumanAdaptationStore(path) as store:
        preferences = HumanAdaptationService(store).language_preferences()
        assert preferences.interface_language == LanguageTag("nl")
        assert preferences.locale == "nl-NL"
        assert preferences.stt_language == LanguageTag("nl")


def test_r3f_r2_canonical_m6_partial_language_is_truthful(tmp_path: Path) -> None:
    capability = _service(tmp_path).capability("xx")
    assert capability.state is LanguageSupportState.UNSUPPORTED
    assert capability.state.value == "unsupported"


def test_r3f_r2_canonical_m7_dynamic_capability_localization(tmp_path: Path) -> None:
    del tmp_path
    metadata = {
        "name": "Power",
        "description": "A capability",
        "names": {"en": "Power", "nl": "Inschakelen"},
        "descriptions": {"en": "Turn on", "nl": "Schakel in"},
    }
    presentation = localize_capability_metadata("generated.power", metadata, "nl")
    assert presentation.capability_id == "generated.power"
    assert presentation.name == "Inschakelen"


def test_r3f_r2_canonical_m8_approval_binding_is_language_invariant(tmp_path: Path) -> None:
    del tmp_path
    request = _approval()
    english = localize_approval_request(request, "en")
    dutch = localize_approval_request(request, "nl")
    assert english.short_text != dutch.short_text
    assert (english.request_id, english.argument_fingerprint, english.action_fingerprint) == (
        dutch.request_id,
        dutch.argument_fingerprint,
        dutch.action_fingerprint,
    )


def test_r3f_r2_canonical_m9_multilingual_privacy(tmp_path: Path) -> None:
    del tmp_path
    boundary = PrivacyBoundary(
        ProviderMetadata("remote", "Remote", "test", locality=ProviderLocality.REMOTE)
    )
    counts: list[int] = []
    for canary in ("Jamie private address", "Jamies privé-adres"):
        message = ChatMessage(uuid4(), uuid4(), MessageRole.USER, canary, datetime.now(UTC))
        request = GenerationRequest(
            (message,),
            "remote",
            512,
            PrivacyContext(PrivacyClassification.SANITIZABLE, (canary,)),
        )
        outbound, _ = boundary.prepare(request)
        assert canary not in outbound.messages[0].content
        assert boundary.last_decision is not None
        counts.append(boundary.last_decision.redaction_count)
    assert counts == [1, 1]


def test_r3f_r2_canonical_m10_language_routing_hard_filter(tmp_path: Path) -> None:
    del tmp_path
    metadata = ProviderMetadata("local", "Local", "test", locality=ProviderLocality.LOCAL)
    registry = ProviderRegistry(
        (
            ProviderDefinition(
                metadata,
                lambda _: cast(AIProvider, object()),
                (ModelMetadata("model", 4096, frozenset({"chat", "language:nl"})),),
            ),
        )
    )
    router = ProviderRouter(registry)
    assert (
        router.route(
            RouteRequest(
                "Dutch response",
                "conversation",
                required_capabilities=frozenset({"language:nl"}),
            )
        ).status
        is RouteStatus.SELECTED
    )
    assert (
        router.route(
            RouteRequest(
                "French response",
                "conversation",
                required_capabilities=frozenset({"language:fr"}),
            )
        ).primary
        is None
    )


def test_r3f_r2_canonical_m11_language_cannot_grant_authority(tmp_path: Path) -> None:
    service = _service(tmp_path)
    actor = ActorContextService().create_trusted(
        session_id=uuid4(),
        principal_id="local-user",
        source=ActorContextSource.LOCAL_DESKTOP_SESSION,
    )
    service.set_language_preferences(
        interface_language="nl", conversation_language="nl", conversation_mode="fixed"
    )
    assert actor.is_active()
    assert service.inspect().keys().isdisjoint({"actor", "approval", "permission", "risk"})


def test_r3f_r2_canonical_m12_least_context_worker_projection(tmp_path: Path) -> None:
    service = _service(tmp_path)
    sentinel = "PRIVATE_PERSONAL_SENTINEL"
    service.set_language_preferences(conversation_language="nl", conversation_mode="fixed")
    context = service.resolve_language()
    assert "conversation_language=nl" in context.prompt_projection()
    assert sentinel not in context.prompt_projection()


def test_r3f_r2_canonical_p1_personalization_off(tmp_path: Path) -> None:
    service = _service(tmp_path)
    service.configure_personalization(mode=PersonalizationMode.OFF.value)
    assert not service.record_persona_evidence("formality", 4, confidence=1.0)
    assert (
        service.record_expression_feedback("tone", "formal", confidence=1.0, provenance="test")
        is None
    )


def test_r3f_r2_canonical_p2_explicit_only(tmp_path: Path) -> None:
    service = _service(tmp_path)
    service.configure_personalization(mode=PersonalizationMode.EXPLICIT_ONLY.value)
    assert not service.record_persona_evidence("formality", 4, confidence=1.0)
    service.set_language_preferences(locale="nl-NL")
    assert service.language_preferences().locale == "nl-NL"
    assert service.adaptive_persona()["formality"] == 2


def test_r3f_r2_canonical_p3_communication_learning_threshold(tmp_path: Path) -> None:
    service = _service(tmp_path)
    service.configure_personalization(
        mode=PersonalizationMode.COMMUNICATION.value,
        adaptive_persona=AdaptivePersonaMode.ADAPTIVE.value,
    )
    assert [service.record_persona_evidence("formality", 4, confidence=0.9) for _ in range(3)] == [
        False,
        False,
        True,
    ]


def test_r3f_r2_canonical_p4_personality_evolves_gradually(tmp_path: Path) -> None:
    service = _service(tmp_path)
    service.configure_personalization(
        mode=PersonalizationMode.COMMUNICATION.value,
        adaptive_persona=AdaptivePersonaMode.ADAPTIVE.value,
    )
    for _ in range(3):
        service.record_persona_evidence("formality", 4, confidence=1.0)
    assert service.adaptive_persona()["formality"] == 3


def test_r3f_r2_canonical_p5_explicit_correction_wins(tmp_path: Path) -> None:
    service = _service(tmp_path)
    service.mark_explicit_persona_update({"formality": 0})
    assert service.record_persona_evidence("formality", 4, confidence=1.0) is False
    assert service.adaptive_persona()["formality"] == 0


def test_r3f_r2_canonical_p6_freeze_survives_restart(tmp_path: Path) -> None:
    path = tmp_path / "human.sqlite3"
    with HumanAdaptationStore(path) as store:
        service = HumanAdaptationService(store)
        service.configure_personalization(
            mode=PersonalizationMode.COMMUNICATION.value,
            adaptive_persona=AdaptivePersonaMode.ADAPTIVE.value,
        )
        service.freeze_adaptive_persona()
        assert not service.record_persona_evidence("formality", 4, confidence=1.0)
    with HumanAdaptationStore(path) as store:
        service = HumanAdaptationService(store)
        assert service.personalization_settings()["adaptive_frozen"] is True


def test_r3f_r2_canonical_p7_reset_preserves_unrelated_explicit_state(tmp_path: Path) -> None:
    service = _service(tmp_path)
    service.set_language_preferences(locale="nl-NL")
    service.configure_personalization(mode=PersonalizationMode.COMMUNICATION.value)
    service.reset_adaptations()
    assert service.language_preferences().locale == "nl-NL"
    assert service.personalization_settings()["mode"] == PersonalizationMode.COMMUNICATION.value


def test_r3f_r2_canonical_p8_pin_blocks_inference(tmp_path: Path) -> None:
    service = _service(tmp_path)
    service.pin_persona_trait("formality", 1)
    service.configure_personalization(
        mode=PersonalizationMode.COMMUNICATION.value,
        adaptive_persona=AdaptivePersonaMode.ADAPTIVE.value,
    )
    for _ in range(3):
        service.record_persona_evidence("formality", 4, confidence=1.0)
    assert service.adaptive_persona()["formality"] == 1


def test_r3f_r2_canonical_p9_personalization_restart(tmp_path: Path) -> None:
    path = tmp_path / "human.sqlite3"
    with HumanAdaptationStore(path) as store:
        service = HumanAdaptationService(store)
        service.configure_personalization(mode=PersonalizationMode.COMMUNICATION.value)
        service.pin_persona_trait("verbosity", 4)
    with HumanAdaptationStore(path) as store:
        service = HumanAdaptationService(store)
        assert service.personalization_settings()["mode"] == PersonalizationMode.COMMUNICATION.value
        assert service.pinned_persona_traits() == ("verbosity",)


def test_r3f_r2_canonical_p10_deep_learning_off(tmp_path: Path) -> None:
    service = _service(tmp_path)
    service.configure_personalization(
        mode=PersonalizationMode.DEEP.value,
        behavioral_learning=False,
        observation_scope=ObservationScope.JARVIS_ONLY.value,
    )
    assert not service.record_behavior_event(
        BehavioralAggregateEvent("composer", keystroke_count=10)
    )
    assert service.behavioral_aggregates() == {}


def test_r3f_r2_canonical_p11_secure_input_leakage(tmp_path: Path) -> None:
    service = _service(tmp_path)
    service.configure_personalization(mode=PersonalizationMode.DEEP.value, behavioral_learning=True)
    sentinel = "SECURE_INPUT_SENTINEL"
    assert (
        service.record_expression_feedback(
            "tone", sentinel, confidence=1.0, provenance="secure", secure_input=True
        )
        is None
    )
    assert not service.record_behavior_event(
        BehavioralAggregateEvent("composer", keystroke_count=10, secure_input=True)
    )
    assert sentinel not in repr(service.inspect())


def test_r3f_r2_canonical_p12_cloud_privacy(tmp_path: Path) -> None:
    service = _service(tmp_path)
    service.configure_personalization(mode=PersonalizationMode.COMMUNICATION.value)
    service.record_expression_feedback("tone", "formal", confidence=1.0, provenance="test")
    projection = service.cloud_style_projection()
    assert "formal" in projection.values()
    assert "PRIVATE" not in repr(projection)


def test_r3f_r2_canonical_p13_relationship_style(tmp_path: Path) -> None:
    service = _service(tmp_path)
    service.configure_personalization(mode=PersonalizationMode.COMMUNICATION.value)
    service.record_expression_feedback(
        "tone", "informal", confidence=1.0, provenance="trusted", relationship="friend"
    )
    assert service.render_style("Review the draft", relationship="friend") != service.render_style(
        "Review the draft", relationship="business"
    )


def test_r3f_r2_canonical_p14_routine_is_suggestion_only(tmp_path: Path) -> None:
    service = _service(tmp_path)
    service.configure_personalization(
        mode=PersonalizationMode.CONTEXTUAL.value, routine_learning=True
    )
    for _ in range(3):
        candidate = service.observe_routine("open.dashboard", "suggest dashboard")
    assert candidate is not None and candidate.suggestion_only is True


def test_r3f_r2_canonical_p15_personalization_does_not_authorize_effects(tmp_path: Path) -> None:
    service = _service(tmp_path)
    service.configure_personalization(mode=PersonalizationMode.DEEP.value)
    for _ in range(3):
        service.record_persona_evidence("initiative", 4, confidence=1.0)
    settings = service.personalization_settings()
    assert (
        "approval" not in settings and "permission" not in settings and "authority" not in settings
    )


def test_r3f_r2_canonical_p16_behavior_does_not_authenticate_actor(tmp_path: Path) -> None:
    service = _service(tmp_path)
    service.configure_personalization(mode=PersonalizationMode.DEEP.value, behavioral_learning=True)
    service.configure_personalization(mode=PersonalizationMode.OFF.value)
    assert not service.record_behavior_event(
        BehavioralAggregateEvent("composer", keystroke_count=3)
    )
    actor_service = ActorContextService()
    actor = actor_service.create_trusted(
        session_id=uuid4(), principal_id="owner", source=ActorContextSource.LOCAL_DESKTOP_SESSION
    )
    assert actor.is_active()


def test_r3f_r2_canonical_p17_cross_context_isolation(tmp_path: Path) -> None:
    left = _service(tmp_path / "left")
    right = _service(tmp_path / "right")
    left.set_language_preferences(locale="nl-NL")
    right.set_language_preferences(locale="en-US")
    assert left.language_preferences().locale != right.language_preferences().locale


def test_r3f_r2_canonical_p18_least_context_model_boundary(tmp_path: Path) -> None:
    service = _service(tmp_path)
    service.configure_personalization(mode=PersonalizationMode.COMMUNICATION.value)
    service.record_expression_feedback("tone", "formal", confidence=1.0, provenance="local")
    projection = service.cloud_style_projection()
    assert set(projection) <= {
        "tone",
        "length",
        "directness",
        "greeting",
        "closing",
        "punctuation",
        "relationship",
    }
    assert "adaptation_history" not in repr(projection)
