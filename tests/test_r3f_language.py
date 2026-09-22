from __future__ import annotations

from collections.abc import AsyncIterator
from datetime import UTC, datetime, timedelta
from pathlib import Path
from uuid import uuid4

import pytest
from jarvis.ai.models import (
    ChatMessage,
    GenerationChunk,
    GenerationRequest,
    GenerationResult,
    MessageRole,
    ModelInfo,
    PrivacyClassification,
    PrivacyContext,
    ProviderHealth,
)
from jarvis.ai.providers.base import AIProvider
from jarvis.ai.providers.registry import (
    ModelMetadata,
    ProviderDefinition,
    ProviderLocality,
    ProviderMetadata,
    ProviderRegistry,
)
from jarvis.ai.routing import ProviderRouter, RouteRequest, RouteStatus
from jarvis.conversation.service import ConversationService
from jarvis.human_adaptation import (
    ConversationLanguageMode,
    DeterministicLanguageDetector,
    HumanAdaptationService,
    HumanAdaptationStore,
    LanguageDetectionProvenance,
    LanguageOverrides,
    LanguagePreferences,
    LanguageSupportState,
    LanguageTag,
    VoiceLanguageCapability,
    VoiceLanguageCatalog,
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


class CapturingProvider(AIProvider):
    def __init__(self) -> None:
        self.requests: list[GenerationRequest] = []

    async def generate(self, request: GenerationRequest) -> GenerationResult:
        self.requests.append(request)
        raise AssertionError("stream path expected")

    async def stream(self, request: GenerationRequest) -> AsyncIterator[GenerationChunk]:
        self.requests.append(request)
        yield GenerationChunk("antwoord", True)

    async def health_check(self) -> ProviderHealth:
        return ProviderHealth(True, "test")

    async def model_info(self) -> ModelInfo:
        raise NotImplementedError

    async def aclose(self) -> None:
        return None


def test_language_scopes_are_independent_and_output_override_is_temporary(tmp_path: Path) -> None:
    with HumanAdaptationStore(tmp_path / "human.sqlite3") as store:
        service = HumanAdaptationService(store)
        service.set_language_preferences(
            LanguagePreferences(
                interface_language=LanguageTag("nl-NL"),
                locale="nl-NL",
                conversation_language=LanguageTag("nl"),
                conversation_mode=ConversationLanguageMode.FIXED,
            )
        )
        context = service.resolve_language(
            LanguageOverrides(requested_output=LanguageTag("en-GB"), content=LanguageTag("en"))
        )
        assert context.interface_language == LanguageTag("nl-NL")
        assert context.conversation.language == LanguageTag("nl")
        assert context.output.language == LanguageTag("en-GB")
        assert context.content_language == LanguageTag("en")
        assert service.language_preferences().conversation_language == LanguageTag("nl")


def test_detection_is_local_provenanced_and_uncertain_for_short_text() -> None:
    detector = DeterministicLanguageDetector()
    detected = detector.detect("Schrijf dit graag met de juiste toon")
    assert detected.language == LanguageTag("nl")
    assert detected.provenance is LanguageDetectionProvenance.LOCAL_DETECTOR
    assert detector.detect("hi").language is None


def test_language_prefs_restart_and_truthful_capability_state(tmp_path: Path) -> None:
    path = tmp_path / "human.sqlite3"
    with HumanAdaptationStore(path) as store:
        service = HumanAdaptationService(store)
        service.set_language_preferences(interface_language="nl", locale="nl-NL")
        assert service.capability("nl").state is LanguageSupportState.TEXT_ONLY
        assert service.capability("xx").state is LanguageSupportState.UNSUPPORTED
    with HumanAdaptationStore(path) as store:
        assert HumanAdaptationService(store).language_preferences().locale == "nl-NL"


@pytest.mark.asyncio
async def test_real_conversation_request_receives_bounded_language_projection() -> None:
    provider = CapturingProvider()
    service = ConversationService(
        provider,
        model="test",
        context_limit=512,
        provider_metadata=ProviderMetadata(
            "test-local", "Test local", "test", locality=ProviderLocality.LOCAL
        ),
    )
    conversation_id = service.create_conversation()
    from jarvis.human_adaptation import LanguageContextResolver

    context = LanguageContextResolver().resolve(
        LanguagePreferences(
            conversation_language=LanguageTag("nl"),
            conversation_mode=ConversationLanguageMode.FIXED,
        ),
        LanguageOverrides(requested_output=LanguageTag("en")),
    )
    updates = [
        item
        async for item in service.stream_reply(
            conversation_id,
            "Schrijf een korte reactie",
            privacy_context=PrivacyContext(PrivacyClassification.SAFE_PUBLIC),
            language_context=context,
            style_projection={"tone": "neutral", "length": "short"},
        )
    ]
    assert updates[-1].done
    request = provider.requests[0]
    assert any("conversation_language=nl" in message.content for message in request.messages)
    assert any("tone=neutral" in message.content for message in request.messages)
    assert all("persona" not in message.content.casefold() for message in request.messages)


def _approval() -> ApprovalRequest:
    task_id = uuid4()
    scope = normalize_scope(
        PermissionScope(
            paths=("C:/private/report.txt",),
            tool_id="trusted-file",
            task_id=task_id,
            duration_seconds=30,
        ),
        Permission.FILESYSTEM_WRITE,
    )
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
        scope=scope,
        reason=DecisionReason.POLICY_APPROVAL_REQUIRED,
        policy_id="test.write",
        created_at=created,
        expires_at=created + timedelta(seconds=30),
        status=ApprovalStatus.PENDING,
    )


def test_dutch_and_english_approval_rendering_preserve_canonical_binding() -> None:
    request = _approval()
    english = localize_approval_request(request, "en")
    dutch = localize_approval_request(request, "nl")
    assert english.request_id == dutch.request_id == request.request_id
    assert (
        english.argument_fingerprint == dutch.argument_fingerprint == request.argument_fingerprint
    )
    assert english.action_fingerprint == dutch.action_fingerprint == request.action_fingerprint
    assert english.short_text != dutch.short_text


def test_dynamic_capability_localization_is_declarative() -> None:
    metadata = {
        "name": "Power",
        "description": "A capability",
        "names": {"en": "Power", "nl": "Inschakelen"},
        "descriptions": {"en": "Turn on", "nl": "Schakel in"},
    }
    assert localize_capability_metadata("generated.power", metadata, "nl").name == "Inschakelen"


def test_voice_contract_is_truthful_without_physical_device_claims() -> None:
    catalog = VoiceLanguageCatalog()
    catalog.register(
        VoiceLanguageCapability(
            "local-stt",
            "stt",
            frozenset({LanguageTag("en"), LanguageTag("nl-NL")}),
            automatic_detection=True,
        )
    )
    assert catalog.supports("stt", "local-stt", "nl")
    capability = catalog.get("stt", "local-stt")
    assert capability is not None and capability.physical_evidence is False
    assert not catalog.supports("tts", "local-stt", "nl")


def test_language_capability_is_a_hard_routing_gate() -> None:
    provider = ProviderMetadata("local", "Local", "test", locality=ProviderLocality.LOCAL)
    registry = ProviderRegistry(
        (
            ProviderDefinition(
                provider,
                lambda _: CapturingProvider(),
                (ModelMetadata("model", 4096, frozenset({"chat", "language:nl"})),),
            ),
        )
    )
    router = ProviderRouter(registry)
    selected = router.route(
        RouteRequest(
            task="answer in Dutch",
            profile="conversation",
            classification="safe_public",
            required_capabilities=frozenset({"language:nl"}),
        )
    )
    assert selected.status is RouteStatus.SELECTED
    rejected = router.route(
        RouteRequest(
            task="answer in Dutch",
            profile="conversation",
            classification="safe_public",
            required_capabilities=frozenset({"language:fr"}),
        )
    )
    assert rejected.primary is None


def test_dutch_and_english_canaries_receive_equivalent_remote_redaction() -> None:
    from jarvis.ai.privacy import PrivacyBoundary

    metadata = ProviderMetadata("remote", "Remote", "test", locality=ProviderLocality.REMOTE)
    boundary = PrivacyBoundary(metadata)
    cases = (
        "My private fact is Jamie's address.",
        "Mijn privéfeit is Jamies adres.",
    )
    counts = []
    for text in cases:
        message = ChatMessage(uuid4(), uuid4(), MessageRole.USER, text, datetime.now(UTC))
        request = GenerationRequest(
            (message,),
            "remote-model",
            1024,
            PrivacyContext(PrivacyClassification.SANITIZABLE, (text,)),
        )
        outbound, _ = boundary.prepare(request)
        assert text not in outbound.messages[0].content
        assert boundary.last_decision is not None
        counts.append(boundary.last_decision.redaction_count)
    assert counts == [1, 1]
