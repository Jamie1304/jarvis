import pytest
from jarvis.application import AssistantEventKind, JarvisAssistantService
from jarvis.control_center import (
    ControlCenterSection,
    ControlCenterService,
    OutputMedium,
    TrustedPermissionSurface,
)
from jarvis.conversation.service import ConversationService
from jarvis.core.errors import ServiceUnavailableError
from jarvis.desktop_shell import (
    LaunchProfile,
)
from jarvis.desktop_shell import (
    TestDriveRegistry as DriveRegistry,
)
from jarvis.desktop_shell import (
    TestDriveStatus as DriveStatus,
)
from jarvis.desktop_shell import (
    TestDriveStep as DriveStep,
)
from jarvis.desktop_shell import (
    TestDriveStepResult as DriveStepResult,
)
from jarvis.permissions import (
    ActionDescriptor,
    Permission,
    PermissionRequest,
    PermissionScope,
    Risk,
)
from jarvis.permissions.models import SafeArgument
from jarvis.speech.tts import TextToSpeechService

from tests.fakes import FakeAIProvider, FakeTtsProvider


@pytest.mark.asyncio
async def test_ui_facing_service_normalizes_streams_and_speaks() -> None:
    provider = FakeAIProvider(("25% van 800 is ", "200."))
    tts_provider = FakeTtsProvider()
    service = JarvisAssistantService(
        ConversationService(provider, model="fake-model", context_limit=1024),
        tts=TextToSpeechService(tts_provider, enabled=True),
    )
    conversation_id = service.create_conversation()

    events = [
        event
        async for event in service.stream_text(
            conversation_id, "Jarvis, hoeveel is 25 procent van 800?"
        )
    ]

    text = "".join(event.content for event in events if event.kind is AssistantEventKind.TEXT)
    assert text == "25% van 800 is 200."
    assert tts_provider.spoken == [text]
    assert provider.requests[0].messages[-1].content == "hoeveel is 25 procent van 800?"
    assert events[-1].done is True


@pytest.mark.asyncio
async def test_ui_service_exposes_test_drive_and_launch_profile_application_services() -> None:
    async def check() -> DriveStepResult:
        return DriveStepResult(DriveStatus.PASS, "fixture passed")

    checks = DriveRegistry()
    checks.register(DriveStep("provider", "Provider", check))
    service = JarvisAssistantService(
        ConversationService(FakeAIProvider(("ready",)), model="fake-model", context_limit=1024),
        test_drive=checks,
    )
    assert service.select_launch_profile(LaunchProfile.VOICE).profile is LaunchProfile.VOICE
    report = await service.run_test_drive()
    assert report.fully_ready is True


@pytest.mark.asyncio
async def test_ui_service_reports_unconfigured_onboarding_and_warmup_safely() -> None:
    service = JarvisAssistantService(
        ConversationService(FakeAIProvider(("ready",)), model="fake-model", context_limit=1024)
    )
    with pytest.raises(ServiceUnavailableError):
        await service.run_onboarding(object())  # type: ignore[arg-type]
    with pytest.raises(ServiceUnavailableError):
        await service.run_test_drive()
    with pytest.raises(ServiceUnavailableError):
        service.start_startup_warmup()


@pytest.mark.asyncio
async def test_ui_service_refreshes_control_center_and_formats_channels() -> None:
    control_center = ControlCenterService()
    service = JarvisAssistantService(
        ConversationService(FakeAIProvider(("ready",)), model="fake-model", context_limit=1024),
        control_center=control_center,
    )
    control_center.register(
        ControlCenterSection.TOOLS,
        "fixture",
        lambda: (),
    )
    snapshot = await service.refresh_control_center(ControlCenterSection.TOOLS)
    assert snapshot.section(ControlCenterSection.TOOLS).items == ()
    assert await service.refresh_semantic_actions(ControlCenterSection.TOOLS) == ()
    assert service.format_for_medium("# hello", OutputMedium.VOICE) == "hello"
    assert service.output_profile(OutputMedium.DESKTOP).allow_markdown is True


def test_ui_service_uses_one_trusted_permission_surface_for_both_channels() -> None:
    request = PermissionRequest(
        Permission.FILESYSTEM_WRITE,
        PermissionScope(paths=("C:/owned/settings.json",)),
    )
    descriptor = ActionDescriptor(
        "edit settings",
        (SafeArgument("path", "C:/owned/settings.json"),),
        Risk.HIGH,
        (request,),
    )
    service = JarvisAssistantService(
        ConversationService(FakeAIProvider(("ready",)), model="fake-model", context_limit=1024),
        permission_surface=TrustedPermissionSurface(),
    )
    prompt = service.render_permission_prompt(request, descriptor)
    assert prompt.presentation.operation.permission_request is request
    assert prompt.desktop_details.endswith("permission=filesystem.write")
    assert "YES / NO / DETAILS" in prompt.voice_prompt
