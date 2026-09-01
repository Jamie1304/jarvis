import asyncio
from collections.abc import AsyncIterator
from typing import Any, cast
from uuid import uuid4

import pytest
from jarvis.application import AssistantEventKind, JarvisAssistantService
from jarvis.control_center import (
    ControlCenterSection,
    ControlCenterService,
    OutputMedium,
    TrustedPermissionSurface,
)
from jarvis.conversation.service import ConversationService
from jarvis.core.errors import ConversationError, ServiceUnavailableError, SpeechDisabledError
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
from jarvis.voice.activation import AudioFrame

from tests.fakes import FakeAIProvider, FakeTtsProvider


class _State:
    application_state: Any = object()


class _OptionalSpeech:
    enabled: bool = True
    available: bool = True
    status: Any = object()

    async def handle_frame(self, frame: Any) -> None:
        self.frame = frame

    async def interrupt(self, text: str) -> None:
        self.interruption = text

    async def aclose(self) -> None:
        self.closed = True


class _Stt:
    async def start_recording(self) -> None:
        self.started = True

    async def stop_and_transcribe(self) -> Any:
        return object()

    async def aclose(self) -> None:
        self.closed = True


class _TaskController:
    async def create_task(self, text: str) -> Any:
        return text

    async def run_task(self, task_id: Any) -> Any:
        return task_id

    async def submit_task(self, text: str) -> Any:
        return text

    async def cancel_task(self, task_id: Any) -> Any:
        return task_id

    def inspect_plan_details(self, task_id: Any) -> Any:
        return task_id

    def list_plan_revisions(self, task_id: Any) -> Any:
        return (task_id,)

    async def edit_plan(self, task_id: Any, edit: Any) -> Any:
        return edit

    async def checkpoint_plan(self, task_id: Any, edit: Any) -> Any:
        return edit

    async def replan_task(
        self, task_id: Any, *, additional_constraints: tuple[str, ...] = ()
    ) -> Any:
        return additional_constraints


class _Memory:
    def inspect(self, query: Any) -> Any:
        return (query,)

    def correct(self, reference: Any, correction: Any) -> Any:
        return correction

    def delete(self, reference: Any) -> bool:
        return True

    def forget_category(self, category: Any, *, workspace_id: str | None = None) -> int:
        return 1

    def export(self, query: Any) -> Any:
        return ({"query": query},)

    def change_retention(self, reference: Any, retention: Any) -> Any:
        return reference

    def pause_learning(self, paused: bool) -> bool:
        return paused

    def mark_explicit(self, reference: Any) -> Any:
        return reference

    def request_reverification(self, reference: Any, *, reason: str) -> str:
        return reason


class _Warmup:
    def start(self) -> asyncio.Task[tuple[object, ...]]:
        async def result() -> tuple[object, ...]:
            return ()

        return asyncio.create_task(result())


class _FailingProvider(FakeAIProvider):
    async def stream(self, request: Any) -> AsyncIterator[Any]:
        if request.model == "never":
            yield request
        raise RuntimeError("provider stream failed")


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
async def test_ui_service_fails_closed_for_unavailable_optional_application_services() -> None:
    conversation = ConversationService(
        FakeAIProvider(("ready",)), model="fake-model", context_limit=1024
    )
    service = JarvisAssistantService(conversation)
    conversation_id = service.create_conversation()
    task_id = uuid4()

    with pytest.raises(ServiceUnavailableError):
        _ = service.control_center
    with pytest.raises(ServiceUnavailableError):
        _ = service.memory_control
    with pytest.raises(ServiceUnavailableError):
        await service.run_test_drive()
    with pytest.raises(ServiceUnavailableError):
        service.start_startup_warmup()
    with pytest.raises(ConversationError):
        service._normalizer.normalize("   ")
    with pytest.raises(SpeechDisabledError):
        await service.handle_voice_frame(cast(AudioFrame, object()))
    with pytest.raises(SpeechDisabledError):
        await service.interrupt_voice("stop")
    with pytest.raises(SpeechDisabledError):
        await service.start_recording()
    with pytest.raises(SpeechDisabledError):
        await service.stop_recording()
    with pytest.raises(ServiceUnavailableError):
        await service.create_task(conversation_id, "calculate 2 + 2")
    with pytest.raises(ServiceUnavailableError):
        await service.run_task(task_id)
    with pytest.raises(ServiceUnavailableError):
        await service.submit_task(conversation_id, "calculate 2 + 2")
    with pytest.raises(ServiceUnavailableError):
        await service.cancel_task(task_id)
    with pytest.raises(ServiceUnavailableError):
        service.inspect_plan(task_id)
    with pytest.raises(ServiceUnavailableError):
        service.list_plan_revisions(task_id)
    with pytest.raises(ServiceUnavailableError):
        await service.edit_plan(task_id, object())  # type: ignore[arg-type]
    with pytest.raises(ServiceUnavailableError):
        await service.checkpoint_plan(task_id, object())  # type: ignore[arg-type]
    with pytest.raises(ServiceUnavailableError):
        await service.replan_task(task_id)
    assert service.stt_enabled is False
    assert service.tts_enabled is False
    assert service.voice_status is None


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
    assert "Say DETAILS or NO" in prompt.voice_prompt
    assert "trusted approval control" in prompt.voice_prompt


@pytest.mark.asyncio
async def test_configured_application_services_keep_ui_on_typed_boundaries() -> None:
    conversation = ConversationService(
        FakeAIProvider(("ready",)), model="fake-model", context_limit=1024
    )
    speech = _OptionalSpeech()
    service = JarvisAssistantService(
        conversation,
        stt=cast(Any, _Stt()),
        tts=cast(Any, _OptionalSpeech()),
        voice=cast(Any, speech),
        state_machine=cast(Any, _State()),
        task_controller=cast(Any, _TaskController()),
        memory_control=cast(Any, _Memory()),
        startup_warmup=cast(Any, _Warmup()),
    )
    conversation_id = service.create_conversation()
    service.cancel(conversation_id)
    assert service.application_state is _State.application_state
    assert service.stt_enabled is True
    assert service.tts_enabled is True
    assert cast(Any, service.voice_status) is speech.status
    await service.handle_voice_frame(cast(AudioFrame, object()))
    await service.interrupt_voice("cancel")
    await service.start_recording()
    assert await service.stop_recording() is not None
    assert cast(Any, await service.create_task(conversation_id, "  Jarvis, do it ")) == "do it"
    assert cast(Any, await service.run_task(conversation_id)) == conversation_id
    assert cast(Any, await service.submit_task(conversation_id, "task")) == "task"
    assert cast(Any, await service.cancel_task(conversation_id)) == conversation_id
    assert cast(Any, service.inspect_plan(conversation_id)) == conversation_id
    assert cast(Any, service.list_plan_revisions(conversation_id)) == (conversation_id,)
    assert await service.edit_plan(conversation_id, cast(Any, object())) is not None
    assert await service.checkpoint_plan(conversation_id, cast(Any, object())) is not None
    assert cast(
        Any, await service.replan_task(conversation_id, additional_constraints=("safe",))
    ) == ("safe",)
    assert cast(Any, service.inspect_memory(cast(Any, "query"))) == ("query",)
    assert (
        cast(Any, service.correct_memory(cast(Any, "ref"), cast(Any, "correction"))) == "correction"
    )
    assert service.delete_memory(cast(Any, "ref")) is True
    assert service.forget_memory_category("category", workspace_id="workspace") == 1
    assert cast(Any, service.export_memory(cast(Any, "query"))) == ({"query": "query"},)
    assert (
        cast(Any, service.change_memory_retention(cast(Any, "ref"), cast(Any, object()))) == "ref"
    )
    assert service.pause_memory_learning(True) is True
    assert cast(Any, service.mark_memory_explicit(cast(Any, "ref"))) == "ref"
    assert (
        cast(Any, service.request_memory_reverification(cast(Any, "ref")))
        == "user requested re-verification"
    )
    warmup = service.start_startup_warmup()
    assert await warmup == ()
    await service.aclose()


@pytest.mark.asyncio
async def test_stream_failure_stops_tts_and_barge_in_rebuilds_response_session() -> None:
    tts_provider = FakeTtsProvider()
    service = JarvisAssistantService(
        ConversationService(_FailingProvider(), model="fake-model", context_limit=1024),
        tts=TextToSpeechService(tts_provider, enabled=True),
    )
    with pytest.raises(RuntimeError, match="provider stream failed"):
        async for _ in service.stream_text(service.create_conversation(), "hello"):
            pass
    assert tts_provider.stopped is True

    rebuilt = False

    async def rebuild() -> None:
        nonlocal rebuilt
        rebuilt = True

    service = JarvisAssistantService(
        ConversationService(FakeAIProvider(), model="fake-model", context_limit=1024),
        tts=TextToSpeechService(FakeTtsProvider(), enabled=True),
        response_session_rebuilder=rebuild,
    )
    await service.barge_in(service.create_conversation())
    assert rebuilt is True
