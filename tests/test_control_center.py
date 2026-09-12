from __future__ import annotations

import asyncio
from datetime import UTC, datetime, timedelta
from uuid import uuid4

import pytest
from jarvis.control_center import (
    ControlCenterError,
    ControlCenterItem,
    ControlCenterSection,
    ControlCenterService,
    ControlCenterStatus,
    ControlCenterValidationError,
    OutputMedium,
    OutputMediumProfile,
    OutputMediumProfileRegistry,
    SemanticActionMetadata,
    TrustedPermissionPrompt,
    TrustedPermissionSurface,
)
from jarvis.permissions import (
    ActionDescriptor,
    ApprovalRequest,
    ApprovalStatus,
    DecisionReason,
    Permission,
    PermissionRequest,
    PermissionScope,
    Risk,
    SafeArgument,
    TrustedActionNarrator,
)
from jarvis.permissions.policy import normalize_scope


def _item(item_id: str = "one") -> ControlCenterItem:
    return ControlCenterItem(
        item_id,
        "Dynamic item",
        ControlCenterStatus.AVAILABLE,
        "available",
        (
            SemanticActionMetadata(
                f"{item_id}.inspect",
                "Inspect",
                "Inspect through the application service",
                "item.inspect",
                (Permission.FILESYSTEM_READ,),
                ("item_id",),
            ),
        ),
        (("source", "fixture"),),
    )


@pytest.mark.asyncio
async def test_control_center_refreshes_registered_sources_and_preserves_dynamic_changes() -> None:
    values = [_item()]
    service = ControlCenterService()
    service.register(ControlCenterSection.CAPABILITIES, "fixture", lambda: tuple(values))

    first = await service.refresh(ControlCenterSection.CAPABILITIES)
    assert first.revision == 1
    assert first.section(ControlCenterSection.CAPABILITIES).items == (values[0],)
    values.append(_item("two"))
    second = await service.refresh(ControlCenterSection.CAPABILITIES)
    assert second.revision == 2
    assert [item.item_id for item in second.section(ControlCenterSection.CAPABILITIES).items] == [
        "one",
        "two",
    ]
    assert second.section(ControlCenterSection.TOOLS).status is ControlCenterStatus.NOT_AVAILABLE
    assert set(service.sources(ControlCenterSection.CAPABILITIES)) == {"fixture"}


@pytest.mark.asyncio
async def test_control_center_isolates_slow_async_and_failing_projection_sources() -> None:
    async def delayed() -> tuple[ControlCenterItem, ...]:
        await asyncio.sleep(0)
        return (_item("async"),)

    def failed() -> tuple[ControlCenterItem, ...]:
        raise RuntimeError("untrusted source detail")

    service = ControlCenterService()
    service.register(ControlCenterSection.TOOLS, "async", delayed)
    service.register(ControlCenterSection.TOOLS, "failed", failed)
    snapshot = await service.refresh(ControlCenterSection.TOOLS)
    view = snapshot.section(ControlCenterSection.TOOLS)
    assert view.status is ControlCenterStatus.DEGRADED
    assert tuple(item.item_id for item in view.items) == ("async",)
    assert "untrusted source detail" not in view.detail


@pytest.mark.asyncio
async def test_control_center_rejects_duplicate_projection_ids_and_supports_unregister() -> None:
    service = ControlCenterService()
    service.register(ControlCenterSection.TOOLS, "first", lambda: (_item("same"),))
    service.register(ControlCenterSection.TOOLS, "second", lambda: (_item("same"),))
    view = (await service.refresh(ControlCenterSection.TOOLS)).section(ControlCenterSection.TOOLS)
    assert view.status is ControlCenterStatus.DEGRADED
    assert view.items == ()
    service.unregister(ControlCenterSection.TOOLS, "second")
    assert service.sources(ControlCenterSection.TOOLS) == ("first",)
    assert (await service.refresh(ControlCenterSection.TOOLS)).section(
        ControlCenterSection.TOOLS
    ).status is ControlCenterStatus.AVAILABLE


def test_control_center_and_medium_metadata_fail_closed() -> None:
    with pytest.raises(ControlCenterValidationError):
        SemanticActionMetadata("bad id!", "Inspect", "safe", "item.inspect")
    with pytest.raises(ControlCenterValidationError):
        ControlCenterItem("item", "bad\nlabel", ControlCenterStatus.AVAILABLE)
    with pytest.raises(ControlCenterValidationError):
        OutputMediumProfile("voice", True)  # type: ignore[arg-type]
    with pytest.raises(ControlCenterValidationError):
        OutputMediumProfile(OutputMedium.VOICE, max_length=0)

    profiles = OutputMediumProfileRegistry()
    assert profiles.get(OutputMedium.DESKTOP).format("**bold**") == "**bold**"
    voice = profiles.get(OutputMedium.VOICE)
    rendered = voice.format("# Hello\n- See https://example.com now.")
    assert "#" not in rendered and "dot" in rendered and "  " not in rendered
    assert voice.allow_markdown is False
    custom = OutputMediumProfile(OutputMedium.COMPACT, True, False, False, False, 100)
    profiles.register(custom)
    assert profiles.get(OutputMedium.COMPACT) is custom
    with pytest.raises(ControlCenterValidationError):
        voice.format("x" * 8_001)


def _permission_request() -> tuple[PermissionRequest, ActionDescriptor]:
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
    return request, descriptor


def test_trusted_permission_surface_shares_one_authority_object() -> None:
    request, descriptor = _permission_request()
    prompt = TrustedPermissionSurface().present(request, descriptor)
    assert isinstance(prompt, TrustedPermissionPrompt)
    assert prompt.presentation.operation.permission_request is request
    assert (
        prompt.desktop_short
        == TrustedActionNarrator().narrate(request, descriptor).short_explanation
    )
    assert "permission=filesystem.write" in prompt.desktop_details
    assert "Say DETAILS or NO" in prompt.voice_prompt
    assert "trusted approval control" in prompt.voice_prompt
    assert prompt.desktop_choices == ("Allow once", "Deny")
    with pytest.raises(TypeError):
        TrustedPermissionSurface().present("YES")  # type: ignore[arg-type]


def test_trusted_approval_request_is_rendered_without_model_authorship() -> None:
    task_id = uuid4()
    scope = normalize_scope(
        PermissionScope(
            paths=("C:/owned/settings.json",),
            tool_id="trusted-file",
            task_id=task_id,
            duration_seconds=30,
        ),
        Permission.FILESYSTEM_WRITE,
    )
    request = ApprovalRequest(
        request_id=uuid4(),
        task_id=task_id,
        exact_action="edit settings",
        arguments_summary=(SafeArgument("path", "C:/owned/settings.json"),),
        argument_fingerprint="a" * 64,
        action_fingerprint="b" * 64,
        permission=Permission.FILESYSTEM_WRITE,
        risk=Risk.HIGH,
        scope=scope,
        reason=DecisionReason.POLICY_APPROVAL_REQUIRED,
        policy_id="trusted-file.write",
        created_at=datetime.now(UTC),
        expires_at=datetime.now(UTC) + timedelta(seconds=30),
        status=ApprovalStatus.PENDING,
    )
    prompt = TrustedPermissionSurface().present(request)
    assert prompt.presentation.operation.approval_request_id == request.request_id
    assert str(request.request_id) in prompt.desktop_details
    with pytest.raises(TypeError):
        TrustedPermissionSurface().present({"permission": "all"})  # type: ignore[arg-type]


@pytest.mark.asyncio
async def test_control_center_close_is_safe() -> None:
    service = ControlCenterService()
    await service.aclose()
    await service.aclose()


def test_control_center_registration_validation() -> None:
    service = ControlCenterService()
    with pytest.raises(ControlCenterValidationError):
        service.register("tools", "source", lambda: ())  # type: ignore[arg-type]
    with pytest.raises(ControlCenterValidationError):
        service.register(ControlCenterSection.TOOLS, "bad id!", lambda: ())
    service.register(ControlCenterSection.TOOLS, "source", lambda: ())
    with pytest.raises(ControlCenterError):
        service.register(ControlCenterSection.TOOLS, "source", lambda: ())
    with pytest.raises(ControlCenterValidationError):
        service.unregister(ControlCenterSection.TOOLS, "bad id!")
    with pytest.raises(ControlCenterValidationError):
        service.sources("tools")  # type: ignore[arg-type]
