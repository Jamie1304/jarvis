from __future__ import annotations

from pathlib import Path
from uuid import uuid4

import pytest
from jarvis.core.config import Settings
from jarvis.core.errors import ServiceUnavailableError
from jarvis.desktop_facade import DesktopApplicationFacade
from jarvis.permissions.models import ActionDescriptor, Risk
from jarvis.runtime import ApplicationRuntime, RuntimeStatus


def test_safe_mode_facade_exposes_settings_and_refuses_normal_actions(tmp_path: Path) -> None:
    runtime = ApplicationRuntime(
        None, status=RuntimeStatus.SAFE_MODE, error="configuration invalid"
    )
    facade = DesktopApplicationFacade(runtime)

    assert facade.runtime_view().safe_mode is True
    assert facade.runtime_view().error == "configuration invalid"
    assert facade.settings_descriptors()
    with pytest.raises(ServiceUnavailableError):
        facade.create_conversation()


@pytest.mark.asyncio
async def test_desktop_facade_projects_canonical_task_and_control_center_data(
    tmp_path: Path,
) -> None:
    runtime = ApplicationRuntime.create(
        Settings(app_data_dir=tmp_path / "data", ai_provider="ollama")
    )
    assert runtime.container is not None
    facade = DesktopApplicationFacade(runtime)
    conversation_id = facade.create_conversation()
    task = await facade.create_task(conversation_id, "calculate 25% of 800")

    rows = await facade.refresh_rows("tasks")
    tools = await facade.refresh_rows("tools")

    assert any(row.identifier == task.identifier for row in rows)
    assert any(row.identifier == "calculator" for row in tools)
    await facade.aclose()


@pytest.mark.asyncio
async def test_desktop_facade_projects_persona_actor_and_preserves_authority(
    tmp_path: Path,
) -> None:
    runtime = ApplicationRuntime.create(
        Settings(app_data_dir=tmp_path / "data", ai_provider="ollama")
    )
    assert runtime.container is not None
    facade = DesktopApplicationFacade(runtime)
    actor = facade.actor_context()
    assert actor.source == "local_desktop_session"
    assert actor.label == "Local Desktop"
    assert actor.active is True
    assert facade.persona().profile.verbosity == 2

    container = runtime.container
    descriptor = ActionDescriptor("facade-negative", (), Risk.LOW, ())
    tool_identity = object()
    before = await container.permission_broker.authorize(
        tool_id="unknown.facade-negative",
        tool_identity=tool_identity,
        declared_permissions=frozenset(),
        task_id=uuid4(),
        user_id=container.actor_context.principal_id,
        descriptor=descriptor,
        normalized_arguments={},
    )
    assert facade.update_persona({"verbosity": 4}).profile.verbosity == 4
    assert facade.persona().profile.verbosity == 4
    after = await container.permission_broker.authorize(
        tool_id="unknown.facade-negative",
        tool_identity=tool_identity,
        declared_permissions=frozenset(),
        task_id=uuid4(),
        user_id=container.actor_context.principal_id,
        descriptor=descriptor,
        normalized_arguments={},
    )
    assert before.reason == after.reason
    assert facade.reset_persona().profile.verbosity == 2
    await facade.aclose()
