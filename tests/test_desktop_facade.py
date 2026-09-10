from __future__ import annotations

import asyncio
import sqlite3
from datetime import UTC, datetime
from hashlib import sha256
from pathlib import Path
from typing import cast
from uuid import uuid4

import pytest
from jarvis.attention import (
    AttentionDeliveryState,
    AttentionItem,
    AttentionPriority,
    InterruptionClass,
)
from jarvis.core.config import Settings
from jarvis.core.errors import ServiceUnavailableError
from jarvis.desktop_facade import DesktopApplicationFacade
from jarvis.events import EventEnvelope, EventPayload, EventType, RuntimeStateChanged
from jarvis.memory.episodes import (
    EPISODE_COMPOSITION_RULE_VERSION,
    EPISODE_SCHEMA_VERSION,
    Episode,
    EpisodeContinuity,
    EpisodeOutcome,
    EpisodeVerification,
)
from jarvis.memory.models import Sensitivity
from jarvis.permissions.models import ActionDescriptor, Risk
from jarvis.runtime import ApplicationRuntime, RuntimeStatus
from jarvis.trace import TraceEventType


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
    context = facade.current_context()
    assert context.safe_mode is True
    assert context.runtime_state == RuntimeStatus.SAFE_MODE.value
    assert context.actor is None
    assert context.provider.provider_id is None


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
async def test_activity_exposes_correlation_only_attention_trace_facts(
    tmp_path: Path,
) -> None:
    runtime = ApplicationRuntime.create(
        Settings(app_data_dir=tmp_path / "data", ai_provider="ollama")
    )
    assert runtime.container is not None
    container = runtime.container
    facade = DesktopApplicationFacade(runtime)
    trace_persisted = asyncio.Event()
    correlation_id = uuid4()

    def observe(update: object) -> None:
        if getattr(update, "correlation_id", None) != correlation_id:
            return
        events = container.trace_service.get(correlation_id=correlation_id).events
        if any(event.event_type is TraceEventType.ATTENTION for event in events):
            trace_persisted.set()

    container.trace_service.add_observer(observe)
    try:
        await asyncio.gather(
            *(
                task
                for task in (
                    container.trace_start_task,
                    container.semantic_start_task,
                )
                if task is not None
            )
        )
        event = EventEnvelope.create(
            EventType.RUNTIME_STATE_CHANGED,
            RuntimeStateChanged("degraded"),
            source="test.p2d.r2.gap",
            correlation_id=correlation_id,
        )
        assert await container.event_bus.publish(cast(EventEnvelope[EventPayload], event))
        await asyncio.wait_for(trace_persisted.wait(), timeout=10)

        attention = next(
            item
            for item in container.attention_store.list_items()
            if item.related_correlation_id == correlation_id
        )
        trace_event = next(
            event
            for event in container.trace_service.get(correlation_id=correlation_id).events
            if event.event_type is TraceEventType.ATTENTION
        )
        activity = facade.activity_view()
        assert any(item.identifier == f"attention:{attention.item_id}" for item in activity.items)
        trace_item = next(
            item for item in activity.items if item.identifier == f"trace:{trace_event.event_id}"
        )
        assert (
            sum(item.identifier == f"trace:{trace_event.event_id}" for item in activity.items) == 1
        )
        assert trace_item.category == TraceEventType.ATTENTION.value
        assert "class=important" in trace_item.summary
        assert "reason=runtime_degraded" in trace_item.summary
        assert "decision=deliver_now" in trace_item.summary
        assert "delivery=queued" in trace_item.summary
        stored_entry = container.attention_policy.entry_for(attention.item_id)
        assert stored_entry is not None and stored_entry.delivered_at is None

        await facade.aclose()
        restarted = ApplicationRuntime.create(
            Settings(app_data_dir=tmp_path / "data", ai_provider="ollama")
        )
        restarted_facade = DesktopApplicationFacade(restarted)
        try:
            restarted_trace = next(
                item
                for item in restarted_facade.activity_view().items
                if item.identifier == f"trace:{trace_event.event_id}"
            )
            assert restarted_trace.category == TraceEventType.ATTENTION.value
        finally:
            await restarted_facade.aclose()
    finally:
        await facade.aclose()


@pytest.mark.asyncio
async def test_current_context_composes_canonical_references_and_restarts_truthfully(
    tmp_path: Path,
) -> None:
    app_data = tmp_path / "data"
    runtime = ApplicationRuntime.create(Settings(app_data_dir=app_data, ai_provider="ollama"))
    assert runtime.container is not None
    facade = DesktopApplicationFacade(runtime)
    initial = facade.current_context()
    assert initial.actor is not None and initial.actor.active is True
    assert initial.actor.source == "local_desktop_session"
    assert initial.persona.verbosity == 2
    assert initial.active_conversation_id is None
    assert initial.active_task_id is None
    assert initial.provider.provider_id == "ollama"
    assert initial.provider.model_id == "llama3.2:3b"
    assert initial.provider.available is None
    assert initial.provider.readiness is not None
    assert initial.provider.readiness.value == "not_probed"

    memory_db = runtime.container.paths.memory_database
    with sqlite3.connect(memory_db) as connection:
        memory_count_before = connection.execute("SELECT COUNT(*) FROM memories").fetchone()[0]

    conversation_id = facade.create_conversation()
    conversation = facade.current_context()
    assert conversation.active_conversation_id == conversation_id
    assert conversation.conversation_session_id == runtime.container.conversation.session_id(
        conversation_id
    )

    task_row = await facade.create_task(conversation_id, "calculate 25% of 800")
    task_context = facade.current_context()
    assert task_context.active_task_id is not None
    assert str(task_context.active_task_id) == task_row.identifier
    assert task_context.active_task_status is runtime.container.task_controller.get_status(
        task_context.active_task_id
    )
    assert task_context.actor is not None
    assert type(task_context.actor).__name__ == "CurrentActorProjection"
    assert type(task_context.persona).__name__ == "PersonaProfile"
    assert not hasattr(task_context, "permission_level")
    assert not hasattr(task_context.model_projection(), "credentials")
    assert not hasattr(runtime.container.current_context, "approval_identity")
    assert not hasattr(runtime.container.current_context, "permission_broker")

    facade.update_persona({"verbosity": 4})
    changed = facade.current_context()
    assert changed.persona.verbosity == 4
    assert changed.actor is not None
    assert changed.model_projection().actor_source == changed.actor.source
    with sqlite3.connect(memory_db) as connection:
        assert (
            connection.execute("SELECT COUNT(*) FROM memories").fetchone()[0] == memory_count_before
        )

    old_actor_session = task_context.actor.session_id if task_context.actor is not None else None
    await facade.aclose()

    restarted = ApplicationRuntime.create(Settings(app_data_dir=app_data, ai_provider="ollama"))
    assert restarted.container is not None
    restarted_facade = DesktopApplicationFacade(restarted)
    after_restart = restarted_facade.current_context()
    assert after_restart.actor is not None
    assert after_restart.actor.session_id != old_actor_session
    assert after_restart.active_conversation_id is None
    assert after_restart.active_task_id is None
    assert after_restart.persona.verbosity == 4
    restarted_facade.reset_persona()
    await restarted_facade.aclose()


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


@pytest.mark.asyncio
async def test_p2_projections_are_typed_read_only_and_keep_unknown_truthful(tmp_path: Path) -> None:
    runtime = ApplicationRuntime.create(
        Settings(app_data_dir=tmp_path / "data", ai_provider="ollama")
    )
    assert runtime.container is not None
    facade = DesktopApplicationFacade(runtime)
    container = runtime.container
    now = datetime.now(UTC)
    attention = AttentionItem(
        uuid4(),
        "capability.health",
        "default",
        AttentionPriority.NORMAL,
        now,
        dedupe_key="fixture:capability-health",
        summary="Capability health requires review",
    )
    entry = container.attention_policy.enqueue(attention)
    waiting_task_id = uuid4()
    waiting = AttentionItem(
        uuid4(),
        "interruption.task_waiting_for_user",
        "default",
        AttentionPriority.HIGH,
        now,
        requires_user_action=True,
        related_task_id=waiting_task_id,
        dedupe_key="fixture:task-waiting-for-user",
        summary="A task is waiting for your action",
        interruption_class=InterruptionClass.IMPORTANT,
        interruption_reason_code="task_waiting_for_user",
    )
    container.attention_policy.enqueue(waiting)
    episode = Episode(
        uuid4(),
        EPISODE_SCHEMA_VERSION,
        EPISODE_COMPOSITION_RULE_VERSION,
        now,
        None,
        now,
        uuid4(),
        None,
        container.actor_context.context_id,
        container.actor_context.principal_id,
        "default",
        "general_task",
        sha256(b"uncertain fixture").hexdigest(),
        (("fixture", "controlled"),),
        (),
        EpisodeOutcome.UNKNOWN_OUTCOME,
        EpisodeVerification.UNKNOWN,
        ("task:controlled",),
        (),
        (),
        (),
        (),
        None,
        None,
        ("unknown_effect_outcome",),
        Sensitivity.PRIVATE,
        EpisodeContinuity.PARTIAL,
        ("test.fixture",),
    )
    container.episodic_memory.persist_episode(episode)

    attention_view = facade.attention_view()
    assert attention_view.state == "ready"
    generic_view = next(item for item in attention_view.items if item.item_id == attention.item_id)
    waiting_view = next(item for item in attention_view.items if item.item_id == waiting.item_id)
    assert generic_view.interruption_class is None
    assert generic_view.decision == entry.decision.value
    assert generic_view.delivery_state == AttentionDeliveryState.QUEUED.value
    assert waiting_view.interruption_class == InterruptionClass.IMPORTANT.value
    assert waiting_view.related_task_id == waiting_task_id
    attention_rows = await facade.refresh_rows("attention")
    assert any(
        "IMPORTANT" in row.status and str(waiting_task_id) in row.detail for row in attention_rows
    )
    stored_entry = container.attention_policy.entry_for(attention.item_id)
    assert stored_entry is not None and stored_entry.delivered_at is None

    episode_view = facade.episode_views()[0]
    assert episode_view.outcome == EpisodeOutcome.UNKNOWN_OUTCOME.value
    assert episode_view.verification == EpisodeVerification.UNKNOWN.value
    episode_rows = await facade.refresh_rows("episodes")
    assert "UNKNOWN_OUTCOME" in episode_rows[0].status
    assert "VERIFIED" not in episode_rows[0].status

    overview = facade.overview_view()
    activity = facade.activity_view()
    assert any(item.item_id == attention.item_id for item in overview.attention.items)
    assert any(item.category == "attention" for item in activity.items)
    assert any(item.category == "episode" for item in activity.items)
    stored_entry = container.attention_policy.entry_for(attention.item_id)
    assert stored_entry is not None and stored_entry.delivered_at is None
    await facade.aclose()


@pytest.mark.asyncio
async def test_safe_mode_p2_projections_are_unavailable_not_empty(tmp_path: Path) -> None:
    del tmp_path
    facade = DesktopApplicationFacade(
        ApplicationRuntime(None, status=RuntimeStatus.SAFE_MODE, error="configuration invalid")
    )
    assert facade.attention_view().state == "unavailable"
    assert facade.activity_view().state == "unavailable"
    assert (await facade.refresh_rows("episodes"))[0].status == "UNAVAILABLE"
    overview = facade.overview_view()
    assert overview.attention.state == "unavailable"
    assert overview.runtime.safe_mode is True


async def test_new_conversation_receives_typed_presentation_guidance(
    tmp_path: Path,
) -> None:
    runtime = ApplicationRuntime.create(
        Settings(app_data_dir=tmp_path / "data", ai_provider="ollama")
    )
    facade = DesktopApplicationFacade(runtime)
    try:
        facade.update_persona({"verbosity": 4, "response_length": 1})
        conversation_id = facade.create_conversation()
        assert runtime.container is not None
        messages = runtime.container.conversation.history(conversation_id)
        assert len(messages) == 1
        assert messages[0].role.value == "system"
        assert "verbosity level 4/4" in messages[0].content
        assert "permissions" in messages[0].content
    finally:
        facade.reset_persona()
        await facade.aclose()
