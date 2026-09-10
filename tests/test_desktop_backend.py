from __future__ import annotations

import asyncio
import threading
from pathlib import Path
from typing import cast
from uuid import UUID

from jarvis.ai.sessions import AgentSessionStore, AgentSessionType
from jarvis.application import AssistantEvent, AssistantEventKind, JarvisAssistantService
from jarvis.bootstrap import create_application_runtime, create_desktop_facade_from_runtime
from jarvis.conversation.service import ConversationService
from jarvis.core.config import Settings
from jarvis.events import EventEnvelope, EventPayload, EventType
from jarvis.events.models import PermissionRequested
from jarvis.frontend.desktop_backend import DesktopBackendHost
from jarvis.projections import ProjectionKind, ProjectionUpdate
from jarvis.runtime import ApplicationRuntime
from jarvis.trace import TraceEvent, TraceEventType

from tests.fakes import FakeAIProvider


class _RuntimeDouble:
    async def aclose(self) -> None:
        return None


def test_desktop_backend_owns_runtime_and_session_store_for_sequential_chat(
    tmp_path: Path,
) -> None:
    owner_threads: list[int] = []
    provider = FakeAIProvider(("reply",))

    def runtime_factory() -> ApplicationRuntime:
        owner_threads.append(threading.get_ident())
        return cast(ApplicationRuntime, _RuntimeDouble())

    def assistant_factory(runtime: ApplicationRuntime) -> JarvisAssistantService:
        del runtime
        owner_threads.append(threading.get_ident())
        store = AgentSessionStore(tmp_path / "sessions.sqlite3")
        conversation = ConversationService(
            provider,
            model="fake-model",
            context_limit=1024,
            session_store=store,
            session_type=AgentSessionType.VOICE,
            provider_id="fake",
        )
        return JarvisAssistantService(conversation)

    backend = DesktopBackendHost(runtime_factory, assistant_factory)
    assert backend.start().ready
    conversation_id = backend.submit(lambda service: service.create_conversation()).result()
    events: list[AssistantEvent] = []
    backend.stream_text(conversation_id, "first", on_event=events.append).result()
    backend.stream_text(conversation_id, "second", on_event=events.append).result()
    backend.close()

    assert owner_threads[0] == owner_threads[1]
    assert owner_threads[0] != threading.get_ident()
    assert [event.content for event in events if event.kind is AssistantEventKind.TEXT] == [
        "reply",
        "reply",
    ]
    assert len(provider.requests) == 2


def test_desktop_backend_starts_p2_subscribers_before_real_work(tmp_path: Path) -> None:
    settings = Settings(
        app_data_dir=tmp_path / "data",
        ai_provider="ollama",
        ollama_autostart=False,
    )
    backend = DesktopBackendHost(
        lambda: create_application_runtime(settings), create_desktop_facade_from_runtime
    )
    try:
        assert backend.start().ready
        conversation_id = backend.submit(lambda facade: facade.create_conversation()).result(
            timeout=10
        )
        created = backend.submit_async(
            lambda facade: facade.create_task(conversation_id, "calculate 25% of 800")
        ).result(timeout=30)
        completed = backend.submit_async(
            lambda facade: facade.run_task(UUID(created.identifier))
        ).result(timeout=30)
        assert completed.status == "completed"
        assert backend.submit(lambda facade: len(facade.episode_views())).result(timeout=10) == 1
    finally:
        backend.close()


def test_desktop_backend_fast_episode_projection_emits_update(tmp_path: Path) -> None:
    settings = Settings(
        app_data_dir=tmp_path / "data",
        ai_provider="ollama",
        ollama_autostart=False,
    )
    episode_ready = threading.Event()
    updates: list[ProjectionUpdate] = []
    backend = DesktopBackendHost(
        lambda: create_application_runtime(settings), create_desktop_facade_from_runtime
    )

    def collect_episode(update: ProjectionUpdate) -> None:
        if update.kind is ProjectionKind.EPISODE:
            updates.append(update)
            episode_ready.set()

    backend.add_projection_listener(collect_episode)
    try:
        assert backend.start().ready
        conversation_id = backend.submit(lambda facade: facade.create_conversation()).result(
            timeout=10
        )
        created = backend.submit_async(
            lambda facade: facade.create_task(conversation_id, "calculate 25% of 800")
        ).result(timeout=30)
        completed = backend.submit_async(
            lambda facade: facade.run_task(UUID(created.identifier))
        ).result(timeout=30)
        assert completed.status == "completed"
        assert episode_ready.wait(10)
        assert (
            len(tuple(update for update in updates if update.kind is ProjectionKind.EPISODE)) == 1
        )
        assert backend.submit(lambda facade: len(facade.episode_views())).result(timeout=10) == 1
        activity = backend.submit(lambda facade: facade.activity_view()).result(timeout=10)
        assert any(
            item.identifier.startswith("trace:") and item.category == "completion"
            for item in activity.items
        )
    finally:
        backend.close()


def test_desktop_backend_slow_episode_projection_converges_after_former_timer_race(
    tmp_path: Path,
) -> None:
    settings = Settings(
        app_data_dir=tmp_path / "data",
        ai_provider="ollama",
        ollama_autostart=False,
    )
    projector_started = threading.Event()
    release_projector = threading.Event()
    episode_ready = threading.Event()
    updates: list[ProjectionUpdate] = []

    def runtime_factory() -> ApplicationRuntime:
        runtime = create_application_runtime(settings)
        assert runtime.container is not None
        composer = runtime.container.episode_composer
        original = composer._on_event

        async def delayed_terminal_projection(event: EventEnvelope[EventPayload]) -> None:
            if (
                getattr(event, "event_type", None) is EventType.TASK_STATE_CHANGED
                and getattr(getattr(event, "payload", None), "to_state", None) == "completed"
            ):
                projector_started.set()
                assert await asyncio.to_thread(release_projector.wait, 10)
            await original(event)

        object.__setattr__(composer, "_on_event", delayed_terminal_projection)
        return runtime

    backend = DesktopBackendHost(runtime_factory, create_desktop_facade_from_runtime)

    def collect_episode(update: ProjectionUpdate) -> None:
        if update.kind is ProjectionKind.EPISODE:
            updates.append(update)
            episode_ready.set()

    backend.add_projection_listener(collect_episode)
    try:
        assert backend.start().ready
        conversation_id = backend.submit(lambda facade: facade.create_conversation()).result(
            timeout=10
        )
        created = backend.submit_async(
            lambda facade: facade.create_task(conversation_id, "calculate 25% of 800")
        ).result(timeout=30)
        completed = backend.submit_async(
            lambda facade: facade.run_task(UUID(created.identifier))
        ).result(timeout=30)
        assert completed.status == "completed"
        assert projector_started.wait(10)

        # This is the former fixed-refresh race: terminal authority is complete,
        # but the deliberately held Episode projection is not available yet.
        assert backend.submit(lambda facade: facade.episode_views()).result(timeout=10) == ()
        assert not episode_ready.is_set()

        release_projector.set()
        assert episode_ready.wait(10)
        assert len(backend.submit(lambda facade: facade.episode_views()).result(timeout=10)) == 1
        assert (
            len(tuple(update for update in updates if update.kind is ProjectionKind.EPISODE)) == 1
        )
    finally:
        release_projector.set()
        backend.close()


def test_desktop_backend_real_p2c_event_emits_attention_trace_without_enqueue(
    tmp_path: Path,
) -> None:
    settings = Settings(
        app_data_dir=tmp_path / "data",
        ai_provider="ollama",
        ollama_autostart=False,
    )
    runtime_holder: list[ApplicationRuntime] = []
    attention_trace_ready = threading.Event()
    updates: list[ProjectionUpdate] = []

    def runtime_factory() -> ApplicationRuntime:
        runtime = create_application_runtime(settings)
        runtime_holder.append(runtime)
        return runtime

    backend = DesktopBackendHost(runtime_factory, create_desktop_facade_from_runtime)

    def collect(update: ProjectionUpdate) -> None:
        updates.append(update)
        if update.kind is ProjectionKind.TRACE:
            runtime = runtime_holder[0]
            if runtime.container is not None and any(
                event.event_id == update.record_id and event.event_type is TraceEventType.ATTENTION
                for event in runtime.container.trace_service.recent_events()
            ):
                attention_trace_ready.set()

    backend.add_projection_listener(collect)
    try:
        assert backend.start().ready

        async def wait_for_services(_facade: object) -> None:
            runtime = runtime_holder[0]
            assert runtime.container is not None
            tasks = tuple(
                task
                for task in (
                    runtime.container.trace_start_task,
                    runtime.container.semantic_start_task,
                )
                if task is not None
            )
            await asyncio.gather(*tasks)

        backend.submit_async(wait_for_services).result(timeout=10)
        conversation_id = backend.submit(lambda facade: facade.create_conversation()).result(
            timeout=10
        )
        task_row = backend.submit_async(
            lambda facade: facade.create_task(conversation_id, "calculate 25% of 800")
        ).result(timeout=10)
        correlation_id = UUID("11111111-1111-4111-8111-111111111111")
        task_id = UUID(task_row.identifier)
        request_id = UUID("33333333-3333-4333-8333-333333333333")
        event = EventEnvelope.create(
            EventType.PERMISSION_REQUESTED,
            PermissionRequested(request_id, "filesystem.read", "low"),
            source="controlled.p2c.product.exercise",
            correlation_id=correlation_id,
            task_id=task_id,
        )

        async def publish(_facade: object) -> bool:
            runtime = runtime_holder[0]
            assert runtime.container is not None
            return await runtime.container.event_bus.publish(
                cast(EventEnvelope[EventPayload], event)
            )

        assert backend.submit_async(publish).result(timeout=10)
        assert attention_trace_ready.wait(10)

        attention = backend.submit(lambda facade: facade.attention_view()).result(timeout=10)
        activity = backend.submit(lambda facade: facade.activity_view()).result(timeout=10)
        important = next(item for item in attention.items if item.related_task_id == task_id)
        assert important.interruption_class == "important"
        assert important.related_task_id == task_id
        assert important.delivery_state == "deferred"
        assert any(
            item.category == "attention" and item.task_id == task_id for item in activity.items
        )

        def read_attention_trace(_facade: object) -> TraceEvent:
            runtime = runtime_holder[0]
            assert runtime.container is not None
            return next(
                event
                for event in runtime.container.trace_service.recent_events()
                if event.event_type is TraceEventType.ATTENTION
                and event.correlation_id == correlation_id
            )

        attention_trace = backend.submit(read_attention_trace).result(timeout=10)
        factual = next(
            item
            for item in activity.items
            if item.identifier == f"trace:{attention_trace.event_id}"
        )
        assert factual.category == TraceEventType.ATTENTION.value
        assert "class=important" in factual.summary
        assert "reason=task_waiting_for_user" in factual.summary
        assert "decision=defer" in factual.summary
        assert "delivery=deferred" in factual.summary
        assert any(update.kind is ProjectionKind.TRACE for update in updates)
        assert runtime_holder[0].container is not None
        stored = runtime_holder[0].container.attention_policy.entry_for(important.item_id)
        assert stored is not None and stored.delivered_at is None
    finally:
        backend.close()
