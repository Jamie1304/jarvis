from __future__ import annotations

import threading
from pathlib import Path
from typing import cast
from uuid import UUID

from jarvis.ai.sessions import AgentSessionStore, AgentSessionType
from jarvis.application import AssistantEvent, AssistantEventKind, JarvisAssistantService
from jarvis.bootstrap import create_application_runtime, create_desktop_facade_from_runtime
from jarvis.conversation.service import ConversationService
from jarvis.core.config import Settings
from jarvis.frontend.desktop_backend import DesktopBackendHost
from jarvis.runtime import ApplicationRuntime

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
