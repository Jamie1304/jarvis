from __future__ import annotations

from pathlib import Path
from typing import Any, cast
from uuid import uuid4

import pytest
from jarvis.ai.providers.registry import (
    ModelMetadata,
    ProviderDefinition,
    ProviderMetadata,
    ProviderRegistry,
)
from jarvis.ai.sessions import AgentSessionStore, AgentSessionType
from jarvis.conversation.service import ConversationService
from jarvis.core.errors import ConversationCancelledError
from jarvis.planning.models import PlanningTaskStatus
from jarvis.voice.activation import PlanningVoiceTaskRunner

from tests.fakes import FakeAIProvider


def _registry(provider: FakeAIProvider) -> ProviderRegistry:
    return ProviderRegistry(
        (
            ProviderDefinition(
                ProviderMetadata("fake", "Fake", "1", local_only=True),
                lambda configuration: provider,
                (ModelMetadata("fake-model", 4096, frozenset({"chat"})),),
            ),
        )
    )


@pytest.mark.asyncio
async def test_provider_registry_config_health_and_model_metadata() -> None:
    provider = FakeAIProvider()
    registry = _registry(provider)
    assert registry.provider_ids() == ("fake",)
    assert registry.create("FAKE", {}) is provider
    assert (await registry.health("fake", provider)).available
    assert (await registry.model("fake", provider)).model_id == "fake-model"
    with pytest.raises(KeyError):
        registry.definition("missing")
    with pytest.raises(ValueError):
        registry.register(
            ProviderDefinition(ProviderMetadata("FAKE", "Duplicate", "1"), lambda _: provider)
        )


def test_session_store_restart_child_usage_model_change_archive_and_persistence(
    tmp_path: Path,
) -> None:
    path = tmp_path / "sessions.sqlite3"
    store = AgentSessionStore(path)
    session = store.create(
        AgentSessionType.VOICE,
        "fake",
        "fake-model",
        context_metadata=(("purpose", "conversation"),),
    )
    used = store.record_usage(session.session_id, 12, 0.25)
    assert used.usage_tokens == 12
    assert used.usage_cost == 0.25
    child = store.child(session.session_id, AgentSessionType.SUBAGENT)
    assert child.parent_session_id == session.session_id
    changed = store.change_model(session.session_id, "new-model")
    assert changed.model_id == "new-model"
    assert store.get(session.session_id).archived  # type: ignore[union-attr]
    restarted = store.rebuild(changed.session_id)
    assert restarted.session_id != changed.session_id
    store.close()

    reopened = AgentSessionStore(path)
    assert reopened.get(restarted.session_id) is not None
    reopened.archive(restarted.session_id)
    assert reopened.get(restarted.session_id).archived  # type: ignore[union-attr]
    reopened.close()


@pytest.mark.asyncio
async def test_conversation_reuses_voice_session_and_rebuilds_after_cancellation(
    tmp_path: Path,
) -> None:
    provider = FakeAIProvider(("first", "second"))
    store = AgentSessionStore(tmp_path / "sessions.sqlite3")
    service = ConversationService(
        provider,
        model="fake-model",
        context_limit=1024,
        session_store=store,
        session_type=AgentSessionType.VOICE,
        provider_id="fake",
    )
    conversation_id = service.create_conversation()
    original = service.session_id(conversation_id)
    assert original is not None
    [update async for update in service.stream_reply(conversation_id, "one")]
    assert service.session_id(conversation_id) == original

    stream = service.stream_reply(conversation_id, "interrupt")
    first = await anext(stream)
    assert first.content == "first"
    service.cancel(conversation_id)
    with pytest.raises(ConversationCancelledError):
        await anext(stream)
    rebuilt_stream = service.stream_reply(conversation_id, "new utterance")
    [update async for update in rebuilt_stream]
    assert service.session_id(conversation_id) != original
    assert store.get(original).synchronized is False  # type: ignore[union-attr]
    store.close()


@pytest.mark.asyncio
async def test_new_utterance_invalidates_previous_stream(tmp_path: Path) -> None:
    provider = FakeAIProvider(("old", "tail"))
    store = AgentSessionStore(tmp_path / "overlap.sqlite3")
    service = ConversationService(
        provider,
        model="fake-model",
        context_limit=1024,
        session_store=store,
        session_type=AgentSessionType.VOICE,
        provider_id="fake",
    )
    conversation_id = service.create_conversation()
    old_stream = service.stream_reply(conversation_id, "old")
    await anext(old_stream)
    new_stream = service.stream_reply(conversation_id, "new")
    await anext(new_stream)
    with pytest.raises(ConversationCancelledError):
        await anext(old_stream)
    [update async for update in new_stream]
    store.close()


@pytest.mark.asyncio
async def test_planning_voice_runner_reuses_and_rebuilds_bound_session(tmp_path: Path) -> None:
    class Controller:
        async def create_task(self, goal: str) -> object:
            del goal
            return type("Task", (), {"task_id": uuid4()})()

        async def run_task(self, task_id: object) -> object:
            return type(
                "Result",
                (),
                {"task_id": task_id, "status": PlanningTaskStatus.COMPLETED, "error": None},
            )()

        async def cancel_task(self, task_id: object) -> object:
            return await self.run_task(task_id)

    store = AgentSessionStore(tmp_path / "voice.sqlite3")
    runner = PlanningVoiceTaskRunner(
        cast(Any, Controller()), session_store=store, provider_id="fake", model_id="fake-model"
    )
    conversation_id = uuid4()
    first = await runner.start(conversation_id, "one")
    await first.completion
    original = runner.session_id(conversation_id)
    assert original is not None
    second = await runner.start(conversation_id, "two")
    await second.completion
    assert runner.session_id(conversation_id) == original
    store.mark_synchronized(original, False)
    third = await runner.start(conversation_id, "three")
    await third.completion
    assert runner.session_id(conversation_id) != original
    store.close()


def test_session_store_rejects_invalid_usage_and_missing_relationships(tmp_path: Path) -> None:
    store = AgentSessionStore(tmp_path / "invalid.sqlite3")
    with pytest.raises(ValueError):
        store.record_usage(uuid4(), -1)
    with pytest.raises(KeyError):
        store.rebuild(uuid4())
    with pytest.raises(KeyError):
        store.change_model(uuid4(), "model")
    with pytest.raises(KeyError):
        store.child(uuid4(), AgentSessionType.SUBAGENT)
    store.close()
