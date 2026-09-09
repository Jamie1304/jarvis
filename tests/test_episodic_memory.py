"""Focused P2B tests for evidence-bound local Episodes."""

from __future__ import annotations

import asyncio
import json
from dataclasses import dataclass, replace
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import cast
from uuid import UUID, uuid4

import pytest
from jarvis.attention import SQLiteAttentionStore
from jarvis.events import (
    EventEnvelope,
    EventPayload,
    EventType,
    InMemoryEventBus,
    SemanticEventService,
    TaskStateChanged,
)
from jarvis.memory.episodes import (
    EpisodeComposer,
    EpisodeContinuity,
    EpisodeOutcome,
    EpisodeVerification,
)
from jarvis.memory.services import EpisodicMemoryService
from jarvis.memory.store import SQLiteMemoryStore
from jarvis.planning.models import (
    BudgetUsage,
    ExecutionBudgets,
    FailureKind,
    PlanningTask,
    PlanningTaskStatus,
    StepError,
)
from jarvis.task_controller import TaskController, TaskResult

NOW = datetime(2026, 9, 9, tzinfo=UTC)


def _task(
    status: PlanningTaskStatus,
    *,
    task_id: UUID | None = None,
    goal: str = "calculate 25% of 800",
    evidence: tuple[str, ...] = ("verified-result",),
    error: StepError | None = None,
) -> PlanningTask:
    task_id = task_id or uuid4()
    return PlanningTask(
        task_id,
        goal,
        (),
        (),
        status,
        None,
        ExecutionBudgets(),
        BudgetUsage(),
        NOW,
        NOW,
        NOW + timedelta(minutes=5),
        NOW + timedelta(seconds=1),
        result_evidence=evidence,
        error=error,
    )


@dataclass
class _Controller:
    task: PlanningTask

    def get_task(self, task_id: UUID) -> PlanningTask | None:
        return self.task if task_id == self.task.task_id else None

    def inspect_plan(self, task_id: UUID) -> None:
        return None

    def get_result(self, task_id: UUID) -> TaskResult | None:
        if task_id != self.task.task_id:
            return None
        return TaskResult(
            task_id, self.task.status, self.task.result_evidence, None, self.task.error
        )


def _raw_terminal(task: PlanningTask, sequence: int) -> EventEnvelope[EventPayload]:
    event = EventEnvelope.create(
        EventType.TASK_STATE_CHANGED,
        TaskStateChanged("executing", "completed", "verified"),
        source="test",
        correlation_id=task.task_id,
        task_id=task.task_id,
        timestamp=NOW,
    )
    return cast(EventEnvelope[EventPayload], replace(event, sequence=sequence))


def _composer(
    tmp_path: Path,
    task: PlanningTask,
    *,
    actor_context_id: UUID | None = None,
) -> tuple[
    EpisodeComposer,
    EpisodicMemoryService,
    SemanticEventService,
    SQLiteMemoryStore,
    SQLiteAttentionStore,
]:
    memory_store = SQLiteMemoryStore(tmp_path / "memory.sqlite3")
    attention_store = SQLiteAttentionStore(tmp_path / "attention.sqlite3")
    bus = InMemoryEventBus()
    semantic = SemanticEventService(bus)
    controller = _Controller(task)
    episodic = EpisodicMemoryService(memory_store, clock=lambda: NOW)
    composer = EpisodeComposer(
        bus,
        cast(TaskController, controller),
        episodic,
        semantic,
        actor_context_id=actor_context_id,
        actor_principal_id="principal-a",
        provider_id="local",
        model_id="fixture",
        clock=lambda: NOW,
    )
    semantic.process(_raw_terminal(task, 1))
    return composer, episodic, semantic, memory_store, attention_store


def test_successful_episode_is_typed_compact_and_idempotent(tmp_path: Path) -> None:
    task = _task(PlanningTaskStatus.COMPLETED)
    composer, episodic, _semantic, memory, attention = _composer(tmp_path, task)
    try:
        first = composer.compose_task(task.task_id)
        second = composer.compose_task(task.task_id)
        assert first is not None
        assert second == first
        assert first.terminal_outcome is EpisodeOutcome.COMPLETED
        assert first.verification is EpisodeVerification.VERIFIED
        assert first.continuity is EpisodeContinuity.COMPLETE
        assert first.semantic_event_ids
        assert first.raw_event_ids
        assert len(episodic.list_episodes(task_id=task.task_id)) == 1
        assert memory.list() and len(attention.list_items()) == 0
    finally:
        memory.close()
        attention.close()


def test_episode_restart_and_actor_scope(tmp_path: Path) -> None:
    actor = uuid4()
    task = _task(PlanningTaskStatus.COMPLETED)
    composer, episodic, _semantic, memory, attention = _composer(
        tmp_path, task, actor_context_id=actor
    )
    try:
        episode = composer.compose_task(task.task_id)
        assert episode is not None
        episode_id = episode.episode_id
    finally:
        memory.close()
        attention.close()

    reopened = SQLiteMemoryStore(tmp_path / "memory.sqlite3")
    try:
        restored = EpisodicMemoryService(reopened).get_episode(episode_id)
        assert restored is not None
        assert restored.episode_id == episode_id
        assert restored.actor_context_id == actor
        assert EpisodicMemoryService(reopened).list_episodes(actor_context_id=uuid4()) == ()
    finally:
        reopened.close()


@pytest.mark.parametrize(
    ("status", "error", "expected", "verification"),
    (
        (PlanningTaskStatus.FAILED, None, EpisodeOutcome.FAILED, EpisodeVerification.NOT_VERIFIED),
        (
            PlanningTaskStatus.CANCELLED,
            None,
            EpisodeOutcome.CANCELLED,
            EpisodeVerification.NOT_VERIFIED,
        ),
        (
            PlanningTaskStatus.FAILED,
            StepError("unknown", "uncertain", FailureKind.UNKNOWN_OUTCOME),
            EpisodeOutcome.UNKNOWN_OUTCOME,
            EpisodeVerification.UNKNOWN,
        ),
        (
            PlanningTaskStatus.BUDGET_EXHAUSTED,
            None,
            EpisodeOutcome.BLOCKED,
            EpisodeVerification.NOT_VERIFIED,
        ),
    ),
)
def test_authoritative_non_success_outcomes(
    tmp_path: Path,
    status: PlanningTaskStatus,
    error: StepError | None,
    expected: EpisodeOutcome,
    verification: EpisodeVerification,
) -> None:
    task = _task(status, error=error, evidence=())
    composer, _episodic, _semantic, memory, attention = _composer(tmp_path, task)
    try:
        episode = composer.compose_task(task.task_id)
        assert episode is not None
        assert episode.terminal_outcome is expected
        assert episode.verification is verification
    finally:
        memory.close()
        attention.close()


def test_gap_is_persisted_as_broken_continuity_without_fabrication(tmp_path: Path) -> None:
    task = _task(PlanningTaskStatus.COMPLETED)
    composer, episodic, semantic, memory, attention = _composer(tmp_path, task)
    try:
        semantic.process(_raw_terminal(task, 3))
        episode = composer.compose_task(task.task_id)
        assert episode is not None
        assert episode.continuity is EpisodeContinuity.BROKEN_CONTINUITY
        assert len(episodic.list_episodes(task_id=task.task_id)) == 1
    finally:
        memory.close()
        attention.close()


def test_forbidden_raw_content_is_not_persisted(tmp_path: Path) -> None:
    canary = "hidden_reasoning_marker_prompt_secret_token"
    task = _task(
        PlanningTaskStatus.FAILED,
        goal=f"{canary} calculate 25% of 800",
        evidence=(canary, "authorization: Bearer fake-token"),
        error=StepError("failure", canary, FailureKind.DETERMINISTIC, (canary,)),
    )
    composer, _episodic, _semantic, memory, attention = _composer(tmp_path, task)
    try:
        episode = composer.compose_task(task.task_id)
        assert episode is not None
        payload = json.dumps(episode.to_data(), sort_keys=True)
        stored = json.dumps(memory.list()[0].data_object, sort_keys=True)
        assert canary not in payload
        assert canary not in stored
        assert "authorization: Bearer fake-token" not in stored
        assert episode.goal_fingerprint != canary
    finally:
        memory.close()
        attention.close()


@pytest.mark.asyncio
async def test_composer_subscribes_and_unsubscribes_without_attention_write(tmp_path: Path) -> None:
    task = _task(PlanningTaskStatus.COMPLETED)
    composer, episodic, semantic, memory, attention = _composer(tmp_path, task)
    bus = composer._event_bus  # noqa: SLF001 - lifecycle assertion for the owned service
    try:
        await semantic.start()
        await composer.start()
        assert bus.pending_consumer_count == 2
        await bus.publish(_raw_terminal(task, 1))
        await asyncio.sleep(0.02)
        assert len(episodic.list_episodes(task_id=task.task_id)) == 1
        assert attention.list_items() == ()
        await composer.close()
        await semantic.close()
        assert bus.pending_consumer_count == 0
    finally:
        await bus.close()
        memory.close()
        attention.close()
