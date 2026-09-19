"""Focused tests for the bounded deterministic P2A semantic projection."""

from __future__ import annotations

import asyncio
from dataclasses import replace
from datetime import UTC, datetime
from pathlib import Path
from uuid import UUID, uuid4

import pytest
from jarvis.attention import SQLiteAttentionStore
from jarvis.events import (
    ContinuityState,
    EventEnvelope,
    EventPayload,
    EventType,
    InMemoryEventBus,
    PatternKind,
    PermissionGranted,
    RuntimeStateChanged,
    SemanticEventService,
    SemanticKind,
    StepFailed,
    ToolFailed,
)
from jarvis.memory.store import SQLiteMemoryStore

NOW = datetime(2026, 9, 9, tzinfo=UTC)


def _event(
    event_type: EventType,
    payload: EventPayload,
    *,
    event_id: UUID | None = None,
    correlation_id: UUID | None = None,
    task_id: UUID | None = None,
    timestamp: datetime = NOW,
    sequence: int = 0,
) -> EventEnvelope[EventPayload]:
    event = EventEnvelope.create(
        event_type,
        payload,
        source="test",
        correlation_id=correlation_id or uuid4(),
        task_id=task_id,
        timestamp=timestamp,
    )
    return replace(event, event_id=event_id or event.event_id, sequence=sequence)


def test_mapping_is_deterministic_and_preserves_provenance() -> None:
    service = SemanticEventService(InMemoryEventBus())
    raw_id = uuid4()
    correlation_id = uuid4()
    task_id = uuid4()
    raw = _event(
        EventType.STEP_FAILED,
        StepFailed(uuid4(), "timeout"),
        event_id=raw_id,
        correlation_id=correlation_id,
        task_id=task_id,
        sequence=10,
    )

    first = service.process(raw)[0]
    again = SemanticEventService(InMemoryEventBus()).process(raw)[0]

    assert first.semantic_event_id == again.semantic_event_id
    assert first.semantic_kind is SemanticKind.EXECUTION_FAILED
    assert first.source_event_ids == (raw_id,)
    assert first.correlation_id == correlation_id
    assert first.task_id == task_id
    assert first.metadata == (("error_code", "timeout"),)

    distinct = service.process(replace(raw, event_id=uuid4(), sequence=11))[0]
    assert distinct.semantic_event_id != first.semantic_event_id


def test_representative_mapping_stays_minimal_and_observational() -> None:
    service = SemanticEventService(InMemoryEventBus())
    task_id = uuid4()
    correlation_id = uuid4()
    cases = (
        (EventType.TOOL_FAILED, ToolFailed("tool", "bad"), SemanticKind.EXECUTION_FAILED),
        (
            EventType.PERMISSION_GRANTED,
            PermissionGranted(uuid4(), "filesystem"),
            SemanticKind.PERMISSION_OBSERVED,
        ),
        (
            EventType.RUNTIME_STATE_CHANGED,
            RuntimeStateChanged("degraded"),
            SemanticKind.RUNTIME_DEGRADED,
        ),
    )
    for index, (event_type, payload, expected) in enumerate(cases, 1):
        semantic = service.process(
            _event(
                event_type,
                payload,
                task_id=task_id,
                correlation_id=correlation_id,
                sequence=index,
            )
        )[0]
        assert semantic.semantic_kind is expected
        assert semantic.task_id == task_id
        assert semantic.correlation_id == correlation_id
        assert all(len(key) < 64 and len(value) < 256 for key, value in semantic.metadata)


def test_duplicates_do_not_change_observations_or_pattern_counts() -> None:
    correlation_id = uuid4()
    task_id = uuid4()
    service = SemanticEventService(InMemoryEventBus())
    first = _event(
        EventType.TOOL_FAILED,
        ToolFailed("tool", "bad"),
        correlation_id=correlation_id,
        task_id=task_id,
        sequence=1,
    )
    second = _event(
        EventType.TOOL_FAILED,
        ToolFailed("tool", "bad"),
        correlation_id=correlation_id,
        task_id=task_id,
        sequence=2,
    )
    service.process(first)
    service.process(first)
    service.process(second)
    service.process(second)

    assert len(service.recent_events()) == 2
    assert len(service.recent_patterns()) == 1
    assert service.recent_patterns()[0].pattern_kind is PatternKind.REPEATED_EXECUTION_FAILURE
    assert service.recent_patterns()[0].supporting_raw_event_ids == (
        first.event_id,
        second.event_id,
    )


def test_gap_breaks_windows_without_fabricating_missing_events() -> None:
    correlation_id = uuid4()
    task_id = uuid4()
    service = SemanticEventService(InMemoryEventBus())
    for sequence in (10, 11):
        service.process(
            _event(
                EventType.STEP_FAILED,
                StepFailed(uuid4(), "bad"),
                correlation_id=correlation_id,
                task_id=task_id,
                sequence=sequence,
            )
        )
    assert len(service.recent_patterns()) == 1

    gap = service.process(
        _event(
            EventType.STEP_FAILED,
            StepFailed(uuid4(), "gap"),
            correlation_id=correlation_id,
            task_id=task_id,
            sequence=14,
        )
    )[0]
    assert gap.continuity is ContinuityState.BROKEN
    assert len(service.recent_patterns()) == 1

    service.process(
        _event(
            EventType.STEP_FAILED,
            StepFailed(uuid4(), "new-1"),
            correlation_id=correlation_id,
            task_id=task_id,
            sequence=15,
        )
    )
    service.process(
        _event(
            EventType.STEP_FAILED,
            StepFailed(uuid4(), "new-2"),
            correlation_id=correlation_id,
            task_id=task_id,
            sequence=16,
        )
    )
    assert len(service.recent_patterns()) == 2
    assert all(
        gap.source_event_ids[0] not in pattern.supporting_raw_event_ids
        for pattern in service.recent_patterns()[1:]
    )


def test_degraded_recovery_is_scoped_and_bounded() -> None:
    service = SemanticEventService(InMemoryEventBus())
    correlation_id = uuid4()
    service.process(
        _event(
            EventType.RUNTIME_STATE_CHANGED,
            RuntimeStateChanged("degraded"),
            correlation_id=correlation_id,
            sequence=1,
        )
    )
    service.process(
        _event(
            EventType.RUNTIME_STATE_CHANGED,
            RuntimeStateChanged("ready"),
            correlation_id=correlation_id,
            sequence=2,
        )
    )
    assert service.recent_patterns()[0].pattern_kind is PatternKind.DEGRADED_THEN_RECOVERED

    other = service.process(
        _event(
            EventType.RUNTIME_STATE_CHANGED,
            RuntimeStateChanged("ready"),
            correlation_id=uuid4(),
            sequence=3,
        )
    )
    assert other
    assert len(service.recent_patterns()) == 1


def test_semantic_processing_does_not_write_memory_or_attention(tmp_path: Path) -> None:
    memory_store = SQLiteMemoryStore(tmp_path / "memory.sqlite3")
    attention_store = SQLiteAttentionStore(tmp_path / "attention.sqlite3")
    try:
        before_memory = len(memory_store.list())
        before_attention = len(attention_store.list_items())
        service = SemanticEventService(InMemoryEventBus())
        correlation_id = uuid4()
        task_id = uuid4()
        for sequence in (1, 2):
            service.process(
                _event(
                    EventType.TOOL_FAILED,
                    ToolFailed("tool", "failure"),
                    correlation_id=correlation_id,
                    task_id=task_id,
                    sequence=sequence,
                )
            )
        assert service.recent_patterns()
        assert len(memory_store.list()) == before_memory
        assert len(attention_store.list_items()) == before_attention
    finally:
        memory_store.close()
        attention_store.close()


@pytest.mark.asyncio
async def test_bus_lifecycle_and_shutdown_unsubscribe() -> None:
    bus = InMemoryEventBus()
    service = SemanticEventService(bus)
    await service.start()
    assert bus.pending_consumer_count == 1
    await bus.publish(_event(EventType.RUNTIME_STATE_CHANGED, RuntimeStateChanged("degraded")))
    await asyncio.sleep(0.02)
    assert len(service.recent_events()) == 1
    await service.close()
    assert bus.pending_consumer_count == 0
    assert service.recent_events() == ()
    await bus.close()
