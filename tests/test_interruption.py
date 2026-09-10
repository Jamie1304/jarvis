"""Focused P2C interruption-intelligence contract tests."""

from __future__ import annotations

import asyncio
from collections.abc import Mapping
from dataclasses import replace
from datetime import UTC, datetime, timedelta
from pathlib import Path
from uuid import UUID, uuid4

import pytest
from jarvis.attention import (
    AttentionDecision,
    AttentionDeliveryState,
    AttentionItem,
    AttentionPolicy,
    AttentionPriority,
    InMemoryAttentionStore,
    InterruptionClass,
    InterruptionContext,
    InterruptionContextState,
    SQLiteAttentionStore,
)
from jarvis.core.config import Settings
from jarvis.events import (
    EventEnvelope,
    EventPayload,
    EventType,
    InMemoryEventBus,
    PermissionRequested,
    RuntimeStateChanged,
    SemanticEventService,
    StepCompleted,
    ToolFailed,
)
from jarvis.interruption import (
    InterruptionIntelligence,
    InterruptionReason,
    InterruptionRuleRegistry,
)
from jarvis.runtime import ApplicationRuntime, RuntimeStatus
from jarvis.trace import TraceEventType, TraceService, TraceStore

NOW = datetime(2026, 9, 9, tzinfo=UTC)


def _context(
    *,
    revision: int = 1,
    dnd: bool | None = False,
    fullscreen: bool | None = False,
    presentation: bool | None = False,
    active_voice: bool | None = False,
    user_typing: bool | None = False,
    active_conversation: bool | None = False,
    active_task: bool | None = False,
    safe_mode: bool = False,
) -> InterruptionContext:
    return InterruptionContext(
        revision,
        dnd,
        fullscreen,
        presentation,
        active_voice,
        user_typing,
        active_conversation,
        active_task,
        safe_mode,
    )


def _item(interruption_class: InterruptionClass, key: str = "item") -> AttentionItem:
    priority = {
        InterruptionClass.SILENT: AttentionPriority.BACKGROUND,
        InterruptionClass.QUEUE: AttentionPriority.LOW,
        InterruptionClass.NORMAL: AttentionPriority.NORMAL,
        InterruptionClass.IMPORTANT: AttentionPriority.HIGH,
        InterruptionClass.URGENT: AttentionPriority.URGENT,
    }[interruption_class]
    return AttentionItem(
        uuid4(),
        "interruption.test",
        "workspace-a",
        priority,
        NOW,
        dedupe_key=key,
        summary="Synthetic bounded attention fact",
        interruption_class=interruption_class,
    )


def _event(
    event_type: EventType,
    payload: EventPayload,
    *,
    sequence: int = 1,
    task_id: UUID | None = None,
    correlation_id: UUID | None = None,
) -> EventEnvelope[EventPayload]:
    return replace(
        EventEnvelope.create(
            event_type,
            payload,
            source="trusted.synthetic.test",
            correlation_id=correlation_id or task_id or uuid4(),
            task_id=task_id,
            timestamp=NOW,
        ),
        sequence=sequence,
    )


def test_canonical_classes_map_deterministically_and_unknown_context_stays_unknown() -> None:
    policy = AttentionPolicy(InMemoryAttentionStore(), clock=lambda: NOW)
    allowed = _context()
    unknown = InterruptionContext.unknown(revision=2)
    results = {
        InterruptionClass.SILENT: policy.enqueue(
            _item(InterruptionClass.SILENT, "silent"), context=allowed
        ),
        InterruptionClass.QUEUE: policy.enqueue(
            _item(InterruptionClass.QUEUE, "queue"), context=allowed
        ),
        InterruptionClass.NORMAL: policy.enqueue(
            _item(InterruptionClass.NORMAL, "normal"), context=allowed
        ),
        InterruptionClass.IMPORTANT: policy.enqueue(
            _item(InterruptionClass.IMPORTANT, "important"), context=allowed
        ),
        InterruptionClass.URGENT: policy.enqueue(
            _item(InterruptionClass.URGENT, "urgent"), context=unknown
        ),
    }
    assert results[InterruptionClass.SILENT].decision is AttentionDecision.SILENT_ACTIVITY
    assert results[InterruptionClass.QUEUE].decision is AttentionDecision.DEFER
    assert results[InterruptionClass.NORMAL].decision is AttentionDecision.DELIVER_NOW
    assert results[InterruptionClass.IMPORTANT].decision is AttentionDecision.DELIVER_NOW
    assert results[InterruptionClass.URGENT].decision is AttentionDecision.DELIVER_NOW
    policy.reconcile(context=allowed)
    queue_entry = policy.entry_for(results[InterruptionClass.QUEUE].item_id)
    assert queue_entry is not None
    assert queue_entry.decision is AttentionDecision.DELIVER_NOW
    assert unknown.blocking_state is InterruptionContextState.UNKNOWN
    silent_item = policy.item_for(results[InterruptionClass.SILENT].item_id)
    assert silent_item is not None and silent_item.resolved is True


def test_context_blocking_and_release_are_explicit_and_durable(tmp_path: Path) -> None:
    store = SQLiteAttentionStore(tmp_path / "attention.sqlite3")
    try:
        policy = AttentionPolicy(store, clock=lambda: NOW)
        item = _item(InterruptionClass.NORMAL, "context-release")
        deferred = policy.enqueue(item, context=_context(dnd=True))
        assert deferred.decision is AttentionDecision.DEFER
        deferred_item = policy.item_for(item.item_id)
        assert deferred_item is not None
        assert deferred_item.delivery_state is AttentionDeliveryState.DEFERRED
        policy.reconcile(context=_context(revision=2))
        released_entry = policy.entry_for(item.item_id)
        assert released_entry is not None
        assert released_entry.decision is AttentionDecision.DELIVER_NOW
        assert released_entry.delivered_at is None
    finally:
        store.close()


def test_context_reevaluation_traces_queue_release_and_is_idempotent(tmp_path: Path) -> None:
    attention_path = tmp_path / "attention.sqlite3"
    trace_path = tmp_path / "trace.sqlite3"
    task_id = uuid4()
    correlation_id = uuid4()
    item_id = uuid4()
    item = AttentionItem(
        item_id,
        "interruption.task_waiting_for_user",
        "workspace-a",
        AttentionPriority.LOW,
        NOW,
        dedupe_key="queue-reevaluation",
        summary="Synthetic bounded attention fact",
        interruption_class=InterruptionClass.QUEUE,
        actor_context_id=uuid4(),
        related_task_id=task_id,
        related_correlation_id=correlation_id,
        source_semantic_event_id=uuid4(),
        interruption_reason_code=InterruptionReason.TASK_WAITING_FOR_USER.value,
    )
    attention = SQLiteAttentionStore(attention_path)
    trace_store = TraceStore(trace_path)
    semantic = SemanticEventService(InMemoryEventBus())
    policy = AttentionPolicy(attention, clock=lambda: NOW)
    trace = TraceService(trace_store, InMemoryEventBus())
    intelligence = InterruptionIntelligence(semantic, policy, trace, lambda: _context())
    try:
        initial = policy.enqueue(item, context=_context())
        assert initial.decision is AttentionDecision.DEFER
        trace.record(
            TraceEventType.ATTENTION,
            "Attention decision recorded",
            task_id=task_id,
            correlation_id=correlation_id,
            result={
                "attention_item_id": str(item_id),
                "attention_decision": initial.decision.value,
            },
        )
        transitions = intelligence.reconcile(_context(revision=2))
        assert len(transitions) == 1
        assert transitions[0].prior_decision is AttentionDecision.DEFER
        assert transitions[0].new_decision is AttentionDecision.DELIVER_NOW
        stored_entry = policy.entry_for(item_id)
        stored_item = policy.item_for(item_id)
        assert stored_entry is not None and stored_entry.delivered_at is None
        assert (
            stored_item is not None and stored_item.delivery_state is AttentionDeliveryState.QUEUED
        )
        events = trace.get(task_id=task_id).events
        reevaluations = tuple(
            event
            for event in events
            if event.event_type is TraceEventType.ATTENTION
            and isinstance(event.result, Mapping)
            and event.result.get("reevaluation_reason") == "context_reevaluation"
        )
        assert len(reevaluations) == 1
        result = reevaluations[0].result
        assert isinstance(result, Mapping)
        assert result["prior_attention_decision"] == "defer"
        assert result["new_attention_decision"] == "deliver_now"
        assert result["prior_delivery_state"] == "deferred"
        assert result["new_delivery_state"] == "queued"
        assert result["context_revision"] == 2
        assert result["authority_changed"] is False
        assert intelligence.reconcile(_context(revision=2)) == ()
        assert (
            len(
                tuple(
                    event
                    for event in trace.get(task_id=task_id).events
                    if event.event_type is TraceEventType.ATTENTION
                    and isinstance(event.result, Mapping)
                    and event.result.get("reevaluation_reason") == "context_reevaluation"
                )
            )
            == 1
        )
    finally:
        intelligence.close()
        attention.close()
        trace_store.close()


def test_context_reevaluation_traces_normal_dnd_release_after_restart(tmp_path: Path) -> None:
    attention_path = tmp_path / "attention.sqlite3"
    trace_path = tmp_path / "trace.sqlite3"
    task_id = uuid4()
    correlation_id = uuid4()
    actor_context_id = uuid4()
    item = AttentionItem(
        uuid4(),
        "interruption.runtime_degraded",
        "workspace-a",
        AttentionPriority.NORMAL,
        NOW,
        dedupe_key="normal-reevaluation",
        summary="Synthetic bounded attention fact",
        interruption_class=InterruptionClass.NORMAL,
        actor_context_id=actor_context_id,
        related_task_id=task_id,
        related_correlation_id=correlation_id,
        source_semantic_event_id=uuid4(),
        source_pattern_id=uuid4(),
        interruption_reason_code=InterruptionReason.RUNTIME_DEGRADED.value,
    )
    attention = SQLiteAttentionStore(attention_path)
    trace_store = TraceStore(trace_path)
    semantic = SemanticEventService(InMemoryEventBus())
    policy = AttentionPolicy(attention, clock=lambda: NOW)
    trace = TraceService(trace_store, InMemoryEventBus())
    intelligence = InterruptionIntelligence(
        semantic,
        policy,
        trace,
        context_provider=lambda: _context(),
        actor_context_id=actor_context_id,
    )
    try:
        initial = policy.enqueue(item, context=_context(dnd=True))
        assert initial.decision is AttentionDecision.DEFER
        trace.record(
            TraceEventType.ATTENTION,
            "Attention decision recorded",
            task_id=task_id,
            correlation_id=correlation_id,
            result={"attention_item_id": str(item.item_id), "attention_decision": "defer"},
        )
    finally:
        intelligence.close()
        attention.close()
        trace_store.close()

    restarted_attention = SQLiteAttentionStore(attention_path)
    restarted_trace_store = TraceStore(trace_path)
    restarted_policy = AttentionPolicy(restarted_attention, clock=lambda: NOW)
    restarted_trace = TraceService(restarted_trace_store, InMemoryEventBus())
    restarted = InterruptionIntelligence(
        SemanticEventService(InMemoryEventBus()),
        restarted_policy,
        restarted_trace,
        context_provider=lambda: _context(),
        actor_context_id=actor_context_id,
    )
    try:
        transitions = restarted.reconcile(_context(revision=7, dnd=False))
        assert len(transitions) == 1
        assert transitions[0].new_decision is AttentionDecision.DELIVER_NOW
        entry = restarted_policy.entry_for(item.item_id)
        assert entry is not None and entry.delivered_at is None
        assert len(restarted_attention.list_items()) == 1
        events = restarted_trace.get(task_id=task_id).events
        assert (
            len(
                tuple(
                    event
                    for event in events
                    if event.event_type is TraceEventType.ATTENTION
                    and isinstance(event.result, Mapping)
                    and event.result.get("reevaluation_reason") == "context_reevaluation"
                )
            )
            == 1
        )
        reevaluation = next(
            event
            for event in events
            if event.event_type is TraceEventType.ATTENTION
            and isinstance(event.result, Mapping)
            and event.result.get("reevaluation_reason") == "context_reevaluation"
        )
        assert isinstance(reevaluation.result, Mapping)
        assert reevaluation.result["source_pattern_id"] == str(item.source_pattern_id)
        assert reevaluation.result["authority_changed"] is False
    finally:
        restarted.close()
        restarted_attention.close()
        restarted_trace_store.close()


def test_generic_attention_without_lineage_reconciles_without_trace_requirement(
    tmp_path: Path,
) -> None:
    now = [NOW]
    store = SQLiteAttentionStore(tmp_path / "attention.sqlite3")
    trace_store = TraceStore(tmp_path / "trace.sqlite3")
    policy = AttentionPolicy(store, clock=lambda: now[0])
    generic = AttentionItem(
        uuid4(),
        "capability.health",
        "default",
        AttentionPriority.NORMAL,
        NOW,
        cooldown_until=NOW + timedelta(hours=1),
        dedupe_key="generic-health-transition",
        summary="Bounded generic health fact",
    )
    intelligence = InterruptionIntelligence(
        SemanticEventService(InMemoryEventBus()),
        policy,
        TraceService(trace_store, InMemoryEventBus()),
        context_provider=lambda: InterruptionContext.unknown(),
    )
    try:
        initial = policy.enqueue(generic)
        assert initial.decision is AttentionDecision.DEFER
        now[0] += timedelta(hours=2)
        assert len(intelligence.reconcile(InterruptionContext.unknown(revision=2))) == 1
        entry = policy.entry_for(generic.item_id)
        stored = policy.item_for(generic.item_id)
        assert entry is not None and entry.decision is AttentionDecision.DELIVER_NOW
        assert stored is not None
        assert stored.related_task_id is None
        assert stored.related_correlation_id is None
        assert stored.source_semantic_event_id is None
        assert stored.interruption_reason_code is None
        assert entry.delivered_at is None
    finally:
        intelligence.close()
        store.close()
        trace_store.close()


def test_mixed_generic_and_p2c_attention_reconcile_independently(tmp_path: Path) -> None:
    now = [NOW]
    task_id, correlation_id = uuid4(), uuid4()
    store = SQLiteAttentionStore(tmp_path / "attention.sqlite3")
    trace_store = TraceStore(tmp_path / "trace.sqlite3")
    policy = AttentionPolicy(store, clock=lambda: now[0])
    generic = AttentionItem(
        uuid4(),
        "capability.health",
        "default",
        AttentionPriority.NORMAL,
        NOW,
        cooldown_until=NOW + timedelta(hours=1),
        dedupe_key="mixed-generic-health",
        summary="Bounded generic health fact",
    )
    p2c = AttentionItem(
        uuid4(),
        "interruption.task_waiting_for_user",
        "default",
        AttentionPriority.LOW,
        NOW,
        dedupe_key="mixed-p2c-queue",
        summary="Bounded interruption fact",
        interruption_class=InterruptionClass.QUEUE,
        related_task_id=task_id,
        related_correlation_id=correlation_id,
        source_semantic_event_id=uuid4(),
        interruption_reason_code=InterruptionReason.TASK_WAITING_FOR_USER.value,
    )
    trace = TraceService(trace_store, InMemoryEventBus())
    intelligence = InterruptionIntelligence(
        SemanticEventService(InMemoryEventBus()),
        policy,
        trace,
        context_provider=lambda: _context(),
    )
    try:
        assert policy.enqueue(generic).decision is AttentionDecision.DEFER
        assert policy.enqueue(p2c, context=_context()).decision is AttentionDecision.DEFER
        trace.record(
            TraceEventType.ATTENTION,
            "Attention decision recorded",
            task_id=task_id,
            correlation_id=correlation_id,
            result={"attention_item_id": str(p2c.item_id), "attention_decision": "defer"},
        )
        now[0] += timedelta(hours=2)
        transitions = intelligence.reconcile(_context(revision=2))
        assert {transition.item_id for transition in transitions} == {
            generic.item_id,
            p2c.item_id,
        }
        generic_entry = policy.entry_for(generic.item_id)
        p2c_entry = policy.entry_for(p2c.item_id)
        assert generic_entry is not None and generic_entry.decision is AttentionDecision.DELIVER_NOW
        assert p2c_entry is not None and p2c_entry.decision is AttentionDecision.DELIVER_NOW
        assert generic_entry.delivered_at is None and p2c_entry.delivered_at is None
        events = trace.get(task_id=task_id).events
        reevaluations = tuple(
            event
            for event in events
            if event.event_type is TraceEventType.ATTENTION
            and isinstance(event.result, Mapping)
            and event.result.get("reevaluation_reason") == "context_reevaluation"
        )
        assert len(reevaluations) == 1
        result = reevaluations[0].result
        assert isinstance(result, Mapping)
        assert result["attention_item_id"] == str(p2c.item_id)
    finally:
        intelligence.close()
        store.close()
        trace_store.close()


def test_policy_decision_is_not_delivery_acknowledgement() -> None:
    policy = AttentionPolicy(InMemoryAttentionStore(), clock=lambda: NOW)
    item = _item(InterruptionClass.URGENT)
    entry = policy.enqueue(item, context=_context(dnd=True))
    assert entry.decision is AttentionDecision.DELIVER_NOW
    assert entry.delivered_at is None
    queued_item = policy.item_for(item.item_id)
    assert queued_item is not None
    assert queued_item.delivery_state is AttentionDeliveryState.QUEUED
    delivered = policy.mark_delivered(item.item_id)
    assert delivered.delivery_state is AttentionDeliveryState.DELIVERED
    assert policy.entry_for(item.item_id).delivered_at == NOW  # type: ignore[union-attr]


def test_semantic_observer_dedupes_repeated_failure_and_resolves_recovery(tmp_path: Path) -> None:
    attention = SQLiteAttentionStore(tmp_path / "attention.sqlite3")
    trace_store = TraceStore(tmp_path / "trace.sqlite3")
    bus = InMemoryEventBus()
    semantic = SemanticEventService(bus)
    policy = AttentionPolicy(attention, clock=lambda: NOW)
    trace = TraceService(trace_store, bus)
    intelligence = InterruptionIntelligence(semantic, policy, trace, lambda: _context())
    task_id = uuid4()
    try:
        first = _event(EventType.TOOL_FAILED, ToolFailed("tool", "bounded"), task_id=task_id)
        second = _event(
            EventType.TOOL_FAILED,
            ToolFailed("tool", "bounded"),
            sequence=2,
            task_id=task_id,
        )
        semantic.process(first)
        semantic.process(first)
        semantic.process(second)
        unresolved = tuple(item for item in attention.list_items() if not item.resolved)
        assert len(unresolved) == 1
        assert unresolved[0].interruption_class is InterruptionClass.IMPORTANT
        runtime_correlation = uuid4()
        degraded = semantic.process(
            _event(
                EventType.RUNTIME_STATE_CHANGED,
                RuntimeStateChanged("degraded"),
                sequence=3,
                correlation_id=runtime_correlation,
            )
        )[0]
        assert degraded
        recovered = semantic.process(
            _event(
                EventType.RUNTIME_STATE_CHANGED,
                RuntimeStateChanged("ready"),
                sequence=4,
                correlation_id=runtime_correlation,
            )
        )[0]
        assert recovered
        assert any(
            item.resolved and item.interruption_class is InterruptionClass.IMPORTANT
            for item in attention.list_items()
        )
        assert any(
            event.event_type is TraceEventType.ATTENTION
            for event in trace.get(task_id=task_id).events
        )
        assert all(
            "bounded" not in str(event.to_dict()) for event in trace.get(task_id=task_id).events
        )
    finally:
        intelligence.close()
        attention.close()
        trace_store.close()


def test_trusted_security_signal_is_the_only_controlled_urgent_escalation(tmp_path: Path) -> None:
    semantic = SemanticEventService(InMemoryEventBus())
    policy = AttentionPolicy(InMemoryAttentionStore(), clock=lambda: NOW)
    trace_store = TraceStore(tmp_path / "trace.sqlite3")
    trace = TraceService(trace_store, InMemoryEventBus())
    intelligence = InterruptionIntelligence(semantic, policy, trace, lambda: _context(dnd=True))
    try:
        observation = semantic.process(
            _event(
                EventType.PERMISSION_REQUESTED,
                PermissionRequested(uuid4(), "filesystem", "high"),
            )
        )[0]
        result = intelligence.process_semantic(
            replace(observation, semantic_event_id=uuid4()),
            trusted_security_boundary_violation=True,
        )
        assert result.interruption.interruption_class is InterruptionClass.URGENT
        assert result.interruption.reason_code is InterruptionReason.SECURITY_BOUNDARY_VIOLATION
        assert result.attention_decision is AttentionDecision.DELIVER_NOW
        assert result.attention_item_id is not None
    finally:
        intelligence.close()
        trace_store.close()


def test_rule_registry_does_not_use_display_language(tmp_path: Path) -> None:
    semantic = SemanticEventService(InMemoryEventBus())
    policy = AttentionPolicy(InMemoryAttentionStore(), clock=lambda: NOW)
    trace_store = TraceStore(tmp_path / "trace.sqlite3")
    trace = TraceService(trace_store, InMemoryEventBus())
    intelligence = InterruptionIntelligence(semantic, policy, trace, lambda: _context())
    try:
        event = semantic.process(
            _event(EventType.STEP_COMPLETED, StepCompleted(uuid4(), "urgent emergency"))
        )[0]
        decision = InterruptionRuleRegistry().classify(event)
        assert decision.interruption_class is InterruptionClass.SILENT
        assert decision.reason_code is InterruptionReason.EXECUTION_SUCCEEDED
    finally:
        intelligence.close()
        trace_store.close()


@pytest.mark.asyncio
async def test_replayed_semantic_observation_reuses_attention_and_trace(tmp_path: Path) -> None:
    attention_path = tmp_path / "attention.sqlite3"
    trace_path = tmp_path / "trace.sqlite3"
    raw = _event(
        EventType.PERMISSION_REQUESTED,
        PermissionRequested(uuid4(), "filesystem", "high"),
    )
    semantic = SemanticEventService(InMemoryEventBus())
    attention = SQLiteAttentionStore(attention_path)
    trace_store = TraceStore(trace_path)
    policy = AttentionPolicy(attention, clock=lambda: NOW)
    trace = TraceService(trace_store, InMemoryEventBus())
    first = InterruptionIntelligence(semantic, policy, trace, lambda: _context())
    observation = semantic.process(raw)[0]
    first.close()
    attention.close()
    trace_store.close()

    restarted_attention = SQLiteAttentionStore(attention_path)
    restarted_trace_store = TraceStore(trace_path)
    restarted_semantic = SemanticEventService(InMemoryEventBus())
    restarted_policy = AttentionPolicy(restarted_attention, clock=lambda: NOW)
    restarted_trace = TraceService(restarted_trace_store, InMemoryEventBus())
    restarted = InterruptionIntelligence(
        restarted_semantic, restarted_policy, restarted_trace, lambda: _context()
    )
    try:
        restarted.process_semantic(observation)
        assert (
            len(tuple(item for item in restarted_attention.list_items() if not item.resolved)) == 1
        )
        events = restarted_trace.get(correlation_id=observation.correlation_id).events
        assert (
            len(tuple(event for event in events if event.event_type is TraceEventType.ATTENTION))
            == 1
        )
    finally:
        restarted.close()
        restarted_attention.close()
        restarted_trace_store.close()


@pytest.mark.asyncio
async def test_real_runtime_interruption_flow_and_success_no_spam(tmp_path: Path) -> None:
    runtime = ApplicationRuntime.create(
        Settings(app_data_dir=tmp_path / "jarvis-data", ai_provider="ollama")
    )
    assert runtime.status is RuntimeStatus.READY
    assert runtime.container is not None
    try:
        semantic_start = runtime.container.semantic_start_task
        trace_start = runtime.container.trace_start_task
        assert semantic_start is not None
        assert trace_start is not None
        await asyncio.gather(
            semantic_start,
            trace_start,
        )
        task_id = uuid4()
        await runtime.container.event_bus.publish(
            _event(
                EventType.PERMISSION_REQUESTED,
                PermissionRequested(uuid4(), "filesystem", "high"),
                task_id=task_id,
            )
        )
        await asyncio.sleep(0.05)
        assert runtime.container.semantic_events.events_for_task(task_id)
        assert any(
            item.item_type == "interruption.task_waiting_for_user"
            for item in runtime.container.attention_policy.pending()
        )
        trace = runtime.container.trace_service.get(task_id=task_id)
        assert any(event.event_type is TraceEventType.ATTENTION for event in trace.events)

        task = await runtime.container.task_controller.submit_task("calculate 25% of 800")
        assert task.status.value == "completed"
        assert not any(
            item.item_type == "interruption.execution_succeeded" and not item.resolved
            for item in runtime.container.attention_store.list_items()
        )
    finally:
        await runtime.aclose()
