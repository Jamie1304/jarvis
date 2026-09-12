"""Deterministic contracts for Phase 19 typed coordination events."""

from __future__ import annotations

import asyncio
import logging
from typing import cast
from uuid import UUID, uuid4

import pytest
from jarvis.events import (
    AutomationStateChanged,
    CameraStateChanged,
    CapabilityChanged,
    EventEnvelope,
    EventType,
    GoalCreated,
    HealthChanged,
    InMemoryEventBus,
    IntegrationChanged,
    PermissionDenied,
    PermissionGranted,
    PermissionRequested,
    PlanCreated,
    PlanUpdated,
    RuntimeStateChanged,
    StepCompleted,
    StepFailed,
    StepStarted,
    SystemError,
    TaskCreated,
    TaskStateChanged,
    ToolCompleted,
    ToolFailed,
    ToolStarted,
    VoiceStateChanged,
)
from jarvis.events.models import EventPayload
from jarvis.state import ApplicationStateMachine
from jarvis.state.models import TaskState, TransitionEvent


def event(
    correlation: UUID | None = None, *, causation: UUID | None = None
) -> EventEnvelope[EventPayload]:
    correlation = correlation or uuid4()
    return cast(
        EventEnvelope[EventPayload],
        EventEnvelope.create(
            EventType.SYSTEM_ERROR,
            SystemError("test", "safe summary"),
            source="tests",
            correlation_id=correlation,
            causation_id=causation,
        ),
    )


@pytest.mark.asyncio
async def test_ordering_and_correlation_metadata() -> None:
    bus = InMemoryEventBus()
    seen: list[EventEnvelope[EventPayload]] = []
    subscription = await bus.subscribe(lambda item: _append(seen, item))
    correlation = uuid4()
    first = event(correlation)
    second = event(correlation, causation=first.event_id)
    await bus.publish(first)
    await bus.publish(second)
    await asyncio.sleep(0)
    await bus.unsubscribe(subscription)
    assert [item.sequence for item in seen] == [1, 2]
    assert seen[1].causation_id == first.event_id
    await bus.close()


async def _append(
    target: list[EventEnvelope[EventPayload]], item: EventEnvelope[EventPayload]
) -> None:
    target.append(item)


@pytest.mark.asyncio
async def test_bounded_queue_drops_oldest_and_failed_subscriber_isolated() -> None:
    bus = InMemoryEventBus(queue_size=1)
    failed = await bus.subscribe(_fail)
    received: list[EventEnvelope[EventPayload]] = []
    good = await bus.subscribe(lambda item: _append(received, item))
    await bus.publish(event())
    await bus.publish(event())
    await asyncio.sleep(0)
    assert received
    await bus.unsubscribe(failed)
    await bus.unsubscribe(good)
    await bus.close()


async def _fail(_item: EventEnvelope[EventPayload]) -> None:
    raise RuntimeError("subscriber failure")


@pytest.mark.asyncio
async def test_correlation_ledger_has_deterministic_lru_cap_and_clears_on_close() -> None:
    bus = InMemoryEventBus(
        max_events_per_correlation=2,
        max_correlation_chains=2,
    )
    await bus.subscribe(_append_noop)
    oldest = uuid4()
    recently_used = uuid4()
    newest = uuid4()

    await bus.publish(event(oldest))
    await bus.publish(event(recently_used))
    await bus.publish(event(oldest))
    await bus.publish(event(newest))

    assert tuple(bus._chain_counts) == (oldest, newest)
    assert await bus.publish(event(oldest)) is False
    assert await bus.publish(event(recently_used)) is True
    assert tuple(bus._chain_counts) == (oldest, recently_used)

    await bus.close()
    assert not bus._chain_counts


@pytest.mark.parametrize("value", [0, -1, True, 1.5, "2"])
def test_correlation_ledger_cap_must_be_a_positive_integer(value: object) -> None:
    with pytest.raises(ValueError, match="max_correlation_chains"):
        InMemoryEventBus(max_correlation_chains=value)  # type: ignore[arg-type]


@pytest.mark.asyncio
async def test_subscriber_failure_log_does_not_disclose_exception(
    caplog: pytest.LogCaptureFixture,
) -> None:
    secret = "Bearer subscriber-secret-value"

    async def fail_with_secret(_item: EventEnvelope[EventPayload]) -> None:
        raise RuntimeError(secret)

    caplog.set_level(logging.ERROR, logger="jarvis.events")
    bus = InMemoryEventBus()
    subscription = await bus.subscribe(fail_with_secret)
    await bus.publish(event())
    await asyncio.sleep(0.02)

    assert "event subscriber failed" in caplog.text
    assert secret not in caplog.text
    assert "RuntimeError" not in caplog.text

    await bus.unsubscribe(subscription)
    await bus.close()


@pytest.mark.asyncio
async def test_unsubscribe_shutdown_and_publish_after_close() -> None:
    bus = InMemoryEventBus()
    subscription = await bus.subscribe(_append_noop)
    await bus.unsubscribe(subscription)
    await bus.close()
    assert await bus.publish(event()) is False
    with pytest.raises(RuntimeError):
        await bus.subscribe(_append_noop)


async def _append_noop(_item: EventEnvelope[EventPayload]) -> None:
    return None


@pytest.mark.asyncio
async def test_cancellation_and_feedback_storm_are_bounded() -> None:
    bus = InMemoryEventBus(max_events_per_correlation=2)
    correlation = uuid4()
    accepted: list[EventEnvelope[EventPayload]] = []

    async def recursive(item: EventEnvelope[EventPayload]) -> None:
        accepted.append(item)
        await bus.publish(event(correlation, causation=item.event_id))

    subscription = await bus.subscribe(recursive)
    await bus.publish(event(correlation))
    await asyncio.sleep(0.02)
    assert len(accepted) == 2
    await bus.unsubscribe(subscription)
    await bus.close()


def test_payloads_are_typed_and_do_not_contain_sensitive_arguments() -> None:
    payload = TaskStateChanged("planning", "executing", "step started")
    envelope = EventEnvelope.create(
        EventType.TASK_STATE_CHANGED,
        payload,
        source="state.machine",
        correlation_id=uuid4(),
    )
    assert envelope.payload.reason == "step started"
    assert not hasattr(envelope.payload, "arguments")
    with pytest.raises(ValueError):
        SystemError("secret", "x" * 300)


def test_all_payload_contracts_are_bounded_and_typed() -> None:
    identifier = uuid4()
    assert TaskCreated("goal").goal == "goal"
    assert GoalCreated("goal").goal == "goal"
    assert TaskStateChanged("a", "b", "reason").to_state == "b"
    assert PlanCreated(identifier, 2).step_count == 2
    assert PlanUpdated(identifier, 3).revision == 3
    assert StepStarted(identifier, "tool").tool_id == "tool"
    assert StepCompleted(identifier, "ok").outcome == "ok"
    assert StepFailed(identifier, "failed").error_code == "failed"
    assert PermissionRequested(identifier, "camera.read", "high").permission == "camera.read"
    assert PermissionGranted(identifier, "camera.read").request_id == identifier
    assert PermissionDenied(None, "denied").request_id is None
    assert ToolStarted("tool").tool_id == "tool"
    assert ToolCompleted("tool", "succeeded").status == "succeeded"
    assert ToolFailed("tool", "failed").error_code == "failed"
    assert CameraStateChanged("camera-1", "active").state == "active"
    assert VoiceStateChanged("listening").state == "listening"
    assert CapabilityChanged("camera.capture", True).available
    assert IntegrationChanged("local-model", "available").state == "available"
    assert RuntimeStateChanged("ready").state == "ready"
    assert HealthChanged("runtime", "healthy").status == "healthy"
    assert AutomationStateChanged(identifier, "idle").state == "idle"


@pytest.mark.asyncio
async def test_metrics_and_no_subscriber_publish() -> None:
    class Metrics:
        def __init__(self) -> None:
            self.names: list[str] = []

        def record(self, name: str, value: int = 1) -> None:
            self.names.extend([name] * value)

    metrics = Metrics()
    bus = InMemoryEventBus(metrics=metrics)
    assert await bus.publish(event()) is False
    assert "events.published" in metrics.names
    await bus.close()


@pytest.mark.asyncio
async def test_state_machine_emits_observations_without_changing_authority() -> None:
    bus = InMemoryEventBus()
    seen: list[EventEnvelope[EventPayload]] = []
    subscription = await bus.subscribe(lambda item: _append(seen, item))
    machine = ApplicationStateMachine(event_bus=bus)
    task_id = uuid4()
    machine.create_task(task_id)
    machine.transition_task(
        task_id,
        TaskState.THINKING,
        TransitionEvent.TASK_THINKING,
        reason="planning",
    )
    await asyncio.sleep(0.02)
    assert [item.event_type for item in seen] == [
        EventType.TASK_CREATED,
        EventType.TASK_STATE_CHANGED,
        EventType.TASK_STATE_CHANGED,
    ]
    assert machine.task(task_id) is not None
    await bus.unsubscribe(subscription)
    await bus.close()


def test_payload_rejects_invalid_identifiers_and_envelope_metadata() -> None:
    identifier = uuid4()
    with pytest.raises(ValueError):
        PlanCreated("not-a-uuid", 1)  # type: ignore[arg-type]
    with pytest.raises(ValueError):
        PlanUpdated(identifier, -1)
    with pytest.raises(ValueError):
        StepStarted(identifier, "")
    with pytest.raises(ValueError):
        PermissionRequested(identifier, "", "high")
    with pytest.raises(ValueError):
        EventEnvelope(
            identifier,
            2,
            EventType.SYSTEM_ERROR,
            __import__("datetime").datetime.now(),
            "tests",
            None,
            identifier,
            None,
            SystemError("code", "summary"),
        )
    with pytest.raises(ValueError):
        EventEnvelope(
            identifier,
            True,
            EventType.SYSTEM_ERROR,
            __import__("datetime").datetime.now(__import__("datetime").UTC),
            "tests",
            None,
            identifier,
            None,
            SystemError("code", "summary"),
        )
    with pytest.raises(ValueError):
        EventEnvelope(
            identifier,
            1,
            EventType.SYSTEM_ERROR,
            "not-a-timestamp",  # type: ignore[arg-type]
            "tests",
            None,
            identifier,
            None,
            SystemError("code", "summary"),
        )
    with pytest.raises(ValueError, match="metadata/payload"):
        EventEnvelope.create(
            EventType.TOOL_STARTED,
            SystemError("code", "summary"),
            source="tests",
            correlation_id=identifier,
        )
