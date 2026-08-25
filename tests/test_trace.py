"""Tests for factual execution traces and guarded replay preparation."""

from __future__ import annotations

import asyncio
import sqlite3
from datetime import UTC, datetime
from pathlib import Path
from typing import Any
from uuid import UUID, uuid4

import pytest
from jarvis.artifacts import ArtifactClassification, ArtifactReference
from jarvis.effects import EffectTraceRecord
from jarvis.events import (
    ArtifactCreated,
    AutomationStateChanged,
    CapabilityChanged,
    CredentialChanged,
    EffectAttestationRecorded,
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
    StepCompleted,
    StepFailed,
    StepStarted,
    SystemError,
    TaskCreated,
    TaskStateChanged,
    ToolCompleted,
    ToolFailed,
    ToolStarted,
)
from jarvis.planning.models import EffectOutcome
from jarvis.trace import (
    EffectTraceSinkAdapter,
    ExecutionTrace,
    ReplayDisposition,
    ReplayMode,
    ReplayRequest,
    TraceError,
    TraceEvent,
    TraceEventType,
    TraceReplayService,
    TraceService,
    TraceStore,
    TraceUsage,
)

NOW = datetime(2026, 8, 23, 12, tzinfo=UTC)


def event(
    trace_id: UUID,
    event_type: TraceEventType,
    summary: str,
    **kwargs: Any,
) -> TraceEvent:
    return TraceEvent(
        trace_id=trace_id,
        event_type=event_type,
        summary=summary,
        occurred_at=NOW,
        **kwargs,
    )


@pytest.mark.asyncio
async def test_runtime_trace_service_projects_and_reloads_one_goal_task_lineage(
    tmp_path: Path,
) -> None:
    bus = InMemoryEventBus()
    store = TraceStore(tmp_path / "trace.sqlite3")
    service = TraceService(store, bus)
    await service.start()
    goal_id = uuid4()
    task_id = uuid4()
    plan_id = uuid4()
    service.bind_goal_task(goal_id, task_id)
    await bus.publish(
        EventEnvelope.create(
            EventType.TASK_CREATED,
            TaskCreated("synthetic goal with no secret in trace"),
            source="state.machine",
            task_id=task_id,
            correlation_id=task_id,
        )
    )
    await bus.publish(
        EventEnvelope.create(
            EventType.PLAN_CREATED,
            PlanCreated(plan_id, 1),
            source="planning.engine",
            task_id=task_id,
            correlation_id=task_id,
        )
    )
    await asyncio.sleep(0.01)
    trace = service.get(goal_id=goal_id)
    assert trace.trace_id == service.get(task_id=task_id).trace_id
    assert [item.event_type for item in trace.events] == [
        TraceEventType.GOAL,
        TraceEventType.PLAN_REVISION,
    ]
    assert "synthetic goal" not in trace.render_text()
    await service.close()
    await bus.close()
    store.close()

    restarted_store = TraceStore(tmp_path / "trace.sqlite3")
    restarted_bus = InMemoryEventBus()
    restarted = TraceService(restarted_store, restarted_bus)
    assert restarted.get(task_id=task_id).trace_id == trace.trace_id
    assert len(restarted.get(task_id=task_id).events) == 2
    await restarted.close()
    await restarted_bus.close()
    restarted_store.close()


@pytest.mark.asyncio
async def test_runtime_trace_service_projects_all_canonical_event_families(tmp_path: Path) -> None:
    bus = InMemoryEventBus()
    store = TraceStore(tmp_path / "trace.sqlite3")
    service = TraceService(store, bus)
    await service.start()
    task_id = uuid4()
    plan_id, step_id, request_id, artifact_id = (uuid4() for _ in range(4))
    observation_id, attestation_id, credential_id, automation_id = (uuid4() for _ in range(4))
    events = (
        (EventType.TASK_CREATED, TaskCreated("untrusted goal text")),
        (EventType.GOAL_CREATED, GoalCreated("untrusted goal text")),
        (EventType.TASK_STATE_CHANGED, TaskStateChanged("queued", "running", "started")),
        (EventType.PLAN_CREATED, PlanCreated(plan_id, 2)),
        (EventType.PLAN_UPDATED, PlanUpdated(plan_id, 3)),
        (EventType.STEP_STARTED, StepStarted(step_id, "synthetic.tool")),
        (EventType.STEP_COMPLETED, StepCompleted(step_id, "completed")),
        (EventType.STEP_FAILED, StepFailed(step_id, "synthetic.failure")),
        (EventType.PERMISSION_REQUESTED, PermissionRequested(request_id, "network", "medium")),
        (EventType.PERMISSION_GRANTED, PermissionGranted(request_id, "network")),
        (EventType.PERMISSION_DENIED, PermissionDenied(request_id, "expired")),
        (EventType.TOOL_STARTED, ToolStarted("synthetic.tool")),
        (EventType.TOOL_COMPLETED, ToolCompleted("synthetic.tool", "completed")),
        (EventType.TOOL_FAILED, ToolFailed("synthetic.tool", "synthetic.failure")),
        (EventType.ARTIFACT_CREATED, ArtifactCreated(artifact_id, 1, "workspace-a", 12)),
        (EventType.CREDENTIAL_CHANGED, CredentialChanged(credential_id, "active", "created")),
        (
            EventType.EFFECT_ATTESTATION_RECORDED,
            EffectAttestationRecorded(
                observation_id,
                attestation_id,
                "synthetic.integration",
                "1.0.0",
                "CANARY",
                "effect_confirmed",
                allowed=True,
                dispatched=True,
            ),
        ),
        (EventType.HEALTH_CHANGED, HealthChanged("synthetic.integration", "healthy")),
        (EventType.AUTOMATION_STATE_CHANGED, AutomationStateChanged(automation_id, "completed")),
        (EventType.CAPABILITY_CHANGED, CapabilityChanged("synthetic.capability", True)),
        (EventType.INTEGRATION_CHANGED, IntegrationChanged("synthetic.integration", "active")),
        (EventType.SYSTEM_ERROR, SystemError("synthetic.error", "bounded failure")),
        (EventType.TASK_STATE_CHANGED, TaskStateChanged("running", "completed", "verified")),
    )
    for event_type, payload in events:
        await bus.publish(
            EventEnvelope.create(
                event_type,
                payload,
                source="trusted.synthetic.test",
                task_id=task_id,
                correlation_id=task_id,
            )
        )
    await asyncio.sleep(0.02)
    trace = service.get(task_id=task_id)
    event_types = {item.event_type for item in trace.events}
    assert {
        TraceEventType.GOAL,
        TraceEventType.RESULT,
        TraceEventType.PLAN_REVISION,
        TraceEventType.STEP,
        TraceEventType.PERMISSION,
        TraceEventType.CAPABILITY_TOOL,
        TraceEventType.ARTIFACT,
        TraceEventType.CREDENTIAL,
        TraceEventType.EFFECT_ATTESTATION,
        TraceEventType.HEALTH,
        TraceEventType.AUTOMATION,
        TraceEventType.CAPABILITY_ACQUISITION,
        TraceEventType.ERROR,
        TraceEventType.COMPLETION,
    }.issubset(event_types)
    assert all("untrusted goal text" not in item.summary for item in trace.events)
    await service.close()
    await bus.close()
    store.close()


def test_trace_renders_full_execution_facts_without_hidden_reasoning() -> None:
    trace_id = uuid4()
    task_id, plan_id, step_id, request_id = uuid4(), uuid4(), uuid4(), uuid4()
    artifact = ArtifactReference(uuid4(), 2, "workspace-a", "content/opaque")
    trace = ExecutionTrace(trace_id)
    trace.append(event(trace_id, TraceEventType.GOAL, "Goal accepted", task_id=task_id))
    trace.append(
        event(
            trace_id,
            TraceEventType.PLAN_REVISION,
            "Plan revision 3 validated",
            task_id=task_id,
            plan_id=plan_id,
        )
    )
    trace.append(
        event(
            trace_id,
            TraceEventType.CAPABILITY_TOOL,
            "Read capability invoked",
            task_id=task_id,
            plan_id=plan_id,
            step_id=step_id,
            request_id=request_id,
            model="local-model",
            usage=TraceUsage(10, 4, 14, 0.02),
            arguments={"path": "settings.json", "token": "do-not-store"},
            permissions=("filesystem.read",),
            result={"status": "success"},
            artifacts=(artifact,),
            evidence=("file hash observed",),
            duration_seconds=0.25,
        )
    )
    trace.append(
        event(
            trace_id,
            TraceEventType.RETRY,
            "Safe transient retry scheduled",
            task_id=task_id,
            effect_outcome=EffectOutcome.SAFE_TO_RETRY,
        )
    )
    trace.append(
        event(
            trace_id,
            TraceEventType.VERIFICATION,
            "Independent file verification passed",
            task_id=task_id,
            evidence=("hash matched",),
        )
    )
    trace.append(event(trace_id, TraceEventType.COMPLETION, "Task completed", task_id=task_id))

    rendered = trace.render_text()
    assert "goal: Goal accepted" in rendered
    assert "plan_revision: Plan revision 3 validated" in rendered
    assert "model=local-model" in rendered
    assert "usage=14 tokens cost=0.02" in rendered
    assert "permissions=filesystem.read" in rendered
    assert str(artifact.artifact_id) in rendered
    assert "[REDACTED]" in rendered
    assert "do-not-store" not in rendered
    assert "chain of thought" not in rendered.casefold()


def test_trace_rejects_model_as_fact_source_and_hidden_reasoning() -> None:
    trace_id = uuid4()
    with pytest.raises(TraceError, match="Model output"):
        event(trace_id, TraceEventType.RESULT, "The model says done", source="model")
    with pytest.raises(TraceError, match="Hidden reasoning"):
        event(trace_id, TraceEventType.AGENT_EXECUTION, "hidden reasoning: ...")


def test_classification_redacts_sensitive_result() -> None:
    record = event(
        uuid4(),
        TraceEventType.RESULT,
        "Credential operation returned metadata",
        classification=ArtifactClassification.CONFIDENTIAL,
        result={"credential_id": "cred-1", "value": "secret-value"},
    )
    assert record.result == "[REDACTED]"
    assert record.redaction_applied
    assert "secret-value" not in str(record.to_dict())


def test_replay_simulation_has_no_effects_and_safe_replay_never_inherits_approval() -> None:
    trace_id = uuid4()
    safe = event(
        trace_id,
        TraceEventType.CAPABILITY_TOOL,
        "Read-only inspection",
        replay_safe=True,
        permissions=("filesystem.read",),
        approval_ids=(uuid4(),),
    )
    trace = ExecutionTrace(trace_id)
    trace.append(safe)
    service = TraceReplayService()

    simulation = service.prepare(trace, ReplayRequest(trace_id, ReplayMode.SIMULATION))
    assert simulation.disposition is ReplayDisposition.ALLOWED
    assert not simulation.has_side_effects

    replay = service.prepare(trace, ReplayRequest(trace_id, ReplayMode.SAFE_REEXECUTE))
    assert replay.disposition is ReplayDisposition.ALLOWED
    assert replay.fresh_approval_required
    assert replay.inherited_approval_ids == ()


def test_trace_captures_multiple_tools_and_trusted_approval() -> None:
    trace_id = uuid4()
    task_id = uuid4()
    approval_id = uuid4()
    trace = ExecutionTrace(trace_id)
    for tool_name in ("filesystem.read", "screen.read"):
        trace.append(
            event(
                trace_id,
                TraceEventType.CAPABILITY_TOOL,
                f"{tool_name} completed",
                task_id=task_id,
                result={"tool": tool_name, "status": "success"},
            )
        )
    trace.append(
        event(
            trace_id,
            TraceEventType.PERMISSION,
            "Trusted approval consumed for exact action",
            task_id=task_id,
            permissions=("filesystem.write",),
            approval_ids=(approval_id,),
        )
    )
    rendered = trace.render_text()
    assert "filesystem.read completed" in rendered
    assert "screen.read completed" in rendered
    assert str(approval_id) in rendered
    assert "permissions=filesystem.write" in rendered


def test_replay_refuses_unknown_outcome_and_unmarked_external_effect() -> None:
    trace_id = uuid4()
    trace = ExecutionTrace(trace_id)
    unknown = event(
        trace_id,
        TraceEventType.RESULT,
        "Effect result was not observed",
        effect_outcome=EffectOutcome.UNKNOWN_OUTCOME,
        external_effect=True,
    )
    trace.append(unknown)
    service = TraceReplayService()
    request = ReplayRequest(trace_id, ReplayMode.SAFE_REEXECUTE)
    refused = service.prepare(trace, request)
    assert refused.disposition is ReplayDisposition.REFUSED
    assert unknown.event_id in refused.unknown_effect_ids

    reconciled = service.prepare(
        trace,
        ReplayRequest(
            trace_id,
            ReplayMode.SAFE_REEXECUTE,
            reconciled_unknown_event_ids=frozenset({unknown.event_id}),
        ),
    )
    assert reconciled.disposition is ReplayDisposition.REFUSED


def test_replan_from_checkpoint_does_not_replay_external_effect() -> None:
    trace_id = uuid4()
    trace = ExecutionTrace(trace_id)
    checkpoint = event(trace_id, TraceEventType.VERIFICATION, "Checkpoint evidence recorded")
    trace.append(event(trace_id, TraceEventType.GOAL, "Goal"))
    trace.append(checkpoint)
    trace.append(
        event(
            trace_id,
            TraceEventType.CAPABILITY_TOOL,
            "Later write was confirmed",
            external_effect=True,
            effect_outcome=EffectOutcome.EFFECT_CONFIRMED,
        )
    )
    plan = TraceReplayService().prepare(
        trace,
        ReplayRequest(trace_id, ReplayMode.REPLAN_FROM_CHECKPOINT, checkpoint.event_id),
    )
    assert plan.disposition is ReplayDisposition.ALLOWED
    assert not plan.has_side_effects
    assert plan.event_ids == (trace.events[0].event_id, checkpoint.event_id)


def test_trace_store_survives_restart_and_preserves_redaction(tmp_path: Path) -> None:
    path = tmp_path / "trace.sqlite3"
    trace_id = uuid4()
    store = TraceStore(path)
    trace = ExecutionTrace(trace_id, store=store)
    trace.append(
        event(
            trace_id,
            TraceEventType.PERMISSION,
            "Permission requested",
            arguments={"path": "settings.json", "api_key": "secret"},
        )
    )
    store.close()

    restarted = TraceStore(path)
    loaded = restarted.load(trace_id)
    assert len(loaded.events) == 1
    assert loaded.events[0].redaction_applied
    assert "secret" not in loaded.render_text()
    restarted.close()


def test_trace_event_round_trip_and_effect_sink_preserve_facts() -> None:
    trace_id = uuid4()
    request_id, effect_id = uuid4(), uuid4()
    record = event(
        trace_id,
        TraceEventType.CAPABILITY_TOOL,
        "Bounded effect observed",
        request_id=request_id,
        effect_id=effect_id,
        usage=TraceUsage(1, 2, 3, 0.1),
        arguments={"path": "safe.txt"},
        permissions=("filesystem.write",),
        result={"status": "ok"},
        effect_outcome=EffectOutcome.EFFECT_CONFIRMED,
        external_effect=True,
        replay_safe=True,
        approval_ids=(uuid4(),),
        effect_attestation_ids=(uuid4(),),
    )
    restored = TraceEvent.from_dict(record.to_dict())
    assert restored.event_id == record.event_id
    assert restored.effect_outcome is EffectOutcome.EFFECT_CONFIRMED
    assert restored.approval_ids == record.approval_ids

    trace = ExecutionTrace(trace_id)
    sink = EffectTraceSinkAdapter(trace)
    asyncio.run(
        sink.record(
            EffectTraceRecord(
                "compensate.file",
                trace_id,
                request_id,
                effect_id,
                "a" * 64,
                "completed",
                NOW,
            )
        )
    )
    assert trace.events[0].event_type is TraceEventType.CAPABILITY_TOOL
    assert trace.events[0].effect_id == effect_id


def test_trace_rejects_malformed_values_and_replay_requests() -> None:
    with pytest.raises(TraceError):
        TraceUsage(-1)
    with pytest.raises(TraceError):
        TraceUsage(1, 1, 1, float("nan"))
    with pytest.raises(TraceError):
        TraceEvent(uuid4(), TraceEventType.RESULT, "bad", occurred_at=datetime(2026, 1, 1))
    with pytest.raises(TraceError):
        event(uuid4(), TraceEventType.RESULT, "bad", arguments={"x": object()})
    with pytest.raises(TraceError):
        ReplayRequest(uuid4(), ReplayMode.SAFE_REEXECUTE, reconciled_unknown_event_ids={uuid4()})  # type: ignore[arg-type]

    trace = ExecutionTrace(uuid4())
    with pytest.raises(TraceError):
        TraceReplayService().prepare(trace, ReplayRequest(uuid4(), ReplayMode.SIMULATION))
    missing = TraceReplayService().prepare(
        trace,
        ReplayRequest(trace.trace_id, ReplayMode.REPLAN_FROM_CHECKPOINT, uuid4()),
    )
    assert missing.disposition is ReplayDisposition.REFUSED


def test_trace_store_rejects_future_schema_and_duplicate_events(tmp_path: Path) -> None:
    path = tmp_path / "trace.sqlite3"
    trace_id = uuid4()
    store = TraceStore(path)
    first = event(trace_id, TraceEventType.GOAL, "stored")
    store.append(first)
    with pytest.raises(TraceError):
        store.append(first)
    store.close()

    with sqlite3.connect(path) as connection:
        connection.execute("INSERT INTO trace_schema_migrations(version) VALUES (99)")
    with pytest.raises(TraceError, match="future schema"):
        TraceStore(path)
