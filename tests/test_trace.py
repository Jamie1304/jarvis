"""Tests for factual execution traces and guarded replay preparation."""

from __future__ import annotations

from datetime import UTC, datetime
from pathlib import Path
from typing import Any
from uuid import UUID, uuid4

import pytest
from jarvis.artifacts import ArtifactClassification, ArtifactReference
from jarvis.planning.models import EffectOutcome
from jarvis.trace import (
    ExecutionTrace,
    ReplayDisposition,
    ReplayMode,
    ReplayRequest,
    TraceError,
    TraceEvent,
    TraceEventType,
    TraceReplayService,
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
