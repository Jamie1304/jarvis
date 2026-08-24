"""Privacy and integrity tests for installation-specific golden workflows."""

from __future__ import annotations

import json
import sqlite3
from dataclasses import replace
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import cast
from uuid import UUID, uuid4

import pytest
from jarvis.artifacts import ArtifactClassification
from jarvis.planning.models import EffectOutcome
from jarvis.testing.golden import (
    ExpectedResult,
    Fixture,
    GoldenActor,
    GoldenCandidateGate,
    GoldenCandidateKind,
    GoldenChangeKind,
    GoldenGateError,
    GoldenGateResult,
    GoldenRunStatus,
    GoldenUnavailable,
    GoldenWorkflow,
    GoldenWorkflowCandidate,
    GoldenWorkflowClass,
    GoldenWorkflowError,
    GoldenWorkflowService,
    GoldenWorkflowStatus,
    GoldenWorkflowStore,
    RunResult,
    Version,
    sanitize_fixture_data,
)
from jarvis.trace import ExecutionTrace, TraceEvent, TraceEventType
from jarvis.verification import EvidenceRecord, EvidenceType, VerificationLevel

NOW = datetime(2026, 8, 24, 12, tzinfo=UTC)


def expected(*criteria: str) -> ExpectedResult:
    return ExpectedResult(
        "Verify a synthetic semantic result",
        criteria,
        allowed_evidence_types=frozenset({EvidenceType.CUSTOM}),
    )


def fixture(identifier: str = "fixture-1") -> Fixture:
    return Fixture(
        identifier,
        "Synthetic fixture",
        {"expression": "2 + 2", "api_token": "gho_never-store", "user_name": "Jamie"},
        expected("result_observed"),
    )


def workflow(
    identifier: str = "golden-workflow",
    *,
    changes: frozenset[GoldenChangeKind] | None = None,
    workflow_class: GoldenWorkflowClass = GoldenWorkflowClass.DETERMINISTIC,
) -> GoldenWorkflow:
    return GoldenWorkflow(
        identifier,
        "Synthetic important workflow",
        Version(1, 0, 0),
        workflow_class,
        (fixture(),),
        changes or frozenset(GoldenChangeKind),
        provenance=("test:synthetic",),
    )


def evidence(observed: object = "result_observed") -> tuple[EvidenceRecord, ...]:
    return (
        EvidenceRecord(
            EvidenceType.CUSTOM,
            "golden.fake-observer",
            NOW,
            timedelta(minutes=5),
            1.0,
            "result_observed",
            observed,
            level=VerificationLevel.AUTOMATED_TESTED,
        ),
    )


def test_fixture_sanitization_generalizes_personal_and_secret_data() -> None:
    safe = sanitize_fixture_data(
        {
            "api_token": "gho_secret",
            "user_name": "Jamie",
            "email": "jamie@example.com",
            "path": r"C:\Users\Jamie\settings.json",
            "count": 2,
        }
    )

    assert "gho_secret" not in repr(safe)
    assert "Jamie" not in repr(safe)
    assert safe["api_token"] == "<redacted>"  # type: ignore[index]
    assert safe["user_name"] == "<generalized>"  # type: ignore[index]
    assert safe["path"] == "<generalized>"  # type: ignore[index]

    item = fixture()
    assert item.sanitized
    assert "gho_never-store" not in repr(item)
    assert "Jamie" not in repr(item)
    assert item.synthetic


def test_trace_derived_workflow_keeps_only_generalized_event_shape() -> None:
    trace_id = uuid4()
    trace = ExecutionTrace(trace_id)
    trace.append(
        TraceEvent(
            trace_id,
            TraceEventType.CAPABILITY_TOOL,
            "Synthetic tool invocation",
            arguments={"api_token": "gho_secret", "user_name": "Jamie"},
            classification=ArtifactClassification.INTERNAL,
            occurred_at=NOW,
        )
    )
    trace.append(
        TraceEvent(
            trace_id,
            TraceEventType.VERIFICATION,
            "Synthetic verification fact",
            occurred_at=NOW,
        )
    )
    trace.append(
        TraceEvent(
            trace_id,
            TraceEventType.COMPLETION,
            "Synthetic completion fact",
            occurred_at=NOW,
        )
    )

    derived = GoldenWorkflow.from_trace(
        trace,
        workflow_id="trace-derived",
        name="Trace-derived synthetic workflow",
    )

    assert derived.fixtures[0].inputs["event_count"] == 3
    assert derived.fixtures[0].inputs["event_shape"] == (
        "capability_tool",
        "verification",
        "completion",
    )
    assert "gho_secret" not in repr(derived)
    assert "Jamie" not in repr(derived)
    assert derived.fixtures[0].source_trace_digest is not None


@pytest.mark.asyncio
async def test_pass_and_fail_use_verification_engine(tmp_path: Path) -> None:
    store = GoldenWorkflowStore(tmp_path / "golden.sqlite3")
    item = workflow()
    store.register(item)
    service = GoldenWorkflowService(store, clock=lambda: NOW)

    passed = await service.run(item, lambda _workflow, _fixture: evidence())
    failed = await service.run(
        item,
        lambda _workflow, _fixture: evidence("different semantic observation"),
    )

    assert passed[0].status is GoldenRunStatus.PASSED
    assert passed[0].verification is not None and passed[0].verification.passed
    assert failed[0].status is GoldenRunStatus.FAILED
    assert failed[0].verification is not None
    assert failed[0].verification.missing_criteria == ("result_observed",)
    assert len(store.runs(item.workflow_id, item.version)) == 2
    store.close()


@pytest.mark.asyncio
async def test_applicable_gate_runs_all_workflows_and_missing_coverage_fails(
    tmp_path: Path,
) -> None:
    store = GoldenWorkflowStore(tmp_path / "golden.sqlite3")
    model = workflow("model-regression", changes=frozenset({GoldenChangeKind.MODEL_CHANGE}))
    integration = workflow(
        "integration-regression",
        changes=frozenset({GoldenChangeKind.INTEGRATION_UPDATE}),
    )
    improvement = workflow(
        "improvement-regression",
        changes=frozenset({GoldenChangeKind.SELF_IMPROVEMENT}),
    )
    store.register(model)
    store.register(integration)
    store.register(improvement)
    service = GoldenWorkflowService(store, clock=lambda: NOW)

    model_gate = await service.run_applicable(GoldenChangeKind.MODEL_CHANGE, lambda *_: evidence())
    integration_gate = await service.require_before(
        GoldenChangeKind.INTEGRATION_UPDATE, lambda *_: evidence()
    )
    improvement_gate = await service.require_before(
        GoldenChangeKind.SELF_IMPROVEMENT, lambda *_: evidence()
    )
    self_update_gate = await service.run_applicable(
        GoldenChangeKind.SELF_UPDATE, lambda *_: evidence()
    )

    assert model_gate.passed
    assert model_gate.workflow_ids == ("model-regression",)
    assert integration_gate.passed
    assert improvement_gate.passed
    assert not self_update_gate.passed
    assert self_update_gate.runs == ()
    with pytest.raises(GoldenGateError):
        await service.require_before(GoldenChangeKind.SELF_UPDATE, lambda *_: evidence())
    store.close()


@pytest.mark.asyncio
async def test_hardware_unavailable_is_not_claimed_as_pass(tmp_path: Path) -> None:
    store = GoldenWorkflowStore(tmp_path / "golden.sqlite3")
    item = workflow(workflow_class=GoldenWorkflowClass.HARDWARE_REQUIRED)
    store.register(item)
    service = GoldenWorkflowService(store, clock=lambda: NOW)

    async def unavailable(
        _workflow: GoldenWorkflow, _fixture: Fixture
    ) -> tuple[EvidenceRecord, ...]:
        raise GoldenUnavailable

    result = await service.run_applicable(GoldenChangeKind.MODEL_CHANGE, unavailable)

    assert result.runs[0].status is GoldenRunStatus.SKIPPED
    assert not result.passed
    store.close()


def test_candidate_gate_rejects_expected_tampering_and_exclusion(tmp_path: Path) -> None:
    store = GoldenWorkflowStore(tmp_path / "golden.sqlite3")
    original = workflow()
    store.register(original)
    gate = GoldenCandidateGate()

    changed_expectation = replace(
        original,
        fixtures=(replace(original.fixtures[0], expected=expected("different_criterion")),),
    )
    candidate = GoldenWorkflowCandidate(
        "candidate-rebuilt",
        GoldenCandidateKind.REPEATED_SUCCESSFUL_ROUTINE,
        changed_expectation,
        2,
        base_workflow_fingerprint=original.fingerprint,
    )
    with pytest.raises(GoldenGateError, match="weaken or replace"):
        gate.admit(candidate, store)

    with pytest.raises(GoldenWorkflowError):
        GoldenWorkflowCandidate(
            "candidate-rebuilt-too-weak",
            GoldenCandidateKind.REPEATED_SUCCESSFUL_ROUTINE,
            replace(
                original,
                fixtures=(
                    replace(
                        original.fixtures[0],
                        expected=ExpectedResult(
                            "Verify a synthetic semantic result",
                            ("result_observed",),
                            required_level=VerificationLevel.IMPLEMENTED,
                        ),
                    ),
                ),
            ),
            2,
            base_workflow_fingerprint=original.fingerprint,
        )
    with pytest.raises(GoldenWorkflowError):
        GoldenWorkflowCandidate(
            "candidate-excludes",
            GoldenCandidateKind.USER_MARKED_IMPORTANT_WORKFLOW,
            original,
            1,
            excluded_workflow_ids=("other-workflow",),
        )
    with pytest.raises(GoldenWorkflowError):
        GoldenWorkflowCandidate(
            "candidate-regenerates",
            GoldenCandidateKind.CRITICAL_GENERATED_CAPABILITY,
            original,
            1,
            regenerated_expected=True,
        )

    changed = replace(original, name="Changed workflow")
    candidate = GoldenWorkflowCandidate(
        "candidate-changed",
        GoldenCandidateKind.FREQUENT_CAPABILITY_CHAIN,
        changed,
        2,
        base_workflow_fingerprint=original.fingerprint,
    )
    with pytest.raises(GoldenGateError, match="weaken or replace"):
        gate.admit(candidate, store)
    with pytest.raises(PermissionError):
        store.register(changed, actor=GoldenActor.USER)
    store.close()


def test_user_can_inspect_retire_delete_but_candidate_cannot(tmp_path: Path) -> None:
    store = GoldenWorkflowStore(tmp_path / "golden.sqlite3")
    item = workflow()
    store.register(item)

    assert store.inspect(item.workflow_id, item.version).fingerprint == item.fingerprint
    assert len(store.list()) == 1
    with pytest.raises(PermissionError):
        store.retire(item.workflow_id, item.version, actor=GoldenActor.TRUSTED_SYSTEM)
    retired = store.retire(item.workflow_id, item.version, actor=GoldenActor.USER)
    assert retired.status is GoldenWorkflowStatus.RETIRED
    assert store.list() == ()
    assert len(store.list(include_retired=True)) == 1
    with pytest.raises(PermissionError):
        store.delete(item.workflow_id, item.version, actor=GoldenActor.TRUSTED_SYSTEM)
    store.delete(item.workflow_id, item.version, actor=GoldenActor.USER)
    with pytest.raises(KeyError):
        store.inspect(item.workflow_id, item.version)
    store.close()


def test_restart_and_durable_fingerprint_tamper_detection(tmp_path: Path) -> None:
    path = tmp_path / "golden.sqlite3"
    item = workflow()
    first = GoldenWorkflowStore(path)
    first.register(item)
    first.close()

    restarted = GoldenWorkflowStore(path)
    assert restarted.inspect(item.workflow_id, item.version).fingerprint == item.fingerprint
    restarted.close()

    connection = sqlite3.connect(path)
    tampered_definition = replace(item, name="Tampered workflow")
    connection.execute(
        "UPDATE golden_workflows SET definition_json=? WHERE workflow_id=?",
        (json.dumps(tampered_definition.to_dict()), item.workflow_id),
    )
    connection.commit()
    connection.close()
    tampered = GoldenWorkflowStore(path)
    with pytest.raises(GoldenWorkflowError, match="fingerprint"):
        tampered.inspect(item.workflow_id, item.version)
    tampered.close()


def test_trace_cannot_become_golden_when_unknown_or_failed() -> None:
    trace_id = uuid4()
    trace = ExecutionTrace(trace_id)
    trace.append(TraceEvent(trace_id, TraceEventType.ERROR, "Synthetic error", occurred_at=NOW))
    with pytest.raises(GoldenWorkflowError):
        GoldenWorkflow.from_trace(trace, workflow_id="failed-trace", name="Failed trace")


def test_trace_requires_verification_and_rejects_unknown_outcome() -> None:
    completion_only = ExecutionTrace(uuid4())
    completion_only.append(
        TraceEvent(
            completion_only.trace_id,
            TraceEventType.COMPLETION,
            "Synthetic completion fact",
            occurred_at=NOW,
        )
    )
    with pytest.raises(GoldenWorkflowError, match="verification"):
        GoldenWorkflow.from_trace(
            completion_only,
            workflow_id="missing-verification",
            name="Missing verification",
        )

    unknown = ExecutionTrace(uuid4())
    for event_type, outcome in (
        (TraceEventType.VERIFICATION, None),
        (TraceEventType.COMPLETION, EffectOutcome.UNKNOWN_OUTCOME),
    ):
        unknown.append(
            TraceEvent(
                unknown.trace_id,
                event_type,
                "Synthetic trace fact",
                effect_outcome=outcome,
                occurred_at=NOW,
            )
        )
    with pytest.raises(GoldenWorkflowError, match="Unknown outcomes"):
        GoldenWorkflow.from_trace(unknown, workflow_id="unknown-trace", name="Unknown trace")


def test_definition_validation_rejects_malformed_security_metadata() -> None:
    with pytest.raises(GoldenWorkflowError):
        Version(-1, 0, 0)
    with pytest.raises(GoldenWorkflowError):
        Version.parse("1.0")
    with pytest.raises(GoldenWorkflowError):
        ExpectedResult("", ("result_observed",))
    with pytest.raises(GoldenWorkflowError):
        ExpectedResult("goal", ("not safe",))
    with pytest.raises(GoldenWorkflowError):
        ExpectedResult("goal", ("result_observed",), required_level=VerificationLevel.IMPLEMENTED)
    with pytest.raises(GoldenWorkflowError):
        ExpectedResult("goal", ("result_observed",), allowed_evidence_types=frozenset())
    with pytest.raises(GoldenWorkflowError):
        ExpectedResult("goal", ("result_observed",), minimum_confidence=2)
    with pytest.raises(GoldenWorkflowError):
        ExpectedResult("goal", ("result_observed",), max_evidence_age=timedelta(0))
    with pytest.raises(GoldenWorkflowError):
        ExpectedResult("goal", ("result_observed",), independent_observation_required=1)  # type: ignore[arg-type]

    with pytest.raises(GoldenWorkflowError):
        Fixture("bad fixture", "title", {}, expected())
    with pytest.raises(GoldenWorkflowError):
        Fixture("fixture-1", "title", {}, "not expected")  # type: ignore[arg-type]
    with pytest.raises(GoldenWorkflowError):
        Fixture("fixture-1", "title", {}, expected(), synthetic=1)  # type: ignore[arg-type]
    with pytest.raises(GoldenWorkflowError):
        Fixture("fixture-1", "title", {}, expected(), source_trace_digest="bad")

    item = workflow()
    with pytest.raises(GoldenWorkflowError):
        replace(item, fixtures=())
    with pytest.raises(GoldenWorkflowError):
        replace(item, fixtures=(item.fixtures[0], item.fixtures[0]))
    with pytest.raises(GoldenWorkflowError):
        replace(item, applicable_to=frozenset())
    with pytest.raises(GoldenWorkflowError):
        replace(item, provenance=(object(),))  # type: ignore[arg-type]
    with pytest.raises(GoldenWorkflowError):
        replace(item, status="active")  # type: ignore[arg-type]


def test_candidate_and_run_records_reject_tampering() -> None:
    item = workflow()
    with pytest.raises(GoldenWorkflowError):
        GoldenWorkflowCandidate("candidate", "bad", item, 1)  # type: ignore[arg-type]
    with pytest.raises(GoldenWorkflowError):
        GoldenWorkflowCandidate(
            "candidate",
            GoldenCandidateKind.CRITICAL_GENERATED_CAPABILITY,
            cast(GoldenWorkflow, "bad"),
            1,
        )
    with pytest.raises(GoldenWorkflowError):
        GoldenWorkflowCandidate(
            "candidate", GoldenCandidateKind.CRITICAL_GENERATED_CAPABILITY, item, 0
        )
    with pytest.raises(GoldenWorkflowError):
        GoldenWorkflowCandidate(
            "candidate", GoldenCandidateKind.REPEATED_SUCCESSFUL_ROUTINE, item, 1
        )
    with pytest.raises(GoldenWorkflowError):
        GoldenWorkflowCandidate(
            "candidate",
            GoldenCandidateKind.CRITICAL_GENERATED_CAPABILITY,
            item,
            1,
            source_trace_digests=("bad",),
        )
    with pytest.raises(GoldenWorkflowError):
        GoldenWorkflowCandidate(
            "candidate",
            GoldenCandidateKind.CRITICAL_GENERATED_CAPABILITY,
            item,
            1,
            base_workflow_fingerprint="bad",
        )
    with pytest.raises(GoldenWorkflowError):
        GoldenWorkflowCandidate(
            "candidate",
            GoldenCandidateKind.CRITICAL_GENERATED_CAPABILITY,
            item,
            1,
            regenerated_expected=cast(bool, 1),
        )

    with pytest.raises(GoldenWorkflowError):
        RunResult(uuid4(), "workflow", Version(1, 0, 0), "fixture-1", NOW, NOW, "bad", None)  # type: ignore[arg-type]
    with pytest.raises(GoldenWorkflowError):
        RunResult(
            uuid4(),
            "workflow",
            Version(1, 0, 0),
            "fixture-1",
            NOW + timedelta(days=1),
            NOW,
            GoldenRunStatus.FAILED,
            None,
        )
    with pytest.raises(GoldenWorkflowError):
        RunResult(
            uuid4(),
            "workflow",
            Version(1, 0, 0),
            "fixture-1",
            NOW,
            NOW,
            GoldenRunStatus.PASSED,
            None,
        )
    with pytest.raises(GoldenWorkflowError):
        RunResult(
            uuid4(),
            "workflow",
            Version(1, 0, 0),
            "fixture-1",
            NOW,
            NOW,
            GoldenRunStatus.FAILED,
            None,
            trace_id=cast(UUID, "bad"),
        )
    with pytest.raises(GoldenWorkflowError):
        GoldenGateResult("bad", (), (), True, "bad")  # type: ignore[arg-type]
    with pytest.raises(GoldenWorkflowError):
        GoldenGateResult(GoldenChangeKind.MODEL_CHANGE, (), ("bad",), True, "bad")  # type: ignore[arg-type]


def test_store_conflicts_versions_and_run_idempotency(tmp_path: Path) -> None:
    store = GoldenWorkflowStore(tmp_path / "golden.sqlite3")
    first = workflow()
    newer = replace(first, version=Version(2, 0, 0))
    assert store.register(first) is first
    assert store.register(first) == first
    assert store.register(newer) == newer
    assert store.inspect(first.workflow_id).version == newer.version
    with pytest.raises(GoldenWorkflowError, match="fingerprint conflict"):
        store.register(replace(first, name="Conflict"))
    with pytest.raises(KeyError):
        store.inspect("missing")
    with pytest.raises(GoldenWorkflowError):
        store.active_for("bad")  # type: ignore[arg-type]

    result = RunResult(
        uuid4(),
        first.workflow_id,
        first.version,
        "fixture-1",
        NOW,
        NOW,
        GoldenRunStatus.FAILED,
        None,
    )
    store.record_run(result)
    store.record_run(result)
    with pytest.raises(GoldenWorkflowError, match="reused"):
        store.record_run(replace(result, error="different"))
    store.retire(first.workflow_id, first.version, actor=GoldenActor.USER)
    with pytest.raises(GoldenWorkflowError, match="Retired"):
        store.record_run(replace(result, run_id=uuid4()))
    with pytest.raises(GoldenGateError, match="Retired"):
        GoldenCandidateGate().admit(
            GoldenWorkflowCandidate(
                "retired-candidate",
                GoldenCandidateKind.USER_MARKED_IMPORTANT_WORKFLOW,
                store.inspect(first.workflow_id, first.version),
                1,
            ),
            store,
        )
    store.close()


def test_store_refuses_a_future_schema(tmp_path: Path) -> None:
    path = tmp_path / "future.sqlite3"
    connection = sqlite3.connect(path)
    connection.execute("CREATE TABLE golden_schema_migrations(version INTEGER PRIMARY KEY)")
    connection.execute("INSERT INTO golden_schema_migrations(version) VALUES (999)")
    connection.commit()
    connection.close()
    with pytest.raises(GoldenWorkflowError, match="future schema"):
        GoldenWorkflowStore(path)


@pytest.mark.asyncio
async def test_service_cancel_rejects_malformed_executor_and_clock(tmp_path: Path) -> None:
    import asyncio

    store = GoldenWorkflowStore(tmp_path / "golden.sqlite3")
    item = workflow()
    store.register(item)
    service = GoldenWorkflowService(store, clock=lambda: NOW)

    cancellation = asyncio.Event()
    cancellation.set()
    cancelled = await service.run(item, lambda *_: evidence(), cancellation)
    assert cancelled[0].status is GoldenRunStatus.CANCELLED

    malformed = await service.run(
        item,
        lambda *_: "not evidence",  # type: ignore[arg-type]
    )
    raised = await service.run(item, lambda *_: (_ for _ in ()).throw(RuntimeError("fake")))
    assert malformed[0].status is GoldenRunStatus.REJECTED
    assert raised[0].status is GoldenRunStatus.REJECTED

    with pytest.raises(GoldenWorkflowError, match="timezone"):
        await GoldenWorkflowService(store, clock=lambda: datetime(2026, 8, 24, 12)).run(
            item, lambda *_: evidence()
        )
    with pytest.raises(GoldenWorkflowError, match="stale"):
        await service.run(replace(item, name="stale"), lambda *_: evidence())
    store.retire(item.workflow_id, item.version, actor=GoldenActor.USER)
    retired = store.inspect(item.workflow_id, item.version)
    with pytest.raises(GoldenWorkflowError, match="Retired"):
        await service.run(retired, lambda *_: evidence())
    store.close()


def test_fixture_sanitizer_fails_closed_for_oversized_or_unsupported_data() -> None:
    with pytest.raises(GoldenWorkflowError):
        sanitize_fixture_data({1: "bad"})
    with pytest.raises(GoldenWorkflowError):
        sanitize_fixture_data({"value": float("nan")})
    with pytest.raises(GoldenWorkflowError):
        sanitize_fixture_data({"value": "x" * 1_001})
    with pytest.raises(GoldenWorkflowError):
        sanitize_fixture_data({"value": "bad\x00value"})
    with pytest.raises(GoldenWorkflowError):
        sanitize_fixture_data({"value": object()})
    with pytest.raises(GoldenWorkflowError):
        sanitize_fixture_data({"value": {str(index): index for index in range(65)}})
    with pytest.raises(GoldenWorkflowError):
        sanitize_fixture_data({"value": tuple(range(129))})

    deeply_nested: object = "leaf"
    for _ in range(7):
        deeply_nested = {"value": deeply_nested}
    with pytest.raises(GoldenWorkflowError):
        sanitize_fixture_data(deeply_nested)
