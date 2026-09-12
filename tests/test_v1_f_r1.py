from __future__ import annotations

import sqlite3
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, cast

import pytest
from jarvis.capability_health import CapabilityHealthService, HealthStatus
from jarvis.component_doctor import (
    ComponentDoctor,
    ComponentProblem,
    DiagnosticOwner,
    DiagnosticProbe,
    DiagnosticProbeResult,
    DoctorStatus,
    FailureSignature,
    FallbackOption,
    RepairAction,
    RepairCaseStatus,
    RepairEffectOutcome,
    RepairExecution,
    RepairPlaybook,
)
from jarvis.core.config import Settings
from jarvis.permissions.models import ApprovalActorKind, ApprovalChoice, ApprovalIdentity
from jarvis.repair_state import (
    RepairAttemptRecord,
    RepairCase,
    RepairStoreError,
    SQLiteRepairStore,
    repair_case_key,
)
from jarvis.runtime import ApplicationRuntime, RuntimeStatus
from jarvis.verification import VerificationDisposition, VerificationLevel, VerificationResult
from jarvis.workflows import ProcedureEvidenceAuthority, WorkflowTemplateError

NOW = datetime(2026, 9, 12, tzinfo=UTC)


def _mark_int(values: list[int], value: int) -> int:
    values.append(value)
    return value


def _mark_str(values: list[str], value: str) -> str:
    values.append(value)
    return value


def _problem(observation_id: str | None = "observation-1") -> ComponentProblem:
    return ComponentProblem(
        "r1.component",
        "synthetic failure",
        DiagnosticOwner.CAPABILITY,
        failure_code="synthetic.failure",
        source="health",
        failure_observation_id=observation_id,
        occurred_at=NOW,
    )


def _playbook(*, fallbacks: tuple[str, ...] = ()) -> RepairPlaybook:
    return RepairPlaybook(
        "r1.playbook",
        "r1.component",
        DiagnosticOwner.CAPABILITY,
        (FailureSignature("synthetic.failure", "synthetic failure"),),
        (DiagnosticProbe("state", "Read state"),),
        (RepairAction("repair", "Repair state"),),
        fallbacks,
    )


def _doctor(path: Path, *, authorize: object, max_attempts: int = 1) -> ComponentDoctor:
    health = CapabilityHealthService(clock=lambda: NOW)
    doctor = ComponentDoctor(
        health,
        repair_store=SQLiteRepairStore(path),
        authorize=cast(Any, authorize),
        clock=lambda: NOW,
        max_attempts=max_attempts,
    )
    doctor.register_playbook(_playbook())
    doctor.register_probe(
        "r1.component",
        "state",
        lambda _problem: DiagnosticProbeResult("state", True, "state", checked_at=NOW),
    )
    return doctor


def _durable_terminal_case(
    path: Path,
    status: RepairCaseStatus,
    outcome: str,
    state: str,
    *,
    selected_action: str | None = "repair",
    verification_reference: str | None = "probe:state",
) -> tuple[SQLiteRepairStore, RepairCase]:
    store = SQLiteRepairStore(path)
    case, created = store.open_case(
        component_id="r1.component",
        owner="capability",
        failure_code="synthetic.failure",
        component_version=None,
        attempt_budget=2,
        now=NOW,
        failure_observation_id="durable-observation",
    )
    assert created
    case = store.update(
        case,
        status=status,
        attempt_count=1,
        selected_action=selected_action,
        effect_outcome=outcome,
        verification_reference=verification_reference,
        terminal_reason="terminal",
    )
    store.save_attempt(
        RepairAttemptRecord(
            case.case_id,
            1,
            state,
            outcome,
            "terminal attempt",
            NOW,
            NOW,
            verification_reference,
        )
    )
    return store, case


@pytest.mark.asyncio
async def test_generic_effect_exception_is_unknown_and_not_retried(tmp_path: Path) -> None:
    calls: list[int] = []
    doctor = _doctor(tmp_path / "repair.sqlite3", authorize=lambda _p, _a: True, max_attempts=3)
    doctor.register_action(
        "r1.component",
        "repair",
        lambda _problem, _action: (
            _mark_int(calls, 1),
            (_ for _ in ()).throw(RuntimeError("lost receipt")),
        )[1],
    )

    first = await doctor.run(_problem())
    second = await doctor.run(_problem())

    assert first.status is DoctorStatus.QUARANTINED
    assert second.status is DoctorStatus.QUARANTINED
    assert len(calls) == 1
    assert first.case_id == second.case_id
    assert first.case_id is not None
    repair_store = doctor.repair_store
    assert repair_store is not None
    stored = repair_store.load(first.case_id)
    assert stored is not None and stored.status is RepairCaseStatus.QUARANTINED
    assert doctor._health.health("r1.component").status is HealthStatus.QUARANTINED  # noqa: SLF001
    doctor.close()


@pytest.mark.asyncio
async def test_permission_required_resumes_same_case_after_current_approval(tmp_path: Path) -> None:
    allowed = [False]
    calls: list[int] = []
    doctor = _doctor(
        tmp_path / "permission.sqlite3",
        authorize=lambda _p, _a: allowed[0],
    )
    doctor.register_action(
        "r1.component",
        "repair",
        lambda _problem, _action: (
            _mark_int(calls, 1),
            RepairExecution(RepairEffectOutcome.EFFECT_CONFIRMED, True, "done"),
        )[1],
    )

    first = await doctor.run(_problem())
    allowed[0] = True
    second = await doctor.run(_problem())

    assert first.status is DoctorStatus.PERMISSION_REQUIRED
    assert second.status is DoctorStatus.REPAIRED
    assert first.case_id == second.case_id
    assert calls == [1]
    doctor.close()


@pytest.mark.asyncio
async def test_verification_pending_restart_never_replays_effect(tmp_path: Path) -> None:
    path = tmp_path / "verification.sqlite3"
    state = [False]
    calls: list[int] = []
    first_store = SQLiteRepairStore(path)
    first = ComponentDoctor(
        CapabilityHealthService(clock=lambda: NOW),
        repair_store=first_store,
        authorize=lambda _p, _a: True,
        verifier=lambda _p, _a, _e: (_ for _ in ()).throw(KeyboardInterrupt()),
        clock=lambda: NOW,
    )
    first.register_playbook(_playbook())
    first.register_probe(
        "r1.component", "state", lambda _p: DiagnosticProbeResult("state", state[0], "state")
    )
    first.register_action(
        "r1.component",
        "repair",
        lambda _p, _a: (
            _mark_int(calls, 1),
            state.__setitem__(0, True),
            RepairExecution(RepairEffectOutcome.EFFECT_CONFIRMED, True, "done"),
        )[2],
    )
    with pytest.raises(KeyboardInterrupt):
        await first.run(_problem())
    case = first_store.latest(repair_case_key("r1.component", "capability", "synthetic.failure"))
    assert case is not None and case.status is RepairCaseStatus.VERIFICATION_PENDING
    first.close()

    second_store = SQLiteRepairStore(path)
    second = ComponentDoctor(
        CapabilityHealthService(clock=lambda: NOW),
        repair_store=second_store,
        clock=lambda: NOW,
    )
    second.register_playbook(_playbook())
    second.register_probe(
        "r1.component", "state", lambda _p: DiagnosticProbeResult("state", state[0], "state")
    )
    second.register_action(
        "r1.component",
        "repair",
        lambda _p, _a: RepairExecution(RepairEffectOutcome.EFFECT_CONFIRMED, True, "not invoked"),
    )
    result = await second.run(_problem())

    assert result.status is DoctorStatus.REPAIRED
    assert calls == [1]
    second.close()


@pytest.mark.asyncio
async def test_verification_pending_without_action_quarantines(tmp_path: Path) -> None:
    store = SQLiteRepairStore(tmp_path / "missing-action.sqlite3")
    case, created = store.open_case(
        component_id="r1.component",
        owner="capability",
        failure_code="synthetic.failure",
        component_version=None,
        attempt_budget=2,
        now=NOW,
        failure_observation_id="missing-action-observation",
    )
    assert created
    store.update(case, status=RepairCaseStatus.VERIFICATION_PENDING, attempt_count=1)
    doctor = ComponentDoctor(
        CapabilityHealthService(clock=lambda: NOW),
        repair_store=store,
        clock=lambda: NOW,
    )
    doctor.register_playbook(_playbook())

    result = await doctor.run(_problem("missing-action-observation"))

    assert result.status is DoctorStatus.QUARANTINED
    stored = store.load(case.case_id)
    assert stored is not None and stored.status is RepairCaseStatus.QUARANTINED
    doctor.close()


@pytest.mark.asyncio
async def test_verification_pending_failed_observation_closes_as_failed(tmp_path: Path) -> None:
    path = tmp_path / "failed-verification.sqlite3"
    state = [False]
    first_store = SQLiteRepairStore(path)
    first = ComponentDoctor(
        CapabilityHealthService(clock=lambda: NOW),
        repair_store=first_store,
        authorize=lambda _problem, _action: True,
        verifier=lambda _problem, _action, _execution: (_ for _ in ()).throw(KeyboardInterrupt()),
        clock=lambda: NOW,
    )
    first.register_playbook(_playbook())
    first.register_probe(
        "r1.component", "state", lambda _problem: DiagnosticProbeResult("state", state[0], "state")
    )
    first.register_action(
        "r1.component",
        "repair",
        lambda _problem, _action: (
            state.__setitem__(0, True),
            RepairExecution(RepairEffectOutcome.EFFECT_CONFIRMED, True, "done"),
        )[1],
    )
    with pytest.raises(KeyboardInterrupt):
        await first.run(_problem("failed-verification-observation"))
    pending = first_store.latest(repair_case_key("r1.component", "capability", "synthetic.failure"))
    assert pending is not None and pending.status is RepairCaseStatus.VERIFICATION_PENDING
    first.close()

    second_store = SQLiteRepairStore(path)
    second = ComponentDoctor(
        CapabilityHealthService(clock=lambda: NOW),
        repair_store=second_store,
        verifier=lambda _problem, _action, _execution: VerificationResult(
            "failed repair verification",
            VerificationLevel.AUTOMATED_TESTED,
            False,
            VerificationDisposition.COMPLETE,
        ),
        clock=lambda: NOW,
    )
    second.register_playbook(_playbook())
    result = await second.run(_problem("failed-verification-observation"))

    assert result.status is DoctorStatus.FAILED
    stored = second_store.load(pending.case_id)
    assert stored is not None and stored.status is RepairCaseStatus.FAILED
    second.close()


@pytest.mark.asyncio
async def test_effectful_fallback_lost_receipt_quarantines_without_next_fallback(
    tmp_path: Path,
) -> None:
    calls: list[str] = []
    doctor = ComponentDoctor(
        CapabilityHealthService(clock=lambda: NOW),
        repair_store=SQLiteRepairStore(tmp_path / "fallback.sqlite3"),
        authorize=lambda _p, _a: True,
        clock=lambda: NOW,
    )
    doctor.register_playbook(_playbook(fallbacks=("lost", "next")))
    doctor.register_action(
        "r1.component",
        "repair",
        lambda _p, _a: RepairExecution(
            RepairEffectOutcome.PRE_EFFECT_FAILURE, False, "before effect"
        ),
    )
    doctor.register_fallback(
        "r1.component",
        FallbackOption("lost", "Lost receipt fallback"),
        lambda _p: (_mark_str(calls, "lost"), (_ for _ in ()).throw(RuntimeError("lost")))[1],
    )
    doctor.register_fallback(
        "r1.component",
        FallbackOption("next", "Never reached"),
        lambda _p: (
            _mark_str(calls, "next"),
            RepairExecution(RepairEffectOutcome.EFFECT_CONFIRMED, True, "bad"),
        )[1],
    )

    result = await doctor.run(_problem())

    assert result.status is DoctorStatus.QUARANTINED
    assert calls == ["lost"]
    doctor.close()


@pytest.mark.asyncio
async def test_terminal_redelivery_needs_new_trusted_observation(tmp_path: Path) -> None:
    calls: list[int] = []
    doctor = _doctor(tmp_path / "identity.sqlite3", authorize=lambda _p, _a: True)
    doctor.register_action(
        "r1.component",
        "repair",
        lambda _p, _a: (
            _mark_int(calls, 1),
            RepairExecution(RepairEffectOutcome.PRE_EFFECT_FAILURE, False, "before effect"),
        )[1],
    )

    first = await doctor.run(_problem("obs-1"))
    replay = await doctor.run(_problem("obs-1"))
    fresh = await doctor.run(_problem("obs-2"))

    assert first.status is DoctorStatus.FAILED
    assert replay.case_id == first.case_id
    assert fresh.case_id != first.case_id
    assert calls == [1, 1]
    doctor.close()


def test_reliability_cannot_be_minted_from_caller_supplied_identity() -> None:
    authority = ProcedureEvidenceAuthority(cast(Any, object()))
    with pytest.raises(WorkflowTemplateError, match="durable canonical repair evidence"):
        authority.issue_reliability(
            "arbitrary.method",
            "arbitrary-verification",
            cast(Any, RepairEffectOutcome.EFFECT_CONFIRMED),
        )


def test_reliability_authority_accepts_only_canonical_terminal_records(tmp_path: Path) -> None:
    authority = ProcedureEvidenceAuthority(cast(Any, object()))
    store, case = _durable_terminal_case(
        tmp_path / "verified.sqlite3",
        RepairCaseStatus.VERIFIED_REPAIRED,
        "effect_confirmed",
        "verified",
    )
    evidence = authority.issue_reliability_from_repair(
        store,
        case.case_id,
        method_key="repair:r1.component:repair",
        compatibility_key="r1-compatible",
    )
    assert evidence.verification_id == f"repair:{case.case_id}:1"
    assert authority.validate_reliability(evidence)
    store.close()

    failed_store, failed = _durable_terminal_case(
        tmp_path / "failed.sqlite3",
        RepairCaseStatus.FAILED,
        "pre_effect_failure",
        "failed",
        verification_reference=None,
    )
    failed_evidence = authority.issue_reliability_from_repair(failed_store, failed.case_id)
    assert failed_evidence.outcome.value == "pre_effect_failure"
    failed_store.close()

    unknown_store, unknown = _durable_terminal_case(
        tmp_path / "unknown.sqlite3",
        RepairCaseStatus.QUARANTINED,
        "unknown_outcome",
        "quarantined",
        selected_action=None,
        verification_reference=None,
    )
    unknown_evidence = authority.issue_reliability_from_repair(unknown_store, unknown.case_id)
    assert unknown_evidence.outcome.value == "unknown_outcome"
    unknown_store.close()


def test_reliability_authority_rejects_noncanonical_or_nonterminal_records(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    authority = ProcedureEvidenceAuthority(cast(Any, object()))
    store = SQLiteRepairStore(tmp_path / "pending.sqlite3")
    pending, _ = store.open_case(
        component_id="r1.component",
        owner="capability",
        failure_code="synthetic.failure",
        component_version=None,
        attempt_budget=2,
        now=NOW,
    )
    with pytest.raises(WorkflowTemplateError, match="terminal"):
        authority.issue_reliability_from_repair(store, pending.case_id)
    with pytest.raises(WorkflowTemplateError, match="malformed"):
        authority.issue_reliability_from_repair(store, cast(Any, object()))
    store.close()

    def expect_invalid(
        name: str,
        message: str,
        status: RepairCaseStatus,
        outcome: str,
        state: str,
        *,
        selected_action: str | None = "repair",
        verification_reference: str | None = "probe:state",
        attempt_outcome: str | None = None,
    ) -> None:
        invalid_store, invalid_case = _durable_terminal_case(
            tmp_path / f"{name}.sqlite3",
            status,
            outcome,
            state,
            selected_action=selected_action,
            verification_reference=verification_reference,
        )
        if attempt_outcome is not None:
            invalid_store.save_attempt(
                RepairAttemptRecord(
                    invalid_case.case_id,
                    1,
                    state,
                    attempt_outcome,
                    "rewritten terminal attempt",
                    NOW,
                    NOW,
                )
            )
        with pytest.raises(WorkflowTemplateError, match=message):
            authority.issue_reliability_from_repair(invalid_store, invalid_case.case_id)
        invalid_store.close()

    expect_invalid(
        "wrong-effect",
        "Successful repair lacks a confirmed durable effect",
        RepairCaseStatus.VERIFIED_REPAIRED,
        "effect_unknown",
        "verified",
    )
    expect_invalid(
        "missing-action",
        "Successful repair lacks a canonical action",
        RepairCaseStatus.VERIFIED_REPAIRED,
        "effect_confirmed",
        "verified",
        selected_action=None,
    )
    expect_invalid(
        "missing-verification",
        "Verified repair lacks durable verification reference",
        RepairCaseStatus.VERIFIED_REPAIRED,
        "effect_confirmed",
        "verified",
        verification_reference=None,
    )
    expect_invalid(
        "bad-attempt",
        "Successful repair lacks a terminal verified attempt",
        RepairCaseStatus.VERIFIED_REPAIRED,
        "effect_confirmed",
        "applying",
    )
    expect_invalid(
        "quarantine-effect",
        "Quarantined repair lacks an unknown durable outcome",
        RepairCaseStatus.QUARANTINED,
        "effect_confirmed",
        "verified",
    )
    expect_invalid(
        "quarantine-attempt",
        "Quarantined repair lacks an unknown terminal attempt",
        RepairCaseStatus.QUARANTINED,
        "unknown_outcome",
        "verified",
        attempt_outcome="effect_confirmed",
    )
    expect_invalid(
        "failed-unknown",
        "Failed repair lacks a trusted retryable failure attempt",
        RepairCaseStatus.FAILED,
        "unknown_outcome",
        "quarantined",
        verification_reference=None,
    )

    mismatch_store, mismatch_case = _durable_terminal_case(
        tmp_path / "attempt-mismatch.sqlite3",
        RepairCaseStatus.VERIFIED_REPAIRED,
        "effect_confirmed",
        "verified",
    )
    mismatch_case = mismatch_store.update(mismatch_case, attempt_count=2)
    with pytest.raises(WorkflowTemplateError, match="latest attempt"):
        authority.issue_reliability_from_repair(mismatch_store, mismatch_case.case_id)
    mismatch_store.close()

    unavailable_store, unavailable_case = _durable_terminal_case(
        tmp_path / "unavailable.sqlite3",
        RepairCaseStatus.VERIFIED_REPAIRED,
        "effect_confirmed",
        "verified",
    )
    monkeypatch.setattr(
        unavailable_store,
        "load",
        lambda _case_id: (_ for _ in ()).throw(RepairStoreError("store unavailable")),
    )
    with pytest.raises(WorkflowTemplateError, match="unavailable"):
        authority.issue_reliability_from_repair(unavailable_store, unavailable_case.case_id)
    unavailable_store.close()

    verified_store, verified = _durable_terminal_case(
        tmp_path / "mismatch.sqlite3",
        RepairCaseStatus.VERIFIED_REPAIRED,
        "effect_confirmed",
        "verified",
    )
    with pytest.raises(WorkflowTemplateError, match="canonical"):
        authority.issue_reliability_from_repair(
            verified_store, verified.case_id, method_key="caller.supplied"
        )
    verified_store.close()


def test_repair_store_migrates_v1_schema_to_v2(tmp_path: Path) -> None:
    path = tmp_path / "legacy.sqlite3"
    connection = sqlite3.connect(path)
    connection.executescript(
        """
        CREATE TABLE repair_schema (version INTEGER PRIMARY KEY, name TEXT NOT NULL);
        INSERT INTO repair_schema(version, name) VALUES (1, 'repair-cases-v1');
        CREATE TABLE repair_cases (
            case_id TEXT PRIMARY KEY,
            case_key TEXT NOT NULL,
            component_id TEXT NOT NULL,
            owner TEXT NOT NULL,
            failure_code TEXT,
            component_version TEXT,
            opened_at TEXT NOT NULL,
            status TEXT NOT NULL,
            attempt_budget INTEGER NOT NULL,
            attempt_count INTEGER NOT NULL,
            latest_diagnosis TEXT,
            selected_action TEXT,
            effect_outcome TEXT,
            verification_reference TEXT,
            fallback TEXT,
            terminal_reason TEXT,
            updated_at TEXT NOT NULL
        );
        CREATE TABLE repair_attempts (
            case_id TEXT NOT NULL REFERENCES repair_cases(case_id) ON DELETE CASCADE,
            number INTEGER NOT NULL,
            state TEXT NOT NULL,
            outcome TEXT,
            detail TEXT NOT NULL,
            started_at TEXT NOT NULL,
            finished_at TEXT,
            verification_reference TEXT,
            PRIMARY KEY(case_id, number)
        );
        """
    )
    connection.commit()
    connection.close()

    store = SQLiteRepairStore(path)
    columns = {
        str(row[1])
        for row in store._conn.execute("PRAGMA table_info(repair_cases)").fetchall()  # noqa: SLF001
    }
    version = store._conn.execute(  # noqa: SLF001
        "SELECT version, name FROM repair_schema WHERE version=2"
    ).fetchone()
    assert "failure_observation_id" in columns
    assert version is not None and tuple(version) == (2, "repair-cases-v2")
    store.close()


@pytest.mark.asyncio
async def test_runtime_broker_authority_composes_with_doctor(tmp_path: Path) -> None:
    runtime = ApplicationRuntime.create(
        Settings(app_data_dir=tmp_path / "runtime", ai_provider="ollama")
    )
    assert runtime.status is RuntimeStatus.READY
    container = runtime.container
    assert container is not None
    doctor = container.component_doctor
    state = [False]
    calls: list[int] = []
    doctor.register_playbook(_playbook())
    doctor.register_probe(
        "r1.component", "state", lambda _p: DiagnosticProbeResult("state", state[0], "state")
    )
    doctor.register_action(
        "r1.component",
        "repair",
        lambda _p, _a: (
            _mark_int(calls, 1),
            state.__setitem__(0, True),
            RepairExecution(RepairEffectOutcome.EFFECT_CONFIRMED, True, "done"),
        )[2],
    )
    problem = _problem("runtime-observation")
    first = await doctor.run(problem)
    pending = await container.permission_broker.pending_approvals(first.case_id)
    request = pending[0]
    context = container.desktop_approval_authenticator.issue_context(
        request_id=request.request_id,
        choice=ApprovalChoice.APPROVE_ONCE,
        identity=ApprovalIdentity(
            container.actor_context.principal_id,
            ApprovalActorKind.TRUSTED_USER,
        ),
    )
    assert (await container.permission_broker.decide(context)).accepted
    second = await doctor.run(problem)

    assert first.status is DoctorStatus.PERMISSION_REQUIRED
    assert second.status is DoctorStatus.REPAIRED
    assert first.case_id == second.case_id
    assert calls == [1]
    learned = container.procedure_learning.bank.reliability("repair:r1.component:repair")
    assert learned is not None
    assert learned.verified_successes == 1
    await runtime.aclose()
