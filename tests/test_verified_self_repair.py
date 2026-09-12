from __future__ import annotations

import json
from dataclasses import replace
from datetime import UTC, datetime
from hashlib import sha256
from pathlib import Path
from types import SimpleNamespace
from typing import Any, cast
from uuid import uuid4

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
    RepairAttemptRecord,
    RepairCase,
    RepairCaseStatus,
    RepairEffectOutcome,
    RepairExecution,
    RepairPlaybook,
    RepairStoreError,
    RoutedRepairResearch,
    SQLiteRepairStore,
    repair_case_key,
)
from jarvis.integration_package import (
    DiagnosticsContract,
    IntegrationPackage,
    PackageBoundary,
    PackageEntry,
    PackageLayout,
    PackageLifecycle,
    PackageProvenance,
)
from jarvis.planning.models import EffectOutcome
from jarvis.planning.store import PlanningStore
from jarvis.tools.models import SemanticVersion
from jarvis.verification import VerificationDisposition, VerificationLevel, VerificationResult
from jarvis.workflows import (
    ProcedureBank,
    ProcedureEvidenceAuthority,
    ProcedureReliabilityStatus,
    SQLiteWorkflowProcedureStore,
)

NOW = datetime(2026, 9, 12, tzinfo=UTC)


def _problem() -> ComponentProblem:
    return ComponentProblem(
        "synthetic.component",
        "synthetic failure",
        DiagnosticOwner.CAPABILITY,
        failure_code="synthetic.failure",
        source="health",
        evidence=("trusted synthetic observation",),
        occurred_at=NOW,
    )


def _playbook() -> RepairPlaybook:
    return RepairPlaybook(
        "synthetic.playbook",
        "synthetic.component",
        DiagnosticOwner.CAPABILITY,
        (FailureSignature("synthetic.failure", "synthetic failure"),),
        (DiagnosticProbe("state", "Read synthetic state"),),
        (RepairAction("repair", "Repair synthetic state"),),
    )


def _doctor(path: Path, state: dict[str, bool], calls: list[str]) -> ComponentDoctor:
    health = CapabilityHealthService(clock=lambda: NOW)
    store = SQLiteRepairStore(path)
    doctor = ComponentDoctor(
        health,
        authorize=lambda _problem, _action: True,
        repair_store=store,
        clock=lambda: NOW,
    )
    doctor.register_playbook(_playbook())
    doctor.register_probe(
        "synthetic.component",
        "state",
        lambda _problem: DiagnosticProbeResult(
            "state", state["healthy"], "healthy" if state["healthy"] else "broken"
        ),
    )

    def action(_problem: ComponentProblem, _action: RepairAction) -> RepairExecution:
        calls.append("effect")
        state["healthy"] = True
        return RepairExecution(RepairEffectOutcome.EFFECT_CONFIRMED, True, "executor completed")

    doctor.register_action("synthetic.component", "repair", action)
    return doctor


@pytest.mark.asyncio
async def test_real_state_needs_independent_verification_and_persists(tmp_path: Path) -> None:
    state = {"healthy": False}
    calls: list[str] = []
    doctor = _doctor(tmp_path / "repair.sqlite3", state, calls)
    doctor.register_verifier(
        "synthetic.component",
        "repair",
        lambda _problem, _action, _execution: state["healthy"],
    )

    result = await doctor.run(_problem())

    assert result.status is DoctorStatus.REPAIRED
    assert result.case_id is not None
    assert calls == ["effect"]
    assert doctor._health.health("synthetic.component").status is HealthStatus.HEALTHY  # noqa: SLF001
    assert doctor.repair_store is not None
    case = doctor.repair_store.load(result.case_id)
    assert case is not None
    assert case.status is RepairCaseStatus.VERIFIED_REPAIRED
    assert case.verification_reference == "independent-verifier"
    doctor.close()


@pytest.mark.asyncio
async def test_callback_self_report_cannot_promote_broken_state(tmp_path: Path) -> None:
    state = {"healthy": False}
    calls: list[str] = []
    doctor = _doctor(tmp_path / "repair.sqlite3", state, calls)
    doctor.register_verifier(
        "synthetic.component",
        "repair",
        lambda _problem, _action, _execution: state["healthy"],
    )
    # Replace the trusted action binding with a lying executor in a separate
    # fixture so the external state remains broken after the callback.
    doctor.close()
    state = {"healthy": False}
    calls = []
    doctor = _doctor(tmp_path / "lying.sqlite3", state, calls)
    doctor._actions[("synthetic.component", "repair")] = (  # noqa: SLF001
        lambda _problem, _action: RepairExecution(
            RepairEffectOutcome.EFFECT_CONFIRMED, True, "claimed complete", ("verified",)
        )
    )
    doctor.register_verifier(
        "synthetic.component",
        "repair",
        lambda _problem, _action, _execution: state["healthy"],
    )

    result = await doctor.run(_problem())

    assert result.status is DoctorStatus.FAILED
    assert doctor._health.health("synthetic.component").status is HealthStatus.UNAVAILABLE  # noqa: SLF001
    assert calls == []
    doctor.close()


@pytest.mark.asyncio
async def test_permission_denial_is_durable_and_has_no_effect_call(tmp_path: Path) -> None:
    state = {"healthy": False}
    calls: list[str] = []
    health = CapabilityHealthService(clock=lambda: NOW)
    store = SQLiteRepairStore(tmp_path / "repair.sqlite3")
    doctor = ComponentDoctor(health, repair_store=store, clock=lambda: NOW)
    doctor.register_playbook(_playbook())

    def denied_action(_problem: ComponentProblem, _action: RepairAction) -> RepairExecution:
        calls.append("effect")
        return RepairExecution(RepairEffectOutcome.EFFECT_CONFIRMED, True, "never")

    doctor.register_action("synthetic.component", "repair", denied_action)

    result = await doctor.run(_problem())

    assert result.status is DoctorStatus.PERMISSION_REQUIRED
    assert calls == []
    assert store.cases()[0].status is RepairCaseStatus.PERMISSION_REQUIRED
    assert state["healthy"] is False
    doctor.close()


@pytest.mark.asyncio
async def test_pre_effect_failure_is_the_only_retriable_failure(tmp_path: Path) -> None:
    state = {"healthy": False}
    calls: list[str] = []
    doctor = _doctor(tmp_path / "repair.sqlite3", state, calls)
    doctor.register_verifier("synthetic.component", "repair", lambda _p, _a, _e: state["healthy"])
    outcomes = iter(
        (
            RepairExecution(RepairEffectOutcome.PRE_EFFECT_FAILURE, False, "before effect"),
            RepairExecution(RepairEffectOutcome.EFFECT_CONFIRMED, True, "completed"),
        )
    )

    def retriable_action(_problem: ComponentProblem, _action: RepairAction) -> RepairExecution:
        state["healthy"] = True
        return next(outcomes)

    doctor._actions[("synthetic.component", "repair")] = retriable_action  # noqa: SLF001

    result = await doctor.run(_problem())

    assert result.status is DoctorStatus.REPAIRED
    assert len(result.attempts) == 2
    assert len(calls) == 0
    doctor.close()


def test_restart_reconciles_in_progress_effect_to_quarantine(tmp_path: Path) -> None:
    store = SQLiteRepairStore(tmp_path / "repair.sqlite3")
    case, _ = store.open_case(
        component_id="synthetic.component",
        owner=DiagnosticOwner.CAPABILITY.value,
        failure_code="synthetic.failure",
        component_version=None,
        attempt_budget=2,
        now=NOW,
    )
    store.save_case(replace(case, status=RepairCaseStatus.EFFECT_IN_PROGRESS, attempt_count=1))
    store.save_attempt(RepairAttemptRecord(case.case_id, 1, "applying", None, "started", NOW))
    store.close()

    restarted = SQLiteRepairStore(tmp_path / "repair.sqlite3")
    restored = restarted.load(case.case_id)
    assert restored is not None
    assert restored.status is RepairCaseStatus.QUARANTINED
    restarted.close()


def test_repair_store_cases_attempts_and_stable_identity(tmp_path: Path) -> None:
    path = tmp_path / "repair.sqlite3"
    store = SQLiteRepairStore(path)
    assert repair_case_key("component", "capability", "failure") == repair_case_key(
        "component", "capability", "failure"
    )
    case, created = store.open_case(
        component_id="component",
        owner="capability",
        failure_code="failure",
        component_version="1",
        attempt_budget=2,
        now=NOW,
    )
    assert created
    same, created_again = store.open_case(
        component_id="component",
        owner="capability",
        failure_code="failure",
        component_version="1",
        attempt_budget=2,
        now=NOW,
    )
    assert same.case_id == case.case_id
    assert not created_again
    store.save_attempt(
        RepairAttemptRecord(case.case_id, 1, "failed", "pre_effect_failure", "no effect", NOW, NOW)
    )
    assert store.load(case.case_id) == case
    assert len(store.attempts(case.case_id)) == 1
    assert store.latest(case.case_key) == case
    assert store.cases(limit=1)[0] == case
    store.close()
    restarted = SQLiteRepairStore(path)
    assert restarted.load(case.case_id) == case
    restarted.close()


@pytest.mark.asyncio
async def test_unknown_case_is_deduplicated_after_terminal_quarantine(tmp_path: Path) -> None:
    state = {"healthy": False}
    calls: list[str] = []
    doctor = _doctor(tmp_path / "repair.sqlite3", state, calls)

    def ambiguous_action(_problem: ComponentProblem, _action: RepairAction) -> RepairExecution:
        calls.append("effect")
        return RepairExecution(RepairEffectOutcome.UNKNOWN_OUTCOME, False, "ambiguous")

    doctor._actions[("synthetic.component", "repair")] = ambiguous_action  # noqa: SLF001
    first = await doctor.run(_problem())
    second = await doctor.run(_problem())
    assert first.status is DoctorStatus.QUARANTINED
    assert second.status is DoctorStatus.QUARANTINED
    assert calls == ["effect"]
    doctor.close()


@pytest.mark.asyncio
async def test_failed_repair_uses_safe_fallback_and_never_reports_healthy(tmp_path: Path) -> None:
    state = {"healthy": False}
    calls: list[str] = []
    health = CapabilityHealthService(clock=lambda: NOW)
    store = SQLiteRepairStore(tmp_path / "repair.sqlite3")
    doctor = ComponentDoctor(
        health,
        authorize=lambda _problem, _action: True,
        repair_store=store,
        clock=lambda: NOW,
        max_attempts=1,
    )
    doctor.register_playbook(replace(_playbook(), fallback_strategy=("degrade",)))
    doctor.register_probe(
        "synthetic.component",
        "state",
        lambda _problem: DiagnosticProbeResult("state", state["healthy"], "state"),
    )

    def failed_action(_problem: ComponentProblem, _action: RepairAction) -> RepairExecution:
        calls.append("effect")
        return RepairExecution(
            RepairEffectOutcome.PRE_EFFECT_FAILURE, False, "failed before effect"
        )

    doctor.register_action("synthetic.component", "repair", failed_action)
    doctor.register_fallback(
        "synthetic.component",
        FallbackOption("degrade", "Text-only mode remains available"),
        lambda _problem: True,
    )
    result = await doctor.run(_problem())
    assert result.status is DoctorStatus.DEGRADED
    assert health.health("synthetic.component").status is HealthStatus.DEGRADED
    assert store.cases()[0].status is RepairCaseStatus.DEGRADED_FALLBACK
    assert calls == ["effect"]
    doctor.close()


def test_procedure_reliability_is_signed_sanitized_and_restart_safe(tmp_path: Path) -> None:
    store = SQLiteWorkflowProcedureStore(tmp_path / "workflow.sqlite3")
    authority = ProcedureEvidenceAuthority(cast(PlanningStore, object()))
    bank = ProcedureBank(store=store, evidence_authority=authority)
    verified = VerificationResult(
        "synthetic repair",
        VerificationLevel.AUTOMATED_TESTED,
        True,
        VerificationDisposition.COMPLETE,
    )
    first = authority.issue_reliability(
        "repair.synthetic",
        "success-1",
        EffectOutcome.EFFECT_CONFIRMED,
        verification=verified,
        compatibility_key="v1",
    )
    assert bank.record_reliability(first) is not None
    first_projection = bank.record_reliability(first)
    assert first_projection is not None
    assert first_projection.verified_successes == 1
    second = authority.issue_reliability(
        "repair.synthetic",
        "success-2",
        EffectOutcome.EFFECT_CONFIRMED,
        verification=verified,
        compatibility_key="v1",
    )
    projection = bank.record_reliability(second)
    assert projection is not None
    assert projection.sample_sufficient
    failure = authority.issue_reliability(
        "repair.synthetic", "failure-1", EffectOutcome.PRE_EFFECT_FAILURE
    )
    failure_projection = bank.record_reliability(failure)
    assert failure_projection is not None
    assert failure_projection.verified_failures == 1
    unknown = authority.issue_reliability(
        "repair.synthetic", "unknown-1", EffectOutcome.UNKNOWN_OUTCOME
    )
    unknown_projection = bank.record_reliability(unknown)
    assert unknown_projection is not None
    assert unknown_projection.status is ProcedureReliabilityStatus.UNKNOWN
    drifted = bank.mark_dependency_drift("repair.synthetic", "v2-incompatible")
    assert drifted.status is ProcedureReliabilityStatus.REVALIDATION_REQUIRED
    store.close()
    restarted_store = SQLiteWorkflowProcedureStore(tmp_path / "workflow.sqlite3")
    restarted = ProcedureBank(store=restarted_store, evidence_authority=authority)
    restarted_projection = restarted.reliability("repair.synthetic")
    assert restarted_projection is not None
    assert restarted_projection.verified_successes == 2
    restarted_store.close()


def test_repair_store_rejects_future_schema(tmp_path: Path) -> None:
    import sqlite3

    path = tmp_path / "future.sqlite3"
    connection = sqlite3.connect(path)
    connection.execute(
        "CREATE TABLE repair_schema (version INTEGER PRIMARY KEY, name TEXT NOT NULL)"
    )
    connection.execute("INSERT INTO repair_schema VALUES (99, 'future')")
    connection.commit()
    connection.close()
    with pytest.raises(RepairStoreError, match="future schema"):
        SQLiteRepairStore(path)


def test_repair_state_validation_and_store_bounds(tmp_path: Path) -> None:
    with pytest.raises(RepairStoreError, match="component"):
        repair_case_key("", "owner", None)
    with pytest.raises(RepairStoreError, match="timezone"):
        RepairCase(
            uuid4(),
            "key",
            "component",
            "owner",
            None,
            None,
            NOW.replace(tzinfo=None),
            RepairCaseStatus.DIAGNOSIS_PENDING,
        )
    with pytest.raises(RepairStoreError, match="identity"):
        RepairAttemptRecord(cast(Any, "bad-id"), 0, "state", None, "detail", NOW)
    with pytest.raises(RepairStoreError, match="path"):
        SQLiteRepairStore(cast(Any, "not-a-path"))
    with pytest.raises(RepairStoreError, match="case ID"):
        RepairCase(
            cast(Any, "not-a-uuid"),
            "key",
            "component",
            "owner",
            None,
            None,
            NOW,
            RepairCaseStatus.DIAGNOSIS_PENDING,
        )
    with pytest.raises(RepairStoreError, match="status"):
        RepairCase(
            uuid4(),
            "key",
            "component",
            "owner",
            None,
            None,
            NOW,
            cast(Any, "invalid"),
        )
    with pytest.raises(RepairStoreError, match="budget"):
        RepairCase(
            uuid4(),
            "key",
            "component",
            "owner",
            None,
            None,
            NOW,
            RepairCaseStatus.DIAGNOSIS_PENDING,
            attempt_budget=0,
        )
    with pytest.raises(RepairStoreError, match="count"):
        RepairCase(
            uuid4(),
            "key",
            "component",
            "owner",
            None,
            None,
            NOW,
            RepairCaseStatus.DIAGNOSIS_PENDING,
            attempt_count=4,
        )

    store = SQLiteRepairStore(tmp_path / "bounds.sqlite3")
    with pytest.raises(RepairStoreError, match="read bound"):
        store.cases(limit=0)
    with pytest.raises(RepairStoreError, match="case is malformed"):
        store.save_case(cast(Any, "not-a-case"))
    with pytest.raises(RepairStoreError, match="attempt is malformed"):
        store.save_attempt(cast(Any, "not-an-attempt"))
    store.close()

    import sqlite3

    broken_attempt_path = tmp_path / "broken-attempt.sqlite3"
    store = SQLiteRepairStore(broken_attempt_path)
    case, _ = store.open_case(
        component_id="component",
        owner="owner",
        failure_code=None,
        component_version=None,
        attempt_budget=2,
        now=NOW,
    )
    store.close()
    connection = sqlite3.connect(broken_attempt_path)
    connection.execute(
        "INSERT INTO repair_attempts VALUES "
        "(?, 1, 'state', NULL, 'detail', 'bad-time', NULL, NULL)",
        (str(case.case_id),),
    )
    connection.commit()
    connection.close()
    store = SQLiteRepairStore(broken_attempt_path)
    with pytest.raises(RepairStoreError, match="malformed"):
        store.attempts(case.case_id)
    store.close()


@pytest.mark.asyncio
async def test_routed_repair_research_is_bounded_and_untrusted() -> None:
    class Dispatcher:
        async def generate(self, _request: object, _intent: object) -> object:
            return SimpleNamespace(
                result=SimpleNamespace(
                    content=json.dumps(
                        {"action_id": "suggested", "description": "inspect local state"}
                    )
                )
            )

    with pytest.raises(Exception, match="dispatcher"):
        RoutedRepairResearch(cast(Any, None))
    research = object.__new__(RoutedRepairResearch)
    research._dispatcher = cast(Any, Dispatcher())  # noqa: SLF001
    candidate = await research(_problem())
    assert candidate is not None
    assert candidate.source == "model"
    assert candidate.trusted is False


@pytest.mark.asyncio
async def test_routed_repair_research_rejects_malformed_model_output() -> None:
    class Dispatcher:
        async def generate(self, _request: object, _intent: object) -> object:
            return SimpleNamespace(result=SimpleNamespace(content="not-json"))

    research = object.__new__(RoutedRepairResearch)
    research._dispatcher = cast(Any, Dispatcher())  # noqa: SLF001
    assert await research(_problem()) is None


@pytest.mark.asyncio
async def test_verification_result_is_required_to_pass_independent_observation(
    tmp_path: Path,
) -> None:
    state = {"healthy": False}
    doctor = _doctor(tmp_path / "verification.sqlite3", state, [])
    doctor.register_verifier(
        "synthetic.component",
        "repair",
        lambda _problem, _action, _execution: VerificationResult(
            "synthetic repair",
            VerificationLevel.AUTOMATED_TESTED,
            False,
            VerificationDisposition.COMPLETE,
        ),
    )
    result = await doctor.run(_problem())
    assert result.status is DoctorStatus.FAILED
    doctor.close()


def test_component_doctor_rejects_untrusted_bindings_and_bad_inputs(tmp_path: Path) -> None:
    health = CapabilityHealthService(clock=lambda: NOW)
    with pytest.raises(Exception, match="version"):
        replace(_problem(), component_version="")
    with pytest.raises(Exception, match="store"):
        ComponentDoctor(health, repair_store=cast(Any, object()))
    with pytest.raises(Exception, match="verifier"):
        ComponentDoctor(health, verifier=cast(Any, object()))
    with pytest.raises(Exception, match="attempt bound"):
        ComponentDoctor(health, max_attempts=0)

    package = IntegrationPackage(
        "registered.package",
        SemanticVersion(1, 0, 0),
        PackageLayout(),
        (
            PackageEntry(
                "python",
                "code/main.py",
                PackageBoundary.PACKAGE_CODE,
                sha256(b"return 1").hexdigest(),
                PackageProvenance("fixture", "revision", "MIT"),
            ),
        ),
        lifecycle=PackageLifecycle.VALIDATED,
        diagnostics=DiagnosticsContract(),
        provenance=PackageProvenance("fixture", "revision", "MIT"),
    )
    package_doctor = ComponentDoctor(health)
    assert package_doctor.register_package(package).component_id == "registered.package"
    package_doctor.close()

    doctor = ComponentDoctor(health, repair_store=SQLiteRepairStore(tmp_path / "bindings.sqlite3"))
    doctor.register_playbook(_playbook())
    with pytest.raises(Exception, match="probe"):
        doctor.register_probe("synthetic.component", "state", cast(Any, object()))
    with pytest.raises(Exception, match="owner"):
        doctor.register_action(
            "synthetic.component",
            "repair",
            lambda _problem, _action: RepairExecution(
                RepairEffectOutcome.EFFECT_CONFIRMED, True, "done"
            ),
            owner=DiagnosticOwner.CORE,
        )
    doctor.register_verifier("synthetic.component", "repair", lambda _p, _a, _e: True)
    with pytest.raises(Exception, match="Independent verifier"):
        doctor.register_verifier("synthetic.component", "repair", cast(Any, object()))
    with pytest.raises(Exception, match="already bound"):
        doctor.register_verifier("synthetic.component", "repair", lambda _p, _a, _e: True)
    with pytest.raises(Exception, match="Fallback"):
        doctor.register_fallback("synthetic.component", cast(Any, object()), lambda _p: True)
    assert doctor.playbooks()
    doctor.close()

    no_store = ComponentDoctor(health)
    case_store = SQLiteRepairStore(tmp_path / "case-for-no-store.sqlite3")
    case, _ = case_store.open_case(
        component_id="component",
        owner="owner",
        failure_code=None,
        component_version=None,
        attempt_budget=2,
        now=NOW,
    )
    case_store.close()
    assert no_store._case_update(case) == case  # noqa: SLF001


@pytest.mark.asyncio
async def test_doctor_handles_verifier_errors_and_legacy_probe_refresh(tmp_path: Path) -> None:
    state = {"healthy": False}
    doctor = _doctor(tmp_path / "errors.sqlite3", state, [])

    async def raising_verifier(
        _problem: ComponentProblem, _action: RepairAction, _execution: RepairExecution
    ) -> bool:
        raise RuntimeError("verification unavailable")

    doctor.register_verifier("synthetic.component", "repair", raising_verifier)
    failed = await doctor.run(_problem())
    assert failed.status is DoctorStatus.FAILED
    doctor.close()

    state = {"healthy": False}
    refreshed = _doctor(tmp_path / "refresh.sqlite3", state, [])
    refreshed._verifiers.clear()  # noqa: SLF001

    def repair_and_mark(_problem: ComponentProblem, _action: RepairAction) -> RepairExecution:
        state["healthy"] = True
        return RepairExecution(RepairEffectOutcome.EFFECT_CONFIRMED, True, "done")

    refreshed._actions[("synthetic.component", "repair")] = (  # noqa: SLF001
        repair_and_mark
    )
    result = await refreshed.run(_problem())
    assert result.status is DoctorStatus.REPAIRED
    refreshed.close()


@pytest.mark.asyncio
async def test_doctor_research_and_authorization_fail_closed(tmp_path: Path) -> None:
    async def broken_research(_problem: ComponentProblem) -> None:
        raise RuntimeError("research unavailable")

    health = CapabilityHealthService(clock=lambda: NOW)
    doctor = ComponentDoctor(
        health,
        research=broken_research,
        repair_store=SQLiteRepairStore(tmp_path / "research.sqlite3"),
    )
    result = await doctor.run(_problem())
    assert result.status is DoctorStatus.RESEARCH_REQUIRED
    doctor.close()

    broken_store = SQLiteRepairStore(tmp_path / "broken-store.sqlite3")

    def broken_open_case(**_kwargs: object) -> object:
        raise RepairStoreError("broken repair persistence")

    cast(Any, broken_store).open_case = broken_open_case
    broken_doctor = ComponentDoctor(health, repair_store=broken_store)
    with pytest.raises(Exception, match="persistence"):
        await broken_doctor.run(_problem())
    broken_store.close()

    state = {"healthy": False}
    denied = _doctor(tmp_path / "authorization.sqlite3", state, [])
    denied._authorize = lambda _problem, _action: (_ for _ in ()).throw(RuntimeError("broker"))  # noqa: SLF001
    denied_result = await denied.run(_problem())
    assert denied_result.status is DoctorStatus.PERMISSION_REQUIRED
    denied._health = cast(Any, object())  # noqa: SLF001
    await denied._safe_health(_problem(), HealthStatus.DEGRADED, "ignored")  # noqa: SLF001
    denied.close()


@pytest.mark.asyncio
async def test_doctor_bounds_malformed_callbacks_and_missing_observation(
    tmp_path: Path,
) -> None:
    health = CapabilityHealthService(clock=lambda: NOW)
    with pytest.raises(Exception, match="health"):
        ComponentDoctor(cast(Any, object()))
    doctor = ComponentDoctor(health, authorize=lambda _p, _a: True)
    with pytest.raises(Exception, match="playbook"):
        doctor.register_playbook(cast(Any, object()))
    with pytest.raises(Exception, match="problem"):
        await doctor.run(cast(Any, object()))

    malformed_research = object.__new__(RoutedRepairResearch)

    class ResearchDispatcher:
        def __init__(self, content: str) -> None:
            self.content = content

        async def generate(self, _request: object, _intent: object) -> object:
            return SimpleNamespace(result=SimpleNamespace(content=self.content))

    for content in (
        json.dumps({"action_id": 1}),
        json.dumps({"action_id": "action", "description": 1}),
    ):
        malformed_research._dispatcher = cast(Any, ResearchDispatcher(content))  # noqa: SLF001
        assert await malformed_research(_problem()) is None

    string_verifier = _doctor(tmp_path / "string-verifier.sqlite3", {"healthy": False}, [])
    string_verifier.register_verifier(
        "synthetic.component", "repair", lambda _p, _a, _e: "trusted-ref"
    )
    assert (await string_verifier.run(_problem())).status is DoctorStatus.REPAIRED
    string_verifier.close()

    malformed_verifier = _doctor(tmp_path / "malformed-verifier.sqlite3", {"healthy": False}, [])
    malformed_verifier.register_verifier(
        "synthetic.component", "repair", cast(Any, lambda _p, _a, _e: 1)
    )
    assert (await malformed_verifier.run(_problem())).status is DoctorStatus.FAILED
    malformed_verifier.close()

    no_probe = ComponentDoctor(
        health,
        authorize=lambda _p, _a: True,
        repair_store=SQLiteRepairStore(tmp_path / "no-probe.sqlite3"),
    )
    no_probe.register_playbook(replace(_playbook(), probes=()))
    no_probe.register_action(
        "synthetic.component",
        "repair",
        lambda _p, _a: RepairExecution(RepairEffectOutcome.EFFECT_CONFIRMED, True, "done"),
    )
    assert (await no_probe.run(_problem())).status is DoctorStatus.FAILED
    no_probe.close()

    bad_probe = _doctor(tmp_path / "bad-probe.sqlite3", {"healthy": False}, [])
    bad_probe._probes[("synthetic.component", "state")] = (  # noqa: SLF001
        lambda _p: cast(Any, object())
    )
    assert (await bad_probe.run(_problem())).status is DoctorStatus.FAILED
    bad_probe.close()


def test_repair_store_rejects_bad_paths_migrations_and_rows(tmp_path: Path) -> None:
    with pytest.raises(RepairStoreError, match="unavailable"):
        SQLiteRepairStore(cast(Any, tmp_path))
    with pytest.raises(RepairStoreError, match="unavailable"):
        SQLiteRepairStore(tmp_path)

    import sqlite3

    identity_path = tmp_path / "identity.sqlite3"
    connection = sqlite3.connect(identity_path)
    connection.execute(
        "CREATE TABLE repair_schema (version INTEGER PRIMARY KEY, name TEXT NOT NULL)"
    )
    connection.execute("INSERT INTO repair_schema VALUES (1, 'wrong-name')")
    connection.commit()
    connection.close()
    with pytest.raises(RepairStoreError, match="identity"):
        SQLiteRepairStore(identity_path)

    store = SQLiteRepairStore(tmp_path / "update.sqlite3")
    case, _ = store.open_case(
        component_id="component",
        owner="owner",
        failure_code=None,
        component_version=None,
        attempt_budget=2,
        now=NOW,
    )
    updated = store.update(case, latest_diagnosis="bounded diagnosis")
    assert updated.latest_diagnosis == "bounded diagnosis"
    with pytest.raises(RepairStoreError, match="case ID"):
        store.load(cast(Any, "bad-id"))
    store.close()

    malformed_path = tmp_path / "malformed.sqlite3"
    store = SQLiteRepairStore(malformed_path)
    case, _ = store.open_case(
        component_id="component",
        owner="owner",
        failure_code=None,
        component_version=None,
        attempt_budget=2,
        now=NOW,
    )
    store.close()
    connection = sqlite3.connect(malformed_path)
    connection.execute(
        "UPDATE repair_cases SET updated_at='not-a-time' WHERE case_id=?", (str(case.case_id),)
    )
    connection.commit()
    connection.close()
    malformed_store = SQLiteRepairStore(malformed_path)
    with pytest.raises(RepairStoreError, match="malformed"):
        malformed_store.load(case.case_id)
    malformed_store.close()

    bad_status_path = tmp_path / "bad-status.sqlite3"
    store = SQLiteRepairStore(bad_status_path)
    status_case, _ = store.open_case(
        component_id="component",
        owner="owner",
        failure_code=None,
        component_version=None,
        attempt_budget=2,
        now=NOW,
    )
    store.close()
    connection = sqlite3.connect(bad_status_path)
    connection.execute(
        "UPDATE repair_cases SET status='not-a-status' WHERE case_id=?",
        (str(status_case.case_id),),
    )
    connection.commit()
    connection.close()
    bad_status_store = SQLiteRepairStore(bad_status_path)
    with pytest.raises(RepairStoreError, match="malformed"):
        bad_status_store.load(status_case.case_id)
    bad_status_store.close()

    bad_attempt_path = tmp_path / "bad-attempt-type.sqlite3"
    store = SQLiteRepairStore(bad_attempt_path)
    attempt_case, _ = store.open_case(
        component_id="component",
        owner="owner",
        failure_code=None,
        component_version=None,
        attempt_budget=2,
        now=NOW,
    )
    store.close()
    connection = sqlite3.connect(bad_attempt_path)
    connection.execute(
        "INSERT INTO repair_attempts VALUES (?, 1, 'state', NULL, 'detail', ?, NULL, NULL)",
        (str(attempt_case.case_id), sqlite3.Binary(b"bad-time")),
    )
    connection.commit()
    connection.close()
    bad_attempt_store = SQLiteRepairStore(bad_attempt_path)
    with pytest.raises(RepairStoreError, match="malformed"):
        bad_attempt_store.attempts(attempt_case.case_id)
    bad_attempt_store.close()
    cast(Any, bad_attempt_store)._connection = None  # noqa: SLF001

    with pytest.raises(RepairStoreError, match="unavailable"):
        _ = bad_attempt_store._conn  # noqa: SLF001

    class BrokenConnection:
        def execute(self, *_args: object, **_kwargs: object) -> None:
            raise sqlite3.DatabaseError("synthetic storage fault")

        def rollback(self) -> None:
            return

        def close(self) -> None:
            return

    broken_case_store = SQLiteRepairStore(tmp_path / "broken-case.sqlite3")
    broken_case, _ = broken_case_store.open_case(
        component_id="component",
        owner="owner",
        failure_code=None,
        component_version=None,
        attempt_budget=2,
        now=NOW,
    )
    cast(Any, broken_case_store)._connection = BrokenConnection()  # noqa: SLF001
    with pytest.raises(RepairStoreError, match="case could not"):
        broken_case_store.save_case(broken_case)
    with pytest.raises(RepairStoreError, match="attempt could not"):
        broken_case_store.save_attempt(
            RepairAttemptRecord(broken_case.case_id, 1, "state", None, "detail", NOW)
        )
    broken_case_store.close()
