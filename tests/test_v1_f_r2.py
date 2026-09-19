from __future__ import annotations

from datetime import UTC, datetime
from pathlib import Path
from typing import Any, cast
from uuid import UUID, uuid4

import pytest
from jarvis.capability_health import CapabilityHealthService
from jarvis.component_doctor import (
    BrokeredRepairAuthorizer,
    ComponentDoctor,
    ComponentProblem,
    DiagnosticOwner,
    DiagnosticProbe,
    DiagnosticProbeResult,
    DoctorStatus,
    FailureSignature,
    FallbackOption,
    RepairAction,
    RepairAttemptState,
    RepairCaseStatus,
    RepairEffectOutcome,
    RepairExecution,
    RepairPlaybook,
)
from jarvis.permissions.approval import TrustedApprovalAuthenticator
from jarvis.permissions.broker import PermissionBroker
from jarvis.permissions.models import (
    ApprovalActorKind,
    ApprovalChoice,
    ApprovalIdentity,
    ApprovalSource,
    Decision,
    Permission,
    PermissionScope,
    PolicyRule,
    ScopeConstraint,
)
from jarvis.permissions.policy import PolicyEngine
from jarvis.repair_state import RepairAttemptRecord, SQLiteRepairStore
from jarvis.workflows import ProcedureEvidenceAuthority, WorkflowTemplateError

NOW = datetime(2026, 9, 12, tzinfo=UTC)


def _problem(observation_id: str = "observation-1") -> ComponentProblem:
    return ComponentProblem(
        "r2.component",
        "synthetic failure",
        DiagnosticOwner.CAPABILITY,
        failure_code="synthetic.failure",
        source="health",
        failure_observation_id=observation_id,
        occurred_at=NOW,
    )


def _playbook(
    action: RepairAction | None = None, *, fallbacks: tuple[str, ...] = ()
) -> RepairPlaybook:
    return RepairPlaybook(
        "r2.playbook",
        "r2.component",
        DiagnosticOwner.CAPABILITY,
        (FailureSignature("synthetic.failure", "synthetic failure"),),
        (DiagnosticProbe("state", "Read state"),),
        () if action is None else (action,),
        fallbacks,
    )


def _rules(
    *,
    path: str | None = None,
    decision: Decision = Decision.REQUIRE_APPROVAL,
) -> PolicyEngine:
    rules = [
        PolicyRule(
            "repair-authority",
            Permission.REPAIR_EXECUTE,
            decision,
            ScopeConstraint(),
            frozenset({"repair.execute"}),
        )
    ]
    if path is not None:
        rules.append(
            PolicyRule(
                "filesystem-write",
                Permission.FILESYSTEM_WRITE,
                decision,
                ScopeConstraint(paths=(path,)),
                frozenset({"repair.execute"}),
            )
        )
    return PolicyEngine(tuple(rules))


def _broker_with_approval(
    *, path: str | None = None, decision: Decision = Decision.REQUIRE_APPROVAL
) -> tuple[PermissionBroker, TrustedApprovalAuthenticator]:
    authenticator = TrustedApprovalAuthenticator(ApprovalSource.TRUSTED_LOCAL_API)
    return (
        PermissionBroker(
            _rules(path=path, decision=decision),
            approval_context_verifier=authenticator.verifier(),
        ),
        authenticator,
    )


def _user() -> ApprovalIdentity:
    return ApprovalIdentity("r2-user", ApprovalActorKind.TRUSTED_USER)


async def _approve(
    broker: PermissionBroker,
    authenticator: TrustedApprovalAuthenticator,
    permission: Permission,
) -> None:
    pending = await broker.pending_approvals()
    request = next(item for item in pending if item.permission is permission)
    decision = await broker.decide(
        authenticator.issue_context(
            request_id=request.request_id,
            choice=ApprovalChoice.APPROVE_ONCE,
            identity=_user(),
        )
    )
    assert decision.accepted


@pytest.mark.asyncio
async def test_repair_authority_overlays_exact_domain_permission_and_scope(tmp_path: Path) -> None:
    target = str(tmp_path / "repair.txt")
    broker, authenticator = _broker_with_approval(path=target)
    authorizer = BrokeredRepairAuthorizer(broker, user_id="r2-user")
    action = RepairAction("write", "Write repair", (Permission.FILESYSTEM_WRITE,))
    assert authorizer.bind_action(
        "r2.component",
        action,
        permission_scopes={Permission.FILESYSTEM_WRITE: PermissionScope(paths=(target,))},
    )
    case_id = uuid4()

    assert not await authorizer(_problem(), action, case_id)
    pending = await broker.pending_approvals(case_id)
    assert {item.permission for item in pending} == {
        Permission.REPAIR_EXECUTE,
        Permission.FILESYSTEM_WRITE,
    }
    assert all(item.scope.task_id == case_id for item in pending)

    await _approve(broker, authenticator, Permission.REPAIR_EXECUTE)
    assert not await authorizer(_problem(), action, case_id)
    await _approve(broker, authenticator, Permission.FILESYSTEM_WRITE)
    assert await authorizer(_problem(), action, case_id)


@pytest.mark.asyncio
async def test_exact_domain_permission_reaches_one_effect(tmp_path: Path) -> None:
    target = str(tmp_path / "repair.txt")
    broker = PermissionBroker(_rules(path=target, decision=Decision.ALLOW))
    authorizer = BrokeredRepairAuthorizer(broker, user_id="r2-user")
    calls: list[int] = []
    doctor = ComponentDoctor(
        CapabilityHealthService(clock=lambda: NOW),
        repair_store=SQLiteRepairStore(tmp_path / "repair.sqlite3"),
        repair_authorizer=authorizer,
        clock=lambda: NOW,
    )
    action = RepairAction("write", "Write repair", (Permission.FILESYSTEM_WRITE,))
    doctor.register_playbook(_playbook(action))
    doctor.register_probe(
        "r2.component",
        "state",
        lambda _problem: DiagnosticProbeResult("state", True, "healthy", checked_at=NOW),
    )

    def write(_problem: ComponentProblem, _action: RepairAction) -> RepairExecution:
        calls.append(1)
        return RepairExecution(RepairEffectOutcome.EFFECT_CONFIRMED, True, "done")

    doctor.register_action(
        "r2.component",
        "write",
        write,
        permission_scopes={Permission.FILESYSTEM_WRITE: PermissionScope(paths=(target,))},
    )
    result = await doctor.run(_problem())
    assert result.status is DoctorStatus.REPAIRED
    assert calls == [1]
    doctor.close()


@pytest.mark.asyncio
async def test_repair_bindings_fail_closed_for_scope_and_permission_mismatch() -> None:
    target = "C:\\r2\\repair.txt"
    broker = PermissionBroker(_rules(path=target, decision=Decision.ALLOW))
    authorizer = BrokeredRepairAuthorizer(broker, user_id="r2-user")
    filesystem = RepairAction("write", "Write repair", (Permission.FILESYSTEM_WRITE,))

    assert not authorizer.bind_action("r2.component", filesystem)
    assert not await authorizer(_problem(), filesystem, uuid4())
    assert authorizer.bind_action(
        "r2.component",
        filesystem,
        permission_scopes={
            Permission.FILESYSTEM_WRITE: PermissionScope(paths=("C:\\r2\\other.txt",))
        },
    )
    assert not await authorizer(_problem(), filesystem, uuid4())
    assert not authorizer.bind_action(
        "r2.component",
        filesystem,
        permission_scopes={
            Permission.FILESYSTEM_WRITE: PermissionScope(paths=(target,)),
            Permission.NETWORK_REQUEST: PermissionScope(hosts=("example.test",)),
        },
    )
    assert not authorizer.bind_action(cast(Any, object()), filesystem)
    unbound = BrokeredRepairAuthorizer(
        PermissionBroker(_rules(path=target, decision=Decision.ALLOW)), user_id="r2-user"
    )
    assert not await unbound(_problem(), filesystem, uuid4())
    assert not await authorizer(_problem(), cast(Any, object()), uuid4())

    empty = RepairAction("empty", "Empty domain repair")
    assert authorizer.bind_action("r2.component", empty, permission_scopes={})
    assert await authorizer(_problem(), empty, uuid4())

    sealed_broker = PermissionBroker(_rules(path=target, decision=Decision.ALLOW))
    sealed_authorizer = BrokeredRepairAuthorizer(sealed_broker, user_id="r2-user")
    sealed_broker.seal_registration()
    assert sealed_authorizer.bind_action(
        "r2.component",
        filesystem,
        permission_scopes={Permission.FILESYSTEM_WRITE: PermissionScope(paths=(target,))},
    )


@pytest.mark.asyncio
async def test_approve_once_cannot_authorize_retry_and_resume_uses_attempt_two(
    tmp_path: Path,
) -> None:
    broker, authenticator = _broker_with_approval()
    authorizer = BrokeredRepairAuthorizer(broker, user_id="r2-user")
    calls: list[int] = []
    doctor = ComponentDoctor(
        CapabilityHealthService(clock=lambda: NOW),
        repair_store=SQLiteRepairStore(tmp_path / "repair.sqlite3"),
        repair_authorizer=authorizer,
        clock=lambda: NOW,
        max_attempts=2,
    )
    doctor.register_playbook(_playbook(RepairAction("repair", "Repair")))
    doctor.register_probe(
        "r2.component",
        "state",
        lambda _problem: DiagnosticProbeResult("state", True, "healthy", checked_at=NOW),
    )

    def repair(_problem: ComponentProblem, _action: RepairAction) -> RepairExecution:
        calls.append(1)
        if len(calls) == 1:
            return RepairExecution(RepairEffectOutcome.PRE_EFFECT_FAILURE, False, "retry")
        return RepairExecution(RepairEffectOutcome.EFFECT_CONFIRMED, True, "done")

    doctor.register_action("r2.component", "repair", repair)
    first = await doctor.run(_problem())
    assert first.status is DoctorStatus.PERMISSION_REQUIRED
    case_id = first.case_id
    assert case_id is not None
    await _approve(broker, authenticator, Permission.REPAIR_EXECUTE)

    paused = await doctor.run(_problem())
    assert paused.status is DoctorStatus.PERMISSION_REQUIRED
    assert calls == [1]
    repair_store = doctor.repair_store
    assert repair_store is not None
    assert [item.number for item in repair_store.attempts(case_id)] == [1, 2]
    assert repair_store.attempts(case_id)[1].state == RepairAttemptState.PERMISSION_REQUIRED.value

    await _approve(broker, authenticator, Permission.REPAIR_EXECUTE)
    resumed = await doctor.run(_problem())
    assert resumed.status is DoctorStatus.REPAIRED
    assert calls == [1, 1]
    assert first.case_id == resumed.case_id
    assert [item.number for item in repair_store.attempts(case_id)] == [1, 2]
    doctor.close()


@pytest.mark.asyncio
async def test_effectful_fallback_always_requires_broker_and_domain_permission(
    tmp_path: Path,
) -> None:
    target = str(tmp_path / "fallback.txt")
    broker = PermissionBroker(_rules(path=target))
    authorizer = BrokeredRepairAuthorizer(broker, user_id="r2-user")
    calls: list[int] = []
    doctor = ComponentDoctor(
        CapabilityHealthService(clock=lambda: NOW),
        repair_store=SQLiteRepairStore(tmp_path / "fallback.sqlite3"),
        repair_authorizer=authorizer,
        clock=lambda: NOW,
    )
    doctor.register_playbook(_playbook(fallbacks=("fallback",)))

    def fallback(_problem: ComponentProblem) -> RepairExecution:
        calls.append(1)
        return RepairExecution(RepairEffectOutcome.EFFECT_CONFIRMED, True, "done")

    doctor.register_fallback(
        "r2.component",
        FallbackOption("fallback", "Fallback", required_permissions=(Permission.FILESYSTEM_WRITE,)),
        fallback,
        permission_scopes={Permission.FILESYSTEM_WRITE: PermissionScope(paths=(target,))},
    )
    result = await doctor.run(_problem())
    assert result.status is DoctorStatus.PERMISSION_REQUIRED
    assert calls == []
    assert {item.permission for item in await broker.pending_approvals()} == {
        Permission.REPAIR_EXECUTE,
        Permission.FILESYSTEM_WRITE,
    }
    doctor.close()


@pytest.mark.asyncio
async def test_fallback_lost_receipt_quarantines_and_quarantine_cannot_reopen(
    tmp_path: Path,
) -> None:
    broker = PermissionBroker(_rules(decision=Decision.ALLOW))
    authorizer = BrokeredRepairAuthorizer(broker, user_id="r2-user")
    calls: list[int] = []
    path = tmp_path / "quarantine.sqlite3"
    doctor = ComponentDoctor(
        CapabilityHealthService(clock=lambda: NOW),
        repair_store=SQLiteRepairStore(path),
        repair_authorizer=authorizer,
        research=lambda _problem: cast(Any, object()),
        clock=lambda: NOW,
    )
    doctor.register_playbook(_playbook(fallbacks=("fallback",)))

    def lost(_problem: ComponentProblem) -> RepairExecution:
        calls.append(1)
        raise RuntimeError("lost receipt")

    doctor.register_fallback("r2.component", FallbackOption("fallback", "Fallback"), lost)
    first = await doctor.run(_problem("one"))
    second = await doctor.run(_problem("two"))
    assert first.status is DoctorStatus.QUARANTINED
    assert second.status is DoctorStatus.QUARANTINED
    assert first.case_id == second.case_id
    assert calls == [1]
    repair_store = doctor.repair_store
    assert repair_store is not None
    assert len(repair_store.cases()) == 1
    doctor.close()

    restarted = ComponentDoctor(
        CapabilityHealthService(clock=lambda: NOW),
        repair_store=SQLiteRepairStore(path),
        repair_authorizer=authorizer,
        clock=lambda: NOW,
    )
    restarted.register_playbook(_playbook(fallbacks=("fallback",)))
    restarted.register_fallback("r2.component", FallbackOption("fallback", "Fallback"), lost)
    replay = await restarted.run(_problem("three"))
    assert replay.status is DoctorStatus.QUARANTINED
    assert replay.case_id == first.case_id
    assert calls == [1]
    restarted.close()


def _terminal_case(
    path: Path,
    status: RepairCaseStatus,
    outcome: str,
    state: str,
    *,
    action: str | None = "repair",
) -> tuple[SQLiteRepairStore, UUID]:
    store = SQLiteRepairStore(path)
    case, created = store.open_case(
        component_id="r2.component",
        owner="capability",
        failure_code="synthetic.failure",
        component_version=None,
        attempt_budget=2,
        now=NOW,
        failure_observation_id="terminal-observation",
    )
    assert created
    store.update(
        case,
        status=status,
        attempt_count=1,
        selected_action=action,
        effect_outcome=outcome,
        verification_reference="probe:state"
        if status is RepairCaseStatus.VERIFIED_REPAIRED
        else None,
        fallback="fallback" if status is RepairCaseStatus.DEGRADED_FALLBACK else None,
        terminal_reason="terminal",
    )
    store.save_attempt(RepairAttemptRecord(case.case_id, 1, state, outcome, "terminal", NOW, NOW))
    return store, case.case_id


def test_fallback_is_not_success_but_failure_and_unknown_remain_factual(
    tmp_path: Path,
) -> None:
    authority = ProcedureEvidenceAuthority(cast(Any, object()))
    degraded, degraded_id = _terminal_case(
        tmp_path / "degraded.sqlite3",
        RepairCaseStatus.DEGRADED_FALLBACK,
        RepairEffectOutcome.EFFECT_CONFIRMED.value,
        "degraded",
        action="fallback",
    )
    with pytest.raises(WorkflowTemplateError):
        authority.issue_reliability_from_repair(degraded, degraded_id)

    verified, verified_id = _terminal_case(
        tmp_path / "verified.sqlite3",
        RepairCaseStatus.VERIFIED_REPAIRED,
        RepairEffectOutcome.EFFECT_CONFIRMED.value,
        "verified",
    )
    assert (
        authority.issue_reliability_from_repair(verified, verified_id).outcome.value
        == RepairEffectOutcome.EFFECT_CONFIRMED.value
    )

    failed, failed_id = _terminal_case(
        tmp_path / "failed.sqlite3",
        RepairCaseStatus.FAILED,
        RepairEffectOutcome.PRE_EFFECT_FAILURE.value,
        "failed",
    )
    assert (
        authority.issue_reliability_from_repair(failed, failed_id).outcome.value
        == RepairEffectOutcome.PRE_EFFECT_FAILURE.value
    )

    unknown, unknown_id = _terminal_case(
        tmp_path / "unknown.sqlite3",
        RepairCaseStatus.QUARANTINED,
        RepairEffectOutcome.UNKNOWN_OUTCOME.value,
        "unknown",
    )
    assert (
        authority.issue_reliability_from_repair(unknown, unknown_id).outcome.value
        == RepairEffectOutcome.UNKNOWN_OUTCOME.value
    )
    degraded.close()
    verified.close()
    failed.close()
    unknown.close()
