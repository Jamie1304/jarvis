from __future__ import annotations

import asyncio
import sqlite3
from collections.abc import Mapping
from datetime import UTC, datetime, timedelta
from pathlib import Path
from uuid import uuid4

import pytest
from jarvis.permissions.broker import PermissionBroker
from jarvis.permissions.models import Decision, Permission, PolicyRule, ScopeConstraint
from jarvis.permissions.policy import PolicyEngine
from jarvis.provisioning import (
    BrokerProvisioningAuthorizer,
    ProvisioningAction,
    ProvisioningActionKind,
    ProvisioningActionResult,
    ProvisioningActionState,
    ProvisioningApplyResult,
    ProvisioningArtifact,
    ProvisioningDenied,
    ProvisioningEffectOutcome,
    ProvisioningEngine,
    ProvisioningError,
    ProvisioningObservation,
    ProvisioningPlan,
    ProvisioningPlanState,
    ProvisioningRollbackPlan,
    ProvisioningValidationError,
    SQLiteProvisioningStore,
)


class Authorizer:
    def __init__(self) -> None:
        self.authorized: list[str] = []
        self.finished: list[ProvisioningEffectOutcome] = []

    async def authorize(self, plan: ProvisioningPlan, action: ProvisioningAction) -> object:
        self.authorized.append(action.action_id)
        return (plan.plan_id, action.action_id)

    async def begin(self, receipt: object) -> None:
        assert isinstance(receipt, tuple)

    async def finish(self, receipt: object, outcome: ProvisioningEffectOutcome) -> None:
        assert isinstance(receipt, tuple)
        self.finished.append(outcome)


class Provider:
    def __init__(self, *, satisfied: bool = False, partial: bool = False) -> None:
        self.satisfied = satisfied
        self.partial = partial
        self.safe_to_retry = False
        self.apply_calls = 0
        self.rollback_calls = 0
        self.next_result = ProvisioningEffectOutcome.EFFECT_CONFIRMED
        self.artifact_hashes: tuple[str, ...] = ()

    async def inspect(self, action: ProvisioningAction) -> ProvisioningObservation:
        return ProvisioningObservation(
            self.satisfied,
            self.partial,
            self.safe_to_retry,
            "fixture reality",
            self.artifact_hashes,
        )

    async def apply(
        self, action: ProvisioningAction, cancellation: asyncio.Event
    ) -> ProvisioningApplyResult:
        del action
        if cancellation.is_set():
            raise asyncio.CancelledError
        self.apply_calls += 1
        outcome = self.next_result
        if outcome is ProvisioningEffectOutcome.EFFECT_CONFIRMED:
            self.satisfied = True
        return ProvisioningApplyResult(
            outcome,
            ProvisioningObservation(
                self.satisfied,
                artifact_hashes=self.artifact_hashes,
                evidence="applied",
            ),
            "fixture apply",
        )

    async def rollback(
        self, action: ProvisioningAction, cancellation: asyncio.Event
    ) -> ProvisioningApplyResult:
        del action, cancellation
        self.rollback_calls += 1
        self.satisfied = False
        return ProvisioningApplyResult(
            ProvisioningEffectOutcome.EFFECT_CONFIRMED,
            ProvisioningObservation(False, evidence="rolled back"),
            "fixture rollback",
        )

    async def health_check(self, action: ProvisioningAction) -> bool:
        del action
        return self.satisfied


def action(
    action_id: str = "write",
    *,
    kind: ProvisioningActionKind = ProvisioningActionKind.WRITE_CONFIG,
    provider_id: str = "fixture",
    parameters: Mapping[str, object] | None = None,
    artifacts: tuple[ProvisioningArtifact, ...] = (),
    idempotent: bool = True,
    undoes_action_id: str | None = None,
    permission: Permission = Permission.FILESYSTEM_WRITE,
    paths: tuple[str, ...] = ("C:/approved",),
    disk_bytes: int = 0,
    expected_state: Mapping[str, object] | None = None,
    non_idempotent_reason: str | None = None,
) -> ProvisioningAction:
    return ProvisioningAction(
        action_id,
        provider_id,
        kind,
        "fixture.target",
        parameters or {"mode": "safe"},
        permission,
        paths=paths,
        disk_bytes=disk_bytes,
        artifacts=artifacts,
        idempotent=idempotent,
        non_idempotent_reason=(
            non_idempotent_reason
            if non_idempotent_reason is not None
            else (None if idempotent else "provider cannot repeat this operation")
        ),
        expected_state=expected_state if expected_state is not None else {},
        undoes_action_id=undoes_action_id,
    )


def plan(
    actions: tuple[ProvisioningAction, ...],
    *,
    rollback: ProvisioningRollbackPlan | None = None,
    max_attempts: int = 1,
) -> ProvisioningPlan:
    now = datetime.now(UTC)
    return ProvisioningPlan(
        uuid4(), uuid4(), actions, now, now + timedelta(minutes=5), rollback, max_attempts
    )


@pytest.mark.asyncio
async def test_already_satisfied_does_not_request_approval_or_apply() -> None:
    provider = Provider(satisfied=True)
    auth = Authorizer()
    result = await ProvisioningEngine({"fixture": provider}, auth).run(plan((action(),)))
    assert result.state is ProvisioningPlanState.VERIFIED
    assert result.actions[0].state is ProvisioningActionState.ALREADY_SATISFIED
    assert provider.apply_calls == 0
    assert auth.authorized == []


@pytest.mark.asyncio
async def test_provisioning_store_survives_restart_and_refuses_future_schema(
    tmp_path: Path,
) -> None:
    database = tmp_path / "provisioning.sqlite3"
    provider = Provider()
    store = SQLiteProvisioningStore(database)
    current_plan = plan((action(),))
    result = await ProvisioningEngine({"fixture": provider}, Authorizer(), store=store).run(
        current_plan
    )
    assert result.state is ProvisioningPlanState.VERIFIED
    store.close()

    reopened = SQLiteProvisioningStore(database)
    persisted = reopened.load(current_plan.plan_id)
    assert persisted["write"].state is ProvisioningActionState.VERIFIED
    reopened.close()

    future = tmp_path / "future-provisioning.sqlite3"
    with sqlite3.connect(future) as connection:
        connection.execute(
            "CREATE TABLE provisioning_schema(version INTEGER PRIMARY KEY, name TEXT NOT NULL)"
        )
        connection.execute("INSERT INTO provisioning_schema(version, name) VALUES (99, 'future')")
    with pytest.raises(ProvisioningError, match="future schema"):
        SQLiteProvisioningStore(future)


@pytest.mark.asyncio
async def test_partial_previous_install_is_inspected_then_applied_once() -> None:
    provider = Provider(partial=True)
    auth = Authorizer()
    result = await ProvisioningEngine({"fixture": provider}, auth).run(plan((action(),)))
    assert result.state is ProvisioningPlanState.VERIFIED
    assert provider.apply_calls == 1
    assert result.actions[0].detail == "fixture apply"


@pytest.mark.asyncio
async def test_unknown_outcome_requires_safe_recovery_before_reapply() -> None:
    provider = Provider()
    provider.next_result = ProvisioningEffectOutcome.UNKNOWN_OUTCOME
    auth = Authorizer()
    engine = ProvisioningEngine({"fixture": provider}, auth)
    current_plan = plan((action(),), max_attempts=2)
    first = await engine.run(current_plan)
    assert first.state is ProvisioningPlanState.RECOVERING
    assert provider.apply_calls == 1
    second = await engine.run(current_plan, resume=True)
    assert second.state is ProvisioningPlanState.RECOVERING
    assert provider.apply_calls == 1
    provider.safe_to_retry = True
    provider.next_result = ProvisioningEffectOutcome.EFFECT_CONFIRMED
    final = await engine.run(current_plan, resume=True)
    assert final.state is ProvisioningPlanState.VERIFIED
    assert provider.apply_calls == 2


@pytest.mark.asyncio
async def test_checksum_mismatch_fails_before_effect() -> None:
    expected = "a" * 64
    provider = Provider()
    provider.artifact_hashes = ("b" * 64,)
    auth = Authorizer()
    result = await ProvisioningEngine({"fixture": provider}, auth).run(
        plan((action(artifacts=(ProvisioningArtifact("download.bin", expected, 12),)),))
    )
    assert result.state is ProvisioningPlanState.FAILED
    assert result.actions[0].detail == "artifact checksum mismatch"
    assert provider.apply_calls == 0


@pytest.mark.asyncio
async def test_failure_rolls_back_completed_actions_in_typed_plan() -> None:
    first_provider = Provider()
    second_provider = Provider()
    second_provider.next_result = ProvisioningEffectOutcome.PRE_EFFECT_FAILURE
    first = action("first")
    second = action("second", provider_id="fixture2", parameters={"mode": "second"})
    rollback_action = action(
        "rollback-first", kind=ProvisioningActionKind.ROLLBACK, undoes_action_id="first"
    )
    current_plan = plan((first, second))
    # Bind the rollback plan to the exact source plan as required by the contract.
    current_plan = ProvisioningPlan(
        current_plan.plan_id,
        current_plan.task_id,
        current_plan.actions,
        current_plan.created_at,
        current_plan.expires_at,
        ProvisioningRollbackPlan(
            current_plan.plan_id, (rollback_action,), "restore previous state"
        ),
    )
    result = await ProvisioningEngine(
        {"fixture": first_provider, "fixture2": second_provider}, Authorizer()
    ).run(current_plan)
    assert result.state is ProvisioningPlanState.ROLLED_BACK
    assert first_provider.rollback_calls == 1


@pytest.mark.asyncio
async def test_unsupported_provider_and_retry_exhaustion_are_safe() -> None:
    auth = Authorizer()
    missing = await ProvisioningEngine({"fixture": Provider()}, auth).run(
        plan((action(provider_id="missing"),))
    )
    assert missing.state is ProvisioningPlanState.FAILED
    provider = Provider()
    provider.next_result = ProvisioningEffectOutcome.SAFE_TO_RETRY
    engine = ProvisioningEngine({"fixture": provider}, auth)
    current = plan((action(),), max_attempts=1)
    exhausted = await engine.run(current)
    assert exhausted.state is ProvisioningPlanState.FAILED
    exhausted = await engine.run(current, resume=True)
    assert exhausted.actions[0].detail == "retry exhaustion"


@pytest.mark.asyncio
async def test_safe_retry_non_idempotent_becomes_recovering() -> None:
    provider = Provider()
    provider.next_result = ProvisioningEffectOutcome.SAFE_TO_RETRY
    engine = ProvisioningEngine({"fixture": provider}, Authorizer())
    current = plan((action(idempotent=False),), max_attempts=2)
    assert (await engine.run(current)).state is ProvisioningPlanState.FAILED
    assert (await engine.run(current, resume=True)).state is ProvisioningPlanState.RECOVERING


class MismatchAfterApplyProvider(Provider):
    async def apply(
        self, action: ProvisioningAction, cancellation: asyncio.Event
    ) -> ProvisioningApplyResult:
        result = await super().apply(action, cancellation)
        return ProvisioningApplyResult(
            result.outcome,
            ProvisioningObservation(True, artifact_hashes=("b" * 64,)),
            result.detail,
        )


@pytest.mark.asyncio
async def test_post_effect_checksum_mismatch_fails_before_verified() -> None:
    expected = "a" * 64
    provider = MismatchAfterApplyProvider()
    provider.artifact_hashes = (expected,)
    result = await ProvisioningEngine({"fixture": provider}, Authorizer()).run(
        plan((action(artifacts=(ProvisioningArtifact("x", expected),)),))
    )
    assert result.state is ProvisioningPlanState.FAILED
    assert result.actions[-1].detail == "artifact checksum mismatch"


@pytest.mark.asyncio
async def test_broker_authorizer_binds_exact_permission_scope_and_fingerprint() -> None:
    broker = PermissionBroker(
        PolicyEngine(
            (
                PolicyRule(
                    "provisioning.test",
                    Permission.FILESYSTEM_WRITE,
                    Decision.ALLOW,
                    ScopeConstraint(paths=("C:/approved",)),
                    frozenset({"provisioning.write_config.write"}),
                ),
            )
        )
    )
    provider = Provider()
    result = await ProvisioningEngine(
        {"fixture": provider}, BrokerProvisioningAuthorizer(broker)
    ).run(plan((action(),)))
    assert result.state is ProvisioningPlanState.VERIFIED
    assert provider.apply_calls == 1


def test_typed_plan_rejects_non_idempotent_without_reason_and_raw_secrets() -> None:
    with pytest.raises(ProvisioningValidationError):
        action(idempotent=False, parameters={"token": "secret"})
    with pytest.raises(ProvisioningValidationError):
        ProvisioningObservation(True, True)


def test_typed_contract_rejects_malformed_metadata() -> None:
    with pytest.raises(ProvisioningValidationError):
        ProvisioningArtifact("x", "not-a-hash")
    with pytest.raises(ProvisioningValidationError):
        action(parameters={"bad key!": "value"})
    with pytest.raises(ProvisioningValidationError):
        action(kind=ProvisioningActionKind.ROLLBACK)
    with pytest.raises(ProvisioningValidationError):
        action(undoes_action_id="write")
    with pytest.raises(ProvisioningValidationError):
        ProvisioningApplyResult("bad")  # type: ignore[arg-type]
    with pytest.raises(ProvisioningValidationError):
        ProvisioningObservation(False, evidence="\n")
    with pytest.raises(ProvisioningValidationError):
        ProvisioningObservation(False, artifact_hashes=("bad",))
    with pytest.raises(ProvisioningValidationError):
        action(parameters={"values": [object()]})
    with pytest.raises(ProvisioningValidationError):
        action(parameters={"values": [float("nan")]})
    with pytest.raises(ProvisioningValidationError):
        action(parameters={"values": ["x"] * 257})
    with pytest.raises(ProvisioningValidationError):
        action(parameters={"values": "x" * 70_000})
    with pytest.raises(ProvisioningValidationError):
        action(parameters={str(index): index for index in range(257)})
    with pytest.raises(ProvisioningValidationError):
        action(parameters={"nested": _deep_mapping(18)})
    with pytest.raises(ProvisioningValidationError):
        ProvisioningAction(
            "bad-parameters",
            "fixture",
            ProvisioningActionKind.WRITE_CONFIG,
            "fixture.target",
            [],  # type: ignore[arg-type]
            Permission.FILESYSTEM_WRITE,
        )
    with pytest.raises(ProvisioningValidationError):
        action(expected_state=[])  # type: ignore[arg-type]
    with pytest.raises(ProvisioningValidationError):
        action(permission="filesystem.write")  # type: ignore[arg-type]
    with pytest.raises(ProvisioningValidationError):
        action(paths=["C:/bad"])  # type: ignore[arg-type]
    with pytest.raises(ProvisioningValidationError):
        action(disk_bytes=-1)
    with pytest.raises(ProvisioningValidationError):
        action(idempotent=False, non_idempotent_reason="")
    with pytest.raises(ProvisioningValidationError):
        ProvisioningArtifact("x", "a" * 64, -1)


def _deep_mapping(depth: int) -> dict[str, object]:
    value: dict[str, object] = {}
    for _ in range(depth):
        value = {"nested": value}
    return value


def test_plan_and_rollback_bindings_are_strict() -> None:
    current = plan((action(),))
    rollback = action("undo", kind=ProvisioningActionKind.ROLLBACK, undoes_action_id="write")
    with pytest.raises(ProvisioningValidationError):
        ProvisioningRollbackPlan(current.plan_id, (action(),), "bad")
    with pytest.raises(ProvisioningValidationError):
        ProvisioningRollbackPlan(current.plan_id, (), "bad")
    with pytest.raises(ProvisioningValidationError):
        ProvisioningPlan(
            current.plan_id,
            current.task_id,
            current.actions,
            current.created_at,
            current.expires_at,
            ProvisioningRollbackPlan(uuid4(), (rollback,), "wrong plan"),
        )
    with pytest.raises(ProvisioningValidationError):
        ProvisioningPlan(
            current.plan_id,
            current.task_id,
            (
                action(
                    "a",
                    parameters={"x": 1},
                ),
                action("a", parameters={"x": 2}),
            ),
            current.created_at,
            current.expires_at,
        )
    with pytest.raises(ProvisioningValidationError):
        ProvisioningPlan(
            current.plan_id,
            current.task_id,
            current.actions,
            current.created_at,
            current.expires_at,
            max_attempts=4,
        )


class BrokenProvider(Provider):
    def __init__(self, mode: str) -> None:
        super().__init__()
        self.mode = mode

    async def inspect(self, action: ProvisioningAction) -> ProvisioningObservation:
        if self.mode == "inspect":
            raise RuntimeError("inspection unavailable")
        return await super().inspect(action)

    async def apply(
        self, action: ProvisioningAction, cancellation: asyncio.Event
    ) -> ProvisioningApplyResult:
        if self.mode == "cancel":
            raise asyncio.CancelledError
        if self.mode == "exception":
            raise RuntimeError("provider crashed")
        if self.mode == "health":
            self.satisfied = True
        return await super().apply(action, cancellation)

    async def health_check(self, action: ProvisioningAction) -> bool:
        return self.mode != "health"


@pytest.mark.asyncio
async def test_engine_rejects_expired_interrupted_cancelled_and_provider_failures() -> None:
    current = plan((action(),))
    expired = ProvisioningPlan(
        current.plan_id,
        current.task_id,
        current.actions,
        current.created_at - timedelta(minutes=10),
        current.created_at - timedelta(minutes=1),
    )
    with pytest.raises(ProvisioningError, match="expired"):
        await ProvisioningEngine({"fixture": Provider()}, Authorizer()).run(expired)
    engine = ProvisioningEngine({"fixture": Provider()}, Authorizer())
    engine._states[current.plan_id] = {
        "write": ProvisioningActionResult(
            "write", ProvisioningActionState.APPLYING, None, "interrupted", 1
        )
    }
    with pytest.raises(ProvisioningError, match="explicit resume"):
        await engine.run(current)
    cancel = asyncio.Event()
    cancel.set()
    cancelled = await ProvisioningEngine({"fixture": Provider()}, Authorizer()).run(
        current, cancellation=cancel
    )
    assert cancelled.state is ProvisioningPlanState.RECOVERING
    for mode in ("inspect", "exception", "cancel"):
        result = await ProvisioningEngine({"fixture": BrokenProvider(mode)}, Authorizer()).run(
            current
        )
        expected = (
            ProvisioningPlanState.RECOVERING if mode != "inspect" else ProvisioningPlanState.FAILED
        )
        assert result.state is expected


@pytest.mark.asyncio
async def test_engine_verification_and_dependency_failures_are_fail_closed() -> None:
    provider = BrokenProvider("health")
    result = await ProvisioningEngine({"fixture": provider}, Authorizer()).run(plan((action(),)))
    assert result.state is ProvisioningPlanState.FAILED
    dependency = action("dependency")
    dependent = ProvisioningAction(
        "dependent",
        "fixture",
        ProvisioningActionKind.WRITE_CONFIG,
        "fixture.target",
        {"mode": "dependent"},
        Permission.FILESYSTEM_WRITE,
        paths=("C:/approved",),
        depends_on=(dependency.action_id,),
    )
    engine = ProvisioningEngine({"fixture": Provider()}, Authorizer())
    engine._states[uuid4()] = {}  # exercise no-op state initialization
    result = await engine.run(plan((dependent, dependency)))
    assert result.state is ProvisioningPlanState.FAILED


@pytest.mark.asyncio
async def test_broker_authorizer_denies_malformed_receipts_and_unapproved_actions() -> None:
    broker = PermissionBroker(PolicyEngine(()))
    authorizer = BrokerProvisioningAuthorizer(broker)
    current = plan((action(),))
    with pytest.raises(ProvisioningDenied):
        await authorizer.authorize(current, current.actions[0])
    with pytest.raises(ProvisioningDenied):
        await authorizer.begin(object())
    with pytest.raises(ProvisioningDenied):
        await authorizer.finish(object(), ProvisioningEffectOutcome.PRE_EFFECT_FAILURE)
    with pytest.raises(ProvisioningValidationError):
        BrokerProvisioningAuthorizer(object())  # type: ignore[arg-type]
