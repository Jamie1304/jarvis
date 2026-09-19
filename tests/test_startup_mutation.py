"""Deterministic authority and exact-effect tests for the R3C startup route."""

import asyncio
import json
import sys
from collections.abc import Coroutine, Mapping
from dataclasses import asdict, replace
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any, TypeVar, cast
from uuid import UUID, uuid4

import pytest
from jarvis.permissions import (
    ApprovalActorKind,
    ApprovalChoice,
    ApprovalIdentity,
    ApprovalSource,
    AuthorizationReceipt,
    Decision,
    DecisionReason,
    Permission,
    PermissionBroker,
    PermissionRequest,
    PermissionScope,
    PolicyEngine,
    PolicyRule,
    SafetyClass,
    ScopeConstraint,
    TrustedApprovalAuthenticator,
)
from jarvis.permissions.policy import normalize_scope
from jarvis.startup_mutation import (
    InMemoryStartupRegistry,
    StartupEffectFailure,
    StartupMutationConflict,
    StartupMutationDenied,
    StartupMutationError,
    StartupMutationRecord,
    StartupMutationService,
    StartupMutationState,
    StartupMutationStore,
    StartupMutationUnknownOutcome,
    UnsupportedMutationSource,
    WindowsRegistryStartupBackend,
    WindowsStartupMutationProvider,
)
from jarvis.system_stewardship import (
    StaleStewardshipPlan,
    StartupEntryEvidence,
    StartupHealthService,
    StartupMutationPlan,
    StartupProviderError,
    StewardshipError,
    SystemStewardshipComposition,
    WindowsStartupProvider,
)
from jarvis.vm.bridge import HostBridge, HostBridgeRequest, HostBridgeResult

NOW = datetime(2026, 9, 19, 12, 0, tzinfo=UTC)
T = TypeVar("T")
RUN = ("current-user", r"Software\Microsoft\Windows\CurrentVersion\Run")
RUN_ONCE = ("current-user", r"Software\Microsoft\Windows\CurrentVersion\RunOnce")
MACHINE_RUN = ("machine", r"Software\Microsoft\Windows\CurrentVersion\Run")


def run(awaitable: Coroutine[Any, Any, T]) -> T:
    return asyncio.run(awaitable)


class DenyingBridge(HostBridge):
    def authorize_with_receipt(
        self,
        request: HostBridgeRequest,
        *,
        receipt: AuthorizationReceipt | None,
        broker: PermissionBroker,
        normalized_arguments: Mapping[str, object],
        expected_instance_id: UUID,
    ) -> HostBridgeResult:
        result = super().authorize_with_receipt(
            request,
            receipt=receipt,
            broker=broker,
            normalized_arguments=normalized_arguments,
            expected_instance_id=expected_instance_id,
        )
        return replace(result, allowed=False, reason="test bridge denial")


def make_service(
    tmp_path: Path,
    *,
    source: tuple[str, str] = RUN,
    bridge: HostBridge | None = None,
) -> tuple[
    StartupMutationService,
    InMemoryStartupRegistry,
    PermissionBroker,
    TrustedApprovalAuthenticator,
    str,
]:
    registry = InMemoryStartupRegistry()
    name = "JARVIS_Qualification"
    registry.values[source] = {name: ("C:\\Windows\\System32\\cmd.exe /c exit 0", 1)}
    entry_id = WindowsStartupProvider.entry_id(*source, name)
    broker, authenticator = make_broker(entry_id)
    provider = WindowsStartupMutationProvider(backend=registry)
    startup = StartupHealthService(provider.observer, clock=lambda: NOW)
    service = StartupMutationService(
        startup,
        provider,
        StartupMutationStore(tmp_path / "startup-state.json"),
        broker,
        bridge or HostBridge(),
        clock=lambda: NOW,
    )
    return service, registry, broker, authenticator, entry_id


def make_broker(
    entry_id: str,
) -> tuple[PermissionBroker, TrustedApprovalAuthenticator]:
    policy = PolicyEngine(
        (
            PolicyRule(
                "startup-test-policy",
                Permission.STARTUP_WRITE,
                # SYSTEM_CONFIGURATION still forces the trusted approval path.
                Decision.ALLOW,
                ScopeConstraint(
                    startup_entries=(entry_id,),
                    tools=frozenset({"system.startup"}),
                ),
                frozenset({"system.startup.disable", "system.startup.restore"}),
            ),
        )
    )
    authenticator = TrustedApprovalAuthenticator(ApprovalSource.TRUSTED_LOCAL_API)
    return (
        PermissionBroker(policy, approval_context_verifier=authenticator.verifier()),
        authenticator,
    )


def approve(
    service: StartupMutationService,
    broker: PermissionBroker,
    authenticator: TrustedApprovalAuthenticator,
    plan: StartupMutationPlan,
    *,
    choice: ApprovalChoice = ApprovalChoice.APPROVE_ONCE,
) -> AuthorizationReceipt:
    pending = run(service.authorize(plan))
    assert pending.approval_requests
    request = pending.approval_requests[0]
    context = authenticator.issue_context(
        request_id=request.request_id,
        choice=choice,
        identity=ApprovalIdentity("trusted-test-user", ApprovalActorKind.TRUSTED_USER),
    )
    decision = run(broker.decide(context))
    assert decision.accepted
    authorized = run(service.authorize(plan))
    assert authorized.authorized and authorized.receipt is not None
    return authorized.receipt


def test_exact_disable_restore_and_restart_reopen(tmp_path: Path) -> None:
    service, registry, broker, authenticator, entry_id = make_service(tmp_path)
    plan = run(service.plan_disable(entry_id))
    receipt = approve(service, broker, authenticator, plan)
    result = run(service.execute(plan, receipt))
    assert result.state is StartupMutationState.DISABLED
    assert registry.effect_calls == [("delete", RUN[0], "JARVIS_Qualification")]

    restart_broker, restart_authenticator = make_broker(entry_id)
    restart_provider = WindowsStartupMutationProvider(backend=registry)
    restarted = StartupMutationService(
        StartupHealthService(restart_provider.observer, clock=lambda: NOW),
        restart_provider,
        StartupMutationStore(tmp_path / "startup-state.json"),
        restart_broker,
        HostBridge(),
        clock=lambda: NOW,
    )
    restore_plan = run(restarted.plan_restore(result.mutation_id))
    restore_receipt = approve(restarted, restart_broker, restart_authenticator, restore_plan)
    restored = run(restarted.execute(restore_plan, restore_receipt))
    assert restored.state is StartupMutationState.RESTORED
    assert registry.effect_calls[-1] == ("set", RUN[0], "JARVIS_Qualification")
    assert run(restarted.reconcile()) == ()


def test_machine_and_runonce_sources_are_read_only(tmp_path: Path) -> None:
    for source in (MACHINE_RUN, RUN_ONCE):
        service, registry, broker, authenticator, entry_id = make_service(
            tmp_path / source[0], source=source
        )
        plan = run(service.plan_disable(entry_id))
        receipt = approve(service, broker, authenticator, plan)
        with pytest.raises(UnsupportedMutationSource):
            run(service.execute(plan, receipt))
        assert registry.effect_calls == []


def test_policy_missing_and_denied_approval_have_zero_effect(tmp_path: Path) -> None:
    service, registry, broker, authenticator, entry_id = make_service(tmp_path)
    plan = run(service.plan_disable(entry_id))
    pending = run(service.authorize(plan))
    assert not pending.authorized and pending.approval_requests
    request = pending.approval_requests[0]
    denied = authenticator.issue_context(
        request_id=request.request_id,
        choice=ApprovalChoice.DENY_ONCE,
        identity=ApprovalIdentity("trusted-test-user", ApprovalActorKind.TRUSTED_USER),
    )
    assert run(broker.decide(denied)).accepted
    assert not run(service.authorize(plan)).authorized
    assert registry.effect_calls == []


def test_toctou_change_is_stale_before_effect(tmp_path: Path) -> None:
    service, registry, broker, authenticator, entry_id = make_service(tmp_path)
    plan = run(service.plan_disable(entry_id))
    receipt = approve(service, broker, authenticator, plan)
    registry.values[RUN]["JARVIS_Qualification"] = ("C:\\changed.exe", 1)
    with pytest.raises(Exception, match="stale|matches"):
        run(service.execute(plan, receipt))
    assert registry.effect_calls == []


def test_receipt_replay_and_mismatched_entry_are_denied(tmp_path: Path) -> None:
    service, registry, broker, authenticator, entry_id = make_service(tmp_path)
    plan = run(service.plan_disable(entry_id))
    receipt = approve(service, broker, authenticator, plan)
    run(service.execute(plan, receipt))
    with pytest.raises(StartupMutationDenied):
        run(service.execute(plan, receipt))
    assert registry.effect_calls.count(("delete", RUN[0], "JARVIS_Qualification")) == 1


def test_host_bridge_denial_has_zero_effect(tmp_path: Path) -> None:
    service, registry, broker, authenticator, entry_id = make_service(
        tmp_path, bridge=DenyingBridge()
    )
    plan = run(service.plan_disable(entry_id))
    receipt = approve(service, broker, authenticator, plan)
    with pytest.raises(StartupMutationError, match="bridge"):
        run(service.execute(plan, receipt))
    assert registry.effect_calls == []


def test_unknown_outcome_reconciles_without_replay(tmp_path: Path) -> None:
    service, registry, broker, authenticator, entry_id = make_service(tmp_path)
    plan = run(service.plan_disable(entry_id))
    receipt = approve(service, broker, authenticator, plan)
    registry.fail_delete = StartupEffectFailure(
        "delete acknowledgement lost", effect_may_have_started=True
    )
    with pytest.raises(StartupMutationUnknownOutcome):
        run(service.execute(plan, receipt))
    assert service.store.all()[0].state is StartupMutationState.UNKNOWN_OUTCOME
    assert run(service.reconcile())[0].state is StartupMutationState.DISABLED
    assert len(registry.effect_calls) == 1


def test_durable_record_tamper_fails_closed(tmp_path: Path) -> None:
    service, registry, broker, authenticator, entry_id = make_service(tmp_path)
    plan = run(service.plan_disable(entry_id))
    receipt = approve(service, broker, authenticator, plan)
    run(service.execute(plan, receipt))
    state = tmp_path / "startup-state.json"
    state.write_text(
        state.read_text(encoding="utf-8").replace("JARVIS_Qualification", "Forged"),
        encoding="utf-8",
    )
    with pytest.raises(StartupMutationError, match="integrity"):
        service.store.all()
    assert registry.effect_calls == [("delete", RUN[0], "JARVIS_Qualification")]


def test_startup_scope_is_exact_and_fail_closed() -> None:
    task_id = uuid4()
    with pytest.raises(ValueError):
        normalize_scope(
            PermissionScope(startup_entries=("\x00",), task_id=task_id, tool_id="system.startup"),
            Permission.STARTUP_WRITE,
        )
    with pytest.raises(ValueError):
        normalize_scope(
            PermissionScope(startup_entries=("*",), task_id=task_id, tool_id="system.startup"),
            Permission.STARTUP_WRITE,
        )
    with pytest.raises(ValueError):
        normalize_scope(
            PermissionScope(task_id=task_id, tool_id="system.startup"),
            Permission.STARTUP_WRITE,
        )
    policy = PolicyEngine(
        (
            PolicyRule(
                "startup-scope",
                Permission.STARTUP_WRITE,
                Decision.ALLOW,
                ScopeConstraint(startup_entries=("startup:a",)),
                frozenset({"system.startup.disable"}),
            ),
        )
    )
    evaluation = policy.evaluate(
        PermissionRequest(
            Permission.STARTUP_WRITE,
            PermissionScope(
                startup_entries=("startup:b",), task_id=task_id, tool_id="system.startup"
            ),
        ),
        action="system.startup.disable",
        safety_class=SafetyClass.SYSTEM_CONFIGURATION,
    )
    assert evaluation.reason is DecisionReason.SCOPE_OUTSIDE_POLICY


def test_backend_native_boundary_success_and_failures(monkeypatch: pytest.MonkeyPatch) -> None:
    class Key:
        def __enter__(self) -> "Key":
            return self

        def __exit__(self, *args: object) -> None:
            return None

    class FakeWinreg:
        HKEY_CURRENT_USER = 1
        HKEY_LOCAL_MACHINE = 2
        KEY_READ = 4
        KEY_SET_VALUE = 8
        REG_SZ = 1
        REG_EXPAND_SZ = 2
        values = [("Entry", "C:\\safe.exe", 1)]
        open_error: BaseException | None = None
        enum_error: BaseException | None = None
        deleted: list[str] = []
        set_values: list[tuple[str, int]] = []

        @classmethod
        def OpenKey(cls, hive: int, path: str, reserved: int, access: int) -> Key:
            del hive, path, reserved, access
            if cls.open_error is not None:
                raise cls.open_error
            return Key()

        @classmethod
        def EnumValue(cls, key: Key, index: int) -> tuple[str, str, int]:
            del key
            if cls.enum_error is not None:
                raise cls.enum_error
            if index >= len(cls.values):
                raise OSError("end")
            return cls.values[index]

        @classmethod
        def DeleteValue(cls, key: Key, name: str) -> None:
            del key
            cls.deleted.append(name)

        @classmethod
        def SetValueEx(
            cls, key: Key, name: str, reserved: int, value_type: int, value: str
        ) -> None:
            del key, name, reserved
            cls.set_values.append((value, value_type))

    monkeypatch.setitem(sys.modules, "winreg", FakeWinreg)
    backend = WindowsRegistryStartupBackend()
    assert backend.read(*RUN) == (("Entry", "C:\\safe.exe", 1),)
    backend.delete(*RUN, "Entry")
    backend.set(*RUN, "Entry", "C:\\safe.exe", 1)
    assert FakeWinreg.deleted == ["Entry"]
    assert FakeWinreg.set_values == [("C:\\safe.exe", 1)]
    FakeWinreg.open_error = FileNotFoundError()
    assert backend.read(*RUN) == ()
    FakeWinreg.open_error = OSError("offline")
    with pytest.raises(StartupProviderError):
        backend.read(*RUN)
    FakeWinreg.open_error = None
    FakeWinreg.values = [("Entry", "C:\\safe.exe", 99)]
    with pytest.raises(StartupProviderError):
        backend.read(*RUN)
    FakeWinreg.values = [("Entry", "C:\\safe.exe", 1)]
    FakeWinreg.open_error = FileNotFoundError()
    with pytest.raises(StaleStewardshipPlan):
        backend.delete(*RUN, "Entry")
    with pytest.raises(StaleStewardshipPlan):
        backend.set(*RUN, "Entry", "C:\\safe.exe", 1)
    FakeWinreg.open_error = OSError("denied")
    with pytest.raises(StartupMutationError):
        backend.delete(*RUN, "Entry")
    with pytest.raises(StartupMutationError):
        backend.set(*RUN, "Entry", "C:\\safe.exe", 1)
    with pytest.raises(UnsupportedMutationSource):
        backend.read("unknown", "source")


def test_restore_collision_and_expired_plan_do_not_effect(tmp_path: Path) -> None:
    service, registry, broker, authenticator, entry_id = make_service(tmp_path)
    plan = run(service.plan_disable(entry_id))
    receipt = approve(service, broker, authenticator, plan)
    run(service.execute(plan, receipt))
    registry.values[RUN]["JARVIS_Qualification"] = ("C:\\different.exe", 1)
    with pytest.raises(StartupMutationConflict):
        run(service.plan_restore(service.store.all()[0].mutation_id))
    del registry.values[RUN]["JARVIS_Qualification"]
    registry.values[RUN]["JARVIS_Qualification"] = (
        "C:\\Windows\\System32\\cmd.exe /c exit 0",
        1,
    )
    fresh_plan = run(service.plan_disable(entry_id))
    expired = replace(
        fresh_plan,
        planned_at=NOW - timedelta(seconds=2),
        expires_at=NOW - timedelta(seconds=1),
    )
    expired_receipt = approve(service, broker, authenticator, expired)
    with pytest.raises(StartupMutationDenied):
        run(service.execute(expired, expired_receipt))
    assert registry.effect_calls.count(("delete", RUN[0], "JARVIS_Qualification")) == 1


def test_private_record_roundtrip_and_malformed_state_fail_closed(tmp_path: Path) -> None:
    service, registry, broker, authenticator, entry_id = make_service(tmp_path)
    plan = run(service.plan_disable(entry_id))
    receipt = approve(service, broker, authenticator, plan)
    result = run(service.execute(plan, receipt))
    record = StartupMutationStore(tmp_path / "startup-state.json").load(result.mutation_id)
    record.verify()
    with pytest.raises(StartupMutationError):
        StartupMutationRecord.from_json({"bad": True})
    with pytest.raises(StartupMutationError):
        StartupMutationStore(tmp_path / "missing.json").load("missing")
    assert record.original_value


def test_provider_identity_and_locator_guards(tmp_path: Path) -> None:
    service, registry, broker, authenticator, entry_id = make_service(tmp_path)
    plan = run(service.plan_disable(entry_id))
    entry = run(service.provider.observer.observe())[0]

    class StaticObserver:
        def __init__(self, value: StartupEntryEvidence) -> None:
            self.value = value

        async def observe(self) -> tuple[StartupEntryEvidence, ...]:
            return (self.value,)

    with pytest.raises(UnsupportedMutationSource):
        run(
            WindowsStartupMutationProvider(
                backend=registry,
                observer=StaticObserver(entry),
            ).resolve(replace(plan, provider="untrusted"))
        )
    with pytest.raises(StaleStewardshipPlan):
        run(
            WindowsStartupMutationProvider(
                backend=registry,
                observer=StaticObserver(entry),
            ).resolve(replace(plan, entry_id="startup:missing"))
        )
    with pytest.raises(StartupMutationError):
        run(
            WindowsStartupMutationProvider(
                backend=registry,
                observer=StaticObserver(replace(entry, owner=None)),
            ).resolve(plan)
        )

    class DuplicateBackend(InMemoryStartupRegistry):
        def read(self, scope: str, key_path: str) -> tuple[tuple[str, str, int], ...]:
            return super().read(scope, key_path) * 2

    duplicate = DuplicateBackend()
    duplicate.values = registry.values
    with pytest.raises(StaleStewardshipPlan):
        run(
            WindowsStartupMutationProvider(
                backend=duplicate,
                observer=StaticObserver(entry),
            ).resolve(plan)
        )

    class WrongValueBackend(InMemoryStartupRegistry):
        def read(self, scope: str, key_path: str) -> tuple[tuple[str, str, int], ...]:
            return (("JARVIS_Qualification", "C:\\changed.exe", 1),)

    with pytest.raises(StaleStewardshipPlan):
        run(
            WindowsStartupMutationProvider(
                backend=WrongValueBackend(),
                observer=StaticObserver(entry),
            ).resolve(plan)
        )
    with pytest.raises(UnsupportedMutationSource):
        WindowsStartupMutationProvider(
            backend=registry,
            observer=StaticObserver(replace(entry, entry_id="untrusted", owner="x")),
        )._trusted_locator(replace(entry, entry_id="untrusted", owner="x"))  # noqa: SLF001


def test_startup_validation_guards_and_uncomposed_effect_boundary(tmp_path: Path) -> None:
    service, _registry, _broker, _authenticator, entry_id = make_service(tmp_path)
    plan = run(service.plan_disable(entry_id))
    entry = run(service.provider.observer.observe())[0]

    with pytest.raises(StewardshipError, match="value type"):
        replace(entry, value_type=True)
    with pytest.raises(StewardshipError, match="operation"):
        replace(plan, operation="invalid")
    with pytest.raises(StewardshipError, match="value type"):
        replace(plan, value_type=True)
    with pytest.raises(StewardshipError, match="task identity"):
        replace(plan, task_id=cast(Any, "not-a-uuid"))

    composition = SystemStewardshipComposition(
        cast(Any, None), cast(Any, None), cast(Any, None), cast(Any, None)
    )

    async def assert_uncomposed() -> None:
        with pytest.raises(StewardshipError):
            await composition.plan_startup_disable(entry_id)
        with pytest.raises(StewardshipError):
            await composition.plan_startup_restore("mutation")
        with pytest.raises(StewardshipError):
            await composition.authorize_startup(plan)
        with pytest.raises(StewardshipError):
            await composition.execute_startup(plan, cast(Any, None))
        with pytest.raises(StewardshipError):
            await composition.reconcile_startup()

    run(assert_uncomposed())


def test_record_validation_store_corruption_and_service_guards(tmp_path: Path) -> None:
    service, registry, broker, authenticator, entry_id = make_service(tmp_path)
    plan = run(service.plan_disable(entry_id))
    receipt = approve(service, broker, authenticator, plan)
    run(service.execute(plan, receipt))
    record = service.store.all()[0]
    with pytest.raises(StartupMutationError):
        replace(record, integrity="bad").verify()
    with pytest.raises(StartupMutationError):
        replace(record, provider="untrusted").sealed().verify()
    with pytest.raises(StartupMutationError):
        replace(record, original_value="").sealed().verify()
    with pytest.raises(StartupMutationError):
        replace(record, created_at="bad").sealed().verify()
    with pytest.raises(StartupMutationError):
        StartupMutationRecord.from_json("not-an-object")
    with pytest.raises(StartupMutationError):
        StartupMutationRecord.from_json({**asdict(record), "operation": "wrong"})
    state = tmp_path / "corrupt.json"
    state.write_text("[]", encoding="utf-8")
    with pytest.raises(StartupMutationError):
        StartupMutationStore(state).all()
    state.write_text(json.dumps({"wrong-key": asdict(record.sealed())}), encoding="utf-8")
    with pytest.raises(StartupMutationError):
        StartupMutationStore(state).all()
    state.write_text("{", encoding="utf-8")
    with pytest.raises(StartupMutationError):
        StartupMutationStore(state).all()
    with pytest.raises(StartupMutationDenied):
        run(service.execute(plan, cast(AuthorizationReceipt, None)))
    with pytest.raises(StartupMutationDenied):
        run(service.execute(plan, replace(receipt, task_id=uuid4())))
    assert service.status() == "SUPPORTED_FOR_EXACT_CURRENT_USER_RUN"
