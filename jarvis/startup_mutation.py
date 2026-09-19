"""One exact, reversible, receipt-backed Windows startup mutation route.

This module is deliberately narrower than the read-only startup observer.  The
only writable source is the current-user ``Run`` value set, and the registry
locator is resolved from trusted observed entry identity rather than accepted
from a request, model, or plan payload.
"""

from __future__ import annotations

import hashlib
import json
import os
from collections.abc import Callable
from dataclasses import asdict, dataclass, replace
from datetime import UTC, datetime, timedelta
from enum import StrEnum
from pathlib import Path
from typing import Final, Protocol
from uuid import UUID, uuid4

from jarvis.permissions import Permission, PermissionBroker, PermissionRequest, PermissionScope
from jarvis.permissions.models import (
    ActionDescriptor,
    AuthorizationReceipt,
    AuthorizationResult,
    Risk,
    SafetyClass,
)
from jarvis.system_stewardship import (
    StaleStewardshipPlan,
    StartupEntryEvidence,
    StartupEntryState,
    StartupHealthService,
    StartupMutationPlan,
    StartupProviderError,
    WindowsStartupProvider,
)
from jarvis.vm.bridge import (
    HostBridge,
    HostBridgeOperation,
    HostBridgeRequest,
    build_host_bridge_action_descriptor,
)


class StartupMutationError(RuntimeError):
    """Base error for a startup effect that did not reach trusted completion."""


class StartupMutationDenied(StartupMutationError):
    """Trusted policy, receipt, or precondition denial."""


class StartupMutationApprovalRequired(StartupMutationError):
    """The normal product route is paused for a trusted approval decision."""

    def __init__(self, requests: tuple[object, ...]) -> None:
        super().__init__("trusted startup approval is required")
        self.requests = requests


class StartupMutationUnknownOutcome(StartupMutationError):
    """The effect may have started without terminal verification."""


class UnsupportedMutationSource(StartupMutationError):
    """The observed source remains read-only in this bounded slice."""


class StartupMutationConflict(StartupMutationError):
    """A restore target is occupied by a conflicting current value."""


class StartupEffectFailure(StartupMutationError):
    """The provider reported a failure before an effect could be confirmed."""

    def __init__(self, message: str, *, effect_may_have_started: bool = False) -> None:
        super().__init__(message)
        self.effect_may_have_started = effect_may_have_started


class StartupMutationState(StrEnum):
    PRE_EFFECT = "PRE_EFFECT"
    DISABLED = "DISABLED"
    RESTORED = "RESTORED"
    ABORTED = "ABORTED"
    FAILED = "FAILED"
    UNKNOWN_OUTCOME = "UNKNOWN_OUTCOME"
    CONFLICT = "CONFLICT"


class StartupOperation(StrEnum):
    DISABLE = "disable"
    RESTORE = "restore"


class StartupRegistryBackend(Protocol):
    def read(self, scope: str, key_path: str) -> tuple[tuple[str, str, int], ...]: ...

    def delete(self, scope: str, key_path: str, value_name: str) -> None: ...

    def set(
        self, scope: str, key_path: str, value_name: str, value: str, value_type: int
    ) -> None: ...


class StartupObserver(Protocol):
    async def observe(self) -> tuple[StartupEntryEvidence, ...]: ...


class WindowsRegistryStartupBackend:
    """Trusted native backend; no caller-provided hive or registry path exists."""

    def read(self, scope: str, key_path: str) -> tuple[tuple[str, str, int], ...]:
        import winreg

        hive = _hive(scope)
        try:
            key = winreg.OpenKey(hive, key_path, 0, winreg.KEY_READ)
        except FileNotFoundError:
            return ()
        except OSError as error:
            raise StartupProviderError("startup registry source is unavailable") from error
        values: list[tuple[str, str, int]] = []
        with key:
            index = 0
            while True:
                try:
                    name, value, value_type = winreg.EnumValue(key, index)
                except OSError:
                    break
                index += 1
                if type(name) is not str or type(value) is not str or value_type not in (1, 2):
                    raise StartupProviderError("startup registry value is malformed")
                values.append((name, value, value_type))
        return tuple(values)

    def delete(self, scope: str, key_path: str, value_name: str) -> None:
        import winreg

        try:
            key = winreg.OpenKey(_hive(scope), key_path, 0, winreg.KEY_SET_VALUE)
            with key:
                winreg.DeleteValue(key, value_name)
        except FileNotFoundError as error:
            raise StaleStewardshipPlan("startup value disappeared before effect") from error
        except OSError as error:
            raise StartupEffectFailure("startup value deletion failed") from error

    def set(self, scope: str, key_path: str, value_name: str, value: str, value_type: int) -> None:
        import winreg

        try:
            key = winreg.OpenKey(_hive(scope), key_path, 0, winreg.KEY_SET_VALUE)
            with key:
                winreg.SetValueEx(key, value_name, 0, value_type, value)
        except FileNotFoundError as error:
            raise StaleStewardshipPlan("startup source disappeared before restore") from error
        except OSError as error:
            raise StartupEffectFailure("startup value restore failed") from error


def _hive(scope: str) -> int:
    import winreg

    if scope == "current-user":
        return int(winreg.HKEY_CURRENT_USER)
    if scope == "machine":
        return int(winreg.HKEY_LOCAL_MACHINE)
    raise UnsupportedMutationSource("unknown trusted startup scope")


@dataclass(frozen=True, slots=True)
class StartupResolvedValue:
    entry: StartupEntryEvidence
    scope: str
    key_path: str
    value_name: str
    value: str
    value_type: int


class WindowsStartupMutationProvider:
    """Resolve observed identity, then perform only exact current-user Run effects."""

    provider_id: Final = WindowsStartupProvider.provider_id
    SUPPORTED_SOURCE: Final = ("current-user", r"Software\Microsoft\Windows\CurrentVersion\Run")

    def __init__(
        self,
        *,
        backend: StartupRegistryBackend | None = None,
        observer: StartupObserver | None = None,
    ) -> None:
        self._backend = backend or WindowsRegistryStartupBackend()
        self._observer = observer or WindowsStartupProvider(self._backend)

    @property
    def observer(self) -> StartupObserver:
        return self._observer

    async def resolve(self, plan: StartupMutationPlan) -> StartupResolvedValue:
        if plan.provider != self.provider_id:
            raise UnsupportedMutationSource("startup plan provider is not trusted")
        report = await self._observer.observe()
        matches = tuple(item for item in report if item.entry_id == plan.entry_id)
        if len(matches) != 1:
            raise StaleStewardshipPlan("startup entry is missing or ambiguous")
        entry = matches[0]
        if entry.owner is None:
            raise StartupMutationError("startup entry has no trusted value identity")
        locator = self._trusted_locator(entry)
        values = self._backend.read(*locator[:2])
        exact = tuple(item for item in values if item[0] == locator[2])
        if len(exact) != 1:
            raise StaleStewardshipPlan("startup value identity is missing or ambiguous")
        _, value, value_type = exact[0]
        if value != entry.target_command or value_type != entry.value_type:
            raise StaleStewardshipPlan("startup value changed after observation")
        if (
            entry.provider != self.provider_id
            or entry.enabled != plan.previous_enabled
            or entry.target_command != plan.target_command
        ):
            raise StaleStewardshipPlan("startup plan no longer matches trusted evidence")
        if plan.value_type is not None and plan.value_type != value_type:
            raise StaleStewardshipPlan("startup registry type changed after planning")
        return StartupResolvedValue(entry, *locator, value, value_type)

    async def resolve_for_restore(
        self, record: StartupMutationRecord
    ) -> StartupResolvedValue | None:
        locator = self._trusted_locator_for_record(record)
        values = self._backend.read(*locator[:2])
        exact = tuple(item for item in values if item[0] == locator[2])
        if not exact:
            return None
        if len(exact) != 1:
            raise StartupMutationConflict("restore identity is ambiguous")
        _, value, value_type = exact[0]
        if value != record.original_value or value_type != record.value_type:
            raise StartupMutationConflict("restore target is occupied by another value")
        entry = StartupEntryEvidence(
            record.entry_id,
            record.value_name,
            self.provider_id,
            True,
            value,
            None,
            datetime.now(UTC),
            StartupEntryState.HEALTHY,
            "trusted startup restore inspection",
            value_type,
        )
        return StartupResolvedValue(entry, *locator, value, value_type)

    async def verify_absent(self, record: StartupMutationRecord) -> bool:
        locator = self._trusted_locator_for_record(record)
        return not any(item[0] == locator[2] for item in self._backend.read(*locator[:2]))

    async def verify_original(self, record: StartupMutationRecord) -> bool:
        restored = await self.resolve_for_restore(record)
        return restored is not None

    def disable(self, resolved: StartupResolvedValue) -> None:
        if (resolved.scope, resolved.key_path) != self.SUPPORTED_SOURCE:
            raise UnsupportedMutationSource("only current-user Run values are writable")
        self._backend.delete(resolved.scope, resolved.key_path, resolved.value_name)

    def restore(self, record: StartupMutationRecord) -> None:
        locator = self._trusted_locator_for_record(record)
        if locator[:2] != self.SUPPORTED_SOURCE:
            raise UnsupportedMutationSource("only current-user Run values are writable")
        self._backend.set(*locator, record.original_value, record.value_type)

    @classmethod
    def _trusted_locator(cls, entry: StartupEntryEvidence) -> tuple[str, str, str]:
        if entry.owner is None:
            raise StartupMutationError("startup value identity is unavailable")
        for scope, key_path in WindowsStartupProvider.TRUSTED_REGISTRY_SOURCES:
            if WindowsStartupProvider.entry_id(scope, key_path, entry.owner) == entry.entry_id:
                return scope, key_path, entry.owner
        raise UnsupportedMutationSource("startup entry source is not in the trusted source set")

    @classmethod
    def _trusted_locator_for_record(cls, record: StartupMutationRecord) -> tuple[str, str, str]:
        for scope, key_path in WindowsStartupProvider.TRUSTED_REGISTRY_SOURCES:
            if (
                WindowsStartupProvider.entry_id(scope, key_path, record.value_name)
                == record.entry_id
            ):
                if (scope, key_path) != (record.scope, record.key_path):
                    raise StartupMutationError("durable startup locator does not match identity")
                return scope, key_path, record.value_name
        raise StartupMutationError("durable startup identity is not trusted")


@dataclass(frozen=True, slots=True)
class StartupMutationRecord:
    mutation_id: str
    entry_id: str
    provider: str
    scope: str
    key_path: str
    value_name: str
    original_value: str
    value_type: int
    original_fingerprint: str
    plan_fingerprint: str
    task_id: str
    operation: StartupOperation
    state: StartupMutationState
    created_at: str
    updated_at: str
    receipt_reference: str
    detail: str
    integrity: str = ""

    def sealed(self) -> StartupMutationRecord:
        payload = self._payload()
        return replace(self, integrity=_digest(payload))

    def verify(self) -> None:
        if self.integrity != _digest(self._payload()):
            raise StartupMutationError(
                "durable startup mutation record failed integrity validation"
            )
        try:
            UUID(self.mutation_id)
            UUID(self.task_id)
            datetime.fromisoformat(self.created_at)
            datetime.fromisoformat(self.updated_at)
        except (TypeError, ValueError) as error:
            raise StartupMutationError("durable startup mutation record is malformed") from error
        if self.provider != WindowsStartupProvider.provider_id:
            raise StartupMutationError("durable startup provider is not trusted")
        if not self.value_name or not self.original_value or self.value_type not in (1, 2):
            raise StartupMutationError("durable startup value is malformed")

    def _payload(self) -> dict[str, object]:
        return {
            "mutation_id": self.mutation_id,
            "entry_id": self.entry_id,
            "provider": self.provider,
            "scope": self.scope,
            "key_path": self.key_path,
            "value_name": self.value_name,
            "original_value": self.original_value,
            "value_type": self.value_type,
            "original_fingerprint": self.original_fingerprint,
            "plan_fingerprint": self.plan_fingerprint,
            "task_id": self.task_id,
            "operation": self.operation.value,
            "state": self.state.value,
            "created_at": self.created_at,
            "updated_at": self.updated_at,
            "receipt_reference": self.receipt_reference,
            "detail": self.detail,
        }

    @classmethod
    def from_json(cls, data: object) -> StartupMutationRecord:
        if not isinstance(data, dict):
            raise StartupMutationError("durable startup mutation record is not an object")
        try:
            values = {key: data[key] for key in cls.__dataclass_fields__ if key != "integrity"}
            values["operation"] = StartupOperation(values["operation"])
            values["state"] = StartupMutationState(values["state"])
            record = cls(**values, integrity=data.get("integrity", ""))
        except (KeyError, TypeError, ValueError) as error:
            raise StartupMutationError("durable startup mutation record is malformed") from error
        record.verify()
        return record


class StartupMutationStore:
    """Small durable private state store with fail-closed integrity checks."""

    def __init__(self, path: Path) -> None:
        self.path = path
        self.path.parent.mkdir(parents=True, exist_ok=True)

    def save(self, record: StartupMutationRecord) -> StartupMutationRecord:
        sealed = record.sealed()
        records = self._read_all()
        records[sealed.mutation_id] = sealed
        temporary = self.path.with_suffix(self.path.suffix + ".tmp")
        temporary.write_text(
            json.dumps(
                {key: asdict(value) for key, value in records.items()},
                sort_keys=True,
                separators=(",", ":"),
                default=lambda value: value.value if isinstance(value, StrEnum) else value,
            ),
            encoding="utf-8",
        )
        os.replace(temporary, self.path)
        return sealed

    def load(self, mutation_id: str) -> StartupMutationRecord:
        record = self._read_all().get(mutation_id)
        if record is None:
            raise StartupMutationError("startup mutation record does not exist")
        return record

    def all(self) -> tuple[StartupMutationRecord, ...]:
        return tuple(self._read_all().values())

    def _read_all(self) -> dict[str, StartupMutationRecord]:
        if not self.path.exists():
            return {}
        try:
            raw = json.loads(self.path.read_text(encoding="utf-8"))
            if not isinstance(raw, dict):
                raise ValueError("not an object")
            records = {key: StartupMutationRecord.from_json(value) for key, value in raw.items()}
            if any(key != record.mutation_id for key, record in records.items()):
                raise ValueError("record key mismatch")
            return records
        except StartupMutationError:
            raise
        except (OSError, ValueError, TypeError, json.JSONDecodeError) as error:
            raise StartupMutationError("durable startup mutation state is unreadable") from error


@dataclass(frozen=True, slots=True)
class StartupMutationResult:
    state: StartupMutationState
    mutation_id: str
    entry_id: str
    operation: StartupOperation


class StartupMutationService:
    """Normal product composition for exact brokered startup effects."""

    TOOL_ID: Final = "system.startup"

    def __init__(
        self,
        startup: StartupHealthService,
        provider: WindowsStartupMutationProvider,
        store: StartupMutationStore,
        permission_broker: PermissionBroker,
        host_bridge: HostBridge,
        *,
        clock: Callable[[], datetime] | None = None,
    ) -> None:
        self.startup = startup
        self.provider = provider
        self.store = store
        self.permission_broker = permission_broker
        self.host_bridge = host_bridge
        self._clock = clock or (lambda: datetime.now(UTC))
        self._identity = object()
        self.permission_broker.register_tool(
            self.TOOL_ID, self._identity, frozenset({Permission.STARTUP_WRITE})
        )

    async def plan_disable(
        self, entry_id: str, *, ttl: timedelta = timedelta(minutes=5)
    ) -> StartupMutationPlan:
        plan = await self.startup.plan_set_enabled(entry_id, False, ttl=ttl)
        return replace(plan, operation=StartupOperation.DISABLE.value)

    async def plan_restore(
        self, mutation_id: str, *, ttl: timedelta = timedelta(minutes=5)
    ) -> StartupMutationPlan:
        record = self.store.load(mutation_id)
        if record.state is not StartupMutationState.DISABLED:
            raise StartupMutationDenied("only a JARVIS-disabled record may be restored")
        if ttl <= timedelta(0):
            raise StartupMutationDenied("restore plan lifetime is invalid")
        if await self.provider.resolve_for_restore(record) is not None:
            raise StartupMutationConflict("restore target is already occupied")
        now = _aware(self._clock())
        task_id = uuid4()
        fingerprint = _digest(
            {
                "entry_id": record.entry_id,
                "provider": record.provider,
                "previous_enabled": False,
                "new_enabled": True,
                "target_command": record.original_value,
                "operation": StartupOperation.RESTORE.value,
                "mutation_id": mutation_id,
                "value_type": record.value_type,
                "task_id": str(task_id),
            }
        )
        return StartupMutationPlan(
            record.entry_id,
            record.provider,
            False,
            True,
            record.original_value,
            now,
            now + ttl,
            fingerprint,
            StartupOperation.RESTORE.value,
            mutation_id,
            record.value_type,
            task_id,
        )

    async def authorize(
        self, plan: StartupMutationPlan, *, user_id: str | None = None
    ) -> AuthorizationResult:
        descriptor = self._descriptor(plan)
        return await self.permission_broker.authorize(
            tool_id=self.TOOL_ID,
            tool_identity=self._identity,
            declared_permissions=frozenset({Permission.STARTUP_WRITE}),
            task_id=_plan_task_id(plan),
            user_id=user_id,
            descriptor=descriptor,
            normalized_arguments=self._arguments(plan),
        )

    async def execute(
        self, plan: StartupMutationPlan, receipt: AuthorizationReceipt
    ) -> StartupMutationResult:
        if receipt is None or type(receipt) is not AuthorizationReceipt:
            raise StartupMutationDenied("trusted startup receipt is required")
        if receipt.task_id != _plan_task_id(plan):
            raise StartupMutationDenied("startup receipt task mismatch")
        reason = await self.permission_broker.begin_execution(receipt)
        if reason is not None:
            raise StartupMutationDenied(reason.value)
        outcome = "not_executed"
        record: StartupMutationRecord | None = None
        try:
            record, resolved = await self._pre_effect(plan, receipt)
            request = self._bridge_request(plan, receipt)
            bridge_result = self.host_bridge.authorize_with_receipt(
                request,
                receipt=receipt,
                broker=self.permission_broker,
                normalized_arguments=self._arguments(plan),
                expected_instance_id=self.host_bridge.instance_id,
            )
            if not bridge_result.allowed:
                record = self._save_state(
                    record, StartupMutationState.ABORTED, bridge_result.reason
                )
                raise StartupMutationDenied(bridge_result.reason)
            try:
                if plan.operation == StartupOperation.DISABLE.value:
                    assert resolved is not None
                    self.provider.disable(resolved)
                else:
                    self.provider.restore(record)
            except StaleStewardshipPlan:
                record = self._save_state(
                    record, StartupMutationState.FAILED, "stale before effect"
                )
                raise
            except UnsupportedMutationSource:
                record = self._save_state(
                    record, StartupMutationState.FAILED, "unsupported mutation source"
                )
                raise
            except StartupEffectFailure as error:
                if error.effect_may_have_started:
                    record = self._save_state(
                        record,
                        StartupMutationState.UNKNOWN_OUTCOME,
                        "effect may have started",
                    )
                    outcome = "unknown_outcome"
                    raise StartupMutationUnknownOutcome(
                        "startup effect lacks terminal evidence"
                    ) from error
                record = self._save_state(
                    record, StartupMutationState.FAILED, "effect did not start"
                )
                raise StartupMutationError("startup effect failed before mutation") from error
            except BaseException as error:
                record = self._save_state(record, StartupMutationState.FAILED, type(error).__name__)
                raise StartupMutationError(
                    "startup effect failed before terminal evidence"
                ) from error
            if plan.operation == StartupOperation.DISABLE:
                verified = await self.provider.verify_absent(record)
                terminal = (
                    StartupMutationState.DISABLED
                    if verified
                    else StartupMutationState.UNKNOWN_OUTCOME
                )
            else:
                verified = await self.provider.verify_original(record)
                terminal = (
                    StartupMutationState.RESTORED
                    if verified
                    else StartupMutationState.UNKNOWN_OUTCOME
                )
            record = self._save_state(
                record, terminal, "effect verified" if verified else "verification absent"
            )
            if not verified:
                outcome = "unknown_outcome"
                raise StartupMutationUnknownOutcome("startup effect lacks terminal verification")
            outcome = "effect_confirmed"
            return StartupMutationResult(
                terminal, record.mutation_id, record.entry_id, record.operation
            )
        except BaseException:
            if outcome == "not_executed" and record is not None:
                outcome = "not_executed"
            try:
                await self.permission_broker.record_execution_outcome(receipt, outcome)
            except BaseException as error:
                if record is not None:
                    self._save_state(
                        record,
                        StartupMutationState.UNKNOWN_OUTCOME,
                        "audit outcome unavailable",
                    )
                raise StartupMutationUnknownOutcome("startup receipt outcome is unknown") from error
            raise
        else:
            await self.permission_broker.record_execution_outcome(receipt, outcome)

    async def reconcile(self) -> tuple[StartupMutationRecord, ...]:
        reconciled: list[StartupMutationRecord] = []
        for record in self.store.all():
            if record.state not in {
                StartupMutationState.PRE_EFFECT,
                StartupMutationState.UNKNOWN_OUTCOME,
            }:
                continue
            if record.operation is StartupOperation.DISABLE:
                absent = await self.provider.verify_absent(record)
                state = StartupMutationState.DISABLED if absent else StartupMutationState.ABORTED
            else:
                restored = await self.provider.verify_original(record)
                state = (
                    StartupMutationState.RESTORED
                    if restored
                    else StartupMutationState.UNKNOWN_OUTCOME
                )
            reconciled.append(self._save_state(record, state, "restart reconciliation"))
        return tuple(reconciled)

    def status(self) -> str:
        return "SUPPORTED_FOR_EXACT_CURRENT_USER_RUN"

    async def _pre_effect(
        self, plan: StartupMutationPlan, receipt: AuthorizationReceipt
    ) -> tuple[StartupMutationRecord, StartupResolvedValue | None]:
        if _aware(self._clock()) >= plan.expires_at:
            raise StartupMutationDenied("startup plan expired")
        if plan.operation == StartupOperation.DISABLE:
            resolved = await self.provider.resolve(plan)
            if not plan.previous_enabled or plan.new_enabled:
                raise StartupMutationDenied("disable plan transition is malformed")
            record = StartupMutationRecord(
                str(uuid4()),
                plan.entry_id,
                plan.provider,
                resolved.scope,
                resolved.key_path,
                resolved.value_name,
                resolved.value,
                resolved.value_type,
                _digest({"value": resolved.value, "type": resolved.value_type}),
                plan.fingerprint,
                str(_plan_task_id(plan)),
                StartupOperation.DISABLE,
                StartupMutationState.PRE_EFFECT,
                _aware(self._clock()).isoformat(),
                _aware(self._clock()).isoformat(),
                str(receipt.receipt_id),
                "trusted pre-effect record",
            )
            return self.store.save(record), resolved
        if plan.operation != StartupOperation.RESTORE or plan.mutation_id is None:
            raise StartupMutationDenied("startup plan operation is malformed")
        record = self.store.load(plan.mutation_id)
        if (
            plan.entry_id != record.entry_id
            or plan.provider != record.provider
            or plan.target_command != record.original_value
            or plan.value_type != record.value_type
        ):
            raise StartupMutationDenied("restore plan does not match its durable record")
        if record.state is not StartupMutationState.DISABLED:
            raise StartupMutationDenied("restore requires a disabled JARVIS record")
        if record.plan_fingerprint == plan.fingerprint:
            raise StartupMutationDenied("restore plan must have a distinct exact fingerprint")
        if await self.provider.resolve_for_restore(record) is not None:
            raise StartupMutationConflict("restore target is already occupied")
        return (
            self._save_state(record, StartupMutationState.PRE_EFFECT, "restore pre-effect record"),
            None,
        )

    def _descriptor(self, plan: StartupMutationPlan) -> ActionDescriptor:
        operation = self._operation(plan)
        return build_host_bridge_action_descriptor(
            action=f"system.startup.{plan.operation}",
            operation=operation,
            resource=f"startup-entry:{plan.entry_id}",
            scope=plan.entry_id,
            risk=Risk.HIGH.value,
            permissions=(
                PermissionRequest(
                    Permission.STARTUP_WRITE,
                    PermissionScope(startup_entries=(plan.entry_id,), task_id=_plan_task_id(plan)),
                ),
            ),
            safety_class=SafetyClass.SYSTEM_CONFIGURATION,
        )

    def _bridge_request(
        self, plan: StartupMutationPlan, receipt: AuthorizationReceipt
    ) -> HostBridgeRequest:
        operation = self._operation(plan)
        return HostBridgeRequest(
            request_id=uuid4(),
            task_id=_plan_task_id(plan),
            instance_id=self.host_bridge.instance_id,
            operation=operation,
            resource=f"startup-entry:{plan.entry_id}",
            scope=plan.entry_id,
            risk=Risk.HIGH.value,
            expires_at=receipt.expires_at,
            tool_id=self.TOOL_ID,
            action=f"system.startup.{plan.operation}",
            argument_fingerprint=receipt.argument_fingerprint,
            action_fingerprint=receipt.action_fingerprint,
            approval_identity=_approval_identity(receipt),
            safety_class=SafetyClass.SYSTEM_CONFIGURATION,
        )

    @staticmethod
    def _operation(plan: StartupMutationPlan) -> HostBridgeOperation:
        if plan.operation == StartupOperation.DISABLE.value:
            return HostBridgeOperation.STARTUP_ENTRY_DISABLE
        if plan.operation == StartupOperation.RESTORE.value:
            return HostBridgeOperation.STARTUP_ENTRY_RESTORE
        raise StartupMutationDenied("unknown startup operation")

    @staticmethod
    def _arguments(plan: StartupMutationPlan) -> dict[str, object]:
        return {
            "entry_id": plan.entry_id,
            "provider": plan.provider,
            "operation": plan.operation,
            "plan_fingerprint": plan.fingerprint,
            "target_enabled": plan.new_enabled,
            "mutation_id": plan.mutation_id,
        }

    def _save_state(
        self, record: StartupMutationRecord, state: StartupMutationState, detail: str
    ) -> StartupMutationRecord:
        return self.store.save(
            replace(
                record,
                state=state,
                updated_at=_aware(self._clock()).isoformat(),
                detail=detail,
            )
        )


def _plan_task_id(plan: StartupMutationPlan) -> UUID:
    # StartupMutationPlan intentionally remains backwards compatible with the
    # read-only planner and carries no caller-controlled task identity.  The
    # exact task is bound by the product route's deterministic namespace.
    return plan.task_id or UUID(bytes=hashlib.sha256(plan.fingerprint.encode()).digest()[:16])


def _approval_identity(receipt: AuthorizationReceipt) -> str | None:
    identities = {
        item.approval_identity
        for item in receipt.approval_requests
        if item.approval_identity is not None
    }
    identities.update(item.identity_id for item in receipt.remembered_grants)
    return sorted(identities)[0] if identities else None


def _aware(value: object) -> datetime:
    if not isinstance(value, datetime) or value.tzinfo is None:
        raise StartupMutationError("startup mutation clock is not timezone-aware")
    return value.astimezone(UTC)


def _digest(value: object) -> str:
    return hashlib.sha256(
        json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode()
    ).hexdigest()


__all__ = [
    "InMemoryStartupRegistry",
    "StartupEffectFailure",
    "StartupMutationError",
    "StartupMutationRecord",
    "StartupMutationResult",
    "StartupMutationService",
    "StartupMutationState",
    "StartupMutationStore",
    "StartupOperation",
    "StartupRegistryBackend",
    "StartupResolvedValue",
    "StartupMutationApprovalRequired",
    "StartupMutationConflict",
    "StartupMutationDenied",
    "StartupMutationUnknownOutcome",
    "UnsupportedMutationSource",
    "WindowsRegistryStartupBackend",
    "WindowsStartupMutationProvider",
]


class InMemoryStartupRegistry:
    """Bounded deterministic registry/effect backend for authority integration tests."""

    def __init__(self) -> None:
        self.values: dict[tuple[str, str], dict[str, tuple[str, int]]] = {}
        self.effect_calls: list[tuple[str, str, str]] = []
        self.fail_delete: BaseException | None = None
        self.fail_set: BaseException | None = None

    def read(self, scope: str, key_path: str) -> tuple[tuple[str, str, int], ...]:
        return tuple(
            (name, value, value_type)
            for name, (value, value_type) in self.values.get((scope, key_path), {}).items()
        )

    def delete(self, scope: str, key_path: str, value_name: str) -> None:
        self.effect_calls.append(("delete", scope, value_name))
        if self.fail_delete is not None:
            error = self.fail_delete
            self.fail_delete = None
            if isinstance(error, StartupEffectFailure) and error.effect_may_have_started:
                values = self.values.setdefault((scope, key_path), {})
                values.pop(value_name, None)
            raise error
        values = self.values.setdefault((scope, key_path), {})
        if value_name not in values:
            raise StaleStewardshipPlan("startup value disappeared before effect")
        del values[value_name]

    def set(self, scope: str, key_path: str, value_name: str, value: str, value_type: int) -> None:
        self.effect_calls.append(("set", scope, value_name))
        if self.fail_set is not None:
            error = self.fail_set
            self.fail_set = None
            raise error
        values = self.values.setdefault((scope, key_path), {})
        if value_name in values:
            raise StartupMutationConflict("restore target is occupied")
        values[value_name] = (value, value_type)
