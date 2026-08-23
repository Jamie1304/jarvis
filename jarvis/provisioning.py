"""Typed, provider-neutral provisioning plans and safe resumption.

Provisioning is a coordinator for reviewed typed providers.  It is not a shell
runner, package catalog, service manager, or product integration.  Every effect
is an exact action with one permission, bounded JSON parameters, an idempotency
declaration, and a reality inspection step before application or retry.
"""

from __future__ import annotations

import asyncio
import hashlib
import json
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass, field
from datetime import UTC, datetime
from enum import StrEnum
from typing import Protocol
from uuid import UUID

from jarvis.permissions.broker import PermissionBroker
from jarvis.permissions.models import (
    ActionDescriptor,
    AuthorizationReceipt,
    Permission,
    PermissionRequest,
    PermissionScope,
    Risk,
    SafeArgument,
)


class ProvisioningError(RuntimeError):
    """A provisioning plan or provider could not be safely executed."""


class ProvisioningValidationError(ProvisioningError, ValueError):
    """Typed provisioning input is malformed."""


class ProvisioningDenied(ProvisioningError):
    """The exact provisioning action was not authorized."""


class ProvisioningApprovalRequired(ProvisioningDenied):
    """The broker requires trusted approval for the exact action."""

    def __init__(self, approvals: object) -> None:
        super().__init__("Provisioning approval is required")
        self.approvals = approvals


class ProvisioningEffectOutcome(StrEnum):
    PRE_EFFECT_FAILURE = "pre_effect_failure"
    SAFE_TO_RETRY = "safe_to_retry"
    EFFECT_CONFIRMED = "effect_confirmed"
    UNKNOWN_OUTCOME = "unknown_outcome"


class ProvisioningActionKind(StrEnum):
    DOWNLOAD_VERIFY = "download_verify"
    INSTALL_PACKAGE = "install_package"
    CREATE_ENVIRONMENT = "create_environment"
    INSTALL_DEPENDENCY = "install_dependency"
    WRITE_CONFIG = "write_config"
    SERVICE = "service"
    CONTAINER = "container"
    VM = "vm"
    NETWORK = "network"
    HEALTH_CHECK = "health_check"
    UNINSTALL = "uninstall"
    ROLLBACK = "rollback"


class ProvisioningActionState(StrEnum):
    PENDING = "pending"
    ALREADY_SATISFIED = "already_satisfied"
    READY = "ready"
    APPLYING = "applying"
    VERIFIED = "verified"
    FAILED = "failed"
    RECOVERING = "recovering"


class ProvisioningPlanState(StrEnum):
    PENDING = "pending"
    APPLYING = "applying"
    VERIFIED = "verified"
    FAILED = "failed"
    RECOVERING = "recovering"
    ROLLING_BACK = "rolling_back"
    ROLLED_BACK = "rolled_back"


_MAX_ACTIONS = 128
_MAX_PARAMETERS_BYTES = 65_536
_MAX_TEXT = 512
_SECRET_NAMES = frozenset({"secret", "password", "token", "private_key", "credential_value"})


def _text(value: object, field_name: str, limit: int = _MAX_TEXT) -> str:
    if (
        type(value) is not str
        or not value.strip()
        or len(value) > limit
        or any(ord(character) < 32 for character in value)
    ):
        raise ProvisioningValidationError(f"{field_name} is malformed")
    return value


def _identifier(value: object, field_name: str) -> str:
    value = _text(value, field_name, 128)
    if any(character not in "abcdefghijklmnopqrstuvwxyz0123456789._-" for character in value):
        raise ProvisioningValidationError(f"{field_name} is malformed")
    return value


def _json_value(value: object, *, depth: int = 0) -> object:
    if depth > 16:
        raise ProvisioningValidationError("Provisioning parameters are too deeply nested")
    if value is None or type(value) is bool or type(value) is int or type(value) is str:
        if type(value) is str and len(value) > _MAX_PARAMETERS_BYTES:
            raise ProvisioningValidationError("Provisioning parameters are too large")
        return value
    if type(value) is float:
        if value != value or value in {float("inf"), float("-inf")}:
            raise ProvisioningValidationError("Provisioning parameters contain an invalid number")
        return value
    if isinstance(value, Sequence) and not isinstance(value, str | bytes | bytearray):
        if len(value) > 256:
            raise ProvisioningValidationError("Provisioning parameter list is too large")
        return [_json_value(item, depth=depth + 1) for item in value]
    if isinstance(value, Mapping):
        if len(value) > 256:
            raise ProvisioningValidationError("Provisioning parameter object is too large")
        result: dict[str, object] = {}
        for key, item in value.items():
            key_text = _identifier(key, "Provisioning parameter name")
            if key_text.casefold() in _SECRET_NAMES:
                raise ProvisioningValidationError("Raw credential material cannot be provisioned")
            result[key_text] = _json_value(item, depth=depth + 1)
        encoded = json.dumps(result, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
        if len(encoded.encode("utf-8")) > _MAX_PARAMETERS_BYTES:
            raise ProvisioningValidationError("Provisioning parameters are too large")
        return result
    raise ProvisioningValidationError("Provisioning parameters must be JSON")


@dataclass(frozen=True, slots=True)
class ProvisioningArtifact:
    reference: str
    sha256: str
    size_bytes: int | None = None

    def __post_init__(self) -> None:
        _text(self.reference, "Provisioning artifact reference", 1_024)
        if len(self.sha256) != 64 or any(
            character not in "0123456789abcdef" for character in self.sha256
        ):
            raise ProvisioningValidationError("Provisioning artifact hash is malformed")
        if self.size_bytes is not None and (
            not isinstance(self.size_bytes, int) or self.size_bytes < 0
        ):
            raise ProvisioningValidationError("Provisioning artifact size is malformed")


@dataclass(frozen=True, slots=True)
class ProvisioningAction:
    action_id: str
    provider_id: str
    kind: ProvisioningActionKind
    target: str
    parameters: Mapping[str, object]
    permission: Permission
    paths: tuple[str, ...] = ()
    network_hosts: tuple[str, ...] = ()
    command_families: tuple[str, ...] = ()
    application_targets: tuple[str, ...] = ()
    artifacts: tuple[ProvisioningArtifact, ...] = ()
    disk_bytes: int = 0
    requires_admin: bool = False
    idempotent: bool = True
    non_idempotent_reason: str | None = None
    depends_on: tuple[str, ...] = ()
    expected_state: Mapping[str, object] = field(default_factory=dict)
    undoes_action_id: str | None = None

    def __post_init__(self) -> None:
        _identifier(self.action_id, "Provisioning action ID")
        _identifier(self.provider_id, "Provisioning provider ID")
        if not isinstance(self.kind, ProvisioningActionKind):
            raise ProvisioningValidationError("Provisioning action kind is malformed")
        _text(self.target, "Provisioning target")
        normalized = _json_value(self.parameters)
        if not isinstance(normalized, dict):
            raise ProvisioningValidationError("Provisioning parameters must be an object")
        normalized_expected = _json_value(self.expected_state)
        if not isinstance(normalized_expected, dict):
            raise ProvisioningValidationError("Provisioning expected state must be an object")
        if not isinstance(self.permission, Permission):
            raise ProvisioningValidationError("Provisioning permission is malformed")
        for name, values in (
            ("path", self.paths),
            ("network host", self.network_hosts),
            ("command family", self.command_families),
            ("application target", self.application_targets),
        ):
            if (
                type(values) is not tuple
                or len(values) > 64
                or any(not _text(value, f"Provisioning {name}", 4_096) for value in values)
            ):
                raise ProvisioningValidationError(f"Provisioning {name}s are malformed")
        if (
            not isinstance(self.artifacts, tuple)
            or len(self.artifacts) > 128
            or any(type(item) is not ProvisioningArtifact for item in self.artifacts)
            or not isinstance(self.disk_bytes, int)
            or self.disk_bytes < 0
            or type(self.requires_admin) is not bool
            or type(self.idempotent) is not bool
            or len(set(self.depends_on)) != len(self.depends_on)
            or any(not _identifier(item, "Provisioning dependency") for item in self.depends_on)
        ):
            raise ProvisioningValidationError("Provisioning action bounds are malformed")
        if not self.idempotent:
            if self.non_idempotent_reason is None:
                raise ProvisioningValidationError("Non-idempotent actions require a reason")
            _text(self.non_idempotent_reason, "Non-idempotent reason", 1_024)
        elif self.non_idempotent_reason is not None:
            raise ProvisioningValidationError(
                "Idempotent actions cannot declare a non-idempotent reason"
            )
        if self.kind is ProvisioningActionKind.ROLLBACK:
            _identifier(self.undoes_action_id, "Rollback source action ID")
        elif self.undoes_action_id is not None:
            raise ProvisioningValidationError("Only ROLLBACK actions may declare a source action")

    @property
    def fingerprint(self) -> str:
        payload = {
            "action_id": self.action_id,
            "provider_id": self.provider_id,
            "kind": self.kind.value,
            "target": self.target,
            "parameters": _json_value(self.parameters),
            "permission": self.permission.value,
            "paths": self.paths,
            "network_hosts": self.network_hosts,
            "command_families": self.command_families,
            "application_targets": self.application_targets,
            "artifacts": [
                {"reference": item.reference, "sha256": item.sha256, "size": item.size_bytes}
                for item in self.artifacts
            ],
            "disk_bytes": self.disk_bytes,
            "requires_admin": self.requires_admin,
            "idempotent": self.idempotent,
            "depends_on": self.depends_on,
            "expected_state": _json_value(self.expected_state),
            "undoes_action_id": self.undoes_action_id,
        }
        return hashlib.sha256(
            json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode()
        ).hexdigest()

    def scope(self, *, task_id: UUID) -> PermissionScope:
        return PermissionScope(
            paths=self.paths,
            hosts=self.network_hosts,
            command_families=self.command_families,
            applications=self.application_targets,
            tool_id=None,
            task_id=task_id,
        )


@dataclass(frozen=True, slots=True)
class ProvisioningRollbackPlan:
    plan_id: UUID
    actions: tuple[ProvisioningAction, ...]
    reason: str

    def __post_init__(self) -> None:
        if not isinstance(self.plan_id, UUID) or not self.actions:
            raise ProvisioningValidationError("Rollback plan is malformed")
        _text(self.reason, "Rollback reason", 1_024)
        if any(action.kind is not ProvisioningActionKind.ROLLBACK for action in self.actions):
            raise ProvisioningValidationError("Rollback plan actions must be ROLLBACK actions")


@dataclass(frozen=True, slots=True)
class ProvisioningPlan:
    plan_id: UUID
    task_id: UUID
    actions: tuple[ProvisioningAction, ...]
    created_at: datetime
    expires_at: datetime
    rollback: ProvisioningRollbackPlan | None = None
    max_attempts: int = 1

    def __post_init__(self) -> None:
        if not isinstance(self.plan_id, UUID) or not isinstance(self.task_id, UUID):
            raise ProvisioningValidationError("Provisioning plan identity is malformed")
        if not self.actions or len(self.actions) > _MAX_ACTIONS:
            raise ProvisioningValidationError("Provisioning plan action count is invalid")
        if self.created_at.tzinfo is None or self.expires_at.tzinfo is None:
            raise ProvisioningValidationError("Provisioning plan timestamps must be timezone-aware")
        if self.expires_at <= self.created_at:
            raise ProvisioningValidationError("Provisioning plan expiry must be after creation")
        if not isinstance(self.max_attempts, int) or not 1 <= self.max_attempts <= 3:
            raise ProvisioningValidationError("Provisioning attempt bound is invalid")
        ids = {action.action_id for action in self.actions}
        if len(ids) != len(self.actions) or any(
            dependency not in ids for action in self.actions for dependency in action.depends_on
        ):
            raise ProvisioningValidationError("Provisioning action dependencies are invalid")
        if self.rollback is not None and self.rollback.plan_id != self.plan_id:
            raise ProvisioningValidationError("Rollback plan is not bound to this plan")


@dataclass(frozen=True, slots=True)
class ProvisioningObservation:
    satisfied: bool
    partial: bool = False
    safe_to_retry: bool = False
    evidence: str = ""
    artifact_hashes: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        if any(
            type(value) is not bool for value in (self.satisfied, self.partial, self.safe_to_retry)
        ):
            raise ProvisioningValidationError("Provisioning observation flags are malformed")
        if self.satisfied and self.partial:
            raise ProvisioningValidationError("A satisfied action cannot be partial")
        _text(self.evidence or "none", "Provisioning evidence", 2_048)
        if any(
            len(value) != 64 or any(character not in "0123456789abcdef" for character in value)
            for value in self.artifact_hashes
        ):
            raise ProvisioningValidationError("Provisioning observed artifact hash is malformed")


@dataclass(frozen=True, slots=True)
class ProvisioningApplyResult:
    outcome: ProvisioningEffectOutcome
    observation: ProvisioningObservation | None = None
    detail: str = ""

    def __post_init__(self) -> None:
        if not isinstance(self.outcome, ProvisioningEffectOutcome):
            raise ProvisioningValidationError("Provisioning effect outcome is malformed")
        if self.observation is not None and type(self.observation) is not ProvisioningObservation:
            raise ProvisioningValidationError("Provisioning observation is malformed")
        _text(self.detail or "none", "Provisioning result detail", 2_048)


@dataclass(frozen=True, slots=True)
class ProvisioningActionResult:
    action_id: str
    state: ProvisioningActionState
    outcome: ProvisioningEffectOutcome | None
    detail: str
    attempts: int


@dataclass(frozen=True, slots=True)
class ProvisioningResult:
    plan_id: UUID
    state: ProvisioningPlanState
    actions: tuple[ProvisioningActionResult, ...]
    detail: str = ""


class ProvisioningProvider(Protocol):
    async def inspect(self, action: ProvisioningAction) -> ProvisioningObservation: ...

    async def apply(
        self, action: ProvisioningAction, cancellation: asyncio.Event
    ) -> ProvisioningApplyResult: ...

    async def rollback(
        self, action: ProvisioningAction, cancellation: asyncio.Event
    ) -> ProvisioningApplyResult: ...

    async def health_check(self, action: ProvisioningAction) -> bool: ...


class ProvisioningAuthorization(Protocol):
    async def authorize(self, plan: ProvisioningPlan, action: ProvisioningAction) -> object: ...

    async def begin(self, receipt: object) -> None: ...

    async def finish(self, receipt: object, outcome: ProvisioningEffectOutcome) -> None: ...


class BrokerProvisioningAuthorizer:
    """Bind typed provisioning actions to the existing PermissionBroker."""

    def __init__(self, broker: PermissionBroker) -> None:
        if not isinstance(broker, PermissionBroker):
            raise ProvisioningValidationError("Provisioning broker is malformed")
        self._broker = broker
        self._identities: dict[Permission, tuple[str, object]] = {}
        for permission in Permission:
            tool_id = f"provisioning.{permission.value}"
            identity = object()
            broker.register_tool(tool_id, identity, frozenset({permission}))
            self._identities[permission] = (tool_id, identity)

    async def authorize(self, plan: ProvisioningPlan, action: ProvisioningAction) -> object:
        tool_id, identity = self._identities[action.permission]
        descriptor = ActionDescriptor(
            f"provisioning.{action.kind.value}.{action.action_id}",
            (
                SafeArgument("target", action.target),
                SafeArgument("fingerprint", action.fingerprint[:16]),
            ),
            Risk.CRITICAL if action.requires_admin else Risk.HIGH,
            (PermissionRequest(action.permission, action.scope(task_id=plan.task_id)),),
        )
        arguments = {
            "plan_id": str(plan.plan_id),
            "action_id": action.action_id,
            "fingerprint": action.fingerprint,
            "parameters": _json_value(action.parameters),
        }
        result = await self._broker.authorize(
            tool_id=tool_id,
            tool_identity=identity,
            declared_permissions=frozenset({action.permission}),
            task_id=plan.task_id,
            user_id=None,
            descriptor=descriptor,
            normalized_arguments=arguments,
        )
        if not result.authorized or result.receipt is None:
            if result.approval_requests:
                raise ProvisioningApprovalRequired(result.approval_requests)
            raise ProvisioningDenied(result.reason.value)
        return result.receipt

    async def begin(self, receipt: object) -> None:
        if type(receipt) is not AuthorizationReceipt:
            raise ProvisioningDenied("Malformed provisioning authorization receipt")
        reason = await self._broker.begin_execution(receipt)
        if reason is not None:
            raise ProvisioningDenied(reason.value)

    async def finish(self, receipt: object, outcome: ProvisioningEffectOutcome) -> None:
        if type(receipt) is not AuthorizationReceipt:
            raise ProvisioningDenied("Malformed provisioning authorization receipt")
        await self._broker.record_execution_outcome(receipt, outcome.value)


class ProvisioningEngine:
    """Inspect reality, apply typed actions, verify, and roll back safely."""

    def __init__(
        self,
        providers: Mapping[str, ProvisioningProvider],
        authorizer: ProvisioningAuthorization,
        *,
        clock: Callable[[], datetime] | None = None,
    ) -> None:
        if not isinstance(providers, Mapping) or not providers:
            raise ProvisioningValidationError("At least one provisioning provider is required")
        self._providers = dict(providers)
        self._authorizer = authorizer
        self._clock = clock or (lambda: datetime.now(UTC))
        self._states: dict[UUID, dict[str, ProvisioningActionResult]] = {}

    async def run(
        self,
        plan: ProvisioningPlan,
        *,
        cancellation: asyncio.Event | None = None,
        resume: bool = False,
    ) -> ProvisioningResult:
        now = self._clock()
        if now >= plan.expires_at:
            raise ProvisioningError("Provisioning plan is expired")
        cancel = cancellation or asyncio.Event()
        state = self._states.setdefault(plan.plan_id, {})
        if (
            not resume
            and state
            and any(item.state is ProvisioningActionState.APPLYING for item in state.values())
        ):
            raise ProvisioningError("Interrupted provisioning requires explicit resume")
        action_results: list[ProvisioningActionResult] = []
        completed: list[ProvisioningAction] = []
        for action in plan.actions:
            if cancel.is_set():
                return self._result(
                    plan, action_results, ProvisioningPlanState.RECOVERING, "cancelled"
                )
            provider = self._providers.get(action.provider_id)
            if provider is None:
                result = self._failed(action, "unsupported provider")
                action_results.append(result)
                state[action.action_id] = result
                return await self._failure(
                    plan, action_results, completed, "unsupported provider", cancel
                )
            if any(
                state.get(dependency, self._failed_by_id(dependency)).state
                not in {ProvisioningActionState.VERIFIED, ProvisioningActionState.ALREADY_SATISFIED}
                for dependency in action.depends_on
            ):
                result = self._failed(action, "dependency is not verified")
                action_results.append(result)
                state[action.action_id] = result
                return await self._failure(plan, action_results, completed, result.detail, cancel)
            try:
                observation = await provider.inspect(action)
            except Exception as error:
                result = self._failed(action, f"reality inspection failed: {type(error).__name__}")
                action_results.append(result)
                state[action.action_id] = result
                return await self._failure(plan, action_results, completed, result.detail, cancel)
            if not self._artifacts_match(action, observation):
                result = self._failed(action, "artifact checksum mismatch")
                action_results.append(result)
                state[action.action_id] = result
                return await self._failure(plan, action_results, completed, result.detail, cancel)
            if observation.satisfied:
                result = ProvisioningActionResult(
                    action.action_id,
                    ProvisioningActionState.ALREADY_SATISFIED,
                    ProvisioningEffectOutcome.EFFECT_CONFIRMED,
                    observation.evidence,
                    state.get(action.action_id, self._failed_by_id(action.action_id)).attempts,
                )
                action_results.append(result)
                state[action.action_id] = result
                completed.append(action)
                continue
            previous = state.get(action.action_id)
            if previous is not None and previous.state is ProvisioningActionState.RECOVERING:
                if not observation.safe_to_retry or not action.idempotent:
                    result = self._recovering(action, "unknown outcome is not safe to replay")
                    action_results.append(result)
                    state[action.action_id] = result
                    return self._result(
                        plan, action_results, ProvisioningPlanState.RECOVERING, result.detail
                    )
            attempts = previous.attempts if previous else 0
            if previous is not None and previous.state is ProvisioningActionState.FAILED:
                if (
                    previous.outcome is ProvisioningEffectOutcome.SAFE_TO_RETRY
                    and not action.idempotent
                ):
                    result = self._recovering(
                        action, "non-idempotent action cannot be replayed", attempts
                    )
                    action_results.append(result)
                    state[action.action_id] = result
                    return self._result(
                        plan, action_results, ProvisioningPlanState.RECOVERING, result.detail
                    )
            if attempts >= plan.max_attempts:
                result = self._failed(action, "retry exhaustion", attempts)
                action_results.append(result)
                state[action.action_id] = result
                return await self._failure(plan, action_results, completed, result.detail, cancel)
            ready = ProvisioningActionResult(
                action.action_id,
                ProvisioningActionState.READY,
                None,
                "partial reality inspected" if observation.partial else "ready",
                attempts,
            )
            state[action.action_id] = ready
            try:
                receipt = await self._authorizer.authorize(plan, action)
                await self._authorizer.begin(receipt)
            except ProvisioningDenied:
                raise
            applying = ProvisioningActionResult(
                action.action_id,
                ProvisioningActionState.APPLYING,
                None,
                "effect in progress",
                attempts + 1,
            )
            state[action.action_id] = applying
            try:
                applied = await provider.apply(action, cancel)
            except asyncio.CancelledError:
                await self._finish_safely(receipt, ProvisioningEffectOutcome.UNKNOWN_OUTCOME)
                state[action.action_id] = self._recovering(
                    action, "cancelled during effect", attempts + 1
                )
                return self._result(
                    plan, list(state.values()), ProvisioningPlanState.RECOVERING, "cancelled"
                )
            except Exception as error:
                await self._finish_safely(receipt, ProvisioningEffectOutcome.UNKNOWN_OUTCOME)
                result = self._recovering(
                    action, f"provider outcome unknown: {type(error).__name__}", attempts + 1
                )
                action_results.append(result)
                state[action.action_id] = result
                return self._result(
                    plan, list(state.values()), ProvisioningPlanState.RECOVERING, result.detail
                )
            await self._authorizer.finish(receipt, applied.outcome)
            if applied.outcome is ProvisioningEffectOutcome.UNKNOWN_OUTCOME:
                result = self._recovering(
                    action, applied.detail or "provider outcome unknown", attempts + 1
                )
                action_results.append(result)
                state[action.action_id] = result
                return self._result(
                    plan, list(state.values()), ProvisioningPlanState.RECOVERING, result.detail
                )
            if applied.outcome in {
                ProvisioningEffectOutcome.PRE_EFFECT_FAILURE,
                ProvisioningEffectOutcome.SAFE_TO_RETRY,
            }:
                result = self._failed(
                    action,
                    applied.detail or applied.outcome.value,
                    attempts + 1,
                    applied.outcome,
                )
                action_results.append(result)
                state[action.action_id] = result
                return await self._failure(
                    plan, list(state.values()), completed, result.detail, cancel
                )
            verified = applied.observation or await provider.inspect(action)
            if not self._artifacts_match(action, verified):
                result = self._failed(action, "artifact checksum mismatch", attempts + 1)
                action_results.append(result)
                state[action.action_id] = result
                return await self._failure(
                    plan, list(state.values()), completed, result.detail, cancel
                )
            healthy = verified.satisfied and await provider.health_check(action)
            result = ProvisioningActionResult(
                action.action_id,
                ProvisioningActionState.VERIFIED if healthy else ProvisioningActionState.FAILED,
                applied.outcome,
                applied.detail or verified.evidence,
                attempts + 1,
            )
            action_results.append(result)
            state[action.action_id] = result
            if not healthy:
                return await self._failure(
                    plan, list(state.values()), completed, "post-action verification failed", cancel
                )
            completed.append(action)
        return self._result(plan, list(state.values()), ProvisioningPlanState.VERIFIED, "verified")

    async def _failure(
        self,
        plan: ProvisioningPlan,
        results: list[ProvisioningActionResult],
        completed: list[ProvisioningAction],
        detail: str,
        cancellation: asyncio.Event,
    ) -> ProvisioningResult:
        if plan.rollback is None or not completed:
            return self._result(plan, results, ProvisioningPlanState.FAILED, detail)
        completed_ids = {action.action_id for action in completed}
        rollback_actions = tuple(
            action
            for action in reversed(plan.rollback.actions)
            if action.undoes_action_id in completed_ids
        )
        if not rollback_actions:
            return self._result(plan, results, ProvisioningPlanState.FAILED, detail)
        for action in rollback_actions:
            provider = self._providers.get(action.provider_id)
            if provider is None:
                return self._result(
                    plan, results, ProvisioningPlanState.FAILED, "rollback provider unavailable"
                )
            receipt = await self._authorizer.authorize(plan, action)
            await self._authorizer.begin(receipt)
            applied = await provider.rollback(action, cancellation)
            await self._authorizer.finish(receipt, applied.outcome)
            if applied.outcome is not ProvisioningEffectOutcome.EFFECT_CONFIRMED:
                return self._result(plan, results, ProvisioningPlanState.FAILED, "rollback failed")
        return self._result(plan, results, ProvisioningPlanState.ROLLED_BACK, detail)

    async def _finish_safely(self, receipt: object, outcome: ProvisioningEffectOutcome) -> None:
        try:
            await self._authorizer.finish(receipt, outcome)
        except Exception:
            pass

    def _result(
        self,
        plan: ProvisioningPlan,
        results: Sequence[ProvisioningActionResult],
        state: ProvisioningPlanState,
        detail: str,
    ) -> ProvisioningResult:
        return ProvisioningResult(plan.plan_id, state, tuple(results), detail)

    @staticmethod
    def _failed(
        action: ProvisioningAction,
        detail: str,
        attempts: int = 0,
        outcome: ProvisioningEffectOutcome | None = None,
    ) -> ProvisioningActionResult:
        return ProvisioningActionResult(
            action.action_id, ProvisioningActionState.FAILED, outcome, detail, attempts
        )

    @staticmethod
    def _recovering(
        action: ProvisioningAction, detail: str, attempts: int = 0
    ) -> ProvisioningActionResult:
        return ProvisioningActionResult(
            action.action_id,
            ProvisioningActionState.RECOVERING,
            ProvisioningEffectOutcome.UNKNOWN_OUTCOME,
            detail,
            attempts,
        )

    @staticmethod
    def _failed_by_id(action_id: str) -> ProvisioningActionResult:
        return ProvisioningActionResult(
            action_id, ProvisioningActionState.PENDING, None, "pending", 0
        )

    @staticmethod
    def _artifacts_match(action: ProvisioningAction, observation: ProvisioningObservation) -> bool:
        if not action.artifacts:
            return True
        expected = tuple(item.sha256 for item in action.artifacts)
        return expected == observation.artifact_hashes


__all__ = [
    "BrokerProvisioningAuthorizer",
    "ProvisioningAction",
    "ProvisioningActionKind",
    "ProvisioningActionResult",
    "ProvisioningActionState",
    "ProvisioningApplyResult",
    "ProvisioningApprovalRequired",
    "ProvisioningArtifact",
    "ProvisioningAuthorization",
    "ProvisioningDenied",
    "ProvisioningEffectOutcome",
    "ProvisioningEngine",
    "ProvisioningError",
    "ProvisioningObservation",
    "ProvisioningPlan",
    "ProvisioningPlanState",
    "ProvisioningProvider",
    "ProvisioningResult",
    "ProvisioningRollbackPlan",
    "ProvisioningValidationError",
]
