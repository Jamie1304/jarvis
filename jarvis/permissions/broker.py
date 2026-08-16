"""Deny-by-default permission broker and trusted approval lifecycle."""

import asyncio
import hashlib
import json
from collections.abc import Callable, Mapping
from dataclasses import replace
from datetime import UTC, datetime, timedelta
from uuid import UUID, uuid4

from jarvis.events import (
    EventBus,
    EventEnvelope,
    EventType,
    PermissionDenied,
    PermissionGranted,
    PermissionRequested,
)
from jarvis.permissions.audit import AuditSink, InMemoryAuditSink
from jarvis.permissions.models import (
    ActionDescriptor,
    ApprovalActorKind,
    ApprovalChoice,
    ApprovalDecisionResult,
    ApprovalIdentity,
    ApprovalRequest,
    ApprovalSource,
    ApprovalStatus,
    AuditRecord,
    AuthorizationReceipt,
    AuthorizationResult,
    Decision,
    DecisionReason,
    Permission,
    PermissionRequest,
    PermissionScope,
    PolicyEvaluation,
    RememberedGrant,
)
from jarvis.permissions.policy import PolicyEngine

type Clock = Callable[[], datetime]


class PermissionBroker:
    """The only runtime authority allowed to authorize tool execution."""

    def __init__(
        self,
        policy: PolicyEngine,
        *,
        audit_sink: AuditSink | None = None,
        approval_ttl_seconds: int = 300,
        max_remembered_seconds: int = 3600,
        clock: Clock | None = None,
        event_bus: EventBus | None = None,
    ) -> None:
        if approval_ttl_seconds <= 0 or max_remembered_seconds <= 0:
            raise ValueError("Approval and remembered-grant lifetimes must be positive")
        self._policy = policy
        self._audit = audit_sink or InMemoryAuditSink()
        self._approval_ttl_seconds = approval_ttl_seconds
        self._max_remembered_seconds = max_remembered_seconds
        self._clock = clock or (lambda: datetime.now(UTC))
        self._event_bus = event_bus
        self._registered_tools: dict[str, tuple[int, frozenset[Permission]]] = {}
        self._approvals: dict[UUID, ApprovalRequest] = {}
        self._grants: dict[UUID, RememberedGrant] = {}
        self._lock = asyncio.Lock()

    @property
    def audit_sink(self) -> AuditSink:
        return self._audit

    def register_tool(
        self,
        tool_id: str,
        tool_identity: object,
        declared_permissions: frozenset[Permission],
    ) -> None:
        """Bind trusted manifest permissions to one exact registered instance."""

        existing = self._registered_tools.get(tool_id)
        registration = (id(tool_identity), declared_permissions)
        if existing == registration:
            return
        if (
            not tool_id
            or existing is not None
            or any(not isinstance(permission, Permission) for permission in declared_permissions)
        ):
            raise ValueError("Tool registration must be unique and use known permissions")
        self._registered_tools[tool_id] = registration

    def unregister_tool(self, tool_id: str, tool_identity: object) -> bool:
        registration = self._registered_tools.get(tool_id)
        if registration is None or registration[0] != id(tool_identity):
            return False
        del self._registered_tools[tool_id]
        return True

    async def authorize(
        self,
        *,
        tool_id: str,
        tool_identity: object,
        declared_permissions: frozenset[Permission],
        task_id: UUID,
        user_id: str | None,
        descriptor: ActionDescriptor,
        normalized_arguments: Mapping[str, object],
    ) -> AuthorizationResult:
        """Authorize an exact validated action without accepting model permission claims."""

        now = self._now()
        try:
            fingerprint = self.fingerprint(normalized_arguments)
        except (TypeError, ValueError):
            result = AuthorizationResult(False, DecisionReason.MALFORMED_ARGUMENTS)
            await self._audit_immediate(
                task_id=task_id,
                user_id=user_id,
                tool_id=tool_id,
                descriptor=descriptor,
                argument_names=tuple(sorted(normalized_arguments)),
                fingerprint="invalid",
                evaluations=(),
                reason=result.reason,
                outcome="not_executed",
            )
            return result

        argument_names = tuple(sorted(normalized_arguments))
        registration = self._registered_tools.get(tool_id)
        if registration is None or registration[0] != id(tool_identity):
            reason = DecisionReason.UNKNOWN_TOOL
            await self._audit_immediate(
                task_id=task_id,
                user_id=user_id,
                tool_id=tool_id,
                descriptor=descriptor,
                argument_names=argument_names,
                fingerprint=fingerprint,
                evaluations=(),
                reason=reason,
                outcome="not_executed",
            )
            return AuthorizationResult(False, reason)
        registered_permissions = registration[1]
        requested_permissions = tuple(item.permission for item in descriptor.permissions)
        if (
            registered_permissions != declared_permissions
            or any(not isinstance(item, Permission) for item in requested_permissions)
            or len(set(requested_permissions)) != len(requested_permissions)
            or set(requested_permissions) != registered_permissions
        ):
            reason = DecisionReason.TOOL_PERMISSION_MISMATCH
            await self._audit_immediate(
                task_id=task_id,
                user_id=user_id,
                tool_id=tool_id,
                descriptor=descriptor,
                argument_names=argument_names,
                fingerprint=fingerprint,
                evaluations=(),
                reason=reason,
                outcome="not_executed",
            )
            return AuthorizationResult(False, reason)

        if not descriptor.permissions:
            evaluation = PolicyEvaluation(
                Decision.ALLOW,
                DecisionReason.NO_PERMISSIONS_REQUIRED,
                "builtin.no_permissions",
                PermissionScope(tool_id=tool_id, task_id=task_id),
                None,
            )
            receipt = AuthorizationReceipt(
                receipt_id=uuid4(),
                task_id=task_id,
                tool_id=tool_id,
                action=descriptor.action,
                argument_fingerprint=fingerprint,
                argument_names=argument_names,
                evaluations=(evaluation,),
                approval_requests=(),
                remembered_grants=(),
                user_id=user_id,
                authorized_at=now,
            )
            return AuthorizationResult(True, evaluation.reason, receipt=receipt)

        evaluations = tuple(
            self._policy.evaluate(
                PermissionRequest(
                    permission=request.permission,
                    scope=replace(request.scope, tool_id=tool_id, task_id=task_id),
                ),
                action=descriptor.action,
                safety_class=descriptor.safety_class,
            )
            for request in descriptor.permissions
        )
        denial = next((item for item in evaluations if item.decision is Decision.DENY), None)
        if denial is not None:
            self._emit_event(
                EventType.PERMISSION_DENIED,
                PermissionDenied(None, denial.reason.value),
                task_id,
            )
            await self._audit_immediate(
                task_id=task_id,
                user_id=user_id,
                tool_id=tool_id,
                descriptor=descriptor,
                argument_names=argument_names,
                fingerprint=fingerprint,
                evaluations=evaluations,
                reason=denial.reason,
                outcome="not_executed",
            )
            return AuthorizationResult(False, denial.reason)

        async with self._lock:
            self._expire_locked(now)
            approvals: list[ApprovalRequest] = []
            usable_approvals: list[ApprovalRequest] = []
            grants: list[RememberedGrant] = []
            missing: list[PolicyEvaluation] = []
            for evaluation in evaluations:
                if evaluation.decision is Decision.ALLOW:
                    continue
                if evaluation.normalized_scope is None:
                    missing.append(evaluation)
                    continue
                permission = evaluation.permission
                if permission is None:
                    missing.append(evaluation)
                    continue
                grant = self._grant_match_locked(permission, evaluation.normalized_scope, now)
                if grant is not None:
                    grants.append(grant)
                    continue
                approval = self._approved_match_locked(
                    task_id,
                    tool_id,
                    descriptor.action,
                    fingerprint,
                    permission,
                    evaluation.normalized_scope,
                    now,
                )
                if approval is not None:
                    approvals.append(approval)
                    usable_approvals.append(approval)
                    continue
                pending = self._pending_match_locked(
                    task_id,
                    tool_id,
                    descriptor.action,
                    fingerprint,
                    permission,
                    evaluation.normalized_scope,
                )
                if pending is None:
                    pending = ApprovalRequest(
                        request_id=uuid4(),
                        task_id=task_id,
                        exact_action=descriptor.action,
                        arguments_summary=descriptor.arguments_summary,
                        argument_fingerprint=fingerprint,
                        permission=permission,
                        risk=descriptor.risk,
                        scope=evaluation.normalized_scope,
                        reason=evaluation.reason,
                        policy_id=evaluation.policy_id or "unknown",
                        created_at=now,
                        expires_at=now + timedelta(seconds=self._approval_ttl_seconds),
                    )
                    self._approvals[pending.request_id] = pending
                    self._emit_event(
                        EventType.PERMISSION_REQUESTED,
                        PermissionRequested(
                            pending.request_id, permission.value, descriptor.risk.value
                        ),
                        task_id,
                    )
                approvals.append(pending)
                missing.append(evaluation)

            if missing:
                pending_approvals = tuple(
                    item for item in approvals if item.status is ApprovalStatus.PENDING
                )
                reason = DecisionReason.APPROVAL_PENDING
            else:
                for approval in usable_approvals:
                    consumed = replace(approval, status=ApprovalStatus.CONSUMED)
                    self._approvals[approval.request_id] = consumed
                consumed_by_id = self._approvals
                approvals = [consumed_by_id.get(item.request_id, item) for item in approvals]
                receipt = AuthorizationReceipt(
                    receipt_id=uuid4(),
                    task_id=task_id,
                    tool_id=tool_id,
                    action=descriptor.action,
                    argument_fingerprint=fingerprint,
                    argument_names=argument_names,
                    evaluations=evaluations,
                    approval_requests=tuple(approvals),
                    remembered_grants=tuple(grants),
                    user_id=user_id,
                    authorized_at=now,
                )
                for approval in approvals:
                    self._emit_event(
                        EventType.PERMISSION_GRANTED,
                        PermissionGranted(approval.request_id, approval.permission.value),
                        task_id,
                    )
                return AuthorizationResult(
                    True,
                    DecisionReason.APPROVAL_APPROVED,
                    receipt=receipt,
                )

        await self._audit_immediate(
            task_id=task_id,
            user_id=user_id,
            tool_id=tool_id,
            descriptor=descriptor,
            argument_names=argument_names,
            fingerprint=fingerprint,
            evaluations=evaluations,
            reason=reason,
            outcome="approval_pending",
        )
        return AuthorizationResult(False, reason, approval_requests=pending_approvals)

    def _emit_event(self, event_type: EventType, payload: object, task_id: UUID) -> None:
        if self._event_bus is None:
            return
        if not isinstance(payload, PermissionRequested | PermissionGranted | PermissionDenied):
            return
        self._event_bus.publish_nowait(
            EventEnvelope.create(
                event_type,
                payload,
                source="permissions.broker",
                task_id=task_id,
                correlation_id=task_id,
            )
        )

    async def decide(
        self,
        request_id: UUID,
        choice: ApprovalChoice,
        identity: ApprovalIdentity,
        source: ApprovalSource,
        *,
        remember_for_seconds: int | None = None,
    ) -> ApprovalDecisionResult:
        """Apply a decision from an authenticated trusted UI/API principal only."""

        now = self._now()
        if identity.kind is not ApprovalActorKind.TRUSTED_USER or source not in {
            ApprovalSource.TRUSTED_UI,
            ApprovalSource.TRUSTED_LOCAL_API,
        }:
            async with self._lock:
                request = self._approvals.get(request_id)
            if request is not None:
                await self._audit_approval_event(
                    request,
                    identity.identity_id,
                    source,
                    Decision.DENY,
                    DecisionReason.UNTRUSTED_APPROVER,
                    "approval_rejected",
                )
            return ApprovalDecisionResult(False, DecisionReason.UNTRUSTED_APPROVER, request)
        async with self._lock:
            self._expire_locked(now)
            request = self._approvals.get(request_id)
            if request is None:
                return ApprovalDecisionResult(False, DecisionReason.APPROVAL_EXPIRED, None)
            if request.status is ApprovalStatus.CONSUMED:
                return ApprovalDecisionResult(False, DecisionReason.APPROVAL_CONSUMED, request)
            if request.status is not ApprovalStatus.PENDING:
                return ApprovalDecisionResult(False, self._approval_reason(request.status), request)
            if choice is ApprovalChoice.DENY_ONCE:
                updated = replace(
                    request,
                    status=ApprovalStatus.DENIED,
                    approval_identity=identity.identity_id,
                    approval_source=source,
                )
            elif choice is ApprovalChoice.APPROVE_LIMITED:
                if (
                    remember_for_seconds is None
                    or isinstance(remember_for_seconds, bool)
                    or remember_for_seconds <= 0
                    or remember_for_seconds > self._max_remembered_seconds
                    or request.scope.duration_seconds is not None
                    and remember_for_seconds > request.scope.duration_seconds
                    or request.reason is DecisionReason.HARD_SAFETY_APPROVAL_REQUIRED
                ):
                    return ApprovalDecisionResult(
                        False,
                        DecisionReason.INVALID_REMEMBERED_GRANT,
                        request,
                    )
                grant = RememberedGrant(
                    grant_id=uuid4(),
                    permission=request.permission,
                    scope=request.scope,
                    tool_id=request.scope.tool_id or "",
                    identity_id=identity.identity_id,
                    source=source,
                    created_at=now,
                    expires_at=now + timedelta(seconds=remember_for_seconds),
                )
                self._grants[grant.grant_id] = grant
                updated = replace(
                    request,
                    status=ApprovalStatus.CONSUMED,
                    approval_identity=identity.identity_id,
                    approval_source=source,
                )
            else:
                updated = replace(
                    request,
                    status=ApprovalStatus.APPROVED,
                    approval_identity=identity.identity_id,
                    approval_source=source,
                )
            self._approvals[request_id] = updated
        reason = (
            DecisionReason.APPROVAL_DENIED
            if choice is ApprovalChoice.DENY_ONCE
            else DecisionReason.APPROVAL_APPROVED
        )
        await self._audit_approval_event(
            updated,
            identity.identity_id,
            source,
            Decision.DENY if choice is ApprovalChoice.DENY_ONCE else Decision.ALLOW,
            reason,
            f"approval_{updated.status.value}",
        )
        return ApprovalDecisionResult(True, reason, updated)

    async def cancel_request(self, request_id: UUID) -> ApprovalRequest | None:
        """Cancel a pending request from trusted application/task lifecycle code."""

        async with self._lock:
            request = self._approvals.get(request_id)
            if request is None or request.status is not ApprovalStatus.PENDING:
                return request
            cancelled = replace(
                request,
                status=ApprovalStatus.CANCELLED,
                approval_source=ApprovalSource.SYSTEM,
            )
            self._approvals[request_id] = cancelled
        await self._audit_approval_event(
            cancelled,
            None,
            ApprovalSource.SYSTEM,
            Decision.DENY,
            DecisionReason.APPROVAL_CANCELLED,
            "approval_cancelled",
        )
        return cancelled

    async def cancel_task(self, task_id: UUID) -> tuple[ApprovalRequest, ...]:
        """Cancel every pending approval associated with a cancelled task."""

        cancelled: list[ApprovalRequest] = []
        async with self._lock:
            for request_id, request in tuple(self._approvals.items()):
                if request.task_id == task_id and request.status is ApprovalStatus.PENDING:
                    updated = replace(
                        request,
                        status=ApprovalStatus.CANCELLED,
                        approval_source=ApprovalSource.SYSTEM,
                    )
                    self._approvals[request_id] = updated
                    cancelled.append(updated)
        for request in cancelled:
            await self._audit_approval_event(
                request,
                None,
                ApprovalSource.SYSTEM,
                Decision.DENY,
                DecisionReason.APPROVAL_CANCELLED,
                "approval_cancelled",
            )
        return tuple(cancelled)

    async def get_approval(self, request_id: UUID) -> ApprovalRequest | None:
        async with self._lock:
            self._expire_locked(self._now())
            return self._approvals.get(request_id)

    async def pending_approvals(self, task_id: UUID | None = None) -> tuple[ApprovalRequest, ...]:
        async with self._lock:
            self._expire_locked(self._now())
            return tuple(
                request
                for request in self._approvals.values()
                if request.status is ApprovalStatus.PENDING
                and (task_id is None or request.task_id == task_id)
            )

    async def record_execution_outcome(self, receipt: AuthorizationReceipt, outcome: str) -> None:
        """Complete audit evidence after the brokered implementation returns."""

        approvals = receipt.approval_requests
        for evaluation in receipt.evaluations:
            approval = next(
                (item for item in approvals if evaluation.normalized_scope == item.scope),
                None,
            )
            grant = next(
                (
                    item
                    for item in receipt.remembered_grants
                    if evaluation.normalized_scope == item.scope
                ),
                None,
            )
            await self._audit.append(
                AuditRecord(
                    time=self._now(),
                    user_id=receipt.user_id,
                    task_id=receipt.task_id,
                    tool_id=receipt.tool_id,
                    requested_permission=self._permission_value(evaluation),
                    action=receipt.action,
                    argument_names=receipt.argument_names,
                    argument_fingerprint=receipt.argument_fingerprint,
                    normalized_scope=evaluation.normalized_scope,
                    policy_id=evaluation.policy_id,
                    decision=evaluation.decision,
                    reason=evaluation.reason,
                    approval_identity=(
                        approval.approval_identity
                        if approval
                        else grant.identity_id
                        if grant
                        else None
                    ),
                    approval_source=(
                        approval.approval_source if approval else grant.source if grant else None
                    ),
                    execution_outcome=outcome,
                )
            )

    @staticmethod
    def fingerprint(arguments: Mapping[str, object]) -> str:
        """Hash canonical full arguments without retaining their values."""

        encoded = json.dumps(
            dict(arguments),
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=False,
            allow_nan=False,
        ).encode("utf-8")
        return hashlib.sha256(encoded).hexdigest()

    async def _audit_immediate(
        self,
        *,
        task_id: UUID,
        user_id: str | None,
        tool_id: str,
        descriptor: ActionDescriptor,
        argument_names: tuple[str, ...],
        fingerprint: str,
        evaluations: tuple[PolicyEvaluation, ...],
        reason: DecisionReason,
        outcome: str,
    ) -> None:
        items: tuple[PolicyEvaluation | None, ...] = evaluations or (None,)
        for evaluation in items:
            await self._audit.append(
                AuditRecord(
                    time=self._now(),
                    user_id=user_id,
                    task_id=task_id,
                    tool_id=tool_id,
                    requested_permission=(
                        self._permission_value(evaluation) if evaluation is not None else None
                    ),
                    action=descriptor.action,
                    argument_names=argument_names,
                    argument_fingerprint=fingerprint,
                    normalized_scope=(evaluation.normalized_scope if evaluation else None),
                    policy_id=evaluation.policy_id if evaluation else None,
                    decision=evaluation.decision if evaluation else Decision.DENY,
                    reason=reason if evaluation is None else evaluation.reason,
                    approval_identity=None,
                    approval_source=None,
                    execution_outcome=outcome,
                )
            )

    async def _audit_approval_event(
        self,
        request: ApprovalRequest,
        identity_id: str | None,
        source: ApprovalSource,
        decision: Decision,
        reason: DecisionReason,
        outcome: str,
    ) -> None:
        await self._audit.append(
            AuditRecord(
                time=self._now(),
                user_id=identity_id,
                task_id=request.task_id,
                tool_id=request.scope.tool_id or "unknown",
                requested_permission=request.permission.value,
                action=request.exact_action,
                argument_names=tuple(item.name for item in request.arguments_summary),
                argument_fingerprint=request.argument_fingerprint,
                normalized_scope=request.scope,
                policy_id=request.policy_id,
                decision=decision,
                reason=reason,
                approval_identity=identity_id,
                approval_source=source,
                execution_outcome=outcome,
            )
        )

    @staticmethod
    def _permission_value(evaluation: PolicyEvaluation) -> str | None:
        return evaluation.permission.value if evaluation.permission is not None else None

    def _approved_match_locked(
        self,
        task_id: UUID,
        tool_id: str,
        action: str,
        fingerprint: str,
        permission: Permission,
        scope: PermissionScope,
        now: datetime,
    ) -> ApprovalRequest | None:
        for request in self._approvals.values():
            if (
                request.status is ApprovalStatus.APPROVED
                and request.expires_at > now
                and self._approval_matches(
                    request, task_id, tool_id, action, fingerprint, permission, scope
                )
            ):
                return request
        return None

    def _pending_match_locked(
        self,
        task_id: UUID,
        tool_id: str,
        action: str,
        fingerprint: str,
        permission: Permission,
        scope: PermissionScope,
    ) -> ApprovalRequest | None:
        return next(
            (
                request
                for request in self._approvals.values()
                if request.status is ApprovalStatus.PENDING
                and self._approval_matches(
                    request, task_id, tool_id, action, fingerprint, permission, scope
                )
            ),
            None,
        )

    @staticmethod
    def _approval_matches(
        request: ApprovalRequest,
        task_id: UUID,
        tool_id: str,
        action: str,
        fingerprint: str,
        permission: Permission,
        scope: PermissionScope,
    ) -> bool:
        return (
            request.task_id == task_id
            and request.scope.tool_id == tool_id
            and request.exact_action == action
            and request.argument_fingerprint == fingerprint
            and request.permission is permission
            and request.scope == scope
        )

    def _grant_match_locked(
        self, permission: Permission, scope: PermissionScope, now: datetime
    ) -> RememberedGrant | None:
        return next(
            (
                grant
                for grant in self._grants.values()
                if grant.permission is permission
                and grant.tool_id == scope.tool_id
                and grant.scope == scope
                and grant.expires_at > now
            ),
            None,
        )

    def _expire_locked(self, now: datetime) -> None:
        for request_id, request in tuple(self._approvals.items()):
            if request.status in {ApprovalStatus.PENDING, ApprovalStatus.APPROVED} and (
                request.expires_at <= now
            ):
                self._approvals[request_id] = replace(request, status=ApprovalStatus.EXPIRED)
        self._grants = {
            grant_id: grant for grant_id, grant in self._grants.items() if grant.expires_at > now
        }

    def _now(self) -> datetime:
        value = self._clock()
        if value.tzinfo is None:
            raise ValueError("Permission broker clock must return timezone-aware timestamps")
        return value.astimezone(UTC)

    @staticmethod
    def _approval_reason(status: ApprovalStatus) -> DecisionReason:
        return {
            ApprovalStatus.PENDING: DecisionReason.APPROVAL_PENDING,
            ApprovalStatus.APPROVED: DecisionReason.APPROVAL_APPROVED,
            ApprovalStatus.DENIED: DecisionReason.APPROVAL_DENIED,
            ApprovalStatus.EXPIRED: DecisionReason.APPROVAL_EXPIRED,
            ApprovalStatus.CANCELLED: DecisionReason.APPROVAL_CANCELLED,
            ApprovalStatus.CONSUMED: DecisionReason.APPROVAL_CONSUMED,
        }[status]
