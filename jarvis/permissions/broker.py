"""Deny-by-default permission broker and trusted approval lifecycle."""

import asyncio
import hashlib
import hmac
import json
import secrets
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
from jarvis.permissions.approval import (
    ApprovalContextVerifier,
    DenyAllApprovalContextVerifier,
    TrustedApprovalContext,
)
from jarvis.permissions.audit import AuditSink, InMemoryAuditSink
from jarvis.permissions.models import (
    ActionDescriptor,
    ApprovalChoice,
    ApprovalDecisionResult,
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
    Risk,
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
        approval_context_verifier: ApprovalContextVerifier | None = None,
    ) -> None:
        if approval_ttl_seconds <= 0 or max_remembered_seconds <= 0:
            raise ValueError("Approval and remembered-grant lifetimes must be positive")
        self._policy = policy
        self._audit = audit_sink or InMemoryAuditSink()
        self._approval_ttl_seconds = approval_ttl_seconds
        self._max_remembered_seconds = max_remembered_seconds
        self._clock = clock or (lambda: datetime.now(UTC))
        self._event_bus = event_bus
        self._approval_context_verifier = (
            approval_context_verifier or DenyAllApprovalContextVerifier()
        )
        self._fingerprint_secret = secrets.token_bytes(32)
        self._registered_tools: dict[str, tuple[int, frozenset[Permission]]] = {}
        self._approvals: dict[UUID, ApprovalRequest] = {}
        self._grants: dict[UUID, RememberedGrant] = {}
        self._issued_receipts: dict[UUID, AuthorizationReceipt] = {}
        self._active_receipts: dict[UUID, AuthorizationReceipt] = {}
        self._cancelled_tasks: set[UUID] = set()
        self._registration_sealed = False
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

        if self._registration_sealed:
            raise RuntimeError("Permission broker registration is sealed")
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
        if self._registration_sealed:
            raise RuntimeError("Permission broker registration is sealed")
        registration = self._registered_tools.get(tool_id)
        if registration is None or registration[0] != id(tool_identity):
            return False
        del self._registered_tools[tool_id]
        return True

    def seal_registration(self) -> None:
        """Permanently close normal runtime tool-registration mutation."""

        self._registration_sealed = True

    @property
    def registration_sealed(self) -> bool:
        return self._registration_sealed

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

        if type(descriptor) is not ActionDescriptor:
            safe_descriptor = ActionDescriptor(
                "malformed_tool_action",
                (),
                Risk.HIGH,
                (),
            )
            try:
                await self._audit_immediate(
                    task_id=task_id,
                    user_id=user_id,
                    tool_id=tool_id,
                    descriptor=safe_descriptor,
                    argument_names=tuple(sorted(normalized_arguments)),
                    fingerprint=fingerprint,
                    evaluations=(),
                    reason=DecisionReason.MALFORMED_ACTION,
                    outcome="not_executed",
                )
            except Exception:
                return AuthorizationResult(False, DecisionReason.AUDIT_UNAVAILABLE)
            return AuthorizationResult(False, DecisionReason.MALFORMED_ACTION)

        argument_names = tuple(sorted(normalized_arguments))
        action_fingerprint = self.action_fingerprint(descriptor)
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
                action_fingerprint=action_fingerprint,
                argument_names=argument_names,
                evaluations=(evaluation,),
                approval_requests=(),
                remembered_grants=(),
                user_id=user_id,
                authorized_at=now,
                expires_at=now + timedelta(seconds=self._approval_ttl_seconds),
            )
            async with self._lock:
                if task_id in self._cancelled_tasks:
                    return await self._deny_cancelled_task(
                        task_id=task_id,
                        user_id=user_id,
                        tool_id=tool_id,
                        descriptor=descriptor,
                        argument_names=argument_names,
                        fingerprint=fingerprint,
                        evaluations=(evaluation,),
                    )
                if not await self._issue_receipt(receipt):
                    return AuthorizationResult(False, DecisionReason.AUDIT_UNAVAILABLE)
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
            if task_id in self._cancelled_tasks:
                return await self._deny_cancelled_task(
                    task_id=task_id,
                    user_id=user_id,
                    tool_id=tool_id,
                    descriptor=descriptor,
                    argument_names=argument_names,
                    fingerprint=fingerprint,
                    evaluations=evaluations,
                )
            if any(
                item.task_id == task_id
                and item.tool_id == tool_id
                and item.action == descriptor.action
                and item.argument_fingerprint == fingerprint
                and item.action_fingerprint == action_fingerprint
                for item in (*self._issued_receipts.values(), *self._active_receipts.values())
            ):
                return AuthorizationResult(False, DecisionReason.OPERATION_OUTCOME_UNKNOWN)
            approvals: list[ApprovalRequest] = []
            usable_approvals: list[ApprovalRequest] = []
            new_pending: list[ApprovalRequest] = []
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
                grant = self._grant_match_locked(
                    permission,
                    evaluation.normalized_scope,
                    action_fingerprint,
                    evaluation.policy_id or "unknown",
                    evaluation.reason,
                    user_id,
                    now,
                )
                if grant is not None:
                    grants.append(grant)
                    continue
                approval = self._approved_match_locked(
                    task_id,
                    tool_id,
                    descriptor.action,
                    fingerprint,
                    action_fingerprint,
                    permission,
                    evaluation.normalized_scope,
                    evaluation.policy_id or "unknown",
                    evaluation.reason,
                    user_id,
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
                    action_fingerprint,
                    permission,
                    evaluation.normalized_scope,
                    evaluation.policy_id or "unknown",
                    evaluation.reason,
                    user_id,
                )
                if pending is None:
                    pending = ApprovalRequest(
                        request_id=uuid4(),
                        task_id=task_id,
                        exact_action=descriptor.action,
                        arguments_summary=descriptor.arguments_summary,
                        argument_fingerprint=fingerprint,
                        action_fingerprint=action_fingerprint,
                        permission=permission,
                        risk=descriptor.risk,
                        scope=evaluation.normalized_scope,
                        reason=evaluation.reason,
                        policy_id=evaluation.policy_id or "unknown",
                        created_at=now,
                        expires_at=now + timedelta(seconds=self._approval_ttl_seconds),
                        requester_user_id=user_id,
                    )
                    new_pending.append(pending)
                approvals.append(pending)
                missing.append(evaluation)

            # A request cannot become visible or approvable unless its exact,
            # secret-safe identity has first reached the durable audit sink.
            try:
                for pending in new_pending:
                    await self._audit_approval_event(
                        pending,
                        None,
                        ApprovalSource.SYSTEM,
                        Decision.REQUIRE_APPROVAL,
                        DecisionReason.APPROVAL_PENDING,
                        "approval_requested",
                    )
            except Exception:
                return AuthorizationResult(False, DecisionReason.AUDIT_UNAVAILABLE)
            for pending in new_pending:
                self._approvals[pending.request_id] = pending
                self._emit_event(
                    EventType.PERMISSION_REQUESTED,
                    PermissionRequested(
                        pending.request_id, pending.permission.value, pending.risk.value
                    ),
                    task_id,
                )

            if missing:
                pending_approvals = tuple(
                    item for item in approvals if item.status is ApprovalStatus.PENDING
                )
                reason = DecisionReason.APPROVAL_PENDING
            else:
                consumed_approvals = {
                    approval.request_id: replace(approval, status=ApprovalStatus.CONSUMED)
                    for approval in usable_approvals
                }
                approvals = [consumed_approvals.get(item.request_id, item) for item in approvals]
                receipt = AuthorizationReceipt(
                    receipt_id=uuid4(),
                    task_id=task_id,
                    tool_id=tool_id,
                    action=descriptor.action,
                    argument_fingerprint=fingerprint,
                    action_fingerprint=action_fingerprint,
                    argument_names=argument_names,
                    evaluations=evaluations,
                    approval_requests=tuple(approvals),
                    remembered_grants=tuple(grants),
                    user_id=user_id,
                    authorized_at=now,
                    expires_at=self._receipt_expiry(
                        now,
                        evaluations,
                        tuple(approvals),
                        tuple(grants),
                    ),
                )
                if not await self._issue_receipt(receipt):
                    return AuthorizationResult(False, DecisionReason.AUDIT_UNAVAILABLE)
                self._approvals.update(consumed_approvals)
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
        context: TrustedApprovalContext,
    ) -> ApprovalDecisionResult:
        """Apply one exact decision minted by the configured trusted channel."""

        now = self._now()
        verification = self._approval_context_verifier.verify_and_consume(context)
        verified = verification.context
        if not verification.accepted or verified is None:
            request_id = context.request_id if isinstance(context, TrustedApprovalContext) else None
            async with self._lock:
                request = self._approvals.get(request_id) if request_id is not None else None
            if request is not None:
                try:
                    await self._audit_approval_event(
                        request,
                        None,
                        ApprovalSource.SYSTEM,
                        Decision.DENY,
                        verification.reason,
                        "approval_rejected",
                    )
                except Exception:
                    return ApprovalDecisionResult(
                        False,
                        DecisionReason.AUDIT_UNAVAILABLE,
                        request,
                    )
            return ApprovalDecisionResult(False, verification.reason, request)

        request_id = verified.request_id
        choice = verified.choice
        identity = verified.identity
        source = verified.source
        remember_for_seconds = verified.remember_for_seconds
        async with self._lock:
            request = self._approvals.get(request_id)
            if request is None:
                return ApprovalDecisionResult(False, DecisionReason.APPROVAL_EXPIRED, None)
            if request.status in {ApprovalStatus.PENDING, ApprovalStatus.APPROVED} and (
                request.expires_at <= now
            ):
                expired = replace(request, status=ApprovalStatus.EXPIRED)
                try:
                    await self._audit_approval_event(
                        expired,
                        identity.identity_id,
                        source,
                        Decision.DENY,
                        DecisionReason.APPROVAL_EXPIRED,
                        "approval_rejected",
                    )
                except Exception:
                    return ApprovalDecisionResult(
                        False,
                        DecisionReason.AUDIT_UNAVAILABLE,
                        request,
                    )
                self._approvals[request_id] = expired
                return ApprovalDecisionResult(
                    False,
                    DecisionReason.APPROVAL_EXPIRED,
                    expired,
                )
            if request.status is not ApprovalStatus.PENDING:
                status_reason = self._approval_reason(request.status)
                try:
                    await self._audit_approval_event(
                        request,
                        identity.identity_id,
                        source,
                        Decision.DENY,
                        status_reason,
                        "approval_rejected",
                    )
                except Exception:
                    return ApprovalDecisionResult(
                        False,
                        DecisionReason.AUDIT_UNAVAILABLE,
                        request,
                    )
                return ApprovalDecisionResult(False, status_reason, request)
            if choice is ApprovalChoice.DENY_ONCE:
                grant = None
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
                    try:
                        await self._audit_approval_event(
                            request,
                            identity.identity_id,
                            source,
                            Decision.DENY,
                            DecisionReason.INVALID_REMEMBERED_GRANT,
                            "approval_rejected",
                        )
                    except Exception:
                        return ApprovalDecisionResult(
                            False,
                            DecisionReason.AUDIT_UNAVAILABLE,
                            request,
                        )
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
                    action_fingerprint=request.action_fingerprint,
                    policy_id=request.policy_id,
                    policy_reason=request.reason,
                    identity_id=identity.identity_id,
                    source=source,
                    requester_user_id=request.requester_user_id,
                    created_at=now,
                    expires_at=now + timedelta(seconds=remember_for_seconds),
                )
                updated = replace(
                    request,
                    status=ApprovalStatus.CONSUMED,
                    approval_identity=identity.identity_id,
                    approval_source=source,
                )
            elif choice is ApprovalChoice.APPROVE_ONCE:
                grant = None
                updated = replace(
                    request,
                    status=ApprovalStatus.APPROVED,
                    approval_identity=identity.identity_id,
                    approval_source=source,
                )
            else:  # Every enum member is handled explicitly; future values fail closed.
                return ApprovalDecisionResult(
                    False,
                    DecisionReason.MALFORMED_APPROVAL_DECISION,
                    request,
                )
            reason = (
                DecisionReason.APPROVAL_DENIED
                if choice is ApprovalChoice.DENY_ONCE
                else DecisionReason.APPROVAL_APPROVED
            )
            try:
                await self._audit_approval_event(
                    updated,
                    identity.identity_id,
                    source,
                    Decision.DENY if choice is ApprovalChoice.DENY_ONCE else Decision.ALLOW,
                    reason,
                    f"approval_{updated.status.value}",
                )
            except Exception:
                return ApprovalDecisionResult(
                    False,
                    DecisionReason.AUDIT_UNAVAILABLE,
                    request,
                )
            if grant is not None:
                self._grants[grant.grant_id] = grant
            self._approvals[request_id] = updated
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
            await self._audit_approval_event(
                cancelled,
                None,
                ApprovalSource.SYSTEM,
                Decision.DENY,
                DecisionReason.APPROVAL_CANCELLED,
                "approval_cancelled",
            )
            self._approvals[request_id] = cancelled
        return cancelled

    async def cancel_task(self, task_id: UUID) -> tuple[ApprovalRequest, ...]:
        """Cancel every unconsumed approval associated with a cancelled task."""

        cancelled: list[ApprovalRequest] = []
        audit_error: BaseException | None = None
        async with self._lock:
            for request_id, request in tuple(self._approvals.items()):
                if request.task_id == task_id and request.status in {
                    ApprovalStatus.PENDING,
                    ApprovalStatus.APPROVED,
                }:
                    updated = replace(
                        request,
                        status=ApprovalStatus.CANCELLED,
                        approval_source=ApprovalSource.SYSTEM,
                    )
                    if audit_error is None:
                        try:
                            await self._audit_approval_event(
                                updated,
                                None,
                                ApprovalSource.SYSTEM,
                                Decision.DENY,
                                DecisionReason.APPROVAL_CANCELLED,
                                "approval_cancelled",
                            )
                        except (Exception, asyncio.CancelledError) as error:
                            audit_error = error
                    self._approvals[request_id] = updated
                    cancelled.append(updated)
            for receipt_id, receipt in tuple(self._issued_receipts.items()):
                if receipt.task_id != task_id:
                    continue
                if audit_error is None:
                    try:
                        await self._append_receipt_audit(
                            receipt,
                            "not_executed_task_cancelled",
                        )
                    except (Exception, asyncio.CancelledError) as error:
                        audit_error = error
                del self._issued_receipts[receipt_id]
            self._grants = {
                grant_id: grant
                for grant_id, grant in self._grants.items()
                if grant.scope.task_id != task_id
            }
            self._cancelled_tasks.add(task_id)
        if audit_error is not None:
            raise audit_error
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

        async with self._lock:
            active = self._active_receipts.get(receipt.receipt_id)
            if active != receipt:
                raise ValueError(DecisionReason.FORGED_AUTHORIZATION_RECEIPT.value)
            # Serialize append and consumption. If durability fails, retain the
            # active receipt as explicit in-process unknown-outcome evidence.
            await self._append_receipt_audit(receipt, outcome)
            del self._active_receipts[receipt.receipt_id]

    async def begin_execution(self, receipt: AuthorizationReceipt) -> DecisionReason | None:
        """Claim one fresh receipt immediately before its host effect."""

        async with self._lock:
            issued = self._issued_receipts.get(receipt.receipt_id)
            if receipt.task_id in self._cancelled_tasks:
                if issued == receipt:
                    try:
                        await self._append_receipt_audit(
                            receipt,
                            "not_executed_task_cancelled",
                        )
                    except Exception:
                        return DecisionReason.AUDIT_UNAVAILABLE
                    del self._issued_receipts[receipt.receipt_id]
                return DecisionReason.TASK_CANCELLED
            if issued != receipt:
                return DecisionReason.FORGED_AUTHORIZATION_RECEIPT
            if receipt.expires_at <= self._now():
                del self._issued_receipts[receipt.receipt_id]
                try:
                    await self._append_receipt_audit(
                        receipt,
                        "not_executed_authorization_expired",
                    )
                except Exception:
                    return DecisionReason.AUDIT_UNAVAILABLE
                return DecisionReason.APPROVAL_EXPIRED
            del self._issued_receipts[receipt.receipt_id]
            self._active_receipts[receipt.receipt_id] = receipt
            return None

    async def _issue_receipt(self, receipt: AuthorizationReceipt) -> bool:
        """Durably record intent before making an execution receipt usable."""

        try:
            await self._append_receipt_audit(receipt, "authorized_intent")
        except Exception:
            return False
        self._issued_receipts[receipt.receipt_id] = receipt
        return True

    def _receipt_expiry(
        self,
        now: datetime,
        evaluations: tuple[PolicyEvaluation, ...],
        approvals: tuple[ApprovalRequest, ...],
        grants: tuple[RememberedGrant, ...],
    ) -> datetime:
        candidates = [now + timedelta(seconds=self._approval_ttl_seconds)]
        candidates.extend(approval.expires_at for approval in approvals)
        candidates.extend(grant.expires_at for grant in grants)
        candidates.extend(
            now + timedelta(seconds=evaluation.normalized_scope.duration_seconds)
            for evaluation in evaluations
            if evaluation.normalized_scope is not None
            and evaluation.normalized_scope.duration_seconds is not None
        )
        return min(candidates)

    async def _append_receipt_audit(
        self,
        receipt: AuthorizationReceipt,
        outcome: str,
    ) -> None:
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
                    action_fingerprint=receipt.action_fingerprint,
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
                    approval_request_id=approval.request_id if approval else None,
                )
            )

    def fingerprint(self, arguments: Mapping[str, object]) -> str:
        """Key canonical arguments without retaining or guessably hashing values."""

        encoded = json.dumps(
            dict(arguments),
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=False,
            allow_nan=False,
        ).encode("utf-8")
        return hmac.new(self._fingerprint_secret, encoded, hashlib.sha256).hexdigest()

    def action_fingerprint(self, descriptor: ActionDescriptor) -> str:
        """Bind approval to trusted action semantics without logging summaries."""

        encoded = json.dumps(
            {
                "action": descriptor.action,
                "arguments_summary": [
                    {"name": item.name, "value": item.value}
                    for item in descriptor.arguments_summary
                ],
                "risk": descriptor.risk.value,
                "safety_class": descriptor.safety_class.value,
            },
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=False,
        ).encode("utf-8")
        return hmac.new(self._fingerprint_secret, encoded, hashlib.sha256).hexdigest()

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
                    action_fingerprint=self.action_fingerprint(descriptor),
                    normalized_scope=(evaluation.normalized_scope if evaluation else None),
                    policy_id=evaluation.policy_id if evaluation else None,
                    decision=evaluation.decision if evaluation else Decision.DENY,
                    reason=reason if evaluation is None else evaluation.reason,
                    approval_identity=None,
                    approval_source=None,
                    execution_outcome=outcome,
                )
            )

    async def _deny_cancelled_task(
        self,
        *,
        task_id: UUID,
        user_id: str | None,
        tool_id: str,
        descriptor: ActionDescriptor,
        argument_names: tuple[str, ...],
        fingerprint: str,
        evaluations: tuple[PolicyEvaluation, ...],
    ) -> AuthorizationResult:
        """Audit and deny work for a task cancelled by trusted lifecycle code."""

        denied_evaluations = tuple(
            replace(
                evaluation,
                decision=Decision.DENY,
                reason=DecisionReason.TASK_CANCELLED,
            )
            for evaluation in evaluations
        )
        self._emit_event(
            EventType.PERMISSION_DENIED,
            PermissionDenied(None, DecisionReason.TASK_CANCELLED.value),
            task_id,
        )
        await self._audit_immediate(
            task_id=task_id,
            user_id=user_id,
            tool_id=tool_id,
            descriptor=descriptor,
            argument_names=argument_names,
            fingerprint=fingerprint,
            evaluations=denied_evaluations,
            reason=DecisionReason.TASK_CANCELLED,
            outcome="not_executed",
        )
        return AuthorizationResult(False, DecisionReason.TASK_CANCELLED)

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
                user_id=request.requester_user_id,
                task_id=request.task_id,
                tool_id=request.scope.tool_id or "unknown",
                requested_permission=request.permission.value,
                action=request.exact_action,
                argument_names=tuple(item.name for item in request.arguments_summary),
                argument_fingerprint=request.argument_fingerprint,
                action_fingerprint=request.action_fingerprint,
                normalized_scope=request.scope,
                policy_id=request.policy_id,
                decision=decision,
                reason=reason,
                approval_identity=identity_id,
                approval_source=source,
                execution_outcome=outcome,
                approval_request_id=request.request_id,
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
        action_fingerprint: str,
        permission: Permission,
        scope: PermissionScope,
        policy_id: str,
        policy_reason: DecisionReason,
        user_id: str | None,
        now: datetime,
    ) -> ApprovalRequest | None:
        for request in self._approvals.values():
            if (
                request.status is ApprovalStatus.APPROVED
                and request.expires_at > now
                and self._approval_matches(
                    request,
                    task_id,
                    tool_id,
                    action,
                    fingerprint,
                    action_fingerprint,
                    permission,
                    scope,
                    policy_id,
                    policy_reason,
                    user_id,
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
        action_fingerprint: str,
        permission: Permission,
        scope: PermissionScope,
        policy_id: str,
        policy_reason: DecisionReason,
        user_id: str | None,
    ) -> ApprovalRequest | None:
        return next(
            (
                request
                for request in self._approvals.values()
                if request.status is ApprovalStatus.PENDING
                and self._approval_matches(
                    request,
                    task_id,
                    tool_id,
                    action,
                    fingerprint,
                    action_fingerprint,
                    permission,
                    scope,
                    policy_id,
                    policy_reason,
                    user_id,
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
        action_fingerprint: str,
        permission: Permission,
        scope: PermissionScope,
        policy_id: str,
        policy_reason: DecisionReason,
        user_id: str | None,
    ) -> bool:
        return (
            request.task_id == task_id
            and request.scope.tool_id == tool_id
            and request.exact_action == action
            and request.argument_fingerprint == fingerprint
            and request.action_fingerprint == action_fingerprint
            and request.permission is permission
            and request.scope == scope
            and request.policy_id == policy_id
            and request.reason is policy_reason
            and request.requester_user_id == user_id
        )

    def _grant_match_locked(
        self,
        permission: Permission,
        scope: PermissionScope,
        action_fingerprint: str,
        policy_id: str,
        policy_reason: DecisionReason,
        user_id: str | None,
        now: datetime,
    ) -> RememberedGrant | None:
        return next(
            (
                grant
                for grant in self._grants.values()
                if grant.permission is permission
                and grant.tool_id == scope.tool_id
                and grant.scope == scope
                and grant.action_fingerprint == action_fingerprint
                and grant.policy_id == policy_id
                and grant.policy_reason is policy_reason
                and grant.requester_user_id == user_id
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
