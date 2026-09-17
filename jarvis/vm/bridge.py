"""Scoped host bridge contracts. Guest input is never trusted as authority."""

from collections.abc import Callable, Mapping
from dataclasses import dataclass
from datetime import UTC, datetime
from enum import StrEnum
from uuid import UUID, uuid4

from jarvis.permissions.broker import PermissionBroker
from jarvis.permissions.models import (
    ActionDescriptor,
    AuthorizationReceipt,
    PermissionRequest,
    Risk,
    SafeArgument,
    SafetyClass,
)


class HostBridgeOperation(StrEnum):
    FILE_READ = "HOST_FILE_READ"
    FILE_WRITE = "HOST_FILE_WRITE"
    FILE_EXPORT = "HOST_FILE_EXPORT"
    FILE_IMPORT = "HOST_FILE_IMPORT"
    APP_LAUNCH = "HOST_APP_LAUNCH"
    APP_INTERACT = "HOST_APP_INTERACT"
    MOUSE_MOVE = "HOST_MOUSE_MOVE"
    KEYBOARD_INPUT = "HOST_KEYBOARD_INPUT"
    FOCUS_CHANGE = "HOST_FOCUS_CHANGE"
    PROCESS_EXECUTE = "HOST_PROCESS_EXECUTE"
    SCREEN_CAPTURE = "HOST_SCREEN_CAPTURE"
    CLIPBOARD_READ = "HOST_CLIPBOARD_READ"
    CLIPBOARD_WRITE = "HOST_CLIPBOARD_WRITE"
    DEVICE_ACCESS = "HOST_DEVICE_ACCESS"
    MODEL_INFERENCE = "HOST_MODEL_INFERENCE"
    FILE_COPY = "HOST_FILE_COPY"
    FILE_MOVE = "HOST_FILE_MOVE"
    FILE_RENAME = "HOST_FILE_RENAME"
    FILE_DELETE = "HOST_FILE_DELETE"
    FILE_RESTORE = "HOST_FILE_RESTORE"


@dataclass(frozen=True, slots=True)
class HostBridgeRequest:
    request_id: UUID
    task_id: UUID
    instance_id: UUID
    operation: HostBridgeOperation
    resource: str
    scope: str
    risk: str = "medium"
    expires_at: datetime | None = None
    tool_id: str | None = None
    action: str | None = None
    argument_fingerprint: str | None = None
    action_fingerprint: str | None = None
    approval_identity: str | None = None
    safety_class: SafetyClass = SafetyClass.ORDINARY


@dataclass(frozen=True, slots=True)
class HostBridgeResult:
    allowed: bool
    reason: str
    operation: HostBridgeOperation
    request_id: UUID


class HostBridge:
    """A deny-by-default request validator, not a guest-side capability object."""

    def __init__(
        self, permission_verifier: Callable[[HostBridgeRequest], bool] | None = None
    ) -> None:
        self.requests: list[HostBridgeRequest] = []
        self._permission_verifier = permission_verifier or (lambda request: False)
        self._consumed_request_ids: set[UUID] = set()
        self.instance_id = uuid4()

    def authorize(self, request: HostBridgeRequest) -> HostBridgeResult:
        self.requests.append(request)
        if request.expires_at is not None and request.expires_at <= datetime.now(UTC):
            return HostBridgeResult(False, "request expired", request.operation, request.request_id)
        if not self._permission_verifier(request):
            return HostBridgeResult(
                False, "trusted permission approval required", request.operation, request.request_id
            )
        if (
            not request.resource
            or not request.scope
            or _contains_wildcard(request.resource)
            or _contains_wildcard(request.scope)
        ):
            return HostBridgeResult(
                False, "resource and scope must be narrow", request.operation, request.request_id
            )
        return HostBridgeResult(
            True, "brokered scope approved", request.operation, request.request_id
        )

    def authorize_with_receipt(
        self,
        request: HostBridgeRequest,
        *,
        receipt: AuthorizationReceipt | None,
        broker: PermissionBroker,
        normalized_arguments: Mapping[str, object],
        expected_instance_id: UUID,
    ) -> HostBridgeResult:
        """Authorize one exact host request against an active broker receipt.

        This is deliberately separate from ``authorize`` so the legacy
        deny-by-default contract remains intact.  The trusted application
        service constructs the request; guest data never supplies a receipt,
        verifier, or scope authority.
        """

        self.requests.append(request)
        if request.expires_at is not None and request.expires_at <= datetime.now(UTC):
            return HostBridgeResult(False, "request expired", request.operation, request.request_id)
        if request.request_id in self._consumed_request_ids:
            return HostBridgeResult(
                False, "request replayed", request.operation, request.request_id
            )
        if (
            not request.resource
            or not request.scope
            or _contains_wildcard(request.resource)
            or _contains_wildcard(request.scope)
        ):
            return HostBridgeResult(
                False, "resource and scope must be narrow", request.operation, request.request_id
            )
        if receipt is None or type(receipt) is not AuthorizationReceipt:
            return HostBridgeResult(
                False, "trusted broker receipt required", request.operation, request.request_id
            )
        if request.instance_id != expected_instance_id:
            return HostBridgeResult(
                False,
                "request is bound to a different instance",
                request.operation,
                request.request_id,
            )
        if (
            request.task_id != receipt.task_id
            or request.tool_id != receipt.tool_id
            or request.action != receipt.action
            or request.expires_at != receipt.expires_at
        ):
            return HostBridgeResult(
                False,
                "request does not match the authorized task",
                request.operation,
                request.request_id,
            )
        if (
            request.argument_fingerprint != receipt.argument_fingerprint
            or broker.fingerprint(normalized_arguments) != receipt.argument_fingerprint
            or request.action_fingerprint != receipt.action_fingerprint
        ):
            return HostBridgeResult(
                False, "authorization fingerprint mismatch", request.operation, request.request_id
            )
        if not broker.is_active_receipt(receipt):
            return HostBridgeResult(
                False, "broker receipt is not active", request.operation, request.request_id
            )
        identities = {
            item.approval_identity
            for item in receipt.approval_requests
            if item.approval_identity is not None
        }
        identities.update(item.identity_id for item in receipt.remembered_grants)
        if identities and (
            request.approval_identity is None or request.approval_identity not in identities
        ):
            return HostBridgeResult(
                False,
                "authenticated approval identity is missing",
                request.operation,
                request.request_id,
            )
        expected_action_fingerprint = _request_action_fingerprint(request, broker)
        if (
            expected_action_fingerprint is None
            or expected_action_fingerprint != receipt.action_fingerprint
        ):
            return HostBridgeResult(
                False, "request action binding mismatch", request.operation, request.request_id
            )
        self._consumed_request_ids.add(request.request_id)
        return HostBridgeResult(
            True, "brokered scope approved", request.operation, request.request_id
        )


def _contains_wildcard(value: object) -> bool:
    return not isinstance(value, str) or any(character in value for character in ("*", "?"))


def _request_action_fingerprint(request: HostBridgeRequest, broker: PermissionBroker) -> str | None:
    if request.action is None:
        return None
    try:
        descriptor = build_host_bridge_action_descriptor(
            action=request.action,
            operation=request.operation,
            resource=request.resource,
            scope=request.scope,
            risk=request.risk,
            safety_class=request.safety_class,
        )
    except (TypeError, ValueError):
        return None
    return broker.action_fingerprint(descriptor)


def build_host_bridge_action_descriptor(
    *,
    action: str,
    operation: HostBridgeOperation,
    resource: str,
    scope: str,
    risk: str | Risk,
    permissions: tuple[PermissionRequest, ...] = (),
    safety_class: SafetyClass = SafetyClass.ORDINARY,
) -> ActionDescriptor:
    """Build the canonical trusted action shape used for bridge binding."""

    normalized_risk = risk if isinstance(risk, Risk) else Risk(risk)
    return ActionDescriptor(
        action=action,
        arguments_summary=(
            SafeArgument("resource", resource),
            SafeArgument("scope", scope),
            SafeArgument("operation", operation.value),
            SafeArgument("risk", normalized_risk.value),
        ),
        risk=normalized_risk,
        permissions=permissions,
        safety_class=safety_class,
    )
