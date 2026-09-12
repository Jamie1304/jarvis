"""Scoped host bridge contracts. Guest input is never trusted as authority."""

from collections.abc import Callable
from dataclasses import dataclass
from datetime import UTC, datetime
from enum import StrEnum
from uuid import UUID


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
            or request.resource == "*"
            or request.scope == "*"
        ):
            return HostBridgeResult(
                False, "resource and scope must be narrow", request.operation, request.request_id
            )
        return HostBridgeResult(
            True, "brokered scope approved", request.operation, request.request_id
        )
