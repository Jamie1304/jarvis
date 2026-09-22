"""Trusted, model-independent permission presentation.

Permission text is an output of the trusted action boundary, never an input to
it.  This module deliberately accepts only broker-owned approval records or
trusted action descriptors.  It does not parse model text, decide approval, or
return a broker capability.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from datetime import UTC, datetime
from enum import StrEnum
from uuid import UUID, uuid4

from jarvis.permissions.approval import (
    TrustedApprovalAuthenticator,
)
from jarvis.permissions.models import (
    ActionDescriptor,
    ApprovalChoice,
    ApprovalDecisionResult,
    ApprovalIdentity,
    ApprovalRequest,
    ApprovalSource,
    ApprovalStatus,
    DecisionReason,
    Permission,
    PermissionRequest,
    PermissionScope,
    Risk,
    SafeArgument,
    SafetyClass,
    validate_safe_display_text,
)
from jarvis.permissions.policy import normalize_scope

_MAX_PRESENTATION_TEXT = 8_192
_MAX_SCOPE_ITEMS = 64


class VoiceApprovalChoice(StrEnum):
    """Fixed, non-authorizing labels for a future trusted voice surface."""

    YES = "YES"
    NO = "NO"
    DETAILS = "DETAILS"


_VOICE_CHOICES = (
    VoiceApprovalChoice.YES,
    VoiceApprovalChoice.NO,
    VoiceApprovalChoice.DETAILS,
)


class SpokenApprovalResult(StrEnum):
    """Non-authorizing parse result for a trusted voice adapter."""

    APPROVE_ONCE = "approve_once"
    DENY_ONCE = "deny_once"
    DETAILS = "details"
    AMBIGUOUS = "ambiguous"
    NO_RESPONSE = "no_response"


class ApprovalChannelClass(StrEnum):
    """Trust level required before an approval channel may authorize."""

    NON_PRIVILEGED_CONFIRMATION = "non_privileged_confirmation"
    PRIVILEGED_APPROVAL = "privileged_approval"
    HIGH_RISK_APPROVAL = "high_risk_approval"


class ApprovalChannelPolicy:
    """Central v1 policy for approval-channel trust.

    Speech recognition is a transport for untrusted text.  It is never an
    owner-authentication channel.  The only voice authorization allowed by
    this policy is the explicitly non-privileged confirmation class; trusted
    desktop composition must authenticate the owner for the other classes.
    """

    @staticmethod
    def classify(
        risk: Risk,
        safety_class: SafetyClass = SafetyClass.ORDINARY,
        *,
        permission: Permission | None = None,
    ) -> ApprovalChannelClass:
        if (
            not isinstance(risk, Risk)
            or not isinstance(safety_class, SafetyClass)
            or permission is not None
            and not isinstance(permission, Permission)
        ):
            raise ValueError("Approval channel metadata is malformed")
        if risk is Risk.CRITICAL or safety_class is not SafetyClass.ORDINARY:
            return ApprovalChannelClass.HIGH_RISK_APPROVAL
        if permission is not None or risk is Risk.HIGH or risk is Risk.MEDIUM:
            return ApprovalChannelClass.PRIVILEGED_APPROVAL
        return ApprovalChannelClass.NON_PRIVILEGED_CONFIRMATION

    @staticmethod
    def voice_may_authorize(channel_class: ApprovalChannelClass) -> bool:
        return channel_class is ApprovalChannelClass.NON_PRIVILEGED_CONFIRMATION


def parse_spoken_approval(text: str | None) -> SpokenApprovalResult:
    """Accept only exact, policy-approved phrases; never infer conditions."""

    if text is None:
        return SpokenApprovalResult.NO_RESPONSE
    normalized = " ".join(text.casefold().strip().split())
    if not normalized:
        return SpokenApprovalResult.NO_RESPONSE
    if any(marker in normalized for marker in (",", " but ", " unless ", " if ", " only ")):
        return SpokenApprovalResult.AMBIGUOUS
    phrase = normalized.rstrip(".!?")
    if phrase in {"yes", "allow once", "go ahead"}:
        return SpokenApprovalResult.APPROVE_ONCE
    if phrase in {"no", "deny", "deny once", "cancel"}:
        return SpokenApprovalResult.DENY_ONCE
    if phrase == "details":
        return SpokenApprovalResult.DETAILS
    return SpokenApprovalResult.AMBIGUOUS


def approval_choice_from_spoken(
    text: str | None,
    *,
    channel_class: ApprovalChannelClass = ApprovalChannelClass.PRIVILEGED_APPROVAL,
) -> ApprovalChoice | None:
    """Map speech to a choice only for an explicitly permitted channel.

    The secure default is the privileged class, so an affirmative transcript
    cannot become a broker approval merely because a caller forgot to supply
    channel metadata.  Denial remains safe to accept for every class.
    """

    if not isinstance(channel_class, ApprovalChannelClass):
        raise ValueError("Approval channel class is malformed")

    result = parse_spoken_approval(text)
    if (
        result is SpokenApprovalResult.APPROVE_ONCE
        and not ApprovalChannelPolicy.voice_may_authorize(channel_class)
    ):
        return None
    return {
        SpokenApprovalResult.APPROVE_ONCE: ApprovalChoice.APPROVE_ONCE,
        SpokenApprovalResult.DENY_ONCE: ApprovalChoice.DENY_ONCE,
    }.get(result)


@dataclass(frozen=True, slots=True)
class TrustedOperation:
    """The exact operation selected by trusted application code.

    The optional approval fields are populated only when the operation came
    from a broker-created request.  They are evidence for presentation, never
    an approval token or an execution receipt.
    """

    action: str
    arguments: tuple[SafeArgument, ...]
    risk: Risk
    permission_request: PermissionRequest
    safety_class: SafetyClass | None = None
    approval_request_id: UUID | None = None
    task_id: UUID | None = None
    argument_fingerprint: str | None = None
    action_fingerprint: str | None = None
    expires_at: datetime | None = None

    def __post_init__(self) -> None:
        _safe_text(self.action, "Trusted action", 128)
        if (
            type(self.arguments) is not tuple
            or any(type(item) is not SafeArgument for item in self.arguments)
            or len({item.name for item in self.arguments}) != len(self.arguments)
            or not isinstance(self.risk, Risk)
            or type(self.permission_request) is not PermissionRequest
            or not isinstance(self.permission_request.permission, Permission)
            or type(self.permission_request.scope) is not PermissionScope
            or self.safety_class is not None
            and not isinstance(self.safety_class, SafetyClass)
            or self.approval_request_id is not None
            and not isinstance(self.approval_request_id, UUID)
            or self.task_id is not None
            and not isinstance(self.task_id, UUID)
            or self.argument_fingerprint is not None
            and not _digest(self.argument_fingerprint)
            or self.action_fingerprint is not None
            and not _digest(self.action_fingerprint)
            or self.expires_at is not None
            and (not isinstance(self.expires_at, datetime) or self.expires_at.tzinfo is None)
        ):
            raise ValueError("Trusted operation metadata is malformed")
        _validate_scope_shape(self.permission_request.scope)


@dataclass(frozen=True, slots=True)
class TrustedPermissionPresentation:
    """One immutable authority object shared by desktop and voice renderers."""

    operation: TrustedOperation
    short_explanation: str
    exact_details: str
    target: str
    scope: str
    effect: str
    risk: Risk
    permission_requested: Permission
    voice_choices: tuple[VoiceApprovalChoice, ...] = _VOICE_CHOICES

    def __post_init__(self) -> None:
        if type(self.operation) is not TrustedOperation or not isinstance(self.risk, Risk):
            raise ValueError("Trusted permission presentation is malformed")
        if self.permission_requested is not self.operation.permission_request.permission:
            raise ValueError("Presentation permission does not match the trusted operation")
        for value, field, maximum in (
            (self.short_explanation, "Short permission explanation", 512),
            (self.exact_details, "Exact permission details", _MAX_PRESENTATION_TEXT),
            (self.target, "Permission target", 2_048),
            (self.scope, "Permission scope", 4_096),
            (self.effect, "Permission effect", 512),
        ):
            _safe_text(value, field, maximum)
        if (
            type(self.voice_choices) is not tuple
            or self.voice_choices != _VOICE_CHOICES
            or self.risk is not self.operation.risk
        ):
            raise ValueError("Voice permission choices must use the fixed trusted contract")

    @property
    def approval_channel_class(self) -> ApprovalChannelClass:
        return ApprovalChannelPolicy.classify(
            self.risk,
            self.operation.safety_class or SafetyClass.ORDINARY,
            permission=self.permission_requested,
        )


class TrustedActionNarrator:
    """Build permission explanations from trusted typed operation metadata.

    ``ApprovalRequest`` is the canonical input for a permission prompt.  The
    descriptor overload is for trusted application code constructing a preview
    before the broker creates a request.  Neither path accepts a string or
    model-authored description.
    """

    def narrate(
        self,
        request: ApprovalRequest | PermissionRequest | object,
        operation: ActionDescriptor | None = None,
    ) -> TrustedPermissionPresentation:
        if type(request) is ApprovalRequest:
            if operation is not None:
                raise TypeError("An approval request already contains its exact operation")
            return self._from_approval_request(request)
        if type(request) is PermissionRequest:
            if type(operation) is not ActionDescriptor:
                raise TypeError("A PermissionRequest requires a trusted ActionDescriptor")
            return self._from_descriptor(request, operation)
        raise TypeError("Permission narration requires a trusted typed request")

    def narrate_operation(
        self,
        operation: ActionDescriptor,
        request: PermissionRequest,
    ) -> TrustedPermissionPresentation:
        """Explicit argument-order alias for trusted application composition."""

        return self.narrate(request, operation)

    def _from_approval_request(self, request: ApprovalRequest) -> TrustedPermissionPresentation:
        _validate_approval_request(request)
        permission_request = PermissionRequest(request.permission, request.scope)
        operation = TrustedOperation(
            action=request.exact_action,
            arguments=request.arguments_summary,
            risk=request.risk,
            permission_request=permission_request,
            approval_request_id=request.request_id,
            task_id=request.task_id,
            argument_fingerprint=request.argument_fingerprint,
            action_fingerprint=request.action_fingerprint,
            expires_at=request.expires_at,
        )
        return self._presentation(operation)

    def _from_descriptor(
        self,
        request: PermissionRequest,
        descriptor: ActionDescriptor,
    ) -> TrustedPermissionPresentation:
        _validate_permission_request(request)
        if sum(item == request for item in descriptor.permissions) != 1:
            raise ValueError("Permission request is not the unique permission on the operation")
        operation = TrustedOperation(
            action=descriptor.action,
            arguments=descriptor.arguments_summary,
            risk=descriptor.risk,
            permission_request=request,
            safety_class=descriptor.safety_class,
        )
        return self._presentation(operation)

    @staticmethod
    def _presentation(operation: TrustedOperation) -> TrustedPermissionPresentation:
        permission = _trusted_permission(operation)
        target = _target(operation.permission_request.scope)
        scope = _scope(operation.permission_request.scope)
        effect = _effect(permission)
        short = f"JARVIS requests {permission.value} permission to {operation.action}."
        exact = _exact_details(operation, target, scope, effect)
        return TrustedPermissionPresentation(
            operation=operation,
            short_explanation=short,
            exact_details=exact,
            target=target,
            scope=scope,
            effect=effect,
            risk=operation.risk,
            permission_requested=permission,
        )


class ExactOperationRenderer:
    """Render the same trusted presentation for different local surfaces."""

    def render(self, presentation: TrustedPermissionPresentation | object) -> str:
        trusted = _require_presentation(presentation)
        return trusted.exact_details

    def render_short(self, presentation: TrustedPermissionPresentation | object) -> str:
        trusted = _require_presentation(presentation)
        return trusted.short_explanation

    def render_voice(self, presentation: TrustedPermissionPresentation | object) -> str:
        """Return trusted voice UX without implying speech is owner approval."""

        trusted = _require_presentation(presentation)
        if not ApprovalChannelPolicy.voice_may_authorize(trusted.approval_channel_class):
            if trusted.approval_channel_class is ApprovalChannelClass.HIGH_RISK_APPROVAL:
                label = "high-risk"
            else:
                label = "privileged"
            return (
                f"{trusted.short_explanation} Say DETAILS or NO. To approve this {label} action, "
                "use the trusted approval control on your desktop."
            )
        choices = " / ".join(choice.value for choice in trusted.voice_choices)
        return f"{trusted.short_explanation} Choose {choices}."


@dataclass(frozen=True, slots=True)
class DesktopApprovalHandoff:
    """Immutable voice-to-desktop reference for one broker approval request.

    This object contains no approval authority.  It is only a bounded,
    fingerprinted reference that lets the trusted desktop surface display and
    approve the exact request that voice narrated.
    """

    handoff_id: UUID
    request_id: UUID
    task_id: UUID
    argument_fingerprint: str
    action_fingerprint: str
    permission: Permission
    scope: PermissionScope
    expires_at: datetime

    @classmethod
    def create(cls, request: ApprovalRequest) -> DesktopApprovalHandoff:
        _validate_approval_request(request)
        if request.status is not ApprovalStatus.PENDING:
            raise ValueError("Only a pending approval can be handed off")
        return cls(
            handoff_id=uuid4(),
            request_id=request.request_id,
            task_id=request.task_id,
            argument_fingerprint=request.argument_fingerprint,
            action_fingerprint=request.action_fingerprint,
            permission=request.permission,
            scope=request.scope,
            expires_at=request.expires_at,
        )

    def matches(self, request: ApprovalRequest, *, now: datetime | None = None) -> bool:
        if type(request) is not ApprovalRequest:
            return False
        if request.status is not ApprovalStatus.PENDING:
            return False
        comparison_time = now or datetime.now(UTC)
        if comparison_time.tzinfo is None or self.expires_at <= comparison_time:
            return False
        return (
            self.request_id == request.request_id
            and self.task_id == request.task_id
            and self.argument_fingerprint == request.argument_fingerprint
            and self.action_fingerprint == request.action_fingerprint
            and self.permission is request.permission
            and self.scope == request.scope
            and self.expires_at == request.expires_at
        )


class TrustedDesktopApprovalSurface:
    """Authenticate and consume a handoff through the normal PermissionBroker."""

    async def decide(
        self,
        handoff: DesktopApprovalHandoff,
        request: ApprovalRequest,
        *,
        choice: ApprovalChoice,
        authenticator: TrustedApprovalAuthenticator,
        identity: ApprovalIdentity,
        broker: object,
        now: datetime | None = None,
    ) -> ApprovalDecisionResult:
        if not isinstance(handoff, DesktopApprovalHandoff) or not isinstance(
            authenticator, TrustedApprovalAuthenticator
        ):
            raise TypeError("Desktop approval requires trusted typed objects")
        if choice not in {ApprovalChoice.APPROVE_ONCE, ApprovalChoice.DENY_ONCE}:
            raise ValueError("Desktop surface supports only one-time approve or deny")
        if not handoff.matches(request, now=now):
            return ApprovalDecisionResult(
                False, DecisionReason.MALFORMED_APPROVAL_DECISION, request
            )
        decide = getattr(broker, "decide", None)
        if not callable(decide):
            raise TypeError("Desktop approval requires the application PermissionBroker")
        context = authenticator.issue_context(
            request_id=request.request_id,
            choice=choice,
            identity=identity,
        )
        if context.source is not ApprovalSource.TRUSTED_UI:
            return ApprovalDecisionResult(False, DecisionReason.UNTRUSTED_APPROVER, request)
        result = await decide(context)
        if not isinstance(result, ApprovalDecisionResult):
            raise TypeError("PermissionBroker returned malformed approval result")
        return result


def _validate_approval_request(request: ApprovalRequest) -> None:
    if (
        not isinstance(request.request_id, UUID)
        or not isinstance(request.task_id, UUID)
        or not isinstance(request.permission, Permission)
        or not isinstance(request.risk, Risk)
        or not isinstance(request.reason, DecisionReason)
        or not isinstance(request.status, ApprovalStatus)
        or not isinstance(request.created_at, datetime)
        or request.created_at.tzinfo is None
        or not isinstance(request.expires_at, datetime)
        or request.expires_at.tzinfo is None
        or request.expires_at <= request.created_at
        or type(request.arguments_summary) is not tuple
        or any(type(item) is not SafeArgument for item in request.arguments_summary)
        or len({item.name for item in request.arguments_summary}) != len(request.arguments_summary)
        or not _digest(request.argument_fingerprint)
        or not _digest(request.action_fingerprint)
        or type(request.scope) is not PermissionScope
        or request.approval_source is not None
        and (
            type(request.approval_source) is not ApprovalSource
            or request.approval_source
            not in {ApprovalSource.TRUSTED_UI, ApprovalSource.TRUSTED_LOCAL_API}
        )
    ):
        raise ValueError("Approval request metadata is malformed")
    _safe_text(request.exact_action, "Approval action", 128)
    _safe_text(request.policy_id, "Approval policy", 128)
    if request.requester_user_id is not None:
        _safe_text(request.requester_user_id, "Approval requester", 256)
    if request.approval_identity is not None:
        _safe_text(request.approval_identity, "Approval identity", 256)
    try:
        normalized = normalize_scope(request.scope, request.permission)
    except (TypeError, ValueError, AttributeError) as error:
        raise ValueError("Approval scope is not validated") from error
    if normalized != request.scope:
        raise ValueError("Approval scope is not canonical")


def _validate_permission_request(request: PermissionRequest) -> None:
    if type(request.permission) is not Permission or type(request.scope) is not PermissionScope:
        raise ValueError("Permission request metadata is malformed")
    _validate_scope_shape(request.scope)


def _validate_scope_shape(scope: PermissionScope) -> None:
    fields = (
        (scope.paths, "Permission paths", 4_096),
        (scope.applications, "Permission applications", 512),
        (scope.hosts, "Permission hosts", 512),
        (scope.command_families, "Permission command families", 512),
    )
    for values, field, maximum in fields:
        if type(values) is not tuple or len(values) > _MAX_SCOPE_ITEMS:
            raise ValueError(f"{field} are malformed")
        for value in values:
            _safe_text(value, field, maximum)
    if scope.tool_id is not None:
        _safe_text(scope.tool_id, "Permission tool", 128)
    if scope.task_id is not None and not isinstance(scope.task_id, UUID):
        raise ValueError("Permission task scope is malformed")
    if scope.duration_seconds is not None and (
        isinstance(scope.duration_seconds, bool)
        or not isinstance(scope.duration_seconds, int)
        or scope.duration_seconds <= 0
    ):
        raise ValueError("Permission duration is malformed")


def _exact_details(
    operation: TrustedOperation,
    target: str,
    scope: str,
    effect: str,
) -> str:
    permission = _trusted_permission(operation)
    arguments = json.dumps(
        [{"name": item.name, "value": item.value} for item in operation.arguments],
        ensure_ascii=False,
        separators=(",", ":"),
    )
    details = (
        f"action={operation.action}; arguments={arguments}; target={target}; scope={scope}; "
        f"effect={effect}; risk={operation.risk.value}; "
        f"permission={permission.value}"
    )
    if operation.approval_request_id is not None:
        details += f"; approval_request_id={operation.approval_request_id}"
    if operation.task_id is not None:
        details += f"; task_id={operation.task_id}"
    if operation.expires_at is not None:
        details += f"; expires_at={operation.expires_at.isoformat()}"
    _safe_text(details, "Exact permission details", _MAX_PRESENTATION_TEXT)
    return details


def _target(scope: PermissionScope) -> str:
    values: list[str] = []
    for label, items in (
        ("path", scope.paths),
        ("application", scope.applications),
        ("host", scope.hosts),
        ("command_family", scope.command_families),
    ):
        if items:
            values.append(f"{label}={','.join(items)}")
    if scope.tool_id is not None:
        values.append(f"tool={scope.tool_id}")
    return "; ".join(values) or "the requested operation"


def _scope(scope: PermissionScope) -> str:
    values: list[str] = []
    for label, items in (
        ("paths", scope.paths),
        ("applications", scope.applications),
        ("hosts", scope.hosts),
        ("command_families", scope.command_families),
    ):
        if items:
            values.append(f"{label}=[{','.join(items)}]")
    if scope.tool_id is not None:
        values.append(f"tool_id={scope.tool_id}")
    if scope.task_id is not None:
        values.append(f"task_id={scope.task_id}")
    if scope.duration_seconds is not None:
        values.append(f"duration_seconds={scope.duration_seconds}")
    return "; ".join(values) or "no additional restriction declared"


_EFFECTS = {
    Permission.FILESYSTEM_READ: "read data from the target",
    Permission.FILESYSTEM_WRITE: "create, change, or delete data at the target",
    Permission.SCREEN_READ: "capture screen content",
    Permission.COMPUTER_INPUT: "send keyboard or mouse input",
    Permission.CAMERA_READ: "capture camera data",
    Permission.MICROPHONE_READ: "capture microphone audio",
    Permission.CLIPBOARD_READ: "read clipboard data",
    Permission.CLIPBOARD_WRITE: "replace clipboard data",
    Permission.TERMINAL_EXECUTE: "start the approved command",
    Permission.APPLICATION_LAUNCH: "launch or close the approved application",
    Permission.APPLICATION_INSTALL: "install or update software",
    Permission.NETWORK_REQUEST: "send a network request",
    Permission.CODE_MODIFY: "change source code",
    Permission.SYSTEM_POWER: "change system power state",
}


def _trusted_permission(operation: TrustedOperation) -> Permission:
    permission = operation.permission_request.permission
    if not isinstance(permission, Permission):
        raise ValueError("Trusted operation permission is malformed")
    return permission


def _effect(permission: Permission) -> str:
    try:
        return _EFFECTS[permission]
    except KeyError as error:  # pragma: no cover - enum exhaustiveness guard
        raise ValueError("Permission has no trusted effect description") from error


def _safe_text(value: object, field: str, maximum: int) -> str:
    return validate_safe_display_text(value, field=field, max_length=maximum)


def _digest(value: object) -> bool:
    return (
        type(value) is str
        and len(value) == 64
        and all(character in "0123456789abcdef" for character in value)
    )


def _require_presentation(value: object) -> TrustedPermissionPresentation:
    if type(value) is not TrustedPermissionPresentation:
        raise TypeError("Renderer requires the exact trusted permission presentation")
    return value
