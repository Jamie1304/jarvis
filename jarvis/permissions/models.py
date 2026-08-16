"""Trusted permission, policy, approval, and audit records."""

from dataclasses import dataclass
from datetime import datetime
from enum import StrEnum
from uuid import UUID

# Directional formatting controls can make trusted labels appear to say something
# other than their underlying value.  Keep this explicit even though the controls
# are currently also non-printable according to Python's Unicode database.
_BIDI_DISPLAY_CONTROLS = frozenset(
    {
        "\u061c",  # Arabic letter mark
        "\u200e",  # left-to-right mark
        "\u200f",  # right-to-left mark
        "\u202a",  # left-to-right embedding
        "\u202b",  # right-to-left embedding
        "\u202c",  # pop directional formatting
        "\u202d",  # left-to-right override
        "\u202e",  # right-to-left override
        "\u2066",  # left-to-right isolate
        "\u2067",  # right-to-left isolate
        "\u2068",  # first-strong isolate
        "\u2069",  # pop directional isolate
        "\u206a",  # deprecated inhibit symmetric swapping
        "\u206b",  # deprecated activate symmetric swapping
        "\u206c",  # deprecated inhibit Arabic form shaping
        "\u206d",  # deprecated activate Arabic form shaping
        "\u206e",  # deprecated national digit shapes
        "\u206f",  # deprecated nominal digit shapes
    }
)


def validate_safe_display_text(
    value: object,
    *,
    field: str,
    max_length: int,
    allow_empty: bool = False,
    require_trimmed: bool = True,
) -> str:
    """Validate text before trusted code exposes it in an approval surface.

    Approval displays must preserve a one-to-one relationship between stored and
    rendered text.  C0/C1 controls (including tab, CR/LF, NUL and ANSI escape),
    non-printing Unicode, and bidirectional formatting controls are therefore
    rejected rather than escaped by individual consumers.
    """

    if (
        type(value) is not str
        or (not allow_empty and not value)
        or len(value) > max_length
        or (require_trimmed and value != value.strip())
        or any(
            not character.isprintable() or character in _BIDI_DISPLAY_CONTROLS
            for character in value
        )
    ):
        raise ValueError(f"{field} must be bounded printable text without display controls")
    return value


class Permission(StrEnum):
    """Granular privileged capabilities recognized by the broker."""

    FILESYSTEM_READ = "filesystem.read"
    FILESYSTEM_WRITE = "filesystem.write"
    SCREEN_READ = "screen.read"
    COMPUTER_INPUT = "computer.input"
    CAMERA_READ = "camera.read"
    MICROPHONE_READ = "microphone.read"
    CLIPBOARD_READ = "clipboard.read"
    CLIPBOARD_WRITE = "clipboard.write"
    TERMINAL_EXECUTE = "terminal.execute"
    APPLICATION_LAUNCH = "application.launch"
    APPLICATION_INSTALL = "application.install"
    NETWORK_REQUEST = "network.request"
    CODE_MODIFY = "code.modify"
    SYSTEM_POWER = "system.power"


class Decision(StrEnum):
    """Complete policy decision set."""

    ALLOW = "ALLOW"
    DENY = "DENY"
    REQUIRE_APPROVAL = "REQUIRE_APPROVAL"


class DecisionReason(StrEnum):
    """Stable, machine-readable reasons for permission outcomes."""

    POLICY_ALLOW = "policy_allow"
    POLICY_DENY = "policy_deny"
    POLICY_APPROVAL_REQUIRED = "policy_approval_required"
    NO_PERMISSIONS_REQUIRED = "no_permissions_required"
    UNKNOWN_PERMISSION = "unknown_permission"
    MALFORMED_PERMISSION = "malformed_permission"
    MALFORMED_ARGUMENTS = "malformed_arguments"
    MALFORMED_ACTION = "malformed_action"
    UNKNOWN_ACTION = "unknown_action"
    UNKNOWN_TOOL = "unknown_tool"
    TOOL_PERMISSION_MISMATCH = "tool_permission_mismatch"
    MALFORMED_SCOPE = "malformed_scope"
    SCOPE_OUTSIDE_POLICY = "scope_outside_policy"
    MISSING_POLICY = "missing_policy"
    POLICY_DISABLED = "policy_disabled"
    HARD_SAFETY_APPROVAL_REQUIRED = "hard_safety_approval_required"
    HARD_SAFETY_DENY = "hard_safety_deny"
    APPROVAL_PENDING = "approval_pending"
    APPROVAL_APPROVED = "approval_approved"
    APPROVAL_DENIED = "approval_denied"
    APPROVAL_EXPIRED = "approval_expired"
    APPROVAL_CANCELLED = "approval_cancelled"
    APPROVAL_CONSUMED = "approval_consumed"
    UNTRUSTED_APPROVER = "untrusted_approver"
    INVALID_REMEMBERED_GRANT = "invalid_remembered_grant"
    TASK_CANCELLED = "task_cancelled"
    MALFORMED_APPROVAL_DECISION = "malformed_approval_decision"
    AUDIT_UNAVAILABLE = "audit_unavailable"
    FORGED_AUTHORIZATION_RECEIPT = "forged_authorization_receipt"
    OPERATION_OUTCOME_UNKNOWN = "operation_outcome_unknown"


class Risk(StrEnum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class SafetyClass(StrEnum):
    """Hard-policy action categories assigned by trusted tool code."""

    ORDINARY = "ordinary"
    BULK_DELETION = "bulk_deletion"
    PRIVILEGE_ESCALATION = "privilege_escalation"
    DESTRUCTIVE_SYSTEM_COMMAND = "destructive_system_command"
    SOFTWARE_INSTALLATION = "software_installation"
    SELF_MODIFICATION = "self_modification"


class ApprovalStatus(StrEnum):
    PENDING = "pending"
    APPROVED = "approved"
    DENIED = "denied"
    EXPIRED = "expired"
    CANCELLED = "cancelled"
    CONSUMED = "consumed"


class ApprovalChoice(StrEnum):
    APPROVE_ONCE = "approve_once"
    DENY_ONCE = "deny_once"
    APPROVE_LIMITED = "approve_limited"


class ApprovalActorKind(StrEnum):
    TRUSTED_USER = "trusted_user"
    MODEL = "model"
    TOOL = "tool"
    SYSTEM = "system"


class ApprovalSource(StrEnum):
    TRUSTED_UI = "trusted_ui"
    TRUSTED_LOCAL_API = "trusted_local_api"
    MODEL = "model"
    TOOL = "tool"
    SYSTEM = "system"


@dataclass(frozen=True, slots=True)
class PermissionScope:
    """Optional least-privilege constraints attached to one request."""

    paths: tuple[str, ...] = ()
    applications: tuple[str, ...] = ()
    hosts: tuple[str, ...] = ()
    command_families: tuple[str, ...] = ()
    tool_id: str | None = None
    task_id: UUID | None = None
    duration_seconds: int | None = None


@dataclass(frozen=True, slots=True)
class ScopeConstraint:
    """Trusted upper bounds declared by one policy rule."""

    paths: tuple[str, ...] = ()
    applications: tuple[str, ...] = ()
    hosts: tuple[str, ...] = ()
    command_families: tuple[str, ...] = ()
    tools: frozenset[str] = frozenset()
    tasks: frozenset[UUID] = frozenset()
    max_duration_seconds: int | None = None


@dataclass(frozen=True, slots=True)
class PermissionRequest:
    permission: Permission | str
    scope: PermissionScope


@dataclass(frozen=True, slots=True)
class SafeArgument:
    """A summary item generated by trusted application code."""

    name: str
    value: str

    def __post_init__(self) -> None:
        validate_safe_display_text(
            self.name,
            field="Safe argument name",
            max_length=128,
        )
        validate_safe_display_text(
            self.value,
            field="Safe argument value",
            max_length=512,
            allow_empty=True,
        )


@dataclass(frozen=True, slots=True)
class ActionDescriptor:
    """Trusted description of an exact validated tool action."""

    action: str
    arguments_summary: tuple[SafeArgument, ...]
    risk: Risk
    permissions: tuple[PermissionRequest, ...]
    safety_class: SafetyClass = SafetyClass.ORDINARY

    def __post_init__(self) -> None:
        try:
            validate_safe_display_text(
                self.action,
                field="Action",
                max_length=128,
            )
        except ValueError as error:
            raise ValueError("Action descriptor must use trusted, bounded types") from error
        if (
            not isinstance(self.risk, Risk)
            or not isinstance(self.safety_class, SafetyClass)
            or not isinstance(self.arguments_summary, tuple)
            or any(type(item) is not SafeArgument for item in self.arguments_summary)
            or len({item.name for item in self.arguments_summary}) != len(self.arguments_summary)
            or not isinstance(self.permissions, tuple)
            or any(not isinstance(item, PermissionRequest) for item in self.permissions)
        ):
            raise ValueError("Action descriptor must use trusted, bounded types")


@dataclass(frozen=True, slots=True)
class PolicyRule:
    policy_id: str
    permission: Permission
    decision: Decision
    scope: ScopeConstraint
    actions: frozenset[str]
    enabled: bool = True

    def __post_init__(self) -> None:
        try:
            validate_safe_display_text(
                self.policy_id,
                field="Policy identifier",
                max_length=128,
            )
        except ValueError as error:
            raise ValueError("Policy rules must use known trusted types") from error
        if (
            not isinstance(self.permission, Permission)
            or not isinstance(self.decision, Decision)
            or not isinstance(self.scope, ScopeConstraint)
            or not isinstance(self.actions, frozenset)
            or any(not isinstance(action, str) for action in self.actions)
            or not isinstance(self.enabled, bool)
        ):
            raise ValueError("Policy rules must use known trusted types")


@dataclass(frozen=True, slots=True)
class PolicyEvaluation:
    decision: Decision
    reason: DecisionReason
    policy_id: str | None
    normalized_scope: PermissionScope | None
    permission: Permission | None = None


@dataclass(frozen=True, slots=True)
class ApprovalIdentity:
    identity_id: str
    kind: ApprovalActorKind

    def __post_init__(self) -> None:
        try:
            validate_safe_display_text(
                self.identity_id,
                field="Approval identity",
                max_length=256,
            )
        except ValueError as error:
            raise ValueError("Approval identity must use trusted bounded types") from error
        if not isinstance(self.kind, ApprovalActorKind):
            raise ValueError("Approval identity must use trusted bounded types")


@dataclass(frozen=True, slots=True)
class ApprovalRequest:
    request_id: UUID
    task_id: UUID
    exact_action: str
    arguments_summary: tuple[SafeArgument, ...]
    argument_fingerprint: str
    action_fingerprint: str
    permission: Permission
    risk: Risk
    scope: PermissionScope
    reason: DecisionReason
    policy_id: str
    created_at: datetime
    expires_at: datetime
    requester_user_id: str | None = None
    status: ApprovalStatus = ApprovalStatus.PENDING
    approval_identity: str | None = None
    approval_source: ApprovalSource | None = None


@dataclass(frozen=True, slots=True)
class RememberedGrant:
    grant_id: UUID
    permission: Permission
    scope: PermissionScope
    tool_id: str
    action_fingerprint: str
    policy_id: str
    policy_reason: DecisionReason
    identity_id: str
    source: ApprovalSource
    requester_user_id: str | None
    created_at: datetime
    expires_at: datetime


@dataclass(frozen=True, slots=True)
class ApprovalDecisionResult:
    accepted: bool
    reason: DecisionReason
    request: ApprovalRequest | None


@dataclass(frozen=True, slots=True)
class AuthorizationReceipt:
    receipt_id: UUID
    task_id: UUID
    tool_id: str
    action: str
    argument_fingerprint: str
    action_fingerprint: str
    argument_names: tuple[str, ...]
    evaluations: tuple[PolicyEvaluation, ...]
    approval_requests: tuple[ApprovalRequest, ...]
    remembered_grants: tuple[RememberedGrant, ...]
    user_id: str | None
    authorized_at: datetime
    expires_at: datetime


@dataclass(frozen=True, slots=True)
class AuthorizationResult:
    authorized: bool
    reason: DecisionReason
    receipt: AuthorizationReceipt | None = None
    approval_requests: tuple[ApprovalRequest, ...] = ()


@dataclass(frozen=True, slots=True)
class AuditRecord:
    time: datetime
    user_id: str | None
    task_id: UUID
    tool_id: str
    requested_permission: str | None
    action: str
    argument_names: tuple[str, ...]
    argument_fingerprint: str
    action_fingerprint: str
    normalized_scope: PermissionScope | None
    policy_id: str | None
    decision: Decision
    reason: DecisionReason
    approval_identity: str | None
    approval_source: ApprovalSource | None
    execution_outcome: str
    approval_request_id: UUID | None = None
