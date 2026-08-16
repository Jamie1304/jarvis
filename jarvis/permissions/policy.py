"""Fail-closed scoped policy evaluation and filesystem normalization."""

import os
import re
from dataclasses import replace
from pathlib import Path
from urllib.parse import urlsplit
from uuid import UUID

from jarvis.permissions.models import (
    Decision,
    DecisionReason,
    Permission,
    PermissionRequest,
    PermissionScope,
    PolicyEvaluation,
    PolicyRule,
    SafetyClass,
    ScopeConstraint,
    validate_safe_display_text,
)

_PATH_PERMISSIONS = {
    Permission.FILESYSTEM_READ,
    Permission.FILESYSTEM_WRITE,
    Permission.CODE_MODIFY,
}
_APPLICATION_PERMISSIONS = {
    Permission.APPLICATION_LAUNCH,
    Permission.APPLICATION_INSTALL,
}
_HOST_PERMISSIONS = {Permission.NETWORK_REQUEST}
_COMMAND_PERMISSIONS = {Permission.TERMINAL_EXECUTE, Permission.SYSTEM_POWER}
_WINDOWS_RESERVED = frozenset(
    {
        "aux",
        "clock$",
        "con",
        "conin$",
        "conout$",
        "nul",
        "prn",
        *(f"com{index}" for index in range(1, 10)),
        *(f"lpt{index}" for index in range(1, 10)),
    }
)


class ScopeNormalizationError(ValueError):
    """Raised internally when untrusted scope is ambiguous or malformed."""


def normalize_path(path: str) -> str:
    """Return one absolute canonical path while rejecting ambiguous traversal."""

    try:
        validate_safe_display_text(path, field="Path", max_length=4_096)
    except ValueError as error:
        raise ScopeNormalizationError("Path must be bounded printable text") from error
    windows_form = path.replace("/", "\\")
    if windows_form.startswith(("\\\\", "\\?\\", "\\.\\")):
        raise ScopeNormalizationError("UNC and Windows device paths are not permitted")
    components = tuple(item for item in re.split(r"[\\/]", path) if item)
    separator_body = windows_form[3:] if re.match(r"^[A-Za-z]:\\", windows_form) else windows_form
    if (
        "\\\\" in separator_body
        or any(item in {".", ".."} for item in components)
        or any(item.endswith((" ", ".")) for item in components)
        or any(":" in item for item in components[1:])
        or any(any(character in item for character in '<>"|?*') for item in components)
        or any(item.split(".", 1)[0].casefold() in _WINDOWS_RESERVED for item in components)
    ):
        raise ScopeNormalizationError("Path contains ambiguous Windows components")
    candidate = Path(path)
    if not candidate.is_absolute():
        raise ScopeNormalizationError("Relative paths are not permitted")
    if ".." in candidate.parts:
        raise ScopeNormalizationError("Parent traversal is not permitted")
    try:
        resolved = os.path.normcase(str(candidate.resolve(strict=False)))
        return validate_safe_display_text(
            resolved,
            field="Resolved path",
            max_length=4_096,
        )
    except (OSError, RuntimeError, ValueError) as error:
        raise ScopeNormalizationError("Path could not be resolved safely") from error


def path_is_within(path: str, root: str) -> bool:
    """Compare canonical paths without vulnerable string-prefix matching."""

    try:
        return os.path.commonpath((path, root)) == root
    except ValueError:
        return False


def _normalize_label(value: str, label: str) -> str:
    try:
        normalized = validate_safe_display_text(
            value,
            field=label,
            max_length=512,
        ).casefold()
    except ValueError as error:
        raise ScopeNormalizationError(f"{label} must be bounded printable text") from error
    if any(character.isspace() for character in normalized):
        raise ScopeNormalizationError(f"{label} cannot contain whitespace")
    return normalized


def _require_string_tuple(value: object, label: str) -> tuple[str, ...]:
    if (
        type(value) is not tuple
        or len(value) > 64
        or any(not isinstance(item, str) or len(item) > 4_096 for item in value)
    ):
        raise ScopeNormalizationError(f"{label} must be a bounded tuple of strings")
    return value


def _normalize_action(value: object) -> str:
    try:
        return validate_safe_display_text(
            value,
            field="Action",
            max_length=128,
        ).casefold()
    except ValueError as error:
        raise ScopeNormalizationError("Action must be bounded printable text") from error


def _normalize_host(value: str) -> str:
    normalized = _normalize_label(value, "Host").rstrip(".")
    try:
        parsed = urlsplit(f"//{normalized}")
        port = parsed.port
    except ValueError as error:
        raise ScopeNormalizationError("Host must be a bare exact hostname") from error
    if (
        parsed.hostname != normalized
        or port is not None
        or any(item in normalized for item in ("/", "@", "*"))
    ):
        raise ScopeNormalizationError("Host must be a bare exact hostname")
    try:
        encoded = normalized.encode("idna").decode("ascii")
    except UnicodeError as error:
        raise ScopeNormalizationError("Host is not valid IDNA") from error
    if len(encoded) > 253:
        raise ScopeNormalizationError("Host is too long")
    return encoded


def normalize_scope(scope: PermissionScope, permission: Permission) -> PermissionScope:
    """Canonicalize and structurally validate a permission scope."""

    if not isinstance(scope, PermissionScope):
        raise ScopeNormalizationError("Scope must be a PermissionScope")
    paths_input = _require_string_tuple(scope.paths, "Paths")
    applications_input = _require_string_tuple(scope.applications, "Applications")
    hosts_input = _require_string_tuple(scope.hosts, "Hosts")
    commands_input = _require_string_tuple(scope.command_families, "Command families")
    try:
        tool_id = validate_safe_display_text(
            scope.tool_id,
            field="Tool identifier",
            max_length=128,
        )
    except ValueError as error:
        raise ScopeNormalizationError("Tool and task scope are mandatory") from error
    if any(character.isspace() for character in tool_id) or not isinstance(scope.task_id, UUID):
        raise ScopeNormalizationError("Tool and task scope are mandatory")
    if scope.duration_seconds is not None and (
        isinstance(scope.duration_seconds, bool)
        or not isinstance(scope.duration_seconds, int)
        or scope.duration_seconds <= 0
    ):
        raise ScopeNormalizationError("Duration must be a positive integer")
    paths = tuple(dict.fromkeys(normalize_path(path) for path in paths_input))
    applications = tuple(
        dict.fromkeys(_normalize_label(value, "Application") for value in applications_input)
    )
    hosts = tuple(dict.fromkeys(_normalize_host(value) for value in hosts_input))
    command_families = tuple(
        dict.fromkeys(_normalize_label(value, "Command family") for value in commands_input)
    )
    normalized = replace(
        scope,
        paths=paths,
        applications=applications,
        hosts=hosts,
        command_families=command_families,
        tool_id=tool_id,
    )
    if permission in _PATH_PERMISSIONS and not normalized.paths:
        raise ScopeNormalizationError("Filesystem permissions require a path")
    if permission in _APPLICATION_PERMISSIONS and not normalized.applications:
        raise ScopeNormalizationError("Application permissions require an application")
    if permission in _HOST_PERMISSIONS and not normalized.hosts:
        raise ScopeNormalizationError("Network permission requires a host")
    if permission in _COMMAND_PERMISSIONS and not normalized.command_families:
        raise ScopeNormalizationError("Command permission requires a command family")
    return normalized


def normalize_constraint(scope: ScopeConstraint) -> ScopeConstraint:
    """Canonicalize trusted policy bounds using the same comparisons as requests."""

    if not isinstance(scope, ScopeConstraint):
        raise ValueError("Policy scope must be a ScopeConstraint")
    try:
        paths = _require_string_tuple(scope.paths, "Policy paths")
        applications = _require_string_tuple(scope.applications, "Policy applications")
        hosts = _require_string_tuple(scope.hosts, "Policy hosts")
        command_families = _require_string_tuple(
            scope.command_families,
            "Policy command families",
        )
    except ScopeNormalizationError as error:
        raise ValueError("Policy scope containers are malformed") from error
    if (
        type(scope.tools) is not frozenset
        or len(scope.tools) > 64
        or type(scope.tasks) is not frozenset
        or len(scope.tasks) > 64
        or any(not isinstance(item, UUID) for item in scope.tasks)
    ):
        raise ValueError("Policy tool/task constraints are malformed")
    try:
        normalized_tools = frozenset(
            validate_safe_display_text(
                item,
                field="Policy tool identifier",
                max_length=128,
            )
            for item in scope.tools
        )
    except ValueError as error:
        raise ValueError("Policy tool/task constraints are malformed") from error
    if any(any(character.isspace() for character in item) for item in normalized_tools):
        raise ValueError("Policy tool/task constraints are malformed")
    if scope.max_duration_seconds is not None and (
        isinstance(scope.max_duration_seconds, bool)
        or not isinstance(scope.max_duration_seconds, int)
        or scope.max_duration_seconds <= 0
    ):
        raise ValueError("Policy duration must be a positive integer")
    return replace(
        scope,
        paths=tuple(dict.fromkeys(normalize_path(path) for path in paths)),
        applications=tuple(
            dict.fromkeys(_normalize_label(value, "Application") for value in applications)
        ),
        hosts=tuple(dict.fromkeys(_normalize_host(value) for value in hosts)),
        command_families=tuple(
            dict.fromkeys(_normalize_label(value, "Command family") for value in command_families)
        ),
        tools=normalized_tools,
    )


class PolicyEngine:
    """Evaluate only explicit rules; malformed and absent configuration deny."""

    def __init__(self, rules: tuple[PolicyRule, ...] = ()) -> None:
        normalized: list[PolicyRule] = []
        policy_ids: set[str] = set()
        for rule in rules:
            if not rule.policy_id or rule.policy_id in policy_ids:
                raise ValueError("Policy IDs must be non-empty and unique")
            if not rule.actions:
                raise ValueError("Policy rules must enumerate exact trusted actions")
            policy_ids.add(rule.policy_id)
            normalized.append(
                replace(
                    rule,
                    scope=normalize_constraint(rule.scope),
                    actions=frozenset(_normalize_action(action) for action in rule.actions),
                )
            )
        self._rules = tuple(normalized)

    def evaluate(
        self,
        request: PermissionRequest | object,
        *,
        action: object,
        safety_class: SafetyClass = SafetyClass.ORDINARY,
    ) -> PolicyEvaluation:
        """Return a complete decision for typed or hostile request data."""

        if not isinstance(request, PermissionRequest):
            return self._deny(DecisionReason.MALFORMED_PERMISSION)
        permission = self._permission(request.permission)
        if permission is None:
            reason = (
                DecisionReason.UNKNOWN_PERMISSION
                if isinstance(request.permission, str)
                and request.permission
                and request.permission == request.permission.strip()
                else DecisionReason.MALFORMED_PERMISSION
            )
            return self._deny(reason)
        if not isinstance(safety_class, SafetyClass):
            return self._deny(DecisionReason.MALFORMED_ACTION)
        try:
            scope = normalize_scope(request.scope, permission)
        except (ScopeNormalizationError, TypeError, AttributeError):
            return self._deny(DecisionReason.MALFORMED_SCOPE)

        try:
            normalized_action = _normalize_action(action)
        except ScopeNormalizationError:
            return self._deny(
                DecisionReason.MALFORMED_ACTION,
                normalized_scope=scope,
            )

        candidates = tuple(rule for rule in self._rules if rule.permission is permission)
        enabled = tuple(rule for rule in candidates if rule.enabled)
        if not enabled:
            reason = DecisionReason.POLICY_DISABLED if candidates else DecisionReason.MISSING_POLICY
            return self._deny(reason, normalized_scope=scope)
        action_matching = tuple(rule for rule in enabled if normalized_action in rule.actions)
        if not action_matching:
            return self._deny(DecisionReason.UNKNOWN_ACTION, normalized_scope=scope)
        matching = tuple(rule for rule in action_matching if self._scope_matches(scope, rule.scope))
        if not matching:
            return self._deny(DecisionReason.SCOPE_OUTSIDE_POLICY, normalized_scope=scope)

        selected = min(matching, key=lambda rule: self._precedence(rule.decision))
        if selected.decision is Decision.DENY:
            return PolicyEvaluation(
                Decision.DENY,
                DecisionReason.POLICY_DENY,
                selected.policy_id,
                scope,
                permission,
            )
        if safety_class is SafetyClass.PRIVILEGE_ESCALATION:
            return PolicyEvaluation(
                Decision.DENY,
                DecisionReason.HARD_SAFETY_DENY,
                selected.policy_id,
                scope,
                permission,
            )
        if safety_class in {
            SafetyClass.BULK_DELETION,
            SafetyClass.DESTRUCTIVE_SYSTEM_COMMAND,
            SafetyClass.SOFTWARE_INSTALLATION,
            SafetyClass.SELF_MODIFICATION,
        }:
            return PolicyEvaluation(
                Decision.REQUIRE_APPROVAL,
                DecisionReason.HARD_SAFETY_APPROVAL_REQUIRED,
                selected.policy_id,
                scope,
                permission,
            )
        reason = (
            DecisionReason.POLICY_ALLOW
            if selected.decision is Decision.ALLOW
            else DecisionReason.POLICY_APPROVAL_REQUIRED
        )
        return PolicyEvaluation(selected.decision, reason, selected.policy_id, scope, permission)

    @staticmethod
    def _permission(value: Permission | str) -> Permission | None:
        if isinstance(value, Permission):
            return value
        if not isinstance(value, str) or not value or value != value.strip():
            return None
        try:
            return Permission(value)
        except ValueError:
            return None

    @staticmethod
    def _scope_matches(request: PermissionScope, policy: ScopeConstraint) -> bool:
        if policy.tools and request.tool_id not in policy.tools:
            return False
        if policy.tasks and request.task_id not in policy.tasks:
            return False
        if request.paths and (
            not policy.paths
            or any(
                not any(path_is_within(path, root) for root in policy.paths)
                for path in request.paths
            )
        ):
            return False
        if request.applications and (
            not policy.applications or not set(request.applications).issubset(policy.applications)
        ):
            return False
        if request.hosts and (not policy.hosts or not set(request.hosts).issubset(policy.hosts)):
            return False
        if request.command_families and (
            not policy.command_families
            or not set(request.command_families).issubset(policy.command_families)
        ):
            return False
        return not (
            request.duration_seconds is not None
            and (
                policy.max_duration_seconds is None
                or request.duration_seconds > policy.max_duration_seconds
            )
        )

    @staticmethod
    def _precedence(decision: Decision) -> int:
        return {
            Decision.DENY: 0,
            Decision.REQUIRE_APPROVAL: 1,
            Decision.ALLOW: 2,
        }[decision]

    @staticmethod
    def _deny(
        reason: DecisionReason,
        *,
        normalized_scope: PermissionScope | None = None,
    ) -> PolicyEvaluation:
        return PolicyEvaluation(Decision.DENY, reason, None, normalized_scope)
