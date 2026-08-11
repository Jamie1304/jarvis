"""Fail-closed scoped policy evaluation and filesystem normalization."""

import os
from dataclasses import replace
from pathlib import Path
from urllib.parse import urlsplit

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


class ScopeNormalizationError(ValueError):
    """Raised internally when untrusted scope is ambiguous or malformed."""


def normalize_path(path: str) -> str:
    """Return one absolute canonical path while rejecting ambiguous traversal."""

    if not isinstance(path, str) or not path or "\x00" in path:
        raise ScopeNormalizationError("Path must be a non-empty string without NULs")
    candidate = Path(path)
    if not candidate.is_absolute():
        raise ScopeNormalizationError("Relative paths are not permitted")
    if ".." in candidate.parts:
        raise ScopeNormalizationError("Parent traversal is not permitted")
    try:
        return os.path.normcase(str(candidate.resolve(strict=False)))
    except (OSError, RuntimeError) as error:
        raise ScopeNormalizationError("Path could not be resolved safely") from error


def path_is_within(path: str, root: str) -> bool:
    """Compare canonical paths without vulnerable string-prefix matching."""

    try:
        return os.path.commonpath((path, root)) == root
    except ValueError:
        return False


def _normalize_label(value: str, label: str) -> str:
    if not isinstance(value, str) or not value.strip() or "\x00" in value:
        raise ScopeNormalizationError(f"{label} must be a non-empty string")
    normalized = value.strip().casefold()
    if any(character.isspace() for character in normalized):
        raise ScopeNormalizationError(f"{label} cannot contain whitespace")
    return normalized


def _normalize_action(value: object) -> str:
    if (
        not isinstance(value, str)
        or not value.strip()
        or value != value.strip()
        or len(value) > 128
        or "\x00" in value
        or "\n" in value
        or "\r" in value
    ):
        raise ScopeNormalizationError("Action must be a bounded single-line label")
    return value.casefold()


def _normalize_host(value: str) -> str:
    normalized = _normalize_label(value, "Host").rstrip(".")
    parsed = urlsplit(f"//{normalized}")
    if (
        parsed.hostname != normalized
        or parsed.port is not None
        or any(item in normalized for item in ("/", "@", "*"))
    ):
        raise ScopeNormalizationError("Host must be a bare exact hostname")
    try:
        return normalized.encode("idna").decode("ascii")
    except UnicodeError as error:
        raise ScopeNormalizationError("Host is not valid IDNA") from error


def normalize_scope(scope: PermissionScope, permission: Permission) -> PermissionScope:
    """Canonicalize and structurally validate a permission scope."""

    if not isinstance(scope, PermissionScope):
        raise ScopeNormalizationError("Scope must be a PermissionScope")
    if scope.tool_id is None or not scope.tool_id.strip() or scope.task_id is None:
        raise ScopeNormalizationError("Tool and task scope are mandatory")
    if scope.duration_seconds is not None and (
        isinstance(scope.duration_seconds, bool) or scope.duration_seconds <= 0
    ):
        raise ScopeNormalizationError("Duration must be a positive integer")
    paths = tuple(dict.fromkeys(normalize_path(path) for path in scope.paths))
    applications = tuple(
        dict.fromkeys(_normalize_label(value, "Application") for value in scope.applications)
    )
    hosts = tuple(dict.fromkeys(_normalize_host(value) for value in scope.hosts))
    command_families = tuple(
        dict.fromkeys(_normalize_label(value, "Command family") for value in scope.command_families)
    )
    normalized = replace(
        scope,
        paths=paths,
        applications=applications,
        hosts=hosts,
        command_families=command_families,
        tool_id=scope.tool_id.strip(),
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

    if scope.max_duration_seconds is not None and (
        isinstance(scope.max_duration_seconds, bool) or scope.max_duration_seconds <= 0
    ):
        raise ValueError("Policy duration must be a positive integer")
    return replace(
        scope,
        paths=tuple(dict.fromkeys(normalize_path(path) for path in scope.paths)),
        applications=tuple(
            dict.fromkeys(_normalize_label(value, "Application") for value in scope.applications)
        ),
        hosts=tuple(dict.fromkeys(_normalize_host(value) for value in scope.hosts)),
        command_families=tuple(
            dict.fromkeys(
                _normalize_label(value, "Command family") for value in scope.command_families
            )
        ),
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
