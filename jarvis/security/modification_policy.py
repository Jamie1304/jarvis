"""Trusted classification of self-modification patches.

The classification in this module is application-owned policy.  Callers never
provide a desired level: it is derived from every path in the proposed patch,
and the highest applicable level wins.
"""

from __future__ import annotations

from collections.abc import Iterable
from dataclasses import dataclass
from enum import IntEnum
from pathlib import PurePosixPath


class ModificationTrustError(ValueError):
    """A patch path cannot be classified safely."""


class ModificationTrustLevel(IntEnum):
    """Increasing trust required to change a JARVIS-owned surface."""

    LEVEL_1 = 1
    GENERATED_INTEGRATION = 1
    LEVEL_2 = 2
    USER_SPACE_JARVIS = 2
    LEVEL_3 = 3
    CORE_AGENT_RUNTIME = 3
    LEVEL_4 = 4
    PERMISSION_BROKER_SECURITY = 4
    LEVEL_5 = 5
    UPDATER_RECOVERY_ROOT_OF_TRUST = 5


@dataclass(frozen=True, slots=True)
class ModificationTrustClassification:
    """The trusted, aggregate classification of one complete patch."""

    level: ModificationTrustLevel
    paths: tuple[str, ...]
    matched_rules: tuple[str, ...]
    required_gates: tuple[str, ...]
    agent_editable: bool
    approval_mode: str
    policy_version: int = 1

    def __post_init__(self) -> None:
        if not isinstance(self.level, ModificationTrustLevel):
            raise ValueError("Modification trust level must be known")
        if not self.paths or any(not isinstance(path, str) or not path for path in self.paths):
            raise ValueError("Modification trust paths are required")
        if not self.matched_rules or not self.required_gates:
            raise ValueError("Modification trust evidence and gates are required")
        if type(self.agent_editable) is not bool:
            raise ValueError("Agent editability must be a boolean")
        if not self.approval_mode or "\n" in self.approval_mode or "\r" in self.approval_mode:
            raise ValueError("Approval mode must be bounded metadata")
        if self.policy_version != 1:
            raise ValueError("Unsupported modification trust policy version")

    @property
    def highest_level(self) -> ModificationTrustLevel:
        """Name the aggregate level explicitly for audit and UI callers."""

        return self.level


class ModificationTrustClassifier:
    """Classify patch paths using immutable, host-owned rules.

    Filename tokens intentionally participate in the classification.  This
    means renaming a protected module does not turn it into an ordinary
    user-space change.  A caller cannot supply a lower declared level.
    """

    POLICY_VERSION = 1
    MAX_PATHS = 256

    _LEVEL_5_EXACT = frozenset(
        {
            "docs/security-constitution.md",
            "docs/security-principles.md",
            "docs/self-modification-policy.md",
            "jarvis/improvement/analysis.py",
            "jarvis/improvement/modification_policy.py",
            "jarvis/improvement/trust.py",
            "jarvis/security/integrity.py",
            "jarvis/security/modification_policy.py",
            "jarvis/security/startup.py",
        }
    )
    _LEVEL_5_PREFIXES = (
        "jarvis/recovery/",
        "jarvis/updater/",
        "jarvis/update/",
        "recovery/",
        "updater/",
        "update/",
    )
    _LEVEL_4_PREFIXES = (
        "jarvis/permissions/",
        "jarvis/security/",
        "jarvis/credentials/",
        "jarvis/credential/",
    )
    _LEVEL_3_PREFIXES = (
        "jarvis/agent_runtime/",
        "jarvis/application/",
        "jarvis/applications/",
        "jarvis/autonomy/",
        "jarvis/camera/",
        "jarvis/computer/",
        "jarvis/events/",
        "jarvis/improvement/",
        "jarvis/planning/",
        "jarvis/tools/",
        "jarvis/voice/",
        "jarvis/vision/",
    )
    _LEVEL_3_EXACT = frozenset(
        {
            "jarvis/agent_runtime.py",
            "jarvis/bootstrap.py",
            "jarvis/runtime.py",
            "jarvis/task_controller.py",
        }
    )
    _LEVEL_1_PREFIXES = (
        "generated/",
        "integrations/",
        "packages/",
        "plugins/",
        "jarvis/generated/",
        "jarvis/integrations/",
        "jarvis/plugins/",
    )
    _LEVEL_5_TOKENS = frozenset(
        {
            "classifier",
            "constitution",
            "integrity",
            "root_of_trust",
            "root-of-trust",
            "recovery",
            "update",
            "updater",
            "update_service",
            "update-service",
        }
    )
    _LEVEL_4_TOKENS = frozenset(
        {
            "approval",
            "authenticator",
            "broker",
            "credential",
            "credentials",
            "permission",
            "permissionbroker",
            "policy",
            "security",
            "vault",
        }
    )
    _LEVEL_3_TOKENS = frozenset(
        {
            "agent_runtime",
            "bootstrap",
            "orchestrator",
            "planning",
            "runtime",
            "task_controller",
            "tool_registry",
        }
    )
    _GATES = {
        ModificationTrustLevel.LEVEL_1: (
            "static_security",
            "sandbox_tests",
            "package_certification",
        ),
        ModificationTrustLevel.LEVEL_2: (
            "static_security",
            "sandbox_tests",
            "package_certification",
            "quality",
            "integration_tests",
            "protected_regression",
            "trusted_approval",
        ),
        ModificationTrustLevel.LEVEL_3: (
            "static_security",
            "sandbox_tests",
            "package_certification",
            "quality",
            "integration_tests",
            "protected_regression",
            "trusted_approval",
            "startup_health",
            "security_review",
        ),
        ModificationTrustLevel.LEVEL_4: (
            "static_security",
            "sandbox_tests",
            "package_certification",
            "quality",
            "integration_tests",
            "protected_regression",
            "trusted_approval",
            "startup_health",
            "security_review",
            "trusted_core_security",
            "permission_policy_review",
            "independent_security_review",
            "recovery_point",
            "change_control_record",
        ),
        ModificationTrustLevel.LEVEL_5: (
            "static_security",
            "sandbox_tests",
            "package_certification",
            "quality",
            "integration_tests",
            "protected_regression",
            "trusted_approval",
            "startup_health",
            "security_review",
            "trusted_core_security",
            "recovery_update_gate",
            "independent_security_review",
            "dual_control_approval",
            "recovery_point",
            "change_control_record",
            "root_of_trust_review",
        ),
    }

    def classify(self, paths: Iterable[str]) -> ModificationTrustClassification:
        """Classify all paths in one patch; the highest level wins."""

        if isinstance(paths, str | bytes):
            raise ModificationTrustError("Modification paths must be an iterable of paths")
        try:
            iterator = iter(paths)
        except TypeError as error:
            raise ModificationTrustError(
                "Modification paths must be an iterable of paths"
            ) from error
        normalized: list[str] = []
        for value in iterator:
            if len(normalized) >= self.MAX_PATHS:
                raise ModificationTrustError("Modification patch contains too many paths")
            path = _normalize_path(value)
            if path not in normalized:
                normalized.append(path)
        if not normalized:
            raise ModificationTrustError("Modification patch must contain a path")

        classified = tuple(self._classify_path(path) for path in normalized)
        level = max((item[0] for item in classified), default=ModificationTrustLevel.LEVEL_2)
        rules = tuple(
            f"{path}:{rule}"
            for path, (_path_level, rule) in zip(normalized, classified, strict=True)
        )
        return ModificationTrustClassification(
            level=level,
            paths=tuple(normalized),
            matched_rules=rules,
            required_gates=self._GATES[level],
            agent_editable=level <= ModificationTrustLevel.CORE_AGENT_RUNTIME,
            approval_mode=(
                "trusted_release_only"
                if level >= ModificationTrustLevel.PERMISSION_BROKER_SECURITY
                else "trusted_approval"
            ),
            policy_version=self.POLICY_VERSION,
        )

    def _classify_path(self, path: str) -> tuple[ModificationTrustLevel, str]:
        folded = path.casefold()
        stem = PurePosixPath(folded).stem
        tokens = set(PurePosixPath(folded).parts) | set(stem.replace("-", "_").split("_"))
        if folded in self._LEVEL_5_EXACT:
            return ModificationTrustLevel.LEVEL_5, "root_of_trust_exact_path"
        if _matches_prefix(folded, self._LEVEL_5_PREFIXES) or tokens & self._LEVEL_5_TOKENS:
            return ModificationTrustLevel.LEVEL_5, "root_of_trust_or_recovery_surface"
        if _matches_prefix(folded, self._LEVEL_4_PREFIXES) or tokens & self._LEVEL_4_TOKENS:
            return ModificationTrustLevel.LEVEL_4, "permission_or_security_service"
        if folded in self._LEVEL_3_EXACT or _matches_prefix(folded, self._LEVEL_3_PREFIXES):
            return ModificationTrustLevel.LEVEL_3, "core_runtime_surface"
        if tokens & self._LEVEL_3_TOKENS:
            return ModificationTrustLevel.LEVEL_3, "renamed_core_runtime_surface"
        if _matches_prefix(folded, self._LEVEL_1_PREFIXES):
            return ModificationTrustLevel.LEVEL_1, "generated_or_integration_surface"
        return ModificationTrustLevel.LEVEL_2, "user_space_jarvis_surface"


def _normalize_path(value: str) -> str:
    if (
        type(value) is not str
        or not value
        or value != value.strip()
        or len(value) > 1_024
        or any(character in value for character in ("\x00", "\n", "\r", "\\", ":"))
    ):
        raise ModificationTrustError("Modification path is malformed")
    normalized = PurePosixPath(value)
    if (
        normalized.is_absolute()
        or normalized.as_posix() != value
        or any(part in {"", ".", ".."} for part in normalized.parts)
    ):
        raise ModificationTrustError("Modification path must be relative and unambiguous")
    return normalized.as_posix().casefold()


def _matches_prefix(path: str, prefixes: tuple[str, ...]) -> bool:
    return any(path == prefix.rstrip("/") or path.startswith(prefix) for prefix in prefixes)
