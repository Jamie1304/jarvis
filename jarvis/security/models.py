"""Immutable records for the v1 trusted-core security boundary."""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from enum import StrEnum
from pathlib import Path
from uuid import UUID


class IntegrityClass(StrEnum):
    """Security ownership class for a repository or runtime artifact."""

    TRUSTED_CORE = "trusted_core"
    PRODUCTION_CORE = "production_core"
    INTEGRATION = "integration"
    GENERATED = "generated"
    USER_CONFIG = "user_config"
    DATA = "data"


class MutationAuthority(StrEnum):
    """Trusted workflow identities; model text can never create authority."""

    ROUTINE_IMPROVEMENT = "routine_improvement"
    CONTROLLED_UPDATE = "controlled_update"
    OWNER_SECURITY_RELEASE = "owner_security_release"


class MutationStage(StrEnum):
    """Distinguish an isolated proposal from a write to the production copy."""

    ISOLATED_PROPOSAL = "isolated_proposal"
    PRODUCTION_APPLY = "production_apply"


class MutationAuthorizationSource(StrEnum):
    """Authenticated release channels; none is available to a model or worker."""

    TRUSTED_UPDATE_SERVICE = "trusted_update_service"
    OWNER_LOCAL_RELEASE = "owner_local_release"


class MutationReason(StrEnum):
    """Stable, machine-readable mutation-policy outcomes."""

    ISOLATED_CANDIDATE_ALLOWED = "isolated_candidate_allowed"
    ROUTINE_MUTATION_ALLOWED = "routine_mutation_allowed"
    CONTROLLED_UPDATE_ALLOWED = "controlled_update_allowed"
    OWNER_RELEASE_ALLOWED = "owner_release_allowed"
    UNKNOWN_PATH = "unknown_path"
    MALFORMED_PATH = "malformed_path"
    MALFORMED_CONTEXT = "malformed_context"
    TRUSTED_CORE_OWNER_RELEASE_REQUIRED = "trusted_core_owner_release_required"
    PRODUCTION_GATES_REQUIRED = "production_gates_required"
    OWNER_AUTHORIZATION_REQUIRED = "owner_authorization_required"
    ROUTINE_SCOPE_DENIED = "routine_scope_denied"
    CLASS_NOT_MUTABLE = "class_not_mutable"


class SecurityViolationCode(StrEnum):
    """Startup violations that force a fail-closed safe-mode result."""

    POLICY_VERSION_UNSUPPORTED = "policy_version_unsupported"
    POLICY_CLASSIFICATION_INVALID = "policy_classification_invalid"
    UNSUPPORTED_COMPUTER_CONTROL = "unsupported_computer_control"
    UNSUPPORTED_CAMERA = "unsupported_camera"
    UNSUPPORTED_APPLICATION_MANAGEMENT = "unsupported_application_management"
    UNSUPPORTED_PACKAGE_INSTALLATION = "unsupported_package_installation"
    UNSUPPORTED_VOICE = "unsupported_voice"
    UNSUPPORTED_STT = "unsupported_stt"
    UNSUPPORTED_TTS = "unsupported_tts"
    UNSUPPORTED_MULTI_AGENT = "unsupported_multi_agent"
    UNSUPPORTED_IMPROVEMENT = "unsupported_improvement"
    REMOTE_APPROVAL_FORBIDDEN = "remote_approval_forbidden"
    AUTONOMOUS_SCHEDULING_FORBIDDEN = "autonomous_scheduling_forbidden"
    MODEL_PROVIDER_UNSUPPORTED = "model_provider_unsupported"
    MODEL_ENDPOINT_NOT_LOCAL = "model_endpoint_not_local"
    APP_DATA_PATH_UNSAFE = "app_data_path_unsafe"
    CONFIGURATION_INVALID = "configuration_invalid"


@dataclass(frozen=True, slots=True)
class ClassifiedPath:
    relative_path: str
    integrity_class: IntegrityClass
    reason_code: str


@dataclass(frozen=True, slots=True)
class MutationContext:
    authority: MutationAuthority
    stage: MutationStage
    full_gates_passed: bool = False
    task_id: UUID | None = None
    base_revision: str | None = None
    candidate_revision: str | None = None
    diff_digest: str | None = None
    gate_report_digest: str | None = None
    authorization: MutationAuthorization | None = field(default=None, repr=False)


@dataclass(frozen=True, slots=True)
class MutationAuthorization:
    """Exact, expiring release authority minted outside model-facing code."""

    authorization_id: UUID
    authority: MutationAuthority
    path: str
    task_id: UUID
    base_revision: str
    candidate_revision: str
    diff_digest: str
    gate_report_digest: str
    identity_id: str
    source: MutationAuthorizationSource
    issued_at: datetime
    expires_at: datetime
    authentication_tag: str = field(repr=False)


@dataclass(frozen=True, slots=True)
class MutationDecision:
    allowed: bool
    reason: MutationReason
    classified_path: ClassifiedPath | None


@dataclass(frozen=True, slots=True)
class SecurityViolation:
    code: SecurityViolationCode
    detail: str


@dataclass(frozen=True, slots=True)
class StartupSecurityReport:
    policy_version: int
    violations: tuple[SecurityViolation, ...]
    resolved_app_data_dir: Path | None = None
    resolved_project_root: Path | None = None

    @property
    def valid(self) -> bool:
        return not self.violations
