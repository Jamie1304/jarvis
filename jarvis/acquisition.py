"""Trusted, provider-neutral resource acquisition.

This module is deliberately a coordinator and a transport seam.  It does not
execute downloaded bytes, install software, or mint permission.  The existing
``PermissionBroker`` remains the authority for actions which are not covered by
an explicitly bounded acquisition policy.
"""

from __future__ import annotations

import asyncio
import hashlib
import json
import os
import re
import sqlite3
from collections.abc import Awaitable, Callable
from dataclasses import dataclass, field
from datetime import UTC, datetime
from enum import StrEnum
from pathlib import Path, PureWindowsPath
from typing import Protocol
from urllib.parse import urlsplit
from uuid import UUID, uuid4

import httpx

from jarvis.permissions.broker import PermissionBroker
from jarvis.permissions.models import (
    ActionDescriptor,
    AuthorizationReceipt,
    Permission,
    PermissionRequest,
    PermissionScope,
    Risk,
    SafeArgument,
)
from jarvis.resources import (
    ReservationReleaseReason,
    ResourceBudget,
    ResourceGovernor,
    ResourcePriority,
)


class AcquisitionError(RuntimeError):
    """A resource acquisition could not safely complete."""


class AcquisitionValidationError(AcquisitionError, ValueError):
    """An acquisition contract is malformed."""


class AcquisitionDenied(AcquisitionError):
    """Policy or trusted authority denied the requested phase."""


class AcquisitionApprovalRequired(AcquisitionDenied):
    """The existing trusted authority requires a user approval."""

    def __init__(self, approvals: object) -> None:
        super().__init__("Acquisition approval is required")
        self.approvals = approvals


class AcquisitionPlacementApprovalRequired(AcquisitionApprovalRequired):
    """Final placement is paused before its filesystem effect begins."""


class AcquisitionDeferred(AcquisitionError):
    """The operation must wait for a known resource or security condition."""


class AcquisitionStaleRequest(AcquisitionDenied):
    """The request or its receipt is no longer current."""


class AcquisitionStaleTarget(AcquisitionDeferred):
    """A previously approved target failed trusted pre-effect revalidation."""


class AcquisitionUnknownOutcome(AcquisitionError):
    """An effect lacks trusted terminal evidence and must be reconciled."""


class AcquisitionTransportError(AcquisitionError):
    """A bounded transport failed before materialization."""


class ResourceType(StrEnum):
    DATA = "data"
    FILE = "file"
    MODEL = "model"
    PACKAGE = "package"
    CAPABILITY = "capability"
    EXECUTABLE = "executable"
    DRIVER = "driver"


class AcquisitionPhase(StrEnum):
    DOWNLOAD = "download"
    INSTALL = "install"
    EXECUTE = "execute"
    GRANT_PRIVILEGES = "grant_privileges"


class AcquisitionPolicyMode(StrEnum):
    OFF = "off"
    ASK_ALWAYS = "ask_always"
    LOW_RISK_ONLY = "low_risk_only"
    WITHIN_LIMITS = "within_limits"
    JARVIS_MANAGED = "jarvis_managed"


class AcquisitionRisk(StrEnum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"
    UNKNOWN = "unknown"


class PrivacyImpact(StrEnum):
    NONE_KNOWN = "none_known"
    LOCAL_ONLY = "local_only"
    NETWORK_METADATA = "network_metadata"
    PRIVATE_DATA = "private_data"
    UNKNOWN = "unknown"


class UnknownExecutablePolicy(StrEnum):
    DENY = "deny"
    REQUIRE_TRUSTED_SCAN = "require_trusted_scan"
    REQUIRE_DISPOSABLE_QUALIFICATION = "require_disposable_qualification"


class SecurityDisposition(StrEnum):
    NOT_REQUIRED_BY_POLICY = "not_required_by_policy"
    REQUIRED_PENDING = "required_pending"
    PASSED_BY_TRUSTED_PROVIDER = "passed_by_trusted_provider"
    FAILED_THREAT = "failed_threat"
    PROVIDER_UNAVAILABLE = "provider_unavailable"
    UNKNOWN = "unknown"


class PolicyDecisionStatus(StrEnum):
    ALLOW = "allow"
    REQUIRE_APPROVAL = "require_approval"
    DENY = "deny"
    DEFER_UNKNOWN = "defer_unknown"


class ArtifactState(StrEnum):
    ACTIVE = "active"
    VERIFICATION_REQUIRED = "verification_required"
    REGISTERED = "registered"
    FAILED = "failed"
    SAFE_TO_REMOVE = "safe_to_remove"
    VERIFIED_STAGED = "verified_staged"
    PLACEMENT_PENDING = "placement_pending"


class AcquisitionResultStatus(StrEnum):
    REGISTERED = "registered"
    DUPLICATE = "duplicate"
    FAILED = "failed"
    VERIFICATION_REQUIRED = "verification_required"
    UNKNOWN_OUTCOME = "unknown_outcome"
    PLACEMENT_PENDING = "placement_pending"


class AcquisitionEffectOutcome(StrEnum):
    PRE_EFFECT_FAILURE = "pre_effect_failure"
    EFFECT_CONFIRMED = "effect_confirmed"
    UNKNOWN_OUTCOME = "unknown_outcome"


def _text(value: object, field_name: str, limit: int, *, allow_empty: bool = False) -> str:
    if (
        type(value) is not str
        or (not allow_empty and not value.strip())
        or len(value) > limit
        or any(ord(character) < 32 or ord(character) == 127 for character in value)
    ):
        raise AcquisitionValidationError(f"{field_name} is malformed")
    return value


def _optional_text(value: object, field_name: str, limit: int) -> str | None:
    if value is None:
        return None
    return _text(value, field_name, limit)


def _optional_bool(value: object, field_name: str) -> None:
    if value is not None and type(value) is not bool:
        raise AcquisitionValidationError(f"{field_name} is malformed")


def _optional_nonnegative_int(value: object, field_name: str) -> None:
    if value is not None and (type(value) is not int or value < 0):
        raise AcquisitionValidationError(f"{field_name} is malformed")


def _hash(value: str | None, field_name: str) -> None:
    if value is not None and (
        type(value) is not str or re.fullmatch(r"[0-9a-fA-F]{64}", value) is None
    ):
        raise AcquisitionValidationError(f"{field_name} must be a SHA-256 digest")


def _timestamp(value: object, field_name: str) -> datetime:
    if not isinstance(value, datetime) or value.tzinfo is None:
        raise AcquisitionValidationError(f"{field_name} must be timezone-aware")
    return value.astimezone(UTC)


def _bounded_strings(values: object, field_name: str, limit: int = 32) -> tuple[str, ...]:
    if type(values) is not tuple or len(values) > limit:
        raise AcquisitionValidationError(f"{field_name} is malformed")
    return tuple(_text(value, field_name, 512) for value in values)


@dataclass(frozen=True, slots=True)
class ProvenanceMetadata:
    """Facts supplied by a source; missing facts remain explicitly unknown."""

    source_identity: str | None = None
    publisher: str | None = None
    provider_reported_digest: str | None = None
    signature_verified: bool | None = None
    trusted_source: bool | None = None
    trusted_publisher: bool | None = None

    def __post_init__(self) -> None:
        for value, field_name in (
            (self.source_identity, "Source identity"),
            (self.publisher, "Publisher"),
        ):
            _optional_text(value, field_name, 512)
        _optional_text(self.provider_reported_digest, "Provider digest", 512)
        for boolean_value, field_name in (
            (self.signature_verified, "Signature verification"),
            (self.trusted_source, "Trusted source"),
            (self.trusted_publisher, "Trusted publisher"),
        ):
            _optional_bool(boolean_value, field_name)


@dataclass(frozen=True, slots=True)
class AcquisitionRequest:
    """One truthful, phase-independent request for a resource."""

    resource_id: str
    resource_type: ResourceType
    purpose: str
    required_for: str | None = None
    expected_benefit: str | None = None
    requested_version: str | None = None
    source: str | None = None
    publisher: str | None = None
    provenance: ProvenanceMetadata = field(default_factory=ProvenanceMetadata)
    download_size_bytes: int | None = None
    installed_size_bytes: int | None = None
    target_location: str | None = None
    target_volume_identity: str | None = None
    target_required_headroom_bytes: int = 0
    license_metadata: str | None = None
    purchase_cost: float | None = None
    network_required: bool | None = None
    administrator_required: bool | None = None
    restart_required: bool | None = None
    security_risk: AcquisitionRisk = AcquisitionRisk.UNKNOWN
    privacy_impact: PrivacyImpact = PrivacyImpact.UNKNOWN
    alternatives: tuple[str, ...] = ()
    verification_plan: str | None = None
    rollback_plan: str | None = None
    expected_sha256: str | None = None
    jarvis_owned: bool = False
    created_at: datetime = field(default_factory=lambda: datetime.now(UTC))
    expires_at: datetime | None = None

    def __post_init__(self) -> None:
        _text(self.resource_id, "Resource identity", 256)
        if not isinstance(self.resource_type, ResourceType):
            raise AcquisitionValidationError("Resource type is malformed")
        _text(self.purpose, "Purpose", 2_000)
        for value, name, limit in (
            (self.required_for, "Required-for relationship", 512),
            (self.expected_benefit, "Expected benefit", 2_000),
            (self.requested_version, "Requested version", 256),
            (self.source, "Source", 2_048),
            (self.publisher, "Publisher", 512),
            (self.target_location, "Target location", 1_024),
            (self.target_volume_identity, "Target volume identity", 512),
            (self.license_metadata, "License metadata", 512),
            (self.verification_plan, "Verification plan", 2_000),
            (self.rollback_plan, "Rollback plan", 2_000),
        ):
            _optional_text(value, name, limit)
        if not isinstance(self.provenance, ProvenanceMetadata):
            raise AcquisitionValidationError("Provenance is malformed")
        _optional_nonnegative_int(self.download_size_bytes, "Download size")
        _optional_nonnegative_int(self.installed_size_bytes, "Installed size")
        if (
            type(self.target_required_headroom_bytes) is not int
            or self.target_required_headroom_bytes < 0
        ):
            raise AcquisitionValidationError("Target headroom is malformed")
        if self.purchase_cost is not None and (
            type(self.purchase_cost) not in {int, float} or self.purchase_cost < 0
        ):
            raise AcquisitionValidationError("Purchase cost is malformed")
        for boolean_value, name in (
            (self.network_required, "Network requirement"),
            (self.administrator_required, "Administrator requirement"),
            (self.restart_required, "Restart requirement"),
            (self.jarvis_owned, "JARVIS ownership"),
        ):
            if name == "JARVIS ownership":
                if type(boolean_value) is not bool:
                    raise AcquisitionValidationError(f"{name} is malformed")
            else:
                _optional_bool(boolean_value, name)
        if not isinstance(self.security_risk, AcquisitionRisk) or not isinstance(
            self.privacy_impact, PrivacyImpact
        ):
            raise AcquisitionValidationError("Acquisition risk or privacy impact is malformed")
        _bounded_strings(self.alternatives, "Alternatives")
        _hash(self.expected_sha256, "Expected resource hash")
        created = _timestamp(self.created_at, "Request creation time")
        if created != self.created_at:
            object.__setattr__(self, "created_at", created)
        if self.expires_at is not None:
            expiry = _timestamp(self.expires_at, "Request expiry")
            if expiry <= created:
                raise AcquisitionValidationError("Request expiry must be after creation")
            if expiry != self.expires_at:
                object.__setattr__(self, "expires_at", expiry)
        if self.source is None and self.resource_type not in {ResourceType.MODEL}:
            raise AcquisitionValidationError("A non-model acquisition requires a source")

    @property
    def fingerprint(self) -> str:
        payload = self.as_dict()
        payload.pop("created_at", None)
        payload.pop("expires_at", None)
        return hashlib.sha256(
            json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode()
        ).hexdigest()

    def as_dict(self) -> dict[str, object]:
        return {
            "resource_id": self.resource_id,
            "resource_type": self.resource_type.value,
            "purpose": self.purpose,
            "required_for": self.required_for,
            "expected_benefit": self.expected_benefit,
            "requested_version": self.requested_version,
            "source": self.source,
            "publisher": self.publisher,
            "provenance": {
                "source_identity": self.provenance.source_identity,
                "publisher": self.provenance.publisher,
                "provider_reported_digest": self.provenance.provider_reported_digest,
                "signature_verified": self.provenance.signature_verified,
                "trusted_source": self.provenance.trusted_source,
                "trusted_publisher": self.provenance.trusted_publisher,
            },
            "download_size_bytes": self.download_size_bytes,
            "installed_size_bytes": self.installed_size_bytes,
            "target_location": self.target_location,
            "target_volume_identity": self.target_volume_identity,
            "target_required_headroom_bytes": self.target_required_headroom_bytes,
            "license_metadata": self.license_metadata,
            "purchase_cost": self.purchase_cost,
            "network_required": self.network_required,
            "administrator_required": self.administrator_required,
            "restart_required": self.restart_required,
            "security_risk": self.security_risk.value,
            "privacy_impact": self.privacy_impact.value,
            "alternatives": list(self.alternatives),
            "verification_plan": self.verification_plan,
            "rollback_plan": self.rollback_plan,
            "expected_sha256": self.expected_sha256,
            "jarvis_owned": self.jarvis_owned,
            "created_at": self.created_at.isoformat(),
            "expires_at": self.expires_at.isoformat() if self.expires_at else None,
        }


@dataclass(frozen=True, slots=True)
class AcquisitionPolicyDecision:
    status: PolicyDecisionStatus
    phase: AcquisitionPhase
    reason: str
    requires_permission: bool


@dataclass(frozen=True, slots=True)
class AcquisitionPolicy:
    mode: AcquisitionPolicyMode = AcquisitionPolicyMode.ASK_ALWAYS
    maximum_automatic_download_bytes: int | None = None
    trusted_sources_only: bool = True
    unknown_executable_policy: UnknownExecutablePolicy = UnknownExecutablePolicy.DENY
    administrator_installation_allowed: bool = False
    model_acquisition_limit_bytes: int | None = None
    vm_only_dependency_policy: bool = True
    paid_resource_requires_approval: bool = True
    driver_requires_approval: bool = True
    require_known_disk_capacity: bool = True
    allow_automatic_install: bool = False
    allow_automatic_execution: bool = False

    def __post_init__(self) -> None:
        if not isinstance(self.mode, AcquisitionPolicyMode) or not isinstance(
            self.unknown_executable_policy, UnknownExecutablePolicy
        ):
            raise AcquisitionValidationError("Acquisition policy enum is malformed")
        for value, name in (
            (self.maximum_automatic_download_bytes, "Maximum download size"),
            (self.model_acquisition_limit_bytes, "Model acquisition limit"),
        ):
            _optional_nonnegative_int(value, name)
        for value, name in (
            (self.trusted_sources_only, "Trusted-source policy"),
            (self.administrator_installation_allowed, "Administrator policy"),
            (self.vm_only_dependency_policy, "VM-only dependency policy"),
            (self.paid_resource_requires_approval, "Paid-resource policy"),
            (self.driver_requires_approval, "Driver policy"),
            (self.require_known_disk_capacity, "Disk certainty policy"),
            (self.allow_automatic_install, "Automatic installation policy"),
            (self.allow_automatic_execution, "Automatic execution policy"),
        ):
            if type(value) is not bool:
                raise AcquisitionValidationError(f"{name} is malformed")

    def decide(
        self,
        request: AcquisitionRequest,
        phase: AcquisitionPhase,
        *,
        disk_free_bytes: int | None = None,
    ) -> AcquisitionPolicyDecision:
        if not isinstance(request, AcquisitionRequest) or not isinstance(phase, AcquisitionPhase):
            raise AcquisitionValidationError("Policy request is malformed")
        if self.mode is AcquisitionPolicyMode.OFF:
            return AcquisitionPolicyDecision(
                PolicyDecisionStatus.DENY, phase, "acquisition is off", True
            )
        if phase is AcquisitionPhase.GRANT_PRIVILEGES:
            return AcquisitionPolicyDecision(
                PolicyDecisionStatus.REQUIRE_APPROVAL,
                phase,
                "privilege grants always require explicit authority",
                True,
            )
        if phase is AcquisitionPhase.EXECUTE and not self.allow_automatic_execution:
            return AcquisitionPolicyDecision(
                PolicyDecisionStatus.REQUIRE_APPROVAL,
                phase,
                "execution is never implied by acquisition",
                True,
            )
        if phase is AcquisitionPhase.INSTALL and not self.allow_automatic_install:
            return AcquisitionPolicyDecision(
                PolicyDecisionStatus.REQUIRE_APPROVAL,
                phase,
                "installation is separate from download",
                True,
            )
        if request.resource_type is ResourceType.DRIVER and self.driver_requires_approval:
            return AcquisitionPolicyDecision(
                PolicyDecisionStatus.REQUIRE_APPROVAL,
                phase,
                "drivers require explicit authority",
                True,
            )
        if request.administrator_required is True:
            if not self.administrator_installation_allowed:
                return AcquisitionPolicyDecision(
                    PolicyDecisionStatus.DENY,
                    phase,
                    "administrator installation is disabled by policy",
                    True,
                )
            return AcquisitionPolicyDecision(
                PolicyDecisionStatus.REQUIRE_APPROVAL,
                phase,
                "administrator authority is required explicitly",
                True,
            )
        if request.purchase_cost is not None and request.purchase_cost > 0:
            if self.paid_resource_requires_approval:
                return AcquisitionPolicyDecision(
                    PolicyDecisionStatus.REQUIRE_APPROVAL,
                    phase,
                    "paid acquisition requires explicit approval",
                    True,
                )
        if self.trusted_sources_only:
            if request.provenance.trusted_source is False:
                return AcquisitionPolicyDecision(
                    PolicyDecisionStatus.DENY,
                    phase,
                    "source is not trusted by policy",
                    True,
                )
            if request.provenance.trusted_source is not True:
                return AcquisitionPolicyDecision(
                    PolicyDecisionStatus.DEFER_UNKNOWN,
                    phase,
                    "source trust is unknown",
                    True,
                )
        size = request.download_size_bytes
        if self.maximum_automatic_download_bytes is not None:
            if size is None:
                return AcquisitionPolicyDecision(
                    PolicyDecisionStatus.DEFER_UNKNOWN,
                    phase,
                    "download size is unknown under a bounded policy",
                    True,
                )
            if size > self.maximum_automatic_download_bytes:
                return AcquisitionPolicyDecision(
                    PolicyDecisionStatus.DENY,
                    phase,
                    "download exceeds the automatic size limit",
                    True,
                )
        if (
            request.resource_type is ResourceType.MODEL
            and self.model_acquisition_limit_bytes is not None
        ):
            if size is None:
                return AcquisitionPolicyDecision(
                    PolicyDecisionStatus.DEFER_UNKNOWN,
                    phase,
                    "model size is unknown under the model acquisition limit",
                    True,
                )
            if size > self.model_acquisition_limit_bytes:
                return AcquisitionPolicyDecision(
                    PolicyDecisionStatus.DENY,
                    phase,
                    "model exceeds the model acquisition limit",
                    True,
                )
        if size is not None and disk_free_bytes is not None and size > disk_free_bytes:
            return AcquisitionPolicyDecision(
                PolicyDecisionStatus.DENY,
                phase,
                "known free disk capacity is insufficient",
                True,
            )
        if size is not None and disk_free_bytes is None and self.require_known_disk_capacity:
            return AcquisitionPolicyDecision(
                PolicyDecisionStatus.DEFER_UNKNOWN,
                phase,
                "free disk capacity is unknown",
                True,
            )
        if request.resource_type in {ResourceType.EXECUTABLE, ResourceType.DRIVER}:
            if self.unknown_executable_policy is UnknownExecutablePolicy.DENY:
                return AcquisitionPolicyDecision(
                    PolicyDecisionStatus.DENY,
                    phase,
                    "executable acquisition is denied without a trusted disposition",
                    True,
                )
            return AcquisitionPolicyDecision(
                PolicyDecisionStatus.REQUIRE_APPROVAL,
                phase,
                "executable acquisition requires trusted scan or qualification",
                True,
            )
        if self.mode is AcquisitionPolicyMode.ASK_ALWAYS:
            return AcquisitionPolicyDecision(
                PolicyDecisionStatus.REQUIRE_APPROVAL,
                phase,
                "user policy asks for every acquisition",
                True,
            )
        if self.mode is AcquisitionPolicyMode.LOW_RISK_ONLY:
            if request.security_risk is not AcquisitionRisk.LOW or request.administrator_required:
                return AcquisitionPolicyDecision(
                    PolicyDecisionStatus.REQUIRE_APPROVAL,
                    phase,
                    "resource is outside the low-risk automatic policy",
                    True,
                )
        if self.mode is AcquisitionPolicyMode.JARVIS_MANAGED and not request.jarvis_owned:
            return AcquisitionPolicyDecision(
                PolicyDecisionStatus.REQUIRE_APPROVAL,
                phase,
                "resource is not JARVIS-owned",
                True,
            )
        return AcquisitionPolicyDecision(
            PolicyDecisionStatus.ALLOW,
            phase,
            "bounded policy allows this acquisition phase",
            False,
        )


@dataclass(frozen=True, slots=True)
class AcquisitionPresentation:
    request_fingerprint: str
    what: str
    why: str
    resources: str
    source: str
    destination: str
    enables: str
    authority: str
    security: str
    privacy: str
    alternatives: tuple[str, ...]
    verification: str
    rollback: str


def _known(value: str | None, *, label: str = "UNKNOWN") -> str:
    return value if value is not None else label


def build_acquisition_presentation(
    request: AcquisitionRequest,
    decision: AcquisitionPolicyDecision | None = None,
) -> AcquisitionPresentation:
    """Build trusted explanatory text only from the typed request and policy."""

    if not isinstance(request, AcquisitionRequest):
        raise AcquisitionValidationError("Presentation request is malformed")
    authority = (
        f"{decision.status.value}: {decision.reason}"
        if decision is not None
        else "policy decision pending"
    )
    if request.administrator_required is True:
        authority += "; administrator authority required"
    return AcquisitionPresentation(
        request.fingerprint,
        f"{request.resource_type.value} {request.resource_id}"
        + (f" version {request.requested_version}" if request.requested_version else ""),
        _known(request.purpose),
        "download="
        + (
            f"{request.download_size_bytes} bytes"
            if request.download_size_bytes is not None
            else "UNKNOWN bytes"
        )
        + "; installed="
        + (
            f"{request.installed_size_bytes} bytes"
            if request.installed_size_bytes is not None
            else "UNKNOWN bytes"
        ),
        _known(request.source),
        _known(request.target_location),
        _known(request.expected_benefit),
        authority,
        request.security_risk.value,
        request.privacy_impact.value,
        request.alternatives,
        _known(request.verification_plan),
        _known(request.rollback_plan),
    )


@dataclass(frozen=True, slots=True)
class SecurityDispositionResult:
    disposition: SecurityDisposition
    detail: str
    provider: str | None = None

    def __post_init__(self) -> None:
        if not isinstance(self.disposition, SecurityDisposition):
            raise AcquisitionValidationError("Security disposition is malformed")
        _text(self.detail, "Security disposition detail", 2_000)
        _optional_text(self.provider, "Security provider", 256)


class SecurityDispositionProvider(Protocol):
    async def assess(
        self, request: AcquisitionRequest, materialized: Path
    ) -> SecurityDispositionResult: ...


class NoSecurityDispositionProvider:
    """A conservative provider: data needs no scan; executables remain pending."""

    async def assess(
        self, request: AcquisitionRequest, materialized: Path
    ) -> SecurityDispositionResult:
        del materialized
        if request.resource_type in {ResourceType.EXECUTABLE, ResourceType.DRIVER}:
            return SecurityDispositionResult(
                SecurityDisposition.REQUIRED_PENDING,
                "trusted security disposition is not configured",
            )
        return SecurityDispositionResult(
            SecurityDisposition.NOT_REQUIRED_BY_POLICY,
            "resource is non-executable under the acquisition policy",
        )


@dataclass(frozen=True, slots=True)
class DisposableQualificationResult:
    passed: bool
    detail: str
    environment_id: str | None = None

    def __post_init__(self) -> None:
        if type(self.passed) is not bool:
            raise AcquisitionValidationError("Qualification result is malformed")
        _text(self.detail, "Qualification detail", 2_000)
        _optional_text(self.environment_id, "Qualification environment", 256)


class DisposableQualifier(Protocol):
    async def qualify(
        self, request: AcquisitionRequest, materialized: Path
    ) -> DisposableQualificationResult: ...


@dataclass(frozen=True, slots=True)
class DownloadEvidence:
    source: str
    destination: Path
    bytes_written: int
    computed_sha256: str
    expected_sha256: str | None
    hash_verified: bool | None
    content_length: int | None
    reused_existing: bool = False

    def __post_init__(self) -> None:
        _text(self.source, "Download source", 2_048)
        if not isinstance(self.destination, Path) or type(self.bytes_written) is not int:
            raise AcquisitionValidationError("Download evidence is malformed")
        if self.bytes_written < 0 or re.fullmatch(r"[0-9a-f]{64}", self.computed_sha256) is None:
            raise AcquisitionValidationError("Download evidence integrity is malformed")
        _hash(self.expected_sha256, "Expected download hash")
        _optional_nonnegative_int(self.content_length, "Content length")
        if type(self.reused_existing) is not bool:
            raise AcquisitionValidationError("Download reuse evidence is malformed")


class BoundedDownloadTransport:
    """One bounded HTTP transport which only materializes bytes under its root."""

    def __init__(self, root: Path, *, timeout_seconds: float = 60.0) -> None:
        if not isinstance(root, Path):
            raise AcquisitionValidationError("Download root is malformed")
        if type(timeout_seconds) not in {int, float} or not 0 < timeout_seconds <= 600:
            raise AcquisitionValidationError("Download timeout is outside the safe bound")
        candidate = root.expanduser().absolute()
        if candidate.is_symlink() or candidate.is_junction():
            raise AcquisitionValidationError("Download root is not trusted")
        candidate.mkdir(parents=True, exist_ok=True)
        self._root = candidate.resolve()
        if self._root.is_symlink() or self._root.is_junction() or not self._root.is_dir():
            raise AcquisitionValidationError("Download root is not trusted")
        self._timeout_seconds = float(timeout_seconds)

    @property
    def root(self) -> Path:
        return self._root

    async def download(
        self,
        source: str,
        destination: str,
        *,
        maximum_bytes: int | None = None,
        expected_sha256: str | None = None,
    ) -> DownloadEvidence:
        _text(source, "Download source", 2_048)
        _hash(expected_sha256, "Expected download hash")
        _optional_nonnegative_int(maximum_bytes, "Maximum download size")
        parsed = urlsplit(source)
        if parsed.scheme.casefold() not in {"http", "https"} or not parsed.hostname:
            raise AcquisitionTransportError("only bounded HTTP(S) sources are supported")
        final = self._target(destination)
        final.parent.mkdir(parents=True, exist_ok=True)
        self._validate_directory_chain(final.parent)
        staging_root = self._root / ".staging"
        staging_root.mkdir(exist_ok=True)
        self._validate_directory_chain(staging_root)
        staging = staging_root / f"{uuid4().hex}.part"
        content_length: int | None = None
        try:
            async with httpx.AsyncClient(
                timeout=httpx.Timeout(self._timeout_seconds),
                trust_env=False,
                follow_redirects=False,
            ) as client:
                try:
                    async with client.stream("GET", source) as response:
                        response.raise_for_status()
                        raw_length = response.headers.get("content-length")
                        if raw_length is not None and raw_length.isdigit():
                            content_length = int(raw_length)
                            if maximum_bytes is not None and content_length > maximum_bytes:
                                raise AcquisitionTransportError(
                                    "content length exceeds the size limit"
                                )
                        digest = hashlib.sha256()
                        written = 0
                        with staging.open("xb") as handle:
                            async for block in response.aiter_bytes(64 * 1024):
                                if not block:
                                    continue
                                written += len(block)
                                if maximum_bytes is not None and written > maximum_bytes:
                                    raise AcquisitionTransportError(
                                        "download exceeds the size limit"
                                    )
                                digest.update(block)
                                handle.write(block)
                        computed = digest.hexdigest()
                except httpx.HTTPError as error:
                    raise AcquisitionTransportError("bounded HTTP download failed") from error
            if expected_sha256 is not None and computed.casefold() != expected_sha256.casefold():
                raise AcquisitionTransportError("download hash does not match the request")
            if final.exists():
                if final.is_symlink() or final.is_junction() or not final.is_file():
                    raise AcquisitionTransportError("download target is not a regular file")
                if (
                    expected_sha256 is not None
                    and await asyncio.to_thread(_sha256_file, final) == expected_sha256.casefold()
                ):
                    return DownloadEvidence(
                        source,
                        final,
                        final.stat().st_size,
                        expected_sha256.casefold(),
                        expected_sha256,
                        True,
                        content_length,
                        True,
                    )
            os.replace(staging, final)
            return DownloadEvidence(
                source,
                final,
                written,
                computed,
                expected_sha256,
                None if expected_sha256 is None else True,
                content_length,
            )
        except AcquisitionTransportError:
            raise
        except (OSError, ValueError) as error:
            raise AcquisitionTransportError("download could not be materialized safely") from error
        finally:
            if staging.exists():
                try:
                    staging.unlink()
                except OSError:
                    pass

    def _target(self, destination: str) -> Path:
        _text(destination, "Download destination", 1_024)
        windows = PureWindowsPath(destination)
        if (
            windows.is_absolute()
            or windows.drive
            or any(part in {"", ".", ".."} for part in windows.parts)
        ):
            raise AcquisitionTransportError("download destination escapes its root")
        candidate = (self._root / Path(*windows.parts)).resolve(strict=False)
        if not candidate.is_relative_to(self._root) or candidate == self._root:
            raise AcquisitionTransportError("download destination escapes its root")
        return candidate

    def _validate_directory_chain(self, directory: Path) -> None:
        current = self._root
        for part in directory.relative_to(self._root).parts:
            current /= part
            if current.is_symlink() or current.is_junction() or not current.is_dir():
                raise AcquisitionTransportError("download path contains an unsafe directory")


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


@dataclass(frozen=True, slots=True)
class AcquisitionArtifactRecord:
    request_fingerprint: str
    resource_id: str
    state: ArtifactState
    target_location: str | None
    computed_sha256: str | None
    size_bytes: int | None
    detail: str
    created_at: datetime
    updated_at: datetime

    def __post_init__(self) -> None:
        _text(self.request_fingerprint, "Acquisition fingerprint", 128)
        _text(self.resource_id, "Artifact resource identity", 256)
        if not isinstance(self.state, ArtifactState):
            raise AcquisitionValidationError("Artifact state is malformed")
        _optional_text(self.target_location, "Artifact target", 1_024)
        _hash(self.computed_sha256, "Computed artifact hash")
        _optional_nonnegative_int(self.size_bytes, "Artifact size")
        _text(self.detail, "Artifact detail", 2_000)
        created = _timestamp(self.created_at, "Artifact creation time")
        updated = _timestamp(self.updated_at, "Artifact update time")
        if updated < created:
            raise AcquisitionValidationError("Artifact update precedes creation")


class AcquisitionLedger(Protocol):
    def get(self, request_fingerprint: str) -> AcquisitionArtifactRecord | None: ...

    def put(self, record: AcquisitionArtifactRecord) -> AcquisitionArtifactRecord: ...

    def records(self) -> tuple[AcquisitionArtifactRecord, ...]: ...

    def close(self) -> None: ...


class InMemoryAcquisitionLedger:
    """Small deterministic ledger used by unit tests and callers without persistence."""

    def __init__(self) -> None:
        self._records: dict[str, AcquisitionArtifactRecord] = {}

    def get(self, request_fingerprint: str) -> AcquisitionArtifactRecord | None:
        return self._records.get(request_fingerprint)

    def put(self, record: AcquisitionArtifactRecord) -> AcquisitionArtifactRecord:
        if not isinstance(record, AcquisitionArtifactRecord):
            raise AcquisitionValidationError("Acquisition ledger record is malformed")
        self._records[record.request_fingerprint] = record
        return record

    def records(self) -> tuple[AcquisitionArtifactRecord, ...]:
        return tuple(self._records[key] for key in sorted(self._records))

    def close(self) -> None:
        return None


class SQLiteAcquisitionLedger:
    """Durable acquisition state; failed evidence is retained, not erased."""

    def __init__(self, path: Path) -> None:
        if not isinstance(path, Path):
            raise AcquisitionValidationError("Acquisition ledger path is malformed")
        path.parent.mkdir(parents=True, exist_ok=True)
        self._connection = sqlite3.connect(path, timeout=5.0, check_same_thread=False)
        self._connection.execute("PRAGMA busy_timeout=5000")
        self._connection.execute(
            """CREATE TABLE IF NOT EXISTS acquisition_artifacts (
                request_fingerprint TEXT PRIMARY KEY,
                resource_id TEXT NOT NULL,
                state TEXT NOT NULL,
                target_location TEXT,
                computed_sha256 TEXT,
                size_bytes INTEGER,
                detail TEXT NOT NULL,
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL
            )"""
        )
        self._connection.commit()

    def get(self, request_fingerprint: str) -> AcquisitionArtifactRecord | None:
        row = self._connection.execute(
            "SELECT * FROM acquisition_artifacts WHERE request_fingerprint=?",
            (request_fingerprint,),
        ).fetchone()
        return None if row is None else self._from_row(row)

    def put(self, record: AcquisitionArtifactRecord) -> AcquisitionArtifactRecord:
        if not isinstance(record, AcquisitionArtifactRecord):
            raise AcquisitionValidationError("Acquisition ledger record is malformed")
        self._connection.execute(
            """INSERT INTO acquisition_artifacts VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(request_fingerprint) DO UPDATE SET resource_id=excluded.resource_id,
            state=excluded.state, target_location=excluded.target_location,
            computed_sha256=excluded.computed_sha256, size_bytes=excluded.size_bytes,
            detail=excluded.detail, updated_at=excluded.updated_at""",
            (
                record.request_fingerprint,
                record.resource_id,
                record.state.value,
                record.target_location,
                record.computed_sha256,
                record.size_bytes,
                record.detail,
                record.created_at.isoformat(),
                record.updated_at.isoformat(),
            ),
        )
        self._connection.commit()
        return record

    def records(self) -> tuple[AcquisitionArtifactRecord, ...]:
        rows = self._connection.execute(
            "SELECT * FROM acquisition_artifacts ORDER BY request_fingerprint"
        ).fetchall()
        return tuple(self._from_row(row) for row in rows)

    def close(self) -> None:
        self._connection.close()

    @staticmethod
    def _from_row(row: tuple[object, ...]) -> AcquisitionArtifactRecord:
        return AcquisitionArtifactRecord(
            str(row[0]),
            str(row[1]),
            ArtifactState(str(row[2])),
            str(row[3]) if row[3] is not None else None,
            str(row[4]) if row[4] is not None else None,
            int(str(row[5])) if row[5] is not None else None,
            str(row[6]),
            datetime.fromisoformat(str(row[7])),
            datetime.fromisoformat(str(row[8])),
        )


@dataclass(frozen=True, slots=True)
class AcquisitionIntegrityEvidence:
    expected_sha256: str | None
    computed_sha256: str | None
    bytes_written: int | None
    provider_reported_digest: str | None = None
    signature_verified: bool | None = None
    trusted_publisher: bool | None = None

    def __post_init__(self) -> None:
        _hash(self.expected_sha256, "Expected integrity hash")
        _hash(self.computed_sha256, "Computed integrity hash")
        _optional_nonnegative_int(self.bytes_written, "Integrity byte count")
        _optional_text(self.provider_reported_digest, "Provider-reported digest", 512)
        _optional_bool(self.signature_verified, "Signature verification")
        _optional_bool(self.trusted_publisher, "Trusted publisher")

    @property
    def verified(self) -> bool | None:
        if self.expected_sha256 is None or self.computed_sha256 is None:
            return None
        return self.expected_sha256.casefold() == self.computed_sha256.casefold()


class AcquisitionPermissionAuthority(Protocol):
    async def authorize(
        self,
        request: AcquisitionRequest,
        phase: AcquisitionPhase,
        *,
        task_id: UUID,
        user_id: str | None,
    ) -> object: ...

    async def begin(self, receipt: object) -> None: ...

    async def finish(self, receipt: object, outcome: AcquisitionEffectOutcome) -> None: ...


class AcquisitionMaterializer(Protocol):
    """Trusted final-placement authority; transport never implements this."""

    async def materialize(
        self,
        request: AcquisitionRequest,
        staging_path: Path,
        *,
        task_id: UUID,
        user_id: str | None,
    ) -> Path: ...


class BrokerAcquisitionAuthorizer:
    """Adapt acquisition phases to the one existing PermissionBroker."""

    _PERMISSIONS = {
        AcquisitionPhase.DOWNLOAD: Permission.RESOURCE_DOWNLOAD,
        AcquisitionPhase.INSTALL: Permission.RESOURCE_INSTALL,
        AcquisitionPhase.EXECUTE: Permission.RESOURCE_EXECUTE,
        AcquisitionPhase.GRANT_PRIVILEGES: Permission.PRIVILEGE_GRANT,
    }

    def __init__(self, broker: PermissionBroker, *, target_root: Path | None = None) -> None:
        if not isinstance(broker, PermissionBroker):
            raise AcquisitionValidationError("Permission broker is malformed")
        if target_root is not None:
            if not isinstance(target_root, Path):
                raise AcquisitionValidationError("Acquisition target root is malformed")
            candidate_root = target_root.expanduser().absolute()
            if candidate_root.is_symlink() or candidate_root.is_junction():
                raise AcquisitionValidationError("Acquisition target root is not trusted")
            candidate_root.mkdir(parents=True, exist_ok=True)
            target_root = candidate_root.resolve()
            if target_root.is_symlink() or target_root.is_junction() or not target_root.is_dir():
                raise AcquisitionValidationError("Acquisition target root is not trusted")
        self._broker = broker
        self._target_root = target_root
        self._identities: dict[AcquisitionPhase, tuple[str, object]] = {}
        for phase, permission in self._PERMISSIONS.items():
            tool_id = f"acquisition.{phase.value}"
            identity = object()
            broker.register_tool(tool_id, identity, frozenset({permission}))
            self._identities[phase] = (tool_id, identity)

    async def authorize(
        self,
        request: AcquisitionRequest,
        phase: AcquisitionPhase,
        *,
        task_id: UUID,
        user_id: str | None,
    ) -> object:
        if not isinstance(request, AcquisitionRequest) or not isinstance(phase, AcquisitionPhase):
            raise AcquisitionValidationError("Broker acquisition authorization is malformed")
        tool_id, identity = self._identities[phase]
        permission = self._PERMISSIONS[phase]
        source_host = _source_host(request.source) if request.source else None
        scope = PermissionScope(
            paths=self._target_paths(request.target_location)
            if phase is not AcquisitionPhase.DOWNLOAD and request.target_location
            else (),
            hosts=(source_host,) if phase is AcquisitionPhase.DOWNLOAD and source_host else (),
            command_families=("resource",)
            if phase in {AcquisitionPhase.EXECUTE, AcquisitionPhase.GRANT_PRIVILEGES}
            else (),
            tool_id=tool_id,
            task_id=task_id,
        )
        descriptor = ActionDescriptor(
            f"acquisition.{phase.value}",
            (
                SafeArgument("resource", request.resource_id),
                SafeArgument("request", request.fingerprint[:16]),
            ),
            Risk.CRITICAL if request.administrator_required else Risk.HIGH,
            (PermissionRequest(permission, scope),),
        )
        result = await self._broker.authorize(
            tool_id=tool_id,
            tool_identity=identity,
            declared_permissions=frozenset({permission}),
            task_id=task_id,
            user_id=user_id,
            descriptor=descriptor,
            normalized_arguments={
                "phase": phase.value,
                "resource_id": request.resource_id,
                "request_fingerprint": request.fingerprint,
            },
        )
        if not result.authorized or result.receipt is None:
            if result.approval_requests:
                raise AcquisitionApprovalRequired(result.approval_requests)
            raise AcquisitionDenied(result.reason.value)
        return result.receipt

    def _target_paths(self, target_location: str | None) -> tuple[str, ...]:
        if target_location is None:
            return ()
        candidate = Path(target_location)
        if candidate.is_absolute():
            resolved = candidate.resolve(strict=False)
        elif self._target_root is not None:
            windows = PureWindowsPath(target_location)
            if (
                windows.is_absolute()
                or windows.drive
                or any(part in {"", ".", ".."} for part in windows.parts)
            ):
                raise AcquisitionDenied("acquisition target escapes its trusted root")
            resolved = (self._target_root / Path(*windows.parts)).resolve(strict=False)
        else:
            raise AcquisitionDenied("a trusted target root is required for this phase")
        if self._target_root is not None and not resolved.is_relative_to(self._target_root):
            raise AcquisitionDenied("acquisition target escapes its trusted root")
        return (str(resolved),)

    async def begin(self, receipt: object) -> None:
        if type(receipt) is not AuthorizationReceipt:
            raise AcquisitionDenied("malformed acquisition authorization receipt")
        reason = await self._broker.begin_execution(receipt)
        if reason is not None:
            raise AcquisitionDenied(reason.value)

    async def finish(self, receipt: object, outcome: AcquisitionEffectOutcome) -> None:
        if type(receipt) is not AuthorizationReceipt:
            raise AcquisitionDenied("malformed acquisition authorization receipt")
        await self._broker.record_execution_outcome(receipt, outcome.value)


@dataclass(frozen=True, slots=True)
class AcquisitionResult:
    status: AcquisitionResultStatus
    request: AcquisitionRequest
    artifact: AcquisitionArtifactRecord
    integrity: AcquisitionIntegrityEvidence | None = None
    security: SecurityDispositionResult | None = None
    policy: AcquisitionPolicyDecision | None = None
    materialized_path: Path | None = None
    consumer_result: object | None = None


Consumer = Callable[[Path], object | Awaitable[object]]
TargetRevalidator = Callable[[AcquisitionRequest], str | None]


class AcquisitionBroker:
    """One authoritative acquisition path for bounded non-provider resources."""

    def __init__(
        self,
        transport: BoundedDownloadTransport,
        policy: AcquisitionPolicy,
        ledger: AcquisitionLedger,
        *,
        permission_authority: AcquisitionPermissionAuthority | None = None,
        security: SecurityDispositionProvider | None = None,
        qualifier: DisposableQualifier | None = None,
        materializer: AcquisitionMaterializer | None = None,
        resource_governor: ResourceGovernor | None = None,
        target_revalidator: TargetRevalidator | None = None,
        clock: Callable[[], datetime] | None = None,
    ) -> None:
        if not isinstance(transport, BoundedDownloadTransport) or not isinstance(
            policy, AcquisitionPolicy
        ):
            raise AcquisitionValidationError("Acquisition broker dependencies are malformed")
        if not callable(getattr(ledger, "get", None)) or not callable(getattr(ledger, "put", None)):
            raise AcquisitionValidationError("Acquisition ledger is malformed")
        self._transport = transport
        self._policy = policy
        self._ledger = ledger
        self._permission_authority = permission_authority
        self._security = security or NoSecurityDispositionProvider()
        self._qualifier = qualifier
        self._materializer = materializer
        self._resource_governor = resource_governor
        self._target_revalidator = target_revalidator
        self._clock = clock or (lambda: datetime.now(UTC))

    @property
    def policy(self) -> AcquisitionPolicy:
        return self._policy

    @property
    def ledger(self) -> AcquisitionLedger:
        return self._ledger

    def materialized_path_for(self, request: AcquisitionRequest) -> Path | None:
        """Return the broker-owned path for an existing ledger record."""

        if not isinstance(request, AcquisitionRequest):
            raise AcquisitionValidationError("Acquisition request is malformed")
        record = self._ledger.get(request.fingerprint)
        return None if record is None else self._path_for(record.target_location)

    async def acquire(
        self,
        request: AcquisitionRequest,
        *,
        task_id: UUID | None = None,
        user_id: str | None = None,
        disk_free_bytes: int | None = None,
        consumer: Consumer | None = None,
        priority: ResourcePriority = ResourcePriority.USER_REQUESTED,
    ) -> AcquisitionResult:
        if not isinstance(request, AcquisitionRequest):
            raise AcquisitionValidationError("Acquisition request is malformed")
        now = _timestamp(self._clock(), "Acquisition clock")
        if request.expires_at is not None and request.expires_at <= now:
            raise AcquisitionStaleRequest("acquisition request is expired")
        existing = self._ledger.get(request.fingerprint)
        if existing is not None:
            if existing.state is ArtifactState.REGISTERED:
                path = self._path_for(existing.target_location)
                if path is not None and path.is_file():
                    return AcquisitionResult(
                        AcquisitionResultStatus.DUPLICATE,
                        request,
                        existing,
                        materialized_path=path,
                    )
            if (
                self._materializer is not None
                and existing.state
                in {ArtifactState.VERIFIED_STAGED, ArtifactState.PLACEMENT_PENDING}
                and request.target_location is not None
                and existing.computed_sha256 == request.expected_sha256
            ):
                staging = self._staging_path(request)
                if staging.is_file() and _sha256_file(staging) == request.expected_sha256:
                    self._ensure_live_target(request)
                    try:
                        final = await self._materializer.materialize(
                            request,
                            staging,
                            task_id=task_id or uuid4(),
                            user_id=user_id,
                        )
                    except AcquisitionPlacementApprovalRequired:
                        self._record(
                            request,
                            ArtifactState.PLACEMENT_PENDING,
                            "verified staging retained while final placement awaits approval",
                            now,
                            computed_sha256=existing.computed_sha256,
                            size_bytes=existing.size_bytes,
                        )
                        raise
                    except AcquisitionUnknownOutcome:
                        self._record(
                            request,
                            ArtifactState.PLACEMENT_PENDING,
                            "final placement requires reconciliation",
                            now,
                            computed_sha256=existing.computed_sha256,
                            size_bytes=existing.size_bytes,
                        )
                        raise
                    if staging.exists():
                        try:
                            staging.unlink()
                        except OSError as error:
                            raise AcquisitionUnknownOutcome(
                                "final placement succeeded but staging disposition is unresolved"
                            ) from error
                    updated = self._record(
                        request,
                        ArtifactState.REGISTERED,
                        "verified staged bytes materialized at final target",
                        now,
                        computed_sha256=existing.computed_sha256,
                        size_bytes=existing.size_bytes,
                    )
                    return AcquisitionResult(
                        AcquisitionResultStatus.REGISTERED,
                        request,
                        updated,
                        AcquisitionIntegrityEvidence(
                            request.expected_sha256,
                            existing.computed_sha256,
                            existing.size_bytes,
                        ),
                        materialized_path=final,
                    )
            if existing.state in {ArtifactState.ACTIVE, ArtifactState.VERIFICATION_REQUIRED}:
                raise AcquisitionUnknownOutcome(
                    "existing acquisition requires reconciliation before another effect"
                )
        decision = self._policy.decide(
            request,
            AcquisitionPhase.DOWNLOAD,
            disk_free_bytes=disk_free_bytes,
        )
        if decision.status is PolicyDecisionStatus.DENY:
            raise AcquisitionDenied(decision.reason)
        if decision.status is PolicyDecisionStatus.DEFER_UNKNOWN:
            raise AcquisitionDeferred(decision.reason)
        reservation_id = None
        if self._resource_governor is not None:
            budget = ResourceBudget(
                disk_bytes=request.download_size_bytes,
                network_bytes=request.download_size_bytes,
                duration_seconds=600,
            )
            admission = self._resource_governor.reserve(
                f"acquisition.{request.resource_id}", priority, budget
            )
            if not admission.allowed:
                raise AcquisitionDeferred(admission.reason)
            reservation_id = admission.reservation_id
        receipt: object | None = None
        try:
            if decision.requires_permission:
                if self._permission_authority is None or task_id is None:
                    raise AcquisitionApprovalRequired(("trusted acquisition permission",))
                receipt = await self._permission_authority.authorize(
                    request, AcquisitionPhase.DOWNLOAD, task_id=task_id, user_id=user_id
                )
                await self._permission_authority.begin(receipt)
            if self._target_revalidator is not None:
                try:
                    target_failure = self._target_revalidator(request)
                except Exception as error:
                    target_failure = f"target revalidation is unknown: {type(error).__name__}"
                if target_failure is not None:
                    self._record(request, ArtifactState.FAILED, target_failure, now)
                    if receipt is not None and self._permission_authority is not None:
                        await self._permission_authority.finish(
                            receipt, AcquisitionEffectOutcome.PRE_EFFECT_FAILURE
                        )
                    raise AcquisitionStaleTarget(target_failure)
            self._record(request, ArtifactState.ACTIVE, "bounded acquisition started", now)
            try:
                if request.target_location is None:
                    raise AcquisitionValidationError("a bounded file acquisition requires a target")
                destination = (
                    self._staging_destination(request)
                    if self._materializer is not None
                    else request.target_location
                )
                evidence = await self._transport.download(
                    request.source or "",
                    destination or "",
                    maximum_bytes=request.download_size_bytes,
                    expected_sha256=request.expected_sha256,
                )
            except AcquisitionTransportError as error:
                self._record(request, ArtifactState.FAILED, str(error), now)
                if receipt is not None and self._permission_authority is not None:
                    await self._permission_authority.finish(
                        receipt, AcquisitionEffectOutcome.PRE_EFFECT_FAILURE
                    )
                raise
            integrity = AcquisitionIntegrityEvidence(
                request.expected_sha256,
                evidence.computed_sha256,
                evidence.bytes_written,
                request.provenance.provider_reported_digest,
                request.provenance.signature_verified,
                request.provenance.trusted_publisher,
            )
            if request.expected_sha256 is None:
                record = self._record(
                    request,
                    ArtifactState.VERIFICATION_REQUIRED,
                    "materialized bytes have no expected cryptographic hash",
                    now,
                    computed_sha256=evidence.computed_sha256,
                    size_bytes=evidence.bytes_written,
                )
                if receipt is not None and self._permission_authority is not None:
                    await self._permission_authority.finish(
                        receipt, AcquisitionEffectOutcome.EFFECT_CONFIRMED
                    )
                return AcquisitionResult(
                    AcquisitionResultStatus.VERIFICATION_REQUIRED,
                    request,
                    record,
                    integrity,
                    policy=decision,
                    materialized_path=evidence.destination,
                )
            security = await self._security.assess(request, evidence.destination)
            if security.disposition not in {
                SecurityDisposition.NOT_REQUIRED_BY_POLICY,
                SecurityDisposition.PASSED_BY_TRUSTED_PROVIDER,
            }:
                record = self._record(
                    request,
                    ArtifactState.VERIFICATION_REQUIRED,
                    security.detail,
                    now,
                    computed_sha256=evidence.computed_sha256,
                    size_bytes=evidence.bytes_written,
                )
                if receipt is not None and self._permission_authority is not None:
                    await self._permission_authority.finish(
                        receipt, AcquisitionEffectOutcome.EFFECT_CONFIRMED
                    )
                return AcquisitionResult(
                    AcquisitionResultStatus.VERIFICATION_REQUIRED,
                    request,
                    record,
                    integrity,
                    security,
                    decision,
                    evidence.destination,
                )
            executable_resource = request.resource_type in {
                ResourceType.EXECUTABLE,
                ResourceType.DRIVER,
            }
            if (
                executable_resource
                and self._policy.unknown_executable_policy
                is UnknownExecutablePolicy.REQUIRE_DISPOSABLE_QUALIFICATION
                and self._qualifier is None
            ):
                record = self._record(
                    request,
                    ArtifactState.VERIFICATION_REQUIRED,
                    "disposable qualification is required but unavailable",
                    now,
                    computed_sha256=evidence.computed_sha256,
                    size_bytes=evidence.bytes_written,
                )
                if receipt is not None and self._permission_authority is not None:
                    await self._permission_authority.finish(
                        receipt, AcquisitionEffectOutcome.EFFECT_CONFIRMED
                    )
                return AcquisitionResult(
                    AcquisitionResultStatus.VERIFICATION_REQUIRED,
                    request,
                    record,
                    integrity,
                    security,
                    decision,
                    evidence.destination,
                )
            if self._qualifier is not None and executable_resource:
                qualification = await self._qualifier.qualify(request, evidence.destination)
                if not qualification.passed:
                    record = self._record(
                        request,
                        ArtifactState.VERIFICATION_REQUIRED,
                        qualification.detail,
                        now,
                        computed_sha256=evidence.computed_sha256,
                        size_bytes=evidence.bytes_written,
                    )
                    if receipt is not None and self._permission_authority is not None:
                        await self._permission_authority.finish(
                            receipt, AcquisitionEffectOutcome.EFFECT_CONFIRMED
                        )
                    return AcquisitionResult(
                        AcquisitionResultStatus.VERIFICATION_REQUIRED,
                        request,
                        record,
                        integrity,
                        security,
                        decision,
                        evidence.destination,
                    )
            if self._materializer is not None:
                staged = self._record(
                    request,
                    ArtifactState.VERIFIED_STAGED,
                    "bytes verified in bounded staging; final placement pending",
                    now,
                    computed_sha256=evidence.computed_sha256,
                    size_bytes=evidence.bytes_written,
                )
                try:
                    self._ensure_live_target(request)
                    final = await self._materializer.materialize(
                        request,
                        evidence.destination,
                        task_id=task_id or uuid4(),
                        user_id=user_id,
                    )
                except AcquisitionPlacementApprovalRequired:
                    self._record(
                        request,
                        ArtifactState.PLACEMENT_PENDING,
                        "verified staging retained while final placement awaits approval",
                        now,
                        computed_sha256=staged.computed_sha256,
                        size_bytes=staged.size_bytes,
                    )
                    raise
                except AcquisitionUnknownOutcome:
                    self._record(
                        request,
                        ArtifactState.PLACEMENT_PENDING,
                        "final placement requires reconciliation",
                        now,
                        computed_sha256=staged.computed_sha256,
                        size_bytes=staged.size_bytes,
                    )
                    raise
                if evidence.destination.exists():
                    try:
                        evidence.destination.unlink()
                    except OSError as error:
                        raise AcquisitionUnknownOutcome(
                            "final placement succeeded but staging disposition is unresolved"
                        ) from error
                updated = self._record(
                    request,
                    ArtifactState.REGISTERED,
                    "materialized, hash-verified, and registered at final target",
                    now,
                    computed_sha256=evidence.computed_sha256,
                    size_bytes=evidence.bytes_written,
                )
                return AcquisitionResult(
                    AcquisitionResultStatus.REGISTERED,
                    request,
                    updated,
                    integrity,
                    security,
                    decision,
                    final,
                )
            consumer_result = None
            if consumer is not None:
                consumer_result = consumer(evidence.destination)
                if isinstance(consumer_result, Awaitable):
                    consumer_result = await consumer_result
            record = self._record(
                request,
                ArtifactState.REGISTERED,
                "materialized, hash-verified, and registered",
                now,
                computed_sha256=evidence.computed_sha256,
                size_bytes=evidence.bytes_written,
            )
            if receipt is not None and self._permission_authority is not None:
                await self._permission_authority.finish(
                    receipt, AcquisitionEffectOutcome.EFFECT_CONFIRMED
                )
            return AcquisitionResult(
                AcquisitionResultStatus.REGISTERED,
                request,
                record,
                integrity,
                security,
                decision,
                evidence.destination,
                consumer_result,
            )
        except AcquisitionError:
            raise
        except (OSError, RuntimeError, ValueError) as error:
            self._record(request, ArtifactState.VERIFICATION_REQUIRED, type(error).__name__, now)
            if receipt is not None and self._permission_authority is not None:
                await self._permission_authority.finish(
                    receipt, AcquisitionEffectOutcome.UNKNOWN_OUTCOME
                )
            raise AcquisitionUnknownOutcome(
                "acquisition effect lacks trusted terminal evidence"
            ) from error
        finally:
            if reservation_id is not None and self._resource_governor is not None:
                self._resource_governor.release(reservation_id, ReservationReleaseReason.COMPLETE)

    async def reconcile(self, request: AcquisitionRequest) -> AcquisitionResult:
        if not isinstance(request, AcquisitionRequest):
            raise AcquisitionValidationError("Acquisition request is malformed")
        record = self._ledger.get(request.fingerprint)
        if record is None:
            raise AcquisitionUnknownOutcome("no acquisition evidence exists")
        path = self._path_for(record.target_location)
        if path is not None and path.is_file() and request.expected_sha256 is not None:
            digest = await asyncio.to_thread(_sha256_file, path)
            if digest.casefold() == request.expected_sha256.casefold():
                updated = self._record(
                    request,
                    ArtifactState.REGISTERED,
                    "reconciled from verified materialized bytes",
                    _timestamp(self._clock(), "Acquisition clock"),
                    computed_sha256=digest,
                    size_bytes=path.stat().st_size,
                )
                return AcquisitionResult(
                    AcquisitionResultStatus.REGISTERED,
                    request,
                    updated,
                    AcquisitionIntegrityEvidence(
                        request.expected_sha256, digest, path.stat().st_size
                    ),
                    materialized_path=path,
                )
        raise AcquisitionUnknownOutcome("acquisition remains unresolved; no blind retry is allowed")

    def _staging_destination(self, request: AcquisitionRequest) -> str:
        return f".staging/{request.fingerprint}.artifact"

    def _staging_path(self, request: AcquisitionRequest) -> Path:
        return self._transport.root / Path(
            *PureWindowsPath(self._staging_destination(request)).parts
        )

    def _ensure_live_target(self, request: AcquisitionRequest) -> None:
        if self._target_revalidator is None:
            return
        try:
            failure = self._target_revalidator(request)
        except Exception as error:
            failure = f"target revalidation is unknown: {type(error).__name__}"
        if failure is not None:
            raise AcquisitionStaleTarget(failure)

    async def aclose(self) -> None:
        close = getattr(self._ledger, "close", None)
        if callable(close):
            close()

    def _record(
        self,
        request: AcquisitionRequest,
        state: ArtifactState,
        detail: str,
        now: datetime,
        *,
        computed_sha256: str | None = None,
        size_bytes: int | None = None,
    ) -> AcquisitionArtifactRecord:
        existing = self._ledger.get(request.fingerprint)
        record = AcquisitionArtifactRecord(
            request.fingerprint,
            request.resource_id,
            state,
            request.target_location,
            computed_sha256,
            size_bytes,
            _text(detail, "Acquisition record detail", 2_000),
            existing.created_at if existing is not None else now,
            now,
        )
        return self._ledger.put(record)

    def _path_for(self, target_location: str | None) -> Path | None:
        if target_location is None:
            return None
        if self._materializer is not None:
            candidate = Path(target_location).expanduser().absolute().resolve(strict=False)
            return candidate
        try:
            target = self._transport._target(target_location)  # noqa: SLF001
        except AcquisitionTransportError:
            return None
        return target


def _source_host(source: str) -> str | None:
    try:
        parsed = urlsplit(source)
    except ValueError:
        return None
    host = parsed.hostname
    return host.casefold() if host else None


__all__ = [
    "AcquisitionArtifactRecord",
    "AcquisitionBroker",
    "AcquisitionEffectOutcome",
    "AcquisitionError",
    "AcquisitionDenied",
    "AcquisitionApprovalRequired",
    "AcquisitionMaterializer",
    "AcquisitionPlacementApprovalRequired",
    "AcquisitionDeferred",
    "AcquisitionIntegrityEvidence",
    "AcquisitionLedger",
    "AcquisitionPermissionAuthority",
    "AcquisitionPhase",
    "AcquisitionPolicy",
    "AcquisitionPolicyDecision",
    "AcquisitionPolicyMode",
    "AcquisitionPresentation",
    "AcquisitionRequest",
    "AcquisitionResult",
    "AcquisitionResultStatus",
    "AcquisitionRisk",
    "AcquisitionStaleRequest",
    "AcquisitionStaleTarget",
    "AcquisitionTransportError",
    "AcquisitionUnknownOutcome",
    "AcquisitionValidationError",
    "ArtifactState",
    "BoundedDownloadTransport",
    "BrokerAcquisitionAuthorizer",
    "DisposableQualificationResult",
    "DownloadEvidence",
    "InMemoryAcquisitionLedger",
    "NoSecurityDispositionProvider",
    "PrivacyImpact",
    "ProvenanceMetadata",
    "ResourceType",
    "SecurityDisposition",
    "SecurityDispositionResult",
    "SecurityDispositionProvider",
    "DisposableQualifier",
    "SQLiteAcquisitionLedger",
    "UnknownExecutablePolicy",
    "build_acquisition_presentation",
]
