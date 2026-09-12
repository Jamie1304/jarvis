"""Trusted records used by the controlled application-manager boundary."""

from dataclasses import dataclass
from datetime import datetime
from enum import StrEnum
from uuid import UUID

from jarvis.permissions.models import Permission, validate_safe_display_text


class ApplicationStatus(StrEnum):
    INSTALLED = "installed"
    BROKEN = "broken"


class ApplicationMatchStatus(StrEnum):
    FOUND = "found"
    AMBIGUOUS = "ambiguous"
    MISSING = "missing"


class InstallationPlanKind(StrEnum):
    INSTALL = "install"
    UPDATE = "update"


@dataclass(frozen=True, slots=True)
class ApplicationRecord:
    """Normalized installed-application evidence; paths are never model inputs."""

    application_id: str
    name: str
    version: str | None
    publisher: str | None
    executable_path: str | None
    installation_source: str
    status: ApplicationStatus


@dataclass(frozen=True, slots=True)
class ApplicationSearchResult:
    status: ApplicationMatchStatus
    query: str
    candidates: tuple[ApplicationRecord, ...]


@dataclass(frozen=True, slots=True)
class InstallationVerification:
    """Expected post-install identity, not package-manager display text."""

    application_name: str
    publisher: str | None
    version: str

    def validate_for_trusted_display(self) -> None:
        """Reject package metadata that could spoof a trusted UI surface."""

        validate_safe_display_text(
            self.application_name,
            field="Verification application name",
            max_length=256,
        )
        if self.publisher is not None:
            validate_safe_display_text(
                self.publisher,
                field="Verification publisher",
                max_length=256,
            )
        validate_safe_display_text(
            self.version,
            field="Verification version",
            max_length=64,
        )

    def __post_init__(self) -> None:
        self.validate_for_trusted_display()


@dataclass(frozen=True, slots=True)
class InstallationCandidate:
    """An exact provider-issued package candidate, safe to show for approval."""

    package_id: str
    source: str
    name: str
    publisher: str | None
    version: str
    requested_permissions: tuple[Permission, ...]
    reason_for_selection: str
    confidence: float
    verification: InstallationVerification

    def validate_for_trusted_display(self) -> None:
        """Validate every provider-controlled field before it reaches a plan or approval."""

        for field, value, max_length in (
            ("Package identifier", self.package_id, 128),
            ("Package source", self.source, 128),
            ("Package name", self.name, 256),
            ("Package version", self.version, 64),
            ("Selection reason", self.reason_for_selection, 512),
        ):
            validate_safe_display_text(value, field=field, max_length=max_length)
        if self.publisher is not None:
            validate_safe_display_text(
                self.publisher,
                field="Package publisher",
                max_length=256,
            )
        if type(self.verification) is not InstallationVerification:
            raise ValueError("Installation verification metadata is malformed")
        self.verification.validate_for_trusted_display()

    def __post_init__(self) -> None:
        self.validate_for_trusted_display()


@dataclass(frozen=True, slots=True)
class InstallationPlan:
    plan_id: UUID
    kind: InstallationPlanKind
    candidate: InstallationCandidate
    current_version: str | None
    created_at: datetime
    expires_at: datetime


@dataclass(frozen=True, slots=True)
class InstallationOutcome:
    kind: InstallationPlanKind
    record: ApplicationRecord
    launch_verified: bool
    already_present: bool = False


class ApplicationManagerError(RuntimeError):
    """Expected safe failure from inventory, plan, or lifecycle operations."""


class ApplicationNotFoundError(ApplicationManagerError):
    """No trusted inventory record matched an exact stable identifier."""


class ApplicationAmbiguousError(ApplicationManagerError):
    """A semantic request has more than one credible installed/package match."""


class PackageNotFoundError(ApplicationManagerError):
    """No provider candidate was available for the requested semantic name."""


class InstallationPlanError(ApplicationManagerError):
    """A plan is unknown, expired, consumed, or unsuitable for its requested operation."""


class PackageOperationError(ApplicationManagerError):
    """A provider could not safely complete a package-manager operation."""


class VerificationError(ApplicationManagerError):
    """Post-install inventory or launch verification did not match the approved plan."""
