"""Trusted records used by the controlled application-manager boundary."""

from dataclasses import dataclass
from datetime import datetime
from enum import StrEnum
from uuid import UUID

from jarvis.permissions.models import Permission


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
