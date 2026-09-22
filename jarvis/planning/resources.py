"""Trusted requirement resolution over the existing acquisition authority."""

from __future__ import annotations

import asyncio
import hashlib
import sys
from collections.abc import Callable, Iterable
from dataclasses import dataclass, field
from enum import StrEnum
from pathlib import Path
from typing import Protocol
from uuid import UUID

from jarvis.acquisition import (
    AcquisitionApprovalRequired,
    AcquisitionBroker,
    AcquisitionDeferred,
    AcquisitionDenied,
    AcquisitionRequest,
    AcquisitionResultStatus,
    AcquisitionRisk,
    AcquisitionTransportError,
    AcquisitionUnknownOutcome,
    ArtifactState,
    PrivacyImpact,
    ProvenanceMetadata,
    ResourceType,
)
from jarvis.planning.models import PlanningResourceRequirement


class ResourceResolutionState(StrEnum):
    SATISFIED = "satisfied"
    MISSING = "missing"
    TEMPORARILY_UNAVAILABLE = "temporarily_unavailable"
    INELIGIBLE = "ineligible"
    RESOURCE_PRESSURE = "resource_pressure"
    UNKNOWN = "unknown"
    DENIED = "denied"


@dataclass(frozen=True, slots=True)
class TrustedResourceDescriptor:
    """Trusted catalog facts used to construct one acquisition request."""

    resource_id: str
    resource_type: ResourceType
    source: str
    expected_sha256: str
    target_location: str
    download_size_bytes: int
    purpose: str
    required_for: str
    requested_version: str | None = None
    publisher: str | None = None
    provenance: ProvenanceMetadata = field(default_factory=ProvenanceMetadata)
    installed_size_bytes: int | None = None
    target_volume_identity: str | None = None
    target_required_headroom_bytes: int = 0
    license_metadata: str | None = None
    network_required: bool | None = None
    administrator_required: bool | None = None
    restart_required: bool | None = None
    security_risk: str = "low"
    privacy_impact: PrivacyImpact = PrivacyImpact.UNKNOWN
    alternatives: tuple[str, ...] = ()
    verification_plan: str = "trusted SHA-256 verification"
    rollback_plan: str | None = None
    jarvis_owned: bool = True
    supported_platforms: tuple[str, ...] = ()
    supported_environments: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        if (
            not self.resource_id.strip()
            or not self.source.strip()
            or not self.target_location.strip()
        ):
            raise ValueError("Trusted resource descriptor text is malformed")
        if not self.purpose.strip() or not self.required_for.strip():
            raise ValueError("Trusted resource descriptor purpose is malformed")
        if self.download_size_bytes < 0 or self.target_required_headroom_bytes < 0:
            raise ValueError("Trusted resource descriptor sizes are malformed")
        if len(self.expected_sha256) != 64:
            raise ValueError("Trusted resource descriptor hash is malformed")
        if not isinstance(self.resource_type, ResourceType):
            raise ValueError("Trusted resource descriptor type is malformed")
        if not isinstance(self.privacy_impact, PrivacyImpact):
            raise ValueError("Trusted resource descriptor privacy is malformed")

    def request_for(self, requirement: PlanningResourceRequirement) -> AcquisitionRequest:
        """Bind trusted catalog facts to the step's validated requirement."""

        return AcquisitionRequest(
            resource_id=self.resource_id,
            resource_type=self.resource_type,
            purpose=self.purpose,
            required_for=self.required_for,
            expected_benefit=requirement.purpose,
            requested_version=self.requested_version,
            source=self.source,
            publisher=self.publisher,
            provenance=self.provenance,
            download_size_bytes=self.download_size_bytes,
            installed_size_bytes=self.installed_size_bytes,
            target_location=self.target_location,
            target_volume_identity=self.target_volume_identity,
            target_required_headroom_bytes=self.target_required_headroom_bytes,
            license_metadata=self.license_metadata,
            network_required=self.network_required,
            administrator_required=self.administrator_required,
            restart_required=self.restart_required,
            security_risk=self._risk(),
            privacy_impact=self.privacy_impact,
            alternatives=self.alternatives,
            verification_plan=self.verification_plan,
            rollback_plan=self.rollback_plan,
            expected_sha256=self.expected_sha256,
            jarvis_owned=self.jarvis_owned,
        )

    def _risk(self) -> AcquisitionRisk:
        return AcquisitionRisk(self.security_risk)


@dataclass(frozen=True, slots=True)
class ResourceResolution:
    requirement: PlanningResourceRequirement
    state: ResourceResolutionState
    request: AcquisitionRequest | None = None
    resource_path: Path | None = None
    detail: str = ""
    evidence: tuple[str, ...] = ()


class ResourceRequirementResolver(Protocol):
    async def resolve(
        self,
        requirement: PlanningResourceRequirement,
        *,
        task_id: UUID,
        step_id: UUID,
    ) -> ResourceResolution: ...

    async def acquire(
        self,
        resolution: ResourceResolution,
        *,
        task_id: UUID,
        step_id: UUID,
        cancellation: asyncio.Event,
    ) -> ResourceResolution: ...

    async def reconcile(
        self,
        resolution: ResourceResolution,
        *,
        task_id: UUID,
    ) -> ResourceResolution: ...


class AcquisitionResourceBridge:
    """Resolve step requirements and delegate effects to AcquisitionBroker."""

    def __init__(
        self,
        acquisition: AcquisitionBroker,
        descriptors: Iterable[TrustedResourceDescriptor] = (),
        *,
        platform: str | None = None,
        environment: str = "local",
        request_sink: Callable[[AcquisitionRequest], None] | None = None,
        disk_free_bytes: Callable[[], int | None] | None = None,
    ) -> None:
        if not isinstance(acquisition, AcquisitionBroker):
            raise TypeError("Acquisition resource bridge requires AcquisitionBroker")
        self._acquisition = acquisition
        self._descriptors: dict[str, TrustedResourceDescriptor] = {}
        self._platform = platform or sys.platform
        self._environment = environment
        self._request_sink = request_sink
        self._disk_free_bytes = disk_free_bytes
        self._last_missing_requirement: object | None = None
        for descriptor in descriptors:
            self.register_descriptor(descriptor)

    @property
    def acquisition(self) -> AcquisitionBroker:
        return self._acquisition

    @property
    def last_missing_requirement(self) -> object | None:
        return self._last_missing_requirement

    def register_descriptor(self, descriptor: TrustedResourceDescriptor) -> None:
        if not isinstance(descriptor, TrustedResourceDescriptor):
            raise TypeError("Trusted resource descriptor is malformed")
        existing = self._descriptors.get(descriptor.resource_id)
        if existing is not None and existing != descriptor:
            raise ValueError("Trusted resource descriptor identity is already bound")
        self._descriptors[descriptor.resource_id] = descriptor

    def bind_request_sink(self, request_sink: Callable[[AcquisitionRequest], None]) -> None:
        if not callable(request_sink):
            raise TypeError("Resource request sink is not callable")
        self._request_sink = request_sink

    async def resolve(
        self,
        requirement: PlanningResourceRequirement,
        *,
        task_id: UUID,
        step_id: UUID,
    ) -> ResourceResolution:
        del task_id, step_id
        descriptor = self._descriptors.get(requirement.resource_id)
        if descriptor is None:
            return ResourceResolution(
                requirement,
                ResourceResolutionState.UNKNOWN,
                detail="no trusted resource descriptor is registered",
                evidence=("resource.descriptor.unknown",),
            )
        try:
            requested_type = ResourceType(requirement.resource_type)
        except ValueError:
            return ResourceResolution(
                requirement,
                ResourceResolutionState.INELIGIBLE,
                detail="resource type is not a trusted acquisition type",
                evidence=("resource.type.ineligible",),
            )
        if requested_type is not descriptor.resource_type:
            return ResourceResolution(
                requirement,
                ResourceResolutionState.INELIGIBLE,
                detail="resource type does not match trusted descriptor",
                evidence=("resource.type.mismatch",),
            )
        if requirement.requested_version not in {None, descriptor.requested_version}:
            return ResourceResolution(
                requirement,
                ResourceResolutionState.INELIGIBLE,
                detail="requested version is not supplied by the trusted descriptor",
                evidence=("resource.version.ineligible",),
            )
        if requirement.privacy_constraint not in {
            "unknown",
            descriptor.privacy_impact.value,
        }:
            return ResourceResolution(
                requirement,
                ResourceResolutionState.INELIGIBLE,
                detail="privacy constraint is not satisfied by the trusted descriptor",
                evidence=("resource.privacy.ineligible",),
            )
        if descriptor.supported_platforms and self._platform not in descriptor.supported_platforms:
            return ResourceResolution(
                requirement,
                ResourceResolutionState.INELIGIBLE,
                detail="resource is not supported on this platform",
                evidence=("resource.platform.ineligible",),
            )
        if (
            descriptor.supported_environments
            and self._environment not in descriptor.supported_environments
        ):
            return ResourceResolution(
                requirement,
                ResourceResolutionState.INELIGIBLE,
                detail="resource is not supported in this execution environment",
                evidence=("resource.environment.ineligible",),
            )
        request = descriptor.request_for(requirement)
        record = self._acquisition.ledger.get(request.fingerprint)
        if record is None or record.state is ArtifactState.FAILED:
            return ResourceResolution(
                requirement,
                ResourceResolutionState.MISSING,
                request,
                detail="trusted descriptor exists but no registered artifact is available",
                evidence=("resource.missing",),
            )
        if record.state is ArtifactState.REGISTERED:
            path = self._acquisition.materialized_path_for(request)
            expected_sha256 = request.expected_sha256
            if path is not None and path.is_file() and expected_sha256 is not None:
                digest = await asyncio.to_thread(_sha256, path)
                if digest.casefold() == expected_sha256.casefold():
                    return ResourceResolution(
                        requirement,
                        ResourceResolutionState.SATISFIED,
                        request,
                        path,
                        "trusted registered resource is usable",
                        ("resource.registered", "resource.integrity.verified"),
                    )
                return ResourceResolution(
                    requirement,
                    ResourceResolutionState.UNKNOWN,
                    request,
                    detail="registered artifact bytes do not match trusted integrity evidence",
                    evidence=("resource.integrity.mismatch",),
                )
            return ResourceResolution(
                requirement,
                ResourceResolutionState.UNKNOWN,
                request,
                detail="registered artifact path is unavailable",
                evidence=("resource.registration.unusable",),
            )
        if record.state in {ArtifactState.ACTIVE, ArtifactState.VERIFICATION_REQUIRED}:
            return ResourceResolution(
                requirement,
                ResourceResolutionState.UNKNOWN,
                request,
                detail="acquisition evidence requires reconciliation before reuse",
                evidence=("resource.acquisition.reconciliation_required",),
            )
        return ResourceResolution(
            requirement,
            ResourceResolutionState.TEMPORARILY_UNAVAILABLE,
            request,
            detail=f"resource lifecycle is {record.state.value}",
            evidence=(f"resource.lifecycle.{record.state.value}",),
        )

    async def acquire(
        self,
        resolution: ResourceResolution,
        *,
        task_id: UUID,
        step_id: UUID,
        cancellation: asyncio.Event,
    ) -> ResourceResolution:
        if resolution.state is not ResourceResolutionState.MISSING or resolution.request is None:
            return resolution
        if self._request_sink is not None:
            self._request_sink(resolution.request)
        from jarvis.system_stewardship import MissingResourceRequirement

        self._last_missing_requirement = MissingResourceRequirement(
            requirement_id=(
                f"task:{task_id}:step:{step_id}:resource:{resolution.request.resource_id}"
            ),
            source="trusted.resource.catalog",
            evidence_reference=f"task:{task_id}:step:{step_id}",
            request=resolution.request,
            task_id=task_id,
            step_id=step_id,
        )
        if cancellation.is_set():
            return ResourceResolution(
                resolution.requirement,
                ResourceResolutionState.TEMPORARILY_UNAVAILABLE,
                resolution.request,
                detail="acquisition was cancelled before the broker effect",
                evidence=("resource.acquisition.cancelled",),
            )
        try:
            result = await self._acquisition.acquire(
                resolution.request,
                task_id=task_id,
                disk_free_bytes=self._disk_free_bytes() if self._disk_free_bytes else None,
            )
        except AcquisitionApprovalRequired as error:
            return ResourceResolution(
                resolution.requirement,
                ResourceResolutionState.TEMPORARILY_UNAVAILABLE,
                resolution.request,
                detail=str(error),
                evidence=("resource.acquisition.awaiting_approval",),
            )
        except AcquisitionDeferred as error:
            return ResourceResolution(
                resolution.requirement,
                ResourceResolutionState.RESOURCE_PRESSURE,
                resolution.request,
                detail=str(error),
                evidence=("resource.acquisition.deferred",),
            )
        except AcquisitionUnknownOutcome as error:
            return ResourceResolution(
                resolution.requirement,
                ResourceResolutionState.UNKNOWN,
                resolution.request,
                detail=str(error),
                evidence=("resource.acquisition.unknown_outcome",),
            )
        except AcquisitionTransportError as error:
            return ResourceResolution(
                resolution.requirement,
                ResourceResolutionState.TEMPORARILY_UNAVAILABLE,
                resolution.request,
                detail=str(error),
                evidence=("resource.acquisition.transport_failure",),
            )
        except AcquisitionDenied as error:
            return ResourceResolution(
                resolution.requirement,
                ResourceResolutionState.DENIED,
                resolution.request,
                detail=str(error),
                evidence=("resource.acquisition.denied",),
            )
        if result.status not in {
            AcquisitionResultStatus.REGISTERED,
            AcquisitionResultStatus.DUPLICATE,
        }:
            return ResourceResolution(
                resolution.requirement,
                ResourceResolutionState.TEMPORARILY_UNAVAILABLE,
                resolution.request,
                detail=f"acquisition ended in {result.status.value}",
                evidence=(f"resource.acquisition.{result.status.value}",),
            )
        return await self.resolve(
            resolution.requirement,
            task_id=task_id,
            step_id=UUID(int=0),
        )

    async def reconcile(
        self,
        resolution: ResourceResolution,
        *,
        task_id: UUID,
    ) -> ResourceResolution:
        if resolution.request is None:
            return resolution
        try:
            await self._acquisition.reconcile(resolution.request)
        except AcquisitionUnknownOutcome as error:
            return ResourceResolution(
                resolution.requirement,
                ResourceResolutionState.UNKNOWN,
                resolution.request,
                detail=str(error),
                evidence=("resource.reconciliation.incomplete",),
            )
        return await self.resolve(
            resolution.requirement,
            task_id=task_id,
            step_id=UUID(int=0),
        )


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


__all__ = [
    "AcquisitionResourceBridge",
    "ResourceRequirementResolver",
    "ResourceResolution",
    "ResourceResolutionState",
    "TrustedResourceDescriptor",
]
