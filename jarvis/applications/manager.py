"""Application discovery, immutable package plans, lifecycle, and verification."""

from __future__ import annotations

import asyncio
import re
from dataclasses import dataclass
from uuid import UUID

from jarvis.applications.models import (
    ApplicationAmbiguousError,
    ApplicationManagerError,
    ApplicationMatchStatus,
    ApplicationNotFoundError,
    ApplicationRecord,
    ApplicationSearchResult,
    ApplicationStatus,
    InstallationOutcome,
    InstallationPlan,
    InstallationPlanError,
    InstallationPlanKind,
    InstallationVerification,
    PackageNotFoundError,
    VerificationError,
)
from jarvis.applications.plans import InstallationPlanStore
from jarvis.applications.providers import ApplicationInventoryProvider, PackageProvider
from jarvis.applications.runtime import ApplicationRuntime
from jarvis.computer.models import LaunchInfo

_VERSION_PARTS = re.compile(r"^v?(\d+(?:\.\d+){0,7})$")


@dataclass(slots=True)
class ApplicationManager:
    """Trusted coordinator; untrusted callers choose names/IDs, never paths or commands."""

    inventory_provider: ApplicationInventoryProvider
    package_provider: PackageProvider
    runtime: ApplicationRuntime
    plans: InstallationPlanStore

    async def inventory(self) -> tuple[ApplicationRecord, ...]:
        records = await self.inventory_provider.enumerate_installed()
        if len({record.application_id for record in records}) != len(records):
            raise ApplicationManagerError("Application inventory contains duplicate identifiers")
        return records

    async def find(self, semantic_name: str) -> ApplicationSearchResult:
        query = _semantic_query(semantic_name)
        matches = tuple(record for record in await self.inventory() if _matches(query, record.name))
        if not matches:
            return ApplicationSearchResult(ApplicationMatchStatus.MISSING, semantic_name, ())
        exact = tuple(record for record in matches if record.name.casefold() == query)
        selected = exact or matches
        status = (
            ApplicationMatchStatus.FOUND if len(selected) == 1 else ApplicationMatchStatus.AMBIGUOUS
        )
        return ApplicationSearchResult(status, semantic_name, selected)

    async def plan_install(
        self, semantic_name: str
    ) -> tuple[InstallationPlan | None, ApplicationRecord | None]:
        """Create a plan only when the target is not already validly installed."""

        query = _semantic_query(semantic_name)
        candidates = await self.package_provider.search(query)
        if not candidates:
            raise PackageNotFoundError("No package candidate was found")
        if len(candidates) != 1:
            raise ApplicationAmbiguousError("Package search is ambiguous")
        candidate = candidates[0]
        existing = self._verification_match(await self.inventory(), candidate.verification)
        if len(existing) > 1:
            raise ApplicationAmbiguousError("Installed application identity is ambiguous")
        if existing:
            record = existing[0]
            if record.status is ApplicationStatus.INSTALLED and await self.runtime.can_launch(
                record
            ):
                return None, record
        plan = await self.plans.create(InstallationPlanKind.INSTALL, candidate)
        return plan, None

    async def plan_update(self, application_id: str) -> InstallationPlan:
        record = await self._record(application_id)
        if record.status is not ApplicationStatus.INSTALLED or record.version is None:
            raise ApplicationManagerError("Application is not in a valid updatable state")
        candidate = await self.package_provider.find_update(record)
        if candidate is None:
            raise PackageNotFoundError("No package update is available")
        if not _is_newer(candidate.version, record.version):
            raise ApplicationManagerError("Update target must be a strictly newer version")
        if not _verification_matches(record, candidate.verification):
            raise VerificationError("Update package identity does not match installed application")
        return await self.plans.create(
            InstallationPlanKind.UPDATE,
            candidate,
            current_version=record.version,
        )

    def plan_for_descriptor(self, plan_id: UUID) -> InstallationPlan | None:
        """Expose immutable plan data to a synchronous broker descriptor only."""

        return self.plans.peek(plan_id)

    async def execute_plan(
        self,
        plan_id: UUID,
        expected_kind: InstallationPlanKind,
        cancellation: asyncio.Event,
    ) -> InstallationOutcome:
        """Consume the plan, execute one fixed provider operation, then independently verify."""

        plan = await self.plans.consume(plan_id)
        if plan.kind is not expected_kind:
            raise InstallationPlanError("Installation plan does not match requested operation")
        already_present = self._verification_match(
            await self.inventory(), plan.candidate.verification
        )
        if len(already_present) > 1:
            raise VerificationError("Installed application identity is ambiguous")
        if already_present and already_present[0].status is ApplicationStatus.INSTALLED:
            record = already_present[0]
            is_current = plan.kind is InstallationPlanKind.INSTALL or (
                record.version == plan.candidate.version
                or (
                    record.version is not None and _is_newer(record.version, plan.candidate.version)
                )
            )
            if is_current and await self.runtime.can_launch(record):
                return InstallationOutcome(plan.kind, record, True, already_present=True)
        if cancellation.is_set():
            raise InstallationPlanError("Installation operation was cancelled")
        if plan.kind is InstallationPlanKind.INSTALL:
            await self.package_provider.install(plan.candidate, cancellation)
        else:
            await self.package_provider.update(plan.candidate, cancellation)
        records = await self.inventory()
        matches = self._verification_match(records, plan.candidate.verification)
        if len(matches) != 1:
            raise VerificationError("Installed application did not match approved package identity")
        record = matches[0]
        if record.status is not ApplicationStatus.INSTALLED:
            raise VerificationError("Installed application is not launchable")
        if record.version != plan.candidate.version:
            raise VerificationError("Installed application version did not match approved package")
        if not await self.runtime.can_launch(record):
            raise VerificationError("Installed application executable could not be verified")
        return InstallationOutcome(plan.kind, record, True)

    async def launch(self, application_id: str) -> LaunchInfo:
        record = await self._record(application_id)
        if record.status is not ApplicationStatus.INSTALLED or not await self.runtime.can_launch(
            record
        ):
            raise ApplicationManagerError("Managed application is not launchable")
        return await self.runtime.launch(record)

    async def close(self, application_id: str, process_id: int) -> None:
        await self.runtime.close(application_id, process_id)

    async def _record(self, application_id: str) -> ApplicationRecord:
        matches = tuple(
            record for record in await self.inventory() if record.application_id == application_id
        )
        if not matches:
            raise ApplicationNotFoundError("Application is not in the current inventory")
        if len(matches) != 1:
            raise ApplicationManagerError("Application inventory identifier is ambiguous")
        return matches[0]

    @staticmethod
    def _verification_match(
        records: tuple[ApplicationRecord, ...], verification: InstallationVerification
    ) -> tuple[ApplicationRecord, ...]:
        return tuple(record for record in records if _verification_matches(record, verification))


def _semantic_query(value: str) -> str:
    normalized = value.strip().casefold()
    if not normalized or len(normalized) > 128 or "\x00" in normalized:
        raise ApplicationManagerError("Application name query is invalid")
    return normalized


def _matches(query: str, name: str) -> bool:
    return query in name.casefold()


def _verification_matches(record: ApplicationRecord, expected: InstallationVerification) -> bool:
    return record.name.casefold() == expected.application_name.casefold() and (
        expected.publisher is None
        or (record.publisher or "").casefold() == expected.publisher.casefold()
    )


def _version_tuple(value: str) -> tuple[int, ...] | None:
    match = _VERSION_PARTS.fullmatch(value.strip())
    if match is None:
        return None
    return tuple(int(item) for item in match.group(1).split("."))


def _is_newer(target: str, current: str) -> bool:
    target_parts = _version_tuple(target)
    current_parts = _version_tuple(current)
    if target_parts is None or current_parts is None:
        return False
    width = max(len(target_parts), len(current_parts))
    return target_parts + (0,) * (width - len(target_parts)) > current_parts + (0,) * (
        width - len(current_parts)
    )
