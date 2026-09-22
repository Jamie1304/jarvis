"""Certified hot-load lifecycle for generic Integration Packages.

This is a coordinator, not a package catalog or execution engine.  It swaps a
prepared package runtime only after certification, health, permission-diff,
Shadow, and Canary gates have all passed.
"""

from __future__ import annotations

from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass, field
from enum import StrEnum
from threading import RLock
from typing import Protocol, TypeVar

from jarvis.capability_lifecycle import SQLiteCapabilityLifecycleStore
from jarvis.integration_package import IntegrationPackage
from jarvis.package_certification import CertificationRecord
from jarvis.tools.models import SemanticVersion


class HotLoadError(RuntimeError):
    """A package could not be safely loaded or swapped."""


class PackageChangeKind(StrEnum):
    INSTALL = "install"
    UPDATE = "update"
    REMOVE = "remove"


@dataclass(frozen=True, slots=True)
class PackageCertification:
    package_id: str
    version: SemanticVersion
    package_hash: str
    certified: bool
    permission_diff_approved: bool
    shadow_passed: bool
    canary_passed: bool
    record: CertificationRecord | None = field(default=None, kw_only=True)

    @classmethod
    def from_record(cls, record: CertificationRecord) -> PackageCertification:
        if not isinstance(record, CertificationRecord):
            raise HotLoadError("Certification record is malformed")
        return cls(
            record.package_id,
            record.version,
            record.package_hash,
            True,
            True,
            record.shadow_eligible,
            record.canary_eligible,
            record=record,
        )


@dataclass(frozen=True, slots=True)
class PackageChange:
    kind: PackageChangeKind
    package: IntegrationPackage | None
    certification: PackageCertification | None = None


@dataclass(frozen=True, slots=True)
class PackageRuntimeHealth:
    healthy: bool
    detail: str


RuntimeState = Mapping[str, object]
RuntimeResult = TypeVar("RuntimeResult")


class PreparedPackageRuntime(Protocol):
    package: IntegrationPackage

    def health_check(self) -> PackageRuntimeHealth: ...

    def export_state(self) -> RuntimeState: ...

    def restore_state(self, state: RuntimeState) -> None: ...

    def drain(self) -> None: ...


class PackageRuntimeFactory(Protocol):
    def prepare(self, package: IntegrationPackage) -> PreparedPackageRuntime: ...


class PackageRegistrationSurface(Protocol):
    """Application-owned atomic registration and projection refresh boundary."""

    def atomic_swap(
        self,
        package: IntegrationPackage,
        runtime: PreparedPackageRuntime,
    ) -> None: ...

    def rollback(
        self,
        package: IntegrationPackage,
        runtime: PreparedPackageRuntime | None,
    ) -> None: ...

    def remove(self, package: IntegrationPackage, runtime: PreparedPackageRuntime) -> None: ...


class PackageWatcher(Protocol):
    def start(self, callback: Callable[[PackageChange], None]) -> None: ...

    def stop(self) -> None: ...


@dataclass(frozen=True, slots=True)
class ActivePackage:
    package: IntegrationPackage
    runtime: PreparedPackageRuntime
    certification: PackageCertification


def compare_package_versions(left: SemanticVersion, right: SemanticVersion) -> int:
    if left < right:
        return -1
    if left > right:
        return 1
    return 0


class HotLoadManager:
    """Own active package runtimes and perform serialized, certified swaps."""

    def __init__(
        self,
        factory: PackageRuntimeFactory,
        surface: PackageRegistrationSurface,
        *,
        watcher: PackageWatcher | None = None,
        lifecycle_store: SQLiteCapabilityLifecycleStore | None = None,
    ) -> None:
        self._factory = factory
        self._surface = surface
        self._watcher = watcher
        if lifecycle_store is not None and not isinstance(
            lifecycle_store, SQLiteCapabilityLifecycleStore
        ):
            raise HotLoadError("Capability lifecycle store is malformed")
        self._lifecycle = lifecycle_store
        self._active: dict[str, ActivePackage] = {}
        self._lock = RLock()

    def start_watching(self) -> None:
        if self._watcher is not None:
            self._watcher.start(self.refresh)

    def stop_watching(self) -> None:
        if self._watcher is not None:
            self._watcher.stop()

    def manual_refresh(
        self,
        package: IntegrationPackage,
        certification: PackageCertification,
    ) -> ActivePackage:
        return self._load(package, certification, allow_same_version=False)

    def refresh(self, change: PackageChange) -> None:
        if change.kind is PackageChangeKind.REMOVE:
            if change.package is None:
                raise HotLoadError("Package removal requires package identity")
            self.remove(change.package.package_id)
            return
        if change.package is None or change.certification is None:
            raise HotLoadError("Package changes require package and certification")
        self._load(change.package, change.certification, allow_same_version=False)

    def remove(self, package_id: str) -> None:
        with self._lock:
            active = self._active.get(package_id)
            if active is None:
                return
            self._surface.remove(active.package, active.runtime)
            active.runtime.drain()
            del self._active[package_id]

    def cleanup_stale(self, package_ids: Sequence[str]) -> tuple[str, ...]:
        keep = set(package_ids)
        with self._lock:
            stale = tuple(package_id for package_id in self._active if package_id not in keep)
        for package_id in stale:
            self.remove(package_id)
        return stale

    def restart(self, package_id: str) -> ActivePackage:
        with self._lock:
            try:
                active = self._active[package_id]
            except KeyError as error:
                raise HotLoadError("Cannot restart an inactive package") from error
            return self._load_locked(active.package, active.certification, allow_same_version=True)

    def rollback_to(
        self,
        package: IntegrationPackage,
        certification: PackageCertification,
    ) -> ActivePackage:
        """Restore an older certified version at the trusted lifecycle boundary."""

        return self._load(
            package,
            certification,
            allow_same_version=True,
            allow_rollback=True,
        )

    def active(self, package_id: str) -> ActivePackage:
        with self._lock:
            try:
                return self._active[package_id]
            except KeyError as error:
                raise KeyError("Package is not active") from error

    def active_packages(self) -> tuple[ActivePackage, ...]:
        with self._lock:
            return tuple(self._active.values())

    def invoke(
        self,
        package_id: str,
        operation: Callable[[PreparedPackageRuntime], RuntimeResult],
    ) -> RuntimeResult:
        """Serialize invocation with swapping so old runtimes drain safely."""

        with self._lock:
            return operation(self.active(package_id).runtime)

    def _load(
        self,
        package: IntegrationPackage,
        certification: PackageCertification,
        *,
        allow_same_version: bool,
        allow_rollback: bool = False,
    ) -> ActivePackage:
        with self._lock:
            return self._load_locked(
                package,
                certification,
                allow_same_version=allow_same_version,
                allow_rollback=allow_rollback,
            )

    def _load_locked(
        self,
        package: IntegrationPackage,
        certification: PackageCertification,
        *,
        allow_same_version: bool,
        allow_rollback: bool = False,
    ) -> ActivePackage:
        self._validate_certification(package, certification)
        if self._lifecycle is not None:
            durable = self._lifecycle.load(package.package_id, str(package.version))
            if durable is None or durable.record.package_hash != package.package_hash:
                raise HotLoadError("Package has no matching durable lifecycle state")
            if durable.record.state.value != "ACTIVE" and not (
                durable.transaction_state == "RECOVERING" and durable.pending_target == "ACTIVE"
            ):
                raise HotLoadError("Runtime swap is not authorized by durable lifecycle state")
        previous = self._active.get(package.package_id)
        if previous is not None:
            comparison = compare_package_versions(package.version, previous.package.version)
            if (comparison < 0 and not allow_rollback) or (
                comparison == 0 and not allow_same_version
            ):
                raise HotLoadError("Package version is not newer than the active version")
            if comparison == 0 and package.package_hash != previous.package.package_hash:
                raise HotLoadError("Changed package content needs a new version")
            if comparison == 0 and allow_same_version:
                pass

        prepared: PreparedPackageRuntime | None = None
        try:
            prepared = self._factory.prepare(package)
            if previous is not None:
                prepared.restore_state(previous.runtime.export_state())
            health = prepared.health_check()
            if not health.healthy:
                raise HotLoadError("Prepared package failed health check")
        except Exception as error:
            _drain_safely(prepared)
            raise HotLoadError("Package preparation or health check failed") from error

        try:
            self._surface.atomic_swap(package, prepared)
        except Exception as error:
            # The surface must make rollback idempotent because a failure may
            # occur after registration but before all projections refresh.
            self._surface.rollback(package, previous.runtime if previous else None)
            _drain_safely(prepared)
            raise HotLoadError("Atomic package registration swap failed") from error

        if previous is not None:
            try:
                previous.runtime.drain()
            except Exception as error:
                # The new runtime is active; report the drain problem without
                # restoring a runtime that may still be in use.
                self._active[package.package_id] = ActivePackage(package, prepared, certification)
                raise HotLoadError("Previous package runtime did not drain") from error
        active = ActivePackage(package, prepared, certification)
        self._active[package.package_id] = active
        return active

    @staticmethod
    def _validate_certification(
        package: IntegrationPackage,
        certification: PackageCertification,
    ) -> None:
        if package.provenance is None or not package.package_hash:
            raise HotLoadError("Package is not provenance/hash certified")
        if (
            certification.package_id != package.package_id
            or certification.version != package.version
            or certification.package_hash != package.package_hash
        ):
            raise HotLoadError("Certification does not bind this exact package version")
        if certification.record is not None:
            if (
                certification.record.package_id != package.package_id
                or certification.record.version != package.version
                or certification.record.package_hash != package.package_hash
                or certification.record.permissions != package.permissions
            ):
                raise HotLoadError("Certification record does not bind package metadata")
        if not all(
            (
                certification.certified,
                certification.permission_diff_approved,
                certification.shadow_passed,
                certification.canary_passed,
            )
        ):
            raise HotLoadError("Package certification, permission, Shadow, or Canary gate failed")


def _drain_safely(runtime: PreparedPackageRuntime | None) -> None:
    if runtime is not None:
        try:
            runtime.drain()
        except Exception:
            pass
