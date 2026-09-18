"""Local-first storage and recovery-aware file stewardship contracts.

The module intentionally keeps observation, planning, authority, and effects
separate.  Storage facts are local machine evidence; plans are inert typed
records; file effects require the existing :class:`PermissionBroker` and are
bound to a durable manifest which is revalidated before every effect.
"""

from __future__ import annotations

import asyncio
import ctypes
import hashlib
import json
import os
import shutil
import sqlite3
import stat
import tempfile
from collections.abc import Callable, Iterable, Mapping, Sequence
from dataclasses import dataclass, replace
from datetime import UTC, datetime, timedelta
from enum import StrEnum
from pathlib import Path
from typing import Protocol, cast
from uuid import UUID, uuid4

from jarvis.acquisition import AcquisitionRequest, ResourceType
from jarvis.permissions import Permission, PermissionBroker, PermissionScope
from jarvis.permissions.models import (
    ActionDescriptor,
    AuthorizationReceipt,
    PermissionRequest,
    Risk,
    SafetyClass,
)
from jarvis.resources import (
    ReservationReleaseReason,
    ResourceBudget,
    ResourceGovernor,
    ResourcePriority,
)
from jarvis.vm.bridge import (
    HostBridge,
    HostBridgeOperation,
    HostBridgeRequest,
    build_host_bridge_action_descriptor,
)


class StorageError(RuntimeError):
    """Base error for storage observation, planning, or stewardship."""


class StorageDeferred(StorageError):
    """A bounded storage operation was deferred by the ResourceGovernor."""


class MutationError(StorageError):
    """Base error for a file mutation that did not complete."""


class MutationDenied(MutationError):
    """Trusted policy or protection evidence denied a mutation."""


class MutationConflict(MutationError):
    """A destination or recovery location conflicts with existing data."""


class StalePlan(MutationError):
    """The machine state no longer matches the exact mutation plan."""


class MutationUnknownOutcome(MutationError):
    """The effect boundary lacks trusted terminal evidence."""


class ManifestIntegrityError(MutationError):
    """A durable mutation manifest was altered or is malformed."""


class MutationApprovalRequired(MutationDenied):
    """The PermissionBroker returned an approval request."""

    def __init__(self, approvals: object) -> None:
        super().__init__("trusted file-mutation approval is required")
        self.approvals = approvals


class VolumeDriveType(StrEnum):
    FIXED = "fixed"
    REMOVABLE = "removable"
    NETWORK = "network"
    OPTICAL = "optical"
    RAM = "ram"
    UNKNOWN = "unknown"


class StoragePressureState(StrEnum):
    HEALTHY = "healthy"
    WATCH = "watch"
    CONSTRAINED = "constrained"
    CRITICAL = "critical"
    UNKNOWN = "unknown"


class ForecastState(StrEnum):
    INSUFFICIENT_EVIDENCE = "insufficient_evidence"
    STABLE = "stable"
    DECLINING = "declining"
    GROWING = "growing"
    UNKNOWN = "unknown"


class PlacementClass(StrEnum):
    HOT = "hot"
    WARM = "warm"
    COLD = "cold"
    ARCHIVE = "archive"


class StorageResourceType(StrEnum):
    MODEL = "model"
    VM_IMAGE = "vm_image"
    DOWNLOAD = "download"
    DATASET = "dataset"
    CACHE = "cache"
    BUILD_ARTIFACT = "build_artifact"
    ARCHIVE = "archive"
    BACKUP = "backup"
    GENERIC = "generic"


class FileOwnership(StrEnum):
    SYSTEM = "system"
    JARVIS = "jarvis"
    USER = "user"
    APPLICATION = "application"
    MODEL_PROVIDER = "model_provider"
    VM = "vm"
    UNKNOWN = "unknown"


class FileCategory(StrEnum):
    SYSTEM_CRITICAL = "system_critical"
    PERFORMANCE_SENSITIVE = "performance_sensitive"
    USER_DATA = "user_data"
    MOVABLE_USER_DATA = "movable_user_data"
    CACHE = "cache"
    TEMPORARY = "temporary"
    MODEL_STORAGE = "model_storage"
    VM_STORAGE = "vm_storage"
    ARCHIVE = "archive"
    APPLICATION_MANAGED = "application_managed"
    JARVIS_OWNED = "jarvis_owned"
    UNKNOWN = "unknown"


class RetentionState(StrEnum):
    ACTIVE = "active"
    NEEDED_FOR_EVIDENCE = "needed_for_evidence"
    ROLLBACK_REQUIRED = "rollback_required"
    RETENTION = "retention"
    EXPIRED = "expired"
    SAFE_TO_REMOVE = "safe_to_remove"
    UNKNOWN = "unknown"


class CleanupState(StrEnum):
    ELIGIBLE = "eligible"
    PROTECTED = "protected"
    UNKNOWN = "unknown"
    DELEGATE = "delegate"


class DownloadState(StrEnum):
    ACTIVE = "active"
    RECENT = "recent"
    INSTALLER_ALREADY_INSTALLED = "installer_already_installed"
    DUPLICATE = "duplicate"
    ARCHIVABLE = "archivable"
    MOVABLE = "movable"
    STALE = "stale"
    UNKNOWN = "unknown"


class MutationOperation(StrEnum):
    COPY = "copy"
    MOVE = "move"
    RENAME = "rename"
    SAFE_DELETE = "safe_delete"
    RESTORE = "restore"


class MutationState(StrEnum):
    PLANNED = "planned"
    IN_PROGRESS = "in_progress"
    COMPLETED = "completed"
    PARTIAL = "partial"
    RESTORED = "restored"
    STALE_PLAN = "stale_plan"
    CONFLICT = "conflict"
    DENIED = "denied"
    UNKNOWN_OUTCOME = "unknown_outcome"


class MutationPhase(StrEnum):
    EFFECT = "effect"
    RESTORE = "restore"


class MutationItemState(StrEnum):
    NOT_STARTED = "not_started"
    INTENT_PERSISTED = "effect_intent_persisted"
    EFFECT_MAY_HAVE_STARTED = "effect_may_have_started"
    VERIFIED = "effect_verified"
    FAILED_BEFORE_EFFECT = "failed_before_effect"
    UNKNOWN_OUTCOME = "outcome_unresolved"
    RESTORATION_IN_PROGRESS = "restoration_in_progress"
    RESTORED = "restoration_verified"


class FilesystemObservationState(StrEnum):
    """Trusted result categories for one read-only filesystem observation."""

    ABSENT = "absent"
    PRESENT_VERIFIED = "present_verified"
    PRESENT_UNEXPECTED = "present_unexpected"
    UNKNOWN = "unknown"
    UNSAFE_REPARSE = "unsafe_reparse"


class Reversibility(StrEnum):
    FULLY_REVERSIBLE = "fully_reversible"
    REVERSIBLE_WITH_BACKUP = "reversible_with_backup"
    REINSTALL_REQUIRED = "reinstall_required"
    PARTIALLY_REVERSIBLE = "partially_reversible"
    IRREVERSIBLE = "irreversible"


class PlacementStatus(StrEnum):
    RECOMMENDED = "recommended"
    ALREADY_SUITABLE = "already_suitable"
    NO_COMPATIBLE_TARGET = "no_compatible_target"
    UNKNOWN_COMPATIBILITY = "unknown_compatibility"
    RELOCATION_UNSUPPORTED = "relocation_unsupported"
    STALE_PLAN = "stale_plan"


def _utc(value: datetime) -> datetime:
    if value.tzinfo is None:
        return value.replace(tzinfo=UTC)
    return value.astimezone(UTC)


def _text(value: object, field_name: str, *, maximum: int = 4_096) -> str:
    if (
        type(value) is not str
        or not value
        or len(value) > maximum
        or any(not character.isprintable() for character in value)
    ):
        raise ValueError(f"{field_name} is malformed")
    return value


def _nonnegative(value: int | None, field_name: str) -> None:
    if value is not None and (type(value) is not int or value < 0):
        raise ValueError(f"{field_name} must be a non-negative integer or UNKNOWN")


def _canonical(path: Path) -> Path:
    candidate = path.expanduser()
    if not candidate.is_absolute():
        raise MutationDenied("file paths must be absolute")
    if _has_reparse_ancestor(candidate):
        raise MutationDenied("file path contains a symlink or junction")
    resolved = candidate.resolve(strict=False)
    if _has_reparse_ancestor(resolved):
        raise MutationDenied("file path contains a reparse point")
    return resolved


def _has_reparse_ancestor(path: Path) -> bool:
    current = path.expanduser().absolute()
    while True:
        try:
            if current.is_symlink() or bool(getattr(current, "is_junction", lambda: False)()):
                return True
        except OSError:
            return True
        if current == current.parent:
            return False
        current = current.parent


def _under(path: Path, root: Path) -> bool:
    try:
        path.relative_to(root)
    except ValueError:
        return False
    return True


def _safe_root(root: Path) -> Path:
    candidate = _canonical(root)
    candidate.mkdir(parents=True, exist_ok=True)
    if not candidate.is_dir() or _has_reparse_ancestor(candidate):
        raise MutationDenied("trusted storage root is unsafe")
    return candidate


@dataclass(frozen=True, slots=True)
class VolumeObservation:
    """Facts actually established for one observed volume."""

    volume_id: str
    mount_points: tuple[str, ...]
    filesystem: str | None
    capacity_bytes: int | None
    used_bytes: int | None
    free_bytes: int | None
    drive_type: VolumeDriveType | None
    speed_class: str | None
    health: str | None
    encryption: str | None
    removable: bool | None
    system_volume: bool | None
    read_only: bool | None
    network: bool | None
    observed_at: datetime
    evidence_source: str
    stable_identity: bool = True

    def __post_init__(self) -> None:
        _text(self.volume_id, "Volume identity", maximum=512)
        if (
            type(self.mount_points) is not tuple
            or not self.mount_points
            or any(type(item) is not str or not item for item in self.mount_points)
        ):
            raise ValueError("Volume mount points are malformed")
        for value, field_name in (
            (self.capacity_bytes, "Volume capacity"),
            (self.used_bytes, "Volume usage"),
            (self.free_bytes, "Volume free space"),
        ):
            _nonnegative(value, field_name)
        if self.capacity_bytes is not None and self.free_bytes is not None:
            if self.free_bytes > self.capacity_bytes:
                raise ValueError("Volume free space exceeds capacity")
        if not isinstance(self.observed_at, datetime) or self.observed_at.tzinfo is None:
            raise ValueError("Volume observation time must be timezone-aware")
        if type(self.stable_identity) is not bool:
            raise ValueError("Volume identity stability is malformed")

    @property
    def identity(self) -> str:
        return self.volume_id

    @property
    def pressure_ratio(self) -> float | None:
        if self.capacity_bytes in (None, 0) or self.free_bytes is None:
            return None
        capacity = self.capacity_bytes
        assert capacity is not None
        return self.free_bytes / capacity

    def as_dict(self) -> dict[str, object]:
        return {
            "volume_id": self.volume_id,
            "mount_points": list(self.mount_points),
            "filesystem": self.filesystem,
            "capacity_bytes": self.capacity_bytes,
            "used_bytes": self.used_bytes,
            "free_bytes": self.free_bytes,
            "drive_type": self.drive_type.value if self.drive_type else None,
            "speed_class": self.speed_class,
            "health": self.health,
            "encryption": self.encryption,
            "removable": self.removable,
            "system_volume": self.system_volume,
            "read_only": self.read_only,
            "network": self.network,
            "observed_at": _utc(self.observed_at).isoformat(),
            "evidence_source": self.evidence_source,
            "stable_identity": self.stable_identity,
        }


@dataclass(frozen=True, slots=True)
class StoragePressurePolicy:
    """Trusted, explicit pressure thresholds; no model-generated policy."""

    watch_free_bytes: int = 32 * 1024**3
    constrained_free_bytes: int = 16 * 1024**3
    critical_free_bytes: int = 4 * 1024**3
    watch_free_ratio: float = 0.15
    constrained_free_ratio: float = 0.08
    critical_free_ratio: float = 0.03
    required_headroom_bytes: int = 0

    def __post_init__(self) -> None:
        for value, name in (
            (self.watch_free_bytes, "watch free bytes"),
            (self.constrained_free_bytes, "constrained free bytes"),
            (self.critical_free_bytes, "critical free bytes"),
            (self.required_headroom_bytes, "required headroom"),
        ):
            if type(value) is not int or value < 0:
                raise ValueError(f"{name} is malformed")
        for ratio_value, name in (
            (self.watch_free_ratio, "watch free ratio"),
            (self.constrained_free_ratio, "constrained free ratio"),
            (self.critical_free_ratio, "critical free ratio"),
        ):
            if type(ratio_value) not in {int, float} or not 0 <= ratio_value <= 1:
                raise ValueError(f"{name} is malformed")
        if not (
            self.critical_free_bytes <= self.constrained_free_bytes <= self.watch_free_bytes
            and self.critical_free_ratio <= self.constrained_free_ratio <= self.watch_free_ratio
        ):
            raise ValueError("pressure thresholds must be ordered")


def classify_storage_pressure(
    volume: VolumeObservation,
    policy: StoragePressurePolicy,
    *,
    incoming_bytes: int = 0,
) -> StoragePressureState:
    """Classify using both absolute and relative evidence plus headroom."""

    if not isinstance(volume, VolumeObservation) or not isinstance(policy, StoragePressurePolicy):
        raise ValueError("storage pressure inputs are malformed")
    if type(incoming_bytes) is not int or incoming_bytes < 0:
        raise ValueError("incoming bytes are malformed")
    if volume.free_bytes is None or volume.capacity_bytes in (None, 0):
        return StoragePressureState.UNKNOWN
    free = volume.free_bytes - incoming_bytes - policy.required_headroom_bytes
    capacity = volume.capacity_bytes
    assert capacity is not None
    ratio = free / capacity
    if free <= policy.critical_free_bytes or ratio <= policy.critical_free_ratio:
        return StoragePressureState.CRITICAL
    if free <= policy.constrained_free_bytes or ratio <= policy.constrained_free_ratio:
        return StoragePressureState.CONSTRAINED
    if free <= policy.watch_free_bytes or ratio <= policy.watch_free_ratio:
        return StoragePressureState.WATCH
    return StoragePressureState.HEALTHY


@dataclass(frozen=True, slots=True)
class StorageHistorySnapshot:
    volume_id: str
    captured_at: datetime
    capacity_bytes: int | None
    used_bytes: int | None
    free_bytes: int | None
    pressure: StoragePressureState

    def __post_init__(self) -> None:
        _text(self.volume_id, "History volume identity", maximum=512)
        if self.captured_at.tzinfo is None:
            raise ValueError("History timestamp must be timezone-aware")
        for value, name in (
            (self.capacity_bytes, "capacity"),
            (self.used_bytes, "used"),
            (self.free_bytes, "free"),
        ):
            _nonnegative(value, name)
        if not isinstance(self.pressure, StoragePressureState):
            raise ValueError("History pressure state is malformed")


class StorageHistoryStore:
    """Bounded metadata-only storage history; raw file content never enters it."""

    def __init__(self, path: Path, *, max_snapshots: int = 256) -> None:
        if type(max_snapshots) is not int or not 1 <= max_snapshots <= 10_000:
            raise ValueError("max_snapshots is malformed")
        self.path = _safe_root(path.parent) / path.name
        self._connection = sqlite3.connect(self.path, timeout=5.0)
        self._connection.execute("PRAGMA journal_mode=WAL")
        self._connection.execute(
            "CREATE TABLE IF NOT EXISTS storage_history ("
            "volume_id TEXT NOT NULL, captured_at TEXT NOT NULL, capacity INTEGER, "
            "used INTEGER, free INTEGER, pressure TEXT NOT NULL, "
            "PRIMARY KEY(volume_id, captured_at))"
        )
        self._connection.commit()
        self.max_snapshots = max_snapshots

    def record(self, snapshot: StorageHistorySnapshot) -> None:
        self._connection.execute(
            "INSERT OR REPLACE INTO storage_history "
            "(volume_id, captured_at, capacity, used, free, pressure) VALUES (?, ?, ?, ?, ?, ?)",
            (
                snapshot.volume_id,
                _utc(snapshot.captured_at).isoformat(),
                snapshot.capacity_bytes,
                snapshot.used_bytes,
                snapshot.free_bytes,
                snapshot.pressure.value,
            ),
        )
        self._connection.execute(
            "DELETE FROM storage_history WHERE volume_id=? AND captured_at NOT IN "
            "(SELECT captured_at FROM storage_history WHERE volume_id=? "
            "ORDER BY captured_at DESC LIMIT ?)",
            (snapshot.volume_id, snapshot.volume_id, self.max_snapshots),
        )
        self._connection.commit()

    def snapshots(self, volume_id: str | None = None) -> tuple[StorageHistorySnapshot, ...]:
        if volume_id is None:
            rows = self._connection.execute(
                "SELECT volume_id, captured_at, capacity, used, free, pressure "
                "FROM storage_history ORDER BY captured_at"
            ).fetchall()
        else:
            rows = self._connection.execute(
                "SELECT volume_id, captured_at, capacity, used, free, pressure "
                "FROM storage_history WHERE volume_id=? ORDER BY captured_at",
                (volume_id,),
            ).fetchall()
        return tuple(
            StorageHistorySnapshot(
                str(row[0]),
                datetime.fromisoformat(str(row[1])),
                int(row[2]) if row[2] is not None else None,
                int(row[3]) if row[3] is not None else None,
                int(row[4]) if row[4] is not None else None,
                StoragePressureState(str(row[5])),
            )
            for row in rows
        )

    def close(self) -> None:
        self._connection.close()


class VolumeProbe(Protocol):
    def __call__(self) -> tuple[VolumeObservation, ...]: ...


class StorageInventoryService:
    """One read-only per-volume inventory authority."""

    def __init__(
        self,
        *,
        probe: VolumeProbe | None = None,
        history: StorageHistoryStore | None = None,
        pressure_policy: StoragePressurePolicy | None = None,
        clock: Callable[[], datetime] | None = None,
    ) -> None:
        self._probe = probe
        self._history = history
        self._policy = pressure_policy or StoragePressurePolicy()
        self._clock = clock or (lambda: datetime.now(UTC))
        self._last: tuple[VolumeObservation, ...] = ()

    @property
    def last(self) -> tuple[VolumeObservation, ...]:
        return self._last

    def inspect(self) -> tuple[VolumeObservation, ...]:
        observations = self._probe() if self._probe is not None else _host_volumes()
        deduplicated: dict[str, VolumeObservation] = {}
        for observation in observations:
            if not isinstance(observation, VolumeObservation):
                raise StorageError("volume probe returned malformed evidence")
            deduplicated[observation.volume_id] = observation
            if self._history is not None:
                self._history.record(
                    StorageHistorySnapshot(
                        observation.volume_id,
                        observation.observed_at,
                        observation.capacity_bytes,
                        observation.used_bytes,
                        observation.free_bytes,
                        classify_storage_pressure(observation, self._policy),
                    )
                )
        self._last = tuple(deduplicated.values())
        return self._last

    def observe(self) -> tuple[VolumeObservation, ...]:
        return self.inspect()

    def pressure(self, volume_id: str, *, incoming_bytes: int = 0) -> StoragePressureState:
        observation = next((item for item in self._last if item.volume_id == volume_id), None)
        if observation is None:
            return StoragePressureState.UNKNOWN
        return classify_storage_pressure(observation, self._policy, incoming_bytes=incoming_bytes)


@dataclass(frozen=True, slots=True)
class StorageForecast:
    volume_id: str
    state: ForecastState
    free_change_bytes_per_day: float | None
    threshold_bytes: int | None
    threshold_crossing_at: datetime | None
    evidence_count: int
    confidence: float
    reason: str

    def __post_init__(self) -> None:
        _text(self.volume_id, "Forecast volume identity", maximum=512)
        if self.evidence_count < 0 or not 0 <= self.confidence <= 1:
            raise ValueError("Forecast evidence is malformed")


def forecast_storage_pressure(
    snapshots: Sequence[StorageHistorySnapshot],
    volume_id: str,
    *,
    threshold_bytes: int | None = None,
) -> StorageForecast:
    """Compute a transparent bounded trend from same-volume snapshots only."""

    samples = sorted(
        (item for item in snapshots if item.volume_id == volume_id and item.free_bytes is not None),
        key=lambda item: item.captured_at,
    )
    if len(samples) < 2:
        return StorageForecast(
            volume_id,
            ForecastState.INSUFFICIENT_EVIDENCE,
            None,
            threshold_bytes,
            None,
            len(samples),
            0.0,
            "at least two timestamped same-volume observations are required",
        )
    slopes: list[float] = []
    discontinuities = 0
    for previous, current in zip(samples, samples[1:], strict=False):
        seconds = (_utc(current.captured_at) - _utc(previous.captured_at)).total_seconds()
        if seconds <= 0 or previous.free_bytes is None or current.free_bytes is None:
            continue
        delta_per_day = (current.free_bytes - previous.free_bytes) * 86_400 / seconds
        slopes.append(delta_per_day)
        if delta_per_day > 0:
            discontinuities += 1
    if not slopes:
        return StorageForecast(
            volume_id,
            ForecastState.UNKNOWN,
            None,
            threshold_bytes,
            None,
            len(samples),
            0.0,
            "timestamps do not establish a usable trend",
        )
    ordered = sorted(slopes)
    rate = ordered[len(ordered) // 2]
    if abs(rate) < 1:
        state = ForecastState.STABLE
    elif rate > 0:
        state = ForecastState.GROWING
    else:
        state = ForecastState.DECLINING
    crossing: datetime | None = None
    if state is ForecastState.DECLINING and threshold_bytes is not None:
        current_free = samples[-1].free_bytes
        if current_free is not None and current_free > threshold_bytes:
            days = (current_free - threshold_bytes) / abs(rate)
            if days >= 0 and days <= 3650:
                crossing = _utc(samples[-1].captured_at) + timedelta(days=days)
    reason = (
        "reclamation discontinuity retained as evidence; median interval trend used"
        if discontinuities
        else "median of timestamped same-volume free-space intervals"
    )
    return StorageForecast(
        volume_id,
        state,
        rate,
        threshold_bytes,
        crossing,
        len(slopes) + 1,
        min(1.0, len(slopes) / 4),
        reason,
    )


@dataclass(frozen=True, slots=True)
class ResourcePlacementRequest:
    resource_id: str
    resource_type: StorageResourceType
    size_bytes: int | None
    placement_class: PlacementClass = PlacementClass.WARM
    performance_sensitive: bool = False
    compatible_volume_ids: tuple[str, ...] = ()
    required_headroom_bytes: int = 0
    current_volume_id: str | None = None
    application_managed: bool = False
    relocation_mechanism: str | None = None
    user_policy: str | None = None

    def __post_init__(self) -> None:
        _text(self.resource_id, "Resource placement identity", maximum=512)
        if not isinstance(self.resource_type, StorageResourceType):
            raise ValueError("Resource type is malformed")
        if self.size_bytes is not None and (
            type(self.size_bytes) is not int or self.size_bytes < 0
        ):
            raise ValueError("Resource size is malformed")
        if type(self.required_headroom_bytes) is not int or self.required_headroom_bytes < 0:
            raise ValueError("Resource headroom is malformed")
        if (
            type(self.performance_sensitive) is not bool
            or type(self.application_managed) is not bool
        ):
            raise ValueError("Resource placement flags are malformed")


@dataclass(frozen=True, slots=True)
class PlacementPlan:
    plan_id: UUID
    request: ResourcePlacementRequest
    status: PlacementStatus
    target_volume_id: str | None
    target_mount_point: str | None
    expected_free_after_bytes: int | None
    rationale: tuple[str, ...]
    evidence: tuple[str, ...]
    approved_target: bool = False

    @property
    def target_location(self) -> str | None:
        if self.target_mount_point is None:
            return None
        safe_id = "".join(
            character if character.isalnum() or character in "-_" else "_"
            for character in self.request.resource_id
        )
        return str(Path(self.target_mount_point) / "JARVIS" / "acquisitions" / safe_id)

    def as_dict(self) -> dict[str, object]:
        return {
            "plan_id": str(self.plan_id),
            "status": self.status.value,
            "target_volume_id": self.target_volume_id,
            "target_mount_point": self.target_mount_point,
            "target_location": self.target_location,
            "expected_free_after_bytes": self.expected_free_after_bytes,
            "rationale": list(self.rationale),
            "evidence": list(self.evidence),
            "approved_target": self.approved_target,
        }


class StoragePlanner:
    """Plan-only placement authority over observed volumes."""

    def __init__(
        self,
        inventory: StorageInventoryService | Iterable[VolumeObservation],
        *,
        resource_governor: ResourceGovernor | None = None,
    ) -> None:
        self._inventory = inventory
        self._resource_governor = resource_governor

    def _volumes(
        self, volumes: Iterable[VolumeObservation] | None
    ) -> tuple[VolumeObservation, ...]:
        if volumes is not None:
            return tuple(volumes)
        if isinstance(self._inventory, StorageInventoryService):
            return self._inventory.last or self._inventory.inspect()
        return tuple(self._inventory)

    def plan(
        self,
        request: ResourcePlacementRequest,
        *,
        volumes: Iterable[VolumeObservation] | None = None,
    ) -> PlacementPlan:
        if not isinstance(request, ResourcePlacementRequest):
            raise StorageError("placement request is malformed")
        if request.application_managed and not request.relocation_mechanism:
            return PlacementPlan(
                uuid4(),
                request,
                PlacementStatus.RELOCATION_UNSUPPORTED,
                None,
                None,
                None,
                ("application-managed storage has no authoritative relocation mechanism",),
                (),
            )
        observations = self._volumes(volumes)
        if request.size_bytes is None:
            return PlacementPlan(
                uuid4(),
                request,
                PlacementStatus.UNKNOWN_COMPATIBILITY,
                None,
                None,
                None,
                ("resource size is unknown",),
                (),
            )
        compatible = set(request.compatible_volume_ids)
        candidates: list[tuple[tuple[int, int, int], VolumeObservation, int]] = []
        unknown_compatibility = False
        for volume in observations:
            if compatible and volume.volume_id not in compatible:
                continue
            if volume.free_bytes is None:
                unknown_compatibility = True
                continue
            if volume.read_only is True or volume.network is True:
                continue
            required = request.size_bytes + request.required_headroom_bytes
            if volume.free_bytes < required:
                continue
            speed_class = volume.speed_class
            if request.performance_sensitive and speed_class is None:
                unknown_compatibility = True
                continue
            speed_value = speed_class.casefold() if speed_class is not None else ""
            if request.performance_sensitive and speed_value not in {
                "fast",
                "ssd",
                "nvme",
            }:
                continue
            placement_penalty = {
                PlacementClass.HOT: 0 if volume.speed_class in {"fast", "ssd", "nvme"} else 2,
                PlacementClass.WARM: 0,
                PlacementClass.COLD: 0 if volume.free_bytes >= required else 2,
                PlacementClass.ARCHIVE: 0 if volume.free_bytes >= required * 2 else 1,
            }[request.placement_class]
            current_penalty = 0 if volume.volume_id == request.current_volume_id else 1
            capacity_preference = -min(volume.free_bytes, 2**63 - 1)
            candidates.append(
                ((placement_penalty, current_penalty, capacity_preference), volume, required)
            )
        if not candidates:
            status = (
                PlacementStatus.UNKNOWN_COMPATIBILITY
                if unknown_compatibility
                else PlacementStatus.NO_COMPATIBLE_TARGET
            )
            return PlacementPlan(uuid4(), request, status, None, None, None, (status.value,), ())
        _, target, required = min(candidates, key=lambda item: item[0])
        status = (
            PlacementStatus.ALREADY_SUITABLE
            if target.volume_id == request.current_volume_id
            else PlacementStatus.RECOMMENDED
        )
        return PlacementPlan(
            uuid4(),
            request,
            status,
            target.volume_id,
            target.mount_points[0] if target.mount_points else None,
            target.free_bytes - required if target.free_bytes is not None else None,
            (
                f"{request.size_bytes} bytes plus "
                f"{request.required_headroom_bytes} bytes headroom fit",
                f"placement class={request.placement_class.value}",
            ),
            tuple(
                item
                for item in (
                    f"volume={target.volume_id}",
                    f"free_bytes={target.free_bytes}",
                    f"filesystem={target.filesystem or 'UNKNOWN'}",
                    f"speed_class={target.speed_class or 'UNKNOWN'}",
                )
            ),
        )

    def plan_acquisition(
        self,
        request: AcquisitionRequest,
        *,
        volumes: Iterable[VolumeObservation] | None = None,
        required_headroom_bytes: int = 0,
    ) -> PlacementPlan:
        resource_type = {
            ResourceType.MODEL: StorageResourceType.MODEL,
            ResourceType.DATA: StorageResourceType.DATASET,
            ResourceType.EXECUTABLE: StorageResourceType.GENERIC,
            ResourceType.DRIVER: StorageResourceType.GENERIC,
            ResourceType.PACKAGE: StorageResourceType.GENERIC,
            ResourceType.FILE: StorageResourceType.GENERIC,
            ResourceType.CAPABILITY: StorageResourceType.GENERIC,
        }.get(request.resource_type, StorageResourceType.GENERIC)
        return self.plan(
            ResourcePlacementRequest(
                request.resource_id,
                resource_type,
                request.installed_size_bytes or request.download_size_bytes,
                PlacementClass.HOT
                if resource_type is StorageResourceType.MODEL
                else PlacementClass.WARM,
                resource_type in {StorageResourceType.MODEL, StorageResourceType.VM_IMAGE},
                required_headroom_bytes=required_headroom_bytes,
                current_volume_id=request.target_volume_identity,
            ),
            volumes=volumes,
        )

    def bind_acquisition(
        self, request: AcquisitionRequest, plan: PlacementPlan
    ) -> AcquisitionRequest:
        if plan.status not in {PlacementStatus.RECOMMENDED, PlacementStatus.ALREADY_SUITABLE}:
            raise StalePlan(f"placement plan is {plan.status.value}")
        if request.target_location is not None and (
            request.target_volume_identity != plan.target_volume_id
            or Path(request.target_location).resolve(strict=False)
            != Path(plan.target_location or "").resolve(strict=False)
        ):
            raise StalePlan("approved acquisition target is materially different from the plan")
        return replace(
            request,
            target_location=plan.target_location,
            target_volume_identity=plan.target_volume_id,
        )

    def validate_acquisition_target(
        self, request: AcquisitionRequest, *, volumes: Iterable[VolumeObservation] | None = None
    ) -> PlacementStatus:
        if request.target_volume_identity is None:
            return PlacementStatus.UNKNOWN_COMPATIBILITY
        target = next(
            (
                item
                for item in self._volumes(volumes)
                if item.volume_id == request.target_volume_identity
            ),
            None,
        )
        required = request.download_size_bytes or request.installed_size_bytes
        if target is None or target.free_bytes is None or target.read_only is True:
            return PlacementStatus.STALE_PLAN
        if required is not None and target.free_bytes < required:
            return PlacementStatus.STALE_PLAN
        return PlacementStatus.ALREADY_SUITABLE


@dataclass(frozen=True, slots=True)
class FileClassification:
    category: FileCategory
    owner: FileOwnership = FileOwnership.UNKNOWN
    confidence: str = "unknown"
    regenerable: bool | None = None
    active_reference: bool | None = None
    last_use_at: datetime | None = None
    cleanup_mechanism: str | None = None
    consequence: str | None = None
    recovery_strategy: str | None = None
    retention: RetentionState = RetentionState.UNKNOWN
    intentional_copy: bool = False
    evidence: tuple[str, ...] = ()
    relocation_mechanism: str | None = None

    def __post_init__(self) -> None:
        if not isinstance(self.category, FileCategory) or not isinstance(self.owner, FileOwnership):
            raise ValueError("file classification enums are malformed")
        if type(self.intentional_copy) is not bool:
            raise ValueError("intentional-copy state is malformed")
        if self.active_reference not in {None, True, False}:
            raise ValueError("active-reference state is malformed")

    @property
    def known(self) -> bool:
        return self.category is not FileCategory.UNKNOWN and self.owner is not FileOwnership.UNKNOWN


class FileClassifier:
    """Conservative classification helper; caller-supplied facts remain explicit."""

    def __init__(
        self, *, protected_roots: Iterable[Path] = (), jarvis_roots: Iterable[Path] = ()
    ) -> None:
        self._protected_roots = tuple(_safe_root(item) for item in protected_roots)
        self._jarvis_roots = tuple(_safe_root(item) for item in jarvis_roots)

    def classify(
        self,
        path: Path,
        *,
        owner: FileOwnership = FileOwnership.UNKNOWN,
        category: FileCategory = FileCategory.UNKNOWN,
        **evidence: object,
    ) -> FileClassification:
        canonical = _canonical(path)
        if any(_under(canonical, root) for root in self._protected_roots):
            active_reference = evidence.get("active_reference")
            last_use_at = evidence.get("last_use_at")
            raw_evidence = evidence.get("evidence")
            return FileClassification(
                FileCategory.SYSTEM_CRITICAL,
                FileOwnership.SYSTEM,
                "trusted_path",
                False,
                active_reference if isinstance(active_reference, bool) else None,
                last_use_at if isinstance(last_use_at, datetime) else None,
                None,
                "system or recovery consequence unknown",
                "protected system recovery",
                RetentionState.NEEDED_FOR_EVIDENCE,
                evidence=(
                    cast(tuple[str, ...], raw_evidence) if isinstance(raw_evidence, tuple) else ()
                ),
            )
        if (
            any(_under(canonical, root) for root in self._jarvis_roots)
            and category is FileCategory.UNKNOWN
        ):
            category = FileCategory.JARVIS_OWNED
            owner = FileOwnership.JARVIS
        return FileClassification(
            category,
            owner,
            str(evidence.get("confidence", "explicit")),
            cast(bool | None, evidence.get("regenerable")),
            cast(bool | None, evidence.get("active_reference")),
            cast(datetime | None, evidence.get("last_use_at")),
            cast(str | None, evidence.get("cleanup_mechanism")),
            cast(str | None, evidence.get("consequence")),
            cast(str | None, evidence.get("recovery_strategy")),
            cast(RetentionState, evidence.get("retention", RetentionState.UNKNOWN)),
            bool(evidence.get("intentional_copy", False)),
            cast(tuple[str, ...], evidence.get("evidence", ())),
            cast(str | None, evidence.get("relocation_mechanism")),
        )


@dataclass(frozen=True, slots=True)
class CleanupCandidate:
    path: Path
    size_bytes: int
    classification: FileClassification
    state: CleanupState
    reason: str
    expected_reclaimed_bytes: int
    evidence: tuple[str, ...] = ()

    @property
    def eligible(self) -> bool:
        return self.state is CleanupState.ELIGIBLE


class CleanupClassifier:
    """Turns trusted ownership/retention facts into non-authoritative candidates."""

    _SAFE_CATEGORIES = frozenset(
        {FileCategory.CACHE, FileCategory.TEMPORARY, FileCategory.JARVIS_OWNED}
    )

    def candidate(self, path: Path, classification: FileClassification) -> CleanupCandidate:
        size = path.stat().st_size if path.is_file() else 0
        if classification.category is FileCategory.MODEL_STORAGE:
            return CleanupCandidate(
                path,
                size,
                classification,
                CleanupState.DELEGATE,
                "installed model removal belongs to model retirement",
                0,
            )
        if classification.category in {FileCategory.SYSTEM_CRITICAL, FileCategory.USER_DATA}:
            return CleanupCandidate(
                path, size, classification, CleanupState.PROTECTED, "protected data", 0
            )
        if classification.intentional_copy:
            return CleanupCandidate(
                path, size, classification, CleanupState.PROTECTED, "intentional copy", 0
            )
        if (
            classification.category not in self._SAFE_CATEGORIES
            or classification.owner is FileOwnership.UNKNOWN
            or classification.active_reference is not False
            or classification.cleanup_mechanism is None
            or classification.recovery_strategy is None
            or classification.retention is not RetentionState.SAFE_TO_REMOVE
        ):
            return CleanupCandidate(
                path,
                size,
                classification,
                CleanupState.UNKNOWN,
                "ownership, activity, mechanism, recovery, or retention evidence is incomplete",
                0,
            )
        return CleanupCandidate(
            path,
            size,
            classification,
            CleanupState.ELIGIBLE,
            "trusted ownership, inactive state, cleanup mechanism, recovery, and "
            "retention are established",
            size,
            classification.evidence,
        )

    def downloads_state(
        self,
        *,
        active: bool | None,
        age_days: float | None,
        installer_already_installed: bool = False,
        exact_duplicate: bool = False,
        trusted_movable: bool = False,
    ) -> DownloadState:
        if active is True:
            return DownloadState.ACTIVE
        if active is None or age_days is None or age_days < 0:
            return DownloadState.UNKNOWN
        if installer_already_installed:
            return DownloadState.INSTALLER_ALREADY_INSTALLED
        if exact_duplicate:
            return DownloadState.DUPLICATE
        if trusted_movable:
            return DownloadState.MOVABLE
        if age_days <= 7:
            return DownloadState.RECENT
        if age_days > 30:
            return DownloadState.STALE
        return DownloadState.ARCHIVABLE


@dataclass(frozen=True, slots=True)
class DuplicateFileEvidence:
    path: Path
    size_bytes: int
    content_hash: str
    volume_id: str
    physical_file_id: str
    classification: FileClassification
    active_reference: bool | None
    reparse: bool
    cloud_placeholder: bool | None = None

    @property
    def verified(self) -> bool:
        return not self.reparse and self.cloud_placeholder is not True and bool(self.content_hash)


@dataclass(frozen=True, slots=True)
class DuplicateGroup:
    content_hash: str
    size_bytes: int
    files: tuple[DuplicateFileEvidence, ...]
    exact: bool
    reclaimable_bytes: int
    safe_reclaimable_bytes: int


class DuplicateDetector:
    """Full-hash duplicate detector that never follows a reparse point."""

    def __init__(
        self,
        *,
        resource_governor: ResourceGovernor | None = None,
        max_files: int = 100_000,
        max_bytes: int = 2 * 1024**4,
    ) -> None:
        if (
            type(max_files) is not int
            or max_files < 1
            or type(max_bytes) is not int
            or max_bytes < 1
        ):
            raise ValueError("duplicate scan bounds are malformed")
        self._governor = resource_governor
        self.max_files = max_files
        self.max_bytes = max_bytes

    def scan(
        self,
        roots: Iterable[Path],
        *,
        classifier: Callable[[Path], FileClassification] | None = None,
        active_reference: Callable[[Path], bool | None] | None = None,
        intentional_copies: Iterable[Path] = (),
    ) -> tuple[DuplicateGroup, ...]:
        reservation = None
        if self._governor is not None:
            admission = self._governor.reserve(
                "storage.duplicate_scan",
                ResourcePriority.BACKGROUND,
                ResourceBudget(disk_bytes=self.max_bytes, duration_seconds=600),
            )
            if not admission.allowed:
                raise StorageDeferred(admission.reason)
            reservation = admission.reservation_id
        intentional = {str(_canonical(item)) for item in intentional_copies}
        records: list[DuplicateFileEvidence] = []
        seen_files = 0
        seen_bytes = 0
        try:
            for root_value in roots:
                root = _canonical(root_value)
                if not root.is_dir():
                    continue
                for path in _walk_files(root):
                    if seen_files >= self.max_files:
                        break
                    try:
                        before = os.stat(path, follow_symlinks=False)
                        if not stat.S_ISREG(before.st_mode):
                            continue
                        size = int(before.st_size)
                        if seen_bytes + size > self.max_bytes:
                            continue
                        if _cloud_placeholder(before):
                            continue
                        digest = _sha256_path(path)
                        after = os.stat(path, follow_symlinks=False)
                        if (before.st_size, before.st_mtime_ns) != (
                            after.st_size,
                            after.st_mtime_ns,
                        ):
                            continue
                        classification = (
                            classifier(path)
                            if classifier is not None
                            else FileClassification(FileCategory.UNKNOWN)
                        )
                        if str(path) in intentional:
                            classification = replace(classification, intentional_copy=True)
                        records.append(
                            DuplicateFileEvidence(
                                path,
                                size,
                                digest,
                                _device_identity(path),
                                f"{before.st_dev}:{before.st_ino}",
                                classification,
                                active_reference(path) if active_reference else None,
                                _has_reparse_ancestor(path),
                                False,
                            )
                        )
                        seen_files += 1
                        seen_bytes += size
                    except (OSError, ValueError):
                        continue
            grouped: dict[tuple[int, str], list[DuplicateFileEvidence]] = {}
            for record in records:
                grouped.setdefault((record.size_bytes, record.content_hash), []).append(record)
            result: list[DuplicateGroup] = []
            for (size, digest), files in grouped.items():
                if len(files) < 2:
                    continue
                physical: dict[tuple[str, str], DuplicateFileEvidence] = {}
                for item in files:
                    physical.setdefault((item.volume_id, item.physical_file_id), item)
                physical_values = tuple(physical.values())
                reclaimable = max(0, len(physical_values) - 1) * size
                eligible = [
                    item
                    for item in physical_values[1:]
                    if item.classification.category
                    in {FileCategory.JARVIS_OWNED, FileCategory.CACHE, FileCategory.TEMPORARY}
                    and item.classification.active_reference is False
                    and not item.classification.intentional_copy
                ]
                result.append(
                    DuplicateGroup(
                        digest,
                        size,
                        tuple(files),
                        all(item.verified for item in files),
                        reclaimable,
                        len(eligible) * size,
                    )
                )
            return tuple(result)
        finally:
            if reservation is not None and self._governor is not None:
                self._governor.release(reservation, ReservationReleaseReason.COMPLETE)


@dataclass(frozen=True, slots=True)
class FileIdentity:
    volume_id: str
    physical_file_id: str
    size_bytes: int
    content_hash: str
    reparse: bool
    is_directory: bool
    modified_ns: int

    def as_dict(self) -> dict[str, object]:
        return {
            "volume_id": self.volume_id,
            "physical_file_id": self.physical_file_id,
            "size_bytes": self.size_bytes,
            "content_hash": self.content_hash,
            "reparse": self.reparse,
            "is_directory": self.is_directory,
            "modified_ns": self.modified_ns,
        }


@dataclass(frozen=True, slots=True)
class FilesystemObservation:
    """Separate existence, object type, identity, and content observations."""

    path: Path | None
    state: FilesystemObservationState
    exists: bool | None
    object_type: str
    identity: str | None
    content_hash: str | None
    reason: str

    def as_dict(self) -> dict[str, object]:
        return {
            "path": str(self.path) if self.path is not None else None,
            "state": self.state.value,
            "exists": self.exists,
            "object_type": self.object_type,
            "identity": self.identity,
            "content_hash": self.content_hash,
            "reason": self.reason,
        }


@dataclass(frozen=True, slots=True)
class MutationItem:
    source: Path
    destination: Path | None
    expected: FileIdentity
    classification: FileClassification
    recovery_path: Path | None = None
    state: MutationItemState = MutationItemState.NOT_STARTED
    detail: str = ""

    def as_dict(self, *, include_runtime: bool = True) -> dict[str, object]:
        payload: dict[str, object] = {
            "source": str(self.source),
            "destination": str(self.destination) if self.destination else None,
            "expected": self.expected.as_dict(),
            "classification": _classification_dict(self.classification),
            "recovery_path": str(self.recovery_path) if self.recovery_path else None,
        }
        if include_runtime:
            payload.update({"state": self.state.value, "detail": self.detail[:2_000]})
        return payload


@dataclass(frozen=True, slots=True)
class MutationManifest:
    plan_id: UUID
    task_id: UUID
    operation: MutationOperation
    trusted_root: Path
    items: tuple[MutationItem, ...]
    volume_ids: tuple[str, ...]
    max_affected_bytes: int
    exclusions: tuple[str, ...]
    authority_requirement: str
    reversibility: Reversibility
    recovery_strategy: str
    created_at: datetime
    phase: MutationPhase = MutationPhase.EFFECT
    approval_binding: str | None = None
    state: MutationState = MutationState.PLANNED
    detail: str = ""

    @property
    def expected_bytes(self) -> int:
        return sum(item.expected.size_bytes for item in self.items)

    @property
    def fingerprint(self) -> str:
        payload = self.as_dict(include_integrity=False, include_runtime=False)
        return hashlib.sha256(_json_bytes(payload)).hexdigest()

    def as_dict(
        self, *, include_integrity: bool = True, include_runtime: bool = True
    ) -> dict[str, object]:
        payload: dict[str, object] = {
            "schema": "jarvis-file-mutation-manifest-2",
            "plan_id": str(self.plan_id),
            "task_id": str(self.task_id),
            "operation": self.operation.value,
            "phase": self.phase.value,
            "trusted_root": str(self.trusted_root),
            "items": [item.as_dict(include_runtime=include_runtime) for item in self.items],
            "volume_ids": list(self.volume_ids),
            "max_affected_bytes": self.max_affected_bytes,
            "exclusions": list(self.exclusions),
            "authority_requirement": self.authority_requirement,
            "reversibility": self.reversibility.value,
            "recovery_strategy": self.recovery_strategy,
            "created_at": _utc(self.created_at).isoformat(),
        }
        if include_runtime:
            payload.update(
                {
                    "approval_binding": self.approval_binding,
                    "state": self.state.value,
                    "detail": self.detail[:2_000],
                }
            )
        if include_integrity:
            payload["integrity"] = hashlib.sha256(_json_bytes(payload)).hexdigest()
        return payload


class MutationManifestStore:
    """Durable, integrity-checked manifest store for restart reconciliation."""

    def __init__(self, root: Path) -> None:
        self.root = _safe_root(root)
        self.manifest_root = _safe_root(self.root / "manifests")

    def path_for(self, plan_id: UUID) -> Path:
        return self.manifest_root / f"{plan_id}.json"

    def save(self, manifest: MutationManifest) -> None:
        path = self.path_for(manifest.plan_id)
        _atomic_json_write(path, manifest.as_dict())

    def load(self, plan_id: UUID) -> MutationManifest:
        path = self.path_for(plan_id)
        try:
            raw = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, UnicodeError, ValueError) as error:
            raise ManifestIntegrityError("mutation manifest is unreadable") from error
        return _manifest_from_dict(raw)

    def pending(self) -> tuple[MutationManifest, ...]:
        manifests: list[MutationManifest] = []
        for path in sorted(self.manifest_root.glob("*.json")):
            try:
                value = _manifest_from_dict(json.loads(path.read_text(encoding="utf-8")))
            except (OSError, UnicodeError, ValueError, ManifestIntegrityError):
                continue
            if value.state in {
                MutationState.IN_PROGRESS,
                MutationState.PARTIAL,
                MutationState.UNKNOWN_OUTCOME,
            }:
                manifests.append(value)
        return tuple(manifests)

    def find_planned_copy(
        self, task_id: UUID, source: Path, destination: Path
    ) -> MutationManifest | None:
        """Return the durable exact copy plan for one task and path pair."""

        for path in sorted(self.manifest_root.glob("*.json")):
            try:
                value = _manifest_from_dict(json.loads(path.read_text(encoding="utf-8")))
            except (OSError, UnicodeError, ValueError, ManifestIntegrityError):
                continue
            if (
                value.task_id == task_id
                and value.operation is MutationOperation.COPY
                and value.state is MutationState.PLANNED
                and len(value.items) == 1
                and value.items[0].source == source
                and value.items[0].destination == destination
            ):
                return value
        return None


@dataclass(frozen=True, slots=True)
class MutationResult:
    manifest: MutationManifest
    before_free_bytes: int | None
    after_free_bytes: int | None
    actual_reclaimed_bytes: int
    actual_moved_bytes: int
    errors: tuple[str, ...] = ()
    unresolved: tuple[str, ...] = ()

    @property
    def state(self) -> MutationState:
        return self.manifest.state

    @property
    def success(self) -> bool:
        return self.state in {MutationState.COMPLETED, MutationState.RESTORED}


class FileSteward:
    """The single trusted local file-effect path for R3B."""

    _TOOL_ID = "storage.file_steward"

    def __init__(
        self,
        root: Path,
        *,
        recovery_root: Path | None = None,
        manifest_store: MutationManifestStore | None = None,
        permission_broker: PermissionBroker | None = None,
        host_bridge: HostBridge | None = None,
        resource_governor: ResourceGovernor | None = None,
        fault_injector: Callable[[str, MutationItem], None] | None = None,
        live_protection_probe: Callable[[Path], FileClassification] | None = None,
        relocation_authority: Callable[[Path, Path, FileClassification], bool] | None = None,
        register_tool: bool = True,
    ) -> None:
        self.root = _safe_root(root)
        self.recovery_root = _safe_root(recovery_root or self.root / ".recovery")
        if not _under(self.recovery_root, self.root):
            raise MutationDenied("recovery root must remain inside the trusted root")
        self.manifests = manifest_store or MutationManifestStore(self.root / ".mutation-state")
        self.permission_broker = permission_broker
        self.host_bridge = host_bridge
        self.resource_governor = resource_governor
        self.fault_injector = fault_injector
        self.live_protection_probe = live_protection_probe
        self.relocation_authority = relocation_authority
        self._identity = object()
        if (
            register_tool
            and permission_broker is not None
            and not permission_broker.registration_sealed
        ):
            permission_broker.register_tool(
                self._TOOL_ID,
                self._identity,
                frozenset({Permission.FILESYSTEM_WRITE}),
            )

    def inspect(self, path: Path) -> FileIdentity:
        canonical = self._owned(path)
        return _file_identity(canonical)

    def plan_copy(
        self,
        source: Path,
        destination: Path,
        *,
        task_id: UUID | None = None,
        classification: FileClassification | None = None,
        max_affected_bytes: int | None = None,
    ) -> MutationManifest:
        return self._plan(
            MutationOperation.COPY,
            source,
            destination,
            task_id=task_id,
            classification=classification,
            max_affected_bytes=max_affected_bytes,
        )

    def plan_move(
        self,
        source: Path,
        destination: Path,
        *,
        task_id: UUID | None = None,
        classification: FileClassification | None = None,
        max_affected_bytes: int | None = None,
    ) -> MutationManifest:
        if (
            classification is not None
            and classification.category is FileCategory.APPLICATION_MANAGED
            and (not classification.relocation_mechanism or self.relocation_authority is None)
        ):
            raise MutationDenied(
                "application-managed data requires an implemented relocation authority"
            )
        return self._plan(
            MutationOperation.MOVE,
            source,
            destination,
            task_id=task_id,
            classification=classification,
            max_affected_bytes=max_affected_bytes,
        )

    def plan_rename(
        self,
        source: Path,
        destination: Path,
        *,
        task_id: UUID | None = None,
        classification: FileClassification | None = None,
    ) -> MutationManifest:
        return self._plan(
            MutationOperation.RENAME,
            source,
            destination,
            task_id=task_id,
            classification=classification,
        )

    def plan_delete(
        self,
        source: Path,
        *,
        task_id: UUID | None = None,
        classification: FileClassification | None = None,
        max_affected_bytes: int | None = None,
    ) -> MutationManifest:
        if classification is None or classification.category is FileCategory.UNKNOWN:
            raise MutationDenied("unknown ownership cannot become delete authority")
        if classification.category is FileCategory.MODEL_STORAGE:
            raise MutationDenied("DELEGATE_TO_MODEL_RETIREMENT")
        if classification.category in {
            FileCategory.SYSTEM_CRITICAL,
            FileCategory.USER_DATA,
            FileCategory.APPLICATION_MANAGED,
            FileCategory.MOVABLE_USER_DATA,
            FileCategory.ARCHIVE,
        }:
            raise MutationDenied(
                "protected or application-managed data cannot be generically deleted"
            )
        if (
            classification.active_reference is not False
            or classification.retention is not RetentionState.SAFE_TO_REMOVE
        ):
            raise MutationDenied("active or unretained data cannot be deleted")
        return self._plan(
            MutationOperation.SAFE_DELETE,
            source,
            None,
            task_id=task_id,
            classification=classification,
            max_affected_bytes=max_affected_bytes,
        )

    def plan_batch(
        self,
        operation: MutationOperation,
        items: Sequence[tuple[Path, Path | None, FileClassification | None]],
        *,
        task_id: UUID | None = None,
        max_affected_bytes: int | None = None,
    ) -> MutationManifest:
        """Create one exact-scope manifest for a bounded set of files."""

        if operation is MutationOperation.RESTORE or not items or len(items) > 256:
            raise MutationDenied("batch operation is unsupported or unbounded")
        planned: list[MutationItem] = []
        for source, destination, classification in items:
            item_classification = classification or FileClassification(FileCategory.UNKNOWN)
            if operation is MutationOperation.SAFE_DELETE:
                if classification is None or item_classification.category in {
                    FileCategory.UNKNOWN,
                    FileCategory.MODEL_STORAGE,
                    FileCategory.SYSTEM_CRITICAL,
                    FileCategory.USER_DATA,
                    FileCategory.APPLICATION_MANAGED,
                    FileCategory.MOVABLE_USER_DATA,
                    FileCategory.ARCHIVE,
                }:
                    raise MutationDenied("batch delete contains a protected or unknown item")
                if (
                    item_classification.active_reference is not False
                    or item_classification.retention is not RetentionState.SAFE_TO_REMOVE
                ):
                    raise MutationDenied("batch delete contains an active or unretained item")
            elif operation is not MutationOperation.COPY and (
                item_classification.category is FileCategory.UNKNOWN
            ):
                raise MutationDenied("batch mutation contains unknown ownership")
            elif (
                operation in {MutationOperation.MOVE, MutationOperation.RENAME}
                and item_classification.category is FileCategory.APPLICATION_MANAGED
                and (
                    not item_classification.relocation_mechanism
                    or self.relocation_authority is None
                )
            ):
                raise MutationDenied(
                    "application-managed data requires an implemented relocation authority"
                )
            owned_source = self._owned(source)
            expected = _file_identity(owned_source)
            if expected.is_directory:
                raise MutationDenied("batch mutation contains a directory")
            owned_destination = (
                self._owned(destination, allow_missing=True) if destination else None
            )
            if owned_destination is not None and owned_destination.exists():
                raise MutationConflict("batch destination already exists")
            recovery = (
                self.recovery_root / f"{uuid4().hex}-{len(planned)}.recovery"
                if operation is MutationOperation.SAFE_DELETE
                else None
            )
            planned.append(
                MutationItem(
                    owned_source,
                    owned_destination,
                    expected,
                    item_classification,
                    recovery,
                )
            )
        expected_bytes = sum(item.expected.size_bytes for item in planned)
        maximum = expected_bytes if max_affected_bytes is None else max_affected_bytes
        if type(maximum) is not int or maximum < expected_bytes:
            raise MutationDenied("batch byte scope is invalid")
        plan_id = uuid4()
        volume_ids = {
            volume_id
            for item in planned
            for volume_id in (
                item.expected.volume_id,
                _device_identity(item.destination.parent)
                if item.destination
                else item.expected.volume_id,
            )
        }
        manifest = MutationManifest(
            plan_id,
            task_id or uuid4(),
            operation,
            self.root,
            tuple(planned),
            tuple(sorted(volume_ids)),
            maximum,
            (str(self.recovery_root),),
            "PermissionBroker -> Protected Host Bridge/trusted file operation",
            (
                Reversibility.FULLY_REVERSIBLE
                if operation is MutationOperation.SAFE_DELETE
                else (
                    Reversibility.PARTIALLY_REVERSIBLE
                    if operation is MutationOperation.COPY
                    else Reversibility.IRREVERSIBLE
                )
            ),
            "bounded per-file recovery staging"
            if operation is MutationOperation.SAFE_DELETE
            else "verified exact-scope effects",
            datetime.now(UTC),
        )
        self.manifests.save(manifest)
        return manifest

    def _plan(
        self,
        operation: MutationOperation,
        source: Path,
        destination: Path | None,
        *,
        task_id: UUID | None,
        classification: FileClassification | None,
        max_affected_bytes: int | None = None,
    ) -> MutationManifest:
        owned_source = self._owned(source)
        expected = _file_identity(owned_source)
        if expected.is_directory:
            raise MutationDenied("R3B file primitives operate on files, not arbitrary directories")
        owned_destination = self._owned(destination, allow_missing=True) if destination else None
        if owned_destination is not None and owned_destination.exists():
            raise MutationConflict("destination already exists")
        item_classification = classification or FileClassification(FileCategory.UNKNOWN)
        if (
            item_classification.category is FileCategory.UNKNOWN
            and operation is not MutationOperation.COPY
        ):
            raise MutationDenied("unknown ownership cannot authorize a mutation")
        plan_id = uuid4()
        recovery = (
            self.recovery_root / f"{plan_id.hex}.recovery"
            if operation is MutationOperation.SAFE_DELETE
            else None
        )
        item = MutationItem(
            owned_source, owned_destination, expected, item_classification, recovery
        )
        maximum = expected.size_bytes if max_affected_bytes is None else max_affected_bytes
        if type(maximum) is not int or maximum < expected.size_bytes:
            raise MutationDenied("mutation byte scope is invalid")
        manifest = MutationManifest(
            plan_id,
            task_id or uuid4(),
            operation,
            self.root,
            (item,),
            tuple(
                sorted(
                    {
                        expected.volume_id,
                        _device_identity(owned_destination.parent)
                        if owned_destination
                        else expected.volume_id,
                    }
                )
            ),
            maximum,
            (str(self.recovery_root),),
            "PermissionBroker -> Protected Host Bridge/trusted file operation",
            (
                Reversibility.FULLY_REVERSIBLE
                if operation is MutationOperation.SAFE_DELETE
                else (
                    Reversibility.PARTIALLY_REVERSIBLE
                    if operation is MutationOperation.COPY
                    else Reversibility.IRREVERSIBLE
                )
            ),
            "recovery staging inside the trusted JARVIS root"
            if recovery
            else "verified destination and source evidence",
            datetime.now(UTC),
        )
        self.manifests.save(manifest)
        return manifest

    def execute(
        self, manifest: MutationManifest | UUID, *, user_id: str | None = None
    ) -> MutationResult:
        try:
            asyncio.get_running_loop()
        except RuntimeError:
            return asyncio.run(self.execute_async(manifest, user_id=user_id))
        raise RuntimeError("use execute_async from an active event loop")

    async def execute_async(
        self,
        manifest: MutationManifest | UUID,
        *,
        user_id: str | None = None,
    ) -> MutationResult:
        current = (
            self.manifests.load(manifest.plan_id)
            if isinstance(manifest, MutationManifest)
            else self.manifests.load(manifest)
        )
        if current.state is not MutationState.PLANNED:
            raise MutationUnknownOutcome("only a fresh planned manifest may execute")
        if self.permission_broker is None or self.host_bridge is None:
            denial_reason = (
                "PermissionBroker is unavailable"
                if self.permission_broker is None
                else "HostBridge is required for file effects"
            )
            updated = replace(current, state=MutationState.DENIED, detail=denial_reason)
            self.manifests.save(updated)
            raise MutationDenied(denial_reason)
        receipt = await self._authorize(current, user_id=user_id)
        execution_reason = await self.permission_broker.begin_execution(receipt)
        if execution_reason is not None:
            raise MutationDenied(execution_reason.value)
        bound = replace(
            current, approval_binding=f"{receipt.argument_fingerprint}:{receipt.action_fingerprint}"
        )
        self.manifests.save(bound)
        try:
            result = self._perform(bound, receipt)
        except (StalePlan, MutationConflict, MutationDenied):
            latest = self.manifests.load(bound.plan_id)
            await self.permission_broker.record_execution_outcome(
                receipt, self._broker_outcome(latest)
            )
            raise
        except BaseException as error:
            latest = self.manifests.load(bound.plan_id)
            if latest.state in {MutationState.PLANNED, MutationState.IN_PROGRESS}:
                unknown = replace(
                    latest, state=MutationState.UNKNOWN_OUTCOME, detail=type(error).__name__
                )
                self.manifests.save(unknown)
                latest = unknown
            await self.permission_broker.record_execution_outcome(
                receipt, self._broker_outcome(latest)
            )
            raise MutationUnknownOutcome("file effect lacks trusted terminal evidence") from error
        await self.permission_broker.record_execution_outcome(
            receipt,
            "effect_confirmed" if result.success else result.state.value,
        )
        return result

    async def execute_with_receipt_async(
        self,
        manifest: MutationManifest | UUID,
        receipt: AuthorizationReceipt,
        *,
        normalized_arguments: Mapping[str, object] | None = None,
    ) -> MutationResult:
        """Execute with the receipt already begun by the Tool boundary.

        The normal ``execute_async`` API remains the standalone storage path.
        This application-composition path deliberately performs no second
        broker authorization or ``begin_execution`` call; the enclosing
        registered tool owns that lifecycle and records the final outcome.
        """

        current = (
            self.manifests.load(manifest.plan_id)
            if isinstance(manifest, MutationManifest)
            else self.manifests.load(manifest)
        )
        if current.state is not MutationState.PLANNED:
            raise MutationUnknownOutcome("only a fresh planned manifest may execute")
        if self.permission_broker is None or self.host_bridge is None:
            raise MutationDenied("receipt-backed HostBridge is required for file effects")
        bound = replace(
            current, approval_binding=f"{receipt.argument_fingerprint}:{receipt.action_fingerprint}"
        )
        self.manifests.save(bound)
        try:
            result = self._perform(bound, receipt, normalized_arguments=normalized_arguments)
        except (StalePlan, MutationConflict, MutationDenied):
            raise
        except BaseException as error:
            latest = self.manifests.load(bound.plan_id)
            if latest.state in {MutationState.PLANNED, MutationState.IN_PROGRESS}:
                self.manifests.save(
                    replace(
                        latest, state=MutationState.UNKNOWN_OUTCOME, detail=type(error).__name__
                    )
                )
            raise MutationUnknownOutcome("file effect lacks trusted terminal evidence") from error
        return result

    async def _authorize(
        self, manifest: MutationManifest, *, user_id: str | None
    ) -> AuthorizationReceipt:
        broker = self.permission_broker
        if broker is None:
            raise MutationDenied("PermissionBroker is required for file effects")
        descriptor = self._descriptor(manifest)
        result = await broker.authorize(
            tool_id=self._TOOL_ID,
            tool_identity=self._identity,
            declared_permissions=frozenset({Permission.FILESYSTEM_WRITE}),
            task_id=manifest.task_id,
            user_id=user_id,
            descriptor=descriptor,
            normalized_arguments=self._authorization_arguments(manifest),
        )
        if not result.authorized or result.receipt is None:
            if result.approval_requests:
                raise MutationApprovalRequired(result.approval_requests)
            raise MutationDenied(result.reason.value)
        return result.receipt

    def _descriptor(self, manifest: MutationManifest) -> ActionDescriptor:
        scope = PermissionScope(paths=(str(self.root),), task_id=manifest.task_id)
        operation = self._effective_operation(manifest)
        return build_host_bridge_action_descriptor(
            action=f"storage.file.{operation.value}",
            operation=self._bridge_operation(operation),
            resource=self._bridge_resource(manifest),
            scope=str(self.root),
            risk=self._risk(manifest),
            permissions=(PermissionRequest(Permission.FILESYSTEM_WRITE, scope),),
            safety_class=self._safety_class(manifest),
        )

    def _authorization_arguments(self, manifest: MutationManifest) -> dict[str, object]:
        return {
            "plan_id": str(manifest.plan_id),
            "phase": manifest.phase.value,
            "operation": self._effective_operation(manifest).value,
            "manifest_fingerprint": manifest.fingerprint,
            "trusted_root": str(self.root),
            "items": tuple(
                {
                    "source": str(item.source),
                    "destination": str(item.destination) if item.destination else None,
                    "recovery_path": str(item.recovery_path) if item.recovery_path else None,
                    "expected": item.expected.as_dict(),
                }
                for item in manifest.items
            ),
            "max_affected_bytes": manifest.max_affected_bytes,
        }

    @staticmethod
    def _effective_operation(manifest: MutationManifest) -> MutationOperation:
        return (
            MutationOperation.RESTORE
            if manifest.phase is MutationPhase.RESTORE
            else manifest.operation
        )

    @staticmethod
    def _bridge_operation(operation: MutationOperation) -> HostBridgeOperation:
        return {
            MutationOperation.COPY: HostBridgeOperation.FILE_COPY,
            MutationOperation.MOVE: HostBridgeOperation.FILE_MOVE,
            MutationOperation.RENAME: HostBridgeOperation.FILE_RENAME,
            MutationOperation.SAFE_DELETE: HostBridgeOperation.FILE_DELETE,
            MutationOperation.RESTORE: HostBridgeOperation.FILE_RESTORE,
        }[operation]

    @staticmethod
    def _risk(manifest: MutationManifest) -> str:
        return (
            Risk.HIGH.value
            if FileSteward._effective_operation(manifest)
            in {MutationOperation.SAFE_DELETE, MutationOperation.MOVE}
            else Risk.MEDIUM.value
        )

    @staticmethod
    def _safety_class(manifest: MutationManifest) -> SafetyClass:
        return (
            SafetyClass.BULK_DELETION
            if FileSteward._effective_operation(manifest) is MutationOperation.SAFE_DELETE
            else SafetyClass.ORDINARY
        )

    @staticmethod
    def _bridge_resource(manifest: MutationManifest) -> str:
        return f"manifest:{manifest.fingerprint}"

    @staticmethod
    def _approval_identity(receipt: AuthorizationReceipt) -> str | None:
        identities = {
            item.approval_identity
            for item in receipt.approval_requests
            if item.approval_identity is not None
        }
        identities.update(item.identity_id for item in receipt.remembered_grants)
        return sorted(identities)[0] if identities else None

    @staticmethod
    def _broker_outcome(manifest: MutationManifest) -> str:
        states = {item.state for item in manifest.items}
        if states & {
            MutationItemState.EFFECT_MAY_HAVE_STARTED,
            MutationItemState.UNKNOWN_OUTCOME,
            MutationItemState.INTENT_PERSISTED,
            MutationItemState.RESTORATION_IN_PROGRESS,
        }:
            return "unknown_outcome"
        if states & {MutationItemState.VERIFIED, MutationItemState.RESTORED}:
            return (
                "effect_confirmed"
                if manifest.state in {MutationState.COMPLETED, MutationState.RESTORED}
                else "effect_partially_completed"
            )
        return "not_executed"

    def _bridge_check(
        self,
        manifest: MutationManifest,
        receipt: AuthorizationReceipt,
        *,
        normalized_arguments: Mapping[str, object] | None = None,
    ) -> None:
        if self.host_bridge is None or self.permission_broker is None:
            raise MutationDenied("receipt-backed HostBridge is required for file effects")
        operation = self._effective_operation(manifest)
        request = HostBridgeRequest(
            request_id=uuid4(),
            task_id=manifest.task_id,
            instance_id=self.host_bridge.instance_id,
            operation=self._bridge_operation(operation),
            resource=self._bridge_resource(manifest),
            scope=str(self.root),
            risk=self._risk(manifest),
            expires_at=receipt.expires_at,
            tool_id=self._TOOL_ID,
            action=f"storage.file.{operation.value}",
            argument_fingerprint=receipt.argument_fingerprint,
            action_fingerprint=receipt.action_fingerprint,
            approval_identity=self._approval_identity(receipt),
            safety_class=self._safety_class(manifest),
        )
        result = self.host_bridge.authorize_with_receipt(
            request,
            receipt=receipt,
            broker=self.permission_broker,
            normalized_arguments=(
                normalized_arguments
                if normalized_arguments is not None
                else self._authorization_arguments(manifest)
            ),
            expected_instance_id=self.host_bridge.instance_id,
        )
        if not result.allowed:
            raise MutationDenied(result.reason)

    def _perform(
        self,
        manifest: MutationManifest,
        receipt: AuthorizationReceipt,
        *,
        normalized_arguments: Mapping[str, object] | None = None,
    ) -> MutationResult:
        before = _free_bytes(manifest.items[0].source)
        current = replace(
            manifest,
            phase=MutationPhase.EFFECT,
            state=MutationState.IN_PROGRESS,
            detail="preflight passed; effect in progress",
        )
        self.manifests.save(current)
        item_index = -1
        effect_started = False
        try:
            if manifest.expected_bytes > manifest.max_affected_bytes:
                raise MutationDenied("maximum byte scope exceeded")
            self._bridge_check(current, receipt, normalized_arguments=normalized_arguments)
            for item_index, item in enumerate(current.items):
                current = replace(
                    current,
                    items=tuple(
                        replace(
                            value,
                            state=(
                                MutationItemState.INTENT_PERSISTED
                                if index == item_index
                                else value.state
                            ),
                            detail=(
                                "effect intent persisted" if index == item_index else value.detail
                            ),
                        )
                        for index, value in enumerate(current.items)
                    ),
                )
                self.manifests.save(current)
                self._revalidate_item(item, current.operation)
                current = replace(
                    current,
                    items=tuple(
                        replace(
                            value,
                            state=(
                                MutationItemState.EFFECT_MAY_HAVE_STARTED
                                if index == item_index
                                else value.state
                            ),
                            detail=(
                                "effect boundary entered" if index == item_index else value.detail
                            ),
                        )
                        for index, value in enumerate(current.items)
                    ),
                )
                self.manifests.save(current)
                effect_started = True
                if current.operation is MutationOperation.COPY:
                    self._copy(item, current)
                elif current.operation is MutationOperation.MOVE:
                    self._move(item, current)
                elif current.operation is MutationOperation.RENAME:
                    self._rename(item, current)
                elif current.operation is MutationOperation.SAFE_DELETE:
                    self._safe_delete(item, current)
                else:
                    raise MutationDenied("restore is executed through restore(), not a raw plan")
                current = replace(
                    current,
                    items=tuple(
                        replace(
                            value,
                            state=(
                                MutationItemState.VERIFIED if index == item_index else value.state
                            ),
                            detail=(
                                "effect independently verified"
                                if index == item_index
                                else value.detail
                            ),
                        )
                        for index, value in enumerate(current.items)
                    ),
                )
                self.manifests.save(current)
                effect_started = False
            completed = replace(
                current, state=MutationState.COMPLETED, detail="all item effects verified"
            )
            self.manifests.save(completed)
            after = _free_bytes(current.items[0].source)
            reclaimed = (
                max(0, (after or 0) - (before or 0))
                if current.operation is MutationOperation.SAFE_DELETE
                else 0
            )
            moved = (
                current.expected_bytes
                if current.operation in {MutationOperation.MOVE, MutationOperation.RENAME}
                else 0
            )
            return MutationResult(completed, before, after, reclaimed, moved)
        except StalePlan as error:
            self._record_effect_failure(current, item_index, effect_started, error)
            raise
        except MutationConflict as error:
            self._record_effect_failure(current, item_index, effect_started, error)
            raise
        except MutationDenied as error:
            self._record_effect_failure(current, item_index, effect_started, error)
            raise
        except BaseException as error:
            self._record_effect_failure(current, item_index, True, error)
            raise

    def _record_effect_failure(
        self,
        manifest: MutationManifest,
        item_index: int,
        effect_started: bool,
        error: BaseException,
    ) -> MutationManifest:
        items = list(manifest.items)
        if effect_started and 0 <= item_index < len(items) and isinstance(error, StalePlan):
            item = items[item_index]
            if item.destination is not None and not item.destination.exists():
                effect_started = False
        if 0 <= item_index < len(items):
            items[item_index] = replace(
                items[item_index],
                state=(
                    MutationItemState.UNKNOWN_OUTCOME
                    if effect_started
                    else MutationItemState.FAILED_BEFORE_EFFECT
                ),
                detail=(
                    "effect outcome is unresolved"
                    if effect_started
                    else f"failed before effect: {type(error).__name__}"
                ),
            )
        states = {item.state for item in items}
        if item_index < 0:
            state = MutationState.DENIED
        elif states & {
            MutationItemState.UNKNOWN_OUTCOME,
            MutationItemState.EFFECT_MAY_HAVE_STARTED,
            MutationItemState.INTENT_PERSISTED,
        }:
            state = MutationState.UNKNOWN_OUTCOME
        elif MutationItemState.VERIFIED in states:
            state = MutationState.PARTIAL
        elif isinstance(error, StalePlan):
            state = MutationState.STALE_PLAN
        elif isinstance(error, MutationConflict):
            state = MutationState.CONFLICT
        else:
            state = MutationState.DENIED
        updated = replace(
            manifest,
            items=tuple(items),
            state=state,
            detail=(
                "partial effect retained for reconciliation"
                if state is MutationState.PARTIAL
                else type(error).__name__
            ),
        )
        self.manifests.save(updated)
        return updated

    def _revalidate_item(self, item: MutationItem, operation: MutationOperation) -> None:
        current = _file_identity(item.source)
        if current != item.expected:
            raise StalePlan("source file identity, content, or reparse state changed")
        if operation is not MutationOperation.SAFE_DELETE and item.destination is None:
            raise StalePlan("destination is missing from an effect plan")
        if item.destination is not None:
            destination = self._owned(item.destination, allow_missing=True)
            if destination.exists():
                raise MutationConflict("destination appeared after planning")
            if _has_reparse_ancestor(destination.parent):
                raise StalePlan("destination parent became a reparse path")
        if operation in {
            MutationOperation.MOVE,
            MutationOperation.RENAME,
            MutationOperation.SAFE_DELETE,
        }:
            if _under(item.source, self.recovery_root):
                raise MutationDenied("protected recovery artifact cannot be generic cleanup")
            classification = item.classification
            if self.live_protection_probe is not None:
                classification = self.live_protection_probe(item.source)
                if type(classification) is not FileClassification:
                    raise MutationDenied("live protection evidence is malformed")
            if classification.category is FileCategory.MODEL_STORAGE:
                raise MutationDenied("DELEGATE_TO_MODEL_RETIREMENT")
            if classification.category is FileCategory.APPLICATION_MANAGED:
                if (
                    operation in {MutationOperation.MOVE, MutationOperation.RENAME}
                    and self.relocation_authority is not None
                    and self.relocation_authority(
                        item.source, item.destination or item.source, classification
                    )
                ):
                    pass
                else:
                    raise MutationDenied(
                        "application-managed relocation is unsupported by an owning authority"
                    )
            if classification.active_reference is not False:
                raise MutationDenied("active-reference protection blocked the effect")
            if (
                operation is MutationOperation.SAFE_DELETE
                and classification.retention is not RetentionState.SAFE_TO_REMOVE
            ):
                raise MutationDenied("live retention evidence blocked the effect")
        elif item.classification.active_reference is True:
            raise MutationDenied("active-reference protection blocked the effect")

    @staticmethod
    def _link_without_overwrite(source: Path, destination: Path) -> None:
        try:
            os.link(source, destination)
        except FileExistsError as error:
            raise MutationConflict(
                "destination appeared during no-overwrite finalization"
            ) from error
        except OSError as error:
            if destination.exists():
                raise MutationConflict(
                    "destination appeared during no-overwrite finalization"
                ) from error
            raise MutationUnknownOutcome(
                "trusted no-overwrite finalization is unavailable"
            ) from error

    @staticmethod
    def _unlink_expected_source(source: Path, expected: FileIdentity) -> None:
        try:
            if _file_identity(source) != expected:
                raise StalePlan("source changed before final disposition")
            source.unlink()
        except FileNotFoundError as error:
            raise MutationUnknownOutcome("source disposition is unresolved") from error
        if source.exists():
            raise MutationUnknownOutcome("source disposition is unresolved")

    def _copy(self, item: MutationItem, manifest: MutationManifest) -> None:
        assert item.destination is not None
        destination = item.destination
        destination.parent.mkdir(parents=True, exist_ok=True)
        if destination.exists():
            raise MutationConflict("destination appeared during copy")
        temporary = destination.with_name(f".{destination.name}.{manifest.plan_id.hex}.partial")
        try:
            if temporary.exists():
                raise MutationConflict("copy staging path already exists")
            shutil.copy2(item.source, temporary)
            if self.fault_injector is not None:
                self.fault_injector("after_copy_before_finalize", item)
            if _file_identity(temporary).content_hash != item.expected.content_hash:
                raise StalePlan("copied bytes failed hash verification")
            destination = self._owned(destination, allow_missing=True)
            if destination.exists() or _has_reparse_ancestor(destination.parent):
                raise MutationConflict("destination appeared before finalize")
            self._link_without_overwrite(temporary, destination)
            temporary.unlink()
            if _file_identity(destination).content_hash != item.expected.content_hash:
                raise StalePlan("finalized copy failed hash verification")
        finally:
            if temporary.exists() and self._is_safe_owned(temporary):
                temporary.unlink()

    def _move(self, item: MutationItem, manifest: MutationManifest) -> None:
        assert item.destination is not None
        destination = item.destination
        destination.parent.mkdir(parents=True, exist_ok=True)
        if destination.exists():
            raise MutationConflict("destination appeared during move")
        same_volume = _device_identity(item.source) == _device_identity(destination.parent)
        if same_volume:
            self._link_without_overwrite(item.source, destination)
            if self.fault_injector is not None:
                self.fault_injector("after_move_finalize", item)
            if (
                not destination.is_file()
                or _file_identity(destination).content_hash != item.expected.content_hash
            ):
                raise MutationUnknownOutcome("renamed destination is not verified")
            self._unlink_expected_source(item.source, item.expected)
            return
        temporary = destination.with_name(f".{destination.name}.{manifest.plan_id.hex}.partial")
        try:
            if temporary.exists():
                raise MutationConflict("move staging path already exists")
            shutil.copy2(item.source, temporary)
            if self.fault_injector is not None:
                self.fault_injector("after_cross_volume_copy", item)
            if _file_identity(temporary).content_hash != item.expected.content_hash:
                raise MutationUnknownOutcome("cross-volume staging hash failed")
            destination = self._owned(destination, allow_missing=True)
            if destination.exists() or _has_reparse_ancestor(destination.parent):
                raise MutationConflict("destination appeared before cross-volume finalize")
            self._link_without_overwrite(temporary, destination)
            temporary.unlink()
            if _file_identity(destination).content_hash != item.expected.content_hash:
                raise MutationUnknownOutcome("cross-volume destination hash failed")
            self._unlink_expected_source(item.source, item.expected)
        finally:
            if temporary.exists() and self._is_safe_owned(temporary):
                temporary.unlink()

    def _rename(self, item: MutationItem, manifest: MutationManifest) -> None:
        assert item.destination is not None
        if _device_identity(item.source) != _device_identity(item.destination.parent):
            raise MutationDenied("rename cannot cross volumes")
        self._link_without_overwrite(item.source, item.destination)
        if self.fault_injector is not None:
            self.fault_injector("after_rename_finalize", item)
        if (
            not item.destination.is_file()
            or _file_identity(item.destination).content_hash != item.expected.content_hash
        ):
            raise MutationUnknownOutcome("renamed file is not verified")
        self._unlink_expected_source(item.source, item.expected)

    def _safe_delete(self, item: MutationItem, manifest: MutationManifest) -> None:
        if item.recovery_path is None:
            raise MutationDenied("safe delete has no recovery staging path")
        recovery = self._owned(item.recovery_path, allow_missing=True)
        if recovery.exists():
            raise MutationConflict("recovery staging path already exists")
        recovery.parent.mkdir(parents=True, exist_ok=True)
        self._link_without_overwrite(item.source, recovery)
        if self.fault_injector is not None:
            self.fault_injector("after_delete_stage", item)
        if (
            recovery.is_file() is not True
            or _file_identity(recovery).content_hash != item.expected.content_hash
        ):
            raise MutationUnknownOutcome("recovery staging content is not verified")
        self._unlink_expected_source(item.source, item.expected)

    def restore(
        self, manifest: MutationManifest | UUID, *, user_id: str | None = None
    ) -> MutationResult:
        try:
            asyncio.get_running_loop()
        except RuntimeError:
            return asyncio.run(self.restore_async(manifest, user_id=user_id))
        raise RuntimeError("use restore_async from an active event loop")

    async def restore_async(
        self, manifest: MutationManifest | UUID, *, user_id: str | None = None
    ) -> MutationResult:
        current = (
            self.manifests.load(manifest.plan_id)
            if isinstance(manifest, MutationManifest)
            else self.manifests.load(manifest)
        )
        if (
            current.operation is not MutationOperation.SAFE_DELETE
            or current.state is not MutationState.COMPLETED
            or current.phase is not MutationPhase.EFFECT
        ):
            raise MutationDenied("only a completed safe-delete manifest can be restored")
        if self.permission_broker is None or self.host_bridge is None:
            raise MutationDenied("PermissionBroker and HostBridge are required for restore")
        restore_manifest = replace(current, phase=MutationPhase.RESTORE)
        receipt = await self._authorize(restore_manifest, user_id=user_id)
        reason = await self.permission_broker.begin_execution(receipt)
        if reason is not None:
            raise MutationDenied(reason.value)
        active = replace(
            restore_manifest,
            state=MutationState.IN_PROGRESS,
            detail="restore intent persisted; effect in progress",
        )
        self.manifests.save(active)
        current_active = active
        item_index = -1
        effect_started = False
        before = _free_bytes(active.items[0].source)
        try:
            self._bridge_check(current_active, receipt)
            for item_index, item in enumerate(current_active.items):
                current_active = replace(
                    current_active,
                    items=tuple(
                        replace(
                            value,
                            state=(
                                MutationItemState.RESTORATION_IN_PROGRESS
                                if index == item_index
                                else value.state
                            ),
                            detail=(
                                "restore intent persisted" if index == item_index else value.detail
                            ),
                        )
                        for index, value in enumerate(current_active.items)
                    ),
                )
                self.manifests.save(current_active)
                self._prepare_restore_item(item)
                effect_started = True
                self._restore_item(item)
                current_active = replace(
                    current_active,
                    items=tuple(
                        replace(
                            value,
                            state=(
                                MutationItemState.RESTORED if index == item_index else value.state
                            ),
                            detail=(
                                "original bytes and recovery disposition verified"
                                if index == item_index
                                else value.detail
                            ),
                        )
                        for index, value in enumerate(current_active.items)
                    ),
                )
                self.manifests.save(current_active)
                effect_started = False
            restored = replace(
                current_active, state=MutationState.RESTORED, detail="all restore items verified"
            )
            self.manifests.save(restored)
            await self.permission_broker.record_execution_outcome(receipt, "effect_confirmed")
            return MutationResult(restored, before, _free_bytes(restored.items[0].source), 0, 0)
        except MutationConflict as error:
            latest = self._record_restore_failure(current_active, item_index, effect_started, error)
            await self.permission_broker.record_execution_outcome(
                receipt, self._broker_outcome(latest)
            )
            raise
        except MutationDenied as error:
            latest = self._record_restore_failure(current_active, item_index, effect_started, error)
            await self.permission_broker.record_execution_outcome(
                receipt, self._broker_outcome(latest)
            )
            raise
        except BaseException as error:
            latest = self._record_restore_failure(current_active, item_index, True, error)
            await self.permission_broker.record_execution_outcome(
                receipt, self._broker_outcome(latest)
            )
            if isinstance(error, MutationUnknownOutcome):
                raise
            raise MutationUnknownOutcome(
                "restore effect lacks trusted terminal evidence"
            ) from error

    def _prepare_restore_item(self, item: MutationItem) -> None:
        if item.recovery_path is None:
            raise MutationUnknownOutcome("recovery bytes are unavailable")
        recovery = self._owned(item.recovery_path, allow_missing=True)
        source = self._owned(item.source, allow_missing=True)
        if not recovery.is_file():
            raise MutationUnknownOutcome("recovery bytes are unavailable")
        if source.exists():
            raise MutationConflict("original path already exists")
        if _file_identity(recovery).content_hash != item.expected.content_hash:
            raise MutationUnknownOutcome("recovery staging was altered")
        if _has_reparse_ancestor(source.parent):
            raise StalePlan("restore destination parent became a reparse path")

    def _restore_item(self, item: MutationItem) -> None:
        assert item.recovery_path is not None
        recovery = self._owned(item.recovery_path)
        source = self._owned(item.source, allow_missing=True)
        if self.fault_injector is not None:
            self.fault_injector("before_restore_finalize", item)
        self._link_without_overwrite(recovery, source)
        if _file_identity(source).content_hash != item.expected.content_hash:
            raise MutationUnknownOutcome("restored bytes failed verification")
        recovery.unlink()
        if recovery.exists():
            raise MutationUnknownOutcome("recovery disposition is unresolved")

    def _record_restore_failure(
        self,
        manifest: MutationManifest,
        item_index: int,
        effect_started: bool,
        error: BaseException,
    ) -> MutationManifest:
        items = list(manifest.items)
        if 0 <= item_index < len(items):
            items[item_index] = replace(
                items[item_index],
                state=(
                    MutationItemState.UNKNOWN_OUTCOME
                    if effect_started or isinstance(error, MutationUnknownOutcome)
                    else MutationItemState.FAILED_BEFORE_EFFECT
                ),
                detail=(
                    "restore outcome is unresolved"
                    if effect_started or isinstance(error, MutationUnknownOutcome)
                    else f"restore failed before effect: {type(error).__name__}"
                ),
            )
        states = {item.state for item in items}
        if item_index < 0:
            state = MutationState.DENIED
        elif states & {
            MutationItemState.UNKNOWN_OUTCOME,
            MutationItemState.RESTORATION_IN_PROGRESS,
        }:
            state = MutationState.UNKNOWN_OUTCOME
        elif MutationItemState.RESTORED in states:
            state = MutationState.PARTIAL
        elif isinstance(error, MutationConflict):
            state = MutationState.CONFLICT
        elif isinstance(error, MutationDenied):
            state = MutationState.DENIED
        else:
            state = MutationState.UNKNOWN_OUTCOME
        updated = replace(
            manifest,
            items=tuple(items),
            state=state,
            detail=(
                "partial restore retained for reconciliation"
                if state is MutationState.PARTIAL
                else type(error).__name__
            ),
        )
        self.manifests.save(updated)
        return updated

    def reconcile(self, manifest: MutationManifest | UUID) -> MutationResult:
        current = (
            self.manifests.load(manifest.plan_id)
            if isinstance(manifest, MutationManifest)
            else self.manifests.load(manifest)
        )
        if current.state not in {
            MutationState.IN_PROGRESS,
            MutationState.PARTIAL,
            MutationState.UNKNOWN_OUTCOME,
        }:
            return MutationResult(current, None, None, 0, 0)
        if current.phase is MutationPhase.RESTORE:
            return self._reconcile_restore(current)
        return self._reconcile_effect(current)

    def _reconcile_effect(self, current: MutationManifest) -> MutationResult:
        dispositions: list[MutationItem] = []
        observations: list[str] = []
        for item in current.items:
            source_observation = _observe_path(item.source)
            destination_observation = _observe_path(
                item.destination, expected_hash=item.expected.content_hash
            )
            recovery_observation = _observe_path(
                item.recovery_path, expected_hash=item.expected.content_hash
            )
            source_absent = source_observation.state is FilesystemObservationState.ABSENT
            destination_verified = (
                destination_observation.state is FilesystemObservationState.PRESENT_VERIFIED
            )
            recovery_verified = (
                recovery_observation.state is FilesystemObservationState.PRESENT_VERIFIED
            )
            if current.operation is MutationOperation.COPY:
                verified = destination_verified
            elif current.operation in {MutationOperation.MOVE, MutationOperation.RENAME}:
                verified = destination_verified and source_absent
            elif current.operation is MutationOperation.SAFE_DELETE:
                verified = recovery_verified and source_absent
            else:
                verified = False
            if verified:
                disposition = replace(
                    item,
                    state=MutationItemState.VERIFIED,
                    detail="effect independently verified during reconciliation",
                )
            elif item.state is MutationItemState.FAILED_BEFORE_EFFECT:
                disposition = item
            else:
                disposition = replace(
                    item,
                    state=MutationItemState.UNKNOWN_OUTCOME,
                    detail="machine evidence does not prove the item terminal state",
                )
            dispositions.append(disposition)
            observations.append(
                _observation_text("source", source_observation)
                + ";"
                + _observation_text("destination", destination_observation)
                + ";"
                + _observation_text("recovery", recovery_observation)
            )
        states = {item.state for item in dispositions}
        if states and states <= {MutationItemState.VERIFIED}:
            aggregate = MutationState.COMPLETED
            detail = "all item effects reconciled from machine evidence"
        elif states & {
            MutationItemState.UNKNOWN_OUTCOME,
            MutationItemState.EFFECT_MAY_HAVE_STARTED,
            MutationItemState.INTENT_PERSISTED,
        }:
            aggregate = MutationState.UNKNOWN_OUTCOME
            detail = "item effect outcome remains unresolved after reconciliation"
        elif MutationItemState.VERIFIED in states:
            aggregate = MutationState.PARTIAL
            detail = "partial item effects retained after reconciliation"
        else:
            aggregate = current.state
            detail = "known pre-effect item failures retained after reconciliation"
        updated = replace(
            current,
            items=tuple(dispositions),
            state=aggregate,
            detail=detail,
        )
        if updated != current:
            self.manifests.save(updated)
        unresolved = tuple(observations) if aggregate is not MutationState.COMPLETED else ()
        moved = (
            current.expected_bytes
            if aggregate is MutationState.COMPLETED
            and current.operation in {MutationOperation.MOVE, MutationOperation.RENAME}
            else 0
        )
        return MutationResult(updated, None, None, 0, moved, unresolved=unresolved)

    def _reconcile_restore(self, current: MutationManifest) -> MutationResult:
        dispositions: list[MutationItem] = []
        observations: list[str] = []
        for item in current.items:
            source_observation = _observe_path(
                item.source, expected_hash=item.expected.content_hash
            )
            recovery_observation = _observe_path(item.recovery_path)
            verified = (
                source_observation.state is FilesystemObservationState.PRESENT_VERIFIED
                and recovery_observation.state is FilesystemObservationState.ABSENT
            )
            if verified:
                disposition = replace(
                    item,
                    state=MutationItemState.RESTORED,
                    detail="restore bytes and recovery disposition verified during reconciliation",
                )
            elif item.state is MutationItemState.FAILED_BEFORE_EFFECT:
                disposition = item
            else:
                disposition = replace(
                    item,
                    state=MutationItemState.UNKNOWN_OUTCOME,
                    detail="restore evidence is incomplete or conflicting",
                )
            dispositions.append(disposition)
            observations.append(
                _observation_text("source", source_observation)
                + ";"
                + _observation_text("recovery", recovery_observation)
            )
        states = {item.state for item in dispositions}
        if states and states <= {MutationItemState.RESTORED}:
            aggregate = MutationState.RESTORED
            detail = "all restore items reconciled from machine evidence"
        elif states & {
            MutationItemState.UNKNOWN_OUTCOME,
            MutationItemState.RESTORATION_IN_PROGRESS,
        }:
            aggregate = MutationState.UNKNOWN_OUTCOME
            detail = "restore outcome remains unresolved after reconciliation"
        elif MutationItemState.RESTORED in states:
            aggregate = MutationState.PARTIAL
            detail = "partial restore retained after reconciliation"
        else:
            aggregate = current.state
            detail = "known restore conflicts retained after reconciliation"
        updated = replace(current, items=tuple(dispositions), state=aggregate, detail=detail)
        if updated != current:
            self.manifests.save(updated)
        unresolved = tuple(observations) if aggregate is not MutationState.RESTORED else ()
        return MutationResult(updated, None, None, 0, 0, unresolved=unresolved)

    def reconcile_pending(self) -> tuple[MutationResult, ...]:
        return tuple(self.reconcile(item) for item in self.manifests.pending())

    def _owned(self, path: Path | None, *, allow_missing: bool = False) -> Path:
        if path is None:
            raise MutationDenied("path is required")
        canonical = _canonical(path)
        if not _under(canonical, self.root):
            raise MutationDenied("path is outside the trusted file scope")
        if not allow_missing and not canonical.exists():
            raise MutationDenied("source path is unavailable")
        return canonical

    def _is_safe_owned(self, path: Path) -> bool:
        try:
            return _under(_canonical(path), self.root)
        except MutationError:
            return False


@dataclass(frozen=True, slots=True)
class EmergencyRecoveryPlan:
    system_volume_id: str
    target_bytes: int
    selected: tuple[CleanupCandidate, ...]
    expected_reclaimable_bytes: int
    shortfall_bytes: int
    status: str
    rationale: tuple[str, ...]


class EmergencyRecoveryPlanner:
    """Bounded safe-category planning; it never executes or broadens scope."""

    def plan(
        self,
        system_volume: VolumeObservation,
        candidates: Iterable[CleanupCandidate],
        *,
        target_bytes: int,
    ) -> EmergencyRecoveryPlan:
        if target_bytes < 0:
            raise ValueError("emergency target must be non-negative")
        if system_volume.system_volume is not True:
            raise MutationDenied("emergency recovery requires a trusted system-volume observation")
        eligible = sorted(
            (
                item
                for item in candidates
                if item.eligible
                and item.classification.owner is FileOwnership.JARVIS
                and item.classification.category
                in {FileCategory.JARVIS_OWNED, FileCategory.CACHE, FileCategory.TEMPORARY}
            ),
            key=lambda item: (-item.expected_reclaimed_bytes, str(item.path)),
        )
        selected: list[CleanupCandidate] = []
        total = 0
        for item in eligible:
            if total >= target_bytes:
                break
            selected.append(item)
            total += item.expected_reclaimed_bytes
        return EmergencyRecoveryPlan(
            system_volume.volume_id,
            target_bytes,
            tuple(selected),
            total,
            max(0, target_bytes - total),
            "TARGET_MET" if total >= target_bytes else "SAFE_SHORTFALL",
            (
                "only trusted JARVIS-owned or known safe cache/temp candidates were selected",
                "personal data, protected evidence, active resources, and unknowns were excluded",
            ),
        )


def _classification_dict(value: FileClassification) -> dict[str, object]:
    return {
        "category": value.category.value,
        "owner": value.owner.value,
        "confidence": value.confidence,
        "regenerable": value.regenerable,
        "active_reference": value.active_reference,
        "last_use_at": _utc(value.last_use_at).isoformat() if value.last_use_at else None,
        "cleanup_mechanism": value.cleanup_mechanism,
        "consequence": value.consequence,
        "recovery_strategy": value.recovery_strategy,
        "retention": value.retention.value,
        "intentional_copy": value.intentional_copy,
        "evidence": list(value.evidence),
        "relocation_mechanism": value.relocation_mechanism,
    }


def _classification_from_dict(raw: object) -> FileClassification:
    if not isinstance(raw, dict):
        raise ManifestIntegrityError("manifest classification is malformed")
    try:
        last_use = raw.get("last_use_at")
        return FileClassification(
            FileCategory(str(raw["category"])),
            FileOwnership(str(raw["owner"])),
            str(raw.get("confidence", "unknown")),
            cast(bool | None, raw.get("regenerable")),
            cast(bool | None, raw.get("active_reference")),
            datetime.fromisoformat(str(last_use)) if last_use else None,
            cast(str | None, raw.get("cleanup_mechanism")),
            cast(str | None, raw.get("consequence")),
            cast(str | None, raw.get("recovery_strategy")),
            RetentionState(str(raw.get("retention", RetentionState.UNKNOWN.value))),
            bool(raw.get("intentional_copy", False)),
            tuple(str(item) for item in raw.get("evidence", [])),
            cast(str | None, raw.get("relocation_mechanism")),
        )
    except (KeyError, TypeError, ValueError) as error:
        raise ManifestIntegrityError("manifest classification is malformed") from error


def _identity_from_dict(raw: object) -> FileIdentity:
    if not isinstance(raw, dict):
        raise ManifestIntegrityError("manifest identity is malformed")
    try:
        return FileIdentity(
            str(raw["volume_id"]),
            str(raw["physical_file_id"]),
            int(raw["size_bytes"]),
            str(raw["content_hash"]),
            bool(raw["reparse"]),
            bool(raw["is_directory"]),
            int(raw["modified_ns"]),
        )
    except (KeyError, TypeError, ValueError) as error:
        raise ManifestIntegrityError("manifest identity is malformed") from error


def _manifest_from_dict(raw: object) -> MutationManifest:
    if not isinstance(raw, dict) or raw.get("schema") not in {
        "jarvis-file-mutation-manifest-1",
        "jarvis-file-mutation-manifest-2",
    }:
        raise ManifestIntegrityError("manifest schema is unsupported")
    legacy = raw.get("schema") == "jarvis-file-mutation-manifest-1"
    unsigned = dict(raw)
    integrity = unsigned.pop("integrity", None)
    if type(integrity) is not str or hashlib.sha256(_json_bytes(unsigned)).hexdigest() != integrity:
        raise ManifestIntegrityError("manifest integrity validation failed")
    try:
        items_raw = raw["items"]
        if not isinstance(items_raw, list) or not items_raw:
            raise ManifestIntegrityError("manifest items are malformed")
        items: list[MutationItem] = []
        for item in items_raw:
            if not isinstance(item, dict):
                raise ManifestIntegrityError("manifest item is malformed")
            destination = item.get("destination")
            recovery = item.get("recovery_path")
            items.append(
                MutationItem(
                    Path(str(item["source"])),
                    Path(str(destination)) if destination else None,
                    _identity_from_dict(item["expected"]),
                    _classification_from_dict(item["classification"]),
                    Path(str(recovery)) if recovery else None,
                    (
                        MutationItemState.UNKNOWN_OUTCOME
                        if legacy
                        and str(raw.get("state"))
                        in {
                            MutationState.IN_PROGRESS.value,
                            MutationState.COMPLETED.value,
                            MutationState.RESTORED.value,
                            MutationState.UNKNOWN_OUTCOME.value,
                        }
                        else MutationItemState(str(item.get("state", "not_started")))
                    ),
                    (
                        "legacy manifest lacks per-item durable evidence"
                        if legacy
                        and str(raw.get("state"))
                        in {
                            MutationState.IN_PROGRESS.value,
                            MutationState.COMPLETED.value,
                            MutationState.RESTORED.value,
                            MutationState.UNKNOWN_OUTCOME.value,
                        }
                        else str(item.get("detail", ""))
                    ),
                )
            )
        raw_state = MutationState(str(raw["state"]))
        if legacy and raw_state in {
            MutationState.IN_PROGRESS,
            MutationState.COMPLETED,
            MutationState.RESTORED,
            MutationState.UNKNOWN_OUTCOME,
        }:
            raw_state = MutationState.UNKNOWN_OUTCOME
        return MutationManifest(
            UUID(str(raw["plan_id"])),
            UUID(str(raw["task_id"])),
            MutationOperation(str(raw["operation"])),
            Path(str(raw["trusted_root"])),
            tuple(items),
            tuple(str(item) for item in raw["volume_ids"]),
            int(raw["max_affected_bytes"]),
            tuple(str(item) for item in raw["exclusions"]),
            str(raw["authority_requirement"]),
            Reversibility(str(raw["reversibility"])),
            str(raw["recovery_strategy"]),
            datetime.fromisoformat(str(raw["created_at"])),
            MutationPhase(str(raw.get("phase", MutationPhase.EFFECT.value))),
            cast(str | None, raw.get("approval_binding")),
            raw_state,
            str(raw.get("detail", "")),
        )
    except ManifestIntegrityError:
        raise
    except (KeyError, TypeError, ValueError) as error:
        raise ManifestIntegrityError("manifest fields are malformed") from error


def _json_bytes(value: object) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode(
        "utf-8"
    )


def _atomic_json_write(path: Path, value: object) -> None:
    payload = _json_bytes(value) + b"\n"
    fd, temporary = tempfile.mkstemp(prefix=f".{path.name}.", dir=path.parent)
    try:
        with os.fdopen(fd, "wb") as handle:
            handle.write(payload)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, path)
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)


def _sha256_path(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        while chunk := handle.read(1024 * 1024):
            digest.update(chunk)
    return digest.hexdigest()


def _observe_path(path: Path | None, *, expected_hash: str | None = None) -> FilesystemObservation:
    """Observe one path without collapsing unsafe or unreadable state to absence."""

    if path is None:
        return FilesystemObservation(
            None,
            FilesystemObservationState.UNKNOWN,
            None,
            "path_field_missing",
            None,
            None,
            "manifest path field is missing",
        )
    candidate = path.expanduser().absolute()
    try:
        if _has_reparse_ancestor(candidate):
            return FilesystemObservation(
                candidate,
                FilesystemObservationState.UNSAFE_REPARSE,
                None,
                "reparse_path",
                None,
                None,
                "path or an ancestor is a symlink or junction",
            )
        info = os.lstat(candidate)
    except FileNotFoundError:
        return FilesystemObservation(
            candidate,
            FilesystemObservationState.ABSENT,
            False,
            "missing",
            None,
            None,
            "path is absent",
        )
    except OSError as error:
        return FilesystemObservation(
            candidate,
            FilesystemObservationState.UNKNOWN,
            None,
            "unreadable",
            None,
            None,
            f"path observation failed: {type(error).__name__}",
        )

    identity = f"{info.st_dev}:{info.st_ino}"
    if stat.S_ISLNK(info.st_mode) or _has_reparse_ancestor(candidate):
        return FilesystemObservation(
            candidate,
            FilesystemObservationState.UNSAFE_REPARSE,
            True,
            "reparse_path",
            identity,
            None,
            "path is a symlink or junction",
        )
    if stat.S_ISDIR(info.st_mode):
        return FilesystemObservation(
            candidate,
            FilesystemObservationState.PRESENT_UNEXPECTED,
            True,
            "directory",
            identity,
            None,
            "directory is not an expected regular file",
        )
    if not stat.S_ISREG(info.st_mode):
        return FilesystemObservation(
            candidate,
            FilesystemObservationState.PRESENT_UNEXPECTED,
            True,
            "special",
            identity,
            None,
            "object is not an expected regular file",
        )
    try:
        content_hash = _sha256_path(candidate)
    except OSError as error:
        return FilesystemObservation(
            candidate,
            FilesystemObservationState.UNKNOWN,
            True,
            "regular_file",
            identity,
            None,
            f"regular file content is unreadable: {type(error).__name__}",
        )
    if expected_hash is not None and content_hash != expected_hash:
        return FilesystemObservation(
            candidate,
            FilesystemObservationState.PRESENT_UNEXPECTED,
            True,
            "regular_file",
            identity,
            content_hash,
            "regular file content does not match the expected hash",
        )
    return FilesystemObservation(
        candidate,
        FilesystemObservationState.PRESENT_VERIFIED,
        True,
        "regular_file",
        identity,
        content_hash,
        "regular file content was read successfully",
    )


def _observation_text(label: str, observation: FilesystemObservation) -> str:
    return (
        f"{label}_state={observation.state.value};"
        f"{label}_exists={observation.exists};"
        f"{label}_object_type={observation.object_type};"
        f"{label}_hash={observation.content_hash};"
        f"{label}_reason={observation.reason}"
    )


def _hash_if_file(path: Path | None) -> str | None:
    observation = _observe_path(path)
    return (
        observation.content_hash
        if observation.state is FilesystemObservationState.PRESENT_VERIFIED
        else None
    )


def _device_identity(path: Path) -> str:
    try:
        value = os.stat(path, follow_symlinks=False).st_dev
    except OSError:
        value = os.stat(path.parent, follow_symlinks=False).st_dev
    return f"device:{value}"


def _file_identity(path: Path) -> FileIdentity:
    canonical = path if path.is_absolute() else path.absolute()
    if _has_reparse_ancestor(canonical):
        raise StalePlan("file identity contains a reparse point")
    try:
        info = os.stat(canonical, follow_symlinks=False)
    except OSError as error:
        raise StalePlan("file is unavailable") from error
    is_directory = stat.S_ISDIR(info.st_mode)
    digest = "" if is_directory else _sha256_path(canonical)
    return FileIdentity(
        _device_identity(canonical),
        f"{info.st_dev}:{info.st_ino}",
        int(info.st_size),
        digest,
        _has_reparse_ancestor(canonical),
        is_directory,
        int(info.st_mtime_ns),
    )


def _free_bytes(path: Path) -> int | None:
    try:
        return int(shutil.disk_usage(path).free)
    except OSError:
        return None


def _walk_files(root: Path) -> Iterable[Path]:
    stack = [root]
    while stack:
        current = stack.pop()
        try:
            entries = tuple(os.scandir(current))
        except OSError:
            continue
        for entry in entries:
            path = Path(entry.path)
            try:
                if entry.is_symlink() or bool(getattr(path, "is_junction", lambda: False)()):
                    continue
                if entry.is_dir(follow_symlinks=False):
                    stack.append(path)
                elif entry.is_file(follow_symlinks=False):
                    yield path
            except OSError:
                continue


def _cloud_placeholder(info: os.stat_result) -> bool:
    attributes = getattr(info, "st_file_attributes", 0)
    offline = getattr(stat, "FILE_ATTRIBUTE_OFFLINE", 0x1000)
    recall = getattr(stat, "FILE_ATTRIBUTE_RECALL_ON_DATA_ACCESS", 0x400000)
    return bool(attributes & (offline | recall))


def _host_volumes() -> tuple[VolumeObservation, ...]:
    now = datetime.now(UTC)
    if os.name == "nt":
        roots = _windows_mounts()
    else:
        roots = (Path("/"),)
    observations: list[VolumeObservation] = []
    system_root = os.environ.get("SystemDrive", "C:").rstrip("\\/").casefold()
    for root in roots:
        try:
            usage = shutil.disk_usage(root)
            volume_id, filesystem, stable = _volume_identity(root)
            mount = str(root)
            drive_type = _drive_type(root)
            is_system = (
                mount.rstrip("\\/").casefold() == system_root if os.name == "nt" else mount == "/"
            )
            observations.append(
                VolumeObservation(
                    volume_id,
                    (mount,),
                    filesystem,
                    int(usage.total),
                    int(usage.total - usage.free),
                    int(usage.free),
                    drive_type,
                    None,
                    None,
                    None,
                    drive_type is VolumeDriveType.REMOVABLE if drive_type else None,
                    is_system,
                    not os.access(root, os.W_OK),
                    drive_type is VolumeDriveType.NETWORK if drive_type else None,
                    now,
                    "win32.volume+disk_usage" if os.name == "nt" else "posix.stat+disk_usage",
                    stable,
                )
            )
        except OSError:
            continue
    return tuple(observations)


def _windows_mounts() -> tuple[Path, ...]:
    try:
        mask = ctypes.windll.kernel32.GetLogicalDrives()
    except (AttributeError, OSError):
        return ()
    return tuple(Path(f"{chr(65 + index)}:\\") for index in range(26) if mask & (1 << index))


def _volume_identity(root: Path) -> tuple[str, str | None, bool]:
    if os.name != "nt":
        try:
            return f"device:{os.stat(root, follow_symlinks=False).st_dev}", None, True
        except OSError:
            return f"mount:{root}", None, False
    mount = str(root)
    buffer = ctypes.create_unicode_buffer(512)
    try:
        result = ctypes.windll.kernel32.GetVolumeNameForVolumeMountPointW(mount, buffer, 512)
        if result:
            volume_name = buffer.value.rstrip("\\")
            fs_buffer = ctypes.create_unicode_buffer(256)
            ctypes.windll.kernel32.GetVolumeInformationW(
                mount, None, 0, None, None, None, fs_buffer, 256
            )
            return f"guid:{volume_name.casefold()}", fs_buffer.value or None, True
    except (AttributeError, OSError):
        pass
    try:
        serial = ctypes.c_uint32()
        ctypes.windll.kernel32.GetVolumeInformationW(
            mount, None, 0, ctypes.byref(serial), None, None, None, 0
        )
        if serial.value:
            return f"serial:{serial.value:08x}", None, True
    except (AttributeError, OSError):
        pass
    return f"mount:{mount.casefold()}", None, False


def _drive_type(root: Path) -> VolumeDriveType | None:
    if os.name != "nt":
        return VolumeDriveType.FIXED
    try:
        value = int(ctypes.windll.kernel32.GetDriveTypeW(str(root)))
    except (AttributeError, OSError):
        return VolumeDriveType.UNKNOWN
    return {
        2: VolumeDriveType.REMOVABLE,
        3: VolumeDriveType.FIXED,
        4: VolumeDriveType.NETWORK,
        5: VolumeDriveType.OPTICAL,
        6: VolumeDriveType.RAM,
    }.get(value, VolumeDriveType.UNKNOWN)


__all__ = [
    "CleanupCandidate",
    "CleanupClassifier",
    "CleanupState",
    "DownloadState",
    "DuplicateDetector",
    "DuplicateFileEvidence",
    "DuplicateGroup",
    "EmergencyRecoveryPlan",
    "EmergencyRecoveryPlanner",
    "FileCategory",
    "FileClassification",
    "FileClassifier",
    "FileIdentity",
    "FileOwnership",
    "FileSteward",
    "FilesystemObservation",
    "FilesystemObservationState",
    "ForecastState",
    "ManifestIntegrityError",
    "MutationApprovalRequired",
    "MutationConflict",
    "MutationDenied",
    "MutationError",
    "MutationItem",
    "MutationItemState",
    "MutationManifest",
    "MutationManifestStore",
    "MutationOperation",
    "MutationPhase",
    "MutationResult",
    "MutationState",
    "MutationUnknownOutcome",
    "PlacementClass",
    "PlacementPlan",
    "PlacementStatus",
    "Reversibility",
    "RetentionState",
    "ResourcePlacementRequest",
    "StalePlan",
    "StorageDeferred",
    "StorageError",
    "StorageForecast",
    "StorageHistorySnapshot",
    "StorageHistoryStore",
    "StorageInventoryService",
    "StoragePlanner",
    "StoragePressurePolicy",
    "StoragePressureState",
    "StorageResourceType",
    "VolumeDriveType",
    "VolumeObservation",
    "classify_storage_pressure",
    "forecast_storage_pressure",
]
