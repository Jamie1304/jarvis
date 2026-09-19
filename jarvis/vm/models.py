"""Bounded, provider-neutral VM and guest execution records."""

from dataclasses import dataclass, field
from datetime import UTC, datetime
from enum import StrEnum
from typing import Final
from uuid import UUID, uuid4

MAX_TEXT: Final = 256


def _text(value: str, name: str, *, limit: int = MAX_TEXT) -> str:
    if type(value) is not str or not value or len(value) > limit or value != value.strip():
        raise ValueError(f"{name} must be bounded non-empty text")
    if any(not char.isprintable() for char in value):
        raise ValueError(f"{name} contains non-printable text")
    return value


class EnvironmentKind(StrEnum):
    HOST = "host"
    WORKBENCH_VM = "workbench_vm"
    DISPOSABLE_TEST_VM = "disposable_test_vm"
    DISPOSABLE_REPAIR_VM = "disposable_repair_vm"
    INTERNAL_TRUSTED = "internal_trusted"


class InstanceState(StrEnum):
    DEFINED = "defined"
    CREATING = "creating"
    STARTING = "starting"
    WAITING_FOR_GUEST = "waiting_for_guest"
    READY = "ready"
    BUSY = "busy"
    SNAPSHOTTING = "snapshotting"
    STOPPING = "stopping"
    STOPPED = "stopped"
    REVERTING = "reverting"
    DESTROYING = "destroying"
    DESTROYED = "destroyed"
    FAILED = "failed"


class NetworkPolicy(StrEnum):
    NO_NETWORK = "no_network"
    INTERNET_ONLY = "internet_only"
    RESTRICTED_DESTINATIONS = "restricted_destinations"
    FULL_VM_NETWORK = "full_vm_network"


class VirtualizationAvailability(StrEnum):
    AVAILABLE = "available"
    AVAILABLE_REQUIRES_SETUP = "available_requires_setup"
    UNAVAILABLE = "unavailable"
    UNSUPPORTED = "unsupported"
    DEGRADED = "degraded"


@dataclass(frozen=True, slots=True)
class Template:
    template_id: str
    provider: str
    os_name: str
    architecture: str
    base_image_hash: str
    purpose: EnvironmentKind
    network_policy: NetworkPolicy = NetworkPolicy.NO_NETWORK
    trusted: bool = False
    generation: int = 1

    def __post_init__(self) -> None:
        for value, name in (
            (self.template_id, "template_id"),
            (self.provider, "provider"),
            (self.os_name, "os_name"),
            (self.architecture, "architecture"),
            (self.base_image_hash, "base_image_hash"),
        ):
            _text(value, name)
        if self.generation < 1:
            raise ValueError("generation must be positive")


@dataclass(frozen=True, slots=True)
class GuestCommand:
    executable: str
    args: tuple[str, ...] = ()
    working_directory: str = "/"
    environment: tuple[tuple[str, str], ...] = ()
    timeout_seconds: float = 30.0
    network_policy: NetworkPolicy = NetworkPolicy.NO_NETWORK
    expected_artifacts: tuple[str, ...] = ()
    request_id: UUID = field(default_factory=uuid4)

    def __post_init__(self) -> None:
        _text(self.executable, "executable")
        if len(self.args) > 128 or any(
            type(item) is not str or len(item) > 1024 for item in self.args
        ):
            raise ValueError("args are not bounded")
        if self.timeout_seconds <= 0 or self.timeout_seconds > 3600:
            raise ValueError("timeout_seconds must be between 0 and 3600")
        if len(self.environment) > 64:
            raise ValueError("environment is not bounded")


@dataclass(frozen=True, slots=True)
class GuestResult:
    request_id: UUID
    instance_id: UUID
    exit_code: int | None
    stdout: str = ""
    stderr: str = ""
    timed_out: bool = False
    cancelled: bool = False
    evidence_digest: str = ""


@dataclass(frozen=True, slots=True)
class Instance:
    instance_id: UUID
    template_id: str
    provider: str
    purpose: EnvironmentKind
    owner_task_id: UUID | None
    state: InstanceState
    network_policy: NetworkPolicy
    created_at: datetime = field(default_factory=lambda: datetime.now(UTC))
    metadata_tag: str = "jarvis-owned"
    snapshot_lineage: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        _text(self.template_id, "template_id")
        _text(self.provider, "provider")
        if self.metadata_tag != "jarvis-owned":
            raise ValueError("instances must carry the JARVIS ownership tag")


@dataclass(frozen=True, slots=True)
class RouteDecision:
    environment: EnvironmentKind
    reason: str
    required_tools: tuple[str, ...] = ()
    host_bridges: tuple[str, ...] = ()
    isolation_level: str = "guest"
    fallbacks: tuple[EnvironmentKind, ...] = ()
    approval_required: bool = False
