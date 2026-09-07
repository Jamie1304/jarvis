"""VM-first execution contracts and deterministic virtualization substrate."""

from jarvis.vm.bridge import HostBridge, HostBridgeOperation, HostBridgeRequest, HostBridgeResult
from jarvis.vm.fabric import ExecutionFabric, ResourcePolicy
from jarvis.vm.models import (
    EnvironmentKind,
    GuestCommand,
    GuestResult,
    Instance,
    InstanceState,
    NetworkPolicy,
    RouteDecision,
    Template,
    VirtualizationAvailability,
)
from jarvis.vm.provider import (
    InMemoryVirtualizationProvider,
    ProviderRegistry,
    VirtualizationProvider,
)
from jarvis.vm.router import ExecutionIntent, ExecutionRouter
from jarvis.vm.wsl import (
    ReadinessObservation,
    ReadinessProbeStatus,
    ReadinessState,
    WSL2VirtualizationProvider,
)

__all__ = [
    "EnvironmentKind",
    "ExecutionFabric",
    "ExecutionIntent",
    "ExecutionRouter",
    "GuestCommand",
    "GuestResult",
    "HostBridge",
    "HostBridgeOperation",
    "HostBridgeRequest",
    "HostBridgeResult",
    "InMemoryVirtualizationProvider",
    "ProviderRegistry",
    "Instance",
    "InstanceState",
    "NetworkPolicy",
    "ResourcePolicy",
    "ReadinessObservation",
    "ReadinessProbeStatus",
    "ReadinessState",
    "RouteDecision",
    "Template",
    "VirtualizationAvailability",
    "VirtualizationProvider",
    "WSL2VirtualizationProvider",
]
