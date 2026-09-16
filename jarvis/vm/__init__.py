"""VM-first execution contracts and deterministic virtualization substrate."""

from jarvis.vm.bridge import (
    HostBridge,
    HostBridgeOperation,
    HostBridgeRequest,
    HostBridgeResult,
    build_host_bridge_action_descriptor,
)
from jarvis.vm.execution import (
    GuestOperationEvidence,
    GuestOperationExecution,
    HostWriteEvidence,
    VMExecutionError,
    VMExecutionEvidence,
    VMExecutionService,
    VMExecutionUnavailable,
    VMOperationSemanticError,
)
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
from jarvis.vm.operations import (
    BuildCheckSemanticResult,
    BuildLanguage,
    BuildProfile,
    GuestOperationSpec,
    ResearchAnalysis,
    ResearchSemanticResult,
    VMBuildCheckInput,
    VMResearchInput,
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
    "GuestOperationEvidence",
    "GuestOperationExecution",
    "GuestOperationSpec",
    "GuestCommand",
    "GuestResult",
    "HostBridge",
    "HostBridgeOperation",
    "HostBridgeRequest",
    "HostBridgeResult",
    "HostWriteEvidence",
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
    "VMExecutionError",
    "VMExecutionEvidence",
    "VMExecutionService",
    "VMExecutionUnavailable",
    "VMOperationSemanticError",
    "VMBuildCheckInput",
    "VMResearchInput",
    "BuildCheckSemanticResult",
    "BuildLanguage",
    "BuildProfile",
    "ResearchAnalysis",
    "ResearchSemanticResult",
    "WSL2VirtualizationProvider",
    "build_host_bridge_action_descriptor",
]
