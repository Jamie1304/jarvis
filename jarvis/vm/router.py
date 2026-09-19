"""Deterministic VM-first execution policy."""

from dataclasses import dataclass
from typing import Final

from jarvis.vm.models import EnvironmentKind, RouteDecision


@dataclass(frozen=True, slots=True)
class ExecutionIntent:
    task_class: str
    host_resource_dependency: bool = False
    physical_device_dependency: bool = False
    host_application_required: bool = False
    exact_host_mutation: bool = False
    isolation_required: bool = False
    persistence_required: bool = False
    network_required: bool = False
    ui_required: bool = False
    explicit_host_request: bool = False
    risk: str = "low"


class ExecutionRouter:
    """Routes by explicit effect/resource metadata; no model or cloud is needed."""

    _REPAIR: Final = frozenset({"repair", "self_repair", "candidate_repair"})
    _TEST: Final = frozenset({"test", "dependency_test", "provisioning_test", "unknown_fixture"})
    _INTERNAL: Final = frozenset({"internal", "planning", "deterministic"})

    def route(self, intent: ExecutionIntent) -> RouteDecision:
        if (
            intent.explicit_host_request
            or intent.host_application_required
            or intent.physical_device_dependency
        ):
            bridge = ("HOST_DEVICE_ACCESS",) if intent.physical_device_dependency else ()
            return RouteDecision(
                EnvironmentKind.HOST,
                "host-specific effect requested",
                host_bridges=bridge,
                isolation_level="protected_host",
                approval_required=intent.risk != "low",
            )
        if intent.exact_host_mutation or intent.host_resource_dependency:
            return RouteDecision(
                EnvironmentKind.HOST,
                "exact host resource is required",
                host_bridges=("HOST_FILE_READ", "HOST_FILE_WRITE"),
                isolation_level="brokered_host",
                approval_required=True,
                fallbacks=(EnvironmentKind.WORKBENCH_VM,),
            )
        task = intent.task_class.lower().strip()
        if task in self._REPAIR:
            return RouteDecision(
                EnvironmentKind.DISPOSABLE_REPAIR_VM,
                "repair requires disposable isolation",
                isolation_level="disposable",
                approval_required=False,
            )
        if task in self._TEST or intent.isolation_required:
            return RouteDecision(
                EnvironmentKind.DISPOSABLE_TEST_VM,
                "testing requires disposable isolation",
                isolation_level="disposable",
                approval_required=False,
            )
        if task in self._INTERNAL:
            return RouteDecision(
                EnvironmentKind.INTERNAL_TRUSTED,
                "deterministic internal operation",
                isolation_level="trusted_core",
            )
        return RouteDecision(
            EnvironmentKind.WORKBENCH_VM,
            "non-host task defaults to JARVIS workbench",
            isolation_level="persistent_guest",
            fallbacks=(EnvironmentKind.DISPOSABLE_TEST_VM,),
        )
