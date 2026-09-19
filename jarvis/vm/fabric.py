"""Lifecycle manager for persistent and disposable JARVIS-owned guests."""

from dataclasses import dataclass
from uuid import UUID

from jarvis.vm.models import EnvironmentKind, Instance, InstanceState, Template
from jarvis.vm.provider import VirtualizationProvider


@dataclass(frozen=True, slots=True)
class ResourcePolicy:
    max_workbench_instances: int = 1
    max_disposable_instances: int = 2

    def __post_init__(self) -> None:
        if self.max_workbench_instances < 1 or self.max_disposable_instances < 1:
            raise ValueError("VM limits must be positive")


class ExecutionFabric:
    def __init__(
        self, provider: VirtualizationProvider, *, policy: ResourcePolicy | None = None
    ) -> None:
        self.provider = provider
        self.policy = policy or ResourcePolicy()
        self.events: list[tuple[str, UUID]] = []

    async def create(self, template: Template, *, task_id: UUID | None = None) -> Instance:
        current = await self.provider.instances()
        disposable = template.purpose in {
            EnvironmentKind.DISPOSABLE_TEST_VM,
            EnvironmentKind.DISPOSABLE_REPAIR_VM,
        }
        limit = (
            self.policy.max_disposable_instances
            if disposable
            else self.policy.max_workbench_instances
        )
        active = sum(
            item.state is not InstanceState.DESTROYED
            for item in current
            if item.purpose is template.purpose
        )
        if active >= limit:
            raise RuntimeError("VM resource limit reached")
        instance = await self.provider.create(template, task_id)
        self.events.append(("created", instance.instance_id))
        return instance

    async def start_ready(self, instance_id: UUID) -> Instance:
        instance = await self.provider.start(instance_id)
        ready = await self.provider.wait_guest_ready(instance.instance_id)
        self.events.append(("guest_ready", ready.instance_id))
        return ready

    async def cleanup_disposable(self, instance_id: UUID) -> Instance:
        instance = await self.provider.stop(instance_id)
        destroyed = await self.provider.destroy(instance.instance_id)
        self.events.append(("destroyed", destroyed.instance_id))
        return destroyed

    async def reconcile(self, owned_ids: frozenset[UUID]) -> tuple[Instance, ...]:
        """Return only owned records; unknown provider machines are never touched."""
        return tuple(
            item for item in await self.provider.instances() if item.instance_id in owned_ids
        )
