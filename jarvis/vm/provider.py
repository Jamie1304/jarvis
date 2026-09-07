"""Provider abstraction and deterministic in-memory provider for CI."""

import hashlib
from dataclasses import replace
from typing import Protocol
from uuid import UUID, uuid4

from jarvis.vm.models import (
    GuestCommand,
    GuestResult,
    Instance,
    InstanceState,
    Template,
    VirtualizationAvailability,
)


class VirtualizationProvider(Protocol):
    """Narrow provider contract; no provider-specific authority leaks upward."""

    name: str

    def probe(self) -> VirtualizationAvailability: ...

    async def create(self, template: Template, owner_task_id: UUID | None = None) -> Instance: ...

    async def start(self, instance_id: UUID) -> Instance: ...

    async def wait_guest_ready(
        self, instance_id: UUID, timeout_seconds: float = 60
    ) -> Instance: ...

    async def execute(self, instance_id: UUID, command: GuestCommand) -> GuestResult: ...

    async def snapshot(self, instance_id: UUID, snapshot_id: str) -> Instance: ...

    async def revert(self, instance_id: UUID, snapshot_id: str) -> Instance: ...

    async def stop(self, instance_id: UUID) -> Instance: ...

    async def destroy(self, instance_id: UUID) -> Instance: ...

    async def instances(self) -> tuple[Instance, ...]: ...


class ProviderRegistry:
    """Trusted application-owned registry for provider implementations."""

    def __init__(self) -> None:
        self._providers: dict[str, VirtualizationProvider] = {}

    def register(self, provider: VirtualizationProvider) -> None:
        if not provider.name or provider.name in self._providers:
            raise ValueError("provider name is missing or already registered")
        self._providers[provider.name] = provider

    def get(self, name: str) -> VirtualizationProvider:
        try:
            return self._providers[name]
        except KeyError as error:
            raise KeyError("unknown virtualization provider") from error

    def providers(self) -> tuple[VirtualizationProvider, ...]:
        return tuple(self._providers.values())


class InMemoryVirtualizationProvider:
    """A deterministic provider that models guest effects without host effects."""

    name = "in-memory"

    def __init__(self, *, available: bool = True) -> None:
        self._availability = (
            VirtualizationAvailability.AVAILABLE
            if available
            else VirtualizationAvailability.UNAVAILABLE
        )
        self._instances: dict[UUID, Instance] = {}
        self._snapshots: dict[tuple[UUID, str], Instance] = {}
        self._failures: dict[str, Exception] = {}
        self.commands: list[tuple[UUID, GuestCommand]] = []

    def probe(self) -> VirtualizationAvailability:
        return self._availability

    def fail_next(self, operation: str, error: Exception | None = None) -> None:
        self._failures[operation] = error or RuntimeError(f"provider {operation} failed")

    def _fail(self, operation: str) -> None:
        error = self._failures.pop(operation, None)
        if error is not None:
            raise error

    def _get(self, instance_id: UUID) -> Instance:
        try:
            return self._instances[instance_id]
        except KeyError as error:
            raise KeyError("unknown instance") from error

    async def create(self, template: Template, owner_task_id: UUID | None = None) -> Instance:
        self._fail("create")
        if self._availability is not VirtualizationAvailability.AVAILABLE:
            raise RuntimeError("provider unavailable")
        instance = Instance(
            uuid4(),
            template.template_id,
            self.name,
            template.purpose,
            owner_task_id,
            InstanceState.READY,
            template.network_policy,
        )
        self._instances[instance.instance_id] = instance
        return instance

    async def start(self, instance_id: UUID) -> Instance:
        self._fail("start")
        instance = self._get(instance_id)
        if instance.state is InstanceState.DESTROYED:
            raise RuntimeError("destroyed instance cannot start")
        updated = _replace(instance, state=InstanceState.READY)
        self._instances[instance_id] = updated
        return updated

    async def wait_guest_ready(self, instance_id: UUID, timeout_seconds: float = 60) -> Instance:
        self._fail("guest_ready")
        if timeout_seconds <= 0:
            raise TimeoutError("guest readiness timed out")
        return self._get(instance_id)

    async def execute(self, instance_id: UUID, command: GuestCommand) -> GuestResult:
        self._fail("execute")
        instance = self._get(instance_id)
        if instance.state is not InstanceState.READY:
            raise RuntimeError("guest is not ready")
        self.commands.append((instance_id, command))
        if command.timeout_seconds < 0.001 or command.executable == "timeout":
            return GuestResult(command.request_id, instance_id, None, timed_out=True)
        if command.executable == "cancel":
            return GuestResult(command.request_id, instance_id, None, cancelled=True)
        output = " ".join((command.executable, *command.args))
        digest = hashlib.sha256(output.encode()).hexdigest()
        return GuestResult(command.request_id, instance_id, 0, output, evidence_digest=digest)

    async def snapshot(self, instance_id: UUID, snapshot_id: str) -> Instance:
        self._fail("snapshot")
        instance = self._get(instance_id)
        updated = _replace(
            instance,
            state=InstanceState.READY,
            snapshot_lineage=(*instance.snapshot_lineage, snapshot_id),
        )
        self._snapshots[(instance_id, snapshot_id)] = updated
        self._instances[instance_id] = updated
        return updated

    async def revert(self, instance_id: UUID, snapshot_id: str) -> Instance:
        self._fail("revert")
        try:
            saved = self._snapshots[(instance_id, snapshot_id)]
        except KeyError as error:
            raise KeyError("unknown snapshot") from error
        self._instances[instance_id] = saved
        return saved

    async def stop(self, instance_id: UUID) -> Instance:
        self._fail("stop")
        updated = _replace(self._get(instance_id), state=InstanceState.STOPPED)
        self._instances[instance_id] = updated
        return updated

    async def destroy(self, instance_id: UUID) -> Instance:
        self._fail("destroy")
        updated = _replace(self._get(instance_id), state=InstanceState.DESTROYED)
        self._instances[instance_id] = updated
        return updated

    async def instances(self) -> tuple[Instance, ...]:
        return tuple(self._instances.values())


def _replace(instance: Instance, **changes: object) -> Instance:
    return replace(instance, **changes)  # type: ignore[arg-type]
