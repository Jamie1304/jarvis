"""Typed execution environments for Acceptance Lab integrations.

The lab asks for an environment by contract. Provider-specific lifecycle and
WSL details stay behind this module so test specifications remain declarative.
"""

from __future__ import annotations

import asyncio
import hashlib
import tempfile
from dataclasses import dataclass
from pathlib import Path
from typing import Protocol
from uuid import UUID, uuid4

from jarvis.vm import ExecutionFabric, GuestCommand, GuestResult, Template
from jarvis.vm.models import EnvironmentKind, Instance, InstanceState, NetworkPolicy
from jarvis.vm.provider import VirtualizationProvider


class AcceptanceEnvironmentError(RuntimeError):
    """An environment could not be acquired or safely cleaned up."""


@dataclass(frozen=True, slots=True)
class EnvironmentLease:
    run_id: str
    test_id: str
    environment: EnvironmentKind
    instance_id: UUID
    provider: str
    guest_identity: str
    started_at: str
    expires_at: str
    disposable: bool


@dataclass(frozen=True, slots=True)
class EnvironmentEvidence:
    lease: EnvironmentLease
    command: str
    result: GuestResult
    guest_state: str
    cleanup_state: str
    artifact_hash: str

    def as_dict(self) -> dict[str, object]:
        return {
            "provider": self.lease.provider,
            "instance": str(self.lease.instance_id),
            "guest_identity": self.lease.guest_identity,
            "run_id": self.lease.run_id,
            "test_id": self.lease.test_id,
            "command": self.command,
            "exit_code": self.result.exit_code,
            "timed_out": self.result.timed_out,
            "evidence_digest": self.result.evidence_digest,
            "artifact_hash": self.artifact_hash,
            "guest_state": self.guest_state,
            "cleanup_state": self.cleanup_state,
        }


class AcceptanceEnvironment(Protocol):
    async def acquire(self, run_id: str, test_id: str, *, disposable: bool) -> EnvironmentLease: ...

    async def execute(
        self, lease: EnvironmentLease, command: GuestCommand
    ) -> EnvironmentEvidence: ...

    async def release(self, lease: EnvironmentLease) -> None: ...

    async def run_disposable_fault(self, run_id: str, test_id: str) -> dict[str, object]: ...


class VMAcceptanceEnvironment:
    """Provider-neutral adapter for Workbench and disposable VM leases."""

    def __init__(
        self, provider: VirtualizationProvider, *, archive_root: Path | None = None
    ) -> None:
        self.provider = provider
        self.fabric = ExecutionFabric(provider)
        self.archive_root = archive_root or Path(tempfile.gettempdir()) / "jarvis-acceptance-vm"
        self._workbench_lock = asyncio.Lock()
        self._leases: dict[UUID, EnvironmentLease] = {}
        self._workbench: Instance | None = None

    async def acquire(self, run_id: str, test_id: str, *, disposable: bool) -> EnvironmentLease:
        lock = self._workbench_lock if not disposable else _NullAsyncLock()
        async with lock:
            if disposable:
                instance = await self._create_disposable()
            else:
                instance = await self._get_workbench()
                instance = await self.fabric.start_ready(instance.instance_id)
            now = __import__("datetime").datetime.now(__import__("datetime").UTC).isoformat()
            lease = EnvironmentLease(
                run_id,
                test_id,
                instance.purpose,
                instance.instance_id,
                instance.provider,
                instance.template_id,
                now,
                now,
                disposable,
            )
            self._leases[instance.instance_id] = lease
            return lease

    async def execute(self, lease: EnvironmentLease, command: GuestCommand) -> EnvironmentEvidence:
        if self._leases.get(lease.instance_id) != lease:
            raise AcceptanceEnvironmentError("unknown or stale acceptance environment lease")
        result = await self.provider.execute(lease.instance_id, command)
        payload = (result.stdout + result.stderr).encode()
        return EnvironmentEvidence(
            lease,
            " ".join((command.executable, *command.args)),
            result,
            InstanceState.READY.value,
            "PENDING",
            hashlib.sha256(payload).hexdigest(),
        )

    async def release(self, lease: EnvironmentLease) -> None:
        if self._leases.pop(lease.instance_id, None) is None:
            return
        if lease.disposable:
            await self.fabric.cleanup_disposable(lease.instance_id)
        else:
            instance = await self.provider.instances()
            current = next(
                (item for item in instance if item.instance_id == lease.instance_id), None
            )
            if current is not None and current.state is InstanceState.READY:
                await self.provider.stop(current.instance_id)

    async def run_disposable_fault(self, run_id: str, test_id: str) -> dict[str, object]:
        """Run a harmless marker fault in a disposable child and destroy it."""
        lease = await self.acquire(run_id, test_id, disposable=True)
        marker = "/tmp/jarvis-acceptance/fault-present"
        cleanup_error: Exception | None = None
        try:
            injected = await self.provider.execute(
                lease.instance_id,
                GuestCommand("sh", ("-c", f"mkdir -p /tmp/jarvis-acceptance && touch {marker}")),
            )
            verified = await self.provider.execute(
                lease.instance_id, GuestCommand("test", ("-f", marker))
            )
            cleaned = await self.provider.execute(
                lease.instance_id,
                GuestCommand("sh", ("-c", f"rm -f {marker} && test ! -e {marker}")),
            )
            return {
                "provider": lease.provider,
                "instance": str(lease.instance_id),
                "guest_identity": lease.guest_identity,
                "fault": "DEPENDENCY_MISSING",
                "injected_exit_code": injected.exit_code,
                "fault_present_exit_code": verified.exit_code,
                "cleanup_exit_code": cleaned.exit_code,
                "fault_verified": verified.exit_code == 0,
                "cleanup_verified": cleaned.exit_code == 0,
            }
        finally:
            try:
                await self.release(lease)
            except Exception as error:
                cleanup_error = error
            if cleanup_error is not None:
                raise AcceptanceEnvironmentError(
                    f"disposable cleanup failed: {cleanup_error}"
                ) from cleanup_error

    async def _get_workbench(self) -> Instance:
        if self._workbench is not None:
            return self._workbench
        existing = next(
            (
                item
                for item in await self.provider.instances()
                if item.template_id == "jarvis-workbench"
            ),
            None,
        )
        if existing is not None and existing.state is not InstanceState.DESTROYED:
            self._workbench = existing
            return existing
        template = Template(
            "jarvis-workbench",
            self.provider.name,
            "Ubuntu 22.04 LTS",
            "x86_64",
            "real-workbench",
            EnvironmentKind.WORKBENCH_VM,
            NetworkPolicy.NO_NETWORK,
            trusted=True,
        )
        self._workbench = await self.fabric.create(template)
        return self._workbench

    async def _create_disposable(self) -> Instance:
        if not hasattr(self.provider, "export") or not hasattr(self.provider, "import_clone"):
            raise AcceptanceEnvironmentError("provider has no disposable clone contract")
        source = await self._get_workbench()
        source_was_running = source.state is InstanceState.READY
        if source.state is InstanceState.READY:
            await self.provider.stop(source.instance_id)
        self.archive_root.mkdir(parents=True, exist_ok=True)
        archive = self.archive_root / f"{uuid4().hex}.tar"
        clone_name = f"jarvis-acceptance-{uuid4().hex[:12]}"
        template = Template(
            clone_name,
            source.provider,
            "Ubuntu 22.04 LTS",
            "x86_64",
            "disposable-from-workbench",
            EnvironmentKind.DISPOSABLE_TEST_VM,
            NetworkPolicy.NO_NETWORK,
            trusted=True,
        )
        try:
            await self.provider.export(source.instance_id, archive)
            instance = await self.provider.import_clone(
                source.instance_id, clone_name, self.archive_root / clone_name, archive, template
            )
        finally:
            archive.unlink(missing_ok=True)
            if source_was_running or source.state is InstanceState.STOPPED:
                self._workbench = await self.fabric.start_ready(source.instance_id)
        return await self.fabric.start_ready(instance.instance_id)

    async def reconcile(self) -> tuple[Instance, ...]:
        return (
            await self.provider.reconcile()
            if hasattr(self.provider, "reconcile")
            else await self.provider.instances()
        )


class _NullAsyncLock:
    async def __aenter__(self) -> None:
        return None

    async def __aexit__(self, *args: object) -> None:
        return None
