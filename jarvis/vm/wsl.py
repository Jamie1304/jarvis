"""Real WSL2 provider, isolated behind the provider-neutral VM contract."""

from __future__ import annotations

import asyncio
import hashlib
import json
import os
import subprocess
import time
from collections.abc import Awaitable, Callable
from dataclasses import dataclass, replace
from enum import StrEnum
from pathlib import Path
from uuid import UUID, uuid4

from jarvis.vm.models import (
    EnvironmentKind,
    GuestCommand,
    GuestResult,
    Instance,
    InstanceState,
    NetworkPolicy,
    Template,
    VirtualizationAvailability,
)


class ReadinessState(StrEnum):
    START_REQUESTED = "start_requested"
    STARTING = "starting"
    READINESS_PROBING = "readiness_probing"
    READY = "ready"
    FAILED = "failed"
    CANCELLED = "cancelled"
    TIMED_OUT = "timed_out"


class ReadinessProbeStatus(StrEnum):
    READY = "ready"
    TEMPORARILY_UNAVAILABLE = "temporarily_unavailable"
    FATAL_FAILURE = "fatal_failure"
    PROBE_TIMEOUT = "probe_timeout"


@dataclass(frozen=True, slots=True)
class ReadinessObservation:
    operation_id: UUID
    distribution: str
    ownership: str
    state: ReadinessState
    probe_number: int
    probe_timeout_seconds: float
    elapsed_seconds: float
    remaining_seconds: float
    status: ReadinessProbeStatus | None = None
    return_code: int | None = None
    stderr_classification: str = ""


@dataclass(frozen=True, slots=True)
class _ProbeResult:
    status: ReadinessProbeStatus
    return_code: int | None = None
    stdout: str = ""
    stderr: str = ""


class WSL2VirtualizationProvider:
    """Controls only distributions carrying the provider's ownership metadata."""

    name = "wsl2"
    startup_timeout_seconds = 60.0
    readiness_probe_timeout_seconds = 5.0
    max_readiness_backoff_seconds = 1.0

    def __init__(
        self,
        *,
        state_path: Path | None = None,
        executable: str = "wsl.exe",
        clock: Callable[[], float] = time.monotonic,
        sleeper: Callable[[float], Awaitable[None]] = asyncio.sleep,
        startup_timeout_seconds: float = 60.0,
        readiness_probe_timeout_seconds: float = 5.0,
    ) -> None:
        if startup_timeout_seconds <= 0 or readiness_probe_timeout_seconds <= 0:
            raise ValueError("WSL readiness deadlines must be positive")
        self.executable = executable
        self._clock = clock
        self._sleeper = sleeper
        self.startup_timeout_seconds = startup_timeout_seconds
        self.readiness_probe_timeout_seconds = readiness_probe_timeout_seconds
        self.state_path = (
            state_path or Path(os.environ.get("LOCALAPPDATA", ".")) / "JARVIS" / "vm" / "wsl2.json"
        )
        self._records: dict[UUID, Instance] = {}
        self._startup_locks: dict[UUID, asyncio.Lock] = {}
        self.last_readiness: tuple[ReadinessObservation, ...] = ()
        self._load()

    def probe(self) -> VirtualizationAvailability:
        if os.name != "nt":
            return VirtualizationAvailability.UNSUPPORTED
        try:
            result = self._run("--status")
        except OSError:
            return VirtualizationAvailability.UNAVAILABLE
        return (
            VirtualizationAvailability.AVAILABLE
            if result.returncode == 0
            else VirtualizationAvailability.DEGRADED
        )

    async def create(self, template: Template, owner_task_id: UUID | None = None) -> Instance:
        if template.provider != self.name:
            raise ValueError("template is not for WSL2")
        name = str(template.template_id)
        result = self._run("--list", "--quiet")
        if name not in result.stdout.splitlines():
            raise RuntimeError("WSL2 creation requires an explicit trusted installation workflow")
        instance = Instance(
            uuid4(),
            name,
            self.name,
            template.purpose,
            owner_task_id,
            InstanceState.STOPPED,
            template.network_policy,
        )
        self._records[instance.instance_id] = instance
        self._save()
        return instance

    async def start(self, instance_id: UUID) -> Instance:
        instance = self._owned(instance_id)
        if instance.state is InstanceState.READY:
            return instance
        return self._set(instance, InstanceState.STARTING)

    async def wait_guest_ready(
        self, instance_id: UUID, timeout_seconds: float | None = None
    ) -> Instance:
        timeout_seconds = (
            self.startup_timeout_seconds if timeout_seconds is None else timeout_seconds
        )
        if timeout_seconds <= 0:
            raise TimeoutError("guest readiness timed out")
        instance = self._owned(instance_id)
        lock = self._startup_locks.setdefault(instance_id, asyncio.Lock())
        async with lock:
            instance = self._owned(instance_id)
            if instance.state is InstanceState.READY:
                return instance
            return await self._wait_guest_ready(instance, timeout_seconds)

    async def _wait_guest_ready(self, instance: Instance, timeout_seconds: float) -> Instance:
        operation_id = uuid4()
        started = self._clock()
        observations: list[ReadinessObservation] = [
            self._observation(
                operation_id,
                instance,
                ReadinessState.START_REQUESTED,
                0,
                0.0,
                timeout_seconds,
            )
        ]
        observations.append(
            self._observation(
                operation_id,
                instance,
                ReadinessState.STARTING,
                0,
                0.0,
                timeout_seconds,
            )
        )
        self._set(instance, InstanceState.WAITING_FOR_GUEST)
        probe_number = 0
        try:
            while True:
                elapsed = self._clock() - started
                remaining = timeout_seconds - elapsed
                if remaining <= 0:
                    observations.append(
                        self._observation(
                            operation_id,
                            instance,
                            ReadinessState.TIMED_OUT,
                            probe_number,
                            0.0,
                            0.0,
                            elapsed,
                        )
                    )
                    self.last_readiness = tuple(observations)
                    self._set(instance, InstanceState.FAILED)
                    raise TimeoutError("WSL2 guest readiness overall deadline timed out")

                probe_number += 1
                probe_timeout = min(self.readiness_probe_timeout_seconds, remaining)
                observations.append(
                    self._observation(
                        operation_id,
                        instance,
                        ReadinessState.READINESS_PROBING,
                        probe_number,
                        probe_timeout,
                        remaining,
                        elapsed,
                    )
                )
                probe = await self._readiness_probe(instance.template_id, probe_timeout)
                elapsed = self._clock() - started
                remaining = max(0.0, timeout_seconds - elapsed)
                classification = _classify_probe_text(probe.stdout, probe.stderr)
                observations.append(
                    self._observation(
                        operation_id,
                        instance,
                        ReadinessState.READINESS_PROBING,
                        probe_number,
                        probe_timeout,
                        remaining,
                        elapsed,
                        status=probe.status,
                        return_code=probe.return_code,
                        stderr_classification=classification,
                    )
                )
                if probe.status is ReadinessProbeStatus.READY:
                    observations.append(
                        self._observation(
                            operation_id,
                            instance,
                            ReadinessState.READY,
                            probe_number,
                            probe_timeout,
                            remaining,
                            elapsed,
                            status=probe.status,
                            return_code=probe.return_code,
                            stderr_classification=classification,
                        )
                    )
                    self.last_readiness = tuple(observations)
                    return self._set(instance, InstanceState.READY)
                if probe.status is ReadinessProbeStatus.FATAL_FAILURE:
                    observations.append(
                        self._observation(
                            operation_id,
                            instance,
                            ReadinessState.FAILED,
                            probe_number,
                            probe_timeout,
                            remaining,
                            elapsed,
                            status=probe.status,
                            return_code=probe.return_code,
                            stderr_classification=classification,
                        )
                    )
                    self.last_readiness = tuple(observations)
                    self._set(instance, InstanceState.FAILED)
                    raise RuntimeError(
                        f"WSL2 guest readiness failed: {classification or probe.stderr.strip()}"
                    )
                if remaining <= 0:
                    observations.append(
                        self._observation(
                            operation_id,
                            instance,
                            ReadinessState.TIMED_OUT,
                            probe_number,
                            probe_timeout,
                            0.0,
                            elapsed,
                            status=probe.status,
                            return_code=probe.return_code,
                            stderr_classification=classification,
                        )
                    )
                    self.last_readiness = tuple(observations)
                    self._set(instance, InstanceState.FAILED)
                    raise TimeoutError("WSL2 guest readiness overall deadline timed out")
                await self._sleeper(min(0.1 * (2 ** min(probe_number - 1, 3)), 1.0, remaining))
        except asyncio.CancelledError:
            elapsed = self._clock() - started
            observations.append(
                self._observation(
                    operation_id,
                    instance,
                    ReadinessState.CANCELLED,
                    probe_number,
                    0.0,
                    max(0.0, timeout_seconds - elapsed),
                    elapsed,
                )
            )
            self.last_readiness = tuple(observations)
            self._set(instance, InstanceState.FAILED)
            raise

    async def _readiness_probe(self, distribution: str, timeout: float) -> _ProbeResult:
        args = ("--distribution", distribution, "--exec", "true")
        try:
            process = await asyncio.create_subprocess_exec(
                self.executable,
                *args,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
        except OSError as error:
            return _ProbeResult(ReadinessProbeStatus.FATAL_FAILURE, stderr=str(error))
        try:
            stdout, stderr = await asyncio.wait_for(process.communicate(), timeout=timeout)
        except TimeoutError:
            self._terminate_probe(process)
            await process.communicate()
            return _ProbeResult(ReadinessProbeStatus.PROBE_TIMEOUT)
        except asyncio.CancelledError:
            self._terminate_probe(process)
            await process.communicate()
            raise
        decoded_stdout = _decode_wsl_output(stdout.decode(errors="replace"))
        decoded_stderr = _decode_wsl_output(stderr.decode(errors="replace"))
        status = (
            ReadinessProbeStatus.READY
            if process.returncode == 0
            else (
                ReadinessProbeStatus.FATAL_FAILURE
                if _is_fatal_probe_error(decoded_stdout, decoded_stderr)
                else ReadinessProbeStatus.TEMPORARILY_UNAVAILABLE
            )
        )
        return _ProbeResult(status, process.returncode, decoded_stdout, decoded_stderr)

    @staticmethod
    def _terminate_probe(process: asyncio.subprocess.Process) -> None:
        if process.returncode is None:
            process.kill()

    def _observation(
        self,
        operation_id: UUID,
        instance: Instance,
        state: ReadinessState,
        probe_number: int,
        probe_timeout: float,
        remaining: float,
        elapsed: float | None = None,
        *,
        status: ReadinessProbeStatus | None = None,
        return_code: int | None = None,
        stderr_classification: str = "",
    ) -> ReadinessObservation:
        return ReadinessObservation(
            operation_id,
            instance.template_id,
            instance.metadata_tag,
            state,
            probe_number,
            probe_timeout,
            elapsed if elapsed is not None else 0.0,
            remaining,
            status,
            return_code,
            stderr_classification,
        )

    async def execute(self, instance_id: UUID, command: GuestCommand) -> GuestResult:
        instance = self._owned(instance_id)
        if instance.state is not InstanceState.READY:
            raise RuntimeError("guest is not ready")
        args = ("--distribution", instance.template_id, "--exec", command.executable, *command.args)
        result = await asyncio.to_thread(self._run, *args, timeout=command.timeout_seconds)
        digest = hashlib.sha256((result.stdout + result.stderr).encode()).hexdigest()
        return GuestResult(
            command.request_id,
            instance_id,
            result.returncode,
            result.stdout,
            result.stderr,
            evidence_digest=digest,
        )

    async def stop(self, instance_id: UUID) -> Instance:
        instance = self._owned(instance_id)
        result = self._run("--terminate", instance.template_id)
        self._check(result, "stop")
        return self._set(instance, InstanceState.STOPPED)

    async def destroy(self, instance_id: UUID) -> Instance:
        instance = self._owned(instance_id)
        result = self._run("--unregister", instance.template_id)
        self._check(result, "destroy")
        return self._set(instance, InstanceState.DESTROYED)

    async def instances(self) -> tuple[Instance, ...]:
        return tuple(self._records.values())

    async def snapshot(self, instance_id: UUID, snapshot_id: str) -> Instance:
        raise NotImplementedError("WSL2 has no provider-neutral snapshot primitive")

    async def revert(self, instance_id: UUID, snapshot_id: str) -> Instance:
        raise NotImplementedError("WSL2 has no provider-neutral snapshot primitive")

    async def export(self, instance_id: UUID, archive: Path) -> Path:
        instance = self._owned(instance_id)
        result = self._run("--export", instance.template_id, str(archive), timeout=300)
        self._check(result, "export")
        return archive

    async def import_clone(
        self,
        source: UUID,
        clone_name: str,
        install_location: Path,
        archive: Path,
        template: Template,
        owner_task_id: UUID | None = None,
    ) -> Instance:
        self._owned(source)
        result = self._run(
            "--import",
            clone_name,
            str(install_location),
            str(archive),
            "--version",
            "2",
            timeout=300,
        )
        self._check(result, "import")
        instance = Instance(
            uuid4(),
            clone_name,
            self.name,
            template.purpose,
            owner_task_id,
            InstanceState.STOPPED,
            template.network_policy,
        )
        self._records[instance.instance_id] = instance
        self._save()
        return instance

    async def reconcile(self) -> tuple[Instance, ...]:
        """Reconcile persisted records without touching foreign distributions."""
        result = self._run("--list", "--quiet")
        names = frozenset(line.strip() for line in result.stdout.splitlines() if line.strip())
        for instance_id, instance in tuple(self._records.items()):
            if instance.template_id not in names and instance.state is not InstanceState.DESTROYED:
                self._records[instance_id] = replace(instance, state=InstanceState.DESTROYED)
        self._save()
        return tuple(self._records.values())

    def _owned(self, instance_id: UUID) -> Instance:
        try:
            instance = self._records[instance_id]
        except KeyError as error:
            raise KeyError("unknown JARVIS-owned WSL instance") from error
        if instance.metadata_tag != "jarvis-owned":
            raise PermissionError("foreign WSL distribution")
        return instance

    def _set(self, instance: Instance, state: InstanceState) -> Instance:
        updated = replace(instance, state=state)
        self._records[instance.instance_id] = updated
        self._save()
        return updated

    def _run(self, *args: str, timeout: float = 30) -> subprocess.CompletedProcess[str]:
        result = subprocess.run(
            (self.executable, *args), capture_output=True, text=True, timeout=timeout, check=False
        )
        return subprocess.CompletedProcess(
            result.args,
            result.returncode,
            _decode_wsl_output(result.stdout),
            _decode_wsl_output(result.stderr),
        )

    @staticmethod
    def _check(result: subprocess.CompletedProcess[str], operation: str) -> None:
        if result.returncode:
            raise RuntimeError(
                f"WSL2 {operation} failed: {result.stderr.strip() or result.stdout.strip()}"
            )

    def _load(self) -> None:
        if not self.state_path.exists():
            return
        raw = json.loads(self.state_path.read_text(encoding="utf-8"))
        for item in raw:
            instance = Instance(
                UUID(item["instance_id"]),
                item["template_id"],
                self.name,
                EnvironmentKind(item["purpose"]),
                UUID(item["owner_task_id"]) if item["owner_task_id"] else None,
                InstanceState(item["state"]),
                NetworkPolicy(item["network_policy"]),
            )
            self._records[instance.instance_id] = instance

    def _save(self) -> None:
        self.state_path.parent.mkdir(parents=True, exist_ok=True)
        data = [
            {
                "instance_id": str(item.instance_id),
                "template_id": item.template_id,
                "purpose": item.purpose.value,
                "owner_task_id": str(item.owner_task_id) if item.owner_task_id else None,
                "state": item.state.value,
                "network_policy": item.network_policy.value,
            }
            for item in self._records.values()
        ]
        self.state_path.write_text(json.dumps(data, indent=2), encoding="utf-8")


def _is_fatal_probe_error(stdout: str, stderr: str) -> bool:
    text = f"{stdout}\n{stderr}".casefold()
    return any(
        marker in text
        for marker in (
            "not registered",
            "distribution was not found",
            "invalid distribution",
            "unknown option",
            "invalid command",
        )
    )


def _classify_probe_text(stdout: str, stderr: str) -> str:
    if _is_fatal_probe_error(stdout, stderr):
        return "fatal_wsl_error"
    if stderr.strip():
        return "transient_wsl_error"
    return ""


def _decode_wsl_output(value: str) -> str:
    """wsl.exe may emit UTF-16LE through redirected Windows console handles."""
    if "\x00" not in value:
        return value
    try:
        return value.encode("latin-1").decode("utf-16-le")
    except UnicodeError:
        return value.replace("\x00", "")
