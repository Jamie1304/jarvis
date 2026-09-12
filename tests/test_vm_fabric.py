import asyncio
import subprocess
from datetime import UTC, datetime, timedelta
from pathlib import Path
from uuid import uuid4

import pytest
from jarvis.vm import (
    EnvironmentKind,
    ExecutionFabric,
    ExecutionRouter,
    GuestCommand,
    HostBridge,
    HostBridgeRequest,
    InMemoryVirtualizationProvider,
    ProviderRegistry,
    ResourcePolicy,
    Template,
    WSL2VirtualizationProvider,
)
from jarvis.vm.bridge import HostBridgeOperation
from jarvis.vm.host_probe import classify_windows_readiness, probe_windows_host
from jarvis.vm.models import Instance, InstanceState, VirtualizationAvailability
from jarvis.vm.router import ExecutionIntent
from jarvis.vm.wsl import (
    ReadinessProbeStatus,
    ReadinessState,
    _classify_probe_text,
    _decode_wsl_output,
    _ProbeResult,
)


def template(purpose: EnvironmentKind = EnvironmentKind.WORKBENCH_VM) -> Template:
    return Template("template-1", "in-memory", "fictional-os", "x64", "sha256:image", purpose)


def test_provider_registry_registration_and_availability() -> None:
    registry = ProviderRegistry()
    provider = InMemoryVirtualizationProvider()
    registry.register(provider)
    assert registry.get("in-memory") is provider
    assert provider.probe() is VirtualizationAvailability.AVAILABLE
    with pytest.raises(ValueError, match="already registered"):
        registry.register(provider)


@pytest.mark.asyncio
async def test_fake_provider_lifecycle_execute_snapshot_revert_and_destroy() -> None:
    provider = InMemoryVirtualizationProvider()
    instance = await provider.create(template())
    assert instance.state is InstanceState.READY
    ready = await provider.wait_guest_ready(instance.instance_id)
    result = await provider.execute(ready.instance_id, GuestCommand("echo", ("hello",)))
    assert result.exit_code == 0
    assert result.evidence_digest
    await provider.snapshot(instance.instance_id, "clean")
    await provider.revert(instance.instance_id, "clean")
    destroyed = await provider.destroy(instance.instance_id)
    assert destroyed.state is InstanceState.DESTROYED


@pytest.mark.asyncio
async def test_fake_provider_timeout_cancel_and_failures() -> None:
    provider = InMemoryVirtualizationProvider()
    instance = await provider.create(template())
    assert (await provider.execute(instance.instance_id, GuestCommand("timeout"))).timed_out
    assert (await provider.execute(instance.instance_id, GuestCommand("cancel"))).cancelled
    provider.fail_next("start")
    with pytest.raises(RuntimeError, match="provider start failed"):
        await provider.start(instance.instance_id)


@pytest.mark.asyncio
async def test_fabric_limits_cleanup_and_orphan_safety() -> None:
    provider = InMemoryVirtualizationProvider()
    fabric = ExecutionFabric(provider, policy=ResourcePolicy(max_workbench_instances=1))
    first = await fabric.create(template())
    with pytest.raises(RuntimeError, match="resource limit"):
        await fabric.create(template())
    assert await fabric.reconcile(frozenset()) == ()
    reconciled = await fabric.reconcile(frozenset({first.instance_id}))
    assert reconciled[0].instance_id == first.instance_id


@pytest.mark.asyncio
async def test_disposable_cleanup_and_repair_instances_are_distinct() -> None:
    provider = InMemoryVirtualizationProvider()
    fabric = ExecutionFabric(provider)
    disposable = await fabric.create(template(EnvironmentKind.DISPOSABLE_TEST_VM))
    repair = await fabric.create(template(EnvironmentKind.DISPOSABLE_REPAIR_VM))
    cleaned = await fabric.cleanup_disposable(disposable.instance_id)
    assert cleaned.state is InstanceState.DESTROYED
    assert repair.purpose is EnvironmentKind.DISPOSABLE_REPAIR_VM


def test_router_is_vm_first_and_host_requires_explicit_effect() -> None:
    router = ExecutionRouter()
    assert router.route(ExecutionIntent("research")).environment is EnvironmentKind.WORKBENCH_VM
    assert (
        router.route(ExecutionIntent("dependency_test")).environment
        is EnvironmentKind.DISPOSABLE_TEST_VM
    )
    assert (
        router.route(ExecutionIntent("repair")).environment is EnvironmentKind.DISPOSABLE_REPAIR_VM
    )
    assert (
        router.route(ExecutionIntent("open_app", host_application_required=True)).environment
        is EnvironmentKind.HOST
    )
    assert (
        router.route(ExecutionIntent("local", explicit_host_request=True)).environment
        is EnvironmentKind.HOST
    )
    assert router.route(ExecutionIntent("planning")).environment is EnvironmentKind.INTERNAL_TRUSTED


def test_vm_suitable_tasks_do_not_request_host_takeover_effects() -> None:
    decision = ExecutionRouter().route(ExecutionIntent("research"))
    assert decision.environment is EnvironmentKind.WORKBENCH_VM
    assert decision.host_bridges == ()
    bridge = HostBridge()
    for operation in (
        HostBridgeOperation.MOUSE_MOVE,
        HostBridgeOperation.KEYBOARD_INPUT,
        HostBridgeOperation.FOCUS_CHANGE,
        HostBridgeOperation.CLIPBOARD_WRITE,
        HostBridgeOperation.APP_LAUNCH,
        HostBridgeOperation.PROCESS_EXECUTE,
    ):
        result = bridge.authorize(
            HostBridgeRequest(uuid4(), uuid4(), uuid4(), operation, "one-resource", "one-scope")
        )
        assert not result.allowed


def test_host_bridge_is_scoped_deny_by_default_and_no_identity_impersonation() -> None:
    bridge = HostBridge()
    request_id = uuid4()
    task_id = uuid4()
    instance_id = uuid4()
    denied = bridge.authorize(
        HostBridgeRequest(
            request_id,
            task_id,
            instance_id,
            HostBridgeOperation.FILE_READ,
            "document.txt",
            "staging",
        )
    )
    assert not denied.allowed
    approved_bridge = HostBridge(permission_verifier=lambda request: request.scope == "staging")
    allowed = approved_bridge.authorize(
        HostBridgeRequest(
            request_id,
            task_id,
            instance_id,
            HostBridgeOperation.FILE_READ,
            "document.txt",
            "staging",
        )
    )
    assert allowed.allowed
    broad = approved_bridge.authorize(
        HostBridgeRequest(
            request_id,
            task_id,
            instance_id,
            HostBridgeOperation.FILE_READ,
            "document.txt",
            "*",
        )
    )
    assert not broad.allowed


def test_host_bridge_expired_request_is_denied_before_permission_verifier() -> None:
    calls: list[HostBridgeRequest] = []

    def verifier(request: HostBridgeRequest) -> bool:
        calls.append(request)
        return True

    bridge = HostBridge(permission_verifier=verifier)
    expired = HostBridgeRequest(
        uuid4(),
        uuid4(),
        uuid4(),
        HostBridgeOperation.FILE_READ,
        "document.txt",
        "staging",
        expires_at=datetime.now(UTC) - timedelta(minutes=1),
    )

    result = bridge.authorize(expired)

    assert result.allowed is False
    assert result.reason == "request expired"
    assert calls == []


def test_unavailable_provider_does_not_fabricate_readiness() -> None:
    assert (
        InMemoryVirtualizationProvider(available=False).probe()
        is VirtualizationAvailability.UNAVAILABLE
    )
    result = probe_windows_host()
    assert result.availability in VirtualizationAvailability


def test_running_hypervisor_overrides_misleading_processor_false_values() -> None:
    result = classify_windows_readiness(
        hypervisor_present=True,
        firmware_virtualization_enabled=False,
        vm_monitor_mode_extensions=False,
        wsl_runtime_available=True,
    )
    assert result[0] is VirtualizationAvailability.AVAILABLE
    assert result[1] is False


def test_processor_false_values_block_only_before_hypervisor() -> None:
    result = classify_windows_readiness(
        hypervisor_present=False,
        firmware_virtualization_enabled=False,
        vm_monitor_mode_extensions=False,
    )
    assert result[0] is VirtualizationAvailability.AVAILABLE_REQUIRES_SETUP
    assert result[1] is True


def test_wsl_provider_preserves_contract_and_ownership_state(tmp_path: Path) -> None:
    provider = WSL2VirtualizationProvider(state_path=tmp_path / "state.json")
    assert provider.name == "wsl2"
    assert provider.state_path == tmp_path / "state.json"


@pytest.mark.asyncio
async def test_wsl_provider_creation_requires_owned_distribution_and_persists_instance(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    with pytest.raises(ValueError, match="deadlines must be positive"):
        WSL2VirtualizationProvider(state_path=tmp_path / "invalid.json", startup_timeout_seconds=0)
    provider = WSL2VirtualizationProvider(state_path=tmp_path / "state.json")
    wsl_template = Template(
        "jarvis-workbench", "wsl2", "linux", "x64", "sha256:image", EnvironmentKind.WORKBENCH_VM
    )
    calls: list[tuple[str, ...]] = []

    def run(*args: str, **kwargs: object) -> subprocess.CompletedProcess[str]:
        del kwargs
        calls.append(args)
        return subprocess.CompletedProcess(args, 0, "", "")

    monkeypatch.setattr(provider, "_run", run)
    with pytest.raises(ValueError, match="not for WSL2"):
        await provider.create(template())
    with pytest.raises(RuntimeError, match="explicit trusted installation"):
        await provider.create(wsl_template)

    monkeypatch.setattr(
        provider,
        "_run",
        lambda *args, **kwargs: subprocess.CompletedProcess(args, 0, "jarvis-workbench\n", ""),
    )
    instance = await provider.create(wsl_template)

    assert instance.template_id == "jarvis-workbench"
    assert instance.state is InstanceState.STOPPED
    assert (await provider.instances()) == (instance,)
    assert calls == [("--list", "--quiet")]

    restored = WSL2VirtualizationProvider(state_path=tmp_path / "state.json")
    restored_instance = (await restored.instances())[0]
    assert restored_instance.instance_id == instance.instance_id
    assert restored_instance.template_id == instance.template_id
    assert restored_instance.state is InstanceState.STOPPED


@pytest.mark.asyncio
async def test_wsl_provider_lifecycle_executes_commands_and_reconciles_ownership(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    provider = WSL2VirtualizationProvider(state_path=tmp_path / "state.json")
    instance = _owned_instance(provider)
    calls: list[tuple[str, ...]] = []

    def run(*args: str, **kwargs: object) -> subprocess.CompletedProcess[str]:
        del kwargs
        calls.append(args)
        if args[:2] == ("--list", "--quiet"):
            return subprocess.CompletedProcess(args, 0, "jarvis-workbench\n", "")
        return subprocess.CompletedProcess(args, 0, "stdout", "")

    monkeypatch.setattr(provider, "_run", run)
    started = await provider.start(instance.instance_id)
    assert started.state is InstanceState.STARTING
    provider._records[instance.instance_id] = provider._set(started, InstanceState.READY)  # noqa: SLF001

    result = await provider.execute(instance.instance_id, GuestCommand("echo", ("hello",)))
    assert result.exit_code == 0
    assert result.stdout == "stdout"
    assert result.evidence_digest

    stopped = await provider.stop(instance.instance_id)
    assert stopped.state is InstanceState.STOPPED
    destroyed = await provider.destroy(instance.instance_id)
    assert destroyed.state is InstanceState.DESTROYED

    provider._records[instance.instance_id] = started  # noqa: SLF001
    monkeypatch.setattr(
        provider,
        "_run",
        lambda *args, **kwargs: subprocess.CompletedProcess(args, 0, "", ""),
    )
    reconciled = await provider.reconcile()
    assert reconciled[0].state is InstanceState.DESTROYED


def test_wsl_probe_text_and_output_decoding_preserve_error_classification() -> None:
    assert _classify_probe_text("", "backend temporarily unavailable") == "transient_wsl_error"
    assert _classify_probe_text("", "The distribution was not found") == "fatal_wsl_error"
    assert _decode_wsl_output("j\x00a\x00r\x00v\x00i\x00s\x00") == "jarvis"
    assert _decode_wsl_output("j\x00a\x00r\x00v\x00i\x00s\x00\x00") == "jarvis"


class _FakeClock:
    def __init__(self) -> None:
        self.value = 0.0

    def now(self) -> float:
        return self.value

    async def sleep(self, seconds: float) -> None:
        self.value += seconds


class _ProbeProvider(WSL2VirtualizationProvider):
    def __init__(self, tmp_path: Path, outcomes: list[ReadinessProbeStatus]) -> None:
        self.clock = _FakeClock()
        self.outcomes = outcomes
        self.probe_timeouts: list[float] = []
        super().__init__(
            state_path=tmp_path / "state.json",
            clock=self.clock.now,
            sleeper=self.clock.sleep,
            startup_timeout_seconds=2.0,
            readiness_probe_timeout_seconds=0.5,
        )

    async def _readiness_probe(self, distribution: str, timeout: float) -> _ProbeResult:
        assert distribution.startswith("jarvis-")
        self.probe_timeouts.append(timeout)
        outcome = self.outcomes.pop(0)
        if outcome is ReadinessProbeStatus.PROBE_TIMEOUT:
            self.clock.value += timeout
        return _ProbeResult(outcome, 0)


def _owned_instance(
    provider: WSL2VirtualizationProvider, purpose: EnvironmentKind = EnvironmentKind.WORKBENCH_VM
) -> Instance:
    instance = Instance(
        uuid4(),
        "jarvis-workbench"
        if purpose is EnvironmentKind.WORKBENCH_VM
        else "jarvis-acceptance-clone",
        provider.name,
        purpose,
        None,
        InstanceState.STOPPED,
        template().network_policy,
    )
    provider._records[instance.instance_id] = instance  # noqa: SLF001
    return instance


@pytest.mark.asyncio
async def test_wsl_readiness_recovers_after_transient_probe_timeout(tmp_path: Path) -> None:
    provider = _ProbeProvider(
        tmp_path,
        [ReadinessProbeStatus.PROBE_TIMEOUT, ReadinessProbeStatus.READY],
    )
    instance = _owned_instance(provider)
    await provider.start(instance.instance_id)
    ready = await provider.wait_guest_ready(instance.instance_id)
    assert ready.state is InstanceState.READY
    assert len(provider.probe_timeouts) == 2
    assert provider.last_readiness[-1].state is ReadinessState.READY
    assert provider.last_readiness[3].status is ReadinessProbeStatus.PROBE_TIMEOUT


@pytest.mark.asyncio
async def test_wsl_immediate_readiness_and_idempotent_same_operation_state(
    tmp_path: Path,
) -> None:
    provider = _ProbeProvider(tmp_path, [ReadinessProbeStatus.READY])
    instance = _owned_instance(provider)
    await provider.start(instance.instance_id)
    assert (await provider.wait_guest_ready(instance.instance_id)).state is InstanceState.READY
    assert (await provider.wait_guest_ready(instance.instance_id)).state is InstanceState.READY
    assert len(provider.probe_timeouts) == 1


@pytest.mark.asyncio
async def test_wsl_repeated_transient_probe_timeouts_respect_overall_deadline(
    tmp_path: Path,
) -> None:
    provider = _ProbeProvider(tmp_path, [ReadinessProbeStatus.PROBE_TIMEOUT] * 10)
    instance = _owned_instance(provider)
    with pytest.raises(TimeoutError, match="overall deadline"):
        await provider.wait_guest_ready(instance.instance_id, timeout_seconds=1.0)
    assert provider.last_readiness[-1].state is ReadinessState.TIMED_OUT
    assert provider.clock.value <= 1.0


@pytest.mark.asyncio
async def test_wsl_expired_overall_deadline_does_not_spawn_a_probe(tmp_path: Path) -> None:
    provider = _ProbeProvider(tmp_path, [])
    instance = _owned_instance(provider)
    clock_calls = 0

    def advancing_clock() -> float:
        nonlocal clock_calls
        clock_calls += 1
        return 0.0 if clock_calls == 1 else 1.0

    provider._clock = advancing_clock  # noqa: SLF001
    with pytest.raises(TimeoutError, match="overall deadline"):
        await provider.wait_guest_ready(instance.instance_id, timeout_seconds=1.0)
    assert provider.probe_timeouts == []


@pytest.mark.asyncio
async def test_wsl_fatal_probe_fails_without_another_probe(tmp_path: Path) -> None:
    provider = _ProbeProvider(tmp_path, [ReadinessProbeStatus.FATAL_FAILURE])
    instance = _owned_instance(provider)
    with pytest.raises(RuntimeError, match="guest readiness failed"):
        await provider.wait_guest_ready(instance.instance_id)
    assert len(provider.probe_timeouts) == 1
    assert provider.last_readiness[-1].state is ReadinessState.FAILED


@pytest.mark.asyncio
async def test_wsl_cancellation_is_terminal_and_does_not_restart_guest(tmp_path: Path) -> None:
    provider = _ProbeProvider(tmp_path, [ReadinessProbeStatus.READY])
    instance = _owned_instance(provider)
    entered = asyncio.Event()

    async def blocked_probe(distribution: str, timeout: float) -> _ProbeResult:
        del distribution, timeout
        entered.set()
        await asyncio.Event().wait()
        return _ProbeResult(ReadinessProbeStatus.PROBE_TIMEOUT)

    provider._readiness_probe = blocked_probe  # type: ignore[method-assign]
    task = asyncio.create_task(provider.wait_guest_ready(instance.instance_id))
    await entered.wait()
    task.cancel()
    with pytest.raises(asyncio.CancelledError):
        await task
    assert provider.last_readiness[-1].state is ReadinessState.CANCELLED
    assert len(provider.probe_timeouts) == 0


@pytest.mark.asyncio
async def test_wsl_persistent_and_disposable_instances_share_readiness_contract(
    tmp_path: Path,
) -> None:
    provider = _ProbeProvider(tmp_path, [ReadinessProbeStatus.READY, ReadinessProbeStatus.READY])
    persistent = _owned_instance(provider)
    disposable = _owned_instance(provider, EnvironmentKind.DISPOSABLE_TEST_VM)
    await provider.start(persistent.instance_id)
    await provider.start(disposable.instance_id)
    assert (await provider.wait_guest_ready(persistent.instance_id)).state is InstanceState.READY
    assert (await provider.wait_guest_ready(disposable.instance_id)).state is InstanceState.READY
    assert len(provider.probe_timeouts) == 2


@pytest.mark.asyncio
async def test_wsl_probe_timeout_kills_only_exact_probe_process(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    class _Process:
        returncode: int | None = None
        killed = False

        async def communicate(self) -> tuple[bytes, bytes]:
            if not self.killed:
                raise TimeoutError
            return b"", b""

        def kill(self) -> None:
            self.killed = True
            self.returncode = -9

    process = _Process()
    calls: list[tuple[str, ...]] = []

    async def create_process(*args: str, **kwargs: object) -> _Process:
        del kwargs
        calls.append(args)
        return process

    monkeypatch.setattr(asyncio, "create_subprocess_exec", create_process)
    provider = WSL2VirtualizationProvider(state_path=tmp_path / "state.json")
    result = await provider._readiness_probe("jarvis-workbench", 0.01)  # noqa: SLF001
    assert result.status is ReadinessProbeStatus.PROBE_TIMEOUT
    assert process.killed
    assert calls == [("wsl.exe", "--distribution", "jarvis-workbench", "--exec", "true")]


@pytest.mark.asyncio
async def test_wsl_probe_classifies_ready_transient_and_fatal_results(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    class _Process:
        def __init__(self, returncode: int, stderr: bytes) -> None:
            self.returncode = returncode
            self.stderr = stderr

        async def communicate(self) -> tuple[bytes, bytes]:
            return b"", self.stderr

        def kill(self) -> None:
            raise AssertionError("a completed probe must not be killed")

    processes = [
        _Process(0, b""),
        _Process(1, b"backend temporarily unavailable"),
        _Process(1, b"The distribution was not found"),
    ]

    async def create_process(*args: str, **kwargs: object) -> _Process:
        del args, kwargs
        return processes.pop(0)

    monkeypatch.setattr(asyncio, "create_subprocess_exec", create_process)
    provider = WSL2VirtualizationProvider(state_path=tmp_path / "state.json")
    assert (
        await provider._readiness_probe("jarvis-workbench", 0.01)  # noqa: SLF001
    ).status is ReadinessProbeStatus.READY
    assert (
        await provider._readiness_probe("jarvis-workbench", 0.01)  # noqa: SLF001
    ).status is ReadinessProbeStatus.TEMPORARILY_UNAVAILABLE
    assert (
        await provider._readiness_probe("jarvis-workbench", 0.01)  # noqa: SLF001
    ).status is ReadinessProbeStatus.FATAL_FAILURE


@pytest.mark.asyncio
async def test_wsl_probe_start_error_is_fatal(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    async def create_process(*args: str, **kwargs: object) -> _ProbeResult:
        del args, kwargs
        raise OSError("wsl executable unavailable")

    monkeypatch.setattr(asyncio, "create_subprocess_exec", create_process)
    provider = WSL2VirtualizationProvider(state_path=tmp_path / "state.json")
    result = await provider._readiness_probe("jarvis-workbench", 0.01)  # noqa: SLF001
    assert result.status is ReadinessProbeStatus.FATAL_FAILURE


@pytest.mark.asyncio
async def test_wsl_probe_cancellation_kills_exact_process(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    class _Process:
        returncode: int | None = None
        killed = False

        async def communicate(self) -> tuple[bytes, bytes]:
            if not self.killed:
                await asyncio.Event().wait()
            return b"", b""

        def kill(self) -> None:
            self.killed = True
            self.returncode = -9

    process = _Process()
    provider = WSL2VirtualizationProvider(state_path=tmp_path / "state.json")

    async def create_process(*args: str, **kwargs: object) -> _Process:
        del args, kwargs
        return process

    monkeypatch.setattr(asyncio, "create_subprocess_exec", create_process)
    task = asyncio.create_task(provider._readiness_probe("jarvis-workbench", 10.0))  # noqa: SLF001
    await asyncio.sleep(0)
    task.cancel()
    with pytest.raises(asyncio.CancelledError):
        await task
    assert process.killed
