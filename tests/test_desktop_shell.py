from __future__ import annotations

import asyncio
from uuid import uuid4

import pytest
from jarvis.desktop_shell import (
    DesktopShellError,
    DesktopShellService,
    DesktopShellState,
    FirstRunWizard,
    LaunchProfile,
    LaunchProfileRegistry,
    LaunchProfileSelection,
    OnboardingResult,
    OnboardingState,
    OnboardingStep,
    OnboardingStepRegistry,
    ShellNavigationItem,
    ShellSection,
    StartupWarmupRegistry,
    WarmupComponent,
    WarmupResult,
    WarmupStatus,
)
from jarvis.desktop_shell import (
    TestDriveRegistry as DriveRegistry,
)
from jarvis.desktop_shell import (
    TestDriveStatus as DriveStatus,
)
from jarvis.desktop_shell import (
    TestDriveStep as DriveStep,
)
from jarvis.desktop_shell import (
    TestDriveStepResult as DriveStepResult,
)
from jarvis.provisioning import ProvisioningPlan, ProvisioningPlanState, ProvisioningResult
from jarvis.setup_conductor import (
    InMemorySetupStore,
    SetupConductor,
    SetupContext,
    SetupInspection,
    SetupStep,
)


class Handler:
    async def inspect(self, step: SetupStep, context: SetupContext) -> SetupInspection:
        del step, context
        return SetupInspection()

    async def prepare(self, step: SetupStep, context: SetupContext, decision: object) -> None:
        del step, context, decision
        return None

    async def configure(self, step: SetupStep, context: SetupContext) -> None:
        del step, context

    async def verify(self, step: SetupStep, context: SetupContext) -> bool:
        del step, context
        return True

    async def first_start(self, step: SetupStep, context: SetupContext) -> bool:
        del step, context
        return True


async def provision(plan: ProvisioningPlan) -> ProvisioningResult:
    return ProvisioningResult(uuid4(), ProvisioningPlanState.VERIFIED, (), "verified")


def wizard() -> FirstRunWizard:
    registry = OnboardingStepRegistry()
    registry.register(OnboardingStep(SetupStep("runtime", "runtime")))
    conductor = SetupConductor({"runtime": Handler()}, InMemorySetupStore(), provision)
    return FirstRunWizard(conductor, registry)


def test_shell_navigation_and_launch_profiles_do_not_change_policy() -> None:
    profiles = LaunchProfileRegistry()
    shell = DesktopShellService(launch_profiles=profiles, health="ready")
    assert tuple(item.section for item in shell.navigation) == tuple(ShellSection)
    assert shell.state().active_section is ShellSection.HOME
    assert shell.select_section(ShellSection.TASKS).active_section is ShellSection.TASKS
    selection = profiles.select(LaunchProfile.PRIVACY)
    assert selection.profile is LaunchProfile.PRIVACY
    assert selection.security_policy_version == 1
    assert shell.select_launch_profile(LaunchProfile.SAFE_MODE).safe_mode is False


def test_shell_metadata_validation_is_strict() -> None:
    with pytest.raises(ValueError):
        ShellNavigationItem("home", "Home")  # type: ignore[arg-type]
    with pytest.raises(ValueError):
        LaunchProfileSelection(LaunchProfile.NORMAL, 0)
    with pytest.raises(ValueError):
        DesktopShellState(ShellSection.HOME, LaunchProfile.NORMAL, "false", "ready")  # type: ignore[arg-type]
    with pytest.raises(ValueError):
        DesktopShellService(safe_mode="false")  # type: ignore[arg-type]
    with pytest.raises(ValueError):
        DesktopShellService().select_section("home")  # type: ignore[arg-type]


@pytest.mark.asyncio
async def test_onboarding_is_optional_skippable_and_resumable() -> None:
    skipped = wizard().skip()
    assert skipped.state is OnboardingState.SKIPPED
    assert skipped.resumable is False

    service = wizard()
    first = await service.run(SetupContext())
    assert first.state is OnboardingState.COMPLETED
    assert first.run is not None
    resumed = await service.resume(SetupContext(), first.run.run_id)
    assert resumed.state is OnboardingState.COMPLETED


@pytest.mark.asyncio
async def test_onboarding_without_available_components_is_safe() -> None:
    steps = OnboardingStepRegistry()
    steps.register(OnboardingStep(SetupStep("voice", "voice"), available=False))
    conductor = SetupConductor({"voice": Handler()}, InMemorySetupStore(), provision)
    result = await FirstRunWizard(conductor, steps).run(SetupContext())
    assert result.state is OnboardingState.SKIPPED
    assert result.run is None


def test_onboarding_registry_validation_and_duplicate() -> None:
    registry = OnboardingStepRegistry()
    item = OnboardingStep(SetupStep("runtime", "runtime"))
    registry.register(item)
    with pytest.raises(DesktopShellError):
        registry.register(item)
    assert registry.all_steps() == (item,)
    with pytest.raises(ValueError):
        registry.register(object())  # type: ignore[arg-type]
    with pytest.raises(ValueError):
        OnboardingStep(object())  # type: ignore[arg-type]


def test_onboarding_result_validation() -> None:
    with pytest.raises(ValueError):
        OnboardingResult("bad")  # type: ignore[arg-type]
    with pytest.raises(ValueError):
        OnboardingResult(OnboardingState.COMPLETED, object())  # type: ignore[arg-type]


@pytest.mark.asyncio
async def test_test_drive_reports_pass_fail_skipped_and_unavailable() -> None:
    async def passed() -> DriveStepResult:
        return DriveStepResult(DriveStatus.PASS, "passed", ("evidence",))

    async def failed() -> DriveStepResult:
        raise RuntimeError("provider unavailable")

    registry = DriveRegistry()
    registry.register(DriveStep("pass", "Pass", passed))
    registry.register(DriveStep("fail", "Fail", failed))
    registry.register(DriveStep("skip", "Skip", passed, required=False))
    registry.register(DriveStep("later", "Later", passed, required=False, available=False))
    report = await registry.run(skip=("skip",))
    statuses = dict(report.results)
    assert statuses["pass"].status is DriveStatus.PASS
    assert statuses["fail"].status is DriveStatus.FAIL
    assert statuses["skip"].status is DriveStatus.SKIPPED
    assert statuses["later"].status is DriveStatus.NOT_AVAILABLE
    assert report.fully_ready is False
    assert "incomplete" in report.readiness_message

    ready = DriveRegistry()
    ready.register(DriveStep("required", "Required", passed))
    ready.register(DriveStep("optional", "Optional", passed, required=False, available=False))
    ready_report = await ready.run()
    assert ready_report.fully_ready is True
    assert ready_report.readiness_message == "JARVIS is fully ready"


@pytest.mark.asyncio
async def test_test_drive_rerun_and_registry_collisions() -> None:
    async def passed() -> DriveStepResult:
        return DriveStepResult(DriveStatus.PASS, "passed")

    registry = DriveRegistry()
    step = DriveStep("check", "Check", passed)
    registry.register(step)
    with pytest.raises(DesktopShellError):
        registry.register(step)
    assert len((await registry.run()).results) == 1
    registry.unregister("check")
    assert registry.steps() == ()


@pytest.mark.asyncio
async def test_test_drive_malformed_runner_and_cancellation_are_not_success() -> None:
    async def malformed() -> object:
        return object()

    registry = DriveRegistry()
    registry.register(DriveStep("malformed", "Malformed", malformed))  # type: ignore[arg-type]
    report = await registry.run()
    assert dict(report.results)["malformed"].status is DriveStatus.FAIL

    async def cancelled() -> DriveStepResult:
        raise asyncio.CancelledError

    cancelled_registry = DriveRegistry()
    cancelled_registry.register(DriveStep("cancelled", "Cancelled", cancelled))
    with pytest.raises(asyncio.CancelledError):
        await cancelled_registry.run()


@pytest.mark.asyncio
async def test_startup_warmup_is_non_blocking_and_isolated() -> None:
    started = asyncio.Event()
    release = asyncio.Event()

    async def slow() -> None:
        started.set()
        await release.wait()

    async def broken() -> None:
        raise RuntimeError("warmup failure")

    warmup = StartupWarmupRegistry()
    warmup.register(WarmupComponent("slow", slow))
    warmup.register(WarmupComponent("broken", broken))
    warmup.register(WarmupComponent("later", slow, available=False))
    task = warmup.start()
    assert not task.done()
    await started.wait()
    release.set()
    results = await warmup.wait()
    statuses = {item.component_id: item.status for item in results}
    assert statuses == {
        "slow": WarmupStatus.READY,
        "broken": WarmupStatus.FAILED,
        "later": WarmupStatus.NOT_AVAILABLE,
    }
    assert warmup.results == results
    await warmup.aclose()


@pytest.mark.asyncio
async def test_startup_warmup_wait_without_start_and_cancellation() -> None:
    warmup = StartupWarmupRegistry()
    assert await warmup.wait() == ()
    release = asyncio.Event()

    async def slow() -> None:
        await release.wait()

    warmup.register(WarmupComponent("slow", slow))
    task = warmup.start()
    await asyncio.sleep(0)
    assert warmup.start() is task
    await warmup.aclose()


def test_warmup_rejects_sync_start_without_event_loop() -> None:
    with pytest.raises(DesktopShellError):
        StartupWarmupRegistry().start()


@pytest.mark.asyncio
async def test_startup_warmup_obeys_governor_and_can_restart() -> None:
    class Governor:
        async def admit(self, component_id: str) -> bool:
            return component_id != "denied"

    async def noop() -> None:
        return None

    warmup = StartupWarmupRegistry(Governor())
    warmup.register(WarmupComponent("denied", noop))
    first = warmup.start()
    assert (await first)[0].status is WarmupStatus.SKIPPED
    second = warmup.start()
    assert (await second)[0].status is WarmupStatus.SKIPPED


def test_invalid_shell_registry_inputs_fail_closed() -> None:
    with pytest.raises(ValueError):
        DesktopShellService(health="")
    with pytest.raises(ValueError):
        LaunchProfileRegistry(initial="normal")  # type: ignore[arg-type]
    with pytest.raises(ValueError):
        OnboardingStepRegistry().unregister("bad id!")
    with pytest.raises(ValueError):
        DriveStep("bad id!", "Bad", lambda: _never())
    with pytest.raises(ValueError):
        DriveStepResult("bad", "detail")  # type: ignore[arg-type]
    with pytest.raises(ValueError):
        WarmupComponent("bad id!", noop_warmup)
    with pytest.raises(ValueError):
        WarmupComponent("valid", noop_warmup, available="yes")  # type: ignore[arg-type]
    with pytest.raises(ValueError):
        WarmupResult("valid", "bad", "detail")  # type: ignore[arg-type]


async def _never() -> DriveStepResult:
    return DriveStepResult(DriveStatus.PASS, "never")


async def noop_warmup() -> None:
    return None
