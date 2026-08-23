"""Application-owned desktop shell, onboarding, test-drive, and warmup contracts.

These are generic UI/application services.  They do not contain product
integrations, grant permissions, or replace SetupConductor, PlanningEngine, or
the runtime security constitution.
"""

from __future__ import annotations

import asyncio
from collections.abc import Awaitable, Callable, Iterable
from dataclasses import dataclass
from datetime import UTC, datetime
from enum import StrEnum
from typing import Protocol
from uuid import UUID

from jarvis.setup_conductor import (
    SetupConductor,
    SetupContext,
    SetupRun,
    SetupRunState,
    SetupStep,
)


class DesktopShellError(RuntimeError):
    """The application shell contract could not be satisfied."""


class DesktopShellValidationError(DesktopShellError, ValueError):
    """Shell, onboarding, test-drive, or warmup metadata is malformed."""


def _text(value: object, name: str, limit: int = 512) -> str:
    if type(value) is not str or not value.strip() or len(value) > limit or "\x00" in value:
        raise DesktopShellValidationError(f"{name} is malformed")
    return value


def _id(value: object, name: str) -> str:
    value = _text(value, name, 128)
    if any(character not in "abcdefghijklmnopqrstuvwxyz0123456789._-" for character in value):
        raise DesktopShellValidationError(f"{name} is malformed")
    return value


def _labels(values: Iterable[str], name: str, limit: int = 64) -> None:
    values = tuple(values)
    if len(values) > limit or any(
        type(value) is not str or not value.strip() or len(value) > 2_000 or "\x00" in value
        for value in values
    ):
        raise DesktopShellValidationError(f"{name} are malformed")


class ShellSection(StrEnum):
    HOME = "home"
    TASKS = "tasks"
    MEMORY = "memory"
    CAPABILITIES = "capabilities"
    ACTIVITY = "activity"
    SETTINGS = "settings"


@dataclass(frozen=True, slots=True)
class ShellNavigationItem:
    section: ShellSection
    label: str

    def __post_init__(self) -> None:
        if not isinstance(self.section, ShellSection):
            raise DesktopShellValidationError("Shell section is malformed")
        _text(self.label, "Shell navigation label", 64)


class LaunchProfile(StrEnum):
    NORMAL = "normal"
    VOICE = "voice"
    FOCUS = "focus"
    PRIVACY = "privacy"
    PRESENTATION = "presentation"
    SAFE_MODE = "safe_mode"
    DEVELOPER = "developer"


@dataclass(frozen=True, slots=True)
class LaunchProfileSelection:
    profile: LaunchProfile
    security_policy_version: int = 1

    def __post_init__(self) -> None:
        if (
            not isinstance(self.profile, LaunchProfile)
            or type(self.security_policy_version) is not int
        ):
            raise DesktopShellValidationError("Launch profile selection is malformed")
        if self.security_policy_version < 1:
            raise DesktopShellValidationError("Launch profile policy version is malformed")


class LaunchProfileRegistry:
    """Expose presentation/startup profiles without changing authority policy."""

    def __init__(self, initial: LaunchProfile = LaunchProfile.NORMAL) -> None:
        if not isinstance(initial, LaunchProfile):
            raise DesktopShellValidationError("Launch profile is malformed")
        self._selection = LaunchProfileSelection(initial)

    @property
    def selection(self) -> LaunchProfileSelection:
        return self._selection

    def select(self, profile: LaunchProfile) -> LaunchProfileSelection:
        if not isinstance(profile, LaunchProfile):
            raise DesktopShellValidationError("Launch profile is malformed")
        self._selection = LaunchProfileSelection(profile, self._selection.security_policy_version)
        return self._selection


@dataclass(frozen=True, slots=True)
class DesktopShellState:
    active_section: ShellSection
    launch_profile: LaunchProfile
    safe_mode: bool
    health: str

    def __post_init__(self) -> None:
        if not isinstance(self.active_section, ShellSection):
            raise DesktopShellValidationError("Active shell section is malformed")
        if not isinstance(self.launch_profile, LaunchProfile) or type(self.safe_mode) is not bool:
            raise DesktopShellValidationError("Shell state is malformed")
        _text(self.health, "Shell health", 128)


class DesktopShellService:
    """Small UI-facing shell service with generic navigation only."""

    _NAVIGATION = (
        ShellNavigationItem(ShellSection.HOME, "Home"),
        ShellNavigationItem(ShellSection.TASKS, "Tasks"),
        ShellNavigationItem(ShellSection.MEMORY, "Memory"),
        ShellNavigationItem(ShellSection.CAPABILITIES, "Capabilities"),
        ShellNavigationItem(ShellSection.ACTIVITY, "Activity"),
        ShellNavigationItem(ShellSection.SETTINGS, "Settings"),
    )

    def __init__(
        self,
        *,
        launch_profiles: LaunchProfileRegistry | None = None,
        safe_mode: bool = False,
        health: str = "unknown",
    ) -> None:
        if type(safe_mode) is not bool:
            raise DesktopShellValidationError("Safe Mode flag is malformed")
        _text(health, "Shell health", 128)
        self._launch_profiles = launch_profiles or LaunchProfileRegistry()
        self._section = ShellSection.HOME
        self._safe_mode = safe_mode
        self._health = health

    @property
    def navigation(self) -> tuple[ShellNavigationItem, ...]:
        return self._NAVIGATION

    def select_section(self, section: ShellSection) -> DesktopShellState:
        if not isinstance(section, ShellSection):
            raise DesktopShellValidationError("Shell section is malformed")
        self._section = section
        return self.state()

    def select_launch_profile(self, profile: LaunchProfile) -> DesktopShellState:
        self._launch_profiles.select(profile)
        return self.state()

    def state(self) -> DesktopShellState:
        return DesktopShellState(
            self._section,
            self._launch_profiles.selection.profile,
            self._safe_mode,
            self._health,
        )


class OnboardingState(StrEnum):
    NOT_STARTED = "not_started"
    SKIPPED = "skipped"
    RUNNING = "running"
    WAITING = "waiting"
    RECOVERING = "recovering"
    COMPLETED = "completed"
    FAILED = "failed"


@dataclass(frozen=True, slots=True)
class OnboardingStep:
    step: SetupStep
    available: bool = True

    def __post_init__(self) -> None:
        if not isinstance(self.step, SetupStep) or type(self.available) is not bool:
            raise DesktopShellValidationError("Onboarding step is malformed")


class OnboardingStepRegistry:
    """Registry for optional setup areas; SetupConductor remains the executor."""

    def __init__(self) -> None:
        self._steps: dict[str, OnboardingStep] = {}

    def register(self, item: OnboardingStep) -> None:
        if not isinstance(item, OnboardingStep):
            raise DesktopShellValidationError("Onboarding step is malformed")
        if item.step.step_id in self._steps:
            raise DesktopShellError("Onboarding step is already registered")
        self._steps[item.step.step_id] = item

    def unregister(self, step_id: str) -> None:
        self._steps.pop(_id(step_id, "Onboarding step ID"), None)

    def available_steps(self) -> tuple[SetupStep, ...]:
        return tuple(item.step for item in self._steps.values() if item.available)

    def all_steps(self) -> tuple[OnboardingStep, ...]:
        return tuple(self._steps.values())


@dataclass(frozen=True, slots=True)
class OnboardingResult:
    state: OnboardingState
    run: SetupRun | None = None
    detail: str = ""

    def __post_init__(self) -> None:
        if not isinstance(self.state, OnboardingState):
            raise DesktopShellValidationError("Onboarding result state is malformed")
        if self.run is not None and not isinstance(self.run, SetupRun):
            raise DesktopShellValidationError("Onboarding result run is malformed")
        if self.detail:
            _text(self.detail, "Onboarding result detail", 2_048)

    @property
    def resumable(self) -> bool:
        return self.state in {
            OnboardingState.WAITING,
            OnboardingState.RECOVERING,
            OnboardingState.FAILED,
        }


class FirstRunWizard:
    """Optional, skippable, resumable adapter around one SetupConductor run."""

    def __init__(
        self,
        conductor: SetupConductor,
        steps: OnboardingStepRegistry,
        *,
        setup_kind: str = "first_run",
    ) -> None:
        if not isinstance(conductor, SetupConductor) or not isinstance(
            steps, OnboardingStepRegistry
        ):
            raise DesktopShellValidationError("First-run wizard dependencies are malformed")
        self._conductor = conductor
        self._steps = steps
        self._setup_kind = _id(setup_kind, "Setup kind")
        self._last = OnboardingResult(OnboardingState.NOT_STARTED)

    @property
    def last_result(self) -> OnboardingResult:
        return self._last

    def skip(self, detail: str = "setup skipped by user") -> OnboardingResult:
        _text(detail, "Skip detail", 2_048)
        self._last = OnboardingResult(OnboardingState.SKIPPED, detail=detail)
        return self._last

    async def run(
        self,
        context: SetupContext,
        *,
        run_id: UUID | None = None,
        cancellation: asyncio.Event | None = None,
    ) -> OnboardingResult:
        if not isinstance(context, SetupContext):
            raise DesktopShellValidationError("Onboarding context is malformed")
        available = self._steps.available_steps()
        if not available:
            self._last = OnboardingResult(
                OnboardingState.SKIPPED,
                detail="no setup areas are currently available",
            )
            return self._last
        self._last = OnboardingResult(OnboardingState.RUNNING)
        result = await self._conductor.run(
            self._setup_kind,
            available,
            context,
            run_id=run_id,
            cancellation=cancellation,
        )
        state = {
            SetupRunState.WAITING_DECISIONS: OnboardingState.WAITING,
            SetupRunState.RECOVERING: OnboardingState.RECOVERING,
            SetupRunState.COMPLETED: OnboardingState.COMPLETED,
            SetupRunState.FAILED: OnboardingState.FAILED,
        }.get(result.state, OnboardingState.RUNNING)
        self._last = OnboardingResult(state, result, result.error or result.state.value)
        return self._last

    async def resume(
        self,
        context: SetupContext,
        run_id: UUID,
        *,
        cancellation: asyncio.Event | None = None,
    ) -> OnboardingResult:
        if not isinstance(run_id, UUID):
            raise DesktopShellValidationError("Onboarding run ID is malformed")
        return await self.run(context, run_id=run_id, cancellation=cancellation)


class TestDriveStatus(StrEnum):
    PASS = "PASS"
    FAIL = "FAIL"
    SKIPPED = "SKIPPED"
    NOT_AVAILABLE = "NOT_AVAILABLE"


@dataclass(frozen=True, slots=True)
class TestDriveStepResult:
    status: TestDriveStatus
    detail: str
    evidence: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        if not isinstance(self.status, TestDriveStatus):
            raise DesktopShellValidationError("Test-drive status is malformed")
        _text(self.detail, "Test-drive detail", 2_048)
        _labels(self.evidence, "Test-drive evidence")


TestDriveRunner = Callable[[], Awaitable[TestDriveStepResult]]


@dataclass(frozen=True, slots=True)
class TestDriveStep:
    step_id: str
    title: str
    runner: TestDriveRunner
    required: bool = True
    available: bool = True

    def __post_init__(self) -> None:
        _id(self.step_id, "Test-drive step ID")
        _text(self.title, "Test-drive title", 128)
        if (
            not callable(self.runner)
            or type(self.required) is not bool
            or type(self.available) is not bool
        ):
            raise DesktopShellValidationError("Test-drive step is malformed")


@dataclass(frozen=True, slots=True)
class TestDriveReport:
    results: tuple[tuple[str, TestDriveStepResult], ...]
    completed_at: datetime
    required_step_ids: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        if type(self.results) is not tuple or any(
            type(step_id) is not str or not isinstance(result, TestDriveStepResult)
            for step_id, result in self.results
        ):
            raise DesktopShellValidationError("Test-drive results are malformed")
        if self.completed_at.tzinfo is None:
            raise DesktopShellValidationError("Test-drive timestamp must be timezone-aware")
        _labels(self.required_step_ids, "Required test-drive step IDs")

    @property
    def fully_ready(self) -> bool:
        results = dict(self.results)
        required = tuple(
            results[step_id] for step_id in self.required_step_ids if step_id in results
        )
        return (
            bool(required)
            and len(required) == len(self.required_step_ids)
            and all(result.status is TestDriveStatus.PASS for result in required)
        )

    @property
    def readiness_message(self) -> str:
        return (
            "JARVIS is fully ready"
            if self.fully_ready
            else "Test drive incomplete; required checks have not all passed"
        )


class TestDriveRegistry:
    """Composable checks for configured capabilities, not a generic setup claim."""

    def __init__(self, *, clock: Callable[[], datetime] | None = None) -> None:
        self._steps: dict[str, TestDriveStep] = {}
        self._clock = clock or (lambda: datetime.now(UTC))

    def register(self, step: TestDriveStep) -> None:
        if not isinstance(step, TestDriveStep):
            raise DesktopShellValidationError("Test-drive step is malformed")
        if step.step_id in self._steps:
            raise DesktopShellError("Test-drive step is already registered")
        self._steps[step.step_id] = step

    def unregister(self, step_id: str) -> None:
        self._steps.pop(_id(step_id, "Test-drive step ID"), None)

    def steps(self) -> tuple[TestDriveStep, ...]:
        return tuple(self._steps.values())

    async def run(self, *, skip: Iterable[str] = ()) -> TestDriveReport:
        skipped = {_id(item, "Skipped test-drive step ID") for item in skip}
        results: list[tuple[str, TestDriveStepResult]] = []
        for step in self._steps.values():
            if not step.available:
                result = TestDriveStepResult(
                    TestDriveStatus.NOT_AVAILABLE, "capability is not available"
                )
            elif step.step_id in skipped:
                result = TestDriveStepResult(TestDriveStatus.SKIPPED, "skipped by user")
            else:
                try:
                    result = await step.runner()
                    if not isinstance(result, TestDriveStepResult):
                        raise DesktopShellValidationError(
                            "test-drive runner returned malformed result"
                        )
                except asyncio.CancelledError:
                    raise
                except Exception as error:
                    result = TestDriveStepResult(TestDriveStatus.FAIL, type(error).__name__)
            results.append((step.step_id, result))
        report = TestDriveReport(
            tuple(results),
            self._clock(),
            tuple(step.step_id for step in self._steps.values() if step.required),
        )
        return report


TestDriveStepRegistry = TestDriveRegistry


class WarmupResourceGovernor(Protocol):
    async def admit(self, component_id: str) -> bool: ...


class WarmupStatus(StrEnum):
    READY = "READY"
    FAILED = "FAILED"
    SKIPPED = "SKIPPED"
    NOT_AVAILABLE = "NOT_AVAILABLE"


@dataclass(frozen=True, slots=True)
class WarmupResult:
    component_id: str
    status: WarmupStatus
    detail: str

    def __post_init__(self) -> None:
        _id(self.component_id, "Warmup component ID")
        if not isinstance(self.status, WarmupStatus):
            raise DesktopShellValidationError("Warmup status is malformed")
        _text(self.detail, "Warmup detail", 2_048)


WarmupRunner = Callable[[], Awaitable[None]]


@dataclass(frozen=True, slots=True)
class WarmupComponent:
    component_id: str
    runner: WarmupRunner
    available: bool = True

    def __post_init__(self) -> None:
        _id(self.component_id, "Warmup component ID")
        if not callable(self.runner) or type(self.available) is not bool:
            raise DesktopShellValidationError("Warmup component is malformed")


class StartupWarmupRegistry:
    """Non-blocking, bounded optional prewarm registry."""

    def __init__(self, governor: WarmupResourceGovernor | None = None) -> None:
        self._components: dict[str, WarmupComponent] = {}
        self._governor = governor
        self._task: asyncio.Task[tuple[WarmupResult, ...]] | None = None
        self._results: tuple[WarmupResult, ...] = ()

    def register(self, component: WarmupComponent) -> None:
        if not isinstance(component, WarmupComponent):
            raise DesktopShellValidationError("Warmup component is malformed")
        if component.component_id in self._components:
            raise DesktopShellError("Warmup component is already registered")
        self._components[component.component_id] = component

    def unregister(self, component_id: str) -> None:
        self._components.pop(_id(component_id, "Warmup component ID"), None)

    def components(self) -> tuple[WarmupComponent, ...]:
        return tuple(self._components.values())

    def start(self) -> asyncio.Task[tuple[WarmupResult, ...]]:
        if self._task is not None and not self._task.done():
            return self._task
        try:
            asyncio.get_running_loop()
        except RuntimeError as error:
            raise DesktopShellError(
                "Startup warmup must start from an active event loop"
            ) from error
        self._task = asyncio.create_task(self._run())
        return self._task

    async def wait(self) -> tuple[WarmupResult, ...]:
        if self._task is None:
            return self._results
        self._results = await self._task
        return self._results

    @property
    def results(self) -> tuple[WarmupResult, ...]:
        return self._results

    async def aclose(self) -> None:
        if self._task is not None and not self._task.done():
            self._task.cancel()
            await asyncio.gather(self._task, return_exceptions=True)

    async def _run(self) -> tuple[WarmupResult, ...]:
        results: list[WarmupResult] = []
        for component in self._components.values():
            if not component.available:
                results.append(
                    WarmupResult(
                        component.component_id, WarmupStatus.NOT_AVAILABLE, "not available"
                    )
                )
                continue
            if self._governor is not None and not await self._governor.admit(
                component.component_id
            ):
                results.append(
                    WarmupResult(
                        component.component_id, WarmupStatus.SKIPPED, "resource governor denied"
                    )
                )
                continue
            try:
                await component.runner()
            except asyncio.CancelledError:
                raise
            except Exception as error:
                results.append(
                    WarmupResult(component.component_id, WarmupStatus.FAILED, type(error).__name__)
                )
            else:
                results.append(WarmupResult(component.component_id, WarmupStatus.READY, "ready"))
        return tuple(results)
