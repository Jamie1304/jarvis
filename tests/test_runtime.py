"""Canonical runtime integration tests; no legacy orchestrator is involved."""

from __future__ import annotations

import asyncio
import inspect
from datetime import UTC, datetime
from pathlib import Path

import pytest
from jarvis import application
from jarvis.browser_broker import BrowserCapabilityStatus
from jarvis.capability_acquisition import CapabilityAcquisitionCoordinator, SolutionDiscovery
from jarvis.capability_health import HealthProbeMode, HealthProbeResult, HealthStatus
from jarvis.control_center import ControlCenterSection
from jarvis.core.config import Settings
from jarvis.credentials import CredentialVault
from jarvis.effects import CompensationService
from jarvis.environment_discovery import EnvironmentDiscoveryService
from jarvis.memory.control import MemoryControlService
from jarvis.memory.services import MemoryConsistencyService
from jarvis.planning.models import PlanningTaskStatus
from jarvis.presence import PresenceProjection
from jarvis.presentation import PresentationSurface
from jarvis.recovery import RecoveryEvidence, RecoveryPhase, RecoveryStore
from jarvis.runtime import ApplicationRuntime, RuntimePaths, RuntimeStatus
from jarvis.task_controller import PlanningTaskController
from jarvis.update_preview import ControlledSelfUpdate


@pytest.mark.asyncio
async def test_canonical_runtime_calculates_and_recovers_persisted_task(tmp_path: Path) -> None:
    settings = Settings(app_data_dir=tmp_path / "jarvis-data", ai_provider="ollama")
    runtime = ApplicationRuntime.create(settings)
    initial_status = runtime.status
    assert initial_status is RuntimeStatus.READY
    assert runtime.container is not None
    assert isinstance(runtime.container.task_controller, PlanningTaskController)
    assert isinstance(runtime.container.capability_acquisition, CapabilityAcquisitionCoordinator)
    assert isinstance(runtime.container.solution_discovery, SolutionDiscovery)
    assert runtime.container.opportunity_engine
    assert runtime.container.opportunity_store
    assert runtime.container.paths.opportunity_database.is_file()
    assert runtime.container.attention_policy
    assert runtime.container.attention_store
    assert runtime.container.paths.attention_database.is_file()
    assert runtime.container.goal_supervisor_store
    assert isinstance(runtime.container.controlled_self_update, ControlledSelfUpdate)
    assert isinstance(runtime.container.credential_vault, CredentialVault)
    assert runtime.container.paths.credential_database.is_file()
    assert id(runtime.container.environment_discovery) != id(runtime.container.discovery)
    assert isinstance(runtime.container.environment_discovery, EnvironmentDiscoveryService)
    assert isinstance(runtime.container.presence_projection, PresenceProjection)
    assert isinstance(runtime.container.presentation_surface, PresentationSurface)
    assert isinstance(runtime.container.compensation_service, CompensationService)
    assert runtime.container.paths.compensation_database.is_file()
    assert runtime.container.tool_registry.permission_broker is runtime.container.permission_broker
    assert runtime.container.voice is None
    assert runtime.container.camera is None
    assert runtime.container.browser_status.value == "unavailable"
    assert runtime.container.service_status("voice").availability.value == "unavailable"
    assert runtime.container.service_status("browser").availability.value == "unavailable"
    assert (
        runtime.container.service_status("environment_discovery").availability.value == "degraded"
    )
    assert {item.service_id for item in runtime.container.service_statuses()} == {
        "voice",
        "camera",
        "browser",
        "environment_discovery",
        "presentation",
        "ui_simulation",
    }
    with pytest.raises(ValueError):
        runtime.container.service_status("")
    with pytest.raises(KeyError):
        runtime.container.service_status("unknown")
    object.__setattr__(runtime.container, "voice", object())
    object.__setattr__(runtime.container, "camera", object())
    object.__setattr__(runtime.container, "browser", object())
    object.__setattr__(runtime.container, "browser_status", BrowserCapabilityStatus.DEGRADED)
    assert runtime.container.service_status("voice").availability.value == "available"
    assert runtime.container.service_status("camera").availability.value == "available"
    assert runtime.container.service_status("browser").availability.value == "degraded"
    assert id(runtime.container.permission_broker) != id(
        runtime.container.capability_lifecycle_store
    )
    assert id(runtime.container.planning_engine) != id(runtime.container.goal_supervisor)
    assert isinstance(runtime.container.memory_consistency, MemoryConsistencyService)
    assert isinstance(runtime.container.memory_control, MemoryControlService)
    assert runtime.container.backup.installation_id
    assert runtime.container.paths.backups.is_dir()
    assert (runtime.container.paths.backups / "installation-id").is_file()
    assert runtime.container.user_model_store.database_path == (
        runtime.container.paths.user_model_database
    )
    assert runtime.container.golden_workflow_store.database_path == (
        runtime.container.paths.golden_workflow_database
    )
    assert {step.step_id for step in runtime.container.test_drive.steps()} == {
        "system-health",
        "model-provider",
    }
    assert [item.component_id for item in runtime.container.startup_warmup.components()] == [
        "default-model"
    ]
    test_drive = await runtime.container.test_drive.run()
    assert {step_id for step_id, _ in test_drive.results} == {
        "system-health",
        "model-provider",
    }
    warmup = runtime.container.startup_warmup.start()
    assert (await warmup)[0].component_id == "default-model"
    center = await runtime.container.control_center.refresh()
    assert center.section(ControlCenterSection.TOOLS).items
    assert any(
        item.item_id == "calculator" for item in center.section(ControlCenterSection.TOOLS).items
    )
    assert any(
        item.item_id == "settings" for item in center.section(ControlCenterSection.SYSTEM).items
    )
    assert center.section(ControlCenterSection.AUTOMATIONS).status.value == "available"
    capability_health = runtime.container.capability_health.evaluate_health(
        "runtime-fixture",
        (HealthProbeResult(HealthProbeMode.PASSIVE, True, "observed", datetime.now(UTC)),),
    )
    assert capability_health.status is HealthStatus.HEALTHY
    degraded = runtime.container.capability_health.evaluate_health(
        "runtime-attention",
        (HealthProbeResult(HealthProbeMode.READ_ONLY, False, "synthetic degradation"),),
    )
    assert degraded.status is HealthStatus.DEGRADED
    assert any(
        attention.item_type == "capability.health"
        for attention in runtime.container.attention_policy.pending()
    )
    health_center = await runtime.container.control_center.refresh(ControlCenterSection.HEALTH)
    assert any(
        item.item_id == "runtime-fixture"
        for item in health_center.section(ControlCenterSection.HEALTH).items
    )

    task = await runtime.container.task_controller.submit_task("calculate 25% of 800")
    assert task.status is PlanningTaskStatus.COMPLETED
    assert (
        runtime.container.task_controller.get_status(task.task_id) is PlanningTaskStatus.COMPLETED
    )
    assert runtime.container.state_machine.task(task.task_id) is not None
    plan = runtime.container.task_controller.inspect_plan(task.task_id)
    assert plan is not None
    assert plan.steps[0].result is not None
    result = runtime.container.task_controller.get_result(task.task_id)
    assert result is not None
    assert result.plan == plan
    assert result.evidence == task.result_evidence
    await runtime.aclose()

    restarted = ApplicationRuntime.create(settings)
    assert restarted.status is RuntimeStatus.READY
    assert restarted.container is not None
    persisted = restarted.container.task_controller.get_task(task.task_id)
    assert persisted is not None
    assert persisted.status is PlanningTaskStatus.COMPLETED
    assert (
        restarted.container.task_controller.get_status(task.task_id) is PlanningTaskStatus.COMPLETED
    )
    assert restarted.container.task_controller.get_result(task.task_id) is not None
    assert restarted.container.state_machine.task(task.task_id) is not None
    assert restarted.container.task_controller.inspect_plan(task.task_id) is not None
    assert any(
        attention.item_type == "capability.health"
        for attention in restarted.container.attention_policy.pending()
    )
    await restarted.aclose()


@pytest.mark.asyncio
async def test_runtime_optional_surfaces_are_application_owned_and_degraded(tmp_path: Path) -> None:
    runtime = ApplicationRuntime.create(
        Settings(app_data_dir=tmp_path / "jarvis-data", ai_provider="ollama")
    )
    assert runtime.status is RuntimeStatus.READY
    assert runtime.container is not None
    assert runtime.container.voice is None
    assert runtime.container.browser_status.value == "unavailable"
    assert runtime.container.presence_projection.snapshot().state.value == "idle"
    requested = await runtime.container.presentation_surface.query_state()
    assert requested.observed is False
    await runtime.aclose()


@pytest.mark.asyncio
async def test_runtime_shutdown_is_idempotent(tmp_path: Path) -> None:
    runtime = ApplicationRuntime.create(
        Settings(app_data_dir=tmp_path / "jarvis-data", ai_provider="ollama")
    )
    initial_status = runtime.status
    assert initial_status is RuntimeStatus.READY
    await asyncio.gather(runtime.aclose(), runtime.aclose())
    await runtime.aclose()
    assert runtime.status.value == RuntimeStatus.STOPPED.value


def test_production_application_and_desktop_do_not_import_legacy_orchestrator() -> None:
    assert "AgentOrchestrator" not in inspect.getsource(application)
    desktop_source = (Path(__file__).resolve().parents[1] / "jarvis" / "desktop.py").read_text(
        encoding="utf-8"
    )
    assert "AgentOrchestrator" not in desktop_source


def test_runtime_enters_safe_mode_after_bounded_startup_crash_loop(tmp_path: Path) -> None:
    settings = Settings(app_data_dir=tmp_path / "jarvis-data", ai_provider="ollama")
    paths = RuntimePaths.from_root(settings.app_data_dir)
    store = RecoveryStore(paths.recovery)
    timestamp = datetime.now(UTC).isoformat()
    for index in range(2):
        store.record(
            RecoveryEvidence(
                f"failed-{index}",
                RecoveryPhase.FAIL,
                "failed_start",
                "candidate did not reach a committed startup",
                None,
                timestamp,
            )
        )
    store.begin_start("stale-start")

    runtime = ApplicationRuntime.create(settings)

    assert runtime.status is RuntimeStatus.SAFE_MODE
    assert runtime.container is None
    assert runtime.error == "recovery crash-loop guard entered safe mode"
