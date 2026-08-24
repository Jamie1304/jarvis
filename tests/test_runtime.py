"""Canonical runtime integration tests; no legacy orchestrator is involved."""

from __future__ import annotations

import asyncio
import inspect
from datetime import UTC, datetime
from pathlib import Path

import pytest
from jarvis import application
from jarvis.capability_health import HealthProbeMode, HealthProbeResult, HealthStatus
from jarvis.control_center import ControlCenterSection
from jarvis.core.config import Settings
from jarvis.memory.control import MemoryControlService
from jarvis.memory.services import MemoryConsistencyService
from jarvis.planning.models import PlanningTaskStatus
from jarvis.recovery import RecoveryEvidence, RecoveryPhase, RecoveryStore
from jarvis.runtime import ApplicationRuntime, RuntimePaths, RuntimeStatus
from jarvis.task_controller import PlanningTaskController


@pytest.mark.asyncio
async def test_canonical_runtime_calculates_and_recovers_persisted_task(tmp_path: Path) -> None:
    settings = Settings(app_data_dir=tmp_path / "jarvis-data", ai_provider="ollama")
    runtime = ApplicationRuntime.create(settings)
    initial_status = runtime.status
    assert initial_status is RuntimeStatus.READY
    assert runtime.container is not None
    assert isinstance(runtime.container.task_controller, PlanningTaskController)
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
    await restarted.aclose()


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
