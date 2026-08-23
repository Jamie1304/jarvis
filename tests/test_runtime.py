"""Canonical runtime integration tests; no legacy orchestrator is involved."""

from __future__ import annotations

import asyncio
import inspect
from pathlib import Path

import pytest
from jarvis import application
from jarvis.core.config import Settings
from jarvis.planning.models import PlanningTaskStatus
from jarvis.runtime import ApplicationRuntime, RuntimeStatus
from jarvis.task_controller import PlanningTaskController


@pytest.mark.asyncio
async def test_canonical_runtime_calculates_and_recovers_persisted_task(tmp_path: Path) -> None:
    settings = Settings(app_data_dir=tmp_path / "jarvis-data", ai_provider="ollama")
    runtime = ApplicationRuntime.create(settings)
    initial_status = runtime.status
    assert initial_status is RuntimeStatus.READY
    assert runtime.container is not None
    assert isinstance(runtime.container.task_controller, PlanningTaskController)

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
