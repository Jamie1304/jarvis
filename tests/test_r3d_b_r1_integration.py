import asyncio
import json
from datetime import UTC, datetime, timedelta
from uuid import uuid4

from jarvis.autonomy.routing import ExecutionRouteSelector
from jarvis.capabilities import CapabilityRegistry
from jarvis.planning.engine import BrokeredPlanningStepExecutor
from jarvis.planning.models import (
    BudgetUsage,
    ExecutionBudgets,
    PlanningStep,
    PlanningStepStatus,
    PlanningTask,
    PlanningTaskStatus,
    StepExecutionResult,
)
from jarvis.tools.catalog import create_safe_tool_registry

from tests.test_capabilities import manifest


def task() -> PlanningTask:
    now = datetime.now(UTC)
    return PlanningTask(
        task_id=uuid4(),
        goal="run a real planned step",
        original_assumptions=(),
        original_constraints=(),
        status=PlanningTaskStatus.EXECUTING,
        plan_id=uuid4(),
        budgets=ExecutionBudgets(),
        usage=BudgetUsage(),
        created_at=now,
        started_at=now,
        deadline=now + timedelta(minutes=1),
        updated_at=now,
    )


def planned_step(tool_id: str = "calculator", capability: str = "math") -> PlanningStep:
    return PlanningStep(
        step_id=uuid4(),
        key="calculate",
        tool_id=tool_id,
        capability=capability,
        input_json=json.dumps({"expression": "2 + 2"}) if tool_id == "calculator" else "{}",
        expected_output="4",
        verification_rule="output_contains",
        expected_evidence=(),
        dependencies=(),
        required_permissions=(),
        expensive_action=False,
        max_retries=0,
        status=PlanningStepStatus.RUNNING,
    )


def executor(
    *, capability_registry: CapabilityRegistry | None = None
) -> BrokeredPlanningStepExecutor:
    registry = create_safe_tool_registry()
    selector = ExecutionRouteSelector(
        model_router=None,
        tool_registry=registry,
        capability_registry=capability_registry,
    )
    return BrokeredPlanningStepExecutor(registry, route_selector=selector)


async def run_step(
    execution: BrokeredPlanningStepExecutor, step: PlanningStep
) -> StepExecutionResult:
    return await execution.execute(task(), step, asyncio.Event())


def test_real_planning_executor_routes_through_r3d_b_then_tool_owner() -> None:
    result = asyncio.run(run_step(executor(), planned_step()))

    assert result.status.value == "succeeded"
    assert '"result":"4"' in result.output_json


def test_production_boundary_reports_no_valid_route_without_legacy_bypass() -> None:
    result = asyncio.run(run_step(executor(), planned_step("missing-tool", "missing-tool")))

    assert result.status.value == "deterministic_failure"
    assert result.error_code == "execution_route_unavailable"


def test_production_boundary_rejects_descriptive_only_capability() -> None:
    registry = CapabilityRegistry((manifest(capability_id="descriptive-only"),))
    result = asyncio.run(
        run_step(
            executor(capability_registry=registry),
            planned_step("descriptive-only", "descriptive-only"),
        )
    )

    assert result.status.value == "deterministic_failure"
    assert result.error_code == "execution_route_unavailable"
