"""Focused R3E-C task-graph and dependency-binding regressions."""

from __future__ import annotations

import json
from dataclasses import replace
from datetime import UTC, datetime, timedelta
from pathlib import Path
from uuid import UUID, uuid4

import pytest
from jarvis.planning import (
    BudgetUsage,
    DependencyBinding,
    DependencyResolutionError,
    ExecutionBudgets,
    GraphReadiness,
    OwnedPlan,
    OwnedPlanStatus,
    PlanningStep,
    PlanningStepStatus,
    PlanningTask,
    PlanningTaskStatus,
    SQLitePlanningStore,
    StepResult,
    TaskGraphView,
)


def _step(
    key: str,
    ids: dict[str, UUID],
    dependencies: tuple[str, ...] = (),
    *,
    status: PlanningStepStatus = PlanningStepStatus.QUEUED,
    result: StepResult | None = None,
    bindings: tuple[DependencyBinding, ...] = (),
) -> PlanningStep:
    return PlanningStep(
        step_id=ids[key],
        key=key,
        tool_id="test-tool",
        capability="test",
        input_json='{"value":"static"}',
        expected_output="value",
        verification_rule="evidence_contains_all",
        expected_evidence=(f"{key}-verified",),
        dependencies=tuple(ids[item] for item in dependencies),
        required_permissions=(),
        expensive_action=False,
        max_retries=1,
        status=status,
        result=result,
        input_bindings=bindings,
    )


def _plan(*steps: PlanningStep, version: int = 1) -> OwnedPlan:
    now = datetime.now(UTC)
    return OwnedPlan(
        plan_id=uuid4(),
        task_id=uuid4(),
        version=version,
        goal="graph test",
        assumptions=(),
        constraints=(),
        steps=steps,
        required_capabilities=("test",),
        required_permissions=(),
        completion_criteria=("verified",),
        status=OwnedPlanStatus.READY,
        created_at=now,
        updated_at=now,
    )


def test_linear_and_independent_roots_have_deterministic_ready_sets() -> None:
    ids = {key: uuid4() for key in ("a", "b", "c")}
    plan = _plan(_step("b", ids, ("a",)), _step("a", ids), _step("c", ids))
    graph = TaskGraphView(plan)

    assert tuple(step.key for step in graph.ready_steps()) == ("a", "c")
    assert (
        graph.readiness(next(step for step in plan.steps if step.key == "b"))
        is GraphReadiness.WAITING_ON_DEPENDENCY
    )


def test_fan_out_and_fan_in_require_exact_verified_predecessors() -> None:
    ids = {key: uuid4() for key in ("a", "b", "c", "d")}
    plan = _plan(
        _step(
            "a",
            ids,
            status=PlanningStepStatus.SUCCEEDED,
            result=StepResult('{"value":1}', ("a-verified",)),
        ),
        _step(
            "b",
            ids,
            ("a",),
            status=PlanningStepStatus.SUCCEEDED,
            result=StepResult('{"value":2}', ("b-verified",)),
        ),
        _step("c", ids, ("a",)),
        _step("d", ids, ("b", "c")),
    )
    graph = TaskGraphView(plan)

    assert tuple(step.key for step in graph.ready_steps()) == ("c",)
    assert (
        graph.readiness(next(step for step in plan.steps if step.key == "d"))
        is GraphReadiness.WAITING_ON_DEPENDENCY
    )
    completed_c = replace(
        next(step for step in plan.steps if step.key == "c"),
        status=PlanningStepStatus.SUCCEEDED,
        result=StepResult('{"value":3}', ("c-verified",)),
    )
    graph = TaskGraphView(_plan(*(completed_c if step.key == "c" else step for step in plan.steps)))
    assert tuple(step.key for step in graph.ready_steps()) == ("d",)


def test_only_verified_direct_dependency_output_can_be_bound() -> None:
    ids = {"a": uuid4(), "b": uuid4()}
    binding = DependencyBinding(ids["a"], "value", "value")
    predecessor = _step(
        "a",
        ids,
        status=PlanningStepStatus.SUCCEEDED,
        result=StepResult('{"value":42}', ("a-verified",)),
    )
    dependent = _step("b", ids, ("a",), bindings=(binding,))
    graph = TaskGraphView(_plan(predecessor, dependent))

    assert json.loads(graph.resolve_input(dependent)) == {"value": 42}
    uncertain = replace(predecessor, status=PlanningStepStatus.RUNNING, result=None)
    with pytest.raises(DependencyResolutionError):
        TaskGraphView(_plan(uncertain, dependent)).resolve_input(dependent)


def test_non_dependency_and_missing_source_bindings_fail_closed() -> None:
    ids = {key: uuid4() for key in ("a", "b", "c")}
    binding = DependencyBinding(ids["a"], "missing", "value")
    dependent = _step("b", ids, ("a",), bindings=(binding,))
    with pytest.raises(DependencyResolutionError):
        TaskGraphView(
            _plan(
                _step("a", ids, status=PlanningStepStatus.SUCCEEDED, result=StepResult("{}", ())),
                dependent,
                _step("c", ids),
            )
        ).resolve_input(dependent)
    with pytest.raises(ValueError):
        _step("b", ids, ("a",), bindings=(DependencyBinding(ids["c"], "value", "other"),))


def test_store_round_trip_and_old_plan_default_bindings(tmp_path: Path) -> None:
    ids = {"a": uuid4()}
    plan = _plan(_step("a", ids))
    task = PlanningTask(
        task_id=plan.task_id,
        goal=plan.goal,
        original_assumptions=(),
        original_constraints=(),
        status=PlanningTaskStatus.READY,
        plan_id=plan.plan_id,
        budgets=ExecutionBudgets(),
        usage=BudgetUsage(),
        created_at=plan.created_at,
        started_at=plan.created_at,
        deadline=plan.created_at + timedelta(seconds=900),
        updated_at=plan.updated_at,
    )
    database = tmp_path / "planning.sqlite3"
    with SQLitePlanningStore(database) as store:
        store.create_task(task)
        store.save_state(task, plan)
    with SQLitePlanningStore(database) as reopened:
        loaded = reopened.load_plan(task.task_id)
        assert loaded is not None
        assert loaded.steps[0].input_bindings == ()
