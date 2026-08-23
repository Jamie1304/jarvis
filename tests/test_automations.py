"""Deterministic contracts for generic event-driven automation."""

from __future__ import annotations

import asyncio
import math
import sqlite3
from dataclasses import replace
from datetime import UTC, datetime, timedelta
from pathlib import Path
from types import SimpleNamespace
from typing import Any, cast
from uuid import UUID, uuid4

import jarvis.automations as automation_module
import pytest
from jarvis.automations import (
    AutomationDefinition,
    AutomationError,
    AutomationMigration,
    AutomationRun,
    AutomationRunStatus,
    AutomationService,
    AutomationStore,
    AutomationStoreError,
    AutomationValidationError,
    ConcurrencyPolicy,
    Condition,
    ConditionOperator,
    SQLiteAutomationStore,
    TriggerDefinition,
)
from jarvis.events import EventEnvelope, EventPayload, EventType, InMemoryEventBus, SystemError
from jarvis.planning.models import BudgetUsage, ExecutionBudgets, PlanningTask, PlanningTaskStatus
from jarvis.task_controller import TaskController


def _event(message: str) -> EventEnvelope[EventPayload]:
    return cast(
        EventEnvelope[EventPayload],
        EventEnvelope.create(
            EventType.SYSTEM_ERROR,
            SystemError("automation-test", message),
            source="tests",
            correlation_id=uuid4(),
        ),
    )


def _task(status: PlanningTaskStatus) -> PlanningTask:
    now = datetime.now(UTC)
    return PlanningTask(
        uuid4(),
        "automation task",
        (),
        (),
        status,
        None,
        ExecutionBudgets(),
        BudgetUsage(),
        now,
        now,
        now + timedelta(minutes=5),
        now,
    )


class _Controller:
    def __init__(self, *, initial_status: PlanningTaskStatus = PlanningTaskStatus.READY) -> None:
        self.initial_status = initial_status
        self.created: list[PlanningTask] = []
        self.ran: list[UUID] = []
        self.tasks: dict[UUID, PlanningTask] = {}
        self.release = asyncio.Event()

    async def create_task(self, goal: str, **_: object) -> PlanningTask:
        del goal
        task = _task(self.initial_status)
        self.created.append(task)
        self.tasks[task.task_id] = task
        return task

    async def create_proposal_task(self, proposal: object, **_: object) -> PlanningTask:
        del proposal
        return await self.create_task("workflow proposal")

    async def run_task(self, task_id: UUID) -> PlanningTask:
        self.ran.append(task_id)
        if not self.release.is_set():
            await self.release.wait()
        task = self.tasks[task_id]
        completed = replace(task, status=PlanningTaskStatus.COMPLETED)
        self.tasks[task_id] = completed
        return completed

    def get_task(self, task_id: UUID) -> PlanningTask | None:
        return self.tasks.get(task_id)


def _definition(
    *,
    policy: ConcurrencyPolicy = ConcurrencyPolicy.DROP,
    simulation: bool = False,
    condition: Condition | None = None,
    debounce_seconds: float = 0.0,
    cooldown_seconds: float = 0.0,
) -> AutomationDefinition:
    trigger = TriggerDefinition(
        uuid4(),
        (EventType.SYSTEM_ERROR,),
        (() if condition is None else (condition,)),
        debounce_seconds=debounce_seconds,
        cooldown_seconds=cooldown_seconds,
    )
    return AutomationDefinition(
        "test automation",
        trigger,
        "workspace",
        "profile",
        goal="calculate a safe value",
        concurrency_policy=policy,
        max_concurrency=1,
        max_queue=2,
        simulation=simulation,
    )


async def _service(
    tmp_path: Path,
    controller: _Controller,
    definition: AutomationDefinition,
) -> tuple[AutomationService, SQLiteAutomationStore, InMemoryEventBus]:
    store = SQLiteAutomationStore(tmp_path / "automations.sqlite3")
    store.save_definition(definition)
    bus = InMemoryEventBus()
    service = AutomationService(cast(AutomationStore, store), bus, cast(TaskController, controller))
    await service.start()
    return service, store, bus


async def _close(
    service: AutomationService, store: SQLiteAutomationStore, bus: InMemoryEventBus
) -> None:
    await service.aclose()
    await bus.close()
    store.close()


@pytest.mark.asyncio
async def test_trigger_condition_and_normal_planning_dispatch(tmp_path: Path) -> None:
    controller = _Controller()
    definition = _definition(
        condition=Condition("payload.summary", ConditionOperator.EQUALS, "fire")
    )
    service, store, bus = await _service(tmp_path, controller, definition)
    try:
        assert await service.handle_event(_event("ignore")) == ()
        accepted = await service.handle_event(_event("fire"))
        assert len(accepted) == 1
        controller.release.set()
        await asyncio.sleep(0.02)
        run = service.runs(definition.automation_id)[0]
        assert run.status is AutomationRunStatus.COMPLETED
        assert len(controller.created) == 1
        assert controller.ran == [controller.created[0].task_id]
    finally:
        await _close(service, store, bus)


@pytest.mark.asyncio
async def test_deduplication_debounce_cooldown_and_storm_are_bounded(tmp_path: Path) -> None:
    controller = _Controller()
    definition = _definition(debounce_seconds=0.01, cooldown_seconds=0.02)
    service, store, bus = await _service(tmp_path, controller, definition)
    try:
        first = _event("first")
        second = _event("second")
        assert len(await service.handle_event(first)) == 1
        assert await service.handle_event(first) == ()
        assert len(await service.handle_event(second)) == 1
        await asyncio.sleep(0.04)
        controller.release.set()
        await asyncio.sleep(0.02)
        statuses = {run.status for run in service.runs(definition.automation_id)}
        assert AutomationRunStatus.DROPPED in statuses
        assert len(controller.created) == 1
    finally:
        await _close(service, store, bus)


@pytest.mark.asyncio
async def test_simulation_never_creates_or_runs_a_task(tmp_path: Path) -> None:
    controller = _Controller()
    definition = _definition(simulation=True)
    service, store, bus = await _service(tmp_path, controller, definition)
    try:
        await bus.publish(_event("simulate"))
        await asyncio.sleep(0.02)
        run = service.runs(definition.automation_id)[0]
        assert run.status is AutomationRunStatus.SIMULATED
        assert controller.created == []
        assert controller.ran == []
    finally:
        await _close(service, store, bus)


@pytest.mark.asyncio
async def test_drop_and_queue_policies_bound_active_work(tmp_path: Path) -> None:
    controller = _Controller()
    definition = _definition(policy=ConcurrencyPolicy.DROP)
    service, store, bus = await _service(tmp_path, controller, definition)
    try:
        await service.handle_event(_event("one"))
        await asyncio.sleep(0)
        assert len(await service.handle_event(_event("two"))) == 1
        await asyncio.sleep(0)
        assert AutomationRunStatus.DROPPED in {item.status for item in service.runs()}
        controller.release.set()
    finally:
        await _close(service, store, bus)


@pytest.mark.asyncio
async def test_permission_waiting_is_reported_without_fabricating_approval(tmp_path: Path) -> None:
    controller = _Controller(initial_status=PlanningTaskStatus.WAITING_FOR_PERMISSION)
    definition = _definition()
    service, store, bus = await _service(tmp_path, controller, definition)
    try:
        await service.handle_event(_event("permission is still required"))
        await asyncio.sleep(0.02)
        run = service.runs(definition.automation_id)[0]
        assert run.status is AutomationRunStatus.WAITING_FOR_PERMISSION
        assert controller.ran == []
    finally:
        await _close(service, store, bus)


@pytest.mark.asyncio
async def test_running_automation_is_reconciled_safely_after_restart(tmp_path: Path) -> None:
    controller = _Controller()
    definition = _definition()
    store = SQLiteAutomationStore(tmp_path / "automations.sqlite3")
    store.save_definition(definition)
    now = datetime.now(UTC)
    run = AutomationRun(
        uuid4(),
        definition.automation_id,
        uuid4(),
        EventType.SYSTEM_ERROR,
        "tests",
        uuid4(),
        "restart-key",
        uuid4(),
        AutomationRunStatus.RUNNING,
        now,
        now,
    )
    assert store.create_run(run)
    store.close()
    bus = InMemoryEventBus()
    reopened = SQLiteAutomationStore(tmp_path / "automations.sqlite3")
    service = AutomationService(
        cast(AutomationStore, reopened), bus, cast(TaskController, controller)
    )
    await service.start()
    try:
        reconciled = reopened.get_run(run.run_id)
        assert reconciled is not None
        assert reconciled.status is AutomationRunStatus.FAILED
        assert reconciled.error == "restart_unknown_submission"
    finally:
        await _close(service, reopened, bus)


def test_conditions_trigger_validation_and_safe_values() -> None:
    event = _event("fire now")
    assert Condition("payload.summary", ConditionOperator.EQUALS, "fire now").evaluate(event)
    assert Condition("payload.summary", ConditionOperator.NOT_EQUALS, "other").evaluate(event)
    assert Condition("payload.summary", ConditionOperator.CONTAINS, "now").evaluate(event)
    assert Condition("payload.summary", ConditionOperator.IN, ("fire now", "other")).evaluate(event)
    assert Condition("payload.summary", ConditionOperator.EXISTS).evaluate(event)
    assert not Condition("payload.missing", ConditionOperator.EXISTS).evaluate(event)
    assert not Condition("payload.missing", ConditionOperator.EQUALS, "value").evaluate(event)
    assert Condition("payload.missing", ConditionOperator.NOT_EQUALS, "value").evaluate(event)
    assert not Condition("payload.summary", ConditionOperator.CONTAINS, 5).evaluate(event)
    assert not Condition("payload", ConditionOperator.CONTAINS, "summary").evaluate(event)

    with pytest.raises(AutomationValidationError):
        Condition("payload.__class__", ConditionOperator.EXISTS)
    with pytest.raises(AutomationValidationError):
        Condition("payload.summary", "equals")  # type: ignore[arg-type]
    with pytest.raises(AutomationValidationError):
        Condition("payload.summary", ConditionOperator.EQUALS, math.nan)
    with pytest.raises(AutomationValidationError):
        Condition("payload.summary", ConditionOperator.EQUALS, {str(i): i for i in range(65)})
    with pytest.raises(AutomationValidationError):
        Condition("payload.summary", ConditionOperator.EQUALS, b"unsafe")

    with pytest.raises(AutomationValidationError):
        TriggerDefinition(uuid4(), ())
    with pytest.raises(AutomationValidationError):
        TriggerDefinition(uuid4(), (EventType.SYSTEM_ERROR, EventType.SYSTEM_ERROR))
    with pytest.raises(AutomationValidationError):
        TriggerDefinition(uuid4(), (EventType.SYSTEM_ERROR,), debounce_seconds=61)
    with pytest.raises(AutomationValidationError):
        TriggerDefinition(uuid4(), (EventType.SYSTEM_ERROR,), deduplication_paths=("payload.x.y",))
    assert TriggerDefinition(uuid4(), (EventType.SYSTEM_ERROR,), source="tests").matches(event)


def test_store_roundtrip_duplicate_update_delete_and_future_schema(tmp_path: Path) -> None:
    path = tmp_path / "store.sqlite3"
    definition = _definition()
    with SQLiteAutomationStore(path) as store:
        assert store.database_path == path
        store.save_definition(definition)
        assert store.get_definition(definition.automation_id) == definition
        assert store.list_definitions(enabled_only=True) == (definition,)
        disabled = replace(definition, enabled=False)
        store.save_definition(disabled)
        assert store.list_definitions(enabled_only=True) == ()
        assert store.get_definition(definition.automation_id) == disabled
        now = datetime.now(UTC)
        run = AutomationRun(
            uuid4(),
            definition.automation_id,
            uuid4(),
            EventType.SYSTEM_ERROR,
            "tests",
            uuid4(),
            "key",
            uuid4(),
            AutomationRunStatus.QUEUED,
            now,
            now,
        )
        assert store.create_run(run)
        assert not store.create_run(replace(run, run_id=uuid4()))
        updated = replace(run, status=AutomationRunStatus.DROPPED, error="bounded")
        store.update_run(updated)
        assert store.get_run(run.run_id) == updated
        assert store.list_runs(definition.automation_id) == (updated,)
        with pytest.raises(AutomationStoreError):
            store.update_run(replace(run, run_id=uuid4()))
        assert store.delete_definition(definition.automation_id)
        assert not store.delete_definition(definition.automation_id)

    connection = sqlite3.connect(path)
    connection.execute(
        "INSERT INTO automation_schema_migrations(version, name, applied_at) VALUES (?, ?, ?)",
        (99, "future", datetime.now(UTC).isoformat()),
    )
    connection.commit()
    connection.close()
    with pytest.raises(AutomationStoreError):
        SQLiteAutomationStore(path)

    with pytest.raises(AutomationError):
        SQLiteAutomationStore(
            tmp_path / "bad.sqlite3",
            migrations=(AutomationMigration(2, "gap", "CREATE TABLE x (id INTEGER);"),),
        )


@pytest.mark.asyncio
async def test_workflow_target_and_missing_registry_fail_closed(tmp_path: Path) -> None:
    class _Template:
        def propose(self, parameters: object, *, workspace_id: str, profile_id: str) -> object:
            assert parameters == {"value": "safe"}
            assert workspace_id == "workspace"
            assert profile_id == "profile"
            return "validated-proposal"

    class _Registry:
        def resolve(self, template_id: str, *, workspace_id: str, profile_id: str) -> _Template:
            assert template_id == "template"
            return _Template()

    controller = _Controller()
    definition = replace(
        _definition(),
        goal=None,
        workflow_template_id="template",
        workflow_parameters={"value": "safe"},
    )
    store = SQLiteAutomationStore(tmp_path / "workflow.sqlite3")
    store.save_definition(definition)
    bus = InMemoryEventBus()
    service = AutomationService(
        cast(AutomationStore, store),
        bus,
        cast(TaskController, controller),
        workflow_registry=cast(object, _Registry()),  # type: ignore[arg-type]
    )
    await service.start()
    try:
        await service.handle_event(_event("workflow"))
        controller.release.set()
        await asyncio.sleep(0.02)
        assert service.runs()[0].status is AutomationRunStatus.COMPLETED
        assert controller.created
    finally:
        await _close(service, store, bus)

    missing_store = SQLiteAutomationStore(tmp_path / "missing-workflow.sqlite3")
    missing_store.save_definition(definition)
    missing_bus = InMemoryEventBus()
    missing = AutomationService(
        cast(AutomationStore, missing_store), missing_bus, cast(TaskController, _Controller())
    )
    await missing.start()
    try:
        await missing.handle_event(_event("missing workflow"))
        await asyncio.sleep(0.02)
        assert missing.runs()[0].status is AutomationRunStatus.FAILED
    finally:
        await _close(missing, missing_store, missing_bus)


@pytest.mark.asyncio
async def test_queue_policy_drains_and_bounds_storm(tmp_path: Path) -> None:
    controller = _Controller()
    definition = _definition(policy=ConcurrencyPolicy.QUEUE)
    service, store, bus = await _service(tmp_path, controller, definition)
    try:
        await service.handle_event(_event("one"))
        await asyncio.sleep(0)
        await service.handle_event(_event("two"))
        await service.handle_event(_event("three"))
        await service.handle_event(_event("four"))
        await asyncio.sleep(0)
        assert AutomationRunStatus.QUEUED in {run.status for run in service.runs()}
        controller.release.set()
        await asyncio.sleep(0.05)
        assert len(controller.created) == 3
        assert AutomationRunStatus.DROPPED in {run.status for run in service.runs()}
        assert all(run.status is not AutomationRunStatus.QUEUED for run in service.runs())
    finally:
        await _close(service, store, bus)


@pytest.mark.asyncio
async def test_cooldown_public_simulation_and_service_lifecycle(tmp_path: Path) -> None:
    controller = _Controller()
    controller.release.set()
    definition = _definition(cooldown_seconds=1)
    service, store, bus = await _service(tmp_path, controller, definition)
    try:
        assert await service.simulate(uuid4(), _event("missing")) is None
        assert await service.simulate(definition.automation_id, _event("direct")) is not None
        await service.handle_event(_event("first"))
        await asyncio.sleep(0.03)
        await service.handle_event(_event("second"))
        await asyncio.sleep(0.03)
        assert AutomationRunStatus.DROPPED in {run.status for run in service.runs()}
        await service.start()
        assert service.definitions()
    finally:
        await _close(service, store, bus)

    with pytest.raises(AutomationError):
        await service.start()


@pytest.mark.asyncio
async def test_shutdown_cancels_active_dispatch_and_unregistration_is_durable(
    tmp_path: Path,
) -> None:
    controller = _Controller()
    definition = _definition()
    service, store, bus = await _service(tmp_path, controller, definition)
    await service.handle_event(_event("cancel on shutdown"))
    await asyncio.sleep(0)
    await service.stop()
    assert service.runs(definition.automation_id)[0].error == "automation_cancelled_unknown_state"
    assert service.unregister(definition.automation_id)
    assert service.runs(definition.automation_id) == ()
    await service.aclose()
    await bus.close()
    store.close()


@pytest.mark.asyncio
async def test_restart_resumes_only_durable_queued_runs(tmp_path: Path) -> None:
    controller = _Controller()
    controller.release.set()
    definition = _definition()
    store = SQLiteAutomationStore(tmp_path / "queued-restart.sqlite3")
    store.save_definition(definition)
    now = datetime.now(UTC)
    queued = AutomationRun(
        uuid4(),
        definition.automation_id,
        uuid4(),
        EventType.SYSTEM_ERROR,
        "tests",
        uuid4(),
        "queued-restart",
        uuid4(),
        AutomationRunStatus.QUEUED,
        now,
        now,
    )
    assert store.create_run(queued)
    bus = InMemoryEventBus()
    service = AutomationService(cast(AutomationStore, store), bus, cast(TaskController, controller))
    await service.start()
    try:
        await asyncio.sleep(0.03)
        assert service.runs()[0].status is AutomationRunStatus.COMPLETED
    finally:
        await _close(service, store, bus)


@pytest.mark.asyncio
async def test_restart_reconciliation_maps_bound_task_states(tmp_path: Path) -> None:
    controller = _Controller()
    definition = _definition()
    store = SQLiteAutomationStore(tmp_path / "reconcile.sqlite3")
    store.save_definition(definition)
    now = datetime.now(UTC)

    def running(task_id: UUID | None) -> AutomationRun:
        return AutomationRun(
            uuid4(),
            definition.automation_id,
            uuid4(),
            EventType.SYSTEM_ERROR,
            "tests",
            uuid4(),
            uuid4().hex,
            uuid4(),
            AutomationRunStatus.RUNNING,
            now,
            now,
            task_id,
        )

    missing = running(uuid4())
    waiting_task = _task(PlanningTaskStatus.WAITING_FOR_PERMISSION)
    executing_task = _task(PlanningTaskStatus.EXECUTING)
    completed_task = _task(PlanningTaskStatus.COMPLETED)
    cancelled_task = _task(PlanningTaskStatus.CANCELLED)
    for task in (waiting_task, executing_task, completed_task, cancelled_task):
        controller.tasks[task.task_id] = task
    runs = (
        missing,
        running(waiting_task.task_id),
        running(executing_task.task_id),
        running(completed_task.task_id),
        running(cancelled_task.task_id),
    )
    for item in runs:
        assert store.create_run(item)
    bus = InMemoryEventBus()
    service = AutomationService(cast(AutomationStore, store), bus, cast(TaskController, controller))
    await service.start()
    try:
        statuses = {item.error: item.status for item in service.runs()}
        assert statuses["restart_task_missing"] is AutomationRunStatus.FAILED
        assert statuses[None] in {
            AutomationRunStatus.WAITING_FOR_PERMISSION,
            AutomationRunStatus.COMPLETED,
            AutomationRunStatus.CANCELLED,
        }
        assert sum(item.error == "restart_requires_reconciliation" for item in service.runs()) == 1
    finally:
        await _close(service, store, bus)


@pytest.mark.asyncio
async def test_restart_if_safe_only_cancels_pre_submission_work(tmp_path: Path) -> None:
    controller = _Controller()
    definition = _definition(policy=ConcurrencyPolicy.RESTART_IF_SAFE)
    service, store, bus = await _service(tmp_path, controller, definition)
    try:
        await service.handle_event(_event("old"))
        await service.handle_event(_event("new"))
        await asyncio.sleep(0.02)
        controller.release.set()
        await asyncio.sleep(0.04)
        assert AutomationRunStatus.CANCELLED in {run.status for run in service.runs()}
        assert AutomationRunStatus.COMPLETED in {run.status for run in service.runs()}
    finally:
        await _close(service, store, bus)


def test_automation_contract_rejects_ambiguous_targets() -> None:
    with pytest.raises(AutomationValidationError):
        AutomationDefinition(
            "invalid",
            TriggerDefinition(uuid4(), (EventType.SYSTEM_ERROR,)),
            "workspace",
            "profile",
            goal="one",
            workflow_template_id="two",
        )


def test_automation_validation_and_storage_fail_closed(tmp_path: Path) -> None:
    definition = _definition()
    now = datetime.now(UTC)

    for field, value in (
        ("automation_id", "bad"),
        ("concurrency_policy", "bad"),
        ("max_concurrency", 0),
        ("max_queue", -1),
        ("name", ""),
        ("goal", ""),
    ):
        kwargs: dict[str, object] = {field: value}
        if field == "goal":
            kwargs["workflow_template_id"] = None
        with pytest.raises((AutomationValidationError, ValueError)):
            replace(definition, **cast(Any, kwargs))

    base_run = AutomationRun(
        uuid4(),
        definition.automation_id,
        uuid4(),
        EventType.SYSTEM_ERROR,
        "tests",
        uuid4(),
        "key",
        uuid4(),
        AutomationRunStatus.QUEUED,
        now,
        now,
    )
    invalid_run_values: tuple[tuple[str, object], ...] = (
        ("run_id", "bad"),
        ("event_type", "bad"),
        ("task_id", "bad"),
        ("event_source", ""),
        ("deduplication_key", ""),
        ("created_at", now.replace(tzinfo=None)),
    )
    for field, invalid_value in invalid_run_values:
        with pytest.raises((AutomationValidationError, ValueError)):
            replace(base_run, **cast(Any, {field: invalid_value}))

    assert automation_module._event_field(_event("x"), "event_type") == EventType.SYSTEM_ERROR.value
    event = _event("x")
    assert automation_module._event_field(event, "source") == "tests"
    assert automation_module._event_field(event, "task_id") is None
    assert isinstance(automation_module._event_field(event, "correlation_id"), UUID)
    assert automation_module._event_field(event, "payload") == event.payload
    assert automation_module._event_field(event, "payload.missing") is automation_module._MISSING
    assert automation_module._canonical(uuid4())
    assert automation_module._canonical(now)
    assert automation_module._canonical(("x", 1)) == ["x", 1]
    assert automation_module._canonical(ConcurrencyPolicy.DROP) == ConcurrencyPolicy.DROP.value
    assert automation_module._json_safe(1.5) == 1.5
    with pytest.raises(AutomationValidationError):
        automation_module._json_safe(math.inf)
    fake_event = cast(
        EventEnvelope[EventPayload],
        SimpleNamespace(
            event_type=EventType.SYSTEM_ERROR,
            source="tests",
            task_id=None,
            correlation_id=uuid4(),
            payload={"items": ("value",), "key": "value"},
        ),
    )
    assert Condition("payload.items", ConditionOperator.CONTAINS, "value").evaluate(fake_event)
    assert Condition("payload", ConditionOperator.CONTAINS, "key").evaluate(fake_event)

    malformed = {
        "automation_id": str(definition.automation_id),
        "name": "name",
        "workspace_id": "workspace",
        "profile_id": "profile",
        "goal": "goal",
        "trigger": {
            "trigger_id": str(uuid4()),
            "event_types": [EventType.SYSTEM_ERROR.value],
            "conditions": "bad",
        },
        "workflow_parameters": [],
    }
    with pytest.raises(AutomationStoreError):
        automation_module._definition_from_dict(malformed)
    malformed["trigger"] = {
        "trigger_id": str(uuid4()),
        "event_types": [EventType.SYSTEM_ERROR.value],
        "conditions": (),
    }
    malformed["workflow_parameters"] = []
    with pytest.raises(AutomationStoreError):
        automation_module._definition_from_dict(malformed)
    malformed["workflow_parameters"] = {}
    malformed["trigger"] = {
        "trigger_id": str(uuid4()),
        "event_types": [EventType.SYSTEM_ERROR.value],
        "conditions": (),
        "deduplication_paths": "bad",
    }
    with pytest.raises(AutomationStoreError):
        automation_module._definition_from_dict(malformed)

    with pytest.raises(AutomationValidationError):
        automation_module._json_safe({str(i): i for i in range(65)})
    with pytest.raises(AutomationValidationError):
        automation_module._json_safe([1] * 65)
    with pytest.raises(AutomationValidationError):
        automation_module._json_safe(object())
    nested: object = "x"
    for _ in range(7):
        nested = [nested]
    with pytest.raises(AutomationValidationError):
        automation_module._json_safe(nested)

    database = tmp_path / "migration-errors.sqlite3"
    with pytest.raises(AutomationStoreError):
        SQLiteAutomationStore(
            database,
            migrations=(AutomationMigration(1, "bad", "not sql"),),
        )
    with pytest.raises(AutomationStoreError):
        SQLiteAutomationStore(
            tmp_path / "empty-migration.sqlite3",
            migrations=(AutomationMigration(1, "", "CREATE TABLE x (id INTEGER);"),),
        )

    identity_path = tmp_path / "migration-identity.sqlite3"
    identity_store = SQLiteAutomationStore(identity_path)
    identity_store.close()
    connection = sqlite3.connect(identity_path)
    connection.execute(
        "UPDATE automation_schema_migrations SET name = ? WHERE version = 1", ("renamed",)
    )
    connection.commit()
    connection.close()
    with pytest.raises(AutomationStoreError):
        SQLiteAutomationStore(identity_path)
