"""Exhaustive deterministic tests for application/task lifecycle transitions."""

from collections.abc import Callable
from datetime import UTC, datetime
from pathlib import Path
from typing import cast
from uuid import UUID, uuid4

import pytest
from jarvis.state import (
    ApplicationState,
    ApplicationStateMachine,
    InMemoryStateStore,
    InvalidStateTransition,
    SQLiteStateStore,
    StateConcurrencyError,
    StateMachineError,
    TaskSnapshot,
    TaskState,
    TransitionEvent,
)
from jarvis.state.models import StateTransition


def _task(machine: ApplicationStateMachine) -> UUID:
    task_id = uuid4()
    machine.create_task(task_id)
    return task_id


def _snapshot(machine: ApplicationStateMachine, task_id: UUID) -> TaskSnapshot:
    snapshot = machine.task(task_id)
    assert snapshot is not None
    return snapshot


def _advance(machine: ApplicationStateMachine, task_id: UUID, states: list[TaskState]) -> None:
    events = {
        TaskState.THINKING: TransitionEvent.TASK_THINKING,
        TaskState.PLANNING: TransitionEvent.PLAN_REQUESTED,
        TaskState.WAITING_FOR_PERMISSION: TransitionEvent.PERMISSION_REQUIRED,
        TaskState.EXECUTING: TransitionEvent.EXECUTION_STARTED,
        TaskState.VERIFYING: TransitionEvent.VERIFICATION_STARTED,
        TaskState.WAITING: TransitionEvent.EXECUTION_WAITING,
        TaskState.RECOVERING: TransitionEvent.RECOVERY_STARTED,
        TaskState.COMPLETED: TransitionEvent.TASK_COMPLETED,
        TaskState.ERROR: TransitionEvent.TASK_FAILED,
        TaskState.CANCELLED: TransitionEvent.TASK_CANCELLED,
    }
    for state in states:
        machine.transition_task(task_id, state, events[state], reason=f"to {state.value}")


def test_full_task_lifecycle_and_transition_evidence() -> None:
    machine = ApplicationStateMachine()
    task_id = _task(machine)
    _advance(
        machine,
        task_id,
        [
            TaskState.THINKING,
            TaskState.PLANNING,
            TaskState.EXECUTING,
            TaskState.VERIFYING,
            TaskState.COMPLETED,
        ],
    )
    assert _snapshot(machine, task_id).state is TaskState.COMPLETED
    history = machine.history(task_id)
    assert history[0].event is TransitionEvent.TASK_CREATED
    assert all(item.task_id == task_id and item.reason for item in history)
    assert machine.application_state is ApplicationState.IDLE


def test_invalid_transition_fails_without_mutating_state() -> None:
    machine = ApplicationStateMachine()
    task_id = _task(machine)
    with pytest.raises(InvalidStateTransition):
        machine.transition_task(
            task_id,
            TaskState.EXECUTING,
            TransitionEvent.EXECUTION_STARTED,
            reason="skip planning",
        )
    assert _snapshot(machine, task_id).state is TaskState.CREATED
    with pytest.raises(InvalidStateTransition):
        machine.transition_application(
            ApplicationState.EXECUTING,
            TransitionEvent.EXECUTION_STARTED,
            reason="skip task",
        )


def test_replan_projection_transitions_require_canonical_events() -> None:
    """The visible replan path cannot be requested through an unrelated event."""

    machine = ApplicationStateMachine()
    task_id = _task(machine)
    _advance(machine, task_id, [TaskState.THINKING, TaskState.PLANNING, TaskState.EXECUTING])

    with pytest.raises(InvalidStateTransition, match="replan_requested"):
        machine.transition_task(
            task_id,
            TaskState.THINKING,
            TransitionEvent.TASK_FAILED,
            reason="untrusted relabel",
        )
    assert _snapshot(machine, task_id).state is TaskState.EXECUTING
    assert machine.application_state.value == ApplicationState.EXECUTING.value

    machine.transition_task(
        task_id,
        TaskState.THINKING,
        TransitionEvent.REPLAN_REQUESTED,
        reason="canonical durable replan",
    )
    machine.transition_task(
        task_id,
        TaskState.WAITING,
        TransitionEvent.PLAN_READY,
        reason="canonical replacement plan ready",
    )

    assert _snapshot(machine, task_id).state is TaskState.WAITING
    assert machine.application_state.value == ApplicationState.WAITING.value


def test_application_replan_transition_rejects_unrelated_event() -> None:
    machine = ApplicationStateMachine()
    task_id = _task(machine)
    _advance(machine, task_id, [TaskState.THINKING, TaskState.PLANNING, TaskState.EXECUTING])

    with pytest.raises(InvalidStateTransition, match="replan_requested"):
        machine.transition_application(
            ApplicationState.THINKING,
            TransitionEvent.EXECUTION_STARTED,
            reason="untrusted relabel",
            task_id=task_id,
        )
    assert machine.application_state is ApplicationState.EXECUTING


@pytest.mark.parametrize(
    ("current", "target"),
    [
        (TaskState.CREATED, TaskState.CANCELLED),
        (TaskState.THINKING, TaskState.CANCELLED),
        (TaskState.PLANNING, TaskState.CANCELLED),
        (TaskState.WAITING_FOR_PERMISSION, TaskState.CANCELLED),
        (TaskState.EXECUTING, TaskState.CANCELLED),
        (TaskState.VERIFYING, TaskState.CANCELLED),
        (TaskState.WAITING, TaskState.CANCELLED),
        (TaskState.ERROR, TaskState.RECOVERING),
    ],
)
def test_cancellation_and_recovery_paths(current: TaskState, target: TaskState) -> None:
    machine = ApplicationStateMachine()
    task_id = _task(machine)
    if current is not TaskState.CREATED:
        path = {
            TaskState.THINKING: [TaskState.THINKING],
            TaskState.PLANNING: [TaskState.THINKING, TaskState.PLANNING],
            TaskState.WAITING_FOR_PERMISSION: [
                TaskState.THINKING,
                TaskState.PLANNING,
                TaskState.WAITING_FOR_PERMISSION,
            ],
            TaskState.EXECUTING: [TaskState.THINKING, TaskState.PLANNING, TaskState.EXECUTING],
            TaskState.VERIFYING: [
                TaskState.THINKING,
                TaskState.PLANNING,
                TaskState.EXECUTING,
                TaskState.VERIFYING,
            ],
            TaskState.WAITING: [TaskState.THINKING, TaskState.PLANNING, TaskState.WAITING],
            TaskState.ERROR: [TaskState.THINKING, TaskState.ERROR],
            TaskState.RECOVERING: [TaskState.THINKING, TaskState.ERROR, TaskState.RECOVERING],
            TaskState.COMPLETED: [
                TaskState.THINKING,
                TaskState.PLANNING,
                TaskState.EXECUTING,
                TaskState.VERIFYING,
                TaskState.COMPLETED,
            ],
            TaskState.CANCELLED: [TaskState.CANCELLED],
        }[current]
        _advance(machine, task_id, path)
    if target is TaskState.CANCELLED:
        if current is not TaskState.CANCELLED:
            machine.cancel_task(task_id)
        assert _snapshot(machine, task_id).cancellation_requested
    else:
        machine.recover(task_id)
        assert _snapshot(machine, task_id).state is TaskState.RECOVERING


def test_independent_tasks_do_not_corrupt_foreground_or_each_other() -> None:
    machine = ApplicationStateMachine()
    first, second = _task(machine), _task(machine)
    _advance(machine, first, [TaskState.THINKING, TaskState.PLANNING])
    _advance(machine, second, [TaskState.THINKING, TaskState.PLANNING, TaskState.EXECUTING])
    assert _snapshot(machine, first).state is TaskState.PLANNING
    assert _snapshot(machine, second).state is TaskState.EXECUTING
    machine.cancel_task(first)
    assert _snapshot(machine, second).state is TaskState.EXECUTING
    assert machine.application_state is ApplicationState.EXECUTING


def test_update_and_restart_are_exclusive_while_task_is_active() -> None:
    machine = ApplicationStateMachine()
    _task(machine)
    with pytest.raises(StateConcurrencyError):
        machine.transition_application(
            ApplicationState.UPDATING,
            TransitionEvent.APP_UPDATE_REQUESTED,
            reason="update requested",
        )


def test_sqlite_store_migration_and_restart_resume(tmp_path: Path) -> None:
    path = tmp_path / "state.sqlite3"
    store = SQLiteStateStore(path)
    machine = ApplicationStateMachine(store)
    task_id = _task(machine)
    machine.transition_task(
        task_id, TaskState.THINKING, TransitionEvent.TASK_THINKING, reason="resume task"
    )
    store.close()
    reopened = SQLiteStateStore(path)
    resumed = reopened.load_task(task_id)
    assert resumed is not None
    assert resumed.state is TaskState.THINKING
    restarted_machine = ApplicationStateMachine(reopened)
    recovered = restarted_machine.task(task_id)
    assert recovered is not None
    assert recovered.state is TaskState.THINKING
    assert len(reopened.transitions(task_id)) >= 2
    reopened.close()


def test_metadata_and_timestamps_are_retained() -> None:
    machine = ApplicationStateMachine(InMemoryStateStore())
    task_id = _task(machine)
    machine.transition_task(
        task_id,
        TaskState.THINKING,
        TransitionEvent.TASK_THINKING,
        reason="thinking",
        metadata={"source": "voice", "safe": "true"},
    )
    item = machine.history(task_id)[-1]
    assert item.metadata["source"] == "voice"
    assert item.timestamp.tzinfo is UTC


def test_public_transition_tables_and_foreground_rules() -> None:
    machine = ApplicationStateMachine()
    assert ApplicationState.LISTENING in machine.allowed_application_transitions(
        ApplicationState.IDLE
    )
    assert TaskState.EXECUTING in machine.allowed_task_transitions(TaskState.PLANNING)
    task_id = _task(machine)
    machine.set_foreground_task(task_id)
    assert machine.foreground_task_id == task_id
    machine.set_foreground_task(None)
    assert machine.foreground_task_id is None
    with pytest.raises(StateMachineError):
        machine.set_foreground_task(uuid4())


def test_global_update_restart_path_is_allowed_when_idle() -> None:
    machine = ApplicationStateMachine()
    machine.transition_application(
        ApplicationState.UPDATING,
        TransitionEvent.APP_UPDATE_REQUESTED,
        reason="trusted update",
    )
    machine.transition_application(
        ApplicationState.RESTARTING,
        TransitionEvent.APP_RESTART_REQUESTED,
        reason="restart after update",
    )
    machine.transition_application(
        ApplicationState.IDLE, TransitionEvent.APP_READY, reason="startup ready"
    )
    assert machine.application_state is ApplicationState.IDLE


def test_unknown_task_operations_are_visible() -> None:
    machine = ApplicationStateMachine()
    unknown = uuid4()
    with pytest.raises(StateMachineError):
        machine.transition_task(
            unknown, TaskState.THINKING, TransitionEvent.TASK_THINKING, reason="unknown"
        )
    with pytest.raises(StateMachineError):
        machine.cancel_task(unknown)
    with pytest.raises(StateMachineError):
        machine.recover(unknown)


@pytest.mark.parametrize(
    "factory",
    [
        lambda: StateTransition(
            cast(ApplicationState, "bad"),
            ApplicationState.IDLE,
            TransitionEvent.APP_READY,
            None,
            datetime.now(UTC),
            "bad",
        ),
        lambda: StateTransition(
            ApplicationState.IDLE,
            cast(ApplicationState, "bad"),
            TransitionEvent.APP_READY,
            None,
            datetime.now(UTC),
            "bad",
        ),
        lambda: StateTransition(
            ApplicationState.IDLE,
            ApplicationState.IDLE,
            cast(TransitionEvent, "bad"),
            None,
            datetime.now(UTC),
            "bad",
        ),
        lambda: StateTransition(
            ApplicationState.IDLE,
            ApplicationState.IDLE,
            TransitionEvent.APP_READY,
            None,
            datetime.now(UTC),
            "",
        ),
        lambda: StateTransition(
            ApplicationState.IDLE,
            ApplicationState.IDLE,
            TransitionEvent.APP_READY,
            None,
            datetime.now(UTC),
            "bad",
            {"\x00": "x"},
        ),
        lambda: TaskSnapshot(uuid4(), cast(TaskState, "bad"), datetime.now(UTC), datetime.now(UTC)),
    ],
)
def test_malformed_state_records_fail_closed(factory: Callable[[], object]) -> None:
    with pytest.raises(ValueError):
        factory()


def test_task_snapshot_bounds_and_sqlite_scope_round_trip(tmp_path: Path) -> None:
    store = SQLiteStateStore(tmp_path / "scope.sqlite3")
    machine = ApplicationStateMachine(store)
    with pytest.raises(ValueError):
        TaskSnapshot(
            uuid4(), TaskState.CREATED, datetime.now(UTC), datetime.now(UTC), plan_revision=0
        )
    with pytest.raises(ValueError):
        StateTransition(
            ApplicationState.IDLE,
            ApplicationState.IDLE,
            TransitionEvent.APP_READY,
            None,
            datetime.now(UTC),
            "bad",
            scope="unknown",
        )
    machine.transition_application(
        ApplicationState.UPDATING, TransitionEvent.APP_UPDATE_REQUESTED, reason="round trip"
    )
    store.close()
    reopened = SQLiteStateStore(tmp_path / "scope.sqlite3")
    records = reopened.transitions()
    assert records[-1].scope == "application"
    reopened.close()
