"""Fail-closed application/task transition coordinator."""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import replace
from datetime import UTC, datetime
from threading import RLock
from types import MappingProxyType
from uuid import UUID

from jarvis.events import EventBus, EventEnvelope, EventType, TaskCreated, TaskStateChanged
from jarvis.state.models import (
    ApplicationState,
    StateTransition,
    TaskSnapshot,
    TaskState,
    TransitionEvent,
)
from jarvis.state.store import InMemoryStateStore, StateStore


class StateMachineError(RuntimeError):
    """Base error for visible lifecycle failures."""


class InvalidStateTransition(StateMachineError):
    """Raised when an event is not allowed from the current state."""


class StateConcurrencyError(StateMachineError):
    """Raised when an exclusive application lifecycle transition is unsafe."""


_APP_TRANSITIONS: dict[ApplicationState, frozenset[ApplicationState]] = {
    ApplicationState.IDLE: frozenset(
        {
            ApplicationState.LISTENING,
            ApplicationState.THINKING,
            ApplicationState.UPDATING,
            ApplicationState.RESTARTING,
            ApplicationState.ERROR,
        }
    ),
    ApplicationState.LISTENING: frozenset(
        {
            ApplicationState.PROCESSING,
            ApplicationState.THINKING,
            ApplicationState.IDLE,
            ApplicationState.ERROR,
        }
    ),
    ApplicationState.PROCESSING: frozenset(
        {
            ApplicationState.THINKING,
            ApplicationState.LISTENING,
            ApplicationState.IDLE,
            ApplicationState.SPEAKING,
            ApplicationState.ERROR,
        }
    ),
    ApplicationState.THINKING: frozenset(
        {
            ApplicationState.PLANNING,
            ApplicationState.WAITING,
            ApplicationState.ERROR,
            ApplicationState.IDLE,
        }
    ),
    ApplicationState.PLANNING: frozenset(
        {
            ApplicationState.WAITING_FOR_PERMISSION,
            ApplicationState.EXECUTING,
            ApplicationState.WAITING,
            ApplicationState.ERROR,
            ApplicationState.IDLE,
        }
    ),
    ApplicationState.WAITING_FOR_PERMISSION: frozenset(
        {
            ApplicationState.PLANNING,
            ApplicationState.EXECUTING,
            ApplicationState.WAITING,
            ApplicationState.ERROR,
            ApplicationState.IDLE,
        }
    ),
    ApplicationState.EXECUTING: frozenset(
        {
            ApplicationState.VERIFYING,
            ApplicationState.WAITING_FOR_PERMISSION,
            ApplicationState.WAITING,
            ApplicationState.RECOVERING,
            ApplicationState.ERROR,
            ApplicationState.IDLE,
        }
    ),
    ApplicationState.VERIFYING: frozenset(
        {
            ApplicationState.THINKING,
            ApplicationState.SPEAKING,
            ApplicationState.WAITING,
            ApplicationState.IDLE,
            ApplicationState.ERROR,
            ApplicationState.RECOVERING,
        }
    ),
    ApplicationState.WAITING: frozenset(
        {
            ApplicationState.EXECUTING,
            ApplicationState.THINKING,
            ApplicationState.VERIFYING,
            ApplicationState.IDLE,
            ApplicationState.ERROR,
        }
    ),
    ApplicationState.SPEAKING: frozenset(
        {ApplicationState.IDLE, ApplicationState.LISTENING, ApplicationState.ERROR}
    ),
    ApplicationState.ERROR: frozenset({ApplicationState.RECOVERING, ApplicationState.IDLE}),
    ApplicationState.RECOVERING: frozenset(
        {ApplicationState.IDLE, ApplicationState.THINKING, ApplicationState.ERROR}
    ),
    ApplicationState.UPDATING: frozenset(
        {ApplicationState.RESTARTING, ApplicationState.ERROR, ApplicationState.IDLE}
    ),
    ApplicationState.RESTARTING: frozenset({ApplicationState.IDLE, ApplicationState.ERROR}),
}

_TASK_TRANSITIONS: dict[TaskState, frozenset[TaskState]] = {
    TaskState.CREATED: frozenset({TaskState.THINKING, TaskState.CANCELLED, TaskState.ERROR}),
    TaskState.THINKING: frozenset({TaskState.PLANNING, TaskState.ERROR, TaskState.CANCELLED}),
    TaskState.PLANNING: frozenset(
        {
            TaskState.WAITING_FOR_PERMISSION,
            TaskState.EXECUTING,
            TaskState.WAITING,
            TaskState.ERROR,
            TaskState.CANCELLED,
        }
    ),
    TaskState.WAITING_FOR_PERMISSION: frozenset(
        {
            TaskState.PLANNING,
            TaskState.EXECUTING,
            TaskState.WAITING,
            TaskState.ERROR,
            TaskState.CANCELLED,
        }
    ),
    TaskState.EXECUTING: frozenset(
        {
            TaskState.VERIFYING,
            TaskState.WAITING_FOR_PERMISSION,
            TaskState.WAITING,
            TaskState.RECOVERING,
            TaskState.ERROR,
            TaskState.CANCELLED,
        }
    ),
    TaskState.VERIFYING: frozenset(
        {
            TaskState.THINKING,
            TaskState.WAITING,
            TaskState.COMPLETED,
            TaskState.ERROR,
            TaskState.CANCELLED,
            TaskState.RECOVERING,
        }
    ),
    TaskState.WAITING: frozenset(
        {
            TaskState.EXECUTING,
            TaskState.THINKING,
            TaskState.VERIFYING,
            TaskState.CANCELLED,
            TaskState.ERROR,
        }
    ),
    TaskState.RECOVERING: frozenset(
        {TaskState.THINKING, TaskState.COMPLETED, TaskState.ERROR, TaskState.CANCELLED}
    ),
    TaskState.COMPLETED: frozenset(),
    TaskState.ERROR: frozenset({TaskState.RECOVERING, TaskState.CANCELLED}),
    TaskState.CANCELLED: frozenset(),
}


_TASK_TO_APP = {
    TaskState.THINKING: ApplicationState.THINKING,
    TaskState.PLANNING: ApplicationState.PLANNING,
    TaskState.WAITING_FOR_PERMISSION: ApplicationState.WAITING_FOR_PERMISSION,
    TaskState.EXECUTING: ApplicationState.EXECUTING,
    TaskState.VERIFYING: ApplicationState.VERIFYING,
    TaskState.WAITING: ApplicationState.WAITING,
    TaskState.RECOVERING: ApplicationState.RECOVERING,
    TaskState.ERROR: ApplicationState.ERROR,
}

# Public read-only transition tables used by UI/docs/tests; callers cannot mutate policy.
APPLICATION_TRANSITIONS = MappingProxyType(_APP_TRANSITIONS)
TASK_TRANSITIONS = MappingProxyType(_TASK_TRANSITIONS)


class ApplicationStateMachine:
    """Own global state and independent task snapshots under one transition table."""

    def __init__(
        self, store: StateStore | None = None, *, event_bus: EventBus | None = None
    ) -> None:
        self._store = store or InMemoryStateStore()
        self._event_bus = event_bus
        self._application_state = ApplicationState.IDLE
        self._tasks: dict[UUID, TaskSnapshot] = {item.task_id: item for item in self._store.tasks()}
        self._history: list[StateTransition] = []
        self._foreground_task: UUID | None = None
        self._lock = RLock()

    @property
    def application_state(self) -> ApplicationState:
        return self._application_state

    @staticmethod
    def allowed_application_transitions(
        state: ApplicationState,
    ) -> frozenset[ApplicationState]:
        return _APP_TRANSITIONS[state]

    @staticmethod
    def allowed_task_transitions(state: TaskState) -> frozenset[TaskState]:
        return _TASK_TRANSITIONS[state]

    @property
    def foreground_task_id(self) -> UUID | None:
        return self._foreground_task

    def task(self, task_id: UUID) -> TaskSnapshot | None:
        with self._lock:
            return self._tasks.get(task_id) or self._store.load_task(task_id)

    def tasks(self) -> tuple[TaskSnapshot, ...]:
        with self._lock:
            return tuple(self._tasks.values())

    def history(self, task_id: UUID | None = None) -> tuple[StateTransition, ...]:
        with self._lock:
            values = self._history
            if task_id is not None:
                values = [item for item in values if item.task_id == task_id]
            return tuple(values)

    def create_task(self, task_id: UUID, *, reason: str = "task created") -> TaskSnapshot:
        with self._lock:
            if task_id in self._tasks or self._store.load_task(task_id) is not None:
                raise StateMachineError(f"Task already exists: {task_id}")
            now = datetime.now(UTC)
            snapshot = TaskSnapshot(task_id, TaskState.CREATED, now, now)
            self._tasks[task_id] = snapshot
            self._store.save_task(snapshot)
            self._record(
                StateTransition(
                    TaskState.CREATED,
                    TaskState.CREATED,
                    TransitionEvent.TASK_CREATED,
                    task_id,
                    now,
                    reason,
                    scope="task",
                )
            )
            return snapshot

    def transition_task(
        self,
        task_id: UUID,
        to_state: TaskState,
        event: TransitionEvent,
        *,
        reason: str,
        metadata: Mapping[str, str] | None = None,
        plan_revision: int | None = None,
        active_step_id: UUID | None = None,
    ) -> TaskSnapshot:
        with self._lock:
            current = self._tasks.get(task_id) or self._store.load_task(task_id)
            if current is None:
                raise StateMachineError(f"Task does not exist: {task_id}")
            self._ensure_allowed(current.state, to_state, event, task_id)
            now = datetime.now(UTC)
            updated = replace(
                current,
                state=to_state,
                updated_at=now,
                cancellation_requested=current.cancellation_requested
                or to_state is TaskState.CANCELLED,
                plan_revision=plan_revision if plan_revision is not None else current.plan_revision,
                active_step_id=active_step_id,
            )
            self._tasks[task_id] = updated
            self._store.save_task(updated)
            self._record(
                StateTransition(
                    current.state, to_state, event, task_id, now, reason, metadata or {}, "task"
                )
            )
            self._sync_application(to_state, task_id, event, reason, metadata or {})
            return updated

    def cancel_task(
        self, task_id: UUID, *, reason: str = "task cancellation requested"
    ) -> TaskSnapshot:
        current = self.task(task_id)
        if current is None:
            raise StateMachineError(f"Task does not exist: {task_id}")
        return self.transition_task(
            task_id, TaskState.CANCELLED, TransitionEvent.TASK_CANCELLED, reason=reason
        )

    def transition_application(
        self,
        to_state: ApplicationState,
        event: TransitionEvent,
        *,
        reason: str,
        task_id: UUID | None = None,
        metadata: Mapping[str, str] | None = None,
    ) -> ApplicationState:
        with self._lock:
            current = self._application_state
            self._ensure_allowed(current, to_state, event, task_id)
            if to_state in {ApplicationState.UPDATING, ApplicationState.RESTARTING}:
                active = [
                    item
                    for item in self._tasks.values()
                    if item.state not in {TaskState.COMPLETED, TaskState.CANCELLED}
                ]
                if active:
                    raise StateConcurrencyError("Cannot update/restart while tasks are active")
            now = datetime.now(UTC)
            self._application_state = to_state
            self._record(
                StateTransition(
                    current, to_state, event, task_id, now, reason, metadata or {}, "application"
                )
            )
            return to_state

    def set_foreground_task(self, task_id: UUID | None) -> None:
        with self._lock:
            if task_id is not None and self.task(task_id) is None:
                raise StateMachineError(f"Cannot foreground unknown task: {task_id}")
            self._foreground_task = task_id

    def recover(self, task_id: UUID, *, reason: str = "recovering persisted task") -> TaskSnapshot:
        current = self.task(task_id)
        if current is None:
            raise StateMachineError(f"Task does not exist: {task_id}")
        return self.transition_task(
            task_id, TaskState.RECOVERING, TransitionEvent.RECOVERY_STARTED, reason=reason
        )

    def reconcile_projection(
        self,
        task_id: UUID,
        target: TaskState,
        *,
        reason: str,
        plan_revision: int | None = None,
    ) -> TaskSnapshot:
        """Repair a non-authoritative state projection from durable planning truth."""

        with self._lock:
            current = self._tasks.get(task_id) or self._store.load_task(task_id)
            if current is None:
                self.create_task(task_id, reason="rebuild state projection")
                current = self._tasks[task_id]
            if current.state is target:
                return current
            now = datetime.now(UTC)
            updated = replace(
                current,
                state=target,
                updated_at=now,
                plan_revision=plan_revision if plan_revision is not None else current.plan_revision,
                recovery_count=current.recovery_count + 1,
            )
            self._tasks[task_id] = updated
            self._store.save_task(updated)
            self._record(
                StateTransition(
                    current.state,
                    target,
                    TransitionEvent.RECOVERY_STARTED,
                    task_id,
                    now,
                    reason,
                    {"projection": "reconciled"},
                    "task",
                )
            )
            return updated

    def _sync_application(
        self,
        task_state: TaskState,
        task_id: UUID,
        event: TransitionEvent,
        reason: str,
        metadata: Mapping[str, str],
    ) -> None:
        if self._foreground_task not in {None, task_id}:
            return
        if self._foreground_task is None:
            self._foreground_task = task_id
        if task_state in {TaskState.COMPLETED, TaskState.CANCELLED}:
            remaining = [
                item
                for item in self._tasks.values()
                if item.task_id != task_id
                and item.state not in {TaskState.COMPLETED, TaskState.CANCELLED}
            ]
            if not remaining and self._application_state is not ApplicationState.IDLE:
                old = self._application_state
                now = datetime.now(UTC)
                self._application_state = ApplicationState.IDLE
                self._record(
                    StateTransition(
                        old,
                        ApplicationState.IDLE,
                        event,
                        task_id,
                        now,
                        reason,
                        metadata,
                        "application",
                    )
                )
                self._foreground_task = None
            elif remaining:
                self._foreground_task = remaining[0].task_id
                handoff_target: ApplicationState | None = _TASK_TO_APP.get(remaining[0].state)
                if handoff_target is not None and handoff_target is not self._application_state:
                    if handoff_target not in _APP_TRANSITIONS[self._application_state]:
                        raise InvalidStateTransition(
                            f"Application {self._application_state.value} cannot follow "
                            f"foreground task {remaining[0].task_id}"
                        )
                    old_state: ApplicationState = self._application_state
                    now = datetime.now(UTC)
                    self._application_state = ApplicationState(str(handoff_target))
                    self._record(
                        StateTransition(
                            old_state,
                            self._application_state,
                            event,
                            remaining[0].task_id,
                            now,
                            "foreground task selected after terminal task",
                            metadata,
                            "application",
                        )
                    )
            return
        mapped_target: ApplicationState | None = _TASK_TO_APP.get(task_state)
        if mapped_target is None:
            return
        if mapped_target is self._application_state:
            return
        if mapped_target not in _APP_TRANSITIONS[self._application_state]:
            raise InvalidStateTransition(
                f"Application {self._application_state.value} cannot follow task "
                f"{task_id} to {task_state.value}"
            )
        now = datetime.now(UTC)
        previous_state: ApplicationState = self._application_state
        next_state: ApplicationState = ApplicationState(str(mapped_target))
        self._application_state = next_state
        self._record(
            StateTransition(
                previous_state, next_state, event, task_id, now, reason, metadata, "application"
            )
        )

    def _record(self, transition: StateTransition) -> None:
        self._history.append(transition)
        self._store.append_transition(transition)
        if self._event_bus is None:
            return
        payload: TaskCreated | TaskStateChanged
        if transition.scope == "task" and transition.event is TransitionEvent.TASK_CREATED:
            payload = TaskCreated(transition.reason)
            event_type = EventType.TASK_CREATED
        elif transition.scope == "task":
            payload = TaskStateChanged(
                str(transition.from_state.value), str(transition.to_state.value), transition.reason
            )
            event_type = EventType.TASK_STATE_CHANGED
        else:
            # Application transitions are represented by the same bounded state event;
            # task_id remains optional and no state authority moves into the bus.
            payload = TaskStateChanged(
                str(transition.from_state.value), str(transition.to_state.value), transition.reason
            )
            event_type = EventType.TASK_STATE_CHANGED
        correlation_id = transition.task_id or UUID(int=0)
        self._event_bus.publish_nowait(
            EventEnvelope.create(
                event_type,
                payload,
                source="state.machine",
                task_id=transition.task_id,
                correlation_id=correlation_id,
            )
        )

    @staticmethod
    def _ensure_allowed(
        current: ApplicationState | TaskState,
        target: ApplicationState | TaskState,
        event: TransitionEvent,
        task_id: UUID | None,
    ) -> None:
        allowed = (
            _APP_TRANSITIONS.get(current, frozenset())
            if isinstance(current, ApplicationState)
            else _TASK_TRANSITIONS.get(current, frozenset())
        )
        if target not in allowed:
            scope = f" for task {task_id}" if task_id else ""
            raise InvalidStateTransition(
                f"Invalid transition{scope}: {current.value} -> {target.value} on {event.value}"
            )
