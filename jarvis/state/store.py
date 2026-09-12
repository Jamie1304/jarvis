"""Small durable state stores with an explicit schema migration."""

from __future__ import annotations

import json
import sqlite3
from abc import ABC, abstractmethod
from datetime import datetime
from pathlib import Path
from threading import RLock
from uuid import UUID

from jarvis.state.models import (
    ApplicationState,
    StateTransition,
    TaskSnapshot,
    TaskState,
    TransitionEvent,
)


class StateStoreError(RuntimeError):
    """Durable state projection is unavailable or malformed."""


class StateStore(ABC):
    @abstractmethod
    def save_task(self, task: TaskSnapshot) -> None: ...

    @abstractmethod
    def load_task(self, task_id: UUID) -> TaskSnapshot | None: ...

    @abstractmethod
    def append_transition(self, transition: StateTransition) -> None: ...

    @abstractmethod
    def transitions(self, task_id: UUID | None = None) -> tuple[StateTransition, ...]: ...

    def tasks(self) -> tuple[TaskSnapshot, ...]:
        """Optional recovery enumeration; stores may return an empty tuple."""

        return ()


class InMemoryStateStore(StateStore):
    def __init__(self) -> None:
        self._tasks: dict[UUID, TaskSnapshot] = {}
        self._transitions: list[StateTransition] = []
        self._lock = RLock()

    def save_task(self, task: TaskSnapshot) -> None:
        with self._lock:
            self._tasks[task.task_id] = task

    def load_task(self, task_id: UUID) -> TaskSnapshot | None:
        with self._lock:
            return self._tasks.get(task_id)

    def append_transition(self, transition: StateTransition) -> None:
        with self._lock:
            self._transitions.append(transition)

    def transitions(self, task_id: UUID | None = None) -> tuple[StateTransition, ...]:
        with self._lock:
            values = self._transitions
            if task_id is not None:
                values = [item for item in values if item.task_id == task_id]
            return tuple(values)

    def tasks(self) -> tuple[TaskSnapshot, ...]:
        with self._lock:
            return tuple(self._tasks.values())


class SQLiteStateStore(StateStore):
    """SQLite persistence for task recovery and transition audit history."""

    _MIGRATIONS = (
        """
        CREATE TABLE IF NOT EXISTS state_schema (
            version INTEGER PRIMARY KEY
        )
        """,
        """
        CREATE TABLE IF NOT EXISTS state_tasks (
            task_id TEXT PRIMARY KEY,
            state TEXT NOT NULL,
            created_at TEXT NOT NULL,
            updated_at TEXT NOT NULL,
            cancellation_requested INTEGER NOT NULL,
            plan_revision INTEGER,
            active_step_id TEXT,
            recovery_count INTEGER NOT NULL,
            metadata_json TEXT NOT NULL
        )
        """,
        """
        CREATE TABLE IF NOT EXISTS state_transitions (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            from_state TEXT NOT NULL,
            to_state TEXT NOT NULL,
            event TEXT NOT NULL,
            task_id TEXT,
            timestamp TEXT NOT NULL,
            reason TEXT NOT NULL,
            metadata_json TEXT NOT NULL
        )
        """,
        "ALTER TABLE state_transitions ADD COLUMN scope TEXT NOT NULL DEFAULT 'task'",
    )

    def __init__(self, database_path: str | Path) -> None:
        self._path = str(database_path)
        if self._path != ":memory:":
            Path(self._path).parent.mkdir(parents=True, exist_ok=True)
        self._connection = sqlite3.connect(self._path, check_same_thread=False)
        self._connection.row_factory = sqlite3.Row
        self._connection.execute("PRAGMA foreign_keys = ON")
        self._connection.execute("PRAGMA busy_timeout = 5000")
        self._connection.execute("PRAGMA journal_mode = WAL")
        self._lock = RLock()
        self._integrity_check()
        self._migrate()

    def _migrate(self) -> None:
        with self._lock, self._connection:
            self._connection.execute(self._MIGRATIONS[0])
            current = self._connection.execute("SELECT MAX(version) FROM state_schema").fetchone()[
                0
            ]
            current = int(current or 0)
            if current > len(self._MIGRATIONS) - 1:
                raise StateStoreError("State database uses a future schema")
            for version, migration in enumerate(self._MIGRATIONS[1:], start=1):
                if current < version:
                    self._connection.execute(migration)
                    self._connection.execute(
                        "INSERT INTO state_schema(version) VALUES (?)", (version,)
                    )

    def _integrity_check(self) -> None:
        try:
            row = self._connection.execute("PRAGMA integrity_check").fetchone()
        except sqlite3.DatabaseError as error:
            raise StateStoreError("State database integrity check failed") from error
        if row is None or str(row[0]).casefold() != "ok":
            raise StateStoreError("State database is corrupt")

    def save_task(self, task: TaskSnapshot) -> None:
        with self._lock, self._connection:
            self._connection.execute(
                """
                INSERT INTO state_tasks VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(task_id) DO UPDATE SET state=excluded.state,
                updated_at=excluded.updated_at,
                cancellation_requested=excluded.cancellation_requested,
                plan_revision=excluded.plan_revision, active_step_id=excluded.active_step_id,
                recovery_count=excluded.recovery_count, metadata_json=excluded.metadata_json
                """,
                (
                    str(task.task_id),
                    task.state.value,
                    task.created_at.isoformat(),
                    task.updated_at.isoformat(),
                    int(task.cancellation_requested),
                    task.plan_revision,
                    str(task.active_step_id) if task.active_step_id else None,
                    task.recovery_count,
                    json.dumps(dict(task.metadata), sort_keys=True),
                ),
            )

    def load_task(self, task_id: UUID) -> TaskSnapshot | None:
        with self._lock:
            row = self._connection.execute(
                "SELECT * FROM state_tasks WHERE task_id = ?", (str(task_id),)
            ).fetchone()
        if row is None:
            return None
        return TaskSnapshot(
            task_id=UUID(row["task_id"]),
            state=TaskState(row["state"]),
            created_at=datetime.fromisoformat(row["created_at"]),
            updated_at=datetime.fromisoformat(row["updated_at"]),
            cancellation_requested=bool(row["cancellation_requested"]),
            plan_revision=row["plan_revision"],
            active_step_id=UUID(row["active_step_id"]) if row["active_step_id"] else None,
            recovery_count=int(row["recovery_count"]),
            metadata=json.loads(row["metadata_json"]),
        )

    def tasks(self) -> tuple[TaskSnapshot, ...]:
        with self._lock:
            rows = self._connection.execute("SELECT task_id FROM state_tasks").fetchall()
        values = [self.load_task(UUID(row["task_id"])) for row in rows]
        return tuple(item for item in values if item is not None)

    def append_transition(self, transition: StateTransition) -> None:
        with self._lock, self._connection:
            self._connection.execute(
                """
                INSERT INTO state_transitions
                (from_state,to_state,event,task_id,timestamp,reason,metadata_json,scope)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    transition.from_state.value,
                    transition.to_state.value,
                    transition.event.value,
                    str(transition.task_id) if transition.task_id else None,
                    transition.timestamp.isoformat(),
                    transition.reason,
                    json.dumps(dict(transition.metadata), sort_keys=True),
                    transition.scope,
                ),
            )

    def transitions(self, task_id: UUID | None = None) -> tuple[StateTransition, ...]:
        with self._lock:
            if task_id is None:
                rows = self._connection.execute(
                    "SELECT * FROM state_transitions ORDER BY id"
                ).fetchall()
            else:
                rows = self._connection.execute(
                    "SELECT * FROM state_transitions WHERE task_id = ? ORDER BY id", (str(task_id),)
                ).fetchall()
        result: list[StateTransition] = []
        for row in rows:
            task = UUID(row["task_id"]) if row["task_id"] else None
            from_state = row["from_state"]
            to_state = row["to_state"]
            # Task and application values overlap; transition records are queried
            # by the machine, while persistence retains the exact value strings.
            state_type = TaskState if row["scope"] == "task" else ApplicationState
            result.append(
                StateTransition(
                    state_type(from_state),
                    state_type(to_state),
                    TransitionEvent(row["event"]),
                    task,
                    datetime.fromisoformat(row["timestamp"]),
                    row["reason"],
                    json.loads(row["metadata_json"]),
                    row["scope"],
                )
            )
        return tuple(result)

    def close(self) -> None:
        with self._lock:
            self._connection.close()
