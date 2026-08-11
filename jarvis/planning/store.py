"""SQLite persistence for restart-safe planning tasks and immutable plan versions."""

from __future__ import annotations

import json
import math
import sqlite3
import threading
from abc import ABC, abstractmethod
from collections.abc import Callable
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from uuid import UUID

from jarvis.permissions.models import Permission
from jarvis.planning.models import (
    BudgetUsage,
    ExecutionBudgets,
    FailureKind,
    OwnedPlan,
    OwnedPlanStatus,
    PlanningStep,
    PlanningStepStatus,
    PlanningTask,
    PlanningTaskStatus,
    StepError,
    StepResult,
)


class PlanningStoreError(RuntimeError):
    """Persistent planning state is malformed or cannot be stored atomically."""


@dataclass(frozen=True, slots=True)
class PlanningMigration:
    version: int
    name: str
    sql: str

    def __post_init__(self) -> None:
        if self.version <= 0 or not self.name.strip() or not self.sql.strip() or "\x00" in self.sql:
            raise ValueError("Planning migrations require a valid version, name, and SQL")


DEFAULT_PLANNING_MIGRATIONS = (
    PlanningMigration(
        1,
        "create_planning_state",
        """
        CREATE TABLE planning_tasks (
            task_id TEXT PRIMARY KEY,
            task_json TEXT NOT NULL,
            updated_at TEXT NOT NULL
        );
        CREATE TABLE planning_plans (
            plan_id TEXT PRIMARY KEY,
            task_id TEXT NOT NULL,
            version INTEGER NOT NULL,
            plan_json TEXT NOT NULL,
            current INTEGER NOT NULL,
            UNIQUE(task_id, version),
            FOREIGN KEY(task_id) REFERENCES planning_tasks(task_id)
        );
        CREATE INDEX planning_current_plan ON planning_plans(task_id, current);
        """,
    ),
)


class PlanningStore(ABC):
    @abstractmethod
    def create_task(self, task: PlanningTask) -> None: ...

    @abstractmethod
    def load_task(self, task_id: UUID) -> PlanningTask | None: ...

    @abstractmethod
    def load_plan(self, task_id: UUID) -> OwnedPlan | None: ...

    @abstractmethod
    def save_state(self, task: PlanningTask, plan: OwnedPlan) -> None: ...

    @abstractmethod
    def save_task(self, task: PlanningTask) -> None: ...


def _now() -> datetime:
    return datetime.now(UTC)


class SQLitePlanningStore(PlanningStore):
    """Local durable task/plan snapshots; every state transition is an atomic replacement."""

    def __init__(
        self,
        database_path: Path,
        *,
        migrations: tuple[PlanningMigration, ...] = DEFAULT_PLANNING_MIGRATIONS,
        clock: Callable[[], datetime] = _now,
    ) -> None:
        self._path = database_path
        self._migrations = migrations
        self._clock = clock
        self._validate_migrations()
        database_path.parent.mkdir(parents=True, exist_ok=True)
        self._connection = sqlite3.connect(database_path, check_same_thread=False)
        self._connection.row_factory = sqlite3.Row
        self._connection.execute("PRAGMA foreign_keys = ON")
        self._lock = threading.RLock()
        self.apply_migrations()

    @property
    def database_path(self) -> Path:
        return self._path

    def close(self) -> None:
        with self._lock:
            self._connection.close()

    def __enter__(self) -> SQLitePlanningStore:
        return self

    def __exit__(self, _type: object, _value: object, _traceback: object) -> None:
        self.close()

    def apply_migrations(self) -> None:
        with self._lock:
            try:
                self._connection.execute(
                    "CREATE TABLE IF NOT EXISTS planning_schema_migrations "
                    "(version INTEGER PRIMARY KEY, name TEXT NOT NULL, applied_at TEXT NOT NULL)"
                )
                applied = {
                    int(row["version"]): str(row["name"])
                    for row in self._connection.execute(
                        "SELECT version, name FROM planning_schema_migrations"
                    )
                }
                for migration in self._migrations:
                    existing = applied.get(migration.version)
                    if existing is not None:
                        if existing != migration.name:
                            raise PlanningStoreError("Planning migration identity mismatch")
                        continue
                    self._connection.executescript(migration.sql)
                    self._connection.execute(
                        "INSERT INTO planning_schema_migrations(version, name, applied_at) "
                        "VALUES (?, ?, ?)",
                        (migration.version, migration.name, _iso(self._clock())),
                    )
                self._connection.commit()
            except (sqlite3.DatabaseError, ValueError) as error:
                self._connection.rollback()
                raise PlanningStoreError("Planning migration failed") from error

    def create_task(self, task: PlanningTask) -> None:
        payload = json.dumps(_task_dict(task), sort_keys=True, separators=(",", ":"))
        with self._lock:
            try:
                self._connection.execute(
                    "INSERT INTO planning_tasks(task_id, task_json, updated_at) VALUES (?, ?, ?)",
                    (str(task.task_id), payload, _iso(task.updated_at)),
                )
                self._connection.commit()
            except sqlite3.IntegrityError as error:
                self._connection.rollback()
                raise PlanningStoreError("Planning task already exists") from error

    def load_task(self, task_id: UUID) -> PlanningTask | None:
        with self._lock:
            row = self._connection.execute(
                "SELECT task_json FROM planning_tasks WHERE task_id = ?", (str(task_id),)
            ).fetchone()
        if row is None:
            return None
        try:
            return _task_from_dict(_object(json.loads(str(row["task_json"]))))
        except (KeyError, TypeError, ValueError, json.JSONDecodeError) as error:
            raise PlanningStoreError("Stored planning task is malformed") from error

    def load_plan(self, task_id: UUID) -> OwnedPlan | None:
        with self._lock:
            rows = tuple(
                self._connection.execute(
                    "SELECT plan_json FROM planning_plans WHERE task_id = ? AND current = 1",
                    (str(task_id),),
                )
            )
        if len(rows) > 1:
            raise PlanningStoreError("Task has multiple current plans")
        if not rows:
            return None
        try:
            return _plan_from_dict(_object(json.loads(str(rows[0]["plan_json"]))))
        except (KeyError, TypeError, ValueError, json.JSONDecodeError) as error:
            raise PlanningStoreError("Stored planning plan is malformed") from error

    def save_task(self, task: PlanningTask) -> None:
        payload = json.dumps(_task_dict(task), sort_keys=True, separators=(",", ":"))
        with self._lock:
            cursor = self._connection.execute(
                "UPDATE planning_tasks SET task_json = ?, updated_at = ? WHERE task_id = ?",
                (payload, _iso(task.updated_at), str(task.task_id)),
            )
            if cursor.rowcount != 1:
                self._connection.rollback()
                raise PlanningStoreError("Planning task does not exist")
            self._connection.commit()

    def save_state(self, task: PlanningTask, plan: OwnedPlan) -> None:
        if task.task_id != plan.task_id or task.plan_id != plan.plan_id:
            raise PlanningStoreError("Task and plan identity do not match")
        task_payload = json.dumps(_task_dict(task), sort_keys=True, separators=(",", ":"))
        plan_payload = json.dumps(_plan_dict(plan), sort_keys=True, separators=(",", ":"))
        with self._lock:
            try:
                self._connection.execute("BEGIN IMMEDIATE")
                cursor = self._connection.execute(
                    "UPDATE planning_tasks SET task_json = ?, updated_at = ? WHERE task_id = ?",
                    (task_payload, _iso(task.updated_at), str(task.task_id)),
                )
                if cursor.rowcount != 1:
                    raise PlanningStoreError("Planning task does not exist")
                self._connection.execute(
                    "UPDATE planning_plans SET current = 0 WHERE task_id = ?",
                    (str(task.task_id),),
                )
                self._connection.execute(
                    "INSERT INTO planning_plans(plan_id, task_id, version, plan_json, current) "
                    "VALUES (?, ?, ?, ?, 1) ON CONFLICT(plan_id) DO UPDATE SET "
                    "plan_json = excluded.plan_json, current = 1",
                    (
                        str(plan.plan_id),
                        str(plan.task_id),
                        plan.version,
                        plan_payload,
                    ),
                )
                self._connection.commit()
            except (sqlite3.DatabaseError, ValueError, PlanningStoreError):
                self._connection.rollback()
                raise

    def _validate_migrations(self) -> None:
        for expected, migration in enumerate(self._migrations, start=1):
            if migration.version != expected:
                raise PlanningStoreError("Planning migrations must be sequential")


def _iso(value: datetime) -> str:
    if value.tzinfo is None:
        value = value.replace(tzinfo=UTC)
    return value.astimezone(UTC).isoformat()


def _error_dict(error: StepError | None) -> dict[str, object] | None:
    if error is None:
        return None
    return {
        "code": error.code,
        "message": error.message,
        "failure_kind": error.failure_kind.value,
        "evidence": list(error.evidence),
    }


def _error_from_dict(value: object) -> StepError | None:
    if value is None:
        return None
    data = _object(value)
    return StepError(
        code=str(data["code"]),
        message=str(data["message"]),
        failure_kind=FailureKind(str(data["failure_kind"])),
        evidence=_strings(data.get("evidence", [])),
    )


def _task_dict(task: PlanningTask) -> dict[str, object]:
    return {
        "task_id": str(task.task_id),
        "goal": task.goal,
        "original_assumptions": list(task.original_assumptions),
        "original_constraints": list(task.original_constraints),
        "status": task.status.value,
        "plan_id": str(task.plan_id) if task.plan_id else None,
        "budgets": {
            "max_steps": task.budgets.max_steps,
            "max_elapsed_seconds": task.budgets.max_elapsed_seconds,
            "max_model_calls": task.budgets.max_model_calls,
            "max_expensive_actions": task.budgets.max_expensive_actions,
            "max_retries": task.budgets.max_retries,
        },
        "usage": {
            "executed_steps": task.usage.executed_steps,
            "model_calls": task.usage.model_calls,
            "expensive_actions": task.usage.expensive_actions,
            "retries": task.usage.retries,
        },
        "created_at": _iso(task.created_at),
        "started_at": _iso(task.started_at),
        "deadline": _iso(task.deadline),
        "updated_at": _iso(task.updated_at),
        "active_step_id": str(task.active_step_id) if task.active_step_id else None,
        "waiting_request_ids": [str(item) for item in task.waiting_request_ids],
        "cancellation_requested": task.cancellation_requested,
        "result_evidence": list(task.result_evidence),
        "error": _error_dict(task.error),
    }


def _task_from_dict(data: dict[str, object]) -> PlanningTask:
    budget = _object(data["budgets"])
    usage = _object(data["usage"])
    return PlanningTask(
        task_id=UUID(str(data["task_id"])),
        goal=str(data["goal"]),
        original_assumptions=_strings(data["original_assumptions"]),
        original_constraints=_strings(data["original_constraints"]),
        status=PlanningTaskStatus(str(data["status"])),
        plan_id=UUID(str(data["plan_id"])) if data.get("plan_id") else None,
        budgets=ExecutionBudgets(
            max_steps=_int(budget["max_steps"]),
            max_elapsed_seconds=_float(budget["max_elapsed_seconds"]),
            max_model_calls=_int(budget["max_model_calls"]),
            max_expensive_actions=_int(budget["max_expensive_actions"]),
            max_retries=_int(budget["max_retries"]),
        ),
        usage=BudgetUsage(
            executed_steps=_int(usage["executed_steps"]),
            model_calls=_int(usage["model_calls"]),
            expensive_actions=_int(usage["expensive_actions"]),
            retries=_int(usage["retries"]),
        ),
        created_at=datetime.fromisoformat(str(data["created_at"])),
        started_at=datetime.fromisoformat(str(data["started_at"])),
        deadline=datetime.fromisoformat(str(data["deadline"])),
        updated_at=datetime.fromisoformat(str(data["updated_at"])),
        active_step_id=UUID(str(data["active_step_id"])) if data.get("active_step_id") else None,
        waiting_request_ids=tuple(UUID(value) for value in _strings(data["waiting_request_ids"])),
        cancellation_requested=_bool(data["cancellation_requested"]),
        result_evidence=_strings(data["result_evidence"]),
        error=_error_from_dict(data.get("error")),
    )


def _step_dict(step: PlanningStep) -> dict[str, object]:
    return {
        "step_id": str(step.step_id),
        "key": step.key,
        "tool_id": step.tool_id,
        "capability": step.capability,
        "input_json": step.input_json,
        "expected_output": step.expected_output,
        "verification_rule": step.verification_rule,
        "expected_evidence": list(step.expected_evidence),
        "dependencies": [str(item) for item in step.dependencies],
        "required_permissions": [item.value for item in step.required_permissions],
        "expensive_action": step.expensive_action,
        "max_retries": step.max_retries,
        "status": step.status.value,
        "attempts": step.attempts,
        "result": (
            {"output_json": step.result.output_json, "evidence": list(step.result.evidence)}
            if step.result
            else None
        ),
        "error": _error_dict(step.error),
    }


def _step_from_dict(data: dict[str, object]) -> PlanningStep:
    raw_result = data.get("result")
    result = None
    if raw_result is not None:
        result_data = _object(raw_result)
        result = StepResult(str(result_data["output_json"]), _strings(result_data["evidence"]))
    return PlanningStep(
        step_id=UUID(str(data["step_id"])),
        key=str(data["key"]),
        tool_id=str(data["tool_id"]),
        capability=str(data["capability"]),
        input_json=str(data["input_json"]),
        expected_output=str(data["expected_output"]),
        verification_rule=str(data["verification_rule"]),
        expected_evidence=_strings(data["expected_evidence"]),
        dependencies=tuple(UUID(value) for value in _strings(data["dependencies"])),
        required_permissions=tuple(
            Permission(value) for value in _strings(data["required_permissions"])
        ),
        expensive_action=_bool(data["expensive_action"]),
        max_retries=_int(data["max_retries"]),
        status=PlanningStepStatus(str(data["status"])),
        attempts=_int(data["attempts"]),
        result=result,
        error=_error_from_dict(data.get("error")),
    )


def _plan_dict(plan: OwnedPlan) -> dict[str, object]:
    return {
        "plan_id": str(plan.plan_id),
        "task_id": str(plan.task_id),
        "version": plan.version,
        "goal": plan.goal,
        "assumptions": list(plan.assumptions),
        "constraints": list(plan.constraints),
        "steps": [_step_dict(step) for step in plan.steps],
        "required_capabilities": list(plan.required_capabilities),
        "required_permissions": [item.value for item in plan.required_permissions],
        "completion_criteria": list(plan.completion_criteria),
        "status": plan.status.value,
        "created_at": _iso(plan.created_at),
        "updated_at": _iso(plan.updated_at),
    }


def _plan_from_dict(data: dict[str, object]) -> OwnedPlan:
    raw_steps = data["steps"]
    if not isinstance(raw_steps, list):
        raise PlanningStoreError("Stored plan steps are malformed")
    return OwnedPlan(
        plan_id=UUID(str(data["plan_id"])),
        task_id=UUID(str(data["task_id"])),
        version=_int(data["version"]),
        goal=str(data["goal"]),
        assumptions=_strings(data["assumptions"]),
        constraints=_strings(data["constraints"]),
        steps=tuple(_step_from_dict(_object(step)) for step in raw_steps),
        required_capabilities=_strings(data["required_capabilities"]),
        required_permissions=tuple(
            Permission(value) for value in _strings(data["required_permissions"])
        ),
        completion_criteria=_strings(data["completion_criteria"]),
        status=OwnedPlanStatus(str(data["status"])),
        created_at=datetime.fromisoformat(str(data["created_at"])),
        updated_at=datetime.fromisoformat(str(data["updated_at"])),
    )


def _object(value: object) -> dict[str, object]:
    if not isinstance(value, dict):
        raise PlanningStoreError("Stored planning value must be an object")
    return {str(key): item for key, item in value.items()}


def _strings(value: object) -> tuple[str, ...]:
    if not isinstance(value, list) or any(not isinstance(item, str) for item in value):
        raise PlanningStoreError("Stored planning value must be a string list")
    return tuple(value)


def _int(value: object) -> int:
    if not isinstance(value, int) or isinstance(value, bool):
        raise PlanningStoreError("Stored planning value must be an integer")
    return value


def _float(value: object) -> float:
    if not isinstance(value, int | float) or isinstance(value, bool):
        raise PlanningStoreError("Stored planning value must be numeric")
    result = float(value)
    if not math.isfinite(result):
        raise PlanningStoreError("Stored planning value must be finite")
    return result


def _bool(value: object) -> bool:
    if not isinstance(value, bool):
        raise PlanningStoreError("Stored planning value must be boolean")
    return value
