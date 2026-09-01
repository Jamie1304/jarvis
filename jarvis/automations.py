"""Generic event-driven automation above the canonical planning boundary.

Automations observe typed facts and may submit a fixed goal or a validated
WorkflowTemplate proposal. They never execute tools, create approvals, or
interpret external event data as policy.
"""

from __future__ import annotations

import asyncio
import hashlib
import json
import math
import sqlite3
import threading
from collections import deque
from collections.abc import Callable, Mapping, Sequence
from dataclasses import asdict, dataclass, field, is_dataclass, replace
from datetime import UTC, datetime, timedelta
from enum import StrEnum
from pathlib import Path
from typing import Any, Protocol, cast
from uuid import UUID, uuid4

from jarvis.events import (
    AutomationStateChanged,
    EventBus,
    EventEnvelope,
    EventPayload,
    EventType,
)
from jarvis.planning.models import ExecutionBudgets, PlanningTaskStatus
from jarvis.task_controller import TaskController
from jarvis.trace import ExecutionTrace, TraceEvent, TraceEventType, TraceStore
from jarvis.workflows import WorkflowTemplateRegistry


class AutomationError(RuntimeError):
    """An automation cannot safely be registered, persisted, or executed."""


class AutomationValidationError(AutomationError, ValueError):
    """An automation contract or condition is malformed."""


class ConditionOperator(StrEnum):
    EQUALS = "equals"
    NOT_EQUALS = "not_equals"
    EXISTS = "exists"
    CONTAINS = "contains"
    IN = "in"


class ConcurrencyPolicy(StrEnum):
    DROP = "drop"
    QUEUE = "queue"
    RESTART_IF_SAFE = "restart_if_safe"
    PARALLEL_BOUNDED = "parallel_bounded"


class AutomationRunStatus(StrEnum):
    DEBOUNCED = "debounced"
    QUEUED = "queued"
    RUNNING = "running"
    WAITING_FOR_PERMISSION = "waiting_for_permission"
    COMPLETED = "completed"
    FAILED = "failed"
    DROPPED = "dropped"
    SIMULATED = "simulated"
    CANCELLED = "cancelled"


_MISSING = object()
_MAX_TEXT = 4_000
_MAX_DEFINITIONS = 1_024
_MAX_RUNS = 4_096
_PATH = "event_type|source|task_id|correlation_id|payload(?:\\.[A-Za-z_][A-Za-z0-9_]*)*"


def _text(value: object, field_name: str, limit: int = _MAX_TEXT) -> str:
    if (
        type(value) is not str
        or not value.strip()
        or len(value) > limit
        or "\x00" in value
        or any(not character.isprintable() for character in value)
    ):
        raise AutomationValidationError(f"{field_name} is malformed")
    return value


def _utc(value: datetime, field_name: str) -> datetime:
    if not isinstance(value, datetime) or value.tzinfo is None:
        raise AutomationValidationError(f"{field_name} must be timezone-aware")
    return value.astimezone(UTC)


def _json_safe(value: object, *, depth: int = 0) -> object:
    if depth > 5:
        raise AutomationValidationError("Automation value is too deeply nested")
    if value is None or type(value) is bool or type(value) is int:
        return value
    if type(value) is float:
        if not math.isfinite(value):
            raise AutomationValidationError("Automation value is not finite")
        return value
    if type(value) is str:
        return _text(value, "Automation value", 2_000)
    if isinstance(value, Mapping):
        if len(value) > 64:
            raise AutomationValidationError("Automation mapping is too large")
        return {
            _text(key, "Automation key", 128): _json_safe(item, depth=depth + 1)
            for key, item in value.items()
        }
    if isinstance(value, Sequence) and not isinstance(value, str | bytes | bytearray):
        if len(value) > 64:
            raise AutomationValidationError("Automation sequence is too large")
        return tuple(_json_safe(item, depth=depth + 1) for item in value)
    raise AutomationValidationError("Automation value is not JSON-like")


def _canonical(value: object) -> object:
    if isinstance(value, StrEnum):
        return value.value
    if isinstance(value, UUID):
        return str(value)
    if isinstance(value, datetime):
        return value.astimezone(UTC).isoformat()
    if is_dataclass(value):
        return {key: _canonical(item) for key, item in asdict(cast(Any, value)).items()}
    if isinstance(value, Mapping):
        return {
            str(key): _canonical(item)
            for key, item in sorted(value.items(), key=lambda i: str(i[0]))
        }
    if isinstance(value, Sequence) and not isinstance(value, str | bytes | bytearray):
        return [_canonical(item) for item in value]
    return value


def _fingerprint(value: object) -> str:
    payload = json.dumps(_canonical(value), sort_keys=True, separators=(",", ":")).encode("utf-8")
    return hashlib.sha256(payload).hexdigest()


@dataclass(frozen=True, slots=True)
class Condition:
    """A declarative, read-only predicate over bounded event fields."""

    path: str
    operator: ConditionOperator
    expected: object = None

    def __post_init__(self) -> None:
        _text(self.path, "Condition path", 256)
        import re

        if re.fullmatch(_PATH, self.path) is None or any(
            part.startswith("__") for part in self.path.split(".")
        ):
            raise AutomationValidationError("Condition path is outside the event schema")
        if not isinstance(self.operator, ConditionOperator):
            raise AutomationValidationError("Condition operator is invalid")
        safe = _json_safe(self.expected)
        object.__setattr__(self, "expected", safe)

    def evaluate(self, event: EventEnvelope[EventPayload]) -> bool:
        actual = _event_field(event, self.path)
        if self.operator is ConditionOperator.EXISTS:
            return actual is not _MISSING
        if actual is _MISSING:
            return False if self.operator is ConditionOperator.EQUALS else True
        expected = self.expected
        if self.operator is ConditionOperator.EQUALS:
            return _canonical(actual) == _canonical(expected)
        if self.operator is ConditionOperator.NOT_EQUALS:
            return _canonical(actual) != _canonical(expected)
        if self.operator is ConditionOperator.CONTAINS:
            if isinstance(actual, str) and isinstance(expected, str):
                return expected in actual
            if isinstance(actual, Mapping):
                return str(expected) in actual
            if isinstance(actual, Sequence) and not isinstance(actual, str):
                return any(_canonical(item) == _canonical(expected) for item in actual)
            return False
        if not isinstance(expected, Sequence) or isinstance(expected, str | bytes | bytearray):
            return False
        return any(_canonical(actual) == _canonical(item) for item in expected)


@dataclass(frozen=True, slots=True)
class TriggerDefinition:
    trigger_id: UUID
    event_types: tuple[EventType, ...]
    conditions: tuple[Condition, ...] = ()
    source: str | None = None
    debounce_seconds: float = 0.0
    cooldown_seconds: float = 0.0
    deduplication_window_seconds: float = 60.0
    deduplication_paths: tuple[str, ...] = ("event_type", "source", "payload")

    def __post_init__(self) -> None:
        if not isinstance(self.trigger_id, UUID) or not self.event_types:
            raise AutomationValidationError("Trigger identity and event types are required")
        if len(self.event_types) > 32 or len(self.conditions) > 32:
            raise AutomationValidationError("Trigger is too large")
        if len(set(self.event_types)) != len(self.event_types):
            raise AutomationValidationError("Trigger event types must be unique")
        if self.source is not None:
            _text(self.source, "Trigger source", 256)
        for value, name, maximum in (
            (self.debounce_seconds, "debounce", 60.0),
            (self.cooldown_seconds, "cooldown", 86_400.0),
            (self.deduplication_window_seconds, "deduplication", 86_400.0),
        ):
            if value < 0 or value > maximum or not math.isfinite(value):
                raise AutomationValidationError(f"Trigger {name} duration is invalid")
        for path in self.deduplication_paths:
            _text(path, "Deduplication path", 256)
            if path != "payload" and path not in {
                "event_type",
                "source",
                "task_id",
                "correlation_id",
            }:
                raise AutomationValidationError("Deduplication path is outside the event schema")

    def matches(self, event: EventEnvelope[EventPayload]) -> bool:
        return (
            event.event_type in self.event_types
            and (self.source is None or event.source == self.source)
            and all(condition.evaluate(event) for condition in self.conditions)
        )

    def deduplication_key(self, event: EventEnvelope[EventPayload]) -> str:
        values = {path: _event_field(event, path) for path in self.deduplication_paths}
        return _fingerprint(values)


@dataclass(frozen=True, slots=True)
class AutomationDefinition:
    name: str
    trigger: TriggerDefinition
    workspace_id: str
    profile_id: str
    goal: str | None = None
    workflow_template_id: str | None = None
    workflow_parameters: Mapping[str, object] = field(default_factory=dict)
    budgets: ExecutionBudgets = field(default_factory=ExecutionBudgets)
    concurrency_policy: ConcurrencyPolicy = ConcurrencyPolicy.DROP
    max_concurrency: int = 1
    max_queue: int = 32
    enabled: bool = True
    simulation: bool = False
    automation_id: UUID = field(default_factory=uuid4)

    def __post_init__(self) -> None:
        if not isinstance(self.automation_id, UUID):
            raise AutomationValidationError("Automation ID is invalid")
        _text(self.name, "Automation name", 256)
        _text(self.workspace_id, "Automation workspace", 256)
        _text(self.profile_id, "Automation profile", 256)
        if (self.goal is None) == (self.workflow_template_id is None):
            raise AutomationValidationError("Automation needs exactly one execution target")
        if self.goal is not None:
            _text(self.goal, "Automation goal")
        if self.workflow_template_id is not None:
            _text(self.workflow_template_id, "Workflow template ID", 256)
        safe_parameters = _json_safe(self.workflow_parameters)
        if not isinstance(safe_parameters, dict):
            raise AutomationValidationError("Workflow parameters must be an object")
        object.__setattr__(self, "workflow_parameters", safe_parameters)
        if not isinstance(self.concurrency_policy, ConcurrencyPolicy):
            raise AutomationValidationError("Concurrency policy is invalid")
        if self.max_concurrency < 1 or self.max_concurrency > 16:
            raise AutomationValidationError("Automation concurrency is invalid")
        if self.max_queue < 0 or self.max_queue > 256:
            raise AutomationValidationError("Automation queue bound is invalid")


@dataclass(frozen=True, slots=True)
class AutomationRun:
    run_id: UUID
    automation_id: UUID
    event_id: UUID
    event_type: EventType
    event_source: str
    correlation_id: UUID
    deduplication_key: str
    trace_id: UUID
    status: AutomationRunStatus
    created_at: datetime
    updated_at: datetime
    task_id: UUID | None = None
    simulation: bool = False
    error: str | None = None

    def __post_init__(self) -> None:
        for value, name in (
            (self.run_id, "run"),
            (self.automation_id, "automation"),
            (self.event_id, "event"),
            (self.correlation_id, "correlation"),
            (self.trace_id, "trace"),
        ):
            if not isinstance(value, UUID):
                raise AutomationValidationError(f"{name} ID is invalid")
        if not isinstance(self.event_type, EventType) or not isinstance(
            self.status, AutomationRunStatus
        ):
            raise AutomationValidationError("Automation run type is invalid")
        _text(self.event_source, "Automation event source", 256)
        _text(self.deduplication_key, "Automation deduplication key", 128)
        if self.task_id is not None and not isinstance(self.task_id, UUID):
            raise AutomationValidationError("Automation task ID is invalid")
        if self.error is not None:
            _text(self.error, "Automation error", 1_000)
        object.__setattr__(self, "created_at", _utc(self.created_at, "Run created_at"))
        object.__setattr__(self, "updated_at", _utc(self.updated_at, "Run updated_at"))


class AutomationStore(Protocol):
    def save_definition(self, definition: AutomationDefinition) -> None: ...
    def get_definition(self, automation_id: UUID) -> AutomationDefinition | None: ...
    def list_definitions(
        self, *, enabled_only: bool = False
    ) -> tuple[AutomationDefinition, ...]: ...
    def delete_definition(self, automation_id: UUID) -> bool: ...
    def create_run(self, run: AutomationRun) -> bool: ...
    def update_run(self, run: AutomationRun) -> None: ...
    def get_run(self, run_id: UUID) -> AutomationRun | None: ...
    def list_runs(self, automation_id: UUID | None = None) -> tuple[AutomationRun, ...]: ...


@dataclass(frozen=True, slots=True)
class AutomationMigration:
    version: int
    name: str
    sql: str


class AutomationStoreError(AutomationError):
    """Durable automation state is unavailable or incompatible."""


DEFAULT_AUTOMATION_MIGRATIONS = (
    AutomationMigration(
        1,
        "create_automations",
        """
        CREATE TABLE automation_definitions (
            automation_id TEXT PRIMARY KEY,
            definition_json TEXT NOT NULL,
            enabled INTEGER NOT NULL
        );
        CREATE TABLE automation_runs (
            run_id TEXT PRIMARY KEY,
            automation_id TEXT NOT NULL REFERENCES automation_definitions(automation_id)
                ON DELETE CASCADE,
            event_id TEXT NOT NULL,
            run_json TEXT NOT NULL,
            created_at TEXT NOT NULL,
            UNIQUE(automation_id, event_id)
        );
        CREATE INDEX automation_runs_recent
            ON automation_runs(automation_id, created_at);
        """,
    ),
)


class SQLiteAutomationStore:
    """Durable automation definitions and bounded run facts."""

    def __init__(
        self,
        database_path: Path,
        *,
        migrations: Sequence[AutomationMigration] = DEFAULT_AUTOMATION_MIGRATIONS,
        clock: Callable[[], datetime] = lambda: datetime.now(UTC),
    ) -> None:
        self._path = database_path
        self._clock = clock
        self._migrations = tuple(migrations)
        self._validate_migrations()
        database_path.parent.mkdir(parents=True, exist_ok=True)
        self._connection = sqlite3.connect(database_path, check_same_thread=False)
        self._connection.row_factory = sqlite3.Row
        self._connection.execute("PRAGMA foreign_keys = ON")
        self._connection.execute("PRAGMA busy_timeout = 5000")
        self._connection.execute("PRAGMA journal_mode = WAL")
        self._lock = threading.RLock()
        self._integrity_check()
        self.apply_migrations()

    @property
    def database_path(self) -> Path:
        return self._path

    def close(self) -> None:
        with self._lock:
            self._connection.close()

    def __enter__(self) -> SQLiteAutomationStore:
        return self

    def __exit__(self, _type: object, _value: object, _traceback: object) -> None:
        self.close()

    def apply_migrations(self) -> None:
        with self._lock:
            try:
                self._connection.execute(
                    "CREATE TABLE IF NOT EXISTS automation_schema_migrations "
                    "(version INTEGER PRIMARY KEY, name TEXT NOT NULL, applied_at TEXT NOT NULL)"
                )
                applied = {
                    int(row["version"]): str(row["name"])
                    for row in self._connection.execute(
                        "SELECT version, name FROM automation_schema_migrations"
                    )
                }
                known = {migration.version: migration.name for migration in self._migrations}
                if any(version not in known for version in applied):
                    raise AutomationStoreError("Automation database uses a future schema")
                for migration in self._migrations:
                    if (
                        migration.version in applied
                        and applied[migration.version] != migration.name
                    ):
                        raise AutomationStoreError("Automation migration identity mismatch")
                for migration in self._migrations:
                    if migration.version in applied:
                        continue
                    self._connection.executescript(migration.sql)
                    self._connection.execute(
                        "INSERT INTO automation_schema_migrations(version, name, applied_at) "
                        "VALUES (?, ?, ?)",
                        (
                            migration.version,
                            migration.name,
                            self._clock().astimezone(UTC).isoformat(),
                        ),
                    )
                self._connection.commit()
            except AutomationStoreError:
                self._connection.rollback()
                raise
            except (sqlite3.DatabaseError, ValueError) as error:
                self._connection.rollback()
                raise AutomationStoreError("Automation migration failed") from error

    def save_definition(self, definition: AutomationDefinition) -> None:
        payload = json.dumps(_definition_dict(definition), sort_keys=True, separators=(",", ":"))
        with self._lock:
            try:
                self._connection.execute(
                    "INSERT INTO automation_definitions(automation_id, definition_json, enabled) "
                    "VALUES (?, ?, ?) ON CONFLICT(automation_id) DO UPDATE SET "
                    "definition_json = excluded.definition_json, enabled = excluded.enabled",
                    (str(definition.automation_id), payload, int(definition.enabled)),
                )
                self._connection.commit()
            except sqlite3.DatabaseError as error:
                self._connection.rollback()
                raise AutomationStoreError("Automation definition could not be saved") from error

    def get_definition(self, automation_id: UUID) -> AutomationDefinition | None:
        with self._lock:
            row = self._connection.execute(
                "SELECT definition_json FROM automation_definitions WHERE automation_id = ?",
                (str(automation_id),),
            ).fetchone()
        return _definition_from_dict(json.loads(str(row["definition_json"]))) if row else None

    def list_definitions(self, *, enabled_only: bool = False) -> tuple[AutomationDefinition, ...]:
        query = "SELECT definition_json FROM automation_definitions"
        if enabled_only:
            query += " WHERE enabled = 1"
        query += " ORDER BY automation_id LIMIT ?"
        with self._lock:
            rows = self._connection.execute(query, (_MAX_DEFINITIONS,)).fetchall()
        return tuple(_definition_from_dict(json.loads(str(row["definition_json"]))) for row in rows)

    def delete_definition(self, automation_id: UUID) -> bool:
        with self._lock:
            cursor = self._connection.execute(
                "DELETE FROM automation_definitions WHERE automation_id = ?", (str(automation_id),)
            )
            self._connection.commit()
        return cursor.rowcount > 0

    def create_run(self, run: AutomationRun) -> bool:
        payload = json.dumps(_run_dict(run), sort_keys=True, separators=(",", ":"))
        with self._lock:
            try:
                self._connection.execute(
                    "INSERT INTO automation_runs(run_id, automation_id, event_id, "
                    "run_json, created_at) "
                    "VALUES (?, ?, ?, ?, ?)",
                    (
                        str(run.run_id),
                        str(run.automation_id),
                        str(run.event_id),
                        payload,
                        run.created_at.isoformat(),
                    ),
                )
                self._connection.commit()
                self._prune_runs(run.automation_id)
                return True
            except sqlite3.IntegrityError:
                self._connection.rollback()
                return False
            except sqlite3.DatabaseError as error:
                self._connection.rollback()
                raise AutomationStoreError("Automation run could not be saved") from error

    def update_run(self, run: AutomationRun) -> None:
        payload = json.dumps(_run_dict(run), sort_keys=True, separators=(",", ":"))
        with self._lock:
            cursor = self._connection.execute(
                "UPDATE automation_runs SET run_json = ?, created_at = ? WHERE run_id = ?",
                (payload, run.created_at.isoformat(), str(run.run_id)),
            )
            if cursor.rowcount != 1:
                self._connection.rollback()
                raise AutomationStoreError("Automation run does not exist")
            self._connection.commit()

    def get_run(self, run_id: UUID) -> AutomationRun | None:
        with self._lock:
            row = self._connection.execute(
                "SELECT run_json FROM automation_runs WHERE run_id = ?", (str(run_id),)
            ).fetchone()
        return _run_from_dict(json.loads(str(row["run_json"]))) if row else None

    def list_runs(self, automation_id: UUID | None = None) -> tuple[AutomationRun, ...]:
        query = "SELECT run_json FROM automation_runs"
        values: tuple[object, ...] = ()
        if automation_id is not None:
            query += " WHERE automation_id = ?"
            values = (str(automation_id),)
        query += " ORDER BY created_at DESC LIMIT ?"
        with self._lock:
            rows = self._connection.execute(query, (*values, _MAX_RUNS)).fetchall()
        return tuple(_run_from_dict(json.loads(str(row["run_json"]))) for row in rows)

    def _prune_runs(self, automation_id: UUID) -> None:
        self._connection.execute(
            "DELETE FROM automation_runs WHERE automation_id = ? AND run_id NOT IN "
            "(SELECT run_id FROM automation_runs WHERE automation_id = ? "
            "ORDER BY created_at DESC LIMIT ?)",
            (str(automation_id), str(automation_id), _MAX_RUNS),
        )

    def _integrity_check(self) -> None:
        row = self._connection.execute("PRAGMA integrity_check").fetchone()
        if row is None or str(row[0]).casefold() != "ok":
            raise AutomationStoreError("Automation database integrity check failed")

    def _validate_migrations(self) -> None:
        versions = [migration.version for migration in self._migrations]
        if versions != list(range(1, len(versions) + 1)):
            raise AutomationStoreError("Automation migrations must be contiguous")
        if any(not item.name.strip() or not item.sql.strip() for item in self._migrations):
            raise AutomationStoreError("Automation migration is incomplete")


class AutomationService:
    """Durable trigger registration and bounded dispatch coordinator."""

    def __init__(
        self,
        store: AutomationStore,
        event_bus: EventBus,
        task_controller: TaskController,
        *,
        workflow_registry: WorkflowTemplateRegistry | None = None,
        trace_store: TraceStore | None = None,
        clock: Callable[[], datetime] = lambda: datetime.now(UTC),
    ) -> None:
        self._store = store
        self._event_bus = event_bus
        self._task_controller = task_controller
        self._workflow_registry = workflow_registry
        self._trace_store = trace_store
        self._clock = clock
        self._subscription_id: str | None = None
        self._closed = False
        self._dispatch_tasks: set[asyncio.Task[None]] = set()
        self._active: dict[UUID, set[UUID]] = {}
        self._queued: dict[UUID, deque[UUID]] = {}
        self._debounced: dict[UUID, asyncio.Task[None]] = {}
        self._task_by_run: dict[UUID, asyncio.Task[None]] = {}
        self._traces: dict[UUID, ExecutionTrace] = {}
        self._drain_task: asyncio.Task[None] | None = None
        self._drain_requested = False

    async def start(self) -> None:
        if self._closed:
            raise AutomationError("Automation service is closed")
        if self._subscription_id is not None:
            return
        self._subscription_id = await self._event_bus.subscribe(self._on_event)
        self._reconcile_runs()
        for run in self._store.list_runs():
            if run.status is AutomationRunStatus.QUEUED:
                definition = self._store.get_definition(run.automation_id)
                if definition is not None and definition.enabled:
                    self._enqueue(run, definition)

    async def stop(self) -> None:
        subscription = self._subscription_id
        self._subscription_id = None
        if subscription is not None:
            await self._event_bus.unsubscribe(subscription)
        for task in tuple(self._debounced.values()):
            task.cancel()
        self._debounced.clear()
        tasks = tuple(self._dispatch_tasks)
        if tasks:
            for task in tasks:
                task.cancel()
            await asyncio.gather(*tasks, return_exceptions=True)
        self._dispatch_tasks.clear()
        drain_task, self._drain_task = self._drain_task, None
        self._drain_requested = False
        if drain_task is not None:
            drain_task.cancel()
            await asyncio.gather(drain_task, return_exceptions=True)
        self._task_by_run.clear()
        self._active.clear()

    async def aclose(self) -> None:
        self._closed = True
        await self.stop()

    def register(self, definition: AutomationDefinition) -> None:
        if len(self._store.list_definitions()) >= _MAX_DEFINITIONS and (
            self._store.get_definition(definition.automation_id) is None
        ):
            raise AutomationValidationError("Automation definition limit reached")
        self._store.save_definition(definition)

    def unregister(self, automation_id: UUID) -> bool:
        for run_id, task in tuple(self._task_by_run.items()):
            run = self._store.get_run(run_id)
            if run is not None and run.automation_id == automation_id:
                task.cancel()
                self._task_by_run.pop(run_id, None)
        self._active.pop(automation_id, None)
        self._queued.pop(automation_id, None)
        pending = self._debounced.pop(automation_id, None)
        if pending is not None:
            pending.cancel()
        return self._store.delete_definition(automation_id)

    def definitions(self) -> tuple[AutomationDefinition, ...]:
        return self._store.list_definitions()

    def runs(self, automation_id: UUID | None = None) -> tuple[AutomationRun, ...]:
        return self._store.list_runs(automation_id)

    async def handle_event(self, event: EventEnvelope[EventPayload]) -> tuple[UUID, ...]:
        """Process one event deterministically; useful for adapters and tests."""

        accepted: list[UUID] = []
        for definition in self._store.list_definitions(enabled_only=True):
            if definition.trigger.matches(event):
                run = await self._accept(definition, event)
                if run is not None:
                    accepted.append(run.run_id)
        return tuple(accepted)

    async def simulate(
        self,
        automation_id: UUID,
        event: EventEnvelope[EventPayload],
    ) -> AutomationRun | None:
        definition = self._store.get_definition(automation_id)
        if definition is None or not definition.trigger.matches(event):
            return None
        run = self._new_run(definition, event, simulation=True)
        if not self._store.create_run(run):
            return None
        self._trace(run, "simulated")
        simulated = replace(run, status=AutomationRunStatus.SIMULATED, updated_at=self._clock())
        self._store.update_run(simulated)
        self._publish_state(simulated)
        return simulated

    async def _on_event(self, event: EventEnvelope[EventPayload]) -> None:
        await self.handle_event(event)

    async def _accept(
        self, definition: AutomationDefinition, event: EventEnvelope[EventPayload]
    ) -> AutomationRun | None:
        now = self._clock()
        key = definition.trigger.deduplication_key(event)
        deduplication_cutoff = now - timedelta(
            seconds=definition.trigger.deduplication_window_seconds
        )
        if any(
            run.deduplication_key == key
            and run.created_at >= deduplication_cutoff
            and run.status not in {AutomationRunStatus.DROPPED, AutomationRunStatus.CANCELLED}
            for run in self._store.list_runs(definition.automation_id)
        ):
            return None
        run = self._new_run(definition, event)
        if not self._store.create_run(run):
            return None
        self._trace(run, "accepted")
        self._publish_state(run)
        cooldown_cutoff = now - timedelta(seconds=definition.trigger.cooldown_seconds)
        if definition.trigger.cooldown_seconds and any(
            other.created_at >= cooldown_cutoff
            and other.status
            in {
                AutomationRunStatus.QUEUED,
                AutomationRunStatus.RUNNING,
                AutomationRunStatus.WAITING_FOR_PERMISSION,
                AutomationRunStatus.COMPLETED,
            }
            for other in self._store.list_runs(definition.automation_id)
            if other.run_id != run.run_id
        ):
            return self._finish(run, AutomationRunStatus.DROPPED, "cooldown")
        if definition.simulation:
            return await self._simulate_run(run)
        if definition.trigger.debounce_seconds > 0:
            prior = self._debounced.get(definition.automation_id)
            if prior is not None:
                prior.cancel()
                for pending in self._store.list_runs(definition.automation_id):
                    if pending.status is AutomationRunStatus.DEBOUNCED:
                        self._finish(
                            pending, AutomationRunStatus.DROPPED, "debounced_by_newer_event"
                        )
            self._debounced[definition.automation_id] = asyncio.create_task(
                self._debounce(run, definition)
            )
            return self._set_status(run, AutomationRunStatus.DEBOUNCED)
        self._enqueue(run, definition)
        return run

    async def _debounce(self, run: AutomationRun, definition: AutomationDefinition) -> None:
        try:
            await asyncio.sleep(definition.trigger.debounce_seconds)
            self._debounced.pop(definition.automation_id, None)
            current = self._store.get_run(run.run_id)
            if current is not None and current.status is AutomationRunStatus.DEBOUNCED:
                self._enqueue(self._set_status(current, AutomationRunStatus.QUEUED), definition)
        except asyncio.CancelledError:
            current = self._store.get_run(run.run_id)
            if current is not None and current.status is AutomationRunStatus.DEBOUNCED:
                self._finish(current, AutomationRunStatus.DROPPED, "debounced_by_newer_event")

    def _enqueue(self, run: AutomationRun, definition: AutomationDefinition) -> None:
        active = self._active.setdefault(definition.automation_id, set())
        if definition.concurrency_policy is ConcurrencyPolicy.RESTART_IF_SAFE and active:
            safe = [
                item
                for item in active
                if (current := self._store.get_run(item)) is not None and current.task_id is None
            ]
            if safe:
                for old_id in safe:
                    old_task = self._dispatch_task(old_id)
                    if old_task is not None:
                        old_task.cancel()
                    old = self._store.get_run(old_id)
                    if old is not None:
                        self._finish(old, AutomationRunStatus.CANCELLED, "restarted_safely")
                    active.discard(old_id)
            else:
                self._finish(run, AutomationRunStatus.DROPPED, "active_effect_not_safe_to_restart")
                return
        if len(active) >= definition.max_concurrency:
            if definition.concurrency_policy is ConcurrencyPolicy.DROP:
                self._finish(run, AutomationRunStatus.DROPPED, "concurrency_drop")
                return
            queue = self._queued.setdefault(definition.automation_id, deque())
            if len(queue) >= definition.max_queue:
                self._finish(run, AutomationRunStatus.DROPPED, "concurrency_queue_full")
                return
            queue.append(run.run_id)
            self._set_status(run, AutomationRunStatus.QUEUED)
            return
        self._start_run(run, definition)

    def _start_run(self, run: AutomationRun, definition: AutomationDefinition) -> None:
        self._active.setdefault(definition.automation_id, set()).add(run.run_id)
        task = asyncio.create_task(self._execute(run, definition))
        self._dispatch_tasks.add(task)
        self._task_by_run[run.run_id] = task
        task.add_done_callback(self._dispatch_done)

    def _dispatch_done(self, task: asyncio.Task[None]) -> None:
        self._dispatch_tasks.discard(task)
        for run_id, candidate in tuple(self._task_by_run.items()):
            if candidate is task:
                self._task_by_run.pop(run_id, None)
                break
        if not task.done():
            return
        try:
            task.exception()
        except asyncio.CancelledError:
            return
        except Exception:
            return
        self._request_drain()

    def _request_drain(self) -> None:
        """Serialize durable queue draining and retain its lifecycle ownership."""

        if self._closed:
            return
        self._drain_requested = True
        if self._drain_task is None or self._drain_task.done():
            self._drain_task = asyncio.create_task(self._drain_loop())

    async def _drain_loop(self) -> None:
        try:
            while self._drain_requested:
                self._drain_requested = False
                await self._drain_after_dispatch()
        finally:
            current = asyncio.current_task()
            if self._drain_task is current:
                self._drain_task = None
            if self._drain_requested and not self._closed:
                self._request_drain()

    async def _drain_after_dispatch(self) -> None:
        for automation_id, active in tuple(self._active.items()):
            active.intersection_update(
                run.run_id
                for run in self._store.list_runs(automation_id)
                if run.status is AutomationRunStatus.RUNNING
            )
            definition = self._store.get_definition(automation_id)
            queue = self._queued.get(automation_id)
            if definition is None or queue is None:
                continue
            while queue and len(active) < definition.max_concurrency:
                run_id = queue.popleft()
                run = self._store.get_run(run_id)
                if run is not None and run.status is AutomationRunStatus.QUEUED:
                    self._start_run(run, definition)
                    active.add(run_id)

    async def _execute(self, run: AutomationRun, definition: AutomationDefinition) -> None:
        current = self._set_status(run, AutomationRunStatus.RUNNING)
        self._trace(current, "running")
        try:
            if definition.workflow_template_id is not None:
                if self._workflow_registry is None:
                    raise AutomationError("Workflow template registry is unavailable")
                template = self._workflow_registry.resolve(
                    definition.workflow_template_id,
                    workspace_id=definition.workspace_id,
                    profile_id=definition.profile_id,
                )
                proposal = template.propose(
                    definition.workflow_parameters,
                    workspace_id=definition.workspace_id,
                    profile_id=definition.profile_id,
                )
                task = await self._task_controller.create_proposal_task(
                    proposal,
                    budgets=definition.budgets,
                    provenance=(f"automation:{definition.automation_id}",),
                )
            else:
                task = await self._task_controller.create_task(
                    definition.goal or "",
                    assumptions=(
                        f"automation:{definition.automation_id}",
                        f"workspace:{definition.workspace_id}",
                        f"profile:{definition.profile_id}",
                    ),
                    budgets=definition.budgets,
                )
            current = replace(current, task_id=task.task_id, updated_at=self._clock())
            self._store.update_run(current)
            self._trace(current, "task_bound", task_id=task.task_id)
            if task.status is PlanningTaskStatus.READY:
                task = await self._task_controller.run_task(task.task_id)
            status = _run_status(task.status)
            self._finish(
                current,
                status,
                None if status is not AutomationRunStatus.FAILED else "task_failed",
            )
        except asyncio.CancelledError:
            latest = self._store.get_run(run.run_id)
            if latest is not None and latest.status is AutomationRunStatus.RUNNING:
                self._finish(
                    latest,
                    AutomationRunStatus.FAILED,
                    "automation_cancelled_unknown_state",
                )
            raise
        except Exception as error:
            latest = self._store.get_run(run.run_id) or current
            self._finish(
                latest,
                AutomationRunStatus.FAILED,
                f"dispatch_failed:{type(error).__name__}",
            )

    async def _simulate_run(self, run: AutomationRun) -> AutomationRun:
        self._trace(run, "simulated")
        return self._finish(run, AutomationRunStatus.SIMULATED, None)

    def _new_run(
        self,
        definition: AutomationDefinition,
        event: EventEnvelope[EventPayload],
        *,
        simulation: bool = False,
    ) -> AutomationRun:
        now = self._clock()
        return AutomationRun(
            run_id=uuid4(),
            automation_id=definition.automation_id,
            event_id=event.event_id,
            event_type=event.event_type,
            event_source=event.source,
            correlation_id=event.correlation_id,
            deduplication_key=definition.trigger.deduplication_key(event),
            trace_id=uuid4(),
            status=AutomationRunStatus.QUEUED,
            created_at=now,
            updated_at=now,
            simulation=simulation,
        )

    def _set_status(self, run: AutomationRun, status: AutomationRunStatus) -> AutomationRun:
        updated = replace(run, status=status, updated_at=self._clock())
        self._store.update_run(updated)
        self._publish_state(updated)
        return updated

    def _finish(
        self,
        run: AutomationRun,
        status: AutomationRunStatus,
        error: str | None,
    ) -> AutomationRun:
        updated = replace(run, status=status, error=error, updated_at=self._clock())
        self._store.update_run(updated)
        self._trace(updated, status.value, error=error)
        self._publish_state(updated)
        return updated

    def _trace(
        self,
        run: AutomationRun,
        detail: str,
        *,
        task_id: UUID | None = None,
        error: str | None = None,
    ) -> None:
        trace = self._traces.get(run.trace_id)
        if trace is None:
            trace = ExecutionTrace(run.trace_id, store=self._trace_store)
            self._traces[run.trace_id] = trace
        trace.append(
            TraceEvent(
                trace_id=run.trace_id,
                event_type=TraceEventType.AUTOMATION,
                source="automation.service",
                summary=f"Automation {run.automation_id} run {detail}",
                occurred_at=self._clock(),
                task_id=task_id or run.task_id,
                correlation_id=run.correlation_id,
                error=error,
                result={"status": run.status.value, "event_type": run.event_type.value},
            )
        )

    def _publish_state(self, run: AutomationRun) -> None:
        self._event_bus.publish_nowait(
            EventEnvelope.create(
                EventType.AUTOMATION_STATE_CHANGED,
                AutomationStateChanged(run.automation_id, run.status.value),
                source="automation.service",
                correlation_id=run.correlation_id,
                causation_id=run.event_id,
            )
        )

    def _dispatch_task(self, run_id: UUID) -> asyncio.Task[None] | None:
        task = self._task_by_run.get(run_id)
        return task if task is not None and not task.done() else None

    def _reconcile_runs(self) -> None:
        for run in self._store.list_runs():
            if run.status is not AutomationRunStatus.RUNNING:
                continue
            if run.task_id is None:
                self._finish(run, AutomationRunStatus.FAILED, "restart_unknown_submission")
                continue
            task = self._task_controller.get_task(run.task_id)
            if task is None:
                self._finish(run, AutomationRunStatus.FAILED, "restart_task_missing")
            elif task.status is PlanningTaskStatus.WAITING_FOR_PERMISSION:
                self._finish(run, AutomationRunStatus.WAITING_FOR_PERMISSION, None)
            elif task.status in {
                PlanningTaskStatus.EXECUTING,
                PlanningTaskStatus.VERIFYING,
                PlanningTaskStatus.RECOVERING,
                PlanningTaskStatus.REPLANNING,
            }:
                self._finish(run, AutomationRunStatus.FAILED, "restart_requires_reconciliation")
            else:
                self._finish(run, _run_status(task.status), None)


def _event_field(event: EventEnvelope[EventPayload], path: str) -> object:
    if path == "event_type":
        return event.event_type.value
    if path == "source":
        return event.source
    if path == "task_id":
        return event.task_id
    if path == "correlation_id":
        return event.correlation_id
    if path == "payload":
        return event.payload
    current: object = event.payload
    for part in path.removeprefix("payload.").split("."):
        if isinstance(current, Mapping):
            current = current.get(part, _MISSING)
        elif hasattr(current, part):
            current = getattr(current, part)
        else:
            return _MISSING
    return current


def _run_status(status: PlanningTaskStatus) -> AutomationRunStatus:
    return {
        PlanningTaskStatus.COMPLETED: AutomationRunStatus.COMPLETED,
        PlanningTaskStatus.WAITING_FOR_PERMISSION: AutomationRunStatus.WAITING_FOR_PERMISSION,
        PlanningTaskStatus.CANCELLED: AutomationRunStatus.CANCELLED,
    }.get(status, AutomationRunStatus.FAILED)


def _definition_dict(definition: AutomationDefinition) -> dict[str, object]:
    trigger = definition.trigger
    return {
        "automation_id": str(definition.automation_id),
        "name": definition.name,
        "workspace_id": definition.workspace_id,
        "profile_id": definition.profile_id,
        "goal": definition.goal,
        "workflow_template_id": definition.workflow_template_id,
        "workflow_parameters": dict(definition.workflow_parameters),
        "budgets": asdict(definition.budgets),
        "concurrency_policy": definition.concurrency_policy.value,
        "max_concurrency": definition.max_concurrency,
        "max_queue": definition.max_queue,
        "enabled": definition.enabled,
        "simulation": definition.simulation,
        "trigger": {
            "trigger_id": str(trigger.trigger_id),
            "event_types": [item.value for item in trigger.event_types],
            "source": trigger.source,
            "debounce_seconds": trigger.debounce_seconds,
            "cooldown_seconds": trigger.cooldown_seconds,
            "deduplication_window_seconds": trigger.deduplication_window_seconds,
            "deduplication_paths": list(trigger.deduplication_paths),
            "conditions": [
                {"path": item.path, "operator": item.operator.value, "expected": item.expected}
                for item in trigger.conditions
            ],
        },
    }


def _definition_from_dict(payload: Mapping[str, object]) -> AutomationDefinition:
    trigger_data = payload["trigger"]
    if not isinstance(trigger_data, Mapping):
        raise AutomationStoreError("Stored automation trigger is malformed")
    condition_data = trigger_data.get("conditions", ())
    if not isinstance(condition_data, Sequence) or isinstance(condition_data, str):
        raise AutomationStoreError("Stored automation conditions are malformed")
    conditions = tuple(
        Condition(
            str(item["path"]),
            ConditionOperator(str(item["operator"])),
            item.get("expected"),
        )
        for item in condition_data
        if isinstance(item, Mapping)
    )
    budget_data = payload.get("budgets", {})
    if not isinstance(budget_data, Mapping):
        raise AutomationStoreError("Stored automation budgets are malformed")
    parameters = payload.get("workflow_parameters", {})
    if not isinstance(parameters, Mapping):
        raise AutomationStoreError("Stored workflow parameters are malformed")
    budgets = ExecutionBudgets(
        max_steps=_stored_int(budget_data, "max_steps", 32),
        max_elapsed_seconds=_stored_float(budget_data, "max_elapsed_seconds", 900.0),
        max_model_calls=_stored_int(budget_data, "max_model_calls", 3),
        max_expensive_actions=_stored_int(budget_data, "max_expensive_actions", 4),
        max_retries=_stored_int(budget_data, "max_retries", 4),
    )
    paths = trigger_data.get("deduplication_paths", ("event_type", "source", "payload"))
    if not isinstance(paths, Sequence) or isinstance(paths, str):
        raise AutomationStoreError("Stored deduplication paths are malformed")
    return AutomationDefinition(
        name=str(payload["name"]),
        trigger=TriggerDefinition(
            trigger_id=UUID(str(trigger_data["trigger_id"])),
            event_types=tuple(EventType(str(item)) for item in trigger_data["event_types"]),
            conditions=conditions,
            source=str(trigger_data["source"]) if trigger_data.get("source") else None,
            debounce_seconds=float(trigger_data.get("debounce_seconds", 0)),
            cooldown_seconds=float(trigger_data.get("cooldown_seconds", 0)),
            deduplication_window_seconds=float(
                trigger_data.get("deduplication_window_seconds", 60)
            ),
            deduplication_paths=tuple(str(item) for item in paths),
        ),
        workspace_id=str(payload["workspace_id"]),
        profile_id=str(payload["profile_id"]),
        goal=str(payload["goal"]) if payload.get("goal") is not None else None,
        workflow_template_id=(
            str(payload["workflow_template_id"]) if payload.get("workflow_template_id") else None
        ),
        workflow_parameters=parameters,
        budgets=budgets,
        concurrency_policy=ConcurrencyPolicy(
            str(payload.get("concurrency_policy", ConcurrencyPolicy.DROP.value))
        ),
        max_concurrency=_stored_int(payload, "max_concurrency", 1),
        max_queue=_stored_int(payload, "max_queue", 32),
        enabled=bool(payload.get("enabled", True)),
        simulation=bool(payload.get("simulation", False)),
        automation_id=UUID(str(payload["automation_id"])),
    )


def _stored_int(payload: Mapping[str, object], key: str, default: int) -> int:
    value = payload.get(key, default)
    if isinstance(value, bool):
        raise AutomationStoreError(f"Stored automation field {key} is malformed")
    try:
        result = int(cast(Any, value))
    except (TypeError, ValueError, OverflowError) as error:
        raise AutomationStoreError(f"Stored automation field {key} is malformed") from error
    if result != cast(Any, value) and not isinstance(value, str):
        raise AutomationStoreError(f"Stored automation field {key} is malformed")
    return result


def _stored_float(payload: Mapping[str, object], key: str, default: float) -> float:
    value = payload.get(key, default)
    if isinstance(value, bool):
        raise AutomationStoreError(f"Stored automation field {key} is malformed")
    try:
        result = float(cast(Any, value))
    except (TypeError, ValueError, OverflowError) as error:
        raise AutomationStoreError(f"Stored automation field {key} is malformed") from error
    if not math.isfinite(result):
        raise AutomationStoreError(f"Stored automation field {key} is malformed")
    return result


def _run_dict(run: AutomationRun) -> dict[str, object]:
    return {
        "run_id": str(run.run_id),
        "automation_id": str(run.automation_id),
        "event_id": str(run.event_id),
        "event_type": run.event_type.value,
        "event_source": run.event_source,
        "correlation_id": str(run.correlation_id),
        "deduplication_key": run.deduplication_key,
        "trace_id": str(run.trace_id),
        "status": run.status.value,
        "created_at": run.created_at.isoformat(),
        "updated_at": run.updated_at.isoformat(),
        "task_id": str(run.task_id) if run.task_id else None,
        "simulation": run.simulation,
        "error": run.error,
    }


def _run_from_dict(payload: Mapping[str, object]) -> AutomationRun:
    return AutomationRun(
        UUID(str(payload["run_id"])),
        UUID(str(payload["automation_id"])),
        UUID(str(payload["event_id"])),
        EventType(str(payload["event_type"])),
        str(payload["event_source"]),
        UUID(str(payload["correlation_id"])),
        str(payload["deduplication_key"]),
        UUID(str(payload["trace_id"])),
        AutomationRunStatus(str(payload["status"])),
        datetime.fromisoformat(str(payload["created_at"])),
        datetime.fromisoformat(str(payload["updated_at"])),
        UUID(str(payload["task_id"])) if payload.get("task_id") else None,
        bool(payload.get("simulation", False)),
        str(payload["error"]) if payload.get("error") else None,
    )


__all__ = [
    "AutomationDefinition",
    "AutomationError",
    "AutomationMigration",
    "AutomationRun",
    "AutomationRunStatus",
    "AutomationService",
    "AutomationStateChanged",
    "AutomationStore",
    "AutomationStoreError",
    "AutomationValidationError",
    "Condition",
    "ConditionOperator",
    "ConcurrencyPolicy",
    "DEFAULT_AUTOMATION_MIGRATIONS",
    "SQLiteAutomationStore",
    "TriggerDefinition",
]
