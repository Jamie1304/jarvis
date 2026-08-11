"""Persistence boundary for task and plan state."""

from abc import ABC, abstractmethod
from uuid import UUID

from jarvis.autonomy.models import Plan, Task


class TaskStore(ABC):
    """Async task persistence contract replaceable by SQLite in a later phase."""

    @abstractmethod
    async def create_task(self, task: Task) -> None:
        """Persist a new task."""

    @abstractmethod
    async def get_task(self, task_id: UUID) -> Task | None:
        """Read a task by identifier."""

    @abstractmethod
    async def save_task(self, task: Task) -> None:
        """Replace the current task snapshot."""

    @abstractmethod
    async def save_plan(self, plan: Plan) -> None:
        """Persist the current plan snapshot."""

    @abstractmethod
    async def get_plan(self, task_id: UUID) -> Plan | None:
        """Read the current plan for a task."""


class InMemoryTaskStore(TaskStore):
    """Process-local store used for Phase 2 and deterministic tests."""

    def __init__(self) -> None:
        self._tasks: dict[UUID, Task] = {}
        self._plans: dict[UUID, Plan] = {}

    async def create_task(self, task: Task) -> None:
        self._tasks[task.task_id] = task

    async def get_task(self, task_id: UUID) -> Task | None:
        return self._tasks.get(task_id)

    async def save_task(self, task: Task) -> None:
        self._tasks[task.task_id] = task

    async def save_plan(self, plan: Plan) -> None:
        self._plans[plan.task_id] = plan

    async def get_plan(self, task_id: UUID) -> Plan | None:
        return self._plans.get(task_id)
