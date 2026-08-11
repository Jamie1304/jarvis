"""Final task response generation separated from orchestration state control."""

from abc import ABC, abstractmethod

from jarvis.autonomy.models import Plan, Task, TaskResult


class TaskResponseGenerator(ABC):
    """Generate a user-facing response from verified application-owned state."""

    @abstractmethod
    async def generate(self, task: Task, plan: Plan) -> TaskResult:
        """Return a final result for a successfully verified task."""


class DefaultTaskResponseGenerator(TaskResponseGenerator):
    """Deterministic response generator used until a guarded model response layer is added."""

    async def generate(self, task: Task, plan: Plan) -> TaskResult:
        del task
        evidence = tuple(step.expected_outcome for step in plan.steps)
        return TaskResult(summary=f"Completed: {plan.goal}", evidence=evidence)
