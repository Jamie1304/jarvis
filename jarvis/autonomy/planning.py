"""Request interpretation and schema-validated plan construction."""

from abc import ABC, abstractmethod
from dataclasses import dataclass
from uuid import uuid4

from pydantic import BaseModel, ConfigDict, Field, ValidationError

from jarvis.autonomy.models import Plan, PlanStep, StructuredTaskError, Task, ToolArgument
from jarvis.core.errors import MalformedPlanError, PlanningError


@dataclass(frozen=True, slots=True)
class TaskIntent:
    """A normalized interpretation of an incoming user request."""

    goal: str


class RequestInterpreter(ABC):
    """Interpret user text without changing task lifecycle state."""

    @abstractmethod
    async def interpret(self, task: Task) -> TaskIntent:
        """Return a typed task intent."""


class DefaultRequestInterpreter(RequestInterpreter):
    """Minimal deterministic interpretation retained until model interpretation is introduced."""

    async def interpret(self, task: Task) -> TaskIntent:
        goal = " ".join(task.user_request.strip().split())
        if not goal:
            raise PlanningError("A task request must contain text")
        return TaskIntent(goal=goal)


class PlanningAdvisor(ABC):
    """Boundary for an optional model that suggests an untrusted plan payload."""

    @abstractmethod
    async def suggest(self, intent: TaskIntent, prior_error: StructuredTaskError | None) -> object:
        """Return untrusted data that must be schema-validated before use."""


class PlanArgumentPayload(BaseModel):
    """Untrusted model payload schema for a scalar tool argument."""

    model_config = ConfigDict(extra="forbid", strict=True)

    name: str = Field(min_length=1, max_length=64)
    value: str = Field(max_length=4_000)


class PlanStepPayload(BaseModel):
    """Untrusted model payload schema for one step."""

    model_config = ConfigDict(extra="forbid", strict=True)

    capability: str = Field(min_length=1, max_length=128)
    action: str = Field(min_length=1, max_length=128)
    arguments: list[PlanArgumentPayload] = Field(default_factory=list, max_length=16)
    depends_on: list[int] = Field(default_factory=list, max_length=16)
    expected_outcome: str = Field(min_length=1, max_length=4_000)


class PlanPayload(BaseModel):
    """Strict plan suggestion schema; arbitrary model JSON is never used directly."""

    model_config = ConfigDict(extra="forbid", strict=True)

    goal: str = Field(min_length=1, max_length=4_000)
    steps: list[PlanStepPayload] = Field(min_length=1, max_length=32)


class TaskPlanner(ABC):
    """Build typed plans from interpreted intent."""

    @abstractmethod
    async def create_plan(self, task: Task, intent: TaskIntent) -> Plan:
        """Create the initial plan."""

    @abstractmethod
    async def replan(
        self, task: Task, intent: TaskIntent, prior_error: StructuredTaskError
    ) -> Plan:
        """Create a replacement plan after explicit verification failure."""


class SchemaValidatedPlanner(TaskPlanner):
    """Turn advisor suggestions into application-owned typed plans after strict validation."""

    def __init__(self, advisor: PlanningAdvisor) -> None:
        self._advisor = advisor

    async def create_plan(self, task: Task, intent: TaskIntent) -> Plan:
        return await self._build(task, intent, None)

    async def replan(
        self, task: Task, intent: TaskIntent, prior_error: StructuredTaskError
    ) -> Plan:
        return await self._build(task, intent, prior_error)

    async def _build(
        self, task: Task, intent: TaskIntent, prior_error: StructuredTaskError | None
    ) -> Plan:
        raw = await self._advisor.suggest(intent, prior_error)
        try:
            payload = PlanPayload.model_validate(raw)
        except ValidationError as error:
            raise MalformedPlanError("Planner output did not match the required schema") from error
        return self._to_plan(task, payload)

    @staticmethod
    def _to_plan(task: Task, payload: PlanPayload) -> Plan:
        step_ids = [uuid4() for _ in payload.steps]
        steps: list[PlanStep] = []
        for index, raw_step in enumerate(payload.steps):
            if any(dependency < 0 or dependency >= index for dependency in raw_step.depends_on):
                raise MalformedPlanError("Plan dependencies must reference earlier steps")
            argument_names = [argument.name for argument in raw_step.arguments]
            if len(argument_names) != len(set(argument_names)):
                raise MalformedPlanError("Plan step argument names must be unique")
            steps.append(
                PlanStep(
                    step_id=step_ids[index],
                    order=index,
                    capability=raw_step.capability,
                    action=raw_step.action,
                    arguments=tuple(
                        ToolArgument(name=argument.name, value=argument.value)
                        for argument in raw_step.arguments
                    ),
                    dependencies=tuple(step_ids[dependency] for dependency in raw_step.depends_on),
                    expected_outcome=raw_step.expected_outcome,
                )
            )
        return Plan(plan_id=uuid4(), task_id=task.task_id, goal=payload.goal, steps=tuple(steps))
