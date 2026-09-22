"""Trusted derived task-graph semantics over the canonical OwnedPlan."""

from __future__ import annotations

import json
from dataclasses import dataclass
from enum import StrEnum
from uuid import UUID

from jarvis.planning.models import (
    OwnedPlan,
    PlanningStep,
    PlanningStepStatus,
    StepResult,
    canonical_json,
)


class GraphReadiness(StrEnum):
    READY = "ready"
    WAITING_ON_DEPENDENCY = "waiting_on_dependency"
    TERMINALLY_BLOCKED = "terminally_blocked"


class DependencyResolutionError(ValueError):
    """A trusted dependency binding could not be resolved before an effect."""


@dataclass(frozen=True, slots=True)
class TaskGraphView:
    """Immutable facts derived from one validated OwnedPlan snapshot."""

    plan: OwnedPlan

    def __post_init__(self) -> None:
        ids = {step.step_id for step in self.plan.steps}
        if any(
            dependency not in ids for step in self.plan.steps for dependency in step.dependencies
        ):
            raise DependencyResolutionError("Graph contains an unresolved dependency")

    @property
    def node_ids(self) -> tuple[UUID, ...]:
        return tuple(step.step_id for step in self.plan.steps)

    @property
    def dependencies(self) -> dict[UUID, tuple[UUID, ...]]:
        return {step.step_id: step.dependencies for step in self.plan.steps}

    @property
    def dependents(self) -> dict[UUID, tuple[UUID, ...]]:
        result: dict[UUID, list[UUID]] = {step.step_id: [] for step in self.plan.steps}
        for step in self.plan.steps:
            for dependency in step.dependencies:
                result[dependency].append(step.step_id)
        return {key: tuple(sorted(value, key=self._key)) for key, value in result.items()}

    def ready_steps(self) -> tuple[PlanningStep, ...]:
        return tuple(
            sorted(
                (step for step in self.plan.steps if self.readiness(step) is GraphReadiness.READY),
                key=lambda step: step.key,
            )
        )

    def pending_dependency_steps(self) -> tuple[PlanningStep, ...]:
        return tuple(
            sorted(
                (
                    step
                    for step in self.plan.steps
                    if self.readiness(step) is GraphReadiness.WAITING_ON_DEPENDENCY
                ),
                key=lambda step: step.key,
            )
        )

    def terminal_nodes(self) -> tuple[PlanningStep, ...]:
        return tuple(
            step
            for step in self.plan.steps
            if step.status
            in {
                PlanningStepStatus.SUCCEEDED,
                PlanningStepStatus.FAILED,
                PlanningStepStatus.CANCELLED,
                PlanningStepStatus.BLOCKED,
            }
        )

    def readiness(self, step: PlanningStep) -> GraphReadiness:
        if step.status is not PlanningStepStatus.QUEUED:
            return GraphReadiness.WAITING_ON_DEPENDENCY
        by_id = {item.step_id: item for item in self.plan.steps}
        dependencies = [by_id[dependency] for dependency in step.dependencies]
        if any(
            item.status
            in {
                PlanningStepStatus.FAILED,
                PlanningStepStatus.CANCELLED,
                PlanningStepStatus.BLOCKED,
            }
            for item in dependencies
        ):
            return GraphReadiness.TERMINALLY_BLOCKED
        if all(item.status is PlanningStepStatus.SUCCEEDED for item in dependencies):
            return GraphReadiness.READY
        return GraphReadiness.WAITING_ON_DEPENDENCY

    def resolve_input(self, step: PlanningStep) -> str:
        """Resolve only verified direct dependency StepResult output fields."""

        if not step.input_bindings:
            return step.input_json
        by_id = {item.step_id: item for item in self.plan.steps}
        try:
            target = json.loads(step.input_json)
        except json.JSONDecodeError as error:
            raise DependencyResolutionError("Owned step input is malformed") from error
        if not isinstance(target, dict):
            raise DependencyResolutionError("Owned step input is not an object")
        for binding in step.input_bindings:
            dependency = by_id.get(binding.dependency_step_id)
            if dependency is None or dependency.status is not PlanningStepStatus.SUCCEEDED:
                raise DependencyResolutionError("Dependency is not verified succeeded")
            result: StepResult | None = dependency.result
            if result is None:
                raise DependencyResolutionError("Verified dependency has no stored result")
            try:
                output = json.loads(result.output_json)
            except json.JSONDecodeError as error:
                raise DependencyResolutionError(
                    "Verified dependency output is malformed"
                ) from error
            if not isinstance(output, dict) or binding.source_field not in output:
                raise DependencyResolutionError("Dependency result field is unavailable")
            target[binding.target_field] = output[binding.source_field]
        return canonical_json(target)

    def _key(self, step_id: UUID) -> str:
        return next(step.key for step in self.plan.steps if step.step_id == step_id)


__all__ = ["DependencyResolutionError", "GraphReadiness", "TaskGraphView"]
