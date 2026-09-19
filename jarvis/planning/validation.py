"""Strict model-proposal validation and deterministic DAG ownership."""

from __future__ import annotations

from collections.abc import Callable
from datetime import UTC, datetime
from typing import Annotated
from uuid import UUID, uuid4

from pydantic import BaseModel, ConfigDict, Field, ValidationError

from jarvis.permissions.models import Permission
from jarvis.planning.models import (
    OwnedPlan,
    OwnedPlanStatus,
    PlanningStep,
    canonical_json,
)
from jarvis.tools.registry import ToolRegistry


class PlanValidationError(ValueError):
    """A model proposal failed a deterministic ownership check."""


BoundedLabel = Annotated[str, Field(min_length=1, max_length=128)]
BoundedText = Annotated[str, Field(min_length=1, max_length=1_000)]


class ProposedStep(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)

    key: str = Field(min_length=1, max_length=128)
    tool_id: str = Field(min_length=1, max_length=128)
    capability: str = Field(min_length=1, max_length=128)
    input: dict[str, object]
    dependencies: list[BoundedLabel] = Field(default_factory=list, max_length=32)
    required_permissions: list[BoundedLabel] = Field(default_factory=list, max_length=16)
    expected_output: str = Field(min_length=1, max_length=4_000)
    verification_rule: str = Field(min_length=1, max_length=1_000)
    expected_evidence: list[BoundedText] = Field(min_length=1, max_length=32)
    expensive_action: bool = False
    max_retries: int = Field(default=0, ge=0, le=8)


class PlanProposal(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)

    goal: str = Field(min_length=1, max_length=4_000)
    assumptions: list[BoundedText] = Field(default_factory=list, max_length=32)
    constraints: list[BoundedText] = Field(default_factory=list, max_length=32)
    required_capabilities: list[BoundedLabel] = Field(min_length=1, max_length=64)
    required_permissions: list[BoundedLabel] = Field(default_factory=list, max_length=32)
    completion_criteria: list[BoundedText] = Field(min_length=1, max_length=32)
    steps: list[ProposedStep] = Field(min_length=1, max_length=64)


class PlanValidator:
    """Convert untrusted plan JSON into an exact, registry-bound owned DAG."""

    def __init__(
        self,
        registry: ToolRegistry,
        *,
        max_steps: int,
        clock: Callable[[], datetime] | None = None,
    ) -> None:
        if max_steps <= 0:
            raise ValueError("Maximum plan step count must be positive")
        self._registry = registry
        self._max_steps = max_steps
        self._clock = clock or (lambda: datetime.now(UTC))

    def validate(
        self,
        raw: object,
        *,
        task_id: UUID,
        version: int = 1,
        required_goal: str | None = None,
        required_assumptions: tuple[str, ...] | None = None,
        required_constraints: tuple[str, ...] | None = None,
        required_constraint_prefix: tuple[str, ...] | None = None,
        provenance: tuple[str, ...] = (),
    ) -> OwnedPlan:
        try:
            proposal = PlanProposal.model_validate(raw)
        except ValidationError as error:
            raise PlanValidationError("Plan proposal does not match the strict schema") from error
        if len(proposal.steps) > self._max_steps:
            raise PlanValidationError("Plan exceeds the trusted step-count limit")
        if required_goal is not None and proposal.goal != required_goal:
            raise PlanValidationError("Replanning cannot change the original goal")
        if required_assumptions is not None and tuple(proposal.assumptions) != required_assumptions:
            raise PlanValidationError("Replanning cannot discard original assumptions")
        if required_constraints is not None and tuple(proposal.constraints) != required_constraints:
            raise PlanValidationError("Replanning cannot discard original constraints")
        if (
            required_constraint_prefix is not None
            and tuple(proposal.constraints)[: len(required_constraint_prefix)]
            != required_constraint_prefix
        ):
            raise PlanValidationError("Plan cannot discard original constraints")
        keys = [step.key for step in proposal.steps]
        if len(keys) != len(set(keys)):
            raise PlanValidationError("Plan step keys must be unique")
        key_ids = {key: uuid4() for key in keys}
        self._validate_dependencies(proposal.steps, key_ids)

        steps = tuple(self._step(step, key_ids) for step in proposal.steps)
        derived_capabilities = tuple(sorted({step.capability for step in steps}))
        derived_permissions = tuple(
            sorted(
                {item for step in steps for item in step.required_permissions},
                key=lambda p: p.value,
            )
        )
        if tuple(sorted(set(proposal.required_capabilities))) != derived_capabilities:
            raise PlanValidationError("Plan required capabilities must exactly match its steps")
        declared_permissions = self._permissions(proposal.required_permissions)
        if declared_permissions != derived_permissions:
            raise PlanValidationError("Plan required permissions must exactly match its steps")
        now = self._clock()
        if not isinstance(now, datetime):
            raise PlanValidationError("Planner clock returned an invalid timestamp")
        return OwnedPlan(
            plan_id=uuid4(),
            task_id=task_id,
            version=version,
            goal=proposal.goal,
            assumptions=tuple(proposal.assumptions),
            constraints=tuple(proposal.constraints),
            steps=steps,
            required_capabilities=derived_capabilities,
            required_permissions=derived_permissions,
            completion_criteria=tuple(proposal.completion_criteria),
            status=OwnedPlanStatus.READY,
            created_at=now,
            updated_at=now,
            provenance=provenance,
        )

    def _step(self, proposed: ProposedStep, key_ids: dict[str, UUID]) -> PlanningStep:
        try:
            record = self._registry.inspect(proposed.tool_id)
        except Exception as error:
            raise PlanValidationError(f"Unknown requested tool: {proposed.tool_id}") from error
        if not record.usable:
            raise PlanValidationError(f"Requested tool is not usable: {proposed.tool_id}")
        if proposed.capability not in record.manifest.capabilities and (
            proposed.capability != record.manifest.tool_id
        ):
            raise PlanValidationError(
                f"Tool {proposed.tool_id} does not provide capability {proposed.capability}"
            )
        if proposed.verification_rule not in {"evidence_contains_all", "output_contains"}:
            raise PlanValidationError("Step uses an unknown verification rule")
        permissions = self._permissions(proposed.required_permissions)
        expected = tuple(sorted(record.manifest.declared_permissions, key=lambda item: item.value))
        if permissions != expected:
            raise PlanValidationError(
                f"Step permissions do not match trusted manifest for {proposed.tool_id}"
            )
        try:
            validated_input = record.manifest.input_schema.model_validate(proposed.input)
        except ValidationError as error:
            raise PlanValidationError(
                f"Step input does not match schema for {proposed.tool_id}"
            ) from error
        return PlanningStep(
            step_id=key_ids[proposed.key],
            key=proposed.key,
            tool_id=proposed.tool_id,
            capability=proposed.capability,
            input_json=canonical_json(validated_input.model_dump(mode="json")),
            expected_output=proposed.expected_output,
            verification_rule=proposed.verification_rule,
            expected_evidence=tuple(proposed.expected_evidence),
            dependencies=tuple(key_ids[key] for key in proposed.dependencies),
            required_permissions=permissions,
            expensive_action=proposed.expensive_action,
            max_retries=proposed.max_retries,
        )

    @staticmethod
    def _permissions(values: list[str]) -> tuple[Permission, ...]:
        try:
            permissions = tuple(Permission(value) for value in values)
        except ValueError as error:
            raise PlanValidationError("Plan contains an unknown permission") from error
        if len(permissions) != len(set(permissions)):
            raise PlanValidationError("Plan permissions must be unique")
        return tuple(sorted(permissions, key=lambda item: item.value))

    @staticmethod
    def _validate_dependencies(steps: list[ProposedStep], key_ids: dict[str, UUID]) -> None:
        graph: dict[str, tuple[str, ...]] = {}
        for step in steps:
            if len(step.dependencies) != len(set(step.dependencies)):
                raise PlanValidationError("Step dependencies must be unique")
            if any(dependency not in key_ids for dependency in step.dependencies):
                raise PlanValidationError("Step dependency cannot be resolved")
            graph[step.key] = tuple(step.dependencies)
        visiting: set[str] = set()
        visited: set[str] = set()

        def visit(key: str) -> None:
            if key in visiting:
                raise PlanValidationError("Plan dependency graph contains a cycle")
            if key in visited:
                return
            visiting.add(key)
            for dependency in graph[key]:
                visit(dependency)
            visiting.remove(key)
            visited.add(key)

        for key in graph:
            visit(key)
