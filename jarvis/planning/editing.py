"""Typed, application-owned plan inspection and revision contracts.

This module contains data transfer objects only.  It deliberately does not
plan, execute, authorize, or persist anything; ``PlanningEngine`` remains the
sole owner of those decisions.
"""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
from datetime import datetime
from types import MappingProxyType
from uuid import UUID

from jarvis.permissions.models import Permission
from jarvis.planning.models import (
    BudgetUsage,
    ExecutionBudgets,
    OwnedPlan,
    OwnedPlanStatus,
    PlanningStepStatus,
    PlanningTaskStatus,
)


class PlanEditError(ValueError):
    """A requested plan edit is malformed or outside its safe lifecycle."""


@dataclass(frozen=True, slots=True)
class PlanStepSpec:
    """A complete replacement step; validation remains in ``PlanValidator``."""

    key: str
    tool_id: str
    capability: str
    input: Mapping[str, object]
    dependencies: tuple[str, ...]
    required_permissions: tuple[str, ...]
    expected_output: str
    verification_rule: str
    expected_evidence: tuple[str, ...]
    expensive_action: bool = False
    max_retries: int = 0

    def __post_init__(self) -> None:
        if not isinstance(self.input, Mapping):
            raise PlanEditError("Step input must be an object")
        object.__setattr__(self, "input", MappingProxyType(dict(self.input)))
        if not isinstance(self.expensive_action, bool) or not isinstance(self.max_retries, int):
            raise PlanEditError("Step execution metadata is malformed")


@dataclass(frozen=True, slots=True)
class StructuredStepEdit:
    """A bounded field-level edit to one existing step."""

    key: str
    tool_id: str | None = None
    capability: str | None = None
    input: Mapping[str, object] | None = None
    dependencies: tuple[str, ...] | None = None
    required_permissions: tuple[str, ...] | None = None
    expected_output: str | None = None
    verification_rule: str | None = None
    expected_evidence: tuple[str, ...] | None = None
    expensive_action: bool | None = None
    max_retries: int | None = None

    def __post_init__(self) -> None:
        if not self.key.strip() or len(self.key) > 128:
            raise PlanEditError("Step edit key is malformed")
        if self.input is not None:
            if not isinstance(self.input, Mapping):
                raise PlanEditError("Step edit input must be an object")
            object.__setattr__(self, "input", MappingProxyType(dict(self.input)))


@dataclass(frozen=True, slots=True)
class PlanEdit:
    """A user-visible edit expressed without accepting an arbitrary raw plan."""

    add_constraints: tuple[str, ...] = ()
    alternatives: tuple[PlanStepSpec, ...] = ()
    remove_optional_steps: tuple[str, ...] = ()
    structured_steps: tuple[StructuredStepEdit, ...] = ()
    pause_checkpoint: bool = False
    provenance: str = "user.plan_edit"

    def __post_init__(self) -> None:
        if not self.provenance.strip() or len(self.provenance) > 256:
            raise PlanEditError("Edit provenance is malformed")
        if len(self.add_constraints) > 32:
            raise PlanEditError("Too many added constraints")
        if any(not item.strip() or len(item) > 1_000 for item in self.add_constraints):
            raise PlanEditError("Added constraints must be bounded")
        if len(self.remove_optional_steps) != len(set(self.remove_optional_steps)):
            raise PlanEditError("Removed step keys must be unique")


@dataclass(frozen=True, slots=True)
class PlanStepView:
    key: str
    status: PlanningStepStatus
    dependencies: tuple[str, ...]
    tool_id: str
    effect: str
    capabilities: tuple[str, ...]
    permissions: tuple[Permission, ...]
    verification: tuple[str, ...]
    resource_estimate: tuple[str, ...]
    evidence: tuple[str, ...]


@dataclass(frozen=True, slots=True)
class PlanInspection:
    task_id: UUID
    plan_id: UUID
    version: int
    goal: str
    constraints: tuple[str, ...]
    status: PlanningTaskStatus
    plan_status: OwnedPlanStatus
    steps: tuple[PlanStepView, ...]
    capabilities: tuple[str, ...]
    permissions: tuple[Permission, ...]
    verification: tuple[str, ...]
    resource_estimates: tuple[str, ...]
    budgets: ExecutionBudgets
    usage: BudgetUsage
    provenance: tuple[str, ...]
    updated_at: datetime


@dataclass(frozen=True, slots=True)
class PlanRevision:
    task_id: UUID
    parent_plan_id: UUID
    parent_version: int
    plan: OwnedPlan
    changed_fields: tuple[str, ...]
    invalidated_approval_ids: tuple[UUID, ...]
    checkpoint_branch: bool
    provenance: str
