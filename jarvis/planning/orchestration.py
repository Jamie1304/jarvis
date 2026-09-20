"""Typed, untrusted orchestration proposal boundary."""

from __future__ import annotations

from dataclasses import dataclass
from uuid import UUID, uuid4

from jarvis.ai.roles import LogicalModelRole, LogicalRoleRequirements


@dataclass(frozen=True, slots=True)
class OrchestrationRequest:
    """Trusted request envelope given to an orchestration proposal provider."""

    orchestration_attempt_id: UUID
    goal: str
    assumptions: tuple[str, ...] = ()
    constraints: tuple[str, ...] = ()
    requirements: LogicalRoleRequirements | None = None

    def __post_init__(self) -> None:
        if not isinstance(self.orchestration_attempt_id, UUID):
            raise ValueError("Orchestration attempt identity is invalid")
        if type(self.goal) is not str or not self.goal.strip() or len(self.goal) > 4_000:
            raise ValueError("Orchestration goal is invalid")
        for name, values in (("assumptions", self.assumptions), ("constraints", self.constraints)):
            if (
                type(values) is not tuple
                or len(values) > 32
                or any(
                    type(value) is not str or not value.strip() or len(value) > 1_000
                    for value in values
                )
            ):
                raise ValueError(f"Orchestration {name} are invalid")
        if self.requirements is not None:
            if self.requirements.role is not LogicalModelRole.ORCHESTRATION:
                raise ValueError("Orchestration requirements must use the orchestration role")

    @classmethod
    def create(
        cls,
        goal: str,
        assumptions: tuple[str, ...] = (),
        constraints: tuple[str, ...] = (),
        requirements: LogicalRoleRequirements | None = None,
    ) -> OrchestrationRequest:
        return cls(uuid4(), goal, assumptions, constraints, requirements)


@dataclass(frozen=True, slots=True)
class OrchestrationResult:
    """An untrusted proposal; it is not validated, executable, or verified."""

    orchestration_attempt_id: UUID
    proposal: object | None = None
    route_decision_id: str | None = None
    failure: str | None = None

    def __post_init__(self) -> None:
        if not isinstance(self.orchestration_attempt_id, UUID):
            raise ValueError("Orchestration attempt identity is invalid")
        if self.route_decision_id is not None and (
            type(self.route_decision_id) is not str
            or not self.route_decision_id.strip()
            or len(self.route_decision_id) > 128
        ):
            raise ValueError("Orchestration route decision identity is invalid")
        if self.failure is not None and (
            type(self.failure) is not str or not self.failure.strip() or len(self.failure) > 1_000
        ):
            raise ValueError("Orchestration failure is invalid")


__all__ = ["OrchestrationRequest", "OrchestrationResult"]
