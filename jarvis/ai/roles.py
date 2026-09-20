"""Logical application roles mapped onto the existing R3D routing boundary."""

from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum

from jarvis.ai.models import ModelRole, PrivacyContext
from jarvis.ai.routing import RouteRequest, RoutingPolicy


class LogicalModelRole(StrEnum):
    """An application responsibility, independent of physical model identity."""

    CONVERSATION = "conversation"
    ORCHESTRATION = "orchestration"


@dataclass(frozen=True, slots=True)
class LogicalRoleRequirements:
    """Typed role requirements projected into the canonical R3D RouteRequest."""

    role: LogicalModelRole
    task: str
    context_tokens: int = 0
    privacy_context: PrivacyContext = PrivacyContext()
    policy: RoutingPolicy = RoutingPolicy.BALANCED
    complexity: str = "medium"
    requires_tools: bool = False
    latency_budget_ms: float | None = None

    def __post_init__(self) -> None:
        if not isinstance(self.role, LogicalModelRole):
            raise ValueError("Logical model role is invalid")
        if type(self.task) is not str or not self.task.strip() or len(self.task) > 4_000:
            raise ValueError("Logical role task is invalid")
        if type(self.context_tokens) is not int or not 0 <= self.context_tokens <= 2_000_000:
            raise ValueError("Logical role context is invalid")
        if not isinstance(self.privacy_context, PrivacyContext):
            raise ValueError("Logical role privacy context is invalid")
        if not isinstance(self.policy, RoutingPolicy):
            raise ValueError("Logical role routing policy is invalid")
        if type(self.requires_tools) is not bool:
            raise ValueError("Logical role tool requirement is invalid")

    def to_route_request(self) -> RouteRequest:
        """Build the existing router request without selecting a provider/model."""

        orchestration = self.role is LogicalModelRole.ORCHESTRATION
        return RouteRequest(
            task=self.task,
            profile=self.role.value,
            role=ModelRole.REASONING if orchestration else ModelRole.GENERAL,
            complexity=self.complexity,
            context_tokens=self.context_tokens,
            requires_tools=self.requires_tools,
            requires_structured_output=orchestration,
            policy=self.policy,
            task_class=self.role.value,
            responsibility=self.role.value,
            privacy_context=self.privacy_context,
            latency_budget_ms=self.latency_budget_ms,
        )


__all__ = ["LogicalModelRole", "LogicalRoleRequirements"]
