"""Typed contracts and execution records for optional bounded multi-agent work."""

from __future__ import annotations

import json
import math
from dataclasses import dataclass
from datetime import UTC, datetime
from enum import StrEnum
from typing import Any
from uuid import UUID

from pydantic import BaseModel

from jarvis.permissions.models import Permission


class AgentType(StrEnum):
    ORCHESTRATOR = "orchestrator"
    RESEARCH = "research"
    CODING = "coding"
    COMPUTER = "computer"


class AgentNodeStatus(StrEnum):
    QUEUED = "queued"
    RUNNING = "running"
    SUCCEEDED = "succeeded"
    PARTIAL = "partial"
    FAILED = "failed"
    TIMED_OUT = "timed_out"
    CANCELLED = "cancelled"
    BLOCKED = "blocked"
    BUDGET_EXHAUSTED = "budget_exhausted"


class AgentResultStatus(StrEnum):
    SUCCEEDED = "succeeded"
    PARTIAL = "partial"
    FAILED = "failed"
    CANCELLED = "cancelled"


class OrchestrationStatus(StrEnum):
    COMPLETED = "completed"
    PARTIAL = "partial"
    FAILED = "failed"
    CANCELLED = "cancelled"
    BUDGET_EXHAUSTED = "budget_exhausted"
    REJECTED = "rejected"


class ExecutionMode(StrEnum):
    SINGLE_AGENT = "single_agent"
    MULTI_AGENT = "multi_agent"


def _bounded(value: str, name: str, limit: int = 4_000) -> None:
    if not isinstance(value, str) or not value.strip() or len(value) > limit or "\x00" in value:
        raise ValueError(f"{name} must be bounded, non-empty, and NUL-free")


def _strings(values: tuple[str, ...], name: str, *, limit: int = 128) -> None:
    if len(values) > 64 or any(
        not isinstance(value, str) or not value.strip() or len(value) > limit or "\x00" in value
        for value in values
    ):
        raise ValueError(f"{name} must contain bounded non-empty strings")
    if len(values) != len(set(values)):
        raise ValueError(f"{name} must be unique")


@dataclass(frozen=True, slots=True)
class ResourceBudget:
    max_model_calls: int
    max_tokens: int
    max_cost_units: int
    max_elapsed_seconds: float

    def __post_init__(self) -> None:
        if min(self.max_model_calls, self.max_tokens, self.max_cost_units) < 0:
            raise ValueError("Agent resource budgets cannot be negative")
        if self.max_elapsed_seconds <= 0 or not math.isfinite(self.max_elapsed_seconds):
            raise ValueError("Agent elapsed-time budget must be positive and finite")

    def contains(self, other: ResourceBudget) -> bool:
        return (
            other.max_model_calls <= self.max_model_calls
            and other.max_tokens <= self.max_tokens
            and other.max_cost_units <= self.max_cost_units
            and other.max_elapsed_seconds <= self.max_elapsed_seconds
        )


@dataclass(frozen=True, slots=True)
class ResourceUsage:
    model_calls: int = 0
    tokens: int = 0
    cost_units: int = 0

    def __post_init__(self) -> None:
        if min(self.model_calls, self.tokens, self.cost_units) < 0:
            raise ValueError("Agent resource usage cannot be negative")

    def within(self, budget: ResourceBudget) -> bool:
        return (
            self.model_calls <= budget.max_model_calls
            and self.tokens <= budget.max_tokens
            and self.cost_units <= budget.max_cost_units
        )

    def plus(self, other: ResourceUsage) -> ResourceUsage:
        return ResourceUsage(
            self.model_calls + other.model_calls,
            self.tokens + other.tokens,
            self.cost_units + other.cost_units,
        )


@dataclass(frozen=True, slots=True)
class EvidenceReference:
    reference_id: str
    summary: str
    digest: str

    def __post_init__(self) -> None:
        _bounded(self.reference_id, "Evidence reference ID", 128)
        _bounded(self.summary, "Evidence summary", 1_000)
        if len(self.digest) != 64 or any(
            character not in "0123456789abcdef" for character in self.digest
        ):
            raise ValueError("Evidence digest must be a lowercase SHA-256 value")


@dataclass(frozen=True, slots=True)
class ContextItem:
    key: str
    value: str

    def __post_init__(self) -> None:
        _bounded(self.key, "Context key", 128)
        _bounded(self.value, "Context value", 2_000)


@dataclass(frozen=True, slots=True)
class AgentContract:
    agent_id: str
    agent_type: AgentType
    responsibility: str
    accepted_task_schema: type[BaseModel]
    allowed_tools: frozenset[str]
    allowed_capabilities: frozenset[str]
    allowed_permissions: frozenset[Permission]
    resource_budget: ResourceBudget
    result_schema: type[BaseModel]
    may_delegate: bool = False
    available: bool = True

    def __post_init__(self) -> None:
        _bounded(self.agent_id, "Agent ID", 128)
        _bounded(self.responsibility, "Agent responsibility", 1_000)
        if not isinstance(self.agent_type, AgentType):
            raise ValueError("Agent type must be recognized")
        if self.may_delegate and self.agent_type is not AgentType.ORCHESTRATOR:
            raise ValueError("Only the orchestrator agent may delegate")
        _strings(tuple(sorted(self.allowed_tools)), "Allowed tools")
        _strings(tuple(sorted(self.allowed_capabilities)), "Allowed capabilities")
        if any(not isinstance(value, Permission) for value in self.allowed_permissions):
            raise ValueError("Agent permissions must be recognized")
        if not issubclass(self.accepted_task_schema, BaseModel) or not issubclass(
            self.result_schema, BaseModel
        ):
            raise ValueError("Agent task and result schemas must be Pydantic models")


@dataclass(frozen=True, slots=True)
class OrchestrationRequest:
    task_id: UUID
    goal: str
    context: tuple[ContextItem, ...]
    evidence: tuple[EvidenceReference, ...]
    allowed_tools: frozenset[str]
    allowed_capabilities: frozenset[str]
    allowed_permissions: frozenset[Permission]
    completion_evidence: tuple[str, ...]

    def __post_init__(self) -> None:
        _bounded(self.goal, "Orchestration goal")
        if len(self.context) > 32 or len({item.key for item in self.context}) != len(self.context):
            raise ValueError("Task context must be bounded and uniquely keyed")
        if len(self.evidence) > 64 or len({item.reference_id for item in self.evidence}) != len(
            self.evidence
        ):
            raise ValueError("Shared evidence references must be bounded and unique")
        if any(not isinstance(value, Permission) for value in self.allowed_permissions):
            raise ValueError("Task permissions must be recognized")
        _strings(self.completion_evidence, "Completion evidence")
        if not self.completion_evidence:
            raise ValueError("Multi-agent tasks require explicit completion evidence")


@dataclass(frozen=True, slots=True)
class AgentInvocation:
    task_id: UUID
    node_id: UUID
    objective: str
    validated_input: BaseModel
    context: tuple[ContextItem, ...]
    evidence: tuple[EvidenceReference, ...]
    required_tools: tuple[str, ...]
    required_capabilities: tuple[str, ...]
    required_permissions: tuple[Permission, ...]
    budget: ResourceBudget

    def __post_init__(self) -> None:
        _bounded(self.objective, "Agent objective")
        _strings(self.required_tools, "Required tools")
        _strings(self.required_capabilities, "Required capabilities")


@dataclass(frozen=True, slots=True)
class AgentResult:
    status: AgentResultStatus
    output_json: str
    evidence: tuple[EvidenceReference, ...]
    usage: ResourceUsage
    error_code: str | None = None
    error_message: str | None = None

    def __post_init__(self) -> None:
        if not isinstance(self.status, AgentResultStatus):
            raise ValueError("Agent result status must be recognized")
        try:
            json.loads(self.output_json)
        except (json.JSONDecodeError, TypeError) as error:
            raise ValueError("Agent result output must be valid JSON") from error
        if len(self.output_json) > 32_000 or len(self.evidence) > 32:
            raise ValueError("Agent result and evidence must be bounded")
        if self.error_code is not None:
            _bounded(self.error_code, "Agent error code", 128)
        if self.error_message is not None:
            _bounded(self.error_message, "Agent error message", 2_000)

    @classmethod
    def success(
        cls,
        output: BaseModel,
        *,
        evidence: tuple[EvidenceReference, ...] = (),
        usage: ResourceUsage | None = None,
    ) -> AgentResult:
        return cls(
            AgentResultStatus.SUCCEEDED,
            output.model_dump_json(),
            evidence,
            usage or ResourceUsage(),
        )


@dataclass(frozen=True, slots=True)
class DelegatedTaskNode:
    node_id: UUID
    key: str
    agent_id: str
    objective: str
    input_json: str
    dependencies: tuple[UUID, ...]
    required_tools: tuple[str, ...]
    required_capabilities: tuple[str, ...]
    required_permissions: tuple[Permission, ...]
    context_keys: tuple[str, ...]
    evidence_references: tuple[str, ...]
    budget: ResourceBudget
    timeout_seconds: float
    status: AgentNodeStatus = AgentNodeStatus.QUEUED
    result: AgentResult | None = None
    error_code: str | None = None
    error_message: str | None = None

    def __post_init__(self) -> None:
        _bounded(self.key, "Delegated node key", 128)
        _bounded(self.agent_id, "Delegated agent ID", 128)
        _bounded(self.objective, "Delegated objective")
        try:
            value = json.loads(self.input_json)
        except json.JSONDecodeError as error:
            raise ValueError("Delegated input must be valid JSON") from error
        if not isinstance(value, dict) or len(self.input_json) > 16_000:
            raise ValueError("Delegated input must be a bounded JSON object")
        if self.node_id in self.dependencies or len(set(self.dependencies)) != len(
            self.dependencies
        ):
            raise ValueError("Delegated dependencies must be unique and cannot reference self")
        _strings(self.required_tools, "Required tools")
        _strings(self.required_capabilities, "Required capabilities")
        _strings(self.context_keys, "Context keys")
        _strings(self.evidence_references, "Evidence references")
        if self.timeout_seconds <= 0 or not math.isfinite(self.timeout_seconds):
            raise ValueError("Delegated timeout must be positive and finite")


@dataclass(frozen=True, slots=True)
class DelegationGraph:
    graph_id: UUID
    task_id: UUID
    goal: str
    nodes: tuple[DelegatedTaskNode, ...]
    rationale: str

    def __post_init__(self) -> None:
        _bounded(self.goal, "Delegation goal")
        _bounded(self.rationale, "Delegation rationale", 2_000)
        if not self.nodes or len(self.nodes) > 32:
            raise ValueError("Delegation graph must contain a bounded set of nodes")
        if len({node.node_id for node in self.nodes}) != len(self.nodes):
            raise ValueError("Delegation node IDs must be unique")
        if len({node.key for node in self.nodes}) != len(self.nodes):
            raise ValueError("Delegation node keys must be unique")


@dataclass(frozen=True, slots=True)
class OrchestrationResult:
    task_id: UUID
    mode: ExecutionMode
    status: OrchestrationStatus
    nodes: tuple[DelegatedTaskNode, ...]
    evidence: tuple[EvidenceReference, ...]
    usage: ResourceUsage
    started_at: datetime
    finished_at: datetime
    reason_code: str
    reason: str

    def __post_init__(self) -> None:
        if not isinstance(self.mode, ExecutionMode) or not isinstance(
            self.status, OrchestrationStatus
        ):
            raise ValueError("Orchestration result mode and status must be recognized")
        _bounded(self.reason_code, "Orchestration reason code", 128)
        _bounded(self.reason, "Orchestration reason", 2_000)
        for name in ("started_at", "finished_at"):
            value = getattr(self, name)
            normalized = (
                value.replace(tzinfo=UTC) if value.tzinfo is None else value.astimezone(UTC)
            )
            object.__setattr__(self, name, normalized)
        if self.finished_at < self.started_at:
            raise ValueError("Orchestration finish time cannot precede start time")


JsonObject = dict[str, Any]
