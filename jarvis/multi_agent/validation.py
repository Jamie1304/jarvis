"""Fail-closed validation of untrusted delegation proposals and privilege scopes."""

from __future__ import annotations

import json
from dataclasses import dataclass
from enum import StrEnum
from uuid import UUID, uuid4

from pydantic import BaseModel, ConfigDict, Field, ValidationError

from jarvis.multi_agent.models import (
    AgentType,
    DataCeiling,
    DelegatedTaskNode,
    DelegationGraph,
    FilesystemScope,
    NetworkScope,
    OrchestrationRequest,
    ResourceBudget,
)
from jarvis.multi_agent.registry import AgentRegistry, AgentRegistryError
from jarvis.permissions.models import Permission


class DelegationValidationReason(StrEnum):
    MALFORMED_PROPOSAL = "malformed_proposal"
    GOAL_MISMATCH = "goal_mismatch"
    GRAPH_TOO_LARGE = "graph_too_large"
    UNKNOWN_AGENT = "unknown_agent"
    UNAVAILABLE_AGENT = "unavailable_agent"
    RECURSIVE_DELEGATION = "recursive_delegation"
    SCOPE_ESCALATION = "scope_escalation"
    DATA_SCOPE_ESCALATION = "data_scope_escalation"
    MALFORMED_INPUT = "malformed_input"
    UNRESOLVED_DEPENDENCY = "unresolved_dependency"
    CYCLE = "cycle"
    BUDGET_EXHAUSTED = "budget_exhausted"
    NO_CONCRETE_ADVANTAGE = "no_concrete_advantage"


class DelegationValidationError(ValueError):
    def __init__(self, reason: DelegationValidationReason, message: str) -> None:
        super().__init__(message)
        self.reason = reason


class ProposedResourceBudget(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)

    max_model_calls: int = Field(ge=0, le=64)
    max_tokens: int = Field(ge=0, le=2_000_000)
    max_cost_units: int = Field(ge=0, le=100_000)
    max_elapsed_seconds: float = Field(gt=0, le=3_600, allow_inf_nan=False)


class ProposedAgentNode(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)

    key: str = Field(min_length=1, max_length=128)
    agent_id: str = Field(min_length=1, max_length=128)
    objective: str = Field(min_length=1, max_length=4_000)
    input: dict[str, object]
    dependencies: list[str] = Field(default_factory=list, max_length=32)
    required_tools: list[str] = Field(default_factory=list, max_length=32)
    required_capabilities: list[str] = Field(default_factory=list, max_length=32)
    required_permissions: list[str] = Field(default_factory=list, max_length=16)
    context_keys: list[str] = Field(default_factory=list, max_length=32)
    evidence_references: list[str] = Field(default_factory=list, max_length=64)
    filesystem_roots: list[str] = Field(default_factory=list, max_length=32)
    network_origins: list[str] = Field(default_factory=list, max_length=32)
    data_ceiling: str = Field(default=DataCeiling.PUBLIC.value, min_length=1, max_length=32)
    budget: ProposedResourceBudget
    timeout_seconds: float = Field(gt=0, le=3_600, allow_inf_nan=False)


class DelegationProposal(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)

    goal: str = Field(min_length=1, max_length=4_000)
    rationale: str = Field(min_length=1, max_length=2_000)
    nodes: list[ProposedAgentNode] = Field(min_length=1, max_length=32)


@dataclass(frozen=True, slots=True)
class DelegationLimits:
    max_nodes: int
    max_concurrency: int
    total_budget: ResourceBudget
    max_depth: int = 1

    def __post_init__(self) -> None:
        if self.max_nodes <= 0 or self.max_nodes > 32:
            raise ValueError("Delegation node limit must be between 1 and 32")
        if self.max_concurrency <= 0 or self.max_concurrency > 16:
            raise ValueError("Delegation concurrency limit must be between 1 and 16")
        if self.max_depth <= 0 or self.max_depth > 1:
            raise ValueError("Delegation recursion depth must be exactly one")


class DelegationValidator:
    def __init__(self, registry: AgentRegistry, limits: DelegationLimits) -> None:
        self._registry = registry
        self._limits = limits

    @property
    def limits(self) -> DelegationLimits:
        return self._limits

    def validate(self, raw: object, request: OrchestrationRequest) -> DelegationGraph:
        try:
            proposal = DelegationProposal.model_validate(raw)
        except ValidationError as error:
            raise DelegationValidationError(
                DelegationValidationReason.MALFORMED_PROPOSAL,
                "Delegation proposal does not match the strict schema",
            ) from error
        if proposal.goal != request.goal:
            raise DelegationValidationError(
                DelegationValidationReason.GOAL_MISMATCH,
                "Delegation cannot change the original goal",
            )
        if len(proposal.nodes) > self._limits.max_nodes:
            raise DelegationValidationError(
                DelegationValidationReason.GRAPH_TOO_LARGE,
                "Delegation exceeds the trusted node limit",
            )
        keys = [node.key for node in proposal.nodes]
        if len(keys) != len(set(keys)):
            raise DelegationValidationError(
                DelegationValidationReason.MALFORMED_PROPOSAL,
                "Delegation node keys must be unique",
            )
        key_ids = {key: uuid4() for key in keys}
        self._validate_dependencies(proposal.nodes, key_ids)
        nodes = tuple(self._node(node, key_ids, request) for node in proposal.nodes)
        self._validate_total_budget(nodes)
        return DelegationGraph(uuid4(), request.task_id, request.goal, nodes, proposal.rationale)

    def has_concrete_advantage(self, graph: DelegationGraph) -> bool:
        """Initial policy delegates only independent work across distinct specialisms."""

        ancestors = self._ancestors(graph)
        for index, left in enumerate(graph.nodes):
            left_type = self._registry.inspect(left.agent_id).agent_type
            for right in graph.nodes[index + 1 :]:
                right_type = self._registry.inspect(right.agent_id).agent_type
                independent = (
                    right.node_id not in ancestors[left.node_id]
                    and left.node_id not in ancestors[right.node_id]
                )
                if independent and left_type is not right_type:
                    return True
        return False

    def _node(
        self,
        proposed: ProposedAgentNode,
        key_ids: dict[str, UUID],
        request: OrchestrationRequest,
    ) -> DelegatedTaskNode:
        try:
            contract = self._registry.inspect(proposed.agent_id)
        except AgentRegistryError as error:
            raise DelegationValidationError(
                DelegationValidationReason.UNKNOWN_AGENT,
                f"Unknown delegated agent: {proposed.agent_id}",
            ) from error
        if contract.agent_type is AgentType.ORCHESTRATOR or contract.may_delegate:
            raise DelegationValidationError(
                DelegationValidationReason.RECURSIVE_DELEGATION,
                "A delegated task cannot target an agent with delegation authority",
            )
        if not contract.available:
            raise DelegationValidationError(
                DelegationValidationReason.UNAVAILABLE_AGENT,
                f"Delegated agent is unavailable: {proposed.agent_id}",
            )
        permissions = self._permissions(proposed.required_permissions)
        required_tools = self._unique(proposed.required_tools, "tools")
        required_capabilities = self._unique(proposed.required_capabilities, "capabilities")
        if (
            not set(required_tools).issubset(request.allowed_tools)
            or not set(required_tools).issubset(contract.allowed_tools)
            or not set(required_capabilities).issubset(request.allowed_capabilities)
            or not set(required_capabilities).issubset(contract.allowed_capabilities)
            or not set(permissions).issubset(request.allowed_permissions)
            or not set(permissions).issubset(contract.allowed_permissions)
        ):
            raise DelegationValidationError(
                DelegationValidationReason.SCOPE_ESCALATION,
                "Delegation cannot expand the parent or agent contract scope",
            )
        try:
            filesystem_scope = FilesystemScope(tuple(proposed.filesystem_roots))
            network_scope = NetworkScope(tuple(proposed.network_origins))
            data_ceiling = DataCeiling(proposed.data_ceiling)
        except ValueError as error:
            raise DelegationValidationError(
                DelegationValidationReason.SCOPE_ESCALATION,
                "Delegation contains an invalid host or data scope",
            ) from error
        if (
            not request.filesystem_scope.contains(filesystem_scope)
            or not contract.filesystem_scope.contains(filesystem_scope)
            or not request.network_scope.contains(network_scope)
            or not contract.network_scope.contains(network_scope)
        ):
            raise DelegationValidationError(
                DelegationValidationReason.SCOPE_ESCALATION,
                "Delegation cannot expand filesystem or network scope",
            )
        if not request.data_ceiling.contains(data_ceiling) or not contract.data_ceiling.contains(
            data_ceiling
        ):
            raise DelegationValidationError(
                DelegationValidationReason.DATA_SCOPE_ESCALATION,
                "Delegation cannot expand its data ceiling",
            )
        if not request.model_policy.contains(contract.model_policy):
            raise DelegationValidationError(
                DelegationValidationReason.SCOPE_ESCALATION,
                "Delegation cannot expand its model policy",
            )
        if not request.delegation_policy.contains(contract.delegation_policy):
            raise DelegationValidationError(
                DelegationValidationReason.RECURSIVE_DELEGATION,
                "Delegation cannot expand its recursion policy",
            )
        budget = self._budget(proposed.budget)
        if not contract.resource_budget.contains(budget):
            raise DelegationValidationError(
                DelegationValidationReason.BUDGET_EXHAUSTED,
                "Delegated node exceeds its agent resource budget",
            )
        if proposed.timeout_seconds > budget.max_elapsed_seconds:
            raise DelegationValidationError(
                DelegationValidationReason.BUDGET_EXHAUSTED,
                "Delegated timeout exceeds its reserved elapsed-time budget",
            )
        context_keys = self._unique(proposed.context_keys, "context keys")
        evidence_references = self._unique(proposed.evidence_references, "evidence references")
        known_context = {item.key for item in request.context}
        known_evidence = {item.reference_id for item in request.evidence}
        if not set(context_keys).issubset(known_context) or not set(evidence_references).issubset(
            known_evidence
        ):
            raise DelegationValidationError(
                DelegationValidationReason.MALFORMED_INPUT,
                "Delegation references unavailable context or evidence",
            )
        selected_context = tuple(item for item in request.context if item.key in context_keys)
        selected_evidence = tuple(
            item for item in request.evidence if item.reference_id in evidence_references
        )
        if any(
            item.contains_secret or not data_ceiling.allows(item.classification)
            for item in selected_context
        ) or any(
            item.contains_secret or not data_ceiling.allows(item.classification)
            for item in selected_evidence
        ):
            raise DelegationValidationError(
                DelegationValidationReason.DATA_SCOPE_ESCALATION,
                "Delegated worker cannot receive secret or out-of-ceiling data",
            )
        try:
            validated = contract.accepted_task_schema.model_validate(proposed.input)
            input_json = json.dumps(
                validated.model_dump(mode="json"),
                sort_keys=True,
                separators=(",", ":"),
                allow_nan=False,
            )
        except (ValidationError, TypeError, ValueError) as error:
            raise DelegationValidationError(
                DelegationValidationReason.MALFORMED_INPUT,
                f"Delegated input does not match agent contract: {proposed.agent_id}",
            ) from error
        return DelegatedTaskNode(
            node_id=key_ids[proposed.key],
            key=proposed.key,
            agent_id=proposed.agent_id,
            objective=proposed.objective,
            input_json=input_json,
            dependencies=tuple(key_ids[key] for key in proposed.dependencies),
            required_tools=required_tools,
            required_capabilities=required_capabilities,
            required_permissions=permissions,
            context_keys=context_keys,
            evidence_references=evidence_references,
            budget=budget,
            timeout_seconds=proposed.timeout_seconds,
            filesystem_scope=filesystem_scope,
            network_scope=network_scope,
            data_ceiling=data_ceiling,
        )

    def _validate_total_budget(self, nodes: tuple[DelegatedTaskNode, ...]) -> None:
        total = self._limits.total_budget
        if (
            sum(node.budget.max_model_calls for node in nodes) > total.max_model_calls
            or sum(node.budget.max_tokens for node in nodes) > total.max_tokens
            or sum(node.budget.max_cost_units for node in nodes) > total.max_cost_units
        ):
            raise DelegationValidationError(
                DelegationValidationReason.BUDGET_EXHAUSTED,
                "Delegation reservations exceed the task resource budget",
            )

    @staticmethod
    def _validate_dependencies(nodes: list[ProposedAgentNode], key_ids: dict[str, UUID]) -> None:
        graph: dict[str, tuple[str, ...]] = {}
        for node in nodes:
            if len(node.dependencies) != len(set(node.dependencies)):
                raise DelegationValidationError(
                    DelegationValidationReason.UNRESOLVED_DEPENDENCY,
                    "Delegated dependencies must be unique",
                )
            if any(dependency not in key_ids for dependency in node.dependencies):
                raise DelegationValidationError(
                    DelegationValidationReason.UNRESOLVED_DEPENDENCY,
                    "Delegated dependency cannot be resolved",
                )
            graph[node.key] = tuple(node.dependencies)
        visiting: set[str] = set()
        visited: set[str] = set()

        def visit(key: str) -> None:
            if key in visiting:
                raise DelegationValidationError(
                    DelegationValidationReason.CYCLE,
                    "Delegation graph contains a cycle",
                )
            if key in visited:
                return
            visiting.add(key)
            for dependency in graph[key]:
                visit(dependency)
            visiting.remove(key)
            visited.add(key)

        for key in graph:
            visit(key)

    @staticmethod
    def _permissions(values: list[str]) -> tuple[Permission, ...]:
        try:
            permissions = tuple(Permission(value) for value in values)
        except ValueError as error:
            raise DelegationValidationError(
                DelegationValidationReason.SCOPE_ESCALATION,
                "Delegation contains an unknown permission",
            ) from error
        if len(permissions) != len(set(permissions)):
            raise DelegationValidationError(
                DelegationValidationReason.MALFORMED_PROPOSAL,
                "Delegated permissions must be unique",
            )
        return tuple(sorted(permissions, key=lambda item: item.value))

    @staticmethod
    def _unique(values: list[str], name: str) -> tuple[str, ...]:
        if len(values) != len(set(values)) or any(
            not value.strip() or len(value) > 128 or "\x00" in value for value in values
        ):
            raise DelegationValidationError(
                DelegationValidationReason.MALFORMED_PROPOSAL,
                f"Delegated {name} must be bounded and unique",
            )
        return tuple(sorted(values))

    @staticmethod
    def _budget(value: ProposedResourceBudget) -> ResourceBudget:
        return ResourceBudget(
            value.max_model_calls,
            value.max_tokens,
            value.max_cost_units,
            value.max_elapsed_seconds,
        )

    @staticmethod
    def _ancestors(graph: DelegationGraph) -> dict[UUID, frozenset[UUID]]:
        nodes = {node.node_id: node for node in graph.nodes}
        cache: dict[UUID, frozenset[UUID]] = {}

        def ancestors(node_id: UUID) -> frozenset[UUID]:
            if node_id not in cache:
                direct = nodes[node_id].dependencies
                cache[node_id] = frozenset(
                    dependency for parent in direct for dependency in (parent, *ancestors(parent))
                )
            return cache[node_id]

        for node_id in nodes:
            ancestors(node_id)
        return cache
