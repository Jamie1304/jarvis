"""Typed contracts and execution records for optional bounded multi-agent work."""

from __future__ import annotations

import json
import math
import ntpath
from dataclasses import dataclass, field
from datetime import UTC, datetime
from enum import StrEnum
from pathlib import PureWindowsPath
from typing import Any
from urllib.parse import urlsplit
from uuid import UUID

from pydantic import BaseModel

from jarvis.permissions.models import Permission


class AgentType(StrEnum):
    ORCHESTRATOR = "orchestrator"
    RESEARCH = "research"
    CODING = "coding"
    INTEGRATION_BUILDER = "integration_builder"
    VERIFICATION = "verification"
    DIAGNOSTICS = "diagnostics"
    COMPUTER = "computer"


class DataClassification(StrEnum):
    PUBLIC = "public"
    INTERNAL = "internal"
    SENSITIVE = "sensitive"
    CONFIDENTIAL = "confidential"
    SECRET = "secret"


class DataCeiling(StrEnum):
    PUBLIC = "public"
    INTERNAL = "internal"
    SENSITIVE = "sensitive"
    CONFIDENTIAL = "confidential"

    def contains(self, child: DataCeiling) -> bool:
        return _DATA_ORDER[child] <= _DATA_ORDER[self]

    def allows(self, classification: DataClassification) -> bool:
        return (
            classification is not DataClassification.SECRET
            and _DATA_ORDER[classification] <= (_DATA_ORDER[self])
        )


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


_DATA_ORDER = {
    DataClassification.PUBLIC: 0,
    DataClassification.INTERNAL: 1,
    DataClassification.SENSITIVE: 2,
    DataClassification.CONFIDENTIAL: 3,
    DataClassification.SECRET: 4,
    DataCeiling.PUBLIC: 0,
    DataCeiling.INTERNAL: 1,
    DataCeiling.SENSITIVE: 2,
    DataCeiling.CONFIDENTIAL: 3,
}


def _scope_strings(values: tuple[str, ...], name: str, limit: int = 32) -> tuple[str, ...]:
    if type(values) is not tuple or len(values) > limit:
        raise ValueError(f"{name} must be a bounded tuple")
    _strings(values, name, limit=512)
    return tuple(values)


def _normalize_filesystem_root(value: str) -> str:
    _bounded(value, "Filesystem scope root", 1_000)
    if any(not character.isprintable() for character in value):
        raise ValueError("Filesystem scope root contains control characters")
    path = PureWindowsPath(value)
    if not path.is_absolute() or ".." in path.parts:
        raise ValueError("Filesystem scope roots must be absolute and traversal-free")
    normalized = ntpath.normcase(ntpath.normpath(str(path)))
    if any(part in {"*", "?"} for part in PureWindowsPath(normalized).parts):
        raise ValueError("Filesystem scope roots cannot contain wildcards")
    return normalized


def _path_contains(parent: str, child: str) -> bool:
    parent = parent.rstrip("\\") or parent
    return child == parent or child.startswith(parent + "\\")


@dataclass(frozen=True, slots=True)
class FilesystemScope:
    """Lexical Windows roots passed to a worker's trusted capability adapter."""

    roots: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        _scope_strings(self.roots, "Filesystem scope roots")
        normalized = tuple(_normalize_filesystem_root(value) for value in self.roots)
        if len(set(normalized)) != len(normalized):
            raise ValueError("Filesystem scope roots must be unique")
        object.__setattr__(self, "roots", normalized)

    def contains(self, child: FilesystemScope) -> bool:
        return all(
            any(_path_contains(parent, root) for parent in self.roots) for root in child.roots
        )


def _normalize_network_origin(value: str) -> str:
    _bounded(value, "Network scope origin", 512)
    parsed = urlsplit(value)
    if parsed.scheme.casefold() not in {"http", "https"} or not parsed.netloc:
        raise ValueError("Network scope must contain authenticated HTTP(S) origins")
    if (
        parsed.username is not None
        or parsed.password is not None
        or parsed.path not in {"", "/"}
        or parsed.query
        or parsed.fragment
    ):
        raise ValueError("Network scope must contain origins without credentials or paths")
    try:
        hostname = parsed.hostname
        port = parsed.port
    except ValueError as error:
        raise ValueError("Network scope origin has an invalid port") from error
    if not hostname:
        raise ValueError("Network scope origin must contain a host")
    host = hostname.casefold()
    if ":" in host:
        host = f"[{host}]"
    scheme = parsed.scheme.casefold()
    default_port = 443 if scheme == "https" else 80
    return f"{scheme}://{host}" + (f":{port}" if port is not None and port != default_port else "")


@dataclass(frozen=True, slots=True)
class NetworkScope:
    """Exact network origins; subdomains and redirects are not implied."""

    origins: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        _scope_strings(self.origins, "Network scope origins")
        normalized = tuple(_normalize_network_origin(value) for value in self.origins)
        if len(set(normalized)) != len(normalized):
            raise ValueError("Network scope origins must be unique")
        object.__setattr__(self, "origins", normalized)

    def contains(self, child: NetworkScope) -> bool:
        return set(child.origins).issubset(self.origins)


@dataclass(frozen=True, slots=True)
class WorkerModelPolicy:
    """Trusted model/provider ceiling; an empty allowlist means none are allowed."""

    provider_allowlist: frozenset[str] = frozenset()
    model_allowlist: frozenset[str] = frozenset()
    local_only: bool = True
    max_context_tokens: int = 32_000

    def __post_init__(self) -> None:
        if (
            type(self.provider_allowlist) is not frozenset
            or type(self.model_allowlist) is not frozenset
        ):
            raise ValueError("Worker model allowlists must be frozensets")
        _strings(tuple(sorted(self.provider_allowlist)), "Worker provider allowlist", limit=256)
        _strings(tuple(sorted(self.model_allowlist)), "Worker model allowlist", limit=256)
        if type(self.local_only) is not bool or self.max_context_tokens <= 0:
            raise ValueError("Worker model policy is malformed")

    def contains(self, child: WorkerModelPolicy) -> bool:
        return (
            (not self.local_only or child.local_only)
            and child.provider_allowlist.issubset(self.provider_allowlist)
            and child.model_allowlist.issubset(self.model_allowlist)
            and child.max_context_tokens <= self.max_context_tokens
        )


@dataclass(frozen=True, slots=True)
class WorkerProfile:
    """Behavioral identity only; profile text never grants authority."""

    profile_id: str
    purpose: str

    def __post_init__(self) -> None:
        _bounded(self.profile_id, "Worker profile ID", 128)
        _bounded(self.purpose, "Worker profile purpose", 2_000)


@dataclass(frozen=True, slots=True)
class WorkerDelegationPolicy:
    """Explicit recursion ceiling. Specialist workers normally receive zero depth."""

    allow_spawn: bool = False
    max_depth: int = 0

    def __post_init__(self) -> None:
        if type(self.allow_spawn) is not bool or self.max_depth < 0 or self.max_depth > 8:
            raise ValueError("Worker delegation policy is malformed")
        if not self.allow_spawn and self.max_depth != 0:
            raise ValueError("A non-delegating worker cannot have recursion depth")
        if self.allow_spawn and self.max_depth == 0:
            raise ValueError("A delegating worker requires a positive recursion depth")

    def contains(self, child: WorkerDelegationPolicy) -> bool:
        return (not child.allow_spawn or self.allow_spawn) and child.max_depth <= self.max_depth


def _looks_secret(value: str) -> bool:
    lowered = value.casefold()
    return any(
        marker in lowered
        for marker in (
            "password=",
            "secret=",
            "api_key=",
            "apikey=",
            "authorization: bearer",
            "private_key=",
        )
    )


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
    classification: DataClassification = DataClassification.PUBLIC

    def __post_init__(self) -> None:
        _bounded(self.reference_id, "Evidence reference ID", 128)
        _bounded(self.summary, "Evidence summary", 1_000)
        if len(self.digest) != 64 or any(
            character not in "0123456789abcdef" for character in self.digest
        ):
            raise ValueError("Evidence digest must be a lowercase SHA-256 value")
        if not isinstance(self.classification, DataClassification):
            raise ValueError("Evidence classification must be recognized")

    @property
    def contains_secret(self) -> bool:
        return self.classification is DataClassification.SECRET or _looks_secret(self.summary)


@dataclass(frozen=True, slots=True)
class ContextItem:
    key: str
    value: str
    classification: DataClassification = DataClassification.PUBLIC

    def __post_init__(self) -> None:
        _bounded(self.key, "Context key", 128)
        _bounded(self.value, "Context value", 2_000)
        if not isinstance(self.classification, DataClassification):
            raise ValueError("Context classification must be recognized")

    @property
    def contains_secret(self) -> bool:
        return self.classification is DataClassification.SECRET or _looks_secret(self.value)


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
    profile: WorkerProfile | None = None
    model_policy: WorkerModelPolicy = field(default_factory=WorkerModelPolicy)
    filesystem_scope: FilesystemScope = field(default_factory=FilesystemScope)
    network_scope: NetworkScope = field(default_factory=NetworkScope)
    data_ceiling: DataCeiling = DataCeiling.INTERNAL
    delegation_policy: WorkerDelegationPolicy = field(default_factory=WorkerDelegationPolicy)

    def __post_init__(self) -> None:
        _bounded(self.agent_id, "Agent ID", 128)
        _bounded(self.responsibility, "Agent responsibility", 1_000)
        if not isinstance(self.agent_type, AgentType):
            raise ValueError("Agent type must be recognized")
        if self.may_delegate and self.agent_type is not AgentType.ORCHESTRATOR:
            raise ValueError("Only the orchestrator agent may delegate")
        if not isinstance(self.delegation_policy, WorkerDelegationPolicy):
            raise ValueError("Worker delegation policy must be recognized")
        if self.delegation_policy.allow_spawn and not self.may_delegate:
            raise ValueError("Delegation policy cannot grant worker spawn authority")
        if self.may_delegate and not self.delegation_policy.allow_spawn:
            object.__setattr__(self, "delegation_policy", WorkerDelegationPolicy(True, 1))
        if self.profile is None:
            object.__setattr__(self, "profile", WorkerProfile(self.agent_id, self.responsibility))
        elif not isinstance(self.profile, WorkerProfile):
            raise ValueError("Worker profile must be recognized")
        if not isinstance(self.model_policy, WorkerModelPolicy):
            raise ValueError("Worker model policy must be recognized")
        if not isinstance(self.filesystem_scope, FilesystemScope) or not isinstance(
            self.network_scope, NetworkScope
        ):
            raise ValueError("Worker host scopes must be recognized")
        if not isinstance(self.data_ceiling, DataCeiling):
            raise ValueError("Worker data ceiling must be recognized")
        if (
            type(self.allowed_tools) is not frozenset
            or type(self.allowed_capabilities) is not frozenset
        ):
            raise ValueError("Agent tool and capability allowlists must be frozensets")
        if type(self.allowed_permissions) is not frozenset:
            raise ValueError("Agent permission allowlist must be a frozenset")
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
    profile: WorkerProfile = field(
        default_factory=lambda: WorkerProfile("orchestration", "Parent task orchestration")
    )
    model_policy: WorkerModelPolicy = field(default_factory=WorkerModelPolicy)
    filesystem_scope: FilesystemScope = field(default_factory=FilesystemScope)
    network_scope: NetworkScope = field(default_factory=NetworkScope)
    data_ceiling: DataCeiling = DataCeiling.INTERNAL
    delegation_policy: WorkerDelegationPolicy = field(default_factory=WorkerDelegationPolicy)

    def __post_init__(self) -> None:
        _bounded(self.goal, "Orchestration goal")
        if type(self.context) is not tuple or type(self.evidence) is not tuple:
            raise ValueError("Task context and evidence must be tuples")
        if (
            type(self.allowed_tools) is not frozenset
            or type(self.allowed_capabilities) is not frozenset
        ):
            raise ValueError("Task tool and capability allowlists must be frozensets")
        if type(self.allowed_permissions) is not frozenset:
            raise ValueError("Task permission allowlist must be a frozenset")
        if any(not isinstance(item, ContextItem) for item in self.context) or any(
            not isinstance(item, EvidenceReference) for item in self.evidence
        ):
            raise ValueError("Task context and evidence must be typed")
        if len(self.context) > 32 or len({item.key for item in self.context}) != len(self.context):
            raise ValueError("Task context must be bounded and uniquely keyed")
        if len(self.evidence) > 64 or len({item.reference_id for item in self.evidence}) != len(
            self.evidence
        ):
            raise ValueError("Shared evidence references must be bounded and unique")
        if any(not isinstance(value, Permission) for value in self.allowed_permissions):
            raise ValueError("Task permissions must be recognized")
        if not isinstance(self.profile, WorkerProfile):
            raise ValueError("Task worker profile must be recognized")
        if not isinstance(self.model_policy, WorkerModelPolicy):
            raise ValueError("Task model policy must be recognized")
        if not isinstance(self.filesystem_scope, FilesystemScope) or not isinstance(
            self.network_scope, NetworkScope
        ):
            raise ValueError("Task host scopes must be recognized")
        if not isinstance(self.data_ceiling, DataCeiling):
            raise ValueError("Task data ceiling must be recognized")
        if not isinstance(self.delegation_policy, WorkerDelegationPolicy):
            raise ValueError("Task delegation policy must be recognized")
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
    profile: WorkerProfile = field(
        default_factory=lambda: WorkerProfile("worker", "Bounded specialist worker")
    )
    model_policy: WorkerModelPolicy = field(default_factory=WorkerModelPolicy)
    filesystem_scope: FilesystemScope = field(default_factory=FilesystemScope)
    network_scope: NetworkScope = field(default_factory=NetworkScope)
    data_ceiling: DataCeiling = DataCeiling.PUBLIC
    delegation_policy: WorkerDelegationPolicy = field(default_factory=WorkerDelegationPolicy)
    output_schema: type[BaseModel] | None = None
    tool_allowlist: frozenset[str] = frozenset()
    capability_allowlist: frozenset[str] = frozenset()

    def __post_init__(self) -> None:
        _bounded(self.objective, "Agent objective")
        if type(self.context) is not tuple or type(self.evidence) is not tuple:
            raise ValueError("Agent context and evidence must be tuples")
        if any(not isinstance(item, ContextItem) for item in self.context) or any(
            not isinstance(item, EvidenceReference) for item in self.evidence
        ):
            raise ValueError("Agent context and evidence must be typed")
        _strings(self.required_tools, "Required tools")
        _strings(self.required_capabilities, "Required capabilities")
        if (
            type(self.tool_allowlist) is not frozenset
            or type(self.capability_allowlist) is not frozenset
        ):
            raise ValueError("Agent tool and capability allowlists must be frozensets")
        _strings(tuple(sorted(self.tool_allowlist)), "Agent tool allowlist")
        _strings(tuple(sorted(self.capability_allowlist)), "Agent capability allowlist")
        if not set(self.required_tools).issubset(self.tool_allowlist) or not set(
            self.required_capabilities
        ).issubset(self.capability_allowlist):
            raise ValueError("Agent request exceeds its registered allowlists")
        if any(not isinstance(value, Permission) for value in self.required_permissions):
            raise ValueError("Agent permissions must be recognized")
        if not isinstance(self.profile, WorkerProfile) or not isinstance(
            self.model_policy, WorkerModelPolicy
        ):
            raise ValueError("Agent profile and model policy must be recognized")
        if not isinstance(self.filesystem_scope, FilesystemScope) or not isinstance(
            self.network_scope, NetworkScope
        ):
            raise ValueError("Agent host scopes must be recognized")
        if not isinstance(self.data_ceiling, DataCeiling) or not isinstance(
            self.delegation_policy, WorkerDelegationPolicy
        ):
            raise ValueError("Agent scope policies must be recognized")
        if self.output_schema is not None and (
            not isinstance(self.output_schema, type)
            or not issubclass(self.output_schema, BaseModel)
        ):
            raise ValueError("Agent output schema must be a Pydantic model")
        if any(
            item.contains_secret or not self.data_ceiling.allows(item.classification)
            for item in self.context
        ) or any(
            item.contains_secret or not self.data_ceiling.allows(item.classification)
            for item in self.evidence
        ):
            raise ValueError("Agent invocation cannot receive secret or out-of-ceiling data")


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
        if type(self.evidence) is not tuple or any(
            not isinstance(item, EvidenceReference) for item in self.evidence
        ):
            raise ValueError("Agent result evidence must be typed")
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
    filesystem_scope: FilesystemScope = field(default_factory=FilesystemScope)
    network_scope: NetworkScope = field(default_factory=NetworkScope)
    data_ceiling: DataCeiling = DataCeiling.PUBLIC
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
        if not isinstance(self.filesystem_scope, FilesystemScope) or not isinstance(
            self.network_scope, NetworkScope
        ):
            raise ValueError("Delegated host scopes must be recognized")
        if not isinstance(self.data_ceiling, DataCeiling):
            raise ValueError("Delegated data ceiling must be recognized")


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
