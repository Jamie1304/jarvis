"""Typed, authority-neutral execution-route discovery and hard eligibility."""

from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum
from uuid import UUID

from jarvis.ai.models import ModelRole, PrivacyContext
from jarvis.ai.providers.registry import ProviderLocality
from jarvis.ai.routing import (
    ProviderRouter,
    RouteCandidate,
    RouteRequest,
    RouteStatus,
    RoutingPolicy,
)
from jarvis.autonomy.models import PlanStep
from jarvis.capabilities import CapabilityRegistry
from jarvis.hardware import HardwareProfile
from jarvis.resources import (
    ResourceBudget,
    ResourceDecisionStatus,
    ResourceGovernor,
    ResourcePriority,
)
from jarvis.tools.registry import ToolRecord, ToolRegistry


class LogicalRole(StrEnum):
    """Small trusted role vocabulary used for route requirements."""

    CONVERSATION = "conversation"
    ORCHESTRATION = "orchestration"
    WORKER = "worker"
    VERIFICATION = "verification"


class ModelInferencePolicy(StrEnum):
    REQUIRED = "required"
    OPTIONAL = "optional"
    FORBIDDEN = "forbidden"


class ExecutionCandidateKind(StrEnum):
    MODEL = "model"
    TOOL = "tool"
    CAPABILITY = "capability"


class EligibilityCode(StrEnum):
    PRIVACY_INELIGIBLE = "privacy_ineligible"
    LOCALITY_INELIGIBLE = "locality_ineligible"
    CAPABILITY_MISSING = "capability_missing"
    MODALITY_UNSUPPORTED = "modality_unsupported"
    CONTEXT_INSUFFICIENT = "context_insufficient"
    STRUCTURED_OUTPUT_UNSUPPORTED = "structured_output_unsupported"
    TOOL_USE_UNSUPPORTED = "tool_use_unsupported"
    PROVIDER_NOT_USABLE = "provider_not_usable"
    RESOURCE_INELIGIBLE = "resource_ineligible"
    COST_LIMIT = "cost_limit"
    LATENCY_LIMIT = "latency_limit"
    NOT_EXECUTABLE = "not_executable"
    POLICY_BLOCKED = "policy_blocked"
    MODEL_ROUTE_UNAVAILABLE = "model_route_unavailable"


class ExecutionRouteStatus(StrEnum):
    SELECTED = "selected"
    NO_VALID_ROUTE = "no_valid_route"


@dataclass(frozen=True, slots=True)
class RoleResolution:
    role: LogicalRole
    source: str


class RoleResolver:
    """Normalize only the bounded role vocabulary; never grant authority."""

    _known = {role.value: role for role in LogicalRole}

    @classmethod
    def resolve(cls, value: LogicalRole | str | None) -> RoleResolution:
        if isinstance(value, LogicalRole):
            return RoleResolution(value, "typed")
        if type(value) is str:
            try:
                return RoleResolution(cls._known[value.casefold()], "normalized")
            except KeyError as error:
                raise ValueError("Unknown logical routing role") from error
        if value is None:
            return RoleResolution(LogicalRole.ORCHESTRATION, "step_default")
        raise ValueError("Logical routing role is invalid")


@dataclass(frozen=True, slots=True)
class StepRoutingContext:
    """Trusted, typed context supplied by the application around a PlanStep."""

    role: LogicalRole = LogicalRole.ORCHESTRATION
    task_class: str = "general"
    complexity: str = "medium"
    privacy_context: PrivacyContext = PrivacyContext()
    modality: str = "text"
    required_capabilities: frozenset[str] = frozenset()
    context_tokens: int = 0
    requires_structured_output: bool = False
    requires_tools: bool = False
    latency_budget_ms: float | None = None
    max_cost_per_million: float | None = None
    model_inference: ModelInferencePolicy = ModelInferencePolicy.OPTIONAL
    policy: RoutingPolicy = RoutingPolicy.BALANCED
    priority: ResourcePriority = ResourcePriority.USER_REQUESTED
    concurrency: int = 1
    resource_budget: ResourceBudget | None = None
    resource_state: HardwareProfile | None = None

    def __post_init__(self) -> None:
        if not isinstance(self.role, LogicalRole):
            raise ValueError("Step routing role must be typed")
        for name, value, limit in (
            ("task class", self.task_class, 128),
            ("complexity", self.complexity, 64),
            ("modality", self.modality, 64),
        ):
            if type(value) is not str or not value.strip() or len(value) > limit or "\x00" in value:
                raise ValueError(f"Step routing {name} is invalid")
        if not isinstance(self.privacy_context, PrivacyContext):
            raise ValueError("Step routing privacy context is invalid")
        if type(self.required_capabilities) is not frozenset or any(
            type(item) is not str or not item.strip() or "\x00" in item
            for item in self.required_capabilities
        ):
            raise ValueError("Step routing capabilities are invalid")
        if type(self.context_tokens) is not int or self.context_tokens < 0:
            raise ValueError("Step routing context is invalid")
        if type(self.requires_structured_output) is not bool:
            raise ValueError("Step routing structured output flag is invalid")
        if type(self.requires_tools) is not bool:
            raise ValueError("Step routing tool use flag is invalid")
        if not isinstance(self.model_inference, ModelInferencePolicy):
            raise ValueError("Step routing model policy is invalid")
        if not isinstance(self.policy, RoutingPolicy):
            raise ValueError("Step routing policy is invalid")
        if not isinstance(self.priority, ResourcePriority):
            raise ValueError("Step routing priority is invalid")
        if type(self.concurrency) is not int or not 1 <= self.concurrency <= 64:
            raise ValueError("Step routing concurrency is invalid")


@dataclass(frozen=True, slots=True)
class StepRequirements:
    """Canonical bounded projection of a trusted plan step for routing."""

    step_id: UUID
    capability: str
    action: str
    role: LogicalRole
    task_class: str
    complexity: str
    privacy_context: PrivacyContext
    modality: str
    required_capabilities: frozenset[str]
    context_tokens: int
    requires_structured_output: bool
    requires_tools: bool
    latency_budget_ms: float | None
    max_cost_per_million: float | None
    model_inference: ModelInferencePolicy
    policy: RoutingPolicy
    priority: ResourcePriority
    concurrency: int
    resource_budget: ResourceBudget | None
    resource_state: HardwareProfile | None

    @classmethod
    def from_step(
        cls, step: PlanStep, *, context: StepRoutingContext | None = None
    ) -> StepRequirements:
        if not isinstance(step, PlanStep):
            raise ValueError("A trusted PlanStep is required")
        supplied = context or StepRoutingContext()
        return cls(
            step_id=step.step_id,
            capability=step.capability,
            action=step.action,
            role=supplied.role,
            task_class=supplied.task_class,
            complexity=supplied.complexity,
            privacy_context=supplied.privacy_context,
            modality=supplied.modality,
            required_capabilities=frozenset({step.capability, *supplied.required_capabilities}),
            context_tokens=supplied.context_tokens,
            requires_structured_output=supplied.requires_structured_output,
            requires_tools=supplied.requires_tools,
            latency_budget_ms=supplied.latency_budget_ms,
            max_cost_per_million=supplied.max_cost_per_million,
            model_inference=supplied.model_inference,
            policy=supplied.policy,
            priority=supplied.priority,
            concurrency=supplied.concurrency,
            resource_budget=supplied.resource_budget,
            resource_state=supplied.resource_state,
        )

    def to_model_request(self) -> RouteRequest:
        """Build the legacy model request only from typed requirements."""

        return RouteRequest(
            task=f"{self.capability}:{self.action}",
            profile=self.task_class,
            role=ModelRole.TOOL_USE if self.requires_tools else ModelRole.GENERAL,
            modality=self.modality,
            complexity=self.complexity,
            context_tokens=self.context_tokens,
            requires_tools=self.requires_tools,
            requires_structured_output=self.requires_structured_output,
            latency_budget_ms=self.latency_budget_ms,
            max_cost_per_million=self.max_cost_per_million,
            resource_state=self.resource_state,
            concurrency=self.concurrency,
            policy=self.policy,
            # The broader selector owns the distinction between a forbidden
            # model and an unsatisfied execution route.  Do not collapse an
            # ineligible model into ProviderRouter's caller-facing NO_LLM.
            allow_no_llm=False,
            privacy_context=self.privacy_context,
            required_capabilities=frozenset(self.required_capabilities),
            priority=self.priority,
            task_class=self.task_class,
            responsibility=self.role.value,
        )


@dataclass(frozen=True, slots=True)
class CandidateEligibility:
    eligible: bool
    codes: tuple[EligibilityCode, ...] = ()

    def __post_init__(self) -> None:
        if type(self.eligible) is not bool or type(self.codes) is not tuple:
            raise ValueError("Candidate eligibility is invalid")
        if any(not isinstance(code, EligibilityCode) for code in self.codes):
            raise ValueError("Candidate eligibility codes are invalid")


@dataclass(frozen=True, slots=True)
class ExecutionCandidate:
    identity: str
    kind: ExecutionCandidateKind
    owner: str
    declared_capabilities: frozenset[str]
    locality: str
    modality: str | None
    requires_permission: bool
    executable: bool
    eligibility: CandidateEligibility
    model: RouteCandidate | None = None
    tool_id: str | None = None

    def __post_init__(self) -> None:
        if type(self.identity) is not str or not self.identity.strip():
            raise ValueError("Execution candidate identity is invalid")
        if not isinstance(self.kind, ExecutionCandidateKind):
            raise ValueError("Execution candidate kind is invalid")
        if type(self.declared_capabilities) is not frozenset:
            raise ValueError("Execution candidate capabilities are invalid")
        if type(self.executable) is not bool or not isinstance(
            self.eligibility, CandidateEligibility
        ):
            raise ValueError("Execution candidate state is invalid")


@dataclass(frozen=True, slots=True)
class ExecutionRouteDecision:
    status: ExecutionRouteStatus
    primary: ExecutionCandidate | None
    eligible: tuple[ExecutionCandidate, ...] = ()
    excluded: tuple[ExecutionCandidate, ...] = ()
    reasons: tuple[EligibilityCode, ...] = ()


class ExecutionRouteSelector:
    """Compose trusted registries; eligibility never grants execution authority."""

    def __init__(
        self,
        *,
        model_router: ProviderRouter,
        tool_registry: ToolRegistry,
        capability_registry: CapabilityRegistry | None = None,
        resource_governor: ResourceGovernor | None = None,
    ) -> None:
        if not isinstance(model_router, ProviderRouter) or not isinstance(
            tool_registry, ToolRegistry
        ):
            raise TypeError("Execution routing requires canonical registries")
        if capability_registry is not None and not isinstance(
            capability_registry, CapabilityRegistry
        ):
            raise TypeError("Capability registry is invalid")
        if resource_governor is not None and not isinstance(resource_governor, ResourceGovernor):
            raise TypeError("Resource governor is invalid")
        self._model_router = model_router
        self._tool_registry = tool_registry
        self._capability_registry = capability_registry
        self._resource_governor = resource_governor

    def route(self, requirements: StepRequirements) -> ExecutionRouteDecision:
        if not isinstance(requirements, StepRequirements):
            raise ValueError("Typed step requirements are required")
        eligible: list[ExecutionCandidate] = []
        excluded: list[ExecutionCandidate] = []
        if requirements.model_inference is not ModelInferencePolicy.FORBIDDEN:
            self._discover_models(requirements, eligible, excluded)
        if requirements.model_inference is not ModelInferencePolicy.REQUIRED:
            self._discover_tools(requirements, eligible, excluded)
        if eligible:
            return ExecutionRouteDecision(
                ExecutionRouteStatus.SELECTED,
                eligible[0],
                tuple(eligible),
                tuple(excluded),
            )
        reasons = tuple(dict.fromkeys(code for item in excluded for code in item.eligibility.codes))
        if not reasons and requirements.model_inference is ModelInferencePolicy.FORBIDDEN:
            reasons = (EligibilityCode.NOT_EXECUTABLE,)
        return ExecutionRouteDecision(
            ExecutionRouteStatus.NO_VALID_ROUTE, None, (), tuple(excluded), reasons
        )

    def _discover_models(
        self,
        requirements: StepRequirements,
        eligible: list[ExecutionCandidate],
        excluded: list[ExecutionCandidate],
    ) -> None:
        decision = self._model_router.route(requirements.to_model_request())
        model_candidates = (
            () if decision.primary is None else (decision.primary,)
        ) + decision.fallbacks
        for candidate in model_candidates:
            eligible.append(
                ExecutionCandidate(
                    identity=candidate.identity.storage_key,
                    kind=ExecutionCandidateKind.MODEL,
                    owner="ProviderRouter/ProviderRegistry",
                    declared_capabilities=frozenset(candidate.model.capabilities),
                    locality=(
                        ProviderLocality.LOCAL.value
                        if candidate.local
                        else ProviderLocality.REMOTE.value
                    ),
                    modality=next(iter(candidate.model.modalities), None),
                    requires_permission=False,
                    executable=True,
                    eligibility=CandidateEligibility(True),
                    model=candidate,
                )
            )
        if not model_candidates and decision.status is not RouteStatus.NO_LLM:
            excluded.append(
                ExecutionCandidate(
                    identity="model-route",
                    kind=ExecutionCandidateKind.MODEL,
                    owner="ProviderRouter/ProviderRegistry",
                    declared_capabilities=frozenset(),
                    locality=ProviderLocality.UNKNOWN.value,
                    modality=None,
                    requires_permission=False,
                    executable=False,
                    eligibility=CandidateEligibility(
                        False, (EligibilityCode.MODEL_ROUTE_UNAVAILABLE,)
                    ),
                )
            )

    def _discover_tools(
        self,
        requirements: StepRequirements,
        eligible: list[ExecutionCandidate],
        excluded: list[ExecutionCandidate],
    ) -> None:
        records = self._tool_registry.find_by_capability(requirements.capability)
        if not records and self._capability_registry is not None:
            try:
                self._capability_registry.inspect(requirements.capability)
            except KeyError:
                pass
            else:
                excluded.append(self._descriptive_capability(requirements.capability))
        for record in records:
            candidate = self._tool_candidate(record, requirements)
            (eligible if candidate.eligibility.eligible else excluded).append(candidate)

    def _tool_candidate(
        self, record: ToolRecord, requirements: StepRequirements
    ) -> ExecutionCandidate:
        codes: list[EligibilityCode] = []
        declared_capabilities = frozenset({*record.manifest.capabilities, record.manifest.tool_id})
        if not record.registered or not record.enabled or not record.healthy:
            codes.append(EligibilityCode.NOT_EXECUTABLE)
        if not requirements.required_capabilities.issubset(declared_capabilities):
            codes.append(EligibilityCode.CAPABILITY_MISSING)
        if self._resource_governor is not None and requirements.resource_budget is not None:
            resource = self._resource_governor.decide(
                f"execution-route.{record.manifest.tool_id}",
                requirements.priority,
                requirements.resource_budget,
            )
            if resource.status in {ResourceDecisionStatus.DENY, ResourceDecisionStatus.DEFER}:
                codes.append(EligibilityCode.RESOURCE_INELIGIBLE)
        return ExecutionCandidate(
            identity=record.manifest.tool_id,
            kind=ExecutionCandidateKind.TOOL,
            owner="ToolRegistry",
            declared_capabilities=declared_capabilities,
            locality="trusted_runtime",
            modality=None,
            requires_permission=bool(record.manifest.declared_permissions),
            executable=record.usable,
            eligibility=CandidateEligibility(not codes, tuple(dict.fromkeys(codes))),
            tool_id=record.manifest.tool_id,
        )

    @staticmethod
    def _descriptive_capability(capability: str) -> ExecutionCandidate:
        return ExecutionCandidate(
            identity=capability,
            kind=ExecutionCandidateKind.CAPABILITY,
            owner="CapabilityRegistry",
            declared_capabilities=frozenset({capability}),
            locality="descriptive",
            modality=None,
            requires_permission=False,
            executable=False,
            eligibility=CandidateEligibility(False, (EligibilityCode.NOT_EXECUTABLE,)),
        )


__all__ = [
    "CandidateEligibility",
    "EligibilityCode",
    "ExecutionCandidate",
    "ExecutionCandidateKind",
    "ExecutionRouteDecision",
    "ExecutionRouteSelector",
    "ExecutionRouteStatus",
    "LogicalRole",
    "ModelInferencePolicy",
    "RoleResolution",
    "RoleResolver",
    "StepRequirements",
    "StepRoutingContext",
]
