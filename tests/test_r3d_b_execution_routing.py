from typing import Any
from uuid import uuid4

import pytest
from jarvis.ai.models import ModelRole, PrivacyClassification, PrivacyContext
from jarvis.ai.providers import (
    ModelMetadata,
    ProviderDefinition,
    ProviderMetadata,
    ProviderRegistry,
)
from jarvis.ai.routing import ProviderRouter
from jarvis.autonomy.models import PlanStep
from jarvis.autonomy.routing import (
    EligibilityCode,
    ExecutionCandidateKind,
    ExecutionRouteSelector,
    ExecutionRouteStatus,
    LogicalRole,
    ModelInferencePolicy,
    RoleResolver,
    StepRequirements,
    StepRoutingContext,
)
from jarvis.capabilities import CapabilityRegistry
from jarvis.tools.catalog import create_safe_tool_registry

from tests.fakes import FakeAIProvider
from tests.test_capabilities import manifest


def step(capability: str = "math") -> PlanStep:
    return PlanStep(
        step_id=uuid4(),
        order=0,
        capability=capability,
        action="execute",
        arguments=(),
        dependencies=(),
        expected_outcome="verified",
    )


def model_registry() -> ProviderRegistry:
    model = ModelMetadata(
        "remote-model",
        8_192,
        capabilities=frozenset({"math", "structured_output", "tool_use"}),
        roles=frozenset({ModelRole.GENERAL}),
        modalities=frozenset({"text"}),
        quality_score=1.0,
        input_cost_per_million=0.0,
        output_cost_per_million=0.0,
    )
    return ProviderRegistry(
        (
            ProviderDefinition(
                ProviderMetadata("remote", "Remote", "test"),
                lambda _: FakeAIProvider(),
                (model,),
            ),
        )
    )


def requirements(**values: Any) -> StepRequirements:
    context_values: dict[str, Any] = {"model_inference": ModelInferencePolicy.FORBIDDEN}
    context_values.update(values)
    return StepRequirements.from_step(step(), context=StepRoutingContext(**context_values))


def selector(*, capabilities: CapabilityRegistry | None = None) -> ExecutionRouteSelector:
    return ExecutionRouteSelector(
        model_router=ProviderRouter(model_registry()),
        tool_registry=create_safe_tool_registry(),
        capability_registry=capabilities,
    )


def test_typed_projection_and_role_normalization_do_not_require_route_request() -> None:
    projected = StepRequirements.from_step(
        step(), context=StepRoutingContext(role=LogicalRole.WORKER, task_class="math")
    )

    assert projected.role is LogicalRole.WORKER
    assert projected.capability == "math"
    assert "math" in projected.required_capabilities
    assert RoleResolver.resolve(" verification ".strip()).role is LogicalRole.VERIFICATION
    with pytest.raises(ValueError):
        RoleResolver.resolve("security-admin")


def test_registered_tool_is_real_non_model_candidate_and_permission_is_descriptive() -> None:
    decision = selector().route(requirements())

    assert decision.status is ExecutionRouteStatus.SELECTED
    assert decision.primary is not None
    assert decision.primary.kind is ExecutionCandidateKind.TOOL
    assert decision.primary.identity == "calculator"
    assert decision.primary.requires_permission is False


def test_descriptive_capability_without_tool_owner_is_not_executable() -> None:
    descriptive = CapabilityRegistry((manifest(capability_id="descriptive-only"),))
    decision = selector(capabilities=descriptive).route(
        StepRequirements.from_step(
            step("descriptive-only"),
            context=StepRoutingContext(model_inference=ModelInferencePolicy.FORBIDDEN),
        )
    )

    assert decision.status is ExecutionRouteStatus.NO_VALID_ROUTE
    assert decision.primary is None
    assert decision.excluded[0].kind is ExecutionCandidateKind.CAPABILITY
    assert decision.excluded[0].executable is False
    assert decision.reasons == (EligibilityCode.NOT_EXECUTABLE,)


def test_no_llm_forbidden_keeps_real_tool_route_and_does_not_select_model() -> None:
    decision = selector().route(requirements(model_inference=ModelInferencePolicy.FORBIDDEN))

    assert decision.primary is not None
    assert decision.primary.kind is ExecutionCandidateKind.TOOL
    assert all(item.kind is not ExecutionCandidateKind.MODEL for item in decision.eligible)


def test_no_llm_forbidden_without_real_route_is_explicit_no_route() -> None:
    decision = selector().route(
        StepRequirements.from_step(
            step("missing-capability"),
            context=StepRoutingContext(model_inference=ModelInferencePolicy.FORBIDDEN),
        )
    )

    assert decision.status is ExecutionRouteStatus.NO_VALID_ROUTE
    assert decision.primary is None
    assert EligibilityCode.NOT_EXECUTABLE in decision.reasons


def test_model_candidates_reuse_provider_router_and_preserve_privacy_hard_gate() -> None:
    decision = selector().route(
        StepRequirements.from_step(
            step(),
            context=StepRoutingContext(
                model_inference=ModelInferencePolicy.REQUIRED,
                privacy_context=PrivacyContext(PrivacyClassification.SECRET),
            ),
        )
    )

    assert decision.status is ExecutionRouteStatus.NO_VALID_ROUTE
    assert decision.primary is None
    assert decision.excluded[0].kind is ExecutionCandidateKind.MODEL
    assert decision.reasons == (EligibilityCode.MODEL_ROUTE_UNAVAILABLE,)


def test_tool_hard_eligibility_precedes_any_future_optimization() -> None:
    decision = selector().route(
        StepRequirements.from_step(
            step("not-a-registered-tool"),
            context=StepRoutingContext(model_inference=ModelInferencePolicy.FORBIDDEN),
        )
    )

    assert decision.primary is None
    assert decision.status is ExecutionRouteStatus.NO_VALID_ROUTE
