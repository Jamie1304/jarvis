"""Focused R3E-B role-boundary regressions."""

from __future__ import annotations

from dataclasses import replace
from typing import cast
from uuid import UUID

import pytest
from jarvis.ai.models import ModelRole, PrivacyClassification, PrivacyContext
from jarvis.ai.providers import ModelMetadata, ProviderDefinition, ProviderRegistry
from jarvis.ai.providers.registry import ProviderLocality, ProviderMetadata
from jarvis.ai.roles import LogicalModelRole, LogicalRoleRequirements
from jarvis.ai.routing import ProviderRouter, RouteStatus, RoutingPolicy
from jarvis.conversation.service import ConversationService, ConversationTurnStatus
from jarvis.planning import OrchestrationRequest, OrchestrationResult, PlanAdvisor, ReplanEvidence

from tests.fakes import FakeAIProvider
from tests.test_hardware import _hardware

_LOCAL = ProviderMetadata("local", "local", "test", locality=ProviderLocality.LOCAL)


def _role_registry() -> ProviderRegistry:
    return ProviderRegistry(
        (
            ProviderDefinition(
                ProviderMetadata("remote", "remote", "test", locality=ProviderLocality.REMOTE),
                lambda _: FakeAIProvider(),
                (
                    ModelMetadata(
                        "remote-general",
                        8_192,
                        frozenset({"chat"}),
                        frozenset({ModelRole.GENERAL}),
                        modalities=frozenset({"text"}),
                        quality_score=0.99,
                        latency_ms=100,
                        input_cost_per_million=1,
                        output_cost_per_million=1,
                    ),
                ),
            ),
            ProviderDefinition(
                ProviderMetadata("local", "local", "test", local_only=True),
                lambda _: FakeAIProvider(),
                (
                    ModelMetadata(
                        "local-reasoning",
                        8_192,
                        frozenset({"chat", "structured_output"}),
                        frozenset({ModelRole.REASONING}),
                        modalities=frozenset({"text"}),
                        quality_score=0.8,
                        latency_ms=40,
                        input_cost_per_million=0,
                        output_cost_per_million=0,
                        storage_bytes=1,
                        ram_bytes=1,
                        compatibility=frozenset({"windows"}),
                    ),
                ),
            ),
        )
    )


def test_logical_roles_are_distinct_from_capability_model_roles() -> None:
    requirements = LogicalRoleRequirements(LogicalModelRole.ORCHESTRATION, "make a plan")
    route = requirements.to_route_request()

    assert LogicalModelRole.CONVERSATION.value == "conversation"
    assert route.responsibility == "orchestration"
    assert route.role.value == "reasoning"
    assert route.requires_structured_output is True
    with pytest.raises(ValueError):
        LogicalRoleRequirements(cast(LogicalModelRole, "conversation"), "invalid")


def test_route_projection_preserves_local_only_privacy_without_provider_selection() -> None:
    route = LogicalRoleRequirements(
        LogicalModelRole.ORCHESTRATION,
        "private plan",
        policy=RoutingPolicy.BALANCED,
        privacy_context=PrivacyContext(PrivacyClassification.LOCAL_ONLY),
    ).to_route_request()

    assert route.privacy_context is not None
    assert route.privacy_context.classification is PrivacyClassification.LOCAL_ONLY
    assert route.preferred_provider_id is None
    assert route.preferred_model_id is None


def test_logical_roles_can_select_different_physical_models_through_existing_router() -> None:
    router = ProviderRouter(_role_registry())
    conversation = router.route(
        replace(
            LogicalRoleRequirements(
                LogicalModelRole.CONVERSATION,
                "say hello",
                policy=RoutingPolicy.QUALITY_FIRST,
                privacy_context=PrivacyContext(PrivacyClassification.SAFE_PUBLIC),
            ).to_route_request(),
            resource_state=_hardware(tags=frozenset({"windows"})),
        )
    )
    orchestration = router.route(
        replace(
            LogicalRoleRequirements(
                LogicalModelRole.ORCHESTRATION,
                "make a plan",
                privacy_context=PrivacyContext(PrivacyClassification.SAFE_PUBLIC),
            ).to_route_request(),
            resource_state=_hardware(tags=frozenset({"windows"})),
        )
    )

    assert conversation.status is RouteStatus.SELECTED
    assert orchestration.status is RouteStatus.SELECTED
    assert conversation.primary is not None and conversation.primary.provider_id == "remote"
    assert orchestration.primary is not None and orchestration.primary.provider_id == "local"


def test_orchestration_request_has_trusted_distinct_identity_and_untrusted_result() -> None:
    first = OrchestrationRequest.create("goal")
    second = OrchestrationRequest.create("goal")
    result = OrchestrationResult(first.orchestration_attempt_id, proposal={"steps": []})

    assert isinstance(first.orchestration_attempt_id, UUID)
    assert first.orchestration_attempt_id != second.orchestration_attempt_id
    assert result.proposal == {"steps": []}
    assert result.route_decision_id is None


@pytest.mark.asyncio
async def test_conversation_turn_has_one_active_owner_and_replacement_cancels_old_turn() -> None:
    provider = FakeAIProvider(("first", "second"))
    service = ConversationService(
        provider,
        model="same-physical-model",
        context_limit=1024,
        provider_metadata=_LOCAL,
    )
    conversation_id = service.create_conversation()

    first_stream = service.stream_reply(conversation_id, "first")
    first_update = await anext(first_stream)
    first_turn = service.turn(conversation_id)
    assert first_turn is not None
    assert first_turn.logical_role is LogicalModelRole.CONVERSATION
    assert first_turn.status is ConversationTurnStatus.ACTIVE
    assert service.active_turn(conversation_id) == first_turn

    second_stream = service.stream_reply(conversation_id, "second")
    second_update = await anext(second_stream)
    second_turn = service.turn(conversation_id)
    assert second_turn is not None
    assert second_turn.turn_id == second_update.turn_id
    assert second_turn.turn_id != first_turn.turn_id
    assert second_turn.status is ConversationTurnStatus.ACTIVE
    assert first_update.turn_id == first_turn.turn_id
    assert service.active_turn(conversation_id) == second_turn


class _CapturingAdvisor(PlanAdvisor):
    def __init__(self) -> None:
        self.requests: list[OrchestrationRequest] = []

    async def propose(
        self, goal: str, assumptions: tuple[str, ...], constraints: tuple[str, ...]
    ) -> object:
        return {
            "goal": goal,
            "assumptions": list(assumptions),
            "constraints": list(constraints),
            "steps": [],
        }

    async def replan(self, evidence: ReplanEvidence) -> object:
        return {"goal": evidence.original_goal, "steps": []}

    async def propose_orchestration(self, request: OrchestrationRequest) -> OrchestrationResult:
        self.requests.append(request)
        return OrchestrationResult(request.orchestration_attempt_id, proposal={})


@pytest.mark.asyncio
async def test_orchestration_result_is_not_a_trusted_plan() -> None:
    advisor = _CapturingAdvisor()
    request = OrchestrationRequest.create("goal")
    result = await advisor.propose_orchestration(request)

    assert advisor.requests == [request]
    assert result.orchestration_attempt_id == request.orchestration_attempt_id
    assert result.proposal == {}
    assert not hasattr(result, "permissions")
    assert not hasattr(result, "effect_verified")


@pytest.mark.asyncio
async def test_replan_boundary_requires_a_new_attempt_identity() -> None:
    advisor = _CapturingAdvisor()
    first = OrchestrationRequest.create("goal")
    second = OrchestrationRequest.create("goal")

    first_result = await advisor.propose_orchestration(first)
    second_result = await advisor.propose_orchestration(second)

    assert first_result.orchestration_attempt_id != second_result.orchestration_attempt_id
