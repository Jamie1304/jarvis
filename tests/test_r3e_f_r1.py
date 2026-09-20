"""Direct production-boundary proofs for R3E-F worker context closure."""

from __future__ import annotations

import asyncio
import json
from collections.abc import Iterable
from dataclasses import replace
from uuid import UUID, uuid4

import pytest
from jarvis.agent_runtime import (
    AgentContext,
    AgenticPlanningStepExecutor,
    AgentLoop,
    AgentMessage,
    ContextManager,
)
from jarvis.ai.models import GenerationRequest, PrivacyClassification, PrivacyContext
from jarvis.ai.providers import ProviderLocality, ProviderMetadata
from jarvis.context_projection import WorkerContextEnvelope
from jarvis.planning.graph import DependencyResolutionError, TaskGraphView
from jarvis.planning.models import DependencyBinding, PlanningStepStatus, StepResult
from jarvis.tools.registry import ToolRegistry

from tests.fakes import FakeAIProvider
from tests.test_r3e_f import _plan_and_task


class _RecordingContextManager(ContextManager):
    def __init__(self) -> None:
        self.calls = 0

    def prepare(
        self,
        context: AgentContext,
        messages: Iterable[AgentMessage],
        *,
        conversation_id: UUID,
        model: str,
        context_limit: int,
    ) -> GenerationRequest:
        self.calls += 1
        return super().prepare(
            context,
            messages,
            conversation_id=conversation_id,
            model=model,
            context_limit=context_limit,
        )


@pytest.mark.asyncio
async def test_real_worker_provider_request_is_least_context_and_uses_context_manager() -> None:
    provider = FakeAIProvider(('{"kind":"response","content":"worker complete"}',))
    manager = _RecordingContextManager()
    loop = AgentLoop(
        provider,
        ToolRegistry(()),
        model="local-model",
        context_limit=1024,
        context_manager=manager,
        provider_metadata=ProviderMetadata(
            "local", "Local", "test", locality=ProviderLocality.LOCAL
        ),
    )
    adapter = AgenticPlanningStepExecutor(
        loop,
        privacy_context=PrivacyContext(
            PrivacyClassification.LOCAL_ONLY,
            known_private_values=("AUTHORITY_SECRET_SENTINEL",),
        ),
    )
    _, task, plan = _plan_and_task()
    step = replace(
        plan.steps[0],
        input_json=json.dumps({"value": "VALID_STEP_INPUT_SENTINEL"}),
    )

    result = await adapter.execute(task, step, asyncio.Event())

    assert result.status.value == "succeeded"
    assert manager.calls == 1
    serialized = "\n".join(message.content for message in provider.requests[0].messages)
    assert "VALID_STEP_INPUT_SENTINEL" in serialized
    for sentinel in (
        "CONVERSATION_SECRET_SENTINEL",
        "MEMORY_SECRET_SENTINEL",
        "OTHER_GOAL_SECRET_SENTINEL",
        "AUTHORITY_SECRET_SENTINEL",
        "AUTHORITY_ID_SENTINEL",
    ):
        assert sentinel not in serialized
    assert provider.requests[0].privacy_context.classification is PrivacyClassification.LOCAL_ONLY
    assert '"relevant_conversation": []' not in serialized


def test_worker_envelope_adapter_preserves_exact_step_scope_without_authority_metadata() -> None:
    envelope = WorkerContextEnvelope(
        uuid4(),
        uuid4(),
        '{"value":"VALID_STEP_INPUT_SENTINEL"}',
        "prepare",
        verification_expectation=("verified",),
        dependency_outputs=(("bound", "BOUND_RESULT_SENTINEL"),),
        privacy_context=PrivacyContext(PrivacyClassification.LOCAL_ONLY),
    )
    context = envelope.to_agent_context()
    assert context.request == envelope.resolved_input_json
    assert context.relevant_conversation == ()
    assert context.selected_memory == ()
    assert context.security_context == ()
    assert context.privacy_context.classification is PrivacyClassification.LOCAL_ONLY
    assert "BOUND_RESULT_SENTINEL" in context.tool_outputs


def test_only_verified_dependency_result_can_be_resolved_into_dependent_input() -> None:
    goal, task, plan = _plan_and_task()
    predecessor = replace(
        plan.steps[0],
        key="predecessor",
        status=PlanningStepStatus.SUCCEEDED,
        result=StepResult('{"value":"BOUND_RESULT_SENTINEL"}', ("verified",)),
    )
    dependent = replace(
        plan.steps[0],
        step_id=uuid4(),
        key="dependent",
        dependencies=(predecessor.step_id,),
        input_json='{"value":"placeholder"}',
        input_bindings=(DependencyBinding(predecessor.step_id, "value", "value"),),
    )
    bound_plan = replace(plan, steps=(predecessor, dependent))
    resolved = TaskGraphView(bound_plan).resolve_input(dependent)
    assert "BOUND_RESULT_SENTINEL" in resolved
    with pytest.raises(DependencyResolutionError):
        TaskGraphView(
            replace(
                bound_plan,
                steps=(replace(predecessor, status=PlanningStepStatus.RUNNING), dependent),
            )
        ).resolve_input(dependent)
    del goal, task
