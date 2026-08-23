from __future__ import annotations

import asyncio
from collections.abc import AsyncIterator
from uuid import uuid4

import pytest
from jarvis.agent_runtime import (
    AgentContext,
    AgentLoop,
    AgentLoopBudget,
    AgentMessage,
    AgentOperation,
    AgentRetryClass,
    AgentTerminationReason,
    ContextManager,
    LoopGuard,
    classify_retry,
)
from jarvis.ai.models import (
    GenerationChunk,
    GenerationRequest,
    GenerationResult,
    MessageRole,
    ModelInfo,
    ProviderHealth,
)
from jarvis.ai.providers.base import AIProvider
from jarvis.tools.calculator import CalculatorTool
from jarvis.tools.local_time import LocalTimeTool
from jarvis.tools.registry import ToolRegistry


class SequenceProvider(AIProvider):
    def __init__(self, responses: tuple[str, ...], *, delay: float = 0) -> None:
        self.responses = list(responses)
        self.delay = delay
        self.requests: list[GenerationRequest] = []

    async def generate(self, request: GenerationRequest) -> GenerationResult:
        self.requests.append(request)
        if self.delay:
            await asyncio.sleep(self.delay)
        return GenerationResult(self.responses.pop(0), model="fake")

    async def stream(self, request: GenerationRequest) -> AsyncIterator[GenerationChunk]:
        yield GenerationChunk((await self.generate(request)).content, done=True)

    async def health_check(self) -> ProviderHealth:
        return ProviderHealth(True, "fake")

    async def model_info(self) -> ModelInfo:
        return ModelInfo("fake", "fake", 4096)

    async def aclose(self) -> None:
        return None


class ContextErrorProvider(SequenceProvider):
    def __init__(self) -> None:
        super().__init__((' {"kind":"response","content":"recovered"}',))
        self.failed = False

    async def generate(self, request: GenerationRequest) -> GenerationResult:
        self.requests.append(request)
        if not self.failed:
            self.failed = True
            raise ValueError("context length exceeded")
        return GenerationResult(self.responses.pop(0).strip(), model="fake")


def _loop(provider: AIProvider) -> AgentLoop:
    return AgentLoop(
        provider,
        ToolRegistry((CalculatorTool(), LocalTimeTool())),
        model="fake",
        context_limit=4096,
    )


@pytest.mark.asyncio
async def test_direct_response_is_proposed_not_self_certified() -> None:
    result = await _loop(SequenceProvider(('{"kind":"response","content":"done"}',))).run(
        uuid4(), "calculate"
    )
    assert result.termination_reason is AgentTerminationReason.COMPLETED
    assert result.proposed_result == "done"
    assert result.effects == ()
    assert AgentOperation.FINALIZATION in result.turns[0].operations


@pytest.mark.asyncio
async def test_single_and_multiple_tools_are_validated_and_returned_to_next_inference() -> None:
    tool_call = (
        '{"kind":"tool_calls","calls":['
        '{"request_id":"00000000-0000-0000-0000-000000000001",'
        '"tool_id":"calculator","arguments":{"expression":"2 + 2"}},'
        '{"request_id":"00000000-0000-0000-0000-000000000002",'
        '"tool_id":"local_time","arguments":{}}]}'
    )
    provider = SequenceProvider((tool_call, '{"kind":"response","content":"finished"}'))
    result = await _loop(provider).run(uuid4(), "use tools")
    assert result.termination_reason is AgentTerminationReason.COMPLETED
    assert len(result.effects) == 2
    assert len(provider.requests) == 2
    assert result.effects[0].output_json is not None


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "response, reason",
    [
        ("not json", AgentTerminationReason.MALFORMED_OUTPUT),
        (
            '{"kind":"tool_call","request_id":"bad","tool_id":"calculator","arguments":{}}',
            AgentTerminationReason.MALFORMED_OUTPUT,
        ),
        (
            '{"kind":"tool_call","request_id":"00000000-0000-0000-0000-000000000001","tool_id":"missing","arguments":{}}',
            AgentTerminationReason.UNKNOWN_TOOL,
        ),
    ],
)
async def test_malformed_and_unknown_tool_output_fails_closed(
    response: str, reason: AgentTerminationReason
) -> None:
    result = await _loop(SequenceProvider((response,))).run(uuid4(), "use a tool")
    assert result.termination_reason is reason


@pytest.mark.asyncio
async def test_tool_validation_failure_does_not_become_success() -> None:
    response = (
        '{"kind":"tool_call","request_id":"00000000-0000-0000-0000-000000000001",'
        '"tool_id":"calculator","arguments":{"wrong":true}}'
    )
    result = await _loop(SequenceProvider((response,))).run(uuid4(), "bad input")
    assert result.termination_reason is AgentTerminationReason.TOOL_FAILURE
    assert result.effects[0].status.value == "validation_error"


@pytest.mark.asyncio
async def test_provider_failure_timeout_cancel_and_turn_exhaustion_are_bounded() -> None:
    provider_failure = await _loop(SequenceProvider(())).run(uuid4(), "provider")
    assert provider_failure.termination_reason is AgentTerminationReason.PROVIDER_FAILURE

    timeout = await _loop(SequenceProvider(("x",), delay=0.2)).run(
        uuid4(), "slow", budget=AgentLoopBudget(max_wall_time_seconds=0.01)
    )
    assert timeout.termination_reason is AgentTerminationReason.TIMEOUT

    cancellation = asyncio.Event()
    provider = SequenceProvider(("x",), delay=0.2)
    pending = asyncio.create_task(_loop(provider).run(uuid4(), "cancel", cancellation=cancellation))
    await asyncio.sleep(0.01)
    cancellation.set()
    assert (await pending).termination_reason is AgentTerminationReason.CANCELLED

    turns = await _loop(SequenceProvider(('{"kind":"tool_calls","calls":[]}',))).run(
        uuid4(), "turns", budget=AgentLoopBudget(max_turns=1)
    )
    assert turns.termination_reason is AgentTerminationReason.MALFORMED_OUTPUT


@pytest.mark.asyncio
async def test_turn_exhaustion_after_repeated_tool_requests() -> None:
    response = (
        '{"kind":"tool_call","request_id":"00000000-0000-0000-0000-000000000001",'
        '"tool_id":"calculator","arguments":{"expression":"1 + 1"}}'
    )
    result = await _loop(SequenceProvider((response, response))).run(
        uuid4(), "repeat", budget=AgentLoopBudget(max_turns=2)
    )
    assert result.termination_reason is AgentTerminationReason.TURN_EXHAUSTED


def test_context_manager_preserves_protected_context_and_compacts_old_pairs() -> None:
    context = AgentContext(
        request="request",
        goal="goal",
        constraints=("never claim external success",),
        current_step="step-1",
        selected_memory=("memory",),
        required_knowledge=("knowledge",),
        evidence=("durable-evidence",),
        tool_outputs=("tool-output",),
        security_context=(("authority", "trusted"),),
        provider_context_limit=256,
        reserved_output=32,
        provenance=("application",),
    )
    manager = ContextManager()
    messages = tuple(
        [
            AgentMessage(MessageRole.USER, "request"),
            AgentMessage(MessageRole.ASSISTANT, "tool call"),
        ]
        + [AgentMessage(MessageRole.USER, "old output " * 30) for _ in range(8)]
    )
    request = manager.prepare(
        context, messages, conversation_id=uuid4(), model="fake", context_limit=256
    )
    assert '"goal":"goal"' in request.messages[0].content
    assert "durable-evidence" in request.messages[0].content
    assert any("compacted prior tool exchanges" in item.content for item in request.messages)


@pytest.mark.asyncio
async def test_context_error_recovers_once_with_bounded_retry() -> None:
    provider = ContextErrorProvider()
    result = await _loop(provider).run(uuid4(), "recover")
    assert result.termination_reason is AgentTerminationReason.COMPLETED
    assert len(provider.requests) == 2


@pytest.mark.asyncio
async def test_loop_guard_detects_repeated_semantic_no_progress() -> None:
    response = (
        '{"kind":"tool_call","request_id":"00000000-0000-0000-0000-000000000001",'
        '"tool_id":"calculator","arguments":{"expression":"1 + 1"}}'
    )
    result = await _loop(SequenceProvider((response, response, response, response))).run(
        uuid4(), "repeat", budget=AgentLoopBudget(max_turns=8)
    )
    assert result.termination_reason is AgentTerminationReason.LOOP_GUARD


def test_retry_classification_never_replays_unknown_effect() -> None:
    assert classify_retry(malformed_response=True) is AgentRetryClass.MALFORMED_RESPONSE
    assert classify_retry(cancelled=True) is AgentRetryClass.CANCEL
    assert classify_retry(provider_error=TimeoutError()) is AgentRetryClass.PROVIDER_TRANSIENT
    assert LoopGuard().observe_progress("same response") is False
