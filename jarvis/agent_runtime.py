"""Native, bounded agentic inference loop.

This module is deliberately not a task store or a second orchestrator. The
PlanningEngine owns durable task state; this loop owns one bounded inference
segment and routes every effect through the trusted ToolRegistry.
"""

from __future__ import annotations

import asyncio
import hashlib
import json
import logging
from collections.abc import Iterable
from dataclasses import dataclass, field
from datetime import UTC, datetime
from enum import StrEnum
from typing import Any
from uuid import UUID, uuid4

from jarvis.ai.models import ChatMessage, GenerationRequest, MessageRole
from jarvis.ai.providers.base import AIProvider
from jarvis.planning.models import (
    PlanningStep,
    PlanningTask,
    StepExecutionResult,
    StepExecutionStatus,
)
from jarvis.skills import (
    PrimedSkillContext,
    SkillClassification,
    SkillContextSources,
    SkillManifest,
    prime_skill_context,
)
from jarvis.tools.models import (
    ToolCaller,
    ToolEffectDisposition,
    ToolExecutionContext,
    ToolResultStatus,
)
from jarvis.tools.registry import ToolRegistry


class AgentOperation(StrEnum):
    CONTEXT_PREPARATION = "context_preparation"
    INFERENCE = "inference"
    UNKNOWN_TOOL = "unknown_tool"
    APPROVAL_PAUSE = "approval_pause"
    TOOL_EXECUTION = "tool_execution"
    RETRY = "retry"
    FINALIZATION = "finalization"


class AgentTerminationReason(StrEnum):
    COMPLETED = "completed"
    UNKNOWN_TOOL = "unknown_tool"
    MALFORMED_OUTPUT = "malformed_output"
    TOOL_FAILURE = "tool_failure"
    APPROVAL_PAUSED = "approval_paused"
    TIMEOUT = "timeout"
    CANCELLED = "cancelled"
    TURN_EXHAUSTED = "turn_exhausted"
    TOOL_CALL_EXHAUSTED = "tool_call_exhausted"
    TOKEN_EXHAUSTED = "token_exhausted"
    PROVIDER_FAILURE = "provider_failure"
    LOOP_GUARD = "loop_guard"


class AgentRetryClass(StrEnum):
    PROVIDER_TRANSIENT = "provider_transient"
    RATE_LIMIT = "rate_limit"
    MALFORMED_RESPONSE = "malformed_response"
    DETERMINISTIC_TOOL_FAILURE = "deterministic_tool_failure"
    SAFE_TRANSIENT = "safe_transient"
    UNKNOWN_OUTCOME = "unknown_outcome"
    CANCEL = "cancel"


class AgentEffectOutcome(StrEnum):
    """Runtime-local effect classification at the external-effect boundary."""

    PRE_EFFECT_FAILURE = "pre_effect_failure"
    SAFE_TO_RETRY = "safe_to_retry"
    EFFECT_CONFIRMED = "effect_confirmed"
    UNKNOWN_OUTCOME = "unknown_outcome"


@dataclass(frozen=True, slots=True)
class AgentContext:
    """Validated context supplied to one bounded agent segment.

    Security context is an immutable tuple because model-visible context must
    never be able to mutate the trusted authority object held by application
    code. Evidence is descriptive only; it does not grant permission.
    """

    request: str
    goal: str
    constraints: tuple[str, ...] = ()
    current_step: str = ""
    relevant_conversation: tuple[AgentMessage, ...] = ()
    selected_memory: tuple[str, ...] = ()
    required_knowledge: tuple[str, ...] = ()
    evidence: tuple[str, ...] = ()
    tool_outputs: tuple[str, ...] = ()
    security_context: tuple[tuple[str, str], ...] = ()
    token_estimate: int = 0
    provider_context_limit: int = 4096
    reserved_output: int = 1024
    priority: int = 0
    provenance: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        for name in ("request", "goal"):
            value = getattr(self, name)
            if not isinstance(value, str) or not value.strip() or len(value) > 16_000:
                raise ValueError(f"Agent context {name} is malformed or unbounded")
        if self.provider_context_limit <= 0 or self.reserved_output < 0:
            raise ValueError("Agent context limits are invalid")
        if self.token_estimate < 0 or self.priority < 0:
            raise ValueError("Agent context accounting is invalid")
        if self.reserved_output >= self.provider_context_limit:
            raise ValueError("Reserved output must leave context capacity")
        for field_name in (
            "constraints",
            "selected_memory",
            "required_knowledge",
            "evidence",
            "tool_outputs",
            "provenance",
        ):
            values = getattr(self, field_name)
            if len(values) > 128 or any(
                not isinstance(item, str) or len(item) > 16_000 for item in values
            ):
                raise ValueError(f"Agent context {field_name} is malformed or unbounded")
        if any(
            not isinstance(key, str)
            or not key.strip()
            or len(key) > 128
            or not isinstance(value, str)
            or len(value) > 4_000
            for key, value in self.security_context
        ):
            raise ValueError("Agent security context is malformed")


class ContextManager:
    """Build bounded provider context while retaining protected facts."""

    def prime_skill(
        self,
        skill: SkillManifest,
        *,
        workspace_id: str,
        profile_id: str,
        sources: SkillContextSources,
        token_budget: int,
        allowed_classifications: frozenset[SkillClassification],
        privacy_mode: bool = False,
    ) -> PrimedSkillContext:
        """Prime one skill through the same canonical context manager boundary."""

        return prime_skill_context(
            skill,
            workspace_id=workspace_id,
            profile_id=profile_id,
            sources=sources,
            token_budget=token_budget,
            allowed_classifications=allowed_classifications,
            privacy_mode=privacy_mode,
        )

    def prepare(
        self,
        context: AgentContext,
        messages: Iterable[AgentMessage],
        *,
        conversation_id: UUID,
        model: str,
        context_limit: int,
    ) -> GenerationRequest:
        if context_limit != context.provider_context_limit:
            raise ValueError("Agent context/provider limits disagree")
        protected = {
            "request": context.request,
            "goal": context.goal,
            "constraints": context.constraints,
            "current_step": context.current_step,
            "selected_memory": context.selected_memory,
            "required_knowledge": context.required_knowledge,
            "evidence": context.evidence,
            "tool_outputs": context.tool_outputs,
            "security_context": context.security_context,
            "completion_criteria": context.constraints,
            "provenance": context.provenance,
        }
        system = AgentMessage(
            MessageRole.SYSTEM,
            json.dumps(protected, sort_keys=True, separators=(",", ":")),
        )
        bounded = self._compact(tuple(messages), context_limit, context.reserved_output)
        return GenerationRequest(
            messages=tuple(
                ChatMessage(
                    item.message_id, conversation_id, item.role, item.content, datetime.now(UTC)
                )
                for item in (system, *bounded)
            ),
            model=model,
            context_limit=context_limit,
        )

    @staticmethod
    def _compact(
        messages: tuple[AgentMessage, ...], context_limit: int, reserved_output: int
    ) -> tuple[AgentMessage, ...]:
        budget = max(256, (context_limit - reserved_output) * 4)
        if sum(len(item.content) for item in messages) <= budget:
            return messages
        # Keep the initial request/system facts and the newest exchanges. Old
        # tool pairs are represented by a digest; durable evidence remains in
        # AgentContext and is never removed by this projection.
        keep: list[AgentMessage] = list(messages[:2])
        tail: list[AgentMessage] = []
        used = sum(len(item.content) for item in keep)
        for item in reversed(messages[2:]):
            if used + len(item.content) > budget - 256:
                break
            tail.append(item)
            used += len(item.content)
        omitted = messages[2 : len(messages) - len(tail)]
        if omitted:
            digest = hashlib.sha256(
                "|".join(item.content for item in omitted).encode("utf-8")
            ).hexdigest()
            keep.append(
                AgentMessage(
                    MessageRole.USER,
                    f"[compacted prior tool exchanges; evidence digest={digest}]",
                )
            )
        return tuple(keep + list(reversed(tail)))


class LoopGuard:
    """Detect bounded semantic repetition without trusting textual variation."""

    def __init__(self, threshold: int = 3) -> None:
        if threshold < 2:
            raise ValueError("Loop guard threshold must be at least two")
        self._threshold = threshold
        self._calls: dict[str, int] = {}
        self._failures: dict[str, int] = {}
        self._progress: dict[str, int] = {}

    def observe_call(self, tool_id: str, arguments: dict[str, Any]) -> bool:
        key = json.dumps([tool_id, arguments], sort_keys=True, separators=(",", ":"))
        self._calls[key] = self._calls.get(key, 0) + 1
        return self._calls[key] >= self._threshold

    def observe_failure(self, effect: AgentEffect) -> bool:
        key = json.dumps(
            [effect.tool_id, effect.status.value, effect.effect_outcome.value, effect.output_json],
            sort_keys=True,
            separators=(",", ":"),
        )
        self._failures[key] = self._failures.get(key, 0) + 1
        return self._failures[key] >= self._threshold

    def observe_progress(self, content: str) -> bool:
        normalized = "".join(character for character in content.lower() if character.isalnum())
        key = hashlib.sha256(normalized.encode("utf-8")).hexdigest()
        self._progress[key] = self._progress.get(key, 0) + 1
        return self._progress[key] >= self._threshold


@dataclass(frozen=True, slots=True)
class AgentMessage:
    role: MessageRole
    content: str
    message_id: UUID = field(default_factory=uuid4)

    def __post_init__(self) -> None:
        if not isinstance(self.role, MessageRole):
            raise ValueError("Agent message role is invalid")
        if (
            not isinstance(self.content, str)
            or not self.content.strip()
            or len(self.content) > 16_000
        ):
            raise ValueError("Agent message content is malformed or unbounded")


@dataclass(frozen=True, slots=True)
class AgentLoopBudget:
    max_turns: int = 8
    max_tool_calls: int = 16
    max_wall_time_seconds: float = 120.0
    max_tokens: int = 16_000
    max_expensive_actions: int = 4
    max_retries: int = 3

    def __post_init__(self) -> None:
        if (
            min(
                self.max_turns,
                self.max_tool_calls,
                self.max_tokens,
                self.max_expensive_actions,
                self.max_retries,
            )
            < 0
            or self.max_wall_time_seconds <= 0
        ):
            raise ValueError("Agent loop budgets must be bounded and non-negative")
        if self.max_turns == 0 or self.max_tokens == 0:
            raise ValueError("Agent loop turns and tokens must be positive")


@dataclass(frozen=True, slots=True)
class AgentUsage:
    turns: int = 0
    tool_calls: int = 0
    tokens: int = 0
    expensive_actions: int = 0
    retries: int = 0


@dataclass(frozen=True, slots=True)
class AgentEffect:
    request_id: UUID
    tool_id: str
    arguments: dict[str, Any]
    status: ToolResultStatus
    output_json: str | None = None
    evidence: tuple[str, ...] = ()
    effect_outcome: AgentEffectOutcome = AgentEffectOutcome.PRE_EFFECT_FAILURE
    approval_request_ids: tuple[UUID, ...] = ()


@dataclass(frozen=True, slots=True)
class AgentTurn:
    number: int
    operations: tuple[AgentOperation, ...]
    assistant_content: str
    effects: tuple[AgentEffect, ...] = ()


@dataclass(frozen=True, slots=True)
class AgentLoopResult:
    termination_reason: AgentTerminationReason
    usage: AgentUsage
    turns: tuple[AgentTurn, ...]
    proposed_result: str | None = None
    effects: tuple[AgentEffect, ...] = ()


class AgentLoop:
    """Run one untrusted model loop under explicit bounds."""

    def __init__(
        self,
        provider: AIProvider,
        registry: ToolRegistry,
        *,
        model: str,
        context_limit: int,
        logger: logging.Logger | None = None,
        context_manager: ContextManager | None = None,
    ) -> None:
        if context_limit <= 0:
            raise ValueError("Agent context limit must be positive")
        self._provider = provider
        self._registry = registry
        self._model = model
        self._context_limit = context_limit
        self._logger = logger or logging.getLogger("jarvis.agent_runtime")
        self._context_manager = context_manager or ContextManager()

    async def run(
        self,
        task_id: UUID,
        prompt: str,
        *,
        budget: AgentLoopBudget | None = None,
        cancellation: asyncio.Event | None = None,
        system_prompt: str | None = None,
        context: AgentContext | None = None,
    ) -> AgentLoopResult:
        if not prompt.strip() or len(prompt) > 4_000:
            raise ValueError("Agent prompt is malformed or unbounded")
        budget = budget or AgentLoopBudget()
        cancellation = cancellation or asyncio.Event()
        agent_context = context or AgentContext(
            request=prompt,
            goal=prompt,
            provider_context_limit=self._context_limit,
        )
        if agent_context.request != prompt:
            raise ValueError("Agent context request must match the submitted prompt")
        messages: list[AgentMessage] = []
        if system_prompt is not None:
            messages.append(AgentMessage(MessageRole.SYSTEM, system_prompt))
        messages.append(AgentMessage(MessageRole.USER, prompt))
        turns: list[AgentTurn] = []
        effects: list[AgentEffect] = []
        usage = AgentUsage()
        context_recovery_used = False
        loop_guard = LoopGuard()
        try:
            async with asyncio.timeout(budget.max_wall_time_seconds):
                for turn_number in range(1, budget.max_turns + 1):
                    if cancellation.is_set():
                        return self._result(AgentTerminationReason.CANCELLED, usage, turns, effects)
                    request = self._context_manager.prepare(
                        agent_context,
                        messages,
                        conversation_id=task_id,
                        model=self._model,
                        context_limit=self._context_limit,
                    )
                    operations = [AgentOperation.CONTEXT_PREPARATION, AgentOperation.INFERENCE]
                    try:
                        raw = await _await_cancellable(
                            self._provider.generate(request), cancellation
                        )
                    except Exception as exc:
                        if not context_recovery_used and _is_context_error(exc):
                            context_recovery_used = True
                            messages.append(
                                AgentMessage(
                                    MessageRole.USER,
                                    "[context error; prior tool pairs compacted; retry once]",
                                )
                            )
                            continue
                        raise
                    usage = AgentUsage(
                        turns=usage.turns + 1,
                        tool_calls=usage.tool_calls,
                        tokens=usage.tokens + _estimate_tokens(raw.content),
                        expensive_actions=usage.expensive_actions,
                        retries=usage.retries,
                    )
                    if usage.tokens > budget.max_tokens:
                        return self._result(
                            AgentTerminationReason.TOKEN_EXHAUSTED, usage, turns, effects
                        )
                    parsed = _parse_model_output(raw.content)
                    if parsed[0] == "response":
                        operations.append(AgentOperation.FINALIZATION)
                        turns.append(AgentTurn(turn_number, tuple(operations), parsed[1]))
                        return self._result(
                            AgentTerminationReason.COMPLETED,
                            usage,
                            turns,
                            effects,
                            proposed_result=parsed[1],
                        )
                    if parsed[0] == "malformed":
                        return self._result(
                            AgentTerminationReason.MALFORMED_OUTPUT, usage, turns, effects
                        )
                    calls = parsed[1]
                    if loop_guard.observe_progress(raw.content):
                        return self._result(
                            AgentTerminationReason.LOOP_GUARD, usage, turns, effects
                        )
                    if usage.tool_calls + len(calls) > budget.max_tool_calls:
                        return self._result(
                            AgentTerminationReason.TOOL_CALL_EXHAUSTED, usage, turns, effects
                        )
                    turn_effects: list[AgentEffect] = []
                    for call in calls:
                        if loop_guard.observe_call(call["tool_id"], call["arguments"]):
                            return self._result(
                                AgentTerminationReason.LOOP_GUARD, usage, turns, effects
                            )
                        try:
                            candidate = self._registry.inspect(call["tool_id"])
                        except Exception:
                            candidate = None
                        if (
                            candidate is not None
                            and candidate.manifest.declared_permissions
                            and usage.expensive_actions >= budget.max_expensive_actions
                        ):
                            return self._result(
                                AgentTerminationReason.TOOL_CALL_EXHAUSTED,
                                usage,
                                turns,
                                effects,
                            )
                        effect, reason = await self._execute_call(
                            task_id, call, cancellation, usage, budget
                        )
                        try:
                            record = self._registry.inspect(effect.tool_id)
                            expensive = bool(record.manifest.declared_permissions)
                        except Exception:
                            expensive = False
                        usage = AgentUsage(
                            turns=usage.turns,
                            tool_calls=usage.tool_calls + 1,
                            tokens=usage.tokens,
                            expensive_actions=usage.expensive_actions + int(expensive),
                            retries=usage.retries,
                        )
                        turn_effects.append(effect)
                        effects.append(effect)
                        if loop_guard.observe_failure(effect):
                            return self._result(
                                AgentTerminationReason.LOOP_GUARD, usage, turns, effects
                            )
                        if reason is not None:
                            if (
                                reason is AgentTerminationReason.TOOL_FAILURE
                                and effect.effect_outcome
                                in {
                                    AgentEffectOutcome.PRE_EFFECT_FAILURE,
                                    AgentEffectOutcome.SAFE_TO_RETRY,
                                }
                                and usage.retries < budget.max_retries
                            ):
                                usage = AgentUsage(
                                    turns=usage.turns,
                                    tool_calls=usage.tool_calls,
                                    tokens=usage.tokens,
                                    expensive_actions=usage.expensive_actions,
                                    retries=usage.retries + 1,
                                )
                                operations.append(AgentOperation.RETRY)
                                messages.append(AgentMessage(MessageRole.ASSISTANT, raw.content))
                                messages.append(
                                    AgentMessage(
                                        MessageRole.USER,
                                        json.dumps(
                                            {
                                                "tool_request_id": str(effect.request_id),
                                                "tool_id": effect.tool_id,
                                                "status": effect.status.value,
                                                "output": effect.output_json,
                                                "evidence": list(effect.evidence),
                                            },
                                            sort_keys=True,
                                        ),
                                    )
                                )
                                continue
                            operations.append(
                                AgentOperation.APPROVAL_PAUSE
                                if reason is AgentTerminationReason.APPROVAL_PAUSED
                                else AgentOperation.UNKNOWN_TOOL
                                if reason is AgentTerminationReason.UNKNOWN_TOOL
                                else AgentOperation.TOOL_EXECUTION
                            )
                            turns.append(
                                AgentTurn(
                                    turn_number,
                                    tuple(operations),
                                    raw.content,
                                    tuple(turn_effects),
                                )
                            )
                            return self._result(reason, usage, turns, effects)
                        operations.append(AgentOperation.TOOL_EXECUTION)
                        messages.append(AgentMessage(MessageRole.ASSISTANT, raw.content))
                        messages.append(
                            AgentMessage(
                                MessageRole.USER,
                                json.dumps(
                                    {
                                        "tool_request_id": str(effect.request_id),
                                        "tool_id": effect.tool_id,
                                        "status": effect.status.value,
                                        "output": effect.output_json,
                                        "evidence": list(effect.evidence),
                                    },
                                    sort_keys=True,
                                ),
                            )
                        )
                    turns.append(
                        AgentTurn(
                            turn_number,
                            tuple(operations),
                            raw.content,
                            tuple(turn_effects),
                        )
                    )
                return self._result(AgentTerminationReason.TURN_EXHAUSTED, usage, turns, effects)
        except TimeoutError:
            return self._result(AgentTerminationReason.TIMEOUT, usage, turns, effects)
        except asyncio.CancelledError:
            return self._result(AgentTerminationReason.CANCELLED, usage, turns, effects)
        except Exception:
            self._logger.error("Agent provider failed; provider details withheld")
            return self._result(AgentTerminationReason.PROVIDER_FAILURE, usage, turns, effects)

    async def _execute_call(
        self,
        task_id: UUID,
        call: dict[str, Any],
        cancellation: asyncio.Event,
        usage: AgentUsage,
        budget: AgentLoopBudget,
    ) -> tuple[AgentEffect, AgentTerminationReason | None]:
        request_id = UUID(call["request_id"])
        tool_id = call["tool_id"]
        arguments = call["arguments"]
        try:
            tool = self._registry.get(tool_id)
        except Exception:
            return (
                AgentEffect(request_id, tool_id, arguments, ToolResultStatus.VALIDATION_ERROR),
                AgentTerminationReason.UNKNOWN_TOOL,
            )
        context = ToolExecutionContext(
            task_id=task_id,
            correlation_id=task_id,
            caller=ToolCaller.AGENT,
            cancellation=cancellation,
            logger=self._logger,
        )
        result = await tool.invoke(context, arguments, self._registry.permission_broker)
        approvals = tuple(
            UUID(item.value) for item in result.metadata if item.key == "approval_request_id"
        )
        effect_outcome = (
            AgentEffectOutcome.EFFECT_CONFIRMED
            if result.effect_disposition is ToolEffectDisposition.CONFIRMED_EFFECT
            else AgentEffectOutcome.UNKNOWN_OUTCOME
            if result.effect_disposition is ToolEffectDisposition.UNKNOWN
            else AgentEffectOutcome.PRE_EFFECT_FAILURE
        )
        effect = AgentEffect(
            request_id,
            tool_id,
            arguments,
            result.status,
            result.output.model_dump_json() if result.output is not None else None,
            tuple(item.value for item in result.evidence),
            effect_outcome,
            approvals,
        )
        if result.status is ToolResultStatus.PERMISSION_DENIED and approvals:
            return effect, AgentTerminationReason.APPROVAL_PAUSED
        if result.status is ToolResultStatus.UNKNOWN_OUTCOME:
            return effect, AgentTerminationReason.TOOL_FAILURE
        if result.status is not ToolResultStatus.SUCCESS:
            if (
                result.effect_disposition is ToolEffectDisposition.NO_EFFECT
                and usage.retries < budget.max_retries
            ):
                return effect, AgentTerminationReason.TOOL_FAILURE
            return effect, AgentTerminationReason.TOOL_FAILURE
        return effect, None

    @staticmethod
    def _result(
        reason: AgentTerminationReason,
        usage: AgentUsage,
        turns: list[AgentTurn],
        effects: list[AgentEffect],
        *,
        proposed_result: str | None = None,
    ) -> AgentLoopResult:
        return AgentLoopResult(reason, usage, tuple(turns), proposed_result, tuple(effects))


class AgenticPlanningStepExecutor:
    """Adapter seam for a future explicit AGENTIC PlanningStep contract."""

    def __init__(self, loop: AgentLoop) -> None:
        self._loop = loop

    async def execute(
        self, task: PlanningTask, step: PlanningStep, cancellation: asyncio.Event
    ) -> StepExecutionResult:
        result = await self._loop.run(
            task.task_id,
            task.goal,
            cancellation=cancellation,
        )
        if result.termination_reason is AgentTerminationReason.APPROVAL_PAUSED:
            return StepExecutionResult(
                StepExecutionStatus.WAITING_FOR_PERMISSION,
                approval_request_ids=tuple(
                    request_id
                    for effect in result.effects
                    for request_id in effect.approval_request_ids
                ),
            )
        if result.termination_reason is AgentTerminationReason.COMPLETED:
            return StepExecutionResult(
                StepExecutionStatus.SUCCEEDED,
                output_json=json.dumps({"proposed_result": result.proposed_result}),
                evidence=("agent_proposed_result",),
            )
        if result.termination_reason is AgentTerminationReason.CANCELLED:
            return StepExecutionResult(StepExecutionStatus.CANCELLED, error_code="agent_cancelled")
        return StepExecutionResult(
            StepExecutionStatus.DETERMINISTIC_FAILURE,
            error_code=result.termination_reason.value,
            error_message="Bounded agent loop did not produce a usable result",
        )


def _parse_model_output(content: str) -> tuple[str, Any]:
    try:
        raw = json.loads(content)
    except (json.JSONDecodeError, TypeError):
        return "malformed", None
    if not isinstance(raw, dict) or not isinstance(raw.get("kind"), str):
        return "malformed", None
    kind = raw.get("kind")
    if kind == "response" and isinstance(raw.get("content"), str) and raw["content"].strip():
        if set(raw) - {"kind", "content"}:
            return "malformed", None
        return "response", raw["content"]
    if kind in {"tool_call", "tool_calls"}:
        if kind == "tool_calls" and set(raw) - {"kind", "calls"}:
            return "malformed", None
        if kind == "tool_call" and set(raw) - {
            "kind",
            "request_id",
            "tool_id",
            "arguments",
        }:
            return "malformed", None
        calls = raw.get("calls") if kind == "tool_calls" else [raw]
        if not isinstance(calls, list) or not calls or len(calls) > 16:
            return "malformed", None
        validated: list[dict[str, Any]] = []
        for call in calls:
            if not isinstance(call, dict) or set(call) - {
                "kind",
                "request_id",
                "tool_id",
                "arguments",
            }:
                return "malformed", None
            try:
                request_id = UUID(str(call["request_id"]))
            except (KeyError, TypeError, ValueError):
                return "malformed", None
            tool_id = call.get("tool_id")
            arguments = call.get("arguments")
            if not isinstance(tool_id, str) or not tool_id.strip() or len(tool_id) > 128:
                return "malformed", None
            if not isinstance(arguments, dict) or len(arguments) > 64:
                return "malformed", None
            validated.append(
                {"request_id": str(request_id), "tool_id": tool_id, "arguments": arguments}
            )
        return "calls", validated
    return "malformed", None


def _estimate_tokens(content: str) -> int:
    return max(1, (len(content) + 3) // 4)


def classify_retry(
    *,
    effect: AgentEffect | None = None,
    provider_error: BaseException | None = None,
    malformed_response: bool = False,
    cancelled: bool = False,
) -> AgentRetryClass:
    """Classify a failure without ever making an uncertain effect retryable."""
    if cancelled:
        return AgentRetryClass.CANCEL
    if effect is not None:
        if effect.effect_outcome is AgentEffectOutcome.UNKNOWN_OUTCOME:
            return AgentRetryClass.UNKNOWN_OUTCOME
        if effect.effect_outcome is AgentEffectOutcome.SAFE_TO_RETRY:
            return AgentRetryClass.SAFE_TRANSIENT
        return AgentRetryClass.DETERMINISTIC_TOOL_FAILURE
    if malformed_response:
        return AgentRetryClass.MALFORMED_RESPONSE
    if provider_error is not None:
        name = type(provider_error).__name__.lower()
        text = str(provider_error).lower()
        if "rate" in name or "rate" in text or "429" in text:
            return AgentRetryClass.RATE_LIMIT
        if isinstance(provider_error, TimeoutError | ConnectionError | OSError):
            return AgentRetryClass.PROVIDER_TRANSIENT
    return AgentRetryClass.DETERMINISTIC_TOOL_FAILURE


def _is_context_error(error: BaseException) -> bool:
    text = f"{type(error).__name__} {error}".lower()
    return any(
        marker in text
        for marker in (
            "context length",
            "context window",
            "too many tokens",
            "maximum context",
            "prompt is too long",
        )
    )


async def _await_cancellable(awaitable: Any, cancellation: asyncio.Event) -> Any:
    task = asyncio.create_task(awaitable)
    waiter = asyncio.create_task(cancellation.wait())
    try:
        done, _ = await asyncio.wait({task, waiter}, return_when=asyncio.FIRST_COMPLETED)
    except asyncio.CancelledError:
        task.cancel()
        waiter.cancel()
        await asyncio.gather(task, waiter, return_exceptions=True)
        raise
    if waiter in done and cancellation.is_set():
        task.cancel()
        await asyncio.gather(task, return_exceptions=True)
        waiter.cancel()
        raise asyncio.CancelledError
    waiter.cancel()
    await asyncio.gather(waiter, return_exceptions=True)
    return await task
