"""Deterministic interruption classification over trusted semantic observations.

This module decides attention importance and records factual provenance. It does
not authorize actions, deliver notifications, or infer user emotion or intent.
"""

from __future__ import annotations

from collections import deque
from collections.abc import Callable
from dataclasses import dataclass
from enum import StrEnum
from typing import Final
from uuid import NAMESPACE_URL, UUID, uuid5

from jarvis.attention import (
    AttentionDecision,
    AttentionDeliveryState,
    AttentionItem,
    AttentionPolicy,
    AttentionPriority,
    InterruptionClass,
    InterruptionContext,
)
from jarvis.current_context import CurrentContextSnapshot
from jarvis.events.semantic import (
    PatternKind,
    SemanticEvent,
    SemanticEventService,
    SemanticKind,
    SemanticPattern,
)
from jarvis.trace import TraceEventType, TraceService

RULE_VERSION: Final[str] = "v1"
_ATTENTION_NAMESPACE: Final[UUID] = uuid5(NAMESPACE_URL, "jarvis/interruption-attention")
_TRACE_NAMESPACE: Final[UUID] = uuid5(NAMESPACE_URL, "jarvis/interruption-trace")


class InterruptionReason(StrEnum):
    TASK_WAITING_FOR_USER = "task_waiting_for_user"
    REPEATED_EXECUTION_FAILURE = "repeated_execution_failure"
    RUNTIME_DEGRADED = "runtime_degraded"
    RUNTIME_RECOVERED = "runtime_recovered"
    SECURITY_BOUNDARY_VIOLATION = "security_boundary_violation"
    CAPABILITY_AVAILABLE = "capability_available"
    CAPABILITY_UNAVAILABLE = "capability_unavailable"
    EXECUTION_SUCCEEDED = "execution_succeeded"
    EXECUTION_FAILURE_OBSERVED = "execution_failure_observed"
    PERMISSION_OBSERVED = "permission_observed"
    UNKNOWN_OUTCOME = "unknown_outcome"
    CONTEXT_REEVALUATION = "context_reevaluation"


@dataclass(frozen=True, slots=True)
class InterruptionDecision:
    """The classifier result before the existing AttentionPolicy evaluates it."""

    interruption_class: InterruptionClass
    reason_code: InterruptionReason
    priority: AttentionPriority
    rule_version: str = RULE_VERSION


@dataclass(frozen=True, slots=True)
class InterruptionResult:
    source_semantic_event_id: UUID | None
    source_pattern_id: UUID | None
    interruption: InterruptionDecision
    attention_item_id: UUID | None
    attention_decision: AttentionDecision
    delivery_state: AttentionDeliveryState
    context: InterruptionContext
    trace_event_id: UUID | None


def context_from_current_context(snapshot: CurrentContextSnapshot) -> InterruptionContext:
    """Project only application-owned activity; unavailable desktop signals stay unknown."""

    active_voice: bool | None = None
    if snapshot.presence is not None:
        active_voice = snapshot.presence.state.value in {"listening", "speaking"}
    return InterruptionContext(
        revision=snapshot.revision,
        dnd=None,
        fullscreen=None,
        presentation=None,
        active_voice=active_voice,
        user_typing=None,
        active_conversation=snapshot.active_conversation_id is not None,
        active_task=snapshot.active_task_id is not None,
        safe_mode=snapshot.safe_mode,
    )


class InterruptionRuleRegistry:
    """Small versioned rule table; display language never participates."""

    def classify(
        self,
        semantic: SemanticEvent,
        *,
        pattern: SemanticPattern | None = None,
        trusted_security_boundary_violation: bool = False,
    ) -> InterruptionDecision:
        if type(trusted_security_boundary_violation) is not bool:
            raise ValueError("trusted security signal is malformed")
        if trusted_security_boundary_violation:
            return InterruptionDecision(
                InterruptionClass.URGENT,
                InterruptionReason.SECURITY_BOUNDARY_VIOLATION,
                AttentionPriority.URGENT,
            )
        if pattern is not None:
            if pattern.pattern_kind is PatternKind.REPEATED_EXECUTION_FAILURE:
                return InterruptionDecision(
                    InterruptionClass.IMPORTANT,
                    InterruptionReason.REPEATED_EXECUTION_FAILURE,
                    AttentionPriority.HIGH,
                )
            if pattern.pattern_kind is PatternKind.DEGRADED_THEN_RECOVERED:
                return InterruptionDecision(
                    InterruptionClass.SILENT,
                    InterruptionReason.RUNTIME_RECOVERED,
                    AttentionPriority.BACKGROUND,
                )
        if semantic.semantic_kind is SemanticKind.WAITING_FOR_USER:
            return InterruptionDecision(
                InterruptionClass.IMPORTANT,
                InterruptionReason.TASK_WAITING_FOR_USER,
                AttentionPriority.HIGH,
            )
        if semantic.semantic_kind is SemanticKind.RUNTIME_DEGRADED:
            return InterruptionDecision(
                InterruptionClass.IMPORTANT,
                InterruptionReason.RUNTIME_DEGRADED,
                AttentionPriority.HIGH,
            )
        if semantic.semantic_kind is SemanticKind.RUNTIME_RECOVERED:
            return InterruptionDecision(
                InterruptionClass.SILENT,
                InterruptionReason.RUNTIME_RECOVERED,
                AttentionPriority.BACKGROUND,
            )
        if semantic.semantic_kind is SemanticKind.CAPABILITY_AVAILABILITY:
            if semantic.state is not None and semantic.state.casefold() in {
                "unavailable",
                "disabled",
                "failed",
            }:
                return InterruptionDecision(
                    InterruptionClass.IMPORTANT,
                    InterruptionReason.CAPABILITY_UNAVAILABLE,
                    AttentionPriority.HIGH,
                )
            return InterruptionDecision(
                InterruptionClass.SILENT,
                InterruptionReason.CAPABILITY_AVAILABLE,
                AttentionPriority.BACKGROUND,
            )
        if semantic.semantic_kind is SemanticKind.EXECUTION_FAILED:
            return InterruptionDecision(
                InterruptionClass.SILENT,
                InterruptionReason.EXECUTION_FAILURE_OBSERVED,
                AttentionPriority.BACKGROUND,
            )
        if semantic.semantic_kind is SemanticKind.EXECUTION_SUCCEEDED:
            if semantic.outcome is not None and semantic.outcome.casefold() == "unknown":
                return InterruptionDecision(
                    InterruptionClass.IMPORTANT,
                    InterruptionReason.UNKNOWN_OUTCOME,
                    AttentionPriority.HIGH,
                )
            return InterruptionDecision(
                InterruptionClass.SILENT,
                InterruptionReason.EXECUTION_SUCCEEDED,
                AttentionPriority.BACKGROUND,
            )
        if semantic.semantic_kind is SemanticKind.PERMISSION_OBSERVED:
            return InterruptionDecision(
                InterruptionClass.SILENT,
                InterruptionReason.PERMISSION_OBSERVED,
                AttentionPriority.BACKGROUND,
            )
        if semantic.semantic_kind is SemanticKind.SYSTEM_PROBLEM:
            return InterruptionDecision(
                InterruptionClass.IMPORTANT,
                InterruptionReason.RUNTIME_DEGRADED,
                AttentionPriority.HIGH,
            )
        return InterruptionDecision(
            InterruptionClass.SILENT,
            InterruptionReason.CONTEXT_REEVALUATION,
            AttentionPriority.BACKGROUND,
        )


class InterruptionIntelligence:
    """Runtime-owned semantic observer using the existing attention and trace stores."""

    def __init__(
        self,
        semantic_events: SemanticEventService,
        attention_policy: AttentionPolicy,
        trace_service: TraceService,
        context_provider: Callable[[], InterruptionContext],
        *,
        workspace: str = "default",
        actor_context_id: UUID | None = None,
        rules: InterruptionRuleRegistry | None = None,
    ) -> None:
        if not workspace.strip():
            raise ValueError("interruption workspace is malformed")
        if actor_context_id is not None and not isinstance(actor_context_id, UUID):
            raise ValueError("interruption actor context is malformed")
        self._semantic_events = semantic_events
        self._attention = attention_policy
        self._trace = trace_service
        self._context_provider = context_provider
        self._workspace = workspace
        self._actor_context_id = actor_context_id
        self._rules = rules or InterruptionRuleRegistry()
        self._seen: deque[UUID] = deque(maxlen=2_048)
        self._seen_set: set[UUID] = set()
        self._closed = False
        self._semantic_events.add_observer(self._on_observation)

    async def aclose(self) -> None:
        self.close()

    def close(self) -> None:
        if not self._closed:
            self._closed = True
            self._semantic_events.remove_observer(self._on_observation)
            self._seen.clear()
            self._seen_set.clear()

    def reconcile(self, context: InterruptionContext) -> None:
        """Reevaluate durable queued items at an explicit context transition."""

        self._attention.reconcile(context=context)

    def process_semantic(
        self,
        semantic: SemanticEvent,
        *,
        pattern: SemanticPattern | None = None,
        context: InterruptionContext | None = None,
        trusted_security_boundary_violation: bool = False,
    ) -> InterruptionResult:
        source_id = pattern.pattern_id if pattern is not None else semantic.semantic_event_id
        if source_id in self._seen_set:
            raise ValueError("semantic interruption observation was already processed")
        if len(self._seen) == self._seen.maxlen:
            self._seen_set.discard(self._seen[0])
        self._seen.append(source_id)
        self._seen_set.add(source_id)
        current = context or self._current_context()
        interruption = self._rules.classify(
            semantic,
            pattern=pattern,
            trusted_security_boundary_violation=trusted_security_boundary_violation,
        )
        non_actionable_silent = interruption.reason_code in {
            InterruptionReason.EXECUTION_SUCCEEDED,
            InterruptionReason.EXECUTION_FAILURE_OBSERVED,
            InterruptionReason.PERMISSION_OBSERVED,
            InterruptionReason.CAPABILITY_AVAILABLE,
            InterruptionReason.CONTEXT_REEVALUATION,
        }
        dedupe_key = self._dedupe_key(semantic, pattern, interruption.reason_code)
        prior = self._attention.entry_for(self._item_id(dedupe_key))
        resolved_items: tuple[AttentionItem, ...] = ()
        if non_actionable_silent:
            item_id = None
            entry_decision = AttentionDecision.SILENT_ACTIVITY
            delivery_state = AttentionDeliveryState.SILENT
        elif interruption.reason_code is InterruptionReason.RUNTIME_RECOVERED:
            resolved_items = self._attention.resolve_dedupe(
                self._workspace,
                self._degradation_key(semantic),
                self._actor_context_id,
            )
            item_id = resolved_items[0].item_id if resolved_items else None
            entry_decision = AttentionDecision.SILENT_ACTIVITY
            delivery_state = (
                resolved_items[0].delivery_state
                if resolved_items
                else AttentionDeliveryState.SILENT
            )
        else:
            item = AttentionItem(
                self._item_id(dedupe_key),
                f"interruption.{interruption.reason_code.value}",
                self._workspace,
                interruption.priority,
                semantic.occurred_at,
                requires_user_action=(
                    interruption.reason_code is InterruptionReason.TASK_WAITING_FOR_USER
                ),
                related_goal_id=None,
                related_permission_id=self._permission_id(semantic),
                dedupe_key=dedupe_key,
                summary=self._summary(interruption.reason_code),
                interruption_class=interruption.interruption_class,
                actor_context_id=self._actor_context_id,
            )
            entry = self._attention.enqueue(item, context=current)
            item_id = item.item_id
            entry_decision = entry.decision
            stored = self._attention.item_for(item_id)
            delivery_state = stored.delivery_state if stored is not None else item.delivery_state
        trace_event_id = (
            self._trace_decision(
                semantic,
                pattern,
                interruption,
                current,
                item_id,
                entry_decision,
                delivery_state,
                prior.decision if prior is not None else None,
            )
            if not non_actionable_silent
            else None
        )
        return InterruptionResult(
            semantic.semantic_event_id,
            pattern.pattern_id if pattern is not None else None,
            interruption,
            item_id,
            entry_decision,
            delivery_state,
            current,
            trace_event_id,
        )

    def _on_observation(
        self, semantic: SemanticEvent, patterns: tuple[SemanticPattern, ...]
    ) -> None:
        if self._closed:
            return
        try:
            self.process_semantic(semantic)
            for pattern in patterns:
                self.process_semantic(semantic, pattern=pattern)
        except ValueError:
            # A duplicate or malformed local observation is not allowed to
            # break the semantic service's own continuity projection.
            return

    def _current_context(self) -> InterruptionContext:
        try:
            context = self._context_provider()
            if not isinstance(context, InterruptionContext):
                raise ValueError("context provider returned malformed context")
            return context
        except Exception:
            return InterruptionContext.unknown()

    def _dedupe_key(
        self,
        semantic: SemanticEvent,
        pattern: SemanticPattern | None,
        reason: InterruptionReason,
    ) -> str:
        if reason is InterruptionReason.RUNTIME_DEGRADED:
            return self._degradation_key(semantic)
        if pattern is not None and pattern.pattern_kind is PatternKind.REPEATED_EXECUTION_FAILURE:
            return f"interruption:{RULE_VERSION}:repeated-failure:{self._scope(semantic)}"
        source = str(pattern.pattern_id if pattern is not None else semantic.semantic_event_id)
        return f"interruption:{RULE_VERSION}:{reason.value}:{source}"

    def _degradation_key(self, semantic: SemanticEvent) -> str:
        subject = semantic.subject or "runtime"
        task = str(semantic.task_id or "none")
        return (
            f"interruption:{RULE_VERSION}:runtime-degraded:"
            f"{task}:{semantic.correlation_id}:{subject}"
        )

    @staticmethod
    def _scope(semantic: SemanticEvent) -> str:
        return f"{semantic.task_id or 'none'}:{semantic.correlation_id}"

    def _item_id(self, dedupe_key: str) -> UUID:
        return uuid5(
            _ATTENTION_NAMESPACE,
            f"{self._workspace}:{self._actor_context_id}:{dedupe_key}",
        )

    @staticmethod
    def _permission_id(semantic: SemanticEvent) -> UUID | None:
        for key, value in semantic.metadata:
            if key == "request_id":
                try:
                    return UUID(value)
                except ValueError:
                    return None
        return None

    @staticmethod
    def _summary(reason: InterruptionReason) -> str:
        return {
            InterruptionReason.TASK_WAITING_FOR_USER: "A task is waiting for owner action",
            InterruptionReason.REPEATED_EXECUTION_FAILURE: "Repeated execution failure observed",
            InterruptionReason.RUNTIME_DEGRADED: "A runtime component is degraded",
            InterruptionReason.CAPABILITY_UNAVAILABLE: "A capability is unavailable",
            InterruptionReason.UNKNOWN_OUTCOME: "An execution outcome is uncertain",
            InterruptionReason.SECURITY_BOUNDARY_VIOLATION: (
                "A trusted security boundary violation was observed"
            ),
        }.get(reason, "A bounded application attention fact was recorded")

    def _trace_decision(
        self,
        semantic: SemanticEvent,
        pattern: SemanticPattern | None,
        interruption: InterruptionDecision,
        context: InterruptionContext,
        item_id: UUID | None,
        decision: AttentionDecision,
        delivery_state: AttentionDeliveryState,
        prior_decision: AttentionDecision | None,
    ) -> UUID:
        source_id = pattern.pattern_id if pattern is not None else semantic.semantic_event_id
        event_id = uuid5(
            _TRACE_NAMESPACE,
            f"{source_id}:{context.revision}:{interruption.interruption_class.value}:{decision.value}",
        )
        result: dict[str, object] = {
            "interruption_class": interruption.interruption_class.value,
            "reason_code": interruption.reason_code.value,
            "attention_decision": decision.value,
            "delivery_state": delivery_state.value,
            "delivery_acknowledged": False,
            "source_semantic_event_id": str(semantic.semantic_event_id),
            "context_revision": context.revision,
            "context": {
                "dnd": context.dnd,
                "fullscreen": context.fullscreen,
                "presentation": context.presentation,
                "active_voice": context.active_voice,
                "user_typing": context.user_typing,
                "active_conversation": context.active_conversation,
                "active_task": context.active_task,
                "safe_mode": context.safe_mode,
            },
            "authority_changed": False,
        }
        if pattern is not None:
            result["source_pattern_id"] = str(pattern.pattern_id)
            result["source_raw_event_ids"] = tuple(
                str(raw_id) for raw_id in pattern.supporting_raw_event_ids[:4]
            )
        else:
            result["source_raw_event_ids"] = tuple(
                str(raw_id) for raw_id in semantic.source_event_ids[:4]
            )
        if item_id is not None:
            result["attention_item_id"] = str(item_id)
        if prior_decision is not None:
            result["prior_attention_decision"] = prior_decision.value
        trace = self._trace.get(task_id=semantic.task_id, correlation_id=semantic.correlation_id)
        if any(existing.event_id == event_id for existing in trace.events):
            return event_id
        event = self._trace.record(
            TraceEventType.ATTENTION,
            "Attention decision recorded",
            event_id=event_id,
            task_id=semantic.task_id,
            correlation_id=semantic.correlation_id,
            result=result,
        )
        return event.event_id


__all__ = [
    "InterruptionDecision",
    "InterruptionIntelligence",
    "InterruptionReason",
    "InterruptionResult",
    "InterruptionRuleRegistry",
    "RULE_VERSION",
    "context_from_current_context",
]
