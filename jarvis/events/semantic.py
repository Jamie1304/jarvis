"""Deterministic, non-authoritative semantic observations over raw events.

This module deliberately contains no model, provider, persistence, or authority
integration.  Raw :class:`EventEnvelope` values remain the canonical
observational source.
"""

from __future__ import annotations

from collections import OrderedDict, defaultdict, deque
from dataclasses import dataclass
from datetime import datetime, timedelta
from enum import StrEnum
from typing import Final
from uuid import NAMESPACE_URL, UUID, uuid5

from jarvis.events.bus import EventBus
from jarvis.events.models import (
    AutomationStateChanged,
    CapabilityChanged,
    EffectAttestationRecorded,
    EventEnvelope,
    EventPayload,
    EventType,
    HealthChanged,
    IntegrationChanged,
    PermissionDenied,
    PermissionGranted,
    PermissionRequested,
    RuntimeStateChanged,
    StepCompleted,
    StepFailed,
    StepStarted,
    SystemError,
    TaskCreated,
    TaskStateChanged,
    ToolCompleted,
    ToolFailed,
    ToolStarted,
)


class SemanticKind(StrEnum):
    TASK_LIFECYCLE = "task.lifecycle"
    EXECUTION_ACTIVITY = "execution.activity"
    EXECUTION_SUCCEEDED = "execution.succeeded"
    EXECUTION_FAILED = "execution.failed"
    WAITING_FOR_USER = "waiting.for_user"
    PERMISSION_OBSERVED = "permission.observed"
    RUNTIME_DEGRADED = "runtime.degraded"
    RUNTIME_RECOVERED = "runtime.recovered"
    CAPABILITY_AVAILABILITY = "capability.availability"
    AUTOMATION_LIFECYCLE = "automation.lifecycle"
    EFFECT_ATTESTATION_OBSERVED = "effect_attestation.observed"
    SYSTEM_PROBLEM = "system.problem"


class ContinuityState(StrEnum):
    CONTINUOUS = "continuous"
    BROKEN = "broken"


class PatternKind(StrEnum):
    REPEATED_EXECUTION_FAILURE = "repeated.execution.failure"
    DEGRADED_THEN_RECOVERED = "degraded.then.recovered"


RULE_VERSION: Final[str] = "v1"
_SEMANTIC_NAMESPACE: Final[UUID] = uuid5(NAMESPACE_URL, "jarvis/semantic-events")


@dataclass(frozen=True, slots=True)
class SemanticEvent:
    semantic_event_id: UUID
    semantic_kind: SemanticKind
    rule_id: str
    rule_version: str
    occurred_at: datetime
    source_event_ids: tuple[UUID, ...]
    source_sequence_start: int
    source_sequence_end: int
    correlation_id: UUID
    causation_id: UUID | None
    task_id: UUID | None
    subject: str | None
    state: str | None
    outcome: str | None
    continuity: ContinuityState
    metadata: tuple[tuple[str, str], ...] = ()


@dataclass(frozen=True, slots=True)
class SemanticPattern:
    pattern_id: UUID
    pattern_kind: PatternKind
    rule_id: str
    rule_version: str
    created_at: datetime
    supporting_semantic_event_ids: tuple[UUID, ...]
    supporting_raw_event_ids: tuple[UUID, ...]
    correlation_id: UUID | None
    task_id: UUID | None
    window_start: datetime
    window_end: datetime
    occurrence_count: int
    continuity: ContinuityState


@dataclass(frozen=True, slots=True)
class _Candidate:
    kind: SemanticKind
    rule_id: str
    subject: str | None = None
    state: str | None = None
    outcome: str | None = None
    metadata: tuple[tuple[str, str], ...] = ()


def _candidate(event: EventEnvelope[EventPayload]) -> _Candidate | None:
    """Map one trusted raw event to at most one bounded factual observation."""

    payload = event.payload
    if event.event_type is EventType.TASK_CREATED:
        assert isinstance(payload, TaskCreated)
        return _Candidate(SemanticKind.TASK_LIFECYCLE, "task.created", state="created")
    if event.event_type is EventType.TASK_STATE_CHANGED:
        assert isinstance(payload, TaskStateChanged)
        return _Candidate(
            SemanticKind.TASK_LIFECYCLE,
            "task.state_changed",
            state=payload.to_state,
            metadata=(("from_state", payload.from_state),),
        )
    if event.event_type is EventType.STEP_STARTED:
        assert isinstance(payload, StepStarted)
        return _Candidate(SemanticKind.EXECUTION_ACTIVITY, "step.started", payload.tool_id)
    if event.event_type is EventType.STEP_COMPLETED:
        assert isinstance(payload, StepCompleted)
        return _Candidate(
            SemanticKind.EXECUTION_SUCCEEDED,
            "step.completed",
            state="completed",
            outcome=payload.outcome,
        )
    if event.event_type is EventType.STEP_FAILED:
        assert isinstance(payload, StepFailed)
        return _Candidate(
            SemanticKind.EXECUTION_FAILED,
            "step.failed",
            state="failed",
            metadata=(("error_code", payload.error_code),),
        )
    if event.event_type is EventType.TOOL_STARTED:
        assert isinstance(payload, ToolStarted)
        return _Candidate(SemanticKind.EXECUTION_ACTIVITY, "tool.started", payload.tool_id)
    if event.event_type is EventType.TOOL_COMPLETED:
        assert isinstance(payload, ToolCompleted)
        return _Candidate(
            SemanticKind.EXECUTION_SUCCEEDED,
            "tool.completed",
            payload.tool_id,
            state=payload.status,
            outcome=payload.status,
        )
    if event.event_type is EventType.TOOL_FAILED:
        assert isinstance(payload, ToolFailed)
        return _Candidate(
            SemanticKind.EXECUTION_FAILED,
            "tool.failed",
            payload.tool_id,
            state="failed",
            metadata=(("error_code", payload.error_code),),
        )
    if event.event_type is EventType.PERMISSION_REQUESTED:
        assert isinstance(payload, PermissionRequested)
        return _Candidate(
            SemanticKind.WAITING_FOR_USER,
            "permission.requested",
            subject=payload.permission,
            state="requested",
            metadata=(("request_id", str(payload.request_id)), ("risk", payload.risk)),
        )
    if event.event_type is EventType.PERMISSION_GRANTED:
        assert isinstance(payload, PermissionGranted)
        return _Candidate(
            SemanticKind.PERMISSION_OBSERVED,
            "permission.granted",
            subject=payload.permission,
            state="granted",
            metadata=(("request_id", str(payload.request_id)),),
        )
    if event.event_type is EventType.PERMISSION_DENIED:
        assert isinstance(payload, PermissionDenied)
        metadata: tuple[tuple[str, str], ...] = (
            (("request_id", str(payload.request_id)),) if payload.request_id else ()
        )
        return _Candidate(
            SemanticKind.PERMISSION_OBSERVED,
            "permission.denied",
            state="denied",
            metadata=metadata + (("reason_code", payload.reason_code),),
        )
    if event.event_type is EventType.RUNTIME_STATE_CHANGED:
        assert isinstance(payload, RuntimeStateChanged)
        return _runtime_candidate("runtime.state_changed", "runtime", payload.state)
    if event.event_type is EventType.HEALTH_CHANGED:
        assert isinstance(payload, HealthChanged)
        return _runtime_candidate("health.changed", payload.component, payload.status)
    if event.event_type is EventType.SYSTEM_ERROR:
        assert isinstance(payload, SystemError)
        return _Candidate(
            SemanticKind.SYSTEM_PROBLEM,
            "system.error",
            state="error",
            metadata=(("code", payload.code),),
        )
    if event.event_type is EventType.CAPABILITY_CHANGED:
        assert isinstance(payload, CapabilityChanged)
        return _Candidate(
            SemanticKind.CAPABILITY_AVAILABILITY,
            "capability.changed",
            payload.capability,
            state="available" if payload.available else "unavailable",
        )
    if event.event_type is EventType.INTEGRATION_CHANGED:
        assert isinstance(payload, IntegrationChanged)
        return _Candidate(
            SemanticKind.CAPABILITY_AVAILABILITY,
            "integration.changed",
            payload.integration,
            state=payload.state,
        )
    if event.event_type is EventType.AUTOMATION_STATE_CHANGED:
        assert isinstance(payload, AutomationStateChanged)
        return _Candidate(
            SemanticKind.AUTOMATION_LIFECYCLE,
            "automation.state_changed",
            str(payload.automation_id),
            state=payload.state,
        )
    if event.event_type is EventType.EFFECT_ATTESTATION_RECORDED:
        assert isinstance(payload, EffectAttestationRecorded)
        metadata = (("status", payload.status), ("activation_state", payload.activation_state))
        return _Candidate(
            SemanticKind.EFFECT_ATTESTATION_OBSERVED,
            "effect_attestation.recorded",
            payload.integration_id,
            state=payload.status,
            metadata=metadata,
        )
    return None


def _runtime_candidate(rule_id: str, subject: str, state: str) -> _Candidate:
    normalized = state.casefold()
    degraded = any(
        token in normalized for token in ("degraded", "unhealthy", "error", "offline", "failed")
    )
    kind = SemanticKind.RUNTIME_DEGRADED if degraded else SemanticKind.RUNTIME_RECOVERED
    return _Candidate(kind, rule_id, subject, state=state)


class SemanticPatternEngine:
    """Bounded deterministic patterns over complete semantic observations."""

    def __init__(self, *, max_patterns: int = 256, max_window_events: int = 32) -> None:
        if max_patterns < 1 or max_window_events < 2:
            raise ValueError("invalid semantic pattern bounds")
        self._max_patterns = max_patterns
        self._max_window_events = max_window_events
        self._patterns: deque[SemanticPattern] = deque(maxlen=max_patterns)
        self._failure_windows: dict[tuple[UUID | None, UUID], deque[SemanticEvent]] = defaultdict(
            lambda: deque(maxlen=max_window_events)
        )
        self._degraded: OrderedDict[tuple[UUID | None, UUID, str | None], SemanticEvent] = (
            OrderedDict()
        )
        self._seen_pattern_ids: deque[UUID] = deque(maxlen=max_patterns * 2)

    def reset_continuity(self) -> None:
        self._failure_windows.clear()
        self._degraded.clear()

    def observe(self, event: SemanticEvent) -> tuple[SemanticPattern, ...]:
        if event.continuity is ContinuityState.BROKEN:
            self.reset_continuity()
            return ()
        created: list[SemanticPattern] = []
        if event.semantic_kind is SemanticKind.EXECUTION_FAILED:
            scope = (event.task_id, event.correlation_id)
            window = self._failure_windows[scope]
            cutoff = event.occurred_at - timedelta(minutes=5)
            while window and window[0].occurred_at < cutoff:
                window.popleft()
            window.append(event)
            if len(window) >= 2:
                created.append(
                    self._make_pattern(PatternKind.REPEATED_EXECUTION_FAILURE, tuple(window)[-2:])
                )
        recovery_scope = (event.task_id, event.correlation_id, event.subject)
        if event.semantic_kind is SemanticKind.RUNTIME_DEGRADED:
            self._degraded[recovery_scope] = event
            self._degraded.move_to_end(recovery_scope)
            if len(self._degraded) > self._max_window_events:
                self._degraded.popitem(last=False)
        elif event.semantic_kind is SemanticKind.RUNTIME_RECOVERED:
            degraded = self._degraded.pop(recovery_scope, None)
            if degraded is not None and event.occurred_at - degraded.occurred_at <= timedelta(
                minutes=5
            ):
                created.append(
                    self._make_pattern(PatternKind.DEGRADED_THEN_RECOVERED, (degraded, event))
                )
        return tuple(pattern for pattern in created if self._retain(pattern))

    def _make_pattern(
        self, kind: PatternKind, support: tuple[SemanticEvent, ...]
    ) -> SemanticPattern:
        raw_ids = tuple(event_id for item in support for event_id in item.source_event_ids)
        identity = ":".join(str(item.semantic_event_id) for item in support)
        pattern_id = uuid5(_SEMANTIC_NAMESPACE, f"pattern:{kind.value}:{RULE_VERSION}:{identity}")
        return SemanticPattern(
            pattern_id,
            kind,
            kind.value,
            RULE_VERSION,
            support[-1].occurred_at,
            tuple(item.semantic_event_id for item in support),
            raw_ids,
            support[-1].correlation_id,
            support[-1].task_id,
            support[0].occurred_at,
            support[-1].occurred_at,
            len(support),
            ContinuityState.CONTINUOUS,
        )

    def _retain(self, pattern: SemanticPattern) -> bool:
        if pattern.pattern_id in self._seen_pattern_ids:
            return False
        self._seen_pattern_ids.append(pattern.pattern_id)
        self._patterns.append(pattern)
        return True

    def recent(self) -> tuple[SemanticPattern, ...]:
        return tuple(self._patterns)


class SemanticEventService:
    """Runtime-owned bounded semantic projection over one EventBus subscription."""

    def __init__(
        self,
        event_bus: EventBus,
        *,
        max_recent_events: int = 512,
        max_seen_raw_event_ids: int = 1_024,
        pattern_engine: SemanticPatternEngine | None = None,
    ) -> None:
        if max_recent_events < 1 or max_seen_raw_event_ids < 1:
            raise ValueError("semantic retention bounds must be positive")
        self._event_bus = event_bus
        self._recent: deque[SemanticEvent] = deque(maxlen=max_recent_events)
        self._seen_raw: deque[UUID] = deque(maxlen=max_seen_raw_event_ids)
        self._seen_raw_set: set[UUID] = set()
        self._pattern_engine = pattern_engine or SemanticPatternEngine()
        self._subscription_id: str | None = None
        self._last_sequence: int | None = None
        self._closed = False

    @property
    def subscription_id(self) -> str | None:
        return self._subscription_id

    async def start(self) -> None:
        if self._closed:
            raise RuntimeError("semantic event service is closed")
        if self._subscription_id is None:
            self._subscription_id = await self._event_bus.subscribe(self._on_event)

    async def close(self) -> None:
        if self._closed:
            return
        self._closed = True
        if self._subscription_id is not None:
            await self._event_bus.unsubscribe(self._subscription_id)
            self._subscription_id = None
        self._recent.clear()
        self._seen_raw.clear()
        self._seen_raw_set.clear()
        self._pattern_engine.reset_continuity()

    async def _on_event(self, event: EventEnvelope[EventPayload]) -> None:
        self.process(event)

    def process(self, event: EventEnvelope[EventPayload]) -> tuple[SemanticEvent, ...]:
        if self._closed or event.event_id in self._seen_raw_set:
            return ()
        if len(self._seen_raw) == self._seen_raw.maxlen:
            self._seen_raw_set.discard(self._seen_raw[0])
        self._seen_raw.append(event.event_id)
        self._seen_raw_set.add(event.event_id)
        continuity = ContinuityState.CONTINUOUS
        if self._last_sequence is not None:
            if event.sequence > self._last_sequence + 1 or event.sequence <= self._last_sequence:
                continuity = ContinuityState.BROKEN
                self._pattern_engine.reset_continuity()
        self._last_sequence = event.sequence
        mapped = _candidate(event)
        if mapped is None:
            return ()
        semantic_id = uuid5(
            _SEMANTIC_NAMESPACE, f"semantic:{mapped.rule_id}:{RULE_VERSION}:{event.event_id}"
        )
        semantic = SemanticEvent(
            semantic_id,
            mapped.kind,
            mapped.rule_id,
            RULE_VERSION,
            event.timestamp,
            (event.event_id,),
            event.sequence,
            event.sequence,
            event.correlation_id,
            event.causation_id,
            event.task_id,
            mapped.subject,
            mapped.state,
            mapped.outcome,
            continuity,
            mapped.metadata,
        )
        self._recent.append(semantic)
        self._pattern_engine.observe(semantic)
        return (semantic,)

    def recent_events(self) -> tuple[SemanticEvent, ...]:
        return tuple(self._recent)

    def recent_patterns(self) -> tuple[SemanticPattern, ...]:
        return self._pattern_engine.recent()

    def events_for_task(self, task_id: UUID) -> tuple[SemanticEvent, ...]:
        return tuple(item for item in self._recent if item.task_id == task_id)

    def patterns_for_task(self, task_id: UUID) -> tuple[SemanticPattern, ...]:
        return tuple(item for item in self._pattern_engine.recent() if item.task_id == task_id)
