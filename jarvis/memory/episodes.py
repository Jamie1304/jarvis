"""Evidence-bound, local-only episodic experience records.

Episodes are durable knowledge projections.  They never become permissions,
receipts, verification authority, or instructions for the planning system.
"""

from __future__ import annotations

import hashlib
import json
from collections.abc import Callable
from dataclasses import dataclass
from datetime import UTC, datetime
from enum import StrEnum
from typing import Any, Protocol, cast
from uuid import NAMESPACE_URL, UUID, uuid5

from jarvis.events import (
    ContinuityState,
    EventBus,
    EventEnvelope,
    EventPayload,
    EventType,
    SemanticEvent,
    SemanticPattern,
)
from jarvis.memory.models import (
    EpisodicAction,
    MemoryProvenance,
    MemoryRecord,
    MemorySource,
    MemoryType,
    RetentionPolicy,
    Sensitivity,
    utc,
)
from jarvis.memory.services import EpisodicMemoryService
from jarvis.memory.store import SQLiteMemoryStore
from jarvis.planning.models import FailureKind, PlanningTask, PlanningTaskStatus
from jarvis.task_controller import TaskController


class EpisodeOutcome(StrEnum):
    COMPLETED = "completed"
    FAILED = "failed"
    CANCELLED = "cancelled"
    BLOCKED = "blocked"
    UNKNOWN_OUTCOME = "unknown_outcome"


class EpisodeVerification(StrEnum):
    VERIFIED = "verified"
    NOT_VERIFIED = "not_verified"
    UNKNOWN = "unknown"


class EpisodeContinuity(StrEnum):
    COMPLETE = "complete"
    PARTIAL = "partial"
    BROKEN_CONTINUITY = "broken_continuity"


EPISODE_SCHEMA_VERSION = 1
EPISODE_COMPOSITION_RULE_VERSION = "v1"
_EPISODE_NAMESPACE = uuid5(NAMESPACE_URL, "jarvis/episodes")


def _bounded(value: str, name: str, limit: int) -> None:
    if not isinstance(value, str) or not value.strip() or len(value) > limit or "\x00" in value:
        raise ValueError(f"{name} must be bounded and non-empty")


def _bounded_tuple(values: tuple[str, ...], name: str, limit: int, item_limit: int) -> None:
    if not isinstance(values, tuple) or len(values) > limit:
        raise ValueError(f"{name} is too large")
    for value in values:
        _bounded(value, name, item_limit)


@dataclass(frozen=True, slots=True)
class Episode:
    episode_id: UUID
    schema_version: int
    composition_rule_version: str
    created_at: datetime
    started_at: datetime | None
    ended_at: datetime
    task_id: UUID
    goal_id: UUID | None
    actor_context_id: UUID | None
    actor_principal_id: str | None
    workspace_id: str | None
    goal_category: str
    goal_fingerprint: str
    context_summary: tuple[tuple[str, str], ...]
    actions: tuple[EpisodicAction, ...]
    terminal_outcome: EpisodeOutcome
    verification: EpisodeVerification
    evidence_references: tuple[str, ...]
    semantic_event_ids: tuple[UUID, ...]
    raw_event_ids: tuple[UUID, ...]
    semantic_pattern_ids: tuple[UUID, ...]
    capability_ids: tuple[str, ...]
    provider_id: str | None
    model_id: str | None
    lessons: tuple[str, ...]
    sensitivity: Sensitivity
    continuity: EpisodeContinuity
    provenance: tuple[str, ...]
    relations: tuple[tuple[str, UUID], ...] = ()

    def __post_init__(self) -> None:
        if not isinstance(self.episode_id, UUID) or type(self.schema_version) is not int:
            raise ValueError("Episode identity/schema is invalid")
        if self.schema_version != EPISODE_SCHEMA_VERSION:
            raise ValueError("Unsupported Episode schema")
        _bounded(self.composition_rule_version, "Composition rule version", 32)
        if (
            not isinstance(self.task_id, UUID)
            or self.goal_id is not None
            and not isinstance(self.goal_id, UUID)
        ):
            raise ValueError("Episode task/goal identity is invalid")
        for value, name, limit in (
            (self.actor_principal_id, "Actor principal", 256),
            (self.workspace_id, "Workspace", 256),
            (self.provider_id, "Provider", 128),
            (self.model_id, "Model", 128),
        ):
            if value is not None:
                _bounded(value, name, limit)
        _bounded(self.goal_category, "Goal category", 64)
        if len(self.goal_fingerprint) != 64 or any(
            character not in "0123456789abcdef" for character in self.goal_fingerprint
        ):
            raise ValueError("Goal fingerprint is invalid")
        _bounded_tuple(self.evidence_references, "Evidence references", 32, 256)
        _bounded_tuple(self.capability_ids, "Capability IDs", 32, 128)
        _bounded_tuple(self.lessons, "Lessons", 16, 256)
        _bounded_tuple(self.provenance, "Provenance", 16, 256)
        if not isinstance(self.context_summary, tuple) or len(self.context_summary) > 32:
            raise ValueError("Episode context is too large")
        for key, value in self.context_summary:
            _bounded(key, "Context key", 64)
            _bounded(value, "Context value", 256)
        if len(self.actions) > 16 or any(
            not isinstance(action, EpisodicAction) for action in self.actions
        ):
            raise ValueError("Episode actions are invalid or too large")
        for collection, name in (
            (self.semantic_event_ids, "Semantic event IDs"),
            (self.raw_event_ids, "Raw event IDs"),
            (self.semantic_pattern_ids, "Pattern IDs"),
        ):
            if (
                not isinstance(collection, tuple)
                or len(collection) > 64
                or any(not isinstance(value, UUID) for value in collection)
            ):
                raise ValueError(f"{name} are invalid or too large")
        if not isinstance(self.terminal_outcome, EpisodeOutcome):
            raise ValueError("Episode outcome is invalid")
        if not isinstance(self.verification, EpisodeVerification):
            raise ValueError("Episode verification is invalid")
        if not isinstance(self.sensitivity, Sensitivity):
            raise ValueError("Episode sensitivity is invalid")
        if not isinstance(self.continuity, EpisodeContinuity):
            raise ValueError("Episode continuity is invalid")
        if len(self.relations) > 16 or any(
            not isinstance(kind, str) or not kind.strip() or not isinstance(value, UUID)
            for kind, value in self.relations
        ):
            raise ValueError("Episode relations are invalid or too large")
        object.__setattr__(self, "created_at", utc(self.created_at))
        object.__setattr__(self, "ended_at", utc(self.ended_at))
        if self.started_at is not None:
            object.__setattr__(self, "started_at", utc(self.started_at))
        if self.started_at is not None and self.ended_at < self.started_at:
            raise ValueError("Episode ended before it started")

    def to_data(self) -> dict[str, object]:
        return {
            "record_type": "episode",
            "schema_version": self.schema_version,
            "composition_rule_version": self.composition_rule_version,
            "created_at": self.created_at.isoformat(),
            "started_at": self.started_at.isoformat() if self.started_at else None,
            "ended_at": self.ended_at.isoformat(),
            "task_id": str(self.task_id),
            "goal_id": str(self.goal_id) if self.goal_id else None,
            "actor_context_id": str(self.actor_context_id) if self.actor_context_id else None,
            "actor_principal_id": self.actor_principal_id,
            "workspace_id": self.workspace_id,
            "goal_category": self.goal_category,
            "goal_fingerprint": self.goal_fingerprint,
            "context_summary": [list(item) for item in self.context_summary],
            "actions": [
                {"tool_id": item.tool_id, "action": item.action, "outcome": item.outcome}
                for item in self.actions
            ],
            "terminal_outcome": self.terminal_outcome.value,
            "verification": self.verification.value,
            "evidence_references": list(self.evidence_references),
            "semantic_event_ids": [str(value) for value in self.semantic_event_ids],
            "raw_event_ids": [str(value) for value in self.raw_event_ids],
            "semantic_pattern_ids": [str(value) for value in self.semantic_pattern_ids],
            "capability_ids": list(self.capability_ids),
            "provider_id": self.provider_id,
            "model_id": self.model_id,
            "lessons": list(self.lessons),
            "sensitivity": self.sensitivity.value,
            "continuity": self.continuity.value,
            "provenance": list(self.provenance),
            "relations": [[kind, str(value)] for kind, value in self.relations],
        }

    @classmethod
    def from_record(cls, record: MemoryRecord) -> Episode:
        if record.memory_type is not MemoryType.EPISODIC:
            raise ValueError("Memory record is not episodic")
        data = cast(dict[str, Any], record.data_object)
        if data.get("record_type") != "episode":
            raise ValueError("Memory record is not a first-class Episode")

        def optional_uuid(value: object) -> UUID | None:
            return UUID(str(value)) if value is not None else None

        def timestamp(value: object) -> datetime:
            return datetime.fromisoformat(str(value)).astimezone(UTC)

        return cls(
            record.memory_id,
            int(data["schema_version"]),
            str(data["composition_rule_version"]),
            timestamp(data["created_at"]),
            timestamp(data["started_at"]) if data["started_at"] else None,
            timestamp(data["ended_at"]),
            UUID(str(data["task_id"])),
            optional_uuid(data["goal_id"]),
            optional_uuid(data["actor_context_id"]),
            str(data["actor_principal_id"]) if data["actor_principal_id"] else None,
            str(data["workspace_id"]) if data["workspace_id"] else None,
            str(data["goal_category"]),
            str(data["goal_fingerprint"]),
            tuple((str(item[0]), str(item[1])) for item in data["context_summary"]),
            tuple(
                EpisodicAction(str(item["tool_id"]), str(item["action"]), str(item["outcome"]))
                for item in data["actions"]
            ),
            EpisodeOutcome(str(data["terminal_outcome"])),
            EpisodeVerification(str(data["verification"])),
            tuple(str(item) for item in data["evidence_references"]),
            tuple(UUID(str(item)) for item in data["semantic_event_ids"]),
            tuple(UUID(str(item)) for item in data["raw_event_ids"]),
            tuple(UUID(str(item)) for item in data["semantic_pattern_ids"]),
            tuple(str(item) for item in data["capability_ids"]),
            str(data["provider_id"]) if data["provider_id"] else None,
            str(data["model_id"]) if data["model_id"] else None,
            tuple(str(item) for item in data["lessons"]),
            Sensitivity(str(data["sensitivity"])),
            EpisodeContinuity(str(data["continuity"])),
            tuple(str(item) for item in data["provenance"]),
            tuple((str(item[0]), UUID(str(item[1]))) for item in data["relations"]),
        )


class EpisodeStore:
    """Typed Episode ownership over the existing SQLiteMemoryStore database."""

    def __init__(
        self, memory_store: SQLiteMemoryStore, *, clock: Callable[[], datetime] | None = None
    ) -> None:
        self._memory_store = memory_store
        self._clock = clock or (lambda: datetime.now(UTC))

    def save(
        self, episode: Episode, *, retention: RetentionPolicy = RetentionPolicy.THIRTY_DAYS
    ) -> Episode:
        existing = self.get(episode.episode_id)
        if existing is not None:
            if existing != episode:
                raise ValueError("Episode identity already contains different evidence")
            return existing
        now = self._clock()
        record = MemoryRecord(
            memory_id=episode.episode_id,
            memory_type=MemoryType.EPISODIC,
            content=f"Episode {episode.episode_id}",
            data=json.dumps(episode.to_data(), sort_keys=True, separators=(",", ":")),
            created_at=episode.created_at,
            provenance=MemoryProvenance(MemorySource.TASK, str(episode.task_id), now, True),
            confidence=None,
            retention=retention,
            sensitivity=episode.sensitivity,
            expires_at=retention.expiry(episode.created_at),
            updated_at=episode.created_at,
        )
        self._memory_store.put(record)
        return episode

    def get(self, episode_id: UUID) -> Episode | None:
        record = self._memory_store.get(episode_id)
        if record is None:
            return None
        return Episode.from_record(record)

    def list(
        self,
        *,
        task_id: UUID | None = None,
        actor_context_id: UUID | None = None,
        workspace_id: str | None = None,
        outcome: EpisodeOutcome | None = None,
    ) -> tuple[Episode, ...]:
        episodes: list[Episode] = []
        for record in self._memory_store.list(MemoryType.EPISODIC):
            if record.data_object.get("record_type") != "episode":
                continue
            episode = Episode.from_record(record)
            if task_id is not None and episode.task_id != task_id:
                continue
            if actor_context_id is not None and episode.actor_context_id != actor_context_id:
                continue
            if workspace_id is not None and episode.workspace_id != workspace_id:
                continue
            if outcome is not None and episode.terminal_outcome is not outcome:
                continue
            episodes.append(episode)
        return tuple(episodes)


class _SemanticQuery(Protocol):
    def events_for_task(self, task_id: UUID) -> tuple[SemanticEvent, ...]: ...
    def patterns_for_task(self, task_id: UUID) -> tuple[SemanticPattern, ...]: ...


class EpisodeComposer:
    """Compose durable Episodes only at authoritative terminal task boundaries."""

    def __init__(
        self,
        event_bus: EventBus,
        task_controller: TaskController,
        episodic_memory: EpisodicMemoryService,
        semantic_events: _SemanticQuery,
        *,
        actor_context_id: UUID | None = None,
        actor_principal_id: str | None = None,
        workspace_id: str | None = None,
        provider_id: str | None = None,
        model_id: str | None = None,
        clock: Callable[[], datetime] | None = None,
    ) -> None:
        self._event_bus = event_bus
        self._task_controller = task_controller
        self._episodic_memory = episodic_memory
        self._semantic_events = semantic_events
        self._actor_context_id = actor_context_id
        self._actor_principal_id = actor_principal_id
        self._workspace_id = workspace_id
        self._provider_id = provider_id
        self._model_id = model_id
        self._clock = clock or (lambda: datetime.now(UTC))
        self._subscription_id: str | None = None
        self._closed = False

    async def start(self) -> None:
        if self._closed:
            raise RuntimeError("Episode composer is closed")
        if self._subscription_id is None:
            self._subscription_id = await self._event_bus.subscribe(self._on_event)

    async def close(self) -> None:
        if self._closed:
            return
        self._closed = True
        if self._subscription_id is not None:
            await self._event_bus.unsubscribe(self._subscription_id)
            self._subscription_id = None

    async def _on_event(self, event: EventEnvelope[EventPayload]) -> None:
        if (
            event.event_type is not EventType.TASK_STATE_CHANGED
            or event.task_id is None
            or not self._is_terminal_state(event.payload)
        ):
            return
        self.compose_task(event.task_id, terminal_event_id=event.event_id)

    @staticmethod
    def _is_terminal_state(payload: EventPayload) -> bool:
        return getattr(payload, "to_state", None) in {
            PlanningTaskStatus.COMPLETED.value,
            "error",
            PlanningTaskStatus.CANCELLED.value,
        }

    def compose_task(
        self, task_id: UUID, *, terminal_event_id: UUID | None = None
    ) -> Episode | None:
        task = self._task_controller.get_task(task_id)
        if task is None or task.status not in {
            PlanningTaskStatus.COMPLETED,
            PlanningTaskStatus.FAILED,
            PlanningTaskStatus.CANCELLED,
            PlanningTaskStatus.BUDGET_EXHAUSTED,
        }:
            return None
        existing = self._episodic_memory.get_episode_for_task(task_id)
        if existing is not None:
            return existing
        plan = self._task_controller.inspect_plan(task_id)
        result = self._task_controller.get_result(task_id)
        semantic = self._semantic_events.events_for_task(task_id)
        patterns = self._semantic_events.patterns_for_task(task_id)
        outcome, verification, lessons = self._outcome(task, result)
        continuity = (
            EpisodeContinuity.PARTIAL
            if not semantic
            else EpisodeContinuity.BROKEN_CONTINUITY
            if any(item.continuity is ContinuityState.BROKEN for item in semantic)
            else EpisodeContinuity.COMPLETE
        )
        raw_ids = tuple(
            dict.fromkeys(
                item for semantic_event in semantic for item in semantic_event.source_event_ids
            )
        )
        if terminal_event_id is not None and terminal_event_id not in raw_ids:
            raw_ids += (terminal_event_id,)
        semantic_ids = tuple(item.semantic_event_id for item in semantic)
        pattern_ids = tuple(item.pattern_id for item in patterns)
        plan_id = plan.plan_id if plan is not None else None
        episode_id = uuid5(
            _EPISODE_NAMESPACE,
            f"episode:{EPISODE_COMPOSITION_RULE_VERSION}:{task_id}:{task.status.value}",
        )
        goal = task.goal.casefold()
        category = (
            "calculation"
            if "calculat" in goal or "%" in goal
            else "weather"
            if "weather" in goal
            else "general_task"
        )
        actions = tuple(
            EpisodicAction(
                step.tool_id,
                step.capability,
                step.status.value,
            )
            for step in (plan.steps if plan is not None else ())
        )
        evidence = [f"task:{task.task_id}"]
        if plan_id is not None:
            evidence.append(f"plan:{plan_id}")
        evidence.extend(
            self._digest_reference(value) for value in (result.evidence if result else ())
        )
        episode = Episode(
            episode_id,
            EPISODE_SCHEMA_VERSION,
            EPISODE_COMPOSITION_RULE_VERSION,
            self._clock(),
            task.started_at,
            task.updated_at,
            task.task_id,
            None,
            self._actor_context_id,
            self._actor_principal_id,
            self._workspace_id,
            category,
            hashlib.sha256(task.goal.encode("utf-8")).hexdigest(),
            (
                ("task_status", task.status.value),
                ("plan_present", str(plan is not None).lower()),
                ("action_count", str(len(actions))),
            ),
            actions,
            outcome,
            verification,
            tuple(dict.fromkeys(evidence)),
            semantic_ids,
            raw_ids,
            pattern_ids,
            tuple(plan.required_capabilities if plan is not None else ()),
            self._provider_id,
            self._model_id,
            lessons,
            Sensitivity.PRIVATE,
            continuity,
            ("planning.task", "semantic.observation", "local.episodic.store"),
        )
        return self._episodic_memory.persist_episode(episode)

    @staticmethod
    def _digest_reference(value: str) -> str:
        return f"evidence-sha256:{hashlib.sha256(value.encode('utf-8')).hexdigest()}"

    @staticmethod
    def _outcome(
        task: PlanningTask, result: object
    ) -> tuple[EpisodeOutcome, EpisodeVerification, tuple[str, ...]]:
        del result
        if task.status is PlanningTaskStatus.COMPLETED:
            return (
                EpisodeOutcome.COMPLETED,
                EpisodeVerification.VERIFIED,
                ("verified_terminal_task",),
            )
        if task.status is PlanningTaskStatus.CANCELLED:
            return (
                EpisodeOutcome.CANCELLED,
                EpisodeVerification.NOT_VERIFIED,
                ("cancelled_terminal_task",),
            )
        if task.error is not None and task.error.failure_kind is FailureKind.UNKNOWN_OUTCOME:
            return (
                EpisodeOutcome.UNKNOWN_OUTCOME,
                EpisodeVerification.UNKNOWN,
                ("unknown_effect_outcome",),
            )
        if task.status is PlanningTaskStatus.BUDGET_EXHAUSTED:
            return (
                EpisodeOutcome.BLOCKED,
                EpisodeVerification.NOT_VERIFIED,
                ("execution_budget_exhausted",),
            )
        return EpisodeOutcome.FAILED, EpisodeVerification.NOT_VERIFIED, ("failed_terminal_task",)
