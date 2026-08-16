"""Services that preserve the separation between context, user, episode, and system memory."""

from __future__ import annotations

import json
import re
from abc import ABC, abstractmethod
from collections.abc import Callable, Sequence
from datetime import UTC, datetime
from pathlib import Path
from uuid import UUID, uuid4

from jarvis.knowledge.store import KnowledgeStore
from jarvis.memory.models import (
    ConversationEntry,
    EpisodicAction,
    LongTermEligibility,
    LongTermMemoryCandidate,
    MemoryProvenance,
    MemoryRecord,
    MemoryRetrieval,
    MemorySource,
    MemoryType,
    RetentionDecision,
    RetentionPolicy,
    Sensitivity,
    SystemMemoryHit,
)
from jarvis.memory.policy import LongTermRetentionPolicy, contains_secret
from jarvis.memory.store import SQLiteMemoryStore

_TOKEN = re.compile(r"[a-z0-9_./-]+")


def _now() -> datetime:
    return datetime.now(UTC)


class ContextSummarizer(ABC):
    """Explicit trusted summarization seam; it cannot persist or execute anything."""

    @abstractmethod
    def summarize(self, entries: tuple[ConversationEntry, ...]) -> str:
        """Return a bounded neutral context summary for discarded local messages."""


class ConversationContextService:
    """Keep per-conversation context bounded in process memory only."""

    def __init__(
        self,
        *,
        max_entries: int = 32,
        max_characters: int = 24_000,
        summarizer: ContextSummarizer | None = None,
        clock: Callable[[], datetime] = _now,
    ) -> None:
        if max_entries <= 0 or max_characters <= 0:
            raise ValueError("Conversation bounds must be positive")
        self._max_entries = max_entries
        self._max_characters = max_characters
        self._summarizer = summarizer
        self._clock = clock
        self._entries: dict[UUID, list[ConversationEntry]] = {}

    def append(self, conversation_id: UUID, role: str, content: str) -> None:
        entries = self._entries.setdefault(conversation_id, [])
        entries.append(ConversationEntry(role, content, self._clock()))
        self._trim(entries)

    def inspect(self, conversation_id: UUID) -> tuple[ConversationEntry, ...]:
        return tuple(self._entries.get(conversation_id, ()))

    def clear(self, conversation_id: UUID) -> bool:
        return self._entries.pop(conversation_id, None) is not None

    def _trim(self, entries: list[ConversationEntry]) -> None:
        reserve_summary_slot = 1 if self._summarizer is not None else 0
        discarded: list[ConversationEntry] = []
        while entries and (
            len(entries) > self._max_entries - reserve_summary_slot
            or self._characters(entries) > self._max_characters
        ):
            discarded.append(entries.pop(0))
        if discarded and self._summarizer is not None:
            summary = self._summarizer.summarize(tuple(discarded))
            if summary.strip() and len(summary) + self._characters(entries) <= self._max_characters:
                entries.insert(0, ConversationEntry("summary", summary, self._clock()))

    @staticmethod
    def _characters(entries: Sequence[ConversationEntry]) -> int:
        return sum(len(entry.content) for entry in entries)


class LongTermMemoryService:
    """Persist only a separately confirmed and policy-approved user memory candidate."""

    def __init__(
        self,
        store: SQLiteMemoryStore,
        *,
        policy: LongTermRetentionPolicy | None = None,
        clock: Callable[[], datetime] = _now,
    ) -> None:
        self._store = store
        self._policy = policy or LongTermRetentionPolicy()
        self._clock = clock

    def evaluate(self, candidate: LongTermMemoryCandidate) -> LongTermEligibility:
        return self._policy.evaluate(candidate)

    def persist(self, candidate: LongTermMemoryCandidate) -> MemoryRecord:
        decision = self.evaluate(candidate)
        if decision.decision is not RetentionDecision.ALLOW:
            raise PermissionError(f"Long-term memory denied: {decision.reason_code}")
        now = self._clock()
        record = MemoryRecord(
            memory_id=uuid4(),
            memory_type=MemoryType.LONG_TERM,
            content=candidate.content,
            data=candidate.data,
            created_at=now,
            provenance=candidate.provenance,
            confidence=candidate.confidence,
            retention=candidate.retention,
            sensitivity=candidate.sensitivity,
            expires_at=candidate.retention.expiry(now),
            updated_at=now,
        )
        self._store.put(record)
        return record


class EpisodicMemoryService:
    """Persist compact completed-action evidence, not full audit logs or raw transcripts."""

    def __init__(self, store: SQLiteMemoryStore, *, clock: Callable[[], datetime] = _now) -> None:
        self._store = store
        self._clock = clock

    def record_completed_action(
        self,
        *,
        task_id: UUID,
        objective: str,
        actions: tuple[EpisodicAction, ...],
        outcome: str,
        errors: tuple[str, ...] = (),
        evidence: tuple[str, ...] = (),
        retention: RetentionPolicy = RetentionPolicy.THIRTY_DAYS,
    ) -> MemoryRecord:
        if not objective.strip() or len(objective) > 1_000:
            raise ValueError("Episode objective must be bounded and non-empty")
        if not outcome.strip() or len(outcome) > 512:
            raise ValueError("Episode outcome must be bounded and non-empty")
        if not isinstance(retention, RetentionPolicy):
            raise ValueError("Episode retention policy must be recognized")
        if len(actions) > 16 or len(errors) > 16 or len(evidence) > 16:
            raise ValueError("Episode evidence must remain compact")
        bounded_errors = tuple(self._bounded(value, 512, "Episode error") for value in errors)
        bounded_evidence = tuple(
            self._bounded(value, 512, "Episode evidence") for value in evidence
        )
        secret_candidates = (
            objective,
            outcome,
            *bounded_errors,
            *bounded_evidence,
            *(
                value
                for action in actions
                for value in (action.tool_id, action.action, action.outcome)
            ),
        )
        if any(contains_secret(value) for value in secret_candidates):
            raise PermissionError("Episodic memory cannot retain credential-like content")
        now = self._clock()
        data = {
            "task_id": str(task_id),
            "actions": [
                {"tool_id": action.tool_id, "action": action.action, "outcome": action.outcome}
                for action in actions
            ],
            "outcome": outcome,
            "errors": list(bounded_errors),
            "evidence": list(bounded_evidence),
        }
        record = MemoryRecord(
            memory_id=uuid4(),
            memory_type=MemoryType.EPISODIC,
            content=f"Completed task: {objective}",
            data=json.dumps(data, sort_keys=True, separators=(",", ":")),
            created_at=now,
            # Task episodes may summarize model/tool/web evidence. They remain
            # useful for retrieval, but never cross back as trusted instructions.
            provenance=MemoryProvenance(MemorySource.TASK, str(task_id), now, True),
            confidence=None,
            retention=retention,
            sensitivity=Sensitivity.PRIVATE,
            expires_at=retention.expiry(now),
            updated_at=now,
        )
        self._store.put(record)
        return record

    @staticmethod
    def _bounded(value: str, limit: int, name: str) -> str:
        if not value.strip() or len(value) > limit or "\x00" in value:
            raise ValueError(f"{name} must be bounded, non-empty, and NUL-free")
        return value


class ProjectSystemMemory:
    """Read-only adapter to the Phase 12 index; it never stores project knowledge as user data."""

    def __init__(self, knowledge: KnowledgeStore, project_root: Path) -> None:
        self._knowledge = knowledge
        self._project_root = project_root

    def search(self, query: str, *, limit: int = 10) -> tuple[SystemMemoryHit, ...]:
        # ``KnowledgeStore`` owns source provenance and stale detection.
        # This adapter only preserves that source boundary.
        return tuple(
            SystemMemoryHit(
                item_id=result.item.item_id,
                title=result.item.title,
                summary=result.item.summary,
                authority=result.item.authority.value,
                source_files=result.item.provenance.source_files,
                stale=result.item.is_stale(self._project_root),
                score=result.score,
            )
            for result in self._knowledge.search(query, limit=limit)
        )


class MemoryRetrievalService:
    """Retrieve relevant data with source/type boundaries visible to every caller."""

    def __init__(
        self,
        store: SQLiteMemoryStore,
        conversation: ConversationContextService,
        system: ProjectSystemMemory,
    ) -> None:
        self._store = store
        self._conversation = conversation
        self._system = system

    def retrieve(
        self, query: str, *, conversation_id: UUID | None = None, limit: int = 10
    ) -> MemoryRetrieval:
        conversation: tuple[ConversationEntry, ...] = ()
        if conversation_id is not None:
            conversation = self._matching_conversation(
                self._conversation.inspect(conversation_id), query, limit
            )
        return MemoryRetrieval(
            conversation=conversation,
            long_term=self._store.search(query, MemoryType.LONG_TERM, limit=limit),
            episodic=self._store.search(query, MemoryType.EPISODIC, limit=limit),
            system=self._system.search(query, limit=limit),
        )

    @staticmethod
    def _matching_conversation(
        entries: tuple[ConversationEntry, ...], query: str, limit: int
    ) -> tuple[ConversationEntry, ...]:
        terms = set(_TOKEN.findall(query.casefold()))
        if not terms or limit <= 0:
            return ()
        matches = [
            entry for entry in entries if terms & set(_TOKEN.findall(entry.content.casefold()))
        ]
        return tuple(matches[-limit:])
