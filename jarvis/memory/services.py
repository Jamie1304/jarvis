"""Services that preserve the separation between context, user, episode, and system memory."""

from __future__ import annotations

import hashlib
import json
import re
from abc import ABC, abstractmethod
from collections.abc import Callable, Sequence
from datetime import UTC, datetime, timedelta
from itertools import combinations
from pathlib import Path
from uuid import UUID, uuid4

from jarvis.knowledge.store import KnowledgeStore
from jarvis.memory.models import (
    ConversationEntry,
    EpisodicAction,
    LongTermEligibility,
    LongTermMemoryCandidate,
    MemoryConflictKind,
    MemoryConflictRecord,
    MemoryConflictStatus,
    MemoryProvenance,
    MemoryRecord,
    MemoryRetrieval,
    MemoryRevalidation,
    MemorySource,
    MemoryType,
    RetentionDecision,
    RetentionPolicy,
    Sensitivity,
    SystemMemoryHit,
)
from jarvis.memory.policy import (
    LongTermRetentionPolicy,
    contains_prompt_injection,
    contains_secret,
)
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


class MemoryConsistencyService:
    """Detect and remediate memory conflicts without inventing a second authority."""

    def __init__(
        self,
        store: SQLiteMemoryStore,
        *,
        stale_after: timedelta = timedelta(days=180),
        low_confidence_threshold: float = 0.5,
        clock: Callable[[], datetime] = _now,
    ) -> None:
        if stale_after <= timedelta(0):
            raise ValueError("Memory staleness duration must be positive")
        if not 0 <= low_confidence_threshold <= 1:
            raise ValueError("Memory confidence threshold must be between zero and one")
        self._store = store
        self._stale_after = stale_after
        self._low_confidence_threshold = low_confidence_threshold
        self._clock = clock

    def scan(
        self,
        *,
        memory_type: MemoryType | None = None,
        now: datetime | None = None,
    ) -> tuple[MemoryConflictRecord, ...]:
        """Persist bounded findings and return the current scan's findings.

        Findings are intentionally not merged automatically. A trusted caller
        must revalidate, correct, supersede, or explicitly resolve them.
        """

        if memory_type is not None and not isinstance(memory_type, MemoryType):
            raise ValueError("Memory type must be recognized")
        timestamp = now or self._clock()
        records = self._store.list(memory_type, include_inactive=True)
        findings: list[MemoryConflictRecord] = []
        active = tuple(record for record in records if record.is_retrievable)

        for record in records:
            if record.superseded_by is not None:
                findings.append(
                    self._ensure_conflict(
                        MemoryConflictKind.SUPERSEDED,
                        (record.memory_id, record.superseded_by),
                        timestamp,
                        "record has an explicit supersession target",
                        ("supersession metadata",),
                        closed=True,
                    )
                )
            provenance_reason = self._impossible_provenance(record, timestamp)
            if provenance_reason is not None:
                findings.append(
                    self._ensure_conflict(
                        MemoryConflictKind.IMPOSSIBLE_PROVENANCE,
                        (record.memory_id,),
                        timestamp,
                        provenance_reason,
                        (record.provenance.source.value,),
                        quarantined=record.quarantined,
                    )
                )
            if contains_prompt_injection(record.content + "\n" + record.data):
                findings.append(
                    self._ensure_conflict(
                        MemoryConflictKind.PROMPT_INJECTION,
                        (record.memory_id,),
                        timestamp,
                        "instruction-shaped content is not trusted memory",
                        ("pattern detection",),
                        quarantined=record.quarantined,
                    )
                )
            if record.confidence is not None and record.confidence < self._low_confidence_threshold:
                findings.append(
                    self._ensure_conflict(
                        MemoryConflictKind.LOW_CONFIDENCE,
                        (record.memory_id,),
                        timestamp,
                        "confidence is below the configured memory threshold",
                        ("confidence threshold",),
                    )
                )
            reference_time = record.last_revalidated_at or record.updated_at
            if timestamp - reference_time > self._stale_after:
                findings.append(
                    self._ensure_conflict(
                        MemoryConflictKind.STALE,
                        (record.memory_id,),
                        timestamp,
                        "memory has not been revalidated within the configured interval",
                        ("revalidation age",),
                    )
                )

        fingerprints: dict[str, list[MemoryRecord]] = {}
        for record in active:
            fingerprints.setdefault(self._fingerprint(record), []).append(record)
        for duplicate_records in fingerprints.values():
            if len(duplicate_records) < 2:
                continue
            ids = tuple(record.memory_id for record in duplicate_records)
            findings.append(
                self._ensure_conflict(
                    MemoryConflictKind.DUPLICATE,
                    ids,
                    timestamp,
                    "active records have identical canonical content",
                    ("canonical content fingerprint",),
                )
            )

        for first, second in combinations(active, 2):
            if first.memory_type is not second.memory_type:
                continue
            subject_first = self._subject_signature(first)
            subject_second = self._subject_signature(second)
            if subject_first is None or subject_first != subject_second:
                continue
            if first.data == second.data:
                continue
            findings.append(
                self._ensure_conflict(
                    MemoryConflictKind.CONTRADICTION,
                    (first.memory_id, second.memory_id),
                    timestamp,
                    "active records describe different values for the same subject",
                    (f"subject:{subject_first}",),
                )
            )
        return tuple(findings)

    def revalidate(self, request: MemoryRevalidation) -> MemoryRecord:
        """Revalidate with trusted evidence and append confidence evolution."""

        if not isinstance(request, MemoryRevalidation):
            raise ValueError("Revalidation must use the typed request")
        record = self._store.get(request.memory_id, include_inactive=True)
        if record is None:
            raise KeyError("Memory record does not exist")
        if record.memory_type is MemoryType.LONG_TERM:
            self._require_user_validation(request, record)
        if record.sensitivity is Sensitivity.SENSITIVE:
            if (
                request.provenance.source is not MemorySource.USER
                or request.provenance.untrusted_content
                or not request.user_confirmed
                or len(request.evidence) < 2
                or request.confidence < 0.8
            ):
                raise PermissionError("Sensitive memory requires strong user revalidation")
        return self._store.apply_revalidation(request)

    def correct(
        self,
        memory_id: UUID,
        replacement: MemoryRecord,
        *,
        evidence: tuple[str, ...],
        now: datetime | None = None,
    ) -> MemoryRecord:
        """Create an explicit replacement and supersede the old record."""

        if not isinstance(memory_id, UUID) or not isinstance(replacement, MemoryRecord):
            raise ValueError("Memory correction is invalid")
        if not isinstance(evidence, tuple) or not 1 <= len(evidence) <= 16:
            raise ValueError("Memory correction evidence must be bounded and non-empty")
        if any(not value.strip() or len(value) > 512 for value in evidence):
            raise ValueError("Memory correction evidence is invalid")
        current = self._store.get(memory_id, include_inactive=True)
        if current is None:
            raise KeyError("Memory record does not exist")
        if current.memory_type is not replacement.memory_type:
            raise ValueError("Memory correction types must match")
        if current.memory_type is MemoryType.LONG_TERM:
            if (
                replacement.provenance.source is not MemorySource.USER
                or replacement.provenance.untrusted_content
            ):
                raise PermissionError("External content cannot correct a personal fact")
            if current.sensitivity is Sensitivity.SENSITIVE and (
                replacement.sensitivity is not Sensitivity.SENSITIVE
                or replacement.confidence is None
                or replacement.confidence < 0.8
                or len(evidence) < 2
            ):
                raise PermissionError("Sensitive memory correction requires stronger evidence")
        if contains_prompt_injection(replacement.content + "\n" + replacement.data):
            raise PermissionError("Prompt-injected memory cannot become a correction")
        if any(contains_secret(value) for value in evidence):
            raise PermissionError("Memory correction evidence cannot contain credentials")
        self._store.put(replacement)
        old = self._store.supersede(
            memory_id,
            replacement.memory_id,
            reason="explicit user correction",
            now=now,
        )
        timestamp = now or self._clock()
        conflict = MemoryConflictRecord(
            conflict_id=uuid4(),
            kind=MemoryConflictKind.SUPERSEDED,
            memory_ids=(old.memory_id, replacement.memory_id),
            detected_at=timestamp,
            reason="user correction superseded the prior record",
            evidence=evidence,
            status=MemoryConflictStatus.RESOLVED,
            resolved_at=timestamp,
            resolution="explicit correction accepted",
        )
        self._store.put_conflict(conflict)
        return replacement

    def _ensure_conflict(
        self,
        kind: MemoryConflictKind,
        memory_ids: tuple[UUID, ...],
        detected_at: datetime,
        reason: str,
        evidence: tuple[str, ...],
        *,
        closed: bool = False,
        quarantined: bool = False,
    ) -> MemoryConflictRecord:
        normalized_ids = tuple(sorted(set(memory_ids), key=str))
        for conflict in self._store.list_conflicts():
            if (
                conflict.kind is kind
                and tuple(sorted(conflict.memory_ids, key=str)) == normalized_ids
            ):
                return conflict
        status = (
            MemoryConflictStatus.QUARANTINED
            if quarantined
            else MemoryConflictStatus.RESOLVED
            if closed
            else MemoryConflictStatus.OPEN
        )
        conflict = MemoryConflictRecord(
            conflict_id=uuid4(),
            kind=kind,
            memory_ids=normalized_ids,
            detected_at=detected_at,
            reason=reason,
            evidence=evidence,
            status=status,
            resolved_at=detected_at if status is not MemoryConflictStatus.OPEN else None,
            resolution=(
                "storage boundary quarantine"
                if status is MemoryConflictStatus.QUARANTINED
                else "record metadata is authoritative"
                if status is MemoryConflictStatus.RESOLVED
                else None
            ),
        )
        self._store.put_conflict(conflict)
        return conflict

    @staticmethod
    def _fingerprint(record: MemoryRecord) -> str:
        value = "|".join((record.memory_type.value, record.content.casefold().strip(), record.data))
        return hashlib.sha256(value.encode("utf-8")).hexdigest()

    @staticmethod
    def _subject_signature(record: MemoryRecord) -> str | None:
        data = record.data_object
        if not data:
            return None
        for key in ("subject", "key", "preference_key", "topic"):
            value = data.get(key)
            if isinstance(value, str) and value.strip():
                return f"{key}:{value.casefold().strip()}"
        if len(data) == 1:
            return next(iter(data)).casefold()
        keys = tuple(
            sorted(
                key
                for key in data
                if key.casefold() not in {"value", "content", "answer", "setting"}
            )
        )
        return ",".join(keys).casefold() if keys else None

    @staticmethod
    def _impossible_provenance(record: MemoryRecord, now: datetime) -> str | None:
        timestamp = now.astimezone(UTC) if now.tzinfo else now.replace(tzinfo=UTC)
        if record.updated_at > timestamp + timedelta(minutes=5):
            return "memory update time is in the future"
        if record.provenance.received_at > timestamp + timedelta(minutes=5):
            return "provenance received time is in the future"
        if record.memory_type is MemoryType.LONG_TERM and (
            record.provenance.source is not MemorySource.USER or record.provenance.untrusted_content
        ):
            return "long-term memory provenance is not a trusted user source"
        if record.provenance.source in {MemorySource.WEB, MemorySource.TOOL} and not (
            record.provenance.untrusted_content
        ):
            return "external provenance is not marked untrusted"
        reference = record.provenance.source_reference.casefold()
        prefixes = {
            MemorySource.USER: ("user:", "conversation:", "ui:"),
            MemorySource.WEB: ("web:",),
            MemorySource.TOOL: ("tool:",),
            MemorySource.SYSTEM: ("system:",),
        }
        expected = prefixes.get(record.provenance.source)
        if expected is not None and not reference.startswith(expected):
            return "provenance source and reference do not agree"
        if record.provenance.source is MemorySource.TASK:
            try:
                if not reference.startswith("task:"):
                    UUID(record.provenance.source_reference)
            except ValueError:
                return "task provenance reference is not a task identifier"
        return None

    @staticmethod
    def _require_user_validation(request: MemoryRevalidation, record: MemoryRecord) -> None:
        if (
            request.provenance.source is not MemorySource.USER
            or request.provenance.untrusted_content
            or not request.user_confirmed
        ):
            raise PermissionError("Personal memory requires trusted user revalidation")


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
