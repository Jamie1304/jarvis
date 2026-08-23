"""Typed, privacy-aware records for the distinct JARVIS memory domains."""

from __future__ import annotations

import json
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from enum import StrEnum
from uuid import UUID


class MemoryType(StrEnum):
    """Durable memory categories; conversation context is intentionally separate."""

    LONG_TERM = "long_term"
    EPISODIC = "episodic"


class Sensitivity(StrEnum):
    """Classification controls persistence and presentation of memory content."""

    PUBLIC = "public"
    PRIVATE = "private"
    SENSITIVE = "sensitive"
    SECRET = "secret"


class RetentionPolicy(StrEnum):
    """Explicit durable retention choices; no implicit permanent retention exists."""

    THIRTY_DAYS = "thirty_days"
    ONE_YEAR = "one_year"
    UNTIL_DELETED = "until_deleted"

    def expiry(self, created_at: datetime) -> datetime | None:
        if self is RetentionPolicy.THIRTY_DAYS:
            return created_at + timedelta(days=30)
        if self is RetentionPolicy.ONE_YEAR:
            return created_at + timedelta(days=365)
        return None


class MemorySource(StrEnum):
    """Provenance category, never a trust or execution grant."""

    USER = "user"
    TASK = "task"
    TOOL = "tool"
    WEB = "web"
    SYSTEM = "system"


class RetentionDecision(StrEnum):
    ALLOW = "allow"
    DENY = "deny"


class MemoryConflictKind(StrEnum):
    """Consistency findings; none of these findings grant authority."""

    DUPLICATE = "duplicate"
    CONTRADICTION = "contradiction"
    STALE = "stale"
    SUPERSEDED = "superseded"
    LOW_CONFIDENCE = "low_confidence"
    IMPOSSIBLE_PROVENANCE = "impossible_provenance"
    PROMPT_INJECTION = "prompt_injection"


class MemoryConflictStatus(StrEnum):
    OPEN = "open"
    RESOLVED = "resolved"
    QUARANTINED = "quarantined"
    DISMISSED = "dismissed"


def utc(value: datetime) -> datetime:
    """Normalize all durable timestamps to UTC."""

    if value.tzinfo is None:
        return value.replace(tzinfo=UTC)
    return value.astimezone(UTC)


def _bounded(value: str, name: str, limit: int) -> None:
    if not value.strip() or len(value) > limit or "\x00" in value:
        raise ValueError(f"{name} must be non-empty, NUL-free, and at most {limit} characters")
    if "\r" in value or "\n" in value:
        raise ValueError(f"{name} must be single-line")


@dataclass(frozen=True, slots=True)
class MemoryProvenance:
    """Safe source metadata retained with every durable memory record."""

    source: MemorySource
    source_reference: str
    received_at: datetime
    untrusted_content: bool = False

    def __post_init__(self) -> None:
        if not isinstance(self.source, MemorySource):
            raise ValueError("Memory source must be recognized")
        if type(self.untrusted_content) is not bool:
            raise ValueError("Untrusted-content provenance flag must be boolean")
        _bounded(self.source_reference, "Source reference", 256)
        object.__setattr__(self, "received_at", utc(self.received_at))


@dataclass(frozen=True, slots=True)
class MemoryRecord:
    """A durable record. ``data`` is canonical JSON and never executable instructions."""

    memory_id: UUID
    memory_type: MemoryType
    content: str
    data: str
    created_at: datetime
    provenance: MemoryProvenance
    confidence: float | None
    retention: RetentionPolicy
    sensitivity: Sensitivity
    expires_at: datetime | None
    updated_at: datetime
    last_accessed_at: datetime | None = None
    last_revalidated_at: datetime | None = None
    quarantined: bool = False
    quarantine_reason: str | None = None
    quarantined_at: datetime | None = None
    superseded_by: UUID | None = None

    def __post_init__(self) -> None:
        if not isinstance(self.memory_type, MemoryType):
            raise ValueError("Memory type must be recognized")
        if not isinstance(self.provenance, MemoryProvenance):
            raise ValueError("Memory provenance must be application-created")
        if not isinstance(self.retention, RetentionPolicy):
            raise ValueError("Retention policy must be recognized")
        if not isinstance(self.sensitivity, Sensitivity):
            raise ValueError("Sensitivity must be recognized")
        if not self.content.strip() or len(self.content) > 4_000 or "\x00" in self.content:
            raise ValueError("Memory content must be bounded, non-empty, and NUL-free")
        if len(self.data) > 16_000 or "\x00" in self.data:
            raise ValueError("Memory data must be bounded and NUL-free")
        try:
            parsed = json.loads(self.data)
        except json.JSONDecodeError as error:
            raise ValueError("Memory data must be valid JSON") from error
        if not isinstance(parsed, dict):
            raise ValueError("Memory data must be a JSON object")
        if self.confidence is not None and not 0 <= self.confidence <= 1:
            raise ValueError("Memory confidence must be between zero and one")
        if type(self.quarantined) is not bool:
            raise ValueError("Memory quarantine state must be boolean")
        if self.quarantine_reason is not None:
            _bounded(self.quarantine_reason, "Memory quarantine reason", 256)
        if self.quarantined and self.quarantine_reason is None:
            raise ValueError("Quarantined memory requires a reason")
        if not self.quarantined and (
            self.quarantine_reason is not None or self.quarantined_at is not None
        ):
            raise ValueError("Active memory cannot contain quarantine metadata")
        if self.superseded_by is not None:
            if not isinstance(self.superseded_by, UUID) or self.superseded_by == self.memory_id:
                raise ValueError("Memory supersession target is invalid")
        object.__setattr__(self, "created_at", utc(self.created_at))
        object.__setattr__(self, "updated_at", utc(self.updated_at))
        if self.expires_at is not None:
            object.__setattr__(self, "expires_at", utc(self.expires_at))
        if self.last_accessed_at is not None:
            object.__setattr__(self, "last_accessed_at", utc(self.last_accessed_at))
        if self.last_revalidated_at is not None:
            object.__setattr__(self, "last_revalidated_at", utc(self.last_revalidated_at))
        if self.quarantined_at is not None:
            object.__setattr__(self, "quarantined_at", utc(self.quarantined_at))
        if self.updated_at < self.created_at:
            raise ValueError("Memory cannot be updated before creation")
        if self.last_revalidated_at is not None and self.last_revalidated_at < self.created_at:
            raise ValueError("Memory revalidation cannot predate creation")
        if self.quarantined and self.quarantined_at is None:
            raise ValueError("Quarantined memory requires a timestamp")
        expected_expiry = self.retention.expiry(self.created_at)
        if self.expires_at != expected_expiry:
            raise ValueError("Memory expiry must match its retention policy")

    @property
    def data_object(self) -> dict[str, object]:
        """Decode the bounded machine-readable payload for trusted application code."""

        value = json.loads(self.data)
        if not isinstance(value, dict):  # guarded by __post_init__, retained for type narrowing
            raise ValueError("Memory data must be a JSON object")
        return value

    def is_expired(self, now: datetime) -> bool:
        return self.expires_at is not None and self.expires_at <= utc(now)

    @property
    def is_retrievable(self) -> bool:
        """Only current, non-quarantined records may enter ordinary retrieval."""

        return not self.quarantined and self.superseded_by is None


@dataclass(frozen=True, slots=True)
class LongTermMemoryCandidate:
    """A user-relevant fact proposed for explicit policy evaluation before storage."""

    content: str
    data: str
    provenance: MemoryProvenance
    confidence: float
    retention: RetentionPolicy
    sensitivity: Sensitivity
    user_confirmed: bool

    def __post_init__(self) -> None:
        if not self.content.strip() or len(self.content) > 4_000:
            raise ValueError("Long-term memory content must be bounded and non-empty")
        if not isinstance(self.provenance, MemoryProvenance):
            raise ValueError("Candidate provenance must be application-created")
        if not isinstance(self.retention, RetentionPolicy):
            raise ValueError("Candidate retention policy must be recognized")
        if not isinstance(self.sensitivity, Sensitivity):
            raise ValueError("Candidate sensitivity must be recognized")
        if not 0 <= self.confidence <= 1:
            raise ValueError("Candidate confidence must be between zero and one")
        try:
            parsed = json.loads(self.data)
        except json.JSONDecodeError as error:
            raise ValueError("Candidate data must be valid JSON") from error
        if not isinstance(parsed, dict):
            raise ValueError("Candidate data must be a JSON object")


@dataclass(frozen=True, slots=True)
class LongTermEligibility:
    """Machine-readable outcome of the explicit long-term retention policy."""

    decision: RetentionDecision
    reason_code: str
    candidate: LongTermMemoryCandidate


@dataclass(frozen=True, slots=True)
class MemoryRevalidation:
    """Trusted application evidence used to evolve confidence or release quarantine."""

    memory_id: UUID
    confidence: float
    provenance: MemoryProvenance
    evidence: tuple[str, ...]
    user_confirmed: bool = False
    now: datetime | None = None

    def __post_init__(self) -> None:
        if not isinstance(self.memory_id, UUID):
            raise ValueError("Revalidation memory ID must be a UUID")
        if not 0 <= self.confidence <= 1:
            raise ValueError("Revalidation confidence must be between zero and one")
        if not isinstance(self.provenance, MemoryProvenance):
            raise ValueError("Revalidation provenance must be application-created")
        if not isinstance(self.evidence, tuple) or not 1 <= len(self.evidence) <= 16:
            raise ValueError("Revalidation evidence must be bounded and non-empty")
        for value in self.evidence:
            _bounded(value, "Revalidation evidence", 512)
        if type(self.user_confirmed) is not bool:
            raise ValueError("Revalidation confirmation must be boolean")
        if self.now is not None:
            object.__setattr__(self, "now", utc(self.now))


@dataclass(frozen=True, slots=True)
class MemoryConflictRecord:
    """Durable, bounded consistency evidence; it is not source truth."""

    conflict_id: UUID
    kind: MemoryConflictKind
    memory_ids: tuple[UUID, ...]
    detected_at: datetime
    reason: str
    evidence: tuple[str, ...] = ()
    status: MemoryConflictStatus = MemoryConflictStatus.OPEN
    resolved_at: datetime | None = None
    resolution: str | None = None

    def __post_init__(self) -> None:
        if not isinstance(self.conflict_id, UUID):
            raise ValueError("Memory conflict ID must be a UUID")
        if not isinstance(self.kind, MemoryConflictKind):
            raise ValueError("Memory conflict kind must be recognized")
        if not isinstance(self.memory_ids, tuple) or not 1 <= len(self.memory_ids) <= 16:
            raise ValueError("Memory conflict references must be bounded and non-empty")
        if any(not isinstance(value, UUID) for value in self.memory_ids):
            raise ValueError("Memory conflict references must be UUIDs")
        if len(set(self.memory_ids)) != len(self.memory_ids):
            raise ValueError("Memory conflict references must be unique")
        _bounded(self.reason, "Memory conflict reason", 512)
        if not isinstance(self.evidence, tuple) or len(self.evidence) > 16:
            raise ValueError("Memory conflict evidence must be bounded")
        for value in self.evidence:
            _bounded(value, "Memory conflict evidence", 512)
        if not isinstance(self.status, MemoryConflictStatus):
            raise ValueError("Memory conflict status must be recognized")
        if self.resolution is not None:
            _bounded(self.resolution, "Memory conflict resolution", 512)
        if self.status is MemoryConflictStatus.OPEN:
            if self.resolved_at is not None or self.resolution is not None:
                raise ValueError("Open memory conflict cannot have a resolution")
        elif self.resolved_at is None or self.resolution is None:
            raise ValueError("Closed memory conflict requires resolution evidence")
        object.__setattr__(self, "detected_at", utc(self.detected_at))
        if self.resolved_at is not None:
            object.__setattr__(self, "resolved_at", utc(self.resolved_at))


@dataclass(frozen=True, slots=True)
class MemoryConfidenceEvent:
    """Append-only confidence evolution without replacing provenance."""

    event_id: UUID
    memory_id: UUID
    occurred_at: datetime
    previous_confidence: float | None
    current_confidence: float
    provenance: MemoryProvenance
    evidence: tuple[str, ...]

    def __post_init__(self) -> None:
        if not isinstance(self.event_id, UUID) or not isinstance(self.memory_id, UUID):
            raise ValueError("Memory confidence event IDs must be UUIDs")
        if self.previous_confidence is not None and not 0 <= self.previous_confidence <= 1:
            raise ValueError("Previous confidence must be between zero and one")
        if not 0 <= self.current_confidence <= 1:
            raise ValueError("Current confidence must be between zero and one")
        if not isinstance(self.provenance, MemoryProvenance):
            raise ValueError("Confidence event provenance must be application-created")
        if not isinstance(self.evidence, tuple) or not 1 <= len(self.evidence) <= 16:
            raise ValueError("Confidence event evidence must be bounded and non-empty")
        for value in self.evidence:
            _bounded(value, "Confidence event evidence", 512)
        object.__setattr__(self, "occurred_at", utc(self.occurred_at))


@dataclass(frozen=True, slots=True)
class ConversationEntry:
    """Bounded process-local context; it is never written by the durable store."""

    role: str
    content: str
    created_at: datetime

    def __post_init__(self) -> None:
        _bounded(self.role, "Conversation role", 32)
        if not self.content.strip() or len(self.content) > 16_000 or "\x00" in self.content:
            raise ValueError("Conversation content must be bounded, non-empty, and NUL-free")
        object.__setattr__(self, "created_at", utc(self.created_at))


@dataclass(frozen=True, slots=True)
class EpisodicAction:
    """One compact, completed tool/action outcome retained in an episode."""

    tool_id: str
    action: str
    outcome: str

    def __post_init__(self) -> None:
        _bounded(self.tool_id, "Tool ID", 128)
        _bounded(self.action, "Action", 256)
        _bounded(self.outcome, "Outcome", 512)


@dataclass(frozen=True, slots=True)
class DurableMemoryHit:
    record: MemoryRecord
    score: int
    content_is_untrusted_data: bool


@dataclass(frozen=True, slots=True)
class SystemMemoryHit:
    """A read-only project-knowledge hit, intentionally not copied into user storage."""

    item_id: str
    title: str
    summary: str
    authority: str
    source_files: tuple[str, ...]
    stale: bool
    score: int


@dataclass(frozen=True, slots=True)
class MemoryRetrieval:
    """Results stay segregated so callers cannot confuse their trust/source domains."""

    conversation: tuple[ConversationEntry, ...]
    long_term: tuple[DurableMemoryHit, ...]
    episodic: tuple[DurableMemoryHit, ...]
    system: tuple[SystemMemoryHit, ...]
