"""Trusted application controls for inspecting and changing user memory.

This module is an adapter, not a third memory database. Durable memory and the
User Model retain separate ownership; the control service only translates their
typed records into safe UI views and delegates mutations to the owning store.
"""

from __future__ import annotations

import json
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from datetime import UTC, datetime
from enum import StrEnum
from typing import Final
from uuid import UUID, uuid4

from jarvis.memory.models import (
    MemoryProvenance,
    MemoryRecord,
    MemorySource,
    MemoryType,
    MemoryVerificationRequest,
    MemoryVerificationStatus,
    RetentionPolicy,
    Sensitivity,
)
from jarvis.memory.policy import contains_secret
from jarvis.memory.services import MemoryConsistencyService
from jarvis.memory.store import SQLiteMemoryStore
from jarvis.user_model import (
    UserModelRecord,
    UserModelSource,
    UserModelStore,
)


class MemoryControlDomain(StrEnum):
    """The authoritative store that owns a displayed record."""

    DURABLE_MEMORY = "durable_memory"
    USER_MODEL = "user_model"


class MemoryVerificationViewStatus(StrEnum):
    NOT_VERIFIED = "not_verified"
    VERIFIED = "verified"
    REQUESTED = "requested"


_DEFAULT_SENSITIVITIES: Final[frozenset[Sensitivity]] = frozenset(
    {Sensitivity.PUBLIC, Sensitivity.PRIVATE, Sensitivity.SENSITIVE}
)
_KNOWN_SOURCES: Final[frozenset[str]] = frozenset(
    {source.value for source in (*MemorySource, *UserModelSource)}
)


def _now() -> datetime:
    return datetime.now(UTC)


def _text(value: str, name: str, limit: int) -> None:
    if type(value) is not str or not value.strip() or len(value) > limit or "\x00" in value:
        raise ValueError(f"{name} must be bounded, non-empty, and NUL-free")
    if "\r" in value or "\n" in value:
        raise ValueError(f"{name} must be single-line")


def _secret_like_reference(value: str) -> bool:
    normalized = value.casefold()
    return contains_secret(value) or any(
        marker in normalized
        for marker in ("bearer", "token", "password", "secret", "api_key", "credential")
    )


@dataclass(frozen=True, slots=True)
class MemoryControlReference:
    """Stable typed reference used by application actions."""

    domain: MemoryControlDomain
    record_id: UUID

    def __post_init__(self) -> None:
        if not isinstance(self.domain, MemoryControlDomain) or not isinstance(self.record_id, UUID):
            raise ValueError("Memory control reference is malformed")


@dataclass(frozen=True, slots=True)
class MemoryControlQuery:
    """Bounded, non-authorizing filters for the memory control surface."""

    workspace_id: str | None = None
    category: str | None = None
    sensitivities: frozenset[Sensitivity] = _DEFAULT_SENSITIVITIES
    sources: frozenset[str] = frozenset()
    recency_after: datetime | None = None
    recency_before: datetime | None = None
    min_confidence: float = 0.0
    max_confidence: float = 1.0
    include_inactive: bool = False
    limit: int = 100

    def __post_init__(self) -> None:
        if self.workspace_id is not None:
            _text(self.workspace_id, "Memory workspace filter", 128)
        if self.category is not None:
            _text(self.category, "Memory category filter", 128)
        if not self.sensitivities <= _DEFAULT_SENSITIVITIES:
            raise PermissionError("Memory controls cannot expose secret sensitivity")
        if len(self.sources) > 16:
            raise ValueError("Memory source filters are bounded")
        for source in self.sources:
            _text(source, "Memory source filter", 64)
            if source not in _KNOWN_SOURCES:
                raise ValueError("Memory source filter is not recognized")
        if not 0 <= self.min_confidence <= self.max_confidence <= 1:
            raise ValueError("Memory confidence filters are invalid")
        if self.recency_after is not None:
            object.__setattr__(self, "recency_after", self._utc(self.recency_after))
        if self.recency_before is not None:
            object.__setattr__(self, "recency_before", self._utc(self.recency_before))
        if (
            self.recency_after is not None
            and self.recency_before is not None
            and self.recency_after > self.recency_before
        ):
            raise ValueError("Memory recency range is inverted")
        if type(self.include_inactive) is not bool or not 1 <= self.limit <= 256:
            raise ValueError("Memory control bounds are invalid")

    @staticmethod
    def _utc(value: datetime) -> datetime:
        if value.tzinfo is None:
            return value.replace(tzinfo=UTC)
        return value.astimezone(UTC)


@dataclass(frozen=True, slots=True)
class MemoryControlEntry:
    """Safe explanation/view model; it never exposes a Vault value."""

    reference: MemoryControlReference
    workspace_id: str | None
    category: str
    belief: str
    why: str
    provenance: str
    source: str
    confidence: float | None
    created_at: datetime
    updated_at: datetime
    last_verified_at: datetime | None
    verification: MemoryVerificationViewStatus
    superseded_by: UUID | None
    supersedes: tuple[UUID, ...]
    retention: RetentionPolicy
    sensitivity: Sensitivity
    retrievable: bool
    active: bool

    def __post_init__(self) -> None:
        if not isinstance(self.reference, MemoryControlReference):
            raise ValueError("Memory control entry reference is malformed")
        _text(self.category, "Memory entry category", 128)
        _text(self.belief, "Memory entry belief", 4_000)
        _text(self.why, "Memory entry explanation", 512)
        _text(self.provenance, "Memory entry provenance", 512)
        _text(self.source, "Memory entry source", 64)
        if self.confidence is not None and not 0 <= self.confidence <= 1:
            raise ValueError("Memory entry confidence is invalid")
        if not isinstance(self.verification, MemoryVerificationViewStatus):
            raise ValueError("Memory entry verification status is invalid")
        if not isinstance(self.retention, RetentionPolicy) or not isinstance(
            self.sensitivity, Sensitivity
        ):
            raise ValueError("Memory entry policy metadata is invalid")
        if self.sensitivity is Sensitivity.SECRET:
            raise PermissionError("Secret memory cannot be presented")
        if type(self.active) is not bool or type(self.retrievable) is not bool:
            raise ValueError("Memory entry state is invalid")


@dataclass(frozen=True, slots=True)
class MemoryCorrection:
    """Explicit user correction input; it is never accepted from model output."""

    belief: str
    data: Mapping[str, object] | None = None
    value: object | None = None
    confidence: float | None = None
    sensitivity: Sensitivity | None = None
    retention: RetentionPolicy | None = None
    evidence: tuple[str, ...] = ("explicit user correction",)
    source_reference: str = "ui:user"

    def __post_init__(self) -> None:
        _text(self.belief, "Memory correction belief", 4_000)
        if self.data is not None and not isinstance(self.data, Mapping):
            raise ValueError("Memory correction data must be a mapping")
        if self.confidence is not None and not 0 <= self.confidence <= 1:
            raise ValueError("Memory correction confidence is invalid")
        if self.sensitivity is not None and not isinstance(self.sensitivity, Sensitivity):
            raise ValueError("Memory correction sensitivity is invalid")
        if self.retention is not None and not isinstance(self.retention, RetentionPolicy):
            raise ValueError("Memory correction retention is invalid")
        if not 1 <= len(self.evidence) <= 16:
            raise ValueError("Memory correction evidence is bounded and non-empty")
        for value in self.evidence:
            _text(value, "Memory correction evidence", 512)
            if contains_secret(value):
                raise PermissionError("Memory correction evidence cannot contain credentials")
        _text(self.source_reference, "Memory correction source reference", 256)
        if contains_secret(self.source_reference):
            raise PermissionError("Memory correction source reference cannot contain credentials")


@dataclass(frozen=True, slots=True)
class MemoryVerificationRequestView:
    """Application-facing verification request with its owning domain."""

    request_id: UUID
    reference: MemoryControlReference
    requested_at: datetime
    reason: str
    status: MemoryVerificationStatus


class MemoryControlService:
    """Application-only memory control facade over the two authoritative stores."""

    def __init__(
        self,
        memory_store: SQLiteMemoryStore,
        user_model_store: UserModelStore,
        *,
        consistency: MemoryConsistencyService | None = None,
        clock: Callable[[], datetime] = _now,
    ) -> None:
        self._memory = memory_store
        self._user_model = user_model_store
        self._consistency = consistency or MemoryConsistencyService(memory_store)
        self._clock = clock

    def inspect(self, query: MemoryControlQuery | None = None) -> tuple[MemoryControlEntry, ...]:
        """Return only safe, labelled views; source stores remain authoritative."""

        request = query or MemoryControlQuery()
        if not isinstance(request, MemoryControlQuery):
            raise ValueError("Memory inspection requires a typed query")
        entries = [
            self._memory_entry(record)
            for record in self._memory.list(include_inactive=request.include_inactive)
            if self._matches_memory(record, request)
        ]
        entries.extend(
            self._user_model_entry(record)
            for record in self._user_model_store_list(request)
            if self._matches_user_model(record, request)
        )
        entries.sort(
            key=lambda entry: (entry.updated_at, str(entry.reference.record_id)), reverse=True
        )
        return tuple(entries[: request.limit])

    def correct(
        self, reference: MemoryControlReference, correction: MemoryCorrection
    ) -> MemoryControlEntry:
        self._validate_reference(reference)
        if not isinstance(correction, MemoryCorrection):
            raise ValueError("Memory correction requires typed user input")
        if reference.domain is MemoryControlDomain.USER_MODEL:
            current_user = self._user_model.get(reference.record_id)
            if current_user is None:
                raise KeyError("User-model record does not exist")
            updated = self._user_model.correct(
                reference.record_id,
                value=correction.value if correction.value is not None else correction.belief,
                source_reference=correction.source_reference,
                sensitivity=correction.sensitivity,
                retention=correction.retention,
                reason="user correction",
                now=self._clock(),
            )
            return self._user_model_entry(updated)

        current = self._memory.get(reference.record_id, include_inactive=True)
        if current is None:
            raise KeyError("Memory record does not exist")
        if current.memory_type is not MemoryType.LONG_TERM:
            raise PermissionError("Only long-term memory can be user-corrected")
        now = self._clock()
        replacement = MemoryRecord(
            memory_id=uuid4(),
            memory_type=current.memory_type,
            content=correction.belief,
            data=json.dumps(
                dict(correction.data or {"correction": correction.belief}),
                sort_keys=True,
                separators=(",", ":"),
            ),
            created_at=now,
            provenance=MemoryProvenance(MemorySource.USER, correction.source_reference, now),
            confidence=correction.confidence if correction.confidence is not None else 1.0,
            retention=correction.retention or current.retention,
            sensitivity=correction.sensitivity or current.sensitivity,
            expires_at=(correction.retention or current.retention).expiry(now),
            updated_at=now,
        )
        corrected = self._consistency.correct(
            current.memory_id,
            replacement,
            evidence=correction.evidence,
            now=now,
        )
        return self._memory_entry(corrected)

    def delete(self, reference: MemoryControlReference) -> bool:
        self._validate_reference(reference)
        if reference.domain is MemoryControlDomain.USER_MODEL:
            return self._user_model.delete(reference.record_id)
        return self._memory.delete(reference.record_id)

    def forget_category(self, category: str, *, workspace_id: str | None = None) -> int:
        _text(category, "Memory category", 128)
        if workspace_id is not None:
            _text(workspace_id, "Memory workspace", 128)
        removed = self._user_model.delete_category(category, workspace_id=workspace_id)
        try:
            memory_type = MemoryType(category)
        except ValueError:
            return removed
        if workspace_id is None:
            return removed + self._memory.delete_category(memory_type)
        return removed

    def export(self, query: MemoryControlQuery | None = None) -> tuple[dict[str, object], ...]:
        """Return a bounded structured export with secret-like values rejected/redacted."""

        result: list[dict[str, object]] = []
        for entry in self.inspect(query):
            if contains_secret(entry.belief):
                raise PermissionError("Memory export refuses secret-like beliefs")
            result.append(
                {
                    "id": str(entry.reference.record_id),
                    "domain": entry.reference.domain.value,
                    "workspace": entry.workspace_id,
                    "category": entry.category,
                    "belief": entry.belief,
                    "why": entry.why,
                    "provenance": entry.provenance,
                    "source": entry.source,
                    "confidence": entry.confidence,
                    "created_at": entry.created_at.isoformat(),
                    "updated_at": entry.updated_at.isoformat(),
                    "last_verified_at": (
                        entry.last_verified_at.isoformat() if entry.last_verified_at else None
                    ),
                    "verification": entry.verification.value,
                    "superseded_by": (
                        str(entry.superseded_by) if entry.superseded_by is not None else None
                    ),
                    "supersedes": [str(value) for value in entry.supersedes],
                    "retention": entry.retention.value,
                    "sensitivity": entry.sensitivity.value,
                    "retrievable": entry.retrievable,
                    "active": entry.active,
                }
            )
        return tuple(result)

    def change_retention(
        self,
        reference: MemoryControlReference,
        retention: RetentionPolicy,
    ) -> MemoryControlEntry:
        self._validate_reference(reference)
        if not isinstance(retention, RetentionPolicy):
            raise ValueError("Memory retention must be typed")
        if reference.domain is MemoryControlDomain.USER_MODEL:
            return self._user_model_entry(
                self._user_model.change_retention(reference.record_id, retention, now=self._clock())
            )
        return self._memory_entry(
            self._memory.change_retention(reference.record_id, retention, now=self._clock())
        )

    def pause_learning(self, paused: bool) -> bool:
        """Persist one user control across both learning authorities."""

        if type(paused) is not bool:
            raise ValueError("Learning pause must be boolean")
        self._memory.set_learning_paused(paused)
        self._user_model.set_learning_paused(paused)
        return paused

    def learning_paused(self) -> bool:
        return self._memory.learning_paused() and self._user_model.learning_paused()

    def mark_explicit(self, reference: MemoryControlReference) -> MemoryControlEntry:
        self._validate_reference(reference)
        if reference.domain is MemoryControlDomain.USER_MODEL:
            current_user = self._user_model.get(reference.record_id)
            if current_user is None:
                raise KeyError("User-model record does not exist")
            return self._user_model_entry(
                self._user_model.correct(
                    current_user.record_id,
                    value=current_user.value,
                    source_reference="ui:user",
                    reason="user marked memory explicit",
                    now=self._clock(),
                )
            )
        current = self._memory.get(reference.record_id, include_inactive=True)
        if current is None:
            raise KeyError("Memory record does not exist")
        if current.memory_type is not MemoryType.LONG_TERM:
            raise PermissionError("Only long-term memory can be marked explicit")
        correction = MemoryCorrection(
            belief=current.content,
            data=current.data_object,
            confidence=current.confidence if current.confidence is not None else 1.0,
            sensitivity=current.sensitivity,
            retention=current.retention,
            evidence=("user marked memory explicit",),
        )
        return self.correct(reference, correction)

    def request_reverification(
        self,
        reference: MemoryControlReference,
        *,
        reason: str = "user requested re-verification",
    ) -> MemoryVerificationRequestView:
        self._validate_reference(reference)
        _text(reason, "Memory verification reason", 512)
        if contains_secret(reason):
            raise PermissionError("Memory verification reason cannot contain credentials")
        request = MemoryVerificationRequest(uuid4(), reference.record_id, self._clock(), reason)
        if reference.domain is MemoryControlDomain.USER_MODEL:
            self._user_model.request_reverification(request)
        else:
            self._memory.request_reverification(request)
        return self._request_view(reference, request)

    def verification_requests(
        self, reference: MemoryControlReference
    ) -> tuple[MemoryVerificationRequestView, ...]:
        self._validate_reference(reference)
        requests = (
            self._user_model.verification_requests(reference.record_id)
            if reference.domain is MemoryControlDomain.USER_MODEL
            else self._memory.verification_requests(reference.record_id)
        )
        return tuple(self._request_view(reference, request) for request in requests)

    def _validate_reference(self, reference: MemoryControlReference) -> None:
        if not isinstance(reference, MemoryControlReference):
            raise ValueError("Memory action requires a typed reference")

    def _user_model_store_list(self, query: MemoryControlQuery) -> tuple[UserModelRecord, ...]:
        if query.workspace_id is None:
            return self._user_model.list(
                include_global=True,
                include_inferred=True,
                include_deleted=query.include_inactive,
            )
        return self._user_model.list(
            workspace_id=query.workspace_id,
            include_global=True,
            include_inferred=True,
            include_deleted=query.include_inactive,
        )

    @staticmethod
    def _matches_memory(record: MemoryRecord, query: MemoryControlQuery) -> bool:
        if query.workspace_id is not None:
            return False
        if query.category is not None and record.memory_type.value != query.category:
            return False
        if record.sensitivity not in query.sensitivities:
            return False
        if query.sources and record.provenance.source.value not in query.sources:
            return False
        if record.confidence is None:
            if query.min_confidence > 0:
                return False
        elif not query.min_confidence <= record.confidence <= query.max_confidence:
            return False
        if query.recency_after is not None and record.updated_at < query.recency_after:
            return False
        if query.recency_before is not None and record.updated_at > query.recency_before:
            return False
        return True

    @staticmethod
    def _matches_user_model(record: UserModelRecord, query: MemoryControlQuery) -> bool:
        if query.workspace_id is not None and record.workspace_id not in {
            query.workspace_id,
            None,
        }:
            return False
        if query.category is not None and record.category != query.category:
            return False
        if record.sensitivity not in query.sensitivities:
            return False
        if query.sources and record.source.value not in query.sources:
            return False
        if not query.min_confidence <= record.confidence <= query.max_confidence:
            return False
        if query.recency_after is not None and record.updated_at < query.recency_after:
            return False
        if query.recency_before is not None and record.updated_at > query.recency_before:
            return False
        return True

    def _memory_entry(self, record: MemoryRecord) -> MemoryControlEntry:
        pending = self._memory.verification_requests(
            record.memory_id, status=MemoryVerificationStatus.PENDING
        )
        provenance = self._safe_provenance(record.provenance)
        verification = (
            MemoryVerificationViewStatus.REQUESTED
            if pending
            else MemoryVerificationViewStatus.VERIFIED
            if record.last_revalidated_at is not None
            else MemoryVerificationViewStatus.NOT_VERIFIED
        )
        origin_reason = (
            "external content is labelled data"
            if record.provenance.untrusted_content
            else "stored through the memory policy"
        )
        why = (
            f"{record.memory_type.value} memory from {record.provenance.source.value}; "
            f"{origin_reason}"
        )
        return MemoryControlEntry(
            MemoryControlReference(MemoryControlDomain.DURABLE_MEMORY, record.memory_id),
            None,
            record.memory_type.value,
            record.content,
            why,
            provenance,
            record.provenance.source.value,
            record.confidence,
            record.created_at,
            record.updated_at,
            record.last_revalidated_at,
            verification,
            record.superseded_by,
            (),
            record.retention,
            record.sensitivity,
            record.is_retrievable,
            True,
        )

    def _user_model_entry(self, record: UserModelRecord) -> MemoryControlEntry:
        pending = self._user_model.verification_requests(
            record.record_id, status=MemoryVerificationStatus.PENDING
        )
        verification = (
            MemoryVerificationViewStatus.REQUESTED
            if pending
            else MemoryVerificationViewStatus.VERIFIED
            if record.last_verified_at is not None
            else MemoryVerificationViewStatus.NOT_VERIFIED
        )
        why = (
            f"{record.origin.value} {record.kind.value} in category {record.category}; "
            f"source is {record.source.value}"
        )
        return MemoryControlEntry(
            MemoryControlReference(MemoryControlDomain.USER_MODEL, record.record_id),
            record.workspace_id,
            record.category,
            record.value_json,
            why,
            self._safe_source_reference(record.source_reference),
            record.source.value,
            record.confidence,
            record.created_at,
            record.updated_at,
            record.last_verified_at,
            verification,
            record.superseded_by,
            record.supersedes,
            record.retention,
            record.sensitivity,
            record.active and record.superseded_by is None,
            record.active,
        )

    def _request_view(
        self, reference: MemoryControlReference, request: MemoryVerificationRequest
    ) -> MemoryVerificationRequestView:
        return MemoryVerificationRequestView(
            request.request_id,
            reference,
            request.requested_at,
            request.reason,
            request.status,
        )

    @staticmethod
    def _safe_source_reference(value: str) -> str:
        return "[redacted]" if _secret_like_reference(value) else value

    @classmethod
    def _safe_provenance(cls, provenance: MemoryProvenance) -> str:
        reference = cls._safe_source_reference(provenance.source_reference)
        return f"{provenance.source.value}:{reference}"


__all__ = [
    "MemoryControlDomain",
    "MemoryControlEntry",
    "MemoryControlQuery",
    "MemoryControlReference",
    "MemoryControlService",
    "MemoryCorrection",
    "MemoryVerificationRequestView",
    "MemoryVerificationViewStatus",
]
