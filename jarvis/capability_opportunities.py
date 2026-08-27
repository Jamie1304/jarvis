"""Durable, authority-safe proactive capability opportunities.

An opportunity is preparation intent and evidence, not an installation request,
approval, capability, or task.  The engine may research and prepare a proposal;
accepted execution is delegated to the canonical capability acquisition
coordinator.
"""

from __future__ import annotations

import json
import sqlite3
import threading
from collections import Counter
from collections.abc import Callable, Iterable, Mapping
from dataclasses import dataclass, replace
from datetime import UTC, datetime, timedelta
from enum import StrEnum
from pathlib import Path
from typing import Protocol, cast
from uuid import NAMESPACE_URL, UUID, uuid5

from jarvis.goal_supervisor import CapabilityAcquisitionReport, CapabilityAcquisitionRequest


class CapabilityOpportunityError(RuntimeError):
    """An opportunity could not be safely assessed or advanced."""


class OpportunityEvidenceSource(StrEnum):
    REPEATED_WORKFLOW = "repeated_workflow"
    GUI_FALLBACK = "gui_fallback"
    REPEATED_FAILURE = "repeated_failure"
    ENVIRONMENT_DISCOVERY = "environment_discovery"
    USER_MODEL = "user_model"
    CAPABILITY_HEALTH = "capability_health"
    TECHNOLOGY_INTELLIGENCE = "technology_intelligence"
    PROCEDURE_LEARNER = "procedure_learner"
    OTHER = "other"


class OpportunityStatus(StrEnum):
    DETECTED = "detected"
    ASSESSING = "assessing"
    PREPARING = "preparing"
    READY_TO_PROPOSE = "ready_to_propose"
    PROPOSED = "proposed"
    ACCEPTED = "accepted"
    DECLINED = "declined"
    EXPIRED = "expired"
    ACTIVATING = "activating"
    ACTIVE = "active"
    FAILED = "failed"
    ARCHIVED = "archived"


class OpportunityPreparationState(StrEnum):
    NOT_STARTED = "not_started"
    RESEARCHING = "researching"
    DESIGNING = "designing"
    BUILDING = "building"
    SANDBOX_TESTING = "sandbox_testing"
    AUDITING = "auditing"
    CERTIFYING = "certifying"
    READY = "ready"
    WAITING_FOR_AUTHORITY = "waiting_for_authority"
    FAILED = "failed"
    SECURITY_BLOCKED = "security_blocked"
    UNKNOWN_OUTCOME = "unknown_outcome"


class OpportunityDecision(StrEnum):
    NONE = "none"
    PREPARE = "prepare"
    PROPOSE = "propose"
    ACCEPT = "accept"
    DECLINE = "decline"


def _text(value: str, name: str, limit: int = 2_000) -> str:
    if (
        type(value) is not str
        or not value.strip()
        or len(value) > limit
        or "\x00" in value
        or any(not character.isprintable() for character in value)
    ):
        raise CapabilityOpportunityError(f"{name} is malformed")
    return value.strip()


def _labels(values: Iterable[str], name: str, limit: int = 64) -> tuple[str, ...]:
    result = tuple(_text(value, name, 512) for value in values)
    if len(result) > limit:
        raise CapabilityOpportunityError(f"{name} are too numerous")
    return result


def _timestamp(value: datetime, name: str) -> datetime:
    if not isinstance(value, datetime) or value.tzinfo is None:
        raise CapabilityOpportunityError(f"{name} must be timezone-aware")
    return value.astimezone(UTC)


def _secret_free(values: Iterable[str]) -> None:
    forbidden = ("password=", "secret=", "token=", "private_key=", "credential_value=")
    if any(marker in value.casefold() for value in values for marker in forbidden):
        raise CapabilityOpportunityError("Raw credential material is not opportunity metadata")


@dataclass(frozen=True, slots=True)
class OpportunityEvidence:
    source: OpportunityEvidenceSource
    reference: str
    summary: str
    confidence: float
    observed_at: datetime
    verified: bool = False

    def __post_init__(self) -> None:
        if not isinstance(self.source, OpportunityEvidenceSource):
            raise CapabilityOpportunityError("Opportunity evidence source is malformed")
        _text(self.reference, "Opportunity evidence reference", 512)
        _text(self.summary, "Opportunity evidence summary")
        if not 0.0 <= self.confidence <= 1.0:
            raise CapabilityOpportunityError("Opportunity evidence confidence is malformed")
        _timestamp(self.observed_at, "Opportunity evidence timestamp")
        if type(self.verified) is not bool:
            raise CapabilityOpportunityError("Opportunity evidence verification is malformed")
        _secret_free((self.reference, self.summary))


@dataclass(frozen=True, slots=True)
class CapabilityOpportunity:
    opportunity_id: UUID
    semantic_need: str
    evidence_references: tuple[str, ...]
    evidence: tuple[OpportunityEvidence, ...]
    confidence: float
    expected_benefit: str
    privacy_impact: str
    estimated_resource_cost: str
    likely_required_authority: tuple[str, ...]
    workspace: str
    created_at: datetime
    updated_at: datetime
    cooldown_until: datetime | None = None
    expires_at: datetime | None = None
    status: OpportunityStatus = OpportunityStatus.DETECTED
    preparation_state: OpportunityPreparationState = OpportunityPreparationState.NOT_STARTED
    decision: OpportunityDecision = OpportunityDecision.NONE
    prepared_summary: str = ""
    remaining_authority: tuple[str, ...] = ()
    last_error: str = ""

    def __post_init__(self) -> None:
        if not isinstance(self.opportunity_id, UUID):
            raise CapabilityOpportunityError("Opportunity ID is malformed")
        _text(self.semantic_need, "Opportunity semantic need", 512)
        _labels(self.evidence_references, "Opportunity evidence references")
        if tuple(sorted(set(self.evidence_references))) != self.evidence_references:
            raise CapabilityOpportunityError(
                "Opportunity evidence references must be unique and sorted"
            )
        if type(self.evidence) is not tuple or any(
            not isinstance(item, OpportunityEvidence) for item in self.evidence
        ):
            raise CapabilityOpportunityError("Opportunity evidence is malformed")
        if set(self.evidence_references) != {item.reference for item in self.evidence}:
            raise CapabilityOpportunityError("Opportunity evidence references are incomplete")
        if not 0.0 <= self.confidence <= 1.0:
            raise CapabilityOpportunityError("Opportunity confidence is malformed")
        _text(self.expected_benefit, "Opportunity expected benefit")
        _text(self.privacy_impact, "Opportunity privacy impact")
        _text(self.estimated_resource_cost, "Opportunity resource estimate")
        _labels(self.likely_required_authority, "Opportunity authority")
        _text(self.workspace, "Opportunity workspace", 256)
        _timestamp(self.created_at, "Opportunity creation timestamp")
        _timestamp(self.updated_at, "Opportunity update timestamp")
        for value, name in (
            (self.cooldown_until, "Opportunity cooldown"),
            (self.expires_at, "Opportunity expiry"),
        ):
            if value is not None:
                _timestamp(value, name)
        if self.expires_at is not None and self.expires_at < self.created_at:
            raise CapabilityOpportunityError("Opportunity expiry precedes creation")
        if not isinstance(self.status, OpportunityStatus):
            raise CapabilityOpportunityError("Opportunity status is malformed")
        if not isinstance(self.preparation_state, OpportunityPreparationState):
            raise CapabilityOpportunityError("Opportunity preparation state is malformed")
        if not isinstance(self.decision, OpportunityDecision):
            raise CapabilityOpportunityError("Opportunity decision is malformed")
        if self.prepared_summary:
            _text(self.prepared_summary, "Opportunity preparation summary")
        _labels(self.remaining_authority, "Remaining opportunity authority")
        if self.last_error:
            _text(self.last_error, "Opportunity error")
        _secret_free(
            (
                self.semantic_need,
                self.expected_benefit,
                self.privacy_impact,
                self.estimated_resource_cost,
                *self.likely_required_authority,
                *self.remaining_authority,
            )
        )


@dataclass(frozen=True, slots=True)
class OpportunityPreparationResult:
    state: OpportunityPreparationState
    prepared_summary: str
    remaining_authority: tuple[str, ...] = ()
    evidence_references: tuple[str, ...] = ()
    activated: bool = False

    def __post_init__(self) -> None:
        if not isinstance(self.state, OpportunityPreparationState):
            raise CapabilityOpportunityError("Preparation result state is malformed")
        _text(self.prepared_summary, "Preparation result summary")
        _labels(self.remaining_authority, "Preparation authority")
        _labels(self.evidence_references, "Preparation evidence")
        if type(self.activated) is not bool:
            raise CapabilityOpportunityError("Preparation activation flag is malformed")
        if self.activated:
            raise CapabilityOpportunityError("Preparation cannot activate a capability")


@dataclass(frozen=True, slots=True)
class OpportunityProposal:
    opportunity_id: UUID
    benefit: str
    prepared: str
    remaining_authority: tuple[str, ...]
    privacy_impact: str
    resource_cost: str


class OpportunityPreparationProvider(Protocol):
    async def prepare(self, opportunity: CapabilityOpportunity) -> OpportunityPreparationResult: ...


class CapabilityAcquisitionBoundary(Protocol):
    async def acquire(
        self, request: CapabilityAcquisitionRequest
    ) -> CapabilityAcquisitionReport: ...


class OpportunityStore(Protocol):
    def get(self, opportunity_id: UUID) -> CapabilityOpportunity | None: ...

    def find_by_key(self, semantic_key: str) -> CapabilityOpportunity | None: ...

    def save(
        self, opportunity: CapabilityOpportunity, *, expected_revision: int | None = None
    ) -> int: ...

    def revision(self, opportunity_id: UUID) -> int: ...

    def list(self) -> tuple[CapabilityOpportunity, ...]: ...

    def close(self) -> None: ...


_PROPOSAL_STATUSES = frozenset({OpportunityStatus.READY_TO_PROPOSE, OpportunityStatus.PROPOSED})
_NON_SUCCESS_PREPARATION_STATES = frozenset(
    {
        OpportunityPreparationState.FAILED,
        OpportunityPreparationState.SECURITY_BLOCKED,
        OpportunityPreparationState.UNKNOWN_OUTCOME,
    }
)


def validate_opportunity_state(opportunity: CapabilityOpportunity) -> None:
    """Validate lifecycle/preparation combinations that can carry authority."""
    if opportunity.preparation_state is OpportunityPreparationState.FAILED and (
        opportunity.status is not OpportunityStatus.FAILED
    ):
        raise CapabilityOpportunityError("Failed preparation must have failed opportunity status")
    if opportunity.status is OpportunityStatus.FAILED and (
        opportunity.preparation_state is not OpportunityPreparationState.FAILED
    ):
        raise CapabilityOpportunityError("Failed opportunity must have failed preparation state")
    if opportunity.status in _PROPOSAL_STATUSES and (
        opportunity.preparation_state is not OpportunityPreparationState.READY
    ):
        raise CapabilityOpportunityError(
            "Proposal-ready opportunity must have successful preparation"
        )
    if (
        opportunity.status
        in {
            OpportunityStatus.ACCEPTED,
            OpportunityStatus.ACTIVATING,
            OpportunityStatus.ACTIVE,
        }
        and opportunity.preparation_state in _NON_SUCCESS_PREPARATION_STATES
    ):
        raise CapabilityOpportunityError(
            "Active opportunity cannot have failed or uncertain preparation"
        )


def _reconcile_opportunity_state(opportunity: CapabilityOpportunity) -> CapabilityOpportunity:
    """Downgrade legacy/inconsistent durable state without treating failure as success."""
    try:
        validate_opportunity_state(opportunity)
        return opportunity
    except CapabilityOpportunityError:
        preparation = opportunity.preparation_state
        if (
            preparation is OpportunityPreparationState.FAILED
            or opportunity.status is OpportunityStatus.FAILED
        ):
            status = OpportunityStatus.FAILED
            preparation = OpportunityPreparationState.FAILED
            decision = OpportunityDecision.PREPARE
        elif preparation is OpportunityPreparationState.SECURITY_BLOCKED:
            status = OpportunityStatus.ARCHIVED
            decision = OpportunityDecision.NONE
        elif preparation is OpportunityPreparationState.UNKNOWN_OUTCOME:
            status = OpportunityStatus.ASSESSING
            decision = OpportunityDecision.PREPARE
        else:
            status = OpportunityStatus.PREPARING
            decision = OpportunityDecision.PREPARE
        return replace(opportunity, status=status, decision=decision)


class SQLiteOpportunityStore:
    """The sole durable owner for opportunity evidence and decision state."""

    _SCHEMA_VERSION = 1

    def __init__(self, path: str | Path) -> None:
        self._path = str(path)
        if self._path != ":memory:":
            Path(self._path).parent.mkdir(parents=True, exist_ok=True)
        self._connection = sqlite3.connect(self._path, timeout=5.0, check_same_thread=False)
        self._connection.execute("PRAGMA journal_mode=WAL")
        self._connection.execute("PRAGMA busy_timeout=5000")
        self._connection.execute("PRAGMA foreign_keys=ON")
        self._lock = threading.RLock()
        self._migrate()

    def _migrate(self) -> None:
        with self._connection:
            self._connection.execute(
                "CREATE TABLE IF NOT EXISTS opportunity_schema "
                "(version INTEGER PRIMARY KEY, name TEXT NOT NULL)"
            )
            versions = {
                int(row[0]): str(row[1])
                for row in self._connection.execute("SELECT version, name FROM opportunity_schema")
            }
            if any(version > self._SCHEMA_VERSION for version in versions):
                raise CapabilityOpportunityError("Opportunity database uses a future schema")
            if not versions:
                self._connection.execute(
                    "CREATE TABLE opportunities ("
                    "opportunity_id TEXT PRIMARY KEY, semantic_key TEXT NOT NULL UNIQUE, "
                    "payload_json TEXT NOT NULL, revision INTEGER NOT NULL, "
                    "updated_at TEXT NOT NULL)"
                )
                self._connection.execute(
                    "INSERT INTO opportunity_schema(version, name) "
                    "VALUES (1, 'create_opportunities')"
                )
            elif versions.get(1) != "create_opportunities":
                raise CapabilityOpportunityError("Opportunity migration identity mismatch")

    def get(self, opportunity_id: UUID) -> CapabilityOpportunity | None:
        row = self._row(opportunity_id)
        if row is None:
            return None
        opportunity = _opportunity_from_json(json.loads(str(row[0])))
        reconciled = _reconcile_opportunity_state(opportunity)
        if reconciled != opportunity:
            self.save(reconciled, expected_revision=int(str(row[1])))
        return reconciled

    def find_by_key(self, semantic_key: str) -> CapabilityOpportunity | None:
        _text(semantic_key, "Opportunity semantic key", 256)
        with self._lock:
            row = self._connection.execute(
                "SELECT opportunity_id FROM opportunities WHERE semantic_key=?", (semantic_key,)
            ).fetchone()
        return self.get(UUID(str(row[0]))) if row is not None else None

    def revision(self, opportunity_id: UUID) -> int:
        row = self._row(opportunity_id)
        if row is None:
            raise CapabilityOpportunityError("Unknown opportunity")
        return int(str(row[1]))

    def save(
        self,
        opportunity: CapabilityOpportunity,
        *,
        expected_revision: int | None = None,
    ) -> int:
        _validate_opportunity(opportunity)
        payload = json.dumps(_opportunity_to_json(opportunity), sort_keys=True)
        semantic_key = _semantic_key(opportunity.workspace, opportunity.semantic_need)
        with self._lock:
            current = self._connection.execute(
                "SELECT revision FROM opportunities WHERE opportunity_id=?",
                (str(opportunity.opportunity_id),),
            ).fetchone()
            if current is None:
                if expected_revision is not None:
                    raise CapabilityOpportunityError("Opportunity revision is stale")
                revision = 1
                self._connection.execute(
                    "INSERT INTO opportunities(opportunity_id, semantic_key, payload_json, "
                    "revision, updated_at) "
                    "VALUES (?, ?, ?, ?, ?)",
                    (
                        str(opportunity.opportunity_id),
                        semantic_key,
                        payload,
                        revision,
                        opportunity.updated_at.isoformat(),
                    ),
                )
            else:
                prior = int(current[0])
                if expected_revision is not None and prior != expected_revision:
                    raise CapabilityOpportunityError("Opportunity revision is stale")
                revision = prior + 1
                cursor = self._connection.execute(
                    "UPDATE opportunities SET semantic_key=?, payload_json=?, revision=?, "
                    "updated_at=? "
                    "WHERE opportunity_id=? AND revision=?",
                    (
                        semantic_key,
                        payload,
                        revision,
                        opportunity.updated_at.isoformat(),
                        str(opportunity.opportunity_id),
                        prior,
                    ),
                )
                if cursor.rowcount != 1:
                    self._connection.rollback()
                    raise CapabilityOpportunityError("Opportunity revision is stale")
            self._connection.commit()
        return revision

    def list(self) -> tuple[CapabilityOpportunity, ...]:
        with self._lock:
            rows = self._connection.execute(
                "SELECT opportunity_id FROM opportunities ORDER BY updated_at"
            ).fetchall()
        opportunities: list[CapabilityOpportunity] = []
        for row in rows:
            opportunity = self.get(UUID(str(row[0])))
            if opportunity is not None:
                opportunities.append(opportunity)
        return tuple(opportunities)

    def close(self) -> None:
        with self._lock:
            self._connection.close()

    def _row(self, opportunity_id: UUID) -> tuple[object, ...] | None:
        if not isinstance(opportunity_id, UUID):
            raise CapabilityOpportunityError("Opportunity ID is malformed")
        with self._lock:
            return cast(
                tuple[object, ...] | None,
                self._connection.execute(
                    "SELECT payload_json, revision FROM opportunities WHERE opportunity_id=?",
                    (str(opportunity_id),),
                ).fetchone(),
            )


class InMemoryOpportunityStore:
    """Deterministic test store with the same owner boundary."""

    def __init__(self) -> None:
        self._items: dict[UUID, tuple[CapabilityOpportunity, int]] = {}

    def get(self, opportunity_id: UUID) -> CapabilityOpportunity | None:
        item = self._items.get(opportunity_id)
        if item is None:
            return None
        reconciled = _reconcile_opportunity_state(item[0])
        if reconciled != item[0]:
            self._items[opportunity_id] = (reconciled, item[1])
        return reconciled

    def find_by_key(self, semantic_key: str) -> CapabilityOpportunity | None:
        for opportunity, _ in self._items.values():
            if _semantic_key(opportunity.workspace, opportunity.semantic_need) == semantic_key:
                return self.get(opportunity.opportunity_id)
        return None

    def revision(self, opportunity_id: UUID) -> int:
        try:
            return self._items[opportunity_id][1]
        except KeyError as error:
            raise CapabilityOpportunityError("Unknown opportunity") from error

    def save(
        self, opportunity: CapabilityOpportunity, *, expected_revision: int | None = None
    ) -> int:
        _validate_opportunity(opportunity)
        current = self._items.get(opportunity.opportunity_id)
        if current is None:
            if expected_revision is not None:
                raise CapabilityOpportunityError("Opportunity revision is stale")
            revision = 1
        else:
            if expected_revision is not None and current[1] != expected_revision:
                raise CapabilityOpportunityError("Opportunity revision is stale")
            revision = current[1] + 1
        self._items[opportunity.opportunity_id] = (opportunity, revision)
        return revision

    def list(self) -> tuple[CapabilityOpportunity, ...]:
        return tuple(
            opportunity
            for opportunity_id in self._items
            if (opportunity := self.get(opportunity_id)) is not None
        )

    def close(self) -> None:
        return None


class CapabilityOpportunityEngine:
    """Create and prepare opportunities without owning real-world authority."""

    def __init__(
        self,
        store: OpportunityStore,
        acquisition: CapabilityAcquisitionBoundary,
        *,
        preparation: OpportunityPreparationProvider | None = None,
        clock: Callable[[], datetime] | None = None,
        minimum_confidence: float = 0.65,
        minimum_evidence: int = 2,
    ) -> None:
        if not hasattr(acquisition, "acquire"):
            raise CapabilityOpportunityError("Capability acquisition coordinator is malformed")
        if minimum_evidence < 2 or not 0.0 < minimum_confidence <= 1.0:
            raise CapabilityOpportunityError("Opportunity evidence policy is malformed")
        self._store = store
        self._acquisition = acquisition
        self._preparation = preparation
        self._clock = clock or (lambda: datetime.now(UTC))
        self._minimum_confidence = minimum_confidence
        self._minimum_evidence = minimum_evidence

    def observe(
        self,
        semantic_need: str,
        evidence: Iterable[OpportunityEvidence],
        *,
        expected_benefit: str,
        privacy_impact: str,
        estimated_resource_cost: str,
        likely_required_authority: Iterable[str],
        workspace: str,
        cooldown: timedelta = timedelta(days=7),
        expiry: timedelta | None = timedelta(days=30),
    ) -> CapabilityOpportunity | None:
        now = _timestamp(self._clock(), "Opportunity clock")
        semantic = _text(semantic_need, "Opportunity semantic need", 512)
        workspace_value = _text(workspace, "Opportunity workspace", 256)
        if cooldown.total_seconds() < 0 or (expiry is not None and expiry.total_seconds() <= 0):
            raise CapabilityOpportunityError("Opportunity retention bounds are malformed")
        incoming = tuple(evidence)
        if any(not isinstance(item, OpportunityEvidence) for item in incoming):
            raise CapabilityOpportunityError("Opportunity evidence is malformed")
        if not self._is_sufficient(incoming):
            return None
        key = _semantic_key(workspace_value, semantic)
        existing = self._store.find_by_key(key)
        if existing is not None and existing.expires_at is not None and existing.expires_at <= now:
            existing = replace(existing, status=OpportunityStatus.EXPIRED, updated_at=now)
            self._save(existing)
        if existing is not None and existing.status is OpportunityStatus.DECLINED:
            if existing.cooldown_until is not None and existing.cooldown_until > now:
                return existing
            if not any(item.reference not in existing.evidence_references for item in incoming):
                return existing
        merged = _merge_evidence(existing.evidence if existing is not None else (), incoming)
        if not self._is_sufficient(merged):
            return existing
        confidence = min(1.0, sum(item.confidence for item in merged) / len(merged))
        continuing_statuses = {
            OpportunityStatus.ASSESSING,
            OpportunityStatus.PREPARING,
            OpportunityStatus.READY_TO_PROPOSE,
            OpportunityStatus.PROPOSED,
            OpportunityStatus.ACCEPTED,
            OpportunityStatus.ACTIVATING,
            OpportunityStatus.ACTIVE,
        }
        continuing = existing is not None and existing.status in continuing_statuses
        prior = existing if continuing else None
        opportunity = CapabilityOpportunity(
            existing.opportunity_id if existing is not None else uuid5(NAMESPACE_URL, key),
            semantic,
            tuple(sorted(item.reference for item in merged)),
            merged,
            confidence,
            _text(expected_benefit, "Opportunity expected benefit"),
            _text(privacy_impact, "Opportunity privacy impact"),
            _text(estimated_resource_cost, "Opportunity resource estimate"),
            tuple(sorted(_labels(likely_required_authority, "Opportunity authority"))),
            workspace_value,
            existing.created_at if existing is not None else now,
            now,
            prior.cooldown_until if prior is not None else now + cooldown,
            prior.expires_at if prior is not None else now + expiry if expiry is not None else None,
            prior.status if prior is not None else OpportunityStatus.DETECTED,
            (
                prior.preparation_state
                if prior is not None
                else OpportunityPreparationState.NOT_STARTED
            ),
            prior.decision if prior is not None else OpportunityDecision.NONE,
            prior.prepared_summary if prior is not None else "",
            prior.remaining_authority if prior is not None else (),
            prior.last_error if prior is not None else "",
        )
        self._save(opportunity, existing)
        return opportunity

    async def prepare(self, opportunity_id: UUID) -> CapabilityOpportunity:
        opportunity = self._require(opportunity_id)
        self._assert_not_in_cooldown(opportunity)
        now = _timestamp(self._clock(), "Opportunity clock")
        assessing = replace(
            opportunity,
            status=OpportunityStatus.PREPARING,
            preparation_state=OpportunityPreparationState.RESEARCHING,
            decision=OpportunityDecision.PREPARE,
            updated_at=now,
        )
        self._save(assessing, opportunity)
        try:
            result = (
                await self._preparation.prepare(assessing)
                if self._preparation is not None
                else OpportunityPreparationResult(
                    OpportunityPreparationState.READY,
                    "Opportunity assessed; no effectful preparation was requested",
                    assessing.likely_required_authority,
                )
            )
            if not isinstance(result, OpportunityPreparationResult):
                raise CapabilityOpportunityError("Opportunity preparation result is malformed")
        except Exception as error:
            failed = replace(
                assessing,
                status=OpportunityStatus.FAILED,
                preparation_state=OpportunityPreparationState.FAILED,
                last_error=f"preparation failed: {type(error).__name__}",
                updated_at=_timestamp(self._clock(), "Opportunity clock"),
            )
            self._save(failed, assessing)
            raise CapabilityOpportunityError("Opportunity preparation failed") from error
        prepared_at = _timestamp(self._clock(), "Opportunity clock")
        result_references = tuple(sorted(set(result.evidence_references)))
        existing_references = {item.reference for item in assessing.evidence}
        preparation_evidence = tuple(
            OpportunityEvidence(
                OpportunityEvidenceSource.OTHER,
                reference,
                "Trusted preparation evidence reference",
                0.65,
                prepared_at,
                True,
            )
            for reference in result_references
            if reference not in existing_references
        )
        if result.state is OpportunityPreparationState.READY:
            status = OpportunityStatus.READY_TO_PROPOSE
            decision = OpportunityDecision.PROPOSE
        elif result.state is OpportunityPreparationState.WAITING_FOR_AUTHORITY:
            status = OpportunityStatus.PREPARING
            decision = OpportunityDecision.PREPARE
        elif result.state is OpportunityPreparationState.SECURITY_BLOCKED:
            status = OpportunityStatus.ARCHIVED
            decision = OpportunityDecision.NONE
        elif result.state is OpportunityPreparationState.UNKNOWN_OUTCOME:
            status = OpportunityStatus.ASSESSING
            decision = OpportunityDecision.PREPARE
        elif result.state is OpportunityPreparationState.FAILED:
            status = OpportunityStatus.FAILED
            decision = OpportunityDecision.PREPARE
        else:
            status = OpportunityStatus.PREPARING
            decision = OpportunityDecision.PREPARE
        prepared = replace(
            assessing,
            status=status,
            preparation_state=result.state,
            decision=decision,
            prepared_summary=result.prepared_summary,
            remaining_authority=tuple(sorted(set(result.remaining_authority))),
            evidence_references=tuple(
                sorted(set(assessing.evidence_references) | set(result_references))
            ),
            evidence=assessing.evidence + preparation_evidence,
            updated_at=prepared_at,
        )
        self._save(prepared, assessing)
        return prepared

    def proposal(self, opportunity_id: UUID) -> OpportunityProposal:
        opportunity = self._require(opportunity_id)
        if not _can_propose(opportunity):
            raise CapabilityOpportunityError("Opportunity is not ready for a proposal")
        proposed = replace(
            opportunity,
            status=OpportunityStatus.PROPOSED,
            updated_at=_timestamp(self._clock(), "Opportunity clock"),
        )
        self._save(proposed, opportunity)
        return OpportunityProposal(
            proposed.opportunity_id,
            proposed.expected_benefit,
            proposed.prepared_summary,
            proposed.remaining_authority or proposed.likely_required_authority,
            proposed.privacy_impact,
            proposed.estimated_resource_cost,
        )

    async def accept(
        self,
        opportunity_id: UUID,
        request: CapabilityAcquisitionRequest,
    ) -> CapabilityAcquisitionReport:
        opportunity = self._require(opportunity_id)
        if not isinstance(request, CapabilityAcquisitionRequest):
            raise CapabilityOpportunityError("Accepted opportunity request is malformed")
        if not _can_accept(opportunity):
            raise CapabilityOpportunityError("Opportunity cannot be accepted in its current state")
        self._assert_not_in_cooldown(opportunity)
        accepted = replace(
            opportunity,
            status=OpportunityStatus.ACCEPTED,
            decision=OpportunityDecision.ACCEPT,
            updated_at=_timestamp(self._clock(), "Opportunity clock"),
        )
        self._save(accepted, opportunity)
        activating = replace(
            accepted, status=OpportunityStatus.ACTIVATING, updated_at=self._clock()
        )
        self._save(activating, accepted)
        try:
            report = await self._acquisition.acquire(request)
        except Exception as error:
            failed = replace(
                activating,
                status=OpportunityStatus.FAILED,
                preparation_state=OpportunityPreparationState.FAILED,
                last_error=f"acquisition failed: {type(error).__name__}",
                updated_at=_timestamp(self._clock(), "Opportunity clock"),
            )
            self._save(failed, activating)
            raise CapabilityOpportunityError("Accepted opportunity acquisition failed") from error
        final_status = OpportunityStatus.ACTIVE if report.active else OpportunityStatus.ACTIVATING
        final_state = (
            OpportunityPreparationState.READY
            if report.active
            else OpportunityPreparationState.WAITING_FOR_AUTHORITY
        )
        self._save(
            replace(
                activating,
                status=final_status,
                preparation_state=final_state,
                prepared_summary=(activating.prepared_summary + "; " + report.detail).strip("; "),
                updated_at=_timestamp(self._clock(), "Opportunity clock"),
            ),
            activating,
        )
        return report

    def decline(self, opportunity_id: UUID) -> CapabilityOpportunity:
        opportunity = self._require(opportunity_id)
        now = _timestamp(self._clock(), "Opportunity clock")
        if opportunity.cooldown_until is None or opportunity.cooldown_until <= now:
            cooldown = now + timedelta(days=7)
        else:
            cooldown = opportunity.cooldown_until
        declined = replace(
            opportunity,
            status=OpportunityStatus.DECLINED,
            decision=OpportunityDecision.DECLINE,
            cooldown_until=cooldown,
            updated_at=now,
        )
        self._save(declined, opportunity)
        return declined

    def get(self, opportunity_id: UUID) -> CapabilityOpportunity:
        opportunity = self._require(opportunity_id)
        now = _timestamp(self._clock(), "Opportunity clock")
        if (
            opportunity.expires_at is not None
            and opportunity.expires_at <= now
            and opportunity.status
            not in {
                OpportunityStatus.EXPIRED,
                OpportunityStatus.ARCHIVED,
                OpportunityStatus.ACTIVE,
            }
        ):
            opportunity = replace(opportunity, status=OpportunityStatus.EXPIRED, updated_at=now)
            self._save(opportunity)
        return opportunity

    def list(self) -> tuple[CapabilityOpportunity, ...]:
        return tuple(self.get(item.opportunity_id) for item in self._store.list())

    def _is_sufficient(self, evidence: tuple[OpportunityEvidence, ...]) -> bool:
        strong = tuple(item for item in evidence if item.confidence >= self._minimum_confidence)
        if len(strong) < self._minimum_evidence:
            return False
        counts = Counter(item.source for item in strong)
        return max(counts.values(), default=0) >= 2 or len(counts) >= 2

    def _assert_not_in_cooldown(self, opportunity: CapabilityOpportunity) -> None:
        now = _timestamp(self._clock(), "Opportunity clock")
        if (
            opportunity.status is OpportunityStatus.DECLINED
            and opportunity.cooldown_until is not None
            and opportunity.cooldown_until > now
        ):
            raise CapabilityOpportunityError("Opportunity is in decline cooldown")

    def _require(self, opportunity_id: UUID) -> CapabilityOpportunity:
        if not isinstance(opportunity_id, UUID):
            raise CapabilityOpportunityError("Opportunity ID is malformed")
        opportunity = self._store.get(opportunity_id)
        if opportunity is None:
            raise CapabilityOpportunityError("Unknown opportunity")
        return opportunity

    def _save(
        self,
        opportunity: CapabilityOpportunity,
        previous: CapabilityOpportunity | None = None,
    ) -> None:
        expected = self._store.revision(previous.opportunity_id) if previous is not None else None
        self._store.save(opportunity, expected_revision=expected)


def _semantic_key(workspace: str, semantic_need: str) -> str:
    return f"{workspace.casefold().strip()}:{semantic_need.casefold().strip()}"


def _merge_evidence(
    prior: tuple[OpportunityEvidence, ...], incoming: tuple[OpportunityEvidence, ...]
) -> tuple[OpportunityEvidence, ...]:
    values = {item.reference: item for item in (*prior, *incoming)}
    return tuple(sorted(values.values(), key=lambda item: item.reference))


def _validate_opportunity(opportunity: CapabilityOpportunity) -> None:
    if not isinstance(opportunity, CapabilityOpportunity):
        raise CapabilityOpportunityError("Opportunity is malformed")
    validate_opportunity_state(opportunity)


def _can_propose(opportunity: CapabilityOpportunity) -> bool:
    try:
        validate_opportunity_state(opportunity)
    except CapabilityOpportunityError:
        return False
    return (
        opportunity.status in _PROPOSAL_STATUSES
        and opportunity.preparation_state is OpportunityPreparationState.READY
    )


def _can_accept(opportunity: CapabilityOpportunity) -> bool:
    try:
        validate_opportunity_state(opportunity)
    except CapabilityOpportunityError:
        return False
    if opportunity.status in {
        OpportunityStatus.READY_TO_PROPOSE,
        OpportunityStatus.PROPOSED,
        OpportunityStatus.ACCEPTED,
    }:
        return opportunity.preparation_state is OpportunityPreparationState.READY
    return opportunity.status is OpportunityStatus.ACTIVATING and opportunity.preparation_state in {
        OpportunityPreparationState.READY,
        OpportunityPreparationState.WAITING_FOR_AUTHORITY,
    }


def _opportunity_to_json(opportunity: CapabilityOpportunity) -> dict[str, object]:
    return {
        "opportunity_id": str(opportunity.opportunity_id),
        "semantic_need": opportunity.semantic_need,
        "evidence_references": list(opportunity.evidence_references),
        "evidence": [
            {
                "source": item.source.value,
                "reference": item.reference,
                "summary": item.summary,
                "confidence": item.confidence,
                "observed_at": item.observed_at.isoformat(),
                "verified": item.verified,
            }
            for item in opportunity.evidence
        ],
        "confidence": opportunity.confidence,
        "expected_benefit": opportunity.expected_benefit,
        "privacy_impact": opportunity.privacy_impact,
        "estimated_resource_cost": opportunity.estimated_resource_cost,
        "likely_required_authority": list(opportunity.likely_required_authority),
        "workspace": opportunity.workspace,
        "created_at": opportunity.created_at.isoformat(),
        "updated_at": opportunity.updated_at.isoformat(),
        "cooldown_until": opportunity.cooldown_until.isoformat()
        if opportunity.cooldown_until
        else None,
        "expires_at": opportunity.expires_at.isoformat() if opportunity.expires_at else None,
        "status": opportunity.status.value,
        "preparation_state": opportunity.preparation_state.value,
        "decision": opportunity.decision.value,
        "prepared_summary": opportunity.prepared_summary,
        "remaining_authority": list(opportunity.remaining_authority),
        "last_error": opportunity.last_error,
    }


def _opportunity_from_json(payload: Mapping[str, object]) -> CapabilityOpportunity:
    raw_evidence = payload.get("evidence", [])
    if not isinstance(raw_evidence, list):
        raise CapabilityOpportunityError("Persisted opportunity evidence is malformed")
    evidence = tuple(
        OpportunityEvidence(
            OpportunityEvidenceSource(str(item["source"])),
            str(item["reference"]),
            str(item["summary"]),
            float(item["confidence"]),
            datetime.fromisoformat(str(item["observed_at"])),
            bool(item.get("verified", False)),
        )
        for item in raw_evidence
        if isinstance(item, dict)
    )
    return CapabilityOpportunity(
        UUID(str(payload["opportunity_id"])),
        str(payload["semantic_need"]),
        tuple(str(item) for item in _payload_items(payload, "evidence_references")),
        evidence,
        float(cast(float, payload["confidence"])),
        str(payload["expected_benefit"]),
        str(payload["privacy_impact"]),
        str(payload["estimated_resource_cost"]),
        tuple(str(item) for item in _payload_items(payload, "likely_required_authority")),
        str(payload["workspace"]),
        datetime.fromisoformat(str(payload["created_at"])),
        datetime.fromisoformat(str(payload["updated_at"])),
        datetime.fromisoformat(str(payload["cooldown_until"]))
        if payload.get("cooldown_until")
        else None,
        datetime.fromisoformat(str(payload["expires_at"])) if payload.get("expires_at") else None,
        OpportunityStatus(str(payload["status"])),
        OpportunityPreparationState(str(payload["preparation_state"])),
        OpportunityDecision(str(payload["decision"])),
        str(payload.get("prepared_summary", "")),
        tuple(str(item) for item in _payload_items(payload, "remaining_authority")),
        str(payload.get("last_error", "")),
    )


def _payload_items(payload: Mapping[str, object], key: str) -> tuple[object, ...]:
    value = payload.get(key, [])
    if not isinstance(value, list):
        raise CapabilityOpportunityError(f"Persisted opportunity field {key} is malformed")
    return tuple(value)


__all__ = [
    "CapabilityOpportunity",
    "CapabilityOpportunityEngine",
    "CapabilityOpportunityError",
    "InMemoryOpportunityStore",
    "OpportunityDecision",
    "OpportunityEvidence",
    "OpportunityEvidenceSource",
    "OpportunityPreparationProvider",
    "OpportunityPreparationResult",
    "OpportunityPreparationState",
    "OpportunityProposal",
    "OpportunityStatus",
    "OpportunityStore",
    "SQLiteOpportunityStore",
    "validate_opportunity_state",
]
