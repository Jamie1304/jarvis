"""Trusted effect previews and brokered compensation contracts.

Previews are application metadata produced by trusted capability code. They are
not inferred from model prose and they never authorize an effect. Compensation
is a new exact tool invocation through ``ToolRegistry`` and its bound
``PermissionBroker``, followed by independent ``VerificationEngine`` evidence.
"""

from __future__ import annotations

import asyncio
import hashlib
import json
import logging
import math
import sqlite3
from collections.abc import Awaitable, Callable, Mapping, Sequence
from dataclasses import dataclass, field, replace
from datetime import UTC, datetime
from enum import StrEnum
from pathlib import Path
from types import MappingProxyType
from typing import Any, Final, Protocol, cast
from uuid import UUID, uuid4

from jarvis.capabilities import Reversibility
from jarvis.permissions.models import Permission, PermissionRequest, PermissionScope
from jarvis.planning.editing import PlanInspection
from jarvis.planning.engine import PlanningEngine
from jarvis.planning.models import ExecutionBudgets, PlanningTask, PlanningTaskStatus
from jarvis.planning.validation import PlanProposal
from jarvis.tools.models import (
    ToolCaller,
    ToolEffectDisposition,
    ToolExecutionContext,
    ToolResult,
    ToolResultStatus,
)
from jarvis.tools.registry import ToolRegistry
from jarvis.verification import (
    EvidenceRecord,
    VerificationEngine,
    VerificationPlan,
    VerificationResult,
)


class EffectError(ValueError):
    """An effect preview, compensation request, or trace record is malformed."""


class CompensationStatus(StrEnum):
    VERIFIED = "verified"
    PERMISSION_REQUIRED = "permission_required"
    DENIED = "denied"
    STALE_STATE = "stale_state"
    FAILED = "failed"
    VERIFICATION_FAILED = "verification_failed"
    UNKNOWN_OUTCOME = "unknown_outcome"
    NOT_AVAILABLE = "not_available"


class CompensationLifecycle(StrEnum):
    """Durable orchestration state; it is not a second execution engine."""

    REQUESTED = "requested"
    EXECUTING = "executing"
    WAITING_FOR_APPROVAL = "waiting_for_approval"
    COMPENSATION_EXECUTED = "compensation_executed"
    COMPENSATION_VERIFIED = "compensation_verified"
    COMPENSATION_FAILED = "compensation_failed"
    COMPENSATION_UNKNOWN = "compensation_unknown"
    COMPENSATION_STALE = "compensation_stale"


_MAX_TEXT: Final = 2_000
_MAX_ITEMS: Final = 64
_MAX_STATE_BYTES: Final = 16_000
_HASH_LENGTH: Final = 64
_FORBIDDEN_STATE_KEYS: Final = frozenset(
    {"password", "token", "secret", "credential", "private_key", "api_key"}
)


def _text(value: object, field_name: str, limit: int = _MAX_TEXT) -> str:
    if (
        type(value) is not str
        or not value.strip()
        or len(value) > limit
        or any(not character.isprintable() for character in value)
    ):
        raise EffectError(f"{field_name} must be bounded printable text")
    return value


def _label_items(values: object, field_name: str, limit: int = _MAX_ITEMS) -> tuple[str, ...]:
    if not isinstance(values, tuple) or len(values) > limit:
        raise EffectError(f"{field_name} must be a bounded tuple")
    return tuple(_text(item, field_name, 512) for item in values)


def _safe_value(value: object, *, field_name: str, depth: int = 0) -> object:
    if depth > 5:
        raise EffectError(f"{field_name} is too deeply nested")
    if value is None or type(value) is bool or type(value) is int:
        return value
    if type(value) is float:
        if not math.isfinite(value):
            raise EffectError(f"{field_name} contains a non-finite number")
        return value
    if type(value) is str:
        return _text(value, field_name, 4_000)
    if isinstance(value, Mapping):
        if len(value) > _MAX_ITEMS:
            raise EffectError(f"{field_name} has too many properties")
        normalized: dict[str, object] = {}
        for key, item in value.items():
            safe_key = _text(key, f"{field_name} key", 128)
            if safe_key.casefold() in _FORBIDDEN_STATE_KEYS:
                raise EffectError(f"{field_name} cannot contain secret material")
            normalized[safe_key] = _safe_value(
                item, field_name=f"{field_name}.{safe_key}", depth=depth + 1
            )
        return MappingProxyType(normalized)
    if isinstance(value, Sequence) and not isinstance(value, str | bytes | bytearray):
        if len(value) > _MAX_ITEMS:
            raise EffectError(f"{field_name} has too many items")
        return tuple(
            _safe_value(item, field_name=f"{field_name}[{index}]", depth=depth + 1)
            for index, item in enumerate(value)
        )
    raise EffectError(f"{field_name} contains an unsupported value")


def _fingerprint(value: object) -> str:
    encoded = json.dumps(value, sort_keys=True, separators=(",", ":"), default=str).encode()
    return hashlib.sha256(encoded).hexdigest()


def _hash(value: object, field_name: str) -> str:
    if (
        type(value) is not str
        or len(value) != _HASH_LENGTH
        or any(character not in "0123456789abcdef" for character in value)
    ):
        raise EffectError(f"{field_name} must be a lowercase SHA-256 fingerprint")
    return value


@dataclass(frozen=True, slots=True)
class CompensationDefinition:
    """Trusted exact tool contract for compensating one effect."""

    capability: str
    tool_id: str
    arguments: Mapping[str, object]
    verification: VerificationPlan
    prior_state_fields: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        _text(self.capability, "Compensation capability", 256)
        _text(self.tool_id, "Compensation tool ID", 256)
        if not isinstance(self.arguments, Mapping):
            raise EffectError("Compensation arguments must be an object")
        normalized = _safe_value(self.arguments, field_name="Compensation arguments")
        if not isinstance(normalized, Mapping):
            raise EffectError("Compensation arguments must be an object")
        object.__setattr__(self, "arguments", normalized)
        if not isinstance(self.verification, VerificationPlan):
            raise EffectError("Compensation verification must be a VerificationPlan")
        fields = _label_items(self.prior_state_fields, "Prior state fields")
        if len(fields) != len(set(fields)):
            raise EffectError("Prior state fields must be unique")
        object.__setattr__(self, "prior_state_fields", fields)

    @property
    def fingerprint(self) -> str:
        return _fingerprint(
            {
                "capability": self.capability,
                "tool_id": self.tool_id,
                "arguments": self.arguments,
                "verification": self.verification.original_goal,
                "criteria": self.verification.criteria,
                "prior_state_fields": self.prior_state_fields,
            }
        )


@dataclass(frozen=True, slots=True)
class EffectPreview:
    """Application-owned preview metadata for a proposed effect."""

    target: str
    expected_change: Mapping[str, object]
    resources: tuple[str, ...]
    permission: tuple[PermissionRequest, ...]
    reversibility: Reversibility
    artifacts: tuple[str, ...]
    verification: VerificationPlan
    compensation: CompensationDefinition | None = None
    effect_id: UUID = field(default_factory=uuid4)
    base_state_fingerprint: str | None = None

    def __post_init__(self) -> None:
        _text(self.target, "Effect target")
        change = _safe_value(self.expected_change, field_name="Expected change")
        if not isinstance(change, Mapping) or not change:
            raise EffectError("Expected change must be a non-empty structured object")
        object.__setattr__(self, "expected_change", change)
        object.__setattr__(self, "resources", _label_items(self.resources, "Effect resources"))
        object.__setattr__(self, "artifacts", _label_items(self.artifacts, "Effect artifacts"))
        if not isinstance(self.permission, tuple) or any(
            not isinstance(item, PermissionRequest)
            or not isinstance(item.permission, Permission)
            or not isinstance(item.scope, PermissionScope)
            for item in self.permission
        ):
            raise EffectError("Effect permissions must be typed PermissionRequests")
        if len(self.permission) > _MAX_ITEMS:
            raise EffectError("Effect permissions are unbounded")
        if not isinstance(self.reversibility, Reversibility):
            raise EffectError("Effect reversibility is invalid")
        if not isinstance(self.verification, VerificationPlan):
            raise EffectError("Effect verification must be a VerificationPlan")
        if self.compensation is not None and not isinstance(
            self.compensation, CompensationDefinition
        ):
            raise EffectError("Effect compensation is malformed")
        if not isinstance(self.effect_id, UUID):
            raise EffectError("Effect ID is malformed")
        if self.base_state_fingerprint is not None:
            _hash(self.base_state_fingerprint, "Effect base state fingerprint")
        if self.reversibility is Reversibility.COMPENSATABLE and self.compensation is None:
            raise EffectError("Compensatable effects require a real compensation definition")

    @property
    def fingerprint(self) -> str:
        return _fingerprint(
            {
                "effect_id": str(self.effect_id),
                "target": self.target,
                "expected_change": self.expected_change,
                "resources": self.resources,
                "permission": tuple(
                    cast(Permission, item.permission).value for item in self.permission
                ),
                "reversibility": self.reversibility.value,
                "artifacts": self.artifacts,
                "verification": self.verification.criteria,
                "compensation": self.compensation.fingerprint
                if self.compensation is not None
                else None,
                "base_state_fingerprint": self.base_state_fingerprint,
            }
        )

    @property
    def can_offer_undo(self) -> bool:
        """Return true only when a real, typed compensation path exists."""

        return (
            self.reversibility
            in {
                Reversibility.REVERSIBLE,
                Reversibility.COMPENSATABLE,
            }
            and self.compensation is not None
        )

    @classmethod
    def from_model_prose(cls, _prose: str) -> EffectPreview:
        """Reject model prose at the trusted preview boundary."""

        raise EffectError("Model prose cannot create authoritative effect metadata")


@dataclass(frozen=True, slots=True)
class OriginalEffectReference:
    """Trusted references to one completed canonical planning step."""

    effect_id: UUID
    effect_fingerprint: str
    task_id: UUID
    plan_id: UUID
    plan_revision: int
    step_id: UUID
    tool_id: str
    capability: str
    target: str
    scope: str
    evidence_references: tuple[str, ...]
    verification_reference: str
    effect_attestation_reference: str | None = None

    def __post_init__(self) -> None:
        for value, name in (
            (self.effect_id, "Original effect ID"),
            (self.task_id, "Original task ID"),
            (self.plan_id, "Original plan ID"),
            (self.step_id, "Original step ID"),
        ):
            if not isinstance(value, UUID):
                raise EffectError(f"{name} is malformed")
        _hash(self.effect_fingerprint, "Original effect fingerprint")
        if type(self.plan_revision) is not int or self.plan_revision <= 0:
            raise EffectError("Original plan revision is malformed")
        for text_value, name in (
            (self.tool_id, "Original tool ID"),
            (self.capability, "Original capability"),
            (self.target, "Original target"),
            (self.scope, "Original scope"),
            (self.verification_reference, "Original verification reference"),
        ):
            _text(text_value, name, 1_000)
        if (
            not isinstance(self.evidence_references, tuple)
            or not self.evidence_references
            or len(self.evidence_references) > _MAX_ITEMS
            or any(
                type(item) is not str or not item.strip() or len(item) > 1_000
                for item in self.evidence_references
            )
        ):
            raise EffectError("Original effect evidence references are malformed")
        if self.effect_attestation_reference is not None:
            _text(self.effect_attestation_reference, "Effect attestation reference", 512)

    @property
    def fingerprint(self) -> str:
        return _fingerprint(
            {
                "effect_id": str(self.effect_id),
                "effect_fingerprint": self.effect_fingerprint,
                "task_id": str(self.task_id),
                "plan_id": str(self.plan_id),
                "plan_revision": self.plan_revision,
                "step_id": str(self.step_id),
                "tool_id": self.tool_id,
                "capability": self.capability,
                "target": self.target,
                "scope": self.scope,
                "evidence_references": self.evidence_references,
                "verification_reference": self.verification_reference,
                "effect_attestation_reference": self.effect_attestation_reference,
            }
        )


@dataclass(frozen=True, slots=True)
class CompensationRequest:
    """One user/application request to perform an exact compensation."""

    request_id: UUID
    task_id: UUID
    correlation_id: UUID
    effect: EffectPreview
    current_state_fingerprint: str
    prior_state: Mapping[str, object] | None = None
    evidence: tuple[EvidenceRecord, ...] = ()
    original_effect: OriginalEffectReference | None = None

    def __post_init__(self) -> None:
        if not isinstance(self.request_id, UUID) or not isinstance(self.task_id, UUID):
            raise EffectError("Compensation request IDs are malformed")
        if not isinstance(self.correlation_id, UUID) or not isinstance(self.effect, EffectPreview):
            raise EffectError("Compensation request context is malformed")
        _hash(self.current_state_fingerprint, "Current state fingerprint")
        if self.prior_state is not None:
            normalized = _safe_value(self.prior_state, field_name="Prior state")
            if not isinstance(normalized, Mapping):
                raise EffectError("Prior state must be an object")
            object.__setattr__(self, "prior_state", normalized)
            if self.effect.compensation is not None:
                required = set(self.effect.compensation.prior_state_fields)
                if set(normalized) - required:
                    raise EffectError(
                        "Prior state contains fields outside the compensation contract"
                    )
                if required - set(normalized):
                    raise EffectError("Prior state is missing a required compensation field")
        if len(self.evidence) > _MAX_ITEMS or any(
            not isinstance(item, EvidenceRecord) for item in self.evidence
        ):
            raise EffectError("Compensation evidence is malformed or unbounded")
        if self.original_effect is not None and not isinstance(
            self.original_effect, OriginalEffectReference
        ):
            raise EffectError("Original effect reference is malformed")

    @property
    def fingerprint(self) -> str:
        return _fingerprint(
            {
                "request_id": str(self.request_id),
                "task_id": str(self.task_id),
                "correlation_id": str(self.correlation_id),
                "effect": self.effect.fingerprint,
                "current_state_fingerprint": self.current_state_fingerprint,
                "prior_state": self.prior_state,
                "original_effect": (
                    self.original_effect.fingerprint if self.original_effect is not None else None
                ),
            }
        )


@dataclass(frozen=True, slots=True)
class CompensationResult:
    request_id: UUID
    status: CompensationStatus
    detail: str
    tool_result: ToolResult | None = None
    verification: VerificationResult | None = None
    approval_request_ids: tuple[UUID, ...] = ()
    trace_event_ids: tuple[UUID, ...] = ()
    planning_task_id: UUID | None = None
    lifecycle: CompensationLifecycle | None = None

    def __post_init__(self) -> None:
        if not isinstance(self.request_id, UUID) or not isinstance(self.status, CompensationStatus):
            raise EffectError("Compensation result is malformed")
        _text(self.detail, "Compensation detail", 2_000)
        if len(self.approval_request_ids) > _MAX_ITEMS or any(
            not isinstance(item, UUID) for item in self.approval_request_ids
        ):
            raise EffectError("Compensation approval IDs are malformed")
        if len(self.trace_event_ids) > _MAX_ITEMS or any(
            not isinstance(item, UUID) for item in self.trace_event_ids
        ):
            raise EffectError("Compensation trace IDs are malformed")
        if self.planning_task_id is not None and not isinstance(self.planning_task_id, UUID):
            raise EffectError("Compensation planning task ID is malformed")
        if self.lifecycle is not None and not isinstance(self.lifecycle, CompensationLifecycle):
            raise EffectError("Compensation lifecycle is malformed")


@dataclass(frozen=True, slots=True)
class EffectTraceRecord:
    event: str
    trace_id: UUID
    request_id: UUID
    effect_id: UUID
    preview_fingerprint: str
    status: str
    recorded_at: datetime

    def __post_init__(self) -> None:
        _text(self.event, "Trace event", 128)
        if not isinstance(self.trace_id, UUID) or not isinstance(self.request_id, UUID):
            raise EffectError("Trace IDs are malformed")
        if not isinstance(self.effect_id, UUID):
            raise EffectError("Trace effect ID is malformed")
        _hash(self.preview_fingerprint, "Trace preview fingerprint")
        _text(self.status, "Trace status", 128)
        if self.recorded_at.tzinfo is None:
            raise EffectError("Trace timestamp must be timezone-aware")


class EffectTraceSink(Protocol):
    async def record(self, trace: EffectTraceRecord) -> None: ...


@dataclass(frozen=True, slots=True)
class PlanStudioEffectView:
    step_key: str
    preview: EffectPreview
    undo_available: bool


class PlanStudioEffectProjection:
    """Add trusted effect previews to the existing typed PlanInspection view."""

    @staticmethod
    def project(
        inspection: PlanInspection,
        previews: Mapping[str, EffectPreview],
    ) -> tuple[PlanStudioEffectView, ...]:
        if not isinstance(inspection, PlanInspection) or not isinstance(previews, Mapping):
            raise EffectError("Plan Studio projection input is malformed")
        step_keys = {step.key for step in inspection.steps}
        if any(not isinstance(key, str) or key not in step_keys for key in previews):
            raise EffectError("Effect preview references an unknown plan step")
        if any(not isinstance(value, EffectPreview) for value in previews.values()):
            raise EffectError("Plan Studio effect preview is malformed")
        return tuple(
            PlanStudioEffectView(step.key, previews[step.key], previews[step.key].can_offer_undo)
            for step in inspection.steps
            if step.key in previews
        )


@dataclass(frozen=True, slots=True)
class CompensationRecord:
    """Durable metadata for one compensation request and its planning task."""

    request_id: UUID
    request_fingerprint: str
    original_effect: OriginalEffectReference
    planning_task_id: UUID
    lifecycle: CompensationLifecycle
    status: CompensationStatus
    detail: str
    approval_request_ids: tuple[UUID, ...] = ()
    trace_event_ids: tuple[UUID, ...] = ()
    updated_at: datetime = field(default_factory=lambda: datetime.now(UTC))

    def __post_init__(self) -> None:
        if not isinstance(self.request_id, UUID) or not isinstance(self.planning_task_id, UUID):
            raise EffectError("Compensation record IDs are malformed")
        _hash(self.request_fingerprint, "Compensation request fingerprint")
        if not isinstance(self.original_effect, OriginalEffectReference):
            raise EffectError("Compensation record effect reference is malformed")
        if not isinstance(self.lifecycle, CompensationLifecycle) or not isinstance(
            self.status, CompensationStatus
        ):
            raise EffectError("Compensation record state is malformed")
        _text(self.detail, "Compensation record detail", 2_000)
        if len(self.approval_request_ids) > _MAX_ITEMS or any(
            not isinstance(item, UUID) for item in self.approval_request_ids
        ):
            raise EffectError("Compensation record approval IDs are malformed")
        if len(self.trace_event_ids) > _MAX_ITEMS or any(
            not isinstance(item, UUID) for item in self.trace_event_ids
        ):
            raise EffectError("Compensation record trace IDs are malformed")
        if self.updated_at.tzinfo is None:
            raise EffectError("Compensation record timestamp must be timezone-aware")


class CompensationStore:
    """Sole durable owner for compensation lifecycle metadata."""

    _SCHEMA = 1

    def __init__(self, path: Path) -> None:
        if not isinstance(path, Path):
            raise EffectError("Compensation database path is malformed")
        path.parent.mkdir(parents=True, exist_ok=True)
        self._connection = sqlite3.connect(path, timeout=5.0, check_same_thread=False)
        self._connection.execute("PRAGMA foreign_keys = ON")
        self._connection.execute("PRAGMA busy_timeout = 5000")
        self._connection.execute("PRAGMA journal_mode = WAL")
        self._connection.execute(
            "CREATE TABLE IF NOT EXISTS compensation_schema "
            "(version INTEGER PRIMARY KEY, name TEXT NOT NULL)"
        )
        versions = tuple(
            int(row[0])
            for row in self._connection.execute("SELECT version FROM compensation_schema")
        )
        if any(version > self._SCHEMA for version in versions):
            self.close()
            raise EffectError("Compensation database uses a future schema")
        self._connection.execute(
            "CREATE TABLE IF NOT EXISTS compensation_records "
            "(request_id TEXT PRIMARY KEY, request_fingerprint TEXT NOT NULL, "
            "record_json TEXT NOT NULL, updated_at TEXT NOT NULL)"
        )
        if not versions:
            self._connection.execute(
                "INSERT INTO compensation_schema(version, name) VALUES (?, ?)",
                (self._SCHEMA, "create_compensation_records"),
            )
        self._connection.commit()

    @property
    def database_path(self) -> Path:
        return Path(str(self._connection.execute("PRAGMA database_list").fetchone()[2]))

    def close(self) -> None:
        self._connection.close()

    def load(self, request_id: UUID) -> CompensationRecord | None:
        if not isinstance(request_id, UUID):
            raise EffectError("Compensation request ID is malformed")
        row = self._connection.execute(
            "SELECT record_json FROM compensation_records WHERE request_id=?", (str(request_id),)
        ).fetchone()
        if row is None:
            return None
        return _compensation_record_from_json(json.loads(str(row[0])))

    def save(self, record: CompensationRecord) -> None:
        if not isinstance(record, CompensationRecord):
            raise EffectError("Compensation record is malformed")
        payload = json.dumps(
            _compensation_record_to_json(record), sort_keys=True, separators=(",", ":")
        )
        if len(payload.encode()) > _MAX_STATE_BYTES:
            raise EffectError("Compensation record is too large")
        existing = self.load(record.request_id)
        if existing is not None and existing.request_fingerprint != record.request_fingerprint:
            raise EffectError("Compensation request fingerprint cannot be rebound")
        self._connection.execute(
            "INSERT OR REPLACE INTO compensation_records "
            "(request_id, request_fingerprint, record_json, updated_at) VALUES (?, ?, ?, ?)",
            (
                str(record.request_id),
                record.request_fingerprint,
                payload,
                record.updated_at.isoformat(),
            ),
        )
        self._connection.commit()


CompensationObservationProvider = Callable[
    [CompensationRequest, PlanningTask], Awaitable[tuple[EvidenceRecord, ...]]
]
CompensationStateProvider = Callable[[CompensationRequest], str]


class CompensationService:
    """Application-owned compensation orchestration over PlanningEngine."""

    def __init__(
        self,
        planning: PlanningEngine,
        registry: ToolRegistry,
        verification: VerificationEngine,
        store: CompensationStore,
        *,
        observation_provider: CompensationObservationProvider | None = None,
        state_provider: CompensationStateProvider | None = None,
        trace: object | None = None,
        clock: Callable[[], datetime] | None = None,
    ) -> None:
        if not isinstance(planning, PlanningEngine) or not isinstance(registry, ToolRegistry):
            raise EffectError("Compensation service requires canonical planning and tools")
        if not isinstance(verification, VerificationEngine) or not isinstance(
            store, CompensationStore
        ):
            raise EffectError("Compensation service dependencies are malformed")
        self._planning = planning
        self._registry = registry
        self._verification = verification
        self._store = store
        self._observation_provider = observation_provider
        self._state_provider = state_provider
        self._trace = trace
        self._clock = clock or (lambda: datetime.now(UTC))

    def close(self) -> None:
        """Close the authoritative compensation store exactly once."""

        self._store.close()

    def bind_original_effect(
        self,
        effect: EffectPreview,
        *,
        task_id: UUID,
        plan_revision: int,
        step_id: UUID,
        target: str,
        scope: str,
        effect_attestation_reference: str | None = None,
    ) -> OriginalEffectReference:
        """Derive a binding only from a completed canonical planning step."""

        if not isinstance(effect, EffectPreview) or not effect.can_offer_undo:
            raise EffectError("Only real reversible or compensatable effects can be bound")
        task = self._planning.get_task(task_id)
        plan = self._planning.inspect_plan(task_id)
        if task is None or plan is None or task.status is not PlanningTaskStatus.COMPLETED:
            raise EffectError("Original effect has no completed canonical task")
        if plan.version != plan_revision:
            raise EffectError("Original effect plan revision is stale")
        step = next((item for item in plan.steps if item.step_id == step_id), None)
        if step is None or step.status.value != "succeeded" or step.result is None:
            raise EffectError("Original effect step is not a verified success")
        if not step.result.evidence:
            raise EffectError("Original effect has no trusted evidence")
        compensation = effect.compensation
        if compensation is None or (
            compensation.tool_id != step.tool_id or compensation.capability != step.capability
        ):
            raise EffectError(
                "Compensation must use the exact capability/tool that produced the effect"
            )
        return OriginalEffectReference(
            effect.effect_id,
            effect.fingerprint,
            task_id,
            plan.plan_id,
            plan_revision,
            step_id,
            step.tool_id,
            step.capability,
            target,
            scope,
            step.result.evidence,
            f"planning-step:{task_id}:{step_id}:verified",
            effect_attestation_reference,
        )

    async def compensate(
        self,
        request: CompensationRequest,
        *,
        cancellation: asyncio.Event | None = None,
    ) -> CompensationResult:
        if not isinstance(request, CompensationRequest) or request.original_effect is None:
            raise EffectError("Compensation requires a trusted original effect reference")
        effect = request.effect
        original = request.original_effect
        if (
            original.effect_id != effect.effect_id
            or original.effect_fingerprint != effect.fingerprint
        ):
            return await self._finish(
                request,
                CompensationLifecycle.COMPENSATION_STALE,
                CompensationStatus.STALE_STATE,
                "Compensation binding does not match the effect",
            )
        if original.task_id != request.task_id:
            return await self._finish(
                request,
                CompensationLifecycle.COMPENSATION_STALE,
                CompensationStatus.STALE_STATE,
                "Compensation task binding is invalid",
            )
        if not effect.can_offer_undo or effect.compensation is None:
            return await self._finish(
                request,
                CompensationLifecycle.COMPENSATION_FAILED,
                CompensationStatus.NOT_AVAILABLE,
                "No real compensation is available",
            )
        existing = self._store.load(request.request_id)
        if existing is not None:
            if existing.request_fingerprint != request.fingerprint:
                return await self._finish(
                    request,
                    CompensationLifecycle.COMPENSATION_STALE,
                    CompensationStatus.STALE_STATE,
                    "Compensation request fingerprint changed",
                )
            if existing.lifecycle in {
                CompensationLifecycle.COMPENSATION_UNKNOWN,
                CompensationLifecycle.COMPENSATION_STALE,
            }:
                return self._result_from_record(existing)
            if existing.lifecycle in {
                CompensationLifecycle.COMPENSATION_VERIFIED,
                CompensationLifecycle.COMPENSATION_FAILED,
            }:
                return self._result_from_record(existing)
        if self._state_provider is None:
            return await self._finish(
                request,
                CompensationLifecycle.COMPENSATION_STALE,
                CompensationStatus.STALE_STATE,
                "No trusted state observer is configured",
            )
        try:
            current = self._state_provider(request)
        except Exception:
            return await self._finish(
                request,
                CompensationLifecycle.COMPENSATION_STALE,
                CompensationStatus.STALE_STATE,
                "Current state could not be revalidated",
            )
        if current != request.current_state_fingerprint or current != effect.base_state_fingerprint:
            return await self._finish(
                request,
                CompensationLifecycle.COMPENSATION_STALE,
                CompensationStatus.STALE_STATE,
                "Current state no longer matches the compensation baseline",
            )
        if existing is not None:
            planning_task_id = existing.planning_task_id
        else:
            planning_task_id = uuid4()
            existing = CompensationRecord(
                request.request_id,
                request.fingerprint,
                original,
                planning_task_id,
                CompensationLifecycle.REQUESTED,
                CompensationStatus.NOT_AVAILABLE,
                "Compensation request accepted",
                updated_at=self._clock(),
            )
            self._store.save(existing)
        task = self._planning.get_task(planning_task_id)
        if task is None:
            proposal = self._proposal(request)
            task = await self._planning.create_proposal_task(
                proposal,
                budgets=ExecutionBudgets(
                    max_steps=1,
                    max_model_calls=0,
                    max_expensive_actions=1,
                    max_retries=0,
                ),
                provenance=("compensation.service", original.verification_reference),
            )
            if task.task_id != planning_task_id:
                planning_task_id = task.task_id
                existing = replace(existing, planning_task_id=planning_task_id)
                self._store.save(existing)
        if self._trace is not None:
            try:
                cast(Any, self._trace).bind_goal_task(original.task_id, task.task_id)
            except Exception:
                # Trace is a derived projection; compensation safety must not
                # depend on its availability.
                pass
        if task.status is PlanningTaskStatus.RECOVERING:
            return await self._finish(
                request,
                CompensationLifecycle.COMPENSATION_UNKNOWN,
                CompensationStatus.UNKNOWN_OUTCOME,
                "Compensation task has an unknown outcome and cannot be replayed",
                planning_task_id=task.task_id,
                persist_existing=existing,
            )
        if task.status not in {
            PlanningTaskStatus.COMPLETED,
            PlanningTaskStatus.FAILED,
            PlanningTaskStatus.CANCELLED,
            PlanningTaskStatus.BUDGET_EXHAUSTED,
        }:
            task = (
                await self._planning.resume(task.task_id)
                if task.status is PlanningTaskStatus.WAITING_FOR_PERMISSION
                else await self._planning.run(task.task_id)
            )
        if task.status is PlanningTaskStatus.WAITING_FOR_PERMISSION:
            return await self._finish(
                request,
                CompensationLifecycle.WAITING_FOR_APPROVAL,
                CompensationStatus.PERMISSION_REQUIRED,
                "Fresh permission is required for the compensating action",
                planning_task_id=task.task_id,
                approval_request_ids=task.waiting_request_ids,
                persist_existing=existing,
            )
        if task.status is PlanningTaskStatus.RECOVERING:
            return await self._finish(
                request,
                CompensationLifecycle.COMPENSATION_UNKNOWN,
                CompensationStatus.UNKNOWN_OUTCOME,
                "Compensation execution outcome is unknown",
                planning_task_id=task.task_id,
                persist_existing=existing,
            )
        if task.status is not PlanningTaskStatus.COMPLETED:
            return await self._finish(
                request,
                CompensationLifecycle.COMPENSATION_FAILED,
                CompensationStatus.FAILED,
                "Compensation plan did not complete",
                planning_task_id=task.task_id,
                persist_existing=existing,
            )
        if self._observation_provider is None:
            return await self._finish(
                request,
                CompensationLifecycle.COMPENSATION_EXECUTED,
                CompensationStatus.VERIFICATION_FAILED,
                "Independent compensation observation is unavailable",
                planning_task_id=task.task_id,
                persist_existing=existing,
            )
        try:
            evidence = await self._observation_provider(request, task)
        except Exception:
            return await self._finish(
                request,
                CompensationLifecycle.COMPENSATION_UNKNOWN,
                CompensationStatus.UNKNOWN_OUTCOME,
                "Compensation verification observation is unavailable",
                planning_task_id=task.task_id,
                persist_existing=existing,
            )
        verification = self._verification.evaluate(
            effect.compensation.verification, evidence, now=self._clock()
        )
        if verification.passed:
            return await self._finish(
                request,
                CompensationLifecycle.COMPENSATION_VERIFIED,
                CompensationStatus.VERIFIED,
                "Compensation effect was independently verified",
                verification=verification,
                planning_task_id=task.task_id,
                persist_existing=existing,
            )
        return await self._finish(
            request,
            CompensationLifecycle.COMPENSATION_EXECUTED,
            CompensationStatus.VERIFICATION_FAILED,
            "Compensation executed but its requested outcome was not proven",
            verification=verification,
            planning_task_id=task.task_id,
            persist_existing=existing,
        )

    def _proposal(self, request: CompensationRequest) -> PlanProposal:
        definition = request.effect.compensation
        if definition is None:
            raise EffectError("Compensation definition is unavailable")
        record = self._registry.inspect(definition.tool_id)
        criteria = list(definition.verification.criteria)
        if not criteria:
            raise EffectError("Compensation verification criteria are required")
        permissions = sorted(
            permission.value for permission in record.manifest.declared_permissions
        )
        return PlanProposal.model_validate(
            {
                "goal": f"compensate effect {request.effect.effect_id}",
                "assumptions": ["trusted original effect binding is valid"],
                "constraints": ["do not replay unknown outcomes"],
                "required_capabilities": [definition.capability],
                "required_permissions": permissions,
                "completion_criteria": criteria,
                "steps": [
                    {
                        "key": "compensate",
                        "tool_id": definition.tool_id,
                        "capability": definition.capability,
                        "input": dict(definition.arguments),
                        "dependencies": [],
                        "required_permissions": permissions,
                        "expected_output": "compensation result",
                        "verification_rule": "evidence_contains_all",
                        "expected_evidence": criteria,
                        "expensive_action": bool(record.manifest.declared_permissions),
                        "max_retries": 0,
                    }
                ],
            }
        )

    async def _finish(
        self,
        request: CompensationRequest,
        lifecycle: CompensationLifecycle,
        status: CompensationStatus,
        detail: str,
        *,
        verification: VerificationResult | None = None,
        planning_task_id: UUID | None = None,
        approval_request_ids: tuple[UUID, ...] = (),
        persist_existing: CompensationRecord | None = None,
    ) -> CompensationResult:
        trace_ids = self._trace_event(request, status, lifecycle)
        existing = persist_existing or self._store.load(request.request_id)
        if existing is not None:
            record = replace(
                existing,
                lifecycle=lifecycle,
                status=status,
                detail=detail,
                approval_request_ids=approval_request_ids,
                trace_event_ids=existing.trace_event_ids + trace_ids,
                updated_at=self._clock(),
            )
            self._store.save(record)
            planning_task_id = record.planning_task_id
        return CompensationResult(
            request.request_id,
            status,
            detail,
            verification=verification,
            approval_request_ids=approval_request_ids,
            trace_event_ids=trace_ids,
            planning_task_id=planning_task_id,
            lifecycle=lifecycle,
        )

    def _result_from_record(self, record: CompensationRecord) -> CompensationResult:
        return CompensationResult(
            record.request_id,
            record.status,
            record.detail,
            approval_request_ids=record.approval_request_ids,
            trace_event_ids=record.trace_event_ids,
            planning_task_id=record.planning_task_id,
            lifecycle=record.lifecycle,
        )

    def _trace_event(
        self,
        request: CompensationRequest,
        status: CompensationStatus,
        lifecycle: CompensationLifecycle,
    ) -> tuple[UUID, ...]:
        if self._trace is None:
            return ()
        try:
            from jarvis.trace import TraceEventType

            event = cast(Any, self._trace).record(
                TraceEventType.RESULT,
                f"Compensation {lifecycle.value}",
                task_id=request.task_id,
                correlation_id=request.correlation_id,
                result={
                    "compensation_request_id": str(request.request_id),
                    "status": status.value,
                    "lifecycle": lifecycle.value,
                },
            )
            return (event.event_id,)
        except Exception:
            return ()


EffectObservationProvider = Callable[
    [CompensationRequest, ToolResult], Awaitable[tuple[EvidenceRecord, ...]]
]


class CompensationExecutor:
    """Execute compensation only through the normal tool/broker boundary."""

    def __init__(
        self,
        registry: ToolRegistry,
        *,
        verification: VerificationEngine | None = None,
        trace: EffectTraceSink | None = None,
        observation_provider: EffectObservationProvider | None = None,
        clock: Callable[[], datetime] | None = None,
    ) -> None:
        if not isinstance(registry, ToolRegistry):
            raise EffectError("Compensation requires the canonical ToolRegistry")
        self._registry = registry
        self._verification = verification or VerificationEngine()
        self._trace = trace
        self._observation_provider = observation_provider
        self._clock = clock or (lambda: datetime.now(UTC))
        self._logger = logging.getLogger("jarvis.compensation")

    async def compensate(
        self,
        request: CompensationRequest,
        *,
        cancellation: asyncio.Event | None = None,
        user_id: str | None = None,
    ) -> CompensationResult:
        if not isinstance(request, CompensationRequest):
            raise EffectError("Compensation request is malformed")
        effect = request.effect
        definition = effect.compensation
        if not effect.can_offer_undo or definition is None:
            return await self._finish(
                request, CompensationStatus.NOT_AVAILABLE, "No real compensation is available"
            )
        if effect.base_state_fingerprint is None:
            return await self._finish(
                request,
                CompensationStatus.STALE_STATE,
                "Compensation has no trusted state baseline",
            )
        if request.current_state_fingerprint != effect.base_state_fingerprint:
            return await self._finish(
                request,
                CompensationStatus.STALE_STATE,
                "Current state no longer matches the preview baseline",
            )
        if definition.prior_state_fields and request.prior_state is None:
            return await self._finish(
                request,
                CompensationStatus.STALE_STATE,
                "Required bounded prior state is unavailable",
            )
        try:
            record = self._registry.inspect(definition.tool_id)
        except Exception:
            return await self._finish(
                request,
                CompensationStatus.NOT_AVAILABLE,
                "Compensation tool is not registered",
            )
        if definition.capability not in record.manifest.capabilities and definition.capability != (
            record.manifest.tool_id
        ):
            return await self._finish(
                request,
                CompensationStatus.NOT_AVAILABLE,
                "Registered tool does not provide the compensation capability",
            )
        cancellation_event = cancellation or asyncio.Event()
        await self._emit(request, "compensation.started", "started")
        try:
            result = await record.tool.invoke(
                ToolExecutionContext(
                    request.task_id,
                    request.correlation_id,
                    ToolCaller.USER_INTERFACE,
                    cancellation_event,
                    self._logger,
                    user_id=user_id,
                ),
                definition.arguments,
                self._registry.permission_broker,
            )
        except Exception:
            return await self._finish(
                request,
                CompensationStatus.UNKNOWN_OUTCOME,
                "Compensation execution outcome is unknown",
            )
        if result.status is ToolResultStatus.PERMISSION_DENIED:
            approval_ids = tuple(
                UUID(item.value)
                for item in result.metadata
                if item.key == "approval_request_id" and _is_uuid(item.value)
            )
            status = (
                CompensationStatus.PERMISSION_REQUIRED
                if approval_ids
                else CompensationStatus.DENIED
            )
            return await self._finish(
                request,
                status,
                "Permission broker did not authorize compensation",
                result,
                approval_ids,
            )
        if (
            result.status is ToolResultStatus.UNKNOWN_OUTCOME
            or result.effect_disposition is ToolEffectDisposition.UNKNOWN
        ):
            return await self._finish(
                request,
                CompensationStatus.UNKNOWN_OUTCOME,
                "Compensation effect outcome is unknown",
                result,
            )
        if not result.succeeded or result.effect_disposition is ToolEffectDisposition.NO_EFFECT:
            return await self._finish(
                request,
                CompensationStatus.FAILED,
                "Compensation tool reported failure before a confirmed effect",
                result,
            )
        evidence = request.evidence
        if self._observation_provider is not None:
            try:
                evidence = await self._observation_provider(request, result)
            except Exception:
                return await self._finish(
                    request,
                    CompensationStatus.UNKNOWN_OUTCOME,
                    "Compensation verification observation is unavailable",
                    result,
                )
        verification = self._verification.evaluate(
            definition.verification,
            evidence,
            now=self._clock(),
        )
        if verification.passed:
            return await self._finish(
                request,
                CompensationStatus.VERIFIED,
                "Compensation effect was independently verified",
                result,
                verification=verification,
            )
        return await self._finish(
            request,
            CompensationStatus.VERIFICATION_FAILED,
            "Compensation executed but its requested outcome was not proven",
            result,
            verification=verification,
        )

    async def _finish(
        self,
        request: CompensationRequest,
        status: CompensationStatus,
        detail: str,
        tool_result: ToolResult | None = None,
        approval_request_ids: tuple[UUID, ...] = (),
        *,
        verification: VerificationResult | None = None,
    ) -> CompensationResult:
        trace_ids = await self._emit(request, "compensation.completed", status.value)
        return CompensationResult(
            request.request_id,
            status,
            detail,
            tool_result,
            verification,
            approval_request_ids,
            trace_ids,
        )

    async def _emit(
        self, request: CompensationRequest, event: str, status: str
    ) -> tuple[UUID, ...]:
        if self._trace is None:
            return ()
        trace = EffectTraceRecord(
            event,
            uuid4(),
            request.request_id,
            request.effect.effect_id,
            request.effect.fingerprint,
            status,
            datetime.now(UTC),
        )
        try:
            await self._trace.record(trace)
        except Exception:
            self._logger.warning("Effect trace sink failed; compensation result is retained")
        return (trace.trace_id,)


def _is_uuid(value: str) -> bool:
    try:
        UUID(value)
    except (ValueError, AttributeError):
        return False
    return True


def _original_effect_to_json(value: OriginalEffectReference) -> dict[str, object]:
    return {
        "effect_id": str(value.effect_id),
        "effect_fingerprint": value.effect_fingerprint,
        "task_id": str(value.task_id),
        "plan_id": str(value.plan_id),
        "plan_revision": value.plan_revision,
        "step_id": str(value.step_id),
        "tool_id": value.tool_id,
        "capability": value.capability,
        "target": value.target,
        "scope": value.scope,
        "evidence_references": value.evidence_references,
        "verification_reference": value.verification_reference,
        "effect_attestation_reference": value.effect_attestation_reference,
    }


def _original_effect_from_json(value: object) -> OriginalEffectReference:
    if not isinstance(value, Mapping):
        raise EffectError("Persisted original effect reference is malformed")
    try:
        return OriginalEffectReference(
            UUID(str(value["effect_id"])),
            str(value["effect_fingerprint"]),
            UUID(str(value["task_id"])),
            UUID(str(value["plan_id"])),
            int(value["plan_revision"]),
            UUID(str(value["step_id"])),
            str(value["tool_id"]),
            str(value["capability"]),
            str(value["target"]),
            str(value["scope"]),
            tuple(str(item) for item in cast(Sequence[object], value["evidence_references"])),
            str(value["verification_reference"]),
            str(value["effect_attestation_reference"])
            if value.get("effect_attestation_reference") is not None
            else None,
        )
    except (KeyError, TypeError, ValueError) as error:
        raise EffectError("Persisted original effect reference is malformed") from error


def _compensation_record_to_json(value: CompensationRecord) -> dict[str, object]:
    return {
        "request_id": str(value.request_id),
        "request_fingerprint": value.request_fingerprint,
        "original_effect": _original_effect_to_json(value.original_effect),
        "planning_task_id": str(value.planning_task_id),
        "lifecycle": value.lifecycle.value,
        "status": value.status.value,
        "detail": value.detail,
        "approval_request_ids": [str(item) for item in value.approval_request_ids],
        "trace_event_ids": [str(item) for item in value.trace_event_ids],
        "updated_at": value.updated_at.isoformat(),
    }


def _compensation_record_from_json(value: object) -> CompensationRecord:
    if not isinstance(value, Mapping):
        raise EffectError("Persisted compensation record is malformed")
    try:
        return CompensationRecord(
            UUID(str(value["request_id"])),
            str(value["request_fingerprint"]),
            _original_effect_from_json(value["original_effect"]),
            UUID(str(value["planning_task_id"])),
            CompensationLifecycle(str(value["lifecycle"])),
            CompensationStatus(str(value["status"])),
            str(value["detail"]),
            tuple(
                UUID(str(item))
                for item in cast(Sequence[object], value.get("approval_request_ids", ()))
            ),
            tuple(
                UUID(str(item)) for item in cast(Sequence[object], value.get("trace_event_ids", ()))
            ),
            datetime.fromisoformat(str(value["updated_at"])),
        )
    except (KeyError, TypeError, ValueError) as error:
        raise EffectError("Persisted compensation record is malformed") from error


__all__ = [
    "CompensationDefinition",
    "CompensationExecutor",
    "CompensationLifecycle",
    "CompensationRequest",
    "CompensationResult",
    "CompensationRecord",
    "CompensationService",
    "CompensationStore",
    "CompensationStatus",
    "EffectError",
    "EffectPreview",
    "EffectTraceRecord",
    "EffectTraceSink",
    "OriginalEffectReference",
    "PlanStudioEffectProjection",
    "PlanStudioEffectView",
]
