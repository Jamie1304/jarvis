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
from collections.abc import Awaitable, Callable, Mapping, Sequence
from dataclasses import dataclass, field
from datetime import UTC, datetime
from enum import StrEnum
from types import MappingProxyType
from typing import Final, Protocol, cast
from uuid import UUID, uuid4

from jarvis.capabilities import Reversibility
from jarvis.permissions.models import Permission, PermissionRequest, PermissionScope
from jarvis.planning.editing import PlanInspection
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
class CompensationRequest:
    """One user/application request to perform an exact compensation."""

    request_id: UUID
    task_id: UUID
    correlation_id: UUID
    effect: EffectPreview
    current_state_fingerprint: str
    prior_state: Mapping[str, object] | None = None
    evidence: tuple[EvidenceRecord, ...] = ()

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


@dataclass(frozen=True, slots=True)
class CompensationResult:
    request_id: UUID
    status: CompensationStatus
    detail: str
    tool_result: ToolResult | None = None
    verification: VerificationResult | None = None
    approval_request_ids: tuple[UUID, ...] = ()
    trace_event_ids: tuple[UUID, ...] = ()

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


__all__ = [
    "CompensationDefinition",
    "CompensationExecutor",
    "CompensationRequest",
    "CompensationResult",
    "CompensationStatus",
    "EffectError",
    "EffectPreview",
    "EffectTraceRecord",
    "EffectTraceSink",
    "PlanStudioEffectProjection",
    "PlanStudioEffectView",
]
