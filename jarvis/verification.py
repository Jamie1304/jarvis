"""Typed post-execution verification and evidence evaluation.

Execution results describe what an application attempted or what a tool
returned.  They do not prove that the requested real-world result exists.
This module is an observation boundary only: it never executes an action,
grants permission, or changes PlanningEngine state.
"""

from __future__ import annotations

import math
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from enum import IntEnum, StrEnum
from typing import Final

from jarvis.presentation import PresentationSurface, UiStateSnapshot


class VerificationError(ValueError):
    """A verification plan or evidence record is malformed."""


class VerificationLevel(IntEnum):
    """Ordered strength of a proven outcome."""

    UNKNOWN = 0
    IMPLEMENTED = 1
    AUTOMATED_TESTED = 2
    INTEGRATION_VERIFIED = 3
    USER_VERIFIED = 4
    OPERATIONALLY_PROVEN = 5


class EvidenceType(StrEnum):
    API = "api"
    FILE = "file"
    PROCESS = "process"
    SCREEN = "screen"
    NETWORK = "network"
    SENSOR = "sensor"
    USER = "user"
    MULTI_SOURCE = "multi_source"
    CUSTOM = "custom"


class VerificationDisposition(StrEnum):
    COMPLETE = "complete"
    DIAGNOSE = "diagnose"
    REPLAN = "replan"
    ASK_USER = "ask_user"


_MAX_RECORDS: Final = 128
_MAX_TEXT: Final = 4_000
_MAX_VALUE_BYTES: Final = 16_000
_MODEL_SOURCES: Final = frozenset({"model", "model.claim", "llm", "assistant"})
_NEGATIVE_USER_RESPONSES: Final = frozenset(
    {"no", "nope", "deny", "denied", "not done", "not yet", "false", "negative"}
)
_POSITIVE_USER_RESPONSES: Final = frozenset(
    {"yes", "y", "done", "it is done", "confirmed", "confirm", "true"}
)


def _text(value: object, field: str, limit: int = _MAX_TEXT) -> str:
    if type(value) is not str or not value.strip() or len(value) > limit or "\x00" in value:
        raise VerificationError(f"{field} must be bounded, non-empty, and NUL-free")
    return value


def _json_like(value: object, *, depth: int = 0, field: str = "value") -> object:
    """Accept bounded data values without allowing executable/custom objects."""

    if depth > 5:
        raise VerificationError(f"{field} is too deeply nested")
    if value is None or type(value) is bool or type(value) is int:
        return value
    if type(value) is float:
        if not math.isfinite(value):
            raise VerificationError(f"{field} contains a non-finite number")
        return value
    if type(value) is str:
        return _text(value, field, _MAX_TEXT)
    if isinstance(value, Mapping):
        if len(value) > 64:
            raise VerificationError(f"{field} has too many properties")
        result: dict[str, object] = {}
        for key, item in value.items():
            result[_text(key, f"{field} key", 128)] = _json_like(
                item, depth=depth + 1, field=f"{field}.{key}"
            )
        return result
    if isinstance(value, Sequence) and not isinstance(value, str | bytes | bytearray):
        if len(value) > 128:
            raise VerificationError(f"{field} has too many items")
        return tuple(
            _json_like(item, depth=depth + 1, field=f"{field}[{index}]")
            for index, item in enumerate(value)
        )
    raise VerificationError(f"{field} contains an unsupported value")


def _utc(value: datetime, field: str) -> datetime:
    if value.tzinfo is None:
        raise VerificationError(f"{field} must be timezone-aware")
    return value.astimezone(UTC)


@dataclass(frozen=True, slots=True)
class VerificationPlan:
    """Trusted application-owned criteria for observing one original goal."""

    original_goal: str
    criteria: tuple[str, ...]
    allowed_evidence_types: frozenset[EvidenceType] = frozenset(EvidenceType)
    required_level: VerificationLevel = VerificationLevel.IMPLEMENTED
    minimum_confidence: float = 0.8
    max_evidence_age: timedelta = timedelta(minutes=15)
    independent_observation_required: bool = True
    ask_user_when_unobservable: bool = True
    user_prompt: str = "Please confirm whether the requested result is physically present."

    def __post_init__(self) -> None:
        _text(self.original_goal, "Original goal")
        if not self.criteria or len(self.criteria) > 64:
            raise VerificationError("Verification plans require bounded criteria")
        if any(
            not isinstance(item, str) or not item.strip() or len(item) > 1_000
            for item in self.criteria
        ):
            raise VerificationError("Verification criteria are malformed")
        if (
            not isinstance(self.allowed_evidence_types, frozenset)
            or not self.allowed_evidence_types
        ):
            raise VerificationError("Verification plans require allowed evidence types")
        if any(not isinstance(item, EvidenceType) for item in self.allowed_evidence_types):
            raise VerificationError("Verification evidence types are malformed")
        if not isinstance(self.required_level, VerificationLevel):
            raise VerificationError("Required verification level is malformed")
        if not 0 <= self.minimum_confidence <= 1 or not math.isfinite(self.minimum_confidence):
            raise VerificationError("Verification confidence must be within [0, 1]")
        if self.max_evidence_age <= timedelta(0) or self.max_evidence_age > timedelta(days=30):
            raise VerificationError("Verification evidence age is outside safe bounds")
        if not isinstance(self.independent_observation_required, bool) or not isinstance(
            self.ask_user_when_unobservable, bool
        ):
            raise VerificationError("Verification flags are malformed")
        _text(self.user_prompt, "User prompt", 1_000)


@dataclass(frozen=True, slots=True)
class EvidenceRecord:
    """Immutable observation supplied by a trusted collector.

    ``source`` identifies the collector, not the model narrative that caused
    the action.  A record marked by a model source is deliberately ignored by
    :class:`VerificationEngine`.
    """

    evidence_type: EvidenceType
    source: str
    time: datetime
    freshness: timedelta
    confidence: float
    expected: object
    observed: object
    contradiction: bool = False
    level: VerificationLevel = VerificationLevel.IMPLEMENTED

    def __post_init__(self) -> None:
        if not isinstance(self.evidence_type, EvidenceType):
            raise VerificationError("Evidence type is malformed")
        _text(self.source, "Evidence source", 512)
        object.__setattr__(self, "time", _utc(self.time, "Evidence time"))
        if self.freshness <= timedelta(0) or self.freshness > timedelta(days=30):
            raise VerificationError("Evidence freshness is outside safe bounds")
        if not 0 <= self.confidence <= 1 or not math.isfinite(self.confidence):
            raise VerificationError("Evidence confidence must be within [0, 1]")
        object.__setattr__(self, "expected", _json_like(self.expected, field="Evidence expected"))
        object.__setattr__(self, "observed", _json_like(self.observed, field="Evidence observed"))
        if not isinstance(self.contradiction, bool):
            raise VerificationError("Evidence contradiction flag is malformed")
        if not isinstance(self.level, VerificationLevel):
            raise VerificationError("Evidence verification level is malformed")
        if len(repr((self.expected, self.observed)).encode()) > _MAX_VALUE_BYTES:
            raise VerificationError("Evidence values are too large")

    def is_fresh(self, now: datetime, maximum_age: timedelta) -> bool:
        current = _utc(now, "Verification time")
        age = current - self.time
        return timedelta(0) <= age <= min(self.freshness, maximum_age)

    @property
    def is_model_claim(self) -> bool:
        source = self.source.casefold()
        return source in _MODEL_SOURCES or source.startswith(("model.", "model:", "llm."))

    @property
    def contradicts_expectation(self) -> bool:
        return self.contradiction or self.expected != self.observed


@dataclass(frozen=True, slots=True)
class VerificationResult:
    """Outcome of observation, retaining the original goal on every path."""

    original_goal: str
    level: VerificationLevel
    passed: bool
    disposition: VerificationDisposition
    evidence: tuple[EvidenceRecord, ...] = ()
    stale_evidence: tuple[EvidenceRecord, ...] = ()
    contradictions: tuple[EvidenceRecord, ...] = ()
    rejected_model_claims: tuple[str, ...] = ()
    missing_criteria: tuple[str, ...] = ()
    diagnosis: str = ""
    needs_user_confirmation: bool = False
    user_prompt: str | None = None

    def __post_init__(self) -> None:
        _text(self.original_goal, "Result original goal")
        if not isinstance(self.level, VerificationLevel) or not isinstance(
            self.disposition, VerificationDisposition
        ):
            raise VerificationError("Verification result status is malformed")
        if not isinstance(self.passed, bool):
            raise VerificationError("Verification result passed flag is malformed")
        if len(self.evidence) > _MAX_RECORDS or len(self.stale_evidence) > _MAX_RECORDS:
            raise VerificationError("Verification result evidence is unbounded")
        if any(
            not isinstance(item, EvidenceRecord) for item in (*self.evidence, *self.stale_evidence)
        ):
            raise VerificationError("Verification result evidence is malformed")
        if len(self.rejected_model_claims) > 32 or any(
            not isinstance(item, str) or len(item) > 1_000 for item in self.rejected_model_claims
        ):
            raise VerificationError("Rejected model claims are malformed")
        if len(self.diagnosis) > 2_000:
            raise VerificationError("Verification diagnosis is too long")
        if self.user_prompt is not None:
            _text(self.user_prompt, "User prompt", 1_000)
        if self.needs_user_confirmation != (self.disposition is VerificationDisposition.ASK_USER):
            raise VerificationError("User confirmation state is inconsistent")


class VerificationEngine:
    """Evaluate observations without executing, authorizing, or replanning."""

    def evaluate(
        self,
        plan: VerificationPlan,
        records: Sequence[EvidenceRecord] = (),
        *,
        model_claim: str | None = None,
        now: datetime | None = None,
    ) -> VerificationResult:
        if len(records) > _MAX_RECORDS or any(
            not isinstance(item, EvidenceRecord) for item in records
        ):
            raise VerificationError("Verification records are malformed or unbounded")
        current = _utc(now or datetime.now(UTC), "Verification time")
        fresh: list[EvidenceRecord] = []
        stale: list[EvidenceRecord] = []
        rejected: list[str] = []
        contradictions: list[EvidenceRecord] = []
        for record in records:
            if record.is_model_claim:
                rejected.append("model output is not evidence")
                continue
            if record.evidence_type not in plan.allowed_evidence_types:
                rejected.append("evidence type is not allowed by the plan")
                continue
            if not record.is_fresh(current, plan.max_evidence_age):
                stale.append(record)
                continue
            if record.confidence < plan.minimum_confidence:
                rejected.append("evidence confidence is below the plan threshold")
                continue
            fresh.append(record)
            if (
                record.contradiction
                or (
                    record.evidence_type is not EvidenceType.USER
                    and record.expected != record.observed
                )
                or (
                    record.evidence_type is EvidenceType.USER
                    and self._user_response(record.observed) is False
                )
            ):
                contradictions.append(record)
        if model_claim is not None:
            _text(model_claim, "Model claim", 2_000)
            rejected.append("model output is not evidence")

        missing = tuple(
            criterion
            for criterion in plan.criteria
            if not any(
                record.expected == criterion
                and (
                    record.observed == criterion
                    or (
                        record.evidence_type is EvidenceType.USER
                        and self._user_response(record.observed) is True
                    )
                )
                for record in fresh
            )
        )
        user_positive = any(
            record.evidence_type is EvidenceType.USER
            and self._user_response(record.observed) is True
            for record in fresh
        )
        independent = any(
            record.evidence_type
            in {
                EvidenceType.API,
                EvidenceType.FILE,
                EvidenceType.PROCESS,
                EvidenceType.SCREEN,
                EvidenceType.NETWORK,
                EvidenceType.SENSOR,
                EvidenceType.MULTI_SOURCE,
                EvidenceType.CUSTOM,
            }
            for record in fresh
        )
        highest = max((record.level for record in fresh), default=VerificationLevel.UNKNOWN)
        if contradictions:
            return self._result(
                plan,
                VerificationLevel.UNKNOWN,
                False,
                VerificationDisposition.REPLAN,
                fresh,
                stale,
                contradictions,
                tuple(rejected),
                missing,
                "Observed evidence contradicts the expected outcome; diagnose and replan.",
            )
        if plan.independent_observation_required and not independent and not user_positive:
            if plan.ask_user_when_unobservable:
                return self._result(
                    plan,
                    VerificationLevel.UNKNOWN,
                    False,
                    VerificationDisposition.ASK_USER,
                    fresh,
                    stale,
                    (),
                    tuple(rejected),
                    missing,
                    "The physical result cannot be independently observed.",
                    user_prompt=plan.user_prompt,
                )
            return self._result(
                plan,
                VerificationLevel.UNKNOWN,
                False,
                VerificationDisposition.DIAGNOSE,
                fresh,
                stale,
                (),
                tuple(rejected),
                missing,
                "No independent observation is available.",
            )
        if not missing and highest >= plan.required_level:
            return self._result(
                plan,
                highest,
                True,
                VerificationDisposition.COMPLETE,
                fresh,
                stale,
                (),
                tuple(rejected),
                (),
                "Expected outcome was observed with sufficient evidence.",
            )
        diagnosis = (
            "Evidence is stale or incomplete; collect fresh evidence and diagnose or replan."
            if stale or rejected
            else "Expected outcome was not observed."
        )
        return self._result(
            plan,
            highest,
            False,
            VerificationDisposition.REPLAN,
            fresh,
            stale,
            (),
            tuple(rejected),
            missing,
            diagnosis,
        )

    async def verify_surface(
        self,
        plan: VerificationPlan,
        surface: PresentationSurface,
        expected: UiStateSnapshot,
        *,
        now: datetime | None = None,
    ) -> VerificationResult:
        """Use the actual queried surface as SCREEN evidence, never the request echo."""

        actual = await surface.query_state()
        actual_fingerprint = (
            actual.state_fingerprint
            if actual.observed
            else f"unobserved:{actual.state_fingerprint}"
        )
        record = EvidenceRecord(
            EvidenceType.SCREEN,
            f"surface:{actual.surface_id}",
            actual.captured_at,
            plan.max_evidence_age,
            1.0,
            expected.state_fingerprint,
            actual_fingerprint,
            (not actual.observed) or actual_fingerprint != expected.state_fingerprint,
            VerificationLevel.INTEGRATION_VERIFIED,
        )
        return self.evaluate(plan, (record,), now=now or datetime.now(UTC))

    @staticmethod
    def _user_response(value: object) -> bool | None:
        if type(value) is bool:
            return value
        if type(value) is not str:
            return None
        normalized = " ".join(value.casefold().split())
        if normalized in _POSITIVE_USER_RESPONSES:
            return True
        if normalized in _NEGATIVE_USER_RESPONSES:
            return False
        return None

    @staticmethod
    def _result(
        plan: VerificationPlan,
        level: VerificationLevel,
        passed: bool,
        disposition: VerificationDisposition,
        evidence: Sequence[EvidenceRecord],
        stale: Sequence[EvidenceRecord],
        contradictions: Sequence[EvidenceRecord],
        rejected: Sequence[str],
        missing: Sequence[str],
        diagnosis: str,
        *,
        user_prompt: str | None = None,
    ) -> VerificationResult:
        return VerificationResult(
            plan.original_goal,
            level,
            passed,
            disposition,
            tuple(evidence),
            tuple(stale),
            tuple(contradictions),
            tuple(rejected),
            tuple(missing),
            diagnosis,
            disposition is VerificationDisposition.ASK_USER,
            user_prompt,
        )


__all__ = [
    "EvidenceRecord",
    "EvidenceType",
    "VerificationDisposition",
    "VerificationEngine",
    "VerificationError",
    "VerificationLevel",
    "VerificationPlan",
    "VerificationResult",
]
