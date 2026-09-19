"""Derived, provider-neutral routing fitness from trusted verified outcomes."""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from enum import StrEnum
from threading import RLock
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from jarvis.planning.models import (
        PlanningStep,
        PlanningTask,
        StepExecutionResult,
        StepVerification,
    )


class SemanticOutcome(StrEnum):
    VERIFIED_SUCCESS = "verified_success"
    VERIFIED_FAILURE = "verified_failure"
    UNVERIFIED = "unverified"
    UNKNOWN = "unknown"


class FitnessEvidence(StrEnum):
    UNKNOWN = "unknown"
    INSUFFICIENT = "insufficient_evidence"
    SUFFICIENT = "sufficient_evidence"
    STALE = "stale"


@dataclass(frozen=True, slots=True)
class VerifiedRouteOutcome:
    """One trusted, bounded route observation; no prompt or response content."""

    observation_id: str
    route_identity: str
    candidate_kind: str
    task_class: str
    role: str
    observed_at: datetime
    operational_outcome: str
    semantic_outcome: SemanticOutcome
    verification_source: str | None = None
    retry_count: int = 0
    failure_class: str | None = None
    latency_ms: float | None = None
    monetary_cost: float | None = None
    evidence_refs: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        for name, value, limit in (
            ("observation ID", self.observation_id, 256),
            ("route identity", self.route_identity, 256),
            ("candidate kind", self.candidate_kind, 64),
            ("task class", self.task_class, 128),
            ("role", self.role, 64),
            ("operational outcome", self.operational_outcome, 64),
        ):
            if type(value) is not str or not value.strip() or len(value) > limit or "\x00" in value:
                raise ValueError(f"Route outcome {name} is invalid")
        if not isinstance(self.semantic_outcome, SemanticOutcome):
            raise ValueError("Route semantic outcome is invalid")
        if self.verification_source is not None and (
            type(self.verification_source) is not str
            or not self.verification_source.strip()
            or len(self.verification_source) > 128
        ):
            raise ValueError("Route verification source is invalid")
        if self.observed_at.tzinfo is None:
            raise ValueError("Route outcome timestamp must be timezone-aware")
        if type(self.retry_count) is not int or self.retry_count < 0:
            raise ValueError("Route outcome retry count is invalid")
        for name, metric in (
            ("latency", self.latency_ms),
            ("cost", self.monetary_cost),
        ):
            if metric is not None and (type(metric) not in {int, float} or metric < 0):
                raise ValueError(f"Route outcome {name} is invalid")
        if type(self.evidence_refs) is not tuple or len(self.evidence_refs) > 16:
            raise ValueError("Route outcome evidence references are invalid")


@dataclass(frozen=True, slots=True)
class RouteFitnessView:
    route_identity: str
    candidate_kind: str
    task_class: str
    sample_count: int
    operational_success_count: int
    semantic_verified_success_count: int
    semantic_verified_failure_count: int
    unknown_outcome_count: int
    unverified_count: int
    retry_count: int
    last_observed_at: datetime | None
    evidence: FitnessEvidence
    mean_latency_ms: float | None

    @property
    def operational_success_rate(self) -> float | None:
        return self.operational_success_count / self.sample_count if self.sample_count else None

    @property
    def verified_success_rate(self) -> float | None:
        return (
            self.semantic_verified_success_count / self.sample_count if self.sample_count else None
        )

    @property
    def failure_rate(self) -> float | None:
        return (
            self.semantic_verified_failure_count / self.sample_count if self.sample_count else None
        )

    def meets_quality_floor(self, minimum_verified_reliability: float, now: datetime) -> bool:
        if self.evidence is not FitnessEvidence.SUFFICIENT:
            return False
        if self.last_observed_at is None or now - self.last_observed_at > timedelta(days=30):
            return False
        rate = self.verified_success_rate
        return rate is not None and rate >= minimum_verified_reliability


class RoutingFitnessProjection:
    """Rebuildable process-local projection; task and verification stores remain authoritative."""

    def __init__(self, *, clock: Callable[[], datetime] | None = None) -> None:
        self._clock = clock or (lambda: datetime.now(UTC))
        self._lock = RLock()
        self._observations: dict[str, VerifiedRouteOutcome] = {}

    def now(self) -> datetime:
        return self._clock()

    def record(self, outcome: VerifiedRouteOutcome) -> bool:
        if not isinstance(outcome, VerifiedRouteOutcome):
            raise ValueError("Route outcome is malformed")
        with self._lock:
            if outcome.observation_id in self._observations:
                return False
            self._observations[outcome.observation_id] = outcome
            return True

    def record_planning_step(
        self,
        task: PlanningTask,
        step: PlanningStep,
        execution: StepExecutionResult,
        verification: StepVerification | None,
    ) -> bool:
        """Record only trusted PlanningEngine execution/verification facts."""

        if verification is None:
            semantic = (
                SemanticOutcome.UNKNOWN
                if execution.status.value == "unknown_outcome"
                else SemanticOutcome.UNVERIFIED
            )
            source = None
        else:
            semantic = (
                SemanticOutcome.VERIFIED_SUCCESS
                if verification.succeeded
                else SemanticOutcome.VERIFIED_FAILURE
            )
            source = "planning.step_verifier"
        outcome = VerifiedRouteOutcome(
            observation_id=f"{task.task_id}:{step.step_id}:{step.attempts}",
            route_identity=step.tool_id,
            candidate_kind="tool",
            task_class=step.capability,
            role="orchestration",
            observed_at=self._clock(),
            operational_outcome=execution.status.value,
            semantic_outcome=semantic,
            verification_source=source,
            retry_count=step.attempts,
            failure_class=execution.error_code,
            evidence_refs=(f"task:{task.task_id}", f"step:{step.step_id}"),
        )
        return self.record(outcome)

    def view(
        self,
        route_identity: str,
        task_class: str,
        *,
        candidate_kind: str = "tool",
        now: datetime | None = None,
    ) -> RouteFitnessView:
        with self._lock:
            observations = tuple(
                item
                for item in self._observations.values()
                if item.route_identity == route_identity
                and item.task_class == task_class
                and item.candidate_kind == candidate_kind
            )
        latest = max((item.observed_at for item in observations), default=None)
        sample_count = len(observations)
        if not observations:
            evidence = FitnessEvidence.UNKNOWN
        elif sample_count < 3:
            evidence = FitnessEvidence.INSUFFICIENT
        else:
            reference = now or self._clock()
            evidence = (
                FitnessEvidence.STALE
                if latest is not None and reference - latest > timedelta(days=30)
                else FitnessEvidence.SUFFICIENT
            )
        latencies = [item.latency_ms for item in observations if item.latency_ms is not None]
        return RouteFitnessView(
            route_identity,
            candidate_kind,
            task_class,
            sample_count,
            sum(item.operational_outcome == "succeeded" for item in observations),
            sum(item.semantic_outcome is SemanticOutcome.VERIFIED_SUCCESS for item in observations),
            sum(item.semantic_outcome is SemanticOutcome.VERIFIED_FAILURE for item in observations),
            sum(item.semantic_outcome is SemanticOutcome.UNKNOWN for item in observations),
            sum(item.semantic_outcome is SemanticOutcome.UNVERIFIED for item in observations),
            sum(item.retry_count for item in observations),
            latest,
            evidence,
            sum(latencies) / len(latencies) if latencies else None,
        )


__all__ = [
    "FitnessEvidence",
    "RouteFitnessView",
    "RoutingFitnessProjection",
    "SemanticOutcome",
    "VerifiedRouteOutcome",
]
