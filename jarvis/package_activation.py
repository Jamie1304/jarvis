"""Trusted staged activation for certified integration packages.

Certification proves that a package is admissible.  This module owns the
separate activation lifecycle.  Package code supplies no lifecycle decision,
broker, or callback: all runners are application-owned composition-root
hooks, and promotion is only performed by this service.
"""

from __future__ import annotations

from collections.abc import Callable, Iterable
from dataclasses import dataclass, replace
from datetime import UTC, datetime
from enum import StrEnum
from hashlib import sha256
from typing import TYPE_CHECKING

from jarvis.integration_package import IntegrationPackage
from jarvis.package_certification import CertificationRecord
from jarvis.package_reviewer import PackageSourceFile
from jarvis.package_runtime import HotLoadError, HotLoadManager, PackageCertification
from jarvis.tools.models import SemanticVersion

if TYPE_CHECKING:
    from typing import Final


class ActivationError(RuntimeError):
    """A package could not proceed through staged activation."""


class ActivationValidationError(ActivationError, ValueError):
    """Activation metadata or trusted runner evidence is malformed."""


class ActivationState(StrEnum):
    CERTIFIED = "CERTIFIED"
    SHADOW = "SHADOW"
    CANARY = "CANARY"
    ACTIVE = "ACTIVE"
    DEGRADED = "DEGRADED"
    QUARANTINED = "QUARANTINED"
    ROLLED_BACK = "ROLLED_BACK"


def _text(value: str, name: str, limit: int = 512) -> None:
    if type(value) is not str or not value.strip() or len(value) > limit or "\x00" in value:
        raise ActivationValidationError(f"{name} is malformed")


def _labels(values: Iterable[str], name: str, limit: int = 128) -> None:
    values = tuple(values)
    if len(values) > limit or any(
        type(value) is not str or not value.strip() or len(value) > 2_000 or "\x00" in value
        for value in values
    ):
        raise ActivationValidationError(f"{name} are malformed")


def _timestamp(value: datetime, name: str) -> None:
    if not isinstance(value, datetime) or value.tzinfo is None:
        raise ActivationValidationError(f"{name} must be timezone-aware")


@dataclass(frozen=True, slots=True)
class CanaryLimits:
    """Trusted, narrow limits passed to the canary broker."""

    scope: str
    max_calls: int = 1
    max_effects: int = 1
    max_budget: int = 100
    max_wall_seconds: float = 30.0

    def __post_init__(self) -> None:
        _text(self.scope, "Canary scope")
        if (
            type(self.max_calls) is not int
            or type(self.max_effects) is not int
            or type(self.max_budget) is not int
            or self.max_calls < 0
            or self.max_calls > 100
            or self.max_effects < 0
            or self.max_effects > 100
            or self.max_budget < 0
            or self.max_budget > 1_000_000
            or type(self.max_wall_seconds) is not float
            or self.max_wall_seconds <= 0
            or self.max_wall_seconds > 3_600
        ):
            raise ActivationValidationError("Canary limits are malformed")


@dataclass(frozen=True, slots=True)
class ShadowExecution:
    """Trusted broker observation; ``side_effects`` must always be empty."""

    predictions: tuple[str, ...] = ()
    broker_behavior: tuple[str, ...] = ()
    side_effects: tuple[str, ...] = ()
    verification: tuple[str, ...] = ()
    passed: bool = True

    def __post_init__(self) -> None:
        _labels(self.predictions, "Shadow predictions")
        _labels(self.broker_behavior, "Shadow broker behavior")
        _labels(self.side_effects, "Shadow side effects")
        _labels(self.verification, "Shadow verification")
        if type(self.passed) is not bool:
            raise ActivationValidationError("Shadow result is malformed")


@dataclass(frozen=True, slots=True)
class CanaryExecution:
    """Trusted broker observation of bounded real effects."""

    scope: str
    predictions: tuple[str, ...] = ()
    broker_behavior: tuple[str, ...] = ()
    effects: tuple[str, ...] = ()
    verification: tuple[str, ...] = ()
    calls: int = 0
    budget_used: int = 0
    wall_seconds: float = 0.0
    passed: bool = True

    def __post_init__(self) -> None:
        _text(self.scope, "Canary result scope")
        _labels(self.predictions, "Canary predictions")
        _labels(self.broker_behavior, "Canary broker behavior")
        _labels(self.effects, "Canary effects")
        _labels(self.verification, "Canary verification")
        if (
            type(self.calls) is not int
            or self.calls < 0
            or type(self.budget_used) is not int
            or self.budget_used < 0
            or type(self.wall_seconds) is not float
            or self.wall_seconds < 0
            or type(self.passed) is not bool
        ):
            raise ActivationValidationError("Canary result is malformed")


def _default_rollback(_: IntegrationPackage, __: tuple[str, ...]) -> bool:
    return True


@dataclass(frozen=True, slots=True)
class ActivationHooks:
    """Trusted application-owned broker and rollback boundaries.

    These callbacks are supplied by the composition root.  A package cannot
    construct this object through the activation API or invoke promotion.
    The Shadow callback must use a zero-effect broker; the Canary callback must
    enforce the supplied limits before performing any effect.
    """

    shadow: Callable[[IntegrationPackage], ShadowExecution]
    canary: Callable[[IntegrationPackage, CanaryLimits], CanaryExecution]
    rollback_effects: Callable[[IntegrationPackage, tuple[str, ...]], bool] = _default_rollback


@dataclass(frozen=True, slots=True)
class ActivationRequest:
    package: IntegrationPackage
    certification: CertificationRecord
    source_files: tuple[PackageSourceFile, ...]
    canary_limits: CanaryLimits

    def __post_init__(self) -> None:
        if not isinstance(self.package, IntegrationPackage):
            raise ActivationValidationError("Activation package is malformed")
        if not isinstance(self.certification, CertificationRecord):
            raise ActivationValidationError("Activation certification is malformed")
        if type(self.source_files) is not tuple or any(
            not isinstance(source, PackageSourceFile) for source in self.source_files
        ):
            raise ActivationValidationError("Activation source snapshot is malformed")
        if not isinstance(self.canary_limits, CanaryLimits):
            raise ActivationValidationError("Canary limits are malformed")


@dataclass(frozen=True, slots=True)
class ActivationTransition:
    from_state: ActivationState | None
    to_state: ActivationState
    detail: str
    recorded_at: datetime

    def __post_init__(self) -> None:
        if self.from_state is not None and not isinstance(self.from_state, ActivationState):
            raise ActivationValidationError("Activation transition source is malformed")
        if not isinstance(self.to_state, ActivationState):
            raise ActivationValidationError("Activation transition target is malformed")
        _text(self.detail, "Activation transition detail")
        _timestamp(self.recorded_at, "Activation transition timestamp")


@dataclass(frozen=True, slots=True)
class ActivationRecord:
    """Evidence and decision history for one exact package version."""

    activation_id: str
    package_id: str
    version: SemanticVersion
    package_hash: str
    certification: CertificationRecord
    state: ActivationState
    predictions: tuple[str, ...]
    broker_behavior: tuple[str, ...]
    canary_effects: tuple[str, ...]
    verification: tuple[str, ...]
    promotion_decision: str
    rollback_evidence: tuple[str, ...]
    history: tuple[ActivationTransition, ...]
    created_at: datetime
    updated_at: datetime

    def __post_init__(self) -> None:
        _text(self.activation_id, "Activation ID", 128)
        _text(self.package_id, "Activation package ID", 128)
        if not isinstance(self.version, SemanticVersion) or not self.package_hash:
            raise ActivationValidationError("Activation package identity is malformed")
        if not isinstance(self.certification, CertificationRecord):
            raise ActivationValidationError("Activation certification is malformed")
        if (
            self.certification.package_id != self.package_id
            or self.certification.version != self.version
            or self.certification.package_hash != self.package_hash
        ):
            raise ActivationValidationError("Activation evidence is not package-bound")
        if not isinstance(self.state, ActivationState):
            raise ActivationValidationError("Activation state is malformed")
        _labels(self.predictions, "Activation predictions")
        _labels(self.broker_behavior, "Activation broker behavior")
        _labels(self.canary_effects, "Activation canary effects")
        _labels(self.verification, "Activation verification")
        _text(self.promotion_decision, "Activation promotion decision")
        _labels(self.rollback_evidence, "Activation rollback evidence")
        if type(self.history) is not tuple or not self.history:
            raise ActivationValidationError("Activation history is incomplete")
        if any(not isinstance(item, ActivationTransition) for item in self.history):
            raise ActivationValidationError("Activation history is malformed")
        _timestamp(self.created_at, "Activation creation timestamp")
        _timestamp(self.updated_at, "Activation update timestamp")


@dataclass
class _ActivationSession:
    request: ActivationRequest
    record: ActivationRecord
    canary_passed: bool = False
    previous: _ActivationSession | None = None


class PackageActivationService:
    """The sole trusted state machine for staged package activation."""

    _MAX_HISTORY: Final[int] = 64

    def __init__(
        self,
        hot_load: HotLoadManager,
        hooks: ActivationHooks,
        *,
        clock: Callable[[], datetime] | None = None,
    ) -> None:
        if not isinstance(hot_load, HotLoadManager) or not isinstance(hooks, ActivationHooks):
            raise ActivationValidationError("Activation service dependencies are malformed")
        self._hot_load = hot_load
        self._hooks = hooks
        self._clock = clock or (lambda: datetime.now(UTC))
        self._sessions: dict[tuple[str, SemanticVersion], _ActivationSession] = {}

    def register_certified(self, request: ActivationRequest) -> ActivationRecord:
        """Register a fresh certified version; this never activates it."""

        self._validate_request(request)
        key = (request.package.package_id, request.package.version)
        if key in self._sessions:
            raise ActivationError("Package version already has an activation lifecycle")
        now = self._now()
        activation_id = sha256(
            f"{request.package.package_id}:{request.package.version}:{request.package.package_hash}:{now.isoformat()}".encode()
        ).hexdigest()
        transition = ActivationTransition(None, ActivationState.CERTIFIED, "certified", now)
        record = ActivationRecord(
            activation_id,
            request.package.package_id,
            request.package.version,
            request.package.package_hash,
            request.certification,
            ActivationState.CERTIFIED,
            (),
            (),
            (),
            (),
            "NOT_PROMOTED",
            (),
            (transition,),
            now,
            now,
        )
        self._sessions[key] = _ActivationSession(request, record)
        return record

    def run_shadow(self, package_id: str, version: SemanticVersion) -> ActivationRecord:
        session = self._session(package_id, version, ActivationState.CERTIFIED)
        if not session.request.certification.shadow_eligible:
            return self._quarantine(session, "Shadow eligibility is not certified", ())
        try:
            result = self._hooks.shadow(session.request.package)
            if not isinstance(result, ShadowExecution):
                raise ActivationValidationError("Shadow broker returned malformed evidence")
        except Exception as error:
            return self._quarantine(session, "Shadow broker failed", (str(error),))
        record = self._append_observations(
            session.record,
            result.predictions,
            result.broker_behavior,
            (),
            result.verification,
        )
        session.record = record
        if result.side_effects:
            return self._quarantine(
                session,
                "Shadow side-effect attempt rejected",
                result.side_effects,
            )
        if not result.passed:
            return self._quarantine(session, "Shadow verification failed", result.verification)
        return self._advance(session, ActivationState.SHADOW, "shadow passed")

    def run_canary(self, package_id: str, version: SemanticVersion) -> ActivationRecord:
        session = self._session(package_id, version, ActivationState.SHADOW)
        if not session.request.certification.canary_eligible:
            return self._quarantine(session, "Canary eligibility is not certified", ())
        limits = session.request.canary_limits
        try:
            result = self._hooks.canary(session.request.package, limits)
            if not isinstance(result, CanaryExecution):
                raise ActivationValidationError("Canary broker returned malformed evidence")
        except Exception as error:
            return self._quarantine(session, "Canary broker failed", (str(error),))
        record = self._append_observations(
            session.record,
            result.predictions,
            result.broker_behavior,
            result.effects,
            result.verification,
        )
        session.record = record
        failures: list[str] = []
        if result.scope != limits.scope:
            failures.append("canary scope exceeded")
        if result.calls > limits.max_calls:
            failures.append("canary call bound exceeded")
        if len(result.effects) > limits.max_effects:
            failures.append("canary effect bound exceeded")
        if result.budget_used > limits.max_budget:
            failures.append("canary budget exceeded")
        if result.wall_seconds > limits.max_wall_seconds:
            failures.append("canary wall-time bound exceeded")
        if not result.passed:
            failures.append("canary verification failed")
        if not result.verification:
            failures.append("canary has no verification evidence")
        if failures:
            rollback = self._rollback_effects(session.request.package, result.effects)
            return self._quarantine(
                session,
                "; ".join(failures),
                tuple(failures) + rollback,
            )
        session.canary_passed = True
        return self._advance(session, ActivationState.CANARY, "canary passed")

    def promote(self, package_id: str, version: SemanticVersion) -> ActivationRecord:
        session = self._session(package_id, version, ActivationState.CANARY)
        if not session.canary_passed:
            raise ActivationError("Only a successful canary can be promoted")
        try:
            active = self._hot_load.active(package_id)
        except KeyError:
            active = None
        if active is not None:
            previous = self._sessions.get((package_id, active.package.version))
            if previous is not None:
                session.previous = previous
        try:
            self._hot_load.manual_refresh(
                session.request.package,
                PackageCertification.from_record(session.request.certification),
            )
        except Exception as error:
            return self._quarantine(session, "activation health/swap failed", (str(error),))
        return self._advance(session, ActivationState.ACTIVE, "promoted by trusted lifecycle")

    def mark_degraded(
        self, package_id: str, version: SemanticVersion, detail: str
    ) -> ActivationRecord:
        _text(detail, "Degradation detail")
        session = self._session(package_id, version, ActivationState.ACTIVE)
        return self._advance(session, ActivationState.DEGRADED, detail)

    def quarantine(
        self, package_id: str, version: SemanticVersion, detail: str
    ) -> ActivationRecord:
        _text(detail, "Quarantine detail")
        session = self._session(package_id, version)
        if session.record.state in {ActivationState.ACTIVE, ActivationState.DEGRADED}:
            evidence = self._rollback_active(session)
            session.record = replace(
                session.record,
                rollback_evidence=session.record.rollback_evidence + evidence,
            )
        return self._advance(session, ActivationState.QUARANTINED, detail)

    def rollback(
        self,
        package_id: str,
        version: SemanticVersion,
        detail: str = "rollback requested",
    ) -> ActivationRecord:
        _text(detail, "Rollback detail")
        session = self._session(package_id, version)
        evidence = self._rollback_effects(session.request.package, session.record.canary_effects)
        if session.record.state in {ActivationState.ACTIVE, ActivationState.DEGRADED}:
            evidence += self._rollback_active(session)
        session.record = replace(
            session.record,
            rollback_evidence=session.record.rollback_evidence + evidence,
        )
        return self._advance(session, ActivationState.ROLLED_BACK, detail)

    def restart(self, package_id: str, version: SemanticVersion) -> ActivationRecord:
        """Restart an active runtime without inheriting a new version's state."""

        session = self._session(package_id, version)
        if session.record.state is ActivationState.ACTIVE:
            try:
                self._hot_load.restart(package_id)
            except HotLoadError as error:
                return self._quarantine(session, "restart health check failed", (str(error),))
            return self._note(session, "active runtime restarted and health checked")
        return session.record

    def record_for(self, package_id: str, version: SemanticVersion) -> ActivationRecord:
        return self._session(package_id, version).record

    def records(self) -> tuple[ActivationRecord, ...]:
        return tuple(session.record for session in self._sessions.values())

    def _validate_request(self, request: ActivationRequest) -> None:
        if not isinstance(request, ActivationRequest):
            raise ActivationValidationError("Activation request is malformed")
        if not request.certification.matches(request.package, request.source_files):
            raise ActivationValidationError("Certification does not match exact package contents")

    def _now(self) -> datetime:
        value = self._clock()
        _timestamp(value, "Activation clock")
        return value

    def _session(
        self,
        package_id: str,
        version: SemanticVersion,
        required: ActivationState | None = None,
    ) -> _ActivationSession:
        if type(package_id) is not str or not isinstance(version, SemanticVersion):
            raise ActivationValidationError("Activation lookup is malformed")
        try:
            session = self._sessions[(package_id, version)]
        except KeyError as error:
            raise ActivationError("Package version has no activation lifecycle") from error
        if required is not None and session.record.state is not required:
            raise ActivationError(
                f"Activation state {session.record.state} cannot perform {required} operation"
            )
        return session

    def _append_observations(
        self,
        record: ActivationRecord,
        predictions: tuple[str, ...],
        broker_behavior: tuple[str, ...],
        effects: tuple[str, ...],
        verification: tuple[str, ...],
    ) -> ActivationRecord:
        return replace(
            record,
            predictions=record.predictions + predictions,
            broker_behavior=record.broker_behavior + broker_behavior,
            canary_effects=record.canary_effects + effects,
            verification=record.verification + verification,
            updated_at=self._now(),
        )

    def _advance(
        self, session: _ActivationSession, state: ActivationState, detail: str
    ) -> ActivationRecord:
        now = self._now()
        history = session.record.history + (
            ActivationTransition(session.record.state, state, detail, now),
        )
        if len(history) > self._MAX_HISTORY:
            history = history[-self._MAX_HISTORY :]
        session.record = replace(
            session.record,
            state=state,
            promotion_decision=(
                detail
                if state
                in {
                    ActivationState.ACTIVE,
                    ActivationState.QUARANTINED,
                    ActivationState.ROLLED_BACK,
                }
                else session.record.promotion_decision
            ),
            history=history,
            updated_at=now,
        )
        return session.record

    def _note(self, session: _ActivationSession, detail: str) -> ActivationRecord:
        now = self._now()
        history = session.record.history + (
            ActivationTransition(session.record.state, session.record.state, detail, now),
        )
        session.record = replace(
            session.record,
            history=history[-self._MAX_HISTORY :],
            updated_at=now,
        )
        return session.record

    def _quarantine(
        self,
        session: _ActivationSession,
        detail: str,
        evidence: tuple[str, ...],
    ) -> ActivationRecord:
        session.record = replace(
            session.record,
            rollback_evidence=session.record.rollback_evidence + evidence,
        )
        return self._advance(session, ActivationState.QUARANTINED, detail)

    def _rollback_effects(
        self, package: IntegrationPackage, effects: tuple[str, ...]
    ) -> tuple[str, ...]:
        if not effects:
            return ()
        try:
            success = self._hooks.rollback_effects(package, effects)
        except Exception as error:
            return (f"effect rollback failed: {error}",)
        return ("effect rollback succeeded",) if success else ("effect rollback failed",)

    def _rollback_active(self, session: _ActivationSession) -> tuple[str, ...]:
        previous = session.previous
        if previous is not None:
            try:
                self._hot_load.rollback_to(
                    previous.request.package,
                    PackageCertification.from_record(previous.request.certification),
                )
                return ("previous certified version restored",)
            except HotLoadError as error:
                return (f"previous version restore failed: {error}",)
        self._hot_load.remove(session.request.package.package_id)
        return ("active package removed; no previous version was registered",)
