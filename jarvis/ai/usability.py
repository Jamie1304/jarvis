"""Provider-neutral evidence for request-specific model usability.

Availability is an observation about an integration.  Usability is a
request-scoped conclusion assembled from provider, model, policy, resource,
and freshness evidence.  This module is deliberately independent of routing
and portfolio lifecycle code so both consumers use the same contract.
"""

from __future__ import annotations

from dataclasses import dataclass, replace
from datetime import UTC, datetime, timedelta
from enum import StrEnum
from typing import ClassVar, cast


class UsabilityValidationError(ValueError, RuntimeError):
    """A provider-neutral usability contract is malformed."""


class ModelUsabilityStatus(StrEnum):
    """Conclusion for one provider/model/request evidence set."""

    USABLE = "usable"
    NOT_USABLE = "not_usable"
    UNKNOWN = "unknown"


class UsabilityFreshness(StrEnum):
    """Freshness of operational evidence."""

    CURRENT = "current"
    STALE = "stale"
    UNTIMESTAMPED = "untimestamped"


class UsabilityReason(StrEnum):
    """Provider-neutral classification of a usability conclusion."""

    INVALID_CREDENTIALS = "invalid_credentials"
    AUTHENTICATION_UNAVAILABLE = "authentication_unavailable"
    QUOTA_EXHAUSTED = "quota_exhausted"
    BILLING_BLOCKED = "billing_blocked"
    BUDGET_EXHAUSTED = "budget_exhausted"
    MODEL_NOT_ENTITLED = "model_not_entitled"
    MODEL_UNAVAILABLE = "model_unavailable"
    MODEL_NOT_FOUND = "model_not_found"
    RATE_LIMITED = "rate_limited"
    PROVIDER_CAPACITY_EXHAUSTED = "provider_capacity_exhausted"
    PROVIDER_OUTAGE = "provider_outage"
    NETWORK_UNAVAILABLE = "network_unavailable"
    POLICY_BLOCKED = "policy_blocked"
    PRIVACY_BLOCKED = "privacy_blocked"
    LOCAL_RESOURCE_BLOCKED = "local_resource_blocked"
    TEMPORARILY_DEGRADED = "temporarily_degraded"
    UNKNOWN = "unknown"


_DIMENSION_FIELDS: tuple[str, ...] = (
    "configured",
    "connected",
    "reachable",
    "authenticated",
    "entitled",
    "quota_usable",
    "capacity_usable",
    "model_usable",
    "policy_eligible",
    "resource_eligible",
    "request_usable",
)

_DIMENSION_REASONS: dict[str, UsabilityReason] = {
    "connected": UsabilityReason.PROVIDER_OUTAGE,
    "reachable": UsabilityReason.NETWORK_UNAVAILABLE,
    "authenticated": UsabilityReason.AUTHENTICATION_UNAVAILABLE,
    "entitled": UsabilityReason.MODEL_NOT_ENTITLED,
    "quota_usable": UsabilityReason.QUOTA_EXHAUSTED,
    "capacity_usable": UsabilityReason.PROVIDER_CAPACITY_EXHAUSTED,
    "model_usable": UsabilityReason.MODEL_UNAVAILABLE,
    "policy_eligible": UsabilityReason.POLICY_BLOCKED,
    "resource_eligible": UsabilityReason.LOCAL_RESOURCE_BLOCKED,
    "request_usable": UsabilityReason.UNKNOWN,
}


def _validate_identity(value: str | None, name: str) -> None:
    if value is not None and (
        type(value) is not str or not value.strip() or len(value) > 256 or "\x00" in value
    ):
        raise UsabilityValidationError(f"{name} is invalid")


def _validate_timestamp(value: datetime | None, name: str) -> None:
    if value is not None and (not isinstance(value, datetime) or value.tzinfo is None):
        raise UsabilityValidationError(f"{name} must be timezone-aware")


@dataclass(frozen=True, slots=True)
class ModelUsabilityEvidence:
    """Typed, provider-neutral evidence for one model or provider scope.

    ``model_id=None`` denotes provider-level evidence.  Boolean dimensions are
    intentionally tri-state: ``None`` means that the dimension was not proven,
    not that it is true.  Request routing may allow an unknown candidate for a
    bounded first attempt, but ``proven_usable`` never treats unknown as true.
    """

    configured: bool | None = None
    connected: bool | None = None
    reachable: bool | None = None
    authenticated: bool | None = None
    entitled: bool | None = None
    quota_usable: bool | None = None
    capacity_usable: bool | None = None
    model_usable: bool | None = None
    policy_eligible: bool | None = None
    resource_eligible: bool | None = None
    request_usable: bool | None = None
    detail: str = "provider-neutral usability evidence"
    provider_id: str | None = None
    model_id: str | None = None
    reason: UsabilityReason = UsabilityReason.UNKNOWN
    source: str = "unknown"
    observed_at: datetime | None = None
    expires_at: datetime | None = None

    _BOOLEAN_FIELDS: ClassVar[tuple[str, ...]] = _DIMENSION_FIELDS

    def __post_init__(self) -> None:
        for name in self._BOOLEAN_FIELDS:
            value = getattr(self, name)
            if value is not None and type(value) is not bool:
                raise UsabilityValidationError(f"Model usability {name} is malformed")
        if not isinstance(self.reason, UsabilityReason):
            raise UsabilityValidationError("Model usability reason is invalid")
        _validate_identity(self.provider_id, "Usability provider identity")
        _validate_identity(self.model_id, "Usability model identity")
        if type(self.detail) is not str or not self.detail.strip() or len(self.detail) > 2_000:
            raise UsabilityValidationError("Model usability detail is invalid")
        if type(self.source) is not str or not self.source.strip() or len(self.source) > 512:
            raise UsabilityValidationError("Model usability source is invalid")
        _validate_timestamp(self.observed_at, "Usability observation timestamp")
        _validate_timestamp(self.expires_at, "Usability expiry timestamp")
        if self.observed_at is not None and self.expires_at is not None:
            if self.expires_at < self.observed_at:
                raise UsabilityValidationError("Usability expiry precedes observation")

    @property
    def dimensions(self) -> tuple[tuple[str, bool | None], ...]:
        """Return all dimensions in the stable contract order."""

        return tuple((name, getattr(self, name)) for name in self._BOOLEAN_FIELDS)

    def freshness_at(self, now: datetime | None = None) -> UsabilityFreshness:
        current = now or datetime.now(UTC)
        _validate_timestamp(current, "Usability comparison timestamp")
        if self.expires_at is not None and current >= self.expires_at:
            return UsabilityFreshness.STALE
        if self.observed_at is None:
            return UsabilityFreshness.UNTIMESTAMPED
        return UsabilityFreshness.CURRENT

    @property
    def freshness(self) -> UsabilityFreshness:
        return self.freshness_at()

    def is_stale(self, now: datetime | None = None) -> bool:
        return self.freshness_at(now) is UsabilityFreshness.STALE

    def effective_dimensions_at(
        self, now: datetime | None = None
    ) -> tuple[tuple[str, bool | None], ...]:
        """Return dimensions safe for a current decision.

        Expired positive and negative operational conclusions are both
        invalidated.  The original evidence remains observable through its
        timestamp, source, and reason, while stale negatives do not become a
        permanent blacklist.
        """

        if self.is_stale(now):
            return tuple((name, None) for name in self._BOOLEAN_FIELDS)
        return self.dimensions

    def status_at(self, now: datetime | None = None) -> ModelUsabilityStatus:
        values = tuple(value for _, value in self.effective_dimensions_at(now))
        if any(value is False for value in values):
            return ModelUsabilityStatus.NOT_USABLE
        if all(value is True for value in values):
            return ModelUsabilityStatus.USABLE
        return ModelUsabilityStatus.UNKNOWN

    @property
    def status(self) -> ModelUsabilityStatus:
        return self.status_at()

    def proven_usable_at(self, now: datetime | None = None) -> bool:
        return self.status_at(now) is ModelUsabilityStatus.USABLE and not self.is_stale(now)

    @property
    def proven_usable(self) -> bool:
        return self.proven_usable_at()

    @property
    def effective_reason(self) -> UsabilityReason:
        if self.reason is not UsabilityReason.UNKNOWN:
            return self.reason
        for name, value in self.effective_dimensions_at():
            if value is False:
                return _DIMENSION_REASONS.get(name, UsabilityReason.UNKNOWN)
        return UsabilityReason.UNKNOWN

    def with_request_eligibility(
        self,
        *,
        policy_eligible: bool = True,
        resource_eligible: bool = True,
        request_usable: bool = True,
    ) -> ModelUsabilityEvidence:
        """Compose already-proven router hard gates into this evidence."""

        return replace(
            self,
            policy_eligible=(
                self.policy_eligible if self.policy_eligible is False else policy_eligible
            ),
            resource_eligible=(
                self.resource_eligible if self.resource_eligible is False else resource_eligible
            ),
            request_usable=(
                self.request_usable if self.request_usable is False else request_usable
            ),
        )

    def merge(self, *overrides: ModelUsabilityEvidence) -> ModelUsabilityEvidence:
        return merge_usability_evidence(self, *overrides)


# Provider-level and model-level observations intentionally share one dataclass.
ProviderUsabilityEvidence = ModelUsabilityEvidence
UsabilityEvidence = ModelUsabilityEvidence


def merge_usability_evidence(
    *evidence: ModelUsabilityEvidence,
) -> ModelUsabilityEvidence:
    """Merge broad evidence first and more specific/latest evidence last."""

    values = tuple(item for item in evidence if item is not None)
    if any(not isinstance(item, ModelUsabilityEvidence) for item in values):
        raise UsabilityValidationError("Usability evidence is malformed")
    if not values:
        return ModelUsabilityEvidence()

    def _latest_bool(name: str) -> bool | None:
        for item in reversed(values):
            value = cast(bool | None, getattr(item, name))
            if value is not None:
                return value
        return None

    provider_id = next(
        (item.provider_id for item in reversed(values) if item.provider_id is not None), None
    )
    model_id = next((item.model_id for item in reversed(values) if item.model_id is not None), None)
    reason = next(
        (item.reason for item in reversed(values) if item.reason is not UsabilityReason.UNKNOWN),
        UsabilityReason.UNKNOWN,
    )
    source = next(
        (item.source for item in reversed(values) if item.source and item.source != "unknown"),
        "unknown",
    )
    detail = next(
        (
            item.detail
            for item in reversed(values)
            if item.detail and item.detail != "provider-neutral usability evidence"
        ),
        "provider-neutral usability evidence",
    )
    observed_at = next(
        (item.observed_at for item in reversed(values) if item.observed_at is not None), None
    )
    expires_at = next(
        (item.expires_at for item in reversed(values) if item.expires_at is not None), None
    )
    return ModelUsabilityEvidence(
        configured=_latest_bool("configured"),
        connected=_latest_bool("connected"),
        reachable=_latest_bool("reachable"),
        authenticated=_latest_bool("authenticated"),
        entitled=_latest_bool("entitled"),
        quota_usable=_latest_bool("quota_usable"),
        capacity_usable=_latest_bool("capacity_usable"),
        model_usable=_latest_bool("model_usable"),
        policy_eligible=_latest_bool("policy_eligible"),
        resource_eligible=_latest_bool("resource_eligible"),
        request_usable=_latest_bool("request_usable"),
        detail=detail,
        provider_id=provider_id,
        model_id=model_id,
        reason=reason,
        source=source,
        observed_at=observed_at,
        expires_at=expires_at,
    )


def evidence_for_failure(
    provider_id: str,
    reason: UsabilityReason,
    *,
    model_id: str | None = None,
    observed_at: datetime | None = None,
    cooldown_seconds: float | None = 300.0,
    source: str = "routing.failure",
    detail: str = "trusted provider failure feedback",
) -> ModelUsabilityEvidence:
    """Translate a trusted failure classification into bounded evidence."""

    if not isinstance(reason, UsabilityReason):
        raise UsabilityValidationError("Usability failure reason is invalid")
    when = observed_at or datetime.now(UTC)
    if cooldown_seconds is not None and (
        type(cooldown_seconds) not in {int, float} or cooldown_seconds < 0
    ):
        raise UsabilityValidationError("Usability cooldown is invalid")
    expiry = (
        when + timedelta(seconds=float(cooldown_seconds)) if cooldown_seconds is not None else None
    )
    dimensions: dict[str, bool | None] = {
        name: None for name in ModelUsabilityEvidence._BOOLEAN_FIELDS
    }
    if reason is UsabilityReason.INVALID_CREDENTIALS:
        dimensions["authenticated"] = False
    elif reason is UsabilityReason.AUTHENTICATION_UNAVAILABLE:
        dimensions["authenticated"] = None
    elif reason in {UsabilityReason.QUOTA_EXHAUSTED, UsabilityReason.BILLING_BLOCKED}:
        dimensions["quota_usable"] = False
    elif reason is UsabilityReason.BUDGET_EXHAUSTED:
        dimensions["policy_eligible"] = False
    elif reason is UsabilityReason.MODEL_NOT_ENTITLED:
        dimensions["entitled"] = False
    elif reason in {UsabilityReason.MODEL_UNAVAILABLE, UsabilityReason.MODEL_NOT_FOUND}:
        dimensions["model_usable"] = False
    elif reason in {
        UsabilityReason.RATE_LIMITED,
        UsabilityReason.PROVIDER_CAPACITY_EXHAUSTED,
        UsabilityReason.TEMPORARILY_DEGRADED,
    }:
        dimensions["capacity_usable"] = False
    elif reason is UsabilityReason.PROVIDER_OUTAGE:
        dimensions["connected"] = False
        dimensions["reachable"] = False
    elif reason is UsabilityReason.NETWORK_UNAVAILABLE:
        dimensions["reachable"] = False
    elif reason is UsabilityReason.POLICY_BLOCKED:
        dimensions["policy_eligible"] = False
    elif reason is UsabilityReason.PRIVACY_BLOCKED:
        dimensions["policy_eligible"] = False
    elif reason is UsabilityReason.LOCAL_RESOURCE_BLOCKED:
        dimensions["resource_eligible"] = False
    dimensions["request_usable"] = False
    return ModelUsabilityEvidence(
        **dimensions,
        detail=detail,
        provider_id=provider_id,
        model_id=model_id,
        reason=reason,
        source=source,
        observed_at=when,
        expires_at=expiry,
    )


def evidence_for_success(
    provider_id: str,
    model_id: str,
    *,
    observed_at: datetime | None = None,
    source: str = "inference.success",
) -> ModelUsabilityEvidence:
    """Return only dimensions justified by a completed inference."""

    when = observed_at or datetime.now(UTC)
    return ModelUsabilityEvidence(
        configured=True,
        connected=True,
        reachable=True,
        authenticated=True,
        capacity_usable=True,
        model_usable=True,
        policy_eligible=True,
        resource_eligible=True,
        request_usable=True,
        provider_id=provider_id,
        model_id=model_id,
        source=source,
        observed_at=when,
        expires_at=when + timedelta(seconds=60),
        detail="successful inference is current operational evidence",
    )


__all__ = [
    "ModelUsabilityEvidence",
    "ModelUsabilityStatus",
    "ProviderUsabilityEvidence",
    "UsabilityEvidence",
    "UsabilityFreshness",
    "UsabilityReason",
    "UsabilityValidationError",
    "evidence_for_failure",
    "evidence_for_success",
    "merge_usability_evidence",
]
