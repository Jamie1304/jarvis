"""Generic passive/read-only/active environment discovery.

Discovery records evidence only.  They do not authenticate devices, establish
ownership, install integrations, or grant authority.
"""

from __future__ import annotations

from collections.abc import Callable, Iterable
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from enum import StrEnum
from typing import Protocol

from jarvis.discovery.models import DiscoverySource


class EnvironmentDiscoveryError(ValueError):
    """Discovery input or policy failed closed."""


class DiscoveryDenied(PermissionError):
    """Active discovery was not authorized by the stronger discovery policy."""


class DiscoveryMode(StrEnum):
    PASSIVE_DISCOVERY = "passive_discovery"
    READ_ONLY_LOCAL_DISCOVERY = "read_only_local_discovery"
    ACTIVE_DISCOVERY = "active_discovery"


@dataclass(frozen=True, slots=True)
class DiscoveryConfidence:
    score: float
    rationale: str

    def __post_init__(self) -> None:
        if not 0.0 <= self.score <= 1.0:
            raise EnvironmentDiscoveryError("Discovery confidence must be between zero and one")
        _text(self.rationale, "Discovery confidence rationale", 1_000)


@dataclass(frozen=True, slots=True)
class EnvironmentIdentity:
    stable_key: str
    kind: str
    identifiers: tuple[tuple[str, str], ...]

    def __post_init__(self) -> None:
        _text(self.stable_key, "Environment identity", 256)
        _text(self.kind, "Environment kind", 128)
        _properties(self.identifiers, "Environment identifiers")
        if not self.identifiers:
            raise EnvironmentDiscoveryError("Environment identity needs an identifier")


@dataclass(frozen=True, slots=True)
class DiscoveryObservation:
    source: DiscoverySource
    observed_at: datetime
    identity: EnvironmentIdentity
    properties: tuple[tuple[str, str], ...]
    classification: str
    origin: str
    first_seen: datetime
    last_seen: datetime
    provenance: tuple[str, ...]
    confidence: DiscoveryConfidence
    external_untrusted: bool = True

    def __post_init__(self) -> None:
        if not isinstance(self.source, DiscoverySource):
            raise EnvironmentDiscoveryError("Discovery source is invalid")
        for timestamp in (self.observed_at, self.first_seen, self.last_seen):
            if timestamp.tzinfo is None:
                raise EnvironmentDiscoveryError("Discovery timestamps must be timezone-aware")
        if self.first_seen > self.last_seen or self.observed_at < self.first_seen:
            raise EnvironmentDiscoveryError("Discovery observation timestamps are inconsistent")
        _properties(self.properties, "Discovery properties")
        _text(self.classification, "Discovery classification", 128)
        _text(self.origin, "Discovery origin", 256)
        _labels(self.provenance, "Discovery provenance", 32)
        if not self.external_untrusted:
            raise EnvironmentDiscoveryError("External discovery cannot be trusted by construction")


@dataclass(frozen=True, slots=True)
class EnvironmentCandidate:
    identity: EnvironmentIdentity
    observations: tuple[DiscoveryObservation, ...]
    classification: str
    origin: str
    first_seen: datetime
    last_seen: datetime
    provenance: tuple[str, ...]
    confidence: DiscoveryConfidence
    external_untrusted: bool = True

    def __post_init__(self) -> None:
        if not self.observations:
            raise EnvironmentDiscoveryError("Environment candidate needs evidence")
        if not self.external_untrusted:
            raise EnvironmentDiscoveryError("Environment candidate cannot be trusted")
        if any(item.identity.stable_key != self.identity.stable_key for item in self.observations):
            raise EnvironmentDiscoveryError("Candidate observations have different identities")

    def stale(self, *, now: datetime, max_age: timedelta) -> bool:
        if now.tzinfo is None or max_age < timedelta(0):
            raise EnvironmentDiscoveryError("Stale check requires timezone-aware nonnegative age")
        return now - self.last_seen > max_age


class EnvironmentDiscoveryProvider(Protocol):
    @property
    def source(self) -> DiscoverySource: ...

    def discover(self, mode: DiscoveryMode) -> tuple[DiscoveryObservation, ...]: ...


class EnvironmentDiscoveryPolicy(Protocol):
    def allow_active(self, source: DiscoverySource) -> bool: ...


class DenyActiveDiscoveryPolicy:
    def allow_active(self, source: DiscoverySource) -> bool:
        del source
        return False


class EnvironmentDiscoveryService:
    """Bounded provider-neutral discovery with evidence-only candidate events."""

    def __init__(
        self,
        providers: Iterable[EnvironmentDiscoveryProvider],
        *,
        policy: EnvironmentDiscoveryPolicy | None = None,
        candidate_sink: Callable[[EnvironmentCandidate], None] | None = None,
    ) -> None:
        self._providers = tuple(providers)
        self._policy = policy or DenyActiveDiscoveryPolicy()
        self._candidate_sink = candidate_sink
        self._candidates: dict[str, EnvironmentCandidate] = {}

    def discover(self, mode: DiscoveryMode) -> tuple[EnvironmentCandidate, ...]:
        for provider in self._providers:
            if not isinstance(provider.source, DiscoverySource):
                raise EnvironmentDiscoveryError("Provider source is invalid")
            if mode is DiscoveryMode.ACTIVE_DISCOVERY and not self._policy.allow_active(
                provider.source
            ):
                raise DiscoveryDenied(f"Active discovery denied for {provider.source.value}")
            observations = provider.discover(mode)
            for observation in observations:
                if observation.source is not provider.source:
                    raise EnvironmentDiscoveryError("Observation source does not match provider")
                self._record(observation)
        return tuple(self._candidates.values())

    def candidates(self) -> tuple[EnvironmentCandidate, ...]:
        return tuple(self._candidates.values())

    def stale(
        self, *, now: datetime | None = None, max_age: timedelta
    ) -> tuple[EnvironmentCandidate, ...]:
        current = now or datetime.now(UTC)
        return tuple(
            candidate
            for candidate in self._candidates.values()
            if candidate.stale(now=current, max_age=max_age)
        )

    def forget_stale(
        self, *, now: datetime | None = None, max_age: timedelta
    ) -> tuple[EnvironmentCandidate, ...]:
        stale = self.stale(now=now, max_age=max_age)
        for candidate in stale:
            self._candidates.pop(candidate.identity.stable_key, None)
        return stale

    def _record(self, observation: DiscoveryObservation) -> None:
        existing = self._candidates.get(observation.identity.stable_key)
        if existing is not None:
            if observation in existing.observations:
                return
            observations = (*existing.observations, observation)
            first_seen = min(existing.first_seen, observation.first_seen)
            last_seen = max(existing.last_seen, observation.last_seen)
            provenance = tuple(dict.fromkeys((*existing.provenance, *observation.provenance)))
            confidence = max(
                (existing.confidence, observation.confidence), key=lambda item: item.score
            )
            candidate = EnvironmentCandidate(
                existing.identity,
                observations,
                existing.classification,
                existing.origin,
                first_seen,
                last_seen,
                provenance,
                confidence,
            )
        else:
            candidate = EnvironmentCandidate(
                observation.identity,
                (observation,),
                observation.classification,
                observation.origin,
                observation.first_seen,
                observation.last_seen,
                observation.provenance,
                observation.confidence,
            )
        self._candidates[observation.identity.stable_key] = candidate
        if self._candidate_sink is not None:
            self._candidate_sink(candidate)


def _text(value: str, name: str, limit: int) -> None:
    if type(value) is not str or not value.strip() or len(value) > limit or not value.isprintable():
        raise EnvironmentDiscoveryError(f"{name} is invalid")


def _properties(values: Iterable[tuple[str, str]], name: str) -> None:
    values = tuple(values)
    if len(values) > 64 or any(
        type(key) is not str
        or type(value) is not str
        or not key.strip()
        or not value.strip()
        or len(key) > 128
        or len(value) > 1_000
        or not key.isprintable()
        or not value.isprintable()
        for key, value in values
    ):
        raise EnvironmentDiscoveryError(f"{name} are invalid")


def _labels(values: Iterable[str], name: str, limit: int) -> None:
    values = tuple(values)
    if len(values) > limit or any(
        type(value) is not str or not value.strip() or len(value) > 512 or not value.isprintable()
        for value in values
    ):
        raise EnvironmentDiscoveryError(f"{name} are invalid")
