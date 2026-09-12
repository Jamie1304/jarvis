"""Trusted broker effect observations for staged integration activation.

Integration output is an intention or an untrusted result.  This module records
what the application-owned broker observed at its dispatch boundary.  Only a
trusted observer issued by :class:`EffectAttestationStore` can write an
observation or mint an attestation.  The store is deliberately small and
durable; it is an evidence store, not a permission or activation authority.
"""

from __future__ import annotations

import json
import sqlite3
from collections.abc import Iterable
from dataclasses import dataclass, field
from datetime import UTC, datetime
from enum import StrEnum
from pathlib import Path
from uuid import UUID, uuid4

from jarvis.events import EventBus, EventEnvelope, EventType
from jarvis.events.models import EffectAttestationRecorded


class EffectAttestationError(ValueError):
    """An effect observation or attestation is malformed or not trusted."""


class EffectAttestationStatus(StrEnum):
    DENIED = "denied"
    SUPPRESSED = "suppressed"
    PRE_EFFECT_FAILURE = "pre_effect_failure"
    DISPATCHED = "dispatched"
    EFFECT_CONFIRMED = "effect_confirmed"
    UNKNOWN_OUTCOME = "unknown_outcome"


def _text(value: object, name: str, limit: int = 1_024) -> str:
    if (
        type(value) is not str
        or not value.strip()
        or len(value) > limit
        or "\x00" in value
        or any(ord(character) < 32 for character in value)
    ):
        raise EffectAttestationError(f"{name} is malformed")
    return value.strip()


def _identifier(value: object, name: str) -> str:
    value = _text(value, name, 256)
    if any(
        character not in "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789._-"
        for character in value
    ):
        raise EffectAttestationError(f"{name} is malformed")
    return value


def _digest(value: object, name: str) -> str:
    value = _text(value, name, 64)
    if len(value) != 64 or any(character not in "0123456789abcdef" for character in value):
        raise EffectAttestationError(f"{name} is malformed")
    return value


def _time(value: datetime, name: str) -> datetime:
    if not isinstance(value, datetime) or value.tzinfo is None:
        raise EffectAttestationError(f"{name} must be timezone-aware")
    return value.astimezone(UTC)


@dataclass(frozen=True, slots=True)
class EffectAttemptRecord:
    """A trusted reservation immediately before a broker dispatch."""

    attempt_id: UUID
    integration_id: str
    integration_version: str
    package_hash: str
    activation_state: str
    activation_id: str
    action_id: str
    request_id: UUID
    broker: str
    normalized_target: str
    normalized_scope: str
    requested_effect: str
    correlation_id: UUID | None = None
    task_id: UUID | None = None
    started_at: datetime = field(default_factory=lambda: datetime.now(UTC))

    def __post_init__(self) -> None:
        if not isinstance(self.attempt_id, UUID) or not isinstance(self.request_id, UUID):
            raise EffectAttestationError("Attempt identity is malformed")
        for value, name in (
            (self.integration_id, "Integration ID"),
            (self.integration_version, "Integration version"),
            (self.activation_state, "Activation state"),
            (self.activation_id, "Activation ID"),
            (self.action_id, "Action ID"),
            (self.broker, "Broker"),
            (self.normalized_target, "Effect target"),
            (self.normalized_scope, "Effect scope"),
            (self.requested_effect, "Requested effect"),
        ):
            _text(value, name)
        _digest(self.package_hash, "Package hash")
        for optional_value, name in (
            (self.correlation_id, "Correlation ID"),
            (self.task_id, "Task ID"),
        ):
            if optional_value is not None and not isinstance(optional_value, UUID):
                raise EffectAttestationError(f"{name} is malformed")
        object.__setattr__(self, "started_at", _time(self.started_at, "Attempt time"))


@dataclass(frozen=True, slots=True)
class BrokerEffectObservation:
    """Immutable fact produced by a trusted JARVIS broker boundary."""

    observation_id: UUID
    attempt_id: UUID
    integration_id: str
    integration_version: str
    package_hash: str
    activation_state: str
    activation_id: str
    action_id: str
    request_id: UUID
    broker: str
    normalized_target: str
    normalized_scope: str
    requested_effect: str
    allowed: bool
    dispatched: bool
    result_category: EffectAttestationStatus
    observed_at: datetime
    correlation_id: UUID | None = None
    task_id: UUID | None = None

    def __post_init__(self) -> None:
        if not isinstance(self.observation_id, UUID) or not isinstance(self.attempt_id, UUID):
            raise EffectAttestationError("Observation identity is malformed")
        if not isinstance(self.request_id, UUID):
            raise EffectAttestationError("Request identity is malformed")
        for value, name in (
            (self.integration_id, "Integration ID"),
            (self.integration_version, "Integration version"),
            (self.activation_state, "Activation state"),
            (self.activation_id, "Activation ID"),
            (self.action_id, "Action ID"),
            (self.broker, "Broker"),
            (self.normalized_target, "Effect target"),
            (self.normalized_scope, "Effect scope"),
            (self.requested_effect, "Requested effect"),
        ):
            _text(value, name)
        _digest(self.package_hash, "Package hash")
        if type(self.allowed) is not bool or type(self.dispatched) is not bool:
            raise EffectAttestationError("Observation authorization flags are malformed")
        if not isinstance(self.result_category, EffectAttestationStatus):
            raise EffectAttestationError("Observation result is malformed")
        if self.result_category is EffectAttestationStatus.SUPPRESSED and self.dispatched:
            raise EffectAttestationError("Suppressed effect cannot be dispatched")
        if self.dispatched and not self.allowed:
            raise EffectAttestationError("Dispatched effect must have been allowed")
        for optional_value, name in (
            (self.correlation_id, "Correlation ID"),
            (self.task_id, "Task ID"),
        ):
            if optional_value is not None and not isinstance(optional_value, UUID):
                raise EffectAttestationError(f"{name} is malformed")
        object.__setattr__(self, "observed_at", _time(self.observed_at, "Observation time"))


@dataclass(frozen=True, slots=True)
class EffectAttestation:
    """Trusted aggregate proof minted from store-owned broker observations."""

    attestation_id: UUID
    activation_id: str
    integration_id: str
    integration_version: str
    package_hash: str
    activation_state: str
    status: EffectAttestationStatus
    observation_ids: tuple[UUID, ...]
    request_count: int
    allowed_count: int
    dispatched_count: int
    unknown_count: int
    effect_descriptions: tuple[str, ...]
    zero_trusted_dispatch: bool
    created_at: datetime

    def __post_init__(self) -> None:
        if not isinstance(self.attestation_id, UUID):
            raise EffectAttestationError("Attestation identity is malformed")
        for value, name in (
            (self.activation_id, "Activation ID"),
            (self.integration_id, "Integration ID"),
            (self.integration_version, "Integration version"),
            (self.activation_state, "Activation state"),
        ):
            _text(value, name)
        _digest(self.package_hash, "Package hash")
        if not isinstance(self.status, EffectAttestationStatus):
            raise EffectAttestationError("Attestation status is malformed")
        if (
            not isinstance(self.observation_ids, tuple)
            or not self.observation_ids
            or any(not isinstance(value, UUID) for value in self.observation_ids)
            or len(set(self.observation_ids)) != len(self.observation_ids)
        ):
            raise EffectAttestationError("Attestation observations are malformed")
        for count_value, name in (
            (self.request_count, "Request count"),
            (self.allowed_count, "Allowed count"),
            (self.dispatched_count, "Dispatch count"),
            (self.unknown_count, "Unknown count"),
        ):
            if type(count_value) is not int or count_value < 0 or count_value > 1_000_000:
                raise EffectAttestationError(f"{name} is malformed")
        if self.dispatched_count > self.allowed_count or self.allowed_count > self.request_count:
            raise EffectAttestationError("Attestation counts are inconsistent")
        if type(self.zero_trusted_dispatch) is not bool:
            raise EffectAttestationError("Zero-dispatch proof is malformed")
        if self.zero_trusted_dispatch != (self.dispatched_count == 0):
            raise EffectAttestationError("Zero-dispatch proof does not match observations")
        if any(type(value) is not str or not value.strip() for value in self.effect_descriptions):
            raise EffectAttestationError("Effect descriptions are malformed")
        object.__setattr__(self, "created_at", _time(self.created_at, "Attestation time"))


class TrustedEffectObserver:
    """Capability held by trusted broker adapters, never by package code."""

    def __init__(
        self, store: EffectAttestationStore, binding: tuple[str, str, str, str, str], token: object
    ):
        self._store = store
        self._binding = binding
        self._token = token

    @property
    def activation_state(self) -> str:
        return self._binding[3]

    @property
    def activation_id(self) -> str:
        return self._binding[4]

    def begin(
        self,
        *,
        action_id: str,
        request_id: UUID,
        broker: str,
        target: str,
        scope: str,
        requested_effect: str,
        correlation_id: UUID | None = None,
        task_id: UUID | None = None,
    ) -> EffectAttemptRecord:
        return self._store._begin(
            self._token,
            EffectAttemptRecord(
                uuid4(),
                self._binding[0],
                self._binding[1],
                self._binding[2],
                self._binding[3],
                self._binding[4],
                action_id,
                request_id,
                broker,
                target,
                scope,
                requested_effect,
                correlation_id,
                task_id,
            ),
        )

    def complete(
        self,
        attempt: EffectAttemptRecord,
        *,
        status: EffectAttestationStatus,
        dispatched: bool,
        allowed: bool = True,
    ) -> BrokerEffectObservation:
        return self._store._complete(self._token, attempt, status, dispatched, allowed)


class EffectAttestationStore:
    """Durable trusted evidence store and the only attestation minting path."""

    _SCHEMA = 1

    def __init__(self, path: Path | None = None, *, event_bus: EventBus | None = None) -> None:
        self._connection: sqlite3.Connection | None = None
        self._event_bus = event_bus
        self._observations: dict[UUID, BrokerEffectObservation] = {}
        self._attempts: dict[UUID, EffectAttemptRecord] = {}
        self._attestations: dict[UUID, EffectAttestation] = {}
        self._token = object()
        if path is not None:
            path.parent.mkdir(parents=True, exist_ok=True)
            self._connection = sqlite3.connect(path, timeout=5.0)
            self._connection.execute("PRAGMA journal_mode=WAL")
            self._connection.execute("PRAGMA busy_timeout=5000")
            self._connection.execute(
                "CREATE TABLE IF NOT EXISTS effect_schema (version INTEGER PRIMARY KEY)"
            )
            versions = {
                int(row[0]) for row in self._connection.execute("SELECT version FROM effect_schema")
            }
            if any(version > self._SCHEMA for version in versions):
                self.close()
                raise EffectAttestationError("Effect evidence database uses a future schema")
            self._connection.execute(
                "CREATE TABLE IF NOT EXISTS effect_observations "
                "(observation_id TEXT PRIMARY KEY, payload TEXT NOT NULL)"
            )
            self._connection.execute(
                "CREATE TABLE IF NOT EXISTS effect_attempts "
                "(attempt_id TEXT PRIMARY KEY, payload TEXT NOT NULL)"
            )
            self._connection.execute(
                "CREATE TABLE IF NOT EXISTS effect_attestations "
                "(attestation_id TEXT PRIMARY KEY, payload TEXT NOT NULL)"
            )
            if not versions:
                self._connection.execute(
                    "INSERT INTO effect_schema(version) VALUES (?)", (self._SCHEMA,)
                )
            self._connection.commit()
            self._load()
            self.reconcile_pending()

    def close(self) -> None:
        if self._connection is not None:
            self._connection.close()
            self._connection = None

    def observer(
        self,
        integration_id: str,
        integration_version: str,
        package_hash: str,
        activation_state: str,
        activation_id: str,
    ) -> TrustedEffectObserver:
        binding = (
            _identifier(integration_id, "Integration ID"),
            _text(integration_version, "Integration version", 256),
            _digest(package_hash, "Package hash"),
            _text(activation_state, "Activation state", 64),
            _text(activation_id, "Activation ID"),
        )
        return TrustedEffectObserver(self, binding, self._token)

    def observations(self, activation_id: str) -> tuple[BrokerEffectObservation, ...]:
        _text(activation_id, "Activation ID")
        return tuple(
            observation
            for observation in self._observations.values()
            if observation.activation_id == activation_id
        )

    def attest(
        self,
        *,
        activation_id: str,
        integration_id: str,
        integration_version: str,
        package_hash: str,
        activation_state: str,
    ) -> EffectAttestation:
        _text(activation_id, "Activation ID")
        _identifier(integration_id, "Integration ID")
        _text(integration_version, "Integration version", 256)
        _digest(package_hash, "Package hash")
        _text(activation_state, "Activation state", 64)
        selected = tuple(
            item
            for item in self._observations.values()
            if item.activation_state == activation_state
            and item.activation_id == activation_id
            and item.integration_id == integration_id
            and item.integration_version == integration_version
            and item.package_hash == package_hash
        )
        if not selected:
            raise EffectAttestationError("No trusted broker observations are available")
        dispatched = sum(item.dispatched for item in selected)
        allowed = sum(item.allowed for item in selected)
        unknown = sum(
            item.result_category is EffectAttestationStatus.UNKNOWN_OUTCOME for item in selected
        )
        if unknown:
            status = EffectAttestationStatus.UNKNOWN_OUTCOME
        elif activation_state == "SHADOW":
            status = (
                EffectAttestationStatus.SUPPRESSED
                if dispatched == 0 and all(not item.dispatched for item in selected)
                else EffectAttestationStatus.UNKNOWN_OUTCOME
            )
        elif dispatched:
            status = (
                EffectAttestationStatus.EFFECT_CONFIRMED
                if all(
                    item.result_category is EffectAttestationStatus.EFFECT_CONFIRMED
                    for item in selected
                    if item.dispatched
                )
                else EffectAttestationStatus.DISPATCHED
            )
        else:
            status = EffectAttestationStatus.PRE_EFFECT_FAILURE
        attestation = EffectAttestation(
            uuid4(),
            activation_id,
            integration_id,
            integration_version,
            package_hash,
            activation_state,
            status,
            tuple(item.observation_id for item in selected),
            len(selected),
            allowed,
            dispatched,
            unknown,
            tuple(item.requested_effect for item in selected if item.dispatched),
            dispatched == 0,
            datetime.now(UTC),
        )
        self._attestations[attestation.attestation_id] = attestation
        self._persist_attestation(attestation)
        self._emit(
            EffectAttestationRecorded(
                None,
                attestation.attestation_id,
                attestation.integration_id,
                attestation.integration_version,
                attestation.activation_state,
                attestation.status.value,
            ),
            next(
                (
                    item.correlation_id or item.task_id
                    for item in selected
                    if item.correlation_id is not None or item.task_id is not None
                ),
                None,
            ),
        )
        return attestation

    def is_trusted(self, attestation: EffectAttestation) -> bool:
        return (
            isinstance(attestation, EffectAttestation)
            and self._attestations.get(attestation.attestation_id) == attestation
        )

    def is_trusted_for(
        self,
        observation_ids: Iterable[UUID],
        activation_id: str,
        activation_state: str,
        integration_id: str,
        integration_version: str,
        package_hash: str,
    ) -> bool:
        ids = tuple(observation_ids)
        selected = tuple(self._observations.get(item) for item in ids)
        if not ids or any(item is None for item in selected):
            return False
        return all(
            item is not None
            and item.activation_id == activation_id
            and item.activation_state == activation_state
            and item.integration_id == integration_id
            and item.integration_version == integration_version
            and item.package_hash == package_hash
            for item in selected
        )

    def is_trusted_attestation(
        self,
        attestation_id: UUID,
        *,
        activation_id: str,
        activation_state: str,
        integration_id: str,
        integration_version: str,
        package_hash: str,
    ) -> bool:
        attestation = self._attestations.get(attestation_id)
        return bool(
            attestation is not None
            and attestation.activation_id == activation_id
            and attestation.activation_state == activation_state
            and attestation.integration_id == integration_id
            and attestation.integration_version == integration_version
            and attestation.package_hash == package_hash
        )

    def _begin(self, token: object, attempt: EffectAttemptRecord) -> EffectAttemptRecord:
        if token is not self._token:
            raise EffectAttestationError("Only the trusted observer may write attempts")
        self._attempts[attempt.attempt_id] = attempt
        self._persist_attempt(attempt)
        return attempt

    def _complete(
        self,
        token: object,
        attempt: EffectAttemptRecord,
        status: EffectAttestationStatus,
        dispatched: bool,
        allowed: bool,
    ) -> BrokerEffectObservation:
        if token is not self._token or self._attempts.get(attempt.attempt_id) != attempt:
            raise EffectAttestationError("Attempt is not owned by the trusted observer")
        if (
            not isinstance(status, EffectAttestationStatus)
            or type(dispatched) is not bool
            or type(allowed) is not bool
        ):
            raise EffectAttestationError("Effect completion is malformed")
        observation = BrokerEffectObservation(
            uuid4(),
            attempt.attempt_id,
            attempt.integration_id,
            attempt.integration_version,
            attempt.package_hash,
            attempt.activation_state,
            attempt.activation_id,
            attempt.action_id,
            attempt.request_id,
            attempt.broker,
            attempt.normalized_target,
            attempt.normalized_scope,
            attempt.requested_effect,
            allowed,
            dispatched,
            status,
            datetime.now(UTC),
            attempt.correlation_id,
            attempt.task_id,
        )
        self._observations[observation.observation_id] = observation
        del self._attempts[attempt.attempt_id]
        self._persist_observation(observation)
        self._delete_attempt(attempt.attempt_id)
        self._emit(
            EffectAttestationRecorded(
                observation.observation_id,
                None,
                observation.integration_id,
                observation.integration_version,
                observation.activation_state,
                observation.result_category.value,
                observation.allowed,
                observation.dispatched,
            ),
            observation.correlation_id or observation.task_id,
        )
        return observation

    def _emit(self, payload: EffectAttestationRecorded, correlation_id: UUID | None) -> None:
        if self._event_bus is None:
            return
        self._event_bus.publish_nowait(
            EventEnvelope.create(
                EventType.EFFECT_ATTESTATION_RECORDED,
                payload,
                source="effect_attestation.trusted_broker",
                correlation_id=correlation_id or UUID(int=0),
            )
        )

    def reconcile_pending(self) -> tuple[BrokerEffectObservation, ...]:
        results = []
        for attempt in tuple(self._attempts.values()):
            results.append(
                self._complete(
                    self._token,
                    attempt,
                    EffectAttestationStatus.UNKNOWN_OUTCOME,
                    True,
                    True,
                )
            )
        return tuple(results)

    def _persist_observation(self, observation: BrokerEffectObservation) -> None:
        if self._connection is None:
            return
        self._connection.execute(
            "INSERT OR REPLACE INTO effect_observations(observation_id,payload) VALUES (?,?)",
            (str(observation.observation_id), json.dumps(_as_json(observation))),
        )
        self._connection.commit()

    def _persist_attempt(self, attempt: EffectAttemptRecord) -> None:
        if self._connection is None:
            return
        self._connection.execute(
            "INSERT OR REPLACE INTO effect_attempts(attempt_id,payload) VALUES (?,?)",
            (str(attempt.attempt_id), json.dumps(_as_json(attempt))),
        )
        self._connection.commit()

    def _delete_attempt(self, attempt_id: UUID) -> None:
        if self._connection is not None:
            self._connection.execute(
                "DELETE FROM effect_attempts WHERE attempt_id=?", (str(attempt_id),)
            )
            self._connection.commit()

    def _persist_attestation(self, attestation: EffectAttestation) -> None:
        if self._connection is None:
            return
        self._connection.execute(
            "INSERT OR REPLACE INTO effect_attestations(attestation_id,payload) VALUES (?,?)",
            (str(attestation.attestation_id), json.dumps(_as_json(attestation))),
        )
        self._connection.commit()

    def _load(self) -> None:
        if self._connection is None:
            return
        for (payload,) in self._connection.execute("SELECT payload FROM effect_observations"):
            item = json.loads(str(payload))
            observation = BrokerEffectObservation(
                UUID(item["observation_id"]),
                UUID(item["attempt_id"]),
                item["integration_id"],
                item["integration_version"],
                item["package_hash"],
                item["activation_state"],
                item["activation_id"],
                item["action_id"],
                UUID(item["request_id"]),
                item["broker"],
                item["target"],
                item["scope"],
                item["requested_effect"],
                item["allowed"],
                item["dispatched"],
                EffectAttestationStatus(item["result_category"]),
                datetime.fromisoformat(item["observed_at"]),
                UUID(item["correlation_id"]) if item.get("correlation_id") else None,
                UUID(item["task_id"]) if item.get("task_id") else None,
            )
            self._observations[observation.observation_id] = observation
        for (payload,) in self._connection.execute("SELECT payload FROM effect_attempts"):
            item = json.loads(str(payload))
            attempt = EffectAttemptRecord(
                UUID(item["attempt_id"]),
                item["integration_id"],
                item["integration_version"],
                item["package_hash"],
                item["activation_state"],
                item["activation_id"],
                item["action_id"],
                UUID(item["request_id"]),
                item["broker"],
                item["target"],
                item["scope"],
                item["requested_effect"],
                UUID(item["correlation_id"]) if item.get("correlation_id") else None,
                UUID(item["task_id"]) if item.get("task_id") else None,
                datetime.fromisoformat(item["started_at"]),
            )
            self._attempts[attempt.attempt_id] = attempt
        for (payload,) in self._connection.execute("SELECT payload FROM effect_attestations"):
            item = json.loads(str(payload))
            attestation = EffectAttestation(
                UUID(item["attestation_id"]),
                item["activation_id"],
                item["integration_id"],
                item["integration_version"],
                item["package_hash"],
                item["activation_state"],
                EffectAttestationStatus(item["status"]),
                tuple(UUID(value) for value in item["observation_ids"]),
                item["request_count"],
                item["allowed_count"],
                item["dispatched_count"],
                item["unknown_count"],
                tuple(item["effect_descriptions"]),
                item["zero_trusted_dispatch"],
                datetime.fromisoformat(item["created_at"]),
            )
            self._attestations[attestation.attestation_id] = attestation


def _as_json(value: object) -> dict[str, object]:
    if isinstance(value, EffectAttemptRecord):
        return {
            "attempt_id": str(value.attempt_id),
            "integration_id": value.integration_id,
            "integration_version": value.integration_version,
            "package_hash": value.package_hash,
            "activation_state": value.activation_state,
            "action_id": value.action_id,
            "activation_id": value.activation_id,
            "request_id": str(value.request_id),
            "broker": value.broker,
            "target": value.normalized_target,
            "scope": value.normalized_scope,
            "requested_effect": value.requested_effect,
            "correlation_id": str(value.correlation_id) if value.correlation_id else None,
            "task_id": str(value.task_id) if value.task_id else None,
            "started_at": value.started_at.isoformat(),
        }
    if isinstance(value, BrokerEffectObservation):
        return {
            "observation_id": str(value.observation_id),
            "attempt_id": str(value.attempt_id),
            "integration_id": value.integration_id,
            "integration_version": value.integration_version,
            "package_hash": value.package_hash,
            "activation_state": value.activation_state,
            "activation_id": value.activation_id,
            "action_id": value.action_id,
            "request_id": str(value.request_id),
            "broker": value.broker,
            "target": value.normalized_target,
            "scope": value.normalized_scope,
            "requested_effect": value.requested_effect,
            "allowed": value.allowed,
            "dispatched": value.dispatched,
            "result_category": value.result_category.value,
            "observed_at": value.observed_at.isoformat(),
            "correlation_id": str(value.correlation_id) if value.correlation_id else None,
            "task_id": str(value.task_id) if value.task_id else None,
        }
    if isinstance(value, EffectAttestation):
        return {
            "attestation_id": str(value.attestation_id),
            "activation_id": value.activation_id,
            "integration_id": value.integration_id,
            "integration_version": value.integration_version,
            "package_hash": value.package_hash,
            "activation_state": value.activation_state,
            "status": value.status.value,
            "observation_ids": [str(item) for item in value.observation_ids],
            "request_count": value.request_count,
            "allowed_count": value.allowed_count,
            "dispatched_count": value.dispatched_count,
            "unknown_count": value.unknown_count,
            "effect_descriptions": list(value.effect_descriptions),
            "zero_trusted_dispatch": value.zero_trusted_dispatch,
            "created_at": value.created_at.isoformat(),
        }
    raise TypeError(type(value).__name__)


__all__ = [
    "BrokerEffectObservation",
    "EffectAttemptRecord",
    "EffectAttestation",
    "EffectAttestationError",
    "EffectAttestationStatus",
    "EffectAttestationStore",
    "TrustedEffectObserver",
]
