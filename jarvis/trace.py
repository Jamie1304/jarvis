"""Human-readable execution facts and guarded replay preparation.

This module is an observability projection.  It does not own task, plan,
permission, artifact, or verification truth and it deliberately has no fields
for prompts, chain-of-thought, or hidden model reasoning.  Events are emitted
by trusted application adapters from facts already returned by those owners.
Replay produces a plan only; it never invokes a tool or treats a recorded
approval as current authority.
"""

from __future__ import annotations

import json
import math
import sqlite3
from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field
from datetime import UTC, datetime
from enum import StrEnum
from pathlib import Path
from types import MappingProxyType
from typing import Any, cast
from uuid import UUID, uuid4, uuid5

from jarvis.artifacts import ArtifactClassification, ArtifactReference
from jarvis.effects import EffectTraceRecord
from jarvis.events import EventBus
from jarvis.events.models import (
    ArtifactCreated,
    AutomationStateChanged,
    CapabilityChanged,
    CredentialChanged,
    EffectAttestationRecorded,
    EventEnvelope,
    EventPayload,
    EventType,
    GoalCreated,
    HealthChanged,
    IntegrationChanged,
    PermissionDenied,
    PermissionGranted,
    PermissionRequested,
    PlanCreated,
    PlanUpdated,
    StepCompleted,
    StepFailed,
    StepStarted,
    SystemError,
    TaskCreated,
    TaskStateChanged,
    ToolCompleted,
    ToolFailed,
    ToolStarted,
)
from jarvis.planning.models import EffectOutcome


class TraceError(ValueError):
    """A trace record or replay request is malformed."""


class TraceEventType(StrEnum):
    GOAL = "goal"
    AUTOMATION = "automation"
    HEALTH = "health"
    DRIFT = "drift"
    DIAGNOSTIC = "diagnostic"
    REPAIR = "repair"
    PLAN_REVISION = "plan_revision"
    STEP = "step"
    AGENT_EXECUTION = "agent_execution"
    PROVIDER = "provider"
    CAPABILITY_TOOL = "capability_tool"
    CAPABILITY_ACQUISITION = "capability_acquisition"
    CREDENTIAL = "credential"
    PROVISIONING = "provisioning"
    EFFECT_ATTESTATION = "effect_attestation"
    PERMISSION = "permission"
    RESULT = "result"
    ARTIFACT = "artifact"
    EVIDENCE = "evidence"
    VERIFICATION = "verification"
    RETRY = "retry"
    REPLAN = "replan"
    COMPLETION = "completion"
    ERROR = "error"
    REPLAY = "replay"


class ReplayMode(StrEnum):
    SIMULATION = "simulation"
    REPLAN_FROM_CHECKPOINT = "replan_from_checkpoint"
    SAFE_REEXECUTE = "safe_reexecute"


class ReplayDisposition(StrEnum):
    ALLOWED = "allowed"
    REFUSED = "refused"


_MAX_TEXT = 2_000
_MAX_VALUE_BYTES = 16_000
_MAX_ITEMS = 64
_UNTRUSTED_SOURCES = frozenset({"model", "llm", "assistant", "model_output", "prompt"})
_SECRET_KEYS = frozenset(
    {
        "password",
        "passphrase",
        "token",
        "secret",
        "api_key",
        "apikey",
        "access_key",
        "private_key",
        "credential",
        "authorization",
        "cookie",
    }
)
_REDACTED = "[REDACTED]"


def _text(value: object, field_name: str, limit: int = _MAX_TEXT) -> str:
    if (
        type(value) is not str
        or not value.strip()
        or len(value) > limit
        or "\x00" in value
        or any(not character.isprintable() for character in value)
    ):
        raise TraceError(f"{field_name} must be bounded printable text")
    return value


def _utc(value: datetime) -> datetime:
    if value.tzinfo is None:
        raise TraceError("Trace time must be timezone-aware")
    return value.astimezone(UTC)


def _safe_value(
    value: object,
    *,
    classification: ArtifactClassification,
    key: str = "value",
    depth: int = 0,
) -> tuple[object, bool]:
    """Return bounded JSON-like data and whether anything was redacted."""

    if depth > 5:
        raise TraceError(f"{key} is too deeply nested")
    if classification in {
        ArtifactClassification.SENSITIVE,
        ArtifactClassification.CONFIDENTIAL,
        ArtifactClassification.CREDENTIAL_SECRET,
    }:
        return _REDACTED, True
    if value is None or type(value) is bool or type(value) is int:
        return value, False
    if type(value) is float:
        if not math.isfinite(value):
            raise TraceError(f"{key} contains a non-finite number")
        return value, False
    if type(value) is str:
        if len(value) > _MAX_TEXT or "\x00" in value:
            raise TraceError(f"{key} is too large or contains NUL")
        if key.casefold() in _SECRET_KEYS:
            return _REDACTED, True
        return value, False
    if isinstance(value, Mapping):
        if len(value) > _MAX_ITEMS:
            raise TraceError(f"{key} has too many properties")
        result_map: dict[str, object] = {}
        redacted = False
        for raw_key, item in value.items():
            safe_key = _text(raw_key, f"{key} key", 128)
            normalized, changed = _safe_value(
                item,
                classification=classification,
                key=safe_key,
                depth=depth + 1,
            )
            result_map[safe_key] = normalized
            redacted = redacted or changed
        return MappingProxyType(result_map), redacted
    if isinstance(value, Sequence) and not isinstance(value, str | bytes | bytearray):
        if len(value) > _MAX_ITEMS:
            raise TraceError(f"{key} has too many items")
        result_items: list[object] = []
        redacted = False
        for index, item in enumerate(value):
            normalized, changed = _safe_value(
                item,
                classification=classification,
                key=f"{key}[{index}]",
                depth=depth + 1,
            )
            result_items.append(normalized)
            redacted = redacted or changed
        return tuple(result_items), redacted
    raise TraceError(f"{key} contains an unsupported value")


def _json_value(value: object) -> object:
    if isinstance(value, Mapping):
        return {str(key): _json_value(item) for key, item in value.items()}
    if isinstance(value, tuple | list):
        return [_json_value(item) for item in value]
    return value


@dataclass(frozen=True, slots=True)
class TraceUsage:
    """Provider usage facts, never a prompt or hidden reasoning trace."""

    input_tokens: int = 0
    output_tokens: int = 0
    total_tokens: int = 0
    cost: float = 0.0

    def __post_init__(self) -> None:
        if min(self.input_tokens, self.output_tokens, self.total_tokens) < 0:
            raise TraceError("Trace token usage cannot be negative")
        if self.total_tokens < self.input_tokens + self.output_tokens:
            raise TraceError("Trace total tokens cannot be below component usage")
        if self.cost < 0 or not math.isfinite(self.cost):
            raise TraceError("Trace cost must be finite and non-negative")


@dataclass(frozen=True, slots=True)
class TraceEvent:
    """One bounded, factual execution event suitable for operator display."""

    trace_id: UUID
    event_type: TraceEventType
    summary: str
    source: str = "application"
    event_id: UUID = field(default_factory=uuid4)
    occurred_at: datetime = field(default_factory=lambda: datetime.now(UTC))
    duration_seconds: float | None = None
    task_id: UUID | None = None
    plan_id: UUID | None = None
    step_id: UUID | None = None
    turn_id: UUID | None = None
    request_id: UUID | None = None
    effect_id: UUID | None = None
    correlation_id: UUID | None = None
    causation_id: UUID | None = None
    goal_id: UUID | None = None
    session_id: UUID | None = None
    integration_id: str | None = None
    package_version: str | None = None
    package_hash: str | None = None
    credential_reference_ids: tuple[UUID, ...] = ()
    model: str | None = None
    usage: TraceUsage | None = None
    arguments: Mapping[str, object] = field(default_factory=dict)
    permissions: tuple[str, ...] = ()
    result: object | None = None
    artifacts: tuple[ArtifactReference, ...] = ()
    evidence: tuple[str, ...] = ()
    error: str | None = None
    effect_outcome: EffectOutcome | None = None
    external_effect: bool = False
    replay_safe: bool = False
    approval_ids: tuple[UUID, ...] = ()
    effect_attestation_ids: tuple[UUID, ...] = ()
    classification: ArtifactClassification = ArtifactClassification.INTERNAL
    redaction_applied: bool = field(init=False, default=False)

    def __post_init__(self) -> None:
        if not isinstance(self.trace_id, UUID) or not isinstance(self.event_id, UUID):
            raise TraceError("Trace IDs must be UUIDs")
        if not isinstance(self.event_type, TraceEventType):
            raise TraceError("Trace event type is invalid")
        _text(self.summary, "Trace summary")
        _text(self.source, "Trace source", 256)
        if self.source.casefold() in _UNTRUSTED_SOURCES:
            raise TraceError("Model output cannot create trusted trace facts")
        for value, name in (
            (self.correlation_id, "Correlation ID"),
            (self.causation_id, "Causation ID"),
            (self.goal_id, "Goal ID"),
            (self.session_id, "Session ID"),
        ):
            if value is not None and not isinstance(value, UUID):
                raise TraceError(f"{name} is malformed")
        if self.integration_id is not None:
            _text(self.integration_id, "Trace integration", 256)
        if self.package_version is not None:
            _text(self.package_version, "Trace package version", 128)
        if self.package_hash is not None:
            if (
                type(self.package_hash) is not str
                or len(self.package_hash) != 64
                or any(character not in "0123456789abcdef" for character in self.package_hash)
            ):
                raise TraceError("Trace package hash is malformed")
        object.__setattr__(self, "occurred_at", _utc(self.occurred_at))
        if self.duration_seconds is not None and (
            self.duration_seconds < 0 or not math.isfinite(self.duration_seconds)
        ):
            raise TraceError("Trace duration must be finite and non-negative")
        if type(self.external_effect) is not bool or type(self.replay_safe) is not bool:
            raise TraceError("Trace effect flags must be booleans")
        if self.model is not None:
            _text(self.model, "Trace model", 512)
        if self.error is not None:
            _text(self.error, "Trace error")
        if not isinstance(self.classification, ArtifactClassification):
            raise TraceError("Trace classification is invalid")
        if self.event_type is TraceEventType.REPLAY and self.external_effect:
            raise TraceError("Replay trace events cannot claim an external effect")
        source = self.summary.casefold()
        if any(
            marker in source for marker in ("chain of thought", "hidden reasoning", "scratchpad")
        ):
            raise TraceError("Hidden reasoning cannot be recorded in an execution trace")
        if (
            not isinstance(self.permissions, tuple)
            or len(self.permissions) > _MAX_ITEMS
            or any(
                type(item) is not str or not item.strip() or len(item) > 256
                for item in self.permissions
            )
        ):
            raise TraceError("Trace permissions are malformed")
        if (
            not isinstance(self.evidence, tuple)
            or len(self.evidence) > _MAX_ITEMS
            or any(
                type(item) is not str or not item.strip() or len(item) > 1_000
                for item in self.evidence
            )
        ):
            raise TraceError("Trace evidence is malformed")
        if not isinstance(self.approval_ids, tuple) or any(
            not isinstance(item, UUID) for item in self.approval_ids
        ):
            raise TraceError("Trace approval IDs are malformed")
        if not isinstance(self.effect_attestation_ids, tuple) or any(
            not isinstance(item, UUID) for item in self.effect_attestation_ids
        ):
            raise TraceError("Trace effect attestation IDs are malformed")
        if not isinstance(self.credential_reference_ids, tuple) or any(
            not isinstance(item, UUID) for item in self.credential_reference_ids
        ):
            raise TraceError("Trace credential references are malformed")
        if any(not isinstance(item, ArtifactReference) for item in self.artifacts):
            raise TraceError("Trace artifact links are malformed")
        arguments, arguments_redacted = _safe_value(
            self.arguments,
            classification=self.classification,
            key="arguments",
        )
        result, result_redacted = _safe_value(
            self.result,
            classification=self.classification,
            key="result",
        )
        object.__setattr__(self, "arguments", arguments)
        object.__setattr__(self, "result", result)
        object.__setattr__(self, "redaction_applied", arguments_redacted or result_redacted)

    def to_dict(self) -> dict[str, object]:
        """Serialize only redacted, bounded facts; storage paths are not exposed."""

        return {
            "trace_id": str(self.trace_id),
            "event_id": str(self.event_id),
            "event_type": self.event_type.value,
            "summary": self.summary,
            "source": self.source,
            "occurred_at": self.occurred_at.isoformat(),
            "duration_seconds": self.duration_seconds,
            "task_id": str(self.task_id) if self.task_id else None,
            "plan_id": str(self.plan_id) if self.plan_id else None,
            "step_id": str(self.step_id) if self.step_id else None,
            "turn_id": str(self.turn_id) if self.turn_id else None,
            "request_id": str(self.request_id) if self.request_id else None,
            "effect_id": str(self.effect_id) if self.effect_id else None,
            "correlation_id": str(self.correlation_id) if self.correlation_id else None,
            "causation_id": str(self.causation_id) if self.causation_id else None,
            "goal_id": str(self.goal_id) if self.goal_id else None,
            "session_id": str(self.session_id) if self.session_id else None,
            "integration_id": self.integration_id,
            "package_version": self.package_version,
            "package_hash": self.package_hash,
            "credential_reference_ids": [str(item) for item in self.credential_reference_ids],
            "model": self.model,
            "usage": (
                {
                    "input_tokens": self.usage.input_tokens,
                    "output_tokens": self.usage.output_tokens,
                    "total_tokens": self.usage.total_tokens,
                    "cost": self.usage.cost,
                }
                if self.usage is not None
                else None
            ),
            "arguments": _json_value(self.arguments),
            "permissions": list(self.permissions),
            "result": _json_value(self.result),
            "artifacts": [
                {
                    "artifact_id": str(item.artifact_id),
                    "version": item.version,
                    "workspace_id": item.workspace_id,
                }
                for item in self.artifacts
            ],
            "evidence": list(self.evidence),
            "error": self.error,
            "effect_outcome": self.effect_outcome.value if self.effect_outcome else None,
            "external_effect": self.external_effect,
            "replay_safe": self.replay_safe,
            "approval_ids": [str(item) for item in self.approval_ids],
            "effect_attestation_ids": [str(item) for item in self.effect_attestation_ids],
            "classification": self.classification.value,
            "redaction_applied": self.redaction_applied,
        }

    @classmethod
    def from_dict(cls, data: Mapping[str, object]) -> TraceEvent:
        def optional_uuid(name: str) -> UUID | None:
            raw = data.get(name)
            return UUID(str(raw)) if raw else None

        usage_data = data.get("usage")
        usage = (
            TraceUsage(
                input_tokens=int(usage_data.get("input_tokens", 0)),
                output_tokens=int(usage_data.get("output_tokens", 0)),
                total_tokens=int(usage_data.get("total_tokens", 0)),
                cost=float(cast(Any, usage_data.get("cost", 0.0))),
            )
            if isinstance(usage_data, Mapping)
            else None
        )
        artifact_data = data.get("artifacts", ())
        if not isinstance(artifact_data, Sequence) or isinstance(artifact_data, str):
            raise TraceError("Trace artifact data is malformed")
        if any(not isinstance(item, Mapping) for item in artifact_data):
            raise TraceError("Trace artifact entry is malformed")
        artifacts = tuple(
            ArtifactReference(
                UUID(str(item["artifact_id"])),
                int(item["version"]),
                str(item["workspace_id"]),
                "trace://artifact/" + str(item["artifact_id"]),
            )
            for item in artifact_data
            if isinstance(item, Mapping)
        )
        arguments = data.get("arguments", {})
        if not isinstance(arguments, Mapping):
            raise TraceError("Trace arguments are malformed")
        permissions = data.get("permissions", ())
        evidence = data.get("evidence", ())
        approval_ids = data.get("approval_ids", ())
        effect_attestation_ids = data.get("effect_attestation_ids", ())
        credential_reference_ids = data.get("credential_reference_ids", ())
        if any(
            not isinstance(value, Sequence) or isinstance(value, str)
            for value in (
                permissions,
                evidence,
                approval_ids,
                effect_attestation_ids,
                credential_reference_ids,
            )
        ):
            raise TraceError("Trace list data is malformed")
        external_effect = data.get("external_effect", False)
        replay_safe = data.get("replay_safe", False)
        if type(external_effect) is not bool or type(replay_safe) is not bool:
            raise TraceError("Trace effect flags are malformed")
        return cls(
            trace_id=UUID(str(data["trace_id"])),
            event_id=UUID(str(data["event_id"])),
            event_type=TraceEventType(str(data["event_type"])),
            summary=str(data["summary"]),
            source=str(data.get("source", "application")),
            occurred_at=datetime.fromisoformat(str(data["occurred_at"])),
            duration_seconds=(
                float(cast(Any, data["duration_seconds"]))
                if data.get("duration_seconds") is not None
                else None
            ),
            task_id=optional_uuid("task_id"),
            plan_id=optional_uuid("plan_id"),
            step_id=optional_uuid("step_id"),
            turn_id=optional_uuid("turn_id"),
            request_id=optional_uuid("request_id"),
            effect_id=optional_uuid("effect_id"),
            correlation_id=optional_uuid("correlation_id"),
            causation_id=optional_uuid("causation_id"),
            goal_id=optional_uuid("goal_id"),
            session_id=optional_uuid("session_id"),
            integration_id=(
                str(data["integration_id"]) if data.get("integration_id") is not None else None
            ),
            package_version=(
                str(data["package_version"]) if data.get("package_version") is not None else None
            ),
            package_hash=(
                str(data["package_hash"]) if data.get("package_hash") is not None else None
            ),
            credential_reference_ids=tuple(
                UUID(str(item)) for item in cast(Sequence[object], credential_reference_ids)
            ),
            model=str(data["model"]) if data.get("model") is not None else None,
            usage=usage,
            arguments=cast(Mapping[str, object], arguments),
            permissions=tuple(str(item) for item in cast(Sequence[object], permissions)),
            result=data.get("result"),
            artifacts=artifacts,
            evidence=tuple(str(item) for item in cast(Sequence[object], evidence)),
            error=str(data["error"]) if data.get("error") is not None else None,
            effect_outcome=(
                EffectOutcome(str(data["effect_outcome"])) if data.get("effect_outcome") else None
            ),
            external_effect=external_effect,
            replay_safe=replay_safe,
            approval_ids=tuple(UUID(str(item)) for item in cast(Sequence[object], approval_ids)),
            effect_attestation_ids=tuple(
                UUID(str(item)) for item in cast(Sequence[object], effect_attestation_ids)
            ),
            classification=ArtifactClassification(str(data["classification"])),
        )


class ExecutionTrace:
    """Bounded trace projection for one execution lineage."""

    def __init__(self, trace_id: UUID | None = None, *, store: TraceStore | None = None) -> None:
        self.trace_id = trace_id or uuid4()
        self._events: list[TraceEvent] = []
        self._store = store

    @property
    def events(self) -> tuple[TraceEvent, ...]:
        return tuple(self._events)

    def append(self, event: TraceEvent) -> None:
        if event.trace_id != self.trace_id:
            raise TraceError("Trace event belongs to another trace")
        if any(item.event_id == event.event_id for item in self._events):
            raise TraceError("Duplicate trace event")
        self._events.append(event)
        if self._store is not None:
            self._store.append(event)

    def render_text(self) -> str:
        lines: list[str] = []
        for event in self._events:
            line = f"{event.occurred_at.isoformat()} {event.event_type.value}: {event.summary}"
            identifiers = [
                ("goal", event.goal_id),
                ("task", event.task_id),
                ("plan", event.plan_id),
                ("step", event.step_id),
                ("request", event.request_id),
                ("session", event.session_id),
            ]
            present = ", ".join(f"{name}={value}" for name, value in identifiers if value)
            if present:
                line += f" [{present}]"
            if event.effect_id:
                line += f" [effect={event.effect_id}]"
            if event.integration_id:
                line += f" integration={event.integration_id}"
            if event.package_version:
                line += f" package={event.package_version}"
            if event.model:
                line += f" model={event.model}"
            if event.usage:
                line += f" usage={event.usage.total_tokens} tokens cost={event.usage.cost:g}"
            if event.arguments:
                line += f" args={json.dumps(_json_value(event.arguments), sort_keys=True)}"
            if event.permissions:
                line += f" permissions={','.join(event.permissions)}"
            if event.approval_ids:
                line += " approvals=" + ",".join(str(item) for item in event.approval_ids)
            if event.effect_attestation_ids:
                line += " attestations=" + ",".join(
                    str(item) for item in event.effect_attestation_ids
                )
            if event.result is not None:
                line += f" result={json.dumps(_json_value(event.result), sort_keys=True)}"
            if event.artifacts:
                line += " artifacts=" + ",".join(
                    f"{item.artifact_id}:v{item.version}" for item in event.artifacts
                )
            if event.evidence:
                line += f" evidence={'; '.join(event.evidence)}"
            if event.error:
                line += f" error={event.error}"
            if event.effect_outcome:
                line += f" outcome={event.effect_outcome.value}"
            if event.duration_seconds is not None:
                line += f" duration={event.duration_seconds:g}s"
            if event.redaction_applied:
                line += " [redacted]"
            lines.append(line)
        return "\n".join(lines)


class EffectTraceSinkAdapter:
    """Adapt compensation trace callbacks into the general factual trace."""

    def __init__(self, trace: ExecutionTrace) -> None:
        self._trace = trace

    async def record(self, record: EffectTraceRecord) -> None:
        self._trace.append(
            TraceEvent(
                trace_id=self._trace.trace_id,
                event_type=TraceEventType.CAPABILITY_TOOL,
                source="compensation_executor",
                summary=f"Compensation {record.event.replace('.', ' ')}",
                occurred_at=record.recorded_at,
                request_id=record.request_id,
                effect_id=record.effect_id,
                result={"status": record.status},
            )
        )


class TraceStore:
    """Small durable projection store; task and audit stores remain authoritative."""

    _SCHEMA_VERSION = 2

    def __init__(self, path: Path) -> None:
        path.parent.mkdir(parents=True, exist_ok=True)
        self._connection = sqlite3.connect(path, timeout=5.0)
        self._connection.execute("PRAGMA journal_mode=WAL")
        self._connection.execute("PRAGMA busy_timeout=5000")
        self._connection.execute(
            "CREATE TABLE IF NOT EXISTS trace_schema_migrations (version INTEGER PRIMARY KEY)"
        )
        versions = {
            int(row[0])
            for row in self._connection.execute(
                "SELECT version FROM trace_schema_migrations"
            ).fetchall()
        }
        if any(version > self._SCHEMA_VERSION for version in versions):
            self.close()
            raise TraceError("Trace database uses a future schema")
        self._connection.execute(
            "CREATE TABLE IF NOT EXISTS execution_trace_events "
            "(sequence INTEGER PRIMARY KEY AUTOINCREMENT, event_id TEXT NOT NULL UNIQUE, "
            "trace_id TEXT NOT NULL, event_json TEXT NOT NULL)"
        )
        self._connection.execute(
            "CREATE TABLE IF NOT EXISTS trace_lineage "
            "(alias_id TEXT PRIMARY KEY, root_id TEXT NOT NULL)"
        )
        if not versions:
            self._connection.execute(
                "INSERT INTO trace_schema_migrations(version) VALUES (?)",
                (self._SCHEMA_VERSION,),
            )
        elif max(versions) < self._SCHEMA_VERSION:
            self._connection.execute(
                "INSERT INTO trace_schema_migrations(version) VALUES (?)",
                (self._SCHEMA_VERSION,),
            )
        self._connection.commit()

    def append(self, event: TraceEvent) -> None:
        payload = json.dumps(event.to_dict(), sort_keys=True, separators=(",", ":"))
        if len(payload.encode()) > _MAX_VALUE_BYTES:
            raise TraceError("Serialized trace event is too large")
        try:
            self._connection.execute(
                "INSERT INTO execution_trace_events(event_id, trace_id, event_json) "
                "VALUES (?, ?, ?)",
                (str(event.event_id), str(event.trace_id), payload),
            )
            self._connection.commit()
        except sqlite3.IntegrityError as error:
            raise TraceError("Duplicate trace event") from error

    def load(self, trace_id: UUID) -> ExecutionTrace:
        trace = ExecutionTrace(trace_id, store=self)
        rows = self._connection.execute(
            "SELECT event_json FROM execution_trace_events WHERE trace_id=? ORDER BY sequence",
            (str(trace_id),),
        ).fetchall()
        for (payload,) in rows:
            # Loading existing rows must not write them back as duplicates.
            trace._events.append(TraceEvent.from_dict(json.loads(str(payload))))
        return trace

    def contains_event_ids(self, event_ids: Sequence[str]) -> bool:
        """Return whether every supplied ID is an existing durable trace fact."""

        if (
            not event_ids
            or len(event_ids) > 32
            or any(
                type(item) is not str or not item.strip() or len(item) > 128 for item in event_ids
            )
        ):
            return False
        placeholders = ",".join("?" for _ in event_ids)
        row = self._connection.execute(
            f"SELECT COUNT(*) FROM execution_trace_events WHERE event_id IN ({placeholders})",
            tuple(event_ids),
        ).fetchone()
        return row is not None and int(row[0]) == len(set(event_ids))

    def bind_lineage(self, alias_id: UUID, root_id: UUID) -> None:
        if not isinstance(alias_id, UUID) or not isinstance(root_id, UUID):
            raise TraceError("Trace lineage identity is malformed")
        existing = self._connection.execute(
            "SELECT root_id FROM trace_lineage WHERE alias_id=?", (str(alias_id),)
        ).fetchone()
        if existing is not None and str(existing[0]) != str(root_id):
            raise TraceError("Trace lineage cannot be rebound to another root")
        self._connection.execute(
            "INSERT OR IGNORE INTO trace_lineage(alias_id, root_id) VALUES (?, ?)",
            (str(alias_id), str(root_id)),
        )
        self._connection.commit()

    def lineage_root(self, alias_id: UUID) -> UUID | None:
        if not isinstance(alias_id, UUID):
            raise TraceError("Trace lineage identity is malformed")
        row = self._connection.execute(
            "SELECT root_id FROM trace_lineage WHERE alias_id=?", (str(alias_id),)
        ).fetchone()
        if row is None:
            return None
        try:
            return UUID(str(row[0]))
        except ValueError as error:
            raise TraceError("Trace lineage metadata is malformed") from error

    def close(self) -> None:
        self._connection.close()


_TRACE_NAMESPACE = UUID("6c5e3f3f-4a58-4d46-9d4a-7f43ec1a9316")


class TraceService:
    """Runtime-owned factual trace projection fed by canonical events.

    This service is intentionally a projection: durable task, permission,
    capability, artifact, and verification owners remain authoritative.  The
    service only records bounded IDs/statuses from trusted application events,
    and stores a small durable goal/task lineage map so a restart continues the
    same human-readable trace.
    """

    def __init__(self, store: TraceStore, event_bus: EventBus) -> None:
        if type(store) is not TraceStore:
            raise TraceError("Trace service requires the runtime TraceStore")
        self._store = store
        self._event_bus = event_bus
        self._subscription_id: str | None = None
        self._traces: dict[UUID, ExecutionTrace] = {}

    async def start(self) -> None:
        if self._subscription_id is None:
            self._subscription_id = await self._event_bus.subscribe(self._on_event)

    async def close(self) -> None:
        if self._subscription_id is not None:
            await self._event_bus.unsubscribe(self._subscription_id)
            self._subscription_id = None
        self._traces.clear()

    def bind_goal_task(self, goal_id: UUID, task_id: UUID) -> None:
        if not isinstance(goal_id, UUID) or not isinstance(task_id, UUID):
            raise TraceError("Goal/task trace binding is malformed")
        self._store.bind_lineage(goal_id, goal_id)
        self._store.bind_lineage(task_id, goal_id)

    def trace_id_for(
        self,
        *,
        goal_id: UUID | None = None,
        task_id: UUID | None = None,
        correlation_id: UUID | None = None,
    ) -> UUID:
        lineage = goal_id or task_id or correlation_id
        if not isinstance(lineage, UUID):
            raise TraceError("A trace lineage identity is required")
        root = self._store.lineage_root(lineage) or lineage
        return uuid5(_TRACE_NAMESPACE, str(root))

    def get(
        self,
        *,
        goal_id: UUID | None = None,
        task_id: UUID | None = None,
        correlation_id: UUID | None = None,
    ) -> ExecutionTrace:
        trace_id = self.trace_id_for(
            goal_id=goal_id, task_id=task_id, correlation_id=correlation_id
        )
        trace = self._traces.get(trace_id)
        if trace is None:
            trace = self._store.load(trace_id)
            self._traces[trace_id] = trace
        return trace

    def record(
        self,
        event_type: TraceEventType,
        summary: str,
        *,
        goal_id: UUID | None = None,
        task_id: UUID | None = None,
        correlation_id: UUID | None = None,
        **fields: Any,
    ) -> TraceEvent:
        trace = self.get(goal_id=goal_id, task_id=task_id, correlation_id=correlation_id)
        event = TraceEvent(
            trace_id=trace.trace_id,
            event_type=event_type,
            summary=summary,
            source="runtime.trace",
            task_id=task_id,
            correlation_id=correlation_id or task_id or goal_id,
            goal_id=goal_id,
            **fields,
        )
        trace.append(event)
        return event

    async def _on_event(self, event: EventEnvelope[EventPayload]) -> None:
        trace_event = self._translate(event)
        if trace_event is None:
            return
        trace_id = self.trace_id_for(task_id=event.task_id, correlation_id=event.correlation_id)
        trace = self._traces.get(trace_id)
        if trace is None:
            trace = self._store.load(trace_id)
            self._traces[trace_id] = trace
        trace.append(trace_event)

    def _translate(self, event: EventEnvelope[EventPayload]) -> TraceEvent | None:
        payload = event.payload
        event_type = event.event_type
        common: dict[str, Any] = {
            "trace_id": self.trace_id_for(
                task_id=event.task_id, correlation_id=event.correlation_id
            ),
            "source": "runtime.event_projection",
            "occurred_at": event.timestamp,
            "task_id": event.task_id,
            "correlation_id": event.correlation_id,
            "causation_id": event.causation_id,
        }
        if event_type is EventType.TASK_CREATED and isinstance(payload, TaskCreated):
            return TraceEvent(event_type=TraceEventType.GOAL, summary="Goal accepted", **common)
        if event_type is EventType.GOAL_CREATED and isinstance(payload, GoalCreated):
            return TraceEvent(event_type=TraceEventType.GOAL, summary="Goal persisted", **common)
        if event_type is EventType.TASK_STATE_CHANGED and isinstance(payload, TaskStateChanged):
            terminal = payload.to_state.casefold() in {
                "completed",
                "failed",
                "cancelled",
                "budget_exhausted",
            }
            return TraceEvent(
                event_type=TraceEventType.COMPLETION if terminal else TraceEventType.RESULT,
                summary="Task state changed",
                result={"from": payload.from_state, "to": payload.to_state},
                **common,
            )
        if event_type is EventType.PLAN_CREATED and isinstance(payload, PlanCreated):
            return TraceEvent(
                event_type=TraceEventType.PLAN_REVISION,
                summary="Plan created",
                plan_id=payload.plan_id,
                result={"steps": payload.step_count},
                **common,
            )
        if event_type is EventType.PLAN_UPDATED and isinstance(payload, PlanUpdated):
            return TraceEvent(
                event_type=TraceEventType.PLAN_REVISION,
                summary="Plan revision persisted",
                plan_id=payload.plan_id,
                result={"revision": payload.revision},
                **common,
            )
        if event_type is EventType.STEP_STARTED and isinstance(payload, StepStarted):
            return TraceEvent(
                event_type=TraceEventType.STEP,
                summary="Step started",
                step_id=payload.step_id,
                arguments={"tool_id": payload.tool_id},
                **common,
            )
        if event_type is EventType.STEP_COMPLETED and isinstance(payload, StepCompleted):
            return TraceEvent(
                event_type=TraceEventType.RESULT,
                summary="Step completed",
                step_id=payload.step_id,
                result={"outcome": payload.outcome},
                **common,
            )
        if event_type is EventType.STEP_FAILED and isinstance(payload, StepFailed):
            return TraceEvent(
                event_type=TraceEventType.ERROR,
                summary="Step failed",
                step_id=payload.step_id,
                error=payload.error_code,
                **common,
            )
        if event_type is EventType.PERMISSION_REQUESTED and isinstance(
            payload, PermissionRequested
        ):
            return TraceEvent(
                event_type=TraceEventType.PERMISSION,
                summary="Permission requested",
                request_id=payload.request_id,
                permissions=(payload.permission,),
                result={"risk": payload.risk},
                **common,
            )
        if event_type is EventType.PERMISSION_GRANTED and isinstance(payload, PermissionGranted):
            return TraceEvent(
                event_type=TraceEventType.PERMISSION,
                summary="Permission granted",
                request_id=payload.request_id,
                approval_ids=(payload.request_id,),
                permissions=(payload.permission,),
                **common,
            )
        if event_type is EventType.PERMISSION_DENIED and isinstance(payload, PermissionDenied):
            return TraceEvent(
                event_type=TraceEventType.PERMISSION,
                summary="Permission denied",
                request_id=payload.request_id,
                error=payload.reason_code,
                **common,
            )
        if event_type is EventType.TOOL_STARTED and isinstance(payload, ToolStarted):
            return TraceEvent(
                event_type=TraceEventType.CAPABILITY_TOOL,
                summary="Tool started",
                arguments={"tool_id": payload.tool_id},
                **common,
            )
        if event_type is EventType.TOOL_COMPLETED and isinstance(payload, ToolCompleted):
            return TraceEvent(
                event_type=TraceEventType.RESULT,
                summary="Tool completed",
                result={"tool_id": payload.tool_id, "status": payload.status},
                **common,
            )
        if event_type is EventType.TOOL_FAILED and isinstance(payload, ToolFailed):
            return TraceEvent(
                event_type=TraceEventType.ERROR,
                summary="Tool failed",
                error=payload.error_code,
                arguments={"tool_id": payload.tool_id},
                **common,
            )
        if event_type is EventType.ARTIFACT_CREATED and isinstance(payload, ArtifactCreated):
            return TraceEvent(
                event_type=TraceEventType.ARTIFACT,
                summary="Artifact created",
                artifacts=(
                    ArtifactReference(
                        payload.artifact_id,
                        payload.version,
                        payload.workspace_id,
                        f"trace://artifact/{payload.artifact_id}",
                    ),
                ),
                result={"size": payload.size},
                **common,
            )
        if event_type is EventType.CREDENTIAL_CHANGED and isinstance(payload, CredentialChanged):
            return TraceEvent(
                event_type=TraceEventType.CREDENTIAL,
                summary="Credential metadata changed",
                credential_reference_ids=(payload.credential_id,),
                result={"status": payload.status, "operation": payload.operation},
                classification=ArtifactClassification.INTERNAL,
                **common,
            )
        if event_type is EventType.EFFECT_ATTESTATION_RECORDED and isinstance(
            payload, EffectAttestationRecorded
        ):
            return TraceEvent(
                event_type=TraceEventType.EFFECT_ATTESTATION,
                summary="Trusted effect observation recorded",
                effect_id=payload.observation_id or payload.attestation_id,
                effect_attestation_ids=(
                    (payload.attestation_id,) if payload.attestation_id is not None else ()
                ),
                integration_id=payload.integration_id,
                package_version=payload.integration_version,
                result={
                    "status": payload.status,
                    "allowed": payload.allowed,
                    "dispatched": payload.dispatched,
                },
                external_effect=bool(payload.dispatched),
                **common,
            )
        if event_type is EventType.HEALTH_CHANGED and isinstance(payload, HealthChanged):
            return TraceEvent(
                event_type=TraceEventType.HEALTH,
                summary="Capability health changed",
                result={"component": payload.component, "status": payload.status},
                **common,
            )
        if event_type is EventType.AUTOMATION_STATE_CHANGED and isinstance(
            payload, AutomationStateChanged
        ):
            return TraceEvent(
                event_type=TraceEventType.AUTOMATION,
                summary="Automation state changed",
                result={"automation_id": str(payload.automation_id), "state": payload.state},
                **common,
            )
        if event_type is EventType.CAPABILITY_CHANGED and isinstance(payload, CapabilityChanged):
            return TraceEvent(
                event_type=TraceEventType.CAPABILITY_TOOL,
                summary="Capability state changed",
                integration_id=payload.capability,
                result={"available": payload.available},
                **common,
            )
        if event_type is EventType.INTEGRATION_CHANGED and isinstance(payload, IntegrationChanged):
            return TraceEvent(
                event_type=TraceEventType.CAPABILITY_ACQUISITION,
                summary="Integration lifecycle changed",
                integration_id=payload.integration,
                result={"state": payload.state},
                **common,
            )
        if event_type is EventType.SYSTEM_ERROR and isinstance(payload, SystemError):
            return TraceEvent(
                event_type=TraceEventType.ERROR,
                summary="Runtime error",
                error=payload.code,
                result={"summary": payload.summary},
                **common,
            )
        return None


@dataclass(frozen=True, slots=True)
class ReplayRequest:
    trace_id: UUID
    mode: ReplayMode
    checkpoint_event_id: UUID | None = None
    reconciled_unknown_event_ids: frozenset[UUID] = frozenset()

    def __post_init__(self) -> None:
        if not isinstance(self.trace_id, UUID) or not isinstance(self.mode, ReplayMode):
            raise TraceError("Replay request identity or mode is malformed")
        if self.checkpoint_event_id is not None and not isinstance(self.checkpoint_event_id, UUID):
            raise TraceError("Replay checkpoint is malformed")
        if not isinstance(self.reconciled_unknown_event_ids, frozenset) or any(
            not isinstance(item, UUID) for item in self.reconciled_unknown_event_ids
        ):
            raise TraceError("Reconciled replay IDs are malformed")


@dataclass(frozen=True, slots=True)
class ReplayPlan:
    disposition: ReplayDisposition
    mode: ReplayMode
    reason: str
    event_ids: tuple[UUID, ...] = ()
    fresh_approval_required: bool = False
    inherited_approval_ids: tuple[UUID, ...] = ()
    unknown_effect_ids: tuple[UUID, ...] = ()
    external_effect_count: int = 0

    @property
    def has_side_effects(self) -> bool:
        return self.external_effect_count > 0


class TraceReplayService:
    """Prepare safe replay intentions without replaying tools or approvals."""

    def prepare(self, trace: ExecutionTrace, request: ReplayRequest) -> ReplayPlan:
        if request.trace_id != trace.trace_id:
            raise TraceError("Replay request belongs to another trace")
        events = trace.events
        if request.mode is ReplayMode.SIMULATION:
            return ReplayPlan(
                ReplayDisposition.ALLOWED,
                request.mode,
                "simulation records facts only and executes zero external effects",
                tuple(item.event_id for item in events),
                fresh_approval_required=False,
                external_effect_count=0,
            )
        if request.mode is ReplayMode.REPLAN_FROM_CHECKPOINT:
            if request.checkpoint_event_id is None:
                return self._refused(request.mode, "checkpoint is required for replan")
            checkpoint_index = next(
                (
                    index
                    for index, item in enumerate(events)
                    if item.event_id == request.checkpoint_event_id
                ),
                None,
            )
            if checkpoint_index is None:
                return self._refused(request.mode, "checkpoint is not in this trace")
            selected = events[: checkpoint_index + 1]
        else:
            selected = events
        unknown = tuple(
            item.event_id
            for item in selected
            if item.effect_outcome is EffectOutcome.UNKNOWN_OUTCOME
            and item.event_id not in request.reconciled_unknown_event_ids
        )
        if unknown:
            return ReplayPlan(
                ReplayDisposition.REFUSED,
                request.mode,
                "UNKNOWN_OUTCOME must be reconciled before replay",
                unknown_effect_ids=unknown,
            )
        if request.mode is ReplayMode.REPLAN_FROM_CHECKPOINT:
            return ReplayPlan(
                ReplayDisposition.ALLOWED,
                request.mode,
                "replan may use checkpoint facts but never replays an external effect",
                tuple(item.event_id for item in selected),
                fresh_approval_required=any(item.permissions for item in selected),
                external_effect_count=0,
            )
        unsafe = tuple(
            item.event_id for item in selected if item.external_effect and not item.replay_safe
        )
        if unsafe:
            return ReplayPlan(
                ReplayDisposition.REFUSED,
                request.mode,
                "external effects are not marked safe for re-execution",
                unknown_effect_ids=unsafe,
            )
        return ReplayPlan(
            ReplayDisposition.ALLOWED,
            request.mode,
            "only explicitly replay-safe facts may be re-executed",
            tuple(item.event_id for item in selected),
            fresh_approval_required=any(item.permissions or item.approval_ids for item in selected),
            inherited_approval_ids=(),
            external_effect_count=sum(item.external_effect for item in selected),
        )

    @staticmethod
    def _refused(mode: ReplayMode, reason: str) -> ReplayPlan:
        return ReplayPlan(ReplayDisposition.REFUSED, mode, reason)
