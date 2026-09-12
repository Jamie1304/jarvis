"""Privacy-safe installation-specific golden workflow regressions.

Golden workflows are durable regression definitions and run evidence.  They do
not execute tools, grant permission, own task state, or replace
``VerificationEngine``.  An injected trusted executor supplies observations;
the verifier decides whether a run passed.
"""

from __future__ import annotations

import hashlib
import inspect
import json
import re
import sqlite3
from collections.abc import Awaitable, Callable, Mapping, Sequence
from dataclasses import dataclass, field, replace
from datetime import UTC, datetime, timedelta
from enum import StrEnum
from pathlib import Path
from types import MappingProxyType
from typing import cast
from uuid import UUID, uuid4

from jarvis.trace import ExecutionTrace, TraceEventType
from jarvis.verification import (
    EvidenceRecord,
    EvidenceType,
    VerificationDisposition,
    VerificationEngine,
    VerificationLevel,
    VerificationPlan,
    VerificationResult,
)


class GoldenWorkflowError(ValueError):
    """A golden definition, candidate, or durable record is invalid."""


class GoldenGateError(RuntimeError):
    """Applicable golden workflows did not pass, so a change must stop."""


class GoldenWorkflowClass(StrEnum):
    DETERMINISTIC = "deterministic"
    SEMI_DETERMINISTIC = "semi_deterministic"
    INTEGRATION_REQUIRED = "integration_required"
    HARDWARE_REQUIRED = "hardware_required"


class GoldenChangeKind(StrEnum):
    MODEL_CHANGE = "model_change"
    INTEGRATION_UPDATE = "integration_update"
    SELF_IMPROVEMENT = "self_improvement"
    SELF_UPDATE = "self_update"


class GoldenCandidateKind(StrEnum):
    REPEATED_SUCCESSFUL_ROUTINE = "repeated_successful_routine"
    USER_MARKED_IMPORTANT_WORKFLOW = "user_marked_important_workflow"
    CRITICAL_GENERATED_CAPABILITY = "critical_generated_capability"
    FREQUENT_CAPABILITY_CHAIN = "frequent_capability_chain"


class GoldenWorkflowStatus(StrEnum):
    ACTIVE = "active"
    RETIRED = "retired"


class GoldenRunStatus(StrEnum):
    PASSED = "passed"
    FAILED = "failed"
    SKIPPED = "skipped"
    REJECTED = "rejected"
    CANCELLED = "cancelled"


class GoldenActor(StrEnum):
    TRUSTED_SYSTEM = "trusted_system"
    USER = "user"


class GoldenUnavailable(RuntimeError):
    """The required integration or hardware was unavailable for this run."""


type GoldenValue = object
type GoldenExecutor = Callable[
    ["GoldenWorkflow", "Fixture"],
    Sequence[EvidenceRecord] | Awaitable[Sequence[EvidenceRecord]],
]

_SCHEMA_VERSION = 1
_MAX_FIXTURES = 128
_MAX_RUNS = 10_000
_SHA256 = re.compile(r"[0-9a-f]{64}\Z")
_LABEL = re.compile(r"[a-z0-9][a-z0-9_.:-]{0,127}\Z")
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
        "authorization",
        "cookie",
        "credential",
    }
)
_PERSONAL_KEYS = frozenset(
    {"name", "user", "username", "user_name", "email", "account", "address", "phone"}
)


@dataclass(frozen=True, slots=True, order=True)
class Version:
    """Immutable regression-definition version."""

    major: int
    minor: int
    patch: int

    def __post_init__(self) -> None:
        if any(
            type(value) is not int or value < 0 or value > 1_000_000
            for value in (self.major, self.minor, self.patch)
        ):
            raise GoldenWorkflowError("Golden workflow version is malformed")

    def __str__(self) -> str:
        return f"{self.major}.{self.minor}.{self.patch}"

    @classmethod
    def parse(cls, value: str) -> Version:
        if not isinstance(value, str) or not re.fullmatch(r"\d+\.\d+\.\d+", value):
            raise GoldenWorkflowError("Golden workflow version is malformed")
        parts = tuple(int(item) for item in value.split("."))
        return cls(*parts)


@dataclass(frozen=True, slots=True)
class ExpectedResult:
    """Semantic verification criteria, never an expected output text snapshot."""

    goal: str
    criteria: tuple[str, ...]
    required_level: VerificationLevel = VerificationLevel.AUTOMATED_TESTED
    allowed_evidence_types: frozenset[EvidenceType] = frozenset({EvidenceType.CUSTOM})
    minimum_confidence: float = 0.9
    max_evidence_age: timedelta = timedelta(minutes=15)
    independent_observation_required: bool = True

    def __post_init__(self) -> None:
        _bounded(self.goal, "Expected result goal", 1_000)
        if not self.criteria or len(self.criteria) > 64:
            raise GoldenWorkflowError("Expected result needs bounded semantic criteria")
        if any(not _LABEL.fullmatch(item) for item in self.criteria):
            raise GoldenWorkflowError("Golden criteria must be safe semantic labels")
        if not isinstance(self.required_level, VerificationLevel):
            raise GoldenWorkflowError("Expected verification level is malformed")
        if self.required_level < VerificationLevel.AUTOMATED_TESTED:
            raise GoldenWorkflowError("Golden results require automated verification")
        if not self.allowed_evidence_types or any(
            not isinstance(item, EvidenceType) for item in self.allowed_evidence_types
        ):
            raise GoldenWorkflowError("Allowed golden evidence types are malformed")
        if not 0 <= self.minimum_confidence <= 1:
            raise GoldenWorkflowError("Golden confidence must be between zero and one")
        if self.max_evidence_age <= timedelta(0) or self.max_evidence_age > timedelta(days=30):
            raise GoldenWorkflowError("Golden evidence age is outside safe bounds")
        if type(self.independent_observation_required) is not bool:
            raise GoldenWorkflowError("Golden independence flag is malformed")

    def plan(self) -> VerificationPlan:
        return VerificationPlan(
            original_goal=self.goal,
            criteria=self.criteria,
            allowed_evidence_types=self.allowed_evidence_types,
            required_level=self.required_level,
            minimum_confidence=self.minimum_confidence,
            max_evidence_age=self.max_evidence_age,
            independent_observation_required=self.independent_observation_required,
            ask_user_when_unobservable=False,
        )


@dataclass(frozen=True, slots=True)
class Fixture:
    """Bounded, sanitized input fixture for one golden workflow."""

    fixture_id: str
    title: str
    inputs: Mapping[str, GoldenValue]
    expected: ExpectedResult
    synthetic: bool = True
    source_trace_digest: str | None = None
    sanitized: bool = field(init=False, default=True)

    def __post_init__(self) -> None:
        _label(self.fixture_id, "Fixture ID")
        _bounded(self.title, "Fixture title", 1_000)
        if not isinstance(self.inputs, Mapping) or len(self.inputs) > 64:
            raise GoldenWorkflowError("Fixture inputs must be a bounded mapping")
        normalized = _sanitize_mapping(self.inputs)
        object.__setattr__(self, "inputs", MappingProxyType(normalized))
        if not isinstance(self.expected, ExpectedResult):
            raise GoldenWorkflowError("Fixture expected result is malformed")
        if type(self.synthetic) is not bool:
            raise GoldenWorkflowError("Fixture synthetic flag is malformed")
        if self.source_trace_digest is not None and not _SHA256.fullmatch(self.source_trace_digest):
            raise GoldenWorkflowError("Fixture source trace must be a SHA-256 digest")


@dataclass(frozen=True, slots=True)
class GoldenWorkflow:
    """Versioned regression definition owned by the golden workflow store."""

    workflow_id: str
    name: str
    version: Version
    workflow_class: GoldenWorkflowClass
    fixtures: tuple[Fixture, ...]
    applicable_to: frozenset[GoldenChangeKind]
    provenance: tuple[str, ...] = ()
    status: GoldenWorkflowStatus = GoldenWorkflowStatus.ACTIVE

    def __post_init__(self) -> None:
        _label(self.workflow_id, "Golden workflow ID")
        _bounded(self.name, "Golden workflow name", 1_000)
        if not isinstance(self.version, Version) or not isinstance(
            self.workflow_class, GoldenWorkflowClass
        ):
            raise GoldenWorkflowError("Golden workflow identity is malformed")
        if not self.fixtures or len(self.fixtures) > _MAX_FIXTURES:
            raise GoldenWorkflowError("Golden workflow fixtures are required and bounded")
        if len({fixture.fixture_id for fixture in self.fixtures}) != len(self.fixtures):
            raise GoldenWorkflowError("Golden fixture IDs must be unique")
        if not self.applicable_to or any(
            not isinstance(item, GoldenChangeKind) for item in self.applicable_to
        ):
            raise GoldenWorkflowError("Golden workflow applicability is malformed")
        if any(not _label_value(item, 512) for item in self.provenance):
            raise GoldenWorkflowError("Golden workflow provenance is malformed")
        if not isinstance(self.status, GoldenWorkflowStatus):
            raise GoldenWorkflowError("Golden workflow status is malformed")

    @property
    def fingerprint(self) -> str:
        payload = json.dumps(self.to_dict(), sort_keys=True, separators=(",", ":"))
        return hashlib.sha256(payload.encode("utf-8")).hexdigest()

    def with_status(self, status: GoldenWorkflowStatus) -> GoldenWorkflow:
        return replace(self, status=status)

    @classmethod
    def from_trace(
        cls,
        trace: ExecutionTrace,
        *,
        workflow_id: str,
        name: str,
        version: Version | None = None,
        workflow_class: GoldenWorkflowClass = GoldenWorkflowClass.SEMI_DETERMINISTIC,
        applicable_to: frozenset[GoldenChangeKind] | None = None,
    ) -> GoldenWorkflow:
        """Derive only a generalized event-shape fixture from trusted trace facts."""

        events = trace.events
        if not events or not any(item.event_type is TraceEventType.COMPLETION for item in events):
            raise GoldenWorkflowError("Trace must contain a completion fact")
        if not any(item.event_type is TraceEventType.VERIFICATION for item in events):
            raise GoldenWorkflowError("Trace must contain a verification fact")
        if any(item.event_type is TraceEventType.ERROR for item in events):
            raise GoldenWorkflowError("Failed traces cannot become golden workflows")
        if any(
            item.effect_outcome is not None and item.effect_outcome.value == "unknown_outcome"
            for item in events
        ):
            raise GoldenWorkflowError("Unknown outcomes cannot become golden workflows")
        shape = tuple(item.event_type.value for item in events)
        shape_digest = _sha256_json({"event_shape": shape, "count": len(shape)})
        expected = ExpectedResult(
            goal=f"Verify sanitized workflow {workflow_id}",
            criteria=("completion_observed", "verification_observed"),
            allowed_evidence_types=frozenset({EvidenceType.CUSTOM}),
        )
        fixture = Fixture(
            fixture_id=f"{workflow_id}.fixture.1",
            title="Synthetic event-shape fixture",
            inputs={"event_shape": shape, "event_count": len(shape)},
            expected=expected,
            synthetic=True,
            source_trace_digest=shape_digest,
        )
        return cls(
            workflow_id=workflow_id,
            name=name,
            version=version or Version(1, 0, 0),
            workflow_class=workflow_class,
            fixtures=(fixture,),
            applicable_to=applicable_to or frozenset(GoldenChangeKind),
            provenance=(f"trace-shape:{shape_digest}",),
        )

    def to_dict(self) -> dict[str, object]:
        return {
            "workflow_id": self.workflow_id,
            "name": self.name,
            "version": str(self.version),
            "workflow_class": self.workflow_class.value,
            "fixtures": [_fixture_to_dict(item) for item in self.fixtures],
            "applicable_to": sorted(item.value for item in self.applicable_to),
            "provenance": list(self.provenance),
            "status": self.status.value,
        }

    @classmethod
    def from_dict(cls, data: Mapping[str, object]) -> GoldenWorkflow:
        if not isinstance(data, Mapping):
            raise GoldenWorkflowError("Golden workflow serialization is malformed")
        fixtures = data.get("fixtures")
        applicable = data.get("applicable_to")
        provenance = data.get("provenance", ())
        if not isinstance(fixtures, Sequence) or isinstance(fixtures, str):
            raise GoldenWorkflowError("Golden fixtures are malformed")
        if not isinstance(applicable, Sequence) or isinstance(applicable, str):
            raise GoldenWorkflowError("Golden applicability is malformed")
        if not isinstance(provenance, Sequence) or isinstance(provenance, str):
            raise GoldenWorkflowError("Golden provenance is malformed")
        try:
            return cls(
                workflow_id=str(data["workflow_id"]),
                name=str(data["name"]),
                version=Version.parse(str(data["version"])),
                workflow_class=GoldenWorkflowClass(str(data["workflow_class"])),
                fixtures=tuple(
                    _fixture_from_dict(item) for item in fixtures if isinstance(item, Mapping)
                ),
                applicable_to=frozenset(GoldenChangeKind(str(item)) for item in applicable),
                provenance=tuple(str(item) for item in provenance),
                status=GoldenWorkflowStatus(
                    str(data.get("status", GoldenWorkflowStatus.ACTIVE.value))
                ),
            )
        except (KeyError, TypeError, ValueError) as error:
            raise GoldenWorkflowError("Golden workflow serialization is malformed") from error


@dataclass(frozen=True, slots=True)
class GoldenWorkflowCandidate:
    """Proposed golden definition subject to trusted candidate gating."""

    candidate_id: str
    candidate_kind: GoldenCandidateKind
    workflow: GoldenWorkflow
    verified_successes: int
    source_trace_digests: tuple[str, ...] = ()
    base_workflow_fingerprint: str | None = None
    regenerated_expected: bool = False
    excluded_workflow_ids: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        _label(self.candidate_id, "Golden candidate ID")
        if not isinstance(self.candidate_kind, GoldenCandidateKind):
            raise GoldenWorkflowError("Golden candidate kind is malformed")
        if not isinstance(self.workflow, GoldenWorkflow):
            raise GoldenWorkflowError("Golden candidate workflow is malformed")
        if type(self.verified_successes) is not int or self.verified_successes <= 0:
            raise GoldenWorkflowError("Golden candidate success count is invalid")
        if (
            self.candidate_kind
            in {
                GoldenCandidateKind.REPEATED_SUCCESSFUL_ROUTINE,
                GoldenCandidateKind.FREQUENT_CAPABILITY_CHAIN,
            }
            and self.verified_successes < 2
        ):
            raise GoldenWorkflowError("Repeated golden candidates need repeated success")
        if any(not _SHA256.fullmatch(item) for item in self.source_trace_digests):
            raise GoldenWorkflowError("Golden candidate trace provenance is malformed")
        if self.base_workflow_fingerprint is not None and not _SHA256.fullmatch(
            self.base_workflow_fingerprint
        ):
            raise GoldenWorkflowError("Golden candidate base fingerprint is malformed")
        if type(self.regenerated_expected) is not bool:
            raise GoldenWorkflowError("Golden candidate expected-result flag is malformed")
        if self.regenerated_expected:
            raise GoldenWorkflowError("Expected results cannot be regenerated from a run")
        if self.excluded_workflow_ids:
            raise GoldenWorkflowError("Candidates cannot silently exclude golden workflows")


@dataclass(frozen=True, slots=True)
class RunResult:
    """Durable result of verifying one fixture through VerificationEngine."""

    run_id: UUID
    workflow_id: str
    version: Version
    fixture_id: str
    started_at: datetime
    finished_at: datetime
    status: GoldenRunStatus
    verification: VerificationResult | None
    trace_id: UUID | None = None
    error: str | None = None

    def __post_init__(self) -> None:
        if not isinstance(self.run_id, UUID):
            raise GoldenWorkflowError("Golden run ID is malformed")
        _label(self.workflow_id, "Golden run workflow ID")
        if not isinstance(self.version, Version) or not _LABEL.fullmatch(self.fixture_id):
            raise GoldenWorkflowError("Golden run identity is malformed")
        object.__setattr__(self, "started_at", _utc(self.started_at))
        object.__setattr__(self, "finished_at", _utc(self.finished_at))
        if self.finished_at < self.started_at:
            raise GoldenWorkflowError("Golden run finish precedes start")
        if not isinstance(self.status, GoldenRunStatus):
            raise GoldenWorkflowError("Golden run status is malformed")
        if self.trace_id is not None and not isinstance(self.trace_id, UUID):
            raise GoldenWorkflowError("Golden run trace ID is malformed")
        if self.error is not None:
            _bounded(self.error, "Golden run error", 1_000)
        if self.status is GoldenRunStatus.PASSED and (
            self.verification is None or not self.verification.passed
        ):
            raise GoldenWorkflowError("Passed golden runs require passed verification")

    def to_dict(self) -> dict[str, object]:
        return {
            "run_id": str(self.run_id),
            "workflow_id": self.workflow_id,
            "version": str(self.version),
            "fixture_id": self.fixture_id,
            "started_at": self.started_at.isoformat(),
            "finished_at": self.finished_at.isoformat(),
            "status": self.status.value,
            "verification": _verification_to_dict(self.verification)
            if self.verification is not None
            else None,
            "trace_id": str(self.trace_id) if self.trace_id else None,
            "error": self.error,
        }

    @classmethod
    def from_dict(cls, data: Mapping[str, object]) -> RunResult:
        verification = data.get("verification")
        return cls(
            run_id=UUID(str(data["run_id"])),
            workflow_id=str(data["workflow_id"]),
            version=Version.parse(str(data["version"])),
            fixture_id=str(data["fixture_id"]),
            started_at=datetime.fromisoformat(str(data["started_at"])),
            finished_at=datetime.fromisoformat(str(data["finished_at"])),
            status=GoldenRunStatus(str(data["status"])),
            verification=(
                _verification_from_dict(verification) if isinstance(verification, Mapping) else None
            ),
            trace_id=UUID(str(data["trace_id"])) if data.get("trace_id") else None,
            error=str(data["error"]) if data.get("error") is not None else None,
        )


@dataclass(frozen=True, slots=True)
class GoldenGateResult:
    change_kind: GoldenChangeKind
    workflow_ids: tuple[str, ...]
    runs: tuple[RunResult, ...]
    passed: bool
    reason: str

    def __post_init__(self) -> None:
        if not isinstance(self.change_kind, GoldenChangeKind):
            raise GoldenWorkflowError("Golden gate coverage is malformed")
        if any(not isinstance(item, RunResult) for item in self.runs):
            raise GoldenWorkflowError("Golden gate runs are malformed")
        if type(self.passed) is not bool:
            raise GoldenWorkflowError("Golden gate status is malformed")
        _bounded(self.reason, "Golden gate reason", 1_000)


class GoldenCandidateGate:
    """Trusted admission gate; candidate data cannot edit existing expectations."""

    def admit(
        self,
        candidate: GoldenWorkflowCandidate,
        store: GoldenWorkflowStore,
    ) -> GoldenWorkflow:
        if candidate.workflow.status is not GoldenWorkflowStatus.ACTIVE:
            raise GoldenGateError("Retired golden workflows cannot be admitted")
        try:
            current = store.inspect(candidate.workflow.workflow_id, candidate.workflow.version)
        except KeyError:
            current = None
        if current is not None:
            if candidate.base_workflow_fingerprint != current.fingerprint:
                raise GoldenGateError(
                    "Candidate base fingerprint does not match the golden workflow"
                )
            if candidate.workflow.fingerprint != current.fingerprint:
                raise GoldenGateError("Candidate cannot weaken or replace golden expectations")
            return current
        if candidate.base_workflow_fingerprint is not None:
            raise GoldenGateError("Candidate claims a base workflow that does not exist")
        store.register(candidate.workflow, actor=GoldenActor.TRUSTED_SYSTEM)
        return candidate.workflow


class GoldenWorkflowStore:
    """Sole durable owner for golden definitions and their run results."""

    def __init__(self, path: Path) -> None:
        path.parent.mkdir(parents=True, exist_ok=True)
        self._path = path
        self._connection = sqlite3.connect(path, timeout=5.0)
        self._connection.execute("PRAGMA journal_mode=WAL")
        self._connection.execute("PRAGMA busy_timeout=5000")
        self._connection.execute("PRAGMA foreign_keys=ON")
        self._connection.execute(
            "CREATE TABLE IF NOT EXISTS golden_schema_migrations (version INTEGER PRIMARY KEY)"
        )
        versions = {
            int(row[0])
            for row in self._connection.execute("SELECT version FROM golden_schema_migrations")
        }
        if any(version > _SCHEMA_VERSION for version in versions):
            self.close()
            raise GoldenWorkflowError("Golden workflow database uses a future schema")
        self._connection.execute(
            "CREATE TABLE IF NOT EXISTS golden_workflows ("
            "workflow_id TEXT NOT NULL, version TEXT NOT NULL, status TEXT NOT NULL, "
            "definition_json TEXT NOT NULL, fingerprint TEXT NOT NULL, updated_at TEXT NOT NULL, "
            "PRIMARY KEY(workflow_id, version))"
        )
        self._connection.execute(
            "CREATE TABLE IF NOT EXISTS golden_runs ("
            "run_id TEXT PRIMARY KEY, workflow_id TEXT NOT NULL, version TEXT NOT NULL, "
            "run_json TEXT NOT NULL, FOREIGN KEY(workflow_id, version) "
            "REFERENCES golden_workflows(workflow_id, version) ON DELETE CASCADE)"
        )
        if not versions:
            self._connection.execute(
                "INSERT INTO golden_schema_migrations(version) VALUES (?)", (_SCHEMA_VERSION,)
            )
        self._connection.commit()

    @property
    def database_path(self) -> Path:
        return self._path

    def register(
        self,
        workflow: GoldenWorkflow,
        *,
        actor: GoldenActor = GoldenActor.TRUSTED_SYSTEM,
    ) -> GoldenWorkflow:
        if actor is not GoldenActor.TRUSTED_SYSTEM:
            raise PermissionError("Only trusted application code may register golden workflows")
        existing = self._row(workflow.workflow_id, workflow.version)
        if existing is not None:
            current = self._decode_workflow(existing)
            if current.fingerprint != workflow.fingerprint:
                raise GoldenWorkflowError("Golden workflow fingerprint conflict")
            return current
        self._connection.execute(
            "INSERT INTO golden_workflows "
            "(workflow_id, version, status, definition_json, fingerprint, updated_at) "
            "VALUES (?, ?, ?, ?, ?, ?)",
            (
                workflow.workflow_id,
                str(workflow.version),
                workflow.status.value,
                json.dumps(workflow.to_dict(), sort_keys=True, separators=(",", ":")),
                workflow.fingerprint,
                datetime.now(UTC).isoformat(),
            ),
        )
        self._connection.commit()
        return workflow

    def inspect(self, workflow_id: str, version: Version | None = None) -> GoldenWorkflow:
        if version is not None:
            row = self._row(workflow_id, version)
            if row is None:
                raise KeyError("Unknown golden workflow")
            rows: list[Sequence[object]] = [row]
        else:
            rows = self._connection.execute(
                "SELECT workflow_id, version, status, definition_json, fingerprint, updated_at "
                "FROM golden_workflows WHERE workflow_id=?",
                (workflow_id,),
            ).fetchall()
        if not rows:
            raise KeyError("Unknown golden workflow")
        if version is None:
            rows.sort(key=lambda row: Version.parse(str(row[1])), reverse=True)
        return self._decode_workflow(rows[0])

    def list(self, *, include_retired: bool = False) -> tuple[GoldenWorkflow, ...]:
        query = (
            "SELECT workflow_id, version, status, definition_json, fingerprint, updated_at "
            "FROM golden_workflows"
        )
        if not include_retired:
            query += " WHERE status=?"
            rows = self._connection.execute(query, (GoldenWorkflowStatus.ACTIVE.value,)).fetchall()
        else:
            rows = self._connection.execute(query).fetchall()
        workflows = [self._decode_workflow(row) for row in rows]
        return tuple(sorted(workflows, key=lambda item: (item.workflow_id, item.version)))

    def active_for(self, change_kind: GoldenChangeKind) -> tuple[GoldenWorkflow, ...]:
        if not isinstance(change_kind, GoldenChangeKind):
            raise GoldenWorkflowError("Golden change kind is malformed")
        return tuple(workflow for workflow in self.list() if change_kind in workflow.applicable_to)

    def retire(
        self,
        workflow_id: str,
        version: Version,
        *,
        actor: GoldenActor,
    ) -> GoldenWorkflow:
        if actor is not GoldenActor.USER:
            raise PermissionError("Only the user may retire a golden workflow")
        current = self.inspect(workflow_id, version)
        retired = current.with_status(GoldenWorkflowStatus.RETIRED)
        self._replace(retired)
        return retired

    def delete(
        self,
        workflow_id: str,
        version: Version,
        *,
        actor: GoldenActor,
    ) -> None:
        if actor is not GoldenActor.USER:
            raise PermissionError("Only the user may delete a golden workflow")
        current = self.inspect(workflow_id, version)
        if current.status is not GoldenWorkflowStatus.RETIRED:
            raise GoldenWorkflowError("Retire a golden workflow before deleting it")
        self._connection.execute(
            "DELETE FROM golden_workflows WHERE workflow_id=? AND version=?",
            (workflow_id, str(version)),
        )
        self._connection.commit()

    def record_run(self, result: RunResult) -> None:
        workflow = self.inspect(result.workflow_id, result.version)
        if workflow.status is GoldenWorkflowStatus.RETIRED:
            raise GoldenWorkflowError("Retired golden workflows cannot receive runs")
        existing = self._connection.execute(
            "SELECT run_json FROM golden_runs WHERE run_id=?", (str(result.run_id),)
        ).fetchone()
        payload = json.dumps(result.to_dict(), sort_keys=True, separators=(",", ":"))
        if existing is not None:
            if str(existing[0]) != payload:
                raise GoldenWorkflowError("Golden run ID was reused with different evidence")
            return
        count = int(
            self._connection.execute(
                "SELECT COUNT(*) FROM golden_runs WHERE workflow_id=? AND version=?",
                (workflow.workflow_id, str(workflow.version)),
            ).fetchone()[0]
        )
        if count >= _MAX_RUNS:
            raise GoldenWorkflowError("Golden workflow run history is bounded")
        self._connection.execute(
            "INSERT INTO golden_runs(run_id, workflow_id, version, run_json) VALUES (?, ?, ?, ?)",
            (str(result.run_id), result.workflow_id, str(result.version), payload),
        )
        self._connection.commit()

    def runs(self, workflow_id: str, version: Version) -> tuple[RunResult, ...]:
        rows = self._connection.execute(
            "SELECT run_json FROM golden_runs WHERE workflow_id=? AND version=? ORDER BY rowid",
            (workflow_id, str(version)),
        ).fetchall()
        return tuple(RunResult.from_dict(json.loads(str(row[0]))) for row in rows)

    def close(self) -> None:
        self._connection.close()

    def _row(self, workflow_id: str, version: Version) -> tuple[object, ...] | None:
        return cast(
            tuple[object, ...] | None,
            self._connection.execute(
                "SELECT workflow_id, version, status, definition_json, fingerprint, updated_at "
                "FROM golden_workflows WHERE workflow_id=? AND version=?",
                (workflow_id, str(version)),
            ).fetchone(),
        )

    def _decode_workflow(self, row: Sequence[object]) -> GoldenWorkflow:
        workflow = GoldenWorkflow.from_dict(json.loads(str(row[3])))
        if (
            str(row[0]) != workflow.workflow_id
            or str(row[1]) != str(workflow.version)
            or str(row[2]) != workflow.status.value
            or str(row[4]) != workflow.fingerprint
        ):
            raise GoldenWorkflowError("Golden workflow durable fingerprint mismatch")
        return workflow

    def _replace(self, workflow: GoldenWorkflow) -> None:
        self._connection.execute(
            "UPDATE golden_workflows SET status=?, definition_json=?, fingerprint=?, updated_at=? "
            "WHERE workflow_id=? AND version=?",
            (
                workflow.status.value,
                json.dumps(workflow.to_dict(), sort_keys=True, separators=(",", ":")),
                workflow.fingerprint,
                datetime.now(UTC).isoformat(),
                workflow.workflow_id,
                str(workflow.version),
            ),
        )
        self._connection.commit()


class GoldenWorkflowService:
    """Run all applicable workflows and gate changes on verified outcomes."""

    def __init__(
        self,
        store: GoldenWorkflowStore,
        *,
        verifier: VerificationEngine | None = None,
        clock: Callable[[], datetime] | None = None,
        uuid_factory: Callable[[], UUID] | None = None,
    ) -> None:
        self._store = store
        self._verifier = verifier or VerificationEngine()
        self._clock = clock or (lambda: datetime.now(UTC))
        self._uuid_factory = uuid_factory or uuid4

    async def run(
        self,
        workflow: GoldenWorkflow,
        executor: GoldenExecutor,
        cancellation: object | None = None,
    ) -> tuple[RunResult, ...]:
        current = self._store.inspect(workflow.workflow_id, workflow.version)
        if current.fingerprint != workflow.fingerprint:
            raise GoldenWorkflowError("Golden workflow is stale or tampered")
        if current.status is GoldenWorkflowStatus.RETIRED:
            raise GoldenWorkflowError("Retired golden workflows cannot run")
        results: list[RunResult] = []
        for fixture in current.fixtures:
            started = self._now()
            if _cancelled(cancellation):
                result = self._result(
                    current,
                    fixture,
                    started,
                    GoldenRunStatus.CANCELLED,
                    None,
                    error="golden run cancelled",
                )
                self._store.record_run(result)
                results.append(result)
                break
            try:
                evidence = executor(current, fixture)
                if inspect.isawaitable(evidence):
                    evidence = await evidence
                if not isinstance(evidence, Sequence) or isinstance(evidence, str):
                    raise GoldenWorkflowError("Golden executor returned malformed evidence")
                verification = self._verifier.evaluate(
                    fixture.expected.plan(), tuple(evidence), now=self._now()
                )
                status = GoldenRunStatus.PASSED if verification.passed else GoldenRunStatus.FAILED
                result = self._result(current, fixture, started, status, verification)
            except GoldenUnavailable:
                result = self._result(
                    current,
                    fixture,
                    started,
                    GoldenRunStatus.SKIPPED,
                    None,
                    error="required integration or hardware unavailable",
                )
            except Exception:
                result = self._result(
                    current,
                    fixture,
                    started,
                    GoldenRunStatus.REJECTED,
                    None,
                    error="golden executor or evidence validation failed",
                )
            self._store.record_run(result)
            results.append(result)
        return tuple(results)

    async def run_applicable(
        self,
        change_kind: GoldenChangeKind,
        executor: GoldenExecutor,
        cancellation: object | None = None,
    ) -> GoldenGateResult:
        workflows = self._store.active_for(change_kind)
        if not workflows:
            return GoldenGateResult(
                change_kind,
                (),
                (),
                False,
                "no applicable golden workflows are registered",
            )
        runs: list[RunResult] = []
        for workflow in workflows:
            runs.extend(await self.run(workflow, executor, cancellation))
        passed = bool(runs) and all(item.status is GoldenRunStatus.PASSED for item in runs)
        return GoldenGateResult(
            change_kind,
            tuple(item.workflow_id for item in workflows),
            tuple(runs),
            passed,
            (
                "all applicable golden workflows passed"
                if passed
                else "an applicable golden workflow failed"
            ),
        )

    async def require_before(
        self,
        change_kind: GoldenChangeKind,
        executor: GoldenExecutor,
        cancellation: object | None = None,
    ) -> GoldenGateResult:
        result = await self.run_applicable(change_kind, executor, cancellation)
        if not result.passed:
            raise GoldenGateError(result.reason)
        return result

    def _now(self) -> datetime:
        value = self._clock()
        if value.tzinfo is None:
            raise GoldenWorkflowError("Golden clock must be timezone-aware")
        return value.astimezone(UTC)

    def _result(
        self,
        workflow: GoldenWorkflow,
        fixture: Fixture,
        started: datetime,
        status: GoldenRunStatus,
        verification: VerificationResult | None,
        *,
        error: str | None = None,
    ) -> RunResult:
        return RunResult(
            self._uuid_factory(),
            workflow.workflow_id,
            workflow.version,
            fixture.fixture_id,
            started,
            self._now(),
            status,
            verification,
            error=error,
        )


def sanitize_fixture_data(value: object) -> object:
    """Generalize real trace/user data before it can enter a fixture."""

    return _sanitize_value(value, key="value", depth=0)


def _sanitize_mapping(value: Mapping[str, object], *, depth: int = 0) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, item in value.items():
        if type(key) is not str or not key.strip() or len(key) > 128:
            raise GoldenWorkflowError("Fixture input key is malformed")
        result[key] = _sanitize_value(item, key=key.casefold(), depth=depth + 1)
    return result


def _sanitize_value(value: object, *, key: str, depth: int) -> object:
    if depth > 5:
        raise GoldenWorkflowError("Fixture input is too deeply nested")
    if key in _SECRET_KEYS or any(marker in key for marker in ("token", "secret", "password")):
        return "<redacted>"
    if key in _PERSONAL_KEYS or any(marker in key for marker in ("email", "username")):
        return "<generalized>"
    if value is None or type(value) is bool or type(value) is int:
        return value
    if type(value) is float:
        if value != value or value in {float("inf"), float("-inf")}:
            raise GoldenWorkflowError("Fixture input contains a non-finite number")
        return value
    if type(value) is str:
        if len(value) > 1_000 or "\x00" in value:
            raise GoldenWorkflowError("Fixture string is too large or malformed")
        if _looks_sensitive(value):
            return "<redacted>"
        if any(marker in key for marker in ("path", "file", "address", "account", "id")):
            return "<generalized>"
        return value
    if isinstance(value, Mapping):
        if len(value) > 64:
            raise GoldenWorkflowError("Fixture mapping is too large")
        return MappingProxyType(_sanitize_mapping(cast(Mapping[str, object], value), depth=depth))
    if isinstance(value, Sequence) and not isinstance(value, str | bytes | bytearray):
        if len(value) > 128:
            raise GoldenWorkflowError("Fixture sequence is too large")
        return tuple(_sanitize_value(item, key=key, depth=depth + 1) for item in value)
    raise GoldenWorkflowError("Fixture input contains unsupported data")


def _looks_sensitive(value: str) -> bool:
    lowered = value.casefold()
    return (
        "-----begin " in lowered
        or lowered.startswith(("gho_", "github_pat_", "sk-", "eyj"))
        or "@" in value
        and "." in value
        or bool(re.fullmatch(r"[0-9a-f]{32,}", lowered))
    )


def _fixture_to_dict(fixture: Fixture) -> dict[str, object]:
    return {
        "fixture_id": fixture.fixture_id,
        "title": fixture.title,
        "inputs": _json_value(fixture.inputs),
        "expected": {
            "goal": fixture.expected.goal,
            "criteria": list(fixture.expected.criteria),
            "required_level": fixture.expected.required_level.value,
            "allowed_evidence_types": sorted(
                item.value for item in fixture.expected.allowed_evidence_types
            ),
            "minimum_confidence": fixture.expected.minimum_confidence,
            "max_evidence_age_seconds": fixture.expected.max_evidence_age.total_seconds(),
            "independent_observation_required": fixture.expected.independent_observation_required,
        },
        "synthetic": fixture.synthetic,
        "source_trace_digest": fixture.source_trace_digest,
    }


def _fixture_from_dict(data: Mapping[str, object]) -> Fixture:
    expected = data.get("expected")
    inputs = data.get("inputs", {})
    if not isinstance(expected, Mapping) or not isinstance(inputs, Mapping):
        raise GoldenWorkflowError("Golden fixture serialization is malformed")
    criteria = expected.get("criteria")
    evidence_types = expected.get("allowed_evidence_types")
    if not isinstance(criteria, Sequence) or isinstance(criteria, str):
        raise GoldenWorkflowError("Golden criteria serialization is malformed")
    if not isinstance(evidence_types, Sequence) or isinstance(evidence_types, str):
        raise GoldenWorkflowError("Golden evidence serialization is malformed")
    return Fixture(
        fixture_id=str(data["fixture_id"]),
        title=str(data["title"]),
        inputs=cast(Mapping[str, object], inputs),
        expected=ExpectedResult(
            goal=str(expected["goal"]),
            criteria=tuple(str(item) for item in criteria),
            required_level=VerificationLevel(int(expected["required_level"])),
            allowed_evidence_types=frozenset(EvidenceType(str(item)) for item in evidence_types),
            minimum_confidence=float(expected["minimum_confidence"]),
            max_evidence_age=timedelta(seconds=float(expected["max_evidence_age_seconds"])),
            independent_observation_required=bool(expected["independent_observation_required"]),
        ),
        synthetic=bool(data.get("synthetic", True)),
        source_trace_digest=(
            str(data["source_trace_digest"])
            if data.get("source_trace_digest") is not None
            else None
        ),
    )


def _verification_to_dict(result: VerificationResult) -> dict[str, object]:
    def evidence(item: EvidenceRecord) -> dict[str, object]:
        return {
            "evidence_type": item.evidence_type.value,
            "source": item.source,
            "time": item.time.isoformat(),
            "freshness_seconds": item.freshness.total_seconds(),
            "confidence": item.confidence,
            "expected": _json_value(item.expected),
            "observed": _json_value(item.observed),
            "contradiction": item.contradiction,
            "level": item.level.value,
        }

    return {
        "original_goal": result.original_goal,
        "level": result.level.value,
        "passed": result.passed,
        "disposition": result.disposition.value,
        "evidence": [evidence(item) for item in result.evidence],
        "stale_evidence": [evidence(item) for item in result.stale_evidence],
        "contradictions": [evidence(item) for item in result.contradictions],
        "rejected_model_claims": list(result.rejected_model_claims),
        "missing_criteria": list(result.missing_criteria),
        "diagnosis": result.diagnosis,
        "needs_user_confirmation": result.needs_user_confirmation,
        "user_prompt": result.user_prompt,
    }


def _verification_from_dict(data: Mapping[str, object]) -> VerificationResult:
    def evidence(item: object) -> EvidenceRecord:
        if not isinstance(item, Mapping):
            raise GoldenWorkflowError("Golden evidence serialization is malformed")
        return EvidenceRecord(
            evidence_type=EvidenceType(str(item["evidence_type"])),
            source=str(item["source"]),
            time=datetime.fromisoformat(str(item["time"])),
            freshness=timedelta(seconds=float(item["freshness_seconds"])),
            confidence=float(item["confidence"]),
            expected=item.get("expected"),
            observed=item.get("observed"),
            contradiction=bool(item.get("contradiction", False)),
            level=VerificationLevel(int(str(item["level"]))),
        )

    def records(name: str) -> tuple[EvidenceRecord, ...]:
        values = data.get(name, ())
        if not isinstance(values, Sequence) or isinstance(values, str):
            raise GoldenWorkflowError("Golden verification evidence is malformed")
        return tuple(evidence(item) for item in values)

    return VerificationResult(
        original_goal=str(data["original_goal"]),
        level=VerificationLevel(int(str(data["level"]))),
        passed=bool(data["passed"]),
        disposition=VerificationDisposition(str(data["disposition"])),
        evidence=records("evidence"),
        stale_evidence=records("stale_evidence"),
        contradictions=records("contradictions"),
        rejected_model_claims=tuple(
            str(item) for item in cast(Sequence[object], data.get("rejected_model_claims", ()))
        ),
        missing_criteria=tuple(
            str(item) for item in cast(Sequence[object], data.get("missing_criteria", ()))
        ),
        diagnosis=str(data.get("diagnosis", "")),
        needs_user_confirmation=bool(data.get("needs_user_confirmation", False)),
        user_prompt=str(data["user_prompt"]) if data.get("user_prompt") is not None else None,
    )


def _json_value(value: object) -> object:
    if isinstance(value, Mapping):
        return {str(key): _json_value(item) for key, item in value.items()}
    if isinstance(value, tuple | list):
        return [_json_value(item) for item in value]
    return value


def _sha256_json(value: object) -> str:
    return hashlib.sha256(
        json.dumps(_json_value(value), sort_keys=True, separators=(",", ":")).encode("utf-8")
    ).hexdigest()


def _utc(value: datetime) -> datetime:
    if value.tzinfo is None:
        raise GoldenWorkflowError("Golden timestamp must be timezone-aware")
    return value.astimezone(UTC)


def _bounded(value: str, field_name: str, maximum: int) -> None:
    if type(value) is not str or not value.strip() or len(value) > maximum or "\x00" in value:
        raise GoldenWorkflowError(f"{field_name} is malformed")


def _label(value: str, field_name: str) -> None:
    if not isinstance(value, str) or not _LABEL.fullmatch(value):
        raise GoldenWorkflowError(f"{field_name} must be a safe label")


def _label_value(value: str, maximum: int) -> bool:
    return (
        type(value) is str and bool(value.strip()) and len(value) <= maximum and "\x00" not in value
    )


def _cancelled(value: object | None) -> bool:
    return bool(value is not None and getattr(value, "is_set", lambda: False)())


__all__ = [
    "ExpectedResult",
    "Fixture",
    "GoldenActor",
    "GoldenCandidateKind",
    "GoldenCandidateGate",
    "GoldenChangeKind",
    "GoldenGateError",
    "GoldenGateResult",
    "GoldenRunStatus",
    "GoldenUnavailable",
    "GoldenWorkflow",
    "GoldenWorkflowCandidate",
    "GoldenWorkflowClass",
    "GoldenWorkflowError",
    "GoldenWorkflowStatus",
    "GoldenWorkflowService",
    "GoldenWorkflowStore",
    "RunResult",
    "Version",
    "sanitize_fixture_data",
]
