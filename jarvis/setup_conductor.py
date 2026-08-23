"""Native, provider-neutral setup orchestration with adoption-first semantics."""

from __future__ import annotations

import asyncio
import hashlib
import json
import sqlite3
from collections.abc import Awaitable, Callable, Iterable, Mapping, Sequence
from dataclasses import dataclass, field
from datetime import UTC, datetime
from enum import StrEnum
from pathlib import Path
from typing import Protocol
from uuid import UUID, uuid4

from jarvis.provisioning import ProvisioningPlan, ProvisioningPlanState, ProvisioningResult


class SetupError(RuntimeError):
    """Setup could not safely continue."""


class SetupValidationError(SetupError, ValueError):
    """Setup input is malformed or contains secret material."""


class AdoptionChoice(StrEnum):
    USE_IN_PLACE = "use_in_place"
    IMPORT_COPY = "import_copy"
    IGNORE = "ignore"
    RECONFIGURE = "reconfigure"
    INSTALL_NEW = "install_new"


class SetupStepState(StrEnum):
    PENDING = "pending"
    ADOPTED = "adopted"
    READY = "ready"
    APPLYING = "applying"
    VERIFIED = "verified"
    DECLINED = "declined"
    FAILED = "failed"


class SetupRunState(StrEnum):
    PENDING = "pending"
    INSPECTING = "inspecting"
    WAITING_DECISIONS = "waiting_decisions"
    APPLYING = "applying"
    VERIFYING = "verifying"
    COMPLETED = "completed"
    FAILED = "failed"
    RECOVERING = "recovering"


_MAX_TEXT = 512
_MAX_JSON_BYTES = 65_536
_SECRET_KEYS = frozenset({"secret", "password", "token", "private_key", "credential_value"})


def _text(value: object, field_name: str, limit: int = _MAX_TEXT) -> str:
    if (
        type(value) is not str
        or not value.strip()
        or len(value) > limit
        or any(ord(character) < 32 for character in value)
    ):
        raise SetupValidationError(f"{field_name} is malformed")
    return value


def _id(value: object, field_name: str) -> str:
    value = _text(value, field_name, 128)
    if any(character not in "abcdefghijklmnopqrstuvwxyz0123456789._-" for character in value):
        raise SetupValidationError(f"{field_name} is malformed")
    return value


def _json_value(value: object, *, depth: int = 0) -> object:
    if depth > 12:
        raise SetupValidationError("Setup data is too deeply nested")
    if value is None or type(value) is bool or type(value) is int or type(value) is str:
        if type(value) is str and len(value) > _MAX_JSON_BYTES:
            raise SetupValidationError("Setup data is too large")
        return value
    if type(value) is float:
        if value != value or value in {float("inf"), float("-inf")}:
            raise SetupValidationError("Setup data contains an invalid number")
        return value
    if isinstance(value, Sequence) and not isinstance(value, str | bytes | bytearray):
        if len(value) > 256:
            raise SetupValidationError("Setup list is too large")
        return [_json_value(item, depth=depth + 1) for item in value]
    if isinstance(value, Mapping):
        if len(value) > 256:
            raise SetupValidationError("Setup object is too large")
        result: dict[str, object] = {}
        for key, item in value.items():
            key_text = _id(key, "Setup field name")
            if key_text.casefold() in _SECRET_KEYS:
                raise SetupValidationError("Raw credential material cannot be stored in setup")
            result[key_text] = _json_value(item, depth=depth + 1)
        return result
    raise SetupValidationError("Setup data must be JSON")


def _fingerprint(value: object) -> str:
    encoded = json.dumps(_json_value(value), sort_keys=True, separators=(",", ":"))
    if len(encoded.encode()) > _MAX_JSON_BYTES:
        raise SetupValidationError("Setup fingerprint input is too large")
    return hashlib.sha256(encoded.encode()).hexdigest()


@dataclass(frozen=True, slots=True)
class SetupContext:
    configuration: Mapping[str, object] = field(default_factory=dict)
    user_choices: Mapping[str, object] = field(default_factory=dict)
    credential_refs: tuple[str, ...] = ()
    workspace: str | None = None

    def __post_init__(self) -> None:
        _json_value(self.configuration)
        _json_value(self.user_choices)
        if self.workspace is not None:
            _text(self.workspace, "Setup workspace")
        if type(self.credential_refs) is not tuple or any(
            not _text(reference, "Credential reference", 256) for reference in self.credential_refs
        ):
            raise SetupValidationError("Credential references are malformed")

    @property
    def fingerprint(self) -> str:
        return _fingerprint(
            {
                "configuration": self.configuration,
                "user_choices": self.user_choices,
                "credential_refs": self.credential_refs,
                "workspace": self.workspace,
            }
        )


@dataclass(frozen=True, slots=True)
class SetupRequirement:
    requirement_id: str
    prompt: str
    choices: tuple[AdoptionChoice, ...] = ()
    required: bool = True

    def __post_init__(self) -> None:
        _id(self.requirement_id, "Setup requirement ID")
        _text(self.prompt, "Setup requirement prompt")
        if type(self.choices) is not tuple or any(
            not isinstance(choice, AdoptionChoice) for choice in self.choices
        ):
            raise SetupValidationError("Setup choices are malformed")
        if type(self.required) is not bool:
            raise SetupValidationError("Setup requirement flag is malformed")


@dataclass(frozen=True, slots=True)
class SetupDecision:
    requirement_id: str
    choice: AdoptionChoice
    values: Mapping[str, object] = field(default_factory=dict)

    def __post_init__(self) -> None:
        _id(self.requirement_id, "Setup decision requirement ID")
        if not isinstance(self.choice, AdoptionChoice):
            raise SetupValidationError("Setup decision choice is malformed")
        _json_value(self.values)


@dataclass(frozen=True, slots=True)
class AdoptionCandidate:
    candidate_id: str
    component_id: str
    location: str
    version: str | None = None
    compatible: bool = True
    has_configuration: bool = False
    has_user_data: bool = False
    evidence: str = ""

    def __post_init__(self) -> None:
        _id(self.candidate_id, "Adoption candidate ID")
        _id(self.component_id, "Adoption component ID")
        _text(self.location, "Adoption candidate location", 2_048)
        if self.version is not None:
            _text(self.version, "Adoption candidate version")
        if (
            type(self.compatible) is not bool
            or type(self.has_configuration) is not bool
            or type(self.has_user_data) is not bool
        ):
            raise SetupValidationError("Adoption candidate flags are malformed")
        if self.evidence:
            _text(self.evidence, "Adoption evidence", 2_048)


@dataclass(frozen=True, slots=True)
class SetupInspection:
    completed: bool = False
    candidates: tuple[AdoptionCandidate, ...] = ()
    partial: bool = False
    detail: str = ""

    def __post_init__(self) -> None:
        if type(self.completed) is not bool or type(self.partial) is not bool:
            raise SetupValidationError("Setup inspection flags are malformed")
        if type(self.candidates) is not tuple or any(
            type(candidate) is not AdoptionCandidate for candidate in self.candidates
        ):
            raise SetupValidationError("Setup candidates are malformed")
        if self.detail:
            _text(self.detail, "Setup inspection detail", 2_048)


@dataclass(frozen=True, slots=True)
class SetupStep:
    step_id: str
    component_id: str
    requirements: tuple[SetupRequirement, ...] = ()
    depends_on: tuple[str, ...] = ()
    destructive: bool = False

    def __post_init__(self) -> None:
        _id(self.step_id, "Setup step ID")
        _id(self.component_id, "Setup component ID")
        if type(self.requirements) is not tuple or any(
            type(requirement) is not SetupRequirement for requirement in self.requirements
        ):
            raise SetupValidationError("Setup requirements are malformed")
        if type(self.depends_on) is not tuple or any(
            not _id(dependency, "Setup dependency") for dependency in self.depends_on
        ):
            raise SetupValidationError("Setup dependencies are malformed")
        if type(self.destructive) is not bool:
            raise SetupValidationError("Setup destructive flag is malformed")


@dataclass(frozen=True, slots=True)
class SetupStepResult:
    step_id: str
    state: SetupStepState
    detail: str = ""
    candidate_id: str | None = None
    provisioning: ProvisioningResult | None = None


@dataclass(frozen=True, slots=True)
class SetupRun:
    run_id: UUID
    setup_kind: str
    context_fingerprint: str | None
    state: SetupRunState
    steps: tuple[SetupStepResult, ...] = ()
    decisions: tuple[SetupDecision, ...] = ()
    updated_at: datetime = field(default_factory=lambda: datetime.now(UTC))
    error: str | None = None

    def __post_init__(self) -> None:
        if not isinstance(self.run_id, UUID):
            raise SetupValidationError("Setup run ID is malformed")
        _id(self.setup_kind, "Setup kind")
        if self.context_fingerprint is not None:
            _text(self.context_fingerprint, "Setup context fingerprint", 128)
        if not isinstance(self.state, SetupRunState) or self.updated_at.tzinfo is None:
            raise SetupValidationError("Setup run metadata is malformed")
        if type(self.steps) is not tuple or type(self.decisions) is not tuple:
            raise SetupValidationError("Setup run collections are malformed")
        if self.error:
            _text(self.error, "Setup run error", 2_048)


class SetupStore(Protocol):
    def load(self, run_id: UUID) -> SetupRun | None: ...

    def save(self, run: SetupRun) -> None: ...


class InMemorySetupStore:
    def __init__(self) -> None:
        self._runs: dict[UUID, SetupRun] = {}

    def load(self, run_id: UUID) -> SetupRun | None:
        return self._runs.get(run_id)

    def save(self, run: SetupRun) -> None:
        self._runs[run.run_id] = run


class SQLiteSetupStore:
    """Versioned setup-run persistence; setup state is not task or permission truth."""

    _VERSION = 1

    def __init__(self, database_path: str | Path) -> None:
        self._path = str(database_path)
        if self._path != ":memory:":
            Path(self._path).parent.mkdir(parents=True, exist_ok=True)
        self._connection = sqlite3.connect(self._path, check_same_thread=False)
        self._connection.execute("PRAGMA foreign_keys = ON")
        self._connection.execute("PRAGMA busy_timeout = 5000")
        self._connection.execute("PRAGMA journal_mode = WAL")
        self._migrate()

    def _migrate(self) -> None:
        with self._connection:
            self._connection.execute(
                "CREATE TABLE IF NOT EXISTS setup_schema (version INTEGER NOT NULL)"
            )
            row = self._connection.execute("SELECT MAX(version) FROM setup_schema").fetchone()
            current = int(row[0] or 0)
            if current > self._VERSION:
                raise SetupError("Setup database uses a future schema")
            if current < 1:
                self._connection.execute(
                    """CREATE TABLE setup_runs (
                    run_id TEXT PRIMARY KEY, setup_kind TEXT NOT NULL,
                    context_fingerprint TEXT, state TEXT NOT NULL,
                    payload_json TEXT NOT NULL, updated_at TEXT NOT NULL
                    )"""
                )
                self._connection.execute("INSERT INTO setup_schema(version) VALUES (1)")

    def load(self, run_id: UUID) -> SetupRun | None:
        row = self._connection.execute(
            "SELECT payload_json FROM setup_runs WHERE run_id = ?", (str(run_id),)
        ).fetchone()
        return _run_from_json(json.loads(row[0])) if row else None

    def save(self, run: SetupRun) -> None:
        payload = _run_to_json(run)
        with self._connection:
            self._connection.execute(
                """INSERT INTO setup_runs
                (run_id, setup_kind, context_fingerprint, state, payload_json, updated_at)
                VALUES (?, ?, ?, ?, ?, ?)
                ON CONFLICT(run_id) DO UPDATE SET state=excluded.state,
                context_fingerprint=excluded.context_fingerprint,
                payload_json=excluded.payload_json, updated_at=excluded.updated_at""",
                (
                    str(run.run_id),
                    run.setup_kind,
                    run.context_fingerprint,
                    run.state.value,
                    json.dumps(payload, sort_keys=True),
                    run.updated_at.isoformat(),
                ),
            )

    def close(self) -> None:
        self._connection.close()


def _decision_to_json(decision: SetupDecision) -> dict[str, object]:
    return {
        "requirement_id": decision.requirement_id,
        "choice": decision.choice.value,
        "values": _json_value(decision.values),
    }


def _run_to_json(run: SetupRun) -> dict[str, object]:
    return {
        "run_id": str(run.run_id),
        "setup_kind": run.setup_kind,
        "context_fingerprint": run.context_fingerprint,
        "state": run.state.value,
        "steps": [
            {
                "step_id": item.step_id,
                "state": item.state.value,
                "detail": item.detail,
                "candidate_id": item.candidate_id,
            }
            for item in run.steps
        ],
        "decisions": [_decision_to_json(item) for item in run.decisions],
        "updated_at": run.updated_at.isoformat(),
        "error": run.error,
    }


def _run_from_json(payload: Mapping[str, object]) -> SetupRun:
    data = _json_value(payload)
    if not isinstance(data, dict):
        raise SetupError("Persisted setup state is malformed")
    steps_raw = data.get("steps", [])
    decisions_raw = data.get("decisions", [])
    if not isinstance(steps_raw, list) or not isinstance(decisions_raw, list):
        raise SetupError("Persisted setup collections are malformed")
    steps = tuple(
        SetupStepResult(
            str(item["step_id"]),
            SetupStepState(str(item["state"])),
            str(item.get("detail", "")),
            str(item["candidate_id"]) if item.get("candidate_id") else None,
        )
        for item in steps_raw
        if isinstance(item, dict)
    )
    decisions = tuple(
        SetupDecision(
            str(item["requirement_id"]),
            AdoptionChoice(str(item["choice"])),
            item.get("values", {}),
        )
        for item in decisions_raw
        if isinstance(item, dict)
    )
    return SetupRun(
        UUID(str(data["run_id"])),
        str(data["setup_kind"]),
        str(data["context_fingerprint"]) if data.get("context_fingerprint") else None,
        SetupRunState(str(data["state"])),
        steps,
        decisions,
        datetime.fromisoformat(str(data["updated_at"])),
        str(data["error"]) if data.get("error") else None,
    )


class SetupHandler(Protocol):
    async def inspect(self, step: SetupStep, context: SetupContext) -> SetupInspection: ...

    async def prepare(
        self, step: SetupStep, context: SetupContext, decision: SetupDecision | None
    ) -> ProvisioningPlan | None: ...

    async def configure(self, step: SetupStep, context: SetupContext) -> None: ...

    async def verify(self, step: SetupStep, context: SetupContext) -> bool: ...

    async def first_start(self, step: SetupStep, context: SetupContext) -> bool: ...


DecisionCollector = Callable[
    [tuple[SetupRequirement, ...], tuple[AdoptionCandidate, ...]],
    Awaitable[tuple[SetupDecision, ...]],
]


class SetupConductor:
    """Coordinate one normalized setup interview and adoption-first execution."""

    def __init__(
        self,
        handlers: Mapping[str, SetupHandler],
        store: SetupStore,
        provision: Callable[[ProvisioningPlan], Awaitable[ProvisioningResult]],
        *,
        decision_collector: DecisionCollector | None = None,
        clock: Callable[[], datetime] | None = None,
    ) -> None:
        if not handlers:
            raise SetupValidationError("At least one setup handler is required")
        self._handlers = dict(handlers)
        self._store = store
        self._provision = provision
        self._collect = decision_collector
        self._clock = clock or (lambda: datetime.now(UTC))

    async def run(
        self,
        setup_kind: str,
        steps: tuple[SetupStep, ...],
        context: SetupContext,
        *,
        run_id: UUID | None = None,
        cancellation: asyncio.Event | None = None,
    ) -> SetupRun:
        _id(setup_kind, "Setup kind")
        self._validate_steps(steps)
        run_id = run_id or uuid4()
        persisted = self._store.load(run_id)
        if persisted is not None and persisted.context_fingerprint not in {
            None,
            context.fingerprint,
        }:
            raise SetupError("Setup context changed; a new setup run is required")
        previous = {item.step_id: item for item in persisted.steps} if persisted else {}
        decisions = {
            item.requirement_id: item for item in (persisted.decisions if persisted else ())
        }
        self._save(
            run_id,
            setup_kind,
            context,
            SetupRunState.INSPECTING,
            tuple(previous.values()),
            decisions.values(),
        )
        cancel = cancellation or asyncio.Event()
        inspections: dict[str, SetupInspection] = {}
        all_requirements: list[SetupRequirement] = []
        all_candidates: list[AdoptionCandidate] = []
        for step in steps:
            if cancel.is_set():
                return self._save(
                    run_id,
                    setup_kind,
                    context,
                    SetupRunState.RECOVERING,
                    tuple(previous.values()),
                    decisions.values(),
                    "cancelled",
                )
            inspection = await self._handlers[step.component_id].inspect(step, context)
            inspections[step.step_id] = inspection
            all_requirements.extend(step.requirements)
            all_candidates.extend(inspection.candidates)
        missing = tuple(
            requirement
            for requirement in all_requirements
            if requirement.requirement_id not in decisions
        )
        if missing:
            if self._collect is None:
                return self._save(
                    run_id,
                    setup_kind,
                    context,
                    SetupRunState.WAITING_DECISIONS,
                    tuple(previous.values()),
                    decisions.values(),
                )
            collected = await self._collect(missing, tuple(all_candidates))
            for collected_decision in collected:
                if collected_decision.requirement_id not in {
                    item.requirement_id for item in all_requirements
                }:
                    raise SetupValidationError("Decision references an unknown requirement")
                decisions[collected_decision.requirement_id] = collected_decision
            if any(item.required and item.requirement_id not in decisions for item in missing):
                return self._save(
                    run_id,
                    setup_kind,
                    context,
                    SetupRunState.WAITING_DECISIONS,
                    tuple(previous.values()),
                    decisions.values(),
                )
        results: dict[str, SetupStepResult] = dict(previous)
        for step in steps:
            prior = results.get(step.step_id)
            if prior is not None and prior.state is SetupStepState.VERIFIED:
                if await self._handlers[step.component_id].verify(step, context):
                    continue
                results.pop(step.step_id, None)
            if any(
                results.get(dependency, SetupStepResult(dependency, SetupStepState.PENDING)).state
                is not SetupStepState.VERIFIED
                for dependency in step.depends_on
            ):
                return self._save(
                    run_id,
                    setup_kind,
                    context,
                    SetupRunState.FAILED,
                    tuple(results.values()),
                    decisions.values(),
                    "dependency is not verified",
                )
            inspection = inspections[step.step_id]
            decision = self._decision_for(step, inspection, decisions)
            if decision is not None and decision.choice is AdoptionChoice.IGNORE:
                results[step.step_id] = SetupStepResult(
                    step.step_id, SetupStepState.DECLINED, "adoption declined"
                )
                continue
            if inspection.completed or (
                decision is not None and decision.choice is AdoptionChoice.USE_IN_PLACE
            ):
                if await self._handlers[step.component_id].verify(step, context):
                    results[step.step_id] = SetupStepResult(
                        step.step_id,
                        SetupStepState.ADOPTED,
                        "existing installation adopted",
                        str(decision.values["candidate_id"])
                        if decision is not None and "candidate_id" in decision.values
                        else None,
                    )
                    continue
            results[step.step_id] = SetupStepResult(
                step.step_id, SetupStepState.APPLYING, "provisioning"
            )
            self._save(
                run_id,
                setup_kind,
                context,
                SetupRunState.APPLYING,
                tuple(results.values()),
                decisions.values(),
            )
            plan = await self._handlers[step.component_id].prepare(step, context, decision)
            if plan is not None:
                provisioned = await self._provision(plan)
                if provisioned.state is not ProvisioningPlanState.VERIFIED:
                    return self._save(
                        run_id,
                        setup_kind,
                        context,
                        SetupRunState.FAILED,
                        tuple(results.values()),
                        decisions.values(),
                        "provisioning failed",
                    )
            await self._handlers[step.component_id].configure(step, context)
            if not await self._handlers[step.component_id].verify(step, context):
                return self._save(
                    run_id,
                    setup_kind,
                    context,
                    SetupRunState.FAILED,
                    tuple(results.values()),
                    decisions.values(),
                    "verification failed",
                )
            if not await self._handlers[step.component_id].first_start(step, context):
                return self._save(
                    run_id,
                    setup_kind,
                    context,
                    SetupRunState.FAILED,
                    tuple(results.values()),
                    decisions.values(),
                    "first-start test failed",
                )
            results[step.step_id] = SetupStepResult(
                step.step_id, SetupStepState.VERIFIED, "setup verified"
            )
            self._save(
                run_id,
                setup_kind,
                context,
                SetupRunState.VERIFYING,
                tuple(results.values()),
                decisions.values(),
            )
        return self._save(
            run_id,
            setup_kind,
            context,
            SetupRunState.COMPLETED,
            tuple(results.values()),
            decisions.values(),
        )

    @staticmethod
    def _decision_for(
        step: SetupStep, inspection: SetupInspection, decisions: Mapping[str, SetupDecision]
    ) -> SetupDecision | None:
        candidate = next((item for item in inspection.candidates if item.compatible), None)
        for requirement in step.requirements:
            decision = decisions.get(requirement.requirement_id)
            if decision is not None:
                if decision.choice is AdoptionChoice.USE_IN_PLACE and candidate is None:
                    raise SetupError("No compatible adoption candidate exists")
                return decision
        return None

    @staticmethod
    def _validate_steps(steps: tuple[SetupStep, ...]) -> None:
        if type(steps) is not tuple or not steps:
            raise SetupValidationError("Setup steps are malformed")
        ids = {step.step_id for step in steps}
        if len(ids) != len(steps) or any(
            dependency not in ids for step in steps for dependency in step.depends_on
        ):
            raise SetupValidationError("Setup step dependencies are malformed")

    def _save(
        self,
        run_id: UUID,
        setup_kind: str,
        context: SetupContext,
        state: SetupRunState,
        steps: tuple[SetupStepResult, ...],
        decisions: Iterable[SetupDecision],
        error: str | None = None,
    ) -> SetupRun:
        run = SetupRun(
            run_id,
            setup_kind,
            context.fingerprint,
            state,
            steps,
            tuple(decisions),
            self._clock(),
            error,
        )
        self._store.save(run)
        return run


__all__ = [
    "AdoptionCandidate",
    "AdoptionChoice",
    "InMemorySetupStore",
    "SQLiteSetupStore",
    "SetupConductor",
    "SetupContext",
    "SetupDecision",
    "SetupError",
    "SetupHandler",
    "SetupInspection",
    "SetupRequirement",
    "SetupRun",
    "SetupRunState",
    "SetupStep",
    "SetupStepResult",
    "SetupStepState",
    "SetupStore",
    "SetupValidationError",
]
