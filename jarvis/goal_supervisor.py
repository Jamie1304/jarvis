"""Bounded long-horizon goal supervision.

The supervisor owns durable intent and high-level coordination only.  The
PlanningEngine remains the sole task/plan executor, AgentLoop remains the
bounded reasoning primitive, and all effects remain behind the normal tool and
permission boundaries.  A supervisor restart never blindly reruns an active
stage or an operation with an uncertain outcome.
"""

from __future__ import annotations

import json
import math
import sqlite3
import threading
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass, field, replace
from datetime import UTC, datetime, timedelta
from enum import StrEnum
from pathlib import Path
from typing import Protocol
from uuid import UUID, uuid4

from jarvis.capabilities import CapabilityLifecycle, CapabilityRegistry, EnvironmentGraph
from jarvis.capability_factory import (
    AdoptionCandidates,
    CapabilityFactory,
    FactoryLifecycle,
    SolutionReport,
    WorkspaceContext,
)
from jarvis.discovery.models import CapabilityGap
from jarvis.permissions.models import Risk
from jarvis.planning.models import (
    EffectOutcome,
    ExecutionBudgets,
    FailureKind,
    PlanningTask,
    PlanningTaskStatus,
)
from jarvis.planning.validation import PlanProposal
from jarvis.task_controller import TaskController
from jarvis.trace import TraceEventType, TraceService
from jarvis.verification import (
    EvidenceRecord,
    EvidenceType,
    VerificationEngine,
    VerificationLevel,
    VerificationPlan,
    VerificationResult,
)


class GoalSupervisorError(RuntimeError):
    """Goal supervision cannot continue safely."""


class GoalSupervisorValidationError(GoalSupervisorError, ValueError):
    """Goal supervision input or durable state is malformed."""


class GoalStatus(StrEnum):
    ANALYZING = "analyzing"
    RESEARCHING = "researching"
    ACQUIRING = "acquiring"
    PLANNING = "planning"
    EXECUTING = "executing"
    VERIFYING = "verifying"
    REPLANNING = "replanning"
    WAITING_FOR_PERMISSION = "waiting_for_permission"
    COMPLETED = "completed"
    BLOCKED = "blocked"
    RECOVERING = "recovering"
    BUDGET_EXHAUSTED = "budget_exhausted"
    FAILED = "failed"


class AlternativeKind(StrEnum):
    ARCHITECTURE = "architecture"
    API_LIBRARY = "api_library"
    MCP = "mcp"
    WORKAROUND = "workaround"
    MODEL = "model"
    TOOL = "tool"
    INFRASTRUCTURE = "infrastructure"
    USER_INPUT = "user_input"


class GoalExecutionStatus(StrEnum):
    COMPLETED = "completed"
    WAITING_FOR_PERMISSION = "waiting_for_permission"
    RECOVERING = "recovering"
    BUDGET_EXHAUSTED = "budget_exhausted"
    FAILED = "failed"


class GoalSupervisorStoreError(GoalSupervisorError):
    """The durable supervisor store is unavailable or incompatible."""


_RISK_ORDER = {
    Risk.LOW: 0,
    Risk.MEDIUM: 1,
    Risk.HIGH: 2,
    Risk.CRITICAL: 3,
}
_ALTERNATIVE_KINDS: tuple[AlternativeKind, ...] = tuple(AlternativeKind)
_MAX_TEXT = 4_000


def _text(value: object, field: str, limit: int = _MAX_TEXT) -> str:
    if (
        type(value) is not str
        or not value.strip()
        or len(value) > limit
        or "\x00" in value
        or any(not character.isprintable() for character in value)
    ):
        raise GoalSupervisorValidationError(f"{field} is malformed")
    return value


def _labels(values: object, field: str, limit: int = 64) -> tuple[str, ...]:
    if not isinstance(values, tuple) or len(values) > limit:
        raise GoalSupervisorValidationError(f"{field} are malformed")
    return tuple(_text(item, field, 1_000) for item in values)


def _utc(value: datetime) -> datetime:
    if value.tzinfo is None:
        raise GoalSupervisorValidationError("Goal timestamp must be timezone-aware")
    return value.astimezone(UTC)


def _json_safe(value: object, *, depth: int = 0) -> object:
    if depth > 5:
        raise GoalSupervisorValidationError("Goal metadata is too deeply nested")
    if value is None or type(value) is bool or type(value) is int:
        return value
    if type(value) is float:
        if not math.isfinite(value):
            raise GoalSupervisorValidationError("Goal metadata contains a non-finite number")
        return value
    if type(value) is str:
        return _text(value, "Goal metadata value")
    if isinstance(value, Mapping):
        if len(value) > 64:
            raise GoalSupervisorValidationError("Goal metadata has too many properties")
        return {
            _text(key, "Goal metadata key", 128): _json_safe(item, depth=depth + 1)
            for key, item in value.items()
        }
    if isinstance(value, Sequence) and not isinstance(value, str | bytes | bytearray):
        if len(value) > 64:
            raise GoalSupervisorValidationError("Goal metadata has too many items")
        return tuple(_json_safe(item, depth=depth + 1) for item in value)
    raise GoalSupervisorValidationError("Goal metadata is not JSON-like")


@dataclass(frozen=True, slots=True)
class GoalIntent:
    """Immutable original user outcome carried across all supervisor stages."""

    original_outcome: str
    assumptions: tuple[str, ...] = ()
    constraints: tuple[str, ...] = ()
    required_capabilities: tuple[str, ...] = ()
    metadata: Mapping[str, object] | None = None
    goal_id: UUID = field(default_factory=uuid4)

    def __post_init__(self) -> None:
        _text(self.original_outcome, "Original outcome")
        _labels(self.assumptions, "Goal assumptions", 32)
        _labels(self.constraints, "Goal constraints", 32)
        _labels(self.required_capabilities, "Required capabilities", 32)
        if not isinstance(self.goal_id, UUID):
            raise GoalSupervisorValidationError("Goal ID is malformed")
        metadata = {} if self.metadata is None else _json_safe(self.metadata)
        if not isinstance(metadata, dict):
            raise GoalSupervisorValidationError("Goal metadata must be an object")
        object.__setattr__(self, "metadata", metadata)


@dataclass(frozen=True, slots=True)
class GoalBudget:
    """Trusted immutable ceilings; no model-facing operation can increase them."""

    max_elapsed_seconds: float = 3_600.0
    max_tokens: int = 64_000
    max_cost: float = 100.0
    max_retries: int = 4
    max_replans: int = 4
    max_disk_bytes: int = 100_000_000
    max_network_bytes: int = 10_000_000
    max_risk: Risk = Risk.MEDIUM
    max_steps: int = 64
    max_model_calls: int = 8
    max_expensive_actions: int = 8

    def __post_init__(self) -> None:
        if (
            self.max_elapsed_seconds <= 0
            or not math.isfinite(self.max_elapsed_seconds)
            or min(
                self.max_tokens,
                self.max_retries,
                self.max_replans,
                self.max_disk_bytes,
                self.max_network_bytes,
                self.max_steps,
                self.max_model_calls,
                self.max_expensive_actions,
            )
            < 0
            or self.max_cost < 0
            or not math.isfinite(self.max_cost)
            or not isinstance(self.max_risk, Risk)
        ):
            raise GoalSupervisorValidationError("Goal budget is malformed")
        if self.max_tokens == 0 or self.max_steps == 0 or self.max_model_calls == 0:
            raise GoalSupervisorValidationError("Goal execution ceilings must permit planning")

    def planning_budgets(self) -> ExecutionBudgets:
        return ExecutionBudgets(
            max_steps=self.max_steps,
            max_elapsed_seconds=self.max_elapsed_seconds,
            max_model_calls=self.max_model_calls,
            max_expensive_actions=self.max_expensive_actions,
            max_retries=self.max_retries,
        )


@dataclass(frozen=True, slots=True)
class GoalUsage:
    tokens: int = 0
    cost: float = 0.0
    retries: int = 0
    replans: int = 0
    disk_bytes: int = 0
    network_bytes: int = 0
    risk: Risk = Risk.LOW

    def __post_init__(self) -> None:
        if (
            min(self.tokens, self.retries, self.replans, self.disk_bytes, self.network_bytes) < 0
            or self.cost < 0
            or not math.isfinite(self.cost)
            or not isinstance(self.risk, Risk)
        ):
            raise GoalSupervisorValidationError("Goal usage is malformed")

    def add(self, delta: GoalUsage) -> GoalUsage:
        risk = self.risk if _RISK_ORDER[self.risk] >= _RISK_ORDER[delta.risk] else delta.risk
        return GoalUsage(
            self.tokens + delta.tokens,
            self.cost + delta.cost,
            self.retries + delta.retries,
            self.replans + delta.replans,
            self.disk_bytes + delta.disk_bytes,
            self.network_bytes + delta.network_bytes,
            risk,
        )


@dataclass(frozen=True, slots=True)
class GoalAlternative:
    kind: AlternativeKind
    alternative_id: str
    detail: str
    viable: bool = False
    safe: bool = True
    risk: Risk = Risk.LOW

    def __post_init__(self) -> None:
        if not isinstance(self.kind, AlternativeKind):
            raise GoalSupervisorValidationError("Alternative kind is malformed")
        _text(self.alternative_id, "Alternative ID", 256)
        _text(self.detail, "Alternative detail", 1_000)
        if (
            type(self.viable) is not bool
            or type(self.safe) is not bool
            or not isinstance(self.risk, Risk)
        ):
            raise GoalSupervisorValidationError("Alternative metadata is malformed")


@dataclass(frozen=True, slots=True)
class GoalAnalysis:
    capability_gap: CapabilityGap | None = None
    known_capabilities: tuple[str, ...] = ()
    evidence: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        if self.capability_gap is not None and not isinstance(self.capability_gap, CapabilityGap):
            raise GoalSupervisorValidationError("Goal capability gap is malformed")
        _labels(self.known_capabilities, "Known capabilities")
        _labels(self.evidence, "Goal analysis evidence")


@dataclass(frozen=True, slots=True)
class CapabilityAcquisitionRequest:
    gap: CapabilityGap
    solution: SolutionReport
    adoption_candidates: AdoptionCandidates
    workspace: WorkspaceContext
    environment: EnvironmentGraph
    preferences: Mapping[str, object]
    goal_id: UUID | None = None

    def __post_init__(self) -> None:
        if not isinstance(self.gap, CapabilityGap) or not isinstance(self.solution, SolutionReport):
            raise GoalSupervisorValidationError("Capability acquisition request is malformed")
        if self.solution.gap != self.gap:
            raise GoalSupervisorValidationError("Capability acquisition gap is inconsistent")
        if not isinstance(self.adoption_candidates, AdoptionCandidates):
            raise GoalSupervisorValidationError("Capability adoption candidates are malformed")
        if not isinstance(self.workspace, WorkspaceContext) or not isinstance(
            self.environment, EnvironmentGraph
        ):
            raise GoalSupervisorValidationError("Capability acquisition scope is malformed")
        _json_safe(self.preferences)
        if self.goal_id is not None and not isinstance(self.goal_id, UUID):
            raise GoalSupervisorValidationError("Capability acquisition goal ID is malformed")


@dataclass(frozen=True, slots=True)
class GoalResearch:
    acquisition: CapabilityAcquisitionRequest | None = None
    usage: GoalUsage = GoalUsage()
    evidence: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        if self.acquisition is not None and not isinstance(
            self.acquisition, CapabilityAcquisitionRequest
        ):
            raise GoalSupervisorValidationError("Goal research acquisition is malformed")
        _labels(self.evidence, "Goal research evidence")


@dataclass(frozen=True, slots=True)
class CapabilityAcquisitionReport:
    active: bool
    capability_id: str | None = None
    usage: GoalUsage = GoalUsage()
    evidence: tuple[str, ...] = ()
    detail: str = ""
    stage: str | None = None

    def __post_init__(self) -> None:
        if type(self.active) is not bool:
            raise GoalSupervisorValidationError("Capability acquisition status is malformed")
        if self.capability_id is not None:
            _text(self.capability_id, "Acquired capability ID", 256)
        _labels(self.evidence, "Capability acquisition evidence")
        if self.detail:
            _text(self.detail, "Capability acquisition detail")
        if self.stage is not None:
            _text(self.stage, "Capability acquisition stage", 128)


@dataclass(frozen=True, slots=True)
class GoalExecutionReport:
    status: GoalExecutionStatus
    task_id: UUID | None = None
    usage: GoalUsage = GoalUsage()
    evidence: tuple[str, ...] = ()
    detail: str = ""
    retry_safe: bool = False
    effect_outcome: EffectOutcome | None = None

    def __post_init__(self) -> None:
        if not isinstance(self.status, GoalExecutionStatus):
            raise GoalSupervisorValidationError("Goal execution status is malformed")
        if self.task_id is not None and not isinstance(self.task_id, UUID):
            raise GoalSupervisorValidationError("Goal task ID is malformed")
        _labels(self.evidence, "Goal execution evidence")
        if self.detail:
            _text(self.detail, "Goal execution detail")
        if type(self.retry_safe) is not bool or (
            self.effect_outcome is not None and not isinstance(self.effect_outcome, EffectOutcome)
        ):
            raise GoalSupervisorValidationError("Goal execution retry metadata is malformed")
        if self.effect_outcome in {
            EffectOutcome.UNKNOWN_OUTCOME,
            EffectOutcome.EFFECT_CONFIRMED,
        }:
            object.__setattr__(self, "retry_safe", False)


@dataclass(frozen=True, slots=True)
class GoalSupervisorState:
    intent: GoalIntent
    budget: GoalBudget
    status: GoalStatus
    created_at: datetime
    updated_at: datetime
    usage: GoalUsage = GoalUsage()
    task_id: UUID | None = None
    capability_id: str | None = None
    alternatives_examined: tuple[str, ...] = ()
    attempted_alternatives: tuple[str, ...] = ()
    evidence: tuple[str, ...] = ()
    last_error: str | None = None
    active_run: bool = False

    def __post_init__(self) -> None:
        if not isinstance(self.intent, GoalIntent) or not isinstance(self.budget, GoalBudget):
            raise GoalSupervisorValidationError("Goal supervisor state is malformed")
        if not isinstance(self.status, GoalStatus):
            raise GoalSupervisorValidationError("Goal supervisor status is malformed")
        object.__setattr__(self, "created_at", _utc(self.created_at))
        object.__setattr__(self, "updated_at", _utc(self.updated_at))
        if self.task_id is not None and not isinstance(self.task_id, UUID):
            raise GoalSupervisorValidationError("Goal task link is malformed")
        if self.capability_id is not None:
            _text(self.capability_id, "Goal capability link", 256)
        _labels(self.alternatives_examined, "Examined alternatives")
        _labels(self.attempted_alternatives, "Attempted alternatives")
        _labels(self.evidence, "Goal evidence")
        if self.last_error is not None:
            _text(self.last_error, "Goal error")
        if type(self.active_run) is not bool:
            raise GoalSupervisorValidationError("Goal active-run marker is malformed")

    @property
    def terminal(self) -> bool:
        return self.status in {
            GoalStatus.COMPLETED,
            GoalStatus.BLOCKED,
            GoalStatus.RECOVERING,
            GoalStatus.BUDGET_EXHAUSTED,
            GoalStatus.FAILED,
        }


class GoalAnalyzer(Protocol):
    async def analyze(self, intent: GoalIntent, registry: CapabilityRegistry) -> GoalAnalysis: ...


class GoalResearcher(Protocol):
    async def research(
        self,
        intent: GoalIntent,
        analysis: GoalAnalysis,
        alternative: GoalAlternative | None = None,
    ) -> GoalResearch: ...


class CapabilityAcquirer(Protocol):
    async def acquire(
        self, request: CapabilityAcquisitionRequest
    ) -> CapabilityAcquisitionReport: ...


class AlternativeExaminer(Protocol):
    async def examine(
        self, intent: GoalIntent, analysis: GoalAnalysis
    ) -> tuple[GoalAlternative, ...]: ...


class GoalTaskRunner(Protocol):
    async def run(self, intent: GoalIntent, budget: GoalBudget) -> GoalExecutionReport: ...


class RegistryGoalAnalyzer:
    """Default registry-first analyzer for explicit required capabilities."""

    async def analyze(self, intent: GoalIntent, registry: CapabilityRegistry) -> GoalAnalysis:
        active = tuple(
            manifest
            for manifest in registry.manifests()
            if manifest.lifecycle is CapabilityLifecycle.ACTIVE
        )
        known = tuple(item.capability_id for item in active)
        missing = tuple(
            required
            for required in intent.required_capabilities
            if not any(
                required.casefold() in {item.capability_id.casefold(), item.name.casefold()}
                for item in active
            )
        )
        if not missing:
            return GoalAnalysis(
                known_capabilities=known, evidence=("registry capability check passed",)
            )
        gap = CapabilityGap(
            missing[0],
            intent.original_outcome,
            missing,
            (),
            Risk.MEDIUM,
            (),
        )
        return GoalAnalysis(
            gap,
            known,
            ("registry capability check found a missing capability",),
        )


class DefaultAlternativeExaminer:
    """Fail-closed examiner that records every required alternative category."""

    async def examine(
        self, intent: GoalIntent, analysis: GoalAnalysis
    ) -> tuple[GoalAlternative, ...]:
        del intent, analysis
        return tuple(
            GoalAlternative(kind, f"unavailable:{kind.value}", "No safe candidate supplied")
            for kind in _ALTERNATIVE_KINDS
        )


class FactoryCapabilityAcquirer:
    """Typed adapter from research output to the existing CapabilityFactory."""

    def __init__(self, factory: CapabilityFactory) -> None:
        self._factory = factory

    async def acquire(self, request: CapabilityAcquisitionRequest) -> CapabilityAcquisitionReport:
        result = await self._factory.acquire(
            request.gap,
            request.solution,
            request.adoption_candidates,
            request.workspace,
            request.environment,
            request.preferences,
        )
        active = result.lifecycle is FactoryLifecycle.ACTIVE
        return CapabilityAcquisitionReport(
            active=active,
            capability_id=result.capability_id if active else None,
            evidence=(result.reason,),
            detail=result.reason,
        )


class PlanningGoalTaskRunner:
    """Run one bounded goal attempt through the canonical TaskController."""

    def __init__(
        self,
        controller: TaskController,
        *,
        generated_planner: object | None = None,
        verification_engine: VerificationEngine | None = None,
        trace: TraceService | None = None,
    ) -> None:
        self._controller = controller
        self._generated_planner = generated_planner
        if verification_engine is not None and type(verification_engine) is not VerificationEngine:
            raise GoalSupervisorValidationError("Generated verification engine is malformed")
        if trace is not None and type(trace) is not TraceService:
            raise GoalSupervisorValidationError("Generated trace service is malformed")
        self._verification = verification_engine
        self._trace = trace

    async def run(self, intent: GoalIntent, budget: GoalBudget) -> GoalExecutionReport:
        proposal: PlanProposal | None = None
        if self._generated_planner is not None:
            propose = getattr(self._generated_planner, "proposal_for", None)
            if not callable(propose):
                raise GoalSupervisorValidationError("Generated planner is malformed")
            candidate = propose(intent)
            if candidate is not None and not isinstance(candidate, PlanProposal):
                raise GoalSupervisorValidationError(
                    "Generated planner returned a malformed proposal"
                )
            proposal = candidate
        if proposal is None:
            task = await self._controller.submit_task(
                intent.original_outcome,
                assumptions=intent.assumptions,
                constraints=intent.constraints,
                budgets=budget.planning_budgets(),
            )
        else:
            task = await self._controller.submit_proposal(
                proposal,
                budgets=budget.planning_budgets(),
                provenance=("goal-supervisor.generated-action",),
            )
        status = {
            PlanningTaskStatus.COMPLETED: GoalExecutionStatus.COMPLETED,
            PlanningTaskStatus.WAITING_FOR_PERMISSION: GoalExecutionStatus.WAITING_FOR_PERMISSION,
            PlanningTaskStatus.RECOVERING: GoalExecutionStatus.RECOVERING,
            PlanningTaskStatus.BUDGET_EXHAUSTED: GoalExecutionStatus.BUDGET_EXHAUSTED,
        }.get(task.status, GoalExecutionStatus.FAILED)
        failure_kind = task.error.failure_kind if task.error is not None else None
        unknown = failure_kind is FailureKind.UNKNOWN_OUTCOME
        retry_safe = (
            not unknown
            and failure_kind is FailureKind.TRANSIENT
            and status is GoalExecutionStatus.FAILED
        )
        evidence = task.result_evidence or (task.error.evidence if task.error else ())
        if proposal is not None and status is GoalExecutionStatus.COMPLETED:
            verification = self._verify_generated_result(task, proposal)
            verification_evidence = tuple(
                f"generated-verification:{item}" for item in verification.missing_criteria
            )
            if verification.passed:
                evidence = evidence + ("generated action independently verified",)
            else:
                evidence = evidence + verification_evidence
                status = GoalExecutionStatus.FAILED
            detail = (
                "generated action completed and independently verified"
                if verification.passed
                else "generated action execution did not pass independent verification"
            )
        else:
            detail = task.error.message if task.error else "task completed"
        return GoalExecutionReport(
            status,
            task.task_id,
            GoalUsage(
                retries=task.usage.retries,
            ),
            evidence,
            detail,
            retry_safe,
            EffectOutcome.UNKNOWN_OUTCOME if unknown else None,
        )

    def _verify_generated_result(
        self, task: PlanningTask, proposal: PlanProposal
    ) -> VerificationResult:
        if self._verification is None:
            raise GoalSupervisorValidationError(
                "Generated action execution requires an application-owned verifier"
            )
        task_id = task.task_id
        if not isinstance(task_id, UUID):  # pragma: no cover - PlanningTask validates this
            raise GoalSupervisorValidationError("Generated task identity is malformed")
        plan = self._controller.inspect_plan(task_id)
        records: list[EvidenceRecord] = []
        if plan is not None:
            for step in plan.steps:
                result = step.result
                if result is None or not step.tool_id.startswith("generated."):
                    continue
                for criterion in step.expected_evidence:
                    if (
                        criterion not in result.evidence
                        or step.expected_output not in result.output_json
                    ):
                        continue
                    records.append(
                        EvidenceRecord(
                            EvidenceType.CUSTOM,
                            "trusted.generated.adapter",
                            datetime.now(UTC),
                            timedelta(minutes=5),
                            1.0,
                            criterion,
                            criterion,
                            level=VerificationLevel.INTEGRATION_VERIFIED,
                        )
                    )
        verification_plan = VerificationPlan(
            proposal.goal,
            tuple(proposal.completion_criteria),
            allowed_evidence_types=frozenset({EvidenceType.CUSTOM}),
            required_level=VerificationLevel.INTEGRATION_VERIFIED,
            independent_observation_required=True,
            ask_user_when_unobservable=False,
        )
        verification = self._verification.evaluate(verification_plan, records)
        if self._trace is not None:
            self._trace.record(
                TraceEventType.VERIFICATION,
                "Generated action result independently verified",
                task_id=task_id,
                correlation_id=task_id,
                result={
                    "passed": verification.passed,
                    "missing_criteria": verification.missing_criteria,
                },
                evidence=tuple(item.expected for item in verification.evidence),
            )
        return verification


class GoalSupervisorStore:
    """Single durable owner for user intent and supervisor coordination state."""

    CURRENT_SCHEMA = 1

    def __init__(self, path: Path) -> None:
        path.parent.mkdir(parents=True, exist_ok=True)
        self._connection = sqlite3.connect(path, timeout=5.0, check_same_thread=False)
        self._connection.execute("PRAGMA journal_mode=WAL")
        self._connection.execute("PRAGMA busy_timeout=5000")
        self._connection.execute("PRAGMA foreign_keys=ON")
        self._lock = threading.RLock()
        try:
            self._connection.execute(
                "CREATE TABLE IF NOT EXISTS goal_supervisor_schema_migrations "
                "(version INTEGER PRIMARY KEY, name TEXT NOT NULL)"
            )
            versions = {
                int(row[0]): str(row[1])
                for row in self._connection.execute(
                    "SELECT version, name FROM goal_supervisor_schema_migrations"
                )
            }
            if any(version > self.CURRENT_SCHEMA for version in versions):
                raise GoalSupervisorStoreError("Goal supervisor database uses a future schema")
            if not versions:
                self._connection.execute(
                    "CREATE TABLE goal_supervisor_state "
                    "(goal_id TEXT PRIMARY KEY, state_json TEXT NOT NULL, updated_at TEXT NOT NULL)"
                )
                self._connection.execute(
                    "INSERT INTO goal_supervisor_schema_migrations(version, name) "
                    "VALUES (1, 'create_goal_supervisor_state')"
                )
            elif versions.get(1) != "create_goal_supervisor_state":
                raise GoalSupervisorStoreError("Goal supervisor migration identity mismatch")
            self._connection.commit()
        except (sqlite3.DatabaseError, ValueError) as error:
            self._connection.close()
            raise GoalSupervisorStoreError("Goal supervisor database is unavailable") from error

    def create(self, state: GoalSupervisorState) -> GoalSupervisorState:
        payload = _encode_state(state)
        with self._lock:
            try:
                self._connection.execute(
                    "INSERT INTO goal_supervisor_state(goal_id, state_json, updated_at) "
                    "VALUES (?, ?, ?)",
                    (str(state.intent.goal_id), payload, state.updated_at.isoformat()),
                )
                self._connection.commit()
            except sqlite3.IntegrityError as error:
                raise GoalSupervisorStoreError("Goal already exists") from error
        return state

    def save(self, state: GoalSupervisorState) -> GoalSupervisorState:
        payload = _encode_state(state)
        with self._lock:
            existing = self._connection.execute(
                "SELECT state_json FROM goal_supervisor_state WHERE goal_id=?",
                (str(state.intent.goal_id),),
            ).fetchone()
            if existing is None:
                raise GoalSupervisorStoreError("Goal does not exist")
            try:
                prior = _decode_state(str(existing[0]))
                if prior.intent != state.intent or prior.budget != state.budget:
                    raise GoalSupervisorStoreError("Goal intent or budget cannot be changed")
                self._connection.execute(
                    "UPDATE goal_supervisor_state SET state_json=?, updated_at=? WHERE goal_id=?",
                    (payload, state.updated_at.isoformat(), str(state.intent.goal_id)),
                )
                self._connection.commit()
            except sqlite3.DatabaseError as error:
                self._connection.rollback()
                raise GoalSupervisorStoreError("Goal state could not be saved") from error
        return state

    def exists(self, goal_id: UUID) -> bool:
        with self._lock:
            return (
                self._connection.execute(
                    "SELECT 1 FROM goal_supervisor_state WHERE goal_id=?", (str(goal_id),)
                ).fetchone()
                is not None
            )

    def load(self, goal_id: UUID, *, reconcile_active: bool = True) -> GoalSupervisorState | None:
        with self._lock:
            row = self._connection.execute(
                "SELECT state_json FROM goal_supervisor_state WHERE goal_id=?", (str(goal_id),)
            ).fetchone()
        if row is None:
            return None
        state = _decode_state(str(row[0]))
        if reconcile_active and state.active_run and not state.terminal:
            state = replace(
                state,
                status=GoalStatus.RECOVERING,
                active_run=False,
                last_error="Supervisor stopped during an active stage; reconciliation is required",
                updated_at=datetime.now(UTC),
            )
            self.save(state)
        return state

    def list(self) -> tuple[GoalSupervisorState, ...]:
        with self._lock:
            rows = self._connection.execute(
                "SELECT state_json FROM goal_supervisor_state ORDER BY updated_at"
            ).fetchall()
        return tuple(_decode_state(str(row[0])) for row in rows)

    def close(self) -> None:
        with self._lock:
            self._connection.close()


class GoalSupervisor:
    """Coordinate long-horizon intent without becoming a second task engine."""

    def __init__(
        self,
        *,
        registry: CapabilityRegistry,
        store: GoalSupervisorStore,
        analyzer: GoalAnalyzer | None,
        researcher: GoalResearcher,
        acquirer: CapabilityAcquirer,
        runner: GoalTaskRunner,
        alternatives: AlternativeExaminer | None = None,
        clock: Callable[[], datetime] | None = None,
        trace: TraceService | None = None,
    ) -> None:
        if not isinstance(registry, CapabilityRegistry):
            raise GoalSupervisorValidationError("Capability registry is malformed")
        self._registry = registry
        self._store = store
        self._analyzer = analyzer or RegistryGoalAnalyzer()
        self._researcher = researcher
        self._acquirer = acquirer
        self._runner = runner
        self._alternatives = alternatives or DefaultAlternativeExaminer()
        self._clock = clock or (lambda: datetime.now(UTC))
        if trace is not None and type(trace) is not TraceService:
            raise GoalSupervisorValidationError("Trace service is malformed")
        self._trace = trace

    async def start(self, intent: GoalIntent, budget: GoalBudget) -> GoalSupervisorState:
        current = self._store.load(intent.goal_id)
        if current is None:
            now = _utc(self._clock())
            current = self._store.create(
                GoalSupervisorState(intent, budget, GoalStatus.ANALYZING, now, now)
            )
        elif current.intent != intent or current.budget != budget:
            raise GoalSupervisorValidationError(
                "Restart intent or budget does not match durable state"
            )
        if current.terminal:
            return current
        if self._trace is not None:
            self._trace.record(
                TraceEventType.GOAL,
                "Goal supervisor state loaded",
                goal_id=intent.goal_id,
                correlation_id=intent.goal_id,
                result={"status": current.status.value},
            )
        if current.status in {GoalStatus.RECOVERING, GoalStatus.WAITING_FOR_PERMISSION}:
            return current
        current = self._save(replace(current, active_run=True))
        analysis: GoalAnalysis | None = None
        selected: GoalAlternative | None = None
        try:
            while True:
                current = self._check_budget(current)
                current = self._transition(current, GoalStatus.ANALYZING)
                analysis = await self._analyzer.analyze(intent, self._registry)
                if not isinstance(analysis, GoalAnalysis):
                    raise GoalSupervisorValidationError("Goal analyzer returned malformed data")
                current = self._add_usage(current, GoalUsage())
                current = self._add_evidence(current, analysis.evidence)
                if analysis.capability_gap is not None:
                    current = self._transition(current, GoalStatus.RESEARCHING)
                    research = await self._researcher.research(intent, analysis, selected)
                    if not isinstance(research, GoalResearch):
                        raise GoalSupervisorValidationError(
                            "Goal researcher returned malformed data"
                        )
                    current = self._add_usage(current, research.usage)
                    current = self._add_evidence(current, research.evidence)
                    current = self._check_budget(current)
                    if research.acquisition is not None:
                        current = self._transition(current, GoalStatus.ACQUIRING)
                        acquired = await self._acquirer.acquire(research.acquisition)
                        if not isinstance(acquired, CapabilityAcquisitionReport):
                            raise GoalSupervisorValidationError(
                                "Capability acquirer returned malformed data"
                            )
                        current = self._add_usage(current, acquired.usage)
                        current = self._add_evidence(current, acquired.evidence)
                        current = self._check_budget(current)
                        if acquired.active:
                            current = self._save(
                                replace(current, capability_id=acquired.capability_id)
                            )
                        else:
                            current, selected = await self._select_alternative(
                                current, intent, analysis
                            )
                            if selected is None:
                                return self._finish_blocked(
                                    current,
                                    "Capability acquisition did not produce an active capability",
                                )
                            current = self._mark_attempt(current, selected)
                            continue
                    else:
                        current, selected = await self._select_alternative(
                            current, intent, analysis
                        )
                        if selected is None:
                            return self._finish_blocked(
                                current, "Research found no safe capability acquisition path"
                            )
                        current = self._mark_attempt(current, selected)
                        continue
                current = self._transition(current, GoalStatus.PLANNING)
                current = self._transition(current, GoalStatus.EXECUTING)
                report = await self._runner.run(intent, current.budget)
                if not isinstance(report, GoalExecutionReport):
                    raise GoalSupervisorValidationError("Goal task runner returned malformed data")
                current = self._add_usage(current, report.usage)
                current = self._add_evidence(current, report.evidence)
                current = self._check_budget(current)
                if report.task_id is not None:
                    if self._trace is not None:
                        self._trace.bind_goal_task(intent.goal_id, report.task_id)
                    current = self._save(replace(current, task_id=report.task_id))
                current = self._transition(current, GoalStatus.VERIFYING)
                if report.status is GoalExecutionStatus.COMPLETED:
                    return self._finish(
                        current, GoalStatus.COMPLETED, report.detail, report.evidence
                    )
                if report.status is GoalExecutionStatus.WAITING_FOR_PERMISSION:
                    return self._finish(
                        current, GoalStatus.WAITING_FOR_PERMISSION, report.detail, report.evidence
                    )
                if (
                    report.status is GoalExecutionStatus.RECOVERING
                    or report.effect_outcome is EffectOutcome.UNKNOWN_OUTCOME
                ):
                    return self._finish(
                        current, GoalStatus.RECOVERING, report.detail, report.evidence
                    )
                if report.status is GoalExecutionStatus.BUDGET_EXHAUSTED:
                    return self._finish(
                        current, GoalStatus.BUDGET_EXHAUSTED, report.detail, report.evidence
                    )
                if not report.retry_safe:
                    current, selected = await self._select_alternative(current, intent, analysis)
                    if selected is None:
                        return self._finish_blocked(current, report.detail or "No safe retry path")
                else:
                    current, selected = await self._select_alternative(current, intent, analysis)
                    if selected is None:
                        return self._finish_blocked(current, report.detail or "No alternate path")
                current = self._save(
                    replace(
                        current,
                        status=GoalStatus.REPLANNING,
                        usage=current.usage.add(GoalUsage(replans=1, retries=1)),
                        last_error=report.detail or "Replanning after execution failure",
                    )
                )
                current = self._check_budget(current)
                current = self._mark_attempt(current, selected)
        except GoalBudgetExceeded as error:
            return self._finish(current, GoalStatus.BUDGET_EXHAUSTED, str(error), ())
        except Exception as error:
            current = self._save(
                replace(
                    current,
                    status=GoalStatus.FAILED,
                    last_error=f"Supervisor failure ({type(error).__name__})",
                )
            )
            raise
        finally:
            latest = self._store.load(intent.goal_id)
            if latest is not None and latest.active_run and latest.terminal:
                self._save(replace(latest, active_run=False))

    async def resume(self, goal_id: UUID, *, reconciled: bool = False) -> GoalSupervisorState:
        state = self._store.load(goal_id)
        if state is None:
            raise GoalSupervisorError("Unknown goal")
        if state.status is GoalStatus.WAITING_FOR_PERMISSION:
            return state
        if state.status is GoalStatus.RECOVERING and not reconciled:
            return state
        if state.status is GoalStatus.RECOVERING:
            state = self._save(replace(state, status=GoalStatus.ANALYZING, last_error=None))
        return await self.start(state.intent, state.budget)

    def get(self, goal_id: UUID) -> GoalSupervisorState | None:
        return self._store.load(goal_id, reconcile_active=False)

    def _transition(self, state: GoalSupervisorState, status: GoalStatus) -> GoalSupervisorState:
        return self._save(replace(state, status=status, updated_at=_utc(self._clock())))

    def _save(self, state: GoalSupervisorState) -> GoalSupervisorState:
        return (
            self._store.save(state)
            if self._store.exists(state.intent.goal_id)
            else self._store.create(state)
        )

    def _add_usage(self, state: GoalSupervisorState, delta: GoalUsage) -> GoalSupervisorState:
        return self._save(
            replace(state, usage=state.usage.add(delta), updated_at=_utc(self._clock()))
        )

    def _add_evidence(
        self, state: GoalSupervisorState, evidence: tuple[str, ...]
    ) -> GoalSupervisorState:
        if not evidence:
            return state
        return self._save(
            replace(
                state,
                evidence=tuple(dict.fromkeys((*state.evidence, *evidence))),
                updated_at=_utc(self._clock()),
            )
        )

    def _check_budget(self, state: GoalSupervisorState) -> GoalSupervisorState:
        elapsed = (_utc(self._clock()) - state.created_at).total_seconds()
        usage = state.usage
        checks = (
            (elapsed <= state.budget.max_elapsed_seconds, "time"),
            (usage.tokens <= state.budget.max_tokens, "tokens"),
            (usage.cost <= state.budget.max_cost, "cost"),
            (usage.retries <= state.budget.max_retries, "retries"),
            (usage.replans <= state.budget.max_replans, "replans"),
            (usage.disk_bytes <= state.budget.max_disk_bytes, "disk"),
            (usage.network_bytes <= state.budget.max_network_bytes, "network"),
            (_RISK_ORDER[usage.risk] <= _RISK_ORDER[state.budget.max_risk], "risk"),
        )
        failed = next((name for valid, name in checks if not valid), None)
        if failed is not None:
            raise GoalBudgetExceeded(f"Goal {failed} budget exhausted")
        return state

    async def _select_alternative(
        self, state: GoalSupervisorState, intent: GoalIntent, analysis: GoalAnalysis
    ) -> tuple[GoalSupervisorState, GoalAlternative | None]:
        candidates = await self._alternatives.examine(intent, analysis)
        if not isinstance(candidates, tuple) or any(
            not isinstance(item, GoalAlternative) for item in candidates
        ):
            raise GoalSupervisorValidationError("Alternative examiner returned malformed data")
        known = {item.alternative_id for item in candidates}
        missing = {
            kind for kind in _ALTERNATIVE_KINDS if not any(item.kind is kind for item in candidates)
        }
        candidates = candidates + tuple(
            GoalAlternative(kind, f"unavailable:{kind.value}", "No safe candidate supplied")
            for kind in missing
        )
        examined = tuple(
            dict.fromkeys(
                (
                    *state.alternatives_examined,
                    *known,
                    *(item.alternative_id for item in candidates),
                )
            )
        )
        updated = self._save(replace(state, alternatives_examined=examined))
        for candidate in candidates:
            if (
                candidate.viable
                and candidate.safe
                and candidate.alternative_id not in updated.attempted_alternatives
                and _RISK_ORDER[candidate.risk] <= _RISK_ORDER[state.budget.max_risk]
            ):
                return updated, candidate
        return updated, None

    def _mark_attempt(
        self, state: GoalSupervisorState, alternative: GoalAlternative
    ) -> GoalSupervisorState:
        return self._save(
            replace(
                state,
                attempted_alternatives=tuple(
                    dict.fromkeys((*state.attempted_alternatives, alternative.alternative_id))
                ),
            )
        )

    def _finish(
        self,
        state: GoalSupervisorState,
        status: GoalStatus,
        detail: str,
        evidence: tuple[str, ...],
    ) -> GoalSupervisorState:
        return self._save(
            replace(
                state,
                status=status,
                evidence=tuple(dict.fromkeys((*state.evidence, *evidence))),
                last_error=None if status is GoalStatus.COMPLETED else detail,
                active_run=False,
                updated_at=_utc(self._clock()),
            )
        )

    def _finish_blocked(self, state: GoalSupervisorState, detail: str) -> GoalSupervisorState:
        return self._finish(state, GoalStatus.BLOCKED, detail, ())


class GoalBudgetExceeded(GoalSupervisorError):
    """A trusted supervisor ceiling was reached."""


def _encode_state(state: GoalSupervisorState) -> str:
    payload = {
        "intent": {
            "goal_id": str(state.intent.goal_id),
            "original_outcome": state.intent.original_outcome,
            "assumptions": list(state.intent.assumptions),
            "constraints": list(state.intent.constraints),
            "required_capabilities": list(state.intent.required_capabilities),
            "metadata": state.intent.metadata,
        },
        "budget": {
            key: getattr(state.budget, key)
            for key in (
                "max_elapsed_seconds",
                "max_tokens",
                "max_cost",
                "max_retries",
                "max_replans",
                "max_disk_bytes",
                "max_network_bytes",
                "max_steps",
                "max_model_calls",
                "max_expensive_actions",
            )
        }
        | {"max_risk": state.budget.max_risk.value},
        "status": state.status.value,
        "created_at": state.created_at.isoformat(),
        "updated_at": state.updated_at.isoformat(),
        "usage": {
            "tokens": state.usage.tokens,
            "cost": state.usage.cost,
            "retries": state.usage.retries,
            "replans": state.usage.replans,
            "disk_bytes": state.usage.disk_bytes,
            "network_bytes": state.usage.network_bytes,
            "risk": state.usage.risk.value,
        },
        "task_id": str(state.task_id) if state.task_id else None,
        "capability_id": state.capability_id,
        "alternatives_examined": list(state.alternatives_examined),
        "attempted_alternatives": list(state.attempted_alternatives),
        "evidence": list(state.evidence),
        "last_error": state.last_error,
        "active_run": state.active_run,
    }
    return json.dumps(payload, sort_keys=True, separators=(",", ":"), allow_nan=False)


def _decode_state(payload: str) -> GoalSupervisorState:
    try:
        data = json.loads(payload)
        intent = data["intent"]
        budget = data["budget"]
        usage = data["usage"]
        return GoalSupervisorState(
            GoalIntent(
                intent["original_outcome"],
                tuple(intent["assumptions"]),
                tuple(intent["constraints"]),
                tuple(intent["required_capabilities"]),
                intent.get("metadata", {}),
                UUID(intent["goal_id"]),
            ),
            GoalBudget(
                max_elapsed_seconds=float(budget["max_elapsed_seconds"]),
                max_tokens=int(budget["max_tokens"]),
                max_cost=float(budget["max_cost"]),
                max_retries=int(budget["max_retries"]),
                max_replans=int(budget["max_replans"]),
                max_disk_bytes=int(budget["max_disk_bytes"]),
                max_network_bytes=int(budget["max_network_bytes"]),
                max_risk=Risk(budget["max_risk"]),
                max_steps=int(budget["max_steps"]),
                max_model_calls=int(budget["max_model_calls"]),
                max_expensive_actions=int(budget["max_expensive_actions"]),
            ),
            GoalStatus(data["status"]),
            datetime.fromisoformat(data["created_at"]),
            datetime.fromisoformat(data["updated_at"]),
            GoalUsage(
                int(usage["tokens"]),
                float(usage["cost"]),
                int(usage["retries"]),
                int(usage["replans"]),
                int(usage["disk_bytes"]),
                int(usage["network_bytes"]),
                Risk(usage["risk"]),
            ),
            UUID(data["task_id"]) if data.get("task_id") else None,
            data.get("capability_id"),
            tuple(data["alternatives_examined"]),
            tuple(data["attempted_alternatives"]),
            tuple(data["evidence"]),
            data.get("last_error"),
            data["active_run"],
        )
    except (KeyError, TypeError, ValueError, json.JSONDecodeError) as error:
        raise GoalSupervisorStoreError("Goal supervisor state is malformed") from error


__all__ = [
    "AlternativeExaminer",
    "AlternativeKind",
    "CapabilityAcquirer",
    "CapabilityAcquisitionReport",
    "CapabilityAcquisitionRequest",
    "DefaultAlternativeExaminer",
    "FactoryCapabilityAcquirer",
    "GoalAlternative",
    "GoalAnalysis",
    "GoalAnalyzer",
    "GoalBudget",
    "GoalBudgetExceeded",
    "GoalExecutionReport",
    "GoalExecutionStatus",
    "GoalIntent",
    "GoalResearch",
    "GoalResearcher",
    "GoalStatus",
    "GoalSupervisor",
    "GoalSupervisorError",
    "GoalSupervisorState",
    "GoalSupervisorStore",
    "GoalSupervisorStoreError",
    "GoalSupervisorValidationError",
    "GoalTaskRunner",
    "GoalUsage",
    "PlanningGoalTaskRunner",
    "RegistryGoalAnalyzer",
]
