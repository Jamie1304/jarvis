"""Typed orchestration proposals and trusted bounded decomposition."""

from __future__ import annotations

import asyncio
import hashlib
import json
from collections.abc import Callable
from dataclasses import dataclass
from datetime import UTC, datetime
from enum import StrEnum
from typing import Protocol
from uuid import UUID, uuid4

from jarvis.ai.roles import LogicalModelRole, LogicalRoleRequirements
from jarvis.planning.models import ReplanEvidence


class OrchestrationResultKind(StrEnum):
    DIRECT = "direct"
    DECOMPOSITION = "decomposition"


class OrchestrationAttemptStatus(StrEnum):
    STARTED = "started"
    COMPLETED = "completed"
    FAILED = "failed"
    INTERRUPTED = "interrupted"


@dataclass(frozen=True, slots=True)
class DecompositionSubproblem:
    """Untrusted bounded child objective; trusted code assigns attempt identity."""

    objective: str
    assumptions: tuple[str, ...] = ()
    constraints: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        if (
            type(self.objective) is not str
            or not self.objective.strip()
            or len(self.objective) > 1_000
        ):
            raise ValueError("Decomposition objective is invalid")
        for name, values in (("assumptions", self.assumptions), ("constraints", self.constraints)):
            if (
                type(values) is not tuple
                or len(values) > 16
                or any(
                    type(value) is not str or not value.strip() or len(value) > 1_000
                    for value in values
                )
            ):
                raise ValueError(f"Decomposition {name} are invalid")


@dataclass(frozen=True, slots=True)
class DecompositionSummary:
    """Small synthesis context; no model transcript or hidden reasoning."""

    attempt_id: UUID
    objective: str
    status: str
    facts: tuple[str, ...] = ()


@dataclass(frozen=True, slots=True)
class OrchestrationRequest:
    """Trusted request envelope given to an orchestration proposal provider."""

    orchestration_attempt_id: UUID
    goal: str
    assumptions: tuple[str, ...] = ()
    constraints: tuple[str, ...] = ()
    requirements: LogicalRoleRequirements | None = None
    parent_attempt_id: UUID | None = None
    root_attempt_id: UUID | None = None
    depth: int = 0
    decomposition_context: tuple[DecompositionSummary, ...] = ()

    def __post_init__(self) -> None:
        if not isinstance(self.orchestration_attempt_id, UUID):
            raise ValueError("Orchestration attempt identity is invalid")
        if type(self.goal) is not str or not self.goal.strip() or len(self.goal) > 4_000:
            raise ValueError("Orchestration goal is invalid")
        for name, values in (("assumptions", self.assumptions), ("constraints", self.constraints)):
            if (
                type(values) is not tuple
                or len(values) > 32
                or any(
                    type(value) is not str or not value.strip() or len(value) > 1_000
                    for value in values
                )
            ):
                raise ValueError(f"Orchestration {name} are invalid")
        if (
            self.requirements is not None
            and self.requirements.role is not LogicalModelRole.ORCHESTRATION
        ):
            raise ValueError("Orchestration requirements must use the orchestration role")
        if type(self.depth) is not int or self.depth < 0 or self.depth > 32:
            raise ValueError("Orchestration depth is invalid")
        if self.parent_attempt_id == self.orchestration_attempt_id:
            raise ValueError("Orchestration attempt cannot parent itself")
        if self.root_attempt_id is not None and not isinstance(self.root_attempt_id, UUID):
            raise ValueError("Orchestration root identity is invalid")
        if len(self.decomposition_context) > 32:
            raise ValueError("Orchestration synthesis context is too large")

    @classmethod
    def create(
        cls,
        goal: str,
        assumptions: tuple[str, ...] = (),
        constraints: tuple[str, ...] = (),
        requirements: LogicalRoleRequirements | None = None,
        *,
        parent_attempt_id: UUID | None = None,
        root_attempt_id: UUID | None = None,
        depth: int = 0,
        decomposition_context: tuple[DecompositionSummary, ...] = (),
    ) -> OrchestrationRequest:
        attempt_id = uuid4()
        return cls(
            attempt_id,
            goal,
            assumptions,
            constraints,
            requirements,
            parent_attempt_id,
            root_attempt_id or attempt_id,
            depth,
            decomposition_context,
        )


@dataclass(frozen=True, slots=True)
class OrchestrationResult:
    """An untrusted direct proposal or bounded decomposition proposal."""

    orchestration_attempt_id: UUID
    proposal: object | None = None
    route_decision_id: str | None = None
    failure: str | None = None
    kind: OrchestrationResultKind = OrchestrationResultKind.DIRECT
    subproblems: tuple[DecompositionSubproblem, ...] = ()

    def __post_init__(self) -> None:
        if not isinstance(self.orchestration_attempt_id, UUID):
            raise ValueError("Orchestration attempt identity is invalid")
        if not isinstance(self.kind, OrchestrationResultKind):
            raise ValueError("Orchestration result kind is invalid")
        if self.route_decision_id is not None and (
            type(self.route_decision_id) is not str
            or not self.route_decision_id.strip()
            or len(self.route_decision_id) > 128
        ):
            raise ValueError("Orchestration route decision identity is invalid")
        if self.failure is not None and (
            type(self.failure) is not str or not self.failure.strip() or len(self.failure) > 1_000
        ):
            raise ValueError("Orchestration failure is invalid")
        if len(self.subproblems) > 32 or any(
            not isinstance(item, DecompositionSubproblem) for item in self.subproblems
        ):
            raise ValueError("Orchestration subproblems are invalid")
        if self.failure is None:
            if self.kind is OrchestrationResultKind.DIRECT and (
                self.proposal is None or self.subproblems
            ):
                raise ValueError("Direct orchestration result must contain only a proposal")
            if self.kind is OrchestrationResultKind.DECOMPOSITION and (
                self.proposal is not None or not self.subproblems
            ):
                raise ValueError("Decomposition result must contain only subproblems")


@dataclass(frozen=True, slots=True)
class DecompositionPolicy:
    max_depth: int = 2
    max_nodes: int = 8
    max_model_calls: int = 8
    max_children: int = 4

    def __post_init__(self) -> None:
        if self.max_depth < 0 or min(self.max_nodes, self.max_model_calls, self.max_children) <= 0:
            raise ValueError("Decomposition bounds must be positive")


@dataclass(frozen=True, slots=True)
class OrchestrationAttempt:
    attempt_id: UUID
    parent_attempt_id: UUID | None
    root_attempt_id: UUID
    depth: int
    kind: OrchestrationResultKind


@dataclass(frozen=True, slots=True)
class DurableOrchestrationAttempt:
    attempt_id: UUID
    task_id: UUID | None
    parent_attempt_id: UUID | None
    root_attempt_id: UUID
    depth: int
    status: OrchestrationAttemptStatus
    started_at: datetime
    finished_at: datetime | None = None
    kind: OrchestrationResultKind | None = None
    route_decision_id: str | None = None
    diagnostic_code: str | None = None


class OrchestrationAttemptStore(Protocol):
    def begin_orchestration_attempt(self, attempt: DurableOrchestrationAttempt) -> None: ...

    def finish_orchestration_attempt(
        self,
        attempt_id: UUID,
        *,
        status: OrchestrationAttemptStatus,
        kind: OrchestrationResultKind | None = None,
        route_decision_id: str | None = None,
        diagnostic_code: str | None = None,
        finished_at: datetime | None = None,
    ) -> None: ...

    def reconcile_orchestration_attempts(self) -> tuple[DurableOrchestrationAttempt, ...]: ...

    def list_orchestration_attempts(self) -> tuple[DurableOrchestrationAttempt, ...]: ...


@dataclass(frozen=True, slots=True)
class OrchestrationRun:
    proposal: object
    model_calls: int
    attempts: tuple[OrchestrationAttempt, ...]


class DecompositionError(ValueError):
    """A trusted bounded decomposition policy rejected an untrusted proposal."""


class OrchestrationAdvisor(Protocol):
    async def propose_orchestration(self, request: OrchestrationRequest) -> OrchestrationResult: ...

    async def replan_orchestration(
        self, request: OrchestrationRequest, evidence: ReplanEvidence
    ) -> OrchestrationResult: ...


class OrchestrationController:
    """Own recursion, budgets and lineage; never executes effects."""

    def __init__(
        self,
        advisor: OrchestrationAdvisor,
        policy: DecompositionPolicy | None = None,
        attempt_store: OrchestrationAttemptStore | None = None,
    ) -> None:
        self._advisor = advisor
        self._policy = policy or DecompositionPolicy()
        self._attempt_store = attempt_store

    async def run(
        self,
        request: OrchestrationRequest,
        *,
        max_model_calls: int,
        cancellation: asyncio.Event | None = None,
        deadline: datetime | None = None,
        replan_evidence: ReplanEvidence | None = None,
        clock: Callable[[], datetime] | None = None,
        task_id: UUID | None = None,
    ) -> OrchestrationRun:
        ledger = _Ledger(
            self._advisor,
            self._policy,
            max_model_calls,
            cancellation,
            deadline,
            clock,
            self._attempt_store,
            task_id,
        )
        ledger.register_root(request)
        proposal, attempts = await self._visit(request, ledger, replan_evidence)
        return OrchestrationRun(proposal, ledger.calls, tuple(attempts))

    async def _visit(
        self,
        request: OrchestrationRequest,
        ledger: _Ledger,
        replan_evidence: ReplanEvidence | None,
    ) -> tuple[object, list[OrchestrationAttempt]]:
        result = await ledger.call(request, replan_evidence)
        attempts = [
            OrchestrationAttempt(
                request.orchestration_attempt_id,
                request.parent_attempt_id,
                request.root_attempt_id or request.orchestration_attempt_id,
                request.depth,
                result.kind,
            )
        ]
        if result.kind is OrchestrationResultKind.DIRECT:
            if result.proposal is None:
                raise DecompositionError("Direct orchestration proposal is empty")
            return result.proposal, attempts
        if request.depth >= self._policy.max_depth:
            raise DecompositionError("Decomposition depth limit exceeded")
        if len(result.subproblems) > self._policy.max_children:
            raise DecompositionError("Decomposition child limit exceeded")
        ledger.register_children(request, result.subproblems)
        summaries: list[DecompositionSummary] = []
        for child in result.subproblems:
            child_request = OrchestrationRequest.create(
                child.objective,
                request.assumptions + child.assumptions,
                request.constraints + child.constraints,
                request.requirements,
                parent_attempt_id=request.orchestration_attempt_id,
                root_attempt_id=request.root_attempt_id,
                depth=request.depth + 1,
            )
            proposal, child_attempts = await self._visit(child_request, ledger, None)
            attempts.extend(child_attempts)
            summaries.append(
                DecompositionSummary(
                    child_request.orchestration_attempt_id,
                    child.objective,
                    "direct_proposal",
                    ("bounded_child_proposal_available",),
                )
            )
            del proposal
        synthesis = OrchestrationRequest.create(
            request.goal,
            request.assumptions,
            request.constraints,
            request.requirements,
            parent_attempt_id=request.orchestration_attempt_id,
            root_attempt_id=request.root_attempt_id,
            depth=request.depth,
            decomposition_context=tuple(summaries),
        )
        final, final_attempts = await self._visit_direct(synthesis, ledger)
        attempts.extend(final_attempts)
        return final, attempts

    async def _visit_direct(
        self, request: OrchestrationRequest, ledger: _Ledger
    ) -> tuple[object, list[OrchestrationAttempt]]:
        result = await ledger.call(request, None)
        if result.kind is not OrchestrationResultKind.DIRECT or result.proposal is None:
            raise DecompositionError("Final synthesis must be one direct executable proposal")
        return result.proposal, [
            OrchestrationAttempt(
                request.orchestration_attempt_id,
                request.parent_attempt_id,
                request.root_attempt_id or request.orchestration_attempt_id,
                request.depth,
                result.kind,
            )
        ]


class _Ledger:
    def __init__(
        self,
        advisor: OrchestrationAdvisor,
        policy: DecompositionPolicy,
        max_model_calls: int,
        cancellation: asyncio.Event | None,
        deadline: datetime | None,
        clock: Callable[[], datetime] | None,
        attempt_store: OrchestrationAttemptStore | None,
        task_id: UUID | None,
    ) -> None:
        self._advisor = advisor
        self.policy = policy
        self.max_model_calls = min(policy.max_model_calls, max_model_calls)
        self.cancellation = cancellation
        self.deadline = deadline
        self.clock = clock or (lambda: datetime.now(UTC))
        self.calls = 0
        self.nodes = 0
        self._fingerprints: set[str] = set()
        self._attempt_store = attempt_store
        self._task_id = task_id

    def register_root(self, request: OrchestrationRequest) -> None:
        self.nodes = 1
        self._fingerprints.add(self._fingerprint(request.goal, request.constraints))

    def register_children(
        self, parent: OrchestrationRequest, children: tuple[DecompositionSubproblem, ...]
    ) -> None:
        if not children:
            raise DecompositionError("Decomposition must contain at least one child")
        if self.nodes + len(children) > self.policy.max_nodes:
            raise DecompositionError("Decomposition node limit exceeded")
        fingerprints: list[str] = []
        for child in children:
            fingerprint = self._fingerprint(child.objective, parent.constraints + child.constraints)
            if fingerprint in self._fingerprints or fingerprint in fingerprints:
                raise DecompositionError("Duplicate or cyclic decomposition subproblem")
            fingerprints.append(fingerprint)
        self._fingerprints.update(fingerprints)
        self.nodes += len(children)

    async def call(
        self, request: OrchestrationRequest, evidence: ReplanEvidence | None
    ) -> OrchestrationResult:
        if self.cancellation is not None and self.cancellation.is_set():
            raise DecompositionError("Planning was cancelled")
        if self.deadline is not None:
            current = self.clock()
            if current >= self.deadline:
                raise DecompositionError("Planning deadline expired")
        if self.calls >= self.max_model_calls:
            raise DecompositionError("Orchestration model-call budget exhausted")
        self.calls += 1
        started = DurableOrchestrationAttempt(
            request.orchestration_attempt_id,
            self._task_id,
            request.parent_attempt_id,
            request.root_attempt_id or request.orchestration_attempt_id,
            request.depth,
            OrchestrationAttemptStatus.STARTED,
            self.clock(),
        )
        if self._attempt_store is not None:
            self._attempt_store.begin_orchestration_attempt(started)
        try:
            if evidence is None:
                result = await self._advisor.propose_orchestration(request)
            else:
                result = await self._advisor.replan_orchestration(request, evidence)
        except Exception:
            if self._attempt_store is not None:
                self._attempt_store.finish_orchestration_attempt(
                    request.orchestration_attempt_id,
                    status=OrchestrationAttemptStatus.FAILED,
                    diagnostic_code="advisor_failed",
                    finished_at=self.clock(),
                )
            raise
        if not isinstance(result, OrchestrationResult):
            raise DecompositionError("Orchestration advisor returned malformed result")
        if result.orchestration_attempt_id != request.orchestration_attempt_id:
            raise DecompositionError("Orchestration attempt identity mismatch")
        if result.failure is not None:
            if self._attempt_store is not None:
                self._attempt_store.finish_orchestration_attempt(
                    request.orchestration_attempt_id,
                    status=OrchestrationAttemptStatus.FAILED,
                    diagnostic_code="advisor_rejected",
                    finished_at=self.clock(),
                )
            raise DecompositionError(result.failure)
        if self._attempt_store is not None:
            self._attempt_store.finish_orchestration_attempt(
                request.orchestration_attempt_id,
                status=OrchestrationAttemptStatus.COMPLETED,
                kind=result.kind,
                route_decision_id=result.route_decision_id,
                finished_at=self.clock(),
            )
        return result

    @staticmethod
    def _fingerprint(objective: str, constraints: tuple[str, ...]) -> str:
        payload = json.dumps(
            {"objective": " ".join(objective.split()).casefold(), "constraints": constraints},
            sort_keys=True,
            separators=(",", ":"),
        )
        return hashlib.sha256(payload.encode()).hexdigest()


__all__ = [
    "DecompositionError",
    "DecompositionPolicy",
    "DecompositionSubproblem",
    "DecompositionSummary",
    "DurableOrchestrationAttempt",
    "OrchestrationAttempt",
    "OrchestrationAttemptStatus",
    "OrchestrationAttemptStore",
    "OrchestrationAdvisor",
    "OrchestrationController",
    "OrchestrationRequest",
    "OrchestrationResult",
    "OrchestrationResultKind",
    "OrchestrationRun",
]
