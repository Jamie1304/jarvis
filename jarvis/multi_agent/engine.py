"""Feature-gated, bounded scheduler for explicit multi-agent task nodes."""

from __future__ import annotations

import asyncio
from abc import ABC, abstractmethod
from collections.abc import Callable
from dataclasses import dataclass, replace
from datetime import UTC, datetime
from time import monotonic
from uuid import UUID

from pydantic import ValidationError

from jarvis.multi_agent.models import (
    AgentInvocation,
    AgentNodeStatus,
    AgentResult,
    AgentResultStatus,
    DelegatedTaskNode,
    DelegationGraph,
    EvidenceReference,
    ExecutionMode,
    OrchestrationRequest,
    OrchestrationResult,
    OrchestrationStatus,
    ResourceUsage,
)
from jarvis.multi_agent.registry import AgentRegistry, AgentRegistryError
from jarvis.multi_agent.validation import (
    DelegationValidationError,
    DelegationValidationReason,
    DelegationValidator,
)
from jarvis.resources import (
    ReservationReleaseReason,
    ResourceGovernor,
    ResourcePriority,
)
from jarvis.resources import (
    ResourceBudget as GovernorBudget,
)


def _now() -> datetime:
    return datetime.now(UTC)


@dataclass(frozen=True, slots=True)
class SingleAgentOutcome:
    status: OrchestrationStatus
    evidence: tuple[EvidenceReference, ...]
    usage: ResourceUsage
    reason_code: str
    reason: str


class SingleAgentExecutor(ABC):
    """Adapter for the unchanged Phase 15 single-agent path."""

    @abstractmethod
    async def execute(
        self, request: OrchestrationRequest, cancellation: asyncio.Event
    ) -> SingleAgentOutcome: ...


@dataclass(frozen=True, slots=True)
class MultiAgentGoalVerification:
    succeeded: bool
    reason: str


class MultiAgentGoalVerifier(ABC):
    @abstractmethod
    async def verify(
        self,
        request: OrchestrationRequest,
        graph: DelegationGraph,
        evidence: tuple[EvidenceReference, ...],
    ) -> MultiAgentGoalVerification: ...


class EvidenceMultiAgentGoalVerifier(MultiAgentGoalVerifier):
    """Require every trusted request-level completion evidence reference."""

    async def verify(
        self,
        request: OrchestrationRequest,
        graph: DelegationGraph,
        evidence: tuple[EvidenceReference, ...],
    ) -> MultiAgentGoalVerification:
        del graph
        observed = {item.reference_id for item in evidence}
        missing = tuple(item for item in request.completion_evidence if item not in observed)
        return MultiAgentGoalVerification(
            not missing,
            "Goal completion evidence observed"
            if not missing
            else "Required goal completion evidence was missing",
        )


class MultiAgentCoordinator:
    """The sole delegation authority; workers receive no recursive spawn interface."""

    _FALLBACK_REASONS = frozenset(
        {
            DelegationValidationReason.UNKNOWN_AGENT,
            DelegationValidationReason.UNAVAILABLE_AGENT,
        }
    )

    def __init__(
        self,
        *,
        enabled: bool,
        registry: AgentRegistry,
        validator: DelegationValidator,
        single_agent: SingleAgentExecutor,
        goal_verifier: MultiAgentGoalVerifier,
        clock: Callable[[], datetime] = _now,
        monotonic_clock: Callable[[], float] = monotonic,
        resource_governor: ResourceGovernor | None = None,
    ) -> None:
        self._enabled = enabled
        self._registry = registry
        self._validator = validator
        self._single_agent = single_agent
        self._goal_verifier = goal_verifier
        self._clock = clock
        self._monotonic = monotonic_clock
        self._resource_governor = resource_governor

    @property
    def enabled(self) -> bool:
        return self._enabled

    async def execute(
        self,
        request: OrchestrationRequest,
        proposal: object | None,
        *,
        cancellation: asyncio.Event | None = None,
    ) -> OrchestrationResult:
        cancellation = cancellation or asyncio.Event()
        started_at = self._clock()
        if not self._enabled:
            return await self._fallback(request, cancellation, started_at, "multi_agent_disabled")
        if proposal is None:
            return await self._fallback(
                request, cancellation, started_at, "delegation_not_proposed"
            )
        try:
            graph = self._validator.validate(proposal, request)
        except DelegationValidationError as error:
            if error.reason in self._FALLBACK_REASONS:
                return await self._fallback(request, cancellation, started_at, error.reason.value)
            return self._result(
                request,
                ExecutionMode.MULTI_AGENT,
                OrchestrationStatus.BUDGET_EXHAUSTED
                if error.reason is DelegationValidationReason.BUDGET_EXHAUSTED
                else OrchestrationStatus.REJECTED,
                (),
                (),
                ResourceUsage(),
                started_at,
                error.reason.value,
                str(error),
            )
        if not self._validator.has_concrete_advantage(graph):
            return await self._fallback(
                request,
                cancellation,
                started_at,
                DelegationValidationReason.NO_CONCRETE_ADVANTAGE.value,
            )
        return await self._execute_graph(request, graph, cancellation, started_at)

    async def _fallback(
        self,
        request: OrchestrationRequest,
        cancellation: asyncio.Event,
        started_at: datetime,
        trigger: str,
    ) -> OrchestrationResult:
        outcome = await self._single_agent.execute(request, cancellation)
        return self._result(
            request,
            ExecutionMode.SINGLE_AGENT,
            outcome.status,
            (),
            outcome.evidence,
            outcome.usage,
            started_at,
            f"single_agent_fallback:{trigger}:{outcome.reason_code}",
            outcome.reason,
        )

    async def _execute_graph(
        self,
        request: OrchestrationRequest,
        graph: DelegationGraph,
        cancellation: asyncio.Event,
        started_at: datetime,
    ) -> OrchestrationResult:
        nodes = {node.node_id: node for node in graph.nodes}
        running: dict[asyncio.Task[AgentResult], UUID] = {}
        reservations: dict[asyncio.Task[AgentResult], UUID] = {}
        deadline = self._monotonic() + self._validator.limits.total_budget.max_elapsed_seconds
        reason_code = "multi_agent_completed"
        reason = "All delegated task nodes completed"

        while True:
            if cancellation.is_set():
                await self._stop_running(running)
                self._release_reservations(reservations, ReservationReleaseReason.CANCEL)
                nodes = self._cancel_nodes(nodes)
                return self._graph_result(
                    request,
                    nodes,
                    started_at,
                    OrchestrationStatus.CANCELLED,
                    "multi_agent_cancelled",
                    "Cancellation propagated to every delegated task",
                )
            if self._monotonic() >= deadline:
                await self._stop_running(running)
                self._release_reservations(reservations, ReservationReleaseReason.TIMEOUT)
                nodes = self._timeout_nodes(nodes)
                return self._graph_result(
                    request,
                    nodes,
                    started_at,
                    OrchestrationStatus.FAILED,
                    "orchestration_timeout",
                    "The multi-agent orchestration timeout expired",
                )

            nodes = self._block_failed_dependents(nodes)
            capacity = self._validator.limits.max_concurrency - len(running)
            resource_blocked = False
            if capacity > 0:
                ready = sorted(
                    (
                        node
                        for node in nodes.values()
                        if node.status is AgentNodeStatus.QUEUED
                        and self._dependencies_succeeded(node, nodes)
                    ),
                    key=lambda node: node.key,
                )
                for node in ready[:capacity]:
                    reservation_id = None
                    if self._resource_governor is not None:
                        decision = self._resource_governor.reserve(
                            f"multi-agent.{node.node_id}",
                            ResourcePriority.USER_REQUESTED,
                            GovernorBudget(
                                concurrency=1,
                                duration_seconds=max(
                                    0.001,
                                    min(
                                        300.0,
                                        self._validator.limits.total_budget.max_elapsed_seconds,
                                    ),
                                ),
                            ),
                        )
                        if not decision.allowed or decision.reservation_id is None:
                            resource_blocked = True
                            continue
                        reservation_id = decision.reservation_id
                    running_node = replace(node, status=AgentNodeStatus.RUNNING)
                    nodes[node.node_id] = running_node
                    task = asyncio.create_task(
                        self._execute_node(request, running_node, cancellation)
                    )
                    running[task] = node.node_id
                    if reservation_id is not None:
                        reservations[task] = reservation_id

            unfinished = tuple(
                node
                for node in nodes.values()
                if node.status in {AgentNodeStatus.QUEUED, AgentNodeStatus.RUNNING}
            )
            if not unfinished:
                break
            if not running:
                if resource_blocked:
                    await asyncio.sleep(min(0.05, max(0.0, deadline - self._monotonic())))
                    continue
                nodes = {
                    node_id: (
                        replace(
                            node,
                            status=AgentNodeStatus.BLOCKED,
                            error_code="scheduler_deadlock",
                            error_message="No executable node remained in the task graph",
                        )
                        if node.status is AgentNodeStatus.QUEUED
                        else node
                    )
                    for node_id, node in nodes.items()
                }
                reason_code = "scheduler_deadlock"
                reason = "The validated graph made no execution progress"
                break

            remaining = max(0.0, deadline - self._monotonic())
            done, _pending = await asyncio.wait(
                tuple(running),
                timeout=min(0.05, remaining),
                return_when=asyncio.FIRST_COMPLETED,
            )
            for task in done:
                node_id = running.pop(task)
                reservation_id = reservations.pop(task, None)
                try:
                    result = task.result()
                except asyncio.CancelledError:
                    if reservation_id is not None and self._resource_governor is not None:
                        self._resource_governor.release(
                            reservation_id, ReservationReleaseReason.CANCEL
                        )
                    raise
                except Exception:
                    if reservation_id is not None and self._resource_governor is not None:
                        self._resource_governor.release(
                            reservation_id, ReservationReleaseReason.CRASH
                        )
                    result = self._failure("worker_crashed", "Delegated worker crashed")
                else:
                    if reservation_id is not None and self._resource_governor is not None:
                        self._resource_governor.release(
                            reservation_id, ReservationReleaseReason.COMPLETE
                        )
                nodes[node_id] = self._complete_node(nodes[node_id], result)

        statuses = {node.status for node in nodes.values()}
        if AgentNodeStatus.BUDGET_EXHAUSTED in statuses:
            status = OrchestrationStatus.BUDGET_EXHAUSTED
            reason_code = "agent_budget_exhausted"
            reason = "A delegated agent exceeded its reserved resource budget"
        elif statuses == {AgentNodeStatus.SUCCEEDED}:
            status = OrchestrationStatus.COMPLETED
        elif AgentNodeStatus.SUCCEEDED in statuses or AgentNodeStatus.PARTIAL in statuses:
            status = OrchestrationStatus.PARTIAL
            reason_code = "partial_delegation_result"
            reason = "Independent work completed but at least one delegated node failed"
        else:
            status = OrchestrationStatus.FAILED
            if reason_code == "multi_agent_completed":
                reason_code = "delegated_task_failed"
                reason = "Delegated task execution failed"
        if status is OrchestrationStatus.COMPLETED:
            evidence = self._collect_evidence(nodes)
            try:
                verification = await self._goal_verifier.verify(request, graph, evidence)
            except Exception as error:
                verification = MultiAgentGoalVerification(
                    False,
                    f"Goal verifier failed ({type(error).__name__})",
                )
            if not verification.succeeded:
                status = OrchestrationStatus.FAILED
                reason_code = "goal_verification_failed"
                reason = verification.reason
        return self._graph_result(request, nodes, started_at, status, reason_code, reason)

    def _release_reservations(
        self,
        reservations: dict[asyncio.Task[AgentResult], UUID],
        reason: ReservationReleaseReason,
    ) -> None:
        if self._resource_governor is None:
            reservations.clear()
            return
        for reservation_id in tuple(reservations.values()):
            self._resource_governor.release(reservation_id, reason)
        reservations.clear()

    async def _execute_node(
        self,
        request: OrchestrationRequest,
        node: DelegatedTaskNode,
        cancellation: asyncio.Event,
    ) -> AgentResult:
        try:
            worker = self._registry.get(node.agent_id)
            contract = self._registry.inspect(node.agent_id)
        except AgentRegistryError as error:
            return self._failure(
                "agent_contract_changed",
                f"Registered agent integrity check failed ({type(error).__name__})",
            )
        try:
            validated_input = contract.accepted_task_schema.model_validate_json(node.input_json)
        except ValidationError:
            return self._failure("owned_input_invalid", "Owned agent input became invalid")
        context_by_key = {item.key: item for item in request.context}
        evidence_by_id = {item.reference_id: item for item in request.evidence}
        profile = contract.profile
        if profile is None:
            return self._failure("agent_profile_missing", "Registered agent profile is missing")
        invocation = AgentInvocation(
            request.task_id,
            node.node_id,
            node.objective,
            validated_input,
            tuple(context_by_key[key] for key in node.context_keys),
            tuple(evidence_by_id[key] for key in node.evidence_references),
            node.required_tools,
            node.required_capabilities,
            node.required_permissions,
            node.budget,
            profile,
            contract.model_policy,
            node.filesystem_scope,
            node.network_scope,
            node.data_ceiling,
            contract.delegation_policy,
            contract.result_schema,
            frozenset(node.required_tools),
            frozenset(node.required_capabilities),
        )
        try:
            result = await asyncio.wait_for(
                worker.execute(invocation, cancellation), timeout=node.timeout_seconds
            )
        except TimeoutError:
            return self._failure("agent_timeout", "Delegated agent exceeded its node timeout")
        except asyncio.CancelledError:
            return AgentResult(
                AgentResultStatus.CANCELLED,
                "{}",
                (),
                ResourceUsage(),
                "agent_cancelled",
                "Delegated agent was cancelled",
            )
        except Exception as error:
            return self._failure(
                "agent_failure",
                f"Delegated agent failed ({type(error).__name__})",
            )
        if not isinstance(result, AgentResult):
            return self._failure(
                "malformed_agent_result", "Delegated agent returned an unknown result type"
            )
        if any(
            evidence.contains_secret or not node.data_ceiling.allows(evidence.classification)
            for evidence in result.evidence
        ):
            return self._failure(
                "agent_result_scope_violation",
                "Delegated agent returned secret or out-of-ceiling evidence",
            )
        if not result.usage.within(node.budget):
            return AgentResult(
                AgentResultStatus.FAILED,
                "{}",
                result.evidence,
                result.usage,
                "agent_budget_exhausted",
                "Delegated agent exceeded its reserved resource budget",
            )
        if result.status in {AgentResultStatus.SUCCEEDED, AgentResultStatus.PARTIAL}:
            try:
                contract.result_schema.model_validate_json(result.output_json)
            except ValidationError:
                return self._failure(
                    "malformed_agent_result",
                    "Delegated output does not match the registered result schema",
                )
        return result

    @staticmethod
    def _failure(code: str, message: str) -> AgentResult:
        return AgentResult(
            AgentResultStatus.FAILED,
            "{}",
            (),
            ResourceUsage(),
            code,
            message,
        )

    @staticmethod
    def _complete_node(node: DelegatedTaskNode, result: AgentResult) -> DelegatedTaskNode:
        if result.error_code == "agent_timeout":
            status = AgentNodeStatus.TIMED_OUT
        elif result.error_code == "agent_budget_exhausted":
            status = AgentNodeStatus.BUDGET_EXHAUSTED
        else:
            status = {
                AgentResultStatus.SUCCEEDED: AgentNodeStatus.SUCCEEDED,
                AgentResultStatus.PARTIAL: AgentNodeStatus.PARTIAL,
                AgentResultStatus.FAILED: AgentNodeStatus.FAILED,
                AgentResultStatus.CANCELLED: AgentNodeStatus.CANCELLED,
            }[result.status]
        return replace(
            node,
            status=status,
            result=result,
            error_code=result.error_code,
            error_message=result.error_message,
        )

    @staticmethod
    def _dependencies_succeeded(
        node: DelegatedTaskNode, nodes: dict[UUID, DelegatedTaskNode]
    ) -> bool:
        return all(
            nodes[dependency].status is AgentNodeStatus.SUCCEEDED
            for dependency in node.dependencies
        )

    @staticmethod
    def _block_failed_dependents(
        nodes: dict[UUID, DelegatedTaskNode],
    ) -> dict[UUID, DelegatedTaskNode]:
        blocked_statuses = {
            AgentNodeStatus.PARTIAL,
            AgentNodeStatus.FAILED,
            AgentNodeStatus.TIMED_OUT,
            AgentNodeStatus.CANCELLED,
            AgentNodeStatus.BLOCKED,
            AgentNodeStatus.BUDGET_EXHAUSTED,
        }
        changed = True
        while changed:
            changed = False
            for node_id, node in tuple(nodes.items()):
                if node.status is AgentNodeStatus.QUEUED and any(
                    nodes[dependency].status in blocked_statuses for dependency in node.dependencies
                ):
                    nodes[node_id] = replace(
                        node,
                        status=AgentNodeStatus.BLOCKED,
                        error_code="dependency_failed",
                        error_message="A required delegated dependency did not succeed",
                    )
                    changed = True
        return nodes

    @staticmethod
    async def _stop_running(running: dict[asyncio.Task[AgentResult], UUID]) -> None:
        for task in running:
            task.cancel()
        if running:
            await asyncio.gather(*running, return_exceptions=True)
        running.clear()

    @staticmethod
    def _cancel_nodes(
        nodes: dict[UUID, DelegatedTaskNode],
    ) -> dict[UUID, DelegatedTaskNode]:
        return {
            node_id: (
                replace(
                    node,
                    status=(
                        AgentNodeStatus.BLOCKED if node.dependencies else AgentNodeStatus.CANCELLED
                    ),
                    error_code="task_cancelled",
                    error_message="Parent task cancellation was requested",
                )
                if node.status in {AgentNodeStatus.QUEUED, AgentNodeStatus.RUNNING}
                else node
            )
            for node_id, node in nodes.items()
        }

    @staticmethod
    def _timeout_nodes(
        nodes: dict[UUID, DelegatedTaskNode],
    ) -> dict[UUID, DelegatedTaskNode]:
        return {
            node_id: (
                replace(
                    node,
                    status=(
                        AgentNodeStatus.BLOCKED if node.dependencies else AgentNodeStatus.TIMED_OUT
                    ),
                    error_code="orchestration_timeout",
                    error_message="The orchestration timeout expired",
                )
                if node.status in {AgentNodeStatus.QUEUED, AgentNodeStatus.RUNNING}
                else node
            )
            for node_id, node in nodes.items()
        }

    def _graph_result(
        self,
        request: OrchestrationRequest,
        nodes: dict[UUID, DelegatedTaskNode],
        started_at: datetime,
        status: OrchestrationStatus,
        reason_code: str,
        reason: str,
    ) -> OrchestrationResult:
        ordered = tuple(sorted(nodes.values(), key=lambda node: node.key))
        evidence = self._collect_evidence(nodes)
        usage = ResourceUsage()
        for node in ordered:
            if node.result is not None:
                usage = usage.plus(node.result.usage)
        return self._result(
            request,
            ExecutionMode.MULTI_AGENT,
            status,
            ordered,
            evidence,
            usage,
            started_at,
            reason_code,
            reason,
        )

    @staticmethod
    def _collect_evidence(
        nodes: dict[UUID, DelegatedTaskNode],
    ) -> tuple[EvidenceReference, ...]:
        return tuple(
            item
            for node in sorted(nodes.values(), key=lambda value: value.key)
            if node.result
            for item in node.result.evidence
        )

    def _result(
        self,
        request: OrchestrationRequest,
        mode: ExecutionMode,
        status: OrchestrationStatus,
        nodes: tuple[DelegatedTaskNode, ...],
        evidence: tuple[EvidenceReference, ...],
        usage: ResourceUsage,
        started_at: datetime,
        reason_code: str,
        reason: str,
    ) -> OrchestrationResult:
        return OrchestrationResult(
            request.task_id,
            mode,
            status,
            nodes,
            evidence,
            usage,
            started_at,
            self._clock(),
            reason_code,
            reason,
        )
