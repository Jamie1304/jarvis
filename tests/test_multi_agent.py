"""Deterministic security and lifecycle tests for optional multi-agent orchestration."""

from __future__ import annotations

import asyncio
import copy
from dataclasses import dataclass, replace
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any, cast
from uuid import uuid4

import pytest
from jarvis.multi_agent import (
    AgentContract,
    AgentInvocation,
    AgentNodeStatus,
    AgentRegistry,
    AgentRegistryError,
    AgentResult,
    AgentResultStatus,
    AgentType,
    AgentWorker,
    ContextItem,
    DataCeiling,
    DataClassification,
    DelegatedTaskNode,
    DelegationGraph,
    DelegationLimits,
    DelegationValidationError,
    DelegationValidationReason,
    DelegationValidator,
    EvidenceMultiAgentGoalVerifier,
    EvidenceReference,
    ExecutionMode,
    FilesystemScope,
    MultiAgentCoordinator,
    NetworkScope,
    OrchestrationRequest,
    OrchestrationResult,
    OrchestrationStatus,
    ResourceBudget,
    ResourceUsage,
    SingleAgentExecutor,
    SingleAgentOutcome,
    WorkerDelegationPolicy,
    WorkerModelPolicy,
    WorkerProfile,
)
from jarvis.permissions.models import Permission
from jarvis.resources import ResourceGovernor, ResourceSnapshot
from pydantic import BaseModel, ConfigDict


class _TaskInput(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)

    topic: str


class _TaskOutput(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)

    value: str


@dataclass
class _ConcurrencyProbe:
    active: int = 0
    maximum: int = 0


class _Worker(AgentWorker):
    def __init__(
        self,
        agent_id: str,
        agent_type: AgentType,
        *,
        delay: float = 0,
        status: AgentResultStatus = AgentResultStatus.SUCCEEDED,
        usage: ResourceUsage | None = None,
        permissions: frozenset[Permission] = frozenset(),
        tools: frozenset[str] = frozenset(),
        capabilities: frozenset[str] = frozenset({"analyze"}),
        available: bool = True,
        probe: _ConcurrencyProbe | None = None,
        log: list[str] | None = None,
        profile: WorkerProfile | None = None,
        model_policy: WorkerModelPolicy | None = None,
        filesystem_scope: FilesystemScope | None = None,
        network_scope: NetworkScope | None = None,
        data_ceiling: DataCeiling = DataCeiling.INTERNAL,
        delegation_policy: WorkerDelegationPolicy | None = None,
    ) -> None:
        self._contract = AgentContract(
            agent_id=agent_id,
            agent_type=agent_type,
            responsibility=f"Fixture {agent_type.value}",
            accepted_task_schema=_TaskInput,
            allowed_tools=tools,
            allowed_capabilities=capabilities,
            allowed_permissions=permissions,
            resource_budget=ResourceBudget(4, 2_000, 20, 2),
            result_schema=_TaskOutput,
            available=available,
            profile=profile,
            model_policy=model_policy or WorkerModelPolicy(),
            filesystem_scope=filesystem_scope or FilesystemScope(),
            network_scope=network_scope or NetworkScope(),
            data_ceiling=data_ceiling,
            delegation_policy=delegation_policy or WorkerDelegationPolicy(),
        )
        self.delay = delay
        self.status = status
        self.usage = usage or ResourceUsage(model_calls=1, tokens=10, cost_units=1)
        self.probe = probe
        self.log = log
        self.invocations: list[AgentInvocation] = []
        self.started = asyncio.Event()

    @property
    def contract(self) -> AgentContract:
        return self._contract

    async def execute(
        self, invocation: AgentInvocation, cancellation: asyncio.Event
    ) -> AgentResult:
        self.invocations.append(invocation)
        self.started.set()
        if self.log is not None:
            self.log.append(f"start:{self.contract.agent_id}")
        if self.probe is not None:
            self.probe.active += 1
            self.probe.maximum = max(self.probe.maximum, self.probe.active)
        try:
            if self.delay:
                await asyncio.sleep(self.delay)
            if cancellation.is_set():
                return AgentResult(
                    AgentResultStatus.CANCELLED,
                    "{}",
                    (),
                    self.usage,
                    "cancelled",
                    "Cancelled",
                )
            if self.status is AgentResultStatus.FAILED:
                return AgentResult(
                    self.status,
                    "{}",
                    (),
                    self.usage,
                    "fixture_failure",
                    "Fixture worker failed",
                )
            return AgentResult(
                self.status,
                _TaskOutput(value=self.contract.agent_id).model_dump_json(),
                (_evidence(f"{self.contract.agent_id}-evidence"),),
                self.usage,
            )
        finally:
            if self.probe is not None:
                self.probe.active -= 1
            if self.log is not None:
                self.log.append(f"end:{self.contract.agent_id}")


class _Fallback(SingleAgentExecutor):
    def __init__(self) -> None:
        self.calls: list[OrchestrationRequest] = []

    async def execute(
        self, request: OrchestrationRequest, cancellation: asyncio.Event
    ) -> SingleAgentOutcome:
        self.calls.append(request)
        if cancellation.is_set():
            return SingleAgentOutcome(
                OrchestrationStatus.CANCELLED,
                (),
                ResourceUsage(),
                "cancelled",
                "Single-agent task cancelled",
            )
        return SingleAgentOutcome(
            OrchestrationStatus.COMPLETED,
            (_evidence("single-ready"),),
            ResourceUsage(model_calls=1, tokens=20, cost_units=1),
            "single_completed",
            "Single-agent fallback completed",
        )


class _RaisingWorker(_Worker):
    async def execute(
        self, invocation: AgentInvocation, cancellation: asyncio.Event
    ) -> AgentResult:
        del invocation, cancellation
        raise RuntimeError("untrusted provider failure")


class _UnknownResultWorker(_Worker):
    async def execute(
        self, invocation: AgentInvocation, cancellation: asyncio.Event
    ) -> AgentResult:
        del invocation, cancellation
        return cast(AgentResult, object())


class _MalformedOutputWorker(_Worker):
    async def execute(
        self, invocation: AgentInvocation, cancellation: asyncio.Event
    ) -> AgentResult:
        del invocation, cancellation
        return AgentResult(
            AgentResultStatus.SUCCEEDED,
            '{"unexpected":"field"}',
            (),
            ResourceUsage(),
        )


class _SelfMutatingWorker(_Worker):
    async def execute(
        self, invocation: AgentInvocation, cancellation: asyncio.Event
    ) -> AgentResult:
        result = await super().execute(invocation, cancellation)
        self._contract = replace(self._contract, responsibility="Changed after binding")
        return result


def _evidence(reference_id: str) -> EvidenceReference:
    return EvidenceReference(reference_id, f"Evidence for {reference_id}", "a" * 64)


def _request(
    *,
    permissions: frozenset[Permission] = frozenset(),
    completion_evidence: tuple[str, ...] = ("coding-evidence",),
    context: tuple[ContextItem, ...] | None = None,
    filesystem_scope: FilesystemScope | None = None,
    network_scope: NetworkScope | None = None,
    model_policy: WorkerModelPolicy | None = None,
    data_ceiling: DataCeiling = DataCeiling.INTERNAL,
    delegation_policy: WorkerDelegationPolicy | None = None,
) -> OrchestrationRequest:
    return OrchestrationRequest(
        task_id=uuid4(),
        goal="Prepare a reviewed implementation brief",
        context=context
        or (
            ContextItem("objective", "Implement the requested feature"),
            ContextItem("constraint", "Do not contact external systems"),
            ContextItem("private-extra", "Must not be copied to unrelated workers"),
        ),
        evidence=(_evidence("architecture"), _evidence("test-report")),
        allowed_tools=frozenset({"repository.read", "computer.focus"}),
        allowed_capabilities=frozenset({"analyze", "modify", "focus"}),
        allowed_permissions=permissions,
        completion_evidence=completion_evidence,
        filesystem_scope=filesystem_scope or FilesystemScope(),
        network_scope=network_scope or NetworkScope(),
        model_policy=model_policy or WorkerModelPolicy(),
        data_ceiling=data_ceiling,
        delegation_policy=delegation_policy or WorkerDelegationPolicy(),
    )


def _budget(
    *, calls: int = 1, tokens: int = 100, cost: int = 1, elapsed: float = 1
) -> dict[str, object]:
    return {
        "max_model_calls": calls,
        "max_tokens": tokens,
        "max_cost_units": cost,
        "max_elapsed_seconds": elapsed,
    }


def _node(
    key: str,
    agent_id: str,
    *,
    dependencies: list[str] | None = None,
    permissions: list[str] | None = None,
    tools: list[str] | None = None,
    capabilities: list[str] | None = None,
    context: list[str] | None = None,
    evidence: list[str] | None = None,
    filesystem_roots: list[str] | None = None,
    network_origins: list[str] | None = None,
    data_ceiling: str = DataCeiling.PUBLIC.value,
    budget: dict[str, object] | None = None,
    timeout: float = 0.5,
) -> dict[str, object]:
    return {
        "key": key,
        "agent_id": agent_id,
        "objective": f"Complete {key}",
        "input": {"topic": key},
        "dependencies": dependencies or [],
        "required_tools": tools or [],
        "required_capabilities": capabilities or ["analyze"],
        "required_permissions": permissions or [],
        "context_keys": context or ["objective"],
        "evidence_references": evidence or ["architecture"],
        "filesystem_roots": filesystem_roots or [],
        "network_origins": network_origins or [],
        "data_ceiling": data_ceiling,
        "budget": budget or _budget(),
        "timeout_seconds": timeout,
    }


def _proposal(*nodes: dict[str, object]) -> dict[str, object]:
    return {
        "goal": "Prepare a reviewed implementation brief",
        "rationale": "Independent research and implementation analysis reduce latency",
        "nodes": list(nodes),
    }


def _coordinator(
    workers: tuple[AgentWorker, ...],
    *,
    enabled: bool = True,
    concurrency: int = 3,
    total_budget: ResourceBudget | None = None,
    resource_governor: ResourceGovernor | None = None,
) -> tuple[MultiAgentCoordinator, _Fallback, DelegationValidator]:
    registry = AgentRegistry(workers)
    validator = DelegationValidator(
        registry,
        DelegationLimits(
            max_nodes=8,
            max_concurrency=concurrency,
            total_budget=total_budget or ResourceBudget(10, 10_000, 100, 2),
        ),
    )
    fallback = _Fallback()
    return (
        MultiAgentCoordinator(
            enabled=enabled,
            registry=registry,
            validator=validator,
            single_agent=fallback,
            goal_verifier=EvidenceMultiAgentGoalVerifier(),
            resource_governor=resource_governor,
        ),
        fallback,
        validator,
    )


@pytest.mark.asyncio
async def test_scheduler_releases_shared_resource_reservation() -> None:
    class Telemetry:
        def snapshot(self) -> ResourceSnapshot:
            return ResourceSnapshot(
                datetime.now(UTC),
                cpu_cores=8,
                ram_total_bytes=16_000,
                ram_available_bytes=12_000,
                disk_free_bytes=10_000_000_000,
            )

    governor = ResourceGovernor(Telemetry())
    coordinator, _fallback, _validator = _coordinator(
        (
            _Worker("research", AgentType.RESEARCH),
            _Worker("coding", AgentType.CODING, capabilities=frozenset({"modify"})),
        ),
        resource_governor=governor,
    )
    result = await coordinator.execute(
        _request(completion_evidence=("research-evidence", "coding-evidence")),
        _proposal(
            _node("research", "research", evidence=["architecture"]),
            _node("coding", "coding", capabilities=["modify"], evidence=["test-report"]),
        ),
    )
    assert result.status is OrchestrationStatus.COMPLETED
    assert governor.reservations()
    assert all(item.status.value == "completed" for item in governor.reservations())


@pytest.mark.asyncio
async def test_correct_delegation_passes_only_selected_context_and_evidence() -> None:
    research = _Worker("research", AgentType.RESEARCH)
    coding = _Worker("coding", AgentType.CODING, capabilities=frozenset({"modify"}))
    coordinator, fallback, _validator = _coordinator((research, coding))
    proposal = _proposal(
        _node("research", "research", context=["objective"], evidence=["architecture"]),
        _node(
            "coding",
            "coding",
            capabilities=["modify"],
            context=["constraint"],
            evidence=["test-report"],
        ),
    )

    result = await coordinator.execute(_request(), proposal)

    assert result.mode is ExecutionMode.MULTI_AGENT
    assert result.status is OrchestrationStatus.COMPLETED
    assert not fallback.calls
    assert [item.key for item in research.invocations[0].context] == ["objective"]
    assert [item.reference_id for item in research.invocations[0].evidence] == ["architecture"]
    assert [item.key for item in coding.invocations[0].context] == ["constraint"]
    assert not hasattr(research.invocations[0], "delegate")


@pytest.mark.asyncio
async def test_specialist_roles_receive_least_privilege_worker_contract() -> None:
    filesystem = FilesystemScope((r"C:\workspace",))
    network = NetworkScope(("https://api.example.test",))
    model_policy = WorkerModelPolicy(
        frozenset({"local-provider"}), frozenset({"small-model"}), True, 8_000
    )
    parent_model_policy = WorkerModelPolicy(
        frozenset({"local-provider"}), frozenset({"small-model"}), True, 32_000
    )
    profile = WorkerProfile("verification-profile", "Independently inspect completion evidence")
    verification = _Worker(
        "verification",
        AgentType.VERIFICATION,
        profile=profile,
        model_policy=model_policy,
        filesystem_scope=filesystem,
        network_scope=network,
        data_ceiling=DataCeiling.SENSITIVE,
        tools=frozenset({"repository.read", "repository.write"}),
        capabilities=frozenset({"analyze", "modify"}),
    )
    diagnostics = _Worker("diagnostics", AgentType.DIAGNOSTICS)
    coordinator, _fallback, _validator = _coordinator((verification, diagnostics))

    result = await coordinator.execute(
        _request(
            filesystem_scope=filesystem,
            network_scope=network,
            model_policy=parent_model_policy,
            data_ceiling=DataCeiling.SENSITIVE,
            completion_evidence=("diagnostics-evidence",),
        ),
        _proposal(
            _node(
                "verification",
                "verification",
                filesystem_roots=[r"C:\workspace\checks"],
                network_origins=["https://api.example.test"],
                data_ceiling=DataCeiling.SENSITIVE.value,
                tools=["repository.read"],
            ),
            _node("diagnostics", "diagnostics"),
        ),
    )

    assert result.status is OrchestrationStatus.COMPLETED
    invocation = verification.invocations[0]
    assert invocation.profile == profile
    assert invocation.model_policy == model_policy
    assert invocation.filesystem_scope.roots == (r"c:\workspace\checks",)
    assert invocation.network_scope.origins == ("https://api.example.test",)
    assert invocation.data_ceiling is DataCeiling.SENSITIVE
    assert invocation.tool_allowlist == frozenset({"repository.read"})
    assert invocation.capability_allowlist == frozenset({"analyze"})
    assert not invocation.delegation_policy.allow_spawn
    assert invocation.output_schema is _TaskOutput


@pytest.mark.parametrize(
    ("mutation", "reason"),
    (
        ("filesystem", DelegationValidationReason.SCOPE_ESCALATION),
        ("network", DelegationValidationReason.SCOPE_ESCALATION),
        ("data", DelegationValidationReason.DATA_SCOPE_ESCALATION),
        ("model", DelegationValidationReason.SCOPE_ESCALATION),
    ),
)
def test_specialist_scope_and_profile_policy_cannot_escalate(
    mutation: str, reason: DelegationValidationReason
) -> None:
    filesystem = FilesystemScope((r"C:\workspace",))
    network = NetworkScope(("https://api.example.test",))
    policy = WorkerModelPolicy(frozenset({"local"}), frozenset({"small"}), True, 4_000)
    worker = _Worker(
        "research",
        AgentType.RESEARCH,
        model_policy=policy,
        filesystem_scope=filesystem,
        network_scope=network,
        data_ceiling=DataCeiling.SENSITIVE,
    )
    coding = _Worker("coding", AgentType.CODING)
    _coordinator_instance, _fallback, validator = _coordinator((worker, coding))
    proposal = _proposal(_node("research", "research"), _node("coding", "coding"))
    nodes = cast(list[dict[str, object]], proposal["nodes"])
    if mutation == "filesystem":
        nodes[0]["filesystem_roots"] = [r"C:\other"]
    elif mutation == "network":
        nodes[0]["network_origins"] = ["https://evil.example.test"]
    elif mutation == "data":
        nodes[0]["data_ceiling"] = DataCeiling.SENSITIVE.value
    else:
        parent_policy = WorkerModelPolicy(
            frozenset({"different-provider"}), frozenset({"different-model"}), True, 4_000
        )
        request = _request(
            filesystem_scope=filesystem,
            network_scope=network,
            model_policy=parent_policy,
            data_ceiling=DataCeiling.SENSITIVE,
        )
        with pytest.raises(DelegationValidationError) as captured:
            validator.validate(proposal, request)
        assert captured.value.reason is reason
        return

    request = _request(
        filesystem_scope=filesystem,
        network_scope=network,
        model_policy=policy,
        data_ceiling=DataCeiling.INTERNAL,
    )
    with pytest.raises(DelegationValidationError) as captured:
        validator.validate(proposal, request)
    assert captured.value.reason is reason


def test_secret_context_is_never_selectable_for_a_specialist() -> None:
    research = _Worker("research", AgentType.RESEARCH, data_ceiling=DataCeiling.CONFIDENTIAL)
    coding = _Worker("coding", AgentType.CODING)
    _coordinator_instance, _fallback, validator = _coordinator((research, coding))
    request = _request(
        context=(
            ContextItem("objective", "Implement the requested feature"),
            ContextItem("secret", "password=do-not-forward", DataClassification.CONFIDENTIAL),
        ),
        data_ceiling=DataCeiling.CONFIDENTIAL,
    )
    proposal = _proposal(
        _node("research", "research", context=["secret"]),
        _node("coding", "coding"),
    )

    with pytest.raises(DelegationValidationError) as captured:
        validator.validate(proposal, request)
    assert captured.value.reason is DelegationValidationReason.DATA_SCOPE_ESCALATION


def test_host_scope_normalization_is_exact_and_traversal_free() -> None:
    with pytest.raises(ValueError, match="absolute"):
        FilesystemScope(("relative\\path",))
    with pytest.raises(ValueError, match="traversal"):
        FilesystemScope((r"C:\workspace\..\secrets",))
    with pytest.raises(ValueError, match="origins"):
        NetworkScope(("https://user:password@example.test/private",))
    parent = FilesystemScope((r"C:\workspace",))
    assert parent.contains(FilesystemScope((r"C:\workspace\src",)))
    assert not parent.contains(FilesystemScope((r"C:\workspaces",)))
    origins = NetworkScope(("https://api.example.test",))
    assert origins.contains(NetworkScope(("https://api.example.test",)))
    assert not origins.contains(NetworkScope(("https://sub.api.example.test",)))


def test_recursion_policy_is_explicitly_bounded() -> None:
    with pytest.raises(ValueError, match="worker spawn"):
        AgentContract(
            "research",
            AgentType.RESEARCH,
            "Research",
            _TaskInput,
            frozenset(),
            frozenset(),
            frozenset(),
            ResourceBudget(1, 100, 1, 1),
            _TaskOutput,
            delegation_policy=WorkerDelegationPolicy(True, 1),
        )
    with pytest.raises(ValueError, match="exactly one"):
        DelegationLimits(2, 1, ResourceBudget(2, 100, 2, 1), max_depth=2)


@pytest.mark.parametrize(
    "role",
    (
        AgentType.RESEARCH,
        AgentType.CODING,
        AgentType.INTEGRATION_BUILDER,
        AgentType.VERIFICATION,
        AgentType.DIAGNOSTICS,
    ),
)
def test_generic_specialist_roles_have_no_delegation_authority(role: AgentType) -> None:
    worker = _Worker(role.value, role)
    assert worker.contract.profile is not None
    assert worker.contract.delegation_policy == WorkerDelegationPolicy()
    assert not worker.contract.may_delegate


@pytest.mark.asyncio
@pytest.mark.parametrize("enabled", (False, True))
async def test_disabled_or_unnecessary_delegation_uses_single_agent(enabled: bool) -> None:
    research = _Worker("research", AgentType.RESEARCH)
    coordinator, fallback, _validator = _coordinator((research,), enabled=enabled)

    result = await coordinator.execute(_request(), _proposal(_node("only", "research")))

    assert result.mode is ExecutionMode.SINGLE_AGENT
    assert result.status is OrchestrationStatus.COMPLETED
    assert len(fallback.calls) == 1
    assert not research.invocations
    expected = "multi_agent_disabled" if not enabled else "no_concrete_advantage"
    assert expected in result.reason_code


@pytest.mark.asyncio
async def test_absent_delegation_proposal_preserves_single_agent_default() -> None:
    research = _Worker("research", AgentType.RESEARCH)
    coordinator, fallback, _validator = _coordinator((research,))

    result = await coordinator.execute(_request(), None)

    assert result.mode is ExecutionMode.SINGLE_AGENT
    assert "delegation_not_proposed" in result.reason_code
    assert len(fallback.calls) == 1


@pytest.mark.asyncio
async def test_independent_jobs_run_in_parallel_with_concurrency_limit() -> None:
    probe = _ConcurrencyProbe()
    research = _Worker("research", AgentType.RESEARCH, delay=0.04, probe=probe)
    coding = _Worker("coding", AgentType.CODING, delay=0.04, probe=probe)
    computer = _Worker("computer", AgentType.COMPUTER, delay=0.04, probe=probe)
    coordinator, _fallback, _validator = _coordinator((research, coding, computer), concurrency=2)

    result = await coordinator.execute(
        _request(),
        _proposal(
            _node("research", "research"),
            _node("coding", "coding"),
            _node("computer", "computer"),
        ),
    )

    assert result.status is OrchestrationStatus.COMPLETED
    assert probe.maximum == 2


@pytest.mark.asyncio
async def test_dependency_ordering_waits_for_both_prerequisites() -> None:
    log: list[str] = []
    research = _Worker("research", AgentType.RESEARCH, delay=0.02, log=log)
    coding = _Worker("coding", AgentType.CODING, delay=0.01, log=log)
    computer = _Worker("computer", AgentType.COMPUTER, log=log)
    coordinator, _fallback, _validator = _coordinator((research, coding, computer))

    result = await coordinator.execute(
        _request(),
        _proposal(
            _node("research", "research"),
            _node("coding", "coding"),
            _node(
                "computer",
                "computer",
                dependencies=["research", "coding"],
            ),
        ),
    )

    assert result.status is OrchestrationStatus.COMPLETED
    assert log.index("start:computer") > log.index("end:research")
    assert log.index("start:computer") > log.index("end:coding")


@pytest.mark.asyncio
async def test_subagent_failure_returns_partial_and_blocks_dependents() -> None:
    research = _Worker("research", AgentType.RESEARCH, status=AgentResultStatus.FAILED)
    coding = _Worker("coding", AgentType.CODING)
    computer = _Worker("computer", AgentType.COMPUTER)
    coordinator, _fallback, _validator = _coordinator((research, coding, computer))

    result = await coordinator.execute(
        _request(),
        _proposal(
            _node("research", "research"),
            _node("coding", "coding"),
            _node("computer", "computer", dependencies=["research"]),
        ),
    )

    statuses = {node.key: node.status for node in result.nodes}
    assert result.status is OrchestrationStatus.PARTIAL
    assert statuses == {
        "coding": AgentNodeStatus.SUCCEEDED,
        "computer": AgentNodeStatus.BLOCKED,
        "research": AgentNodeStatus.FAILED,
    }
    assert not computer.invocations


@pytest.mark.asyncio
async def test_cancellation_propagates_to_active_and_downstream_nodes() -> None:
    research = _Worker("research", AgentType.RESEARCH, delay=2)
    coding = _Worker("coding", AgentType.CODING, delay=2)
    computer = _Worker("computer", AgentType.COMPUTER)
    coordinator, _fallback, _validator = _coordinator((research, coding, computer))
    cancellation = asyncio.Event()
    running = asyncio.create_task(
        coordinator.execute(
            _request(),
            _proposal(
                _node("research", "research"),
                _node("coding", "coding"),
                _node("computer", "computer", dependencies=["research", "coding"]),
            ),
            cancellation=cancellation,
        )
    )
    await research.started.wait()
    await coding.started.wait()

    cancellation.set()
    result = await running

    assert result.status is OrchestrationStatus.CANCELLED
    assert {node.status for node in result.nodes} == {
        AgentNodeStatus.CANCELLED,
        AgentNodeStatus.BLOCKED,
    }


def test_recursive_spawn_contracts_are_rejected() -> None:
    with pytest.raises(ValueError, match="Only the orchestrator"):
        AgentContract(
            "research",
            AgentType.RESEARCH,
            "Research",
            _TaskInput,
            frozenset(),
            frozenset(),
            frozenset(),
            ResourceBudget(1, 100, 1, 1),
            _TaskOutput,
            may_delegate=True,
        )
    orchestrator_contract = AgentContract(
        "main",
        AgentType.ORCHESTRATOR,
        "Own delegation",
        _TaskInput,
        frozenset(),
        frozenset(),
        frozenset(),
        ResourceBudget(1, 100, 1, 1),
        _TaskOutput,
        may_delegate=True,
    )
    orchestrator_worker = _Worker("research", AgentType.RESEARCH)
    orchestrator_worker._contract = orchestrator_contract
    with pytest.raises(AgentRegistryError, match="not a delegated worker"):
        AgentRegistry((orchestrator_worker,))


@pytest.mark.asyncio
async def test_delegation_cannot_escalate_computer_agent_privileges() -> None:
    computer = _Worker(
        "computer",
        AgentType.COMPUTER,
        permissions=frozenset({Permission.SYSTEM_POWER}),
        capabilities=frozenset({"focus"}),
    )
    research = _Worker("research", AgentType.RESEARCH)
    coordinator, fallback, _validator = _coordinator((computer, research))
    proposal = _proposal(
        _node(
            "computer",
            "computer",
            permissions=[Permission.SYSTEM_POWER.value],
            capabilities=["focus"],
        ),
        _node("research", "research"),
    )

    result = await coordinator.execute(_request(), proposal)

    assert result.status is OrchestrationStatus.REJECTED
    assert result.reason_code == DelegationValidationReason.SCOPE_ESCALATION.value
    assert not computer.invocations
    assert not fallback.calls


@pytest.mark.asyncio
async def test_reserved_and_actual_budget_exhaustion_fail_closed() -> None:
    research = _Worker("research", AgentType.RESEARCH)
    coding = _Worker("coding", AgentType.CODING)
    coordinator, _fallback, _validator = _coordinator(
        (research, coding),
        total_budget=ResourceBudget(1, 150, 2, 2),
    )
    reserved = await coordinator.execute(
        _request(),
        _proposal(_node("research", "research"), _node("coding", "coding")),
    )
    assert reserved.status is OrchestrationStatus.BUDGET_EXHAUSTED
    assert not research.invocations and not coding.invocations

    excessive = _Worker(
        "excessive",
        AgentType.RESEARCH,
        usage=ResourceUsage(model_calls=2, tokens=200, cost_units=2),
    )
    normal = _Worker("normal", AgentType.CODING)
    coordinator, _fallback, _validator = _coordinator((excessive, normal))
    actual = await coordinator.execute(
        _request(),
        _proposal(_node("excessive", "excessive"), _node("normal", "normal")),
    )
    assert actual.status is OrchestrationStatus.BUDGET_EXHAUSTED
    assert {node.status for node in actual.nodes} == {
        AgentNodeStatus.BUDGET_EXHAUSTED,
        AgentNodeStatus.SUCCEEDED,
    }


@pytest.mark.asyncio
async def test_unavailable_agent_falls_back_before_any_delegated_execution() -> None:
    unavailable = _Worker("research", AgentType.RESEARCH, available=False)
    coding = _Worker("coding", AgentType.CODING)
    coordinator, fallback, _validator = _coordinator((unavailable, coding))

    result = await coordinator.execute(
        _request(),
        _proposal(_node("research", "research"), _node("coding", "coding")),
    )

    assert result.mode is ExecutionMode.SINGLE_AGENT
    assert "unavailable_agent" in result.reason_code
    assert len(fallback.calls) == 1
    assert not unavailable.invocations and not coding.invocations


def test_cycle_and_unknown_evidence_are_rejected_deterministically() -> None:
    research = _Worker("research", AgentType.RESEARCH)
    coding = _Worker("coding", AgentType.CODING)
    _coordinator_instance, _fallback, validator = _coordinator((research, coding))

    with pytest.raises(DelegationValidationError) as cycle:
        validator.validate(
            _proposal(
                _node("research", "research", dependencies=["coding"]),
                _node("coding", "coding", dependencies=["research"]),
            ),
            _request(),
        )
    assert cycle.value.reason is DelegationValidationReason.CYCLE

    with pytest.raises(DelegationValidationError) as missing:
        validator.validate(
            _proposal(
                _node("research", "research", evidence=["missing"]),
                _node("coding", "coding"),
            ),
            _request(),
        )
    assert missing.value.reason is DelegationValidationReason.MALFORMED_INPUT


@pytest.mark.asyncio
async def test_agent_timeout_is_observable_without_blind_retry() -> None:
    research = _Worker("research", AgentType.RESEARCH, delay=0.1)
    coding = _Worker("coding", AgentType.CODING)
    coordinator, _fallback, _validator = _coordinator((research, coding))

    result = await coordinator.execute(
        _request(),
        _proposal(
            _node("research", "research", timeout=0.01),
            _node("coding", "coding"),
        ),
    )

    assert result.status is OrchestrationStatus.PARTIAL
    assert {node.status for node in result.nodes} == {
        AgentNodeStatus.SUCCEEDED,
        AgentNodeStatus.TIMED_OUT,
    }
    assert len(research.invocations) == 1


@pytest.mark.asyncio
async def test_global_timeout_cancels_all_active_agents() -> None:
    research = _Worker("research", AgentType.RESEARCH, delay=1)
    coding = _Worker("coding", AgentType.CODING, delay=1)
    coordinator, _fallback, _validator = _coordinator(
        (research, coding),
        total_budget=ResourceBudget(4, 1_000, 10, 0.01),
    )

    result = await coordinator.execute(
        _request(),
        _proposal(_node("research", "research"), _node("coding", "coding")),
    )

    assert result.status is OrchestrationStatus.FAILED
    assert result.reason_code == "orchestration_timeout"
    assert {node.status for node in result.nodes} == {AgentNodeStatus.TIMED_OUT}


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("worker_type", "error_code"),
    (
        (_RaisingWorker, "agent_failure"),
        (_UnknownResultWorker, "malformed_agent_result"),
        (_MalformedOutputWorker, "malformed_agent_result"),
    ),
)
async def test_untrusted_worker_failures_become_typed_partial_results(
    worker_type: type[_Worker], error_code: str
) -> None:
    failing = worker_type("research", AgentType.RESEARCH)
    coding = _Worker("coding", AgentType.CODING)
    coordinator, _fallback, _validator = _coordinator((failing, coding))

    result = await coordinator.execute(
        _request(),
        _proposal(_node("research", "research"), _node("coding", "coding")),
    )

    assert result.status is OrchestrationStatus.PARTIAL
    failed = next(node for node in result.nodes if node.key == "research")
    assert failed.error_code == error_code


@pytest.mark.asyncio
async def test_all_subagent_failures_produce_failed_orchestration() -> None:
    research = _Worker("research", AgentType.RESEARCH, status=AgentResultStatus.FAILED)
    coding = _Worker("coding", AgentType.CODING, status=AgentResultStatus.FAILED)
    coordinator, _fallback, _validator = _coordinator((research, coding))

    result = await coordinator.execute(
        _request(),
        _proposal(_node("research", "research"), _node("coding", "coding")),
    )

    assert result.status is OrchestrationStatus.FAILED
    assert result.reason_code == "delegated_task_failed"


@pytest.mark.asyncio
async def test_successful_nodes_still_require_goal_level_evidence() -> None:
    research = _Worker("research", AgentType.RESEARCH)
    coding = _Worker("coding", AgentType.CODING)
    coordinator, _fallback, _validator = _coordinator((research, coding))

    result = await coordinator.execute(
        _request(completion_evidence=("independent-verification",)),
        _proposal(_node("research", "research"), _node("coding", "coding")),
    )

    assert {node.status for node in result.nodes} == {AgentNodeStatus.SUCCEEDED}
    assert result.status is OrchestrationStatus.FAILED
    assert result.reason_code == "goal_verification_failed"


@pytest.mark.asyncio
async def test_registered_contract_mutation_is_detected_before_next_node() -> None:
    research = _SelfMutatingWorker("research", AgentType.RESEARCH)
    coding = _Worker("coding", AgentType.CODING)
    coordinator, _fallback, _validator = _coordinator((research, coding))

    result = await coordinator.execute(
        _request(),
        _proposal(
            _node("research-first", "research"),
            _node("coding", "coding"),
            _node("research-second", "research", dependencies=["research-first"]),
        ),
    )

    second = next(node for node in result.nodes if node.key == "research-second")
    assert result.status is OrchestrationStatus.PARTIAL
    assert second.error_code == "agent_contract_changed"


def test_agent_contract_and_registry_reject_invalid_boundaries(tmp_path: Path) -> None:
    del tmp_path
    worker = _Worker("research", AgentType.RESEARCH)
    with pytest.raises(AgentRegistryError, match="Duplicate"):
        AgentRegistry((worker, worker))
    with pytest.raises(ValueError, match="finite"):
        ResourceBudget(1, 1, 1, float("nan"))
    with pytest.raises(ValueError, match="SHA-256"):
        EvidenceReference("evidence", "summary", "not-a-digest")


def test_multi_agent_domain_models_reject_malformed_state() -> None:
    with pytest.raises(ValueError, match="non-empty"):
        ContextItem("", "value")
    with pytest.raises(ValueError, match="cannot be negative"):
        ResourceUsage(tokens=-1)
    with pytest.raises(ValueError, match="Agent type"):
        replace(_Worker("research", AgentType.RESEARCH).contract, agent_type=cast(AgentType, "x"))
    with pytest.raises(ValueError, match="uniquely keyed"):
        replace(
            _request(),
            context=(ContextItem("same", "one"), ContextItem("same", "two")),
        )
    with pytest.raises(ValueError, match="recognized"):
        replace(
            _request(),
            allowed_permissions=frozenset({cast(Permission, "unknown")}),
        )
    with pytest.raises(ValueError, match="valid JSON"):
        AgentResult(AgentResultStatus.SUCCEEDED, "{", (), ResourceUsage())
    with pytest.raises(ValueError, match="recognized"):
        AgentResult(cast(AgentResultStatus, "unknown"), "{}", (), ResourceUsage())
    with pytest.raises(ValueError, match="error code"):
        AgentResult(
            AgentResultStatus.FAILED,
            "{}",
            (),
            ResourceUsage(),
            "",
            "failure",
        )

    node = DelegatedTaskNode(
        uuid4(),
        "node",
        "research",
        "Research",
        '{"topic":"node"}',
        (),
        (),
        ("analyze",),
        (),
        ("objective",),
        ("architecture",),
        ResourceBudget(1, 100, 1, 1),
        1,
    )
    with pytest.raises(ValueError, match="valid JSON"):
        replace(node, input_json="{")
    with pytest.raises(ValueError, match="cannot reference self"):
        replace(node, dependencies=(node.node_id,))
    with pytest.raises(ValueError, match="positive and finite"):
        replace(node, timeout_seconds=float("nan"))
    with pytest.raises(ValueError, match="node IDs"):
        DelegationGraph(uuid4(), uuid4(), "goal", (node, node), "rationale")
    now = datetime.now(UTC)
    with pytest.raises(ValueError, match="cannot precede"):
        OrchestrationResult(
            uuid4(),
            ExecutionMode.MULTI_AGENT,
            OrchestrationStatus.FAILED,
            (node,),
            (),
            ResourceUsage(),
            now,
            now - timedelta(seconds=1),
            "failed",
            "Failed",
        )


def test_specialist_policy_models_cover_fail_closed_boundaries() -> None:
    assert DataCeiling.CONFIDENTIAL.contains(DataCeiling.PUBLIC)
    assert not DataCeiling.PUBLIC.contains(DataCeiling.INTERNAL)
    assert DataCeiling.SENSITIVE.allows(DataClassification.SENSITIVE)
    assert not DataCeiling.CONFIDENTIAL.allows(DataClassification.SECRET)

    with pytest.raises(ValueError, match="bounded tuple"):
        FilesystemScope(cast(Any, [r"C:\workspace"]))
    with pytest.raises(ValueError, match="control"):
        FilesystemScope(("C:\\workspace\n",))
    with pytest.raises(ValueError, match="wildcards"):
        FilesystemScope((r"C:\workspace\*",))
    with pytest.raises(ValueError, match="unique"):
        FilesystemScope((r"C:\workspace", r"c:\workspace"))

    with pytest.raises(ValueError, match="HTTP"):
        NetworkScope(("ftp://example.test",))
    with pytest.raises(ValueError, match="HTTP"):
        NetworkScope(("https://",))
    with pytest.raises(ValueError, match="port"):
        NetworkScope(("https://example.test:bad",))
    with pytest.raises(ValueError, match="host"):
        NetworkScope(("https://:443",))
    assert NetworkScope(("http://example.test:8080",)).origins == ("http://example.test:8080",)
    assert NetworkScope(("https://[::1]",)).origins == ("https://[::1]",)
    with pytest.raises(ValueError, match="unique"):
        NetworkScope(("https://example.test", "HTTPS://EXAMPLE.TEST:443"))

    bounded = WorkerModelPolicy(frozenset({"p"}), frozenset({"m"}), True, 8_000)
    narrower = WorkerModelPolicy(frozenset({"p"}), frozenset({"m"}), True, 4_000)
    broader = WorkerModelPolicy(frozenset({"p", "other"}), frozenset({"m"}), True, 8_000)
    assert bounded.contains(narrower)
    assert not bounded.contains(broader)
    with pytest.raises(ValueError, match="frozensets"):
        WorkerModelPolicy(cast(Any, {"p"}), frozenset({"m"}))
    with pytest.raises(ValueError, match="malformed"):
        WorkerModelPolicy(frozenset(), frozenset(), True, 0)
    with pytest.raises(ValueError, match="malformed"):
        WorkerModelPolicy(frozenset({"p"}), frozenset({"m"}), cast(Any, "yes"))

    assert WorkerDelegationPolicy(True, 1).contains(WorkerDelegationPolicy(False, 0))
    assert not WorkerDelegationPolicy(False, 0).contains(WorkerDelegationPolicy(True, 1))
    with pytest.raises(ValueError, match="recursion depth"):
        WorkerDelegationPolicy(False, 1)
    with pytest.raises(ValueError, match="positive"):
        WorkerDelegationPolicy(True, 0)
    with pytest.raises(ValueError, match="malformed"):
        WorkerDelegationPolicy(cast(Any, "yes"), 0)

    with pytest.raises(ValueError, match="profile ID"):
        WorkerProfile("", "purpose")
    with pytest.raises(ValueError, match="purpose"):
        WorkerProfile("profile", "")


def test_specialist_invocation_rejects_scope_and_allowlist_violations() -> None:
    context = (ContextItem("public", "safe"),)
    evidence = (_evidence("architecture"),)
    common: dict[str, object] = {
        "task_id": uuid4(),
        "node_id": uuid4(),
        "objective": "Inspect the bounded objective",
        "validated_input": _TaskInput(topic="test"),
        "context": context,
        "evidence": evidence,
        "required_tools": ("repository.read",),
        "required_capabilities": ("analyze",),
        "required_permissions": (),
        "budget": ResourceBudget(1, 100, 1, 1),
        "tool_allowlist": frozenset({"repository.read"}),
        "capability_allowlist": frozenset({"analyze"}),
    }
    invocation_factory = cast(Any, AgentInvocation)
    valid = invocation_factory(**common)
    assert valid.context == context
    with pytest.raises(ValueError, match="allowlist"):
        invocation_factory(**{**common, "tool_allowlist": frozenset()})
    with pytest.raises(ValueError, match="permissions"):
        invocation_factory(**{**common, "required_permissions": (cast(Any, "bad"),)})
    with pytest.raises(ValueError, match="out-of-ceiling"):
        invocation_factory(
            **{
                **common,
                "context": (ContextItem("sensitive", "private", DataClassification.SENSITIVE),),
            }
        )
    with pytest.raises(ValueError, match="secret"):
        invocation_factory(
            **{
                **common,
                "evidence": (
                    EvidenceReference(
                        "secret",
                        "secret=must-not-forward",
                        "a" * 64,
                        DataClassification.CONFIDENTIAL,
                    ),
                ),
                "data_ceiling": DataCeiling.CONFIDENTIAL,
            }
        )
    with pytest.raises(ValueError, match="output schema"):
        invocation_factory(**{**common, "output_schema": cast(Any, object())})


def test_worker_result_evidence_is_typed_and_stays_within_data_ceiling() -> None:
    with pytest.raises(ValueError, match="typed"):
        AgentResult(
            AgentResultStatus.SUCCEEDED,
            "{}",
            cast(Any, (object(),)),
            ResourceUsage(),
        )

    research = _Worker("research", AgentType.RESEARCH)
    coding = _Worker("coding", AgentType.CODING)
    coordinator, _fallback, _validator = _coordinator((research, coding))
    original_execute = research.execute

    async def secret_result(
        invocation: AgentInvocation, cancellation: asyncio.Event
    ) -> AgentResult:
        del invocation, cancellation
        return AgentResult.success(
            _TaskOutput(value="research"),
            evidence=(
                EvidenceReference(
                    "secret-result",
                    "secret=must-not-escape",
                    "a" * 64,
                    DataClassification.CONFIDENTIAL,
                ),
            ),
        )

    research.execute = secret_result  # type: ignore[method-assign]
    try:
        result = asyncio.run(
            coordinator.execute(
                _request(completion_evidence=("coding-evidence",)),
                _proposal(_node("research", "research"), _node("coding", "coding")),
            )
        )
    finally:
        research.execute = original_execute  # type: ignore[method-assign]
    assert result.status is OrchestrationStatus.PARTIAL
    research_node = next(node for node in result.nodes if node.agent_id == "research")
    assert research_node.error_code == "agent_result_scope_violation"


def test_specialist_contract_rejects_policy_type_escalation() -> None:
    arguments: tuple[object, ...] = (
        "worker",
        AgentType.RESEARCH,
        "Research",
        _TaskInput,
        frozenset(),
        frozenset(),
        frozenset(),
        ResourceBudget(1, 100, 1, 1),
        _TaskOutput,
    )
    contract_factory = cast(Any, AgentContract)
    with pytest.raises(ValueError, match="delegation policy"):
        contract_factory(*arguments, delegation_policy=cast(Any, object()))
    with pytest.raises(ValueError, match="profile"):
        contract_factory(*arguments, profile=cast(Any, object()))
    with pytest.raises(ValueError, match="model policy"):
        contract_factory(*arguments, model_policy=cast(Any, object()))
    with pytest.raises(ValueError, match="host scopes"):
        contract_factory(*arguments, filesystem_scope=cast(Any, object()))
    with pytest.raises(ValueError, match="data ceiling"):
        contract_factory(*arguments, data_ceiling=cast(Any, "secret"))


@pytest.mark.parametrize(
    ("mutation", "reason"),
    (
        ("goal", DelegationValidationReason.GOAL_MISMATCH),
        ("unknown_permission", DelegationValidationReason.SCOPE_ESCALATION),
        ("tool_escape", DelegationValidationReason.SCOPE_ESCALATION),
        ("invalid_input", DelegationValidationReason.MALFORMED_INPUT),
        ("unknown_context", DelegationValidationReason.MALFORMED_INPUT),
        ("agent_budget", DelegationValidationReason.BUDGET_EXHAUSTED),
        ("timeout_budget", DelegationValidationReason.BUDGET_EXHAUSTED),
    ),
)
def test_delegation_validator_rejects_boundary_mutations(
    mutation: str, reason: DelegationValidationReason
) -> None:
    research = _Worker(
        "research",
        AgentType.RESEARCH,
        tools=frozenset({"repository.read"}),
    )
    coding = _Worker("coding", AgentType.CODING)
    _coordinator_instance, _fallback, validator = _coordinator((research, coding))
    proposal = _proposal(
        _node("research", "research"),
        _node("coding", "coding"),
    )
    mutated = copy.deepcopy(proposal)
    nodes = cast(list[dict[str, object]], mutated["nodes"])
    if mutation == "goal":
        mutated["goal"] = "Changed goal"
    elif mutation == "unknown_permission":
        nodes[0]["required_permissions"] = ["unknown.permission"]
    elif mutation == "tool_escape":
        nodes[0]["required_tools"] = ["terminal.execute"]
    elif mutation == "invalid_input":
        nodes[0]["input"] = {"unexpected": "field"}
    elif mutation == "unknown_context":
        nodes[0]["context_keys"] = ["global-conversation"]
    elif mutation == "agent_budget":
        nodes[0]["budget"] = _budget(calls=5)
    else:
        nodes[0]["budget"] = _budget(elapsed=0.25)
        nodes[0]["timeout_seconds"] = 0.5

    with pytest.raises(DelegationValidationError) as captured:
        validator.validate(mutated, _request())
    assert captured.value.reason is reason


def test_delegation_limits_and_malformed_schema_fail_closed() -> None:
    with pytest.raises(ValueError, match="node limit"):
        DelegationLimits(0, 1, ResourceBudget(1, 1, 1, 1))
    with pytest.raises(ValueError, match="concurrency"):
        DelegationLimits(1, 0, ResourceBudget(1, 1, 1, 1))
    worker = _Worker("research", AgentType.RESEARCH)
    validator = DelegationValidator(
        AgentRegistry((worker,)),
        DelegationLimits(1, 1, ResourceBudget(1, 100, 1, 1)),
    )
    with pytest.raises(DelegationValidationError) as malformed:
        validator.validate({"goal": "missing fields"}, _request())
    assert malformed.value.reason is DelegationValidationReason.MALFORMED_PROPOSAL
