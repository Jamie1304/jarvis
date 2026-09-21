"""R3G-R2 source-closure tests for task-originated resource acquisition."""

from __future__ import annotations

import asyncio
import hashlib
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any
from uuid import UUID

import pytest
from jarvis.acquisition import (
    AcquisitionBroker,
    AcquisitionPolicy,
    AcquisitionPolicyMode,
    AcquisitionRequest,
    BoundedDownloadTransport,
    DownloadEvidence,
    InMemoryAcquisitionLedger,
    PrivacyImpact,
    ProvenanceMetadata,
    ResourceType,
    SQLiteAcquisitionLedger,
)
from jarvis.capabilities import CapabilityRegistry
from jarvis.goal_scheduler import GoalScheduler, GoalScheduleStatus
from jarvis.goal_supervisor import (
    GoalBudget,
    GoalIntent,
    GoalResearch,
    GoalSupervisor,
    GoalSupervisorStore,
    PlanningGoalTaskRunner,
    RegistryGoalAnalyzer,
)
from jarvis.planning import (
    BrokeredPlanningStepExecutor,
    CompletionCriteriaVerifier,
    EvidencePlanningStepVerifier,
    PlanAdvisor,
    PlanningEngine,
    PlanningTaskStatus,
    PlanProposal,
    PlanValidator,
    SQLitePlanningStore,
)
from jarvis.planning.resources import (
    AcquisitionResourceBridge,
    ResourceResolution,
    ResourceResolutionState,
    TrustedResourceDescriptor,
)
from jarvis.system_stewardship import MissingResourceRequirement
from jarvis.task_controller import PlanningTaskController
from jarvis.tools.base import Tool
from jarvis.tools.models import (
    SemanticVersion,
    ToolEvidence,
    ToolExecutionContext,
    ToolManifest,
    ToolPlatform,
    ToolResult,
)
from jarvis.tools.registry import ToolRegistry
from pydantic import BaseModel, ConfigDict

PAYLOAD = b"R3G-R2 acceptance-owned resource\n"
PAYLOAD_HASH = hashlib.sha256(PAYLOAD).hexdigest()


class _Handler(BaseHTTPRequestHandler):
    hits = 0
    delay_seconds = 0.0

    def do_GET(self) -> None:  # noqa: N802 - stdlib handler contract
        type(self).hits += 1
        if type(self).delay_seconds:
            time.sleep(type(self).delay_seconds)
        if self.path != "/resource.bin":
            self.send_error(404)
            return
        self.send_response(200)
        self.send_header("Content-Length", str(len(PAYLOAD)))
        self.end_headers()
        self.wfile.write(PAYLOAD)

    def log_message(self, *_args: object) -> None:
        return None


class _ResourceInput(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)

    resource_path: str


class _ResourceOutput(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)

    bytes_read: int


class _ResourceConsumer(Tool[_ResourceInput, _ResourceOutput]):
    def __init__(self) -> None:
        self.consumed: list[bytes] = []

    @property
    def manifest(self) -> ToolManifest:
        return ToolManifest(
            tool_id="consume.resource",
            name="Consume resource",
            description="Acceptance-owned resource consumer",
            version=SemanticVersion(1, 0, 0),
            capability_tags=frozenset({"consume.resource"}),
            input_schema=_ResourceInput,
            output_schema=_ResourceOutput,
            declared_permissions=frozenset(),
            supported_platforms=frozenset(
                {ToolPlatform.WINDOWS, ToolPlatform.LINUX, ToolPlatform.MACOS}
            ),
            timeout_seconds=2,
        )

    @property
    def input_model(self) -> type[_ResourceInput]:
        return _ResourceInput

    async def _execute_authorized(
        self, context: ToolExecutionContext, validated_input: _ResourceInput
    ) -> ToolResult:
        del context
        payload = Path(validated_input.resource_path).read_bytes()
        self.consumed.append(payload)
        return ToolResult.success(
            _ResourceOutput(bytes_read=len(payload)),
            evidence=(ToolEvidence("consumer", "resource-consumed"),),
        )


class _Advisor(PlanAdvisor):
    def __init__(self, proposal: PlanProposal) -> None:
        self.proposal = proposal

    async def propose(
        self, goal: str, assumptions: tuple[str, ...], constraints: tuple[str, ...]
    ) -> object:
        del assumptions, constraints
        assert goal == self.proposal.goal
        return self.proposal

    async def replan(self, evidence: object) -> object:
        del evidence
        raise AssertionError("the acceptance route must not replan")


class _NoopResearcher:
    async def research(self, *args: object, **kwargs: object) -> GoalResearch:
        del args, kwargs
        return GoalResearch()


class _NoopAcquirer:
    async def acquire(self, request: object) -> Any:
        del request
        raise AssertionError("capability acquisition is not part of this resource route")


class _UnknownTransport(BoundedDownloadTransport):
    async def download(
        self,
        source: str,
        destination: str,
        *,
        maximum_bytes: int | None = None,
        expected_sha256: str | None = None,
    ) -> DownloadEvidence:
        del source, destination, maximum_bytes, expected_sha256
        raise RuntimeError("controlled interruption after the acquisition effect boundary")


class _InterruptAfterAcquisitionBridge(AcquisitionResourceBridge):
    async def acquire(
        self,
        resolution: ResourceResolution,
        *,
        task_id: UUID,
        step_id: UUID,
        cancellation: asyncio.Event,
    ) -> ResourceResolution:
        result = await super().acquire(
            resolution,
            task_id=task_id,
            step_id=step_id,
            cancellation=cancellation,
        )
        if result.state is ResourceResolutionState.SATISFIED:
            raise asyncio.CancelledError()
        return result


def _proposal(goal: str) -> PlanProposal:
    return PlanProposal.model_validate(
        {
            "goal": goal,
            "assumptions": [],
            "constraints": [],
            "required_capabilities": ["consume.resource"],
            "required_permissions": [],
            "completion_criteria": ["resource-consumed"],
            "steps": [
                {
                    "key": "consume",
                    "tool_id": "consume.resource",
                    "capability": "consume.resource",
                    "input": {"resource_path": "placeholder"},
                    "dependencies": [],
                    "required_permissions": [],
                    "expected_output": "resource bytes consumed",
                    "verification_rule": "evidence_contains_all",
                    "expected_evidence": ["resource-consumed"],
                    "expensive_action": False,
                    "max_retries": 0,
                    "resource_requirements": [
                        {
                            "resource_id": "acceptance.resource",
                            "resource_type": "data",
                            "purpose": "provide bytes required by the consuming step",
                            "consumer_input_field": "resource_path",
                            "required_for": "consumer step",
                            "requested_version": "1",
                            "privacy_constraint": "unknown",
                            "alternatives": [],
                        }
                    ],
                }
            ],
        }
    )


def _descriptor(source: str, *, target: str = "resource.bin") -> TrustedResourceDescriptor:
    return TrustedResourceDescriptor(
        resource_id="acceptance.resource",
        resource_type=ResourceType.DATA,
        source=source,
        expected_sha256=PAYLOAD_HASH,
        target_location=target,
        download_size_bytes=len(PAYLOAD),
        purpose="acceptance-owned consumer resource",
        required_for="R3G-R2 consumer",
        requested_version="1",
        provenance=ProvenanceMetadata(
            source_identity="r3g-r2-local-http",
            trusted_source=True,
        ),
        privacy_impact=PrivacyImpact.NETWORK_METADATA,
    )


def _engine_for_bridge(
    tmp_path: Path,
    bridge: AcquisitionResourceBridge,
) -> tuple[PlanningEngine, SQLitePlanningStore, _ResourceConsumer]:
    consumer = _ResourceConsumer()
    registry = ToolRegistry((consumer,))
    store = SQLitePlanningStore(tmp_path / "planning.sqlite3")
    proposal = _proposal("consume acceptance resource")
    engine = PlanningEngine(
        store=store,
        advisor=_Advisor(proposal),
        validator=PlanValidator(registry, max_steps=4),
        executor=BrokeredPlanningStepExecutor(registry),
        step_verifier=EvidencePlanningStepVerifier(),
        goal_verifier=CompletionCriteriaVerifier(),
        resource_bridge=bridge,
    )
    return engine, store, consumer


@pytest.mark.asyncio
async def test_goal_task_step_missing_resource_acquires_registers_and_consumes(
    tmp_path: Path,
) -> None:
    _Handler.hits = 0
    server = ThreadingHTTPServer(("127.0.0.1", 0), _Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        consumer = _ResourceConsumer()
        registry = ToolRegistry((consumer,))
        planning_store = SQLitePlanningStore(tmp_path / "planning.sqlite3")
        ledger = InMemoryAcquisitionLedger()
        broker = AcquisitionBroker(
            BoundedDownloadTransport(tmp_path / "downloads"),
            AcquisitionPolicy(
                mode=AcquisitionPolicyMode.JARVIS_MANAGED,
                trusted_sources_only=True,
                require_known_disk_capacity=True,
            ),
            ledger,
        )
        requests: list[AcquisitionRequest] = []
        bridge = AcquisitionResourceBridge(
            broker,
            disk_free_bytes=lambda: 100_000,
            request_sink=requests.append,
        )
        bridge.register_descriptor(
            _descriptor(f"http://127.0.0.1:{server.server_port}/resource.bin")
        )
        proposal = _proposal("consume acceptance resource")
        engine = PlanningEngine(
            store=planning_store,
            advisor=_Advisor(proposal),
            validator=PlanValidator(registry, max_steps=4),
            executor=BrokeredPlanningStepExecutor(registry),
            step_verifier=EvidencePlanningStepVerifier(),
            goal_verifier=CompletionCriteriaVerifier(),
            resource_bridge=bridge,
        )
        controller = PlanningTaskController(engine, registry.permission_broker)
        runner = PlanningGoalTaskRunner(controller)
        supervisor = GoalSupervisor(
            registry=CapabilityRegistry(),
            store=GoalSupervisorStore(tmp_path / "goals.sqlite3"),
            analyzer=RegistryGoalAnalyzer(),
            researcher=_NoopResearcher(),
            acquirer=_NoopAcquirer(),
            runner=runner,
        )
        scheduler = GoalScheduler(supervisor)
        intent = GoalIntent("consume acceptance resource")

        scheduled = await scheduler.submit(intent, GoalBudget())
        terminal = await scheduler.wait(intent.goal_id)

        assert scheduled.status is GoalScheduleStatus.QUEUED
        assert terminal.status is GoalScheduleStatus.TERMINAL
        assert terminal.goal_status is not None
        assert terminal.goal_status.value == "completed"
        assert terminal.task_id is not None
        task = engine.get_task(terminal.task_id)
        assert task is not None and task.status is PlanningTaskStatus.COMPLETED
        plan = engine.inspect_plan(terminal.task_id)
        assert plan is not None and plan.steps[0].status.value == "succeeded"
        assert consumer.consumed == [PAYLOAD]
        assert len(requests) == 1
        assert _Handler.hits == 1
        missing = bridge.last_missing_requirement
        assert isinstance(missing, MissingResourceRequirement)
        assert missing.task_id == terminal.task_id
        assert missing.step_id == plan.steps[0].step_id
        assert ledger.records()[0].state.value == "registered"
        assert (
            await bridge.resolve(
                plan.steps[0].resource_requirements[0],
                task_id=terminal.task_id,
                step_id=plan.steps[0].step_id,
            )
        ).state is ResourceResolutionState.SATISFIED
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=5)


@pytest.mark.asyncio
async def test_concurrent_goals_share_registered_resource_without_duplicate_acquisition(
    tmp_path: Path,
) -> None:
    _Handler.hits = 0
    _Handler.delay_seconds = 0.5
    server = ThreadingHTTPServer(("127.0.0.1", 0), _Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        root = tmp_path / "downloads"
        ledger = SQLiteAcquisitionLedger(tmp_path / "acquisition.sqlite3")
        broker = AcquisitionBroker(
            BoundedDownloadTransport(root),
            AcquisitionPolicy(
                mode=AcquisitionPolicyMode.JARVIS_MANAGED,
                trusted_sources_only=True,
            ),
            ledger,
        )
        bridge = AcquisitionResourceBridge(broker, disk_free_bytes=lambda: 100_000)
        bridge.register_descriptor(
            _descriptor(f"http://127.0.0.1:{server.server_port}/resource.bin")
        )
        engine, _store, consumer = _engine_for_bridge(tmp_path, bridge)
        controller = PlanningTaskController(engine, ToolRegistry(()).permission_broker)
        supervisor = GoalSupervisor(
            registry=CapabilityRegistry(),
            store=GoalSupervisorStore(tmp_path / "goals.sqlite3"),
            analyzer=RegistryGoalAnalyzer(),
            researcher=_NoopResearcher(),
            acquirer=_NoopAcquirer(),
            runner=PlanningGoalTaskRunner(controller),
        )
        scheduler = GoalScheduler(supervisor)
        intents = (
            GoalIntent("consume acceptance resource"),
            GoalIntent("consume acceptance resource"),
        )
        scheduled = await asyncio.gather(
            *(scheduler.submit(intent, GoalBudget()) for intent in intents)
        )
        views = await asyncio.gather(*(scheduler.wait(intent.goal_id) for intent in intents))

        assert all(
            item.status in {GoalScheduleStatus.SUSPENDED, GoalScheduleStatus.TERMINAL}
            for item in views
        )
        assert all(
            item.goal_status is not None
            and item.goal_status.value in {"completed", "waiting_for_resource"}
            for item in views
        ), [(item.goal_status, item.error) for item in views]
        assert _Handler.hits == 1
        waiting = [
            item
            for item in views
            if item.goal_status is not None and item.goal_status.value == "waiting_for_resource"
        ]
        for item in waiting:
            await scheduler.resume(item.goal_id)
            resumed = await scheduler.wait(item.goal_id)
            assert resumed.status is GoalScheduleStatus.TERMINAL
            assert resumed.goal_status is not None and resumed.goal_status.value == "completed"
        assert _Handler.hits == 1
        assert consumer.consumed == [PAYLOAD, PAYLOAD]
        assert ledger.records()[0].state.value == "registered"
        del scheduled
    finally:
        _Handler.delay_seconds = 0.0
        server.shutdown()
        server.server_close()
        thread.join(timeout=5)


@pytest.mark.asyncio
async def test_interrupted_acquisition_stays_uncertain_until_reconciliation(
    tmp_path: Path,
) -> None:
    root = tmp_path / "downloads"
    ledger = SQLiteAcquisitionLedger(tmp_path / "acquisition.sqlite3")
    unknown_broker = AcquisitionBroker(
        _UnknownTransport(root),
        AcquisitionPolicy(
            mode=AcquisitionPolicyMode.JARVIS_MANAGED,
            trusted_sources_only=True,
        ),
        ledger,
    )
    unknown_bridge = AcquisitionResourceBridge(
        unknown_broker,
        disk_free_bytes=lambda: 100_000,
    )
    unknown_bridge.register_descriptor(_descriptor("http://127.0.0.1:9/resource.bin"))
    engine, store, consumer = _engine_for_bridge(tmp_path, unknown_bridge)

    waiting = await engine.submit_proposal(_proposal("consume acceptance resource"))

    assert waiting.status is PlanningTaskStatus.WAITING_FOR_RESOURCE
    assert not consumer.consumed
    assert ledger.records()[0].state.value == "verification_required"

    (root / "resource.bin").write_bytes(PAYLOAD)
    store.close()
    reconciled_broker = AcquisitionBroker(
        BoundedDownloadTransport(root),
        AcquisitionPolicy(
            mode=AcquisitionPolicyMode.JARVIS_MANAGED,
            trusted_sources_only=True,
        ),
        ledger,
    )
    reconciled_bridge = AcquisitionResourceBridge(
        reconciled_broker,
        disk_free_bytes=lambda: 100_000,
    )
    reconciled_bridge.register_descriptor(_descriptor("http://127.0.0.1:9/resource.bin"))
    resumed_engine, _, resumed_consumer = _engine_for_bridge(tmp_path, reconciled_bridge)

    resumed = await resumed_engine.resume(waiting.task_id)

    assert resumed.status is PlanningTaskStatus.COMPLETED
    assert resumed_consumer.consumed == [PAYLOAD]
    assert ledger.records()[0].state.value == "registered"


@pytest.mark.asyncio
async def test_restart_after_registration_resumes_consumer_once(tmp_path: Path) -> None:
    _Handler.hits = 0
    server = ThreadingHTTPServer(("127.0.0.1", 0), _Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        root = tmp_path / "downloads"
        ledger = SQLiteAcquisitionLedger(tmp_path / "acquisition.sqlite3")
        broker = AcquisitionBroker(
            BoundedDownloadTransport(root),
            AcquisitionPolicy(
                mode=AcquisitionPolicyMode.JARVIS_MANAGED,
                trusted_sources_only=True,
            ),
            ledger,
        )
        interrupted_bridge = _InterruptAfterAcquisitionBridge(
            broker,
            disk_free_bytes=lambda: 100_000,
        )
        interrupted_bridge.register_descriptor(
            _descriptor(f"http://127.0.0.1:{server.server_port}/resource.bin")
        )
        engine, store, consumer = _engine_for_bridge(tmp_path, interrupted_bridge)

        with pytest.raises(asyncio.CancelledError):
            await engine.submit_proposal(_proposal("consume acceptance resource"))
        assert not consumer.consumed
        assert ledger.records()[0].state.value == "registered"
        assert _Handler.hits == 1
        store.close()

        restarted_broker = AcquisitionBroker(
            BoundedDownloadTransport(root),
            AcquisitionPolicy(
                mode=AcquisitionPolicyMode.JARVIS_MANAGED,
                trusted_sources_only=True,
            ),
            ledger,
        )
        restarted_bridge = AcquisitionResourceBridge(
            restarted_broker,
            disk_free_bytes=lambda: 100_000,
        )
        restarted_bridge.register_descriptor(
            _descriptor(f"http://127.0.0.1:{server.server_port}/resource.bin")
        )
        restarted_engine, _, restarted_consumer = _engine_for_bridge(tmp_path, restarted_bridge)
        waiting_task = restarted_engine.list_tasks()[0]
        assert waiting_task.status is PlanningTaskStatus.WAITING_FOR_RESOURCE

        completed = await restarted_engine.resume(waiting_task.task_id)

        assert completed.status is PlanningTaskStatus.COMPLETED
        assert restarted_consumer.consumed == [PAYLOAD]
        assert _Handler.hits == 1
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=5)
