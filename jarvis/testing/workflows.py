"""Deterministic agent-workflow evaluations with fake planners and tools only."""

from __future__ import annotations

import asyncio
import logging
from collections.abc import Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import Any
from uuid import uuid4

from pydantic import BaseModel, ConfigDict

from jarvis.autonomy.execution import (
    DefaultObservationService,
    DefaultToolExecutor,
    EvidenceVerifier,
    RegistryCapabilitySelector,
)
from jarvis.autonomy.models import StructuredTaskError, TaskStatus
from jarvis.autonomy.orchestrator import AgentOrchestrator
from jarvis.autonomy.planning import (
    DefaultRequestInterpreter,
    PlanningAdvisor,
    SchemaValidatedPlanner,
    TaskIntent,
)
from jarvis.autonomy.response import DefaultTaskResponseGenerator
from jarvis.autonomy.store import InMemoryTaskStore
from jarvis.permissions.broker import PermissionBroker
from jarvis.permissions.models import (
    ActionDescriptor,
    Decision,
    Permission,
    PermissionRequest,
    PermissionScope,
    PolicyRule,
    Risk,
    ScopeConstraint,
)
from jarvis.permissions.policy import PolicyEngine
from jarvis.tools.base import Tool
from jarvis.tools.calculator import CalculatorTool
from jarvis.tools.models import (
    SemanticVersion,
    ToolCaller,
    ToolEvidence,
    ToolExecutionContext,
    ToolManifest,
    ToolPlatform,
    ToolResult,
    ToolResultStatus,
)
from jarvis.tools.registry import ToolRegistry


@dataclass(frozen=True, slots=True)
class WorkflowEvaluation:
    scenario_id: str
    passed: bool
    summary: str
    evidence: tuple[str, ...]


class _Advisor(PlanningAdvisor):
    def __init__(self, payloads: Sequence[dict[str, object]]) -> None:
        self._payloads = iter(payloads)
        self.calls = 0

    async def suggest(self, intent: TaskIntent, prior_error: StructuredTaskError | None) -> object:
        del intent, prior_error
        self.calls += 1
        return next(self._payloads)


class _Input(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)


class _Output(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)

    summary: str


class _ScenarioTool(Tool[_Input, _Output]):
    def __init__(
        self,
        tool_id: str,
        outcomes: Sequence[tuple[str, tuple[str, ...]]],
        *,
        started: asyncio.Event | None = None,
        release: asyncio.Event | None = None,
    ) -> None:
        self._tool_id = tool_id
        self._outcomes = iter(outcomes)
        self._started = started
        self._release = release
        self.calls = 0

    @property
    def manifest(self) -> ToolManifest:
        return ToolManifest(
            tool_id=self._tool_id,
            name=self._tool_id,
            description="Deterministic fake workflow tool",
            version=SemanticVersion(1, 0, 0),
            capability_tags=frozenset({"test"}),
            input_schema=_Input,
            output_schema=_Output,
            declared_permissions=frozenset(),
            supported_platforms=frozenset(
                {ToolPlatform.WINDOWS, ToolPlatform.LINUX, ToolPlatform.MACOS}
            ),
            timeout_seconds=2,
        )

    @property
    def input_model(self) -> type[_Input]:
        return _Input

    async def _execute_authorized(
        self, context: ToolExecutionContext, validated_input: _Input
    ) -> ToolResult:
        del context, validated_input
        self.calls += 1
        if self._started is not None:
            self._started.set()
        if self._release is not None:
            await self._release.wait()
        summary, evidence = next(self._outcomes)
        return ToolResult.success(
            _Output(summary=summary),
            evidence=tuple(ToolEvidence("scenario", item) for item in evidence),
        )


class _PermissionProbe(Tool[_Input, _Output]):
    executed = False

    @property
    def manifest(self) -> ToolManifest:
        return ToolManifest(
            tool_id="permission-probe",
            name="Permission probe",
            description="Fake tool that proves approval pauses execution",
            version=SemanticVersion(1, 0, 0),
            capability_tags=frozenset({"test"}),
            input_schema=_Input,
            output_schema=_Output,
            declared_permissions=frozenset({Permission.FILESYSTEM_READ}),
            supported_platforms=frozenset(
                {ToolPlatform.WINDOWS, ToolPlatform.LINUX, ToolPlatform.MACOS}
            ),
            timeout_seconds=1,
        )

    @property
    def input_model(self) -> type[_Input]:
        return _Input

    def _describe_action(
        self, context: ToolExecutionContext, validated_input: _Input
    ) -> ActionDescriptor:
        del validated_input
        return ActionDescriptor(
            action="invoke:permission-probe",
            arguments_summary=(),
            risk=Risk.LOW,
            permissions=(
                PermissionRequest(
                    Permission.FILESYSTEM_READ,
                    PermissionScope(
                        paths=(str(Path.cwd()),),
                        tool_id="permission-probe",
                        task_id=context.task_id,
                    ),
                ),
            ),
        )

    async def _execute_authorized(
        self, context: ToolExecutionContext, validated_input: _Input
    ) -> ToolResult:
        del context, validated_input
        self.executed = True
        return ToolResult.success(_Output(summary="should not execute"))


class DeterministicWorkflowEvaluator:
    """Run fixed agent scenarios; no provider, hardware, network, or OS tool is used."""

    async def evaluate(self, scenario_id: str) -> WorkflowEvaluation:
        scenarios = {
            "calculator-workflow": self._calculator,
            "permission-pause": self._permission_pause,
            "tool-failure-retry": self._tool_failure_retry,
            "cancellation": self._cancellation,
            "verification-failure": self._verification_failure,
        }
        try:
            return await scenarios[scenario_id]()
        except KeyError as error:
            raise ValueError(f"Unknown deterministic workflow scenario: {scenario_id}") from error

    async def _calculator(self) -> WorkflowEvaluation:
        advisor = _Advisor((_plan("calculator", "200", expression="25 procent van 800"),))
        task = await _orchestrator(advisor, (CalculatorTool(),), max_replans=0).submit(
            uuid4(), "calculate 25 percent of 800"
        )
        passed = task.status is TaskStatus.COMPLETED and task.result is not None
        return WorkflowEvaluation(
            "calculator-workflow", passed, "Calculator workflow completed", ("200",)
        )

    async def _permission_pause(self) -> WorkflowEvaluation:
        root = str(Path.cwd())
        policy = PolicyEngine(
            (
                PolicyRule(
                    policy_id="scenario-approval",
                    permission=Permission.FILESYSTEM_READ,
                    decision=Decision.REQUIRE_APPROVAL,
                    scope=ScopeConstraint(paths=(root,), tools=frozenset({"permission-probe"})),
                    actions=frozenset({"invoke:permission-probe"}),
                ),
            )
        )
        broker = PermissionBroker(policy)
        tool = _PermissionProbe()
        ToolRegistry((tool,), permission_broker=broker)
        result = await tool.invoke(
            ToolExecutionContext(
                task_id=uuid4(),
                correlation_id=uuid4(),
                caller=ToolCaller.TEST,
                cancellation=asyncio.Event(),
                logger=logging.getLogger("jarvis.testing.permission"),
            ),
            {},
            broker,
        )
        passed = result.status is ToolResultStatus.PERMISSION_DENIED and not tool.executed
        return WorkflowEvaluation(
            "permission-pause",
            passed,
            "Permission broker paused fake tool before execution",
            tuple(item.value for item in result.metadata),
        )

    async def _tool_failure_retry(self) -> WorkflowEvaluation:
        tool = _ScenarioTool("fake", (("transient", ("transient",)), ("done", ("done",))))
        advisor = _Advisor((_plan("fake", "done"), _plan("fake", "done")))
        task = await _orchestrator(advisor, (tool,), max_replans=1).submit(uuid4(), "retry tool")
        passed = task.status is TaskStatus.COMPLETED and tool.calls == 2 and advisor.calls == 2
        return WorkflowEvaluation(
            "tool-failure-retry",
            passed,
            "Verification failure caused one bounded replan and retry",
            ("replans=1", f"tool_calls={tool.calls}"),
        )

    async def _cancellation(self) -> WorkflowEvaluation:
        started, release = asyncio.Event(), asyncio.Event()
        tool = _ScenarioTool("fake", (("done", ("done",)),), started=started, release=release)
        orchestrator = _orchestrator(_Advisor((_plan("fake", "done"),)), (tool,), max_replans=0)
        task = await orchestrator.create_task(uuid4(), "cancel workflow")
        running = asyncio.create_task(orchestrator.run(task.task_id))
        await started.wait()
        await orchestrator.cancel(task.task_id)
        result = await running
        return WorkflowEvaluation(
            "cancellation",
            result.status is TaskStatus.CANCELLED,
            "Active fake tool workflow was cancelled",
            (result.status.value,),
        )

    async def _verification_failure(self) -> WorkflowEvaluation:
        tool = _ScenarioTool("fake", (("wrong", ("wrong",)),))
        task = await _orchestrator(
            _Advisor((_plan("fake", "done"),)), (tool,), max_replans=0
        ).submit(uuid4(), "verify workflow")
        passed = task.status is TaskStatus.FAILED and task.error is not None
        error_code = task.error.code if task.error is not None else "missing_error"
        return WorkflowEvaluation(
            "verification-failure",
            passed and error_code == "verification_failed",
            "Unverified evidence did not become success",
            (error_code,),
        )


def _orchestrator(
    advisor: _Advisor, tools: tuple[Tool[Any, Any], ...], *, max_replans: int
) -> AgentOrchestrator:
    registry = ToolRegistry(tools)
    return AgentOrchestrator(
        store=InMemoryTaskStore(),
        interpreter=DefaultRequestInterpreter(),
        planner=SchemaValidatedPlanner(advisor),
        selector=RegistryCapabilitySelector(registry),
        executor=DefaultToolExecutor(registry.permission_broker),
        observer=DefaultObservationService(),
        verifier=EvidenceVerifier(),
        response_generator=DefaultTaskResponseGenerator(),
        max_steps=4,
        timeout_seconds=2,
        max_replans=max_replans,
    )


def _plan(capability: str, expected: str, *, expression: str | None = None) -> dict[str, object]:
    arguments = [{"name": "expression", "value": expression}] if expression is not None else []
    return {
        "goal": "deterministic workflow",
        "steps": [
            {
                "capability": capability,
                "action": "run",
                "arguments": arguments,
                "depends_on": [],
                "expected_outcome": expected,
            }
        ],
    }
