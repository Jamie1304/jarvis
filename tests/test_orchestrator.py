import asyncio
from collections.abc import Sequence
from typing import Any
from uuid import UUID

import pytest
from jarvis.autonomy.execution import (
    DefaultObservationService,
    DefaultToolExecutor,
    EvidenceVerifier,
    RegistryCapabilitySelector,
)
from jarvis.autonomy.models import StructuredTaskError, Task, TaskStatus, ToolObservation
from jarvis.autonomy.orchestrator import AgentOrchestrator
from jarvis.autonomy.planning import (
    DefaultRequestInterpreter,
    PlanningAdvisor,
    SchemaValidatedPlanner,
    TaskIntent,
)
from jarvis.autonomy.response import DefaultTaskResponseGenerator
from jarvis.autonomy.store import InMemoryTaskStore
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


class ScriptedAdvisor(PlanningAdvisor):
    def __init__(self, payloads: Sequence[object]) -> None:
        self._payloads = iter(payloads)
        self.calls = 0

    async def suggest(self, intent: TaskIntent, prior_error: StructuredTaskError | None) -> object:
        del intent, prior_error
        self.calls += 1
        return next(self._payloads)


class FakeToolInput(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)


class FakeToolOutput(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)

    summary: str


class FakeTool(Tool[FakeToolInput, FakeToolOutput]):
    def __init__(
        self,
        capability_name: str,
        observations: Sequence[ToolObservation] = (),
        *,
        error: Exception | None = None,
        started: asyncio.Event | None = None,
        release: asyncio.Event | None = None,
    ) -> None:
        self._capability_name = capability_name
        self._observations = iter(observations)
        self._error = error
        self._started = started
        self._release = release
        self.calls: list[ToolExecutionContext] = []

    @property
    def manifest(self) -> ToolManifest:
        return ToolManifest(
            tool_id=self._capability_name,
            name=self._capability_name,
            description="Deterministic test tool",
            version=SemanticVersion(1, 0, 0),
            capability_tags=frozenset({"test"}),
            input_schema=FakeToolInput,
            output_schema=FakeToolOutput,
            declared_permissions=frozenset(),
            supported_platforms=frozenset(
                {ToolPlatform.WINDOWS, ToolPlatform.LINUX, ToolPlatform.MACOS}
            ),
            timeout_seconds=1.0,
        )

    @property
    def input_model(self) -> type[FakeToolInput]:
        return FakeToolInput

    async def execute(
        self, context: ToolExecutionContext, validated_input: FakeToolInput
    ) -> ToolResult:
        del validated_input
        self.calls.append(context)
        if self._started is not None:
            self._started.set()
        if self._release is not None:
            await self._release.wait()
        if self._error is not None:
            raise self._error
        observation = next(self._observations)
        return ToolResult.success(
            FakeToolOutput(summary=observation.summary),
            evidence=tuple(ToolEvidence("evidence", item) for item in observation.evidence),
        )


def payload(*steps: dict[str, object]) -> dict[str, object]:
    return {"goal": "test goal", "steps": list(steps)}


def step(
    expected: str,
    *,
    capability: str = "fake",
    depends_on: list[int] | None = None,
) -> dict[str, object]:
    return {
        "capability": capability,
        "action": "run",
        "arguments": [],
        "depends_on": depends_on or [],
        "expected_outcome": expected,
    }


def make_orchestrator(
    advisor: ScriptedAdvisor,
    tools: tuple[Tool[Any, Any], ...] = (),
    *,
    max_steps: int = 8,
    timeout_seconds: float = 1,
    max_replans: int = 1,
) -> AgentOrchestrator:
    return AgentOrchestrator(
        store=InMemoryTaskStore(),
        interpreter=DefaultRequestInterpreter(),
        planner=SchemaValidatedPlanner(advisor),
        selector=RegistryCapabilitySelector(ToolRegistry(tools)),
        executor=DefaultToolExecutor(),
        observer=DefaultObservationService(),
        verifier=EvidenceVerifier(),
        response_generator=DefaultTaskResponseGenerator(),
        max_steps=max_steps,
        timeout_seconds=timeout_seconds,
        max_replans=max_replans,
    )


async def submit(orchestrator: AgentOrchestrator) -> tuple[UUID, Task]:
    task = await orchestrator.create_task(UUID(int=1), "complete this task")
    return task.task_id, await orchestrator.run(task.task_id)


@pytest.mark.asyncio
async def test_simple_one_step_success() -> None:
    tool = FakeTool("fake", (ToolObservation("done", ("done",)),))
    orchestrator = make_orchestrator(ScriptedAdvisor((payload(step("done")),)), (tool,))

    _, result = await submit(orchestrator)

    assert result.status is TaskStatus.COMPLETED
    assert result.result is not None
    assert result.result.evidence == ("done",)


@pytest.mark.asyncio
async def test_multi_step_success_honors_dependencies() -> None:
    tool = FakeTool(
        "fake",
        (ToolObservation("first", ("first",)), ToolObservation("second", ("second",))),
    )
    orchestrator = make_orchestrator(
        ScriptedAdvisor((payload(step("first"), step("second", depends_on=[0])),)), (tool,)
    )

    _, result = await submit(orchestrator)

    assert result.status is TaskStatus.COMPLETED
    assert len(tool.calls) == 2
    assert tool.calls[1].task_id == tool.calls[0].task_id


@pytest.mark.asyncio
async def test_tool_failure_is_observable() -> None:
    tool = FakeTool("fake", error=RuntimeError("fake tool failed"))
    orchestrator = make_orchestrator(ScriptedAdvisor((payload(step("done")),)), (tool,))

    _, result = await submit(orchestrator)

    assert result.status is TaskStatus.FAILED
    assert result.error is not None
    assert result.error.code == "tool_execution_error"


@pytest.mark.asyncio
async def test_verification_failure_is_not_treated_as_success() -> None:
    tool = FakeTool("fake", (ToolObservation("wrong", ("wrong",)),))
    orchestrator = make_orchestrator(
        ScriptedAdvisor((payload(step("done")),)), (tool,), max_replans=0
    )

    _, result = await submit(orchestrator)

    assert result.status is TaskStatus.FAILED
    assert result.error is not None
    assert result.error.code == "verification_failed"


@pytest.mark.asyncio
async def test_unverifiable_observation_is_not_treated_as_success() -> None:
    tool = FakeTool("fake", (ToolObservation("no evidence"),))
    orchestrator = make_orchestrator(
        ScriptedAdvisor((payload(step("done")),)), (tool,), max_replans=0
    )

    _, result = await submit(orchestrator)

    assert result.status is TaskStatus.FAILED
    assert result.error is not None
    assert result.error.code == "verification_unverifiable"


@pytest.mark.asyncio
async def test_verification_failure_replans_then_completes() -> None:
    tool = FakeTool(
        "fake",
        (ToolObservation("wrong", ("wrong",)), ToolObservation("done", ("done",))),
    )
    advisor = ScriptedAdvisor((payload(step("done")), payload(step("done"))))
    orchestrator = make_orchestrator(advisor, (tool,), max_replans=1)

    _, result = await submit(orchestrator)

    assert result.status is TaskStatus.COMPLETED
    assert advisor.calls == 2


@pytest.mark.asyncio
async def test_maximum_step_protection_stops_task() -> None:
    tool = FakeTool(
        "fake",
        (ToolObservation("one", ("one",)), ToolObservation("two", ("two",))),
    )
    orchestrator = make_orchestrator(
        ScriptedAdvisor((payload(step("one"), step("two", depends_on=[0])),)),
        (tool,),
        max_steps=1,
    )

    _, result = await submit(orchestrator)

    assert result.status is TaskStatus.FAILED
    assert result.error is not None
    assert "maximum step count" in result.error.message


@pytest.mark.asyncio
async def test_cancellation_interrupts_active_tool() -> None:
    started = asyncio.Event()
    release = asyncio.Event()
    tool = FakeTool("fake", (ToolObservation("done", ("done",)),), started=started, release=release)
    orchestrator = make_orchestrator(ScriptedAdvisor((payload(step("done")),)), (tool,))
    task = await orchestrator.create_task(UUID(int=2), "cancel task")
    running = asyncio.create_task(orchestrator.run(task.task_id))

    await started.wait()
    await orchestrator.cancel(task.task_id)
    result = await running

    assert result.status is TaskStatus.CANCELLED
    assert result.cancellation_requested is True


@pytest.mark.asyncio
async def test_timeout_is_observable() -> None:
    started = asyncio.Event()
    release = asyncio.Event()
    tool = FakeTool("fake", (ToolObservation("done", ("done",)),), started=started, release=release)
    orchestrator = make_orchestrator(
        ScriptedAdvisor((payload(step("done")),)), (tool,), timeout_seconds=0.01
    )

    _, result = await submit(orchestrator)

    assert result.status is TaskStatus.TIMED_OUT
    assert result.error is not None
    assert result.error.code == "task_timeout"


@pytest.mark.asyncio
async def test_malformed_model_output_fails_schema_validation() -> None:
    orchestrator = make_orchestrator(ScriptedAdvisor(({"goal": 1, "steps": []},)))

    _, result = await submit(orchestrator)

    assert result.status is TaskStatus.FAILED
    assert result.error is not None
    assert result.error.code == "malformed_plan"


@pytest.mark.asyncio
async def test_unavailable_capability_fails_explicitly() -> None:
    orchestrator = make_orchestrator(
        ScriptedAdvisor((payload(step("done", capability="not_registered")),))
    )

    _, result = await submit(orchestrator)

    assert result.status is TaskStatus.FAILED
    assert result.error is not None
    assert result.error.code == "capability_unavailable"
