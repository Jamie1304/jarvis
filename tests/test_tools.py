import asyncio
from uuid import uuid4

import pytest
from jarvis.autonomy.execution import (
    DefaultObservationService,
    DefaultToolExecutor,
    EvidenceVerifier,
    RegistryCapabilitySelector,
)
from jarvis.autonomy.models import StructuredTaskError
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
from jarvis.tools.calculator import CalculatorTool
from jarvis.tools.catalog import create_safe_tool_registry
from jarvis.tools.harness import ToolHarness
from jarvis.tools.local_time import LocalTimeTool
from jarvis.tools.models import (
    SemanticVersion,
    ToolExecutionContext,
    ToolManifest,
    ToolPlatform,
    ToolResult,
    ToolResultStatus,
)
from jarvis.tools.registry import ToolRegistry
from jarvis.tools.weather import UnavailableWeatherTool
from pydantic import BaseModel, ConfigDict


class StaticAdvisor(PlanningAdvisor):
    def __init__(self, payload: object) -> None:
        self._payload = payload

    async def suggest(self, intent: TaskIntent, prior_error: StructuredTaskError | None) -> object:
        del intent, prior_error
        return self._payload


class ProbeInput(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)

    value: str


class ProbeOutput(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)

    value: str


class ProbeTool(Tool[ProbeInput, ProbeOutput]):
    def __init__(
        self,
        *,
        delay_seconds: float = 0,
        timeout_seconds: float = 1,
        raises: bool = False,
        error_message: str = "test implementation failure",
    ) -> None:
        self.delay_seconds = delay_seconds
        self.timeout_seconds = timeout_seconds
        self.raises = raises
        self.error_message = error_message
        self.executions = 0

    @property
    def manifest(self) -> ToolManifest:
        return ToolManifest(
            tool_id="probe",
            name="Probe",
            description="Deterministic tool contract probe.",
            version=SemanticVersion(1, 0, 0),
            capability_tags=frozenset({"test"}),
            input_schema=ProbeInput,
            output_schema=ProbeOutput,
            declared_permissions=frozenset(),
            supported_platforms=frozenset(
                {ToolPlatform.WINDOWS, ToolPlatform.LINUX, ToolPlatform.MACOS}
            ),
            timeout_seconds=self.timeout_seconds,
        )

    @property
    def input_model(self) -> type[ProbeInput]:
        return ProbeInput

    async def _execute_authorized(
        self, context: ToolExecutionContext, validated_input: ProbeInput
    ) -> ToolResult:
        del context
        self.executions += 1
        if self.delay_seconds:
            await asyncio.sleep(self.delay_seconds)
        if self.raises:
            raise RuntimeError(self.error_message)
        return ToolResult.success(ProbeOutput(value=validated_input.value))


@pytest.mark.asyncio
async def test_calculator_successfully_evaluates_dutch_percentage() -> None:
    result = await ToolHarness().invoke(CalculatorTool(), {"expression": "25 procent van 800"})

    assert result.status is ToolResultStatus.SUCCESS
    assert result.output is not None
    assert result.output.model_dump()["result"] == "200"
    assert any(item.value == "200" for item in result.evidence)


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("expression", "expected"),
    [("1 + 2 * 3", "7"), ("-2", "-2"), ("1.5 + 2.5", "4")],
)
async def test_calculator_evaluates_basic_arithmetic(expression: str, expected: str) -> None:
    result = await ToolHarness().invoke(CalculatorTool(), {"expression": expression})

    assert result.status is ToolResultStatus.SUCCESS
    assert result.output is not None
    assert result.output.model_dump()["result"] == expected


@pytest.mark.asyncio
@pytest.mark.parametrize("expression", ["1 / 0", "True", "unknown()"])
async def test_calculator_rejects_unsafe_or_invalid_expressions(expression: str) -> None:
    result = await ToolHarness().invoke(CalculatorTool(), {"expression": expression})

    assert result.status is ToolResultStatus.EXPECTED_FAILURE
    assert result.error is not None
    assert result.error.code == "invalid_expression"


@pytest.mark.asyncio
async def test_tool_rejects_unknown_and_invalid_input_before_execution() -> None:
    tool = ProbeTool()
    harness = ToolHarness()

    unknown = await harness.invoke(tool, {"value": "ok", "unexpected": "blocked"})
    invalid_type = await harness.invoke(tool, {"value": 3})

    assert unknown.status is ToolResultStatus.VALIDATION_ERROR
    assert invalid_type.status is ToolResultStatus.VALIDATION_ERROR
    assert tool.executions == 0


@pytest.mark.asyncio
async def test_tool_timeout_returns_structured_result() -> None:
    result = await ToolHarness().invoke(
        ProbeTool(delay_seconds=0.1, timeout_seconds=0.01), {"value": "slow"}
    )

    assert result.status is ToolResultStatus.TIMEOUT
    assert result.error is not None
    assert result.error.code == "tool_timeout"


@pytest.mark.asyncio
async def test_tool_cancellation_interrupts_execution() -> None:
    cancellation = asyncio.Event()
    tool = ProbeTool(delay_seconds=1, timeout_seconds=2)
    invocation = asyncio.create_task(
        ToolHarness().invoke(tool, {"value": "cancel"}, cancellation=cancellation)
    )

    await asyncio.sleep(0)
    cancellation.set()
    result = await invocation

    assert result.status is ToolResultStatus.CANCELLED


@pytest.mark.asyncio
async def test_unavailable_weather_tool_is_explicit() -> None:
    result = await ToolHarness().invoke(UnavailableWeatherTool(), {"location": "Amsterdam"})

    assert result.status is ToolResultStatus.UNAVAILABLE
    assert result.error is not None
    assert result.error.code == "tool_unavailable"


@pytest.mark.asyncio
async def test_safe_registry_exposes_versioned_manifests_and_health() -> None:
    registry = create_safe_tool_registry()
    manifests = registry.manifests()
    health = await registry.health()

    assert {manifest.tool_id for manifest in manifests} == {"calculator", "local_time", "weather"}
    assert str(next(item for item in manifests if item.tool_id == "calculator").version) == "1.0.0"
    assert dict(health)["weather"].status.value == "unavailable"


@pytest.mark.asyncio
async def test_local_time_tool_returns_typed_local_time() -> None:
    result = await ToolHarness().invoke(LocalTimeTool(), {})

    assert result.status is ToolResultStatus.SUCCESS
    assert result.output is not None
    assert "local_time" in result.output.model_dump()


@pytest.mark.asyncio
async def test_raw_tool_failure_becomes_structured_internal_failure(
    caplog: pytest.LogCaptureFixture,
) -> None:
    secret = "credential-value-must-not-be-logged"
    tool = ProbeTool(raises=True, error_message=secret)
    result = await ToolHarness().invoke(tool, {"value": "fail"})

    assert result.status is ToolResultStatus.INTERNAL_FAILURE
    assert result.error is not None
    assert result.error.code == "tool_internal_failure"
    assert secret not in caplog.text


@pytest.mark.asyncio
async def test_orchestrator_executes_registered_calculator_and_verifies_200() -> None:
    advisor = StaticAdvisor(
        {
            "goal": "Calculate 25 percent of 800",
            "steps": [
                {
                    "capability": "calculator",
                    "action": "calculate",
                    "arguments": [{"name": "expression", "value": "25 procent van 800"}],
                    "depends_on": [],
                    "expected_outcome": "200",
                }
            ],
        }
    )
    registry = ToolRegistry((CalculatorTool(),))
    orchestrator = AgentOrchestrator(
        store=InMemoryTaskStore(),
        interpreter=DefaultRequestInterpreter(),
        planner=SchemaValidatedPlanner(advisor),
        selector=RegistryCapabilitySelector(registry),
        executor=DefaultToolExecutor(registry.permission_broker),
        observer=DefaultObservationService(),
        verifier=EvidenceVerifier(),
        response_generator=DefaultTaskResponseGenerator(),
        max_steps=2,
        timeout_seconds=1,
        max_replans=0,
    )

    task = await orchestrator.submit(
        conversation_id=uuid4(),
        user_request="Wat is 25 procent van 800?",
    )

    assert task.status.value == "completed"
    assert task.result is not None
    assert "200" in task.result.evidence
