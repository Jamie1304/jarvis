"""Tests for typed effect previews, Plan Studio projection, and compensation."""

from __future__ import annotations

import hashlib
from collections.abc import Callable, Mapping
from dataclasses import replace
from datetime import UTC, datetime, timedelta
from pathlib import Path
from types import SimpleNamespace
from typing import Any, cast
from uuid import UUID, uuid4

import pytest
from jarvis.capabilities import Reversibility
from jarvis.effects import (
    CompensationDefinition,
    CompensationExecutor,
    CompensationObservationPhase,
    CompensationObservationUnavailable,
    CompensationRequest,
    CompensationResult,
    CompensationService,
    CompensationStateObservation,
    CompensationStatus,
    CompensationStore,
    EffectError,
    EffectPreview,
    EffectStateObserverRegistry,
    EffectTraceRecord,
    FilesystemStateObserver,
    OriginalEffectReference,
    PlanStudioEffectProjection,
)
from jarvis.permissions.models import Permission, PermissionRequest, PermissionScope
from jarvis.planning.editing import PlanInspection, PlanStepView
from jarvis.planning.engine import PlanningEngine
from jarvis.planning.models import (
    BudgetUsage,
    ExecutionBudgets,
    OwnedPlanStatus,
    PlanningStepStatus,
    PlanningTaskStatus,
)
from jarvis.tools.base import Tool
from jarvis.tools.models import (
    SemanticVersion,
    ToolEffectDisposition,
    ToolEvidence,
    ToolExecutionContext,
    ToolHealth,
    ToolHealthStatus,
    ToolManifest,
    ToolPlatform,
    ToolResult,
    ToolResultStatus,
)
from jarvis.tools.registry import ToolRegistry
from jarvis.verification import (
    EvidenceRecord,
    EvidenceType,
    VerificationEngine,
    VerificationLevel,
    VerificationPlan,
)
from pydantic import BaseModel, ConfigDict

NOW = datetime(2026, 8, 23, 12, tzinfo=UTC)
BASELINE = "a" * 64


class _Input(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)

    value: str


class _Output(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)

    value: str


class _CompensationTool(Tool[_Input, _Output]):
    def __init__(self, result: ToolResult | None = None) -> None:
        self.calls = 0
        self.result = result
        self.raise_error = False

    @property
    def manifest(self) -> ToolManifest:
        return ToolManifest(
            "restore.tool",
            "Restore",
            "Restore a value",
            SemanticVersion(1, 0, 0),
            frozenset({"restore"}),
            _Input,
            _Output,
            frozenset(),
            frozenset({ToolPlatform.WINDOWS, ToolPlatform.LINUX, ToolPlatform.MACOS}),
            1.0,
        )

    @property
    def input_model(self) -> type[_Input]:
        return _Input

    async def health_check(self) -> ToolHealth:
        return ToolHealth(ToolHealthStatus.AVAILABLE, "available")

    async def _execute_authorized(
        self, context: ToolExecutionContext, validated_input: _Input
    ) -> ToolResult:
        del context
        self.calls += 1
        if self.raise_error:
            raise RuntimeError("provider failure")
        if self.result is not None:
            return self.result
        return ToolResult.success(
            _Output(value=validated_input.value),
            evidence=(ToolEvidence("restore", "tool returned"),),
        )


class _Trace:
    def __init__(self) -> None:
        self.records: list[EffectTraceRecord] = []

    async def record(self, trace: EffectTraceRecord) -> None:
        self.records.append(trace)


def verification() -> VerificationPlan:
    return VerificationPlan(
        "Restore the prior value",
        ("restored",),
        frozenset({EvidenceType.API}),
        VerificationLevel.INTEGRATION_VERIFIED,
    )


def definition() -> CompensationDefinition:
    return CompensationDefinition(
        "restore",
        "restore.tool",
        {"value": "old"},
        verification(),
        ("revision",),
    )


def preview(
    *,
    target: str = "settings.json",
    expected_change: dict[str, object] | None = None,
    resources: object = ("disk",),
    reversibility: Reversibility = Reversibility.COMPENSATABLE,
    compensation: CompensationDefinition | None = None,
    baseline: str | None = BASELINE,
    include_compensation: bool = True,
) -> EffectPreview:
    return EffectPreview(
        target,
        expected_change or {"operation": "write", "before": "old", "after": "new"},
        cast(tuple[str, ...], resources),
        (PermissionRequest(Permission.FILESYSTEM_WRITE, PermissionScope()),),
        reversibility,
        ("settings.json",),
        verification(),
        compensation
        if compensation is not None
        else definition()
        if include_compensation
        else None,
        uuid4(),
        baseline,
    )


def request(effect: EffectPreview, *, current: str = BASELINE) -> CompensationRequest:
    return CompensationRequest(
        uuid4(),
        uuid4(),
        uuid4(),
        effect,
        current,
        {"revision": 7}
        if effect.compensation is not None and effect.compensation.prior_state_fields
        else None,
        (
            EvidenceRecord(
                EvidenceType.API,
                "restore.check",
                NOW,
                timedelta(minutes=5),
                1.0,
                "restored",
                "restored",
                level=VerificationLevel.INTEGRATION_VERIFIED,
            ),
        ),
    )


def test_effect_preview_and_compensation_definition_are_typed() -> None:
    effect = preview(compensation=definition())
    assert effect.reversibility is Reversibility.COMPENSATABLE
    assert effect.can_offer_undo
    assert len(effect.fingerprint) == 64
    assert definition().fingerprint != ""
    with pytest.raises(EffectError):
        EffectPreview.from_model_prose("The model says this can be undone")
    with pytest.raises(EffectError):
        preview(
            reversibility=Reversibility.COMPENSATABLE,
            compensation=None,
            include_compensation=False,
        )


def test_irreversible_and_unknown_never_offer_undo() -> None:
    for kind in (Reversibility.READ_ONLY, Reversibility.IRREVERSIBLE, Reversibility.UNKNOWN):
        effect = preview(reversibility=kind)
        assert not effect.can_offer_undo


def test_preview_rejects_secret_state_and_untyped_permissions() -> None:
    with pytest.raises(EffectError):
        EffectPreview(
            "settings.json",
            {"operation": "write"},
            (),
            (cast(PermissionRequest, Permission.FILESYSTEM_WRITE),),
            Reversibility.IRREVERSIBLE,
            (),
            verification(),
        )
    with pytest.raises(EffectError):
        CompensationDefinition("restore", "restore.tool", {"token": "secret"}, verification())
    with pytest.raises(EffectError):
        CompensationRequest(
            uuid4(), uuid4(), uuid4(), preview(), "not-a-hash", prior_state={"revision": 1}
        )


def test_plan_studio_projection_exposes_only_real_undo_paths() -> None:
    inspection = PlanInspection(
        uuid4(),
        uuid4(),
        1,
        "restore",
        (),
        PlanningTaskStatus.READY,
        OwnedPlanStatus.READY,
        (
            PlanStepView(
                "restore",
                PlanningStepStatus.QUEUED,
                (),
                "restore.tool",
                "mutation",
                (),
                (),
                (),
                (),
                (),
            ),
        ),
        ("restore",),
        (),
        ("restored",),
        (),
        ExecutionBudgets(),
        BudgetUsage(),
        (),
        NOW,
    )
    effect = preview(compensation=definition())
    projected = PlanStudioEffectProjection.project(inspection, {"restore": effect})
    assert projected[0].undo_available
    with pytest.raises(EffectError):
        PlanStudioEffectProjection.project(inspection, {"unknown": effect})


@pytest.mark.asyncio
async def test_compensation_uses_tool_registry_verification_and_trace() -> None:
    tool = _CompensationTool()
    trace = _Trace()
    executor = CompensationExecutor(ToolRegistry((tool,)), trace=trace, clock=lambda: NOW)
    result = await executor.compensate(request(preview(compensation=definition())))
    assert result.status is CompensationStatus.VERIFIED
    assert result.verification is not None and result.verification.passed
    assert tool.calls == 1
    assert len(trace.records) == 2
    assert result.trace_event_ids


@pytest.mark.asyncio
async def test_stale_state_stops_compensation_before_tool_execution() -> None:
    tool = _CompensationTool()
    executor = CompensationExecutor(ToolRegistry((tool,)), clock=lambda: NOW)
    result = await executor.compensate(
        request(preview(compensation=definition()), current="b" * 64)
    )
    assert result.status is CompensationStatus.STALE_STATE
    assert tool.calls == 0


@pytest.mark.asyncio
async def test_missing_baseline_and_missing_prior_state_are_explicit() -> None:
    tool = _CompensationTool()
    executor = CompensationExecutor(ToolRegistry((tool,)), clock=lambda: NOW)
    no_baseline = await executor.compensate(
        request(preview(compensation=definition(), baseline=None))
    )
    assert no_baseline.status is CompensationStatus.STALE_STATE
    assert tool.calls == 0
    no_prior = CompensationRequest(
        uuid4(), uuid4(), uuid4(), preview(compensation=definition()), BASELINE, None
    )
    missing = await executor.compensate(no_prior)
    assert missing.status is CompensationStatus.STALE_STATE
    assert tool.calls == 0


@pytest.mark.asyncio
async def test_failed_and_unverified_compensation_are_not_success() -> None:
    failed_tool = _CompensationTool(
        ToolResult.failure(
            ToolResultStatus.EXPECTED_FAILURE,
            "restore_failed",
            "restore failed",
            effect_disposition=ToolEffectDisposition.NO_EFFECT,
        )
    )
    failed = await CompensationExecutor(ToolRegistry((failed_tool,)), clock=lambda: NOW).compensate(
        request(preview(compensation=definition()))
    )
    assert failed.status is CompensationStatus.FAILED

    unverified_tool = _CompensationTool()
    unverified = CompensationRequest(
        uuid4(), uuid4(), uuid4(), preview(compensation=definition()), BASELINE, {"revision": 7}
    )
    result = await CompensationExecutor(
        ToolRegistry((unverified_tool,)), clock=lambda: NOW
    ).compensate(unverified)
    assert result.status is CompensationStatus.VERIFICATION_FAILED


def test_result_and_trace_contracts_are_bounded() -> None:
    result = CompensationResult(uuid4(), CompensationStatus.FAILED, "explicit failure")
    assert result.status is CompensationStatus.FAILED
    trace = EffectTraceRecord(
        "compensation.completed",
        uuid4(),
        uuid4(),
        uuid4(),
        BASELINE,
        "failed",
        NOW,
    )
    assert trace.recorded_at == NOW
    with pytest.raises(EffectError):
        EffectTraceRecord("event", uuid4(), uuid4(), uuid4(), "bad", "failed", NOW)


def test_preview_request_result_and_trace_validation_rejects_malformed_values() -> None:
    for bad in ("", "line\nfeed"):
        with pytest.raises(EffectError):
            preview(target=bad)
        with pytest.raises(EffectError):
            preview(resources=cast(tuple[str, ...], ["disk"]))
    with pytest.raises(EffectError):
        preview(resources=("disk",) * 65)
    with pytest.raises(EffectError):
        EffectPreview(
            "target",
            {},
            (),
            (),
            Reversibility.READ_ONLY,
            (),
            verification(),
        )
    with pytest.raises(EffectError):
        EffectPreview(
            "target",
            cast(Mapping[str, object], []),
            (),
            (),
            Reversibility.READ_ONLY,
            (),
            verification(),
        )
    with pytest.raises(EffectError):
        EffectPreview(
            "target",
            {"operation": "read"},
            (),
            tuple(
                PermissionRequest(Permission.FILESYSTEM_READ, PermissionScope()) for _ in range(65)
            ),
            Reversibility.READ_ONLY,
            (),
            verification(),
        )
    with pytest.raises(EffectError):
        EffectPreview(
            "target",
            {"operation": "read"},
            (),
            (),
            cast(Reversibility, "bad"),
            (),
            verification(),
        )
    with pytest.raises(EffectError):
        EffectPreview(
            "target",
            {"operation": "read"},
            (),
            (),
            Reversibility.READ_ONLY,
            (),
            cast(VerificationPlan, "bad"),
        )
    with pytest.raises(EffectError):
        EffectPreview(
            "target",
            {"operation": "read"},
            (),
            (),
            Reversibility.READ_ONLY,
            (),
            verification(),
            cast(CompensationDefinition, "bad"),
        )
    with pytest.raises(EffectError):
        EffectPreview(
            "target",
            {"operation": "read"},
            (),
            (),
            Reversibility.READ_ONLY,
            (),
            verification(),
            effect_id=cast(UUID, "bad"),
        )
    with pytest.raises(EffectError):
        preview(baseline="bad")


def test_malformed_compensation_definition_and_request_inputs() -> None:
    with pytest.raises(EffectError):
        CompensationDefinition("cap", "tool", cast(Mapping[str, object], []), verification())
    with pytest.raises(EffectError):
        CompensationDefinition("cap", "tool", {}, cast(VerificationPlan, "bad"))
    with pytest.raises(EffectError):
        CompensationDefinition("cap", "tool", {}, verification(), ("same", "same"))
    effect = preview(compensation=definition())
    with pytest.raises(EffectError):
        CompensationRequest(cast(UUID, "bad"), uuid4(), uuid4(), effect, BASELINE)
    with pytest.raises(EffectError):
        CompensationRequest(uuid4(), uuid4(), cast(UUID, "bad"), effect, BASELINE)
    with pytest.raises(EffectError):
        CompensationRequest(uuid4(), uuid4(), uuid4(), effect, BASELINE, {"other": 1})
    with pytest.raises(EffectError):
        CompensationRequest(uuid4(), uuid4(), uuid4(), effect, BASELINE, {})
    with pytest.raises(EffectError):
        CompensationRequest(
            uuid4(),
            uuid4(),
            uuid4(),
            effect,
            BASELINE,
            {"revision": 1},
            (cast(EvidenceRecord, "bad"),),
        )
    with pytest.raises(EffectError):
        CompensationResult(cast(UUID, "bad"), CompensationStatus.FAILED, "failed")
    with pytest.raises(EffectError):
        CompensationResult(
            uuid4(), CompensationStatus.FAILED, "failed", approval_request_ids=(cast(UUID, "bad"),)
        )
    with pytest.raises(EffectError):
        CompensationResult(
            uuid4(), CompensationStatus.FAILED, "failed", trace_event_ids=(cast(UUID, "bad"),)
        )
    with pytest.raises(EffectError):
        EffectTraceRecord("event", cast(UUID, "bad"), uuid4(), uuid4(), BASELINE, "failed", NOW)
    with pytest.raises(EffectError):
        EffectTraceRecord("event", uuid4(), uuid4(), cast(UUID, "bad"), BASELINE, "failed", NOW)
    with pytest.raises(EffectError):
        EffectTraceRecord(
            "event", uuid4(), uuid4(), uuid4(), BASELINE, "failed", NOW.replace(tzinfo=None)
        )


def test_safe_preview_values_are_bounded() -> None:
    with pytest.raises(EffectError):
        preview(expected_change=cast(dict[str, object], {"value": float("nan")}))
    with pytest.raises(EffectError):
        preview(expected_change=cast(dict[str, object], {"secret": "value"}))
    deep: object = "leaf"
    for _ in range(7):
        deep = {"nested": deep}
    with pytest.raises(EffectError):
        preview(expected_change=cast(dict[str, object], {"nested": deep}))
    with pytest.raises(EffectError):
        preview(expected_change=cast(dict[str, object], {str(index): index for index in range(65)}))
    with pytest.raises(EffectError):
        preview(expected_change=cast(dict[str, object], {"items": list(range(65))}))
    with pytest.raises(EffectError):
        preview(expected_change=cast(dict[str, object], {"value": object()}))


@pytest.mark.asyncio
async def test_compensation_executor_rejects_unavailable_and_unknown_paths() -> None:
    with pytest.raises(EffectError):
        CompensationExecutor(cast(ToolRegistry, object()))
    with pytest.raises(EffectError):
        await CompensationExecutor(ToolRegistry()).compensate(cast(CompensationRequest, object()))
    no_undo = await CompensationExecutor(ToolRegistry()).compensate(
        request(preview(reversibility=Reversibility.REVERSIBLE, include_compensation=False))
    )
    assert no_undo.status is CompensationStatus.NOT_AVAILABLE

    missing_definition = CompensationDefinition(
        "missing", "missing.tool", {"value": "old"}, verification()
    )
    missing = await CompensationExecutor(ToolRegistry()).compensate(
        request(preview(compensation=missing_definition))
    )
    assert missing.status is CompensationStatus.NOT_AVAILABLE

    mismatch_definition = CompensationDefinition(
        "wrong", "restore.tool", {"value": "old"}, verification()
    )
    mismatch_tool = _CompensationTool()
    mismatch = await CompensationExecutor(ToolRegistry((mismatch_tool,))).compensate(
        request(preview(compensation=mismatch_definition))
    )
    assert mismatch.status is CompensationStatus.NOT_AVAILABLE
    assert mismatch_tool.calls == 0


@pytest.mark.asyncio
async def test_compensation_permission_unknown_observation_and_trace_failure() -> None:
    denied_tool = _CompensationTool(
        ToolResult.failure(ToolResultStatus.PERMISSION_DENIED, "denied", "denied")
    )
    denied = await CompensationExecutor(ToolRegistry((denied_tool,)), clock=lambda: NOW).compensate(
        request(preview(compensation=definition()))
    )
    assert denied.status is CompensationStatus.DENIED

    unknown_tool = _CompensationTool(
        ToolResult.failure(ToolResultStatus.UNKNOWN_OUTCOME, "unknown", "unknown")
    )
    unknown = await CompensationExecutor(
        ToolRegistry((unknown_tool,)), clock=lambda: NOW
    ).compensate(request(preview(compensation=definition())))
    assert unknown.status is CompensationStatus.UNKNOWN_OUTCOME

    raising_tool = _CompensationTool()
    raising_tool.raise_error = True
    raised = await CompensationExecutor(
        ToolRegistry((raising_tool,)), clock=lambda: NOW
    ).compensate(request(preview(compensation=definition())))
    assert raised.status is CompensationStatus.UNKNOWN_OUTCOME

    async def observation_failure(
        _request: CompensationRequest, _result: ToolResult
    ) -> tuple[EvidenceRecord, ...]:
        raise RuntimeError("observation failed")

    observed = await CompensationExecutor(
        ToolRegistry((_CompensationTool(),)),
        observation_provider=observation_failure,
        clock=lambda: NOW,
    ).compensate(request(preview(compensation=definition())))
    assert observed.status is CompensationStatus.UNKNOWN_OUTCOME

    class BrokenTrace:
        async def record(self, trace: EffectTraceRecord) -> None:
            del trace
            raise RuntimeError("trace unavailable")

    traced = await CompensationExecutor(
        ToolRegistry((_CompensationTool(),)), trace=BrokenTrace(), clock=lambda: NOW
    ).compensate(request(preview(compensation=definition())))
    assert traced.status is CompensationStatus.VERIFIED


class _PlanningStub:
    def __init__(
        self,
        *,
        created_status: PlanningTaskStatus = PlanningTaskStatus.READY,
        final_status: PlanningTaskStatus = PlanningTaskStatus.COMPLETED,
    ) -> None:
        self.created_status = created_status
        self.final_status = final_status
        self.tasks: dict[UUID, Any] = {}

    def get_task(self, task_id: UUID) -> Any | None:
        return self.tasks.get(task_id)

    async def create_proposal_task(self, *_args: object, **_kwargs: object) -> Any:
        task = SimpleNamespace(
            task_id=uuid4(),
            status=self.created_status,
            waiting_request_ids=(
                (uuid4(),)
                if self.created_status is PlanningTaskStatus.WAITING_FOR_PERMISSION
                else ()
            ),
        )
        self.tasks[task.task_id] = task
        return task

    async def run(self, task_id: UUID, **_kwargs: object) -> Any:
        task = self.tasks[task_id]
        task.status = self.final_status
        return task

    async def resume(self, task_id: UUID, **_kwargs: object) -> Any:
        return await self.run(task_id)


class _ServiceTrace:
    def __init__(self, *, fail_bind: bool = False, fail_record: bool = False) -> None:
        self.fail_bind = fail_bind
        self.fail_record = fail_record

    def bind_goal_task(self, _goal_id: UUID, _task_id: UUID) -> None:
        if self.fail_bind:
            raise RuntimeError("synthetic trace projection failure")

    def record(self, *_args: object, **_kwargs: object) -> Any:
        if self.fail_record:
            raise RuntimeError("synthetic trace write failure")
        return SimpleNamespace(event_id=uuid4())


def _service_request(
    *,
    state: str = BASELINE,
    request_id: UUID | None = None,
    task_id: UUID | None = None,
    original_task_id: UUID | None = None,
    effect: EffectPreview | None = None,
    target: str | None = None,
) -> CompensationRequest:
    selected_effect = effect or preview(compensation=definition())
    selected_task_id = task_id or uuid4()
    selected_target = target or selected_effect.target
    original = OriginalEffectReference(
        selected_effect.effect_id,
        selected_effect.fingerprint,
        original_task_id or selected_task_id,
        uuid4(),
        1,
        uuid4(),
        "restore.tool",
        "restore",
        selected_target,
        selected_target,
        ("canonical-step-evidence",),
        "verification:canonical-step",
    )
    return CompensationRequest(
        request_id or uuid4(),
        selected_task_id,
        uuid4(),
        selected_effect,
        state,
        original_effect=original,
    )


async def _empty_observation(*_args: object) -> tuple[EvidenceRecord, ...]:
    return ()


class _BoundStateObserver:
    def __init__(
        self,
        request: CompensationRequest,
        *,
        target: str | None = None,
        observed_at: datetime = NOW,
    ) -> None:
        assert request.original_effect is not None
        self.request = request
        self.target = target or request.original_effect.target
        self.observed_at = observed_at

    async def observe(
        self,
        request: CompensationRequest,
        phase: CompensationObservationPhase,
    ) -> CompensationStateObservation:
        del phase
        assert request.original_effect is not None
        return CompensationStateObservation(
            request.request_id,
            request.effect.effect_id,
            request.task_id,
            request.original_effect.tool_id,
            request.original_effect.capability,
            self.target,
            BASELINE,
            (),
            self.observed_at,
            "synthetic.trusted.observer",
        )


@pytest.mark.asyncio
async def test_compensation_observer_registry_binds_and_rejects_forged_state() -> None:
    request = _service_request()
    assert request.original_effect is not None
    registry = EffectStateObserverRegistry()
    registry.register_tool(request.original_effect.tool_id, _BoundStateObserver(request))
    registry.seal()
    observation = await registry.observe(
        request,
        CompensationObservationPhase.BEFORE,
        now=NOW,
    )
    assert observation.state_fingerprint == BASELINE
    assert registry.sealed
    with pytest.raises(CompensationObservationUnavailable):
        await EffectStateObserverRegistry().observe(
            request,
            CompensationObservationPhase.BEFORE,
            now=NOW,
        )

    forged = EffectStateObserverRegistry()
    forged.register_tool(
        request.original_effect.tool_id,
        _BoundStateObserver(request, target="wrong-target"),
    )
    forged.seal()
    with pytest.raises(CompensationObservationUnavailable):
        await forged.observe(request, CompensationObservationPhase.BEFORE, now=NOW)


@pytest.mark.asyncio
async def test_compensation_observer_registry_fails_closed_for_malformed_stale_and_unavailable(
    tmp_path: Path,
) -> None:
    request = _service_request()
    assert request.original_effect is not None

    class MalformedObserver:
        async def observe(
            self, _request: CompensationRequest, _phase: CompensationObservationPhase
        ) -> object:
            return object()

    class RaisingObserver:
        async def observe(
            self, _request: CompensationRequest, _phase: CompensationObservationPhase
        ) -> CompensationStateObservation:
            raise RuntimeError("synthetic trusted observer failure")

    class UnavailableObserver:
        async def observe(
            self, _request: CompensationRequest, _phase: CompensationObservationPhase
        ) -> CompensationStateObservation:
            raise CompensationObservationUnavailable("synthetic unavailable")

    for provider in (MalformedObserver(), RaisingObserver(), UnavailableObserver()):
        registry = EffectStateObserverRegistry()
        registry.register_tool(request.original_effect.tool_id, provider)  # type: ignore[arg-type]
        registry.seal()
        with pytest.raises(CompensationObservationUnavailable):
            await registry.observe(request, CompensationObservationPhase.BEFORE, now=NOW)

    stale = EffectStateObserverRegistry()
    stale.register_tool(
        request.original_effect.tool_id,
        _BoundStateObserver(request, observed_at=NOW - timedelta(minutes=10)),
    )
    stale.seal()
    with pytest.raises(CompensationObservationUnavailable):
        await stale.observe(request, CompensationObservationPhase.BEFORE, now=NOW)
    future = EffectStateObserverRegistry()
    future.register_tool(
        request.original_effect.tool_id,
        _BoundStateObserver(request, observed_at=NOW + timedelta(minutes=10)),
    )
    future.seal()
    with pytest.raises(CompensationObservationUnavailable):
        await future.observe(request, CompensationObservationPhase.BEFORE, now=NOW)

    duplicate = EffectStateObserverRegistry()
    duplicate.register_tool(request.original_effect.tool_id, _BoundStateObserver(request))
    with pytest.raises(EffectError):
        duplicate.register_tool(request.original_effect.tool_id, _BoundStateObserver(request))
    duplicate.register_capability("restore", _BoundStateObserver(request))
    with pytest.raises(EffectError):
        duplicate.register_capability("restore", _BoundStateObserver(request))
    duplicate.seal()
    assert duplicate.has_observer(tool_id=request.original_effect.tool_id, capability="other")
    assert not duplicate.has_observer(tool_id="other", capability="other")
    with pytest.raises(EffectError):
        duplicate.register_tool("other", _BoundStateObserver(request))
    with pytest.raises(EffectError):
        duplicate.register_capability("other", _BoundStateObserver(request))

    with pytest.raises(EffectError):
        await duplicate.observe(object(), CompensationObservationPhase.BEFORE, now=NOW)  # type: ignore[arg-type]
    no_original = CompensationRequest(
        request.request_id,
        request.task_id,
        request.correlation_id,
        request.effect,
        request.current_state_fingerprint,
    )
    with pytest.raises(CompensationObservationUnavailable):
        await duplicate.observe(no_original, CompensationObservationPhase.BEFORE, now=NOW)

    with pytest.raises(EffectError):
        duplicate.register_tool("bad", object())  # type: ignore[arg-type]
    with pytest.raises(EffectError):
        duplicate.register_capability("bad", object())  # type: ignore[arg-type]

    valid_registry = EffectStateObserverRegistry()
    valid_registry.register_tool(request.original_effect.tool_id, _BoundStateObserver(request))
    valid_registry.seal()
    valid_observation = await valid_registry.observe(
        request,
        CompensationObservationPhase.BEFORE,
        now=NOW,
    )
    malformed_factories: tuple[Callable[[], object], ...] = (
        lambda: replace(valid_observation, request_id=cast(Any, "bad")),
        lambda: replace(valid_observation, evidence=cast(Any, [])),
        lambda: replace(valid_observation, observed_at=datetime.now()),
    )
    for malformed_factory in malformed_factories:
        with pytest.raises(EffectError):
            malformed_factory()

    state_file = tmp_path / "state.txt"
    state_file.write_text("bounded", encoding="utf-8")
    filesystem_request = _service_request(
        effect=preview(target=str(state_file)),
        target=str(state_file),
    )
    filesystem = FilesystemStateObserver((tmp_path,))
    filesystem_registry = EffectStateObserverRegistry()
    filesystem_registry.register_tool("restore.tool", filesystem)
    filesystem_registry.seal()
    observed = await filesystem_registry.observe(
        filesystem_request,
        CompensationObservationPhase.BEFORE,
        now=datetime.now(UTC),
    )
    assert observed.state_fingerprint == hashlib.sha256(b"bounded").hexdigest()

    with pytest.raises(EffectError):
        FilesystemStateObserver(())
    with pytest.raises(EffectError):
        FilesystemStateObserver((tmp_path / "missing",))
    with pytest.raises(EffectError):
        FilesystemStateObserver((state_file,))
    with pytest.raises(EffectError):
        FilesystemStateObserver((tmp_path,), max_bytes=0)
    with pytest.raises(EffectError):
        FilesystemStateObserver((tmp_path,), max_bytes=4 * 1024 * 1024 + 1)
    missing_request = _service_request(
        effect=preview(target=str(tmp_path / "missing.txt")),
        target=str(tmp_path / "missing.txt"),
    )
    with pytest.raises(CompensationObservationUnavailable):
        await filesystem.observe(missing_request, CompensationObservationPhase.BEFORE)
    outside_path = tmp_path.parent / "outside.txt"
    outside_path.write_text("outside", encoding="utf-8")
    outside = _service_request(
        effect=preview(target=str(outside_path)),
        target=str(outside_path),
    )
    with pytest.raises(CompensationObservationUnavailable):
        await filesystem.observe(outside, CompensationObservationPhase.BEFORE)
    with pytest.raises(CompensationObservationUnavailable):
        await filesystem.observe(no_original, CompensationObservationPhase.BEFORE)
    small = FilesystemStateObserver((tmp_path,), max_bytes=1)
    with pytest.raises(CompensationObservationUnavailable):
        await small.observe(filesystem_request, CompensationObservationPhase.BEFORE)


@pytest.mark.asyncio
async def test_compensation_service_reports_unavailable_trusted_observation(tmp_path: Path) -> None:
    request = _service_request()
    service = _new_service(tmp_path, _PlanningStub(), state_provider=None)
    service._observer_registry = EffectStateObserverRegistry()
    unavailable = await service.compensate(request)
    assert unavailable.status is CompensationStatus.OBSERVATION_UNAVAILABLE
    assert unavailable.planning_task_id is None
    service.close()

    class AfterUnavailableObserver(_BoundStateObserver):
        async def observe(
            self,
            observed_request: CompensationRequest,
            phase: CompensationObservationPhase,
        ) -> CompensationStateObservation:
            if phase is CompensationObservationPhase.AFTER:
                raise CompensationObservationUnavailable("synthetic after observation unavailable")
            return await super().observe(observed_request, phase)

    observed_service = _new_service(tmp_path, _PlanningStub(), state_provider=None)
    registry = EffectStateObserverRegistry()
    assert request.original_effect is not None
    registry.register_tool(
        request.original_effect.tool_id,
        AfterUnavailableObserver(request),
    )
    registry.seal()
    observed_service._observer_registry = registry
    after_unavailable = await observed_service.compensate(request)
    assert after_unavailable.status is CompensationStatus.OBSERVATION_UNAVAILABLE
    assert after_unavailable.planning_task_id is not None
    observed_service.close()


def _new_service(
    tmp_path: Path,
    planning: _PlanningStub,
    *,
    state_provider: Any = lambda _request: BASELINE,
    observation_provider: Any = None,
    trace: Any = None,
) -> CompensationService:
    service: Any = object.__new__(CompensationService)
    service._planning = planning
    service._registry = SimpleNamespace(
        inspect=lambda _tool_id: SimpleNamespace(
            manifest=SimpleNamespace(declared_permissions=frozenset())
        )
    )
    service._verification = VerificationEngine()
    service._store = CompensationStore(tmp_path / f"compensation-{uuid4().hex}.sqlite3")
    service._observation_provider = observation_provider
    service._state_provider = state_provider
    service._trace = trace
    service._clock = lambda: NOW
    return cast(CompensationService, service)


def test_compensation_service_rejects_malformed_dependencies(tmp_path: Path) -> None:
    store = CompensationStore(tmp_path / "malformed.sqlite3")
    with pytest.raises(EffectError):
        CompensationService(object(), ToolRegistry(), VerificationEngine(), store)  # type: ignore[arg-type]
    with pytest.raises(EffectError):
        CompensationService(
            cast(Any, object.__new__(PlanningEngine)),
            ToolRegistry(),
            object(),  # type: ignore[arg-type]
            store,
        )
    store.close()


@pytest.mark.asyncio
async def test_compensation_service_fail_closed_paths_and_durable_idempotency(
    tmp_path: Path,
) -> None:
    malformed = _service_request()
    no_reference = CompensationRequest(
        malformed.request_id,
        malformed.task_id,
        malformed.correlation_id,
        malformed.effect,
        malformed.current_state_fingerprint,
    )
    service = _new_service(tmp_path, _PlanningStub())
    with pytest.raises(EffectError):
        await service.compensate(no_reference)

    mismatched = _service_request()
    mismatched_reference = OriginalEffectReference(
        mismatched.effect.effect_id,
        "b" * 64,
        mismatched.task_id,
        uuid4(),
        1,
        uuid4(),
        "restore.tool",
        "restore",
        "settings.json",
        "settings.json",
        ("proof",),
        "verification",
    )
    mismatched = CompensationRequest(
        mismatched.request_id,
        mismatched.task_id,
        mismatched.correlation_id,
        mismatched.effect,
        mismatched.current_state_fingerprint,
        original_effect=mismatched_reference,
    )
    result = await service.compensate(mismatched)
    assert result.status is CompensationStatus.STALE_STATE

    task_id = uuid4()
    step_id = uuid4()
    bind_task = SimpleNamespace(status=PlanningTaskStatus.COMPLETED)
    bind_plan = SimpleNamespace(
        version=1,
        plan_id=uuid4(),
        steps=(
            SimpleNamespace(
                step_id=step_id,
                status=PlanningStepStatus.SUCCEEDED,
                result=SimpleNamespace(evidence=("proof",)),
                tool_id="restore.tool",
                capability="restore",
            ),
        ),
    )
    bind_planning = SimpleNamespace(
        get_task=lambda _task_id: bind_task,
        inspect_plan=lambda _task_id: bind_plan,
    )
    cast(Any, service)._planning = bind_planning
    with pytest.raises(EffectError):
        service.bind_original_effect(
            preview(reversibility=Reversibility.REVERSIBLE, include_compensation=False),
            task_id=task_id,
            plan_revision=1,
            step_id=step_id,
            target="settings.json",
            scope="settings.json",
        )
    with pytest.raises(EffectError):
        service.bind_original_effect(
            preview(),
            task_id=task_id,
            plan_revision=2,
            step_id=step_id,
            target="settings.json",
            scope="settings.json",
        )
    bind_task.status = PlanningTaskStatus.FAILED
    with pytest.raises(EffectError):
        service.bind_original_effect(
            preview(),
            task_id=task_id,
            plan_revision=1,
            step_id=step_id,
            target="settings.json",
            scope="settings.json",
        )
    bind_task.status = PlanningTaskStatus.COMPLETED
    bind_plan.version = 1
    bind_plan.steps = (SimpleNamespace(step_id=step_id, status=PlanningStepStatus.QUEUED),)
    with pytest.raises(EffectError):
        service.bind_original_effect(
            preview(),
            task_id=task_id,
            plan_revision=1,
            step_id=step_id,
            target="settings.json",
            scope="settings.json",
        )
    bind_plan.steps = (
        SimpleNamespace(
            step_id=step_id,
            status=PlanningStepStatus.SUCCEEDED,
            result=SimpleNamespace(evidence=()),
            tool_id="restore.tool",
            capability="restore",
        ),
    )
    with pytest.raises(EffectError):
        service.bind_original_effect(
            preview(),
            task_id=task_id,
            plan_revision=1,
            step_id=step_id,
            target="settings.json",
            scope="settings.json",
        )
    no_undo_effect = preview(reversibility=Reversibility.REVERSIBLE, include_compensation=False)
    no_undo_request = _service_request(effect=no_undo_effect)
    assert (await service.compensate(no_undo_request)).status is CompensationStatus.NOT_AVAILABLE
    with pytest.raises(EffectError):
        cast(Any, service)._proposal(no_undo_request)
    assert (
        await service.compensate(_service_request(original_task_id=uuid4()))
    ).status is CompensationStatus.STALE_STATE
    service.close()

    async def raising_observation(*_args: object) -> tuple[EvidenceRecord, ...]:
        raise RuntimeError("synthetic observer failure")

    scenarios = (
        (
            _PlanningStub(final_status=PlanningTaskStatus.WAITING_FOR_PERMISSION),
            None,
            CompensationStatus.PERMISSION_REQUIRED,
        ),
        (
            _PlanningStub(created_status=PlanningTaskStatus.RECOVERING),
            None,
            CompensationStatus.UNKNOWN_OUTCOME,
        ),
        (
            _PlanningStub(final_status=PlanningTaskStatus.FAILED),
            None,
            CompensationStatus.FAILED,
        ),
        (
            _PlanningStub(final_status=PlanningTaskStatus.RECOVERING),
            None,
            CompensationStatus.UNKNOWN_OUTCOME,
        ),
        (_PlanningStub(), None, CompensationStatus.VERIFICATION_FAILED),
        (_PlanningStub(), raising_observation, CompensationStatus.UNKNOWN_OUTCOME),
        (_PlanningStub(), _empty_observation, CompensationStatus.VERIFICATION_FAILED),
    )
    for index, (planning, observer, expected) in enumerate(scenarios):
        trace = _ServiceTrace(fail_bind=index == 4, fail_record=index == 5)
        scenario = _new_service(
            tmp_path,
            planning,
            observation_provider=observer,
            trace=trace,
        )
        request_value = _service_request()
        outcome = await scenario.compensate(request_value)
        assert outcome.status is expected
        repeated = await scenario.compensate(request_value)
        assert repeated.status is expected
        scenario.close()

    def failing_state(_request: CompensationRequest) -> str:
        raise RuntimeError("synthetic state observer failure")

    state_failure = _new_service(tmp_path, _PlanningStub(), state_provider=failing_state)
    assert (
        await state_failure.compensate(_service_request())
    ).status is CompensationStatus.STALE_STATE
    state_failure.close()

    denied_state = _new_service(tmp_path, _PlanningStub(), state_provider=None)
    assert (
        await denied_state.compensate(_service_request())
    ).status is CompensationStatus.STALE_STATE
    denied_state.close()

    terminal = _new_service(tmp_path, _PlanningStub(), observation_provider=_empty_observation)
    terminal_request = _service_request()
    terminal_result = await terminal.compensate(terminal_request)
    changed = CompensationRequest(
        terminal_request.request_id,
        terminal_request.task_id,
        terminal_request.correlation_id,
        terminal_request.effect,
        "c" * 64,
        original_effect=terminal_request.original_effect,
    )
    assert (await terminal.compensate(changed)).status is CompensationStatus.STALE_STATE
    assert terminal_result.status is CompensationStatus.VERIFICATION_FAILED
    terminal.close()
