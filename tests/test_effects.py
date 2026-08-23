"""Tests for typed effect previews, Plan Studio projection, and compensation."""

from __future__ import annotations

from collections.abc import Mapping
from datetime import UTC, datetime, timedelta
from typing import cast
from uuid import UUID, uuid4

import pytest
from jarvis.capabilities import Reversibility
from jarvis.effects import (
    CompensationDefinition,
    CompensationExecutor,
    CompensationRequest,
    CompensationResult,
    CompensationStatus,
    EffectError,
    EffectPreview,
    EffectTraceRecord,
    PlanStudioEffectProjection,
)
from jarvis.permissions.models import Permission, PermissionRequest, PermissionScope
from jarvis.planning.editing import PlanInspection, PlanStepView
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
from jarvis.verification import EvidenceRecord, EvidenceType, VerificationLevel, VerificationPlan
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
