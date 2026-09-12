"""Tests for bounded long-horizon goal supervision."""

from __future__ import annotations

import sqlite3
from collections.abc import Callable
from dataclasses import replace
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any, cast
from uuid import uuid4

import pytest
from jarvis.capabilities import CapabilityLifecycle, CapabilityRegistry, EnvironmentGraph
from jarvis.capability_factory import (
    AdoptionCandidates,
    CapabilityFactoryResult,
    FactoryLifecycle,
    SolutionReport,
    WorkspaceContext,
)
from jarvis.discovery.models import CapabilityGap
from jarvis.goal_supervisor import (
    AlternativeKind,
    CapabilityAcquisitionReport,
    CapabilityAcquisitionRequest,
    DefaultAlternativeExaminer,
    FactoryCapabilityAcquirer,
    GoalAlternative,
    GoalAnalysis,
    GoalBudget,
    GoalBudgetExceeded,
    GoalExecutionReport,
    GoalExecutionStatus,
    GoalIntent,
    GoalResearch,
    GoalStatus,
    GoalSupervisor,
    GoalSupervisorError,
    GoalSupervisorState,
    GoalSupervisorStore,
    GoalSupervisorStoreError,
    GoalSupervisorValidationError,
    GoalUsage,
    PlanningGoalTaskRunner,
    RegistryGoalAnalyzer,
)
from jarvis.permissions.models import Risk
from jarvis.planning.models import (
    BudgetUsage,
    EffectOutcome,
    ExecutionBudgets,
    FailureKind,
    PlanningTask,
    PlanningTaskStatus,
    StepError,
)
from jarvis.task_controller import TaskController


def _gap(capability: str) -> CapabilityGap:
    return CapabilityGap(
        capability, "unknown long-horizon outcome", (capability,), (), Risk.LOW, ()
    )


def _request(gap: CapabilityGap) -> CapabilityAcquisitionRequest:
    return CapabilityAcquisitionRequest(
        gap,
        SolutionReport(gap),
        AdoptionCandidates(),
        WorkspaceContext("workspace-" + uuid4().hex[:8]),
        EnvironmentGraph(),
        {},
    )


def _task(status: PlanningTaskStatus, error: StepError | None = None) -> PlanningTask:
    now = datetime.now(UTC)
    return PlanningTask(
        uuid4(),
        "task outcome",
        (),
        (),
        status,
        None,
        ExecutionBudgets(),
        BudgetUsage(retries=1),
        now,
        now,
        now + timedelta(microseconds=1),
        now,
        error=error,
    )


class _Analyzer:
    def __init__(self, gap: CapabilityGap | None) -> None:
        self.gap = gap
        self.calls = 0

    async def analyze(self, intent: GoalIntent, registry: CapabilityRegistry) -> GoalAnalysis:
        del intent, registry
        self.calls += 1
        return GoalAnalysis(self.gap)


class _Researcher:
    def __init__(
        self, request: CapabilityAcquisitionRequest | None, usage: GoalUsage | None = None
    ) -> None:
        self.request = request
        self.usage = usage or GoalUsage()
        self.alternatives: list[str | None] = []

    async def research(
        self,
        intent: GoalIntent,
        analysis: GoalAnalysis,
        alternative: GoalAlternative | None = None,
    ) -> GoalResearch:
        del intent, analysis
        self.alternatives.append(alternative.alternative_id if alternative else None)
        return GoalResearch(self.request, self.usage)


class _Acquirer:
    def __init__(self, reports: tuple[CapabilityAcquisitionReport, ...]) -> None:
        self.reports = list(reports)
        self.calls = 0

    async def acquire(self, request: CapabilityAcquisitionRequest) -> CapabilityAcquisitionReport:
        del request
        self.calls += 1
        return self.reports.pop(0)


class _Runner:
    def __init__(self, reports: tuple[GoalExecutionReport, ...]) -> None:
        self.reports = list(reports)
        self.calls = 0
        self.intents: list[GoalIntent] = []

    async def run(self, intent: GoalIntent, budget: GoalBudget) -> GoalExecutionReport:
        assert budget.max_tokens > 0
        self.intents.append(intent)
        self.calls += 1
        return self.reports.pop(0)


class _Alternatives:
    def __init__(self, candidates: tuple[GoalAlternative, ...]) -> None:
        self.candidates = candidates
        self.calls = 0

    async def examine(
        self, intent: GoalIntent, analysis: GoalAnalysis
    ) -> tuple[GoalAlternative, ...]:
        del intent, analysis
        self.calls += 1
        return self.candidates


def _supervisor(
    tmp_path: Path,
    *,
    analyzer: _Analyzer,
    researcher: _Researcher,
    acquirer: _Acquirer,
    runner: _Runner,
    alternatives: _Alternatives | None = None,
) -> GoalSupervisor:
    return GoalSupervisor(
        registry=CapabilityRegistry(),
        store=GoalSupervisorStore(tmp_path / "goals.sqlite3"),
        analyzer=analyzer,
        researcher=researcher,
        acquirer=acquirer,
        runner=runner,
        alternatives=alternatives,
    )


@pytest.mark.asyncio
async def test_goal_preserves_original_intent_through_acquisition_and_completion(
    tmp_path: Path,
) -> None:
    capability = "unknown-" + uuid4().hex
    gap = _gap(capability)
    researcher = _Researcher(_request(gap))
    runner = _Runner(
        (
            GoalExecutionReport(
                GoalExecutionStatus.COMPLETED,
                task_id=uuid4(),
                evidence=("verified outcome",),
                detail="goal verified",
            ),
        )
    )
    supervisor = _supervisor(
        tmp_path,
        analyzer=_Analyzer(gap),
        researcher=researcher,
        acquirer=_Acquirer((CapabilityAcquisitionReport(True, capability),)),
        runner=runner,
    )
    intent = GoalIntent(
        "Reach the original user outcome",
        assumptions=("existing data is preserved",),
        constraints=("do not expose secrets",),
        required_capabilities=(capability,),
    )
    state = await supervisor.start(intent, GoalBudget(max_cost=5))
    assert state.status is GoalStatus.COMPLETED
    assert state.intent.original_outcome == intent.original_outcome
    assert runner.intents[0] == intent
    assert state.capability_id == capability
    assert "verified outcome" in state.evidence


@pytest.mark.asyncio
async def test_failed_acquisition_examines_alternatives_before_blocking(tmp_path: Path) -> None:
    gap = _gap("random-missing-" + uuid4().hex)
    alternatives = _Alternatives(())
    supervisor = _supervisor(
        tmp_path,
        analyzer=_Analyzer(gap),
        researcher=_Researcher(_request(gap)),
        acquirer=_Acquirer((CapabilityAcquisitionReport(False, detail="not compatible"),)),
        runner=_Runner(()),
        alternatives=alternatives,
    )
    state = await supervisor.start(GoalIntent("Preserve this outcome"), GoalBudget())
    assert state.status is GoalStatus.BLOCKED
    assert alternatives.calls == 1
    assert {
        AlternativeKind(item.split(":", 1)[1])
        for item in state.alternatives_examined
        if item.startswith("unavailable:")
    } == set(AlternativeKind)
    assert state.intent.original_outcome == "Preserve this outcome"


@pytest.mark.asyncio
async def test_viable_alternative_replans_and_then_executes(tmp_path: Path) -> None:
    gap = _gap("unknown-" + uuid4().hex)
    alternative = GoalAlternative(
        AlternativeKind.API_LIBRARY,
        "api-" + uuid4().hex,
        "Use a compatible local API",
        viable=True,
    )
    researcher = _Researcher(_request(gap))
    supervisor = _supervisor(
        tmp_path,
        analyzer=_Analyzer(gap),
        researcher=researcher,
        acquirer=_Acquirer(
            (
                CapabilityAcquisitionReport(False, detail="first path failed"),
                CapabilityAcquisitionReport(True, "api-capability"),
            )
        ),
        runner=_Runner((GoalExecutionReport(GoalExecutionStatus.COMPLETED, detail="verified"),)),
        alternatives=_Alternatives((alternative,)),
    )
    state = await supervisor.start(
        GoalIntent("Complete without changing the outcome"), GoalBudget()
    )
    assert state.status is GoalStatus.COMPLETED
    assert researcher.alternatives == [None, alternative.alternative_id]
    assert state.attempted_alternatives == (alternative.alternative_id,)
    assert state.usage.replans == 0


@pytest.mark.asyncio
async def test_unknown_execution_outcome_enters_recovery_without_retry(tmp_path: Path) -> None:
    runner = _Runner(
        (
            GoalExecutionReport(
                GoalExecutionStatus.RECOVERING,
                task_id=uuid4(),
                detail="external result cannot be reconciled",
                effect_outcome=EffectOutcome.UNKNOWN_OUTCOME,
            ),
        )
    )
    supervisor = _supervisor(
        tmp_path,
        analyzer=_Analyzer(None),
        researcher=_Researcher(None),
        acquirer=_Acquirer(()),
        runner=runner,
    )
    state = await supervisor.start(GoalIntent("Do not lose this intent"), GoalBudget())
    assert state.status is GoalStatus.RECOVERING
    assert runner.calls == 1


@pytest.mark.asyncio
async def test_budget_is_trusted_and_exhaustion_prevents_acquisition(tmp_path: Path) -> None:
    gap = _gap("missing-" + uuid4().hex)
    supervisor = _supervisor(
        tmp_path,
        analyzer=_Analyzer(gap),
        researcher=_Researcher(_request(gap), GoalUsage(tokens=10)),
        acquirer=_Acquirer((CapabilityAcquisitionReport(True, "unused"),)),
        runner=_Runner(()),
    )
    state = await supervisor.start(GoalIntent("Keep the budget fixed"), GoalBudget(max_tokens=5))
    assert state.status is GoalStatus.BUDGET_EXHAUSTED
    assert state.intent.original_outcome == "Keep the budget fixed"


def test_goal_intent_and_budget_survive_store_restart(tmp_path: Path) -> None:
    store = GoalSupervisorStore(tmp_path / "restart.sqlite3")
    intent = GoalIntent("Original outcome survives restart", required_capabilities=("x",))
    now = datetime.now(UTC)
    state = GoalSupervisorState(
        intent, GoalBudget(max_cost=3), GoalStatus.EXECUTING, now, now, active_run=True
    )
    store.create(state)
    store.close()
    restarted = GoalSupervisorStore(tmp_path / "restart.sqlite3")
    recovered = restarted.load(intent.goal_id)
    assert recovered is not None
    assert recovered.status is GoalStatus.RECOVERING
    assert recovered.intent.original_outcome == intent.original_outcome
    assert recovered.budget.max_cost == 3
    restarted.close()


@pytest.mark.parametrize(
    "factory",
    (
        lambda: GoalIntent(""),
        lambda: GoalIntent("x", assumptions=cast(Any, ["bad"])),
        lambda: GoalIntent("x", metadata={"bad": float("nan")}),
        lambda: GoalBudget(max_tokens=-1),
        lambda: GoalBudget(max_tokens=0),
        lambda: GoalUsage(tokens=-1),
        cast(Callable[[], Any], lambda: GoalAlternative(cast(Any, "bad"), "id", "detail")),
        lambda: GoalAlternative(AlternativeKind.TOOL, "", "detail"),
        lambda: GoalAnalysis(cast(Any, 123)),
        lambda: GoalResearch(cast(Any, 123)),
        lambda: CapabilityAcquisitionReport(cast(Any, "yes")),
        lambda: GoalExecutionReport(cast(Any, "bad")),
    ),
)
def test_supervisor_contracts_fail_closed(factory: Callable[[], Any]) -> None:
    with pytest.raises((GoalSupervisorValidationError, ValueError)):
        factory()


@pytest.mark.asyncio
async def test_registry_analyzer_and_default_alternatives_cover_unknown_fixture() -> None:
    intent = GoalIntent("unknown outcome", required_capabilities=("unknown-" + uuid4().hex,))
    analysis = await RegistryGoalAnalyzer().analyze(intent, CapabilityRegistry())
    assert analysis.capability_gap is not None
    alternatives = await DefaultAlternativeExaminer().examine(intent, analysis)
    assert {item.kind for item in alternatives} == set(AlternativeKind)


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("status", "error", "expected", "unknown"),
    (
        (PlanningTaskStatus.COMPLETED, None, GoalExecutionStatus.COMPLETED, False),
        (
            PlanningTaskStatus.WAITING_FOR_PERMISSION,
            None,
            GoalExecutionStatus.WAITING_FOR_PERMISSION,
            False,
        ),
        (
            PlanningTaskStatus.RECOVERING,
            StepError("u", "unknown", FailureKind.UNKNOWN_OUTCOME),
            GoalExecutionStatus.RECOVERING,
            True,
        ),
        (PlanningTaskStatus.BUDGET_EXHAUSTED, None, GoalExecutionStatus.BUDGET_EXHAUSTED, False),
        (
            PlanningTaskStatus.FAILED,
            StepError("t", "transient", FailureKind.TRANSIENT),
            GoalExecutionStatus.FAILED,
            False,
        ),
    ),
)
async def test_planning_runner_maps_canonical_task_outcomes(
    status: PlanningTaskStatus,
    error: StepError | None,
    expected: GoalExecutionStatus,
    unknown: bool,
) -> None:
    class Controller:
        async def submit_task(self, *args: object, **kwargs: object) -> PlanningTask:
            del args, kwargs
            return _task(status, error)

    report = await PlanningGoalTaskRunner(cast(TaskController, Controller())).run(
        GoalIntent("outcome"), GoalBudget()
    )
    assert report.status is expected
    assert (report.effect_outcome is EffectOutcome.UNKNOWN_OUTCOME) is unknown
    assert report.retry_safe is (status is PlanningTaskStatus.FAILED and not unknown)


def test_store_rejects_duplicates_mismatches_future_schema_and_bad_state(tmp_path: Path) -> None:
    path = tmp_path / "store.sqlite3"
    store = GoalSupervisorStore(path)
    now = datetime.now(UTC)
    state = GoalSupervisorState(GoalIntent("outcome"), GoalBudget(), GoalStatus.ANALYZING, now, now)
    store.create(state)
    with pytest.raises(GoalSupervisorStoreError, match="already exists"):
        store.create(state)
    with pytest.raises(GoalSupervisorStoreError, match="does not exist"):
        store.save(replace(state, intent=GoalIntent("other")))
    changed = replace(state, budget=GoalBudget(max_cost=2))
    with pytest.raises(GoalSupervisorStoreError, match="cannot be changed"):
        store.save(changed)
    with pytest.raises(GoalSupervisorStoreError, match="malformed"):
        store._connection.execute("UPDATE goal_supervisor_state SET state_json='{}'")
        store._connection.commit()
        store.load(state.intent.goal_id)
    store.close()

    future = sqlite3.connect(tmp_path / "future.sqlite3")
    future.execute(
        "CREATE TABLE goal_supervisor_schema_migrations "
        "(version INTEGER PRIMARY KEY, name TEXT NOT NULL)"
    )
    future.execute("INSERT INTO goal_supervisor_schema_migrations VALUES (99, 'future')")
    future.commit()
    future.close()
    with pytest.raises(GoalSupervisorStoreError, match="future schema"):
        GoalSupervisorStore(tmp_path / "future.sqlite3")


@pytest.mark.asyncio
async def test_waiting_goal_is_not_replayed_and_recovery_requires_explicit_reconcile(
    tmp_path: Path,
) -> None:
    intent = GoalIntent("waiting outcome")
    runner = _Runner(
        (
            GoalExecutionReport(GoalExecutionStatus.WAITING_FOR_PERMISSION, detail="approval"),
            GoalExecutionReport(GoalExecutionStatus.COMPLETED, detail="verified"),
        )
    )
    supervisor = _supervisor(
        tmp_path,
        analyzer=_Analyzer(None),
        researcher=_Researcher(None),
        acquirer=_Acquirer(()),
        runner=runner,
    )
    waiting = await supervisor.start(intent, GoalBudget())
    assert waiting.status is GoalStatus.WAITING_FOR_PERMISSION
    assert (
        await supervisor.start(intent, GoalBudget())
    ).status is GoalStatus.WAITING_FOR_PERMISSION
    assert (await supervisor.resume(intent.goal_id)).status is GoalStatus.WAITING_FOR_PERMISSION
    with pytest.raises(GoalSupervisorError, match="Unknown goal"):
        await supervisor.resume(uuid4())
    assert runner.calls == 1

    store = supervisor._store
    active = replace(waiting, status=GoalStatus.EXECUTING, active_run=True)
    store.save(active)
    recovered = store.load(intent.goal_id)
    assert recovered is not None and recovered.status is GoalStatus.RECOVERING
    assert (await supervisor.resume(intent.goal_id)).status is GoalStatus.RECOVERING
    resumed = await supervisor.resume(intent.goal_id, reconciled=True)
    assert resumed.status is GoalStatus.COMPLETED
    assert runner.calls == 2


@pytest.mark.asyncio
async def test_supervisor_rejects_restart_intent_and_propagates_analyzer_failure(
    tmp_path: Path,
) -> None:
    supervisor = _supervisor(
        tmp_path,
        analyzer=_Analyzer(None),
        researcher=_Researcher(None),
        acquirer=_Acquirer(()),
        runner=_Runner((GoalExecutionReport(GoalExecutionStatus.COMPLETED),)),
    )
    intent = GoalIntent("original")
    await supervisor.start(intent, GoalBudget())
    with pytest.raises(GoalSupervisorValidationError, match="Restart"):
        await supervisor.start(GoalIntent("changed", goal_id=intent.goal_id), GoalBudget())

    class Broken:
        async def analyze(self, intent: GoalIntent, registry: CapabilityRegistry) -> GoalAnalysis:
            del intent, registry
            raise RuntimeError("broken analyzer")

    broken = _supervisor(
        tmp_path / "broken",
        analyzer=cast(Any, Broken()),
        researcher=_Researcher(None),
        acquirer=_Acquirer(()),
        runner=_Runner(()),
    )
    with pytest.raises(RuntimeError, match="broken analyzer"):
        await broken.start(GoalIntent("broken outcome"), GoalBudget())


def test_intent_metadata_and_timestamps_are_strictly_bounded() -> None:
    intent = GoalIntent(
        "structured outcome",
        metadata={
            "enabled": True,
            "count": 2,
            "ratio": 0.5,
            "label": "safe",
            "items": (None, False, 3),
        },
    )
    assert intent.metadata == {
        "enabled": True,
        "count": 2,
        "ratio": 0.5,
        "label": "safe",
        "items": (None, False, 3),
    }
    with pytest.raises(GoalSupervisorValidationError):
        GoalIntent("naive timestamp", metadata={"nested": object()})
    with pytest.raises(GoalSupervisorValidationError):
        GoalIntent("too deep", metadata={"a": {"b": {"c": {"d": {"e": {"f": 1}}}}}})
    with pytest.raises(GoalSupervisorValidationError):
        GoalIntent("too many keys", metadata={str(index): index for index in range(65)})
    with pytest.raises(GoalSupervisorValidationError):
        GoalIntent("too many items", metadata={"items": tuple(range(65))})
    with pytest.raises(GoalSupervisorValidationError):
        GoalIntent("bad goal id", goal_id=cast(Any, "not-a-uuid"))

    now = datetime.now(UTC)
    with pytest.raises(GoalSupervisorValidationError):
        GoalSupervisorState(
            GoalIntent("naive"), GoalBudget(), GoalStatus.ANALYZING, now.replace(tzinfo=None), now
        )
    with pytest.raises(GoalSupervisorValidationError):
        GoalSupervisorState(cast(Any, object()), GoalBudget(), GoalStatus.ANALYZING, now, now)
    with pytest.raises(GoalSupervisorValidationError):
        GoalSupervisorState(GoalIntent("bad status"), GoalBudget(), cast(Any, "bad"), now, now)
    with pytest.raises(GoalSupervisorValidationError):
        GoalSupervisorState(
            GoalIntent("bad task"),
            GoalBudget(),
            GoalStatus.ANALYZING,
            now,
            now,
            task_id=cast(Any, "bad"),
        )
    with pytest.raises(GoalSupervisorValidationError):
        GoalSupervisorState(
            GoalIntent("bad active"),
            GoalBudget(),
            GoalStatus.ANALYZING,
            now,
            now,
            active_run=cast(Any, "bad"),
        )


def test_dataclass_security_contracts_reject_malformed_metadata(tmp_path: Path) -> None:
    gap = _gap("gap-" + uuid4().hex)
    with pytest.raises(GoalSupervisorValidationError):
        GoalAlternative(AlternativeKind.TOOL, "id", "detail", viable=cast(Any, "yes"))
    with pytest.raises(GoalSupervisorValidationError):
        CapabilityAcquisitionRequest(
            cast(Any, object()),
            SolutionReport(gap),
            AdoptionCandidates(),
            WorkspaceContext("w"),
            EnvironmentGraph(),
            {},
        )
    with pytest.raises(GoalSupervisorValidationError):
        CapabilityAcquisitionRequest(
            gap,
            SolutionReport(_gap("other-" + uuid4().hex)),
            AdoptionCandidates(),
            WorkspaceContext("w"),
            EnvironmentGraph(),
            {},
        )
    with pytest.raises(GoalSupervisorValidationError):
        CapabilityAcquisitionRequest(
            gap,
            SolutionReport(gap),
            cast(Any, object()),
            WorkspaceContext("w"),
            EnvironmentGraph(),
            {},
        )
    with pytest.raises(GoalSupervisorValidationError):
        CapabilityAcquisitionRequest(
            gap,
            SolutionReport(gap),
            AdoptionCandidates(),
            cast(Any, object()),
            EnvironmentGraph(),
            {},
        )
    with pytest.raises(GoalSupervisorValidationError):
        CapabilityAcquisitionRequest(
            gap,
            SolutionReport(gap),
            AdoptionCandidates(),
            WorkspaceContext("w"),
            cast(Any, object()),
            {},
        )
    with pytest.raises(GoalSupervisorValidationError):
        GoalExecutionReport(GoalExecutionStatus.FAILED, task_id=cast(Any, "bad"))
    with pytest.raises(GoalSupervisorValidationError):
        GoalExecutionReport(GoalExecutionStatus.FAILED, retry_safe=cast(Any, "yes"))

    store = GoalSupervisorStore(tmp_path / "state.sqlite3")
    now = datetime.now(UTC)
    state = GoalSupervisorState(GoalIntent("list me"), GoalBudget(), GoalStatus.COMPLETED, now, now)
    store.create(state)
    assert store.list() == (state,)
    store.close()


@pytest.mark.asyncio
async def test_registry_known_capability_and_factory_lifecycle_adapter() -> None:
    class Manifest:
        lifecycle = CapabilityLifecycle.ACTIVE
        capability_id = "known-capability"
        name = "Known capability"

    class Registry:
        def manifests(self) -> tuple[Manifest, ...]:
            return (Manifest(),)

    known = await RegistryGoalAnalyzer().analyze(
        GoalIntent("known", required_capabilities=("known-capability",)),
        cast(Any, Registry()),
    )
    assert known.capability_gap is None
    assert known.known_capabilities == ("known-capability",)

    class Factory:
        def __init__(self, lifecycle: FactoryLifecycle) -> None:
            self.lifecycle = lifecycle

        async def acquire(self, *args: object, **kwargs: object) -> CapabilityFactoryResult:
            del args, kwargs
            gap = _gap("factory-" + uuid4().hex)
            return CapabilityFactoryResult(
                uuid4(),
                gap,
                self.lifecycle,
                None,
                "active-id" if self.lifecycle is FactoryLifecycle.ACTIVE else None,
                reason="factory result",
            )

    gap = _gap("factory-gap-" + uuid4().hex)
    request = _request(gap)
    active = await FactoryCapabilityAcquirer(cast(Any, Factory(FactoryLifecycle.ACTIVE))).acquire(
        request
    )
    assert active.active is True
    assert active.capability_id == "active-id"
    inactive = await FactoryCapabilityAcquirer(
        cast(Any, Factory(FactoryLifecycle.DECLINED))
    ).acquire(request)
    assert inactive.active is False
    assert inactive.capability_id is None


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("status", "expected"),
    (
        (GoalExecutionStatus.WAITING_FOR_PERMISSION, GoalStatus.WAITING_FOR_PERMISSION),
        (GoalExecutionStatus.BUDGET_EXHAUSTED, GoalStatus.BUDGET_EXHAUSTED),
    ),
)
async def test_supervisor_preserves_permission_and_budget_stops(
    tmp_path: Path, status: GoalExecutionStatus, expected: GoalStatus
) -> None:
    supervisor = _supervisor(
        tmp_path,
        analyzer=_Analyzer(None),
        researcher=_Researcher(None),
        acquirer=_Acquirer(()),
        runner=_Runner((GoalExecutionReport(status, detail="stop"),)),
    )
    state = await supervisor.start(GoalIntent("bounded stop"), GoalBudget())
    assert state.status is expected
    assert state.last_error == "stop"


@pytest.mark.asyncio
async def test_supervisor_rejects_malformed_stage_results_and_alternatives(tmp_path: Path) -> None:
    class BadAnalyzer:
        async def analyze(self, intent: GoalIntent, registry: CapabilityRegistry) -> object:
            del intent, registry
            return object()

    supervisor = _supervisor(
        tmp_path / "analyzer",
        analyzer=cast(Any, BadAnalyzer()),
        researcher=_Researcher(None),
        acquirer=_Acquirer(()),
        runner=_Runner(()),
    )
    with pytest.raises(GoalSupervisorValidationError, match="analyzer"):
        await supervisor.start(GoalIntent("bad analyzer"), GoalBudget())

    class BadAlternatives:
        async def examine(self, intent: GoalIntent, analysis: GoalAnalysis) -> tuple[object, ...]:
            del intent, analysis
            return (object(),)

    supervisor = _supervisor(
        tmp_path / "alternatives",
        analyzer=_Analyzer(_gap("missing-" + uuid4().hex)),
        researcher=_Researcher(None),
        acquirer=_Acquirer(()),
        runner=_Runner(()),
        alternatives=cast(Any, BadAlternatives()),
    )
    with pytest.raises(GoalSupervisorValidationError, match="[Aa]lternative examiner"):
        await supervisor.start(GoalIntent("bad alternatives"), GoalBudget())


def test_budget_checks_cover_every_trusted_ceiling(tmp_path: Path) -> None:
    supervisor = _supervisor(
        tmp_path / "nested",
        analyzer=_Analyzer(None),
        researcher=_Researcher(None),
        acquirer=_Acquirer(()),
        runner=_Runner(()),
    )
    now = datetime.now(UTC)
    limits = (
        ("tokens", replace(GoalUsage(), tokens=2), replace(GoalBudget(), max_tokens=1)),
        ("cost", replace(GoalUsage(), cost=2), replace(GoalBudget(), max_cost=1)),
        ("retries", replace(GoalUsage(), retries=2), replace(GoalBudget(), max_retries=1)),
        ("replans", replace(GoalUsage(), replans=2), replace(GoalBudget(), max_replans=1)),
        ("disk", replace(GoalUsage(), disk_bytes=2), replace(GoalBudget(), max_disk_bytes=1)),
        (
            "network",
            replace(GoalUsage(), network_bytes=2),
            replace(GoalBudget(), max_network_bytes=1),
        ),
        ("risk", replace(GoalUsage(), risk=Risk.HIGH), replace(GoalBudget(), max_risk=Risk.LOW)),
    )
    for name, usage, budget in limits:
        state = GoalSupervisorState(
            GoalIntent("budget " + name), budget, GoalStatus.ANALYZING, now, now, usage=usage
        )
        with pytest.raises(GoalBudgetExceeded, match=name):
            supervisor._check_budget(state)
    expired = GoalSupervisorState(
        GoalIntent("expired"),
        replace(GoalBudget(), max_elapsed_seconds=1),
        GoalStatus.ANALYZING,
        now - timedelta(seconds=2),
        now,
    )
    with pytest.raises(GoalBudgetExceeded, match="time"):
        supervisor._check_budget(expired)
