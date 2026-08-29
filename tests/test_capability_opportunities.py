from __future__ import annotations

import json
import sqlite3
from collections.abc import Callable
from dataclasses import replace
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import cast
from uuid import UUID, uuid4

import pytest
from jarvis.capabilities import EnvironmentGraph
from jarvis.capability_factory import (
    AdoptionCandidates,
    FactoryStrategy,
    SolutionOption,
    SolutionReport,
    WorkspaceContext,
)
from jarvis.capability_opportunities import (
    CapabilityOpportunity,
    CapabilityOpportunityEngine,
    CapabilityOpportunityError,
    InMemoryOpportunityStore,
    OpportunityDecision,
    OpportunityEvidence,
    OpportunityEvidenceSource,
    OpportunityPreparationProvider,
    OpportunityPreparationResult,
    OpportunityPreparationState,
    OpportunityStatus,
    SQLiteOpportunityStore,
    validate_opportunity_state,
)
from jarvis.discovery.models import CapabilityGap
from jarvis.goal_supervisor import (
    CapabilityAcquisitionReport,
    CapabilityAcquisitionRequest,
)
from jarvis.permissions.models import Risk

NOW = datetime(2026, 1, 1, tzinfo=UTC)


class _Preparation:
    async def prepare(self, opportunity: object) -> OpportunityPreparationResult:
        del opportunity
        return OpportunityPreparationResult(
            OpportunityPreparationState.READY,
            "Read-only research and sandbox preparation completed",
            ("desktop owner approval required",),
            ("preparation:synthetic-evidence",),
        )


class _Acquisition:
    def __init__(self, *, active: bool = True) -> None:
        self.active = active
        self.requests: list[CapabilityAcquisitionRequest] = []

    async def acquire(self, request: CapabilityAcquisitionRequest) -> CapabilityAcquisitionReport:
        self.requests.append(request)
        return CapabilityAcquisitionReport(
            self.active,
            request.gap.desired_capability if self.active else None,
            detail="normal acquisition delegated",
        )


class _FailingPreparation:
    def __init__(self) -> None:
        self.calls = 0

    async def prepare(self, opportunity: object) -> OpportunityPreparationResult:
        del opportunity
        self.calls += 1
        raise RuntimeError("synthetic preparation failure")


class _RetryPreparation:
    def __init__(self) -> None:
        self.calls = 0

    async def prepare(self, opportunity: object) -> OpportunityPreparationResult:
        del opportunity
        self.calls += 1
        if self.calls == 1:
            raise RuntimeError("synthetic retryable failure")
        return OpportunityPreparationResult(
            OpportunityPreparationState.READY,
            "synthetic retry succeeded",
            evidence_references=("preparation:retry-success",),
        )


class _FailedResultPreparation:
    async def prepare(self, opportunity: object) -> OpportunityPreparationResult:
        del opportunity
        return OpportunityPreparationResult(
            OpportunityPreparationState.FAILED,
            "synthetic review failure with retained evidence",
            evidence_references=("preparation:failed",),
        )


class _StatePreparation:
    def __init__(self, state: OpportunityPreparationState) -> None:
        self.state = state

    async def prepare(self, opportunity: object) -> OpportunityPreparationResult:
        del opportunity
        return OpportunityPreparationResult(self.state, "synthetic preparation state")


class _SecurityBlockingPreparation:
    def __init__(self) -> None:
        self.calls = 0

    async def prepare(self, opportunity: object) -> OpportunityPreparationResult:
        del opportunity
        self.calls += 1
        return OpportunityPreparationResult(
            OpportunityPreparationState.SECURITY_BLOCKED,
            "Trusted policy blocked autonomous preparation",
            evidence_references=("security:block",),
        )


class _FailingAcquisition(_Acquisition):
    def __init__(self) -> None:
        super().__init__()
        self.calls = 0

    async def acquire(self, request: CapabilityAcquisitionRequest) -> CapabilityAcquisitionReport:
        del request
        self.calls += 1
        raise RuntimeError("synthetic acquisition failure")


class _UnreconciledStore(InMemoryOpportunityStore):
    """Synthetic store that lets proposal/accept tests exercise defense in depth."""

    def get(self, opportunity_id: UUID) -> CapabilityOpportunity | None:
        item = self._items.get(opportunity_id)
        return item[0] if item is not None else None


def _request(goal_id: UUID | None = None) -> CapabilityAcquisitionRequest:
    gap = CapabilityGap(
        "opportunity-capability",
        "Provide the recurring capability",
        ("safe generic adapter",),
        (),
        Risk.LOW,
        (),
    )
    solution = SolutionReport(
        gap,
        (
            SolutionOption(
                "reuse-existing",
                FactoryStrategy.REUSE_API_LIBRARY_MCP_CLI,
                gap.desired_capability,
            ),
        ),
    )
    return CapabilityAcquisitionRequest(
        gap,
        solution,
        AdoptionCandidates(),
        WorkspaceContext("workspace-opportunity"),
        EnvironmentGraph(),
        {},
        goal_id=goal_id,
    )


def _evidence(
    *references: str,
    source: OpportunityEvidenceSource = OpportunityEvidenceSource.REPEATED_WORKFLOW,
    confidence: float = 0.9,
    observed_at: datetime = NOW,
) -> tuple[OpportunityEvidence, ...]:
    return tuple(
        OpportunityEvidence(
            source, reference, "Synthetic verified evidence", confidence, observed_at, True
        )
        for reference in references
    )


def _engine(
    store: InMemoryOpportunityStore | SQLiteOpportunityStore,
    acquisition: _Acquisition | None = None,
    *,
    clock: list[datetime] | None = None,
    preparation: OpportunityPreparationProvider | None = None,
) -> CapabilityOpportunityEngine:
    ticks = clock if clock is not None else [NOW]
    return CapabilityOpportunityEngine(
        store,
        acquisition or _Acquisition(),
        preparation=preparation or _Preparation(),
        clock=lambda: ticks[0],
    )


def _observe(
    engine: CapabilityOpportunityEngine, evidence: tuple[OpportunityEvidence, ...]
) -> CapabilityOpportunity | None:
    return engine.observe(
        "Provide the recurring capability",
        evidence,
        expected_benefit="Reduce repeated manual work",
        privacy_impact="No additional personal data required",
        estimated_resource_cost="Small bounded preparation",
        likely_required_authority=("desktop owner approval",),
        workspace="workspace-opportunity",
    )


def test_repeated_workflow_creates_opportunity() -> None:
    engine = _engine(InMemoryOpportunityStore())

    opportunity = _observe(engine, _evidence("workflow:one", "workflow:two"))

    assert opportunity is not None
    assert opportunity.status is OpportunityStatus.DETECTED
    assert opportunity.confidence == pytest.approx(0.9)


def test_weak_single_observation_does_not_create_opportunity() -> None:
    engine = _engine(InMemoryOpportunityStore())

    assert _observe(engine, _evidence("workflow:one")) is None
    assert _observe(engine, _evidence("workflow:two", confidence=0.4)) is None


@pytest.mark.asyncio
async def test_safe_preparation_survives_restart(tmp_path: Path) -> None:
    path = tmp_path / "opportunities.sqlite3"
    store = SQLiteOpportunityStore(path)
    engine = _engine(store)
    opportunity = _observe(engine, _evidence("workflow:one", "workflow:two"))
    assert opportunity is not None

    prepared = await engine.prepare(opportunity.opportunity_id)
    assert prepared.status is OpportunityStatus.READY_TO_PROPOSE
    assert prepared.preparation_state is OpportunityPreparationState.READY
    store.close()

    restored_store = SQLiteOpportunityStore(path)
    restored = _engine(restored_store).get(opportunity.opportunity_id)
    restored_store.close()
    assert restored.status is OpportunityStatus.READY_TO_PROPOSE
    assert restored.prepared_summary.startswith("Read-only research")
    assert "desktop owner approval required" in restored.remaining_authority


@pytest.mark.asyncio
async def test_accept_requires_typed_normal_acquisition_request() -> None:
    acquisition = _Acquisition()
    engine = _engine(InMemoryOpportunityStore(), acquisition)
    opportunity = _observe(engine, _evidence("workflow:one", "workflow:two"))
    assert opportunity is not None
    await engine.prepare(opportunity.opportunity_id)

    with pytest.raises(CapabilityOpportunityError):
        await engine.accept(
            opportunity.opportunity_id, cast(CapabilityAcquisitionRequest, object())
        )
    assert acquisition.requests == []


@pytest.mark.asyncio
async def test_accept_delegates_to_canonical_acquisition_path() -> None:
    acquisition = _Acquisition()
    engine = _engine(InMemoryOpportunityStore(), acquisition)
    opportunity = _observe(engine, _evidence("workflow:one", "workflow:two"))
    assert opportunity is not None
    await engine.prepare(opportunity.opportunity_id)

    report = await engine.accept(opportunity.opportunity_id, _request(uuid4()))

    assert report.active
    assert len(acquisition.requests) == 1
    assert engine.get(opportunity.opportunity_id).status is OpportunityStatus.ACTIVE


@pytest.mark.asyncio
async def test_non_active_acquisition_waits_without_granting_authority() -> None:
    acquisition = _Acquisition(active=False)
    engine = _engine(InMemoryOpportunityStore(), acquisition)
    opportunity = _observe(engine, _evidence("workflow:one", "workflow:two"))
    assert opportunity is not None
    await engine.prepare(opportunity.opportunity_id)

    report = await engine.accept(opportunity.opportunity_id, _request())

    assert not report.active
    restored = engine.get(opportunity.opportunity_id)
    assert restored.status is OpportunityStatus.ACTIVATING
    assert restored.preparation_state is OpportunityPreparationState.WAITING_FOR_AUTHORITY


def test_decline_cooldown_and_new_evidence() -> None:
    clock = [NOW]
    engine = _engine(
        InMemoryOpportunityStore(),
        clock=clock,
    )
    opportunity = _observe(engine, _evidence("workflow:one", "workflow:two"))
    assert opportunity is not None
    declined = engine.decline(opportunity.opportunity_id)
    assert declined.status is OpportunityStatus.DECLINED

    assert _observe(engine, _evidence("workflow:one", "workflow:two")) is declined
    clock[0] += timedelta(days=8)
    refreshed = _observe(engine, _evidence("workflow:one", "workflow:three"))

    assert refreshed is not None
    assert refreshed.status is OpportunityStatus.DETECTED
    assert "workflow:three" in refreshed.evidence_references


@pytest.mark.asyncio
async def test_preparation_without_provider_and_proposal_state() -> None:
    engine = _engine(
        InMemoryOpportunityStore(),
        acquisition=_Acquisition(),
    )
    opportunity = _observe(engine, _evidence("workflow:one", "workflow:two"))
    assert opportunity is not None
    prepared = await engine.prepare(opportunity.opportunity_id)
    assert prepared.preparation_state is OpportunityPreparationState.READY
    proposal = engine.proposal(opportunity.opportunity_id)
    assert proposal.opportunity_id == opportunity.opportunity_id
    assert engine.proposal(opportunity.opportunity_id).benefit == proposal.benefit


@pytest.mark.asyncio
async def test_failed_preparation_and_acquisition_are_recorded() -> None:
    preparation_store = InMemoryOpportunityStore()
    preparation_engine = CapabilityOpportunityEngine(
        preparation_store,
        _Acquisition(),
        preparation=_FailingPreparation(),
        clock=lambda: NOW,
    )
    opportunity = _observe(preparation_engine, _evidence("workflow:one", "workflow:two"))
    assert opportunity is not None
    with pytest.raises(CapabilityOpportunityError):
        await preparation_engine.prepare(opportunity.opportunity_id)
    failed = preparation_engine.get(opportunity.opportunity_id)
    assert failed.status is OpportunityStatus.FAILED
    assert failed.preparation_state is OpportunityPreparationState.FAILED
    assert failed.last_error == "preparation failed: RuntimeError"
    with pytest.raises(CapabilityOpportunityError):
        preparation_engine.proposal(opportunity.opportunity_id)
    with pytest.raises(CapabilityOpportunityError):
        await preparation_engine.accept(opportunity.opportunity_id, _request())

    acquisition = _FailingAcquisition()
    engine = _engine(InMemoryOpportunityStore(), acquisition)
    opportunity = _observe(engine, _evidence("workflow:one", "workflow:two"))
    assert opportunity is not None
    await engine.prepare(opportunity.opportunity_id)
    with pytest.raises(CapabilityOpportunityError):
        await engine.accept(opportunity.opportunity_id, _request())
    assert engine.get(opportunity.opportunity_id).status is OpportunityStatus.FAILED
    assert (
        engine.get(opportunity.opportunity_id).preparation_state
        is OpportunityPreparationState.FAILED
    )
    with pytest.raises(CapabilityOpportunityError):
        engine.proposal(opportunity.opportunity_id)
    with pytest.raises(CapabilityOpportunityError):
        await engine.accept(opportunity.opportunity_id, _request())


@pytest.mark.asyncio
async def test_failed_preparation_stays_failed_when_observed_again() -> None:
    store = InMemoryOpportunityStore()
    preparation = _FailingPreparation()
    engine = CapabilityOpportunityEngine(
        store,
        _Acquisition(),
        preparation=preparation,
        clock=lambda: NOW,
    )
    opportunity = _observe(engine, _evidence("observe-failed:one", "observe-failed:two"))
    assert opportunity is not None
    with pytest.raises(CapabilityOpportunityError):
        await engine.prepare(opportunity.opportunity_id)

    failed = engine.get(opportunity.opportunity_id)
    revision = store.revision(opportunity.opportunity_id)
    same_evidence = _observe(engine, _evidence("observe-failed:one", "observe-failed:two"))
    assert same_evidence is not None
    assert same_evidence.status is OpportunityStatus.FAILED
    assert same_evidence.preparation_state is OpportunityPreparationState.FAILED
    assert same_evidence.decision is OpportunityDecision.PREPARE
    assert same_evidence.last_error == failed.last_error
    assert same_evidence.evidence_references == failed.evidence_references
    assert store.revision(opportunity.opportunity_id) == revision + 1

    new_evidence = _observe(
        engine,
        _evidence("observe-failed:one", "observe-failed:two", "observe-failed:three"),
    )
    assert new_evidence is not None
    assert new_evidence.status is OpportunityStatus.FAILED
    assert new_evidence.preparation_state is OpportunityPreparationState.FAILED
    assert new_evidence.last_error == failed.last_error
    assert "observe-failed:three" in new_evidence.evidence_references
    assert preparation.calls == 1
    with pytest.raises(CapabilityOpportunityError):
        engine.proposal(opportunity.opportunity_id)
    with pytest.raises(CapabilityOpportunityError):
        await engine.accept(opportunity.opportunity_id, _request())


@pytest.mark.asyncio
async def test_failed_preparation_observation_stays_failed_after_two_restarts(
    tmp_path: Path,
) -> None:
    path = tmp_path / "failed-preparation-observation.sqlite3"
    preparation = _FailingPreparation()
    store = SQLiteOpportunityStore(path)
    engine = CapabilityOpportunityEngine(
        store,
        _Acquisition(),
        preparation=preparation,
        clock=lambda: NOW,
    )
    opportunity = _observe(engine, _evidence("restart-observe:one", "restart-observe:two"))
    assert opportunity is not None
    with pytest.raises(CapabilityOpportunityError):
        await engine.prepare(opportunity.opportunity_id)
    first_failed = engine.get(opportunity.opportunity_id)
    first_revision = store.revision(opportunity.opportunity_id)
    store.close()

    first_restart_store = SQLiteOpportunityStore(path)
    first_restart = CapabilityOpportunityEngine(
        first_restart_store,
        _Acquisition(),
        preparation=preparation,
        clock=lambda: NOW,
    )
    observed = _observe(
        first_restart,
        _evidence("restart-observe:one", "restart-observe:two", "restart-observe:three"),
    )
    assert observed is not None
    assert observed.status is OpportunityStatus.FAILED
    assert observed.preparation_state is OpportunityPreparationState.FAILED
    assert observed.last_error == first_failed.last_error
    assert "restart-observe:three" in observed.evidence_references
    assert first_restart_store.revision(opportunity.opportunity_id) == first_revision + 1
    with pytest.raises(CapabilityOpportunityError):
        first_restart.proposal(opportunity.opportunity_id)
    first_restart_store.close()

    second_restart_store = SQLiteOpportunityStore(path)
    second_restart = _engine(second_restart_store)
    restored = second_restart.get(opportunity.opportunity_id)
    assert restored.status is OpportunityStatus.FAILED
    assert restored.preparation_state is OpportunityPreparationState.FAILED
    assert restored.last_error == first_failed.last_error
    assert "restart-observe:three" in restored.evidence_references
    assert preparation.calls == 1
    second_restart_store.close()


@pytest.mark.asyncio
async def test_failed_acquisition_stays_failed_when_observed_again() -> None:
    acquisition = _FailingAcquisition()
    engine = _engine(InMemoryOpportunityStore(), acquisition)
    opportunity = _observe(engine, _evidence("observe-acquisition:one", "observe-acquisition:two"))
    assert opportunity is not None
    await engine.prepare(opportunity.opportunity_id)
    with pytest.raises(CapabilityOpportunityError):
        await engine.accept(opportunity.opportunity_id, _request())

    failed = engine.get(opportunity.opportunity_id)
    observed = _observe(
        engine,
        _evidence(
            "observe-acquisition:one",
            "observe-acquisition:two",
            "observe-acquisition:three",
        ),
    )
    assert observed is not None
    assert observed.status is OpportunityStatus.FAILED
    assert observed.preparation_state is OpportunityPreparationState.FAILED
    assert observed.last_error == failed.last_error
    assert "observe-acquisition:three" in observed.evidence_references
    assert acquisition.calls == 1


@pytest.mark.asyncio
async def test_prepare_from_failed_is_explicit_application_owned_retry() -> None:
    preparation = _RetryPreparation()
    engine = CapabilityOpportunityEngine(
        InMemoryOpportunityStore(),
        _Acquisition(),
        preparation=preparation,
        clock=lambda: NOW,
    )
    opportunity = _observe(engine, _evidence("explicit-retry:one", "explicit-retry:two"))
    assert opportunity is not None
    with pytest.raises(CapabilityOpportunityError):
        await engine.prepare(opportunity.opportunity_id)
    failed = engine.get(opportunity.opportunity_id)
    assert failed.status is OpportunityStatus.FAILED
    assert failed.preparation_state is OpportunityPreparationState.FAILED

    retried = await engine.prepare(opportunity.opportunity_id)
    assert preparation.calls == 2
    assert retried.status is OpportunityStatus.READY_TO_PROPOSE
    assert retried.preparation_state is OpportunityPreparationState.READY
    assert "preparation:retry-success" in retried.evidence_references
    proposal = engine.proposal(opportunity.opportunity_id)
    assert proposal.opportunity_id == opportunity.opportunity_id


@pytest.mark.asyncio
async def test_explicit_failed_result_stays_failed_when_observed_again() -> None:
    engine = _engine(
        InMemoryOpportunityStore(),
        preparation=_FailedResultPreparation(),
    )
    opportunity = _observe(engine, _evidence("explicit-failed:one", "explicit-failed:two"))
    assert opportunity is not None
    failed = await engine.prepare(opportunity.opportunity_id)
    assert failed.status is OpportunityStatus.FAILED
    assert failed.preparation_state is OpportunityPreparationState.FAILED
    assert failed.last_error == ""
    observed = _observe(
        engine,
        _evidence("explicit-failed:one", "explicit-failed:two", "explicit-failed:three"),
    )
    assert observed is not None
    assert observed.status is OpportunityStatus.FAILED
    assert observed.preparation_state is OpportunityPreparationState.FAILED
    assert observed.decision is failed.decision
    assert observed.prepared_summary == failed.prepared_summary
    assert observed.remaining_authority == failed.remaining_authority
    assert observed.last_error == failed.last_error
    assert "explicit-failed:three" in observed.evidence_references
    with pytest.raises(CapabilityOpportunityError):
        engine.proposal(opportunity.opportunity_id)


@pytest.mark.asyncio
async def test_failed_preparation_with_evidence_is_not_proposal_ready() -> None:
    engine = CapabilityOpportunityEngine(
        InMemoryOpportunityStore(),
        _Acquisition(),
        preparation=_FailedResultPreparation(),
        clock=lambda: NOW,
    )
    opportunity = _observe(engine, _evidence("workflow:failed-one", "workflow:failed-two"))
    assert opportunity is not None
    prepared = await engine.prepare(opportunity.opportunity_id)
    assert prepared.status is OpportunityStatus.FAILED
    assert prepared.preparation_state is OpportunityPreparationState.FAILED
    assert "preparation:failed" in prepared.evidence_references
    observed = _observe(engine, _evidence("workflow:failed-one", "workflow:failed-two"))
    assert observed is not None
    assert observed.status is OpportunityStatus.FAILED
    assert observed.preparation_state is OpportunityPreparationState.FAILED
    assert observed.last_error == prepared.last_error
    with pytest.raises(CapabilityOpportunityError):
        engine.proposal(opportunity.opportunity_id)


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "state",
    [
        OpportunityPreparationState.SECURITY_BLOCKED,
        OpportunityPreparationState.UNKNOWN_OUTCOME,
        OpportunityPreparationState.WAITING_FOR_AUTHORITY,
    ],
)
async def test_non_success_preparation_is_not_proposal_ready(
    state: OpportunityPreparationState,
) -> None:
    engine = CapabilityOpportunityEngine(
        InMemoryOpportunityStore(),
        _Acquisition(),
        preparation=_StatePreparation(state),
        clock=lambda: NOW,
    )
    opportunity = _observe(engine, _evidence(f"state:{state}", "state:second"))
    assert opportunity is not None
    prepared = await engine.prepare(opportunity.opportunity_id)

    assert prepared.preparation_state is state
    assert prepared.status is not OpportunityStatus.READY_TO_PROPOSE
    with pytest.raises(CapabilityOpportunityError):
        engine.proposal(opportunity.opportunity_id)
    with pytest.raises(CapabilityOpportunityError):
        await engine.accept(opportunity.opportunity_id, _request())


@pytest.mark.parametrize(
    ("preparation_state", "expected_status"),
    [
        (OpportunityPreparationState.FAILED, OpportunityStatus.FAILED),
        (OpportunityPreparationState.SECURITY_BLOCKED, OpportunityStatus.ARCHIVED),
        (OpportunityPreparationState.UNKNOWN_OUTCOME, OpportunityStatus.ASSESSING),
        (OpportunityPreparationState.WAITING_FOR_AUTHORITY, OpportunityStatus.PREPARING),
    ],
)
def test_inconsistent_proposal_state_is_reconciled(
    preparation_state: OpportunityPreparationState,
    expected_status: OpportunityStatus,
) -> None:
    store = InMemoryOpportunityStore()
    engine = _engine(store)
    opportunity = _observe(engine, _evidence("reconcile:one", "reconcile:two"))
    assert opportunity is not None
    store._items[opportunity.opportunity_id] = (
        replace(
            opportunity,
            status=OpportunityStatus.READY_TO_PROPOSE,
            preparation_state=preparation_state,
        ),
        store.revision(opportunity.opportunity_id),
    )

    reconciled = engine.get(opportunity.opportunity_id)
    assert reconciled.status is expected_status
    assert reconciled.preparation_state is preparation_state
    assert reconciled.evidence_references == opportunity.evidence_references


def test_store_rejects_active_failed_preparation() -> None:
    store = InMemoryOpportunityStore()
    engine = _engine(store)
    opportunity = _observe(engine, _evidence("invalid:one", "invalid:two"))
    assert opportunity is not None
    with pytest.raises(CapabilityOpportunityError):
        store.save(
            replace(
                opportunity,
                status=OpportunityStatus.ACTIVE,
                preparation_state=OpportunityPreparationState.FAILED,
            ),
            expected_revision=store.revision(opportunity.opportunity_id),
        )


def test_validator_rejects_inconsistent_failed_preparation_state() -> None:
    engine = _engine(InMemoryOpportunityStore())
    opportunity = _observe(engine, _evidence("invalid-status:one", "invalid-status:two"))
    assert opportunity is not None
    with pytest.raises(CapabilityOpportunityError):
        validate_opportunity_state(
            replace(
                opportunity,
                status=OpportunityStatus.DETECTED,
                preparation_state=OpportunityPreparationState.FAILED,
            )
        )
    with pytest.raises(CapabilityOpportunityError):
        validate_opportunity_state(
            replace(
                opportunity,
                status=OpportunityStatus.FAILED,
                preparation_state=OpportunityPreparationState.UNKNOWN_OUTCOME,
            )
        )


@pytest.mark.asyncio
async def test_proposal_and_accept_fail_closed_when_store_returns_inconsistent_state() -> None:
    store = _UnreconciledStore()
    engine = _engine(store)
    opportunity = _observe(engine, _evidence("unreconciled:one", "unreconciled:two"))
    assert opportunity is not None
    current = store._items[opportunity.opportunity_id][0]
    store._items[opportunity.opportunity_id] = (
        replace(
            current,
            status=OpportunityStatus.READY_TO_PROPOSE,
            preparation_state=OpportunityPreparationState.FAILED,
        ),
        store.revision(opportunity.opportunity_id),
    )

    with pytest.raises(CapabilityOpportunityError):
        engine.proposal(opportunity.opportunity_id)
    with pytest.raises(CapabilityOpportunityError):
        await engine.accept(opportunity.opportunity_id, _request())


@pytest.mark.asyncio
async def test_failed_acquisition_remains_rejected_after_restart(tmp_path: Path) -> None:
    path = tmp_path / "failed-opportunity.sqlite3"
    store = SQLiteOpportunityStore(path)
    acquisition = _FailingAcquisition()
    engine = _engine(store, acquisition)
    opportunity = _observe(engine, _evidence("restart:one", "restart:two"))
    assert opportunity is not None
    await engine.prepare(opportunity.opportunity_id)
    with pytest.raises(CapabilityOpportunityError):
        await engine.accept(opportunity.opportunity_id, _request())
    store.close()

    restored_store = SQLiteOpportunityStore(path)
    restored_engine = _engine(restored_store, _FailingAcquisition())
    restored = restored_engine.get(opportunity.opportunity_id)
    assert restored.status is OpportunityStatus.FAILED
    assert restored.preparation_state is OpportunityPreparationState.FAILED
    with pytest.raises(CapabilityOpportunityError):
        restored_engine.proposal(opportunity.opportunity_id)
    with pytest.raises(CapabilityOpportunityError):
        await restored_engine.accept(opportunity.opportunity_id, _request())
    restored_store.close()


@pytest.mark.asyncio
async def test_failed_preparation_remains_failed_after_restart(tmp_path: Path) -> None:
    path = tmp_path / "failed-preparation.sqlite3"
    store = SQLiteOpportunityStore(path)
    engine = CapabilityOpportunityEngine(
        store,
        _Acquisition(),
        preparation=_FailingPreparation(),
        clock=lambda: NOW,
    )
    opportunity = _observe(engine, _evidence("preparation-restart:one", "preparation-restart:two"))
    assert opportunity is not None
    with pytest.raises(CapabilityOpportunityError):
        await engine.prepare(opportunity.opportunity_id)
    failed = engine.get(opportunity.opportunity_id)
    assert failed.status is OpportunityStatus.FAILED
    assert failed.preparation_state is OpportunityPreparationState.FAILED
    with pytest.raises(CapabilityOpportunityError):
        engine.proposal(opportunity.opportunity_id)
    with pytest.raises(CapabilityOpportunityError):
        await engine.accept(opportunity.opportunity_id, _request())
    store.close()

    restored_store = SQLiteOpportunityStore(path)
    restored_engine = CapabilityOpportunityEngine(
        restored_store,
        _Acquisition(),
        preparation=_FailingPreparation(),
        clock=lambda: NOW,
    )
    restored = restored_engine.get(opportunity.opportunity_id)
    assert restored.status is OpportunityStatus.FAILED
    assert restored.preparation_state is OpportunityPreparationState.FAILED
    assert restored.last_error == "preparation failed: RuntimeError"
    with pytest.raises(CapabilityOpportunityError):
        restored_engine.proposal(opportunity.opportunity_id)
    with pytest.raises(CapabilityOpportunityError):
        await restored_engine.accept(opportunity.opportunity_id, _request())
    restored_store.close()


@pytest.mark.asyncio
async def test_legacy_detected_failed_preparation_reconciles_durably(tmp_path: Path) -> None:
    path = tmp_path / "legacy-detected-failed.sqlite3"
    store = SQLiteOpportunityStore(path)
    engine = _engine(store)
    opportunity = _observe(engine, _evidence("legacy-detected:one", "legacy-detected:two"))
    assert opportunity is not None
    payload = json.loads(
        str(
            store._connection.execute(
                "SELECT payload_json FROM opportunities WHERE opportunity_id=?",
                (str(opportunity.opportunity_id),),
            ).fetchone()[0]
        )
    )
    payload["status"] = OpportunityStatus.DETECTED.value
    payload["preparation_state"] = OpportunityPreparationState.FAILED.value
    store._connection.execute(
        "UPDATE opportunities SET payload_json=? WHERE opportunity_id=?",
        (json.dumps(payload, sort_keys=True), str(opportunity.opportunity_id)),
    )
    store._connection.commit()
    store.close()

    restored_store = SQLiteOpportunityStore(path)
    restored_engine = _engine(restored_store)
    restored = restored_engine.get(opportunity.opportunity_id)
    assert restored.status is OpportunityStatus.FAILED
    assert restored.preparation_state is OpportunityPreparationState.FAILED
    assert restored.evidence_references == opportunity.evidence_references
    with pytest.raises(CapabilityOpportunityError):
        restored_engine.proposal(opportunity.opportunity_id)
    with pytest.raises(CapabilityOpportunityError):
        await restored_engine.accept(opportunity.opportunity_id, _request())
    restored_store.close()

    second_store = SQLiteOpportunityStore(path)
    second = _engine(second_store).get(opportunity.opportunity_id)
    assert second.status is OpportunityStatus.FAILED
    assert second.preparation_state is OpportunityPreparationState.FAILED
    second_store.close()


@pytest.mark.asyncio
async def test_stale_proposal_is_rejected_after_opportunity_failure() -> None:
    store = InMemoryOpportunityStore()
    engine = _engine(store)
    opportunity = _observe(engine, _evidence("stale:one", "stale:two"))
    assert opportunity is not None
    await engine.prepare(opportunity.opportunity_id)
    engine.proposal(opportunity.opportunity_id)
    proposed = store.get(opportunity.opportunity_id)
    assert proposed is not None
    failed = replace(
        proposed,
        status=OpportunityStatus.FAILED,
        preparation_state=OpportunityPreparationState.FAILED,
        last_error="synthetic failure after proposal",
    )
    store.save(failed, expected_revision=store.revision(opportunity.opportunity_id))

    with pytest.raises(CapabilityOpportunityError):
        engine.proposal(opportunity.opportunity_id)
    with pytest.raises(CapabilityOpportunityError):
        await engine.accept(opportunity.opportunity_id, _request())


@pytest.mark.asyncio
async def test_impossible_persisted_proposal_state_is_reconciled_fail_closed(
    tmp_path: Path,
) -> None:
    path = tmp_path / "legacy-opportunity.sqlite3"
    store = SQLiteOpportunityStore(path)
    engine = _engine(store)
    opportunity = _observe(engine, _evidence("legacy:one", "legacy:two"))
    assert opportunity is not None
    prepared = engine.get(opportunity.opportunity_id)
    payload = json.loads(
        str(
            store._connection.execute(
                "SELECT payload_json FROM opportunities WHERE opportunity_id=?",
                (str(opportunity.opportunity_id),),
            ).fetchone()[0]
        )
    )
    payload["status"] = OpportunityStatus.READY_TO_PROPOSE.value
    payload["preparation_state"] = OpportunityPreparationState.FAILED.value
    store._connection.execute(
        "UPDATE opportunities SET payload_json=? WHERE opportunity_id=?",
        (json.dumps(payload, sort_keys=True), str(opportunity.opportunity_id)),
    )
    store._connection.commit()
    store.close()

    restored_store = SQLiteOpportunityStore(path)
    restored_engine = _engine(restored_store)
    restored = restored_engine.get(prepared.opportunity_id)
    assert restored.status is OpportunityStatus.FAILED
    assert restored.preparation_state is OpportunityPreparationState.FAILED
    assert restored.evidence_references == prepared.evidence_references
    with pytest.raises(CapabilityOpportunityError):
        restored_engine.proposal(prepared.opportunity_id)
    with pytest.raises(CapabilityOpportunityError):
        await restored_engine.accept(prepared.opportunity_id, _request())
    restored_store.close()


def test_opportunity_validation_and_retention_bounds_fail_closed() -> None:
    engine = _engine(InMemoryOpportunityStore())
    with pytest.raises(CapabilityOpportunityError):
        CapabilityOpportunityEngine(InMemoryOpportunityStore(), object())  # type: ignore[arg-type]
    with pytest.raises(CapabilityOpportunityError):
        CapabilityOpportunityEngine(InMemoryOpportunityStore(), _Acquisition(), minimum_evidence=1)
    with pytest.raises(CapabilityOpportunityError):
        engine.observe(
            "need",
            _evidence("one", "two"),
            expected_benefit="benefit",
            privacy_impact="private",
            estimated_resource_cost="small",
            likely_required_authority=(),
            workspace="workspace",
            cooldown=timedelta(seconds=-1),
        )

    evidence = _evidence("one")[0]
    malformed: tuple[Callable[[], object], ...] = (
        lambda: replace(evidence, source="workflow"),  # type: ignore[arg-type]
        lambda: replace(evidence, reference=""),
        lambda: replace(evidence, confidence=2.0),
        lambda: replace(evidence, observed_at=datetime(2026, 1, 1)),
        lambda: replace(evidence, verified="yes"),  # type: ignore[arg-type]
        lambda: replace(evidence, summary="token=raw"),
    )
    for factory in malformed:
        with pytest.raises(CapabilityOpportunityError):
            factory()


def test_expired_opportunity_and_store_revision_are_explicit(tmp_path: Path) -> None:
    clock = [NOW]
    path = tmp_path / "opportunities.sqlite3"
    store = SQLiteOpportunityStore(path)
    engine = _engine(store, clock=clock)
    opportunity = engine.observe(
        "short-lived need",
        _evidence("one", "two"),
        expected_benefit="benefit",
        privacy_impact="private",
        estimated_resource_cost="small",
        likely_required_authority=(),
        workspace="workspace",
        expiry=timedelta(seconds=1),
    )
    assert opportunity is not None
    revision = store.revision(opportunity.opportunity_id)
    store.save(opportunity, expected_revision=revision)
    with pytest.raises(CapabilityOpportunityError):
        store.save(opportunity, expected_revision=revision)
    clock[0] += timedelta(seconds=2)
    assert engine.get(opportunity.opportunity_id).status is OpportunityStatus.EXPIRED
    store.close()


def test_future_opportunity_schema_and_malformed_payload_fail_closed(tmp_path: Path) -> None:
    future = tmp_path / "future.sqlite3"
    with sqlite3.connect(future) as connection:
        connection.execute(
            "CREATE TABLE opportunity_schema(version INTEGER PRIMARY KEY, name TEXT NOT NULL)"
        )
        connection.execute("INSERT INTO opportunity_schema VALUES (99, 'future')")
    with pytest.raises(CapabilityOpportunityError):
        SQLiteOpportunityStore(future)


@pytest.mark.asyncio
async def test_security_block_is_terminal_under_observation_and_normal_actions() -> None:
    preparation = _SecurityBlockingPreparation()
    acquisition = _Acquisition()
    engine = CapabilityOpportunityEngine(
        InMemoryOpportunityStore(), acquisition, preparation=preparation, clock=lambda: NOW
    )
    opportunity = _observe(engine, _evidence("security:one", "security:two"))
    assert opportunity is not None
    blocked = await engine.prepare(opportunity.opportunity_id)
    assert blocked.status is OpportunityStatus.ARCHIVED
    assert blocked.preparation_state is OpportunityPreparationState.SECURITY_BLOCKED
    assert blocked.decision is OpportunityDecision.NONE
    summary = blocked.prepared_summary
    references = blocked.evidence_references

    same = _observe(engine, _evidence("security:one", "security:two"))
    assert same is not None
    assert same.status is OpportunityStatus.ARCHIVED
    assert same.preparation_state is OpportunityPreparationState.SECURITY_BLOCKED
    assert same.decision is OpportunityDecision.NONE
    assert same.prepared_summary == summary
    assert same.evidence_references == references

    new = _observe(engine, _evidence("security:three", "security:four"))
    assert new is not None
    assert new.status is OpportunityStatus.ARCHIVED
    assert new.preparation_state is OpportunityPreparationState.SECURITY_BLOCKED
    assert new.prepared_summary == summary
    assert "security:three" in new.evidence_references
    with pytest.raises(CapabilityOpportunityError):
        await engine.prepare(new.opportunity_id)
    with pytest.raises(CapabilityOpportunityError):
        engine.proposal(new.opportunity_id)
    with pytest.raises(CapabilityOpportunityError):
        await engine.accept(new.opportunity_id, _request())
    with pytest.raises(CapabilityOpportunityError):
        engine.decline(new.opportunity_id)
    assert preparation.calls == 1
    assert acquisition.requests == []


@pytest.mark.asyncio
async def test_security_block_survives_two_sqlite_restarts_and_expiry(tmp_path: Path) -> None:
    path = tmp_path / "security-block.sqlite3"
    clock = [NOW]
    preparation = _SecurityBlockingPreparation()
    store = SQLiteOpportunityStore(path)
    engine = CapabilityOpportunityEngine(
        store, _Acquisition(), preparation=preparation, clock=lambda: clock[0]
    )
    opportunity = engine.observe(
        "security durable need",
        _evidence("durable:one", "durable:two"),
        expected_benefit="benefit",
        privacy_impact="private",
        estimated_resource_cost="small",
        likely_required_authority=(),
        workspace="workspace",
        expiry=timedelta(seconds=1),
    )
    assert opportunity is not None
    blocked = await engine.prepare(opportunity.opportunity_id)
    store.close()

    store = SQLiteOpportunityStore(path)
    engine = CapabilityOpportunityEngine(
        store, _Acquisition(), preparation=preparation, clock=lambda: clock[0]
    )

    def observe_durable(evidence: tuple[OpportunityEvidence, ...]) -> CapabilityOpportunity | None:
        return engine.observe(
            "security durable need",
            evidence,
            expected_benefit="benefit",
            privacy_impact="private",
            estimated_resource_cost="small",
            likely_required_authority=(),
            workspace="workspace",
        )

    clock[0] += timedelta(days=1)
    for evidence in (
        _evidence("durable:one", "durable:two"),
        _evidence("durable:three", "durable:four"),
    ):
        observed = observe_durable(evidence)
        assert observed is not None
        assert observed.status is OpportunityStatus.ARCHIVED
        assert observed.preparation_state is OpportunityPreparationState.SECURITY_BLOCKED
    store.close()

    store = SQLiteOpportunityStore(path)
    restored = CapabilityOpportunityEngine(
        store, _Acquisition(), preparation=preparation, clock=lambda: clock[0]
    ).get(blocked.opportunity_id)
    assert restored.status is OpportunityStatus.ARCHIVED
    assert restored.preparation_state is OpportunityPreparationState.SECURITY_BLOCKED
    assert restored.prepared_summary == blocked.prepared_summary
    store.close()


def test_security_block_invariant_reconciles_legacy_state() -> None:
    store = InMemoryOpportunityStore()
    engine = _engine(store)
    opportunity = _observe(engine, _evidence("legacy:one", "legacy:two"))
    assert opportunity is not None
    store._items[opportunity.opportunity_id] = (
        replace(
            opportunity,
            status=OpportunityStatus.DETECTED,
            preparation_state=OpportunityPreparationState.SECURITY_BLOCKED,
        ),
        store.revision(opportunity.opportunity_id),
    )
    reconciled = engine.get(opportunity.opportunity_id)
    assert reconciled.status is OpportunityStatus.ARCHIVED
    assert reconciled.preparation_state is OpportunityPreparationState.SECURITY_BLOCKED
    store._items[opportunity.opportunity_id] = (
        replace(
            reconciled,
            preparation_state=OpportunityPreparationState.NOT_STARTED,
        ),
        store.revision(opportunity.opportunity_id),
    )
    repaired_archived = engine.get(opportunity.opportunity_id)
    assert repaired_archived.status is OpportunityStatus.ARCHIVED
    assert repaired_archived.preparation_state is OpportunityPreparationState.SECURITY_BLOCKED
    with pytest.raises(CapabilityOpportunityError):
        validate_opportunity_state(
            replace(
                opportunity,
                status=OpportunityStatus.ARCHIVED,
                preparation_state=OpportunityPreparationState.NOT_STARTED,
            )
        )
