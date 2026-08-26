from __future__ import annotations

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
    OpportunityEvidence,
    OpportunityEvidenceSource,
    OpportunityPreparationResult,
    OpportunityPreparationState,
    OpportunityStatus,
    SQLiteOpportunityStore,
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
    async def prepare(self, opportunity: object) -> OpportunityPreparationResult:
        del opportunity
        raise RuntimeError("synthetic preparation failure")


class _FailedResultPreparation:
    async def prepare(self, opportunity: object) -> OpportunityPreparationResult:
        del opportunity
        return OpportunityPreparationResult(
            OpportunityPreparationState.FAILED,
            "synthetic review failure with retained evidence",
            evidence_references=("preparation:failed",),
        )


class _FailingAcquisition(_Acquisition):
    async def acquire(self, request: CapabilityAcquisitionRequest) -> CapabilityAcquisitionReport:
        del request
        raise RuntimeError("synthetic acquisition failure")


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
) -> CapabilityOpportunityEngine:
    ticks = clock if clock is not None else [NOW]
    return CapabilityOpportunityEngine(
        store,
        acquisition or _Acquisition(),
        preparation=_Preparation(),
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
    assert (
        preparation_engine.get(opportunity.opportunity_id).preparation_state
        is OpportunityPreparationState.FAILED
    )

    acquisition = _FailingAcquisition()
    engine = _engine(InMemoryOpportunityStore(), acquisition)
    opportunity = _observe(engine, _evidence("workflow:one", "workflow:two"))
    assert opportunity is not None
    await engine.prepare(opportunity.opportunity_id)
    with pytest.raises(CapabilityOpportunityError):
        await engine.accept(opportunity.opportunity_id, _request())
    assert (
        engine.get(opportunity.opportunity_id).preparation_state
        is OpportunityPreparationState.FAILED
    )


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
    with pytest.raises(CapabilityOpportunityError):
        engine.proposal(opportunity.opportunity_id)


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
