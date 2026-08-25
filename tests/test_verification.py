"""Tests for typed evidence and post-execution outcome verification."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from typing import cast

import pytest
from jarvis.presentation import (
    PresentationContent,
    PresentationEntry,
    PresentationKind,
    PresentationSurface,
)
from jarvis.verification import (
    EvidenceRecord,
    EvidenceType,
    VerificationDisposition,
    VerificationEngine,
    VerificationError,
    VerificationLevel,
    VerificationPlan,
    VerificationResult,
)

NOW = datetime(2026, 8, 23, 12, tzinfo=UTC)


def plan(
    criterion: str = "result exists",
    *,
    required: VerificationLevel = VerificationLevel.IMPLEMENTED,
    independent: bool = True,
    ask_user: bool = True,
    allowed: frozenset[EvidenceType] | None = None,
) -> VerificationPlan:
    return VerificationPlan(
        "Original user goal: make the result exist",
        (criterion,),
        frozenset(EvidenceType) if allowed is None else allowed,
        required,
        0.8,
        timedelta(minutes=10),
        independent,
        ask_user,
    )


def evidence(
    expected: object = "result exists",
    observed: object = "result exists",
    *,
    kind: EvidenceType = EvidenceType.API,
    source: str = "trusted.api",
    at: datetime = NOW,
    level: VerificationLevel = VerificationLevel.INTEGRATION_VERIFIED,
    contradiction: bool = False,
) -> EvidenceRecord:
    return EvidenceRecord(
        kind,
        source,
        at,
        timedelta(minutes=5),
        1.0,
        expected,
        observed,
        contradiction,
        level,
    )


def test_verification_levels_and_positive_evidence_are_ordered() -> None:
    assert VerificationLevel.UNKNOWN < VerificationLevel.OPERATIONALLY_PROVEN
    result = VerificationEngine().evaluate(
        plan(required=VerificationLevel.INTEGRATION_VERIFIED),
        (evidence(),),
        now=NOW,
    )
    assert result.passed
    assert result.level is VerificationLevel.INTEGRATION_VERIFIED
    assert result.disposition is VerificationDisposition.COMPLETE
    assert result.original_goal.startswith("Original user goal")


def test_stale_evidence_is_retained_but_cannot_prove_outcome() -> None:
    stale = evidence(at=NOW - timedelta(minutes=11))
    result = VerificationEngine().evaluate(plan(ask_user=False), (stale,), now=NOW)
    assert not result.passed
    assert result.level is VerificationLevel.UNKNOWN
    assert result.stale_evidence == (stale,)
    assert result.disposition is VerificationDisposition.DIAGNOSE


def test_conflicting_evidence_preserves_goal_and_requires_replan() -> None:
    result = VerificationEngine().evaluate(
        plan(), (evidence(observed="result is absent"),), now=NOW
    )
    assert not result.passed
    assert result.contradictions
    assert result.disposition is VerificationDisposition.REPLAN
    assert "diagnose" in result.diagnosis
    assert result.original_goal.startswith("Original user goal")


def test_explicit_user_no_is_negative_evidence() -> None:
    negative = evidence(
        kind=EvidenceType.USER,
        source="user.confirmation",
        observed="no",
        level=VerificationLevel.USER_VERIFIED,
    )
    result = VerificationEngine().evaluate(plan(), (negative,), now=NOW)
    assert not result.passed
    assert result.contradictions == (negative,)
    assert result.disposition is VerificationDisposition.REPLAN


def test_user_yes_can_verify_when_physical_state_is_unobservable() -> None:
    confirmation = evidence(
        kind=EvidenceType.USER,
        source="user.confirmation",
        observed="yes",
        level=VerificationLevel.USER_VERIFIED,
    )
    result = VerificationEngine().evaluate(
        plan(required=VerificationLevel.USER_VERIFIED), (confirmation,), now=NOW
    )
    assert result.passed
    assert result.level is VerificationLevel.USER_VERIFIED


def test_model_done_claim_is_never_evidence() -> None:
    result = VerificationEngine().evaluate(plan(), model_claim="done", now=NOW)
    assert not result.passed
    assert result.level is VerificationLevel.UNKNOWN
    assert result.rejected_model_claims == ("model output is not evidence",)
    assert result.disposition is VerificationDisposition.ASK_USER

    forged = evidence(source="model.claim", level=VerificationLevel.OPERATIONALLY_PROVEN)
    rejected = VerificationEngine().evaluate(plan(), (forged,), now=NOW)
    assert not rejected.passed
    assert rejected.level is VerificationLevel.UNKNOWN


@pytest.mark.asyncio
async def test_presentation_query_state_is_screen_evidence_not_request_echo() -> None:
    observed: list[PresentationEntry] = []
    rendered: list[PresentationEntry] = []

    async def observer(_surface_id: str) -> tuple[PresentationEntry, ...]:
        return tuple(observed)

    async def renderer(_surface_id: str, entries: tuple[PresentationEntry, ...]) -> None:
        rendered[:] = entries

    surface = PresentationSurface("desktop", observer=observer, renderer=renderer)
    expected = await surface.present(
        PresentationContent.declarative(PresentationKind.DECLARATIVE_VIEW, {"state": "active"})
    )
    mismatch = await VerificationEngine().verify_surface(
        plan(expected.state_fingerprint, required=VerificationLevel.INTEGRATION_VERIFIED),
        surface,
        expected,
        now=expected.captured_at + timedelta(seconds=1),
    )
    assert not mismatch.passed
    assert mismatch.contradictions
    assert mismatch.evidence[0].evidence_type is EvidenceType.SCREEN

    # Only the observed entries make the subsequent result pass.
    observed.extend(rendered)
    verified = await VerificationEngine().verify_surface(
        plan(expected.state_fingerprint, required=VerificationLevel.INTEGRATION_VERIFIED),
        surface,
        expected,
        now=expected.captured_at + timedelta(seconds=1),
    )
    assert verified.passed
    assert verified.evidence[0].source == "surface:desktop"


@pytest.mark.asyncio
async def test_unobserved_presentation_state_cannot_prove_screen_outcome() -> None:
    surface = PresentationSurface("desktop")
    expected = await surface.present(
        PresentationContent.declarative(PresentationKind.DECLARATIVE_VIEW, {"state": "active"})
    )
    actual = await surface.query_state()
    assert not actual.observed
    result = await VerificationEngine().verify_surface(
        plan(expected.state_fingerprint, required=VerificationLevel.INTEGRATION_VERIFIED),
        surface,
        expected,
        now=expected.captured_at + timedelta(seconds=1),
    )
    assert not result.passed
    assert result.contradictions
    assert result.evidence[0].observed == f"unobserved:{actual.state_fingerprint}"


def test_unobservable_physical_result_requests_user_confirmation() -> None:
    result = VerificationEngine().evaluate(plan(), (), now=NOW)
    assert not result.passed
    assert result.disposition is VerificationDisposition.ASK_USER
    assert result.needs_user_confirmation
    assert result.user_prompt is not None


def test_plan_and_evidence_validation_is_strict_and_bounded() -> None:
    with pytest.raises(VerificationError):
        VerificationPlan("goal", ())
    with pytest.raises(VerificationError):
        VerificationPlan("goal", ("criterion",), minimum_confidence=1.1)
    with pytest.raises(VerificationError):
        EvidenceRecord(
            EvidenceType.API,
            "source",
            NOW.replace(tzinfo=None),
            timedelta(minutes=1),
            1.0,
            "expected",
            "observed",
        )

    with pytest.raises(VerificationError):
        VerificationPlan("goal", (cast(str, ""),))
    with pytest.raises(VerificationError):
        VerificationPlan(
            "goal", ("criterion",), allowed_evidence_types=cast(frozenset[EvidenceType], set())
        )
    with pytest.raises(VerificationError):
        VerificationPlan(
            "goal", ("criterion",), allowed_evidence_types=cast(frozenset[EvidenceType], {"api"})
        )
    with pytest.raises(VerificationError):
        VerificationPlan("goal", ("criterion",), required_level=cast(VerificationLevel, "bad"))
    with pytest.raises(VerificationError):
        VerificationPlan("goal", ("criterion",), max_evidence_age=timedelta(days=31))
    with pytest.raises(VerificationError):
        VerificationPlan("goal", ("criterion",), independent_observation_required=cast(bool, "yes"))

    with pytest.raises(VerificationError):
        EvidenceRecord(
            cast(EvidenceType, "api"), "source", NOW, timedelta(minutes=1), 1.0, "a", "a"
        )
    with pytest.raises(VerificationError):
        EvidenceRecord(EvidenceType.API, "source", NOW, timedelta(0), 1.0, "a", "a")
    with pytest.raises(VerificationError):
        EvidenceRecord(EvidenceType.API, "source", NOW, timedelta(minutes=1), 1.1, "a", "a")
    with pytest.raises(VerificationError):
        EvidenceRecord(
            EvidenceType.API,
            "source",
            NOW,
            timedelta(minutes=1),
            1.0,
            cast(object, float("nan")),
            "a",
        )
    with pytest.raises(VerificationError):
        EvidenceRecord(
            EvidenceType.API,
            "source",
            NOW,
            timedelta(minutes=1),
            1.0,
            "a",
            "a",
            contradiction=cast(bool, "yes"),
        )
    with pytest.raises(VerificationError):
        EvidenceRecord(
            EvidenceType.API,
            "source",
            NOW,
            timedelta(minutes=1),
            1.0,
            "a",
            "a",
            level=cast(VerificationLevel, "bad"),
        )

    nested: object = "leaf"
    for _ in range(7):
        nested = {"nested": nested}
    for value in (
        nested,
        {str(index): index for index in range(65)},
        list(range(129)),
        {1: "bad"},
        b"bytes",
    ):
        with pytest.raises(VerificationError):
            EvidenceRecord(EvidenceType.API, "source", NOW, timedelta(minutes=1), 1.0, value, "a")

    with pytest.raises(VerificationError):
        EvidenceRecord(
            EvidenceType.API,
            "source",
            NOW,
            timedelta(minutes=1),
            1.0,
            "a" * 10_000,
            "a" * 10_000,
        )


def test_low_confidence_and_incomplete_evidence_are_not_success() -> None:
    low = evidence(level=VerificationLevel.INTEGRATION_VERIFIED)
    low = EvidenceRecord(
        low.evidence_type,
        low.source,
        low.time,
        low.freshness,
        0.2,
        low.expected,
        low.observed,
        level=low.level,
    )
    result = VerificationEngine().evaluate(plan(ask_user=False), (low,), now=NOW)
    assert not result.passed
    assert result.rejected_model_claims == ("evidence confidence is below the plan threshold",)

    incomplete = VerificationEngine().evaluate(
        plan(ask_user=False), (evidence(expected="another criterion"),), now=NOW
    )
    assert incomplete.disposition is VerificationDisposition.REPLAN
    assert incomplete.missing_criteria == ("result exists",)


def test_verification_response_normalization_and_result_contract() -> None:
    engine = VerificationEngine()
    assert engine._user_response(True) is True
    assert engine._user_response(False) is False
    assert engine._user_response(1) is None
    assert engine._user_response("  YES  ") is True
    assert engine._user_response("maybe") is None
    assert evidence(observed="other", contradiction=True).contradicts_expectation

    valid = engine.evaluate(plan(ask_user=False), (evidence(),), now=NOW)
    assert valid.passed
    for values in (
        (cast(VerificationLevel, "bad"), VerificationDisposition.COMPLETE, True),
        (VerificationLevel.IMPLEMENTED, cast(VerificationDisposition, "bad"), True),
        (VerificationLevel.IMPLEMENTED, VerificationDisposition.COMPLETE, cast(bool, "yes")),
    ):
        with pytest.raises(VerificationError):
            VerificationResult(
                "goal",
                values[0],
                values[2],
                values[1],
            )
    with pytest.raises(VerificationError):
        EvidenceRecord(
            EvidenceType.API,
            "source",
            NOW,
            timedelta(minutes=1),
            1.0,
            cast(object, {"bad": object()}),
            "observed",
        )


def test_disallowed_and_low_confidence_evidence_cannot_complete() -> None:
    result = VerificationEngine().evaluate(
        plan(ask_user=False, allowed=frozenset({EvidenceType.FILE})),
        (evidence(kind=EvidenceType.API),),
        now=NOW,
    )
    assert not result.passed
    assert result.rejected_model_claims == ("evidence type is not allowed by the plan",)
