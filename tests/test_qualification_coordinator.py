from collections.abc import Callable

import pytest
from jarvis.acceptance.coordinator import (
    FormalQualificationCoordinator,
    FormalStageKind,
    FormalStageOutcome,
    GateOutcome,
    aggregate_formal_counts,
)

STAGES = tuple(f"Q{index:02}" for index in range(1, 31))


def passing_gate(stage: str) -> Callable[[], GateOutcome]:
    return lambda: GateOutcome(stage, True)


def injected_gate(stage: str, failed_stage: str) -> Callable[[], GateOutcome]:
    return lambda: GateOutcome(stage, stage != failed_stage, f"INJECTED:{failed_stage}")


def test_coordinator_simulates_complete_success_without_formal_counts() -> None:
    coordinator = FormalQualificationCoordinator()
    result = coordinator.run(
        STAGES,
        {stage: passing_gate(stage) for stage in STAGES},
    )
    assert result.passed
    assert result.executed_stages == STAGES
    assert result.blocker is None


def test_coordinator_stops_at_each_injected_failure() -> None:
    coordinator = FormalQualificationCoordinator()
    for index, failed_stage in enumerate(STAGES):
        result = coordinator.run(
            STAGES,
            {stage: injected_gate(stage, failed_stage) for stage in STAGES},
        )
        assert not result.passed
        assert result.executed_stages == STAGES[: index + 1]
        assert result.blocker == f"INJECTED:{failed_stage}"


def test_coordinator_rejects_missing_or_misbound_gate() -> None:
    coordinator = FormalQualificationCoordinator()
    missing = coordinator.run(("Q01",), {})
    assert missing.blocker == "MISSING_GATE:Q01"
    misbound = coordinator.run(("Q01",), {"Q01": lambda: GateOutcome("Q02", True)})
    assert misbound.blocker == "IDENTITY_MISMATCH:Q01"


def test_formal_aggregation_counts_q10_as_one_pair_result() -> None:
    aggregate = aggregate_formal_counts(
        (
            FormalStageOutcome("Q09", FormalStageKind.THREE_OF_THREE, 3, 1, True),
            FormalStageOutcome("Q10", FormalStageKind.SAME_RUNTIME_PAIR, 2, 1, True, (True, True)),
            FormalStageOutcome("Q11", FormalStageKind.FINAL_TEN, 10, 1, True),
        )
    )
    assert aggregate.as_dict() == {
        "formal_3_of_3": "3/3",
        "formal_pair": "1/1",
        "formal_final_ten": "10/10",
    }


def test_failed_q10_pair_contributes_zero_of_one() -> None:
    aggregate = aggregate_formal_counts(
        (
            FormalStageOutcome("Q09", FormalStageKind.THREE_OF_THREE, 3, 1, True),
            FormalStageOutcome(
                "Q10", FormalStageKind.SAME_RUNTIME_PAIR, 2, 1, False, (True, False)
            ),
            FormalStageOutcome("Q11", FormalStageKind.FINAL_TEN, 10, 1, True),
        )
    )
    assert aggregate.formal_pair == (0, 1)
    assert aggregate.formal_final_ten == (0, 10)


def test_formal_aggregation_rejects_ambiguous_or_incomplete_inputs() -> None:
    with pytest.raises(ValueError, match="wrong stage"):
        FormalStageOutcome("Q09", FormalStageKind.SAME_RUNTIME_PAIR, 2, 1, True, (True, True))
    with pytest.raises(ValueError, match="member count"):
        FormalStageOutcome("Q09", FormalStageKind.THREE_OF_THREE, 2, 1, True)
    with pytest.raises(ValueError, match="formal result"):
        FormalStageOutcome("Q10", FormalStageKind.SAME_RUNTIME_PAIR, 2, 2, True)
    with pytest.raises(ValueError, match="member outcomes"):
        FormalStageOutcome("Q10", FormalStageKind.SAME_RUNTIME_PAIR, 2, 1, False, (True,))
    with pytest.raises(ValueError, match="pair result"):
        FormalStageOutcome("Q10", FormalStageKind.SAME_RUNTIME_PAIR, 2, 1, True, (True, False))
    with pytest.raises(ValueError, match="incomplete"):
        aggregate_formal_counts(
            (
                FormalStageOutcome(
                    "Q10", FormalStageKind.SAME_RUNTIME_PAIR, 2, 1, True, (True, True)
                ),
            )
        )
    with pytest.raises(ValueError, match="duplicate"):
        aggregate_formal_counts(
            (
                FormalStageOutcome("Q09", FormalStageKind.THREE_OF_THREE, 3, 1, True),
                FormalStageOutcome("Q09", FormalStageKind.THREE_OF_THREE, 3, 1, True),
            )
        )
