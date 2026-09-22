"""Fail-closed deterministic orchestration for qualification simulations."""

from __future__ import annotations

from collections.abc import Callable, Iterable
from dataclasses import dataclass
from enum import StrEnum


class FormalStageKind(StrEnum):
    """The result unit contributed by a formal qualification stage."""

    THREE_OF_THREE = "THREE_OF_THREE"
    SAME_RUNTIME_PAIR = "SAME_RUNTIME_PAIR"
    FINAL_TEN = "FINAL_TEN"


@dataclass(frozen=True, slots=True)
class GateOutcome:
    stage_id: str
    passed: bool
    blocker: str | None = None


@dataclass(frozen=True, slots=True)
class CoordinatorResult:
    passed: bool
    executed_stages: tuple[str, ...]
    blocker: str | None


@dataclass(frozen=True, slots=True)
class FormalStageOutcome:
    """One deterministic stage result, distinct from its member count."""

    stage_id: str
    kind: FormalStageKind
    required_member_count: int
    formal_result_units: int
    succeeded: bool
    member_successes: tuple[bool, ...] = ()

    def __post_init__(self) -> None:
        expected = {
            FormalStageKind.THREE_OF_THREE: ("Q09", 3),
            FormalStageKind.SAME_RUNTIME_PAIR: ("Q10", 2),
            FormalStageKind.FINAL_TEN: ("Q11", 10),
        }
        expected_stage, expected_members = expected[self.kind]
        if self.stage_id != expected_stage:
            raise ValueError("formal stage kind is bound to the wrong stage")
        if self.required_member_count != expected_members:
            raise ValueError("formal member count is malformed")
        if self.formal_result_units != 1:
            raise ValueError("formal result contribution must be one unit")
        if self.kind is FormalStageKind.SAME_RUNTIME_PAIR:
            if len(self.member_successes) != 2 or not all(
                type(item) is bool for item in self.member_successes
            ):
                raise ValueError("pair member outcomes are malformed")
            if self.succeeded != all(self.member_successes):
                raise ValueError("pair result does not match member outcomes")


@dataclass(frozen=True, slots=True)
class FormalCountAggregate:
    """Formal outcomes counted as stage results, not lifecycle members."""

    formal_3_of_3: tuple[int, int]
    formal_pair: tuple[int, int]
    formal_final_ten: tuple[int, int]

    def as_dict(self) -> dict[str, str]:
        return {
            "formal_3_of_3": f"{self.formal_3_of_3[0]}/{self.formal_3_of_3[1]}",
            "formal_pair": f"{self.formal_pair[0]}/{self.formal_pair[1]}",
            "formal_final_ten": f"{self.formal_final_ten[0]}/{self.formal_final_ten[1]}",
        }


def aggregate_formal_counts(outcomes: Iterable[FormalStageOutcome]) -> FormalCountAggregate:
    """Aggregate one result unit for Q09, Q10, and Q11 respectively."""

    by_kind: dict[FormalStageKind, FormalStageOutcome] = {}
    for outcome in outcomes:
        if outcome.kind in by_kind:
            raise ValueError("duplicate formal stage outcome")
        by_kind[outcome.kind] = outcome
    required = set(FormalStageKind)
    if set(by_kind) != required:
        raise ValueError("formal stage outcome set is incomplete")

    stopped = False

    def count(kind: FormalStageKind) -> tuple[int, int]:
        nonlocal stopped
        outcome = by_kind[kind]
        denominator = (
            1 if kind is FormalStageKind.SAME_RUNTIME_PAIR else outcome.required_member_count
        )
        if stopped:
            return 0, denominator
        numerator = denominator if outcome.succeeded else 0
        if not outcome.succeeded:
            stopped = True
        return numerator, denominator

    return FormalCountAggregate(
        formal_3_of_3=count(FormalStageKind.THREE_OF_THREE),
        formal_pair=count(FormalStageKind.SAME_RUNTIME_PAIR),
        formal_final_ten=count(FormalStageKind.FINAL_TEN),
    )


class FormalQualificationCoordinator:
    """Run ordered gate callables and stop at the first typed failure."""

    def run(
        self,
        stage_ids: Iterable[str],
        gates: dict[str, Callable[[], GateOutcome]],
    ) -> CoordinatorResult:
        executed: list[str] = []
        for stage_id in stage_ids:
            gate = gates.get(stage_id)
            if gate is None:
                return CoordinatorResult(False, tuple(executed), f"MISSING_GATE:{stage_id}")
            outcome = gate()
            executed.append(stage_id)
            if outcome.stage_id != stage_id:
                return CoordinatorResult(False, tuple(executed), f"IDENTITY_MISMATCH:{stage_id}")
            if not outcome.passed:
                return CoordinatorResult(
                    False,
                    tuple(executed),
                    outcome.blocker or f"GATE_FAILED:{stage_id}",
                )
        return CoordinatorResult(True, tuple(executed), None)
