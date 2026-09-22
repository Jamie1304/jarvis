"""Focused R3E-D bounded recursive orchestration regressions."""

from __future__ import annotations

import asyncio
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import cast
from uuid import UUID

import pytest
from jarvis.planning import (
    DecompositionError,
    DecompositionPolicy,
    DecompositionSubproblem,
    OrchestrationController,
    OrchestrationRequest,
    OrchestrationResult,
    OrchestrationResultKind,
    ReplanEvidence,
)


class _Advisor:
    def __init__(self, responses: dict[str, OrchestrationResult]) -> None:
        self.responses = responses
        self.requests: list[OrchestrationRequest] = []
        self.replan_requests: list[OrchestrationRequest] = []

    async def propose_orchestration(self, request: OrchestrationRequest) -> OrchestrationResult:
        self.requests.append(request)
        response = None if request.decomposition_context else self.responses.get(request.goal)
        if response is None:
            return OrchestrationResult(
                request.orchestration_attempt_id, proposal={"goal": request.goal}
            )
        return response

    async def replan_orchestration(
        self, request: OrchestrationRequest, evidence: ReplanEvidence
    ) -> OrchestrationResult:
        del evidence
        self.replan_requests.append(request)
        return OrchestrationResult(
            request.orchestration_attempt_id, proposal={"goal": request.goal}
        )


def _decompose(request_id: UUID, *objectives: str) -> OrchestrationResult:
    return OrchestrationResult(
        request_id,
        kind=OrchestrationResultKind.DECOMPOSITION,
        subproblems=tuple(DecompositionSubproblem(objective) for objective in objectives),
    )


@pytest.mark.asyncio
async def test_direct_proposal_is_one_bounded_attempt() -> None:
    request = OrchestrationRequest.create("direct")
    advisor = _Advisor({})

    run = await OrchestrationController(advisor).run(request, max_model_calls=8)

    assert run.proposal == {"goal": "direct"}
    assert run.model_calls == 1
    assert run.attempts[0].attempt_id == request.orchestration_attempt_id
    assert run.attempts[0].depth == 0


@pytest.mark.asyncio
async def test_one_level_tree_uses_child_objectives_and_final_synthesis() -> None:
    root = OrchestrationRequest.create("root")
    advisor = _Advisor({})
    advisor.responses["root"] = _decompose(root.orchestration_attempt_id, "left", "right")

    run = await OrchestrationController(advisor).run(root, max_model_calls=8)

    assert run.model_calls == 4
    assert [request.goal for request in advisor.requests] == ["root", "left", "right", "root"]
    assert len(run.attempts) == 4
    assert run.attempts[1].parent_attempt_id == root.orchestration_attempt_id
    assert run.attempts[1].depth == 1
    assert advisor.requests[-1].decomposition_context


@pytest.mark.asyncio
async def test_multiple_levels_keep_distinct_ids_and_parent_depth_lineage() -> None:
    class RecursiveAdvisor:
        def __init__(self) -> None:
            self.requests: list[OrchestrationRequest] = []

        async def propose_orchestration(self, request: OrchestrationRequest) -> OrchestrationResult:
            self.requests.append(request)
            if request.decomposition_context:
                return OrchestrationResult(
                    request.orchestration_attempt_id, proposal={"final": True}
                )
            if request.goal == "root":
                return _decompose(request.orchestration_attempt_id, "left", "right")
            if request.goal == "left":
                return _decompose(request.orchestration_attempt_id, "leaf")
            return OrchestrationResult(
                request.orchestration_attempt_id, proposal={"goal": request.goal}
            )

        async def replan_orchestration(
            self, request: OrchestrationRequest, evidence: ReplanEvidence
        ) -> OrchestrationResult:
            del evidence
            return OrchestrationResult(request.orchestration_attempt_id, proposal={})

    advisor = RecursiveAdvisor()
    run = await OrchestrationController(advisor).run(
        OrchestrationRequest.create("root"), max_model_calls=8
    )

    assert run.model_calls == 6
    assert len({attempt.attempt_id for attempt in run.attempts}) == 6
    left = next(attempt for attempt in run.attempts if attempt.depth == 1)
    leaf = next(attempt for attempt in run.attempts if attempt.depth == 2)
    assert leaf.parent_attempt_id == left.attempt_id
    assert leaf.root_attempt_id == run.attempts[0].root_attempt_id


@pytest.mark.asyncio
async def test_recursive_tree_respects_depth_and_node_bounds() -> None:
    root = OrchestrationRequest.create("root")
    advisor = _Advisor({})
    advisor.responses["root"] = _decompose(root.orchestration_attempt_id, "child")
    policy = DecompositionPolicy(max_depth=0, max_nodes=8, max_model_calls=8, max_children=4)

    with pytest.raises(DecompositionError, match="depth"):
        await OrchestrationController(advisor, policy).run(root, max_model_calls=8)
    assert len(advisor.requests) == 1

    root = OrchestrationRequest.create("many")
    advisor = _Advisor({})
    advisor.responses["many"] = _decompose(root.orchestration_attempt_id, "a", "b", "c")
    policy = DecompositionPolicy(max_depth=2, max_nodes=2, max_model_calls=8, max_children=4)
    with pytest.raises(DecompositionError, match="node"):
        await OrchestrationController(advisor, policy).run(root, max_model_calls=8)
    assert len(advisor.requests) == 1


@pytest.mark.asyncio
async def test_global_model_call_budget_is_not_reset_for_children_or_synthesis() -> None:
    root = OrchestrationRequest.create("root")
    advisor = _Advisor({})
    advisor.responses["root"] = _decompose(root.orchestration_attempt_id, "child")

    with pytest.raises(DecompositionError, match="budget"):
        await OrchestrationController(advisor).run(root, max_model_calls=2)
    assert len(advisor.requests) == 2


@pytest.mark.asyncio
async def test_duplicate_and_cycle_like_children_fail_closed() -> None:
    root = OrchestrationRequest.create("root")
    advisor = _Advisor({})
    advisor.responses["root"] = _decompose(root.orchestration_attempt_id, "same", "same")
    with pytest.raises(DecompositionError, match="Duplicate"):
        await OrchestrationController(advisor).run(root, max_model_calls=8)

    root = OrchestrationRequest.create("root")
    advisor = _Advisor({})
    advisor.responses["root"] = _decompose(root.orchestration_attempt_id, "root")
    with pytest.raises(DecompositionError, match="Duplicate"):
        await OrchestrationController(advisor).run(root, max_model_calls=8)


@pytest.mark.asyncio
async def test_cancellation_and_deadline_stop_before_another_model_call() -> None:
    root = OrchestrationRequest.create("root")
    advisor = _Advisor({})
    event = asyncio.Event()
    event.set()
    with pytest.raises(DecompositionError, match="cancelled"):
        await OrchestrationController(advisor).run(root, max_model_calls=8, cancellation=event)
    assert not advisor.requests

    with pytest.raises(DecompositionError, match="deadline"):
        await OrchestrationController(advisor).run(
            root, max_model_calls=8, deadline=datetime.now(UTC) - timedelta(seconds=1)
        )


@pytest.mark.asyncio
async def test_replan_uses_distinct_request_and_preserves_budget_seam() -> None:
    advisor = _Advisor({})
    request = OrchestrationRequest.create("replan")
    evidence = cast(ReplanEvidence, object())

    run = await OrchestrationController(advisor).run(
        request, max_model_calls=3, replan_evidence=evidence
    )

    assert run.model_calls == 1
    assert advisor.replan_requests == [request]
    assert request.parent_attempt_id is None


def test_result_is_discriminated_and_never_carries_effect_authority() -> None:
    request = OrchestrationRequest.create("goal")
    result = OrchestrationResult(request.orchestration_attempt_id, proposal={"steps": []})

    assert result.kind is OrchestrationResultKind.DIRECT
    assert result.subproblems == ()
    assert not hasattr(result, "permissions")


@pytest.mark.asyncio
async def test_bounded_tree_reaches_one_validated_owned_plan_before_execution(
    tmp_path: Path,
) -> None:
    from jarvis.planning import (
        CompletionCriteriaVerifier,
        EvidencePlanningStepVerifier,
        ExecutionBudgets,
        PlanAdvisor,
        PlanningEngine,
        PlanValidator,
        SQLitePlanningStore,
    )
    from jarvis.tools.registry import ToolRegistry

    from tests.test_planning_engine import (
        _Clock,
        _Executor,
        _plan,
        _result,
        _step,
        _Tool,
    )

    goal = "Prepare my system for a meeting"
    clock = _Clock()

    class TreeAdvisor(PlanAdvisor):
        def __init__(self) -> None:
            self.calls = 0
            self.requests: list[OrchestrationRequest] = []

        async def propose(
            self, goal: str, assumptions: tuple[str, ...], constraints: tuple[str, ...]
        ) -> object:
            del goal, assumptions, constraints
            return _plan(_step("prepare"))

        async def replan(self, evidence: ReplanEvidence) -> object:
            del evidence
            return _plan(_step("prepare"))

        async def propose_orchestration(self, request: OrchestrationRequest) -> OrchestrationResult:
            self.calls += 1
            self.requests.append(request)
            if self.calls == 1:
                return _decompose(request.orchestration_attempt_id, "prepare", "verify")
            if request.goal == "prepare" and not request.decomposition_context:
                return _decompose(request.orchestration_attempt_id, "prepare-core", "prepare-check")
            return OrchestrationResult(
                request.orchestration_attempt_id,
                proposal=_plan(_step("prepare"), constraints=["hard constraint"]),
            )

    advisor = TreeAdvisor()
    executor = _Executor((_result("prepare-ready"),))
    store = SQLitePlanningStore(tmp_path / "tree.sqlite3", clock=clock)
    engine = PlanningEngine(
        store=store,
        advisor=advisor,
        validator=PlanValidator(ToolRegistry((_Tool("prepare"),)), max_steps=4, clock=clock),
        executor=executor,
        step_verifier=EvidencePlanningStepVerifier(),
        goal_verifier=CompletionCriteriaVerifier(),
        clock=clock,
    )

    created = await engine.create_task(
        goal,
        constraints=("hard constraint",),
        budgets=ExecutionBudgets(max_model_calls=8, max_elapsed_seconds=60),
    )

    assert created.status.value == "ready"
    assert created.usage.model_calls == 7
    assert advisor.calls == 7
    assert len({request.orchestration_attempt_id for request in advisor.requests}) == 7
    assert advisor.requests[1].parent_attempt_id == advisor.requests[0].orchestration_attempt_id
    assert advisor.requests[1].depth == 1
    assert advisor.requests[2].depth == 2
    assert executor.calls == []
    completed = await engine.run(created.task_id)
    assert completed.status.value == "completed"
    assert executor.calls == ["prepare"]
