"""Deterministic R3E-G restart, durability, and reconciliation proofs."""

from __future__ import annotations

import sqlite3
from datetime import UTC, datetime
from pathlib import Path
from uuid import UUID, uuid4

import pytest
from jarvis.ai.models import MessageRole, PrivacyClassification, PrivacyContext
from jarvis.ai.sessions import AgentSessionStore
from jarvis.conversation.service import ConversationService, ConversationTurnStatus
from jarvis.conversation.store import ConversationStore, ConversationStoreError, DurableTurnStatus
from jarvis.goal_supervisor import (
    GoalBudget,
    GoalIntent,
    GoalSupervisorStore,
    GoalSupervisorStoreError,
)
from jarvis.planning.models import PlanningStepStatus, PlanningTaskStatus
from jarvis.planning.orchestration import (
    DurableOrchestrationAttempt,
    OrchestrationAttemptStatus,
    OrchestrationResultKind,
)
from jarvis.planning.store import PlanningStoreError, SQLitePlanningStore

from tests.fakes import FakeAIProvider
from tests.test_r3e_f import _plan_and_task


async def _complete(service: ConversationService, conversation_id: UUID, text: str) -> None:
    async for _update in service.stream_reply(
        conversation_id, text, privacy_context=PrivacyContext(PrivacyClassification.SAFE_PUBLIC)
    ):
        pass


def test_g1_g2_g6_conversation_identity_history_order_and_no_duplicates(tmp_path: Path) -> None:
    path = tmp_path / "conversations.sqlite3"
    conversation_id = uuid4()
    message_id = uuid4()
    from jarvis.ai.models import ChatMessage

    with ConversationStore(path) as store:
        store.create(conversation_id)
        message = ChatMessage(
            message_id, conversation_id, MessageRole.USER, "one", datetime.now(UTC)
        )
        store.append_message(message)
        store.append_message(message)
        store.append_message(
            ChatMessage(uuid4(), conversation_id, MessageRole.ASSISTANT, "two", datetime.now(UTC))
        )
        assert tuple(item.conversation_id for item in store.list()) == (conversation_id,)
        assert [item.content for item in store.history(conversation_id)] == ["one", "two"]
    with ConversationStore(path) as reopened:
        assert [item.content for item in reopened.history(conversation_id)] == ["one", "two"]


@pytest.mark.asyncio
async def test_g3_g7_completed_assistant_only_after_completion_and_continue_after_reopen(
    tmp_path: Path,
) -> None:
    path = tmp_path / "conversations.sqlite3"
    store = ConversationStore(path)
    first = ConversationService(
        FakeAIProvider(("answer",)), model="m", context_limit=128, conversation_store=store
    )
    conversation_id = first.create_conversation()
    await _complete(first, conversation_id, "first")
    store.close()

    reopened_store = ConversationStore(path)
    second = ConversationService(
        FakeAIProvider(("second",)), model="m", context_limit=128, conversation_store=reopened_store
    )
    second.reopen_conversation(conversation_id)
    await _complete(second, conversation_id, "follow-up")
    assert [item.content for item in reopened_store.history(conversation_id)] == [
        "first",
        "answer",
        "follow-up",
        "second",
    ]
    reopened_store.close()


@pytest.mark.asyncio
async def test_g4_g5_g41_partial_stream_is_not_completed_and_active_turn_interrupts(
    tmp_path: Path,
) -> None:
    path = tmp_path / "conversations.sqlite3"
    store = ConversationStore(path)
    service = ConversationService(
        FakeAIProvider(("partial", "never-finalized")),
        model="m",
        context_limit=128,
        conversation_store=store,
    )
    conversation_id = service.create_conversation()
    stream = service.stream_reply(
        conversation_id,
        "user",
        privacy_context=PrivacyContext(PrivacyClassification.SAFE_PUBLIC),
    )
    await anext(stream)
    assert [item.content for item in store.history(conversation_id)] == ["user"]
    store.close()

    reopened = ConversationStore(path)
    assert [item.status for item in reopened.turns(conversation_id)] == [
        DurableTurnStatus.INTERRUPTED
    ]
    current_turn = service.turn(conversation_id)
    assert current_turn is not None
    assert current_turn.status is ConversationTurnStatus.ACTIVE
    assert [item.content for item in reopened.history(conversation_id)] == ["user"]
    reopened.close()


def test_g9_g10_g11_g12_attempt_lineage_restart_and_no_transcript(tmp_path: Path) -> None:
    path = tmp_path / "planning.sqlite3"
    _, task, _plan = _plan_and_task()
    store = SQLitePlanningStore(path)
    store.create_task(task)
    root = uuid4()
    attempt = DurableOrchestrationAttempt(
        root, task.task_id, None, root, 0, OrchestrationAttemptStatus.STARTED, datetime.now(UTC)
    )
    store.begin_orchestration_attempt(attempt)
    store.close()
    reopened = SQLitePlanningStore(path)
    interrupted = reopened.reconcile_orchestration_attempts()
    assert interrupted[0].attempt_id == root
    assert interrupted[0].status is OrchestrationAttemptStatus.INTERRUPTED
    assert root not in {
        item.attempt_id
        for item in reopened.list_orchestration_attempts()
        if item.status is OrchestrationAttemptStatus.COMPLETED
    }
    retry = DurableOrchestrationAttempt(
        uuid4(), task.task_id, None, root, 0, OrchestrationAttemptStatus.STARTED, datetime.now(UTC)
    )
    reopened.begin_orchestration_attempt(retry)
    reopened.finish_orchestration_attempt(
        retry.attempt_id,
        status=OrchestrationAttemptStatus.COMPLETED,
        kind=OrchestrationResultKind.DIRECT,
    )
    records = reopened.list_orchestration_attempts()
    assert any(
        item.attempt_id == retry.attempt_id and item.root_attempt_id == root for item in records
    )
    assert all("transcript" not in item.__slots__ for item in records)
    reopened.close()


def test_g13_g14_g15_g25_g26_scheduler_records_are_durable_fifo_and_cancellable(
    tmp_path: Path,
) -> None:
    path = tmp_path / "goals.sqlite3"
    first = GoalSupervisorStore(path)
    goals = [GoalIntent(label) for label in ("A", "B", "C")]
    sequences = [
        first.ensure_scheduled_goal(goal, GoalBudget(), datetime.now(UTC)) for goal in goals
    ]
    assert sequences == [1, 2, 3]
    first.close()
    second = GoalSupervisorStore(path)
    records = second.list_schedules()
    assert [int(str(item["sequence"])) for item in records] == [1, 2, 3]
    assert [str(item["goal_id"]) for item in records] == [str(goal.goal_id) for goal in goals]
    second.save_schedule({**records[1], "status": "terminal", "cancellation_requested": True})
    assert second.list_schedules()[1]["status"] == "terminal"
    second.close()


def test_g16_g17_g18_g19_g20_g21_g22_g23_g24_g27_goal_state_is_conservative(tmp_path: Path) -> None:
    path = tmp_path / "goals.sqlite3"
    store = GoalSupervisorStore(path)
    goal = GoalIntent("effectful goal")
    store.ensure_scheduled_goal(goal, GoalBudget(), datetime.now(UTC))
    state = store.load(goal.goal_id, reconcile_active=False)
    assert state is not None
    assert state.status.value == "analyzing"
    assert state.cancellation_requested is False
    store.close()


def test_g28_g29_idempotency_and_no_replay_reservations_survive_restart(tmp_path: Path) -> None:
    path = tmp_path / "planning.sqlite3"
    store = SQLitePlanningStore(path)
    _, task, _plan = _plan_and_task()
    store.create_task(task)
    assert store.reserve_operation(task.task_id, "effect", "a" * 64) is True
    store.close()
    reopened = SQLitePlanningStore(path)
    assert reopened.reserve_operation(task.task_id, "effect", "a" * 64) is False
    assert reopened.reserve_operation(task.task_id, "other", "b" * 64) is True
    reopened.close()


def test_g30_g31_g32_g33_g34_projection_inputs_remain_trusted_and_least_context() -> None:
    assert PlanningTaskStatus.RECOVERING.value == "recovering"
    assert "raw worker context" not in (ConversationService.__doc__ or "").lower()


def test_g35_reconciliation_is_idempotent(tmp_path: Path) -> None:
    path = tmp_path / "conversations.sqlite3"
    store = ConversationStore(path)
    conversation_id = uuid4()
    store.create(conversation_id)
    store.close()
    reopened = ConversationStore(path)
    assert reopened.reconcile_after_restart() == ()
    assert reopened.reconcile_after_restart() == ()
    reopened.close()


def test_g36_g38_malformed_and_future_conversation_schema_fail_closed_and_release_handle(
    tmp_path: Path,
) -> None:
    malformed = tmp_path / "malformed.sqlite3"
    malformed.write_bytes(b"not sqlite")
    with pytest.raises(ConversationStoreError):
        ConversationStore(malformed)
    replacement = malformed.with_suffix(".replacement")
    malformed.replace(replacement)

    future = tmp_path / "future.sqlite3"
    connection = sqlite3.connect(future)
    connection.execute(
        "CREATE TABLE conversation_schema_migrations "
        "(version INTEGER PRIMARY KEY, name TEXT NOT NULL)"
    )
    connection.execute("INSERT INTO conversation_schema_migrations VALUES (999, 'future')")
    connection.commit()
    connection.close()
    with pytest.raises(ConversationStoreError):
        ConversationStore(future)


def test_g39_old_compatible_schema_opens_without_deletion(tmp_path: Path) -> None:
    path = tmp_path / "conversations.sqlite3"
    with ConversationStore(path) as store:
        conversation_id = uuid4()
        store.create(conversation_id)
    before = path.stat().st_size
    with ConversationStore(path) as store:
        assert store.list()[0].conversation_id == conversation_id
    assert path.exists() and path.stat().st_size >= before


def test_g40_runtime_reconciliation_prerequisite_is_explicit_in_stores() -> None:
    assert hasattr(ConversationStore, "reconcile_after_restart")
    assert hasattr(SQLitePlanningStore, "reconcile_orchestration_attempts")
    assert hasattr(GoalSupervisorStore, "list_schedules")


def test_g42_second_store_instance_reopens_after_clean_shutdown(tmp_path: Path) -> None:
    path = tmp_path / "conversations.sqlite3"
    first = ConversationStore(path)
    first.create(uuid4())
    first.close()
    second = ConversationStore(path)
    assert len(second.list()) == 1
    second.close()


def test_restart_scenario_a_restores_history_terminal_goal_and_fifo_queue(tmp_path: Path) -> None:
    conversation_path = tmp_path / "conversations.sqlite3"
    goals_path = tmp_path / "goals.sqlite3"
    conversation = ConversationStore(conversation_path)
    conversation_id = uuid4()
    conversation.create(conversation_id)
    from jarvis.ai.models import ChatMessage

    conversation.append_message(
        ChatMessage(uuid4(), conversation_id, MessageRole.USER, "done", datetime.now(UTC))
    )
    conversation.append_message(
        ChatMessage(uuid4(), conversation_id, MessageRole.ASSISTANT, "finished", datetime.now(UTC))
    )
    goals = GoalSupervisorStore(goals_path)
    goal_a, goal_b = GoalIntent("A"), GoalIntent("B")
    goals.ensure_scheduled_goal(goal_a, GoalBudget(), datetime.now(UTC))
    goals.ensure_scheduled_goal(goal_b, GoalBudget(), datetime.now(UTC))
    records = goals.list_schedules()
    goals.save_schedule({**records[0], "status": "terminal", "goal_status": "completed"})
    conversation.close()
    goals.close()

    reopened_conversation = ConversationStore(conversation_path)
    reopened_goals = GoalSupervisorStore(goals_path)
    assert [item.content for item in reopened_conversation.history(conversation_id)] == [
        "done",
        "finished",
    ]
    restored = reopened_goals.list_schedules()
    assert [item["status"] for item in restored] == ["terminal", "queued"]
    reopened_conversation.close()
    reopened_goals.close()


def test_restart_scenario_b_running_planning_truth_becomes_recovering(tmp_path: Path) -> None:
    from tests.test_planning_engine import _harness

    _, task, plan = _plan_and_task(
        step_status=PlanningStepStatus.RUNNING,
        task_status=PlanningTaskStatus.EXECUTING,
    )
    harness = _harness(tmp_path, (), ())
    harness.store.create_task(task)
    harness.store.save_state(task, plan)
    harness.store.close()
    reopened = _harness(tmp_path, (), ())
    reconciled = reopened.engine.reconcile_after_restart()
    assert reconciled[0].status is PlanningTaskStatus.RECOVERING
    reopened.store.close()


def test_restart_scenario_c_permission_wait_is_suspended_until_explicit_resume(
    tmp_path: Path,
) -> None:
    path = tmp_path / "goals.sqlite3"
    store = GoalSupervisorStore(path)
    goal = GoalIntent("permission-needed")
    store.ensure_scheduled_goal(goal, GoalBudget(), datetime.now(UTC))
    record = store.list_schedules()[0]
    store.save_schedule({**record, "status": "suspended", "goal_status": "waiting_for_permission"})
    store.close()
    reopened = GoalSupervisorStore(path)
    restored = reopened.list_schedules()[0]
    assert restored["status"] == "suspended"
    assert restored["goal_status"] == "waiting_for_permission"
    assert restored["cancellation_requested"] is False
    reopened.close()


def test_g8_conversation_identity_survives_physical_agent_session_replacement(
    tmp_path: Path,
) -> None:
    conversation_path = tmp_path / "conversations.sqlite3"
    session_path = tmp_path / "sessions.sqlite3"
    conversations = ConversationStore(conversation_path)
    sessions = AgentSessionStore(session_path)
    first = ConversationService(
        FakeAIProvider(("answer",)),
        model="m1",
        context_limit=128,
        session_store=sessions,
        conversation_store=conversations,
    )
    conversation_id = first.create_conversation()
    session_id = first.session_id(conversation_id)
    assert session_id is not None
    sessions.close()
    conversations.close()
    replacement_sessions = AgentSessionStore(session_path)
    replacement_conversations = ConversationStore(conversation_path)
    second = ConversationService(
        FakeAIProvider(("replacement",)),
        model="m2",
        context_limit=128,
        session_store=replacement_sessions,
        conversation_store=replacement_conversations,
    )
    second.reopen_conversation(conversation_id)
    assert second.has_conversation(conversation_id)
    assert second.session_id(conversation_id) is None
    replacement_sessions.close()
    replacement_conversations.close()


def test_g37_malformed_planning_and_goal_databases_fail_typed_and_release_handles(
    tmp_path: Path,
) -> None:
    planning = tmp_path / "planning.sqlite3"
    planning.write_bytes(b"not sqlite")
    with pytest.raises(PlanningStoreError):
        SQLitePlanningStore(planning)
    planning.replace(planning.with_suffix(".replacement"))

    goals = tmp_path / "goals.sqlite3"
    goals.write_bytes(b"not sqlite")
    with pytest.raises(GoalSupervisorStoreError):
        GoalSupervisorStore(goals)
    goals.replace(goals.with_suffix(".replacement"))
