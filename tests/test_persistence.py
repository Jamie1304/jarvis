"""Crash-consistency contracts for the canonical planning runtime."""

from __future__ import annotations

import sqlite3
from dataclasses import replace
from datetime import UTC, datetime
from pathlib import Path
from uuid import uuid4

import pytest
from jarvis.core.config import Settings
from jarvis.core.errors import ServiceUnavailableError, SpeechDisabledError
from jarvis.permissions.audit import AuditStoreError, SQLiteAuditSink
from jarvis.permissions.models import AuditRecord, Decision, DecisionReason
from jarvis.planning.engine import task_state_for_status
from jarvis.planning.models import OwnedPlanStatus, PlanningStepStatus, PlanningTaskStatus
from jarvis.planning.store import PlanningStoreError, SQLitePlanningStore
from jarvis.runtime import ApplicationRuntime, RuntimeStatus
from jarvis.speech.stt import AudioData, SpeechToTextService
from jarvis.speech.tts import TextToSpeechService
from jarvis.state import SQLiteStateStore, StateStoreError
from jarvis.state.models import ApplicationState, TaskState

from tests.fakes import FakeAIProvider, FakeRecorder, FakeSttProvider, FakeTtsProvider


@pytest.mark.asyncio
async def test_operation_idempotency_keys_fail_closed(tmp_path: Path) -> None:
    runtime = ApplicationRuntime.create(
        Settings(app_data_dir=tmp_path / "data", ai_provider="ollama")
    )
    assert runtime.container is not None
    task = await runtime.container.task_controller.submit_task("calculate 25% of 800")
    store = runtime.container.planning_store
    assert store.reserve_operation(task.task_id, "manual-test", "a" * 64)
    assert not store.reserve_operation(task.task_id, "manual-test", "a" * 64)
    with pytest.raises(PlanningStoreError, match="fingerprint mismatch"):
        store.reserve_operation(task.task_id, "manual-test", "b" * 64)
    with pytest.raises(PlanningStoreError, match="malformed"):
        store.reserve_operation(task.task_id, "", "a" * 64)
    await runtime.aclose()


def test_future_planning_schema_refuses_startup(tmp_path: Path) -> None:
    path = tmp_path / "planning.sqlite3"
    store = SQLitePlanningStore(path)
    store.close()
    connection = sqlite3.connect(path)
    connection.execute(
        "INSERT INTO planning_schema_migrations(version, name, applied_at) "
        "VALUES (99, 'future', 'x')"
    )
    connection.commit()
    connection.close()
    with pytest.raises(PlanningStoreError, match="future schema"):
        SQLitePlanningStore(path)


def test_future_state_schema_refuses_startup(tmp_path: Path) -> None:
    path = tmp_path / "state.sqlite3"
    store = SQLiteStateStore(path)
    store.close()
    connection = sqlite3.connect(path)
    connection.execute("INSERT INTO state_schema(version) VALUES (99)")
    connection.commit()
    connection.close()
    with pytest.raises(StateStoreError, match="future schema"):
        SQLiteStateStore(path)


@pytest.mark.asyncio
async def test_corrupt_runtime_database_enters_safe_mode(tmp_path: Path) -> None:
    data = tmp_path / "data"
    data.mkdir()
    (data / "planning.sqlite3").write_text("not a sqlite database", encoding="utf-8")
    runtime = ApplicationRuntime.create(Settings(app_data_dir=data, ai_provider="ollama"))
    assert runtime.status is RuntimeStatus.SAFE_MODE
    assert runtime.container is None


@pytest.mark.asyncio
async def test_corrupt_state_database_enters_safe_mode(tmp_path: Path) -> None:
    data = tmp_path / "data"
    data.mkdir()
    (data / "state.sqlite3").write_text("not a sqlite database", encoding="utf-8")
    runtime = ApplicationRuntime.create(Settings(app_data_dir=data, ai_provider="ollama"))
    assert runtime.status is RuntimeStatus.SAFE_MODE
    assert runtime.container is None
    await runtime.aclose()


def test_future_audit_schema_refuses_startup(tmp_path: Path) -> None:
    path = tmp_path / "audit.sqlite3"
    sink = SQLiteAuditSink(path)
    sink.close()
    connection = sqlite3.connect(path)
    connection.execute("INSERT INTO audit_schema_migrations(version) VALUES (99)")
    connection.commit()
    connection.close()

    with pytest.raises(AuditStoreError, match="future schema"):
        SQLiteAuditSink(path)


@pytest.mark.asyncio
async def test_audit_is_append_only_and_validates_lifecycle_shape(tmp_path: Path) -> None:
    sink = SQLiteAuditSink(tmp_path / "audit.sqlite3")
    task_id = uuid4()
    await sink.append(
        AuditRecord(
            time=datetime.now(UTC),
            user_id=None,
            task_id=task_id,
            tool_id="calculator",
            requested_permission=None,
            action="invoke",
            argument_names=("expression",),
            argument_fingerprint="a" * 64,
            normalized_scope=None,
            policy_id=None,
            decision=Decision.ALLOW,
            reason=DecisionReason.POLICY_ALLOW,
            approval_identity=None,
            approval_source=None,
            execution_outcome="succeeded",
        )
    )
    sink.record_lifecycle("planning.task_persisted", task_id=task_id, detail={"status": "ready"})
    assert sink.lifecycle_entries()[0][1:] == (
        "planning.task_persisted",
        str(task_id),
        '{"status":"ready"}',
    )
    with pytest.raises(ValueError, match="malformed"):
        sink.record_lifecycle("", task_id=task_id, detail={})
    sink.close()


@pytest.mark.asyncio
async def test_corrupt_audit_database_enters_safe_mode(tmp_path: Path) -> None:
    data = tmp_path / "data"
    data.mkdir()
    (data / "audit.sqlite3").write_text("not a sqlite database", encoding="utf-8")
    runtime = ApplicationRuntime.create(Settings(app_data_dir=data, ai_provider="ollama"))
    assert runtime.status is RuntimeStatus.SAFE_MODE
    assert runtime.container is None
    await runtime.aclose()


@pytest.mark.parametrize(
    ("status", "expected"),
    [
        (PlanningTaskStatus.CREATED, TaskState.CREATED),
        (PlanningTaskStatus.PLANNING, TaskState.PLANNING),
        (PlanningTaskStatus.READY, TaskState.WAITING),
        (PlanningTaskStatus.EXECUTING, TaskState.EXECUTING),
        (PlanningTaskStatus.WAITING_FOR_PERMISSION, TaskState.WAITING_FOR_PERMISSION),
        (PlanningTaskStatus.VERIFYING, TaskState.VERIFYING),
        (PlanningTaskStatus.REPLANNING, TaskState.THINKING),
        (PlanningTaskStatus.RECOVERING, TaskState.RECOVERING),
        (PlanningTaskStatus.COMPLETED, TaskState.COMPLETED),
        (PlanningTaskStatus.FAILED, TaskState.ERROR),
        (PlanningTaskStatus.CANCELLED, TaskState.CANCELLED),
        (PlanningTaskStatus.BUDGET_EXHAUSTED, TaskState.ERROR),
    ],
)
def test_planning_status_projection_is_exhaustive(
    status: PlanningTaskStatus, expected: TaskState
) -> None:
    assert task_state_for_status(status) is expected


@pytest.mark.asyncio
async def test_restart_marks_inflight_operation_recovering_without_replay(tmp_path: Path) -> None:
    settings = Settings(app_data_dir=tmp_path / "data", ai_provider="ollama")
    runtime = ApplicationRuntime.create(settings)
    assert runtime.container is not None
    created = await runtime.container.task_controller.create_task("calculate 25% of 800")
    plan = runtime.container.task_controller.inspect_plan(created.task_id)
    assert plan is not None
    interrupted_plan = replace(
        plan,
        status=OwnedPlanStatus.ACTIVE,
        steps=(replace(plan.steps[0], status=PlanningStepStatus.RUNNING, attempts=1),),
    )
    interrupted_task = replace(
        created,
        status=PlanningTaskStatus.EXECUTING,
        active_step_id=plan.steps[0].step_id,
    )
    runtime.container.planning_store.save_state(interrupted_task, interrupted_plan)
    await runtime.aclose()

    restarted = ApplicationRuntime.create(settings)
    assert restarted.status is RuntimeStatus.READY, restarted.error
    assert restarted.container is not None
    recovered = restarted.container.task_controller.get_task(created.task_id)
    assert recovered is not None
    assert recovered.status is PlanningTaskStatus.RECOVERING
    assert recovered.error is not None
    assert recovered.error.code == "unknown_operation_outcome"
    assert restarted.container.state_machine.task(created.task_id) is not None
    await restarted.aclose()


@pytest.mark.asyncio
async def test_restart_invalidates_pending_approval_and_requires_fresh_request(
    tmp_path: Path,
) -> None:
    settings = Settings(app_data_dir=tmp_path / "data", ai_provider="ollama")
    runtime = ApplicationRuntime.create(settings)
    assert runtime.container is not None
    created = await runtime.container.task_controller.create_task("calculate 25% of 800")
    plan = runtime.container.task_controller.inspect_plan(created.task_id)
    assert plan is not None
    paused_plan = replace(
        plan,
        status=OwnedPlanStatus.WAITING_FOR_PERMISSION,
        steps=(replace(plan.steps[0], status=PlanningStepStatus.WAITING_FOR_PERMISSION),),
    )
    paused_task = replace(
        created,
        status=PlanningTaskStatus.WAITING_FOR_PERMISSION,
        active_step_id=plan.steps[0].step_id,
        waiting_request_ids=(uuid4(),),
    )
    runtime.container.planning_store.save_state(paused_task, paused_plan)
    await runtime.aclose()

    restarted = ApplicationRuntime.create(settings)
    assert restarted.status is RuntimeStatus.READY
    assert restarted.container is not None
    resumed = restarted.container.task_controller.get_task(created.task_id)
    resumed_plan = restarted.container.task_controller.inspect_plan(created.task_id)
    assert resumed is not None and resumed_plan is not None
    assert resumed.status is PlanningTaskStatus.READY
    assert resumed.waiting_request_ids == ()
    assert resumed_plan.status is OwnedPlanStatus.ACTIVE
    assert resumed_plan.steps[0].status is PlanningStepStatus.QUEUED
    await restarted.aclose()


@pytest.mark.asyncio
async def test_ui_task_wrappers_use_only_the_runtime_task_controller(tmp_path: Path) -> None:
    from jarvis.application import JarvisAssistantService
    from jarvis.bootstrap import create_assistant_from_runtime

    settings = Settings(app_data_dir=tmp_path / "data", ai_provider="ollama")
    runtime = ApplicationRuntime.create(settings)
    assert runtime.container is not None
    service = create_assistant_from_runtime(runtime)
    conversation_id = service.create_conversation()
    created = await service.create_task(conversation_id, "Jarvis, calculate 25% of 800")
    completed = await service.run_task(created.task_id)
    assert completed.status is PlanningTaskStatus.COMPLETED
    submitted = await service.submit_task(conversation_id, "calculate 25% of 800")
    assert submitted.status is PlanningTaskStatus.COMPLETED
    assert service.application_state is ApplicationState.IDLE

    unconfigured = JarvisAssistantService(runtime.container.conversation)
    assert not unconfigured.stt_enabled
    assert not unconfigured.tts_enabled
    assert unconfigured.voice_status is None
    assert unconfigured.application_state is ApplicationState.IDLE
    unconfigured.cancel(conversation_id)
    with pytest.raises(ServiceUnavailableError):
        await unconfigured.create_task(conversation_id, "calculate 25% of 800")
    with pytest.raises(SpeechDisabledError):
        await unconfigured.start_recording()
    with pytest.raises(SpeechDisabledError):
        await unconfigured.stop_recording()
    await runtime.aclose()


@pytest.mark.asyncio
async def test_application_service_exposes_transient_speech_lifecycle() -> None:
    from jarvis.application import JarvisAssistantService
    from jarvis.conversation.service import ConversationService

    provider = FakeAIProvider()
    recorder = FakeRecorder(
        AudioData(samples=(0.1,), sample_rate=16_000, captured_at=datetime.now(UTC))
    )
    stt_provider = FakeSttProvider("calculate 25% of 800")
    tts_provider = FakeTtsProvider()
    service = JarvisAssistantService(
        ConversationService(provider, model="fake", context_limit=64),
        stt=SpeechToTextService(recorder, stt_provider),
        tts=TextToSpeechService(tts_provider, enabled=True),
    )
    assert service.stt_enabled
    assert service.tts_enabled
    assert service.voice_status is None
    assert (await service.provider_status()).available
    await service.start_recording()
    transcription = await service.stop_recording()
    assert transcription.text == "calculate 25% of 800"
    await service.aclose()
    assert recorder.closed
    assert provider.closed


@pytest.mark.asyncio
async def test_bootstrap_assistant_default_keeps_hardware_disabled(tmp_path: Path) -> None:
    from jarvis.bootstrap import create_application_runtime, create_assistant_service

    settings = Settings(
        app_data_dir=tmp_path / "data",
        ai_provider="ollama",
        stt_enabled=False,
        tts_enabled=False,
    )
    assistant = create_assistant_service(settings)
    assert not assistant.stt_enabled
    assert not assistant.tts_enabled
    await assistant.aclose()

    runtime = create_application_runtime(settings)
    assert runtime.status is RuntimeStatus.READY
    await runtime.aclose()
