"""Bounded R3B production-composition workflow tests."""

from __future__ import annotations

import asyncio
import logging
from datetime import UTC, datetime
from pathlib import Path
from uuid import UUID, uuid4

import pytest
from jarvis.core.config import Settings
from jarvis.permissions.models import (
    ApprovalActorKind,
    ApprovalChoice,
    ApprovalIdentity,
    Permission,
)
from jarvis.planning.models import PlanningTaskStatus
from jarvis.planning.validation import PlanProposal, ProposedStep
from jarvis.runtime import ApplicationRuntime, RuntimeStatus
from jarvis.storage import VolumeDriveType, VolumeObservation
from jarvis.storage_tools import StorageInspectOutput, StorageInventoryOutput
from jarvis.tools.models import (
    ToolCaller,
    ToolEffectDisposition,
    ToolExecutionContext,
    ToolResultStatus,
)


def _copy_proposal(source: Path, destination: Path) -> PlanProposal:
    return PlanProposal(
        goal="Copy one acceptance-owned file",
        required_capabilities=["copy"],
        required_permissions=[Permission.FILESYSTEM_WRITE.value],
        completion_criteria=["storage.copy.completed"],
        steps=[
            ProposedStep(
                key="copy",
                tool_id="storage.file_steward",
                capability="copy",
                input={
                    "source": str(source),
                    "destination": str(destination),
                    "max_affected_bytes": 128,
                },
                required_permissions=[Permission.FILESYSTEM_WRITE.value],
                expected_output="copy",
                verification_rule="evidence_contains_all",
                expected_evidence=[
                    "storage.copy.completed",
                    "storage.copy.source_hash",
                    "storage.copy.destination_hash",
                ],
            )
        ],
    )


async def _approve(runtime: ApplicationRuntime, task_id: UUID) -> None:
    assert runtime.container is not None
    requests = await runtime.container.task_controller.pending_approvals(task_id)
    assert len(requests) == 1
    context = runtime.container.desktop_approval_authenticator.issue_context(
        request_id=requests[0].request_id,
        choice=ApprovalChoice.APPROVE_ONCE,
        identity=ApprovalIdentity("desktop-local-user", ApprovalActorKind.TRUSTED_USER),
    )
    decision = await runtime.container.task_controller.submit_approval_decision(context)
    assert decision.accepted


@pytest.mark.asyncio
async def test_registered_storage_inspect_is_bounded_and_read_only(tmp_path: Path) -> None:
    runtime = ApplicationRuntime.create(
        Settings(app_data_dir=tmp_path / "app-data", ai_provider="ollama")
    )
    assert runtime.container is not None
    container = runtime.container
    target = container.file_steward.root / "acceptance" / "observed.bin"
    target.parent.mkdir(parents=True)
    target.write_bytes(b"read-only observation")
    before = target.read_bytes()
    tool = container.tool_registry.get("storage.inspect")
    result = await tool.invoke(
        ToolExecutionContext(
            task_id=uuid4(),
            correlation_id=uuid4(),
            caller=ToolCaller.TEST,
            cancellation=asyncio.Event(),
            logger=logging.getLogger("v1-i-r3b.inspect"),
        ),
        {"path": str(target)},
        container.permission_broker,
    )
    assert result.succeeded
    assert isinstance(result.output, StorageInspectOutput)
    assert result.output.size_bytes == len(before)
    assert result.output.content_hash
    assert result.output.is_directory is False
    assert tool.manifest.declared_permissions == frozenset({Permission.FILESYSTEM_READ})
    assert target.read_bytes() == before
    await runtime.aclose()


@pytest.mark.asyncio
async def test_registered_storage_inventory_is_read_only_and_uses_observed_provider(
    tmp_path: Path,
) -> None:
    runtime = ApplicationRuntime.create(
        Settings(app_data_dir=tmp_path / "app-data", ai_provider="ollama")
    )
    assert runtime.container is not None
    container = runtime.container
    observed = VolumeObservation(
        "acceptance-volume",
        (str(container.file_steward.root),),
        "testfs",
        1_000,
        400,
        600,
        VolumeDriveType.FIXED,
        None,
        None,
        None,
        False,
        False,
        False,
        False,
        datetime.now(UTC),
        "acceptance-owned-provider",
    )
    container.storage_inventory._probe = lambda: (observed,)  # noqa: SLF001
    tool = container.tool_registry.get("storage.inventory")
    result = await tool.invoke(
        ToolExecutionContext(
            task_id=uuid4(),
            correlation_id=uuid4(),
            caller=ToolCaller.TEST,
            cancellation=asyncio.Event(),
            logger=logging.getLogger("v1-i-r3b.inventory"),
        ),
        {},
        container.permission_broker,
    )
    assert result.succeeded
    assert isinstance(result.output, StorageInventoryOutput)
    assert result.output.volume_ids == ("acceptance-volume",)
    assert result.output.free_bytes == (600,)
    assert tool.manifest.declared_permissions == frozenset({Permission.FILESYSTEM_READ})
    assert container.storage_inventory.last == (observed,)
    await runtime.aclose()


@pytest.mark.asyncio
async def test_registered_storage_inspect_reports_unavailable_outside_owned_root(
    tmp_path: Path,
) -> None:
    runtime = ApplicationRuntime.create(
        Settings(app_data_dir=tmp_path / "app-data", ai_provider="ollama")
    )
    assert runtime.container is not None
    container = runtime.container
    tool = container.tool_registry.get("storage.inspect")
    result = await tool.invoke(
        ToolExecutionContext(
            task_id=uuid4(),
            correlation_id=uuid4(),
            caller=ToolCaller.TEST,
            cancellation=asyncio.Event(),
            logger=logging.getLogger("v1-i-r3b.inspect-unavailable"),
        ),
        {"path": str(tmp_path / "outside.bin")},
        container.permission_broker,
    )
    assert result.status is ToolResultStatus.UNAVAILABLE
    assert result.effect_disposition is ToolEffectDisposition.NO_EFFECT
    assert result.error is not None
    assert result.error.code == "storage_inspection_unavailable"
    await runtime.aclose()


@pytest.mark.asyncio
async def test_registered_storage_inventory_reports_unavailable_provider(
    tmp_path: Path,
) -> None:
    runtime = ApplicationRuntime.create(
        Settings(app_data_dir=tmp_path / "app-data", ai_provider="ollama")
    )
    assert runtime.container is not None
    container = runtime.container

    def failing_probe() -> tuple[VolumeObservation, ...]:
        raise RuntimeError("acceptance provider failure")

    container.storage_inventory._probe = failing_probe  # noqa: SLF001
    tool = container.tool_registry.get("storage.inventory")
    result = await tool.invoke(
        ToolExecutionContext(
            task_id=uuid4(),
            correlation_id=uuid4(),
            caller=ToolCaller.TEST,
            cancellation=asyncio.Event(),
            logger=logging.getLogger("v1-i-r3b.inventory-unavailable"),
        ),
        {},
        container.permission_broker,
    )
    assert result.status is ToolResultStatus.UNAVAILABLE
    assert result.effect_disposition is ToolEffectDisposition.NO_EFFECT
    assert result.error is not None
    assert result.error.code == "storage_inventory_unavailable"
    await runtime.aclose()


@pytest.mark.asyncio
async def test_runtime_storage_copy_denied_has_no_effect(tmp_path: Path) -> None:
    runtime = ApplicationRuntime.create(
        Settings(app_data_dir=tmp_path / "app-data", ai_provider="ollama")
    )
    assert runtime.container is not None
    root = runtime.container.file_steward.root
    source = root / "acceptance" / "source.bin"
    destination = root / "acceptance" / "destination.bin"
    source.parent.mkdir(parents=True)
    source.write_bytes(b"denied")
    task = await runtime.container.task_controller.submit_proposal(
        _copy_proposal(source, destination)
    )
    assert task.status is PlanningTaskStatus.WAITING_FOR_PERMISSION
    request = (await runtime.container.task_controller.pending_approvals(task.task_id))[0]
    context = runtime.container.desktop_approval_authenticator.issue_context(
        request_id=request.request_id,
        choice=ApprovalChoice.DENY_ONCE,
        identity=ApprovalIdentity("desktop-local-user", ApprovalActorKind.TRUSTED_USER),
    )
    decision = await runtime.container.task_controller.submit_approval_decision(context)
    assert decision.accepted
    rejected = await runtime.container.task_controller.resume_task(task.task_id)
    assert rejected.status is PlanningTaskStatus.WAITING_FOR_PERMISSION
    assert not destination.exists()
    await runtime.aclose()


@pytest.mark.asyncio
async def test_runtime_storage_copy_is_brokered_durable_and_not_replayed(tmp_path: Path) -> None:
    settings = Settings(app_data_dir=tmp_path / "app-data", ai_provider="ollama")
    runtime = ApplicationRuntime.create(settings)
    assert runtime.status is RuntimeStatus.READY
    assert runtime.container is not None
    root = runtime.container.file_steward.root
    source = root / "acceptance" / "source.bin"
    destination = root / "acceptance" / "destination.bin"
    source.parent.mkdir(parents=True)
    source.write_bytes(b"R3B-P1 deterministic bytes")

    task = await runtime.container.task_controller.submit_proposal(
        _copy_proposal(source, destination)
    )
    assert task.status is PlanningTaskStatus.WAITING_FOR_PERMISSION
    assert not destination.exists()
    await _approve(runtime, task.task_id)
    completed = await runtime.container.task_controller.resume_task(task.task_id)
    assert completed.status is PlanningTaskStatus.COMPLETED
    assert destination.read_bytes() == source.read_bytes()
    result = runtime.container.task_controller.get_result(task.task_id)
    assert result is not None and result.plan is not None
    step_result = result.plan.steps[0].result
    assert step_result is not None
    manifest_id = step_result.output_json
    assert "storage.copy.destination_hash" in result.evidence
    await runtime.aclose()

    restarted = ApplicationRuntime.create(settings)
    assert restarted.status is RuntimeStatus.READY
    assert restarted.container is not None
    persisted = restarted.container.task_controller.get_result(task.task_id)
    assert persisted is not None and persisted.status is PlanningTaskStatus.COMPLETED
    assert destination.read_bytes() == source.read_bytes()
    assert len(tuple(restarted.container.file_steward.manifests.manifest_root.glob("*.json"))) == 1
    assert manifest_id
    await restarted.aclose()


@pytest.mark.asyncio
async def test_runtime_storage_preview_and_stale_source_have_no_unapproved_copy(
    tmp_path: Path,
) -> None:
    runtime = ApplicationRuntime.create(
        Settings(app_data_dir=tmp_path / "app-data", ai_provider="ollama")
    )
    assert runtime.container is not None
    root = runtime.container.file_steward.root
    source = root / "acceptance" / "source.bin"
    destination = root / "acceptance" / "destination.bin"
    source.parent.mkdir(parents=True)
    source.write_bytes(b"before")
    planned = runtime.container.file_steward.plan_copy(source, destination, max_affected_bytes=128)
    assert planned.state.value == "planned"
    assert not destination.exists()

    task = await runtime.container.task_controller.submit_proposal(
        _copy_proposal(source, destination)
    )
    assert task.status is PlanningTaskStatus.WAITING_FOR_PERMISSION
    source.write_bytes(b"changed")
    await _approve(runtime, task.task_id)
    rejected = await runtime.container.task_controller.resume_task(task.task_id)
    assert rejected.status is PlanningTaskStatus.FAILED
    assert not destination.exists()
    await runtime.aclose()
