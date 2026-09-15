"""Bounded V1-I-R1 product-composition acceptance for D and E."""

from __future__ import annotations

import asyncio
import logging
from dataclasses import replace
from datetime import UTC, datetime, timedelta
from pathlib import Path
from uuid import UUID, uuid4

import pytest
from jarvis.acceptance.evidence import HostSideEffectMonitor
from jarvis.core.config import Settings
from jarvis.credentials import SecretBackend, TestOnlyInMemorySecretBackend
from jarvis.permissions import PermissionBroker, PolicyEngine
from jarvis.permissions.models import (
    ApprovalActorKind,
    ApprovalChoice,
    ApprovalIdentity,
    AuthorizationReceipt,
    Permission,
)
from jarvis.planning.models import PlanningTaskStatus
from jarvis.planning.validation import PlanProposal, ProposedStep
from jarvis.runtime import ApplicationRuntime, RuntimeStatus
from jarvis.tools.models import (
    ToolCaller,
    ToolEffectDisposition,
    ToolExecutionContext,
    ToolResultStatus,
)
from jarvis.vm import (
    EnvironmentKind,
    ExecutionRouter,
    GuestCommand,
    GuestResult,
    HostBridgeOperation,
    HostBridgeRequest,
    HostBridgeResult,
    HostWriteEvidence,
    InMemoryVirtualizationProvider,
    Instance,
    InstanceState,
    RouteDecision,
    VirtualizationAvailability,
    VirtualizationProvider,
    VMExecutionError,
    VMExecutionEvidence,
    VMExecutionService,
    VMExecutionUnavailable,
    WSL2VirtualizationProvider,
)
from jarvis.vm.router import ExecutionIntent
from jarvis.vm.tools import (
    GuestCommandInput,
    GuestCommandTool,
    HostFileWriteInput,
    HostFileWriteTool,
)


def _guest_proposal(tool_id: str, marker: str, evidence: str) -> PlanProposal:
    return PlanProposal(
        goal=f"Run the {tool_id} product task",
        required_capabilities=[tool_id],
        completion_criteria=[evidence],
        steps=[
            ProposedStep(
                key="execute",
                tool_id=tool_id,
                capability=tool_id,
                input={"executable": "printf", "args": [marker]},
                expected_output=marker,
                verification_rule="evidence_contains_all",
                expected_evidence=[evidence],
            )
        ],
    )


def _host_proposal(relative_path: str, content: str) -> PlanProposal:
    return PlanProposal(
        goal="Write the exact acceptance-owned host marker",
        required_capabilities=["host_file_write"],
        required_permissions=[Permission.FILESYSTEM_WRITE.value],
        completion_criteria=["host_post_effect_verified=true"],
        steps=[
            ProposedStep(
                key="write",
                tool_id="vm.host_file.write",
                capability="host_file_write",
                input={"relative_path": relative_path, "content": content},
                expected_output="HOST_FILE_WRITE",
                verification_rule="evidence_contains_all",
                expected_evidence=["host_post_effect_verified=true"],
                required_permissions=[Permission.FILESYSTEM_WRITE.value],
                expensive_action=True,
            )
        ],
    )


def _runtime(
    tmp_path: Path,
    provider: VirtualizationProvider,
    recovery_backend: SecretBackend | None = None,
) -> ApplicationRuntime:
    runtime = ApplicationRuntime.create(
        Settings(
            environment="production",
            app_data_dir=tmp_path / "jarvis-data",
            ai_provider="ollama",
            ollama_autostart=False,
        ),
        recovery_key_backend=recovery_backend or TestOnlyInMemorySecretBackend(),
        virtualization_provider=provider,
    )
    assert runtime.status is RuntimeStatus.READY, runtime.error
    assert runtime.container is not None
    return runtime


def test_v1_i_r1_evidence_is_machine_readable_and_service_fails_closed(tmp_path: Path) -> None:
    task_id = uuid4()
    intent = ExecutionIntent("research", network_required=True)
    route = RouteDecision(
        EnvironmentKind.WORKBENCH_VM,
        "non-host task defaults to JARVIS workbench",
        fallbacks=(EnvironmentKind.DISPOSABLE_TEST_VM,),
    )
    guest = VMExecutionEvidence(
        task_id,
        intent,
        route,
        "in-memory",
        uuid4(),
        EnvironmentKind.WORKBENCH_VM,
        uuid4(),
        True,
        "completed",
        exit_code=0,
        stdout="marker",
        evidence_digest="digest",
    )
    guest_payload = guest.as_dict()
    intent_payload = guest_payload["trusted_execution_intent"]
    route_payload = guest_payload["route"]
    assert isinstance(intent_payload, dict)
    assert isinstance(route_payload, dict)
    assert intent_payload["network_required"] is True
    assert route_payload["environment"] == "workbench_vm"
    assert guest_payload["host_bridge_operations"] == ()

    host_request = HostBridgeRequest(
        uuid4(),
        task_id,
        uuid4(),
        HostBridgeOperation.FILE_WRITE,
        "C:/JARVIS/acceptance/marker.txt",
        "C:/JARVIS/acceptance",
        expires_at=datetime.now(UTC) + timedelta(minutes=1),
        approval_identity="trusted-user",
    )
    host_evidence = HostWriteEvidence(
        task_id,
        ExecutionRouter().route(
            ExecutionIntent(
                "host_resource",
                host_resource_dependency=True,
                exact_host_mutation=True,
                explicit_host_request=True,
                risk="medium",
            )
        ),
        host_request,
        HostBridgeResult(
            True, "brokered scope approved", HostBridgeOperation.FILE_WRITE, host_request.request_id
        ),
        host_request.resource,
        host_request.scope,
        6,
        "content-digest",
        True,
    )
    host_payload = host_evidence.as_dict()
    assert host_payload["authorized"] is True
    assert host_payload["post_effect_verified"] is True
    assert host_payload["approval_identity"] == "trusted-user"


@pytest.mark.asyncio
async def test_v1_i_r1_service_rejects_unsupported_guest_and_unsafe_paths(tmp_path: Path) -> None:
    class _BrokenProvider(InMemoryVirtualizationProvider):
        def probe(self) -> VirtualizationAvailability:
            raise RuntimeError("probe unavailable")

    service = VMExecutionService(
        _BrokenProvider(),
        PermissionBroker(PolicyEngine()),
        state_root=tmp_path / "vm",
        host_root=tmp_path / "host",
    )
    assert service.provider_name == "in-memory"
    assert service.probe() is VirtualizationAvailability.UNAVAILABLE
    with pytest.raises(ValueError, match="VM route"):
        await service.execute_guest(uuid4(), ExecutionIntent("planning"), GuestCommand("printf"))
    with pytest.raises(ValueError, match="trusted VM command policy"):
        await service.execute_guest(uuid4(), ExecutionIntent("research"), GuestCommand("touch"))
    for relative_path in ("../escape.txt", "C:/absolute.txt", "wild*.txt"):
        with pytest.raises(ValueError):
            service.host_resource(relative_path)


@pytest.mark.asyncio
async def test_v1_i_r1_service_and_tools_preserve_no_effect_failures(tmp_path: Path) -> None:
    provider = InMemoryVirtualizationProvider()
    provider.fail_next("create")
    service = VMExecutionService(
        provider,
        PermissionBroker(PolicyEngine()),
        state_root=tmp_path / "vm",
        host_root=tmp_path / "host",
    )
    with pytest.raises(VMExecutionUnavailable):
        await service.execute_guest(uuid4(), ExecutionIntent("research"), GuestCommand("printf"))
    assert service.execution_evidence[-1].status == "unavailable"

    with pytest.raises(ValueError, match="guest tool metadata"):
        GuestCommandTool(
            service,
            tool_id="",
            intent=ExecutionIntent("research"),
            description="invalid",
        )

    class _FailedGuestProvider(InMemoryVirtualizationProvider):
        async def execute(self, instance_id: UUID, command: GuestCommand) -> GuestResult:
            result = await super().execute(instance_id, command)
            return replace(result, exit_code=1)

    failed_service = VMExecutionService(
        _FailedGuestProvider(),
        PermissionBroker(PolicyEngine()),
        state_root=tmp_path / "failed-vm",
        host_root=tmp_path / "failed-host",
    )
    guest_tool = GuestCommandTool(
        failed_service,
        tool_id="vm.failure",
        intent=ExecutionIntent("research"),
        description="bounded failure",
    )
    task_id = uuid4()
    failed_context = ToolExecutionContext(
        task_id=task_id,
        correlation_id=task_id,
        caller=ToolCaller.AGENT,
        cancellation=asyncio.Event(),
        logger=logging.getLogger("v1-i-r1.failure"),
    )
    failed_result = await guest_tool._execute_authorized(  # noqa: SLF001
        failed_context,
        GuestCommandInput(executable="printf", args=["failure"]),
    )
    assert failed_result.status is ToolResultStatus.EXPECTED_FAILURE
    assert failed_result.effect_disposition is ToolEffectDisposition.NO_EFFECT

    host_tool = HostFileWriteTool(failed_service)
    missing_receipt = await host_tool._execute_authorized(  # noqa: SLF001
        failed_context,
        HostFileWriteInput(relative_path="missing-receipt.txt", content="no-effect"),
    )
    assert missing_receipt.status is ToolResultStatus.PERMISSION_DENIED
    assert missing_receipt.effect_disposition is ToolEffectDisposition.NO_EFFECT

    now = datetime.now(UTC)
    inactive_receipt = AuthorizationReceipt(
        receipt_id=uuid4(),
        task_id=task_id,
        tool_id="vm.host_file.write",
        action="host.file.write",
        argument_fingerprint="inactive-arguments",
        action_fingerprint="inactive-action",
        argument_names=("relative_path", "content"),
        evaluations=(),
        approval_requests=(),
        remembered_grants=(),
        user_id=None,
        authorized_at=now,
        expires_at=now + timedelta(minutes=1),
    )
    denied_host = await failed_service.execute_host_write(
        task_id,
        ExecutionIntent(
            "host_resource",
            host_resource_dependency=True,
            exact_host_mutation=True,
            explicit_host_request=True,
            risk="medium",
        ),
        "inactive-receipt.txt",
        "no-effect",
        inactive_receipt,
        {"relative_path": "inactive-receipt.txt", "content": "no-effect"},
        tool_id="vm.host_file.write",
        action="host.file.write",
    )
    assert not denied_host.authorization.allowed
    assert not failed_service.host_resource("inactive-receipt.txt").exists()

    class _CleanupFailureProvider(InMemoryVirtualizationProvider):
        async def destroy(self, instance_id: UUID) -> Instance:
            raise RuntimeError(f"cleanup failure for {instance_id}")

    cleanup_service = VMExecutionService(
        _CleanupFailureProvider(),
        PermissionBroker(PolicyEngine()),
        state_root=tmp_path / "cleanup-vm",
        host_root=tmp_path / "cleanup-host",
    )
    with pytest.raises(VMExecutionError, match="cleanup failed"):
        await cleanup_service.execute_guest(
            uuid4(), ExecutionIntent("dependency_test"), GuestCommand("printf")
        )
    assert cleanup_service.execution_evidence[-1].error_code == "disposable_cleanup_failed"


@pytest.mark.asyncio
async def test_v1_i_r1_d_vm_first_product_task_routes_all_representative_classes(
    tmp_path: Path,
) -> None:
    provider = InMemoryVirtualizationProvider()
    runtime = _runtime(tmp_path, provider)
    container = runtime.container
    assert container is not None
    service = container.vm_execution_service
    try:
        cases = (
            ("vm.research", "research-marker", "vm_route=workbench_vm"),
            ("vm.coding", "coding-marker", "vm_route=disposable_test_vm"),
            ("vm.test", "test-marker", "vm_route=disposable_test_vm"),
            ("vm.repair", "repair-marker", "vm_route=disposable_repair_vm"),
        )
        tasks = [
            await container.task_controller.submit_proposal(
                _guest_proposal(tool_id, marker, evidence),
                provenance=("v1-i-r1-normal-product-path",),
            )
            for tool_id, marker, evidence in cases
        ]
        assert all(task.status is PlanningTaskStatus.COMPLETED for task in tasks)
        evidence = service.execution_evidence
        assert tuple(item.route.environment for item in evidence) == (
            EnvironmentKind.WORKBENCH_VM,
            EnvironmentKind.DISPOSABLE_TEST_VM,
            EnvironmentKind.DISPOSABLE_TEST_VM,
            EnvironmentKind.DISPOSABLE_REPAIR_VM,
        )
        assert all(item.guest_ready and item.exit_code == 0 for item in evidence)
        assert all(item.host_bridge_operations == () for item in evidence)
        assert all(item.provider == "in-memory" for item in evidence)
        instances = await provider.instances()
        assert sum(item.purpose is EnvironmentKind.WORKBENCH_VM for item in instances) == 1
        assert all(
            item.state is InstanceState.DESTROYED
            for item in instances
            if item.purpose
            in {EnvironmentKind.DISPOSABLE_TEST_VM, EnvironmentKind.DISPOSABLE_REPAIR_VM}
        )
    finally:
        await runtime.aclose()


@pytest.mark.asyncio
async def test_v1_i_r1_e_host_transaction_requires_exact_broker_approval(
    tmp_path: Path,
) -> None:
    runtime = _runtime(tmp_path, InMemoryVirtualizationProvider())
    container = runtime.container
    assert container is not None
    service = container.vm_execution_service
    relative_path = "acceptance-owned/approved-marker.txt"
    content = "v1-i-r1-approved"
    target = service.host_resource(relative_path)
    try:
        paused = await container.task_controller.submit_proposal(
            _host_proposal(relative_path, content),
            provenance=("v1-i-r1-host-product-path",),
        )
        assert paused.status is PlanningTaskStatus.WAITING_FOR_PERMISSION
        assert not target.exists()
        assert service.host_bridge.requests == []

        request = (await container.task_controller.pending_approvals(paused.task_id))[0]
        decision_context = container.desktop_approval_authenticator.issue_context(
            request_id=request.request_id,
            choice=ApprovalChoice.APPROVE_ONCE,
            identity=ApprovalIdentity("v1-i-r1-test-user", ApprovalActorKind.TRUSTED_USER),
        )
        decision = await container.task_controller.submit_approval_decision(decision_context)
        assert decision.accepted
        completed = await container.task_controller.resume_task(paused.task_id)
        assert completed.status is PlanningTaskStatus.COMPLETED
        assert target.read_text(encoding="utf-8") == content
        assert len(service.host_write_evidence) == 1
        host_evidence = service.host_write_evidence[0]
        assert host_evidence.authorization.allowed
        assert host_evidence.request.operation.value == "HOST_FILE_WRITE"
        assert host_evidence.request.resource == str(target)
        assert host_evidence.request.scope == str(service.host_root)
        assert host_evidence.post_effect_verified
        assert host_evidence.request.approval_identity == "v1-i-r1-test-user"
    finally:
        await runtime.aclose()


@pytest.mark.asyncio
async def test_v1_i_r1_host_denial_never_creates_the_protected_effect(tmp_path: Path) -> None:
    runtime = _runtime(tmp_path, InMemoryVirtualizationProvider())
    container = runtime.container
    assert container is not None
    service = container.vm_execution_service
    relative_path = "acceptance-owned/denied-marker.txt"
    target = service.host_resource(relative_path)
    try:
        paused = await container.task_controller.submit_proposal(
            _host_proposal(relative_path, "must-not-exist"),
            provenance=("v1-i-r1-host-denial",),
        )
        request = (await container.task_controller.pending_approvals(paused.task_id))[0]
        decision_context = container.desktop_approval_authenticator.issue_context(
            request_id=request.request_id,
            choice=ApprovalChoice.DENY_ONCE,
            identity=ApprovalIdentity("v1-i-r1-denier", ApprovalActorKind.TRUSTED_USER),
        )
        decision = await container.task_controller.submit_approval_decision(decision_context)
        assert decision.accepted
        await container.task_controller.cancel_task(paused.task_id)
        assert not target.exists()
        assert service.host_bridge.requests == []
    finally:
        await runtime.aclose()


@pytest.mark.asyncio
async def test_v1_i_r1_host_bridge_binding_rejects_negative_variants(tmp_path: Path) -> None:
    runtime = _runtime(tmp_path, InMemoryVirtualizationProvider())
    container = runtime.container
    assert container is not None
    service = container.vm_execution_service
    task_id = uuid4()
    relative_path = "acceptance-owned/binding-marker.txt"
    target = service.host_resource(relative_path)
    tool = container.tool_registry.get("vm.host_file.write")
    validated = HostFileWriteInput(relative_path=relative_path, content="binding")
    context = ToolExecutionContext(
        task_id=task_id,
        correlation_id=task_id,
        caller=ToolCaller.AGENT,
        cancellation=asyncio.Event(),
        logger=logging.getLogger("v1-i-r1.binding"),
    )
    descriptor = tool._describe_action(context, validated)  # noqa: SLF001
    arguments = validated.model_dump(mode="json")
    try:
        pending = await container.permission_broker.authorize(
            tool_id=tool.manifest.tool_id,
            tool_identity=tool,
            declared_permissions=tool.manifest.declared_permissions,
            task_id=task_id,
            user_id=None,
            descriptor=descriptor,
            normalized_arguments=arguments,
        )
        assert not pending.authorized
        approval = pending.approval_requests[0]
        approval_context = container.desktop_approval_authenticator.issue_context(
            request_id=approval.request_id,
            choice=ApprovalChoice.APPROVE_ONCE,
            identity=ApprovalIdentity("v1-i-r1-binding-user", ApprovalActorKind.TRUSTED_USER),
        )
        assert (await container.permission_broker.decide(approval_context)).accepted
        authorized = await container.permission_broker.authorize(
            tool_id=tool.manifest.tool_id,
            tool_identity=tool,
            declared_permissions=tool.manifest.declared_permissions,
            task_id=task_id,
            user_id=None,
            descriptor=descriptor,
            normalized_arguments=arguments,
        )
        receipt = authorized.receipt
        assert authorized.authorized and receipt is not None
        assert await container.permission_broker.begin_execution(receipt) is None
        identity = receipt.approval_requests[0].approval_identity
        base = HostBridgeRequest(
            request_id=uuid4(),
            task_id=task_id,
            instance_id=service.host_instance_id,
            operation=HostBridgeOperation.FILE_WRITE,
            resource=str(target),
            scope=str(service.host_root),
            risk="medium",
            expires_at=receipt.expires_at,
            tool_id=receipt.tool_id,
            action=receipt.action,
            argument_fingerprint=receipt.argument_fingerprint,
            action_fingerprint=receipt.action_fingerprint,
            approval_identity=identity,
        )

        async def check(
            request: HostBridgeRequest,
            supplied_receipt: AuthorizationReceipt | None = receipt,
        ) -> bool:
            result = service.host_bridge.authorize_with_receipt(
                request,
                receipt=supplied_receipt,
                broker=container.permission_broker,
                normalized_arguments=arguments,
                expected_instance_id=service.host_instance_id,
            )
            return result.allowed

        assert not await check(replace(base, expires_at=datetime.now(UTC) - timedelta(seconds=1)))
        assert not await check(replace(base, resource=str(service.host_root / "changed.txt")))
        assert not await check(replace(base, scope=str(service.host_root / "narrower")))
        assert not await check(replace(base, operation=HostBridgeOperation.FILE_READ))
        assert not await check(replace(base, resource="*"))
        assert not await check(replace(base, scope="*"))
        assert not await check(replace(base, task_id=uuid4()))
        assert not await check(replace(base, instance_id=uuid4()))
        assert not await check(base, None)

        exact = replace(base, request_id=uuid4())
        assert await check(exact)
        assert not await check(exact)
        assert not target.exists()
        await container.permission_broker.record_execution_outcome(receipt, "binding_test")
    finally:
        await runtime.aclose()


@pytest.mark.asyncio
async def test_v1_i_r1_restart_reuses_persistent_workbench_without_replay(tmp_path: Path) -> None:
    provider = InMemoryVirtualizationProvider()
    recovery_backend = TestOnlyInMemorySecretBackend()
    first = _runtime(tmp_path, provider, recovery_backend)
    first_container = first.container
    assert first_container is not None
    try:
        completed = await first_container.task_controller.submit_proposal(
            _guest_proposal("vm.research", "restart-marker", "vm_route=workbench_vm"),
            provenance=("v1-i-r1-restart",),
        )
        assert completed.status is PlanningTaskStatus.COMPLETED
        first_id = first_container.vm_execution_service.execution_evidence[-1].instance_id
        assert first_id is not None
        assert len(provider.commands) == 1
    finally:
        await first.aclose()

    second = _runtime(tmp_path, provider, recovery_backend)
    second_container = second.container
    assert second_container is not None
    try:
        completed = await second_container.task_controller.submit_proposal(
            _guest_proposal("vm.research", "restart-marker-2", "vm_route=workbench_vm"),
            provenance=("v1-i-r1-restart",),
        )
        assert completed.status is PlanningTaskStatus.COMPLETED
        assert second_container.vm_execution_service.execution_evidence[-1].instance_id == first_id
        assert len(provider.commands) == 2
        instances = await provider.instances()
        assert sum(item.purpose is EnvironmentKind.WORKBENCH_VM for item in instances) == 1
    finally:
        await second.aclose()


@pytest.mark.asyncio
async def test_v1_i_r1_vm_unavailable_fails_closed_without_host_fallback(tmp_path: Path) -> None:
    provider = InMemoryVirtualizationProvider(available=False)
    runtime = _runtime(tmp_path, provider)
    container = runtime.container
    assert container is not None
    service = container.vm_execution_service
    try:
        task = await container.task_controller.submit_proposal(
            _guest_proposal("vm.research", "unavailable-marker", "vm_route=workbench_vm"),
            provenance=("v1-i-r1-unavailable",),
        )
        assert task.status is PlanningTaskStatus.FAILED
        assert service.probe() is VirtualizationAvailability.UNAVAILABLE
        assert service.execution_evidence[-1].status == "unavailable"
        assert service.execution_evidence[-1].error_code == "vm_provider_unavailable"
        assert provider.commands == []
        assert service.host_bridge.requests == []
    finally:
        await runtime.aclose()


@pytest.mark.real_qualification
@pytest.mark.asyncio
async def test_v1_i_r1_real_wsl_workbench_product_task(tmp_path: Path) -> None:
    provider = WSL2VirtualizationProvider(state_path=tmp_path / "data" / "vm" / "wsl2.json")
    runtime = _runtime(tmp_path, provider)
    container = runtime.container
    assert container is not None
    service = container.vm_execution_service
    monitor = HostSideEffectMonitor(tmp_path / "host-observation")
    monitor.snapshot()
    try:
        task = await container.task_controller.submit_proposal(
            _guest_proposal("vm.research", "v1-i-r1-real-wsl", "vm_route=workbench_vm"),
            provenance=("v1-i-r1-real-wsl",),
        )
        assert task.status is PlanningTaskStatus.COMPLETED
        evidence = service.execution_evidence[-1]
        assert evidence.provider == "wsl2"
        assert evidence.route.environment is EnvironmentKind.WORKBENCH_VM
        assert evidence.instance_purpose is EnvironmentKind.WORKBENCH_VM
        assert evidence.guest_ready
        assert evidence.exit_code == 0
        assert evidence.evidence_digest
        assert evidence.host_bridge_operations == ()
        instances = await provider.instances()
        assert any(item.instance_id == evidence.instance_id for item in instances)
        observed = monitor.compare(monitor.snapshot())
        assert observed["host_filesystem_mutation"] == "NONE"
        assert observed["mouse_movement"] == "NONE"
        assert observed["focus_change"] == "NONE"
        assert set(observed["new_gui_processes"]).issubset({"msrdc.exe", "wslhost.exe"})
        assert observed["keyboard_injection"] == "NOT_OBSERVED"
        assert observed["clipboard_mutation"] != "OBSERVED_CHANGE"
    finally:
        await runtime.aclose()
