import asyncio
import logging
import os
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from pathlib import Path
from uuid import uuid4

import pytest
from jarvis.permissions import (
    ActionDescriptor,
    ApprovalActorKind,
    ApprovalChoice,
    ApprovalIdentity,
    ApprovalRequest,
    ApprovalSource,
    ApprovalStatus,
    AuthorizationReceipt,
    Decision,
    DecisionReason,
    InMemoryAuditSink,
    Permission,
    PermissionBroker,
    PermissionRequest,
    PermissionScope,
    PolicyEngine,
    PolicyRule,
    Risk,
    SafeArgument,
    SafetyClass,
    ScopeConstraint,
)
from jarvis.tools.base import Tool
from jarvis.tools.harness import ToolHarness
from jarvis.tools.models import (
    SemanticVersion,
    ToolCaller,
    ToolExecutionContext,
    ToolManifest,
    ToolPlatform,
    ToolResult,
    ToolResultStatus,
)
from jarvis.tools.registry import ToolRegistry
from pydantic import BaseModel, ConfigDict, Field


class FileInput(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)

    path: str = Field(min_length=1)
    secret: str = Field(min_length=1)


class FileOutput(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)

    executed: bool


class BrokeredFileTool(Tool[FileInput, FileOutput]):
    def __init__(self, *, safety_class: SafetyClass = SafetyClass.ORDINARY) -> None:
        self.executions = 0
        self.receipts: list[AuthorizationReceipt] = []
        self._safety_class = safety_class

    @property
    def manifest(self) -> ToolManifest:
        return ToolManifest(
            tool_id="brokered-file",
            name="Brokered file probe",
            description="Security test tool that does not touch the filesystem.",
            version=SemanticVersion(1, 0, 0),
            capability_tags=frozenset({"security-test"}),
            input_schema=FileInput,
            output_schema=FileOutput,
            declared_permissions=frozenset({Permission.FILESYSTEM_WRITE}),
            supported_platforms=frozenset(
                {ToolPlatform.WINDOWS, ToolPlatform.LINUX, ToolPlatform.MACOS}
            ),
            timeout_seconds=1,
        )

    @property
    def input_model(self) -> type[FileInput]:
        return FileInput

    def _describe_action(
        self, context: ToolExecutionContext, validated_input: FileInput
    ) -> ActionDescriptor:
        del context
        return ActionDescriptor(
            action="write approved test file",
            arguments_summary=(
                SafeArgument("path", validated_input.path),
                SafeArgument("secret", "[REDACTED]"),
            ),
            risk=Risk.CRITICAL if self._safety_class is not SafetyClass.ORDINARY else Risk.HIGH,
            permissions=(
                PermissionRequest(
                    Permission.FILESYSTEM_WRITE,
                    PermissionScope(
                        paths=(validated_input.path,),
                        duration_seconds=120,
                    ),
                ),
            ),
            safety_class=self._safety_class,
        )

    async def _execute_authorized(
        self, context: ToolExecutionContext, validated_input: FileInput
    ) -> ToolResult:
        del validated_input
        assert context.authorization is not None
        self.receipts.append(context.authorization)
        self.executions += 1
        return ToolResult.success(FileOutput(executed=True))


class MissingPermissionDescriptorTool(BrokeredFileTool):
    def _describe_action(
        self, context: ToolExecutionContext, validated_input: FileInput
    ) -> ActionDescriptor:
        del context, validated_input
        return ActionDescriptor(
            action="write approved test file",
            arguments_summary=(),
            risk=Risk.HIGH,
            permissions=(),
        )


@dataclass
class MutableClock:
    value: datetime

    def __call__(self) -> datetime:
        return self.value


def make_broker(
    root: Path,
    *,
    decision: Decision = Decision.REQUIRE_APPROVAL,
    enabled: bool = True,
    clock: MutableClock | None = None,
    audit: InMemoryAuditSink | None = None,
) -> PermissionBroker:
    return PermissionBroker(
        PolicyEngine(
            (
                PolicyRule(
                    policy_id="filesystem.write.test-root",
                    permission=Permission.FILESYSTEM_WRITE,
                    decision=decision,
                    scope=ScopeConstraint(
                        paths=(str(root),),
                        tools=frozenset({"brokered-file"}),
                        max_duration_seconds=120,
                    ),
                    actions=frozenset({"write approved test file"}),
                    enabled=enabled,
                ),
            )
        ),
        audit_sink=audit,
        approval_ttl_seconds=30,
        max_remembered_seconds=120,
        clock=clock,
    )


def make_harness(
    root: Path,
    *,
    decision: Decision = Decision.REQUIRE_APPROVAL,
    enabled: bool = True,
    clock: MutableClock | None = None,
    audit: InMemoryAuditSink | None = None,
    safety_class: SafetyClass = SafetyClass.ORDINARY,
) -> tuple[BrokeredFileTool, PermissionBroker, ToolHarness]:
    broker = make_broker(
        root,
        decision=decision,
        enabled=enabled,
        clock=clock,
        audit=audit,
    )
    tool = BrokeredFileTool(safety_class=safety_class)
    ToolRegistry((tool,), permission_broker=broker)
    return tool, broker, ToolHarness(broker=broker)


def trusted_user() -> ApprovalIdentity:
    return ApprovalIdentity("local-user-1", ApprovalActorKind.TRUSTED_USER)


async def require_one_approval(broker: PermissionBroker) -> ApprovalRequest:
    pending = await broker.pending_approvals()
    assert len(pending) == 1
    return pending[0]


def test_tool_cannot_replace_brokered_entry_point_with_public_execute() -> None:
    with pytest.raises(TypeError, match="_execute_authorized"):

        class BypassTool(BrokeredFileTool):
            async def execute(self) -> None:
                pass


def test_broker_configuration_and_registration_are_fail_closed() -> None:
    with pytest.raises(ValueError, match="lifetimes"):
        PermissionBroker(PolicyEngine(), approval_ttl_seconds=0)
    broker = PermissionBroker(PolicyEngine())
    tool = BrokeredFileTool()
    broker.register_tool(tool.manifest.tool_id, tool, tool.manifest.declared_permissions)

    assert broker.audit_sink is not None
    assert broker.unregister_tool("missing", tool) is False
    with pytest.raises(ValueError, match="unique"):
        broker.register_tool(tool.manifest.tool_id, object(), frozenset())


def test_invalid_policy_configuration_is_rejected(tmp_path: Path) -> None:
    rule = PolicyRule(
        "duplicate",
        Permission.FILESYSTEM_READ,
        Decision.ALLOW,
        ScopeConstraint(paths=(str(tmp_path),)),
        frozenset({"read file"}),
    )
    with pytest.raises(ValueError, match="unique"):
        PolicyEngine((rule, rule))
    with pytest.raises(ValueError, match="enumerate exact"):
        PolicyEngine(
            (
                PolicyRule(
                    "no-actions",
                    Permission.FILESYSTEM_READ,
                    Decision.ALLOW,
                    ScopeConstraint(paths=(str(tmp_path),)),
                    frozenset(),
                ),
            )
        )
    with pytest.raises(ValueError, match="duration"):
        PolicyEngine(
            (
                PolicyRule(
                    "bad-duration",
                    Permission.FILESYSTEM_READ,
                    Decision.ALLOW,
                    ScopeConstraint(paths=(str(tmp_path),), max_duration_seconds=0),
                    frozenset({"read file"}),
                ),
            )
        )


def test_unknown_and_malformed_permissions_fail_closed(tmp_path: Path) -> None:
    scope = PermissionScope(
        paths=(str(tmp_path),),
        tool_id="brokered-file",
        task_id=uuid4(),
    )
    engine = PolicyEngine()

    unknown = engine.evaluate(PermissionRequest("filesystem.superuser", scope), action="write")
    malformed = engine.evaluate(PermissionRequest(" filesystem.write", scope), action="write")
    wrong_type = engine.evaluate({"permission": "filesystem.write"}, action="write")

    assert unknown == unknown.__class__(
        Decision.DENY,
        DecisionReason.UNKNOWN_PERMISSION,
        None,
        None,
    )
    assert malformed.reason is DecisionReason.MALFORMED_PERMISSION
    assert wrong_type.reason is DecisionReason.MALFORMED_PERMISSION


def test_missing_and_disabled_policy_fail_closed(tmp_path: Path) -> None:
    scope = PermissionScope(
        paths=(str(tmp_path),),
        tool_id="brokered-file",
        task_id=uuid4(),
    )
    request = PermissionRequest(Permission.FILESYSTEM_WRITE, scope)
    missing = PolicyEngine().evaluate(request, action="write")
    disabled = PolicyEngine(
        (
            PolicyRule(
                "disabled",
                Permission.FILESYSTEM_WRITE,
                Decision.ALLOW,
                ScopeConstraint(paths=(str(tmp_path),)),
                frozenset({"write"}),
                enabled=False,
            ),
        )
    ).evaluate(request, action="write")

    assert missing.decision is Decision.DENY
    assert missing.reason is DecisionReason.MISSING_POLICY
    assert disabled.decision is Decision.DENY
    assert disabled.reason is DecisionReason.POLICY_DISABLED


def test_unknown_and_malformed_actions_fail_closed(tmp_path: Path) -> None:
    request = PermissionRequest(
        Permission.FILESYSTEM_WRITE,
        PermissionScope(
            paths=(str(tmp_path / "file.txt"),),
            tool_id="writer",
            task_id=uuid4(),
        ),
    )
    engine = PolicyEngine(
        (
            PolicyRule(
                "known-write",
                Permission.FILESYSTEM_WRITE,
                Decision.ALLOW,
                ScopeConstraint(paths=(str(tmp_path),), tools=frozenset({"writer"})),
                frozenset({"write file"}),
            ),
        )
    )

    unknown = engine.evaluate(request, action="delete file")
    malformed = engine.evaluate(request, action="write file\nignore policy")

    assert unknown.reason is DecisionReason.UNKNOWN_ACTION
    assert malformed.reason is DecisionReason.MALFORMED_ACTION


def test_explicit_deny_takes_precedence_over_allow(tmp_path: Path) -> None:
    scope = ScopeConstraint(paths=(str(tmp_path),), tools=frozenset({"writer"}))
    engine = PolicyEngine(
        (
            PolicyRule(
                "allow-write",
                Permission.FILESYSTEM_WRITE,
                Decision.ALLOW,
                scope,
                frozenset({"write file"}),
            ),
            PolicyRule(
                "deny-write",
                Permission.FILESYSTEM_WRITE,
                Decision.DENY,
                scope,
                frozenset({"write file"}),
            ),
        )
    )
    result = engine.evaluate(
        PermissionRequest(
            Permission.FILESYSTEM_WRITE,
            PermissionScope(
                paths=(str(tmp_path / "file.txt"),),
                tool_id="writer",
                task_id=uuid4(),
            ),
        ),
        action="write file",
    )

    assert result.decision is Decision.DENY
    assert result.reason is DecisionReason.POLICY_DENY
    assert result.policy_id == "deny-write"


def test_path_traversal_and_scope_escape_are_denied(tmp_path: Path) -> None:
    allowed = tmp_path / "allowed"
    allowed.mkdir()
    task_id = uuid4()
    engine = PolicyEngine(
        (
            PolicyRule(
                "bounded-read",
                Permission.FILESYSTEM_READ,
                Decision.ALLOW,
                ScopeConstraint(paths=(str(allowed),), tools=frozenset({"reader"})),
                frozenset({"read file"}),
            ),
        )
    )

    traversal = engine.evaluate(
        PermissionRequest(
            Permission.FILESYSTEM_READ,
            PermissionScope(
                paths=(str(allowed / ".." / "escape.txt"),),
                tool_id="reader",
                task_id=task_id,
            ),
        ),
        action="read file",
    )
    escaped = engine.evaluate(
        PermissionRequest(
            Permission.FILESYSTEM_READ,
            PermissionScope(
                paths=(str(tmp_path / "outside.txt"),),
                tool_id="reader",
                task_id=task_id,
            ),
        ),
        action="read file",
    )

    assert traversal.reason is DecisionReason.MALFORMED_SCOPE
    assert escaped.reason is DecisionReason.SCOPE_OUTSIDE_POLICY

    relative = engine.evaluate(
        PermissionRequest(
            Permission.FILESYSTEM_READ,
            PermissionScope(
                paths=("relative.txt",),
                tool_id="reader",
                task_id=task_id,
            ),
        ),
        action="read file",
    )
    nul_path = engine.evaluate(
        PermissionRequest(
            Permission.FILESYSTEM_READ,
            PermissionScope(
                paths=(f"{allowed}{os.sep}bad\x00name",),
                tool_id="reader",
                task_id=task_id,
            ),
        ),
        action="read file",
    )

    assert relative.reason is DecisionReason.MALFORMED_SCOPE
    assert nul_path.reason is DecisionReason.MALFORMED_SCOPE


def test_symlink_or_junction_escape_is_denied_when_supported(tmp_path: Path) -> None:
    allowed = tmp_path / "allowed"
    outside = tmp_path / "outside"
    allowed.mkdir()
    outside.mkdir()
    link = allowed / "link"
    try:
        link.symlink_to(outside, target_is_directory=True)
    except OSError:
        pytest.skip("Creating a symlink/junction is not available to this test user")
    engine = PolicyEngine(
        (
            PolicyRule(
                "bounded-read",
                Permission.FILESYSTEM_READ,
                Decision.ALLOW,
                ScopeConstraint(paths=(str(allowed),), tools=frozenset({"reader"})),
                frozenset({"read file"}),
            ),
        )
    )

    result = engine.evaluate(
        PermissionRequest(
            Permission.FILESYSTEM_READ,
            PermissionScope(
                paths=(str(link / "private.txt"),),
                tool_id="reader",
                task_id=uuid4(),
            ),
        ),
        action="read file",
    )

    assert result.decision is Decision.DENY
    assert result.reason is DecisionReason.SCOPE_OUTSIDE_POLICY


def test_tool_task_and_duration_scopes_are_enforced(tmp_path: Path) -> None:
    allowed_task = uuid4()
    engine = PolicyEngine(
        (
            PolicyRule(
                "narrow",
                Permission.FILESYSTEM_READ,
                Decision.ALLOW,
                ScopeConstraint(
                    paths=(str(tmp_path),),
                    tools=frozenset({"reader"}),
                    tasks=frozenset({allowed_task}),
                    max_duration_seconds=10,
                ),
                actions=frozenset({"read file"}),
            ),
        )
    )
    wrong_task = PermissionScope(
        paths=(str(tmp_path / "file.txt"),),
        tool_id="reader",
        task_id=uuid4(),
        duration_seconds=10,
    )
    too_long = PermissionScope(
        paths=(str(tmp_path / "file.txt"),),
        tool_id="reader",
        task_id=allowed_task,
        duration_seconds=11,
    )

    assert (
        engine.evaluate(
            PermissionRequest(Permission.FILESYSTEM_READ, wrong_task),
            action="read file",
        ).reason
        is DecisionReason.SCOPE_OUTSIDE_POLICY
    )
    assert (
        engine.evaluate(
            PermissionRequest(Permission.FILESYSTEM_READ, too_long),
            action="read file",
        ).reason
        is DecisionReason.SCOPE_OUTSIDE_POLICY
    )


def test_application_host_and_command_family_scopes_are_enforced() -> None:
    task_id = uuid4()
    engine = PolicyEngine(
        (
            PolicyRule(
                "launch-notepad",
                Permission.APPLICATION_LAUNCH,
                Decision.ALLOW,
                ScopeConstraint(
                    applications=("notepad.exe",),
                    tools=frozenset({"launcher"}),
                ),
                frozenset({"launch application"}),
            ),
            PolicyRule(
                "request-weather",
                Permission.NETWORK_REQUEST,
                Decision.ALLOW,
                ScopeConstraint(
                    hosts=("api.weather.example",),
                    tools=frozenset({"weather"}),
                ),
                frozenset({"request weather"}),
            ),
            PolicyRule(
                "run-git-status",
                Permission.TERMINAL_EXECUTE,
                Decision.ALLOW,
                ScopeConstraint(
                    command_families=("git.status",),
                    tools=frozenset({"terminal"}),
                ),
                frozenset({"inspect repository"}),
            ),
        )
    )

    application = engine.evaluate(
        PermissionRequest(
            Permission.APPLICATION_LAUNCH,
            PermissionScope(
                applications=("NOTEPAD.EXE",),
                tool_id="launcher",
                task_id=task_id,
            ),
        ),
        action="launch application",
    )
    host = engine.evaluate(
        PermissionRequest(
            Permission.NETWORK_REQUEST,
            PermissionScope(
                hosts=("API.WEATHER.EXAMPLE.",),
                tool_id="weather",
                task_id=task_id,
            ),
        ),
        action="request weather",
    )
    command_escape = engine.evaluate(
        PermissionRequest(
            Permission.TERMINAL_EXECUTE,
            PermissionScope(
                command_families=("powershell",),
                tool_id="terminal",
                task_id=task_id,
            ),
        ),
        action="inspect repository",
    )

    assert application.decision is Decision.ALLOW
    assert host.decision is Decision.ALLOW
    assert command_escape.reason is DecisionReason.SCOPE_OUTSIDE_POLICY


@pytest.mark.asyncio
async def test_unknown_tool_cannot_execute(tmp_path: Path) -> None:
    tool = BrokeredFileTool()
    broker = make_broker(tmp_path)
    context = ToolExecutionContext(
        task_id=uuid4(),
        correlation_id=uuid4(),
        caller=ToolCaller.AGENT,
        cancellation=asyncio.Event(),
        logger=logging.getLogger("test.permissions"),
    )

    result = await tool.invoke(
        context,
        {"path": str(tmp_path / "file.txt"), "secret": "hidden"},
        broker,
    )

    assert result.status is ToolResultStatus.PERMISSION_DENIED
    assert result.error is not None
    assert result.error.code == DecisionReason.UNKNOWN_TOOL.value
    assert tool.executions == 0


@pytest.mark.asyncio
async def test_manifest_and_action_permission_mismatch_denies(tmp_path: Path) -> None:
    broker = make_broker(tmp_path)
    tool = MissingPermissionDescriptorTool()
    ToolRegistry((tool,), permission_broker=broker)

    result = await ToolHarness(broker=broker).invoke(
        tool,
        {"path": str(tmp_path / "file.txt"), "secret": "hidden"},
    )

    assert result.status is ToolResultStatus.PERMISSION_DENIED
    assert result.error is not None
    assert result.error.code == DecisionReason.TOOL_PERMISSION_MISMATCH.value
    assert tool.executions == 0


@pytest.mark.asyncio
async def test_noncanonical_arguments_fail_before_authorization(tmp_path: Path) -> None:
    tool, broker, _ = make_harness(tmp_path)
    context = ToolExecutionContext(
        task_id=uuid4(),
        correlation_id=uuid4(),
        caller=ToolCaller.TEST,
        cancellation=asyncio.Event(),
        logger=logging.getLogger("test.permissions"),
    )
    validated = FileInput(path=str(tmp_path / "file.txt"), secret="hidden")

    result = await broker.authorize(
        tool_id=tool.manifest.tool_id,
        tool_identity=tool,
        declared_permissions=tool.manifest.declared_permissions,
        task_id=context.task_id,
        user_id=None,
        descriptor=tool._describe_action(context, validated),
        normalized_arguments={"unsupported": object()},
    )

    assert result.authorized is False
    assert result.reason is DecisionReason.MALFORMED_ARGUMENTS


@pytest.mark.asyncio
async def test_approval_request_is_trusted_safe_and_exact(tmp_path: Path) -> None:
    tool, broker, harness = make_harness(tmp_path)
    path = str(tmp_path / "file.txt")
    task_id = uuid4()

    result = await harness.invoke(
        tool,
        {"path": path, "secret": "do-not-display"},
        task_id=task_id,
    )
    request = await require_one_approval(broker)

    assert result.status is ToolResultStatus.PERMISSION_DENIED
    assert request.task_id == task_id
    assert request.exact_action == "write approved test file"
    assert request.arguments_summary == (
        SafeArgument("path", path),
        SafeArgument("secret", "[REDACTED]"),
    )
    assert request.permission is Permission.FILESYSTEM_WRITE
    assert request.risk is Risk.HIGH
    assert request.scope.tool_id == "brokered-file"
    assert request.expires_at > request.created_at
    assert "do-not-display" not in repr(request.arguments_summary)


@pytest.mark.asyncio
async def test_expired_approval_never_executes(tmp_path: Path) -> None:
    clock = MutableClock(datetime(2026, 1, 1, tzinfo=UTC))
    tool, broker, harness = make_harness(tmp_path, clock=clock)
    arguments = {"path": str(tmp_path / "file.txt"), "secret": "hidden"}
    await harness.invoke(tool, arguments)
    request = await require_one_approval(broker)
    clock.value += timedelta(seconds=31)

    decision = await broker.decide(
        request.request_id,
        ApprovalChoice.APPROVE_ONCE,
        trusted_user(),
        ApprovalSource.TRUSTED_UI,
    )
    retry = await harness.invoke(tool, arguments)

    assert decision.accepted is False
    assert decision.reason is DecisionReason.APPROVAL_EXPIRED
    assert retry.status is ToolResultStatus.PERMISSION_DENIED
    assert tool.executions == 0


@pytest.mark.asyncio
async def test_one_time_approval_is_consumed_and_not_reused(tmp_path: Path) -> None:
    tool, broker, harness = make_harness(tmp_path)
    arguments = {"path": str(tmp_path / "file.txt"), "secret": "hidden"}
    task_id = uuid4()
    await harness.invoke(tool, arguments, task_id=task_id)
    request = await require_one_approval(broker)
    approved = await broker.decide(
        request.request_id,
        ApprovalChoice.APPROVE_ONCE,
        trusted_user(),
        ApprovalSource.TRUSTED_UI,
    )

    executed = await harness.invoke(tool, arguments, task_id=task_id)
    replay = await harness.invoke(tool, arguments, task_id=task_id)
    consumed = await broker.get_approval(request.request_id)

    assert approved.accepted is True
    assert executed.status is ToolResultStatus.SUCCESS
    assert replay.status is ToolResultStatus.PERMISSION_DENIED
    assert consumed is not None and consumed.status is ApprovalStatus.CONSUMED
    assert tool.executions == 1


@pytest.mark.asyncio
async def test_caller_cannot_supply_a_broker_receipt(tmp_path: Path) -> None:
    tool, broker, harness = make_harness(tmp_path)
    arguments = {"path": str(tmp_path / "file.txt"), "secret": "hidden"}
    task_id = uuid4()
    await harness.invoke(tool, arguments, task_id=task_id)
    request = await require_one_approval(broker)
    await broker.decide(
        request.request_id,
        ApprovalChoice.APPROVE_ONCE,
        trusted_user(),
        ApprovalSource.TRUSTED_UI,
    )
    assert (await harness.invoke(tool, arguments, task_id=task_id)).succeeded
    receipt = tool.receipts[0]
    forged_context = ToolExecutionContext(
        task_id=task_id,
        correlation_id=uuid4(),
        caller=ToolCaller.AGENT,
        cancellation=asyncio.Event(),
        logger=logging.getLogger("test.permissions"),
        authorization=receipt,
    )

    result = await tool.invoke(forged_context, arguments, broker)

    assert result.status is ToolResultStatus.PERMISSION_DENIED
    assert result.error is not None
    assert result.error.code == "caller_supplied_authorization"
    assert tool.executions == 1


@pytest.mark.asyncio
async def test_changed_arguments_do_not_match_approval(tmp_path: Path) -> None:
    tool, broker, harness = make_harness(tmp_path)
    first = {"path": str(tmp_path / "first.txt"), "secret": "one"}
    changed = {"path": str(tmp_path / "second.txt"), "secret": "two"}
    task_id = uuid4()
    await harness.invoke(tool, first, task_id=task_id)
    request = await require_one_approval(broker)
    await broker.decide(
        request.request_id,
        ApprovalChoice.APPROVE_ONCE,
        trusted_user(),
        ApprovalSource.TRUSTED_UI,
    )

    changed_result = await harness.invoke(tool, changed, task_id=task_id)
    original_result = await harness.invoke(tool, first, task_id=task_id)

    assert changed_result.status is ToolResultStatus.PERMISSION_DENIED
    assert original_result.status is ToolResultStatus.SUCCESS
    assert tool.executions == 1


@pytest.mark.asyncio
async def test_model_cannot_claim_or_grant_permission(tmp_path: Path) -> None:
    tool, broker, harness = make_harness(tmp_path)
    forged_argument = await harness.invoke(
        tool,
        {
            "path": str(tmp_path / "file.txt"),
            "secret": "hidden",
            "permission_granted": True,
        },
    )
    assert forged_argument.status is ToolResultStatus.VALIDATION_ERROR
    assert await broker.pending_approvals() == ()

    await harness.invoke(
        tool,
        {"path": str(tmp_path / "file.txt"), "secret": "hidden"},
    )
    request = await require_one_approval(broker)
    forged_decision = await broker.decide(
        request.request_id,
        ApprovalChoice.APPROVE_ONCE,
        ApprovalIdentity("planner", ApprovalActorKind.MODEL),
        ApprovalSource.MODEL,
    )

    assert forged_decision.accepted is False
    assert forged_decision.reason is DecisionReason.UNTRUSTED_APPROVER
    assert tool.executions == 0


@pytest.mark.asyncio
async def test_disabled_policy_prevents_execution(tmp_path: Path) -> None:
    tool, broker, harness = make_harness(tmp_path, enabled=False)

    result = await harness.invoke(
        tool,
        {"path": str(tmp_path / "file.txt"), "secret": "hidden"},
    )

    assert result.status is ToolResultStatus.PERMISSION_DENIED
    assert result.error is not None
    assert result.error.code == DecisionReason.POLICY_DISABLED.value
    assert await broker.pending_approvals() == ()
    assert tool.executions == 0


@pytest.mark.asyncio
async def test_approval_cancellation_prevents_execution(tmp_path: Path) -> None:
    tool, broker, harness = make_harness(tmp_path)
    arguments = {"path": str(tmp_path / "file.txt"), "secret": "hidden"}
    await harness.invoke(tool, arguments)
    request = await require_one_approval(broker)

    cancelled = await broker.cancel_request(request.request_id)
    decision = await broker.decide(
        request.request_id,
        ApprovalChoice.APPROVE_ONCE,
        trusted_user(),
        ApprovalSource.TRUSTED_UI,
    )
    retry = await harness.invoke(tool, arguments)

    assert cancelled is not None and cancelled.status is ApprovalStatus.CANCELLED
    assert decision.accepted is False
    assert decision.reason is DecisionReason.APPROVAL_CANCELLED
    assert retry.status is ToolResultStatus.PERMISSION_DENIED
    assert tool.executions == 0


@pytest.mark.asyncio
async def test_task_cancellation_cancels_only_matching_approvals(tmp_path: Path) -> None:
    tool, broker, harness = make_harness(tmp_path)
    first_task = uuid4()
    second_task = uuid4()
    arguments = {"path": str(tmp_path / "file.txt"), "secret": "hidden"}
    await harness.invoke(tool, arguments, task_id=first_task)
    await harness.invoke(tool, arguments, task_id=second_task)

    cancelled = await broker.cancel_task(first_task)
    remaining = await broker.pending_approvals()

    assert len(cancelled) == 1
    assert cancelled[0].task_id == first_task
    assert cancelled[0].status is ApprovalStatus.CANCELLED
    assert len(remaining) == 1 and remaining[0].task_id == second_task


@pytest.mark.asyncio
async def test_deny_once_does_not_create_a_persistent_deny(tmp_path: Path) -> None:
    tool, broker, harness = make_harness(tmp_path)
    arguments = {"path": str(tmp_path / "file.txt"), "secret": "hidden"}
    await harness.invoke(tool, arguments)
    request = await require_one_approval(broker)
    denied = await broker.decide(
        request.request_id,
        ApprovalChoice.DENY_ONCE,
        trusted_user(),
        ApprovalSource.TRUSTED_UI,
    )

    retry = await harness.invoke(tool, arguments)
    pending = await broker.pending_approvals()

    assert denied.accepted is True
    assert denied.request is not None and denied.request.status is ApprovalStatus.DENIED
    assert retry.status is ToolResultStatus.PERMISSION_DENIED
    assert len(pending) == 1 and pending[0].request_id != request.request_id


@pytest.mark.asyncio
async def test_limited_grant_is_scoped_and_expires(tmp_path: Path) -> None:
    clock = MutableClock(datetime(2026, 1, 1, tzinfo=UTC))
    tool, broker, harness = make_harness(tmp_path, clock=clock)
    task_id = uuid4()
    approved_path = str(tmp_path / "approved.txt")
    arguments = {"path": approved_path, "secret": "one"}
    await harness.invoke(tool, arguments, task_id=task_id)
    request = await require_one_approval(broker)
    granted = await broker.decide(
        request.request_id,
        ApprovalChoice.APPROVE_LIMITED,
        trusted_user(),
        ApprovalSource.TRUSTED_LOCAL_API,
        remember_for_seconds=10,
    )

    first = await harness.invoke(
        tool,
        {"path": approved_path, "secret": "changed-inside-scope"},
        task_id=task_id,
    )
    other_task = await harness.invoke(tool, arguments, task_id=uuid4())
    clock.value += timedelta(seconds=11)
    expired = await harness.invoke(tool, arguments, task_id=task_id)

    assert granted.accepted is True
    assert first.status is ToolResultStatus.SUCCESS
    assert other_task.status is ToolResultStatus.PERMISSION_DENIED
    assert expired.status is ToolResultStatus.PERMISSION_DENIED
    assert tool.executions == 1


def test_hard_safety_policy_overrides_allow(tmp_path: Path) -> None:
    scope = PermissionScope(
        paths=(str(tmp_path / "target"),),
        tool_id="brokered-file",
        task_id=uuid4(),
    )
    engine = PolicyEngine(
        (
            PolicyRule(
                "allow-write",
                Permission.FILESYSTEM_WRITE,
                Decision.ALLOW,
                ScopeConstraint(paths=(str(tmp_path),)),
                frozenset({"write approved test file"}),
            ),
        )
    )
    request = PermissionRequest(Permission.FILESYSTEM_WRITE, scope)

    bulk = engine.evaluate(
        request,
        action="write approved test file",
        safety_class=SafetyClass.BULK_DELETION,
    )
    escalation = engine.evaluate(
        request,
        action="write approved test file",
        safety_class=SafetyClass.PRIVILEGE_ESCALATION,
    )
    destructive = engine.evaluate(
        request,
        action="write approved test file",
        safety_class=SafetyClass.DESTRUCTIVE_SYSTEM_COMMAND,
    )

    assert bulk.decision is Decision.REQUIRE_APPROVAL
    assert bulk.reason is DecisionReason.HARD_SAFETY_APPROVAL_REQUIRED
    assert destructive.decision is Decision.REQUIRE_APPROVAL
    assert escalation.decision is Decision.DENY
    assert escalation.reason is DecisionReason.HARD_SAFETY_DENY


@pytest.mark.asyncio
async def test_hard_safety_approval_cannot_be_remembered(tmp_path: Path) -> None:
    tool, broker, harness = make_harness(
        tmp_path,
        decision=Decision.ALLOW,
        safety_class=SafetyClass.BULK_DELETION,
    )
    await harness.invoke(
        tool,
        {"path": str(tmp_path / "many-files"), "secret": "hidden"},
    )
    request = await require_one_approval(broker)

    decision = await broker.decide(
        request.request_id,
        ApprovalChoice.APPROVE_LIMITED,
        trusted_user(),
        ApprovalSource.TRUSTED_UI,
        remember_for_seconds=10,
    )

    assert decision.accepted is False
    assert decision.reason is DecisionReason.INVALID_REMEMBERED_GRANT
    assert tool.executions == 0


@pytest.mark.asyncio
async def test_audit_records_decision_identity_fingerprint_and_outcome_without_secret(
    tmp_path: Path,
) -> None:
    audit = InMemoryAuditSink()
    tool, broker, harness = make_harness(tmp_path, audit=audit)
    arguments = {"path": str(tmp_path / "file.txt"), "secret": "top-secret-value"}
    task_id = uuid4()
    await harness.invoke(tool, arguments, task_id=task_id)
    request = await require_one_approval(broker)
    await broker.decide(
        request.request_id,
        ApprovalChoice.APPROVE_ONCE,
        trusted_user(),
        ApprovalSource.TRUSTED_UI,
    )
    await harness.invoke(tool, arguments, task_id=task_id)

    records = await audit.records()
    execution = records[-1]

    assert execution.requested_permission == Permission.FILESYSTEM_WRITE.value
    assert execution.argument_fingerprint == PermissionBroker.fingerprint(arguments)
    assert execution.argument_names == ("path", "secret")
    assert execution.policy_id == "filesystem.write.test-root"
    assert execution.approval_identity == "local-user-1"
    assert execution.approval_source is ApprovalSource.TRUSTED_UI
    assert execution.execution_outcome == ToolResultStatus.SUCCESS.value
    assert "top-secret-value" not in repr(records)
