import asyncio
import logging
import os
from dataclasses import dataclass, replace
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import cast
from uuid import UUID, uuid4

import pytest
from jarvis.permissions import (
    ActionDescriptor,
    ApprovalActorKind,
    ApprovalChoice,
    ApprovalIdentity,
    ApprovalRequest,
    ApprovalSource,
    ApprovalStatus,
    AuditRecord,
    AuditSink,
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
    TrustedApprovalAuthenticator,
    TrustedApprovalContext,
)
from jarvis.tools.base import Tool
from jarvis.tools.harness import ToolHarness
from jarvis.tools.models import (
    SemanticVersion,
    ToolCaller,
    ToolExecutionContext,
    ToolHealth,
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


class MalformedDescriptorTool(BrokeredFileTool):
    def _describe_action(
        self, context: ToolExecutionContext, validated_input: FileInput
    ) -> ActionDescriptor:
        del context, validated_input
        return cast(ActionDescriptor, object())


class VersionedDescriptorFileTool(BrokeredFileTool):
    def __init__(self) -> None:
        super().__init__()
        self.resource_version = "v1"

    def _describe_action(
        self, context: ToolExecutionContext, validated_input: FileInput
    ) -> ActionDescriptor:
        descriptor = super()._describe_action(context, validated_input)
        return replace(
            descriptor,
            arguments_summary=descriptor.arguments_summary
            + (SafeArgument("resource_version", self.resource_version),),
        )


class PartialFailureFileTool(BrokeredFileTool):
    async def _execute_authorized(
        self, context: ToolExecutionContext, validated_input: FileInput
    ) -> ToolResult:
        del context, validated_input
        self.executions += 1
        return ToolResult.failure(
            ToolResultStatus.EXPECTED_FAILURE,
            "post_effect_verification_failed",
            "The provider could not verify its external effect",
        )


@dataclass
class MutableClock:
    value: datetime

    def __call__(self) -> datetime:
        return self.value


class FailingAuditSink(AuditSink):
    async def append(self, record: AuditRecord) -> None:
        del record
        raise OSError("audit unavailable")


class SwitchableAuditSink(InMemoryAuditSink):
    def __init__(self) -> None:
        super().__init__()
        self.available = True

    async def append(self, record: AuditRecord) -> None:
        if not self.available:
            raise OSError("audit unavailable")
        await super().append(record)


class OutcomeFailingAuditSink(InMemoryAuditSink):
    async def append(self, record: AuditRecord) -> None:
        if record.execution_outcome != "authorized_intent":
            raise OSError("outcome audit unavailable")
        await super().append(record)


_HOSTILE_APPROVAL_TEXT = (
    "tab\tspoof",
    "nul\x00spoof",
    "line\nspoof",
    "return\rspoof",
    "ansi\x1b[2Jspoof",
    "c1\x85spoof",
    "override\u202espoof",
    "isolate\u2066spoof\u2069",
)


@pytest.mark.parametrize("hostile", _HOSTILE_APPROVAL_TEXT)
def test_safe_argument_rejects_control_and_bidi_display_spoofing(hostile: str) -> None:
    with pytest.raises(ValueError, match="display controls"):
        SafeArgument("publisher", hostile)
    with pytest.raises(ValueError, match="display controls"):
        SafeArgument(hostile, "trusted value")


def test_safe_argument_preserves_bounded_printable_unicode() -> None:
    argument = SafeArgument("éditeur", "München 株式会社 🚀")

    assert argument.name == "éditeur"
    assert argument.value == "München 株式会社 🚀"


@pytest.mark.parametrize("hostile", ("install\x1b[2Jpackage", "install\u202epackage"))
def test_action_descriptor_rejects_display_spoofing(hostile: str) -> None:
    with pytest.raises(ValueError, match="trusted, bounded types"):
        ActionDescriptor(hostile, (), Risk.CRITICAL, ())


class ExpiringHealthFileTool(BrokeredFileTool):
    def __init__(self, clock: MutableClock) -> None:
        super().__init__()
        self._clock = clock

    async def health_check(self) -> ToolHealth:
        self._clock.value += timedelta(seconds=31)
        return await super().health_check()


class BlockingHealthFileTool(BrokeredFileTool):
    def __init__(self) -> None:
        super().__init__()
        self.health_started = asyncio.Event()
        self.release_health = asyncio.Event()

    async def health_check(self) -> ToolHealth:
        self.health_started.set()
        await self.release_health.wait()
        return await super().health_check()


_APPROVAL_AUTHENTICATORS: dict[int, TrustedApprovalAuthenticator] = {}


def make_broker(
    root: Path,
    *,
    decision: Decision = Decision.REQUIRE_APPROVAL,
    enabled: bool = True,
    clock: MutableClock | None = None,
    audit: AuditSink | None = None,
    approval_source: ApprovalSource = ApprovalSource.TRUSTED_UI,
    approval_context_ttl_seconds: int = 60,
) -> PermissionBroker:
    authenticator = TrustedApprovalAuthenticator(
        approval_source,
        context_ttl_seconds=approval_context_ttl_seconds,
        clock=clock,
    )
    broker = PermissionBroker(
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
        approval_context_verifier=authenticator.verifier(),
    )
    _APPROVAL_AUTHENTICATORS[id(broker)] = authenticator
    return broker


def make_harness(
    root: Path,
    *,
    decision: Decision = Decision.REQUIRE_APPROVAL,
    enabled: bool = True,
    clock: MutableClock | None = None,
    audit: AuditSink | None = None,
    safety_class: SafetyClass = SafetyClass.ORDINARY,
    approval_source: ApprovalSource = ApprovalSource.TRUSTED_UI,
    approval_context_ttl_seconds: int = 60,
) -> tuple[BrokeredFileTool, PermissionBroker, ToolHarness]:
    broker = make_broker(
        root,
        decision=decision,
        enabled=enabled,
        clock=clock,
        audit=audit,
        approval_source=approval_source,
        approval_context_ttl_seconds=approval_context_ttl_seconds,
    )
    tool = BrokeredFileTool(safety_class=safety_class)
    ToolRegistry((tool,), permission_broker=broker)
    return tool, broker, ToolHarness(broker=broker)


def trusted_user() -> ApprovalIdentity:
    return ApprovalIdentity("local-user-1", ApprovalActorKind.TRUSTED_USER)


def trusted_context(
    broker: PermissionBroker,
    request_id: UUID,
    choice: ApprovalChoice,
    *,
    remember_for_seconds: int | None = None,
) -> TrustedApprovalContext:
    return _APPROVAL_AUTHENTICATORS[id(broker)].issue_context(
        request_id=request_id,
        choice=choice,
        identity=trusted_user(),
        remember_for_seconds=remember_for_seconds,
    )


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
    malformed_safety = engine.evaluate(
        request,
        action="write file",
        safety_class=cast(SafetyClass, "privilege_escalation"),
    )

    assert unknown.reason is DecisionReason.UNKNOWN_ACTION
    assert malformed.reason is DecisionReason.MALFORMED_ACTION
    assert malformed_safety.reason is DecisionReason.MALFORMED_ACTION


def test_malformed_scope_containers_and_policy_constraints_fail_closed(tmp_path: Path) -> None:
    request = PermissionRequest(
        Permission.TERMINAL_EXECUTE,
        PermissionScope(
            command_families=cast(tuple[str, ...], "git"),
            tool_id="terminal",
            task_id=uuid4(),
        ),
    )
    result = PolicyEngine().evaluate(request, action="run git")
    malformed_task = PolicyEngine().evaluate(
        PermissionRequest(
            Permission.FILESYSTEM_READ,
            PermissionScope(
                paths=(str(tmp_path),),
                tool_id="reader",
                task_id=cast(UUID, "not-a-task-id"),
            ),
        ),
        action="read",
    )
    malformed_host = PolicyEngine().evaluate(
        PermissionRequest(
            Permission.NETWORK_REQUEST,
            PermissionScope(
                hosts=("example.com:notaport",),
                tool_id="network-client",
                task_id=uuid4(),
            ),
        ),
        action="request",
    )

    assert result.reason is DecisionReason.MALFORMED_SCOPE
    assert malformed_task.reason is DecisionReason.MALFORMED_SCOPE
    assert malformed_host.reason is DecisionReason.MALFORMED_SCOPE
    with pytest.raises(ValueError, match="containers are malformed"):
        PolicyEngine(
            (
                PolicyRule(
                    "bad-container",
                    Permission.TERMINAL_EXECUTE,
                    Decision.ALLOW,
                    ScopeConstraint(
                        command_families=cast(tuple[str, ...], "git"),
                    ),
                    frozenset({"run git"}),
                ),
            )
        )


@pytest.mark.parametrize(
    "hostile",
    ("\t", "\x1b[2J", "\x85", "\u202e", "\u2066"),
)
def test_scope_display_fields_reject_control_and_bidi_spoofing(
    tmp_path: Path,
    hostile: str,
) -> None:
    task_id = uuid4()
    engine = PolicyEngine()
    results = (
        engine.evaluate(
            PermissionRequest(
                Permission.FILESYSTEM_READ,
                PermissionScope(
                    paths=(str(tmp_path / f"file{hostile}.txt"),),
                    tool_id="reader",
                    task_id=task_id,
                ),
            ),
            action="read file",
        ),
        engine.evaluate(
            PermissionRequest(
                Permission.APPLICATION_LAUNCH,
                PermissionScope(
                    applications=(f"notepad{hostile}.exe",),
                    tool_id="launcher",
                    task_id=task_id,
                ),
            ),
            action="launch application",
        ),
        engine.evaluate(
            PermissionRequest(
                Permission.NETWORK_REQUEST,
                PermissionScope(
                    hosts=(f"api{hostile}.example",),
                    tool_id="network",
                    task_id=task_id,
                ),
            ),
            action="request network",
        ),
        engine.evaluate(
            PermissionRequest(
                Permission.TERMINAL_EXECUTE,
                PermissionScope(
                    command_families=(f"git{hostile}.status",),
                    tool_id="terminal",
                    task_id=task_id,
                ),
            ),
            action="inspect repository",
        ),
        engine.evaluate(
            PermissionRequest(
                Permission.FILESYSTEM_READ,
                PermissionScope(
                    paths=(str(tmp_path),),
                    tool_id=f"reader{hostile}",
                    task_id=task_id,
                ),
            ),
            action="read file",
        ),
    )

    assert {result.reason for result in results} == {DecisionReason.MALFORMED_SCOPE}


def test_policy_tool_identifier_rejects_display_spoofing() -> None:
    with pytest.raises(ValueError, match="tool/task constraints"):
        PolicyEngine(
            (
                PolicyRule(
                    "safe-policy",
                    Permission.APPLICATION_LAUNCH,
                    Decision.ALLOW,
                    ScopeConstraint(tools=frozenset({"launcher\u202e"})),
                    frozenset({"launch application"}),
                ),
            )
        )


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
        trusted_context(broker, request.request_id, ApprovalChoice.APPROVE_ONCE)
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
        trusted_context(broker, request.request_id, ApprovalChoice.APPROVE_ONCE)
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
    await broker.decide(trusted_context(broker, request.request_id, ApprovalChoice.APPROVE_ONCE))
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
    await broker.decide(trusted_context(broker, request.request_id, ApprovalChoice.APPROVE_ONCE))

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
    rogue_authenticator = TrustedApprovalAuthenticator(ApprovalSource.TRUSTED_UI)
    with pytest.raises(ValueError, match="authenticated trusted user"):
        rogue_authenticator.issue_context(
            request_id=request.request_id,
            choice=ApprovalChoice.APPROVE_ONCE,
            identity=ApprovalIdentity("planner", ApprovalActorKind.MODEL),
        )
    forged_decision = await broker.decide(
        rogue_authenticator.issue_context(
            request_id=request.request_id,
            choice=ApprovalChoice.APPROVE_ONCE,
            identity=trusted_user(),
        )
    )

    assert forged_decision.accepted is False
    assert forged_decision.reason is DecisionReason.UNTRUSTED_APPROVER
    assert tool.executions == 0


@pytest.mark.asyncio
async def test_malformed_tool_descriptor_denies_before_effect(tmp_path: Path) -> None:
    broker = make_broker(tmp_path, decision=Decision.ALLOW)
    tool = MalformedDescriptorTool()
    ToolRegistry((tool,), permission_broker=broker)

    result = await ToolHarness(broker=broker).invoke(
        tool,
        {"path": str(tmp_path / "file.txt"), "secret": "hidden"},
    )

    assert result.status is ToolResultStatus.PERMISSION_DENIED
    assert result.error is not None
    assert result.error.code == DecisionReason.MALFORMED_ACTION.value
    assert tool.executions == 0

    direct = await broker.authorize(
        tool_id=tool.manifest.tool_id,
        tool_identity=tool,
        declared_permissions=tool.manifest.declared_permissions,
        task_id=uuid4(),
        user_id="test-user",
        descriptor=cast(ActionDescriptor, object()),
        normalized_arguments={"path": str(tmp_path / "file.txt")},
    )
    assert not direct.authorized
    assert direct.reason is DecisionReason.MALFORMED_ACTION


@pytest.mark.asyncio
async def test_changed_trusted_action_semantics_require_fresh_approval(tmp_path: Path) -> None:
    broker = make_broker(tmp_path)
    tool = VersionedDescriptorFileTool()
    ToolRegistry((tool,), permission_broker=broker)
    harness = ToolHarness(broker=broker)
    task_id = uuid4()
    arguments = {"path": str(tmp_path / "file.txt"), "secret": "hidden"}
    await harness.invoke(tool, arguments, task_id=task_id)
    original = await require_one_approval(broker)
    await broker.decide(trusted_context(broker, original.request_id, ApprovalChoice.APPROVE_ONCE))
    tool.resource_version = "v2"

    changed = await harness.invoke(tool, arguments, task_id=task_id)
    pending = await broker.pending_approvals(task_id)

    assert changed.status is ToolResultStatus.PERMISSION_DENIED
    assert len(pending) == 1
    assert pending[0].action_fingerprint != original.action_fingerprint
    assert tool.executions == 0


@pytest.mark.asyncio
async def test_remembered_grant_does_not_cover_changed_action_semantics(tmp_path: Path) -> None:
    broker = make_broker(tmp_path)
    tool = VersionedDescriptorFileTool()
    ToolRegistry((tool,), permission_broker=broker)
    harness = ToolHarness(broker=broker)
    task_id = uuid4()
    arguments = {"path": str(tmp_path / "file.txt"), "secret": "hidden"}
    await harness.invoke(tool, arguments, task_id=task_id)
    original = await require_one_approval(broker)
    await broker.decide(
        trusted_context(
            broker,
            original.request_id,
            ApprovalChoice.APPROVE_LIMITED,
            remember_for_seconds=30,
        )
    )
    tool.resource_version = "v2"

    changed = await harness.invoke(tool, arguments, task_id=task_id)

    assert changed.status is ToolResultStatus.PERMISSION_DENIED
    assert len(await broker.pending_approvals(task_id)) == 1
    assert tool.executions == 0


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "choice",
    (ApprovalChoice.APPROVE_ONCE, ApprovalChoice.APPROVE_LIMITED),
)
async def test_approval_does_not_survive_policy_substitution(
    tmp_path: Path, choice: ApprovalChoice
) -> None:
    tool, broker, harness = make_harness(tmp_path)
    task_id = uuid4()
    arguments = {"path": str(tmp_path / "file.txt"), "secret": "hidden"}
    await harness.invoke(tool, arguments, task_id=task_id)
    original = await require_one_approval(broker)
    await broker.decide(
        trusted_context(
            broker,
            original.request_id,
            choice,
            remember_for_seconds=30 if choice is ApprovalChoice.APPROVE_LIMITED else None,
        )
    )
    broker._policy = PolicyEngine(  # noqa: SLF001 - simulate trusted policy replacement
        (
            PolicyRule(
                policy_id="filesystem.write.replacement-policy",
                permission=Permission.FILESYSTEM_WRITE,
                decision=Decision.REQUIRE_APPROVAL,
                scope=ScopeConstraint(
                    paths=(str(tmp_path),),
                    tools=frozenset({"brokered-file"}),
                    max_duration_seconds=120,
                ),
                actions=frozenset({"write approved test file"}),
            ),
        )
    )

    changed = await harness.invoke(tool, arguments, task_id=task_id)
    pending = await broker.pending_approvals(task_id)

    assert changed.status is ToolResultStatus.PERMISSION_DENIED
    assert len(pending) == 1
    assert pending[0].request_id != original.request_id
    assert pending[0].policy_id == "filesystem.write.replacement-policy"
    assert tool.executions == 0


@pytest.mark.asyncio
async def test_privileged_post_effect_failure_has_unknown_outcome(tmp_path: Path) -> None:
    broker = make_broker(tmp_path)
    tool = PartialFailureFileTool()
    ToolRegistry((tool,), permission_broker=broker)
    harness = ToolHarness(broker=broker)
    task_id = uuid4()
    arguments = {"path": str(tmp_path / "file.txt"), "secret": "hidden"}
    await harness.invoke(tool, arguments, task_id=task_id)
    request = await require_one_approval(broker)
    await broker.decide(trusted_context(broker, request.request_id, ApprovalChoice.APPROVE_ONCE))

    result = await harness.invoke(tool, arguments, task_id=task_id)

    assert result.status is ToolResultStatus.UNKNOWN_OUTCOME
    assert result.error is not None
    assert result.error.code == "tool_execution_outcome_unknown"
    assert tool.executions == 1


@pytest.mark.asyncio
async def test_approval_context_is_single_use(tmp_path: Path) -> None:
    tool, broker, harness = make_harness(tmp_path)
    await harness.invoke(
        tool,
        {"path": str(tmp_path / "file.txt"), "secret": "hidden"},
    )
    request = await require_one_approval(broker)
    context = trusted_context(broker, request.request_id, ApprovalChoice.APPROVE_ONCE)

    accepted = await broker.decide(context)
    replayed = await broker.decide(context)

    assert accepted.accepted is True
    assert replayed.accepted is False
    assert replayed.reason is DecisionReason.APPROVAL_CONSUMED


def test_approval_context_cannot_resurrect_after_wall_clock_rollback() -> None:
    clock = MutableClock(datetime(2026, 1, 1, tzinfo=UTC))
    authenticator = TrustedApprovalAuthenticator(
        ApprovalSource.TRUSTED_UI,
        context_ttl_seconds=60,
        clock=clock,
    )
    verifier = authenticator.verifier()
    context = authenticator.issue_context(
        request_id=uuid4(),
        choice=ApprovalChoice.APPROVE_ONCE,
        identity=trusted_user(),
    )

    assert verifier.verify_and_consume(context).accepted
    clock.value += timedelta(minutes=10)
    authenticator.issue_context(
        request_id=uuid4(),
        choice=ApprovalChoice.APPROVE_ONCE,
        identity=trusted_user(),
    )
    clock.value = context.issued_at + timedelta(seconds=1)

    replay = verifier.verify_and_consume(context)

    assert not replay.accepted
    assert replay.reason is DecisionReason.APPROVAL_CONSUMED


@pytest.mark.asyncio
async def test_approval_context_binds_every_decision_claim(tmp_path: Path) -> None:
    tool, broker, harness = make_harness(tmp_path)
    await harness.invoke(
        tool,
        {"path": str(tmp_path / "file.txt"), "secret": "hidden"},
    )
    request = await require_one_approval(broker)
    context = trusted_context(broker, request.request_id, ApprovalChoice.APPROVE_ONCE)

    tampered_contexts = (
        replace(context, request_id=uuid4()),
        replace(
            context,
            identity=ApprovalIdentity("different-user", ApprovalActorKind.TRUSTED_USER),
        ),
        replace(context, source=ApprovalSource.TRUSTED_LOCAL_API),
        replace(context, expires_at=context.expires_at + timedelta(seconds=1)),
        replace(context, choice=ApprovalChoice.DENY_ONCE),
        replace(
            context,
            choice=ApprovalChoice.APPROVE_LIMITED,
            remember_for_seconds=10,
        ),
    )
    rejected = []
    for item in tampered_contexts:
        rejected.append(await broker.decide(item))
    original = await broker.decide(context)

    assert all(item.reason is DecisionReason.UNTRUSTED_APPROVER for item in rejected)
    assert original.accepted is True


@pytest.mark.asyncio
async def test_expired_approval_context_cannot_decide_pending_request(tmp_path: Path) -> None:
    clock = MutableClock(datetime(2026, 1, 1, tzinfo=UTC))
    tool, broker, harness = make_harness(
        tmp_path,
        clock=clock,
        approval_context_ttl_seconds=1,
    )
    await harness.invoke(
        tool,
        {"path": str(tmp_path / "file.txt"), "secret": "hidden"},
    )
    request = await require_one_approval(broker)
    context = trusted_context(broker, request.request_id, ApprovalChoice.APPROVE_ONCE)
    clock.value += timedelta(seconds=2)

    expired = await broker.decide(context)

    assert expired.accepted is False
    assert expired.reason is DecisionReason.APPROVAL_EXPIRED
    pending = await broker.get_approval(request.request_id)
    assert pending is not None and pending.status is ApprovalStatus.PENDING


@pytest.mark.asyncio
async def test_approval_authenticator_rejects_unsafe_construction_and_minting() -> None:
    with pytest.raises(ValueError, match="trusted local source"):
        TrustedApprovalAuthenticator(ApprovalSource.MODEL)
    for invalid_ttl in (True, 0, 301):
        with pytest.raises(ValueError, match="between 1 and 300"):
            TrustedApprovalAuthenticator(
                ApprovalSource.TRUSTED_UI,
                context_ttl_seconds=cast(int, invalid_ttl),
            )

    authenticator = TrustedApprovalAuthenticator(ApprovalSource.TRUSTED_UI)
    with pytest.raises(ValueError, match="typed request and decision"):
        authenticator.issue_context(
            request_id=cast(UUID, "request-id"),
            choice=ApprovalChoice.APPROVE_ONCE,
            identity=trusted_user(),
        )
    with pytest.raises(ValueError, match="positive remembered duration"):
        authenticator.issue_context(
            request_id=uuid4(),
            choice=ApprovalChoice.APPROVE_LIMITED,
            identity=trusted_user(),
        )
    with pytest.raises(ValueError, match="only for limited approval"):
        authenticator.issue_context(
            request_id=uuid4(),
            choice=ApprovalChoice.APPROVE_ONCE,
            identity=trusted_user(),
            remember_for_seconds=10,
        )
    naive_clock_authenticator = TrustedApprovalAuthenticator(
        ApprovalSource.TRUSTED_UI,
        clock=lambda: datetime(2026, 1, 1),
    )
    with pytest.raises(ValueError, match="timezone-aware"):
        naive_clock_authenticator.issue_context(
            request_id=uuid4(),
            choice=ApprovalChoice.APPROVE_ONCE,
            identity=trusted_user(),
        )

    context = authenticator.issue_context(
        request_id=uuid4(),
        choice=ApprovalChoice.APPROVE_ONCE,
        identity=trusted_user(),
    )
    assert context._proof.hex() not in repr(context)
    unpaired_broker = PermissionBroker(PolicyEngine())
    denied = await unpaired_broker.decide(context)
    malformed = await unpaired_broker.decide(cast(TrustedApprovalContext, "not-a-context"))
    assert denied.reason is DecisionReason.UNTRUSTED_APPROVER
    assert malformed.reason is DecisionReason.MALFORMED_APPROVAL_DECISION


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
        trusted_context(broker, request.request_id, ApprovalChoice.APPROVE_ONCE)
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
async def test_task_cancellation_revokes_approved_but_unconsumed_request(tmp_path: Path) -> None:
    tool, broker, harness = make_harness(tmp_path)
    task_id = uuid4()
    arguments = {"path": str(tmp_path / "file.txt"), "secret": "hidden"}
    await harness.invoke(tool, arguments, task_id=task_id)
    request = await require_one_approval(broker)
    approved = await broker.decide(
        trusted_context(broker, request.request_id, ApprovalChoice.APPROVE_ONCE)
    )

    cancelled = await broker.cancel_task(task_id)
    retry = await harness.invoke(tool, arguments, task_id=task_id)

    assert approved.accepted
    assert len(cancelled) == 1
    assert cancelled[0].status is ApprovalStatus.CANCELLED
    assert retry.status is ToolResultStatus.PERMISSION_DENIED
    assert retry.error is not None
    assert retry.error.code == DecisionReason.TASK_CANCELLED.value
    assert await broker.pending_approvals(task_id) == ()
    assert tool.executions == 0


@pytest.mark.asyncio
async def test_deny_once_does_not_create_a_persistent_deny(tmp_path: Path) -> None:
    tool, broker, harness = make_harness(tmp_path)
    arguments = {"path": str(tmp_path / "file.txt"), "secret": "hidden"}
    await harness.invoke(tool, arguments)
    request = await require_one_approval(broker)
    denied = await broker.decide(
        trusted_context(broker, request.request_id, ApprovalChoice.DENY_ONCE)
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
    tool, broker, harness = make_harness(
        tmp_path,
        clock=clock,
        approval_source=ApprovalSource.TRUSTED_LOCAL_API,
    )
    task_id = uuid4()
    approved_path = str(tmp_path / "approved.txt")
    arguments = {"path": approved_path, "secret": "one"}
    await harness.invoke(tool, arguments, task_id=task_id)
    request = await require_one_approval(broker)
    granted = await broker.decide(
        trusted_context(
            broker,
            request.request_id,
            ApprovalChoice.APPROVE_LIMITED,
            remember_for_seconds=10,
        )
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
    self_modification = engine.evaluate(
        request,
        action="write approved test file",
        safety_class=SafetyClass.SELF_MODIFICATION,
    )

    assert bulk.decision is Decision.REQUIRE_APPROVAL
    assert bulk.reason is DecisionReason.HARD_SAFETY_APPROVAL_REQUIRED
    assert destructive.decision is Decision.REQUIRE_APPROVAL
    assert self_modification.decision is Decision.REQUIRE_APPROVAL
    assert self_modification.reason is DecisionReason.HARD_SAFETY_APPROVAL_REQUIRED
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
        trusted_context(
            broker,
            request.request_id,
            ApprovalChoice.APPROVE_LIMITED,
            remember_for_seconds=10,
        )
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
    await harness.invoke(tool, arguments, task_id=task_id, user_id="requester-1")
    request = await require_one_approval(broker)
    await broker.decide(trusted_context(broker, request.request_id, ApprovalChoice.APPROVE_ONCE))
    await harness.invoke(tool, arguments, task_id=task_id, user_id="requester-1")

    records = await audit.records()
    requested = next(
        record for record in records if record.execution_outcome == "approval_requested"
    )
    execution = records[-1]

    assert requested.user_id == "requester-1"
    assert requested.approval_request_id == request.request_id
    assert execution.requested_permission == Permission.FILESYSTEM_WRITE.value
    assert execution.argument_fingerprint == broker.fingerprint(arguments)
    assert execution.argument_names == ("path", "secret")
    assert execution.policy_id == "filesystem.write.test-root"
    assert execution.approval_identity == "local-user-1"
    assert execution.approval_source is ApprovalSource.TRUSTED_UI
    assert execution.execution_outcome == ToolResultStatus.SUCCESS.value
    assert "top-secret-value" not in repr(records)


@pytest.mark.parametrize(
    "untrusted_input",
    (
        "deny_once",
        "YES if the path is safe",
        "maybe approve and also remember it",
    ),
)
@pytest.mark.asyncio
async def test_unknown_or_ambiguous_approval_input_fails_closed_instead_of_approving(
    tmp_path: Path,
    untrusted_input: str,
) -> None:
    tool, broker, harness = make_harness(tmp_path)
    arguments = {"path": str(tmp_path / "file.txt"), "secret": "hidden"}
    await harness.invoke(tool, arguments)
    await require_one_approval(broker)

    decision = await broker.decide(cast(TrustedApprovalContext, untrusted_input))

    assert not decision.accepted
    assert decision.reason is DecisionReason.MALFORMED_APPROVAL_DECISION
    assert tool.executions == 0


@pytest.mark.asyncio
async def test_audit_failure_blocks_execution_before_effect(tmp_path: Path) -> None:
    tool, _broker, harness = make_harness(
        tmp_path,
        decision=Decision.ALLOW,
        audit=FailingAuditSink(),
    )

    result = await harness.invoke(
        tool,
        {"path": str(tmp_path / "file.txt"), "secret": "hidden"},
    )

    assert result.status is ToolResultStatus.PERMISSION_DENIED
    assert result.error is not None and result.error.code == DecisionReason.AUDIT_UNAVAILABLE.value
    assert tool.executions == 0


@pytest.mark.asyncio
async def test_audit_failure_cannot_leave_an_unaudited_pending_request(tmp_path: Path) -> None:
    audit = SwitchableAuditSink()
    audit.available = False
    tool, broker, harness = make_harness(tmp_path, audit=audit)
    arguments = {"path": str(tmp_path / "file.txt"), "secret": "hidden"}

    denied = await harness.invoke(tool, arguments)

    assert denied.status is ToolResultStatus.PERMISSION_DENIED
    assert denied.error is not None
    assert denied.error.code == DecisionReason.AUDIT_UNAVAILABLE.value
    assert await broker.pending_approvals() == ()

    audit.available = True
    retry = await harness.invoke(tool, arguments)
    assert retry.status is ToolResultStatus.PERMISSION_DENIED
    assert len(await broker.pending_approvals()) == 1
    records = await audit.records()
    assert records[0].execution_outcome == "approval_requested"


@pytest.mark.asyncio
async def test_audit_failure_cannot_make_an_approval_or_grant_usable(tmp_path: Path) -> None:
    audit = SwitchableAuditSink()
    tool, broker, harness = make_harness(tmp_path, audit=audit)
    task_id = uuid4()
    arguments = {"path": str(tmp_path / "file.txt"), "secret": "hidden"}
    await harness.invoke(tool, arguments, task_id=task_id)
    request = await require_one_approval(broker)
    audit.available = False

    context = trusted_context(
        broker,
        request.request_id,
        ApprovalChoice.APPROVE_LIMITED,
        remember_for_seconds=10,
    )
    rejected = await broker.decide(context)

    assert not rejected.accepted
    assert rejected.reason is DecisionReason.AUDIT_UNAVAILABLE
    assert (await broker.get_approval(request.request_id)) == request
    audit.available = True
    replayed = await broker.decide(context)
    retry = await harness.invoke(tool, arguments, task_id=task_id)
    assert replayed.accepted is False
    assert replayed.reason is DecisionReason.APPROVAL_CONSUMED
    assert (await broker.get_approval(request.request_id)) == request
    assert retry.status is ToolResultStatus.PERMISSION_DENIED
    assert tool.executions == 0


@pytest.mark.asyncio
async def test_audit_failure_cannot_make_cancellation_visible(tmp_path: Path) -> None:
    audit = SwitchableAuditSink()
    _tool, broker, harness = make_harness(tmp_path, audit=audit)
    await harness.invoke(
        _tool,
        {"path": str(tmp_path / "file.txt"), "secret": "hidden"},
    )
    request = await require_one_approval(broker)
    audit.available = False

    with pytest.raises(OSError, match="audit unavailable"):
        await broker.cancel_request(request.request_id)

    assert (await broker.get_approval(request.request_id)) == request


@pytest.mark.asyncio
async def test_authorization_receipt_outcome_is_single_use(tmp_path: Path) -> None:
    tool, broker, harness = make_harness(tmp_path, decision=Decision.ALLOW)
    result = await harness.invoke(
        tool,
        {"path": str(tmp_path / "file.txt"), "secret": "hidden"},
    )
    receipt = tool.receipts[0]

    assert result.status is ToolResultStatus.SUCCESS
    with pytest.raises(ValueError, match=DecisionReason.FORGED_AUTHORIZATION_RECEIPT.value):
        await broker.record_execution_outcome(receipt, "replayed")


@pytest.mark.asyncio
async def test_approval_expiring_during_health_check_never_reaches_effect(tmp_path: Path) -> None:
    clock = MutableClock(datetime(2026, 1, 1, tzinfo=UTC))
    broker = make_broker(tmp_path, clock=clock)
    tool = ExpiringHealthFileTool(clock)
    ToolRegistry((tool,), permission_broker=broker)
    harness = ToolHarness(broker=broker)
    arguments = {"path": str(tmp_path / "file.txt"), "secret": "hidden"}
    task_id = uuid4()
    await harness.invoke(tool, arguments, task_id=task_id)
    request = await require_one_approval(broker)
    await broker.decide(trusted_context(broker, request.request_id, ApprovalChoice.APPROVE_ONCE))

    result = await harness.invoke(tool, arguments, task_id=task_id)

    assert result.status is ToolResultStatus.PERMISSION_DENIED
    assert result.error is not None
    assert result.error.code == DecisionReason.APPROVAL_EXPIRED.value
    assert tool.executions == 0


@pytest.mark.asyncio
async def test_task_cancelled_after_authorization_never_reaches_effect(tmp_path: Path) -> None:
    audit = InMemoryAuditSink()
    broker = make_broker(tmp_path, audit=audit)
    tool = BlockingHealthFileTool()
    ToolRegistry((tool,), permission_broker=broker)
    harness = ToolHarness(broker=broker)
    arguments = {"path": str(tmp_path / "file.txt"), "secret": "hidden"}
    task_id = uuid4()
    await harness.invoke(tool, arguments, task_id=task_id)
    request = await require_one_approval(broker)
    await broker.decide(trusted_context(broker, request.request_id, ApprovalChoice.APPROVE_ONCE))
    invocation = asyncio.create_task(harness.invoke(tool, arguments, task_id=task_id))
    await tool.health_started.wait()

    await broker.cancel_task(task_id)
    tool.release_health.set()
    result = await invocation
    records = await audit.records()

    assert result.status is ToolResultStatus.PERMISSION_DENIED
    assert result.error is not None
    assert result.error.code == DecisionReason.TASK_CANCELLED.value
    assert records[-1].execution_outcome == "not_executed_task_cancelled"
    assert tool.executions == 0


@pytest.mark.asyncio
async def test_unknown_effect_outcome_is_not_reauthorized_in_same_process(
    tmp_path: Path,
) -> None:
    audit = OutcomeFailingAuditSink()
    tool, _broker, harness = make_harness(
        tmp_path,
        decision=Decision.ALLOW,
        audit=audit,
    )
    arguments = {"path": str(tmp_path / "file.txt"), "secret": "hidden"}
    task_id = uuid4()

    first = await harness.invoke(tool, arguments, task_id=task_id)
    second = await harness.invoke(tool, arguments, task_id=task_id)

    assert first.status is ToolResultStatus.UNKNOWN_OUTCOME
    assert second.status is ToolResultStatus.PERMISSION_DENIED
    assert second.error is not None
    assert second.error.code == DecisionReason.OPERATION_OUTCOME_UNKNOWN.value
    assert tool.executions == 1


@pytest.mark.asyncio
async def test_approval_and_remembered_scope_are_bound_to_requesting_user(tmp_path: Path) -> None:
    tool, broker, harness = make_harness(tmp_path)
    task_id = uuid4()
    arguments = {"path": str(tmp_path / "file.txt"), "secret": "hidden"}
    await harness.invoke(tool, arguments, task_id=task_id, user_id="alice")
    request = await require_one_approval(broker)
    await broker.decide(trusted_context(broker, request.request_id, ApprovalChoice.APPROVE_ONCE))

    other_user = await harness.invoke(tool, arguments, task_id=task_id, user_id="bob")
    original_user = await harness.invoke(tool, arguments, task_id=task_id, user_id="alice")

    assert other_user.status is ToolResultStatus.PERMISSION_DENIED
    assert original_user.status is ToolResultStatus.SUCCESS
    assert tool.executions == 1


@pytest.mark.asyncio
async def test_authorization_intent_is_audited_before_outcome(tmp_path: Path) -> None:
    audit = InMemoryAuditSink()
    _tool, _broker, harness = make_harness(
        tmp_path,
        decision=Decision.ALLOW,
        audit=audit,
    )
    await harness.invoke(
        _tool,
        {"path": str(tmp_path / "file.txt"), "secret": "not-logged"},
    )

    records = await audit.records()
    assert tuple(record.execution_outcome for record in records) == (
        "authorized_intent",
        ToolResultStatus.SUCCESS.value,
    )
    assert "not-logged" not in repr(records)
