"""Trusted ToolRegistry adapters for VM-first and scoped host execution."""

from __future__ import annotations

from typing import Any

from pydantic import BaseModel, ConfigDict, Field

from jarvis.permissions.models import (
    ActionDescriptor,
    Permission,
    PermissionRequest,
    PermissionScope,
    Risk,
)
from jarvis.tools.base import Tool
from jarvis.tools.models import (
    SemanticVersion,
    ToolEffectDisposition,
    ToolEvidence,
    ToolExecutionContext,
    ToolManifest,
    ToolMetadata,
    ToolPlatform,
    ToolResult,
    ToolResultStatus,
)
from jarvis.vm.bridge import HostBridgeOperation, build_host_bridge_action_descriptor
from jarvis.vm.execution import (
    GuestOperationExecution,
    HostWriteEvidence,
    VMExecutionError,
    VMExecutionService,
    VMExecutionUnavailable,
    VMOperationSemanticError,
)
from jarvis.vm.models import GuestCommand, NetworkPolicy
from jarvis.vm.operations import (
    BuildCheckSemanticResult,
    ResearchSemanticResult,
    VMBuildCheckInput,
    VMResearchInput,
)
from jarvis.vm.router import ExecutionIntent


class GuestCommandInput(BaseModel):
    """Bounded command data; routing and network policy are trusted metadata."""

    model_config = ConfigDict(extra="forbid", strict=True)

    executable: str = Field(min_length=1, max_length=64)
    args: list[str] = Field(default_factory=list, max_length=32)


class GuestCommandOutput(BaseModel):
    """Machine-readable guest result without trusted authority material."""

    model_config = ConfigDict(extra="forbid", strict=True)

    task_id: str
    task_class: str
    environment: str
    provider: str
    instance_id: str
    instance_purpose: str
    request_id: str
    guest_ready: bool
    exit_code: int | None
    stdout: str
    stderr: str
    evidence_digest: str
    host_bridge_operations: tuple[str, ...]


class HostFileWriteInput(BaseModel):
    """One acceptance-owned relative path and its exact content."""

    model_config = ConfigDict(extra="forbid", strict=True)

    relative_path: str = Field(min_length=1, max_length=256)
    content: str = Field(max_length=4_096)


class HostFileWriteOutput(BaseModel):
    """Trusted post-effect observation for one approved host write."""

    model_config = ConfigDict(extra="forbid", strict=True)

    task_id: str
    request_id: str
    operation: str
    resource: str
    scope: str
    approval_identity: str
    action_fingerprint: str
    content_digest: str
    bytes_written: int
    post_effect_verified: bool


class GuestCommandTool(Tool[GuestCommandInput, GuestCommandOutput]):
    """Route one trusted task class to the application VM execution owner."""

    def __init__(
        self,
        service: VMExecutionService,
        *,
        tool_id: str,
        intent: ExecutionIntent,
        description: str,
    ) -> None:
        if not tool_id or intent.task_class in {"", "host"}:
            raise ValueError("guest tool metadata is malformed")
        self._service = service
        self.execution_intent = intent
        self._manifest = ToolManifest(
            tool_id=tool_id,
            name=f"VM {intent.task_class.title()}",
            description=description,
            version=SemanticVersion(1, 0, 0),
            capability_tags=frozenset({"vm", "vm_execution", tool_id}),
            input_schema=GuestCommandInput,
            output_schema=GuestCommandOutput,
            declared_permissions=frozenset(),
            supported_platforms=frozenset(
                {ToolPlatform.WINDOWS, ToolPlatform.LINUX, ToolPlatform.MACOS}
            ),
            timeout_seconds=120.0,
            implementation_id="jarvis.vm.tools.GuestCommandTool",
        )

    @property
    def manifest(self) -> ToolManifest:
        return self._manifest

    @property
    def input_model(self) -> type[GuestCommandInput]:
        return GuestCommandInput

    async def _execute_authorized(
        self, context: ToolExecutionContext, validated_input: GuestCommandInput
    ) -> ToolResult:
        command = GuestCommand(
            validated_input.executable,
            tuple(validated_input.args),
            network_policy=(
                NetworkPolicy.INTERNET_ONLY
                if self.execution_intent.network_required
                else NetworkPolicy.NO_NETWORK
            ),
        )
        try:
            evidence = await self._service.execute_guest(
                context.task_id, self.execution_intent, command
            )
        except VMExecutionUnavailable as error:
            return ToolResult.failure(
                ToolResultStatus.UNAVAILABLE,
                "vm_unavailable",
                "The requested VM route is unavailable; no host fallback was used",
                metadata=(ToolMetadata("route", error.evidence.route.environment.value),),
                effect_disposition=ToolEffectDisposition.NO_EFFECT,
            )
        except (VMExecutionError, ValueError):
            return ToolResult.failure(
                ToolResultStatus.INTERNAL_FAILURE,
                "vm_execution_failed",
                "The trusted VM execution service could not complete the guest command",
                effect_disposition=ToolEffectDisposition.NO_EFFECT,
            )
        if evidence.exit_code != 0 or evidence.timed_out or evidence.cancelled:
            return ToolResult.failure(
                ToolResultStatus.EXPECTED_FAILURE,
                "guest_command_failed",
                "The guest command did not complete successfully",
                effect_disposition=ToolEffectDisposition.NO_EFFECT,
            )
        assert evidence.instance_id is not None
        assert evidence.instance_purpose is not None
        output = GuestCommandOutput(
            task_id=str(evidence.task_id),
            task_class=evidence.intent.task_class,
            environment=evidence.route.environment.value,
            provider=evidence.provider,
            instance_id=str(evidence.instance_id),
            instance_purpose=evidence.instance_purpose.value,
            request_id=str(evidence.guest_request_id),
            guest_ready=evidence.guest_ready,
            exit_code=evidence.exit_code,
            stdout=evidence.stdout,
            stderr=evidence.stderr,
            evidence_digest=evidence.evidence_digest,
            host_bridge_operations=evidence.host_bridge_operations,
        )
        return ToolResult.success(
            output,
            evidence=(
                ToolEvidence("vm_route", f"vm_route={evidence.route.environment.value}"),
                ToolEvidence("vm_provider", f"provider={evidence.provider}"),
                ToolEvidence(
                    "vm_instance_purpose", f"instance_purpose={evidence.instance_purpose.value}"
                ),
                ToolEvidence("guest_ready", "guest_ready=true"),
                ToolEvidence("guest_exit", f"guest_exit_code={evidence.exit_code}"),
                ToolEvidence("host_bridge_operations", "host_bridge_operations=NONE"),
            ),
        )


class VMResearchOutput(BaseModel):
    """Verified bounded research result without retaining the supplied text."""

    model_config = ConfigDict(extra="forbid", strict=True)

    operation_id: str
    semantic_result_type: str
    input_digest: str
    result_digest: str
    character_count: int
    line_count: int
    word_count: int
    normalized_digest: str
    semantic_status: str
    trusted_verification_passed: bool
    environment: str
    provider: str
    instance_id: str
    instance_purpose: str
    guest_request_id: str
    exit_code: int | None
    host_bridge_operations: tuple[str, ...]
    cleanup_state: str


class VMBuildCheckOutput(BaseModel):
    """Verified bounded build-check result without executing submitted source."""

    model_config = ConfigDict(extra="forbid", strict=True)

    operation_id: str
    semantic_result_type: str
    input_digest: str
    result_digest: str
    valid: bool
    error_type: str | None
    error_line: int | None
    error_offset: int | None
    semantic_status: str
    trusted_verification_passed: bool
    environment: str
    provider: str
    instance_id: str
    instance_purpose: str
    guest_request_id: str
    exit_code: int | None
    host_bridge_operations: tuple[str, ...]
    cleanup_state: str


def _guest_operation_evidence(execution: GuestOperationExecution) -> tuple[ToolEvidence, ...]:
    evidence = execution.evidence
    return (
        ToolEvidence("vm_operation_id", f"vm_operation_id={evidence.operation_id}"),
        ToolEvidence("vm_route", f"vm_route={evidence.route.environment.value}"),
        ToolEvidence("vm_provider", f"provider={evidence.provider}"),
        ToolEvidence(
            "vm_instance_purpose",
            f"instance_purpose={evidence.instance_purpose.value}"
            if evidence.instance_purpose is not None
            else "instance_purpose=NONE",
        ),
        ToolEvidence("vm_input_digest", f"vm_input_digest={evidence.input_digest}"),
        ToolEvidence(
            "vm_semantic_result_type",
            f"vm_semantic_result_type={evidence.semantic_result_type}",
        ),
        ToolEvidence(
            "vm_semantic_result_digest",
            f"vm_semantic_result_digest={evidence.semantic_result_digest}",
        ),
        ToolEvidence("vm_semantic_status", f"vm_semantic_status={evidence.semantic_status}"),
        ToolEvidence(
            "vm_semantic_verification",
            "vm_semantic_verification=PASS"
            if evidence.trusted_verification_passed
            else "vm_semantic_verification=FAIL",
        ),
        ToolEvidence("guest_exit", f"guest_exit_code={evidence.exit_code}"),
        ToolEvidence(
            "host_bridge_operations",
            "host_bridge_operations=NONE"
            if not evidence.host_bridge_operations
            else f"host_bridge_operations={evidence.host_bridge_operations}",
        ),
        ToolEvidence("vm_cleanup", f"vm_cleanup={evidence.cleanup_state}"),
    )


class VMResearchTool(Tool[VMResearchInput, VMResearchOutput]):
    """Run the fixed trusted text-statistics program in the persistent Workbench."""

    def __init__(self, service: VMExecutionService) -> None:
        self._service = service
        self._manifest = ToolManifest(
            tool_id="vm.research",
            name="VM Research Analysis",
            description="Analyze bounded supplied text with a fixed read-only guest operation.",
            version=SemanticVersion(1, 0, 0),
            capability_tags=frozenset({"vm", "vm_execution", "research", "vm.research"}),
            input_schema=VMResearchInput,
            output_schema=VMResearchOutput,
            declared_permissions=frozenset(),
            supported_platforms=frozenset(
                {ToolPlatform.WINDOWS, ToolPlatform.LINUX, ToolPlatform.MACOS}
            ),
            timeout_seconds=120.0,
            implementation_id="jarvis.vm.tools.VMResearchTool",
        )

    @property
    def manifest(self) -> ToolManifest:
        return self._manifest

    @property
    def input_model(self) -> type[VMResearchInput]:
        return VMResearchInput

    async def _execute_authorized(
        self, context: ToolExecutionContext, validated_input: VMResearchInput
    ) -> ToolResult:
        try:
            execution = await self._service.execute_operation(context.task_id, validated_input)
        except VMExecutionUnavailable as error:
            return ToolResult.failure(
                ToolResultStatus.UNAVAILABLE,
                "vm_unavailable",
                "The Workbench VM is unavailable; no host fallback was used",
                metadata=(ToolMetadata("route", error.evidence.route.environment.value),),
                effect_disposition=ToolEffectDisposition.NO_EFFECT,
            )
        except VMOperationSemanticError as error:
            return ToolResult.failure(
                ToolResultStatus.EXPECTED_FAILURE,
                "semantic_verification_failed",
                "The guest result did not satisfy trusted research verification",
                metadata=(
                    ToolMetadata("operation_id", error.execution.evidence.operation_id),
                    ToolMetadata("result_digest", error.execution.evidence.semantic_result_digest),
                ),
                effect_disposition=ToolEffectDisposition.NO_EFFECT,
            )
        except (VMExecutionError, ValueError):
            return ToolResult.failure(
                ToolResultStatus.INTERNAL_FAILURE,
                "vm_operation_failed",
                "The trusted research operation could not complete",
                effect_disposition=ToolEffectDisposition.NO_EFFECT,
            )
        result = execution.result
        if not isinstance(result, ResearchSemanticResult):
            return ToolResult.failure(
                ToolResultStatus.INTERNAL_FAILURE,
                "operation_result_mismatch",
                "The trusted operation returned an unexpected result type",
                effect_disposition=ToolEffectDisposition.NO_EFFECT,
            )
        evidence = execution.evidence
        assert evidence.instance_id is not None
        assert evidence.instance_purpose is not None
        output = VMResearchOutput(
            operation_id=result.operation_id,
            semantic_result_type=result.semantic_result_type,
            input_digest=result.input_digest,
            result_digest=result.result_digest,
            character_count=result.character_count,
            line_count=result.line_count,
            word_count=result.word_count,
            normalized_digest=result.normalized_digest,
            semantic_status=result.semantic_status,
            trusted_verification_passed=result.verification_passed,
            environment=evidence.route.environment.value,
            provider=evidence.provider,
            instance_id=str(evidence.instance_id),
            instance_purpose=str(evidence.instance_purpose.value),
            guest_request_id=str(evidence.guest_request_id),
            exit_code=evidence.exit_code,
            host_bridge_operations=evidence.host_bridge_operations,
            cleanup_state=evidence.cleanup_state,
        )
        return ToolResult.success(output, evidence=_guest_operation_evidence(execution))


class VMBuildCheckTool(Tool[VMBuildCheckInput, VMBuildCheckOutput]):
    """Compile bounded Python source as data in a disposable test VM."""

    def __init__(self, service: VMExecutionService) -> None:
        self._service = service
        self._manifest = ToolManifest(
            tool_id="vm.coding",
            name="VM Coding Build Check",
            description="Statically compile bounded Python source in a disposable test VM.",
            version=SemanticVersion(1, 0, 0),
            capability_tags=frozenset({"vm", "vm_execution", "coding", "vm.coding"}),
            input_schema=VMBuildCheckInput,
            output_schema=VMBuildCheckOutput,
            declared_permissions=frozenset(),
            supported_platforms=frozenset(
                {ToolPlatform.WINDOWS, ToolPlatform.LINUX, ToolPlatform.MACOS}
            ),
            timeout_seconds=120.0,
            implementation_id="jarvis.vm.tools.VMBuildCheckTool",
        )

    @property
    def manifest(self) -> ToolManifest:
        return self._manifest

    @property
    def input_model(self) -> type[VMBuildCheckInput]:
        return VMBuildCheckInput

    async def _execute_authorized(
        self, context: ToolExecutionContext, validated_input: VMBuildCheckInput
    ) -> ToolResult:
        try:
            execution = await self._service.execute_operation(context.task_id, validated_input)
        except VMExecutionUnavailable as error:
            return ToolResult.failure(
                ToolResultStatus.UNAVAILABLE,
                "vm_unavailable",
                "The disposable test VM is unavailable; no host fallback was used",
                metadata=(ToolMetadata("route", error.evidence.route.environment.value),),
                effect_disposition=ToolEffectDisposition.NO_EFFECT,
            )
        except VMOperationSemanticError as error:
            return ToolResult.failure(
                ToolResultStatus.EXPECTED_FAILURE,
                "semantic_verification_failed",
                "The guest build result did not satisfy trusted verification",
                metadata=(
                    ToolMetadata("operation_id", error.execution.evidence.operation_id),
                    ToolMetadata("result_digest", error.execution.evidence.semantic_result_digest),
                ),
                effect_disposition=ToolEffectDisposition.NO_EFFECT,
            )
        except (VMExecutionError, ValueError):
            return ToolResult.failure(
                ToolResultStatus.INTERNAL_FAILURE,
                "vm_operation_failed",
                "The trusted build operation could not complete",
                effect_disposition=ToolEffectDisposition.NO_EFFECT,
            )
        result = execution.result
        if not isinstance(result, BuildCheckSemanticResult):
            return ToolResult.failure(
                ToolResultStatus.INTERNAL_FAILURE,
                "operation_result_mismatch",
                "The trusted operation returned an unexpected result type",
                effect_disposition=ToolEffectDisposition.NO_EFFECT,
            )
        evidence = execution.evidence
        assert evidence.instance_id is not None
        assert evidence.instance_purpose is not None
        output = VMBuildCheckOutput(
            operation_id=result.operation_id,
            semantic_result_type=result.semantic_result_type,
            input_digest=result.input_digest,
            result_digest=result.result_digest,
            valid=result.valid,
            error_type=result.error_type,
            error_line=result.error_line,
            error_offset=result.error_offset,
            semantic_status=result.semantic_status,
            trusted_verification_passed=result.verification_passed,
            environment=evidence.route.environment.value,
            provider=evidence.provider,
            instance_id=str(evidence.instance_id),
            instance_purpose=str(evidence.instance_purpose.value),
            guest_request_id=str(evidence.guest_request_id),
            exit_code=evidence.exit_code,
            host_bridge_operations=evidence.host_bridge_operations,
            cleanup_state=evidence.cleanup_state,
        )
        return ToolResult.success(output, evidence=_guest_operation_evidence(execution))


class HostFileWriteTool(Tool[HostFileWriteInput, HostFileWriteOutput]):
    """Trusted exact host-file transaction backed by PermissionBroker + HostBridge."""

    _ACTION = "host.file.write"

    def __init__(self, service: VMExecutionService) -> None:
        self._service = service
        self._manifest = ToolManifest(
            tool_id="vm.host_file.write",
            name="Scoped Host File Write",
            description="Writes one acceptance-owned host file after exact approval.",
            version=SemanticVersion(1, 0, 0),
            capability_tags=frozenset({"host_bridge", "filesystem", "host_file_write"}),
            input_schema=HostFileWriteInput,
            output_schema=HostFileWriteOutput,
            declared_permissions=frozenset({Permission.FILESYSTEM_WRITE}),
            supported_platforms=frozenset(
                {ToolPlatform.WINDOWS, ToolPlatform.LINUX, ToolPlatform.MACOS}
            ),
            timeout_seconds=30.0,
            implementation_id="jarvis.vm.tools.HostFileWriteTool",
        )

    @property
    def manifest(self) -> ToolManifest:
        return self._manifest

    @property
    def input_model(self) -> type[HostFileWriteInput]:
        return HostFileWriteInput

    def _describe_action(
        self, context: ToolExecutionContext, validated_input: HostFileWriteInput
    ) -> ActionDescriptor:
        resource = self._service.host_resource(validated_input.relative_path)
        scope = self._service.host_root
        permission = PermissionRequest(
            Permission.FILESYSTEM_WRITE,
            PermissionScope(
                paths=(str(resource),),
                tool_id=self.manifest.tool_id,
                task_id=context.task_id,
            ),
        )
        return build_host_bridge_action_descriptor(
            action=self._ACTION,
            operation=HostBridgeOperation.FILE_WRITE,
            resource=str(resource),
            scope=str(scope),
            risk=Risk.MEDIUM,
            permissions=(permission,),
        )

    async def _execute_authorized(
        self, context: ToolExecutionContext, validated_input: HostFileWriteInput
    ) -> ToolResult:
        receipt = context.authorization
        if receipt is None:
            return ToolResult.failure(
                ToolResultStatus.PERMISSION_DENIED,
                "missing_broker_receipt",
                "Host effects require a broker-issued execution receipt",
                effect_disposition=ToolEffectDisposition.NO_EFFECT,
            )
        try:
            evidence = await self._service.execute_host_write(
                context.task_id,
                ExecutionIntent(
                    "host_resource",
                    host_resource_dependency=True,
                    exact_host_mutation=True,
                    explicit_host_request=True,
                    risk="medium",
                ),
                validated_input.relative_path,
                validated_input.content,
                receipt,
                validated_input.model_dump(mode="json"),
                tool_id=self.manifest.tool_id,
                action=self._ACTION,
            )
        except (VMExecutionError, ValueError):
            return ToolResult.failure(
                ToolResultStatus.UNKNOWN_OUTCOME,
                "host_effect_outcome_unknown",
                "The host effect outcome is unknown; automatic replay is forbidden",
                effect_disposition=ToolEffectDisposition.UNKNOWN,
            )
        if not evidence.authorization.allowed:
            return ToolResult.failure(
                ToolResultStatus.PERMISSION_DENIED,
                "host_bridge_denied",
                "HostBridge denied the exact scoped request",
                effect_disposition=ToolEffectDisposition.NO_EFFECT,
            )
        return ToolResult.success(
            self._output(evidence),
            evidence=self._evidence(evidence),
        )

    @staticmethod
    def _output(evidence: HostWriteEvidence) -> HostFileWriteOutput:
        return HostFileWriteOutput(
            task_id=str(evidence.task_id),
            request_id=str(evidence.request.request_id),
            operation=evidence.request.operation.value,
            resource=evidence.resource,
            scope=evidence.scope,
            approval_identity=evidence.request.approval_identity or "",
            action_fingerprint=evidence.request.action_fingerprint or "",
            content_digest=evidence.content_digest,
            bytes_written=evidence.bytes_written,
            post_effect_verified=evidence.post_effect_verified,
        )

    @staticmethod
    def _evidence(evidence: HostWriteEvidence) -> tuple[ToolEvidence, ...]:
        return (
            ToolEvidence(
                "host_bridge_request",
                f"host_bridge_request_id={evidence.request.request_id}",
            ),
            ToolEvidence("host_bridge_operation", "host_bridge_operation=HOST_FILE_WRITE"),
            ToolEvidence("host_effect", "host_effect=approved_exact_write"),
            ToolEvidence("host_post_effect", "host_post_effect_verified=true"),
            ToolEvidence("host_resource", f"host_resource={evidence.resource}"),
            ToolEvidence("host_scope", f"host_scope={evidence.scope}"),
        )


def default_vm_tools(service: VMExecutionService) -> tuple[Tool[Any, Any], ...]:
    """Return the trusted generic VM/host adapters installed by runtime composition."""

    return (
        VMResearchTool(service),
        VMBuildCheckTool(service),
        GuestCommandTool(
            service,
            tool_id="vm.test",
            intent=ExecutionIntent("dependency_test"),
            description="Run a bounded isolated test command in a disposable VM.",
        ),
        GuestCommandTool(
            service,
            tool_id="vm.repair",
            intent=ExecutionIntent("repair"),
            description="Run a bounded repair command in a disposable repair VM.",
        ),
        HostFileWriteTool(service),
    )


__all__ = [
    "GuestCommandInput",
    "GuestCommandOutput",
    "GuestCommandTool",
    "VMBuildCheckInput",
    "VMBuildCheckOutput",
    "VMBuildCheckTool",
    "VMResearchInput",
    "VMResearchOutput",
    "VMResearchTool",
    "HostFileWriteInput",
    "HostFileWriteOutput",
    "HostFileWriteTool",
    "default_vm_tools",
]
