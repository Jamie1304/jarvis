"""Strict brokered tools for controlled application management."""

from __future__ import annotations

from uuid import UUID

from pydantic import BaseModel, ConfigDict, Field, field_validator

from jarvis.applications.manager import ApplicationManager
from jarvis.applications.models import (
    ApplicationAmbiguousError,
    ApplicationManagerError,
    ApplicationRecord,
    InstallationOutcome,
    InstallationPlan,
    InstallationPlanError,
    InstallationPlanKind,
    PackageNotFoundError,
    PackageOperationError,
    VerificationError,
)
from jarvis.permissions.models import (
    ActionDescriptor,
    Permission,
    PermissionRequest,
    PermissionScope,
    Risk,
    SafeArgument,
    SafetyClass,
)
from jarvis.tools.base import Tool
from jarvis.tools.models import (
    SemanticVersion,
    ToolEvidence,
    ToolExecutionContext,
    ToolManifest,
    ToolPlatform,
    ToolResult,
    ToolResultStatus,
)

_WINDOWS_ONLY = frozenset({ToolPlatform.WINDOWS})


class _StrictModel(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)


class ApplicationQueryInput(_StrictModel):
    name: str = Field(min_length=1, max_length=128)

    @field_validator("name")
    @classmethod
    def validate_name(cls, value: str) -> str:
        if value != value.strip() or "\x00" in value:
            raise ValueError("Application name must be a bounded non-empty label")
        return value


class ApplicationIdInput(_StrictModel):
    application_id: str = Field(pattern=r"^[a-z0-9][a-z0-9._:-]{0,127}$")


class ApplicationCloseInput(ApplicationIdInput):
    process_id: int = Field(gt=0)


class PlanExecutionInput(_StrictModel):
    plan_id: UUID


class ApplicationOutput(_StrictModel):
    application_id: str
    name: str
    version: str | None
    publisher: str | None
    executable_path: str | None
    installation_source: str
    status: str


class FindApplicationOutput(_StrictModel):
    status: str
    candidates: tuple[ApplicationOutput, ...]


class InstallationPlanOutput(_StrictModel):
    outcome: str
    plan_id: UUID | None
    kind: str | None
    package_id: str | None
    source: str | None
    publisher: str | None
    version: str | None
    reason_for_selection: str | None
    confidence: float | None
    verification_name: str | None
    verification_publisher: str | None
    already_installed: ApplicationOutput | None


class InstallationOutput(_StrictModel):
    kind: str
    application: ApplicationOutput
    launch_verified: bool
    already_present: bool


class LaunchApplicationOutput(_StrictModel):
    application_id: str
    process_id: int


class CloseApplicationOutput(_StrictModel):
    application_id: str
    process_id: int
    closed: bool


class FindApplicationTool(Tool[ApplicationQueryInput, FindApplicationOutput]):
    def __init__(self, manager: ApplicationManager) -> None:
        self._manager = manager

    @property
    def manifest(self) -> ToolManifest:
        return ToolManifest(
            "application.find",
            "Find installed application",
            "Find installed applications by semantic name without launching them.",
            SemanticVersion(1, 0, 0),
            frozenset({"application", "inventory", "discover"}),
            ApplicationQueryInput,
            FindApplicationOutput,
            frozenset(),
            _WINDOWS_ONLY,
            10,
        )

    @property
    def input_model(self) -> type[ApplicationQueryInput]:
        return ApplicationQueryInput

    async def _execute_authorized(
        self, context: ToolExecutionContext, validated_input: ApplicationQueryInput
    ) -> ToolResult:
        del context
        try:
            result = await self._manager.find(validated_input.name)
        except ApplicationManagerError:
            return _failure(
                "application_inventory_failed", "Installed application inventory is unavailable"
            )
        output = FindApplicationOutput(
            status=result.status.value,
            candidates=tuple(_application_output(item) for item in result.candidates),
        )
        return ToolResult.success(
            output,
            evidence=(ToolEvidence("match_count", str(len(result.candidates))),),
        )


class PlanInstallTool(Tool[ApplicationQueryInput, InstallationPlanOutput]):
    """Plan discovery only; it deliberately has no package-manager side effect."""

    def __init__(self, manager: ApplicationManager) -> None:
        self._manager = manager

    @property
    def manifest(self) -> ToolManifest:
        return ToolManifest(
            "application.plan_install",
            "Plan application installation",
            "Create an immutable installation plan or report an existing verified install.",
            SemanticVersion(1, 0, 0),
            frozenset({"application", "install", "plan"}),
            ApplicationQueryInput,
            InstallationPlanOutput,
            frozenset(),
            _WINDOWS_ONLY,
            10,
        )

    @property
    def input_model(self) -> type[ApplicationQueryInput]:
        return ApplicationQueryInput

    async def _execute_authorized(
        self, context: ToolExecutionContext, validated_input: ApplicationQueryInput
    ) -> ToolResult:
        del context
        try:
            plan, existing = await self._manager.plan_install(validated_input.name)
        except ApplicationAmbiguousError:
            return _failure("application_ambiguous", "Application or package search is ambiguous")
        except PackageNotFoundError:
            return _failure("package_not_found", "No package candidate was found")
        except ApplicationManagerError:
            return _failure("installation_plan_failed", "Installation plan could not be created")
        if existing is not None:
            return ToolResult.success(
                InstallationPlanOutput(
                    outcome="already_installed",
                    plan_id=None,
                    kind=None,
                    package_id=None,
                    source=None,
                    publisher=None,
                    version=None,
                    reason_for_selection=None,
                    confidence=None,
                    verification_name=None,
                    verification_publisher=None,
                    already_installed=_application_output(existing),
                ),
                evidence=(ToolEvidence("application_id", existing.application_id),),
            )
        assert plan is not None
        return ToolResult.success(
            _plan_output(plan), evidence=(ToolEvidence("plan_id", str(plan.plan_id)),)
        )


class PlanUpdateTool(Tool[ApplicationIdInput, InstallationPlanOutput]):
    def __init__(self, manager: ApplicationManager) -> None:
        self._manager = manager

    @property
    def manifest(self) -> ToolManifest:
        return ToolManifest(
            "application.plan_update",
            "Plan application update",
            "Create an immutable update plan; updates are separate from fresh installs.",
            SemanticVersion(1, 0, 0),
            frozenset({"application", "update", "plan"}),
            ApplicationIdInput,
            InstallationPlanOutput,
            frozenset(),
            _WINDOWS_ONLY,
            10,
        )

    @property
    def input_model(self) -> type[ApplicationIdInput]:
        return ApplicationIdInput

    async def _execute_authorized(
        self, context: ToolExecutionContext, validated_input: ApplicationIdInput
    ) -> ToolResult:
        del context
        try:
            plan = await self._manager.plan_update(validated_input.application_id)
        except PackageNotFoundError:
            return _failure("update_not_available", "No safe update candidate is available")
        except (ApplicationManagerError, VerificationError):
            return _failure("update_plan_failed", "Update plan could not be created")
        return ToolResult.success(
            _plan_output(plan), evidence=(ToolEvidence("plan_id", str(plan.plan_id)),)
        )


class _PlanExecutionTool(Tool[PlanExecutionInput, InstallationOutput]):
    _kind: str
    _tool_id: str
    _action: str

    def __init__(self, manager: ApplicationManager) -> None:
        self._manager = manager

    @property
    def manifest(self) -> ToolManifest:
        return ToolManifest(
            self._tool_id,
            f"{self._kind.title()} application",
            "Execute one immutable application package plan after trusted-user approval.",
            SemanticVersion(1, 0, 0),
            frozenset({"application", self._kind}),
            PlanExecutionInput,
            InstallationOutput,
            frozenset({Permission.APPLICATION_INSTALL}),
            _WINDOWS_ONLY,
            180,
        )

    @property
    def input_model(self) -> type[PlanExecutionInput]:
        return PlanExecutionInput

    def _describe_action(
        self, context: ToolExecutionContext, validated_input: PlanExecutionInput
    ) -> ActionDescriptor:
        del context
        plan = self._manager.plan_for_descriptor(validated_input.plan_id)
        candidate = plan.candidate if plan is not None and plan.kind.value == self._kind else None
        package = candidate.package_id if candidate is not None else "unknown"
        source = candidate.source if candidate is not None else "unknown"
        version = candidate.version if candidate is not None else "unknown"
        publisher = candidate.publisher or "unknown" if candidate is not None else "unknown"
        return ActionDescriptor(
            self._action,
            (
                SafeArgument("plan_id", str(validated_input.plan_id)),
                SafeArgument("package_id", package),
                SafeArgument("source", source),
                SafeArgument("publisher", publisher),
                SafeArgument("version", version),
            ),
            Risk.CRITICAL,
            (
                PermissionRequest(
                    Permission.APPLICATION_INSTALL,
                    PermissionScope(applications=(package,)),
                ),
            ),
            SafetyClass.SOFTWARE_INSTALLATION,
        )

    async def _execute_authorized(
        self, context: ToolExecutionContext, validated_input: PlanExecutionInput
    ) -> ToolResult:
        try:
            outcome = await self._manager.execute_plan(
                validated_input.plan_id,
                InstallationPlanKind(self._kind),
                context.cancellation,
            )
        except InstallationPlanError:
            return _failure(
                "installation_plan_unavailable", "Installation plan is expired or already used"
            )
        except PackageOperationError:
            return _failure(
                "package_operation_failed", "Package provider could not complete the operation"
            )
        except VerificationError:
            return _failure("installation_verification_failed", "Installed package did not verify")
        except ApplicationManagerError:
            return _failure("installation_failed", "Application installation failed")
        return ToolResult.success(
            _installation_output(outcome),
            evidence=(
                ToolEvidence("application_id", outcome.record.application_id),
                ToolEvidence("version", outcome.record.version or "unknown"),
                ToolEvidence("launch_verified", str(outcome.launch_verified).lower()),
            ),
        )


class InstallApplicationTool(_PlanExecutionTool):
    _kind = "install"
    _tool_id = "application.install"
    _action = "install application"


class UpdateApplicationTool(_PlanExecutionTool):
    _kind = "update"
    _tool_id = "application.update"
    _action = "update application"


class LaunchManagedApplicationTool(Tool[ApplicationIdInput, LaunchApplicationOutput]):
    def __init__(self, manager: ApplicationManager) -> None:
        self._manager = manager

    @property
    def manifest(self) -> ToolManifest:
        return ToolManifest(
            "application.launch",
            "Launch managed application",
            "Launch a current managed inventory record, never a caller executable path.",
            SemanticVersion(1, 0, 0),
            frozenset({"application", "launch"}),
            ApplicationIdInput,
            LaunchApplicationOutput,
            frozenset({Permission.APPLICATION_LAUNCH}),
            _WINDOWS_ONLY,
            15,
        )

    @property
    def input_model(self) -> type[ApplicationIdInput]:
        return ApplicationIdInput

    def _describe_action(
        self, context: ToolExecutionContext, validated_input: ApplicationIdInput
    ) -> ActionDescriptor:
        del context
        return ActionDescriptor(
            "launch managed application",
            (SafeArgument("application_id", validated_input.application_id),),
            Risk.HIGH,
            (
                PermissionRequest(
                    Permission.APPLICATION_LAUNCH,
                    PermissionScope(applications=(validated_input.application_id,)),
                ),
            ),
        )

    async def _execute_authorized(
        self, context: ToolExecutionContext, validated_input: ApplicationIdInput
    ) -> ToolResult:
        del context
        try:
            launched = await self._manager.launch(validated_input.application_id)
        except ApplicationManagerError:
            return _failure(
                "application_launch_failed", "Managed application could not be launched"
            )
        return ToolResult.success(
            LaunchApplicationOutput(
                application_id=launched.application_id,
                process_id=launched.process_id,
            ),
            evidence=(ToolEvidence("process_id", str(launched.process_id)),),
        )


class CloseManagedApplicationTool(Tool[ApplicationCloseInput, CloseApplicationOutput]):
    def __init__(self, manager: ApplicationManager) -> None:
        self._manager = manager

    @property
    def manifest(self) -> ToolManifest:
        return ToolManifest(
            "application.close",
            "Close managed application",
            "Close only an application process previously launched by the managed runtime.",
            SemanticVersion(1, 0, 0),
            frozenset({"application", "close"}),
            ApplicationCloseInput,
            CloseApplicationOutput,
            frozenset({Permission.APPLICATION_LAUNCH}),
            _WINDOWS_ONLY,
            15,
        )

    @property
    def input_model(self) -> type[ApplicationCloseInput]:
        return ApplicationCloseInput

    def _describe_action(
        self, context: ToolExecutionContext, validated_input: ApplicationCloseInput
    ) -> ActionDescriptor:
        del context
        return ActionDescriptor(
            "close managed application",
            (
                SafeArgument("application_id", validated_input.application_id),
                SafeArgument("process_id", str(validated_input.process_id)),
            ),
            Risk.HIGH,
            (
                PermissionRequest(
                    Permission.APPLICATION_LAUNCH,
                    PermissionScope(applications=(validated_input.application_id,)),
                ),
            ),
        )

    async def _execute_authorized(
        self, context: ToolExecutionContext, validated_input: ApplicationCloseInput
    ) -> ToolResult:
        del context
        try:
            await self._manager.close(validated_input.application_id, validated_input.process_id)
        except ApplicationManagerError:
            return _failure("application_close_failed", "Managed application could not be closed")
        return ToolResult.success(
            CloseApplicationOutput(
                application_id=validated_input.application_id,
                process_id=validated_input.process_id,
                closed=True,
            ),
            evidence=(ToolEvidence("closed_process_id", str(validated_input.process_id)),),
        )


def _application_output(record: ApplicationRecord) -> ApplicationOutput:
    return ApplicationOutput(
        application_id=record.application_id,
        name=record.name,
        version=record.version,
        publisher=record.publisher,
        executable_path=record.executable_path,
        installation_source=record.installation_source,
        status=record.status.value,
    )


def _plan_output(plan: InstallationPlan) -> InstallationPlanOutput:
    candidate = plan.candidate
    return InstallationPlanOutput(
        outcome="plan_created",
        plan_id=plan.plan_id,
        kind=plan.kind.value,
        package_id=candidate.package_id,
        source=candidate.source,
        publisher=candidate.publisher,
        version=candidate.version,
        reason_for_selection=candidate.reason_for_selection,
        confidence=candidate.confidence,
        verification_name=candidate.verification.application_name,
        verification_publisher=candidate.verification.publisher,
        already_installed=None,
    )


def _installation_output(outcome: InstallationOutcome) -> InstallationOutput:
    return InstallationOutput(
        kind=outcome.kind.value,
        application=_application_output(outcome.record),
        launch_verified=outcome.launch_verified,
        already_present=outcome.already_present,
    )


def _failure(code: str, message: str) -> ToolResult:
    return ToolResult.failure(ToolResultStatus.EXPECTED_FAILURE, code, message)
