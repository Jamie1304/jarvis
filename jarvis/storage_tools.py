"""Application-owned, bounded storage tools over the R3B foundations."""

from __future__ import annotations

from pathlib import Path

from pydantic import BaseModel, ConfigDict, Field

from jarvis.permissions.models import (
    ActionDescriptor,
    Permission,
    PermissionRequest,
    PermissionScope,
    Risk,
    SafeArgument,
)
from jarvis.storage import (
    FileSteward,
    MutationConflict,
    MutationDenied,
    MutationManifest,
    MutationUnknownOutcome,
    StalePlan,
    StorageInventoryService,
)
from jarvis.tools.base import Tool
from jarvis.tools.models import (
    SemanticVersion,
    ToolEffectDisposition,
    ToolEvidence,
    ToolExecutionContext,
    ToolManifest,
    ToolPlatform,
    ToolResult,
    ToolResultStatus,
)
from jarvis.vm.bridge import HostBridgeOperation, build_host_bridge_action_descriptor


class StorageInspectInput(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)

    path: str = Field(min_length=1, max_length=4096)


class StorageInspectOutput(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)

    path: str
    size_bytes: int
    content_hash: str
    is_directory: bool


class StorageInventoryInput(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)


class StorageInventoryOutput(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)

    volume_ids: tuple[str, ...]
    free_bytes: tuple[int | None, ...]


class StorageCopyInput(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)

    source: str = Field(min_length=1, max_length=4096)
    destination: str = Field(min_length=1, max_length=4096)
    max_affected_bytes: int | None = Field(default=None, ge=0)


class StorageCopyOutput(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)

    plan_id: str
    state: str
    source_hash: str
    destination_hash: str
    copied_bytes: int


class StorageInspectTool(Tool[StorageInspectInput, StorageInspectOutput]):
    def __init__(self, steward: FileSteward) -> None:
        self._steward = steward

    @property
    def manifest(self) -> ToolManifest:
        return ToolManifest(
            tool_id="storage.inspect",
            name="Inspect bounded storage",
            description="Inspect one file inside the application-owned storage root.",
            version=SemanticVersion(1, 0, 0),
            capability_tags=frozenset({"storage", "inspection"}),
            input_schema=StorageInspectInput,
            output_schema=StorageInspectOutput,
            declared_permissions=frozenset({Permission.FILESYSTEM_READ}),
            supported_platforms=frozenset(
                {ToolPlatform.WINDOWS, ToolPlatform.LINUX, ToolPlatform.MACOS}
            ),
            timeout_seconds=10,
        )

    @property
    def input_model(self) -> type[StorageInspectInput]:
        return StorageInspectInput

    def _describe_action(
        self, context: ToolExecutionContext, value: StorageInspectInput
    ) -> ActionDescriptor:
        del context
        return ActionDescriptor(
            action="storage.inspect",
            arguments_summary=(SafeArgument("path", value.path),),
            risk=Risk.LOW,
            permissions=(
                PermissionRequest(
                    Permission.FILESYSTEM_READ,
                    PermissionScope(paths=(str(self._steward.root),)),
                ),
            ),
        )

    async def _execute_authorized(
        self, context: ToolExecutionContext, value: StorageInspectInput
    ) -> ToolResult:
        del context
        try:
            identity = self._steward.inspect(Path(value.path))
        except Exception:
            return ToolResult.failure(
                ToolResultStatus.UNAVAILABLE,
                "storage_inspection_unavailable",
                "The requested storage observation is unavailable",
                effect_disposition=ToolEffectDisposition.NO_EFFECT,
            )
        output = StorageInspectOutput(
            path=value.path,
            size_bytes=identity.size_bytes,
            content_hash=identity.content_hash,
            is_directory=identity.is_directory,
        )
        return ToolResult.success(
            output,
            evidence=(
                ToolEvidence("storage.path", str(identity.size_bytes)),
                ToolEvidence("storage.hash", identity.content_hash),
            ),
        )


class StorageInventoryTool(Tool[StorageInventoryInput, StorageInventoryOutput]):
    def __init__(self, inventory: StorageInventoryService, root: Path) -> None:
        self._inventory = inventory
        self._root = root

    @property
    def manifest(self) -> ToolManifest:
        return ToolManifest(
            tool_id="storage.inventory",
            name="Inspect storage volumes",
            description="Inspect bounded metadata for currently observed storage volumes.",
            version=SemanticVersion(1, 0, 0),
            capability_tags=frozenset({"storage", "inventory"}),
            input_schema=StorageInventoryInput,
            output_schema=StorageInventoryOutput,
            declared_permissions=frozenset({Permission.FILESYSTEM_READ}),
            supported_platforms=frozenset(
                {ToolPlatform.WINDOWS, ToolPlatform.LINUX, ToolPlatform.MACOS}
            ),
            timeout_seconds=10,
        )

    @property
    def input_model(self) -> type[StorageInventoryInput]:
        return StorageInventoryInput

    def _describe_action(
        self, context: ToolExecutionContext, value: StorageInventoryInput
    ) -> ActionDescriptor:
        del context, value
        return ActionDescriptor(
            action="storage.inventory",
            arguments_summary=(),
            risk=Risk.LOW,
            permissions=(
                PermissionRequest(
                    Permission.FILESYSTEM_READ, PermissionScope(paths=(str(self._root),))
                ),
            ),
        )

    async def _execute_authorized(
        self, context: ToolExecutionContext, value: StorageInventoryInput
    ) -> ToolResult:
        del context, value
        try:
            observations = self._inventory.inspect()
        except Exception:
            return ToolResult.failure(
                ToolResultStatus.UNAVAILABLE,
                "storage_inventory_unavailable",
                "Storage inventory is unavailable",
                effect_disposition=ToolEffectDisposition.NO_EFFECT,
            )
        return ToolResult.success(
            StorageInventoryOutput(
                volume_ids=tuple(item.volume_id for item in observations),
                free_bytes=tuple(item.free_bytes for item in observations),
            ),
            evidence=(ToolEvidence("storage.inventory.observed", "storage.inventory.observed"),),
        )


class StorageCopyTool(Tool[StorageCopyInput, StorageCopyOutput]):
    """Plan and execute one exact copy through one registered tool authority."""

    def __init__(self, steward: FileSteward) -> None:
        self._steward = steward

    @property
    def manifest(self) -> ToolManifest:
        return ToolManifest(
            tool_id=FileSteward._TOOL_ID,
            name="Copy one bounded file",
            description="Copy one exact file within the application-owned storage root.",
            version=SemanticVersion(1, 0, 0),
            capability_tags=frozenset({"storage", "file", "copy"}),
            input_schema=StorageCopyInput,
            output_schema=StorageCopyOutput,
            declared_permissions=frozenset({Permission.FILESYSTEM_WRITE}),
            supported_platforms=frozenset(
                {ToolPlatform.WINDOWS, ToolPlatform.LINUX, ToolPlatform.MACOS}
            ),
            timeout_seconds=30,
        )

    @property
    def input_model(self) -> type[StorageCopyInput]:
        return StorageCopyInput

    def _manifest(self, context: ToolExecutionContext, value: StorageCopyInput) -> MutationManifest:
        source = Path(value.source).expanduser().resolve(strict=False)
        destination = Path(value.destination).expanduser().resolve(strict=False)
        existing = self._steward.manifests.find_planned_copy(context.task_id, source, destination)
        return existing or self._steward.plan_copy(
            source,
            destination,
            task_id=context.task_id,
            max_affected_bytes=value.max_affected_bytes,
        )

    def _describe_action(
        self, context: ToolExecutionContext, value: StorageCopyInput
    ) -> ActionDescriptor:
        manifest = self._manifest(context, value)
        return build_host_bridge_action_descriptor(
            action="storage.file.copy",
            operation=HostBridgeOperation.FILE_COPY,
            resource=f"manifest:{manifest.fingerprint}",
            scope=str(self._steward.root),
            risk=Risk.MEDIUM,
            permissions=(
                PermissionRequest(
                    Permission.FILESYSTEM_WRITE,
                    PermissionScope(paths=(str(self._steward.root),), task_id=context.task_id),
                ),
            ),
        )

    async def _execute_authorized(
        self, context: ToolExecutionContext, value: StorageCopyInput
    ) -> ToolResult:
        try:
            manifest = self._manifest(context, value)
            if context.authorization is None:
                return ToolResult.failure(
                    ToolResultStatus.PERMISSION_DENIED,
                    "missing_authorization_receipt",
                    "The storage copy requires a broker receipt",
                )
            result = await self._steward.execute_with_receipt_async(
                manifest,
                context.authorization,
                normalized_arguments=value.model_dump(mode="json"),
            )
            item = result.manifest.items[0]
            destination = self._steward.inspect(item.destination)  # type: ignore[arg-type]
            return ToolResult.success(
                StorageCopyOutput(
                    plan_id=str(result.manifest.plan_id),
                    state=result.state.value,
                    source_hash=item.expected.content_hash,
                    destination_hash=destination.content_hash,
                    copied_bytes=destination.size_bytes,
                ),
                evidence=(
                    ToolEvidence("storage.copy.completed", "storage.copy.completed"),
                    ToolEvidence("storage.copy.source_hash", "storage.copy.source_hash"),
                    ToolEvidence("storage.copy.destination_hash", "storage.copy.destination_hash"),
                ),
            )
        except (StalePlan, MutationConflict, MutationDenied) as error:
            return ToolResult.failure(
                ToolResultStatus.VALIDATION_ERROR,
                type(error).__name__.lower(),
                "The approved copy was rejected by current storage state",
                effect_disposition=ToolEffectDisposition.NO_EFFECT,
            )
        except MutationUnknownOutcome:
            return ToolResult.failure(
                ToolResultStatus.UNKNOWN_OUTCOME,
                "storage_copy_unknown_outcome",
                "The copy outcome is unknown and is quarantined",
            )


__all__ = ["StorageCopyTool", "StorageInspectTool", "StorageInventoryTool"]
