"""Brokered one-shot camera tools; streaming is deliberately not an agent capability."""

from pydantic import BaseModel, ConfigDict, Field

from jarvis.camera.controller import CameraController
from jarvis.camera.models import (
    CameraCaptureCancelledError,
    CameraCaptureTimeoutError,
    CameraProviderError,
    CameraState,
)
from jarvis.camera.store import EphemeralFrameStore
from jarvis.permissions.models import (
    ActionDescriptor,
    Permission,
    PermissionRequest,
    PermissionScope,
    Risk,
    SafeArgument,
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


class CameraListInput(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)


class CameraDeviceOutput(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)

    device_id: str
    label: str
    driver: str


class CameraListOutput(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)

    devices: tuple[CameraDeviceOutput, ...]
    state: CameraState
    active_device_id: str | None


class CameraCaptureInput(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)

    device_id: str = Field(min_length=1, max_length=64, pattern=r"^[A-Za-z0-9_.:-]+$")
    timeout_seconds: int = Field(default=10, ge=1, le=60)


class CameraCaptureOutput(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)

    frame_id: str
    device_id: str
    width: int
    height: int
    captured_at: str
    expires_at: str
    content_type: str


class CameraListTool(Tool[CameraListInput, CameraListOutput]):
    def __init__(self, controller: CameraController) -> None:
        self._controller = controller

    @property
    def manifest(self) -> ToolManifest:
        return ToolManifest(
            tool_id="camera.list",
            name="List cameras",
            description="Enumerate camera devices without opening a persistent session.",
            version=SemanticVersion(1, 0, 0),
            capability_tags=frozenset({"camera", "discovery"}),
            input_schema=CameraListInput,
            output_schema=CameraListOutput,
            declared_permissions=frozenset({Permission.CAMERA_READ}),
            supported_platforms=_WINDOWS_ONLY,
            timeout_seconds=10,
        )

    @property
    def input_model(self) -> type[CameraListInput]:
        return CameraListInput

    def _describe_action(
        self, context: ToolExecutionContext, validated_input: CameraListInput
    ) -> ActionDescriptor:
        del context, validated_input
        return ActionDescriptor(
            action="list cameras",
            arguments_summary=(),
            risk=Risk.MEDIUM,
            permissions=(PermissionRequest(Permission.CAMERA_READ, PermissionScope()),),
        )

    async def _execute_authorized(
        self, context: ToolExecutionContext, validated_input: CameraListInput
    ) -> ToolResult:
        del context, validated_input
        try:
            devices = await self._controller.list_devices()
        except CameraProviderError:
            return ToolResult.failure(
                ToolResultStatus.UNAVAILABLE,
                "camera_enumeration_failed",
                "Camera devices could not be enumerated",
            )
        status = self._controller.status
        output = CameraListOutput(
            devices=tuple(
                CameraDeviceOutput(
                    device_id=device.device_id,
                    label=device.label,
                    driver=device.driver,
                )
                for device in devices
            ),
            state=status.state,
            active_device_id=status.device_id,
        )
        return ToolResult.success(
            output,
            evidence=(ToolEvidence("camera_state", status.state.value),),
        )


class CameraCaptureTool(Tool[CameraCaptureInput, CameraCaptureOutput]):
    def __init__(self, controller: CameraController, frames: EphemeralFrameStore) -> None:
        self._controller = controller
        self._frames = frames

    @property
    def manifest(self) -> ToolManifest:
        return ToolManifest(
            tool_id="camera.capture",
            name="Capture camera frame",
            description="Open one trusted camera, capture one bounded frame, and close it.",
            version=SemanticVersion(1, 0, 0),
            capability_tags=frozenset({"camera", "capture"}),
            input_schema=CameraCaptureInput,
            output_schema=CameraCaptureOutput,
            declared_permissions=frozenset({Permission.CAMERA_READ}),
            supported_platforms=_WINDOWS_ONLY,
            timeout_seconds=65,
        )

    @property
    def input_model(self) -> type[CameraCaptureInput]:
        return CameraCaptureInput

    def _describe_action(
        self, context: ToolExecutionContext, validated_input: CameraCaptureInput
    ) -> ActionDescriptor:
        del context
        device = (
            validated_input.device_id
            if validated_input.device_id in self._controller.allowed_device_ids
            else "unknown"
        )
        return ActionDescriptor(
            action="capture camera frame",
            arguments_summary=(
                SafeArgument("device", device),
                SafeArgument("timeout_seconds", str(validated_input.timeout_seconds)),
            ),
            risk=Risk.HIGH,
            permissions=(PermissionRequest(Permission.CAMERA_READ, PermissionScope()),),
        )

    async def _execute_authorized(
        self, context: ToolExecutionContext, validated_input: CameraCaptureInput
    ) -> ToolResult:
        try:
            frame = await self._controller.capture_once(
                validated_input.device_id,
                timeout_seconds=validated_input.timeout_seconds,
                cancellation=context.cancellation,
            )
            artifact = await self._frames.save(
                validated_input.device_id,
                frame,
                ttl_seconds=30,
            )
        except CameraCaptureTimeoutError:
            return ToolResult.failure(
                ToolResultStatus.TIMEOUT,
                "camera_capture_timeout",
                "Camera capture exceeded its timeout",
            )
        except CameraCaptureCancelledError:
            return ToolResult.failure(
                ToolResultStatus.CANCELLED,
                "camera_capture_cancelled",
                "Camera capture was cancelled",
            )
        except CameraProviderError:
            return ToolResult.failure(
                ToolResultStatus.EXPECTED_FAILURE,
                "camera_capture_failed",
                "Camera frame could not be captured",
            )
        output = CameraCaptureOutput(
            frame_id=artifact.reference,
            device_id=artifact.device_id,
            width=artifact.width,
            height=artifact.height,
            captured_at=artifact.captured_at.isoformat(),
            expires_at=artifact.expires_at.isoformat(),
            content_type=artifact.content_type,
        )
        return ToolResult.success(
            output,
            evidence=(
                ToolEvidence("camera_state", self._controller.status.state.value),
                ToolEvidence("temporary_frame", artifact.reference),
            ),
        )
