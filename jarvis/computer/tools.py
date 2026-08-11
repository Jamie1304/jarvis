"""Typed, brokered semantic computer capability tools."""

from __future__ import annotations

import hashlib
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator

from jarvis.computer.accessibility import AccessibilityAdapter
from jarvis.computer.adapters import ComputerAdapter, ComputerAdapterError
from jarvis.computer.artifacts import ScreenshotStore
from jarvis.computer.filesystem import FilesystemAdapter
from jarvis.computer.terminal import ControlledCommandService
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
    ToolResultError,
    ToolResultStatus,
)

_WINDOWS_ONLY = frozenset({ToolPlatform.WINDOWS})


class WindowOutput(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)

    window_id: int
    title: str
    process_id: int | None
    is_focused: bool


class DiscoverWindowsInput(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)

    title_contains: str | None = Field(default=None, max_length=128)


class DiscoverWindowsOutput(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)

    windows: tuple[WindowOutput, ...]


class AccessibilityNodeOutput(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)

    window_id: int
    automation_id: str | None
    name: str
    control_type: str
    left: int
    top: int
    width: int
    height: int
    value_fingerprint: str | None


class ReadAccessibilityInput(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)

    window_id: int | None = Field(default=None, gt=0)


class ReadAccessibilityOutput(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)

    nodes: tuple[AccessibilityNodeOutput, ...]


class LaunchApplicationInput(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)

    application_id: str = Field(min_length=1, max_length=64, pattern=r"^[a-z0-9][a-z0-9_.-]*$")


class LaunchApplicationOutput(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)

    application_id: str
    process_id: int


class FocusWindowInput(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)

    window_id: int = Field(gt=0)


class FocusWindowOutput(WindowOutput):
    pass


class SetTextInput(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)

    window_id: int = Field(gt=0)
    control_id: str = Field(min_length=1, max_length=128, pattern=r"^[A-Za-z0-9_.-]+$")
    text: str = Field(max_length=16_384)


class SetTextOutput(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)

    window_id: int
    control_id: str
    character_count: int


class MouseFallbackInput(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)

    x: int = Field(ge=0, le=16_384)
    y: int = Field(ge=0, le=16_384)
    button: Literal["left", "right"] = "left"
    fallback_reason: str = Field(min_length=1, max_length=256)


class MouseFallbackOutput(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)

    x: int
    y: int
    button: str
    used_fallback: bool = True


class CaptureScreenInput(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)


class CaptureScreenOutput(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)

    reference: str
    content_type: str
    width: int
    height: int
    captured_at: str
    content_fingerprint: str


class ClipboardReadInput(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)

    max_characters: int = Field(default=4096, ge=1, le=16_384)


class ClipboardReadOutput(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)

    text: str
    truncated: bool


class ClipboardWriteInput(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)

    text: str = Field(max_length=16_384)


class ClipboardWriteOutput(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)

    character_count: int


class ReadTextFileInput(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)

    path: str = Field(min_length=1, max_length=1024)
    max_characters: int = Field(default=16_384, ge=1, le=65_536)


class ReadTextFileOutput(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)

    path: str
    content: str
    truncated: bool


class ControlledCommandInput(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)

    command_id: str = Field(min_length=1, max_length=64, pattern=r"^[a-z0-9][a-z0-9_.-]*$")
    arguments: tuple[str, ...] = Field(default=(), max_length=32)
    working_directory: str = Field(min_length=1, max_length=1024)
    timeout_seconds: int = Field(default=30, ge=1, le=60)

    @field_validator("arguments")
    @classmethod
    def reject_unsafe_arguments(cls, arguments: tuple[str, ...]) -> tuple[str, ...]:
        if any("\x00" in argument or len(argument) > 2048 for argument in arguments):
            raise ValueError("Command arguments contain an unsafe value")
        return arguments


class ControlledCommandOutput(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)

    exit_code: int | None
    stdout: str
    stderr: str
    timed_out: bool
    cancelled: bool


def _window_output(
    window_id: int, title: str, process_id: int | None, focused: bool
) -> WindowOutput:
    return WindowOutput(
        window_id=window_id,
        title=title,
        process_id=process_id,
        is_focused=focused,
    )


def _authorized_path(context: ToolExecutionContext, permission: Permission) -> str:
    """Use the broker-normalized path, never the model's raw string."""

    receipt = context.authorization
    if receipt is None:
        raise RuntimeError("Computer tool ran without a broker receipt")
    for evaluation in receipt.evaluations:
        if evaluation.permission is permission and evaluation.normalized_scope is not None:
            paths = evaluation.normalized_scope.paths
            if len(paths) == 1:
                return paths[0]
    raise RuntimeError("Broker receipt did not contain one authorized path")


class DiscoverWindowsTool(Tool[DiscoverWindowsInput, DiscoverWindowsOutput]):
    def __init__(self, adapter: ComputerAdapter) -> None:
        self._adapter = adapter

    @property
    def manifest(self) -> ToolManifest:
        return ToolManifest(
            tool_id="computer.discover_windows",
            name="Discover windows",
            description="Find Windows application windows by a semantic title query.",
            version=SemanticVersion(1, 0, 0),
            capability_tags=frozenset({"computer", "window", "discovery"}),
            input_schema=DiscoverWindowsInput,
            output_schema=DiscoverWindowsOutput,
            declared_permissions=frozenset({Permission.SCREEN_READ}),
            supported_platforms=_WINDOWS_ONLY,
            timeout_seconds=5,
        )

    @property
    def input_model(self) -> type[DiscoverWindowsInput]:
        return DiscoverWindowsInput

    def _describe_action(
        self, context: ToolExecutionContext, validated_input: DiscoverWindowsInput
    ) -> ActionDescriptor:
        del context
        return ActionDescriptor(
            action="discover windows",
            arguments_summary=(
                SafeArgument(
                    "title_query",
                    "all windows"
                    if validated_input.title_contains is None
                    else f"provided ({len(validated_input.title_contains)} characters)",
                ),
            ),
            risk=Risk.MEDIUM,
            permissions=(PermissionRequest(Permission.SCREEN_READ, PermissionScope()),),
        )

    async def _execute_authorized(
        self, context: ToolExecutionContext, validated_input: DiscoverWindowsInput
    ) -> ToolResult:
        del context
        try:
            windows = await self._adapter.discover_windows(validated_input.title_contains)
        except ComputerAdapterError:
            return ToolResult.failure(
                ToolResultStatus.UNAVAILABLE,
                "computer_adapter_unavailable",
                "Window discovery adapter is unavailable",
            )
        output = DiscoverWindowsOutput(
            windows=tuple(
                _window_output(item.window_id, item.title, item.process_id, item.is_focused)
                for item in windows
            )
        )
        return ToolResult.success(
            output,
            evidence=(ToolEvidence("window_count", str(len(windows))),),
        )


class ReadAccessibilityTool(Tool[ReadAccessibilityInput, ReadAccessibilityOutput]):
    """Expose semantic UI state only after the same screen-read authorization."""

    def __init__(self, adapter: AccessibilityAdapter) -> None:
        self._adapter = adapter

    @property
    def manifest(self) -> ToolManifest:
        return ToolManifest(
            tool_id="computer.read_accessibility",
            name="Read accessibility tree",
            description="Read bounded semantic UI Automation controls for visual grounding.",
            version=SemanticVersion(1, 0, 0),
            capability_tags=frozenset({"computer", "screen", "accessibility"}),
            input_schema=ReadAccessibilityInput,
            output_schema=ReadAccessibilityOutput,
            declared_permissions=frozenset({Permission.SCREEN_READ}),
            supported_platforms=_WINDOWS_ONLY,
            timeout_seconds=10,
        )

    @property
    def input_model(self) -> type[ReadAccessibilityInput]:
        return ReadAccessibilityInput

    def _describe_action(
        self, context: ToolExecutionContext, validated_input: ReadAccessibilityInput
    ) -> ActionDescriptor:
        del context
        return ActionDescriptor(
            action="read accessibility tree",
            arguments_summary=(
                SafeArgument(
                    "window",
                    "desktop" if validated_input.window_id is None else "specified window",
                ),
            ),
            risk=Risk.MEDIUM,
            permissions=(PermissionRequest(Permission.SCREEN_READ, PermissionScope()),),
        )

    async def _execute_authorized(
        self, context: ToolExecutionContext, validated_input: ReadAccessibilityInput
    ) -> ToolResult:
        del context
        try:
            nodes = await self._adapter.read_accessibility(validated_input.window_id)
        except ComputerAdapterError:
            return ToolResult.failure(
                ToolResultStatus.UNAVAILABLE,
                "accessibility_unavailable",
                "Accessibility information is unavailable",
            )
        output = ReadAccessibilityOutput(
            nodes=tuple(
                AccessibilityNodeOutput(
                    window_id=node.window_id,
                    automation_id=node.automation_id,
                    name=node.name,
                    control_type=node.control_type,
                    left=node.left,
                    top=node.top,
                    width=node.width,
                    height=node.height,
                    value_fingerprint=node.value_fingerprint,
                )
                for node in nodes
            )
        )
        return ToolResult.success(
            output,
            evidence=(ToolEvidence("accessibility_node_count", str(len(nodes))),),
        )


class LaunchApplicationTool(Tool[LaunchApplicationInput, LaunchApplicationOutput]):
    def __init__(self, adapter: ComputerAdapter, applications: frozenset[str]) -> None:
        self._adapter = adapter
        self._applications = applications

    @property
    def manifest(self) -> ToolManifest:
        return ToolManifest(
            tool_id="computer.launch_application",
            name="Launch application",
            description="Launch one application from a trusted local catalog.",
            version=SemanticVersion(1, 0, 0),
            capability_tags=frozenset({"computer", "application", "launch"}),
            input_schema=LaunchApplicationInput,
            output_schema=LaunchApplicationOutput,
            declared_permissions=frozenset({Permission.APPLICATION_LAUNCH}),
            supported_platforms=_WINDOWS_ONLY,
            timeout_seconds=10,
        )

    @property
    def input_model(self) -> type[LaunchApplicationInput]:
        return LaunchApplicationInput

    def _describe_action(
        self, context: ToolExecutionContext, validated_input: LaunchApplicationInput
    ) -> ActionDescriptor:
        del context
        application = (
            validated_input.application_id
            if validated_input.application_id in self._applications
            else "unknown"
        )
        return ActionDescriptor(
            action="launch application",
            arguments_summary=(SafeArgument("application", application),),
            risk=Risk.HIGH,
            permissions=(
                PermissionRequest(
                    Permission.APPLICATION_LAUNCH,
                    PermissionScope(applications=(application,)),
                ),
            ),
        )

    async def _execute_authorized(
        self, context: ToolExecutionContext, validated_input: LaunchApplicationInput
    ) -> ToolResult:
        del context
        try:
            launched = await self._adapter.launch_application(validated_input.application_id)
        except ComputerAdapterError:
            return ToolResult.failure(
                ToolResultStatus.EXPECTED_FAILURE,
                "application_launch_failed",
                "The requested trusted application could not be launched",
            )
        output = LaunchApplicationOutput(
            application_id=launched.application_id,
            process_id=launched.process_id,
        )
        return ToolResult.success(
            output,
            evidence=(ToolEvidence("process_id", str(launched.process_id)),),
        )


class FocusWindowTool(Tool[FocusWindowInput, FocusWindowOutput]):
    def __init__(self, adapter: ComputerAdapter) -> None:
        self._adapter = adapter

    @property
    def manifest(self) -> ToolManifest:
        return ToolManifest(
            tool_id="computer.focus_window",
            name="Focus window",
            description="Focus a discovered application window.",
            version=SemanticVersion(1, 0, 0),
            capability_tags=frozenset({"computer", "window", "focus"}),
            input_schema=FocusWindowInput,
            output_schema=FocusWindowOutput,
            declared_permissions=frozenset({Permission.COMPUTER_INPUT}),
            supported_platforms=_WINDOWS_ONLY,
            timeout_seconds=5,
        )

    @property
    def input_model(self) -> type[FocusWindowInput]:
        return FocusWindowInput

    def _describe_action(
        self, context: ToolExecutionContext, validated_input: FocusWindowInput
    ) -> ActionDescriptor:
        del context
        return ActionDescriptor(
            action="focus window",
            arguments_summary=(SafeArgument("window_id", str(validated_input.window_id)),),
            risk=Risk.HIGH,
            permissions=(PermissionRequest(Permission.COMPUTER_INPUT, PermissionScope()),),
        )

    async def _execute_authorized(
        self, context: ToolExecutionContext, validated_input: FocusWindowInput
    ) -> ToolResult:
        del context
        try:
            window = await self._adapter.focus_window(validated_input.window_id)
        except ComputerAdapterError:
            return ToolResult.failure(
                ToolResultStatus.EXPECTED_FAILURE,
                "window_focus_failed",
                "The requested window could not be focused",
            )
        output = FocusWindowOutput(
            window_id=window.window_id,
            title=window.title,
            process_id=window.process_id,
            is_focused=window.is_focused,
        )
        return ToolResult.success(
            output,
            evidence=(ToolEvidence("focused_window", str(window.window_id)),),
        )


class SetTextTool(Tool[SetTextInput, SetTextOutput]):
    def __init__(self, adapter: ComputerAdapter) -> None:
        self._adapter = adapter

    @property
    def manifest(self) -> ToolManifest:
        return ToolManifest(
            tool_id="computer.set_text",
            name="Set text",
            description="Set text in an accessible control by semantic control ID.",
            version=SemanticVersion(1, 0, 0),
            capability_tags=frozenset({"computer", "keyboard", "accessibility"}),
            input_schema=SetTextInput,
            output_schema=SetTextOutput,
            declared_permissions=frozenset({Permission.COMPUTER_INPUT}),
            supported_platforms=_WINDOWS_ONLY,
            timeout_seconds=10,
        )

    @property
    def input_model(self) -> type[SetTextInput]:
        return SetTextInput

    def _describe_action(
        self, context: ToolExecutionContext, validated_input: SetTextInput
    ) -> ActionDescriptor:
        del context
        return ActionDescriptor(
            action="set text",
            arguments_summary=(
                SafeArgument("window_id", str(validated_input.window_id)),
                SafeArgument("control_id", validated_input.control_id),
                SafeArgument("character_count", str(len(validated_input.text))),
            ),
            risk=Risk.HIGH,
            permissions=(PermissionRequest(Permission.COMPUTER_INPUT, PermissionScope()),),
        )

    async def _execute_authorized(
        self, context: ToolExecutionContext, validated_input: SetTextInput
    ) -> ToolResult:
        del context
        try:
            state = await self._adapter.set_text(
                validated_input.window_id,
                validated_input.control_id,
                validated_input.text,
            )
        except ComputerAdapterError:
            return ToolResult.failure(
                ToolResultStatus.EXPECTED_FAILURE,
                "set_text_failed",
                "The accessible text control could not be updated",
            )
        output = SetTextOutput(
            window_id=state.window_id,
            control_id=state.control_id,
            character_count=len(validated_input.text),
        )
        return ToolResult.success(
            output,
            evidence=(
                ToolEvidence("control_id", state.control_id),
                ToolEvidence("text_character_count", str(len(validated_input.text))),
            ),
        )


class MouseFallbackTool(Tool[MouseFallbackInput, MouseFallbackOutput]):
    def __init__(self, adapter: ComputerAdapter) -> None:
        self._adapter = adapter

    @property
    def manifest(self) -> ToolManifest:
        return ToolManifest(
            tool_id="computer.mouse_fallback",
            name="Mouse fallback",
            description=(
                "Use a bounded coordinate click only when semantic automation is unavailable."
            ),
            version=SemanticVersion(1, 0, 0),
            capability_tags=frozenset({"computer", "mouse", "fallback"}),
            input_schema=MouseFallbackInput,
            output_schema=MouseFallbackOutput,
            declared_permissions=frozenset({Permission.COMPUTER_INPUT}),
            supported_platforms=_WINDOWS_ONLY,
            timeout_seconds=5,
        )

    @property
    def input_model(self) -> type[MouseFallbackInput]:
        return MouseFallbackInput

    def _describe_action(
        self, context: ToolExecutionContext, validated_input: MouseFallbackInput
    ) -> ActionDescriptor:
        del context
        return ActionDescriptor(
            action="mouse fallback click",
            arguments_summary=(
                SafeArgument("coordinates", f"{validated_input.x},{validated_input.y}"),
                SafeArgument("button", validated_input.button),
                SafeArgument("fallback_reason", "provided"),
            ),
            risk=Risk.HIGH,
            permissions=(PermissionRequest(Permission.COMPUTER_INPUT, PermissionScope()),),
        )

    async def _execute_authorized(
        self, context: ToolExecutionContext, validated_input: MouseFallbackInput
    ) -> ToolResult:
        del context
        try:
            state = await self._adapter.mouse_click(
                validated_input.x,
                validated_input.y,
                validated_input.button,
            )
        except ComputerAdapterError:
            return ToolResult.failure(
                ToolResultStatus.EXPECTED_FAILURE,
                "mouse_fallback_failed",
                "The coordinate fallback could not be performed",
            )
        output = MouseFallbackOutput(x=state.x, y=state.y, button=state.button)
        return ToolResult.success(
            output,
            evidence=(ToolEvidence("mouse_fallback", f"{state.x},{state.y}"),),
        )


class CaptureScreenTool(Tool[CaptureScreenInput, CaptureScreenOutput]):
    def __init__(self, adapter: ComputerAdapter, screenshots: ScreenshotStore) -> None:
        self._adapter = adapter
        self._screenshots = screenshots

    @property
    def manifest(self) -> ToolManifest:
        return ToolManifest(
            tool_id="computer.capture_screen",
            name="Capture screen",
            description="Capture the screen into trusted artifact storage.",
            version=SemanticVersion(1, 0, 0),
            capability_tags=frozenset({"computer", "screen", "capture"}),
            input_schema=CaptureScreenInput,
            output_schema=CaptureScreenOutput,
            declared_permissions=frozenset({Permission.SCREEN_READ}),
            supported_platforms=_WINDOWS_ONLY,
            timeout_seconds=10,
        )

    @property
    def input_model(self) -> type[CaptureScreenInput]:
        return CaptureScreenInput

    def _describe_action(
        self, context: ToolExecutionContext, validated_input: CaptureScreenInput
    ) -> ActionDescriptor:
        del context, validated_input
        return ActionDescriptor(
            action="capture screen",
            arguments_summary=(),
            risk=Risk.MEDIUM,
            permissions=(PermissionRequest(Permission.SCREEN_READ, PermissionScope()),),
        )

    async def _execute_authorized(
        self, context: ToolExecutionContext, validated_input: CaptureScreenInput
    ) -> ToolResult:
        del context, validated_input
        try:
            capture = await self._adapter.capture_screen()
            artifact = await self._screenshots.save(capture)
        except ComputerAdapterError:
            return ToolResult.failure(
                ToolResultStatus.UNAVAILABLE,
                "screen_capture_unavailable",
                "Screen capture adapter is unavailable",
            )
        output = CaptureScreenOutput(
            reference=artifact.reference,
            content_type=artifact.content_type,
            width=artifact.width,
            height=artifact.height,
            captured_at=artifact.captured_at.isoformat(),
            content_fingerprint=artifact.content_fingerprint,
        )
        return ToolResult.success(
            output,
            evidence=(ToolEvidence("screenshot_reference", artifact.reference),),
        )


class ReadClipboardTool(Tool[ClipboardReadInput, ClipboardReadOutput]):
    def __init__(self, adapter: ComputerAdapter) -> None:
        self._adapter = adapter

    @property
    def manifest(self) -> ToolManifest:
        return ToolManifest(
            tool_id="computer.read_clipboard",
            name="Read clipboard",
            description="Read bounded text from the local clipboard.",
            version=SemanticVersion(1, 0, 0),
            capability_tags=frozenset({"computer", "clipboard", "read"}),
            input_schema=ClipboardReadInput,
            output_schema=ClipboardReadOutput,
            declared_permissions=frozenset({Permission.CLIPBOARD_READ}),
            supported_platforms=_WINDOWS_ONLY,
            timeout_seconds=5,
        )

    @property
    def input_model(self) -> type[ClipboardReadInput]:
        return ClipboardReadInput

    def _describe_action(
        self, context: ToolExecutionContext, validated_input: ClipboardReadInput
    ) -> ActionDescriptor:
        del context
        return ActionDescriptor(
            action="read clipboard",
            arguments_summary=(
                SafeArgument("max_characters", str(validated_input.max_characters)),
            ),
            risk=Risk.MEDIUM,
            permissions=(PermissionRequest(Permission.CLIPBOARD_READ, PermissionScope()),),
        )

    async def _execute_authorized(
        self, context: ToolExecutionContext, validated_input: ClipboardReadInput
    ) -> ToolResult:
        del context
        try:
            text = await self._adapter.read_clipboard()
        except ComputerAdapterError:
            return ToolResult.failure(
                ToolResultStatus.EXPECTED_FAILURE,
                "clipboard_read_failed",
                "The clipboard could not be read",
            )
        output = ClipboardReadOutput(
            text=text[: validated_input.max_characters],
            truncated=len(text) > validated_input.max_characters,
        )
        return ToolResult.success(
            output,
            evidence=(ToolEvidence("clipboard_character_count", str(len(output.text))),),
        )


class WriteClipboardTool(Tool[ClipboardWriteInput, ClipboardWriteOutput]):
    def __init__(self, adapter: ComputerAdapter) -> None:
        self._adapter = adapter

    @property
    def manifest(self) -> ToolManifest:
        return ToolManifest(
            tool_id="computer.write_clipboard",
            name="Write clipboard",
            description="Write text to the local clipboard.",
            version=SemanticVersion(1, 0, 0),
            capability_tags=frozenset({"computer", "clipboard", "write"}),
            input_schema=ClipboardWriteInput,
            output_schema=ClipboardWriteOutput,
            declared_permissions=frozenset({Permission.CLIPBOARD_WRITE}),
            supported_platforms=_WINDOWS_ONLY,
            timeout_seconds=5,
        )

    @property
    def input_model(self) -> type[ClipboardWriteInput]:
        return ClipboardWriteInput

    def _describe_action(
        self, context: ToolExecutionContext, validated_input: ClipboardWriteInput
    ) -> ActionDescriptor:
        del context
        digest = hashlib.sha256(validated_input.text.encode("utf-8")).hexdigest()[:12]
        return ActionDescriptor(
            action="write clipboard",
            arguments_summary=(
                SafeArgument("character_count", str(len(validated_input.text))),
                SafeArgument("content_digest", digest),
            ),
            risk=Risk.HIGH,
            permissions=(PermissionRequest(Permission.CLIPBOARD_WRITE, PermissionScope()),),
        )

    async def _execute_authorized(
        self, context: ToolExecutionContext, validated_input: ClipboardWriteInput
    ) -> ToolResult:
        del context
        try:
            count = await self._adapter.write_clipboard(validated_input.text)
        except ComputerAdapterError:
            return ToolResult.failure(
                ToolResultStatus.EXPECTED_FAILURE,
                "clipboard_write_failed",
                "The clipboard could not be written",
            )
        output = ClipboardWriteOutput(character_count=count)
        return ToolResult.success(
            output,
            evidence=(ToolEvidence("clipboard_character_count", str(count)),),
        )


class ReadTextFileTool(Tool[ReadTextFileInput, ReadTextFileOutput]):
    def __init__(self, filesystem: FilesystemAdapter) -> None:
        self._filesystem = filesystem

    @property
    def manifest(self) -> ToolManifest:
        return ToolManifest(
            tool_id="computer.read_text_file",
            name="Read text file",
            description="Read bounded text from a broker-scoped file path.",
            version=SemanticVersion(1, 0, 0),
            capability_tags=frozenset({"computer", "filesystem", "read"}),
            input_schema=ReadTextFileInput,
            output_schema=ReadTextFileOutput,
            declared_permissions=frozenset({Permission.FILESYSTEM_READ}),
            supported_platforms=_WINDOWS_ONLY,
            timeout_seconds=10,
        )

    @property
    def input_model(self) -> type[ReadTextFileInput]:
        return ReadTextFileInput

    def _describe_action(
        self, context: ToolExecutionContext, validated_input: ReadTextFileInput
    ) -> ActionDescriptor:
        del context
        return ActionDescriptor(
            action="read text file",
            arguments_summary=(
                SafeArgument("path", validated_input.path),
                SafeArgument("max_characters", str(validated_input.max_characters)),
            ),
            risk=Risk.MEDIUM,
            permissions=(
                PermissionRequest(
                    Permission.FILESYSTEM_READ,
                    PermissionScope(paths=(validated_input.path,)),
                ),
            ),
        )

    async def _execute_authorized(
        self, context: ToolExecutionContext, validated_input: ReadTextFileInput
    ) -> ToolResult:
        try:
            path = _authorized_path(context, Permission.FILESYSTEM_READ)
            content = await self._filesystem.read_text(path, validated_input.max_characters + 1)
        except OSError:
            return ToolResult.failure(
                ToolResultStatus.EXPECTED_FAILURE,
                "filesystem_read_failed",
                "The authorized text file could not be read",
            )
        output = ReadTextFileOutput(
            path=path,
            content=content[: validated_input.max_characters],
            truncated=len(content) > validated_input.max_characters,
        )
        return ToolResult.success(
            output,
            evidence=(ToolEvidence("read_path", path),),
        )


class ControlledCommandTool(Tool[ControlledCommandInput, ControlledCommandOutput]):
    def __init__(self, service: ControlledCommandService) -> None:
        self._service = service

    @property
    def manifest(self) -> ToolManifest:
        return ToolManifest(
            tool_id="computer.execute_command",
            name="Execute controlled command",
            description="Run a trusted command ID with arguments through a no-shell adapter.",
            version=SemanticVersion(1, 0, 0),
            capability_tags=frozenset({"computer", "terminal", "controlled"}),
            input_schema=ControlledCommandInput,
            output_schema=ControlledCommandOutput,
            declared_permissions=frozenset({Permission.TERMINAL_EXECUTE}),
            supported_platforms=_WINDOWS_ONLY,
            timeout_seconds=65,
        )

    @property
    def input_model(self) -> type[ControlledCommandInput]:
        return ControlledCommandInput

    def _describe_action(
        self, context: ToolExecutionContext, validated_input: ControlledCommandInput
    ) -> ActionDescriptor:
        del context
        definition = self._service.describe(validated_input.command_id)
        family = definition.command_family if definition is not None else "unknown"
        safety_class = (
            definition.safety_class
            if definition is not None
            else SafetyClass.DESTRUCTIVE_SYSTEM_COMMAND
        )
        return ActionDescriptor(
            action="execute controlled command",
            arguments_summary=(
                SafeArgument("command_id", validated_input.command_id),
                SafeArgument("argument_count", str(len(validated_input.arguments))),
                SafeArgument("working_directory", "policy-normalized"),
                SafeArgument("timeout_seconds", str(validated_input.timeout_seconds)),
            ),
            risk=Risk.CRITICAL if safety_class is not SafetyClass.ORDINARY else Risk.HIGH,
            permissions=(
                PermissionRequest(
                    Permission.TERMINAL_EXECUTE,
                    PermissionScope(
                        paths=(validated_input.working_directory,),
                        command_families=(family,),
                        duration_seconds=validated_input.timeout_seconds,
                    ),
                ),
            ),
            safety_class=safety_class,
        )

    async def _execute_authorized(
        self, context: ToolExecutionContext, validated_input: ControlledCommandInput
    ) -> ToolResult:
        try:
            working_directory = _authorized_path(context, Permission.TERMINAL_EXECUTE)
            execution = await self._service.execute(
                validated_input.command_id,
                validated_input.arguments,
                working_directory,
                validated_input.timeout_seconds,
                context.cancellation,
            )
        except OSError:
            return ToolResult.failure(
                ToolResultStatus.EXPECTED_FAILURE,
                "command_start_failed",
                "The trusted command could not be started",
            )
        output = ControlledCommandOutput(
            exit_code=execution.exit_code,
            stdout=execution.stdout,
            stderr=execution.stderr,
            timed_out=execution.timed_out,
            cancelled=execution.cancelled,
        )
        if execution.cancelled:
            return ToolResult(
                status=ToolResultStatus.CANCELLED,
                output=output,
                error=ToolResultError("command_cancelled", "The controlled command was cancelled"),
            )
        if execution.rejected:
            return ToolResult.failure(
                ToolResultStatus.EXPECTED_FAILURE,
                "command_arguments_rejected",
                "The trusted command does not permit those arguments",
            )
        if execution.timed_out:
            return ToolResult(
                status=ToolResultStatus.TIMEOUT,
                output=output,
                error=ToolResultError(
                    "command_timeout",
                    "The controlled command exceeded its timeout",
                ),
            )
        return ToolResult.success(
            output,
            evidence=(
                ToolEvidence("command_exit_code", str(execution.exit_code)),
                ToolEvidence("command_id", validated_input.command_id),
            ),
        )
