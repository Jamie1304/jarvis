"""Explicit factory for optional brokered Windows computer tools."""

from typing import Any

from jarvis.computer.adapters import ComputerAdapter
from jarvis.computer.artifacts import ScreenshotStore
from jarvis.computer.filesystem import FilesystemAdapter
from jarvis.computer.terminal import ControlledCommandService
from jarvis.computer.tools import (
    CaptureScreenTool,
    ControlledCommandTool,
    DiscoverWindowsTool,
    FocusWindowTool,
    LaunchApplicationTool,
    MouseFallbackTool,
    ReadClipboardTool,
    ReadTextFileTool,
    SetTextTool,
    WriteClipboardTool,
)
from jarvis.tools.base import Tool


def create_computer_tools(
    *,
    adapter: ComputerAdapter,
    screenshots: ScreenshotStore,
    filesystem: FilesystemAdapter,
    commands: ControlledCommandService,
    applications: frozenset[str],
) -> tuple[Tool[Any, Any], ...]:
    """Return optional tools only when trusted composition supplies every adapter."""

    return (
        DiscoverWindowsTool(adapter),
        LaunchApplicationTool(adapter, applications),
        FocusWindowTool(adapter),
        SetTextTool(adapter),
        MouseFallbackTool(adapter),
        CaptureScreenTool(adapter, screenshots),
        ReadClipboardTool(adapter),
        WriteClipboardTool(adapter),
        ReadTextFileTool(filesystem),
        ControlledCommandTool(commands),
    )
