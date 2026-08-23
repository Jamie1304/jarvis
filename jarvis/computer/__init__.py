"""Controlled Windows computer capability layer; no tools are auto-registered."""

from jarvis.computer.accessibility import (
    AccessibilityAdapter,
    AccessibilityNode,
    WindowsAccessibilityAdapter,
)
from jarvis.computer.adapters import (
    ComputerAdapter,
    ComputerAdapterError,
    WindowsUiAutomationAdapter,
)
from jarvis.computer.artifacts import InMemoryScreenshotStore, ScreenshotStore
from jarvis.computer.catalog import create_computer_tools
from jarvis.computer.filesystem import FilesystemAdapter, LocalFilesystemAdapter
from jarvis.computer.process import (
    ProcessIdentityError,
    resolve_trusted_executable,
    trusted_process_environment,
)
from jarvis.computer.terminal import (
    CommandAdapter,
    ControlledCommandService,
    SubprocessCommandAdapter,
)

__all__ = [
    "CommandAdapter",
    "AccessibilityAdapter",
    "AccessibilityNode",
    "ComputerAdapter",
    "ComputerAdapterError",
    "ControlledCommandService",
    "FilesystemAdapter",
    "InMemoryScreenshotStore",
    "LocalFilesystemAdapter",
    "ProcessIdentityError",
    "ScreenshotStore",
    "SubprocessCommandAdapter",
    "resolve_trusted_executable",
    "trusted_process_environment",
    "WindowsUiAutomationAdapter",
    "WindowsAccessibilityAdapter",
    "create_computer_tools",
]
