"""Adapter protocols and optional Windows UI Automation implementation."""

import asyncio
import io
import subprocess
import sys
from abc import ABC, abstractmethod
from collections.abc import Mapping
from importlib import import_module
from typing import Any

from jarvis.computer.models import (
    ApplicationDefinition,
    CapturedScreen,
    ControlState,
    LaunchInfo,
    MouseActionState,
    WindowInfo,
)


class ComputerAdapterError(RuntimeError):
    """Expected host-adapter failure that never carries raw system exceptions."""


class ComputerAdapter(ABC):
    """Platform-neutral semantic computer operations used by brokered tools."""

    @abstractmethod
    async def discover_windows(self, title_contains: str | None) -> tuple[WindowInfo, ...]:
        """Find top-level windows by semantic title criteria."""

    @abstractmethod
    async def launch_application(self, application_id: str) -> LaunchInfo:
        """Launch one trusted catalog application."""

    @abstractmethod
    async def focus_window(self, window_id: int) -> WindowInfo:
        """Focus an existing window and return its observed state."""

    @abstractmethod
    async def set_text(self, window_id: int, control_id: str, text: str) -> ControlState:
        """Set an accessible control's text by semantic control identifier."""

    @abstractmethod
    async def mouse_click(self, x: int, y: int, button: str) -> MouseActionState:
        """Perform the deliberately explicit coordinate fallback."""

    @abstractmethod
    async def capture_screen(self) -> CapturedScreen:
        """Capture one screen image for the artifact store."""

    @abstractmethod
    async def read_clipboard(self) -> str:
        """Read text clipboard content."""

    @abstractmethod
    async def write_clipboard(self, text: str) -> int:
        """Write text clipboard content and return the character count."""


class WindowsUiAutomationAdapter(ComputerAdapter):  # pragma: no cover
    """Optional Windows UI Automation adapter backed by pywinauto/Pillow.

    Dependencies are imported lazily so deterministic CI and non-Windows hosts do
    not require desktop libraries. Applications are resolved from a trusted catalog;
    untrusted planner input cannot become an arbitrary executable.
    """

    def __init__(self, applications: Mapping[str, ApplicationDefinition]) -> None:
        self._applications = dict(applications)

    async def discover_windows(self, title_contains: str | None) -> tuple[WindowInfo, ...]:
        return await asyncio.to_thread(self._discover_windows, title_contains)

    async def launch_application(self, application_id: str) -> LaunchInfo:
        return await asyncio.to_thread(self._launch_application, application_id)

    async def focus_window(self, window_id: int) -> WindowInfo:
        return await asyncio.to_thread(self._focus_window, window_id)

    async def set_text(self, window_id: int, control_id: str, text: str) -> ControlState:
        return await asyncio.to_thread(self._set_text, window_id, control_id, text)

    async def mouse_click(self, x: int, y: int, button: str) -> MouseActionState:
        return await asyncio.to_thread(self._mouse_click, x, y, button)

    async def capture_screen(self) -> CapturedScreen:
        return await asyncio.to_thread(self._capture_screen)

    async def read_clipboard(self) -> str:
        return await asyncio.to_thread(self._read_clipboard)

    async def write_clipboard(self, text: str) -> int:
        return await asyncio.to_thread(self._write_clipboard, text)

    @staticmethod
    def _require_windows() -> None:
        if sys.platform != "win32":
            raise ComputerAdapterError("Windows UI Automation is available only on Windows")

    @staticmethod
    def _desktop() -> Any:
        WindowsUiAutomationAdapter._require_windows()
        try:
            desktop_class = import_module("pywinauto").Desktop
        except ImportError as error:
            raise ComputerAdapterError(
                "Windows automation dependencies are unavailable; install the windows extra"
            ) from error
        return desktop_class(backend="uia")

    def _discover_windows(self, title_contains: str | None) -> tuple[WindowInfo, ...]:
        query = title_contains.casefold() if title_contains else None
        windows: list[WindowInfo] = []
        for window in self._desktop().windows():
            title = str(window.window_text())
            if query and query not in title.casefold():
                continue
            windows.append(
                WindowInfo(
                    window_id=int(window.handle),
                    title=title,
                    process_id=int(window.process_id()),
                    is_focused=False,
                )
            )
        return tuple(windows)

    def _launch_application(self, application_id: str) -> LaunchInfo:
        self._require_windows()
        try:
            application = self._applications[application_id]
        except KeyError as error:
            raise ComputerAdapterError(
                "Application is not in the trusted launch catalog"
            ) from error
        try:
            process = subprocess.Popen(
                [application.executable, *application.default_arguments],
                shell=False,
                stdin=subprocess.DEVNULL,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
            )
        except OSError as error:
            raise ComputerAdapterError("Application could not be launched") from error
        return LaunchInfo(application.application_id, process.pid)

    def _focus_window(self, window_id: int) -> WindowInfo:
        window = self._desktop().window(handle=window_id)
        try:
            window.set_focus()
            return WindowInfo(
                window_id=window_id,
                title=str(window.window_text()),
                process_id=int(window.process_id()),
                is_focused=True,
            )
        except Exception as error:
            raise ComputerAdapterError("Window could not be focused") from error

    def _set_text(self, window_id: int, control_id: str, text: str) -> ControlState:
        window = self._desktop().window(handle=window_id)
        try:
            control = window.child_window(auto_id=control_id, control_type="Edit")
            control.set_edit_text(text)
            return ControlState(window_id=window_id, control_id=control_id, value=text)
        except Exception as error:
            raise ComputerAdapterError("Accessible text control could not be updated") from error

    def _mouse_click(self, x: int, y: int, button: str) -> MouseActionState:
        self._require_windows()
        try:
            mouse = import_module("pywinauto.mouse")
            mouse.click(button=button, coords=(x, y))
        except (ImportError, OSError) as error:
            raise ComputerAdapterError("Mouse fallback could not be performed") from error
        return MouseActionState(x=x, y=y, button=button)

    def _capture_screen(self) -> CapturedScreen:
        self._require_windows()
        try:
            image_grab = import_module("PIL.ImageGrab")
        except ImportError as error:
            raise ComputerAdapterError(
                "Screen capture dependencies are unavailable; install the windows extra"
            ) from error
        try:
            image = image_grab.grab()
            buffer = io.BytesIO()
            image.save(buffer, format="PNG")
        except OSError as error:
            raise ComputerAdapterError("Screen capture could not be performed") from error
        from datetime import UTC, datetime

        return CapturedScreen(
            png_bytes=buffer.getvalue(),
            width=int(image.width),
            height=int(image.height),
            captured_at=datetime.now(UTC),
        )

    def _read_clipboard(self) -> str:
        self._require_windows()
        try:
            win32clipboard = import_module("win32clipboard")

            win32clipboard.OpenClipboard()
            try:
                value = win32clipboard.GetClipboardData(win32clipboard.CF_UNICODETEXT)
            finally:
                win32clipboard.CloseClipboard()
        except (ImportError, OSError) as error:
            raise ComputerAdapterError("Clipboard could not be read") from error
        return str(value)

    def _write_clipboard(self, text: str) -> int:
        self._require_windows()
        try:
            win32clipboard = import_module("win32clipboard")

            win32clipboard.OpenClipboard()
            try:
                win32clipboard.EmptyClipboard()
                win32clipboard.SetClipboardText(text, win32clipboard.CF_UNICODETEXT)
            finally:
                win32clipboard.CloseClipboard()
        except (ImportError, OSError) as error:
            raise ComputerAdapterError("Clipboard could not be written") from error
        return len(text)
