"""Read-only accessibility contracts used by the controlled computer layer."""

import asyncio
import hashlib
import sys
from abc import ABC, abstractmethod
from dataclasses import dataclass
from importlib import import_module
from typing import Any

from jarvis.computer.adapters import ComputerAdapterError


@dataclass(frozen=True, slots=True)
class AccessibilityNode:
    """A bounded semantic UI fact; control values are represented only by a digest."""

    window_id: int
    automation_id: str | None
    name: str
    control_type: str
    left: int
    top: int
    width: int
    height: int
    value_fingerprint: str | None = None


class AccessibilityAdapter(ABC):
    """Read-only semantic UI information for the brokered screen-read tool."""

    @abstractmethod
    async def read_accessibility(self, window_id: int | None) -> tuple[AccessibilityNode, ...]:
        """Return semantic controls for one window or the current desktop."""


class WindowsAccessibilityAdapter(AccessibilityAdapter):  # pragma: no cover
    """Optional UI Automation reader with lazy Windows-only dependencies."""

    _MAX_NODES = 512

    async def read_accessibility(self, window_id: int | None) -> tuple[AccessibilityNode, ...]:
        return await asyncio.to_thread(self._read_accessibility, window_id)

    @staticmethod
    def _desktop() -> Any:
        if sys.platform != "win32":
            raise ComputerAdapterError("Windows accessibility is available only on Windows")
        try:
            desktop_class = import_module("pywinauto").Desktop
        except ImportError as error:
            raise ComputerAdapterError(
                "Windows automation dependencies are unavailable; install the windows extra"
            ) from error
        return desktop_class(backend="uia")

    def _read_accessibility(self, window_id: int | None) -> tuple[AccessibilityNode, ...]:
        desktop = self._desktop()
        try:
            windows = (
                (desktop.window(handle=window_id),)
                if window_id is not None
                else tuple(desktop.windows())
            )
            nodes: list[AccessibilityNode] = []
            for window in windows:
                for control in window.descendants()[: self._MAX_NODES - len(nodes)]:
                    info = control.element_info
                    rectangle = info.rectangle
                    value = getattr(info, "value", None)
                    value_fingerprint = (
                        hashlib.sha256(str(value).encode("utf-8")).hexdigest()
                        if value is not None
                        else None
                    )
                    nodes.append(
                        AccessibilityNode(
                            window_id=int(window.handle),
                            automation_id=str(info.automation_id) or None,
                            name=str(info.name)[:256],
                            control_type=str(info.control_type)[:64],
                            left=int(rectangle.left),
                            top=int(rectangle.top),
                            width=max(0, int(rectangle.width())),
                            height=max(0, int(rectangle.height())),
                            value_fingerprint=value_fingerprint,
                        )
                    )
                    if len(nodes) >= self._MAX_NODES:
                        return tuple(nodes)
            return tuple(nodes)
        except Exception as error:
            raise ComputerAdapterError("Accessibility information could not be read") from error
