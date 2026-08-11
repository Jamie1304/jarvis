"""Explicit factory for optional brokered camera tools."""

from typing import Any

from jarvis.camera.controller import CameraController
from jarvis.camera.store import EphemeralFrameStore
from jarvis.camera.tools import CameraCaptureTool, CameraListTool
from jarvis.tools.base import Tool


def create_camera_tools(
    *, controller: CameraController, frames: EphemeralFrameStore
) -> tuple[Tool[Any, Any], ...]:
    """Return one-shot camera tools only when trusted composition supplies both services."""

    return (CameraListTool(controller), CameraCaptureTool(controller, frames))
