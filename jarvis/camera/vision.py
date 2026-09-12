"""Explicit, short-lived handoff from camera frames to the existing vision provider."""

from uuid import UUID

from jarvis.camera.store import EphemeralFrameStore
from jarvis.vision.models import VisionAnalysis, VisionRequest, VisualSource
from jarvis.vision.providers import VisionProvider


class CameraVisionBridge:
    """Read one live frame for vision, then release it regardless of provider outcome."""

    def __init__(self, frames: EphemeralFrameStore, provider: VisionProvider) -> None:
        self._frames = frames
        self._provider = provider

    async def analyze(
        self,
        frame_id: str,
        *,
        task_id: UUID,
        task_objective: str,
    ) -> VisionAnalysis:
        del task_id
        frame = await self._frames.read(frame_id)
        if frame is None:
            raise ValueError("Camera frame is expired or has already been released")
        try:
            return await self._provider.observe(
                VisionRequest(
                    screenshot_id=frame_id,
                    dimensions=(frame.width, frame.height),
                    timestamp=frame.captured_at,
                    task_objective=task_objective,
                    accessibility_tree=(),
                    previous_observation=None,
                    source=VisualSource.CAMERA,
                )
            )
        finally:
            await self._frames.release(frame_id)
