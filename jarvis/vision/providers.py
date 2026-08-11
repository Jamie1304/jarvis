"""Provider-neutral visual understanding contract."""

from abc import ABC, abstractmethod

from jarvis.vision.models import VisionAnalysis, VisionRequest


class VisionProvider(ABC):
    """Interpret a trusted screenshot reference, never authorize host actions."""

    @abstractmethod
    async def observe(self, request: VisionRequest) -> VisionAnalysis:
        """Return structured visual suggestions for one current desktop state."""
