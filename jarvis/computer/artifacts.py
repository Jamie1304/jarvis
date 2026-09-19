"""Secure references for screenshots; binary content stays below the tool boundary."""

from abc import ABC, abstractmethod
from hashlib import sha256
from uuid import uuid4

from jarvis.computer.models import CapturedScreen, ScreenshotArtifact


class ScreenshotStore(ABC):
    """Trusted store for screen bytes; tool results expose only metadata/reference."""

    @abstractmethod
    async def save(self, capture: CapturedScreen) -> ScreenshotArtifact:
        """Persist a capture and return its opaque reference."""


class InMemoryScreenshotStore(ScreenshotStore):
    """Deterministic test store; production must replace it with protected storage."""

    def __init__(self) -> None:
        self._captures: dict[str, CapturedScreen] = {}

    async def save(self, capture: CapturedScreen) -> ScreenshotArtifact:
        reference = f"screenshot:{uuid4()}"
        self._captures[reference] = capture
        return ScreenshotArtifact(
            reference=reference,
            width=capture.width,
            height=capture.height,
            captured_at=capture.captured_at,
            content_fingerprint=sha256(capture.png_bytes).hexdigest(),
        )

    def metadata(self, reference: str) -> ScreenshotArtifact | None:
        capture = self._captures.get(reference)
        if capture is None:
            return None
        return ScreenshotArtifact(
            reference=reference,
            width=capture.width,
            height=capture.height,
            captured_at=capture.captured_at,
            content_fingerprint=sha256(capture.png_bytes).hexdigest(),
        )
