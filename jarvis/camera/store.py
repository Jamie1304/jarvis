"""Non-persistent, expiring camera frame storage for trusted vision handoff."""

import asyncio
from abc import ABC, abstractmethod
from datetime import UTC, datetime, timedelta
from uuid import uuid4

from jarvis.camera.models import CameraFrame, CameraFrameArtifact


class EphemeralFrameStore(ABC):
    @abstractmethod
    async def save(
        self, device_id: str, frame: CameraFrame, ttl_seconds: float
    ) -> CameraFrameArtifact:
        """Keep a frame temporarily and return an opaque reference."""

    @abstractmethod
    async def read(self, reference: str) -> CameraFrame | None:
        """Read a live frame for trusted vision handoff."""

    @abstractmethod
    async def release(self, reference: str) -> None:
        """Delete the temporary frame immediately."""


class InMemoryFrameStore(EphemeralFrameStore):
    """Default store; frames never touch disk and expire or release explicitly."""

    def __init__(self) -> None:
        self._frames: dict[str, tuple[str, CameraFrame, datetime]] = {}
        self._lock = asyncio.Lock()

    async def save(
        self, device_id: str, frame: CameraFrame, ttl_seconds: float
    ) -> CameraFrameArtifact:
        if ttl_seconds <= 0:
            raise ValueError("Frame TTL must be positive")
        now = datetime.now(UTC)
        expires_at = now + timedelta(seconds=ttl_seconds)
        reference = f"camera-frame:{uuid4()}"
        async with self._lock:
            self._purge(now)
            self._frames[reference] = (device_id, frame, expires_at)
        return CameraFrameArtifact(
            reference,
            device_id,
            frame.width,
            frame.height,
            frame.captured_at,
            expires_at,
            frame.content_type,
        )

    async def read(self, reference: str) -> CameraFrame | None:
        async with self._lock:
            self._purge(datetime.now(UTC))
            item = self._frames.get(reference)
            return item[1] if item is not None else None

    async def release(self, reference: str) -> None:
        async with self._lock:
            self._frames.pop(reference, None)

    def _purge(self, now: datetime) -> None:
        expired = [
            reference for reference, (_, _, expires_at) in self._frames.items() if expires_at <= now
        ]
        for reference in expired:
            self._frames.pop(reference, None)
