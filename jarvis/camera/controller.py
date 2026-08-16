"""Single-owner camera lifecycle controller with bounded capture and cleanup."""

from __future__ import annotations

import asyncio
from dataclasses import dataclass, field
from uuid import UUID

from jarvis.camera.models import (
    CameraCaptureCancelledError,
    CameraCaptureTimeoutError,
    CameraDevice,
    CameraFrame,
    CameraHealth,
    CameraProviderError,
    CameraState,
    CameraStatus,
)
from jarvis.camera.provider import CameraProvider, CameraSession
from jarvis.events import CameraStateChanged, EventBus, EventEnvelope, EventType


@dataclass(slots=True)
class CameraController:
    """Own the only active session and expose state for UI/application status."""

    provider: CameraProvider
    allowed_device_ids: frozenset[str]
    event_bus: EventBus | None = None
    _lock: asyncio.Lock = field(init=False, repr=False)
    _session: CameraSession | None = field(init=False, default=None, repr=False)
    _status: CameraStatus = field(init=False, repr=False)

    def __post_init__(self) -> None:
        self._lock = asyncio.Lock()
        self._session: CameraSession | None = None
        self._status = CameraStatus(CameraState.INACTIVE, None, "Camera is inactive")

    @property
    def status(self) -> CameraStatus:
        return self._status

    def _set_status(self, status: CameraStatus) -> None:
        self._status = status
        if self.event_bus is not None:
            self.event_bus.publish_nowait(
                EventEnvelope.create(
                    EventType.CAMERA_STATE_CHANGED,
                    CameraStateChanged(status.device_id or "unknown", status.state.value),
                    source="camera.controller",
                    correlation_id=UUID(int=0),
                )
            )

    async def list_devices(self) -> tuple[CameraDevice, ...]:
        try:
            return await self.provider.enumerate_devices()
        except CameraProviderError as error:
            self._set_status(CameraStatus(CameraState.ERROR, None, str(error)))
            raise

    async def health(self, device_id: str | None = None) -> CameraHealth:
        return await self.provider.health(device_id)

    async def capture_once(
        self,
        device_id: str,
        *,
        timeout_seconds: float,
        cancellation: asyncio.Event,
    ) -> CameraFrame:
        if device_id not in self.allowed_device_ids:
            self._set_status(
                CameraStatus(
                    CameraState.ERROR,
                    device_id,
                    "Camera device is not in the trusted application catalog",
                )
            )
            raise CameraProviderError("Camera device is not in the trusted application catalog")
        if timeout_seconds <= 0 or timeout_seconds > 60:
            raise ValueError("Camera capture timeout must be between one and sixty seconds")
        async with self._lock:
            session: CameraSession | None = None
            try:
                self._set_status(CameraStatus(CameraState.OPENING, device_id, "Opening camera"))
                session = await self.provider.open_device(device_id)
                self._session = session
                self._set_status(
                    CameraStatus(CameraState.ACTIVE, device_id, "Camera capture active")
                )
                return await self._capture_with_guards(session, timeout_seconds, cancellation)
            except asyncio.CancelledError as error:
                self._set_status(CameraStatus(CameraState.INACTIVE, device_id, "Capture cancelled"))
                raise CameraCaptureCancelledError("Camera capture was cancelled") from error
            except TimeoutError as error:
                self._set_status(
                    CameraStatus(CameraState.ERROR, device_id, "Camera capture timed out")
                )
                raise CameraCaptureTimeoutError("Camera capture timed out") from error
            except CameraProviderError as error:
                self._set_status(CameraStatus(CameraState.ERROR, device_id, str(error)))
                raise
            finally:
                self._session = None
                if session is not None:
                    try:
                        await session.close()
                        if self._status.state is CameraState.ACTIVE:
                            self._set_status(
                                CameraStatus(CameraState.INACTIVE, device_id, "Camera is inactive")
                            )
                    except Exception as error:
                        self._set_status(
                            CameraStatus(
                                CameraState.ERROR,
                                device_id,
                                "Camera handle cleanup failed",
                            )
                        )
                        if not isinstance(error, CameraProviderError):
                            # The diagnostic remains in trusted logs, never in a tool result.
                            pass
                elif self._status.state is CameraState.OPENING:
                    self._set_status(
                        CameraStatus(CameraState.ERROR, device_id, "Camera could not open")
                    )
                elif self._status.state is CameraState.ACTIVE:
                    self._set_status(
                        CameraStatus(CameraState.INACTIVE, device_id, "Camera is inactive")
                    )

    async def shutdown(self) -> None:
        async with self._lock:
            session = self._session
            self._session = None
            if session is not None:
                try:
                    await session.close()
                finally:
                    self._set_status(CameraStatus(CameraState.INACTIVE, None, "Camera shut down"))
            elif self._status.state is not CameraState.INACTIVE:
                self._set_status(CameraStatus(CameraState.INACTIVE, None, "Camera shut down"))

    async def _capture_with_guards(
        self,
        session: CameraSession,
        timeout_seconds: float,
        cancellation: asyncio.Event,
    ) -> CameraFrame:
        capture_task = asyncio.create_task(session.capture_frame(timeout_seconds, cancellation))
        cancellation_task = asyncio.create_task(cancellation.wait())
        try:
            done, _ = await asyncio.wait(
                {capture_task, cancellation_task},
                timeout=timeout_seconds,
                return_when=asyncio.FIRST_COMPLETED,
            )
            if cancellation_task in done:
                capture_task.cancel()
                await asyncio.gather(capture_task, return_exceptions=True)
                raise asyncio.CancelledError
            if capture_task not in done:
                capture_task.cancel()
                await asyncio.gather(capture_task, return_exceptions=True)
                raise TimeoutError
            return await capture_task
        finally:
            if not cancellation_task.done():
                cancellation_task.cancel()
            await asyncio.gather(cancellation_task, return_exceptions=True)
