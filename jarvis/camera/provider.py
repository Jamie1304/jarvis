"""Provider-neutral camera hardware contract and optional OpenCV Windows adapter."""

from __future__ import annotations

import asyncio
import sys
from abc import ABC, abstractmethod
from datetime import UTC, datetime
from importlib import import_module
from typing import Any

from jarvis.camera.models import (
    CameraBusyError,
    CameraCaptureTimeoutError,
    CameraDevice,
    CameraDeviceNotFoundError,
    CameraFrame,
    CameraHealth,
    CameraHealthState,
    CameraProviderError,
)


class CameraSession(ABC):
    """One opened device; close is required and must be idempotent.

    ``capture_frame`` owns the native read until it returns. Providers must not
    return early merely because the asyncio caller was cancelled: many native
    reads cannot be force-cancelled safely.
    """

    @property
    @abstractmethod
    def device_id(self) -> str:
        """Return the trusted device identifier."""

    @abstractmethod
    async def capture_frame(
        self, timeout_seconds: float, cancellation: asyncio.Event
    ) -> CameraFrame:
        """Capture one bounded frame."""

    async def start_stream(self) -> None:
        """Optional provider lifecycle; agent tools never expose this method."""

        raise CameraProviderError("Streaming is not enabled by the controlled camera tools")

    async def stop_stream(self) -> None:
        """Optional provider lifecycle hook."""

        raise CameraProviderError("Streaming is not enabled by the controlled camera tools")

    @abstractmethod
    async def close(self) -> None:
        """Release every hardware handle."""


class CameraProvider(ABC):
    """Platform/model-neutral camera provider abstraction."""

    @abstractmethod
    async def enumerate_devices(self) -> tuple[CameraDevice, ...]:
        """Enumerate devices without leaving any device opened."""

    @abstractmethod
    async def open_device(self, device_id: str) -> CameraSession:
        """Open one selected device."""

    @abstractmethod
    async def health(self, device_id: str | None = None) -> CameraHealth:
        """Return provider/device health without starting a stream."""


class OpenCvCameraProvider(CameraProvider):  # pragma: no cover
    """Optional Windows-first OpenCV provider; hardware tests remain opt-in."""

    def __init__(
        self, *, probe_count: int = 4, allowed_device_ids: frozenset[str] | None = None
    ) -> None:
        if probe_count < 1 or probe_count > 16:
            raise ValueError("Camera probe count must be between one and sixteen")
        self._probe_count = probe_count
        self._allowed_device_ids = allowed_device_ids

    async def enumerate_devices(self) -> tuple[CameraDevice, ...]:
        return await asyncio.to_thread(self._enumerate_devices)

    async def open_device(self, device_id: str) -> CameraSession:
        return await asyncio.to_thread(self._open_device, device_id)

    async def health(self, device_id: str | None = None) -> CameraHealth:
        if device_id is None:
            devices = await self.enumerate_devices()
            return CameraHealth(
                None,
                CameraHealthState.AVAILABLE if devices else CameraHealthState.UNAVAILABLE,
                "Device probe completed",
            )
        try:
            session = await asyncio.to_thread(self._open_device, device_id)
            await session.close()
        except CameraProviderError as error:
            return CameraHealth(device_id, CameraHealthState.UNAVAILABLE, str(error))
        return CameraHealth(device_id, CameraHealthState.AVAILABLE, "Device opened successfully")

    @staticmethod
    def _cv2() -> Any:
        if sys.platform != "win32":
            raise CameraProviderError("OpenCV camera provider is supported on Windows only")
        try:
            return import_module("cv2")
        except ImportError as error:
            raise CameraProviderError(
                "OpenCV camera dependencies are unavailable; install the camera extra"
            ) from error

    def _enumerate_devices(self) -> tuple[CameraDevice, ...]:
        cv2 = self._cv2()
        devices: list[CameraDevice] = []
        for index in range(self._probe_count):
            capture = cv2.VideoCapture(index, cv2.CAP_DSHOW)
            try:
                if capture.isOpened():
                    devices.append(CameraDevice(str(index), f"Windows camera {index}", "opencv"))
            finally:
                capture.release()
        return tuple(devices)

    def _open_device(self, device_id: str) -> CameraSession:
        cv2 = self._cv2()
        try:
            index = int(device_id)
        except ValueError as error:
            raise CameraDeviceNotFoundError(
                "Camera device is not in the trusted catalog"
            ) from error
        if (
            index < 0
            or index >= self._probe_count
            or (self._allowed_device_ids is not None and device_id not in self._allowed_device_ids)
        ):
            raise CameraDeviceNotFoundError("Camera device is not in the trusted catalog")
        capture = cv2.VideoCapture(index, cv2.CAP_DSHOW)
        if not capture.isOpened():
            capture.release()
            raise CameraBusyError("Camera device is unavailable or already in use")
        return _OpenCvCameraSession(device_id, capture, cv2)


class _OpenCvCameraSession(CameraSession):  # pragma: no cover
    def __init__(self, device_id: str, capture: Any, cv2: Any) -> None:
        self._device_id = device_id
        self._capture = capture
        self._cv2_module = cv2
        self._closed = False

    @property
    def device_id(self) -> str:
        return self._device_id

    async def capture_frame(
        self, timeout_seconds: float, cancellation: asyncio.Event
    ) -> CameraFrame:
        if cancellation.is_set():
            raise asyncio.CancelledError
        read_task = asyncio.create_task(asyncio.to_thread(self._capture.read))
        cancelled_task = asyncio.create_task(cancellation.wait())
        try:
            done, _ = await asyncio.wait(
                {read_task, cancelled_task},
                timeout=timeout_seconds,
                return_when=asyncio.FIRST_COMPLETED,
            )
            if cancelled_task in done:
                # A native read running in a worker thread cannot be safely
                # force-cancelled. Wait for ownership to return before the
                # controller is allowed to close the device.
                await read_task
                raise asyncio.CancelledError
            if read_task not in done:
                await read_task
                raise CameraCaptureTimeoutError("Camera did not return a frame in time")
            success, frame = await read_task
        finally:
            if not cancelled_task.done():
                cancelled_task.cancel()
            await asyncio.gather(cancelled_task, return_exceptions=True)
        if cancellation.is_set():
            raise asyncio.CancelledError
        if not success:
            raise CameraCaptureTimeoutError("Camera did not return a frame")
        encoded, data = self._cv2_module.imencode(".jpg", frame)
        if not encoded:
            raise CameraProviderError("Camera frame encoding failed")
        height, width = frame.shape[:2]
        return CameraFrame(data.tobytes(), int(width), int(height), datetime.now(UTC))

    async def close(self) -> None:
        if not self._closed:
            self._closed = True
            await asyncio.to_thread(self._capture.release)
