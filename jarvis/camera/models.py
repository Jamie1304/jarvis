"""Typed camera state, device, frame, and health records."""

from dataclasses import dataclass
from datetime import datetime
from enum import StrEnum


class CameraState(StrEnum):
    INACTIVE = "inactive"
    OPENING = "opening"
    ACTIVE = "active"
    ERROR = "error"


class CameraHealthState(StrEnum):
    AVAILABLE = "available"
    UNAVAILABLE = "unavailable"
    UNKNOWN = "unknown"


class CameraProviderError(RuntimeError):
    """Expected provider failure with no raw hardware details exposed to callers."""


class CameraBusyError(CameraProviderError):
    """The selected device is already owned by another process/session."""


class CameraDeviceNotFoundError(CameraProviderError):
    """The requested trusted device is absent or disconnected."""


class CameraCaptureTimeoutError(CameraProviderError):
    """A bounded frame capture exceeded its timeout."""


class CameraCaptureCancelledError(CameraProviderError):
    """Capture was cancelled and the session was cleaned up."""


@dataclass(frozen=True, slots=True)
class CameraDevice:
    device_id: str
    label: str
    driver: str


@dataclass(frozen=True, slots=True)
class CameraHealth:
    device_id: str | None
    state: CameraHealthState
    detail: str


@dataclass(frozen=True, slots=True)
class CameraFrame:
    """Provider-owned bytes; callers must hand them to an ephemeral store."""

    data: bytes
    width: int
    height: int
    captured_at: datetime
    content_type: str = "image/jpeg"

    def __post_init__(self) -> None:
        if not self.data or self.width <= 0 or self.height <= 0:
            raise ValueError("Camera frames require bytes and positive dimensions")


@dataclass(frozen=True, slots=True)
class CameraFrameArtifact:
    reference: str
    device_id: str
    width: int
    height: int
    captured_at: datetime
    expires_at: datetime
    content_type: str


@dataclass(frozen=True, slots=True)
class CameraStatus:
    state: CameraState
    device_id: str | None
    detail: str
