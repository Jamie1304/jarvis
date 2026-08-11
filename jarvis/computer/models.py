"""Platform-neutral records for controlled computer capabilities."""

from dataclasses import dataclass, field
from datetime import datetime

from jarvis.permissions.models import SafetyClass


@dataclass(frozen=True, slots=True)
class WindowInfo:
    window_id: int
    title: str
    process_id: int | None
    is_focused: bool


@dataclass(frozen=True, slots=True)
class ApplicationDefinition:
    """Trusted launch configuration; model input refers only to application_id."""

    application_id: str
    executable: str
    default_arguments: tuple[str, ...] = ()


@dataclass(frozen=True, slots=True)
class LaunchInfo:
    application_id: str
    process_id: int


@dataclass(frozen=True, slots=True)
class ControlState:
    window_id: int
    control_id: str
    value: str | None = None


@dataclass(frozen=True, slots=True)
class MouseActionState:
    x: int
    y: int
    button: str


@dataclass(frozen=True, slots=True)
class CapturedScreen:
    """Adapter-private screen bytes; only the artifact store may retain them."""

    png_bytes: bytes
    width: int
    height: int
    captured_at: datetime


@dataclass(frozen=True, slots=True)
class ScreenshotArtifact:
    reference: str
    width: int
    height: int
    captured_at: datetime
    content_type: str = "image/png"


@dataclass(frozen=True, slots=True)
class CommandDefinition:
    """Trusted command catalog entry with exact permitted argument sequences."""

    command_id: str
    executable: str
    command_family: str
    allowed_argument_sequences: frozenset[tuple[str, ...]] = field(
        default_factory=lambda: frozenset({()})
    )
    safety_class: SafetyClass = SafetyClass.DESTRUCTIVE_SYSTEM_COMMAND


@dataclass(frozen=True, slots=True)
class CommandExecution:
    exit_code: int | None
    stdout: str
    stderr: str
    timed_out: bool = False
    cancelled: bool = False
    rejected: bool = False
