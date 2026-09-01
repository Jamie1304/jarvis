"""Strict visual-state records; provider output is never execution authority."""

import math
from dataclasses import dataclass
from datetime import datetime
from enum import StrEnum
from uuid import UUID

from jarvis.computer.accessibility import AccessibilityNode


class TargetSource(StrEnum):
    VISION = "vision"
    ACCESSIBILITY = "accessibility"
    FUSED = "fused"


class VisualSource(StrEnum):
    SCREEN = "screen"
    CAMERA = "camera"


class ActionIntent(StrEnum):
    FOCUS = "focus"
    SET_TEXT = "set_text"
    CLICK_FALLBACK = "click_fallback"


class VerificationStatus(StrEnum):
    SUCCESS = "success"
    FAILURE = "failure"
    UNCERTAIN = "uncertain"


class InteractionStatus(StrEnum):
    SUCCESS = "success"
    FAILURE = "failure"
    UNCERTAIN = "uncertain"
    STALE_OBSERVATION = "stale_observation"
    ACTION_DENIED = "action_denied"


@dataclass(frozen=True, slots=True)
class NormalizedBounds:
    """A target rectangle in the current screenshot's normalized [0, 1] space."""

    x: float
    y: float
    width: float
    height: float

    def __post_init__(self) -> None:
        values = (self.x, self.y, self.width, self.height)
        if any(
            type(value) not in {int, float} or not math.isfinite(float(value)) for value in values
        ):
            raise ValueError("Normalized bounds must be numeric")
        if self.width <= 0 or self.height <= 0 or self.x < 0 or self.y < 0:
            raise ValueError("Normalized bounds must be non-negative with positive dimensions")
        if self.x + self.width > 1 or self.y + self.height > 1:
            raise ValueError("Normalized bounds must fit within the screenshot")

    @property
    def center(self) -> tuple[float, float]:
        return (self.x + self.width / 2, self.y + self.height / 2)


@dataclass(frozen=True, slots=True)
class DisplayGeometry:
    """Trusted screenshot/desktop geometry needed for safe coordinate conversion."""

    screenshot_width: int
    screenshot_height: int
    physical_width: int
    physical_height: int
    dpi_scale_x: float
    dpi_scale_y: float

    def __post_init__(self) -> None:
        if (
            min(
                self.screenshot_width,
                self.screenshot_height,
                self.physical_width,
                self.physical_height,
            )
            <= 0
        ):
            raise ValueError("Display dimensions must be positive")
        if self.dpi_scale_x <= 0 or self.dpi_scale_y <= 0:
            raise ValueError("DPI scale must be positive")
        if abs(self.physical_width / self.screenshot_width - self.dpi_scale_x) > 0.01:
            raise ValueError("Horizontal DPI scale does not match display dimensions")
        if abs(self.physical_height / self.screenshot_height - self.dpi_scale_y) > 0.01:
            raise ValueError("Vertical DPI scale does not match display dimensions")

    def physical_point(self, bounds: NormalizedBounds) -> tuple[int, int]:
        x, y = bounds.center
        return (
            min(self.physical_width - 1, max(0, round(x * self.physical_width))),
            min(self.physical_height - 1, max(0, round(y * self.physical_height))),
        )


@dataclass(frozen=True, slots=True)
class ActiveWindow:
    window_id: int
    title: str
    process_id: int | None


@dataclass(frozen=True, slots=True)
class VisibleElement:
    label: str
    role: str
    bounds: NormalizedBounds
    confidence: float

    def __post_init__(self) -> None:
        if (
            type(self.label) is not str
            or type(self.role) is not str
            or not self.label.strip()
            or not self.role.strip()
            or type(self.confidence) not in {int, float}
            or not math.isfinite(float(self.confidence))
            or not 0 <= self.confidence <= 1
        ):
            raise ValueError("Visible elements require bounded labels, roles, and confidence")


@dataclass(frozen=True, slots=True)
class VisionCandidate:
    """Provider suggestion that is later assigned a trusted target ID by fusion."""

    label: str
    role: str
    bounds: NormalizedBounds
    confidence: float

    def __post_init__(self) -> None:
        if (
            type(self.label) is not str
            or type(self.role) is not str
            or not self.label.strip()
            or not self.role.strip()
            or type(self.confidence) not in {int, float}
            or not math.isfinite(float(self.confidence))
            or not 0 <= self.confidence <= 1
        ):
            raise ValueError("Vision candidates require bounded labels, roles, and confidence")


@dataclass(frozen=True, slots=True)
class CandidateTarget:
    target_id: str
    label: str
    role: str
    bounds: NormalizedBounds
    confidence: float
    source: TargetSource
    window_id: int | None = None
    automation_id: str | None = None
    value_fingerprint: str | None = None


@dataclass(frozen=True, slots=True)
class VisionRequest:
    screenshot_id: str
    dimensions: tuple[int, int]
    timestamp: datetime
    task_objective: str
    accessibility_tree: tuple[AccessibilityNode, ...]
    previous_observation: "DesktopObservation | None"
    source: VisualSource = VisualSource.SCREEN


@dataclass(frozen=True, slots=True)
class VisionAnalysis:
    visible_elements: tuple[VisibleElement, ...]
    candidate_targets: tuple[VisionCandidate, ...]
    confidence: float

    def __post_init__(self) -> None:
        if not 0 <= self.confidence <= 1:
            raise ValueError("Vision analysis confidence must be within [0, 1]")


@dataclass(frozen=True, slots=True)
class DesktopObservation:
    observation_id: UUID
    screenshot_id: str
    dimensions: tuple[int, int]
    timestamp: datetime
    geometry: DisplayGeometry
    active_window: ActiveWindow | None
    visible_elements: tuple[VisibleElement, ...]
    confidence: float
    accessibility_matches: tuple[AccessibilityNode, ...]
    candidate_targets: tuple[CandidateTarget, ...]
    state_fingerprint: str


@dataclass(frozen=True, slots=True)
class VerificationExpectation:
    target_id: str | None = None
    target_visible: bool | None = None
    active_window_id: int | None = None
    control_id: str | None = None
    expected_value_fingerprint: str | None = None
    minimum_confidence: float = 0.7

    def __post_init__(self) -> None:
        if not 0 <= self.minimum_confidence <= 1:
            raise ValueError("Verification confidence must be within [0, 1]")


@dataclass(frozen=True, slots=True)
class ActionProposal:
    """Untrusted plan data; grounding maps it to an existing brokered tool only."""

    intent: ActionIntent
    target_id: str
    expectation: VerificationExpectation
    text: str | None = None

    def __post_init__(self) -> None:
        if not self.target_id:
            raise ValueError("Actions must name a target from the current observation")
        if self.intent is ActionIntent.SET_TEXT and self.text is None:
            raise ValueError("Set-text actions require text")
        if self.intent is not ActionIntent.SET_TEXT and self.text is not None:
            raise ValueError("Only set-text actions may include text")


@dataclass(frozen=True, slots=True)
class GroundedAction:
    observation_id: UUID
    state_fingerprint: str
    target: CandidateTarget
    tool_id: str
    tool_input: dict[str, object]
    expectation: VerificationExpectation


@dataclass(frozen=True, slots=True)
class VerificationResult:
    status: VerificationStatus
    detail: str
    evidence: tuple[str, ...] = ()


@dataclass(frozen=True, slots=True)
class InteractionResult:
    status: InteractionStatus
    before: DesktopObservation
    after: DesktopObservation | None
    verification: VerificationResult | None
    attempts: int
    detail: str
