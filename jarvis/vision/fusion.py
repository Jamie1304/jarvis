"""Trusted semantic-first fusion and target grounding for visual observations."""

import hashlib
import json
from dataclasses import dataclass
from datetime import datetime
from uuid import uuid4

from jarvis.computer.accessibility import AccessibilityNode
from jarvis.vision.models import (
    ActionIntent,
    ActionProposal,
    ActiveWindow,
    CandidateTarget,
    DesktopObservation,
    DisplayGeometry,
    GroundedAction,
    NormalizedBounds,
    TargetSource,
    VisionAnalysis,
)


class StaleObservationError(ValueError):
    """Raised when an action's observed desktop state is no longer current."""


def _digest(value: object) -> str:
    encoded = json.dumps(value, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


def _normalized_bounds(
    node: AccessibilityNode, geometry: DisplayGeometry
) -> NormalizedBounds | None:
    if node.width <= 0 or node.height <= 0:
        return None
    bounds = NormalizedBounds(
        x=node.left / geometry.physical_width,
        y=node.top / geometry.physical_height,
        width=node.width / geometry.physical_width,
        height=node.height / geometry.physical_height,
    )
    return bounds if bounds.x + bounds.width <= 1 and bounds.y + bounds.height <= 1 else None


def _overlap(left: NormalizedBounds, right: NormalizedBounds) -> float:
    x_overlap = max(0.0, min(left.x + left.width, right.x + right.width) - max(left.x, right.x))
    y_overlap = max(0.0, min(left.y + left.height, right.y + right.height) - max(left.y, right.y))
    intersection = x_overlap * y_overlap
    union = left.width * left.height + right.width * right.height - intersection
    return intersection / union if union else 0.0


def _target_id(
    *,
    label: str,
    role: str,
    bounds: NormalizedBounds,
    window_id: int | None,
    automation_id: str | None,
) -> str:
    return _digest(
        {
            "label": label.casefold(),
            "role": role.casefold(),
            "bounds": tuple(
                round(item, 4) for item in (bounds.x, bounds.y, bounds.width, bounds.height)
            ),
            "window_id": window_id,
            "automation_id": automation_id,
        }
    )[:24]


@dataclass(frozen=True, slots=True)
class ObservationAssembler:
    """Fuses accessibility facts first, then augments them with vision suggestions."""

    def assemble(
        self,
        *,
        screenshot_id: str,
        screenshot_fingerprint: str,
        dimensions: tuple[int, int],
        timestamp: datetime,
        geometry: DisplayGeometry,
        active_window: ActiveWindow | None,
        accessibility_tree: tuple[AccessibilityNode, ...],
        analysis: VisionAnalysis,
    ) -> DesktopObservation:
        if (geometry.screenshot_width, geometry.screenshot_height) != dimensions:
            raise ValueError("Observation geometry must match screenshot dimensions")
        candidates: list[CandidateTarget] = []
        semantic_by_bounds: list[tuple[AccessibilityNode, NormalizedBounds]] = []
        for node in accessibility_tree:
            try:
                bounds = _normalized_bounds(node, geometry)
            except ValueError:
                continue
            if bounds is None:
                continue
            semantic_by_bounds.append((node, bounds))
            candidates.append(
                CandidateTarget(
                    target_id=_target_id(
                        label=node.name or node.control_type,
                        role=node.control_type,
                        bounds=bounds,
                        window_id=node.window_id,
                        automation_id=node.automation_id,
                    ),
                    label=node.name or node.control_type,
                    role=node.control_type,
                    bounds=bounds,
                    confidence=1.0,
                    source=TargetSource.ACCESSIBILITY,
                    window_id=node.window_id,
                    automation_id=node.automation_id,
                    value_fingerprint=node.value_fingerprint,
                )
            )
        for visual in analysis.candidate_targets:
            match = next(
                (
                    (node, bounds)
                    for node, bounds in semantic_by_bounds
                    if node.name.casefold() == visual.label.casefold()
                    and _overlap(bounds, visual.bounds) >= 0.5
                ),
                None,
            )
            if match is None:
                candidates.append(
                    CandidateTarget(
                        target_id=_target_id(
                            label=visual.label,
                            role=visual.role,
                            bounds=visual.bounds,
                            window_id=active_window.window_id if active_window else None,
                            automation_id=None,
                        ),
                        label=visual.label,
                        role=visual.role,
                        bounds=visual.bounds,
                        confidence=visual.confidence,
                        source=TargetSource.VISION,
                        window_id=active_window.window_id if active_window else None,
                    )
                )
                continue
            node, bounds = match
            candidates.append(
                CandidateTarget(
                    target_id=_target_id(
                        label=node.name or visual.label,
                        role=node.control_type,
                        bounds=bounds,
                        window_id=node.window_id,
                        automation_id=node.automation_id,
                    ),
                    label=node.name or visual.label,
                    role=node.control_type,
                    bounds=bounds,
                    confidence=(visual.confidence + 1.0) / 2,
                    source=TargetSource.FUSED,
                    window_id=node.window_id,
                    automation_id=node.automation_id,
                    value_fingerprint=node.value_fingerprint,
                )
            )
        unique_targets: dict[str, CandidateTarget] = {}
        for candidate in candidates:
            unique_targets[candidate.target_id] = candidate
        deduplicated = tuple(unique_targets.values())
        state_fingerprint = _digest(
            {
                "dimensions": dimensions,
                "screenshot_fingerprint": screenshot_fingerprint,
                "active_window": active_window.window_id if active_window else None,
                "targets": [
                    (target.target_id, round(target.confidence, 3), target.source.value)
                    for target in deduplicated
                ],
            }
        )
        return DesktopObservation(
            observation_id=uuid4(),
            screenshot_id=screenshot_id,
            dimensions=dimensions,
            timestamp=timestamp,
            geometry=geometry,
            active_window=active_window,
            visible_elements=analysis.visible_elements,
            confidence=analysis.confidence,
            accessibility_matches=accessibility_tree,
            candidate_targets=deduplicated,
            state_fingerprint=state_fingerprint,
        )


@dataclass(frozen=True, slots=True)
class TargetGrounder:
    """Convert one current observed target to an existing brokered computer action."""

    def ground(
        self,
        proposal: ActionProposal,
        observed: DesktopObservation,
        current: DesktopObservation,
    ) -> GroundedAction:
        if observed.observation_id != current.observation_id and (
            observed.state_fingerprint != current.state_fingerprint
            or observed.dimensions != current.dimensions
            or self._active_window_id(observed) != self._active_window_id(current)
        ):
            raise StaleObservationError("The desktop changed after the target was observed")
        target = next(
            (item for item in current.candidate_targets if item.target_id == proposal.target_id),
            None,
        )
        if target is None:
            raise StaleObservationError("The observed target is no longer present")
        if proposal.intent is ActionIntent.FOCUS:
            if target.window_id is None:
                raise StaleObservationError("Target cannot be focused without a current window")
            return GroundedAction(
                current.observation_id,
                current.state_fingerprint,
                target,
                "computer.focus_window",
                {"window_id": target.window_id},
                proposal.expectation,
            )
        if proposal.intent is ActionIntent.SET_TEXT:
            if target.window_id is None or target.automation_id is None or proposal.text is None:
                raise StaleObservationError(
                    "Text entry requires a current semantic accessibility target"
                )
            return GroundedAction(
                current.observation_id,
                current.state_fingerprint,
                target,
                "computer.set_text",
                {
                    "window_id": target.window_id,
                    "control_id": target.automation_id,
                    "text": proposal.text,
                },
                proposal.expectation,
            )
        x, y = current.geometry.physical_point(target.bounds)
        return GroundedAction(
            current.observation_id,
            current.state_fingerprint,
            target,
            "computer.mouse_fallback",
            {
                "x": x,
                "y": y,
                "button": "left",
                "fallback_reason": "no semantic action was available for the current target",
            },
            proposal.expectation,
        )

    @staticmethod
    def _active_window_id(observation: DesktopObservation) -> int | None:
        return observation.active_window.window_id if observation.active_window else None
