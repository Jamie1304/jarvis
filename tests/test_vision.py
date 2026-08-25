import asyncio
import json
from dataclasses import replace
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any, cast
from uuid import uuid4

import pytest
from jarvis.computer.accessibility import AccessibilityAdapter, AccessibilityNode
from jarvis.computer.adapters import ComputerAdapter
from jarvis.computer.artifacts import InMemoryScreenshotStore
from jarvis.computer.models import (
    CapturedScreen,
    ControlState,
    LaunchInfo,
    MouseActionState,
    WindowInfo,
)
from jarvis.computer.tools import (
    CaptureScreenTool,
    DiscoverWindowsTool,
    FocusWindowTool,
    MouseFallbackTool,
    ReadAccessibilityTool,
    SetTextTool,
)
from jarvis.permissions import (
    Decision,
    Permission,
    PermissionBroker,
    PolicyEngine,
    PolicyRule,
    ScopeConstraint,
)
from jarvis.tools.registry import ToolRegistry
from jarvis.vision.fusion import ObservationAssembler, StaleObservationError, TargetGrounder
from jarvis.vision.gateway import BrokeredToolInvoker
from jarvis.vision.interaction import (
    BrokeredDesktopObserver,
    RetryAdvisor,
    VisualInteractionService,
    VisualVerifier,
)
from jarvis.vision.models import (
    ActionIntent,
    ActionProposal,
    ActiveWindow,
    CandidateTarget,
    DesktopObservation,
    DisplayGeometry,
    NormalizedBounds,
    TargetSource,
    VerificationExpectation,
    VerificationResult,
    VerificationStatus,
    VisibleElement,
    VisionAnalysis,
    VisionCandidate,
)
from jarvis.vision.providers import VisionProvider

_FIXTURE_PATH = Path(__file__).parent / "fixtures" / "desktop_observations.json"


def fixture_states() -> dict[str, dict[str, Any]]:
    return cast(dict[str, dict[str, Any]], json.loads(_FIXTURE_PATH.read_text(encoding="utf-8")))


def node_from_fixture(value: dict[str, Any]) -> AccessibilityNode:
    return AccessibilityNode(
        window_id=int(value["window_id"]),
        automation_id=value["automation_id"] if isinstance(value["automation_id"], str) else None,
        name=str(value["name"]),
        control_type=str(value["control_type"]),
        left=int(value["left"]),
        top=int(value["top"]),
        width=int(value["width"]),
        height=int(value["height"]),
        value_fingerprint=(
            value["value_fingerprint"] if isinstance(value["value_fingerprint"], str) else None
        ),
    )


def bounds_from_fixture(value: list[Any]) -> NormalizedBounds:
    return NormalizedBounds(*(float(item) for item in value))


def analysis_from_state(state: dict[str, Any], confidence: float | None = None) -> VisionAnalysis:
    vision = state["vision"]
    assert isinstance(vision, dict)
    visible = tuple(
        VisibleElement(
            label=str(item["label"]),
            role=str(item["role"]),
            bounds=bounds_from_fixture(item["bounds"]),
            confidence=float(item["confidence"]),
        )
        for item in vision["visible_elements"]
    )
    candidates = tuple(
        VisionCandidate(
            label=str(item["label"]),
            role=str(item["role"]),
            bounds=bounds_from_fixture(item["bounds"]),
            confidence=float(item["confidence"]),
        )
        for item in vision["candidate_targets"]
    )
    return VisionAnalysis(visible, candidates, confidence or float(vision["confidence"]))


class FixtureVisionProvider(VisionProvider):
    def __init__(self, state: dict[str, Any], confidences: list[float] | None = None) -> None:
        self._state = state
        self._confidences = confidences or []
        self.requests: list[object] = []

    async def observe(self, request: object) -> VisionAnalysis:
        self.requests.append(request)
        confidence = self._confidences.pop(0) if self._confidences else None
        return analysis_from_state(self._state, confidence)


class FixtureComputerAdapter(ComputerAdapter):
    def __init__(self, state: dict[str, Any], *, focus_changes_state: bool = True) -> None:
        self.state = state
        self.focus_changes_state = focus_changes_state
        self.focused = False
        self.focuses: list[int] = []
        self.text_updates: list[tuple[int, str, str]] = []
        self.mouse_clicks: list[MouseActionState] = []
        self.capture_count = 0
        self.screen_bytes = b"fixture-screen"

    @property
    def dimensions(self) -> tuple[int, int]:
        raw = self.state["dimensions"]
        assert isinstance(raw, list)
        return int(raw[0]), int(raw[1])

    async def discover_windows(self, title_contains: str | None) -> tuple[WindowInfo, ...]:
        del title_contains
        return (WindowInfo(101, "Notepad", 42, self.focused),)

    async def launch_application(self, application_id: str) -> LaunchInfo:
        return LaunchInfo(application_id, 777)

    async def focus_window(self, window_id: int) -> WindowInfo:
        self.focuses.append(window_id)
        if self.focus_changes_state:
            self.focused = True
        return WindowInfo(window_id, "Notepad", 42, self.focused)

    async def set_text(self, window_id: int, control_id: str, text: str) -> ControlState:
        self.text_updates.append((window_id, control_id, text))
        return ControlState(window_id, control_id)

    async def mouse_click(self, x: int, y: int, button: str) -> MouseActionState:
        state = MouseActionState(x, y, button)
        self.mouse_clicks.append(state)
        return state

    async def capture_screen(self) -> CapturedScreen:
        width, height = self.dimensions
        captured_at = datetime(2026, 1, 1, tzinfo=UTC) + timedelta(seconds=self.capture_count)
        self.capture_count += 1
        return CapturedScreen(self.screen_bytes, width, height, captured_at)

    async def read_clipboard(self) -> str:
        return ""

    async def write_clipboard(self, text: str) -> int:
        return len(text)


class FixtureAccessibilityAdapter(AccessibilityAdapter):
    def __init__(self, computer: FixtureComputerAdapter) -> None:
        self._computer = computer

    async def read_accessibility(self, window_id: int | None) -> tuple[AccessibilityNode, ...]:
        del window_id
        return tuple(node_from_fixture(item) for item in self._computer.state["accessibility"])


class RevisedActionAdvisor(RetryAdvisor):
    def __init__(self, revised: ActionProposal) -> None:
        self.revised = revised
        self.calls = 0

    async def revise(
        self,
        proposal: ActionProposal,
        before: DesktopObservation,
        after: DesktopObservation | None,
        verification: VerificationResult | None,
    ) -> ActionProposal | None:
        del proposal, before, after, verification
        self.calls += 1
        return self.revised


def broker(*, include_input: bool = True) -> PermissionBroker:
    rules = [
        PolicyRule(
            "capture",
            Permission.SCREEN_READ,
            Decision.ALLOW,
            ScopeConstraint(tools=frozenset({"computer.capture_screen"})),
            frozenset({"capture screen"}),
        ),
        PolicyRule(
            "windows",
            Permission.SCREEN_READ,
            Decision.ALLOW,
            ScopeConstraint(tools=frozenset({"computer.discover_windows"})),
            frozenset({"discover windows"}),
        ),
        PolicyRule(
            "accessibility",
            Permission.SCREEN_READ,
            Decision.ALLOW,
            ScopeConstraint(tools=frozenset({"computer.read_accessibility"})),
            frozenset({"read accessibility tree"}),
        ),
    ]
    if include_input:
        rules.extend(
            (
                PolicyRule(
                    "focus",
                    Permission.COMPUTER_INPUT,
                    Decision.ALLOW,
                    ScopeConstraint(tools=frozenset({"computer.focus_window"})),
                    frozenset({"focus window"}),
                ),
                PolicyRule(
                    "set-text",
                    Permission.COMPUTER_INPUT,
                    Decision.ALLOW,
                    ScopeConstraint(tools=frozenset({"computer.set_text"})),
                    frozenset({"set text"}),
                ),
            )
        )
    return PermissionBroker(PolicyEngine(tuple(rules)))


def build_service(
    state: dict[str, Any],
    *,
    include_input: bool = True,
    focus_changes_state: bool = True,
    confidences: list[float] | None = None,
) -> tuple[VisualInteractionService, FixtureComputerAdapter, FixtureVisionProvider]:
    computer = FixtureComputerAdapter(state, focus_changes_state=focus_changes_state)
    accessibility = FixtureAccessibilityAdapter(computer)
    registry = ToolRegistry(
        (
            CaptureScreenTool(computer, InMemoryScreenshotStore()),
            DiscoverWindowsTool(computer),
            ReadAccessibilityTool(accessibility),
            FocusWindowTool(computer),
            SetTextTool(computer),
            MouseFallbackTool(computer),
        ),
        permission_broker=broker(include_input=include_input),
    )
    provider = FixtureVisionProvider(state, confidences)
    invoker = BrokeredToolInvoker(registry)
    return (
        VisualInteractionService(BrokeredDesktopObserver(invoker, provider), invoker),
        computer,
        provider,
    )


def fixture_observation(state: dict[str, Any]) -> DesktopObservation:
    raw_dimensions = state["dimensions"]
    dimensions = int(raw_dimensions[0]), int(raw_dimensions[1])
    return ObservationAssembler().assemble(
        screenshot_id="fixture:notepad",
        screenshot_fingerprint="fixture-fingerprint",
        dimensions=dimensions,
        timestamp=datetime(2026, 1, 1, tzinfo=UTC),
        geometry=DisplayGeometry(*dimensions, *dimensions, 1.0, 1.0),
        active_window=ActiveWindow(101, "Notepad", 42),
        accessibility_tree=tuple(node_from_fixture(item) for item in state["accessibility"]),
        analysis=analysis_from_state(state),
    )


def target(observation: DesktopObservation, label: str) -> CandidateTarget:
    return next(item for item in observation.candidate_targets if item.label == label)


def test_fixture_finds_visible_target_and_fuses_accessibility_with_vision() -> None:
    observation = fixture_observation(fixture_states()["notepad"])
    send = target(observation, "Send")

    assert observation.visible_elements[0].label == "Send"
    assert send.source is TargetSource.FUSED
    assert send.automation_id == "SendButton"


def test_fusion_retains_a_visual_only_target_and_ignores_invalid_semantic_bounds() -> None:
    state = fixture_states()["notepad"]
    analysis = VisionAnalysis(
        (),
        (VisionCandidate("Help", "Button", NormalizedBounds(0.1, 0.1, 0.1, 0.1), 0.8),),
        0.8,
    )
    observation = ObservationAssembler().assemble(
        screenshot_id="fixture:visual-only",
        screenshot_fingerprint="fingerprint",
        dimensions=(800, 600),
        timestamp=datetime(2026, 1, 1, tzinfo=UTC),
        geometry=DisplayGeometry(800, 600, 800, 600, 1.0, 1.0),
        active_window=ActiveWindow(101, "Notepad", 42),
        accessibility_tree=(
            node_from_fixture(state["accessibility"][0]),
            AccessibilityNode(101, "offscreen", "Offscreen", "Button", 900, 0, 20, 20),
            AccessibilityNode(101, "empty", "Empty", "Button", 0, 0, 0, 20),
        ),
        analysis=analysis,
    )

    help_target = target(observation, "Help")
    assert help_target.source is TargetSource.VISION
    assert all(item.label != "Offscreen" for item in observation.candidate_targets)


def test_visual_models_reject_malformed_bounds_geometry_confidence_and_actions() -> None:
    with pytest.raises(ValueError):
        NormalizedBounds(-0.1, 0, 0.1, 0.1)
    with pytest.raises(ValueError):
        NormalizedBounds(0.9, 0.1, 0.2, 0.1)
    with pytest.raises(ValueError):
        NormalizedBounds(float("nan"), 0, 0.1, 0.1)
    with pytest.raises(ValueError):
        NormalizedBounds(0, 0, float("inf"), 0.1)
    with pytest.raises(ValueError):
        DisplayGeometry(800, 600, 1200, 900, 1.0, 1.5)
    with pytest.raises(ValueError):
        VisibleElement("", "Button", NormalizedBounds(0, 0, 0.1, 0.1), 0.9)
    with pytest.raises(ValueError):
        VisibleElement("Save", "Button", NormalizedBounds(0, 0, 0.1, 0.1), float("nan"))
    with pytest.raises(ValueError):
        VisionAnalysis((), (), 1.1)
    with pytest.raises(ValueError):
        VerificationExpectation(minimum_confidence=1.1)
    with pytest.raises(ValueError):
        ActionProposal(ActionIntent.SET_TEXT, "target", VerificationExpectation())
    with pytest.raises(ValueError):
        ActionProposal(ActionIntent.FOCUS, "target", VerificationExpectation(), text="no")


def test_geometry_rejects_dimension_mismatch_and_converts_dpi_scaled_coordinates() -> None:
    state = fixture_states()["notepad"]
    observation = fixture_observation(state)
    send = target(observation, "Send")
    geometry = DisplayGeometry(800, 600, 1200, 900, 1.5, 1.5)

    assert geometry.physical_point(send.bounds) == (1102, 75)
    with pytest.raises(ValueError, match="geometry"):
        ObservationAssembler().assemble(
            screenshot_id="fixture:mismatch",
            screenshot_fingerprint="fixture-fingerprint",
            dimensions=(800, 600),
            timestamp=datetime(2026, 1, 1, tzinfo=UTC),
            geometry=DisplayGeometry(1200, 900, 1200, 900, 1.0, 1.0),
            active_window=None,
            accessibility_tree=(),
            analysis=VisionAnalysis((), (), 1.0),
        )


def test_verifier_reports_success_failure_and_uncertain_states() -> None:
    observation = fixture_observation(fixture_states()["notepad"])
    send = target(observation, "Send")
    verifier = VisualVerifier()

    success = verifier.verify(
        VerificationExpectation(target_id=send.target_id, target_visible=True), observation
    )
    failure = verifier.verify(VerificationExpectation(active_window_id=999), observation)
    uncertain = verifier.verify(
        VerificationExpectation(
            target_id=send.target_id, target_visible=True, minimum_confidence=0.99
        ),
        observation,
    )

    assert success.status is VerificationStatus.SUCCESS
    assert failure.status is VerificationStatus.FAILURE
    assert uncertain.status is VerificationStatus.UNCERTAIN


def test_verifier_handles_missing_and_mismatched_semantic_control_state() -> None:
    observation = fixture_observation(fixture_states()["notepad"])
    verifier = VisualVerifier()

    missing = verifier.verify(VerificationExpectation(control_id="Missing"), observation)
    mismatch = verifier.verify(
        VerificationExpectation(control_id="DocumentText", expected_value_fingerprint="wrong"),
        observation,
    )
    no_expectation = verifier.verify(VerificationExpectation(), observation)

    assert missing.status is VerificationStatus.UNCERTAIN
    assert mismatch.status is VerificationStatus.FAILURE
    assert no_expectation.status is VerificationStatus.UNCERTAIN


def test_grounder_requires_current_target_and_prefers_semantic_actions() -> None:
    observation = fixture_observation(fixture_states()["notepad"])
    document = target(observation, "Document")
    send = target(observation, "Send")
    grounder = TargetGrounder()

    text_action = grounder.ground(
        ActionProposal(
            ActionIntent.SET_TEXT, document.target_id, VerificationExpectation(), text="hello"
        ),
        observation,
        observation,
    )
    click_action = grounder.ground(
        ActionProposal(ActionIntent.CLICK_FALLBACK, send.target_id, VerificationExpectation()),
        observation,
        observation,
    )
    stale = replace(observation, observation_id=uuid4(), candidate_targets=())

    assert text_action.tool_id == "computer.set_text"
    assert text_action.tool_input["control_id"] == "DocumentText"
    assert click_action.tool_id == "computer.mouse_fallback"
    with pytest.raises(StaleObservationError):
        grounder.ground(
            ActionProposal(ActionIntent.FOCUS, send.target_id, VerificationExpectation()),
            observation,
            stale,
        )


@pytest.mark.asyncio
async def test_brokered_invoker_fails_closed_for_an_unregistered_tool() -> None:
    result = await BrokeredToolInvoker(ToolRegistry()).invoke(
        "computer.capture_screen",
        {},
        task_id=uuid4(),
        cancellation=asyncio.Event(),
        user_id="trusted-user",
    )

    assert result.status.value == "unavailable"
    assert result.error is not None and result.error.code == "visual_tool_unavailable"


@pytest.mark.asyncio
async def test_visual_loop_reobserves_before_acting_and_verifies_success() -> None:
    service, computer, provider = build_service(fixture_states()["notepad"])
    task_id = uuid4()
    observed = await service.observe(
        task_id=task_id,
        task_objective="Focus the Notepad window",
        cancellation=asyncio.Event(),
        user_id="trusted-user",
    )
    send = target(observed, "Send")

    result = await service.act_from_observation(
        task_id=task_id,
        task_objective="Focus the Notepad window",
        observed=observed,
        proposal=ActionProposal(
            ActionIntent.FOCUS,
            send.target_id,
            VerificationExpectation(active_window_id=101),
        ),
        cancellation=asyncio.Event(),
        user_id="trusted-user",
    )

    assert result.status.value == "success"
    assert (
        result.verification is not None and result.verification.status is VerificationStatus.SUCCESS
    )
    assert computer.focuses == [101]
    assert len(provider.requests) == 3


@pytest.mark.asyncio
async def test_stale_observation_after_resize_prevents_action() -> None:
    states = fixture_states()
    service, computer, _ = build_service(states["notepad"])
    task_id = uuid4()
    observed = await service.observe(
        task_id=task_id,
        task_objective="Focus window",
        cancellation=asyncio.Event(),
        user_id="trusted-user",
    )
    computer.state = states["resized"]
    send = target(observed, "Send")

    result = await service.act_from_observation(
        task_id=task_id,
        task_objective="Focus window",
        observed=observed,
        proposal=ActionProposal(
            ActionIntent.FOCUS,
            send.target_id,
            VerificationExpectation(active_window_id=101),
        ),
        cancellation=asyncio.Event(),
        user_id="trusted-user",
    )

    assert result.status.value == "stale_observation"
    assert computer.focuses == []


@pytest.mark.asyncio
async def test_stale_observation_after_material_screen_change_prevents_action() -> None:
    service, computer, _ = build_service(fixture_states()["notepad"])
    task_id = uuid4()
    observed = await service.observe(
        task_id=task_id,
        task_objective="Focus window",
        cancellation=asyncio.Event(),
        user_id="trusted-user",
    )
    computer.screen_bytes = b"materially-changed-fixture-screen"
    send = target(observed, "Send")

    result = await service.act_from_observation(
        task_id=task_id,
        task_objective="Focus window",
        observed=observed,
        proposal=ActionProposal(
            ActionIntent.FOCUS,
            send.target_id,
            VerificationExpectation(active_window_id=101),
        ),
        cancellation=asyncio.Event(),
        user_id="trusted-user",
    )

    assert result.status.value == "stale_observation"
    assert computer.focuses == []


@pytest.mark.asyncio
async def test_identifying_send_target_does_not_bypass_input_permission() -> None:
    service, computer, _ = build_service(fixture_states()["notepad"], include_input=False)
    task_id = uuid4()
    observed = await service.observe(
        task_id=task_id,
        task_objective="Click Send",
        cancellation=asyncio.Event(),
        user_id="trusted-user",
    )
    send = target(observed, "Send")

    result = await service.act_from_observation(
        task_id=task_id,
        task_objective="Click Send",
        observed=observed,
        proposal=ActionProposal(
            ActionIntent.CLICK_FALLBACK,
            send.target_id,
            VerificationExpectation(target_id=send.target_id, target_visible=True),
        ),
        cancellation=asyncio.Event(),
        user_id="trusted-user",
    )

    assert result.status.value == "action_denied"
    assert computer.mouse_clicks == []


@pytest.mark.asyncio
async def test_retry_cap_requires_a_revised_action_and_stops_at_limit() -> None:
    service, computer, _ = build_service(fixture_states()["notepad"], focus_changes_state=False)
    task_id = uuid4()
    preview = await service.observe(
        task_id=task_id,
        task_objective="Focus then enter text",
        cancellation=asyncio.Event(),
        user_id="trusted-user",
    )
    send = target(preview, "Send")
    document = target(preview, "Document")
    first = ActionProposal(
        ActionIntent.FOCUS,
        send.target_id,
        VerificationExpectation(active_window_id=101),
    )
    revised = ActionProposal(
        ActionIntent.SET_TEXT,
        document.target_id,
        VerificationExpectation(active_window_id=101),
        text="hello",
    )
    advisor = RevisedActionAdvisor(revised)

    result = await service.run(
        task_id=task_id,
        task_objective="Focus then enter text",
        proposal=first,
        cancellation=asyncio.Event(),
        user_id="trusted-user",
        max_attempts=2,
        retry_advisor=advisor,
    )

    assert result.attempts == 2
    assert advisor.calls == 1
    assert computer.focuses == [101]
    assert computer.text_updates == [(101, "DocumentText", "hello")]


@pytest.mark.asyncio
async def test_retry_refuses_a_blind_repeat_of_the_same_action() -> None:
    service, computer, _ = build_service(fixture_states()["notepad"], focus_changes_state=False)
    task_id = uuid4()
    preview = await service.observe(
        task_id=task_id,
        task_objective="Focus window",
        cancellation=asyncio.Event(),
        user_id="trusted-user",
    )
    send = target(preview, "Send")
    proposal = ActionProposal(
        ActionIntent.FOCUS,
        send.target_id,
        VerificationExpectation(active_window_id=101),
    )
    advisor = RevisedActionAdvisor(proposal)

    result = await service.run(
        task_id=task_id,
        task_objective="Focus window",
        proposal=proposal,
        cancellation=asyncio.Event(),
        user_id="trusted-user",
        max_attempts=3,
        retry_advisor=advisor,
    )

    assert result.attempts == 1
    assert advisor.calls == 1
    assert computer.focuses == [101]
