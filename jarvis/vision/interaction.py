"""Observe-understand-ground-act-observe-verify orchestration above computer tools."""

import asyncio
import hashlib
from abc import ABC, abstractmethod
from datetime import datetime
from typing import TypeVar
from uuid import UUID

from pydantic import BaseModel

from jarvis.computer.accessibility import AccessibilityNode
from jarvis.computer.tools import (
    CaptureScreenOutput,
    DiscoverWindowsOutput,
    ReadAccessibilityOutput,
)
from jarvis.tools.models import ToolResult, ToolResultStatus
from jarvis.vision.fusion import ObservationAssembler, StaleObservationError, TargetGrounder
from jarvis.vision.gateway import BrokeredToolInvoker
from jarvis.vision.models import (
    ActionProposal,
    ActiveWindow,
    DesktopObservation,
    DisplayGeometry,
    InteractionResult,
    InteractionStatus,
    VerificationExpectation,
    VerificationResult,
    VerificationStatus,
    VisionRequest,
)
from jarvis.vision.providers import VisionProvider

OutputType = TypeVar("OutputType", bound=BaseModel)


class GeometryProvider(ABC):
    """Trusted desktop metrics provider; it must agree with each screenshot artifact."""

    @abstractmethod
    def geometry_for(self, width: int, height: int) -> DisplayGeometry:
        """Return physical display geometry for one captured screenshot."""


class IdentityGeometryProvider(GeometryProvider):
    """Safe default for adapters whose capture coordinates are physical pixels."""

    def geometry_for(self, width: int, height: int) -> DisplayGeometry:
        return DisplayGeometry(width, height, width, height, 1.0, 1.0)


class RetryAdvisor(ABC):
    """Diagnose a verified non-success and propose a materially revised next action."""

    @abstractmethod
    async def revise(
        self,
        proposal: ActionProposal,
        before: DesktopObservation,
        after: DesktopObservation | None,
        verification: VerificationResult | None,
    ) -> ActionProposal | None:
        """Return a revised action proposal or stop retries."""


class NoRetryAdvisor(RetryAdvisor):
    async def revise(
        self,
        proposal: ActionProposal,
        before: DesktopObservation,
        after: DesktopObservation | None,
        verification: VerificationResult | None,
    ) -> ActionProposal | None:
        del proposal, before, after, verification
        return None


class BrokeredDesktopObserver:
    """Collect a new screen state through existing brokered screen-read tools."""

    def __init__(
        self,
        invoker: BrokeredToolInvoker,
        provider: VisionProvider,
        *,
        assembler: ObservationAssembler | None = None,
        geometry_provider: GeometryProvider | None = None,
    ) -> None:
        self._invoker = invoker
        self._provider = provider
        self._assembler = assembler or ObservationAssembler()
        self._geometry_provider = geometry_provider or IdentityGeometryProvider()

    async def observe(
        self,
        *,
        task_id: UUID,
        task_objective: str,
        cancellation: asyncio.Event,
        user_id: str | None,
        previous: DesktopObservation | None = None,
    ) -> DesktopObservation:
        capture = await self._invoker.invoke(
            "computer.capture_screen",
            {},
            task_id=task_id,
            cancellation=cancellation,
            user_id=user_id,
        )
        capture_output = self._output(capture, CaptureScreenOutput)
        if capture_output is None:
            raise RuntimeError("A current screenshot could not be observed through the broker")
        dimensions = (capture_output.width, capture_output.height)
        geometry = self._geometry_provider.geometry_for(*dimensions)
        windows = await self._invoker.invoke(
            "computer.discover_windows",
            {},
            task_id=task_id,
            cancellation=cancellation,
            user_id=user_id,
        )
        window_output = self._output(windows, DiscoverWindowsOutput)
        active_window = self._active_window(window_output)
        accessibility_tree = await self._read_accessibility(
            task_id=task_id,
            cancellation=cancellation,
            user_id=user_id,
        )
        timestamp = datetime.fromisoformat(capture_output.captured_at)
        analysis = await self._provider.observe(
            VisionRequest(
                screenshot_id=capture_output.reference,
                dimensions=dimensions,
                timestamp=timestamp,
                task_objective=task_objective,
                accessibility_tree=accessibility_tree,
                previous_observation=previous,
            )
        )
        return self._assembler.assemble(
            screenshot_id=capture_output.reference,
            screenshot_fingerprint=capture_output.content_fingerprint,
            dimensions=dimensions,
            timestamp=timestamp,
            geometry=geometry,
            active_window=active_window,
            accessibility_tree=accessibility_tree,
            analysis=analysis,
        )

    async def _read_accessibility(
        self,
        *,
        task_id: UUID,
        cancellation: asyncio.Event,
        user_id: str | None,
    ) -> tuple[AccessibilityNode, ...]:
        result = await self._invoker.invoke(
            "computer.read_accessibility",
            {},
            task_id=task_id,
            cancellation=cancellation,
            user_id=user_id,
        )
        output = self._output(result, ReadAccessibilityOutput)
        if output is None:
            return ()
        return tuple(
            AccessibilityNode(
                window_id=node.window_id,
                automation_id=node.automation_id,
                name=node.name,
                control_type=node.control_type,
                left=node.left,
                top=node.top,
                width=node.width,
                height=node.height,
                value_fingerprint=node.value_fingerprint,
            )
            for node in output.nodes
        )

    @staticmethod
    def _output(result: ToolResult, model: type[OutputType]) -> OutputType | None:
        if result.status is not ToolResultStatus.SUCCESS or not isinstance(result.output, model):
            return None
        return result.output

    @staticmethod
    def _active_window(output: DiscoverWindowsOutput | None) -> ActiveWindow | None:
        if output is None:
            return None
        focused = next((item for item in output.windows if item.is_focused), None)
        if focused is None:
            return None
        return ActiveWindow(focused.window_id, focused.title, focused.process_id)


class VisualVerifier:
    """Compare a newly observed state with explicit semantic/visual expectations."""

    def verify(
        self,
        expectation: VerificationExpectation,
        after: DesktopObservation,
    ) -> VerificationResult:
        if after.confidence < expectation.minimum_confidence:
            return VerificationResult(
                VerificationStatus.UNCERTAIN,
                "Current observation confidence is below the verification threshold",
            )
        evidence: list[str] = []
        if expectation.active_window_id is not None:
            actual = after.active_window.window_id if after.active_window else None
            if actual != expectation.active_window_id:
                return VerificationResult(
                    VerificationStatus.FAILURE,
                    "The expected window is not active",
                    (f"active_window={actual}",),
                )
            evidence.append("active window matched")
        if expectation.target_id is not None and expectation.target_visible is not None:
            target = next(
                (
                    item
                    for item in after.candidate_targets
                    if item.target_id == expectation.target_id
                ),
                None,
            )
            visible = target is not None and target.confidence >= expectation.minimum_confidence
            if visible != expectation.target_visible:
                return VerificationResult(
                    VerificationStatus.FAILURE,
                    "The expected target visibility did not match",
                    (f"target_visible={visible}",),
                )
            evidence.append("target visibility matched")
        if expectation.control_id is not None:
            node = next(
                (
                    item
                    for item in after.accessibility_matches
                    if item.automation_id == expectation.control_id
                ),
                None,
            )
            if node is None:
                return VerificationResult(
                    VerificationStatus.UNCERTAIN,
                    "The control is not present in the current accessibility snapshot",
                )
            if (
                expectation.expected_value_fingerprint is not None
                and node.value_fingerprint != expectation.expected_value_fingerprint
            ):
                return VerificationResult(
                    VerificationStatus.FAILURE,
                    "The control state did not match the expected value fingerprint",
                )
            evidence.append("control state matched")
        if not evidence:
            return VerificationResult(
                VerificationStatus.UNCERTAIN,
                "No independently verifiable expectation was supplied",
            )
        return VerificationResult(
            VerificationStatus.SUCCESS, "Expected state observed", tuple(evidence)
        )


class VisualInteractionService:
    """Run the mandatory observe-understand-ground-act-observe-verify loop."""

    def __init__(
        self,
        observer: BrokeredDesktopObserver,
        invoker: BrokeredToolInvoker,
        *,
        grounder: TargetGrounder | None = None,
        verifier: VisualVerifier | None = None,
    ) -> None:
        self._observer = observer
        self._invoker = invoker
        self._grounder = grounder or TargetGrounder()
        self._verifier = verifier or VisualVerifier()

    async def observe(
        self,
        *,
        task_id: UUID,
        task_objective: str,
        cancellation: asyncio.Event,
        user_id: str | None,
    ) -> DesktopObservation:
        """Perform the OBSERVE/UNDERSTAND stage before a planner proposes a target action."""

        return await self._observer.observe(
            task_id=task_id,
            task_objective=task_objective,
            cancellation=cancellation,
            user_id=user_id,
        )

    async def act_from_observation(
        self,
        *,
        task_id: UUID,
        task_objective: str,
        observed: DesktopObservation,
        proposal: ActionProposal,
        cancellation: asyncio.Event,
        user_id: str | None,
    ) -> InteractionResult:
        """Re-observe, reject stale targets, act through the broker, then verify."""

        return await self._act_and_verify(
            task_id=task_id,
            task_objective=task_objective,
            observed=observed,
            proposal=proposal,
            cancellation=cancellation,
            user_id=user_id,
            attempt=1,
        )

    async def run(
        self,
        *,
        task_id: UUID,
        task_objective: str,
        proposal: ActionProposal,
        cancellation: asyncio.Event,
        user_id: str | None,
        max_attempts: int = 1,
        retry_advisor: RetryAdvisor | None = None,
    ) -> InteractionResult:
        if max_attempts < 1 or max_attempts > 3:
            raise ValueError("Visual interaction retries must be between one and three attempts")
        advisor = retry_advisor or NoRetryAdvisor()
        current_proposal = proposal
        for attempt in range(1, max_attempts + 1):
            before = await self._observer.observe(
                task_id=task_id,
                task_objective=task_objective,
                cancellation=cancellation,
                user_id=user_id,
            )
            result = await self._act_and_verify(
                task_id=task_id,
                task_objective=task_objective,
                observed=before,
                proposal=current_proposal,
                cancellation=cancellation,
                user_id=user_id,
                attempt=attempt,
            )
            if result.status in {InteractionStatus.SUCCESS, InteractionStatus.ACTION_DENIED}:
                return result
            if attempt == max_attempts:
                return result
            revised = await advisor.revise(
                current_proposal,
                result.before,
                result.after,
                result.verification,
            )
            if revised is None or self._same_action(revised, current_proposal):
                return result
            current_proposal = revised
        raise AssertionError("Visual interaction retry loop did not terminate")

    @staticmethod
    def _same_action(left: ActionProposal, right: ActionProposal) -> bool:
        """Reject retries that change only verification prose rather than the action."""

        return (
            left.intent is right.intent
            and left.target_id == right.target_id
            and left.text == right.text
        )

    async def _act_and_verify(
        self,
        *,
        task_id: UUID,
        task_objective: str,
        observed: DesktopObservation,
        proposal: ActionProposal,
        cancellation: asyncio.Event,
        user_id: str | None,
        attempt: int,
    ) -> InteractionResult:
        current = await self._observer.observe(
            task_id=task_id,
            task_objective=task_objective,
            cancellation=cancellation,
            user_id=user_id,
            previous=observed,
        )
        try:
            action = self._grounder.ground(proposal, observed, current)
        except StaleObservationError as error:
            return InteractionResult(
                InteractionStatus.STALE_OBSERVATION,
                observed,
                current,
                None,
                attempt,
                str(error),
            )
        action_result = await self._invoker.invoke(
            action.tool_id,
            action.tool_input,
            task_id=task_id,
            cancellation=cancellation,
            user_id=user_id,
        )
        if action_result.status is not ToolResultStatus.SUCCESS:
            status = (
                InteractionStatus.ACTION_DENIED
                if action_result.status is ToolResultStatus.PERMISSION_DENIED
                else InteractionStatus.FAILURE
            )
            return InteractionResult(
                status,
                current,
                None,
                None,
                attempt,
                action_result.error.code if action_result.error else "computer_action_failed",
            )
        after = await self._observer.observe(
            task_id=task_id,
            task_objective=task_objective,
            cancellation=cancellation,
            user_id=user_id,
            previous=current,
        )
        verification = self._verifier.verify(action.expectation, after)
        return InteractionResult(
            InteractionStatus(verification.status.value),
            current,
            after,
            verification,
            attempt,
            verification.detail,
        )


def fingerprint_text(value: str) -> str:
    """Return a secret-safe control-value fingerprint for trusted verification setup."""

    return hashlib.sha256(value.encode("utf-8")).hexdigest()
