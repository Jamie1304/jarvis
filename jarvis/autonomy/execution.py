"""Capability selection, execution, observation, and verification services."""

from abc import ABC, abstractmethod
from typing import Any

from jarvis.autonomy.models import (
    PlanStep,
    ToolObservation,
    VerificationResult,
    VerificationStatus,
)
from jarvis.core.errors import CapabilityUnavailableError, ToolExecutionError
from jarvis.tools.base import Tool
from jarvis.tools.models import (
    ToolExecutionContext,
    ToolResult,
    ToolResultStatus,
)
from jarvis.tools.registry import ToolRegistry


class CapabilitySelector(ABC):
    """Select an allowed application capability for a typed step."""

    @abstractmethod
    def select(self, step: PlanStep) -> Tool[Any, Any]:
        """Return the selected registered tool."""


class RegistryCapabilitySelector(CapabilitySelector):
    """Select only capabilities explicitly included in the local registry."""

    def __init__(self, registry: ToolRegistry) -> None:
        self._registry = registry

    def select(self, step: PlanStep) -> Tool[Any, Any]:
        return self._registry.resolve_best_matching_capability(step.capability)


class ToolExecutor(ABC):
    """Execute an approved capability request."""

    @abstractmethod
    async def execute(
        self,
        tool: Tool[Any, Any],
        context: ToolExecutionContext,
        raw_input: dict[str, object],
    ) -> ToolResult:
        """Return the tool boundary result without leaking implementation exceptions."""


class DefaultToolExecutor(ToolExecutor):
    """Small execution adapter that converts unexpected tool errors into task errors."""

    async def execute(
        self,
        tool: Tool[Any, Any],
        context: ToolExecutionContext,
        raw_input: dict[str, object],
    ) -> ToolResult:
        return await tool.invoke(context, raw_input)


class ObservationService(ABC):
    """Normalize execution output into an observation before verification."""

    @abstractmethod
    async def observe(self, result: ToolResult) -> ToolObservation:
        """Return the observation that verification may evaluate."""


class DefaultObservationService(ObservationService):
    """Reject empty observations so execution cannot silently imply success."""

    async def observe(self, result: ToolResult) -> ToolObservation:
        if not result.succeeded:
            error = result.error
            message = error.message if error else "Tool returned a failed result"
            if result.status is ToolResultStatus.UNAVAILABLE:
                raise CapabilityUnavailableError(message)
            raise ToolExecutionError(message)
        if result.output is None:
            raise ToolExecutionError("Tool returned success without typed output")
        evidence = tuple(
            value for item in result.evidence for value in (item.value, f"{item.kind}={item.value}")
        )
        return ToolObservation(summary=result.output.model_dump_json(), evidence=evidence)


class StepVerifier(ABC):
    """Verify observed evidence independently from tool invocation success."""

    @abstractmethod
    async def verify(self, step: PlanStep, observation: ToolObservation) -> VerificationResult:
        """Return explicit success, failure, or unverifiable evidence."""


class EvidenceVerifier(StepVerifier):
    """Require expected outcome evidence; returning normally is never sufficient."""

    async def verify(self, step: PlanStep, observation: ToolObservation) -> VerificationResult:
        if step.expected_outcome in observation.evidence:
            return VerificationResult(
                status=VerificationStatus.SUCCEEDED,
                success_evidence=(step.expected_outcome,),
            )
        if observation.evidence:
            return VerificationResult(
                status=VerificationStatus.FAILED,
                failure_evidence=observation.evidence,
                detail="Observed evidence did not match the expected outcome",
            )
        return VerificationResult(
            status=VerificationStatus.UNVERIFIABLE,
            detail="The tool returned no evidence for the expected outcome",
        )
