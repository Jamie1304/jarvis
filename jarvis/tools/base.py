"""Schema-validated, versioned tool execution boundary."""

import asyncio
import sys
from abc import ABC, abstractmethod
from collections.abc import Mapping
from typing import Generic, TypeVar

from pydantic import ValidationError

from jarvis.tools.models import (
    ToolExecutionContext,
    ToolHealth,
    ToolHealthStatus,
    ToolInput,
    ToolManifest,
    ToolOutput,
    ToolPlatform,
    ToolResult,
    ToolResultStatus,
)

InputModel = TypeVar("InputModel", bound=ToolInput)
OutputModel = TypeVar("OutputModel", bound=ToolOutput)


class Tool(ABC, Generic[InputModel, OutputModel]):
    """A versioned capability that validates untrusted arguments before execution."""

    @property
    @abstractmethod
    def manifest(self) -> ToolManifest:
        """Return the stable capability contract."""

    @property
    def capability(self) -> str:
        """Compatibility alias for the manifest's unique tool identifier."""

        return self.manifest.tool_id

    @property
    @abstractmethod
    def input_model(self) -> type[InputModel]:
        """Return the strict Pydantic input model for this tool."""

    @abstractmethod
    async def execute(
        self, context: ToolExecutionContext, validated_input: InputModel
    ) -> ToolResult:
        """Execute validated input and return a structured result without raw exceptions."""

    async def health_check(self) -> ToolHealth:
        """Report whether the tool can currently be invoked."""

        return ToolHealth(ToolHealthStatus.AVAILABLE, "Tool is available")

    async def invoke(
        self, context: ToolExecutionContext, raw_input: Mapping[str, object]
    ) -> ToolResult:
        """Validate, permission-check, time-bound, and execute untrusted tool arguments."""

        if context.cancellation.is_set():
            return ToolResult.failure(
                ToolResultStatus.CANCELLED,
                "tool_cancelled",
                "Tool invocation was cancelled before execution",
            )
        if self._current_platform() not in self.manifest.supported_platforms:
            return ToolResult.failure(
                ToolResultStatus.UNAVAILABLE,
                "unsupported_platform",
                "Tool is unavailable on the current platform",
            )
        if not context.permissions.allows(self.manifest.declared_permissions):
            return ToolResult.failure(
                ToolResultStatus.PERMISSION_DENIED,
                "permission_denied",
                "Required tool permissions were not granted",
            )
        health = await self.health_check()
        if health.status is ToolHealthStatus.UNAVAILABLE:
            return ToolResult.failure(
                ToolResultStatus.UNAVAILABLE,
                "tool_unavailable",
                health.detail,
            )
        unknown_fields = set(raw_input) - set(self.input_model.model_fields)
        if unknown_fields:
            return ToolResult.failure(
                ToolResultStatus.VALIDATION_ERROR,
                "unknown_input_fields",
                f"Unknown tool input fields: {', '.join(sorted(unknown_fields))}",
            )
        try:
            validated_input = self.input_model.model_validate(dict(raw_input), strict=True)
        except ValidationError as error:
            context.logger.info(
                "Tool input validation failed for %s: %s", self.manifest.tool_id, error
            )
            return ToolResult.failure(
                ToolResultStatus.VALIDATION_ERROR,
                "invalid_tool_input",
                "Tool input did not match the declared schema",
            )
        try:
            async with asyncio.timeout(self.manifest.timeout_seconds):
                result = await self._execute_or_cancel(context, validated_input)
        except TimeoutError:
            return ToolResult.failure(
                ToolResultStatus.TIMEOUT,
                "tool_timeout",
                "Tool exceeded its declared timeout",
            )
        except asyncio.CancelledError:
            return ToolResult.failure(
                ToolResultStatus.CANCELLED,
                "tool_cancelled",
                "Tool invocation was cancelled",
            )
        except Exception:
            context.logger.exception("Tool %s failed internally", self.manifest.tool_id)
            return ToolResult.failure(
                ToolResultStatus.INTERNAL_FAILURE,
                "tool_internal_failure",
                "Tool failed internally; diagnostic details were logged",
            )
        if context.cancellation.is_set() and result.succeeded:
            return ToolResult.failure(
                ToolResultStatus.CANCELLED,
                "tool_cancelled",
                "Tool invocation was cancelled",
            )
        return result

    async def _execute_or_cancel(
        self, context: ToolExecutionContext, validated_input: InputModel
    ) -> ToolResult:
        execution_task = asyncio.create_task(self.execute(context, validated_input))
        cancellation_task = asyncio.create_task(context.cancellation.wait())
        try:
            done, _ = await asyncio.wait(
                {execution_task, cancellation_task}, return_when=asyncio.FIRST_COMPLETED
            )
            if cancellation_task in done:
                return ToolResult.failure(
                    ToolResultStatus.CANCELLED,
                    "tool_cancelled",
                    "Tool invocation was cancelled",
                )
            return await execution_task
        finally:
            for pending in (execution_task, cancellation_task):
                if not pending.done():
                    pending.cancel()
            await asyncio.gather(execution_task, cancellation_task, return_exceptions=True)

    @staticmethod
    def _current_platform() -> ToolPlatform:
        if sys.platform.startswith("win"):
            return ToolPlatform.WINDOWS
        if sys.platform == "darwin":
            return ToolPlatform.MACOS
        return ToolPlatform.LINUX
