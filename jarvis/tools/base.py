"""Schema-validated, versioned tool execution boundary."""

import asyncio
import sys
from abc import ABC, abstractmethod
from collections.abc import Mapping
from dataclasses import replace
from typing import Generic, TypeVar

from pydantic import ValidationError

from jarvis.events import EventBus, EventEnvelope, EventType, ToolCompleted, ToolFailed, ToolStarted
from jarvis.permissions.broker import PermissionBroker
from jarvis.permissions.models import ActionDescriptor, Risk
from jarvis.tools.models import (
    ToolExecutionContext,
    ToolHealth,
    ToolHealthStatus,
    ToolInput,
    ToolManifest,
    ToolMetadata,
    ToolOutput,
    ToolPlatform,
    ToolResult,
    ToolResultStatus,
)

InputModel = TypeVar("InputModel", bound=ToolInput)
OutputModel = TypeVar("OutputModel", bound=ToolOutput)


class Tool(ABC, Generic[InputModel, OutputModel]):
    """A versioned capability that validates untrusted arguments before execution."""

    def __init_subclass__(cls, **kwargs: object) -> None:
        """Make bypasses conspicuous by reserving the public brokered entry point."""

        super().__init_subclass__(**kwargs)
        if "invoke" in cls.__dict__:
            raise TypeError("Tools cannot override the brokered invoke boundary")
        if "execute" in cls.__dict__:
            raise TypeError("Tool implementations must use _execute_authorized")

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
    async def _execute_authorized(
        self, context: ToolExecutionContext, validated_input: InputModel
    ) -> ToolResult:
        """Execute only after the base class attaches a broker-minted receipt."""

    def _describe_action(
        self, context: ToolExecutionContext, validated_input: InputModel
    ) -> ActionDescriptor:
        """Build trusted approval data; privileged tools must override this hook."""

        del context, validated_input
        return ActionDescriptor(
            action=f"invoke:{self.manifest.tool_id}",
            arguments_summary=(),
            risk=Risk.LOW,
            permissions=(),
        )

    async def health_check(self) -> ToolHealth:
        """Report whether the tool can currently be invoked."""

        return ToolHealth(ToolHealthStatus.AVAILABLE, "Tool is available")

    async def invoke(
        self,
        context: ToolExecutionContext,
        raw_input: Mapping[str, object],
        broker: PermissionBroker,
        *,
        event_bus: EventBus | None = None,
    ) -> ToolResult:
        """Validate then authorize an exact action before private implementation execution."""

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
        if not self.manifest.enabled:
            return ToolResult.failure(
                ToolResultStatus.UNAVAILABLE,
                "tool_disabled",
                "Tool is disabled by trusted registration metadata",
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
        if context.authorization is not None:
            return ToolResult.failure(
                ToolResultStatus.PERMISSION_DENIED,
                "caller_supplied_authorization",
                "Callers cannot supply authorization receipts",
            )
        descriptor = self._describe_action(context, validated_input)
        authorization = await broker.authorize(
            tool_id=self.manifest.tool_id,
            tool_identity=self,
            declared_permissions=self.manifest.declared_permissions,
            task_id=context.task_id,
            user_id=context.user_id,
            descriptor=descriptor,
            normalized_arguments=validated_input.model_dump(mode="json"),
        )
        if not authorization.authorized or authorization.receipt is None:
            if event_bus is not None:
                event_bus.publish_nowait(
                    EventEnvelope.create(
                        EventType.TOOL_FAILED,
                        ToolFailed(self.manifest.tool_id, authorization.reason.value),
                        source="tool.invoke",
                        task_id=context.task_id,
                        correlation_id=context.correlation_id,
                    )
                )
            metadata = tuple(
                ToolMetadata("approval_request_id", str(request.request_id))
                for request in authorization.approval_requests
            )
            return ToolResult.failure(
                ToolResultStatus.PERMISSION_DENIED,
                authorization.reason.value,
                "Permission broker denied execution or requires trusted user approval",
                metadata=metadata,
            )
        if event_bus is not None:
            event_bus.publish_nowait(
                EventEnvelope.create(
                    EventType.TOOL_STARTED,
                    ToolStarted(self.manifest.tool_id),
                    source="tool.invoke",
                    task_id=context.task_id,
                    correlation_id=context.correlation_id,
                )
            )
        authorized_context = replace(context, authorization=authorization.receipt)
        health = await self.health_check()
        if health.status is ToolHealthStatus.UNAVAILABLE:
            result = ToolResult.failure(
                ToolResultStatus.UNAVAILABLE,
                "tool_unavailable",
                health.detail,
            )
            await broker.record_execution_outcome(authorization.receipt, result.status.value)
            return result
        try:
            async with asyncio.timeout(self.manifest.timeout_seconds):
                result = await self._execute_or_cancel(authorized_context, validated_input)
        except TimeoutError:
            result = ToolResult.failure(
                ToolResultStatus.TIMEOUT,
                "tool_timeout",
                "Tool exceeded its declared timeout",
            )
        except asyncio.CancelledError:
            result = ToolResult.failure(
                ToolResultStatus.CANCELLED,
                "tool_cancelled",
                "Tool invocation was cancelled",
            )
        except Exception:
            context.logger.exception("Tool %s failed internally", self.manifest.tool_id)
            result = ToolResult.failure(
                ToolResultStatus.INTERNAL_FAILURE,
                "tool_internal_failure",
                "Tool failed internally; diagnostic details were logged",
            )
        if context.cancellation.is_set() and result.succeeded:
            result = ToolResult.failure(
                ToolResultStatus.CANCELLED,
                "tool_cancelled",
                "Tool invocation was cancelled",
            )
        await broker.record_execution_outcome(authorization.receipt, result.status.value)
        if event_bus is not None:
            payload: ToolCompleted | ToolFailed
            event_type: EventType
            if result.succeeded:
                payload = ToolCompleted(self.manifest.tool_id, result.status.value)
                event_type = EventType.TOOL_COMPLETED
            else:
                payload = ToolFailed(
                    self.manifest.tool_id,
                    result.error.code if result.error is not None else result.status.value,
                )
                event_type = EventType.TOOL_FAILED
            event_bus.publish_nowait(
                EventEnvelope.create(
                    event_type,
                    payload,
                    source="tool.invoke",
                    task_id=context.task_id,
                    correlation_id=context.correlation_id,
                )
            )
        return result

    async def _execute_or_cancel(
        self, context: ToolExecutionContext, validated_input: InputModel
    ) -> ToolResult:
        execution_task = asyncio.create_task(self._execute_authorized(context, validated_input))
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
