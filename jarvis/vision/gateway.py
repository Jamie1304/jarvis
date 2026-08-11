"""Narrow integration point from visual workflow to registered brokered tools."""

import asyncio
import logging
from collections.abc import Mapping
from uuid import UUID, uuid4

from jarvis.core.errors import CapabilityUnavailableError
from jarvis.tools.models import ToolCaller, ToolExecutionContext, ToolResult, ToolResultStatus
from jarvis.tools.registry import ToolRegistry


class BrokeredToolInvoker:
    """Invoke only registered tools, preserving the Phase 5 authorization boundary."""

    def __init__(self, registry: ToolRegistry, *, logger: logging.Logger | None = None) -> None:
        self._registry = registry
        self._logger = logger or logging.getLogger("jarvis.vision.gateway")

    async def invoke(
        self,
        tool_id: str,
        raw_input: Mapping[str, object],
        *,
        task_id: UUID,
        cancellation: asyncio.Event,
        user_id: str | None,
    ) -> ToolResult:
        try:
            tool = self._registry.get(tool_id)
        except CapabilityUnavailableError:
            return ToolResult.failure(
                ToolResultStatus.UNAVAILABLE,
                "visual_tool_unavailable",
                "Required controlled computer tool is unavailable",
            )
        context = ToolExecutionContext(
            task_id=task_id,
            correlation_id=uuid4(),
            caller=ToolCaller.AGENT,
            cancellation=cancellation,
            logger=self._logger,
            user_id=user_id,
        )
        return await tool.invoke(context, raw_input, self._registry.permission_broker)
