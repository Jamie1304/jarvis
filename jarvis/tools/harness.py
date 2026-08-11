"""Independent test and manual invocation harness for a single tool."""

import asyncio
import logging
from collections.abc import Mapping
from typing import Any
from uuid import UUID, uuid4

from jarvis.tools.base import Tool
from jarvis.tools.models import PermissionContext, ToolCaller, ToolExecutionContext, ToolResult


class ToolHarness:
    """Construct minimal explicit context without bootstrapping the application."""

    def __init__(self, *, logger: logging.Logger | None = None) -> None:
        self._logger = logger or logging.getLogger("jarvis.tools.harness")

    async def invoke(
        self,
        tool: Tool[Any, Any],
        raw_input: Mapping[str, object],
        *,
        task_id: UUID | None = None,
        correlation_id: UUID | None = None,
        caller: ToolCaller = ToolCaller.TEST,
        cancellation: asyncio.Event | None = None,
        permissions: PermissionContext | None = None,
    ) -> ToolResult:
        """Invoke a tool with only its declared execution context."""

        context = ToolExecutionContext(
            task_id=task_id or uuid4(),
            correlation_id=correlation_id or uuid4(),
            caller=caller,
            cancellation=cancellation or asyncio.Event(),
            permissions=permissions or PermissionContext(),
            logger=self._logger,
        )
        return await tool.invoke(context, raw_input)
