"""Independent test and manual invocation harness for a single tool."""

import asyncio
import logging
from collections.abc import Mapping
from typing import Any
from uuid import UUID, uuid4

from jarvis.permissions.broker import PermissionBroker
from jarvis.permissions.policy import PolicyEngine
from jarvis.tools.base import Tool
from jarvis.tools.models import ToolCaller, ToolExecutionContext, ToolResult


class ToolHarness:
    """Construct minimal explicit context without bootstrapping the application."""

    def __init__(
        self,
        *,
        logger: logging.Logger | None = None,
        broker: PermissionBroker | None = None,
    ) -> None:
        self._logger = logger or logging.getLogger("jarvis.tools.harness")
        self._broker = broker

    async def invoke(
        self,
        tool: Tool[Any, Any],
        raw_input: Mapping[str, object],
        *,
        task_id: UUID | None = None,
        correlation_id: UUID | None = None,
        caller: ToolCaller = ToolCaller.TEST,
        cancellation: asyncio.Event | None = None,
        user_id: str | None = "test-user",
    ) -> ToolResult:
        """Invoke a tool with only its declared execution context."""

        broker = self._broker or PermissionBroker(PolicyEngine())
        broker.register_tool(tool.manifest.tool_id, tool, tool.manifest.declared_permissions)
        context = ToolExecutionContext(
            task_id=task_id or uuid4(),
            correlation_id=correlation_id or uuid4(),
            caller=caller,
            cancellation=cancellation or asyncio.Event(),
            logger=self._logger,
            user_id=user_id,
        )
        return await tool.invoke(context, raw_input, broker)
