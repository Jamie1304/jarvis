"""Native MCP ExtensionManager: discovery, validation, lifecycle, and cleanup."""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass

from jarvis.mcp.adapter import MCPToolAdapter, input_model_from_schema
from jarvis.mcp.client import MCPClient, MCPProtocolError
from jarvis.mcp.models import MCPExtensionConfig, MCPExtensionState
from jarvis.tools.registry import ToolRegistry


@dataclass(frozen=True, slots=True)
class MCPExtensionStatus:
    extension_id: str
    state: MCPExtensionState
    detail: str
    tool_ids: tuple[str, ...] = ()


class MCPExtensionManager:
    """Own configured MCP clients and register only validated adapters."""

    def __init__(
        self,
        registry: ToolRegistry,
        *,
        client_factory: Callable[[MCPExtensionConfig], MCPClient] | None = None,
    ) -> None:
        self._registry = registry
        self._client_factory = client_factory or MCPClient
        self._configs: dict[str, MCPExtensionConfig] = {}
        self._clients: dict[str, MCPClient] = {}
        self._statuses: dict[str, MCPExtensionStatus] = {}
        self._tool_ids: dict[str, tuple[str, ...]] = {}

    def discover(self, configs: tuple[MCPExtensionConfig, ...]) -> tuple[MCPExtensionStatus, ...]:
        """Validate local configuration and expose only DISCOVERED extensions."""

        for config in configs:
            if config.extension_id in self._configs:
                raise ValueError("Duplicate MCP extension ID")
            self._configs[config.extension_id] = config
            self._statuses[config.extension_id] = MCPExtensionStatus(
                config.extension_id, MCPExtensionState.DISCOVERED, "Configuration discovered"
            )
        return self.statuses()

    async def start(self, extension_id: str) -> MCPExtensionStatus:
        config = self._configs[extension_id]
        if not config.enabled:
            return self._set_status(
                extension_id, MCPExtensionState.STOPPED, "Disabled by local configuration"
            )
        if self._registry.sealed:
            return self._set_status(
                extension_id, MCPExtensionState.FAILED, "Tool registry is already sealed"
            )
        self._set_status(extension_id, MCPExtensionState.CONFIGURED, "Configuration validated")
        client = self._client_factory(config)
        self._clients[extension_id] = client
        self._set_status(extension_id, MCPExtensionState.STARTING, "Starting MCP transport")
        try:
            await client.start()
            listing = await client.request("tools/list", {})
            tools = listing.get("tools")
            if not isinstance(tools, list) or len(tools) > config.max_tools:
                raise MCPProtocolError("MCP tool listing is invalid or too large")
            adapters: list[MCPToolAdapter] = []
            for descriptor in tools:
                if not isinstance(descriptor, dict):
                    raise MCPProtocolError("MCP tool descriptor is invalid")
                name = descriptor.get("name")
                description = descriptor.get("description", "")
                schema = descriptor.get("inputSchema", {})
                if (
                    not isinstance(name, str)
                    or not isinstance(description, str)
                    or not isinstance(schema, dict)
                ):
                    raise MCPProtocolError("MCP tool descriptor fields are invalid")
                adapter = MCPToolAdapter(
                    config,
                    client,
                    name,
                    description,
                    input_model_from_schema(schema),
                )
                if any(
                    manifest.tool_id == adapter.manifest.tool_id
                    for manifest in self._registry.manifests()
                ) or any(item.manifest.tool_id == adapter.manifest.tool_id for item in adapters):
                    raise MCPProtocolError("MCP tool namespace collision")
                adapters.append(adapter)
            for adapter in adapters:
                self._registry.register(adapter)
            tool_ids = tuple(adapter.manifest.tool_id for adapter in adapters)
            self._tool_ids[extension_id] = tool_ids
            return self._set_status(
                extension_id, MCPExtensionState.HEALTHY, "MCP tools registered", tool_ids
            )
        except Exception:
            await client.close()
            self._clients.pop(extension_id, None)
            return self._set_status(extension_id, MCPExtensionState.FAILED, "MCP startup failed")

    async def stop(self, extension_id: str) -> MCPExtensionStatus:
        client = self._clients.pop(extension_id, None)
        for tool_id in self._tool_ids.pop(extension_id, ()):
            self._registry.unregister(tool_id)
        if client is not None:
            await client.close()
        return self._set_status(extension_id, MCPExtensionState.STOPPED, "MCP extension stopped")

    async def health_check(self, extension_id: str) -> MCPExtensionStatus:
        client = self._clients.get(extension_id)
        if client is None:
            return self._set_status(
                extension_id, MCPExtensionState.DEGRADED, "MCP client is not running"
            )
        try:
            await client.request("ping", {})
        except MCPProtocolError:
            return self._set_status(
                extension_id, MCPExtensionState.DEGRADED, "MCP health check failed"
            )
        return self._set_status(
            extension_id,
            MCPExtensionState.HEALTHY,
            "MCP server is responsive",
            self._tool_ids.get(extension_id, ()),
        )

    async def list_resources(self, extension_id: str) -> tuple[dict[str, object], ...]:
        client = self._clients.get(extension_id)
        if client is None:
            raise MCPProtocolError("MCP extension is not running")
        return await client.list_resources()

    async def read_resource(self, extension_id: str, uri: str) -> dict[str, object]:
        client = self._clients.get(extension_id)
        if client is None:
            raise MCPProtocolError("MCP extension is not running")
        return await client.read_resource(uri)

    def invalidate_cache(self, extension_id: str) -> None:
        self._tool_ids.pop(extension_id, None)

    def statuses(self) -> tuple[MCPExtensionStatus, ...]:
        return tuple(self._statuses[key] for key in sorted(self._statuses))

    async def close(self) -> None:
        for extension_id in tuple(self._clients):
            await self.stop(extension_id)

    def _set_status(
        self,
        extension_id: str,
        state: MCPExtensionState,
        detail: str,
        tool_ids: tuple[str, ...] = (),
    ) -> MCPExtensionStatus:
        status = MCPExtensionStatus(extension_id, state, detail, tool_ids)
        self._statuses[extension_id] = status
        return status
