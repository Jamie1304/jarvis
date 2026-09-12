from __future__ import annotations

import asyncio
import logging
import sys
from collections.abc import Mapping
from pathlib import Path
from typing import cast
from uuid import uuid4

import httpx
import pytest
from jarvis.mcp.adapter import MCPToolOutput, _bounded_output, input_model_from_schema
from jarvis.mcp.client import MCPClient, MCPProtocolError
from jarvis.mcp.manager import MCPExtensionManager
from jarvis.mcp.models import MCPExtensionConfig, MCPExtensionState, MCPServerTransport
from jarvis.permissions.models import Permission
from jarvis.tools.models import ToolCaller, ToolExecutionContext, ToolResultStatus
from jarvis.tools.registry import ToolRegistry


class FakeClient:
    def __init__(self, config: MCPExtensionConfig) -> None:
        self.config = config
        self.closed = False

    async def start(self) -> None:
        return None

    async def request(self, method: str, params: dict[str, object]) -> dict[str, object]:
        del params
        if method == "tools/list":
            return {
                "tools": [
                    {
                        "name": "echo",
                        "description": "untrusted description",
                        "inputSchema": {
                            "type": "object",
                            "properties": {"text": {"type": "string"}},
                            "required": ["text"],
                        },
                    }
                ]
            }
        if method == "tools/call":
            return {"content": [{"type": "text", "text": "external data"}]}
        if method == "resources/list":
            return {"resources": [{"uri": "memory://safe", "name": "safe"}]}
        if method == "resources/read":
            return {"contents": [{"uri": "memory://safe", "text": "external data"}]}
        return {}

    async def close(self) -> None:
        self.closed = True


class MaliciousSchemaClient(FakeClient):
    async def request(self, method: str, params: dict[str, object]) -> dict[str, object]:
        if method == "tools/list":
            return {
                "tools": [
                    {
                        "name": "../escape",
                        "description": "x\nforged policy",
                        "inputSchema": {"type": "array"},
                    }
                ]
            }
        return await super().request(method, params)


class DuplicateToolsClient(FakeClient):
    async def request(self, method: str, params: dict[str, object]) -> dict[str, object]:
        if method == "tools/list":
            descriptor = {
                "name": "duplicate",
                "description": "synthetic duplicate",
                "inputSchema": {"type": "object"},
            }
            return {"tools": [descriptor, descriptor.copy()]}
        return await super().request(method, params)


class BrokenClient(FakeClient):
    async def start(self) -> None:
        raise RuntimeError("fake transport failure")


class BadResponseClient(FakeClient):
    async def request(self, method: str, params: dict[str, object]) -> dict[str, object]:
        del params
        if method == "tools/list":
            return {"tools": "not a list"}
        return {}


class BadResultClient(FakeClient):
    async def request(self, method: str, params: dict[str, object]) -> dict[str, object]:
        if method == "tools/call":
            return {"content": "malformed"}
        return await super().request(method, params)


class UnhealthyClient(FakeClient):
    async def request(self, method: str, params: dict[str, object]) -> dict[str, object]:
        if method == "ping":
            raise MCPProtocolError("offline")
        return await super().request(method, params)


class ResourceClient(MCPClient):
    async def start(self) -> None:
        return None

    async def request(self, method: str, params: Mapping[str, object]) -> dict[str, object]:
        del params
        if method == "tools/list":
            return {
                "tools": [
                    {
                        "name": "resource-tool",
                        "description": "ignored",
                        "inputSchema": {"type": "object"},
                    }
                ]
            }
        if method == "resources/list":
            return {"resources": [{"uri": "memory://safe", "name": "safe"}]}
        return {"contents": [{"uri": "memory://safe", "text": "external data"}]}


def config(extension_id: str = "owned") -> MCPExtensionConfig:
    return MCPExtensionConfig(
        extension_id=extension_id,
        transport=MCPServerTransport.STDIO,
        command=("owned-server",),
        permissions=frozenset({Permission.NETWORK_REQUEST}),
    )


@pytest.mark.asyncio
async def test_mcp_discovery_adapter_is_brokered_and_stops() -> None:
    registry = ToolRegistry()
    clients: list[FakeClient] = []

    def factory(item: MCPExtensionConfig) -> FakeClient:
        client = FakeClient(item)
        clients.append(client)
        return client

    manager = MCPExtensionManager(
        registry, client_factory=lambda item: cast(MCPClient, factory(item))
    )
    manager.discover((config(),))
    status = await manager.start("owned")
    assert status.state is MCPExtensionState.HEALTHY
    assert status.tool_ids == ("mcp:owned:echo",)
    context = ToolExecutionContext(
        task_id=uuid4(),
        correlation_id=uuid4(),
        caller=ToolCaller.TEST,
        cancellation=asyncio.Event(),
        logger=logging.getLogger("test"),
    )
    result = await registry.get("mcp:owned:echo").invoke(
        context, {"text": "hello"}, registry.permission_broker
    )
    assert result.status is ToolResultStatus.PERMISSION_DENIED
    await manager.stop("owned")
    assert clients[0].closed
    assert manager.statuses()[0].state is MCPExtensionState.STOPPED


@pytest.mark.asyncio
async def test_mcp_malicious_schema_fails_closed() -> None:
    registry = ToolRegistry()
    manager = MCPExtensionManager(
        registry,
        client_factory=lambda item: cast(MCPClient, MaliciousSchemaClient(item)),
    )
    manager.discover((config("hostile"),))
    status = await manager.start("hostile")
    assert status.state is MCPExtensionState.FAILED
    assert registry.manifests() == ()


@pytest.mark.asyncio
async def test_mcp_namespace_collision_fails_closed_without_partial_registration() -> None:
    registry = ToolRegistry()
    manager = MCPExtensionManager(
        registry,
        client_factory=lambda item: cast(MCPClient, DuplicateToolsClient(item)),
    )
    manager.discover((config("collision"),))
    status = await manager.start("collision")
    assert status.state is MCPExtensionState.FAILED
    assert registry.manifests() == ()
    await manager.close()


@pytest.mark.asyncio
async def test_mcp_unprivileged_result_and_health() -> None:
    # An unprivileged MCP result still uses the normal Tool boundary.
    safe_registry = ToolRegistry()
    manager = MCPExtensionManager(
        safe_registry,
        client_factory=lambda item: cast(MCPClient, FakeClient(item)),
    )
    manager.discover(
        (
            MCPExtensionConfig(
                "safe",
                MCPServerTransport.STDIO,
                command=("owned-server",),
            ),
        )
    )
    await manager.start("safe")
    result = await safe_registry.get("mcp:safe:echo").invoke(
        ToolExecutionContext(
            task_id=uuid4(),
            correlation_id=uuid4(),
            caller=ToolCaller.TEST,
            cancellation=asyncio.Event(),
            logger=logging.getLogger("test"),
        ),
        {"text": "hello"},
        safe_registry.permission_broker,
    )
    assert result.succeeded
    assert result.output is not None
    assert cast(MCPToolOutput, result.output).text == "external data"
    assert (await manager.health_check("safe")).state is MCPExtensionState.HEALTHY
    await manager.close()


@pytest.mark.asyncio
async def test_mcp_http_auth_and_bounds() -> None:
    config_value = MCPExtensionConfig(
        "http",
        MCPServerTransport.HTTP,
        url="http://127.0.0.1:8000",
        bearer_token="secret",
    )
    client = MCPClient(config_value)

    def handler(request: httpx.Request) -> httpx.Response:
        assert request.headers["authorization"] == "Bearer secret"
        return httpx.Response(
            200,
            json={"jsonrpc": "2.0", "id": 1, "result": {"ok": True}},
        )

    client._http = httpx.AsyncClient(transport=httpx.MockTransport(handler))
    assert await client.request("ping", {}) == {"ok": True}
    await client.close()
    with pytest.raises(ValueError):
        _bounded_output({"content": [{"type": "image", "data": "x"}]}, 128)
    with pytest.raises(ValueError):
        _bounded_output({"content": [{"type": "text", "text": "x" * 129}]}, 128)
    with pytest.raises(ValueError):
        _bounded_output({"content": [], "structuredContent": []}, 128)


@pytest.mark.asyncio
async def test_mcp_http_failures_and_invalid_requests() -> None:
    config_value = MCPExtensionConfig(
        "httpfail",
        MCPServerTransport.HTTP,
        url="https://example.com/mcp",
        bearer_token="secret",
        max_result_bytes=32,
    )
    client = MCPClient(config_value)
    with pytest.raises(MCPProtocolError):
        await client.request("ping", {})
    with pytest.raises(MCPProtocolError):
        await client.request("", {})

    def invalid_json(_: httpx.Request) -> httpx.Response:
        return httpx.Response(200, content=b"not json")

    client._http = httpx.AsyncClient(transport=httpx.MockTransport(invalid_json))
    with pytest.raises(MCPProtocolError):
        await client.request("ping", {})
    await client.close()

    def too_large(_: httpx.Request) -> httpx.Response:
        return httpx.Response(200, content=b"x" * 33)

    client._http = httpx.AsyncClient(transport=httpx.MockTransport(too_large))
    with pytest.raises(MCPProtocolError):
        await client.request("ping", {})
    await client.close()

    with pytest.raises(ValueError):
        MCPExtensionConfig("fast", MCPServerTransport.STDIO, command=("x",), timeout_seconds=0)
    with pytest.raises(ValueError):
        MCPExtensionConfig(
            "large", MCPServerTransport.STDIO, command=("x",), max_result_bytes=2_000_000
        )
    with pytest.raises(ValueError):
        MCPExtensionConfig(
            "credentialed", MCPServerTransport.STDIO, command=("x",), bearer_token="secret"
        )


@pytest.mark.asyncio
async def test_mcp_stdio_round_trip_and_protocol_failures(tmp_path: Path) -> None:
    server = (
        "import sys,json\n"
        "for line in sys.stdin:\n"
        "    r=json.loads(line)\n"
        "    print(json.dumps({'jsonrpc':'2.0','id':r['id'],'result':{}}),flush=True)\n"
    )
    config_value = MCPExtensionConfig(
        "stdio",
        MCPServerTransport.STDIO,
        command=(sys.executable, "-c", server),
        working_directory=tmp_path,
    )
    client = MCPClient(config_value)
    await client.start()
    assert await client.request("ping", {}) == {}
    await client.close()
    with pytest.raises(MCPProtocolError):
        await client.request("ping", {})


@pytest.mark.asyncio
async def test_mcp_stdio_rejects_ambiguous_process_identity_and_cwd(tmp_path: Path) -> None:
    relative = MCPClient(
        MCPExtensionConfig(
            "relative",
            MCPServerTransport.STDIO,
            command=("python.exe",),
            working_directory=tmp_path,
        )
    )
    with pytest.raises(MCPProtocolError, match="identity"):
        await relative.start()

    missing_cwd = MCPClient(
        MCPExtensionConfig("no-cwd", MCPServerTransport.STDIO, command=(sys.executable,))
    )
    with pytest.raises(MCPProtocolError, match="working directory"):
        await missing_cwd.start()


@pytest.mark.asyncio
async def test_mcp_start_failure_closes_started_process(tmp_path: Path) -> None:
    server = "import time; print('{}', flush=True); time.sleep(60)"
    client = MCPClient(
        MCPExtensionConfig(
            "bad-init",
            MCPServerTransport.STDIO,
            command=(sys.executable, "-c", server),
            working_directory=tmp_path,
        )
    )

    with pytest.raises(MCPProtocolError):
        await client.start()

    assert client._process is None


def test_mcp_schema_validation_and_config_states(tmp_path: Path) -> None:
    model = input_model_from_schema(
        {
            "type": "object",
            "properties": {
                "count": {"type": "integer"},
                "flag": {"type": "boolean"},
                "values": {"type": "array"},
            },
            "required": ["count"],
        }
    )
    assert model.model_validate({"count": 2, "flag": True, "values": []}, strict=True)
    with pytest.raises(ValueError):
        input_model_from_schema({"type": "object", "required": ["missing"]})
    with pytest.raises(ValueError):
        input_model_from_schema({"type": "array"})
    with pytest.raises(ValueError):
        input_model_from_schema({"type": "object", "properties": []})
    with pytest.raises(ValueError):
        input_model_from_schema({"type": "object", "properties": {"bad-name": {}}})
    with pytest.raises(ValueError):
        input_model_from_schema({"type": "object", "properties": {"bad": {"type": 1}}})
    with pytest.raises(ValueError):
        MCPExtensionConfig(
            "stdio",
            MCPServerTransport.STDIO,
            command=("x",),
            working_directory=tmp_path / "missing",
        )
    with pytest.raises(ValueError):
        MCPExtensionConfig("many", MCPServerTransport.STDIO, command=("x",), max_tools=2_000)
    with pytest.raises(ValueError):
        MCPExtensionConfig(
            "permissions",
            MCPServerTransport.STDIO,
            command=("x",),
            permissions=frozenset({"fake"}),  # type: ignore[arg-type]
        )


@pytest.mark.asyncio
async def test_mcp_optional_resources_are_bounded_data() -> None:
    client = ResourceClient(config("resources"))
    assert await client.list_resources() == (({"uri": "memory://safe", "name": "safe"}),)
    assert (await client.read_resource("memory://safe"))["contents"]
    with pytest.raises(MCPProtocolError):
        await client.read_resource("bad\nuri")

    registry = ToolRegistry()
    manager = MCPExtensionManager(registry, client_factory=lambda item: client)
    manager.discover((config("resource-manager"),))
    await manager.start("resource-manager")
    assert await manager.list_resources("resource-manager")
    assert await manager.read_resource("resource-manager", "memory://safe")
    manager.invalidate_cache("resource-manager")
    await manager.close()


@pytest.mark.asyncio
async def test_mcp_manager_rejects_sealed_registry_and_bad_descriptors() -> None:
    sealed = ToolRegistry()
    sealed.seal()
    manager = MCPExtensionManager(
        sealed,
        client_factory=lambda item: cast(MCPClient, FakeClient(item)),
    )
    manager.discover((config("sealed"),))
    assert (await manager.start("sealed")).state is MCPExtensionState.FAILED

    class DescriptorClient(FakeClient):
        async def request(self, method: str, params: dict[str, object]) -> dict[str, object]:
            if method == "tools/list":
                return {"tools": ["not an object"]}
            return await super().request(method, params)

    bad = MCPExtensionManager(
        ToolRegistry(),
        client_factory=lambda item: cast(MCPClient, DescriptorClient(item)),
    )
    bad.discover((config("descriptor"),))
    assert (await bad.start("descriptor")).state is MCPExtensionState.FAILED


@pytest.mark.asyncio
async def test_mcp_manager_disabled_duplicate_and_degraded_states() -> None:
    registry = ToolRegistry()
    manager = MCPExtensionManager(
        registry,
        client_factory=lambda item: cast(MCPClient, FakeClient(item)),
    )
    disabled = MCPExtensionConfig(
        "disabled", MCPServerTransport.STDIO, command=("x",), enabled=False
    )
    manager.discover((disabled,))
    assert (await manager.start("disabled")).state is MCPExtensionState.STOPPED
    with pytest.raises(ValueError):
        manager.discover((disabled,))
    assert (await manager.health_check("missing")).state is MCPExtensionState.DEGRADED


@pytest.mark.asyncio
async def test_mcp_manager_startup_failures_and_http_config() -> None:
    assert (
        MCPExtensionConfig(
            "secure", MCPServerTransport.HTTP, url="https://example.com/mcp", bearer_token="secret"
        ).transport
        is MCPServerTransport.HTTP
    )
    manager = MCPExtensionManager(
        ToolRegistry(),
        client_factory=lambda item: cast(MCPClient, BrokenClient(item)),
    )
    manager.discover((config("broken"),))
    assert (await manager.start("broken")).state is MCPExtensionState.FAILED

    bad_manager = MCPExtensionManager(
        ToolRegistry(),
        client_factory=lambda item: cast(MCPClient, BadResponseClient(item)),
    )
    bad_manager.discover((config("bad"),))
    assert (await bad_manager.start("bad")).state is MCPExtensionState.FAILED

    unhealthy = MCPExtensionManager(
        ToolRegistry(),
        client_factory=lambda item: cast(MCPClient, UnhealthyClient(item)),
    )
    unhealthy.discover((config("unhealthy"),))
    assert (await unhealthy.start("unhealthy")).state is MCPExtensionState.HEALTHY
    assert (await unhealthy.health_check("unhealthy")).state is MCPExtensionState.DEGRADED


@pytest.mark.asyncio
async def test_mcp_malformed_result_fails_closed() -> None:
    registry = ToolRegistry()
    manager = MCPExtensionManager(
        registry,
        client_factory=lambda item: cast(MCPClient, BadResultClient(item)),
    )
    manager.discover((MCPExtensionConfig("badresult", MCPServerTransport.STDIO, command=("x",)),))
    await manager.start("badresult")
    result = await registry.get("mcp:badresult:echo").invoke(
        ToolExecutionContext(
            task_id=uuid4(),
            correlation_id=uuid4(),
            caller=ToolCaller.TEST,
            cancellation=asyncio.Event(),
            logger=logging.getLogger("test"),
        ),
        {"text": "hello"},
        registry.permission_broker,
    )
    assert result.status is ToolResultStatus.INTERNAL_FAILURE


def test_mcp_config_rejects_unsafe_http_and_invalid_stdio(tmp_path: Path) -> None:
    with pytest.raises(ValueError):
        MCPExtensionConfig("bad id", MCPServerTransport.STDIO, command=("x",))
    with pytest.raises(ValueError):
        MCPExtensionConfig(
            "remote", MCPServerTransport.HTTP, url="http://example.com", bearer_token="secret"
        )
    with pytest.raises(ValueError):
        MCPExtensionConfig(
            "local",
            MCPServerTransport.HTTP,
            url="http://127.0.0.1:8000?unsafe=true",
            bearer_token="secret",
        )
    with pytest.raises(ValueError):
        MCPExtensionConfig(
            "stdio",
            MCPServerTransport.STDIO,
            command=("x",),
            working_directory=tmp_path / "missing",
        )
