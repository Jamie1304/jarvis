"""Bounded JSON-RPC MCP transports with no access to trusted JARVIS services."""

from __future__ import annotations

import asyncio
import json
import os
import sys
from collections.abc import Mapping
from pathlib import Path

import httpx

from jarvis.computer.process import (
    ProcessIdentityError,
    resolve_trusted_executable,
    trusted_process_environment,
)
from jarvis.mcp.models import MCPExtensionConfig, MCPServerTransport


class MCPProtocolError(RuntimeError):
    """An MCP server returned malformed or unsuccessful protocol data."""


class MCPClient:
    """Small JSON-RPC client; all server output is bounded and untrusted."""

    def __init__(self, config: MCPExtensionConfig) -> None:
        self.config = config
        self._process: asyncio.subprocess.Process | None = None
        self._http: httpx.AsyncClient | None = None
        self._request_id = 0
        self._lock = asyncio.Lock()

    async def start(self) -> None:
        if self.config.transport is MCPServerTransport.STDIO:
            try:
                executable = resolve_trusted_executable(self.config.command[0])
                working_directory = _resolve_working_directory(self.config.working_directory)
            except (OSError, RuntimeError, ProcessIdentityError) as error:
                raise MCPProtocolError(
                    "MCP stdio process identity or working directory is unsafe"
                ) from error
            try:
                self._process = await asyncio.create_subprocess_exec(
                    os.fspath(executable),
                    *self.config.command[1:],
                    stdin=asyncio.subprocess.PIPE,
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.DEVNULL,
                    cwd=os.fspath(working_directory),
                    env=trusted_process_environment(),
                    creationflags=0 if not sys.platform.startswith("win") else 0x08000000,
                )
            except OSError as error:
                raise MCPProtocolError("MCP stdio server could not be started") from error
        else:
            self._http = httpx.AsyncClient(
                timeout=httpx.Timeout(self.config.timeout_seconds),
                trust_env=False,
                follow_redirects=False,
            )
        try:
            await self.request("initialize", {"protocolVersion": "2025-03-26", "capabilities": {}})
        except BaseException:
            await self.close()
            raise

    async def request(self, method: str, params: Mapping[str, object]) -> dict[str, object]:
        if not method or len(method) > 128 or any(ord(char) < 32 for char in method):
            raise MCPProtocolError("MCP method is invalid")
        async with self._lock:
            self._request_id += 1
            request_id = self._request_id
            request = {"jsonrpc": "2.0", "id": request_id, "method": method, "params": dict(params)}
            if self.config.transport is MCPServerTransport.STDIO:
                response = await self._stdio_request(request)
            else:
                response = await self._http_request(request)
        if not isinstance(response, dict) or response.get("jsonrpc") != "2.0":
            raise MCPProtocolError("MCP response envelope is malformed")
        if response.get("id") != request_id or "error" in response:
            raise MCPProtocolError("MCP request failed")
        result = response.get("result")
        if not isinstance(result, dict):
            raise MCPProtocolError("MCP result is malformed")
        return result

    async def list_resources(self) -> tuple[dict[str, object], ...]:
        result = await self.request("resources/list", {})
        resources = result.get("resources")
        if not isinstance(resources, list) or len(resources) > 256:
            raise MCPProtocolError("MCP resource listing is invalid or too large")
        bounded: list[dict[str, object]] = []
        for resource in resources:
            if not isinstance(resource, dict):
                raise MCPProtocolError("MCP resource descriptor is invalid")
            if len(json.dumps(resource, ensure_ascii=True)) > self.config.max_result_bytes:
                raise MCPProtocolError("MCP resource descriptor exceeded its bound")
            bounded.append(resource)
        return tuple(bounded)

    async def read_resource(self, uri: str) -> dict[str, object]:
        if not uri or len(uri) > 2048 or any(ord(char) < 32 for char in uri):
            raise MCPProtocolError("MCP resource URI is invalid")
        result = await self.request("resources/read", {"uri": uri})
        if len(json.dumps(result, ensure_ascii=True)) > self.config.max_result_bytes:
            raise MCPProtocolError("MCP resource result exceeded its bound")
        return result

    async def _stdio_request(self, request: dict[str, object]) -> dict[str, object]:
        if self._process is None or self._process.stdin is None or self._process.stdout is None:
            raise MCPProtocolError("MCP stdio server is not started")
        payload = json.dumps(request, separators=(",", ":")) + "\n"
        self._process.stdin.write(payload.encode("utf-8"))
        await self._process.stdin.drain()
        line = await asyncio.wait_for(
            self._process.stdout.readline(), timeout=self.config.timeout_seconds
        )
        if not line or len(line) > self.config.max_result_bytes:
            raise MCPProtocolError("MCP stdio response exceeded its bound")
        try:
            value = json.loads(line)
        except (UnicodeDecodeError, json.JSONDecodeError) as error:
            raise MCPProtocolError("MCP stdio response is not valid JSON") from error
        if not isinstance(value, dict):
            raise MCPProtocolError("MCP stdio response is not an object")
        return value

    async def _http_request(self, request: dict[str, object]) -> dict[str, object]:
        if self._http is None or self.config.url is None or self.config.bearer_token is None:
            raise MCPProtocolError("MCP HTTP server is not started")
        try:
            response = await self._http.post(
                self.config.url,
                json=request,
                headers={"Authorization": f"Bearer {self.config.bearer_token}"},
            )
            response.raise_for_status()
        except (httpx.HTTPError, TimeoutError) as error:
            raise MCPProtocolError("MCP HTTP request failed") from error
        if len(response.content) > self.config.max_result_bytes:
            raise MCPProtocolError("MCP HTTP response exceeded its bound")
        try:
            value = response.json()
        except ValueError as error:
            raise MCPProtocolError("MCP HTTP response is not valid JSON") from error
        if not isinstance(value, dict):
            raise MCPProtocolError("MCP HTTP response is not an object")
        return value

    async def close(self) -> None:
        if self._http is not None:
            await self._http.aclose()
            self._http = None
        process, self._process = self._process, None
        if process is not None:
            if process.stdin is not None:
                process.stdin.close()
            if process.returncode is None:
                process.terminate()
                try:
                    await asyncio.wait_for(process.wait(), timeout=2)
                except TimeoutError:
                    process.kill()
                    await process.wait()


def _resolve_working_directory(value: Path | None) -> Path:
    if value is None or not value.is_absolute():
        raise MCPProtocolError("MCP stdio requires an absolute working directory")
    current = value
    while True:
        if current.is_symlink() or current.is_junction():
            raise MCPProtocolError("MCP working directory contains a reparse point")
        parent = current.parent
        if parent == current:
            break
        current = parent
    resolved = value.resolve(strict=True)
    if resolved != value or not resolved.is_dir():
        raise MCPProtocolError("MCP working directory is not a private regular directory")
    return resolved
