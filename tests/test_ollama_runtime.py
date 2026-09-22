from __future__ import annotations

from pathlib import Path
from typing import Any

import httpx
import pytest
from jarvis.ai.providers.ollama_runtime import (
    OllamaProcessOwnership,
    OllamaRuntimeManager,
    OllamaServerState,
)


def _manager(handler: httpx.MockTransport, **kwargs: Any) -> OllamaRuntimeManager:
    return OllamaRuntimeManager(
        endpoint="http://127.0.0.1:11434",
        model="configured:latest",
        autostart=True,
        executable=None,
        start_timeout_seconds=0.2,
        stop_owned_on_exit=False,
        client=httpx.AsyncClient(transport=handler),
        **kwargs,
    )


@pytest.mark.asyncio
async def test_reachable_ollama_is_adopted_without_a_second_launch() -> None:
    launched: list[list[str]] = []

    def handler(request: httpx.Request) -> httpx.Response:
        payload = {"models": [{"name": "configured:latest"}]}
        return httpx.Response(200, json=payload)

    manager = _manager(httpx.MockTransport(handler), launcher=launched.append)
    status = await manager.ensure_running()

    assert status.server is OllamaServerState.RUNNING
    assert status.ownership is OllamaProcessOwnership.EXTERNAL
    assert status.chat_ready is True
    assert launched == []


@pytest.mark.asyncio
async def test_model_discovery_distinguishes_installed_running_and_chat_ready() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/api/tags":
            return httpx.Response(200, json={"models": [{"name": "other:latest"}]})
        return httpx.Response(200, json={"models": [{"model": "other:latest"}]})

    manager = _manager(httpx.MockTransport(handler))
    status = await manager.status()

    assert status.installed_models == ("other:latest",)
    assert status.running_models == ("other:latest",)
    assert status.configured_model_installed is False
    assert status.chat_ready is False


@pytest.mark.asyncio
async def test_unavailable_ollama_makes_one_owned_launch_attempt() -> None:
    requests = 0

    class Process:
        def poll(self) -> None:
            return None

    def handler(request: httpx.Request) -> httpx.Response:
        nonlocal requests
        requests += 1
        if requests == 1:
            raise httpx.ConnectError("offline", request=request)
        return httpx.Response(200, json={"models": [{"name": "configured:latest"}]})

    launched: list[list[str]] = []

    def launch(arguments: list[str]) -> Process:
        launched.append(arguments)
        return Process()

    manager = OllamaRuntimeManager(
        endpoint="http://127.0.0.1:11434",
        model="configured:latest",
        autostart=True,
        executable=Path(__file__),
        start_timeout_seconds=0.2,
        stop_owned_on_exit=False,
        client=httpx.AsyncClient(transport=httpx.MockTransport(handler)),
        launcher=launch,
    )

    status = await manager.ensure_running()

    assert status.server is OllamaServerState.RUNNING
    assert status.ownership is OllamaProcessOwnership.JARVIS
    assert len(launched) == 1
