"""Trusted local lifecycle management and readiness discovery for Ollama."""

from __future__ import annotations

import asyncio
import shutil
import subprocess
from collections.abc import AsyncIterator, Callable
from contextlib import asynccontextmanager
from dataclasses import dataclass
from enum import StrEnum
from pathlib import Path
from typing import Any

import httpx

from jarvis.security import local_model_endpoint_is_safe


class OllamaServerState(StrEnum):
    RUNNING = "running"
    STARTING = "starting"
    UNAVAILABLE = "unavailable"


class OllamaProcessOwnership(StrEnum):
    EXTERNAL = "external"
    JARVIS = "jarvis"
    NONE = "none"


@dataclass(frozen=True, slots=True)
class OllamaRuntimeStatus:
    server: OllamaServerState
    ownership: OllamaProcessOwnership
    installed_models: tuple[str, ...]
    running_models: tuple[str, ...]
    configured_model: str
    configured_model_installed: bool
    configured_model_loaded: bool
    chat_ready: bool
    detail: str


class OllamaRuntimeManager:
    """Probe first, then own at most one explicitly launched local process."""

    def __init__(
        self,
        *,
        endpoint: str,
        model: str,
        autostart: bool,
        executable: Path | None,
        start_timeout_seconds: float,
        stop_owned_on_exit: bool,
        client: httpx.AsyncClient | None = None,
        launcher: Callable[[list[str]], Any] | None = None,
    ) -> None:
        self._endpoint = endpoint.rstrip("/")
        self._model = model
        self._autostart = autostart
        self._executable = executable
        self._start_timeout_seconds = start_timeout_seconds
        self._stop_owned_on_exit = stop_owned_on_exit
        self._client = client
        self._launcher = launcher or self._launch
        self._process: Any | None = None

    async def ensure_running(self) -> OllamaRuntimeStatus:
        """Adopt an existing server or make one bounded launch attempt."""

        status = await self.status()
        if status.server is OllamaServerState.RUNNING:
            return status
        if not self._autostart or not local_model_endpoint_is_safe(self._endpoint):
            return status
        executable = self._resolve_executable()
        if executable is None:
            return self._unavailable("Ollama executable was not found")
        if self._process is None or self._process.poll() is not None:
            self._process = self._launcher([str(executable), "serve"])
        deadline = asyncio.get_running_loop().time() + self._start_timeout_seconds
        while asyncio.get_running_loop().time() < deadline:
            status = await self.status()
            if status.server is OllamaServerState.RUNNING:
                return status
            await asyncio.sleep(0.1)
        return self._unavailable("Ollama did not become reachable before the start timeout")

    async def status(self) -> OllamaRuntimeStatus:
        """Discover server, installed models, loaded models, and chat readiness."""

        try:
            async with self._request_client() as client:
                tags = await client.get(f"{self._endpoint}/api/tags")
                if tags.status_code >= 400:
                    return self._unavailable(f"Ollama health returned HTTP {tags.status_code}")
                installed = self._models(tags.json())
                process_response = await client.get(f"{self._endpoint}/api/ps")
                running = (
                    self._models(process_response.json())
                    if process_response.status_code < 400
                    else ()
                )
        except (httpx.HTTPError, ValueError):
            return self._unavailable("Ollama server is unavailable")
        installed_model = self._model in installed
        loaded_model = self._model in running
        detail = "Chat ready" if installed_model else "Configured model is not installed"
        return OllamaRuntimeStatus(
            OllamaServerState.RUNNING,
            OllamaProcessOwnership.JARVIS
            if self._process is not None
            else OllamaProcessOwnership.EXTERNAL,
            installed,
            running,
            self._model,
            installed_model,
            loaded_model,
            installed_model,
            detail,
        )

    async def aclose(self) -> None:
        """Terminate only the exact process that this manager launched, when configured."""

        process, self._process = self._process, None
        if process is not None and self._stop_owned_on_exit and process.poll() is None:
            process.terminate()
            await asyncio.to_thread(process.wait, 10)

    def _unavailable(self, detail: str) -> OllamaRuntimeStatus:
        return OllamaRuntimeStatus(
            OllamaServerState.UNAVAILABLE,
            OllamaProcessOwnership.JARVIS
            if self._process is not None
            else OllamaProcessOwnership.NONE,
            (),
            (),
            self._model,
            False,
            False,
            False,
            detail,
        )

    def _resolve_executable(self) -> Path | None:
        if self._executable is not None:
            return self._executable if self._executable.is_file() else None
        found = shutil.which("ollama")
        return Path(found) if found else None

    @staticmethod
    def _launch(arguments: list[str]) -> Any:
        return subprocess.Popen(
            arguments,
            shell=False,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )

    @staticmethod
    def _models(payload: object) -> tuple[str, ...]:
        if not isinstance(payload, dict) or not isinstance(payload.get("models"), list):
            return ()
        models: list[str] = []
        for item in payload["models"]:
            if not isinstance(item, dict):
                continue
            value = item.get("name") or item.get("model")
            if type(value) is str and value.strip() and len(value) <= 256 and "\x00" not in value:
                models.append(value)
        return tuple(dict.fromkeys(models))

    @asynccontextmanager
    async def _request_client(self) -> AsyncIterator[httpx.AsyncClient]:
        if self._client is not None:
            yield self._client
        else:
            async with httpx.AsyncClient(timeout=httpx.Timeout(5.0), trust_env=False) as client:
                yield client
