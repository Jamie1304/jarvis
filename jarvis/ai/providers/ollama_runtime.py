"""Trusted local lifecycle management and readiness discovery for Ollama."""

from __future__ import annotations

import asyncio
import json
import shutil
import subprocess
import time
from collections.abc import AsyncIterator, Callable
from contextlib import asynccontextmanager
from dataclasses import dataclass
from datetime import UTC, datetime
from enum import StrEnum
from pathlib import Path
from typing import Any

import httpx

from jarvis.ai.model_manager import (
    LocalModelSpec,
    ModelArtifact,
    ModelHealth,
    ModelRemovalUnknownOutcome,
    ProviderModelAdapter,
)
from jarvis.ai.models import EvidenceKind, EvidenceRecord, ModelRole
from jarvis.ai.providers.registry import ModelMetadata, ProviderLocality, ProviderMetadata
from jarvis.core.errors import ProviderError, ProviderTimeoutError, ProviderUnavailableError
from jarvis.hardware import ModelMeasurement
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

    @property
    def endpoint(self) -> str:
        return self._endpoint

    @property
    def configured_model(self) -> str:
        return self._model

    @property
    def ownership(self) -> OllamaProcessOwnership:
        return (
            OllamaProcessOwnership.JARVIS
            if self._process is not None
            else OllamaProcessOwnership.EXTERNAL
        )

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

    async def recover(self) -> OllamaRuntimeStatus:
        """Recover only the exact process launched by this manager."""

        status = await self.status()
        if status.ownership is not OllamaProcessOwnership.JARVIS:
            return status
        process, self._process = self._process, None
        if process is not None and process.poll() is None:
            process.terminate()
            wait = getattr(process, "wait", None)
            if callable(wait):
                await asyncio.to_thread(wait, 10)
        return await self.ensure_running()

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


@dataclass(frozen=True, slots=True)
class OllamaModelHandle:
    model_id: str
    loaded_at: float


class OllamaModelAdapter(ProviderModelAdapter):
    """Provider-neutral model lifecycle adapter backed by typed Ollama HTTP APIs."""

    def __init__(
        self,
        runtime: OllamaRuntimeManager,
        *,
        provider_id: str = "ollama",
        timeout_seconds: float = 60.0,
        client: httpx.AsyncClient | None = None,
    ) -> None:
        if not isinstance(runtime, OllamaRuntimeManager):
            raise ValueError("Ollama runtime manager is invalid")
        if type(provider_id) is not str or not provider_id.strip():
            raise ValueError("Ollama provider identity is invalid")
        if not local_model_endpoint_is_safe(runtime.endpoint):
            raise ValueError("Ollama endpoint is unsafe")
        self._runtime = runtime
        self._provider_id = provider_id
        self._endpoint = runtime.endpoint
        self._timeout_seconds = timeout_seconds
        self._client = client
        self._owned_client: httpx.AsyncClient | None = None
        self._latest: dict[str, LocalModelSpec] = {}

    @property
    def provider_metadata(self) -> ProviderMetadata:
        return ProviderMetadata(
            self._provider_id,
            "Ollama",
            "provider-reported",
            local_only=True,
            locality=ProviderLocality.LOCAL,
        )

    async def ensure_provider(self) -> OllamaRuntimeStatus:
        status = await self._runtime.ensure_running()
        if status.server is not OllamaServerState.RUNNING:
            raise ProviderUnavailableError(status.detail)
        return status

    async def discover(self) -> tuple[LocalModelSpec, ...]:
        status = await self._runtime.status()
        if status.server is not OllamaServerState.RUNNING:
            raise ProviderUnavailableError(status.detail)
        tags = await self._get("/api/tags")
        payload = _json_object(tags)
        raw_models = payload.get("models")
        if not isinstance(raw_models, list):
            raise ProviderError("Ollama model catalog is malformed")
        running = set(status.running_models)
        specifications: list[LocalModelSpec] = []
        for raw in raw_models[:256]:
            if not isinstance(raw, dict):
                continue
            model_id = _bounded_model_text(raw.get("name") or raw.get("model"))
            if model_id is None:
                continue
            raw_details = raw.get("details")
            details: dict[str, object] = raw_details if isinstance(raw_details, dict) else {}
            capabilities = _capabilities(raw.get("capabilities"))
            roles = {ModelRole.GENERAL}
            if "tools" in capabilities:
                capabilities.add("tool_use")
                roles.add(ModelRole.TOOL_USE)
            if "vision" in capabilities:
                roles.add(ModelRole.VISION)
            if "thinking" in capabilities:
                capabilities.add("reasoning")
                roles.add(ModelRole.REASONING)
            context_limit = _positive_int(details.get("context_length")) or 4_096
            digest = _bounded_model_text(raw.get("digest"), 512)
            size = _nonnegative_int(raw.get("size"))
            metrics = tuple(
                item
                for item in (
                    ("digest", digest) if digest is not None else None,
                    ("size_bytes", str(size)) if size is not None else None,
                )
                if item is not None
            )
            metadata = ModelMetadata(
                model_id=model_id,
                context_limit=context_limit,
                capabilities=frozenset(capabilities),
                roles=frozenset(roles),
                family=_bounded_model_text(details.get("family"), 256) or "",
                version=_bounded_model_text(details.get("parameter_size"), 128) or "",
                quantization=_bounded_model_text(details.get("quantization_level"), 128) or "",
                runtime="ollama",
                source="ollama.api.tags",
                modalities=frozenset({"text", "image"} if "vision" in capabilities else {"text"}),
                storage_bytes=size,
                evidence=(
                    EvidenceRecord(
                        EvidenceKind.PROVIDER_REPORTED,
                        "ollama.api.tags",
                        "Provider-reported model metadata; digest is not a JARVIS byte hash",
                        metrics=metrics,
                    ),
                ),
            )
            spec = LocalModelSpec(
                model_id,
                metadata,
                ModelArtifact(
                    f"ollama://{model_id}",
                    None,
                    size,
                    provider_digest=digest,
                    provider_managed=True,
                ),
                provider_managed=True,
                installed=True,
                loaded=model_id in running,
                provider_digest=digest,
            )
            specifications.append(spec)
        self._latest = {item.model_id: item for item in specifications}
        return tuple(specifications)

    async def acquire(self, spec: LocalModelSpec) -> None:
        if not spec.provider_managed:
            raise ProviderError("Ollama adapter received a file-managed model")
        await self._post("/api/pull", {"model": spec.model_id, "stream": False})
        discovered = await self.discover()
        if spec.model_id not in {item.model_id for item in discovered}:
            raise ProviderError("Ollama did not report the acquired model")

    async def verify(self, spec: LocalModelSpec) -> bool:
        discovered = await self.discover()
        current = next((item for item in discovered if item.model_id == spec.model_id), None)
        if current is None:
            return False
        expected = spec.provider_digest
        observed = current.provider_digest
        if expected is None or observed is None:
            # Provider identity is established, but unknown digest is not promoted
            # to a JARVIS-computed integrity claim.
            return True
        return expected == observed

    async def load(self, spec: LocalModelSpec) -> OllamaModelHandle:
        started = time.monotonic()
        await self._post(
            "/api/generate",
            {
                "model": spec.model_id,
                "prompt": "",
                "stream": False,
                "keep_alive": "5m",
                "options": {"num_predict": 0},
            },
        )
        return OllamaModelHandle(spec.model_id, started)

    async def unload(self, model_id: str, handle: object | None) -> None:
        del handle
        await self._post(
            "/api/generate",
            {"model": model_id, "prompt": "", "stream": False, "keep_alive": 0},
        )

    async def remove(self, spec: LocalModelSpec) -> None:
        if not spec.provider_managed:
            raise ProviderError("Ollama removal received a file-managed model")
        try:
            await self._delete("/api/delete", {"model": spec.model_id})
        except (ProviderTimeoutError, ProviderUnavailableError) as error:
            raise ModelRemovalUnknownOutcome(
                "Ollama model removal outcome is ambiguous; reconcile provider inventory"
            ) from error

    async def health(self, model_id: str, handle: object | None) -> ModelHealth:
        del handle
        status = await self._runtime.status()
        available = (
            status.server is OllamaServerState.RUNNING and model_id in status.installed_models
        )
        return ModelHealth(
            model_id,
            available,
            "provider reports model installed" if available else status.detail,
            datetime.now(UTC),
        )

    async def benchmark(self, model_id: str, handle: object) -> ModelMeasurement:
        if not isinstance(handle, OllamaModelHandle) or handle.model_id != model_id:
            raise ProviderError("Ollama benchmark handle is invalid")
        started = time.monotonic()
        response = await self._post(
            "/api/generate",
            {
                "model": model_id,
                "prompt": "Return exactly JARVIS_CALIBRATION_OK.",
                "stream": False,
                "keep_alive": "5m",
                "options": {"num_predict": 16},
            },
        )
        elapsed = max(time.monotonic() - started, 0.000001)
        eval_count = _positive_int(response.get("eval_count"))
        eval_duration = _positive_int(response.get("eval_duration"))
        throughput = (
            float(eval_count) / (float(eval_duration) / 1_000_000_000.0)
            if eval_count is not None and eval_duration is not None
            else None
        )
        spec = self._latest.get(model_id)
        return ModelMeasurement(
            model_id,
            datetime.now(UTC),
            "ollama.api.generate",
            storage_bytes=spec.metadata.storage_bytes if spec is not None else None,
            load_seconds=max(time.monotonic() - handle.loaded_at, 0.0),
            throughput=throughput if throughput is not None else 1.0 / elapsed,
        )

    async def recover_provider(self) -> OllamaRuntimeStatus:
        return await self._runtime.recover()

    async def aclose(self) -> None:
        if self._owned_client is not None:
            await self._owned_client.aclose()
            self._owned_client = None

    async def _get(self, path: str) -> httpx.Response:
        try:
            async with self._request_client() as client:
                response = await client.get(f"{self._endpoint}{path}")
                self._raise(response)
                return response
        except httpx.TimeoutException as error:
            raise ProviderTimeoutError("Ollama model discovery timed out") from error
        except httpx.ConnectError as error:
            raise ProviderUnavailableError("Ollama server is unavailable") from error

    async def _post(self, path: str, payload: dict[str, object]) -> dict[str, object]:
        try:
            async with self._request_client() as client:
                response = await client.post(f"{self._endpoint}{path}", json=payload)
                self._raise(response)
                return _json_object(response)
        except httpx.TimeoutException as error:
            raise ProviderTimeoutError("Ollama model lifecycle operation timed out") from error
        except httpx.ConnectError as error:
            raise ProviderUnavailableError("Ollama server is unavailable") from error

    async def _delete(self, path: str, payload: dict[str, object]) -> None:
        try:
            async with self._request_client() as client:
                response = await client.request("DELETE", f"{self._endpoint}{path}", json=payload)
                self._raise(response)
        except httpx.TimeoutException as error:
            raise ProviderTimeoutError("Ollama model removal timed out") from error
        except httpx.ConnectError as error:
            raise ProviderUnavailableError("Ollama server is unavailable") from error

    @staticmethod
    def _raise(response: httpx.Response) -> None:
        if response.status_code >= 400:
            raise ProviderError(f"Ollama returned HTTP {response.status_code}")

    @asynccontextmanager
    async def _request_client(self) -> AsyncIterator[httpx.AsyncClient]:
        if self._client is not None:
            yield self._client
            return
        async with httpx.AsyncClient(
            timeout=httpx.Timeout(self._timeout_seconds), trust_env=False
        ) as client:
            yield client


def _json_object(response: httpx.Response) -> dict[str, object]:
    try:
        value = response.json()
    except (ValueError, json.JSONDecodeError) as error:
        raise ProviderError("Ollama returned malformed JSON") from error
    if not isinstance(value, dict):
        raise ProviderError("Ollama returned a malformed object")
    return value


def _bounded_model_text(value: object, limit: int = 256) -> str | None:
    if type(value) is not str or not value.strip() or len(value) > limit or "\x00" in value:
        return None
    return value


def _positive_int(value: object) -> int | None:
    return value if type(value) is int and value > 0 else None


def _nonnegative_int(value: object) -> int | None:
    return value if type(value) is int and value >= 0 else None


def _capabilities(value: object) -> set[str]:
    if not isinstance(value, list):
        return set()
    return {
        item.casefold()
        for item in value
        if type(item) is str and item.strip() and len(item) <= 128 and "\x00" not in item
    }
