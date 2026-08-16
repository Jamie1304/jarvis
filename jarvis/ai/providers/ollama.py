"""Ollama adapter isolated behind the provider interface."""

import json
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from typing import Any

import httpx

from jarvis.ai.models import (
    GenerationChunk,
    GenerationRequest,
    GenerationResult,
    ModelInfo,
    ProviderHealth,
)
from jarvis.ai.providers.base import AIProvider
from jarvis.core.errors import (
    ModelUnavailableError,
    ProviderError,
    ProviderTimeoutError,
    ProviderUnavailableError,
    StreamingInterruptedError,
)


class OllamaProvider(AIProvider):
    """Asynchronous local Ollama implementation of :class:`AIProvider`."""

    def __init__(
        self,
        *,
        model: str,
        endpoint: str,
        timeout_seconds: float,
        context_limit: int,
        client: httpx.AsyncClient | None = None,
    ) -> None:
        self._model = model
        self._endpoint = endpoint.rstrip("/")
        self._context_limit = context_limit
        self._client = client
        self._timeout_seconds = timeout_seconds

    async def generate(self, request: GenerationRequest) -> GenerationResult:
        payload = self._payload(request, stream=False)
        try:
            async with self._request_client() as client:
                response = await client.post(f"{self._endpoint}/api/chat", json=payload)
                self._raise_for_ollama_error(response)
                body = response.json()
                content = self._message_content(body)
        except httpx.TimeoutException as error:
            raise ProviderTimeoutError("Ollama generation timed out") from error
        except httpx.ConnectError as error:
            raise ProviderUnavailableError("Ollama server is unavailable") from error
        return GenerationResult(content=content, model=self._model)

    async def stream(self, request: GenerationRequest) -> AsyncIterator[GenerationChunk]:
        payload = self._payload(request, stream=True)
        completed = False
        try:
            async with self._request_client() as client:
                async with client.stream(
                    "POST", f"{self._endpoint}/api/chat", json=payload
                ) as response:
                    self._raise_for_ollama_error(response)
                    async for line in response.aiter_lines():
                        if not line:
                            continue
                        body = self._parse_stream_line(line)
                        done = bool(body.get("done", False))
                        content = self._message_content(body)
                        if content or done:
                            yield GenerationChunk(content=content, done=done)
                        if done:
                            completed = True
                            break
        except httpx.TimeoutException as error:
            raise ProviderTimeoutError("Ollama streaming timed out") from error
        except httpx.ConnectError as error:
            raise ProviderUnavailableError("Ollama server is unavailable") from error
        if not completed:
            raise StreamingInterruptedError("Ollama ended the response stream before completion")

    async def health_check(self) -> ProviderHealth:
        try:
            async with self._request_client() as client:
                response = await client.get(f"{self._endpoint}/api/tags")
                self._raise_for_ollama_error(response)
        except (ProviderUnavailableError, ProviderTimeoutError) as error:
            return ProviderHealth(available=False, detail=str(error))
        except httpx.TimeoutException as error:
            return ProviderHealth(available=False, detail=f"Ollama health check timed out: {error}")
        except httpx.ConnectError as error:
            return ProviderHealth(available=False, detail=str(error))
        return ProviderHealth(available=True, detail="Ollama is reachable")

    async def model_info(self) -> ModelInfo:
        request = GenerationRequest(
            messages=(), model=self._model, context_limit=self._context_limit
        )
        return ModelInfo(
            provider="ollama", model=request.model, context_limit=request.context_limit
        )

    async def aclose(self) -> None:
        return None

    @asynccontextmanager
    async def _request_client(self) -> AsyncIterator[httpx.AsyncClient]:
        if self._client is not None:
            yield self._client
        else:
            async with httpx.AsyncClient(
                timeout=httpx.Timeout(self._timeout_seconds), trust_env=False
            ) as client:
                yield client

    def _payload(self, request: GenerationRequest, *, stream: bool) -> dict[str, Any]:
        return {
            "model": request.model,
            "stream": stream,
            "messages": [
                {"role": item.role.value, "content": item.content} for item in request.messages
            ],
            "options": {"num_ctx": request.context_limit},
        }

    @staticmethod
    def _message_content(body: dict[str, Any]) -> str:
        message = body.get("message", {})
        return str(message.get("content", "")) if isinstance(message, dict) else ""

    @staticmethod
    def _parse_stream_line(line: str) -> dict[str, Any]:
        try:
            value = json.loads(line)
        except json.JSONDecodeError as error:
            raise StreamingInterruptedError("Ollama returned malformed stream data") from error
        if not isinstance(value, dict):
            raise StreamingInterruptedError("Ollama returned an invalid stream event")
        return value

    @staticmethod
    def _raise_for_ollama_error(response: httpx.Response) -> None:
        if response.status_code < 400:
            return
        # Response bodies can echo prompts, credentials, or malicious server text.
        # Preserve only trusted protocol metadata in application exceptions.
        if response.status_code == 404:
            raise ModelUnavailableError("Ollama model is unavailable")
        raise ProviderError(f"Ollama returned HTTP {response.status_code}")
