"""Ollama adapter isolated behind the provider interface."""

import json
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from datetime import UTC, datetime
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
from jarvis.ai.usability import ModelUsabilityEvidence, UsabilityReason
from jarvis.core.errors import (
    ModelUnavailableError,
    ProviderError,
    ProviderTimeoutError,
    ProviderUnavailableError,
    StreamingInterruptedError,
)

_MAX_RESPONSE_BYTES = 4 * 1024 * 1024
_MAX_STREAM_LINE_BYTES = 1 * 1024 * 1024


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
                if len(response.content) > _MAX_RESPONSE_BYTES:
                    raise ProviderError("Ollama response exceeded its safety bound")
                body = response.json()
                content = self._message_content(body)
        except httpx.TimeoutException as error:
            raise ProviderTimeoutError("Ollama generation timed out") from error
        except httpx.ConnectError as error:
            raise ProviderUnavailableError("Ollama server is unavailable") from error
        return GenerationResult(content=content, model=request.model)

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
                        if len(line.encode("utf-8")) > _MAX_STREAM_LINE_BYTES:
                            raise StreamingInterruptedError(
                                "Ollama stream event exceeded its safety bound"
                            )
                        body = self._parse_stream_line(line)
                        done_value = body.get("done", False)
                        if type(done_value) is not bool:
                            raise StreamingInterruptedError(
                                "Ollama stream completion flag is malformed"
                            )
                        done = done_value
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

    async def probe_usability(self) -> ModelUsabilityEvidence:
        """Observe local server/model state without loading or generating."""

        observed_at = datetime.now(UTC)
        try:
            async with self._request_client() as client:
                response = await client.get(f"{self._endpoint}/api/tags")
        except httpx.TimeoutException:
            return ModelUsabilityEvidence(
                configured=True,
                connected=None,
                reachable=False,
                request_usable=False,
                reason=UsabilityReason.NETWORK_UNAVAILABLE,
                source="ollama.api.tags",
                observed_at=observed_at,
                detail="Ollama status probe timed out",
                model_id=self._model,
            )
        except httpx.ConnectError:
            return ModelUsabilityEvidence(
                configured=True,
                connected=False,
                reachable=False,
                request_usable=False,
                reason=UsabilityReason.NETWORK_UNAVAILABLE,
                source="ollama.api.tags",
                observed_at=observed_at,
                detail="Ollama status endpoint is unreachable",
                model_id=self._model,
            )
        if response.status_code == 401:
            return ModelUsabilityEvidence(
                configured=True,
                connected=True,
                reachable=True,
                authenticated=False,
                request_usable=False,
                reason=UsabilityReason.INVALID_CREDENTIALS,
                source="ollama.api.tags",
                observed_at=observed_at,
                detail="Ollama status endpoint rejected authentication",
                model_id=self._model,
            )
        if response.status_code >= 500:
            return ModelUsabilityEvidence(
                configured=True,
                connected=False,
                reachable=True,
                request_usable=False,
                reason=UsabilityReason.PROVIDER_OUTAGE,
                source="ollama.api.tags",
                observed_at=observed_at,
                detail="Ollama status endpoint reported provider failure",
                model_id=self._model,
            )
        if response.status_code >= 400:
            return ModelUsabilityEvidence(
                configured=True,
                connected=True,
                reachable=True,
                request_usable=False,
                reason=UsabilityReason.MODEL_UNAVAILABLE,
                source="ollama.api.tags",
                observed_at=observed_at,
                detail="Ollama status endpoint rejected the probe",
                model_id=self._model,
            )
        try:
            body = response.json()
        except ValueError:
            body = None
        models = body.get("models") if isinstance(body, dict) else None
        if not isinstance(models, list):
            return ModelUsabilityEvidence(
                configured=True,
                connected=True,
                reachable=True,
                authenticated=True,
                request_usable=False,
                reason=UsabilityReason.UNKNOWN,
                source="ollama.api.tags",
                observed_at=observed_at,
                detail="Ollama model catalog was not sufficient to prove usability",
                model_id=self._model,
            )
        installed = any(
            isinstance(item, dict)
            and (item.get("name") == self._model or item.get("model") == self._model)
            for item in models
        )
        return ModelUsabilityEvidence(
            configured=True,
            connected=True,
            reachable=True,
            authenticated=True,
            entitled=True if installed else None,
            quota_usable=True,
            model_usable=installed,
            request_usable=None if installed else False,
            reason=UsabilityReason.UNKNOWN if installed else UsabilityReason.MODEL_NOT_FOUND,
            source="ollama.api.tags",
            observed_at=observed_at,
            detail=(
                "Ollama model is installed and provider-native status is healthy"
                if installed
                else "Ollama provider is reachable but the requested model is not installed"
            ),
            model_id=self._model,
        )

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
    def _message_content(body: object) -> str:
        if not isinstance(body, dict):
            raise ProviderError("Ollama response schema is malformed")
        message = body.get("message")
        if not isinstance(message, dict):
            raise ProviderError("Ollama response message is malformed")
        content = message.get("content", "")
        if type(content) is not str:
            raise ProviderError("Ollama response content is malformed")
        return content

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
