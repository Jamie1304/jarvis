"""Configurable local multimodal vision provider; it has no execution authority."""

from __future__ import annotations

import base64
import json
from abc import ABC, abstractmethod
from collections.abc import Mapping
from typing import cast

import httpx

from jarvis.security import local_model_endpoint_is_safe
from jarvis.vision.models import (
    NormalizedBounds,
    VisibleElement,
    VisionAnalysis,
    VisionCandidate,
    VisionRequest,
)
from jarvis.vision.providers import VisionProvider


class ScreenshotBytesLoader(ABC):
    """Trusted artifact-store read port; model references never become paths."""

    @abstractmethod
    async def load(self, reference: str) -> bytes | None: ...


class OllamaVisionProvider(VisionProvider):
    """Local Ollama multimodal adapter with strict JSON output validation."""

    def __init__(
        self,
        *,
        model: str,
        screenshots: ScreenshotBytesLoader,
        endpoint: str = "http://127.0.0.1:11434",
        timeout_seconds: float = 30,
        client: httpx.AsyncClient | None = None,
    ) -> None:
        if not model.strip() or timeout_seconds <= 0 or not local_model_endpoint_is_safe(endpoint):
            raise ValueError("Local vision provider configuration is invalid")
        self._model, self._screenshots = model, screenshots
        self._endpoint = endpoint.rstrip("/")
        self._timeout = timeout_seconds
        self._client = client

    async def health_check(self) -> bool:
        client, close = self._client_or_new()
        try:
            response = await client.get(f"{self._endpoint}/api/tags")
            response.raise_for_status()
            return any(
                isinstance(item, Mapping) and item.get("name") == self._model
                for item in response.json().get("models", [])
            )
        except (httpx.HTTPError, ValueError, AttributeError):
            return False
        finally:
            if close:
                await client.aclose()

    async def observe(self, request: VisionRequest) -> VisionAnalysis:
        image = await self._screenshots.load(request.screenshot_id)
        if not image:
            raise ValueError("Vision screenshot reference is unavailable")
        client, close = self._client_or_new()
        try:
            response = await client.post(
                f"{self._endpoint}/api/chat",
                json={
                    "model": self._model,
                    "stream": False,
                    "format": "json",
                    "messages": [
                        {
                            "role": "user",
                            "content": _SCHEMA,
                            "images": [base64.b64encode(image).decode("ascii")],
                        }
                    ],
                },
            )
            response.raise_for_status()
            return _analysis(json.loads(response.json()["message"]["content"]))
        except (httpx.HTTPError, KeyError, TypeError, ValueError, json.JSONDecodeError) as error:
            raise ValueError(
                "Local vision provider returned malformed structured output"
            ) from error
        finally:
            if close:
                await client.aclose()

    def _client_or_new(self) -> tuple[httpx.AsyncClient, bool]:
        if self._client is not None:
            return self._client, False
        return httpx.AsyncClient(timeout=self._timeout, trust_env=False), True


_SCHEMA = (
    'Return only JSON: {"visible_elements":[{"label":"","role":"",'
    '"bounds":[0,0,1,1],"confidence":0}],"candidate_targets":[],"confidence":0}'
)


def _analysis(value: object) -> VisionAnalysis:
    if not isinstance(value, dict):
        raise ValueError("Vision result must be an object")
    return VisionAnalysis(
        cast(
            tuple[VisibleElement, ...],
            _elements(value.get("visible_elements", []), VisibleElement),
        ),
        cast(
            tuple[VisionCandidate, ...],
            _elements(value.get("candidate_targets", []), VisionCandidate),
        ),
        float(value["confidence"]),
    )


def _elements(
    value: object, kind: type[VisibleElement] | type[VisionCandidate]
) -> tuple[VisibleElement | VisionCandidate, ...]:
    if not isinstance(value, list) or len(value) > 128:
        raise ValueError("Vision elements are malformed or excessive")
    items: list[VisibleElement | VisionCandidate] = []
    for item in value:
        if not isinstance(item, dict) or set(item) != {"label", "role", "bounds", "confidence"}:
            raise ValueError("Vision element is malformed")
        bounds = item["bounds"]
        if not isinstance(bounds, list) or len(bounds) != 4:
            raise ValueError("Vision bounds are malformed")
        items.append(
            kind(
                str(item["label"]),
                str(item["role"]),
                NormalizedBounds(*bounds),
                float(item["confidence"]),
            )
        )
    return tuple(items)
