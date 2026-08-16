"""Deterministic contracts for optional local-only production providers."""

from datetime import UTC, datetime

import httpx
import pytest
from jarvis.vision.local import OllamaVisionProvider, ScreenshotBytesLoader
from jarvis.vision.models import VisionRequest
from jarvis.voice import AudioFrame, EnergyVADProvider


class Loader(ScreenshotBytesLoader):
    async def load(self, reference: str) -> bytes | None:
        return b"image" if reference == "screenshot:test" else None


def request() -> VisionRequest:
    return VisionRequest("screenshot:test", (10, 10), datetime.now(UTC), "inspect", (), None)


@pytest.mark.asyncio
async def test_local_ollama_vision_health_and_strict_structured_result() -> None:
    def handler(http_request: httpx.Request) -> httpx.Response:
        if http_request.url.path == "/api/tags":
            return httpx.Response(200, json={"models": [{"name": "llava:test"}]})
        return httpx.Response(
            200,
            json={
                "message": {
                    "content": (
                        '{"visible_elements":[{"label":"Save","role":"Button",'
                        '"bounds":[0,0,0.2,0.2],"confidence":0.9}],'
                        '"candidate_targets":[],"confidence":0.9}'
                    )
                }
            },
        )

    async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as client:
        provider = OllamaVisionProvider(model="llava:test", screenshots=Loader(), client=client)
        assert await provider.health_check()
        result = await provider.observe(request())

    assert result.visible_elements[0].label == "Save"


@pytest.mark.asyncio
async def test_local_ollama_vision_rejects_missing_or_malformed_artifacts() -> None:
    client = httpx.AsyncClient()
    provider = OllamaVisionProvider(model="llava:test", screenshots=Loader(), client=client)
    with pytest.raises(ValueError, match="unavailable"):
        await provider.observe(
            VisionRequest("missing", (10, 10), datetime.now(UTC), "inspect", (), None)
        )
    await client.aclose()


def test_local_energy_vad_is_bounded_and_deterministic() -> None:
    vad = EnergyVADProvider(speech_threshold=0.1, end_threshold=0.02)
    assert vad.is_speech(AudioFrame((0.2, -0.2), 16_000))
    assert vad.is_end(AudioFrame((0.0,), 16_000))
    with pytest.raises(ValueError):
        EnergyVADProvider(speech_threshold=0.01, end_threshold=0.02)
