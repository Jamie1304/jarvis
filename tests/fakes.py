"""Deterministic provider fakes for local tests."""

from collections.abc import AsyncIterator

from jarvis.ai.models import (
    GenerationChunk,
    GenerationRequest,
    GenerationResult,
    ModelInfo,
    ProviderHealth,
)
from jarvis.ai.providers.base import AIProvider
from jarvis.speech.stt import AudioData, AudioRecorder, SttProvider, Transcription
from jarvis.speech.tts import TtsProvider


class FakeAIProvider(AIProvider):
    def __init__(self, chunks: tuple[str, ...] = ("200",)) -> None:
        self.chunks = chunks
        self.requests: list[GenerationRequest] = []
        self.closed = False

    async def generate(self, request: GenerationRequest) -> GenerationResult:
        self.requests.append(request)
        return GenerationResult(content="".join(self.chunks), model=request.model)

    async def stream(self, request: GenerationRequest) -> AsyncIterator[GenerationChunk]:
        self.requests.append(request)
        for index, content in enumerate(self.chunks):
            yield GenerationChunk(content=content, done=index == len(self.chunks) - 1)

    async def health_check(self) -> ProviderHealth:
        return ProviderHealth(available=True, detail="fake provider")

    async def model_info(self) -> ModelInfo:
        return ModelInfo(provider="fake", model="fake-model", context_limit=4096)

    async def aclose(self) -> None:
        self.closed = True


class FakeRecorder(AudioRecorder):
    def __init__(self, audio: AudioData) -> None:
        self.audio = audio
        self.started = False
        self.closed = False

    async def start(self) -> None:
        self.started = True

    async def stop(self) -> AudioData:
        self.started = False
        return self.audio

    async def aclose(self) -> None:
        self.closed = True


class FakeSttProvider(SttProvider):
    def __init__(self, text: str) -> None:
        self.text = text
        self.received: AudioData | None = None

    async def transcribe(self, audio: AudioData) -> Transcription:
        self.received = audio
        return Transcription(text=self.text, language="nl")


class FakeTtsProvider(TtsProvider):
    def __init__(self) -> None:
        self.spoken: list[str] = []
        self.stopped = False

    async def speak(self, text: str) -> None:
        self.spoken.append(text)

    async def stop(self) -> None:
        self.stopped = True
