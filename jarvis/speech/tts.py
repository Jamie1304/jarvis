"""Local text-to-speech abstractions with an explicit disabled mode."""

import asyncio
from abc import ABC, abstractmethod
from typing import Any

from jarvis.core.errors import SpeechDisabledError, SpeechError


class TtsProvider(ABC):
    """Asynchronous speech playback provider contract."""

    @abstractmethod
    async def speak(self, text: str) -> None:
        """Speak text without blocking the caller's event loop."""

    @abstractmethod
    async def stop(self) -> None:
        """Stop active playback if any."""

    async def aclose(self) -> None:  # noqa: B027
        """Release playback resources."""


class DisabledTtsProvider(TtsProvider):
    """Explicit TTS disabled mode."""

    async def speak(self, text: str) -> None:
        del text
        raise SpeechDisabledError("Text-to-speech is disabled")

    async def stop(self) -> None:
        return None


class Pyttsx3TtsProvider(TtsProvider):
    """Lazy Windows-friendly local pyttsx3 adapter."""

    def __init__(self, *, voice: str | None = None) -> None:
        self._voice = voice
        self._engine: Any | None = None

    async def speak(self, text: str) -> None:
        await asyncio.to_thread(self._speak_sync, text)

    async def stop(self) -> None:
        await asyncio.to_thread(self._stop_sync)

    def _speak_sync(self, text: str) -> None:
        try:
            import pyttsx3
        except ImportError as error:
            raise SpeechError(
                "Text-to-speech dependency is missing; install the speech extra"
            ) from error
        if self._engine is None:
            self._engine = pyttsx3.init()
            if self._voice:
                self._engine.setProperty("voice", self._voice)
        try:
            self._engine.say(text)
            self._engine.runAndWait()
        except Exception as error:
            raise SpeechError("Local text-to-speech playback failed") from error

    def _stop_sync(self) -> None:
        if self._engine is not None:
            self._engine.stop()


class TextToSpeechService:
    """Tracks output state while delegating playback to an interchangeable provider."""

    def __init__(self, provider: TtsProvider, *, enabled: bool) -> None:
        self._provider = provider
        self._enabled = enabled
        self._speaking = False

    @property
    def is_speaking(self) -> bool:
        return self._speaking

    @property
    def enabled(self) -> bool:
        return self._enabled

    async def speak(self, text: str) -> None:
        if not self._enabled:
            return
        self._speaking = True
        try:
            await self._provider.speak(text)
        finally:
            self._speaking = False

    async def stop(self) -> None:
        await self._provider.stop()
        self._speaking = False

    async def aclose(self) -> None:
        await self.stop()
        await self._provider.aclose()
