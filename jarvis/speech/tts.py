"""Local text-to-speech abstractions with an explicit disabled mode."""

import asyncio
from abc import ABC, abstractmethod
from collections.abc import AsyncIterable, AsyncIterator
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

    async def speak_chunks(self, chunks: AsyncIterable[str]) -> None:
        """Speak incremental chunks; providers may override to keep output open."""

        async for chunk in chunks:
            await self.speak(chunk)

    async def reopen_output(self) -> None:
        """Reset provider output after a device change or playback failure."""

        await self.stop()

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

    def __init__(
        self,
        provider: TtsProvider,
        *,
        enabled: bool,
        fallback: TtsProvider | None = None,
        queue_size: int = 8,
    ) -> None:
        if queue_size < 1 or queue_size > 64:
            raise ValueError("TTS queue size must be between one and sixty-four")
        self._provider = provider
        self._fallback = fallback
        self._enabled = enabled
        self._speaking = False
        self._generation = 0
        self._active_task: asyncio.Task[None] | None = None
        self._queue_size = queue_size
        self._available = True

    @property
    def is_speaking(self) -> bool:
        return self._speaking

    @property
    def enabled(self) -> bool:
        return self._enabled

    @property
    def available(self) -> bool:
        return self._available

    async def speak(self, text: str) -> None:
        if not self._enabled:
            return
        self._speaking = True
        try:
            await self._speak_with_fallback(text)
        finally:
            self._speaking = False

    async def speak_incremental(self, chunks: AsyncIterable[str]) -> None:
        """Play a bounded stream while it is still being generated.

        The generation guard makes queued chunks observational data only: once
        stopped, old chunks are discarded and cannot reach a new utterance.
        """

        if not self._enabled:
            return
        self._generation += 1
        generation = self._generation
        self._speaking = True
        current_task = asyncio.current_task()
        if self._active_task is None and current_task is not None:
            self._active_task = current_task

        async def guarded() -> AsyncIterator[str]:
            async for chunk in chunks:
                if generation != self._generation:
                    return
                normalized = " ".join(chunk.split())
                if normalized:
                    yield normalized

        try:
            await self._provider.speak_chunks(guarded())
            self._available = True
        except SpeechError:
            if self._fallback is None or generation != self._generation:
                self._available = False
                return
            try:
                await self._fallback.speak_chunks(guarded())
                self._available = True
            except SpeechError:
                self._available = False
        finally:
            self._speaking = False
            if self._active_task is current_task:
                self._active_task = None
            close = getattr(chunks, "aclose", None)
            if callable(close):
                result = close()
                if asyncio.iscoroutine(result):
                    await result

    def start_incremental(self, chunks: AsyncIterable[str]) -> asyncio.Task[None]:
        """Start incremental output without blocking response generation."""

        if self._active_task is not None and not self._active_task.done():
            raise SpeechError("TTS output is already active")
        self._active_task = asyncio.create_task(self.speak_incremental(chunks))
        return self._active_task

    async def stop(self) -> None:
        self._generation += 1
        active, self._active_task = self._active_task, None
        if active is not None and not active.done():
            active.cancel()
            await asyncio.gather(active, return_exceptions=True)
        await self._provider.stop()
        if self._fallback is not None:
            await self._fallback.stop()
        self._speaking = False

    async def reopen_output(self) -> None:
        await self.stop()
        await self._provider.reopen_output()
        if self._fallback is not None:
            await self._fallback.reopen_output()

    async def aclose(self) -> None:
        await self.stop()
        await self._provider.aclose()
        if self._fallback is not None:
            await self._fallback.aclose()

    async def _speak_with_fallback(self, text: str) -> None:
        try:
            await self._provider.speak(text)
            self._available = True
        except SpeechError:
            if self._fallback is None:
                self._available = False
                return
            try:
                await self._fallback.speak(text)
                self._available = True
            except SpeechError:
                self._available = False


class SpeakableChunker:
    """Release only complete, bounded natural-language speech chunks."""

    def __init__(self, *, max_chunk_length: int = 1_000) -> None:
        if max_chunk_length < 64:
            raise ValueError("Speech chunk bound is too small")
        self._buffer = ""
        self._max_chunk_length = max_chunk_length

    def feed(self, text: str) -> tuple[str, ...]:
        self._buffer += text
        return self._split(False)

    def finish(self) -> tuple[str, ...]:
        return self._split(True)

    def _split(self, final: bool) -> tuple[str, ...]:
        output: list[str] = []
        while True:
            boundary = self._boundary(self._buffer)
            if boundary is None:
                break
            chunk = self._buffer[:boundary].strip()
            remainder = self._buffer[boundary:]
            if chunk and not self._safe(chunk):
                break
            self._buffer = remainder
            if chunk:
                output.append(chunk)
        if final and self._buffer.strip() and self._safe(self._buffer.strip()):
            output.append(self._buffer.strip())
            self._buffer = ""
        if len(self._buffer) > self._max_chunk_length:
            # Never emit an incomplete protocol/markup fragment. Keep the
            # bounded tail and discard only plain-text overflow.
            if self._safe(self._buffer[: self._max_chunk_length]):
                output.append(self._buffer[: self._max_chunk_length].strip())
                self._buffer = self._buffer[self._max_chunk_length :]
        return tuple(output)

    @staticmethod
    def _boundary(value: str) -> int | None:
        for index, character in enumerate(value):
            if character in ".!?" and (index + 1 == len(value) or value[index + 1].isspace()):
                return index + 1
        return None

    @staticmethod
    def _safe(value: str) -> bool:
        return (
            value.count("```") % 2 == 0
            and value.count("<") == value.count(">")
            and not value.lstrip().startswith(('{"tool', "TOOL_CALL", "<tool"))
        )
