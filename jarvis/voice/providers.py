"""Optional local-only production adapters for the voice activation contracts."""

from __future__ import annotations

import asyncio
from collections.abc import AsyncIterator
from importlib import import_module
from typing import Any

from jarvis.voice.activation import (
    AudioFrame,
    AudioSource,
    VADProvider,
    WakeDetection,
    WakeWordProvider,
)


class EnergyVADProvider(VADProvider):
    """Deterministic local VAD suitable as a conservative fallback, not transcription."""

    def __init__(self, *, speech_threshold: float = 0.02, end_threshold: float = 0.005) -> None:
        if not 0 <= end_threshold <= speech_threshold <= 1:
            raise ValueError("VAD thresholds must be ordered values in [0, 1]")
        self._speech_threshold = speech_threshold
        self._end_threshold = end_threshold

    @staticmethod
    def _energy(frame: AudioFrame) -> float:
        return sum(abs(sample) for sample in frame.samples) / max(1, len(frame.samples))

    def is_speech(self, frame: AudioFrame) -> bool:
        return self._energy(frame) >= self._speech_threshold

    def is_end(self, frame: AudioFrame) -> bool:
        return bool(frame.samples) and self._energy(frame) <= self._end_threshold


class OpenWakeWordProvider(WakeWordProvider):  # pragma: no cover
    """Lazy local openWakeWord adapter; idle audio never leaves the host."""

    def __init__(self, *, model_path: str | None = None) -> None:
        self._model_path = model_path
        self._model: Any | None = None

    async def detect(self, frame: AudioFrame, wake_word: str) -> WakeDetection:
        return await asyncio.to_thread(self._detect_sync, frame, wake_word)

    def _detect_sync(self, frame: AudioFrame, wake_word: str) -> WakeDetection:
        try:
            model_class = import_module("openwakeword.model").Model
        except ImportError as error:
            raise RuntimeError("openWakeWord is unavailable; install the voice extra") from error
        if self._model is None:
            models = [self._model_path] if self._model_path else None
            self._model = model_class(wakeword_models=models)
        scores = self._model.predict(list(frame.samples))
        score = max((float(value) for value in scores.values()), default=0.0)
        return WakeDetection(score > 0, min(1.0, max(0.0, score)), wake_word)


class SoundDeviceAudioSource(AudioSource):  # pragma: no cover
    """On-demand local microphone source with bounded frames and explicit stop."""

    def __init__(self, *, sample_rate: int = 16_000, frame_samples: int = 1_280) -> None:
        if sample_rate <= 0 or frame_samples <= 0:
            raise ValueError("Audio source dimensions must be positive")
        self._sample_rate = sample_rate
        self._frame_samples = frame_samples
        self._queue: asyncio.Queue[AudioFrame | None] = asyncio.Queue(maxsize=8)
        self._stream: Any | None = None
        self._loop: asyncio.AbstractEventLoop | None = None

    async def start(self) -> None:
        if self._stream is not None:
            return
        self._loop = asyncio.get_running_loop()
        try:
            sounddevice = import_module("sounddevice")
        except ImportError as error:
            raise RuntimeError("sounddevice is unavailable; install the speech extra") from error
        self._stream = sounddevice.InputStream(
            channels=1,
            samplerate=self._sample_rate,
            blocksize=self._frame_samples,
            callback=self._callback,
        )
        self._stream.start()

    def _callback(self, indata: Any, _: int, __: Any, status: Any) -> None:
        if status or self._loop is None:
            return
        samples = tuple(float(value) for value in indata[:, 0])
        frame = AudioFrame(samples, self._sample_rate)
        self._loop.call_soon_threadsafe(self._offer, frame)

    def _offer(self, frame: AudioFrame) -> None:
        if not self._queue.full():
            self._queue.put_nowait(frame)

    async def frames(self) -> AsyncIterator[AudioFrame]:
        while True:
            frame = await self._queue.get()
            if frame is None:
                return
            yield frame

    async def stop(self) -> None:
        stream, self._stream = self._stream, None
        if stream is not None:
            await asyncio.to_thread(stream.stop)
            await asyncio.to_thread(stream.close)
        if not self._queue.full():
            self._queue.put_nowait(None)
