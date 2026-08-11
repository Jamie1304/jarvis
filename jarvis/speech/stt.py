"""Transient microphone recording and local speech-to-text abstractions."""

import asyncio
import logging
from abc import ABC, abstractmethod
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any

from jarvis.core.errors import RecordingStateError, SpeechDisabledError, SpeechError

logger = logging.getLogger(__name__)


@dataclass(frozen=True, slots=True)
class AudioData:
    """In-memory mono audio; it is never persisted by the service."""

    samples: tuple[float, ...]
    sample_rate: int
    captured_at: datetime


@dataclass(frozen=True, slots=True)
class Transcription:
    """Text produced from a transient audio capture."""

    text: str
    language: str | None = None


class SttProvider(ABC):
    """Asynchronous local speech-to-text provider contract."""

    @abstractmethod
    async def transcribe(self, audio: AudioData) -> Transcription:
        """Convert transient audio into text."""

    async def aclose(self) -> None:  # noqa: B027
        """Release provider resources."""


class AudioRecorder(ABC):
    """Microphone lifecycle contract with no always-open device."""

    @abstractmethod
    async def start(self) -> None:
        """Open and begin recording from the configured device."""

    @abstractmethod
    async def stop(self) -> AudioData:
        """Stop, close, and return the transient capture."""

    @abstractmethod
    async def aclose(self) -> None:
        """Close an active recording cleanly."""


class DisabledSttProvider(SttProvider):
    """Explicit disabled mode used by default for privacy and portability."""

    async def transcribe(self, audio: AudioData) -> Transcription:
        del audio
        raise SpeechDisabledError("Speech-to-text is disabled")


class FasterWhisperSttProvider(SttProvider):
    """Lazy local faster-whisper adapter, imported only when speech is enabled."""

    def __init__(self, model_name: str, *, device: str = "cpu", compute_type: str = "int8") -> None:
        self._model_name = model_name
        self._device = device
        self._compute_type = compute_type
        self._model: Any | None = None

    async def transcribe(self, audio: AudioData) -> Transcription:
        return await asyncio.to_thread(self._transcribe_sync, audio)

    def _transcribe_sync(self, audio: AudioData) -> Transcription:
        try:
            import numpy as np
            from faster_whisper import WhisperModel  # type: ignore[import-untyped]
        except ImportError as error:
            raise SpeechError(
                "Speech-to-text dependency is missing: "
                f"{error.name or 'unknown'}; install the speech extra"
            ) from error
        if self._model is None:
            self._model = WhisperModel(
                self._model_name,
                device=self._device,
                compute_type=self._compute_type,
            )
        try:
            segments, info = self._model.transcribe(
                np.asarray(audio.samples, dtype=np.float32),
                language=None,
                vad_filter=True,
            )
            return Transcription(
                text="".join(segment.text for segment in segments).strip(),
                language=getattr(info, "language", None),
            )
        except Exception as error:
            logger.exception("Local speech transcription failed")
            raise SpeechError(f"Local speech transcription failed: {error}") from error


class SoundDeviceRecorder(AudioRecorder):
    """On-demand sounddevice recorder that closes the microphone after each capture."""

    def __init__(self, *, device: str | int | None, sample_rate: int) -> None:
        self._device = device
        self._sample_rate = sample_rate
        self._stream: Any | None = None
        self._samples: list[float] = []

    async def start(self) -> None:
        if self._stream is not None:
            raise RecordingStateError("Microphone recording is already active")
        await asyncio.to_thread(self._start_sync)

    async def stop(self) -> AudioData:
        if self._stream is None:
            raise RecordingStateError("Microphone recording is not active")
        await asyncio.to_thread(self._stop_sync)
        return AudioData(
            samples=tuple(self._samples),
            sample_rate=self._sample_rate,
            captured_at=datetime.now(UTC),
        )

    async def aclose(self) -> None:
        if self._stream is not None:
            await self.stop()

    def _start_sync(self) -> None:
        try:
            import sounddevice as sd  # type: ignore[import-untyped]
        except ImportError as error:
            raise SpeechError(
                "Microphone dependencies are missing; install the speech extra"
            ) from error

        self._samples = []

        def collect(indata: Any, _: int, __: Any, status: Any) -> None:
            if status:
                return
            self._samples.extend(float(sample) for sample in indata[:, 0])

        try:
            self._stream = sd.InputStream(
                samplerate=self._sample_rate,
                channels=1,
                dtype="float32",
                callback=collect,
                device=self._device,
            )
            self._stream.start()
        except Exception as error:
            self._stream = None
            raise SpeechError(
                "Could not open the configured microphone; set JARVIS_STT_DEVICE to a "
                "valid device ID"
            ) from error

    def _stop_sync(self) -> None:
        if self._stream is None:
            return
        try:
            self._stream.stop()
            self._stream.close()
        finally:
            self._stream = None


class SpeechToTextService:
    """Coordinates recording and transcription without retaining raw audio."""

    def __init__(self, recorder: AudioRecorder, provider: SttProvider) -> None:
        self._recorder = recorder
        self._provider = provider
        self._recording = False

    @property
    def is_recording(self) -> bool:
        return self._recording

    async def start_recording(self) -> None:
        if self._recording:
            raise RecordingStateError("Microphone recording is already active")
        await self._recorder.start()
        self._recording = True

    async def stop_and_transcribe(self) -> Transcription:
        if not self._recording:
            raise RecordingStateError("Microphone recording is not active")
        try:
            audio = await self._recorder.stop()
        finally:
            self._recording = False
        return await self._provider.transcribe(audio)

    async def aclose(self) -> None:
        await self._recorder.aclose()
        await self._provider.aclose()
        self._recording = False
