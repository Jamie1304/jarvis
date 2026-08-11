# ADR 0002: Local-first conversation and optional speech

## Decision

Use provider-neutral interfaces for AI, STT, TTS, and recording. Select Ollama, faster-whisper/sounddevice, and pyttsx3 only in the composition root. Keep speech and desktop dependencies optional and disabled by default.

## Rationale

The text conversation path remains usable without hardware, cloud access, or large audio/UI dependencies. CI can use fakes, while Windows users can opt into local microphone and TTS support. Audio stays transient and no privileged tools are introduced.
