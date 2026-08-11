# Testing

Tests live under `tests/` and use `pytest`. Unit and fake-provider integration tests cover typed settings, health/version, AI streaming, failed Ollama connectivity, process-local conversation history, cancellation, STT recording/transcription lifecycle, TTS lifecycle, and the UI-facing application service. Phase 2 tests add one-step and multi-step task success, tool failure, verification failure, replanning, step limits, cancellation, timeout, malformed plan payloads, and unavailable capabilities. The CI and local quality command run formatting, linting, mypy, tests, and coverage.

Phase 3 tool tests cover successful calculator execution, strict unknown-field and type rejection, timeout, cancellation, unavailable weather, structured internal failure, typed local-time output, and orchestration of `25 procent van 800` through the registered calculator tool.

New code should test normal behavior and security-relevant failure paths. Tests must not require network access, machine-specific paths, cloud credentials, microphones, speakers, Ollama, or privileged host capabilities. Desktop and physical audio hardware smoke tests remain manual.
