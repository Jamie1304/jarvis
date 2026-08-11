# Testing

Tests live under `tests/` and use `pytest`. Unit and fake-provider integration tests cover typed settings, health/version, AI streaming, failed Ollama connectivity, process-local conversation history, cancellation, STT recording/transcription lifecycle, TTS lifecycle, and the UI-facing application service. Phase 2 tests add one-step and multi-step task success, tool failure, verification failure, replanning, step limits, cancellation, timeout, malformed plan payloads, and unavailable capabilities. The CI and local quality command run formatting, linting, mypy, tests, and coverage.

Phase 3 tool tests cover successful calculator execution, strict unknown-field and type rejection, timeout, cancellation, unavailable weather, structured internal failure, typed local-time output, and orchestration of `25 procent van 800` through the registered calculator tool.

New code should test normal behavior and security-relevant failure paths. Tests must not require network access, machine-specific paths, cloud credentials, microphones, speakers, Ollama, or privileged host capabilities. Desktop and physical audio hardware smoke tests remain manual.

Phase 5 security tests use a non-mutating privileged probe tool. They cover fail-
closed unknown/malformed permissions and tools, missing/disabled policy, filesystem
traversal and scope/link escape, trusted approval data, expiry, one-time replay,
argument mutation, model-forged grants, cancellation, deny-once, bounded remembered
grants, hard-safety overrides, reserved tool entry points, and secret-safe audit
evidence. Link-escape coverage skips only when the test identity cannot create a
Windows symlink/junction.

Phase 6 deterministic tests use mock computer, filesystem, screenshot, and command
adapters. They cover broker denial before adapter invocation, catalogued application
launch, semantic input, labelled mouse fallback, separate clipboard permissions,
filesystem scope denial, secure screenshot-reference lifecycle, command timeout,
and cancellation. Real Windows desktop tests are marked `windows_integration` and
are skipped unless `JARVIS_WINDOWS_INTEGRATION=true`; they are not part of ordinary
CI and must never be reported as a successful UI interaction when skipped.

Phase 7 uses static screenshot-reference and accessibility-tree fixtures with mock
computer adapters and a provider stub. The deterministic suite covers target finding,
semantic/vision agreement, dimensions and DPI conversion, screenshot-content stale
state, verification success/failure/uncertainty, broker denial after identifying a
sensitive Send target, and a capped revised retry loop. No test treats a successful
tool result as visual success without a new observation and verification result.
