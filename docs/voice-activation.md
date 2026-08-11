# Local voice activation

Phase 17 adds an opt-in, local-first voice controller. Its single state machine
exposes `idle` (wake monitoring), `listening`, `processing`, `speaking`, and
`error` to the application UI:

`IDLE -> LISTENING -> PROCESSING -> SPEAKING -> IDLE`

Only the wake-word provider receives frames while idle. The default
configuration is disabled; when enabled, the provider must be local. Speech to
text starts only after an accepted wake and is given transient in-memory audio.
The controller never uploads idle audio or persists raw frames. A capture
source is opened on demand and always closed in a `finally` block.

`WakeWordProvider`, `VADProvider`, and `AudioSource` are provider-neutral
interfaces. Hardware adapters belong at the composition root and must not be
used by the planner. Deterministic tests use fake frames; real microphone tests
are manual/Windows-only and must be marked separately from CI.

Task execution is delegated through `VoiceTaskRunner`. The production adapter,
`OrchestratorVoiceTaskRunner`, creates and cancels tasks through
`AgentOrchestrator`; voice does not create a second task lifecycle or grant
permissions. A transcription containing exactly `stop` or `cancel` cancels the
central task and stops TTS. `wait` stops active TTS without authorizing a new
task. Commands are exact normalized matches, not arbitrary model instructions.

Cooldown/debounce prevents overlapping wake sessions. Wake confidence, wake
word, and timing limits are configuration values, with `Jarvis` as the default
word. Voice activation remains separate from camera, terminal, and other
privileged tools; a spoken request still follows the normal planner,
Permission Broker, approval, and verification boundaries.

## Privacy and manual testing

While idle, raw microphone samples stay in the local wake provider and are
discarded after detection. No cloud STT service is contacted. After a wake,
the bounded utterance is held in memory only until STT completes, then the
sample buffer is released. Enable `JARVIS_VOICE_ENABLED` only after selecting a
trusted local wake/VAD/STT adapter. Hardware testing should verify device open,
capture, wake, cancellation, TTS interruption, and clean shutdown on a Windows
desktop; it is not part of deterministic CI.
