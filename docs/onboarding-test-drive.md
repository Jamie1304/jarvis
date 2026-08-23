# First-Run Onboarding and Test Drive

## Optional setup

`FirstRunWizard` is an application-service adapter around the existing
`SetupConductor`. It is optional and skippable. Registered setup areas are
filtered by availability, and only the available `SetupStep` values are sent
to the conductor. Hardware/runtime, local model, privacy, voice, camera,
permission defaults, knowledge folders, and backup may register steps when
their trusted services exist; unavailable areas are not reported as complete.

The conductor still owns adoption-first inspection, one normalized
`SetupContext`, typed provisioning, verification, persistence, and resume. A
wizard cancellation or partial failure remains resumable through the same
`run_id`; skipping does not delete user data or change authority. No cloud
account is required.

## Modular test drive

`TestDriveRegistry` accepts independent `TestDriveStep` checks. A check returns
exactly `PASS`, `FAIL`, `SKIPPED`, or `NOT_AVAILABLE`, with bounded detail and
evidence. Required configured checks must all return `PASS` before the report
exposes `fully_ready` or the message `JARVIS is fully ready`. Optional or
unavailable checks do not become false successes. Current runtime composition
registers only authoritative persistence and configured provider checks;
future voice, camera, knowledge, backup, permission-prompt, memory, and safe
tool services can register their own checks.

## Non-blocking warmup

`StartupWarmupRegistry` is a separate best-effort registry. It runs optional
prewarm callbacks in an asynchronous task and isolates failures as `FAILED`.
Unavailable components are `NOT_AVAILABLE`, and a future
`WarmupResourceGovernor` can deny admission as `SKIPPED`. Warmup never blocks
basic desktop construction and does not alter permissions. Current runtime
composition registers a default-model health warmup; STT, wake model, TTS,
embeddings, and session restore can register later.

Warmup output is readiness evidence only. It cannot activate a capability,
create an approval, or make an unverified setup/test result authoritative.
