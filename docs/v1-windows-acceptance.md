# JARVIS v1 Windows Acceptance Evidence

**Run date:** 2026-08-25
**Repository:** Jamie1304/jarvis
**Branch:** agent/v1-integration
**Base HEAD:** d3933473f00b0c52eebf64ec56ef1dad6906ed07
**Working tree:** intentionally mutable and uncommitted
**Decision:** READY FOR RC FREEZE WITH DOCUMENTED OPTIONAL LIMITATIONS

This record covers the local Windows evidence run for the current working tree.
It used only repository-controlled synthetic fixtures, localhost Ollama, owned
Notepad, the attached microphone/camera, and bounded temporary state. No real
credentials were used, no recordings or images were retained, and no external
network probing was performed. No commit, push, merge, tag, publication, or
release was performed.

## Evidence classes and release claim matrix

These labels are deliberately not interchangeable:

| Class | Meaning in this run |
|---|---|
| REAL_WINDOWS | An actual Windows API, process, device, or configured local service was exercised on this host. |
| LOCAL_INTEGRATION | A repository-owned local process or localhost service was exercised through its production adapter. |
| DETERMINISTIC | A bounded synthetic fixture or fake backend was used. It is not evidence of a real external device or companion. |
| OPTIONAL_NOT_AVAILABLE | The capability is optional and unavailable; this is not counted as a pass. |
| NOT_EXECUTED | The required prerequisite or operation was not run. |
| NOT_PROVEN | Existing deterministic/composition evidence is insufficient for the stated real-Windows claim. |

| Claim class | v1 interpretation |
|---|---|
| REQUIRED_FOR_WINDOWS_V1_RELEASE | Core startup/restart/shutdown, broker/security boundaries, canonical task execution, trusted generated-process containment, and the configured local-provider path. These need real evidence on the release host. |
| OPTIONAL_HARDWARE_CAPABILITY | Full conversational voice/wake/PTT/TTS behavior and camera use. Missing hardware or a failed optional provider degrades that capability; it does not make the whole core pass. It is still not recorded as passed. |
| OPTIONAL_EXTERNAL_RUNTIME | Browser companion, configured external MCP server, and other optional companions. No mock is promoted to real evidence. |
| DETERMINISTICALLY_PROVEN_ONLY | Unknown-capability acquisition, certification/Shadow/Canary, recovery/update, backup/migration, UI simulation, browser fake backend, and most adversarial package behavior. |
| NOT_A_V1_CLAIM | Donor runtimes, cloud/vendor services, gesture control, VM/kernel isolation, cross-machine secret migration, and uncontrolled direct MCP/terminal execution. |

The matrix does not remove a release-critical claim to make the result green.
Optional voice/camera absence is not a whole-application failure, but the
optional capability remains NOT_PROVEN or NOT_AVAILABLE.

## Host and declared dependencies

| Item | Observed value | Evidence |
|---|---|---|
| OS | Windows 10 Home, build 19045, x64 | REAL_WINDOWS |
| CPU | Intel Core i7-6700 @ 3.40 GHz, 8 logical processors | REAL_WINDOWS |
| RAM | 34,311,077,888 bytes | REAL_WINDOWS |
| GPU | NVIDIA GeForce GTX 1060 6GB, driver 581.80, nvidia-smi memory 6144 MiB | REAL_WINDOWS |
| Python | 3.13.14 from the repository .venv | REAL_WINDOWS |
| Ollama | 0.32.15, local executable, llama3.2:3b present | REAL_WINDOWS, localhost only |
| Audio endpoints | Nor-Tec streaming microphone, USB 2.0 camera microphone, High Definition Audio, speaker/headphone outputs | inventory only |
| Camera | OpenCV enumerated device 0 | REAL_WINDOWS functional test below |

The only packages installed for this run were already declared optional project
extras. Versions imported successfully were:

| Extra | Packages |
|---|---|
| windows | Pillow 11.1.0, pywinauto 0.6.9 |
| camera | opencv-python 4.11.0.86 |
| speech | sounddevice 0.5.1, faster-whisper 1.1.0, pyttsx3 2.98, numpy 2.2.1 |

openwakeword, Playwright, and Selenium were not installed. No dependency was
added merely because an old report named it. The system Python at
C:\Python314\python.exe is not the release interpreter because it lacks the
declared development dependencies.

## Production composition evidence

An actual ApplicationRuntime.create() was run with
Settings(environment="production", app_data_dir=<isolated temporary path>,
ai_provider="ollama"):

* runtime status was ready;
* the composed TestDrive returned fully_ready=True, with
  system-health=PASS and model-provider=PASS;
* service statuses were voice UNAVAILABLE, camera UNAVAILABLE, browser
  UNAVAILABLE, environment discovery DEGRADED, presentation AVAILABLE,
  and UI simulation AVAILABLE;
* the isolated state directory was removable after shutdown;
* the runtime shutdown path is idempotent in the deterministic tests.

The unavailable optional services did not cause a core startup failure and did
not create an uncontrolled fallback.

## Actual Windows checks

### Generic desktop accessibility/UI Automation — PASS (REAL_WINDOWS)

The opt-in test used the production WindowsUiAutomationAdapter and
WindowsAccessibilityAdapter, not coordinates or a fake backend. It:

1. resolved the trusted system Notepad executable;
2. launched only the process returned by the adapter;
3. discovered the window by the exact owned PID (the installed title is localized);
4. focused the window and inspected its semantic UI Automation tree;
5. found an accessible Edit control and entered known temporary text;
6. verified the same text through the clipboard adapter;
7. captured one screen artifact in memory; and
8. closed only the owned PID tree.

The test does not retain the screen bytes. The localized-title correction is a
test-harness fix: ownership remains PID-based, never title-based.

### Camera lifecycle — PASS (REAL_WINDOWS, optional capability)

OpenCV enumerated trusted device 0. The production CameraController opened,
captured, encoded, released, reopened, and captured again. Both frames had
positive dimensions and data; the controller ended inactive. Frames were not
written to disk or retained.

### Microphone capture and local STT — PASS for the exercised primitive (REAL_WINDOWS)

SoundDeviceAudioSource opened the default input and delivered one bounded
1,280-sample frame before clean stop. A separate 1.2-second SoundDeviceRecorder
capture delivered 19,136 samples to the cached local Whisper base model.
Transcription completed in 8.7 seconds with an empty ambient result; only result
length/metadata were recorded and no audio was retained.

This does not prove the complete voice runtime: the runtime composition leaves
voice disabled by default, and the PTT/wake/streaming/barging/session path was
not driven by a real user utterance.

### TTS — NOT_PROVEN / optional degradation required (REAL_WINDOWS attempt)

The bounded Pyttsx3TtsProvider attempt for one short phrase did not return
within its 20-second bound and was terminated by the local test harness. No
Python or SAPI worker remained afterward. The provider therefore cannot be
reported as a passing Windows output capability in this run. The safe product
state for this result is text-only/fallback output; spoken privileged approval
remains disabled by design and cannot fall back to speech recognition.

### Local model, sessions, and Agent Runtime — PASS with explicit limits

The configured Ollama endpoint was contacted only on 127.0.0.1:

* health returned available;
* the production ConversationService completed a short streaming turn and
  bound an AgentSession;
* a second turn reused the same session;
* cancellation marked the session unsynchronized and the next turn rebuilt it;
* a production AgentLoop request reached the brokered safe calculator through
  structured model output and returned a confirmed calculator effect. The next
  model response was malformed, so the overall loop was not treated as a full
  success.

The provider has no exercised production unload/reload control in this path.
No benchmark is claimed from this run; only observed health, turn counts,
latency, session reuse, cancellation, and resynchronization are recorded.

### ResourceGovernor — PASS for admission/telemetry

The runtime-owned SystemResourceTelemetry observed 8 cores, 34.3 GB total
RAM, 18.8 GB available RAM, about 902 GB free disk, and AC power. A real
interactive and background admission was allowed under the observed state. A
separate controlled synthetic pressure snapshot deferred background work while
allowing interactive work; the interactive reservation was released as
completed, leaving zero active reservations.

### Windows generated-process containment — PASS for the declared contract

Repository-owned child processes exercised the canonical AppContainer path,
ACLs, explicit handle list, Job Object, process cleanup, IPC bounds, outside-root
denial, loopback network denial, and fail-closed unavailable-feature paths.
The actual AppContainer test passed on this host and is stronger evidence than
same-user Job cleanup alone. It is not a VM, dedicated-account, kernel, or
universal TOCTOU guarantee; the limits are documented in
docs/security/windows-integration-isolation.md.

## Optional or unavailable external paths

### Browser companion — NOT_EXECUTED (OPTIONAL_EXTERNAL_RUNTIME)

Microsoft Edge was running, but no supported trusted companion or debugging
endpoint was configured. Playwright and Selenium were absent, and no local MCP
browser bridge was configured. Deterministic fake-browser broker tests pass but
are not converted into real-browser evidence. The runtime reports browser
UNAVAILABLE and has no unsafe fallback. This is a blocker only if a browser
companion is promoted to a required v1 claim.

### MCP — transport PASS, complete production manager NOT_PROVEN

The repository-owned stdio transport round-trip, malformed protocol, exact
identity, timeout/cleanup, and restart-related tests pass. A configured real
MCP server was not available for this run. The current runtime creates the
MCP manager but does not consume a configured MCP server in this environment;
therefore a direct test-fake manager is not presented as production-composition
evidence. External MCP remains optional and cannot become a release claim by
test substitution.

### Existing-capability identity — PASS for the exercised observation contract

The opt-in test
`tests/test_adoption.py::test_real_windows_identity_is_opt_in_and_observation_only`
ran with `JARVIS_RUN_WINDOWS_IDENTITY_TESTS=1` against the configured local
Python executable. The production `WindowsFileIdentityProvider` observed volume
serial `2686182429`, file ID `004c000000000078`, and content hash
`b70275ad94210fce7548761143be5e177769721045e287bb6c80aac3f928c65b`. The
production `WindowsSignerVerifier` returned `VALID_TRUSTED_SIGNATURE`.
No process was launched by the test and no privileged operation was attempted.
This proves the observation path on this host only; adoption policy still binds
independent dependency provenance, reinspection, compatibility, expiry, and
normal PermissionBroker requirements.

### Unknown capability and recovery/update — DETERMINISTICALLY_PROVEN_ONLY

The production composition and v1 acceptance suites exercise randomized local
capability acquisition, package review/certification, Shadow/Canary, lifecycle
restore, trace, backup, and trusted recovery seams. They do not constitute a
real Windows installation of a newly generated executable, a signed candidate
update, or a destructive rollback. Those claims remain deterministic-only.

## Burn-in and leak checks

A bounded 20-cycle local burn-in used the real ApplicationRuntime composition.
Each cycle created a temporary app-data root, created a conversation/session,
ran a TaskController -> PlanningEngine calculation, shut down, and removed
the exact temporary root. Results were 20/20 completed tasks, 20/20 cleaned
roots, zero failures, and no residual Python worker process after the run.

This is a lifecycle burn-in, not a multi-hour battery/disk/GPU stress test and
not evidence that every optional external subsystem is available.

## Exact commands and results

All commands below used D:\JARVIS\.venv\Scripts\python.exe.

| Command | Result |
|---|---|
| python scripts/quality.py (test fixture environment) | PASS - 1,360 passed, 6 skipped, 90% coverage; Ruff and mypy passed |
| python scripts/run_system_tests.py --suite deterministic-workflows | PASS - 26; run a6ccfbfe-9d5d-4079-b7da-62dae9dda1cb |
| python scripts/run_system_tests.py --suite deterministic-permissions | PASS - 72 passed, 1 skipped; run 01b7e1f3-408c-4691-a230-8fe0981fab2b |
| python scripts/run_system_tests.py --suite v1-acceptance | PASS - 21; run 0ac58287-a1c2-4e88-a3dc-a37295fc6298 |
| python scripts/run_system_tests.py --suite windows-hardware-manual | SKIPPED - explicit opt-in required; run 2b3fa806-1783-4dac-bd4c-af398b14120a |
| JARVIS_CAMERA_INTEGRATION=true python scripts/run_system_tests.py --suite windows-hardware-manual --allow-hardware | PASS - 3; run b8c2922b-52a1-4b98-bbc1-bd5534cdb7cb |
| JARVIS_WINDOWS_INTEGRATION=true JARVIS_CAMERA_INTEGRATION=true pytest tests/test_windows_integration.py -q -rs | PASS - 3 |
| pytest tests/test_sandbox.py tests/test_windows_sandbox_native.py -q -rs | PASS - 34 |
| targeted AppContainer/restricted-token/fail-closed tests | PASS - 3 |

The system Python command was not used to claim a pass: it lacks the project
development dependencies. No skipped or unavailable result was counted as a
pass.

## Remaining blockers and decision

WINDOWS_REQUIRED_EVIDENCE_COMPLETE: YES
WINDOWS_OPTIONAL_EVIDENCE_COMPLETE: NO

The real Windows evidence now closes the former UI/camera/process-containment
test gap for the exercised contracts. It does not claim the following optional
or deterministic-only capabilities as real-world evidence:

1. broad third-party executable adoption, dependency provenance completeness,
   and signer/revocation behavior beyond this local executable remain bounded
   by the adoption policy and are not inferred from this one observation. The
   native identity opt-in passes on this host; the default local runtime could
   not initialize Windows Credential Manager for trusted recovery and therefore
   correctly fails closed as `RecoveryAuthorityUnavailable` rather than using a
   plaintext or test backend;
2. full production voice output/voice-runtime behavior is not proven and the
   configured local TTS attempt timed out (optional capability, safe text-only
   degradation required);
3. browser companion and complete configured MCP manager evidence are absent
   (optional external runtimes); and
4. capability acquisition, update/recovery, backup/migration, and Shadow/Canary
   external-effect claims remain deterministic/local evidence rather than a
   real generated-package or signed-update run.

No unavailable, unexecuted, or deterministic-only result is silently promoted
to PASS. These optional limitations do not block the declared v1 core claim;
safe degradation and deny-first behavior remain required. Gesture control and
donor frameworks remain outside the v1 claim and are not hard-coded into core.

R3 Windows evidence result: READY_TO_FREEZE_WITH_OPTIONAL_LIMITATIONS
