# Production capability status

This document distinguishes a tested abstraction from a provider that has actually
used the local machine. Every privileged operation remains a registered tool behind
`PermissionBroker`; this table is not an authorization grant.

| Capability | Provider / evidence | Status |
| --- | --- | --- |
| Semantic Windows discovery, focus, accessibility, text, mouse fallback, screenshot, clipboard | `WindowsUiAutomationAdapter` / `WindowsAccessibilityAdapter`; opt-in Notepad acceptance | available but not verified on this host |
| Controlled commands and scoped file reads | `SubprocessCommandAdapter`, `ControlledCommandService`, filesystem tool | deterministic-test verified |
| Windows Notepad interaction | `tests/test_windows_integration.py`, enabled only by `JARVIS_WINDOWS_INTEGRATION=true` | disabled by default; skipped without an interactive desktop |
| Visual grounding/verification | `VisionProvider`, fusion, stale-observation guard, brokered computer tools | deterministic-test verified |
| Local multimodal vision | configurable `OllamaVisionProvider`, screenshot-store loader, health/model detection and strict JSON validation | deterministic-test verified; disabled in canonical runtime |
| One-shot camera capture | `OpenCvCameraProvider`, explicit controller allowlist, ephemeral frame store | deterministic-test verified; hardware provider available but not verified |
| Windows installed-app inventory | read-only uninstall registry provider; `winget` availability check | deterministic-test verified; host registry/package-manager acceptance disabled |
| Application install/update | exact candidate/source/version plan and independent inventory/launch verification | disabled in canonical runtime |
| Local audio source/wake/VAD | `SoundDeviceAudioSource`, `OpenWakeWordProvider`, `EnergyVADProvider` | VAD deterministic-test verified; hardware/wake provider available but not verified |
| Voice conversation UX | canonical task-controller integration only | disabled pending a separately configured UI/runtime composition |

## Acceptance rules

Real Windows and camera checks are opt-in and must run in a dedicated interactive
session. A skipped check means **not executed**, never success. The Notepad test
launches a catalogued `notepad.exe`, finds the exact PID it created, uses semantic
UI Automation, performs a clipboard roundtrip and screenshot, and terminates only
that PID in cleanup. It does not use a simulated adapter.

Set `JARVIS_CAMERA_INTEGRATION=true` only on a dedicated Windows machine with a
reviewed camera at device ID `0`. The acceptance check captures one frame through
an explicit allowlist, shuts the controller down, and asserts the device lifecycle
returns to `inactive`. It skips if the dependency or device is unavailable.

## Provider configuration and safety

The canonical runtime keeps computer control, camera, package installation, local
vision inference, and voice activation disabled until trusted application
composition supplies provider configuration, an explicit catalog/allowlist, and
narrow policies. `winget` detection is read-only; no CI test installs software.
OpenCV devices must be both provider-accepted and controller-allowed. Local voice
providers process transient host audio only; neither idle frames nor camera frames
are persisted by these adapters.
