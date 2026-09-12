# Presence and presentation

**Status:** v1 native application primitives
**Updated:** 2026-08-23

JARVIS has one ambient display projection and one generic presentation boundary.
Neither is a task engine, permission authority, artifact owner, or donor runtime.

## PresenceProjection

`PresenceProjection` subscribes to the canonical typed `EventBus` and derives a
small `PresenceSnapshot` from facts already owned by runtime/application
services. It can represent:

`IDLE`, `LISTENING`, `THINKING`, `EXECUTING`, `WAITING_PERMISSION`, `VERIFYING`,
`SPEAKING`, `DEGRADED`, `ERROR`, and `SAFE_MODE`.

Task, voice, tool, permission, health, runtime, and error events are inputs only.
The projection is rebuildable and exposes no mutation path to those owners. A
projection revision and source event ID make observations traceable without
making them durable domain truth. Safe Mode has explicit precedence and remains
diagnostic-only; displaying it does not disable or bypass policy because the
projection has no authority to do so.

Optional microphone level, speech envelope, activity level, and alert text are
bounded display signals. They are not authentication, approval, or policy
inputs. A microphone/listening mode therefore cannot change the permission
constitution.

## Safe themes

`PresenceThemeManifest` contains an ID/version, supported states, declarative
layout and animation values, visual parameters, and opaque
`PackageAssetReference` values. Theme values are bounded and reject executable
HTML/JavaScript/Python, script URLs, unsafe properties, and arbitrary paths.
Themes are package-owned data; the trusted desktop UI does not interpret theme
code. A package asset reference identifies a certified package asset and hash,
not a filesystem path.

## PresentationSurface

`PresentationSurface.present()` accepts typed `PresentationContent` values. A
content item may be:

- an `ArtifactReference` validated against the workspace and `ArtifactStore`;
- a certified package asset reference;
- a bounded declarative document, chart, plan, model comparison, or control.

Declarative controls describe an application operation for trusted application
services to render. They do not execute an operation and cannot manufacture an
approval. The model can supply untrusted data for a safe declarative view, but
cannot supply HTML, scripts, Python, executable callbacks, or arbitrary paths.

The surface renderer is an application-owned adapter. `query_state()` calls the
surface observer when one is configured and returns the actual observed
`UiStateSnapshot`; it does not simply return the last request. A stable
presentation ID, generation, and content hash allow `VerificationEngine` to
compare intended and observed state and report missing or unexpected entries.
Without an observer, the in-process surface state is the bounded fallback
observation and should be treated as a local projection rather than independent
proof of a physical display.

## Security and ownership

Presentation content never reads arbitrary paths. Artifact bytes and metadata
remain owned by `ArtifactStore`, whose workspace and classification checks still
apply. Credential secrets are not presentation artifacts. External/page/model
content remains data and is validated as such. Desktop and voice channels may
format the same trusted application object, but channel formatting cannot alter
facts, goals, permissions, or authority.

There is intentionally no gesture-control implementation in core. A future
camera/gesture capability must follow the normal capability path:

`CapabilityGap -> research -> generated integration -> camera permission ->
sandbox -> certification`

The `ai-visualizer` and `barehands` projects are reference-only inspirations and
are not imported, packaged, or required at runtime.

## Verification and tests

The native tests cover every presence state, event projection, bounded signals,
Safe Mode, declarative theme validation, artifact presentation, dynamic control
presentation, actual observer state, intended/actual mismatch, asset/path
escape, and executable/untrusted content rejection. Hardware display, camera,
gesture, and physical asset-rendering checks remain unexecuted manual tests.
