# UI simulation harness

**Status:** v1 native certification boundary
**Updated:** 2026-08-23

`UISimulationHarness` lets trusted application code test generated UI before a
package can be certified or staged. It is a deterministic simulation, not a
desktop automation bridge and not a production capability runtime.

## Contract

The harness loads a `UISimulationManifest` only when its package ID and version
match the supplied `IntegrationPackage`. The manifest declares bounded
components, safe package/artifact assets, fake actions, and states. Supported
built-in states are:

`IDLE`, `ACTIVE`, `LOADING`, `ERROR`, `DEGRADED`, `DISCONNECTED`, and
`WAITING_PERMISSION`.

Packages may add custom state names using the same bounded safe-state syntax.
Components cover containers, text, artifacts, images, documents, charts, plans,
model comparisons, controls, and safe declarative views. Components may be
state-specific. Unknown states, duplicate IDs, oversized content, unsupported
values, executable strings, and unsafe property names fail closed at manifest
validation.

## Zero authority

The harness has no real `Tool`, `ToolRegistry`, `PermissionBroker`, credential
vault, process, network, or desktop handle. `FakeCapabilityRegistry` exposes
capability-shaped action endpoints only. Invoking one records a simulated call
and returns `effect_count=0`; it cannot reach a real-world effect boundary.

Approval controls are not trusted merely because a generated UI labels them
“Allow”, “Approve”, or “Allow once”. Approval-like action IDs and labels are
reported as a security failure, and forbidden trusted-approval metadata is
rejected. The real trusted permission object remains application-owned and is
never fabricated by generated UI.

## Shot and evidence

`UISimulationHarness.shot(state)` renders one known declared state and returns:

- a semantic `UISimulatedView` with stable nodes and control tree;
- a deterministic render fingerprint and bounded render bytes; and
- `UISimulationEvidence` containing binding, asset, security, determinism,
  layout, and zero-effect checks.

The default render bytes are a canonical JSON render artifact. An application
may provide a bounded screenshot renderer, but pixel equality is not the
acceptance authority. Semantic/control-tree checks and targeted visual evidence
are primary. `run_all()` executes every declared state, including custom states.

`UISimulationHarness.attest(source_hash)` is the only certification-facing
operation. It runs every declared state, aggregates the semantic, binding,
security, asset, layout, determinism, and zero-effect checks, and returns a
trusted `UISimulationAttestation`. The attestation binds:

- package ID, version, package hash, and the built source hash;
- the UI manifest fingerprint, manifest schema version, harness version, and
  simulation policy version;
- every tested state, action-binding/security/asset check, zero-effect result,
  timestamp, and opaque ArtifactRefs for captured render evidence; and
- `PASS`, `PASS_WITH_RESTRICTIONS`, `FAIL`, `INVALID`, or `STALE`.

The attestation carries an application-issued self-digest and cannot be created
by package metadata, model output, a UI callback, or a caller-provided boolean.
The certifier accepts only a fresh harness-issued passing result whose package,
version, source binding, and digest still validate. Altering the package,
source snapshot, UI manifest, or version requires a new simulation run.

When configured with an app-owned `ArtifactStore` and workspace, the shot is
stored as an internal artifact with package/version provenance. Package assets
must be declared immutable entries below the package asset root with matching
hashes. Artifact assets require a workspace-checked `ArtifactStore` reference,
matching content hash, and non-secret classification. No arbitrary path is
rendered, and credential secrets cannot become UI evidence.

## Certification and activation

`PackageCertifier` deterministically treats validated packages with UI assets or
profiles as UI-bearing. It requires a fresh `UISimulationAttestation` supplied
by the trusted application composition hook. The old harness-available flag and
free-form evidence strings are metadata only and cannot satisfy this gate. A
missing, malformed, failed, stale, or mismatched attestation rejects
`VERIFICATION` and therefore cannot produce `CERTIFIED`.

The attestation is appended to the verification record and its reference/digest
is persisted in the canonical lifecycle certification record, but it does not
certify package code by itself and does not make the package active.
Static review, unit tests, sandbox integration, permission diff, trusted
authority decision, health, verification, Shadow, Canary, and activation gates
remain separate.

The harness does not validate physical desktop pixels, camera gestures, or a
real control invocation. Those remain manual or later capability tests. A
future gesture capability must follow the normal gap, research, generated
integration, camera permission, sandbox, certification, and staged activation
path; gesture control is not part of this core harness.
