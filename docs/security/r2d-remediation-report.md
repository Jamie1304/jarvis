# R2D remediation report

Date: 2026-08-24
Scope: R2A trust-boundary review, R2B secure-code review, and R2C synthetic
negative-test coverage
Repository: `Jamie1304/jarvis`

## Executive result

The actionable findings were reproduced only with local synthetic fixtures. The
following narrow fixes are now present:

- adoption decisions bind to an explicitly selected candidate and its SHA-256
  identity digest, are persisted, and are re-inspected before use;
- generated knowledge snapshots have a trusted generated-root requirement,
  byte/list/field bounds, strict types, future-schema refusal, digest checks,
  and relative provenance-path checks;
- ArtifactStore rejects reparse ancestors and uses exclusive/no-follow file
  descriptors where the host provides those flags;
- presentation snapshots explicitly distinguish a requested state from an
  independently observed state, and unobserved request echoes cannot satisfy
  screen verification;
- the earlier R2B fixes for provider streams, vision values, generated UI
  authority imitation, MCP launch handling, and Winget launch identity remain
  covered by regression tests.

The repository is **GO for the requested code-quality and deterministic
workflow gates**, but **NO-GO for enabling generated/MCP hostile-code
activation, production browser actions, spoken privileged approval, or
self-update/code LKG restore**. Those capabilities still have unresolved
trust-boundary requirements listed as `REQUIRES_FOLLOWUP` below. No CRITICAL
finding was reported by R2A or R2B; unresolved HIGH findings remain release
blockers for their respective capabilities.

No commit, push, merge, tag, release, external-system access, or uncontrolled
network activity was performed.

## Status rules

- `FIXED`: the reported defect is rejected by the implementation and has a
  passing regression test.
- `MITIGATED`: the unsafe path is bounded or inactive, but a stronger control
  is still required before a dependent capability is enabled.
- `ACCEPTED_RISK`: the residual is documented and does not grant authority or
  cross a v1 trust boundary under the current composition.
- `NOT_REPRODUCED`: the reported condition was not reproduced in the reviewed
  repository and synthetic test environment.
- `REQUIRES_FOLLOWUP`: the current controls fail closed or keep the feature
  inactive, but the missing control is material and remains a release gate.

## Reproduction and remediation evidence

| Finding | Safe reproduction or evidence | Remediation and regression evidence | Status |
|---|---|---|---|
| R2A-H02 / R2B-H03 adoption identity | Before the patch, `test_adoption_rejects_unlisted_candidate_identity` completed instead of raising `SetupError` for an unlisted candidate ID. No binary was launched and no user data was changed. | `SetupConductor` now requires `candidate_id` and `identity_digest` for `USE_IN_PLACE`, records the digest in `SetupStepResult`, re-inspects immediately before verification, and rejects replacement. Tests: `tests/test_setup_conductor.py::test_adoption_rejects_unlisted_candidate_identity`, `::test_adoption_rejects_candidate_replacement_before_verification`, `::test_existing_local_runtime_is_adopted_without_provisioning`. | `MITIGATED` |
| R2B-M02 knowledge snapshot decoding | The existing repository index contains 83 items and a legitimate provenance map of 213 entries. The first bounded implementation exposed that fact and was corrected from 128 to a still-bounded 512-entry map; the real index then loaded successfully. | `jarvis/knowledge/store.py` enforces an 8 MiB file limit, bounded collections, exact scalar types, known fields, SHA-256 provenance, safe relative paths, and future-schema refusal. Tests: `tests/test_knowledge.py::test_knowledge_store_rejects_malformed_or_unbounded_generated_snapshot`, `::test_knowledge_store_rejects_invalid_types_and_supports_bounded_queries`. | `FIXED` |
| R2B-M01 ArtifactStore path boundary | A synthetic parent symlink fixture is rejected when link creation is available; the fixture skips only when the Windows test user cannot create a link. The existing forged storage-reference test remains denied. | `jarvis/artifacts.py` rejects reparse ancestors of the root and content path, uses `O_EXCL`/`O_NOFOLLOW` where available for creation/read, and rechecks before deletion. Test: `tests/test_artifacts.py::test_artifact_root_rejects_reparse_ancestor_when_supported`. Windows handle-relative delete/TOCTOU protection is not claimed. | `MITIGATED` |
| R2A-M07 presentation evidence | A surface without an observer previously returned the same state it had requested, which could be mistaken for a physical screen observation. | `UiStateSnapshot.observed` is explicit; `VerificationEngine` treats an unobserved state as contradictory evidence. Tests: `tests/test_verification.py::test_unobserved_presentation_state_cannot_prove_screen_outcome`, `tests/test_presence_presentation.py::test_presentation_observer_rejects_snapshot_for_another_surface`. | `FIXED` |
| R2B-F01 provider stream schema | Synthetic malformed Ollama stream chunks were rejected by the existing R2B regression suite. | Strict bounded stream/schema handling remains in `jarvis/ai/providers/ollama.py`; tests: `tests/test_ollama_provider.py`. | `FIXED` |
| R2B-F02 vision values | Synthetic non-finite and wrong-type vision values were rejected. | Strict finite numeric/schema validation remains in `jarvis/vision/models.py` and `jarvis/vision/local.py`; tests: `tests/test_vision.py`. | `FIXED` |
| R2B-F03 generated UI authority imitation | Randomized semantic approval-like controls are rejected without relying only on a fixed button name. | Conservative authority-imitation checks remain in `jarvis/ui_simulation.py`; tests: `tests/test_ui_simulation.py::test_approval_spoof_is_rejected_by_security_evidence`, `::test_semantic_authority_spoof_is_rejected_even_without_known_button_names`. | `FIXED` |
| R2B-F04 MCP launch boundary | Synthetic bad executable identity, environment, redirect, result, collision, and failed-start cases are denied/cleaned up. | Exact stdio identity, sanitized environment, redirect policy, startup cleanup, and schema/namespace validation remain in `jarvis/mcp/client.py`; tests: `tests/test_mcp.py`. | `FIXED` |
| R2B-F05 Winget launch boundary | A synthetic PATH/ambiguous executable cannot become the trusted Winget process. | Trusted executable identity and bounded launch remain in `jarvis/applications/providers.py`; tests: `tests/test_applications.py`. | `FIXED` |

## Finding disposition

### HIGH findings

#### R2A-H01 / R2B-H01 — same-user subprocesses are not an OS security boundary

**Historical status: `MITIGATED`; R4 status: `RESOLVED` for the canonical
generated executable package path.**

The Windows `SandboxProcess` path now adds a restricted primary token,
explicit standard-handle inheritance, suspended launch with pre-resume Job
assignment, native lifecycle limits, fail-closed setup and bounded descendant
cleanup. This is a material mitigation, not a complete same-user OS security
boundary; filesystem/network/code-integrity isolation remains unproven and
release-blocking. The exact contract is recorded in
`docs/security/windows-integration-isolation.md`. That was the R2D baseline;
the R4 native AppContainer follow-up is recorded below.

`jarvis/sandbox.py` provides typed IPC, bounded messages, restricted-token
launch on Windows, explicit handles, pre-resume Job assignment, cleanup, and a
Windows Job Object where available. Those mechanisms are useful containment,
but a same-user child is not prevented from using ambient OS authority merely
by a sanitized environment, token reduction, or process-group ownership. The
default runtime still records generated activation as disabled in
`jarvis/runtime.py`, and the MCP registry is sealed in the production
composition.

Synthetic tests prove bounded IPC, identity rejection, oversized-message
rejection, restricted-token status, explicit non-inheritance of a trusted
handle, mandatory-feature fail-closed behavior, crash containment,
proxy path/origin/credential scope checks, descendant cleanup and restart
limits (`tests/test_sandbox.py`, `tests/test_sandbox_proxies.py`, and
`tests/test_mcp.py`). They do not prove AppContainer, VM, same-user
filesystem/network denial, or an equivalent complete boundary. The follow-up
must add an owned Windows isolation environment and reject activation when
that boundary is not available. No generated code was enabled by this run.

R4 completed that follow-up for the canonical `SandboxProcess` path. The
capability-free AppContainer launcher now applies scoped ACLs, explicit stdio
handle inheritance, and pre-resume Job assignment. Outside synthetic file
read/write and local loopback probes are denied, and malformed/unavailable
AppContainer setup fails closed. `PackageCertifier` and
`PackageActivationService` require the observed status for executable packages;
the durable activation record retains the selected mode. Direct uncomposed MCP
or terminal process paths remain separately blocked and are not covered by this
resolution. Evidence is in `docs/security/windows-integration-isolation.md`,
`tests/test_sandbox.py`, `tests/test_package_certification.py`, and
`tests/test_package_activation.py`.

#### R2A-H02 / R2B-H03 — adoption identity binding

**Status: `MITIGATED`; exact trusted platform identity remains a follow-up.**

The patch closes the demonstrated confused-deputy case: a setup decision cannot
name an unlisted candidate, omit the identity digest, or pass verification
after the inspected candidate changes. The digest is persisted with the setup
result and candidate selection is not taken from an arbitrary caller-supplied
record.

The digest is still measured by the composition-owned setup handler. The
repository does not yet provide a Windows-native signer/file-ID/dependency-lock
adapter that independently measures the executable and protects that
measurement from a mutable handler. Adoption of untrusted existing binaries
therefore remains blocked until that adapter and its owned-process tests exist.

#### R2A-H03 / R2B-H04 — staged activation observations are not independently authoritative

**Status: `FIXED` for the callback/effect-evidence gap; Windows isolation remains a separate limitation.**

`jarvis/effect_attestation.py` now records broker-bound attempts and immutable
observations, and `jarvis/sandbox_proxies.py` supplies the trusted observer at
the host dispatch boundary. Shadow requests are recorded as suppressed before
dispatch; unfinished attempts reconcile to `UNKNOWN_OUTCOME` after restart.
`PackageActivationService` rejects missing, forged, or mismatched attestations,
uses trusted dispatch counts/effect descriptions, and requires an independent
non-model `VerificationResult` before promotion. Callback `effects`, `passed`,
and “I did nothing” claims cannot qualify staged activation.

Evidence references are retained in `ActivationRecord.attestation_ids`, host
proxy audit events, and `TraceEvent.effect_attestation_ids`. Regression coverage
is in `tests/test_effect_attestation.py` and `tests/test_package_activation.py`.
The separate R2B-H01 same-user Windows isolation limitation is not reclassified
by this fix.

#### R2A-H04 — UI simulation approval imitation

**Status: `FIXED` for the reported narrow defect; generated UI remains gated by
H01/H03.**

The earlier R2B fix replaced the narrow exact-name conjunction with conservative
semantic authority-imitation checks. Declarative UI cannot mint a broker
approval, and the host-owned permission surface remains the authority. The
passing randomized semantic-spoof tests are listed above. Ambiguous UI still
requires host review/certification; this fix does not authorize generated UI.

#### R2A-H05 / R2B-H02 — authenticated recovery/LKG authority

**Status: `FIXED` for the current local recovery contract.**

`jarvis/recovery.py` now has manifest schema 3, per-file SHA-256 hashes,
path/reparse checks, exact application build hashing, and a
`TrustedRecoveryAuthority`. `last-known-good.json` carries a signed
`TrustedRecoveryRecord` bound to the manifest, transaction, installation,
revision/build hash, configuration/database compatibility, status, authority
version, prior record, and monotonic generation. The HMAC key and generation
floor live in the secure backend and are never written beside recovery files.
Missing, modified, future, stale, unrelated, or unavailable-backend state fails
closed and Safe Mode is used when no authenticated restore point remains.

Regression evidence is in `tests/test_recovery_authority.py` and the existing
`tests/test_recovery.py` suite: authenticated restart, field mutation,
corrupted auth, key/backend loss, candidate self-promotion, failed health,
successful promotion, rollback, and future-schema behavior.

The specific unauthenticated-LKG finding is fixed. Vendor-signed release
provenance and a complete self-update executor remain separate trusted gates;
this remediation does not enable them.

#### R2A-H06 / R2B-H05 — spoken affirmative phrases are not speaker authentication

**Status: `REQUIRES_FOLLOWUP`. Blocks spoken privileged approval.**

The current safe behavior is strict and non-authorizing: exact transcript
parsing rejects conditional/ambiguous phrases, while microphone mode, wake
state, TTS output, and model text do not alter PermissionBroker policy. Tests:
`tests/trusted_core/test_permission_presentation.py::test_spoken_approval_is_strict_and_non_authorizing`
and `tests/test_voice.py::test_microphone_modes_are_explicit_and_not_authority_modes`.

There is no trusted speaker/owner authentication binding that proves the
transcript came from the owner in response to the current request. Until that
exists, voice may remain text-only/degraded but cannot authorize privileged
effects.

#### R2A-H07 — browser gate canonical Broker adapter remediation

**Status: `FIXED` for the supported configured runtime path.**

`jarvis/browser.py` still defaults to `DenyBrowserPermissionGate` and validates
stale document generation, origin, cross-origin frames, password redaction, and
tab closure. `jarvis/browser_broker.py` now closes the composition gap by
registering strict per-action tools in `ToolRegistry` and routing them through
the canonical `PermissionBroker -> Policy` path before backend dispatch. The
exact tab/document/origin/argument binding, missing-vault rejection, unsupported
backend behavior, and runtime composition are covered by deterministic tests.

## MEDIUM, LOW, and informational findings

| Finding | Status | Evidence/disposition |
|---|---|---|
| R2A-M01 static review is not code-safety proof | `MITIGATED` | `GeneratedPackageReviewer` remains a fail-closed restricted gate and never becomes activation authority. Manual review, sandbox, certification, and staged activation are still required. |
| R2A-M02 provider stream validation | `FIXED` | Covered by the strict Ollama stream implementation and malformed-stream tests listed above. |
| R2A-M03 AgentSession workspace binding | `REQUIRES_FOLLOWUP` | Current composition is single-scope and tests pass; immutable workspace/profile/classification binding is required before multi-workspace session reuse. |
| R2A-M04 procedure learning trust metadata | `FIXED` | Runtime-owned `ProcedureEvidenceAuthority` now issues proof only from completed durable Task/Plan state, passing VerificationEngine evidence, confirmed outcome, and durable Trace IDs. `ProcedureBank` ignores caller trust flags; forged/unknown/unverified observations are rejected and regression coverage passes. |
| R2A-M05 event source authenticity/storms | `MITIGATED` | Bounded queues, correlation caps, feedback guards, automation deduplication, ordinary Goal dispatch, and no approval payload path pass the event/automation tests. Authenticated producer identity remains a hardening follow-up. |
| R2A-M06 artifact/backup secret classification | `MITIGATED` | Credential-secret artifacts are rejected and backup tests cover secret components, encryption, tamper, wrong key, reauthorization, and recertification. A Vault-only exporter/registration boundary remains follow-up before arbitrary generated providers can contribute data. |
| R2A-M07 presentation query evidence | `FIXED` | Explicit `UiStateSnapshot.observed` and verification regression added in this run. |
| R2A-M08 attention/proactive preparation | `REQUIRES_FOLLOWUP` | A dedicated durable priority/expiry attention queue is not present; this is an incomplete capability, not an authority bypass. |
| R2A-M09 certification/drift/repair provenance | `REQUIRES_FOLLOWUP` | Composition callbacks and typed records are safe only inside the trusted process. Cross-process authenticated provenance and durable independent observation are still required. |
| R2A-L01 defensive heuristic/provider-detail limits | `ACCEPTED_RISK` | These are bounded detection/availability limits with no permission or trusted-identity grant. They remain documented and tested as defense-in-depth. |
| R2A-I01 donor/runtime and product-specific core scan | `NOT_REPRODUCED` | Repository scan and quality tests found no donor runtime dependency or new product-specific core adapter in this run. |
| R2B-M03 generic command process-tree/cwd identity | `REQUIRES_FOLLOWUP` | No shell-by-default path was found; timeout and executable checks exist. A Windows Job Object/handle-relative cwd identity contract is still needed for untrusted command execution. |
| R2B-I01 dangerous primitive scan | `NOT_REPRODUCED` | No production `shell=True`, `os.system`, pickle/marshal/dill, or unsafe YAML loader was found in the reviewed paths. |

## R2C negative-test coverage disposition

R2C is a coverage matrix rather than a finding list. Its synthetic negative
tests are now green in the full quality run. The matrix covers malformed agent
requests, budget escalation, fake completion, forged/expired/replayed
approvals, context poisoning and workspace isolation, MCP schema/collision and
proxy boundaries, credential leakage, browser stale/origin/password controls,
automation storms, Shadow/Canary/self-promotion/drift, generated UI simulation,
plan revision and unknown-effect replay, backup/recovery, self-improvement and
Golden Workflow tampering, voice ambiguity/mode separation, and setup/adoption.

New or directly expanded regression tests in this remediation run are:

- `tests/test_setup_conductor.py` — candidate identity selection,
  replacement, persistence validation, and malformed identity metadata;
- `tests/test_knowledge.py` — generated-root, future schema, malformed type,
  bounds, digest, and provenance-path rejection;
- `tests/test_artifacts.py` — reparse ancestor rejection;
- `tests/test_presence_presentation.py` and `tests/test_verification.py` —
  observer surface binding and no request-echo screen proof.

The R2C test status is `FIXED` as coverage. It does not change the
`REQUIRES_FOLLOWUP` architecture blockers above.

## Exact validation

Targeted remediation tests:

```text
python -m pytest tests/test_setup_conductor.py tests/test_artifacts.py tests/test_knowledge.py tests/test_presence_presentation.py tests/test_verification.py -q
47 passed, 1 skipped; the skip is the Windows symlink fixture because link creation is unavailable to this test process
```

Repository gates:

```text
python scripts/quality.py
1155 passed, 6 skipped; Ruff passed; mypy passed; coverage 90%

python scripts/run_system_tests.py --suite deterministic-workflows
passed; pytest:passed 26
```

The optional skips are not converted to passes. They include environment-bound
Windows/hardware or link-creation checks. No physical camera, microphone,
speaker, browser, external provider, generated integration, or OS-isolation
manual test was claimed as executed by this report.

## Next run

1. Keep direct uncomposed MCP/terminal process launchers blocked; the canonical
   generated `SandboxProcess` path now has the tested AppContainer/ACL/Job
   boundary, but stronger VM/dedicated-account/kernel guarantees and manual
   acceptance remain outside this remediation.
2. Trusted independent Shadow/Canary effect attestation is implemented for
   supported broker paths; retain the exact activation-bound evidence gate.
3. Retain the authenticated recovery/LKG record and extend the same trusted
   owner/generation/migration gates to any future self-update executor.
4. Add trusted executable identity/signature/dependency measurement for setup
   adoption.
5. Keep voice privileged approval disabled until speaker/owner authentication
   is bound to the exact trusted PermissionRequest; keep the canonical browser
   Broker adapter deny-first and prevent uncontrolled fallbacks.
6. Replace caller-supplied procedure trust metadata with VerificationEngine-
   derived evidence before autonomous procedure banking.

## Browser Broker remediation update

R2A-H07 is **FIXED for the supported configured runtime path**. The native
`BrowserBrokerAdapter` registers strict per-action tools in `ToolRegistry` and
routes them through `PermissionBroker` before the trusted browser backend is
called. Regression evidence in `tests/test_browser.py` covers broker dispatch,
denial before backend effects, stale/origin binding, password redaction,
missing-vault rejection, unsupported backend rejection, and runtime
composition. Missing or unsupported browser companions remain unavailable;
there is no uncontrolled fallback and no OS browser-process isolation claim.
See `docs/security/browser-broker.md`.
