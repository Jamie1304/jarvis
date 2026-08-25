# R2B secure-code review

**Repository:** `Jamie1304/jarvis`
**Review baseline:** `d3933473f00b0c52eebf64ec56ef1dad6906ed07` plus the
uncommitted, narrowly scoped remediation changes listed in this document
**Review date:** 2026-08-24
**Review type:** authorized defensive Secure-SDLC review of JARVIS source,
configuration, tests, and local synthetic fixtures only

## Executive decision

**NO-GO for v1.0.0 if generated integrations, hostile MCP servers, adoption,
voice approval, browser mutation, or self-update are enabled with the current
optional composition.** The default core remains conservative: privileged work
must pass through `Tool -> PermissionBroker -> Policy`, the default approval
verifier denies, generated activation is disabled in the normal runtime
composition, and no donor runtime is required.

That default is an effective feature gate, not proof that the gated paths are
safe. The carry-forward high-risk findings from the R2A review remain blockers
for those paths, especially same-user sandbox limitations, adoption identity,
staged activation attestation, recovery trust, and spoken approval
authentication. No CRITICAL issue was identified in this bounded review. The
release requirement is therefore not met for an enabled self-expansion/update
profile because reachable HIGH findings remain without an OS/trusted-core
mitigation.

No external system, account, service, device, or network was targeted. No
exploit payload, credential collection, persistence mechanism, or evasion code
was created.

## Review method and trust assumptions

The review used source inspection, architecture reasoning, static searches,
existing security tests, and bounded local negative tests using temporary
directories, fake providers, fake MCP processes, and declarative UI fixtures.
The test run did not probe real networks or hardware.

The following are treated as untrusted data:

- model/provider output and stream metadata;
- MCP schemas, resources, and results;
- package manifests, generated source, diagnostics, UI, and migrations;
- browser/page text, voice transcripts, event payloads, discovery metadata,
  documents, memory, and knowledge;
- filesystem/application observations and backup component payloads.

Only trusted application code may create identity, policy, approval, mutation
authority, certification, or an execution receipt. A model claim of success is
not evidence. Derived events, traces, projections, artifacts, memories,
knowledge indexes, and backup bundles do not replace the authoritative owner of
their domain.

## Boundary review matrix

| Area | Trusted inputs | Untrusted inputs | Authority owned | Must never own | Current fail behavior / control |
|---|---|---|---|---|---|
| PermissionBroker / policy | typed tool descriptor, broker state, policy | model arguments, page text, voice transcript, package data | normalized permission decision and execution receipt | owner identity fabrication, arbitrary approval, policy changes | malformed scope and stale/fingerprint-mismatched approvals fail closed; voice parser is non-authorizing |
| Planning / Agent Runtime | durable task and plan records, bounded budgets | model messages, tool requests, tool output | task/plan/step lifecycle | permission, completion proof, external success | bounded loops and UNKNOWN outcome handling are covered by deterministic tests |
| Context / memory / knowledge | scoped retrieval policy and authoritative stores | documents, memory proposals, prompt-injected content | scoped context selection or domain facts only in its store | permission, owner identity, trusted policy | classification/workspace checks exist; generated JSON loader remains under-bounded (R2B-M06) |
| ProviderRegistry / Router | configured provider definition and resource policy | provider responses and health text | provider selection and health projection | approval, tool authority, success proof | provider failures degrade; native stream schema is now stricter (R2B-F01) |
| MCP / sandbox | trusted extension configuration and host proxies | server process, schemas, tools, resources, results | adapter lifecycle and bounded IPC | Broker/Vault/Trusted Core access | canonical executable packages require capability-free AppContainer/ACL/Job status; direct MCP process paths remain separately gated (R2B-H01) |
| Packages / certification / activation | certified manifest, source hashes, trusted lifecycle | generated code/UI/diagnostics and package metadata | package lifecycle records | self-certification, self-promotion, policy edits | static and staged gates exist; supported host-proxy effects now use trusted broker attestations, while activation remains disabled until Windows isolation/default composition gates pass |
| Files / artifacts / recovery | owner roots, typed references, hashes | names, paths, backup/snapshot bytes | artifact/recovery metadata and bytes in their stores | Vault secrets, cross-workspace access | artifact/reparse races remain (R2B-M01); authenticated recovery closes R2B-H02 |
| Desktop / browser / presentation | host-owned services, ArtifactRefs, trusted permission object | UI/page text, semantic IDs, package assets | derived display/query state | approval authority or arbitrary path rendering | presentation is typed; browser/physical-screen and host-owned approval gaps remain from R2A |
| Automation / scheduler / setup / doctor | durable definitions and trusted service callbacks | event payloads, setup observations, repair declarations | scheduling/setup/diagnostic orchestration | permission or standing authority | routes to normal PlanningEngine/Broker; adoption and repair callback provenance need stronger binding |

## Findings summary

`FIXED` entries below are included because each was a concrete defect found in
this review and now has regression coverage. `RESIDUAL` entries remain open and
are not hidden by the fixes.

| ID | Severity | Component | Status | Blocks v1.0.0? |
|---|---|---|---|---|
| R2B-H01 | HIGH | MCP/generated process and generic subprocess boundary | RESOLVED for the canonical generated `SandboxProcess` path; direct uncomposed process paths remain blocked | No for the supported generated-package path; yes for uncomposed direct process activation |
| R2B-H02 | HIGH | Recovery/LKG manifest and pointer trust | **FIXED for the current local recovery contract**; authenticated `TrustedRecoveryRecord` and secure generation floor now bind the LKG to trusted lifecycle evidence | Self-update still requires separate update execution/owner gates |
| R2B-H03 | HIGH | Setup adoption identity binding | Carry-forward RESIDUAL | Yes for adoption/factory activation |
| R2B-H04 | HIGH | Shadow/Canary independent effect attestation | **FIXED for the supported broker path; carry-forward only for uncomposed paths** | Generated activation remains disabled pending Windows isolation/default composition |
| R2B-H05 | HIGH | Spoken approval authentication | **FIXED BY V1 DESIGN**: affirmative STT is non-authorizing; trusted desktop handoff is exact and broker-bound | No for v1 voice capture/text; spoken privileged approval is disabled |
| R2B-M01 | MEDIUM | ArtifactStore reparse/TOCTOU boundary | RESIDUAL | Yes for untrusted path-bearing integrations; otherwise hardening required |
| R2B-M02 | MEDIUM | Durable knowledge snapshot bounds and strict decoding | RESIDUAL | No; quarantine/limit before production ingestion |
| R2B-M03 | MEDIUM | Generic command process-tree/cwd ownership | RESIDUAL | Yes for untrusted command execution |
| R2B-F01 | MEDIUM | Ollama stream/schema validation | FIXED | No |
| R2B-F02 | MEDIUM | Vision numeric/schema validation | FIXED | No |
| R2B-F03 | MEDIUM | Generated UI authority imitation detection | FIXED, conservative heuristic remains | UI packages still require host-owned approval review |
| R2B-F04 | MEDIUM | MCP launch identity, environment, redirect, startup cleanup | FIXED narrow boundary | No; does not solve OS sandboxing |
| R2B-F05 | MEDIUM | Winget executable ambiguity and unbounded launch | FIXED narrow boundary | No; provider remains opt-in and must be configured |
| R2B-I01 | INFORMATIONAL | Dangerous primitive scan | No issue found | No |

## Detailed findings

### R2B-H01 — Same-user subprocesses are not an OS security boundary

**Original R2B status: `MITIGATED` and blocking. Superseded R4 status:
`RESOLVED` for the canonical generated `SandboxProcess` path.** The original
Windows path used a restricted primary token, explicit standard-handle
inheritance, suspended launch, pre-resume Job assignment, native lifecycle
limits, fail-closed setup and bounded descendant cleanup. R4 adds the selected
capability-free AppContainer, scoped ACL, and package activation gate. The
independent MCP/terminal/UI subprocess paths are not silently treated as
upgraded; hostile activation through those paths remains disabled.

**Affected code:** `jarvis/mcp/client.py:MCPClient.start` (current lines
36-69), `jarvis/computer/terminal.py:SubprocessCommandAdapter.execute`,
`jarvis/computer/adapters.py:WindowsUiAutomationAdapter._launch_application`,
and the limitation documented in `jarvis/sandbox.py` and
`docs/sandbox-isolation.md`.

**Evidence and impact:** The canonical `SandboxProcess` path now establishes a
restricted Windows primary token and Job Object before resume, but the generic
terminal/MCP paths still use their own direct process launch contracts. Even in
the restricted-token path, a child running as the same Windows user can still
attempt direct filesystem, registry, network, credential, or child-process
operations outside the typed host-proxy contract. A Job Object does not prove
that every deliberate breakaway descendant is prevented or that same-user
resources are inaccessible.

**Control already present:** no shell strings are used in these paths;
executable identity is resolved; the canonical sandbox uses restricted-token
and explicit-handle launch; MCP stdio requires an absolute regular working
directory and a sanitized environment; host proxies enforce typed
network/filesystem/credential scopes; generated activation is disabled in the
normal runtime.

**Required remediation:** before enabling generated code or hostile MCP, use an
OS-enforced AppContainer, dedicated least-privilege account, Windows
Sandbox/VM, or equivalent deny-by-default isolation with process-tree
ownership. The restricted-token `SandboxProcess` mitigation may be retained as
defense in depth, but must not be presented as that stronger boundary. Keep
typed brokers as a second policy layer. Reject activation if the selected
isolation provider is not available. Add owned Windows tests for source/.git/
Vault/recovery denial, undeclared network/private-address denial,
child-process containment, and IPC identity binding.

**Regression test:** owned local synthetic tests now cover restricted-token
status, explicit non-inheritance of a trusted file handle, mandatory-feature
fail-closed behavior, cancellation and descendant cleanup. They do not prove
same-user filesystem/network denial or a stronger OS boundary; those remain
release-blocking tests for the follow-up isolation provider. No external target
is used.

**Release impact:** blocks generated integration and MCP activation.

### R2B-H02 — Recovery payloads and the authenticated recovery authority

**Affected code:** `jarvis/recovery.py:RecoveryStore.create_snapshot`,
`RecoveryStore.load`, `RecoveryStore.restore`, `_verify_snapshot_files`,
`last_known_good`, and `_atomic_json`.

**Evidence:** Before this review, a copied snapshot file was restored without a
content digest. The remediation adds schema version 2, per-file SHA-256
digests, reparse/path checks, and fail-closed verification before load/restore.
The prior remaining issue was that `manifest.json` and the
`last-known-good.json` pointer were ordinary mutable files in the recovery
root. The current remediation replaces the unsigned pointer with an
authenticated `TrustedRecoveryRecord`; the exact manifest bytes, transaction,
build hash, installation, compatibility, status, and generation are now bound
by a secure-backend HMAC and stale generations fail closed.

**Historical security consequence:** code/configuration/data rollback could be
redirected to attacker-controlled recovery material, undermining LKG and
self-update gates. The current supported local recovery path rejects that
condition; self-update remains separately disabled.

**Historical required remediation:** bind the manifest, LKG pointer, transaction
ID, candidate revision, and migration references to an OS-protected owner
boundary or a trusted-core key that is unavailable to ordinary
application/package data. Reconcile migrations before restored code starts and
enter Safe Mode on authentication failure. This is implemented for the current
local recovery contract by `TrustedRecoveryAuthority` and the production
composition path described below.

**Regression test:** mutate payload, manifest hash, manifest revision, LKG
pointer, and migration metadata independently and together; assert restore
refusal, preserved incident evidence, and Safe Mode when no authenticated LKG
remains. The new payload-tamper test is
`tests/test_recovery.py:test_snapshot_file_tampering_is_rejected_before_restore`.

**Remediation status:** **FIXED for the current local recovery contract.**
`TrustedRecoveryAuthority` binds the authenticated LKG record to the manifest,
transaction ID, exact application build hash, installation identity, schema
compatibility, status, authority version, previous record, and monotonic
generation. The HMAC key and generation floor are outside ordinary recovery
files in the secure secret backend. Boot validation refuses missing, modified,
future, stale, unrelated, or unavailable-backend records and the coordinator
enters Safe Mode when no authenticated restore point remains.

**Release impact:** the specific unauthenticated-LKG finding is closed for the
local recovery contract. This does not claim vendor-signed update provenance or
enable self-update; those remain separately controlled update/release gates.

**Evidence:** `docs/security/trusted-recovery-authority.md`,
`tests/test_recovery_authority.py`, and the existing recovery suite.

### R2B-H03 — Adoption does not bind the user decision to an exact inspected executable

**Affected code:** `jarvis/setup_conductor.py:AdoptionCandidate`,
`SetupConductor._decision_for`, and the adoption branch in
`SetupConductor.run`.

**Evidence:** `AdoptionCandidate` contains location, version, compatibility
flags, and free-form evidence, but not an executable hash, signer/file
identity, dependency lock, or reparse identity. `_decision_for` selects the
first compatible candidate; the run branch invokes the component handler's
generic `verify` and records a caller-provided `decision.values["candidate_id"]`
without proving that this ID is the inspected candidate. This is the same
carry-forward issue recorded as R2A-H02.

**Security consequence:** a replaced or malicious existing binary/configuration
can be adopted as a compatible capability, and the audit can name a different
candidate than the one actually used.

**Required remediation:** make candidate identity typed and immutable: canonical
path, file identity, content hash, signer, version/dependency evidence, and
candidate ID must flow through inspection, decision, setup, verification,
certification, and activation. Revalidate immediately before use and reject
unknown or changed candidates.

**Regression test:** inspect two synthetic candidates, select one, substitute
its file or path, and submit an unknown candidate ID. All cases must refuse
adoption without configuration or first-start side effects.

**Release impact:** blocks adoption and CapabilityFactory activation.

### R2B-H04 — Shadow/Canary effect observations are not independently authoritative

**Affected code:** `jarvis/package_activation.py:ActivationHooks`,
`PackageActivationService.run_shadow`, `run_canary`, and `promote`.

**Evidence:** the service receives `ShadowExecution` and `CanaryExecution`
records from composition callbacks and validates the returned fields after the
callback completes. It does not itself enforce zero effects at the effect
boundary, provide an independent broker observer, or persist the lifecycle in
an authoritative store. The package cannot directly call `promote` through the
typed API, but a same-user package outside an OS sandbox can produce effects
that never appear in the callback's reported observations. This carries
forward R2A-H03.

**Security consequence:** Shadow can be falsely side-effect-free and Canary can
be falsely within scope; a fresh version/restart can also lose lifecycle
authority if state is reconstructed from application callbacks.

**Required remediation:** enforce Shadow zero-effect mode in the broker, bind
each effect to package hash/certification/scope/reservation/trace, use a trusted
observer, persist activation state, and require an owner-authenticated,
expiring promotion decision. Missing or contradictory observations must
quarantine.

**Regression test:** synthetic package attempts every available effect path in
Shadow, lies about Canary observations, requests self-promotion, changes its
hash, and restarts between states. All attempts must be denied or quarantined.

**Release impact:** blocks generated package activation.

### R2B-H05 — Spoken affirmative phrases are not speaker authentication

**Affected code:** `jarvis/permissions/presentation.py:parse_spoken_approval`
and `approval_choice_from_spoken`, plus voice composition.

**Evidence:** the parser correctly accepts only exact policy phrases and rejects
conditional/ambiguous text, but an exact phrase such as `yes` is still only a
transcript-derived choice. There is no repository-wide trusted speaker
authentication binding that proves the owner spoke the phrase in response to
the current trusted operation. This carries forward R2A-H06.

**Security consequence:** if a future open-microphone or wake path maps the
transcript directly to the Broker, a nearby speaker or stale/malicious audio
could approve a current operation. Narration and TTS do not establish owner
identity.

**Required remediation:** keep voice choices non-authorizing until an
owner-authenticated, current trusted presentation binds the transcript to the
exact request, task, fingerprint, scope, and expiry. Otherwise require desktop
or another authenticated channel. Preserve microphone-mode independence.

**Regression test:** synthetic transcripts from an unauthenticated source,
stale prompt, barge-in response, and ambiguous/conditional wording must never
produce an approval receipt.

**Release impact:** blocks voice privileged approval.

**R2D/R4 disposition:** **FIXED BY DESIGN for v1.0.0 scope.** The release does
not expose spoken privileged approval. STT remains untrusted, affirmative
phrases are rejected by the secure default channel policy, and `NO`/`DETAILS`
remain safe interactions. Only a trusted authenticated desktop surface may
consume a `DesktopApprovalHandoff` through `PermissionBroker` after rechecking
the exact request and fingerprints. The HIGH risk is therefore blocked by
product scope rather than hidden behind a claim that speech authenticates the
owner.

### R2B-M01 — ArtifactStore path validation still has reparse/TOCTOU limits

**Affected code:** `jarvis/artifacts.py:_safe_root`, `_assert_safe_path`,
`ArtifactStore._write_version`, `read`, and `purge_expired`.

**Evidence:** the store resolves the configured root and rejects a reparse
point at the final root, then validates content paths before open/read/unlink.
It does not reject every reparse ancestor of the root, and a check followed by
`read_bytes()` or `unlink()` is not an atomic handle-based operation. A
directory or file can change between validation and use.

**Security consequence:** an attacker controlling a mutable parent or artifact
directory could redirect reads/deletes, violate workspace isolation, or cause
the store to act on a path outside the intended owner root. The content hash
protects returned bytes from silent corruption but does not make path
resolution race-free.

**Required remediation:** create and validate an owner-controlled root with
reparse ancestors rejected; use Windows handle-relative APIs or equivalent
no-follow semantics for reads/deletes; recheck workspace/reference ownership at
the effect boundary; quarantine on ambiguity.

**Regression test:** local junction/symlink fixtures where supported, plus a
bounded race fixture that swaps a validated path before read/delete. Assert no
outside file is read or removed.

**Release impact:** hardening is required before untrusted/generated packages
receive artifact path access; ordinary in-process artifact use remains covered
by workspace/reference checks.

### R2B-M02 — KnowledgeStore accepts unbounded and loosely typed generated JSON

**Affected code:** `jarvis/knowledge/store.py:KnowledgeStore.load`,
`_mapping`, `_sequence`, and the coercions in `_item_from_dict`,
`_component_from_dict`, and `_tool_from_dict`.

**Evidence:** `load` reads the entire caller-selected file without a byte
limit, calls `json.loads`, coerces fields with `int()`/`str()`, and trusts list
sizes before constructing records. JSON is not executable deserialization, but
an oversized or malformed generated index can consume memory, produce
misleading metadata, or turn malformed values into apparently valid context.

**Security consequence:** resource exhaustion and context-integrity/poisoning
risk. Knowledge remains data, not policy, but downstream context priming could
receive malformed or excessive data.

**Required remediation:** load only from a trusted generated root, impose file,
record, field, and nesting limits before decoding, require exact schema types,
reject future schemas and unknown security-sensitive fields, and quarantine the
index on any validation error. Retain provenance and workspace/classification
checks at retrieval.

**Regression test:** malformed scalar/list types, future schema, oversized file,
oversized record/content, invalid provenance, and prompt-injection text must
either be rejected or retained only as explicitly untrusted data.

**Release impact:** does not block the minimal core if the index is treated as
untrusted and bounded at its caller, but blocks production ingestion of
unreviewed generated indexes until limits are enforced.

### R2B-M03 — Generic command execution lacks complete process-tree and cwd identity binding

**Affected code:** `jarvis/computer/terminal.py:SubprocessCommandAdapter.execute`
and `_terminate`, and `jarvis/computer/tools.py:_authorized_path`.

**Evidence:** the command adapter now resolves the executable and uses the
Broker-normalized working directory, no shell, and a bounded timeout. It kills
the direct process on cancellation/timeout, but does not prove that descendants
are terminated or that the working-directory object is unchanged between
authorization, `resolve`, and process launch. The broker receipt binds the
requested path, not an OS file handle.

**Security consequence:** a permitted command can leave a child running after
timeout or operate against a directory replaced after authorization. This is a
confused-deputy/resource-leak risk for any command whose child inherits useful
authority.

**Required remediation:** use a process-tree owner (Windows Job Object with
kill-on-close or a trusted equivalent), reject reparse ancestors at launch, and
bind the canonical directory/file identity to the effect boundary. Keep the
exact command catalog and Broker scope checks.

**Regression test:** owned parent/child process fixture, timeout/cancel, cwd
replacement, and reparse-directory cases; assert descendants are gone and no
outside marker is written.

**Release impact:** blocks untrusted or generated command execution; catalogued
trusted commands remain narrowly constrained but should not be described as
fully isolated.

### R2B-F01 — Ollama stream/schema validation was too permissive (fixed)

**Affected code:** `jarvis/ai/providers/ollama.py:OllamaProvider.generate`,
`stream`, and `_message_content`.

**Defect:** `bool(body.get("done", False))` treated the string `"false"` as
true, and `str(message["content"])` converted malformed numeric/object output
into assistant text. Response and individual stream-event sizes were also not
bounded.

**Fix:** completion flags now require an exact boolean; message/content shapes
are strict; complete response and stream-line bounds are enforced; provider
errors do not include untrusted response bodies.

**Regression test:** `tests/test_ollama_provider.py` now rejects string
completion flags and non-string content. Existing connection/interrupted/error
tests remain intact.

**Release impact:** fixed in this working tree; no v1 block from this finding.

### R2B-F02 — Vision provider accepted non-finite/coerced model values (fixed)

**Affected code:** `jarvis/vision/models.py:NormalizedBounds`,
`VisibleElement`, `VisionCandidate`, and `jarvis/vision/local.py:_analysis`/
`_elements`.

**Defect:** NaN/Infinity could pass comparison-based bounds checks, and provider
output coerced arbitrary labels/confidence values with `str()`/`float()`.

**Fix:** exact primitive types and finite values are required for bounds,
confidence, labels, and roles before constructing typed records.

**Regression test:** `tests/test_vision.py:test_visual_models_reject_malformed_bounds_geometry_confidence_and_actions`
checks NaN/Infinity and malformed confidence.

**Release impact:** fixed in this working tree.

### R2B-F03 — Generated UI approval-imitation detection was too narrow (fixed conservatively)

**Affected code:** `jarvis/ui_simulation.py:UISimulationHarness._security_check`
and `_looks_like_authority_control`.

**Defect:** simulation rejected only a small exact action/title vocabulary. A
different action ID with semantically authority-claiming text could pass.

**Fix:** the simulation now inspects action ID, title, text, and declared
capability tokens and rejects authority markers conservatively. This protects
the simulation gate; it is not a substitute for a host-owned trusted permission
component. Ambiguous UI-bearing packages should still require manual review.

**Regression test:**
`tests/test_ui_simulation.py:test_semantic_authority_spoof_is_rejected_even_without_known_button_names`.

**Release impact:** the exact defect is fixed; UI-bearing activation still
requires the R2A host-owned approval and simulation evidence gates.

### R2B-F04 — MCP stdio launch identity, environment, redirect, and failed-start cleanup were weak (fixed narrowly)

**Affected code:** `jarvis/mcp/client.py:MCPClient.start` and
`_resolve_working_directory`.

**Defect:** stdio launch previously accepted PATH-resolved executables and an
inherited/minimal caller environment; HTTP client behavior did not explicitly
disable redirects; a failed initialize could leave a child process alive.

**Fix:** stdio requires an exact absolute regular executable and an explicit
absolute non-reparse working directory, uses `trusted_process_environment`,
HTTP redirects are disabled, and initialization failure closes the started
transport. This remains only launch hardening, not OS sandboxing.

**Regression tests:**
`tests/test_mcp.py:test_mcp_stdio_rejects_ambiguous_process_identity_and_cwd` and
`test_mcp_start_failure_closes_started_process`.

**Release impact:** fixed narrow launch defects; R2B-H01 still blocks hostile
MCP activation.

### R2B-F05 — Winget process launch used ambiguous executable identity and no bound timeout (fixed narrowly)

**Affected code:** `jarvis/applications/providers.py:WingetPackageProvider`
and `_run`.

**Defect:** the optional provider launched the literal `winget.exe` through
inherited lookup, inherited the ambient environment, and could wait without a
provider timeout.

**Fix:** installation/update now requires an explicitly configured trusted
executable identity, uses the sanitized process environment, and applies a
bounded timeout with process termination. The provider remains optional; its
read-only `available` check is advisory and does not authorize an install.

**Regression test:** `tests/test_applications.py:test_winget_provider_requires_explicit_trusted_executable`.

**Release impact:** fixed narrow launch defect; no provider is enabled by this
review.

## Negative review results

The following checks found no new production violation in the reviewed tree:

- no production `shell=True`, `os.system`, `pickle`, `cPickle`, `marshal`,
  `dill`, or unsafe YAML loader was found by the repository scan;
- command/application execution uses argument-vector APIs rather than shell
  command strings in the inspected production paths;
- MCP result/request JSON, package paths, UI package assets, backup envelopes,
  and vision records have existing bounds or typed validation; the defects
  listed above were the remaining concrete gaps selected for remediation;
- backup export uses AES-GCM through the reviewed crypto library, refuses raw
  credential components, requires reauthorization/recertification where
  applicable, and performs technical snapshot/rollback callbacks for
  destructive restore;
- ArtifactStore rejects `CREDENTIAL_SECRET` classification, stores content by
  opaque generated references, checks content hashes, and binds references to
  workspace IDs;
- model/provider errors inspected here do not copy raw provider response bodies
  into errors; untrusted page/document/MCP text remains data and is not a
  policy input;
- tests do not disable Shadow/Canary, approvals, drift, golden-workflow, or
  trusted-core gates to make production behavior pass;
- no donor project is imported as a required runtime dependency and no
  service-specific core adapter was added.

These are negative review results, not proof against future regressions. Keep
the static scans and adversarial synthetic tests in CI.

## Remediation and test evidence

Changed production boundaries in this review:

- `jarvis/recovery.py` — snapshot schema 2, file digests, integrity checks,
  reparse/path checks, and fail-closed legacy file snapshots;
- `jarvis/mcp/client.py` — exact stdio identity, sanitized environment,
  explicit cwd/redirect policy, and startup-failure cleanup;
- `jarvis/applications/providers.py` — trusted Winget identity and bounded
  process execution;
- `jarvis/ai/providers/ollama.py` — strict bounded provider stream/schema;
- `jarvis/vision/models.py` and `jarvis/vision/local.py` — strict finite
  model-output values;
- `jarvis/ui_simulation.py` — conservative authority-imitation detection.

Regression tests were added or updated in the corresponding subsystem test
files. The focused remediation run passed 82 tests before the Ollama/MCP
follow-up; the follow-up provider/MCP/application tests passed 13 and 36 tests
respectively.

Required full gates for this review:

```text
python scripts/quality.py
python scripts/run_system_tests.py --suite deterministic-workflows
```

The final result of those commands is recorded in the handoff response. The
deterministic system suite is local and synthetic; hardware/manual Windows
isolation tests remain unexecuted unless explicitly listed by the test runner.

## Required next security work

1. Provide an OS-enforced sandbox and process-tree owner before enabling any
   generated/MCP runtime.
2. Bind adoption to exact executable identity and persist independent
   certification/activation evidence.
3. Make Shadow/Canary effect enforcement and observations trusted and durable.
4. Authenticate recovery manifests/LKG pointers outside mutable application
   data.
5. Add strict bounded knowledge snapshot loading and artifact handle-relative
   path operations.
6. Establish authenticated voice approval or keep voice permanently
   non-authorizing for privileged actions.
7. Finish the carry-forward R2A browser, presentation physical-observation,
   repair/provenance, and static-review limitations before enabling those
   surfaces.

No commit, push, merge, tag, release, or external coordination was performed.

## Browser Broker status update

The previous canonical browser-path gap is **FIXED for the supported configured
runtime path**. `BrowserBrokerAdapter` exposes strict per-action registered
tools and the trusted backend is reached only after the canonical
`PermissionBroker` path. Unsupported/missing browser backends and missing
trusted vault state fail closed. Deterministic browser and runtime regression
tests cover denial before effects, stale/origin binding, password redaction,
opaque credential references, and composition. This review does not claim OS
isolation for the browser process or authorize an uncontrolled fallback.

## Effect-attestation remediation update

R2B-H04 is **FIXED** for the callback/effect-evidence defect. Supported host
proxy operations now produce trusted, activation-bound broker observations;
Shadow suppression is recorded before dispatch, unfinished attempts reconcile
to `UNKNOWN_OUTCOME`, and promotion requires trusted CANARY evidence plus an
independent non-model `VerificationResult`. Fake and mismatched attestations
are rejected by regression tests. The Windows same-user isolation finding is
`RESOLVED` for the canonical generated-package path; direct uncomposed process
paths remain blocked and are not hidden by this change.

## R4 Windows isolation resolution

R2B-H01 is **`RESOLVED` for the canonical generated executable
`IntegrationPackage` path**. `WindowsAppContainerLauncher` now creates a
capability-free AppContainer, applies package/runtime ACL leases, passes only
explicit stdio handles, assigns a Job Object before resume, and reports the
observed posture through `SandboxSecurityStatus`. The package certifier and
activation service reject executable packages when that status is absent or
weaker than the required contract. The durable activation record retains the
selected isolation mode.

Repository-owned Windows tests provide concrete local evidence for outside
synthetic filesystem read/write denial, capability-free local loopback denial,
owned data writes, handle non-inheritance, Job/process limits, malformed
configuration, unavailable AppContainer setup, certification refusal, and
activation refusal. See
`docs/security/windows-integration-isolation.md` and
`tests/test_sandbox.py`.

This resolution is scoped. Existing restricted-token and Job-only modes remain
diagnostic and do not satisfy executable package activation. Direct MCP,
terminal, UI, or other process launch paths that are not composed through this
boundary remain independently gated and are not upgraded by documentation or
by importing the launcher. R2B-H01 therefore no longer blocks the supported
canonical generated-package path, while the overall release gate remains
subject to the unrelated findings recorded in this report.
