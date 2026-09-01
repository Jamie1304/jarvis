# R2A pre-v1 trust-boundary security review

**Repository:** `Jamie1304/jarvis`
**Review revision:** `d3933473f00b0c52eebf64ec56ef1dad6906ed07`
**Review date:** 2026-08-24
**Review type:** authorized defensive Secure-SDLC review of repository code, tests,
configuration, and local fixtures only

## Executive decision

**NO-GO for v1.0.0 with self-expansion, MCP, generated UI, adoption, voice
approval, or self-update enabled.**

The normal default composition is intentionally conservative: privileged approval
uses a deny-all verifier, generated activation is recorded as disabled, the MCP
registry is sealed before any manager can start, browser access defaults to deny,
and the local voice path is not a privileged approval surface. Under that exact
default entry point, the high-risk expansion paths are blocked rather than
proven safe.

That is an effective current mitigation, not a v1 security certification. Once
the disabled paths are enabled, this review finds reachable HIGH conditions in
the sandbox/MCP boundary, adoption identity binding, staged activation, UI
approval imitation, recovery integrity, and spoken approval authentication.
Those conditions violate the release requirement of zero reachable CRITICAL and
zero reachable HIGH without an effective blocking mitigation. No CRITICAL
finding was identified in the reviewed revision.

No production code was changed by this review. No external service, account,
device, network, or third-party system was targeted.

## Method and trust model

The review used:

- source and architecture inspection of the composition root, security modules,
  stores, adapters, and lifecycle services;
- existing security, trusted-core, deterministic, and subsystem tests;
- bounded local negative checks using synthetic package/UI, adoption, recovery,
  and sandbox fixtures; no reusable exploitation payload is included here;
- static searches for donor runtime dependencies, service-specific core logic,
  shell bypasses, permission bypass switches, and test-only exemptions;
- reachability analysis that distinguishes a default-disabled feature from a
  production-wired security boundary.

The security constitution is treated as the source of authority. Model output,
page text, event payloads, MCP metadata, package source, generated UI, provider
responses, discovered environment data, memory/knowledge content, and voice
transcripts are untrusted data. They may propose work or produce evidence, but
they cannot mint identity, approval, policy, completion, or authority.

The required production flow remains:

`application -> PlanningEngine -> ToolRegistry -> Tool -> PermissionBroker ->
Policy/approval -> effect -> evidence/verification`.

Derived projections, traces, events, automation records, memories, knowledge
chunks, artifacts, and backup bundles do not replace the authoritative owner of
their domain.

## Findings summary

| ID | Severity | Component | Reachability in current default | v1 impact |
|---|---|---|---|---|
| R2A-H01 | HIGH | Integration Sandbox, MCP stdio, host proxies, generated packages | Blocked by absent generated activation; MCP manager cannot start after registry sealing | **Blocks** any hostile/generated/MCP activation |
| R2A-H02 | HIGH | SetupConductor and CapabilityFactory adoption | Setup/Factory are not default-composed | **Blocks** adoption of existing binaries or runtimes |
| R2A-H03 | HIGH | Shadow/Canary activation and drift | Activation is not default-composed; trusted effect evidence is now enforced on the supported path | **Blocks** staged generated-package activation only where the separate Windows isolation/default-composition gate is not met |
| R2A-H04 | HIGH | UI Simulation Harness and dynamic UI | UI-bearing generated activation is not default-composed | **Blocks** UI-bearing generated packages |
| R2A-H05 | HIGH | RecoveryStore/LKG | **RESOLVED for the current local recovery contract**: `TrustedRecoveryAuthority` authenticates the exact record, manifest, build hash, transaction, installation, compatibility, and generation through the secure backend; unsupported/missing trust fails closed | Does not by itself authorize self-update or claim vendor-signed release provenance |
| R2A-H06 | HIGH | Voice permission interaction | **RESOLVED BY V1 SCOPE**: privileged/high-risk spoken approval is disabled by design; exact desktop handoff is trusted-code and fingerprint bound | **No longer blocks v1 voice capture/text interaction; privileged spoken approval remains unavailable** |
| R2A-H07 | HIGH | Browser Semantic Bridge authorization adapter | **FIXED for the supported configured runtime path** by `BrowserBrokerAdapter`; unconfigured browser remains unavailable/default-deny | No longer blocks the supported browser path; residual backend/host limitations remain |
| R2A-M01 | MEDIUM | Static package review | Reachable as a static gate | Static review cannot be the only hostile-code boundary |
| R2A-M02 | MEDIUM | Provider stream validation | Native local provider is reachable | Malformed streams can cause premature/incorrect conversational state |
| R2A-M03 | MEDIUM | AgentSession/workspace binding | Workspace profiles are not default-composed | Cross-workspace reuse risk when multi-workspace sessions are enabled |
| R2A-M04 | MEDIUM | Context priming and ProcedureBank | APIs are available; automatic learning is not a production authority | Caller-supplied trust flags can poison a miswired learning path |
| R2A-M05 | MEDIUM | EventBus and Event Automation | EventBus/automation are composed and bounded | Spoofed facts can cause bounded task/notification DoS, not approval |
| R2A-M06 | MEDIUM | Backup component boundary and artifact classification | Backup/ArtifactStore are composed | Misregistered trusted providers can misclassify secret-bearing payloads |
| R2A-M07 | MEDIUM | PresentationSurface query evidence | Surface is available as a typed service | Without an observer it reports requested state, not physical screen state |
| R2A-M08 | MEDIUM | Attention and proactive preparation | Dedicated priority queue/OpportunityEngine is missing | Expiring authority notices can be lost; feature remains incomplete |
| R2A-M09 | MEDIUM | Certification, drift, repair, and golden actor provenance | Services rely on composition-owned callbacks/records | Caller-forged trusted-looking records are unsafe if exposed across a trust boundary |
| R2A-L01 | LOW | Local provider error/detail and defensive classification heuristics | Reachable | Availability and detection-quality limitations; no direct authority grant |
| R2A-I01 | INFORMATIONAL | Donor/runtime dependency and product-specific core scan | Verified clean | No donor framework is a runtime dependency; retain this gate in CI |

## Detailed findings

### R2A-H01 — The current Windows sandbox is not an OS security sandbox

**R4 status update: `MITIGATED` for the canonical `SandboxProcess` lifecycle
and privilege-reduction path, but still `BLOCKING` for hostile generated/MCP
activation.** The Windows launcher now uses a restricted primary token,
explicit standard handles, suspended pre-resume Job assignment, fail-closed
mandatory setup and bounded descendant cleanup. It still does not guarantee
same-user filesystem/network/code-integrity isolation; see
`docs/security/windows-integration-isolation.md`.

**Affected component:** `jarvis/sandbox.py`, `docs/sandbox-isolation.md`,
`jarvis/sandbox_proxies.py`, `jarvis/mcp/client.py`, generated integration
activation.

**Concrete evidence:** `jarvis/sandbox.py:1-8` documents that the child has
bounded JSON IPC and a Windows Job Object, but explicitly states that Job
Objects are not a filesystem, network, or identity sandbox. The limitation is
repeated in `docs/sandbox-isolation.md:59-76`: the child retains the same
Windows identity, filesystem ACLs, network access, registry access, and ability
to attempt OS operations available to that user. `MCPClient` uses
`create_subprocess_exec` with a reduced environment (`jarvis/mcp/client.py:25-48`)
but does not place a stdio server in the JARVIS sandbox or deny its ambient OS
access.

A bounded local fixture confirmed the documented property: a sandbox child
could read a known repository file by absolute path even though that path was
not passed in the environment or working directory. This was a read-only local
fixture check; no source or repository file was modified.

**Security consequence:** Generated or malicious MCP code can bypass host
proxies by using direct filesystem, network, process, registry, or credential
access available to the same Windows user. It can read source, `.git`, JARVIS
databases, audit/recovery data, and potentially discover or use Windows-backed
credential targets. It can also create children outside the intended typed
proxy protocol. The result is a confused-deputy and secret-integrity boundary
failure. Shadow side-effect guarantees and drift baselines are also bypassable
when effects do not pass through a trusted broker.

**Recommended fix:** Before enabling hostile/generated or MCP code, launch it
under an OS-enforced restricted token/AppContainer, Windows Sandbox/VM, or an
equivalent deny-by-default policy. Bind access to the staged package and its
dedicated data root only; deny source, `.git`, JARVIS state, recovery, audit,
Vault metadata, and undeclared network/private-address access. Put stdio MCP
servers behind the same boundary or reject them. Keep typed host proxies as a
second policy layer, not as the only containment layer. Add owned Windows tests
that assert source/config/Vault/network/process-tree denial, not merely reduced
environment variables.

**Regression test:** An owned malicious child attempts repository reads,
recovery/audit reads, a private/network request, an undeclared child process,
and IPC identity substitution. Each must be denied or the package must remain
inactive; the test must run only in an explicitly provisioned Windows isolation
environment.

**Blocks v1.0.0:** **Yes** for generated integration or MCP activation. The
current disabled composition is an effective block, not an effective mitigation
for an enabled feature.

### R2A-H02 — Adoption is not bound to an exact existing executable identity

**Affected component:** `SetupConductor`, `CapabilityFactory`, setup handlers.

**Concrete evidence:** `SetupAdoptionCandidate` in
`jarvis/setup_conductor.py:175-199` records location, version, compatibility
booleans, and free-form evidence, but no executable hash, signer identity,
file identity, reparse-point identity, dependency lock, or base revision.
`SetupConductor._decision_for` (`jarvis/setup_conductor.py:652-662`) only checks
that *some* candidate is compatible. The adoption branch
(`jarvis/setup_conductor.py:574-586`) calls the handler's generic `verify`
without binding it to the selected candidate and records a caller-supplied
`decision.values["candidate_id"]`. `CapabilityFactory` chooses a candidate at
`jarvis/capability_factory.py:532-548`, but `_run_setup` passes only the setup
step and a context (`jarvis/capability_factory.py:491-504`), dropping the
selected candidate identity from the setup contract.

A bounded synthetic fixture supplied an unlisted candidate ID in a
`USE_IN_PLACE` decision while a compatible candidate existed. The run completed
and recorded the unlisted ID as adopted. This was an in-memory local check; no
binary was installed or launched.

**Security consequence:** A malicious or replaced local binary/configuration
can be adopted based on a boolean compatibility result. The audit can name a
different candidate from the one actually inspected, and a time-of-check/time-
of-use replacement is not prevented. Hidden dependencies, incompatible
versions, reparse paths, and binary substitution can enter the production
capability path without exact identity proof.

**Recommended fix:** Make the candidate identity a typed, immutable setup
input. Bind candidate ID, canonical path, file identity, content hash, signer
and version/dependency evidence into the decision, setup run, verification, and
activation record. Revalidate the exact identity immediately before every use
and after configuration. Reject a decision whose candidate ID is absent,
incompatible, or not the inspected candidate. Use a trusted brokered typed
setup handler; do not let arbitrary `configure` or `first_start` callbacks
perform unreviewed mutation.

**Regression test:** Two synthetic candidates with different hashes and paths;
select one, mutate/substitute it between inspection and verification, and pass
an unknown candidate ID. All cases must refuse adoption and must not run
configuration or first-start effects.

**Blocks v1.0.0:** **Yes** for SetupConductor/CapabilityFactory adoption.

### R2A-H03 — Staged activation relies on trusted hook contracts without independent effect attestation

**Affected component:** `PackageActivationService`, `ActivationHooks`,
`HotLoadManager`, Shadow/Canary and drift integration.

**Concrete evidence:** `ActivationHooks` are composition callbacks documented at
`jarvis/package_activation.py:149-161`. The service calls the Shadow hook and
then trusts the returned `ShadowExecution` observations before checking the
reported `side_effects` (`:308-334`). It calls the Canary hook and checks the
reported scope, call count, effect count, budget, wall time, and verification
only after the hook returns (`:336-378`). Promotion has no explicit trusted
identity, approval reference, or owner-authentication input (`:380-399`), and
activation sessions are held in an in-memory dictionary. `Runtime` does not
compose this service for generated activation and records
`generated_package_state={"activation": "disabled"}` at
`jarvis/runtime.py:1146-1167`.

The callback contract is intended for trusted composition code, so this is not
described as a package directly calling `promote`. The problem is that the
repository does not provide an independently enforcing production runner that
can make those observations authoritative. If a future runner executes
untrusted code in the current same-user sandbox, the sandbox can perform effects
outside the callback's broker observations.

**Security consequence:** A package can appear to pass Shadow while causing
side effects through ambient OS access, or appear within Canary limits while
the observation is incomplete. A fresh version can inherit an unsafe lifecycle
if state/promotion is reconstructed incorrectly after restart. Drift detection
also sees only broker-observed behavior and cannot see ambient effects.

**Recommended fix:** Make Shadow an enforced zero-effect execution mode and
Canary an effect-time broker budget, not a post-run report. Bind every effect to
the package hash, certification, exact scope, resource reservation, trace, and
trusted observer. Require an owner-authenticated, expiring promotion decision;
persist the lifecycle and revalidate certification after restart/hot reload.
Quarantine on missing or contradictory observations. The OS isolation fix in
R2A-H01 is a prerequisite, not a substitute for these checks.

**Regression test:** A synthetic runner attempts a side effect through every
available path during Shadow, lies about its observed calls during Canary, tries
promotion from the package context, restarts between stages, and changes the
package hash. All attempts must be blocked or quarantined with durable evidence.

**Blocks v1.0.0:** **Yes** for generated package activation.

### R2A-H04 — UI simulation approval-spoof detection is too narrow

**Affected component:** `UISimulationHarness`, generated UI certification,
trusted approval presentation.

**Concrete evidence:** The simulator defines a small exact action vocabulary at
`jarvis/ui_simulation.py:88-98` and rejects only controls where both the action
ID and title exactly match one of the small allow/approve sets
(`jarvis/ui_simulation.py:582-599`). A control with a different action ID and a
semantically equivalent security title is not recognized as an approval-like
control. A bounded synthetic manifest using an action named `continue` and a
title describing authorization passed the simulator's security evidence.

**Security consequence:** A malicious generated UI can imitate trusted approval
language while avoiding the exact string conjunction. The fake endpoint still
cannot mint a `PermissionBroker` approval, but the simulation can certify a
phishing surface that persuades a user to act on a later real prompt or to
mistake an integration action for trusted authority.

**Recommended fix:** Do not attempt to recognize a closed list of approval
button IDs. Declarative generated UI should be prohibited from presenting any
authority/approval affordance or authority-claiming language unless it uses a
trusted, application-owned permission component bound to the exact
`PermissionRequest`. Add semantic checks for role, accessible name, text,
bindings, and authority claims, with conservative manual review on ambiguity.
Render package identity and trusted approval chrome in an unspoofable host-owned
surface. Bind simulation evidence to the exact manifest/package hash and
certification record.

**Regression test:** Use randomized action IDs, accessible names, labels,
localized equivalents, nested containers, and approval-like explanatory text.
Every authority imitation must fail security evidence; only the host-owned
trusted permission component may render the authority control.

**Blocks v1.0.0:** **Yes** for UI-bearing generated packages.

### R2A-H05 — Recovery file contents have no authenticated integrity binding

**Affected component:** `RecoveryStore`, LKG restore, self-update/recovery.

**Concrete evidence:** `RecoveryManifest` records file names but no file hashes
(`jarvis/recovery.py:48-60`). `create_snapshot` copies files and writes the
manifest (`jarvis/recovery.py:174-222`); `restore` validates containment and
copies the selected file but does not verify its content against a recorded
hash (`jarvis/recovery.py:245-282`). The runtime currently creates a metadata
snapshot without file inputs (`jarvis/runtime.py:1146-1167`), so the normal
startup snapshot does not itself provide a restorable code/data baseline.

A bounded temporary recovery fixture changed a copied snapshot file and the
restore operation accepted the changed bytes. No repository or persistent user
data was modified.

**Security consequence:** A same-user process able to modify recovery storage
can turn a nominal LKG into attacker-controlled code/configuration/data or
silently corrupt restored state. A malicious candidate can also be restored as
known-good if the recovery metadata is not authenticated. The current empty
file set means this is partly a missing recovery guarantee today; it becomes a
direct update/recovery vulnerability when files are included.

**Recommended fix:** Record and verify a content hash, size, file identity, and
schema for every snapshot file. Authenticate the manifest and LKG pointer with
a key outside mutable application data, or store recovery in an OS-protected
owner boundary. Refuse mismatches and enter Safe Mode. Make production startup
snapshot the actual authoritative durable domains or explicitly report that
only metadata was captured. Test migration reconciliation before any restored
code can start.

**Regression test:** Tamper with a snapshot payload, manifest, LKG pointer,
transaction ID, migration reference, and candidate revision. Restore must fail
closed, preserve incident evidence, avoid a restart loop, and enter Safe Mode
when no authenticated LKG remains.

**Original status:** **Blocks v1.0.0** for self-update, code rollback, or claims of
complete crash recovery.

**2026-08-24 remediation update:** `RecoveryStore` now requires a current
application build hash when creating a snapshot and stores an authenticated
`TrustedRecoveryRecord` rather than an unsigned LKG pointer. The record binds
installation identity, revision/build hash, transaction, snapshot and exact
manifest hash, schema compatibility, status, authority identity/version, prior
record, and a monotonic generation. HMAC-SHA-256 follows the existing project
authentication pattern; the key and generation floor are held in the secure
backend. `tests/test_recovery_authority.py` covers field mutation, key/backend
loss, stale/unrelated records, candidate self-promotion, failed health,
successful promotion, restart, and future-schema Safe Mode. The finding is
`FIXED` for authenticated local recovery; complete self-update execution,
platform owner identity, and vendor release signing remain separate gates.

### R2A-H06 — Exact spoken phrases are not user authentication

**Affected component:** voice permission interaction, `TrustedApprovalAuthenticator`,
voice runtime.

**Concrete evidence:** `parse_spoken_approval` maps exact phrases such as `yes`,
`allow once`, and `go ahead` to an approval choice in
`jarvis/permissions/presentation.py:63-90`. The parser correctly rejects
conditional/ambiguous text, but the review found no production call site that
binds the voice transcript to an authenticated owner identity and a current
trusted presentation. The trusted narrator/renderer are application-owned,
while voice activation and provider output are optional and independently
configured.

**Security consequence:** If a microphone is open, a wake path is spoofed, or a
malicious TTS/provider output socially manipulates a user, a nearby or
non-owner speaker saying an exact affirmative phrase could be treated as a
trusted approval if a future adapter maps it directly to the broker. Barge-in
and stale response protections prevent stale text from becoming a broker token,
but they do not authenticate the speaker.

**Recommended fix:** Keep spoken parsing non-authorizing. Require a separate
trusted user-presence/authentication binding for voice approvals, or require a
trusted desktop confirmation for privileged/high-risk operations. Bind the
approval to the current `PermissionRequest`, exact operation fingerprint,
identity, expiry, and one-time consumption. Do not let microphone mode, wake
acceptance, TTS text, or provider output change authority.

**Regression test:** Synthetic transcripts from an unauthenticated source,
nearby-speaker source, stale conversation, barge-in generation, and malicious
TTS text must not produce a trusted approval context. Exact affirmative speech
must still fail without the trusted identity binding; ambiguous speech must
remain unapproved.

**Blocks v1.0.0:** **Yes** for voice approval of privileged effects. Voice
capture and text-only voice interaction may remain degraded/available.

**R2D/R4 disposition:** **FIXED BY DESIGN for v1.0.0 scope.** The product
decision is not to authenticate speech. `ApprovalChannelPolicy` rejects
affirmative voice approval for `PRIVILEGED_APPROVAL` and `HIGH_RISK_APPROVAL`;
`DesktopApprovalHandoff` binds the same pending request, normalized scope,
expiry, and exact fingerprints before the trusted desktop surface calls the
normal `PermissionBroker`. No voice path creates an approval context. This
finding remains a permanent restriction on spoken privileged approval rather
than an invitation to add voice biometrics.

### R2A-H07 — Browser authorization is an injectable protocol boundary — remediated by the canonical Broker adapter

**Affected component:** `BrowserSemanticBridge` and browser permission gate.

**Concrete evidence and disposition:** The original application-supplied gate
gap is closed for the supported composition by `BrowserBrokerAdapter`
(`jarvis/browser_broker.py`). It registers one strict typed tool per browser
action in `ToolRegistry`; the canonical `PermissionBroker -> Policy ->
approval` path runs before the trusted backend. Requests bind tab, document
generation, origin, semantic reference, bounded arguments, and task/correlation
context. The bridge remains deny-by-default when not composed.

Permission denial prevents backend dispatch. Stale-reference, origin,
cross-origin, password-redaction, and missing-vault tests remain fail-closed.
The trusted backend is application-owned but is not claimed to be an OS browser
process isolation boundary.

**Fix implemented:** Browser operations are registered typed tools whose broker
action descriptors include tab, document generation, origin, target reference,
and bounded arguments. Runtime composition accepts only an explicitly
supported backend and otherwise reports `UNAVAILABLE`; credential filling
requires an opaque trusted Vault reference. Uncomposed bridges remain
deny-by-default.

**Regression test:** `tests/test_browser.py` covers broker dispatch, denial
before backend effects, stale/origin binding, password and page-data handling,
missing-vault rejection, unsupported backend rejection, typed action bounds,
health failure, and runtime composition. Existing bridge tests cover
cross-origin frames, page approval text, password fields, and tab close.

**Blocks v1.0.0:** **No for the supported configured browser path.** Missing or
unsupported backends remain unavailable and no uncontrolled fallback is
selected. See `docs/security/browser-broker.md` for residual limits.

## Medium and lower findings

### R2A-M01 — Static review is a useful gate, not a code-safety proof

`GeneratedPackageReviewer._scan_source` uses regular expressions for dynamic
execution, imports, deserialization, subprocesses, paths, logging, network, and
authority bypass (`jarvis/package_reviewer.py:707-784`). This correctly rejects
known patterns and never imports or executes the package, but aliases, encoding,
reflection, native binaries, delayed behavior, and dependency behavior can evade
pattern matching. The reviewer itself documents that later certification,
Sandbox, PermissionBroker, Shadow, and Canary gates remain necessary.

**Fix/test:** Keep review fail-closed and require manual review for opaque
binaries, external runtimes, migrations, elevated permissions, and missing source
snapshots. Add parser/AST and dependency provenance analysis where practical,
but retain OS isolation and staged broker enforcement as the security boundary.
Do not change a static PASS into activation authority. **Blocks v1:** only if
used as the sole hostile-code boundary; with the H01/H03 gates, it is a required
restricted gate rather than an independent release blocker.

### R2A-M02 — Provider stream schema validation is looser than the trust model

`OllamaProvider.stream` converts `done` with `bool(body.get("done", False))` and
converts message content to text (`jarvis/ai/providers/ollama.py:59-88`), while
`GenerationChunk` has no validating `__post_init__`. A malformed local response
can therefore look complete or turn non-string content into display text.

**Consequence:** Premature completion, stale session synchronization, malformed
voice/TTS content, and denial of service. It cannot directly create broker
authority because model output remains untrusted. **Fix/test:** require exact
boolean/string/object schema, bounded content, terminal-event rules, and reject
extra/security-sensitive fields; add malformed-stream regression fixtures.
**Blocks v1:** No for privileged authority, but required before claiming robust
provider behavior.

### R2A-M03 — Agent sessions do not carry an enforced workspace identity

`AgentSession` stores type, provider/model, timestamps, usage, parent, archive,
and synchronization state, but no workspace/profile/security-scope field
(`jarvis/ai/sessions.py:26-42`). Conversation metadata currently contains only a
conversation ID (`jarvis/conversation/service.py:59-60`). This is safe for the
current single-scope composition, which does not expose workspace-aware
conversation reuse, but it is insufficient for future cross-workspace session
reuse.

**Fix/test:** Bind session creation and every child/rebuild/model-change action
to immutable workspace, profile, classification ceiling, and security context;
reject mismatches and test restart/voice reuse across two synthetic workspaces.
**Blocks v1:** Yes for multi-workspace session reuse; no for the current single
scope.

### R2A-M04 — Context priming and procedure learning rely on caller-supplied trust metadata

`ProcedureObservation` includes a caller-supplied `trusted_source` boolean and
`ProcedureBank` accepts verified/effect-confirmed observations when that flag is
true (`jarvis/workflows.py:295-355`). Skill context retrieval is supplied through
a callback and returned items carry caller-supplied workspace/classification
metadata. These APIs correctly prevent a candidate from directly becoming
authority and require repeated verification, but a miswired model/integration
caller could label poisoned data as trusted.

**Fix/test:** Accept observations only from a composition-owned verification
adapter that derives trust from Planning/Verification records; remove trust
booleans from untrusted input. Bind priming to authoritative stores and enforce
workspace/classification at the store boundary. Add poisoned-method and forged
provenance fixtures. **Blocks v1:** Yes for autonomous procedure activation;
no for the current suggestion-only bank.

### R2A-M05 — Event facts are bounded, but source authenticity and automation storms remain a risk

`EventEnvelope.source` is typed/bounded but producer authenticity is not
cryptographically established. `InMemoryEventBus` bounds queues and correlation
chains (`jarvis/events/bus.py:70-98`), while `AutomationService` publishes
automation state events with the same correlation (`jarvis/automations.py:959-967`).
The feedback guard blocks a chain after a configured limit, but correlation state
is bounded/evicted and external adapters can still submit many fresh facts.

**Consequence:** A spoofed observation can trigger a fixed automation, causing
bounded task/notification/resource pressure. It cannot carry an approval because
automations submit ordinary tasks and the broker still owns effects. **Fix/test:**
authenticate internal event producers at composition boundaries, distinguish
observation source from claimed source, persist storm/dedup policy, and test
fresh-correlation storms, restart, and critical-event preservation. **Blocks v1:**
No if bounded task creation and broker authorization remain mandatory.

### R2A-M06 — Secret exclusion is classification/registration dependent in artifacts and backups

`ArtifactStore` rejects the explicit `CREDENTIAL_SECRET` classification
(`jarvis/artifacts.py:451`), and `BackupComponent` rejects obvious credential
component IDs and secret classifications (`jarvis/backup.py:118-154`). Backup
restore requires reauthorization/recertification metadata for credential-bearing
or generated components (`jarvis/backup.py:440-505`). However, an incorrectly
registered trusted component source can provide secret bytes under a benign ID
or classification; the opaque payload contract cannot independently inspect all
secret formats.

**Fix/test:** Make Vault the only provider allowed to expose secret references,
require authenticated domain ownership for backup component registration, reject
raw secret bytes at the Vault-to-artifact/backup boundary, and add cross-domain
registration/restore tests. **Blocks v1:** Yes for untrusted component
registration; no for current trusted composition with no Vault exporter.

### R2A-M07 — `PresentationSurface.query_state()` is only physically authoritative when an observer is supplied

`PresentationSurface.query_state()` returns an injected observer result when one
exists, but otherwise returns the last requested in-memory entries. The class
description says “observed actual state,” yet the no-observer path is a projection
of requested state. This can produce false verification if a renderer fails or a
different surface is shown.

**Fix/test:** Require a trusted renderer/observer pair for claims of physical
verification; label the fallback as `REQUESTED_STATE`; compare stable IDs,
content hashes, and renderer evidence. Add renderer-failure, stale-observer, and
unexpected-overlay tests. **Blocks v1:** No for non-authoritative presentation;
yes if used as independent screen evidence.

### R2A-M08 — Priority-aware AttentionPolicy and OpportunityEngine are absent

The repository has bounded transient `AttentionNotice` records
(`jarvis/capability_health.py:435-455`) but no durable priority-aware attention
queue that guarantees an urgent expiring authority request survives bundling,
restart, or low-priority work. The missing OpportunityEngine also means
autonomous preparation is not a reachable production chain.

**Consequence:** loss of a notice is a safety/availability failure, not an
approval grant. **Fix/test:** implement only through the existing authority
owner when this feature is authorized: durable priority/expiry/ack state,
critical-event non-suppression, restart reconciliation, and no approval carried
by a notice. **Blocks v1:** Yes for proactive authority delivery; no for the
current non-proactive runtime.

### R2A-M09 — Several trust records are structurally typed but not authenticated across process boundaries

Certification records, behavior observations, repair authorizations, backup
providers, and Golden Workflow actor enums are protected by trusted composition
contracts, but many are plain dataclasses/callback results. `ComponentDoctor`
fails closed when its authorizer is absent or raises (`jarvis/component_doctor.py:741-754`),
which is good; the remaining risk is accidental exposure of these constructors
to untrusted integration code. The same concern applies to drift observations
marked as broker-trusted and golden actors marked as user/system.

**Fix/test:** keep constructors internal to owner services, use authenticated
typed service interfaces, bind records to package/task/revision hashes, and add
cross-process forgery tests. **Blocks v1:** No while generated code remains
out-of-process and the OS boundary in R2A-H01 is enforced; yes if these records
are accepted from generated code or arbitrary IPC.

### R2A-L01 — Defensive heuristics and provider error projection have known limits

Secret/prompt-injection detection is conservative pattern matching, and provider
errors intentionally discard response bodies. These are appropriate defense in
depth but cannot prove absence of secrets or malicious semantics. Continue to
treat external content as data, use classification and store ownership, and
avoid asserting that heuristic scans are complete. Add regression examples as
new formats are found. **Blocks v1:** No direct authority finding.

### R2A-I01 — Donor and product-specific dependency review is clean

Static searches found no Goose, Agent Zero, fullstack-agent, Backtalk,
ai-visualizer, ai-memory-vault, or barehands package/import/server/Docker runtime
dependency in `pyproject.toml`, lockfiles, or `jarvis/`. The provenance map says
there are no approved `PORT` entries. No Spotify/Hue/Home Assistant/Discord,
printer/NAS/car-specific core branch, product-specific browser handler, or
vendor-mandatory voice provider was found. Keep this check in CI and require
provenance before any future source reuse.

## Trust-boundary matrix

The following matrix records the ten requested boundary questions for every
reviewed subsystem. “Owner” means the sole authority for that domain; a
projection or callback is not an owner. “FF” means fail closed.

### Core execution and authority

#### Trusted Core

- **Trusted inputs:** compiled security manifest, composition-root dependencies,
  owner-authenticated release records.
- **Untrusted inputs:** model output, generated code, package metadata, external
  content, UI/voice text, events, provider data.
- **Owns:** root policy, integrity classification, mutation/recovery gates,
  construction of trusted services.
- **Must never own:** user goals, memory facts, knowledge content, artifacts, or
  integration business logic.
- **Persistent data:** only protected policy/release metadata where needed;
  ordinary data remains with its domain store.
- **Boundary:** composition root creates it; application services call typed
  policy interfaces; generated code never imports it.
- **Failure behavior:** malformed security metadata and unknown paths FF.
- **Failure modes:** classifier tampering, same-user store tampering, accidental
  trusted callback exposure.
- **Existing controls:** integrity classes, modification trust levels, sealed
  registries, deny-by-default policy.
- **Missing controls:** OS-protected root/recovery storage and owner release
  attestation for future self-update.

#### PermissionBroker

- **Trusted inputs:** registered exact tool instance, trusted `ActionDescriptor`,
  normalized policy, trusted approval context.
- **Untrusted inputs:** model tool requests, arguments, task claims, forged
  tools, malformed permission/scope data.
- **Owns:** effect authorization, approval lifecycle, argument/action
  fingerprints, one-time consumption, unknown-outcome reservation.
- **Must never own:** planning, evidence truth, user memory, or provider choice.
- **Persistent data:** current broker approval/receipt state is process-local;
  audit and planning stores retain durable facts.
- **Boundary:** Tool -> Broker -> Policy -> approved effect; UI cannot call a
  tool executor directly.
- **Failure behavior:** unknown tool, malformed request, audit failure, expired
  or mismatched approval FF.
- **Failure modes:** forged caller context, replay, changed path/arguments,
  unknown effect replay.
- **Existing controls:** instance binding, HMAC fingerprints, task/scope/
  identity/expiry binding, deny-all default, extensive tests.
- **Missing controls:** production-authenticated UI/voice identity adapters;
  pending approvals intentionally require re-creation after restart.

#### Approval authentication and voice interaction

- **Trusted inputs:** broker-created `PermissionRequest`, exact operation,
  trusted owner identity, authenticated UI/local channel.
- **Untrusted inputs:** model narration, page text, TTS output, transcripts,
  wake/open-mic state, ambiguous speech.
- **Owns:** authentication of the approver and minting of a bounded decision.
- **Must never own:** microphone mode, task planning, or policy relaxation.
- **Persistent data:** approval/audit evidence; no raw transcript or secret.
- **Boundary:** same typed authority object to desktop and voice; parser only
  produces a non-authorizing choice.
- **Failure behavior:** no response/ambiguity/stale request FF to deny or remain
  unapproved.
- **Failure modes:** nearby speaker, stale generation, fake narration,
  malicious TTS, microphone mode confusion.
- **Existing controls:** exact phrase parser, trusted narrator/renderer,
  fingerprints, expiry, one-time consumption.
- **Missing controls:** authenticated speaker/user-presence binding and a
  production voice-to-broker adapter; see R2A-H06.

#### CredentialVault

- **Trusted inputs:** application-owned credential metadata, Windows-backed
  secret backend, scoped trusted request.
- **Untrusted inputs:** model/provider/package requests, raw secret values in
  ordinary data, cross-integration refs.
- **Owns:** all raw credential material and credential metadata/status.
- **Must never own:** ordinary memory, artifacts, logs, prompts, or integration
  policy.
- **Persistent data:** metadata SQLite only plus OS-backed secret target.
- **Boundary:** trusted proxy resolves opaque refs; generated code receives no
  master access or raw Vault authority.
- **Failure behavior:** missing backend, malformed metadata, future schema, and
  scope mismatch FF; no plaintext fallback.
- **Failure modes:** cross-integration scope confusion, logging/event leakage,
  same-user process reading OS credential targets.
- **Existing controls:** Windows backend, no secret DB columns, scope subset
  checks, secret-safe events/tests.
- **Missing controls:** effective OS isolation for generated/MCP processes and
  authenticated component registration for backup/artifacts.

#### PlanningEngine and TaskController

- **Trusted inputs:** application task request, validated plan, durable state,
  broker receipts, verification evidence.
- **Untrusted inputs:** model plan/tool proposals, user-edit payloads,
  external event payloads, fake result prose.
- **Owns:** durable task/plan/step execution truth, budgets, retries,
  cancellation, permission waiting, recovery state.
- **Must never own:** direct UI authority, provider trust, credential secrets,
  or a second orchestrator.
- **Persistent data:** planning SQLite/WAL/idempotency/audit-linked task truth.
- **Boundary:** TaskController/application only; legacy orchestrators are
  compatibility-only and not production authority.
- **Failure behavior:** malformed plans, budget exhaustion, unknown outcomes,
  stale revisions FF to recovery/blocking.
- **Failure modes:** duplicate control plane, replayed effect, fake success,
  budget escalation, stale approval.
- **Existing controls:** PlanValidator, exact step budget, fingerprints,
  `UNKNOWN_OUTCOME -> RECOVERING`, restart tests.
- **Missing controls:** no material high finding in the canonical path; retain
  topology tests whenever a new orchestrator is introduced.

#### GoalSupervisor

- **Trusted inputs:** original user goal, PlanningEngine status, bounded budgets,
  verified capability/health/evidence reports.
- **Untrusted inputs:** model analysis, discovery data, research documents,
  candidate packages, external instructions.
- **Owns:** durable intent coordination and bounded replan/dead-end analysis,
  not task effects.
- **Must never own:** direct tools, permissions, certification, or secret
  identity.
- **Persistent data:** goal/intention projections only; task truth remains
  PlanningEngine-owned.
- **Boundary:** GoalSupervisor proposes; CapabilityFactory/certification and
  PlanningEngine execute through their owners.
- **Failure behavior:** budget/cancellation/unknown outcome FF; alternatives are
  considered before blocked where implemented.
- **Failure modes:** autonomous preparation chaining into authority, duplicate
  planner, model-increased budget.
- **Existing controls:** bounded budgets, typed capability gap/factory boundary,
  no default direct effect path.
- **Missing controls:** no single complete production end-to-end supervisor is
  composed; do not treat the gap as permission to add a bypass.

#### Agent Runtime and ContextManager

- **Trusted inputs:** bounded execution contract, immutable security context,
  tool registry, PlanningEngine task ID, provider registry.
- **Untrusted inputs:** model responses, tool IDs/arguments, retrieved text,
  provider errors, context documents.
- **Owns:** bounded inference-turn orchestration and proposed agent result;
  it does not own durable task completion.
- **Must never own:** authority, trusted approval, external success claims, or
  durable memory truth.
- **Persistent data:** durable task/evidence belongs to PlanningEngine;
  sessions are separate execution records.
- **Boundary:** AgentLoop -> validated ToolRegistry request -> Broker; results
  return as untrusted evidence for verification.
- **Failure behavior:** malformed/unknown tool, timeout, cancellation, loop,
  token/wall/expensive budget FF.
- **Failure modes:** repeated calls, fake success, context security compaction,
  provider schema manipulation.
- **Existing controls:** strict structured output, LoopGuard, protected context
  fields, bounded compaction, unknown-outcome non-replay.
- **Missing controls:** provider-aware token accounting and enforced workspace
  binding on persistent sessions; see R2A-M02/R2A-M03.

### Data and model boundaries

#### Memory and User Model

- **Trusted inputs:** explicit user corrections/facts through application-owned
  services, authoritative provenance, retention policy.
- **Untrusted inputs:** external/model text, inferred facts, prompt-injected
  notes, low-confidence observations.
- **Owns:** UserModelStore facts/preferences and memory provenance/conflict/
  supersession state.
- **Must never own:** approvals, credentials, task completion, or policy.
- **Persistent data:** memory/UserModel SQLite and bounded history; no raw Vault
  secret.
- **Boundary:** scoped retrieval/control services; model sees selected context,
  never raw Vault.
- **Failure behavior:** secret, injection, cross-workspace, bad provenance and
  malformed correction FF to reject/quarantine.
- **Failure modes:** poisoning, stale belief, contradiction merge, workspace
  leakage, heuristic DLP gaps.
- **Existing controls:** classification, provenance, quarantine, correction,
  deletion, retention, workspace tests.
- **Missing controls:** authenticated source adapters rather than caller-supplied
  trust labels for future automatic learning.

#### Knowledge Libraries

- **Trusted inputs:** explicitly approved source roots/files, safe extractors,
  hash/modification metadata, workspace policy.
- **Untrusted inputs:** document text, metadata, prompt injections, discovered
  paths, integration-provided sources.
- **Owns:** documentary index, chunks, citations, sync state and source identity.
- **Must never own:** UserModel facts, permissions, credentials, or source-file
  deletion.
- **Persistent data:** knowledge-library SQLite/index metadata; source documents
  remain external.
- **Boundary:** scoped retrieval through ContextManager/Skills; source roots are
  application-owned.
- **Failure behavior:** path escape, secret content, classification mismatch,
  malformed extractor data FF/skip.
- **Failure modes:** prompt injection, path/reparse escape, stale/deleted index,
  cross-workspace retrieval.
- **Existing controls:** explicit roots, hashing, citations, untrusted flag,
  source-preserving deletion, classification/workspace tests.
- **Missing controls:** no high finding in current owner boundary; ensure future
  integration sources cannot self-declare trust.

#### ProviderRegistry and ModelRouter

- **Trusted inputs:** composition-owned provider definitions, model metadata,
  routing policy, resource state, privacy policy.
- **Untrusted inputs:** provider responses/streams, model metadata from external
  sources, endpoint/config values, cost/health claims.
- **Owns:** provider selection and health projection, not approval or task truth.
- **Must never own:** permission escalation, credential authority, or completion.
- **Persistent data:** model catalog/config/benchmark evidence, not prompts or
  secrets.
- **Boundary:** registry factory creates provider; AgentLoop/ConversationService
  consumes provider-neutral types.
- **Failure behavior:** unsupported provider, unsafe endpoint, malformed stream,
  unavailable model FF/degrades to configured fallback/NO_LLM.
- **Failure modes:** privacy misrouting, malformed stream, provider data leak,
  false health.
- **Existing controls:** local endpoint validation, `LOCAL_ONLY`/
  `PRIVACY_STRICT`, provider-neutral registry, fallback policies.
- **Missing controls:** strict stream schema and complete provider-aware token
  accounting; see R2A-M02.

#### AgentSession

- **Trusted inputs:** application session creation, provider/model identity,
  parent/child relation, synchronization state.
- **Untrusted inputs:** provider chunks, user/model context, cancellation races.
- **Owns:** execution-session lifecycle, usage, archive, and resynchronization
  metadata.
- **Must never own:** Task/Goal/UserMemory truth or approvals.
- **Persistent data:** session registry SQLite; no conversation truth beyond
  session metadata.
- **Boundary:** Conversation/Voice binds one session; cancellation rebuilds when
  synchronization is uncertain.
- **Failure behavior:** archive/rebuild on stale synchronization; provider error
  does not grant authority.
- **Failure modes:** stale response mixing, session reuse across workspace,
  usage tampering.
- **Existing controls:** synchronized flag, archive/rebuild, parent relation,
  voice cancellation tests.
- **Missing controls:** immutable workspace/profile/security ceiling; see
  R2A-M03.

### Extension, package, and acquisition boundaries

#### MCP Extension Manager

- **Trusted inputs:** validated user configuration, exact transport policy,
  ToolRegistry registration, broker policy.
- **Untrusted inputs:** server descriptors, tool/resource schemas, names,
  descriptions, results, stdio process, HTTP response.
- **Owns:** extension lifecycle/cache and adapter registration only.
- **Must never own:** Broker, Vault master access, trusted identity, policy, or
  direct tool execution.
- **Persistent data:** extension config/state/cache; credentials should be Vault
  references, not raw values.
- **Boundary:** MCP -> validated adapter -> ToolRegistry -> Broker. Current
  runtime creates the manager then seals the registry at `jarvis/runtime.py:589-590`,
  so manager startup is blocked.
- **Failure behavior:** malformed schema, timeout, collision, oversized result,
  process failure FF/degraded.
- **Failure modes:** stdio same-user escape, schema poisoning, process-tree
  escape, raw bearer token config, DNS/private-address surprises.
- **Existing controls:** bounded JSON IPC, no shell, namespace checks, result
  bounds, default disabled composition.
- **Missing controls:** H01 OS isolation for stdio, Vault reference support for
  HTTP credentials, authenticated host/network policy.

#### Integration Package, static review, and certification

- **Trusted inputs:** package hash, provenance, dependency lock, independent
  tests/audit, certification record, trusted authority decision.
- **Untrusted inputs:** package manifest/source/dependencies/binaries/UI,
  generated diagnostics, migrations, test evidence.
- **Owns:** admissibility/certification evidence, never package authority.
- **Must never own:** self-certification, promotion, policy mutation, Vault,
  reviewer mutation, or install hooks.
- **Persistent data:** package code/manifest/certification records and external
  user data separated by package boundaries.
- **Boundary:** reviewer -> certification -> trusted activation; package never
  calls reviewer/policy/certifier.
- **Failure behavior:** invalid layout/hash/provenance/permissions/dependency
  evidence FF to REJECT/manual review.
- **Failure modes:** regex bypass, forged evidence objects, dependency/typosquat,
  hidden install hooks, UI spoof, migration abuse.
- **Existing controls:** exact hashes, source review, dependency pinning, hook
  rejection, lifecycle checks, package/user-data separation.
- **Missing controls:** semantic/static analysis depth, authenticated durable
  certification ownership, H01/H03 enforcement.

#### Integration Sandbox and capability brokers

- **Trusted inputs:** certified package identity, typed IPC version/request ID,
  manifest capability and scope, broker decisions.
- **Untrusted inputs:** generated source/process, IPC messages, environment,
  paths, network responses, process requests.
- **Owns:** no trusted authority; only isolated package-local process state.
- **Must never own:** Broker, Policy, Vault master, trusted audit writer,
  RuntimeContainer, arbitrary host spawn, undeclared device/network/filesystem.
- **Persistent data:** dedicated work/data roots and rebuildable generated cache.
- **Boundary:** trusted host -> safe typed IPC -> OS-isolated sandbox; host
  proxies validate identity/manifest/capability/permission/scope.
- **Failure behavior:** identity/path/message/timeout/cancel/crash/reparse
  failure FF and cleanup.
- **Failure modes:** ambient OS escape, source/config/Vault read, IPC spoof,
  process-tree/network bypass, TOCTOU.
- **Existing controls:** typed JSON bounds, sanitized environment, owned roots,
  Job Object process/memory limits, host proxy checks, honest limitations.
- **Missing controls:** OS security container/restricted token and end-to-end
  malicious Windows tests; R2A-H01.

#### ProvisioningEngine

- **Trusted inputs:** typed provisioning plan, exact action identity, hashes,
  paths, permissions, rollback plan, broker approval.
- **Untrusted inputs:** generated plans, URLs/metadata, installers, checksums,
  package dependency declarations.
- **Owns:** execution state of typed setup actions, not package certification or
  permissions.
- **Must never own:** arbitrary giant scripts, unreviewed install hooks, Vault
  secrets, or activation.
- **Persistent data:** plan/action state and hashes sufficient for idempotent
  resume/rollback.
- **Boundary:** SetupConductor proposes; ProvisioningEngine executes typed
  actions under Broker/Policy and verifies reality.
- **Failure behavior:** checksum/unsupported provider/partial state/rollback
  failure FF; resume inspects reality.
- **Failure modes:** binary substitution, install hook, path/network/admin scope,
  partial rollback.
- **Existing controls:** bounded typed actions, idempotency states, exact plan
  fingerprints, tests for resume/checksum/rollback.
- **Missing controls:** no product-specific gap; exact executable signer/hash
  identity must remain mandatory for adoption/install.

#### CapabilityFactory and SetupConductor

- **Trusted inputs:** CapabilityGap, scoped SolutionReport, EnvironmentGraph
  evidence, user choices, SetupContext.
- **Untrusted inputs:** discovery candidates, research/package proposals,
  existing binaries/config, model recommendations.
- **Owns:** acquisition ordering and setup orchestration, not permissions or
  active capability authority.
- **Must never own:** direct install bypass, policy, certification, promotion,
  raw secrets, or a second task engine.
- **Persistent data:** setup run/context fingerprints and candidate evidence;
  user data/config remain external.
- **Boundary:** discover -> adopt -> reuse -> build; SetupConductor -> typed
  ProvisioningEngine; generated build stops ready-for-approval.
- **Failure behavior:** malformed candidate/context/decision FF; incomplete or
  declined setup remains inactive.
- **Failure modes:** malicious adoption, candidate substitution, setup callback
  authority, incompatible config, duplicate install.
- **Existing controls:** adoption-first selection, one interview, idempotent run
  state, no default factory composition, no raw secret in SetupContext.
- **Missing controls:** exact candidate binding and handler identity; R2A-H02.

### Lifecycle, UI, and interaction boundaries

#### Shadow, Canary, activation, and behavior drift

- **Trusted inputs:** certified package hash, host broker observations, signed/
  owner promotion decision, health/baseline store.
- **Untrusted inputs:** package behavior, declared effects, UI/voice observations,
  drift claims, generated evidence.
- **Owns:** trusted lifecycle state and drift response, not package policy.
- **Must never own:** self-promotion, baseline rewriting, approval bypass, or
  external effect execution outside broker.
- **Persistent data:** activation records, baseline versions, drift evidence,
  rollback target.
- **Boundary:** lifecycle service controls transitions; Health/Doctor reports;
  package remains a client.
- **Failure behavior:** missing/contradictory evidence, material/security drift,
  failed canary FF to quarantine/degrade.
- **Failure modes:** post-facto reported effects, fake promotion, baseline
  poisoning, delayed ambient behavior.
- **Existing controls:** fresh certification per version, Shadow/Canary states,
  budget checks, quarantine/rollback, generated/model baseline rejection.
- **Missing controls:** complete OS isolation and a durable activation-session
  owner; trusted broker observations and independent promotion evidence are now
  enforced for the supported host-proxy path. R2A-H01 remains.

#### Dynamic UI and PresenceProjection

- **Trusted inputs:** application service results, typed events, package-owned
  declarative manifests, ArtifactRefs.
- **Untrusted inputs:** package UI declarations/content, model text, page text,
  assets, animation signals.
- **Owns:** only a derived presentation/projection; no task or permission truth.
- **Must never own:** direct tool execution, approval, policy, or arbitrary code
  loading.
- **Persistent data:** UI/package assets and presentation references, not
  authority state.
- **Boundary:** UI -> application services; Presence derives from EventBus;
  trusted permission component is host-owned.
- **Failure behavior:** unsafe asset/script/theme/control metadata FF; Safe Mode
  falls back to generic UI.
- **Failure modes:** approval imitation, arbitrary JS/assets, stale projection,
  query-state false evidence.
- **Existing controls:** declarative themes, opaque Asset/ArtifactRefs,
  forbidden executable keys, application-only UI tests.
- **Missing controls:** robust approval-claim analysis and host-owned chrome;
  query observer requirement; R2A-H04/R2A-M07.

#### Browser Semantic Bridge

- **Trusted inputs:** browser adapter document identity, tab/document generation,
  origin, Vault reference, canonical Broker decision.
- **Untrusted inputs:** DOM/page text, frames, URLs, semantic IDs, form values,
  page controls.
- **Owns:** scoped semantic references and adapter state, not browser secrets or
  permission.
- **Must never own:** cookies/password stores, cross-origin hidden data,
  approval, arbitrary browser internals.
- **Persistent data:** bounded tab/document projection and events; no secrets.
- **Boundary:** BrowserSemanticBridge -> BrowserBrokerAdapter -> registered
  Browser Tool -> PermissionBroker -> trusted browser adapter; uncomposed
  bridges remain deny-by-default.
- **Failure behavior:** stale ID/origin/tab/credential/reference mismatch FF.
- **Failure modes:** origin confusion, page approval spoof, password/cookie leak,
  cross-origin frame confusion.
- **Existing controls:** origin binding, generation IDs, password redaction,
  Vault refs, cross-origin stripping, stale tests.
- **Missing controls:** no supported OS/browser-process isolation is claimed;
  companion availability and vision/coordinate fallbacks remain separate
  capabilities.

#### Event Automation and Scheduler

- **Trusted inputs:** typed event facts, durable automation definition, bounded
  concurrency policy, PlanningEngine/task service.
- **Untrusted inputs:** external event payload/content, event source claims,
  trigger conditions, model-authored goals.
- **Owns:** subscriptions, debounce/cooldown/dedupe/concurrency and run trace;
  Scheduler owns timing/admission only.
- **Must never own:** direct effect execution, approval, task truth, or standing
  authority.
- **Persistent data:** automation definitions/runs; task truth remains planning
  store and scheduler state remains scheduler-owned.
- **Boundary:** Event -> trigger/condition -> normal Goal/WorkflowTemplate ->
  PlanningEngine -> Broker -> Verification.
- **Failure behavior:** event storm, restart unknown, queue overflow, malformed
  condition FF/drop/queue according to typed policy.
- **Failure modes:** approval smuggling, recursive triggers, standing grants,
  resource exhaustion.
- **Existing controls:** typed definitions, durable dedupe/cooldown, bounded
  queue/concurrency, simulation mode, normal task/broker path.
- **Missing controls:** authenticated event producer/source and durable
  priority/attention coordination; R2A-M05/R2A-M08.

#### Plan Studio

- **Trusted inputs:** current PlanningEngine plan/revision, structured user edit,
  PlanValidator, effect fingerprints.
- **Untrusted inputs:** model-suggested edits, UI text, stale plan/revision,
  unknown step/capability.
- **Owns:** no execution; creates validated plan revisions and invalidates stale
  approvals.
- **Must never own:** task status, effect replay, permission minting, or direct
  tool calls.
- **Persistent data:** plan revisions/provenance in planning store.
- **Boundary:** UI/application service -> Plan Studio -> PlanValidator ->
  PlanningEngine.
- **Failure behavior:** stale/invalid edit or unknown effect FF; branch retains
  evidence and never replays unknown outcomes.
- **Failure modes:** stale approval inheritance, branch after effect, second
  planner, unknown replay.
- **Existing controls:** revision/fingerprint tests and canonical PlanningEngine.
- **Missing controls:** no independent high finding; preserve one-plan-owner
  topology in future UI wiring.

#### Trace Explorer

- **Trusted inputs:** domain-owner facts, broker/audit receipts, evidence,
  artifact references, classification policy.
- **Untrusted inputs:** model summaries, tool outputs, replay requests,
  presentation text.
- **Owns:** derived human-readable trace and replay preparation only.
- **Must never own:** hidden chain-of-thought, approval, completion, or replay
  execution.
- **Persistent data:** sanitized trace/events and replay plans; source domains
  retain authority.
- **Boundary:** domain owners emit facts; Trace renders/restricts replay; replay
  returns to PlanningEngine/Broker.
- **Failure behavior:** secret/classification/unknown-outcome/stale approval FF.
- **Failure modes:** secret leakage, fake evidence, permission bypass through
  replay, model chain-of-thought exposure.
- **Existing controls:** redaction, simulation mode, unknown-outcome refusal,
  stale approval tests.
- **Missing controls:** protect local trace store from same-user sandbox access
  under R2A-H01.

### Persistence, recovery, and improvement

#### ArtifactStore

- **Trusted inputs:** typed ArtifactRecord/content, workspace/classification,
  producer/provenance, safe app-owned storage.
- **Untrusted inputs:** artifact bytes, MIME/name/path, external content, model
  claims, ArtifactRefs from other workspaces.
- **Owns:** artifact metadata/content, immutable versions/derivations and safe
  storage reference.
- **Must never own:** evidence truth, memory, credentials, task completion, or
  arbitrary UI filesystem loading.
- **Persistent data:** app-owned artifact directory and metadata SQLite.
- **Boundary:** task/capability writes through store; Presentation/Backup/Trace
  receive opaque refs with workspace checks.
- **Failure behavior:** traversal, reparse, collision, secret classification,
  cross-workspace reference FF.
- **Failure modes:** MIME/path confusion, secret misclassification, retention
  leak, renderer/parser risk.
- **Existing controls:** immutable hash/version, workspace checks, reparse/path
  hardening, explicit credential-secret rejection.
- **Missing controls:** authenticated producer registration/content classification;
  see R2A-M06.

#### Backup and Migration

- **Trusted inputs:** user-selected component providers, reviewed crypto,
  authenticated bundle, migration/reauth/recertification decisions.
- **Untrusted inputs:** backup path/bundle bytes, component payloads, schema,
  external paths, old versions, generated integration data.
- **Owns:** encrypted transport bundle and restore planning/report, not domain
  truth or LKG recovery.
- **Must never own:** plaintext credentials, automatic package activation, source
  deletion, or hidden destructive restore.
- **Persistent data:** encrypted backup bundle/manifest and migration report;
  source domain stores remain owners.
- **Boundary:** domain owner exports/imports through registered callbacks;
  Backup verifies, previews, snapshots, migrates, and invokes owner appliers.
- **Failure behavior:** wrong key/tamper/future schema/conflict/reauth/
  recertification/relink failure FF and rollback where practical.
- **Failure modes:** secret-bearing payload under benign component, bundle
  transplant/downgrade, path/MIME abuse, callback authority.
- **Existing controls:** AES-GCM authenticated bundle, reviewed KDF, bounds,
  selective restore, reauth/recertification, technical snapshot.
- **Missing controls:** authenticated provider ownership and stronger LKG
  integrity; R2A-H05/R2A-M06.

#### Self-Improvement

- **Trusted inputs:** protected regression baseline, complete patch path set,
  modification trust classifier, independent gates, owner release authority.
- **Untrusted inputs:** model/code candidates, research/docs, generated tests,
  claimed risk/benefit, dependency metadata.
- **Owns:** proposal/evaluation/workspace evidence, never root trust or direct
  production mutation.
- **Must never own:** classifier/policy editing, Broker/Vault/security release,
  self-certification, or silent regression removal.
- **Persistent data:** proposal/worktree/evaluation evidence and golden records.
- **Boundary:** candidate -> isolated workspace -> static/tests/regression ->
  trusted release; no production merge/deploy executor.
- **Failure behavior:** malformed metadata, protected path, regression, gate
  failure FF; highest trust level controls mixed patch.
- **Failure modes:** classifier tamper, renamed protected module, test/golden
  tamper, dependency injection, update-preview omission.
- **Existing controls:** levels 1-5, protected paths, exact fingerprints,
  independent protected scenarios, user/system actor checks.
- **Missing controls:** owner-authenticated external release service and OS
  isolation; do not treat passing generated tests as proof.

#### Self-Update, LKG, and Recovery

- **Trusted inputs:** candidate revision, authenticated snapshot/manifest,
  migration metadata, health deadline, trusted recovery authority.
- **Untrusted inputs:** candidate build, config/schema, migration, startup health,
  LKG pointer/evidence files.
- **Owns:** recovery state, startup attempts, crash-loop detection, Safe Mode,
  rollback evidence and restore points.
- **Must never own:** permission policy mutation, unreviewed package activation,
  or arbitrary update execution without owner gates.
- **Persistent data:** recovery manifests, active-start marker, LKG pointer,
  evidence log, snapshots.
- **Boundary:** update/release service prepares; RecoveryStore verifies/records;
  Runtime health checks; Safe Mode disables privileged/generated/scheduler work.
- **Failure behavior:** malformed/future metadata, failed health, migration
  mismatch, crash loop FF to LKG/Safe Mode.
- **Failure modes:** unsigned/tampered LKG, incomplete snapshot, rollback loop,
  migration downgrade, gate tamper.
- **Existing controls:** bounded startup deadline, crash-loop threshold,
  schema refusal, path checks, Safe Mode capabilities.
- **Missing controls:** authenticated content hashes and complete production
  update coordinator; R2A-H05. No UpdatePreview executor is present to review.

#### SetupConductor

- **Trusted inputs:** normalized user choices, setup handler contract, typed plan,
  workspace/credential references.
- **Untrusted inputs:** adoption inspection, existing config/data, candidate
  metadata, setup prompts and component recommendations.
- **Owns:** setup interview/run state and idempotent step orchestration.
- **Must never own:** permission grant, raw secret, arbitrary install shell,
  capability certification/activation.
- **Persistent data:** setup run/context fingerprint and step decisions; user
  folders/config are external and preserved.
- **Boundary:** inspect -> one interview -> adopt/reuse/provision -> configure ->
  verify; destructive work uses ProvisioningEngine/Broker.
- **Failure behavior:** incompatible/declined/partial/malformed setup FF or
  resumes safely.
- **Failure modes:** unsafe adoption, callback mutation, insecure defaults,
  duplicate install, candidate mismatch.
- **Existing controls:** adoption-first contract, one interview, decision/context
  fingerprints, restart/idempotency tests.
- **Missing controls:** H02 exact candidate identity and trusted typed handler
  boundary.

#### ComponentDoctor

- **Trusted inputs:** owner-registered probes/playbooks, health evidence, typed
  repair action, fresh approval through application policy.
- **Untrusted inputs:** capability failure descriptions, package diagnostics,
  repair proposals, provider/process output.
- **Owns:** diagnostic routing and repair orchestration for the named component,
  not the component's domain authority.
- **Must never own:** cross-domain repair, permission bypass, package self-repair
  authority, or direct arbitrary commands.
- **Persistent data:** diagnosis/repair attempts, health status, quarantine and
  verification evidence.
- **Boundary:** CapabilityHealth owner -> ComponentDoctor -> owner probe/action ->
  Broker/Provisioning if needed -> verify.
- **Failure behavior:** unknown owner/action/unsafe description/approval failure
  FF; safe degradation preferred.
- **Failure modes:** malicious playbook, cross-domain authority, unsafe repair,
  capability crash taking down core.
- **Existing controls:** owner matching, action allowlists, absent/failed
  authorizer deny, bounded attempts, no implicit authority.
- **Missing controls:** authenticated playbook/provider registration when package
  activation becomes reachable; H01/H03 remain prerequisites.

#### ResourceGovernor

- **Trusted inputs:** composition-owned telemetry, resource policy, priority,
  bounded budget/reservation request.
- **Untrusted inputs:** provider/model cost claims, telemetry adapters, background
  job requests, stale snapshots.
- **Owns:** process-wide resource admission and reservation lifecycle only.
- **Must never own:** task cancellation as a substitute for permission, policy,
  completion, or model truth.
- **Persistent data:** transient reservations/decisions; no durable task truth.
- **Boundary:** Runtime owns one governor; ModelRouter/Scheduler/Sandbox/
  indexing/warmup request reservations.
- **Failure behavior:** malformed telemetry/request FF/defer; terminal complete,
  cancel, crash, timeout release reservations.
- **Failure modes:** DoS via telemetry spoof, reservation leak, pressure-induced
  starvation, unnecessary foreground cancellation.
- **Existing controls:** bounded budgets, centralized instance, release reason,
  fake telemetry tests.
- **Missing controls:** authenticated telemetry source for hostile local
  processes; impact is availability rather than authority.

## Attack-family disposition

| Attack family | Result | Reason |
|---|---|---|
| Agent tool forgery, loops, fake success, budget/identity/task spoof | PASS with residual | AgentLoop/PlanValidator/Broker bounds and fingerprints pass existing tests; model claims remain untrusted |
| Context/memory/knowledge injection and poisoning | PASS with restrictions | Classification, provenance, quarantine, scope, and bounded priming exist; heuristic detection and caller trust labels remain defense-in-depth |
| Voice wake/open mic, ambiguity, stale barge-in, narration, TTS | NO-GO for spoken privileged approval | Capture/barge-in/strict phrase tests pass; speaker/user authentication and production broker binding are missing (R2A-H06) |
| Providers and malformed streams | PASS with restrictions | Local privacy endpoint checks and routing pass; stream schema is loose (R2A-M02) |
| MCP malicious server/schema/process | NO-GO for enablement | Registry is sealed in default runtime; stdio is not OS-isolated and HTTP credential handling is not Vault-native (R2A-H01) |
| Factory/adoption/setup | NO-GO for adoption | Candidate compatibility is not exact identity-bound (R2A-H02) |
| Sandbox/Windows/host proxies | NO-GO for hostile code | Typed IPC and Job Object are not sufficient OS isolation (R2A-H01) |
| Credentials/logs/events/context/artifacts/backup | PASS with restrictions | Vault boundary and secret-safe projections pass tests; same-user isolation and provider registration remain gaps |
| Browser | PASS WITH RESTRICTIONS | Configured browser actions use `BrowserBrokerAdapter` and the canonical broker; missing/unsupported companions remain unavailable and no OS browser isolation is claimed |
| Dynamic UI/presentation/theme/assets | NO-GO for generated UI | Declarative/asset controls pass, but approval imitation check is bypassable (R2A-H04) and physical query evidence is conditional (R2A-M07) |
| UI simulation/certification | NO-GO for UI-bearing activation | Zero-effect fake endpoint works; security spoof check is incomplete |
| Automation/scheduler/workflows | PASS with restrictions | Normal PlanningEngine/Broker path and bounded feedback/concurrency; source spoof/storm remains availability risk |
| Shadow/Canary/drift | PASS WITH RESTRICTIONS | Trusted effect attestation and independent verification are enforced for the supported broker path; generated activation remains NO-GO until Windows isolation/default composition gates pass |
| Repair/ComponentDoctor | PASS with restrictions | Ownership and absent-authorizer FF; registration trust depends on future package boundary |
| Artifacts/backup/migration | PASS with restrictions | Authenticated backup, safe artifact paths, and the authenticated local LKG record pass; vendor-signed release provenance and complete self-update execution remain out of scope |
| Resource/Governor | PASS | Central bounded admission; telemetry spoof affects availability only |
| Golden Workflows | PASS with restrictions | Fingerprints and candidate gates pass; actor authenticity is composition-owned |
| Self-improvement/self-update/LKG | NO-GO for update | Modification classification and local authenticated recovery now pass; complete trusted self-update execution, release-owner identity, and vendor provenance remain absent |
| Autonomous preparation | BLOCKED/SAFE | Factory stops before approval and no OpportunityEngine authority chain is composed |
| Donor ports | PASS | No runtime donor dependency or approved PORT entry found |

## Required remediation order before v1

1. Provide and verify OS-enforced isolation for generated and MCP processes;
   keep the current default disabled until Windows denial tests pass.
2. Bind SetupConductor/CapabilityFactory adoption to exact candidate identity,
   executable hash/signer, dependency evidence, and pre-use revalidation.
3. Keep effect-time trusted broker attestation, authenticated owner promotion,
   durable lifecycle state, and restart-safe evidence on every newly composed
   broker path.
4. Make generated UI unable to imitate trusted approval; use host-owned typed
   permission controls and broaden simulation security validation.
5. Authenticate snapshot file contents/LKG metadata and make production recovery
   capture the actual restorable authoritative state.
6. Keep spoken approval non-authorizing until a trusted identity/user-presence
   binding and exact current request binding are implemented and tested.
7. Retain the canonical Broker-backed Browser adapter and its exact
   binding/deny-first tests; do not enable an uncontrolled browser fallback.
8. Add strict provider stream schemas, workspace-bound sessions, authenticated
   learning/context source adapters, and owner-authenticated package/backup
   registration as defense-in-depth.

## Validation executed

The security/trusted/deterministic sweep executed against this revision:

- targeted security/trusted subsystem pytest sweep: **716 passed, 2 skipped**;
- `python scripts/run_system_tests.py --suite deterministic-workflows`:
  **passed, 26 tests**;
- `python scripts/run_system_tests.py --suite deterministic-permissions`:
  **passed, 70 tests, 1 skipped**;
- bounded local synthetic checks described in R2A-H01, R2A-H02, R2A-H04, and
  R2A-H05: findings reproduced without modifying repository or user data;
- `python scripts/quality.py`: **passed** — Ruff format/check, mypy, **1,138
  passed and 5 skipped**, coverage report **90%**;
- final `python scripts/run_system_tests.py --suite deterministic-workflows`:
  **passed, 26 tests**.

No hardware/manual, Windows Accessibility/UI Automation, physical microphone,
camera, real TTS/STT, real browser, authenticated user-presence, AppContainer/
restricted-token, or deployment/update test was executed. Those must not be
reported as passed. The safe default/disabled state is the only current blocker
for the unexecuted privileged expansion surfaces.

## Final release statement

Current core controls are strong for the canonical PlanningEngine -> Tool ->
PermissionBroker path, and no CRITICAL finding was found. The repository is not
ready to claim v1.0.0 for its adaptive self-expansion architecture because the
remaining HIGH findings become reachable when the promised generated/MCP/UI/
adoption/voice/update paths are activated. Keep those paths disabled or
quarantined until each named remediation has an owner, a negative regression
test, and an independently verified production composition.

## Effect-attestation remediation update

The former R2A-H03 callback-evidence gap is **FIXED** for the supported staged
activation path. `EffectAttestationStore` now owns durable broker attempts and
package/activation-bound observations; `PackageActivationService` rejects
missing, forged, or mismatched attestations and requires independent
non-model verification before promotion. Host-proxy Shadow dispatch is
suppressed before the executor/native client is called. See
`docs/security/effect-attestation.md` and `tests/test_effect_attestation.py`.

This does not resolve R2A-H01: same-user Windows process isolation remains a
separate blocker for hostile generated-code activation.

## Browser Broker follow-up disposition

R2A-H07 is **FIXED for the supported configured runtime path**. The native
`BrowserBrokerAdapter` registers strict per-action tools in `ToolRegistry` and
routes them through `PermissionBroker` before the trusted browser backend is
called. The request binds the tab, document generation, origin, semantic
reference, bounded arguments, and task/correlation context. Missing or
unsupported browser backends remain unavailable; the bridge's default gate
still denies uncomposed access. Credential fill requires an opaque Vault
reference and a configured trusted `CredentialVault`.

Evidence: `tests/test_browser.py` covers broker dispatch, denial before
backend effects, stale/origin binding, password and page-data handling,
missing-vault rejection, and unsupported backend rejection; runtime composition
is covered in the same test module and `tests/test_runtime.py`. Residual
limitations are documented in `docs/security/browser-broker.md`; this change
does not claim OS isolation for a browser process or make vision/coordinate
automation an implicit fallback.
