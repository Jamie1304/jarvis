# ADR: Sandbox certification contract and generated-code trust boundary

## Status

Implemented D6B1 contract: **immutable worker and constrained payload**.
The D6R review established the defect; D6B1 implements the selected Option 1
without changing the AppContainer, Job, or ACL cleanup contract.

## D6B1H console-host containment repair

**Selected architecture: `WINDOWED_INTERPRETER_SINGLE_PROCESS_WORKER`.**

The console-subsystem `python.exe` is not an admissible AppContainer worker on
this host.  A live owned-Job observation showed the Python worker as the first
member and `C:\\Windows\\System32\\conhost.exe` as its child after resume and
normal stdin/stdout protocol use.  The Job's authoritative
`JOBOBJECT_BASIC_ACCOUNTING_INFORMATION.ActiveProcesses` then rose from one to
two despite its configured active-process limit of one.  The earlier
`CREATE_NO_WINDOW` flag and explicit standard-handle list were already present,
so that flag alone is not a sufficient one-process guarantee for this console
interpreter/AppContainer combination.

The trusted Windows worker executable is now the installed base
`pythonw.exe`, not `python.exe`.  In the same AppContainer launcher, with the
same explicit stdin/stdout pipes, Job limit, suspended assignment-before-resume
sequence, and NUL stderr handle, the windowed interpreter completed protocol
requests with one Job member and no console host.  Missing `pythonw.exe` is a
startup failure; there is no fallback to the console worker.  The executable
hash is included in the immutable-worker compatibility fingerprint, so a
changed interpreter invalidates constrained-package certification records.

The launch also applies
`PROC_THREAD_ATTRIBUTE_CHILD_PROCESS_POLICY` with
`PROCESS_CREATION_CHILD_PROCESS_RESTRICTED`.  Attribute application failure
fails startup.  This is a second, native enforcement layer: the constrained
payload has no code or subprocess primitive, and a deliberately adversarial
AppContainer worker attempting `subprocess.Popen` is denied while the Job
remains at one active member.  The policy is used only with the capability-free
AppContainer worker; it is not an exception for a named helper.

`PROC_THREAD_ATTRIBUTE_JOB_LIST` was rejected because the existing suspended
root-process assignment happens before resume and did not explain the observed
console child.  Raising the Job limit, accepting a process by executable name,
and retaining the console executable with a presumed helper exception are
rejected: none proves that generated content lacks general child-process
authority.  `CREATE_NO_WINDOW` was also rejected as the selected mechanism
because the live console-worker experiment still produced `conhost.exe`.

The wire protocol remains parent-owned validation over explicit stdin/stdout
pipes.  Stderr remains the existing NUL route; no AppContainer stderr pipe is
introduced.  AppContainer profile, SID, ACL-lease, Job, and owned-filesystem
cleanup remain mandatory and fail closed.

## Implemented D6B1 contract

`jarvis.sandbox_worker` is versioned JARVIS production code, materialized by
the trusted parent into a hash-verified sandbox-owned runtime directory. It is
not Trusted Core authority: it runs inside the existing single-process
AppContainer Job and receives no broker, vault, approval, audit, or host-bridge
object. The worker owns frame parsing, identity echoing, result framing,
protocol bootstrap, payload load classification, health dispatch, bounded
failure responses, and stdout.

New packages use `schema: 2`, format `CONSTRAINED_WORKER_PAYLOAD`, and contain
only immutable `code/payload.json`. The versioned payload is data, not Python:
it declares an identity, label, untrusted self-health value, dependency names,
and actions using the small supported operation set (`default_output`,
`concat_strings`, or deterministic `fail`). Unsupported, malformed, missing,
or dependency-bearing payloads fail closed through a valid worker response.
There is no generated `entrypoint.py`, `exec`, `eval`, compilation, dynamic
import, or generated stdout/protocol path.

The worker returns `PROTOCOL_READY` independently of payload success. Payload
failures are typed as `PACKAGE_MANIFEST_INVALID`, `PAYLOAD_INVALID`,
`PAYLOAD_VERSION_UNSUPPORTED`, or `DEPENDENCY_UNAVAILABLE`; valid unhealthy
self-health remains untrusted evidence and cannot certify a package. Functional
probes continue through the trusted parent and application semantic oracle.
Certification records bind the worker compatibility/fingerprint, so a worker
change requires recertification.

Schema-1 or otherwise old stored packages are detected as
`LEGACY_COMPLETE_ENTRYPOINT`, retained for diagnosis, and quarantined from
load/activation. They are never executed, rewritten, grandfathered, or
recertified automatically; safe use requires regeneration and full
recertification.

## Context and evidence

The current production path is:

`AgentRuntimeCapabilityGenerator` -> `ProductionPackageStore` ->
`ProductionSandboxRunner` -> `SandboxProcess` -> Windows AppContainer/Job ->
trusted `jarvis.sandbox_worker` plus stored `code/payload.json` ->
`ProductionCertificationProvider` -> `PackageCertifier` ->
`PackageActivationService`.

The relevant implementation is in `jarvis/production_capability.py`,
`jarvis/sandbox.py`, `jarvis/windows_sandbox.py`,
`jarvis/package_certification.py`, and `jarvis/package_activation.py`.
The source identity for this review is branch `agent/v1-integration`, HEAD
`77eaa48ea9370b792e9df51f2a43e1853873a0b8`, parent
`faccb32c67f1ec54ff99f8142e93f214df41f70d`, version `1.0.0`.

The D3 ACL repair remains part of the security contract. It owns temporary
AppContainer ACL leases, ordered restoration, semantic post-restore checking,
profile deletion, and fail-closed cleanup. D6B2F/G adds a distinct lifecycle
rule: the foreground cleanup deadline bounds JARVIS responsiveness, not native
terminality. A deadline produces typed `CLEANUP_OUTCOME_UNKNOWN`, retains an
atomic schema-2 trusted receipt (operation ID, process generation, profile/SID
binding, resource-class binding, semantic fingerprints, and exact bounded raw
DACL baselines), and quarantines the affected sandbox root. A fingerprint is
not restoration data. It cannot claim ACL restore, profile deletion, lease
release, or resource reuse. Startup discovers terminal and non-terminal
receipts, admits one trusted reconciler through an OS lock, and performs
observation before any exact trusted mutation. Only post-mutation semantic
verification may produce `CLEANUP_CONFIRMED`; invalid metadata, unknown
ownership, failed verification, or a reconciliation deadline produces
`RECOVERY_BLOCKED` and keeps allocation denied. No generated worker can create,
edit, authorize, invoke, or reconcile this state, and the AppContainer Job
remains one `pythonw.exe` process with a maximum active-process count of one.

## Current constrained-worker contract

Generated capability content is data only. `_parse_generation_spec()` rejects a
model-supplied complete `source`; generation produces an immutable
`code/payload.json` with the versioned constrained-payload schema. The trusted
parent materializes the hash-verified `jarvis.sandbox_worker` from JARVIS code
and passes only the payload path and package identity into it. There is no
generated `entrypoint.py`, `exec`, `eval`, compilation, dynamic import, or
generated protocol implementation.

The worker owns the fixed newline-JSON protocol and supports only the bounded
operation set declared by the certified manifest. It reports protocol readiness
separately from payload self-health. A declared operation that requires host
authority becomes a typed parent broker request; the worker never receives a
broker, permission receipt, credential, approval object, or recovery authority.
`ProductionPackageStore` stores only schema-2 constrained payloads and
quarantines legacy complete-entrypoint packages for regeneration and
recertification.

The package metadata, action schemas, identifiers, payload hash, worker
compatibility fingerprint, and source snapshot are JARVIS-owned deterministic
data structures. They establish provenance and integrity, not authority. The
parent owns transport validation, certification, activation, verification,
cleanup, and post-restart reconciliation.

## Protocol ownership and trust

The immutable JARVIS worker owns the child protocol. The parent `SandboxProcess`
still validates frame size, JSON shape, response identity, integration identity,
protocol version, trace identity, and bounded diagnostic volume. The constrained
payload can select only data-driven behavior declared by the certified manifest;
it cannot replace parsing, transport, health framing, command dispatch, or
error/shutdown handling.

The trust classes are:

- `TRUSTED_CORE`: the parent application, `PermissionBroker`, durable package
  and lifecycle stores, `PackageCertifier`, activation service, verification
  engine, and native launcher orchestration.
- `PRODUCTION_CORE`: `ProductionSandboxRunner`, `SandboxProcess`, parent-side
  protocol validation, and trusted composition hooks. They observe and decide;
  they do not trust child claims.
- `SANDBOX_RUNTIME`: the AppContainer/Job process and its native containment,
  still untrusted for statements even though it is isolated.
- `GENERATED_UNTRUSTED`: model/provider source, generated package code, and
  child self-reports.
- `DATA`: package metadata, source snapshots, protocol payloads, hashes, and
  bounded diagnostics. Data is evidence input, not authority.

## Health semantics and certification authority

`status == "healthy"` means that one fresh immutable worker produced a bounded,
correctly framed response whose request ID, integration ID, and protocol
version passed parent validation; the observed AppContainer status also
reports executable isolation. The payload's `healthy` value remains an
**untrusted package self-health claim plus trusted protocol evidence**. It does
not prove action functional correctness or safe authorization.

The claim is not sufficient for certification. `PackageCertifier` requires the
static audit, unit/functional evidence, sandbox integration test, permission
diff, authority decision, install/content integrity, healthcheck, and
verification hooks. Production functional cases are checked against an
application-owned semantic oracle. Authority, Shadow, Canary, independent
verification, and promotion are owned by trusted services. A generated package
cannot self-certify, self-authorize, self-promote, or rewrite certifier policy.
The immutable worker and parent-owned transport keep the protocol ownership
boundary inside the trusted implementation.

### Constrained broker operation

Payload v1 may declare one versioned operation identifier declared by the
certified manifest. The immutable worker validates its typed input and returns
a bounded broker request; it never receives a broker, permission receipt,
credential, or protocol authority. The trusted parent checks the
package/action identity and declared operation before invoking the injected
application broker and returning a bounded JSON result through a second worker
request. Missing brokers, undeclared operations, malformed arguments, and
non-JSON/oversized results fail closed. This is a transport bridge to the
existing application-owned broker boundary, not a new tool registry. The
historical `synthetic.transform.v1` identifier is TEST_ONLY and is not a
production worker or capability branch; production accepts only generic,
manifest-declared operation identifiers and reports unregistered ones as
typed unavailable failures.

## Failure taxonomy and information loss

The intended buckets and current coverage are:

| Boundary | Current native/project equivalent | Current distinction |
| --- | --- | --- |
| launch | `SandboxProcessError`, `SandboxStartupError`, native launch errors | Partial: native layer distinguishes; provider often wraps |
| isolation | `SandboxIsolationUnavailable`, `SandboxSecurityStatus.executable_isolation` | Yes at sandbox/certifier gate; outer report can coalesce |
| protocol bootstrap | startup EOF before parent protocol response | Partial: no dedicated package-bootstrap stage |
| protocol transport | `SandboxProtocolError`, diagnostics classifications, timeout/write failure | Yes in `SandboxProcess`; often coalesced by provider |
| package load | constrained payload parse/schema/identity validation | Typed worker response; certification fails closed |
| dependency load | dependency names are rejected by the payload validator | Typed `DEPENDENCY_UNAVAILABLE`; no child import path |
| package self-health | `HEALTHCHECK` and `status` payload | Yes, but conflated with load/transport in outer errors |
| functional probe | functional case and semantic-oracle evidence | Yes |
| certification | `CertificationFailure` with a named stage | Yes |
| Shadow | `ActivationState.SHADOW`, quarantine, `Shadow broker failed` | Yes at activation, but reported as `Shadow activation failed` by coordinator |
| Canary | `ActivationState.CANARY`, bounded attestation and verification | Yes |
| verification | `VerificationEngine` and acquisition verification | Yes |
| cleanup | `SandboxCleanupError`, native ACL/profile cleanup error | Yes and fail-closed at native boundary; outer report may wrap |

Payload schema failure, dependency rejection, protocol EOF, malformed response,
and a valid unhealthy self-report remain distinct bounded observations. The
parent preserves protocol classification and worker payload-load status through
certification without exposing secrets; no generated Python bootstrap or import
path is part of the production package contract.

## Process and native transaction semantics

Certification and activation use multiple fresh `SandboxProcess` instances.
`ProductionSandboxRunner._execute()` creates one process, starts it, performs
one request, and closes it. Functional cases, sandbox integration health,
healthcheck, Shadow, Canary, and active-runtime invocations consequently do not
share child memory. This is intentional process isolation and is compatible
with the current Job `max_processes=1` rule; no generated process state is
expected to survive. The evidence is bound to package identity and operation,
not to an assumption that health process A proves that process B has retained
state. Functional and semantic evidence must therefore be repeated on the
fresh process that performs the operation.

Each native stage owns the exact lifecycle: create/adopt a unique AppContainer
profile, capture and grant bounded ACL leases, create the suspended process,
assign it to the Job before resume, establish explicit stdio, execute the
request, terminate/wait, close handles, wait for Job emptiness, restore ACLs,
verify restored DACL semantics and temporary SID absence, and delete the
profile. `SandboxProcess._stop_locked()` records a durable schema-2 receipt
before and during cleanup. A foreground deadline bounds host responsiveness;
it does not claim native terminality. `CLEANUP_OUTCOME_UNKNOWN` retains the
receipt and denies allocation. Startup recovery observes the receipt and OS
state, restores only validated DACL baselines, re-verifies, reconciles the
exact profile/SID, and writes `CLEANUP_CONFIRMED` atomically. This contract is
**correct: YES** on current source inspection.

The certification transaction owns package evidence and every sandbox process
it creates through the trusted runner. Native profile/ACL ownership is inside
the launcher/native process adapter; the one trusted startup reconciler is
parent-owned and serialized by an OS lock. The boundary is operationally split
across these cooperating owners, but unknown cleanup remains quarantined until
trusted observation and correction prove the terminal condition.

## Historical failure reclassification

No exact historical root cause is invented.

| Failure | Supported bucket | Root cause status |
| --- | --- | --- |
| D4 A, `f32d0b93d1de`, `salt-57594a30`, Shadow activation failed | Shadow-stage sandbox/package/protocol boundary failure; the outer coordinator wording is not more specific | UNKNOWN; later isolated replay passed |
| D4 B, `4fae9218c47`, `salt-9029b3fd`, generated runtime failure | Package bootstrap/load, protocol startup, or later generated action/runtime failure are all compatible with the recorded wrapper | UNKNOWN; later isolated replay passed |
| D5 C, `723d9e82cc1d`, certification healthcheck failure | Sandbox/package bootstrap or package self-health failure during HEALTHCHECK | UNKNOWN; both PASS and FAIL behavior occurred |

The proven architecture defect makes these buckets diagnostically plausible,
but does not prove that it caused any one historical event. The D3 ACL defect
and the ordinary-host Job/venv differential remain separate unless new evidence
directly relates them.

## Architecture options

### Option 1 — selected: immutable one-process JARVIS worker with constrained action payload

Keep one AppContainer/Job process and the `max_processes=1` invariant, but make
the protocol worker immutable JARVIS-owned code. Generated packages provide
bounded declarative action metadata and a capability-specific action payload
that is loaded only after protocol bootstrap through a narrow, fail-closed
boundary. The preferred payload form is data or a restricted operation model;
arbitrary generated Python must not be able to replace protocol functions,
stdout, frame validation, policy, or certifier state. Bootstrap returns a typed
package-load result before health/self-health is requested.

- Security: materially improves protocol ownership and preserves generated code
  as untrusted inside AppContainer; same-process arbitrary Python is not an
  acceptable final payload because it can monkey-patch globals, alter stdout,
  call `sys.exit`, or corrupt worker state.
- Reliability/diagnostics: separates native launch, protocol bootstrap,
  package load, dependency load, self-health, and action failure.
- Scope/risk: medium-to-high; generation schema, stored layout, worker,
  reviewer, certifier hooks, and focused tests change. Expected D6B model:
  GPT-5.6 Terra because this crosses multiple security-critical boundaries.
- Windows/process count: one child, one Job slot, no nested child requirement;
  fully compatible with current AppContainer and ACL lifecycle.
- Compatibility/performance: old arbitrary `source` packages require migration
  or quarantine; generic payloads remain cheap, with negligible transport
  overhead and lower diagnostic ambiguity.

### Option 2 — trusted protocol supervisor plus generated child

Use a stable JARVIS worker process that owns IPC and starts a separate generated
child. This gives the strongest same-host protocol separation and clear package
load boundaries, but it requires at least two processes or nested Job design.
It conflicts with the current strict one-process Job limit and would require a
new defensible Windows containment contract. It is rejected for D6B unless a
separate security review authorizes the process-limit change.

### Option 3 — retain the current generated complete entrypoint

Keep the current template and source override, relying on parent frame checks,
static review, hashes, AppContainer isolation, and later certification. This
has the smallest implementation cost and full current-package compatibility,
but it leaves generated code as protocol owner, coalesces package-load and
health failures, and cannot satisfy the intended trust-boundary contract. It is
rejected as the canonical future contract.

## Preferred canonical contract and stages

The selected contract is Option 1 with these invariants:

1. Model output and generated package bytes are untrusted data.
2. A stable JARVIS-owned worker owns protocol versioning, framing, request
   identity checks, trace policy, response serialization, and bounded shutdown.
3. Generated capability behavior is loaded only after worker bootstrap and only
   through a narrow constrained action boundary. It cannot supply or replace
   protocol code, certifier hooks, approval, lifecycle state, or broker access.
4. Native containment is independently observed by the parent; AppContainer
   does not make child statements trusted.
5. A self-health response is untrusted evidence paired with trusted transport
   evidence, never certification authority.
6. Every fresh process has its own package-load and self-health result; no
   cross-process memory continuity is assumed.
7. ACL/profile/Job cleanup must reach a verified terminal barrier before the
   next stage, and cleanup failure blocks certification.
8. Only trusted static review, test/oracle evidence, permission/authority
   decisions, broker attestations, independent verification, and the trusted
   certifier can produce `CERTIFIED` or promotion.

The clearer conceptual stages are:

`SANDBOX_CREATE` -> `ISOLATION_VERIFY` -> `PROTOCOL_BOOTSTRAP` ->
`PACKAGE_LOAD` -> `PACKAGE_SELF_HEALTH` -> `FUNCTIONAL_PROBE` ->
`STATIC_AUDIT`/`PERMISSION_DIFF`/`AUTHORITY_DECISION` -> `CERTIFICATION` ->
`SHADOW` -> `CANARY` -> `VERIFY` -> `PROMOTE`.

The exact ordering remains subject to the existing certifier's static and
functional gates, but each result must have a typed stage and package-bound
evidence. Health cannot stand for package load, functional correctness, or
security certification.

## Deterministic regression contract

D6B must add or adapt one deterministic fault for every boundary. The current
coverage map is:

| Fault | Existing D6A/current evidence | Coverage | Required D6B regression |
| --- | --- | --- | --- |
| native launch failure | `test_process_start_failure_and_malformed_response_are_contained` | PARTIAL | assert typed launch stage, exit/OS detail, cleanup |
| AppContainer isolation failure | `test_appcontainer_unavailable_fails_closed`, executable-isolation cert tests | COVERED | preserve exact isolation stage binding |
| protocol bootstrap failure | malformed/early-EOF sandbox tests | PARTIAL | worker bootstrap result distinct from package load |
| generated parse/import failure | no dedicated production boundary test | MISSING | force syntax/import failure before request and assert PACKAGE_LOAD |
| dependency load failure | no dedicated typed test | MISSING | force missing dependency and preserve dependency cause |
| generated action exception | production functional/fake native tests | PARTIALLY_COVERED | assert ACTION_FAILURE distinct from self-health/load |
| valid unhealthy self-report | `test_d6a4_unhealthy_response_is_valid_but_not_healthy` | COVERED | retain as PACKAGE_SELF_HEALTH failure |
| malformed protocol response | D6A4 matrix and sandbox malformed-response tests | COVERED | retain protocol classification and fail closed |
| identity mismatch | `test_identity_spoof_oversized_response_and_crash_are_contained` | COVERED | retain request/integration identity checks |
| process exit | crash/EOF sandbox tests | COVERED | bind exit code and phase to typed stage |
| functional probe failure | package certification semantic-oracle tests | COVERED | retain independent oracle requirement |
| Shadow failure | activation failure/quarantine tests | COVERED | preserve original child-stage cause |
| Canary failure | canary bounds/verification tests | COVERED | retain trusted attestation and rollback |
| cleanup failure | sandbox cleanup lifecycle tests and D3 native contract | PARTIAL | deterministic ACL/profile cleanup fault blocks certification |

D6A4, D6A6, and D6A7 are observability/fidelity evidence, not substitutes
for these boundary regressions. D6A4's simplified trace fixture and D6A6's
synthetic diagnostic child are `WRONG_LAYER` for proving real generated package
bootstrap semantics. D6A7 correctly proves no current independent readiness
state, but it does not prove a stable protocol owner.

Randomized stress remains useful as a qualification and contamination detector
after deterministic boundary tests are complete. It is no longer the primary
diagnostic mechanism. Every production-relevant failure still resets a
qualifying sequential count to zero.

## Smallest D6B migration

Likely production modules are:

- `jarvis/production_capability.py`: remove arbitrary complete-entrypoint
  ownership, split worker/scaffold from action payload, and preserve package
  identity/source binding;
- a new or existing worker module/package used only by the sandbox child;
- `jarvis/package_reviewer.py`: review the new payload contract and reject
  protocol/scaffold substitution and forbidden top-level effects;
- `jarvis/sandbox.py`: expose typed bootstrap/load/self-health outcomes without
  weakening transport or cleanup;
- `jarvis/package_certification.py` and `jarvis/production_capability.py`:
  preserve typed causes and package-bound evidence through certification;
- focused tests under `tests/test_production_capability.py`,
  `tests/test_sandbox.py`, certification/activation tests, and a deterministic
  D6B fault matrix.

The migration must version the stored package format, quarantine or explicitly
recertify old complete-entrypoint packages, and preserve D3 native cleanup,
AppContainer policy, Job limit, broker authority, and final trusted
certification. No new cloud dependency or host authority is required.

## Security exclusions for this review

This review did not weaken AppContainer, change Job policy or process limits,
change ACL authority or timeout, alter certification verdict rules, change
trusted approval, grant generated packages authority, add a cloud dependency,
or expose secrets. No production repair, readiness state, retry, or transport
change was made.
