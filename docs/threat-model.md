# Phase 5 permission-boundary threat model

> This phase history remains useful background. The current cross-phase threat
> model and immutable v1 controls are authoritative in
> [`security-constitution.md`](security-constitution.md).

## Assets and security goals

JARVIS must protect user files, credentials, private sensor data, clipboard data,
applications, network destinations, and host availability. Untrusted model output
must never create, widen, remember, or approve authority. A tool may execute a
privileged action only after trusted code has validated its arguments, described
the exact action, evaluated policy, and (when required) matched a live trusted-user
approval to the same task, tool, permission, scope, and argument fingerprint.

## Capability inventory

Current implemented capability contracts are:

- calculator and local-time agent tools, which are non-privileged;
- an unavailable weather placeholder, which performs no network request;
- Ollama HTTP transport (`network.request`), selected by trusted composition code;
- on-demand microphone capture (`microphone.read`), started by a direct UI gesture;
- local speech synthesis/audio output, which is not an input or host-mutation
  permission in the Phase 5 taxonomy.
- controlled, opt-in computer tools for window discovery, catalogued application
  launch, focus, semantic text entry, explicit mouse fallback, screen capture,
  clipboard, scoped filesystem read, and catalogued terminal commands. They are
  not registered in the default runtime catalog.

The Ollama and microphone paths are provider/UI flows, not planner-selected tools.
They remain separately bounded by trusted configuration and an explicit user
gesture. If either becomes planner-selectable it must first be converted to a
brokered tool.

Planned or reserved privileged capabilities are filesystem write, camera capture,
application installation, arbitrary network requests, source-code modification,
persistent memory storage, and system power control. Computer input uses its own
`computer.input` permission. Each capability requires a granular permission;
there is no aggregate computer-access permission.

Developer-only subprocess use in `scripts/quality.py` is outside the running
assistant and is not an agent capability.

## Adversaries and abuse cases

The primary adversary is malicious or confused model output, including prompt
injection embedded in files, web content, tool output, or user text. It may name an
unknown permission or tool, forge an approval claim, alter arguments after a user
review, replay an approval, request an over-broad scope, use path traversal or a
link/junction escape, or disguise a destructive command as an ordinary action.

Other failures include buggy tools under-declaring permissions, stale or disabled
policy, races around cancellation/expiry, approval API misuse, secret leakage in
audit logs, and a developer accidentally calling a privileged implementation
without the broker.

Phase 6 additionally considers UI spoofing/incorrect-window targeting, raw input
used in place of semantic controls, application-ID or command-ID substitution,
shell interpretation, unbounded child processes, screenshots or clipboard data
leaking through results, and filesystem paths escaping approved roots after policy
evaluation.

Phase 7 adds adversarial visual content, provider hallucination, accessibility/vision
disagreement, stale screenshots, race conditions between observation and input,
window switching, coordinate/DPI confusion, and visual recognition of sensitive
controls. A model or provider may describe a button but must not turn that description
into authority or a verified outcome.

Phase 9 adds package-search poisoning, package/source substitution, stale or replayed
install plans, malicious registry/display-icon entries, version downgrade, a package
manager interpreting a shell string, verification that trusts package-manager output,
and closing an arbitrary user process. Package catalog and inventory data are treated
as evidence: only trusted composition chooses providers, only immutable plans can
reach a provider, and post-operation success comes from an independent re-query.

Phase 10 adds search-result poisoning, prompt injection in READMEs/package pages/API
documentation, provenance spoofing, malicious package/plugin identity, biased ranking,
and a discovery result being mistaken for an approved capability. Discovery sources are
evidence only. External text is never interpreted as a command, policy, instruction,
approval, package operation, or dynamic source module; it is retained only as a digest
and untrusted evidence label.

## Trust boundaries

1. Model/planner output to strict plan and tool-input schemas: entirely untrusted.
2. Registered tool metadata and action descriptors: trusted application code,
   reviewed with the tool implementation.
3. Tool to `PermissionBroker`: mandatory runtime authorization boundary.
4. Policy configuration and normalized scope roots: trusted operator input.
5. Approval presentation and decision: trusted application UI/API plus an
   authenticated human identity; model/tool identities are rejected.
6. Broker to host/provider implementation: only an exact, short-lived
   authorization receipt may cross this boundary.
7. Audit sink: trusted append-only destination receiving fingerprints and safe
   summaries, never raw arguments or secrets.
8. Platform-neutral adapter to Windows UI Automation/Win32/subprocess APIs: only
   the authorized private tool hook may call this boundary. Windows adapter output
   is evidence, not an authorization decision.
9. Vision provider output to trusted semantic-first fusion: untrusted structured
   suggestions; it cannot directly access input adapters, the broker, or approvals.
10. Application inventory/package provider to manager: provider results are
    untrusted evidence, normalized and verified by trusted manager code. The target
    contract requires a pinned executable plus validated argument array; the current
    `winget` adapter is disabled because its executable identity/PATH boundary is not
    yet pinned.
11. Manager to process/package runtime: only a broker-authorized, immutable plan or
    freshly resolved inventory record crosses this boundary; executable strings,
    repository names, and package IDs cannot be supplied as raw OS commands.
12. Discovery providers to recommendation service: catalogs and research data are
    untrusted candidate evidence. Trusted service code validates candidate shape,
    retains provenance, scores explicit factors, and emits advisory output only.

Python does not provide an in-process security sandbox. Generated integration
code is therefore kept out of Trusted Core and uses `SandboxProcess`, which
provides typed bounded IPC and Windows Job Object process-tree ownership. A Job
Object is not a filesystem, network, token, or AppContainer boundary: a child
with the same user identity may still access user-readable paths and OS APIs.
The registry therefore prohibits dynamic discovery, and privileged implementation
methods are deliberately private and reachable only through the brokered tool
entry point by convention and tests.

## Fail-closed invariants

- Unknown/malformed permissions, unknown tools/actions, malformed scopes, missing
  or disabled policies, and invalid action descriptors deny with machine-readable
  reasons.
- Approval data is built from trusted descriptors, never free-form model prose.
- Approval matching includes task, tool, action, permission, normalized scope, and
  a canonical full-argument fingerprint.
- One-time approvals are atomically consumed once and cannot authorize changed
  arguments. Cancellation and expiry win over execution.
- Limited remembered grants have explicit scope and expiry and cannot cover hard
  safety actions. There is no global or unbounded remember option.
- Bulk deletion and destructive system commands require a fresh trusted approval;
  privilege escalation is denied by hard policy.
- Filesystem scope accepts only absolute, canonical paths beneath trusted roots and
  rejects traversal plus symlink/junction escape.
- Audit records contain decision provenance and execution outcome without raw
  arguments, approval tokens, credentials, or file contents.
- Application and terminal command IDs resolve only through trusted catalogues;
  executable paths and shell strings are never model-controlled.
- Terminal execution uses an argument vector with `shell=False`, explicit working
  directory and timeout, and kills the child process on timeout or cancellation.
- Screenshot bytes remain in a trusted artifact store. The model receives an opaque
  reference and metadata, not an adapter-private binary payload.
- Visual actions name a current trusted-fusion target ID. The interaction service
  re-observes and rejects changed display/window/target/fingerprint state before it
  invokes an action tool, then verifies with a new observation.
- A visual finding never grants a permission. Sensitive input still receives the
  original tool's policy, approval, audit, cancellation, and hard-safety controls.
- Application discovery never launches or installs. Installation and update tools
  are opt-in only, require `application.install`, and use the hard
  `software_installation` class: fresh trusted approval is mandatory and may not be
  remembered. Approval summaries contain exact package identity/source/publisher/
  version from an immutable expiring plan, not model text.
- Package-manager invocation uses an independently validated argument vector
  (`shell=False`); no model string becomes a command. Production activation also
  requires a pinned package-manager executable identity rather than PATH lookup. An update must
  be strictly newer than the installed normalized numeric version. Verification
  re-queries inventory and checks expected name/publisher/version plus launch
  capability. The managed runtime closes only its own tracked launch process.
- Discovery does not authorize a capability. Recommendations do not register tools,
  alter policy, install a package/plugin, create credentials, call an API, or execute
  generated code. Any later implementation must independently pass normal tool,
  broker, policy, approval, provider, and test review.

## Phase 11 autonomous-improvement extension

### Privileged capability inventory

Phase 11 implements trusted repository inspection and scoped source modification in
an isolated worktree, but exposes neither operation as a model-selectable tool. Its
initial proposal-only mode does not merge, install dependencies, push to a remote,
restart a service, or deploy. If planner access is introduced later, repository
inspection requires scoped `filesystem.read`; candidate writes require scoped
`filesystem.write` and `code.modify`; trusted Git operations require a catalogued
`terminal.execute` command family. Any future dependency installation, remote
network operation, production write, merge, deployment, restart, or system mutation
is a separate privileged capability and receives its own policy and trusted approval.

### Additional adversaries and abuse cases

Self-improvement adds self-authorization, generated code modifying the running
checkout, forged or escaped worktree paths, symlink/junction races, Git hook/config
side effects, baseline or gate tampering, generated tests concealing a regression,
security-check evasion, proposal replay or mutation, dependency insertion,
secret/network access from tests, resource exhaustion, and prompt injection in issue
or telemetry evidence. A coding model may also attempt to alter workflows, quality
gates, the broker, or the improvement engine itself so a later unsafe change appears
valid.

### Additional trust boundaries

13. Observation sources to candidate generation: logs, issue text, web content,
    package metadata, and tool output are evidence, never coding instructions. Raw
    external text is reduced to a digest and fixed untrusted label before the coding
    boundary.
14. Improvement reasoning to coding agent: trusted application code supplies a
    concrete bounded specification and structured safe evidence. The coding agent
    returns untrusted typed file-change data and receives no filesystem, command,
    Git, approval, or deployment capability.
15. Coding output to isolated workspace: the trusted change applier validates
    workspace ownership, specification/path boundaries, canonical containment, link
    safety, and exact base digests before writing.
16. Worktree/gate boundary to host: trusted Git creates a generated detached
    worktree; independently confined gate processes must attest that production,
    shared Git metadata, network, secrets, and source mutation are unavailable.
17. Evaluation to proposal: independently protected baseline metrics and every
    mandatory gate must pass before a fingerprinted, expiring proposal is stored.
18. Proposal to future merge/deployment: outside Phase 11. Only a separately
    authenticated trusted user and brokered execution service may cross it after
    revalidating the exact proposal; model/tool approval claims are untrusted.

### Additional fail-closed invariants

- Improvement observation and prioritization do not authorize source modification.
  The normal outcome may be `NO_WORTHWHILE_IMPROVEMENT`, and risk classification may
  raise but never lower a candidate's declared risk.
- The coding agent can return only bounded typed text changes. Trusted code generates
  workspace paths and revisions, rejects changes outside the specification, forbids
  `.git`, workflow, and quality-gate control paths, checks existing-file digests, and
  never writes the production checkout.
- Production and workspace roots must be disjoint canonical directories. Production
  must be clean at a full immutable revision and remain unchanged throughout the run;
  a forged handle, reparse escape, identity change, or integrity failure quarantines
  the candidate.
- Dependency manifest changes deny unless an exact path/base-digest/candidate-digest
  transition has trusted risk and reversibility analysis. Eligibility never grants
  installation, download, merge, or deployment authority.
- A proposal contains every mandatory passing gate exactly once, an independently
  improved protected baseline comparison, exact change/tree evidence, expiry, and
  the previous known-good revision. The engine can create only
  `AWAITING_TRUSTED_APPROVAL` and has no approval, merge, push, or deploy method.
- Real process confinement is an external trusted boundary, not a Python type. A gate
  without complete workspace-only/network-disabled/secrets-removed/process-tree
  attestation fails. Fake CI adapters demonstrate control flow, not OS isolation.

### Residual security assumptions

Python does not isolate mutually untrusted in-process adapters. Application
composition, the Git client, change applier, gate definitions, concrete OS sandbox,
security scanners, metric provider, proposal store, and any future approval/merge
service remain in the trusted computing base. A malicious imported Python module can
bypass these interfaces; dynamic loading remains prohibited.

Git worktrees share repository object metadata. Trusted worktree creation necessarily
touches that metadata, while coding and gate processes must not receive access to it.
`SandboxProcess` enforces bounded IPC, timeout/cancellation, process-tree cleanup,
and Windows active-process/per-process-memory Job Object controls. It does not yet
enforce disk, network, handle, token, or filesystem ACL isolation; deterministic
tests cannot prove those missing Windows/container controls. The built-in static checker is only
a minimum preflight and does not replace deeper scanning or human review. See the
explicit threat/control/residual-risk table in `docs/autonomous-improvement.md`.

## Phase 14 memory extension

Durable memory introduces private user facts, task evidence, SQLite files, migration
integrity, and retention/deletion controls as protected assets. Model output,
conversation text, web/tool output, remembered data, and source references are data
only; they cannot grant a permission, become an approval, register a tool, or issue
an instruction. A trusted long-term policy requires explicit user confirmation,
user-source provenance, confidence, and non-secret/non-untrusted content. The store
defensively rejects secret-like values even if a caller bypasses that policy.

The persistence boundary is trusted application/UI code to `SQLiteMemoryStore`; a
future multi-user API must add authenticated ownership checks before exposing the
inspect/delete operations. The project-knowledge boundary remains read-only through
`KnowledgeStore`, so generated repository documentation is not copied into personal
memory. Local SQLite encryption, device-level access control, and a platform secret
store are deployment responsibilities outside this Phase 14 library; the subsystem
therefore rejects rather than stores credentials.

## Phase 15 planning extension

The goal, proposed steps, arguments, dependencies, claimed permissions, tool output,
failure evidence, and replan are untrusted. A malicious planner may name a privileged
tool without its permissions, forge approval text, create a cycle, exhaust resources,
change original constraints during replan, reuse stale evidence, or rely on a crash to
repeat an action. A corrupt local planning snapshot may also claim impossible status
or omit graph state.

The live registry/manifests/schemas, validator, engine, permission broker, persistence
migrations, clock, and verification adapters form the trusted boundary. A proposal is
accepted only when tools and capabilities resolve, declared permissions exactly match
the tool manifest, arguments validate, dependencies form a bounded DAG, and rules are
host-owned. No plan field is authority. Every privileged call still enters the broker;
a persisted request ID or model assertion cannot approve it.

State and usage are saved before observable boundaries. Permission waits retain the
whole graph and resume through the broker. Retry/model/step/time/expensive-action
budgets are independent and fail closed. Replans are bound to actual failure evidence
and must preserve the original task contract. Completion requires independent
goal-level evidence. Unknown post-crash running/verifying state fails rather than
silently replaying a potentially irreversible action.

Residual assumptions are that trusted composition supplies honest clocks, verifiers,
brokers, tool manifests, and a protected single-user SQLite path. SQLite is not an
authentication boundary or distributed scheduler. The native sandbox is not yet a
complete same-user filesystem/network isolation boundary, and production must not
activate hostile code on that assumption. Tool-specific cross-process idempotency and distributed
execution leases are not claimed in Phase 15.

## Phase 16 multi-agent extension

Delegation adds malicious graph decomposition, recursive spawning, privilege
laundering between agents, excessive fan-out, context oversharing, forged resource
usage, agent-result prompt injection, deadlock, cancellation loss, and duplicate or
partial side effects. The proposal, node inputs, claimed scopes, agent output, and
referenced evidence are untrusted. One agent asking another to perform an action is
not approval and cannot transfer authority.

The coordinator, registry/contracts, graph validator, scheduler, clocks, provider
usage adapters, and single-agent fallback form the trusted boundary. Only the
coordinator creates nodes. Workers have no recursive delegation API. Every child
scope is intersected by validation with the parent and exact worker contract before
launch; privileged capability adapters must still use the existing registered tool
and Permission Broker. Context crosses only through bounded selected keys and evidence
references. Contract snapshots prevent post-validation schema/scope replacement.
Reservations, concurrency, timeouts, cancellation, and aggregate goal verification
are host-owned.

Unknown/cyclic/malformed/escalating graphs deny. Unavailable agents and graphs without
a proven independent-specialist advantage fall back before delegated execution.
Runtime failure returns typed failed/partial evidence and blocks dependants rather
than silently retrying or assuming success. Residual risk remains that same-process
Python workers are trusted code, resource usage relies on provider-side accounting,
and this phase has no durable/distributed multi-agent lease or crash recovery.
