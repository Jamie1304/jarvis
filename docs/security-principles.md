# Security principles

- Security-sensitive defaults are deny-by-default.
- AI/provider code cannot directly invoke privileged operating-system APIs.
- Privileged operations must be explicit tools mediated by a permission broker.
- Secrets belong in environment variables or an approved local secret store, never source control.
- External services must be hidden behind provider interfaces so the core remains local-first and testable.
- Logs must not contain secrets or sensitive payloads by default.
- Every future autonomous or long-running action requires an auditable task ID, cancellation path, and clear authorization boundary.
- Microphone audio is transient by default: it is held in memory only until local transcription completes and is never written to disk by Phase 1.
- Planning/model output is untrusted. It is schema-validated before becoming a typed plan and cannot change task state, budgets, permissions, or capability availability.
- Tool observations are not proof of success. Independent verification requires explicit evidence before a task can complete.
- Phase 2 registers no operating-system, filesystem, shell, computer-control, camera, or network-action tools. Future capabilities must be explicitly registered and mediated by permissions.
- Tool arguments are untrusted model output. The tool boundary rejects unknown fields and invalid types before a tool implementation executes.
- Tools receive only explicit execution context, not the application container. Unexpected implementation exceptions are logged and mapped to structured failures.

Phase 3 retains the deny-by-default boundary: only registered, non-privileged capabilities are available, and calculator/local-time declare no permissions.

Phase 5 enforces the boundary. Tool callers cannot pass grants or approval claims.
The registry binds trusted manifest permissions to an exact tool instance, and the
base tool entry point always consults that registry's `PermissionBroker` after
strict argument validation. Policy recognizes granular dotted permissions only;
unknown tools/permissions, malformed or escaping scopes, missing rules, and
disabled rules deny. Approval requests and safe summaries come from trusted tool
descriptors, while exact canonical argument fingerprints prevent mutation/replay.
One-time approvals are consumed atomically. Remembered grants are scope- and
time-limited and unavailable to hard-safety actions. Privilege escalation always
denies; bulk deletion and destructive system commands always require a fresh human
approval. Audit records contain fingerprints and normalized scope, never raw
arguments or secrets.

Phase 6 extends the same invariants to Windows interaction. Semantic actions are
brokered tools backed by a platform-neutral adapter; the model never receives a
Windows automation object or unrestricted OS primitive. Keyboard/control input and
the coordinate fallback require `computer.input`; capture, clipboard, filesystem,
launch, and terminal operations require their separate permissions. A trusted
catalogue resolves application IDs and command IDs. Terminal execution uses an
executable and argument array with `shell=False`, while filesystem execution uses
the broker-normalized in-scope path only. Optional real desktop integration is not
evidence of execution in CI; adapters must return structured evidence only after
they actually perform an action.

Phase 7 treats screenshots, accessibility snapshots, and vision-provider output as
evidence rather than authority. The required visual loop re-observes before input,
checks a trusted current-state fingerprint and DPI-aware geometry, and verifies with
a new observation afterward. A visual target cannot bypass the permission broker:
the mapped computer action still needs its own declared permission, policy decision,
approval where applicable, audit record, and cancellation handling. Low confidence or
missing semantic evidence is `UNCERTAIN`, never success.

Phase 8 keeps camera activation behind `camera.read` and a trusted device catalogue.
The controller exposes camera state to the application, opens only for a bounded
one-shot capture, and closes in all success, failure, timeout, cancellation, and
shutdown paths. Camera frames are ephemeral by default and are never written to disk.
Vision receives only a short-lived reference through the provider abstraction; a
camera image cannot grant input, messaging, or any other permission.

Phase 9 treats application inventory and package catalogs as untrusted evidence, not
execution authority. Package operations occur only from an immutable expiring plan
created by trusted manager code, passed through the broker with the exact package and
source in a fresh trusted-user approval, and then consumed. `software_installation`
cannot receive a remembered grant or automatic allow. Providers construct a fixed
executable plus validated argument array with no shell interpretation. Post-install
success requires an independent inventory re-query, identity/version/executable
checks, and launch-capability evidence; package-manager text is not proof. Generic
application configuration is forbidden: only reviewed per-application adapters may
be registered. Managed close operations apply only to runtime-owned process IDs.

Phase 10 makes capability discovery advisory-only. Catalog entries, package metadata,
documentation, search results, and web pages are untrusted data, including text that
claims to override policy or asks JARVIS to execute a command. The discovery layer
preserves source reference, safe summary, and a digest for external content, but never
forwards raw external instructions as an action. Scoring is explainable and cannot
grant permissions, register a tool, install software, create configuration, or execute
a candidate. Recommendations always end at a user/policy decision.

Phase 11 is proposal-and-test only. Improvement signals and external issue content
are evidence, not coding instructions; raw external content is replaced by a digest
and fixed label before the coding-agent boundary. Trusted code specifies path and
behavior boundaries before generation. The coding agent returns typed text changes
and receives no filesystem, Git, command, approval, merge, or deployment primitive.
Only a generated detached worktree outside the clean production checkout may be
modified, and production identity and cleanliness are rechecked throughout the run.

Every candidate defaults to dependency-manifest denial and must pass formatting/lint,
type, unit, integration, security, protected regression, and startup/health gates in
an independently confined environment. A complete sandbox attestation, not a zero
exit code alone, is required. Passing generated tests is insufficient: protected
metrics must improve over a pre-change baseline bound to the candidate and immutable
base revision. Success emits only an expiring fingerprinted proposal with rollback
metadata and `AWAITING_TRUSTED_APPROVAL`; the engine cannot approve, merge, push,
install, deploy, or modify the running copy.

Phase 15 treats plans as untrusted structured proposals, never execution authority.
Trusted validation resolves every node against the live registry and requires exact
tool capability, manifest permission, argument-schema, bounded-DAG, and verification-
rule agreement. A permission name or approval claim in model output has no effect:
the exact tool action always re-enters `PermissionBroker`, including after a durable
pause and resume. The deterministic engine owns lifecycle, budgets, cancellation,
bounded retry, and evidence-bound replan while preserving the original constraints.
No task completes merely because its tools returned success; trusted step and goal
verification must both accept observed evidence. Ambiguous post-crash action state,
unknown tools or permissions, malformed snapshots, cycles, and exhausted budgets fail
closed.

Phase 16 does not turn delegation into authority. Multi-agent mode is off by default,
and deterministic policy uses it only for independent work across distinct registered
specialisms. The coordinator validates every child tool/capability/permission scope as
a subset of both the parent request and exact worker contract. Those declarations are
not grants; computer and other privileged actions still enter their registered tool
and `PermissionBroker`. Workers receive no spawn, approval, registry, application-
container, or global-conversation handle. Concurrency, node/global timeout,
cancellation, and model/token/cost reservations are bounded. Malformed graphs, cycles,
scope escalation, and budget overflow fail closed; unavailable agents fall back before
any delegated action starts. Contract mutation after validation is rejected, and node
success cannot bypass trusted aggregate goal-evidence verification.
