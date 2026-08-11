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
