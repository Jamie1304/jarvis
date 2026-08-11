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
