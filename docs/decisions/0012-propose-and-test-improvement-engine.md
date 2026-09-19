# ADR 0012: proposal-and-test autonomous improvement

## Decision

Introduce a provider-neutral improvement engine that can identify and prioritize a
candidate, specify it, apply typed text changes in a trusted detached Git worktree,
run independently confined mandatory gates, compare protected baseline metrics, and
emit an expiring merge/deployment proposal. The only Phase 11 mode is
`PROPOSE_AND_TEST`, and every new proposal is `AWAITING_TRUSTED_APPROVAL`.

Keep improvement reasoning, coding output, trusted file application, gate execution,
security checking, evaluation, and proposal storage behind separate interfaces. Do
not give the coding agent filesystem, command, approval, policy, Git, merge, or
deployment primitives. Reject unapproved dependency-manifest changes and isolate
raw external content as untrusted digest evidence.

All proposed changes also pass the application-owned modification trust classifier.
It derives one Level 1-5 classification from the complete path set and uses the
highest level for mixed patches. Level 4 PermissionBroker/Vault/security changes
and Level 5 updater/recovery/root-of-trust changes are not agent-editable; changing
the classifier or splitting a protected patch cannot lower the requirement.

## Rationale

Self-modification concentrates code-execution, supply-chain, prompt-injection, and
authorization risks. Tests produced alongside a change can be incomplete or
manipulated, and a worktree is useful isolation but not an operating-system sandbox.
A typed proposal with immutable evidence permits controlled experimentation while a
separate trusted user retains the authority to approve any later repository or
deployment mutation.

## Consequences

No worthwhile candidate, any missing/failed gate, a regression, an integrity change,
or an unapproved dependency is a normal fail-closed outcome. Production stays at the
known-good revision; successful candidate worktrees are retained only for review and
failed ones are quarantined. Phase 11 cannot merge, deploy, push, install, or approve
its own result. A future execution service must revalidate the proposal fingerprint
and expiry, obtain brokered permissions and trusted approval, and preserve the base
revision as rollback metadata.

Deterministic CI uses fake Git, sandbox, coding-agent, metric, and proposal adapters.
Those tests demonstrate orchestration and failure behavior, not real OS sandboxing,
real coding-model quality, Windows worktree security, or deployment safety; each
production adapter requires separate integration and security validation.
