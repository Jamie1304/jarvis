# Verified Procedure Learning

JARVIS may bank a reusable method only after evidence-based repetition:

```text
expensive/agentic attempt
  -> independently verified success
  -> repeated similar verified success
  -> RoutineCandidate
  -> ProcedureCandidate (Skill, WorkflowTemplate, or deterministic helper)
  -> ordinary validation
  -> explicit activation
```

`ProcedureBank` is a proposal bank, not an execution engine, scheduler, or
permission store. In production it is composed with the runtime-owned
`SQLiteWorkflowProcedureStore` (`workflow-procedures.sqlite3`). The store
durably owns sanitized trusted observations, `ProcedureCandidate` lifecycle,
accepted Skill/WorkflowTemplate linkage, and user enable/disable/retire state.
It refuses future schemas and preserves candidate history without persisting
exact input values.

An observation is eligible only when a trusted `ProcedureEvidenceAuthority`
issues a proof bound to a completed durable Task/Plan step, a passing
`VerificationEngine` result at an adequate level, a confirmed effect outcome,
and durable Trace event IDs. `verified`, `outcome`, and `trusted_source` fields
are compatibility metadata only; caller/model values cannot authorize learning.
The bank ignores missing/invalid evidence, unverified outcomes, one-off
successes below the configured repetition threshold, `UNKNOWN_OUTCOME`, and
untrusted external instructions. Candidate activation requires a normal
application validator and explicit acceptance/linkage.

Candidates retain generalized parameter shapes and safe provenance labels, not
exact personal values, secret-bearing histories, credentials, or approval
objects. Personal and secret fields are removed before a candidate is formed.
Permission expectations remain metadata: future execution must request fresh
authorization through `Tool -> PermissionBroker -> Policy`, even when a
candidate is validated or preferred.

The bank is deliberately conservative. It can reduce repeated discovery and
model cost by offering a tested method, but it cannot declare success, widen
scope, activate code, or turn model output into trusted policy. Accepted
learned procedures preserve no approval, credential, or trusted identity;
future execution always requests fresh authority and resolves current scoped
context. Context requirements are generalized retrieval hints, never stored
retrieved secrets or private histories.
