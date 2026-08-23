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
permission store. It ignores unverified outcomes, one-off successes below the
configured repetition threshold, `UNKNOWN_OUTCOME`, and untrusted external
instructions. Candidate activation requires a normal application validator.

Candidates retain generalized parameter shapes and safe provenance labels, not
exact personal values, secret-bearing histories, credentials, or approval
objects. Personal and secret fields are removed before a candidate is formed.
Permission expectations remain metadata: future execution must request fresh
authorization through `Tool -> PermissionBroker -> Policy`, even when a
candidate is validated or preferred.

The bank is deliberately conservative. It can reduce repeated discovery and
model cost by offering a tested method, but it cannot declare success, widen
scope, activate code, or turn model output into trusted policy. A future
durable learned-method store must be added to the authoritative-state map
before persistence is introduced.
