# Verification and proven outcomes

Execution and outcome verification are separate contracts.

`PlanningEngine` remains the authority for task and plan lifecycle. A tool
result, process return code, or model response describes execution; it does
not by itself prove that the requested real-world result exists. The native
`jarvis.verification` boundary evaluates immutable `EvidenceRecord` values and
returns a `VerificationResult`. It never executes, authorizes, or replans.

## Levels

Verification strength is ordered as:

`UNKNOWN` → `IMPLEMENTED` → `AUTOMATED_TESTED` → `INTEGRATION_VERIFIED` →
`USER_VERIFIED` → `OPERATIONALLY_PROVEN`.

The required level and completion criteria belong to the trusted,
application-owned `VerificationPlan`. A result cannot exceed its supplied
evidence. In particular, “done” from a model is retained only as a rejected
claim and is never an `EvidenceRecord`.

## Evidence

Evidence is typed as `API`, `FILE`, `PROCESS`, `SCREEN`, `NETWORK`, `SENSOR`,
`USER`, `MULTI_SOURCE`, or `CUSTOM`. Every record carries its source, capture
time, bounded freshness, confidence, expected value, observed value, and an
explicit contradiction flag. Stale, low-confidence, disallowed, model-only,
or contradictory records cannot silently complete a plan.

`PresentationSurface.query_state()` is a valid `SCREEN` observation source.
The verifier compares the actual queried `UiStateSnapshot` with the intended
snapshot; it does not treat the last presentation request as proof.

## Failure and physical confirmation

When evidence conflicts with the goal, the result preserves the original goal,
records the contradiction, and returns `REPLAN` with a diagnosis. Planning code
may then diagnose or construct a new validated plan; the verification service
does not mutate the plan.

When a physical result cannot be independently observed, the result remains
`UNKNOWN` and returns `ASK_USER` with a bounded confirmation prompt. A strict
affirmative user response is explicit evidence; a user “no” is negative
evidence and requires diagnosis/replanning. Conditional or ambiguous language
does not become approval or verification.

Evidence is observation data, not permission, identity, policy, or audit
authority. Durable task outcome remains owned by `PlanningEngine`; any future
durable evidence store must be added to `docs/authoritative-state-map.md`
before implementation.

## Installation-specific regressions

`GoldenWorkflowStore` owns versioned privacy-safe regression definitions and run
evidence. `GoldenWorkflowService` passes trusted executor observations through
this same `VerificationEngine`; exact response text or a model completion claim
cannot pass a golden workflow. Synthetic fixtures are preferred, real trace data
is sanitized and generalized, and failed or `UNKNOWN_OUTCOME` traces cannot
create a golden definition. Before model changes, integration updates,
self-improvement, or self-update activation, the owning change service must run
all applicable active golden workflows. Missing coverage and unavailable
integration/hardware checks are not passes.
