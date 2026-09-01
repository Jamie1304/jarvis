# ADR 0011: advisory capability discovery

## Decision

Represent unmet requests as typed capability gaps and use provider-neutral discovery
to produce explainable, provenance-preserving recommendations only. Isolate external
research text as untrusted digest evidence. Do not dynamically load plugins, generate
or execute source, install software, or alter authorization from discovery output.

## Rationale

Search metadata and documentation are vulnerable to prompt injection and cannot be
trusted as a control plane. Separating evidence, ranking, and later human/policy choice
keeps discovery useful without allowing a candidate to become an executable capability.

## Consequences

Discovery is safe to run with static/mock providers in CI. Real web research must be
separately authorized before it enters the evidence adapter. Every recommended future
tool remains subject to normal implementation, permission, policy, approval, and
provider review.
