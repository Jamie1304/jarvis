# ADR 0014: separate memory domains and policy-gated persistence

## Decision

Use four conceptually distinct memory paths: bounded process-local conversation
context, policy-gated durable user memory, compact durable action episodes, and a
read-only adapter to the Phase 12 project-knowledge index. Use SQLite with reviewed,
ordered migrations for the two durable categories. Do not introduce a vector database
or make memory a planner-controlled capability.

## Consequences

The application gains inspect/delete/retention-cleanup controls and provenance for
durable records without silently retaining every utterance or duplicating project
knowledge. Retrieval keeps source/type results separate. The local SQLite adapter is
not a user-identity or secret-management system: future multi-user UI/API composition
must enforce ownership, and credentials require a dedicated secret store. Historical
web/tool content is retained only as labelled untrusted data.
