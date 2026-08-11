# ADR 0015: deterministic ownership of durable task plans

## Decision

Treat model-generated plans as untrusted proposals. Validate them into versioned,
application-owned DAGs using the live tool registry, manifests, permission enum, and
input schemas. Persist task and plan state atomically in SQLite. Execute one ready
step at a time through the exact broker-bound tool, require step and goal verification,
and fail closed for ambiguous restart state. Replanning must retain the original goal,
assumptions, and constraints and consume observed failure evidence.

## Consequences

Long-running work can pause for permission and survive restart without allowing a
model or snapshot to grant authority. Cycles, unknown capabilities, malformed inputs,
unbounded retries, and successful steps without goal evidence cannot complete a task.
The initial implementation deliberately excludes multi-agent and parallel execution.
SQLite access control, distributed leases, and tool-specific recovery from an unknown
external outcome remain deployment or future design concerns.
