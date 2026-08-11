# ADR 0003: Bounded single-agent orchestration

## Decision

Represent user work as typed `Task` and `Plan` records. Use an `AgentOrchestrator` that owns all lifecycle transitions and delegates interpretation, strict plan validation, capability selection, execution, observation, verification, and final response generation. Persist through an async `TaskStore` interface, initially in memory.

## Rationale

The core can be tested with deterministic fakes without an LLM or privileged tools. Strict validation prevents arbitrary model payloads from becoming executable instructions, while the registry and evidence verifier preserve application control over capability availability and task completion. Bounded steps, timeout, replans, and cancellation prevent uncontrolled execution.
