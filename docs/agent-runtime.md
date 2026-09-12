# Native bounded Agent Runtime

`jarvis.agent_runtime.AgentLoop` is a bounded inference segment, not a task
authority. The composition root owns one instance and `PlanningEngine` remains
the durable owner of task, plan, step, budget, retry, and recovery state.

The intended application boundary is:

```text
PlanningEngine
  -> explicit AGENTIC planning step
  -> AgentLoop
  -> provider inference
  -> strict structured request validation
  -> ToolRegistry -> PermissionBroker -> Policy
  -> structured tool result
  -> next inference
  -> proposed result (never trusted success)
```

The current durable plan schema accepts only registry-bound tools. `AgentLoop`
is therefore exposed as a native composition-root service and an
`AgenticPlanningStepExecutor` adapter seam; introducing an `AGENTIC` step into
durable plans requires a separate schema/validation contract. No pseudo-tool,
donor runtime, dynamic registry registration, or model-directed authority is
used.

## Contracts and bounds

The runtime defines typed `AgentMessage`, `AgentTurn`, `AgentEffect`,
`AgentLoopBudget`, `AgentUsage`, `AgentTerminationReason`, `AgentLoopResult`,
and `AgentOperation` records. Operations are explicitly classified as context
preparation, inference, unknown tool, approval pause, tool execution, retry,
and finalization.

Every model response must be bounded JSON describing either a final proposed
response or one/more tool calls. Tool IDs, UUID request IDs, argument objects,
unknown fields, and tool input schemas are validated before invocation. Every
effect is sent through the existing `ToolRegistry` and broker boundary. A model
response cannot self-certify external success; the result is only a proposed
result for the owning planner/application verifier.

The loop bounds turns, tool calls, approximate generated tokens, expensive
brokered actions, retries, wall time, and cancellation. Permission pauses return
request IDs to the planner without fabricating approval. Unknown or externally
uncertain effects terminate safely and remain subject to PlanningEngine
recovery rules.

## Context and recovery

`AgentContext` carries the request, goal, constraints, current step, relevant
conversation, selected memory, required knowledge, evidence, tool outputs, and
the immutable security-context projection. Each context records its token
estimate, provider limit, reserved output, priority, and provenance. The
`ContextManager` preserves goal, constraints, permission/security facts,
unresolved effects, evidence, and completion criteria while compacting old
tool exchanges into a digest for the model-facing projection. Durable evidence
is never discarded by compaction.

Provider context errors receive at most one bounded reactive recovery. A
`LoopGuard` detects repeated canonical calls, equivalent failures, and
no-progress responses despite superficial textual changes. It terminates the
segment rather than allowing unbounded repetition. `AgentRetryClass` separates
provider transient/rate-limit, malformed response, deterministic tool failure,
safe transient, cancellation, and unknown-outcome cases. `UNKNOWN_OUTCOME` is
never classified as safe to retry or replay.

The context manager has explicit slots for future Skill and Workflow
requirements; those are data requirements only and cannot grant authority.

No Goose, Agent Zero, fullstack-agent, Backtalk, ai-visualizer,
ai-memory-vault, or barehands runtime dependency is used.
