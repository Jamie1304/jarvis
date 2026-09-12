# ADR 0016: optional bounded multi-agent orchestration

## Decision

Keep Phase 15 single-agent planning as the default. Add a separate feature-gated
coordinator that accepts only strict delegation proposals, validates nodes against
registered agent contracts and parent privilege/context/resource scopes, and runs
genuinely independent specialist nodes concurrently. Application code is the sole
delegation authority; workers receive typed requests/results, immutable profile/model
policy, narrowed host/data scopes, and no spawn interface.

## Consequences

Independent specialist work can reduce critical-path latency without making every
task multi-agent. Sequential, one-node, disabled, unknown-agent, and unavailable-agent
cases retain the single-agent path. Scope cannot grow through delegation, and
privileged actions still require their ordinary tool and Permission Broker boundary.
The initial design intentionally excludes recursive spawning, agent free-chat,
distributed execution, and durable multi-agent recovery. Specialist profiles and
model policies are ceilings rather than authority; raw secrets are never delegated,
and lexical host scopes still require trusted adapter enforcement for reparse/TOCTOU
limits.
