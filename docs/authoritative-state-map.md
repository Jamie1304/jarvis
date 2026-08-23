# JARVIS authoritative state map

**Status:** v1 baseline  
**Updated:** 2026-08-23

This document defines the ownership rule for durable truth:

> Every durable domain has exactly one authoritative store and owner. Derived
> projections, caches, events, indexes, and UI models may exist, but they may
> not decide or overwrite the domain's truth.

Future runs must update this map before introducing a new durable domain, store,
migration, recovery rule, or competing projection.

## Current ownership map

| Domain | Authoritative owner/store | Derived or secondary data | Current status and boundary |
|---|---|---|---|
| Task, plan, step, budget, retry, operation reservation | `PlanningEngine` over `SQLitePlanningStore` (`planning.sqlite3`) | `ApplicationStateMachine`, lifecycle audit, typed events, `TaskController` result views | IMPLEMENTED_AND_WIRED. Planning records are the only task-control truth. Writes of task/plan versions are atomic. |
| Application/task lifecycle projection | `ApplicationStateMachine` over `SQLiteStateStore` (`state.sqlite3`) | UI state, transition/event consumers | IMPLEMENTED_AND_WIRED as a rebuildable projection. It must not decide planning completion or authorization. |
| Permission policy | `PolicyEngine` and trusted broker composition | Policy evaluations and permission events | IMPLEMENTED_AND_WIRED. Policy rules are code/configuration authority; model text and events cannot modify them. |
| Approval request, receipt, remembered grant | `PermissionBroker` in the current process | Audit records, approval events, UI request views | PARTIAL DURABILITY. Exact task/tool/action/argument fingerprint, permission, normalized scope, identity, expiry, and consumption are enforced in the broker. Approval state is process-local; restart intentionally invalidates pending approval and requires a fresh request. Receipts are never persisted or replayed. |
| Audit | Runtime-owned `SQLiteAuditSink` (`audit.sqlite3`) | Logs, event observations | IMPLEMENTED_AND_WIRED. Permission decisions and outcomes are append-only secret-safe records; planning lifecycle records are separate audit entries. Audit is evidence, not task or permission authority. |
| Episodic and long-term memory | Runtime-owned `SQLiteMemoryStore` (`memory.sqlite3`) through memory services | Retrieval hits, conversation context, system-memory views | IMPLEMENTED_AND_WIRED. Memory cannot authorize, complete tasks, or become instructions merely because it is retrieved. |
| Conversation context | `ConversationContextService` (process-local) | UI conversation views, provider requests | IMPLEMENTED as transient context. It is not long-term memory or task truth. |
| Execution sessions | `AgentSessionStore` over `sessions.sqlite3` | Provider requests, voice/session projections | IMPLEMENTED_AND_WIRED. Owns session identity, provider/model binding, context metadata, usage/cost, parentage, archive state, and synchronization status only; it cannot own task, goal, approval, or memory truth. |
| Project knowledge libraries | Generated project index plus `KnowledgeStore` | Search results and `ProjectSystemMemory` | PARTIAL. The generated index is the source artifact for the current local knowledge view, but it is derived from repository/docs sources and is not policy or task authority. Revision freshness must remain explicit. |
| Runtime readiness and startup security | `ApplicationRuntime` and `StartupSecurityValidator` | Health API, runtime status, security report | IMPLEMENTED_AND_WIRED. Readiness is derived from validated configuration and successfully opened stores; health cannot enable capabilities. |
| Typed coordination events | `InMemoryEventBus` | Subscriber queues, metrics, UI observations | IMPLEMENTED but intentionally non-durable. Events describe facts and never grant permission, change policy, or replace an owner store. |
| Artifacts | `ArtifactStore` over the app-owned `artifacts/` content directory and `artifacts.sqlite3` metadata store | Opaque references, event observations, and future Trace, PresentationSurface, Knowledge-import, and Backup projections | IMPLEMENTED_AND_WIRED. `ArtifactStore` is the sole authoritative owner of artifact metadata and content. Immutable versions and derivations are workspace-scoped; evidence, memory, planning, audit, and credentials remain separate. Credential secrets are rejected. |
| Capability/integration metadata | `CapabilityRegistry` for canonical capability manifests and `ToolRegistry`/`MCPExtensionManager` for executable adapter lifecycle | Capability discovery candidates, generated knowledge, MCP descriptions/results, environment observations, events | IMPLEMENTED as descriptive metadata plus adapter lifecycle. The registry does not execute or authorize; MCP servers remain untrusted, namespaced adapters only, cannot grant permissions, and cannot become a second authority. EnvironmentGraph is a credential-free observation projection. |
| Integration package boundaries | Validated `IntegrationPackage` contract; package lifecycle remains application/trusted-policy owned | Package code manifests, external user config/data, Vault references, rebuildable cache, diagnostics, migrations, provenance | IMPLEMENTED as a contract only. Package code is immutable/hash-bound; user config and package data are external and preserved across update/uninstall; credentials are references only; no package catalog or executor exists. |
| Skill manifests and context priming | `SkillRegistry` and the canonical agent-runtime `ContextManager` | Bounded primed context, retrieval hits, procedure projections | IMPLEMENTED. Skill requirements are retrieval hints only; memory, knowledge, workspace documents, artifacts, task truth, and permissions retain their existing owners. Workspace, classification, privacy, and token checks fail closed. |
| Credentials and secrets | No JARVIS durable credential store | Environment/configuration references and redacted summaries | MISSING by design. Secrets must not be placed in planning, memory, audit, events, artifacts, or generated knowledge. A future credential store needs an explicit owner and security ADR first. |
| Automation/scheduling | No production scheduler or durable automation store | Automation event contracts only | MISSING/disabled. No task, approval, or receipt may be resurrected by a future scheduler without a new trusted design. |
| Recovery snapshots, restore points, LKG, startup/crash evidence | `RecoveryStore` over the runtime recovery directory | Health checks and runtime status | IMPLEMENTED as recovery authority. It records revision/configuration/schema/migrations/integration/generated-state metadata and selected restore artifacts; it cannot replace task, permission, audit, memory, or integration ownership. |

## Persistence and recovery invariants

The canonical planning database is the durable unit for task execution. Its
schema migrations are ordered and versioned; future schema versions and
migration identity mismatches fail closed. SQLite stores enable WAL, foreign
keys, a bounded busy timeout, and integrity checks. Task/plan writes use one
transaction, and operation reservations bind an exact operation key to a
fingerprint. A different fingerprint for an existing key is rejected.

At startup, `ApplicationRuntime` opens and validates each store, then
`PlanningEngine.reconcile_after_restart()` rebuilds the state projection from
planning truth. A task interrupted during execution, verification, or replanning
is persisted as `RECOVERING` with `unknown_operation_outcome`; it is never
replayed blindly. A permission-waiting task is requeued with old request IDs
removed, so the next execution must create a fresh broker request.

The broker's approval request binds the exact task, tool/action, keyed arguments
fingerprint, action fingerprint, permission, normalized scope, trusted identity,
requester, expiry, and lifecycle status. The paired trusted verifier consumes
the context once. Broker receipts expire no later than their approval/scope and
are claimed at effect time. Audit intent is written before an effect; an
unresolved outcome is recorded as unknown and prevents automatic retry or
replanning.

## Ownership rules for future domains

Before adding durable state, a change must answer all of these questions in this
document and in the relevant ADR:

1. What exact domain does the state represent?
2. Which single store owns creation, mutation, versioning, and recovery?
3. Which data is merely a projection, cache, index, event, or artifact?
4. What transaction/effect boundary prevents partial or duplicate authority?
5. How do migration, future-schema refusal, corruption, restart, and
   `UNKNOWN_OUTCOME` behave?
6. What secrets or untrusted external content are excluded?
7. Which application service exposes read/write access without allowing UI,
   model, event, or integration code to bypass the owner?

No new domain is production-ready until the map, owner, migration, recovery
tests, and security boundary agree.
