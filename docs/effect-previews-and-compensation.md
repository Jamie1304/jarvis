# Effect previews and safe compensation

`PRODUCTION_COMPENSATION_VERIFICATION: RESOLVED`

Execution, preview, compensation, and verification are separate boundaries.
`EffectPreview` is trusted application metadata describing a proposed effect;
it is not generated from model prose and it does not authorize execution.
Permission remains owned by `PermissionBroker` and task execution remains owned
by `PlanningEngine`.

## Preview contract

Each preview contains a target, structured expected change, bounded resources,
typed permission requests, the existing `Reversibility` classification,
artifact labels, and a `VerificationPlan`. A compensatable preview must carry a
real `CompensationDefinition` naming an exact capability/tool, exact arguments,
and a verification plan. Read-only, irreversible, or unknown effects never
advertise an Undo action unless the classification and real compensation path
allow it. In particular, an irreversible or unknown action cannot become
undoable because a model described it as reversible.

The preview fingerprint binds the effect metadata. A compensation request also
binds a current state fingerprint to the preview baseline. Only bounded prior
state fields explicitly required by the compensation definition may be carried;
secret-like fields are rejected.

## Compensation

The runtime-owned `CompensationService` is the sole production orchestration
path. It creates a one-step compensation proposal and submits it to the
canonical `PlanningEngine`; execution then follows:

`PlanningEngine -> ToolRegistry -> Tool.invoke -> PermissionBroker -> Policy/approval`

`CompensationExecutor` remains a lower-level compatibility contract for
isolated callers and tests. It is not a second production task engine or
authority.

It never calls a provider or adapter directly. A permission denial, stale state,
missing baseline, failed tool, unknown effect outcome, or failed verification is
returned as an explicit `CompensationResult`; none is silently treated as Undo
success or replayed. Tool success is not compensation proof. The configured
`VerificationEngine` must receive fresh independent evidence before the result
can be `VERIFIED`.

## Plan Studio and Trace

`PlanStudioEffectProjection` augments the existing typed `PlanInspection` view
with previews in plan-step order and exposes Undo only when a real compensation
definition exists. It is a presentation projection and cannot mutate plans or
grant permission.

`EffectTraceRecord` and the optional `EffectTraceSink` capture bounded preview
fingerprints, compensation start/completion, request IDs, and statuses. Trace
is observational and never becomes task, permission, artifact, or verification
authority. A trace sink failure does not change the explicit compensation
result.

Before execution, `CompensationService.bind_original_effect()` derives an
immutable `OriginalEffectReference` from a completed durable PlanningEngine
task, exact plan revision, exact successful step, and its durable evidence.
The compensation tool/capability must match that producing step. A caller
boolean, callback, or model statement cannot create this binding. The service
revalidates the current state fingerprint, persists bounded lifecycle metadata
in `compensation.sqlite3`, and binds its compensation task into the original
trace lineage. Independent VerificationEngine evidence is required for
`VERIFIED`; `RECOVERING`/unknown outcomes are terminal and never replayed.
