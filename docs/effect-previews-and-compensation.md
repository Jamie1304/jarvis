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

### Trusted observation boundary

Normal application composition owns one sealed `EffectStateObserverRegistry`.
It binds trusted observers to the exact compensating tool or capability and
validates the returned request, effect, task, tool, capability, and target
identities before use. The registry is not exposed to generated packages or
sandbox processes. `FilesystemStateObserver` is the generic v1 observer; it
reads only bounded files under the application-owned data root and emits a
SHA-256 state fingerprint plus hash-only `FILE` evidence. Other capabilities
must register an application-side observer through the same trusted startup
boundary or compensation returns `OBSERVATION_UNAVAILABLE`.

The pre-effect observation is fresh and must match the original effect's exact
state baseline. The post-effect observation is fresh trusted evidence for
`VerificationEngine`. A package callback, model claim, tool return value, or
caller-supplied verdict cannot establish compensation safety or success.

`CompensationExecutor` remains a lower-level compatibility contract for
isolated callers and tests. It is not a second production task engine or
authority.

It never calls a provider or adapter directly. A permission denial, stale state,
missing baseline, failed tool, unknown effect outcome, or failed verification is
returned as an explicit `CompensationResult`; none is silently treated as Undo
success or replayed. Tool success is not compensation proof. The configured
`VerificationEngine` must receive fresh independent evidence before the result
can be `VERIFIED`. If a trusted observer is absent or stale, the service returns
`OBSERVATION_UNAVAILABLE` and performs no compensating execution. Existing
`STALE_STATE` remains the result for a changed baseline or binding.

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
The compensation target must match the trusted preview and the compensation
tool/capability must match that producing step. A caller boolean, callback, or
model statement cannot create this binding. The service
revalidates the current state fingerprint, persists bounded lifecycle metadata
in `compensation.sqlite3`, and binds its compensation task into the original
trace lineage. Independent VerificationEngine evidence is required for
`VERIFIED`; `RECOVERING`/unknown outcomes are terminal and never replayed.
