# Local User Model

`UserModelStore` is the sole authoritative owner of durable user facts and
preferences. It is intentionally separate from process-local conversation
context, episodic and long-term memory, workspace/profile configuration, tasks,
plans, permissions, credentials, artifacts, and audit records.

## Record contract

Each active record is a structured `FACT` or `PREFERENCE` identified by a
workspace-scoped key. It contains a category, JSON value, source and bounded
source reference, confidence, creation/update/verification timestamps,
sensitivity, retention, explicit/inferred origin, and bounded relationships.
The store keeps one current value per `(workspace, key, kind)` and increments
its revision on correction. Previous values are not copied into the audit log;
the log records lifecycle action, actor, revision, reason, and SHA-256 value
fingerprints.

Only a user source can create an `EXPLICIT` record. Model output is accepted
only as `INFERRED` application data and cannot create trusted identity,
permission, approval, or policy. A correction is an explicit user operation and
creates a new revision. Deletion is a durable tombstone with audit evidence;
retention expiry is a separate audited purge.

The API accepts structured records, not raw messages or an utterance ingestion
stream. Credential-like fields, secret sensitivity, raw transcript fields, and
credential-like source references are rejected before persistence. Raw
credentials belong only in `CredentialVault`. Instruction-shaped prompt-injection
content is also rejected; imported or model-derived values remain explicitly
inferred data and cannot become trusted personal facts merely because they are
stored.

## Context and privacy

`UserModelContextPolicy` is a retrieval filter, not an authority grant. It
requires a workspace and can restrict categories, keys, sensitivity, inferred
records, and result count. Workspace-specific records never cross into another
workspace; global records are explicitly marked and may be included by the
caller.

`UserModelRetrievalQuery` adds semantic ranking over the structured record
projection. Metadata, workspace, classification, confidence, and origin gates
are applied before scoring; recency and confidence are bounded ranking signals.
The default local hash encoder is deterministic and replaceable by a configured
provider-neutral encoder. Any embedding is derived search data, never source
truth, and a close semantic score does not consolidate records.

Local context can include the configured non-secret sensitivity classes. Cloud
context is opt-in and the convenient `cloud_public()` policy selects only
`PUBLIC` records. `UserModelContext.export_for_cloud()` refuses local views and
returns only the already-filtered structured values. The store performs no
network operation; the provider/application boundary remains responsible for
the final data-sharing decision.

User-model views may inform solution ranking, model routing, UI, opportunities,
communication, and `AttentionPolicy`. They are data inputs only and never grant
permissions or change the trusted security constitution.

## Controlled consolidation

Consolidation requires a typed `UserModelConsolidationRequest`. `MERGE`,
`UPDATE`, and `REPLACE` require independent evidence and an exact resolved
structured result value. `KEEP_SEPARATE` and `IGNORE_SKIP` are auditable no-op
decisions. No decision is generated from embedding proximity alone.

Effectful consolidation keeps the target record authoritative, marks the source
as a tombstone, and records lineage, supersession, related record IDs, and
audited value fingerprints. The target retains its creation history and the
source remains inspectable through its audit/tombstone record. Sensitivity is
promoted to the most restrictive participating level; provenance and confidence
remain available on the involved records. A derived summary is never written as
source truth without an explicit resolved value and evidence.

## Persistence and recovery

The app-owned `user-model.sqlite3` database uses WAL, foreign keys, a bounded
busy timeout, integrity checks, ordered migrations, and future-schema refusal.
Records and their audit entry commit together. Runtime composition owns one
store and closes it exactly once. A rebuildable retrieval view or event is not a
second user-model authority.
