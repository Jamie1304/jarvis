# ADR 0015: authoritative structured User Model

## Decision

JARVIS owns structured user facts and preferences in a dedicated local
`UserModelStore` (`user-model.sqlite3`). The store is separate from durable
long-term/episodic memory and process-local conversation context. It is the only
authority for this domain and exposes filtered read views for application
consumers.

Records are workspace-scoped, typed as facts or preferences, and carry source,
confidence, timestamps, verification, sensitivity, retention, origin, and
bounded relationships. Explicit values require a trusted user source;
model-originated values are inferred data. Corrections increment revisions and
append audit fingerprints without retaining previous raw values. Deletion and
retention expiry are audited.

## Security and privacy

The store accepts structured JSON only. It does not ingest conversation history,
store raw credentials, or turn model output into identity, permission, approval,
or policy. Credential-like fields, raw transcript fields, and secret sensitivity
fail closed. Context retrieval requires an explicit workspace/sensitivity policy;
cloud export is opt-in and returns only filtered non-secret records.

User-model data may influence ranking, routing, presentation, opportunities,
communication, and attention policy as untrusted application data. It cannot
authorize an effect or change the security constitution.

## Consequences

The application has an auditable local preference/fact lifecycle without making
the general memory store a competing identity authority. SQLite migration,
future-schema, WAL, foreign-key, busy-timeout, restart, and workspace-boundary
behavior are tested. A future multi-user identity layer must be introduced as a
separate reviewed contract rather than inferred from this store.
