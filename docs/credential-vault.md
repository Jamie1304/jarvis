# CredentialVault and generic authentication

`CredentialVault` is the sole authoritative owner of credential secret material.
It stores only bounded metadata in the app-owned `credentials.sqlite3` database:
credential ID, label, association, scope, authentication method, timestamps,
status, and expiry. The database has no secret column and refuses future schemas
and detected secret columns.

Production composition uses the native Windows Credential Manager backend. On a
host without that secure backend, credential creation/use fails closed. The
explicit `TestOnlyInMemorySecretBackend` exists only for deterministic tests and
is never selected automatically; JARVIS never silently falls back to plaintext
files, ordinary SQLite blobs, configuration, environment snapshots, logs, or
memory.

The normal model/application surface receives `CredentialMetadata` and opaque
credential IDs. `scoped_use` is a trusted application/proxy boundary: it checks
active status, expiry, exact association, and requested-scope containment before
returning transient bytes to the authenticated-request proxy. Callers must not
place those bytes in prompts, events, audit, memory, artifacts, research, or
backup.

Create, update, rotate, revoke, delete, status, and scoped-use operations are
fail-closed and metadata/audit safe. Revocation/deletion first makes the
credential unusable and then removes the secure backend entry; cleanup failure
is reported without exposing the secret.

`GenericAuthenticationService` provides provider-neutral API token/key storage,
OAuth authorization-code and local-callback completion, device-code flow, and
refresh rotation. Provider adapters implement protocol methods only; they do not
receive the broker, Vault authority, policy, or trusted identity, and provider
responses never become permission grants. Authentication returns metadata
references, not token bytes. Authorization URLs and device-code challenges are
transient trusted UI/proxy inputs and must never be sent to a model, prompt,
memory, event, artifact, research, or backup path. Browser, MCP, or future
integrations must use a trusted proxy and a fresh PermissionBroker decision for
authenticated effects.
