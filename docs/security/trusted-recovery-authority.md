# Trusted Recovery Authority

**Status:** implemented in the current working tree
**Scope:** local deterministic recovery and the Windows production composition

`RecoveryStore` remains the sole durable owner of snapshots, startup markers,
the authenticated Last-Known-Good (LKG) record, and recovery evidence.
`TrustedRecoveryAuthority` is the trusted application/update-side verifier and
promoter for that record. It is not a second recovery store and is never passed
to generated code, integrations, model providers, UI code, or event payloads.

## Authenticated record

`TrustedRecoveryRecord` replaces the former unsigned snapshot pointer in
`last-known-good.json`. Its authenticated payload contains:

- record schema, committed status, installation identity, authority identity and
  authority version;
- application revision and exact application build-tree SHA-256;
- update transaction ID, snapshot ID, exact persisted manifest SHA-256, and
  required database/configuration schema compatibility;
- previous trusted record ID, promotion timestamp, and monotonic generation;
- an HMAC-SHA-256 integrity value over all preceding fields.

The manifest itself remains schema-versioned and contains per-file hashes. The
record binds the manifest bytes, manifest metadata, application hash, schema
compatibility, transaction, and installation identity together. A changed
record, manifest, snapshot reference, build hash, transaction, status, schema,
or file fails validation.

## Key and sequence storage

The HMAC key and generation floor are stored through the existing secure secret
backend. Production/local composition selects Windows Credential Manager and
uses installation-scoped targets. Unsupported production hosts fail closed;
there is no plaintext file, SQLite column, log, event, artifact, memory, or
backup fallback. The deterministic `test` composition alone may inject or use
the explicit `TestOnlyInMemorySecretBackend`.

Missing key material is never silently replaced when an LKG record already
exists. The generation floor is advanced before an ordinary record replacement;
if the process fails between those writes, an older record is rejected rather
than replayed. A legitimate rollback is a new trusted promotion with a higher
generation and a link to the prior record, even when its application revision
is older.

## Promotion boundary

The candidate has no public `mark_known_good` or `mark_myself_good` operation
and receives no authority object. `RecoveryCoordinator` owns candidate start,
bounded health, migration reconciliation, and the `RecoveryStore` commit call.
Only after the trusted composition reaches `HEALTH_CHECK` successfully does
`RecoveryStore.commit_start()` ask the private authority path to create a new
authenticated record. A failed start or health check leaves the candidate out
of LKG and records evidence.

This record is recovery integrity evidence; it does not grant permission,
activate an integration, or replace `ToolRegistry -> PermissionBroker ->
Policy`. Update gates, certification, activation, and user approval remain
separate trusted services.

## Boot and failure behavior

Before selecting LKG, the store verifies:

1. supported record and manifest schemas;
2. secure-backend HMAC and generation floor;
3. installation, authority, status, and transaction linkage;
4. exact application revision/build hash;
5. snapshot/manifest reference and hash;
6. database/configuration compatibility metadata and snapshot file hashes.

Invalid, future, stale, unrelated, missing-key, or unavailable-backend state
is evidence of an unsafe recovery condition. The runtime does not execute that
target as trusted LKG; the bounded coordinator enters Safe Mode when recovery
cannot establish a valid restore point.

## Defensive evidence

Local synthetic tests in `tests/test_recovery_authority.py` cover valid records,
restart persistence, modified build/snapshot/manifest/transaction/status/schema
fields, corrupted authentication, missing keys/backends, stale generation,
unrelated installations, candidate commit without the trusted startup
lifecycle, failed health, successful promotion, and future-schema Safe Mode.
`tests/test_recovery.py` covers the existing snapshot, rollback, crash-loop,
deadline, migration, retention, and Safe Mode behavior.

This is an authenticated local recovery boundary, not a claim of a signed
vendor release or a kernel/VM isolation boundary. Code review, update preview,
Golden Workflow gates, platform acceptance, and owner policy remain required
for any future self-update scope.
