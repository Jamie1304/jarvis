# Encrypted user-facing backup, export, and migration

## Boundary

JARVIS has two different forms of restore-related state:

- `RecoveryStore` owns technical startup recovery, candidate/LKG builds,
  crash-loop detection, and Safe Mode.
- `BackupService` owns user-requested encrypted export bundles and restore
  planning. A bundle is transport and migration input; it is not a new
  authoritative store.

The composition root creates `BackupService` under the app-owned `backups/`
directory. Component providers and appliers are registered by the owning
application service. This keeps task/plan, memory, knowledge, artifacts,
skills, automation, capability, package, and credential truth in their
existing owners.

## Bundle contract

The native contracts are `BackupManifest`, `BackupBundle`, `BackupComponent`,
`BackupPolicy`, `RestorePlan`, and `MigrationReport` in `jarvis.backup`.

Selectable component IDs cover settings/privacy, workspaces, User Model and
memory, Knowledge metadata/indexes, Skills, WorkflowTemplates, Automations,
Artifacts, generated integrations, certifications, capability metadata, UI,
and configuration. Model files and generated caches are explicit opt-in
selections and are excluded by the default policy. Component providers must
return bounded bytes, a component version, classification, source reference,
external path metadata, and any machine-bound or recertification requirement.

The manifest records a format version, bundle ID, UTC creation time, source
installation identity when available, component versions, sizes, SHA-256
hashes, classifications, external paths, credential-reference metadata, and
security flags. Installation identity is metadata only; it is not a key.

## Encryption and secret boundary

Bundles use the reviewed `cryptography` package: PBKDF2-HMAC-SHA256 derives a
32-byte key from the user-supplied password, and AES-GCM provides authenticated
encryption with a fresh salt and nonce. The authenticated manifest and payloads
are encrypted together. The password/key is never serialized in the bundle,
and a wrong password, modified envelope, malformed JSON, or hash mismatch
fails closed.

Raw credentials and secret-bearing component IDs are rejected. A component may
carry an opaque Vault reference or a machine-bound marker, but the secret is
not exported to ordinary database, configuration, log, memory, artifact, or
backup data. On a different installation, restore reports
`REAUTHORIZATION_REQUIRED`; it never falls back to plaintext export.

## Restore lifecycle

Restore is explicit and can be selective or full:

1. Authenticate and verify the bundle envelope, manifest, bounds, component
   metadata, and payload hashes.
2. Build a `RestorePlan` showing selected components, version conflicts,
   migration requirements, reauthorization, generated-integration
   recertification, missing external paths, and whether application is
   destructive.
3. Resolve required reauthorization, migration, conflict, relink, and
   recertification decisions through trusted application callbacks. A generated
   integration does not inherit `ACTIVE` on a new installation; it must be
   certified again before activation.
4. Take a technical snapshot before destructive application. Apply only
   registered component appliers, with the selected component IDs and exact
   authenticated bytes.
5. Record a `MigrationReport`. If application fails, invoke the supplied
   rollback callback and surface an explicit failed report. Rollback failure is
   itself reported as a restore failure.

Knowledge sources and workspace folders are represented by metadata and
external paths, not copied implicitly from the whole filesystem. Missing
sources require an explicit relink decision. Deleting an index or restoring a
bundle does not silently delete the original source.

The service bounds component and bundle sizes, rejects traversal and unsafe
bundle destinations, writes exports atomically, refuses future schema
versions, and reports old supported schema versions through
`MigrationReport`. Component migration is owned by the component service; the
backup layer does not guess how domain data should be transformed.

## Non-goals and limitations

Backup is not a distributed transaction and cannot make arbitrary external
effects reversible. A registered applier is responsible for its own safe
validation and domain transaction. Technical snapshots are required by the
service before destructive restore, but their storage and rollback semantics
remain composition-owned. No model files or caches are bundled by default,
and no backup operation grants permission, trusted identity, capability
activation, or approval.
