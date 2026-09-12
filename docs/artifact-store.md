# Canonical ArtifactStore

JARVIS keeps three concepts separate:

- **Evidence** is proof used to support a task or decision.
- **Memory** is retained knowledge for future context.
- **Artifact** is a concrete output produced by a task, tool, integration, or
  other trusted application service.

`ArtifactStore` is the sole authoritative owner of artifact metadata and
content. It stores metadata in the app-owned `artifacts.sqlite3` database and
bytes below the app-owned `artifacts/content` directory. Other services may
retain an `ArtifactReference`, observe `artifact.created`, or build a
projection, but they do not copy artifact truth into a competing authority.

## Contract

An artifact has an immutable `ArtifactRecord` with immutable
`ArtifactVersion` values. A version records its task/goal context, workspace,
name, MIME type, size, SHA-256 hash, classification, producer, provenance,
timestamps, retention policy, and opaque storage reference. A derived version
points to its parent reference. New content always receives a new version and
new storage object; existing bytes are never overwritten.

References are workspace-scoped. Reads and derivations require the caller to
present the same workspace identifier that was recorded with the reference.
Content filenames are generated opaque names, never caller-controlled paths.
The store rejects traversal-like names and references, checks containment, and
rejects symlink/junction/reparse-point roots or content paths. These checks
reduce path and reparse escape risk; Windows native filesystem races cannot be
claimed impossible without stronger OS-level handle/open protections.

Credential secrets are not artifacts. The store rejects the credential-secret
classification, and callers must not serialize `CredentialVault` material into
content, provenance, or metadata.

Retention may expire versions or bound the number of retained versions. Purge
is an explicit store operation and does not change the immutability of a
version while it is retained. Restart reopens the same WAL-backed metadata
store and validates content hashes on reads.

## Integration boundary

The EventBus receives an observational `artifact.created` event after the
metadata/content transaction commits. Events do not grant authority or become
artifact truth. Trace, PresentationSurface, Knowledge import, and `BackupService`
consume references and store their own projections or encrypted backup copies
under explicit ownership contracts; none may silently become a second artifact
metadata/content owner. Backup does not export CredentialVault secrets.
