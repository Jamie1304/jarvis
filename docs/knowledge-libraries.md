# Personal documentary knowledge libraries

**Status:** v1 native contract
**Updated:** 2026-08-24

KnowledgeLibrary is the sole authoritative owner of a user's documentary
index and its metadata. It is deliberately separate from UserModelStore:

- User Model records are structured facts and preferences about the user.
- A Knowledge Library indexes approved documents and returns evidence with
  citations.

The generated repository index (KnowledgeStore) remains a separate,
read-only project-knowledge artifact. It is not a personal library and it
does not replace this owner.

## Sources and scope

A source is registered explicitly as one of:

- APPROVED_DIRECTORY, with an explicit workspace and optional recursion;
- APPROVED_FILE, with an explicit workspace; or
- INTEGRATION, a credential-free URI reserved for a future trusted adapter.

There is no implicit source and no whole-filesystem indexing mode. A
filesystem source must be inside the caller-provided approved workspace root.
Absolute paths, traversal components, reparse points, symlinks that escape
the root, and filesystem roots are rejected. A source registration is a
bounded indexing grant, not a permission or credential grant.

Path resolution and the subsequent read are separate operations. On Windows,
native reparse-point and TOCTOU behavior cannot be made perfectly
force-cancellable by this Python boundary; the implementation resolves and
rechecks paths, rejects detected links/junctions, and records the limitation
instead of claiming a stronger guarantee.

## Ingestion and incremental sync

Only bounded UTF-8 text formats are extracted (txt, Markdown, reStructured
Text, CSV, JSON, YAML, TOML, and log text). Extraction never imports, executes,
or evaluates a document. Files larger than 8 MiB, malformed text, NUL-bearing
content, unsupported files, and common credential-shaped content are skipped
without persisting their content. Explicit secret classification is rejected.

Each indexed document records its stable source identity, relative location,
size, SHA-256 content hash, modification time, MIME type, workspace,
classification, metadata, and provenance. Content is split into bounded
chunks with hashes and offsets. Every chunk is marked untrusted.

Sync compares source identity, size, modification time, and content hash:

| Source reality | Index action |
| --- | --- |
| New | Add document and chunks |
| Unchanged | Skip without rewriting |
| Changed | Replace its immutable index representation |
| Deleted | Mark the document deleted and remove searchable chunks |

Sync state records counts, status, timestamp, and bounded diagnostic class.
The source itself is never removed by indexing or by delete_index.

## Retrieval and citations

retrieve() is always workspace-scoped and rejects secret retrieval. It
supports deterministic keyword, semantic-compatible local ranking, or hybrid
ranking, plus classification, source, MIME, and metadata filters. A future
embedding implementation may add a derived semantic index, but it must not
become documentary truth or bypass these filters.

Each result contains the document, chunk, score, and a KnowledgeCitation
with source identity, relative location, content hash, excerpt, and document
and chunk IDs. Citations identify evidence; they do not authenticate a source
or grant authority.

Documents are external content. Prompt-injection-shaped text is retained as
data when it passes the secret/content safety boundary and is marked
untrusted_content; it is never interpreted as a policy, permission, tool
request, or instruction. Skill and workflow context priming may call this
normal scoped retrieval API, subject to the same workspace, classification,
privacy, and token limits.

## Persistence and recovery

knowledge-library.sqlite3 is app-owned and uses foreign keys, WAL, a
bounded busy timeout, integrity checks, ordered migrations, and future-schema
refusal. Documents and chunks are transactional with sync-state updates.
Deleting an index removes only library rows. Reopening the database restores
registered sources, document metadata, and sync state.

No library row contains a Vault secret. Credential references, if a future
integration needs them, remain opaque references resolved by the trusted
credential boundary.
