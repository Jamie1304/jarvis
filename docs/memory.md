# Memory model

Phase 14 keeps four different kinds of memory separate. Memory is context, never a
permission grant, tool registration, approval, or executable instruction.

## What is persisted

`SQLiteMemoryStore` is a local durable store with ordered application migrations in
`jarvis.memory.store`. Its caller explicitly chooses the database path; the library
does not create a hidden repository database or upload data. Each record has a UUID,
durable type, safe content and JSON data, UTC creation/update/access times, source
provenance, optional confidence, sensitivity, retention policy, and computed expiry.
The store also retains bounded quarantine and supersession state. It rejects
malformed migrations, duplicate IDs, expired records, and secret-like content.
It has inspect, individual-delete, category-delete, and expiry-cleanup operations.
Quarantined and superseded records remain inspectable by trusted application code
but are excluded from ordinary retrieval.

Only two categories enter this database:

- **Long-term user memory** contains a confirmed, user-sourced, sufficiently
  confident preference or fact. `LongTermRetentionPolicy` evaluates a candidate first
  and emits a machine-readable allow/deny reason. Casual conversation, tool/web data,
  low-confidence candidates, unconfirmed candidates, and untrusted sources are denied.
- **Episodic memory** contains a compact completed task record: objective, bounded tool
  actions, outcome, errors, and relevant evidence. It is not a copy of the permission
  audit trail, raw transcripts, screenshots, or full tool output.

Retention is explicit: 30 days, one year, or until the user deletes it. Expiry is
bound to the selected policy and enforced on retrieval and cleanup.

## What is not persisted here

- **Short-term conversation context** is a bounded process-local
  `ConversationContextService`. It trims old context and can use an explicit trusted
  summarizer seam. `clear(conversation_id)` drops it immediately; it never calls the
  SQLite store. The existing chat service remains process-local as well.
- **System/project memory** is a read-only `ProjectSystemMemory` adapter around the
  Phase 12 `KnowledgeStore`. It queries the generated project index and retains its
  source hashes/stale flag; it never copies source knowledge into user memory.
- API tokens, passwords, authentication cookies, and other secret-like values are
  rejected. They require a dedicated platform or application secret store, which is
  outside this memory subsystem.

## Provenance, trust, and retrieval

Every durable record records source category/reference/receipt time and whether its
content was untrusted. Historical web or tool text is returned only as labelled data
(`content_is_untrusted_data`); it must not be interpreted as instructions or used to
alter policy, tools, prompts, approvals, or execution.

`MemoryConsistencyService` scans the authoritative store for exact duplicates,
structured contradictions, stale records, explicit supersession, low confidence,
impossible provenance, and instruction-shaped prompt injection. Findings are
persisted as `MemoryConflictRecord` values. Similarity or matching text never
silently merges records. Prompt-injected or impossible-provenance content is
quarantined at the storage boundary; low-confidence long-term records are treated
the same way until revalidated. Quarantine removes records from ordinary retrieval
without destroying the evidence.

Trusted revalidation appends `MemoryConfidenceEvent` history and may release a
quarantine only with typed evidence. Long-term personal memory requires trusted,
explicit user revalidation. Sensitive memory requires user confirmation, confidence
at least 0.8, and multiple bounded evidence items. A user correction creates a new
record and explicitly supersedes the old one; it never overwrites or merges the old
value. External content cannot perform that correction.

`MemoryRetrievalService` returns four separate result lists: `conversation`,
`long_term`, `episodic`, and `system`. It uses deterministic local lexical matching,
not a vector database. Callers must preserve these source/type labels when preparing
context for an AI provider or UI.

## User privacy controls

Trusted application/UI code must authenticate the requesting user before exposing the
store, then may call `get`/`list` to inspect, `delete` for one record,
`delete_category` for a durable category, `ConversationContextService.clear` for a
conversation, and `cleanup_expired` for scheduled retention cleanup. No model text
can directly call these methods in the agent tool path; a future UI/API must add its
own authenticated ownership checks before multi-user use.

## Updating and testing

Migrations run when a `SQLiteMemoryStore` is opened and can be invoked explicitly by
`apply_migrations()`. New migrations must be ordered, reviewed Python constants and
must include a temporary-database test. Run the focused deterministic suite with:

```powershell
.\.venv\Scripts\python.exe -m pytest tests/test_memory.py -q
```

Then run `python scripts/quality.py`. The tests use temporary SQLite databases and
fake clocks only; they do not persist user data, contact a network, invoke tools, or
activate hardware.
