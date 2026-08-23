# Provider and execution-session runtime

JARVIS resolves model providers through `ProviderRegistry` definitions. A
definition supplies provider metadata, a factory, and optional model metadata;
the composition root supplies configuration. Provider-specific selection does
not spread through application services as `if/elif` trees. The current local
Ollama adapter is registered through this path and remains local-only by
policy.

`ModelMetadata` is descriptive rather than a download or execution request. It
can identify model roles, family/version/quantization, runtime/source,
modalities, context, resource requirements, license, compatibility tags,
evidence provenance, quality/latency benchmarks, and token-cost metadata.
`LocalModelManager` owns verified local artifact lifecycle through typed
catalog/downloader/runtime protocols and exposes no post-install script hook.
`ProviderRouter` selects compatible provider/model candidates under explicit
privacy, latency, resource, concurrency, benchmark, and cost policy. Unknown
capacity produces an unknown route, never an optimistic fit. It also selects
provider-neutral STT/TTS chains and can return explicit `NO_LLM`. See
`docs/hardware-and-models.md` and `docs/model-management-and-routing.md`.

`AgentSessionStore` is the authoritative store for execution-session identity
and lifecycle metadata only. It is not a task/goal store, user-model store, or
conversation-memory store. A session records its type, provider/model,
timestamps, context metadata, usage/cost, parent, archive state, and whether
provider state is synchronized.

Voice conversations bind one `VOICE` session and reuse it across adjacent
utterances after successful completion. Cancellation or barge-in marks the
session unsynchronized and invalidates the active generation. The next
utterance archives/rebuilds the session before requesting new provider output;
chunks from the cancelled generation cannot be emitted or appended to history.
This is conservative for providers whose cancellation synchronization cannot be
proven. Model changes likewise archive the old session and create a new one.

Session records are durable SQLite metadata with busy timeout and foreign-key
configuration. Session state is execution context, not authority: permissions,
task truth, audit, and memory remain owned by their existing stores and
services. No donor runtime is required.
