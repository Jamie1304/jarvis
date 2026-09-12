# Local model management and inference routing

JARVIS manages models through provider-neutral typed contracts. The local model
manager owns only the app-owned model root and verified lifecycle facts; it is
not a task, permission, credential, or audit authority.

## Lifecycle

`LocalModelManager` supports:

`discover -> compatibility -> download -> integrity verification -> install ->
load/unload -> health -> benchmark -> remove/repair`

Catalogs, downloaders, and runtimes are injected protocols. A model artifact is
bound to an exact SHA-256 and byte size. Downloads use a bounded temporary file
and atomic replacement. Model paths are derived from validated model IDs and are
checked for path escape, symlink, junction/reparse, and non-directory parents.
These checks protect the app-owned root from ordinary path mistakes; they do not
make a hostile process with equivalent host privileges race-free, so such a
process is outside this boundary.

There is deliberately no post-install script, shell command, dynamic hook, or
arbitrary executable callback in the lifecycle contract. A runtime may load a
validated artifact only through its typed `LocalModelRuntime` adapter.

Repair re-verifies reality before downloading again. A loaded model must be
unloaded before repair or removal. A benchmark is accepted only from the
trusted runtime adapter and is recorded as `MEASURED_ON_THIS_MACHINE`; missing
measurements remain unknown.

The durable model-knowledge store exposes benchmark facts through typed,
bounded measurement queries. Provider metadata remains descriptive, while each
measurement retains its source, timestamp, exact `this_machine` scope, and only
the values supplied by the trusted runtime. A provider refresh therefore cannot
overwrite the latest machine measurement projection. Cookbook
`VERIFIED_SUCCESS` is counted only when `verified=True` and the agreement is
`DETERMINISTIC_VERIFICATION`, `INDEPENDENT_MODEL_REVIEW`, or `USER_CONFIRMED`;
model self-claims, non-independent model review, and unknown agreement do not
certify it. P3C may later choose evidence weighting; this knowledge plane does
not make routing or fallback decisions.

## Routing

`ProviderRouter` evaluates provider/model candidates against:

- task, profile, role, modality, complexity, classification, and context;
- tool/structured-output declarations;
- provider health and configured preference;
- latency budgets and timestamped benchmark overrides;
- model and hardware RAM/VRAM/disk/concurrency limits; and
- local/privacy policy and API/token cost metadata.

P3C makes this an availability-aware per-step decision. The
`ModelKnowledgeService` supplies descriptive catalog, provider-health,
machine-measurement, and task-specific cookbook evidence, while
`ProviderRegistry` remains the only factory and execution authority. Typed
privacy, health, stale, capability, context, structured/tool, cost/latency,
concurrency, and resource filters run before deterministic ranking. Unknown
health, capacity, cost, latency, or task evidence remains unknown; it is never
treated as healthy, free, zero-latency, or verified. With an explicit reliability
threshold, that threshold is applied before policy optimization: `LOWEST_COST`,
`SPEED_FIRST`, and `BALANCED` optimize their documented efficiency factors only
among qualifying candidates, while `QUALITY_FIRST` remains reliability-oriented.
Without an explicit threshold, best-effort routing remains conservative and
reliability-first. Ties end in the full provider/model variant identity.

Agent routing context eligibility includes the complete bounded model-visible
protected projection and conversation messages, plus reserved output capacity.
`ContextManager` revalidates the final projected request after deterministic
history compaction; a smaller or cheaper model is selected only when that real
request fits.

Policies are `LOCAL_ONLY`, `PREFER_LOCAL`, `QUALITY_FIRST`, `SPEED_FIRST`,
`LOWEST_COST`, `BALANCED`, and `PRIVACY_STRICT`. Unknown capacity or an
unknown required latency benchmark is not treated as compatible. Routing does
not download, load, activate, authorize, or change a permission policy.

`InferenceDispatcher` is the single execution seam after selection. It binds
the selected identity to a registry-created provider and re-enters the router
only for a bounded pre-output failure. Cancellation and unknown outcomes do
not trigger fallback, and a stream that has yielded output is never stitched
with another provider. A P3A privacy block can only re-evaluate as a
local-only route. Conversation and agent segments route independently; a
provider/model transition archives the old execution session while preserving
its context lineage. Safe factual outcomes may be recorded through the P3B
cookbook feedback seam, but model text is not verification evidence.

The explicit `NO_LLM` result is available when the request allows it. For voice,
the same router selects provider-neutral STT/TTS definitions. It can construct
an STT failover chain or a TTS service with ordered fallback providers. If no
TTS route is available, the caller receives `None` and remains text-only; this
does not change microphone mode or PermissionBroker policy.

No vendor, cloud service, local runtime, model family, or speech engine is a
mandatory core dependency. Provider definitions and configuration remain the
composition root's responsibility.

## Evidence and limits

CI uses deterministic fake catalogs, downloaders, runtimes, hardware, model
metadata, and STT/TTS providers. No real model is downloaded or benchmarked by
the test suite, and CI results are not machine compatibility claims. The native
hardware probe continues to leave unestablished GPU/VRAM and concurrency facts
unknown.
