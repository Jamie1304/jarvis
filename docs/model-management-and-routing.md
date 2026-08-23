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

## Routing

`ProviderRouter` evaluates provider/model candidates against:

- task, profile, role, modality, complexity, classification, and context;
- tool/structured-output declarations;
- provider health and configured preference;
- latency budgets and timestamped benchmark overrides;
- model and hardware RAM/VRAM/disk/concurrency limits; and
- local/privacy policy and API/token cost metadata.

Policies are `LOCAL_ONLY`, `PREFER_LOCAL`, `QUALITY_FIRST`, `SPEED_FIRST`,
`LOWEST_COST`, `BALANCED`, and `PRIVACY_STRICT`. Unknown capacity or an
unknown required latency benchmark is not treated as compatible. Routing does
not download, load, activate, authorize, or change a permission policy.

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
