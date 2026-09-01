# Empirical hardware and model inventory

JARVIS keeps hardware facts and model metadata descriptive. They help trusted
application code choose a compatible runtime; they do not enable a capability,
grant a permission, or turn a model response into evidence.

## Evidence provenance

Every published model fact can be marked `PUBLISHED`, `COMMUNITY`, or
`MEASURED_ON_THIS_MACHINE`. The measured kind requires a timezone-aware capture
time and the exact scope `this_machine`. A model card or a model-generated
claim cannot be recorded as local measurement. Unknown values remain `None`;
the planner returns `UNKNOWN` instead of treating an unknown GPU, VRAM, RAM,
disk, or concurrency limit as zero or as success.

`HardwareInventoryService` obtains a raw `HardwareReading` from an injected
`HardwareProbe` and wraps it in measured provenance. `SystemHardwareProbe` uses
stdlib/platform APIs for CPU, RAM where the host exposes it, OS, Python runtime,
and free disk. It deliberately leaves GPU/VRAM and scheduling concurrency
unknown when it cannot establish them safely. A future trusted adapter may add
driver/runtime or GPU observations; no donor or product-specific integration is
required.

## Model metadata

`ProviderRegistry.ModelMetadata` records, where known:

- model roles: GENERAL, REASONING, CODING, TOOL_USE, VISION, EMBEDDING,
  RERANKING, STT, TTS, and IMAGE_GENERATION;
- family, version, quantization, runtime, source, modalities, context limit,
  storage/RAM/VRAM requirements, license, compatibility tags, and evidence.

`ModelInventory.record_measurement()` accepts results from a trusted runtime
benchmark and appends local measured evidence. It updates only values supplied
by that benchmark; it never fills a missing result with a default or a model
claim.

## Resource-aware combinations

`ModelPlanner` maps required roles to registered models and evaluates bounded
combinations. It checks exact compatibility tags, free disk, aggregate model
memory, available VRAM, and requested concurrency. Simultaneous combinations
sum model RAM/VRAM; sequential combinations use peak requirements. A plan is
`COMPATIBLE`, `INCOMPATIBLE`, or `UNKNOWN`. `UNKNOWN` is not activation or
permission and must be resolved by a trusted measurement or an explicit user
choice.

The planner supports one model serving multiple roles and distinct models for
specialized roles. It has bounded role/candidate expansion and does not start a
model, download a model, change a provider, or provision hardware.

## Testing and operational limits

CI uses fake hardware readings and fake model metadata so resource decisions are
repeatable without loading a model or inspecting a developer machine. Tests
cover missing capacities, incompatible tags, local measurement requirements,
simultaneous versus sequential memory, concurrency denial, malformed metadata,
and evidence provenance.

Real hardware/model measurements are not claimed by CI. A local inventory result
is valid only for the timestamped machine probe or trusted benchmark that
produced it; it must not be copied to another machine or treated as a published
compatibility guarantee.
