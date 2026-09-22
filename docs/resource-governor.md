# ResourceGovernor

`ResourceGovernor` is the single process-wide admission policy for work that
competes for CPU, memory, GPU/VRAM, disk, network, or concurrency. It is a
coordination service, not a task, plan, model, sandbox, or scheduler authority.
Those services retain their own state and ask the governor for a bounded
decision before starting work.

## Contracts

- `ResourceSnapshot` records only observed telemetry. Unsupported probes remain
  `None`; no host capability is inferred from a missing value.
- `ResourcePolicy` is immutable for a governor instance and defines pressure,
  battery, low-disk, concurrency, model-degradation, and background-yield rules.
- `ResourceBudget` describes one bounded request. It does not grant a
  permission or alter a PlanningEngine/task budget.
- `ResourceDecision` is `ALLOW`, `REDUCE`, `DEFER`, or `DENY`, with an effective
  budget and reasons. A decision never authorizes a tool effect.
- `ResourceReservation` is released exactly once, idempotently, with
  `COMPLETE`, `CANCEL`, `CRASH`, or `TIMEOUT`. Expiry is treated as timeout.

`SystemResourceTelemetry` is best effort. It uses safe standard-library/OS
probes for memory, CPU load where available, disk, Windows power state, and
Windows user-idle time. GPU/VRAM and heavy-foreground-workload values remain
unknown unless a trusted host probe supplies them. Tests inject deterministic
fake telemetry.

## Priority behavior

`INTERACTIVE` and `USER_REQUESTED` work is not cancelled by pressure. Lower
priority `BACKGROUND`, `MAINTENANCE`, `BENCHMARK`, and `INDEXING` work may be
deferred. Benchmarks default to defer on battery; indexing and background
research yield under pressure; large disk operations defer when free space is
low; pressure may reduce concurrency and tell model routing to unload cold
models or choose a smaller acceptable model.

The governor does not silently release another owner's reservation. A caller
must report its own terminal outcome. No reservation is a durable task or audit
record; if durable resource history is required, that future domain must first
be added to `docs/authoritative-state-map.md`.

## Consumers

The composition root creates one governor and passes it to the provider/model
router and startup warmup. Knowledge indexing, generated capability
acquisition, sandbox process admission, and the feature-gated multi-agent
scheduler accept the same governor when constructed. Components use the
governor for admission only; PermissionBroker remains mandatory for privileged
effects and ResourceGovernor cannot grant authority.

Resource decisions are advisory to model selection but authoritative for
admission. Router/provider failures still degrade through the normal provider
fallback policy. Warmup, indexing, background work, and generated capability
setup may be skipped and retried later rather than blocking the desktop or
cancelling an important foreground task.
