# Generic SetupConductor

`SetupConductor` is the native orchestration layer for first-run onboarding,
model setup, generated integration installation, migrations, and repair. It is
not a package catalog, a task engine, a permission authority, or a replacement
for `ProvisioningEngine`.

The flow is:

```text
inspect -> detect/adopt -> one setup interview -> SetupContext
  -> provision missing typed actions -> configure -> verify
  -> first-start test -> persist SetupRun
```

## Typed contract

- `SetupContext` contains normalized configuration, user choices, workspace,
  and opaque credential references. It cannot contain raw secret fields and
  it never grants permission.
- `SetupRequirement` describes a decision once. A `DecisionCollector` receives
  all missing requirements and adoption candidates for the run, preventing
  independent component interviews from asking the same question repeatedly.
- `AdoptionCandidate` records existing location, compatibility, configuration,
  and user-data evidence. It is evidence, not trust or ownership.
- `SetupStep` names a component and explicit dependencies. Its handler inspects,
  prepares a typed provisioning plan, configures, verifies, and runs a
  first-start check.
- `SetupRun` records decisions, step states, context fingerprint, and recovery
  state in `InMemorySetupStore` or versioned `SQLiteSetupStore`.

## Adoption and safety

Compatible existing installations are preferred. `USE_IN_PLACE` does not move,
copy, or overwrite them. `IMPORT_COPY`, `RECONFIGURE`, and `INSTALL_NEW` are
explicit choices; `IGNORE` leaves an existing candidate untouched. Existing
user folders are never imported implicitly.

Only missing effects reach the injected provisioning callback. That callback
must use the typed `ProvisioningPlan`/`ProvisioningEngine` path, so destructive
changes still pass `Tool -> PermissionBroker -> Policy -> approval` with an
approval scoped to the exact action. Setup cannot bypass policy, create an
approval, or expose Vault secrets.

## Resume and persistence

Each run has a stable ID and context fingerprint. Re-running a run re-inspects
reality, verifies completed steps, resumes incomplete steps, and avoids a
second installation after successful verification. A changed context requires
a new run. SQLite setup state uses WAL, foreign keys, a busy timeout, and
future-schema refusal. Setup state is coordination evidence only; it does not
become task/plan, credential, audit, artifact, or permission truth.

Handlers remain generic and injected. No donor framework, service-specific
integration, or arbitrary shell script is required by the core.
