# Typed generic provisioning

JARVIS provisioning is a provider-neutral coordinator for exact, reviewed host
changes. It is not a package catalog, product integration, service manager,
container runtime, VM runtime, or shell-script runner.

The boundary is:

```text
trusted application -> ProvisioningPlan -> PermissionBroker -> typed provider
  -> inspect reality -> apply one action -> verify reality -> audit outcome
```

## Contract

`ProvisioningPlan` contains immutable task/plan identity, expiry, ordered typed
actions, and an optional exact `ProvisioningRollbackPlan`. Each
`ProvisioningAction` contains:

- action/provider/kind and target identity;
- bounded JSON parameters with raw secret names rejected;
- exact paths, network hosts, command families, application targets,
  artifacts/hashes, disk estimate, and admin requirement;
- one explicit `Permission`, idempotency declaration, dependencies, and expected
  state.

Compound effects must be split into separately authorized actions. A provider
does not receive an arbitrary executable, shell string, giant script, or model
permission claim. `BrokerProvisioningAuthorizer` binds the action kind, exact
action ID, task, scope, parameters, and action fingerprint to the normal
`PermissionBroker` receipt. Approval is therefore only for the exact action.

Supported generic action kinds are `DOWNLOAD_VERIFY`, `INSTALL_PACKAGE`,
`CREATE_ENVIRONMENT`, `INSTALL_DEPENDENCY`, `WRITE_CONFIG`, `SERVICE`,
`CONTAINER`, `VM`, `NETWORK`, `HEALTH_CHECK`, `UNINSTALL`, and `ROLLBACK`.

## Reality and lifecycle

Before every effect, the provider must inspect reality. An already satisfied
action becomes `ALREADY_SATISFIED` and is not approved or repeated. Partial
state is reported to the provider and may be reconciled by a typed idempotent
operation. After application, the provider must report confirmed reality and
pass a health check before the action becomes `VERIFIED`.

Action states are `PENDING`, `READY`, `APPLYING`, `ALREADY_SATISFIED`,
`VERIFIED`, `FAILED`, and `RECOVERING`. Plan results distinguish `VERIFIED`,
`FAILED`, `ROLLED_BACK`, and `RECOVERING`.

An interrupted or unknown effect is never blindly replayed. Resuming the same
plan re-inspects reality first; only an idempotent action whose provider says
`safe_to_retry` may be attempted again. Non-idempotent actions must state why
they cannot be repeated and remain recovering until a trusted resolution. A
checksum mismatch fails before effect execution. Rollback actions are explicit,
typed, separately authorized actions. Each rollback action names the exact
completed action it undoes; unrelated rollback actions are not run. They run
only when the plan declares them.

No durable provisioning authority is introduced by this module. If execution
state becomes durable in a future run, the authoritative-state map and a
versioned recovery store must be updated before activation. Providers remain
injected capabilities and cannot grant permission or become a second task,
package, credential, audit, or artifact authority.
