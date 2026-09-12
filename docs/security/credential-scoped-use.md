# Credential scoped-use boundary

**Status:** v1 production composition contract
**Updated:** 2026-08-24

`CredentialVault` is the sole secret authority. `RuntimeContainer` creates one
Vault and one `CredentialBroker`. The broker is an application-owned adapter;
it is not passed to integration code, model context, UI, EventBus payloads,
Trace, ArtifactStore, memory, Knowledge Libraries, or backup/export code.

## Production flow

```text
integration/model request
  -> typed CredentialRef metadata
  -> HostProxy / trusted adapter validates identity, action, scope, destination,
     workspace, package hash, expiry, and revocation
  -> ToolRegistry -> PermissionBroker / Policy / approval
  -> CredentialBroker -> CredentialVault -> secure OS backend
  -> trusted adapter constructs the authenticated request
  -> sanitized result, audit, effect attestation, verification
```

`CredentialRef` binds the credential ID to the integration ID, package version
and hash, operation, normalized destination, workspace, exact scope, issue time,
and short expiry. A reference is not a secret and its representation is
redacted. `CredentialVault.resolve_ref()` requires every binding to match and
rechecks status, expiry, association, and scope before reading the secure
backend.

The network host proxy performs PermissionBroker authorization before resolving
the reference. If permission, identity, scope, destination, or reference
validation fails, the secure backend is not read and no request is dispatched.
The only plaintext secret lifetime is inside the trusted host-side adapter while
it constructs the authenticated request; it is not returned as a result.

## Persistence and leakage rules

- SQLite stores credential metadata only; raw bytes are held by the secure
  Windows backend in production. The deterministic in-memory backend is an
  explicit test seam.
- Revocation and expiry deny future reference resolution. A new operation needs
  a new exact reference; references are not reusable authorization receipts.
- References carry a Vault-issued in-memory proof over their binding. A caller
  that constructs or mutates a structurally valid `CredentialRef` without that
  proof is rejected. The proof key is intentionally not persisted, so restart
  invalidates outstanding references and the application must issue a new one.
- Secret values are excluded from exceptions, logs, events, trace fields,
  artifacts, memories, Knowledge Libraries, prompts, UI state, and backup
  bundles. Trace and audit may contain a credential ID or binding metadata.
- Unsupported secure storage fails closed. There is no plaintext fallback.

## Evidence

The production-composition acceptance test
`test_v1_acceptance_vault_uses_runtime_owned_typed_credential_broker` uses a
repository-owned fake secure backend and local `httpx` transport. It proves an
authenticated request succeeds only after the runtime-owned broker path, that
the exact package/workspace/destination/scope binding is used, and that the
reference representation does not contain the synthetic secret. Unit tests
cover wrong integration/package/destination/workspace/action/scope, expiry,
revocation, and opaque-reference validation.

The fake backend and local transport are not evidence of Windows Credential
Manager or external service availability; those remain platform/integration
acceptance items.
