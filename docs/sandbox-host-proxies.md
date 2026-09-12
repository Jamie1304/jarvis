# Trusted sandbox host proxies

Generated integration code remains out of the Trusted Core. When an integration
needs a host capability, the narrow boundary is:

```text
generated integration -> bounded typed IPC -> HostProxy
  -> manifest validation -> PermissionBroker -> Policy -> trusted host adapter
```

The sandbox receives no `PermissionBroker`, policy, Vault master access,
approval authenticator, mutation authority, trusted audit writer, runtime
container, or unrestricted host handle. A proxy is registered as one or more
ordinary broker tools before broker registration is sealed. Each capability is
registered separately so the broker's declared permission set exactly matches
the action descriptor.

## Request contract

Every `HostProxyRequest` carries a UUID request ID, task ID, integration ID,
package hash, capability ID, and action. The trusted proxy requires exact
matches for integration and package identity, then requires an exact declared
capability/action and operation-specific scope. The request cannot carry an
approval or permission claim. Policy and the normal trusted approval path decide
whether the action may proceed. The effect starts only after
`PermissionBroker.begin_execution`; the receipt is completed with an explicit
outcome and cannot be reused.

`HostProxyAuditEvent` is bounded operational evidence. A production adapter
must forward it to the existing authoritative audit service; the in-memory
implementation is test-only. It contains identifiers, action, outcome, and a
safe scope summary, never credential material, request bodies, or file contents.

## Network proxy

Network access is deny-by-default. A manifest lists exact normalized origins;
wildcards, user-info, fragments, and undeclared hosts are rejected. Requests
use `httpx` with `trust_env=False`, bounded timeouts, bounded connections,
bounded request bodies, and bounded response headers/body. Redirects are
rejected unless the manifest enables them, and every redirect is checked again
against the exact origin set and address policy. Private, loopback, link-local,
reserved, multicast, and unspecified addresses are rejected by default. A
manifest must explicitly opt into private addresses for a controlled local
service.

The address check is a preflight defense. DNS and connection routing can still
change after validation (including rebinding or proxy behavior), so a future
stronger implementation should bind the transport to the checked address. No
claim of complete network isolation is made by the Windows Job Object.

Caller headers cannot set `Authorization`, cookies, `Host`, proxy
authorization, or `Set-Cookie`. Network responses are untrusted bounded data.

## Filesystem proxy

The child names only a manifest root ID and a portable relative path. Trusted
composition supplies existing regular directory roots of kind `PACKAGE_DATA` or
`APPROVED_USER`; there is no caller-supplied host root. Traversal, absolute or
drive paths, backslashes, protected components (`.git`, VCS metadata, and
`trusted_core`), symlinks, junctions, and reparse points are rejected. The
proxy also checks configured forbidden roots such as the source checkout and
Trusted Core. Writes are bounded and create-only: an existing trusted file is
never overwritten by this proxy.

Path checks reduce traversal and reparse risk but do not eliminate a TOCTOU
race on a same-user filesystem. Windows certification for hostile code still
needs OS-level ACL/AppContainer or equivalent containment and owned malicious
fixtures. User data roots are explicitly configured and are not inferred from
package source paths.

## Credentials

The child receives and submits only an opaque UUID credential reference plus a
manifest credential-binding ID and bounded scope. The trusted side checks the
binding association and scope, resolves the reference through `CredentialVault`,
and injects the secret into a trusted authenticated network request. The raw
secret is never returned as a proxy result or placed in an IPC message. A wrong
association, scope, inactive/expired credential, or undeclared binding fails
closed. If a provider cannot be represented by a safe trusted request adapter,
the operation is unavailable rather than exposing the secret to the sandbox.

## Process, provisioning, and device actions

The host exposes no arbitrary executable, argument vector, shell, working
directory, or process-spawn endpoint. Process and device operations use a
manifest-declared action and bounded JSON payload schema, then call a trusted
typed executor selected by composition. Process payloads explicitly reject
`executable`, `argv`, `command`, `shell`, and `cwd`. Device/capability actions
are declared in the same way and remain behind `PermissionBroker`; discovery or
external metadata cannot add declarations or grant permission.

These proxies are generic primitives, not a product integration catalog. No
donor project or donor host bridge is imported or required at runtime.
