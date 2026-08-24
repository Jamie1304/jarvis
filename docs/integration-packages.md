# Generic JARVIS Integration Packages

An Integration Package is a validated, versioned contract for an optional
capability boundary. JARVIS has no integration catalog in this contract. A
package may declare a manifest, tools, MCP adapters, API/backend adapters,
services, events, Skills, profiles, UI assets, settings schema, permissions,
Vault-reference secret schema, health, tests, migrations, lifecycle,
diagnostics, repair declarations, provenance, and a dependency lock.

The package model is descriptive. It does not discover, install, execute,
authorize, or provide a second task/control plane. Any actual action still
passes through the existing ToolRegistry, PlanningEngine, PermissionBroker,
policy, approval, audit, and recovery boundaries.

## Data separation

These boundaries are permanent:

| Boundary | Ownership and update rule |
| --- | --- |
| Package code | Immutable, versioned, hashed, and provenance-certified package content. |
| User config | External versioned schema; never package source and never silently deleted. |
| Package data | External migratable data; never assumed disposable package source. |
| Credentials | Vault references only; package metadata never contains secret values. |
| Generated cache | External, disposable, and rebuildable; it is not trusted package code. |

`PackageOperationPolicy` explicitly preserves user configuration and package
data. Package update/uninstall declarations cannot remove them or Vault
credentials. A future lifecycle executor must apply these rules through trusted
policy and record migration/rollback evidence.

Before staged activation, a generated package must complete the native
`PackageCertifier` pipeline documented in
[`package-certification.md`](package-certification.md). Certification binds
the exact package/source/dependency/manifest hashes, test and audit evidence,
permissions, trusted authority decision, install/health/verification evidence,
and rollback target. `CERTIFIED` is not `ACTIVE`; `PackageActivationService`
owns the trusted version lifecycle and gates Shadow, bounded Canary, promotion,
quarantine, and rollback before the serialized hot-load manager registers a
runtime. Generated package code cannot self-promote.

Paths are portable relative paths with no traversal, absolute path, drive,
reparse-style ambiguity, empty segment, or arbitrary asset loading. UI assets
must be immutable package-owned entries below the validated asset root or
opaque `ArtifactRef` values. They cannot be caller-supplied filesystem paths.

## Diagnostics

The optional diagnostics contract contains known failure signatures,
read-only diagnostic probes, safe repair declarations, fallback hints or
fallback strategies, and expected repair-verification evidence. Probes must be
read-only. Repairs must declare permissions and cannot disable approval. The
runtime `ComponentDoctor` binds declarations to trusted application-owned
callbacks and routes them through the normal health, broker, sandbox, and
verification boundaries. Package metadata itself does not authorize repair;
unknown outcomes are quarantined and never blindly replayed.

Generated package source and security surfaces are reviewed by the native
data-only `GeneratedPackageReviewer`; see
[`generated-package-review.md`](generated-package-review.md). A `PASS` result
does not activate a package or replace sandbox, host-proxy, broker, audit,
certification, Shadow, or Canary gates.
