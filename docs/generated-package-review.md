# Generated package static review

`GeneratedPackageReviewer` is a native, data-only security review boundary for
generated integration packages. It never imports or executes package code,
starts a subprocess, installs a dependency, changes a registry, or changes
reviewer, policy, or approval state. Its result is a static gate only;
certification, trusted composition, `PermissionBroker`, Shadow, Canary, and
package lifecycle still own activation.

## Input and output

The reviewer consumes the validated `IntegrationPackage` contract, bounded
source snapshots whose paths and SHA-256 hashes must match immutable package
entries, and untrusted declarations for hooks, binaries, network destinations,
credential scopes, persistence paths, and UI actions.

It returns one of:

| Result | Meaning |
| --- | --- |
| `PASS` | The supplied metadata and source passed static checks. No authority is granted. |
| `PASS_WITH_RESTRICTIONS` | Effects remain constrained by the named broker/proxy or repair gate. |
| `MANUAL_REVIEW_REQUIRED` | A trusted human/reviewer must resolve provenance, binary, dependency, network, migration, runtime, or elevated-permission risk. |
| `REJECT` | A contract violation or unsafe behavior was detected. The package cannot proceed to certification. |

The result contains bounded findings with category, stable code, severity,
message, and optional package path. Results are deterministic for the same
inputs except for the review timestamp.

## Checks

The review covers manifest/layout/schema boundaries, lifecycle state, provenance
consistency, exact package/source hashes, exact dependency versions or content
hashes, arbitrary install hooks, opaque binaries, services/MCP runtimes,
migrations, dynamic execution/imports, unsafe deserialization, shell/process
spawning, direct network clients, path traversal, secret logging, exact HTTPS
network destinations, private-address rejection, opaque Vault references,
credential scope, package data/cache persistence, update/uninstall preservation,
UI approval spoofing, diagnostic declarations, and permission elevation.

Unknown or unavailable source is not treated as safe: code without a supplied
source snapshot produces `MANUAL_REVIEW_REQUIRED`. Malformed input fails
closed. Static matching is not a proof of safety, so passing never removes
runtime sandboxing, typed host proxies, permission checks, audit, or approval.

Malicious fixtures cover dynamic execution, imports, deserialization, process
and shell use, traversal, secret logging, direct network, fake approval,
dependency/source/hash errors, install hooks, private destinations, raw or
broad credentials, unsafe persistence, and lifecycle/permission hazards.
