# Generated integration process isolation

Generated integration code is never imported into the Trusted JARVIS process.
The native boundary is:

```text
trusted application
  -> SandboxProcess
  -> bounded JSON-over-stdio IPC
  -> generated integration process
```

`SandboxProcess` receives only an executable identity, fixed argument vector,
integration ID, dedicated working/data directories, and bounded JSON requests.
It does not receive `PermissionBroker`, `PolicyEngine`, `CredentialVault` or
Vault master access, approval authentication, mutation authority, the trusted
audit writer, `RuntimeContainer`, open application handles, or an inherited
application environment.

## IPC contract

`SandboxMessage` is a strict version-1 envelope containing a protocol version,
UUID request ID, validated integration ID, bounded message kind, JSON-only object
payload, and request/response direction. Frames are newline-delimited UTF-8
JSON. Unknown fields, non-JSON objects, non-finite numbers, malformed UUIDs,
version changes, oversized frames, and response identity mismatches fail closed
and terminate the child. No pickle, Python object serialization, file descriptor,
broker object, or callback crosses this boundary. Requests are rejected before
writing when their encoded form exceeds the configured bound.

## Lifecycle and controls

Each instance creates a unique app-owned sandbox root with separate `work` and
`data` directories. The root and its immediate children reject symlinks,
junctions/reparse points, path escapes, and collisions. Shutdown terminates the
owned process and removes the owned root. A failed request, timeout, cancellation,
protocol violation, or crash contains the child; restart is explicit and bounded.

The child environment contains only the small set of Windows startup variables
needed for process startup (`SystemRoot`/Windows and temporary-directory values),
UTF-8 settings, and a JARVIS sandbox marker. `PATH`, `PYTHONPATH`, user profile,
proxy, credential, Vault, application, and arbitrary `JARVIS_` variables are not
forwarded. Stderr is discarded rather than merged into unbounded IPC or logs.

On Windows the manager creates a native Job Object before launch, assigns the
child immediately after creation, enables kill-on-job-close, and configures
active-process and per-process memory limits. Termination uses the Job Object,
so descendants created by the child are terminated during cleanup. A small
post-launch assignment race exists because the current asyncio subprocess API
does not expose a suspended `CreateProcess`/`STARTUPINFOEX` launch; a future
stronger boundary can close it with native suspended launch and process
mitigation attributes.

On non-Windows, the manager uses a new process session/group and bounded
termination, but does not claim equivalent OS resource enforcement. Windows Job
Object setup failure is an isolation failure; there is no silent uncontained
fallback on Windows.

## What this does not guarantee

Windows Job Objects provide process-tree ownership and resource accounting, not
a complete security sandbox. The current boundary keeps the child in the same
Windows user identity and does not enforce filesystem ACL isolation, network
denial, registry isolation, token reduction, AppContainer capabilities, code
signing, or a full broker-mediated child-process denial. A malicious child that
already knows a path readable by the same user may still read it, and it may
attempt network or OS operations allowed to that user. The manager does not pass
source paths, but absence of a passed path is not filesystem protection.

Therefore this is a native out-of-process containment boundary and a required
integration lifecycle primitive, not a claim that arbitrary malicious Python is
already safe to activate. Production certification of hostile or unreviewed
code still requires a separately evaluated Windows AppContainer/restricted-token
launch, Windows Sandbox/VM boundary, or equivalent OS policy. Such a mechanism
must grant access only to staged package code and the dedicated data directory,
deny source/config/Vault access, and be verified with owned malicious fixtures.

## Security tests

`tests/test_sandbox.py` covers JSON/type validation, environment minimization,
dedicated paths, response identity spoofing, oversized request/response,
crash/timeout/cancellation containment, bounded restart, process-tree cleanup,
and malformed configuration. The process-tree test demonstrates descendant
cleanup on the current Windows host; it does not certify filesystem, network, or
AppContainer isolation. No donor project is imported or required at runtime.
