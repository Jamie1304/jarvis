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

On Windows the default executable launch additionally uses a capability-free
AppContainer, scoped ACLs, an explicit standard-handle list, and a Job Object.
Restricted-token and Job-only modes are explicit diagnostic/degraded modes, not
silent fallbacks. The exact native claims and residual limits are recorded in
`docs/security/windows-integration-isolation.md`.

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

On Windows the manager creates a native Job Object before launch. The canonical
AppContainer launcher creates the child suspended, applies the capability-free
security context and scoped ACLs, assigns it to the Job Object before resume,
and configures kill-on-job-close, active-process and per-process memory limits.
Standard-handle inheritance is explicit. Shutdown also performs bounded cleanup
of exact locally observed descendants that escaped normal Job membership. The
ledger binds each PID to its creation time and validates its native parent edge,
so it never targets a process merely by executable name or a reused PID. That
cleanup is lifecycle hygiene, not a guarantee against every breakaway.

Where JARVIS needs to prove that a Job has no remaining members, it queries
`JobObjectBasicAccountingInformation.ActiveProcesses` through
`QueryInformationJobObject`. A Job handle signal is not interpreted as process
membership evidence. Query failure is containment failure, never an implicit
empty Job.

On non-Windows, the manager uses a new process session/group and bounded
termination, but does not claim equivalent OS resource enforcement. Windows Job
Object setup failure is an isolation failure; there is no silent uncontained
fallback on Windows.

## What this does not guarantee

Windows Job Objects provide process-tree ownership and resource accounting, not
a complete security sandbox. The canonical executable boundary uses a
capability-free AppContainer and scoped ACLs, but it does not claim VM/kernel
isolation, code-signing enforcement, universal TOCTOU protection, or safety of
uncomposed direct MCP/terminal process paths. The manager does not pass source
paths, but absence of a passed path is not filesystem protection by itself.

Therefore the canonical executable package path has a native Windows boundary,
but it remains subject to certification, broker policy, Shadow/Canary, drift,
and independent verification. If AppContainer/profile/ACL setup is unavailable,
production executable activation is refused; there is no weaker fallback.

## Security tests

`tests/test_sandbox.py` covers JSON/type validation, environment minimization,
dedicated paths, response identity spoofing, oversized request/response,
crash/timeout/cancellation containment, bounded restart, process-tree cleanup,
explicit handle non-inheritance, restricted-token status, capability-free
AppContainer identity, outside-root filesystem denial, local loopback denial,
fail-closed mandatory setup, and malformed configuration. No donor project is
imported or required at runtime.
