# Windows integration isolation

Status: `RESOLVED FOR THE CANONICAL EXECUTABLE PACKAGE PATH; FAIL-CLOSED WHEN UNAVAILABLE`

Date: 2026-08-24

This is the security contract for generated executable Integration Packages
launched through `SandboxProcess` on Windows. It is deliberately narrower than
a claim that arbitrary code is universally safe. Generated code remains outside
Trusted Core and receives no `PermissionBroker`, `PolicyEngine`, `CredentialVault`,
approval authenticator, mutation authority, trusted audit writer, or
`RuntimeContainer` object.

The production activation gate requires an observed
`SandboxSecurityStatus.executable_isolation` result. A missing, malformed, or
weaker result prevents executable packages from certification/activation. The
restricted-token and Job-only modes remain useful explicit diagnostic modes;
they are not acceptable substitutes for the executable package contract.

## Selected native design

The canonical Windows launch is composed as follows:

1. Trusted JARVIS resolves the executable identity and requires it to be below
   an owned, regular runtime root. Reparse points and path escapes are refused.
2. JARVIS creates a unique capability-free AppContainer profile. The security
   capabilities attribute contains the AppContainer SID and zero declared
   capabilities. No network, device, or other AppContainer capability is
   granted by this launch.
3. JARVIS grants the profile read/execute access to the staged runtime and
   dependency roots, and full access only to the disposable per-run sandbox
   root. Parent directories receive only the traversal permission needed to
   reach an approved root. Existing ACLs are restored when the process lease
   ends.
4. JARVIS creates the child suspended with an explicit standard-handle list,
   a sanitized environment, fixed arguments, and no trusted handle inheritance.
5. The suspended process is assigned to a Job Object before it is resumed.
   Active-process, memory, kill-on-close, timeout, cancellation, and process-tree
   lifecycle controls remain owned by that Job Object.
6. The only application IPC is bounded, versioned JSON over the listed stdio
   handles. Host effects still require typed JARVIS broker requests.
7. Shutdown closes the owned process/Job handles, restores temporary ACL leases,
   deletes the temporary AppContainer profile, and removes the disposable
   sandbox directories. Cleanup failure is surfaced as sandbox failure; no
   weaker launch is attempted.

The AppContainer profile is created per launch rather than being a long-lived
authority. Its generated profile name is retained only as sanitized activation
evidence; SID and native handles never cross IPC or enter ordinary data stores.

## Actual boundary

### Process lifecycle containment

`Job Object` membership is established while the child is suspended and before
resume. When the native calls succeed, Windows provides active-process and
memory limits for Job members and kill-on-job-close semantics. This is lifecycle
containment, not a guarantee against every possible Job breakaway or kernel-level
attack. The manager also performs bounded cleanup of locally observable
descendants; that cleanup is application hygiene, not an OS security claim.

Timeout, cancellation, crash, malformed IPC, and shutdown all use the same
owned termination path. A failed Job/profile/token/ACL/handle/process setup
returns `SandboxIsolationUnavailable` and does not fall back to an unrestricted
child.

### Privilege and token containment

An AppContainer is a restricted Windows security context. With zero declared
capabilities, direct network/device access is outside the selected launch
contract. The child is not given the parent process token or any trusted handle.
The native process has the AppContainer identity created by trusted JARVIS; the
generated package cannot select its profile, capabilities, or token.

This is not a VM, a kernel boundary, a dedicated service account, or a proof of
code integrity. The package can still execute code available inside its staged
runtime and its AppContainer data area. That is why code review, certification,
broker policy, Shadow/Canary, behavior drift, and verification remain required.

### Filesystem and network containment

The AppContainer access check plus the temporary ACL contract limits the child
to the runtime/dependency roots and its disposable writable sandbox root. The
repository-owned Windows test reads/writes an outside synthetic file and is
denied, while a file in the owned data root is writable. A local loopback probe
is denied for the capability-free profile. These are local defensive tests, not
network scanning.

The root selection still occurs in trusted code and rejects symlink/junction/
reparse roots. Windows ACL and filesystem TOCTOU semantics are not claimed to
be stronger than the operating system provides; the implementation does not
promise handle-relative protection for every future filesystem operation.

### Broker boundary

The OS boundary limits ambient access; it does not turn arbitrary child code
into a trusted client. Network, filesystem, process/provisioning, device,
browser, and credential effects must use the corresponding typed host proxy:

```text
generated process
  -> bounded typed IPC
  -> validated capability broker
  -> ToolRegistry
  -> PermissionBroker -> Policy -> approval when required
  -> trusted application adapter
```

MCP descriptions, package data, model output, page text, and child responses
remain untrusted data. A broker request cannot carry a fabricated approval or
credential secret. The Vault resolves opaque references on the trusted side.

## Native option evaluation

| Mechanism | Decision | Actual claim |
| --- | --- | --- |
| AppContainer with zero capabilities | **Selected** | OS-enforced restricted identity and capability deny-by-default for the canonical launch. |
| Job Object | **Selected** | OS-enforced Job lifecycle/resource controls for members; not a complete security boundary by itself. |
| Scoped filesystem ACLs | **Selected** | OS access checks are applied to approved roots for the profile; existing ACLs and TOCTOU limitations remain explicit. |
| Restricted token | **Retained** | Explicit diagnostic/compatibility hardening. It is not used as the generated executable production contract. |
| Integrity-level change | Not separately selected | AppContainer restriction is used; JARVIS makes no independent low-integrity claim. |
| Capability SIDs | **Selected conservatively** | Zero optional capabilities are declared. Future capability grants require a new reviewed contract. |
| Explicit handle list | **Selected** | Only the three required stdio/NUL handles are eligible for inheritance. |
| Environment sanitization | **Selected** | Only trusted startup variables and AppContainer temporary paths are supplied. This is not a secret boundary by itself. |
| Process mitigation policy | Not selected | No untested mitigation claim is made. |
| Dedicated account / VM / Windows Sandbox | Not selected | Not required by the native v1 path; may be needed for stronger hostile-code assurance. |
| Direct network firewall rule | Not selected | Capability-free AppContainer denial is the OS contract; broker host/origin policy remains mandatory. |

## Guarantee classes

### `OS_ENFORCED`

Only after native status reports success:

- capability-free AppContainer identity and zero optional capabilities;
- Windows access checks for the AppContainer token and package SID on the
  approved ACL roots;
- no unlisted inherited handles through the explicit handle-list attribute;
- suspended creation and Job assignment before resume;
- Job active-process, memory, and kill-on-close behavior for Job members;
- Windows semantics for the process, AppContainer profile, ACL, and Job handles.

### `BROKER_ENFORCED`

- strict IPC schema, request identity, package identity, and message bounds;
- capability/manifest/action/scope/permission checks;
- `ToolRegistry -> PermissionBroker -> Policy` for privileged effects;
- opaque CredentialVault references and trusted-side authenticated requests;
- broker audit/effect attestation, verification, and Shadow/Canary rules.

### `APPLICATION_POLICY`

- only trusted composition may choose AppContainer roots, profile, and
  capabilities;
- `PackageCertifier(require_executable_isolation=True)` rejects executable
  packages without a successful status;
- `PackageActivationService(require_executable_isolation=True)` rejects them
  before `CERTIFIED`, `SHADOW`, `CANARY`, or `ACTIVE` lifecycle use;
- a fresh package version does not inherit an old version's isolation evidence;
- unavailable or malformed native setup is observable and fail-closed.

### `BEST_EFFORT`

- environment minimization, exact executable resolution, and fixed arguments;
- owned/reparse-checked directory creation and cleanup;
- temporary ACL restoration and profile cleanup;
- bounded cleanup of descendants not retained by the Job;
- local timing around blocking native calls.

### `NOT_GUARANTEED`

This implementation does not claim:

- VM, kernel, driver, or dedicated-account isolation;
- prevention of every AppContainer escape, code injection, DLL/interpreter
  vulnerability, or kernel exploit;
- denial of resources explicitly made available inside the runtime or
  AppContainer data area;
- universal protection against future filesystem reparse/TOCTOU races outside
  the validated launch roots;
- that direct MCP, terminal, UI, or other process paths are upgraded merely by
  importing this module. Those paths remain independently gated and cannot be
  used to activate an executable generated package without the canonical
  production boundary.

## Local defensive evidence

Repository-owned synthetic tests (Windows-only where applicable) cover:

- capability-free AppContainer identity/status and profile evidence;
- package data write success and outside synthetic file read/write denial;
- capability-free local loopback denial;
- explicit trusted-handle non-inheritance;
- Job process-tree cleanup, process/resource bounds, cancellation, timeout,
  crash, restart, and shutdown;
- malformed AppContainer configuration and unavailable mandatory primitive;
- certification and activation refusal without executable isolation;
- persisted activation mode evidence through the lifecycle record.

The targeted run for this remediation was:

```text
.venv\Scripts\python.exe -m pytest \
  tests/test_windows_sandbox_native.py tests/test_sandbox.py \
  tests/test_package_certification.py tests/test_package_activation.py \
  tests/test_capability_lifecycle.py tests/test_capability_acquisition_runtime.py \
  tests/test_v1_acceptance.py -q
101 passed
```

The AppContainer probes use only temporary repository test directories and a
local synthetic socket. No external target, credential, or network was used.
Hardware/manual UI, camera, microphone, browser-companion, burn-in, and
third-party integration checks remain unexecuted and are not represented as
passing evidence.

## R2B-H01 disposition

The previous finding was that a same-user child plus a Job Object was not an OS
security boundary. That statement remains correct for the old restricted-token
or Job-only modes. The canonical generated executable path now has a material
native AppContainer, zero-capability, ACL-scoped, explicit-handle, pre-resume
Job boundary and rejects activation when it cannot establish it.

**R2B-H01: `RESOLVED` for the canonical generated IntegrationPackage /
`SandboxProcess` path; not a blanket approval of uncomposed direct process
launches.** Direct MCP/terminal paths that do not use this boundary remain
separately unavailable for hostile generated activation. The overall v1 release
gate remains `NO-GO` while unrelated recovery, adoption, hardware, or other
release findings remain open.
