# VM execution fabric

JARVIS treats the physical host as a protected resource. Tasks that do not
need host state route to a JARVIS-owned persistent Workbench VM by default.
Tests and untrusted provisioning use disposable test VMs; candidate repair
uses a disposable repair VM. Deterministic internal work stays inside the
trusted application. Host execution is exceptional and must be justified by a
host application, physical device, exact host mutation, trusted compute
broker, or explicit user request.

## Contracts

`VirtualizationProvider` is provider-neutral and exposes probe, create/start,
guest readiness, explicit executable-plus-arguments execution, snapshot,
revert, stop, destroy, and instance enumeration. `InMemoryVirtualizationProvider`
is deterministic CI infrastructure; it does not claim to be a real VM or
execute commands on the host.

Instances carry a random identity, template, purpose, owner task, lifecycle
state, network policy, and the immutable `jarvis-owned` metadata tag. The
fabric enforces conservative per-purpose quotas and reconciles only persisted
owned identities. It never stops a machine based on a display name.

The Workbench is persistent and is not destroyed during ordinary shutdown.
Disposable environments are cleaned after execution; a cleanup error must be
recorded as an orphan for later reconciliation rather than retried forever.

## Guest boundary

Guest commands are typed, bounded, timeout-aware, cancellable, and carry a
request ID. The contract has no pickle or arbitrary object deserialization and
does not confer host authority. File transfer and artifact staging remain
explicit future fabric operations; guest output is evidence, not trusted state.

Network policy is explicit (`NO_NETWORK`, `INTERNET_ONLY`, restricted
destinations, or full VM network). No host-private service, Trusted Core IPC,
CredentialVault, or unrestricted host filesystem is exposed by default.

## Routing and host bridge

`ExecutionRouter` is deterministic and cloud-free. Its reason is operational
metadata, not model reasoning. `HostBridge` requests bind task, instance,
request, operation, resource, scope, risk, approval, and expiry. It denies by
default, rejects wildcard scope, and cannot be used by a guest to grant or
broaden its own permission. A guest never receives `PermissionBroker`,
`CredentialVault`, or trusted-core objects; privileged host effects remain
owned by existing trusted services.

Local model inference may remain host-side through a future
`ModelInferenceBroker`; compute access does not imply GUI, filesystem, or
desktop authority.

## Recovery and Safe Mode

The provider abstraction is optional infrastructure. Safe Mode and recovery do
not require it to be healthy; they may report unavailable backends, stale
leases, or owned orphans while retaining diagnostics and rollback access.
Unknown provider machines are not automatically destroyed.

## Current host status

`jarvis.vm.host_probe.probe_windows_host()` performs a read-only probe. A
running `Win32_ComputerSystem.HypervisorPresent` takes precedence over the
pre-hypervisor processor fields `VirtualizationFirmwareEnabled` and
`VMMonitorModeExtensions`; those fields may be false after Hyper-V has taken
control and must not trigger BIOS remediation. Functional WSL2 guest execution
is the strongest readiness evidence.

## WSL2 backend

`WSL2VirtualizationProvider` is the real Windows provider for the persistent
`jarvis-workbench` distribution and disposable test/repair distributions. It
uses only the installed WSL CLI, persists exact instance identities outside
the repository, and reconciles only records carrying `jarvis-owned` metadata.
The supported lifecycle is start, readiness, execute, terminate, unregister,
enumerate, export, import/clone, and reconciliation. WSL does not provide the
provider-neutral snapshot/revert primitive, so those operations are explicit
unsupported results rather than simulated state.

The Workbench is an Ubuntu 22.04 LTS WSL2 distribution, not a full Windows VM.
Its per-distro `/etc/wsl.conf` disables automatic Windows drive mounts,
Windows executable interop, and Windows PATH injection, and selects the
dedicated non-root `jarvis` user. The `/mnt/c` directory can still exist as an
empty path; mount state, not path existence, is the isolation check. WSL2
networking remains shared/NAT-like and is not a complete network-isolation
boundary. Host GUI/input and host filesystem authority remain outside the
guest and are available only through the protected Host Bridge and
`PermissionBroker`.

Official WSL `export`/`import --version 2` is the disposable clone mechanism.
Archives and distro data belong under application data such as
`%LOCALAPPDATA%\\JARVIS\\vm`, never in Git or package output. Safe Mode and
trusted recovery remain usable when this optional provider is unavailable.
