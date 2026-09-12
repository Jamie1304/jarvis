# VM host bridge security

The host bridge is a brokered request boundary, not an RPC tunnel. Guests,
generated capabilities, repair agents, and models can submit requests but
cannot authorize themselves, impersonate a trusted identity, broaden scope,
change VM classification, or mutate policy.

Every request binds a request ID, task ID, guest instance ID, exact operation,
narrow resource and scope, risk, and optional expiry. Approval is supplied only
by an application-injected verifier bound to the trusted permission workflow;
it is not a guest-controlled request field. Wildcards are rejected and approval is deny-by-default. The trusted
application remains responsible for routing a request through `PermissionBroker`
and trusted approval where required. `CredentialVault` secrets are never
injected into a guest; future authenticated use should use opaque references
and a trusted broker.

Ordinary VM work must not move the host mouse, inject keyboard input, steal
focus, mutate clipboard, launch arbitrary host applications, or execute
arbitrary host processes. Those capabilities are separate, scoped bridge
operations and are not implied by guest command execution. Existing sandbox,
generated-code isolation, audit, recovery, Safe Mode, and `UNKNOWN_OUTCOME`
semantics remain authoritative.

## WSL2 boundary

The JARVIS Workbench uses a dedicated Ubuntu 22.04 WSL2 distribution with
per-distro `/etc/wsl.conf` settings that disable automatic Windows drive
mounts, Windows executable interop, and Windows PATH injection. This reduces
ambient host authority for ordinary guest work; it is not equivalent to a
full Windows VM and WSL networking is not complete network isolation.

The provider accepts only exact persisted JARVIS-owned distribution records.
It never adopts or unregisters a foreign distribution based on a substring
match. Persistent Workbench state is retained across terminate/start. Test and
repair environments use separate identities and are disposable through the
official WSL export/import workflow. Provider snapshot/revert is not claimed
where WSL has no corresponding primitive.

Host input/UI checks are negative by design: ordinary guest commands do not
move the mouse, inject keyboard input, change focus or clipboard, launch GUI
applications, or create unrequested host processes. A future host operation
must still cross the existing trusted Host Bridge and `PermissionBroker`; WSL
interop is not a substitute for that authority path. A local model may be
made available through `ModelInferenceBroker` when its protocol is implemented,
without re-enabling arbitrary Windows executable interop.
