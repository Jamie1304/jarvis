# Controlled application manager

## Boundary

The application manager is optional and is never added to the default tool catalog.
Its required path is:

`AI/planner -> typed application tool -> PermissionBroker -> policy + trusted approval -> immutable plan -> provider/runtime -> Windows`

The model may request a semantic name, stable inventory ID, or opaque plan ID. It
cannot provide an executable path, a package-manager shell command, a package source,
permission state, or approval claim. Inventory and package results are provider
evidence; only trusted composition creates providers and only the manager creates
plans.

## Discovery, launch, and close

`WindowsRegistryInventoryProvider` reads standard uninstall registry locations and
normalizes records to stable IDs, display name/version/publisher, source, status, and
an executable only when a direct display-icon path resolves to an existing `.exe`.
Registry data is not sufficient authority to run a path. The manager resolves a fresh
record, checks `ApplicationRuntime.can_launch`, and passes that record—not caller
text—to `WindowsApplicationRuntime`. The runtime uses `Popen([executable],
shell=False)` with standard handles disabled. It tracks started processes and refuses
to close a PID it did not launch; close may terminate unsaved work and is high risk.

Inventory status `broken` means no safely verified executable was found. A valid
already-installed record is returned from `plan_install` rather than reinstalled.

## Package plans and winget

`PackageProvider` is a provider abstraction, not an OBS integration. The optional
`WingetPackageProvider` receives a trusted composition-owned candidate catalog and
constructs fixed argument arrays for `winget.exe install` or `winget.exe upgrade`.
It does not accept a raw shell string and does not dynamically execute provider search
text. An `InstallationCandidate` contains exact ID/source/publisher/version,
requested permission, selection reason/confidence, and expected verification data.

`application.plan_install` creates an expiring, immutable, one-use plan. It has no
package side effect. `application.install` and `application.update` need
`application.install` scoped to that exact package ID and always require a fresh
trusted-user approval because they use `software_installation`. Approval may not be
remembered. Update planning is separate, requires a strictly newer normalized numeric
version, and does not silently downgrade.

After a provider operation, the manager re-queries inventory, checks expected
name/publisher/version and executable status, then verifies launch capability. It
returns failure rather than claiming installation success if any evidence disagrees.

## Configuration

There is intentionally no generic configuration tool. `ApplicationConfigurationAdapter`
and `ConfigurationRegistry` exist only for future reviewed, application-specific
adapters with a strict setting schema and a reliable documented API/config contract.
An unknown application has no configuration capability.

## Windows manual test

Do this only on a disposable Windows test machine and only after composing an explicit
`WindowsRegistryInventoryProvider`, `WingetPackageProvider`, `WindowsApplicationRuntime`,
application-tool catalog, PermissionBroker policy, and trusted approval UI.

1. Verify `application.find` detects a known installed application without launching it.
2. Create an install plan for a disposable approved package and inspect exact package
   ID, source, publisher, and version in the trusted approval UI.
3. Deny approval and confirm no `winget.exe` process is created.
4. Approve once, execute the same plan, and confirm it cannot be replayed.
5. Confirm the manager reports success only after an inventory re-query and launch
   capability check.
6. Plan an update with a newer version; verify an equal/older target is rejected.
7. Launch the managed app, then attempt close with an untracked PID and confirm denial.

No Windows registry, winget, installation, update, or application launch is exercised
by normal CI.
