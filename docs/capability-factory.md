# Central CapabilityFactory

`CapabilityFactory` is the central, provider-neutral acquisition coordinator
for a `CapabilityGap`. Its hard order is:

```text
DISCOVER -> ADOPT -> REUSE -> BUILD
```

It consumes a `CapabilityGap`, `SolutionReport`, machine `AdoptionCandidates`,
scoped `WorkspaceContext`, credential-free `EnvironmentGraph`, and explicitly
allowed user-model preferences. Preferences select among safe options; they do
not grant permission, create trusted identity, or turn external metadata into
policy.

## Acquisition

1. Active compatible JARVIS capabilities are reused without generation.
2. Safe compatible machine candidates are adopted through `SetupConductor`.
   In-place use, import/copy, reconfiguration, installation, and ignore remain
   explicit choices. Declined candidates stay inactive and have no authority.
3. Existing API/library/MCP/CLI solutions are reused, or typed support is
   provisioned through `SetupConductor`.
4. Only when earlier paths are unavailable does a generator produce an inactive
   adapter or MCP-server package proposal.

The factory never contains product-specific fixture code. Unknown systems are
treated as evidence requiring compatibility and safety checks, not as trusted
install targets.

## Generated lifecycle

Generated proposals pass through `DESIGNING`, `GENERATING`,
`STATIC_CHECKING`, `SANDBOX_TESTING`, and `SECURITY_CHECKING`. A fully checked
proposal ends at `READY_FOR_APPROVAL`; it is not registered, provisioned,
loaded, or active. Certification, shadow/canary operation, activation,
degradation, quarantine, update, and rollback remain later trusted lifecycle
operations. A declined proposal remains inactive.

Generated package content is the existing validated `IntegrationPackage`
contract: manifest, code, dependencies, permissions, Vault-reference secret
schema, configuration, tests, health/verification, UI, Skills, profiles,
events, migrations, diagnostics, repair declarations, and provenance. Generated
code never becomes Trusted Core or a second task/control plane.

`CapabilityRegistry` remains descriptive metadata only. `SetupConductor` owns
setup sequencing and persistence; `ProvisioningEngine` and the normal
`Tool -> PermissionBroker -> Policy -> approval` boundary own effects.
