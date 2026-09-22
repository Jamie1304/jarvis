# Canonical Capability Vocabulary

`CapabilityManifest` is the descriptive contract for one capability exposed by
an integration or by native JARVIS code. It records identity/version, owner,
actions, strict I/O schema descriptions, permissions, risk, platform/network
fit, credential references, dependencies, configuration, health, verification,
UI/voice metadata, provenance/hash, and lifecycle.

Effect metadata records the effect classification, preview support,
reversibility (`READ_ONLY`, `REVERSIBLE`, `COMPENSATABLE`, `IRREVERSIBLE`, or
`UNKNOWN`), compensation guidance, produced artifacts, and emitted events.
These fields describe risk and verification expectations; they do not authorize
execution. Runtime calls still use the existing ToolRegistry, PermissionBroker,
policy, approval, and PlanningEngine boundaries.

## Registry

`CapabilityRegistry` supports explicit registration, unregistration,
inspection, search, capability-gap detection, health lookup, permission lookup,
and dependency lookup. It is a vocabulary/catalog authority, not an execution
engine or a permission broker. A missing dependency or stopped/deprecated
capability is reported as a gap; registering a capability never activates an
integration or grants a permission.

## Environment graph

`EnvironmentGraph` records bounded observations of computers, applications,
services, devices, account references, integrations, capabilities,
model/runtimes, and workspaces. Nodes and edges retain provenance, confidence,
and last-verified timestamps. The graph contains only account references, never
credentials, tokens, passwords, or secret material. It is an observation
projection and cannot become the authority for credentials, permissions,
workspace truth, or task execution.

Capability and graph metadata may be stale or untrusted until independently
verified. Randomized identifiers are used in tests to ensure code does not
silently rely on fixture-specific identity.
