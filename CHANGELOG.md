# Changelog

All notable JARVIS release changes are recorded here. Dates describe the
working-tree release preparation date and are not a claim that a public release
has been published.

## [1.0.0] - 2026-08-24

Release-candidate preparation for the minimal adaptive core.

### Added

- Canonical PlanningEngine task execution with GoalSupervisor intent
  persistence and bounded Agent Runtime execution.
- Trusted Core, PermissionBroker, policy, audit, CredentialVault and data
  classification boundaries.
- Generic filesystem, process, application, accessibility, browser-semantic,
  voice, audio, camera, vision, clipboard and presentation primitives.
- Capability discovery and acquisition contracts using discover, adopt, reuse,
  build, review, sandbox, certify, Shadow, Canary, Active and verification
  stages.
- Integration Package validation, sandbox host brokers, lifecycle state,
  effect attestation, hot-loading and behavior-drift containment.
- Event Automation, Skills, WorkflowTemplates, ArtifactStore, User Model,
  documentary Knowledge Libraries, EnvironmentDiscovery and ResourceGovernor.
- PresenceProjection, PresentationSurface, UI simulation evidence,
  PlanStudio, human-readable Trace, effect preview/compensation and
  ComponentDoctor contracts.
- Encrypted backup/migration, recovery/LKG handling, UpdatePreview,
  SetupConductor, AttentionPolicy, Golden Workflow regressions and the
  deterministic `v1-acceptance` system suite.

### Security and privacy boundaries

- External/model content remains untrusted data and cannot create authority.
- Existing-capability adoption now requires trusted Windows file identity,
  bounded content hashing, Authenticode status, independent dependency
  provenance, exact expiring attestation, and immediate pre-use reinspection;
  adoption evidence never grants permission.
- Generated code remains outside Trusted Core and cannot self-authorize,
  self-certify or self-promote.
- Privileged operations remain brokered and raw credential bytes remain in the
  external secure credential authority.
- Donor projects are reference/provenance material only; no donor runtime is a
  required dependency.
- Speech recognition is not owner authentication for privileged approval.

### Known limitations

- The default composition does not claim physical voice, camera, browser,
  desktop UI Automation, MCP, or hostile generated-code acceptance without the
  required optional backend and manual evidence.
- The canonical generated executable path has local capability-free
  AppContainer/ACL/explicit-handle/Job evidence. This is not VM,
  dedicated-account, kernel, or universal same-user hostile-code isolation;
  direct uncomposed process paths remain outside the claim.
- Authenticated local recovery/LKG evidence and independent local adoption
  identity/provenance evidence are implemented for the declared generic
  contracts. A complete signed self-update executor remains a separate release
  gate; this changelog does not authorize release.
