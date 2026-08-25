# Package certification

`PackageCertifier` is the trusted application coordinator for staged package
certification:

```text
BUILD
 -> STATIC_AUDIT
 -> UNIT_TESTS
 -> SANDBOX_INTEGRATION_TEST
 -> PERMISSION_DIFF
 -> AUTHORITY_DECISION
 -> INSTALL
 -> HEALTHCHECK
 -> VERIFICATION
 -> CERTIFIED
```

The certifier receives injected application-owned hooks. Generated package
code cannot provide hooks, execute itself, approve itself, or alter reviewer,
policy, broker, or approval state. Static audit uses the native
`GeneratedPackageReviewer`; source snapshots are hash-bound and are never
imported or run by the certifier.

## CertificationRecord

An immutable `CertificationRecord` binds:

- package ID, version, package hash, source hash, dependency hash, and
  manifest hash;
- unit-test and sandbox evidence, static audit evidence, permission set, and
  trusted approval reference;
- environment compatibility, health, verification, rollback target, and
  expected behavior baseline; and
- completed stage evidence plus Shadow/Canary eligibility.
- for UI-bearing packages, the trusted UI simulation attestation reference and
  digest (never screenshots or arbitrary UI content).

`CertificationRecord.matches()` invalidates the record if code/source,
dependencies, manifest, version, package hash, or permissions change. A
failed stage raises `CertificationFailure` naming the stage and returns the
partial evidence to the trusted caller; later stages do not execute.

`CERTIFIED` is evidence, not activation. `PackageCertification.from_record()`
adapts a valid record to the existing hot-load gate, while
`HotLoadManager` still separately performs prepared-runtime health checks,
atomic registration, Shadow/Canary gates, and active registration. No package
is active merely because it is certified.

UI-bearing packages are not certifiable without a current
`UISimulationAttestation` from the native `UISimulationHarness`. The harness
must render every declared state, validate bindings and safe assets, inspect
semantic controls, and prove zero simulated external effects. The certifier
derives UI-bearing status from validated package structure (`ui_assets` or
`profiles`); a package cannot turn the requirement off with a false boolean.

The attestation binds package ID/version/hash, the built source hash, UI
manifest hash/schema, harness and policy versions, tested states, check results,
zero-effect evidence, and ArtifactRefs. Missing, failed, malformed, stale,
mismatched, or caller-fabricated evidence fails the `VERIFICATION` stage.
`CertificationRecord` stores only the opaque attestation reference and digest;
render artifacts remain owned by ArtifactStore. Any package/source/UI manifest
change requires a fresh attestation. Activation applies the same certification
record and has an additional fail-closed UI-attestation binding check.
