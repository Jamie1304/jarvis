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

`CertificationRecord.matches()` invalidates the record if code/source,
dependencies, manifest, version, package hash, or permissions change. A
failed stage raises `CertificationFailure` naming the stage and returns the
partial evidence to the trusted caller; later stages do not execute.

`CERTIFIED` is evidence, not activation. `PackageCertification.from_record()`
adapts a valid record to the existing hot-load gate, while
`HotLoadManager` still separately performs prepared-runtime health checks,
atomic registration, Shadow/Canary gates, and active registration. No package
is active merely because it is certified.

UI-bearing packages are not certifiable without evidence from the native
`UISimulationHarness`. The harness must render declared states, validate
bindings and safe assets, inspect semantic controls, and prove zero simulated
external effects. A caller-provided string is evidence metadata only; the
trusted composition root must obtain it from the harness run. This certifier
does not invent unexecuted UI evidence.
