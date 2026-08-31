# JARVIS version and development log

This is a factual engineering and release-candidate chronology. JARVIS has
been developed toward semantic version `1.0.0`; the earlier phases and release
candidates below were engineering milestones, not retroactively assigned
public semantic versions. There are no Git tags in this repository history at
the time of this log.

Use [CHANGELOG.md](CHANGELOG.md) for the concise product-facing summary and
this file for immutable candidate history. Neither file authorizes a tag,
publication, deployment, or public release.

## Pre-v1 development milestones

| Date range | Evidence range | Development milestone |
| --- | --- | --- |
| 2026-08-11 | `bc3f74a` .. `b8de381` | Project baseline, contribution/CI foundation, brokered permissions, generic Windows primitives, controlled self-tests, durable planning, bounded delegation, and early local voice/state contracts. |
| 2026-08-23 | `a334c2e` .. `600092f` | Generic environment discovery, semantic browser bridge, CredentialVault, generated-code sandbox/proxies, provisioning, adoption-first setup, capability factory/review/certification/activation, desktop/onboarding, presentation, verification, trace, GoalSupervisor, specialist workers, and model/resource contracts. |
| 2026-08-24 | `33ff619` .. `d393347` | Hardware/model inventory, User Model and Knowledge boundaries, automation, drift/diagnostics, donor study, self-modification policy, Golden Workflows, recovery, backup, functional acceptance, adversarial acceptance, and architecture audit records. |

The commit ranges are historical pointers, not claims that each listed feature
is independently release-authorized. The detailed architecture and security
records under `docs/` remain the source for their scope and limitations.

## v1.0.0 release-candidate history

Every row below is immutable Git history. Parent, date, and subject were read
from `git log`; CI/audit classifications are recorded from the corresponding
release-preflight and audit records. "Not reconstructed" means this log does
not invent a status where the available release records did not establish one.

| Candidate | Date | Commit | Parent | Subject | Hosted CI record | Independent R4 / disposition |
| --- | --- | --- | --- | --- | --- | --- |
| 1 | 2026-08-25 | `f63b225ec8117c4d4b5e07eff73271f9dfe62911` | `d3933473f00b0c52eebf64ec56ef1dad6906ed07` | `release: prepare Jarvis v1.0.0 release candidate` | `RC_CI_FAILED` | Historical failed RC; not publishable. |
| 2 | 2026-08-25 | `3bee1a268d8e23bb9949c3de7a7bdee3887dee69` | `f63b225ec8117c4d4b5e07eff73271f9dfe62911` | `release: remediate Windows CI sandbox boundary for v1.0.0 RC` | Not reconstructed | `R4_NO_GO`; immutable historical candidate. |
| 3 | 2026-08-25 | `1860c37763c923db97349a437a83963412daab64` | `3bee1a268d8e23bb9949c3de7a7bdee3887dee69` | `release: compose production self-expansion for Jarvis v1.0.0 RC` | Not reconstructed | `R4_NO_GO`; immutable historical candidate. |
| 4 | 2026-08-26 | `69a39ae5b438d09471fa5f9bda90ead98b8df78c` | `1860c37763c923db97349a437a83963412daab64` | `release: complete semantic self-expansion for Jarvis v1.0.0 RC` | Not reconstructed | `R4_NO_GO`; immutable historical candidate. |
| 5 | 2026-08-26 | `57862f6777e3dc1966f8f1c07688fde7257e7428` | `69a39ae5b438d09471fa5f9bda90ead98b8df78c` | `release: fix opportunity failure-state integrity for Jarvis v1.0.0 RC` | Not reconstructed | Source review GO was later superseded by `PACKAGE_FAILED_REQUIRES_NEW_RC`; not publishable. |
| 6 | 2026-08-27 | `6ff54d7b058a61c465d92280d80516103819818c` | `57862f6777e3dc1966f8f1c07688fde7257e7428` | `release: make Jarvis v1.0.0 distribution-ready for private use` | `RC_CI_FAILED` | Historical failed RC; not publishable. |
| 7 | 2026-08-27 | `61c1909035ecfdc65d8bf73ac0b7f4a54c823e59` | `6ff54d7b058a61c465d92280d80516103819818c` | `release: correct Windows handle boundary test for Jarvis v1.0.0 RC` | `RC_CI_FAILED` | Historical failed RC; not publishable. |
| 8 | 2026-08-27 | `5795cfeedd618d98573bb80f54cb7daecdad7f8d` | `61c1909035ecfdc65d8bf73ac0b7f4a54c823e59` | `release: isolate PEP 517 packaging for Jarvis v1.0.0 RC` | Not reconstructed | `R4_NO_GO`; immutable historical candidate. |
| 9 | 2026-08-27 | `6cf44a7ced8f55ca194cad05903a48d75f77f400` | `5795cfeedd618d98573bb80f54cb7daecdad7f8d` | `release: fix opportunity preparation failure state for Jarvis v1.0.0 RC` | Exact-SHA green | `R4_NO_GO`: 104 PASS / 2 FAIL / 0 NOT_PROVEN; criteria 4 and 100 failed. Not packaging-authorized. |
| 10 | 2026-08-28 | `ac7fc45f9332f004349e0c7c0868758cc036c8f2` | `6cf44a7ced8f55ca194cad05903a48d75f77f400` | `release: preserve failed opportunities across observation for Jarvis v1.0.0 RC` | Exact-SHA green | `R4_NO_GO`: 103 PASS / 3 FAIL / 0 NOT_PROVEN; criteria 4, 70, and 86 failed; criterion 100 passed. Not packaging-authorized. |
| 11 | 2026-08-29 | `3bf78458ed5556aaaf72318911874dc85f919be1` | `ac7fc45f9332f004349e0c7c0868758cc036c8f2` | `release: fix security-blocked lifecycle and controlled test runner for Jarvis v1.0.0 RC` | Exact-SHA push CI green: run `33276631872`, job `99164379256` | `R4_NO_GO`: 98 PASS / 8 FAIL / 0 NOT_PROVEN; criteria 4, 17, 25, 26, 30, 70, 86, and 105 failed; criterion 100 passed. Not packaging-authorized. |
| 12 | 2026-08-30 | `b55f8a4dd1364e0c588df0d63de1cd0025b18eba` | `3bf78458ed5556aaaf72318911874dc85f919be1` | `release: close Candidate 11 blockers for Jarvis v1.0.0 RC` | `RC_CI_FAILED`: run `33339183982`, job `99331570440`; quality/workflows/permissions passed, v1 acceptance failed `process_cleanup_failed`, package smoke skipped | Not independently R4-audited; immutable, not packaging-authorized. |

Candidate 11's hosted CI result was real historical evidence for that exact
commit, but the later independent audit found defects in the trusted release
test infrastructure. It therefore remains `R4_NO_GO`; historical green CI is
not evidence for a later mutable tree.

## Current unreleased hardening

Candidate 12 is immutable and permanently `RC_CI_FAILED`; it must not be
amended or used as release evidence. The current working tree is an R4P mutable
remediation of its Windows Job-empty predicate. Its local validation, review,
and exact future Candidate 13 hosted-CI requirements are tracked in
[docs/releases/v1.0.0-rc-preflight.md](docs/releases/v1.0.0-rc-preflight.md).

No semantic version number is being assigned to this mutable work. Candidate
13 can exist only after a normal commit and push, and its CI evidence must be
for that exact resulting SHA.
