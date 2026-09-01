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
| 13 | 2026-08-31 | `faccb32c67f1ec54ff99f8142e93f214df41f70d` | `b55f8a4dd1364e0c588df0d63de1cd0025b18eba` | `release: prepare Jarvis v1.0.0 release candidate` | Exact-SHA CI green: run `33368910216`, attempt 2 | `R4_GO_SOURCE` (106 PASS / 0 FAIL / 0 NOT_PROVEN) was superseded by `PACKAGE_CERTIFICATION_FAILED_REQUIRES_NEW_RC`: Run 30 found the installed `RECORD` validator accepted an `INSTALLER` RECORD-only hash mutation. Immutable historical candidate; not certified, tagged, published, or deployable. |

Candidate 11's hosted CI result was real historical evidence for that exact
commit, but the later independent audit found defects in the trusted release
test infrastructure. It therefore remains `R4_NO_GO`; historical green CI is
not evidence for a later mutable tree.

## Current unreleased hardening

Candidate 13 is immutable and retains its exact-source R4 result
`R4_GO_SOURCE` (106 PASS / 0 FAIL / 0 NOT_PROVEN), but Run 30 package
certification rejected its artifacts because installed-distribution integrity
validated only an explicit Trusted Core subset. The following Candidate 13
artifact hashes are rejected historical evidence, not certified release inputs:

- wheel: `68CEF6B0825DFB8153F8CF715D7B297F1EE4475071EA2B8F69D28FF871C05AF0`;
- sdist: `CE92C50FB0622E57FA75B04ED237E90628DA0D6F554E6FF58B00A778C1E0CDD7`;
- sdist round-trip wheel:
  `492D1C264F5DA43926A7FDABBEB611C2DBB20014DDBA2C0C9532CDAC65E5F8A2`.

The current R4Q mutable remediation establishes full canonical installed
`RECORD` inventory validation, including non-critical package members and all
matching dist-info members such as `INSTALLER`; it retains the exact narrow
exceptions for `RECORD` itself and installer-created `__pycache__` bytecode.
The ongoing prefreeze evidence is tracked in
[docs/releases/v1.0.0-rc-preflight.md](docs/releases/v1.0.0-rc-preflight.md).

The R4Q follow-up calibrated the deterministic `v1-acceptance` catalog budget
from 420 to 600 seconds after two controlled production-runner passes completed
23/23 tests in 357.36 and 431.27 seconds. The runner semantics and coverage
threshold were unchanged; the current mutable tree remains unfrozen while the
threshold were unchanged. R4Q-B3 added meaningful fail-closed integrity and
application-boundary regression tests; quality #5/#6 are stable at raw
89.77775098464754%, below the required 90.10% prefreeze target. The current
mutable tree remains unfrozen and Candidate 14 does not yet exist.

No semantic version number is being assigned to this mutable work. A future
Candidate 14 can exist only after separately authorized freeze, normal commit,
push, exact-SHA CI, and independent audit.

R4Q-B4 added narrowly scoped lifecycle, runtime-composition, and application
boundary regression tests. The final full coverage attempt was not a qualifying
green run: one randomized acceptance scenario failed transiently during replan,
and the measured raw coverage was 89.88224419258901%, below the 90.10% prefreeze
buffer. Candidate 14 does not exist.

### R4Q-B5 acceptance replan stability and coverage follow-up

The mutable tree remains based on Candidate 13
`faccb32c67f1ec54ff99f8142e93f214df41f70d`, parent
`b55f8a4dd1364e0c588df0d63de1cd0025b18eba`, branch `agent/v1-integration`,
and version `1.0.0`. Candidate 14 was not created.

The prior randomized acceptance failure was reproduced from its exact source
path: a deterministic execution failure requested replan while the application
and task projections were `EXECUTING`; the state tables rejected the valid
`EXECUTING -> THINKING` replan transition, and the replanned task then required
`THINKING -> WAITING`. The production transition tables now admit those valid
replan projections, with a regression test in
`tests/test_planning_engine.py` proving the persisted transition history.

Serialized stress also exposed a distinct bounded timing defect: generated
capability adapters and the production sandbox used a 30-second request limit,
which could classify native Windows startup under host load as `tool_timeout`.
The limit is now a finite 60 seconds in the generated adapter and both
production sandbox invocation paths, with an alignment regression in
`tests/test_production_capability.py`. This is not an unbounded retry or a
permission bypass; effectful calls remain brokered and bounded.

Evidence after these fixes:

- focused production/planning tests: 129 passed;
- deterministic workflows run `fd28be30-b945-4806-b363-670b0d031b5a`: 26
  passed;
- deterministic permissions run `91ad768b-57d3-41e1-b2a6-a74e4ef940bf`: 72
  passed and 1 documented skip;
- controlled v1 acceptance runs `87588a7a-7e8d-4b7f-a0b2-bc97ba7080b7` and
  `115c67fe-d755-4271-ab10-4a462eda4777`: 23/23 passed in 505.06s and
  509.14s respectively under the 600-second suite bound;
- final-code fresh-process stress targets 1-5 passed in 324.65s, 323.21s,
  315.20s, 311.03s, and 319.22s respectively. This satisfies the containing
  file minimum of 5/5 but is only 5/25 of the required total stress target.

At the time of the failed run, Quality #2 was before the final 60-second timing
change: it ran 1,618 passed and 7 documented skips, but the
randomized acceptance node again ended in `safe builtin planner cannot replan
(tool_timeout)` and teardown reported pending in-memory event consumers. The
earlier all-green full run after the state fix was 1,618 passed and 7 skips
at raw coverage `90.3062454786593%`. No coverage threshold, exclusion,
skip, xfail, or security control was changed.

Two subsequent post-60-second-change quality passes are green: 1,619 passed
and 7 documented skips in 717.24s with raw coverage
`90.3062454786593%`, followed by 1,619 passed and 7 documented skips in
769.29s with raw coverage `90.3082549634274%`. Strict Ruff and mypy passed on
both runs. These are qualifying quality results; they do not by themselves
complete the separate fresh-process stress requirement.

The required 25/25 final-code stress target and final prefreeze marker were not
established at this point. The preflight state remains **STILL BLOCKING**
because only 5 of the required 25 final-code stress attempts have passed; no
`READY_TO_FREEZE_R4Q_FULL_RECORD_INTEGRITY`
marker, external seal, commit, stage, push, tag, merge, release, or publication
was performed.

### R4Q-B7 quality interruption provenance and final gates

B7 continued the mutable Candidate 13-based tree without a commit. The
interrupted B6 Quality #2 has no trustworthy terminal summary, exit record, or
exact historical PID lineage and remains non-qualifying. Three fresh observed
`tests/test_system_testing.py` runs passed 40/40 in 15.06s, 15.18s, and 14.92s;
all observed descendants were synthetic Python pytest fixtures, no Ollama
process appeared, and no relevant process remained after completion. The event
is classified `F — TOOL/EXECUTION INTERRUPTION WITH NO REPOSITORY DEFECT`; no
repository fix was required.

B7 reconfirmed both B6 fail-closed corrections. The fresh quality run passed
Ruff, strict mypy, and 1,621 tests with 7 documented skips. Its exact
coverage.py combined value was 89.9941733137771% (display 90%); the established
R4Q partial-branch raw buffer was 90.315645657110%. No coverage policy or
security test was changed. Controlled v1 acceptance passed twice through the
production runner: run `b5d011ec-784b-46ad-a8bf-df5a3d40b09c` in 501.84s and
run `ed14777f-0597-4bc9-ac85-33b032f61ee7` in 491.66s, both 23/23 under 600s.
Workflows passed 26; permissions passed 72 with one existing documented skip;
the final system-testing repeat passed 40. Package smoke #1/#2 and the full
installed RECORD tamper matrix passed. The post-edit quality pair and final
prefreeze marker are pending; Candidate 14 does not exist.
