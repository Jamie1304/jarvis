# R2 Security Gate

**Review date:** 2026-08-24
**Repository:** `Jamie1304/jarvis`
**Working branch:** `agent/v1-integration`
**Reviewed revision:** `d3933473f00b0c52eebf64ec56ef1dad6906ed07`
**Decision:** **NO-GO for v1.0.0 security release**

## Scope and decision

This is a source-code, test, configuration, and local synthetic-fixture assurance
review. It performs no external probing, exploitation, credential use, or device
testing. It reviews:

- `docs/security/r2a-trust-boundary-review.md`
- `docs/security/r2b-secure-code-review.md`
- `docs/security/r2c-negative-test-coverage.md`
- `docs/security/r2d-remediation-report.md`
- the current working-tree diff against the reviewed revision
- the security, Trusted Core, and deterministic test suites

The working tree was already dirty before this report. The review preserved those
changes and did not modify production code, stage files, commit, push, merge, tag,
or release. The current diff contains the R2 remediation changes in the files listed
by `git diff --name-only`; `docs/security/` is untracked documentation supplied by
the ongoing review work. The system-test runner records the repository `HEAD`, not a
cryptographic digest of uncommitted changes, so the test results below apply to the
working tree but are not a release artifact.

The gate is **NO-GO** because several R2 HIGH findings remain explicitly
`REQUIRES_FOLLOWUP`. The current implementation fails closed by keeping the affected
features disabled or deny-by-default, which is useful containment but is not proof
that the promised v1 security boundaries are sound when those capabilities are
enabled.

## Required security criteria

| # | Criterion | Result | Evidence and scope |
|---|---|---|---|
| 1 | All reachable CRITICAL findings are resolved | **PASS** | R2A and R2B reported no CRITICAL finding. The current diff introduced no reviewed dangerous primitive (`shell=True`, `os.system`, pickle-style loading, or `create_subprocess_shell`); quality and all selected negative suites pass. This is a result for the reviewed repository scope, not a claim that source review proves absence of every future defect. |
| 2 | All reachable HIGH findings have effective blocking mitigation | **NOT_PROVEN** | The recovery/LKG authentication gap is fixed for the current local contract, and the callback/effect-evidence gap, configured browser Broker path, and canonical Windows generated-process path are fixed or restricted. Adoption identity, direct uncomposed process paths, and required Windows/manual evidence remain release blockers. |
| 3 | `PermissionBroker` remains mandatory for authority | **PASS** | `jarvis/runtime.py:580-590` constructs the broker and seals the `ToolRegistry`; `jarvis/tools/registry.py:69-177` binds registration and execution to a broker. `jarvis/permissions/broker.py:51` owns authorization, approvals, execution lifecycle, and audit completion. Forged, stale, changed, replayed, and ambiguous approvals are covered by the security tests. |
| 4 | Generated code remains outside Trusted Core | **PASS** | Trusted Core integrity/startup rules and package/runtime boundaries do not import generated package code into the trusted process. Generated/MCP activation is disabled in the default runtime (`jarvis/runtime.py:1167` records `generated_package_state={"activation": "disabled"}`), and package review, certification, UI simulation, and sandbox tests reject the relevant bypasses. This does not upgrade the same-user subprocess into an OS security boundary; that limitation is tracked under criterion 6 and R2B-H01. |
| 5 | `CredentialVault` secrets remain isolated | **PASS** | `jarvis/credentials.py:308` makes `CredentialVault` the secret owner; metadata loading rejects secret-bearing columns (`jarvis/credentials.py:366-367`), secure backend failure does not fall back to plaintext, and host proxies receive opaque references before trusted-side use (`jarvis/sandbox_proxies.py:818`). Credential, log/event/artifact, backup, and scope-negative tests pass. Arbitrary future generated providers still require a Vault-only exporter boundary, as recorded in R2D. |
| 6 | Sandbox capabilities remain brokered | **PASS** | `HostProxyService` requires a `PermissionBroker` (`jarvis/sandbox_proxies.py:457-468`) and every supported operation authorizes, begins, and records execution (`jarvis/sandbox_proxies.py:684-704`). Typed IPC, capability-free AppContainer launch, scoped ACLs, bounded messages, sanitized launch, and process cleanup are tested. Direct uncomposed process paths remain separately gated; no supported proxy path is unbrokered. |
| 7 | Shadow mode cannot produce effects through supported paths | **PASS** | `jarvis/effect_attestation.py` and `jarvis/sandbox_proxies.py` record a trusted pre-dispatch attempt and suppress supported network/filesystem/process/device proxy dispatches in SHADOW. Activation requires a store-minted, package/version/activation-bound zero-dispatch attestation; callback claims cannot substitute. The separate same-user Windows isolation finding remains a release blocker for hostile code. |
| 8 | Capability activation is trusted-code controlled | **PASS** | `jarvis/package_activation.py` owns staged lifecycle transitions; `ActivationHooks` are application-owned, package self-promotion tests pass, and generated activation is disabled in the default runtime. Promotion also requires store-minted package-bound broker attestation and independent non-model verification. The separate Windows isolation limitation still blocks hostile generated activation. |
| 9 | Update/recovery gates cannot self-bypass | **PASS WITH RESTRICTIONS** | `TrustedRecoveryAuthority` authenticates the exact LKG record, manifest/build hash, transaction, installation, schema compatibility, status, and monotonic generation through the secure backend; missing/modified/future/stale records fail closed. Self-update/code restore remains separately disabled until its complete trusted executor and owner gates exist. |
| 10 | External/model content remains untrusted data | **PASS** | Model/provider, MCP, browser/page, knowledge, memory, UI, artifact, automation, and verification tests reject malformed or authority-bearing content. The Agent Runtime validates tool requests; VerificationEngine does not treat model prose as proof; event/automation payloads cannot carry trusted approvals; strict generated knowledge decoding and UI manifest checks pass. No model or external document is granted identity, permission, or policy authority. |
| 11 | No donor framework became security/runtime authority | **PASS** | Repository dependency/configuration inspection and donor scans found no Goose, Agent Zero, fullstack-agent, Backtalk, ai-visualizer, ai-memory-vault, or barehands runtime dependency/import. Donor material remains documented reference/source material. Production composition is native JARVIS code (`jarvis/runtime.py`), with no donor security model used as a root of trust. |

## R2 residual findings and release effect

The following statuses are carried from the R2D remediation evidence. They are not
reopened as new vulnerabilities; they are the reason this final assurance gate does
not approve v1.0.0.

| Finding | R2D status | Current containment | Release consequence |
|---|---|---|---|
| R2A-H01 / R2B-H01 — same-user sandbox is not an OS security boundary | `RESOLVED` for canonical generated package path | Capability-free AppContainer, scoped ACLs, explicit handles, pre-resume Job assignment, fail-closed setup, outside-root/loopback denial, and activation gates are tested; supported proxy calls remain brokered and bounded. | Direct uncomposed MCP/terminal process activation remains blocked; unrelated R2 HIGH findings keep the overall gate NO-GO. |
| R2A-H03 / R2B-H04 — staged activation trusts callback-reported effect observations | `FIXED` | `EffectAttestationStore` mints evidence only from trusted observer writes; Shadow suppression, CANARY dispatch, package binding, independent verification, fake-attestation rejection, and restart reconciliation are covered by `tests/test_effect_attestation.py` and `tests/test_package_activation.py`. | This callback/evidence gap no longer blocks staged activation. Canonical executable activation additionally requires the resolved Windows isolation contract. |
| R2A-H05 / R2B-H02 — recovery/LKG metadata is not independently authenticated | `FIXED` for local recovery | `TrustedRecoveryRecord` is HMAC-authenticated by `TrustedRecoveryAuthority`; secure key/generation floor, exact build/manifest/transaction/install/schema binding, restart/tamper/future-schema tests, and Safe Mode failure behavior are implemented. | The specific unauthenticated-LKG finding no longer blocks the local recovery contract; vendor-signed update provenance and a self-update executor remain separate scope gates. |
| R2A-H06 / R2B-H05 — spoken affirmative phrases are not speaker authentication | `FIXED_BY_DESIGN` | Privileged/high-risk spoken approval is disabled; STT affirmative input cannot produce an approval choice. A trusted desktop handoff revalidates the exact request and consumes through `PermissionBroker`. | Does not block v1 voice capture/text interaction; spoken privileged approval is intentionally unavailable. |
| R2A-H07 — browser authorization is not the canonical production Broker adapter | `FIXED` | `BrowserBrokerAdapter` registers strict per-action tools in `ToolRegistry`; denial, stale/origin, password-redaction, missing-vault, unsupported-backend, and runtime-composition tests pass. | No longer blocks the supported configured browser path; missing/unsupported companions remain unavailable and no OS browser isolation is claimed. |
| R2A-H02 / R2B-H03 — adoption identity binding | `MITIGATED` with platform identity follow-up | Candidate ID and SHA-256 identity digest are required, persisted, and re-inspected immediately before verification; replacement tests pass. | No current silent-adoption path was demonstrated, but trusted executable identity must be completed before broad adoption of existing binaries. |
| R2A-M01 / R2B-M01 — filesystem reparse/TOCTOU limits | `MITIGATED` | Artifact paths reject reparse ancestors and use exclusive/no-follow flags where available; Windows handle-relative guarantees are not claimed. | Keep the existing conservative scope; do not interpret it as complete OS filesystem isolation. |
| R2A-M04 — caller-supplied procedure trust metadata | `FIXED` | `ProcedureEvidenceAuthority` issues proof only after completed durable Task/Plan state, passing VerificationEngine evidence, confirmed outcome, and durable Trace IDs; ProcedureBank ignores caller `verified`/`trusted_source` flags. Runtime restart/caller-forgery/UNKNOWN_OUTCOME regressions pass. | Candidate validation and accepted linkage remain separate from authority; every later execution uses fresh PlanningEngine/PermissionBroker policy. |
| R2A-M05 / R2A-M09 — producer/provenance authenticity | `MITIGATED` / `REQUIRES_FOLLOWUP` | Event bounds, correlation caps, no approval payload path, and typed records pass. | Cross-process authenticated producer identity and independent durable observations remain required for hostile integrations. |

No R2 report identified a reachable CRITICAL finding. The release decision is still
NO-GO because unresolved HIGH/platform items concern the exact boundaries required
for self-expansion, adoption identity, direct process activation, privileged voice,
browser/manual acceptance, and staged generated activation. The local authenticated
recovery/LKG gap is no longer one of those unresolved findings.

## Trust-boundary assurance summary

### Trusted Core and authority

The composition root creates the broker, tool registry, planning task controller,
event bus, recovery state, and MCP manager. Application/UI layers use typed services;
the event bus and presentation projections are not authority stores. The broker
remains the only supported path for permissioned tool authority, and approval
fingerprints bind operation identity, arguments, scope, task, expiry, and consumption.

The Trusted Core tests pass, including forged identity, approval replay, changed
operation/path/candidate, expiry, malformed metadata, generated core mutation,
conditional spoken input, and permission narration ownership. These tests establish
fail-closed behavior for the tested in-process contracts. They do not substitute for
OS-enforced isolation or authenticated cross-process evidence.

### Generated packages, MCP, and sandbox

Generated package code receives typed IPC and brokered host proxies rather than the
broker, Vault master access, policy engine, trusted audit writer, or runtime
container. MCP descriptions/results are validated as untrusted data. The native
MCP/sandbox tests pass malformed schema, collision, bad identity, oversized message,
undeclared host/path/capability, process-spawn, cleanup, and fake-server cases.

The boundary is not release-complete: a same-user process can still be hostile to
the host unless Windows provides a stronger OS boundary. Job Objects provide process
ownership/cleanup, not full privilege or filesystem/network isolation. This is the
primary R2B-H01 limitation.

### Secrets and data

Vault metadata is durable; secret material is held by the secure backend and exposed
only through trusted scoped-use paths. Ordinary persistence, events, memory,
artifacts, model context, and backup tests do not accept raw credential material.
Credential references are not approvals and do not grant capability authority.

### External and model content

Providers, MCP servers, pages, documents, model responses, event payloads, generated
manifests, UI content, and diagnostic declarations are data. They cannot create
trusted identity, approval, policy, or activation state. Verification requires typed
evidence rather than model claims. The review found no donor framework used as a
runtime or security authority.

## Validation executed

All commands were local and used synthetic fixtures/mocks where applicable:

| Check | Result |
|---|---|
| `python -m pytest -q` security-focused selection covering Agent Runtime, permissions, Vault, sandbox/proxies, MCP, package review/certification/activation/runtime, recovery, setup/adoption, browser, artifacts, knowledge, automation, plan, trace, UI simulation, voice, presence, verification, and Trusted Core | **662 passed, 3 skipped** in 45.55s |
| `python -m pytest -q tests/trusted_core` | **109 passed** in 3.66s |
| `python scripts/run_system_tests.py --suite deterministic-workflows` | **passed; 26 tests**; run id `1e2b65c8-81ee-4ddc-944d-ac5bd54ac7c1` |
| `python scripts/run_system_tests.py --suite deterministic-permissions` | **passed; 70 tests, 1 skipped**; run id `c3e41f71-3653-4a49-8cc5-9bf99baff3c3` |
| `python scripts/quality.py` | **passed; 1,322 passed, 6 skipped; Ruff format/check passed; mypy passed; 90% total coverage** |
| `git diff --check` | **passed**; only Git line-ending normalization warnings were emitted |
| defensive primitive scan for `shell=True`, `os.system`, pickle-style loading, `create_subprocess_shell`, and unsafe `Popen` patterns in reviewed production paths | No prohibited match; ordinary bounded `create_subprocess_exec`/process ownership paths remain and are covered by their own controls/tests |

The skipped cases are environment limitations, not passing security assertions:

- an ArtifactStore symlink/reparse test skips when the test user cannot create the
  synthetic link;
- one deterministic permission case and three Windows integration tests are
  environment-dependent/unavailable;
- no hardware, microphone, camera, speaker-authentication, external browser, real
  MCP server, network, or third-party integration test was claimed as executed.

## Gate result and required next run

**NO-GO for v1.0.0 security release. Do not release.**

Before reconsidering the gate, a follow-up must, at minimum:

1. enforce a documented OS-level Windows isolation boundary for generated/MCP code,
   or formally remove those capabilities from the release scope;
2. keep the new trusted Shadow/Canary effect-attestation path bound durably to the
   certified package/version as additional brokers are composed;
3. retain the authenticated recovery/LKG record and extend it to any future
   update executor, including owner identity, migration, and downgrade gates;
4. keep spoken approval non-authorizing, or add a separately authenticated trusted
   approval channel with replay/identity protection;
5. retain the canonical PermissionBroker browser adapter and deny-first
   unsupported/fallback behavior;
6. finish and rerun the targeted regression tests, including supported Windows
   isolation/reparse fixtures where the environment permits them.

No release, commit, push, merge, tag, or production-code change was made by this
assurance run.

## Browser Broker status update

R2A-H07 is **FIXED for the supported configured runtime path**. The native
`BrowserBrokerAdapter` registers strict per-action tools in `ToolRegistry` and
routes them through `PermissionBroker` before backend dispatch. Tests cover
broker denial, stale/origin binding, password redaction, missing-vault and
unsupported-backend fail-closed behavior, and runtime composition. Missing or
unsupported companions remain unavailable; this does not claim OS isolation
for a browser process. The overall R2 gate remains NO-GO for the unrelated
open release blockers.
