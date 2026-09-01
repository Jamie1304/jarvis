# Autonomous improvement engine

## Operating mode and boundary

Phase 11 is a proposal-and-test subsystem. Its only operating mode is
`PROPOSE_AND_TEST`; it has no autonomous merge, deployment, approval, package
installation, policy-editing, or production-write mode. It is not registered as a
planner-selectable tool in the default application composition.

The trusted pipeline is:

`OBSERVE SYSTEM -> IDENTIFY CANDIDATE -> SPECIFY CHANGE -> ANALYZE RISK -> CREATE ISOLATED WORKSPACE -> MODIFY -> TEST -> SECURITY CHECK -> EVALUATE -> PRODUCE PROPOSAL`

Every unsuccessful stage stops the run and quarantines the workspace where one
exists. A successful run emits an expiring `MergeDeploymentProposal` whose initial
and only engine-created state is `AWAITING_TRUSTED_APPROVAL`. The engine exposes no
method that approves, merges, pushes, deploys, or changes the running checkout.

## Candidate and specification lifecycle

`ObservedImprovementSignal` accepts structured evidence for repeated errors, failed
workflows, performance metrics, capability gaps, dependency problems, and evaluation
regressions. `StructuredCandidateGenerator` converts that evidence into an
`ImprovementCandidate` with an objective, benefit, affected components, risk,
reversibility, and at least one baseline-linked evaluation scenario.

External issue text, web content, package metadata, and similar material are
untrusted data. When a signal includes external content, the generator retains a
SHA-256 digest and a fixed safe label; it does not copy the content into the
candidate, change specification, or coding-agent context. A source reference and
trusted bounded summary are evidence, not instructions or authority.

Prioritization is deterministic and explainable. Impact, frequency, confidence,
user relevance, inverse risk, and inverse implementation cost each retain their
score, weight, and explanation. A configurable minimum score applies after risk is
raised by trusted component rules. An empty set or a top score below the threshold
returns `NO_WORTHWHILE_IMPROVEMENT`; creating a change is not required for a
successful observation cycle.

Before any coding adapter runs, `TrustedTemplateSpecifier` produces a concrete
`ChangeSpecification` containing the problem, intended behavior, boundaries,
likely affected paths, required evaluation tests, and rollback plan. Trusted risk
classification can raise, but never lower, the declared risk. Changes to permission,
tool, bootstrap, workflow, quality-gate, dependency-control, or improvement-engine
components are critical-risk proposals; computer, camera, vision, application, and
autonomy components are at least high risk.

## Separation of responsibilities

The improvement engine composes independent ports:

- candidate generation, prioritization, risk classification, and specification;
- a `CodingAgent` that returns a typed `ProposedChangeSet` but receives no filesystem,
  command, Git, permission, approval, or deployment primitive;
- a trusted workspace manager and change applier;
- a default-deny dependency guard;
- an independently confined gate process adapter and separate security checker;
- a protected metric provider and regression evaluator; and
- a proposal store that can only add awaiting-approval records.

Generated tests are never the evaluator. Protected metrics are captured before
modification and bound to the candidate, worktree ID, and immutable base revision.
The evaluator measures the same scenarios after all executable gates. Passing tests
without the required baseline improvement yields no proposal; no change,
regression, non-finite data, or a baseline mismatch fails evaluation.

## Worktree and write isolation

`GitWorktreeManager` accepts production and workspace roots only from trusted
composition. The roots must be existing canonical directories and must not overlap.
Before creating a worktree, the manager requires a clean production checkout,
canonical Git identity, and a full immutable HEAD revision. It generates an opaque
workspace ID and direct-child path itself, creates a detached worktree through a
fixed no-shell Git operation, verifies the new worktree identity, and checks that
production did not change. A model cannot choose the root, branch, revision, Git
executable, or argument vector.

The Git adapter disables repository hooks and external diff helpers for worktree
creation, ignores global/system Git configuration, disables terminal prompts, uses
a bounded timeout, and does not forward the general application environment. Git
worktree creation still updates trusted shared Git metadata; this operation belongs
to the reviewed adapter, never the coding agent or gate process.

`TrustedWorkspaceChangeApplier` is the only Phase 11 mutation port. It accepts
bounded text create/modify/delete records, verifies the specification ID, allows
only relative paths within a declared affected path, rejects ambiguous Windows
paths and symlink/junction escapes, checks exact base digests for existing files,
and applies writes atomically. It forbids `.git`, `.github/workflows`, and
`scripts/quality.py`. Baseline tests and gate-control files such as `conftest.py`,
`pyproject.toml`, pytest/mypy/Ruff/coverage configuration, and module-shadowing
startup files are immutable in this mode, including nested configuration files.
Tree fingerprints reject links, junctions, non-regular files,
and changes after the trusted apply step. Production cleanliness and revision are
checked throughout the run. A forged handle, changed workspace identity, production
mutation, or integrity mismatch quarantines the workspace and fails closed.

Quarantine and retention are logical terminal states; Phase 11 does not recursively
delete worktrees. A later trusted maintenance component must implement bounded,
reviewed cleanup without exposing a deletion primitive to the coding agent.

## Mandatory gates and evaluation

A proposal must contain exactly one passing result for every gate:

1. formatting and linting;
2. type checking;
3. unit tests;
4. relevant integration tests;
5. startup/health check;
6. independent static security check; and
7. protected regression evaluation.

The protected regression evaluation may include installation-specific
`GoldenWorkflow` definitions. Before a self-improvement activation, the trusted
change service must invoke `GoldenWorkflowService.require_before` with
`SELF_IMPROVEMENT` and run every applicable active workflow. The same gate
contract is required for model changes, integration updates, and self-updates.
No applicable workflow or an unavailable required integration/hardware check is
a failure, not a waiver. Golden definitions and expected criteria are owned by
`GoldenWorkflowStore`; generated output cannot delete, weaken, exclude, or
regenerate them.

Executable gate definitions are host-owned absolute executables with argument
arrays and finite timeouts. There is no shell-string interface. The process adapter
must attest that writes are confined to the candidate workspace, production and
shared Git metadata are inaccessible, network is disabled, secrets are removed,
the source tree is immutable during a gate, and timeout/cancellation controls the
entire process tree. Missing, duplicated, failed, cancelled, timed-out, or
incompletely attested gates fail the run. Phase 11 intentionally provides no
permissive in-process gate executor.

The built-in static checker is a minimum preflight for path correspondence, obvious
secret literals, `shell=True`, `eval`, `exec`, and `os.system`. It runs before any
candidate code can execute and again as the mandatory security gate after the test
gates. It is not a complete security analysis. Trusted production composition must
add appropriate scanners and review, and final human approval remains mandatory.

## Modification trust levels

The trusted `ModificationTrustClassifier` derives a modification level from every
path in the complete proposed change set. It does not accept a model-supplied
classification. The aggregate is the highest applicable level, so a mixed patch
cannot be split into lower-risk requests. A typed rename retains its old protected
path, and conservative protected filename tokens cover renamed Broker, Vault,
recovery, updater, policy, and classifier modules.

Generated integrations are Level 1, user-space JARVIS is Level 2, and the Core
Agent Runtime is Level 3. PermissionBroker/Vault/security services are Level 4;
Updater/Recovery/Security Constitution/root-of-trust surfaces are Level 5. The
last two levels are rejected by the proposal applier for agent-authored changes
and require a separately held trusted release. The classifier and policy are
themselves Level 5. See [`self-modification-policy.md`](self-modification-policy.md)
for the complete gate contract and limitations.

## Supply-chain policy

Dependency manifests are discovered recursively and fingerprinted before
modification. The protected set includes Python project/setup, requirements,
constraints, Pipenv, Poetry, uv, Conda, Node, Rust, and Go manifests and lockfiles.
The default policy rejects every
manifest transition. A dependency change is eligible only when trusted application
configuration supplies an exact exception binding the manifest path, prior digest,
candidate digest, package records, explicit risk analysis, and reversibility. This
is analysis and eligibility, not permission to install, download, execute, merge, or
deploy the dependency. Gate sandboxes remain network-disabled.

## Proposal and approval lifecycle

`MergeDeploymentProposal` binds its identity, task, complete candidate and evidence,
specification, workspace identity/path/base, modification and tree fingerprints,
dependency assessment, every gate result, evaluation, timestamps, status, and
rollback metadata to a canonical proposal fingerprint. The proposal store recomputes
that fingerprint before acceptance. Rollback metadata always names the previous
known-good full revision. Duplicate proposal fingerprints are rejected by the
current in-memory store.

Proposal approval is deliberately outside this engine. Future approval and merge
services must authenticate a trusted user, verify expiry and the exact fingerprint,
revalidate repository state and all evidence, and independently pass the Permission
Broker for every privileged action. They must not accept a model/tool claim that a
proposal was approved. Approval of one fingerprint must not authorize changed
arguments, a different revision, another task, dependency installation, a network
push, or deployment.

## Privileged capabilities and future integration

Phase 11 currently exposes no model-selectable privileged tool. Trusted setup reads
repository metadata and creates/modifies files only in its configured isolated
workspace. If any part becomes planner-selectable, the complete operation must be a
registered tool and pass through `PermissionBroker`; at minimum repository reads
need scoped `filesystem.read`, candidate writes need scoped `filesystem.write` and
`code.modify`, and any controlled Git command needs an exact trusted command family
under `terminal.execute`.

Future merge, checkout mutation, dependency installation, remote fetch/push,
release, service restart, or deployment are separate privileged capabilities. They
require exact scoped policy and fresh trusted approval as appropriate. A Phase 11
proposal grants none of them, and critical/high-impact modifications must never be
automatically merged or deployed.

## Donor/reference study

Open-source donor research is metadata-only and feeds Phase 11 rather than
creating a parallel change path. `DonorStudyService` verifies an authoritative
upstream, exact revision, license/notices, source-file digests, concept,
comparison, risk/benefit, tests, and benchmarks before creating a fingerprinted
`NativeAdaptationProposal`. It never clones, imports, executes, installs, or
adds dependencies. The proposal can be converted only into an
`ObservedImprovementSignal`; the existing isolated workspace, security,
dependency, benchmark, regression, rollback, and approval gates remain
mandatory.

## Security review

| Threat | Current control | Residual assumption or limitation |
| --- | --- | --- |
| Model self-authorization or deployment | Engine creates only expiring `AWAITING_TRUSTED_APPROVAL` records and has no approval/merge/deploy port | A future approval service must authenticate humans and revalidate the exact fingerprint |
| Direct production modification | Disjoint generated worktree, owned handles, clean immutable base, repeated production checks, typed applier only | Trusted in-process adapters must remain reviewed; Python is not an in-process sandbox |
| Path traversal, alias, junction, or link escape | Canonical containment, unambiguous relative paths, long-path alias comparison, Windows reserved-name checks, reparse rejection, base digests | Host filesystem and trusted root configuration must behave consistently; races require OS confinement and dedicated roots |
| Coding-agent prompt injection | Raw external content is replaced by a digest and fixed label; coding context contains structured safe evidence only | Trusted summarization/source-reference production must not smuggle instructions or secrets |
| Generated tests hiding a regression | Independent protected baseline and evaluator; regression is a mandatory gate | Metric providers and scenarios are trusted configuration and need domain review |
| Gate escape or false success | Fixed argv, mandatory complete gate set, secure sandbox attestation, evidence digests, fail closed | CI mocks prove orchestration contracts, not real Windows/container confinement; deployment composition needs an audited OS sandbox |
| Dependency or package insertion | Manifest snapshot and exact-digest default-deny guard; network-disabled gates | Non-manifest vendored code still needs security review; an exception is only as trustworthy as its operator analysis |
| Mutation after approval | Proposal fingerprints bind revisions, paths, tree/diff, gates, evaluation, and dependencies | The future merge service must recompute and compare evidence immediately before mutation |
| Malicious generated source | Bounded text changes, protected control paths, static security preflight, gates, human review | Static pattern checks are incomplete and cannot prove source safety |
| Resource exhaustion or secret/network access | File-size limits, gate timeouts/cancellation, removed secrets, network-disabled attestation | The concrete process sandbox must enforce CPU, memory, disk, handle, and process-tree limits |
| Git hooks/config side effects | Fixed no-shell Git call, hooks/diff helper disabled, global/system config ignored, prompt disabled | The trusted Git executable and repository metadata remain part of the trusted computing base |

The subsystem is safe only under the stated trust model: application composition,
workspace manager, change applier, gate definitions, sandbox adapter, metric provider,
security scanners, proposal store, and future approval/merge service are trusted and
reviewed. In-process malicious Python can bypass application-level interfaces and is
outside the protection offered by these types alone.
