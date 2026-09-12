# Native donor study

JARVIS may study open-source projects as reference material, but a donor is
never a runtime dependency and donor source is never uncontrolled input to the
trusted process. The native contract is implemented in
`jarvis.improvement.donor_study`.

## Workflow

```text
discover
  -> verify authoritative upstream
  -> pin exact revision
  -> inspect license and notices
  -> record useful concept and exact source-file references
  -> compare with existing JARVIS ownership
  -> assess security risk and benefit
  -> NativeAdaptationProposal
  -> existing Self-Improvement pipeline
```

`DonorStudyService` advances one stage at a time:

`DISCOVERED -> UPSTREAM_VERIFIED -> REVISION_PINNED -> LICENSE_INSPECTED ->
CONCEPT_ANALYZED -> COMPARED -> ASSESSED -> PROPOSAL_READY`.

Proposal creation requires the service-authorized transition chain. A caller
cannot create a ready record merely by setting its stage field. The service
does not browse, clone, download, execute, import, install, or mutate a
repository. A `DonorFileReference` stores only a safe repository-relative path,
purpose, and exact digest; source contents do not enter JARVIS.

## Proposal contents

`NativeAdaptationProposal` binds:

- project, canonical HTTPS upstream, and exact immutable revision;
- reviewed source-file references and SHA-256 digests;
- inspected license identifier, license-file digest, copyright notices, and
  third-party review status;
- useful concept, comparison with native JARVIS architecture, risk, benefit,
  destination, and security impact;
- explicit tests and benchmarks; and
- dependency notes, which are documentation only.

The proposal is fingerprinted over every field and can only have
`REVIEW_REQUIRED` status. `PORT` additionally requires explicit provenance and
notice review. Even then, PORT is a review disposition, not permission to copy
source or add a dependency.

Allowed dispositions are `PORT`, `REIMPLEMENT`, `INSPIRE`, and `REJECT`.
`INSPIRE_ONLY` is a compatibility alias for `INSPIRE`. JARVIS’s safe default
is native reimplementation or inspiration; existing donor provenance records
remain the authoritative source study index.

## Self-improvement handoff

`NativeAdaptationProposal.to_improvement_signal(...)` creates only an
`ObservedImprovementSignal` for the existing `ImprovementEngine`. That engine
still owns isolated workspaces, typed changes, default-deny dependency control,
security gates, protected benchmarks, regression evaluation, rollback metadata,
and the final expiring trusted-approval proposal. Donor study never approves,
merges, pushes, installs, deploys, or modifies production.

The model may suggest a study or concept, but it cannot establish upstream
identity, revision, license, approval, or successful adaptation. External
project text remains bounded evidence and cannot become JARVIS instructions,
policy, credentials, or authority.

## Security and legal boundary

Exact license and notice metadata is evidence, not legal clearance. Repository
licenses do not automatically cover dependencies, assets, models, prompts, or
generated content. A future PORT review must preserve applicable notices and
resolve dependency provenance separately. No automatic dependency addition is
available in this contract.

No donor package, binary, server, container, UI, memory service, or runtime is
required by JARVIS. A future native implementation must be authored and tested
inside the normal self-improvement and trusted review flow.
