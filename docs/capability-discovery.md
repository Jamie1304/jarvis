# Capability-gap detection and discovery

## Boundary

Discovery is not authorization. The Phase 10 workflow is:

`missing capability -> discover evidence -> evaluate -> recommend/propose -> user/policy decision`

It deliberately stops before registration, installation, setup, configuration, API
calls, or execution. `CapabilityGap` records the requested capability, current task,
missing requirements, known alternatives, risk, and safe evidence. A recommendation
cannot alter the tool registry, PermissionBroker, policy, approval state, or host.

## Providers and provenance

`DiscoveryProvider` is provider-neutral. Current adapters support:

- `InternalToolCatalogProvider` for the explicitly registered local manifest catalog;
- `StaticCatalogDiscoveryProvider` for composition-owned plugin, integration, and
  software/package catalogs;
- `ResearchEvidenceDiscoveryProvider` for already-authorized controlled web research.

No provider dynamically imports a plugin, calls a package manager, or fetches the web.
The research provider accepts already collected data, hashes its raw external content,
and retains only source reference, safe summary, digest, and an `external_untrusted`
label in the candidate provenance. README text, package descriptions, API docs, and
websites are untrusted data—not JARVIS instructions.

## Candidates and evaluation

`DiscoveryCandidate` contains capability, source, exact identity, provenance,
publisher/owner, requested granular permissions, setup needs, architecture fit,
confidence, testability, and maintenance status. Candidate identity and source are
validated; source must match provenance and permissions must be known `Permission`
values.

`CandidateEvaluator` exposes the factors and score used for each candidate:

| Factor | Meaning |
| --- | --- |
| functional fit | provider confidence for the requested capability |
| trust/source quality | source class and verified owner provenance |
| required privileges | proposed JARVIS permissions; excessive privileges reject |
| maintenance risk | active/maintained/unknown/unmaintained status |
| compatibility | compatible/adaptable/incompatible architecture fit |
| reversibility | whether setup is reversible or needs installation |
| testability | deterministic, mockable, manual-only, or unknown |

Incompatible candidates and candidates needing excessive privileges are rejected.
Controlled web research is `caution` at best, even if it has a high numeric score.
Ranking is advisory and stable; it never grants authority.

## Future adapters

`ToolAdapterScaffolder` returns a typed `ToolAdapterSpecification`, not source code.
It names proposed contracts, validation, permissions, and tests for human review.
Rejected candidates have no specification. Implementing an accepted proposal still
requires a separate reviewed tool/provider implementation and all normal broker,
policy, approval, and test requirements.

## Package-tracking example

If a user asks JARVIS to track a package while no package-tracking capability is in
the trusted registry, the detector returns a gap with carrier-status lookup missing.
Discovery may present API/plugin/software options with provenance and risk factors.
It does not install an SDK, create an API credential, fetch a tracking URL, or claim a
package tracker exists. The user/operator must choose whether to pursue a future
integration through the normal authorization and implementation process.
