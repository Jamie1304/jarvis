# v1 functional acceptance record

**Run revision:** `d9f514d703ab2f5de108a955d5b27c03e876fccc`  
**Branch:** `agent/v1-integration`  
**Date:** 2026-08-24  
**Result:** **NO-GO for the complete end-to-end v1 constitution**

This record is the primary acceptance boundary for the current v1 baseline. It
uses the existing native unit/contract suites and deterministic fakes. No
product-specific production adapter, donor runtime, or hard-coded adopted
runtime fixture was added.

There is not currently one registered `v1-acceptance` system-test catalog entry.
The evidence below is the full quality suite plus every existing trusted system
catalog suite. A passing component suite is not silently promoted to an
end-to-end production claim.

## Acceptance matrix

| Area | Evidence | Result | Boundary |
|---|---|---|---|
| A — unknown capability acquisition | `tests/test_capability_factory.py`, `tests/test_package_reviewer.py`, `tests/test_package_certification.py`, `tests/test_package_activation.py` | PARTIAL | Discovery/adoption/build and staged activation are individually covered, but `CapabilityFactory` stops generated work at `READY_FOR_APPROVAL`; certification/Shadow/Canary/Active are a separate composition path, not one production end-to-end coordinator. |
| B — restart/reuse | `tests/test_capability_health.py`, `tests/test_package_activation.py` | PARTIAL | Health and activation restart behavior are covered, but `CapabilityRegistry` and activation lifecycle state are in-memory; no authoritative durable capability lifecycle store is composed. |
| C — environment discovery | `tests/test_environment_discovery.py`, `tests/test_discovery.py` | PASS | Unknown candidates remain untrusted evidence; active probing requires policy. |
| D — event automation | `tests/test_automations.py`, `tests/test_events.py` | PASS | Events dispatch normal task/planning flow; permission and verification remain downstream. |
| E — Plan Studio | `tests/test_planning_engine.py` | PASS | Revisions validate, stale approvals invalidate, and unknown effects are not replayed. |
| F — trace | `tests/test_trace.py` | PASS | Human-readable facts are rendered with redaction and no hidden reasoning. |
| G — proactive capability opportunities | No `OpportunityEngine` acceptance surface exists | MISSING | There is no production opportunity queue that prepares safely and retains an expiring authority request without loss. |
| H — knowledge | `tests/test_knowledge_library.py`, `tests/test_skills.py` | PASS | Scoped indexing, citations, classification, source preservation, and prompt-injection-as-data are covered. |
| I — backup/migration | `tests/test_backup.py`, `docs/backup-export-migration.md` | PASS at service boundary | Encryption, tamper/wrong-key refusal, selective restore, reauthorization, recertification, migration, relinking, and rollback are covered. Domain providers/appliers remain explicit composition callbacks. |
| J — workflow/routine learning | `tests/test_workflows.py` | PASS | Repeated verified success produces a scoped candidate and normal planning remains authoritative. |
| K — effect preview/compensation | `tests/test_effects.py` | PASS | Real compensation uses normal tools/broker/verification; irreversible and unknown effects have no fake Undo. |
| L — Shadow/Canary | `tests/test_package_activation.py` | PASS at lifecycle boundary | Shadow zero-effect enforcement, bounded Canary, promotion, rollback, restart, and self-promotion refusal are covered. |
| M — behavior drift | `tests/test_capability_health.py` | PASS | Undeclared behavior is classified through trusted broker observations and can degrade/quarantine. |
| N — attention | `tests/test_capability_health.py`, `tests/test_permissions.py` | PARTIAL | Attention notices and expiring permission state exist, but there is no dedicated priority-aware bundling/urgent-attention queue acceptance path. |
| O — artifacts | `tests/test_artifacts.py` | PASS | Immutable, provenance-aware, workspace-scoped artifacts survive restart. |
| P — resource governor | `tests/test_resources.py` | PASS | Pressure, battery, disk, GPU uncertainty, reservations, and priority-aware deferral are covered with fake telemetry. |
| Q — golden workflow | `tests/test_golden_workflows.py`, `tests/fixtures/regressions/` | PASS | Verification gates block bad candidates; expected-result tampering and silent exclusion fail closed. |
| R — setup/adoption | `tests/test_setup_conductor.py` | PASS | Existing generic installations/data are adopted in place, setup is resumable/idempotent, and declined adoption preserves data. |
| S — voice runtime | `tests/test_voice.py`, `tests/trusted_core/test_permission_presentation.py` | PASS with fakes | Streaming/early TTS, persistent output, barge-in, stale suppression, PTT repeat safety, degradation, mode independence, and ambiguous approval refusal pass deterministically. Hardware/provider execution remains unclaimed. |
| T — presence/presentation | `tests/test_presence_presentation.py` | PASS | Presence derives from canonical events; typed artifacts and actual `query_state()` are used; unsafe assets are rejected. |
| U — generated UI simulation | `tests/test_ui_simulation.py` | PASS | Representative states, semantic controls, artifacts, malicious approval spoofing, unsafe assets, and zero real effects are covered. |
| V — component doctor | `tests/test_component_doctor.py` | PASS | Known repair, unknown-failure research boundary, sandbox/test, authority, verification, degradation, and crash isolation are covered. |
| W — procedure learning/context priming | `tests/test_workflows.py`, `tests/test_skills.py` | PASS | Verified repetition produces reusable candidates, context requirements remain retrieval hints, and scope/authority are preserved. |

## Anti-cheating audit

The core search found no product-specific integration names (Spotify, Hue,
Home Assistant, Discord, printer/NAS/car logic), no donor runtime import, and no
fixture-specific production adapter. Fixture/test vocabulary is confined to
testing infrastructure; reviewer patterns mentioning bypasses are detection
rules, not bypasses. No global `bypassPermissions` switch exists.

Randomized unknown capability IDs are used by the goal-supervisor tests. External
discovery, model output, and knowledge text remain data and cannot create trust,
approval, activation, or authority.

## Executed suites

| Command | Result |
|---|---|
| `python scripts/quality.py` | PASS — 1,138 passed, 5 skipped, 90% coverage |
| `python scripts/run_system_tests.py --suite deterministic-workflows` | PASS — 26 passed |
| `python scripts/run_system_tests.py --suite deterministic-permissions` | PASS — 70 passed, 1 skipped |
| `python scripts/run_system_tests.py --suite windows-hardware-manual` | SKIPPED — hardware suite disabled |
| Full pytest suite | Included in quality gate; 1,138 passed, 5 skipped |

## Blockers to complete GO

1. Compose one trusted capability acquisition coordinator that connects
   `DISCOVER/ADOPT/REUSE/BUILD` to package audit/certification, Shadow, required
   authority, bounded Canary, Active, and verification without allowing the
   generated package to self-promote.
2. Add one authoritative durable store for capability/integration lifecycle
   metadata and startup health/reuse reconciliation.
3. Add a generic Opportunity/Attention service with bounded priority bundling,
   expiry-aware authority notices, and restart behavior.
4. Register a single deterministic `v1-acceptance` system suite after the
   above end-to-end path exists.

Real Windows UI, camera, microphone/provider, authenticated approval UI,
process isolation, and other hardware/manual checks remain unexecuted. This is
not a release or deployment decision.
