# R3G system stewardship

R3G closes the application-owned stewardship composition around the existing
JARVIS authorities. `SystemStewardshipCoordinator` observes and classifies
trusted evidence, binds inert plans to an observation fingerprint, and records
lifecycle transitions through the existing audit sink. It does not own a
downloader, filesystem effect, installer, model registry, startup backend, or
security decision.

## Responsibility audit

| Capability | R3G status | Authoritative owner / boundary |
| --- | --- | --- |
| Acquisition, materialization, provenance, integrity | PRODUCTION_COMPLETE | `AcquisitionBroker`, acquisition ledger, `FileSteward` |
| Missing-resource escalation | PRODUCTION_COMPLETE | typed `MissingResourceRequirement` -> `AcquisitionRequest` |
| Resource registration and health verification | PRODUCTION_COMPLETE | acquisition ledger and provider/model registries |
| Software inventory and update planning | PRODUCTION_PARTIAL | `ApplicationManager`, trusted inventory/package providers; use evidence remains UNKNOWN when unavailable |
| Model portfolio and retirement | PRODUCTION_COMPLETE | `ModelPortfolioOptimizer`, `LocalModelManager`, provider registry, broker |
| Storage inventory, pressure, forecast | PRODUCTION_COMPLETE | `StorageInventoryService`, history store, explicit pressure policy |
| Relocation planning | PRODUCTION_COMPLETE | `StoragePlanner`; application-managed/unknown targets remain bounded or unsupported |
| Duplicate detection | PRODUCTION_COMPLETE | full-hash `DuplicateDetector`, physical identity and reparse guards |
| Cleanup classification and retention | PRODUCTION_COMPLETE | `FileClassifier`, `CleanupClassifier`, retention authority, `FileSteward` |
| Startup observation and exact mutation | PRODUCTION_COMPLETE | `WindowsStartupProvider`, `StartupMutationService`, `PermissionBroker`, `HostBridge` |
| Security health and integrity | PRODUCTION_PARTIAL | trusted security-provider registry; host-wide provider may remain UNAVAILABLE |
| Security scanning and quarantine | PHYSICAL_QUALIFICATION_REQUIRED | no provider is fabricated; acquisition remains pending when required disposition is absent |
| Recovery, rollback, interrupted mutation | PRODUCTION_COMPLETE | storage manifests, acquisition ledger, model retirement store, startup store, recovery authority |
| Permission isolation | PRODUCTION_COMPLETE | existing `PermissionBroker` and protected Host Bridge |
| UI projection | PRODUCTION_PARTIAL | desktop System Health projection is read-only; effect controls remain existing trusted paths |
| Runtime composition | PRODUCTION_COMPLETE | `RuntimeContainer.system_stewardship` |
| Restart/durability | PRODUCTION_COMPLETE | domain stores reconcile uncertainty; coordinator never blindly replays effects |

## Ownership map

| Concern | Stewardship role | Effect authority |
| --- | --- | --- |
| Observe/classify/explain | `SystemStewardshipCoordinator` | none |
| Acquire/place/register | prepare request and present evidence | `AcquisitionBroker` -> `PermissionBroker` -> `FileSteward` |
| Move/delete/restore | produce cleanup or placement proposal | `FileSteward` + Host Bridge + recovery manifest |
| Retire a model | compare measured evidence and stage proposal | `ModelPortfolioOptimizer` + provider manager + broker |
| Startup change | expose exact plan | `StartupMutationService` + trusted Windows provider |
| Software install/update | expose provider-issued plan | `ApplicationManager` and package provider |
| Security disposition | project provider evidence | registered trusted security provider |
| Lifecycle evidence | record projection transitions | existing SQLite audit sink |

## Lifecycle

`observe()` produces a `CLASSIFIED` observation. Plans are `PLANNED` and bind
to a stable fingerprint of the observed provider facts. Before delegation,
`assert_current()` re-observes and rejects stale or expired plans. Effect
transitions are recorded as `AWAITING_AUTHORITY`, `EXECUTING`, `VERIFYING`,
`VERIFIED`, `FAILED`, or `UNKNOWN_OUTCOME`. `reconcile()` asks existing
effect owners to reconcile their durable records and explicitly does not retry
uncertain work.

## Canonical S1-S16 matrix

| ID | Production route | Exact focused evidence | Boundary / fake policy | Verdict |
| --- | --- | --- | --- | --- |
| S1 | typed missing requirement -> formal acquisition plan -> existing broker | `tests/test_r3g_system_stewardship.py::test_formal_acquisition_plan_preserves_unknown_metadata`; `tests/test_r3a_acquisition_portfolio.py::test_acquisition_ledger_persists_terminal_and_failure_evidence` | controlled provider fixture; no downloader replacement | STRONG |
| S2 | measured portfolio evidence -> dominance analysis -> retirement proposal | `tests/test_r3a_acquisition_portfolio.py` portfolio coverage; `tests/test_r3a_acquisition_portfolio.py::test_model_usability_evidence_does_not_equate_availability_with_usability` | model evidence is real typed knowledge; no name-only decision | STRONG |
| S3 | retirement authority -> provider removal -> registry/fallback verification | `tests/test_r3a_acquisition_portfolio.py::test_retirement_store_persists_protection_and_approval_bindings` | controlled model manager; provider effect remains authoritative | STRONG |
| S4 | observed volumes -> pressure -> bounded placement proposal | `tests/test_r3g_system_stewardship.py::test_stewardship_plan_rejects_changed_volume_evidence`; `tests/test_storage_stewardship.py::test_storage_planner_selects_capacity_volume_and_preserves_unknown_routes` | controlled volumes; no real disk mutation | STRONG |
| S5 | full-hash duplicate groups with physical identity | `tests/test_storage_stewardship.py::test_duplicate_detector_requires_full_hash_and_does_not_count_hardlinks`; `test_duplicate_detector_reports_exact_reclaimable_bytes_for_physical_objects` | controlled filesystem; reparse/intentional-copy guards active | STRONG |
| S6 | bounded cleanup classification -> inert grouped proposal | `tests/test_r3g_system_stewardship.py::test_observation_cleanup_is_truthful_and_plan_is_inert`; `tests/test_storage_stewardship.py::test_classifier_cleanup_and_download_hygiene_are_conservative` | controlled artifact root; no delete from projection | STRONG |
| S7 | trusted provider result projects threat/unknown state | `tests/test_system_stewardship.py::test_security_rejects_model_claim_and_stale_bound_is_validated` | model claims rejected; harmless provider fixture only | STRONG |
| S8 | exact startup identity -> disable -> verify -> restore -> verify | `tests/test_startup_mutation.py::test_exact_disable_restore_and_restart_reopen` | in-memory acceptance-owned registry; no unrelated host entry | STRONG |
| S9 | interrupted file effect -> unknown/reconcile | `tests/test_storage_stewardship.py::test_file_steward_interrupted_copy_reconciles_unknown_without_retry` | controlled file mutation and existing manifest authority | STRONG |
| S10 | generated capability attempts effect outside scope | existing permission and Host Bridge suites; `tests/test_startup_mutation.py::test_policy_missing_and_denied_approval_have_zero_effect` | real broker policy; no approval mock | STRONG |
| S11 | active/evidence/rollback retention excludes cleanup | `tests/test_storage_stewardship.py::test_retention_reference_authority_uses_conservative_precedence` | trusted retention references | STRONG |
| S12 | governor defers duplicate work under pressure | `tests/test_r3g_system_stewardship.py::test_observation_cleanup_is_truthful_and_plan_is_inert` (`duplicate_scan_state=deferred`) | controlled low-headroom telemetry; no sleep/threshold inflation | STRONG |
| S13 | acquisition pending/unknown stays pending for reconciliation | acquisition ledger and restart tests in `tests/test_r3a_acquisition_portfolio.py` | no blind repeat | STRONG |
| S14 | unavailable providers project UNKNOWN/UNAVAILABLE | `tests/test_system_stewardship.py::test_security_and_startup_record_validation_is_fail_closed` | unavailable provider is explicit | STRONG |
| S15 | presentation projection does not alter authority | `tests/test_r3f_runtime_integration.py`; `tests/test_r3g_system_stewardship.py::test_runtime_exposes_system_health_projection_without_effects` | read-only desktop view | STRONG |
| S16 | durable domain records reconcile after restart | `tests/test_startup_mutation.py::test_unknown_outcome_reconciles_without_replay`; storage manifest restart tests; coordinator `reconcile()` | existing domain stores are reused; no duplicate recovery authority | STRONG |

## Deliberate physical gaps

Later independent qualification still needs real Windows Defender/security
provider evidence, acceptance-owned startup mutation, real disk-pressure
behavior, real model download/removal, real software acquisition, large-file
relocation, and physical rollback. R3G supplies the production paths and
reports those capabilities as unavailable or not yet qualified; it does not
claim controlled fixtures are host proof.

