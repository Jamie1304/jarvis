# R2C Defensive Negative-Test Coverage

## Scope and safety

This is an authorized defensive review of the JARVIS repository. The fixtures in
this run are synthetic and local. No real credentials, external services,
network probing, uncontrolled process execution, or product-specific adapters
are used.

The purpose of this run is to make fail-closed behavior executable and
traceable. A rejection, quarantine, pause, or explicit recovery state is the
expected secure result; a test is not an exploit demonstration.

## Tests added in R2C

| Boundary | Test | Defensive assertion |
| --- | --- | --- |
| Agent Runtime | `tests/test_agent_runtime.py::test_model_output_cannot_expand_budget_or_certify_completion` | A response containing a model-supplied `max_turns` field is malformed, cannot change the trusted budget, and cannot produce a proposed result. |
| Agent context | `tests/test_agent_runtime.py::test_untrusted_context_text_cannot_replace_protected_security_projection` | Untrusted text remains a later user message while the application-owned security projection remains the first system message. |
| MCP | `tests/test_mcp.py::test_mcp_namespace_collision_fails_closed_without_partial_registration` | Duplicate synthetic tool names fail startup and leave the registry with no partial registration. |
| Automation | `tests/test_automations.py::test_event_payload_cannot_smuggle_trusted_approval_into_normal_goal` | A synthetic `PermissionGranted` event is data only; it creates a normal task through the task controller and is not used as a broker approval. |

These tests add explicit regression coverage for the gaps found while mapping
the existing suite. They do not introduce production adapters or test-only
authority bypasses.

## Requested negative-test matrix

The following matrix records the existing synthetic tests that cover the rest
of the requested attack classes. Function names are part of the local evidence
record and should be updated if tests are renamed.

### Agent Runtime and verification

- Malformed and unknown tool requests: `tests/test_agent_runtime.py::test_malformed_and_unknown_tool_output_fails_closed` and `::test_tool_validation_failure_does_not_become_success`.
- Model budget escalation and fake completion: the new budget test above, `::test_direct_response_is_proposed_not_self_certified`, and `tests/test_planning_engine.py::test_simple_plan_completes_only_after_goal_verification`.
- Completion cannot override verification failure: `tests/test_planning_engine.py::test_step_success_does_not_override_goal_verification_failure`.
- Bounded loops, timeout, cancellation, and unknown-effect retry refusal: `tests/test_agent_runtime.py::test_provider_failure_timeout_cancel_and_turn_exhaustion_are_bounded`, `::test_loop_guard_detects_repeated_semantic_no_progress`, and `::test_retry_classification_never_replays_unknown_effect`.

### Permissions and approval authentication

- Forged or caller-supplied approval: `tests/test_permissions.py::test_caller_cannot_supply_a_broker_receipt`, `tests/trusted_core/test_permission_presentation.py::test_model_crafted_permission_narration_is_not_a_trusted_input`, and `::test_spoken_approval_is_strict_and_non_authorizing`.
- Expiry, changed arguments, changed scope/action, and one-time consumption: `tests/test_permissions.py::test_expired_approval_never_executes`, `::test_changed_arguments_do_not_match_approval`, `::test_changed_trusted_action_semantics_require_fresh_approval`, `::test_limited_grant_is_scoped_and_expires`, `::test_one_time_approval_is_consumed_and_not_reused`, and `::test_authorization_receipt_outcome_is_single_use`.
- Identity, fingerprint, policy substitution, and unknown outcomes: `tests/test_permissions.py::test_approval_context_binds_every_decision_claim`, `::test_approval_does_not_survive_policy_substitution`, `::test_unknown_effect_outcome_is_not_reauthorized_in_same_process`, and `::test_audit_records_decision_identity_fingerprint_and_outcome_without_secret`.

### Context, memory, User Model, and Knowledge

- Untrusted instructions and poisoned remembered content: the new context test above, `tests/test_memory.py::test_prompt_injection_policy_and_provenance_flags_fail_closed`, `::test_untrusted_remembered_content_is_data_and_not_long_term_eligible`, and `::test_consistency_scan_records_duplicates_contradictions_staleness_and_poisoning`.
- Sensitive context and provider boundaries: `tests/test_memory.py::test_secret_content_is_excluded_from_long_term_and_low_level_storage`, `tests/test_user_model.py::test_sensitivity_and_credential_boundaries_fail_closed`, and `::test_workspace_scoped_context_excludes_other_workspace_and_filters_cloud`.
- Cross-workspace retrieval, correction, deletion, retention, and learning pause: `tests/test_memory_control.py::test_correction_retention_delete_and_retrieval_use_authoritative_stores`, `::test_learning_pause_and_reverification_are_durable_and_scoped`, and `tests/test_user_model.py::test_workspace_scoped_context_excludes_other_workspace_and_filters_cloud`.
- Knowledge path, injection, classification, and source isolation: `tests/test_knowledge.py::test_secret_files_and_secret_bearing_documents_are_excluded`, `::test_provenance_and_stale_detection_cover_changed_and_deleted_sources`, and `tests/test_memory.py::test_prompt_injection_policy_and_provenance_flags_fail_closed`.

### MCP and sandbox boundaries

- Malformed schema and result handling: `tests/test_mcp.py::test_mcp_malicious_schema_fails_closed`, `::test_mcp_manager_rejects_sealed_registry_and_bad_descriptors`, and `::test_mcp_malformed_result_fails_closed`.
- Namespace collision: the new MCP test above.
- Undeclared privileged operations remain brokered: `tests/test_mcp.py::test_mcp_discovery_adapter_is_brokered_and_stops` and `tests/test_sandbox_proxies.py::test_proxy_permission_approval_is_not_satisfied_by_sandbox_input`.
- Filesystem, network, capability, process, identity, and IPC bounds: `tests/test_sandbox_proxies.py::test_filesystem_proxy_allows_only_declared_roots_and_new_files`, `::test_network_proxy_is_exact_origin_bounded_and_audited`, `::test_identity_manifest_action_and_process_boundaries_fail_closed`, `tests/test_sandbox.py::test_identity_spoof_oversized_response_and_crash_are_contained`, `::test_oversized_request_and_process_spawn_limit`, and `::test_message_decode_rejects_each_security_metadata_shape`.
- Redirect/private-address, response-size, cleanup, and restart containment: `tests/test_sandbox_proxies.py::test_network_proxy_denies_private_redirect_and_oversized_response` and `tests/test_sandbox.py::test_timeout_cancellation_and_restart_bound`.

### Credentials and secret-safe telemetry

- Declared scope and opaque use: `tests/test_credentials.py::test_metadata_only_storage_and_scoped_use`, `::test_api_token_and_key_are_opaque_metadata_references`, and `tests/test_sandbox_proxies.py::test_credentials_are_opaque_and_resolved_only_on_trusted_side`.
- No raw secret in metadata, events, logs, artifacts, or low-level storage: `tests/test_credentials.py::test_status_events_are_metadata_only`, `::test_validation_and_backend_failures_are_sanitized`, `tests/test_memory.py::test_secret_content_is_excluded_from_long_term_and_low_level_storage`, and `tests/test_artifacts.py::test_artifact_workspace_isolation_path_attacks_and_secret_rejection`.
- No plaintext fallback and schema refusal: `tests/test_credentials.py::test_secure_backend_fail_closed_without_plaintext_fallback` and `::test_metadata_schema_refuses_future_and_secret_columns`.

### Browser semantic bridge

- Stale references, navigation, origin changes, and tab closure: `tests/test_browser.py::test_navigation_and_origin_change_invalidate_old_references` and `::test_stale_document_reference_and_closed_tab_are_rejected`.
- Page prompt injection, password redaction, Vault-only credential fill, and cross-origin isolation: `tests/test_browser.py::test_page_prompt_injection_is_untrusted_data_and_never_authority`, `::test_password_values_are_redacted_and_vault_reference_is_required`, and `::test_cross_origin_frames_and_nodes_are_not_exposed`.

### Automation and event safety

- Event payload cannot be approval: the new automation test above and `tests/test_automations.py::test_permission_waiting_is_reported_without_fabricating_approval`.
- Normal Goal/task path: `tests/test_automations.py::test_trigger_condition_and_normal_planning_dispatch`.
- Storm, deduplication, debounce, cooldown, queue, and bounded concurrency: `tests/test_automations.py::test_deduplication_debounce_cooldown_and_storm_are_bounded`, `::test_drop_and_queue_policies_bound_active_work`, and `::test_queue_policy_drains_and_bounds_storm`.
- Recursive event feedback and bounded correlation state: `tests/test_events.py::test_cancellation_and_feedback_storm_are_bounded` and `::test_correlation_ledger_has_deterministic_lru_cap_and_clears_on_close`.

### Shadow, Canary, and behavior drift

- Shadow effect refusal and containment: `tests/test_package_activation.py::test_shadow_side_effect_attempt_is_quarantined` and `::test_broker_failures_fail_closed`.
- Canary bounds, failed promotion, restart, version isolation, and self-promotion refusal: `tests/test_package_activation.py::test_canary_bounds_trigger_effect_rollback_and_quarantine`, `::test_failed_canary_and_missing_verification_cannot_promote`, `::test_generated_package_cannot_self_promote_before_trusted_canary`, `::test_new_version_starts_fresh_and_rolls_back_to_prior_version`, and `::test_activation_never_accepts_changed_source_or_duplicate_lifecycle`.
- Undeclared behavior and security containment: `tests/test_capability_health.py::test_all_security_drift_categories_and_broker_trust_boundary` and `::test_material_and_security_drift_escalate_without_auto_recovery`.
- Certified baseline integrity: `tests/test_capability_health.py::test_baseline_is_hashed_and_generated_or_model_rewrites_fail`.

### Generated UI and presentation

- Executable content, arbitrary assets, oversized content, and unregistered actions: `tests/test_ui_simulation.py::test_oversized_or_executable_content_is_not_loaded`, `::test_bad_asset_and_hash_fail_closed`, `::test_missing_action_is_evidence_failure_and_fake_action_has_zero_effects`, and `::test_manifest_and_component_contracts_fail_closed`.
- Trusted approval impersonation: `tests/test_ui_simulation.py::test_approval_spoof_is_rejected_by_security_evidence` and `::test_semantic_authority_spoof_is_rejected_even_without_known_button_names`.
- Deterministic semantic/control evidence and ArtifactStore capture: `tests/test_ui_simulation.py::test_all_states_and_generic_component_types_render_deterministically` and `::test_shot_captures_semantic_render_artifact`.

### Plan editing, replay, and unknown outcomes

- Plan revision and stale approval invalidation: `tests/test_planning_engine.py::test_plan_edit_invalidates_approval_when_effect_fingerprint_changes`, `::test_plan_inspection_edit_revision_and_restart_history`, and `::test_invalid_plan_edit_cannot_remove_required_or_dependent_step`.
- Checkpoint branches do not inherit uncertain effects: `tests/test_planning_engine.py::test_checkpoint_branch_rejects_unknown_outcome` and `tests/test_trace.py::test_replan_from_checkpoint_does_not_replay_external_effect`.
- Replay refuses unknown or unmarked external effects and does not inherit approval: `tests/test_trace.py::test_replay_simulation_has_no_effects_and_safe_replay_never_inherits_approval` and `::test_replay_refuses_unknown_outcome_and_unmarked_external_effect`.

### Backup, recovery, and migration

- Altered encrypted bundle and wrong key: `tests/test_backup.py::test_backup_is_encrypted_authenticated_and_wrong_key_fails` and `::test_tampered_ciphertext_and_secret_components_fail_closed`.
- Machine-bound credentials require reauthorization and generated integrations require recertification: `tests/test_backup.py::test_cross_machine_requires_reauthorization_and_generated_recertification`.
- Selective restore, missing sources, schema bounds, conflict analysis, and rollback: `tests/test_backup.py::test_selective_restore_uses_only_selected_component_and_applier`, `::test_external_source_requires_explicit_relink_and_missing_source_is_not_imported`, `::test_legacy_manifest_migrates_and_future_manifest_refuses`, and `::test_restore_rolls_back_on_unexpected_failure_and_reports_rollback_failure`.
- LKG integrity, failed-start recovery, crash-loop containment, and Safe Mode: `tests/test_recovery.py::test_snapshot_file_tampering_is_rejected_before_restore`, `::test_bad_candidate_restores_restarts_and_verifies_lkg`, `::test_crash_loop_threshold_and_malformed_evidence_fail_closed`, and `::test_failure_without_lkg_enters_safe_mode`.

### Self-improvement, Golden Workflows, and setup/adoption

- Trust classification and test/gate tampering: `tests/test_improvement.py::test_risk_classification_cannot_be_lowered_by_a_candidate`, `::test_gate_catalog_rejects_missing_and_duplicate_mandatory_gates`, `::test_security_gate_rejects_dangerous_generated_code`, and `::test_gate_and_static_security_evidence_must_bind_exact_changed_paths`.
- Golden Workflow expectation tampering, exclusion, regeneration, and unknown results: `tests/test_golden_workflows.py::test_candidate_gate_rejects_expected_tampering_and_exclusion`, `::test_trace_cannot_become_golden_when_unknown_or_failed`, and `::test_trace_requires_verification_and_rejects_unknown_outcome`.
- Malicious candidate cannot edit protected code or bypass gates: `tests/test_improvement.py::test_routine_improvement_cannot_propose_trusted_core_changes`, `::test_failed_test_gate_stops_proposal_and_quarantines_workspace`, and `::test_security_adapter_exception_fails_closed_before_tests`.
- Incompatible adoption is not silent and declined data is preserved: `tests/test_setup_conductor.py::test_incompatible_installation_is_not_adopted_and_install_new_is_typed`, `::test_existing_local_runtime_is_adopted_without_provisioning`, and `::test_declined_adoption_preserves_existing_user_data`.
- Adoption/setup does not bypass authority: `tests/test_setup_conductor.py::test_permission_required_provisioning_is_not_bypassed`, `tests/test_capability_factory.py::test_declined_adoption_is_inactive_and_does_not_build`, and `::test_generated_package_stops_ready_for_approval_and_never_registers_active`.

### Voice permission and microphone separation

- Ambiguous spoken responses, trusted narration, and model-crafted approval text: `tests/trusted_core/test_permission_presentation.py::test_spoken_approval_is_strict_and_non_authorizing`, `::test_narrator_builds_one_typed_authority_object_for_all_surfaces`, and `::test_model_crafted_permission_narration_is_not_a_trusted_input`.
- Microphone mode does not alter authority policy: `tests/test_voice.py::test_microphone_modes_are_explicit_and_not_authority_modes`.
- Streaming, early TTS, persistent output, barge-in, stale response suppression, PTT repeat protection, and degradation: `tests/test_voice.py::test_tts_interruption_stops_playback_and_cancels_central_task`, `::test_ptt_key_repeat_is_edge_triggered`, `::test_open_mic_failure_degrades_to_ptt`, `::test_sounddevice_stale_callback_cannot_resurrect_after_stop`, and the capture/stream tests in the same module.

## Negative-test execution policy

All fixtures must remain synthetic and local. Security tests must assert one of:

1. rejection before effect;
2. pause pending trusted authority;
3. bounded cancellation/cleanup;
4. `RECOVERING`, `QUARANTINED`, `DEGRADED`, or Safe Mode containment; or
5. explicit evidence that a derived observation did not become authority.

No test may use a real credential, external URL, uncontrolled network scan,
product-specific adapter, donor runtime, or production bypass flag. Tests that
need process behavior use owned local fakes and typed IPC fixtures.

## Commands and evidence

The following checks are required for this run:

```text
python scripts/quality.py
python scripts/run_system_tests.py --suite deterministic-workflows
python scripts/run_system_tests.py --suite deterministic-permissions
```

The security-focused pytest run covers the modules listed in the matrix,
including `tests/trusted_core`. The optional
`tests/test_windows_integration.py` checks remain hardware/manual and are not
treated as passed when skipped.

Observed local results for this run:

- security-focused selection: **686 passed, 2 skipped**;
- `scripts/quality.py`: **1,149 passed, 5 skipped**, Ruff and mypy passed,
  total coverage **90%**;
- `deterministic-workflows`: **26 passed**;
- `deterministic-permissions`: **70 passed, 1 skipped**.

The skips are environment-bounded optional checks; they are not converted into
passes and do not weaken a security assertion.

## Result interpretation

This document records regression coverage, not a claim that every possible
security defect has been eliminated. A missing or failing negative test is a
release blocker until the boundary is repaired and the test is green. No new
authority is granted by these tests, and no donor project is a runtime
dependency.
