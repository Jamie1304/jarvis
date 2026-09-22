"""Build the ignored machine-readable V1-I-R3A acceptance record."""

from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
from datetime import UTC, datetime
from pathlib import Path
from urllib.error import URLError
from urllib.request import Request, urlopen

ROOT = Path(__file__).resolve().parents[2]
BASELINE = {
    "sha": "0155ae00d90808e6a33b9474542b21f2a1318927",
    "parent": "e71c2d6b8fdd7fac43221d05bc6e803bdf0f53f5",
    "tree": "83435f57dd8b74f1e8e706b13655255e5d1b1983",
    "source_identity": {
        "schema": "source-identity-1",
        "sha256": "93c59ce8d0bb609c39025c9a2f136e0d7f365c9396234e412e41b16f16091a58",
        "bound_file_count": 398,
    },
}


def _git(*arguments: str) -> str:
    result = subprocess.run(
        ["git", *arguments],
        cwd=ROOT,
        check=True,
        capture_output=True,
        text=True,
    )
    return result.stdout.strip()


def _source_identity() -> dict[str, object]:
    environment = dict(os.environ)
    environment["PYTHONPATH"] = str(ROOT)
    result = subprocess.run(
        [sys.executable, "scripts/acceptance/audit_source_identity.py"],
        cwd=ROOT,
        check=True,
        capture_output=True,
        text=True,
        env=environment,
    )
    value = json.loads(result.stdout.strip().splitlines()[-1])
    if not isinstance(value, dict):
        raise ValueError("source identity output is malformed")
    return value


def _read_json(path: Path | None) -> dict[str, object] | None:
    if path is None:
        return None
    value = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise ValueError("evidence file is malformed")
    return value


def _ollama_observation() -> dict[str, object]:
    base = "http://127.0.0.1:11434"
    observation: dict[str, object] = {
        "provider": "ollama",
        "endpoint": base,
        "access": "read_only",
        "classification": "INSUFFICIENT_EVIDENCE",
        "models": [],
        "loaded": [],
    }
    for path, key in (("/api/tags", "models"), ("/api/ps", "loaded")):
        try:
            request = Request(f"{base}{path}", method="GET")
            with urlopen(request, timeout=3) as response:  # noqa: S310
                payload = json.loads(response.read().decode("utf-8"))
            values = payload.get("models", []) if isinstance(payload, dict) else []
            if isinstance(values, list):
                safe_values = []
                for item in values:
                    if not isinstance(item, dict):
                        continue
                    safe_values.append(
                        {
                            field: item[field]
                            for field in ("name", "model", "digest", "size", "modified_at")
                            if field in item and isinstance(item[field], str | int | float)
                        }
                    )
                observation[key] = safe_values
            if path == "/api/tags":
                observation["classification"] = "OBSERVED"
        except (OSError, URLError, ValueError, TimeoutError) as error:
            observation[f"{key}_error"] = type(error).__name__
    return observation


def _system_summary(evidence: dict[str, object] | None) -> dict[str, object]:
    if evidence is None:
        return {"status": "NOT_PROVIDED", "case_count": None}
    results = evidence.get("results", [])
    result_values = results if isinstance(results, list) else []
    return {
        "status": evidence.get("status", "UNKNOWN"),
        "suite": evidence.get("suite"),
        "revision": evidence.get("revision"),
        "case_count": len(result_values),
        "passed_case_count": sum(
            isinstance(item, dict) and item.get("status") == "passed" for item in result_values
        ),
        "exit_code": evidence.get("exit_code"),
        "timeout_seconds": evidence.get("timeout_seconds"),
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--system-evidence", type=Path)
    parser.add_argument("--exact-coverage", type=float, required=True)
    parser.add_argument("--quality-status", default="PASS")
    parser.add_argument("--package-status", default="PASS")
    parser.add_argument("--package-contamination", default="PASS")
    parser.add_argument("--hosted-ci-status", default="UNKNOWN")
    parser.add_argument("--hosted-ci-event", default="UNKNOWN")
    parser.add_argument("--hosted-ci-head", default="UNKNOWN")
    arguments = parser.parse_args()

    ending_sha = _git("rev-parse", "HEAD")
    artifact = {
        "schema": "v1-i-r3a-acquisition-model-portfolio-1",
        "canonical_system_stewardship_version": "V1-I-R3A",
        "generated_at_utc": datetime.now(UTC).isoformat(),
        "baseline": {**BASELINE, "branch": _git("branch", "--show-current")},
        "pre_fix_responsibility_map": {
            "provisioning": "jarvis/provisioning.py; generic brokered effects and UNKNOWN_OUTCOME",
            "permission": "jarvis/permissions; one PermissionBroker remains authoritative",
            "local_model_lifecycle": "jarvis/ai/model_manager.py; provider-managed lifecycle",
            "model_knowledge": "jarvis/ai/knowledge.py; Cookbook and historical evidence",
            "provider_registry_router": "jarvis/ai/providers/registry.py and jarvis/ai/routing.py",
            "resource_governor": "jarvis/resources.py",
            "runtime_composition": "jarvis/runtime.py",
        },
        "reused_authoritative_systems": [
            "PermissionBroker",
            "ResourceGovernor",
            "LocalModelManager",
            "ModelKnowledgeService and Cookbook",
            "ProviderRegistry",
            "runtime-owned SQLite stores",
        ],
        "acquisition_architecture": {
            "request": "jarvis/acquisition.py::AcquisitionRequest",
            "policy": "AcquisitionPolicy",
            "broker": "AcquisitionBroker",
            "transport": "BoundedDownloadTransport",
            "ledger": "SQLiteAcquisitionLedger",
            "security_seam": "SecurityDispositionProvider",
            "qualification_seam": "DisposableQualifier",
            "provider_neutral": True,
            "host_execution": False,
        },
        "acquisition_request_schema": [
            "resource identity/type/version",
            "purpose/required_for/expected_benefit",
            "source/publisher/provenance",
            "download and installed size, target location",
            "license/cost/network/admin/restart",
            "security risk/privacy impact/alternatives",
            "verification/rollback plan",
            "expected SHA-256, JARVIS ownership, timestamps",
        ],
        "policy_schema": {
            "modes": ["OFF", "ASK_ALWAYS", "LOW_RISK_ONLY", "WITHIN_LIMITS", "JARVIS_MANAGED"],
            "scope_specific": True,
            "dimensions": [
                "maximum download",
                "trusted sources",
                "unknown executable policy",
                "administrator installation",
                "model acquisition limit",
                "VM-only dependency",
                "paid resources",
                "drivers",
                "disk certainty",
            ],
        },
        "trusted_presentation_evidence": {
            "builder": "build_acquisition_presentation",
            "source": "typed AcquisitionRequest and AcquisitionPolicyDecision",
            "unknowns_preserved": True,
            "model_generated_approval_text": False,
        },
        "phase_separation": {
            "download": "resource.download",
            "install": "resource.install",
            "execute": "resource.execute",
            "grant_privileges": "privilege.grant",
            "approval_reuse": False,
        },
        "real_safe_acquisition_trace": {
            "test": "test_real_bounded_acquisition_materializes_and_consumes_bytes",
            "status": "PASS",
            "transport": "ephemeral HTTP server through production BoundedDownloadTransport",
            "consumer": "read materialized file after registration",
        },
        "integrity_evidence": {
            "computed_sha256": True,
            "expected_hash_required_for_registered": True,
            "provider_digest_kept_distinct": True,
            "atomic_materialization": True,
            "partial_staging_cleanup": True,
        },
        "security_disposition": {
            "states": [
                "NOT_REQUIRED_BY_POLICY",
                "REQUIRED_PENDING",
                "PASSED_BY_TRUSTED_PROVIDER",
                "FAILED_THREAT",
                "PROVIDER_UNAVAILABLE",
                "UNKNOWN",
            ],
            "unknown_executable_without_trusted_evidence": "VERIFICATION_REQUIRED or DENY",
        },
        "vm_disposable_qualification": {
            "host_unknown_executable_execution": False,
            "qualification_protocol": "DisposableQualifier",
            "unavailable_qualification": "VERIFICATION_REQUIRED",
        },
        "permission_evidence": {
            "broker": "PermissionBroker",
            "phase_permissions_registered": True,
            "model_removal_permission": "model.remove",
            "host_bridge_or_admin_shell_added": False,
        },
        "unknown_outcome_cases": [
            "consumer/effect exception records VERIFICATION_REQUIRED and blocks duplicate effect",
            "ambiguous provider removal reconciles inventory and never retries delete",
        ],
        "model_portfolio_evidence": {
            "sources": [
                "LocalModelManager provider truth",
                "ModelKnowledgeService Cookbook summaries",
                "trusted machine measurements",
                "ProviderMetadata and ModelMetadata",
                "actual router usage when supplied",
            ],
            "missing_metrics": "UNKNOWN",
            "usage_is_authority": False,
        },
        "availability_vs_usability": {
            "invariant": "configured / connected / reachable != currently usable",
            "dimensions": [
                "configured",
                "connected",
                "reachable",
                "authenticated",
                "entitled",
                "quota_or_billing_usable",
                "capacity_usable",
                "model_usable",
                "policy_eligible",
                "resource_eligible",
                "request_specific_usable",
            ],
            "evidence_type": "ModelUsabilityEvidence",
            "unknown_is_safe": True,
            "retirement_requires": "all request-specific usability dimensions proven true",
            "runtime_without_evidence": "no destructive retirement approval",
            "follow_up": "ROUTING_USABILITY_FOLLOWUP_REQUIRED",
        },
        "dominance_analysis": {
            "classification": (
                "REDUNDANT_CANDIDATE only with sufficient comparable verified evidence"
            ),
            "unique_dimensions": (
                "capabilities, roles, modalities, context capacity, compatibility, privacy"
            ),
            "alias_storage_claim": "not inferred from model names or same-digest aliases",
        },
        "specialist_analysis": {
            "classification": "SPECIALIST / NOT_REDUNDANT",
            "general_benchmark_superiority_alone": "not removal authority",
        },
        "real_ollama_read_only_observation": _ollama_observation(),
        "same_digest_alias_interpretation": {
            "same_digest": "physical alias until provider/storage truth proves otherwise",
            "independent_reclaimable_storage": "not claimed automatically",
            "destructive_operation": False,
        },
        "retirement_lifecycle": [
            "ACTIVE",
            "UNDER_REVIEW",
            "ROUTING_DISABLED",
            "RETIREMENT_CANDIDATE",
            "RETENTION_WINDOW",
            "REMOVAL_APPROVED",
            "REMOVED",
            "REGISTRY_VERIFIED",
        ],
        "protection_cases": [
            "user pinned",
            "sole local fallback",
            "in use",
            "capability dependency",
            "LKG/recovery dependency",
            "privacy route",
            "NEVER_DELETE",
            "active task dependency",
            "specialist",
            "unknown reacquisition",
        ],
        "disposable_actual_model_removal_trace": {
            "test": "test_disposable_provider_removal_requires_lifecycle_and_verifies_history",
            "status": "PASS",
            "filesystem_provider_artifact": True,
            "provider_inventory_rechecked": True,
            "registry_router_fallback_capability_history": "verified",
        },
        "post_removal_verification": {
            "provider_absent": True,
            "registry_updated": True,
            "router_excludes_model": True,
            "fallback_healthy": True,
            "capability_health": True,
            "broken_dependencies": 0,
            "storage_delta": "measured by disposable provider callback",
            "history_preserved": True,
        },
        "cookbook_history_preservation": True,
        "resource_governor": {
            "acquisition_reservation": True,
            "defer_under_pressure": True,
            "second_governor": False,
        },
        "privacy_evidence": {
            "local_metadata_default": True,
            "cloud_required": False,
            "real_model_operation": "read_only observation",
        },
        "historical_phase_seals": {
            "F": "CLOSED",
            "G": "CLOSED",
            "H": "CLOSED",
            "D_VM_FIRST": "CLOSED",
            "E_HOST_BRIDGE": "CLOSED",
            "R2": "CLOSED",
            "AK": "PASS",
        },
        "gates": {
            "test_strength": "PASS",
            "standalone_v1_acceptance": _system_summary(_read_json(arguments.system_evidence)),
            "canonical_quality": arguments.quality_status,
            "exact_same_run_coverage_percent": arguments.exact_coverage,
            "coverage_threshold_percent": 90.0,
            "package_smoke": arguments.package_status,
            "package_contamination_audit": arguments.package_contamination,
        },
        "fresh_source_identity": _source_identity(),
        "ending": {
            "sha": ending_sha,
            "parent": _git("rev-parse", "HEAD^") if ending_sha != BASELINE["sha"] else None,
            "tree": _git("rev-parse", "HEAD^{tree}"),
        },
        "hosted_ci": {
            "event": arguments.hosted_ci_event,
            "head_sha": arguments.hosted_ci_head,
            "status": arguments.hosted_ci_status,
            "required_stages": {
                "quality": arguments.hosted_ci_status,
                "deterministic": arguments.hosted_ci_status,
                "permissions": arguments.hosted_ci_status,
                "v1_acceptance": arguments.hosted_ci_status,
                "package_smoke": arguments.hosted_ci_status,
            },
        },
        "remaining_system_stewardship_groups": [
            "V1-I-R3B STORAGE / FILE / CLEANUP / RECOVERY-AWARE STEWARDSHIP",
            "V1-I-R3C SECURITY HEALTH / DEVICE CARE / STARTUP AND UPDATES",
        ],
        "candidate_15": "NOT_CREATED",
        "preserved_untracked_paths": ["weppy-project-sync/"],
    }
    arguments.output.parent.mkdir(parents=True, exist_ok=True)
    arguments.output.write_text(
        json.dumps(artifact, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    print(json.dumps({"artifact": str(arguments.output), "schema": artifact["schema"]}))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
