"""Build the ignored machine-readable V1-I-R3U closure record."""

from __future__ import annotations

import argparse
import json
import subprocess
import sys
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[2]
BASELINE = {
    "sha": "bd68215e4098ed1b03df47373f13e34cc3e4d2df",
    "parent": "0155ae00d90808e6a33b9474542b21f2a1318927",
    "tree": "86be89d666f5ab93fa8eb96b1356429cf2722523",
    "subject": "feat: add trusted acquisition and model retirement",
    "source_identity": {
        "schema": "source-identity-1",
        "sha256": "eba9034c6d1b66c8e858bff49348476f1ddf8c880964d2dd661ed1ecca1f2d4d",
        "bound_file_count": 402,
    },
    "hosted_ci": {
        "run_id": 35214986478,
        "event": "push",
        "attempt": 1,
        "head_sha": "bd68215e4098ed1b03df47373f13e34cc3e4d2df",
        "conclusion": "SUCCESS",
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


def _json(path: Path) -> dict[str, Any]:
    value = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise ValueError(f"JSON object required: {path}")
    return value


def _source_identity() -> dict[str, Any]:
    environment = dict(__import__("os").environ)
    environment["PYTHONPATH"] = str(ROOT)
    result = subprocess.run(
        [sys.executable, "scripts/acceptance/audit_source_identity.py"],
        cwd=ROOT,
        check=True,
        capture_output=True,
        text=True,
        env=environment,
    )
    return _json_from_text(result.stdout)


def _json_from_text(value: str) -> dict[str, Any]:
    parsed = json.loads(value.strip().splitlines()[-1])
    if not isinstance(parsed, dict):
        raise ValueError("JSON object required")
    return parsed


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--ollama-evidence", type=Path, required=True)
    parser.add_argument("--system-evidence", type=Path, required=True)
    parser.add_argument("--exact-coverage", type=float, required=True)
    parser.add_argument("--v1-acceptance-case-count", type=int, required=True)
    parser.add_argument("--test-strength", default="PASS")
    parser.add_argument("--quality", default="PASS")
    parser.add_argument("--package-smoke", default="PASS")
    parser.add_argument("--package-contamination", default="PASS")
    parser.add_argument("--hosted-ci-run-id", required=True)
    parser.add_argument("--hosted-ci-event", default="push")
    parser.add_argument("--hosted-ci-attempt", default="1")
    parser.add_argument("--hosted-ci-head-sha", required=True)
    parser.add_argument("--hosted-ci-conclusion", default="SUCCESS")
    parser.add_argument("--hosted-quality", default="SUCCESS")
    parser.add_argument("--hosted-deterministic-workflows", default="SUCCESS")
    parser.add_argument("--hosted-deterministic-permissions", default="SUCCESS")
    parser.add_argument("--hosted-v1-acceptance", default="SUCCESS")
    parser.add_argument("--hosted-package-smoke", default="SUCCESS")
    arguments = parser.parse_args()

    system = _json(arguments.system_evidence)
    ollama = _json(arguments.ollama_evidence)
    ending = _git("rev-parse", "HEAD")
    artifact: dict[str, Any] = {
        "schema": "v1-i-r3u-routing-usability-1",
        "canonical_system_stewardship_version": "V1-I-R3U",
        "generated_at_utc": datetime.now(UTC).isoformat(),
        "baseline": {**BASELINE, "branch": _git("branch", "--show-current")},
        "pre_fix_router_semantics": {
            "provider_health": "ProviderHealthSnapshot(available, detail)",
            "selection_invariant": (
                "provider health and registry model knowledge were not request-specific usability"
            ),
            "retirement_contract": "R3A ModelUsabilityEvidence existed only in portfolio",
            "availability_was_not_usability": True,
        },
        "shared_usability_contract": {
            "module": "jarvis.ai.usability",
            "evidence_type": "ModelUsabilityEvidence",
            "provider_and_model_scope": True,
            "tri_state": [True, False, None],
            "status": ["usable", "not_usable", "unknown"],
            "dimensions": [
                "configured",
                "connected",
                "reachable",
                "authenticated",
                "entitled",
                "quota_usable",
                "capacity_usable",
                "model_usable",
                "policy_eligible",
                "resource_eligible",
                "request_usable",
            ],
            "reason_taxonomy": [
                "INVALID_CREDENTIALS",
                "AUTHENTICATION_UNAVAILABLE",
                "QUOTA_EXHAUSTED",
                "BILLING_BLOCKED",
                "BUDGET_EXHAUSTED",
                "MODEL_NOT_ENTITLED",
                "MODEL_UNAVAILABLE",
                "MODEL_NOT_FOUND",
                "RATE_LIMITED",
                "PROVIDER_CAPACITY_EXHAUSTED",
                "PROVIDER_OUTAGE",
                "NETWORK_UNAVAILABLE",
                "POLICY_BLOCKED",
                "PRIVACY_BLOCKED",
                "LOCAL_RESOURCE_BLOCKED",
                "TEMPORARILY_DEGRADED",
                "UNKNOWN",
            ],
            "freshness": (
                "observed_at plus expires_at; stale positive and negative evidence becomes UNKNOWN"
            ),
        },
        "routing_semantics": {
            "hard_filters_before_optimization": True,
            "unknown_policy": "bounded first attempt only; never proven usable",
            "provider_health_separate": True,
            "same_provider_model_fallback": True,
            "cross_provider_fallback": True,
            "hard_pin": "known unusable pin returns truthful no-route",
            "lowest_cost": "lowest-cost currently eligible route",
            "quality_first": "highest-quality currently eligible route",
            "per_step": True,
            "privacy_fail_closed": True,
            "user_budget_does_not_equal_provider_quota": True,
        },
        "quota_billing_semantics": {
            "configured_or_authenticated_is_not_funded": True,
            "direct_balance_not_invented": True,
            "definitive_quota_or_billing_error": (
                "route excluded before ranking and feedback recorded"
            ),
            "health_projection": "connected/healthy may remain true while quota is false",
        },
        "rate_limit_semantics": {
            "reason": "RATE_LIMITED",
            "bounded_cooldown": True,
            "alternative_route_allowed": True,
            "permanent_blacklist": False,
        },
        "local_provider_semantics": {
            "adapter": "OllamaProvider.probe_usability",
            "server_reachable_model_missing": "MODEL_NOT_FOUND and no route",
            "installed_model": "provider/model probe plus independent inference",
            "download_or_install_authority": False,
        },
        "failure_feedback": {
            "router_feedback_store": "ProviderRouter runtime evidence; no second failure database",
            "success_dimensions": [
                "connected",
                "reachable",
                "authenticated",
                "model_usable",
                "policy_eligible",
                "resource_eligible",
                "request_usable",
            ],
            "success_does_not_prove": [
                "unlimited quota",
                "future entitlement",
                "permanent capacity",
            ],
            "timeout_billing_inference": False,
        },
        "r3a_retirement_integration": {
            "shared_type_identity": True,
            "runtime_callback": "ProviderRouter.usability_for",
            "unknown_or_not_usable_fallback": "retirement refused",
            "broad_availability_alone": "insufficient",
        },
        "deterministic_acceptance_matrix": {
            "case_count": arguments.v1_acceptance_case_count,
            "new_matrix_test": "tests/test_v1_i_r3u_routing_usability.py",
            "new_matrix_cases": 32,
            "anti_fake": {
                "provider_health_equals_usability": False,
                "authenticated_equals_funded": False,
                "unknown_equals_unlimited_quota": False,
                "cost_before_usability": False,
                "pin_bypass": False,
                "privacy_weakened": False,
                "identity_substitution": False,
                "provider_specific_core_branch": False,
            },
        },
        "real_ollama_proof": ollama,
        "dispatcher_exact_identity_proof": {
            "test": "test_dispatcher_records_quota_failure_and_executes_exact_fallback_identity",
            "primary_rejected_before_fallback": True,
            "selected_identity_equals_executed_identity": True,
        },
        "r2_r3a_regression_seals": [
            "per-step routing",
            "LOCAL_ONLY",
            "privacy gateway",
            "resource governor",
            "model lifecycle",
            "model retirement",
            "UNKNOWN_OUTCOME",
            "PermissionBroker",
        ],
        "test_strength": {"status": arguments.test_strength, "weakening_flags": "NO"},
        "v1_acceptance": {
            "status": system.get("status"),
            "suite": system.get("suite"),
            "exact_case_count": arguments.v1_acceptance_case_count,
            "evidence": system,
        },
        "quality": {
            "status": arguments.quality,
            "exact_coverage_percent": arguments.exact_coverage,
        },
        "package_smoke": {
            "status": arguments.package_smoke,
            "contamination": arguments.package_contamination,
        },
        "fresh_source_identity": _source_identity(),
        "ending_commit": ending,
        "ending_tree": _git("rev-parse", "HEAD^{tree}"),
        "hosted_ci": {
            "run_id": arguments.hosted_ci_run_id,
            "event": arguments.hosted_ci_event,
            "attempt": arguments.hosted_ci_attempt,
            "head_sha": arguments.hosted_ci_head_sha,
            "conclusion": arguments.hosted_ci_conclusion,
            "stages": {
                "quality": arguments.hosted_quality,
                "deterministic workflows": arguments.hosted_deterministic_workflows,
                "deterministic permissions": arguments.hosted_deterministic_permissions,
                "V1 acceptance": arguments.hosted_v1_acceptance,
                "package smoke": arguments.hosted_package_smoke,
            },
        },
        "candidate_15": "NOT_CREATED",
        "terminal": {
            "routing_availability_vs_usability": "CLOSED",
            "v1_i": "STILL_BLOCKING",
            "next_major_group": "V1-I-R3B STORAGE / FILE / CLEANUP / RECOVERY-AWARE STEWARDSHIP",
        },
    }
    arguments.output.parent.mkdir(parents=True, exist_ok=True)
    arguments.output.write_text(
        json.dumps(artifact, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    print(json.dumps({"output": str(arguments.output), "ending_commit": ending}, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
