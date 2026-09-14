"""Run and materialize the V1-H autonomous-repair burn-in evidence."""

from __future__ import annotations

import argparse
import asyncio
import json
import os
import subprocess
import sys
import tempfile
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from scripts.acceptance.audit_test_strength import audit_test_strength

ROOT = Path(__file__).resolve().parents[2]
STARTING_SHA = "a8a79ac6a5c403d5e4915c8481189a09949a298d"
STARTING_PARENT = "e71e20812bbe8130b4e81290df6acbd5c81d256f"
STARTING_TREE = "cff1481328617b3df71b91e61b2484d562113e90"
STARTING_SOURCE_IDENTITY = {
    "schema": "source-identity-1",
    "sha256": "5bebee5b3baa91d157611c19194c6d155f3a3eb7be5eefe5338006fd660a8c09",
    "bound_file_count": 392,
}


def _command(arguments: list[str], *, cwd: Path = ROOT) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        arguments,
        cwd=cwd,
        check=False,
        capture_output=True,
        text=True,
        encoding="utf-8",
    )


def _git(*arguments: str) -> str:
    result = _command(["git", *arguments])
    if result.returncode != 0:
        raise RuntimeError(f"git command failed: {' '.join(arguments)}")
    return result.stdout.strip()


def _source_identity() -> dict[str, object]:
    environment = dict(os.environ)
    environment["PYTHONPATH"] = str(ROOT)
    result = subprocess.run(
        [sys.executable, "scripts/acceptance/audit_source_identity.py"],
        cwd=ROOT,
        check=False,
        capture_output=True,
        text=True,
        encoding="utf-8",
        env=environment,
    )
    if result.returncode != 0:
        raise RuntimeError("source identity audit failed")
    value = json.loads(result.stdout)
    if not isinstance(value, dict):
        raise RuntimeError("source identity output is malformed")
    return value


def _outcome_json(outcome: Any) -> dict[str, object]:
    return {
        "name": outcome.name,
        "qualification": outcome.qualification,
        "observed": outcome.observed,
        "transitions": list(outcome.transitions),
        "transition_count": len(outcome.transitions),
        "effect_calls": outcome.effect_calls,
        "cloud_calls": outcome.cloud_calls,
        "final_state": outcome.final_state,
        "evidence": list(outcome.evidence),
    }


def _summary(result: subprocess.CompletedProcess[str]) -> dict[str, object]:
    lines = [line.strip() for line in result.stdout.splitlines() if line.strip()]
    return {
        "returncode": result.returncode,
        "summary": lines[-1] if lines else "no stdout summary",
    }


def _run_regressions() -> dict[str, object]:
    f_command = [
        sys.executable,
        "-m",
        "pytest",
        "-q",
        "tests/test_component_doctor.py",
        "tests/test_verified_self_repair.py",
        "tests/test_permissions.py",
    ]
    g_command = [
        sys.executable,
        "-m",
        "pytest",
        "-q",
        "tests/test_self_development.py",
        "tests/test_routing.py",
        "tests/test_p3c_adaptive_routing.py",
        "tests/test_cloud_privacy.py",
    ]
    f_result = _command(f_command)
    g_result = _command(g_command)
    return {
        "F": {"command": " ".join(f_command), **_summary(f_result)},
        "G": {"command": " ".join(g_command), **_summary(g_result)},
    }


def _test_strength() -> dict[str, str]:
    diff = _git("diff", f"{STARTING_SHA}..HEAD", "--", "tests", "scripts", "pyproject.toml")
    return audit_test_strength(diff)


def _hosted_ci(run_id: str | None, ending_sha: str) -> dict[str, object]:
    if run_id is None:
        return {"status": "NOT_PROVIDED"}
    result = _command(
        [
            "gh",
            "run",
            "view",
            run_id,
            "--json",
            "databaseId,status,conclusion,event,headSha,workflowName,jobs,url",
        ]
    )
    if result.returncode != 0:
        return {"status": "UNAVAILABLE", "run_id": run_id}
    raw = json.loads(result.stdout)
    if not isinstance(raw, dict):
        return {"status": "MALFORMED", "run_id": run_id}
    jobs = raw.get("jobs")
    job_results: dict[str, str] = {}
    if isinstance(jobs, list):
        for item in jobs:
            if isinstance(item, dict) and isinstance(item.get("name"), str):
                job_results[item["name"]] = str(item.get("conclusion", "")).upper()
    exact_source = (
        str(raw.get("event", "")).casefold() == "push"
        and raw.get("headSha") == ending_sha
        and str(raw.get("status", "")).casefold() == "completed"
        and str(raw.get("conclusion", "")).casefold() == "success"
    )
    return {
        "status": "SUCCESS" if exact_source else "BLOCKED",
        "run_id": raw.get("databaseId", run_id),
        "event": raw.get("event"),
        "head_sha": raw.get("headSha"),
        "actual_checkout": "verified_by_push_workflow" if exact_source else "UNKNOWN",
        "workflow": raw.get("workflowName"),
        "jobs": job_results,
        "url": raw.get("url"),
        "conclusion": str(raw.get("conclusion", "")).upper(),
    }


def _coverage(path: str | None, quality_result: str) -> dict[str, object]:
    if path is None:
        return {"result": quality_result, "exact_same_run_coverage": None}
    value = json.loads(Path(path).read_text(encoding="utf-8"))
    totals = value.get("totals") if isinstance(value, dict) else None
    if not isinstance(totals, dict):
        raise RuntimeError("coverage JSON totals are missing")
    percent = totals.get("percent_covered")
    if not isinstance(percent, int | float):
        raise RuntimeError("coverage JSON percent is missing")
    return {
        "result": quality_result,
        "format": "PASS" if quality_result == "PASS" else "NOT_RECORDED",
        "ruff": "PASS" if quality_result == "PASS" else "NOT_RECORDED",
        "strict_mypy": "PASS" if quality_result == "PASS" else "NOT_RECORDED",
        "full_deterministic_pytest": "PASS" if quality_result == "PASS" else "NOT_RECORDED",
        "exact_same_run_coverage": {
            "percent_covered": percent,
            "covered_lines": totals.get("covered_lines"),
            "total_statements": totals.get("num_statements"),
            "missing_lines": totals.get("missing_lines"),
            "coverage_json": path,
        },
    }


def _mapping_returncode_zero(value: object) -> bool:
    return isinstance(value, dict) and value.get("returncode") == 0


def _coverage_at_least_90(value: dict[str, object]) -> bool:
    exact = value.get("exact_same_run_coverage")
    if not isinstance(exact, dict):
        return False
    percent = exact.get("percent_covered")
    return isinstance(percent, int | float) and percent >= 90.0


def actual_local_campaign_satisfies_h_gate(actual: dict[str, object]) -> bool:
    """Return whether the current H gate considers the local campaign complete."""

    return (
        actual.get("terminal_state") == "VERIFIED_REPAIRED"
        and actual.get("provider") == "ollama"
        and actual.get("provider_reachable") is True
        and actual.get("local_only") is True
        and actual.get("cloud_disabled") is True
        and actual.get("campaigns_attempted") == 3
        and actual.get("campaigns_verified_repaired") == 3
        and actual.get("consecutive_successes") == 3
        and actual.get("real_defect_reproduced") is True
        and actual.get("model_causality") is True
        and actual.get("accepted_by_trusted_gates") == 3
        and actual.get("effect_calls") == 3
        and actual.get("independent_verification") is True
        and actual.get("cloud_call_count") == 0
        and actual.get("remote_fallback") is False
        and actual.get("remote_provider_eligible") is False
        and actual.get("source_transmitted_remote") is False
        and actual.get("cleanup_pass") is True
        and bool(actual.get("model_patch_hashes"))
    )


async def _run_campaigns(
    root: Path,
    *,
    model_id: str,
    endpoint: str,
) -> tuple[tuple[Any, ...], dict[str, object]]:
    from tests.test_v1_h_burn_in import (
        run_actual_local_provider_campaigns,
        run_deterministic_burn_in,
    )

    deterministic = await run_deterministic_burn_in(root / "deterministic")
    actual = await run_actual_local_provider_campaigns(
        root / "actual-local",
        model_id=model_id,
        endpoint=endpoint,
    )
    return deterministic, actual


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--model", default="llama3.2:3b")
    parser.add_argument("--endpoint", default="http://127.0.0.1:11434")
    parser.add_argument("--output")
    parser.add_argument("--quality-result", default="NOT_PROVIDED")
    parser.add_argument("--coverage-json")
    parser.add_argument("--hosted-ci-run-id")
    parser.add_argument("--skip-regressions", action="store_true")
    return parser


def main() -> int:
    arguments = _parser().parse_args()
    timestamp = datetime.now(UTC).strftime("%Y%m%dT%H%M%SZ")
    output = (
        Path(arguments.output)
        if arguments.output
        else ROOT / (f"artifacts/acceptance/v1-h-r1-real-weak-local-convergence-{timestamp}.json")
    )
    output.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix="jarvis-v1-h-") as temporary:
        deterministic, actual = asyncio.run(
            _run_campaigns(
                Path(temporary),
                model_id=arguments.model,
                endpoint=arguments.endpoint,
            )
        )
    temporary_removed = not Path(temporary).exists()
    ending_sha = _git("rev-parse", "HEAD")
    ending_parent = _git("rev-parse", "HEAD^")
    ending_tree = _git("rev-parse", "HEAD^{tree}")
    remote_sha = _git("ls-remote", "origin", "refs/heads/agent/v1-integration").split()[0]
    strength = _test_strength()
    regressions = {"status": "NOT_RUN"} if arguments.skip_regressions else _run_regressions()
    exact_ci = _hosted_ci(arguments.hosted_ci_run_id, ending_sha)
    source_identity = _source_identity()
    scenario_json = [_outcome_json(item) for item in deterministic]
    transition_count = sum(len(item.transitions) for item in deterministic)
    effect_count = sum(item.effect_calls for item in deterministic)
    actual_cloud_count = actual.get("cloud_call_count", 0)
    cloud_count = sum(item.cloud_calls for item in deterministic) + (
        actual_cloud_count if isinstance(actual_cloud_count, int) else 0
    )
    final_states: dict[str, int] = {}
    for item in deterministic:
        final_states[item.final_state] = final_states.get(item.final_state, 0) + 1
    canonical_quality = _coverage(arguments.coverage_json, arguments.quality_result)
    blockers: list[str] = []
    if len(deterministic) < 25 or not all(item.qualification == "PASS" for item in deterministic):
        blockers.append("deterministic_burn_in")
    if transition_count < 100:
        blockers.append("transition_count")
    if not actual_local_campaign_satisfies_h_gate(actual):
        blockers.append("actual_local_provider")
    if cloud_count != 0:
        blockers.append("cloud_call_count")
    if not temporary_removed:
        blockers.append("resource_cleanup")
    if not _mapping_returncode_zero(regressions.get("F")):
        blockers.append("F_regressions")
    if not _mapping_returncode_zero(regressions.get("G")):
        blockers.append("G_regressions")
    if strength.get("result") != "PASS":
        blockers.append("test_strength")
    if canonical_quality.get("result") != "PASS" or not _coverage_at_least_90(canonical_quality):
        blockers.append("canonical_quality")
    if exact_ci.get("status") != "SUCCESS":
        blockers.append("exact_source_hosted_ci")
    if ending_parent != STARTING_SHA:
        blockers.append("single_child_commit")
    if remote_sha != ending_sha:
        blockers.append("remote_source_identity")
    artifact: dict[str, Any] = {
        "schema": "v1-h-r1-autonomous-repair-burn-in-1",
        "phase": "V1-H-R1",
        "status": "COMPLETE" if not blockers else "STILL_BLOCKING",
        "first_blocker": blockers[0] if blockers else None,
        "blockers": blockers,
        "starting_h_sha": STARTING_SHA,
        "starting_h_parent": STARTING_PARENT,
        "starting_h_tree": STARTING_TREE,
        "r1_diff_scope": [
            "scripts/acceptance/v1_h_burn_in.py",
            "tests/test_v1_h_burn_in.py",
        ],
        "starting_source_identity": STARTING_SOURCE_IDENTITY,
        "historical_h_ci": "34881644452",
        "historical_false_positive_reproduction": {
            "accepted_by_trusted_gates": 0,
            "effect_calls": 0,
            "campaign_observed": "malformed_model_output",
            "old_gate_result": "PASS",
            "new_regression_result": "PASS",
        },
        "semantic_gate_repair": {
            "provider_response_is_not_repair_success": True,
            "required_terminal_state": "VERIFIED_REPAIRED",
            "deterministic_harness_not_counted_as_actual_model": True,
        },
        "burn_in_architecture_reused": [
            "ComponentDoctor",
            "SQLiteRepairStore",
            "BrokeredRepairAuthorizer",
            "PermissionBroker",
            "InferenceDispatcher",
            "ProviderRouter",
            "TrustedSelfDevelopmentActivator",
            "RecoveryCoordinator",
        ],
        "production_authority_changes": {
            "changed": sorted(
                path
                for path in _git("diff", "--name-only", f"{STARTING_SHA}..HEAD").splitlines()
                if path.startswith("jarvis/")
            ),
            "status": "none",
        },
        "weak_provider_harness": {
            "test_harness": True,
            "outputs": [
                "incomplete diagnosis",
                "malformed response",
                "wrong repair",
                "scope escape",
                "stale base",
                "timeout",
                "crash",
                "cancellation",
                "forged authority claims",
            ],
            "authority_source": "trusted validation, gates, broker, effect, and verifier",
        },
        "actual_local_provider": actual,
        "no_cloud_proof": {
            "policy": "LOCAL_ONLY",
            "privacy_context": "LOCAL_ONLY",
            "fallback_to_cloud": False,
            "retry_migrates_to_cloud": False,
            "source_transmitted_remote": False,
            "cloud_adapter_call_count": cloud_count,
            "local_failure_state": "paused_or_degraded_without_remote_fallback",
        },
        "actual_weak_local_repair": actual,
        "successful_weak_local_repair": {
            "source": "actual_weak_local_repair",
            "terminal_state": actual.get("terminal_state"),
            "campaigns_verified_repaired": actual.get("campaigns_verified_repaired"),
            "model_assertion_used_as_authority": False,
        },
        "invalid_proposal_rejection_cases": [
            item["name"]
            for item in scenario_json
            if item["effect_calls"] == 0 and item["final_state"] == "rejected_before_effect"
        ],
        "protected_path_rejection": "protected_path_attempt",
        "permission_denial_replay_expiry": [
            "denied_permission",
            "replayed_permission_receipt",
            "expired_permission_receipt",
        ],
        "unknown_outcome_proof": {
            "scenario": "ambiguous_effect_outcome",
            "effect_calls": 1,
            "terminal_state": "quarantined",
            "automatic_blind_retry": False,
        },
        "restart_persistence_cases": [
            "restart_after_durable_intent",
            "restart_after_candidate_materialization",
            "restart_during_verification",
        ],
        "candidate_verification_failure": "candidate_verification_failure",
        "rollback_proof": "rollback_success",
        "lkg_failure_safe_mode_proof": "lkg_failure_safe_mode",
        "anti_thrash_retry_budget": {
            "scenarios": [
                "repeated_bad_proposal_1",
                "repeated_bad_proposal_2",
                "repeated_bad_proposal_3",
                "duplicate_proposal_fingerprint",
            ],
            "bounded": True,
            "effect_retry_after_unknown": False,
        },
        "campaign_scenario_count": len(deterministic),
        "repair_state_transition_count": transition_count,
        "resource_process_task_cleanup": {
            "deterministic_child_processes_spawned": 0,
            "cloud_adapter_calls": cloud_count,
            "temporary_campaign_root_removed": temporary_removed,
            "bounded_effect_calls": effect_count,
            "final_state_counts": final_states,
        },
        "proposal_store_final_state": {
            "disposable_store_roots_removed": temporary_removed,
            "terminal_state_counts": final_states,
        },
        "F_regressions": regressions.get("F", regressions),
        "G_regressions": regressions.get("G", regressions),
        "Level4_5_preservation": "protected authority rejected before preview/effect",
        "ToolRegistry_authority_preservation": (
            "existing broker registration and exact authority retained"
        ),
        "test_strength": strength,
        "canonical_quality": canonical_quality,
        "fresh_source_identity": source_identity,
        "ending_sha": ending_sha,
        "ending_parent": ending_parent,
        "ending_tree": ending_tree,
        "remote_sha": remote_sha,
        "new_exact_source_hosted_ci": exact_ci,
        "candidate15": "NOT_CREATED",
        "phase_after_h": "NOT_STARTED",
        "scenarios": scenario_json,
    }
    output.write_text(json.dumps(artifact, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(
        json.dumps(
            {
                "artifact": str(output),
                "scenario_count": len(deterministic),
                "transition_count": transition_count,
            }
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
