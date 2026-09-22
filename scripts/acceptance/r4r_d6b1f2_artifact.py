"""Write the identity-correct D6B1F2 qualification artifact."""

from __future__ import annotations

import json
import subprocess
from datetime import UTC, datetime
from pathlib import Path

from jarvis.acceptance.evidence import source_binding_fingerprint, utc_artifact_timestamp

ROOT = Path(__file__).resolve().parents[2]
SOURCE_PATHS = (
    "jarvis/acceptance/evidence.py",
    "jarvis/production_capability.py",
    "jarvis/runtime.py",
    "jarvis/sandbox.py",
    "jarvis/sandbox_proxies.py",
    "jarvis/sandbox_worker.py",
    "jarvis/package_certification.py",
    "tests/test_d6b1f_brokered_unknown_capability.py",
    "tests/test_sandbox_worker.py",
    "tests/test_acceptance_evidence.py",
    "scripts/acceptance/r4r_d6b1d_artifact.py",
    "scripts/acceptance/run_acceptance.py",
)


def _git(*args: str) -> str:
    return subprocess.run(
        ("git", *args), cwd=ROOT, capture_output=True, text=True, check=True
    ).stdout.strip()


def main() -> int:
    captured = datetime.now(UTC)
    stamp = utc_artifact_timestamp(captured)
    artifact = {
        "schema": "r4r-d6b1f2-direct-base-broker-qualification-1",
        "run_id": "R4R-D6B1F2",
        "terminal_family": "R4R_SANDBOX_REPAIR",
        "timestamp_utc": captured.isoformat().replace("+00:00", "Z"),
        "source": {
            "branch": _git("branch", "--show-current"),
            "head": _git("rev-parse", "HEAD"),
            "parent": _git("rev-parse", "HEAD^"),
            "version": "1.0.0",
            "candidate_15": "NOT_CREATED",
            "starting_fingerprint": (
                "f453ad5e28f5cdb4720ee015400a6ae5b0bd31c6846f31a49696f4a0691fc9f8"
            ),
            "final_fingerprint": source_binding_fingerprint(ROOT, SOURCE_PATHS),
            "paths": list(SOURCE_PATHS),
        },
        "direct_base": {
            "interpreter": r"C:\Users\jamie\AppData\Local\Programs\Python\Python312\python.exe",
            "sys_executable": r"C:\Users\jamie\AppData\Local\Programs\Python\Python312\python.exe",
            "sys_base_executable": (
                r"C:\Users\jamie\AppData\Local\Programs\Python\Python312\python.exe"
            ),
            "venv_redirector_involved": "NO",
            "outer_job": "current agent Windows Job; direct-base native control topology",
            "b1f_test": (
                "1 passed, 1 skipped; skip was SandboxIsolationUnavailable and is not "
                "qualification evidence"
            ),
        },
        "production_traversal": {
            "application_runtime": "REACHED",
            "runner": "REACHED",
            "appcontainer": "REACHED; status reported isolated=True",
            "worker": "REACHED; protocol and health passed",
            "parent_bridge": "REACHED",
            "host_proxy": "REACHED",
            "permission_broker": "REACHED; safe operation policy path",
            "registry": "trusted composition handler map",
            "target": "NOT_REACHED; certification cleanup failed first",
            "semantic_oracle": "CERTIFICATION FUNCTIONAL ORACLE PASSED BEFORE SHADOW FAILURE",
            "certifier": "CERTIFICATION RECORD CREATED, ACTIVATION FAILED CLOSED",
        },
        "capabilities": {
            "one": {
                "identity": "fresh runtime-generated; not promoted because native cleanup failed",
                "production_source_occurrence": "NONE",
                "target_invocation_count": 0,
                "permission": "NOT_PROVEN_END_TO_END",
                "semantic_oracle": "PASS for certification functional case",
                "certification": "FAIL_CLOSED_AT_SHADOW_CLEANUP",
            },
            "two": {
                "identity": "NOT_REACHED",
                "production_code_modified_after_one": "NO",
                "production_source_occurrence": "NONE",
                "target_invocation": "NOT_REACHED",
                "semantic_oracle": "NOT_REACHED",
                "certification": "NOT_REACHED",
            },
        },
        "anti_catalog": {
            "new_identity_needs_core_edit": "NO",
            "generated_trusted_registration": "NO",
            "per_capability_worker_branch": "NO",
            "per_capability_runtime_branch": "NO",
        },
        "authority_controls": {
            "allow": "NOT_PROVEN_END_TO_END",
            "deny": "PRESERVED_FAIL_CLOSED_REGRESSION",
            "deny_target_calls": 0,
            "undeclared": "PASS_PARENT_REJECTS",
            "unknown_target": "PASS_BROKER_OPERATION_UNAVAILABLE",
            "missing_bridge": "PASS_FAIL_CLOSED_REGRESSION",
            "scope_escalation": "NOT_APPLICABLE_SAFE_OPERATION",
            "argument_mutation": "PRESERVED_EXISTING_EXACT_FINGERPRINT_REGRESSION",
        },
        "binding": {
            "package": "CERTIFICATION_RECORD_PACKAGE_BOUND",
            "hash": "CERTIFICATION_RECORD_HASH_BOUND",
            "manifest": "CERTIFICATION_RECORD_MANIFEST_HASH_BOUND",
            "action": "FUNCTIONAL_CASE_ACTION_BOUND",
            "worker": "jarvis-sandbox-worker-v1 compatibility bound",
            "broker_operation": "NOT_REACHED_FOR_TARGET_INVOCATION",
            "semantic_oracle": "INDEPENDENT_ORACLE_EVALUATED_CERTIFICATION_CASE",
            "cross_package_reuse": "NOT_REACHED; package equality checks preserved",
        },
        "lying_health": {
            "health": "HEALTHY",
            "functional": "FAIL_CONTROL_PRESERVED",
            "certification": "FAIL_CONTROL_PRESERVED",
        },
        "legacy": {
            "execution": "DENIED",
            "quarantine": "PRESERVED",
            "recertification": "REQUIRED",
        },
        "native": {
            "appcontainer": "isolated=True reported",
            "job": "assigned; active_process_count=2 during cleanup",
            "process_count": 2,
            "process_cleanup": "FAIL_CLOSED; process remained alive in diagnostic snapshot",
            "profile": "cleanup terminal reported",
            "temporary_sid": "NOT_PROVEN_CLEAN",
            "acl": "NOT_PROVEN_CLEAN",
            "leases": "NOT_PROVEN_CLEAN",
            "residue": "BLOCKING_UNKNOWN",
            "known_signature": (
                "SandboxIsolationUnavailable / CURRENT_AGENT_WINDOWS_JOB_CONTAINMENT"
            ),
        },
        "static": {
            "ruff_format": "PASS",
            "ruff": "PASS",
            "mypy": "PASS",
            "previous_b1f_ruff_blocker_resolved": "YES",
            "previous_b1f_mypy_blocker_resolved": "YES",
        },
        "native_regression_evidence": {
            "direct_base_sandbox": "24/24 PASS; REUSED_VALID",
            "ordinary_host": "18 PASS / 6 exact known failures; REUSED_VALID",
            "known_six": "CURRENT_AGENT_WINDOWS_JOB_CONTAINMENT",
            "additional": (
                "D6B1F2 production cleanup failure is blocking and not counted as a "
                "qualification pass"
            ),
        },
        "vision_alignment": {
            "fresh_capability_without_core_edit": "YES",
            "generated_authority_absent": "YES",
            "permission_broker_authoritative": "YES",
            "discover_adopt_reuse_build": "YES",
            "final_v1_challenge_pending": "YES",
            "overall": "FAIL; native end-to-end qualification incomplete",
        },
        "b2_eligibility": "NOT_ELIGIBLE",
        "blockers": [
            "DIRECT_BASE_END_TO_END_BROKER_QUALIFICATION_NOT_COMPLETE",
            "NATIVE_CLEANUP_ACTIVE_PROCESS_COUNT_2",
        ],
        "secrets": "NONE",
    }
    path = ROOT / "artifacts" / "acceptance" / f"r4r-d6b1f2-{stamp}.json"
    path.write_text(json.dumps(artifact, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(json.dumps({"artifact": str(path), "run_id": artifact["run_id"]}))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
