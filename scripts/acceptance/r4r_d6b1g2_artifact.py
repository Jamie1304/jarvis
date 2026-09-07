"""Write the stopped R4R-D6B1G2 qualification artifact."""

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
)
OBSERVABILITY_PATHS = SOURCE_PATHS + ("jarvis/windows_sandbox.py",)


def _git(*args: str) -> str:
    return subprocess.run(
        ("git", *args), cwd=ROOT, capture_output=True, text=True, check=True
    ).stdout.strip()


def _lifecycle(
    lifecycle_id: str,
    job_id: str,
    worker_pid: int,
    helper_pid: int,
    profile: str,
    created_ns: int,
    closed_ns: int,
    worker_creation: int,
    helper_creation: int,
) -> dict[str, object]:
    job = {
        "evidence_id": job_id,
        "state": "CLOSED",
        "created_monotonic_ns": created_ns,
        "closed_monotonic_ns": closed_ns,
        "configured_limits": {
            "active_process_limit": 1,
            "limit_flags": 8456,
            "process_memory_limit": 268435456,
        },
        "active_process_count_at_cleanup_begin": 2,
        "maximum_active_process_count": 2,
        "assigned_pids": [worker_pid, helper_pid],
        "empty_at_terminal": True,
        "processes": [
            {
                "pid": worker_pid,
                "parent_pid": 43124,
                "executable": r"C:\Users\jamie\AppData\Local\Programs\Python\Python312\python.exe",
                "creation_time": worker_creation,
                "alive_at_cleanup_begin": True,
                "terminal": True,
                "exit_code": 1,
            },
            {
                "pid": helper_pid,
                "parent_pid": worker_pid,
                "executable": r"C:\Windows\System32\conhost.exe",
                "creation_time": helper_creation,
                "alive_at_cleanup_begin": True,
                "terminal": True,
                "exit_code": 1,
            },
        ],
    }
    return {
        "lifecycle_id": lifecycle_id,
        "purpose": "production composition proactive capability health probe",
        "capability_id": "synthetic-capability-a6fc5a986fa5",
        "package_id": "generated.synthetic-proactive-capability-a6fc5a986fa5.415ef99d06",
        "action_id": "health",
        "start_monotonic_ns": created_ns,
        "process_creation_observed": True,
        "pid": worker_pid,
        "parent_pid": 43124,
        "executable": r"C:\Users\jamie\AppData\Local\Programs\Python\Python312\python.exe",
        "job": job,
        "appcontainer": {
            "mode": "appcontainer",
            "profile": profile,
            "executable_isolation": True,
        },
        "checkpoints": {
            "process_created": "PASS",
            "worker_protocol_ready": "PASS",
            "cleanup_begin": "PASS; active_process_count=2",
            "process_terminal": "PASS",
            "job_empty": "PASS",
            "acl_restored": "PASS",
            "profile_removed": "PASS",
            "leases_released": "PASS",
            "close_complete": "PASS",
        },
        "security_cleanup": {
            "acl_lease_count": 8,
            "acl_restored": True,
            "profile_deleted": True,
            "leases_released": True,
            "cleanup_terminal": True,
        },
        "containment_violation": {
            "type": "ONE_PROCESS_CONTAINMENT_VIOLATION",
            "applied_limit": 1,
            "simultaneous_active_count": 2,
            "unexpected_assigned_pid": helper_pid,
            "unexpected_executable": r"C:\Windows\System32\conhost.exe",
        },
    }


def main() -> int:
    captured = datetime.now(UTC)
    stamp = utc_artifact_timestamp(captured)
    source_fingerprint = source_binding_fingerprint(ROOT, SOURCE_PATHS)
    observability_fingerprint = source_binding_fingerprint(ROOT, OBSERVABILITY_PATHS)
    artifact = {
        "schema": "r4r-d6b1g2-instrumented-direct-base-production-qualification-1",
        "run_id": "R4R-D6B1G2",
        "terminal": "R4R_SANDBOX_REPAIR: STILL_BLOCKING",
        "timestamp_utc": captured.isoformat().replace("+00:00", "Z"),
        "source": {
            "branch": _git("branch", "--show-current"),
            "head": _git("rev-parse", "HEAD"),
            "parent": _git("rev-parse", "HEAD^"),
            "version": "1.0.0",
            "candidate_15": "NOT_CREATED",
            "starting_fingerprint": (
                "07579b53cb83fa3d38b7bc7665ab906be7023fb975fac1b1107ba023c755bfc9"
            ),
            "final_fingerprint": source_fingerprint,
            "observability_fingerprint_including_windows_launcher": observability_fingerprint,
            "source_paths": list(SOURCE_PATHS),
            "observability_paths": list(OBSERVABILITY_PATHS),
            "source_changed_during_qualification": True,
        },
        "historical_evidence_correction": {
            "B1F2_DIRECT_BASE_LABEL_PROVEN": "NO",
            "B1F2_CONTAINS_VENV_PATH_EVIDENCE": "YES",
            "B1F2_ACTIVE_PROCESS_COUNT_2_ROOT_CAUSE": "UNKNOWABLE_FROM_RETAINED_EVIDENCE",
            "CURRENT_DIRECT_BASE_REPRODUCTION": (
                "FAIL; current valid run found a new containment violation"
            ),
            "CURRENT_PRODUCT_BLOCKER_FROM_B1F2_OBSERVATION": "NO",
            "historical_classification": "HISTORICAL_ACTIVE_PROCESS_COUNT_2_PROVENANCE_INVALID",
            "historical_observation_reproduced": "NO; current violation is separately evidenced",
        },
        "direct_base_environment": {
            "interpreter": r"C:\Users\jamie\AppData\Local\Programs\Python\Python312\python.exe",
            "sys_executable": r"C:\Users\jamie\AppData\Local\Programs\Python\Python312\python.exe",
            "sys_base_executable": (
                r"C:\Users\jamie\AppData\Local\Programs\Python\Python312\python.exe"
            ),
            "venv_redirector": "NO",
            "outer_job": "current agent Windows Job; outer PID 43124",
        },
        "capabilities": {
            "one": {
                "identity": "synthetic-capability-a6fc5a986fa5",
                "present_in_production_source": "NO",
                "package_created": "PASS; runtime identity observed",
                "production_lifecycle": "STOPPED at first valid containment violation",
                "worker": "PASS; health protocol reached",
                "broker": "NOT_REACHED",
                "permission_broker": "NOT_REACHED",
                "target_invocations": "NOT_REACHED",
                "semantic_oracle": "NOT_REACHED",
                "certification": "NOT_REACHED",
                "shadow": "NOT_REACHED",
                "canary": "NOT_REACHED",
                "activation": "NOT_REACHED",
                "restart": "NOT_REACHED",
            },
            "two": {
                "identity": "NOT_REACHED",
                "production_source_changed_after_one": "NO",
                "present_in_production_source": "NOT_PROVEN",
                "target_invocations": "NOT_REACHED",
                "oracle": "NOT_REACHED",
                "certification": "NOT_REACHED",
            },
        },
        "sandbox_instances": [
            _lifecycle(
                "1c354188-fb98-4472-bac6-098b5e931706",
                "06eec1b3-23e1-4c9f-a4c4-d3558c15ecd2",
                10924,
                44796,
                "JARVIS-f99376d26af69af3d5f7087a822020d4",
                62371187000000,
                62380531000000,
                134330840393327445,
                134330840393413956,
            ),
            _lifecycle(
                "4e57986a-971d-439b-8fd3-54ac23dfb7a1",
                "9efa0fcc-3178-4382-8765-cd23293f9488",
                36828,
                35016,
                "JARVIS-567121c8cfebfa526e3849b93500aa7f",
                62380546000000,
                62388718000000,
                134330840478326407,
                134330840478363216,
            ),
        ],
        "process_containment": {
            "all_jobs_applied_process_limit": 1,
            "any_active_count_gt_1": "YES",
            "same_job_two_live_process_event": "YES",
            "unexpected_pids": [44796, 35016],
            "unexpected_processes": [r"C:\Windows\System32\conhost.exe"],
            "terminal_classification": "ONE_PROCESS_CONTAINMENT_VIOLATION",
        },
        "cleanup": {
            "observed_instances": (
                "PROCESS TERMINAL; JOB EMPTY/CLOSED; ACL BASELINE RESTORED; "
                "PROFILE REMOVED; LEASES RELEASED"
            ),
            "all_processes": "TERMINAL",
            "all_jobs": "EMPTY/CLOSED",
            "profiles": "CLEAN",
            "temporary_sid": "ABSENT after profile deletion",
            "acl": "BASELINE RESTORED",
            "leases": "RELEASED",
            "filesystem": "EXPECTED",
            "residue": "NONE OBSERVED",
            "qualification_status": "BLOCKED by containment before end-to-end capability proof",
        },
        "authority_controls": {
            "allow": "NOT_REACHED",
            "deny": "NOT_REACHED",
            "undeclared": "NOT_REACHED",
            "unknown": "NOT_REACHED",
            "missing_bridge": "NOT_REACHED",
            "scope_argument_binding": "NOT_REACHED",
        },
        "lying_health": {
            "self_health": "NOT_REACHED",
            "functional": "NOT_REACHED",
            "certification": "NOT_REACHED",
        },
        "legacy": {
            "execution": "NOT_REACHED",
            "quarantine": "NOT_REACHED",
            "recertification": "NOT_REACHED",
        },
        "evidence_binding": {
            "capability_one_evidence_usable_for_two": "NO; capability two was not run",
            "package": "NOT_REACHED",
            "manifest": "NOT_REACHED",
            "worker": "NOT_REACHED",
            "operation": "NOT_REACHED",
            "oracle": "NOT_REACHED",
        },
        "static": {
            "ruff_format": "PASS for changed modules before artifact writer",
            "ruff": "PASS for changed modules before artifact writer",
            "mypy": "PASS for changed modules before artifact writer",
        },
        "native_regression": {
            "direct_base_primitive": "FRESH; 24/24 PASS",
            "ordinary_host": (
                "FRESH sandbox suite observed 6 established differential failures "
                "plus one AppContainer cleanup timeout"
            ),
            "known_six": "CURRENT_AGENT_WINDOWS_JOB_CONTAINMENT",
            "additional": (
                "AppContainer cleanup timeout observed in ordinary-host run; "
                "qualification already blocked by direct-base containment violation"
            ),
        },
        "vision_alignment": {
            "minimal_adaptive_core": "PASS by current architecture",
            "generic_fresh_capability": "NOT_PROVEN",
            "generated_authority_absent": "NOT_PROVEN in this stopped run",
            "permission_broker_authoritative": "NOT_PROVEN in this stopped run",
            "one_process_containment": "FAIL",
            "self_development_not_self_authorization": "NOT_PROVEN",
            "discover_adopt_reuse_build_compatible": "NOT_PROVEN",
            "overall": "FAIL",
        },
        "b2_eligibility": "NOT_ELIGIBLE",
        "blockers": [
            "ONE_PROCESS_CONTAINMENT_VIOLATION",
            "CROSS_COMPONENT_CONTAINMENT_ARCHITECTURE_REVIEW_REQUIRED",
            "CAPABILITY_ONE_END_TO_END_NOT_COMPLETED",
            "CAPABILITY_TWO_NOT_REACHED",
        ],
        "next_operation": {
            "decision": "DO_NOT_START B2",
            "required": (
                "containment architecture review; do not raise max_processes "
                "or continue qualification"
            ),
            "recommended_next_model": "GPT-5.6 Terra / high",
        },
        "secrets": "NONE",
    }
    path = ROOT / "artifacts" / "acceptance" / f"r4r-d6b1g2-{stamp}.json"
    path.write_text(json.dumps(artifact, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(
        json.dumps(
            {"artifact": str(path), "run_id": artifact["run_id"], "terminal": artifact["terminal"]}
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
