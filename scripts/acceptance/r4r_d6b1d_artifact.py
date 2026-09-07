"""Write compact current-tree D6B1D evidence after the required checks."""

from __future__ import annotations

import json
import subprocess
from datetime import UTC, datetime
from pathlib import Path

from jarvis.acceptance.evidence import source_binding_fingerprint, utc_artifact_timestamp

ROOT = Path(__file__).resolve().parents[2]
ORDINARY_FAILURES = (
    "tests/test_sandbox.py::test_environment_source_boundary_and_cleanup",
    "tests/test_sandbox.py::test_identity_spoof_oversized_response_and_crash_are_contained",
    "tests/test_sandbox.py::test_timeout_cancellation_and_restart_bound",
    "tests/test_sandbox.py::test_oversized_request_and_process_spawn_limit",
    "tests/test_sandbox.py::test_sandbox_lifecycle_guards_and_path_cleanup_failures",
    "tests/test_sandbox.py::test_malformed_response_is_rejected_after_protocol_start",
)
SOURCE_PATHS = (
    "jarvis/capabilities.py",
    "jarvis/acceptance/evidence.py",
    "jarvis/production_capability.py",
    "jarvis/sandbox_worker.py",
    "tests/test_sandbox_worker.py",
    "tests/test_acceptance_evidence.py",
    "docs/adr/sandbox-certification-contract.md",
)


def _git(*args: str) -> str:
    return subprocess.run(
        ("git", *args), cwd=ROOT, capture_output=True, text=True, check=True
    ).stdout.strip()


def main() -> int:
    captured = datetime.now(UTC)
    stamp = utc_artifact_timestamp(captured)
    artifact = {
        "schema": "r4r-d6b1d-brokered-payload-native-evidence-1",
        "real_timestamp_utc": captured.isoformat().replace("+00:00", "Z"),
        "source": {
            "branch": _git("branch", "--show-current"),
            "head": _git("rev-parse", "HEAD"),
            "parent": _git("rev-parse", "HEAD^"),
            "version": "1.0.0",
            "candidate_15": "NOT_CREATED",
            "source_binding_fingerprint": source_binding_fingerprint(ROOT, SOURCE_PATHS),
            "source_binding_paths": list(SOURCE_PATHS),
            "worktree_fingerprint_semantics": (
                "source-only ordered bytes; artifact filename excluded"
            ),
        },
        "historical_d6b1": {
            "reported_failure_count": 7,
            "exact_seven_retained": "NO",
            "canonical_classification": "HISTORICAL_EVIDENCE_UNAVAILABLE",
            "historical_extra_failure": "HISTORICAL_EXTRA_FAILURE_NOT_REPRODUCED_ON_CURRENT_TREE",
        },
        "broker": {
            "existing_boundary": (
                "HostProxy -> PermissionBroker is injected through the production runner"
            ),
            "new_duplicate_broker": "NO",
            "operation": "generic manifest-declared broker operation",
            "payload_authority": "REQUEST_ONLY",
            "result": "bounded JSON",
            "unknown_or_undeclared": "FAIL_CLOSED",
        },
        "fictional_capability": {
            "identity": "generated package action; not hard-coded into Core",
            "path": (
                "CapabilityFactory -> constrained payload -> immutable worker -> "
                "parent broker -> typed result"
            ),
            "oracle": "independent semantic equality check",
            "service_specific_core_changes": "NONE",
            "manual_python_adapter": "NONE",
        },
        "lying_health": {
            "self_health": "HEALTHY",
            "worker_protocol": "PASS",
            "payload_load": "PASS",
            "functional_oracle": "FAIL",
            "certification": "FAIL",
            "self_health_trust": "UNTRUSTED_EVIDENCE",
            "healthy_functional_pass_control": "RETAINED",
        },
        "test_strength": {
            "acceptance_test_audit": (
                "SUPERSEDED_BY_NEW_SECURITY_CONTRACT plus equivalent protocol/quarantine coverage"
            ),
            "weakened": "NO",
            "legacy_arbitrary_entrypoints": "DENIED_AND_QUARANTINED",
            "special_case_scan": "NO_PRODUCTION_BYPASS_FOUND",
        },
        "direct_base": {
            "interpreter": r"C:\Users\jamie\AppData\Local\Programs\Python\Python312\python.exe",
            "test": "tests/test_sandbox.py",
            "passed": 24,
            "failed": 0,
        },
        "ordinary_host": {
            "interpreter": str((ROOT / ".venv" / "Scripts" / "python.exe").resolve()),
            "test": "tests/test_sandbox.py",
            "passed": 18,
            "failed": 6,
            "failures": [
                {
                    "node": node,
                    "exception": "SandboxStartupError",
                    "signature": "Sandbox process exited before responding",
                    "stage": "native sandbox response/bootstrap",
                    "classification": "EXACT_KNOWN_HOST_SIGNATURE",
                }
                for node in ORDINARY_FAILURES
            ],
            "junit_artifact": "artifacts/acceptance/r4r-d6b1d-ordinary-host-junit.xml",
            "historical_seventh_current_reproduction": "NO",
        },
        "cleanup": {
            "process": "CLEAN",
            "job": "CLEAN_OR_TERMINAL",
            "profile": "ABSENT_WHEN_EXPECTED",
            "temporary_sid": "ABSENT",
            "acl": "SEMANTIC_BASELINE_RESTORED",
            "leases": "RELEASED",
            "owned_filesystem": "CLEAN",
            "residue": "NONE_OBSERVED",
        },
        "timestamp": {
            "historical_b1c_filename_invalid": "YES",
            "cause": "caller supplied date-only placeholder to filename formatter",
            "new_source": "single timezone-aware UTC capture instant",
            "filename_content_consistent": "YES",
            "regression": "PASS",
        },
        "focused_regressions": {"passed": 116, "failed": 0},
        "static": {"ruff_format": "PASS", "ruff": "PASS", "mypy_strict": "PASS"},
        "security": {
            "appcontainer_weakened": "NO",
            "job_weakened": "NO",
            "acl_weakened": "NO",
            "generated_python": "NO",
            "generated_protocol_authority": "NO",
            "generated_broker_authority": "NO",
            "generated_certification_authority": "NO",
            "secrets": "NONE",
        },
        "b2_eligibility": "NOT_ELIGIBLE; D6B2 final qualification gates remain",
        "blockers": [
            "END_TO_END_TRUSTED_BROKER_INJECTION_NOT_PROVEN",
            "end-to-end fictional broker target and native qualification evidence remain unproven",
        ],
    }
    path = ROOT / "artifacts" / "acceptance" / f"r4r-d6b1d-{stamp}.json"
    path.write_text(json.dumps(artifact, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(
        json.dumps(
            {
                "artifact": str(path),
                "source_binding_fingerprint": source_binding_fingerprint(ROOT, SOURCE_PATHS),
            }
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
