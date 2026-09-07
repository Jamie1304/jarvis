"""Record the stopped R4R-D6B2R qualification without fabricating passes."""

from __future__ import annotations

import hashlib
import subprocess
import sys
from datetime import UTC, datetime
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from jarvis.acceptance.evidence import (
    qualification_source_manifest,
    utc_artifact_timestamp,
    write_json,
)

ROOT = Path(__file__).resolve().parents[2]
SEAL = "9d85299a822d500b9cc01a491bd0fbed437d63efe17ee1e6f7ea2d57242b56b7"


def _git(*args: str) -> str:
    return subprocess.run(
        ("git", *args), cwd=ROOT, check=True, capture_output=True, text=True
    ).stdout.strip()


def main() -> int:
    timestamp = utc_artifact_timestamp()
    manifest = tuple(
        path
        for path in qualification_source_manifest(ROOT)
        if path != "scripts/acceptance/r4r_d6b2r_artifact.py"
    )
    digest = hashlib.sha256()
    for relative in manifest:
        encoded_path = relative.encode("utf-8")
        content = (ROOT / relative).read_bytes()
        digest.update(len(encoded_path).to_bytes(8, "big"))
        digest.update(encoded_path)
        digest.update(len(content).to_bytes(8, "big"))
        digest.update(content)
    if digest.hexdigest() != SEAL:
        raise RuntimeError(
            f"qualification seal changed while recording blocker: {digest.hexdigest()}"
        )
    artifact = {
        "schema": "r4r-d6b2r-qualification-closure-1",
        "run_id": "R4R-D6B2R",
        "real_utc": datetime.now(UTC).isoformat(),
        "source_identity": {
            "branch": _git("branch", "--show-current"),
            "head": _git("rev-parse", "HEAD"),
            "parent": _git("rev-parse", "HEAD^"),
            "version": "1.0.0",
            "candidate_15": "NOT_CREATED",
        },
        "qualification_seal": {
            "sha256": SEAL,
            "bound_file_count": len(manifest),
            "manifest": list(manifest),
        },
        "historical_b2": {
            "failure_mechanism": "UNRECOVERABLE_FROM_RETAINED_EVIDENCE",
            "failed_run_cleanup": "UNRECOVERABLE_FROM_RETAINED_EVIDENCE",
            "current_exact_replay": "PASS",
            "evidence_capture_defect": "REPAIRED_BEFORE_THIS_RUN",
            "old_failure_current_blocker": "NO",
        },
        "b2a_diagnostic_repair_verification": "PASS",
        "failure_cleanup_self_test": "PASS",
        "first_current_blocker": {
            "gate": "UNIT_TESTS",
            "typed_code": "CERTIFICATION_FAILURE followed by TRACE_EVIDENCE_MALFORMED",
            "safe_detail": (
                "certification execution rejected:SandboxCleanupError; "
                "TraceEvent rejected the failed-run evidence during acquisition recording"
            ),
            "capability_id": "synthetic-capability-84a623478a42",
            "action_id": "transform-84a623478a42",
            "package_hash": "NOT_RETAINED_DUE_TO_TERMINAL_TRACE_RECORDING_ERROR",
            "cleanup": "SandboxCleanupError; complete terminal cleanup evidence not retained",
            "registry_authority": "NOT_ESTABLISHED",
            "certification_state": "FAILED",
            "activation_state": "NOT_ESTABLISHED",
        },
        "deterministic_matrix": {
            "passed": 48,
            "failed": 0,
            "result": "PASS",
            "known_host_only": "NOT_RUN",
        },
        "d5_class_sequential_regression": "NOT_EXECUTED",
        "special_case_scan": "NOT_EXECUTED",
        "workbench": "NOT_EXECUTED_IN_B2R",
        "disposable": "NOT_EXECUTED_IN_B2R",
        "host_bridge_separation": "NOT_EXECUTED_IN_B2R",
        "sequential_3": "NOT_EXECUTED",
        "pair_qualification": "NOT_EXECUTED",
        "final_ten": {"seal_start": None, "entries": [], "consecutive": "NOT_STARTED"},
        "acceptance_lab": {
            "count": 115,
            "unique": "YES",
            "integrity": "PASS",
            "self_tests": "PASS",
            "future_false_pass": "NO",
        },
        "v1_acceptance": {
            "result": "FAIL",
            "passed": 22,
            "failed": 1,
            "failure": (
                "test_v1_production_composition_acquires_randomized_capability_and_restores_it"
            ),
        },
        "full_quality": "NOT_EXECUTED",
        "static": "NOT_EXECUTED",
        "native": {"direct_base": "NOT_EXECUTED", "ordinary": "NOT_EXECUTED"},
        "coverage": "NOT_EXECUTED",
        "package_smoke": "NOT_EXECUTED",
        "persistence_idempotency": "NOT_EXECUTED",
        "security_regressions": "NOT_EXECUTED",
        "test_strength_audit": "NOT_EXECUTED",
        "contamination_audit": "NOT_EXECUTED",
        "cp1_inventory": "NOT_PREPARED",
        "env_example": {
            "classification": "PRESERVE_AND_EXCLUDE_FROM_CP1_PENDING_EXPLICIT_DECISION",
            "staged": 0,
        },
        "vision_alignment": "NOT_QUALIFIED",
        "v1_release_reality_gate": "NOT_YET_EXECUTED",
        "release_ready": "NO",
        "cp1_eligibility": "NO",
        "secrets": "NONE",
        "qualification_status": "BLOCKED_BY_CURRENT_PRODUCTION_EVIDENCE_DEFECT",
        "worktree_policy": {
            "staged": 0,
            "candidate_15": "NOT_CREATED",
            "mutations_preserved": True,
        },
    }
    path = ROOT / "artifacts" / "acceptance" / f"r4r-d6b2r-{timestamp}.json"
    write_json(path, artifact)
    print(path)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
