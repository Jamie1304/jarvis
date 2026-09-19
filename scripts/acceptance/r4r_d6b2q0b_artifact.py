"""Write the bounded R4R-D6B2Q0B blocker-closure artifact."""

from __future__ import annotations

import json
import subprocess
from datetime import UTC, datetime
from pathlib import Path

from jarvis.acceptance.evidence import qualification_source_seal
from jarvis.qualification_manifest import manifest_dict, qualification_manifest

ROOT = Path(__file__).resolve().parents[2]


def git(*args: str) -> str:
    return subprocess.run(
        ["git", *args], cwd=ROOT, check=False, capture_output=True, text=True
    ).stdout.strip()


def changed_paths() -> tuple[str, ...]:
    tracked = git("diff", "--name-only").splitlines()
    untracked = git("ls-files", "--others", "--exclude-standard").splitlines()
    return tuple(sorted(set(tracked) | set(untracked)))


def inventory(paths: tuple[str, ...]) -> dict[str, list[str]]:
    result: dict[str, list[str]] = {
        "CP1_INCLUDE": [],
        "CP1_EXCLUDE": [],
        "MANUAL_DECISION": [],
    }
    for path in paths:
        lowered = path.casefold()
        if path == ".env.example":
            category = "MANUAL_DECISION"
        elif (
            lowered.startswith("artifacts/")
            or "__pycache__" in lowered
            or lowered.startswith(("build/", "dist/", ".venv/"))
            or lowered.endswith((".log", ".pyc", ".sqlite3"))
            or any(token in lowered for token in ("vm-image", "rootfs", "screenshot"))
        ):
            category = "CP1_EXCLUDE"
        else:
            category = "CP1_INCLUDE"
        result[category].append(path)
    return result


def stages() -> dict[str, dict[str, object]]:
    statuses = {
        "Q01": "PASS: identity and seal recomputed",
        "Q02": "REUSED_PASS",
        "Q03": "PASS: deterministic evidence tests",
        "Q04": "REUSED_PASS: 115 canonical IDs",
        "Q05": "REUSED_PASS",
        "Q06": "REUSED_PASS",
        "Q07": "REUSED_PASS: real VM foundation",
        "Q08": "PASS: deterministic pair budget and preconditions",
        "Q09": "PASS: controller fixtures",
        "Q10": "BLOCKED: prior ordinary/direct-base pair routes hung before terminal evidence",
        "Q11": "PASS: controller fixtures",
        "Q12": "REUSED_PASS",
        "Q13": "SUBSUMED_BY:Q18",
        "Q14": "PASS: seal mismatch and equality",
        "Q15": "REUSED_PASS: 23/23",
        "Q16": (
            "BLOCKED: last canonical quality terminal was 1735 passed, 7 skipped, "
            "1 deselected, coverage 88%"
        ),
        "Q17": "SUBSUMED_BY:Q16: static checks passed",
        "Q18": "PASS: tests/test_sandbox.py 24/24",
        "Q19": "REUSED_PASS: native shim 15/15",
        "Q20": "BLOCKED: coverage 88% below unchanged 90% threshold",
        "Q21": "PASS: package smoke",
        "Q22": "REUSED_PASS: 43/43",
        "Q23": "REUSED_PASS: 28/28",
        "Q24": "REUSED_PASS: 206/206",
        "Q25": "REUSED_PASS: 25/25",
        "Q26": "PASS: V1 expectation audit NO_WEAKENING",
        "Q27": "REUSED_PASS: 83/83",
        "Q28": "PASS: all discovered paths categorized",
        "Q29": "PASS: foundation vision audit",
        "Q30": "REUSED_PASS: git audit terminal",
    }
    manifest = {stage.stage_id: stage for stage in qualification_manifest()}
    return {
        stage_id: {
            "runner": manifest[stage_id].runner,
            "execution_result": status,
            "terminal": True,
            "formal_ready": status.startswith(("PASS", "REUSED_PASS", "SUBSUMED_BY")),
        }
        for stage_id, status in statuses.items()
    }


def main() -> int:
    paths = changed_paths()
    seal, bound_files = qualification_source_seal(ROOT)
    timestamp = datetime.now(UTC).strftime("%Y%m%dT%H%M%SZ")
    target = ROOT / "artifacts" / "acceptance" / f"r4r-d6b2q0b-{timestamp}.json"
    artifact = {
        "schema": "r4r-d6b2q0b-qualification-blocker-closure-1",
        "run_id": "R4R-D6B2Q0B",
        "source": {
            "branch": git("branch", "--show-current"),
            "head": git("rev-parse", "HEAD"),
            "parent": git("rev-parse", "HEAD^"),
            "version": "1.0.0",
            "candidate_15": "NOT_CREATED",
            "starting_seal": {
                "sha256": "22c4b7c7ffd76d5e4ae27b5f71459e76f46c2ef92c7a2c640e01dee557661220",
                "bound_file_count": 356,
            },
            "final_seal": {"sha256": seal, "bound_file_count": len(bound_files)},
            "bound_files": list(bound_files),
        },
        "q0a_diff_semantic_audit": {
            "jarvis/acceptance/campaign.py": "QUALIFICATION_ONLY",
            "jarvis/acceptance/coordinator.py": "QUALIFICATION_ONLY",
            "jarvis/acceptance/evidence.py": (
                "QUALIFICATION_ONLY; terminal failure propagation strengthened"
            ),
            "jarvis/qualification_manifest.py": "QUALIFICATION_ONLY",
            "pyproject.toml": (
                "TEST_NEUTRAL: real marker and optional piper typing; policy unchanged"
            ),
            "scripts/quality.py": (
                "QUALIFICATION_ONLY: excludes only explicit real_qualification marker"
            ),
            "scripts/acceptance/run_diagnostic_lifecycle.py": (
                "QUALIFICATION_ONLY: bounded executor and diagnostic projection"
            ),
            "tests/test_acceptance_evidence.py": "TEST_STRENGTHENING",
            "tests/test_qualification_campaign.py": "TEST_STRENGTHENING",
            "tests/test_qualification_coordinator.py": "QUALIFICATION_ONLY",
            "tests/test_qualification_manifest.py": (
                "TEST_STRENGTHENING: marker-to-manifest topology binding"
            ),
            "tests/test_v1_acceptance.py": "LEGITIMATE_PRODUCT_CONTRACT_UPDATE",
            "unclassified": "NO_WEAKENING_OR_UNKNOWN_CHANGE_FOUND_IN_THE_AUDITED_SET",
        },
        "v1_acceptance_expectation_audit": {
            "terminal": "V1_ACCEPTANCE_EXPECTATION_AUDIT: NO_WEAKENING",
            "old": {
                "payload": "complete Python entrypoint source",
                "preparation": "FAILED / OpportunityPreparationState.FAILED",
                "decision": "prepare",
                "decline": "raises CapabilityOpportunityError",
            },
            "new": {
                "payload": "constrained declarative code/payload.json",
                "preparation": "READY_TO_PROPOSE / READY",
                "decision": "propose",
                "decline": "allowed while inactive",
            },
            "reason": (
                "production generated capability contract moved from rejected complete Python "
                "to constrained data-only payload with trusted semantic boundaries"
            ),
            "production_behavior": (
                "certification remains inactive; trusted activation, broker authority, "
                "verification, persistence, and cleanup are still asserted"
            ),
            "classification": "LEGITIMATE_PRODUCT_CONTRACT_UPDATE",
            "strength": (
                "NO_WEAKENING: legacy source rejection remains covered in "
                "tests/test_production_capability.py"
            ),
        },
        "single_lifecycle": {
            "pre_repair_q0a": "OpportunityStatus.FAILED during preparation; root cause not proven",
            "post_repair_executor": {
                "interpreter": (
                    "C:\\Users\\jamie\\AppData\\Local\\Programs\\Python\\Python312\\python.exe"
                ),
                "result": "FAIL",
                "returncode": 1,
                "timeout_seconds": 600,
                "stdout_sha256": "789da7d4544cf5442565b83ea08ecc8c1ad3f5f936de49522f9129c769eaa827",
                "stderr_sha256": "f88cb0251f0a1f283acdf009c98d4d67581f72f3db22180ec028e038e0c4b84",
            },
            "preparation_trace": {
                "status": "READY_TO_PROPOSE",
                "preparation_state": "READY",
                "decision": "PROPOSE",
                "acquisition_stage": "CERTIFYING",
                "provider_id": "synthetic-local",
                "configured_response_count": 1,
                "request_count": 1,
                "persisted_state": "READY_TO_PROPOSE/READY",
            },
            "later_result": (
                "goal supervisor did not reach COMPLETED after a separate acquisition reached "
                "ACTIVE; exact typed goal detail was not retained by the bounded parent artifact"
            ),
            "classification": "G_OTHER_UNRESOLVED_LIFECYCLE_FAILURE",
            "repair": "bounded diagnostic executor only; no production special-case or forced PASS",
        },
        "pair": {
            "classification": "D_PAIR_HARNESS_LIFECYCLE_DEFECT",
            "ordinary": (
                "venv launcher resolved direct-base child; no sandbox worker observed; "
                "hung before terminal"
            ),
            "direct_base": (
                "single direct-base pytest process; no sandbox worker observed; "
                "hung before terminal"
            ),
            "first_boundary": (
                "prior evidence did not prove the first authoritative non-progress boundary"
            ),
            "relation_to_single": (
                "not proven; both implicate native-sensitive lifecycle progress, but no causal "
                "equivalence is asserted"
            ),
            "post_repair_pair": "NOT_RUN: single lifecycle did not pass",
        },
        "pair_progress_and_snapshot": {
            "pre_repair_timeline": ["PAIR_RUNTIME_CREATED", "A_STARTED"],
            "observed_hang_boundary": (
                "before terminal lifecycle evidence; worker PID/Job state unavailable because "
                "no worker was observed"
            ),
            "snapshot": {
                "qualification_processes": (
                    "outer diagnostic executor plus direct-base pytest child"
                ),
                "child_processes": 0,
                "native_worker": "NOT_OBSERVED",
                "task_stack": "NOT_CAPTURED",
            },
            "no_fabricated_stages": True,
        },
        "terminal_failure_propagation": {
            "repair": (
                "QualificationTerminalFailure plus finally-owned runtime close in "
                "run_same_runtime_pair"
            ),
            "regression": (
                "tests/test_acceptance_evidence.py::"
                "test_pair_terminal_failure_is_typed_and_closes_runtime"
            ),
            "result": "PASS",
        },
        "provider_fixture_audit": {
            "single": (
                "one runtime-scoped FakeAIProvider instance; one configured response; "
                "one preparation request observed"
            ),
            "pair": (
                "runtime-scoped queued provider owns two intended responses; exhaustion raises; "
                "no global mutable queue"
            ),
            "stale_waiter": "not observed; real pair not rerun",
            "fresh_state": (
                "controller/fixture regression coverage PASS; native lifecycle proof absent"
            ),
        },
        "coverage": {
            "before_percent": 88,
            "after_percent": "NOT_RERUN",
            "threshold_percent": 90,
            "policy_changed": False,
            "status": "BLOCKED_BELOW_THRESHOLD",
        },
        "canonical_quality": {
            "last_terminal": "FAIL: 1735 passed, 7 skipped, 1 deselected; coverage 88% below 90%",
            "static_after_closure": "PASS: Ruff format, Ruff check, strict mypy 332 files",
            "full_rerun": "NOT_RERUN: targeted improvements did not establish >=90%",
        },
        "test_topology": {
            "real_marker": "real_qualification",
            "mapped_stage": "Q10",
            "deterministic_exclusion": "only the explicit real pair",
            "topology_test": "PASS",
        },
        "test_strength_audit": {
            "security_weakening": "NO",
            "coverage_weakening": "NO",
            "assertion_weakening": "NO",
            "hidden_skip": "NO",
            "fake_pass": "NO",
            "production_qualification_special_case": "NO",
        },
        "manifest_readiness": {
            "machine_manifest_stages": 30,
            "formal_ready_or_subsumed": False,
            "blocked": ["Q10", "Q16", "Q20"],
            "reason": "unresolved pair proof and unchanged coverage gate",
            "manifest": manifest_dict(),
        },
        "coordinator_simulation": {
            "result": "PASS",
            "tests": (
                "26 focused closure tests passed; coordinator success/failure-at-each-stage "
                "included"
            ),
            "formal_real_campaign": "NOT_RUN",
        },
        "formal_counts": {"formal_3_of_3": 0, "formal_pair": 0, "formal_final_ten": 0},
        "cp1_inventory": inventory(paths),
        "remaining_blockers": [
            "Q10 first authoritative pair non-progress boundary remains unproven",
            (
                "single lifecycle did not reach completed qualification pass after later "
                "ACTIVE acquisition"
            ),
            "coverage remains 88%, below unchanged 90% threshold",
        ],
        "terminal": "R4R_QUALIFICATION_SHAKEDOWN: STILL_BLOCKING",
    }
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(json.dumps(artifact, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(target)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
