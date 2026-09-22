"""Write the focused R4R-D6B2Q0A closure artifact."""

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


def paths() -> tuple[str, ...]:
    tracked = git("diff", "--name-only").splitlines()
    untracked = git("ls-files", "--others", "--exclude-standard").splitlines()
    return tuple(sorted(set(tracked) | set(untracked)))


def inventory(all_paths: tuple[str, ...]) -> dict[str, list[str]]:
    categories = {"CP1_INCLUDE": [], "CP1_EXCLUDE": [], "MANUAL_DECISION": []}
    for path in all_paths:
        lowered = path.casefold()
        if path == ".env.example":
            category = "MANUAL_DECISION"
        elif (
            lowered.startswith("artifacts/")
            or "__pycache__" in lowered
            or lowered.startswith(("build/", "dist/", ".venv/"))
            or lowered.endswith((".log", ".pyc", ".sqlite3"))
            or any(
                token in lowered
                for token in ("vm-image", "rootfs", "runtime-receipt", "screenshot")
            )
        ):
            category = "CP1_EXCLUDE"
        else:
            category = "CP1_INCLUDE"
        categories[category].append(path)
    return categories


def test_strength(all_paths: tuple[str, ...]) -> dict[str, object]:
    qualification_tests = [
        path
        for path in all_paths
        if path.startswith("tests/") or path.startswith("scripts/acceptance/")
    ]
    return {
        "qualification_test_paths": qualification_tests,
        "tests/test_windows_sandbox_native.py": (
            "TEST_STRENGTHENING: added authoritative cleanup join and "
            "unknown-until-terminal assertions"
        ),
        "tests/test_sandbox.py": (
            "TEST_STRENGTHENING: pythonw topology plus explicit child denial "
            "and Job accounting assertions"
        ),
        "tests/test_v1_acceptance.py": (
            "CHANGED_EXPECTATION_REQUIRES_REVIEW: failed preparation expectation "
            "changed to proposal-ready; isolated fresh lifecycle later failed at that assertion"
        ),
        "new_skip_scan": "NO_ADDED_PYTEST_SKIP_FOUND_IN_TRACKED_TEST_DIFF",
        "removed_assertion_scan": (
            "NO_REMOVED_ASSERTION_PROVEN; changed expectation remains unresolved"
        ),
        "result": "REVIEW_REQUIRED",
    }


def stage_results() -> dict[str, dict[str, object]]:
    results = {
        "Q01": "PASS: source identity and final seal recomputed",
        "Q02": "REUSED_PASS: unchanged recovery evidence",
        "Q03": "PASS: focused evidence tests; real pair separately mapped",
        "Q04": "REUSED_PASS: 115 canonical IDs",
        "Q05": "REUSED_PASS",
        "Q06": "REUSED_PASS",
        "Q07": "REUSED_PASS: real VM 2/2",
        "Q08": "PASS: deterministic pair-budget/precondition tests",
        "Q09": "PASS: generic controller fixture tests; fresh lifecycle driver terminal FAIL",
        "Q10": (
            "BLOCKED: ordinary and direct-base pair diagnostics both hung before terminal evidence"
        ),
        "Q11": "PASS: generic ten-record controller fixture semantics",
        "Q12": "REUSED_PASS",
        "Q13": "SUBSUMED_BY:Q18",
        "Q14": "PASS: changed seal mismatch and unchanged equality",
        "Q15": "REUSED_PASS: 23/23",
        "Q16": "BLOCKED: 1735 passed, 7 skipped, 1 deselected; coverage 88% below 90%",
        "Q17": "SUBSUMED_BY:Q16: format, ruff, strict mypy passed",
        "Q18": "PASS: tests/test_sandbox.py collected 24, passed 24",
        "Q19": "REUSED_PASS: native shim differential 15/15",
        "Q20": "BLOCKED: Q16 coverage report 88%, policy is 90%",
        "Q21": "PASS: wheel and sdist package smoke",
        "Q22": "REUSED_PASS: 43/43",
        "Q23": "REUSED_PASS: 28/28",
        "Q24": "REUSED_PASS: 206/206",
        "Q25": "REUSED_PASS: 25/25",
        "Q26": "BLOCKED: expected-outcome change requires audit; isolated fresh lifecycle failed",
        "Q27": "REUSED_PASS: 83/83",
        "Q28": "PASS: all discovered paths categorized",
        "Q29": "PASS: symbol-to-regression foundation audit; post-CP1 expansion excluded",
        "Q30": "REUSED_PASS: git audit commands terminal",
    }
    manifest = {item.stage_id: item for item in qualification_manifest()}
    return {
        stage: {
            "runner": manifest[stage].runner,
            "execution_result": result,
            "terminal": True,
            "formal_ready": result.startswith(("PASS", "REUSED_PASS", "SUBSUMED_BY")),
        }
        for stage, result in results.items()
    }


def main() -> int:
    all_paths = paths()
    seal, bound_files = qualification_source_seal(ROOT)
    timestamp = datetime.now(UTC).strftime("%Y%m%dT%H%M%SZ")
    target = ROOT / "artifacts" / "acceptance" / f"r4r-d6b2q0a-{timestamp}.json"
    artifact = {
        "schema": "r4r-d6b2q0a-qualification-orchestrator-closure-1",
        "run_id": "R4R-D6B2Q0A",
        "source": {
            "branch": git("branch", "--show-current"),
            "head": git("rev-parse", "HEAD"),
            "parent": git("rev-parse", "HEAD^"),
            "version": "1.0.0",
            "candidate_15": "NOT_CREATED",
            "starting_seal": {
                "sha256": "434f409f62b499fcb2012a6ca37ef882c2806a4872b22556c42976ffe49d27ef",
                "bound_file_count": 349,
            },
            "final_seal": {"sha256": seal, "bound_file_count": len(bound_files)},
            "bound_files": list(bound_files),
        },
        "pair_interpreter_differential": {
            "ordinary": {
                "launcher": ".venv\\Scripts\\python.exe",
                "resolved_child": (
                    "C:\\Users\\jamie\\AppData\\Local\\Programs\\Python\\Python312\\python.exe"
                ),
                "process_shape": (
                    "outer venv launcher plus direct-base pytest child; no sandbox worker observed"
                ),
                "result": "HUNG_BEFORE_TERMINAL",
            },
            "direct_base": {
                "launcher": (
                    "C:\\Users\\jamie\\AppData\\Local\\Programs\\Python\\Python312\\python.exe"
                ),
                "process_shape": ("single direct-base pytest process; no sandbox worker observed"),
                "result": "HUNG_BEFORE_TERMINAL",
            },
            "classification": "D_PAIR_HARNESS_LIFECYCLE_DEFECT",
            "root_cause_status": (
                "FIRST_AUTHORITATIVE_BOUNDARY_NOT_PROVEN; finite progress instrumentation added"
            ),
        },
        "q08_q10_consolidation": {
            "Q08": "deterministic pair-budget/precondition regression only",
            "Q10": "one explicit real same-ApplicationRuntime pair",
            "duplicate_real_execution": False,
        },
        "campaign_controller": {
            "implementation": ("jarvis/acceptance/campaign.py::ConsecutiveQualificationCampaign"),
            "tests": "tests/test_qualification_campaign.py",
            "three_of_three": "PASS fixture semantics",
            "final_ten": "PASS fixture semantics",
            "replacement_and_duplicate_rejection": "PASS",
            "coordinator": ("jarvis/acceptance/coordinator.py::FormalQualificationCoordinator"),
            "simulation": ("PASS: all-stage success and failure-at-each-stage stop tests"),
        },
        "real_qualification_topology": {
            "marker": "real_qualification",
            "canonical_quality": "excludes only marked real pair",
            "formal_route": "explicit Q10 runner",
            "machine_mapping_test": "tests/test_qualification_manifest.py",
        },
        "q16_q17_q20": {
            "Q16": "execution stage",
            "Q17": "validation stage consuming Q16 static output",
            "Q20": "validation stage consuming Q16 coverage output",
            "pytest": {"passed": 1735, "skipped": 7, "deselected": 1},
            "coverage_percent": 88,
            "threshold_percent": 90,
        },
        "native_suite_identity": {
            "canonical": "tests/test_sandbox.py",
            "collected": 24,
            "passed": 24,
            "shim_differential": ("tests/test_windows_sandbox_native.py, 15 collected/passed"),
            "Q13": (
                "subsumed by tests/test_sandbox.py::"
                "test_appcontainer_boundary_is_explicit_and_observable"
            ),
        },
        "fresh_diagnostic_lifecycle": {
            "runner": "scripts/acceptance/run_diagnostic_lifecycle.py",
            "interpreter": (
                "C:\\Users\\jamie\\AppData\\Local\\Programs\\Python\\Python312\\python.exe"
            ),
            "result": "FAIL",
            "failure": (
                "OpportunityStatus.FAILED at preparation; expected proposal-ready "
                "state was not reached"
            ),
            "formal_count": 0,
        },
        "q13": "SUBSUMED_BY_Q18_PASS",
        "q14": "PASS",
        "package_smoke": "PASS wheel + sdist round-trip and RECORD tamper matrix",
        "test_strength_audit": test_strength(all_paths),
        "cp1_inventory": inventory(all_paths),
        "foundation_vision_audit": (
            "PASS: scripts/acceptance/audit_foundation_vision.py; "
            "POST_CP1_REBASELINE_REQUIRED excluded"
        ),
        "qualification_manifest": manifest_dict(),
        "stages": stage_results(),
        "formal_coordinator_simulation": (
            "PASS fixture success plus failure injection at every Q-stage"
        ),
        "formal_counts": {
            "formal_3_of_3": 0,
            "formal_pair": 0,
            "formal_final_ten": 0,
        },
        "blockers": [
            (
                "pair first authoritative non-progress boundary remains unproven; "
                "both interpreter routes hung"
            ),
            "coverage is 88%, below unchanged 90% policy",
            ("fresh direct-base lifecycle failed at expected proposal-ready preparation state"),
            ("test-strength audit remains open on tests/test_v1_acceptance.py changed expectation"),
        ],
        "terminal": "R4R_QUALIFICATION_SHAKEDOWN: STILL_BLOCKING",
    }
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(json.dumps(artifact, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(target)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
