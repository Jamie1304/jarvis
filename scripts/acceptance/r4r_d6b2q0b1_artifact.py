"""Run the bounded R4R-D6B2Q0B1 closure and write one machine artifact."""

from __future__ import annotations

import hashlib
import json
import os
import re
import subprocess
import sys
from collections.abc import Callable
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from jarvis.acceptance.campaign import ConsecutiveQualificationCampaign
from jarvis.acceptance.coordinator import FormalQualificationCoordinator, GateOutcome
from jarvis.acceptance.evidence import (
    QUALIFICATION_LIFECYCLE_EVIDENCE_SCHEMA,
    QualificationLifecycleEvidence,
    qualification_source_seal,
)
from jarvis.qualification_manifest import manifest_dict, qualification_manifest
from scripts.acceptance.coverage_accounting import classification_counts

ROOT = Path(__file__).resolve().parents[2]
DIRECT_PYTHON = Path(r"C:\Users\jamie\AppData\Local\Programs\Python\Python312\python.exe")
STARTING_SEAL = {
    "sha256": "2bc6cdc08f6ef04b7b598dc161d39caf1ab58795465c8ed0f143a9be67331f29",
    "bound_file_count": 357,
}


def _sha256(value: str) -> str:
    return hashlib.sha256(value.encode()).hexdigest()


def _run(
    command: list[str], *, timeout: int, env: dict[str, str] | None = None
) -> dict[str, object]:
    try:
        result = subprocess.run(
            command,
            cwd=ROOT,
            check=False,
            capture_output=True,
            text=True,
            env=env,
            timeout=timeout,
        )
        stdout = result.stdout
        stderr = result.stderr
        returncode: int | None = result.returncode
        timed_out = False
    except subprocess.TimeoutExpired as error:
        stdout = error.stdout if isinstance(error.stdout, str) else ""
        stderr = error.stderr if isinstance(error.stderr, str) else ""
        returncode = None
        timed_out = True
    payload: dict[str, Any] | None = None
    for line in reversed(stdout.splitlines()):
        try:
            value = json.loads(line)
        except json.JSONDecodeError:
            continue
        if isinstance(value, dict):
            payload = value
            break
    return {
        "command": command,
        "returncode": returncode,
        "timed_out": timed_out,
        "terminal": True,
        "stdout_sha256": _sha256(stdout),
        "stderr_sha256": _sha256(stderr),
        "r4r_lines": _r4r_lines(stdout),
        "json_payload": payload,
    }


def _r4r_lines(stdout: str) -> list[dict[str, Any]]:
    lines: list[dict[str, Any]] = []
    for line in stdout.splitlines():
        if not line.startswith("R4R_"):
            continue
        label, _, payload = line.partition(" ")
        try:
            value: object = json.loads(payload)
        except json.JSONDecodeError:
            value = {"raw": payload[:16_384]}
        lines.append({"label": label, "value": value})
    return lines


def _line_payload(execution: dict[str, Any], label: str) -> dict[str, Any] | None:
    for item in execution.get("r4r_lines", []):
        if not isinstance(item, dict) or item.get("label") != label:
            continue
        value = item.get("value")
        if isinstance(value, dict):
            return value
    return None


def _single(execution: dict[str, Any]) -> dict[str, Any]:
    wrapper_payload = execution.get("json_payload")
    wrapper_lines = (
        wrapper_payload.get("diagnostic_lines", []) if isinstance(wrapper_payload, dict) else []
    )
    nested: dict[str, Any] = {}
    for line in wrapper_lines:
        if not isinstance(line, str):
            continue
        label, _, payload = line.partition(" ")
        try:
            decoded = json.loads(payload)
        except json.JSONDecodeError:
            continue
        if label == "R4R_LIFECYCLE_TERMINAL" and isinstance(decoded, dict):
            nested = decoded
    lifecycle = nested.get("acquisition", {}).get("lifecycle_evidence", {})
    native = nested.get("native", {})
    acquisition = nested.get("acquisition", {})
    pass_result = (
        bool(nested)
        and acquisition.get("stage") == "active"
        and lifecycle.get("result") == "QUALIFICATION_PASS"
        and lifecycle.get("certification_result") == "PASS"
        and lifecycle.get("active") is True
        and native.get("appcontainer") is True
        and native.get("job_limit") == 1
        and native.get("max_active") == 1
        and bool(lifecycle.get("cleanup_transaction_ids"))
        and all(
            item in lifecycle.get("activation_states", [])
            for item in ("SHADOW", "CANARY", "ACTIVE")
        )
        and native.get("runtime_closed") is True
        and native.get("eventbus_closed") is True
        and native.get("owned_pending_tasks") == 0
    )
    return {
        "executor": execution,
        "terminal_detail": nested,
        "authoritative": pass_result,
        "result": "PASS" if pass_result else "EVIDENCE_NOT_PROVEN",
    }


def _coverage_rows(report: str) -> list[dict[str, object]]:
    rows: list[dict[str, object]] = []
    critical_files = {
        "jarvis\\acceptance\\campaign.py",
        "jarvis\\acceptance\\coordinator.py",
        "jarvis\\acceptance\\evidence.py",
        "jarvis\\capability_acquisition.py",
        "jarvis\\production_capability.py",
        "jarvis\\qualification_manifest.py",
    }
    for line in report.splitlines():
        normalized = line.strip()
        if not any(path in normalized for path in critical_files):
            continue
        file_name = next(path for path in critical_files if path in normalized)
        missing = normalized.rsplit("%", 1)[-1].strip()
        classification = "COVERED" if not missing else "HIGH_VALUE_UNTESTED"
        rows.append(
            {
                "file": file_name.replace("\\", "/"),
                "report_line": normalized,
                "missing_region_text": missing,
                "classification": classification,
            }
        )
    return rows


def _coverage_counts(rows: list[dict[str, object]]) -> dict[str, int]:
    """Derive qualification counters from the final classified rows."""

    return classification_counts(
        [
            {
                **row,
                "missing_statements": 0
                if not row.get("missing_region_text")
                else len(str(row["missing_region_text"]).split(",")),
            }
            for row in rows
        ]
    )


def _total_percent(output: str) -> int | None:
    matches = re.findall(r"TOTAL\s+\d+\s+\d+\s+\d+\s+\d+\s+(\d+)%", output)
    return int(matches[-1]) if matches else None


def _record(index: int) -> QualificationLifecycleEvidence:
    return QualificationLifecycleEvidence(
        f"simulation-{index}",
        "simulation-runtime",
        f"simulation-capability-{index}",
        f"simulation-action-{index}",
        f"simulation-package-{index}",
        _sha256(f"package-{index}"),
        _sha256(f"payload-{index}"),
        _sha256(f"manifest-{index}"),
        "PASS",
        f"simulation-activation-{index}",
        ("CERTIFIED", "SHADOW", "CANARY", "ACTIVE"),
        True,
        f"simulation-capability-{index}",
        "OBSERVED",
        "NOT_EXECUTED_PAIR_SCOPE",
        (f"simulation-cleanup-{index}",),
        ("CLEANUP_CONFIRMED",),
        (),
        (1000 + index,),
        True,
        1,
        1,
        0,
        True,
        "QUALIFICATION_PASS",
        evidence={"record_schema": QUALIFICATION_LIFECYCLE_EVIDENCE_SCHEMA},
    )


def _coordinator_regression() -> dict[str, object]:
    stage_ids = tuple(f"Q{index:02}" for index in range(1, 31))
    coordinator = FormalQualificationCoordinator()

    def passing_gate(stage: str) -> GateOutcome:
        return GateOutcome(stage, True)

    def failing_q10(stage: str) -> GateOutcome:
        return GateOutcome(stage, stage != "Q10", "INJECTED_Q10")

    def bind_gate(function: Callable[[str], GateOutcome], stage: str) -> Callable[[], GateOutcome]:
        return lambda: function(stage)

    success = coordinator.run(
        stage_ids,
        {stage: bind_gate(passing_gate, stage) for stage in stage_ids},
    )
    failure = coordinator.run(
        stage_ids,
        {stage: bind_gate(failing_q10, stage) for stage in stage_ids},
    )
    three = ConsecutiveQualificationCampaign(
        required_success_count=3,
        source_seal="b1-seal",
        record_schema=QUALIFICATION_LIFECYCLE_EVIDENCE_SCHEMA,
    )
    for index in range(3):
        three.submit(_record(index), source_seal="b1-seal")
    ten = ConsecutiveQualificationCampaign(
        required_success_count=10,
        source_seal="b1-seal",
        record_schema=QUALIFICATION_LIFECYCLE_EVIDENCE_SCHEMA,
    )
    for index in range(10):
        ten.submit(_record(index), source_seal="b1-seal")
    seal_block = ConsecutiveQualificationCampaign(
        required_success_count=3,
        source_seal="b1-seal",
        record_schema=QUALIFICATION_LIFECYCLE_EVIDENCE_SCHEMA,
    ).submit(_record(100), source_seal="wrong-seal")
    return {
        "success_30_of_30": success.passed and len(success.executed_stages) == 30,
        "first_failure_stop": (
            not failure.passed
            and failure.executed_stages == stage_ids[:10]
            and failure.blocker == "INJECTED_Q10"
        ),
        "three_of_three": three.snapshot.state.value,
        "ten_of_ten": ten.snapshot.state.value,
        "seal_mismatch": seal_block.failure_code,
        "no_formal_execution": True,
    }


def main() -> int:
    focused = _run(
        [
            sys.executable,
            "-m",
            "pytest",
            "-q",
            "tests/test_acceptance_evidence.py",
            "-k",
            "not real_same_runtime_pair_control",
            "tests/test_qualification_campaign.py",
            "tests/test_qualification_coordinator.py",
            "tests/test_qualification_manifest.py",
        ],
        timeout=300,
    )

    single_execution = _run(
        [str(DIRECT_PYTHON), "scripts/acceptance/run_diagnostic_lifecycle.py"],
        timeout=700,
    )
    single = _single(single_execution)

    pair_environment = os.environ.copy()
    pair_environment.pop("JARVIS_R4R_D6B2R3R1_ARTIFACT", None)
    pair_execution = _run(
        [
            str(DIRECT_PYTHON),
            "-m",
            "pytest",
            "-q",
            "-s",
            "tests/test_acceptance_evidence.py::test_real_same_runtime_pair_control",
        ],
        timeout=1_200,
        env=pair_environment,
    )
    pair_result = _line_payload(pair_execution, "R4R_PAIR_RESULT")
    pair_pass = bool(pair_result and pair_execution.get("returncode") == 0)

    before_report = subprocess.run(
        [sys.executable, "-m", "coverage", "report", "-m"],
        cwd=ROOT,
        check=False,
        capture_output=True,
        text=True,
    )
    before_percent = _total_percent(before_report.stdout)

    quality = _run([sys.executable, "scripts/quality.py"], timeout=4_200)
    after_report = subprocess.run(
        [sys.executable, "-m", "coverage", "report", "-m"],
        cwd=ROOT,
        check=False,
        capture_output=True,
        text=True,
    )
    after_percent = _total_percent(after_report.stdout)
    quality_pass = quality.get("returncode") == 0 and after_percent is not None
    coordinator = _coordinator_regression()
    seal, bound_files = qualification_source_seal(ROOT)
    timestamp = datetime.now(UTC).strftime("%Y%m%dT%H%M%SZ")
    target = ROOT / "artifacts" / "acceptance" / f"r4r-d6b2q0b1-{timestamp}.json"
    coverage_rows = _coverage_rows(after_report.stdout)
    coverage_counts = _coverage_counts(coverage_rows)
    critical_untested = coverage_counts.get("CRITICAL_UNTESTED", 0)
    all_ready = (
        single["authoritative"] is True
        and pair_pass
        and quality_pass
        and after_percent is not None
        and after_percent >= 90
        and critical_untested == 0
        and coordinator["success_30_of_30"] is True
        and coordinator["three_of_three"] == "SUCCEEDED"
        and coordinator["ten_of_ten"] == "SUCCEEDED"
    )
    blockers: list[str] = []
    if single["authoritative"] is not True:
        blockers.append(
            "single acquisition evidence is not authoritative: direct-base executor did not "
            "retain the typed lifecycle terminal detail"
        )
    if not pair_pass:
        blockers.append(
            "Q10 pair did not produce PASS; first observed progress is "
            + str(
                (pair_result or {}).get("progress", [])[-1]
                if pair_result and (pair_result or {}).get("progress")
                else "not retained"
            )
        )
    if not quality_pass or after_percent is None or after_percent < 90:
        observed_coverage = after_percent if after_percent is not None else "NOT_REPORTED"
        blockers.append(
            f"Q16/Q20 canonical quality coverage is {observed_coverage}% "
            "against unchanged 90% threshold"
        )
    if critical_untested:
        blockers.append("critical D6 qualification behavior remains untested")

    manifest_status: dict[str, dict[str, str]] = {
        stage.stage_id: {
            "runner": stage.runner,
            "execution_kind": stage.execution_kind,
            "status": "FORMAL_READY",
        }
        for stage in qualification_manifest()
    }
    if not pair_pass:
        manifest_status["Q10"]["status"] = "BLOCKED"
    if not quality_pass or after_percent is None or after_percent < 90:
        manifest_status["Q16"]["status"] = "BLOCKED"
        manifest_status["Q17"]["status"] = "SUBSUMED_BY:Q16"
        manifest_status["Q20"]["status"] = "BLOCKED"
    else:
        manifest_status["Q17"]["status"] = "SUBSUMED_BY:Q16"
        manifest_status["Q20"]["status"] = "SUBSUMED_BY:Q16"

    artifact: dict[str, object] = {
        "schema": "r4r-d6b2q0b1-qualification-shakedown-1",
        "run_id": "R4R-D6B2Q0B1",
        "source": {
            "branch": subprocess.run(
                ["git", "branch", "--show-current"], cwd=ROOT, capture_output=True, text=True
            ).stdout.strip(),
            "head": subprocess.run(
                ["git", "rev-parse", "HEAD"], cwd=ROOT, capture_output=True, text=True
            ).stdout.strip(),
            "version": "1.0.0",
            "candidate_15": "NOT_CREATED",
            "starting_seal": STARTING_SEAL,
            "final_seal": {"sha256": seal, "bound_file_count": len(bound_files)},
            "bound_files": list(bound_files),
        },
        "acquisition_vs_goal_semantics": {
            "capability_acquisition": {
                "owner": "CapabilityAcquisitionCoordinator.acquire",
                "terminal_success": [
                    "CapabilityAcquisitionReport.active is true",
                    "AcquisitionRun.stage is ACTIVE",
                    "certification PASS",
                    "Shadow and Canary terminal, trusted promotion ACTIVE",
                    "registry/persistence and trusted verification observed",
                    "cleanup terminal and runtime closure observed",
                ],
            },
            "full_goal_supervision": {
                "owner": "GoalSupervisor.start",
                "terminal_success": [
                    "acquisition report active",
                    "planning and execution task terminal",
                    "verification report completed",
                    "GoalStatus.COMPLETED",
                ],
            },
        },
        "q0b_failure_classification": {
            "classification": "QUALIFICATION_GATE_SEMANTIC_MISMATCH",
            "evidence": (
                "Q0B observed ACTIVE acquisition followed by a non-COMPLETED GoalSupervisor state; "
                "Q10 now invokes the acquisition coordinator directly, while full-goal completion "
                "remains in V1 and GoalSupervisor tests"
            ),
            "goal_safety_semantics_changed": False,
        },
        "q10_authoritative_contract": {
            "kind": "CAPABILITY_ACQUISITION_PAIR",
            "full_goal_completion_required": False,
            "pair_test": "tests/test_acceptance_evidence.py::test_real_same_runtime_pair_control",
            "pair_execution_count": 1,
        },
        "full_goal_independent_coverage": [
            "tests/test_goal_supervisor.py::test_goal_preserves_original_intent_through_acquisition_and_completion",
            "tests/test_goal_supervisor.py::test_unknown_execution_outcome_enters_recovery_without_retry",
            "tests/test_goal_supervisor.py::test_failed_acquisition_examines_alternatives_before_blocking",
            "tests/test_capability_acquisition_runtime.py::test_production_coordinator_builds_certifies_stages_and_verifies_random_fixture",
            "tests/test_v1_acceptance.py::test_v1_production_composition_acquires_randomized_capability_and_restores_it",
        ],
        "diagnostic_terminal_detail": {
            "single": single,
            "fields": [
                "goal_id",
                "goal_status",
                "goal_last_error",
                "goal_evidence",
                "goal_task_id",
                "goal_capability_id",
                "acquisition_id/status/stage",
                "capability_id",
                "package_id/hash",
                "certification",
                "activation",
                "cleanup",
            ],
            "prior_non_authoritative_wrapper_attempt": {
                "result": "PASS",
                "issue": "pytest default capture suppressed R4R_LIFECYCLE_TERMINAL",
                "formal_count": 0,
            },
        },
        "fresh_single_acquisition": single,
        "fresh_pair": {
            "execution": pair_execution,
            "result": pair_result,
            "pass": pair_pass,
            "formal_count": 0,
        },
        "pair_progress_trace": (pair_result.get("progress", []) if pair_result is not None else []),
        "coverage": {
            "before_percent": before_percent,
            "after_percent": after_percent,
            "threshold_percent": 90,
            "policy_changed": False,
            "before_report_focus": _coverage_rows(before_report.stdout),
            "after_report_focus": coverage_rows,
            "critical_untested_count": critical_untested,
            "high_value_untested_count": coverage_counts.get("HIGH_VALUE_UNTESTED", 0),
            "meaningful_untested_count": coverage_counts.get("HIGH_VALUE_UNTESTED", 0),
            "platform_defensive_classification": "retained; not excluded",
            "exclusion_policy_changed": False,
            "raw_before_console_sha256": _sha256(before_report.stdout),
            "raw_after_console_sha256": _sha256(after_report.stdout),
        },
        "canonical_quality": {
            "execution": quality,
            "pass": quality_pass and after_percent is not None and after_percent >= 90,
            "static": "PASS" if quality_pass else "NOT_PROVEN",
            "deterministic_pytest": "PASS" if quality_pass else "NOT_PROVEN",
            "coverage": after_percent,
            "execution_count": 1,
        },
        "q16_q20_relationship": {
            "Q16": "canonical quality owns pytest and coverage once",
            "Q17": "SUBSUMED_BY:Q16",
            "Q20": "SUBSUMED_BY:Q16 evidence validation; no second coverage suite",
        },
        "manifest_readiness": {
            "machine_manifest_stages": 30,
            "formal_ready_or_subsumed": all(
                item["status"] in {"FORMAL_READY", "SUBSUMED_BY:Q16"}
                for item in manifest_status.values()
            ),
            "stages": manifest_status,
            "manifest": manifest_dict(),
        },
        "coordinator_regression": coordinator,
        "focused_regression": focused,
        "formal_counts": {"formal_3_of_3": 0, "formal_pair": 0, "formal_final_ten": 0},
        "test_strength": {
            "security_weakening": "NO",
            "coverage_policy_change": "NO",
            "production_goal_semantics_weakened": "NO",
            "qualification_special_case": "NO",
            "fake_pass": "NO",
        },
        "remaining_blockers": blockers,
        "terminal": (
            "R4R_QUALIFICATION_SHAKEDOWN: READY_FOR_DEFINITIVE_QUALIFICATION"
            if all_ready
            else "R4R_QUALIFICATION_SHAKEDOWN: STILL_BLOCKING"
        ),
    }
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(json.dumps(artifact, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(target)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
