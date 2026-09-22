"""Run the bounded D6A5 trace differential and natural trigger campaign."""

from __future__ import annotations

import json
import os
import subprocess
import sys
import time
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[2]
TEST = (
    "tests/test_v1_acceptance.py::"
    "test_v1_production_composition_acquires_randomized_capability_and_restores_it"
)
C_IDENTITY = ("723d9e82cc1d", "salt-18fbf381")


def event(output: str, prefix: str) -> dict[str, Any] | None:
    for line in output.splitlines():
        if line.startswith(prefix):
            try:
                value = json.loads(line[len(prefix) :])
            except json.JSONDecodeError:
                return None
            return value if isinstance(value, dict) else None
    return None


def classify(result: int, output: str) -> str:
    if result == 0:
        return "PASS"
    if "ProposedStep" in output or "tool_id" in output and "128" in output:
        return "PRE_SANDBOX_VALIDATION_FAILURE"
    if "HEALTHCHECK" in output or "health" in output.lower():
        return "SANDBOX_HEALTH_FAILURE"
    return "POST_SANDBOX_FAILURE"


def run_case(label: str, suffix: str, salt: str, trace: bool) -> dict[str, Any]:
    env = os.environ.copy()
    env["JARVIS_R4R_REPLAY_SUFFIX"] = suffix
    env["JARVIS_R4R_REPLAY_SALT"] = salt
    env["JARVIS_R4R_CHILD_TRACE"] = "on" if trace else "off"
    started = time.monotonic()
    result = subprocess.run(
        [sys.executable, "-m", "pytest", "-q", "-s", TEST],
        cwd=ROOT,
        env=env,
        capture_output=True,
        text=True,
        check=False,
        timeout=300,
    )
    output = result.stdout + result.stderr
    diagnostic = event(output, "R4R_STRESS_FAILURE ") or event(
        output, "R4R_STRESS_RUNTIME_FAILURE "
    )
    return {
        "label": label,
        "identity": {"suffix": suffix, "salt": salt},
        "trace": trace,
        "duration_seconds": round(time.monotonic() - started, 3),
        "exit_code": result.returncode,
        "classification": classify(result.returncode, output),
        "case": event(output, "R4R_STRESS_CASE "),
        "security": event(output, "R4R_STRESS_SECURITY "),
        "diagnostic": diagnostic,
        "flight_recorder": event(output, "R4R_FLIGHT ")
        or (diagnostic or {}).get("flight_recorder"),
        "output_tail": output[-3000:],
    }


def bounded_replay(label: str, trace: bool, maximum: int) -> list[dict[str, Any]]:
    runs: list[dict[str, Any]] = []
    for attempt in range(1, maximum + 1):
        result = run_case(f"{label}-{attempt}", *C_IDENTITY, trace)
        result["attempt"] = attempt
        runs.append(result)
        print(json.dumps(result, sort_keys=True), flush=True)
        if result["classification"] != "PASS":
            break
    return runs


def main() -> int:
    started = datetime.now(UTC)
    trace_on = bounded_replay("C-trace-on", True, 8)
    trace_off: list[dict[str, Any]] = []
    fresh: list[dict[str, Any]] = []
    if all(item["classification"] == "PASS" for item in trace_on):
        trace_off = bounded_replay("C-trace-off", False, 5)
    if trace_off and all(item["classification"] == "PASS" for item in trace_off):
        for number in range(1, 13):
            suffix = f"d6a5-{started.strftime('%Y%m%d')}-{number:02d}-{os.urandom(4).hex()}"
            salt = f"salt-{os.urandom(4).hex()}"
            result = run_case(f"fresh-{number}", suffix, salt, True)
            fresh.append(result)
            print(json.dumps(result, sort_keys=True), flush=True)
            if result["classification"] != "PASS":
                break
    artifact = {
        "schema": "r4r-d6a5-instrumented-natural-trigger-campaign-1",
        "timestamp_utc": datetime.now(UTC).isoformat(),
        "started_utc": started.isoformat(),
        "source": {
            "branch": subprocess.run(
                ["git", "branch", "--show-current"], cwd=ROOT, capture_output=True, text=True
            ).stdout.strip(),
            "head": subprocess.run(
                ["git", "rev-parse", "HEAD"], cwd=ROOT, capture_output=True, text=True
            ).stdout.strip(),
        },
        "tool_id_confounder": {
            "value": "not preserved by D6A4 artifact",
            "length": ">128 (exact length unavailable)",
            "schema_limit": 128,
            "source": "prior diagnostic artifact only; exact provenance not machine-captured",
            "classification": "UNRESOLVED_PROVENANCE__LIKELY_HARNESS_GENERATOR_DEFECT",
            "product_defect": "not proven",
            "harness_defect": "not proven without original value",
        },
        "c_trace_on": trace_on,
        "c_trace_off": trace_off,
        "fresh_randomized": fresh,
        "trace_perturbation": (
            "SUPPORTED"
            if trace_off and any(x["classification"] != "PASS" for x in trace_off)
            else "NOT_PROVEN"
        ),
        "classification": "STILL_UNEXPLAINED",
        "observability_complete": True,
        "security": {
            "authority_changed": False,
            "appcontainer_changed": False,
            "job_limits_changed": False,
            "timeout_changed": False,
            "secrets": "none",
        },
    }
    path = (
        ROOT
        / "artifacts"
        / "acceptance"
        / f"r4r-d6a5-campaign-{started.strftime('%Y%m%dT%H%M%SZ')}.json"
    )
    path.write_text(json.dumps(artifact, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(
        json.dumps(
            {"artifact": str(path), "classification": artifact["classification"]}, sort_keys=True
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
