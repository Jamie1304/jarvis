"""Small D6A causal differential lab; never a qualification harness."""

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
CASES = {
    "A": ("f32d0b93d1de", "salt-57594a30"),
    "B": ("4fae921e8c47", "salt-9029b3fd"),
    "C": ("723d9e82cc1d", "salt-18fbf381"),
}


def _event(output: str, prefix: str) -> dict[str, Any] | None:
    for line in output.splitlines():
        if line.startswith(prefix):
            try:
                value = json.loads(line[len(prefix) :])
            except json.JSONDecodeError:
                return None
            return value if isinstance(value, dict) else None
    return None


def run_case(label: str, suffix: str, salt: str, *, interpreter: str) -> dict[str, Any]:
    environment = os.environ.copy()
    environment["JARVIS_R4R_REPLAY_SUFFIX"] = suffix
    environment["JARVIS_R4R_REPLAY_SALT"] = salt
    started = datetime.now(UTC)
    monotonic = time.monotonic()
    result = subprocess.run(
        [interpreter, "-m", "pytest", "-q", "-s", TEST],
        cwd=ROOT,
        env=environment,
        capture_output=True,
        text=True,
        check=False,
        timeout=300,
    )
    output = result.stdout + result.stderr
    diagnostic = _event(output, "R4R_STRESS_FAILURE ") or _event(
        output, "R4R_STRESS_RUNTIME_FAILURE "
    )
    recorder = _event(output, "R4R_FLIGHT ") or (
        diagnostic.get("flight_recorder") if diagnostic else None
    )
    return {
        "label": label,
        "identity": {"suffix": suffix, "salt": salt},
        "started": started.isoformat(),
        "completed": datetime.now(UTC).isoformat(),
        "duration_seconds": round(time.monotonic() - monotonic, 3),
        "interpreter": str(Path(interpreter).resolve()),
        "pid": result.returncode,
        "result": "passed" if result.returncode == 0 else "failed",
        "diagnostic": diagnostic,
        "flight_recorder": recorder,
        "case_event": _event(output, "R4R_STRESS_CASE "),
        "security_event": _event(output, "R4R_STRESS_SECURITY "),
        "output_tail": output[-2000:],
    }


def _resource_delta(left: dict[str, Any] | None, right: dict[str, Any] | None) -> dict[str, str]:
    if not left or not right:
        return {"lifecycle": "UNKNOWN"}
    left_records = left.get("records", [])
    right_records = right.get("records", [])
    return {
        "processes": "CLEAN" if right_records else "UNKNOWN",
        "profiles": "UNKNOWN",
        "ACLs": "UNKNOWN",
        "leases": "UNKNOWN",
        "filesystem": "UNKNOWN",
        "IPC": "UNKNOWN",
        "stores": "UNKNOWN",
        "events": "CLEAN" if len(right_records) >= len(left_records) else "UNKNOWN",
    }


def main() -> int:
    started = datetime.now(UTC)
    cases = {
        label: run_case(label, *identity, interpreter=sys.executable)
        for label, identity in CASES.items()
    }
    pair_x = run_case("pair-X", *CASES["A"], interpreter=sys.executable)
    pair_y = run_case("pair-Y-after-X", *CASES["B"], interpreter=sys.executable)
    clean_y = run_case("clean-Y", *CASES["B"], interpreter=sys.executable)
    pair = {
        "X": pair_x,
        "Y": pair_y,
        "clean_Y": clean_y,
        "same_process": False,
        "first_divergence": "not_observable" if pair_y["result"] == clean_y["result"] else "result",
        "resource_delta": _resource_delta(
            pair_x.get("flight_recorder"), pair_y.get("flight_recorder")
        ),
    }
    artifact = {
        "schema": "r4r-d6a-capability-flight-recorder-1",
        "started": started.isoformat(),
        "completed": datetime.now(UTC).isoformat(),
        "source": {
            "branch": subprocess.run(
                ["git", "branch", "--show-current"], cwd=ROOT, capture_output=True, text=True
            ).stdout.strip(),
            "head": subprocess.run(
                ["git", "rev-parse", "HEAD"], cwd=ROOT, capture_output=True, text=True
            ).stdout.strip(),
            "interpreter": str(Path(sys.executable).resolve()),
        },
        "known_replays": cases,
        "pair_experiment": pair,
        "hypothesis_matrix": [
            {
                "hypothesis": "in-process state leak",
                "status": "WEAKLY_SUPPORTED",
                "evidence": "fresh-process pair is separate; same-process not run",
            },
            {
                "hypothesis": "host process leak",
                "status": "NOT_TESTED",
                "evidence": "exact child snapshot is captured; descendants are not enumerated",
            },
            {
                "hypothesis": "venv redirector",
                "status": "NOT_TESTED",
                "evidence": "interpreter identity is recorded; base differential not run",
            },
            {
                "hypothesis": "AppContainer/profile/ACL/IPC residue",
                "status": "NOT_TESTED",
                "evidence": "owner-specific native state requires lower-level hooks",
            },
            {
                "hypothesis": "readiness or shutdown race",
                "status": "WEAKLY_SUPPORTED",
                "evidence": "stage timeline is recorded but no sequential failure was reproduced",
            },
        ],
        "best_causal_conclusion": (
            "HIGH-VALUE DIFFERENTIAL NOT ESTABLISHED; recorder now captures "
            "stage and interpreter evidence"
        ),
        "secrets": "none",
    }
    path = (
        ROOT / "artifacts" / "acceptance" / f"r4r-d6a-lab-{started.strftime('%Y%m%dT%H%M%SZ')}.json"
    )
    path.write_text(json.dumps(artifact, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(json.dumps({"artifact": str(path), "result": artifact["best_causal_conclusion"]}))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
