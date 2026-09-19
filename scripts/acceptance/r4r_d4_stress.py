"""Run the D4 randomized native capability stress sequentially."""

from __future__ import annotations

import json
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


def _event(output: str, prefix: str) -> dict[str, Any] | None:
    for line in output.splitlines():
        if line.startswith(prefix):
            try:
                value = json.loads(line[len(prefix) :])
            except json.JSONDecodeError:
                return None
            return value if isinstance(value, dict) else None
    return None


def main() -> int:
    count = 10
    evidence_dir = ROOT / "artifacts" / "acceptance"
    evidence_dir.mkdir(parents=True, exist_ok=True)
    started = datetime.now(UTC)
    iterations: list[dict[str, Any]] = []
    for number in range(1, count + 1):
        iteration_started = datetime.now(UTC)
        clock = time.monotonic()
        result = subprocess.run(
            [sys.executable, "-m", "pytest", "-q", "-s", TEST],
            cwd=ROOT,
            capture_output=True,
            text=True,
            check=False,
            timeout=300,
        )
        output = result.stdout + result.stderr
        case = _event(output, "R4R_STRESS_CASE ")
        candidate = _event(output, "R4R_STRESS_CANDIDATE ")
        security = _event(output, "R4R_STRESS_SECURITY ")
        failure = _event(output, "R4R_STRESS_FAILURE ")
        flight = _event(output, "R4R_FLIGHT ")
        record = {
            "iteration": number,
            "identity": case or {},
            "candidate": candidate or {},
            "appcontainer": security or {},
            "failure": failure or {},
            "flight_recorder": flight or {},
            "start_timestamp": iteration_started.isoformat(),
            "completion_timestamp": datetime.now(UTC).isoformat(),
            "duration_seconds": round(time.monotonic() - clock, 3),
            "result": "passed" if result.returncode == 0 else "failed",
            "certification": "passed" if result.returncode == 0 else "not_proven",
            "cleanup": "passed" if result.returncode == 0 else "not_proven",
            "exit": result.returncode,
        }
        iterations.append(record)
        print(json.dumps(record, sort_keys=True), flush=True)
        if result.returncode != 0 or case is None or candidate is None or security is None:
            print(output, file=sys.stderr)
            break

    evidence = {
        "schema": "r4r-d4-randomized-stress-1",
        "started": started.isoformat(),
        "completed": datetime.now(UTC).isoformat(),
        "required_count": count,
        "executed_count": len(iterations),
        "passed_count": sum(item["result"] == "passed" for item in iterations),
        "failed_count": sum(item["result"] != "passed" for item in iterations),
        "interpreter": str(Path(sys.executable).resolve()),
        "iterations": iterations,
    }
    output_path = evidence_dir / f"r4r-d4-stress-{started.strftime('%Y%m%dT%H%M%SZ')}.json"
    output_path.write_text(json.dumps(evidence, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(json.dumps({"evidence": str(output_path), **evidence}, sort_keys=True))
    return 0 if len(iterations) == count and not evidence["failed_count"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
