"""Write the non-counting R4R-D6B2Q0 dress-rehearsal artifact."""

from __future__ import annotations

import json
import subprocess
import sys
from datetime import UTC, datetime
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))

from jarvis.acceptance.evidence import qualification_source_seal  # noqa: E402
from jarvis.qualification_manifest import manifest_dict  # noqa: E402


def _git(*args: str) -> str:
    result = subprocess.run(["git", *args], cwd=ROOT, capture_output=True, text=True, check=False)
    return result.stdout.strip()


def _stage_results() -> dict[str, dict[str, object]]:
    passed = {
        "Q01": "PASS: branch/head/parent/tree/version/status inspected",
        "Q02": "PASS: 46 recovery tests",
        "Q03": "PASS: 11 evidence/liveness tests; real pair excluded after separate hang",
        "Q04": "PASS: 115 canonical specifications validated",
        "Q05": "PASS: 83 production contamination tests",
        "Q06": "PASS: 68 deterministic foundation tests",
        "Q07": "PASS: vm-foundation real-vm 2/2",
        "Q12": "PASS: 9 cleanup-recovery tests",
        "Q15": "PASS: v1-acceptance 23/23",
        "Q17": "PASS: format, ruff, strict mypy",
        "Q18": "PASS: direct-base native suite 15/15 in current tree",
        "Q19": "PASS: ordinary venv suite 15/15; no new differential signature",
        "Q22": "PASS: persistence/certification 43/43",
        "Q23": "PASS: effects/acquisition 28/28",
        "Q24": "PASS: security bundle 206/206",
        "Q25": "PASS: recovery authority 25/25",
        "Q27": "PASS: contamination bundle 83/83",
        "Q30": "PASS: git diff --check/status/name-only terminal",
    }
    blockers = {
        "Q08": "BLOCKED: D5-class actual sequence not separately reached",
        "Q09": "BLOCKED: no machine controller fixture exists",
        "Q10": "BLOCKED: actual same-runtime pair hung before terminal evidence",
        "Q11": "BLOCKED: no machine final-ten controller fixture exists",
        "Q13": "BLOCKED: generated-child denial not separately reached in this run",
        "Q14": "BLOCKED: seal comparison fixture not separately reached",
        "Q16": (
            "BLOCKED: full quality pytest interrupted at same-runtime-pair hang; "
            "no final terminal result"
        ),
        "Q20": "NOT_REACHED: canonical coverage gate was not run independently",
        "Q21": "NOT_REACHED: package smoke was not run",
        "Q26": "BLOCKED: complete D6-era diff-strength audit not closed",
        "Q28": "BLOCKED: categorized CP1 inventory not generated",
        "Q29": "BLOCKED: foundation-only vision audit not separately recorded",
    }
    result: dict[str, dict[str, object]] = {}
    for number in range(1, 31):
        stage_id = f"Q{number:02}"
        status = passed.get(stage_id, blockers.get(stage_id, "NOT_REACHED"))
        result[stage_id] = {
            "runner_result": status,
            "executed": stage_id in passed or stage_id == "Q10" or stage_id == "Q16",
            "terminal": status.startswith("PASS"),
            "evidence_serialized": status.startswith("PASS"),
            "formal_ready": status.startswith("PASS") and stage_id not in {"Q07"},
        }
    return result


def main() -> int:
    seal, bound_files = qualification_source_seal(ROOT)
    timestamp = datetime.now(UTC).strftime("%Y%m%dT%H%M%SZ")
    target = ROOT / "artifacts" / "acceptance" / f"r4r-d6b2q0-{timestamp}.json"
    status = _git("status", "--short")
    modified = [line[3:] for line in status.splitlines() if len(line) > 3]
    inventory = {
        "include": [
            path for path in modified if path.startswith(("jarvis/", "tests/", "scripts/", "docs/"))
        ],
        "exclude": [
            "artifacts/generated runtime reports and receipts",
            "VM images/rootfs",
            "caches",
        ],
        "manual_decision": [".env.example", "qualification JSON artifacts", "screenshots", "logs"],
    }
    artifact = {
        "schema": "r4r-d6b2q0-complete-pre-self-repair-qualification-shakedown-1",
        "run_id": "R4R-D6B2Q0",
        "formal_counts": {"formal_3_of_3": 0, "formal_pair": 0, "formal_final_ten": 0},
        "source": {
            "branch": _git("branch", "--show-current"),
            "head": _git("rev-parse", "HEAD"),
            "parent": _git("rev-parse", "HEAD^"),
            "version": "1.0.0",
            "candidate_15": "NOT_CREATED",
            "starting_seal": {
                "sha256": "95bd1f9038a3aa2774ad806b195533f14302507863e250d8b1ddc2ba9d2bdb2b",
                "bound_file_count": 345,
            },
            "final_seal": {"sha256": seal, "bound_file_count": len(bound_files)},
            "bound_files": list(bound_files),
        },
        "qualification_manifest": manifest_dict(),
        "stages": _stage_results(),
        "diff_audit": {
            "windows_native_test": (
                "TEST_STRENGTHENING: authoritative join and "
                "unknown-until-late-terminal assertions added; no assertions weakened"
            ),
            "qualification_files": modified,
            "test_weakening": "UNKNOWN: complete D6-era semantic audit remains open",
        },
        "vm_foundation": {
            "workbench": "PASS",
            "disposable": "PASS",
            "host_bridge": "PASS",
            "hardening": "PASS",
            "result": "PASS 2/2 real-vm",
        },
        "diagnostic_lifecycle": {"result": "NOT_SEPARATELY_CAPTURED_IN_THIS_RUN"},
        "diagnostic_pair": {
            "result": "BLOCKED",
            "reason": "same-runtime pair control hung before terminal evidence",
        },
        "campaign_controllers": {
            "three_of_three": "NOT_IMPLEMENTED",
            "final_ten": "NOT_IMPLEMENTED",
            "result": "BLOCKED",
        },
        "late_gates": {
            "v1_acceptance": "23/23 PASS",
            "quality": "INTERRUPTED_AT_PAIR_HANG",
            "static": "PASS",
            "direct_base": "15/15 PASS",
            "ordinary_differential": "15/15 PASS",
            "coverage": "NOT_RUN",
            "package_smoke": "NOT_RUN",
            "persistence": "43/43 PASS",
            "idempotency": "28/28 PASS",
            "security": "206/206 PASS",
            "recovery_authority": "25/25 PASS",
            "contamination": "83/83 PASS",
        },
        "cp1_inventory": inventory,
        "formal_coordinator_simulation": "NOT_EXECUTED: no coordinator/fixture route exists",
        "discovered_harness_defects": [
            (
                "new manifest initially failed format/ruff; repaired and focused "
                "static regression passed"
            ),
            "same-runtime pair does not reach terminal result",
        ],
        "repairs": [
            "added typed 30-stage qualification manifest and JSON exporter",
            "formatted/linted manifest and exporter",
        ],
        "next_step_eligibility": (
            "BLOCKED: resolve pair liveness and implement/prove Q09/Q11 controller "
            "fixture paths, then rerun affected stages"
        ),
        "terminal": "R4R_QUALIFICATION_SHAKEDOWN: STILL_BLOCKING",
    }
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(json.dumps(artifact, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(target)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
