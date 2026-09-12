"""Write the compact, read-only D6A6 causal audit artifact."""

# The artifact intentionally keeps compact audit fields on one line.
# ruff: noqa: E501

from __future__ import annotations

import hashlib
import json
import subprocess
from datetime import UTC, datetime
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]


def command(*args: str) -> str:
    return subprocess.run(args, cwd=ROOT, capture_output=True, text=True, check=True).stdout.strip()


def main() -> int:
    now = datetime.now(UTC)
    relevant = (ROOT / "jarvis" / "sandbox.py").read_bytes() + (
        ROOT / "jarvis" / "production_capability.py"
    ).read_bytes()
    artifact = {
        "schema": "r4r-d6a6-trace-perturbation-1",
        "real_timestamp_utc": now.isoformat(),
        "source": {
            "branch": command("git", "branch", "--show-current"),
            "head": command("git", "rev-parse", "HEAD"),
            "parent": command("git", "rev-parse", "HEAD^"),
            "version": "1.0.0",
            "starting_fingerprint": "bb85e604a4bb4ee38760e92b13fb4e0f41c680c36928048c89a53d2c567a9161",
            "final_fingerprint": hashlib.sha256(relevant).hexdigest(),
        },
        "code_path_audit": {
            "trace_computation": "generic child constructs and serializes trace metadata only for TRACE_ON/COMPUTE_ONLY",
            "stdout_writes": "TRACE_ON adds bounded newline-delimited child trace frames; BASELINE_OFF does not",
            "flush_drain": "parent request uses write followed by asyncio StreamWriter.drain in all modes; generic child response flush is shared",
            "yield_scheduling": "no independent trace-only await/yield primitive found",
            "reader_path": "same parent readuntil newline loop; trace frames are skipped until one authoritative response",
            "other_differences": "TRACE_ON enables child diagnostics flag and stderr capture; diagnostic mode is trusted test-only plumbing",
        },
        "stdout_buffering": {
            "child_mode": "non-tty pipe",
            "line_buffered": "not relied upon",
            "write_through": "not relied upon",
            "unbuffered": "not enabled by diagnostic mode",
            "authoritative_response_write": "text sys.stdout.write with newline in generated worker",
            "explicit_flush": "yes, shared by response path",
            "trace_write": "text write plus explicit flush in TRACE_ON",
            "relevance": "not isolated as causal because response flush is shared and natural failure was not reproduced",
        },
        "parent_reader": {
            "trace_off": "continuous readuntil newline loop",
            "trace_on": "same continuous readuntil newline loop",
            "same_implementation": True,
            "reader_start": "after request drain",
            "frame_loop": True,
            "eof_handling": "IncompleteReadError classified as STDOUT_EOF",
            "timeout_start": "after request drain, at response wait",
            "cancellation": "bounded task cancellation and owned process cleanup",
        },
        "parent_only_recorder": {
            "child_side_perturbation": "NONE",
            "phases": "bounded in-memory records with monotonic and UTC timestamps",
            "process_evidence": "owned PID/alive/exit/elapsed only",
            "job_evidence": "owned Job active count and configured limit only",
            "response_evidence": "write, drain, wait, receive, parse, validation phases",
            "artifact_write_timing": "after lifecycle cleanup by diagnostic runner",
        },
        "modes": {
            "BASELINE_OFF": "implemented; no trace computation or child trace write",
            "COMPUTE_ONLY": "implemented; generic worker computes serialized trace metadata without writing",
            "FLUSH_ONLY": "implemented as meaningful only where a separate flush exists; response flush is shared, so no production differential",
            "YIELD_ONLY": "NOT_APPLICABLE; no independent trace-only scheduling primitive",
            "UNIFIED_READER_NO_TRACE": "NOT_APPLICABLE; TRACE ON/OFF already share the reader",
            "TRACE_ON": "implemented; current generic child trace behavior",
        },
        "c_results": {
            "BASELINE_OFF": {
                "attempts": 1,
                "passes": 1,
                "failures": 0,
                "representative_seconds": 108.07,
            },
            "COMPUTE_ONLY": {
                "attempts": 1,
                "passes": 1,
                "failures": 0,
                "representative_seconds": 108.21,
            },
            "FLUSH_ONLY": {
                "attempts": 1,
                "passes": 1,
                "failures": 0,
                "representative_seconds": 111.01,
            },
            "TRACE_ON": {
                "attempts": 0,
                "passes": 0,
                "failures": 0,
                "note": "reused prior D6A5 8/8 PASS; no rerun",
            },
        },
        "baseline_natural_failure": {
            "captured": False,
            "reason": "bounded BASELINE_OFF replay passed",
        },
        "controlled_differential": {
            "suspected_mechanism": "unresolved; no natural failure and no trace-capable child path in the explicit replay fixture",
            "baseline_result": "PASS",
            "control_result": "PASS",
            "trace_on_result": "prior D6A5 8/8 PASS",
        },
        "security": {
            "appcontainer_changed": False,
            "job_policy_changed": False,
            "timeout_changed": False,
            "authority_changed": False,
            "certification_weakened": False,
            "new_handles": "NONE",
            "secret_leakage": "NONE",
        },
        "conclusion": "STILL_UNEXPLAINED",
        "secrets": "none",
    }
    path = ROOT / "artifacts" / "acceptance" / f"r4r-d6a6-{now.strftime('%Y%m%dT%H%M%SZ')}.json"
    path.write_text(json.dumps(artifact, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(path)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
