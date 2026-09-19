"""Create the compact D6A7 replay-fidelity/readiness evidence artifact."""

# Compact audit strings intentionally remain single-line fields.
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


def digest(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def main() -> int:
    now = datetime.now(UTC)
    production = ROOT / "jarvis" / "production_capability.py"
    sandbox = ROOT / "jarvis" / "sandbox.py"
    replay = ROOT / "tests" / "test_v1_acceptance.py"
    artifact = {
        "schema": "r4r-d6a7-replay-fidelity-readiness-1",
        "real_timestamp_utc": now.isoformat(),
        "source": {
            "branch": command("git", "branch", "--show-current"),
            "head": command("git", "rev-parse", "HEAD"),
            "parent": command("git", "rev-parse", "HEAD^"),
            "version": "1.0.0",
            "starting_fingerprint": "e40ae8b94b79327f2bdbea1195307eadccfc2138439c68e5488ae22980899808",
            "final_fingerprint": hashlib.sha256(
                production.read_bytes() + sandbox.read_bytes() + replay.read_bytes()
            ).hexdigest(),
        },
        "production_path_fingerprint": {
            "entrypoint_contract": digest(production),
            "protocol_implementation": digest(sandbox),
            "runner": "jarvis.production_capability.ProductionSandboxRunner",
            "sandbox_provider": "jarvis.sandbox.SandboxProcess + Windows AppContainer",
            "child_executable": "_sandbox_python_executable()",
            "health_handler": "generated code/entrypoint.py health branch",
            "package_runtime": "ProductionPackageRuntime",
            "certifier": "ProductionCertificationProvider -> PackageCertifier",
        },
        "replay_path_fingerprint": {
            "entrypoint": "tests/test_v1_acceptance.py action_source stored as code/entrypoint.py",
            "runner": "ProductionSandboxRunner",
            "sandbox_provider": "SandboxProcess + Windows AppContainer",
            "protocol": "SandboxMessage / newline JSON",
            "health_handler": "same stored synthetic entrypoint health branch",
            "health_state_source": "entrypoint response payload; no separate readiness store",
            "certifier": "same ProductionCertificationProvider and PackageCertifier",
        },
        "fidelity": {
            "c_replay_real_generated_entrypoint": "YES",
            "same_health_handler": "YES",
            "same_runtime_readiness_state": "YES - neither path has an independent readiness state",
            "same_appcontainer": "YES",
            "same_protocol": "YES",
            "same_certifier": "YES",
            "overall": "FULL_FIDELITY_FOR_CURRENT_C_HEALTH_PATH",
            "d6a4_fixture_fidelity": "NO - simplified child fixture",
            "d6a6_fixture_fidelity": "NO - simplified child fixture",
        },
        "historical_correction": {
            "d6a5_trace_perturbation": "NOT_PROVEN",
            "reason": "prior trace differential was not proven against a trace-capable equivalent production child",
        },
        "startup_readiness_timeline": {
            "process_create": "SandboxProcess.start launches child",
            "protocol_loop": "child enters for-line loop",
            "runtime_initialization": "none represented in generated worker",
            "readiness_transition": "none represented",
            "health_available": "immediately when a line is parsed",
            "shadow_activation": "after certification, separate trusted sandbox request",
            "certification": "one-shot health stage plus functional/authority stages",
            "active": "activation lifecycle ACTIVE, after certification and shadow/canary promotion; later verification updates acquisition ACTIVE",
        },
        "health_semantics": {
            "source": "generated entrypoint health branch hardcodes healthy response",
            "owner": "child entrypoint response, validated by trusted parent",
            "initial_state": "no explicit transitional state",
            "healthy_state": "response payload status=healthy",
            "background_work": "none identified",
            "request_count": "one per SandboxProcess invocation",
            "parent_behavior": "valid non-healthy response fails the certification stage immediately",
            "transport_timeout": "60 seconds per request, not a readiness deadline",
        },
        "deterministic_readiness_experiment": {
            "performed": "NO",
            "reason": "no canonical readiness state or transition exists to gate; adding one would invent production semantics",
            "first_health_result": "not applicable",
            "post_release_health_result": "not applicable",
            "same_child": "not applicable; runner creates one SandboxProcess per request",
        },
        "active_state_audit": {
            "meaning": "trusted activation/lifecycle state, not sandbox process readiness",
            "before_health": "NO; certification precedes registration, shadow, canary, promotion",
            "authoritative": "YES for activation lifecycle; not health truth",
            "ordering": "correct for current state machine",
            "separate_defect": "NO_PROVEN",
        },
        "controls": {
            "never_ready": "NOT_APPLICABLE - no readiness gate exists",
            "process_exit": "existing protocol fault matrix remains fail-closed",
            "invalid_response": "existing D6A4 matrix remains fail-closed without readiness retry",
        },
        "security": {
            "appcontainer_changed": False,
            "job_limits_changed": False,
            "acl_changed": False,
            "timeout_changed": False,
            "certification_changed": False,
            "fault_hook": "none added",
            "authority_changed": False,
            "secrets": "none",
        },
        "classification": "SUBSYSTEM_ISOLATED",
        "next_operation": "ARCHITECTURE-LEVEL REVIEW OF THE SANDBOX READINESS/CERTIFICATION CONTRACT",
    }
    path = ROOT / "artifacts" / "acceptance" / f"r4r-d6a7-{now.strftime('%Y%m%dT%H%M%SZ')}.json"
    path.write_text(json.dumps(artifact, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(path)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
