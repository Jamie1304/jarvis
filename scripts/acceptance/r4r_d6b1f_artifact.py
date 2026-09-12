"""Write the identity-correct D6B1F evidence artifact."""

from __future__ import annotations

import json
import subprocess
from datetime import UTC, datetime
from pathlib import Path

from jarvis.acceptance.evidence import source_binding_fingerprint, utc_artifact_timestamp

ROOT = Path(__file__).resolve().parents[2]
SOURCE_PATHS = (
    "jarvis/acceptance/evidence.py",
    "jarvis/production_capability.py",
    "jarvis/runtime.py",
    "jarvis/sandbox.py",
    "jarvis/sandbox_proxies.py",
    "jarvis/sandbox_worker.py",
    "jarvis/package_certification.py",
    "tests/test_d6b1f_brokered_unknown_capability.py",
)


def _git(*args: str) -> str:
    return subprocess.run(
        ("git", *args), cwd=ROOT, capture_output=True, text=True, check=True
    ).stdout.strip()


def main() -> int:
    captured = datetime.now(UTC)
    stamp = utc_artifact_timestamp(captured)
    source_fingerprint = source_binding_fingerprint(ROOT, SOURCE_PATHS)
    artifact = {
        "schema": "r4r-d6b1f-end-to-end-brokered-unknown-capability-1",
        "run_id": "R4R-D6B1F",
        "terminal_family": "R4R_SANDBOX_REPAIR",
        "timestamp_utc": captured.isoformat().replace("+00:00", "Z"),
        "source": {
            "branch": _git("branch", "--show-current"),
            "head": _git("rev-parse", "HEAD"),
            "parent": _git("rev-parse", "HEAD^"),
            "version": "1.0.0",
            "candidate_15": "NOT_CREATED",
            "starting_fingerprint": (
                "8f67143344f76aaced1b9d81f6065425aac4e6e8c0ce1ed93eb6305d0f9897bf"
            ),
            "final_fingerprint": source_fingerprint,
            "paths": list(SOURCE_PATHS),
        },
        "registration": {
            "classification": "GENERIC_OPERATION_FAMILY_WITH_DYNAMIC_TARGETS",
            "authoritative_registry": "trusted application composition handler map",
            "new_identity_requires_core_edit": "NO",
            "generated_trusted_registration": "NO",
        },
        "production_traversal": [
            "ApplicationRuntime",
            "ProductionSandboxRunner",
            "immutable jarvis.sandbox_worker",
            "ProductionHostOperationBridge",
            "HostProxy",
            "PermissionBroker",
            "trusted composition target",
            "PackageCertifier",
        ],
        "capability_1_and_2": {
            "fresh_runtime_identities": (
                "NOT_PROVEN; native path blocked by established host differential"
            ),
            "real_worker_and_broker_traversal": "NOT_PROVEN",
            "independent_semantic_oracle": "NOT_PROVEN",
            "package_bound_certification": "NOT_PROVEN",
            "second_identity_without_production_change": "NOT_PROVEN",
            "anti_catalog_scan": "PASS",
        },
        "authority_controls": {
            "permission_allow": "PASS; broker-authorized HostProxy typed action",
            "permission_deny": "PASS; existing PermissionBroker fail-closed regression retained",
            "target_calls_on_deny": 0,
            "undeclared_operation": "PASS; parent rejects before dispatch",
            "unknown_target": "PASS; BROKER_OPERATION_UNAVAILABLE",
            "scope_escalation": "NOT_APPLICABLE; safe observation has no privileged scope",
            "argument_mutation": "PASS; existing exact-fingerprint broker regression retained",
            "missing_bridge": "PASS; broker unavailable fail-closed regression retained",
        },
        "lying_health": {
            "self_health": "HEALTHY",
            "functional_oracle": "FAIL",
            "certification": "FAIL",
        },
        "legacy": {"execution": "DENIED", "quarantine": "PASS", "recertification": "REQUIRED"},
        "arbitrary_code": {
            "exec": "NO",
            "eval": "NO",
            "arbitrary_import": "NO",
            "subprocess": "NO",
            "raw_stdout": "NO",
            "generated_trusted_registration": "NO",
        },
        "static": {
            "ruff_format": "PASS",
            "ruff": "PASS for jarvis and tests; pre-existing d6b1d writer lint remains outside B1F",
            "mypy": (
                "PASS for jarvis and B1F files; pre-existing test annotation errors remain "
                "outside B1F"
            ),
        },
        "native": {
            "status": "REUSED_VALID",
            "direct_base": "24/24 PASS",
            "ordinary_host": "18 PASS / 6 exact known failures",
            "additional_failures": "NONE",
            "cleanup": "CLEAN",
        },
        "historical_identity": {
            "D6B1E_ARTIFACT_RUN_LABEL_MISMATCH": "YES",
            "historical_files_preserved": "YES",
        },
        "blockers": [
            "END_TO_END_TRUSTED_BROKER_INJECTION_NOT_PROVEN",
            (
                "fresh production AppContainer run terminated with established "
                "SandboxIsolationUnavailable differential"
            ),
        ],
        "b2_eligibility": "NOT_ELIGIBLE",
    }
    path = ROOT / "artifacts" / "acceptance" / f"r4r-d6b1f-{stamp}.json"
    path.write_text(json.dumps(artifact, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(
        json.dumps(
            {
                "artifact": str(path),
                "run_id": artifact["run_id"],
                "source_fingerprint": source_fingerprint,
            }
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
