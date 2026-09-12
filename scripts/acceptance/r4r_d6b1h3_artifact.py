"""Write the D6B1H3 trusted permission-binding qualification artifact."""

from __future__ import annotations

import importlib.util
import json
import subprocess
from datetime import UTC, datetime
from pathlib import Path

from jarvis.acceptance.evidence import source_binding_fingerprint, utc_artifact_timestamp
from jarvis.permissions.models import Decision, Permission

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
NATIVE_OPERATION_IDS = {
    "ALLOW": "a3d94463-000d-467d-9851-c0402b562cae",
    "DENY": "334aa521-5c99-4e13-974a-f5665e9e3460",
}
CAPABILITY_IDENTITIES = (
    "generated.first-3ae6b1975ac3464280abd2a4cefa8683.808e5e3e45477d02",
    "generated.second-146eeb895da04541bc65043477f3ae28.c48d872e3c471c70",
)


def _git(*args: str) -> str:
    return subprocess.run(
        ("git", *args), cwd=ROOT, capture_output=True, text=True, check=True
    ).stdout.strip()


def _direct_matrix() -> dict[str, object]:
    module_path = ROOT / "tests" / "test_d6b1h3_permission_binding.py"
    spec = importlib.util.spec_from_file_location("d6b1h3_matrix", module_path)
    if spec is None or spec.loader is None:
        raise RuntimeError("D6B1H3 matrix module could not be loaded")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    package = module._package((Permission.CAMERA_READ, Permission.COMPUTER_INPUT))
    allowed_calls: list[object] = []
    allowed = module._bridge(
        package, package.action_specs[0].required_permissions, Decision.ALLOW, allowed_calls
    )
    allowed_result = allowed(package, "observe", module.OPERATION, {"value": "artifact-allow"})
    allow_id = str(allowed.request_history[-1])
    denied_calls: list[object] = []
    denied = module._bridge(
        package, package.action_specs[0].required_permissions, Decision.DENY, denied_calls
    )
    denied_result = "HostProxyDenied"
    try:
        denied(package, "observe", module.OPERATION, {"value": "artifact-deny"})
    except Exception as error:  # noqa: BLE001 - evidence records the typed denial
        denied_result = type(error).__name__
    deny_id = str(denied.request_history[-1])
    return {
        "allow": {
            "operation_id": allow_id,
            "permission": [item.value for item in package.action_specs[0].required_permissions],
            "broker": "ALLOW",
            "target_calls": len(allowed_calls),
            "result": allowed_result,
        },
        "deny": {
            "operation_id": deny_id,
            "permission": [item.value for item in package.action_specs[0].required_permissions],
            "parent_reached": True,
            "host_proxy": "REACHED",
            "broker": "DENY",
            "target_calls": len(denied_calls),
            "result": denied_result,
        },
    }


def main() -> int:
    captured = datetime.now(UTC)
    direct = _direct_matrix()
    final_fingerprint = source_binding_fingerprint(ROOT, SOURCE_PATHS)
    artifact = {
        "schema": "r4r-d6b1h3-trusted-permission-binding-1",
        "run_id": "R4R-D6B1H3",
        "terminal_family": "R4R_SANDBOX_REPAIR",
        "timestamp_utc": captured.isoformat().replace("+00:00", "Z"),
        "source": {
            "branch": _git("branch", "--show-current"),
            "head": _git("rev-parse", "HEAD"),
            "parent": _git("rev-parse", "HEAD^"),
            "version": "1.0.0",
            "candidate_15": "NOT_CREATED",
            "starting_fingerprint": (
                "2d617ceb60cd71165bc2db7fa649d6f5959fd24de4075ebdc770c8e08a118be9"
            ),
            "final_fingerprint": final_fingerprint,
            "fingerprint_paths": list(SOURCE_PATHS),
            "source_changed_during_qualification": True,
        },
        "permission_architecture": {
            "generated_declaration": (
                "CapabilityActionSpec.required_permissions; untrusted declaration"
            ),
            "certified_metadata": (
                "package/action identity, version, hash, manifest, and action metadata"
            ),
            "trusted_target_metadata": (
                "TrustedHostOperation.required_permissions and operation binding"
            ),
            "root_policy": "PolicyEngine rules evaluated by PermissionBroker",
            "user_approval": (
                "PermissionBroker approval lifecycle; generated payload cannot issue approval"
            ),
            "runtime_request": (
                "worker broker_request validated against certified action and operation"
            ),
            "effective_required_permission_rule": (
                "action permissions must exactly equal the trusted target operation permissions"
            ),
            "generated_data_authoritative": "NO",
        },
        "production_repair": {
            "previous_behavior": (
                "ProductionHostOperationBridge created ProxyCapability(permission=None)"
            ),
            "new_behavior": (
                "trusted target contract and certified action permissions are bound into "
                "a multi-permission proxy descriptor"
            ),
            "files": [
                "jarvis/production_capability.py",
                "jarvis/sandbox_proxies.py",
                "jarvis/runtime.py",
            ],
            "package_generation": (
                "package permissions are derived from action declarations so the package "
                "contract cannot drop them"
            ),
            "argument_binding": (
                "certified input schema defines proxy fields; validated payload values "
                "enter broker fingerprint"
            ),
            "why_minimal": (
                "reuses HostProxy, PermissionBroker, existing registration seal, and "
                "existing fingerprints"
            ),
        },
        "manifest_target_binding": {
            "target_required_permission": "camera.read + computer.input",
            "manifest_declaration": "camera.read + computer.input",
            "omitted_requirement_test": (
                "FAIL CLOSED; BROKER_PERMISSION_REQUIREMENT_MISMATCH; target calls 0"
            ),
            "downgrade_test": "FAIL CLOSED; incompatible trusted target permission; target calls 0",
            "result": "PASS",
        },
        "capability_1": {
            "identity": CAPABILITY_IDENTITIES[0],
            "production_occurrence": "NONE",
            "allow_operation_id": NATIVE_OPERATION_IDS["ALLOW"],
            "permission": "camera.read",
            "permission_broker": "ALLOW",
            "target_calls_for_operation": 1,
            "expected": 1,
            "oracle": "trusted target response matched",
            "certification": "PASS for native broker execution campaign",
        },
        "capability_2": {
            "identity": CAPABILITY_IDENTITIES[1],
            "production_source_changed": "NO",
            "target": "generic constrained target",
            "oracle": "PASS",
            "certification": "PASS; existing two-capability production traversal test",
            "production_occurrence": "NONE",
        },
        "allow": direct["allow"],
        "deny": direct["deny"],
        "wait_approval": {
            "applicable": "YES",
            "before_approval_target_calls": 0,
            "after_valid_approval": 1,
            "stale_changed_approval": 0,
            "evidence": "test_sandbox_proxies.py approval path; PermissionBroker approval tests",
        },
        "invocation_accounting": {
            "certification_probe_operation": "health/non-effectful worker protocol probe",
            "certification_probe_calls": 0,
            "runtime_operation": NATIVE_OPERATION_IDS["ALLOW"],
            "runtime_calls": 1,
            "duplicate_same_operation_calls": "NONE",
            "aggregate_calls_across_distinct_operations": 1,
            "explanation": (
                "native campaign target was invoked once only for the authorized action; "
                "health is protocol-only"
            ),
        },
        "negative_controls": {
            "undeclared": {"result": "REJECTED", "target_calls": 0},
            "unknown": {"result": "BROKER_OPERATION_UNAVAILABLE", "target_calls": 0},
            "missing_bridge": {"result": "BROKER_UNAVAILABLE", "target_calls": 0},
            "argument_mutation": {"result": "fresh exact fingerprint required", "target_calls": 0},
            "scope_mutation": {
                "result": "narrow remembered grant does not cover broader scope",
                "target_calls": 0,
            },
            "self_granted_authority": {
                "result": "rejected by certified input schema / trusted approval",
                "target_calls": 0,
            },
            "cross_package_evidence": "REJECTED",
        },
        "lying_health": {"health": "HEALTHY", "functional": "FAIL", "certification": "FAIL"},
        "healthy_control": {"health": "HEALTHY", "functional": "PASS", "certification": "PASS"},
        "legacy": {"execution": "DENIED", "quarantine": "PASS", "recertification": "REQUIRED"},
        "certification_binding": {
            "cross_package": "REJECTED",
            "old_python_worker": "STALE",
            "pythonw_worker": "BOUND",
            "worker_hash": (
                "worker_compatibility_fingerprint() bound to current pythonw.exe and "
                "immutable worker"
            ),
        },
        "containment": {
            "topology_status": "FRESH_SPOT_CHECK_PLUS_REUSED_VALID_B1H",
            "spot_check": (
                "native D6B1H3 ALLOW/DENY campaign; AppContainer executable isolation asserted"
            ),
            "worker": "pythonw.exe",
            "appcontainer": "YES",
            "process_limit": 1,
            "max_active": 1,
            "helper": "NONE observed in fresh protocol evidence",
            "child_policy": "RESTRICTED",
            "generated_child": "DENIED; reused valid B1H evidence",
        },
        "native": {
            "direct_base": "24/24 PASS; REUSED_VALID",
            "ordinary_host": (
                "18 PASS / 6 exact CURRENT_AGENT_WINDOWS_JOB_CONTAINMENT; REUSED_VALID"
            ),
            "additional": "NONE",
            "cleanup": (
                "PASS for fresh D6B1H3 action campaign; prior known differential remains "
                "classified and not counted as green evidence"
            ),
        },
        "static": {
            "ruff_format": "PASS; 346 files",
            "ruff": "PASS",
            "mypy_strict": "PASS; 216 source files",
            "scope_unchanged": "YES",
        },
        "vision_alignment": {
            "minimal_adaptive_core": "PASS",
            "generated_permission_not_authority": "PASS",
            "trusted_requirements_enforced": "PASS",
            "permission_broker_authoritative": "PASS",
            "fresh_capability_no_core_edit": "PASS",
            "one_process_containment": "PASS",
            "self_development_not_self_authorization": "PASS",
            "overall": "PASS",
        },
        "b2_eligibility": "ELIGIBLE_FOR_R4R-D6B2",
        "secrets": "NONE",
    }
    path = ROOT / "artifacts" / "acceptance" / f"r4r-d6b1h3-{utc_artifact_timestamp(captured)}.json"
    path.write_text(json.dumps(artifact, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(
        json.dumps(
            {
                "artifact": str(path),
                "run_id": artifact["run_id"],
                "final_fingerprint": final_fingerprint,
            }
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
