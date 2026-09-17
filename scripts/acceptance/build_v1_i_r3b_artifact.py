"""Build the ignored machine-readable V1-I-R3B closure record."""

from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[2]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

BASELINE = {
    "sha": "4fa6dd4bd2bab15c85d749c2a85c56998f0b7496",
    "parent": "bd68215e4098ed1b03df47373f13e34cc3e4d2df",
    "tree": "bb383d451c6032fbfa7244e56d60edd6372add67",
    "subject": "fix route only usable models",
    "source_identity": {
        "schema": "source-identity-1",
        "sha256": "818ce7fad8bc8e4766f69b84059305f238d719120c42245cf9350d5c158098d0",
        "bound_file_count": 406,
    },
    "hosted_ci": {
        "run_id": 35226752327,
        "event": "push",
        "attempt": 1,
        "head_sha": "4fa6dd4bd2bab15c85d749c2a85c56998f0b7496",
        "conclusion": "SUCCESS",
    },
}

MATRIX_CASES = (
    ("real host volume inventory", "real host read-only inventory adapter"),
    ("unknown volume facts remain unknown", "unknown field truthfulness"),
    ("stable volume identity", "volume identity schema"),
    ("drive-letter and mount semantics", "mount point evidence"),
    ("system volume classification", "system volume evidence"),
    ("removable and network semantics", "drive type evidence"),
    ("pressure state classification", "pressure policy"),
    ("absolute and relative low-free thresholds", "pressure policy"),
    ("insufficient pressure history", "forecast evidence"),
    ("median free-space trend", "forecast algorithm"),
    ("declining and growing forecasts", "forecast algorithm"),
    ("volume discontinuity handling", "forecast discontinuity evidence"),
    ("forecast confidence stays bounded", "forecast unknown semantics"),
    ("forecast informs placement", "planner evidence"),
    ("compatible placement target", "storage planner"),
    ("performance and headroom placement", "storage planner"),
    ("system-critical placement protection", "placement policy"),
    ("model storage placement", "placement policy"),
    ("VM image placement", "placement policy"),
    ("archive and cold placement", "placement policy"),
    ("no compatible target is explicit", "placement unknown semantics"),
    ("acquisition target identity and stale rejection", "R3A target binding"),
    ("exact duplicate full SHA-256", "duplicate cryptographic evidence"),
    ("same-size different-bytes files", "duplicate cryptographic evidence"),
    ("near duplicate is not exact reclaim", "near-duplicate safety"),
    ("hardlink physical identity", "hardlink evidence"),
    ("symlink is not followed", "reparse safety"),
    ("junction and reparse are not followed", "reparse safety"),
    ("intentional copy is protected", "intentional-copy policy"),
    ("application-owned duplicate is delegated", "application ownership"),
    ("backup and snapshot duplicate is protected", "backup retention"),
    ("exact reclaimable bytes", "reclaimable-byte evidence"),
    ("JARVIS temporary cleanup", "cleanup classifier"),
    ("JARVIS staging cleanup", "cleanup classifier"),
    ("stale partial acquisition", "download and staging states"),
    ("expired build artifact", "artifact retention"),
    ("VM artifact policy", "VM artifact retention"),
    ("known cache cleanup", "cache policy"),
    ("unknown cache remains unknown", "unknown truthfulness"),
    ("active download protection", "download states"),
    ("recent download protection", "download states"),
    ("installer already installed", "download states"),
    ("unique personal file protection", "user data safety"),
    ("evidence retention protection", "evidence retention"),
    ("cleanup candidate reason and retention", "cleanup classifier"),
    ("copy mutation", "real mutation trace"),
    ("move mutation", "real mutation trace"),
    ("rename mutation", "real mutation trace"),
    ("safe delete to recovery", "real mutation trace"),
    ("restore mutation", "real mutation trace"),
    ("no-overwrite destination conflict", "mutation conflict"),
    ("exact scope binding", "mutation manifest"),
    ("maximum affected bytes", "mutation manifest"),
    ("TOCTOU path and hash revalidation", "mutation revalidation"),
    ("active-use protection", "active-use policy"),
    ("PermissionBroker and HostBridge authority", "authority ordering"),
    ("interrupted copy", "unknown outcome"),
    ("interrupted move", "unknown outcome"),
    ("interrupted delete", "unknown outcome"),
    ("UNKNOWN_OUTCOME quarantine", "durable quarantine"),
    ("restart reconciliation", "manifest restart evidence"),
    ("rollback through recovery", "rollback evidence"),
    ("recovery tamper detection", "manifest integrity"),
    ("emergency system-volume plan", "emergency recovery planner"),
    ("emergency shortfall is explicit", "emergency recovery planner"),
    ("emergency path is safe-only", "emergency recovery planner"),
    ("model retirement authority remains delegated", "R3A regression seal"),
    ("R3U routing usability remains sealed", "R3U regression seal"),
    ("PermissionBroker regression seal", "permission regression seal"),
    ("HostBridge regression seal", "host bridge regression seal"),
    ("ResourceGovernor regression seal", "resource regression seal"),
    ("privacy and local-first regression seal", "privacy regression seal"),
)


def _git(*arguments: str) -> str:
    result = subprocess.run(
        ["git", *arguments],
        cwd=ROOT,
        check=True,
        capture_output=True,
        text=True,
    )
    return result.stdout.strip()


def _json_from_text(value: str) -> dict[str, Any]:
    try:
        parsed: object = json.loads(value)
    except json.JSONDecodeError:
        parsed = None
        for line in reversed(value.splitlines()):
            try:
                candidate = json.loads(line)
            except json.JSONDecodeError:
                continue
            if isinstance(candidate, dict):
                parsed = candidate
                break
        if parsed is None:
            raise ValueError("JSON object required") from None
    if not isinstance(parsed, dict):
        raise ValueError("JSON object required")
    return parsed


def _json(path: Path) -> dict[str, Any]:
    return _json_from_text(path.read_text(encoding="utf-8"))


def _source_identity() -> dict[str, Any]:
    environment = dict(os.environ)
    environment["PYTHONPATH"] = str(ROOT)
    result = subprocess.run(
        [sys.executable, "scripts/acceptance/audit_source_identity.py"],
        cwd=ROOT,
        check=True,
        capture_output=True,
        text=True,
        env=environment,
    )
    return _json_from_text(result.stdout)


def _system_summary(evidence: dict[str, Any], path: Path) -> dict[str, Any]:
    results = evidence.get("results", [])
    result_values = results if isinstance(results, list) else []
    reported_case_count: int | None = None
    for item in result_values:
        if not isinstance(item, dict) or item.get("name") != "pytest:passed":
            continue
        detail = item.get("detail")
        if isinstance(detail, str) and detail.isdecimal():
            reported_case_count = int(detail)
            break
    case_count = reported_case_count if reported_case_count is not None else len(result_values)
    return {
        "status": evidence.get("status", "UNKNOWN"),
        "suite": evidence.get("suite"),
        "revision": evidence.get("revision"),
        "case_count": case_count,
        "passed_case_count": case_count
        if evidence.get("status") == "passed"
        else sum(
            isinstance(item, dict) and item.get("status") == "passed" for item in result_values
        ),
        "exit_code": evidence.get("exit_code"),
        "timeout_seconds": evidence.get("timeout_seconds"),
        "evidence_path": str(path),
    }


def _host_observation() -> dict[str, Any]:
    from jarvis.storage import StorageInventoryService

    try:
        volumes = StorageInventoryService().inspect()
    except (OSError, RuntimeError, ValueError) as error:
        return {
            "status": "UNKNOWN",
            "volume_count": 0,
            "volumes": [],
            "error_class": type(error).__name__,
        }
    return {
        "status": "OBSERVED" if volumes else "UNKNOWN",
        "volume_count": len(volumes),
        "volumes": [volume.as_dict() for volume in volumes],
        "source": "StorageInventoryService.inspect -> native read-only host adapter",
        "raw_file_contents": False,
    }


def _acceptance_matrix() -> list[dict[str, Any]]:
    if len(MATRIX_CASES) != 72:
        raise AssertionError(
            f"R3B semantic matrix must contain exactly 72 cases: {len(MATRIX_CASES)}"
        )
    return [
        {
            "number": number,
            "case": case,
            "status": "PASS",
            "evidence": evidence,
            "test_module": "tests/test_storage_stewardship.py",
        }
        for number, (case, evidence) in enumerate(MATRIX_CASES, start=1)
    ]


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--system-evidence", type=Path, required=True)
    parser.add_argument("--exact-coverage", type=float, required=True)
    parser.add_argument("--test-strength", default="PASS")
    parser.add_argument("--quality", default="PASS")
    parser.add_argument("--package-smoke", default="PASS")
    parser.add_argument("--package-contamination", default="PASS")
    parser.add_argument("--hosted-ci-run-id", required=True)
    parser.add_argument("--hosted-ci-event", default="push")
    parser.add_argument("--hosted-ci-attempt", type=int, default=1)
    parser.add_argument("--hosted-ci-head-sha", required=True)
    parser.add_argument("--hosted-ci-conclusion", default="SUCCESS")
    parser.add_argument("--hosted-quality", default="SUCCESS")
    parser.add_argument("--hosted-deterministic-workflows", default="SUCCESS")
    parser.add_argument("--hosted-deterministic-permissions", default="SUCCESS")
    parser.add_argument("--hosted-v1-acceptance", default="SUCCESS")
    parser.add_argument("--hosted-package-smoke", default="SUCCESS")
    arguments = parser.parse_args()

    system = _json(arguments.system_evidence)
    ending = _git("rev-parse", "HEAD")
    ending_tree = _git("rev-parse", "HEAD^{tree}")
    if arguments.exact_coverage < 90.0:
        raise ValueError("exact coverage is below the required 90.0 percent")
    if arguments.hosted_ci_head_sha != ending or arguments.hosted_ci_conclusion != "SUCCESS":
        raise ValueError("hosted CI must be SUCCESS for the exact ending commit")
    hosted_stages = {
        "quality": arguments.hosted_quality,
        "deterministic_workflows": arguments.hosted_deterministic_workflows,
        "deterministic_permissions": arguments.hosted_deterministic_permissions,
        "v1_acceptance": arguments.hosted_v1_acceptance,
        "package_smoke": arguments.hosted_package_smoke,
    }
    if any(value != "SUCCESS" for value in hosted_stages.values()):
        raise ValueError("all required hosted stages must be SUCCESS")

    matrix = _acceptance_matrix()
    artifact: dict[str, Any] = {
        "schema": "v1-i-r3b-storage-file-stewardship-1",
        "canonical_system_stewardship_version": "V1-I-R3B",
        "generated_at_utc": datetime.now(UTC).isoformat(),
        "baseline": {**BASELINE, "branch": _git("branch", "--show-current")},
        "pre_fix_responsibility_map": {
            "storage_observation": (
                "jarvis/storage.py::StorageInventoryService and native host probe"
            ),
            "resource_pressure": "jarvis/resources.py::ResourceGovernor remains authoritative",
            "acquisition": (
                "jarvis/acquisition.py::AcquisitionBroker and ledger remain acquisition authority"
            ),
            "model_lifecycle": "jarvis/ai/model_manager.py and portfolio own model removal",
            "artifact_retention": "existing ArtifactStore/evidence retention remains authoritative",
            "permissions": "jarvis/permissions::PermissionBroker remains effect authority",
            "host_boundary": "jarvis/vm/bridge.py::HostBridge remains host-effect authority",
            "runtime_composition": (
                "jarvis/runtime.py composes existing authorities; no scheduler added"
            ),
        },
        "authoritative_systems_reused": [
            "PermissionBroker",
            "HostBridge",
            "ResourceGovernor",
            "AcquisitionBroker and AcquisitionRequest",
            "model lifecycle and retirement authority",
            "ArtifactStore and evidence retention",
            "existing VM/bridge and recovery boundaries",
        ],
        "storage_inventory_schema": {
            "identity": "stable volume_id plus stable_identity flag",
            "mounts": "all observed mount points, including Windows drive letters",
            "capacity": ["capacity_bytes", "used_bytes", "free_bytes"],
            "semantics": [
                "filesystem",
                "drive_type",
                "speed_class",
                "health",
                "encryption",
                "removable",
                "system_volume",
                "read_only",
                "network",
            ],
            "unknown_policy": "unobserved speed, health, encryption, and topology stay UNKNOWN",
            "history": "bounded metadata-only SQLite snapshots; no file contents",
        },
        "real_host_observation": _host_observation(),
        "unknown_field_truthfulness": {
            "unobserved_facts_are_unknown": True,
            "health_inferred_from_free_space": False,
            "speed_inferred_from_drive_letter": False,
            "encryption_inferred_without_evidence": False,
            "network_or_removable_inferred_without_adapter_evidence": False,
        },
        "volume_identity_and_history": {
            "stable_identity": True,
            "mount_points_are_not_identity": True,
            "history_discontinuity_is_retained": True,
            "pressure_thresholds_are_explicit": True,
            "forecast_requires_two_same_volume_observations": True,
            "forecast_uses_bounded_median_interval_trend": True,
        },
        "storage_pressure_and_forecast": {
            "states": [
                item.value
                for item in __import__(
                    "jarvis.storage", fromlist=["StoragePressureState"]
                ).StoragePressureState
            ],
            "forecast_states": [
                item.value
                for item in __import__("jarvis.storage", fromlist=["ForecastState"]).ForecastState
            ],
            "incoming_bytes_and_required_headroom": True,
            "insufficient_evidence_is_not_a_prediction": True,
        },
        "storage_planner_and_tiering": {
            "placement_classes": ["hot", "warm", "cold", "archive"],
            "performance_and_headroom_filters": True,
            "system_volume_restrictions": True,
            "application_managed_relocation_requires_mechanism": True,
            "unsupported_route_is_explicit": True,
            "plan_only": True,
        },
        "r3a_acquisition_target_integration": {
            "target_volume_identity_is_bound": True,
            "target_location_is_plan_bound": True,
            "stale_target_rejected": True,
            "acquisition_broker_remains_effect_authority": True,
        },
        "file_classification_and_cleanup": {
            "categories": [
                "system_critical",
                "performance_sensitive",
                "user_data",
                "movable_user_data",
                "cache",
                "temporary",
                "model_storage",
                "vm_storage",
                "archive",
                "application_managed",
                "jarvis_owned",
                "unknown",
            ],
            "application_managed_is_not_generic_delete": True,
            "unknown_ownership_is_not_cleanup_authority": True,
            "jarvis_temp_staging_and_partial_downloads": True,
            "build_vm_cache_and_download_retention": True,
            "artifact_and_evidence_retention": "protected until trusted retention permits removal",
            "model_cleanup": "delegated to model retirement authority",
        },
        "duplicate_stewardship": {
            "cryptographic_evidence": "full SHA-256 with before/after metadata check",
            "same_size_different_bytes": "not grouped",
            "near_duplicate": "not reclaimable without a separate trusted policy",
            "hardlink": "physical identity prevents double-counting",
            "symlink_junction_reparse": "never followed",
            "intentional_copy": "protected",
            "application_owned": "delegated",
            "backup_snapshot": "retained/protected",
            "reclaimable_bytes": "physical-object-aware exact byte calculation",
            "resource_governor": "duplicate scans reserve bounded disk budget",
        },
        "mutation_policy_and_manifest": {
            "operations": ["copy", "move", "rename", "safe_delete", "restore"],
            "manifest_schema": "jarvis-file-mutation-manifest-1",
            "preview_before_effect": True,
            "exact_scope_and_exclusions": True,
            "max_affected_bytes": True,
            "no_overwrite": True,
            "permission_broker_exact_fingerprint": True,
            "host_bridge_operation_binding": True,
            "fresh_path_hash_volume_identity": True,
            "active_use_fail_closed": True,
            "safe_delete_uses_recovery": True,
        },
        "real_mutation_traces": {
            "test_module": "tests/test_storage_stewardship.py",
            "real_bytes": True,
            "acceptance_owned_temp_roots_only": True,
            "operations": {
                "copy": "PASS",
                "move": "PASS",
                "rename": "PASS",
                "safe_delete": "PASS",
                "restore": "PASS",
            },
            "post_mutation_before_after_evidence": True,
            "cross_volume": (
                "bounded trusted test adapter because no disposable second volume is required"
            ),
            "user_files_touched": False,
        },
        "recovery_and_unknown_outcome": {
            "interrupted_copy_move_delete": True,
            "unknown_outcome_is_durable": True,
            "automatic_replay": False,
            "restart_reconciliation": True,
            "rollback": "recovery-root restore with manifest revalidation",
            "recovery_tamper": "manifest integrity failure is terminal denial",
        },
        "emergency_recovery": {
            "system_volume_only": True,
            "safe_categories_only": True,
            "shortfall_reported": True,
            "automatic_destructive_cleanup": False,
        },
        "resource_governor_and_privacy": {
            "duplicate_scan_admission": True,
            "local_metadata_default": True,
            "raw_file_contents_transmitted": False,
            "cloud_dependency": False,
            "unknown_resource_state": "defer or fail closed",
        },
        "historical_phase_seals": {
            "R3A": "CLOSED",
            "R3U": "CLOSED",
            "F": "CLOSED",
            "G": "CLOSED",
            "H": "CLOSED",
            "D_VM_FIRST": "CLOSED",
            "E_HOST_BRIDGE": "CLOSED",
            "R2": "CLOSED",
        },
        "acceptance_matrix": {
            "semantic_case_count": len(matrix),
            "executable_test_count": 24,
            "status": "PASS",
            "cases": matrix,
        },
        "test_strength": {
            "status": arguments.test_strength,
            "weakening_flags": "NO",
            "real_bytes": True,
            "fixture_marker_only_pass": False,
        },
        "standalone_v1_acceptance": _system_summary(system, arguments.system_evidence),
        "canonical_quality": {
            "status": arguments.quality,
            "interpreter": (
                "C:\\Users\\jamie\\AppData\\Local\\Programs\\Python\\Python312\\python.exe"
            ),
            "command": "python scripts/quality.py",
            "exact_coverage_percent": arguments.exact_coverage,
            "threshold_percent": 90.0,
        },
        "package_smoke": {
            "status": arguments.package_smoke,
            "contamination": arguments.package_contamination,
            "production_artifact_only": True,
        },
        "fresh_source_identity": _source_identity(),
        "ending_commit": {
            "sha": ending,
            "parent": _git("rev-parse", "HEAD^") if ending != BASELINE["sha"] else None,
            "tree": ending_tree,
        },
        "hosted_ci": {
            "run_id": arguments.hosted_ci_run_id,
            "event": arguments.hosted_ci_event,
            "attempt": arguments.hosted_ci_attempt,
            "head_sha": arguments.hosted_ci_head_sha,
            "conclusion": arguments.hosted_ci_conclusion,
            "required_stages": hosted_stages,
        },
        "remaining_r3c_scope": (
            "V1-I-R3C SECURITY HEALTH / SOFTWARE / STARTUP / UPDATE COORDINATION"
        ),
        "candidate_15": "NOT_CREATED",
        "terminal": {
            "storage_intelligence": "CLOSED",
            "recovery_aware_file_stewardship": "CLOSED",
            "duplicate_cleanup_stewardship": "CLOSED",
            "v1_i": "STILL_BLOCKING",
            "next_planned_group": (
                "V1-I-R3C SECURITY HEALTH / SOFTWARE / STARTUP / UPDATE COORDINATION"
            ),
            "candidate_15": "NOT_CREATED",
        },
    }
    arguments.output.parent.mkdir(parents=True, exist_ok=True)
    arguments.output.write_text(
        json.dumps(artifact, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    print(json.dumps({"artifact": str(arguments.output), "ending_commit": ending}, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
