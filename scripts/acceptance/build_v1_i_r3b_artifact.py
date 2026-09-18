"""Build the ignored machine-readable V1-I-R3B closure record."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import subprocess
import sys
from datetime import UTC, datetime
from pathlib import Path
from typing import Any
from xml.etree import ElementTree

ROOT = Path(__file__).resolve().parents[2]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

BASELINE = {
    "sha": "89e8e55c2884ca66580b3623cb0f98895639dba5",
    "parent": "4fa6dd4bd2bab15c85d749c2a85c56998f0b7496",
    "tree": "9924037265cac29eea811b4d781ad25c7a71c30d",
    "subject": "feat: add recovery-aware storage stewardship",
    "source_identity": {
        "schema": "source-identity-1",
        "sha256": "eb963cd16c94c95073b376c8de0f401ef22fdf6a508926710e123d6dc3108908",
        "bound_file_count": 409,
    },
    "hosted_ci": {
        "run_id": 35260351999,
        "event": "push",
        "attempt": 1,
        "head_sha": "89e8e55c2884ca66580b3623cb0f98895639dba5",
        "conclusion": "NON_TERMINAL",
    },
}

HISTORICAL_R1_CI = {
    "run_id": 35274007561,
    "event": "push",
    "attempt": 1,
    "head_sha": "05ad4d91979ccc92d663df259622bcfbc342cc26",
    "conclusion": "SUCCESS",
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

R1_REQUIREMENTS = (
    (
        "R3B-R1-A",
        "partial batch reconciliation",
        "test_r1_reproduction_partial_batch_does_not_complete_from_first_item",
    ),
    (
        "R3B-R1-B",
        "all-item batch restore",
        "test_r1_reproduction_batch_restore_requires_all_items",
    ),
    (
        "R3B-R1-C",
        "partial broker effect outcome",
        "test_r1_reproduction_partial_effect_is_not_a_not_executed_receipt",
    ),
    (
        "R3B-R1-D",
        "receipt-bound HostBridge authority",
        "test_r1_receipt_bound_host_bridge_covers_exact_batch_and_rejects_replays",
    ),
    (
        "R3B-R1-D-NO-BRIDGE",
        "missing HostBridge denies all host effects",
        "test_r1_reproduction_missing_host_bridge_does_not_bypass_host_authority",
    ),
    (
        "R3B-R1-E",
        "cross-volume destination and source races",
        "test_r1_reproduction_cross_volume_finalization_preserves_conflict_and_source",
    ),
    (
        "R3B-R1-F",
        "restore interruption direction",
        "test_r1_restore_interruption_is_not_reconciled_as_delete",
    ),
    (
        "R3B-R1-G",
        "child-process restart reconciliation",
        "test_r1_child_process_interruption_reconciles_without_replay",
    ),
    (
        "R3B-R1-H",
        "live protection revalidation",
        "test_r1_live_protection_revalidation_denies_new_obligations",
    ),
    (
        "R3B-R1-I",
        "acceptance evidence provenance",
        "test_r1_reproduction_builder_rejects_missing_failed_and_stale_evidence",
    ),
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


_REVISION_RE = re.compile(r"^[0-9a-fA-F]{40}$")
_SHA256_RE = re.compile(r"^[0-9a-fA-F]{64}$")


def _valid_revision(value: object) -> bool:
    return isinstance(value, str) and _REVISION_RE.fullmatch(value) is not None


def _valid_sha256(value: object) -> bool:
    return isinstance(value, str) and _SHA256_RE.fullmatch(value) is not None


def _valid_tree(value: object) -> bool:
    return _valid_revision(value)


def _valid_source_identity(value: object) -> bool:
    if not isinstance(value, dict):
        return False
    return (
        value.get("schema") == "source-identity-1"
        and _valid_sha256(value.get("sha256"))
        and type(value.get("bound_file_count")) is int
        and int(value["bound_file_count"]) > 0
    )


def _file_sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        while chunk := handle.read(1024 * 1024):
            digest.update(chunk)
    return digest.hexdigest()


def _evidence_path(value: object) -> Path | None:
    if not isinstance(value, str) or not value:
        return None
    candidate = Path(value)
    return candidate if candidate.is_absolute() else ROOT / candidate


def _raw_evidence_entries(execution: dict[str, Any]) -> tuple[dict[str, str], ...]:
    raw = execution.get("raw_evidence")
    if isinstance(raw, list):
        entries: list[dict[str, str]] = []
        for item in raw:
            if not isinstance(item, dict):
                return ()
            path = item.get("path")
            digest = item.get("sha256")
            if not isinstance(path, str) or not isinstance(digest, str):
                return ()
            entries.append({"path": path, "sha256": digest})
        return tuple(entries)
    path = execution.get("raw_evidence_path")
    digest = execution.get("raw_evidence_sha256", execution.get("evidence_digest"))
    if isinstance(path, str) and isinstance(digest, str):
        return ({"path": path, "sha256": digest},)
    return ()


def _raw_evidence_is_bound(execution: dict[str, Any]) -> tuple[bool, str]:
    entries = _raw_evidence_entries(execution)
    if not entries:
        return False, "raw evidence path and digest are required"
    for entry in entries:
        if not _valid_sha256(entry["sha256"]):
            return False, "raw evidence digest is malformed"
        path = _evidence_path(entry["path"])
        if path is None or not path.is_file():
            return False, "raw evidence file is missing"
        try:
            observed = _file_sha256(path)
        except OSError:
            return False, "raw evidence file is unreadable"
        if observed.casefold() != entry["sha256"].casefold():
            return False, "raw evidence digest does not match"
    return True, "raw evidence digest verified"


def _execution_is_bound(
    evidence: dict[str, Any],
    ending: str,
    ending_tree: str,
    source: dict[str, Any] | None = None,
) -> tuple[bool, str]:
    execution = evidence.get("execution")
    if not isinstance(execution, dict):
        return False, "execution-time provenance is missing"
    if not isinstance(execution.get("run_id"), str) or not execution["run_id"].strip():
        return False, "execution run identity is missing"
    command = execution.get("command")
    if not (isinstance(command, str) and command.strip()) and not (
        isinstance(command, list)
        and bool(command)
        and all(isinstance(value, str) and value for value in command)
    ):
        return False, "execution command is missing"
    selection = execution.get("selection")
    if not (isinstance(selection, str) and selection.strip()) and not (
        isinstance(selection, list)
        and bool(selection)
        and all(isinstance(value, str) and value for value in selection)
    ):
        return False, "execution test selection is missing"
    exit_code = execution.get("exit_code", evidence.get("exit_code"))
    if type(exit_code) is not int:
        return False, "execution exit status is missing"
    if evidence.get("exit_code") is not None and evidence.get("exit_code") != exit_code:
        return False, "execution and evidence exit statuses disagree"
    base_revision = execution.get("base_revision")
    if not _valid_revision(base_revision):
        return False, "execution base revision is malformed"
    tested_tree = execution.get("tested_tree")
    if not _valid_tree(tested_tree) or tested_tree != ending_tree:
        return False, "execution tested tree is not the final source tree"
    for key in ("tree_before", "tree_after"):
        if not _valid_tree(execution.get(key)):
            return False, f"execution {key} is malformed"
    before = execution.get("source_identity_before")
    after = execution.get("source_identity_after")
    if not _valid_source_identity(before) or not _valid_source_identity(after):
        return False, "execution source identity seal is incomplete"
    if before != after:
        return False, "source identity changed during execution"
    if source is not None and after != source:
        return False, "execution source identity does not match the final source"
    raw_ok, raw_detail = _raw_evidence_is_bound(execution)
    if not raw_ok:
        return False, raw_detail
    if not _valid_revision(ending) or not _valid_tree(ending_tree):
        return False, "final source labels are malformed"
    return True, "execution-time source and raw evidence bound"


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
        "tree": evidence.get("tree"),
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


def _scenario_tests(
    path: Path | None,
    *,
    supplied_revision: str | None = None,
    supplied_tree: str | None = None,
    provenance_path: Path | None = None,
) -> tuple[dict[str, Any], ...]:
    if path is None:
        return ()
    provenance: dict[str, Any] = {}
    if provenance_path is not None:
        provenance = _json(provenance_path)
        if isinstance(provenance.get("execution"), dict):
            provenance = provenance["execution"]
    if path.suffix.casefold() == ".xml":
        root = ElementTree.parse(path).getroot()
        normalized: list[dict[str, Any]] = []
        for node in root.iter("testcase"):
            classname = str(node.get("classname", ""))
            name = str(node.get("name", ""))
            test_id = f"{classname}::{name}" if classname else name
            if node.find("failure") is not None or node.find("error") is not None:
                status = "FAIL"
                observed = "test failure or error recorded by JUnit"
                classification = "EXECUTED_FAILED"
            elif node.find("skipped") is not None:
                status = "NOT_EXECUTED"
                observed = "test was skipped"
                classification = "SKIPPED"
            else:
                status = "PASS"
                observed = "testcase completed without failure"
                classification = "EXECUTED_PASS"
            normalized.append(
                {
                    "test_id": test_id,
                    "name": name,
                    "status": status,
                    "execution_classification": classification,
                    "observed_outcome": observed,
                    "evidence_reference": f"{path}::{test_id}",
                    "revision": supplied_revision,
                    "tree": supplied_tree,
                    "requirement_id": None,
                    "requirement_ids": (),
                    "case": None,
                    "execution": provenance or None,
                }
            )
        return tuple(normalized)
    payload = _json(path)
    records = payload.get("tests", payload.get("cases", ()))
    if not isinstance(records, list):
        raise ValueError("scenario evidence tests must be a list")
    evidence_revision = payload.get("revision", supplied_revision)
    evidence_tree = payload.get("tree", supplied_tree)
    evidence_exit_code = payload.get("exit_code", 0)
    payload_execution = payload.get("execution")
    normalized = []
    for index, record in enumerate(records):
        if not isinstance(record, dict) or not isinstance(record.get("test_id"), str):
            normalized.append(
                {
                    "test_id": f"malformed-record-{index}",
                    "name": f"malformed-record-{index}",
                    "status": "BLOCKING_NOT_PROVEN",
                    "execution_classification": "MALFORMED_RECORD",
                    "observed_outcome": "scenario evidence record identity is malformed",
                    "evidence_reference": str(path),
                    "revision": evidence_revision,
                    "tree": evidence_tree,
                    "requirement_id": None,
                    "requirement_ids": (),
                    "case": None,
                    "execution": payload_execution,
                    "mapping_error": "malformed record",
                }
            )
            continue
        supplied = str(record.get("status", "NOT_EXECUTED")).upper()
        status = {
            "PASSED": "PASS",
            "PASS": "PASS",
            "FAILED": "FAIL",
            "FAIL": "FAIL",
            "SKIPPED": "NOT_EXECUTED",
            "NOT_EXECUTED": "NOT_EXECUTED",
            "BLOCKING_NOT_PROVEN": "BLOCKING_NOT_PROVEN",
        }.get(supplied, "BLOCKING_NOT_PROVEN")
        normalized.append(
            {
                "test_id": record["test_id"],
                "name": str(record.get("name", record["test_id"])),
                "status": status,
                "execution_classification": str(
                    record.get("execution_classification", "SUPPLIED_EVIDENCE")
                ),
                "observed_outcome": str(record.get("observed_outcome", "")),
                "evidence_reference": str(record.get("evidence_reference", path)),
                "revision": record.get("revision", evidence_revision),
                "tree": record.get("tree", evidence_tree),
                "exit_code": record.get("exit_code", evidence_exit_code),
                "requirement_id": record.get("requirement_id"),
                "requirement_ids": record.get("requirement_ids", ()),
                "case": record.get("case"),
                "source_identity": record.get("source_identity"),
                "execution": record.get("execution", payload_execution),
            }
        )
    return tuple(normalized)


def _scenario_is_bound(
    record: dict[str, Any],
    ending: str,
    tree: str,
    source: dict[str, Any] | None = None,
) -> bool:
    if record.get("tree") != tree:
        return False
    revision = record.get("revision")
    if not _valid_revision(revision):
        return False
    execution = record.get("execution")
    if not isinstance(execution, dict) or execution.get("base_revision") != revision:
        return False
    claimed_identity = record.get("source_identity")
    if claimed_identity is not None and claimed_identity != execution.get("source_identity_after"):
        return False
    bound, _detail = _execution_is_bound(record, ending, tree, source)
    return bound


def _scenario_status(
    record: dict[str, Any],
    ending: str,
    tree: str,
    source: dict[str, Any] | None = None,
) -> str:
    if not _scenario_is_bound(record, ending, tree, source):
        return "BLOCKING_NOT_PROVEN"
    status = str(record.get("status", "BLOCKING_NOT_PROVEN"))
    if status == "PASS" and record.get("exit_code", 0) != 0:
        return "BLOCKING_NOT_PROVEN"
    return status


def _find_scenario_test(
    records: tuple[dict[str, Any], ...], expected_name: str
) -> dict[str, Any] | None:
    for record in records:
        if record.get("name") == expected_name or str(record.get("test_id", "")).endswith(
            f"::{expected_name}"
        ):
            return record
    return None


def _r1_requirements(
    records: tuple[dict[str, Any], ...],
    source: dict[str, Any],
    ending: str,
    tree: str,
) -> list[dict[str, Any]]:
    output: list[dict[str, Any]] = []
    for requirement_id, description, test_name in R1_REQUIREMENTS:
        record = _find_scenario_test(records, test_name)
        status = "NOT_EXECUTED"
        if record is not None:
            status = _scenario_status(record, ending, tree, source)
        output.append(
            {
                "requirement_id": requirement_id,
                "description": description,
                "test_scenario_identity": test_name,
                "execution_classification": (
                    record["execution_classification"] if record is not None else "NOT_EXECUTED"
                ),
                "source_identity": source,
                "tree": tree,
                "evidence_reference": record["evidence_reference"] if record else None,
                "observed_outcome": (
                    record["observed_outcome"]
                    if record is not None
                    else "required scenario evidence was not supplied"
                ),
                "status": status,
                "coverage_disposition": "requires same-run canonical quality evidence",
            }
        )
    return output


def _matrix_specs() -> tuple[tuple[str, str, str], ...]:
    return tuple(
        (f"R3B-{number:03d}", case, evidence)
        for number, (case, evidence) in enumerate(MATRIX_CASES, start=1)
    )


def _mapped_matrix_records(
    records: tuple[dict[str, Any], ...],
) -> tuple[
    dict[str, list[tuple[int, dict[str, Any]]]],
    dict[int, str],
    tuple[str, ...],
]:
    specs = _matrix_specs()
    known = {requirement_id: (case, evidence) for requirement_id, case, evidence in specs}
    by_case = {case: requirement_id for requirement_id, (case, _evidence) in known.items()}
    by_id: dict[str, list[tuple[int, dict[str, Any]]]] = {}
    errors: dict[int, str] = {}
    diagnostics: list[str] = []
    for index, record in enumerate(records):
        raw_ids = record.get("requirement_ids", ())
        if isinstance(raw_ids, str):
            ids = [raw_ids]
        elif isinstance(raw_ids, list | tuple) and all(isinstance(value, str) for value in raw_ids):
            ids = list(raw_ids)
        elif raw_ids is None or raw_ids == ():
            ids = []
        else:
            ids = []
            errors[index] = "requirement_ids is malformed"
        requirement_id = record.get("requirement_id")
        if requirement_id is not None:
            if isinstance(requirement_id, str):
                ids.append(requirement_id)
            else:
                errors[index] = "requirement_id is malformed"
        ids = list(dict.fromkeys(ids))
        case = record.get("case")
        if not ids:
            if isinstance(case, str) and case in by_case:
                ids.append(by_case[case])
            elif case is not None:
                errors[index] = "case is unknown or malformed"
                diagnostics.append(f"record {index}: unknown case mapping")
        for candidate in ids:
            if candidate not in known:
                diagnostics.append(f"record {index}: unknown requirement id {candidate}")
                errors[index] = f"unknown requirement id: {candidate}"
                continue
            by_id.setdefault(candidate, []).append((index, record))
            expected_case = known[candidate][0]
            if case is not None and case != expected_case:
                errors[index] = "requirement id and case disagree"
                diagnostics.append(f"record {index}: requirement id and case disagree")
    return by_id, errors, tuple(diagnostics)


def _matrix_status(
    entries: list[tuple[int, dict[str, Any]]],
    errors: dict[int, str],
    ending: str,
    tree: str,
    source: dict[str, Any],
) -> str:
    if not entries:
        return "NOT_EXECUTED"
    if any(index in errors for index, _record in entries):
        return "BLOCKING_NOT_PROVEN"
    statuses = [_scenario_status(record, ending, tree, source) for _index, record in entries]
    if any(status == "FAIL" for status in statuses):
        return "FAIL"
    if any(status == "BLOCKING_NOT_PROVEN" for status in statuses):
        return "BLOCKING_NOT_PROVEN"
    if any(status == "NOT_EXECUTED" for status in statuses):
        return "NOT_EXECUTED"
    test_ids = [str(record.get("test_id")) for _index, record in entries]
    if len(set(test_ids)) != len(test_ids):
        return "BLOCKING_NOT_PROVEN"
    return "PASS" if all(status == "PASS" for status in statuses) else "BLOCKING_NOT_PROVEN"


def _acceptance_matrix(
    records: tuple[dict[str, Any], ...], source: dict[str, Any], ending: str, tree: str
) -> list[dict[str, Any]]:
    """Return evidence-backed rows keyed by stable requirement identity."""

    supplied_by_id, mapping_errors, _diagnostics = _mapped_matrix_records(records)
    output: list[dict[str, Any]] = []
    for requirement_id, case, evidence in _matrix_specs():
        entries = supplied_by_id.get(requirement_id, [])
        status = _matrix_status(entries, mapping_errors, ending, tree, source)
        record = entries[0][1] if entries else None
        output.append(
            {
                "requirement_id": requirement_id,
                "number": int(requirement_id.removeprefix("R3B-")),
                "case": case,
                "status": status,
                "evidence": evidence,
                "test_scenario_identity": (str(record.get("test_id")) if record else None),
                "execution_classification": (
                    str(record.get("execution_classification", "SUPPLIED_EVIDENCE"))
                    if record
                    else "NOT_EXECUTED"
                ),
                "source_identity": source,
                "tree": tree,
                "evidence_reference": record.get("evidence_reference") if record else None,
                "observed_outcome": (
                    str(record.get("observed_outcome", ""))
                    if record
                    else "required scenario evidence was not supplied"
                ),
                "coverage_disposition": "requires same-run canonical quality evidence",
            }
        )
    return output


def _matrix_mapping_diagnostics(records: tuple[dict[str, Any], ...]) -> tuple[str, ...]:
    return _mapped_matrix_records(records)[2]


def _observed_gate(
    *,
    label: str,
    supplied_status: str | None,
    evidence_path: Path | None,
    ending: str,
    ending_tree: str,
    source: dict[str, Any] | None = None,
    exact_coverage: float | None = None,
) -> dict[str, Any]:
    evidence: dict[str, Any] | None = None
    error: str | None = None
    if evidence_path is None:
        error = "independent gate evidence was not supplied"
    else:
        try:
            evidence = _json(evidence_path)
        except (OSError, UnicodeError, ValueError) as exc:
            error = f"gate evidence is unreadable: {type(exc).__name__}"
    status = "BLOCKING_NOT_PROVEN"
    if evidence is not None:
        observed_status = str(evidence.get("status", "")).upper()
        exit_code = evidence.get("exit_code")
        source_bound, binding_detail = _execution_is_bound(evidence, ending, ending_tree, source)
        coverage_ok = True
        if exact_coverage is not None:
            try:
                coverage_path = _evidence_path(evidence["coverage_json"])
                entries = _raw_evidence_entries(evidence["execution"])
                coverage_entry = next(
                    (item for item in entries if _evidence_path(item.get("path")) == coverage_path),
                    None,
                )
                coverage_payload = _json(coverage_path) if coverage_path is not None else {}
                coverage_totals = coverage_payload.get("totals", coverage_payload)
                coverage_ok = (
                    coverage_path is not None
                    and coverage_entry is not None
                    and _valid_sha256(coverage_entry.get("sha256"))
                    and float(coverage_totals["percent_covered"]) == exact_coverage
                    and float(evidence["exact_coverage_percent"]) == exact_coverage
                )
            except (KeyError, TypeError, ValueError):
                coverage_ok = False
        if (
            observed_status in {"PASS", "PASSED", "SUCCESS"}
            and exit_code == 0
            and source_bound
            and coverage_ok
            and supplied_status in {None, "PASS", "SUCCESS"}
        ):
            status = "PASS"
        else:
            error = (
                "status, exit code, execution source binding, raw evidence, "
                f"or exact coverage did not validate: {binding_detail}"
            )
    return {
        "name": label,
        "status": status,
        "supplied_status": supplied_status,
        "exit_code": evidence.get("exit_code") if evidence else None,
        "revision": evidence.get("revision", evidence.get("head_sha")) if evidence else None,
        "tree": evidence.get("tree") if evidence else None,
        "exact_coverage_percent": (
            evidence.get("exact_coverage_percent") if evidence else exact_coverage
        ),
        "evidence_path": str(evidence_path) if evidence_path else None,
        "disposition": error or "independently validated",
    }


def _hosted_observation(
    arguments: argparse.Namespace, ending: str, evidence_path: Path | None
) -> dict[str, Any]:
    evidence: dict[str, Any] | None = None
    error: str | None = None
    if evidence_path is None:
        error = "independent hosted CI evidence was not supplied"
    else:
        try:
            evidence = _json(evidence_path)
        except (OSError, UnicodeError, ValueError) as exc:
            error = f"hosted CI evidence is unreadable: {type(exc).__name__}"
    required_names = (
        "quality",
        "deterministic_workflows",
        "deterministic_permissions",
        "v1_acceptance",
        "package_smoke",
    )
    observed_stages: dict[str, str] = {}
    raw_run: dict[str, Any] | None = None
    raw_detail = "hosted raw run evidence was not validated"
    if evidence is not None:
        raw_entries = evidence.get("raw_evidence")
        if isinstance(raw_entries, list) and len(raw_entries) == 1:
            raw_entry = raw_entries[0]
            if isinstance(raw_entry, dict):
                raw_path = _evidence_path(raw_entry.get("path"))
                raw_digest = raw_entry.get("sha256")
                if raw_path is not None and _valid_sha256(raw_digest) and raw_path.is_file():
                    try:
                        if _file_sha256(raw_path).casefold() == str(raw_digest).casefold():
                            raw_run = _json(raw_path)
                            raw_detail = "hosted raw run digest verified"
                    except (OSError, UnicodeError, ValueError):
                        raw_run = None
        observed_stages = _hosted_stage_statuses(raw_run) if raw_run is not None else {}
        run_ok = _hosted_run_matches(
            raw_run,
            required_names,
            arguments.hosted_ci_run_id,
            arguments.hosted_ci_attempt,
            ending,
            observed_stages,
        )
        if not run_ok:
            error = (
                "raw hosted event, attempt, checkout SHA, conclusion, run identity, or "
                f"stage results did not validate: {raw_detail}"
            )
    required = {
        "quality": arguments.hosted_quality,
        "deterministic_workflows": arguments.hosted_deterministic_workflows,
        "deterministic_permissions": arguments.hosted_deterministic_permissions,
        "v1_acceptance": arguments.hosted_v1_acceptance,
        "package_smoke": arguments.hosted_package_smoke,
    }
    if not observed_stages:
        observed_stages = {name: "NOT_PROVEN" for name in required}
    return {
        "run_id": arguments.hosted_ci_run_id,
        "event": evidence.get("event") if evidence else arguments.hosted_ci_event,
        "attempt": evidence.get("attempt") if evidence else arguments.hosted_ci_attempt,
        "head_sha": evidence.get("head_sha") if evidence else arguments.hosted_ci_head_sha,
        "conclusion": evidence.get("conclusion") if evidence else arguments.hosted_ci_conclusion,
        "required_stages": observed_stages,
        "status": "PASS" if evidence is not None and error is None else "BLOCKING_NOT_PROVEN",
        "evidence_path": str(evidence_path) if evidence_path else None,
        "disposition": error or "exact push checkout and required stages independently validated",
    }


_HOSTED_STEP_NAMES = {
    "quality": "Run quality gate",
    "deterministic_workflows": "Run deterministic system self-tests",
    "deterministic_permissions": "Run deterministic permission self-tests",
    "v1_acceptance": "Run v1 acceptance suite",
    "package_smoke": "Run artifact-only package smoke",
}


def _hosted_status(value: object) -> str:
    normalized = str(value or "").upper()
    if normalized in {"SUCCESS", "PASSED", "PASS"}:
        return "SUCCESS"
    if normalized in {"FAILURE", "FAILED", "CANCELLED", "TIMED_OUT", "ACTION_REQUIRED"}:
        return normalized
    if normalized in {"IN_PROGRESS", "RUNNING"}:
        return "IN_PROGRESS"
    if normalized in {"QUEUED", "PENDING", "WAITING"}:
        return "PENDING"
    return "NOT_PROVEN"


def _hosted_stage_statuses(raw: dict[str, Any] | None) -> dict[str, str]:
    if raw is None or not isinstance(raw.get("jobs"), list):
        return {}
    statuses = {name: "NOT_PROVEN" for name in _HOSTED_STEP_NAMES}
    for job in raw["jobs"]:
        if not isinstance(job, dict):
            continue
        job_status = _hosted_status(job.get("conclusion") or job.get("status"))
        steps = job.get("steps", [])
        if not isinstance(steps, list):
            steps = []
        for stage, step_name in _HOSTED_STEP_NAMES.items():
            matches = [
                step for step in steps if isinstance(step, dict) and step.get("name") == step_name
            ]
            if matches:
                step = matches[-1]
                statuses[stage] = _hosted_status(step.get("conclusion") or step.get("status"))
            elif str(job.get("name", "")).casefold() == stage.casefold():
                statuses[stage] = job_status
    return statuses


def _hosted_run_matches(
    raw: dict[str, Any] | None,
    required_names: tuple[str, ...],
    run_id: str,
    attempt: int,
    ending: str,
    stages: dict[str, str],
) -> bool:
    if raw is None:
        return False
    try:
        raw_attempt = int(raw.get("attempt", 0))
    except (TypeError, ValueError):
        return False
    observed_run_id = raw.get("databaseId", raw.get("run_id"))
    observed_sha = raw.get("headSha", raw.get("head_sha"))
    return (
        str(observed_run_id) == str(run_id)
        and str(raw.get("event")) == "push"
        and raw_attempt == int(attempt)
        and str(observed_sha) == ending
        and str(raw.get("conclusion", "")).upper() == "SUCCESS"
        and all(stages.get(name) == "SUCCESS" for name in required_names)
    )


def _historical_r1_ci_observation(path: Path | None) -> dict[str, Any]:
    if path is None:
        return {
            "status": "NOT_RECORDED",
            "evidence_path": None,
            "disposition": "later terminal disposition was not supplied",
        }
    try:
        raw = _json(path)
        digest = _file_sha256(path)
    except (OSError, UnicodeError, ValueError) as error:
        return {
            "status": "BLOCKING_NOT_PROVEN",
            "evidence_path": str(path),
            "disposition": f"historical terminal evidence is unreadable: {type(error).__name__}",
        }
    stages = _hosted_stage_statuses(raw)
    valid = _hosted_run_matches(
        raw,
        tuple(_HOSTED_STEP_NAMES),
        str(HISTORICAL_R1_CI["run_id"]),
        int(str(HISTORICAL_R1_CI["attempt"])),
        str(HISTORICAL_R1_CI["head_sha"]),
        stages,
    )
    return {
        "status": "SUCCESS" if valid else "BLOCKING_NOT_PROVEN",
        "run_id": raw.get("databaseId", raw.get("run_id")),
        "event": raw.get("event"),
        "attempt": raw.get("attempt"),
        "head_sha": raw.get("headSha", raw.get("head_sha")),
        "conclusion": raw.get("conclusion"),
        "required_stages": stages,
        "evidence_path": str(path),
        "evidence_sha256": digest,
        "disposition": (
            "historical R1 push checkout and all required stages independently validated"
            if valid
            else "historical event, checkout, conclusion, or stage evidence did not validate"
        ),
    }


def _scenario_observation(
    records: tuple[dict[str, Any], ...],
    names: tuple[str, ...],
    source: dict[str, Any],
    ending: str,
    tree: str,
) -> dict[str, Any]:
    matched = [record for record in records if record.get("name") in names]
    bound = [record for record in matched if _scenario_is_bound(record, ending, tree, source)]
    if any(_scenario_status(record, ending, tree, source) == "FAIL" for record in bound):
        status = "FAIL"
    elif (
        bound
        and len(bound) == len(matched)
        and all(_scenario_status(record, ending, tree, source) == "PASS" for record in bound)
    ):
        status = "PASS"
    else:
        status = "BLOCKING_NOT_PROVEN" if matched else "NOT_EXECUTED"
    return {
        "status": status,
        "test_scenario_identities": list(names),
        "source_identity": source,
        "revision": ending,
        "tree": tree,
        "evidence_references": [record.get("evidence_reference") for record in matched],
        "observed_outcomes": [record.get("observed_outcome") for record in matched],
    }


def _pre_fix_reproductions(path: Path | None) -> dict[str, Any]:
    if path is None:
        return {
            "status": "NOT_RECORDED",
            "evidence_path": None,
            "disposition": "pre-fix reproduction evidence was not supplied",
        }
    try:
        evidence = _json(path)
    except (OSError, UnicodeError, ValueError) as exc:
        return {
            "status": "BLOCKING_NOT_PROVEN",
            "evidence_path": str(path),
            "disposition": f"pre-fix evidence is unreadable: {type(exc).__name__}",
        }
    cases = evidence.get("cases")
    baseline = evidence.get("baseline", {})
    case_records = cases if isinstance(cases, list) else []
    valid_cases = bool(case_records)
    bound = (
        isinstance(baseline, dict)
        and baseline.get("sha") == BASELINE["sha"]
        and baseline.get("tree") == BASELINE["tree"]
    )
    statuses_valid = valid_cases and all(
        isinstance(case, dict)
        and case.get("observed_status") in {"FAIL", "PASS", "NOT_EXECUTED", "BLOCKING_NOT_PROVEN"}
        for case in case_records
    )
    return {
        "status": "RECORDED" if bound and statuses_valid else "BLOCKING_NOT_PROVEN",
        "evidence_path": str(path),
        "baseline": baseline,
        "cases": case_records,
        "disposition": (
            "observed against the exact R3B starting identity"
            if bound and statuses_valid
            else "baseline identity or executable case records did not validate"
        ),
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--system-evidence", type=Path, required=True)
    parser.add_argument("--exact-coverage", type=float, required=True)
    parser.add_argument("--ending-commit")
    parser.add_argument("--ending-parent")
    parser.add_argument("--ending-tree")
    parser.add_argument("--ending-branch")
    parser.add_argument("--pre-fix-evidence", type=Path)
    parser.add_argument("--scenario-evidence", type=Path)
    parser.add_argument("--scenario-provenance", type=Path)
    parser.add_argument("--scenario-revision")
    parser.add_argument("--scenario-tree")
    parser.add_argument("--test-strength-evidence", type=Path)
    parser.add_argument("--quality-evidence", type=Path)
    parser.add_argument("--package-evidence", type=Path)
    parser.add_argument("--test-strength")
    parser.add_argument("--quality")
    parser.add_argument("--package-smoke")
    parser.add_argument("--package-contamination")
    parser.add_argument("--hosted-ci-run-id", required=True)
    parser.add_argument("--hosted-ci-event")
    parser.add_argument("--hosted-ci-attempt", type=int, default=1)
    parser.add_argument("--hosted-ci-head-sha", required=True)
    parser.add_argument("--hosted-ci-conclusion")
    parser.add_argument("--hosted-quality")
    parser.add_argument("--hosted-deterministic-workflows")
    parser.add_argument("--hosted-deterministic-permissions")
    parser.add_argument("--hosted-v1-acceptance")
    parser.add_argument("--hosted-package-smoke")
    parser.add_argument("--hosted-evidence", type=Path)
    parser.add_argument("--historical-r1-ci-evidence", type=Path)
    parser.add_argument("--historical-ci-disposition", default="NON_TERMINAL")
    arguments = parser.parse_args()

    system = _json(arguments.system_evidence)
    ending = arguments.ending_commit or _git("rev-parse", "HEAD")
    ending_tree = arguments.ending_tree or _git("rev-parse", "HEAD^{tree}")
    ending_parent = (
        arguments.ending_parent
        if arguments.ending_parent is not None
        else (_git("rev-parse", "HEAD^") if ending != BASELINE["sha"] else None)
    )
    ending_branch = arguments.ending_branch or _git("branch", "--show-current")
    source = _source_identity()
    scenarios = _scenario_tests(
        arguments.scenario_evidence,
        supplied_revision=arguments.scenario_revision,
        supplied_tree=arguments.scenario_tree,
        provenance_path=arguments.scenario_provenance,
    )
    matrix = _acceptance_matrix(scenarios, source, ending, ending_tree)
    r1 = _r1_requirements(scenarios, source, ending, ending_tree)
    pre_fix = _pre_fix_reproductions(arguments.pre_fix_evidence)
    quality = _observed_gate(
        label="canonical_quality",
        supplied_status=arguments.quality,
        evidence_path=arguments.quality_evidence,
        ending=ending,
        ending_tree=ending_tree,
        source=source,
        exact_coverage=arguments.exact_coverage,
    )
    test_strength = _observed_gate(
        label="test_strength",
        supplied_status=arguments.test_strength,
        evidence_path=arguments.test_strength_evidence,
        ending=ending,
        ending_tree=ending_tree,
        source=source,
    )
    package = _observed_gate(
        label="package_smoke",
        supplied_status=arguments.package_smoke,
        evidence_path=arguments.package_evidence,
        ending=ending,
        ending_tree=ending_tree,
        source=source,
    )
    system_summary = _system_summary(system, arguments.system_evidence)
    system_source_bound, system_binding_detail = _execution_is_bound(
        system, ending, ending_tree, source
    )
    system_gate = {
        **system_summary,
        "status": (
            "PASS"
            if system.get("status") == "passed"
            and system.get("exit_code") == 0
            and system_source_bound
            else "BLOCKING_NOT_PROVEN"
        ),
        "disposition": (
            "independently validated"
            if system.get("status") == "passed"
            and system.get("exit_code") == 0
            and system_source_bound
            else (
                "status, exit code, or execution source binding did not validate: "
                f"{system_binding_detail}"
            )
        ),
    }
    hosted = _hosted_observation(arguments, ending, arguments.hosted_evidence)
    historical_r1_ci = _historical_r1_ci_observation(arguments.historical_r1_ci_evidence)
    all_r1_scenarios_pass = all(item["status"] == "PASS" for item in r1)
    all_gates_pass = all(
        item["status"] == "PASS" for item in (quality, test_strength, package, system_gate, hosted)
    )
    r1_status = (
        "COMPLETE"
        if all_r1_scenarios_pass and all_gates_pass and pre_fix["status"] == "RECORDED"
        else "STILL_BLOCKING"
    )
    r3b_requirements_pass = all(item["status"] == "PASS" for item in matrix)
    artifact: dict[str, Any] = {
        "schema": "v1-i-r3b-r1-file-transaction-truth-1",
        "canonical_system_stewardship_version": "V1-I-R3B-R1",
        "generated_at_utc": datetime.now(UTC).isoformat(),
        "baseline": {
            **BASELINE,
            "branch": ending_branch,
            "historical_ci_disposition": arguments.historical_ci_disposition,
            "historical_ci_run": 35260351999,
        },
        "historical_r1_ci": historical_r1_ci,
        "pre_fix_reproductions": pre_fix,
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
            "manifest_schema": "jarvis-file-mutation-manifest-2",
            "per_item_states": [
                "not_started",
                "effect_intent_persisted",
                "effect_may_have_started",
                "effect_verified",
                "failed_before_effect",
                "outcome_unresolved",
                "restoration_in_progress",
                "restoration_verified",
            ],
            "aggregate_completion_rule": "COMPLETED only when every item is effect_verified",
            "aggregate_restore_rule": "RESTORED only when every item is restoration_verified",
            "legacy_ambiguous_records": "migrate conservatively to UNKNOWN_OUTCOME",
            "preview_before_effect": True,
            "exact_scope_and_exclusions": True,
            "max_affected_bytes": True,
            "no_overwrite": True,
            "permission_broker_exact_fingerprint": True,
            "host_bridge_operation_binding": True,
            "fresh_path_hash_volume_identity": True,
            "active_use_fail_closed": True,
            "safe_delete_uses_recovery": True,
            "reversibility": {
                "copy": "partially_reversible",
                "safe_delete": "fully_reversible_with_verified_recovery",
                "move": "irreversible_without_a_reverse_transaction",
                "rename": "irreversible_without_a_reverse_transaction",
            },
        },
        "real_mutation_traces": {
            "test_module": "tests/test_storage_stewardship.py",
            "real_bytes": "derived from supplied scenario evidence",
            "acceptance_owned_temp_roots_only": True,
            "operations": {
                "copy": _scenario_observation(
                    scenarios,
                    (
                        "test_file_steward_real_copy_move_rename_delete_restore_and_manifest_restart",
                    ),
                    source,
                    ending,
                    ending_tree,
                ),
                "move": _scenario_observation(
                    scenarios,
                    (
                        "test_file_steward_real_copy_move_rename_delete_restore_and_manifest_restart",
                    ),
                    source,
                    ending,
                    ending_tree,
                ),
                "rename": _scenario_observation(
                    scenarios,
                    (
                        "test_file_steward_real_copy_move_rename_delete_restore_and_manifest_restart",
                    ),
                    source,
                    ending,
                    ending_tree,
                ),
                "safe_delete": _scenario_observation(
                    scenarios,
                    (
                        "test_file_steward_real_copy_move_rename_delete_restore_and_manifest_restart",
                    ),
                    source,
                    ending,
                    ending_tree,
                ),
                "restore": _scenario_observation(
                    scenarios,
                    (
                        "test_file_steward_real_copy_move_rename_delete_restore_and_manifest_restart",
                    ),
                    source,
                    ending,
                    ending_tree,
                ),
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
            "restore_phase_is_distinct": True,
            "restore_reconciliation_never_replays_delete": True,
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
            "executable_test_count": len(scenarios),
            "status": "PASS" if r3b_requirements_pass else "STILL_BLOCKING",
            "mapping_diagnostics": list(_matrix_mapping_diagnostics(scenarios)),
            "cases": matrix,
        },
        "r1_requirements": {
            "status": r1_status,
            "requirements": r1,
        },
        "test_strength": {
            **test_strength,
            "weakening_flags": "NO only when independently supplied evidence says so",
            "real_bytes": "evidence-derived",
            "fixture_marker_only_pass": False,
        },
        "standalone_v1_acceptance": system_gate,
        "canonical_quality": {
            **quality,
            "interpreter": (
                "C:\\Users\\jamie\\AppData\\Local\\Programs\\Python\\Python312\\python.exe"
            ),
            "command": "python scripts/quality.py",
            "exact_coverage_percent": arguments.exact_coverage,
            "threshold_percent": 90.0,
        },
        "package_smoke": {
            **package,
            "contamination": arguments.package_contamination or "NOT_PROVEN",
            "production_artifact_only": True,
        },
        "scenario_evidence": {
            "path": str(arguments.scenario_evidence) if arguments.scenario_evidence else None,
            "test_count": len(scenarios),
            "revision": arguments.scenario_revision,
            "declared_tree": arguments.scenario_tree,
            "source_bound": all(
                _scenario_is_bound(record, ending, ending_tree, source) for record in scenarios
            )
            if scenarios
            else False,
            "source_identity": source,
            "tree": ending_tree,
        },
        "fresh_source_identity": source,
        "ending_commit": {
            "sha": ending,
            "parent": ending_parent,
            "tree": ending_tree,
        },
        "hosted_ci": {
            **hosted,
        },
        "remaining_r3c_scope": (
            "V1-I-R3C SECURITY HEALTH / SOFTWARE / STARTUP / UPDATE COORDINATION"
        ),
        "candidate_15": "NOT_CREATED",
        "terminal": {
            "r3b_r1": r1_status,
            "storage_intelligence": "CLOSED" if r3b_requirements_pass else "STILL_BLOCKING",
            "recovery_aware_file_stewardship": "CLOSED"
            if r3b_requirements_pass
            else "STILL_BLOCKING",
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
