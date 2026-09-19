"""Adversarial tests for the v1 Trusted Core enforcement primitives."""

from __future__ import annotations

import asyncio
import base64
import hashlib
import os
import sys
from dataclasses import replace
from datetime import UTC, datetime, timedelta
from importlib.metadata import Distribution
from inspect import signature
from pathlib import Path
from typing import cast
from uuid import uuid4

import jarvis.security.startup as startup_security
import pytest
from jarvis.computer.models import CommandDefinition
from jarvis.computer.terminal import SubprocessCommandAdapter
from jarvis.core.config import Settings
from jarvis.core.errors import ToolRegistrationError
from jarvis.improvement.workspace import TrustedWorkspaceChangeApplier
from jarvis.permissions import SafetyClass, normalize_path
from jarvis.runtime import ApplicationRuntime, RuntimePaths, RuntimeStatus
from jarvis.security import (
    SECURITY_POLICY_VERSION,
    InstalledDistributionIntegrityEvidenceProvider,
    IntegrityClass,
    IntegrityClassificationError,
    IntegrityEvidenceError,
    MutationAuthority,
    MutationAuthorization,
    MutationAuthorizationSource,
    MutationAuthorizer,
    MutationContext,
    MutationPolicy,
    MutationReason,
    MutationStage,
    RepositoryIntegrityClassifier,
    SecurityViolationCode,
    SourceCheckoutIntegrityEvidenceProvider,
    StartupSecurityConfiguration,
    StartupSecurityValidator,
)
from jarvis.tools.calculator import CalculatorTool
from jarvis.tools.registry import ToolRegistry

_MUTATION_NOW = datetime(2026, 8, 16, tzinfo=UTC)
_BASE_REVISION = "a" * 40
_CANDIDATE_REVISION = "b" * 40
_DIFF_DIGEST = "c" * 64
_GATE_REPORT_DIGEST = "d" * 64


@pytest.mark.parametrize(
    ("path", "expected"),
    [
        ("jarvis/security/integrity.py", IntegrityClass.TRUSTED_CORE),
        ("jarvis/permissions/broker.py", IntegrityClass.TRUSTED_CORE),
        ("jarvis/tools/base.py", IntegrityClass.TRUSTED_CORE),
        ("jarvis/api.py", IntegrityClass.TRUSTED_CORE),
        ("jarvis/core/health.py", IntegrityClass.TRUSTED_CORE),
        ("docs/security-constitution.md", IntegrityClass.TRUSTED_CORE),
        ("jarvis/computer/tools.py", IntegrityClass.PRODUCTION_CORE),
        ("integrations/calendar/manifest.json", IntegrityClass.INTEGRATION),
        ("knowledge/generated/project-index.json", IntegrityClass.GENERATED),
        ("config/user.json", IntegrityClass.USER_CONFIG),
        ("data/tasks.sqlite3", IntegrityClass.DATA),
    ],
)
def test_integrity_classifier_uses_compiled_manifest(
    path: str,
    expected: IntegrityClass,
) -> None:
    assert RepositoryIntegrityClassifier().classify(path).integrity_class is expected


def test_source_integrity_evidence_fails_closed_when_repository_files_are_missing(
    tmp_path: Path,
) -> None:
    with pytest.raises(IntegrityEvidenceError):
        SourceCheckoutIntegrityEvidenceProvider(tmp_path / "missing-source").validate()


class _FakeDistribution:
    """A local installed-wheel layout; never a source-resource substitute."""

    def __init__(self, root: Path, version: str = "1.0.0") -> None:
        self.root = root
        self.version = version

    def locate_file(self, path: object) -> Path:
        raw = str(path).replace("\\", "/")
        return self.root if raw in {"", "."} else self.root.joinpath(*raw.split("/"))


def _record_digest(content: bytes) -> str:
    return base64.urlsafe_b64encode(hashlib.sha256(content).digest()).rstrip(b"=").decode("ascii")


def _write_test_record(root: Path, rows: list[tuple[str, str, str]] | None = None) -> Path:
    record = root / "jarvis-1.0.0.dist-info" / "RECORD"
    if rows is None:
        rows = []
        for path in sorted(root.rglob("*")):
            if not path.is_file() or path == record:
                continue
            content = path.read_bytes()
            rows.append(
                (
                    path.relative_to(root).as_posix(),
                    f"sha256={_record_digest(content)}",
                    str(len(content)),
                )
            )
        rows.append((record.relative_to(root).as_posix(), "", ""))
    record.write_text("\n".join(",".join(row) for row in rows) + "\n", encoding="utf-8")
    return record


def _installed_test_distribution(tmp_path: Path) -> tuple[_FakeDistribution, Path]:
    root = tmp_path / "site-packages"
    contents = {
        "jarvis/api.py": "api = 1\n",
        "jarvis/improvement/workspace.py": "workspace = 1\n",
        "jarvis/permissions/broker.py": "broker = 1\n",
        "jarvis/recovery.py": "recovery = 1\n",
        "jarvis/runtime.py": "runtime = 1\n",
        "jarvis/security/integrity.py": "integrity = 1\n",
        "jarvis/security/startup.py": "startup = 1\n",
        "jarvis/tools/base.py": "base = 1\n",
        "jarvis/noncritical.py": "ordinary = 1\n",
        "jarvis-1.0.0.dist-info/METADATA": "Name: jarvis\nVersion: 1.0.0\n",
        "jarvis-1.0.0.dist-info/WHEEL": "Wheel-Version: 1.0\n",
        "jarvis-1.0.0.dist-info/top_level.txt": "jarvis\n",
        "jarvis-1.0.0.dist-info/INSTALLER": "pip\n",
        "jarvis-1.0.0.dist-info/REQUESTED": "",
        "jarvis-1.0.0.dist-info/licenses/LICENSE.txt": "license\n",
    }
    for relative, content in contents.items():
        path = root / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(content, encoding="utf-8")
    _write_test_record(root)
    return _FakeDistribution(root), root


def _installed_provider(
    distribution: _FakeDistribution,
) -> InstalledDistributionIntegrityEvidenceProvider:
    return InstalledDistributionIntegrityEvidenceProvider(
        lambda _name: cast(Distribution, distribution)
    )


def _replace_record_row(record: Path, relative: str, replacement: str) -> None:
    rows = record.read_text(encoding="utf-8").splitlines()
    record.write_text(
        "\n".join(replacement if row.startswith(f"{relative},") else row for row in rows) + "\n",
        encoding="utf-8",
    )


def test_installed_integrity_evidence_validates_complete_wheel_inventory(tmp_path: Path) -> None:
    distribution, _root = _installed_test_distribution(tmp_path)

    _installed_provider(distribution).validate()


@pytest.mark.parametrize(
    "relative",
    (
        "jarvis/security/integrity.py",
        "jarvis/noncritical.py",
        "jarvis-1.0.0.dist-info/METADATA",
        "jarvis-1.0.0.dist-info/WHEEL",
        "jarvis-1.0.0.dist-info/top_level.txt",
        "jarvis-1.0.0.dist-info/INSTALLER",
        "jarvis-1.0.0.dist-info/licenses/LICENSE.txt",
    ),
)
def test_installed_integrity_evidence_detects_any_recorded_member_mutation(
    tmp_path: Path,
    relative: str,
) -> None:
    distribution, root = _installed_test_distribution(tmp_path)
    (root / relative).write_text("tampered\n", encoding="utf-8")

    with pytest.raises(IntegrityEvidenceError):
        _installed_provider(distribution).validate()


def test_installed_integrity_evidence_rejects_installer_record_tamper_with_startup_policy(
    tmp_path: Path,
) -> None:
    distribution, root = _installed_test_distribution(tmp_path)
    record = root / "jarvis-1.0.0.dist-info" / "RECORD"
    _replace_record_row(
        record,
        "jarvis-1.0.0.dist-info/INSTALLER",
        "jarvis-1.0.0.dist-info/INSTALLER,sha256=" + "A" * 43 + ",4",
    )

    with pytest.raises(IntegrityEvidenceError):
        _installed_provider(distribution).validate()
    report = StartupSecurityValidator(_installed_provider(distribution)).validate(
        _startup_config(tmp_path)
    )
    assert SecurityViolationCode.POLICY_CLASSIFICATION_INVALID in {
        violation.code for violation in report.violations
    }


@pytest.mark.parametrize(
    "mutation",
    (
        "remove_recorded_member",
        "add_unrecorded_member",
        "remove_record_row",
        "fake_record_row",
        "duplicate_record_row",
        "size_tamper",
        "unsafe_record_path",
        "malformed_digest",
        "hashless_regular_member",
        "bad_record_self",
    ),
)
def test_installed_integrity_evidence_rejects_complete_inventory_tampering(
    tmp_path: Path,
    mutation: str,
) -> None:
    distribution, root = _installed_test_distribution(tmp_path)
    record = root / "jarvis-1.0.0.dist-info" / "RECORD"
    baseline = record.read_text(encoding="utf-8")
    if mutation == "remove_recorded_member":
        (root / "jarvis/noncritical.py").unlink()
    elif mutation == "add_unrecorded_member":
        (root / "jarvis/extra.py").write_text("extra\n", encoding="utf-8")
    elif mutation == "remove_record_row":
        record.write_text(
            "\n".join(line for line in baseline.splitlines() if "noncritical.py" not in line),
            encoding="utf-8",
        )
    elif mutation == "fake_record_row":
        record.write_text(
            baseline + "jarvis/fake.py,sha256=" + _record_digest(b"fake") + ",4\n", encoding="utf-8"
        )
    elif mutation == "duplicate_record_row":
        line = next(line for line in baseline.splitlines() if "noncritical.py" in line)
        record.write_text(baseline + line.replace("/", "\\", 1) + "\n", encoding="utf-8")
    elif mutation == "size_tamper":
        row = next(line for line in baseline.splitlines() if "INSTALLER" in line)
        record.write_text(
            baseline.replace(row, row.rsplit(",", 1)[0] + ",999999"), encoding="utf-8"
        )
    elif mutation == "unsafe_record_path":
        record.write_text(
            baseline + "../outside.py,sha256=" + _record_digest(b"x") + ",1\n", encoding="utf-8"
        )
    elif mutation == "malformed_digest":
        record.write_text(baseline.replace("sha256=", "sha512=", 1), encoding="utf-8")
    elif mutation == "hashless_regular_member":
        _replace_record_row(record, "jarvis/noncritical.py", "jarvis/noncritical.py,,")
    else:
        record.write_text(
            baseline.replace(
                "jarvis-1.0.0.dist-info/RECORD,,",
                "jarvis-1.0.0.dist-info/RECORD,sha256=" + _record_digest(b"self") + ",4",
            ),
            encoding="utf-8",
        )

    with pytest.raises(IntegrityEvidenceError):
        _installed_provider(distribution).validate()


def test_installed_integrity_evidence_handles_bounded_optional_pyc_only(tmp_path: Path) -> None:
    distribution, root = _installed_test_distribution(tmp_path)
    cache = root / "jarvis" / "__pycache__"
    cache.mkdir()
    (cache / "noncritical.cpython-312.pyc").write_bytes(b"bytecode")
    _installed_provider(distribution).validate()

    (cache / "unknown.cpython-312.pyc").write_bytes(b"bytecode")
    with pytest.raises(IntegrityEvidenceError):
        _installed_provider(distribution).validate()


def test_installed_integrity_evidence_missing_record_fails_closed(tmp_path: Path) -> None:
    distribution, root = _installed_test_distribution(tmp_path)
    (root / "jarvis-1.0.0.dist-info" / "RECORD").unlink()

    with pytest.raises(IntegrityEvidenceError):
        _installed_provider(distribution).validate()


@pytest.mark.parametrize(
    "unsafe_path",
    (
        "../outside.py",
        "/absolute.py",
        r"\\server\share\file.py",
        "C:/Windows/system.py",
        "jarvis/NUL.py",
        "jarvis/file.py:stream",
    ),
)
def test_installed_integrity_evidence_rejects_unsafe_record_paths(
    tmp_path: Path,
    unsafe_path: str,
) -> None:
    distribution, root = _installed_test_distribution(tmp_path)
    record = root / "jarvis-1.0.0.dist-info" / "RECORD"
    record.write_text(
        record.read_text(encoding="utf-8") + f"{unsafe_path},sha256={_record_digest(b'x')},1\n",
        encoding="utf-8",
    )

    with pytest.raises(IntegrityEvidenceError):
        _installed_provider(distribution).validate()


def test_installed_integrity_evidence_version_or_dist_info_ambiguity_fails_closed(
    tmp_path: Path,
) -> None:
    distribution, root = _installed_test_distribution(tmp_path)
    mismatch = _FakeDistribution(root, "9.9.9")
    with pytest.raises(IntegrityEvidenceError):
        _installed_provider(mismatch).validate()

    duplicate = root / "jarvis-copy.dist-info"
    duplicate.mkdir()
    (duplicate / "METADATA").write_text("Name: jarvis\nVersion: 1.0.0\n", encoding="utf-8")
    with pytest.raises(IntegrityEvidenceError):
        _installed_provider(distribution).validate()


@pytest.mark.parametrize(
    "failure",
    (ImportError, KeyError, OSError, TypeError, ValueError, UnicodeError),
)
def test_installed_integrity_loader_failures_fail_closed(
    failure: type[Exception],
) -> None:
    def load(_name: str) -> Distribution:
        raise failure("synthetic loader failure")

    provider = InstalledDistributionIntegrityEvidenceProvider(load)

    with pytest.raises(IntegrityEvidenceError, match="malformed"):
        provider.validate()


@pytest.mark.parametrize(
    "record_text",
    (
        "",
        "jarvis/noncritical.py,sha256=x\n",
        "jarvis/noncritical.py,sha256=A,1\n",
        "jarvis/noncritical.py,sha256=" + "A" * 43 + ",not-a-size\n",
        "jarvis/noncritical.py,sha256=" + "A" * 43 + ",-1\n",
    ),
)
def test_installed_integrity_rejects_malformed_record_integrity_fields(
    tmp_path: Path,
    record_text: str,
) -> None:
    distribution, root = _installed_test_distribution(tmp_path)
    record = root / "jarvis-1.0.0.dist-info" / "RECORD"
    record.write_text(record_text, encoding="utf-8")

    with pytest.raises(IntegrityEvidenceError):
        _installed_provider(distribution).validate()


def test_installed_integrity_rejects_unreadable_metadata(tmp_path: Path) -> None:
    distribution, root = _installed_test_distribution(tmp_path)
    (root / "jarvis-1.0.0.dist-info" / "METADATA").write_bytes(b"Name: \xff\n")

    with pytest.raises(IntegrityEvidenceError, match="unreadable"):
        _installed_provider(distribution).validate()


def test_installed_integrity_rejects_package_file_instead_of_directory(tmp_path: Path) -> None:
    distribution, root = _installed_test_distribution(tmp_path)
    package = root / "jarvis"
    package.rename(root / "jarvis-tree")
    package.write_text("not a package directory\n", encoding="utf-8")

    with pytest.raises(IntegrityEvidenceError, match="invalid"):
        _installed_provider(distribution).validate()


def test_installed_integrity_rejects_unsafe_installed_root(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    distribution, root = _installed_test_distribution(tmp_path)
    real_root = root.resolve()
    monkeypatch.setattr(
        startup_security,
        "_is_reparse_point",
        lambda path: path.resolve() == real_root,
    )

    with pytest.raises(IntegrityEvidenceError, match="root is unsafe"):
        _installed_provider(distribution).validate()


def test_installed_integrity_rejects_record_external_reference(tmp_path: Path) -> None:
    distribution, root = _installed_test_distribution(tmp_path)
    record = root / "jarvis-1.0.0.dist-info" / "RECORD"
    baseline = record.read_text(encoding="utf-8")
    record.write_text(
        baseline + "other-package/file.py,sha256=" + _record_digest(b"x") + ",1\n",
        encoding="utf-8",
    )

    with pytest.raises(IntegrityEvidenceError, match="external path"):
        _installed_provider(distribution).validate()


def test_installed_integrity_rejects_missing_installed_root(tmp_path: Path) -> None:
    distribution = _FakeDistribution(tmp_path / "missing-site-packages")

    with pytest.raises(IntegrityEvidenceError, match="root is unavailable"):
        _installed_provider(distribution).validate()


def test_installed_integrity_rejects_missing_metadata(tmp_path: Path) -> None:
    distribution, root = _installed_test_distribution(tmp_path)
    (root / "jarvis-1.0.0.dist-info" / "METADATA").unlink()

    with pytest.raises(IntegrityEvidenceError, match="dist-info is ambiguous"):
        _installed_provider(distribution).validate()


def test_installed_integrity_rejects_missing_package_directory(tmp_path: Path) -> None:
    distribution, root = _installed_test_distribution(tmp_path)
    (root / "jarvis").rename(root / "jarvis-tree")

    with pytest.raises(IntegrityEvidenceError, match="package directory is ambiguous"):
        _installed_provider(distribution).validate()


def test_installed_integrity_allows_missing_recorded_optional_pyc(tmp_path: Path) -> None:
    distribution, root = _installed_test_distribution(tmp_path)
    record = root / "jarvis-1.0.0.dist-info" / "RECORD"
    baseline = record.read_text(encoding="utf-8")
    pyc = "jarvis/__pycache__/noncritical.cpython-312.pyc"
    record.write_text(
        baseline + f"{pyc},sha256={_record_digest(b'bytecode')},8\n",
        encoding="utf-8",
    )

    _installed_provider(distribution).validate()


def test_installed_integrity_rejects_unrelated_pyc_name(tmp_path: Path) -> None:
    distribution, root = _installed_test_distribution(tmp_path)
    cache = root / "jarvis" / "__pycache__"
    cache.mkdir()
    (cache / ".pyc").write_bytes(b"bytecode")

    with pytest.raises(IntegrityEvidenceError, match="unrecorded member"):
        _installed_provider(distribution).validate()


def test_installed_integrity_rejects_reparse_child(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    distribution, root = _installed_test_distribution(tmp_path)
    package = root / "jarvis"
    real_is_reparse = startup_security._is_reparse_point
    monkeypatch.setattr(
        startup_security,
        "_is_reparse_point",
        lambda path: path == package or real_is_reparse(path),
    )

    with pytest.raises(IntegrityEvidenceError, match="reparse point"):
        _installed_provider(distribution).validate()


def test_installed_integrity_rejects_member_read_failure(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    distribution, root = _installed_test_distribution(tmp_path)
    real_read_bytes = Path.read_bytes
    target = root / "jarvis" / "noncritical.py"

    def fail_target(path: Path) -> bytes:
        if path == target:
            raise OSError("synthetic read failure")
        return real_read_bytes(path)

    monkeypatch.setattr(Path, "read_bytes", fail_target)

    with pytest.raises(IntegrityEvidenceError, match="malformed"):
        _installed_provider(distribution).validate()


def test_source_integrity_rejects_a_file_as_checkout_root(tmp_path: Path) -> None:
    root = tmp_path / "checkout"
    root.write_text("not a directory\n", encoding="utf-8")

    with pytest.raises(IntegrityEvidenceError, match="unsafe"):
        SourceCheckoutIntegrityEvidenceProvider(root).validate()


def test_source_integrity_rejects_missing_required_evidence(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    root = tmp_path / "checkout"
    root.mkdir()
    monkeypatch.setattr(
        startup_security, "_SOURCE_INTEGRITY_FILES", ("jarvis/security/startup.py",)
    )

    with pytest.raises(IntegrityEvidenceError, match="missing"):
        SourceCheckoutIntegrityEvidenceProvider(root).validate()


def test_source_integrity_rejects_non_trusted_classification(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    root = tmp_path / "checkout"
    evidence = root / "jarvis" / "security" / "startup.py"
    evidence.parent.mkdir(parents=True)
    evidence.write_text("startup = 1\n", encoding="utf-8")
    monkeypatch.setattr(
        startup_security, "_SOURCE_INTEGRITY_FILES", ("jarvis/security/startup.py",)
    )

    class _NonTrustedClassifier:
        def classify(self, _path: str) -> object:
            class _Classification:
                class _Class:
                    value = "production_core"

                integrity_class = _Class()

            return _Classification()

    monkeypatch.setattr(startup_security, "RepositoryIntegrityClassifier", _NonTrustedClassifier)

    with pytest.raises(IntegrityEvidenceError, match="trusted core"):
        SourceCheckoutIntegrityEvidenceProvider(root).validate()


def test_startup_validator_rejects_invalid_integrity_provider() -> None:
    with pytest.raises(ValueError, match="provider is invalid"):
        StartupSecurityValidator(object())  # type: ignore[arg-type]


def test_startup_validator_fails_closed_on_policy_and_capability_flags(tmp_path: Path) -> None:
    changes: dict[str, object] = {"policy_version": SECURITY_POLICY_VERSION + 1}
    changes.update({field_name: True for field_name, _code in StartupSecurityValidator._FLAG_CODES})
    config = _startup_config(tmp_path, **changes)
    report = StartupSecurityValidator().validate(config)

    codes = {violation.code for violation in report.violations}
    assert SecurityViolationCode.POLICY_VERSION_UNSUPPORTED in codes
    assert all(code in codes for _field, code in StartupSecurityValidator._FLAG_CODES)


@pytest.mark.parametrize(
    "endpoint",
    ("http://127.0.0.1:not-a-port", "http://127.0.0.1:0", "http://127.0.0.1:65536"),
)
def test_startup_validator_rejects_malformed_model_endpoint(
    tmp_path: Path,
    endpoint: str,
) -> None:
    report = StartupSecurityValidator().validate(_startup_config(tmp_path, ai_endpoint=endpoint))

    assert SecurityViolationCode.MODEL_ENDPOINT_NOT_LOCAL in {
        violation.code for violation in report.violations
    }


@pytest.mark.parametrize(
    "path",
    [
        "../jarvis/security.py",
        "jarvis//security.py",
        "jarvis\\security.py",
        "C:/Windows/System32/file.py",
        "//server/share/file.py",
        "jarvis/file.py:stream",
        "jarvis/NUL/file.py",
        "jarvis/CONIN$/file.py",
        "jarvis/CONOUT$.txt",
        "jarvis/CLOCK$/file.py",
        "jarvis/bad<name.py",
        "jarvis/bad>name.py",
        'jarvis/bad"name.py',
        "jarvis/bad|name.py",
        "jarvis/bad?name.py",
        "jarvis/bad*name.py",
    ],
)
def test_ambiguous_repository_paths_fail_closed(path: str) -> None:
    with pytest.raises(IntegrityClassificationError):
        RepositoryIntegrityClassifier().classify(path)


def test_unknown_paths_and_generated_executables_fail_closed() -> None:
    policy = MutationPolicy()
    context = MutationContext(
        MutationAuthority.ROUTINE_IMPROVEMENT,
        MutationStage.PRODUCTION_APPLY,
    )
    assert policy.evaluate("unknown-area/file.txt", context).reason is MutationReason.UNKNOWN_PATH
    assert (
        policy.evaluate("knowledge/generated/startup.py", context).reason
        is MutationReason.MALFORMED_PATH
    )


@pytest.mark.parametrize(
    "path",
    [
        r"\\server\share\file.txt",
        r"\\?\C:\Windows\file.txt",
        r"\\.\PhysicalDrive0",
        r"C:\safe\file.txt:alternate-stream",
        r"C:\safe\\ambiguous.txt",
        r"C:\safe\NUL.txt",
    ],
)
def test_permission_paths_reject_remote_device_and_ads_forms(path: str) -> None:
    with pytest.raises(ValueError):
        normalize_path(path)


def test_routine_improvement_cannot_modify_trusted_or_production_core() -> None:
    policy = MutationPolicy()
    production = MutationContext(
        MutationAuthority.ROUTINE_IMPROVEMENT,
        MutationStage.PRODUCTION_APPLY,
        full_gates_passed=True,
    )

    assert not policy.evaluate("jarvis/permissions/broker.py", production).allowed
    assert not policy.evaluate("jarvis/computer/tools.py", production).allowed
    assert not policy.evaluate("integrations/calendar/manifest.json", production).allowed
    assert not policy.evaluate("knowledge/generated/project-index.json", production).allowed


def test_controlled_and_owner_release_paths_are_separate() -> None:
    authorizer = MutationAuthorizer(
        "owner-1",
        MutationAuthorizationSource.OWNER_LOCAL_RELEASE,
        clock=lambda: _MUTATION_NOW,
    )
    policy = MutationPolicy(authorizer)
    task_id = uuid4()
    update_authority = authorizer.issue(
        authority=MutationAuthority.CONTROLLED_UPDATE,
        path="jarvis/planning/engine.py",
        task_id=task_id,
        base_revision=_BASE_REVISION,
        candidate_revision=_CANDIDATE_REVISION,
        diff_digest=_DIFF_DIGEST,
        gate_report_digest=_GATE_REPORT_DIGEST,
    )
    controlled_without_gates = MutationContext(
        MutationAuthority.CONTROLLED_UPDATE,
        MutationStage.PRODUCTION_APPLY,
        task_id=task_id,
        base_revision=_BASE_REVISION,
        candidate_revision=_CANDIDATE_REVISION,
        diff_digest=_DIFF_DIGEST,
        gate_report_digest=_GATE_REPORT_DIGEST,
        authorization=update_authority,
    )
    controlled = MutationContext(
        MutationAuthority.CONTROLLED_UPDATE,
        MutationStage.PRODUCTION_APPLY,
        full_gates_passed=True,
        task_id=task_id,
        base_revision=_BASE_REVISION,
        candidate_revision=_CANDIDATE_REVISION,
        diff_digest=_DIFF_DIGEST,
        gate_report_digest=_GATE_REPORT_DIGEST,
        authorization=update_authority,
    )
    release_authority = authorizer.issue(
        authority=MutationAuthority.OWNER_SECURITY_RELEASE,
        path="jarvis/permissions/broker.py",
        task_id=task_id,
        base_revision=_BASE_REVISION,
        candidate_revision=_CANDIDATE_REVISION,
        diff_digest=_DIFF_DIGEST,
        gate_report_digest=_GATE_REPORT_DIGEST,
    )
    owner_release = MutationContext(
        MutationAuthority.OWNER_SECURITY_RELEASE,
        MutationStage.PRODUCTION_APPLY,
        full_gates_passed=True,
        task_id=task_id,
        base_revision=_BASE_REVISION,
        candidate_revision=_CANDIDATE_REVISION,
        diff_digest=_DIFF_DIGEST,
        gate_report_digest=_GATE_REPORT_DIGEST,
        authorization=release_authority,
    )

    assert not policy.evaluate("jarvis/planning/engine.py", controlled_without_gates).allowed
    assert not policy.evaluate(
        "jarvis/computer/tools.py",
        controlled,
    ).allowed
    assert policy.evaluate("jarvis/planning/engine.py", controlled).allowed
    assert not policy.evaluate("jarvis/planning/engine.py", controlled).allowed
    assert not policy.evaluate("jarvis/permissions/broker.py", controlled).allowed
    assert policy.evaluate("jarvis/permissions/broker.py", owner_release).allowed


def _controlled_mutation_context(authorizer: MutationAuthorizer) -> MutationContext:
    task_id = uuid4()
    authorization = authorizer.issue(
        authority=MutationAuthority.CONTROLLED_UPDATE,
        path="jarvis/planning/engine.py",
        task_id=task_id,
        base_revision=_BASE_REVISION,
        candidate_revision=_CANDIDATE_REVISION,
        diff_digest=_DIFF_DIGEST,
        gate_report_digest=_GATE_REPORT_DIGEST,
    )
    return MutationContext(
        MutationAuthority.CONTROLLED_UPDATE,
        MutationStage.PRODUCTION_APPLY,
        full_gates_passed=True,
        task_id=task_id,
        base_revision=_BASE_REVISION,
        candidate_revision=_CANDIDATE_REVISION,
        diff_digest=_DIFF_DIGEST,
        gate_report_digest=_GATE_REPORT_DIGEST,
        authorization=authorization,
    )


def test_mutation_authorization_binds_every_release_and_gate_field() -> None:
    authorizer = MutationAuthorizer(
        "update-service",
        MutationAuthorizationSource.TRUSTED_UPDATE_SERVICE,
        clock=lambda: _MUTATION_NOW,
    )
    policy = MutationPolicy(authorizer)
    context = _controlled_mutation_context(authorizer)
    tampered_contexts = (
        replace(context, task_id=uuid4()),
        replace(context, base_revision="e" * 40),
        replace(context, candidate_revision="e" * 40),
        replace(context, diff_digest="e" * 64),
        replace(context, gate_report_digest="e" * 64),
    )

    for tampered in tampered_contexts:
        assert not policy.evaluate("jarvis/planning/engine.py", tampered).allowed
    assert policy.evaluate("jarvis/planning/engine.py", context).allowed


def test_mutation_authorization_binds_owner_identity_and_source() -> None:
    authorizer = MutationAuthorizer(
        "update-service",
        MutationAuthorizationSource.TRUSTED_UPDATE_SERVICE,
        clock=lambda: _MUTATION_NOW,
    )
    policy = MutationPolicy(authorizer)
    context = _controlled_mutation_context(authorizer)
    assert context.authorization is not None

    forged_identity = replace(context.authorization, identity_id="forged-owner")
    forged_source = replace(
        context.authorization,
        source=MutationAuthorizationSource.OWNER_LOCAL_RELEASE,
    )

    assert not policy.evaluate(
        "jarvis/planning/engine.py",
        replace(context, authorization=forged_identity),
    ).allowed
    assert not policy.evaluate(
        "jarvis/planning/engine.py",
        replace(context, authorization=forged_source),
    ).allowed
    assert policy.evaluate("jarvis/planning/engine.py", context).allowed


def test_malformed_mutation_metadata_fails_closed() -> None:
    def make_authorization(**changes: object) -> MutationAuthorization:
        values: dict[str, object] = {
            "authorization_id": uuid4(),
            "authority": MutationAuthority.CONTROLLED_UPDATE,
            "path": "jarvis/planning/engine.py",
            "task_id": uuid4(),
            "base_revision": _BASE_REVISION,
            "candidate_revision": _CANDIDATE_REVISION,
            "diff_digest": _DIFF_DIGEST,
            "gate_report_digest": _GATE_REPORT_DIGEST,
            "identity_id": "owner-1",
            "source": MutationAuthorizationSource.TRUSTED_UPDATE_SERVICE,
            "issued_at": _MUTATION_NOW,
            "expires_at": _MUTATION_NOW + timedelta(minutes=1),
            "authentication_tag": "0" * 64,
        }
        values.update(changes)
        return MutationAuthorization(**values)  # type: ignore[arg-type]

    with pytest.raises(ValueError, match="metadata is malformed"):
        make_authorization(identity_id="owner\nforged")
    with pytest.raises(ValueError, match="metadata is malformed"):
        make_authorization(path="../jarvis/planning/engine.py")

    authorizer = MutationAuthorizer(
        "update-service",
        MutationAuthorizationSource.TRUSTED_UPDATE_SERVICE,
        clock=lambda: _MUTATION_NOW,
    )
    context = _controlled_mutation_context(authorizer)
    assert (
        not MutationPolicy(authorizer)
        .evaluate(
            "jarvis/planning/engine.py",
            replace(context, authorization=object()),  # type: ignore[arg-type]
        )
        .allowed
    )


def test_mutation_authorization_rejects_forged_record_without_consuming_original() -> None:
    authorizer = MutationAuthorizer(
        "update-service",
        MutationAuthorizationSource.TRUSTED_UPDATE_SERVICE,
        clock=lambda: _MUTATION_NOW,
    )
    policy = MutationPolicy(authorizer)
    context = _controlled_mutation_context(authorizer)
    assert context.authorization is not None
    forged = replace(context.authorization, authentication_tag="0" * 64)

    assert not policy.evaluate(
        "jarvis/planning/engine.py",
        replace(context, authorization=forged),
    ).allowed
    assert policy.evaluate("jarvis/planning/engine.py", context).allowed


def test_mutation_authorization_expires_and_cannot_cross_authorizer_restart() -> None:
    current_time = [_MUTATION_NOW]

    def clock() -> datetime:
        return current_time[0]

    authorizer = MutationAuthorizer(
        "update-service",
        MutationAuthorizationSource.TRUSTED_UPDATE_SERVICE,
        ttl_seconds=1,
        clock=clock,
    )
    expired_context = _controlled_mutation_context(authorizer)
    current_time[0] += timedelta(seconds=2)

    assert (
        not MutationPolicy(authorizer)
        .evaluate("jarvis/planning/engine.py", expired_context)
        .allowed
    )

    current_time[0] = _MUTATION_NOW
    live_authorizer = MutationAuthorizer(
        "update-service",
        MutationAuthorizationSource.TRUSTED_UPDATE_SERVICE,
        clock=clock,
    )
    pre_restart_context = _controlled_mutation_context(live_authorizer)
    restarted_authorizer = MutationAuthorizer(
        "update-service",
        MutationAuthorizationSource.TRUSTED_UPDATE_SERVICE,
        clock=clock,
    )

    assert (
        not MutationPolicy(restarted_authorizer)
        .evaluate("jarvis/planning/engine.py", pre_restart_context)
        .allowed
    )
    assert (
        MutationPolicy(live_authorizer)
        .evaluate("jarvis/planning/engine.py", pre_restart_context)
        .allowed
    )


def test_mutation_authorization_requires_a_sha256_gate_report_digest() -> None:
    authorizer = MutationAuthorizer(
        "update-service",
        MutationAuthorizationSource.TRUSTED_UPDATE_SERVICE,
        clock=lambda: _MUTATION_NOW,
    )

    with pytest.raises(ValueError, match="trusted release scope"):
        authorizer.issue(
            authority=MutationAuthority.CONTROLLED_UPDATE,
            path="jarvis/planning/engine.py",
            task_id=uuid4(),
            base_revision=_BASE_REVISION,
            candidate_revision=_CANDIDATE_REVISION,
            diff_digest=_DIFF_DIGEST,
            gate_report_digest="not-a-digest",
        )


def test_mutation_authorizer_cannot_mint_routine_or_owner_authority_from_wrong_source() -> None:
    update_service = MutationAuthorizer(
        "update-service",
        MutationAuthorizationSource.TRUSTED_UPDATE_SERVICE,
        clock=lambda: _MUTATION_NOW,
    )
    task_id = uuid4()

    with pytest.raises(ValueError, match="trusted release scope"):
        update_service.issue(
            authority=MutationAuthority.ROUTINE_IMPROVEMENT,
            path="integrations/calendar/manifest.json",
            task_id=task_id,
            base_revision=_BASE_REVISION,
            candidate_revision=_CANDIDATE_REVISION,
            diff_digest=_DIFF_DIGEST,
            gate_report_digest=_GATE_REPORT_DIGEST,
        )
    with pytest.raises(ValueError, match="trusted release scope"):
        update_service.issue(
            authority=MutationAuthority.OWNER_SECURITY_RELEASE,
            path="jarvis/permissions/broker.py",
            task_id=task_id,
            base_revision=_BASE_REVISION,
            candidate_revision=_CANDIDATE_REVISION,
            diff_digest=_DIFF_DIGEST,
            gate_report_digest=_GATE_REPORT_DIGEST,
        )


def test_improvement_change_applier_has_no_mutation_policy_injection_port() -> None:
    assert tuple(signature(TrustedWorkspaceChangeApplier).parameters) == ("manager",)


def _startup_config(root: Path, **changes: object) -> StartupSecurityConfiguration:
    values: dict[str, object] = {
        "policy_version": 1,
        "app_data_dir": root,
        "project_root": Path(__file__).resolve().parents[2],
        "ai_provider": "ollama",
        "ai_endpoint": "http://127.0.0.1:11434",
        "computer_enabled": False,
        "camera_enabled": False,
        "application_management_enabled": False,
        "package_installation_enabled": False,
        "voice_enabled": False,
        "stt_enabled": False,
        "tts_enabled": False,
        "multi_agent_enabled": False,
        "improvement_enabled": False,
        "remote_approval_enabled": False,
        "autonomous_scheduling_enabled": False,
    }
    values.update(changes)
    return StartupSecurityConfiguration(**values)  # type: ignore[arg-type]


@pytest.mark.parametrize(
    ("field", "code"),
    [
        ("computer_enabled", SecurityViolationCode.UNSUPPORTED_COMPUTER_CONTROL),
        ("camera_enabled", SecurityViolationCode.UNSUPPORTED_CAMERA),
        (
            "application_management_enabled",
            SecurityViolationCode.UNSUPPORTED_APPLICATION_MANAGEMENT,
        ),
        (
            "package_installation_enabled",
            SecurityViolationCode.UNSUPPORTED_PACKAGE_INSTALLATION,
        ),
        ("voice_enabled", SecurityViolationCode.UNSUPPORTED_VOICE),
        ("multi_agent_enabled", SecurityViolationCode.UNSUPPORTED_MULTI_AGENT),
        ("improvement_enabled", SecurityViolationCode.UNSUPPORTED_IMPROVEMENT),
        ("remote_approval_enabled", SecurityViolationCode.REMOTE_APPROVAL_FORBIDDEN),
        (
            "autonomous_scheduling_enabled",
            SecurityViolationCode.AUTONOMOUS_SCHEDULING_FORBIDDEN,
        ),
    ],
)
def test_unsupported_security_capability_forces_invalid_startup_report(
    tmp_path: Path,
    field: str,
    code: SecurityViolationCode,
) -> None:
    report = StartupSecurityValidator().validate(_startup_config(tmp_path, **{field: True}))

    assert not report.valid
    assert code in {violation.code for violation in report.violations}


@pytest.mark.parametrize(
    "endpoint",
    [
        "https://127.0.0.1:11434",
        "http://localhost:11434",
        "http://example.com:11434",
        "http://user:password@127.0.0.1:11434",
        "http://127.0.0.1:11434/api",
        "http://127.0.0.1:11434?proxy=true",
    ],
)
def test_model_endpoint_must_be_literal_loopback(endpoint: str, tmp_path: Path) -> None:
    report = StartupSecurityValidator().validate(_startup_config(tmp_path, ai_endpoint=endpoint))

    assert SecurityViolationCode.MODEL_ENDPOINT_NOT_LOCAL in {
        violation.code for violation in report.violations
    }


def test_unsafe_runtime_configuration_enters_safe_mode_before_filesystem_write(
    tmp_path: Path,
) -> None:
    app_data = tmp_path / "must-not-be-created"
    settings = Settings(
        app_data_dir=app_data,
        remote_approval_enabled=True,
        _env_file=None,
    )

    runtime = ApplicationRuntime.create(settings)

    assert runtime.status is RuntimeStatus.SAFE_MODE
    assert runtime.container is None
    assert runtime.security_report is not None and not runtime.security_report.valid
    assert not app_data.exists()
    with pytest.raises(AttributeError):
        runtime.status = RuntimeStatus.READY  # type: ignore[misc]
    with pytest.raises(AttributeError):
        runtime.container = None  # type: ignore[misc]


def test_ambiguous_relative_app_data_path_is_rejected_without_creating_it(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.chdir(tmp_path)
    requested = Path("relative-data")

    runtime = ApplicationRuntime.create(
        Settings(app_data_dir=requested, ai_endpoint="http://127.0.0.1:11434", _env_file=None)
    )

    assert runtime.status is RuntimeStatus.SAFE_MODE
    assert not requested.exists()


def test_default_app_data_is_anchored_to_trusted_project_not_working_directory(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    project_root = tmp_path / "trusted-project"
    unrelated_working_directory = tmp_path / "untrusted-working-directory"
    project_root.mkdir()
    unrelated_working_directory.mkdir()
    monkeypatch.chdir(unrelated_working_directory)

    report = StartupSecurityValidator().validate(
        _startup_config(Path(".jarvis"), project_root=project_root)
    )

    assert report.valid
    assert report.resolved_app_data_dir == project_root / ".jarvis"
    assert not (unrelated_working_directory / ".jarvis").exists()


@pytest.mark.asyncio
async def test_runtime_consumes_project_anchored_default_app_data(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    repository_root = Path(__file__).resolve().parents[2]
    project_root = tmp_path / "trusted-project"
    knowledge = project_root / "knowledge" / "generated" / "project-index.json"
    knowledge.parent.mkdir(parents=True)
    knowledge.write_bytes(
        (repository_root / "knowledge" / "generated" / "project-index.json").read_bytes()
    )
    unrelated_working_directory = tmp_path / "untrusted-working-directory"
    unrelated_working_directory.mkdir()
    monkeypatch.chdir(unrelated_working_directory)

    runtime = ApplicationRuntime.create(
        Settings(app_data_dir=Path(".jarvis"), _env_file=None),
        project_root=project_root,
    )

    assert runtime.status is RuntimeStatus.READY, runtime.error
    assert runtime.container is not None
    assert runtime.container.paths.root == project_root / ".jarvis"
    assert not (unrelated_working_directory / ".jarvis").exists()
    await runtime.aclose()


@pytest.mark.parametrize("relative", [Path("."), Path(".git"), Path("jarvis/permissions")])
def test_app_data_cannot_overlap_source_or_git(
    tmp_path: Path,
    relative: Path,
) -> None:
    project_root = tmp_path / "trusted-project"
    (project_root / ".git").mkdir(parents=True)
    candidate = project_root / relative

    report = StartupSecurityValidator().validate(
        _startup_config(candidate, project_root=project_root)
    )

    assert SecurityViolationCode.APP_DATA_PATH_UNSAFE in {
        violation.code for violation in report.violations
    }


def test_app_data_rejects_root_existing_file_and_unsafe_windows_forms(tmp_path: Path) -> None:
    existing_file = tmp_path / "not-a-directory"
    existing_file.write_text("data", encoding="utf-8")
    candidates = (
        Path(tmp_path.anchor),
        existing_file,
        Path(r"\\server\share\data"),
        Path(r"\\?\C:\data"),
        Path(r"\\.\PhysicalDrive0"),
        Path(r"C:\safe\data:stream"),
        Path(r"C:\safe\trailing.\data"),
        Path("C:\\safe\\trailing \\data"),
        Path(r"C:\safe\NUL\data"),
        Path(r"C:\safe\CONIN$\data"),
        Path(r"C:\safe\CONOUT$\data"),
        Path(r"C:\safe\CLOCK$\data"),
        *(tmp_path / f"invalid-{character}-name" for character in '<>"|?*'),
    )

    for candidate in candidates:
        report = StartupSecurityValidator().validate(_startup_config(candidate))
        assert SecurityViolationCode.APP_DATA_PATH_UNSAFE in {
            violation.code for violation in report.violations
        }, candidate


def test_app_data_rejects_lexical_symlink_before_resolution(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    link = tmp_path / "linked-root"
    candidate = link / "data"
    link.mkdir()
    real_is_symlink = Path.is_symlink
    real_resolve = Path.resolve
    monkeypatch.setattr(
        Path,
        "is_symlink",
        lambda path: path == link or real_is_symlink(path),
    )

    def guarded_resolve(path: Path, *, strict: bool = False) -> Path:
        if path == candidate:
            raise AssertionError("Candidate was resolved before lexical link inspection")
        return real_resolve(path, strict=strict)

    monkeypatch.setattr(Path, "resolve", guarded_resolve)

    report = StartupSecurityValidator().validate(_startup_config(candidate))

    assert SecurityViolationCode.APP_DATA_PATH_UNSAFE in {
        violation.code for violation in report.violations
    }


def test_app_data_rejects_lexical_junction_before_resolution(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    junction = tmp_path / "junction"
    junction.mkdir()
    real_is_junction = Path.is_junction
    monkeypatch.setattr(
        Path,
        "is_junction",
        lambda path: path == junction or real_is_junction(path),
    )

    report = StartupSecurityValidator().validate(_startup_config(junction / "data"))

    assert SecurityViolationCode.APP_DATA_PATH_UNSAFE in {
        violation.code for violation in report.violations
    }


def test_runtime_path_resolution_failure_enters_safe_mode(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def fail_resolution(cls: type[RuntimePaths], root: Path) -> RuntimePaths:
        del cls, root
        raise OSError("simulated path race")

    monkeypatch.setattr(RuntimePaths, "from_root", classmethod(fail_resolution))

    runtime = ApplicationRuntime.create(Settings(app_data_dir=tmp_path / "data", _env_file=None))

    assert runtime.status is RuntimeStatus.SAFE_MODE
    assert runtime.security_report is not None
    assert SecurityViolationCode.APP_DATA_PATH_UNSAFE in {
        violation.code for violation in runtime.security_report.violations
    }


def test_runtime_revalidates_path_identity_after_directory_creation(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    app_data = tmp_path / "data"
    real_is_junction = Path.is_junction
    monkeypatch.setattr(
        Path,
        "is_junction",
        lambda path: (path == app_data and path.exists()) or real_is_junction(path),
    )

    runtime = ApplicationRuntime.create(Settings(app_data_dir=app_data, _env_file=None))

    assert app_data.exists()
    assert runtime.status is RuntimeStatus.SAFE_MODE
    assert runtime.container is None
    assert runtime.security_report is not None
    assert SecurityViolationCode.APP_DATA_PATH_UNSAFE in {
        violation.code for violation in runtime.security_report.violations
    }


@pytest.mark.parametrize("child_name", ("cache", "state.sqlite3", "state.sqlite3-wal"))
def test_runtime_rejects_reparse_children_before_database_open(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    child_name: str,
) -> None:
    app_data = tmp_path / "data"
    app_data.mkdir()
    child = app_data / child_name
    if child.suffix:
        child.touch()
    else:
        child.mkdir()
    real_is_symlink = Path.is_symlink
    monkeypatch.setattr(
        Path,
        "is_symlink",
        lambda path: path == child or real_is_symlink(path),
    )

    runtime = ApplicationRuntime.create(Settings(app_data_dir=app_data, _env_file=None))

    assert runtime.status is RuntimeStatus.SAFE_MODE
    assert runtime.container is None
    assert not (app_data / "planning.sqlite3").exists()
    assert not (app_data / "audit.sqlite3").exists()


def test_runtime_rejects_hard_linked_database_file(tmp_path: Path) -> None:
    app_data = tmp_path / "data"
    app_data.mkdir()
    external = tmp_path / "external.sqlite3"
    external.touch()
    try:
        os.link(external, app_data / "state.sqlite3")
    except OSError as error:
        pytest.skip(f"hard links unavailable: {type(error).__name__}")

    runtime = ApplicationRuntime.create(Settings(app_data_dir=app_data, _env_file=None))

    assert runtime.status is RuntimeStatus.SAFE_MODE
    assert runtime.container is None
    assert external.stat().st_size == 0


def test_tool_registry_seal_prevents_late_capability_mutation() -> None:
    registry = ToolRegistry((CalculatorTool(),))
    registry.seal()

    assert registry.sealed
    assert registry.permission_broker.registration_sealed
    with pytest.raises(RuntimeError, match="sealed"):
        registry.permission_broker.unregister_tool("calculator", CalculatorTool())
    with pytest.raises(ToolRegistrationError, match="sealed"):
        registry.register(CalculatorTool())


@pytest.mark.asyncio
async def test_command_adapter_rejects_path_resolution_and_strips_credentials(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("JARVIS_SECURITY_TEST_TOKEN", "must-not-cross")
    arguments = (
        "-c",
        "import os; print(os.environ.get('JARVIS_SECURITY_TEST_TOKEN', 'absent'))",
    )
    trusted = CommandDefinition(
        "python-environment",
        sys.executable,
        "python.environment",
        frozenset({arguments}),
        SafetyClass.ORDINARY,
    )
    result = await SubprocessCommandAdapter().execute(
        trusted,
        arguments,
        os.fspath(tmp_path),
        10,
        asyncio.Event(),
    )
    relative = await SubprocessCommandAdapter().execute(
        CommandDefinition("python", "python.exe", "python", safety_class=SafetyClass.ORDINARY),
        (),
        os.fspath(tmp_path),
        10,
        asyncio.Event(),
    )

    assert result.exit_code == 0
    assert result.stdout.strip() == "absent"
    assert relative.rejected
