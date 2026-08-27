"""Adversarial tests for the v1 Trusted Core enforcement primitives."""

from __future__ import annotations

import asyncio
import base64
import hashlib
import os
import sys
from dataclasses import replace
from datetime import UTC, datetime, timedelta
from importlib import resources
from importlib.metadata import Distribution
from inspect import signature
from pathlib import Path
from typing import cast
from uuid import uuid4

import pytest
from jarvis.computer.models import CommandDefinition
from jarvis.computer.terminal import SubprocessCommandAdapter
from jarvis.core.config import Settings
from jarvis.core.errors import ToolRegistrationError
from jarvis.improvement.workspace import TrustedWorkspaceChangeApplier
from jarvis.permissions import SafetyClass, normalize_path
from jarvis.runtime import ApplicationRuntime, RuntimePaths, RuntimeStatus
from jarvis.security import (
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
    def __init__(self, files: tuple[str, ...], version: str = "1.0.0") -> None:
        from pathlib import PurePosixPath

        self.files = tuple(PurePosixPath(path) for path in files)
        self.version = version

    def read_text(self, name: str) -> str | None:
        if name != "RECORD":
            return None
        package_root = resources.files("jarvis")
        rows: list[str] = []
        for path in self.files:
            relative = path.as_posix()
            if not relative.startswith("jarvis/") or relative.endswith("/RECORD"):
                continue
            resource = package_root.joinpath(*relative.removeprefix("jarvis/").split("/"))
            content = resource.read_bytes()
            digest = (
                base64.urlsafe_b64encode(hashlib.sha256(content).digest())
                .rstrip(b"=")
                .decode("ascii")
            )
            rows.append(f"{relative},sha256={digest},{len(content)}")
        rows.append("jarvis-1.0.0.dist-info/RECORD,,")
        return "\n".join(rows)


def _installed_integrity_files() -> tuple[str, ...]:
    return (
        "jarvis/api.py",
        "jarvis/improvement/workspace.py",
        "jarvis/permissions/broker.py",
        "jarvis/recovery.py",
        "jarvis/runtime.py",
        "jarvis/security/integrity.py",
        "jarvis/security/startup.py",
        "jarvis/tools/base.py",
        "jarvis-1.0.0.dist-info/RECORD",
    )


def test_installed_integrity_evidence_uses_package_files_and_record() -> None:
    provider = InstalledDistributionIntegrityEvidenceProvider(
        lambda _name: cast(Distribution, _FakeDistribution(_installed_integrity_files()))
    )

    provider.validate()


@pytest.mark.parametrize(
    "files",
    (
        tuple(path for path in _installed_integrity_files() if path != "jarvis/runtime.py"),
        tuple(path for path in _installed_integrity_files() if not path.endswith("/RECORD")),
    ),
)
def test_installed_integrity_evidence_missing_data_fails_closed(
    files: tuple[str, ...],
) -> None:
    provider = InstalledDistributionIntegrityEvidenceProvider(
        lambda _name: cast(Distribution, _FakeDistribution(files))
    )

    with pytest.raises(IntegrityEvidenceError):
        provider.validate()


def test_installed_integrity_evidence_version_mismatch_fails_closed() -> None:
    provider = InstalledDistributionIntegrityEvidenceProvider(
        lambda _name: cast(Distribution, _FakeDistribution(_installed_integrity_files(), "9.9.9"))
    )

    with pytest.raises(IntegrityEvidenceError):
        provider.validate()


def test_installed_integrity_evidence_malformed_record_fails_closed() -> None:
    class MalformedDistribution(_FakeDistribution):
        def read_text(self, name: str) -> str | None:
            del name
            return "not,csv,integrity,metadata"

    provider = InstalledDistributionIntegrityEvidenceProvider(
        lambda _name: cast(
            Distribution,
            MalformedDistribution(_installed_integrity_files()),
        )
    )

    with pytest.raises(IntegrityEvidenceError):
        provider.validate()


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
