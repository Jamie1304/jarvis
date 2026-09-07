from __future__ import annotations

import asyncio
import json
import subprocess
import sys
from dataclasses import replace
from pathlib import Path
from types import SimpleNamespace
from typing import Any, cast

import jarvis.acceptance.runner as runner_module
import pytest
from jarvis.acceptance.environment import AcceptanceEnvironmentError, VMAcceptanceEnvironment
from jarvis.acceptance.faults import FaultTransaction, default_faults
from jarvis.acceptance.models import AcceptanceStatus, EvidenceTrust
from jarvis.acceptance.runner import AcceptanceRunner, Selection
from jarvis.acceptance.specs import SPECS, validate_specs
from jarvis.vm import GuestCommand, InMemoryVirtualizationProvider
from jarvis.vm.models import InstanceState


def test_canonical_ids_are_complete_and_unique() -> None:
    validate_specs()
    assert len(SPECS) == 115
    assert [item.test_id for item in SPECS] == [f"{number:03}" for number in range(1, 116)]
    assert all(item.classification and item.automation_level for item in SPECS)


def test_selector_profiles_and_filters(tmp_path: Path) -> None:
    runner = AcceptanceRunner(tmp_path)
    assert {item.test_id for item in runner.select(profile="smoke")} == {
        "001",
        "002",
        "016",
        "021",
        "078",
        "084",
    }
    assert {item.test_id for item in runner.select(profile="vm-foundation")} == {"043", "078"}
    assert all(item.phase.startswith("F") for item in runner.select(phase="F"))
    assert all(item.test_id.startswith("0") for item in runner.select(tags=("phase-a",)))
    assert {item.test_id for item in runner.select(profile="vm")} == {
        item.test_id for item in SPECS if item.classification.value == "VM"
    }
    assert {item.test_id for item in runner.select(profile="windows")} == {
        item.test_id for item in SPECS if item.classification.value == "REAL_WINDOWS"
    }
    assert all(item.security_relevance != "normal" for item in runner.select(profile="security"))
    assert {item.test_id for item in runner.select(profile="self-repair")} == {
        "082",
        "083",
        "086",
        "087",
        "090",
    }


def test_evidence_model_rejects_model_self_certification() -> None:
    from jarvis.acceptance.models import EvidenceEnvelope

    evidence = EvidenceEnvelope(
        "e",
        "r",
        "001",
        "model",
        "text",
        "host",
        EvidenceTrust.MODEL_REPORTED,
        AcceptanceStatus.PASS,
    )
    assert not evidence.satisfies_critical_assertion()


def test_fault_transactions_are_reversible(tmp_path: Path) -> None:
    spec = default_faults()[0]
    with FaultTransaction(spec, root=tmp_path) as transaction:
        assert transaction.result is not None
        assert transaction.result.occurred
        assert transaction.result.cleaned
        assert transaction.result.base_environment_healthy
    assert not (tmp_path / "fault-present.json").exists()


def test_faults_reject_host_targets(tmp_path: Path) -> None:
    from dataclasses import replace

    with pytest.raises(ValueError):
        FaultTransaction(replace(default_faults()[0], target_environment="HOST"), root=tmp_path)


def test_runner_reports_non_executable_truthfully(tmp_path: Path) -> None:
    runner = AcceptanceRunner(tmp_path, tmp_path / "artifacts")
    specs = runner.select(test_ids=("001", "109", "111"))
    report = cast(
        dict[str, Any],
        asyncio.run(runner.run(Selection(tuple(item.test_id for item in specs), "test"))),
    )
    assert cast(dict[str, Any], report["specifications"])["defined"] == 115
    counts = cast(dict[str, Any], report["counts"])
    assert counts["PASS"] == 1
    assert counts["HUMAN_JUDGMENT_REQUIRED"] == 1
    assert counts["LONG_RUNNING_PENDING"] == 1
    run_dir = next((tmp_path / "artifacts").glob("run-*"))
    report = cast(dict[str, Any], json.loads((run_dir / "report.json").read_text()))
    assert report["specifications"]["missing_ids"] == []


@pytest.mark.asyncio
async def test_vm_environment_lease_binds_guest_evidence_and_releases(tmp_path: Path) -> None:
    provider = InMemoryVirtualizationProvider()
    environment = VMAcceptanceEnvironment(provider, archive_root=tmp_path / "archives")
    lease = await environment.acquire("run-1", "078", disposable=False)
    evidence = await environment.execute(lease, GuestCommand("printf", ("acceptance",)))
    assert evidence.lease.instance_id == lease.instance_id
    assert evidence.result.exit_code == 0
    assert evidence.as_dict()["guest_identity"] == "jarvis-workbench"
    await environment.release(lease)
    instances = await provider.instances()
    assert instances[0].state.value == "stopped"


@pytest.mark.asyncio
async def test_runner_executes_vm_and_fault_boundaries_without_host_authority(
    tmp_path: Path,
) -> None:
    class _CloneProvider(InMemoryVirtualizationProvider):
        async def export(self, instance_id: object, archive: Path) -> None:
            del instance_id
            archive.write_text("bounded archive", encoding="utf-8")

        async def import_clone(
            self,
            source_instance_id: object,
            clone_name: str,
            destination: Path,
            archive: Path,
            template: object,
        ) -> object:
            del source_instance_id, clone_name, destination, archive
            return await self.create(cast(Any, template))

    provider = _CloneProvider()
    environment = VMAcceptanceEnvironment(provider, archive_root=tmp_path / "archives")
    runner = AcceptanceRunner(tmp_path, tmp_path / "artifacts", environment)
    vm_spec = next(item for item in SPECS if item.test_id == "078")
    vm_result = await runner._execute(vm_spec, "vm-run", tmp_path / "run")  # noqa: SLF001
    assert vm_result.status is AcceptanceStatus.PASS

    blocked_runner = AcceptanceRunner(tmp_path, tmp_path / "blocked")
    blocked = await blocked_runner._execute(vm_spec, "blocked-run", tmp_path / "run")  # noqa: SLF001
    assert blocked.status is AcceptanceStatus.BLOCKED_ENVIRONMENT

    faultless = await environment.run_disposable_fault("fault-run", "043")
    assert faultless["fault_verified"] is True
    assert faultless["cleanup_verified"] is True


@pytest.mark.asyncio
async def test_runner_fault_and_environment_failures_remain_typed(tmp_path: Path) -> None:
    runner = AcceptanceRunner(tmp_path, tmp_path / "artifacts")
    disposable = next(item for item in SPECS if item.test_id == "043")
    no_adapter = await runner._execute_fault(disposable, "fault-no-adapter")  # noqa: SLF001
    assert no_adapter.status is AcceptanceStatus.BLOCKED_ENVIRONMENT

    class _FailingEnvironment:
        async def run_disposable_fault(self, run_id: str, test_id: str) -> dict[str, object]:
            del run_id, test_id
            raise AcceptanceEnvironmentError("cleanup unavailable")

    failed_runner = AcceptanceRunner(
        tmp_path, tmp_path / "failed", cast(Any, _FailingEnvironment())
    )
    failed = await failed_runner._execute_fault(disposable, "fault-failed")  # noqa: SLF001
    assert failed.status is AcceptanceStatus.FAIL
    assert failed.error == "cleanup unavailable"


@pytest.mark.asyncio
async def test_vm_environment_rejects_stale_leases_and_missing_clone_contract(
    tmp_path: Path,
) -> None:
    environment = VMAcceptanceEnvironment(InMemoryVirtualizationProvider())
    lease = await environment.acquire("run", "078", disposable=False)
    await environment.release(lease)
    with pytest.raises(AcceptanceEnvironmentError, match="unknown or stale"):
        await environment.execute(
            lease,
            GuestCommand("printf", ("stale",)),
        )
    await environment.release(lease)
    with pytest.raises(AcceptanceEnvironmentError, match="clone contract"):
        await environment.acquire("run", "043", disposable=True)
    assert (
        await VMAcceptanceEnvironment(
            InMemoryVirtualizationProvider(), archive_root=tmp_path / "archives"
        ).reconcile()
        == ()
    )


@pytest.mark.asyncio
async def test_vm_environment_reuses_existing_workbench_and_surfaces_cleanup_error(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    provider = InMemoryVirtualizationProvider()
    first = VMAcceptanceEnvironment(provider, archive_root=tmp_path / "first")
    await first.acquire("run", "078", disposable=False)
    second = VMAcceptanceEnvironment(provider, archive_root=tmp_path / "second")
    existing = await second._get_workbench()  # noqa: SLF001
    assert existing.template_id == "jarvis-workbench"

    class _CloneProvider(InMemoryVirtualizationProvider):
        async def export(self, instance_id: object, archive: Path) -> None:
            del instance_id
            archive.write_text("archive", encoding="utf-8")

        async def import_clone(
            self,
            source_instance_id: object,
            clone_name: str,
            destination: Path,
            archive: Path,
            template: object,
        ) -> object:
            del source_instance_id, clone_name, destination, archive
            return await self.create(cast(Any, template))

    clone_environment = VMAcceptanceEnvironment(
        _CloneProvider(), archive_root=tmp_path / "cleanup-error"
    )

    async def fail_release(lease: object) -> None:
        del lease
        raise RuntimeError("release failed")

    monkeypatch.setattr(clone_environment, "release", cast(Any, fail_release))
    with pytest.raises(AcceptanceEnvironmentError, match="cleanup failed"):
        await clone_environment.run_disposable_fault("run", "043")

    stopped_provider = _CloneProvider()
    stopped_environment = VMAcceptanceEnvironment(
        stopped_provider, archive_root=tmp_path / "stopped"
    )
    source = await stopped_environment._get_workbench()  # noqa: SLF001
    stopped_environment._workbench = replace(  # noqa: SLF001
        source, state=InstanceState.DEFINED
    )
    lease = await stopped_environment.acquire("run", "043", disposable=True)
    assert lease.disposable


def test_worktree_fingerprint_binds_files_and_directories(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    (tmp_path / "tracked.txt").write_text("tracked", encoding="utf-8")
    (tmp_path / "nested").mkdir()
    (tmp_path / "nested" / "deeper").mkdir()
    (tmp_path / "nested" / "file.txt").write_text("nested", encoding="utf-8")

    def fake_run(*args: object, **kwargs: object) -> object:
        del args, kwargs
        return SimpleNamespace(stdout=" M tracked.txt\n?? nested\n?? absent.txt\n")

    monkeypatch.setattr(cast(Any, runner_module).subprocess, "run", fake_run)
    first = runner_module.worktree_fingerprint(tmp_path)
    (tmp_path / "nested" / "file.txt").write_text("changed", encoding="utf-8")
    assert first != runner_module.worktree_fingerprint(tmp_path)


@pytest.mark.asyncio
async def test_runner_resume_cancel_and_typed_non_vm_boundaries(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    runner = AcceptanceRunner(tmp_path, tmp_path / "artifacts")
    monkeypatch.setattr(cast(Any, runner_module).os, "name", "posix")
    assert (
        await runner._execute(  # noqa: SLF001
            next(item for item in SPECS if item.test_id == "004"), "run", tmp_path
        )
    ).status is AcceptanceStatus.BLOCKED_ENVIRONMENT  # noqa: SLF001
    assert (
        await runner._execute(  # noqa: SLF001
            next(item for item in SPECS if item.test_id == "102"), "run", tmp_path
        )
    ).status is AcceptanceStatus.BLOCKED_ENVIRONMENT  # noqa: SLF001
    assert (
        await runner._execute(  # noqa: SLF001
            next(item for item in SPECS if item.test_id == "008"), "run", tmp_path
        )
    ).status is AcceptanceStatus.BLOCKED_FEATURE  # noqa: SLF001
    assert (
        await runner._execute(  # noqa: SLF001
            next(item for item in SPECS if item.test_id == "002"), "run", tmp_path
        )
    ).status is AcceptanceStatus.BLOCKED_FEATURE  # noqa: SLF001
    assert (
        await runner._execute(  # noqa: SLF001
            next(item for item in SPECS if item.test_id == "031"), "run", tmp_path
        )
    ).status is AcceptanceStatus.PASS  # noqa: SLF001

    class _Monitor:
        def __init__(self, *args: object) -> None:
            del args

        def snapshot(self) -> object:
            return object()

        def evidence(self, *args: object, **kwargs: object) -> object:
            del args, kwargs
            return SimpleNamespace(result=AcceptanceStatus.UNKNOWN_OUTCOME)

    monkeypatch.setattr(cast(Any, runner_module).os, "name", "nt")
    monkeypatch.setattr(runner_module, "HostSideEffectMonitor", _Monitor)
    native = await runner._execute(  # noqa: SLF001
        next(item for item in SPECS if item.test_id == "004"), "native", tmp_path
    )
    assert native.status is AcceptanceStatus.PASS

    report = await runner.run(Selection(("001", "002"), "cancelled"), cancel_after=1)
    assert len(cast(list[object], report["results"])) == 1
    resumed = await runner.run(Selection(("001", "002"), "cancelled"), resume=True)
    assert len(cast(list[object], resumed["results"])) == 2
    fault_report = await runner.run(Selection(("043",), "fault", fault=True), cancel_after=None)
    assert cast(dict[str, int], fault_report["counts"])["BLOCKED_ENVIRONMENT"] == 1


@pytest.mark.asyncio
async def test_runner_preserves_fault_and_vm_cleanup_failures(
    tmp_path: Path,
) -> None:
    disposable = next(item for item in SPECS if item.test_id == "043")

    class _FalseFault:
        async def run_disposable_fault(self, run_id: str, test_id: str) -> dict[str, object]:
            del run_id, test_id
            return {"fault_verified": True, "cleanup_verified": False}

    false_result = await AcceptanceRunner(
        tmp_path, tmp_path / "false", cast(Any, _FalseFault())
    )._execute_fault(disposable, "fault")  # noqa: SLF001
    assert false_result.status is AcceptanceStatus.FAIL

    lease = object()

    class _BrokenVM:
        async def acquire(self, run_id: str, test_id: str, *, disposable: bool) -> object:
            del run_id, test_id, disposable
            return lease

        async def execute(self, current: object, command: object) -> object:
            del current, command
            raise RuntimeError("execution failed")

        async def release(self, current: object) -> None:
            assert current is lease
            raise RuntimeError("release failed")

    broken = await AcceptanceRunner(tmp_path, tmp_path / "broken", cast(Any, _BrokenVM()))._execute(
        next(item for item in SPECS if item.test_id == "078"), "vm", tmp_path
    )  # noqa: SLF001
    assert broken.status is AcceptanceStatus.FAIL
    assert broken.error == "execution failed; cleanup failed: release failed"

    class _AcquireBroken:
        async def acquire(self, *args: object, **kwargs: object) -> object:
            del args, kwargs
            raise RuntimeError("acquire failed")

    acquired = await AcceptanceRunner(
        tmp_path, tmp_path / "acquire-broken", cast(Any, _AcquireBroken())
    )._execute(next(item for item in SPECS if item.test_id == "078"), "vm", tmp_path)  # noqa: SLF001
    assert acquired.error == "acquire failed"


def test_runner_fingerprint_uses_git_status_without_raising_on_failure(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    def failed_run(*args: object, **kwargs: object) -> object:
        del args, kwargs
        return subprocess.CompletedProcess((), 128, stdout="", stderr="not a repository")

    monkeypatch.setattr(cast(Any, runner_module).subprocess, "run", failed_run)
    assert len(runner_module.worktree_fingerprint(tmp_path)) == 64


def test_runner_reports_unknown_version_when_version_module_is_unavailable(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setitem(sys.modules, "jarvis.version", None)
    assert AcceptanceRunner(tmp_path)._version() == "unknown"  # noqa: SLF001
