from __future__ import annotations

import base64
import json
import sys
import threading
import time
from collections.abc import Mapping
from hashlib import sha256
from pathlib import Path
from types import SimpleNamespace
from typing import Any, cast
from uuid import uuid4

import jarvis.native_cleanup_recovery as recovery_module
import pytest
from jarvis.native_cleanup_recovery import (
    PROCESS_INSTANCE_ID,
    NativeCleanupRecoveryCoordinator,
    RecoveryState,
    clear_live_cleanup_owner,
    mark_live_cleanup_owner,
)

BASELINE = bytes((2, 0, 12, 0, 1, 0, 0, 0, 0, 0, 4, 0))
PROFILE = "JARVIS-" + "a" * 32
SID = "S-1-15-2-123456"
TEST_INTEGRITY_KEY = b"native-recovery-test-key"


def _sign(payload: Mapping[str, object]) -> str:
    encoded = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return sha256(TEST_INTEGRITY_KEY + encoded).hexdigest()


def _verify(payload: Mapping[str, object], integrity: str) -> bool:
    return integrity == _sign(payload)


class FakeOperations:
    def __init__(self, *, dirty: bool = False, stall: threading.Event | None = None) -> None:
        self.dirty = dirty
        self.stall = stall
        self.restores: list[str] = []
        self.observations: list[str] = []
        self.profile_calls = 0

    def profile_sid_bytes(self, profile_name: str, expected_sid: str) -> bytes:
        assert profile_name == PROFILE
        assert expected_sid == SID
        if self.stall is not None:
            self.stall.wait()
        return b"temporary-sid"

    def observe_acl(self, path: str, baseline: bytes, temporary_sid: bytes) -> Mapping[str, object]:
        assert baseline == BASELINE
        assert temporary_sid == b"temporary-sid"
        self.observations.append(path)
        dirty = self.dirty and not self.restores
        return {
            "path": path,
            "baseline_matches": not dirty,
            "temporary_sid_present": dirty,
        }

    def restore_acl(self, path: str, baseline: bytes) -> None:
        assert baseline == BASELINE
        self.restores.append(path)

    def reconcile_profile(self, profile_name: str, expected_sid: str) -> tuple[str, bytes]:
        self.profile_calls += 1
        assert profile_name == PROFILE
        assert expected_sid == SID
        return "DELETED", b"temporary-sid"


def _receipt(
    tmp_path: Path, *, state: str = "CLEANUP_OUTCOME_UNKNOWN", owner: str | None = None
) -> Path:
    parent = tmp_path / "sandboxes"
    parent.mkdir(parents=True)
    root = parent / ("jarvis-sandbox-" + "b" * 16 + "-" + "c" * 32)
    (root / "work").mkdir(parents=True)
    (root / "data").mkdir()
    encoded = base64.b64encode(BASELINE).decode("ascii")
    resource = {
        "path": str(root),
        "resource_kind": "sandbox_root",
        "baseline_b64": encoded,
        "baseline_sha256": sha256(BASELINE).hexdigest(),
        "temporary_sid": SID,
    }
    path = root / "native-cleanup-recovery.json"
    path.write_text(
        json.dumps(
            {
                "schema": 2,
                "operation_id": uuid4().hex,
                "state": state,
                "owner": {"instance_id": owner or uuid4().hex, "pid": 999999},
                "resource_binding": {
                    "class": "JARVIS_NATIVE_SANDBOX",
                    "integration_id": "generated.test",
                    "sandbox_parent": str(parent),
                    "sandbox_root": str(root),
                    "profile": {"name": PROFILE, "sid": SID},
                    "acl": [resource],
                    "filesystem": {"owned_root": str(root)},
                },
                "evidence": {"cleanup_operation_id": "placeholder"},
            }
        ),
        encoding="utf-8",
    )
    # Bind the evidence operation ID to the top-level value after serialization.
    raw = json.loads(path.read_text(encoding="utf-8"))
    raw["evidence"]["cleanup_operation_id"] = raw["operation_id"]
    raw["integrity"] = _sign(raw)
    path.write_text(json.dumps(raw), encoding="utf-8")
    return path


def _coordinator(
    path: Path, operations: FakeOperations, deadline: float = 1.0
) -> NativeCleanupRecoveryCoordinator:
    return NativeCleanupRecoveryCoordinator(
        path.parent.parent,
        trusted_roots=(path.parent.parent,),
        foreground_deadline_seconds=deadline,
        operations=operations,
        integrity_verifier=_verify,
        integrity_signer=_sign,
    )


def test_already_clean_confirms_without_acl_mutation(tmp_path: Path) -> None:
    receipt = _receipt(tmp_path)
    operations = FakeOperations()
    result = _coordinator(receipt, operations).reconcile_all()[0]
    assert result.state is RecoveryState.CONFIRMED
    assert operations.restores == []
    assert operations.profile_calls == 1
    assert not (receipt.parent / "work").exists()
    assert json.loads(receipt.read_text(encoding="utf-8"))["state"] == "CLEANUP_CONFIRMED"


def test_dirty_acl_is_restored_and_reverified(tmp_path: Path) -> None:
    receipt = _receipt(tmp_path)
    operations = FakeOperations(dirty=True)
    result = _coordinator(receipt, operations).reconcile_all()[0]
    assert result.state is RecoveryState.CONFIRMED
    assert operations.restores == [str(receipt.parent)]
    assert len(operations.observations) == 2


def test_tampered_path_fails_closed_before_native_operations(tmp_path: Path) -> None:
    receipt = _receipt(tmp_path)
    raw = json.loads(receipt.read_text(encoding="utf-8"))
    raw["resource_binding"]["acl"][0]["path"] = str(tmp_path / "outside")
    raw["integrity"] = _sign({key: value for key, value in raw.items() if key != "integrity"})
    receipt.write_text(json.dumps(raw), encoding="utf-8")
    operations = FakeOperations(dirty=True)
    result = _coordinator(receipt, operations).reconcile_all()[0]
    assert result.state is RecoveryState.METADATA_INVALID
    assert operations.restores == []
    assert operations.profile_calls == 0


def test_mismatched_sid_fails_closed(tmp_path: Path) -> None:
    receipt = _receipt(tmp_path)
    raw = json.loads(receipt.read_text(encoding="utf-8"))
    raw["resource_binding"]["acl"][0]["temporary_sid"] = "S-1-15-2-999"
    receipt.write_text(json.dumps(raw), encoding="utf-8")
    result = _coordinator(receipt, FakeOperations()).reconcile_all()[0]
    assert result.state is RecoveryState.METADATA_INVALID


def test_corrupt_receipt_fails_closed(tmp_path: Path) -> None:
    receipt = _receipt(tmp_path)
    receipt.write_text("{not-json", encoding="utf-8")
    operations = FakeOperations()
    result = _coordinator(receipt, operations).reconcile_all()[0]
    assert result.state is RecoveryState.METADATA_INVALID
    assert operations.observations == []


def test_live_unknown_is_not_raced(tmp_path: Path) -> None:
    receipt = _receipt(tmp_path)
    operation_id = json.loads(receipt.read_text(encoding="utf-8"))["operation_id"]
    raw = json.loads(receipt.read_text(encoding="utf-8"))
    raw["owner"]["instance_id"] = PROCESS_INSTANCE_ID
    raw["integrity"] = _sign({key: value for key, value in raw.items() if key != "integrity"})
    receipt.write_text(json.dumps(raw), encoding="utf-8")
    mark_live_cleanup_owner(operation_id)
    try:
        operations = FakeOperations(dirty=True)
        result = _coordinator(receipt, operations).reconcile_all()[0]
        assert result.live_owner
        assert operations.observations == []
        assert operations.restores == []
    finally:
        clear_live_cleanup_owner(operation_id)


def test_stalled_reconciliation_is_bounded_and_lock_is_retained(tmp_path: Path) -> None:
    receipt = _receipt(tmp_path)
    release = threading.Event()
    operations = FakeOperations(stall=release)
    coordinator = _coordinator(receipt, operations, deadline=0.01)
    started = time.monotonic()
    result = coordinator.reconcile_all()[0]
    elapsed = time.monotonic() - started
    assert result.timed_out
    assert elapsed < 0.2
    assert json.loads(receipt.read_text(encoding="utf-8"))["state"] == "RECOVERY_BLOCKED"
    second = _coordinator(receipt, FakeOperations(), deadline=0.01).reconcile_all()[0]
    assert second.live_owner
    release.set()
    time.sleep(0.05)


def test_repeated_restart_can_reconcile_after_prior_failure(tmp_path: Path) -> None:
    receipt = _receipt(tmp_path)

    class Failing(FakeOperations):
        def profile_sid_bytes(self, profile_name: str, expected_sid: str) -> bytes:
            raise RuntimeError("synthetic unavailable observer")

    first = _coordinator(receipt, Failing()).reconcile_all()[0]
    assert first.state is RecoveryState.BLOCKED
    second = _coordinator(receipt, FakeOperations()).reconcile_all()[0]
    assert second.state is RecoveryState.CONFIRMED


def test_terminal_receipt_is_observed_without_replaying_cleanup(tmp_path: Path) -> None:
    receipt = _receipt(tmp_path, state="CLEANUP_CONFIRMED")
    operations = FakeOperations(dirty=True)
    result = _coordinator(receipt, operations).reconcile_all()[0]
    assert result.state is RecoveryState.CONFIRMED
    assert operations.observations == []
    assert operations.restores == []


def test_recovery_evidence_and_validation_helpers_fail_closed(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    module = cast(Any, recovery_module)
    evidence = module.RecoveryEvidence(
        tmp_path / "receipt",
        None,
        RecoveryState.BLOCKED,
        RecoveryState.BLOCKED.value,
        detail="x" * 300,
        observations=tuple({"index": index} for index in range(40)),
    )
    rendered = evidence.as_dict()
    assert len(cast(str, rendered["detail"])) == 256
    assert len(cast(list[object], rendered["observations"])) == 32

    with pytest.raises(module.NativeCleanupRecoveryError, match="not absolute"):
        module._canonical(Path("relative"))
    with pytest.raises(module.NativeCleanupRecoveryError, match="malformed"):
        module._text("", "field")
    with pytest.raises(module.NativeCleanupRecoveryError, match="malformed"):
        module._mapping({1: "not a string key"}, "field")
    with pytest.raises(module.NativeCleanupRecoveryError, match="not base64"):
        module._strict_baseline("%%%", "hash", "baseline")
    with pytest.raises(module.NativeCleanupRecoveryError, match="invalid size"):
        module._strict_baseline(base64.b64encode(b"small").decode(), "hash", "baseline")
    with pytest.raises(module.NativeCleanupRecoveryError, match="fingerprint"):
        module._strict_baseline(base64.b64encode(BASELINE).decode(), "wrong", "baseline")
    assert module._is_under(tmp_path / "child", tmp_path)
    assert not module._is_under(tmp_path.parent, tmp_path)

    with pytest.raises(module.NativeCleanupRecoveryError, match="owned root"):
        module._validate_resource_path(
            tmp_path / "other",
            "sandbox_root",
            root=tmp_path,
            trusted_roots=(tmp_path,),
            prior_paths=(),
        )
    with pytest.raises(module.NativeCleanupRecoveryError, match="traversal"):
        module._validate_resource_path(
            tmp_path / "unrelated",
            "traversal_parent",
            root=tmp_path,
            trusted_roots=(tmp_path,),
            prior_paths=(),
        )
    module._validate_resource_path(
        tmp_path.parent,
        "traversal_parent",
        root=tmp_path,
        trusted_roots=(tmp_path,),
        prior_paths=(),
    )
    with pytest.raises(module.NativeCleanupRecoveryError, match="class"):
        module._validate_resource_path(
            tmp_path,
            "unknown",
            root=tmp_path,
            trusted_roots=(tmp_path,),
            prior_paths=(),
        )
    with pytest.raises(module.NativeCleanupRecoveryError, match="outside"):
        module._validate_resource_path(
            tmp_path.parent,
            "runtime_root",
            root=tmp_path,
            trusted_roots=(tmp_path,),
            prior_paths=(),
        )
    module._validate_resource_path(
        tmp_path / "child",
        "runtime_root",
        root=tmp_path,
        trusted_roots=(tmp_path,),
        prior_paths=(),
    )

    class FakePath:
        def is_absolute(self) -> bool:
            return True

        def is_symlink(self) -> bool:
            return False

        def resolve(self, *, strict: bool = False) -> Path:
            del strict
            return tmp_path / "different"

        def __fspath__(self) -> str:
            return str(tmp_path / "original")

    with pytest.raises(module.NativeCleanupRecoveryError, match="identity"):
        module._canonical(cast(Path, FakePath()))
    monkeypatch.setattr(Path, "is_symlink", lambda self: True)
    try:
        with pytest.raises(module.NativeCleanupRecoveryError, match="reparse"):
            module._canonical(tmp_path)
    finally:
        monkeypatch.undo()


def test_recovery_receipt_validation_rejects_each_binding_boundary(tmp_path: Path) -> None:
    module = cast(Any, recovery_module)
    cases: list[tuple[str, Any]] = [
        ("operation ID", lambda raw: raw.update(operation_id="not-a-uuid")),
        ("owner generation", lambda raw: raw["owner"].update(instance_id="bad")),
        ("owner PID", lambda raw: raw["owner"].update(pid=0)),
        ("resource class", lambda raw: raw["resource_binding"].update({"class": "bad"})),
        ("profile identity", lambda raw: raw["resource_binding"]["profile"].update(name="bad")),
        ("ACL resource set", lambda raw: raw["resource_binding"].update(acl=[])),
        ("baseline", lambda raw: raw["resource_binding"]["acl"][0].update(baseline_b64="%%%")),
        (
            "ACL/profile SID",
            lambda raw: raw["resource_binding"]["acl"][0].update(temporary_sid="S-1-15-2-9"),
        ),
        (
            "resource class",
            lambda raw: raw["resource_binding"]["acl"][0].update(resource_kind="unknown"),
        ),
        ("evidence", lambda raw: raw.update(evidence="bad")),
    ]
    for index, (label, mutate) in enumerate(cases):
        case_root = tmp_path / f"case-{index}"
        case_root.mkdir()
        receipt = _receipt(case_root)
        raw = json.loads(receipt.read_text(encoding="utf-8"))
        mutate(raw)
        raw["integrity"] = _sign({key: value for key, value in raw.items() if key != "integrity"})
        receipt.write_text(json.dumps(raw), encoding="utf-8")
        try:
            module.validate_receipt(
                receipt,
                sandbox_parent=receipt.parent.parent,
                trusted_roots=(receipt.parent.parent,),
                integrity_verifier=_verify,
            )
        except module.NativeCleanupRecoveryError:
            pass
        else:
            pytest.fail(f"validation case did not fail closed: {index}:{label}")

    outside = _receipt(tmp_path / "outside-case")
    with pytest.raises(module.NativeCleanupRecoveryError, match="outside"):
        module.validate_receipt(
            outside,
            sandbox_parent=tmp_path,
            trusted_roots=(tmp_path,),
            integrity_verifier=_verify,
        )

    invalid_name = _receipt(tmp_path / "invalid-name")
    invalid_root = invalid_name.parent.with_name("not-a-sandbox")
    invalid_name.parent.rename(invalid_root)
    with pytest.raises(module.NativeCleanupRecoveryError, match="identity"):
        module.validate_receipt(
            invalid_root / invalid_name.name,
            sandbox_parent=invalid_root.parent,
            trusted_roots=(invalid_root.parent,),
            integrity_verifier=_verify,
        )

    unavailable = _receipt(tmp_path / "unavailable")
    root = unavailable.parent
    shutil = __import__("shutil")
    shutil.rmtree(root)
    with pytest.raises(module.NativeCleanupRecoveryError, match="unavailable"):
        module.validate_receipt(
            unavailable,
            sandbox_parent=root.parent,
            trusted_roots=(root.parent,),
            integrity_verifier=_verify,
        )

    oversized = _receipt(tmp_path / "oversized")
    oversized.write_bytes(b"x" * (256 * 1024 + 1))
    with pytest.raises(module.NativeCleanupRecoveryError, match="size"):
        module.validate_receipt(
            oversized,
            sandbox_parent=oversized.parent.parent,
            trusted_roots=(oversized.parent.parent,),
            integrity_verifier=_verify,
        )

    unsupported = _receipt(tmp_path / "unsupported")
    unsupported.write_text("[]", encoding="utf-8")
    with pytest.raises(module.NativeCleanupRecoveryError, match="unsupported"):
        module.validate_receipt(
            unsupported,
            sandbox_parent=unsupported.parent.parent,
            trusted_roots=(unsupported.parent.parent,),
            integrity_verifier=_verify,
        )

    mismatch = _receipt(tmp_path / "binding-mismatch")
    mismatch_raw = json.loads(mismatch.read_text(encoding="utf-8"))
    mismatch_raw["resource_binding"]["sandbox_parent"] = str(tmp_path / "other")
    mismatch_raw["integrity"] = _sign(
        {key: value for key, value in mismatch_raw.items() if key != "integrity"}
    )
    mismatch.write_text(json.dumps(mismatch_raw), encoding="utf-8")
    with pytest.raises(module.NativeCleanupRecoveryError, match="binding"):
        module.validate_receipt(
            mismatch,
            sandbox_parent=mismatch.parent.parent,
            trusted_roots=(mismatch.parent.parent,),
            integrity_verifier=_verify,
        )

    evidence_mismatch = _receipt(tmp_path / "evidence-mismatch")
    evidence_raw = json.loads(evidence_mismatch.read_text(encoding="utf-8"))
    evidence_raw["evidence"]["cleanup_operation_id"] = "different"
    evidence_raw["integrity"] = _sign(
        {key: value for key, value in evidence_raw.items() if key != "integrity"}
    )
    evidence_mismatch.write_text(json.dumps(evidence_raw), encoding="utf-8")
    with pytest.raises(module.NativeCleanupRecoveryError, match="evidence"):
        module.validate_receipt(
            evidence_mismatch,
            sandbox_parent=evidence_mismatch.parent.parent,
            trusted_roots=(evidence_mismatch.parent.parent,),
            integrity_verifier=_verify,
        )


def test_recovery_native_operation_adapters_and_lock_boundaries(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    module = cast(Any, recovery_module)

    class Profile:
        def __init__(self, sid_text: str = SID) -> None:
            self.sid_text_value = sid_text
            self.closed: list[bool] = []

        def sid_text(self) -> str:
            return self.sid_text_value

        def sid_bytes(self) -> bytes:
            return b"sid"

        def close(self, delete: bool = True) -> str:
            self.closed.append(delete)
            if not delete and self.sid_text_value == "close-error":
                raise RuntimeError("close error")
            return "DELETED"

    profile = Profile()
    fake_profile = SimpleNamespace(derive=lambda name: profile)
    fake_acl = SimpleNamespace(
        observe=lambda path, baseline, sid: {"path": path},
        restore=lambda path, baseline: None,
    )
    monkeypatch.setattr(module, "_AppContainerProfile", fake_profile)
    monkeypatch.setattr(module, "_AppContainerAclLease", fake_acl)
    operations = module._WindowsRecoveryOperations()
    assert operations.observe_acl("path", BASELINE, b"sid") == {"path": "path"}
    operations.restore_acl("path", BASELINE)
    assert operations.profile_sid_bytes(PROFILE, SID) == b"sid"
    assert operations.reconcile_profile(PROFILE, SID) == ("DELETED", b"sid")

    mismatch = Profile("other")
    monkeypatch.setattr(
        module, "_AppContainerProfile", SimpleNamespace(derive=lambda name: mismatch)
    )
    with pytest.raises(module.NativeCleanupRecoveryError, match="binding"):
        operations.profile_sid_bytes(PROFILE, SID)
    with pytest.raises(module.NativeCleanupRecoveryError, match="binding"):
        operations.reconcile_profile(PROFILE, SID)

    lock = module._TransactionLock(tmp_path / "lock")
    assert lock.acquire()
    assert not lock.acquire()
    lock.release()
    lock.release()
    assert not module._TransactionLock(tmp_path / "missing" / "lock").acquire()

    fcntl = SimpleNamespace(
        LOCK_EX=1,
        LOCK_NB=2,
        LOCK_UN=4,
        flock=lambda handle, mode: None,
    )
    monkeypatch.setitem(sys.modules, "fcntl", fcntl)
    monkeypatch.setattr(module.os, "name", "posix")
    posix_lock = module._TransactionLock(tmp_path / "posix-lock")
    assert posix_lock.acquire()
    posix_lock.release()

    def fail_flock(handle: object, mode: object) -> None:
        del handle, mode
        raise OSError("lock busy")

    monkeypatch.setitem(
        sys.modules,
        "fcntl",
        SimpleNamespace(LOCK_EX=1, LOCK_NB=2, LOCK_UN=4, flock=fail_flock),
    )
    assert not module._TransactionLock(tmp_path / "busy-lock").acquire()


def test_recovery_reconciliation_blocks_on_postconditions_and_signer(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    module = cast(Any, recovery_module)
    receipt = _receipt(tmp_path)

    class DirtyForever(FakeOperations):
        def observe_acl(
            self, path: str, baseline: bytes, temporary_sid: bytes
        ) -> Mapping[str, object]:
            del path, baseline, temporary_sid
            return {"baseline_matches": False, "temporary_sid_present": True}

    blocked = _coordinator(receipt, DirtyForever()).reconcile_all()[0]
    assert blocked.state is RecoveryState.BLOCKED

    (tmp_path / "sid-change").mkdir()
    receipt = _receipt(tmp_path / "sid-change")

    class ChangedProfile(FakeOperations):
        def reconcile_profile(self, profile_name: str, expected_sid: str) -> tuple[str, bytes]:
            del profile_name, expected_sid
            return "DELETED", b"different"

    changed = _coordinator(receipt, ChangedProfile()).reconcile_all()[0]
    assert changed.state is RecoveryState.BLOCKED

    (tmp_path / "no-signer").mkdir()
    receipt = _receipt(tmp_path / "no-signer")
    coordinator = NativeCleanupRecoveryCoordinator(
        receipt.parent.parent,
        trusted_roots=(receipt.parent.parent,),
        operations=FakeOperations(),
        integrity_verifier=_verify,
    )
    with pytest.raises(module.NativeCleanupRecoveryError, match="signer"):
        coordinator.reconcile(receipt)

    with pytest.raises(ValueError, match="deadline"):
        NativeCleanupRecoveryCoordinator(tmp_path / "invalid", foreground_deadline_seconds=0)
    missing = NativeCleanupRecoveryCoordinator(tmp_path / "missing")
    assert missing.discover() == ()
    non_directory = tmp_path / "jarvis-sandbox-file"
    non_directory.write_text("not a directory", encoding="utf-8")
    assert missing.discover() == ()
    discovered = NativeCleanupRecoveryCoordinator(tmp_path).discover()
    assert all(item.parent != non_directory for item in discovered)

    fake_root = tmp_path / "fake-root"
    receipt_path = tmp_path / "fake-receipt.json"
    receipt_path.write_text("{}", encoding="utf-8")
    resource = module._AclResource(fake_root, "sandbox_root", BASELINE, SID)
    validated = module._ValidatedReceipt(
        receipt_path,
        fake_root,
        uuid4().hex,
        uuid4().hex,
        1,
        PROFILE,
        SID,
        (resource,),
        {},
    )
    direct = _coordinator(_receipt(tmp_path / "direct"), FakeOperations())
    result = direct._reconcile_validated(validated)  # noqa: SLF001
    assert result.state is RecoveryState.CONFIRMED

    child_root = tmp_path / "child-root"
    (child_root / "work").mkdir(parents=True)
    original_is_symlink = Path.is_symlink
    monkeypatch.setattr(
        Path,
        "is_symlink",
        lambda path: path.name == "work" or original_is_symlink(path),
    )
    with pytest.raises(module.NativeCleanupRecoveryError, match="reparse"):
        module.NativeCleanupRecoveryCoordinator._remove_owned_disposable_children(child_root)

    oversized_receipt = _receipt(tmp_path / "oversized-state")
    validated_oversized = module.validate_receipt(
        oversized_receipt,
        sandbox_parent=oversized_receipt.parent.parent,
        trusted_roots=(oversized_receipt.parent.parent,),
        integrity_verifier=_verify,
    )
    oversized_coordinator = NativeCleanupRecoveryCoordinator(
        oversized_receipt.parent.parent,
        operations=FakeOperations(),
        integrity_signer=lambda raw: "x" * 300_000,
        integrity_verifier=_verify,
    )
    with pytest.raises(module.NativeCleanupRecoveryError, match="bound"):
        oversized_coordinator._write_state(  # noqa: SLF001
            validated_oversized, RecoveryState.BLOCKED, {"state": "x"}
        )
