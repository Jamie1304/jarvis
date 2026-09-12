"""Security and lifecycle contracts for user-facing encrypted backups."""

from __future__ import annotations

import base64
import json
from datetime import UTC, datetime
from pathlib import Path
from uuid import uuid4

import pytest
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from jarvis import backup as backup_module
from jarvis.backup import (
    BackupClassification,
    BackupCompatibilityError,
    BackupComponent,
    BackupComponentInfo,
    BackupError,
    BackupIntegrityError,
    BackupMigrationRequired,
    BackupPolicy,
    BackupReauthorizationRequired,
    BackupRecertificationRequired,
    BackupRelinkRequired,
    BackupRestoreError,
    BackupService,
    MigrationReport,
    RestoreMode,
    RestorePlan,
)


def _component(
    component_id: str,
    payload: bytes = b"payload",
    *,
    version: str = "1",
    source_reference: str = "",
    classification: BackupClassification = BackupClassification.INTERNAL,
    external_paths: tuple[str, ...] = (),
    credential_references: tuple[str, ...] = (),
    machine_bound: bool = False,
    requires_recertification: bool = False,
    is_cache: bool = False,
    is_model_file: bool = False,
) -> BackupComponent:
    return BackupComponent(
        component_id,
        version,
        payload,
        source_reference,
        classification,
        external_paths,
        credential_references,
        machine_bound,
        requires_recertification,
        is_cache,
        is_model_file,
    )


def test_backup_is_encrypted_authenticated_and_wrong_key_fails(tmp_path: Path) -> None:
    service = BackupService(tmp_path / "backups", installation_id="machine-a")
    source = _component("settings_privacy", b"private settings")
    path = tmp_path / "export.jarvis-backup"

    bundle = service.create_bundle(path, password="correct horse", components=(source,))

    raw = path.read_bytes()
    assert b"private settings" not in raw
    assert b"correct horse" not in raw
    opened = service.open_bundle(path, password="correct horse")
    assert opened.manifest.bundle_id == bundle.manifest.bundle_id
    assert opened.payload("settings_privacy") == source.payload
    with pytest.raises(BackupIntegrityError):
        service.open_bundle(path, password="wrong horse")
    with pytest.raises(BackupError):
        service.create_bundle(path, password="correct horse", components=(source,))
    destination_directory = tmp_path / "destination-directory"
    destination_directory.mkdir()
    with pytest.raises(BackupError):
        service.create_bundle(
            destination_directory,
            password="correct horse",
            components=(source,),
        )


def test_tampered_ciphertext_and_secret_components_fail_closed(tmp_path: Path) -> None:
    service = BackupService(tmp_path / "backups", installation_id="machine-a")
    path = tmp_path / "tampered.jarvis-backup"
    service.create_bundle(path, password="passphrase", components=(_component("ui"),))
    envelope = json.loads(path.read_text(encoding="utf-8"))
    ciphertext = str(envelope["ciphertext"])
    envelope["ciphertext"] = ("A" if ciphertext[0] != "A" else "B") + ciphertext[1:]
    path.write_text(json.dumps(envelope), encoding="utf-8")
    with pytest.raises(BackupIntegrityError):
        service.open_bundle(path, password="passphrase")

    with pytest.raises(BackupError, match="Credential secrets"):
        _component("credentials", b"secret")
    with pytest.raises(BackupError, match="password"):
        service.create_bundle(
            tmp_path / "empty-password.jarvis-backup",
            password="",
            components=(_component("ui"),),
        )


def test_policy_excludes_model_files_and_caches_by_default(tmp_path: Path) -> None:
    service = BackupService(tmp_path / "backups", installation_id="machine-a")
    settings = _component("settings_privacy")
    model = _component("model_files", b"large model", is_model_file=True)
    cache = _component("generated_caches", b"cache", is_cache=True)
    path = tmp_path / "selected.jarvis-backup"

    bundle = service.create_bundle(
        path,
        password="passphrase",
        components=(settings, model, cache),
        policy=BackupPolicy(),
    )
    assert [item.component_id for item in bundle.manifest.components] == ["settings_privacy"]

    explicit = service.create_bundle(
        tmp_path / "explicit.jarvis-backup",
        password="passphrase",
        components=(model, cache),
        policy=BackupPolicy(
            selected_components=("model_files", "generated_caches"),
            include_model_files=True,
            include_caches=True,
        ),
    )
    assert {item.component_id for item in explicit.manifest.components} == {
        "model_files",
        "generated_caches",
    }


def test_selective_restore_uses_only_selected_component_and_applier(tmp_path: Path) -> None:
    source = BackupService(tmp_path / "source", installation_id="machine-a")
    policy = BackupPolicy(selected_components=("settings_privacy", "artifacts"))
    bundle = source.create_bundle(
        tmp_path / "selective.jarvis-backup",
        password="passphrase",
        components=(_component("settings_privacy"), _component("artifacts", b"artifact")),
        policy=policy,
    )
    target = BackupService(tmp_path / "target", installation_id="machine-a")
    applied: list[tuple[str, bytes]] = []

    plan, report = target.restore(
        bundle,
        selected_components=("settings_privacy",),
        apply=lambda identifier, payload: applied.append((identifier, payload)),
    )

    assert plan.mode.value == "selective"
    assert applied == [("settings_privacy", b"payload")]
    assert report.success


def test_cross_machine_requires_reauthorization_and_generated_recertification(
    tmp_path: Path,
) -> None:
    source = BackupService(tmp_path / "source", installation_id="machine-a")
    bundle = source.create_bundle(
        tmp_path / "cross-machine.jarvis-backup",
        password="passphrase",
        components=(
            _component(
                "user_model_memory",
                credential_references=("credential-ref-1",),
                machine_bound=True,
            ),
            _component("generated_integrations", requires_recertification=True),
        ),
        policy=BackupPolicy(
            selected_components=("user_model_memory", "generated_integrations"),
        ),
    )
    target = BackupService(tmp_path / "target", installation_id="machine-b")
    plan = target.preview_restore(bundle, current_installation_id="machine-b")
    assert plan.reauthorization_required == ("user_model_memory",)
    assert plan.recertification_required == ("generated_integrations",)
    with pytest.raises(BackupReauthorizationRequired):
        target.restore(
            bundle,
            current_installation_id="machine-b",
            apply=lambda _identifier, _payload: None,
        )

    applied: list[str] = []
    target.restore(
        bundle,
        current_installation_id="machine-b",
        reauthorize=lambda _info: True,
        recertify=lambda _info: True,
        apply=lambda identifier, _payload: applied.append(identifier),
    )
    assert applied == ["user_model_memory", "generated_integrations"]


def test_external_source_requires_explicit_relink_and_missing_source_is_not_imported(
    tmp_path: Path,
) -> None:
    source = BackupService(tmp_path / "source", installation_id="machine-a")
    bundle = source.create_bundle(
        tmp_path / "knowledge.jarvis-backup",
        password="passphrase",
        components=(
            _component(
                "knowledge_metadata_indexes",
                b"index metadata",
                external_paths=("C:/old/library",),
            ),
        ),
        policy=BackupPolicy(selected_components=("knowledge_metadata_indexes",)),
    )
    target = BackupService(tmp_path / "target", installation_id="machine-a")
    plan = target.preview_restore(bundle, path_exists=lambda _path: False)
    assert plan.relink_required == ("knowledge_metadata_indexes",)
    with pytest.raises(BackupRelinkRequired):
        target.restore(bundle, path_exists=lambda _path: False, apply=lambda *_: None)
    applied: list[str] = []
    target.restore(
        bundle,
        path_exists=lambda _path: False,
        relink=lambda _info: True,
        apply=lambda identifier, _payload: applied.append(identifier),
    )
    assert applied == ["knowledge_metadata_indexes"]


def test_migration_conflict_and_restore_failure_roll_back_technical_snapshot(
    tmp_path: Path,
) -> None:
    source = BackupService(tmp_path / "source", installation_id="machine-a")
    bundle = source.create_bundle(
        tmp_path / "migration.jarvis-backup",
        password="passphrase",
        components=(_component("settings_privacy", b"new", version="2"),),
        policy=BackupPolicy(selected_components=("settings_privacy",)),
    )
    target = BackupService(tmp_path / "target", installation_id="machine-a")
    old = _component("settings_privacy", b"old", version="1")
    existing_info = BackupComponentInfo(
        old.component_id,
        old.version,
        len(old.payload),
        "0" * 64,
        "settings.sqlite3",
        BackupClassification.INTERNAL,
        (),
        (),
        False,
        False,
        False,
        False,
        False,
    )
    with pytest.raises(BackupRestoreError):
        target.restore(
            bundle,
            existing_components={"settings_privacy": existing_info},
            resolve_conflict=lambda _info: True,
            apply=lambda *_: None,
        )

    calls: list[str] = []

    def snapshot(_plan: object) -> str:
        calls.append("snapshot")
        return "token"

    with pytest.raises(BackupRestoreError) as failure:
        target.restore(
            bundle,
            existing_components={"settings_privacy": existing_info},
            resolve_conflict=lambda _info: True,
            snapshot=snapshot,
            rollback=lambda _token: calls.append("rollback"),
            migrate=lambda _info, _payload: b"migrated",
            apply=lambda _identifier, _payload: (_ for _ in ()).throw(RuntimeError("disk")),
        )
    assert calls == ["snapshot", "rollback"]
    assert failure.value.report is not None
    assert not failure.value.report.success


def test_legacy_manifest_migrates_and_future_manifest_refuses(tmp_path: Path) -> None:
    service = BackupService(tmp_path / "backups", installation_id="machine-a")
    for version, expected in ((0, "migrated"), (99, "future")):
        path = tmp_path / f"legacy-{version}.jarvis-backup"
        _write_test_envelope(path, version)
        if version == 0:
            bundle = service.open_bundle(path, password="passphrase")
            assert bundle.migration_report.warnings
            assert expected == "migrated"
        else:
            with pytest.raises(BackupCompatibilityError):
                service.open_bundle(path, password="passphrase")


def test_contracts_and_component_registration_reject_malformed_values(tmp_path: Path) -> None:
    with pytest.raises(BackupError):
        _component("ui", bytearray(b"not bytes"))
    with pytest.raises(BackupError):
        BackupComponent("ui", "1", b"x", classification="internal")  # type: ignore[arg-type]
    with pytest.raises(BackupError):
        BackupComponent("ui", "1", b"x", machine_bound="yes")  # type: ignore[arg-type]
    with pytest.raises(BackupError):
        BackupComponent("ui", "1", b"x", is_cache="yes")  # type: ignore[arg-type]
    with pytest.raises(BackupError):
        BackupComponent("ui", "1", b"x", external_paths=("",))
    with pytest.raises(BackupError):
        BackupComponent("ui", "1", b"x", credential_references=("",))

    info = backup_module._component_info(_component("ui"))
    with pytest.raises(BackupError):
        backup_module.BackupManifest(1, object(), datetime.now(UTC), None, (info,))  # type: ignore[arg-type]
    with pytest.raises(BackupError):
        backup_module.BackupManifest(1, uuid4(), datetime.now(), None, (info,))
    with pytest.raises(BackupError):
        backup_module.BackupManifest(1, uuid4(), datetime.now(UTC), None, [info])  # type: ignore[arg-type]
    with pytest.raises(BackupError):
        backup_module.BackupManifest(1, uuid4(), datetime.now(UTC), None, (info,), False)
    with pytest.raises(BackupError):
        MigrationReport(-1, 1)
    with pytest.raises(BackupError):
        BackupPolicy(selected_components=("ui", "ui"))
    with pytest.raises(BackupError):
        BackupPolicy(include_caches=1)  # type: ignore[arg-type]
    with pytest.raises(BackupError):
        BackupPolicy(max_component_bytes=0)
    with pytest.raises(BackupError):
        RestorePlan(
            object(),  # type: ignore[arg-type]
            RestoreMode.SELECTIVE,
            (),
            (),
            (),
            (),
            (),
            (),
            False,
            False,
            True,
            None,
            None,
        )

    service = BackupService(tmp_path / "backups", installation_id="machine-a")
    assert service.collect() == ()
    service.register_component_source("ui", lambda: _component("ui"))
    assert service.collect()[0].component_id == "ui"
    with pytest.raises(BackupError):
        service.register_component_source("", lambda: _component("ui"))
    with pytest.raises(BackupError):
        service.register_component_source("bad", None)  # type: ignore[arg-type]
    with pytest.raises(BackupError):
        service.register_component_applier("bad", None)  # type: ignore[arg-type]

    broken = BackupService(
        tmp_path / "broken",
        installation_id="machine-a",
        component_sources={"ui": lambda: _component("other")},
    )
    with pytest.raises(BackupError):
        broken.collect()
    with pytest.raises(BackupError):
        service.create_bundle(
            tmp_path / "duplicate.jarvis-backup",
            password="passphrase",
            components=(_component("ui"), _component("ui")),
        )


def test_backup_path_envelope_and_payload_validation_fail_closed(tmp_path: Path) -> None:
    service = BackupService(tmp_path / "backups", installation_id="machine-a")
    missing = tmp_path / "missing.jarvis-backup"
    with pytest.raises(BackupIntegrityError):
        service.open_bundle(missing, password="passphrase")
    directory = tmp_path / "directory.jarvis-backup"
    directory.mkdir()
    with pytest.raises(BackupIntegrityError):
        service.open_bundle(directory, password="passphrase")
    malformed = tmp_path / "malformed.jarvis-backup"
    malformed.write_text("not json", encoding="utf-8")
    with pytest.raises(BackupIntegrityError):
        service.open_bundle(malformed, password="passphrase")

    invalid_header = tmp_path / "invalid-header.jarvis-backup"
    _write_test_envelope(invalid_header, 1, header_updates={"format": "other"})
    with pytest.raises(BackupIntegrityError):
        service.open_bundle(invalid_header, password="passphrase")
    invalid_crypto = tmp_path / "invalid-crypto.jarvis-backup"
    _write_test_envelope(invalid_crypto, 1, header_updates={"kdf": "other"})
    with pytest.raises(BackupCompatibilityError):
        service.open_bundle(invalid_crypto, password="passphrase")
    invalid_encoding = tmp_path / "invalid-encoding.jarvis-backup"
    _write_test_envelope(invalid_encoding, 1, header_updates={"salt": "bad"})
    with pytest.raises(BackupIntegrityError):
        service.open_bundle(invalid_encoding, password="passphrase")

    payload_manifest = {
        "format_version": 1,
        "bundle_id": str(uuid4()),
        "created_at": datetime.now(UTC).isoformat(),
        "source_installation_id": "machine-a",
        "encrypted": True,
        "components": [
            {
                "component_id": "ui",
                "version": "1",
                "size_bytes": 1,
                "sha256": "0" * 64,
                "classification": "internal",
            }
        ],
    }
    bad_payload = tmp_path / "bad-payload.jarvis-backup"
    _write_test_envelope(
        bad_payload,
        1,
        manifest=payload_manifest,
        payloads={"ui": "!not-base64!"},
    )
    with pytest.raises(BackupIntegrityError):
        service.open_bundle(bad_payload, password="passphrase")

    oversized = tmp_path / "oversized.jarvis-backup"
    oversized.write_bytes(b"0")
    oversized.write_bytes(b"0" * (128 * 1024 * 1024 + 1))
    with pytest.raises(BackupIntegrityError):
        service.open_bundle(oversized, password="passphrase")


def test_preview_and_restore_require_explicit_decisions_and_appliers(tmp_path: Path) -> None:
    source = BackupService(tmp_path / "source", installation_id="machine-a")
    bundle = source.create_bundle(
        tmp_path / "decisions.jarvis-backup",
        password="passphrase",
        components=(_component("generated_integrations", requires_recertification=True),),
        policy=BackupPolicy(selected_components=("generated_integrations",)),
    )
    target = BackupService(tmp_path / "target", installation_id="machine-b")
    with pytest.raises(BackupRecertificationRequired):
        target.restore(bundle, current_installation_id="machine-b", apply=lambda *_: None)
    with pytest.raises(BackupError):
        target.preview_restore(bundle, selected_components=("missing",))
    with pytest.raises(BackupError):
        target.preview_restore(object())  # type: ignore[arg-type]
    with pytest.raises(BackupError):
        target.restore(
            bundle,
            current_installation_id="machine-b",
            recertify=lambda _info: True,
        )

    source = BackupService(tmp_path / "versioned-source", installation_id="machine-a")
    versioned = source.create_bundle(
        tmp_path / "versioned.jarvis-backup",
        password="passphrase",
        components=(_component("ui", version="2"),),
        policy=BackupPolicy(selected_components=("ui",)),
    )
    existing = _component("ui", version="1")
    with pytest.raises(BackupRestoreError) as missing_migration:
        target.restore(
            versioned,
            existing_components={"ui": existing},
            resolve_conflict=lambda _info: True,
            snapshot=lambda _plan: "token",
            rollback=lambda _token: None,
            apply=lambda *_: None,
        )
    assert isinstance(missing_migration.value.__cause__, BackupMigrationRequired)
    with pytest.raises(BackupRestoreError):
        target.restore(
            versioned,
            existing_components={"ui": existing},
            resolve_conflict=lambda _info: True,
            snapshot=lambda _plan: "token",
            rollback=lambda _token: None,
            migrate=lambda _info, _payload: b"migrated",
        )
    with pytest.raises(BackupError):
        target.restore(
            versioned,
            existing_components={"ui": existing},
            resolve_conflict=lambda _info: False,
            snapshot=lambda _plan: "token",
            rollback=lambda _token: None,
            migrate=lambda _info, _payload: b"migrated",
            apply=lambda *_: None,
        )

    same = source.create_bundle(
        tmp_path / "same.jarvis-backup",
        password="passphrase",
        components=(_component("ui"),),
        policy=BackupPolicy(selected_components=("ui",)),
    )
    info = same.manifest.components[0]
    with pytest.raises(BackupRestoreError):
        target.restore(same, existing_components={"ui": info}, apply=lambda *_: None)
    with pytest.raises(BackupRestoreError):
        target.restore(same)


def test_restore_rolls_back_on_unexpected_failure_and_reports_rollback_failure(
    tmp_path: Path,
) -> None:
    source = BackupService(tmp_path / "source", installation_id="machine-a")
    bundle = source.create_bundle(
        tmp_path / "failure.jarvis-backup",
        password="passphrase",
        components=(_component("ui"),),
        policy=BackupPolicy(selected_components=("ui",)),
    )
    target = BackupService(tmp_path / "target", installation_id="machine-a")
    with pytest.raises(BackupRestoreError) as failure:
        target.restore(
            bundle,
            existing_components={"ui": bundle.manifest.components[0]},
            snapshot=lambda _plan: "token",
            rollback=lambda _token: (_ for _ in ()).throw(RuntimeError("rollback")),
            apply=lambda _identifier, _payload: (_ for _ in ()).throw(RuntimeError("apply")),
        )
    assert "rollback" in str(failure.value)
    assert failure.value.report is not None
    assert failure.value.report.errors


def test_installation_identity_is_reused_and_password_bounds_are_enforced(tmp_path: Path) -> None:
    root = tmp_path / "backups"
    first = BackupService(root)
    second = BackupService(root)
    assert first.installation_id == second.installation_id
    with pytest.raises(BackupError):
        first.create_bundle(
            tmp_path / "long-password.jarvis-backup",
            password="x" * 1025,
            components=(_component("ui"),),
        )
    with pytest.raises(BackupError):
        first.create_bundle(
            tmp_path / "small-bundle.jarvis-backup",
            password="passphrase",
            components=(_component("ui", b"payload"),),
            policy=BackupPolicy(selected_components=("ui",), max_bundle_bytes=1),
        )


def _write_test_envelope(
    path: Path,
    manifest_version: int,
    *,
    manifest: dict[str, object] | None = None,
    payloads: dict[str, object] | None = None,
    header_updates: dict[str, object] | None = None,
) -> None:
    manifest = manifest or {
        "format_version": manifest_version,
        "bundle_id": str(uuid4()),
        "created_at": datetime.now(UTC).isoformat(),
        "source_installation_id": "machine-a",
        "encrypted": True,
        "components": [],
    }
    manifest["format_version"] = manifest_version
    plaintext = json.dumps(
        {"manifest": manifest, "payloads": payloads or {}},
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")
    salt = b"0" * backup_module._SALT_BYTES
    nonce = b"1" * backup_module._NONCE_BYTES
    header = {
        "format": "jarvis-backup",
        "format_version": 1,
        "kdf": "PBKDF2-HMAC-SHA256",
        "iterations": backup_module._PBKDF2_ITERATIONS,
        "salt": base64.b64encode(salt).decode("ascii"),
        "cipher": "AES-256-GCM",
        "nonce": base64.b64encode(nonce).decode("ascii"),
    }
    header.update(header_updates or {})
    ciphertext = AESGCM(backup_module._derive_key("passphrase", salt)).encrypt(
        nonce, plaintext, backup_module._canonical(header)
    )
    path.write_text(
        json.dumps(
            {**header, "ciphertext": base64.b64encode(ciphertext).decode("ascii")},
            sort_keys=True,
        ),
        encoding="utf-8",
    )
