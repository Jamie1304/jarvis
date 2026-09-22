from pathlib import Path

import pytest
from jarvis.backup import BackupError, BackupService


def test_backup_identity_uses_stable_root_without_creating_legacy_identity(tmp_path: Path) -> None:
    backup = BackupService(
        tmp_path / "backups",
        identity_root=tmp_path / "config",
        legacy_identity_root=tmp_path / "backups",
    )

    assert (tmp_path / "config" / "installation-id").is_file()
    assert not (tmp_path / "backups" / "installation-id").exists()
    assert (
        BackupService(tmp_path / "backups", identity_root=tmp_path / "config").installation_id
        == backup.installation_id
    )


def test_backup_identity_migrates_matching_legacy_and_rejects_conflict(tmp_path: Path) -> None:
    legacy = tmp_path / "backups"
    legacy.mkdir()
    (legacy / "installation-id").write_text("installation-legacy", encoding="ascii")
    assert (
        BackupService(
            legacy, identity_root=tmp_path / "config", legacy_identity_root=legacy
        ).installation_id
        == "installation-legacy"
    )
    (legacy / "installation-id").write_text("installation-other", encoding="ascii")

    with pytest.raises(BackupError, match="disagree"):
        BackupService(legacy, identity_root=tmp_path / "config", legacy_identity_root=legacy)
