from __future__ import annotations

from pathlib import Path

import pytest
from jarvis.core.environment_settings import (
    EnvironmentSettingDescriptor,
    EnvironmentSettingsService,
)


def _descriptor(service: EnvironmentSettingsService, name: str) -> EnvironmentSettingDescriptor:
    return next(item for item in service.descriptors() if item.name == name)


def test_environment_settings_round_trip_preserves_unknown_lines(tmp_path: Path) -> None:
    path = tmp_path / ".env"
    path.write_text("# local notes\nOTHER_VALUE=preserved\nJARVIS_PORT=8010\n", encoding="utf-8")
    service = EnvironmentSettingsService(env_file=path)

    service.save({"port": 8011, "log_json": True})

    assert "# local notes" in path.read_text(encoding="utf-8")
    assert "OTHER_VALUE=preserved" in path.read_text(encoding="utf-8")
    assert "JARVIS_PORT=8011" in path.read_text(encoding="utf-8")
    assert _descriptor(service, "port").saved_value == "8011"


def test_environment_settings_reports_process_override(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    path = tmp_path / ".env"
    path.write_text("JARVIS_PORT=8010\n", encoding="utf-8")
    monkeypatch.setenv("JARVIS_PORT", "8020")
    service = EnvironmentSettingsService(env_file=path)

    port = _descriptor(service, "port")

    assert port.value == 8020
    assert port.saved_value == "8010"
    assert port.source == "process environment"


def test_environment_settings_masks_unknown_secret_like_values(tmp_path: Path) -> None:
    path = tmp_path / ".env"
    path.write_text("JARVIS_PRIVATE_KEY=private-value\n", encoding="utf-8")
    service = EnvironmentSettingsService(env_file=path)

    private_key = _descriptor(service, "JARVIS_PRIVATE_KEY")

    assert private_key.value == "********"
    assert private_key.saved_value == "********"
    assert private_key.secret is True
    assert private_key.editable is False


def test_environment_settings_rejects_invalid_value_without_corrupting_file(tmp_path: Path) -> None:
    path = tmp_path / ".env"
    original = "JARVIS_PORT=8010\n"
    path.write_text(original, encoding="utf-8")
    service = EnvironmentSettingsService(env_file=path)

    with pytest.raises(ValueError):
        service.save({"port": "not-a-port"})

    assert path.read_text(encoding="utf-8") == original


def test_environment_settings_unsets_optional_value_without_serializing_none(
    tmp_path: Path,
) -> None:
    path = tmp_path / ".env"
    path.write_text("JARVIS_TTS_VOICE=old-voice\n", encoding="utf-8")
    service = EnvironmentSettingsService(env_file=path)

    service.save({"tts_voice": None})

    assert "JARVIS_TTS_VOICE" not in path.read_text(encoding="utf-8")
    assert _descriptor(service, "tts_voice").saved_value is None
