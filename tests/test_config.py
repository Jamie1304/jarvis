from jarvis.core.config import Settings
from pytest import MonkeyPatch


def test_settings_have_safe_local_defaults(monkeypatch: MonkeyPatch) -> None:
    for name in (
        "JARVIS_ENVIRONMENT",
        "JARVIS_HOST",
        "JARVIS_PORT",
        "JARVIS_LOG_LEVEL",
        "JARVIS_AI_PROVIDER",
        "JARVIS_STT_ENABLED",
        "JARVIS_TTS_ENABLED",
        "JARVIS_AGENT_MAX_STEPS",
        "JARVIS_AGENT_TIMEOUT_SECONDS",
        "JARVIS_AGENT_MAX_REPLANS",
        "JARVIS_MULTI_AGENT_ENABLED",
        "JARVIS_MULTI_AGENT_MAX_CONCURRENCY",
        "JARVIS_MULTI_AGENT_TIMEOUT_SECONDS",
    ):
        monkeypatch.delenv(name, raising=False)
    settings = Settings(_env_file=None)

    assert settings.environment == "local"
    assert settings.host == "127.0.0.1"
    assert settings.port == 8000
    assert settings.log_level == "INFO"
    assert settings.ai_provider == "ollama"
    assert settings.stt_enabled is False
    assert settings.stt_compute_device == "cpu"
    assert settings.stt_compute_type == "int8"
    assert settings.tts_enabled is False
    assert settings.agent_max_steps == 8
    assert settings.multi_agent_enabled is False
    assert settings.multi_agent_max_concurrency == 3


def test_environment_values_override_defaults(monkeypatch: MonkeyPatch) -> None:
    monkeypatch.setenv("JARVIS_ENVIRONMENT", "test")
    monkeypatch.setenv("JARVIS_PORT", "9000")

    settings = Settings(_env_file=None)

    assert settings.environment == "test"
    assert settings.port == 9000


def test_blank_stt_device_uses_default_input(monkeypatch: MonkeyPatch) -> None:
    monkeypatch.setenv("JARVIS_STT_DEVICE", "")

    settings = Settings(_env_file=None)

    assert settings.stt_device is None


def test_numeric_stt_device_becomes_device_id(monkeypatch: MonkeyPatch) -> None:
    monkeypatch.setenv("JARVIS_STT_DEVICE", "26")

    settings = Settings(_env_file=None)

    assert settings.stt_device == 26
