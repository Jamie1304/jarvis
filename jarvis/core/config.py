"""Typed, environment-aware application settings."""

from functools import lru_cache
from pathlib import Path
from typing import Literal

from pydantic import Field, field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict

from jarvis.version import __version__


class Settings(BaseSettings):
    """Application settings read from explicit process configuration and safe defaults."""

    model_config = SettingsConfigDict(
        env_prefix="JARVIS_",
        env_file=None,
        case_sensitive=False,
        extra="ignore",
    )

    environment: Literal["local", "test", "production"] = "local"
    host: str = "127.0.0.1"
    port: int = 8000
    log_level: str = "INFO"
    log_json: bool = False
    version: str = __version__
    ai_provider: str = "ollama"
    ai_model: str = "llama3.2:3b"
    ai_endpoint: str = "http://127.0.0.1:11434"
    ai_timeout_seconds: float = Field(default=60.0, gt=0)
    ai_context_limit: int = Field(default=4096, gt=0)
    stt_enabled: bool = False
    stt_model: str = "base"
    stt_device: int | str | None = None
    stt_compute_device: Literal["cpu", "cuda"] = "cpu"
    stt_compute_type: str = "int8"
    stt_sample_rate: int = Field(default=16_000, gt=0)
    tts_enabled: bool = False
    tts_voice: str | None = None
    voice_enabled: bool = False
    voice_wake_word: str = "Jarvis"
    voice_wake_confidence_threshold: float = Field(default=0.8, ge=0, le=1)
    voice_cooldown_seconds: float = Field(default=1.0, ge=0, le=60)
    agent_max_steps: int = Field(default=8, gt=0, le=32)
    agent_timeout_seconds: float = Field(default=30.0, gt=0, le=300)
    agent_max_replans: int = Field(default=2, ge=0, le=8)
    multi_agent_enabled: bool = False
    multi_agent_max_concurrency: int = Field(default=3, gt=0, le=16)
    multi_agent_timeout_seconds: float = Field(default=120.0, gt=0, le=3_600)
    app_data_dir: Path = Path(".jarvis")
    mcp_enabled: bool = False
    mcp_config_path: Path | None = None
    computer_enabled: bool = False
    camera_enabled: bool = False
    application_management_enabled: bool = False
    package_installation_enabled: bool = False
    discovery_enabled: bool = True
    improvement_enabled: bool = False
    remote_approval_enabled: bool = False
    autonomous_scheduling_enabled: bool = False
    security_policy_version: int = Field(default=1, ge=1)

    @field_validator("stt_device", mode="before")
    @classmethod
    def normalize_stt_device(cls, value: object) -> int | str | None:
        """Treat a blank environment variable as the default input device."""

        if value is None:
            return None
        if isinstance(value, str):
            normalized = value.strip()
            if not normalized:
                return None
            if normalized.isdecimal():
                return int(normalized)
            return normalized
        if isinstance(value, int):
            return value
        raise ValueError("STT device must be a device name or numeric device ID")


@lru_cache(maxsize=1)
def get_settings() -> Settings:
    """Return the process-wide settings instance."""

    return Settings()
