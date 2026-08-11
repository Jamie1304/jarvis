"""Typed, environment-aware application settings."""

from functools import lru_cache
from typing import Literal

from pydantic import Field, field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    """Application settings with environment variables taking precedence over .env values."""

    model_config = SettingsConfigDict(
        env_prefix="JARVIS_",
        env_file=".env",
        env_file_encoding="utf-8",
        case_sensitive=False,
        extra="ignore",
    )

    environment: Literal["local", "test", "production"] = "local"
    host: str = "127.0.0.1"
    port: int = 8000
    log_level: str = "INFO"
    log_json: bool = False
    version: str = "0.1.0"
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
    agent_max_steps: int = Field(default=8, gt=0, le=32)
    agent_timeout_seconds: float = Field(default=30.0, gt=0, le=300)
    agent_max_replans: int = Field(default=2, ge=0, le=8)

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
