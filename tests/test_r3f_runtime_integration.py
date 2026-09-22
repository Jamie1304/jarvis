from __future__ import annotations

from pathlib import Path

import pytest
from jarvis.core.config import Settings
from jarvis.credentials import TestOnlyInMemorySecretBackend
from jarvis.human_adaptation import ConversationLanguageMode, LanguageTag, PersonalizationMode
from jarvis.runtime import ApplicationRuntime, RuntimeStatus


@pytest.mark.asyncio
async def test_application_runtime_constructs_and_restarts_human_adaptation(tmp_path: Path) -> None:
    settings = Settings(app_data_dir=tmp_path / "jarvis-data", ai_provider="ollama")
    recovery_backend = TestOnlyInMemorySecretBackend()
    runtime = ApplicationRuntime.create(settings, recovery_key_backend=recovery_backend)
    assert runtime.status is RuntimeStatus.READY
    assert runtime.container is not None
    container = runtime.container
    assert container.paths.human_adaptation_database.is_file()
    container.human_adaptation.set_language_preferences(
        interface_language=LanguageTag("nl"),
        locale="nl-NL",
        conversation_mode=ConversationLanguageMode.AUTO.value,
    )
    container.human_adaptation.configure_personalization(
        mode=PersonalizationMode.COMMUNICATION.value,
        learning_paused=True,
    )
    await runtime.aclose()

    restarted = ApplicationRuntime.create(settings, recovery_key_backend=recovery_backend)
    assert restarted.status is RuntimeStatus.READY
    assert restarted.container is not None
    assert (
        restarted.container.human_adaptation.language_preferences().interface_language
        == LanguageTag("nl")
    )
    assert (
        restarted.container.human_adaptation.personalization_settings()["learning_paused"] is True
    )
    await restarted.aclose()
