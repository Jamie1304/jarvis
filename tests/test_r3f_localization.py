from __future__ import annotations

import pytest
from jarvis.human_adaptation import LanguageTag, load_default_localizer


def test_english_and_dutch_core_bundles_and_fallback() -> None:
    localizer = load_default_localizer()
    assert localizer.translate("app.settings", "en") == "Settings"
    assert localizer.translate("app.settings", "nl") == "Instellingen"
    assert localizer.translate("task.completed", "fr") == "Task completed"
    assert localizer.translate("not.present", LanguageTag("nl")) == "[not.present]"


def test_localization_interpolation_is_named_and_bounded() -> None:
    localizer = load_default_localizer()
    assert "write" in localizer.translate(
        "permission.request", "en", permission="filesystem.write", action="write"
    )
    with pytest.raises(ValueError):
        localizer.translate("permission.request", "en", permission="write")
    with pytest.raises(TypeError):
        localizer.translate("permission.request", "en", permission=object(), action="write")
