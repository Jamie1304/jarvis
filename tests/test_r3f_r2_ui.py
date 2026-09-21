from __future__ import annotations

import os
from pathlib import Path
from typing import Any, cast

import pytest
from jarvis.bootstrap import create_application_runtime, create_desktop_facade_from_runtime
from jarvis.core.config import Settings
from jarvis.frontend.desktop import run_desktop_app
from jarvis.frontend.desktop_backend import DesktopBackendHost

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")
pytest.importorskip("PySide6")
from PySide6.QtCore import QTimer  # noqa: E402
from PySide6.QtWidgets import (  # noqa: E402
    QApplication,
    QComboBox,
    QMainWindow,
    QPushButton,
    QWidget,
)


def test_real_settings_surface_persists_language_and_personalization(
    tmp_path: Path,
) -> None:
    application = QApplication.instance()
    app: QApplication = application if isinstance(application, QApplication) else QApplication([])
    settings = Settings(
        app_data_dir=tmp_path / "data", ai_provider="ollama", ollama_autostart=False
    )
    backend = DesktopBackendHost(
        lambda: create_application_runtime(settings), create_desktop_facade_from_runtime
    )
    observed: dict[str, Any] = {}

    def drive() -> None:
        window: Any = next(
            widget
            for widget in app.topLevelWidgets()
            if isinstance(widget, QMainWindow) and widget.isVisible()
        )
        settings_button: QPushButton | None = None
        for candidate in cast(list[QPushButton], window.findChildren(QPushButton)):
            if candidate.text() == "Settings":
                settings_button = candidate
                break
        assert settings_button is not None
        settings_button.click()
        required = {
            "r3f-interface-language",
            "r3f-locale",
            "r3f-conversation-language",
            "r3f-conversation-mode",
            "r3f-stt-language",
            "r3f-tts-language",
            "r3f-personalization-depth",
            "r3f-learning-paused",
            "r3f-pins",
            "r3f-learned-state",
        }
        controls: set[str] = set()
        for item in cast(list[QWidget], window.findChildren(QWidget)):
            if item.objectName():
                controls.add(item.objectName())
        observed["controls"] = controls
        observed["required"] = required <= observed["controls"]
        interface = window.findChild(QComboBox, "r3f-interface-language")
        locale = window.findChild(QComboBox, "r3f-locale")
        conversation = window.findChild(QComboBox, "r3f-conversation-language")
        mode = window.findChild(QComboBox, "r3f-conversation-mode")
        depth = window.findChild(QComboBox, "r3f-personalization-depth")
        save_language = window.findChild(QPushButton, "r3f-save-language")
        save_personalization = window.findChild(QPushButton, "r3f-save-personalization")
        assert all(item is not None for item in (interface, locale, conversation, mode, depth))
        assert save_language is not None and save_personalization is not None
        interface.setCurrentIndex(1)
        locale.setCurrentText("nl-NL")
        conversation.setCurrentIndex(2)
        mode.setCurrentText("Fixed")
        depth.setCurrentText("Communication")
        save_language.click()
        QTimer.singleShot(100, lambda: save_personalization.click())

        def verify() -> None:
            observed["language"] = backend.submit(
                lambda service: service.language_preferences()
            ).result(timeout=2)
            observed["personalization"] = backend.submit(
                lambda service: service.personalization()
            ).result(timeout=2)
            observed["dutch_settings"] = any(
                button.text() == "Instellingen"
                for button in cast(list[QPushButton], window.findChildren(QPushButton))
            )
            window.close()
            app.quit()

        QTimer.singleShot(250, verify)

    QTimer.singleShot(0, drive)
    assert run_desktop_app(backend) == 0
    assert observed["required"] is True
    assert observed["language"]["interface_language"] == "nl"
    assert observed["language"]["locale"] == "nl-NL"
    assert observed["language"]["conversation_language"] == "nl"
    assert observed["personalization"]["personalization"]["mode"] == "communication"
    assert observed["dutch_settings"] is True


def test_real_settings_surface_captures_english_and_dutch_review_screenshots(
    tmp_path: Path,
) -> None:
    application = QApplication.instance()
    app: QApplication = application if isinstance(application, QApplication) else QApplication([])
    settings = Settings(
        app_data_dir=tmp_path / "data", ai_provider="ollama", ollama_autostart=False
    )
    backend = DesktopBackendHost(
        lambda: create_application_runtime(settings), create_desktop_facade_from_runtime
    )
    observed: dict[str, Any] = {}
    artifact_dir = Path("artifacts/development")
    artifact_dir.mkdir(parents=True, exist_ok=True)

    def drive() -> None:
        window: Any = next(
            widget
            for widget in app.topLevelWidgets()
            if isinstance(widget, QMainWindow) and widget.isVisible()
        )
        settings_button: QPushButton | None = None
        for candidate in cast(list[QPushButton], window.findChildren(QPushButton)):
            if candidate.text() == "Settings":
                settings_button = candidate
                break
        assert settings_button is not None
        settings_button.click()
        english_language = artifact_dir / "v1-i-r3f-r2-language-region-english.png"
        english_personality = artifact_dir / "v1-i-r3f-r2-personality-english.png"
        observed["english"] = window.grab().save(str(english_language)) and window.grab().save(
            str(english_personality)
        )
        interface = window.findChild(QComboBox, "r3f-interface-language")
        assert interface is not None
        interface.setCurrentIndex(1)
        window._ui_language = "nl"
        window._apply_ui_language()

        def capture_dutch() -> None:
            dutch_language = artifact_dir / "v1-i-r3f-r2-language-region-dutch.png"
            dutch_personality = artifact_dir / "v1-i-r3f-r2-personality-dutch.png"
            observed["dutch"] = window.grab().save(str(dutch_language)) and window.grab().save(
                str(dutch_personality)
            )
            window.close()
            app.quit()

        QTimer.singleShot(150, capture_dutch)

    QTimer.singleShot(0, drive)
    assert run_desktop_app(backend) == 0
    assert observed == {"english": True, "dutch": True}
