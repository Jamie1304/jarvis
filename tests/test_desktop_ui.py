from __future__ import annotations

import os
from collections.abc import AsyncIterator
from datetime import UTC, datetime
from pathlib import Path
from types import SimpleNamespace
from typing import Any
from uuid import UUID, uuid4

import pytest
from jarvis.actor_persona import PersonaProfile
from jarvis.application import AssistantEvent, AssistantEventKind
from jarvis.bootstrap import create_application_runtime, create_desktop_facade_from_runtime
from jarvis.core.config import Settings
from jarvis.current_context import (
    CurrentActorProjection,
    CurrentContextSnapshot,
    CurrentProviderProjection,
)
from jarvis.desktop_facade import DesktopRuntimeView
from jarvis.desktop_shell import DesktopShellService
from jarvis.frontend.desktop import run_desktop_app
from jarvis.frontend.desktop_backend import DesktopBackendHost
from jarvis.runtime import ApplicationRuntime, RuntimeStatus

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")
PySide6 = pytest.importorskip("PySide6")
from PySide6.QtCore import QTimer  # noqa: E402
from PySide6.QtWidgets import (  # noqa: E402
    QApplication,
    QLabel,
    QLineEdit,
    QMainWindow,
    QPushButton,
    QStackedWidget,
)


def _application() -> QApplication:
    application = QApplication.instance()
    if application is None:
        return QApplication([])
    assert isinstance(application, QApplication)
    return application


class _RuntimeDouble(ApplicationRuntime):
    def __init__(self) -> None:
        super().__init__(None)

    async def aclose(self) -> None:
        return None


class _DesktopServiceDouble:
    safe_mode = False

    def __init__(self) -> None:
        self.messages: list[str] = []
        self.profile = PersonaProfile.defaults()
        self.actor = SimpleNamespace(
            session_id=uuid4(), source="local_desktop_session", label="Local Desktop", active=True
        )

    def create_conversation(self) -> UUID:
        return uuid4()

    def runtime_view(self) -> DesktopRuntimeView:
        return DesktopRuntimeView(
            "ready", "1.0.0", False, None, "ollama", "fake", "disabled", "disabled"
        )

    def settings_descriptors(self) -> tuple[object, ...]:
        return ()

    def persona(self) -> SimpleNamespace:
        return SimpleNamespace(profile=self.profile)

    def actor_context(self) -> SimpleNamespace:
        return self.actor

    def update_persona(self, values: dict[str, int]) -> PersonaProfile:
        self.profile = PersonaProfile(
            verbosity=values["verbosity"],
            response_length=values["response_length"],
            technical_depth=values["technical_depth"],
        )
        return self.profile

    def reset_persona(self) -> PersonaProfile:
        self.profile = PersonaProfile.defaults()
        return self.profile

    def current_context(self) -> CurrentContextSnapshot:
        return CurrentContextSnapshot(
            revision=0,
            captured_at=datetime.now(UTC),
            actor=CurrentActorProjection(
                context_id=uuid4(),
                session_id=self.actor.session_id,
                source=self.actor.source,
                active=self.actor.active,
            ),
            persona=self.profile,
            active_conversation_id=None,
            conversation_session_id=None,
            active_task_id=None,
            active_task_status=None,
            presence=None,
            runtime_state="ready",
            safe_mode=False,
            provider=CurrentProviderProjection("ollama", "fake", True, None),
            provenance=(),
        )

    async def ollama_status(self, *, ensure_running: bool = False) -> object:
        del ensure_running
        return SimpleNamespace(
            server=SimpleNamespace(value="ready"),
            configured_model="fake",
            configured_model_installed=True,
            running_models=(),
            chat_ready=True,
            detail="ready",
        )

    async def stream_text(self, conversation_id: UUID, text: str) -> AsyncIterator[AssistantEvent]:
        del conversation_id
        self.messages.append(text)
        yield AssistantEvent(AssistantEventKind.TEXT, text)

    def cancel(self, conversation_id: UUID) -> None:
        del conversation_id

    async def stop_speaking(self) -> None:
        return None

    async def start_recording(self) -> None:
        return None

    async def stop_recording(self) -> str:
        return ""


def test_desktop_constructs_all_navigation_pages_offscreen(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    del monkeypatch
    app = _application()
    settings = Settings(
        app_data_dir=tmp_path / "data", ai_provider="ollama", ollama_autostart=False
    )
    backend = DesktopBackendHost(
        lambda: create_application_runtime(settings), create_desktop_facade_from_runtime
    )
    observed: dict[str, object] = {}

    def inspect_window() -> None:
        window: QMainWindow | None = next(
            (
                widget
                for widget in app.topLevelWidgets()
                if isinstance(widget, QMainWindow) and widget.isVisible()
            ),
            None,
        )
        if window is None:
            observed["error"] = "Main window was not shown"
            backend.close()
            app.quit()
            return
        button_texts: set[str] = set()
        navigation_buttons: list[QPushButton] = list(window.findChildren(QPushButton))
        for button in navigation_buttons:
            button_texts.add(button.text())
        observed["buttons"] = button_texts
        pages = window.findChild(QStackedWidget)
        assert pages is not None
        observed["pages"] = pages.count()
        window.close()
        app.quit()

    QTimer.singleShot(0, inspect_window)
    assert run_desktop_app(backend) == 0

    assert "error" not in observed
    buttons = observed["buttons"]
    pages = observed["pages"]
    assert isinstance(buttons, set)
    assert isinstance(pages, int)
    assert buttons >= {item.label for item in DesktopShellService().navigation}
    assert pages == len(DesktopShellService().navigation)


def test_desktop_send_uses_typed_input_not_qt_clicked_boolean() -> None:
    app = _application()
    service_holder: list[_DesktopServiceDouble] = []

    def create_service(_runtime: object) -> _DesktopServiceDouble:
        service = _DesktopServiceDouble()
        service_holder.append(service)
        return service

    backend = DesktopBackendHost(lambda: _RuntimeDouble(), create_service)

    def click_send() -> None:
        window: QMainWindow | None = next(
            (
                widget
                for widget in app.topLevelWidgets()
                if isinstance(widget, QMainWindow) and widget.isVisible()
            ),
            None,
        )
        if window is None:
            app.quit()
            return
        text_input: QLineEdit | None = None
        input_fields: list[QLineEdit] = list(window.findChildren(QLineEdit))
        for field in input_fields:
            if field.placeholderText() == "Type a message for JARVIS":
                text_input = field
                break
        assert text_input is not None
        text_input.setText("typed message")
        send_button: QPushButton | None = None
        action_buttons: list[QPushButton] = list(window.findChildren(QPushButton))
        for button in action_buttons:
            if button.text() == "Send":
                send_button = button
                break
        assert send_button is not None
        send_button.click()
        QTimer.singleShot(50, window.close)
        QTimer.singleShot(60, app.quit)

    QTimer.singleShot(0, click_send)
    assert run_desktop_app(backend) == 0

    assert service_holder[0].messages == ["typed message"]


def test_desktop_safe_mode_renders_settings_and_disables_normal_execution() -> None:
    app = _application()
    runtime = ApplicationRuntime(
        None, status=RuntimeStatus.SAFE_MODE, error="configuration invalid"
    )
    backend = DesktopBackendHost(lambda: runtime, create_desktop_facade_from_runtime)
    observed: dict[str, object] = {}

    def inspect_window() -> None:
        window: QMainWindow | None = next(
            (
                widget
                for widget in app.topLevelWidgets()
                if isinstance(widget, QMainWindow) and widget.isVisible()
            ),
            None,
        )
        if window is None:
            observed["error"] = "Main window was not shown"
            app.quit()
            return
        mode_status: QLabel | None = window.findChild(QLabel, "mode-status")
        context_session: QLabel | None = window.findChild(QLabel, "current-context-session")
        context_mode: QLabel | None = window.findChild(QLabel, "current-context-mode")
        observed["mode"] = mode_status is not None and mode_status.text() == "Mode: Safe Mode"
        observed["context_session"] = context_session is not None
        observed["context_mode"] = context_mode is not None
        buttons: dict[str, bool] = {}
        safe_mode_buttons: list[QPushButton] = list(window.findChildren(QPushButton))
        for button in safe_mode_buttons:
            buttons[button.text()] = button.isEnabled()
        observed["send_enabled"] = buttons.get("Send")
        observed["task_create_enabled"] = buttons.get("Create Task")
        observed["settings_button"] = "Settings" in buttons
        window.close()
        app.quit()

    QTimer.singleShot(0, inspect_window)
    assert run_desktop_app(backend) == 0

    assert "error" not in observed
    assert observed["mode"] is True
    assert observed["context_session"] is True
    assert observed["context_mode"] is True
    assert observed["send_enabled"] is False
    assert observed["task_create_enabled"] is False
    assert observed["settings_button"] is True


def test_persona_save_and_reset_completion_stays_on_qt_thread() -> None:
    app = _application()
    service_holder: list[_DesktopServiceDouble] = []

    def create_service(_runtime: object) -> _DesktopServiceDouble:
        service = _DesktopServiceDouble()
        service_holder.append(service)
        return service

    backend = DesktopBackendHost(lambda: _RuntimeDouble(), create_service)
    observed: dict[str, object] = {}

    def finish() -> None:
        window: Any = next(
            widget
            for widget in app.topLevelWidgets()
            if isinstance(widget, QMainWindow) and widget.isVisible()
        )
        defaults = PersonaProfile.defaults()
        observed["saved"] = service_holder[0].profile.verbosity == 4
        context = window.findChild(QLabel, "current-context-persona")
        assert context is not None
        observed["saved_context"] = "verbosity 4/4" in context.text()
        reset: QPushButton = next(
            button
            for button in window.findChildren(QPushButton)
            if button.text() == "Reset Persona Defaults"
        )
        reset.click()

        def verify_reset() -> None:
            observed["reset"] = service_holder[0].profile == defaults
            context = window.findChild(QLabel, "current-context-persona")
            observed["reset_context"] = context is not None and "verbosity 2/4" in context.text()
            observed["backend_responsive"] = (
                backend.submit(lambda service: service.current_context()).result(timeout=1).persona
                == defaults
            )
            window.close()
            app.quit()

        QTimer.singleShot(150, verify_reset)

    def drive() -> None:
        window: Any = next(
            widget
            for widget in app.topLevelWidgets()
            if isinstance(widget, QMainWindow) and widget.isVisible()
        )
        settings: QPushButton = next(
            button for button in window.findChildren(QPushButton) if button.text() == "Settings"
        )
        settings.click()
        window._persona_verbosity.setCurrentText("4")
        window._persona_response_length.setCurrentText("4")
        save: QPushButton = next(
            button for button in window.findChildren(QPushButton) if button.text() == "Save Persona"
        )
        save.click()
        QTimer.singleShot(150, finish)

    QTimer.singleShot(0, drive)
    assert run_desktop_app(backend) == 0
    assert observed == {
        "saved": True,
        "saved_context": True,
        "reset": True,
        "reset_context": True,
        "backend_responsive": True,
    }
