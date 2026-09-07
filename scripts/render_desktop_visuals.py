"""Render deterministic candidate screenshots for the native desktop shell.

This is a visual QA harness only. The service below is test data and is never
used by production startup or production UI state.
"""

from __future__ import annotations

import os
from collections.abc import AsyncIterator
from pathlib import Path
from types import SimpleNamespace
from uuid import UUID, uuid4

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

from jarvis.application import AssistantEvent, AssistantEventKind
from jarvis.bootstrap import create_desktop_facade_from_runtime
from jarvis.desktop_facade import DesktopRow, DesktopRuntimeView
from jarvis.desktop_shell import DesktopShellService
from jarvis.frontend.desktop import run_desktop_app
from jarvis.frontend.desktop_backend import DesktopBackendHost
from jarvis.runtime import ApplicationRuntime
from PySide6.QtCore import QTimer
from PySide6.QtGui import QFont
from PySide6.QtWidgets import QApplication, QMainWindow, QPushButton, QStackedWidget


class VisualService:
    """Deterministic test-only projection; no production state is fabricated."""

    safe_mode = False

    def create_conversation(self) -> UUID:
        return uuid4()

    def runtime_view(self) -> DesktopRuntimeView:
        return DesktopRuntimeView(
            "ready", "1.0.0", False, None, "ollama", "local", "disabled", "disabled"
        )

    def settings_descriptors(self) -> tuple[object, ...]:
        return ()

    async def ollama_status(self, *, ensure_running: bool = False) -> object:
        del ensure_running
        return SimpleNamespace(
            server=SimpleNamespace(value="ready"),
            configured_model="local",
            configured_model_installed=True,
            running_models=("local",),
            chat_ready=True,
            detail="ready",
        )

    async def stream_text(self, conversation_id: UUID, text: str) -> AsyncIterator[AssistantEvent]:
        del conversation_id
        yield AssistantEvent(AssistantEventKind.TEXT, f"Received: {text}")

    def cancel(self, conversation_id: UUID) -> None:
        del conversation_id

    async def stop_speaking(self) -> None:
        return None

    async def start_recording(self) -> None:
        return None

    async def stop_recording(self) -> str:
        return ""

    async def refresh_rows(self, page: str) -> tuple[DesktopRow, ...]:
        return (
            ()
            if page != "overview"
            else (DesktopRow("runtime", "Runtime", "ready", "Local runtime available"),)
        )


def render_size(app: QApplication, output: Path, size: tuple[int, int]) -> None:
    backend = DesktopBackendHost(lambda: ApplicationRuntime(None), lambda runtime: VisualService())
    names = [item.label for item in DesktopShellService().navigation]
    output.mkdir(parents=True, exist_ok=True)
    observed: dict[str, object] = {}

    def capture() -> None:
        window = next(
            widget
            for widget in app.topLevelWidgets()
            if isinstance(widget, QMainWindow) and widget.isVisible()
        )
        window.resize(*size)
        window.show()
        app.processEvents()
        pages = window.findChild(QStackedWidget)
        assert pages is not None and pages.count() == len(names)
        assert window.width() >= 1100 and window.height() >= 650
        buttons = {button.text(): button for button in window.findChildren(QPushButton)}
        for name in names:
            button = buttons[name]
            button.click()
            app.processEvents()
            path = output / f"{size[0]}x{size[1]}-{name.lower()}.png"
            assert window.grab().save(str(path))
        observed["window"] = window
        window.close()
        app.quit()

    QTimer.singleShot(0, capture)
    assert run_desktop_app(backend) == 0


def render_safe_mode(app: QApplication, output: Path) -> None:
    backend = DesktopBackendHost(
        lambda: ApplicationRuntime(None), create_desktop_facade_from_runtime
    )

    def capture() -> None:
        window = next(
            widget
            for widget in app.topLevelWidgets()
            if isinstance(widget, QMainWindow) and widget.isVisible()
        )
        window.resize(1280, 720)
        window.show()
        app.processEvents()
        assert window.findChild(QStackedWidget) is not None
        assert window.grab().save(str(output / "1280x720-safe-mode.png"))
        window.close()
        app.quit()

    QTimer.singleShot(0, capture)
    assert run_desktop_app(backend) == 0


def main() -> int:
    existing_app = QApplication.instance()
    app = existing_app if isinstance(existing_app, QApplication) else QApplication([])
    app.setFont(QFont("Arial", 10))
    root = Path("artifacts") / "desktop-visual-candidates"
    for size in ((1672, 941), (1440, 900), (1280, 720)):
        render_size(app, root, size)
    render_safe_mode(app, root)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
