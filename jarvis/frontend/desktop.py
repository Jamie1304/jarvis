"""Optional PySide6 desktop adapter that only calls the application service."""

import asyncio
import threading
from typing import Any
from uuid import UUID

from jarvis.application import AssistantEvent, AssistantEventKind, JarvisAssistantService
from jarvis.core.errors import JarvisError
from jarvis.desktop_shell import DesktopShellService, ShellSection


def run_desktop_app(service: JarvisAssistantService) -> int:
    """Run the local desktop chat client, failing clearly if its optional UI extra is absent."""

    try:
        from PySide6.QtCore import QThread, Signal
        from PySide6.QtWidgets import (
            QApplication,
            QHBoxLayout,
            QLabel,
            QLineEdit,
            QMainWindow,
            QPushButton,
            QTextEdit,
            QVBoxLayout,
            QWidget,
        )
    except ImportError as error:
        raise RuntimeError(
            "Desktop UI dependencies are missing; install the desktop extra"
        ) from error

    shell = DesktopShellService(launch_profiles=service.launch_profiles)

    class TextWorker(QThread):  # type: ignore[misc]
        event = Signal(object)
        failed = Signal(str)

        def __init__(self, conversation_id: UUID, text: str) -> None:
            super().__init__()
            self._conversation_id = conversation_id
            self._text = text

        def cancel(self) -> None:
            service.cancel(self._conversation_id)

        def run(self) -> None:
            try:
                asyncio.run(self._run_stream())
            except (JarvisError, RuntimeError) as error:
                self.failed.emit(str(error))

        async def _run_stream(self) -> None:
            async for event in service.stream_text(self._conversation_id, self._text):
                self.event.emit(event)

    class RecordingWorker(QThread):  # type: ignore[misc]
        status = Signal(str)
        transcription = Signal(str)
        failed = Signal(str)

        def __init__(self) -> None:
            super().__init__()
            self._stop_requested = threading.Event()

        def request_stop(self) -> None:
            self._stop_requested.set()

        def run(self) -> None:
            try:
                asyncio.run(self._record())
            except (JarvisError, RuntimeError) as error:
                self.failed.emit(str(error))

        async def _record(self) -> None:
            await service.start_recording()
            self.status.emit("Recording…")
            await asyncio.to_thread(self._stop_requested.wait)
            transcription = await service.stop_recording()
            self.transcription.emit(transcription.text)

    class ProviderWorker(QThread):  # type: ignore[misc]
        status = Signal(str)

        def run(self) -> None:
            health = asyncio.run(self._warm_and_check())
            self.status.emit("Connected" if health.available else f"Unavailable: {health.detail}")

        async def _warm_and_check(self) -> Any:
            try:
                await service.start_startup_warmup()
            except (JarvisError, RuntimeError):
                pass
            return await service.provider_status()

    class MainWindow(QMainWindow):  # type: ignore[misc]
        def __init__(self) -> None:
            super().__init__()
            self._conversation_id = service.create_conversation()
            self._text_worker: Any | None = None
            self._recording_worker: Any | None = None
            self._provider_worker: Any | None = None
            self.setWindowTitle("JARVIS")
            self.resize(760, 560)

            root = QWidget()
            layout = QVBoxLayout(root)
            self._history = QTextEdit(readOnly=True)
            self._input = QLineEdit()
            self._input.setPlaceholderText("Type a message for JARVIS")
            self._send = QPushButton("Send")
            self._microphone = QPushButton("Start microphone")
            self._provider_status = QLabel("Provider: checking…")
            self._stream_status = QLabel("Assistant: ready")
            self._speech_status = QLabel("STT: ready" if service.stt_enabled else "STT: disabled")
            self._tts_status = QLabel("TTS: ready" if service.tts_enabled else "TTS: disabled")
            self._section_status = QLabel("Section: Home")
            self._mode_status = QLabel(
                "Mode: Safe Mode" if shell.state().safe_mode else "Mode: Normal"
            )
            self._error = QLabel()
            self._error.setStyleSheet("color: #b00020")

            controls = QHBoxLayout()
            navigation = QHBoxLayout()
            for item in shell.navigation:
                button = QPushButton(item.label)
                button.clicked.connect(
                    lambda _checked=False, section=item.section: self._select_section(section)
                )
                navigation.addWidget(button)
            controls.addWidget(self._input)
            controls.addWidget(self._send)
            controls.addWidget(self._microphone)
            layout.addWidget(self._history)
            layout.addLayout(navigation)
            layout.addLayout(controls)
            layout.addWidget(self._section_status)
            layout.addWidget(self._mode_status)
            layout.addWidget(self._provider_status)
            layout.addWidget(self._stream_status)
            layout.addWidget(self._speech_status)
            layout.addWidget(self._tts_status)
            layout.addWidget(self._error)
            self.setCentralWidget(root)

            self._send.clicked.connect(self._send_text)
            self._input.returnPressed.connect(self._send_text)
            self._microphone.clicked.connect(self._toggle_microphone)
            self._refresh_provider_status()

        def _select_section(self, section: ShellSection) -> None:
            state = shell.select_section(section)
            self._section_status.setText(f"Section: {state.active_section.value.title()}")

        def _refresh_provider_status(self) -> None:
            self._provider_worker = ProviderWorker(self)
            self._provider_worker.status.connect(
                lambda text: self._provider_status.setText(f"Provider: {text}")
            )
            self._provider_worker.start()

        def _send_text(self, text: str | None = None) -> None:
            value = text if text is not None else self._input.text()
            if not value.strip() or self._text_worker is not None:
                return
            self._error.setText("")
            self._history.append(f"<b>You:</b> {value}")
            self._history.append("<b>JARVIS:</b> ")
            self._input.clear()
            self._send.setEnabled(False)
            self._text_worker = TextWorker(self._conversation_id, value)
            self._text_worker.event.connect(self._render_event)
            self._text_worker.failed.connect(self._show_error)
            self._text_worker.finished.connect(self._text_finished)
            self._text_worker.start()

        def _render_event(self, event: AssistantEvent) -> None:
            if event.kind is AssistantEventKind.TEXT:
                cursor = self._history.textCursor()
                cursor.movePosition(cursor.MoveOperation.End)
                cursor.insertText(event.content)
            elif event.kind is AssistantEventKind.STREAMING:
                self._stream_status.setText(f"Assistant: {event.content}")
            elif event.kind is AssistantEventKind.TTS:
                self._tts_status.setText(f"TTS: {event.content}")

        def _text_finished(self) -> None:
            self._text_worker = None
            self._send.setEnabled(True)

        def _toggle_microphone(self) -> None:
            if not service.stt_enabled:
                self._show_error("Speech-to-text is disabled in configuration")
                return
            if self._recording_worker is None:
                self._recording_worker = RecordingWorker()
                self._recording_worker.status.connect(self._speech_status.setText)
                self._recording_worker.transcription.connect(self._recording_finished)
                self._recording_worker.failed.connect(self._show_error)
                self._recording_worker.finished.connect(self._recording_ended)
                self._recording_worker.start()
                self._microphone.setText("Stop microphone")
            else:
                self._recording_worker.request_stop()
                self._speech_status.setText("Transcribing…")

        def _recording_finished(self, text: str) -> None:
            if text:
                self._send_text(text)
            else:
                self._show_error("No speech was transcribed")

        def _recording_ended(self) -> None:
            self._recording_worker = None
            self._microphone.setText("Start microphone")
            self._speech_status.setText("STT: ready")

        def _show_error(self, message: str) -> None:
            self._error.setText(f"Error: {message}")
            self._send.setEnabled(True)

        def closeEvent(self, event: Any) -> None:
            if self._text_worker is not None:
                self._text_worker.cancel()
            if self._recording_worker is not None:
                self._recording_worker.request_stop()
            asyncio.run(service.aclose())
            event.accept()

    app = QApplication.instance() or QApplication([])
    window = MainWindow()
    window.show()
    return app.exec()
