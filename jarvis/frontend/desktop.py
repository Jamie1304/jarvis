"""Optional PySide6 desktop adapter that renders backend-owner results."""

from collections.abc import Callable
from typing import Any, get_args
from uuid import UUID

from jarvis.application import AssistantEvent, AssistantEventKind
from jarvis.core.config import Settings
from jarvis.core.errors import ServiceUnavailableError
from jarvis.current_context import CurrentContextSnapshot
from jarvis.desktop_facade import DesktopRow
from jarvis.desktop_shell import DesktopShellService, ShellSection
from jarvis.frontend.desktop_backend import DesktopBackendHost
from jarvis.frontend.theme import desktop_stylesheet
from jarvis.memory.control import MemoryControlReference
from jarvis.memory.models import RetentionPolicy
from jarvis.permissions import ApprovalChoice


def run_desktop_app(
    backend: DesktopBackendHost, *, restart: Callable[[], None] | None = None
) -> int:
    """Run the local desktop chat client, failing clearly if its optional UI extra is absent."""

    try:
        from PySide6.QtCore import QObject, Qt, Signal
        from PySide6.QtGui import QFont
        from PySide6.QtWidgets import (
            QApplication,
            QCheckBox,
            QComboBox,
            QFormLayout,
            QFrame,
            QHBoxLayout,
            QInputDialog,
            QLabel,
            QLineEdit,
            QListWidget,
            QListWidgetItem,
            QMainWindow,
            QMessageBox,
            QPushButton,
            QScrollArea,
            QStackedWidget,
            QTextEdit,
            QVBoxLayout,
            QWidget,
        )
    except ImportError as error:
        raise RuntimeError(
            "Desktop UI dependencies are missing; install the desktop extra"
        ) from error

    startup = backend.start()
    if not startup.ready:
        raise RuntimeError(startup.error or "Desktop backend is unavailable")
    shell = DesktopShellService()

    class BackendSignals(QObject):
        assistant_event = Signal(object)
        failed = Signal(str)
        provider_status = Signal(str)
        context_updated = Signal(object)
        text_finished = Signal(object)
        page_rows = Signal(str, object)
        recording_finished = Signal(str)
        recording_started = Signal(object)
        settings_finished = Signal(object)
        task_action_finished = Signal(object)
        memory_action_finished = Signal(object)
        permission_action_finished = Signal(object)
        operation_finished = Signal(str, object)

    class MainWindow(QMainWindow):
        def __init__(self) -> None:
            super().__init__()

            def label(text: str, name: str) -> QLabel:
                result = QLabel(text)
                result.setObjectName(name)
                return result

            self._signals = BackendSignals()
            self._signals.assistant_event.connect(self._render_event)
            self._signals.failed.connect(self._show_error)
            self._signals.provider_status.connect(self._render_provider_status)
            self._signals.context_updated.connect(self._render_current_context)
            self._signals.text_finished.connect(self._text_finished)
            self._signals.page_rows.connect(self._render_page_rows)
            self._signals.recording_finished.connect(self._recording_finished)
            self._signals.recording_started.connect(self._recording_started)
            self._signals.settings_finished.connect(self._settings_saved)
            self._signals.task_action_finished.connect(self._task_action_finished)
            self._signals.memory_action_finished.connect(self._memory_action_finished)
            self._signals.permission_action_finished.connect(self._permission_action_finished)
            self._signals.operation_finished.connect(self._operation_finished)
            self._safe_mode = backend.submit(lambda service: service.safe_mode).result()
            self._conversation_id = (
                backend.submit(lambda service: service.create_conversation()).result()
                if not self._safe_mode
                else None
            )
            self._text_future: Any | None = None
            self._restart_after_save = False
            self.setWindowTitle("JARVIS")
            self.setMinimumSize(1100, 650)
            self.resize(1672, 941)
            self.setStyleSheet(desktop_stylesheet())

            root = QWidget()
            root.setObjectName("desktop-root")
            layout = QVBoxLayout(root)
            layout.setContentsMargins(0, 0, 0, 0)
            layout.setSpacing(0)

            topbar = QFrame()
            topbar.setObjectName("topbar")
            top_layout = QHBoxLayout(topbar)
            top_layout.setContentsMargins(22, 14, 22, 14)
            brand = QLabel("JARVIS")
            brand.setStyleSheet("font-size: 18px; font-weight: 800; color: #35C2FF;")
            top_layout.addWidget(brand)
            top_layout.addWidget(label("LOCAL INTELLIGENCE OPERATING SYSTEM", "eyebrow"))
            top_layout.addStretch()
            self._history = QTextEdit()
            self._history.setReadOnly(True)
            self._history.setObjectName("conversation-history")
            self._input = QLineEdit()
            self._input.setPlaceholderText("Type a message for JARVIS")
            self._send = QPushButton("Send")
            self._send.setObjectName("primary-action")
            self._cancel_response = QPushButton("Cancel response")
            self._cancel_response.setEnabled(False)
            self._stop_speaking = QPushButton("Stop speaking")
            self._microphone = QPushButton("Start microphone")
            self._provider_status = QLabel("Provider health: checking…")
            self._stream_status = QLabel("Assistant: ready")
            self._speech_status = QLabel("STT: checking")
            self._tts_status = QLabel("TTS: checking")
            self._section_status = QLabel("Section: Overview")
            self._mode_status = QLabel(
                "Mode: Safe Mode" if shell.state().safe_mode else "Mode: Normal"
            )
            self._mode_status.setObjectName("mode-status")
            self._context_session = QLabel()
            self._context_session.setObjectName("current-context-session")
            self._context_activity = QLabel()
            self._context_activity.setObjectName("current-context-activity")
            self._context_model = QLabel()
            self._context_model.setObjectName("current-context-model")
            self._context_persona = QLabel()
            self._context_persona.setObjectName("current-context-persona")
            self._context_mode = QLabel()
            self._context_mode.setObjectName("current-context-mode")
            for context_label in (
                self._context_session,
                self._context_activity,
                self._context_model,
                self._context_persona,
                self._context_mode,
            ):
                context_label.setWordWrap(True)
            self._error = QLabel()
            self._error.setObjectName("status-line")
            self._error.setWordWrap(True)

            top_layout.addWidget(self._mode_status)
            layout.addWidget(topbar)

            self._pages = QStackedWidget()
            self._page_indexes: dict[ShellSection, int] = {}
            self._page_lists: dict[str, QListWidget] = {}
            self._page_rows: dict[str, tuple[DesktopRow, ...]] = {}
            self._normal_action_widgets: list[QWidget] = []
            chat_page = QWidget()
            chat_layout = QVBoxLayout(chat_page)
            chat_layout.setContentsMargins(24, 24, 24, 18)
            chat_title = label("Chat", "page-title")
            chat_layout.addWidget(chat_title)
            chat_layout.addWidget(
                label("A calm command surface for local-first work.", "page-subtitle")
            )
            controls = QHBoxLayout()
            controls.setSpacing(8)
            navigation = QVBoxLayout()
            for item in shell.navigation:
                button = QPushButton()
                button.setText(item.label)
                button.setObjectName("nav-item")
                button.setCheckable(True)
                button.setAutoExclusive(True)
                if item.section is ShellSection.OVERVIEW:
                    button.setChecked(True)
                button.clicked.connect(
                    lambda _checked=False, section=item.section: self._select_section(section)
                )
                navigation.addWidget(button)
            navigation.addStretch()
            controls.addWidget(self._input)
            controls.addWidget(self._send)
            controls.addWidget(self._cancel_response)
            controls.addWidget(self._stop_speaking)
            controls.addWidget(self._microphone)
            chat_layout.addWidget(self._history)
            chat_layout.addLayout(controls)
            self._page_indexes[ShellSection.CHAT] = self._pages.addWidget(chat_page)
            for section in ShellSection:
                if section is ShellSection.CHAT:
                    continue
                page = QWidget()
                page_layout = QVBoxLayout(page)
                page_layout.setContentsMargins(24, 24, 24, 18)
                heading = label(section.value.title(), "page-title")
                content = QLabel(self._page_description(section))
                content.setObjectName("page-subtitle")
                content.setWordWrap(True)
                page_layout.addWidget(heading)
                page_layout.addWidget(content)
                if section is ShellSection.SETTINGS:
                    self._settings_form = QFormLayout()
                    settings_body = QWidget()
                    settings_body.setLayout(self._settings_form)
                    scroll = QScrollArea()
                    scroll.setWidgetResizable(True)
                    scroll.setWidget(settings_body)
                    self._reset_setting_selector = QComboBox()
                    reset_unsaved = QPushButton("Reset Unsaved Changes")
                    reset_unsaved.clicked.connect(self._refresh_settings)
                    reset_default = QPushButton("Reset Setting to Default")
                    reset_default.clicked.connect(self._reset_setting_to_default)
                    save = QPushButton("Save")
                    save.clicked.connect(self._save_settings)
                    save_restart = QPushButton("Save and Restart")
                    save_restart.clicked.connect(self._save_and_restart)
                    restart_now = QPushButton("Restart")
                    restart_now.clicked.connect(self._restart_desktop)
                    persona_heading = QLabel("<b>Persona (presentation only)</b>")
                    self._persona_verbosity = QComboBox()
                    self._persona_verbosity.addItems(["0", "1", "2", "3", "4"])
                    self._persona_response_length = QComboBox()
                    self._persona_response_length.addItems(["0", "1", "2", "3", "4"])
                    self._persona_technical_depth = QComboBox()
                    self._persona_technical_depth.addItems(["0", "1", "2", "3", "4"])
                    persona_save = QPushButton("Save Persona")
                    persona_save.clicked.connect(self._save_persona)
                    persona_reset = QPushButton("Reset Persona Defaults")
                    persona_reset.clicked.connect(self._reset_persona)
                    self._actor_status = QLabel()
                    page_layout.addWidget(scroll)
                    page_layout.addWidget(self._reset_setting_selector)
                    page_layout.addWidget(reset_unsaved)
                    page_layout.addWidget(reset_default)
                    page_layout.addWidget(save)
                    page_layout.addWidget(save_restart)
                    page_layout.addWidget(restart_now)
                    page_layout.addWidget(persona_heading)
                    page_layout.addWidget(QLabel("Verbosity (0-4)"))
                    page_layout.addWidget(self._persona_verbosity)
                    page_layout.addWidget(QLabel("Response length (0-4)"))
                    page_layout.addWidget(self._persona_response_length)
                    page_layout.addWidget(QLabel("Technical depth (0-4)"))
                    page_layout.addWidget(self._persona_technical_depth)
                    page_layout.addWidget(persona_save)
                    page_layout.addWidget(persona_reset)
                    page_layout.addWidget(self._actor_status)
                    self._refresh_settings()
                    self._refresh_persona()
                else:
                    rows = QListWidget()
                    rows.setMinimumHeight(180)
                    refresh = QPushButton("Refresh")
                    refresh.clicked.connect(
                        lambda _checked=False, name=section.value: self._refresh_page(name)
                    )
                    page_layout.addWidget(rows, 1)
                    if section is ShellSection.TASKS:
                        self._task_goal = QLineEdit()
                        self._task_goal.setPlaceholderText("Describe a task")
                        create_task = QPushButton("Create Task")
                        create_task.clicked.connect(self._create_task)
                        run_task = QPushButton("Run Selected")
                        run_task.clicked.connect(self._run_selected_task)
                        cancel_task = QPushButton("Cancel Selected")
                        cancel_task.clicked.connect(self._cancel_selected_task)
                        task_controls = QHBoxLayout()
                        task_controls.addWidget(self._task_goal)
                        task_controls.addWidget(create_task)
                        task_controls.addWidget(run_task)
                        task_controls.addWidget(cancel_task)
                        page_layout.addLayout(task_controls)
                        self._normal_action_widgets.extend(
                            (self._task_goal, create_task, run_task, cancel_task)
                        )
                    if section is ShellSection.MEMORY:
                        correct_memory = QPushButton("Correct Selected")
                        correct_memory.clicked.connect(self._correct_selected_memory)
                        delete_memory = QPushButton("Delete Selected")
                        delete_memory.clicked.connect(self._delete_selected_memory)
                        mark_explicit = QPushButton("Mark Explicit")
                        mark_explicit.clicked.connect(self._mark_selected_memory_explicit)
                        reverify_memory = QPushButton("Request Reverification")
                        reverify_memory.clicked.connect(self._reverify_selected_memory)
                        memory_actions = QHBoxLayout()
                        memory_actions.addWidget(correct_memory)
                        memory_actions.addWidget(delete_memory)
                        memory_actions.addWidget(mark_explicit)
                        memory_actions.addWidget(reverify_memory)
                        self._memory_retention = QComboBox()
                        self._memory_retention.addItems(
                            [policy.value for policy in RetentionPolicy]
                        )
                        set_retention = QPushButton("Set Retention")
                        set_retention.clicked.connect(self._set_selected_memory_retention)
                        self._memory_forget_category = QLineEdit()
                        self._memory_forget_category.setPlaceholderText("Category to forget")
                        forget_category = QPushButton("Forget Category")
                        forget_category.clicked.connect(self._forget_memory_category)
                        memory_policy = QHBoxLayout()
                        memory_policy.addWidget(self._memory_retention)
                        memory_policy.addWidget(set_retention)
                        memory_policy.addWidget(self._memory_forget_category)
                        memory_policy.addWidget(forget_category)
                        self._memory_learning_paused = QCheckBox("Pause Learning")
                        self._memory_learning_paused.toggled.connect(
                            self._set_memory_learning_paused
                        )
                        page_layout.addLayout(memory_actions)
                        page_layout.addLayout(memory_policy)
                        page_layout.addWidget(self._memory_learning_paused)
                        self._normal_action_widgets.extend(
                            (
                                correct_memory,
                                delete_memory,
                                mark_explicit,
                                reverify_memory,
                                self._memory_retention,
                                set_retention,
                                self._memory_forget_category,
                                forget_category,
                                self._memory_learning_paused,
                            )
                        )
                    if section is ShellSection.PERMISSIONS:
                        approve_permission = QPushButton("Approve Once")
                        approve_permission.clicked.connect(self._approve_selected_permission)
                        deny_permission = QPushButton("Deny")
                        deny_permission.clicked.connect(self._deny_selected_permission)
                        permission_actions = QHBoxLayout()
                        permission_actions.addWidget(approve_permission)
                        permission_actions.addWidget(deny_permission)
                        page_layout.addLayout(permission_actions)
                        self._normal_action_widgets.extend((approve_permission, deny_permission))
                    if section in {
                        ShellSection.CAPABILITIES,
                        ShellSection.TOOLS,
                        ShellSection.AUTOMATIONS,
                        ShellSection.PERMISSIONS,
                        ShellSection.ACTIVITY,
                    }:
                        inspect_selected = QPushButton("Inspect Selected")
                        inspect_selected.clicked.connect(
                            lambda _checked=False,
                            page_name=section.value: self._inspect_selected_row(page_name)
                        )
                        page_layout.addWidget(inspect_selected)
                        self._normal_action_widgets.append(inspect_selected)
                    if section is ShellSection.TOOLS:
                        check_tool_health = QPushButton("Check Selected Health")
                        check_tool_health.clicked.connect(self._check_selected_tool_health)
                        page_layout.addWidget(check_tool_health)
                        self._normal_action_widgets.append(check_tool_health)
                    if section is ShellSection.AUTOMATIONS:
                        remove_automation = QPushButton("Remove Selected")
                        remove_automation.clicked.connect(self._remove_selected_automation)
                        page_layout.addWidget(remove_automation)
                        self._normal_action_widgets.append(remove_automation)
                    page_layout.addWidget(refresh)
                    self._page_lists[section.value] = rows
                    if section is not ShellSection.OVERVIEW:
                        self._normal_action_widgets.append(refresh)
                self._page_indexes[section] = self._pages.addWidget(page)
            body = QFrame()
            body_layout = QHBoxLayout(body)
            body_layout.setContentsMargins(0, 0, 0, 0)
            nav_frame = QFrame()
            nav_frame.setObjectName("sidebar")
            nav_frame.setMinimumWidth(210)
            nav_frame.setMaximumWidth(250)
            nav_frame.setLayout(navigation)
            body_layout.addWidget(nav_frame)
            body_layout.addWidget(self._pages, 1)
            observe = QFrame()
            observe.setObjectName("observability")
            observe.setMinimumWidth(250)
            observe.setMaximumWidth(350)
            observe_layout = QVBoxLayout(observe)
            observe_layout.setContentsMargins(18, 22, 18, 18)
            observe_layout.addWidget(label("OBSERVABILITY", "eyebrow"))
            core_card = QFrame()
            core_card.setObjectName("card")
            core_layout = QVBoxLayout(core_card)
            core_layout.addWidget(label("JARVIS CORE", "eyebrow"))
            self._core_status = label("READY", "core-status")
            core_layout.addWidget(self._core_status)
            core_layout.addWidget(self._stream_status, 0)
            observe_layout.addWidget(core_card)
            provider_card = QFrame()
            provider_card.setObjectName("card")
            provider_layout = QVBoxLayout(provider_card)
            provider_layout.addWidget(label("PROVIDER", "eyebrow"))
            provider_layout.addWidget(self._provider_status)
            provider_layout.addWidget(self._speech_status, 0)
            provider_layout.addWidget(self._tts_status, 0)
            observe_layout.addWidget(provider_card)
            context_card = QFrame()
            context_card.setObjectName("card")
            context_layout = QVBoxLayout(context_card)
            context_layout.addWidget(label("CURRENT CONTEXT", "eyebrow"))
            context_layout.addWidget(self._context_session)
            context_layout.addWidget(self._context_activity)
            context_layout.addWidget(self._context_model)
            context_layout.addWidget(self._context_persona)
            context_layout.addWidget(self._context_mode)
            observe_layout.addWidget(context_card)
            activity_card = QFrame()
            activity_card.setObjectName("card")
            activity_layout = QVBoxLayout(activity_card)
            activity_layout.addWidget(label("LIVE ACTIVITY", "eyebrow"))
            activity_layout.addWidget(
                label("Operational events appear here when available.", "muted")
            )
            activity_layout.addStretch()
            observe_layout.addWidget(activity_card, 1)
            body_layout.addWidget(observe)
            layout.addWidget(body, 1)
            footer = QFrame()
            footer.setObjectName("topbar")
            footer_layout = QHBoxLayout(footer)
            footer_layout.setContentsMargins(22, 8, 22, 8)
            footer_layout.addWidget(self._section_status)
            footer_layout.addStretch()
            footer_layout.addWidget(self._error, 1)
            layout.addWidget(footer)
            self.setCentralWidget(root)

            self._send.clicked.connect(self._send_current_text)
            self._input.returnPressed.connect(self._send_current_text)
            self._cancel_response.clicked.connect(self._cancel_active_response)
            self._stop_speaking.clicked.connect(self._stop_active_speech)
            self._microphone.clicked.connect(self._toggle_microphone)
            if self._safe_mode:
                self._mode_status.setText("Mode: Safe Mode")
                safe_mode_error = backend.submit(
                    lambda service: service.runtime_view().error
                ).result()
                self._error.setText(
                    "Safe Mode: normal execution is disabled"
                    + (f" — {safe_mode_error}" if safe_mode_error else "")
                )
                self._send.setEnabled(False)
                self._input.setEnabled(False)
                self._cancel_response.setEnabled(False)
                self._stop_speaking.setEnabled(False)
                self._microphone.setEnabled(False)
                for widget in self._normal_action_widgets:
                    widget.setEnabled(False)
            self._pages.setCurrentIndex(self._page_indexes[ShellSection.OVERVIEW])
            self._refresh_page("overview")
            self._refresh_current_context()
            if not self._safe_mode:
                self._refresh_provider_status()

        def _select_section(self, section: ShellSection) -> None:
            state = shell.select_section(section)
            self._section_status.setText(f"Section: {state.active_section.value.title()}")
            self._pages.setCurrentIndex(self._page_indexes[section])
            if section is ShellSection.OVERVIEW:
                self._refresh_page(section.value)
            elif not self._safe_mode and section not in {ShellSection.CHAT, ShellSection.SETTINGS}:
                self._refresh_page(section.value)

        @staticmethod
        def _page_description(section: ShellSection) -> str:
            descriptions = {
                ShellSection.OVERVIEW: "Runtime status and configured local provider health.",
                ShellSection.TASKS: (
                    "Canonical task and plan status is available through the runtime."
                ),
                ShellSection.MEMORY: "Trusted memory controls are available through the runtime.",
                ShellSection.CAPABILITIES: "Capability lifecycle state is owned by the runtime.",
                ShellSection.TOOLS: "Trusted registered tools are owned by the runtime.",
                ShellSection.AUTOMATIONS: (
                    "Automation definitions and runs are owned by the runtime."
                ),
                ShellSection.PERMISSIONS: "Permission requests use the trusted approval surface.",
                ShellSection.ACTIVITY: "Bounded operational activity is owned by the runtime.",
                ShellSection.SETTINGS: (
                    "Configuration is read and saved through the JARVIS environment service."
                ),
            }
            return descriptions[section]

        def _refresh_provider_status(self) -> None:
            future = backend.submit_async(
                lambda service: service.ollama_status(ensure_running=True)
            )
            future.add_done_callback(self._provider_finished)

        def _send_current_text(self) -> None:
            self._send_text(self._input.text())

        def _send_text(self, text: str) -> None:
            if self._conversation_id is None or not text.strip() or self._text_future is not None:
                return
            self._error.setText("")
            self._history.append(f"<b>You:</b> {text}")
            self._history.append("<b>JARVIS:</b> ")
            self._input.clear()
            self._send.setEnabled(False)
            self._cancel_response.setEnabled(True)
            self._text_future = backend.stream_text(
                self._conversation_id, text, on_event=self._signals.assistant_event.emit
            )
            self._refresh_current_context()
            self._text_future.add_done_callback(self._signals.text_finished.emit)

        def _render_event(self, event: AssistantEvent) -> None:
            if event.kind is AssistantEventKind.TEXT:
                cursor = self._history.textCursor()
                cursor.movePosition(cursor.MoveOperation.End)
                cursor.insertText(event.content)
            elif event.kind is AssistantEventKind.STREAMING:
                self._stream_status.setText(f"Assistant: {event.content}")
                self._refresh_current_context()
            elif event.kind is AssistantEventKind.TTS:
                self._tts_status.setText(f"TTS: {event.content}")

        def _text_finished(self, future: Any) -> None:
            try:
                future.result()
            except Exception as error:
                self._signals.failed.emit(str(error))
            finally:
                self._text_future = None
                self._send.setEnabled(True)
                self._cancel_response.setEnabled(False)
                self._refresh_current_context()

        def _cancel_active_response(self) -> None:
            if self._conversation_id is None or self._text_future is None:
                return
            backend.cancel(self._conversation_id)
            self._stream_status.setText("Assistant: cancelling response")
            self._refresh_current_context()

        def _stop_active_speech(self) -> None:
            future = backend.submit_async(lambda service: service.stop_speaking())
            future.add_done_callback(self._speech_stop_finished)

        def _speech_stop_finished(self, future: Any) -> None:
            try:
                future.result()
                self._tts_status.setText("TTS: stopped")
            except Exception as error:
                self._signals.failed.emit(str(error))

        def _provider_finished(self, future: Any) -> None:
            try:
                status = future.result()
                self._signals.provider_status.emit(
                    "\n".join(
                        (
                            f"Ollama server: {status.server.value.title()}",
                            f"Configured model: {status.configured_model}",
                            "Model installed: "
                            f"{'Yes' if status.configured_model_installed else 'No'}",
                            f"Running models: {', '.join(status.running_models) or 'None'}",
                            f"Chat: {'Ready' if status.chat_ready else status.detail}",
                        )
                    )
                )
            except Exception as error:
                self._signals.provider_status.emit(f"Unavailable: {error}")

        def _render_provider_status(self, status: str) -> None:
            self._provider_status.setText(f"Provider health: {status}")

        def _refresh_current_context(self) -> None:
            future = backend.submit(lambda service: service.current_context())
            future.add_done_callback(self._signals.context_updated.emit)

        def _render_current_context(self, future: Any) -> None:
            try:
                context = future.result()
                if not isinstance(context, CurrentContextSnapshot):
                    raise TypeError("Current context projection is malformed")
                actor = context.actor
                if actor is None:
                    actor_text = "Session: unavailable in Safe Mode"
                elif actor.active and actor.source == "local_desktop_session":
                    actor_text = "Session: Local Desktop · active"
                else:
                    state = "active" if actor.active else "ended"
                    actor_text = f"Session: {actor.source} · {state}"
                conversation = (
                    f"Conversation: {str(context.active_conversation_id)[:8]}"
                    if context.active_conversation_id is not None
                    else "Conversation: none"
                )
                task = (
                    f"Task: {str(context.active_task_id)[:8]} · {context.active_task_status}"
                    if context.active_task_id is not None
                    else "Task: none"
                )
                presence = (
                    context.presence.state.value.replace("_", " ").title()
                    if context.presence is not None
                    else "unavailable"
                )
                provider = context.provider
                provider_name = provider.provider_id or "none"
                model = provider.model_id or "none"
                if provider.readiness is None:
                    readiness = "unavailable"
                elif provider.readiness.value == "not_probed":
                    readiness = "Not checked yet"
                else:
                    readiness = provider.readiness.value
                self._context_session.setText(actor_text)
                self._context_activity.setText(f"{conversation}\n{task}\nPresence: {presence}")
                self._context_model.setText(
                    f"Configured model: {provider_name} / {model}\nReadiness: {readiness}"
                )
                self._context_persona.setText(
                    "Persona: presentation profile "
                    f"(verbosity {context.persona.verbosity}/4, "
                    f"depth {context.persona.technical_depth}/4)"
                )
                self._context_mode.setText(
                    "Mode: Safe Mode" if context.safe_mode else "Mode: Normal"
                )
            except (AttributeError, ServiceUnavailableError, TypeError, ValueError) as error:
                self._context_session.setText("Current context unavailable")
                self._context_activity.setText(str(error))
                self._context_model.clear()
                self._context_persona.clear()
                self._context_mode.clear()

        def _refresh_page(self, page: str) -> None:
            if page == "overview":
                future = backend.submit(lambda service: service.runtime_view())
                future.add_done_callback(
                    lambda result: self._signals.page_rows.emit(
                        page,
                        (
                            DesktopRow(
                                "runtime",
                                "Runtime",
                                result.result().state,
                                result.result().error or result.result().version,
                            ),
                        ),
                    )
                )
                return
            future = backend.submit_async(lambda service: service.refresh_rows(page))
            future.add_done_callback(lambda result: self._page_rows_finished(page, result))

        def _page_rows_finished(self, page: str, future: Any) -> None:
            try:
                self._signals.page_rows.emit(page, future.result())
            except Exception as error:
                self._signals.failed.emit(str(error))

        def _render_page_rows(self, page: str, rows: object) -> None:
            target = self._page_lists.get(page)
            if target is None:
                return
            if not isinstance(rows, tuple) or not all(isinstance(row, DesktopRow) for row in rows):
                self._signals.failed.emit("Desktop page projection is malformed")
                return
            page_rows: tuple[DesktopRow, ...] = rows
            self._page_rows[page] = page_rows
            target.clear()
            for row in page_rows:
                item = QListWidgetItem(f"{row.title} [{row.status}]\n{row.detail}")
                item.setData(
                    Qt.ItemDataRole.UserRole,
                    (
                        row.reference
                        if getattr(row, "reference", None) is not None
                        else row.identifier
                    ),
                )
                item.setData(int(Qt.ItemDataRole.UserRole) + 1, row)
                target.addItem(item)
            if target.count() == 0:
                target.addItem("No operational records are available.")

        def _create_task(self) -> None:
            goal = self._task_goal.text().strip()
            if self._conversation_id is None or not goal:
                return
            self._task_goal.clear()
            future = backend.submit_async(
                lambda service: service.create_task(self._conversation_id, goal)
            )
            future.add_done_callback(self._signals.task_action_finished.emit)

        def _run_selected_task(self) -> None:
            task_id = self._selected_task_id()
            if task_id is None:
                return
            future = backend.submit_async(lambda service: service.run_task(task_id))
            future.add_done_callback(self._signals.task_action_finished.emit)

        def _cancel_selected_task(self) -> None:
            task_id = self._selected_task_id()
            if task_id is None:
                return
            future = backend.submit_async(lambda service: service.cancel_task(task_id))
            future.add_done_callback(self._signals.task_action_finished.emit)

        def _selected_task_id(self) -> UUID | None:
            item = self._page_lists[ShellSection.TASKS.value].currentItem()
            if item is None:
                self._signals.failed.emit("Select a task first")
                return None
            try:
                return UUID(str(item.data(Qt.ItemDataRole.UserRole)))
            except (TypeError, ValueError):
                self._signals.failed.emit("The selected task identifier is invalid")
                return None

        def _task_action_finished(self, future: Any) -> None:
            try:
                future.result()
                self._refresh_page(ShellSection.TASKS.value)
                self._refresh_current_context()
            except Exception as error:
                self._signals.failed.emit(str(error))

        def _selected_memory_reference(self) -> MemoryControlReference | None:
            item = self._page_lists[ShellSection.MEMORY.value].currentItem()
            reference = item.data(Qt.ItemDataRole.UserRole) if item is not None else None
            if not isinstance(reference, MemoryControlReference):
                self._signals.failed.emit("Select a memory record first")
                return None
            return reference

        def _selected_memory_row(self) -> DesktopRow | None:
            item = self._page_lists[ShellSection.MEMORY.value].currentItem()
            row = item.data(int(Qt.ItemDataRole.UserRole) + 1) if item is not None else None
            return row if isinstance(row, DesktopRow) else None

        def _correct_selected_memory(self) -> None:
            reference = self._selected_memory_reference()
            row = self._selected_memory_row()
            if reference is None or row is None:
                return
            belief, accepted = QInputDialog.getMultiLineText(
                self, "Correct Memory", "Replacement memory", row.title
            )
            if not accepted or not belief.strip():
                return
            if (
                QMessageBox.question(
                    self,
                    "Confirm Memory Correction",
                    "Replace the selected memory with this correction?",
                    QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
                    QMessageBox.StandardButton.No,
                )
                != QMessageBox.StandardButton.Yes
            ):
                return
            future = backend.submit(
                lambda service: service.correct_memory(reference, belief.strip())
            )
            future.add_done_callback(self._signals.memory_action_finished.emit)

        def _delete_selected_memory(self) -> None:
            reference = self._selected_memory_reference()
            if reference is None:
                return
            if (
                QMessageBox.question(
                    self,
                    "Delete Memory",
                    "Delete the selected memory?",
                    QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
                    QMessageBox.StandardButton.No,
                )
                != QMessageBox.StandardButton.Yes
            ):
                return
            future = backend.submit(lambda service: service.delete_memory(reference))
            future.add_done_callback(self._signals.memory_action_finished.emit)

        def _mark_selected_memory_explicit(self) -> None:
            reference = self._selected_memory_reference()
            if reference is None:
                return
            future = backend.submit(lambda service: service.mark_memory_explicit(reference))
            future.add_done_callback(self._signals.memory_action_finished.emit)

        def _reverify_selected_memory(self) -> None:
            reference = self._selected_memory_reference()
            if reference is None:
                return
            future = backend.submit(
                lambda service: service.request_memory_reverification(reference)
            )
            future.add_done_callback(self._signals.memory_action_finished.emit)

        def _set_selected_memory_retention(self) -> None:
            reference = self._selected_memory_reference()
            if reference is None:
                return
            retention = RetentionPolicy(self._memory_retention.currentText())
            future = backend.submit(
                lambda service: service.change_memory_retention(reference, retention)
            )
            future.add_done_callback(self._signals.memory_action_finished.emit)

        def _forget_memory_category(self) -> None:
            category = self._memory_forget_category.text().strip()
            if not category:
                self._signals.failed.emit("Enter a memory category to forget")
                return
            if (
                QMessageBox.question(
                    self,
                    "Forget Memory Category",
                    f"Delete all user-managed memories in category '{category}'?",
                    QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
                    QMessageBox.StandardButton.No,
                )
                != QMessageBox.StandardButton.Yes
            ):
                return
            future = backend.submit(lambda service: service.forget_memory_category(category))
            future.add_done_callback(self._signals.memory_action_finished.emit)

        def _set_memory_learning_paused(self, paused: bool) -> None:
            future = backend.submit(lambda service: service.pause_memory_learning(paused))
            future.add_done_callback(self._signals.memory_action_finished.emit)

        def _memory_action_finished(self, future: Any) -> None:
            try:
                result = future.result()
                self._stream_status.setText(f"Memory: action completed ({result})")
                self._refresh_page(ShellSection.MEMORY.value)
            except Exception as error:
                self._signals.failed.emit(str(error))

        def _selected_permission_id(self) -> UUID | None:
            item = self._page_lists[ShellSection.PERMISSIONS.value].currentItem()
            identifier = item.data(Qt.ItemDataRole.UserRole) if item is not None else None
            try:
                return UUID(str(identifier))
            except (TypeError, ValueError):
                self._signals.failed.emit("Select a pending permission request first")
                return None

        def _approve_selected_permission(self) -> None:
            self._decide_selected_permission(ApprovalChoice.APPROVE_ONCE)

        def _deny_selected_permission(self) -> None:
            self._decide_selected_permission(ApprovalChoice.DENY_ONCE)

        def _decide_selected_permission(self, choice: ApprovalChoice) -> None:
            request_id = self._selected_permission_id()
            if request_id is None:
                return
            label = "approve" if choice is ApprovalChoice.APPROVE_ONCE else "deny"
            if (
                QMessageBox.question(
                    self,
                    "Confirm Permission Decision",
                    f"{label.title()} the selected pending permission request once?",
                    QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
                    QMessageBox.StandardButton.No,
                )
                != QMessageBox.StandardButton.Yes
            ):
                return
            future = backend.submit_async(
                lambda service: service.decide_permission(request_id, choice)
            )
            future.add_done_callback(self._signals.permission_action_finished.emit)

        def _permission_action_finished(self, future: Any) -> None:
            try:
                accepted = future.result()
                status = "submitted" if accepted else "rejected"
                self._stream_status.setText(f"Permission: decision {status}")
                self._refresh_page(ShellSection.PERMISSIONS.value)
            except Exception as error:
                self._signals.failed.emit(str(error))

        def _selected_row(self, page: str) -> DesktopRow | None:
            item = self._page_lists[page].currentItem()
            row = item.data(int(Qt.ItemDataRole.UserRole) + 1) if item is not None else None
            if not isinstance(row, DesktopRow):
                self._signals.failed.emit("Select an operational record first")
                return None
            return row

        def _inspect_selected_row(self, page: str) -> None:
            row = self._selected_row(page)
            if row is None:
                return
            QMessageBox.information(self, row.title, f"ID: {row.identifier}\n\n{row.detail}")

        def _check_selected_tool_health(self) -> None:
            row = self._selected_row(ShellSection.TOOLS.value)
            if row is None:
                return
            future = backend.submit_async(lambda service: service.check_tool_health(row.identifier))
            future.add_done_callback(
                lambda result: self._signals.operation_finished.emit(
                    ShellSection.TOOLS.value, result
                )
            )

        def _remove_selected_automation(self) -> None:
            row = self._selected_row(ShellSection.AUTOMATIONS.value)
            if row is None:
                return
            try:
                automation_id = UUID(row.identifier)
            except ValueError:
                self._signals.failed.emit("The selected automation identifier is invalid")
                return
            if (
                QMessageBox.question(
                    self,
                    "Remove Automation",
                    "Remove the selected automation and its active runs?",
                    QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
                    QMessageBox.StandardButton.No,
                )
                != QMessageBox.StandardButton.Yes
            ):
                return
            future = backend.submit(lambda service: service.remove_automation(automation_id))
            future.add_done_callback(
                lambda result: self._signals.operation_finished.emit(
                    ShellSection.AUTOMATIONS.value, result
                )
            )

        def _operation_finished(self, page: str, future: Any) -> None:
            try:
                result = future.result()
                self._stream_status.setText(f"{page.title()}: operation completed ({result})")
                self._refresh_page(page)
            except Exception as error:
                self._signals.failed.emit(str(error))

        def _refresh_settings(self) -> None:
            descriptors = backend.submit(lambda service: service.settings_descriptors()).result()
            self._setting_inputs: dict[str, QLineEdit | QCheckBox | QComboBox] = {}
            self._setting_initial: dict[str, object] = {}
            while self._settings_form.rowCount():
                self._settings_form.removeRow(0)
            current_group: str | None = None
            for descriptor in descriptors:
                group = self._settings_group(descriptor.name)
                if group != current_group:
                    current_group = group
                    self._settings_form.addRow(QLabel(f"<b>{group}</b>"), QLabel())
                value = (
                    descriptor.saved_value
                    if descriptor.saved_value is not None
                    else descriptor.value
                )
                field: QLineEdit | QCheckBox | QComboBox
                if not descriptor.editable or descriptor.name in {
                    "version",
                    "security_policy_version",
                }:
                    field = QLineEdit("" if value is None else str(value))
                    field.setReadOnly(True)
                elif isinstance(value, bool):
                    field = QCheckBox()
                    field.setChecked(value)
                elif descriptor.name in {"environment", "tts_provider", "stt_compute_device"}:
                    field = QComboBox()
                    choices = {
                        "environment": ["local", "test", "production"],
                        "tts_provider": ["piper", "pyttsx3"],
                        "stt_compute_device": ["cpu", "cuda"],
                    }[descriptor.name]
                    field.addItems(choices)
                    field.setCurrentText(str(value))
                else:
                    field = QLineEdit("" if value is None else str(value))
                    field.setPlaceholderText(
                        f"Saved: {descriptor.saved_value!s}; Effective: {descriptor.value!s}; "
                        f"Source: {descriptor.source}; "
                        f"{'restart required' if descriptor.restart_required else 'hot applicable'}"
                    )
                    if descriptor.secret:
                        field.setEchoMode(QLineEdit.EchoMode.Password)
                if descriptor.name in Settings.model_fields:
                    annotation = Settings.model_fields[descriptor.name].annotation
                    field.setProperty("optional-setting", type(None) in get_args(annotation))
                self._settings_form.addRow(f"{descriptor.name} ({descriptor.source})", field)
                self._setting_inputs[descriptor.name] = field
                self._setting_initial[descriptor.name] = self._setting_value(field)
            self._reset_setting_selector.clear()
            self._reset_setting_selector.addItems(
                [
                    descriptor.name
                    for descriptor in descriptors
                    if descriptor.editable
                    and descriptor.name not in {"version", "security_policy_version"}
                ]
            )

        def _refresh_persona(self) -> None:
            try:
                view = backend.submit(lambda service: service.persona()).result()
                self._persona_verbosity.setCurrentText(str(view.profile.verbosity))
                self._persona_response_length.setCurrentText(str(view.profile.response_length))
                self._persona_technical_depth.setCurrentText(str(view.profile.technical_depth))
                actor = backend.submit(lambda service: service.actor_context()).result()
                state = "active" if actor.active else "ended"
                self._actor_status.setText(
                    f"Current session: {actor.label or 'Application session'}; "
                    f"trusted source: {actor.source}; state: {state}"
                )
            except (AttributeError, ServiceUnavailableError):
                # Compatibility service doubles may expose only legacy settings.
                self._actor_status.setText("Persona/session provenance unavailable")

        def _save_persona(self) -> None:
            future = backend.submit(
                lambda service: service.update_persona(
                    {
                        "verbosity": int(self._persona_verbosity.currentText()),
                        "response_length": int(self._persona_response_length.currentText()),
                        "technical_depth": int(self._persona_technical_depth.currentText()),
                    }
                )
            )
            future.add_done_callback(self._persona_saved)

        def _reset_persona(self) -> None:
            future = backend.submit(lambda service: service.reset_persona())
            future.add_done_callback(self._persona_saved)

        def _persona_saved(self, future: Any) -> None:
            try:
                future.result()
                self._refresh_persona()
                self._stream_status.setText("Persona: saved; presentation preferences only")
                self._refresh_current_context()
            except Exception as error:
                self._signals.failed.emit(str(error))

        def _save_settings(self) -> None:
            self._restart_after_save = False
            self._save_settings_with_restart()

        def _save_and_restart(self) -> None:
            self._restart_after_save = True
            self._save_settings_with_restart()

        def _reset_setting_to_default(self) -> None:
            name = self._reset_setting_selector.currentText()
            if not name:
                return
            self._restart_after_save = False
            future = backend.submit(lambda service: service.reset_setting_to_default(name))
            future.add_done_callback(self._signals.settings_finished.emit)

        def _save_settings_with_restart(self) -> None:
            updates = {
                name: self._setting_value(field)
                for name, field in self._setting_inputs.items()
                if name not in {"version", "security_policy_version"}
                and name in Settings.model_fields
                and self._setting_value(field) != self._setting_initial.get(name)
            }
            if not updates:
                self._restart_if_requested()
                return
            future = backend.submit(lambda service: service.save_settings(updates))
            future.add_done_callback(self._signals.settings_finished.emit)

        def _settings_saved(self, future: Any) -> None:
            try:
                future.result()
                self._refresh_settings()
                self._stream_status.setText(
                    "Settings: saved; restart-required values apply after restart"
                )
                self._restart_if_requested()
            except Exception as error:
                self._restart_after_save = False
                self._signals.failed.emit(str(error))

        def _restart_if_requested(self) -> None:
            if not self._restart_after_save:
                return
            self._restart_after_save = False
            if restart is None:
                self._signals.failed.emit("Restart is unavailable for this desktop session")
                return
            try:
                restart()
            except Exception as error:
                self._signals.failed.emit(f"Desktop restart failed: {error}")
                return
            self.close()

        def _restart_desktop(self) -> None:
            self._restart_after_save = True
            self._restart_if_requested()

        @staticmethod
        def _setting_value(field: QLineEdit | QCheckBox | QComboBox) -> object:
            if isinstance(field, QCheckBox):
                return field.isChecked()
            if isinstance(field, QComboBox):
                return field.currentText()
            value = field.text()
            return None if not value and field.property("optional-setting") else value

        @staticmethod
        def _settings_group(name: str) -> str:
            if name in {"environment", "host", "port", "log_level", "log_json", "version"}:
                return "General"
            if name.startswith(("ai_", "ollama_")):
                return "AI / Ollama"
            if name.startswith(("stt_", "tts_", "voice_")):
                return "Speech"
            if name.startswith(("agent_", "multi_agent_")):
                return "Agent"
            if name in {
                "discovery_enabled",
                "improvement_enabled",
                "autonomous_scheduling_enabled",
            }:
                return "Capabilities / Autonomy"
            if name in {"computer_enabled", "camera_enabled", "application_management_enabled"}:
                return "Hardware"
            if name in {"remote_approval_enabled", "security_policy_version"}:
                return "Security / Privacy"
            if name.endswith(("_dir", "_path")):
                return "Paths"
            return "Developer / Advanced"

        def _toggle_microphone(self) -> None:
            if self._microphone.text() == "Start microphone":
                self._microphone.setText("Stop microphone")
                self._speech_status.setText("STT: recording")
                future = backend.submit_async(lambda service: service.start_recording())
                future.add_done_callback(self._signals.recording_started.emit)
            else:
                self._microphone.setEnabled(False)
                self._speech_status.setText("STT: transcribing")
                future = backend.submit_async(lambda service: service.stop_recording())
                future.add_done_callback(lambda result: self._recording_stopped(result))

        def _recording_started(self, future: Any) -> None:
            try:
                future.result()
            except Exception as error:
                self._microphone.setText("Start microphone")
                self._signals.failed.emit(str(error))

        def _recording_stopped(self, future: Any) -> None:
            try:
                self._signals.recording_finished.emit(future.result())
            except Exception as error:
                self._microphone.setEnabled(True)
                self._microphone.setText("Start microphone")
                self._speech_status.setText("STT: unavailable")
                self._signals.failed.emit(str(error))

        def _recording_finished(self, text: str) -> None:
            self._microphone.setEnabled(True)
            self._microphone.setText("Start microphone")
            self._speech_status.setText("STT: ready")
            if text:
                self._input.setText(text)

        def _show_error(self, message: str) -> None:
            self._error.setText(f"Error: {message}")
            self._send.setEnabled(True)

        def closeEvent(self, event: Any) -> None:
            if self._text_future is not None and self._conversation_id is not None:
                backend.cancel(self._conversation_id)
            backend.close()
            event.accept()

    existing_app = QApplication.instance()
    app = existing_app if isinstance(existing_app, QApplication) else QApplication([])
    app.setFont(QFont("Arial", 10))
    window = MainWindow()
    window.show()
    return app.exec()
