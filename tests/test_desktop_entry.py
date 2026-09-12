from __future__ import annotations

import subprocess
import sys
from typing import Any

from jarvis import desktop


def test_restart_desktop_process_uses_fixed_module_command(monkeypatch: Any) -> None:
    launched: list[tuple[list[str], dict[str, object]]] = []

    def fake_popen(arguments: list[str], **kwargs: object) -> object:
        launched.append((arguments, kwargs))
        return object()

    monkeypatch.setattr(subprocess, "Popen", fake_popen)

    desktop.restart_desktop_process()

    assert launched == [
        (
            [sys.executable, "-m", "jarvis.desktop"],
            {"close_fds": True, "shell": False},
        )
    ]
