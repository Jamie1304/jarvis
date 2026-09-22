"""Desktop application entry point."""

import subprocess
import sys

from jarvis.bootstrap import create_application_runtime, create_desktop_facade_from_runtime
from jarvis.frontend.desktop import run_desktop_app
from jarvis.frontend.desktop_backend import DesktopBackendHost


def restart_desktop_process() -> None:
    """Launch the fixed desktop entry point without accepting executable input."""

    subprocess.Popen(
        [sys.executable, "-m", "jarvis.desktop"],
        close_fds=True,
        shell=False,
    )


def main() -> int:
    """Create the configured local application and run its optional desktop UI."""

    backend = DesktopBackendHost(create_application_runtime, create_desktop_facade_from_runtime)
    return run_desktop_app(backend, restart=restart_desktop_process)


if __name__ == "__main__":
    raise SystemExit(main())
