"""Desktop application entry point."""

from jarvis.bootstrap import create_assistant_service
from jarvis.core.config import get_settings
from jarvis.frontend.desktop import run_desktop_app


def main() -> int:
    """Create the configured local application and run its optional desktop UI."""

    return run_desktop_app(create_assistant_service(get_settings()))


if __name__ == "__main__":
    raise SystemExit(main())
