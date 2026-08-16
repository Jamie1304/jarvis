"""Desktop application entry point."""

from jarvis.bootstrap import create_application_runtime, create_assistant_from_runtime
from jarvis.core.config import get_settings
from jarvis.frontend.desktop import run_desktop_app


def main() -> int:
    """Create the configured local application and run its optional desktop UI."""

    runtime = create_application_runtime(get_settings())
    return run_desktop_app(create_assistant_from_runtime(runtime))


if __name__ == "__main__":
    raise SystemExit(main())
