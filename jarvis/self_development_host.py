"""Trusted headless candidate entrypoint used by the self-development host."""

from __future__ import annotations

import json
import sys
from pathlib import Path

from jarvis.core.config import Settings
from jarvis.recovery import compute_application_build_hash
from jarvis.runtime import ApplicationRuntime, RuntimeStatus


def main(arguments: list[str]) -> int:
    if len(arguments) != 1:
        return 2
    app_data = Path(arguments[0]).expanduser().resolve()
    runtime = ApplicationRuntime.create(
        Settings(environment="local", app_data_dir=app_data, ai_provider="ollama"),
        project_root=Path(__file__).resolve().parents[1],
    )
    root = Path(__file__).resolve().parents[1]
    payload = {
        "application_hash": compute_application_build_hash(root),
        "root": str(root),
        "status": runtime.status.value,
    }
    sys.stdout.write(json.dumps(payload, sort_keys=True) + "\n")
    return 0 if runtime.status is RuntimeStatus.READY else 1


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
