"""Trusted headless candidate entrypoint used by the self-development host."""

from __future__ import annotations

import asyncio
import json
import os
import sys
from pathlib import Path

from jarvis.core.config import Settings
from jarvis.credentials import EphemeralQualificationSecretBackend
from jarvis.recovery import compute_application_build_hash
from jarvis.runtime import ApplicationRuntime, RuntimeStatus


def main(arguments: list[str]) -> int:
    if len(arguments) != 1:
        return 2
    app_data = Path(arguments[0]).expanduser().resolve()
    return asyncio.run(_observe(app_data))


async def _observe(app_data: Path) -> int:
    root = Path(__file__).resolve().parents[1]
    runtime = ApplicationRuntime.create(
        Settings(environment="local", app_data_dir=app_data, ai_provider="ollama"),
        project_root=root,
        recovery_key_backend=EphemeralQualificationSecretBackend(),
    )
    status = runtime.status
    payload = {
        "application_hash": compute_application_build_hash(root),
        "environment_isolated": _environment_isolated(root),
        "root": str(root),
        "status": status.value,
    }
    close = getattr(runtime, "aclose", None)
    try:
        if callable(close):
            result = close()
            if hasattr(result, "__await__"):
                await result
    finally:
        sys.stdout.write(json.dumps(payload, sort_keys=True) + "\n")
    return 0 if status is RuntimeStatus.READY else 1


def _environment_isolated(root: Path) -> bool:
    forbidden = (
        "PYTEST_",
        "COVERAGE_",
        "JARVIS_",
        "GITHUB_",
        "CI",
        "GH_TOKEN",
        "GITHUB_TOKEN",
    )
    return all(
        not name.startswith(prefix) for name in os.environ for prefix in forbidden
    ) and os.environ.get("PYTHONPATH") == str(root)


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
