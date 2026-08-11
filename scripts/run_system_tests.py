"""Run one trusted deterministic system-test suite and print a JSON evidence record."""

from __future__ import annotations

import argparse
import asyncio
import json
import subprocess
import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))


def _revision(project_root: Path) -> str:
    try:
        result = subprocess.run(
            ["git", "rev-parse", "HEAD"],
            cwd=project_root,
            check=False,
            capture_output=True,
            text=True,
            timeout=5,
        )
    except (OSError, subprocess.SubprocessError):
        return "unknown"
    revision = result.stdout.strip()
    return revision if revision else "unknown"


async def _run(suite_id: str) -> int:
    from jarvis.testing.catalog import create_deterministic_suite_catalog
    from jarvis.testing.runner import ControlledTestRunner, TestArtifactStore

    project_root = PROJECT_ROOT
    runner = ControlledTestRunner(
        create_deterministic_suite_catalog(),
        project_root,
        TestArtifactStore(project_root / "build" / "system-test-artifacts"),
    )
    run = await runner.run(suite_id, _revision(project_root), asyncio.Event())
    print(json.dumps(run.to_dict(), sort_keys=True))
    return 0 if run.status.value in {"passed", "skipped"} else 1


def main() -> int:
    from jarvis.testing.catalog import create_deterministic_suite_catalog

    catalog = create_deterministic_suite_catalog()
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--suite", required=True, choices=tuple(suite.suite_id for suite in catalog.all())
    )
    arguments = parser.parse_args()
    return asyncio.run(_run(arguments.suite))


if __name__ == "__main__":
    raise SystemExit(main())
