"""Run one trusted deterministic system-test suite and print a JSON evidence record."""

from __future__ import annotations

import argparse
import asyncio
import json
import os
import subprocess
import sys
import tempfile
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


def _tree(project_root: Path) -> str:
    try:
        result = subprocess.run(
            ["git", "rev-parse", "HEAD^{tree}"],
            cwd=project_root,
            check=False,
            capture_output=True,
            text=True,
            timeout=5,
        )
    except (OSError, subprocess.SubprocessError):
        return "unknown"
    tree = result.stdout.strip()
    return tree if tree else "unknown"


def _tested_worktree_tree(project_root: Path) -> str:
    """Hash the current tracked worktree through a private temporary index."""

    index_path: Path | None = None
    try:
        with tempfile.NamedTemporaryFile(
            prefix="jarvis-index-", suffix=".tmp", delete=False
        ) as handle:
            index_path = Path(handle.name)
        index_path.unlink(missing_ok=True)
        environment = dict(os.environ)
        environment["GIT_INDEX_FILE"] = str(index_path)
        for command in (
            ["git", "read-tree", "HEAD"],
            ["git", "add", "-u", "--", "."],
        ):
            result = subprocess.run(
                command,
                cwd=project_root,
                env=environment,
                check=False,
                capture_output=True,
                text=True,
                timeout=30,
            )
            if result.returncode:
                return "unknown"
        result = subprocess.run(
            ["git", "write-tree"],
            cwd=project_root,
            env=environment,
            check=False,
            capture_output=True,
            text=True,
            timeout=30,
        )
        tree = result.stdout.strip()
        return tree if result.returncode == 0 and tree else "unknown"
    except (OSError, subprocess.SubprocessError):
        return "unknown"
    finally:
        if index_path is not None:
            try:
                index_path.unlink(missing_ok=True)
            except OSError:
                pass


def _source_identity(project_root: Path) -> dict[str, object]:
    from jarvis.acceptance.evidence import qualification_source_seal

    seal, files = qualification_source_seal(project_root)
    return {"schema": "source-identity-1", "sha256": seal, "bound_file_count": len(files)}


async def _run(suite_id: str, *, allow_hardware: bool = False) -> int:
    from jarvis.testing.catalog import create_deterministic_suite_catalog
    from jarvis.testing.runner import ControlledTestRunner, TestArtifactStore

    project_root = PROJECT_ROOT
    source_before = _source_identity(project_root)
    tree_before = _tree(project_root)
    tested_tree_before = _tested_worktree_tree(project_root)
    runner = ControlledTestRunner(
        create_deterministic_suite_catalog(),
        project_root,
        TestArtifactStore(project_root / "build" / "system-test-artifacts"),
    )
    run = await runner.run(
        suite_id,
        _revision(project_root),
        asyncio.Event(),
        allow_hardware=allow_hardware,
    )
    source_after = _source_identity(project_root)
    tree_after = _tree(project_root)
    tested_tree_after = _tested_worktree_tree(project_root)
    payload = run.to_dict()
    payload["tree"] = tree_after
    payload["source_identity"] = source_after
    payload["execution"] = {
        "run_id": str(run.run_id),
        "command": [run.suite.command.executable, *run.suite.command.arguments],
        "selection": suite_id,
        "base_revision": run.revision,
        "tested_tree": tested_tree_after,
        "tree_before": tree_before,
        "tree_after": tree_after,
        "exit_code": run.exit_code,
        "source_identity_before": source_before,
        "source_identity_after": source_after,
        "raw_evidence": [
            {
                "path": f"build/system-test-artifacts/{artifact.relative_path}",
                "sha256": artifact.sha256,
            }
            for artifact in run.artifacts
        ],
        "tested_tree_before": tested_tree_before,
        "tested_tree_after": tested_tree_after,
    }
    print(json.dumps(payload, sort_keys=True))
    return 0 if run.status.value in {"passed", "skipped"} else 1


def main() -> int:
    from jarvis.testing.catalog import create_deterministic_suite_catalog

    catalog = create_deterministic_suite_catalog()
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--suite", required=True, choices=tuple(suite.suite_id for suite in catalog.all())
    )
    parser.add_argument(
        "--allow-hardware",
        action="store_true",
        help="Explicitly allow the catalogued opt-in hardware/manual suite to execute",
    )
    arguments = parser.parse_args()
    return asyncio.run(_run(arguments.suite, allow_hardware=arguments.allow_hardware))


if __name__ == "__main__":
    raise SystemExit(main())
