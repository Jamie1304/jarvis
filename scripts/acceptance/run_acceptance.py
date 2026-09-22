"""Canonical Acceptance Lab entrypoint."""

from __future__ import annotations

import argparse
import asyncio
import sys
from collections.abc import Mapping
from pathlib import Path
from typing import cast

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from jarvis.acceptance.runner import AcceptanceRunner, Selection


def main() -> int:
    parser = argparse.ArgumentParser(description="Run a selectable JARVIS acceptance profile")
    parser.add_argument(
        "--profile",
        default="auto",
        choices=(
            "smoke",
            "vm-foundation",
            "auto",
            "vm",
            "windows",
            "security",
            "self-repair",
            "full",
        ),
    )
    parser.add_argument("--test", action="append", default=[])
    parser.add_argument("--tests")
    parser.add_argument("--phase")
    parser.add_argument("--tags", default="")
    parser.add_argument("--resume", action="store_true")
    parser.add_argument(
        "--real-vm",
        action="store_true",
        help="Use the existing JARVIS WSL2 provider for VM-classified tests",
    )
    parser.add_argument(
        "--fault", action="store_true", help="Run a harmless disposable fault transaction"
    )
    args = parser.parse_args()
    selected = set(args.test)
    if args.tests:
        start, end = (int(value) for value in args.tests.split("-", 1))
        selected.update(f"{value:03}" for value in range(start, end + 1))
    root = Path(__file__).resolve().parents[2]
    environment = None
    if args.real_vm:
        from jarvis.acceptance.environment import VMAcceptanceEnvironment
        from jarvis.vm import WSL2VirtualizationProvider

        environment = VMAcceptanceEnvironment(WSL2VirtualizationProvider())
    runner = AcceptanceRunner(root, environment=environment)
    specs = runner.select(
        profile=args.profile,
        test_ids=tuple(sorted(selected)),
        tags=tuple(filter(None, args.tags.split(","))),
        phase=args.phase,
    )
    report = asyncio.run(
        runner.run(
            Selection(tuple(item.test_id for item in specs), args.profile, fault=args.fault),
            resume=args.resume,
        )
    )
    report_values = cast(Mapping[str, object], report)
    specifications = cast(Mapping[str, object], report_values["specifications"])
    counts = cast(Mapping[str, int], report_values["counts"])
    print(
        f"defined={specifications['defined']} selected={specifications['selected']} counts={counts}"
    )
    return 1 if counts.get("FAIL", 0) else 0


if __name__ == "__main__":
    raise SystemExit(main())
