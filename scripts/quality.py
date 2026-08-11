"""Run the complete local quality gate."""

import subprocess
import sys


def main() -> int:
    commands = [
        [sys.executable, "-m", "ruff", "format", "--check", "."],
        [sys.executable, "-m", "ruff", "check", "."],
        [sys.executable, "-m", "mypy", "jarvis", "tests"],
        [sys.executable, "-m", "coverage", "run", "-m", "pytest"],
        [sys.executable, "-m", "coverage", "report"],
    ]
    for command in commands:
        print("$", " ".join(command), flush=True)
        result = subprocess.run(command, check=False)
        if result.returncode:
            return result.returncode
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
