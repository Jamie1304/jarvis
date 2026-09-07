"""Emit the machine-bound source identity used by qualification Q01."""

from __future__ import annotations

import json
from pathlib import Path

from jarvis.acceptance.evidence import qualification_source_seal

ROOT = Path(__file__).resolve().parents[2]


def main() -> int:
    seal, files = qualification_source_seal(ROOT)
    print(
        json.dumps({"schema": "source-identity-1", "sha256": seal, "bound_file_count": len(files)})
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
