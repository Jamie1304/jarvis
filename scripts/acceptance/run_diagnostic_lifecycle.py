"""Run one fresh direct-base diagnostic lifecycle without formal counting."""

from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path
from uuid import uuid4

from jarvis.acceptance.evidence import qualification_source_seal
from jarvis.acceptance.formal_campaign import (
    FormalCampaignError,
    RealQualificationLifecycleExecutor,
    validate_lifecycle_record,
)

ROOT = Path(__file__).resolve().parents[2]


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--interpreter",
        default=os.environ.get("JARVIS_QUALIFICATION_PYTHON", sys.executable),
    )
    parser.add_argument("--timeout-seconds", type=float, default=600.0)
    arguments = parser.parse_args()
    starting_seal, bound_files = qualification_source_seal(ROOT)
    run_id = f"diagnostic-{uuid4().hex}"
    result: dict[str, object] = {
        "schema": "diagnostic-lifecycle-run-2",
        "run_id": run_id,
        "formal_count": 0,
        "source_seal": starting_seal,
        "source_bound_file_count": len(bound_files),
        "interpreter": str(Path(arguments.interpreter).resolve()),
    }
    try:
        executor = RealQualificationLifecycleExecutor(
            interpreter=Path(arguments.interpreter),
            root=ROOT,
            timeout_seconds=arguments.timeout_seconds,
        )
        record = validate_lifecycle_record(executor.execute(run_id))
        final_seal, final_files = qualification_source_seal(ROOT)
        if final_seal != starting_seal or len(final_files) != len(bound_files):
            raise FormalCampaignError(
                "SOURCE_SEAL_MISMATCH", "source changed during diagnostic run"
            )
        result.update(
            {
                "terminal": True,
                "result": "PASS",
                "record": record.as_dict(),
                "final_source_seal": final_seal,
            }
        )
        print(json.dumps(result, sort_keys=True))
        return 0
    except FormalCampaignError as error:
        result.update(
            {
                "terminal": True,
                "result": "FAIL",
                "failure_code": error.code,
                "failure": str(error),
                "final_source_seal": qualification_source_seal(ROOT)[0],
            }
        )
        if error.subprocess_evidence is not None:
            result["subprocess"] = error.subprocess_evidence.as_dict()
        print(json.dumps(result, sort_keys=True))
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
