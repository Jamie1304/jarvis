"""Run one real, finite formal acquisition campaign."""

from __future__ import annotations

import argparse
import json
import os
import sys
from collections.abc import Sequence
from pathlib import Path
from uuid import uuid4

from jarvis.acceptance.campaign import ConsecutiveQualificationCampaign
from jarvis.acceptance.evidence import (
    QUALIFICATION_LIFECYCLE_EVIDENCE_SCHEMA,
    qualification_source_seal,
)
from jarvis.acceptance.formal_campaign import (
    FormalCampaignExecutor,
    FormalCampaignKind,
    LifecycleExecutor,
    RealQualificationLifecycleExecutor,
    interpreter_identity,
)

ROOT = Path(__file__).resolve().parents[2]


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--campaign", choices=("three", "ten"), required=True)
    parser.add_argument(
        "--interpreter",
        default=os.environ.get("JARVIS_QUALIFICATION_PYTHON", sys.executable),
        help="direct-base interpreter bound by the machine qualification manifest",
    )
    return parser


def main(
    argv: Sequence[str] | None = None,
    *,
    lifecycle_executor: LifecycleExecutor | None = None,
    root: Path = ROOT,
) -> int:
    arguments = _parser().parse_args(argv)
    kind = (
        FormalCampaignKind.THREE_OF_THREE
        if arguments.campaign == "three"
        else FormalCampaignKind.FINAL_TEN
    )
    starting_seal, bound_files = qualification_source_seal(root)
    campaign_run_id = f"formal-{kind.value.casefold()}-{uuid4().hex}"
    if lifecycle_executor is None:
        interpreter = Path(arguments.interpreter).resolve()
        lifecycle_executor = RealQualificationLifecycleExecutor(
            interpreter=interpreter,
            root=root,
            timeout_seconds=600.0,
        )
    else:
        interpreter = Path(arguments.interpreter).resolve()
    campaign = ConsecutiveQualificationCampaign(
        required_success_count=kind.required_count,
        source_seal=starting_seal,
        record_schema=QUALIFICATION_LIFECYCLE_EVIDENCE_SCHEMA,
    )
    interpreter_name, base_executable = interpreter_identity(interpreter)
    executor = FormalCampaignExecutor(
        campaign=campaign,
        campaign_run_id=campaign_run_id,
        kind=kind,
        lifecycle_executor=lifecycle_executor,
        source_seal=starting_seal,
        source_seal_provider=lambda: qualification_source_seal(root)[0],
        source_bound_file_count=len(bound_files),
        interpreter=interpreter_name,
        base_executable=base_executable,
        source_bound_file_count_provider=lambda: len(qualification_source_seal(root)[1]),
    )
    result = executor.execute()
    print(json.dumps(result.as_dict(), sort_keys=True))
    return 0 if result.terminal_status.value == "SUCCEEDED" else 1


if __name__ == "__main__":
    raise SystemExit(main())
