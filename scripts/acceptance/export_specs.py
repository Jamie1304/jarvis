"""Export the typed registry to a portable JSON acceptance specification."""

import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from jarvis.acceptance.specs import SPECS, validate_specs

validate_specs()
target = Path(__file__).resolve().parents[2] / "docs" / "testing" / "acceptance-specs-v1.json"
target.write_text(
    json.dumps(
        {"schema_version": "1.0", "tests": [item.as_dict() for item in SPECS]},
        indent=2,
        ensure_ascii=False,
    )
    + "\n",
    encoding="utf-8",
)
print(target)
