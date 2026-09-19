import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from jarvis.acceptance.specs import SPECS, validate_specs

validate_specs()
print(f"validated {len(SPECS)} canonical acceptance specifications")
