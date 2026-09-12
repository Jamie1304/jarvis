import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from jarvis.qualification_manifest import write_manifest

if __name__ == "__main__":
    target = (
        Path(sys.argv[1])
        if len(sys.argv) > 1
        else Path("artifacts/acceptance/qualification-manifest.json")
    )
    write_manifest(target)
    print(target)
