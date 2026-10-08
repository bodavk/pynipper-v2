"""Standalone offline sample-preparation entry point; never modifies audits."""
from pathlib import Path
import sys

REPOSITORY_ROOT = Path(__file__).resolve().parents[1]
if str(REPOSITORY_ROOT) not in sys.path:
    sys.path.insert(0, str(REPOSITORY_ROOT))

from src.anonymize.__main__ import main  # noqa: E402


if __name__ == "__main__":
    raise SystemExit(main())
