"""Ensure the repo root (which holds the `guard` package) is importable
when pytest collects tests from the tests/ directory."""

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))
