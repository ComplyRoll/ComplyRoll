#!/usr/bin/env python3
"""Source-checkout compatibility launcher for the original stigroll command."""

from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent / "src"))

from complyroll.compat.stigroll import main  # noqa: E402

if __name__ == "__main__":
    raise SystemExit(main())
