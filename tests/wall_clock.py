# ******************************************************************************
# *Title: Wall-Clock Switch*
# *Author: Kyle Versluis*
# *Description: Gates the suite's wall-clock bounds on COMPLYROLL_TIMING_TESTS.*
# ******************************************************************************
"""The one switch for the suite's wall-clock bounds.

A bound on elapsed time can fail under heavy parallel load however correct the code is, so
a test asserts one only when `COMPLYROLL_TIMING_TESTS` is `1`. CI sets it. The work the bound
times, and every other assertion, run either way.
"""

# *--- Imports ---*

from __future__ import annotations

import os

# *--- Configuration ---*

#: Whether the wall-clock assertions run: set in CI, and in a local run that exports it.
TIMING_TESTS = os.environ.get("COMPLYROLL_TIMING_TESTS") == "1"
