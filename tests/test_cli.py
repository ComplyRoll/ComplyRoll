from __future__ import annotations

import io
import unittest
from contextlib import redirect_stdout

from complyroll.cli import main


class CliTests(unittest.TestCase):
    def test_version(self) -> None:
        output = io.StringIO()
        with redirect_stdout(output):
            result = main(["version"])
        self.assertEqual(result, 0)
        self.assertEqual(output.getvalue(), "ComplyRoll 0.1.0a0\n")

    def test_plan_lists_all_phases(self) -> None:
        output = io.StringIO()
        with redirect_stdout(output):
            result = main(["plan"])
        self.assertEqual(result, 0)
        self.assertIn("Phase 0:", output.getvalue())
        self.assertIn("Phase 4:", output.getvalue())


if __name__ == "__main__":
    unittest.main()
