from __future__ import annotations

import io
import tempfile
import unittest
from contextlib import redirect_stderr, redirect_stdout
from pathlib import Path

from complyroll.compat.stigroll import Finding, main, render_csv, render_markdown, summarize

TEST_ROOT = Path(__file__).parent
FIXTURES = TEST_ROOT / "fixtures"
GOLDEN = TEST_ROOT / "golden"


class StigrollCompatibilityTests(unittest.TestCase):
    def run_cli(self, arguments: list[str]) -> tuple[int, str, str]:
        stdout = io.StringIO()
        stderr = io.StringIO()
        with redirect_stdout(stdout), redirect_stderr(stderr):
            result = main(arguments)
        return result, stdout.getvalue(), stderr.getvalue()

    def test_markdown_matches_original_stigroll_golden_output(self) -> None:
        result, stdout, stderr = self.run_cli([str(FIXTURES / "ubuntu-host.cklb")])
        expected = (GOLDEN / "ubuntu-host.md").read_text(encoding="utf-8")
        self.assertEqual(result, 0)
        self.assertEqual(stderr, "")
        self.assertEqual(stdout, f"{expected}\n")

    def test_csv_matches_original_stigroll_golden_output(self) -> None:
        inputs = [
            str(FIXTURES / "windows-host.ckl"),
            str(FIXTURES / "ubuntu-host.cklb"),
            str(FIXTURES / "openscap-results.xml"),
        ]
        result, stdout, stderr = self.run_cli([*inputs, "--format", "csv"])
        expected = (GOLDEN / "mixed.csv").read_bytes().decode("utf-8")
        self.assertEqual(result, 0)
        self.assertEqual(stderr, "")
        self.assertEqual(stdout, f"{expected}\n")

    def test_json_matches_original_stigroll_golden_output(self) -> None:
        inputs = [
            str(FIXTURES / "windows-host.ckl"),
            str(FIXTURES / "ubuntu-host.cklb"),
            str(FIXTURES / "openscap-results.xml"),
        ]
        result, stdout, stderr = self.run_cli([*inputs, "--format", "json"])
        expected = (GOLDEN / "mixed.json").read_text(encoding="utf-8")
        self.assertEqual(result, 0)
        self.assertEqual(stderr, "")
        self.assertEqual(stdout, f"{expected}\n")

    def test_output_file_workflow_is_preserved(self) -> None:
        expected = (GOLDEN / "ubuntu-host.md").read_text(encoding="utf-8")
        with tempfile.TemporaryDirectory() as directory:
            output_path = Path(directory) / "rollup.md"
            result, stdout, stderr = self.run_cli(
                [str(FIXTURES / "ubuntu-host.cklb"), "-o", str(output_path)]
            )
            actual = output_path.read_text(encoding="utf-8")

        self.assertEqual(result, 0)
        self.assertEqual(stdout, "")
        self.assertEqual(stderr, f"wrote {output_path}\n")
        self.assertEqual(actual, expected)

    def test_malformed_input_is_visible_and_cannot_report_clean(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "broken.cklb"
            path.write_text("{", encoding="utf-8")
            result, stdout, stderr = self.run_cli([str(path)])

        self.assertEqual(result, 1)
        self.assertEqual(stdout, "")
        self.assertIn("warning: could not parse broken.cklb", stderr)
        self.assertIn("error: no findings parsed from any input", stderr)

    def test_cci_mapping_remains_available(self) -> None:
        result, stdout, stderr = self.run_cli(
            [
                str(FIXTURES / "windows-host.ckl"),
                "--cci-list",
                str(FIXTURES / "cci-list.xml"),
                "--format",
                "json",
            ]
        )
        self.assertEqual(result, 0)
        self.assertEqual(stderr, "")
        expected = (GOLDEN / "mixed-mapped.json").read_text(encoding="utf-8")
        mixed_result, mixed_stdout, mixed_stderr = self.run_cli(
            [
                str(FIXTURES / "windows-host.ckl"),
                str(FIXTURES / "ubuntu-host.cklb"),
                str(FIXTURES / "openscap-results.xml"),
                "--cci-list",
                str(FIXTURES / "cci-list.xml"),
                "--format",
                "json",
            ]
        )
        self.assertEqual(mixed_result, 0)
        self.assertEqual(mixed_stderr, "")
        self.assertEqual(mixed_stdout, f"{expected}\n")
        self.assertIn('"CM-6"', stdout)

    def test_csv_formula_injection_is_neutralized(self) -> None:
        finding = Finding(
            rule_id="V-1",
            title="=HYPERLINK(\"https://invalid.example\")",
            severity="high",
            status="open",
            host="@synthetic-host",
            source="synthetic.cklb",
            ccis=(),
            controls=(),
        )
        output = render_csv([finding])
        self.assertIn("'@synthetic-host", output)
        self.assertIn("'=HYPERLINK", output)

    def test_markdown_cells_do_not_emit_raw_html_or_new_rows(self) -> None:
        finding = Finding(
            rule_id="V-1",
            title="<script>|next\nrow</script>",
            severity="high",
            status="open",
            host="<b>synthetic-host</b>",
            source="synthetic.cklb",
            ccis=(),
            controls=(),
        )
        output = render_markdown([finding], summarize([finding]))
        self.assertNotIn("<script>", output)
        self.assertNotIn("<b>", output)
        self.assertIn("&lt;script&gt;\\|next row&lt;/script&gt;", output)


if __name__ == "__main__":
    unittest.main()
