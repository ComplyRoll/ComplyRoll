from __future__ import annotations

import io
import json
import tempfile
import unittest
from contextlib import redirect_stderr, redirect_stdout
from pathlib import Path

from complyroll.compat.stigroll import Finding, main, render_csv, render_markdown, summarize

TEST_ROOT = Path(__file__).parent
FIXTURES = TEST_ROOT / "fixtures"
GOLDEN = TEST_ROOT / "golden"
# A checklist under each SARIF or HDF name, and the refusal its adapter gives it.
REFUSED_CHECKLISTS = (
    (
        "checklist.hdf.json",
        "HDF document carries a 'stigs' member; a STIG Viewer checklist is read under a "
        ".cklb or .json name",
    ),
    ("checklist.sarif", "SARIF version must be the string 2.1.0"),
    ("checklist.sarif.json", "SARIF version must be the string 2.1.0"),
)


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

    def test_a_sarif_log_is_skipped_with_a_warning_and_the_csv_is_unchanged(self) -> None:
        # stigroll rolls up STIG checklists; a SARIF log would otherwise read as zero
        # findings in silence, so it is named and skipped before the parse diagnostics.
        inputs = [
            str(FIXTURES / "windows-host.ckl"),
            str(FIXTURES / "trivy-image.sarif"),
            str(FIXTURES / "ubuntu-host.cklb"),
            str(FIXTURES / "openscap-results.xml"),
        ]
        result, stdout, stderr = self.run_cli([*inputs, "--format", "csv"])
        expected = (GOLDEN / "mixed.csv").read_bytes().decode("utf-8")
        self.assertEqual(result, 0)
        self.assertEqual(
            stderr,
            "warning: trivy-image.sarif is a SARIF log; stigroll rolls up STIG checklists "
            "only, skipping\n",
        )
        self.assertEqual(stdout, f"{expected}\n")

    def test_a_lone_sarif_log_yields_no_findings_and_exit_code_one(self) -> None:
        result, stdout, stderr = self.run_cli([str(FIXTURES / "codeql-repo.sarif")])
        self.assertEqual(result, 1)
        self.assertEqual(stdout, "")
        self.assertEqual(
            stderr,
            "warning: codeql-repo.sarif is a SARIF log; stigroll rolls up STIG checklists "
            "only, skipping\n"
            "error: no findings parsed from any input\n",
        )

    def test_hdf_documents_are_skipped_with_a_warning_and_the_csv_is_unchanged(self) -> None:
        # An HDF document is named and skipped like a SARIF log, whether its name ends
        # .hdf.json or it is a bare .json the sniff sends to the HDF adapter, where it used
        # to be told it has no 'stigs' key (ADR 0013).
        inputs = [
            str(FIXTURES / "windows-host.ckl"),
            str(FIXTURES / "inspec-linux-host.hdf.json"),
            str(FIXTURES / "ubuntu-host.cklb"),
            str(FIXTURES / "inspec-overlay.json"),
            str(FIXTURES / "openscap-results.xml"),
        ]
        result, stdout, stderr = self.run_cli([*inputs, "--format", "csv"])
        expected = (GOLDEN / "mixed.csv").read_bytes().decode("utf-8")
        self.assertEqual(result, 0)
        self.assertEqual(
            stderr,
            "warning: inspec-linux-host.hdf.json is an HDF document; stigroll rolls up STIG "
            "checklists only, skipping\n"
            "warning: inspec-overlay.json is an HDF document; stigroll rolls up STIG "
            "checklists only, skipping\n",
        )
        self.assertEqual(stdout, f"{expected}\n")

    def test_a_lone_hdf_document_yields_no_findings_and_exit_code_one(self) -> None:
        for name in ("saf-trivy-image.hdf.json", "inspec-overlay.json"):
            with self.subTest(name=name):
                result, stdout, stderr = self.run_cli([str(FIXTURES / name)])
                self.assertEqual(result, 1)
                self.assertEqual(stdout, "")
                self.assertEqual(
                    stderr,
                    f"warning: {name} is an HDF document; stigroll rolls up STIG checklists "
                    "only, skipping\n"
                    "error: no findings parsed from any input\n",
                )

    def run_on(self, name: str, content: bytes, *arguments: str) -> tuple[int, str, str]:
        """Run the CLI on one file written under the given name, then the given arguments."""
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / name
            path.write_bytes(content)
            return self.run_cli([str(path), *arguments])

    def test_a_refused_checklist_says_why_and_is_never_named_as_a_log_or_document(self) -> None:
        # A file that fails under a SARIF or HDF name is neither, so it is told why as a
        # checklist is, rather than skipped as the log or document it could not be read as.
        checklist = (FIXTURES / "ubuntu-host.cklb").read_bytes()
        for name, message in REFUSED_CHECKLISTS:
            with self.subTest(name=name):
                result, stdout, stderr = self.run_on(name, checklist)
                self.assertEqual(result, 1)
                self.assertEqual(stdout, "")
                self.assertEqual(
                    stderr,
                    f"warning: could not parse {name}: {message}\n"
                    "error: no findings parsed from any input\n",
                )

    def test_malformed_json_under_a_sarif_or_hdf_name_names_the_decode_error(self) -> None:
        try:
            json.loads("{")
        except json.JSONDecodeError as exc:
            decode_error = str(exc)
        for name in ("malformed.hdf.json", "malformed.sarif", "malformed.sarif.json"):
            with self.subTest(name=name):
                result, stdout, stderr = self.run_on(name, b"{")
                self.assertEqual(result, 1)
                self.assertEqual(stdout, "")
                self.assertEqual(
                    stderr,
                    f"warning: could not parse {name}: {decode_error}\n"
                    "error: no findings parsed from any input\n",
                )
                self.assertNotIn("skipping", stderr)

    def test_a_malformed_sarif_or_hdf_file_leaves_the_checklist_rollup_unchanged(self) -> None:
        checklist = str(FIXTURES / "ubuntu-host.cklb")
        alone, expected, quiet = self.run_cli([checklist, "--format", "csv"])
        self.assertEqual((alone, quiet), (0, ""))
        for name in ("malformed.hdf.json", "malformed.sarif", "malformed.sarif.json"):
            with self.subTest(name=name):
                result, stdout, stderr = self.run_on(name, b"{", checklist, "--format", "csv")
                self.assertEqual(result, 0)
                self.assertEqual(stdout, expected)
                self.assertTrue(stderr.startswith(f"warning: could not parse {name}: "), stderr)
                self.assertEqual(stderr.count("\n"), 1)

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
