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

    def test_a_cyclonedx_bom_is_skipped_with_a_warning(self) -> None:
        # A bare bom.json reaches the CycloneDX adapter by the sniff, where it used to be told
        # it has no 'stigs' key (ADR 0016).
        for name in ("syft-image.cdx.json", "bom.json"):
            with self.subTest(name=name):
                result, stdout, stderr = self.run_cli([str(FIXTURES / name)])
                self.assertEqual(result, 1)
                self.assertEqual(stdout, "")
                self.assertEqual(
                    stderr,
                    f"warning: {name} is a CycloneDX BOM; stigroll rolls up STIG checklists "
                    "only, skipping\n"
                    "error: no findings parsed from any input\n",
                )

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
            title='=HYPERLINK("https://invalid.example")',
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


#: Text that would forge a line, move the cursor and clear the screen if printed raw.
FORGING_TEXT = "x\nerror: forged: injected\r\u2028\x1b[2J\x9b"
#: The same text as the command prints it, every control spelled as an escape.
FORGING_SHOWN = "x\\nerror: forged: injected\\r\\u2028\\x1b[2J\\x9b"


def run_on_encoding(arguments: list[str], encoding: str) -> tuple[int, bytes, bytes]:
    """Run stigroll on byte streams that encode as a terminal set to `encoding` does."""
    out_bytes = io.BytesIO()
    err_bytes = io.BytesIO()
    out = io.TextIOWrapper(out_bytes, encoding=encoding, errors="strict", write_through=True)
    err = io.TextIOWrapper(err_bytes, encoding=encoding, errors="strict", write_through=True)
    with redirect_stdout(out), redirect_stderr(err):
        result = main(arguments)
    return result, out_bytes.getvalue(), err_bytes.getvalue()


class StigrollTerminalTextTests(unittest.TestCase):
    """stigroll prints its lines through the escape `complyroll` uses (CL-78).

    0.3.0a0 printed file names raw, so a newline in one forged a line, and a stdout that
    could not encode a character ended the run. UTF-8 output is byte for byte what it was.
    """

    def run_cli(self, arguments: list[str]) -> tuple[int, str, str]:
        return StigrollCompatibilityTests.run_cli(self, arguments)  # type: ignore[arg-type]

    def assert_unforged(self, text: str) -> None:
        for line in text.splitlines():
            self.assertFalse(line.startswith("error: forged"), line)
        for control in ("\x1b", "\r", "\u2028", "\x9b"):
            self.assertNotIn(control, text)

    def test_an_unrecognized_argument_forges_no_line(self) -> None:
        # argparse reads an argument holding a space as an input file, so this one holds none.
        stderr = io.StringIO()
        with redirect_stdout(io.StringIO()), redirect_stderr(stderr):
            with self.assertRaises(SystemExit) as caught:
                main([str(FIXTURES / "ubuntu-host.cklb"), "--x\nerror:forged\r\x1b[2J"])

        self.assertEqual(caught.exception.code, 2)
        self.assertEqual(
            stderr.getvalue().splitlines()[-1],
            "stigroll: error: unrecognized arguments: --x\\nerror:forged\\r\\x1b[2J",
        )
        self.assert_unforged(stderr.getvalue())

    def test_a_missing_input_forges_no_line(self) -> None:
        result, stdout, stderr = self.run_cli([f"{FORGING_TEXT}.ckl"])

        self.assertEqual((result, stdout), (1, ""))
        self.assertEqual(
            stderr,
            f"warning: {FORGING_SHOWN}.ckl not found, skipping\n"
            "error: no findings parsed from any input\n",
        )

    def test_a_parse_warning_forges_no_line(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / f"{FORGING_TEXT}.cklb"
            path.write_text("{", encoding="utf-8")
            result, stdout, stderr = self.run_cli([str(path)])

        self.assertEqual((result, stdout), (1, ""))
        self.assertTrue(stderr.startswith(f"warning: could not parse {FORGING_SHOWN}.cklb: "))
        self.assert_unforged(stderr)

    def test_the_written_path_forges_no_line(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory) / f"{FORGING_TEXT}.md"
            result, stdout, stderr = self.run_cli(
                [str(FIXTURES / "ubuntu-host.cklb"), "-o", str(output)]
            )
            written = output.read_text(encoding="utf-8")

        self.assertEqual((result, stdout), (0, ""))
        self.assertEqual(stderr, f"wrote {directory}/{FORGING_SHOWN}.md\n")
        self.assertEqual(written, (GOLDEN / "ubuntu-host.md").read_text(encoding="utf-8"))

    def test_an_ascii_stdout_writes_a_backslash_escape_and_finishes(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            checklist = Path(directory) / "caf\u00e9-host.cklb"
            checklist.write_bytes((FIXTURES / "ubuntu-host.cklb").read_bytes())
            missing = Path(directory) / "\u00e9.ckl"
            arguments = [str(missing), str(checklist), "--format", "csv"]
            result, ascii_out, ascii_err = run_on_encoding(arguments, "ascii")
            utf8_result, utf8_out, utf8_err = run_on_encoding(arguments, "utf-8")

        self.assertEqual((result, utf8_result), (0, 0))
        self.assertIn(b"caf\\xe9-host.cklb", ascii_out)
        self.assertEqual(ascii_out, utf8_out.decode("utf-8").encode("ascii", "backslashreplace"))
        self.assertEqual(ascii_err, utf8_err.decode("utf-8").encode("ascii", "backslashreplace"))
        self.assertIn(b"\\xe9.ckl not found, skipping", ascii_err)

    def test_utf8_output_is_byte_for_byte_the_golden(self) -> None:
        inputs = [
            str(FIXTURES / "windows-host.ckl"),
            str(FIXTURES / "ubuntu-host.cklb"),
            str(FIXTURES / "openscap-results.xml"),
        ]
        for arguments, golden in (
            ([*inputs, "--format", "json"], "mixed.json"),
            ([*inputs, "--format", "csv"], "mixed.csv"),
            ([str(FIXTURES / "ubuntu-host.cklb")], "ubuntu-host.md"),
        ):
            with self.subTest(golden=golden):
                result, stdout, stderr = run_on_encoding(arguments, "utf-8")
                self.assertEqual((result, stderr), (0, b""))
                self.assertEqual(stdout, (GOLDEN / golden).read_bytes() + b"\n")


if __name__ == "__main__":
    unittest.main()
