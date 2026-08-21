from __future__ import annotations

import io
import json
import shutil
import tempfile
import unittest
from collections.abc import Sequence
from contextlib import redirect_stderr, redirect_stdout
from pathlib import Path

from complyroll import __version__
from complyroll.cli import main

REPO_ROOT = Path(__file__).parent.parent
FIXTURES = REPO_ROOT / "tests" / "fixtures"
GOLDEN = REPO_ROOT / "tests" / "golden"
EXAMPLES = REPO_ROOT / "examples"

REPORT_ARGUMENTS = (
    "report",
    "vdt",
    str(FIXTURES / "ubuntu-host.cklb"),
    str(FIXTURES / "windows-host.ckl"),
    str(FIXTURES / "openscap-results.xml"),
    "--class",
    "C",
    "--package-uri",
    "https://example.test/cpo",
    "--from",
    "2026-08-01T00:00:00Z",
    "--to",
    "2026-08-31T23:59:59Z",
    "--as-of",
    "2026-08-21T12:00:00Z",
    "--detected-at",
    "2026-08-01T00:00:00Z",
    "--evaluations",
    str(EXAMPLES / "evaluations.json"),
)


def run(argv: Sequence[str]) -> tuple[int, str, str]:
    """Run one CLI invocation and capture its streams."""

    out = io.StringIO()
    err = io.StringIO()
    with redirect_stdout(out), redirect_stderr(err):
        code = main(list(argv))
    return code, out.getvalue(), err.getvalue()


class CliTests(unittest.TestCase):
    def test_version(self) -> None:
        code, out, _ = run(["version"])

        self.assertEqual(code, 0)
        self.assertEqual(out, f"ComplyRoll {__version__}\n")

    def test_plan_lists_all_phases(self) -> None:
        code, out, _ = run(["plan"])

        self.assertEqual(code, 0)
        self.assertIn("Phase 0:", out)
        self.assertIn("Phase 4:", out)


class ReportVdtCommandTests(unittest.TestCase):
    def test_report_writes_the_golden_json_and_markdown(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            json_path = Path(directory) / "report.json"
            markdown_path = Path(directory) / "report.md"

            code, out, err = run(
                [*REPORT_ARGUMENTS, "-o", str(json_path), "--markdown", str(markdown_path)]
            )

            self.assertEqual(code, 0)
            self.assertEqual(out, "")
            self.assertIn("warning: source_timestamp_missing", err)
            self.assertEqual(
                json_path.read_text(encoding="utf-8"),
                (GOLDEN / "vdt-fixtures.json").read_text(encoding="utf-8"),
            )
            self.assertEqual(
                markdown_path.read_text(encoding="utf-8"),
                (GOLDEN / "vdt-fixtures.md").read_text(encoding="utf-8"),
            )

    def test_report_without_output_writes_json_to_stdout(self) -> None:
        code, out, _ = run(list(REPORT_ARGUMENTS))

        self.assertEqual(code, 0)
        self.assertEqual(out, (GOLDEN / "vdt-fixtures.json").read_text(encoding="utf-8"))
        self.assertEqual(len(json.loads(out)["vulnerabilities"]), 6)

    def test_report_refuses_to_overwrite_an_input_artifact(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            artifact = Path(directory) / "windows-host.ckl"
            shutil.copyfile(FIXTURES / "windows-host.ckl", artifact)
            before = artifact.read_bytes()

            code, out, err = run(
                [
                    "report",
                    "vdt",
                    str(artifact),
                    "--class",
                    "C",
                    "--package-uri",
                    "https://example.test/cpo",
                    "--from",
                    "2026-08-01T00:00:00Z",
                    "--to",
                    "2026-08-31T23:59:59Z",
                    "--detected-at",
                    "2026-08-01T00:00:00Z",
                    "-o",
                    str(artifact),
                ]
            )

            self.assertEqual(code, 1)
            self.assertEqual(out, "")
            self.assertIn("refusing to overwrite the input file", err)
            self.assertEqual(artifact.read_bytes(), before)

    def test_report_refuses_to_overwrite_the_evaluations_file(self) -> None:
        code, _, err = run([*REPORT_ARGUMENTS, "-o", str(EXAMPLES / "evaluations.json")])

        self.assertEqual(code, 1)
        self.assertIn("refusing to overwrite the input file", err)

    def test_report_refuses_two_outputs_at_the_same_path(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            target = Path(directory) / "report.json"

            code, _, err = run([*REPORT_ARGUMENTS, "-o", str(target), "--markdown", str(target)])

            self.assertEqual(code, 1)
            self.assertIn("two outputs to the same file", err)
            self.assertFalse(target.exists())

    def test_ingest_failure_exits_one_and_writes_nothing(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            broken = Path(directory) / "broken.cklb"
            broken.write_text("{not json", encoding="utf-8")
            target = Path(directory) / "report.json"

            code, out, err = run(
                [
                    "report",
                    "vdt",
                    str(broken),
                    "--class",
                    "C",
                    "--package-uri",
                    "https://example.test/cpo",
                    "--from",
                    "2026-08-01T00:00:00Z",
                    "--to",
                    "2026-08-31T23:59:59Z",
                    "-o",
                    str(target),
                ]
            )

            self.assertEqual(code, 1)
            self.assertEqual(out, "")
            self.assertTrue(err.startswith("error: "))
            self.assertFalse(target.exists())

    def test_missing_detection_time_exits_one_and_names_the_tracking_ids(self) -> None:
        code, out, err = run(
            [
                "report",
                "vdt",
                str(FIXTURES / "windows-host.ckl"),
                "--class",
                "C",
                "--package-uri",
                "https://example.test/cpo",
                "--from",
                "2026-08-01T00:00:00Z",
                "--to",
                "2026-08-31T23:59:59Z",
            ]
        )

        self.assertEqual(code, 1)
        self.assertEqual(out, "")
        self.assertIn("error: detection_time_missing", err)
        self.assertIn("case-490f49bfdd1bd019", err)

    def test_a_timestamp_without_an_offset_is_refused(self) -> None:
        code, _, err = run(
            [
                "report",
                "vdt",
                str(FIXTURES / "windows-host.ckl"),
                "--class",
                "C",
                "--package-uri",
                "https://example.test/cpo",
                "--from",
                "2026-08-01T00:00:00",
                "--to",
                "2026-08-31T23:59:59Z",
            ]
        )

        self.assertEqual(code, 1)
        self.assertIn("error: invalid_input", err)
        self.assertIn("--from", err)

    def test_a_relative_package_uri_is_refused(self) -> None:
        code, _, err = run(
            [
                "report",
                "vdt",
                str(FIXTURES / "windows-host.ckl"),
                "--class",
                "C",
                "--package-uri",
                "example.test/cpo",
                "--from",
                "2026-08-01T00:00:00Z",
                "--to",
                "2026-08-31T23:59:59Z",
            ]
        )

        self.assertEqual(code, 1)
        self.assertIn("error: invalid_option", err)

    def test_an_unmatched_evaluation_exits_one(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "evaluations.json"
            path.write_text(
                json.dumps(
                    {
                        "evaluations": [
                            {
                                "match": {"sourceRecordId": "V-999999"},
                                "completedAt": "2026-08-04T12:00:00Z",
                                "isInternetReachable": False,
                                "isLikelyExploitable": False,
                                "pain": 2,
                                "potentialAgencyImpact": "None expected.",
                                "rationale": "Not reachable.",
                                "evaluator": "Example Provider vulnerability team",
                            }
                        ]
                    }
                ),
                encoding="utf-8",
            )

            code, _, err = run([*REPORT_ARGUMENTS[:-1], str(path)])

            self.assertEqual(code, 1)
            self.assertIn("error: evaluation_unmatched", err)
            self.assertIn("[evaluations[0]]", err)

    def test_a_malformed_evaluations_file_exits_one(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "evaluations.json"
            path.write_text('{"evaluations": [{"match": {}}]}', encoding="utf-8")

            code, _, err = run([*REPORT_ARGUMENTS[:-1], str(path)])

            self.assertEqual(code, 1)
            self.assertIn("error: invalid_input", err)

    def test_missing_required_options_exit_two(self) -> None:
        with self.assertRaises(SystemExit) as caught:
            run(["report", "vdt", str(FIXTURES / "windows-host.ckl")])

        self.assertEqual(caught.exception.code, 2)

    def test_an_unsupported_class_exits_two(self) -> None:
        with self.assertRaises(SystemExit) as caught:
            run([*REPORT_ARGUMENTS[:5], "--class", "A", *REPORT_ARGUMENTS[7:]])

        self.assertEqual(caught.exception.code, 2)


class ValidateCommandTests(unittest.TestCase):
    def test_a_valid_report_prints_the_schema_provenance(self) -> None:
        code, out, err = run(
            [
                "validate",
                str(GOLDEN / "vdt-fixtures.json"),
                "--schema",
                "vulnerability-detail",
            ]
        )

        self.assertEqual(code, 0)
        self.assertEqual(err, "")
        self.assertTrue(out.startswith("valid: https://fedramp.gov/schemas/"))
        self.assertIn("0.1.1", out)
        self.assertEqual(len(out.strip().split()[-1]), 64)

    def test_an_invalid_report_lists_every_issue_and_the_provenance(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "report.json"
            path.write_text(json.dumps({"vulnerabilities": []}), encoding="utf-8")

            code, out, err = run(["validate", str(path), "--schema", "vulnerability-detail"])

            self.assertEqual(code, 1)
            self.assertEqual(out, "")
            self.assertIn("required", err)
            self.assertIn("certificationPackageOverviewUri", err)
            self.assertIn("schema: https://fedramp.gov/schemas/", err)

    def test_a_malformed_report_exits_one(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "report.json"
            path.write_text("{not json", encoding="utf-8")

            code, _, err = run(["validate", str(path), "--schema", "vulnerability-detail"])

            self.assertEqual(code, 1)
            self.assertIn("error: report_malformed", err)

    def test_a_missing_report_exits_one(self) -> None:
        code, _, err = run(
            ["validate", str(FIXTURES / "gone.json"), "--schema", "vulnerability-detail"]
        )

        self.assertEqual(code, 1)
        self.assertIn("error: report_read_failed", err)

    def test_duplicate_keys_are_refused(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "report.json"
            path.write_text('{"vulnerabilities": [], "vulnerabilities": []}', encoding="utf-8")

            code, _, err = run(["validate", str(path), "--schema", "vulnerability-detail"])

            self.assertEqual(code, 1)
            self.assertIn("duplicate JSON object key", err)

    def test_every_bundled_schema_is_selectable(self) -> None:
        for schema in ("vulnerability-detail", "accepted-vulnerability", "historical-activity"):
            with self.subTest(schema=schema), tempfile.TemporaryDirectory() as directory:
                path = Path(directory) / "report.json"
                path.write_text("{}", encoding="utf-8")

                code, _, err = run(["validate", str(path), "--schema", schema])

                self.assertEqual(code, 1)
                self.assertIn("schema: https://fedramp.gov/schemas/", err)


if __name__ == "__main__":
    unittest.main()
