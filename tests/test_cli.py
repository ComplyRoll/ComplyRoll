from __future__ import annotations

import errno
import io
import json
import os
import shutil
import sqlite3
import tempfile
import unittest
from collections.abc import Callable, Mapping, Sequence
from contextlib import closing, redirect_stderr, redirect_stdout, suppress
from dataclasses import replace
from datetime import UTC, datetime
from pathlib import Path
from typing import Any
from unittest.mock import patch

from complyroll import __version__
from complyroll import cli as cli_module
from complyroll.adapters import ingest_stig_artifact
from complyroll.cli import main
from complyroll.events import EventRepository
from complyroll.history import AUDIT_FAULT_CODES
from complyroll.models import Observation
from complyroll.store import EventRecord, NewEvent, SQLiteEventStore

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

#: What a destination held before a run that fails part way through publishing it. The
#: rollback has to put exactly this back.
PREVIOUS_REPORT = '{"note": "the report a previous run published"}\n'
#: The Markdown beside it, for the pair a failed publication leaves mixed.
PREVIOUS_MARKDOWN = "# the report a previous run published\n"



class ReplaceFailingOnCall:
    """An `os.replace` that fails on the numbered calls it is given, and works otherwise.

    A rollback replaces files too, so a fake that failed for good could not tell a
    rollback that ran from one that never did: the restore would fail the same way.
    Naming several calls is how a failed publication whose rollback also fails is built:
    call 2 is the second destination, call 3 is the restore of the first.
    """

    def __init__(self, *fail_on: int) -> None:
        self.real = os.replace
        self.fail_on = frozenset(fail_on)
        self.calls = 0

    def __call__(self, source: Any, destination: Any) -> None:
        self.calls += 1
        if self.calls in self.fail_on:
            # The call number is in the text so a failed restore can be told apart from
            # the failed publication that provoked it: the rollback message has to carry
            # the restore's own error rather than repeating the first one.
            raise OSError(
                errno.EIO, f"simulated replace failure on call {self.calls}", str(destination)
            )
        self.real(source, destination)


def unlink_failing_on(path: Path) -> Callable[..., None]:
    """Return a `Path.unlink` that fails for one path and works for every other one.

    The rollback removes a destination this run created rather than restoring one it
    replaced, and that removal can fail too. Nothing else the run touches is affected.
    """

    real = Path.unlink

    def unlink(self: Path, *, missing_ok: bool = False) -> None:
        if self == path:
            raise OSError(errno.EIO, "simulated unlink failure", str(self))
        real(self, missing_ok=missing_ok)

    return unlink


def run(argv: Sequence[str]) -> tuple[int, str, str]:
    """Run one CLI invocation and capture its streams."""

    out = io.StringIO()
    err = io.StringIO()
    with redirect_stdout(out), redirect_stderr(err):
        code = main(list(argv))
    return code, out.getvalue(), err.getvalue()


def help_text(argv: Sequence[str]) -> str:
    """Return one command's `--help` output with its line wrapping folded away.

    Argparse wraps help and description text to the terminal width, so an assertion
    about a whole sentence has to read the text as one line rather than as whatever
    the wrapping happened to produce.
    """

    out = io.StringIO()
    with redirect_stdout(out), suppress(SystemExit):
        main([*argv, "--help"])
    return " ".join(out.getvalue().split())


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

    def test_a_failed_markdown_write_leaves_no_json_behind(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            json_path = Path(directory) / "report.json"
            markdown_path = Path(directory) / "missing" / "report.md"

            code, out, err = run(
                [*REPORT_ARGUMENTS, "-o", str(json_path), "--markdown", str(markdown_path)]
            )

            self.assertEqual(code, 1)
            self.assertEqual(out, "")
            self.assertIn("error: output_write_failed", err)
            self.assertFalse(json_path.exists())
            self.assertEqual(list(Path(directory).iterdir()), [])

    def test_a_failed_json_write_leaves_no_markdown_behind(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            json_path = Path(directory) / "missing" / "report.json"
            markdown_path = Path(directory) / "report.md"

            code, out, err = run(
                [*REPORT_ARGUMENTS, "-o", str(json_path), "--markdown", str(markdown_path)]
            )

            self.assertEqual(code, 1)
            self.assertEqual(out, "")
            self.assertIn("error: output_write_failed", err)
            self.assertFalse(markdown_path.exists())
            self.assertEqual(list(Path(directory).iterdir()), [])

    def test_a_failed_markdown_write_suppresses_the_stdout_json(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            markdown_path = Path(directory) / "missing" / "report.md"

            code, out, err = run([*REPORT_ARGUMENTS, "--markdown", str(markdown_path)])

            self.assertEqual(code, 1)
            self.assertEqual(out, "")
            self.assertIn("error: output_write_failed", err)

    def test_a_successful_run_leaves_no_temporary_files(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            json_path = Path(directory) / "report.json"
            markdown_path = Path(directory) / "report.md"

            code, _, _ = run(
                [*REPORT_ARGUMENTS, "-o", str(json_path), "--markdown", str(markdown_path)]
            )

            self.assertEqual(code, 0)
            self.assertEqual(
                sorted(item.name for item in Path(directory).iterdir()),
                ["report.json", "report.md"],
            )

    def test_a_failed_second_replace_restores_the_first_destination(self) -> None:
        # Staging every file first stops a rendering failure from half-publishing a pair.
        # It cannot stop the second rename from failing once the first has landed, which
        # left new JSON beside stale Markdown until the rollback arrived.
        with tempfile.TemporaryDirectory() as directory:
            workspace = Path(directory)
            json_path = workspace / "report.json"
            markdown_path = workspace / "report.md"
            json_path.write_text(PREVIOUS_REPORT, encoding="utf-8")
            failing = ReplaceFailingOnCall(2)

            with patch("os.replace", failing):
                code, out, err = run(
                    [*REPORT_ARGUMENTS, "-o", str(json_path), "--markdown", str(markdown_path)]
                )

            self.assertEqual(code, 1)
            self.assertEqual(out, "")
            self.assertIn("error: output_write_failed", err)
            self.assertEqual(json_path.read_text(encoding="utf-8"), PREVIOUS_REPORT)
            self.assertFalse(markdown_path.exists())
            # The third call is the restore, so the rollback demonstrably ran.
            self.assertEqual(failing.calls, 3)
            self.assertEqual([item.name for item in workspace.iterdir()], ["report.json"])

    def test_a_failed_second_replace_removes_a_first_destination_it_created(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            workspace = Path(directory)
            json_path = workspace / "report.json"
            markdown_path = workspace / "report.md"
            failing = ReplaceFailingOnCall(2)

            with patch("os.replace", failing):
                code, out, err = run(
                    [*REPORT_ARGUMENTS, "-o", str(json_path), "--markdown", str(markdown_path)]
                )

            self.assertEqual(code, 1)
            self.assertEqual(out, "")
            self.assertIn("error: output_write_failed", err)
            self.assertFalse(json_path.exists())
            self.assertFalse(markdown_path.exists())
            # Nothing existed to restore, so the rollback unlinked instead of replacing.
            self.assertEqual(failing.calls, 2)
            self.assertEqual(list(workspace.iterdir()), [])

    def test_a_failed_rollback_keeps_the_previous_bytes_and_names_them(self) -> None:
        # The rollback itself can fail, and it used to fail in silence: the restore error
        # was suppressed, the preserved copy was deleted straight after, and the operator
        # was told only about the original write failure while the outputs were mixed and
        # the previous content was gone (ADR 0007 amendment).
        with tempfile.TemporaryDirectory() as directory:
            workspace = Path(directory)
            json_path = workspace / "report.json"
            markdown_path = workspace / "report.md"
            json_path.write_text(PREVIOUS_REPORT, encoding="utf-8")
            failing = ReplaceFailingOnCall(2, 3)

            with patch("os.replace", failing):
                code, out, err = run(
                    [*REPORT_ARGUMENTS, "-o", str(json_path), "--markdown", str(markdown_path)]
                )

            self.assertEqual(code, 1)
            self.assertEqual(out, "")
            self.assertIn("error: output_rollback_failed", err)
            # The original failure, the destination left in its new state, and the file
            # holding what it held before are all in the one line the operator reads.
            self.assertIn("simulated replace failure", err)
            self.assertIn(str(json_path), err)
            keepers = [item for item in workspace.iterdir() if item.name.endswith(".keep")]
            self.assertEqual(len(keepers), 1)
            self.assertIn(str(keepers[0]), err)
            self.assertEqual(keepers[0].read_text(encoding="utf-8"), PREVIOUS_REPORT)
            self.assertEqual(
                json_path.read_text(encoding="utf-8"),
                (GOLDEN / "vdt-fixtures.json").read_text(encoding="utf-8"),
            )
            self.assertFalse(markdown_path.exists())
            self.assertEqual(failing.calls, 3)
            self.assertEqual(
                sorted(item.name for item in workspace.iterdir()),
                sorted(["report.json", keepers[0].name]),
            )

    def test_a_failed_restore_names_its_own_error_beside_the_write_failure(self) -> None:
        # Both destinations already hold a previous report, so both are preserved. Call 2
        # is the Markdown publication and call 3 is the restore of the JSON, and they fail
        # for reasons of their own: a permission problem and a full filesystem call for
        # different remedies, so the operator is told which one stopped the restore rather
        # than being handed the write failure twice.
        with tempfile.TemporaryDirectory() as directory:
            workspace = Path(directory)
            json_path = workspace / "report.json"
            markdown_path = workspace / "report.md"
            json_path.write_text(PREVIOUS_REPORT, encoding="utf-8")
            markdown_path.write_text(PREVIOUS_MARKDOWN, encoding="utf-8")
            failing = ReplaceFailingOnCall(2, 3)

            with patch("os.replace", failing):
                code, out, err = run(
                    [*REPORT_ARGUMENTS, "-o", str(json_path), "--markdown", str(markdown_path)]
                )

            self.assertEqual(code, 1)
            self.assertEqual(out, "")
            self.assertEqual(failing.calls, 3)
            self.assertIn("error: output_rollback_failed", err)
            # The write failure that stopped the publication, and the restore's own error.
            self.assertIn("simulated replace failure on call 2", err)
            self.assertIn("restore failed: ", err)
            self.assertIn("simulated replace failure on call 3", err)

            keepers = [item for item in workspace.iterdir() if item.name.endswith(".keep")]
            self.assertEqual(len(keepers), 1)
            self.assertTrue(keepers[0].name.startswith(".report.json."))
            self.assertIn(str(keepers[0]), err)
            # Exactly three files: the new JSON, the untouched previous Markdown, and the
            # one keeper holding the previous JSON. The Markdown keeper is gone because
            # the Markdown was never replaced, and no temporary is left behind.
            self.assertEqual(
                sorted(item.name for item in workspace.iterdir()),
                sorted(["report.json", "report.md", keepers[0].name]),
            )
            self.assertEqual(keepers[0].read_text(encoding="utf-8"), PREVIOUS_REPORT)
            self.assertEqual(markdown_path.read_text(encoding="utf-8"), PREVIOUS_MARKDOWN)
            self.assertEqual(
                json_path.read_text(encoding="utf-8"),
                (GOLDEN / "vdt-fixtures.json").read_text(encoding="utf-8"),
            )

    def test_a_rollback_that_cannot_remove_what_it_created_says_so(self) -> None:
        # No destination existed, so there is nothing to restore and no keeper to name;
        # the removal of the file this run created can still fail, and that also leaves a
        # destination in its new state the operator has to be told about.
        with tempfile.TemporaryDirectory() as directory:
            workspace = Path(directory)
            json_path = workspace / "report.json"
            markdown_path = workspace / "report.md"
            failing = ReplaceFailingOnCall(2)

            with (
                patch("os.replace", failing),
                patch("pathlib.Path.unlink", unlink_failing_on(json_path)),
            ):
                code, out, err = run(
                    [*REPORT_ARGUMENTS, "-o", str(json_path), "--markdown", str(markdown_path)]
                )

            self.assertEqual(code, 1)
            self.assertEqual(out, "")
            self.assertIn("error: output_rollback_failed", err)
            self.assertIn("simulated replace failure", err)
            self.assertIn(f"{json_path} holds this run's content", err)
            self.assertIn("could not remove", err)
            self.assertIn("removal failed: ", err)
            self.assertIn("simulated unlink failure", err)
            self.assertEqual(
                json_path.read_text(encoding="utf-8"),
                (GOLDEN / "vdt-fixtures.json").read_text(encoding="utf-8"),
            )
            self.assertFalse(markdown_path.exists())

    def test_a_destination_that_is_a_symlink_is_refused_before_anything_is_staged(self) -> None:
        # Publishing replaces the destination and restores it from a copy of its bytes,
        # so a link would be followed on the way in and replaced on the way back: the
        # content would survive and the link would not (ADR 0007 amendment).
        with tempfile.TemporaryDirectory() as directory:
            workspace = Path(directory)
            target = workspace / "target.json"
            target.write_text(PREVIOUS_REPORT, encoding="utf-8")
            link = workspace / "report.json"
            link.symlink_to(target)

            code, out, err = run([*REPORT_ARGUMENTS, "-o", str(link)])

            self.assertEqual(code, 1)
            self.assertEqual(out, "")
            self.assertIn("error: output_is_symlink", err)
            # The path is the diagnostic's location, so the message does not repeat it:
            # one line naming the same path twice reads as two different paths at a glance.
            self.assertEqual(err.count(str(link)), 1)
            self.assertIn(f"[{link}]", err)
            self.assertTrue(link.is_symlink())
            self.assertEqual(target.read_text(encoding="utf-8"), PREVIOUS_REPORT)
            self.assertEqual(
                sorted(item.name for item in workspace.iterdir()),
                ["report.json", "target.json"],
            )

    def test_a_symlink_destination_is_refused_before_any_artifact_is_parsed(self) -> None:
        # The check needs the paths and nothing else, so it runs beside the input-overwrite
        # refusal rather than at publication time. An artifact that cannot be parsed proves
        # the ordering: the run never reaches it.
        with tempfile.TemporaryDirectory() as directory:
            workspace = Path(directory)
            broken = workspace / "broken.cklb"
            broken.write_text("{not json", encoding="utf-8")
            link = workspace / "report.json"
            link.symlink_to(workspace / "gone.json")

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
                    str(link),
                ]
            )

            self.assertEqual(code, 1)
            self.assertEqual(out, "")
            self.assertIn("error: output_is_symlink", err)
            self.assertNotIn("broken.cklb", err)
            self.assertEqual(err.count(str(link)), 1)
            self.assertEqual(
                sorted(item.name for item in workspace.iterdir()),
                ["broken.cklb", "report.json"],
            )
            self.assertTrue(link.is_symlink())
            self.assertFalse(link.exists())

    def test_a_dangling_markdown_symlink_is_refused_and_no_json_is_written(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            workspace = Path(directory)
            json_path = workspace / "report.json"
            link = workspace / "report.md"
            link.symlink_to(workspace / "gone.md")

            code, out, err = run(
                [*REPORT_ARGUMENTS, "-o", str(json_path), "--markdown", str(link)]
            )

            self.assertEqual(code, 1)
            self.assertEqual(out, "")
            self.assertIn("error: output_is_symlink", err)
            self.assertEqual(err.count(str(link)), 1)
            self.assertIn(f"[{link}]", err)
            self.assertTrue(link.is_symlink())
            self.assertFalse(link.exists())
            self.assertFalse(json_path.exists())
            self.assertEqual([item.name for item in workspace.iterdir()], ["report.md"])

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


PERSISTED_ARTIFACTS = (
    str(FIXTURES / "ubuntu-host.cklb"),
    str(FIXTURES / "windows-host.ckl"),
    str(FIXTURES / "openscap-results.xml"),
)
#: The golden ingest instant, so a persisted report can be compared to the goldens.
INGESTED_AT = "2026-08-21T12:00:00Z"
#: The instant the fixtures' cases attest, since no fixture declares one.
ATTESTED_AT = "2026-08-01T00:00:00Z"
RATIONALE = "The fixtures declare no assessment timestamp; the assessment ran on 1 August."
#: The case behind `windows-host.ckl`, whose evaluation the history demo revises.
WINDOWS_CASE = "case-490f49bfdd1bd019"
#: The case behind the evaluated Ubuntu finding, the one entry carrying a disposition.
UBUNTU_CASE = "case-1f3e011db93cc89e"
#: A well-formed tracking id no fixture produces.
UNKNOWN_CASE = "case-00000000000000ff"
#: The `cases list` header, which is the whole output of an empty store.
CASE_HEADER = "TRACKING ID  PROVIDER ID  SOURCE RECORD  RESOURCES  EVALUATIONS  PAIN  DISPOSITION"

#: One rule seen twice, once with a source timestamp and once without.
PARTIAL_TIMESTAMP_XCCDF = """<?xml version="1.0" encoding="UTF-8"?>
<Benchmark xmlns="http://checklists.nist.gov/xccdf/1.2" id="mixed">
  <TestResult id="shared" end-time="2026-08-03T09:00:00Z">
    <target>lab-timed</target>
    <rule-result idref="xccdf_org.ssgproject.content_rule_banner_etc_issue" severity="medium">
      <result>fail</result>
      <ident system="https://public.cyber.mil/stigs/cci/">CCI-000048</ident>
    </rule-result>
  </TestResult>
  <TestResult id="shared">
    <target>lab-untimed</target>
    <rule-result idref="xccdf_org.ssgproject.content_rule_banner_etc_issue" severity="medium">
      <result>fail</result>
      <ident system="https://public.cyber.mil/stigs/cci/">CCI-000048</ident>
    </rule-result>
  </TestResult>
</Benchmark>
"""


#: The run identifier the smuggled events below carry. It is a canonical version-4 UUID
#: so the metadata is not a second fault alongside the payload each test is about.
SMUGGLED_RUN_ID = "run-00000000-0000-4000-8000-000000000004"

#: The metadata a smuggled event carries when a test is not about metadata: exactly the
#: envelope this version writes, so `audit_history` has nothing to say about it.
SMUGGLED_METADATA = {
    "actor": "smuggler",
    "method": "cli",
    "tool": "complyroll",
    "toolVersion": __version__,
    "runId": SMUGGLED_RUN_ID,
}
#: Streams no fixture writes, one of each kind, so a smuggled event is the only event on
#: the stream and its fault is the only thing the audit finds there.
SMUGGLED_ARTIFACT_STREAM = f"artifact/{'b' * 64}/complyroll.cklb/1"
SMUGGLED_CASE_STREAM = f"case/{UNKNOWN_CASE}"
#: A second well-formed tracking id no fixture produces, for the case whose recorded
#: identifier and stream disagree.
OTHER_UNKNOWN_CASE = "case-00000000000000fe"

#: The audit fault codes the `store verify` tests below cover, checked against
#: `AUDIT_FAULT_CODES` so a new code cannot ship without one.
COVERED_AUDIT_CODES = {
    "artifact_duplicate_observation",
    "artifact_incomplete",
    "artifact_overfull",
    "artifact_stream_mismatch",
    "case_tracking_id_mismatch",
    "event_metadata_invalid",
    "event_stream_mismatch",
    "payload_contract_invalid",
}

#: A source timestamp Python parses and RFC 3339 forbids: an offset carrying seconds.
#: `observation.recorded` stores exactly what `to_canonical_dict` writes, and this is
#: text the replay reader refuses, so the contract refuses to store it in the first
#: place. The refusal lands with the store already open, which is what makes it worth
#: a test of its own.
SUB_MINUTE_OFFSET_XCCDF = """<?xml version="1.0" encoding="UTF-8"?>
<Benchmark xmlns="http://checklists.nist.gov/xccdf/1.2" id="odd">
  <TestResult id="odd" end-time="2026-08-03T09:00:00+00:01:30">
    <target>lab-odd</target>
    <rule-result idref="xccdf_org.ssgproject.content_rule_banner_etc_issue" severity="medium">
      <result>fail</result>
      <ident system="https://public.cyber.mil/stigs/cci/">CCI-000048</ident>
    </rule-result>
  </TestResult>
</Benchmark>
"""


def current_rating(document: dict[str, Any], source_record_id: str) -> Any:
    """Return one compiled vulnerability's current PAIN rating."""

    for item in document["vulnerabilities"]:
        if str(item["vulnerabilityDescription"]).startswith(source_record_id):
            return item.get("currentRating")
    raise AssertionError(f"no vulnerability for {source_record_id}")


def tamper_with_one_payload(database: Path) -> None:
    """Rewrite one stored payload without its digest, around the append-only guard.

    The store's UPDATE trigger exists precisely to stop this, so the test drops it,
    rewrites the row, and restores the trigger from the definition SQLite itself
    recorded. Restoring the exact stored DDL keeps `store verify` reporting the one
    fault under test rather than a schema fault alongside it.
    """

    with closing(sqlite3.connect(database, isolation_level=None)) as raw:
        (definition,) = raw.execute(
            "SELECT sql FROM sqlite_master WHERE name = 'events_reject_update'"
        ).fetchone()
        raw.execute("DROP TRIGGER events_reject_update")
        raw.execute(
            "UPDATE events SET payload_json = ? WHERE sequence = 1",
            ('{"tampered":true}',),
        )
        raw.execute(definition)


class PersistedStoreTestCase(unittest.TestCase):
    """A temporary store driven only through the command line, as an operator would."""

    def setUp(self) -> None:
        directory = tempfile.TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        self.workspace = Path(directory.name)
        self.database = self.workspace / "history.db"

    def succeeds(self, argv: Sequence[str]) -> tuple[str, str]:
        """Run one command, require exit zero, and return its two streams."""

        code, out, err = run(argv)
        self.assertEqual(code, 0, msg=f"{list(argv)} exited {code}: {err}")
        return out, err

    def ingest_fixtures(self, *, actor: str = "golden") -> tuple[str, str]:
        return self.succeeds(
            [
                "ingest",
                *PERSISTED_ARTIFACTS,
                "--db",
                str(self.database),
                "--as-of",
                INGESTED_AT,
                "--actor",
                actor,
            ]
        )

    def correlate(self, *, actor: str = "golden") -> tuple[str, str]:
        return self.succeeds(
            ["cases", "correlate", "--db", str(self.database), "--actor", actor]
        )

    def attest_missing(self, *, actor: str = "golden") -> tuple[str, str]:
        return self.succeeds(
            [
                "cases",
                "attest-detection",
                "--db",
                str(self.database),
                "--all-missing",
                "--detected-at",
                ATTESTED_AT,
                "--rationale",
                RATIONALE,
                "--actor",
                actor,
            ]
        )

    def attest_case(
        self,
        tracking_id: str,
        *,
        rationale: str = RATIONALE,
        detected_at: str = ATTESTED_AT,
        actor: str = "golden",
    ) -> tuple[str, str]:
        """Attest one named case, the way an operator revises a recorded attestation."""

        return self.succeeds(
            [
                "cases",
                "attest-detection",
                "--db",
                str(self.database),
                "--case",
                tracking_id,
                "--detected-at",
                detected_at,
                "--rationale",
                rationale,
                "--actor",
                actor,
            ]
        )

    def evaluate(self, path: Path | None = None, *, actor: str = "golden") -> tuple[str, str]:
        source = EXAMPLES / "evaluations.json" if path is None else path
        return self.succeeds(
            [
                "cases",
                "evaluate",
                "--db",
                str(self.database),
                "--evaluations",
                str(source),
                "--actor",
                actor,
            ]
        )

    def populate(self) -> None:
        """Run the four writing commands in the order the documentation gives them."""

        self.ingest_fixtures()
        self.correlate()
        self.attest_missing()
        self.evaluate()

    def report(
        self,
        *,
        output: Path | None = None,
        markdown: Path | None = None,
    ) -> tuple[str, str]:
        """Compile the persisted report with the golden options."""

        argv = [
            "report",
            "vdt",
            "--db",
            str(self.database),
            "--class",
            "C",
            "--package-uri",
            "https://example.test/cpo",
            "--from",
            "2026-08-01T00:00:00Z",
            "--to",
            "2026-08-31T23:59:59Z",
            "--as-of",
            INGESTED_AT,
        ]
        if output is not None:
            argv += ["-o", str(output)]
        if markdown is not None:
            argv += ["--markdown", str(markdown)]
        return self.succeeds(argv)

    def revised_evaluations(self, source_record_id: str, pain: int) -> Path:
        """Write a copy of the example evaluations with one PAIN rating changed."""

        payload = json.loads((EXAMPLES / "evaluations.json").read_text(encoding="utf-8"))
        for entry in payload["evaluations"]:
            if entry["match"]["sourceRecordId"] == source_record_id:
                entry["pain"] = pain
        path = self.workspace / "evaluations-revised.json"
        path.write_text(json.dumps(payload), encoding="utf-8")
        return path

    def records(self) -> tuple[EventRecord, ...]:
        """Read the whole log back, oldest first."""

        with SQLiteEventStore(self.database) as store:
            return EventRepository(store).read_all()

    def latest_sequence(self) -> int:
        with SQLiteEventStore(self.database) as store:
            return store.latest_sequence


class PersistedSequenceTests(PersistedStoreTestCase):
    """ADR 0008 Decision 6: the documented sequence rebuilds the golden report."""

    def test_the_documented_sequence_reproduces_the_golden_report(self) -> None:
        out, err = self.ingest_fixtures()

        self.assertEqual(
            out.splitlines(),
            [
                "ubuntu-host.cklb: recorded 6 observation(s)",
                "windows-host.ckl: recorded 2 observation(s)",
                "openscap-results.xml: recorded 3 observation(s)",
            ],
        )
        self.assertIn("warning: source_timestamp_missing", err)

        out, _ = self.correlate()

        self.assertEqual(
            out,
            "created 6 case(s), linked 6 observation(s), "
            "skipped 0 already-linked observation(s)\n",
        )

        out, _ = self.attest_missing()

        self.assertEqual(
            out.splitlines(),
            [
                "selected 6 case(s) with no source timestamp on any observation",
                "attested 6 case(s), skipped 0 unchanged case(s), 0 not applicable case(s)",
            ],
        )

        out, _ = self.evaluate()

        self.assertEqual(
            out.splitlines(),
            [
                "evaluations: 2 appended, 0 skipped",
                "pain reductions: 1 appended, 0 skipped",
                "dispositions: 1 appended, 0 skipped",
                "identifications: 0 appended, 0 skipped",
            ],
        )

        json_path = self.workspace / "out.json"
        markdown_path = self.workspace / "out.md"
        _, err = self.report(output=json_path, markdown=markdown_path)

        self.assertIn("warning: source_timestamp_missing", err)
        self.assertEqual(
            json_path.read_text(encoding="utf-8"),
            (GOLDEN / "vdt-fixtures.json").read_text(encoding="utf-8"),
        )
        self.assertEqual(
            markdown_path.read_text(encoding="utf-8"),
            (GOLDEN / "vdt-fixtures.md").read_text(encoding="utf-8"),
        )

    def test_a_persisted_report_without_an_output_goes_to_stdout(self) -> None:
        self.populate()

        out, _ = self.report()

        self.assertEqual(out, (GOLDEN / "vdt-fixtures.json").read_text(encoding="utf-8"))

    def test_a_persisted_report_refuses_to_overwrite_its_own_store(self) -> None:
        self.populate()
        before = self.database.read_bytes()

        code, out, err = run(
            [
                "report",
                "vdt",
                "--db",
                str(self.database),
                "--class",
                "C",
                "--package-uri",
                "https://example.test/cpo",
                "--from",
                "2026-08-01T00:00:00Z",
                "--to",
                "2026-08-31T23:59:59Z",
                "-o",
                str(self.database),
            ]
        )

        self.assertEqual(code, 1)
        self.assertEqual(out, "")
        self.assertIn("refusing to overwrite the input file", err)
        self.assertEqual(self.database.read_bytes(), before)


class PersistedIngestTests(PersistedStoreTestCase):
    def test_ingesting_twice_records_nothing_the_second_time(self) -> None:
        self.ingest_fixtures()
        before = self.latest_sequence()

        out, _ = self.ingest_fixtures()

        self.assertEqual(
            out.splitlines(),
            [
                "ubuntu-host.cklb: already_recorded",
                "windows-host.ckl: already_recorded",
                "openscap-results.xml: already_recorded",
            ],
        )
        self.assertEqual(self.latest_sequence(), before)

    def test_a_broken_artifact_stops_the_run_and_records_nothing(self) -> None:
        broken = self.workspace / "broken.cklb"
        broken.write_text("{not json", encoding="utf-8")

        code, out, err = run(
            [
                "ingest",
                str(broken),
                *PERSISTED_ARTIFACTS,
                "--db",
                str(self.database),
                "--actor",
                "golden",
            ]
        )

        self.assertEqual(code, 1)
        self.assertEqual(out, "")
        self.assertTrue(err.startswith("error: "))
        self.assertFalse(self.database.exists())

    def test_a_failing_second_artifact_leaves_no_store_behind(self) -> None:
        # Every artifact is parsed before the store is opened, so the first artifact's
        # observations are never recorded and no database file is created at all.
        broken = self.workspace / "broken.cklb"
        broken.write_text("{not json", encoding="utf-8")

        code, out, err = run(
            [
                "ingest",
                PERSISTED_ARTIFACTS[0],
                str(broken),
                "--db",
                str(self.database),
                "--actor",
                "golden",
            ]
        )

        self.assertEqual(code, 1)
        self.assertEqual(out, "")
        self.assertIn("error: ", err)
        self.assertFalse(self.database.exists())
        self.assertEqual(list(self.workspace.iterdir()), [broken])

    def test_a_payload_the_contract_refuses_leaves_no_store_behind(self) -> None:
        # This artifact parses, so the refusal arrives with the store already open.
        # A failed ingest still has to leave the operator exactly what they had.
        artifact = self.workspace / "odd.xml"
        artifact.write_text(SUB_MINUTE_OFFSET_XCCDF, encoding="utf-8")

        code, out, err = run(
            ["ingest", str(artifact), "--db", str(self.database), "--as-of", INGESTED_AT]
        )

        self.assertEqual(code, 1)
        self.assertEqual(out, "")
        self.assertIn("error: event_contract_invalid", err)
        self.assertIn("/observed_at", err)
        self.assertFalse(self.database.exists())
        self.assertEqual(list(self.workspace.iterdir()), [artifact])

    def test_a_refused_second_artifact_records_neither_on_an_existing_store(self) -> None:
        # Each `record_ingest` used to commit its own transaction, so the first artifact
        # of this run stayed durable while the second was refused, and the summary was
        # buffered until after the failure and so printed nothing at all: empty output
        # while the store had grown. One transaction around the run fixes both halves
        # (ADR 0008, second amendment).
        self.succeeds(
            [
                "ingest",
                PERSISTED_ARTIFACTS[0],
                "--db",
                str(self.database),
                "--as-of",
                INGESTED_AT,
                "--actor",
                "golden",
            ]
        )
        before = self.latest_sequence()
        refused = self.workspace / "odd.xml"
        refused.write_text(SUB_MINUTE_OFFSET_XCCDF, encoding="utf-8")

        code, out, err = run(
            [
                "ingest",
                PERSISTED_ARTIFACTS[1],
                str(refused),
                "--db",
                str(self.database),
                "--as-of",
                INGESTED_AT,
            ]
        )

        self.assertEqual(code, 1)
        self.assertEqual(out, "")
        self.assertIn("error: event_contract_invalid", err)
        self.assertEqual(self.latest_sequence(), before)
        self.assertEqual(len(self.records()), before)
        self.assertNotIn(
            "windows-host.ckl",
            {
                str(record.payload.get("name"))
                for record in self.records()
                if record.event_type == "artifact.ingested"
            },
        )
        verified, _ = self.succeeds(["store", "verify", "--db", str(self.database)])
        self.assertEqual(verified, f"ok: {before} event(s) verified\n")

    def test_a_refused_payload_leaves_an_existing_store_untouched(self) -> None:
        self.ingest_fixtures()
        before = self.latest_sequence()
        artifact = self.workspace / "odd.xml"
        artifact.write_text(SUB_MINUTE_OFFSET_XCCDF, encoding="utf-8")

        code, _, err = run(
            ["ingest", str(artifact), "--db", str(self.database), "--as-of", INGESTED_AT]
        )

        self.assertEqual(code, 1)
        self.assertIn("error: event_contract_invalid", err)
        self.assertTrue(self.database.is_file())
        self.assertEqual(self.latest_sequence(), before)


class PersistedStorePublicationTests(PersistedStoreTestCase):
    """A new store is built beside its destination and linked in, and never unlinked.

    Recording existence up front and unlinking the path on failure is a race: a
    concurrent ingest can create and populate a real store between the check and the
    failure, and the failing run would delete it (ADR 0008, second amendment).
    """

    def refused_artifact(self) -> Path:
        """Write an artifact that parses and whose payload the contract then refuses.

        The refusal lands with the store already open, which is the only way a failure
        reaches the publication step at all.
        """

        artifact = self.workspace / "odd.xml"
        artifact.write_text(SUB_MINUTE_OFFSET_XCCDF, encoding="utf-8")
        return artifact

    def ingest_refused(self) -> tuple[int, str, str]:
        return run(
            [
                "ingest",
                str(self.refused_artifact()),
                "--db",
                str(self.database),
                "--as-of",
                INGESTED_AT,
            ]
        )

    def test_a_successful_first_ingest_leaves_exactly_the_database_file(self) -> None:
        self.ingest_fixtures()

        self.assertEqual(
            sorted(item.name for item in self.workspace.iterdir()),
            ["history.db"],
        )

    def test_a_failed_first_ingest_leaves_no_file_and_no_temporary(self) -> None:
        code, out, err = self.ingest_refused()

        self.assertEqual(code, 1)
        self.assertEqual(out, "")
        self.assertIn("error: event_contract_invalid", err)
        self.assertFalse(self.database.exists())
        self.assertEqual([item.name for item in self.workspace.iterdir()], ["odd.xml"])

    def test_a_failed_ingest_leaves_an_existing_store_byte_identical(self) -> None:
        self.ingest_fixtures()
        before = self.database.read_bytes()

        code, _, err = self.ingest_refused()

        self.assertEqual(code, 1)
        self.assertIn("error: event_contract_invalid", err)
        self.assertEqual(self.database.read_bytes(), before)
        self.assertEqual(
            sorted(item.name for item in self.workspace.iterdir()),
            ["history.db", "odd.xml"],
        )

    def test_a_dangling_store_link_is_named_rather_than_reported_as_a_conflict(self) -> None:
        # `Path.exists` follows links, so a dangling one reads as a path with no store:
        # the run built a store beside it, `os.link` refused the name the link already
        # occupies, and the operator was told a store had appeared while the run was
        # building, which is not what happened.
        link = self.workspace / "link.db"
        link.symlink_to(self.workspace / "gone.db")

        code, out, err = run(
            [
                "ingest",
                *PERSISTED_ARTIFACTS,
                "--db",
                str(link),
                "--as-of",
                INGESTED_AT,
            ]
        )

        self.assertEqual(code, 1)
        self.assertEqual(out, "")
        self.assertIn("error: store_unavailable", err)
        self.assertNotIn("store_conflict", err)
        # The link is the diagnostic's location; the message names only what it points at.
        self.assertEqual(err.count(str(link)), 1)
        self.assertIn(f"[{link}]", err)
        self.assertIn("gone.db", err)
        self.assertTrue(link.is_symlink())
        self.assertFalse(link.exists())
        self.assertEqual([item.name for item in self.workspace.iterdir()], ["link.db"])

    def test_a_link_to_a_real_store_is_opened_in_place(self) -> None:
        # The refusal above is for a link with nothing behind it. A link to a store is a
        # store: the run reads the history already there and appends through the link.
        self.ingest_fixtures()
        before = self.latest_sequence()
        artifact = self.workspace / "partial.xml"
        artifact.write_text(PARTIAL_TIMESTAMP_XCCDF, encoding="utf-8")
        link = self.workspace / "link.db"
        link.symlink_to(self.database)

        out, _ = self.succeeds(
            [
                "ingest",
                PERSISTED_ARTIFACTS[0],
                str(artifact),
                "--db",
                str(link),
                "--as-of",
                INGESTED_AT,
                "--actor",
                "golden",
            ]
        )

        self.assertEqual(out.splitlines()[0], "ubuntu-host.cklb: already_recorded")
        self.assertTrue(out.splitlines()[1].startswith("partial.xml: recorded "))
        self.assertGreater(self.latest_sequence(), before)
        self.assertTrue(link.is_symlink())
        self.assertEqual(
            sorted(item.name for item in self.workspace.iterdir()),
            ["history.db", "link.db", "partial.xml"],
        )

    def test_a_store_that_appears_while_building_is_reported_not_clobbered(self) -> None:
        appeared = b"a store another run published"
        real_record_ingest = cli_module.record_ingest

        def publish_a_rival_store_first(*args: Any, **kwargs: Any) -> Any:
            # Stands in for the concurrent ingest that wins the race to the destination
            # while this run is still filling its temporary store.
            if not self.database.exists():
                self.database.write_bytes(appeared)
            return real_record_ingest(*args, **kwargs)

        with patch.object(cli_module, "record_ingest", publish_a_rival_store_first):
            code, out, err = run(
                [
                    "ingest",
                    *PERSISTED_ARTIFACTS,
                    "--db",
                    str(self.database),
                    "--as-of",
                    INGESTED_AT,
                ]
            )

        self.assertEqual(code, 1)
        self.assertEqual(out, "")
        self.assertIn("error: store_conflict", err)
        self.assertIn(str(self.database), err)
        self.assertEqual(self.database.read_bytes(), appeared)
        self.assertEqual(
            sorted(item.name for item in self.workspace.iterdir()),
            ["history.db"],
        )


class PersistedAttestationTests(PersistedStoreTestCase):
    """`--all-missing` selects the cases that need an attestation, and only those."""

    def setUp(self) -> None:
        super().setUp()
        self.ingest_fixtures()
        self.correlate()

    def test_a_second_all_missing_run_attests_nothing(self) -> None:
        self.attest_missing()
        before = self.latest_sequence()

        out, _ = self.attest_missing()

        self.assertEqual(
            out.splitlines(),
            [
                "selected 0 case(s) with no source timestamp on any observation",
                "attested 0 case(s), skipped 0 unchanged case(s), 0 not applicable case(s)",
            ],
        )
        self.assertEqual(self.latest_sequence(), before)

    def test_all_missing_skips_an_attested_case_that_case_still_revises(self) -> None:
        self.attest_missing()
        before = self.latest_sequence()

        self.attest_missing()
        out, _ = self.attest_case(UBUNTU_CASE, rationale="The assessment window moved.")

        self.assertEqual(
            out,
            "attested 1 case(s), skipped 0 unchanged case(s), 0 not applicable case(s)\n",
        )
        self.assertEqual(self.latest_sequence(), before + 1)

        listing, _ = self.succeeds(["cases", "history", UBUNTU_CASE, "--db", str(self.database)])
        attested = [line for line in listing.splitlines() if "\tdetection.attested\t" in line]

        self.assertEqual(len(attested), 2)


class PersistedHistoryTests(PersistedStoreTestCase):
    """A changed evaluation appends a second one; it never overwrites the first."""

    def setUp(self) -> None:
        super().setUp()
        self.populate()

    def test_a_changed_evaluation_appends_one_event_and_moves_the_report(self) -> None:
        revised = self.revised_evaluations("V-253260", 5)

        out, _ = self.evaluate(revised)

        self.assertEqual(
            out.splitlines(),
            [
                "evaluations: 1 appended, 1 skipped",
                "pain reductions: 0 appended, 1 skipped",
                "dispositions: 0 appended, 1 skipped",
                "identifications: 0 appended, 0 skipped",
            ],
        )

        listing, _ = self.succeeds(["cases", "history", WINDOWS_CASE, "--db", str(self.database)])
        evaluated = [line for line in listing.splitlines() if "\tcase.evaluated\t" in line]

        self.assertEqual(len(evaluated), 2)
        self.assertIn("evaluated PAIN 4", evaluated[0])
        self.assertIn("evaluated PAIN 5", evaluated[1])
        self.assertLess(int(evaluated[0].split("\t")[0]), int(evaluated[1].split("\t")[0]))

        json_path = self.workspace / "out.json"
        self.report(output=json_path)
        document = json.loads(json_path.read_text(encoding="utf-8"))

        self.assertEqual(current_rating(document, "V-253260"), 5)

    def test_a_third_identical_run_appends_nothing(self) -> None:
        revised = self.revised_evaluations("V-253260", 5)
        self.evaluate(revised)
        before = self.latest_sequence()

        out, _ = self.evaluate(revised)

        self.assertEqual(out.splitlines()[0], "evaluations: 0 appended, 2 skipped")
        self.assertEqual(self.latest_sequence(), before)

    def test_an_unknown_case_is_reported_as_missing(self) -> None:
        code, out, err = run(["cases", "history", UNKNOWN_CASE, "--db", str(self.database)])

        self.assertEqual(code, 1)
        self.assertEqual(out, "")
        self.assertIn("error: case_not_found", err)
        self.assertIn(UNKNOWN_CASE, err)

    def test_a_malformed_tracking_id_is_refused_before_the_store_is_read(self) -> None:
        code, _, err = run(["cases", "history", "not-a-case", "--db", str(self.database)])

        self.assertEqual(code, 1)
        self.assertIn("error: invalid_option", err)


class PersistedEvaluationWarningTests(PersistedStoreTestCase):
    def test_dropping_a_disposition_warns_and_keeps_the_recorded_one(self) -> None:
        self.populate()
        payload = json.loads((EXAMPLES / "evaluations.json").read_text(encoding="utf-8"))
        for entry in payload["evaluations"]:
            entry.pop("disposition", None)
        path = self.workspace / "evaluations-without-disposition.json"
        path.write_text(json.dumps(payload), encoding="utf-8")

        out, err = self.evaluate(path)

        self.assertIn("warning: disposition_retained:", err)
        self.assertIn(UBUNTU_CASE, err)
        self.assertIn("dispositions: 0 appended, 0 skipped", out)

    def test_an_unmatched_entry_is_reported_as_unmatched(self) -> None:
        self.populate()
        path = self.workspace / "evaluations-unmatched.json"
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

        code, out, err = run(
            ["cases", "evaluate", "--db", str(self.database), "--evaluations", str(path)]
        )

        self.assertEqual(code, 1)
        self.assertEqual(out, "")
        self.assertIn("error: evaluation_unmatched", err)


class PersistedCaseListingTests(PersistedStoreTestCase):
    def test_an_empty_store_prints_only_the_header(self) -> None:
        with SQLiteEventStore(self.database):
            pass

        out, err = self.succeeds(["cases", "list", "--db", str(self.database)])

        self.assertEqual(err, "")
        self.assertEqual(out.splitlines(), [CASE_HEADER])

    def test_the_listing_states_each_case_current_position(self) -> None:
        self.populate()

        out, _ = self.succeeds(["cases", "list", "--db", str(self.database)])
        lines = out.splitlines()
        tracking_ids = [line.split()[0] for line in lines[1:]]

        self.assertEqual(len(lines), 7)
        self.assertTrue(lines[0].startswith("TRACKING ID"))
        self.assertEqual(tracking_ids, sorted(tracking_ids))
        self.assertEqual(
            next(line for line in lines if "V-260470" in line).split(),
            [UBUNTU_CASE, "-", "V-260470", "1", "1", "3", "partially_mitigated"],
        )
        self.assertEqual(
            next(line for line in lines if "V-260469" in line).split(),
            ["case-9bed0d8f88355393", "-", "V-260469", "1", "0", "-", "active"],
        )


class PersistedMetadataTests(PersistedStoreTestCase):
    def test_the_actor_and_one_run_id_reach_every_event(self) -> None:
        self.ingest_fixtures(actor="auditor")

        records = self.records()

        self.assertTrue(records)
        self.assertEqual({record.metadata["actor"] for record in records}, {"auditor"})
        self.assertEqual({record.metadata["method"] for record in records}, {"cli"})
        self.assertEqual({record.metadata["tool"] for record in records}, {"complyroll"})
        self.assertEqual(len({record.metadata["runId"] for record in records}), 1)

    def test_each_invocation_records_its_own_run_id(self) -> None:
        self.ingest_fixtures(actor="auditor")
        self.correlate(actor="auditor")

        run_ids = {record.metadata["runId"] for record in self.records()}

        self.assertEqual(len(run_ids), 2)


class StoreVerifyCommandTests(PersistedStoreTestCase):
    def smuggle(
        self,
        event_type: str,
        payload: dict[str, Any],
        *,
        stream_id: str = SMUGGLED_ARTIFACT_STREAM,
        metadata: dict[str, str] | None = None,
        expected_version: int = 0,
    ) -> int:
        """Append one event straight to the store, past the contract the repository holds.

        `EventRepository` is the only writer that checks a payload, its stream, and its
        metadata, so this is how history no writer would produce comes to exist: another
        tool, an older version, or a rule tightened after the event was written. Each
        argument defaults to something the audit has nothing to say about, so a test only
        has to spell the one fault it is about. `expected_version` is the version the
        stream is already at, which is zero for the unused streams above and the last
        stored version for a test that adds an event to a stream the fixtures wrote.
        """

        with SQLiteEventStore(self.database) as store:
            appended = store.append(
                stream_id,
                [
                    NewEvent(
                        event_type=event_type,
                        occurred_at=datetime(2026, 8, 21, 12, 0, tzinfo=UTC),
                        payload=payload,
                        metadata=metadata or dict(SMUGGLED_METADATA),
                    )
                ],
                expected_version=expected_version,
            )
        return appended[0].sequence

    def relabelled(self, payload: Mapping[str, Any], source_record_id: str) -> dict[str, Any]:
        """Return one stored observation as a different finding on the same artifact.

        Both the fingerprint and the identifier derive from the observation's fields, so
        moving the source record moves both: the result still names the artifact its
        stream names, and is not a repeat of anything the stream already holds. An
        overfull stream and a stream holding one observation twice are different faults.
        """

        moved = replace(
            Observation.from_canonical_dict(payload), source_record_id=source_record_id
        )
        return replace(moved, observation_id=moved.derived_observation_id).to_canonical_dict()

    def artifact_stream(self) -> tuple[EventRecord, ...]:
        """Return the whole first artifact stream in the log, in stream order."""

        records = self.records()
        observation = next(
            record for record in records if record.event_type == "observation.recorded"
        )
        return tuple(record for record in records if record.stream_id == observation.stream_id)

    def test_a_clean_store_verifies_and_exits_zero(self) -> None:
        self.populate()

        out, err = self.succeeds(["store", "verify", "--db", str(self.database)])

        self.assertEqual(err, "")
        self.assertTrue(out.startswith("ok: "))
        self.assertIn("event(s) verified", out)
        # The domain audit read the whole log and found nothing to say about it.
        self.assertEqual(out, f"ok: {self.latest_sequence()} event(s) verified\n")

    def test_the_audited_codes_are_exactly_the_ones_these_tests_cover(self) -> None:
        # A new audit fault code with no command test would otherwise ship reported by
        # `audit_history` and unproven at the command line.
        self.assertEqual(set(AUDIT_FAULT_CODES), COVERED_AUDIT_CODES)

    def test_a_payload_no_contract_admits_is_named_and_exits_one(self) -> None:
        # Nothing here is damaged: the payload was stored faithfully and its digest
        # matches. It is still text the replay reader refuses, which used to show up
        # as a clean verify followed by `report vdt --db` failing with history_invalid.
        self.populate()
        recorded = next(
            record for record in self.records() if record.event_type == "observation.recorded"
        )
        smuggled = {**recorded.payload, "ingested_at": "2026-08-21T12:00:00Z"}
        sequence = self.smuggle("observation.recorded", smuggled)

        code, out, err = run(["store", "verify", "--db", str(self.database)])

        self.assertEqual(code, 1)
        self.assertEqual(out, "")
        self.assertIn(f"error: sequence {sequence}: payload_contract_invalid:", err)
        self.assertIn("/ingested_at", err)
        self.assertIn("faults: 1 domain fault(s) in", err)

    def test_a_spelling_only_the_reader_refuses_is_named_and_exits_one(self) -> None:
        # The contract's pattern admits a whole second spelled with six zero digits; the
        # replay reader does not. The audit reads observation payloads back through that
        # reader, so verify cannot call this store healthy.
        self.populate()
        result = ingest_stig_artifact(
            FIXTURES / "ubuntu-host.cklb",
            ingested_at=datetime(2026, 8, 21, 12, tzinfo=UTC),
        )
        payload = result.observations[0].to_canonical_dict()
        payload["ingested_at"] = "2026-08-21T12:00:00.000000+00:00"
        sequence = self.smuggle("observation.recorded", payload)

        code, out, err = run(["store", "verify", "--db", str(self.database)])

        self.assertEqual(code, 1)
        self.assertEqual(out, "")
        self.assertIn(f"error: sequence {sequence}: payload_contract_invalid:", err)
        self.assertIn("is not readable", err)

    def test_an_event_type_no_contract_publishes_is_named_and_exits_one(self) -> None:
        self.populate()
        sequence = self.smuggle("case.retracted", {"reason": "someone changed their mind"})

        code, _, err = run(["store", "verify", "--db", str(self.database)])

        self.assertEqual(code, 1)
        self.assertIn(f"error: sequence {sequence}: payload_contract_invalid:", err)
        self.assertIn("no published contract for event 'case.retracted'", err)

    def test_a_payload_its_own_contract_refuses_is_named_and_exits_one(self) -> None:
        self.populate()
        sequence = self.smuggle(
            "case.pain_reduced",
            {"reducedAt": "2026-08-10T00:00:00Z", "rating": 9},
            stream_id=SMUGGLED_CASE_STREAM,
        )

        code, out, err = run(["store", "verify", "--db", str(self.database)])

        self.assertEqual(code, 1)
        self.assertEqual(out, "")
        self.assertIn(f"error: sequence {sequence}: payload_contract_invalid:", err)
        self.assertIn("/rating", err)
        self.assertIn("faults: 1 domain fault(s) in", err)

    def case_stream(self, tracking_id: str) -> tuple[EventRecord, ...]:
        """Return one fixture case stream in the log, in stream order."""

        stream_id = f"case/{tracking_id}"
        return tuple(record for record in self.records() if record.stream_id == stream_id)

    def report_from_history(self) -> tuple[int, str, str]:
        """Compile the persisted report with the golden options, without requiring exit 0."""

        return run(
            [
                "report",
                "vdt",
                "--db",
                str(self.database),
                "--class",
                "C",
                "--package-uri",
                "https://example.test/cpo",
                "--from",
                "2026-08-01T00:00:00Z",
                "--to",
                "2026-08-31T23:59:59Z",
                "--as-of",
                INGESTED_AT,
            ]
        )

    def smuggle_disposition(self, **overrides: Any) -> int:
        """Append one disposition onto a real case stream, past the contract."""

        stream = self.case_stream(UBUNTU_CASE)
        self.assertTrue(stream)
        payload: dict[str, Any] = {
            "status": "closed",
            "closedDisposition": "remediated",
            "acceptanceRationale": None,
            "recordedAt": "2026-08-21T12:00:00Z",
        }
        payload.update(overrides)
        return self.smuggle(
            "case.disposition_recorded",
            payload,
            stream_id=stream[0].stream_id,
            expected_version=stream[-1].stream_version,
        )

    def test_an_incoherent_disposition_is_reported_as_a_contract_failure(self) -> None:
        # `EventContractError` and `HistoryError` are siblings, and the class decides what
        # the operator reads: the fold validates before it parses, so a smuggled payload
        # its contract refuses is `event_contract_invalid` rather than `history_invalid`.
        self.populate()
        sequence = self.smuggle_disposition(closedDisposition=None)

        verify_code, _, verify_err = run(["store", "verify", "--db", str(self.database)])
        report_code, report_out, report_err = self.report_from_history()

        self.assertEqual(verify_code, 1)
        self.assertIn(f"error: sequence {sequence}: payload_contract_invalid:", verify_err)
        self.assertEqual(report_code, 1)
        self.assertEqual(report_out, "")
        self.assertIn("error: event_contract_invalid", report_err)
        self.assertNotIn("history_invalid", report_err)
        self.assertIn("/closedDisposition", report_err)

    def smuggle_whitespace_rationale(self) -> int:
        """Append a disposition accepting risk on a rationale of three spaces.

        The rule lived in `DispositionRecord` alone until now, so this exact store passed
        `store verify` and was then refused by `report vdt --db`. It lives in the contract,
        so both commands read it the same way.
        """

        return self.smuggle_disposition(
            status="accepted", closedDisposition=None, acceptanceRationale="   "
        )

    def test_a_rationale_of_whitespace_is_named_and_exits_one(self) -> None:
        self.populate()
        sequence = self.smuggle_whitespace_rationale()

        code, out, err = run(["store", "verify", "--db", str(self.database)])

        self.assertEqual(code, 1)
        self.assertEqual(out, "")
        self.assertIn(f"error: sequence {sequence}: payload_contract_invalid:", err)
        self.assertIn("/acceptanceRationale", err)
        self.assertIn("faults: 1 domain fault(s) in", err)

    def test_the_report_refuses_the_same_rationale_verify_refuses(self) -> None:
        # The pairing that was missing: `store verify` used to certify this store and
        # `report vdt --db` used to refuse it as history_invalid. Both refuse it now, and
        # the report's refusal is a contract failure because that is where the rule lives.
        self.populate()
        self.smuggle_whitespace_rationale()

        code, out, err = self.report_from_history()

        self.assertEqual(code, 1)
        self.assertEqual(out, "")
        self.assertIn("error: event_contract_invalid", err)
        self.assertNotIn("history_invalid", err)
        self.assertIn("/acceptanceRationale", err)

    def test_an_incomplete_artifact_stream_is_named_and_exits_one(self) -> None:
        # An artifact event declaring observations no observation event follows is what
        # an ingest interrupted by an older version left behind. Every byte verifies.
        self.populate()
        sequence = self.smuggle(
            "artifact.ingested",
            {
                "name": "phantom.cklb",
                "sha256": "c" * 64,
                "sizeBytes": 128,
                "mediaType": "application/json",
                "parserName": "complyroll.cklb",
                "parserVersion": "1",
                "ingestedAt": "2026-08-21T12:00:00Z",
                "observationCount": 2,
                "diagnostics": [],
            },
            stream_id=f"artifact/{'c' * 64}/complyroll.cklb/1",
        )

        code, out, err = run(["store", "verify", "--db", str(self.database)])

        self.assertEqual(code, 1)
        self.assertEqual(out, "")
        self.assertIn(f"error: sequence {sequence}: artifact_incomplete:", err)
        self.assertIn("declared 2 observations, found 0", err)
        self.assertIn("faults: 1 domain fault(s) in", err)

    def test_an_observation_on_another_artifact_stream_is_named_and_exits_one(self) -> None:
        # An observation copied verbatim onto another artifact's stream is the right kind
        # of event for that stream and is internally consistent, so every check there was
        # passed it: it rehydrated under bytes it never came from and its finding was
        # counted twice. The stream id is the artifact's identity, so the payload has to
        # name the same digest, parser, and parser version (ADR 0008, second amendment).
        self.populate()
        recorded = next(
            record for record in self.records() if record.event_type == "observation.recorded"
        )
        sequence = self.smuggle("observation.recorded", recorded.payload)

        code, out, err = run(["store", "verify", "--db", str(self.database)])

        self.assertEqual(code, 1)
        self.assertEqual(out, "")
        self.assertIn(f"error: sequence {sequence}: artifact_stream_mismatch:", err)
        self.assertIn(SMUGGLED_ARTIFACT_STREAM, err)
        self.assertIn("faults: 1 domain fault(s) in", err)

    def test_an_overfull_artifact_stream_is_named_and_exits_one(self) -> None:
        # The mirror of the incomplete stream above. Here the extra observation belongs to
        # the artifact whose stream holds it, so its identity is beyond reproach and only
        # the count gives it away: seven observations on a stream that declared six is a
        # finding the artifact does not carry.
        self.populate()
        stream = self.artifact_stream()
        declared = stream[0]
        self.assertEqual(declared.event_type, "artifact.ingested")
        self.smuggle(
            "observation.recorded",
            self.relabelled(stream[1].payload, "V-999999"),
            stream_id=declared.stream_id,
            expected_version=stream[-1].stream_version,
        )

        code, out, err = run(["store", "verify", "--db", str(self.database)])

        self.assertEqual(code, 1)
        self.assertEqual(out, "")
        self.assertIn(f"error: sequence {declared.sequence}: artifact_overfull:", err)
        self.assertIn("declared 6 observations, found 7", err)
        self.assertIn("faults: 1 domain fault(s) in", err)

    def rebased(self, payload: Mapping[str, Any], digest: str) -> dict[str, Any]:
        """Return one stored observation as the same finding read out of other bytes.

        The digest is part of an artifact-bound observation's identity, so moving it moves
        the fingerprint and the identifier with it. The result names the smuggled stream
        rather than the fixture's, which is what lets a forged stream be built beside the
        real ones without touching them.
        """

        moved = replace(
            Observation.from_canonical_dict(payload), source_artifact_digest=digest
        )
        return replace(moved, observation_id=moved.derived_observation_id).to_canonical_dict()

    def test_one_observation_recorded_twice_is_named_and_exits_one(self) -> None:
        # A forged head: it declares two observations and the stream carries two, so the
        # count adds up; both name exactly the artifact the stream names, so the identity
        # check is satisfied; and one finding still rehydrates twice.
        self.populate()
        digest = "b" * 64
        payload = self.rebased(self.artifact_stream()[1].payload, digest)
        self.smuggle(
            "artifact.ingested",
            {
                "name": "forged.cklb",
                "sha256": digest,
                "sizeBytes": 4096,
                "mediaType": "application/json",
                "parserName": "complyroll.cklb",
                "parserVersion": "1",
                "ingestedAt": "2026-08-21T12:00:00Z",
                "observationCount": 2,
                "diagnostics": [],
            },
        )
        self.smuggle("observation.recorded", payload, expected_version=1)
        sequence = self.smuggle("observation.recorded", payload, expected_version=2)

        code, out, err = run(["store", "verify", "--db", str(self.database)])

        self.assertEqual(code, 1)
        self.assertEqual(out, "")
        self.assertIn(f"error: sequence {sequence}: artifact_duplicate_observation:", err)
        self.assertIn(SMUGGLED_ARTIFACT_STREAM, err)
        self.assertIn(str(payload["observation_id"]), err)
        self.assertIn("faults: 1 domain fault(s) in", err)

    def test_a_case_created_naming_another_tracking_id_is_named_and_exits_one(self) -> None:
        self.populate()
        sequence = self.smuggle(
            "case.created",
            {
                "trackingId": OTHER_UNKNOWN_CASE,
                "sourceType": "ckl",
                "sourceRecordId": "V-000001",
                "contextKey": "A retired benchmark",
                "title": "A weakness recorded by an earlier run",
                "description": "Recorded from an artifact that is no longer supplied.",
                "createdAt": "2026-08-21T12:00:00Z",
            },
            stream_id=SMUGGLED_CASE_STREAM,
        )

        code, out, err = run(["store", "verify", "--db", str(self.database)])

        self.assertEqual(code, 1)
        self.assertEqual(out, "")
        self.assertIn(f"error: sequence {sequence}: case_tracking_id_mismatch:", err)
        self.assertIn(OTHER_UNKNOWN_CASE, err)
        self.assertIn("faults: 1 domain fault(s) in", err)

    def test_an_event_on_the_wrong_kind_of_stream_is_named_and_exits_one(self) -> None:
        # A `detection.attested` on an artifact stream is read by nobody: the fold reads
        # attestations off case streams only, so the log looks healthy and a case quietly
        # has no attested detection time.
        self.populate()
        sequence = self.smuggle(
            "detection.attested",
            {
                "detectedAt": ATTESTED_AT,
                "rationale": RATIONALE,
                "attestedAt": "2026-08-21T12:00:00Z",
            },
        )

        code, out, err = run(["store", "verify", "--db", str(self.database)])

        self.assertEqual(code, 1)
        self.assertEqual(out, "")
        self.assertIn(f"error: sequence {sequence}: event_stream_mismatch:", err)
        self.assertIn("detection.attested", err)
        self.assertIn("faults: 1 domain fault(s) in", err)

    def test_a_metadata_envelope_outside_the_rules_is_named_and_exits_one(self) -> None:
        # A run identifier that is not a version-4 UUID cannot group a run, so two
        # spellings of one run read as two, and the store used to keep it verbatim.
        self.populate()
        sequence = self.smuggle(
            "detection.attested",
            {
                "detectedAt": ATTESTED_AT,
                "rationale": RATIONALE,
                "attestedAt": "2026-08-21T12:00:00Z",
            },
            stream_id=SMUGGLED_CASE_STREAM,
            metadata={**SMUGGLED_METADATA, "runId": "run-not-a-uuid"},
        )

        code, out, err = run(["store", "verify", "--db", str(self.database)])

        self.assertEqual(code, 1)
        self.assertEqual(out, "")
        self.assertIn(f"error: sequence {sequence}: event_metadata_invalid:", err)
        self.assertIn("runId", err)
        self.assertIn("faults: 1 domain fault(s) in", err)

    def test_a_rewritten_payload_is_named_and_exits_one(self) -> None:
        self.populate()
        tamper_with_one_payload(self.database)

        code, out, err = run(["store", "verify", "--db", str(self.database)])

        self.assertEqual(code, 1)
        self.assertEqual(out, "")
        self.assertIn("error: payload_digest_mismatch", err)
        self.assertIn("sequence 1", err)
        self.assertIn("faults: 1 problem(s)", err)

    def test_a_damaged_store_reports_its_faults_and_skips_the_contract_pass(self) -> None:
        # The rewritten payload is not a JSON object at all, so the contract pass would
        # have plenty to say about it. Saying it would describe the same damage twice
        # and bury the fault that matters, so the walk stops at the store's own report.
        self.populate()
        tamper_with_one_payload(self.database)

        code, _, err = run(["store", "verify", "--db", str(self.database)])

        self.assertEqual(code, 1)
        self.assertIn("warning: payload_contracts_unchecked", err)
        self.assertNotIn("payload_contract_invalid", err)


class ReportSourceConflictTests(unittest.TestCase):
    """`report vdt` takes a store or stateless inputs, never both and never neither."""

    BASE = (
        "--class",
        "C",
        "--package-uri",
        "https://example.test/cpo",
        "--from",
        "2026-08-01T00:00:00Z",
        "--to",
        "2026-08-31T23:59:59Z",
    )

    def refuses(self, argv: Sequence[str], *named: str) -> None:
        code, out, err = run(argv)

        self.assertEqual(code, 1)
        self.assertEqual(out, "")
        self.assertIn("error: invalid_option", err)
        for name in named:
            self.assertIn(name, err)

    def test_a_store_and_artifacts_together_are_refused(self) -> None:
        self.refuses(
            [
                "report",
                "vdt",
                str(FIXTURES / "windows-host.ckl"),
                "--db",
                "history.db",
                *self.BASE,
            ],
            "--db",
            "artifacts",
        )

    def test_a_store_and_an_evaluations_file_together_are_refused(self) -> None:
        self.refuses(
            [
                "report",
                "vdt",
                "--db",
                "history.db",
                "--evaluations",
                str(EXAMPLES / "evaluations.json"),
                *self.BASE,
            ],
            "--db",
            "--evaluations",
        )

    def test_a_store_and_a_detection_time_together_are_refused(self) -> None:
        self.refuses(
            [
                "report",
                "vdt",
                "--db",
                "history.db",
                "--detected-at",
                "2026-08-01T00:00:00Z",
                *self.BASE,
            ],
            "--db",
            "--detected-at",
        )

    def test_neither_a_store_nor_an_artifact_is_refused(self) -> None:
        self.refuses(["report", "vdt", *self.BASE], "artifact", "--db")


class PersistedNotApplicableTests(PersistedStoreTestCase):
    """A case any of whose observations is timestamped gains no attestation."""

    def test_attesting_a_partly_timestamped_case_warns_and_records_nothing(self) -> None:
        artifact = self.workspace / "partial.xml"
        artifact.write_text(PARTIAL_TIMESTAMP_XCCDF, encoding="utf-8")
        self.succeeds(
            [
                "ingest",
                str(artifact),
                "--db",
                str(self.database),
                "--as-of",
                INGESTED_AT,
                "--actor",
                "golden",
            ]
        )
        self.correlate()
        listing, _ = self.succeeds(["cases", "list", "--db", str(self.database)])
        rows = listing.splitlines()[1:]
        self.assertEqual(len(rows), 1)
        tracking_id = rows[0].split()[0]
        before = self.latest_sequence()

        out, err = self.attest_case(tracking_id)

        self.assertIn(
            f"warning: attestation_not_applicable: {tracking_id} carries a source timestamp",
            err,
        )
        self.assertEqual(
            out,
            "attested 0 case(s), skipped 0 unchanged case(s), 1 not applicable case(s)\n",
        )
        self.assertEqual(self.latest_sequence(), before)


class AllMissingSelectionTests(PersistedStoreTestCase):
    """`--all-missing` sweeps only the cases whose every observation lacks a time."""

    def cases_by_source_record(self) -> dict[str, str]:
        """Return the listing's source record identifier for each tracking id."""

        listing, _ = self.succeeds(["cases", "list", "--db", str(self.database)])
        rows = [line.split() for line in listing.splitlines()[1:]]
        return {columns[0]: columns[2] for columns in rows}

    def history_of(self, tracking_id: str) -> str:
        out, _ = self.succeeds(["cases", "history", tracking_id, "--db", str(self.database)])
        return out

    def test_a_partly_timestamped_case_is_left_out_of_the_sweep(self) -> None:
        # The sweep's timestamp filter is what keeps an attestation off a case the
        # compiler would resolve from its own source time. Without it this case is
        # selected, reported as not applicable, and warned about, and the operator is
        # told about a case they never asked to attest.
        artifact = self.workspace / "partial.xml"
        artifact.write_text(PARTIAL_TIMESTAMP_XCCDF, encoding="utf-8")
        self.succeeds(
            [
                "ingest",
                str(FIXTURES / "ubuntu-host.cklb"),
                str(artifact),
                "--db",
                str(self.database),
                "--as-of",
                INGESTED_AT,
                "--actor",
                "golden",
            ]
        )
        self.correlate()
        listed = self.cases_by_source_record()
        partly_timestamped = [
            tracking_id
            for tracking_id, source_record in listed.items()
            if "banner_etc_issue" in source_record
        ]
        untimestamped = [
            tracking_id
            for tracking_id, source_record in listed.items()
            if "banner_etc_issue" not in source_record
        ]
        self.assertEqual(len(partly_timestamped), 1)
        self.assertTrue(untimestamped)

        out, err = self.attest_missing()

        self.assertEqual(
            out.splitlines(),
            [
                f"selected {len(untimestamped)} case(s) with no source timestamp on "
                "any observation",
                f"attested {len(untimestamped)} case(s), skipped 0 unchanged case(s), "
                "0 not applicable case(s)",
            ],
        )
        self.assertNotIn("attestation_not_applicable", err)
        self.assertNotIn("detection.attested", self.history_of(partly_timestamped[0]))
        for tracking_id in untimestamped:
            self.assertIn("detection.attested", self.history_of(tracking_id))


class HelpTextTests(unittest.TestCase):
    """What the commands promise on `--help` is part of their contract."""

    def test_all_missing_states_that_an_attested_case_is_not_selected(self) -> None:
        text = help_text(["cases", "attest-detection"])

        self.assertIn(
            "attest every case that carries no attestation yet and whose every "
            "observation link declares no source timestamp",
            text,
        )
        self.assertIn("re-attesting it requires an explicit --case", text)

    def test_both_artifact_arguments_name_every_accepted_format(self) -> None:
        # ARF has been ingested since Phase 0 and the help text never said so, so an
        # operator holding one had no way to know the command would read it.
        for argv in (["ingest"], ["report", "vdt"]):
            with self.subTest(command=" ".join(argv)):
                text = help_text(argv)

                self.assertIn("ARF", text)
                self.assertIn("CKLB, CKL, XCCDF, or ARF file", text)

    def test_store_verify_names_the_sidecar_files_a_walk_can_leave(self) -> None:
        text = help_text(["store", "verify"])

        self.assertIn(
            "Verifying a WAL-mode store may leave -shm and -wal sidecar files beside "
            "it, while the database file's own bytes stay unchanged.",
            text,
        )


class MissingStoreTests(unittest.TestCase):
    """Every command but `ingest` answers a missing store with an error, not a file.

    Opening a SQLite path that holds no file creates an empty database, so a typo in
    `--db` used to be answered with an empty result and a new file where the operator
    had none. Only `ingest` may create a store.
    """

    def test_every_writing_command_but_ingest_refuses_a_path_with_no_store(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            database = Path(directory) / "history.db"
            commands = (
                ["cases", "correlate", "--db", str(database)],
                [
                    "cases",
                    "attest-detection",
                    "--db",
                    str(database),
                    "--all-missing",
                    "--detected-at",
                    ATTESTED_AT,
                    "--rationale",
                    RATIONALE,
                ],
                [
                    "cases",
                    "evaluate",
                    "--db",
                    str(database),
                    "--evaluations",
                    str(EXAMPLES / "evaluations.json"),
                ],
            )

            for argv in commands:
                with self.subTest(command=" ".join(argv[:2])):
                    code, out, err = run(argv)

                    self.assertEqual(code, 1)
                    self.assertEqual(out, "")
                    self.assertIn("error: store_missing", err)
                    self.assertFalse(database.exists())
            self.assertEqual(list(Path(directory).iterdir()), [])

    def test_every_read_only_command_refuses_a_path_with_no_store(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            database = Path(directory) / "history.db"
            commands = (
                ["cases", "list", "--db", str(database)],
                ["cases", "history", WINDOWS_CASE, "--db", str(database)],
                ["store", "verify", "--db", str(database)],
                [
                    "report",
                    "vdt",
                    "--db",
                    str(database),
                    "--class",
                    "C",
                    "--package-uri",
                    "https://example.test/cpo",
                    "--from",
                    "2026-08-01T00:00:00Z",
                    "--to",
                    "2026-08-31T23:59:59Z",
                ],
            )

            for argv in commands:
                with self.subTest(command=" ".join(argv[:2])):
                    code, out, err = run(argv)

                    self.assertEqual(code, 1)
                    self.assertEqual(out, "")
                    self.assertIn("error: store_missing", err)
                    self.assertFalse(database.exists())
            self.assertEqual(list(Path(directory).iterdir()), [])


if __name__ == "__main__":
    unittest.main()
