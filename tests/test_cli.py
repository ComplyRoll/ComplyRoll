from __future__ import annotations

import copy
import errno
import hashlib
import io
import json
import os
import shutil
import sqlite3
import sys
import tempfile
import unittest
from collections.abc import Callable, Iterator, Mapping, Sequence
from contextlib import closing, contextmanager, redirect_stderr, redirect_stdout, suppress
from dataclasses import replace
from datetime import UTC, datetime, timedelta, timezone
from functools import partial
from pathlib import Path
from typing import Any
from unittest.mock import patch

from test_cyclonedx import compile_cyclonedx_golden, compile_cyclonedx_historical_golden
from test_hdf import compile_hdf_golden
from test_replay import bumped, moved
from test_sarif import compile_sarif_golden, make_log, make_result, make_run
from test_store import plant_undecodable_schema_object, retype_sequence_as_text

from complyroll import __version__
from complyroll import cli as cli_module
from complyroll.adapters import (
    DiagnosticLevel,
    FailureClass,
    IngestDiagnostic,
    IngestResult,
    classify_ingest,
    ingest_stig_artifact,
)
from complyroll.adapters import common as adapters_common
from complyroll.adapters.common import parse_timestamp
from complyroll.adapters.hdf import HDF_PARSER_VERSION
from complyroll.adapters.sarif import SARIF_PARSER_VERSION
from complyroll.cli import main
from complyroll.events import (
    FAILURE_STREAM_SCHEMA_VERSION,
    HELD_FAILURE_SCHEMA_VERSION,
    EventMetadata,
    EventRepository,
    failure_hold_orphan_message,
    failure_stream_id,
)
from complyroll.history import (
    AUDIT_FAULT_CODES,
    HistoryError,
    fold_all_cases,
    record_failure,
    record_ingest,
)
from complyroll.models import Observation
from complyroll.reports import vdt as vdt_module
from complyroll.store import MAX_EVENT_JSON_BYTES, EventRecord, NewEvent, SQLiteEventStore

# Versions after the shipped SARIF parser, for a fixture re-read under another version.
SARIF_NEXT = str(int(SARIF_PARSER_VERSION) + 1)
SARIF_AFTER_NEXT = str(int(SARIF_PARSER_VERSION) + 2)

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

#: The example evaluations with one more entry, which accepts the banner finding.
ACCEPTED_EVALUATIONS = EXAMPLES / "evaluations-accepted.json"
#: The `report avi` twin of `REPORT_ARGUMENTS`: the same fixtures, period, and instants,
#: read with the evaluations file that carries an acceptance to report.
AVI_ARGUMENTS = (
    "report",
    "avi",
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
    str(ACCEPTED_EVALUATIONS),
)
#: The `report historical` twin: a snapshot as of `--as-of`, so it takes no period.
HISTORICAL_ARGUMENTS = (
    "report",
    "historical",
    str(FIXTURES / "ubuntu-host.cklb"),
    str(FIXTURES / "windows-host.ckl"),
    str(FIXTURES / "openscap-results.xml"),
    "--class",
    "C",
    "--package-uri",
    "https://example.test/cpo",
    "--as-of",
    "2026-08-21T12:00:00Z",
    "--detected-at",
    "2026-08-01T00:00:00Z",
    "--evaluations",
    str(ACCEPTED_EVALUATIONS),
)
#: The case `evaluations-accepted.json` accepts: in the AVI report and the historical
#: snapshot, and out of the Vulnerability Detail Report.
ACCEPTED_CASE = "case-04efea8c137ae82f"

#: The synthetic inventory the coverage goldens were cut with, over the golden fixtures.
EXAMPLE_INVENTORY = EXAMPLES / "inventory.json"
#: The `vdt-coverage` run: the `vdt-fixtures` run plus the example inventory (ADR 0015).
COVERAGE_ARGUMENTS = (*REPORT_ARGUMENTS, "--inventory", str(EXAMPLE_INVENTORY))
#: The `vdt-coverage-timed` run: two SARIF artifacts that declare their own clocks, so
#: machine clocks anchor, which the untimed checklist set above never can. Its inventory
#: is a test fixture; `examples/inventory.json` stays the one walkthrough file.
TIMED_INVENTORY = FIXTURES / "inventory-timed.json"
TIMED_ARTIFACTS = (str(FIXTURES / "codeql-repo.sarif"), str(FIXTURES / "clean-run.sarif"))
TIMED_AS_OF = "2026-09-03T12:00:00Z"
#: The `vdt-cyclonedx-coverage` run: a timed and an untimed syft inventory, a clean grype
#: match, a trivy match and the spec corners over an inventory of their images (ADR 0016).
CYCLONEDX_INVENTORY = FIXTURES / "inventory-cyclonedx.json"
CYCLONEDX_COVERAGE_ARGUMENTS = (
    "report",
    "vdt",
    *(
        str(FIXTURES / name)
        for name in (
            "syft-image.cdx.json",
            "syft-untimed.cdx.json",
            "grype-clean.cdx.json",
            "trivy-image.cdx.json",
            "cyclonedx-spec-corners.cdx.json",
        )
    ),
    "--class",
    "C",
    "--package-uri",
    "https://example.test/cpo",
    "--calendar-tz",
    "UTC",
    "--as-of",
    "2026-10-03T12:00:00Z",
    "--from",
    "2026-10-01T00:00:00Z",
    "--to",
    "2026-10-31T23:59:59Z",
    "--inventory",
    str(CYCLONEDX_INVENTORY),
)


def timed_argv(kind: str = "vdt", *, inventory: bool = True, db: Path | None = None) -> list[str]:
    """Build the timed coverage run from the artifacts or a store, with or without inventory."""

    argv = ["report", kind]
    argv += list(TIMED_ARTIFACTS) if db is None else ["--db", str(db)]
    argv += ["--class", "C", "--package-uri", "https://example.test/cpo", "--calendar-tz", "UTC"]
    argv += ["--as-of", TIMED_AS_OF]
    if kind != "historical":
        argv += ["--from", "2026-09-01T00:00:00Z", "--to", "2026-09-30T23:59:59Z"]
    if inventory:
        argv += ["--inventory", str(TIMED_INVENTORY)]
    return argv


#: The synthetic CISA KEV catalog and the run the three KEV goldens were cut with. Every
#: identifier in it is `CVE-2099-*`; no real catalog content is carried in this repo.
KEV_CATALOG = FIXTURES / "kev-catalog.json"
KEV_EVALUATIONS = EXAMPLES / "evaluations-kev.json"
KEV_ARTIFACTS = (
    str(FIXTURES / "kev-image-web.sarif"),
    str(FIXTURES / "kev-image-worker.sarif"),
)
KEV_AS_OF = "2026-09-15T12:00:00Z"
#: The settings all three KEV commands share. The calendar zone is named even though the
#: KEV clock never reads it, so the goldens pin that the zone makes no difference.
KEV_ARGUMENTS = (
    "--class",
    "C",
    "--package-uri",
    "https://example.test/cpo",
    "--calendar-tz",
    "UTC",
)
#: The reporting period the two period-taking commands use; `historical` is a snapshot.
KEV_PERIOD = ("--from", "2026-09-01T00:00:00Z", "--to", "2026-09-30T23:59:59Z")


def kev_argv(
    kind: str,
    *,
    catalog: Path | None = KEV_CATALOG,
    db: Path | None = None,
    as_of: str = KEV_AS_OF,
) -> list[str]:
    """Build one KEV report invocation, from the artifacts or from a store.

    The two paths differ only in where the records come from: a catalog is a per-run
    input on both, so `--kev` is spelled the same way either way.
    """

    argv = ["report", kind]
    if db is None:
        argv += [*KEV_ARTIFACTS, "--evaluations", str(KEV_EVALUATIONS)]
    else:
        argv += ["--db", str(db)]
    argv += [*KEV_ARGUMENTS, "--as-of", as_of]
    if kind != "historical":
        argv += list(KEV_PERIOD)
    if catalog is not None:
        argv += ["--kev", str(catalog)]
    return argv


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
    """Run one CLI invocation and capture its streams.

    `main` runs in this process, so an exception it does not handle raises out of the call
    and fails the test; no traceback ever reaches the captured stderr.
    """

    out = io.StringIO()
    err = io.StringIO()
    with redirect_stdout(out), redirect_stderr(err):
        code = main(list(argv))
    return code, out.getvalue(), err.getvalue()


def run_on_one_stream(argv: Sequence[str]) -> tuple[int, str]:
    """Run one CLI invocation with both streams captured together, in the order written.

    `run` keeps the streams apart, so it cannot see which line came first. A terminal shows
    both on one screen, in the order the run wrote them.
    """

    written = io.StringIO()
    with redirect_stdout(written), redirect_stderr(written):
        code = main(list(argv))
    return code, written.getvalue()


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


def unwrapped_help_text(argv: Sequence[str]) -> str:
    """Return `--help` output rendered wide enough that no identifier is split.

    Argparse breaks a long line at hyphens as well as at spaces, so in a narrow
    listing a rule id such as VER-TFR-MRH can come out on two lines, which `help_text`
    folds back into "VER-TFR- MRH". A wide terminal keeps every identifier whole.
    """

    with patch.dict(os.environ, {"COLUMNS": "200"}):
        return help_text(argv)


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

    def test_a_staging_failure_of_any_kind_leaves_no_temporary_files(self) -> None:
        # Text that cannot be encoded fails inside the write as a UnicodeEncodeError, not
        # an OSError: the JSON staged before it and the Markdown file itself stayed behind.
        with tempfile.TemporaryDirectory() as directory:
            workspace = Path(directory)
            targets = [(workspace / "report.json", "{}\n"), (workspace / "report.md", "\udcff")]

            with self.assertRaises(UnicodeEncodeError):
                cli_module._stage(targets)

            self.assertEqual(list(workspace.iterdir()), [])

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

            code, out, err = run([*REPORT_ARGUMENTS, "-o", str(json_path), "--markdown", str(link)])

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


class ReportAviCommandTests(unittest.TestCase):
    """`report avi` publishes the accepted records with activity in the period."""

    def test_report_writes_the_golden_json_and_markdown(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            json_path = Path(directory) / "report.json"
            markdown_path = Path(directory) / "report.md"

            code, out, err = run(
                [*AVI_ARGUMENTS, "-o", str(json_path), "--markdown", str(markdown_path)]
            )

            self.assertEqual(code, 0)
            self.assertEqual(out, "")
            self.assertIn("warning: source_timestamp_missing", err)
            self.assertEqual(
                json_path.read_text(encoding="utf-8"),
                (GOLDEN / "avi-fixtures.json").read_text(encoding="utf-8"),
            )
            self.assertEqual(
                markdown_path.read_text(encoding="utf-8"),
                (GOLDEN / "avi-fixtures.md").read_text(encoding="utf-8"),
            )

    def test_report_without_output_writes_json_to_stdout(self) -> None:
        code, out, _ = run(list(AVI_ARGUMENTS))

        self.assertEqual(code, 0)
        self.assertEqual(out, (GOLDEN / "avi-fixtures.json").read_text(encoding="utf-8"))
        document = json.loads(out)
        self.assertEqual(
            [
                item["vulnerabilityDetail"]["providerTrackingId"]
                for item in document["acceptedVulnerabilities"]
            ],
            [ACCEPTED_CASE],
        )
        self.assertEqual(document["x-complyroll"]["excludedByPeriod"], 0)
        self.assertEqual(document["x-complyroll"]["activeNotReported"], 5)

    def test_the_accepted_case_is_in_this_report_and_out_of_the_detail_report(self) -> None:
        # One evaluations file drives both reports, so the case has exactly one home:
        # the detail report names it only in the diagnostic that sends the reader here.
        _, avi, _ = run(list(AVI_ARGUMENTS))
        _, vdt, err = run([*REPORT_ARGUMENTS[:-1], str(ACCEPTED_EVALUATIONS)])

        accepted = json.loads(avi)["acceptedVulnerabilities"]
        detail = json.loads(vdt)
        self.assertEqual(
            [item["vulnerabilityDetail"]["providerTrackingId"] for item in accepted],
            [ACCEPTED_CASE],
        )
        self.assertNotIn(
            ACCEPTED_CASE, [item["providerTrackingId"] for item in detail["vulnerabilities"]]
        )
        self.assertEqual(len(detail["vulnerabilities"]), 5)
        self.assertIn(f"info: accepted_excluded: {ACCEPTED_CASE}", err)

    def test_the_report_validates_against_the_accepted_vulnerability_schema(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            json_path = Path(directory) / "report.json"
            self.assertEqual(run([*AVI_ARGUMENTS, "-o", str(json_path)])[0], 0)

            code, out, err = run(["validate", str(json_path), "--schema", "accepted-vulnerability"])

            self.assertEqual(code, 0)
            self.assertEqual(err, "")
            self.assertTrue(out.startswith("valid: https://fedramp.gov/schemas/"))

    def test_a_period_opening_after_the_acceptance_leaves_the_case_out_with_a_reason(
        self,
    ) -> None:
        # The acceptance was completed at 2026-08-06T09:00:00Z and nothing else happened
        # to the case, so a period that opens the next day has no activity to report.
        argv = list(AVI_ARGUMENTS)
        argv[argv.index("--from") + 1] = "2026-08-07T00:00:00Z"

        code, out, err = run(argv)

        self.assertEqual(code, 0)
        document = json.loads(out)
        self.assertEqual(document["acceptedVulnerabilities"], [])
        self.assertEqual(document["x-complyroll"]["excludedByPeriod"], 1)
        [diagnostic] = [
            item
            for item in document["x-complyroll"]["diagnostics"]
            if item["code"] == "excluded_by_period"
        ]
        self.assertIn(ACCEPTED_CASE, diagnostic["message"])
        self.assertIn("is accepted", diagnostic["message"])
        self.assertNotIn("None", diagnostic["message"])
        self.assertIn(f"info: excluded_by_period: {diagnostic['message']}", err)

    def test_help_names_the_rule_the_period_and_the_disclaimer(self) -> None:
        listing = unwrapped_help_text(["report"])
        text = help_text(["report", "avi"])

        self.assertIn("Accepted Vulnerability Information report (VER-RPT-AVI)", listing)
        self.assertIn("every accepted vulnerability with recorded activity", text)
        self.assertIn("--from RFC3339", text)
        self.assertIn("--to RFC3339", text)
        self.assertIn("it is not a FedRAMP determination", text)

    def test_report_refuses_to_overwrite_the_evaluations_file(self) -> None:
        code, _, err = run([*AVI_ARGUMENTS, "-o", str(ACCEPTED_EVALUATIONS)])

        self.assertEqual(code, 1)
        self.assertIn("refusing to overwrite the input file", err)

    def test_a_destination_that_is_a_symlink_is_refused(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            workspace = Path(directory)
            target = workspace / "target.json"
            target.write_text(PREVIOUS_REPORT, encoding="utf-8")
            link = workspace / "report.json"
            link.symlink_to(target)

            code, out, err = run([*AVI_ARGUMENTS, "-o", str(link)])

            self.assertEqual(code, 1)
            self.assertEqual(out, "")
            self.assertIn("error: output_is_symlink", err)
            self.assertIn(f"[{link}]", err)
            self.assertTrue(link.is_symlink())
            self.assertEqual(target.read_text(encoding="utf-8"), PREVIOUS_REPORT)


class ReportHistoricalCommandTests(unittest.TestCase):
    """`report historical` publishes the whole population as of one instant."""

    def test_report_writes_the_golden_json_and_markdown(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            json_path = Path(directory) / "report.json"
            markdown_path = Path(directory) / "report.md"

            code, out, err = run(
                [*HISTORICAL_ARGUMENTS, "-o", str(json_path), "--markdown", str(markdown_path)]
            )

            self.assertEqual(code, 0)
            self.assertEqual(out, "")
            self.assertIn("warning: source_timestamp_missing", err)
            self.assertEqual(
                json_path.read_text(encoding="utf-8"),
                (GOLDEN / "historical-fixtures.json").read_text(encoding="utf-8"),
            )
            self.assertEqual(
                markdown_path.read_text(encoding="utf-8"),
                (GOLDEN / "historical-fixtures.md").read_text(encoding="utf-8"),
            )

    def test_report_without_output_writes_json_to_stdout(self) -> None:
        code, out, _ = run(list(HISTORICAL_ARGUMENTS))

        self.assertEqual(code, 0)
        self.assertEqual(out, (GOLDEN / "historical-fixtures.json").read_text(encoding="utf-8"))
        document = json.loads(out)
        self.assertEqual(document["generatedAt"], "2026-08-21T12:00:00Z")
        self.assertNotIn("reportPeriod", document)
        self.assertEqual(len(document["activeVulnerabilities"]), 5)
        self.assertEqual(
            [
                item["vulnerabilityDetail"]["providerTrackingId"]
                for item in document["acceptedVulnerabilities"]
            ],
            [ACCEPTED_CASE],
        )

    def test_the_report_validates_against_the_historical_activity_schema(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            json_path = Path(directory) / "report.json"
            self.assertEqual(run([*HISTORICAL_ARGUMENTS, "-o", str(json_path)])[0], 0)

            code, out, err = run(["validate", str(json_path), "--schema", "historical-activity"])

            self.assertEqual(code, 0)
            self.assertEqual(err, "")
            self.assertTrue(out.startswith("valid: https://fedramp.gov/schemas/"))

    def test_help_names_the_rule_and_omits_the_report_period(self) -> None:
        listing = unwrapped_help_text(["report"])
        text = help_text(["report", "historical"])

        self.assertIn("Historical VER Activity snapshot (VER-TFR-MRH)", listing)
        self.assertIn("as of --as-of", text)
        self.assertIn("with no report period", text)
        self.assertIn("it is not a FedRAMP determination", text)
        self.assertNotIn("--from", text)
        self.assertNotIn("--to", text)

    def test_a_report_period_is_rejected_as_unrecognized(self) -> None:
        # The snapshot has no period, so the two options are not defined on it at all:
        # argparse refuses them the way it refuses any option a command never had.
        err = io.StringIO()
        with (
            redirect_stdout(io.StringIO()),
            redirect_stderr(err),
            self.assertRaises(SystemExit) as caught,
        ):
            main(
                [
                    *HISTORICAL_ARGUMENTS,
                    "--from",
                    "2026-08-01T00:00:00Z",
                    "--to",
                    "2026-08-31T23:59:59Z",
                ]
            )

        self.assertEqual(caught.exception.code, 2)
        self.assertIn(
            "unrecognized arguments: --from 2026-08-01T00:00:00Z --to 2026-08-31T23:59:59Z",
            err.getvalue(),
        )


class KevReportCommandTests(unittest.TestCase):
    """`--kev` on all three commands, reading the artifacts from disk.

    The catalog is an input like any other: it is named in the overwrite guard, it is
    read before the options it belongs to so a malformed one is refused as bad input
    rather than as a bad option, and only one may be given.
    """

    KINDS = ("vdt", "avi", "historical")

    def test_every_command_reproduces_its_kev_golden_pair(self) -> None:
        for kind in self.KINDS:
            with self.subTest(report=kind), tempfile.TemporaryDirectory() as directory:
                json_path = Path(directory) / "report.json"
                markdown_path = Path(directory) / "report.md"

                code, out, err = run(
                    [*kev_argv(kind), "-o", str(json_path), "--markdown", str(markdown_path)]
                )

                self.assertEqual(code, 0, msg=err)
                self.assertEqual(out, "")
                self.assertIn("info: kev_entries_after_as_of", err)
                self.assertEqual(json_path.read_bytes(), (GOLDEN / f"{kind}-kev.json").read_bytes())
                self.assertEqual(
                    markdown_path.read_bytes(), (GOLDEN / f"{kind}-kev.md").read_bytes()
                )

    def test_a_malformed_catalog_is_refused_as_bad_input_and_writes_nothing(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            catalog = Path(directory) / "kev.json"
            catalog.write_text('{"vulnerabilities": [{}]}', encoding="utf-8")
            json_path = Path(directory) / "report.json"

            code, out, err = run([*kev_argv("vdt", catalog=catalog), "-o", str(json_path)])

            self.assertEqual(code, 1)
            self.assertEqual(out, "")
            self.assertIn("error: invalid_input: KEV catalog:", err)
            self.assertFalse(json_path.exists())

    def test_a_catalog_that_is_not_there_is_refused_as_bad_input(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            json_path = Path(directory) / "report.json"
            missing = Path(directory) / "gone.json"

            code, out, err = run([*kev_argv("vdt", catalog=missing), "-o", str(json_path)])

            self.assertEqual(code, 1)
            self.assertEqual(out, "")
            self.assertIn("error: invalid_input: KEV catalog cannot be read", err)
            self.assertFalse(json_path.exists())

    def test_writing_a_report_over_the_catalog_is_refused(self) -> None:
        for option in ("-o", "--markdown"):
            with self.subTest(destination=option), tempfile.TemporaryDirectory() as directory:
                catalog = Path(directory) / "kev-catalog.json"
                shutil.copyfile(KEV_CATALOG, catalog)
                before = catalog.read_bytes()

                code, out, err = run([*kev_argv("vdt", catalog=catalog), option, str(catalog)])

                self.assertEqual(code, 1)
                self.assertEqual(out, "")
                self.assertIn("refusing to overwrite the input file", err)
                self.assertEqual(catalog.read_bytes(), before)

    def test_a_second_catalog_is_refused_on_every_command(self) -> None:
        # `--kev` appends, so argparse would otherwise keep the last of several and
        # apply a catalog the operator did not mean to name.
        for kind in self.KINDS:
            with self.subTest(report=kind):
                code, out, err = run([*kev_argv(kind), "--kev", str(KEV_CATALOG)])

                self.assertEqual(code, 1)
                self.assertEqual(out, "")
                self.assertIn(
                    f"error: invalid_option: report {kind} takes one --kev catalog, not 2", err
                )

    def test_a_catalog_released_after_the_as_of_instant_stops_the_run(self) -> None:
        # The refusal is a compile diagnostic, not an option error, so it reaches the
        # operator through `_persisted_run` even though this path opens no store.
        with tempfile.TemporaryDirectory() as directory:
            json_path = Path(directory) / "report.json"

            code, out, err = run(
                [*kev_argv("vdt", as_of="2026-09-10T00:00:00Z"), "-o", str(json_path)]
            )

            self.assertEqual(code, 1)
            self.assertEqual(out, "")
            self.assertIn("error: kev_catalog_after_as_of", err)
            self.assertIn("supply the catalog current then", err)
            self.assertFalse(json_path.exists())


#: One fixture per detection process failure class (ADR 0014), in name order.
FAILED_ARTIFACTS = (
    str(FIXTURES / "failed-invalid-rules.cklb"),
    str(FIXTURES / "failed-invocation.sarif"),
    str(FIXTURES / "failed-truncated.sarif"),
)


def with_failed_artifacts(argv: Sequence[str]) -> list[str]:
    """Add the failed fixtures to a golden run, beside its own three artifacts."""

    return [*argv[:5], *FAILED_ARTIFACTS, *argv[5:]]


class RecordFailedImportsTests(unittest.TestCase):
    """`--record-failed-imports` publishes the report, then exits 3 when it recorded one."""

    #: Each report command's golden run, whose artifacts are argv[2:5].
    COMMANDS = (
        ("vdt", REPORT_ARGUMENTS),
        ("avi", AVI_ARGUMENTS),
        ("historical", HISTORICAL_ARGUMENTS),
    )

    def assert_failures_listed(self, text: str) -> None:
        failures = json.loads(text)["x-complyroll"]["detectionFailures"]
        self.assertEqual(
            [item["name"] for item in failures],
            [Path(path).name for path in FAILED_ARTIFACTS],
        )

    def test_a_recorded_failure_writes_both_outputs_and_exits_3(self) -> None:
        for command, argv in self.COMMANDS:
            with self.subTest(command=command), tempfile.TemporaryDirectory() as directory:
                json_path = Path(directory) / "report.json"
                markdown_path = Path(directory) / "report.md"

                code, out, err = run(
                    [
                        *with_failed_artifacts(argv),
                        "--record-failed-imports",
                        "-o",
                        str(json_path),
                        "--markdown",
                        str(markdown_path),
                    ]
                )

                self.assertEqual(code, 3)
                self.assertEqual(code, cli_module.EXIT_DETECTION_FAILURES)
                self.assertEqual(out, "")
                self.assertEqual(err.count("warning: detection_failure_recorded"), 3)
                self.assertNotIn("error:", err)
                self.assert_failures_listed(json_path.read_text(encoding="utf-8"))
                self.assertIn(
                    "### Detection process failures", markdown_path.read_text(encoding="utf-8")
                )

    def test_a_recorded_failure_writes_stdout_and_exits_3(self) -> None:
        for command, argv in self.COMMANDS:
            with self.subTest(command=command):
                code, out, err = run([*with_failed_artifacts(argv), "--record-failed-imports"])

                self.assertEqual(code, 3)
                self.assertNotIn("error:", err)
                self.assert_failures_listed(out)

    def test_the_flag_without_a_failure_exits_0_with_the_golden_bytes(self) -> None:
        for command, argv in self.COMMANDS:
            with self.subTest(command=command):
                code, out, _ = run([*argv, "--record-failed-imports"])

                self.assertEqual(code, 0)
                self.assertEqual(
                    out, (GOLDEN / f"{command}-fixtures.json").read_text(encoding="utf-8")
                )

    def test_every_report_golden_recompiles_byte_identical_with_the_flag(self) -> None:
        # The SARIF, HDF and CycloneDX goldens are compiled through the library, as their own
        # tests do.
        runs = {
            **{f"{command}-fixtures": argv for command, argv in self.COMMANDS},
            **{f"{kind}-kev": kev_argv(kind) for kind in KevReportCommandTests.KINDS},
            "vdt-coverage": COVERAGE_ARGUMENTS,
            "vdt-coverage-timed": timed_argv(),
            "vdt-cyclonedx-coverage": CYCLONEDX_COVERAGE_ARGUMENTS,
        }
        compiled = {
            "vdt-sarif": compile_sarif_golden(record_failed_imports=True),
            "vdt-hdf": compile_hdf_golden(record_failed_imports=True),
            "vdt-cyclonedx": compile_cyclonedx_golden(record_failed_imports=True),
            "historical-cyclonedx": compile_cyclonedx_historical_golden(record_failed_imports=True),
        }
        reports = {
            path.stem
            for path in GOLDEN.glob("*.json")
            if "x-complyroll" in json.loads(path.read_text(encoding="utf-8"))
        }
        # The failure and coverage gap goldens exit 3 by design; each pair has its own
        # reproduction, the gap pair in `test_coverage_gap_report`.
        system_goldens = {
            "vdt-failed",
            "historical-failed",
            "vdt-coverage-gaps",
            "historical-coverage-gaps",
        }
        self.assertEqual(reports - system_goldens, {*runs, *compiled})
        for name, argv in runs.items():
            with self.subTest(golden=name), tempfile.TemporaryDirectory() as directory:
                json_path = Path(directory) / "report.json"
                markdown_path = Path(directory) / "report.md"

                code, _, err = run(
                    [
                        *argv,
                        "--record-failed-imports",
                        "-o",
                        str(json_path),
                        "--markdown",
                        str(markdown_path),
                    ]
                )

                self.assertEqual(code, 0, msg=err)
                self.assertEqual(json_path.read_bytes(), (GOLDEN / f"{name}.json").read_bytes())
                self.assertEqual(markdown_path.read_bytes(), (GOLDEN / f"{name}.md").read_bytes())
        for name, report in compiled.items():
            with self.subTest(golden=name):
                self.assertEqual(
                    report.to_json().encode("utf-8"), (GOLDEN / f"{name}.json").read_bytes()
                )
                self.assertEqual(
                    report.to_markdown().encode("utf-8"), (GOLDEN / f"{name}.md").read_bytes()
                )

    def test_without_the_flag_a_failure_stops_the_run_and_writes_nothing(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            json_path = Path(directory) / "report.json"

            code, out, err = run([*with_failed_artifacts(REPORT_ARGUMENTS), "-o", str(json_path)])

            self.assertEqual(code, 1)
            self.assertEqual(out, "")
            self.assertIn("error: artifact_parse_failed", err)
            self.assertNotIn("detection_failure_recorded", err)
            self.assertFalse(json_path.exists())

    def test_an_unmintable_failure_exits_1_and_writes_nothing(self) -> None:
        payload = {
            "target_data": {"host_name": "host-partial"},
            "stigs": [{"stig_id": "SYN_STIG", "rules": [{"group_id": "V-000001"}, 1]}],
        }
        with tempfile.TemporaryDirectory() as directory:
            partial = Path(directory) / "partial.cklb"
            partial.write_text(json.dumps(payload), encoding="utf-8")
            json_path = Path(directory) / "report.json"
            argv = with_failed_artifacts(REPORT_ARGUMENTS)
            argv[2:2] = [str(partial)]

            code, out, err = run([*argv, "--record-failed-imports", "-o", str(json_path)])

            self.assertEqual(code, 1)
            self.assertEqual(out, "")
            self.assertIn("error: invalid_rule", err)
            self.assertNotIn("detection_failure_recorded", err)
            self.assertFalse(json_path.exists())

    def test_a_refused_artifact_stops_the_run_and_still_names_every_failure(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            notes = Path(directory) / "notes.txt"
            notes.write_text("not a scanner output\n", encoding="utf-8")
            json_path = Path(directory) / "report.json"
            argv = list(REPORT_ARGUMENTS)
            argv[2:2] = [
                str(FIXTURES / "failed-truncated.sarif"),
                str(FIXTURES / "failed-invalid-rules.cklb"),
                str(notes),
            ]

            flagged = run([*argv, "--record-failed-imports", "-o", str(json_path)])
            plain = run([*argv, "-o", str(json_path)])

            self.assertEqual(flagged[0], 1)
            self.assertEqual(flagged[1], "")
            self.assertEqual(flagged[2], plain[2])
            self.assertEqual(plain[0], 1)
            for name in ("failed-truncated.sarif", "failed-invalid-rules.cklb", "notes.txt"):
                self.assertIn(f"[{name}]", flagged[2])
            self.assertNotIn("detection_failure_recorded", flagged[2])
            self.assertFalse(json_path.exists())

    def test_a_sarif_log_whose_findings_were_withheld_exits_1_and_writes_nothing(self) -> None:
        # The first run's finding is real; the second run's ERROR withholds it, so minting a
        # content failure would drop it from the report.
        finding = {
            "ruleId": "R1",
            "message": {"text": "finding"},
            "locations": [{"physicalLocation": {"artifactLocation": {"uri": "src/a.py"}}}],
        }
        log = {
            "version": "2.1.0",
            "runs": [
                {"tool": {"driver": {"name": "Synth"}}, "results": [finding]},
                {"tool": {"driver": {"name": "Synth"}}, "results": [7]},
            ],
        }
        with tempfile.TemporaryDirectory() as directory:
            partial = Path(directory) / "partial.sarif"
            partial.write_text(json.dumps(log), encoding="utf-8")
            json_path = Path(directory) / "report.json"
            argv = list(REPORT_ARGUMENTS)
            argv[2:2] = [str(partial)]

            code, out, err = run([*argv, "--record-failed-imports", "-o", str(json_path)])

            self.assertEqual(code, 1)
            self.assertEqual(out, "")
            self.assertIn("error: invalid_result", err)
            self.assertNotIn("detection_failure_recorded", err)
            self.assertFalse(json_path.exists())

    def test_a_failed_publication_exits_1_not_3(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            json_path = Path(directory) / "report.json"

            with patch("os.replace", ReplaceFailingOnCall(1)):
                code, out, err = run(
                    [
                        *with_failed_artifacts(REPORT_ARGUMENTS),
                        "--record-failed-imports",
                        "-o",
                        str(json_path),
                    ]
                )

            self.assertEqual(code, 1)
            self.assertEqual(out, "")
            self.assertIn("error: output_write_failed", err)
            self.assertFalse(json_path.exists())

    def test_only_the_flag_turns_recorded_failures_into_exit_3(self) -> None:
        # Until `ingest` records failures into a store, the only report that carries them
        # without the flag is this one: the compile is made to record them regardless.
        real = vdt_module._ingest_all

        def recording(*args: Any, **kwargs: Any) -> Any:
            return real(*args, **{**kwargs, "record_failed_imports": True})

        with patch.object(vdt_module, "_ingest_all", recording):
            code, out, _ = run(with_failed_artifacts(REPORT_ARGUMENTS))

        self.assertEqual(code, 0)
        self.assert_failures_listed(out)


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

#: Two failed readings whose recorded streams the failure-stream audit tests below damage.
TRUNCATED_FIXTURE = FIXTURES / "failed-truncated.sarif"
INVALID_RULES_FIXTURE = FIXTURES / "failed-invalid-rules.cklb"
#: A log that imports, with its failed invocation recorded beside it as a side record.
INVOCATION_FIXTURE = FIXTURES / "failed-invocation.sarif"

#: The audit fault codes the `store verify` tests below cover, checked against
#: `AUDIT_FAULT_CODES` so a new code cannot ship without one.
COVERED_AUDIT_CODES = {
    "artifact_duplicate_observation",
    "artifact_incomplete",
    "artifact_overfull",
    "artifact_stream_mismatch",
    "case_tracking_id_mismatch",
    # Its `store verify` command tests live in `UnusableStoredClockTests` below.
    "clock_out_of_range",
    # Its library tests live in `tests/test_replay.py`, beside the report's refusal.
    "disposition_without_evaluation",
    # The five coverage codes' `store verify` command tests live in
    # `tests/test_coverage_streams.py`.
    "coverage_identity_breach",
    "coverage_incomplete",
    "coverage_overfull",
    "coverage_schema_unmarked",
    "coverage_stream_mismatch",
    # Its `store verify` command tests live in `tests/test_evaluation_order.py`.
    "evaluation_before_detection",
    "event_metadata_invalid",
    "event_stream_mismatch",
    "failure_duplicate_observation",
    "failure_hold_orphaned",
    "failure_incomplete",
    "failure_overfull",
    "failure_schema_unmarked",
    "failure_stream_mismatch",
    "payload_contract_invalid",
}

#: A source timestamp Python parses and RFC 3339 forbids: an offset carrying seconds.
#: `observation.recorded` stores exactly what `to_canonical_dict` writes, and this is
#: text the replay reader refuses, so the contract refuses to store it in the first
#: place. The refusal lands with the store already open, which is what makes it worth
#: a test of its own. The XCCDF reader now refuses such a clock itself (`parse_clock`), so
#: the tests read it through `unguarded_stig_clocks`, standing in for any reading that
#: hands the store a payload its contract refuses.
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


@contextmanager
def unguarded_stig_clocks() -> Iterator[None]:
    """Read CKLB and XCCDF clocks with the unguarded parser the STIG adapter once used."""

    with patch("complyroll.adapters.stig.parse_clock", parse_timestamp):
        yield


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


def moved_reading(
    path: Path,
    *,
    ingested_at: datetime,
    parser_name: str,
    parser_version: str,
    parse_failure: bool = False,
    clean: bool = False,
) -> IngestResult:
    """Read `path` as `parser_name` at `parser_version` would, the way `moved` moves a reading.

    `clean` drops the failed invocation, so the reading reports none. `parse_failure` leaves
    the reading nothing but one ERROR `artifact_parse_failed` and no failed invocation.
    Patched in for `ingest_stig_artifact`, it is the reader of a parser this tree does not
    ship.
    """

    reading = moved(
        ingest_stig_artifact(path, ingested_at=ingested_at), parser_name, parser_version
    )
    if clean:
        reading = replace(
            reading,
            diagnostics=tuple(
                item for item in reading.diagnostics if item.code != "execution_unsuccessful"
            ),
            failed_execution_at=None,
        )
    if parse_failure:
        unparsed = IngestDiagnostic(
            level=DiagnosticLevel.ERROR, code="artifact_parse_failed", message="cannot parse"
        )
        reading = replace(
            reading, observations=(), diagnostics=(unparsed,), failed_execution_at=None
        )
    return reading


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
        return self.succeeds(["cases", "correlate", "--db", str(self.database), "--actor", actor])

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

    def populate(self, evaluations: Path | None = None) -> None:
        """Run the four writing commands in the order the documentation gives them."""

        self.ingest_fixtures()
        self.correlate()
        self.attest_missing()
        self.evaluate(evaluations)

    def report(
        self,
        kind: str = "vdt",
        *,
        output: Path | None = None,
        markdown: Path | None = None,
        as_of: str = INGESTED_AT,
    ) -> tuple[str, str]:
        """Compile one persisted report with the golden options, at the golden instant by default.

        `historical` is a snapshot as of `--as-of`, so its command takes no period.
        """

        argv = [
            "report",
            kind,
            "--db",
            str(self.database),
            "--class",
            "C",
            "--package-uri",
            "https://example.test/cpo",
        ]
        if kind != "historical":
            argv += ["--from", "2026-08-01T00:00:00Z", "--to", "2026-08-31T23:59:59Z"]
        argv += ["--as-of", as_of]
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

    @staticmethod
    def canonical(value: Mapping[str, Any]) -> str:
        return json.dumps(
            value, allow_nan=False, ensure_ascii=False, separators=(",", ":"), sort_keys=True
        )

    def raw(self) -> sqlite3.Connection:
        connection = sqlite3.connect(self.database, isolation_level=None)
        connection.row_factory = sqlite3.Row
        return connection

    def update(self, work: Callable[[sqlite3.Connection], object]) -> None:
        """Run `work` with only `events_reject_update` dropped, then rebuild it as stored."""

        with closing(self.raw()) as connection:
            (restore,) = connection.execute(
                "SELECT sql FROM sqlite_master WHERE name = 'events_reject_update'"
            ).fetchone()
            connection.execute("DROP TRIGGER events_reject_update")
            work(connection)
            connection.execute(restore)

    def copy_store(self, source: Path, name: str) -> None:
        """Point the test at a copy of one store, so each damage starts from the same log."""

        self.database = self.workspace / name
        with (
            closing(sqlite3.connect(source)) as origin,
            closing(sqlite3.connect(self.database)) as copy,
        ):
            origin.backup(copy)


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
            "created 6 case(s), linked 6 observation(s), skipped 0 already-linked observation(s)\n",
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


class PersistedSarifRoundTripTests(PersistedStoreTestCase):
    """A SARIF log ingested into a store reports exactly as the same log reports statelessly.

    `codeql-repo.sarif` declares an invocation clock, so neither path needs a detection
    attestation, and it carries the `open`-kind result that both paths must name as an
    unresolved observation rather than report as a vulnerability (ADR 0011).
    """

    SARIF = FIXTURES / "codeql-repo.sarif"
    INGESTED_AT = "2026-09-15T12:00:00Z"
    OPTIONS = (
        "--class",
        "C",
        "--package-uri",
        "https://example.test/cpo",
        "--from",
        "2026-09-01T00:00:00Z",
        "--to",
        "2026-09-30T23:59:59Z",
        "--as-of",
        "2026-09-15T12:00:00Z",
    )

    def ingest_sarif(self) -> tuple[str, str]:
        return self.succeeds(
            [
                "ingest",
                str(self.SARIF),
                "--db",
                str(self.database),
                "--as-of",
                self.INGESTED_AT,
                "--actor",
                "golden",
            ]
        )

    def test_a_persisted_sarif_report_matches_the_stateless_report_byte_for_byte(self) -> None:
        out, err = self.ingest_sarif()

        self.assertEqual(out, "codeql-repo.sarif: recorded 3 observation(s)\n")
        self.assertIn("info: baseline_state_ignored", err)

        persisted_json = self.workspace / "persisted.json"
        persisted_markdown = self.workspace / "persisted.md"
        _, err = self.succeeds(
            [
                "report",
                "vdt",
                "--db",
                str(self.database),
                *self.OPTIONS,
                "-o",
                str(persisted_json),
                "--markdown",
                str(persisted_markdown),
            ]
        )

        self.assertIn("warning: unresolved_observation: js/xss-through-dom", err)

        stateless_json = self.workspace / "stateless.json"
        stateless_markdown = self.workspace / "stateless.md"
        _, err = self.succeeds(
            [
                "report",
                "vdt",
                str(self.SARIF),
                *self.OPTIONS,
                "-o",
                str(stateless_json),
                "--markdown",
                str(stateless_markdown),
            ]
        )

        self.assertIn("warning: unresolved_observation: js/xss-through-dom", err)
        self.assertEqual(persisted_json.read_bytes(), stateless_json.read_bytes())
        self.assertEqual(persisted_markdown.read_bytes(), stateless_markdown.read_bytes())
        document = json.loads(persisted_json.read_text(encoding="utf-8"))
        self.assertEqual(
            [item["providerTrackingId"] for item in document["vulnerabilities"]],
            ["case-04716522daa6f550", "case-d2b9f5abf1fe44ac"],
        )
        self.assertEqual(
            document["x-complyroll"]["parserVersions"], {"complyroll.sarif": SARIF_PARSER_VERSION}
        )
        self.assertIsNone(document["x-complyroll"]["detectionTimeAttestation"])

    def test_the_persisted_sarif_report_validates_against_the_official_schema(self) -> None:
        self.ingest_sarif()
        output = self.workspace / "report.json"
        self.succeeds(
            ["report", "vdt", "--db", str(self.database), *self.OPTIONS, "-o", str(output)]
        )

        code, out, err = run(["validate", str(output), "--schema", "vulnerability-detail"])

        self.assertEqual(code, 0)
        self.assertEqual(err, "")
        self.assertTrue(out.startswith("valid: https://fedramp.gov/schemas/"))
        self.assertIn("0.1.1", out)


class CleanSarifLogTests(PersistedStoreTestCase):
    """A SARIF log with no results imports on both paths and is evidence, not a case.

    `clean-run.sarif` is one clocked run with an empty `results` array under a successful
    invocation, so it yields one PASS observation of the image it scanned (ADR 0015
    decision 1) and nothing for a report to list.
    """

    CLEAN = FIXTURES / "clean-run.sarif"
    INGESTED_AT = "2026-09-15T12:00:00Z"
    OPTIONS = (
        "--class",
        "C",
        "--package-uri",
        "https://example.test/cpo",
        "--from",
        "2026-08-01T00:00:00Z",
        "--to",
        "2026-08-31T23:59:59Z",
        "--as-of",
        "2026-09-15T12:00:00Z",
    )

    def ingest_clean(self) -> tuple[str, str]:
        return self.succeeds(
            [
                "ingest",
                str(self.CLEAN),
                "--db",
                str(self.database),
                "--as-of",
                self.INGESTED_AT,
                "--actor",
                "golden",
            ]
        )

    def test_the_clean_log_ingests_once_and_is_idempotent(self) -> None:
        out, err = self.ingest_clean()

        self.assertEqual(out, "clean-run.sarif: recorded 1 observation(s)\n")
        self.assertEqual(
            err,
            "info: run_clean: run reports no results (1 occurrence: runs[0]) [clean-run.sarif]\n",
        )
        recorded = [
            record.payload
            for record in self.records()
            if record.event_type == "observation.recorded"
        ]
        self.assertEqual([item["source_record_id"] for item in recorded], ["sarif.run"])
        self.assertEqual(recorded[0]["disposition"], "pass")
        before = self.latest_sequence()

        out, _ = self.ingest_clean()

        self.assertEqual(out, "clean-run.sarif: already_recorded\n")
        self.assertEqual(self.latest_sequence(), before)

    def test_the_clean_log_ingests_with_the_failed_import_flag_and_records_no_failure(self) -> None:
        out, err = self.succeeds(
            [
                "ingest",
                str(self.CLEAN),
                "--db",
                str(self.database),
                "--as-of",
                self.INGESTED_AT,
                "--actor",
                "golden",
                "--record-failed-imports",
            ]
        )

        self.assertEqual(out, "clean-run.sarif: recorded 1 observation(s)\n")
        self.assertNotIn("detection_failure_recorded", err)
        self.assertEqual(
            [record.event_type for record in self.records() if "failure" in record.event_type], []
        )

    def test_both_paths_report_the_clean_log_as_no_vulnerabilities(self) -> None:
        self.ingest_clean()
        self.succeeds(["cases", "correlate", "--db", str(self.database), "--actor", "golden"])
        persisted = self.workspace / "persisted.json"
        stateless = self.workspace / "stateless.json"
        self.succeeds(
            ["report", "vdt", "--db", str(self.database), *self.OPTIONS, "-o", str(persisted)]
        )
        _, err = self.succeeds(
            ["report", "vdt", str(self.CLEAN), *self.OPTIONS, "-o", str(stateless)]
        )

        self.assertIn("info: run_clean", err)
        self.assertEqual(persisted.read_bytes(), stateless.read_bytes())
        document = json.loads(stateless.read_text(encoding="utf-8"))
        self.assertEqual(document["vulnerabilities"], [])
        self.assertEqual(
            document["x-complyroll"]["parserVersions"], {"complyroll.sarif": SARIF_PARSER_VERSION}
        )

    def test_the_stateless_report_with_the_flag_exits_zero_and_records_nothing(self) -> None:
        output = self.workspace / "report.json"

        code, _, err = run(
            [
                "report",
                "vdt",
                str(self.CLEAN),
                *self.OPTIONS,
                "--record-failed-imports",
                "-o",
                str(output),
            ]
        )

        self.assertEqual(code, 0)
        self.assertNotIn("detection_failure_recorded", err)
        document = json.loads(output.read_text(encoding="utf-8"))
        self.assertEqual(document["vulnerabilities"], [])


class PersistedHdfRoundTripTests(PersistedStoreTestCase):
    """An HDF document ingested into a store reports exactly as it reports statelessly.

    `inspec-linux-host.hdf.json` is native InSpec output whose results carry start times, so
    neither path needs a detection attestation, and it carries the errored check that both
    paths must name as an unresolved observation rather than report as a vulnerability
    (ADR 0013).
    """

    HDF = FIXTURES / "inspec-linux-host.hdf.json"
    INGESTED_AT = "2026-09-15T12:00:00Z"
    OPTIONS = (
        "--class",
        "C",
        "--package-uri",
        "https://example.test/cpo",
        "--from",
        "2026-09-01T00:00:00Z",
        "--to",
        "2026-09-30T23:59:59Z",
        "--as-of",
        "2026-09-15T12:00:00Z",
    )
    UNRESOLVED = (
        "warning: unresolved_observation: SYN-LNX-0005 on "
        "3f0c9a2e-6d4b-4c1e-9a7b-2f1e8d5c4b3a has disposition error"
    )

    def ingest_hdf(self) -> tuple[str, str]:
        return self.succeeds(
            [
                "ingest",
                str(self.HDF),
                "--db",
                str(self.database),
                "--as-of",
                self.INGESTED_AT,
                "--actor",
                "golden",
            ]
        )

    def test_a_persisted_hdf_report_matches_the_stateless_report_byte_for_byte(self) -> None:
        out, err = self.ingest_hdf()

        self.assertEqual(out, "inspec-linux-host.hdf.json: recorded 6 observation(s)\n")
        self.assertIn("warning: control_waived", err)
        self.assertIn("info: impact_zero_not_applicable", err)

        persisted_json = self.workspace / "persisted.json"
        persisted_markdown = self.workspace / "persisted.md"
        _, err = self.succeeds(
            [
                "report",
                "vdt",
                "--db",
                str(self.database),
                *self.OPTIONS,
                "-o",
                str(persisted_json),
                "--markdown",
                str(persisted_markdown),
            ]
        )

        self.assertIn(self.UNRESOLVED, err)

        stateless_json = self.workspace / "stateless.json"
        stateless_markdown = self.workspace / "stateless.md"
        _, err = self.succeeds(
            [
                "report",
                "vdt",
                str(self.HDF),
                *self.OPTIONS,
                "-o",
                str(stateless_json),
                "--markdown",
                str(stateless_markdown),
            ]
        )

        self.assertIn(self.UNRESOLVED, err)
        self.assertEqual(persisted_json.read_bytes(), stateless_json.read_bytes())
        self.assertEqual(persisted_markdown.read_bytes(), stateless_markdown.read_bytes())
        document = json.loads(persisted_json.read_text(encoding="utf-8"))
        self.assertEqual(
            [item["providerTrackingId"] for item in document["vulnerabilities"]],
            ["case-181b4b18c88fe895"],
        )
        self.assertEqual(
            document["x-complyroll"]["parserVersions"], {"complyroll.hdf": HDF_PARSER_VERSION}
        )
        self.assertIsNone(document["x-complyroll"]["detectionTimeAttestation"])

    def test_the_persisted_hdf_report_validates_against_the_official_schema(self) -> None:
        self.ingest_hdf()
        output = self.workspace / "report.json"
        self.succeeds(
            ["report", "vdt", "--db", str(self.database), *self.OPTIONS, "-o", str(output)]
        )

        code, out, err = run(["validate", str(output), "--schema", "vulnerability-detail"])

        self.assertEqual(code, 0)
        self.assertEqual(err, "")
        self.assertTrue(out.startswith("valid: https://fedramp.gov/schemas/"))
        self.assertIn("0.1.1", out)


class PersistedCycloneDxRoundTripTests(PersistedStoreTestCase):
    """CycloneDX SBOMs ingested into a store report exactly as they report statelessly.

    `grype-image.cdx.json` and `trivy-image.cdx.json` are two producers' matches of one image,
    each declaring `metadata.timestamp`, so neither path needs a detection attestation. The
    persisted reports are the `vdt-cyclonedx` and `historical-cyclonedx` goldens byte for byte
    (plan section 17, ADR 0010).
    """

    ARTIFACTS = (FIXTURES / "grype-image.cdx.json", FIXTURES / "trivy-image.cdx.json")
    INGESTED_AT = "2026-10-02T12:00:00Z"
    OPTIONS = (
        "--class",
        "C",
        "--package-uri",
        "https://example.test/cpo",
        "--calendar-tz",
        "UTC",
        "--as-of",
        "2026-10-03T12:00:00Z",
    )
    PERIOD = ("--from", "2026-10-01T00:00:00Z", "--to", "2026-10-31T23:59:59Z")
    WEAK = "warning: package_identity_weak: an affected component has no usable purl"

    def ingest_sboms(self, artifacts: Sequence[Path] = ARTIFACTS) -> tuple[str, str]:
        return self.succeeds(
            [
                "ingest",
                *(str(path) for path in artifacts),
                "--db",
                str(self.database),
                "--as-of",
                self.INGESTED_AT,
                "--actor",
                "golden",
            ]
        )

    def report(self, kind: str, source: Sequence[str], stem: str) -> tuple[Path, Path, str]:
        json_path = self.workspace / f"{stem}.json"
        markdown_path = self.workspace / f"{stem}.md"
        period = self.PERIOD if kind == "vdt" else ()
        _, err = self.succeeds(
            [
                "report",
                kind,
                *source,
                *self.OPTIONS,
                *period,
                "-o",
                str(json_path),
                "--markdown",
                str(markdown_path),
            ]
        )
        return json_path, markdown_path, err

    def test_ingest_correlate_and_report_match_the_stateless_goldens(self) -> None:
        out, err = self.ingest_sboms()

        self.assertEqual(
            out,
            "grype-image.cdx.json: recorded 5 observation(s)\n"
            "trivy-image.cdx.json: recorded 4 observation(s)\n",
        )
        self.assertIn(self.WEAK, err)
        self.correlate()

        for kind in ("vdt", "historical"):
            with self.subTest(kind=kind):
                persisted = self.report(kind, ["--db", str(self.database)], f"{kind}-persisted")
                stateless = self.report(
                    kind, [str(path) for path in self.ARTIFACTS], f"{kind}-stateless"
                )
                golden = f"{kind}-cyclonedx"
                for rendering in (0, 1):
                    self.assertEqual(
                        persisted[rendering].read_bytes(), stateless[rendering].read_bytes()
                    )
                self.assertEqual(
                    persisted[0].read_bytes(), (GOLDEN / f"{golden}.json").read_bytes()
                )
                self.assertEqual(persisted[1].read_bytes(), (GOLDEN / f"{golden}.md").read_bytes())
                self.assertIn(self.WEAK, stateless[2])

    def test_reversed_ingest_order_reports_the_same_bytes(self) -> None:
        self.ingest_sboms(tuple(reversed(self.ARTIFACTS)))
        self.correlate()

        json_path, markdown_path, _ = self.report("vdt", ["--db", str(self.database)], "vdt")

        self.assertEqual(json_path.read_bytes(), (GOLDEN / "vdt-cyclonedx.json").read_bytes())
        self.assertEqual(markdown_path.read_bytes(), (GOLDEN / "vdt-cyclonedx.md").read_bytes())

    def test_the_persisted_reports_validate_against_the_official_schemas(self) -> None:
        self.ingest_sboms()
        self.correlate()
        schemas = (("vdt", "vulnerability-detail"), ("historical", "historical-activity"))
        for kind, schema in schemas:
            with self.subTest(kind=kind):
                json_path, _, _ = self.report(kind, ["--db", str(self.database)], kind)

                code, out, err = run(["validate", str(json_path), "--schema", schema])

                self.assertEqual(code, 0)
                self.assertEqual(err, "")
                self.assertTrue(out.startswith("valid: https://fedramp.gov/schemas/"))

    def tool_less_matched_bom(self) -> Path:
        """Write the trivy match with its `metadata.tools` removed: a K3 with no producer."""
        document = json.loads(self.ARTIFACTS[1].read_text(encoding="utf-8"))
        del document["metadata"]["tools"]
        path = self.workspace / "tool-less.cdx.json"
        path.write_text(json.dumps(document), encoding="utf-8")
        return path

    # FX2 CL-5: a K1 or K2 identity refusal is a format refusal, never a detection failure.
    def test_an_inventory_identity_refusal_records_no_failure_under_the_flag(self) -> None:
        subject = {"type": "container", "name": "x" * 600}
        for name, extra in (("k1.cdx.json", {}), ("k2.cdx.json", {"vulnerabilities": []})):
            with self.subTest(name=name):
                document = {
                    "bomFormat": "CycloneDX",
                    "specVersion": "1.6",
                    "metadata": {"tools": [{"name": "syft"}], "component": subject},
                    **extra,
                }
                path = self.workspace / name
                path.write_text(json.dumps(document), encoding="utf-8")
                output = self.workspace / f"{name}.report.json"
                argv = ["report", "vdt", str(path), *self.OPTIONS, *self.PERIOD]
                code, _, err = run([*argv, "--record-failed-imports", "-o", str(output)])
                self.assertNotEqual(code, 3)
                self.assertIn("artifact_parse_failed", err)
                self.assertNotIn("VDR-CSO-FAV", err)
                self.assertNotIn("detection_failure_recorded", err)

    def test_a_tool_less_matched_bom_is_a_content_failure_under_the_flag(self) -> None:
        path = self.tool_less_matched_bom()
        digest = hashlib.sha256(path.read_bytes()).hexdigest()
        output = self.workspace / "report.json"
        argv = ["report", "vdt", str(path), *self.OPTIONS, *self.PERIOD]

        code, _, err = run([*argv, "-o", str(output)])

        self.assertEqual(code, 1)
        self.assertIn("error: invalid_bom: no tool named", err)
        self.assertFalse(output.exists())

        code, _, err = run([*argv, "--record-failed-imports", "-o", str(output)])

        self.assertEqual(code, 3)
        self.assertIn(
            f"class content for source artifact sha256:{digest} (VDR-CSO-FAV) [tool-less.cdx.json]",
            err,
        )
        self.assertIn("warning: invalid_bom: no tool named", err)
        document = json.loads(output.read_text(encoding="utf-8"))
        (failure,) = document["x-complyroll"]["detectionFailures"]
        self.assertEqual(
            [failure[key] for key in ("failureClass", "failureCodes", "parser", "sha256")],
            ["content", ["invalid_bom"], "complyroll.cyclonedx", digest],
        )
        self.assertTrue(failure["trackingId"].startswith("case-"))
        self.assertEqual(
            [item["providerTrackingId"] for item in document["vulnerabilities"]],
            [failure["trackingId"]],
        )


class PersistedAcceptedSequenceTests(PersistedStoreTestCase):
    """The documented sequence with `evaluations-accepted.json` rebuilds the new goldens.

    The store is the one `PersistedSequenceTests` builds, up to the evaluation step; the
    accepted evaluations file adds one acceptance, and the three reports read it back
    exactly as the stateless path reads the file.
    """

    def test_the_documented_sequence_reproduces_the_accepted_goldens(self) -> None:
        self.ingest_fixtures()
        self.correlate()
        self.attest_missing()

        out, _ = self.evaluate(ACCEPTED_EVALUATIONS)

        self.assertEqual(
            out.splitlines(),
            [
                "evaluations: 3 appended, 0 skipped",
                "pain reductions: 1 appended, 0 skipped",
                "dispositions: 2 appended, 0 skipped",
                "identifications: 0 appended, 0 skipped",
            ],
        )

        listing, _ = self.succeeds(["cases", "list", "--db", str(self.database)])

        [row] = [line for line in listing.splitlines() if line.startswith(ACCEPTED_CASE)]
        self.assertEqual(
            row.split(),
            [ACCEPTED_CASE, "-", "banner_etc_issue", "1", "1", "2", "accepted"],
        )

        for kind in ("avi", "historical"):
            with self.subTest(report=kind):
                json_path = self.workspace / f"{kind}.json"
                markdown_path = self.workspace / f"{kind}.md"

                _, err = self.report(kind, output=json_path, markdown=markdown_path)

                self.assertIn("warning: source_timestamp_missing", err)
                self.assertEqual(
                    json_path.read_text(encoding="utf-8"),
                    (GOLDEN / f"{kind}-fixtures.json").read_text(encoding="utf-8"),
                )
                self.assertEqual(
                    markdown_path.read_text(encoding="utf-8"),
                    (GOLDEN / f"{kind}-fixtures.md").read_text(encoding="utf-8"),
                )

    def test_persisted_avi_and_historical_reports_go_to_stdout(self) -> None:
        self.populate(ACCEPTED_EVALUATIONS)

        for kind in ("avi", "historical"):
            with self.subTest(report=kind):
                out, _ = self.report(kind)

                self.assertEqual(
                    out, (GOLDEN / f"{kind}-fixtures.json").read_text(encoding="utf-8")
                )

    def test_the_detail_report_from_the_same_store_leaves_the_accepted_case_out(self) -> None:
        self.populate(ACCEPTED_EVALUATIONS)

        out, err = self.report()

        document = json.loads(out)
        self.assertNotIn(
            ACCEPTED_CASE, [item["providerTrackingId"] for item in document["vulnerabilities"]]
        )
        self.assertEqual(len(document["vulnerabilities"]), 5)
        self.assertIn(f"info: accepted_excluded: {ACCEPTED_CASE}", err)


class PersistedKevReportTests(PersistedStoreTestCase):
    """The same three KEV reports compiled from a store rather than from the artifacts.

    No store holds a CISA KEV catalog, so `--kev` is a per-run input here too and sits
    beside `--db` rather than conflicting with it. The KEV SARIF fixtures declare their
    own timestamps, so the sequence needs no detection attestation.
    """

    def populate_kev(self) -> None:
        """Run the writing commands the KEV fixtures need, in the documented order."""

        self.succeeds(
            [
                "ingest",
                *KEV_ARTIFACTS,
                "--db",
                str(self.database),
                "--as-of",
                KEV_AS_OF,
                "--actor",
                "golden",
            ]
        )
        self.correlate()
        self.succeeds(
            [
                "cases",
                "evaluate",
                "--db",
                str(self.database),
                "--evaluations",
                str(KEV_EVALUATIONS),
                "--actor",
                "golden",
            ]
        )

    def test_a_store_and_a_catalog_together_reproduce_the_golden_pairs(self) -> None:
        self.populate_kev()

        for kind in ("vdt", "avi", "historical"):
            with self.subTest(report=kind):
                json_path = self.workspace / f"{kind}.json"
                markdown_path = self.workspace / f"{kind}.md"

                _, err = self.succeeds(
                    [
                        *kev_argv(kind, db=self.database),
                        "-o",
                        str(json_path),
                        "--markdown",
                        str(markdown_path),
                    ]
                )

                self.assertIn("info: kev_entries_after_as_of", err)
                self.assertEqual(json_path.read_bytes(), (GOLDEN / f"{kind}-kev.json").read_bytes())
                self.assertEqual(
                    markdown_path.read_bytes(), (GOLDEN / f"{kind}-kev.md").read_bytes()
                )

    def test_a_catalog_beside_a_store_is_not_a_source_conflict(self) -> None:
        self.populate_kev()

        code, out, err = run(kev_argv("vdt", db=self.database))

        self.assertEqual(code, 0, msg=err)
        self.assertNotIn("invalid_option", err)
        self.assertEqual(out, (GOLDEN / "vdt-kev.json").read_text(encoding="utf-8"))

    def test_a_second_catalog_is_refused_against_a_store_too(self) -> None:
        self.populate_kev()

        code, out, err = run([*kev_argv("vdt", db=self.database), "--kev", str(KEV_CATALOG)])

        self.assertEqual(code, 1)
        self.assertEqual(out, "")
        self.assertIn("error: invalid_option: report vdt takes one --kev catalog, not 2", err)


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

    def test_a_duplicate_key_never_writes_a_terminal_escape_to_stderr(self) -> None:
        # The duplicated key is untrusted text, and the refusal that names it is printed.
        artifact = self.workspace / "escape.hdf.json"
        key = json.dumps("\x1b[2J\x1b]0;synthetic\x07" + "A" * 3000)
        artifact.write_text(f"{{{key}:1,{key}:2}}", encoding="utf-8")

        code, out, err = run(["ingest", str(artifact), "--db", str(self.database)])

        self.assertEqual(code, 1)
        self.assertEqual(out, "")
        self.assertIn(
            "error: artifact_parse_failed: duplicate JSON object key is prohibited: ", err
        )
        self.assertNotIn("\x1b", err)
        self.assertNotIn("\x07", err)
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

        with unguarded_stig_clocks():
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

        with unguarded_stig_clocks():
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

        with unguarded_stig_clocks():
            code, _, err = run(
                ["ingest", str(artifact), "--db", str(self.database), "--as-of", INGESTED_AT]
            )

        self.assertEqual(code, 1)
        self.assertIn("error: event_contract_invalid", err)
        self.assertTrue(self.database.is_file())
        self.assertEqual(self.latest_sequence(), before)


class PersistedFailedImportTests(PersistedStoreTestCase):
    """`ingest --record-failed-imports` records each failure as a failure stream (ADR 0014)."""

    #: A second ingest instant. A failure that declares no clock read at it derives another
    #: system observation than the same failure read at `INGESTED_AT`.
    LATER = "2026-08-21T13:00:00Z"
    #: What a flagged ingest of every persisted and failed fixture prints as it builds a
    #: fresh store: each reading's line in listed order, a side record's failure in its
    #: reading's slot, then the pure failures in name order.
    FRESH_STORE_SUMMARY = (
        "ubuntu-host.cklb: recorded 6 observation(s)",
        "windows-host.ckl: recorded 2 observation(s)",
        "openscap-results.xml: recorded 3 observation(s)",
        "failed-invocation.sarif: recorded 1 observation(s)",
        "failed-invocation.sarif: recorded detection failure (execution)",
        "failed-invalid-rules.cklb: recorded detection failure (content)",
        "failed-truncated.sarif: recorded detection failure (parse)",
    )
    #: The truncated log's own ERROR, as a failure's diagnostics carry it: demoted.
    TRUNCATED_PARSE_FAILED = (
        "warning: artifact_parse_failed: Unterminated string starting at: line 18 column 21 "
        "(char 419) [failed-truncated.sarif]"
    )

    def flagged_argv(self, *artifacts: str | Path, as_of: str = INGESTED_AT) -> list[str]:
        """Return one flagged ingest's arguments, at the golden instant by default."""

        return [
            "ingest",
            *(str(path) for path in artifacts),
            "--record-failed-imports",
            "--db",
            str(self.database),
            "--as-of",
            as_of,
            "--actor",
            "golden",
        ]

    def ingest_flagged(
        self, *artifacts: str | Path, as_of: str = INGESTED_AT
    ) -> tuple[int, str, str]:
        """Run one flagged ingest, at the golden instant by default, and return its streams."""

        return run(self.flagged_argv(*artifacts, as_of=as_of))

    @staticmethod
    def recorded_notice(name: str, failure_class: str) -> str:
        """Return the notice `ingest` writes for the failure of the fixture named `name`."""

        digest = hashlib.sha256((FIXTURES / name).read_bytes()).hexdigest()
        return (
            "warning: detection_failure_recorded: recorded a detection process failure of "
            f"class {failure_class} for source artifact sha256:{digest} (VDR-CSO-FAV) [{name}]"
        )

    def fresh_store_diagnostics(self) -> list[str]:
        """Return what a flagged ingest of every persisted and failed fixture writes to stderr.

        Each reading's own diagnostics are written as it is read, in listed order, while a
        failed reading writes nothing yet. Once the store is published the failures' follow:
        the side record's notice in its reading's slot, then each failed reading's demoted
        list in name order, ordered by code and closed by its notice (ADR 0014 Decision 14).
        """

        def undated(name: str) -> str:
            return (
                "warning: source_timestamp_missing: source artifact does not declare an "
                f"observation timestamp; observed_at is unknown [{name}]"
            )

        return [
            undated("ubuntu-host.cklb"),
            undated("windows-host.ckl"),
            undated("openscap-results.xml"),
            "warning: execution_unsuccessful: invocation reports executionSuccessful false; its "
            "results are still read (1 occurrence: runs[1].invocations[0]) "
            "[failed-invocation.sarif]",
            "info: run_clean: run reports no results (1 occurrence: runs[1]) "
            "[failed-invocation.sarif]",
            self.recorded_notice("failed-invocation.sarif", "execution"),
            "warning: invalid_rules: STIG entry has no rules array [stigs[0].rules]",
            "warning: no_observations: CKLB contains no usable rules [failed-invalid-rules.cklb]",
            undated("failed-invalid-rules.cklb"),
            self.recorded_notice("failed-invalid-rules.cklb", "content"),
            self.TRUNCATED_PARSE_FAILED,
            self.recorded_notice("failed-truncated.sarif", "parse"),
        ]

    def schema_version(self) -> int:
        with SQLiteEventStore(self.database) as store:
            return store.schema_version

    def failure_heads(self) -> list[dict[str, Any]]:
        return [
            dict(record.payload)
            for record in self.records()
            if record.event_type == "failure.recorded"
        ]

    def copy_of(self, source: str | Path, name: str) -> Path:
        """Write the source's bytes under another name in this test's workspace."""

        path = self.workspace / name
        path.write_bytes(Path(source).read_bytes())
        return path

    def record_reading(
        self, *, parser_name: str, parser_version: str, path: Path = TRUNCATED_FIXTURE
    ) -> str:
        """Record a reading of a failed log's bytes under another parser, through the writer.

        The installed parser cannot read those bytes, so the reading is moved the way
        `test_replay`'s `bumped` moves one: by replacing fields on its `IngestResult`, with
        its findings and diagnostics dropped.
        """

        at = datetime(2026, 8, 21, 12, tzinfo=UTC)
        result = ingest_stig_artifact(path, ingested_at=at)
        assert result.artifact is not None
        artifact = replace(result.artifact, parser_name=parser_name, parser_version=parser_version)
        moved = replace(result, artifact=artifact, observations=(), diagnostics=())
        with SQLiteEventStore(self.database) as store:
            outcome = record_ingest(
                EventRepository(store),
                moved,
                metadata=EventMetadata(actor="golden", run_id=SMUGGLED_RUN_ID),
                ingested_at=at,
            )
        return outcome.stream_id

    def record_failed_reading(self, *, parser_version: str, path: Path = TRUNCATED_FIXTURE) -> str:
        """Record a failed log's failure under another version of its parser."""

        at = datetime(2026, 8, 21, 12, tzinfo=UTC)
        result = ingest_stig_artifact(path, ingested_at=at)
        assert result.artifact is not None
        moved = replace(result, artifact=replace(result.artifact, parser_version=parser_version))
        classification = classify_ingest(moved)
        assert classification is not None
        with SQLiteEventStore(self.database) as store:
            outcome = record_failure(
                EventRepository(store),
                moved,
                classification,
                metadata=EventMetadata(actor="golden", run_id=SMUGGLED_RUN_ID),
                ingested_at=at,
            )
        return outcome.stream_id

    def record_parse_failure(
        self, path: Path, *, parser_name: str, parser_version: str, at: datetime
    ) -> str:
        """Record the bytes at `path` as a parse failure under the given parser, through the writer.

        The reading parses nothing and reports no failed invocation, so its system
        observation is at `at` whatever clock the log declares.
        """

        failed = moved_reading(
            path,
            ingested_at=at,
            parser_name=parser_name,
            parser_version=parser_version,
            parse_failure=True,
        )
        classification = classify_ingest(failed)
        assert classification is not None and not classification.side_record
        self.assertIs(classification.failure_class, FailureClass.PARSE)
        with SQLiteEventStore(self.database) as store:
            outcome = record_failure(
                EventRepository(store),
                failed,
                classification,
                metadata=EventMetadata(actor="golden", run_id=SMUGGLED_RUN_ID),
                ingested_at=at,
            )
        self.assertTrue(outcome.appended)
        return outcome.stream_id

    def clockless_side_record(self, name: str = "no-clock.sarif") -> Path:
        """Write a SARIF log with one finding and a failed invocation that declares no clock.

        `ingest` records its failure beside its reading, at the run's `--as-of`, so a run at
        another instant derives another system observation.
        """

        path = self.workspace / name
        log = make_log(make_run([make_result()], invocations=[{"executionSuccessful": False}]))
        path.write_text(json.dumps(log), encoding="utf-8")
        classification = classify_ingest(ingest_stig_artifact(path, ingested_at=datetime.now(UTC)))
        assert classification is not None and classification.side_record
        self.assertIsNone(classification.clock)
        return path

    def held_execution_failure(self) -> Path:
        """Write a SARIF log whose one failed invocation reports nothing it can read.

        The run's `results` is not an array, so the reading has ERRORs and no observation
        beside the failed invocation: `ingest` holds it as an execution failure rather than
        recording it beside an import, as it does `failed-invocation.sarif`.
        """

        failed_run = make_run(
            invocations=[{"executionSuccessful": False, "startTimeUtc": "2026-08-21T09:30:00Z"}]
        )
        failed_run["results"] = {}
        path = self.workspace / "failed-run.sarif"
        path.write_text(json.dumps(make_log(failed_run)), encoding="utf-8")
        classification = classify_ingest(ingest_stig_artifact(path, ingested_at=datetime.now(UTC)))
        assert classification is not None and not classification.side_record
        self.assertIs(classification.failure_class, FailureClass.EXECUTION)
        return path

    def refusal(
        self, holder: str, name: str, under: str = f"complyroll.sarif {SARIF_PARSER_VERSION}"
    ) -> str:
        """Return the line `ingest` refuses a failure with, the installed parser's by default."""

        return (
            f"error: failure_read_elsewhere: history holds a reading of these bytes in {holder} "
            f"that outranks their failure under {under}, so it is not a detection failure and "
            f"nothing was recorded by this run [{name}]"
        )

    def held_warning(
        self, holder: str, name: str, under: str = f"complyroll.sarif {SARIF_PARSER_VERSION}"
    ) -> str:
        """Return the WARNING `ingest` names the stream holding a failure it records as a hold."""

        return (
            f"warning: failure_held_by_another_stream: {holder} already holds this failure's "
            f"system observation, so the failure is recorded under {under} as a hold on it; a "
            "report carries the earliest record of that observation that no reading of these "
            f"bytes supersedes [{name}]"
        )

    def failure_streams(self) -> list[tuple[str, str]]:
        """Return each failure stream's head type and id, in recorded order, holds included."""

        return [
            (record.event_type, record.stream_id)
            for record in self.records()
            if record.event_type in ("failure.recorded", "failure.held")
        ]

    def persisted(self, *, as_of: str = INGESTED_AT) -> dict[str, Any]:
        """Correlate, attest, and return the persisted VDT report's extension at `as_of`."""

        self.correlate()
        self.attest_missing()
        report, _ = self.report(as_of=as_of)
        extension: dict[str, Any] = json.loads(report)["x-complyroll"]
        return extension

    @staticmethod
    def entries(extension: Mapping[str, Any]) -> list[tuple[str, str, str, str]]:
        """Return each `detectionFailures` entry as its parser, version, class and instant."""

        return [
            (entry["parser"], entry["parserVersion"], entry["failureClass"], entry["observedAt"])
            for entry in extension.get("detectionFailures", [])
        ]

    @staticmethod
    def codes(extension: Mapping[str, Any]) -> list[tuple[str, str | None]]:
        """Return each report diagnostic as its code and location."""

        return [(item["code"], item.get("location")) for item in extension["diagnostics"]]

    @staticmethod
    def message(extension: Mapping[str, Any], code: str, location: str) -> str:
        """Return the one report diagnostic with this code at this location."""

        (found,) = [
            item["message"]
            for item in extension["diagnostics"]
            if (item["code"], item.get("location")) == (code, location)
        ]
        return str(found)

    @contextmanager
    def refuse_after_the_hold(self) -> Iterator[list[str]]:
        """Fail `ingest` once its writer has appended a hold, listing each hold it appended.

        The real writer runs, so the hold is in the run's transaction when `HistoryError`
        stops the run, and only the rollback keeps it out of the store.
        """

        real_record_failure = cli_module.record_failure
        holds: list[str] = []

        def record_then_refuse(*args: Any, **kwargs: Any) -> Any:
            outcome = real_record_failure(*args, **kwargs)
            if outcome.appended and outcome.held_by is not None:
                holds.append(outcome.stream_id)
                raise HistoryError("simulated refusal after the hold")
            return outcome

        with patch.object(cli_module, "record_failure", record_then_refuse):
            yield holds

    def test_a_fresh_store_is_published_with_its_failures_and_the_run_exits_3(self) -> None:
        code, out, err = self.ingest_flagged(*PERSISTED_ARTIFACTS, *FAILED_ARTIFACTS)

        self.assertEqual(code, 3)
        self.assertEqual(code, cli_module.EXIT_DETECTION_FAILURES)
        self.assertTrue(self.database.is_file())
        self.assertEqual(out.splitlines(), list(self.FRESH_STORE_SUMMARY))
        # Every diagnostic, whole and in order. The failed readings' ERRORs are written
        # demoted, so a run that exits 3 prints none.
        self.assertEqual(err.splitlines(), self.fresh_store_diagnostics())
        self.assertEqual(
            sorted(head["name"] for head in self.failure_heads()),
            sorted(Path(path).name for path in FAILED_ARTIFACTS),
        )
        self.assertEqual(self.schema_version(), FAILURE_STREAM_SCHEMA_VERSION)
        verified, _ = self.succeeds(["store", "verify", "--db", str(self.database)])
        self.assertEqual(verified, f"ok: {self.latest_sequence()} event(s) verified\n")

    def test_a_fresh_store_writes_every_diagnostic_before_its_summary(self) -> None:
        # The readings' own diagnostics are written as they are read, and the failures' once
        # the store is published, just before the lines that claim them, so on a terminal no
        # recorded line comes before a diagnostic of the run.
        code, written = run_on_one_stream(
            self.flagged_argv(*PERSISTED_ARTIFACTS, *FAILED_ARTIFACTS)
        )

        self.assertEqual(code, 3)
        self.assertEqual(
            written.splitlines(), [*self.fresh_store_diagnostics(), *self.FRESH_STORE_SUMMARY]
        )

    def test_a_rerun_finds_every_failure_recorded_and_still_exits_3(self) -> None:
        self.ingest_flagged(*PERSISTED_ARTIFACTS, *FAILED_ARTIFACTS)
        before = self.latest_sequence()

        code, out, err = self.ingest_flagged(*PERSISTED_ARTIFACTS, *FAILED_ARTIFACTS)

        self.assertEqual(code, 3)
        self.assertEqual(
            out.splitlines(),
            [
                "ubuntu-host.cklb: already_recorded",
                "windows-host.ckl: already_recorded",
                "openscap-results.xml: already_recorded",
                "failed-invocation.sarif: already_recorded",
                "failed-invocation.sarif: already_recorded",
                "failed-invalid-rules.cklb: already_recorded",
                "failed-truncated.sarif: already_recorded",
            ],
        )
        # The rerun writes what the first run wrote, each failure's notice included.
        self.assertEqual(err.splitlines(), self.fresh_store_diagnostics())
        self.assertEqual(self.latest_sequence(), before)

    def test_the_flag_without_a_failure_exits_0_and_leaves_the_store_at_schema_1(self) -> None:
        code, out, _ = self.ingest_flagged(*PERSISTED_ARTIFACTS)

        self.assertEqual(code, 0)
        self.assertEqual(len(out.splitlines()), 3)
        self.assertEqual(self.failure_heads(), [])
        self.assertEqual(self.schema_version(), 1)

    def test_without_the_flag_a_failed_invocation_imports_as_it_always_has(self) -> None:
        code, out, err = run(
            ["ingest", str(FIXTURES / "failed-invocation.sarif"), "--db", str(self.database)]
        )

        self.assertEqual(code, 0)
        self.assertEqual(out, "failed-invocation.sarif: recorded 1 observation(s)\n")
        self.assertIn("warning: execution_unsuccessful", err)
        self.assertNotIn("detection_failure_recorded", err)
        self.assertEqual(self.failure_heads(), [])
        self.assertEqual(self.schema_version(), 1)

    def test_an_unmintable_failure_exits_1_and_writes_nothing(self) -> None:
        partial = self.workspace / "partial.cklb"
        partial.write_text(
            json.dumps(
                {
                    "target_data": {"host_name": "host-partial"},
                    "stigs": [{"stig_id": "SYN_STIG", "rules": [{"group_id": "V-000001"}, 1]}],
                }
            ),
            encoding="utf-8",
        )

        code, out, err = self.ingest_flagged(*FAILED_ARTIFACTS, partial)

        self.assertEqual(code, 1)
        self.assertEqual(out, "")
        self.assertIn("error: invalid_rule", err)
        self.assertNotIn("detection_failure_recorded", err)
        self.assertFalse(self.database.exists())
        self.assertEqual(list(self.workspace.iterdir()), [partial])

    def test_bytes_read_in_the_same_run_stop_their_failure_and_write_nothing(self) -> None:
        # A misnamed copy of bytes the run reads is not a detection failure, so it stops the
        # run with its own ERRORs, exactly as it does without the flag. That is decided only
        # once every file is read, so the failure listed after the copy is named too, in the
        # order listed, and no `failure_read_elsewhere` line is written.
        copy = self.copy_of(PERSISTED_ARTIFACTS[2], "openscap-copy.sarif")

        code, out, err = self.ingest_flagged(PERSISTED_ARTIFACTS[2], copy, TRUNCATED_FIXTURE)

        self.assertEqual(code, 1)
        self.assertEqual(out, "")
        self.assert_failure_named_not_claimed(err, copy, "artifact_parse_failed")
        self.assert_failure_named_not_claimed(err, TRUNCATED_FIXTURE, "artifact_parse_failed")
        self.assertEqual(
            [line.rsplit(" ", 1)[1] for line in err.splitlines() if line.startswith("error: ")],
            ["[openscap-copy.sarif]", "[failed-truncated.sarif]"],
        )
        self.assertNotIn("failure_read_elsewhere", err)
        self.assertFalse(self.database.exists())

    def assert_failure_named_not_claimed(self, err: str, path: str | Path, code: str) -> None:
        """Require a failed reading's own diagnostics on stderr, whole, and no recording claimed.

        A run that exits 1 records nothing, so each failed reading writes, as one block, the
        lines a run without the flag writes for that file alone, ERROR `code` among them.
        """

        with tempfile.TemporaryDirectory() as directory:
            alone, out, written = run(
                [
                    "ingest",
                    str(path),
                    "--db",
                    str(Path(directory) / "unflagged.sqlite"),
                    "--as-of",
                    INGESTED_AT,
                ]
            )
        self.assertEqual((alone, out), (1, ""))
        block = written.splitlines()
        self.assertTrue(any(line.startswith(f"error: {code}: ") for line in block), msg=written)
        lines = err.splitlines()
        self.assertTrue(
            any(
                lines[start : start + len(block)] == block
                for start in range(len(lines) - len(block) + 1)
            ),
            msg=f"{block!r} is not one block of:\n{err}",
        )
        self.assertNotIn("detection_failure_recorded", err)

    def test_a_store_that_appears_while_building_names_the_failure_and_claims_none(self) -> None:
        # The run records both failures in its own transaction, then loses the race to
        # publish, so nothing it recorded survives and stderr must not say otherwise.
        appeared = b"a store another run published"
        real_record_ingest = cli_module.record_ingest

        def publish_a_rival_store_first(*args: Any, **kwargs: Any) -> Any:
            if not self.database.exists():
                self.database.write_bytes(appeared)
            return real_record_ingest(*args, **kwargs)

        with patch.object(cli_module, "record_ingest", publish_a_rival_store_first):
            code, out, err = self.ingest_flagged(
                TRUNCATED_FIXTURE, FIXTURES / "failed-invocation.sarif"
            )

        self.assertEqual(code, 1)
        self.assertEqual(out, "")
        self.assertIn("error: store_conflict", err)
        self.assert_failure_named_not_claimed(err, TRUNCATED_FIXTURE, "artifact_parse_failed")
        self.assertEqual(self.database.read_bytes(), appeared)

    def test_a_rolled_back_run_names_the_failure_and_claims_none(self) -> None:
        # The windows checklist's append fails before any failure is recorded, so the failed
        # reading's own diagnostics are all that name it.
        def refuse(*args: Any, **kwargs: Any) -> Any:
            raise HistoryError("simulated history refusal")

        with patch.object(cli_module, "record_ingest", refuse):
            code, out, err = self.ingest_flagged(PERSISTED_ARTIFACTS[1], TRUNCATED_FIXTURE)

        self.assertEqual(code, 1)
        self.assertEqual(out, "")
        self.assertIn("error: history_invalid: simulated history refusal", err)
        self.assert_failure_named_not_claimed(err, TRUNCATED_FIXTURE, "artifact_parse_failed")
        self.assertFalse(self.database.exists())

    def test_a_failure_refused_after_another_was_recorded_names_both_and_claims_neither(
        self,
    ) -> None:
        # The first failure is recorded and the second refused in the same transaction, so
        # the first's diagnostics would claim a recording the rollback discarded.
        real_record_failure = cli_module.record_failure
        calls: list[str] = []

        def refuse_the_second(repository: Any, result: Any, *args: Any, **kwargs: Any) -> Any:
            calls.append(result.artifact.name)
            if len(calls) > 1:
                raise HistoryError("simulated history refusal")
            return real_record_failure(repository, result, *args, **kwargs)

        with patch.object(cli_module, "record_failure", refuse_the_second):
            code, out, err = self.ingest_flagged(TRUNCATED_FIXTURE, FAILED_ARTIFACTS[0])

        self.assertEqual(calls, ["failed-invalid-rules.cklb", "failed-truncated.sarif"])
        self.assertEqual(code, 1)
        self.assertEqual(out, "")
        self.assertIn("error: history_invalid: simulated history refusal", err)
        self.assert_failure_named_not_claimed(err, INVALID_RULES_FIXTURE, "no_observations")
        self.assert_failure_named_not_claimed(err, TRUNCATED_FIXTURE, "artifact_parse_failed")
        self.assertFalse(self.database.exists())

    def test_bytes_history_reads_elsewhere_refuse_the_failure_and_append_nothing(self) -> None:
        self.succeeds(
            ["ingest", PERSISTED_ARTIFACTS[2], "--db", str(self.database), "--as-of", INGESTED_AT]
        )
        before = self.latest_sequence()
        (reading,) = [
            record.stream_id
            for record in self.records()
            if record.event_type == "artifact.ingested"
        ]
        copy = self.copy_of(PERSISTED_ARTIFACTS[2], "openscap-copy.sarif")

        # The windows checklist reads cleanly, so a refusal that came after the first
        # append would leave it recorded.
        code, out, err = self.ingest_flagged(PERSISTED_ARTIFACTS[1], copy)

        self.assertEqual(code, 1)
        self.assertEqual(out, "")
        self.assertIn(self.refusal(reading, "openscap-copy.sarif"), err.splitlines())
        self.assertNotIn("detection_failure_recorded", err)
        self.assertEqual(self.latest_sequence(), before)
        self.assertEqual(self.schema_version(), 1)

    def test_a_refusal_history_decides_comes_before_every_failed_reading_named(self) -> None:
        # History decides `read_elsewhere` only once every file is read, so a failure listed
        # after the copy is named too. The refusal comes first, then each failed reading's
        # own ERROR in the order listed, wherever the copy was listed.
        self.succeeds(
            ["ingest", PERSISTED_ARTIFACTS[2], "--db", str(self.database), "--as-of", INGESTED_AT]
        )
        before = self.latest_sequence()
        (reading,) = [
            record.stream_id
            for record in self.records()
            if record.event_type == "artifact.ingested"
        ]
        copy = self.copy_of(PERSISTED_ARTIFACTS[2], "openscap-copy.sarif")

        for listed in ((copy, TRUNCATED_FIXTURE), (TRUNCATED_FIXTURE, copy)):
            names = [path.name for path in listed]
            with self.subTest(listed=names):
                code, out, err = self.ingest_flagged(*listed)

                self.assertEqual(code, 1)
                self.assertEqual(out, "")
                lines = err.splitlines()
                self.assertEqual(lines[0], self.refusal(reading, "openscap-copy.sarif"))
                self.assertEqual(
                    [line.rsplit(" ", 1)[1] for line in lines[1:]], [f"[{name}]" for name in names]
                )
                self.assert_failure_named_not_claimed(
                    err, TRUNCATED_FIXTURE, "artifact_parse_failed"
                )
                self.assertEqual(self.latest_sequence(), before)

    def test_a_side_record_another_stream_holds_records_its_reading_and_names_the_holder(
        self,
    ) -> None:
        # The next version reads the log a run of the installed version recorded, so its
        # reading is a new artifact stream while its failed invocation is the system
        # observation the installed version's side record holds. The failure is recorded as a
        # hold on the next version's own failure stream: stdout names the holder after the
        # class, and the WARNING follows the notice.
        def read_by_the_next_version(path: Path, *, ingested_at: datetime) -> IngestResult:
            return bumped(ingest_stig_artifact(path, ingested_at=ingested_at), SARIF_NEXT)

        self.assertEqual(self.ingest_flagged(INVOCATION_FIXTURE)[0], 3)
        (holder,) = [
            record.stream_id for record in self.records() if record.event_type == "failure.recorded"
        ]

        with patch.object(cli_module, "ingest_stig_artifact", read_by_the_next_version):
            code, out, err = self.ingest_flagged(INVOCATION_FIXTURE)

        self.assertEqual(code, 3)
        self.assertEqual(
            out.splitlines(),
            [
                "failed-invocation.sarif: recorded 1 observation(s)",
                "failed-invocation.sarif: recorded detection failure (execution), held by "
                f"{holder}",
            ],
        )
        lines = err.splitlines()
        warning = self.held_warning(
            holder, "failed-invocation.sarif", under=f"complyroll.sarif {SARIF_NEXT}"
        )
        notices = [
            index
            for index, line in enumerate(lines)
            if line.startswith("warning: detection_failure_recorded: ")
        ]
        self.assertEqual(len(notices), 1)
        self.assertEqual(lines[notices[0] + 1], warning)
        self.assertEqual(
            sorted(
                record.stream_id.split("/", 2)[2]
                for record in self.records()
                if record.event_type == "artifact.ingested"
            ),
            sorted([f"complyroll.sarif/{SARIF_PARSER_VERSION}", f"complyroll.sarif/{SARIF_NEXT}"]),
        )
        hold = f"{holder.removesuffix(SARIF_PARSER_VERSION)}{SARIF_NEXT}"
        self.assertEqual(
            self.failure_streams(), [("failure.recorded", holder), ("failure.held", hold)]
        )
        self.assertEqual(self.schema_version(), HELD_FAILURE_SCHEMA_VERSION)

    def test_every_run_that_meets_a_hold_names_its_holder(self) -> None:
        # A rerun of the held reading finds its hold and repeats the WARNING beside
        # `already_recorded`, so a pipeline sees the hold on every run. A rerun of the
        # holder's own reading is a rerun of a recorded failure and stays silent (ADR 0014,
        # amendment 2026-10-13).
        def read_by_the_next_version(path: Path, *, ingested_at: datetime) -> IngestResult:
            return bumped(ingest_stig_artifact(path, ingested_at=ingested_at), SARIF_NEXT)

        self.assertEqual(self.ingest_flagged(INVOCATION_FIXTURE)[0], 3)
        ((_, holder),) = self.failure_streams()
        warning = self.held_warning(
            holder, "failed-invocation.sarif", under=f"complyroll.sarif {SARIF_NEXT}"
        )
        with patch.object(cli_module, "ingest_stig_artifact", read_by_the_next_version):
            self.assertEqual(self.ingest_flagged(INVOCATION_FIXTURE)[0], 3)
        streams = self.failure_streams()
        self.assertEqual([head for head, _ in streams], ["failure.recorded", "failure.held"])
        before = self.database.read_bytes()

        for label, reader, warned in (
            ("the held reading", read_by_the_next_version, True),
            ("the holder's reading", ingest_stig_artifact, False),
        ):
            with self.subTest(label):
                with patch.object(cli_module, "ingest_stig_artifact", reader):
                    code, out, err = self.ingest_flagged(INVOCATION_FIXTURE)

                self.assertEqual(code, 3)
                self.assertEqual(
                    out.splitlines(), ["failed-invocation.sarif: already_recorded"] * 2
                )
                self.assertEqual(warning in err.splitlines(), warned)
                self.assertEqual("failure_held_by_another_stream" in err, warned)
                self.assertNotIn("error:", err)
                self.assertEqual(self.failure_streams(), streams)
                self.assertEqual(self.database.read_bytes(), before)

    def superseded_parse_holder(self) -> tuple[Path, str]:
        """Write a side record whose own reading supersedes the failure holding it.

        Version 0 of the installed parser failed to parse the log at the golden instant.
        The installed version reads it there, and its failed invocation declares no clock, so
        the side record derives the system observation version 0's failure holds. Its own
        artifact then supersedes that failure under R3, and R4 keeps the side record current.
        """

        side = self.clockless_side_record()
        holder = self.record_parse_failure(
            side,
            parser_name="complyroll.sarif",
            parser_version="0",
            at=datetime(2026, 8, 21, 12, tzinfo=UTC),
        )
        return side, holder

    def test_a_side_record_held_by_a_failure_its_reading_supersedes_is_carried_by_its_hold(
        self,
    ) -> None:
        # The run's own artifact supersedes version 0's parse failure under R3, and R4 keeps
        # the side record standing, so its hold carries the failure: the report names the
        # installed version's failure at the golden instant (ADR 0014, amendment 2026-10-13).
        side, holder = self.superseded_parse_holder()
        hold = f"{holder[:-1]}{SARIF_PARSER_VERSION}"

        code, out, err = self.ingest_flagged(side)

        self.assertEqual(code, 3)
        self.assertEqual(
            out.splitlines(),
            [
                "no-clock.sarif: recorded 1 observation(s)",
                f"no-clock.sarif: recorded detection failure (execution), held by {holder}",
            ],
        )
        self.assertIn("warning: execution_unsuccessful", err)
        self.assertIn(self.held_warning(holder, "no-clock.sarif"), err.splitlines())
        self.assertNotIn("error:", err)
        self.assertEqual(
            self.failure_streams(), [("failure.recorded", holder), ("failure.held", hold)]
        )
        extension = self.persisted()
        self.assertEqual(
            [item["parserVersion"] for item in extension["artifacts"]], [SARIF_PARSER_VERSION]
        )
        self.assertEqual(
            self.entries(extension),
            [("complyroll.sarif", SARIF_PARSER_VERSION, "execution", INGESTED_AT)],
        )
        self.assertIn(("failure_superseded", holder), self.codes(extension))
        before = self.database.read_bytes()

        # Another instant would derive another system observation, but the reading's own
        # stream is found first, so the first instant wins and the run is a rerun.
        code, out, err = self.ingest_flagged(side, as_of=self.LATER)

        self.assertEqual(code, 3)
        self.assertEqual(out.splitlines(), ["no-clock.sarif: already_recorded"] * 2)
        self.assertIn(self.held_warning(holder, "no-clock.sarif"), err.splitlines())
        self.assertEqual(self.database.read_bytes(), before)
        self.assertEqual(
            self.entries(self.persisted(as_of=self.LATER)),
            [("complyroll.sarif", SARIF_PARSER_VERSION, "execution", INGESTED_AT)],
        )

    def test_a_held_side_record_with_a_declared_clock_is_recorded_as_a_hold_at_any_as_of(
        self,
    ) -> None:
        # The scanner's clock is the system observation's instant, so `--as-of` cannot move
        # it. The first run records the hold, which carries once the run's own artifact
        # supersedes version 0's parse failure; a run at another instant is its rerun.
        holder = self.record_parse_failure(
            INVOCATION_FIXTURE,
            parser_name="complyroll.sarif",
            parser_version="0",
            at=datetime(2026, 8, 4, 10, tzinfo=UTC),
        )
        hold = f"{holder[:-1]}{SARIF_PARSER_VERSION}"
        expected = {
            INGESTED_AT: [
                "failed-invocation.sarif: recorded 1 observation(s)",
                "failed-invocation.sarif: recorded detection failure (execution), held by "
                f"{holder}",
            ],
            self.LATER: ["failed-invocation.sarif: already_recorded"] * 2,
        }

        for as_of, lines in expected.items():
            with self.subTest(as_of=as_of):
                code, out, err = self.ingest_flagged(INVOCATION_FIXTURE, as_of=as_of)

                self.assertEqual(code, 3)
                self.assertEqual(out.splitlines(), lines)
                self.assertIn(
                    self.held_warning(holder, "failed-invocation.sarif"), err.splitlines()
                )
                self.assertEqual(
                    self.failure_streams(), [("failure.recorded", holder), ("failure.held", hold)]
                )

        self.assertEqual(
            self.entries(self.persisted()),
            [("complyroll.sarif", SARIF_PARSER_VERSION, "execution", "2026-08-04T10:00:00Z")],
        )
        out, _ = self.succeeds(
            ["ingest", str(INVOCATION_FIXTURE), "--db", str(self.database), "--as-of", INGESTED_AT]
        )
        self.assertEqual(out, "failed-invocation.sarif: already_recorded\n")

    def test_a_held_failure_whose_holder_a_newer_reading_superseded_is_carried_by_its_hold(
        self,
    ) -> None:
        # Version 0.2 read the bytes after version 0.1 failed on them, so nothing keeps the
        # installed version's failure out before the writes. Its system observation is version
        # 0.1's, which the 0.2 reading supersedes, so the hold carries the failure, and R2
        # retires the 0.2 reading in its favour as it would a recorded failure at the installed
        # version.
        holder = self.record_failed_reading(parser_version="0.1")
        reading = self.record_reading(parser_name="complyroll.sarif", parser_version="0.2")

        code, out, err = self.ingest_flagged(TRUNCATED_FIXTURE)

        self.assertEqual(code, 3)
        self.assertEqual(
            out,
            f"failed-truncated.sarif: recorded detection failure (parse), held by {holder}\n",
        )
        self.assertIn(self.held_warning(holder, "failed-truncated.sarif"), err.splitlines())
        self.assertNotIn("error:", err)
        extension = self.persisted()
        self.assertEqual(
            self.entries(extension),
            [("complyroll.sarif", SARIF_PARSER_VERSION, "parse", INGESTED_AT)],
        )
        self.assertIn(
            f"failed under the newer complyroll.sarif {SARIF_PARSER_VERSION};",
            self.message(extension, "artifact_superseded_by_failure", reading),
        )
        self.assertIn(("failure_superseded", holder), self.codes(extension))

    def test_a_held_failure_is_carried_beside_newer_failures_of_its_bytes(self) -> None:
        # Version 1 fails to parse the log, version 2 reads it with its failed invocation,
        # and version 3 fails to parse it, so R2 retires version 2's reading in favour of
        # version 3's failure. Version 4, failing at version 1's instant, is held beneath
        # version 1's failure, which version 2's reading supersedes, so the hold carries
        # beside the newer failures and R2's replacement moves to version 4.
        side = self.clockless_side_record()
        for version, parse_failure, as_of in (
            ("1", True, INGESTED_AT),
            ("2", False, "2026-08-22T12:00:00Z"),
            ("3", True, "2026-08-23T12:00:00Z"),
        ):
            reader = partial(
                moved_reading,
                parser_name="complyroll.sarif",
                parser_version=version,
                parse_failure=parse_failure,
            )
            with patch.object(cli_module, "ingest_stig_artifact", reader):
                self.assertEqual(self.ingest_flagged(side, as_of=as_of)[0], 3)
        (holder,) = [
            record.stream_id
            for record in self.records()
            if record.event_type == "failure.recorded" and record.stream_id.endswith("/1")
        ]
        (reading,) = [
            record.stream_id
            for record in self.records()
            if record.event_type == "artifact.ingested"
        ]
        as_of = "2026-08-24T12:00:00Z"
        newer = [
            ("complyroll.sarif", "2", "execution", "2026-08-22T12:00:00Z"),
            ("complyroll.sarif", "3", "parse", "2026-08-23T12:00:00Z"),
        ]
        before = self.persisted(as_of=as_of)
        self.assertEqual(self.entries(before), newer)
        self.assertIn(
            "failed under the newer complyroll.sarif 3;",
            self.message(before, "artifact_superseded_by_failure", reading),
        )

        reader = partial(
            moved_reading, parser_name="complyroll.sarif", parser_version="4", parse_failure=True
        )
        with patch.object(cli_module, "ingest_stig_artifact", reader):
            code, out, err = self.ingest_flagged(side)

        self.assertEqual(code, 3)
        self.assertEqual(
            out, f"no-clock.sarif: recorded detection failure (parse), held by {holder}\n"
        )
        self.assertIn(
            self.held_warning(holder, "no-clock.sarif", under="complyroll.sarif 4"),
            err.splitlines(),
        )
        after = self.persisted(as_of=as_of)
        self.assertEqual(
            self.entries(after), [*newer, ("complyroll.sarif", "4", "parse", INGESTED_AT)]
        )
        self.assertIn(
            "failed under the newer complyroll.sarif 4;",
            self.message(after, "artifact_superseded_by_failure", reading),
        )
        self.assertEqual(len({entry["trackingId"] for entry in after["detectionFailures"]}), 1)

    def test_a_failure_held_by_a_superseded_execution_failure_is_carried_by_its_hold(
        self,
    ) -> None:
        # R4 supersedes version 0.1's execution failure by the clean 0.2 reading, and nothing
        # reads the bytes cleanly at the installed version, so the hold carries the failure and
        # R2 retires the 0.2 reading. The log declares its clock, so a run at another `--as-of`
        # is a rerun, and without the flag its ERRORs stop the run as they always have.
        failed = self.held_execution_failure()
        holder = self.record_failed_reading(parser_version="0.1", path=failed)
        reading = self.record_reading(
            parser_name="complyroll.sarif", parser_version="0.2", path=failed
        )

        code, out, err = self.ingest_flagged(failed)

        self.assertEqual(code, 3)
        self.assertEqual(
            out, f"failed-run.sarif: recorded detection failure (execution), held by {holder}\n"
        )
        self.assertIn(self.held_warning(holder, "failed-run.sarif"), err.splitlines())
        extension = self.persisted()
        self.assertEqual(
            self.entries(extension),
            [("complyroll.sarif", SARIF_PARSER_VERSION, "execution", "2026-08-21T09:30:00Z")],
        )
        self.assertIn(
            f"failed under the newer complyroll.sarif {SARIF_PARSER_VERSION};",
            self.message(extension, "artifact_superseded_by_failure", reading),
        )
        self.assertIn(("failure_superseded", holder), self.codes(extension))
        before = self.database.read_bytes()

        code, out, err = self.ingest_flagged(failed, as_of=self.LATER)

        self.assertEqual(code, 3)
        self.assertEqual(out, "failed-run.sarif: already_recorded\n")
        self.assertIn(self.held_warning(holder, "failed-run.sarif"), err.splitlines())
        self.assertEqual(self.database.read_bytes(), before)

        code, out, err = run(["ingest", str(failed), "--db", str(self.database)])
        self.assertEqual(code, 1)
        self.assertEqual(out, "")
        self.assertTrue(
            any(
                line.startswith("error: ") and line.endswith("[failed-run.sarif]")
                for line in err.splitlines()
            ),
            msg=err,
        )
        self.assertNotIn("failure_held_by_another_stream", err)
        self.assertEqual(self.database.read_bytes(), before)

    def test_a_held_failure_its_bytes_supersede_at_birth_keeps_the_warning(self) -> None:
        # A clean reading under the next version supersedes the side record's failure at birth
        # under R4, so no report carries it whoever holds it. It is recorded as a hold all the
        # same and is superseded from the start, as a recorded side record would be.
        side = self.clockless_side_record()
        holder = self.record_parse_failure(
            side,
            parser_name="complyroll.sarif",
            parser_version="0",
            at=datetime(2026, 8, 21, 12, tzinfo=UTC),
        )
        self.record_reading(parser_name="complyroll.sarif", parser_version=SARIF_NEXT, path=side)

        code, out, err = self.ingest_flagged(side)

        self.assertEqual(code, 3)
        self.assertEqual(
            out.splitlines(),
            [
                "no-clock.sarif: recorded 1 observation(s)",
                f"no-clock.sarif: recorded detection failure (execution), held by {holder}",
            ],
        )
        self.assertIn(self.held_warning(holder, "no-clock.sarif"), err.splitlines())
        extension = self.persisted()
        self.assertEqual(self.entries(extension), [])
        self.assertIn(
            ("failure_superseded", f"{holder[:-1]}{SARIF_PARSER_VERSION}"), self.codes(extension)
        )

    def test_a_held_failure_whose_holder_stays_current_keeps_the_warning(self) -> None:
        # The next version's parse failure is newer than the reading, so it stays current and
        # R2 supersedes the reading instead: the report carries the holder's failure. The side
        # record's failure is recorded as a hold, dormant beneath it, and the report names it.
        side = self.clockless_side_record()
        holder = self.record_parse_failure(
            side,
            parser_name="complyroll.sarif",
            parser_version=SARIF_NEXT,
            at=datetime(2026, 8, 21, 12, tzinfo=UTC),
        )

        code, out, err = self.ingest_flagged(side)

        self.assertEqual(code, 3)
        self.assertEqual(
            out.splitlines(),
            [
                "no-clock.sarif: recorded 1 observation(s)",
                f"no-clock.sarif: recorded detection failure (execution), held by {holder}",
            ],
        )
        lines = err.splitlines()
        (notice,) = [
            line for line in lines if line.startswith("warning: detection_failure_recorded: ")
        ]
        self.assertTrue(notice.endswith("[no-clock.sarif]"))
        self.assertEqual(
            lines[lines.index(notice) + 1], self.held_warning(holder, "no-clock.sarif")
        )
        (reading,) = [
            record.stream_id
            for record in self.records()
            if record.event_type == "artifact.ingested"
        ]
        report, _ = self.report()
        extension = json.loads(report)["x-complyroll"]
        self.assertIn(("artifact_superseded_by_failure", reading), self.codes(extension))
        hold = f"{holder.removesuffix(SARIF_NEXT)}{SARIF_PARSER_VERSION}"
        self.assertIn(("failure_held", hold), self.codes(extension))
        self.assertEqual(
            self.entries(extension), [("complyroll.sarif", SARIF_NEXT, "parse", INGESTED_AT)]
        )

    def test_a_run_that_fails_after_its_hold_leaves_the_store_and_its_directory_as_they_were(
        self,
    ) -> None:
        # The side record's artifact stream and its hold are both appended before the run
        # fails, so only the rollback keeps them out.
        side, _ = self.superseded_parse_holder()
        before = self.database.read_bytes()

        with self.refuse_after_the_hold() as holds:
            code, out, err = self.ingest_flagged(side)

        self.assertEqual(len(holds), 1)
        self.assertEqual(code, 1)
        self.assertEqual(out, "")
        self.assertIn("error: history_invalid: simulated refusal after the hold", err)
        self.assertNotIn("detection_failure_recorded", err)
        self.assertEqual(self.database.read_bytes(), before)
        self.assertEqual(
            sorted(item.name for item in self.workspace.iterdir()),
            ["history.db", "no-clock.sarif"],
        )

    def test_a_holder_a_later_reading_supersedes_re_homes_the_held_failure(self) -> None:
        # The residual ADR 0014 Decision 13 documented, now recorded: the run that met
        # another parser's side record held by version 1's failure wrote the hold. A clean
        # reading later supersedes the holder and meets no hold, and the hold carries the
        # failure from then on. A rerun of the held reading is a rerun of its hold.
        def reading(parser_name: str, parser_version: str = "1", *, clean: bool = False) -> Any:
            return partial(
                moved_reading, parser_name=parser_name, parser_version=parser_version, clean=clean
            )

        held = reading("complyroll.other")
        for reader, as_of, expected in (
            (reading("complyroll.sarif"), INGESTED_AT, 3),
            (held, INGESTED_AT, 3),
            (reading("complyroll.sarif", "2", clean=True), self.LATER, 0),
        ):
            with patch.object(cli_module, "ingest_stig_artifact", reader):
                code, _, err = self.ingest_flagged(INVOCATION_FIXTURE, as_of=as_of)
            self.assertEqual(code, expected, msg=err)
        (holder,), (hold,) = (
            [stream for head, stream in self.failure_streams() if head == kind]
            for kind in ("failure.recorded", "failure.held")
        )
        self.assertTrue(holder.endswith("/complyroll.sarif/1"))
        self.assertTrue(hold.endswith("/complyroll.other/1"))
        extension = self.persisted(as_of=self.LATER)
        self.assertEqual(
            self.entries(extension),
            [("complyroll.other", "1", "execution", "2026-08-04T10:00:00Z")],
        )
        self.assertIn(("failure_superseded", holder), self.codes(extension))
        before = self.database.read_bytes()

        with patch.object(cli_module, "ingest_stig_artifact", held):
            code, out, err = self.ingest_flagged(INVOCATION_FIXTURE)

        self.assertEqual(code, 3)
        self.assertEqual(out.splitlines(), ["failed-invocation.sarif: already_recorded"] * 2)
        self.assertIn(
            self.held_warning(holder, "failed-invocation.sarif", under="complyroll.other 1"),
            err.splitlines(),
        )
        self.assertEqual(self.database.read_bytes(), before)

    def test_side_record_holds_come_before_pure_failure_holds_whatever_the_order(self) -> None:
        # `ingest` prints each reading it parsed, side records included, in listed order and
        # before any pure failure, so the side record `b-no-clock.sarif` and its WARNING come
        # before the pure failure `a-truncated.sarif` and its WARNING, whatever their names
        # and whichever order they were listed in.
        side = self.clockless_side_record("b-no-clock.sarif")
        failed = self.copy_of(TRUNCATED_FIXTURE, "a-truncated.sarif")
        outputs = []
        for listed in ((side, failed), (failed, side)):
            names = [path.name for path in listed]
            with self.subTest(listed=names):
                self.database = self.workspace / f"{names[0]}.db"
                side_holder = self.record_parse_failure(
                    side,
                    parser_name="complyroll.sarif",
                    parser_version="0",
                    at=datetime(2026, 8, 21, 12, tzinfo=UTC),
                )
                failed_holder = self.record_failed_reading(parser_version="0.1", path=failed)
                self.record_reading(
                    parser_name="complyroll.sarif", parser_version="0.2", path=failed
                )

                code, out, err = self.ingest_flagged(*listed)

                self.assertEqual(code, 3)
                self.assertEqual(
                    out.splitlines(),
                    [
                        "b-no-clock.sarif: recorded 1 observation(s)",
                        "b-no-clock.sarif: recorded detection failure (execution), held by "
                        f"{side_holder}",
                        "a-truncated.sarif: recorded detection failure (parse), held by "
                        f"{failed_holder}",
                    ],
                )
                self.assertEqual(
                    [
                        line
                        for line in err.splitlines()
                        if line.startswith("warning: failure_held_by_another_stream: ")
                    ],
                    [
                        self.held_warning(side_holder, "b-no-clock.sarif"),
                        self.held_warning(failed_holder, "a-truncated.sarif"),
                    ],
                )
                outputs.append((out, err))
        self.assertEqual(len(outputs), 2)
        self.assertEqual(outputs[0], outputs[1])

    def test_side_records_meet_holds_in_name_order_whatever_the_listed_order(self) -> None:
        # Two names for one log, read by two parsers. Recorded by name, `a.sarif` writes its
        # failure first, which the store's clean reading under its parser supersedes at
        # birth, so `b.sarif` finds it holding its own and is recorded as a hold beneath it
        # whichever order they were listed in. Nothing supersedes the hold, so it carries.
        first = self.clockless_side_record("a.sarif")
        second = self.copy_of(first, "b.sarif")

        def read_by_name(path: Path, *, ingested_at: datetime) -> IngestResult:
            parser_name = "complyroll.other" if path.name == "a.sarif" else "complyroll.sarif"
            return moved_reading(
                path, ingested_at=ingested_at, parser_name=parser_name, parser_version="1"
            )

        digest = hashlib.sha256(first.read_bytes()).hexdigest()
        holder = failure_stream_id(digest, "complyroll.other", "1")
        hold = failure_stream_id(digest, "complyroll.sarif", "1")
        lines = {
            "a.sarif": [
                "a.sarif: recorded 1 observation(s)",
                "a.sarif: recorded detection failure (execution)",
            ],
            "b.sarif": [
                "b.sarif: recorded 1 observation(s)",
                f"b.sarif: recorded detection failure (execution), held by {holder}",
            ],
        }
        for listed in ((second, first), (first, second)):
            names = [path.name for path in listed]
            with self.subTest(listed=names):
                # The first run writes, so each order starts from its own copy of the store.
                self.database = self.workspace / f"{names[0]}.db"
                self.record_reading(parser_name="complyroll.other", parser_version="2", path=first)

                with patch.object(cli_module, "ingest_stig_artifact", read_by_name):
                    code, out, err = self.ingest_flagged(*listed)

                self.assertEqual(code, 3)
                self.assertEqual(out.splitlines(), [line for name in names for line in lines[name]])
                self.assertEqual(
                    [
                        line
                        for line in err.splitlines()
                        if line.startswith("warning: failure_held_by_another_stream: ")
                    ],
                    [self.held_warning(holder, "b.sarif", under="complyroll.sarif 1")],
                )
                self.assertEqual(
                    self.failure_streams(), [("failure.recorded", holder), ("failure.held", hold)]
                )
                self.assertEqual(
                    self.entries(self.persisted()),
                    [("complyroll.sarif", "1", "execution", INGESTED_AT)],
                )

    def test_two_readings_held_by_one_superseded_stream_share_one_hold(self) -> None:
        # Two names for one log, both held by the version 0 parse failure the run's own
        # artifact supersedes under R3. `a.sarif` records the hold, and `b.sarif`, the same
        # bytes under the same parser, finds that stream: one hold, each name warned (ADR
        # 0014 Decision 2).
        first = self.clockless_side_record("a.sarif")
        second = self.copy_of(first, "b.sarif")
        holder = self.record_parse_failure(
            first,
            parser_name="complyroll.sarif",
            parser_version="0",
            at=datetime(2026, 8, 21, 12, tzinfo=UTC),
        )

        code, out, err = self.ingest_flagged(first, second)

        self.assertEqual(code, 3, msg=err)
        self.assertEqual(
            out.splitlines(),
            [
                "a.sarif: recorded 1 observation(s)",
                f"a.sarif: recorded detection failure (execution), held by {holder}",
                "b.sarif: already_recorded",
                "b.sarif: already_recorded",
            ],
        )
        self.assertEqual(
            [
                line
                for line in err.splitlines()
                if line.startswith("warning: failure_held_by_another_stream: ")
            ],
            [self.held_warning(holder, "a.sarif"), self.held_warning(holder, "b.sarif")],
        )
        self.assertNotIn("error:", err)
        hold = f"{holder[:-1]}{SARIF_PARSER_VERSION}"
        self.assertEqual(
            self.failure_streams(), [("failure.recorded", holder), ("failure.held", hold)]
        )

    def test_a_rerun_of_a_failure_recorded_at_another_instant_is_not_a_hold(self) -> None:
        # Recorded at another instant, the side record is on its own stream, so a rerun finds
        # that stream rather than a holder and is never weighed, superseded holder or not.
        side, _ = self.superseded_parse_holder()
        self.assertEqual(self.ingest_flagged(side, as_of=self.LATER)[0], 3)

        code, out, err = self.ingest_flagged(side, as_of=self.LATER)

        self.assertEqual(code, 3)
        self.assertEqual(
            out.splitlines(),
            ["no-clock.sarif: already_recorded", "no-clock.sarif: already_recorded"],
        )
        self.assertNotIn("error:", err)

    def test_a_rerun_whose_later_reading_supersedes_it_at_birth_keeps_the_warning(self) -> None:
        # The later reading supersedes the holder under R3 and the hold under R4, so no
        # report carries either, and a rerun still finds the hold and names its holder (ADR
        # 0014, amendment 2026-10-13).
        side = self.clockless_side_record()
        holder = self.record_parse_failure(
            side,
            parser_name="complyroll.sarif",
            parser_version=SARIF_NEXT,
            at=datetime(2026, 8, 21, 12, tzinfo=UTC),
        )
        code, _, err = self.ingest_flagged(side)
        self.assertEqual(code, 3, msg=err)
        self.assertIn(f"warning: failure_held_by_another_stream: {holder} ", err)
        self.record_reading(
            parser_name="complyroll.sarif", parser_version=SARIF_AFTER_NEXT, path=side
        )
        before = self.database.read_bytes()

        code, out, err = self.ingest_flagged(side)

        self.assertEqual(code, 3, msg=err)
        self.assertEqual(
            out.splitlines(),
            ["no-clock.sarif: already_recorded", "no-clock.sarif: already_recorded"],
        )
        self.assertIn(f"warning: failure_held_by_another_stream: {holder} ", err)
        self.assertNotIn("error:", err)
        self.assertEqual(self.database.read_bytes(), before)

    def test_a_reading_recorded_before_the_hold_supersedes_it_and_its_rerun_still_warns(
        self,
    ) -> None:
        # The hdf reading supersedes the holder under R3 but not the side record's execution
        # failure under R4, which needs the same parser; the next version's sarif reading
        # recorded before the first run does, even though the hdf reading has superseded that
        # reading by then. A rerun finds the hold and names its holder (ADR 0014, amendment
        # 2026-10-13).
        side = self.clockless_side_record()
        self.record_reading(parser_name="complyroll.sarif", parser_version=SARIF_NEXT, path=side)
        holder = self.record_parse_failure(
            side,
            parser_name="complyroll.sarif",
            parser_version=SARIF_AFTER_NEXT,
            at=datetime(2026, 8, 21, 12, tzinfo=UTC),
        )
        code, _, err = self.ingest_flagged(side)
        self.assertEqual(code, 3, msg=err)
        self.assertIn(f"warning: failure_held_by_another_stream: {holder} ", err)
        self.record_reading(parser_name="complyroll.hdf", parser_version="3", path=side)
        before = self.database.read_bytes()

        code, out, err = self.ingest_flagged(side)

        self.assertEqual(code, 3, msg=err)
        self.assertEqual(
            out.splitlines(),
            ["no-clock.sarif: already_recorded", "no-clock.sarif: already_recorded"],
        )
        self.assertIn(f"warning: failure_held_by_another_stream: {holder} ", err)
        self.assertNotIn("error:", err)
        self.assertEqual(self.database.read_bytes(), before)

    def test_a_held_pure_failure_a_current_reading_outranks_is_refused_first(self) -> None:
        # The next version's reading is current under R1 and outranks the installed version, so
        # the rerun is refused by reading_elsewhere's current-reading check before the writes
        # and never reaches the hold the first run recorded (ADR 0014 Decisions 11 and 13).
        holder = self.record_failed_reading(parser_version="0.1")
        code, out, err = self.ingest_flagged(TRUNCATED_FIXTURE)
        self.assertEqual(code, 3, msg=err)
        self.assertEqual(
            out,
            f"failed-truncated.sarif: recorded detection failure (parse), held by {holder}\n",
        )
        # A hold writes what a recorded failure would, then the WARNING naming its holder.
        self.assertEqual(
            err.splitlines(),
            [
                self.TRUNCATED_PARSE_FAILED,
                self.recorded_notice("failed-truncated.sarif", "parse"),
                self.held_warning(holder, "failed-truncated.sarif"),
            ],
        )
        reading = self.record_reading(parser_name="complyroll.sarif", parser_version=SARIF_NEXT)
        before = self.database.read_bytes()

        code, out, err = self.ingest_flagged(TRUNCATED_FIXTURE)

        self.assertEqual(code, 1)
        self.assertEqual(out, "")
        self.assertEqual(err.splitlines()[0], self.refusal(reading, "failed-truncated.sarif"))
        self.assert_failure_named_not_claimed(err, TRUNCATED_FIXTURE, "artifact_parse_failed")
        self.assertNotIn("failure_held_by", err)
        self.assertEqual(self.database.read_bytes(), before)

    def test_a_held_pure_failure_a_superseded_reading_supersedes_at_birth_is_refused(self) -> None:
        # The sarif 0.7 reading is current under R1 but below the installed version, so the
        # current-reading check finds nothing; the superseded hdf 0.5 reading would still
        # supersede the installed version's parse failure at birth under R3, so the at-birth
        # leg of reading_elsewhere refuses the rerun before the writes and it never reaches the
        # hold the first run recorded (ADR 0014 Decisions 11 and 13).
        holder = self.record_failed_reading(parser_version="0.1")
        code, out, err = self.ingest_flagged(TRUNCATED_FIXTURE)
        self.assertEqual(code, 3, msg=err)
        self.assertEqual(
            out,
            f"failed-truncated.sarif: recorded detection failure (parse), held by {holder}\n",
        )
        self.assertIn(self.held_warning(holder, "failed-truncated.sarif"), err.splitlines())
        reading = self.record_reading(parser_name="complyroll.hdf", parser_version="0.5")
        self.record_reading(parser_name="complyroll.sarif", parser_version="0.7")
        before = self.database.read_bytes()

        code, out, err = self.ingest_flagged(TRUNCATED_FIXTURE)

        self.assertEqual(code, 1)
        self.assertEqual(out, "")
        self.assertEqual(err.splitlines()[0], self.refusal(reading, "failed-truncated.sarif"))
        self.assert_failure_named_not_claimed(err, TRUNCATED_FIXTURE, "artifact_parse_failed")
        self.assertNotIn("failure_held_by", err)
        self.assertEqual(self.database.read_bytes(), before)

    def test_the_at_birth_check_compares_versions_numerically(self) -> None:
        # Version 1's parse failure holds the observation, and the clean version 9 reading
        # supersedes it under R3. Version 10's failure is outranked only by a reading of the
        # digest at version 10 or later: none as numbers (9 < 10), though "9" sorts after
        # "10" as text, which would refuse the failure as read elsewhere. As numbers, it is
        # recorded as a hold that carries, and R2 retires the version 9 reading.
        side = self.clockless_side_record()
        holder = self.record_parse_failure(
            side,
            parser_name="complyroll.sarif",
            parser_version="1",
            at=datetime(2026, 8, 21, 12, tzinfo=UTC),
        )
        reading = self.record_reading(parser_name="complyroll.sarif", parser_version="9", path=side)
        reader = partial(
            moved_reading, parser_name="complyroll.sarif", parser_version="10", parse_failure=True
        )

        with patch.object(cli_module, "ingest_stig_artifact", reader):
            code, out, err = self.ingest_flagged(side)

        self.assertEqual(code, 3, msg=err)
        self.assertEqual(
            out, f"no-clock.sarif: recorded detection failure (parse), held by {holder}\n"
        )
        self.assertIn(
            self.held_warning(holder, "no-clock.sarif", under="complyroll.sarif 10"),
            err.splitlines(),
        )
        self.assertNotIn("failure_read_elsewhere", err)
        extension = self.persisted()
        self.assertEqual(
            self.entries(extension), [("complyroll.sarif", "10", "parse", INGESTED_AT)]
        )
        self.assertIn(
            "failed under the newer complyroll.sarif 10;",
            self.message(extension, "artifact_superseded_by_failure", reading),
        )

    def test_a_refusal_whose_rollback_fails_reports_only_the_store(self) -> None:
        # The run fails once its hold is appended, so only a finished rollback keeps the hold
        # out. A rollback that fails is the one ERROR: nothing names the failure that stopped
        # the run as if the store were unchanged.
        side, _ = self.superseded_parse_holder()

        with (
            self.refuse_after_the_hold() as holds,
            patch(
                "complyroll.store.sqlite._write_transaction._rollback",
                return_value=sqlite3.OperationalError("simulated rollback failure"),
            ),
        ):
            code, out, err = self.ingest_flagged(side)

        self.assertEqual(len(holds), 1)
        self.assertEqual(code, 1)
        self.assertEqual(out, "")
        errors = [line for line in err.splitlines() if line.startswith("error: ")]
        self.assertEqual(len(errors), 1, msg=err)
        self.assertTrue(
            errors[0].startswith("error: store_unavailable: could not roll back after ")
        )
        self.assertNotIn("history_invalid", err)

    def test_a_pure_failure_whose_rollback_fails_still_names_its_file(self) -> None:
        # The run fails once the pure failure's hold is appended, and its rollback fails too.
        # The store's error comes first, and the pure failure's own ERROR still follows it,
        # as on any run that exits 1 (ADR 0014).
        self.record_failed_reading(parser_version="0.1")
        self.record_reading(parser_name="complyroll.sarif", parser_version="0.2")

        with (
            self.refuse_after_the_hold() as holds,
            patch(
                "complyroll.store.sqlite._write_transaction._rollback",
                return_value=sqlite3.OperationalError("simulated rollback failure"),
            ),
        ):
            code, out, err = self.ingest_flagged(TRUNCATED_FIXTURE)

        self.assertEqual(len(holds), 1)
        self.assertEqual(code, 1)
        self.assertEqual(out, "")
        errors = [line for line in err.splitlines() if line.startswith("error: ")]
        self.assertEqual(len(errors), 2)
        self.assertTrue(
            errors[0].startswith("error: store_unavailable: could not roll back after ")
        )
        self.assertTrue(errors[1].startswith("error: artifact_parse_failed: "))
        self.assertTrue(errors[1].endswith("[failed-truncated.sarif]"))
        self.assertNotIn("detection_failure_recorded", err)

    def test_a_failure_an_earlier_build_left_out_is_recorded_as_a_hold_on_rerun(self) -> None:
        # Recovery for stores an earlier build wrote. A pure failure the refusal stopped left
        # the store as it was, and a side record whose holder a later ingest superseded left
        # its reading and no failure. Either way the writer finds no stream of the reading's
        # own, finds the holder, and records the hold, which carries (ADR 0014, amendment
        # 2026-10-13).
        def other(path: Path, *, ingested_at: datetime) -> IngestResult:
            return moved_reading(
                path, ingested_at=ingested_at, parser_name="complyroll.other", parser_version="1"
            )

        def clean(path: Path, *, ingested_at: datetime) -> IngestResult:
            return moved_reading(
                path,
                ingested_at=ingested_at,
                parser_name="complyroll.sarif",
                parser_version=SARIF_NEXT,
                clean=True,
            )

        with self.subTest("a pure failure the refusal stopped"):
            self.database = self.workspace / "pure.db"
            holder = self.record_failed_reading(parser_version="0.1")
            self.record_reading(parser_name="complyroll.sarif", parser_version="0.2")

            code, out, _ = self.ingest_flagged(TRUNCATED_FIXTURE)

            self.assertEqual(code, 3)
            self.assertEqual(
                out,
                f"failed-truncated.sarif: recorded detection failure (parse), held by {holder}\n",
            )
            self.assertEqual(
                self.entries(self.persisted()),
                [("complyroll.sarif", SARIF_PARSER_VERSION, "parse", INGESTED_AT)],
            )

        with self.subTest("a side record whose holder a later ingest superseded"):
            self.database = self.workspace / "side.db"
            self.assertEqual(self.ingest_flagged(INVOCATION_FIXTURE)[0], 3)
            ((_, holder),) = self.failure_streams()
            # What an earlier build left of the held side record: its reading, no failure.
            with patch.object(cli_module, "ingest_stig_artifact", other):
                self.succeeds(
                    [
                        "ingest",
                        str(INVOCATION_FIXTURE),
                        "--db",
                        str(self.database),
                        "--as-of",
                        INGESTED_AT,
                    ]
                )
            with patch.object(cli_module, "ingest_stig_artifact", clean):
                self.assertEqual(self.ingest_flagged(INVOCATION_FIXTURE, as_of=self.LATER)[0], 0)
            self.assertEqual(self.entries(self.persisted(as_of=self.LATER)), [])

            with patch.object(cli_module, "ingest_stig_artifact", other):
                code, out, err = self.ingest_flagged(INVOCATION_FIXTURE)

            self.assertEqual(code, 3)
            self.assertEqual(
                out.splitlines(),
                [
                    "failed-invocation.sarif: already_recorded",
                    "failed-invocation.sarif: recorded detection failure (execution), held by "
                    f"{holder}",
                ],
            )
            self.assertIn(
                self.held_warning(holder, "failed-invocation.sarif", under="complyroll.other 1"),
                err.splitlines(),
            )
            self.assertEqual(
                self.entries(self.persisted(as_of=self.LATER)),
                [("complyroll.other", "1", "execution", "2026-08-04T10:00:00Z")],
            )

    def test_a_pure_failure_an_earlier_build_lost_to_a_later_reading_is_refused(self) -> None:
        # The upgrade chain on a store an earlier build wrote: version 1 failed to parse the
        # log at T, version 2's pure execution failure at T met version 1's hold and left
        # nothing, and version 3 read the log with its failed invocation a day later. Version
        # 3's reading is current and outranks version 2, so re-ingesting version 2's failure
        # at T is refused before the writes, and that failure has no recording path.
        side = self.clockless_side_record()
        self.record_parse_failure(
            side,
            parser_name="complyroll.sarif",
            parser_version="1",
            at=datetime(2026, 8, 21, 12, tzinfo=UTC),
        )
        later = partial(moved_reading, parser_name="complyroll.sarif", parser_version="3")
        with patch.object(cli_module, "ingest_stig_artifact", later):
            self.assertEqual(self.ingest_flagged(side, as_of="2026-08-22T12:00:00Z")[0], 3)
        (reading,) = [
            record.stream_id
            for record in self.records()
            if record.event_type == "artifact.ingested"
        ]
        before = self.database.read_bytes()

        def pure_execution(path: Path, *, ingested_at: datetime) -> IngestResult:
            failed = moved_reading(
                path, ingested_at=ingested_at, parser_name="complyroll.sarif", parser_version="2"
            )
            error = IngestDiagnostic(
                level=DiagnosticLevel.ERROR, code="no_observations", message="no usable results"
            )
            return replace(failed, observations=(), diagnostics=(*failed.diagnostics, error))

        with patch.object(cli_module, "ingest_stig_artifact", pure_execution):
            code, out, err = self.ingest_flagged(side)

        self.assertEqual(code, 1)
        self.assertEqual(out, "")
        self.assertEqual(
            err.splitlines()[0],
            self.refusal(reading, "no-clock.sarif", under="complyroll.sarif 2"),
        )
        self.assertTrue(reading.endswith("/complyroll.sarif/3"))
        self.assertNotIn("failure_held_by_another_stream", err)
        self.assertEqual(self.database.read_bytes(), before)

    def test_a_hold_is_stored_exactly_when_its_run_warned(self) -> None:
        # Decision 15's fifth condition, read from the store for history written from the
        # amendment on: the digests with a `failure.held` stream are exactly the digests some
        # run warned `failure_held_by_another_stream` for (ADR 0014, amendment 2026-10-13).
        def newer(path: Path, *, ingested_at: datetime) -> IngestResult:
            return bumped(ingest_stig_artifact(path, ingested_at=ingested_at), SARIF_NEXT)

        digests = {
            Path(path).name: hashlib.sha256(Path(path).read_bytes()).hexdigest()
            for path in FAILED_ARTIFACTS
        }
        runs = (
            ("the golden failures", ingest_stig_artifact, FAILED_ARTIFACTS, INGESTED_AT, False),
            ("a newer parser, one instant", newer, (INVOCATION_FIXTURE,), INGESTED_AT, True),
            ("its rerun", newer, (INVOCATION_FIXTURE,), INGESTED_AT, True),
            ("a newer parser, another instant", newer, (TRUNCATED_FIXTURE,), self.LATER, False),
        )
        warned_for: set[str] = set()
        for label, reader, artifacts, as_of, warns in runs:
            with self.subTest(label):
                with patch.object(cli_module, "ingest_stig_artifact", reader):
                    code, _, err = self.ingest_flagged(*artifacts, as_of=as_of)

                self.assertEqual(code, 3, msg=err)
                named = {
                    line.rsplit(" ", 1)[1][1:-1]
                    for line in err.splitlines()
                    if line.startswith("warning: failure_held_by_another_stream: ")
                }
                self.assertEqual(bool(named), warns)
                warned_for |= {digests[name] for name in named}
                self.assertEqual(
                    {
                        stream_id.split("/")[1]
                        for head, stream_id in self.failure_streams()
                        if head == "failure.held"
                    },
                    warned_for,
                )
        self.assertEqual(warned_for, {digests[INVOCATION_FIXTURE.name]})

    def test_only_an_older_reading_by_the_same_parser_lets_a_failure_be_recorded(self) -> None:
        # The installed SARIF parser is version `SARIF_PARSER_VERSION`. A failure joins history
        # only to replace an older reading by it, which R2 then supersedes (ADR 0014).
        for parser_name, parser_version, expected in (
            ("complyroll.sarif", "0", 3),
            ("complyroll.sarif", SARIF_PARSER_VERSION, 1),
            ("complyroll.sarif", f"{SARIF_PARSER_VERSION}.0", 1),
            ("complyroll.sarif", SARIF_NEXT, 1),
            ("complyroll.other", "0", 1),
        ):
            with self.subTest(parser=parser_name, version=parser_version):
                self.database = self.workspace / f"{parser_name}-{parser_version}.db"
                reading = self.record_reading(
                    parser_name=parser_name, parser_version=parser_version
                )
                before = self.latest_sequence()

                code, out, err = self.ingest_flagged(TRUNCATED_FIXTURE)

                self.assertEqual(code, expected)
                if expected == 3:
                    self.assertEqual(
                        out, "failed-truncated.sarif: recorded detection failure (parse)\n"
                    )
                    report, _ = self.report()
                    diagnostics = json.loads(report)["x-complyroll"]["diagnostics"]
                    self.assertIn(
                        ("artifact_superseded_by_failure", reading),
                        [(item["code"], item.get("location")) for item in diagnostics],
                    )
                else:
                    self.assertEqual(out, "")
                    self.assertIn(self.refusal(reading, "failed-truncated.sarif"), err.splitlines())
                    self.assertEqual(self.latest_sequence(), before)

    def test_a_failure_the_fold_would_supersede_at_birth_is_refused(self) -> None:
        # R3 counts every reading of the digest, so a superseded one keeps a parse failure
        # out exactly as a current one does, whichever order the readings were recorded in.
        def cross_parser(first: str, second: str) -> Callable[[], str]:
            def record() -> str:
                streams = {
                    name: self.record_reading(parser_name=name, parser_version="0")
                    for name in (first, second)
                }
                return streams["other.sarif"]

            return record

        def r2_then_older_version() -> str:
            # The next version read the bytes and the one after failed on them, so R2 left no
            # reading current; the installed version failing is still superseded at birth by
            # the next version.
            reading = self.record_reading(parser_name="complyroll.sarif", parser_version=SARIF_NEXT)
            self.record_failed_reading(parser_version=SARIF_AFTER_NEXT)
            return reading

        for label, record in (
            ("another parser read them first", cross_parser("other.sarif", "complyroll.sarif")),
            ("another parser read them last", cross_parser("complyroll.sarif", "other.sarif")),
            ("an older version failing after R2", r2_then_older_version),
        ):
            with self.subTest(label):
                self.database = self.workspace / f"{label}.db"
                holder = record()
                before = self.latest_sequence()

                code, out, err = self.ingest_flagged(TRUNCATED_FIXTURE)

                self.assertEqual(code, 1)
                self.assertEqual(out, "")
                self.assertIn(self.refusal(holder, "failed-truncated.sarif"), err.splitlines())
                self.assertNotIn("detection_failure_recorded", err)
                self.assertEqual(self.latest_sequence(), before)

    def test_an_execution_failure_is_refused_exactly_as_before(self) -> None:
        # R4 lets no reading under another parser supersede an execution failure, so a
        # superseded one keeps nothing out, while a current one still refuses it.
        failed = self.held_execution_failure()

        self.database = self.workspace / "current.db"
        holder = self.record_reading(parser_name="other.sarif", parser_version="0", path=failed)
        before = self.latest_sequence()
        code, out, err = self.ingest_flagged(failed)
        self.assertEqual(code, 1)
        self.assertEqual(out, "")
        self.assertIn(self.refusal(holder, "failed-run.sarif"), err.splitlines())
        self.assertEqual(self.latest_sequence(), before)

        self.database = self.workspace / "superseded.db"
        for name in ("other.sarif", "complyroll.sarif"):
            self.record_reading(parser_name=name, parser_version="0", path=failed)
        code, out, err = self.ingest_flagged(failed)
        self.assertEqual(code, 3)
        self.assertEqual(out, "failed-run.sarif: recorded detection failure (execution)\n")
        self.assertNotIn("failure_read_elsewhere", err)

    def test_failed_readings_of_one_digest_are_recorded_under_the_lowest_name(self) -> None:
        for order in (("b", "a"), ("a", "b")):
            with self.subTest(order=order):
                self.database = self.workspace / f"{''.join(order)}.db"
                copies = [
                    self.copy_of(TRUNCATED_FIXTURE, f"{prefix}-truncated.sarif") for prefix in order
                ]

                code, out, _ = self.ingest_flagged(*copies)

                self.assertEqual(code, 3)
                self.assertEqual(
                    out.splitlines(),
                    [
                        "a-truncated.sarif: recorded detection failure (parse)",
                        "b-truncated.sarif: already_recorded",
                    ],
                )
                self.assertEqual(
                    [head["name"] for head in self.failure_heads()], ["a-truncated.sarif"]
                )

    def test_a_store_holding_failures_reports_them_and_exits_0(self) -> None:
        # The failures were signalled with 3 when they were recorded; a report over the
        # store is not a run that failed to read anything (ADR 0014).
        self.ingest_flagged(*PERSISTED_ARTIFACTS, *FAILED_ARTIFACTS)
        self.correlate()
        self.attest_missing()

        out, err = self.report()

        self.assertEqual(
            [item["name"] for item in json.loads(out)["x-complyroll"]["detectionFailures"]],
            [Path(path).name for path in FAILED_ARTIFACTS],
        )
        self.assertNotIn("error:", err)

    def test_a_driverless_failed_run_keeps_its_invocation_clock_on_both_paths(self) -> None:
        # Its invocations are read before the driver check, so the failure is an execution
        # failure at the invocation's start, not a content failure at the as-of (ADR 0014).
        started = "2026-08-04T10:00:00Z"
        log = self.workspace / "driverless.sarif"
        run_ = {
            "tool": {},
            "invocations": [{"executionSuccessful": False, "startTimeUtc": started}],
            "results": [],
        }
        log.write_text(json.dumps({"version": "2.1.0", "runs": [run_]}), encoding="utf-8")

        def assert_invocation_clock(output: Path) -> None:
            report = json.loads(output.read_text(encoding="utf-8"))
            self.assertEqual(
                [
                    (item["failureClass"], item["clock"], item["observedAt"])
                    for item in report["x-complyroll"]["detectionFailures"]
                ],
                [("execution", "invocation", started)],
            )
            self.assertEqual(
                [item["detection"]["detectedAt"] for item in report["vulnerabilities"]],
                [started],
            )

        with self.subTest(path="stateless"):
            stateless = self.workspace / "stateless.json"
            code, _, err = run(
                [
                    "report",
                    "vdt",
                    str(log),
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
                    "--record-failed-imports",
                    "-o",
                    str(stateless),
                ]
            )
            self.assertEqual(code, 3, msg=err)
            assert_invocation_clock(stateless)
        with self.subTest(path="persisted"):
            persisted = self.workspace / "persisted.json"
            code, _, err = self.ingest_flagged(log)
            self.assertEqual(code, 3, msg=err)
            self.correlate()
            self.report(output=persisted)
            assert_invocation_clock(persisted)

    def test_the_documented_sequence_reproduces_the_failed_goldens(self) -> None:
        code, _, _ = self.ingest_flagged(*PERSISTED_ARTIFACTS, *FAILED_ARTIFACTS)
        self.assertEqual(code, 3)

        out, _ = self.correlate()
        self.assertEqual(
            out,
            "created 10 case(s), linked 10 observation(s), "
            "skipped 0 already-linked observation(s)\n",
        )

        # A system record's detection time is its own instant, so the sweep leaves the
        # three system cases alone and attests only the fixtures' six.
        out, _ = self.attest_missing()
        self.assertEqual(
            out.splitlines()[0], "selected 6 case(s) with no source timestamp on any observation"
        )
        with SQLiteEventStore(self.database) as store:
            unattested = {
                case.source_type
                for case in fold_all_cases(EventRepository(store))
                if case.attestation is None
            }
        self.assertIn("complyroll.detection-process", unattested)

        self.evaluate(EXAMPLES / "evaluations-failed.json")
        for kind, golden in (("vdt", "vdt-failed"), ("historical", "historical-failed")):
            with self.subTest(report=kind):
                json_path = self.workspace / f"{kind}.json"
                markdown_path = self.workspace / f"{kind}.md"

                self.report(kind, output=json_path, markdown=markdown_path)

                self.assertEqual(
                    json_path.read_text(encoding="utf-8"),
                    (GOLDEN / f"{golden}.json").read_text(encoding="utf-8"),
                )
                self.assertEqual(
                    markdown_path.read_text(encoding="utf-8"),
                    (GOLDEN / f"{golden}.md").read_text(encoding="utf-8"),
                )


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
        with unguarded_stig_clocks():
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
        requires_schema: int = 1,
    ) -> int:
        """Append one event straight to the store, past the contract the repository holds.

        `EventRepository` is the only writer that checks a payload, its stream, and its
        metadata, so this is how history no writer would produce comes to exist: another
        tool, an older version, or a rule tightened after the event was written. Each
        argument defaults to something the audit has nothing to say about, so a test only
        has to spell the one fault it is about. `expected_version` is the version the
        stream is already at, which is zero for the unused streams above and the last
        stored version for a test that adds an event to a stream the fixtures wrote.
        `requires_schema` is the schema the store is marked forward to, as the repository
        marks it for a failure stream.
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
                requires_schema=requires_schema,
            )
        return appended[0].sequence

    def relabelled(self, payload: Mapping[str, Any], source_record_id: str) -> dict[str, Any]:
        """Return one stored observation as a different finding on the same artifact.

        Both the fingerprint and the identifier derive from the observation's fields, so
        moving the source record moves both: the result still names the artifact its
        stream names, and is not a repeat of anything the stream already holds. An
        overfull stream and a stream holding one observation twice are different faults.
        """

        moved = replace(Observation.from_canonical_dict(payload), source_record_id=source_record_id)
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

        moved = replace(Observation.from_canonical_dict(payload), source_artifact_digest=digest)
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

    def failed_reading(self, path: Path) -> tuple[str, dict[str, Any], dict[str, Any]]:
        """Return the stream id, head, and system observation one failed reading records.

        The writer records them into a scratch log, so each payload is exactly what history
        holds and a test smuggles them into the store with only its own fault added.
        """

        at = datetime(2026, 8, 21, 12, tzinfo=UTC)
        result = ingest_stig_artifact(path, ingested_at=at)
        classification = classify_ingest(result)
        assert classification is not None
        with SQLiteEventStore(":memory:") as store:
            outcome = record_failure(
                EventRepository(store),
                result,
                classification,
                metadata=EventMetadata(actor="smuggler", run_id=SMUGGLED_RUN_ID),
                ingested_at=at,
            )
            head, observation = store.read_stream(outcome.stream_id)
        return outcome.stream_id, dict(head.payload), dict(observation.payload)

    def smuggle_failure(
        self,
        stream_id: str,
        events: Sequence[tuple[str, dict[str, Any]]],
        *,
        requires_schema: int = FAILURE_STREAM_SCHEMA_VERSION,
    ) -> list[int]:
        """Append events to one new failure stream past the repository, in order."""

        return [
            self.smuggle(
                event_type,
                payload,
                stream_id=stream_id,
                expected_version=version,
                requires_schema=requires_schema,
            )
            for version, (event_type, payload) in enumerate(events)
        ]

    def test_a_failure_stream_in_a_store_left_at_schema_1_is_named_and_exits_one(self) -> None:
        # Both events are exactly what the writer records. Only the store's mark is wrong:
        # written past the repository, the stream never moved the store to schema 2, so a
        # build that predates failure streams would open this file and misread it.
        self.populate()
        stream_id, head, observation = self.failed_reading(TRUNCATED_FIXTURE)
        sequences = self.smuggle_failure(
            stream_id,
            [("failure.recorded", head), ("observation.recorded", observation)],
            requires_schema=1,
        )

        code, out, err = run(["store", "verify", "--db", str(self.database)])

        self.assertEqual(code, 1)
        self.assertEqual(out, "")
        self.assertIn(f"error: sequence {sequences[0]}: failure_schema_unmarked:", err)
        self.assertIn(stream_id, err)
        self.assertIn("faults: 1 domain fault(s) in", err)

    def test_a_failure_stream_holding_another_digests_record_is_named_and_exits_one(
        self,
    ) -> None:
        # The observation is a well-formed system record, of other bytes: rehydrated here
        # it would open a case for an artifact this stream never read.
        self.populate()
        stream_id, head, _ = self.failed_reading(TRUNCATED_FIXTURE)
        _, _, foreign = self.failed_reading(INVALID_RULES_FIXTURE)
        sequences = self.smuggle_failure(
            stream_id, [("failure.recorded", head), ("observation.recorded", foreign)]
        )

        code, out, err = run(["store", "verify", "--db", str(self.database)])

        self.assertEqual(code, 1)
        self.assertEqual(out, "")
        self.assertIn(f"error: sequence {sequences[1]}: failure_stream_mismatch:", err)
        self.assertIn("is not the system record", err)
        self.assertIn("faults: 1 domain fault(s) in", err)

    def test_an_error_diagnostic_in_a_failure_head_is_named_and_exits_one(self) -> None:
        # No writer stores an ERROR: `record_ingest` refuses one and a failure head carries
        # each one demoted. One planted in a head used to verify clean while every report
        # refused the store. The contract admits INFO and WARNING alone, so the audit and
        # the reports now name the same head for the same reason.
        self.populate()
        stream_id, head, observation = self.failed_reading(TRUNCATED_FIXTURE)
        head["diagnostics"] = [
            {**head["diagnostics"][0], "level": "error"},
            *head["diagnostics"][1:],
        ]
        sequences = self.smuggle_failure(
            stream_id, [("failure.recorded", head), ("observation.recorded", observation)]
        )

        code, out, err = run(["store", "verify", "--db", str(self.database)])
        report_code, report_out, report_err = self.report_from_history()

        self.assertEqual(code, 1)
        self.assertEqual(out, "")
        self.assertIn(f"error: sequence {sequences[0]}: payload_contract_invalid:", err)
        self.assertIn("/diagnostics/0/level: enum:", err)
        self.assertIn("faults: 1 domain fault(s) in", err)
        self.assertEqual(report_code, 1)
        self.assertEqual(report_out, "")
        self.assertIn(
            f"error: history_invalid: event {sequences[0]} is not a readable failure record: ",
            report_err,
        )
        self.assertIn("/diagnostics/0/level: enum:", report_err)

    def test_a_failure_stream_id_naming_no_digest_is_named_and_exits_one(self) -> None:
        # Each event's check parses the id before it reads the payload, so a malformed id
        # is a fault on every event of the stream rather than an exception out of the audit.
        self.populate()
        _, head, observation = self.failed_reading(TRUNCATED_FIXTURE)
        stream_id = f"failure/not-a-digest/complyroll.sarif/{SARIF_PARSER_VERSION}"
        sequences = self.smuggle_failure(
            stream_id, [("failure.recorded", head), ("observation.recorded", observation)]
        )

        code, out, err = run(["store", "verify", "--db", str(self.database)])

        self.assertEqual(code, 1)
        self.assertEqual(out, "")
        mismatches = [line for line in err.splitlines() if "failure_stream_mismatch" in line]
        self.assertEqual(
            [line.split(": failure_stream_mismatch:")[0] for line in mismatches],
            [f"error: sequence {sequence}" for sequence in sequences],
        )
        for line in mismatches:
            self.assertIn(f"stream {stream_id!r} names no failed reading", line)
        self.assertIn("faults: 2 domain fault(s) in", err)

    def test_a_malformed_failure_stream_holding_the_failure_refuses_the_ingest(self) -> None:
        # The holder of a failure is found by its digest's prefix alone, so a stream id with
        # too few or too many parts can hold the failure a newer parser derives. The store is
        # folded before a hold is written beneath it, so `ingest` refuses it as history and
        # appends nothing.
        self.populate()
        populated = self.database

        def read_by_the_next_version(path: Path, *, ingested_at: datetime) -> IngestResult:
            return bumped(ingest_stig_artifact(path, ingested_at=ingested_at), SARIF_NEXT)

        for fixture in (TRUNCATED_FIXTURE, INVOCATION_FIXTURE):
            _, head, observation = self.failed_reading(fixture)
            for parts, stream_id in (
                (2, f"failure/{head['sha256']}/{head['parserName']}"),
                (4, f"failure/{head['sha256']}/{head['parserName']}/{SARIF_PARSER_VERSION}/extra"),
            ):
                with self.subTest(fixture=fixture.name, parts=parts):
                    self.copy_store(populated, f"{fixture.stem}-{parts}.db")
                    self.smuggle_failure(
                        stream_id,
                        [("failure.recorded", head), ("observation.recorded", observation)],
                    )
                    before = self.latest_sequence()

                    with patch.object(cli_module, "ingest_stig_artifact", read_by_the_next_version):
                        code, out, err = run(
                            [
                                "ingest",
                                str(fixture),
                                "--record-failed-imports",
                                "--db",
                                str(self.database),
                                "--as-of",
                                INGESTED_AT,
                            ]
                        )

                    self.assertEqual(code, 1)
                    self.assertEqual(out, "")
                    self.assertIn("error: history_invalid:", err)
                    self.assertIn(f"stream {stream_id!r} names no failed reading", err)
                    self.assertEqual(self.latest_sequence(), before)

    def test_a_failure_stream_missing_its_observation_is_named_and_exits_one(self) -> None:
        self.populate()
        stream_id, head, _ = self.failed_reading(TRUNCATED_FIXTURE)
        sequences = self.smuggle_failure(stream_id, [("failure.recorded", head)])

        code, out, err = run(["store", "verify", "--db", str(self.database)])
        report_code, _, report_err = self.report_from_history()

        self.assertEqual(code, 1)
        self.assertEqual(out, "")
        self.assertIn(f"error: sequence {sequences[0]}: failure_incomplete:", err)
        self.assertIn("found 1 failure record(s) and 0 observation(s)", err)
        self.assertIn("faults: 1 domain fault(s) in", err)
        # The reader refuses what the audit names, rather than reporting half a failure.
        self.assertEqual(report_code, 1)
        self.assertIn("history_invalid", report_err)
        self.assertIn("is incomplete", report_err)

    def test_a_failure_stream_holding_only_its_observation_is_one_fault(self) -> None:
        # The observation opens a stream that holds no head. That stream is incomplete and
        # nothing more, so verify names one fault rather than calling it out of order too.
        self.populate()
        stream_id, _, observation = self.failed_reading(TRUNCATED_FIXTURE)
        sequences = self.smuggle_failure(stream_id, [("observation.recorded", observation)])

        code, out, err = run(["store", "verify", "--db", str(self.database)])

        self.assertEqual(code, 1)
        self.assertEqual(out, "")
        self.assertEqual(err.count("failure_incomplete:"), 1)
        self.assertIn(f"error: sequence {sequences[0]}: failure_incomplete:", err)
        self.assertIn("found 0 failure record(s) and 1 observation(s)", err)
        self.assertNotIn("failure_stream_mismatch", err)
        self.assertIn("faults: 1 domain fault(s) in", err)

    def test_a_failure_stream_with_a_second_head_is_named_and_exits_one(self) -> None:
        self.populate()
        stream_id, head, observation = self.failed_reading(TRUNCATED_FIXTURE)
        sequences = self.smuggle_failure(
            stream_id,
            [
                ("failure.recorded", head),
                ("observation.recorded", observation),
                ("failure.recorded", head),
            ],
        )

        code, out, err = run(["store", "verify", "--db", str(self.database)])
        report_code, _, report_err = self.report_from_history()

        self.assertEqual(code, 1)
        self.assertEqual(out, "")
        self.assertIn(f"error: sequence {sequences[0]}: failure_overfull:", err)
        self.assertIn("found 2 failure record(s) and 1 observation(s)", err)
        self.assertIn("faults: 1 domain fault(s) in", err)
        self.assertEqual(report_code, 1)
        self.assertIn("history_invalid", report_err)
        self.assertIn("is overfull", report_err)

    def test_one_system_record_held_by_two_failure_streams_is_named_and_exits_one(
        self,
    ) -> None:
        # Each stream is whole and names its own reading, so only the pair is wrong: the
        # system record's identity is the digest and the instant, never the parser, so the
        # second stream holding it rehydrates one failure twice. The copy's metadata names its
        # own stream's version, which the fingerprint does not cover.
        self.populate()
        stream_id, head, observation = self.failed_reading(TRUNCATED_FIXTURE)
        newer = f"{head['parserVersion']}.1"
        other = failure_stream_id(head["sha256"], head["parserName"], newer)
        copied = {
            **observation,
            "source_metadata": {**observation["source_metadata"], "artifact.parserVersion": newer},
        }
        self.smuggle_failure(
            stream_id, [("failure.recorded", head), ("observation.recorded", observation)]
        )
        sequences = self.smuggle_failure(
            other,
            [
                ("failure.recorded", {**head, "parserVersion": newer}),
                ("observation.recorded", copied),
            ],
        )

        code, out, err = run(["store", "verify", "--db", str(self.database)])
        report_code, _, report_err = self.report_from_history()

        self.assertEqual(code, 1)
        self.assertEqual(out, "")
        self.assertIn(f"error: sequence {sequences[1]}: failure_duplicate_observation:", err)
        self.assertIn(stream_id, err)
        self.assertIn(other, err)
        self.assertIn(str(observation["observation_id"]), err)
        self.assertIn("faults: 1 domain fault(s) in", err)
        self.assertEqual(report_code, 1)
        self.assertIn("history_invalid", report_err)
        self.assertIn(str(observation["observation_id"]), report_err)

    def test_a_hold_beneath_no_recorded_failure_is_named_and_exits_one(self) -> None:
        # A hold is written beneath the recorded failure that first holds its system record
        # (ADR 0014, amendment 2026-10-13). Smuggled in alone, at the schema a hold marks,
        # it holds the record first itself, so nothing is above it: the audit names it and
        # the reports refuse it, with the same words.
        self.populate()
        stream_id, head, observation = self.failed_reading(TRUNCATED_FIXTURE)
        sequences = self.smuggle_failure(
            stream_id,
            [("failure.held", head), ("observation.recorded", observation)],
            requires_schema=HELD_FAILURE_SCHEMA_VERSION,
        )
        orphaned = failure_hold_orphan_message(stream_id, observation["observation_id"], None)

        code, out, err = run(["store", "verify", "--db", str(self.database)])
        report_code, report_out, report_err = self.report_from_history()

        self.assertEqual(code, 1)
        self.assertEqual(out, "")
        self.assertIn(f"error: sequence {sequences[1]}: failure_hold_orphaned: {orphaned}\n", err)
        self.assertIn("faults: 1 domain fault(s) in", err)
        self.assertEqual(report_code, 1)
        self.assertEqual(report_out, "")
        self.assertIn(f"error: history_invalid: {orphaned}", report_err)

    def assert_one_failure_mismatch(self, sequence: int, expected: str) -> None:
        """Require `store verify` and `report vdt --db` to name one failure-stream fault."""

        code, out, err = run(["store", "verify", "--db", str(self.database)])
        report_code, report_out, report_err = self.report_from_history()

        self.assertEqual(code, 1)
        self.assertEqual(out, "")
        self.assertIn(f"error: sequence {sequence}: failure_stream_mismatch:", err)
        self.assertIn(expected, err)
        self.assertIn("faults: 1 domain fault(s) in", err)
        # The reader refuses what the audit names, rather than rendering it or crashing.
        self.assertEqual(report_code, 1)
        self.assertEqual(report_out, "")
        self.assertIn("history_invalid", report_err)
        self.assertIn(expected, report_err)

    def test_a_system_record_whose_metadata_its_writer_never_stores_is_named_and_exits_one(
        self,
    ) -> None:
        # The fingerprint covers none of a system record's metadata, so each copy below keeps
        # its derived id, and replay renders `detectionFailures` from that metadata. A store
        # holding one passed `store verify`, then the report named a parser, digest, or class
        # the failure never had, or crashed on a key that was not there.
        self.populate()
        populated = self.database
        stream_id, head, observation = self.failed_reading(TRUNCATED_FIXTURE)
        metadata = observation["source_metadata"]
        missing = {key: value for key, value in metadata.items() if key != "failure.class"}
        not_codes = (
            "its metadata failure.codes is {!r}, not the compact JSON array of sorted, distinct "
            "failure codes its writer stores"
        )
        for index, (label, changed, expected) in enumerate(
            (
                (
                    "another parser",
                    {**metadata, "artifact.parser": "complyroll.cklb"},
                    "its metadata artifact.parser is 'complyroll.cklb', where the stream names "
                    f"{head['parserName']!r}",
                ),
                (
                    "another version",
                    {**metadata, "artifact.parserVersion": "9"},
                    "its metadata artifact.parserVersion is '9', where the stream names "
                    f"{head['parserVersion']!r}",
                ),
                (
                    "another digest",
                    {**metadata, "artifact.sha256": "b" * 64},
                    f"its metadata artifact.sha256 is {'b' * 64!r}, where the stream names "
                    f"{head['sha256']!r}",
                ),
                (
                    "a class that is none",
                    {**metadata, "failure.class": "fatal"},
                    "its metadata failure.class is 'fatal', not a failure class",
                ),
                (
                    "codes that are not JSON",
                    {**metadata, "failure.codes": "artifact_parse_failed"},
                    not_codes.format("artifact_parse_failed"),
                ),
                (
                    "no codes",
                    {**metadata, "failure.codes": "[]"},
                    not_codes.format("[]"),
                ),
                (
                    "a code twice",
                    {**metadata, "failure.codes": '["no_observations","no_observations"]'},
                    not_codes.format('["no_observations","no_observations"]'),
                ),
                (
                    "codes the writer would spell without the padding",
                    {**metadata, "failure.codes": '[ "artifact_parse_failed" ]'},
                    not_codes.format('[ "artifact_parse_failed" ]'),
                ),
                (
                    "a clock that is none",
                    {**metadata, "failure.clock": "later"},
                    "its metadata failure.clock is 'later', not a failure clock",
                ),
                ("a missing key", missing, "its metadata has no 'failure.class'"),
            )
        ):
            with self.subTest(shape=label):
                self.copy_store(populated, f"metadata-{index}.db")
                damaged = {**observation, "source_metadata": changed}
                sequences = self.smuggle_failure(
                    stream_id,
                    [("failure.recorded", head), ("observation.recorded", damaged)],
                )

                self.assert_one_failure_mismatch(sequences[1], expected)

    def test_a_system_record_describing_another_failure_than_its_head_is_named_and_exits_one(
        self,
    ) -> None:
        # Each record below is well formed alone, so only reading both events catches it. The
        # head decides which failure supersedes which and the record is what the report
        # renders, so a store where they differ ranks one failure and reports another.
        self.populate()
        populated = self.database
        stream_id, head, observation = self.failed_reading(TRUNCATED_FIXTURE)
        self.assertEqual((head["failureClass"], head["clock"]), ("parse", "as-of"))
        metadata = observation["source_metadata"]
        for index, (label, edits, key, head_key) in enumerate(
            (
                # Each record keeps a class its own codes name, so only the head disagrees.
                (
                    "another class",
                    {"failure.class": "content", "failure.codes": '["no_observations"]'},
                    "failure.class",
                    "failureClass",
                ),
                (
                    "other codes",
                    {"failure.codes": '["artifact_parse_failed","no_observations"]'},
                    "failure.codes",
                    "failureCodes",
                ),
                ("another clock", {"failure.clock": "invocation"}, "failure.clock", "clock"),
                ("another name", {"artifact.name": "other.sarif"}, "artifact.name", "name"),
                ("another size", {"artifact.sizeBytes": "1"}, "artifact.sizeBytes", "sizeBytes"),
                (
                    "another media type",
                    {"artifact.mediaType": "text/plain"},
                    "artifact.mediaType",
                    "mediaType",
                ),
            )
        ):
            with self.subTest(shape=label):
                self.copy_store(populated, f"pair-{index}.db")
                value = edits[key]
                damaged = {**observation, "source_metadata": {**metadata, **edits}}
                sequences = self.smuggle_failure(
                    stream_id,
                    [("failure.recorded", head), ("observation.recorded", damaged)],
                )

                self.assert_one_failure_mismatch(
                    sequences[1],
                    f"failure stream {stream_id!r} records {head_key} {head[head_key]!r} in its "
                    f"failure.recorded and {key} {value!r} in its system record",
                )

    def test_a_system_record_carrying_what_its_builder_never_writes_is_named_and_exits_one(
        self,
    ) -> None:
        # The derived id is read from the stored fingerprint, so each copy below keeps it.
        # A record edited to `pass` used to verify clean and then drop out of
        # `detectionFailures`, the report printing one vulnerability fewer.
        self.populate()
        populated = self.database
        stream_id, head, observation = self.failed_reading(TRUNCATED_FIXTURE)
        evidence = f"sha256:{head['sha256']}"
        self.assertEqual(observation["evidence_ids"], [evidence])
        other = f"sha256:{'d' * 64}"
        for index, (field, value, expected) in enumerate(
            (
                ("disposition", "pass", "its disposition is 'pass'"),
                ("source_severity", "high", "its source severity is 'high'"),
                (
                    "source_identifiers",
                    ["CVE-2099-0001"],
                    "its source identifiers are ['CVE-2099-0001']",
                ),
                ("evidence_ids", [other], f"its evidence ids are [{other!r}]"),
                ("evidence_ids", [evidence, other], "its evidence ids are"),
                # The report prints the title as the vulnerability description.
                ("title", "FORGED FAILURE TITLE", "its title is 'FORGED FAILURE TITLE'"),
                ("description", "x", "its description is 'x'"),
            )
        ):
            with self.subTest(field=field, value=value):
                self.copy_store(populated, f"fixed-{index}.db")
                sequences = self.smuggle_failure(
                    stream_id,
                    [
                        ("failure.recorded", head),
                        ("observation.recorded", {**observation, field: value}),
                    ],
                )

                self.assert_one_failure_mismatch(sequences[1], expected)

    def test_a_failure_class_its_codes_do_not_name_is_named_and_exits_one(self) -> None:
        # The head and the record agree, so the disagreement check passes them, and the
        # class decides which reading supersedes which.
        self.populate()
        stream_id, head, observation = self.failed_reading(TRUNCATED_FIXTURE)
        self.assertEqual(
            (head["failureClass"], head["failureCodes"]), ("parse", ["artifact_parse_failed"])
        )
        forged = {**head, "failureClass": "content"}
        metadata = {**observation["source_metadata"], "failure.class": "content"}
        sequences = self.smuggle_failure(
            stream_id,
            [
                ("failure.recorded", forged),
                ("observation.recorded", {**observation, "source_metadata": metadata}),
            ],
        )

        self.assert_one_failure_mismatch(
            sequences[1],
            "its metadata failure.class is 'content', and its failure.codes "
            "'[\"artifact_parse_failed\"]' are those of class 'parse'",
        )

    def test_a_failure_stream_opened_by_its_observation_is_named_and_exits_one(self) -> None:
        # Both events are exactly what the writer records, in the wrong order: the writer
        # appends the head first, and the repository now refuses anything else at version 0.
        self.populate()
        stream_id, head, observation = self.failed_reading(TRUNCATED_FIXTURE)
        sequences = self.smuggle_failure(
            stream_id, [("observation.recorded", observation), ("failure.recorded", head)]
        )

        self.assert_one_failure_mismatch(
            sequences[0], f"failure stream {stream_id!r} does not open with its failure.recorded"
        )

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

    def test_a_disposition_with_no_evaluation_is_named_and_exits_one(self) -> None:
        # No case writer records one, but nothing refused it on the way in: `store verify`
        # passed it, `cases correlate` extended it, and only a report refused it.
        self.ingest_fixtures()
        self.correlate()
        self.attest_missing()
        stream_id = f"case/{WINDOWS_CASE}"
        with SQLiteEventStore(self.database) as store:
            version = len(store.read_stream(stream_id))
        sequence = self.smuggle(
            "case.disposition_recorded",
            {
                "status": "fully_mitigated",
                "closedDisposition": None,
                "acceptanceRationale": None,
                "recordedAt": INGESTED_AT,
            },
            stream_id=stream_id,
            expected_version=version,
        )
        message = (
            f"{WINDOWS_CASE} records disposition 'fully_mitigated' with no evaluation, so the "
            "disposition cannot be reported"
        )

        code, out, err = run(["store", "verify", "--db", str(self.database)])

        self.assertEqual((code, out), (1, ""))
        self.assertIn(
            f"error: sequence {sequence}: disposition_without_evaluation: {message}\n", err
        )
        self.assertIn("faults: 1 domain fault(s) in", err)
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
                "--as-of",
                INGESTED_AT,
            ]
        )
        self.assertEqual((code, out), (1, ""))
        self.assertIn(f"disposition_without_evaluation: {message}", err)

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

    def test_a_metadata_fault_beside_a_case_stream_naming_no_tracking_id_is_named(self) -> None:
        # A case stream whose id names no tracking id is a fault of its own, at its first
        # event, so the metadata fault is reported beside it rather than alone.
        self.populate()
        sequence = self.smuggle(
            "detection.attested",
            {
                "detectedAt": ATTESTED_AT,
                "rationale": RATIONALE,
                "attestedAt": "2026-08-21T12:00:00Z",
            },
            stream_id="case/not-a-valid-id",
            metadata={**SMUGGLED_METADATA, "runId": "run-not-a-uuid"},
        )

        code, out, err = run(["store", "verify", "--db", str(self.database)])

        self.assertEqual(code, 1)
        self.assertEqual(out, "")
        self.assertIn(f"error: sequence {sequence}: case_tracking_id_mismatch:", err)
        self.assertIn(f"error: sequence {sequence}: event_metadata_invalid:", err)
        self.assertIn("faults: 2 domain fault(s) in", err)

    def test_a_case_stream_naming_no_tracking_id_is_refused_by_every_reader(self) -> None:
        # Its id is `case/` and then no tracking id. No event on it is `case.created`, so
        # the placement check had nothing to say, and verify, `cases list`, a report,
        # `cases evaluate` and `cases attest-detection` each ended in a ValueError traceback
        # when they folded it.
        self.populate()
        stream_id = "case/not-a-valid-id"
        sequence = self.smuggle(
            "detection.attested",
            {
                "detectedAt": ATTESTED_AT,
                "rationale": RATIONALE,
                "attestedAt": "2026-08-21T12:00:00Z",
            },
            stream_id=stream_id,
        )
        second = self.smuggle(
            "detection.attested",
            {
                "detectedAt": ATTESTED_AT,
                "rationale": RATIONALE,
                "attestedAt": "2026-08-21T12:00:00Z",
            },
            stream_id=stream_id,
            expected_version=1,
        )
        named = (
            f"stream {stream_id!r} names no tracking id: tracking_id must match "
            "'case-<16 hex characters>', got 'not-a-valid-id'"
        )

        code, out, err = run(["store", "verify", "--db", str(self.database)])

        self.assertEqual((code, out), (1, ""))
        # One fault for the stream, at its first event, not one per event.
        self.assertIn(f"error: sequence {sequence}: case_tracking_id_mismatch: {named}\n", err)
        self.assertNotIn(f"sequence {second}:", err)
        self.assertIn("faults: 1 domain fault(s) in", err)
        refused = f"error: history_invalid: {named}\n"
        commands = {
            "cases list": ["cases", "list", "--db", str(self.database)],
            "cases evaluate": [
                "cases",
                "evaluate",
                "--db",
                str(self.database),
                "--evaluations",
                str(EXAMPLES / "evaluations.json"),
            ],
            "cases attest-detection": [
                "cases",
                "attest-detection",
                "--db",
                str(self.database),
                "--all-missing",
                "--detected-at",
                ATTESTED_AT,
                "--rationale",
                RATIONALE,
            ],
            "report vdt": [
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
            ],
        }
        before = self.latest_sequence()
        for label, argv in commands.items():
            with self.subTest(label):
                self.assertEqual(run(argv), (1, "", refused))
        self.assertEqual(self.latest_sequence(), before)

    def test_a_long_stored_value_is_quoted_within_the_bound(self) -> None:
        # CL-41, R1: on ed9fcf4 a 5155-character trackingId made `store verify` print 10,667
        # bytes, because the contract issue and the placement fault each quoted it whole.
        self.populate()
        long = "x" * 5155
        sequence = self.smuggle(
            "case.created",
            {
                "trackingId": long,
                "sourceType": "cklb",
                "sourceRecordId": "V-260470",
                "contextKey": "Canonical Ubuntu 24.04 LTS STIG",
                "title": "Inactive accounts are not disabled",
                "description": "Inactive accounts are not disabled on the shared host.",
                "createdAt": "2026-08-21T12:00:00Z",
            },
            stream_id=SMUGGLED_CASE_STREAM,
        )
        cut = f"'{long[:199]}... ({len(long) + 2} characters)"

        code, out, err = run(["store", "verify", "--db", str(self.database)])

        self.assertEqual((code, out), (1, ""))
        self.assertLessEqual(len(err.encode()), 1024, err[:300])
        for fault in ("case_tracking_id_mismatch", "payload_contract_invalid"):
            with self.subTest(fault=fault):
                prefix = f"error: sequence {sequence}: {fault}: "
                (line,) = [line for line in err.splitlines() if line.startswith(prefix)]
                self.assertIn(cut, line)
        self.assertIn(
            f"case.created records tracking id {cut} on stream {SMUGGLED_CASE_STREAM!r}", err
        )
        code, out, err = run(["cases", "list", "--db", str(self.database)])
        self.assertEqual(code, 1, err[:300])
        self.assertIn(cut, err)
        self.assertLessEqual(len(err.encode()), 1024, err[:300])

    def test_a_long_case_stream_id_is_quoted_within_the_bound(self) -> None:
        # The store holds a stream id to 500 characters, and the message quoted it twice.
        self.populate()
        stream_id = "case/" + "y" * 495
        self.smuggle(
            "detection.attested",
            {
                "detectedAt": ATTESTED_AT,
                "rationale": RATIONALE,
                "attestedAt": "2026-08-21T12:00:00Z",
            },
            stream_id=stream_id,
        )
        named = (
            f"stream '{stream_id[:199]}... (502 characters) names no tracking id: tracking_id "
            f"must match 'case-<16 hex characters>', got '{'y' * 199}... (497 characters)"
        )

        code, out, err = run(["store", "verify", "--db", str(self.database)])

        self.assertEqual((code, out), (1, ""))
        self.assertIn(f"case_tracking_id_mismatch: {named}\n", err)
        self.assertEqual(
            run(["cases", "list", "--db", str(self.database)]),
            (1, "", f"error: history_invalid: {named}\n"),
        )

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

    def test_a_text_sequence_is_reported_without_a_traceback(self) -> None:
        # On 298f1be the counter check passed the text to int() and the command ended in
        # a ValueError traceback.
        self.populate()
        retype_sequence_as_text(self.database)

        code, out, err = run(["store", "verify", "--db", str(self.database)])

        self.assertEqual(code, 1)
        self.assertEqual(out, "")
        self.assertIn(
            "error: schema_object_altered: table events does not match its expected definition",
            err,
        )
        self.assertIn("faults: 1 problem(s) in 0 verified event(s)", err)

    def test_an_events_table_missing_its_columns_is_reported_without_a_traceback(self) -> None:
        # On 298f1be the walk read `event_id` from a table rebuilt with `sequence` alone and
        # the command ended in an IndexError traceback.
        self.populate()
        with closing(sqlite3.connect(self.database, isolation_level=None)) as connection:
            connection.executescript(
                "DROP TABLE events; CREATE TABLE events (sequence INTEGER); "
                "INSERT INTO events VALUES (1);"
            )

        code, out, err = run(["store", "verify", "--db", str(self.database)])

        self.assertEqual(code, 1)
        self.assertEqual(out, "")
        self.assertIn(
            "error: schema_object_altered: table events does not match its expected definition",
            err,
        )
        self.assertIn("faults: 5 problem(s) in 0 verified event(s)", err)

    def test_a_migration_table_missing_its_version_column_keeps_its_schema_fault(self) -> None:
        # On 298f1be the migration check queried `version` on a table rebuilt without it, and
        # the store error that ended the command dropped the schema fault already found.
        self.populate()
        count = self.latest_sequence()
        with closing(sqlite3.connect(self.database, isolation_level=None)) as connection:
            connection.executescript(
                "DROP TABLE complyroll_schema_migrations; "
                "CREATE TABLE complyroll_schema_migrations (wrong INTEGER); "
                "INSERT INTO complyroll_schema_migrations VALUES (1);"
            )

        code, out, err = run(["store", "verify", "--db", str(self.database)])

        self.assertEqual(code, 1)
        self.assertEqual(out, "")
        self.assertNotIn("store_unavailable", err)
        self.assertIn(
            "error: schema_object_altered: table complyroll_schema_migrations does not match "
            "its expected definition",
            err,
        )
        self.assertIn(f"faults: 1 problem(s) in {count} verified event(s)", err)

    def test_a_second_sequence_counter_row_is_reported_and_refused(self) -> None:
        # On 298f1be a text row added after SQLite's own counter row passed `store verify`
        # and every command, because each check read only the first row.
        self.populate()
        count = self.latest_sequence()
        with closing(sqlite3.connect(self.database, isolation_level=None)) as connection:
            connection.execute("INSERT INTO sqlite_sequence (name, seq) VALUES ('events', 'x')")
        message = "the events sequence counter is stored in more than one row"

        code, out, err = run(["store", "verify", "--db", str(self.database)])

        self.assertEqual(code, 1)
        self.assertEqual(out, "")
        self.assertIn(f"error: sequence_counter_mismatch: sequence {count}: {message}", err)
        code, out, err = run(["cases", "list", "--db", str(self.database)])
        self.assertEqual(code, 1)
        self.assertEqual(out, "")
        self.assertIn(f"error: store_integrity: {message}", err)


class StoreRefusalCommandTests(PersistedStoreTestCase):
    """An append the store refuses for a reason other than history is a coded refusal."""

    def test_an_insert_a_planted_trigger_aborts_is_not_called_a_conflict(self) -> None:
        # CL-42: unknown schema objects are not refused, so `store verify` passes this file,
        # and the abort used to read "conflicts with committed history".
        self.ingest_fixtures()
        with closing(self.raw()) as connection:
            connection.execute(
                "CREATE TRIGGER planted BEFORE INSERT ON events BEGIN "
                "SELECT RAISE(ABORT, 'planted refusal'); END"
            )
        self.assertEqual(run(["store", "verify", "--db", str(self.database)])[0], 0)
        before = self.latest_sequence()

        code, out, err = run(["cases", "correlate", "--db", str(self.database)])

        self.assertEqual((code, out), (1, ""))
        self.assertRegex(
            err,
            r"^error: store_unavailable: the database refused event 'evt-[0-9a-f-]+': "
            r"'planted refusal'\n$",
        )
        self.assertEqual(self.latest_sequence(), before)

    def test_an_event_over_a_store_cap_is_a_coded_refusal_with_nothing_appended(self) -> None:
        # CL-47: the cap raised a bare ValueError, which `_persisted_run` did not catch.
        with patch("complyroll.store.sqlite.MAX_EVENT_JSON_BYTES", 256):
            code, out, err = run(
                [
                    "ingest",
                    str(FIXTURES / "windows-host.ckl"),
                    "--db",
                    str(self.database),
                    "--as-of",
                    INGESTED_AT,
                ]
            )

        self.assertEqual((code, out), (1, ""))
        # The reading's own WARNING lines come first; the refusal is the one error line.
        self.assertEqual(
            [line for line in err.splitlines() if line.startswith("error: ")],
            ["error: event_too_large: payload exceeds the 256-byte limit"],
        )
        self.assertFalse(self.database.exists())

    def test_an_evaluation_over_the_store_cap_is_a_coded_refusal(self) -> None:
        # The unpatched cap is reachable: an evaluations file may hold 8 MiB, and its rationale
        # is stored as given. On ed9fcf4 this ended `cases evaluate` in a ValueError traceback.
        self.ingest_fixtures()
        self.correlate()
        before = self.latest_sequence()
        payload = json.loads((EXAMPLES / "evaluations.json").read_text(encoding="utf-8"))
        payload["evaluations"] = payload["evaluations"][:1]
        payload["evaluations"][0]["rationale"] = "x" * MAX_EVENT_JSON_BYTES
        path = self.workspace / "evaluations-long.json"
        path.write_text(json.dumps(payload), encoding="utf-8")

        code, out, err = run(
            ["cases", "evaluate", "--db", str(self.database), "--evaluations", str(path)]
        )

        self.assertEqual((code, out), (1, ""))
        self.assertEqual(
            err, f"error: event_too_large: payload exceeds the {MAX_EVENT_JSON_BYTES}-byte limit\n"
        )
        self.assertEqual(self.latest_sequence(), before)


class ContentNeutralFaultCommandTests(PersistedStoreTestCase):
    """ADR 0008 amendment 2026-10-14 (second): the content-neutral faults `store verify` reports.

    Each shape is planted in a copy of one store and set against an untouched copy, its
    clean twin. `store verify` names the shape's faults at their sequence and exits 1, while
    `report vdt --db` writes the twin's bytes, `cases list` and `cases history` exit and
    print as on the twin, and the writers an operator runs after a rescan append events of
    the same types to the same streams, in the same order, as on the twin. Each writer
    stamps everything it appends with one run id, new to the store and to every other
    writer. A policy that made a reader or a case writer refuse one of these shapes has to
    change this test on purpose.
    """

    #: The rationale the revised attestation records, on the twin and the planted store alike.
    REVISED = "The rescan of a second host confirmed the 1 August assessment."

    def setUp(self) -> None:
        super().setUp()
        # The fixtures with one recorded failure, correlated and attested: a store every
        # report renders, holding artifact, failure and case streams.
        code, _out, err = run(
            [
                "ingest",
                *PERSISTED_ARTIFACTS,
                str(TRUNCATED_FIXTURE),
                "--record-failed-imports",
                "--db",
                str(self.database),
                "--as-of",
                INGESTED_AT,
            ]
        )
        self.assertEqual(code, 3, err)
        self.correlate()
        self.attest_missing()
        self.clean = self.database
        # The Windows checklist from a second host: `cases correlate` links it to the
        # Windows case, which the example evaluations match and the writers attest again.
        self.rescan = self.workspace / "windows-rescan.ckl"
        self.rescan.write_text(
            (FIXTURES / "windows-host.ckl")
            .read_text(encoding="utf-8")
            .replace("lab-win-01", "lab-win-02"),
            encoding="utf-8",
        )
        self.copy_store(self.clean, "twin.db")
        self.assertEqual(run(["store", "verify", "--db", str(self.database)])[0], 0)
        self.twin_outputs = self.outputs("twin")
        self.twin_cases = sorted(
            {
                record.stream_id.removeprefix("case/")
                for record in self.records()
                if record.stream_id.startswith("case/")
            }
        )
        self.assertIn(WINDOWS_CASE, self.twin_cases)
        self.twin_reads = self.case_reads()
        # Every read succeeds on the twin, so equal reads are never two refusals.
        self.assertEqual({code for code, _out in self.twin_reads.values()}, {0})
        self.twin_appended = self.appended()
        # Every writer has work to do, so equal appends are never two empty runs.
        self.assertNotIn([], self.twin_appended.values())

    def outputs(self, name: str) -> tuple[bytes, bytes]:
        """Write `report vdt --db` as JSON and Markdown and return both files' bytes."""

        output = self.workspace / f"{name}.json"
        markdown = self.workspace / f"{name}.md"
        self.report(output=output, markdown=markdown)
        return output.read_bytes(), markdown.read_bytes()

    def case_reads(self) -> dict[str, tuple[int, str]]:
        """Run `cases list`, then `cases history` for each case; return each status and stdout.

        Every case of the twin is read, which covers the case a shape damages and, for a
        shape on a non-case stream, a case of the store. No shape changes what these print:
        the key planted beside a case event's actor leaves the actor shown, and every
        misplaced event lands on a non-case stream, so the reads equal the twin's in full.
        """

        reads = {"cases list": run(["cases", "list", "--db", str(self.database)])[:2]}
        for tracking_id in self.twin_cases:
            argv = ["cases", "history", tracking_id, "--db", str(self.database)]
            reads[f"cases history {tracking_id}"] = run(argv)[:2]
        return reads

    def appended(self) -> dict[str, list[tuple[str, str]]]:
        """Ingest the rescan, then run each case writer; return what each command appended.

        Each command maps to the type and stream of every event it appended, in log order.
        Every event one command appends carries one run id, which no event stored before the
        command carries, planted events included, and which no other command reuses.
        """

        steps: dict[str, Callable[[], object]] = {
            "ingest": lambda: self.succeeds(
                ["ingest", str(self.rescan), "--db", str(self.database), "--as-of", INGESTED_AT]
            ),
            "cases correlate": self.correlate,
            "cases evaluate": self.evaluate,
            "cases attest-detection --case": lambda: self.attest_case(
                WINDOWS_CASE, rationale=self.REVISED
            ),
        }
        appended: dict[str, list[tuple[str, str]]] = {}
        run_ids: dict[str, str] = {}
        for command, step in steps.items():
            before = self.latest_sequence()
            step()
            with closing(self.raw()) as connection:
                rows = connection.execute(
                    "SELECT sequence, event_type, stream_id, metadata_json FROM events "
                    "ORDER BY sequence"
                ).fetchall()
            stored = {
                json.loads(row["metadata_json"]).get("runId")
                for row in rows
                if row["sequence"] <= before
            }
            added = [row for row in rows if row["sequence"] > before]
            appended[command] = [(row["event_type"], row["stream_id"]) for row in added]
            stamped = {json.loads(row["metadata_json"]).get("runId") for row in added}
            self.assertEqual(len(stamped), 1, msg=f"{command} stamped {stamped}")
            (run_id,) = stamped
            self.assertIsInstance(run_id, str, msg=command)
            self.assertNotIn(run_id, stored, msg=f"{command} reused a stored run id")
            run_ids[command] = run_id
        self.assertEqual(len(set(run_ids.values())), len(steps), msg=run_ids)
        return appended

    def verify_faults(self) -> list[tuple[int, str]]:
        """Require `store verify` to exit 1 and return each fault's sequence and code."""

        code, out, err = run(["store", "verify", "--db", str(self.database)])
        self.assertEqual((code, out), (1, ""), msg=err)
        faults: list[tuple[int, str]] = []
        for line in err.splitlines():
            if line.startswith("error: sequence "):
                where, fault, _message = line.removeprefix("error: ").split(": ", 2)
                faults.append((int(where.removeprefix("sequence ")), fault))
        self.assertIn(f"faults: {len(faults)} domain fault(s) in", err)
        return faults

    def assert_content_neutral(self, name: str, plant: Callable[[], list[tuple[int, str]]]) -> None:
        """Plant one shape in a fresh copy and hold every command but `store verify` to the twin."""

        self.copy_store(self.clean, f"{name}.db")
        expected = plant()

        self.assertEqual(self.verify_faults(), expected)
        self.assertEqual(self.outputs(name), self.twin_outputs)
        # Read before the writers run, which extend the case histories.
        self.assertEqual(self.case_reads(), self.twin_reads)
        self.assertEqual(self.appended(), self.twin_appended)

    def mark_schema_by_hand(self, marker: int) -> None:
        """Leave the store marked `marker`, with exactly the migration records it needs.

        The records above it go too: a marker lowered below a stored record is a store fault
        of its own (`migration_unexpected`), and these shapes are a stream the marker does
        not account for, not a marker its own records contradict.
        """

        with closing(self.raw()) as connection:
            connection.execute(
                "DELETE FROM complyroll_schema_migrations WHERE version > ?", (marker,)
            )
            connection.execute(f"PRAGMA user_version = {int(marker)}")

    def record(self, event_type: str, stream_id: str | None = None) -> EventRecord:
        """Return the first event of a type in the log, on one stream if one is named."""

        return next(
            record
            for record in self.records()
            if record.event_type == event_type and stream_id in (None, record.stream_id)
        )

    def add_metadata_key(
        self, event_type: str, stream_id: str | None = None
    ) -> list[tuple[int, str]]:
        """Store a key the rules do not know in one event's metadata, which no digest covers."""

        record = self.record(event_type, stream_id)

        def work(connection: sqlite3.Connection) -> None:
            (stored,) = connection.execute(
                "SELECT metadata_json FROM events WHERE sequence = ?", (record.sequence,)
            ).fetchone()
            connection.execute(
                "UPDATE events SET metadata_json = ? WHERE sequence = ?",
                (self.canonical({**json.loads(stored), "planted": "x"}), record.sequence),
            )

        self.update(work)
        return [(record.sequence, "event_metadata_invalid")]

    def misplace(
        self, stream_id: str, event_type: str, payload: Mapping[str, Any], codes: Sequence[str]
    ) -> list[tuple[int, str]]:
        """Append one event past the repository in an envelope the rules accept.

        Returns `codes` at the appended event's sequence, the faults it alone causes.
        """

        with SQLiteEventStore(self.database) as store:
            (appended,) = store.append(
                stream_id,
                [
                    NewEvent(
                        event_type=event_type,
                        occurred_at=datetime(2026, 8, 21, 12, 0, tzinfo=UTC),
                        payload=dict(payload),
                        metadata=dict(SMUGGLED_METADATA),
                    )
                ],
                expected_version=len(store.read_stream(stream_id)),
            )
        return [(appended.sequence, code) for code in codes]

    def test_a_metadata_envelope_outside_the_rules_changes_no_report_and_no_writer(
        self,
    ) -> None:
        events = {
            "on the case the writers extend": ("case.created", f"case/{WINDOWS_CASE}"),
            "on an artifact record": ("artifact.ingested", None),
            "on an observation": ("observation.recorded", None),
        }
        for index, (label, (event_type, stream_id)) in enumerate(events.items()):
            with self.subTest(label):
                self.assert_content_neutral(
                    f"metadata-{index}", partial(self.add_metadata_key, event_type, stream_id)
                )

    def test_an_event_on_a_non_case_stream_it_does_not_belong_on_changes_nothing_else(
        self,
    ) -> None:
        artifact = self.record("artifact.ingested")
        failure = self.record("failure.recorded")
        link = self.record("case.observation_linked", f"case/{WINDOWS_CASE}")
        shapes: dict[str, tuple[str, str, Mapping[str, Any], tuple[str, ...]]] = {
            "a case event on an artifact stream": (
                artifact.stream_id,
                link.event_type,
                link.payload,
                ("event_stream_mismatch",),
            ),
            "an invalid case event on an artifact stream": (
                artifact.stream_id,
                link.event_type,
                {**link.payload, "planted": "x"},
                ("event_stream_mismatch", "payload_contract_invalid"),
            ),
            "an unpublished type on a stream of no kind": (
                "misc/x",
                "probe.planted",
                {},
                ("event_stream_mismatch", "payload_contract_invalid"),
            ),
            "an artifact record on a failure stream": (
                failure.stream_id,
                artifact.event_type,
                artifact.payload,
                ("artifact_incomplete", "event_stream_mismatch"),
            ),
        }
        for index, (label, (stream_id, event_type, payload, codes)) in enumerate(shapes.items()):
            with self.subTest(label):
                self.assert_content_neutral(
                    f"misplaced-{index}",
                    partial(self.misplace, stream_id, event_type, payload, codes),
                )

    def test_a_failure_schema_marker_left_low_changes_no_report_and_no_writer(self) -> None:
        failure = self.record("failure.recorded")

        def plant() -> list[tuple[int, str]]:
            self.mark_schema_by_hand(1)
            return [(failure.sequence, "failure_schema_unmarked")]

        self.assert_content_neutral("schema", plant)

    def test_a_failure_schema_marker_left_low_does_not_hide_an_evaluation_order_inversion(
        self,
    ) -> None:
        # The order check runs beside this fault as beside an envelope outside the rules,
        # so a marker left low does not hide an inversion for good.
        self.copy_store(self.clean, "schema-order.db")
        self.evaluate()
        failure = self.record("failure.recorded")
        evaluated = self.record("case.evaluated")
        with SQLiteEventStore(self.database) as store:
            (inverted,) = store.append(
                evaluated.stream_id,
                [
                    NewEvent(
                        event_type=evaluated.event_type,
                        occurred_at=evaluated.occurred_at,
                        payload={**evaluated.payload, "completedAt": "2020-01-01T00:00:00Z"},
                        metadata=dict(evaluated.metadata),
                    )
                ],
                expected_version=len(store.read_stream(evaluated.stream_id)),
            )
        self.mark_schema_by_hand(1)

        self.assertEqual(
            self.verify_faults(),
            [
                (failure.sequence, "failure_schema_unmarked"),
                (inverted.sequence, "evaluation_before_detection"),
            ],
        )

    def test_a_coverage_schema_marker_left_low_changes_no_report_and_no_writer(self) -> None:
        # The twin holds the same coverage streams: the fold reads them, so a stream planted
        # in one copy alone would change the report (ADR 0015, PR 3 step 4 finding 5).
        self.copy_store(self.clean, "coverage-clean.db")
        code, _out, err = run(
            [
                "cases",
                "coverage",
                "--db",
                str(self.database),
                "--class",
                "C",
                "--as-of",
                INGESTED_AT,
                "--inventory",
                str(EXAMPLE_INVENTORY),
            ]
        )
        self.assertEqual(code, 3, err)
        self.clean = self.database
        coverage = self.record("coverage.recorded")
        self.copy_store(self.clean, "coverage-twin.db")
        self.twin_outputs = self.outputs("coverage-twin")
        self.twin_reads = self.case_reads()
        self.twin_appended = self.appended()

        def plant() -> list[tuple[int, str]]:
            self.mark_schema_by_hand(3)
            return [(coverage.sequence, "coverage_schema_unmarked")]

        self.assert_content_neutral("coverage-schema", plant)


class ReportSourceConflictTests(unittest.TestCase):
    """Every `report` command takes a store or stateless inputs, never both, never neither.

    The three commands share one runner, so each refusal is checked on all of them, and
    the message has to name the command the operator ran rather than `vdt` every time.
    """

    OPTIONS = ("--class", "C", "--package-uri", "https://example.test/cpo")
    PERIOD = ("--from", "2026-08-01T00:00:00Z", "--to", "2026-08-31T23:59:59Z")
    #: Each command with the options it requires; `historical` takes no period.
    COMMANDS = (
        ("vdt", OPTIONS + PERIOD),
        ("avi", OPTIONS + PERIOD),
        ("historical", OPTIONS),
    )

    def refuses(self, command: str, argv: Sequence[str], message: str) -> None:
        code, out, err = run(["report", command, *argv])

        self.assertEqual(code, 1)
        self.assertEqual(out, "")
        self.assertIn(f"error: invalid_option: report {command} {message}", err)

    def test_a_store_and_artifacts_together_are_refused(self) -> None:
        for command, base in self.COMMANDS:
            with self.subTest(command=command):
                self.refuses(
                    command,
                    [str(FIXTURES / "windows-host.ckl"), "--db", "history.db", *base],
                    "takes either --db or artifacts, never both",
                )

    def test_a_store_and_an_evaluations_file_together_are_refused(self) -> None:
        for command, base in self.COMMANDS:
            with self.subTest(command=command):
                self.refuses(
                    command,
                    ["--db", "history.db", "--evaluations", str(ACCEPTED_EVALUATIONS), *base],
                    "takes either --db or --evaluations, never both",
                )

    def test_a_store_and_a_detection_time_together_are_refused(self) -> None:
        for command, base in self.COMMANDS:
            with self.subTest(command=command):
                self.refuses(
                    command,
                    ["--db", "history.db", "--detected-at", "2026-08-01T00:00:00Z", *base],
                    "takes either --db or --detected-at, never both",
                )

    def test_a_store_and_recorded_failed_imports_together_are_refused(self) -> None:
        # A store already recorded or refused each failure when `ingest` read it.
        for command, base in self.COMMANDS:
            with self.subTest(command=command):
                self.refuses(
                    command,
                    ["--db", "history.db", "--record-failed-imports", *base],
                    "takes either --db or --record-failed-imports, never both",
                )

    def test_neither_a_store_nor_an_artifact_is_refused(self) -> None:
        for command, base in self.COMMANDS:
            with self.subTest(command=command):
                self.refuses(command, base, "needs at least one artifact, or --db")


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
        # operator holding one had no way to know the command would read it. SARIF joined
        # the list with ADR 0011 and HDF with ADR 0013.
        for argv in (
            ["ingest"],
            ["report", "vdt"],
            ["report", "avi"],
            ["report", "historical"],
        ):
            with self.subTest(command=" ".join(argv)):
                text = help_text(argv)

                self.assertIn("ARF", text)
                self.assertIn("SARIF", text)
                self.assertIn("HDF", text)
                self.assertIn("CycloneDX", text)
                self.assertIn("CKLB, CKL, XCCDF, ARF, SARIF, HDF, or CycloneDX file", text)

    def test_the_report_listing_names_every_command_with_its_rule(self) -> None:
        text = unwrapped_help_text(["report"])

        self.assertIn("vdt compile a Vulnerability Detail Report (VER-RPT-VDT)", text)
        self.assertIn(
            "avi compile an Accepted Vulnerability Information report (VER-RPT-AVI)", text
        )
        self.assertIn("historical compile a Historical VER Activity snapshot (VER-TFR-MRH)", text)

    def test_every_report_command_offers_the_kev_catalog_flag(self) -> None:
        # That the feed is read from disk and never fetched belongs in the help text:
        # an operator who expected the command to download it would otherwise read a
        # stale report as a current one.
        for kind in ("vdt", "avi", "historical"):
            with self.subTest(command=kind):
                text = help_text(["report", kind])

                self.assertIn("--kev FILE", text)
                self.assertIn(
                    "CISA KEV catalog JSON feed to apply (read locally, never fetched)", text
                )

    def test_every_report_command_states_what_recording_a_failure_does(self) -> None:
        # The exit status is part of the promise: a pipeline that treats any nonzero
        # status as a refusal has to learn from the help text that 3 wrote a report.
        for kind in ("vdt", "avi", "historical"):
            with self.subTest(command=kind):
                text = unwrapped_help_text(["report", kind])

                self.assertIn(
                    "--record-failed-imports record a detection process failure "
                    "(VDR-CSO-FAV) as a system observation instead of stopping; exits 3 "
                    "when one is recorded",
                    text,
                )

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
                [
                    "report",
                    "avi",
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
                [
                    "report",
                    "historical",
                    "--db",
                    str(database),
                    "--class",
                    "C",
                    "--package-uri",
                    "https://example.test/cpo",
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


class StoredValueRefusalCommandTests(PersistedStoreTestCase):
    """H3: each command in `readers` refuses a planted stored value with one coded line.

    Append writes none of these rows, so each is planted with raw SQL. setUp ingests with one
    recorded failure, correlates and attests, so an unmodified store renders all three reports.
    In `assert_refused` each reader exits 1 with exactly one `error: store_integrity:` line,
    appends no event, leaves the pre-seeded report outputs unchanged, and prints no traceback
    and no line longer than LINE_BOUND bytes; `store verify` then exits 1 with the codes named
    and no traceback. `cases history` reads only its case's stream, so it joins only the
    refusals at open. On 298f1be most of these values ended a reader in a traceback or echoed
    a 5000-character name; D reads clean there on 3.14.
    """

    LINE_BOUND = 1024
    LONG = 5000
    SEED = b"pre-seeded output\n"
    REPORTS = ("vdt", "avi", "historical")

    def setUp(self) -> None:
        super().setUp()
        # The J cases are sized against the default digit limit, not whatever
        # PYTHONINTMAXSTRDIGITS set for this process.
        self.addCleanup(sys.set_int_max_str_digits, sys.get_int_max_str_digits())
        sys.set_int_max_str_digits(sys.int_info.default_max_str_digits)
        code, _out, err = run(
            [
                "ingest",
                str(FIXTURES / "windows-host.ckl"),
                str(TRUNCATED_FIXTURE),
                "--record-failed-imports",
                "--db",
                str(self.database),
                "--as-of",
                INGESTED_AT,
            ]
        )
        self.assertEqual(code, 3, err)
        # Correlated and attested, an unmodified store renders all three reports, so a
        # report leg reaches its output stage rather than stopping at detection_time_missing.
        self.correlate()
        self.attest_missing()
        # The failed-run example evaluations without the Ubuntu entry match this store's two
        # cases, so `cases evaluate` has work to append and reads the store to find it.
        payload = json.loads((EXAMPLES / "evaluations-failed.json").read_text(encoding="utf-8"))
        payload["evaluations"] = [
            entry for entry in payload["evaluations"] if entry["match"]["sourceType"] != "cklb"
        ]
        self.evaluations = self.workspace / "evaluations-windows.json"
        self.evaluations.write_text(json.dumps(payload), encoding="utf-8")

    @staticmethod
    def digest(text: str) -> str:
        return hashlib.sha256(text.encode("utf-8")).hexdigest()

    def insert(self, **overrides: object) -> None:
        """INSERT one row after the last; no trigger guards INSERT."""

        with closing(self.raw()) as connection:
            first = connection.execute("SELECT * FROM events ORDER BY sequence LIMIT 1").fetchone()
            values: dict[str, object] = {
                "event_id": "evt-planted",
                "stream_id": "probe/planted",
                "stream_version": 1,
                "event_type": "probe.planted",
                "event_version": 1,
                "occurred_at": first["occurred_at"],
                "recorded_at": first["recorded_at"],
                "payload_json": "{}",
                "metadata_json": "{}",
                "payload_sha256": self.digest("{}"),
            }
            values.update(overrides)
            columns = ", ".join(values)
            marks = ", ".join("?" for _ in values)
            connection.execute(
                f"INSERT INTO events ({columns}) VALUES ({marks})", tuple(values.values())
            )

    def retarget_failure(self, *, digits: int = 0, total: int = 0) -> None:
        """Move the one failure stream to a long version: stream id, payloads, digests."""

        def work(connection: sqlite3.Connection) -> None:
            rows = connection.execute(
                "SELECT * FROM events WHERE stream_id LIKE 'failure/%' ORDER BY sequence"
            ).fetchall()
            target = rows[0]["stream_id"]
            head = target.rsplit("/", 1)[0] + "/"
            version = "1" * (digits or total - len(head))
            for row in rows:
                payload = json.loads(row["payload_json"])
                if row["event_type"] == "failure.recorded":
                    payload["parserVersion"] = version
                else:
                    payload["source_metadata"]["artifact.parserVersion"] = version
                text = self.canonical(payload)
                connection.execute(
                    "UPDATE events SET stream_id = ?, payload_json = ?, payload_sha256 = ? "
                    "WHERE sequence = ?",
                    (head + version, text, self.digest(text), row["sequence"]),
                )

        self.update(work)

    def output(self, kind: str) -> Path:
        return self.workspace / f"{kind}.json"

    def report_reader(self, kind: str) -> list[str]:
        argv = [
            "report",
            kind,
            "--class",
            "C",
            "--package-uri",
            "https://example.test/cpo",
        ]
        if kind != "historical":
            argv += ["--from", "2026-08-01T00:00:00Z", "--to", "2026-08-31T23:59:59Z"]
        return argv + [
            "--as-of",
            INGESTED_AT,
            "--db",
            str(self.database),
            "-o",
            str(self.output(kind)),
        ]

    def readers(self, *, at_open: bool) -> dict[str, list[str]]:
        """The commands under test; `plain ingest` and `cases history` join only at open."""

        database = str(self.database)
        commands = {f"report {kind}": self.report_reader(kind) for kind in self.REPORTS}
        commands |= {
            "cases correlate": ["cases", "correlate", "--db", database],
            "cases list": ["cases", "list", "--db", database],
            "cases evaluate": [
                "cases",
                "evaluate",
                "--db",
                database,
                "--evaluations",
                str(self.evaluations),
            ],
            "cases attest-detection": [
                "cases",
                "attest-detection",
                "--db",
                database,
                "--all-missing",
                "--detected-at",
                ATTESTED_AT,
                "--rationale",
                RATIONALE,
            ],
            "flagged ingest": [
                "ingest",
                str(TRUNCATED_FIXTURE),
                "--record-failed-imports",
                "--db",
                database,
                "--as-of",
                INGESTED_AT,
            ],
        }
        if at_open:
            commands["plain ingest"] = [
                "ingest",
                str(FIXTURES / "semgrep-code.sarif"),
                "--db",
                database,
                "--as-of",
                INGESTED_AT,
            ]
            commands["cases history"] = ["cases", "history", WINDOWS_CASE, "--db", database]
        return commands

    def latest_sequence(self) -> int:
        with closing(self.raw()) as connection:
            return int(connection.execute("SELECT MAX(sequence) FROM events").fetchone()[0])

    def assert_bounded(self, out: str, err: str) -> None:
        for line in out.splitlines() + err.splitlines():
            self.assertLessEqual(len(line.encode()), self.LINE_BOUND, line[:200])

    def assert_refused(
        self, fragment: str, verify_codes: set[str], *, at_open: bool = False
    ) -> None:
        before = self.latest_sequence()
        for kind in self.REPORTS:
            self.output(kind).write_bytes(self.SEED)
        for name, argv in self.readers(at_open=at_open).items():
            with self.subTest(command=name):
                code, out, err = run(argv)
                self.assertEqual(code, 1, err[:500])
                # The ingests also print the truncated fixture's own diagnostics, so the
                # refusal is counted by its prefix rather than by the lines on stderr.
                refusals = [
                    line for line in err.splitlines() if line.startswith("error: store_integrity: ")
                ]
                self.assertEqual(len(refusals), 1, err[:500])
                self.assertIn(fragment, refusals[0])
                self.assert_bounded(out, err)
                for kind in self.REPORTS:
                    self.assertEqual(self.output(kind).read_bytes(), self.SEED, kind)
        self.assertEqual(self.latest_sequence(), before)
        code, out, err = run(["store", "verify", "--db", str(self.database)])
        self.assertEqual(code, 1, err[:500])
        self.assert_bounded(out, err)
        reported = {
            line.split(": ")[1]
            for line in out.splitlines() + err.splitlines()
            if line.startswith("error: ")
        }
        self.assertLessEqual(verify_codes, reported, err[:500])

    # h3-v2: the parser-version route.

    def test_a_failure_stream_past_the_name_cap_is_refused(self) -> None:
        for digits in (self.LONG, 4300):
            with self.subTest(digits=digits):
                self.database.unlink()
                self.setUp()
                self.retarget_failure(digits=digits)
                self.assert_refused("has an unreadable stream_id", {"event_name_invalid"})

    def test_a_head_only_artifact_stream_past_the_name_cap_is_refused(self) -> None:
        with closing(self.raw()) as connection:
            row = connection.execute(
                "SELECT * FROM events WHERE event_type = 'artifact.ingested' "
                "ORDER BY sequence LIMIT 1"
            ).fetchone()
            payload = json.loads(row["payload_json"])
            payload.update(sha256="c" * 64, observationCount=0, parserVersion="1" * self.LONG)
            text = self.canonical(payload)
        self.insert(
            event_id="evt-smuggled-artifact",
            stream_id=f"artifact/{'c' * 64}/{payload['parserName']}/{'1' * self.LONG}",
            event_type="artifact.ingested",
            payload_json=text,
            payload_sha256=self.digest(text),
            metadata_json=row["metadata_json"],
        )
        self.assert_refused("has an unreadable stream_id", {"event_name_invalid"})

    def test_a_failure_stream_at_the_name_cap_reads_clean(self) -> None:
        self.retarget_failure(total=500)
        code, out, err = run(self.report_reader("vdt"))
        self.assertEqual(code, 0, err[:500])
        self.assertNotIn("store_integrity", err)
        self.assertTrue(self.output("vdt").is_file())
        code, out, err = run(["store", "verify", "--db", str(self.database)])
        self.assertEqual(code, 0, out + err)

    # J: integer literals and nesting in stored JSON.

    def test_j1_a_payload_integer_past_the_digit_limit_is_refused(self) -> None:
        def work(connection: sqlite3.Connection) -> None:
            row = connection.execute(
                "SELECT sequence, payload_json FROM events WHERE event_type = 'failure.recorded'"
            ).fetchone()
            text = row["payload_json"]
            start = text.index('"sizeBytes":') + len('"sizeBytes":')
            end = start
            while text[end].isdigit():
                end += 1
            text = text[:start] + "1" * self.LONG + text[end:]
            connection.execute(
                "UPDATE events SET payload_json = ?, payload_sha256 = ? WHERE sequence = ?",
                (text, self.digest(text), row["sequence"]),
            )

        self.update(work)
        self.assert_refused("contains JSON past the decoder's limits", {"payload_not_json"})

    def test_j2_a_metadata_integer_past_the_digit_limit_is_refused(self) -> None:
        text = '{"n":' + "1" * self.LONG + "}"
        for how in ("update", "insert"):
            with self.subTest(how=how):
                self.database.unlink()
                self.setUp()
                if how == "update":
                    self.update(
                        lambda connection: connection.execute(
                            "UPDATE events SET metadata_json = ? WHERE sequence = 1", (text,)
                        )
                    )
                else:
                    self.insert(metadata_json=text)
                self.assert_refused("contains JSON past the decoder's limits", {"payload_not_json"})

    def test_j3_metadata_nested_past_the_recursion_limit_is_refused(self) -> None:
        self.insert(metadata_json='{"n":' + "[" * 200_000 + "]" * 200_000 + "}")
        self.assert_refused("contains JSON past the decoder's limits", {"payload_not_json"})

    # S and D: append's JSON rules. On 298f1be, with this setUp, S1 ends `report vdt` and
    # `report historical` in a traceback while staging the output and S5 ends all three reports
    # there; the other readers finish as on an unmodified store and `store verify` says ok. D
    # reads clean with every reader on 3.14, and `store verify` faults only its extra key.

    def plant_surrogate(self, event_type: str, change: Callable[[dict[str, Any]], None]) -> None:
        """Rewrite the first payload of `event_type` around a lone surrogate escape."""

        def work(connection: sqlite3.Connection) -> None:
            row = connection.execute(
                "SELECT sequence, payload_json FROM events WHERE event_type = ? "
                "ORDER BY sequence LIMIT 1",
                (event_type,),
            ).fetchone()
            payload = json.loads(row["payload_json"])
            change(payload)
            text = self.canonical(payload).replace("\ud800", "\\ud800")
            connection.execute(
                "UPDATE events SET payload_json = ?, payload_sha256 = ? WHERE sequence = ?",
                (text, self.digest(text), row["sequence"]),
            )

        self.update(work)

    def test_s1_a_lone_surrogate_in_an_observation_title_is_refused(self) -> None:
        self.plant_surrogate(
            "observation.recorded", lambda payload: payload.update(title="Ubuntu \ud800 notice")
        )
        self.assert_refused("payload contains text that is not valid Unicode", {"payload_not_json"})

    def test_s5_a_lone_surrogate_in_a_failure_diagnostic_is_refused(self) -> None:
        def change(payload: dict[str, Any]) -> None:
            payload["diagnostics"][0]["message"] = "x\ud800"

        self.plant_surrogate("failure.recorded", change)
        self.assert_refused("payload contains text that is not valid Unicode", {"payload_not_json"})

    def test_d_metadata_past_the_append_depth_is_refused(self) -> None:
        def work(connection: sqlite3.Connection) -> None:
            (text,) = connection.execute(
                "SELECT metadata_json FROM events WHERE sequence = 1"
            ).fetchone()
            deep = "[" * 65 + "]" * 65
            connection.execute(
                "UPDATE events SET metadata_json = ? WHERE sequence = 1",
                (text[:-1] + ',"zz":' + deep + "}",),
            )

        self.update(work)
        self.assert_refused("metadata exceeds the JSON depth limit", {"payload_not_json"})

    # V and E: the integer columns.

    def test_v1_a_text_stream_version_is_refused_at_open(self) -> None:
        self.insert(stream_version="x")
        self.assert_refused(
            "has stream_version stored as text", {"event_version_invalid"}, at_open=True
        )

    def test_v2_an_overlong_numeric_stream_version_is_refused_at_open(self) -> None:
        self.insert(stream_version="1" * self.LONG)
        self.assert_refused(
            "has stream_version stored as real", {"event_version_invalid"}, at_open=True
        )

    def test_e1_a_text_event_version_is_refused_on_read(self) -> None:
        self.insert(event_version="x")
        self.assert_refused("has event_version stored as text", {"event_version_invalid"})

    # N: the echo.

    def test_n1_a_long_event_id_with_a_bad_digest_is_not_echoed(self) -> None:
        self.insert(event_id="e" * self.LONG, payload_sha256="0" * 64)
        self.assert_refused(
            "has an unreadable event_id", {"event_name_invalid", "payload_digest_mismatch"}
        )

    def test_n2_a_long_stream_id_at_version_two_is_not_echoed(self) -> None:
        self.insert(stream_id="probe/" + "x" * self.LONG, stream_version=2)
        self.assert_refused(
            "characters outside the name grammar>",
            {"event_name_invalid", "stream_version_gap"},
            at_open=True,
        )

    # K: stored JSON in a spelling `append` never writes. The digest is recomputed, so only
    # the text check stands between it and a read.

    def test_k_a_payload_in_another_spelling_is_refused_by_every_command(self) -> None:
        def work(connection: sqlite3.Connection) -> None:
            (stored,) = connection.execute(
                "SELECT payload_json FROM events WHERE sequence = 1"
            ).fetchone()
            text = json.dumps(json.loads(stored), indent=1, sort_keys=True)
            connection.execute(
                "UPDATE events SET payload_json = ?, payload_sha256 = ? WHERE sequence = 1",
                (text, self.digest(text)),
            )

        self.update(work)
        self.assert_refused(
            "payload is not the canonical JSON text append writes", {"payload_not_json"}
        )

    # T: a stored timestamp in a spelling `append` never writes. On ecc382d an `occurred_at`
    # moved to `+14:00` read everywhere and `cases history` printed the offset.

    def test_t_a_timestamp_in_another_spelling_is_refused_by_every_command(self) -> None:
        def work(connection: sqlite3.Connection) -> None:
            (stored,) = connection.execute(
                "SELECT occurred_at FROM events WHERE sequence = 1"
            ).fetchone()
            moved = datetime.fromisoformat(stored).astimezone(timezone(timedelta(hours=14)))
            connection.execute(
                "UPDATE events SET occurred_at = ? WHERE sequence = 1",
                (moved.isoformat(timespec="microseconds"),),
            )

        self.update(work)
        self.assert_refused(
            "occurred_at is not in the UTC form append writes", {"event_timestamp_invalid"}
        )

    # M: migration records against the marker. On ecc382d a marker lowered below a record
    # ended the next marking append in `store_unavailable` "UNIQUE constraint failed".

    def test_m_a_record_above_a_lowered_marker_refuses_the_marking_ingest(self) -> None:
        with closing(self.raw()) as connection:
            connection.execute("PRAGMA user_version = 1")
        before = self.header_state()
        self.assertEqual(before[0], 1)
        self.assertEqual(before[2], [1, 2])

        code, out, err = run(
            [
                "ingest",
                str(INVALID_RULES_FIXTURE),
                "--record-failed-imports",
                "--db",
                str(self.database),
                "--as-of",
                INGESTED_AT,
            ]
        )

        self.assertEqual((code, out), (1, ""), err[:500])
        self.assertIn(
            "error: store_unavailable: database holds migration record 2 above its schema "
            "marker 1\n",
            err,
        )
        self.assertNotIn("UNIQUE", err)
        self.assertEqual(self.header_state(), before)
        code, out, err = run(["store", "verify", "--db", str(self.database)])
        self.assertEqual(code, 1, err[:500])
        self.assertIn(
            "error: migration_unexpected: database holds migration record 2 above its schema "
            "marker 1\n",
            err,
        )

    # Q: the AUTOINCREMENT counter.

    def test_q_a_counter_stored_as_text_is_refused_at_open(self) -> None:
        with closing(self.raw()) as connection:
            connection.execute("UPDATE sqlite_sequence SET seq = 'x' WHERE name = 'events'")
        self.assert_refused(
            "sequence counter is stored as text", {"sequence_counter_mismatch"}, at_open=True
        )

    # U: text that is not valid UTF-8. On ed9fcf4 `sqlite3` failed to decode it before any
    # check ran, and every command, `store verify` included, printed `store_unavailable`
    # quoting the column's bytes.

    def test_u_text_that_is_not_utf8_is_refused_by_every_command(self) -> None:
        def work(connection: sqlite3.Connection) -> None:
            connection.execute(
                "UPDATE events SET payload_json = CAST(? AS TEXT) WHERE sequence = 1",
                (b"\xff" + b"u" * self.LONG,),
            )

        self.update(work)
        self.assert_refused(
            "column payload_json holds text that is not valid UTF-8", {"event_text_invalid"}
        )
        code, out, err = run(["store", "verify", "--db", str(self.database)])
        self.assertIn(
            "error: event_text_invalid: sequence 1: event column payload_json holds text that is "
            "not valid UTF-8\n",
            err,
        )
        self.assertNotIn("store_unavailable", err)

    def test_u_a_schema_object_holding_undecodable_text_is_refused_by_every_command(self) -> None:
        # CL4B-01: verify read the stand-in and passed what every open refuses.
        for kind in ("trigger", "index", "view", "table"):
            with self.subTest(kind):
                self.database.unlink()
                self.setUp()
                expected = plant_undecodable_schema_object(self.database, kind)
                self.assert_refused(
                    "holds text that is not valid UTF-8", {"schema_text_invalid"}, at_open=True
                )
                _code, _out, err = run(["store", "verify", "--db", str(self.database)])
                self.assertIn(f"error: schema_text_invalid: {expected}\n", err)

    # H: the header's schema marker. On 298f1be a marker of -1 verified clean and the next
    # append ended in `KeyError: 0`.

    def header_state(self) -> tuple[object, ...]:
        with closing(self.raw()) as connection:
            return (
                connection.execute("PRAGMA user_version").fetchone()[0],
                tuple(connection.execute("SELECT COUNT(*), MAX(sequence) FROM events").fetchone()),
                [
                    row[0]
                    for row in connection.execute(
                        "SELECT version FROM complyroll_schema_migrations ORDER BY version"
                    )
                ],
            )

    def test_a_marker_below_the_supported_range_is_refused_by_every_command(self) -> None:
        with closing(self.raw()) as connection:
            connection.execute("PRAGMA user_version = -1")
        before = self.header_state()
        for name, argv in self.readers(at_open=True).items():
            with self.subTest(command=name):
                code, out, err = run(argv)
                self.assertEqual(code, 1, err[:500])
                self.assertIn(
                    "error: store_unavailable: database schema -1 is outside supported "
                    "schemas 1 to 4",
                    err,
                )
                self.assert_bounded(out, err)
        self.assertEqual(self.header_state(), before)
        self.assertEqual(before[0], -1)
        for kind in self.REPORTS:
            self.assertFalse(self.output(kind).exists(), kind)
        code, out, err = run(["store", "verify", "--db", str(self.database)])
        self.assertEqual(code, 1, err[:500])
        self.assertIn(
            "schema_version_unsupported: database is marked schema -1; this build opens "
            "schemas 1 to 4",
            out + err,
        )
        self.assert_bounded(out, err)


#: A small inventory over the golden fixtures: one entry reached through an alias whose drift
#: is unknown, and one attested procedure. The coverage goldens use `examples/inventory.json`.
CLI_INVENTORY = {
    "schema": "complyroll.inventory",
    "schemaVersion": 1,
    "name": "cli-boundary",
    "resources": [
        {
            "resourceType": "host",
            "resourceId": "ubuntu-primary",
            "machineBased": True,
            "driftLikely": "unknown",
            "expectedSince": "2026-07-01T00:00:00Z",
            "aliases": [{"resourceType": "host", "resourceId": "lab-ubuntu-01"}],
        },
        {
            "resourceType": "logical",
            "resourceId": "incident-response-procedure",
            "machineBased": False,
            "expectedSince": "2026-07-01T00:00:00Z",
            "verifications": [{"at": "2026-08-01T17:00:00Z", "reference": "IR tabletop record"}],
        },
    ],
}
#: The drift warning the inventory raises, as stderr prints it.
CLI_DRIFT_WARNING = (
    'warning: drift_likelihood_unknown: host:ubuntu-primary declares driftLikely "unknown", '
    "so it carries VDR-TFR-PDD, the shorter drift window, until the inventory says whether "
    "drift is likely [cli-boundary host:ubuntu-primary]"
)


def stripped_policy(*rule_ids: str) -> Callable[..., Any]:
    """Return a `select_policy` that drops the named rules from what it selects."""

    real = vdt_module.select_policy

    def select(snapshot: Any, profile: Any) -> Any:
        policy = real(snapshot, profile)
        return replace(
            policy, rules=tuple(item for item in policy.rules if item.rule_id not in rule_ids)
        )

    return select


class InventoryReportCommandTests(unittest.TestCase):
    """`--inventory` on all three commands, reading the artifacts from disk (ADR 0015).

    The inventory is a per-run input exactly as the KEV catalog is: named in the overwrite
    guard, read before the options so a malformed one is refused as bad input, one only.
    """

    COMMANDS = (
        ("vdt", REPORT_ARGUMENTS),
        ("avi", AVI_ARGUMENTS),
        ("historical", HISTORICAL_ARGUMENTS),
    )

    def setUp(self) -> None:
        directory = tempfile.TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        self.workspace = Path(directory.name)
        self.inventory = self.workspace / "inventory.json"
        self.inventory.write_text(json.dumps(CLI_INVENTORY), encoding="utf-8")

    def write_inventory(self, content: bytes) -> Path:
        path = self.workspace / "refused.json"
        path.write_bytes(content)
        return path

    def test_every_command_carries_the_block_and_leaves_the_rest_alone(self) -> None:
        for kind, argv in self.COMMANDS:
            with self.subTest(report=kind):
                json_path = self.workspace / f"{kind}.json"
                markdown_path = self.workspace / f"{kind}.md"

                code, out, err = run(
                    [
                        *argv,
                        "--inventory",
                        str(self.inventory),
                        "-o",
                        str(json_path),
                        "--markdown",
                        str(markdown_path),
                    ]
                )

                self.assertEqual(code, 0, msg=err)
                self.assertEqual(out, "")
                self.assertIn(CLI_DRIFT_WARNING, err.splitlines())
                document = json.loads(json_path.read_text(encoding="utf-8"))
                golden = json.loads((GOLDEN / f"{kind}-fixtures.json").read_text(encoding="utf-8"))
                extension = document.pop("x-complyroll")
                golden_extension = golden.pop("x-complyroll")
                self.assertEqual(document, golden)
                coverage = extension.pop("coverage")
                self.assertEqual(
                    coverage["inventory"],
                    {
                        "name": "cli-boundary",
                        "sha256": hashlib.sha256(self.inventory.read_bytes()).hexdigest(),
                        "sizeBytes": self.inventory.stat().st_size,
                        "entries": 2,
                    },
                )
                diagnostics = extension.pop("diagnostics")
                self.assertEqual(
                    [item for item in diagnostics if item["code"] != "drift_likelihood_unknown"],
                    golden_extension.pop("diagnostics"),
                )
                self.assertEqual(extension, golden_extension)
                self.assertIn("\n## Coverage\n", markdown_path.read_text(encoding="utf-8"))

    def test_the_three_commands_carry_one_block(self) -> None:
        blocks = {}
        for kind, argv in self.COMMANDS:
            code, out, err = run([*argv, "--inventory", str(self.inventory)])
            self.assertEqual(code, 0, msg=err)
            blocks[kind] = json.loads(out)["x-complyroll"]["coverage"]
        self.assertEqual(blocks["avi"], blocks["vdt"])
        self.assertEqual(blocks["historical"], blocks["vdt"])
        statuses = {
            (item["resourceId"], clock["ruleId"]): clock["status"]
            for item in blocks["vdt"]["resources"]
            for clock in item["clocks"]
        }
        self.assertEqual(
            statuses,
            {
                ("incident-response-procedure", "VDR-TFR-NMV"): "current",
                ("ubuntu-primary", "VDR-TFR-MVX"): "missing",
                ("ubuntu-primary", "VDR-TFR-PDD"): "missing",
            },
        )

    def test_a_second_inventory_is_refused_on_every_command(self) -> None:
        # `--inventory` appends, so argparse would otherwise keep the last of several.
        for kind, argv in self.COMMANDS:
            with self.subTest(report=kind):
                code, out, err = run(
                    [*argv, "--inventory", str(self.inventory), "--inventory", str(self.inventory)]
                )

                self.assertEqual(code, 1)
                self.assertEqual(out, "")
                self.assertIn(
                    f"error: invalid_option: report {kind} takes one --inventory file, not 2", err
                )

    def test_a_refused_inventory_is_bad_input_and_writes_nothing(self) -> None:
        colon = copy.deepcopy(CLI_INVENTORY)
        colon["resources"][0]["resourceType"] = "host:linux"
        group = copy.deepcopy(CLI_INVENTORY)
        group["resources"][0]["sampleGroup"] = "g" * 129
        cases = {
            "not JSON": (b"resourceType,resourceId\n", "inventory must be a JSON document"),
            "a KEV catalog": (
                (FIXTURES / "kev-catalog.json").read_bytes(),
                "inventory: schema is required",
            ),
            "a colon in a type": (
                json.dumps(colon).encode("utf-8"),
                "inventory resources[0]: resourceType must not contain a colon, got 'host:linux'",
            ),
            "a long group name": (
                json.dumps(group).encode("utf-8"),
                "inventory resources[0]: sampleGroup must be 1 to 128 printable ASCII",
            ),
        }
        for label, (content, message) in cases.items():
            for kind, argv in self.COMMANDS:
                with self.subTest(case=label, report=kind):
                    path = self.write_inventory(content)
                    json_path = self.workspace / "report.json"

                    code, out, err = run([*argv, "--inventory", str(path), "-o", str(json_path)])

                    self.assertEqual(code, 1)
                    self.assertEqual(out, "")
                    self.assertIn(f"error: invalid_input: {message}", err)
                    self.assertFalse(json_path.exists())

    def test_an_inventory_that_is_not_there_is_refused_as_bad_input(self) -> None:
        json_path = self.workspace / "report.json"

        missing = self.workspace / "gone.json"
        code, out, err = run([*REPORT_ARGUMENTS, "--inventory", str(missing), "-o", str(json_path)])

        self.assertEqual(code, 1)
        self.assertEqual(out, "")
        self.assertIn("error: invalid_input: inventory cannot be read", err)
        self.assertFalse(json_path.exists())

    def test_writing_a_report_over_the_inventory_is_refused(self) -> None:
        before = self.inventory.read_bytes()
        for option in ("-o", "--markdown"):
            with self.subTest(destination=option):
                inventory = str(self.inventory)
                code, out, err = run(
                    [*REPORT_ARGUMENTS, "--inventory", inventory, option, inventory]
                )

                self.assertEqual(code, 1)
                self.assertEqual(out, "")
                self.assertIn("refusing to overwrite the input file", err)
                self.assertEqual(self.inventory.read_bytes(), before)

    def test_a_policy_without_a_coverage_rule_stops_the_run_and_writes_nothing(self) -> None:
        for kind, argv in self.COMMANDS:
            with (
                self.subTest(report=kind),
                patch.object(vdt_module, "select_policy", stripped_policy("VDR-TFR-PSD")),
            ):
                json_path = self.workspace / "report.json"

                code, out, err = run(
                    [*argv, "--inventory", str(self.inventory), "-o", str(json_path)]
                )

                self.assertEqual(code, 1)
                self.assertEqual(out, "")
                self.assertIn(
                    "error: coverage_rule_unavailable: an information resource inventory was "
                    "supplied, but the Class C policy selects no VDR-TFR-PSD rule, so no "
                    "coverage clock can run [cli-boundary]",
                    err,
                )
                self.assertFalse(json_path.exists())

    def test_without_the_flag_the_coverage_rules_are_never_read(self) -> None:
        for kind, argv in self.COMMANDS:
            with (
                self.subTest(report=kind),
                patch.object(
                    vdt_module,
                    "select_policy",
                    stripped_policy(
                        "VDR-TFR-MVX", "VDR-TFR-NMV", "VDR-TFR-PCD", "VDR-TFR-PDD", "VDR-TFR-PSD"
                    ),
                ),
            ):
                code, out, err = run(argv)

                self.assertEqual(code, 0, msg=err)
                self.assertEqual(
                    out, (GOLDEN / f"{kind}-fixtures.json").read_text(encoding="utf-8")
                )
                self.assertNotIn("drift_likelihood_unknown", err)
                self.assertNotIn("coverage", json.loads(out)["x-complyroll"])

    def test_help_names_the_option_on_every_command(self) -> None:
        for kind, _ in self.COMMANDS:
            with self.subTest(report=kind):
                text = help_text(["report", kind])
                self.assertIn("--inventory FILE", text)
                self.assertIn(
                    "information resource inventory JSON to measure coverage against "
                    "(read locally, never stored)",
                    text,
                )


class PersistedInventoryTests(PersistedStoreTestCase):
    """`--inventory` beside `--db`: no store holds an inventory, so it is never a conflict."""

    KINDS = ("vdt", "avi", "historical")

    def setUp(self) -> None:
        super().setUp()
        self.populate(ACCEPTED_EVALUATIONS)
        self.inventory = self.workspace / "inventory.json"
        self.inventory.write_text(json.dumps(CLI_INVENTORY), encoding="utf-8")

    def persisted(self, kind: str, *extra: str) -> list[str]:
        argv = [
            "report",
            kind,
            "--db",
            str(self.database),
            "--class",
            "C",
            "--package-uri",
            "https://example.test/cpo",
            "--as-of",
            INGESTED_AT,
        ]
        if kind != "historical":
            argv += ["--from", "2026-08-01T00:00:00Z", "--to", "2026-08-31T23:59:59Z"]
        return [*argv, *extra]

    @staticmethod
    def stateless(kind: str, *extra: str) -> list[str]:
        """Return the stateless run of the same inputs the store was populated with."""

        if kind == "avi":
            argv = list(AVI_ARGUMENTS)
        elif kind == "historical":
            argv = list(HISTORICAL_ARGUMENTS)
        else:
            argv = [*REPORT_ARGUMENTS[:-1], str(ACCEPTED_EVALUATIONS)]
        return [*argv, *extra]

    def test_an_inventory_beside_a_store_is_not_a_source_conflict(self) -> None:
        for kind in self.KINDS:
            with self.subTest(report=kind):
                code, out, err = run(self.persisted(kind, "--inventory", str(self.inventory)))

                self.assertEqual(code, 0, msg=err)
                self.assertNotIn("invalid_option", err)
                self.assertIn(CLI_DRIFT_WARNING, err.splitlines())
                self.assertIn("coverage", json.loads(out)["x-complyroll"])

    def test_the_persisted_report_equals_the_stateless_one_byte_for_byte(self) -> None:
        for kind in self.KINDS:
            with self.subTest(report=kind):
                persisted = self.workspace / f"{kind}-persisted"
                stateless = self.workspace / f"{kind}-stateless"
                outputs = []
                for argv, stem in (
                    (self.persisted(kind), persisted),
                    (self.stateless(kind), stateless),
                ):
                    code, _, err = run(
                        [
                            *argv,
                            "--inventory",
                            str(self.inventory),
                            "-o",
                            f"{stem}.json",
                            "--markdown",
                            f"{stem}.md",
                        ]
                    )
                    self.assertEqual(code, 0, msg=err)
                    outputs.append(err)

                self.assertEqual(
                    Path(f"{persisted}.json").read_bytes(), Path(f"{stateless}.json").read_bytes()
                )
                self.assertEqual(
                    Path(f"{persisted}.md").read_bytes(), Path(f"{stateless}.md").read_bytes()
                )
                self.assertIn(CLI_DRIFT_WARNING, outputs[0].splitlines())

    def test_a_second_inventory_is_refused_against_a_store_too(self) -> None:
        code, out, err = run(
            self.persisted(
                "vdt", "--inventory", str(self.inventory), "--inventory", str(self.inventory)
            )
        )

        self.assertEqual(code, 1)
        self.assertEqual(out, "")
        self.assertIn("error: invalid_option: report vdt takes one --inventory file, not 2", err)

    def test_a_refused_inventory_against_a_store_writes_nothing(self) -> None:
        refused = self.workspace / "refused.json"
        refused.write_bytes(b"{}")
        json_path = self.workspace / "report.json"

        code, out, err = run(
            self.persisted("vdt", "--inventory", str(refused), "-o", str(json_path))
        )

        self.assertEqual(code, 1)
        self.assertEqual(out, "")
        self.assertIn("error: invalid_input: inventory: schema is required", err)
        self.assertFalse(json_path.exists())


class CoverageGoldenTests(unittest.TestCase):
    """The `vdt-coverage` goldens: the `vdt-fixtures` run plus `examples/inventory.json`."""

    def golden(self) -> dict[str, Any]:
        return json.loads((GOLDEN / "vdt-coverage.json").read_text(encoding="utf-8"))

    def test_the_command_reproduces_the_coverage_golden_pair(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            json_path = Path(directory) / "report.json"
            markdown_path = Path(directory) / "report.md"

            code, out, err = run(
                [*COVERAGE_ARGUMENTS, "-o", str(json_path), "--markdown", str(markdown_path)]
            )

            self.assertEqual(code, 0, msg=err)
            self.assertEqual(out, "")
            self.assertIn(
                "warning: drift_likelihood_unknown: host:lab-rhel-01 declares driftLikely "
                '"unknown"',
                err,
            )
            self.assertIn("[example-boundary host:lab-rhel-01]", err)
            self.assertEqual(json_path.read_bytes(), (GOLDEN / "vdt-coverage.json").read_bytes())
            self.assertEqual(markdown_path.read_bytes(), (GOLDEN / "vdt-coverage.md").read_bytes())

    def test_the_golden_validates_against_the_official_schema(self) -> None:
        code, out, err = run(
            ["validate", str(GOLDEN / "vdt-coverage.json"), "--schema", "vulnerability-detail"]
        )

        self.assertEqual(code, 0, msg=err)
        self.assertTrue(out.startswith("valid: "), out)

    def test_the_official_fields_equal_the_fixtures_golden(self) -> None:
        coverage = self.golden()
        fixtures = json.loads((GOLDEN / "vdt-fixtures.json").read_text(encoding="utf-8"))
        extension = coverage.pop("x-complyroll")
        fixtures_extension = fixtures.pop("x-complyroll")

        self.assertEqual(coverage, fixtures)
        self.assertIn("coverage", extension)
        extension.pop("coverage")
        self.assertEqual(
            [
                item
                for item in extension.pop("diagnostics")
                if item["code"] != "drift_likelihood_unknown"
            ],
            fixtures_extension.pop("diagnostics"),
        )
        self.assertEqual(extension, fixtures_extension)

    def test_avi_and_historical_carry_the_golden_block(self) -> None:
        block = self.golden()["x-complyroll"]["coverage"]
        for kind, argv in (("avi", AVI_ARGUMENTS), ("historical", HISTORICAL_ARGUMENTS)):
            with self.subTest(report=kind):
                code, out, err = run([*argv, "--inventory", str(EXAMPLE_INVENTORY)])

                self.assertEqual(code, 0, msg=err)
                self.assertEqual(json.loads(out)["x-complyroll"]["coverage"], block)

    def test_the_golden_shows_what_the_fixtures_can_reach(self) -> None:
        # The golden fixtures are untimed, so no machine resource can be verified at this
        # as-of: only attested resources reach current or stale, and nothing is undetermined.
        block = self.golden()["x-complyroll"]["coverage"]
        self.assertEqual(
            block["inventory"]["sha256"],
            hashlib.sha256(EXAMPLE_INVENTORY.read_bytes()).hexdigest(),
        )
        resources = {item["resourceId"]: item for item in block["resources"]}
        statuses = {
            (name, clock["ruleId"]): clock["status"]
            for name, item in resources.items()
            for clock in item["clocks"]
        }
        self.assertEqual(
            statuses,
            {
                ("lab-rhel-01", "VDR-TFR-MVX"): "missing",
                ("lab-rhel-01", "VDR-TFR-PDD"): "missing",
                ("lab-ubuntu-03", "VDR-TFR-MVX"): "unanchored",
                ("lab-ubuntu-03", "VDR-TFR-PDD"): "unanchored",
                ("lab-win-01", "VDR-TFR-MVX"): "missing",
                ("lab-win-01", "VDR-TFR-PCD"): "missing",
                ("ubuntu-web-01", "VDR-TFR-MVX"): "missing",
                ("ubuntu-web-01", "VDR-TFR-PDD"): "missing",
                ("backup-restore-procedure", "VDR-TFR-NMV"): "stale",
                ("contingency-plan", "VDR-TFR-NMV"): "missing",
                ("contingency-plan", "VDR-TFR-PSD"): "stale",
                ("incident-response-procedure", "VDR-TFR-NMV"): "current",
                ("incident-response-procedure", "VDR-TFR-PSD"): "stale",
            },
        )
        group = resources["contingency-plan"]["clocks"][1]
        self.assertEqual(
            group["standIn"],
            {"resourceType": "logical", "resourceId": "incident-response-procedure"},
        )
        self.assertEqual(
            (resources["ubuntu-web-01"]["untimed"], resources["lab-win-01"]["untimed"]), (6, 2)
        )
        self.assertEqual(
            resources["ubuntu-web-01"]["aliases"],
            [{"resourceType": "host", "resourceId": "lab-ubuntu-01"}],
        )
        self.assertTrue(resources["contingency-plan"]["attested"])
        self.assertEqual(resources["lab-rhel-01"]["decommissionedAt"], "2026-08-10T00:00:00Z")
        self.assertEqual(
            block["unregistered"],
            [{"resourceType": "host", "resourceId": "lab-ubuntu-02", "observations": 3}],
        )
        self.assertEqual(
            [(item["kind"], item["reference"]) for item in block["later"]],
            [("attestation", "IR tabletop record TT-2026-09")],
        )
        markdown = (GOLDEN / "vdt-coverage.md").read_text(encoding="utf-8")
        self.assertIn("VDR-TFR-MVX MUST missing (6 untimed)", markdown)


class PersistedCoverageGoldenTests(PersistedStoreTestCase):
    """The documented sequence plus `--inventory` rebuilds the coverage goldens."""

    def test_the_documented_sequence_reproduces_the_coverage_golden(self) -> None:
        self.populate()
        json_path = self.workspace / "report.json"
        markdown_path = self.workspace / "report.md"

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
                "--as-of",
                INGESTED_AT,
                "--inventory",
                str(EXAMPLE_INVENTORY),
                "-o",
                str(json_path),
                "--markdown",
                str(markdown_path),
            ]
        )

        self.assertEqual(code, 0, msg=err)
        self.assertEqual(out, "")
        self.assertEqual(json_path.read_bytes(), (GOLDEN / "vdt-coverage.json").read_bytes())
        self.assertEqual(markdown_path.read_bytes(), (GOLDEN / "vdt-coverage.md").read_bytes())


class TimedCoverageGoldenTests(unittest.TestCase):
    """The `vdt-coverage-timed` goldens: machine clocks anchored by timed SARIF evidence."""

    def golden(self) -> dict[str, Any]:
        return json.loads((GOLDEN / "vdt-coverage-timed.json").read_text(encoding="utf-8"))

    def test_the_command_reproduces_the_timed_golden_pair(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            json_path = Path(directory) / "report.json"
            markdown_path = Path(directory) / "report.md"

            code, out, err = run(
                [*timed_argv(), "-o", str(json_path), "--markdown", str(markdown_path)]
            )

            self.assertEqual(code, 0, msg=err)
            self.assertEqual(out, "")
            self.assertNotIn("drift_likelihood_unknown", err)
            self.assertEqual(
                json_path.read_bytes(), (GOLDEN / "vdt-coverage-timed.json").read_bytes()
            )
            self.assertEqual(
                markdown_path.read_bytes(), (GOLDEN / "vdt-coverage-timed.md").read_bytes()
            )

    def test_the_golden_validates_against_the_official_schema(self) -> None:
        code, out, err = run(
            [
                "validate",
                str(GOLDEN / "vdt-coverage-timed.json"),
                "--schema",
                "vulnerability-detail",
            ]
        )

        self.assertEqual(code, 0, msg=err)
        self.assertTrue(out.startswith("valid: "), out)

    def test_the_official_fields_equal_the_run_without_the_inventory(self) -> None:
        # No golden holds this run without `--inventory`, so it is compiled here.
        code, out, err = run(timed_argv(inventory=False))
        self.assertEqual(code, 0, msg=err)
        bare = json.loads(out)
        timed = self.golden()
        extension = timed.pop("x-complyroll")
        bare_extension = bare.pop("x-complyroll")

        self.assertEqual(timed, bare)
        self.assertNotIn("coverage", bare_extension)
        extension.pop("coverage")
        # No entry declares drift unknown, so the diagnostics are equal as they stand.
        self.assertEqual(extension, bare_extension)

    def test_avi_and_historical_carry_the_golden_block(self) -> None:
        block = self.golden()["x-complyroll"]["coverage"]
        for kind in ("avi", "historical"):
            with self.subTest(report=kind):
                code, out, err = run(timed_argv(kind))

                self.assertEqual(code, 0, msg=err)
                self.assertEqual(json.loads(out)["x-complyroll"]["coverage"], block)

    def test_the_golden_shows_the_machine_statuses(self) -> None:
        block = self.golden()["x-complyroll"]["coverage"]
        self.assertEqual(
            block["inventory"]["sha256"], hashlib.sha256(TIMED_INVENTORY.read_bytes()).hexdigest()
        )
        resources = {item["resourceId"].rsplit("/", 1)[-1]: item for item in block["resources"]}
        statuses = {
            (name, clock["ruleId"]): clock["status"]
            for name, item in resources.items()
            for clock in item["clocks"]
        }
        self.assertEqual(
            statuses,
            {
                ("helpers.js", "VDR-TFR-MVX"): "current",
                ("helpers.js", "VDR-TFR-PCD"): "current",
                ("index.js", "VDR-TFR-MVX"): "missing",
                ("index.js", "VDR-TFR-PDD"): "missing",
                ("index.js", "VDR-TFR-PSD"): "current",
                ("legacy.js", "VDR-TFR-MVX"): "undetermined",
                ("legacy.js", "VDR-TFR-PDD"): "undetermined",
                ("render.js", "VDR-TFR-MVX"): "current",
                ("render.js", "VDR-TFR-PDD"): "current",
                ("render.js", "VDR-TFR-PSD"): "current",
                ("example-service:1.4.0", "VDR-TFR-MVX"): "stale",
                ("example-service:1.4.0", "VDR-TFR-PDD"): "stale",
            },
        )
        # A member never scanned is current on its group clock through a scanned member.
        render = {"resourceType": "file", "resourceId": "src/ui/render.js"}
        self.assertEqual(resources["index.js"]["clocks"][2]["standIn"], render)
        # The scanner names render.js by its repository URL, which only the alias matches.
        self.assertEqual(
            resources["render.js"]["clocks"][0]["evidence"]["resourceId"],
            "https://github.com/example/webapp/src/ui/render.js",
        )
        self.assertEqual(
            [(item["ruleId"], item["closedAt"], item["resumedAt"]) for item in block["windows"]],
            [
                ("VDR-TFR-MVX", "2026-08-04T00:00:00Z", "2026-08-05T10:00:00Z"),
                ("VDR-TFR-MVX", "2026-08-08T10:00:00Z", None),
                ("VDR-TFR-PDD", "2026-08-19T10:00:00Z", None),
            ],
        )
        self.assertEqual((block["unregistered"], block["later"]), ([], []))
        self.assertEqual({item["untimed"] for item in block["resources"]}, {0})


class PersistedTimedCoverageGoldenTests(PersistedStoreTestCase):
    """A store holding the timed SARIF fixtures plus `--inventory` rebuilds the timed goldens.

    The fixtures declare their own clocks, so the sequence needs no detection attestation.
    """

    def test_a_store_and_the_timed_inventory_reproduce_the_golden_pair(self) -> None:
        self.succeeds(
            [
                "ingest",
                *TIMED_ARTIFACTS,
                "--db",
                str(self.database),
                "--as-of",
                TIMED_AS_OF,
                "--actor",
                "golden",
            ]
        )
        self.correlate()
        json_path = self.workspace / "report.json"
        markdown_path = self.workspace / "report.md"

        out, _ = self.succeeds(
            [*timed_argv(db=self.database), "-o", str(json_path), "--markdown", str(markdown_path)]
        )

        self.assertEqual(out, "")
        self.assertEqual(json_path.read_bytes(), (GOLDEN / "vdt-coverage-timed.json").read_bytes())
        self.assertEqual(
            markdown_path.read_bytes(), (GOLDEN / "vdt-coverage-timed.md").read_bytes()
        )


def run_on_encoding(argv: Sequence[str], encoding: str) -> tuple[int, bytes, bytes]:
    """Run one CLI invocation on byte streams that encode as a terminal set to `encoding` does.

    `run` captures text, so it can never fail to encode; a real stdout under
    `PYTHONIOENCODING=ascii` is a strict wrapper like these.
    """

    out_bytes = io.BytesIO()
    err_bytes = io.BytesIO()
    out = io.TextIOWrapper(out_bytes, encoding=encoding, errors="strict", write_through=True)
    err = io.TextIOWrapper(err_bytes, encoding=encoding, errors="strict", write_through=True)
    with redirect_stdout(out), redirect_stderr(err):
        code = main(list(argv))
    return code, out_bytes.getvalue(), err_bytes.getvalue()


#: Text that would forge a diagnostic line, move the cursor and clear the screen if a terminal
#: received it raw: a newline, a carriage return, a line separator and ANSI escapes.
FORGING_TEXT = "x\nerror: forged: injected\r\u2028\x1b[2J\x9b"
#: The same text as text output prints it, every control spelled as an escape.
FORGING_SHOWN = "x\\nerror: forged: injected\\r\\u2028\\x1b[2J\\x9b"


class TerminalTextTests(PersistedStoreTestCase):
    """Text output escapes control characters, so no input forges a line (CL-50, CL-51).

    Every line the CLI prints goes through one choke point that spells C0 and C1 controls,
    DEL, U+2028 and U+2029 as escapes; JSON output already escapes them and is unchanged.
    A stream that cannot encode a character writes it as a backslash escape rather than
    ending the run, and JSON written to such a stream spells it as a JSON escape.
    """

    def assert_unforged(self, text: str) -> None:
        for line in text.splitlines():
            self.assertFalse(line.startswith("error: forged"), line)
        self.assertNotIn("\x1b", text)
        self.assertNotIn("\r", text)
        self.assertNotIn("\u2028", text)
        self.assertNotIn("\x9b", text)

    def test_a_file_name_forges_no_line_on_the_stateless_path(self) -> None:
        artifact = self.workspace / f"{FORGING_TEXT}.cklb"
        artifact.write_text("{not json", encoding="utf-8")
        argv = list(REPORT_ARGUMENTS)
        argv[2:5] = [str(artifact)]

        code, out, err = run(argv)

        self.assertEqual((code, out), (1, ""))
        self.assert_unforged(err)
        self.assertEqual(len(err.splitlines()), 1)
        self.assertIn(f"[{FORGING_SHOWN}.cklb]", err)

    def test_an_ingest_summary_names_a_file_with_its_controls_escaped(self) -> None:
        artifact = self.workspace / f"{FORGING_TEXT}.cklb"
        artifact.write_bytes((FIXTURES / "ubuntu-host.cklb").read_bytes())

        code, out, err = run(["ingest", str(artifact), "--db", str(self.database)])

        self.assertEqual(code, 0, err)
        self.assert_unforged(out + err)
        self.assertEqual(out, f"{FORGING_SHOWN}.cklb: recorded 6 observation(s)\n")

    def test_stored_text_forges_no_line_in_cases_history(self) -> None:
        self.ingest_fixtures()
        self.correlate()
        self.attest_missing()
        payload = json.loads((EXAMPLES / "evaluations.json").read_text(encoding="utf-8"))
        for entry in payload["evaluations"]:
            entry["evaluator"] = FORGING_TEXT
        evaluations = self.workspace / "evaluations.json"
        evaluations.write_text(json.dumps(payload), encoding="utf-8")
        self.evaluate(evaluations, actor=FORGING_TEXT)

        listing, err = self.succeeds(["cases", "history", WINDOWS_CASE, "--db", str(self.database)])

        self.assert_unforged(listing + err)
        evaluated = [line for line in listing.splitlines() if "\tcase.evaluated\t" in line]
        self.assertEqual(len(evaluated), 1)
        fields = evaluated[0].split("\t")
        self.assertEqual(fields[3], FORGING_SHOWN)
        self.assertTrue(fields[4].endswith(f" by {FORGING_SHOWN}"), fields[4])

    def test_a_tab_stays_a_tab(self) -> None:
        # `cases history` separates its fields with tabs; a tab moves no line.
        self.ingest_fixtures()
        self.correlate()

        listing, _ = self.succeeds(["cases", "history", WINDOWS_CASE, "--db", str(self.database)])

        self.assertTrue(all(line.count("\t") == 4 for line in listing.splitlines()))

    def test_json_on_stdout_is_unchanged(self) -> None:
        code, out, _ = run_on_encoding(REPORT_ARGUMENTS, "utf-8")

        self.assertEqual(code, 0)
        self.assertEqual(out, (GOLDEN / "vdt-fixtures.json").read_bytes())

    def test_json_on_an_ascii_stdout_is_the_same_document(self) -> None:
        code, out, err = run_on_encoding(REPORT_ARGUMENTS, "ascii")

        self.assertEqual(code, 0, err)
        golden = (GOLDEN / "vdt-fixtures.json").read_text(encoding="utf-8")
        self.assertIn("\u00ae", golden)
        self.assertEqual(json.loads(out.decode("ascii")), json.loads(golden))
        self.assertEqual(out.decode("ascii"), golden.replace("\u00ae", "\\u00ae"))

    def test_ingest_on_an_ascii_stdout_reports_the_write_it_committed(self) -> None:
        artifact = self.workspace / "caf\u00e9-host.cklb"
        artifact.write_bytes((FIXTURES / "ubuntu-host.cklb").read_bytes())
        argv = ["ingest", str(artifact), "--db", str(self.database), "--as-of", INGESTED_AT]

        code, out, err = run_on_encoding(argv, "ascii")

        self.assertEqual(code, 0, err)
        self.assertEqual(out, b"caf\\xe9-host.cklb: recorded 6 observation(s)\n")
        self.assertIn(b"warning: source_timestamp_missing: ", err)
        self.assertIn(b"[caf\\xe9-host.cklb]", err)
        code, out, _ = run_on_encoding(argv, "utf-8")
        self.assertEqual(code, 0)
        self.assertEqual(out, "caf\u00e9-host.cklb: already_recorded\n".encode())

    def test_a_diagnostic_on_an_ascii_stderr_does_not_end_the_run(self) -> None:
        artifact = self.workspace / "caf\u00e9.cklb"
        artifact.write_text("{not json", encoding="utf-8")
        argv = list(REPORT_ARGUMENTS)
        argv[2:5] = [str(artifact)]

        code, out, err = run_on_encoding(argv, "ascii")

        self.assertEqual((code, out), (1, b""))
        self.assertTrue(err.startswith(b"error: artifact_parse_failed: "), err)
        self.assertIn(b"[caf\\xe9.cklb]", err)


class FrozenCategoryStoreTests(PersistedStoreTestCase):
    """A store 0.3.0a0 wrote on 3.11 can hold an identity the frozen table refuses (CL-65).

    3.11's Unicode 14.0.0 database called U+13439 to U+1343F unassigned, so 0.3.0a0 on 3.11
    accepted them in an identity. No reader or `store verify` calls `identity_problem`, so
    such a store still reads and verifies; only reading the same bytes again refuses them.
    """

    def test_a_stored_identity_holding_one_of_the_seven_still_reads_and_verifies(self) -> None:
        uri = "src/egyptian\U00013439.py"
        artifact = self.workspace / "egyptian.sarif"
        artifact.write_text(json.dumps(make_log(make_run([make_result(uri=uri)]))), "utf-8")
        argv = ["ingest", str(artifact), "--db", str(self.database), "--as-of", INGESTED_AT]
        real = adapters_common.prohibited_category

        # 0.3.0a0 on 3.11: the code point read as unassigned, so the identity was accepted.
        def unassigned(char: str) -> str | None:
            return None if char == "\U00013439" else real(char)

        with patch.object(adapters_common, "prohibited_category", unassigned):
            self.succeeds(argv)

        self.succeeds(["store", "verify", "--db", str(self.database)])
        self.correlate()
        self.attest_missing()
        listing, _ = self.succeeds(["cases", "list", "--db", str(self.database)])
        self.assertEqual(len(listing.splitlines()), 2)
        out, _ = self.report()
        self.assertIn('"resourceId": "src/egyptian\U00013439.py"', out)
        self.succeeds(["store", "verify", "--db", str(self.database)])

        code, out, err = run(argv)
        self.assertEqual((code, out), (1, ""))
        self.assertIn("error: identity_input_invalid: ", err)
        self.assertIn("contains prohibited code point U+13439", err)


class UnusableStoredClockTests(PersistedStoreTestCase):
    """A store an earlier build wrote can hold a clock no report can compute with (CL-54).

    0.3.0a0 read CKLB and XCCDF clocks unguarded, so a store can hold year 1 or year 9999.
    The readers refuse exactly the clocks whose use overflows, each with a code and no
    traceback, and `store verify` names every one of them with the same predicate. Clocks
    that reported before still report, byte for byte.
    """

    #: Year 1 east and year 9999 west: the conversion to UTC overflows, in every reader.
    CONVERSION = ("0001-01-01T00:00:00+01:00", "9999-12-31T23:00:00-01:00")
    #: The VER-TFR-EVU deadline overflows: 5 days under Class C, 7 under Class B.
    DEADLINE_BOTH = "9999-12-31T23:59:59Z"
    DEADLINE_B = "9999-12-26T12:00:00Z"
    #: Outside the years a current build reads, and still reported today.
    REPORTED = (
        "0001-01-01T00:00:00Z",
        "1969-12-31T23:59:59Z",
        "9001-01-01T00:00:00Z",
        "9990-01-01T00:00:00Z",
    )
    KINDS = ("vdt", "avi", "historical")

    def checklist(self, clock: str, name: str = "ubuntu-host.cklb") -> Path:
        document = json.loads((FIXTURES / "ubuntu-host.cklb").read_text(encoding="utf-8"))
        document["completed_at"] = clock
        path = self.workspace / name
        path.write_text(json.dumps(document), encoding="utf-8")
        return path

    def ingest_clock(self, clock: str, name: str = "ubuntu-host.cklb") -> Path:
        """Ingest the Ubuntu checklist at `clock` the way 0.3.0a0 read it, unguarded."""

        path = self.checklist(clock, name)
        with unguarded_stig_clocks():
            self.succeeds(["ingest", str(path), "--db", str(self.database), "--as-of", INGESTED_AT])
        return path

    def report_argv(
        self, kind: str, certification_class: str = "C", *, inventory: bool = False
    ) -> list[str]:
        argv = ["report", kind, "--db", str(self.database), "--class", certification_class]
        argv += ["--package-uri", "https://example.test/cpo", "--as-of", INGESTED_AT]
        if kind != "historical":
            argv += ["--from", "2026-08-01T00:00:00Z", "--to", "2026-08-31T23:59:59Z"]
        if inventory:
            argv += ["--inventory", str(EXAMPLE_INVENTORY)]
        return argv

    def assert_clock_refusal(self, argv: Sequence[str], clock: str) -> list[str]:
        """Assert one run is refused with `clock_out_of_range` lines only; return messages."""

        code, out, err = run(argv)
        self.assertEqual((code, out), (1, ""), err)
        lines = err.splitlines()
        self.assertTrue(lines)
        prefix = "error: clock_out_of_range: "
        for line in lines:
            self.assertTrue(line.startswith(prefix), line)
            self.assertIn(clock, line)
        return [line[len(prefix) :].rsplit(" [", 1)[0] for line in lines]

    def verify_faults(self) -> list[str]:
        code, out, err = run(["store", "verify", "--db", str(self.database)])
        self.assertEqual((code, out), (1, ""), err)
        faults = [line for line in err.splitlines() if ": clock_out_of_range: " in line]
        self.assertTrue(faults, err)
        return [line.split(": clock_out_of_range: ", 1)[1] for line in faults]

    def test_a_clock_whose_utc_conversion_overflows_is_refused_by_every_report(self) -> None:
        for clock in self.CONVERSION:
            with self.subTest(clock=clock):
                self.setUp()
                self.ingest_clock(clock)
                for kind in self.KINDS:
                    for inventory in (False, True):
                        messages = self.assert_clock_refusal(
                            self.report_argv(kind, inventory=inventory), clock
                        )
                        # Coverage converts all six observations; a report, each case's first.
                        self.assertEqual(len(messages), 6 if inventory else 3)

    def test_the_conversion_message_names_the_case_and_the_clock(self) -> None:
        self.ingest_clock(self.CONVERSION[0])

        code, _, err = run(self.report_argv("vdt"))

        self.assertEqual(code, 1)
        self.assertEqual(
            err.splitlines()[0],
            "error: clock_out_of_range: case-9bed0d8f88355393 has detection time "
            "0001-01-01T00:00:00+01:00 in history, which has no UTC instant inside the years "
            "1 to 9999, so no report can compute with it [V-260469]",
        )

    def test_a_detection_time_whose_deadline_overflows_is_refused_under_its_class(self) -> None:
        self.ingest_clock(self.DEADLINE_BOTH)
        for kind in self.KINDS:
            for certification_class in ("B", "C"):
                self.assert_clock_refusal(self.report_argv(kind, certification_class), "9999")

    def test_a_deadline_only_one_class_overflows_is_refused_only_under_it(self) -> None:
        self.ingest_clock(self.DEADLINE_B)
        for kind in self.KINDS:
            with self.subTest(kind=kind):
                messages = self.assert_clock_refusal(self.report_argv(kind, "B"), "9999")
                self.assertIn("VER-TFR-EVU deadline under Class B", messages[0])
                self.succeeds(self.report_argv(kind, "C"))

    def test_correlate_refuses_a_conversion_overflow_and_appends_nothing(self) -> None:
        for clock in self.CONVERSION:
            with self.subTest(clock=clock):
                self.setUp()
                self.ingest_clock(clock)
                before = self.latest_sequence()

                code, out, err = run(["cases", "correlate", "--db", str(self.database)])

                self.assertEqual((code, out), (1, ""))
                self.assertEqual(len(err.splitlines()), 1)
                self.assertTrue(err.startswith("error: history_invalid: observation obs-"), err)
                self.assertIn(f"has source time {clock} in history", err)
                self.assertEqual(self.latest_sequence(), before)

    def test_correlate_links_a_clock_only_a_deadline_overflows(self) -> None:
        self.ingest_clock(self.DEADLINE_BOTH)

        self.correlate()

    def test_cases_coverage_refuses_a_conversion_overflow_and_appends_nothing(self) -> None:
        self.ingest_clock(self.CONVERSION[0])
        before = self.latest_sequence()

        argv = ["cases", "coverage", "--db", str(self.database), "--class", "C"]
        argv += ["--as-of", INGESTED_AT, "--inventory", str(EXAMPLE_INVENTORY)]
        self.assert_clock_refusal(argv, self.CONVERSION[0])
        self.assertEqual(self.latest_sequence(), before)

    def test_store_verify_names_each_clock_in_the_words_a_reader_refuses_it_with(self) -> None:
        for clock, argv in (
            (self.CONVERSION[0], lambda: self.report_argv("vdt", inventory=True)),
            (self.CONVERSION[1], lambda: self.report_argv("vdt", inventory=True)),
            (self.DEADLINE_BOTH, lambda: self.report_argv("vdt", "B")),
            (self.DEADLINE_B, lambda: self.report_argv("vdt", "B")),
        ):
            with self.subTest(clock=clock):
                self.setUp()
                self.ingest_clock(clock)
                refused = self.assert_clock_refusal(argv(), clock[:4])
                self.assertEqual(self.verify_faults(), refused)

    def test_clocks_that_reported_before_still_report_and_verify(self) -> None:
        for clock in self.REPORTED:
            with self.subTest(clock=clock):
                self.setUp()
                path = self.ingest_clock(clock)
                self.succeeds(["store", "verify", "--db", str(self.database)])
                for kind in self.KINDS:
                    for certification_class in ("B", "C"):
                        argv = self.report_argv(kind, certification_class, inventory=True)
                        persisted, _ = self.succeeds(argv)
                        stateless = [*argv[:2], str(path), *argv[4:]]
                        stateless += ["--detected-at", ATTESTED_AT]
                        with unguarded_stig_clocks():
                            direct, _ = self.succeeds(stateless)
                        self.assertEqual(persisted, direct)
                self.correlate()
                self.succeeds(["store", "verify", "--db", str(self.database)])

    def test_an_evaluated_case_that_gains_such_a_clock_is_a_fault_not_a_traceback(self) -> None:
        # The order check resolves the group's detection time, which converted the clock.
        self.ingest_clock("2026-08-03T09:00:00Z", "timed.cklb")
        self.correlate()
        payload = json.loads((EXAMPLES / "evaluations.json").read_text(encoding="utf-8"))
        payload["evaluations"] = payload["evaluations"][:1]
        evaluations = self.workspace / "ubuntu-evaluation.json"
        evaluations.write_text(json.dumps(payload), encoding="utf-8")
        self.evaluate(evaluations)
        self.ingest_clock(self.CONVERSION[0], "year-one.cklb")

        faults = self.verify_faults()

        self.assertEqual(len(faults), 6)
        self.assert_clock_refusal(self.report_argv("vdt"), self.CONVERSION[0])
        self.evaluate(evaluations)


#: A duplicated key that would print as its own `error:` line, and clear the screen, if it
#: reached stderr raw.
FORGED_KEY = "a\\nerror: forged: injected\\u001b[2J"


def forged_lines(err: str) -> list[str]:
    """Return every stderr line that begins as a forged diagnostic would."""

    return [line for line in err.splitlines() if line.startswith("error: forged")]


class InputRefusalCommandTests(unittest.TestCase):
    """Input files the CLI refuses with one coded line and no traceback (cleanup PR 5a).

    `main` runs in this process, so a traceback is an exception out of `run` and fails the
    test; each refusal is also checked for its code, since a wrong code is the other way
    these inputs used to fail.
    """

    def setUp(self) -> None:
        workspace = tempfile.TemporaryDirectory()
        self.addCleanup(workspace.cleanup)
        self.workspace = Path(workspace.name)
        # Sized against the default digit limit, not whatever PYTHONINTMAXSTRDIGITS set.
        self.addCleanup(sys.set_int_max_str_digits, sys.get_int_max_str_digits())
        sys.set_int_max_str_digits(sys.int_info.default_max_str_digits)

    def write(self, name: str, text: str) -> Path:
        path = self.workspace / name
        path.write_text(text, encoding="utf-8")
        return path

    def loop(self, name: str) -> Path:
        link = self.workspace / name
        link.symlink_to(link)
        return link

    def report_with(
        self,
        *,
        artifact: Path | None = None,
        evaluations: Path | None = None,
        ubuntu: Path | None = None,
    ):
        """Run the fixture report with its artifacts, evaluations or Ubuntu checklist swapped."""

        argv = list(REPORT_ARGUMENTS)
        if ubuntu is not None:
            argv[2] = str(ubuntu)
        if artifact is not None:
            argv[2:5] = [str(artifact)]
        if evaluations is not None:
            argv[argv.index("--evaluations") + 1] = str(evaluations)
        return run(argv)

    def test_validate_quotes_a_duplicate_key(self) -> None:
        path = self.write("report.json", f'{{"{FORGED_KEY}": 1, "{FORGED_KEY}": 2}}')

        code, out, err = run(["validate", str(path), "--schema", "vulnerability-detail"])

        self.assertEqual(code, 1)
        self.assertEqual(out, "")
        self.assertEqual(forged_lines(err), [])
        self.assertNotIn("\x1b", err)
        self.assertEqual(
            err,
            "error: report_malformed: duplicate JSON object key is prohibited: "
            f"'a\\nerror: forged: injected\\x1b[2J' [{path}]\n",
        )

    def test_evaluations_quote_a_duplicate_key(self) -> None:
        evaluations = self.write("evaluations.json", f'{{"{FORGED_KEY}": 1, "{FORGED_KEY}": 2}}')

        code, out, err = self.report_with(evaluations=evaluations)

        self.assertEqual(code, 1)
        self.assertEqual(out, "")
        self.assertEqual(forged_lines(err), [])
        self.assertEqual(
            err,
            "error: invalid_input: duplicate JSON object key is prohibited: "
            "'a\\nerror: forged: injected\\x1b[2J'\n",
        )

    def test_validate_refuses_an_integer_past_the_digit_limit(self) -> None:
        limit = sys.int_info.default_max_str_digits
        path = self.write("report.json", '{"n": ' + "9" * 5000 + "}")

        code, out, err = run(["validate", str(path), "--schema", "vulnerability-detail"])

        self.assertEqual(code, 1)
        self.assertEqual(out, "")
        self.assertEqual(
            err,
            f"error: report_malformed: report contains an integer longer than {limit} digits "
            f"[{path}]\n",
        )

    def test_evaluations_refuse_an_integer_past_the_digit_limit_as_input(self) -> None:
        limit = sys.int_info.default_max_str_digits
        evaluations = self.write("evaluations.json", '{"n": ' + "9" * 5000 + "}")

        code, out, err = self.report_with(evaluations=evaluations)

        self.assertEqual(code, 1)
        self.assertEqual(out, "")
        self.assertEqual(
            err,
            "error: invalid_input: evaluations file contains an integer longer than "
            f"{limit} digits\n",
        )

    def test_an_artifact_that_is_a_symlink_loop_is_an_artifact_read_failure(self) -> None:
        loop = self.loop("loop.ckl")

        code, out, err = self.report_with(artifact=loop)

        self.assertEqual(code, 1)
        self.assertEqual(out, "")
        self.assertTrue(err.startswith("error: artifact_read_failed: "), err)
        self.assertEqual(len(err.splitlines()), 1)

    def test_a_clock_flag_outside_the_supported_years_is_refused_coded(self) -> None:
        # Year 1 used to overflow in the compiler and end the run in a traceback.
        for flag in ("--as-of", "--from", "--to", "--detected-at"):
            for value in ("0001-01-01T00:00:00Z", "9999-12-31T23:59:59Z"):
                with self.subTest(flag=flag, value=value):
                    argv = list(REPORT_ARGUMENTS)
                    argv[argv.index(flag) + 1] = value
                    code, out, err = run(argv)
                    self.assertEqual((code, out), (1, ""))
                    self.assertEqual(
                        err,
                        f"error: invalid_input: {flag} must fall in the years 1970 through 9000 "
                        f"UTC, got '{value}'\n",
                    )

    def test_a_long_clock_flag_is_refused_without_being_echoed(self) -> None:
        argv = list(REPORT_ARGUMENTS)
        argv[argv.index("--as-of") + 1] = "2" * 100_000

        code, out, err = run(argv)

        self.assertEqual((code, out), (1, ""))
        self.assertEqual(
            err, "error: invalid_input: --as-of must be at most 64 characters, got 100000\n"
        )

    def test_ingest_refuses_an_unsupported_as_of_and_creates_no_store(self) -> None:
        database = self.workspace / "history.db"

        code, out, err = run(
            [
                "ingest",
                str(FIXTURES / "ubuntu-host.cklb"),
                "--db",
                str(database),
                "--as-of",
                "2026-08-21T12:00:00+05:30:15",
            ]
        )

        self.assertEqual((code, out), (1, ""))
        self.assertEqual(
            err,
            "error: invalid_input: --as-of must have a UTC offset in whole minutes, got "
            "'2026-08-21T12:00:00+05:30:15'\n",
        )
        self.assertFalse(database.exists())

    def test_a_checklist_clock_no_report_can_compute_with_is_read_as_absent(self) -> None:
        # Year 9999 used to ingest and then overflow the deadline arithmetic in every report.
        document = json.loads((FIXTURES / "ubuntu-host.cklb").read_text(encoding="utf-8"))
        document["completed_at"] = "9999-12-31T23:59:59Z"
        artifact = self.write("ubuntu-host.cklb", json.dumps(document))

        code, out, err = self.report_with(ubuntu=artifact)

        self.assertEqual(code, 0, err)
        self.assertIn("warning: source_timestamp_missing:", err)
        self.assertNotIn("9999", out)

    def test_a_symlink_loop_is_refused_alike_where_resolve_raises(self) -> None:
        # Python 3.11's Path.resolve raises RuntimeError on a loop, where 3.13 and later
        # return the path; the overwrite check must not depend on which one runs it.
        real = Path.resolve

        def resolve(path: Path, strict: bool = False) -> Path:
            if path.name.startswith("loop"):
                raise RuntimeError(f"Symlink loop from {str(path)!r}")
            return real(path, strict=strict)

        artifact = self.loop("loop.ckl")
        evaluations = self.loop("loop-evaluations.json")
        with patch.object(Path, "resolve", resolve):
            artifact_run = self.report_with(artifact=artifact)
            evaluations_run = self.report_with(evaluations=evaluations)

        code, out, err = artifact_run
        self.assertEqual((code, out), (1, ""))
        self.assertTrue(err.startswith("error: artifact_read_failed: "), err)
        code, out, err = evaluations_run
        self.assertEqual((code, out), (1, ""))
        self.assertTrue(
            err.startswith("error: invalid_input: evaluations file cannot be read"), err
        )


if __name__ == "__main__":
    unittest.main()
