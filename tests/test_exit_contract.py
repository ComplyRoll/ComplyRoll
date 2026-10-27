# ******************************************************************************
# *Title: Exit Contract Tests*
# *Author: Kyle Versluis*
# *Description: The ADR 0017 exit table: the publish guard and unpinned rows.*
# ******************************************************************************
"""Tests for the exit contract ADR 0017 Decision 1 freezes, and the guard of Decision 2."""

# *--- Imports ---*

from __future__ import annotations

import errno
import io
import json
import re
import tempfile
import unittest
from collections.abc import Callable, Iterator, Sequence
from contextlib import contextmanager, redirect_stderr, redirect_stdout
from dataclasses import replace
from pathlib import Path
from typing import Any
from unittest.mock import patch

from test_cli import (
    AVI_ARGUMENTS,
    COVERAGE_ARGUMENTS,
    CYCLONEDX_COVERAGE_ARGUMENTS,
    EXAMPLE_INVENTORY,
    FAILED_ARTIFACTS,
    HISTORICAL_ARGUMENTS,
    INGESTED_AT,
    PERSISTED_ARTIFACTS,
    REPORT_ARGUMENTS,
    PersistedStoreTestCase,
    kev_argv,
    run,
    timed_argv,
    with_failed_artifacts,
)
from test_coverage import host
from test_coverage_gap_report import (
    GAP_FLAG,
    HISTORICAL_GAP_ARGUMENTS,
    VDT_GAP_ARGUMENTS,
    write_inventory,
)
from test_reports import FAILED_EVALUATIONS, FIXTURES, GOLDEN, REPORT_KINDS

from complyroll import cli as cli_module
from complyroll.adapters import DiagnosticLevel
from complyroll.cli import main
from complyroll.compat import stigroll
from complyroll.reports import ReportDiagnostic
from complyroll.schemas import MAX_REPORT_BYTES

# *--- Fixtures ---*

#: An `error:` line on stderr, the form every ERROR diagnostic and refusal renders as.
ERROR_LINE = re.compile(r"^error:", re.MULTILINE)
#: The guard's refusal, and the ERROR a stub report carries to reach it.
UNPUBLISHED = "error: error_diagnostic_unpublished"
PLANTED_ERROR = ReportDiagnostic(
    level=DiagnosticLevel.ERROR, code="planted_error", message="a stub ERROR no input builds"
)
PLANTED_WARNING = replace(PLANTED_ERROR, level=DiagnosticLevel.WARNING, code="planted_warning")
#: The failed SARIF invocation, an execution-class failure (ADR 0014 Decision 3).
INVOCATION = FIXTURES / "failed-invocation.sarif"
#: The golden runs `tests/test_cli.py` reproduces with the flag, restated because its dict is a
#: local of one test method; each exits 0.
GOLDEN_RUNS: dict[str, Sequence[str]] = {
    "vdt-fixtures": REPORT_ARGUMENTS,
    "avi-fixtures": AVI_ARGUMENTS,
    "historical-fixtures": HISTORICAL_ARGUMENTS,
    **{f"{kind}-kev": kev_argv(kind) for kind in REPORT_KINDS},
    "vdt-coverage": COVERAGE_ARGUMENTS,
    "vdt-coverage-timed": timed_argv(),
    "vdt-cyclonedx-coverage": CYCLONEDX_COVERAGE_ARGUMENTS,
}
#: The four system goldens, each cut by a run that records its records and exits 3.
SYSTEM_RUNS: dict[str, Sequence[str]] = {
    "vdt-failed": [
        *with_failed_artifacts(REPORT_ARGUMENTS[:-1]),
        str(FAILED_EVALUATIONS),
        "--record-failed-imports",
    ],
    "historical-failed": [
        *with_failed_artifacts(HISTORICAL_ARGUMENTS[:-1]),
        str(FAILED_EVALUATIONS),
        "--record-failed-imports",
    ],
    "vdt-coverage-gaps": VDT_GAP_ARGUMENTS,
    "historical-coverage-gaps": HISTORICAL_GAP_ARGUMENTS,
}
#: The report goldens compiled through the library, which no command-line run cuts.
LIBRARY_GOLDENS = {"vdt-sarif", "vdt-hdf", "vdt-cyclonedx", "historical-cyclonedx"}
#: Each stateless report command's golden run, whose artifacts are argv[2:5].
COMMANDS = (
    ("vdt", REPORT_ARGUMENTS),
    ("avi", AVI_ARGUMENTS),
    ("historical", HISTORICAL_ARGUMENTS),
)


# *--- Helpers ---*


def error_lines(stderr: str) -> list[str]:
    return [line for line in stderr.splitlines() if ERROR_LINE.match(line)]


def report_goldens() -> set[str]:
    return {
        path.stem
        for path in GOLDEN.glob("*.json")
        if "x-complyroll" in json.loads(path.read_text(encoding="utf-8"))
    }


def levels_in(value: Any) -> Iterator[str]:
    """Yield every diagnostic `level` anywhere in a JSON value, failures' own included."""

    if isinstance(value, dict):
        level = value.get("level")
        if isinstance(level, str):
            yield level
        for item in value.values():
            yield from levels_in(item)
    elif isinstance(value, list):
        for item in value:
            yield from levels_in(item)


def with_invocation(argv: Sequence[str]) -> list[str]:
    """Add the failed invocation to a golden run, beside its own three artifacts."""

    return [*argv[:5], str(INVOCATION), *argv[5:]]


@contextmanager
def planting(diagnostic: ReportDiagnostic) -> Iterator[None]:
    """Make `report vdt` compile its real report with one more diagnostic appended.

    No input builds an ERROR that reaches `_publish`, so the stub is the real compiled
    report with the diagnostic added: the guard is the only thing that can tell them apart.
    """

    command = cli_module._REPORT_COMMAND_BY_NAME["vdt"]
    compile_stateless: Callable[..., Any] = command.stateless

    def stateless(*args: Any, **kwargs: Any) -> Any:
        report = compile_stateless(*args, **kwargs)
        return replace(report, diagnostics=(*report.diagnostics, diagnostic))

    stub = replace(command, stateless=stateless)
    with patch.dict(cli_module._REPORT_COMMAND_BY_NAME, {"vdt": stub}):
        yield


def run_stigroll(argv: Sequence[str]) -> tuple[int, str, str]:
    out = io.StringIO()
    err = io.StringIO()
    with redirect_stdout(out), redirect_stderr(err):
        code = stigroll.main(list(argv))
    return code, out.getvalue(), err.getvalue()


# *--- Publish Guard ---*


class PublishGuardTests(unittest.TestCase):
    """ADR 0017 Decision 2: a compiled report carrying an ERROR is never written."""

    def test_a_report_carrying_an_error_exits_1_and_writes_nothing(self) -> None:
        with tempfile.TemporaryDirectory() as directory, planting(PLANTED_ERROR):
            json_path = Path(directory) / "report.json"
            markdown_path = Path(directory) / "report.md"

            code, out, err = run(
                [*REPORT_ARGUMENTS, "-o", str(json_path), "--markdown", str(markdown_path)]
            )

            self.assertEqual(code, 1)
            self.assertEqual(out, "")
            lines = err.splitlines()
            self.assertIn(PLANTED_ERROR.render(), lines)
            # The report's own diagnostics come first, then the one refusal that names them.
            self.assertTrue(lines[-1].startswith(f"{UNPUBLISHED}: "), lines[-1])
            self.assertEqual(err.count(UNPUBLISHED), 1)
            self.assertFalse(json_path.exists())
            self.assertFalse(markdown_path.exists())
            self.assertEqual(list(Path(directory).iterdir()), [])

    def test_a_report_carrying_an_error_never_reaches_stdout(self) -> None:
        with planting(PLANTED_ERROR):
            code, out, err = run(REPORT_ARGUMENTS)

        self.assertEqual(code, 1)
        self.assertEqual(out, "")
        self.assertIn(UNPUBLISHED, err)

    def test_an_existing_destination_keeps_its_bytes(self) -> None:
        with tempfile.TemporaryDirectory() as directory, planting(PLANTED_ERROR):
            json_path = Path(directory) / "report.json"
            markdown_path = Path(directory) / "report.md"
            json_path.write_text("previous json\n", encoding="utf-8")
            markdown_path.write_text("previous markdown\n", encoding="utf-8")

            code, _, err = run(
                [*REPORT_ARGUMENTS, "-o", str(json_path), "--markdown", str(markdown_path)]
            )

            self.assertEqual(code, 1)
            self.assertIn(UNPUBLISHED, err)
            self.assertEqual(json_path.read_text(encoding="utf-8"), "previous json\n")
            self.assertEqual(markdown_path.read_text(encoding="utf-8"), "previous markdown\n")

    def test_a_recorded_failure_beside_the_error_still_exits_1_not_3(self) -> None:
        # Exit 3 means published; a run the guard refused published nothing.
        with tempfile.TemporaryDirectory() as directory, planting(PLANTED_ERROR):
            json_path = Path(directory) / "report.json"

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
            self.assertIn("warning: detection_failure_recorded", err)
            self.assertIn(UNPUBLISHED, err)
            self.assertFalse(json_path.exists())

    def test_a_report_carrying_only_a_warning_is_published(self) -> None:
        with tempfile.TemporaryDirectory() as directory, planting(PLANTED_WARNING):
            json_path = Path(directory) / "report.json"
            markdown_path = Path(directory) / "report.md"

            code, out, err = run(
                [*REPORT_ARGUMENTS, "-o", str(json_path), "--markdown", str(markdown_path)]
            )

            self.assertEqual(code, 0, msg=err)
            self.assertEqual(out, "")
            self.assertIn(PLANTED_WARNING.render(), err.splitlines())
            self.assertEqual(error_lines(err), [])
            self.assertTrue(json_path.is_file())
            self.assertTrue(markdown_path.is_file())


# *--- Invariant I1 ---*


class ErrorDiagnosticInvariantTests(unittest.TestCase):
    """I1: no written report, and no exit 0 or 3, carries an ERROR diagnostic."""

    def test_no_report_golden_carries_an_error_diagnostic(self) -> None:
        names = report_goldens()
        self.assertEqual(names, {*GOLDEN_RUNS, *SYSTEM_RUNS, *LIBRARY_GOLDENS})
        for name in sorted(names):
            with self.subTest(golden=name):
                document = json.loads((GOLDEN / f"{name}.json").read_text(encoding="utf-8"))
                levels = list(levels_in(document["x-complyroll"]))

                self.assertTrue(levels, "every report golden carries some diagnostic")
                self.assertLessEqual(set(levels), {"warning", "info"})

    def test_every_golden_run_exiting_0_or_3_prints_no_error_line(self) -> None:
        runs: list[tuple[str, Sequence[str], int]] = [
            *((name, argv, 0) for name, argv in GOLDEN_RUNS.items()),
            *(
                (f"{name} --record-failed-imports", [*argv, "--record-failed-imports"], 0)
                for name, argv in GOLDEN_RUNS.items()
            ),
            *((name, argv, 3) for name, argv in SYSTEM_RUNS.items()),
        ]
        for name, argv, status in runs:
            with self.subTest(run=name), tempfile.TemporaryDirectory() as directory:
                json_path = Path(directory) / "report.json"
                markdown_path = Path(directory) / "report.md"

                code, _, err = run([*argv, "-o", str(json_path), "--markdown", str(markdown_path)])

                self.assertEqual(code, status, msg=err)
                self.assertEqual(error_lines(err), [])
                self.assertTrue(json_path.is_file())


# *--- Stateless Report Rows ---*


class UnflaggedExecutionFailureTests(unittest.TestCase):
    """An execution-class failure without the flag stays a WARNING and exits 0."""

    def test_a_failed_invocation_without_the_flag_publishes_and_exits_0(self) -> None:
        for command, argv in COMMANDS:
            with self.subTest(command=command), tempfile.TemporaryDirectory() as directory:
                json_path = Path(directory) / "report.json"

                code, out, err = run([*with_invocation(argv), "-o", str(json_path)])

                self.assertEqual(code, 0, msg=err)
                self.assertEqual(out, "")
                self.assertIn(
                    "warning: execution_unsuccessful: invocation reports executionSuccessful "
                    "false; its results are read unless the run is refused (1 occurrence: "
                    "runs[1].invocations[0]) [failed-invocation.sarif]",
                    err.splitlines(),
                )
                self.assertNotIn("detection_failure_recorded", err)
                self.assertEqual(error_lines(err), [])
                extension = json.loads(json_path.read_text(encoding="utf-8"))["x-complyroll"]
                self.assertNotIn("detectionFailures", extension)

    def test_the_same_run_with_the_flag_exits_3(self) -> None:
        for command, argv in COMMANDS:
            with self.subTest(command=command):
                code, out, err = run([*with_invocation(argv), "--record-failed-imports"])

                self.assertEqual(code, 3, msg=err)
                self.assertEqual(error_lines(err), [])
                failures = json.loads(out)["x-complyroll"]["detectionFailures"]
                self.assertEqual([item["name"] for item in failures], [INVOCATION.name])


class OutsidePeriodRecordTests(unittest.TestCase):
    """ADR 0015 Decision 31: a record the period excludes still makes the run exit 3."""

    def test_a_gap_recorded_after_the_period_still_exits_3(self) -> None:
        argv = list(REPORT_ARGUMENTS)
        argv[argv.index("--as-of") + 1] = "2026-09-21T12:00:00Z"
        with tempfile.TemporaryDirectory() as directory:
            # A host expected from September has no window to close inside August.
            inventory = write_inventory(
                Path(directory), host("lab-later-01", expectedSince="2026-09-01T00:00:00Z")
            )

            code, out, err = run([*argv, "--inventory", str(inventory), GAP_FLAG])

        self.assertEqual(code, 3, msg=err)
        self.assertEqual(error_lines(err), [])
        document = json.loads(out)
        windows = document["x-complyroll"]["coverage"]["windows"]
        self.assertTrue(windows)
        for window in windows:
            self.assertIs(window["recorded"], True)
            self.assertGreater(window["closedAt"], "2026-08-31T23:59:59Z")
        reported = {item["providerTrackingId"] for item in document["vulnerabilities"]}
        self.assertFalse({window["trackingId"] for window in windows} & reported)
        self.assertEqual(document["x-complyroll"]["excludedByPeriod"], len(windows))


# *--- Persisted Rows ---*


class StoreWithFailuresAndGapsTests(PersistedStoreTestCase):
    """I4: `report --db` and `store verify` exit 0 over a store holding both kinds of record."""

    def setUp(self) -> None:
        super().setUp()
        code, _, err = run(
            [
                "ingest",
                *PERSISTED_ARTIFACTS,
                *FAILED_ARTIFACTS,
                "--db",
                str(self.database),
                "--as-of",
                INGESTED_AT,
                "--record-failed-imports",
            ]
        )
        self.assertEqual(code, 3, msg=err)
        self.correlate()
        self.attest_missing()
        self.evaluate()
        code, _, err = run(
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
        self.assertEqual(code, 3, msg=err)

    def report_argv(self, kind: str) -> list[str]:
        argv = ["report", kind, "--db", str(self.database), "--class", "C"]
        argv += ["--package-uri", "https://example.test/cpo", "--as-of", INGESTED_AT]
        if kind != "historical":
            argv += ["--from", "2026-08-01T00:00:00Z", "--to", "2026-08-31T23:59:59Z"]
        return argv

    def test_a_report_from_the_store_exits_0(self) -> None:
        for kind in REPORT_KINDS:
            for extra in ((), ("--inventory", str(EXAMPLE_INVENTORY))):
                with self.subTest(report=kind, inventory=bool(extra)):
                    code, out, err = run([*self.report_argv(kind), *extra])

                    self.assertEqual(code, 0, msg=err)
                    self.assertEqual(error_lines(err), [])
                    extension = json.loads(out)["x-complyroll"]
                    self.assertEqual(
                        sorted(item["name"] for item in extension["detectionFailures"]),
                        sorted(Path(path).name for path in FAILED_ARTIFACTS),
                    )
                    if extra:
                        windows = extension["coverage"]["windows"]
                        self.assertTrue(windows)
                        self.assertEqual({window["recorded"] for window in windows}, {True})

    def test_store_verify_exits_0(self) -> None:
        code, out, err = run(["store", "verify", "--db", str(self.database)])

        self.assertEqual(code, 0, msg=err)
        self.assertRegex(out, r"^ok: \d+ event\(s\) verified\n$")
        self.assertEqual(err, "")


# *--- Validate And Stigroll Rows ---*


class ValidateExitTests(unittest.TestCase):
    """`validate` reads the official document only, and its issue lines carry no prefix."""

    def test_schema_issue_lines_carry_no_error_prefix(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "report.json"
            path.write_text(json.dumps({"vulnerabilities": []}), encoding="utf-8")

            code, out, err = run(["validate", str(path), "--schema", "vulnerability-detail"])

        self.assertEqual(code, 1)
        self.assertEqual(out, "")
        lines = err.splitlines()
        self.assertGreater(len(lines), 1)
        self.assertEqual(error_lines(err), [])
        self.assertTrue(lines[-1].startswith("schema: "), lines[-1])
        for line in lines[:-1]:
            self.assertRegex(line, r"^\S+: \S+: ")

    def test_an_error_inside_the_extension_is_never_read(self) -> None:
        document = json.loads((GOLDEN / "vdt-failed.json").read_text(encoding="utf-8"))
        document["x-complyroll"]["diagnostics"].append(PLANTED_ERROR.to_dict())
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "report.json"
            path.write_text(json.dumps(document), encoding="utf-8")

            code, out, err = run(["validate", str(path), "--schema", "vulnerability-detail"])

        self.assertEqual(code, 0, msg=err)
        self.assertTrue(out.startswith("valid: "), out)
        self.assertEqual(err, "")

    def test_a_report_over_the_size_limit_exits_1_unread(self) -> None:
        # The limit is checked on the file's size before any byte is read, so a sparse
        # file one byte over it is a real oversize report that costs no disk.
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "report.json"
            with path.open("wb") as handle:
                handle.truncate(MAX_REPORT_BYTES + 1)

            code, out, err = run(["validate", str(path), "--schema", "vulnerability-detail"])

        self.assertEqual(code, 1)
        self.assertEqual(out, "")
        self.assertEqual(
            err,
            f"error: report_too_large: report is {MAX_REPORT_BYTES + 1} bytes; maximum is "
            f"{MAX_REPORT_BYTES} bytes [{path}]\n",
        )


class StigrollExitTests(unittest.TestCase):
    """`stigroll` answers 0 when any input yielded findings, else 1 or a traceback."""

    def test_a_checklist_that_fails_to_parse_beside_a_good_one_exits_0(self) -> None:
        checklist = str(FIXTURES / "ubuntu-host.cklb")
        alone = run_stigroll([checklist, "--format", "csv"])
        with tempfile.TemporaryDirectory() as directory:
            broken = Path(directory) / "broken.cklb"
            broken.write_text("{", encoding="utf-8")

            code, out, err = run_stigroll([str(broken), checklist, "--format", "csv"])

        self.assertEqual(alone[0], 0)
        self.assertEqual(code, 0)
        self.assertEqual(out, alone[1])
        self.assertTrue(err.startswith("warning: could not parse broken.cklb: "), err)
        self.assertEqual(error_lines(err), [])

    def test_a_missing_or_unreadable_cci_list_exits_1(self) -> None:
        checklist = str(FIXTURES / "windows-host.ckl")
        with tempfile.TemporaryDirectory() as directory:
            missing = Path(directory) / "missing.xml"
            malformed = Path(directory) / "malformed.xml"
            malformed.write_text("<not-closed", encoding="utf-8")
            for path, line in (
                (missing, "error: CCI list not found: "),
                (malformed, "error: could not parse malformed.xml: "),
            ):
                with self.subTest(cci_list=path.name):
                    code, out, err = run_stigroll([checklist, "--cci-list", str(path)])

                    self.assertEqual(code, 1)
                    self.assertEqual(out, "")
                    self.assertTrue(error_lines(err)[0].startswith(line), err)

    def test_an_output_write_failure_is_a_traceback(self) -> None:
        with tempfile.TemporaryDirectory() as directory, self.assertRaises(OSError):
            run_stigroll([str(FIXTURES / "windows-host.ckl"), "-o", directory])


# *--- Edges Outside The Contract ---*


class UncontractedEdgeTests(unittest.TestCase):
    """The edges ADR 0017 Decisions 1 and 12 name and pin as they are."""

    def test_version_and_plan_reach_1_only_through_an_uncaught_exception(self) -> None:
        for command in ("version", "plan"):
            with (
                self.subTest(command=command),
                patch.object(cli_module, "print", create=True, side_effect=ValueError("simulated")),
                self.assertRaises(ValueError),
            ):
                main([command])

    def test_a_broken_pipe_inside_an_action_reads_as_store_unavailable(self) -> None:
        def action() -> int:
            raise BrokenPipeError(errno.EPIPE, "Broken pipe")

        stream = io.StringIO()

        self.assertEqual(cli_module._persisted_run(stream, action), 1)
        self.assertTrue(stream.getvalue().startswith("error: store_unavailable: "))


if __name__ == "__main__":
    unittest.main()
