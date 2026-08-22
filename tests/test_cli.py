from __future__ import annotations

import io
import json
import shutil
import sqlite3
import tempfile
import unittest
from collections.abc import Sequence
from contextlib import closing, redirect_stderr, redirect_stdout, suppress
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from complyroll import __version__
from complyroll.adapters import ingest_stig_artifact
from complyroll.cli import main
from complyroll.events import EventRepository
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
            out,
            "attested 6 case(s), skipped 0 unchanged case(s), 0 not applicable case(s)\n",
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
            out,
            "attested 0 case(s), skipped 0 unchanged case(s), 0 not applicable case(s)\n",
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
    def smuggle(self, event_type: str, payload: dict[str, Any]) -> int:
        """Append one event straight to the store, past the contract the repository holds.

        `EventRepository` is the only writer that checks a payload, so this is how a
        stored event that no contract admits comes to exist: another tool, an older
        version, or a contract tightened after the event was written.
        """

        with SQLiteEventStore(self.database) as store:
            appended = store.append(
                f"artifact/{'b' * 64}/complyroll.cklb/1",
                [
                    NewEvent(
                        event_type=event_type,
                        occurred_at=datetime(2026, 8, 21, 12, 0, tzinfo=UTC),
                        payload=payload,
                        metadata={
                            "actor": "smuggler",
                            "method": "cli",
                            "tool": "complyroll",
                            "toolVersion": __version__,
                            "runId": "run-smuggled",
                        },
                    )
                ],
                expected_version=0,
            )
        return appended[0].sequence

    def test_a_clean_store_verifies_and_exits_zero(self) -> None:
        self.populate()

        out, err = self.succeeds(["store", "verify", "--db", str(self.database)])

        self.assertEqual(err, "")
        self.assertTrue(out.startswith("ok: "))
        self.assertIn("event(s) verified", out)
        # The contract pass read the whole log and found nothing to say about it.
        self.assertEqual(out, f"ok: {self.latest_sequence()} event(s) verified\n")

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
        self.assertIn(f"error: payload_contract_invalid: sequence {sequence}:", err)
        self.assertIn("/ingested_at", err)
        self.assertIn("1 payload(s) do not satisfy their published contract", err)

    def test_a_spelling_only_the_reader_refuses_is_named_and_exits_one(self) -> None:
        # The contract's pattern admits a whole second spelled with six zero digits; the
        # replay reader does not. The contract pass reads observation payloads back
        # through that reader, so verify cannot call this store healthy.
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
        self.assertIn(f"error: payload_contract_invalid: sequence {sequence}:", err)
        self.assertIn("is not readable", err)

    def test_an_event_type_no_contract_publishes_is_named_and_exits_one(self) -> None:
        self.populate()
        sequence = self.smuggle("case.retracted", {"reason": "someone changed their mind"})

        code, _, err = run(["store", "verify", "--db", str(self.database)])

        self.assertEqual(code, 1)
        self.assertIn(f"error: payload_contract_invalid: sequence {sequence}:", err)
        self.assertIn("no published contract for event 'case.retracted'", err)

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
            out,
            f"attested {len(untimestamped)} case(s), skipped 0 unchanged case(s), "
            "0 not applicable case(s)\n",
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
