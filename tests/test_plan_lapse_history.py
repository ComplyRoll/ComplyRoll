# ******************************************************************************
# *Title: Plan Lapse History Tests*
# *Author: Kyle Versluis*
# *Description: cases response-gaps records lapsed plans; notes and the golden.*
# ******************************************************************************
"""Tests that a store records a lapsed planned response once and reports it (plan D7, D10)."""

# *--- Imports ---*

from __future__ import annotations

import json
import sqlite3
import unittest
from contextlib import closing
from datetime import UTC, datetime
from typing import Any

from test_cli import PLANNED_ARTIFACT, PLANNED_EVALUATIONS, PersistedStoreTestCase, run
from test_coverage_streams import metadata
from test_evaluation_order import orphan_created
from test_reports import GOLDEN

from complyroll.events import EventRepository, case_stream_id
from complyroll.history import writers as history_writers
from complyroll.reports import parse_evaluations
from complyroll.schemas import ReportSchema, validate_bundled_report_bytes
from complyroll.store import SQLiteEventStore

# *--- Fixtures ---*

GOLDEN_NAME = "historical-planned-response"
INGEST_TEXT = "2026-09-03T00:00:00Z"
#: The fixture's plan: N2 by 11 September 16:00, stated by the evaluation of 4 September.
PLANNED_TEXT = "2026-09-11T16:00:00Z"
#: The run that records the lapse, as the warning golden's report reads the same store.
AS_OF_TEXT = "2026-09-15T12:00:00Z"
OPTIONS = ("--class", "C", "--as-of", AS_OF_TEXT)
REPORT = (
    "--class",
    "C",
    "--package-uri",
    "https://example.test/cpo",
    "--calendar-tz",
    "UTC",
    "--as-of",
    AS_OF_TEXT,
)
PLANNED_CASE = "case-748ec5056f5557ed"
PLAN_LINE = f"planned reduction of {PLANNED_CASE} to N2 was not recorded by {PLANNED_TEXT}"
ORPHAN_CASE = "case-00000000000000ff"
WARNING = "planned_reduction_lapsed"


class StoreCase(PersistedStoreTestCase):
    """A store driven only through the command line, as an operator records lapsed plans."""

    def cr(self, *argv: str) -> tuple[int, str, str]:
        return run([*argv[:2], "--db", str(self.database), *argv[2:]])

    def response_gaps(self, *options: str) -> tuple[int, str, str]:
        return self.cr("cases", "response-gaps", *(options or OPTIONS), "--actor", "golden")

    def plan(self) -> None:
        """Ingest the scan, open its case, and evaluate it with the planned fixture."""
        self.succeeds(
            ["ingest", PLANNED_ARTIFACT, "--db", str(self.database), "--as-of", INGEST_TEXT]
        )
        self.succeeds(["cases", "correlate", "--db", str(self.database)])
        self.succeeds(
            [
                "cases",
                "evaluate",
                "--db",
                str(self.database),
                "--evaluations",
                str(PLANNED_EVALUATIONS),
            ]
        )

    def build_golden_store(self) -> None:
        """The golden recipe: plan, record the lapse, then open its case."""
        self.plan()
        code, _, err = self.response_gaps()
        self.assertEqual(code, 3, msg=err)
        self.succeeds(["cases", "correlate", "--db", str(self.database)])

    def reevaluate(self, **overrides: Any) -> None:
        """File the fixture's evaluation again with fields replaced, None dropping one."""
        entry = dict(json.loads(PLANNED_EVALUATIONS.read_text(encoding="utf-8"))["evaluations"][0])
        entry.update(overrides)
        entry = {key: value for key, value in entry.items() if value is not None}
        path = self.workspace / f"evaluations-{len(list(self.workspace.iterdir()))}.json"
        path.write_text(json.dumps({"evaluations": [entry]}), encoding="utf-8")
        self.succeeds(["cases", "evaluate", "--db", str(self.database), "--evaluations", str(path)])

    def report(self, *extra: str, as_of: str = AS_OF_TEXT) -> tuple[int, str, str]:
        options = [*REPORT[:-1], as_of]
        return run(["report", "historical", "--db", str(self.database), *options, *extra])

    def diagnostics(self, as_of: str = AS_OF_TEXT) -> list[dict[str, Any]]:
        path = self.workspace / "diagnostics.json"
        code, _, err = self.report("-o", str(path), as_of=as_of)
        self.assertEqual(code, 0, msg=err)
        document = json.loads(path.read_text(encoding="utf-8"))
        return list(document["x-complyroll"]["diagnostics"])

    def codes(self, as_of: str = AS_OF_TEXT) -> list[str]:
        return [item["code"] for item in self.diagnostics(as_of)]

    def schema_version(self) -> int:
        with closing(sqlite3.connect(self.database)) as connection:
            return int(connection.execute("PRAGMA user_version").fetchone()[0])

    def event_count(self) -> int:
        with closing(sqlite3.connect(self.database)) as connection:
            return int(connection.execute("SELECT COUNT(*) FROM events").fetchone()[0])

    def recorded_ids(self, out: str) -> list[str]:
        return [line.split(":", 1)[0] for line in out.splitlines() if ": recorded " in line]


# *--- Command ---*


class PlanLapseCommandTests(StoreCase):
    """`cases response-gaps` records a lapsed plan once, exits 3 when it records, 0 otherwise."""

    def test_the_run_records_the_lapse_marks_schema_8_and_a_rerun_records_none(self) -> None:
        self.plan()
        self.assertEqual(self.schema_version(), 1)
        code, out, err = self.response_gaps()
        self.assertEqual((code, err), (3, ""))
        (plan_id,) = self.recorded_ids(out)
        self.assertEqual(
            out.splitlines(),
            [
                f"{plan_id}: recorded {PLAN_LINE}",
                "recorded 1 response gap(s), skipped 0 already-recorded response gap(s)",
            ],
        )
        self.assertEqual(self.schema_version(), 8)
        count = self.event_count()
        code, out, err = self.response_gaps()
        self.assertEqual((code, err), (0, ""))
        self.assertEqual(
            out.splitlines(),
            [
                f"{plan_id}: already_recorded {PLAN_LINE}",
                "recorded 0 response gap(s), skipped 1 already-recorded response gap(s)",
            ],
        )
        self.assertEqual(self.event_count(), count)
        out, err = self.succeeds(["store", "verify", "--db", str(self.database)])
        self.assertTrue(out.startswith("ok: "), msg=err)

    def test_a_run_at_the_planned_time_records_nothing_and_one_second_later_records(self) -> None:
        self.plan()
        code, out, _ = self.response_gaps("--class", "C", "--as-of", PLANNED_TEXT)
        self.assertEqual(
            (code, out),
            (0, "recorded 0 response gap(s), skipped 0 already-recorded response gap(s)\n"),
        )
        self.assertEqual(self.schema_version(), 1)
        code, out, _ = self.response_gaps("--class", "C", "--as-of", "2026-09-11T16:00:01Z")
        self.assertEqual(code, 3)
        self.assertIn(f": recorded {PLAN_LINE}", out)

    def test_the_class_does_not_move_the_record(self) -> None:
        # No class or calendar zone enters the identity, so a run under the other class finds
        # the same record already there (plan D10: unmatched cannot arise for this kind).
        self.plan()
        _, first, _ = self.response_gaps()
        code, out, _ = self.response_gaps(
            "--class", "B", "--as-of", AS_OF_TEXT, "--calendar-tz", "America/New_York"
        )
        self.assertEqual(code, 0)
        self.assertIn(f"{self.recorded_ids(first)[0]}: already_recorded {PLAN_LINE}", out)

    def test_a_restated_plan_is_the_same_record(self) -> None:
        self.plan()
        _, first, _ = self.response_gaps()
        self.reevaluate(completedAt="2026-09-14T09:00:00Z", rationale="SYNTHETIC. Re-reviewed.")
        code, out, _ = self.response_gaps()
        self.assertEqual(code, 0)
        self.assertIn(f"{self.recorded_ids(first)[0]}: already_recorded {PLAN_LINE}", out)

    def test_a_new_plan_that_also_lapses_is_a_second_case_and_the_first_stands(self) -> None:
        self.plan()
        _, first, _ = self.response_gaps()
        self.reevaluate(
            completedAt="2026-09-14T09:00:00Z",
            projectedNextReduction={"estimatedAt": "2026-09-18T16:00:00Z", "targetRating": 2},
        )
        code, out, _ = self.response_gaps("--class", "C", "--as-of", "2026-09-20T00:00:00Z")
        self.assertEqual(code, 3)
        second = (
            f"planned reduction of {PLANNED_CASE} to N2 was not recorded by 2026-09-18T16:00:00Z"
        )
        self.assertEqual(out.splitlines()[0].split(": ", 1)[1], f"recorded {second}")
        self.assertNotEqual(self.recorded_ids(out), self.recorded_ids(first))
        self.succeeds(["cases", "correlate", "--db", str(self.database)])
        codes = self.codes("2026-09-20T00:00:00Z")
        # The revised plan does not undo the first record: it stands with no note.
        self.assertEqual(codes.count(WARNING), 1)
        self.assertNotIn("response_gap_contradicted", codes)
        self.assertNotIn("response_gap_unmatched", codes)
        self.assertNotIn("response_gap_unrecorded", codes)

    def test_a_provider_tracking_id_does_not_move_the_record(self) -> None:
        self.plan()
        self.reevaluate(trackingId="PROVIDER-PLAN-7")
        code, out, _ = self.response_gaps()
        self.assertEqual(code, 3)
        self.assertIn(f": recorded {PLAN_LINE}", out)
        with_override = self.recorded_ids(out)
        self.setUp()
        self.plan()
        _, plain, _ = self.response_gaps()
        self.assertEqual(with_override, self.recorded_ids(plain))

    def test_a_met_or_excluded_plan_records_nothing(self) -> None:
        for label, overrides in (
            ("met", {"painReductionEvents": [{"reducedAt": "2026-09-08T10:00:00Z", "rating": 2}]}),
            ("fully mitigated", {"disposition": "fully_mitigated"}),
            ("no plan", {"projectedNextReduction": None}),
        ):
            with self.subTest(label):
                self.setUp()
                self.plan()
                self.reevaluate(**overrides)
                code, out, _ = self.response_gaps()
                self.assertEqual(code, 0, msg=out)
                self.assertNotIn("planned reduction", out)

    def test_a_stale_case_neither_warns_nor_records(self) -> None:
        # A case no current open observation matches is in no report (plan F2).
        self.plan()
        entry = {
            "match": {
                "sourceRecordId": "V-000001",
                "sourceType": "ckl",
                "contextKey": "Retired Windows STIG",
            },
            **{
                key: value
                for key, value in json.loads(PLANNED_EVALUATIONS.read_text(encoding="utf-8"))[
                    "evaluations"
                ][0].items()
                if key not in ("match", "painReductionEvents")
            },
        }
        evaluation = parse_evaluations(json.dumps({"evaluations": [entry]}).encode("utf-8"))
        written = datetime(2026, 9, 4, 15, 0, tzinfo=UTC)
        with SQLiteEventStore(self.database) as store:
            repository = EventRepository(store)
            stream = case_stream_id(ORPHAN_CASE)
            for version, (event_type, payload) in enumerate(
                (
                    ("case.created", orphan_created(ORPHAN_CASE)),
                    (
                        "case.evaluated",
                        history_writers._evaluation_payload(evaluation.entries[0]),
                    ),
                )
            ):
                repository.append(
                    stream,
                    event_type,
                    payload,
                    occurred_at=written,
                    metadata=metadata(),
                    expected_version=version,
                )
        code, out, _ = self.response_gaps()
        self.assertEqual(code, 3)
        self.assertNotIn(ORPHAN_CASE, out)
        self.assertEqual(len(self.recorded_ids(out)), 1)
        diagnostics = self.diagnostics()
        warned = [item["message"] for item in diagnostics if item["code"] == WARNING]
        self.assertEqual(len(warned), 1)
        self.assertNotIn(ORPHAN_CASE, warned[0])
        self.assertIn("stale_case", [item["code"] for item in diagnostics])


class ReportedEvaluationRefusalTests(StoreCase):
    """The run reads the evaluations a report reads, so it refuses what a report refuses."""

    def test_a_disposition_with_no_evaluation_is_refused_by_the_run_and_named_by_verify(
        self,
    ) -> None:
        self.plan()
        written = datetime(2026, 9, 4, 15, 0, tzinfo=UTC)
        with SQLiteEventStore(self.database) as store:
            repository = EventRepository(store)
            stream = case_stream_id(ORPHAN_CASE)
            disposition = {
                "status": "partially_mitigated",
                "closedDisposition": None,
                "acceptanceRationale": None,
                "recordedAt": "2026-09-04T15:00:00Z",
            }
            for version, (event_type, payload) in enumerate(
                (
                    ("case.created", orphan_created(ORPHAN_CASE)),
                    ("case.disposition_recorded", disposition),
                )
            ):
                repository.append(
                    stream,
                    event_type,
                    payload,
                    occurred_at=written,
                    metadata=metadata(),
                    expected_version=version,
                )
        count = self.event_count()
        code, out, err = self.response_gaps()
        self.assertEqual((code, out), (1, ""), msg=err)
        self.assertIn(
            f"error: disposition_without_evaluation: {ORPHAN_CASE} records disposition "
            "'partially_mitigated' with no evaluation",
            err,
        )
        self.assertEqual(self.event_count(), count)
        code, _, err = run(["store", "verify", "--db", str(self.database)])
        self.assertEqual(code, 1)
        self.assertIn("disposition_without_evaluation", err)


# *--- Notes ---*


class PlanLapseNoteTests(StoreCase):
    """Where a store and its run disagree about a lapsed plan, an INFO note says so (D10)."""

    def test_a_derived_lapse_no_record_carries_is_unrecorded(self) -> None:
        self.build_golden_store()
        self.reevaluate(
            completedAt="2026-09-14T09:00:00Z",
            projectedNextReduction={"estimatedAt": "2026-09-18T16:00:00Z", "targetRating": 2},
        )
        notes = [
            item
            for item in self.diagnostics("2026-09-20T00:00:00Z")
            if item["code"].startswith("response_gap_")
        ]
        self.assertEqual(
            notes,
            [
                {
                    "code": "response_gap_unrecorded",
                    "level": "info",
                    "location": f"planned-response-lapse {PLANNED_CASE}",
                    "message": (
                        f"the planned reduction of {PLANNED_CASE} to PAIN N2 was not recorded by "
                        "2026-09-18T16:00:00Z, and history records no response gap for it, so no "
                        "case in this report carries it; cases response-gaps with this run's as-of "
                        "records it"
                    ),
                }
            ],
        )

    def test_a_reduction_in_the_window_under_the_same_plan_contradicts_the_record(self) -> None:
        self.build_golden_store()
        self.reevaluate(
            painReductionEvents=[
                {"reducedAt": "2026-09-04T15:00:00Z", "rating": 3},
                {"reducedAt": "2026-09-09T10:00:00Z", "rating": 2},
            ]
        )
        diagnostics = self.diagnostics()
        self.assertNotIn(WARNING, [item["code"] for item in diagnostics])
        notes = [item for item in diagnostics if item["code"].startswith("response_gap_")]
        (note,) = notes
        self.assertEqual(note["code"], "response_gap_contradicted")
        self.assertEqual(note["location"], f"planned-response-lapse {PLANNED_CASE}")
        self.assertIn(
            f"carries the recorded response gap of {PLANNED_CASE}'s planned reduction to PAIN N2 "
            f"by {PLANNED_TEXT}, but the current evaluation of {PLANNED_CASE} still states that "
            "plan and records a reduction to PAIN N2 at 2026-09-09T10:00:00Z, inside its window, "
            "so the planned reduction happened in time, so this run derives no such gap; the gap "
            "stays recorded, and an evaluation can dispose it as a false positive",
            note["message"],
        )

    def test_a_reduction_at_the_window_edges_contradicts_and_one_past_them_does_not(self) -> None:
        for reduced_at, contradicted in (
            ("2026-09-04T15:00:00Z", True),
            (PLANNED_TEXT, True),
            ("2026-09-11T16:00:01Z", False),
            ("2026-09-04T14:59:59Z", False),
        ):
            with self.subTest(reduced_at=reduced_at):
                self.setUp()
                self.build_golden_store()
                self.reevaluate(painReductionEvents=[{"reducedAt": reduced_at, "rating": 2}])
                codes = self.codes()
                self.assertEqual("response_gap_contradicted" in codes, contradicted)
                self.assertNotIn("response_gap_unmatched", codes)

    def test_a_plan_met_late_revised_or_closed_stands_with_no_note(self) -> None:
        # A reduction after the planned time leaves the rating as stated, so the warning stays
        # until an evaluation lowers it; the record's title, "not recorded by", stays true.
        for label, overrides, warns in (
            (
                "met late",
                {"painReductionEvents": [{"reducedAt": "2026-09-12T10:00:00Z", "rating": 2}]},
                True,
            ),
            (
                "met late and re-rated",
                {
                    "pain": 2,
                    "painReductionEvents": [{"reducedAt": "2026-09-12T10:00:00Z", "rating": 2}],
                },
                False,
            ),
            (
                "revised",
                {
                    "projectedNextReduction": {
                        "estimatedAt": "2026-09-30T16:00:00Z",
                        "targetRating": 2,
                    }
                },
                False,
            ),
            ("closed", {"disposition": "fully_mitigated", "projectedNextReduction": None}, False),
            ("re-rated", {"pain": 2, "projectedNextReduction": None}, False),
        ):
            with self.subTest(label):
                self.setUp()
                self.build_golden_store()
                self.reevaluate(**overrides)
                codes = self.codes()
                self.assertEqual(WARNING in codes, warns)
                self.assertEqual([code for code in codes if code.startswith("response_gap_")], [])

    def test_a_reduction_that_meets_a_revised_plan_does_not_contradict_the_old_one(self) -> None:
        # The contradiction reads the current evaluation only while it states the recorded plan.
        self.build_golden_store()
        self.reevaluate(
            projectedNextReduction={"estimatedAt": "2026-09-30T16:00:00Z", "targetRating": 2},
            painReductionEvents=[{"reducedAt": "2026-09-10T10:00:00Z", "rating": 2}],
        )
        codes = self.codes()
        self.assertNotIn(WARNING, codes)
        self.assertEqual([code for code in codes if code.startswith("response_gap_")], [])

    def test_a_reduction_before_the_evaluation_does_not_contradict(self) -> None:
        # The record is no longer derived once the rating meets the target, so only the
        # contradiction's own window keeps a reduction before completedAt out of it.
        self.build_golden_store()
        self.reevaluate(
            pain=2,
            painReductionEvents=[{"reducedAt": "2026-09-03T10:00:00Z", "rating": 2}],
        )
        codes = self.codes()
        self.assertNotIn(WARNING, codes)
        self.assertEqual([code for code in codes if code.startswith("response_gap_")], [])

    def test_the_contradiction_names_the_earliest_reduction_that_met_the_plan(self) -> None:
        self.build_golden_store()
        self.reevaluate(
            painReductionEvents=[
                {"reducedAt": "2026-09-09T10:00:00Z", "rating": 1},
                {"reducedAt": "2026-09-06T10:00:00Z", "rating": 2},
            ]
        )
        (note,) = [
            item for item in self.diagnostics() if item["code"] == "response_gap_contradicted"
        ]
        self.assertIn("records a reduction to PAIN N2 at 2026-09-06T10:00:00Z", note["message"])

    def test_a_store_that_recorded_the_lapse_reads_with_no_note(self) -> None:
        self.build_golden_store()
        codes = self.codes()
        self.assertEqual(codes, [WARNING])


# *--- Golden ---*


class PlanLapseGoldenTests(StoreCase):
    """The `historical-planned-response` pair, cut from a store that recorded a lapsed plan."""

    def test_the_golden_store_reports_the_golden_and_verifies(self) -> None:
        self.build_golden_store()
        json_path = self.workspace / "report.json"
        markdown_path = self.workspace / "report.md"
        code, _, err = self.report("-o", str(json_path), "--markdown", str(markdown_path))
        self.assertEqual(code, 0, msg=err)
        self.assertEqual(json_path.read_bytes(), (GOLDEN / f"{GOLDEN_NAME}.json").read_bytes())
        self.assertEqual(markdown_path.read_bytes(), (GOLDEN / f"{GOLDEN_NAME}.md").read_bytes())
        out, err = self.succeeds(["store", "verify", "--db", str(self.database)])
        self.assertTrue(out.startswith("ok: "), msg=err)
        self.assertEqual(self.schema_version(), 8)

    def test_the_golden_validates_and_carries_the_record_and_the_warning(self) -> None:
        payload = (GOLDEN / f"{GOLDEN_NAME}.json").read_bytes()
        self.assertTrue(
            validate_bundled_report_bytes(ReportSchema.HISTORICAL_ACTIVITY, payload).is_valid
        )
        document = json.loads(payload)
        codes = [item["code"] for item in document["x-complyroll"]["diagnostics"]]
        self.assertEqual(codes, [WARNING])
        markdown = (GOLDEN / f"{GOLDEN_NAME}.md").read_text(encoding="utf-8")
        self.assertIn(PLAN_LINE, markdown)
        self.assertIn(
            "for a lapsed planned response, from the instant its planned reduction was expected",
            markdown,
        )


if __name__ == "__main__":
    unittest.main()
