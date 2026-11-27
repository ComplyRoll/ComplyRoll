# ******************************************************************************
# *Title: Response Gap History Tests*
# *Author: Kyle Versluis*
# *Description: cases response-gaps, its golden, evaluations and notes.*
# ******************************************************************************
"""Tests that a store records response gaps once and reports them (ADR 0019)."""

# *--- Imports ---*

from __future__ import annotations

import json
import sqlite3
import unittest
from collections.abc import Sequence
from contextlib import closing
from datetime import UTC, datetime
from typing import Any

from test_cli import (
    RECURRENCE_ARTIFACTS,
    RECURRENCE_EVALUATIONS,
    PersistedStoreTestCase,
    help_text,
    run,
)
from test_coverage import policy
from test_reports import FIXTURES, GOLDEN, options
from test_response_gaps import (
    BACK_AT,
    CASE_ID,
    FIRST_SEEN,
    INGESTED,
    LATER_AT,
    REMEDIATED_AT,
    Case,
    Link,
    fail,
    recurrence_records,
)

from complyroll.correlation import group_open_observations
from complyroll.events import EventRepository
from complyroll.history import fold_all_cases
from complyroll.models import Observation
from complyroll.reports import (
    REPORT_DIAGNOSTIC_CODES,
    DetectionAttestation,
    ReportDiagnostic,
    compile_record_set,
)
from complyroll.reports.response_gaps import (
    ResponseGapHistory,
    attestation_lapse,
    attestation_lapse_observation,
)
from complyroll.store import SQLiteEventStore

# *--- Fixtures ---*

GOLDEN_NAME = "historical-response-gaps"
UNTIMED = str(FIXTURES / "attestation-untimed.cklb")
#: The untimed checklist's first sighting, and the remediated scan's two readings.
SEEN_TEXT = "2026-09-01T00:00:00Z"
BEFORE_TEXT = "2026-09-03T00:00:00Z"
AFTER_TEXT = "2026-09-13T00:00:00Z"
#: The run that records both gaps: past the class C window of the untimed case (6 September).
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
#: The cases the golden store holds, by what they are.
REMEDIATED_CASE = "case-748ec5056f5557ed"
UNTIMED_CASE = "case-a28eeaac0789b5e2"
RECURRENCE_CASE = "case-36313f6ed3164db8"
LAPSE_CASE = "case-21e6bd73f9174969"
RECURRENCE_ID = "obs-6567363ed96e0fffdf168fd13832f385e5e15d498b16bb2cf320600de0b086f1"
LAPSE_ID = "obs-5e1b2b5cf665b208a471fb68c878627a207694012c555f4472872516db3ac823"
RECURRENCE_LINE = (
    f"remediation of {REMEDIATED_CASE} recorded 2026-09-05T15:00:00Z did not hold: "
    "image:registry.example.test/recurrence/api:1.4.2/usr/lib/libexample-json.so.2 detected "
    "again 2026-09-12T08:40:00Z"
)
LAPSE_LINE = (
    f"detection time of {UNTIMED_CASE} was not attested within VER-TFR-EVU from {SEEN_TEXT}"
)
RATIONALE = "The checklist declares no assessment timestamp; the review ran on 1 September."
#: Values no default would produce, so the record shows they came from the evaluation.
GAP_ENTRY: dict[str, Any] = {
    "completedAt": "2026-09-14T09:00:00Z",
    "isInternetReachable": False,
    "isLikelyExploitable": False,
    "pain": 2,
    "potentialAgencyImpact": "SYNTHETIC. The image shipped the flawed package again.",
    "rationale": "SYNTHETIC. The pin was lost in a rebuild; the build now fails on it.",
    "evaluator": "Example Provider vulnerability team (response review)",
}


class StoreCase(PersistedStoreTestCase):
    """A store driven only through the command line, as an operator records response gaps."""

    def cr(self, *argv: str) -> tuple[int, str, str]:
        return run([*argv[:2], "--db", str(self.database), *argv[2:]])

    def ingest(self, artifact: str, as_of: str) -> None:
        self.succeeds(["ingest", artifact, "--db", str(self.database), "--as-of", as_of])

    def response_gaps(self, *options: str) -> tuple[int, str, str]:
        return self.cr("cases", "response-gaps", *(options or OPTIONS), "--actor", "golden")

    def remediate(self) -> None:
        """Ingest the untimed checklist and the first scan, then remediate the scan's finding."""
        before, _ = RECURRENCE_ARTIFACTS
        self.ingest(UNTIMED, SEEN_TEXT)
        self.ingest(before, BEFORE_TEXT)
        self.succeeds(["cases", "correlate", "--db", str(self.database)])
        self.succeeds(
            [
                "cases",
                "evaluate",
                "--db",
                str(self.database),
                "--evaluations",
                str(RECURRENCE_EVALUATIONS),
            ]
        )

    def build_golden_store(self) -> None:
        """The golden recipe: remediate, ingest what came back, record, correlate, attest."""
        self.remediate()
        self.ingest(RECURRENCE_ARTIFACTS[1], AFTER_TEXT)
        code, _, err = self.response_gaps()
        self.assertEqual(code, 3, msg=err)
        self.succeeds(["cases", "correlate", "--db", str(self.database)])
        self.attest()

    def attest(self) -> None:
        self.succeeds(
            [
                "cases",
                "attest-detection",
                "--db",
                str(self.database),
                "--all-missing",
                "--detected-at",
                SEEN_TEXT,
                "--rationale",
                RATIONALE,
            ]
        )

    def report(self, *extra: str) -> tuple[int, str, str]:
        return run(["report", "historical", "--db", str(self.database), *REPORT, *extra])

    def schema_version(self) -> int:
        with closing(sqlite3.connect(self.database)) as connection:
            return int(connection.execute("PRAGMA user_version").fetchone()[0])

    def evaluate(self, entry: dict[str, Any]) -> tuple[int, str, str]:
        path = self.workspace / "gap-evaluations.json"
        path.write_text(json.dumps({"evaluations": [entry]}), encoding="utf-8")
        return self.cr("cases", "evaluate", "--evaluations", str(path))


# *--- Command ---*


class ResponseGapCommandTests(StoreCase):
    """`cases response-gaps` records each gap once, exits 3 when it records, 0 otherwise."""

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
        self.assertEqual(self.schema_version(), 7)

    def test_the_golden_carries_both_records_and_no_note(self) -> None:
        document = json.loads((GOLDEN / f"{GOLDEN_NAME}.json").read_text(encoding="utf-8"))
        codes = [item["code"] for item in document["x-complyroll"]["diagnostics"]]
        self.assertEqual(codes, ["source_timestamp_missing", "recurrence_after_remediation"])
        tracking = [item["providerTrackingId"] for item in document["activeVulnerabilities"]]
        self.assertIn(RECURRENCE_CASE, tracking)
        self.assertIn(LAPSE_CASE, tracking)

    def test_recording_prints_each_gap_then_a_rerun_records_none(self) -> None:
        self.remediate()
        self.ingest(RECURRENCE_ARTIFACTS[1], AFTER_TEXT)
        code, out, err = self.response_gaps()
        self.assertEqual((code, err), (3, ""))
        self.assertEqual(
            out.splitlines(),
            [
                f"{RECURRENCE_ID}: recorded {RECURRENCE_LINE}",
                f"{LAPSE_ID}: recorded {LAPSE_LINE}",
                "recorded 2 response gap(s), skipped 0 already-recorded response gap(s)",
            ],
        )
        code, out, err = self.response_gaps()
        self.assertEqual((code, err), (0, ""))
        self.assertEqual(
            out.splitlines(),
            [
                f"{RECURRENCE_ID}: already_recorded {RECURRENCE_LINE}",
                f"{LAPSE_ID}: already_recorded {LAPSE_LINE}",
                "recorded 0 response gap(s), skipped 2 already-recorded response gap(s)",
            ],
        )

    def test_a_store_with_nothing_to_record_exits_0_and_marks_no_schema(self) -> None:
        self.ingest(RECURRENCE_ARTIFACTS[0], BEFORE_TEXT)
        before = self.schema_version()
        code, out, err = self.response_gaps()
        self.assertEqual((code, err), (0, ""))
        self.assertEqual(
            out, "recorded 0 response gap(s), skipped 0 already-recorded response gap(s)\n"
        )
        self.assertEqual(self.schema_version(), before)

    def test_an_attestation_made_before_any_run_prevents_the_lapse(self) -> None:
        self.ingest(UNTIMED, SEEN_TEXT)
        self.succeeds(["cases", "correlate", "--db", str(self.database)])
        self.attest()
        code, out, _ = self.response_gaps()
        self.assertEqual(code, 0)
        self.assertNotIn("recorded detection time", out)

    def test_a_run_before_the_window_closes_records_no_lapse(self) -> None:
        self.ingest(UNTIMED, SEEN_TEXT)
        self.succeeds(["cases", "correlate", "--db", str(self.database)])
        code, _, _ = self.response_gaps("--class", "C", "--as-of", "2026-09-05T23:59:59Z")
        self.assertEqual(code, 0)
        code, out, _ = self.response_gaps("--class", "C", "--as-of", "2026-09-06T00:00:00Z")
        self.assertEqual(code, 3)
        self.assertIn(f"recorded {LAPSE_LINE}", out)

    def test_a_case_that_was_never_correlated_has_no_first_sighting(self) -> None:
        # F1: no links, no first sighting, no record, however late the run.
        self.ingest(UNTIMED, SEEN_TEXT)
        code, out, _ = self.response_gaps("--class", "C", "--as-of", "2027-01-01T00:00:00Z")
        self.assertEqual((code, out.splitlines()[-1]), (0, out.splitlines()[-1]))
        self.assertNotIn("recorded detection time", out)

    def test_a_recurrence_is_recorded_before_correlate_links_what_came_back(self) -> None:
        # F9: the store path reads the report's grouping, linked or not.
        self.remediate()
        self.ingest(RECURRENCE_ARTIFACTS[1], AFTER_TEXT)
        with SQLiteEventStore(self.database) as store:
            (remediated,) = [
                case
                for case in fold_all_cases(EventRepository(store))
                if case.tracking_id == REMEDIATED_CASE
            ]
        self.assertEqual(len(remediated.links), 1)
        code, out, _ = self.response_gaps()
        self.assertEqual(code, 3)
        self.assertIn(f"{RECURRENCE_ID}: recorded", out)

    def test_refusals_write_nothing(self) -> None:
        code, _, err = self.response_gaps()
        self.assertEqual(code, 1)
        self.assertIn("error: store_missing: ", err)
        self.ingest(RECURRENCE_ARTIFACTS[0], BEFORE_TEXT)
        for options_given, expected in (
            (("--class", "C", "--as-of", "yesterday"), "error: invalid_input: "),
            (
                ("--class", "C", "--as-of", AS_OF_TEXT, "--calendar-tz", "Mars/Olympus"),
                "error: invalid_option: ",
            ),
        ):
            with self.subTest(options=options_given):
                code, out, err = self.response_gaps(*options_given)
                self.assertEqual((code, out), (1, ""))
                self.assertIn(expected, err)
        self.assertEqual(self.schema_version(), 1)

    def test_the_help_names_the_record_and_exit_3(self) -> None:
        text = help_text(["cases", "response-gaps", "--help"])
        # NOTE: argparse may wrap a hyphenated rule id at its hyphen, so the rule is not asserted.
        self.assertIn("system record; exits 3 when one is recorded", text)
        self.assertIn("--class", text)
        self.assertIn("--calendar-tz", text)


# *--- Cases And Evaluations ---*


class ResponseGapCaseTests(StoreCase):
    """A response gap becomes a case after `cases correlate`, evaluated by the full triple."""

    def test_cases_list_names_each_response_gap_case_context_key(self) -> None:
        self.build_golden_store()
        out, _ = self.succeeds(["cases", "list", "--db", str(self.database)])
        lines = out.splitlines()
        self.assertTrue(lines[0].endswith("CONTEXT KEY"))
        self.assertTrue(any(line.endswith(f"active       {UNTIMED_CASE}") for line in lines))
        self.assertTrue(
            any(
                line.endswith(f"{REMEDIATED_CASE}:remediated:2026-09-05T15:00:00Z")
                for line in lines
            )
        )
        self.assertTrue(
            any(line.startswith(REMEDIATED_CASE) and line.endswith("-") for line in lines)
        )

    def test_an_evaluation_matches_a_recurrence_by_the_full_triple_alone(self) -> None:
        self.build_golden_store()
        key = f"{REMEDIATED_CASE}:remediated:2026-09-05T15:00:00Z"
        short = {"sourceRecordId": "remediation-recurrence", "sourceType": "complyroll.recurrence"}
        code, _, err = self.evaluate({"match": short, **GAP_ENTRY})
        self.assertEqual(code, 1)
        self.assertIn(
            f"matches the remediation recurrence {RECURRENCE_CASE}; a remediation recurrence is "
            "matched by sourceRecordId, sourceType and contextKey together, so add contextKey",
            err,
        )
        code, out, err = self.evaluate({"match": {**short, "contextKey": key}, **GAP_ENTRY})
        self.assertEqual(code, 0, msg=err)
        self.assertIn("evaluations: 1 appended", out)

    def test_an_evaluation_before_a_lapse_closed_names_its_remedy(self) -> None:
        self.build_golden_store()
        match = {
            "sourceRecordId": "attestation-lapse",
            "sourceType": "complyroll.attestation",
            "contextKey": UNTIMED_CASE,
        }
        code, _, err = self.evaluate(
            {"match": match, **GAP_ENTRY, "completedAt": "2026-09-05T23:59:59Z"}
        )
        self.assertEqual(code, 1)
        self.assertIn(
            "a lapsed attestation is detected when its evaluation window closed, so evaluate it "
            "at or after that instant, or correct completedAt",
            err,
        )

    def test_the_report_groups_the_records_before_cases_correlate_opens_their_cases(self) -> None:
        self.remediate()
        self.ingest(RECURRENCE_ARTIFACTS[1], AFTER_TEXT)
        self.assertEqual(self.response_gaps()[0], 3)
        self.attest()
        code, out, err = run(["report", "historical", "--db", str(self.database), *REPORT])
        self.assertEqual(code, 0, msg=err)
        self.assertIn("attestation-lapse", out)
        self.assertIn("remediation-recurrence", out)


# *--- Divergence Notes ---*


class ResponseGapStoreNoteTests(StoreCase):
    """A store that recorded a response gap names where it and this run disagree (F4)."""

    def notes(self, *extra: str) -> list[dict[str, str]]:
        code, out, err = self.report(*extra)
        self.assertEqual(code, 0, msg=err)
        return [
            item
            for item in json.loads(out)["x-complyroll"]["diagnostics"]
            if item["code"].startswith("response_gap_")
        ]

    def test_a_store_that_never_recorded_a_response_gap_writes_no_note(self) -> None:
        self.remediate()
        self.ingest(RECURRENCE_ARTIFACTS[1], AFTER_TEXT)
        self.attest()
        self.assertEqual(self.notes(), [])

    def test_a_gap_derived_after_the_last_run_is_unrecorded(self) -> None:
        self.remediate()
        self.assertEqual(self.response_gaps()[0], 3)
        self.ingest(RECURRENCE_ARTIFACTS[1], AFTER_TEXT)
        self.succeeds(["cases", "correlate", "--db", str(self.database)])
        self.attest()
        self.assertEqual(
            self.notes(),
            [
                {
                    "level": "info",
                    "code": "response_gap_unrecorded",
                    "message": (
                        f"the remediation of {REMEDIATED_CASE} recorded 2026-09-05T15:00:00Z did "
                        "not hold on image:registry.example.test/recurrence/api:1.4.2/usr/lib/"
                        "libexample-json.so.2, detected again 2026-09-12T08:40:00Z, and history "
                        "records no response gap for it, so no case in this report carries it; "
                        "cases response-gaps with this run's as-of records it"
                    ),
                    "location": f"remediation-recurrence {REMEDIATED_CASE}",
                }
            ],
        )

    def test_a_lapse_read_under_another_class_is_unmatched(self) -> None:
        self.build_golden_store()
        code, out, err = run(
            [
                "report",
                "historical",
                "--db",
                str(self.database),
                *("--class", "B", "--package-uri", "https://example.test/cpo"),
                *("--as-of", AS_OF_TEXT),
            ]
        )
        self.assertEqual(code, 0, msg=err)
        notes = [
            item
            for item in json.loads(out)["x-complyroll"]["diagnostics"]
            if item["code"].startswith("response_gap_")
        ]
        self.assertEqual([item["code"] for item in notes], ["response_gap_unmatched"])
        self.assertEqual(notes[0]["location"], f"attestation-lapse {UNTIMED_CASE}")
        self.assertIn(
            f"carries the recorded response gap of {UNTIMED_CASE}'s VER-TFR-EVU window from "
            f"{SEEN_TEXT} that closed 2026-09-06T00:00:00Z, and this run derives no such gap",
            notes[0]["message"],
        )

    def test_a_lapse_stands_once_the_case_is_attested(self) -> None:
        self.build_golden_store()
        self.assertEqual(self.notes(), [])

    def test_a_recurrence_stands_after_the_case_is_re_evaluated(self) -> None:
        self.build_golden_store()
        entry = json.loads(RECURRENCE_EVALUATIONS.read_text(encoding="utf-8"))["evaluations"][0]
        code, _, err = self.evaluate(
            {**entry, "completedAt": "2026-09-14T09:00:00Z", "disposition": "fully_mitigated"}
        )
        self.assertEqual(code, 0, msg=err)
        self.assertEqual(self.notes(), [])


class ResponseGapNoteTests(unittest.TestCase):
    """The notes read each recorded gap against its own record, case by case (F4, D39)."""

    def notes(
        self, observations: Sequence[Observation], history: ResponseGapHistory
    ) -> list[ReportDiagnostic]:
        record_set = compile_record_set(
            artifacts=(),
            observations=tuple(observations),
            ingest_diagnostics=(),
            evaluations_by_tracking_id={},
            attestation=DetectionAttestation(default=FIRST_SEEN),
            options=options(detected_at=None, period_from=None, period_to=None),
            response_gap_history=history,
        )
        return [item for item in record_set.diagnostics if item.code.startswith("response_gap_")]

    def test_the_three_codes_are_registered(self) -> None:
        for code in (
            "response_gap_contradicted",
            "response_gap_unmatched",
            "response_gap_unrecorded",
        ):
            self.assertIn(code, REPORT_DIAGNOSTIC_CODES)

    def test_a_recurrence_whose_evidence_is_gone_is_contradicted(self) -> None:
        before = fail("lab-01", FIRST_SEEN)
        (record,) = recurrence_records(before, fail("lab-01", BACK_AT))
        (group,) = group_open_observations((before,))
        history = ResponseGapHistory(
            cases=(), ingested_at={}, remediated_at={group.tracking_id: REMEDIATED_AT}
        )
        (note,) = self.notes((before, record), history)
        self.assertEqual(note.code, "response_gap_contradicted")
        self.assertIn(
            f"but no current open observation of {group.tracking_id} on host:lab-01 was detected "
            "after 2026-08-05T12:00:00Z, so the evidence it rests on is no longer in history",
            note.message,
        )
        self.assertTrue(
            note.message.endswith("and an evaluation can dispose it as a false positive")
        )

    def test_a_recurrence_rebuilt_from_its_own_record_stands(self) -> None:
        found = (fail("lab-01", FIRST_SEEN), fail("lab-01", BACK_AT))
        (record,) = recurrence_records(*found)
        # The case is no longer remediated, so this run derives nothing, and the record stands.
        history = ResponseGapHistory(cases=(), ingested_at={}, remediated_at={})
        self.assertEqual(self.notes((*found, record), history), [])

    def test_a_contradicted_gap_names_a_sibling_that_keeps_the_case_open(self) -> None:
        before = fail("lab-01", FIRST_SEEN)
        records = recurrence_records(before, fail("lab-01", BACK_AT), fail("lab-02", LATER_AT))
        (group,) = group_open_observations((before,))
        history = ResponseGapHistory(cases=(), ingested_at={}, remediated_at={})
        kept = fail("lab-02", LATER_AT)
        (note,) = self.notes((before, kept, *records), history)
        self.assertEqual(note.code, "response_gap_contradicted")
        self.assertIn(
            "but the case also carries the response gap of the remediation of", note.message
        )
        self.assertIn("on host:lab-02", note.message)
        self.assertIn(group.tracking_id, note.message)

    def test_a_lapse_timed_inside_its_window_is_contradicted(self) -> None:
        lapse = attestation_lapse(Case(), INGESTED, policy("C"), datetime(2026, 10, 1, tzinfo=UTC))
        assert lapse is not None
        record = attestation_lapse_observation(lapse, ingested_at=datetime(2026, 10, 1, tzinfo=UTC))
        timed = Case(links=(Link("obs-first"), Link("obs-second", BACK_AT)))
        history = ResponseGapHistory(cases=(timed,), ingested_at=INGESTED, remediated_at={})
        (note,) = self.notes((record,), history)
        self.assertEqual(note.code, "response_gap_contradicted")
        self.assertEqual(note.location, f"attestation-lapse {CASE_ID}")
        self.assertIn(
            f"but obs-second, linked to {CASE_ID}, declares a source timestamp and was recorded "
            "2026-09-03T08:00:00Z, inside that window, so the case had a detection time in time",
            note.message,
        )

    def test_a_lapse_timed_after_its_window_stands(self) -> None:
        lapse = attestation_lapse(Case(), INGESTED, policy("C"), datetime(2026, 10, 1, tzinfo=UTC))
        assert lapse is not None
        record = attestation_lapse_observation(lapse, ingested_at=datetime(2026, 10, 1, tzinfo=UTC))
        late = {**INGESTED, "obs-late": datetime(2026, 9, 20, tzinfo=UTC)}
        timed = Case(links=(Link("obs-first"), Link("obs-late", BACK_AT)))
        history = ResponseGapHistory(cases=(timed,), ingested_at=late, remediated_at={})
        self.assertEqual(self.notes((record,), history), [])

    def test_a_lapse_timed_at_its_window_close_is_contradicted(self) -> None:
        # The window is closed at its close: evidence recorded at that instant was in time.
        lapse = attestation_lapse(Case(), INGESTED, policy("C"), datetime(2026, 10, 1, tzinfo=UTC))
        assert lapse is not None
        record = attestation_lapse_observation(lapse, ingested_at=datetime(2026, 10, 1, tzinfo=UTC))
        at_close = {**INGESTED, "obs-close": lapse.window_closed_at}
        timed = Case(links=(Link("obs-first"), Link("obs-close", BACK_AT)))
        history = ResponseGapHistory(cases=(timed,), ingested_at=at_close, remediated_at={})
        (note,) = self.notes((record,), history)
        self.assertEqual(note.code, "response_gap_contradicted")
        self.assertIn("obs-close", note.message)


if __name__ == "__main__":
    unittest.main()
