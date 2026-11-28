# ******************************************************************************
# *Title: Plan Lapse Fix Tests*
# *Author: Kyle Versluis*
# *Description: Tests for the PR 2 audit fixes to the lapsed planned response.*
# ******************************************************************************
"""Tests that close the OpenAI audit's PR 2 findings (ADR 0019, section of 2026-11-27)."""

# *--- Imports ---*

from __future__ import annotations

import json
import sqlite3
import unittest
from contextlib import closing
from datetime import UTC, datetime, timedelta
from typing import Any
from unittest import mock

from test_cli import PLANNED_ARTIFACT, RECURRENCE_ARTIFACTS, RECURRENCE_EVALUATIONS, run
from test_coverage_streams import StoreCase as RepositoryCase
from test_coverage_streams import metadata, pending, rebuilt
from test_plan_lapse_history import (
    AS_OF_TEXT,
    INGEST_TEXT,
    PLAN_LINE,
    PLANNED_CASE,
    WARNING,
)
from test_plan_lapse_history import StoreCase as CommandCase
from test_plan_lapse_streams import plan_events
from test_response_gap_history import (
    LAPSE_CASE,
    LAPSE_LINE,
    RECURRENCE_CASE,
    SEEN_TEXT,
    UNTIMED,
    UNTIMED_CASE,
)

from complyroll import correlation as correlation_module
from complyroll.events import (
    EventContractError,
    EventRepository,
    case_stream_id,
    response_gap_stream_id_of,
)
from complyroll.events import repository as repository_module
from complyroll.history import HistoryError, audit_history, rehydrate_observations
from complyroll.models import PainRating
from complyroll.reports.response_gaps import (
    PLAN_LAPSE_SOURCE_TYPE,
    PlanLapse,
    plan_lapse_observation,
)
from complyroll.store import SQLiteEventStore

# *--- Fixtures ---*

#: The correlation id of the planned fixture's plan lapse case (`historical-planned-response`).
PLAN_CASE = "case-041a65e24f5b6d6d"
PLANNED_AT = datetime(2026, 9, 11, 16, 0, tzinfo=UTC)
ON_TIME = [{"reducedAt": "2026-09-09T10:00:00Z", "rating": 2}]


class FixCase(CommandCase):
    """A command-line store with the helpers the fix tests share."""

    def store_bytes(self) -> bytes:
        return self.database.read_bytes()

    def response_gap_streams(self) -> list[str]:
        with closing(sqlite3.connect(self.database)) as connection:
            rows = connection.execute(
                "SELECT stream_id FROM events WHERE stream_id LIKE 'response-gap/%' "
                "ORDER BY sequence"
            ).fetchall()
        return list(dict.fromkeys(row[0] for row in rows))

    def notes(self, as_of: str = AS_OF_TEXT) -> list[str]:
        return [code for code in self.codes(as_of) if code.startswith("response_gap_")]

    def untimed_and_planned(self) -> None:
        """Ingest the untimed checklist and the planned scan, open both cases, plan the scan."""
        self.succeeds(["ingest", UNTIMED, "--db", str(self.database), "--as-of", SEEN_TEXT])
        self.succeeds(
            ["ingest", PLANNED_ARTIFACT, "--db", str(self.database), "--as-of", INGEST_TEXT]
        )
        self.succeeds(["cases", "correlate", "--db", str(self.database)])
        self.reevaluate()

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
                "The checklist declares no assessment timestamp.",
            ]
        )


# *--- D01: a run never merges two published ids ---*


class TrackingIdCollisionTests(FixCase):
    """A run whose new record would publish an id another record publishes records nothing."""

    def assert_refused(self, opened: str) -> None:
        before = self.store_bytes()
        code, out, err = self.response_gaps()
        self.assertEqual((code, out), (1, ""), msg=err)
        self.assertIn(
            f"error: tracking_id_collision: effective tracking id '{opened}' is claimed by ", err
        )
        self.assertIn(f"(originally {opened})", err)
        self.assertIn(f"; this run would record the response gap of {opened}, so it records", err)
        self.assertEqual(self.store_bytes(), before)
        out, err = self.succeeds(["store", "verify", "--db", str(self.database)])
        self.assertTrue(out.startswith("ok: "), msg=err)

    def test_a_provider_id_equal_to_the_plan_lapse_case_refuses_the_run(self) -> None:
        self.plan()
        self.reevaluate(trackingId=PLAN_CASE)
        self.assert_refused(PLAN_CASE)
        code, _, err = self.report()
        self.assertEqual(code, 0, msg=err)

    def test_a_provider_id_equal_to_an_attestation_lapse_case_refuses_the_run(self) -> None:
        self.succeeds(["ingest", UNTIMED, "--db", str(self.database), "--as-of", SEEN_TEXT])
        self.succeeds(
            ["ingest", RECURRENCE_ARTIFACTS[0], "--db", str(self.database), "--as-of", INGEST_TEXT]
        )
        self.succeeds(["cases", "correlate", "--db", str(self.database)])
        entry = dict(
            json.loads(RECURRENCE_EVALUATIONS.read_text(encoding="utf-8"))["evaluations"][0]
        )
        entry["trackingId"] = LAPSE_CASE
        path = self.workspace / "override.json"
        path.write_text(json.dumps({"evaluations": [entry]}), encoding="utf-8")
        self.succeeds(["cases", "evaluate", "--db", str(self.database), "--evaluations", str(path)])
        self.assert_refused(LAPSE_CASE)

    def test_a_provider_id_equal_to_a_recurrence_case_refuses_the_run(self) -> None:
        before_scan, after_scan = RECURRENCE_ARTIFACTS
        self.succeeds(["ingest", before_scan, "--db", str(self.database), "--as-of", INGEST_TEXT])
        self.succeeds(["cases", "correlate", "--db", str(self.database)])
        entry = dict(
            json.loads(RECURRENCE_EVALUATIONS.read_text(encoding="utf-8"))["evaluations"][0]
        )
        entry["trackingId"] = RECURRENCE_CASE
        path = self.workspace / "override.json"
        path.write_text(json.dumps({"evaluations": [entry]}), encoding="utf-8")
        self.succeeds(["cases", "evaluate", "--db", str(self.database), "--evaluations", str(path)])
        self.succeeds(
            ["ingest", after_scan, "--db", str(self.database), "--as-of", "2026-09-13T00:00:00Z"]
        )
        self.assert_refused(RECURRENCE_CASE)

    def test_a_collision_held_on_entry_does_not_stop_unrelated_work(self) -> None:
        # The planned case already publishes the untimed case's id: a collision the store held
        # before the run, written past the writers. It is verify's to name, and the run still
        # records the untimed case's lapse and the plan's, neither of which joins it.
        self.untimed_and_planned()
        with SQLiteEventStore(self.database) as store:
            repository = EventRepository(store)
            stream = case_stream_id(PLANNED_CASE)
            repository.append(
                stream,
                "case.identified",
                {"providerTrackingId": UNTIMED_CASE},
                occurred_at=datetime(2026, 9, 5, tzinfo=UTC),
                metadata=metadata(),
                expected_version=repository.current_version(stream),
            )
        code, _, err = run(["store", "verify", "--db", str(self.database)])
        self.assertEqual(code, 1)
        self.assertIn("tracking_id_collision", err)
        before = self.store_bytes()
        code, out, err = self.response_gaps()
        self.assertEqual(code, 3, msg=err)
        self.assertNotIn("tracking_id_collision", err)
        self.assertEqual(len(self.recorded_ids(out)), 2)
        self.assertNotEqual(self.store_bytes(), before)
        code, _, err = run(["store", "verify", "--db", str(self.database)])
        self.assertEqual(code, 1)
        self.assertIn("tracking_id_collision", err)

    def test_a_new_group_sharing_a_correlation_id_is_refused_and_named_by_its_key(self) -> None:
        # Two group keys under one 64-bit correlation id, forced through the one function that
        # names a group's id; report, verify and the run all read groups through it.
        self.plan()
        real = correlation_module.tracking_id_for

        def shared(source_type: str, source_record_id: str, context_key: str) -> str:
            if source_type == PLAN_LAPSE_SOURCE_TYPE:
                return PLANNED_CASE
            return real(source_type, source_record_id, context_key)

        with mock.patch.object(correlation_module, "tracking_id_for", shared):
            before = self.store_bytes()
            code, out, err = self.response_gaps()
            self.assertEqual((code, out), (1, ""), msg=err)
            self.assertIn(
                f"error: tracking_id_collision: effective tracking id '{PLANNED_CASE}' is claimed",
                err,
            )
            self.assertIn("the two share that correlation id, as the groups (sourceType ", err)
            self.assertIn("'complyroll.response-plan'", err)
            self.assertIn("sourceRecordId 'CVE-2099-0101'", err)
            self.assertIn(", so it records nothing", err)
            self.assertEqual(self.store_bytes(), before)
            out, err = self.succeeds(["store", "verify", "--db", str(self.database)])
            self.assertTrue(out.startswith("ok: "), msg=err)

    def test_without_the_override_the_same_runs_record(self) -> None:
        self.plan()
        code, out, _ = self.response_gaps()
        self.assertEqual(code, 3)
        self.assertIn(f": recorded {PLAN_LINE}", out)


# *--- D03: a lapse is ingested after its planned time ---*


def planned_record(ingested_at: datetime) -> Any:
    lapse = PlanLapse(
        "case-0123456789abcdef",
        datetime(2026, 9, 4, 15, 0, tzinfo=UTC),
        PLANNED_AT,
        PainRating.N2,
        PainRating.N3,
    )
    return plan_lapse_observation(lapse, ingested_at=ingested_at)


class PlanLapseIngestTimeTests(RepositoryCase):
    """A plan lapse ingested at or before its planned time is a record its writer never mints."""

    def append(self, record: Any) -> None:
        self.repository.append_batch(
            response_gap_stream_id_of(record),
            tuple(pending(kind, payload) for kind, payload in plan_events(record)),
            expected_version=0,
        )

    def test_one_microsecond_after_the_planned_time_appends(self) -> None:
        self.append(planned_record(PLANNED_AT + timedelta(microseconds=1)))
        self.assertEqual(audit_history(self.repository), ())

    def test_at_or_before_the_planned_time_is_refused_at_append(self) -> None:
        for ingested_at in (PLANNED_AT, PLANNED_AT - timedelta(microseconds=1)):
            with self.subTest(ingested_at=ingested_at):
                with self.assertRaisesRegex(EventContractError, "not after its planned time"):
                    self.append(planned_record(ingested_at))
        self.assertEqual(self.store.latest_sequence, 0)

    def test_written_past_the_repository_it_is_named_and_refused_in_one_text(self) -> None:
        record = planned_record(PLANNED_AT)
        self.stage(response_gap_stream_id_of(record), plan_events(record), requires_schema=8)
        faults = [
            fault
            for fault in audit_history(self.repository)
            if fault.code == "responsegap_identity_breach"
        ]
        self.assertEqual(len(faults), 1)
        self.assertIn("not after its planned time '2026-09-11T16:00:00Z'", faults[0].message)
        with self.assertRaises(HistoryError) as caught:
            rehydrate_observations(self.repository)
        self.assertIn(faults[0].message.split(": ", 1)[-1], str(caught.exception))

    def test_the_record_check_reads_the_ingest_time(self) -> None:
        record = planned_record(PLANNED_AT + timedelta(seconds=1))
        self.assertIsNone(
            repository_module.response_gap_record_problem(
                response_gap_stream_id_of(record),
                "observation.recorded",
                record.to_canonical_dict(),
            )
        )
        moved = rebuilt(record, ingested_at=PLANNED_AT)
        problem = repository_module.response_gap_record_problem(
            response_gap_stream_id_of(moved), "observation.recorded", moved.to_canonical_dict()
        )
        assert problem is not None
        self.assertEqual(problem[0], "responsegap_identity_breach")


class PlanLapseIngestTimeCommandTests(FixCase):
    """A real run one microsecond past the planned time, spelled with an offset, records."""

    def test_a_run_one_microsecond_past_the_planned_time_records_and_verifies(self) -> None:
        self.plan()
        # 2026-09-11T16:00:00Z is the planned time; the same instant at -07:00 records nothing.
        code, out, _ = self.response_gaps("--class", "C", "--as-of", "2026-09-11T09:00:00-07:00")
        self.assertEqual(code, 0, msg=out)
        code, out, err = self.response_gaps(
            "--class", "C", "--as-of", "2026-09-11T09:00:00.000001-07:00"
        )
        self.assertEqual(code, 3, msg=err)
        self.assertIn(f": recorded {PLAN_LINE}", out)
        out, err = self.succeeds(["store", "verify", "--db", str(self.database)])
        self.assertTrue(out.startswith("ok: "), msg=err)


# *--- F01: the contradiction reads the plan and ignores the disposition ---*


class ContradictionInputTests(FixCase):
    """The contradiction needs the same planned time and target, and nothing of the disposition."""

    def setUp(self) -> None:
        super().setUp()
        self.build_golden_store()

    def test_a_revision_of_the_target_alone_leaves_no_contradiction(self) -> None:
        self.reevaluate(
            projectedNextReduction={"estimatedAt": "2026-09-11T16:00:00Z", "targetRating": 1},
            painReductionEvents=[{"reducedAt": "2026-09-09T10:00:00Z", "rating": 1}],
        )
        self.assertEqual(self.notes(), [])

    def test_the_same_plan_met_in_time_contradicts_after_the_record_is_closed(self) -> None:
        for label, overrides in (
            ("fully mitigated", {"disposition": "fully_mitigated"}),
            ("closed as remediated", {"disposition": "closed", "closedDisposition": "remediated"}),
            ("false positive", {"disposition": "false_positive"}),
        ):
            with self.subTest(label):
                self.setUp()
                self.reevaluate(painReductionEvents=ON_TIME, **overrides)
                self.assertEqual(self.notes(), ["response_gap_contradicted"])


# *--- F02: the run reads every reduction the store holds ---*


class RetainedReductionTests(FixCase):
    """A reduction an earlier evaluation filed still meets a later evaluation's plan."""

    def test_a_retained_on_time_reduction_keeps_the_run_from_recording(self) -> None:
        self.plan()
        self.reevaluate(painReductionEvents=ON_TIME)
        count = self.event_count()
        # A real second evaluation, inside the window the retained reduction meets.
        self.reevaluate(completedAt="2026-09-06T09:00:00Z", painReductionEvents=None)
        self.assertGreater(self.event_count(), count)
        count = self.event_count()
        code, out, _ = self.response_gaps()
        self.assertEqual(
            (code, out),
            (0, "recorded 0 response gap(s), skipped 0 already-recorded response gap(s)\n"),
        )
        self.assertEqual(self.event_count(), count)


# *--- F03: one run, two kinds, one transaction ---*


class MixedRunTests(FixCase):
    """A run that records a PR 1 kind and a plan lapse writes them in order, or neither."""

    def test_the_lapse_is_written_before_the_plan(self) -> None:
        self.untimed_and_planned()
        code, out, err = self.response_gaps()
        self.assertEqual(code, 3, msg=err)
        lines = out.splitlines()
        self.assertIn(f"recorded {LAPSE_LINE}", lines[0])
        self.assertIn(f"recorded {PLAN_LINE}", lines[1])
        ids = self.recorded_ids(out)
        with SQLiteEventStore(self.database) as store:
            written = [
                observation.observation_id
                for observation in rehydrate_observations(EventRepository(store))
                if observation.observation_id in ids
            ]
        self.assertEqual(written, ids)
        self.assertEqual(len(self.response_gap_streams()), 2)
        self.assertEqual(self.schema_version(), 8)

    def test_a_refusal_at_the_second_append_leaves_neither_stream_nor_the_marker(self) -> None:
        self.untimed_and_planned()
        before = self.store_bytes()
        schema = self.schema_version()
        original = EventRepository.append_batch
        calls: list[str] = []
        # The schema each append left visible inside the run's transaction.
        marked: list[int] = []

        # The second append reaches the store and marks schema 8 before the refusal, so the
        # rollback has to undo the marker too.
        def refuse_after_second(
            repository: EventRepository, stream_id: str, *args: Any, **kw: Any
        ) -> Any:
            calls.append(stream_id)
            appended = original(repository, stream_id, *args, **kw)
            marked.append(repository.store.schema_version)
            if len(calls) == 2:
                raise EventContractError("planted refusal after the second append")
            return appended

        with mock.patch.object(EventRepository, "append_batch", refuse_after_second):
            code, out, err = self.response_gaps()
        self.assertEqual((code, out), (1, ""), msg=err)
        self.assertIn("planted refusal after the second append", err)
        self.assertEqual(len(calls), 2)
        self.assertEqual(marked, [7, 8])
        self.assertEqual(self.response_gap_streams(), [])
        self.assertEqual(self.schema_version(), schema)
        self.assertEqual(self.store_bytes(), before)


# *--- F04: notes once any response gap is recorded ---*


class FirstPlanNoteTests(FixCase):
    """A store holding only a PR 1 gap notes an overdue plan no record carries."""

    def test_an_overdue_plan_beside_a_recorded_attestation_lapse_is_unrecorded(self) -> None:
        self.untimed_and_planned()
        # Past the untimed case's class C window (6 September), before the plan's time.
        code, out, _ = self.response_gaps("--class", "C", "--as-of", "2026-09-10T00:00:00Z")
        self.assertEqual(code, 3)
        self.assertNotIn("planned reduction", out)
        self.attest()
        self.assertEqual(self.notes(), ["response_gap_unrecorded"])
        (note,) = [item for item in self.diagnostics() if item["code"] == "response_gap_unrecorded"]
        self.assertEqual(note["location"], f"planned-response-lapse {PLANNED_CASE}")


# *--- F05: the run reads groups, not links ---*


class UnlinkedGroupTests(FixCase):
    """A current, evaluated group with no linked observation still records its lapse."""

    def test_an_unlinked_evaluated_group_records_and_keeps_its_id(self) -> None:
        self.succeeds(
            ["ingest", PLANNED_ARTIFACT, "--db", str(self.database), "--as-of", INGEST_TEXT]
        )
        created = {
            "trackingId": PLANNED_CASE,
            "sourceType": "sarif",
            "sourceRecordId": "CVE-2099-0101",
            "contextKey": "Trivy|images/api",
            "title": "CVE-2099-0101: example-json: synthetic flaw for recurrence tests",
            "description": "A case opened before any observation was linked to it.",
            "createdAt": "2026-09-03T00:00:00Z",
        }
        with SQLiteEventStore(self.database) as store:
            EventRepository(store).append(
                case_stream_id(PLANNED_CASE),
                "case.created",
                created,
                occurred_at=datetime(2026, 9, 3, tzinfo=UTC),
                metadata=metadata(),
                expected_version=0,
            )
        self.reevaluate()
        self.assertIn(WARNING, self.codes())
        code, out, err = self.response_gaps()
        self.assertEqual(code, 3, msg=err)
        (first,) = self.recorded_ids(out)
        self.succeeds(["cases", "correlate", "--db", str(self.database)])
        code, out, _ = self.response_gaps()
        self.assertEqual(code, 0)
        self.assertIn(f"{first}: already_recorded {PLAN_LINE}", out)


# *--- B01: a lapse is recorded for a record no report can compile yet ---*


class UntimedPlanTests(FixCase):
    """Kyle's ruling B01: the run records the lapse of an untimed case, which a report refuses."""

    def test_the_run_records_both_kinds_while_the_report_waits_for_an_attestation(self) -> None:
        self.succeeds(["ingest", UNTIMED, "--db", str(self.database), "--as-of", SEEN_TEXT])
        self.succeeds(["cases", "correlate", "--db", str(self.database)])
        entry = {
            "match": {
                "sourceRecordId": "V-299001",
                "sourceType": "cklb",
                "contextKey": "Synthetic PostgreSQL 16 STIG",
            },
            "completedAt": "2026-09-02T15:00:00Z",
            "isInternetReachable": False,
            "isLikelyExploitable": True,
            "pain": 3,
            "potentialAgencyImpact": "SYNTHETIC. Failed logins go unlogged on one database.",
            "rationale": "SYNTHETIC. Logging is enabled on the replica; the primary is planned.",
            "evaluator": "Example Provider vulnerability team (synthetic untimed plan)",
            "disposition": "partially_mitigated",
            "projectedNextReduction": {"estimatedAt": "2026-09-09T16:00:00Z", "targetRating": 2},
        }
        path = self.workspace / "untimed.json"
        path.write_text(json.dumps({"evaluations": [entry]}), encoding="utf-8")
        self.succeeds(["cases", "evaluate", "--db", str(self.database), "--evaluations", str(path)])
        code, out, err = self.response_gaps()
        self.assertEqual(code, 3, msg=err)
        lines = out.splitlines()
        self.assertIn(f"recorded {LAPSE_LINE}", lines[0])
        self.assertIn(
            "recorded planned reduction of case-a28eeaac0789b5e2 to N2 was not recorded by "
            "2026-09-09T16:00:00Z",
            lines[1],
        )
        plan_id = self.recorded_ids(out)[1]
        code, _, err = self.report()
        self.assertEqual(code, 1)
        self.assertIn("error: detection_time_missing: ", err)
        out, err = self.succeeds(["store", "verify", "--db", str(self.database)])
        self.assertTrue(out.startswith("ok: "), msg=err)
        self.attest()
        codes = self.codes()
        self.assertIn(WARNING, codes)
        self.assertEqual(self.notes(), [])
        # The recorded lapse itself is in the report once it compiles, not only its warning.
        path = self.workspace / "attested.json"
        code, _, err = self.report("-o", str(path))
        self.assertEqual(code, 0, msg=err)
        document = json.loads(path.read_text(encoding="utf-8"))
        carried = [
            item
            for item in document["activeVulnerabilities"]
            if plan_id in item["x-complyroll"]["observationIds"]
        ]
        self.assertEqual(len(carried), 1)
        self.assertEqual(carried[0]["x-complyroll"]["observationIds"], [plan_id])


if __name__ == "__main__":
    unittest.main()
