# ******************************************************************************
# *Title: Plan Lapse Stream Tests*
# *Author: Kyle Versluis*
# *Description: The planned response gap head, its audits and store schema 8.*
# ******************************************************************************
"""Tests for the `response_gap.plan_lapsed` head and store schema 8 (ADR 0019, plan D8, D9)."""

# *--- Imports ---*

from __future__ import annotations

import sqlite3
import unittest
from collections.abc import Mapping
from contextlib import closing
from datetime import UTC, datetime
from typing import Any
from unittest import mock

from test_cli import RECURRENCE_ARTIFACTS, PersistedStoreTestCase, run
from test_coverage_streams import StoreCase, metadata, pending, rebuilt
from test_response_gap_streams import (
    INGESTED_AT,
    REPORT_OPTIONS,
    SEVENTH,
    lapse_record,
    record_gap,
    recurrence_record,
)
from test_response_gaps import CASE_ID, fail

from complyroll.events import (
    RESPONSE_GAP_HEAD_TYPES,
    RESPONSE_GAP_PLAN_LAPSED,
    RESPONSE_GAP_PLAN_SCHEMA_VERSION,
    RESPONSE_GAP_RECORDED,
    RESPONSE_GAP_STREAM_EVENT_TYPES,
    RESPONSE_GAP_STREAM_SCHEMA_VERSION,
    EventContractError,
    response_gap_head_payload,
    response_gap_head_type,
    response_gap_record_disagreement,
    response_gap_stream_id_of,
)
from complyroll.events import repository as repository_module
from complyroll.history import HistoryError, audit_history, rehydrate_observations
from complyroll.models import Observation, PainRating
from complyroll.reports import response_gaps as builder
from complyroll.reports.response_gaps import PlanLapse, plan_lapse_observation
from complyroll.store import (
    SUPPORTED_SCHEMA_VERSION,
    NewEvent,
    SQLiteEventStore,
    UnsupportedSchemaError,
)
from complyroll.store import sqlite as sqlite_module

# *--- Fixtures ---*

NOW = datetime(2026, 11, 27, 12, 0, tzinfo=UTC)
COMPLETED_AT = datetime(2026, 8, 5, 12, 0, tzinfo=UTC)
PLANNED_AT = datetime(2026, 8, 12, 16, 0, tzinfo=UTC)
PLANNED_TEXT = "2026-08-12T16:00:00Z"
EIGHTH = (8, "planned response gap heads, ADR 0019")


def plan_record(
    tracking_id: str = CASE_ID,
    *,
    planned_at: datetime = PLANNED_AT,
    target: PainRating = PainRating.N2,
) -> Observation:
    """Return the lapse of a plan to reach `target` by `planned_at`, rated N3 when it passed."""
    lapse = PlanLapse(tracking_id, COMPLETED_AT, planned_at, target, PainRating.N3)
    return plan_lapse_observation(lapse, ingested_at=NOW)


def plan_events(
    record: Observation, head: Mapping[str, Any] | None = None, *, head_type: str | None = None
) -> list[tuple[str, dict[str, Any]]]:
    """Return the two events one plan lapse stream holds: its head, then its record."""
    return [
        (
            response_gap_head_type(record) if head_type is None else head_type,
            dict(response_gap_head_payload(record) if head is None else head),
        ),
        ("observation.recorded", record.to_canonical_dict()),
    ]


def record_plan(repository: Any, record: Observation) -> str:
    """Record one plan lapse through the repository, as the writer does."""
    stream_id = response_gap_stream_id_of(record)
    repository.append_batch(
        stream_id,
        tuple(pending(event_type, payload) for event_type, payload in plan_events(record)),
        expected_version=0,
    )
    return stream_id


def with_metadata(record: Observation, **values: str) -> Observation:
    """Return the record with metadata values replaced, under the id it now derives."""
    replaced = {**dict(record.source_metadata), **values}
    return rebuilt(record, source_metadata=tuple(sorted(replaced.items())))


# *--- Identity ---*


class PlanLapseIdentityConstantTests(unittest.TestCase):
    """The event layer spells each plan lapse constant the report layer writes."""

    def test_the_repository_spells_the_builders_constants(self) -> None:
        for name in (
            "PLAN_LAPSE_SOURCE_TYPE",
            "PLAN_LAPSE_PARSER_NAME",
            "PLAN_LAPSE_PARSER_VERSION",
            "PLAN_LAPSE_RECORD_ID",
            "PLAN_LAPSE_TITLE",
            "PLAN_LAPSE_DESCRIPTION",
            "PLAN_LAPSE_METADATA_KEYS",
        ):
            with self.subTest(name=name):
                self.assertEqual(getattr(repository_module, name), getattr(builder, name))
        self.assertEqual(repository_module.RESPONSE_GAP_SOURCE_TOOL, builder.PLAN_LAPSE_SOURCE_TOOL)

    def test_the_head_is_a_second_type_on_the_same_stream_kind(self) -> None:
        self.assertEqual(RESPONSE_GAP_PLAN_LAPSED, "response_gap.plan_lapsed")
        self.assertEqual(RESPONSE_GAP_HEAD_TYPES, (RESPONSE_GAP_RECORDED, RESPONSE_GAP_PLAN_LAPSED))
        self.assertEqual(
            RESPONSE_GAP_STREAM_EVENT_TYPES,
            {RESPONSE_GAP_RECORDED, RESPONSE_GAP_PLAN_LAPSED, "observation.recorded"},
        )
        self.assertEqual(
            response_gap_stream_id_of(plan_record()), f"response-gap/{plan_record().fingerprint}"
        )
        self.assertEqual(response_gap_head_type(plan_record()), RESPONSE_GAP_PLAN_LAPSED)
        self.assertEqual(response_gap_head_type(recurrence_record()), RESPONSE_GAP_RECORDED)
        self.assertEqual(response_gap_head_type(lapse_record()), RESPONSE_GAP_RECORDED)

    def test_the_head_is_read_off_the_record_with_the_target_an_integer(self) -> None:
        self.assertEqual(
            response_gap_head_payload(plan_record()),
            {
                "caseTrackingId": CASE_ID,
                "contextKey": f"{CASE_ID}:planned:{PLANNED_TEXT}:2",
                "estimatedAt": PLANNED_TEXT,
                "targetRating": 2,
            },
        )

    def test_the_earlier_heads_keep_their_bytes(self) -> None:
        # A plan lapse adds no field to `response_gap.recorded`, which stays nine fields.
        self.assertEqual(
            sorted(response_gap_head_payload(recurrence_record())),
            sorted(
                (
                    "kind",
                    "caseTrackingId",
                    "contextKey",
                    "remediatedAt",
                    "observationId",
                    "observationDetectedAt",
                    "firstSeenAt",
                    "windowClosedAt",
                    "rule",
                )
            ),
        )

    def test_a_head_is_refused_for_a_record_whose_target_is_not_a_rating(self) -> None:
        stray = with_metadata(plan_record(), **{"plan.targetRating": "N2"})
        with self.assertRaisesRegex(ValueError, "not 1 to 5"):
            response_gap_head_payload(stray)


# *--- Contract ---*


class PlanLapseContractTests(StoreCase):
    """The plan lapse head contract is closed, requires four fields, and holds a rating."""

    def test_the_head_validates(self) -> None:
        self.repository.validate_payload(
            RESPONSE_GAP_PLAN_LAPSED, response_gap_head_payload(plan_record())
        )

    def test_a_malformed_head_is_refused(self) -> None:
        head = dict(response_gap_head_payload(plan_record()))
        for label, broken in (
            ("missing", {key: value for key, value in head.items() if key != "targetRating"}),
            ("extra", {**head, "kind": "plan"}),
            ("rating 0", {**head, "targetRating": 0}),
            ("rating 6", {**head, "targetRating": 6}),
            ("rating text", {**head, "targetRating": "2"}),
            ("rating bool", {**head, "targetRating": True}),
            ("rating fraction", {**head, "targetRating": 2.5}),
            ("tracking id", {**head, "caseTrackingId": "PROVIDER-1"}),
            ("instant", {**head, "estimatedAt": "2026-02-30T00:00:00Z"}),
            ("offset", {**head, "estimatedAt": "2026-08-12T09:00:00-07:00"}),
            ("blank key", {**head, "contextKey": " "}),
        ):
            with self.subTest(label):
                with self.assertRaises(EventContractError):
                    self.repository.validate_payload(RESPONSE_GAP_PLAN_LAPSED, broken)

    def test_neither_head_contract_takes_the_other_heads_payload(self) -> None:
        with self.assertRaises(EventContractError):
            self.repository.validate_payload(
                RESPONSE_GAP_RECORDED, response_gap_head_payload(plan_record())
            )
        with self.assertRaises(EventContractError):
            self.repository.validate_payload(
                RESPONSE_GAP_PLAN_LAPSED, response_gap_head_payload(recurrence_record())
            )


# *--- Append ---*


class PlanLapseAppendTests(StoreCase):
    """A plan lapse stream is written whole and once, head first, held to its record."""

    def test_a_whole_stream_appends_and_marks_schema_8(self) -> None:
        self.assertEqual(self.store.schema_version, 1)
        stream_id = record_plan(self.repository, plan_record())
        self.assertEqual(self.store.schema_version, RESPONSE_GAP_PLAN_SCHEMA_VERSION)
        self.assertEqual(self.migrations()[-2:], [SEVENTH, EIGHTH])
        self.assertEqual([version for version, _ in self.migrations()], [1, 2, 3, 4, 5, 6, 7, 8])
        self.assertEqual(self.repository.current_version(stream_id), 2)
        self.assertTrue(self.repository.holds_response_gap_stream())
        self.assertEqual(
            [item.observation_id for item in rehydrate_observations(self.repository)],
            [plan_record().observation_id],
        )
        self.assertEqual(audit_history(self.repository), ())

    def test_the_earlier_kinds_stay_at_7_and_a_plan_moves_the_store_to_8(self) -> None:
        record_gap(self.repository, recurrence_record())
        record_gap(self.repository, lapse_record())
        self.assertEqual(self.store.schema_version, RESPONSE_GAP_STREAM_SCHEMA_VERSION)
        self.assertEqual(self.migrations()[-1], SEVENTH)
        record_plan(self.repository, plan_record())
        self.assertEqual(self.store.schema_version, 8)
        self.assertEqual(self.migrations()[-1], EIGHTH)
        self.assertEqual(
            [item.observation_id for item in rehydrate_observations(self.repository)],
            [
                recurrence_record().observation_id,
                lapse_record().observation_id,
                plan_record().observation_id,
            ],
        )
        self.assertEqual(audit_history(self.repository), ())

    def test_every_shape_but_the_whole_batch_is_refused_and_writes_nothing(self) -> None:
        record = plan_record()
        stream_id = response_gap_stream_id_of(record)
        head, observed = plan_events(record)
        for label, events, version in (
            ("head alone", [head], 0),
            ("record first", [observed, head], 0),
            ("three events", [head, observed, observed], 0),
            ("two heads", [head, head], 0),
            ("a later version", [head, observed], 2),
        ):
            with self.subTest(shape=label):
                with self.assertRaises(EventContractError) as caught:
                    self.repository.append_batch(
                        stream_id,
                        tuple(pending(event_type, payload) for event_type, payload in events),
                        expected_version=version,
                    )
                self.assertIn(stream_id, str(caught.exception))
        self.assertEqual(self.store.latest_sequence, 0)
        self.assertEqual(self.store.schema_version, 1)

    def test_a_second_write_is_refused(self) -> None:
        stream_id = record_plan(self.repository, plan_record())
        with self.assertRaises(EventContractError):
            record_plan(self.repository, plan_record())
        self.assertEqual(self.repository.current_version(stream_id), 2)

    def test_a_head_of_the_other_type_is_refused(self) -> None:
        record = plan_record()
        recurrence = recurrence_record()
        for label, stream_id, events in (
            (
                "plan record under the recorded head",
                response_gap_stream_id_of(record),
                plan_events(
                    record, response_gap_head_payload(recurrence), head_type=RESPONSE_GAP_RECORDED
                ),
            ),
            (
                "recurrence under the plan head",
                response_gap_stream_id_of(recurrence),
                [
                    (RESPONSE_GAP_PLAN_LAPSED, response_gap_head_payload(record)),
                    ("observation.recorded", recurrence.to_canonical_dict()),
                ],
            ),
        ):
            with self.subTest(label):
                with self.assertRaisesRegex(EventContractError, "whose head is"):
                    self.repository.append_batch(
                        stream_id,
                        tuple(pending(event_type, payload) for event_type, payload in events),
                        expected_version=0,
                    )
        self.assertEqual(self.store.latest_sequence, 0)
        self.assertEqual(self.store.schema_version, 1)

    def test_a_head_that_disagrees_with_its_record_is_refused(self) -> None:
        record = plan_record()
        head = dict(response_gap_head_payload(record))
        for field_name, value in (
            ("caseTrackingId", "case-ffffffffffffffff"),
            ("contextKey", f"{CASE_ID}:planned:{PLANNED_TEXT}:3"),
            ("estimatedAt", "2026-08-13T16:00:00Z"),
            ("targetRating", 3),
        ):
            with self.subTest(field=field_name):
                with self.assertRaisesRegex(EventContractError, "the two describe one gap"):
                    self.repository.append_batch(
                        response_gap_stream_id_of(record),
                        tuple(
                            pending(event_type, payload)
                            for event_type, payload in plan_events(
                                record, {**head, field_name: value}
                            )
                        ),
                        expected_version=0,
                    )
        self.assertEqual(self.store.latest_sequence, 0)

    def test_the_target_is_compared_as_the_integer_its_record_spells(self) -> None:
        record = plan_record().to_canonical_dict()
        head = dict(response_gap_head_payload(plan_record()))
        stream_id = response_gap_stream_id_of(plan_record())
        self.assertIsNone(
            response_gap_record_disagreement(
                stream_id, head, record, head_type=RESPONSE_GAP_PLAN_LAPSED
            )
        )
        for value in (True, "2", 2.0, None):
            with self.subTest(value=value):
                self.assertIsNotNone(
                    response_gap_record_disagreement(
                        stream_id,
                        {**head, "targetRating": value},
                        record,
                        head_type=RESPONSE_GAP_PLAN_LAPSED,
                    )
                )

    def test_a_record_edited_in_a_field_the_fingerprint_does_not_cover_is_refused(self) -> None:
        record = plan_record()
        for field_name, value, why in (
            ("title", "edited", "its title is"),
            ("description", "edited", "its description is"),
            ("evidence_ids", ("case:case-ffffffffffffffff",), "its evidence ids are"),
        ):
            with self.subTest(field=field_name):
                with self.assertRaisesRegex(EventContractError, why):
                    record_plan(self.repository, rebuilt(record, **{field_name: value}))
        self.assertEqual(self.store.latest_sequence, 0)

    def test_a_metadata_value_its_writer_never_records_is_refused(self) -> None:
        record = plan_record()
        for label, edited, why in (
            (
                "tracking id",
                with_metadata(record, **{"plan.caseTrackingId": "case-ffffffffffffffff"}),
                "its resource is",
            ),
            (
                "instant spelling",
                with_metadata(record, **{"plan.estimatedAt": "2026-08-12T16:00:00.000000Z"}),
                "not an instant as its writer spells one",
            ),
            (
                "instant moved",
                with_metadata(record, **{"plan.estimatedAt": "2026-08-13T16:00:00Z"}),
                "where the record is observed at",
            ),
            (
                "rating with a zero",
                rebuilt(
                    with_metadata(record, **{"plan.targetRating": "02"}),
                    context_key=f"{CASE_ID}:planned:{PLANNED_TEXT}:02",
                ),
                "not a rating from 1 to 5",
            ),
            (
                "rating moved",
                with_metadata(record, **{"plan.targetRating": "3"}),
                "context key",
            ),
            (
                "context key",
                rebuilt(record, context_key=f"{CASE_ID}:planned:{PLANNED_TEXT}:2:x"),
                "context key",
            ),
        ):
            with self.subTest(label):
                payload = edited.to_canonical_dict()
                problem = repository_module.response_gap_record_problem(
                    response_gap_stream_id_of(edited), "observation.recorded", payload
                )
                assert problem is not None
                self.assertEqual(problem[0], "responsegap_identity_breach")
                self.assertIn(why, problem[1])

    def test_a_tracking_id_the_head_contract_refuses_is_named_by_the_record_check(self) -> None:
        payload = plan_record().to_canonical_dict()
        payload["source_metadata"] = {**payload["source_metadata"], "plan.caseTrackingId": "X-1"}
        problem = repository_module.response_gap_record_problem(
            response_gap_stream_id_of(plan_record()), "observation.recorded", payload
        )
        assert problem is not None
        self.assertEqual(problem[0], "responsegap_identity_breach")
        self.assertIn("not a correlation tracking id", problem[1])

    def test_only_a_response_gap_record_names_a_stream(self) -> None:
        with self.assertRaisesRegex(ValueError, "'complyroll.response-plan' names a response gap"):
            response_gap_stream_id_of(fail("lab-01", NOW))


# *--- Schema ---*


class PlanLapseSchemaTests(StoreCase):
    """A store that records a plan lapse is schema 8; one that records only PR 1's stays at 7."""

    def test_this_build_opens_schema_8(self) -> None:
        self.assertEqual(SUPPORTED_SCHEMA_VERSION, RESPONSE_GAP_PLAN_SCHEMA_VERSION)
        self.assertEqual(sqlite_module._MIGRATION_DESCRIPTIONS[8], EIGHTH[1])

    def test_a_schema_7_build_refuses_a_store_holding_a_plan_lapse(self) -> None:
        record_plan(self.repository, plan_record())
        self.store.close()
        with mock.patch.object(sqlite_module, "SUPPORTED_SCHEMA_VERSION", 7):
            with self.assertRaises(UnsupportedSchemaError) as caught:
                SQLiteEventStore(self.path)
        self.assertIn("database schema 8 is newer than supported schema 7", str(caught.exception))

    def test_a_schema_7_build_still_opens_a_store_holding_only_the_earlier_kinds(self) -> None:
        record_gap(self.repository, recurrence_record())
        self.store.close()
        with mock.patch.object(sqlite_module, "SUPPORTED_SCHEMA_VERSION", 7):
            reopened = SQLiteEventStore(self.path)
            self.addCleanup(reopened.close)
            self.assertEqual(reopened.schema_version, 7)

    def test_a_refused_append_leaves_the_schema(self) -> None:
        record_gap(self.repository, recurrence_record())
        record = plan_record()
        head = dict(response_gap_head_payload(record), targetRating=3)
        with self.assertRaises(EventContractError):
            self.repository.append_batch(
                response_gap_stream_id_of(record),
                tuple(pending(kind, payload) for kind, payload in plan_events(record, head)),
                expected_version=0,
            )
        self.assertEqual(self.store.schema_version, 7)
        self.assertEqual(self.migrations()[-1], SEVENTH)


# *--- Audit And Reader ---*


class PlanLapseAuditTests(StoreCase):
    """Whatever a report from the store refuses, `store verify` rejects, in one text (D9)."""

    def refused(self, code: str) -> None:
        """Hold the reader to a refusal and the audit to the same fault, by text."""
        faults = [fault for fault in audit_history(self.repository) if fault.code == code]
        self.assertTrue(faults, f"the audit names no {code}")
        with self.assertRaises(HistoryError) as caught:
            rehydrate_observations(self.repository)
        self.assertTrue(
            any(fault.message in str(caught.exception) for fault in faults),
            f"{caught.exception} names none of {[fault.message for fault in faults]}",
        )

    def stage_plan(self, events: list[tuple[str, dict[str, Any]]], **kwargs: Any) -> None:
        stream_id = kwargs.pop("stream_id", response_gap_stream_id_of(plan_record()))
        self.stage(stream_id, events, requires_schema=kwargs.pop("schema", 8))

    def test_a_head_alone_is_incomplete(self) -> None:
        self.stage_plan(plan_events(plan_record())[:1])
        self.refused("responsegap_incomplete")
        (fault,) = [f for f in audit_history(self.repository) if f.code == "responsegap_incomplete"]
        self.assertIn(
            "holds one response_gap.recorded or response_gap.plan_lapsed head and one "
            "observation, found 1 head(s) and 0 observation(s)",
            fault.message,
        )

    def test_a_second_record_or_a_second_head_of_either_type_is_overfull(self) -> None:
        head, observed = plan_events(plan_record())
        recorded_head = (RESPONSE_GAP_RECORDED, response_gap_head_payload(recurrence_record()))
        for label, events in (
            ("second record", [head, observed, observed]),
            ("second head", [head, recorded_head, observed]),
        ):
            with self.subTest(label):
                self.setUp()
                self.stage_plan(events)
                self.refused("responsegap_overfull")

    def test_a_record_ahead_of_its_head_is_a_stream_mismatch(self) -> None:
        head, observed = plan_events(plan_record())
        self.stage_plan([observed, head])
        self.refused("responsegap_stream_mismatch")

    def test_a_head_that_disagrees_or_is_of_the_other_type_is_an_identity_breach(self) -> None:
        record = plan_record()
        for label, events in (
            (
                "rating",
                plan_events(record, {**response_gap_head_payload(record), "targetRating": 4}),
            ),
            (
                "other type",
                plan_events(
                    record,
                    response_gap_head_payload(recurrence_record()),
                    head_type=RESPONSE_GAP_RECORDED,
                ),
            ),
        ):
            with self.subTest(label):
                self.setUp()
                self.stage_plan(events)
                self.refused("responsegap_identity_breach")

    def test_an_edited_record_is_an_identity_breach(self) -> None:
        edited = rebuilt(plan_record(), title="edited")
        self.stage_plan(plan_events(edited), stream_id=response_gap_stream_id_of(edited))
        self.refused("responsegap_identity_breach")

    def test_a_plan_head_in_a_store_below_schema_8_names_8_and_is_still_read(self) -> None:
        for schema in (7, 6, 1):
            with self.subTest(schema=schema):
                self.setUp()
                record_gap_at = schema
                self.stage_plan(plan_events(plan_record()), schema=record_gap_at)
                faults = audit_history(self.repository)
                self.assertEqual([fault.code for fault in faults], ["responsegap_schema_unmarked"])
                self.assertEqual(
                    faults[0].message,
                    f"response gap stream {response_gap_stream_id_of(plan_record())!r} holds a "
                    f"response_gap.plan_lapsed in a store at schema {schema}; a store holding a "
                    "planned response gap head is marked schema 8, so a build that cannot read it "
                    "refuses it rather than misreading it",
                )
                # Content-neutral, as every marker fault is: no reader refuses it.
                self.assertEqual(
                    [item.observation_id for item in rehydrate_observations(self.repository)],
                    [plan_record().observation_id],
                )

    def test_an_earlier_kind_at_schema_7_beside_no_plan_is_no_fault(self) -> None:
        self.stage(
            response_gap_stream_id_of(recurrence_record()),
            [
                (RESPONSE_GAP_RECORDED, response_gap_head_payload(recurrence_record())),
                ("observation.recorded", recurrence_record().to_canonical_dict()),
            ],
            requires_schema=7,
        )
        self.assertEqual(audit_history(self.repository), ())

    def test_a_missing_case_is_not_a_fault(self) -> None:
        # The head is held to its own record; a lapse recorded before correlation is legal.
        record_plan(self.repository, plan_record())
        self.assertEqual(audit_history(self.repository), ())


# *--- Store Verify ---*


class PlanLapseStoreVerifyCommandTests(PersistedStoreTestCase):
    """`store verify` names each plan lapse fault and exits 1; every reader refuses it by name."""

    def setUp(self) -> None:
        super().setUp()
        before, after = RECURRENCE_ARTIFACTS
        self.succeeds(["ingest", before, after, "--db", str(self.database), "--as-of", INGESTED_AT])

    def smuggle(self, events: list[tuple[str, dict[str, Any]]], *, schema: int = 8) -> None:
        """Append the events to the plan record's stream straight to the store."""
        with SQLiteEventStore(self.database) as store:
            for version, (event_type, payload) in enumerate(events):
                store.append(
                    response_gap_stream_id_of(plan_record()),
                    [
                        NewEvent(
                            event_type=event_type,
                            occurred_at=NOW,
                            payload=payload,
                            metadata=metadata().to_dict(),
                        )
                    ],
                    expected_version=version,
                    requires_schema=schema,
                )

    def verify_faults(self) -> list[str]:
        code, out, err = run(["store", "verify", "--db", str(self.database)])
        self.assertEqual((code, out), (1, ""), msg=err)
        return err.splitlines()[:-1]

    def test_a_whole_stream_verifies_and_reports(self) -> None:
        self.smuggle(plan_events(plan_record()))
        out, err = self.succeeds(["store", "verify", "--db", str(self.database)])
        self.assertTrue(out.startswith("ok: "), msg=err)
        self.succeeds(["report", "vdt", "--db", str(self.database), *REPORT_OPTIONS])

    def test_each_damaged_shape_is_named_by_verify_and_refused_by_every_reader(self) -> None:
        record = plan_record()
        head, observed = plan_events(record)
        disagreeing = plan_events(record, {**head[1], "targetRating": 4})
        for label, events, code in (
            ("head alone", [head], "responsegap_incomplete"),
            ("second record", [head, observed, observed], "responsegap_overfull"),
            ("record first", [observed, head], "responsegap_stream_mismatch"),
            ("head disagrees", disagreeing, "responsegap_identity_breach"),
        ):
            with self.subTest(shape=label):
                self.setUp()
                self.smuggle(events)
                lines = [line for line in self.verify_faults() if f": {code}: " in line]
                self.assertEqual(len(lines), 1, msg=self.verify_faults())
                message = lines[0].split(f": {code}: ", 1)[1]
                with closing(sqlite3.connect(self.database)) as connection:
                    before = connection.execute("SELECT COUNT(*) FROM events").fetchone()
                for argv in (
                    ["report", "vdt", "--db", str(self.database), *REPORT_OPTIONS],
                    ["cases", "correlate", "--db", str(self.database)],
                    ["cases", "response-gaps", "--db", str(self.database), "--class", "C"]
                    + ["--as-of", "2026-09-15T12:00:00Z"],
                ):
                    code_seen, out, err = run(argv)
                    self.assertEqual((code_seen, out), (1, ""), msg=err)
                    self.assertIn("error: history_invalid: ", err)
                    self.assertIn(message, err)
                with closing(sqlite3.connect(self.database)) as connection:
                    after = connection.execute("SELECT COUNT(*) FROM events").fetchone()
                self.assertEqual(after, before)

    def test_an_unmarked_store_is_named_and_still_reports(self) -> None:
        self.smuggle(plan_events(plan_record()), schema=7)
        (line,) = self.verify_faults()
        self.assertIn(": responsegap_schema_unmarked: ", line)
        self.assertIn("is marked schema 8", line)
        code, _, err = run(["report", "vdt", "--db", str(self.database), *REPORT_OPTIONS])
        self.assertEqual(code, 0, msg=err)


if __name__ == "__main__":
    unittest.main()
