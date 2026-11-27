# ******************************************************************************
# *Title: Response Gap Stream Tests*
# *Author: Kyle Versluis*
# *Description: Response gap streams, contract, audits and store schema 7.*
# ******************************************************************************
"""Tests for the response gap stream kind and store schema 7 (ADR 0019)."""

# *--- Imports ---*

from __future__ import annotations

import sqlite3
import unittest
from collections.abc import Mapping
from contextlib import closing
from datetime import UTC, datetime
from typing import Any
from unittest import mock

from test_cli import (
    KEV_ARGUMENTS,
    KEV_AS_OF,
    KEV_PERIOD,
    RECURRENCE_ARTIFACTS,
    PersistedStoreTestCase,
    run,
)
from test_coverage import policy
from test_coverage_streams import StoreCase, metadata, pending, rebuilt
from test_response_gaps import (
    BACK_AT,
    CASE_ID,
    FIRST_SEEN,
    INGESTED,
    REMEDIATED_AT,
    Case,
    fail,
)

from complyroll.correlation import group_open_observations
from complyroll.events import (
    RESPONSE_GAP_ATTESTATION_RULE,
    RESPONSE_GAP_RECORDED,
    RESPONSE_GAP_STREAM_PREFIX,
    RESPONSE_GAP_STREAM_SCHEMA_VERSION,
    EventContractError,
    EventRepository,
    is_change_gap_stream,
    is_response_gap_stream,
    response_gap_head_payload,
    response_gap_stream_fingerprint,
    response_gap_stream_id,
    response_gap_stream_id_of,
    stream_kind,
)
from complyroll.events import repository as repository_module
from complyroll.history import (
    AUDIT_FAULT_CODES,
    HistoryError,
    audit_history,
    rehydrate_observations,
)
from complyroll.models import Observation
from complyroll.reports import response_gaps as builder
from complyroll.reports.response_gaps import (
    attestation_lapse,
    attestation_lapse_observation,
    recurrence_observations,
    remediation_recurrences,
)
from complyroll.store import (
    SUPPORTED_SCHEMA_VERSION,
    NewEvent,
    SQLiteEventStore,
    UnsupportedSchemaError,
)
from complyroll.store import sqlite as sqlite_module

# *--- Fixtures ---*

NOW = datetime(2026, 11, 26, 12, 0, tzinfo=UTC)
#: The ingest `--as-of` of the store the command tests plant damage in.
INGESTED_AT = "2026-09-13T00:00:00Z"
#: A report of that store, as the recurrence golden's run reads it.
REPORT_OPTIONS = (*KEV_ARGUMENTS, "--as-of", KEV_AS_OF, *KEV_PERIOD)
SEVENTH = (7, "response gap streams, ADR 0019")
RESPONSE_CODES = (
    "responsegap_identity_breach",
    "responsegap_incomplete",
    "responsegap_overfull",
    "responsegap_schema_unmarked",
    "responsegap_stream_mismatch",
)


def recurrence_record() -> Observation:
    """Return the recurrence a remediation of 5 August that a scan of 10 August contradicts."""
    (group,) = group_open_observations((fail("lab-01", FIRST_SEEN), fail("lab-01", BACK_AT)))
    (recurrence,) = remediation_recurrences((group,), {group.tracking_id: REMEDIATED_AT})
    (record,) = recurrence_observations(recurrence, ingested_at=NOW)
    return record


def lapse_record() -> Observation:
    """Return the lapse of an untimed case first seen 1 September, under class C."""
    lapse = attestation_lapse(Case(), INGESTED, policy("C"), NOW)
    assert lapse is not None
    return attestation_lapse_observation(lapse, ingested_at=NOW)


def events_of(
    record: Observation, head: Mapping[str, Any] | None = None
) -> list[tuple[str, dict[str, Any]]]:
    """Return the two events one response gap stream holds: its head, then its record."""
    return [
        (RESPONSE_GAP_RECORDED, dict(response_gap_head_payload(record) if head is None else head)),
        ("observation.recorded", record.to_canonical_dict()),
    ]


def record_gap(repository: EventRepository, record: Observation) -> str:
    """Record one response gap through the repository, as the writer does."""
    stream_id = response_gap_stream_id_of(record)
    repository.append_batch(
        stream_id,
        tuple(pending(event_type, payload) for event_type, payload in events_of(record)),
        expected_version=0,
    )
    return stream_id


# *--- Identity ---*


class ResponseGapIdentityConstantTests(unittest.TestCase):
    """The event layer spells each builder constant the report layer writes."""

    def test_the_repository_spells_the_builders_constants(self) -> None:
        for name in (
            "RECURRENCE_SOURCE_TYPE",
            "RECURRENCE_PARSER_NAME",
            "RECURRENCE_PARSER_VERSION",
            "RECURRENCE_RECORD_ID",
            "RECURRENCE_TITLE",
            "RECURRENCE_DESCRIPTION",
            "RECURRENCE_METADATA_KEYS",
            "ATTESTATION_LAPSE_SOURCE_TYPE",
            "ATTESTATION_LAPSE_PARSER_NAME",
            "ATTESTATION_LAPSE_PARSER_VERSION",
            "ATTESTATION_LAPSE_RECORD_ID",
            "ATTESTATION_LAPSE_TITLE",
            "ATTESTATION_LAPSE_DESCRIPTION",
            "ATTESTATION_LAPSE_METADATA_KEYS",
            "ATTESTATION_LAPSE_RESOURCE_TYPE",
            "ATTESTATION_LAPSE_RESOURCE_PREFIX",
        ):
            with self.subTest(name=name):
                self.assertEqual(getattr(repository_module, name), getattr(builder, name))
        self.assertEqual(repository_module.RESPONSE_GAP_SOURCE_TOOL, builder.RECURRENCE_SOURCE_TOOL)
        self.assertEqual(
            repository_module.RESPONSE_GAP_SOURCE_TOOL, builder.ATTESTATION_LAPSE_SOURCE_TOOL
        )
        self.assertEqual(RESPONSE_GAP_ATTESTATION_RULE, builder.ATTESTATION_LAPSE_RULE)


class ResponseGapStreamIdTests(unittest.TestCase):
    """A response gap stream is named for its record's fingerprint (F12)."""

    def test_the_stream_id_names_the_fingerprint_and_reads_back(self) -> None:
        for record in (recurrence_record(), lapse_record()):
            with self.subTest(source_type=record.source_type):
                stream_id = response_gap_stream_id_of(record)
                self.assertEqual(stream_id, f"response-gap/{record.fingerprint}")
                self.assertEqual(response_gap_stream_fingerprint(stream_id), record.fingerprint)
                self.assertTrue(is_response_gap_stream(stream_id))
                self.assertFalse(is_change_gap_stream(stream_id))
                self.assertEqual(stream_kind(stream_id), RESPONSE_GAP_STREAM_PREFIX)
                self.assertNotIn(CASE_ID, stream_id)

    def test_only_a_response_gap_record_names_a_stream(self) -> None:
        with self.assertRaisesRegex(ValueError, "names a response gap stream"):
            response_gap_stream_id_of(fail("lab-01", BACK_AT))
        with self.assertRaises(ValueError):
            response_gap_stream_id("not-a-digest")
        with self.assertRaises(ValueError):
            response_gap_stream_fingerprint("changegap/" + "a" * 64)

    def test_the_head_is_read_off_the_record_with_the_other_kind_null(self) -> None:
        self.assertEqual(
            response_gap_head_payload(recurrence_record()),
            {
                "kind": "recurrence",
                "caseTrackingId": recurrence_record().metadata_value("recurrence.caseTrackingId"),
                "contextKey": recurrence_record().context_key,
                "remediatedAt": "2026-08-05T12:00:00Z",
                "observationId": recurrence_record().metadata_value("recurrence.observationId"),
                "observationDetectedAt": "2026-08-10T09:00:00Z",
                "firstSeenAt": None,
                "windowClosedAt": None,
                "rule": None,
            },
        )
        self.assertEqual(
            response_gap_head_payload(lapse_record()),
            {
                "kind": "attestation",
                "caseTrackingId": CASE_ID,
                "contextKey": CASE_ID,
                "remediatedAt": None,
                "observationId": None,
                "observationDetectedAt": None,
                "firstSeenAt": "2026-09-01T08:00:00Z",
                "windowClosedAt": "2026-09-06T08:00:00Z",
                "rule": "VER-TFR-EVU",
            },
        )


# *--- Contract ---*


class ResponseGapContractTests(StoreCase):
    """The head contract is closed, requires every field, and nulls the other kind's."""

    def test_both_kinds_of_head_validate(self) -> None:
        for record in (recurrence_record(), lapse_record()):
            with self.subTest(source_type=record.source_type):
                self.repository.validate_payload(
                    RESPONSE_GAP_RECORDED, response_gap_head_payload(record)
                )

    def test_a_head_naming_the_other_kinds_field_is_refused(self) -> None:
        head = dict(response_gap_head_payload(recurrence_record()))
        for field_name, value in (
            ("firstSeenAt", "2026-09-01T08:00:00Z"),
            ("windowClosedAt", "2026-09-06T08:00:00Z"),
            ("rule", "VER-TFR-EVU"),
        ):
            with self.subTest(field=field_name):
                with self.assertRaises(EventContractError):
                    self.repository.validate_payload(
                        RESPONSE_GAP_RECORDED, {**head, field_name: value}
                    )
        lapse = dict(response_gap_head_payload(lapse_record()))
        with self.assertRaises(EventContractError):
            self.repository.validate_payload(
                RESPONSE_GAP_RECORDED, {**lapse, "remediatedAt": None, "rule": None}
            )

    def test_a_missing_or_unknown_field_and_an_unknown_kind_are_refused(self) -> None:
        head = dict(response_gap_head_payload(recurrence_record()))
        for broken in (
            {key: value for key, value in head.items() if key != "firstSeenAt"},
            {**head, "extra": "x"},
            {**head, "kind": "planned"},
            {**head, "caseTrackingId": "PROVIDER-1"},
            {**head, "remediatedAt": "2026-02-30T00:00:00Z"},
        ):
            with self.subTest(broken=sorted(broken)):
                with self.assertRaises(EventContractError):
                    self.repository.validate_payload(RESPONSE_GAP_RECORDED, broken)


# *--- Append ---*


class ResponseGapAppendTests(StoreCase):
    """A response gap stream is written whole and once, head first, held to its record."""

    def test_a_whole_stream_appends_and_marks_schema_7(self) -> None:
        self.assertEqual(self.store.schema_version, 1)
        stream_id = record_gap(self.repository, recurrence_record())
        self.assertEqual(self.store.schema_version, RESPONSE_GAP_STREAM_SCHEMA_VERSION)
        self.assertEqual(self.migrations()[-1], SEVENTH)
        self.assertEqual([version for version, _ in self.migrations()], [1, 2, 3, 4, 5, 6, 7])
        self.assertEqual(self.repository.current_version(stream_id), 2)
        self.assertTrue(self.repository.holds_response_gap_stream())
        record_gap(self.repository, lapse_record())
        self.assertEqual(
            [item.observation_id for item in rehydrate_observations(self.repository)],
            [recurrence_record().observation_id, lapse_record().observation_id],
        )
        self.assertEqual(audit_history(self.repository), ())

    def test_a_store_with_no_response_gap_holds_none(self) -> None:
        self.assertFalse(self.repository.holds_response_gap_stream())

    def test_every_shape_but_the_whole_batch_is_refused_and_writes_nothing(self) -> None:
        record = recurrence_record()
        stream_id = response_gap_stream_id_of(record)
        head, observed = events_of(record)
        for label, events, version in (
            ("head alone", [head], 0),
            ("record first", [observed, head], 0),
            ("three events", [head, observed, observed], 0),
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
        stream_id = record_gap(self.repository, recurrence_record())
        with self.assertRaises(EventContractError) as caught:
            record_gap(self.repository, recurrence_record())
        self.assertIn("more than once", str(caught.exception))
        self.assertEqual(self.repository.current_version(stream_id), 2)

    def test_a_head_that_disagrees_with_its_record_is_refused(self) -> None:
        record = recurrence_record()
        head = dict(response_gap_head_payload(record))
        for field_name, value in (
            ("remediatedAt", "2026-08-06T12:00:00Z"),
            ("observationId", "obs-other"),
            ("caseTrackingId", "case-ffffffffffffffff"),
        ):
            with self.subTest(field=field_name):
                with self.assertRaisesRegex(EventContractError, "the two describe one gap"):
                    self.repository.append_batch(
                        response_gap_stream_id_of(record),
                        tuple(
                            pending(event_type, payload)
                            for event_type, payload in events_of(
                                record, {**head, field_name: value}
                            )
                        ),
                        expected_version=0,
                    )
        with self.assertRaisesRegex(EventContractError, "records kind"):
            lapse_head = response_gap_head_payload(lapse_record())
            self.repository.append_batch(
                response_gap_stream_id_of(record),
                tuple(
                    pending(event_type, payload)
                    for event_type, payload in events_of(record, lapse_head)
                ),
                expected_version=0,
            )
        self.assertEqual(self.store.latest_sequence, 0)

    def test_a_record_on_another_stream_or_of_another_kind_is_refused(self) -> None:
        record = recurrence_record()
        other = lapse_record()
        with self.assertRaisesRegex(EventContractError, "is the record of stream"):
            self.repository.append_batch(
                response_gap_stream_id_of(other),
                tuple(pending(event_type, payload) for event_type, payload in events_of(record)),
                expected_version=0,
            )
        artifact = rebuilt(fail("lab-01", BACK_AT))
        with self.assertRaisesRegex(EventContractError, "names a response gap stream"):
            self.repository.append_batch(
                response_gap_stream_id_of(record),
                (
                    pending(RESPONSE_GAP_RECORDED, response_gap_head_payload(record)),
                    pending("observation.recorded", artifact.to_canonical_dict()),
                ),
                expected_version=0,
            )

    def test_a_record_edited_in_a_field_the_fingerprint_does_not_cover_is_refused(self) -> None:
        record = recurrence_record()
        for field_name, value, why in (
            ("title", "edited", "its title is"),
            ("description", "edited", "its description is"),
            ("evidence_ids", ("obs-elsewhere",), "its evidence ids are"),
        ):
            with self.subTest(field=field_name):
                edited = rebuilt(record, **{field_name: value})
                with self.assertRaisesRegex(EventContractError, why):
                    record_gap(self.repository, edited)
        self.assertEqual(self.store.latest_sequence, 0)

    def test_the_record_check_names_what_the_head_contract_cannot_see(self) -> None:
        # The head contract refuses a case id that is not one, so the record check is reached
        # only by a record written past the repository; it names it in the audit's words.
        for record, key in (
            (recurrence_record(), "recurrence.caseTrackingId"),
            (lapse_record(), "attestation.caseTrackingId"),
        ):
            with self.subTest(key=key):
                payload = record.to_canonical_dict()
                payload["source_metadata"] = {**payload["source_metadata"], key: "PROVIDER-1"}
                problem = repository_module.response_gap_record_problem(
                    response_gap_stream_id_of(record), "observation.recorded", payload
                )
                assert problem is not None
                self.assertEqual(problem[0], "responsegap_identity_breach")
                self.assertIn("not a correlation tracking id", problem[1])

    def test_a_metadata_value_its_writer_never_records_is_refused(self) -> None:
        record = recurrence_record()
        metadata_now = dict(record.source_metadata)
        for key, value, why in (
            ("recurrence.remediatedAt", "2026-08-10T09:00:00Z", "context key"),
            ("recurrence.caseTrackingId", "PROVIDER-1", "caseTrackingId"),
        ):
            with self.subTest(key=key):
                edited = rebuilt(
                    record, source_metadata=tuple(sorted({**metadata_now, key: value}.items()))
                )
                with self.assertRaisesRegex(EventContractError, why):
                    self.repository.append_batch(
                        response_gap_stream_id_of(edited),
                        (
                            pending(RESPONSE_GAP_RECORDED, response_gap_head_payload(edited)),
                            pending("observation.recorded", edited.to_canonical_dict()),
                        ),
                        expected_version=0,
                    )
        lapse = lapse_record()
        lapse_metadata = dict(lapse.source_metadata)
        for key, value, why in (
            ("attestation.firstSeenAt", "2026-09-07T08:00:00Z", "not before its window close"),
            ("attestation.force", "MAYBE", "not a rule force"),
        ):
            with self.subTest(key=key):
                edited = rebuilt(
                    lapse, source_metadata=tuple(sorted({**lapse_metadata, key: value}.items()))
                )
                with self.assertRaisesRegex(EventContractError, why):
                    self.repository.append_batch(
                        response_gap_stream_id_of(edited),
                        (
                            pending(RESPONSE_GAP_RECORDED, response_gap_head_payload(edited)),
                            pending("observation.recorded", edited.to_canonical_dict()),
                        ),
                        expected_version=0,
                    )


# *--- Schema ---*


class ResponseGapSchemaTests(StoreCase):
    """A store that records a response gap is schema 7; one that never does stays put (D9)."""

    def damage(self, statement: str) -> None:
        self.store.close()
        with closing(sqlite3.connect(self.path, isolation_level=None)) as connection:
            connection.execute(statement)

    def test_this_build_opens_schema_7(self) -> None:
        self.assertEqual(SUPPORTED_SCHEMA_VERSION, RESPONSE_GAP_STREAM_SCHEMA_VERSION)
        self.assertEqual(sqlite_module._MIGRATION_DESCRIPTIONS[7], SEVENTH[1])

    def test_a_schema_6_build_refuses_a_store_holding_a_response_gap(self) -> None:
        record_gap(self.repository, recurrence_record())
        self.store.close()
        with mock.patch.object(sqlite_module, "SUPPORTED_SCHEMA_VERSION", 6):
            with self.assertRaises(UnsupportedSchemaError) as caught:
                SQLiteEventStore(self.path)
        self.assertIn("database schema 7 is newer than supported schema 6", str(caught.exception))

    def test_a_schema_6_build_still_opens_a_store_with_no_response_gap(self) -> None:
        self.store.close()
        with mock.patch.object(sqlite_module, "SUPPORTED_SCHEMA_VERSION", 6):
            reopened = SQLiteEventStore(self.path)
            self.addCleanup(reopened.close)
            self.assertEqual(reopened.schema_version, 1)

    def test_a_rolled_back_append_leaves_the_schema(self) -> None:
        record = recurrence_record()
        head = dict(response_gap_head_payload(record), observationId="obs-other")
        with self.assertRaises(EventContractError):
            self.repository.append_batch(
                response_gap_stream_id_of(record),
                tuple(pending(kind, payload) for kind, payload in events_of(record, head)),
                expected_version=0,
            )
        self.assertEqual(self.store.schema_version, 1)

    def test_a_store_newer_than_the_supported_schema_is_refused(self) -> None:
        record_gap(self.repository, recurrence_record())
        self.damage("PRAGMA user_version = 8")
        with self.assertRaises(UnsupportedSchemaError) as caught:
            SQLiteEventStore(self.path)
        self.assertIn("database schema 8 is newer than supported schema 7", str(caught.exception))


# *--- Audit And Reader ---*


class ResponseGapAuditTests(StoreCase):
    """Whatever a report from the store refuses, `store verify` rejects, in one text (D10)."""

    def test_the_five_codes_are_published(self) -> None:
        self.assertLessEqual(set(RESPONSE_CODES), set(AUDIT_FAULT_CODES))

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

    def test_a_head_alone_is_incomplete(self) -> None:
        record = recurrence_record()
        self.stage(
            response_gap_stream_id_of(record),
            events_of(record)[:1],
            requires_schema=RESPONSE_GAP_STREAM_SCHEMA_VERSION,
        )
        self.refused("responsegap_incomplete")

    def test_a_second_record_is_overfull(self) -> None:
        record = recurrence_record()
        head, observed = events_of(record)
        self.stage(
            response_gap_stream_id_of(record),
            [head, observed, observed],
            requires_schema=RESPONSE_GAP_STREAM_SCHEMA_VERSION,
        )
        self.refused("responsegap_overfull")

    def test_a_record_ahead_of_its_head_is_a_stream_mismatch(self) -> None:
        record = recurrence_record()
        head, observed = events_of(record)
        self.stage(
            response_gap_stream_id_of(record),
            [observed, head],
            requires_schema=RESPONSE_GAP_STREAM_SCHEMA_VERSION,
        )
        self.refused("responsegap_stream_mismatch")

    def test_a_record_of_another_stream_is_a_stream_mismatch(self) -> None:
        self.stage(
            response_gap_stream_id_of(lapse_record()),
            events_of(recurrence_record()),
            requires_schema=RESPONSE_GAP_STREAM_SCHEMA_VERSION,
        )
        self.refused("responsegap_stream_mismatch")

    def test_a_head_that_disagrees_with_its_record_is_an_identity_breach(self) -> None:
        record = lapse_record()
        head = dict(response_gap_head_payload(record), firstSeenAt="2026-09-02T08:00:00Z")
        self.stage(
            response_gap_stream_id_of(record),
            events_of(record, head),
            requires_schema=RESPONSE_GAP_STREAM_SCHEMA_VERSION,
        )
        self.refused("responsegap_identity_breach")

    def test_an_edited_record_is_an_identity_breach(self) -> None:
        edited = rebuilt(recurrence_record(), title="edited")
        self.stage(
            response_gap_stream_id_of(edited),
            events_of(edited),
            requires_schema=RESPONSE_GAP_STREAM_SCHEMA_VERSION,
        )
        self.refused("responsegap_identity_breach")

    def test_a_stream_in_a_store_below_schema_7_is_named_and_still_read(self) -> None:
        record = recurrence_record()
        self.stage(response_gap_stream_id_of(record), events_of(record), requires_schema=6)
        faults = audit_history(self.repository)
        self.assertEqual([fault.code for fault in faults], ["responsegap_schema_unmarked"])
        self.assertIn("is in a store at schema 6", faults[0].message)
        # Content-neutral, as every marker fault is: no reader refuses it.
        self.assertEqual(
            [item.observation_id for item in rehydrate_observations(self.repository)],
            [record.observation_id],
        )

    def test_a_missing_case_is_not_a_fault(self) -> None:
        # F5: the head is held to its own record; a gap recorded before correlation is legal.
        record_gap(self.repository, lapse_record())
        self.assertEqual(audit_history(self.repository), ())

    def test_a_foreign_event_on_a_response_gap_stream_is_refused(self) -> None:
        record = recurrence_record()
        self.stage(
            response_gap_stream_id_of(record),
            [*events_of(record), ("case.identified", {"providerTrackingId": "X"})],
            requires_schema=RESPONSE_GAP_STREAM_SCHEMA_VERSION,
        )
        codes = {fault.code for fault in audit_history(self.repository)}
        self.assertIn("event_stream_mismatch", codes)
        with self.assertRaises(HistoryError):
            rehydrate_observations(self.repository)


# *--- Store Verify ---*


class ResponseGapStoreVerifyCommandTests(PersistedStoreTestCase):
    """`store verify` names each response gap fault and exits 1; every reader refuses it by name.

    Each shape is planted past the repository in a store holding the recurrence fixtures. A
    refusal is `history_invalid` on every command that reads the store's observations, never an
    uncaught exception, and the text is the audit's (D10).
    """

    def setUp(self) -> None:
        super().setUp()
        before, after = RECURRENCE_ARTIFACTS
        self.succeeds(["ingest", before, after, "--db", str(self.database), "--as-of", INGESTED_AT])

    def smuggle(
        self, stream_id: str, events: list[tuple[str, dict[str, Any]]], *, schema: int = 7
    ) -> list[int]:
        """Append events to one new stream straight to the store, past the repository."""
        sequences = []
        with SQLiteEventStore(self.database) as store:
            for version, (event_type, payload) in enumerate(events):
                (appended,) = store.append(
                    stream_id,
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
                sequences.append(appended.sequence)
        return sequences

    def verify_faults(self) -> list[str]:
        code, out, err = run(["store", "verify", "--db", str(self.database)])
        self.assertEqual((code, out), (1, ""), msg=err)
        return err.splitlines()[:-1]

    def assert_refused_everywhere(self, message: str) -> None:
        for label, argv in (
            ("report vdt", ["report", "vdt", "--db", str(self.database), *REPORT_OPTIONS]),
            ("cases correlate", ["cases", "correlate", "--db", str(self.database)]),
        ):
            with self.subTest(label):
                code, out, err = run(argv)
                self.assertEqual((code, out), (1, ""), msg=err)
                self.assertIn("error: history_invalid: ", err)
                self.assertIn(message, err)
                self.assertNotIn("Traceback", err)

    def test_a_whole_stream_verifies(self) -> None:
        record = recurrence_record()
        self.smuggle(response_gap_stream_id_of(record), events_of(record))
        out, err = self.succeeds(["store", "verify", "--db", str(self.database)])
        self.assertTrue(out.startswith("ok: "), msg=err)

    def test_each_damaged_shape_is_named_by_verify_and_refused_by_every_reader(self) -> None:
        record = recurrence_record()
        head, observed = events_of(record)
        disagreeing = events_of(record, {**head[1], "observationId": "obs-other"})
        for label, stream_id, events, code in (
            ("head alone", response_gap_stream_id_of(record), [head], "responsegap_incomplete"),
            (
                "second record",
                response_gap_stream_id_of(record),
                [head, observed, observed],
                "responsegap_overfull",
            ),
            (
                "record first",
                response_gap_stream_id_of(record),
                [observed, head],
                "responsegap_stream_mismatch",
            ),
            (
                "head disagrees",
                response_gap_stream_id_of(record),
                disagreeing,
                "responsegap_identity_breach",
            ),
        ):
            with self.subTest(shape=label):
                self.setUp()
                self.smuggle(stream_id, events)
                lines = [line for line in self.verify_faults() if f": {code}: " in line]
                self.assertEqual(len(lines), 1, msg=self.verify_faults())
                self.assert_refused_everywhere(lines[0].split(f": {code}: ", 1)[1])

    def test_an_unmarked_store_is_named_and_still_reports(self) -> None:
        record = recurrence_record()
        self.smuggle(response_gap_stream_id_of(record), events_of(record), schema=1)
        (line,) = self.verify_faults()
        self.assertIn(": responsegap_schema_unmarked: ", line)
        code, _, err = run(["report", "vdt", "--db", str(self.database), *REPORT_OPTIONS])
        self.assertEqual(code, 0, msg=err)


if __name__ == "__main__":
    unittest.main()
