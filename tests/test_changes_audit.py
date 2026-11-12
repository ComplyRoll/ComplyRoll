# ******************************************************************************
# *Title: Change Audit Tests*
# *Author: Kyle Versluis*
# *Description: The change stream audits and what the reader refuses.*
# ******************************************************************************
"""Tests for the four `change_*` audit codes and what the reader refuses (ADR 0018)."""

# *--- Imports ---*

from __future__ import annotations

import json
import sqlite3
import tempfile
import unittest
from collections.abc import Mapping, Sequence
from contextlib import closing
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from test_change_streams import payload
from test_cli import EXAMPLE_INVENTORY, INGESTED_AT, run
from test_coverage_streams import metadata
from test_events import GOOD_PAYLOADS

from complyroll.events import (
    CHANGE_RECORDED,
    CHANGE_STREAM_SCHEMA_VERSION,
    EventRepository,
    change_identity_breach,
    change_stream_id,
)
from complyroll.history import (
    AUDIT_FAULT_CODES,
    HistoryError,
    audit_history,
    read_stored_changes,
    record_changes,
)
from complyroll.history.fold import _ORDER_CHECKED_BESIDE
from complyroll.reports import load_changes
from complyroll.store import NewEvent, SQLiteEventStore

# *--- Fixtures ---*

NOW = datetime(2026, 11, 9, 12, 0, tzinfo=UTC)
CHANGE_ID = "CHG-1001"
OTHER_ID = "CHG-1002"
EXAMPLE_CHANGES = Path(__file__).parent.parent / "examples" / "changes.json"
ARTIFACT_STREAM = f"artifact/{'a' * 64}"
#: An event whose contract holds, which no change stream carries.
FOREIGN = ("artifact.ingested", {**GOOD_PAYLOADS["artifact.ingested"], "observationCount": 0})


class ChangeAuditCase(unittest.TestCase):
    """A store written past the repository, so a shape no writer can leave is reachable."""

    def setUp(self) -> None:
        directory = tempfile.TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        self.workspace = Path(directory.name)
        self.database = self.workspace / "history.db"
        self.store = SQLiteEventStore(self.database)
        self.addCleanup(self.store.close)
        self.repository = EventRepository(self.store)

    def stage(
        self,
        stream_id: str,
        events: Sequence[tuple[str, Mapping[str, Any]]],
        *,
        requires_schema: int = CHANGE_STREAM_SCHEMA_VERSION,
    ) -> list[int]:
        """Append events to one new stream straight to the store, past the repository."""
        sequences = []
        for version, (event_type, event_payload) in enumerate(events):
            (appended,) = self.store.append(
                stream_id,
                [
                    NewEvent(
                        event_type=event_type,
                        occurred_at=NOW,
                        payload=dict(event_payload),
                        metadata=metadata().to_dict(),
                    )
                ],
                expected_version=version,
                requires_schema=requires_schema,
            )
            sequences.append(appended.sequence)
        return sequences

    def assert_faults(self, expected: list[tuple[int, str]], *messages: str) -> None:
        faults = audit_history(self.repository)
        self.assertEqual([(fault.sequence, fault.code) for fault in faults], expected)
        for message in messages:
            self.assertTrue(
                any(message in fault.message for fault in faults),
                msg=f"{message!r} not in {[fault.message for fault in faults]}",
            )

    def assert_verify_names(self, *expected: tuple[int, str]) -> None:
        """Run `store verify`, requiring exit 1 and a line naming each fault at its sequence."""
        code, out, err = run(["store", "verify", "--db", str(self.database)])

        self.assertEqual((code, out), (1, ""), msg=err)
        for sequence, fault_code in expected:
            self.assertIn(f"error: sequence {sequence}: {fault_code}:", err)
        self.assertIn(f"faults: {len(expected)} domain fault(s) in", err)

    def assert_reader_refuses(self, message: str) -> None:
        with self.assertRaises(HistoryError) as caught:
            read_stored_changes(self.repository)
        self.assertIn(message, str(caught.exception))


# *--- Audit Faults ---*


class ChangeStreamAuditTests(ChangeAuditCase):
    """One test per fault code: `store verify` names it, and the reader refuses what it names."""

    def good(self, change_id: str = CHANGE_ID) -> tuple[str, dict[str, Any]]:
        return (CHANGE_RECORDED, payload(changeId=change_id))

    def test_a_recorded_change_is_no_fault(self) -> None:
        record_changes(
            self.repository,
            load_changes(EXAMPLE_CHANGES),
            recorded_at=NOW,
            metadata=metadata(),
        )

        self.assertEqual(audit_history(self.repository), ())
        self.assertIsNotNone(read_stored_changes(self.repository))

    def test_change_overfull(self) -> None:
        sequences = self.stage(change_stream_id(CHANGE_ID), [self.good(), self.good()])

        self.assert_faults(
            [(sequences[0], "change_overfull")],
            "is overfull: a change stream holds one change.recorded, found 2",
        )
        self.assert_verify_names((sequences[0], "change_overfull"))
        self.assert_reader_refuses("is overfull: a change stream holds one change.recorded")

    def test_change_incomplete(self) -> None:
        (sequence,) = self.stage(change_stream_id(CHANGE_ID), [FOREIGN])

        self.assert_faults(
            [
                (sequence, "change_incomplete"),
                (sequence, "change_stream_mismatch"),
                (sequence, "event_stream_mismatch"),
            ],
            "is incomplete: a change stream holds one change.recorded, found 0",
        )
        self.assert_verify_names(
            (sequence, "change_incomplete"),
            (sequence, "change_stream_mismatch"),
            (sequence, "event_stream_mismatch"),
        )
        self.assert_reader_refuses("does not belong on stream")

    def test_change_stream_mismatch_when_the_id_is_not_the_changes_digest(self) -> None:
        stream_id = change_stream_id(OTHER_ID)
        (sequence,) = self.stage(stream_id, [self.good(CHANGE_ID)])

        breach = change_identity_breach(stream_id, CHANGE_RECORDED, payload(changeId=CHANGE_ID))
        assert breach is not None
        self.assert_faults([(sequence, "change_stream_mismatch")], breach)
        self.assert_verify_names((sequence, "change_stream_mismatch"))
        self.assert_reader_refuses(breach)

    def test_change_stream_mismatch_for_an_event_no_change_stream_carries(self) -> None:
        stream_id = change_stream_id(CHANGE_ID)
        first, foreign = self.stage(stream_id, [self.good(), FOREIGN])

        self.assert_faults(
            [(foreign, "change_stream_mismatch"), (foreign, "event_stream_mismatch")],
            f"event 'artifact.ingested' does not belong on stream {stream_id!r}",
        )
        self.assertLess(first, foreign)
        self.assert_verify_names(
            (foreign, "change_stream_mismatch"), (foreign, "event_stream_mismatch")
        )
        self.assert_reader_refuses("does not belong on stream")

    def test_change_stream_mismatch_for_a_change_event_on_no_change_stream(self) -> None:
        (sequence,) = self.stage(ARTIFACT_STREAM, [self.good()])

        self.assert_faults(
            [(sequence, "change_stream_mismatch"), (sequence, "event_stream_mismatch")],
            f"event 'change.recorded' does not belong on stream {ARTIFACT_STREAM!r}",
        )
        self.assert_verify_names(
            (sequence, "change_stream_mismatch"), (sequence, "event_stream_mismatch")
        )
        self.assert_reader_refuses("does not belong on stream")

    def test_a_payload_outside_its_contract_is_refused_and_named(self) -> None:
        (sequence,) = self.stage(change_stream_id(CHANGE_ID), [(CHANGE_RECORDED, {"changeId": 7})])

        self.assert_faults([(sequence, "payload_contract_invalid")])
        self.assert_reader_refuses("is not a readable change record")

    def test_a_breach_on_a_wrong_payload_is_not_read_off_it(self) -> None:
        # A payload its contract refuses is named by the contract check alone.
        (sequence,) = self.stage(
            change_stream_id(OTHER_ID), [(CHANGE_RECORDED, {"changeId": CHANGE_ID})]
        )

        self.assert_faults([(sequence, "payload_contract_invalid")])

    def test_change_schema_unmarked_below_5(self) -> None:
        for schema in (1, 2, 3, 4):
            with self.subTest(schema=schema):
                self.setUp()
                (sequence,) = self.stage(
                    change_stream_id(CHANGE_ID), [self.good()], requires_schema=schema
                )

                self.assertEqual(self.store.schema_version, schema)
                stream_id = change_stream_id(CHANGE_ID)
                self.assert_faults(
                    [(sequence, "change_schema_unmarked")],
                    f"change stream {stream_id!r} is in a store at schema {schema}",
                    "is marked schema 5",
                )

    def test_change_schema_unmarked_is_read_and_named_once_at_the_first_stream(self) -> None:
        (first,) = self.stage(change_stream_id(CHANGE_ID), [self.good()], requires_schema=4)
        self.stage(change_stream_id(OTHER_ID), [self.good(OTHER_ID)], requires_schema=4)

        self.assert_faults([(first, "change_schema_unmarked")], f"{change_stream_id(CHANGE_ID)!r}")
        self.assert_verify_names((first, "change_schema_unmarked"))
        self.assertIsNotNone(read_stored_changes(self.repository))

    def test_no_reader_refuses_an_unmarked_store_and_the_report_still_reads_it(self) -> None:
        self.stage(change_stream_id(CHANGE_ID), [self.good()], requires_schema=4)
        self.store.close()

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
            ]
        )

        self.assertEqual(code, 0, msg=err)
        self.assertIn("changes", json.loads(out)["x-complyroll"])

    def test_the_order_check_still_runs_beside_an_unmarked_store(self) -> None:
        self.assertIn("change_schema_unmarked", _ORDER_CHECKED_BESIDE)
        self.assertEqual(
            _ORDER_CHECKED_BESIDE,
            {
                "event_metadata_invalid",
                "failure_schema_unmarked",
                "coverage_schema_unmarked",
                "change_schema_unmarked",
            },
        )

    def test_the_four_codes_are_published_in_the_sorted_table(self) -> None:
        for code in (
            "change_incomplete",
            "change_overfull",
            "change_schema_unmarked",
            "change_stream_mismatch",
        ):
            self.assertIn(code, AUDIT_FAULT_CODES)
        self.assertEqual(AUDIT_FAULT_CODES, tuple(sorted(AUDIT_FAULT_CODES)))

    def test_a_damaged_stream_fails_every_report_as_history_invalid(self) -> None:
        self.stage(change_stream_id(CHANGE_ID), [self.good(), self.good()])
        self.store.close()

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
            ]
        )

        self.assertEqual((code, out), (1, ""))
        self.assertIn("error: history_invalid:", err)
        self.assertIn("is overfull: a change stream holds one change.recorded", err)

    def test_a_schema_5_mark_survives_a_hand_lowered_marker_only_as_a_fault(self) -> None:
        record_changes(
            self.repository,
            load_changes(EXAMPLE_CHANGES),
            recorded_at=NOW,
            metadata=metadata(),
        )
        self.store.close()
        with closing(sqlite3.connect(self.database)) as connection:
            connection.execute("DELETE FROM complyroll_schema_migrations WHERE version > 4")
            connection.execute("PRAGMA user_version = 4")
            connection.commit()

        code, _, err = run(["store", "verify", "--db", str(self.database)])

        self.assertEqual(code, 1)
        self.assertIn("change_schema_unmarked", err)


if __name__ == "__main__":
    unittest.main()
