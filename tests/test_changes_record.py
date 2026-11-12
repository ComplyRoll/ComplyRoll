# ******************************************************************************
# *Title: Changes Record Tests*
# *Author: Kyle Versluis*
# *Description: The change writer and the changes record command (ADR 0018).*
# ******************************************************************************
"""Tests for `record_changes` and `changes record`: idempotence, conflicts and refusals."""

# *--- Imports ---*

from __future__ import annotations

import json
import tempfile
import unittest
from datetime import UTC, datetime, timedelta, timezone
from itertools import combinations
from pathlib import Path
from typing import Any
from unittest.mock import patch

from test_changes_input import change, document, encoded, pair
from test_cli import run
from test_coverage_streams import metadata

from complyroll.events import (
    CHANGE_RECORDED,
    EventMetadata,
    EventRepository,
    change_stream_id,
)
from complyroll.history import (
    ChangeConflictError,
    ChangeRecordOutcome,
    HistoryError,
    record_changes,
)
from complyroll.reports.changes_input import ChangeSet, parse_changes
from complyroll.store import NewEvent, SQLiteEventStore

# *--- Fixtures ---*

REPO_ROOT = Path(__file__).parent.parent
EXAMPLE_CHANGES = REPO_ROOT / "examples" / "changes.json"
NOW = datetime(2026, 11, 9, 12, 0, 0, tzinfo=UTC)
LATER = datetime(2026, 12, 25, 6, 30, 0, tzinfo=UTC)
#: The contract fields a re-run compares, in the order `change_conflict` reads them.
COMPARED_FIELDS = (
    "kind",
    "occurredAt",
    "source",
    "resources",
    "significant",
    "rationale",
    "detectBy",
    "job",
)
#: A change every field of which the differing edits below can move.
FULL = change(
    "CHG-1",
    kind="modified",
    occurredAt="2026-09-01T00:00:00Z",
    source={"tool": "git", "reference": "commit 0123abc"},
    resources=[pair("lab-01"), pair("lab-02")],
    significant=True,
    rationale="Kernel upgrade across the web tier.",
    detectBy="2026-09-08T00:00:00Z",
    job="weekly-scan",
)
#: One edit per compared field, each changing that field alone.
FIELD_EDITS: dict[str, dict[str, Any]] = {
    "kind": {"kind": "created"},
    "occurredAt": {"occurredAt": "2026-09-02T00:00:00Z"},
    "source": {"source": {"tool": "git", "reference": "commit 9999999"}},
    "resources": {"resources": [pair("lab-01")]},
    "significant": {"significant": False},
    "rationale": {"rationale": "A different reason."},
    "detectBy": {"detectBy": "2026-09-09T00:00:00Z"},
    "job": {"job": "another-scan"},
}


def change_set(*changes: dict[str, Any], name: str = "changes-2026-09") -> ChangeSet:
    """Return the change set a file holding these changes parses to."""
    return parse_changes(encoded({**document(*changes), "name": name}))


def edited(**fields: Any) -> dict[str, Any]:
    """Return the full change with fields replaced, a `None` value removing one."""
    value = {**FULL, **fields}
    return {key: item for key, item in value.items() if item is not None}


class RecordCase(unittest.TestCase):
    """A temporary store in memory, a repository over it, and the writer."""

    def setUp(self) -> None:
        self.store = SQLiteEventStore(":memory:")
        self.addCleanup(self.store.close)
        self.repository = EventRepository(self.store)

    def record(
        self, *changes: dict[str, Any], recorded_at: datetime = NOW, name: str = "changes-2026-09"
    ) -> ChangeRecordOutcome:
        return record_changes(
            self.repository,
            change_set(*changes, name=name),
            recorded_at=recorded_at,
            metadata=metadata(),
        )

    def stored(self, change_id: str) -> dict[str, Any]:
        (record,) = self.repository.read_stream(change_stream_id(change_id))
        self.assertEqual(record.event_type, CHANGE_RECORDED)
        return dict(record.payload)

    def assert_conflict(self, changes: dict[str, Any], field: str) -> None:
        before = self.store.latest_sequence
        with self.assertRaises(ChangeConflictError) as caught:
            self.record(changes)
        self.assertEqual(caught.exception.field_name, field)
        self.assertEqual(caught.exception.change_id, "CHG-1")
        self.assertIn(field, str(caught.exception))
        self.assertIn("CHG-1", str(caught.exception))
        self.assertEqual(self.store.latest_sequence, before)


# *--- Writer ---*


class RecordChangesTests(RecordCase):
    """Each change the store lacks is appended, once, atomically."""

    def test_records_one_stream_per_change(self) -> None:
        outcome = self.record(change("CHG-1"), change("CHG-2"))

        self.assertEqual(
            outcome, ChangeRecordOutcome(recorded=("CHG-1", "CHG-2"), already_recorded=())
        )
        for change_id in ("CHG-1", "CHG-2"):
            with self.subTest(change_id=change_id):
                events = self.repository.read_stream(change_stream_id(change_id))
                self.assertEqual([event.event_type for event in events], [CHANGE_RECORDED])
                self.assertEqual(events[0].payload["changeId"], change_id)
                self.assertEqual(events[0].occurred_at, NOW)

    def test_the_stored_payload_is_the_file_as_read(self) -> None:
        changes = change(
            "CHG-1",
            occurredAt="2026-09-01T02:30:00+02:00",
            resources=[pair("b-host"), pair("a-host"), pair("z", "firewall")],
            rationale="clean\u200btext",
            detectBy="2026-09-08T00:00:00Z",
            job="weekly-scan",
        )

        self.record(
            changes, recorded_at=datetime(2026, 11, 9, 7, 0, tzinfo=timezone(timedelta(hours=-5)))
        )

        self.assertEqual(
            self.stored("CHG-1"),
            {
                "changeId": "CHG-1",
                "kind": "modified",
                "occurredAt": "2026-09-01T00:30:00Z",
                "source": {"tool": "git", "reference": "commit 0123abc"},
                "resources": [
                    {"resourceType": "firewall", "resourceId": "z"},
                    {"resourceType": "host", "resourceId": "a-host"},
                    {"resourceType": "host", "resourceId": "b-host"},
                ],
                "significant": True,
                "rationale": "cleantext",
                "detectBy": "2026-09-08T00:00:00Z",
                "job": "weekly-scan",
                "changesName": "changes-2026-09",
                "changesSha256": change_set(changes).sha256,
                "recordedAt": "2026-11-09T12:00:00Z",
            },
        )

    def test_an_absent_detect_by_and_job_are_stored_null(self) -> None:
        self.record(change("CHG-1"))

        payload = self.stored("CHG-1")
        self.assertIsNone(payload["detectBy"])
        self.assertIsNone(payload["job"])

    def test_rerun_is_already_recorded(self) -> None:
        first = self.record(change("CHG-1"), change("CHG-2"))
        sequence = self.store.latest_sequence

        second = self.record(change("CHG-1"), change("CHG-2"))

        self.assertEqual(first.recorded, ("CHG-1", "CHG-2"))
        self.assertEqual(
            second, ChangeRecordOutcome(recorded=(), already_recorded=("CHG-1", "CHG-2"))
        )
        self.assertEqual(self.store.latest_sequence, sequence)

    def test_grown_file_records_only_the_new_change(self) -> None:
        self.record(change("CHG-1"))
        sequence = self.store.latest_sequence

        grown = self.record(change("CHG-1"), change("CHG-2"))

        self.assertEqual(
            grown, ChangeRecordOutcome(recorded=("CHG-2",), already_recorded=("CHG-1",))
        )
        self.assertEqual(self.store.latest_sequence, sequence + 1)
        self.assertEqual(self.stored("CHG-1")["recordedAt"], "2026-11-09T12:00:00Z")

    def test_recorded_at_and_digest_and_name_do_not_move_idempotence(self) -> None:
        self.record(change("CHG-1"), recorded_at=NOW, name="first-name")
        original = self.stored("CHG-1")
        sequence = self.store.latest_sequence

        # A later run of a renamed file with other bytes names the same change: the first
        # recorded payload stands, with the name, digest and time it was first recorded under.
        again = self.record(change("CHG-1"), recorded_at=LATER, name="renamed-file")

        self.assertEqual(again.already_recorded, ("CHG-1",))
        self.assertEqual(again.recorded, ())
        self.assertEqual(self.store.latest_sequence, sequence)
        self.assertEqual(self.stored("CHG-1"), original)
        self.assertEqual(original["changesName"], "first-name")
        self.assertNotEqual(original["recordedAt"], "2026-12-25T06:30:00Z")

    def test_offset_spelling_of_an_instant_is_already_recorded(self) -> None:
        self.record(
            change("CHG-1", occurredAt="2026-09-01T00:00:00Z", detectBy="2026-09-08T00:00:00Z")
        )

        again = self.record(
            change(
                "CHG-1",
                occurredAt="2026-09-01T02:00:00+02:00",
                detectBy="2026-09-08T01:00:00+01:00",
            )
        )

        self.assertEqual(again, ChangeRecordOutcome(recorded=(), already_recorded=("CHG-1",)))

    def test_resources_in_another_order_are_already_recorded(self) -> None:
        self.record(change("CHG-1", resources=[pair("a"), pair("b")]))

        again = self.record(change("CHG-1", resources=[pair("b"), pair("a")]))

        self.assertEqual(again.already_recorded, ("CHG-1",))

    def test_conflict_names_the_first_differing_field(self) -> None:
        for field, edit in FIELD_EDITS.items():
            with self.subTest(field=field):
                self.setUp()
                self.record(FULL)
                self.assert_conflict(edited(**edit), field)

    def test_a_field_absent_on_either_side_is_a_conflict_on_that_field(self) -> None:
        for field in ("detectBy", "job"):
            with self.subTest(field=field, side="absent in the file"):
                self.setUp()
                self.record(FULL)
                self.assert_conflict(edited(**{field: None}), field)
            with self.subTest(field=field, side="absent in the store"):
                self.setUp()
                self.record(edited(**{field: None}))
                self.assert_conflict(FULL, field)

    def test_the_first_field_in_the_contract_order_is_named(self) -> None:
        for earlier, later in combinations(COMPARED_FIELDS, 2):
            with self.subTest(earlier=earlier, later=later):
                self.setUp()
                self.record(FULL)
                self.assert_conflict(edited(**FIELD_EDITS[earlier], **FIELD_EDITS[later]), earlier)

    def test_a_conflict_writes_nothing(self) -> None:
        # The first change of the file is new and sorts first; the second conflicts.
        self.record(FULL)
        sequence = self.store.latest_sequence
        new_first = change("CHG-0", occurredAt="2026-08-01T00:00:00Z")

        with self.assertRaises(ChangeConflictError):
            self.record(new_first, edited(rationale="A different reason."))

        self.assertEqual(self.store.latest_sequence, sequence)
        self.assertEqual(self.repository.read_stream(change_stream_id("CHG-0")), ())

    def test_a_stream_holding_something_else_is_refused_rather_than_compared(self) -> None:
        stream_id = change_stream_id("CHG-1")
        stored_payload = {
            "changeId": "CHG-9",
            "kind": "modified",
            "occurredAt": "2026-09-01T00:00:00Z",
            "source": {"tool": "git", "reference": "commit 0123abc"},
            "resources": [{"resourceType": "host", "resourceId": "lab-01"}],
            "significant": True,
            "rationale": "Kernel upgrade across the web tier.",
            "detectBy": None,
            "job": None,
            "changesName": "changes-2026-09",
            "changesSha256": "a" * 64,
            "recordedAt": "2026-11-09T12:00:00Z",
        }
        self.store.append(
            stream_id,
            [NewEvent(CHANGE_RECORDED, NOW, stored_payload, metadata=metadata().to_dict())],
            expected_version=0,
            requires_schema=5,
        )

        with self.assertRaises(HistoryError) as caught:
            self.record(change("CHG-1"))

        self.assertNotIsInstance(caught.exception, ChangeConflictError)
        self.assertIn("refused rather than resumed", str(caught.exception))
        self.assertIn(f"on stream {stream_id!r}", str(caught.exception))

    def test_a_stream_of_two_events_is_refused_rather_than_compared(self) -> None:
        stream_id = change_stream_id("CHG-1")
        payload = {**self._good_payload(), "changeId": "CHG-1"}
        for version in (0, 1):
            self.store.append(
                stream_id,
                [NewEvent(CHANGE_RECORDED, NOW, dict(payload), metadata=metadata().to_dict())],
                expected_version=version,
                requires_schema=5,
            )

        with self.assertRaises(HistoryError) as caught:
            self.record(change("CHG-1"))

        self.assertIn("refused rather than resumed", str(caught.exception))
        self.assertIn(stream_id, str(caught.exception))

    def test_a_stored_payload_outside_its_contract_is_refused(self) -> None:
        stream_id = change_stream_id("CHG-1")
        broken = {**self._good_payload(), "changeId": "CHG-1", "kind": "retired"}
        self.store.append(
            stream_id,
            [NewEvent(CHANGE_RECORDED, NOW, broken, metadata=metadata().to_dict())],
            expected_version=0,
            requires_schema=5,
        )

        with self.assertRaises(HistoryError) as caught:
            self.record(change("CHG-1"))

        self.assertIn("is not a readable change record", str(caught.exception))

    @staticmethod
    def _good_payload() -> dict[str, Any]:
        return {
            "changeId": "CHG-1",
            "kind": "modified",
            "occurredAt": "2026-09-01T00:00:00Z",
            "source": {"tool": "git", "reference": "commit 0123abc"},
            "resources": [{"resourceType": "host", "resourceId": "lab-01"}],
            "significant": True,
            "rationale": "Kernel upgrade across the web tier.",
            "detectBy": None,
            "job": None,
            "changesName": "changes-2026-09",
            "changesSha256": "a" * 64,
            "recordedAt": "2026-11-09T12:00:00Z",
        }

    def test_the_run_joins_a_callers_transaction(self) -> None:
        with self.assertRaises(RuntimeError):
            with self.repository.transaction():
                self.record(change("CHG-1"))
                self.assertEqual(self.store.schema_version, 5)
                raise RuntimeError("abandon the run")

        self.assertEqual(self.store.schema_version, 1)
        self.assertEqual(self.store.latest_sequence, 0)

    def test_arguments_are_checked(self) -> None:
        with self.assertRaises(TypeError):
            record_changes(
                self.repository,
                "not a change set",  # type: ignore[arg-type]
                recorded_at=NOW,
                metadata=metadata(),
            )
        naive = datetime(2026, 11, 9, 12, 0)
        with self.assertRaises(ValueError):
            record_changes(
                self.repository,
                change_set(change("CHG-1")),
                recorded_at=naive,
                metadata=metadata(),
            )

    def test_a_recorded_change_is_written_by_the_actor_of_the_run(self) -> None:
        record_changes(
            self.repository,
            change_set(change("CHG-1")),
            recorded_at=NOW,
            metadata=EventMetadata(actor="someone"),
        )

        (record,) = self.repository.read_stream(change_stream_id("CHG-1"))
        self.assertEqual(record.metadata["actor"], "someone")


# *--- Command ---*


class ChangesRecordCommandTests(unittest.TestCase):
    """`changes record` as an operator runs it."""

    def setUp(self) -> None:
        directory = tempfile.TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        self.workspace = Path(directory.name)
        self.database = self.workspace / "history.db"
        SQLiteEventStore(self.database).close()
        self.changes = self.workspace / "changes.json"
        self.write_changes(change("CHG-1"), change("CHG-2", occurredAt="2026-09-02T00:00:00Z"))

    def write_changes(self, *changes: dict[str, Any]) -> None:
        self.changes.write_bytes(encoded(document(*changes)))

    def argv(self, *extra: str, changes: Path | None = None) -> list[str]:
        return [
            "changes",
            "record",
            "--db",
            str(self.database),
            "--changes",
            str(self.changes if changes is None else changes),
            *extra,
        ]

    def stored(self, change_id: str) -> dict[str, Any]:
        with SQLiteEventStore(self.database) as store:
            (record,) = EventRepository(store).read_stream(change_stream_id(change_id))
            return dict(record.payload)

    def test_it_records_then_says_already_recorded(self) -> None:
        code, out, err = run(self.argv("--as-of", "2026-11-09T12:00:00Z"))

        self.assertEqual((code, err), (0, ""))
        self.assertEqual(
            out,
            "CHG-1: recorded\n"
            "CHG-2: recorded\n"
            "recorded 2 change(s), skipped 0 already-recorded change(s)\n",
        )
        with SQLiteEventStore(self.database) as store:
            self.assertEqual(store.schema_version, 5)

        code, out, err = run(self.argv("--as-of", "2026-12-01T00:00:00Z"))

        self.assertEqual((code, err), (0, ""))
        self.assertEqual(
            out,
            "CHG-1: already_recorded\n"
            "CHG-2: already_recorded\n"
            "recorded 0 change(s), skipped 2 already-recorded change(s)\n",
        )

    def test_as_of_is_recorded_in_utc(self) -> None:
        self.assertEqual(run(self.argv("--as-of", "2026-11-09T14:00:00+02:00"))[0], 0)

        self.assertEqual(self.stored("CHG-1")["recordedAt"], "2026-11-09T12:00:00Z")

    def test_as_of_defaults_to_the_current_second(self) -> None:
        instant = datetime(2026, 11, 9, 7, 8, 9, tzinfo=UTC)
        with patch("complyroll.cli._now", return_value=instant):
            code, _, err = run(self.argv())

        self.assertEqual((code, err), (0, ""))
        self.assertEqual(self.stored("CHG-1")["recordedAt"], "2026-11-09T07:08:09Z")

    def test_a_bad_as_of_is_invalid_input(self) -> None:
        code, out, err = run(self.argv("--as-of", "yesterday"))

        self.assertEqual((code, out), (1, ""))
        self.assertIn("error: invalid_input:", err)

    def test_actor_reaches_the_event_metadata(self) -> None:
        self.assertEqual(run(self.argv("--actor", "alice"))[0], 0)

        with SQLiteEventStore(self.database) as store:
            (record,) = EventRepository(store).read_stream(change_stream_id("CHG-1"))
            self.assertEqual(record.metadata["actor"], "alice")

    def test_a_blank_actor_is_invalid_option(self) -> None:
        code, out, err = run(self.argv("--actor", ""))

        self.assertEqual((code, out), (1, ""))
        self.assertIn("error: invalid_option:", err)
        with SQLiteEventStore(self.database) as store:
            self.assertEqual(store.latest_sequence, 0)

    def test_missing_store_is_refused(self) -> None:
        missing = self.workspace / "no-such.db"

        code, out, err = run(
            ["changes", "record", "--db", str(missing), "--changes", str(self.changes)]
        )

        self.assertEqual((code, out), (1, ""))
        self.assertIn("error: store_missing:", err)
        self.assertFalse(missing.exists())

    def test_second_changes_file_is_invalid_option(self) -> None:
        code, out, err = run([*self.argv(), "--changes", str(self.changes)])

        self.assertEqual((code, out), (1, ""))
        self.assertIn("error: invalid_option: changes record takes one --changes file, not 2", err)
        with SQLiteEventStore(self.database) as store:
            self.assertEqual(store.latest_sequence, 0)

    def test_no_changes_file_is_invalid_option(self) -> None:
        code, out, err = run(["changes", "record", "--db", str(self.database)])

        self.assertEqual((code, out), (1, ""))
        self.assertIn("error: invalid_option: changes record needs --changes", err)

    def test_an_unreadable_change_file_is_invalid_input(self) -> None:
        self.changes.write_text("not json", encoding="utf-8")

        code, out, err = run(self.argv())

        self.assertEqual((code, out), (1, ""))
        self.assertIn("error: invalid_input:", err)
        with SQLiteEventStore(self.database) as store:
            self.assertEqual(store.latest_sequence, 0)

    def test_a_conflict_exits_one_and_writes_nothing(self) -> None:
        self.assertEqual(run(self.argv())[0], 0)
        with SQLiteEventStore(self.database) as store:
            sequence = store.latest_sequence
        self.write_changes(
            change("CHG-0", occurredAt="2026-08-01T00:00:00Z"),
            change("CHG-1", rationale="A different reason."),
        )

        code, out, err = run(self.argv())

        self.assertEqual((code, out), (1, ""))
        self.assertIn("error: change_conflict: ", err)
        self.assertIn("rationale", err)
        with SQLiteEventStore(self.database) as store:
            self.assertEqual(store.latest_sequence, sequence)

    def test_a_damaged_stream_is_history_invalid(self) -> None:
        stream_id = change_stream_id("CHG-1")
        with SQLiteEventStore(self.database) as store:
            store.append(
                stream_id,
                [
                    NewEvent(
                        CHANGE_RECORDED,
                        NOW,
                        {"changeId": "CHG-9"},
                        metadata=metadata().to_dict(),
                    )
                ],
                expected_version=0,
                requires_schema=5,
            )

        code, out, err = run(self.argv())

        self.assertEqual((code, out), (1, ""))
        self.assertIn("error: history_invalid: ", err)

    def test_the_example_change_file_records_and_reruns_cleanly(self) -> None:
        code, out, err = run(self.argv(changes=EXAMPLE_CHANGES))
        self.assertEqual((code, err), (0, ""))
        document_text = json.loads(EXAMPLE_CHANGES.read_text(encoding="utf-8"))
        count = len(document_text["changes"])
        self.assertIn(f"recorded {count} change(s)", out)

        code, out, err = run(self.argv(changes=EXAMPLE_CHANGES))

        self.assertEqual((code, err), (0, ""))
        self.assertIn(f"skipped {count} already-recorded change(s)", out)
        with SQLiteEventStore(self.database) as store:
            self.assertTrue(store.verify_history().ok)


if __name__ == "__main__":
    unittest.main()
