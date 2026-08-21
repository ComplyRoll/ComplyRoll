from __future__ import annotations

import hashlib
import json
import sqlite3
import tempfile
import time
import unittest
from contextlib import closing
from datetime import UTC, datetime, timedelta, timezone
from pathlib import Path

from complyroll.store import (
    MAX_EVENT_JSON_BYTES,
    EventConcurrencyError,
    EventConflictError,
    EventIntegrityError,
    EventStoreBusyError,
    EventStoreError,
    NewEvent,
    ProjectionConcurrencyError,
    SQLiteEventStore,
    UnsupportedSchemaError,
)
from complyroll.store.sqlite import (
    _SCHEMA_V1,
    APPLICATION_ID,
    SCHEMA_VERSION,
    _write_transaction,
)

OCCURRED_AT = datetime(2026, 8, 20, 9, 30, tzinfo=timezone(timedelta(hours=-7)))
RECORDED_AT = datetime(2026, 8, 20, 16, 31, tzinfo=UTC)

TRIGGER_STATEMENTS = tuple(
    statement for statement in _SCHEMA_V1 if "CREATE TRIGGER" in statement.upper()
)


def sample_event(
    event_id: str = "evt-001",
    *,
    event_type: str = "case.created",
    payload: dict[str, object] | None = None,
) -> NewEvent:
    return NewEvent(
        event_id=event_id,
        event_type=event_type,
        occurred_at=OCCURRED_AT,
        payload=payload or {"case_id": "case-001", "title": "Synthetic weakness"},
        metadata={"actor": "test-user", "method": "unit-test"},
    )


def raw_connection(path: Path) -> sqlite3.Connection:
    """Open an autocommit connection that bypasses the store, as an attacker would."""

    return sqlite3.connect(path, isolation_level=None)


class FakeConnection:
    """Connection double that records statements and can fail COMMIT or ROLLBACK."""

    def __init__(
        self,
        *,
        commit_error: Exception | None = None,
        rollback_error: Exception | None = None,
        in_transaction: bool = False,
    ) -> None:
        self.statements: list[str] = []
        self.in_transaction = in_transaction
        self._commit_error = commit_error
        self._rollback_error = rollback_error

    def execute(self, statement: str) -> None:
        self.statements.append(statement)
        if statement == "BEGIN IMMEDIATE":
            self.in_transaction = True
        elif statement == "COMMIT":
            if self._commit_error is not None:
                raise self._commit_error
            self.in_transaction = False
        elif statement == "ROLLBACK":
            if self._rollback_error is not None:
                raise self._rollback_error
            self.in_transaction = False


class WriteTransactionTests(unittest.TestCase):
    """Direct tests for the transaction guard, without needing a contended database."""

    def test_failed_commit_rolls_back_and_raises_busy_error(self) -> None:
        connection = FakeConnection(commit_error=sqlite3.OperationalError("database is locked"))

        with self.assertRaises(EventStoreBusyError) as caught:
            with _write_transaction(connection):  # type: ignore[arg-type]
                pass

        self.assertEqual(connection.statements, ["BEGIN IMMEDIATE", "COMMIT", "ROLLBACK"])
        self.assertFalse(connection.in_transaction)
        self.assertIn("could not commit", str(caught.exception))
        self.assertIsInstance(caught.exception.__cause__, sqlite3.OperationalError)

    def test_failed_commit_without_lock_wording_raises_generic_store_error(self) -> None:
        connection = FakeConnection(commit_error=sqlite3.OperationalError("disk I/O error"))

        with self.assertRaises(EventStoreError) as caught:
            with _write_transaction(connection):  # type: ignore[arg-type]
                pass

        self.assertNotIsInstance(caught.exception, EventStoreBusyError)
        self.assertIn("ROLLBACK", connection.statements)
        self.assertFalse(connection.in_transaction)

    def test_secondary_rollback_failure_is_reported_not_masked(self) -> None:
        connection = FakeConnection(
            commit_error=sqlite3.OperationalError("database is locked"),
            rollback_error=sqlite3.OperationalError("cannot roll back"),
        )

        with self.assertRaises(EventStoreBusyError) as caught:
            with _write_transaction(connection):  # type: ignore[arg-type]
                pass

        message = str(caught.exception)
        self.assertIn("database is locked", message)
        self.assertIn("rollback also failed", message)

    def test_body_failure_still_rolls_back_and_propagates_the_original_error(self) -> None:
        connection = FakeConnection()

        with self.assertRaisesRegex(ValueError, "domain rule"):
            with _write_transaction(connection):  # type: ignore[arg-type]
                raise ValueError("domain rule violated")

        self.assertEqual(connection.statements, ["BEGIN IMMEDIATE", "ROLLBACK"])
        self.assertFalse(connection.in_transaction)

    def test_connection_already_in_a_transaction_is_refused(self) -> None:
        connection = FakeConnection(in_transaction=True)

        with self.assertRaisesRegex(EventStoreError, "already inside a transaction"):
            with _write_transaction(connection):  # type: ignore[arg-type]
                pass

        self.assertEqual(connection.statements, [])


class SQLiteEventStoreTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary_directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary_directory.cleanup)
        self.database_path = Path(self.temporary_directory.name) / "complyroll.db"

    def open_store(self) -> SQLiteEventStore:
        store = SQLiteEventStore(self.database_path, clock=lambda: RECORDED_AT)
        self.addCleanup(store.close)
        return store

    def test_initialization_marks_and_migrates_database(self) -> None:
        store = self.open_store()

        self.assertEqual(store.schema_version, 1)
        self.assertEqual(store.latest_sequence, 0)

        with closing(raw_connection(self.database_path)) as connection:
            application_id = int(connection.execute("PRAGMA application_id").fetchone()[0])
            migration = connection.execute(
                "SELECT version, description FROM complyroll_schema_migrations"
            ).fetchone()

        self.assertEqual(application_id, APPLICATION_ID)
        self.assertEqual(migration[0], 1)
        self.assertIn("event history", migration[1])

    def test_append_canonicalizes_payload_and_preserves_event_envelope(self) -> None:
        store = self.open_store()
        payload: dict[str, object] = {
            "title": "Synthetic weakness",
            "case_id": "case-001",
            "labels": ["test", "phase-1"],
        }
        event = sample_event(payload=payload)

        appended = store.append("case/case-001", [event], expected_version=0)
        payload["title"] = "caller mutation after append"
        loaded = store.read_stream("case/case-001")[0]

        canonical = json.dumps(
            {
                "case_id": "case-001",
                "labels": ["test", "phase-1"],
                "title": "Synthetic weakness",
            },
            ensure_ascii=False,
            separators=(",", ":"),
            sort_keys=True,
        )
        self.assertEqual(appended, (loaded,))
        self.assertEqual(loaded.sequence, 1)
        self.assertEqual(loaded.stream_version, 1)
        self.assertEqual(loaded.event_version, 1)
        self.assertEqual(loaded.occurred_at, OCCURRED_AT.astimezone(UTC))
        self.assertEqual(loaded.recorded_at, RECORDED_AT)
        self.assertEqual(loaded.payload["title"], "Synthetic weakness")
        self.assertEqual(loaded.metadata["actor"], "test-user")
        self.assertEqual(
            loaded.payload_sha256,
            hashlib.sha256(canonical.encode("utf-8")).hexdigest(),
        )

    def test_batch_append_assigns_ordered_global_and_stream_versions(self) -> None:
        store = self.open_store()

        records = store.append(
            "case/case-001",
            [
                sample_event("evt-001"),
                sample_event("evt-002", event_type="case.observation_linked"),
            ],
            expected_version=0,
        )
        other = store.append(
            "case/case-002",
            [sample_event("evt-003")],
            expected_version=0,
        )

        self.assertEqual([record.sequence for record in (*records, *other)], [1, 2, 3])
        self.assertEqual([record.stream_version for record in records], [1, 2])
        self.assertEqual(other[0].stream_version, 1)
        self.assertEqual(store.current_stream_version("case/case-001"), 2)
        self.assertEqual(store.latest_sequence, 3)
        self.assertEqual(
            [record.event_id for record in store.read_all(after_sequence=1)],
            ["evt-002", "evt-003"],
        )

    def test_stale_expected_version_rejects_entire_append(self) -> None:
        store = self.open_store()
        store.append("case/case-001", [sample_event("evt-001")], expected_version=0)

        with self.assertRaisesRegex(EventConcurrencyError, "current version is 1"):
            store.append("case/case-001", [sample_event("evt-002")], expected_version=0)

        self.assertEqual(store.current_stream_version("case/case-001"), 1)
        self.assertEqual(store.latest_sequence, 1)

    def test_separate_writer_rejects_stale_stream_version(self) -> None:
        first = self.open_store()
        second = self.open_store()
        first.append("case/case-001", [sample_event("evt-001")], expected_version=0)

        with self.assertRaisesRegex(EventConcurrencyError, "current version is 1"):
            second.append("case/case-001", [sample_event("evt-002")], expected_version=0)

        committed = second.append(
            "case/case-001",
            [sample_event("evt-002")],
            expected_version=1,
        )
        self.assertEqual(committed[0].stream_version, 2)

    def test_duplicate_event_identifier_rolls_back_batch(self) -> None:
        store = self.open_store()
        store.append("case/case-001", [sample_event("evt-existing")], expected_version=0)

        with self.assertRaisesRegex(EventConflictError, "conflicts with committed history"):
            store.append(
                "case/case-002",
                [sample_event("evt-new"), sample_event("evt-existing")],
                expected_version=0,
            )

        self.assertEqual(store.current_stream_version("case/case-002"), 0)
        self.assertEqual(store.latest_sequence, 1)

    def test_rolled_back_batch_does_not_burn_a_global_sequence(self) -> None:
        store = self.open_store()
        store.append("case/case-001", [sample_event("evt-existing")], expected_version=0)

        with self.assertRaises(EventConflictError):
            store.append(
                "case/case-002",
                [sample_event("evt-new"), sample_event("evt-existing")],
                expected_version=0,
            )
        recovered = store.append("case/case-002", [sample_event("evt-later")], expected_version=0)

        self.assertEqual(recovered[0].sequence, 2)
        self.assertEqual([record.sequence for record in store.read_all()], [1, 2])

    def test_database_triggers_reject_event_update_and_delete(self) -> None:
        store = self.open_store()
        store.append("case/case-001", [sample_event()], expected_version=0)

        with closing(raw_connection(self.database_path)) as connection:
            with self.assertRaisesRegex(sqlite3.IntegrityError, "append-only"):
                connection.execute(
                    "UPDATE events SET event_type = 'case.closed' WHERE event_id = 'evt-001'"
                )
            with self.assertRaisesRegex(sqlite3.IntegrityError, "append-only"):
                connection.execute("DELETE FROM events WHERE event_id = 'evt-001'")

        self.assertEqual(store.read_all()[0].event_type, "case.created")

    def test_payload_digest_detects_out_of_band_corruption(self) -> None:
        store = self.open_store()
        store.append("case/case-001", [sample_event()], expected_version=0)

        with closing(raw_connection(self.database_path)) as connection:
            connection.execute("DROP TRIGGER events_reject_update")
            connection.execute(
                "UPDATE events SET payload_json = '{\"case_id\":\"altered\"}' WHERE event_id = ?",
                ("evt-001",),
            )
            for statement in TRIGGER_STATEMENTS:
                if "events_reject_update" in statement:
                    connection.execute(statement)

        with self.assertRaises(EventIntegrityError) as caught:
            store.read_all()
        self.assertIn("recorded digest", str(caught.exception))
        self.assertEqual(caught.exception.sequence, 1)

        reopened = SQLiteEventStore(self.database_path, clock=lambda: RECORDED_AT)
        self.addCleanup(reopened.close)
        with self.assertRaisesRegex(EventIntegrityError, "recorded digest"):
            reopened.read_all()

    def test_projection_checkpoint_uses_compare_and_swap_and_can_reset(self) -> None:
        store = self.open_store()
        store.append(
            "case/case-001",
            [sample_event("evt-001"), sample_event("evt-002")],
            expected_version=0,
        )

        empty = store.get_projection_checkpoint("case-list")
        advanced = store.advance_projection(
            "case-list",
            expected_sequence=0,
            last_sequence=2,
        )

        self.assertEqual(empty.last_sequence, 0)
        self.assertIsNone(empty.updated_at)
        self.assertEqual(advanced.last_sequence, 2)
        self.assertEqual(advanced.updated_at, RECORDED_AT)
        with self.assertRaisesRegex(ProjectionConcurrencyError, "checkpoint is 2"):
            store.advance_projection(
                "case-list",
                expected_sequence=0,
                last_sequence=2,
            )
        with self.assertRaisesRegex(ValueError, "exceeds latest event sequence"):
            store.advance_projection(
                "another-projection",
                expected_sequence=0,
                last_sequence=3,
            )

        reset = store.reset_projection("case-list", expected_sequence=2)
        self.assertEqual(reset.last_sequence, 0)
        self.assertEqual(store.get_projection_checkpoint("case-list"), reset)

    def test_invalid_json_and_unbounded_payloads_are_rejected_before_write(self) -> None:
        store = self.open_store()
        invalid_payloads: tuple[dict[object, object], ...] = (
            {1: "non-string key"},
            {"value": float("nan")},
            {"value": ("tuple", "is not JSON")},
            {"value": "x" * MAX_EVENT_JSON_BYTES},
        )

        for index, payload in enumerate(invalid_payloads):
            with self.subTest(index=index):
                with self.assertRaises((TypeError, ValueError)):
                    store.append(
                        "case/case-001",
                        [sample_event(f"evt-{index}", payload=payload)],  # type: ignore[arg-type]
                        expected_version=0,
                    )

        self.assertEqual(store.latest_sequence, 0)

    def test_naive_timestamps_and_invalid_names_are_rejected(self) -> None:
        with self.assertRaisesRegex(ValueError, "occurred_at must include a timezone"):
            NewEvent(
                event_id="evt-001",
                event_type="case.created",
                occurred_at=datetime(2026, 8, 20, 9, 30),
                payload={},
            )

        store = self.open_store()
        with self.assertRaisesRegex(ValueError, "stream_id"):
            store.append(" case/case-001", [sample_event()], expected_version=0)
        with self.assertRaisesRegex(ValueError, "event_version must be a positive integer"):
            NewEvent(
                event_id="evt-001",
                event_type="case.created",
                event_version=0,
                occurred_at=OCCURRED_AT,
                payload={},
            )

    def test_reopening_store_preserves_history_and_migration(self) -> None:
        first = SQLiteEventStore(self.database_path, clock=lambda: RECORDED_AT)
        first.append("case/case-001", [sample_event()], expected_version=0)
        first.close()

        second = self.open_store()

        self.assertEqual(second.schema_version, 1)
        self.assertEqual(second.read_all()[0].event_id, "evt-001")
        with closing(raw_connection(self.database_path)) as connection:
            migration_count = connection.execute(
                "SELECT COUNT(*) FROM complyroll_schema_migrations"
            ).fetchone()[0]
        self.assertEqual(migration_count, 1)

    def test_foreign_application_database_is_rejected(self) -> None:
        with closing(raw_connection(self.database_path)) as connection:
            connection.execute("PRAGMA application_id = 12345")

        with self.assertRaisesRegex(UnsupportedSchemaError, "another application"):
            SQLiteEventStore(self.database_path)

    def test_closed_store_rejects_operations(self) -> None:
        store = SQLiteEventStore(self.database_path, clock=lambda: RECORDED_AT)
        store.close()

        with self.assertRaisesRegex(EventStoreError, "closed"):
            store.read_all()

    def test_write_lock_contention_raises_busy_without_wedging_the_store(self) -> None:
        store = SQLiteEventStore(
            self.database_path,
            clock=lambda: RECORDED_AT,
            busy_timeout_ms=100,
        )
        self.addCleanup(store.close)
        store.append("case/case-001", [sample_event("evt-001")], expected_version=0)

        with closing(raw_connection(self.database_path)) as blocker:
            blocker.execute("BEGIN IMMEDIATE")

            started = time.monotonic()
            with self.assertRaises(EventStoreBusyError):
                store.append("case/case-002", [sample_event("evt-002")], expected_version=0)
            elapsed = time.monotonic() - started

            self.assertLess(elapsed, 2.0)
            self.assertFalse(store._connection.in_transaction)
            self.assertEqual([record.event_id for record in store.read_all()], ["evt-001"])
            self.assertEqual(store.current_stream_version("case/case-002"), 0)

            concurrent = SQLiteEventStore(self.database_path, busy_timeout_ms=100)
            self.addCleanup(concurrent.close)
            self.assertEqual(concurrent.schema_version, SCHEMA_VERSION)

            blocker.execute("ROLLBACK")

        retried = store.append("case/case-002", [sample_event("evt-002")], expected_version=0)

        self.assertEqual(retried[0].sequence, 2)
        self.assertEqual(
            [record.event_id for record in store.read_all()],
            ["evt-001", "evt-002"],
        )

    def test_reopening_rejects_a_database_with_dropped_schema_objects(self) -> None:
        store = self.open_store()
        store.append("case/case-001", [sample_event()], expected_version=0)
        store.close()

        with closing(raw_connection(self.database_path)) as connection:
            connection.execute("DROP TRIGGER events_reject_update")
            connection.execute("DROP INDEX events_type_sequence_idx")

        with self.assertRaises(UnsupportedSchemaError) as caught:
            SQLiteEventStore(self.database_path)

        message = str(caught.exception)
        self.assertIn("missing schema objects", message)
        self.assertIn("trigger events_reject_update", message)
        self.assertIn("index events_type_sequence_idx", message)

    def test_deleted_event_row_is_reported_as_a_history_gap(self) -> None:
        store = self.open_store()
        store.append(
            "case/case-001",
            [sample_event(f"evt-00{index}") for index in range(1, 6)],
            expected_version=0,
        )
        store.close()

        with closing(raw_connection(self.database_path)) as connection:
            connection.execute("DROP TRIGGER events_reject_update")
            connection.execute("DROP TRIGGER events_reject_delete")
            connection.execute("DELETE FROM events WHERE sequence = 3")
            for statement in TRIGGER_STATEMENTS:
                connection.execute(statement)

        reopened = SQLiteEventStore(self.database_path, clock=lambda: RECORDED_AT)
        self.addCleanup(reopened.close)

        with self.assertRaises(EventIntegrityError) as global_caught:
            reopened.read_all()
        with self.assertRaises(EventIntegrityError) as stream_caught:
            reopened.read_stream("case/case-001")

        self.assertIn("missing sequence 3", str(global_caught.exception))
        self.assertEqual(global_caught.exception.sequence, 4)
        self.assertIn("missing version 3", str(stream_caught.exception))
        self.assertEqual(stream_caught.exception.sequence, 4)

    def test_reads_that_start_after_a_gap_remain_contiguous(self) -> None:
        store = self.open_store()
        store.append(
            "case/case-001",
            [sample_event(f"evt-00{index}") for index in range(1, 6)],
            expected_version=0,
        )

        self.assertEqual(
            [record.sequence for record in store.read_all(after_sequence=2)],
            [3, 4, 5],
        )
        self.assertEqual(
            [record.stream_version for record in store.read_stream("case/case-001", limit=2)],
            [1, 2],
        )

    def test_garbage_file_is_rejected_as_a_database(self) -> None:
        self.database_path.write_bytes(b"ComplyRoll is not a SQLite file. " * 200)

        with self.assertRaisesRegex(UnsupportedSchemaError, "not a SQLite database"):
            SQLiteEventStore(self.database_path)

    def test_unversioned_database_with_existing_objects_is_rejected(self) -> None:
        with closing(raw_connection(self.database_path)) as connection:
            connection.execute("CREATE TABLE events (sequence INTEGER PRIMARY KEY)")

        with self.assertRaisesRegex(UnsupportedSchemaError, "already contains objects"):
            SQLiteEventStore(self.database_path)

    def test_file_database_uses_write_ahead_logging_and_full_synchronous(self) -> None:
        store = self.open_store()

        synchronous = store._connection.execute("PRAGMA synchronous").fetchone()[0]

        self.assertEqual(store.journal_mode, "wal")
        self.assertEqual(int(synchronous), 2)

    def test_memory_database_is_usable_without_write_ahead_logging(self) -> None:
        memory = SQLiteEventStore(":memory:", clock=lambda: RECORDED_AT)
        self.addCleanup(memory.close)

        memory.append("case/case-001", [sample_event()], expected_version=0)

        self.assertEqual(memory.journal_mode, "memory")
        self.assertEqual(memory.read_all()[0].event_id, "evt-001")

    def test_busy_timeout_is_validated_and_applied_to_the_connection(self) -> None:
        invalid: tuple[object, ...] = (0, -1, "5000", True)

        for value in invalid:
            with self.subTest(value=value):
                with self.assertRaisesRegex(ValueError, "busy_timeout_ms"):
                    SQLiteEventStore(self.database_path, busy_timeout_ms=value)  # type: ignore

        store = SQLiteEventStore(self.database_path, busy_timeout_ms=250)
        self.addCleanup(store.close)

        applied = store._connection.execute("PRAGMA busy_timeout").fetchone()[0]
        self.assertEqual(int(applied), 250)


class _FakeConnection:
    """Minimal stand-in that fails on chosen statements and records what was issued."""

    def __init__(self, *, fail_on: set[str], error: str = "database is locked") -> None:
        self.fail_on = fail_on
        self.error = error
        self.statements: list[str] = []
        self.in_transaction = False
        self.closed = False

    def execute(self, sql: str, parameters: object = ()) -> object:
        statement = sql.strip().split()[0].upper()
        self.statements.append(statement)
        if statement in self.fail_on:
            raise sqlite3.OperationalError(self.error)
        if statement == "BEGIN":
            self.in_transaction = True
        elif statement in {"COMMIT", "ROLLBACK"}:
            self.in_transaction = False
        return None

    def close(self) -> None:
        self.closed = True


class StorageErrorMappingTests(unittest.TestCase):
    """No raw sqlite3 exception crosses the store's public boundary."""

    def setUp(self) -> None:
        self.temporary_directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary_directory.cleanup)
        self.database_path = Path(self.temporary_directory.name) / "complyroll.db"

    def test_disk_full_during_append_is_a_store_error_and_store_stays_usable(self) -> None:
        store = SQLiteEventStore(self.database_path, clock=lambda: RECORDED_AT)
        self.addCleanup(store.close)
        assert store._connection is not None
        store._connection.execute("PRAGMA max_page_count = 8")
        big = {"pad": "x" * 200_000}

        with self.assertRaises(EventStoreError) as raised:
            for index in range(50):
                store.append(
                    "stream-full",
                    [sample_event(f"evt-full-{index}", payload=big)],
                    expected_version=index,
                )
        self.assertNotIsInstance(raised.exception, EventStoreBusyError)
        self.assertIn("full", str(raised.exception).lower())
        self.assertFalse(store._connection.in_transaction)

        store._connection.execute("PRAGMA max_page_count = 1000000")
        version = store.current_stream_version("stream-full")
        store.append("stream-full", [sample_event("evt-after-full")], expected_version=version)
        self.assertEqual(store.current_stream_version("stream-full"), version + 1)

    def test_corrupted_file_is_reported_as_a_store_error_on_open(self) -> None:
        store = SQLiteEventStore(self.database_path, clock=lambda: RECORDED_AT)
        for index in range(40):
            store.append(
                "stream-c",
                [sample_event(f"evt-c-{index}", payload={"pad": "y" * 2000})],
                expected_version=index,
            )
        store.close()
        for side_file in (".db-wal", ".db-shm"):
            candidate = self.database_path.with_name(self.database_path.name + side_file[3:])
            if candidate.exists():
                candidate.unlink()

        raw = bytearray(self.database_path.read_bytes())
        # Page 1 holds sqlite_master; its cells live at the end of the page, so scribbling
        # over the second half makes the schema unreadable and SQLite reports a malformed
        # image the moment the store tries to verify its objects.
        raw[2048:4096] = b"\xff" * 2048
        self.database_path.write_bytes(bytes(raw))

        with self.assertRaises(EventStoreError) as raised:
            reopened = SQLiteEventStore(self.database_path)
            self.addCleanup(reopened.close)
            reopened.read_all(limit=100)
        self.assertNotIsInstance(raised.exception, EventStoreBusyError)

    def test_failed_rollback_after_failed_commit_closes_the_connection(self) -> None:
        abandoned: list[bool] = []
        connection = _FakeConnection(fail_on={"COMMIT", "ROLLBACK"})

        with self.assertRaises(EventStoreBusyError) as raised:
            with _write_transaction(connection, on_unrecoverable=lambda: abandoned.append(True)):  # type: ignore[arg-type]
                pass
        self.assertIn("rollback also failed", str(raised.exception))
        self.assertIn("closed", str(raised.exception))
        self.assertTrue(connection.closed)
        self.assertEqual(abandoned, [True])

    def test_failed_rollback_after_body_error_closes_the_connection(self) -> None:
        abandoned: list[bool] = []
        connection = _FakeConnection(fail_on={"ROLLBACK"}, error="disk I/O error")

        with self.assertRaises(EventStoreError) as raised:
            with _write_transaction(connection, on_unrecoverable=lambda: abandoned.append(True)):  # type: ignore[arg-type]
                raise RuntimeError("body failure")
        self.assertIsInstance(raised.exception.__cause__, RuntimeError)
        self.assertIn("closed", str(raised.exception))
        self.assertTrue(connection.closed)
        self.assertEqual(abandoned, [True])

    def test_store_reports_closed_after_an_unrecoverable_transaction(self) -> None:
        store = SQLiteEventStore(self.database_path, clock=lambda: RECORDED_AT)
        self.addCleanup(store.close)
        store._abandon_connection()
        with self.assertRaises(EventStoreError) as raised:
            _ = store.latest_sequence
        self.assertIn("closed", str(raised.exception))

    def test_busy_detection_uses_sqlite_result_names_not_message_text(self) -> None:
        from complyroll.store.sqlite import _is_busy_error

        self.assertFalse(_is_busy_error(sqlite3.OperationalError("no such table: locked_out")))
        with closing(sqlite3.connect(":memory:")) as connection:
            try:
                connection.execute("SELECT * FROM missing_table")
            except sqlite3.OperationalError as error:
                self.assertFalse(_is_busy_error(error))

    def test_opening_a_fresh_store_while_a_peer_holds_the_file_is_busy_not_raw(self) -> None:
        with closing(sqlite3.connect(self.database_path, isolation_level=None)) as holder:
            holder.execute("BEGIN IMMEDIATE")
            holder.execute("CREATE TABLE peer_placeholder (x INTEGER)")
            with self.assertRaises(EventStoreError) as raised:
                SQLiteEventStore(self.database_path, busy_timeout_ms=150)
            self.assertNotIsInstance(raised.exception.__cause__, type(None))
            holder.execute("ROLLBACK")
        store = SQLiteEventStore(self.database_path, busy_timeout_ms=150)
        self.addCleanup(store.close)
        self.assertEqual(store.journal_mode, "wal")

    def test_unopenable_paths_raise_store_errors_not_raw_sqlite(self) -> None:
        directory = Path(self.temporary_directory.name)
        for label, path in (
            ("directory", directory),
            ("missing parent", directory / "missing" / "store.db"),
        ):
            with self.subTest(path=label):
                with self.assertRaises(EventStoreError) as raised:
                    SQLiteEventStore(path)
                self.assertNotIsInstance(raised.exception, EventStoreBusyError)
                self.assertIn("open", str(raised.exception))


class TamperEvidenceTests(unittest.TestCase):
    """Out-of-band changes that keep object names intact are still detected on reopen."""

    def setUp(self) -> None:
        self.temporary_directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary_directory.cleanup)
        self.database_path = Path(self.temporary_directory.name) / "complyroll.db"
        store = SQLiteEventStore(self.database_path, clock=lambda: RECORDED_AT)
        for index in range(5):
            store.append("stream-t", [sample_event(f"evt-t-{index}")], expected_version=index)
        store.close()

    def _raw(self) -> sqlite3.Connection:
        return sqlite3.connect(self.database_path, isolation_level=None)

    def test_same_named_trigger_with_a_different_body_is_rejected(self) -> None:
        with closing(self._raw()) as raw:
            raw.execute("DROP TRIGGER events_reject_update")
            raw.execute(
                "CREATE TRIGGER events_reject_update BEFORE UPDATE ON events BEGIN "
                "SELECT 1; END"
            )
        with self.assertRaisesRegex(UnsupportedSchemaError, "do not match"):
            SQLiteEventStore(self.database_path)

    def test_table_recreated_without_its_checks_is_rejected(self) -> None:
        with closing(self._raw()) as raw:
            raw.execute("DROP TRIGGER events_reject_update")
            raw.execute("DROP TRIGGER events_reject_delete")
            raw.execute("ALTER TABLE events RENAME TO events_old")
            raw.execute(
                "CREATE TABLE events (sequence INTEGER PRIMARY KEY AUTOINCREMENT, event_id TEXT,"
                " stream_id TEXT, stream_version INTEGER, event_type TEXT, event_version INTEGER,"
                " occurred_at TEXT, recorded_at TEXT, payload_json TEXT, metadata_json TEXT,"
                " payload_sha256 TEXT)"
            )
            raw.execute("INSERT INTO events SELECT * FROM events_old")
            raw.execute("DROP TABLE events_old")
            for statement in _SCHEMA_V1:
                if "CREATE TRIGGER" in statement or "CREATE INDEX" in statement:
                    raw.execute(statement)
        with self.assertRaisesRegex(UnsupportedSchemaError, "do not match"):
            SQLiteEventStore(self.database_path)

    def test_deleting_the_most_recent_events_is_detected_on_reopen(self) -> None:
        with closing(self._raw()) as raw:
            raw.execute("DROP TRIGGER events_reject_delete")
            raw.execute("DELETE FROM events WHERE sequence > 3")
            for statement in _SCHEMA_V1:
                if "events_reject_delete" in statement:
                    raw.execute(statement)
        with self.assertRaises(EventIntegrityError) as raised:
            SQLiteEventStore(self.database_path)
        self.assertIn("truncated", str(raised.exception))
        self.assertEqual(raised.exception.sequence, 3)

    def test_intact_history_reopens_and_appends_normally(self) -> None:
        store = SQLiteEventStore(self.database_path, clock=lambda: RECORDED_AT)
        self.addCleanup(store.close)
        store.append("stream-t", [sample_event("evt-t-5")], expected_version=5)
        self.assertEqual([record.sequence for record in store.read_all()], [1, 2, 3, 4, 5, 6])


if __name__ == "__main__":
    unittest.main()
