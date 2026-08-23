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
    IntegrityReport,
    NewEvent,
    ProjectionConcurrencyError,
    SQLiteEventStore,
    UnsupportedSchemaError,
)
from complyroll.store.sqlite import (
    _SCHEMA_V1,
    APPLICATION_ID,
    EXPECTED_SCHEMA_OBJECTS,
    SCHEMA_VERSION,
    _write_transaction,
)

OCCURRED_AT = datetime(2026, 8, 20, 9, 30, tzinfo=timezone(timedelta(hours=-7)))
RECORDED_AT = datetime(2026, 8, 20, 16, 31, tzinfo=UTC)
RECORDED_TEXT = RECORDED_AT.isoformat(timespec="microseconds").replace("+00:00", "Z")

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


def recorded_sql(connection: sqlite3.Connection, name: str) -> str:
    """Return the exact DDL SQLite recorded for one schema object.

    Rebuilding a dropped trigger from this text, rather than from the source DDL, keeps a
    damage fixture from reporting an altered object it never meant to alter.
    """

    row = connection.execute(
        "SELECT sql FROM sqlite_master WHERE name = ?",
        (name,),
    ).fetchone()
    if row is None or row[0] is None:
        raise AssertionError(f"sqlite_master holds no recorded DDL for {name}")
    return str(row[0])


def insert_event_row(
    connection: sqlite3.Connection,
    *,
    sequence: int,
    event_id: str,
    stream_id: str,
    stream_version: int,
) -> None:
    """Insert one well-formed row directly, choosing its sequence and stream by hand.

    Nothing in the schema blocks an insert, so this needs no trigger dropped. The payload
    digest is computed the way the store computes it, which keeps a contiguity fixture from
    also reporting a payload fault it never meant to create.
    """

    payload_json = json.dumps({"case_id": stream_id}, separators=(",", ":"), sort_keys=True)
    connection.execute(
        """
        INSERT INTO events (
            sequence, event_id, stream_id, stream_version, event_type, event_version,
            occurred_at, recorded_at, payload_json, metadata_json, payload_sha256
        ) VALUES (?, ?, ?, ?, 'case.created', 1, ?, ?, ?, '{}', ?)
        """,
        (
            sequence,
            event_id,
            stream_id,
            stream_version,
            RECORDED_TEXT,
            RECORDED_TEXT,
            payload_json,
            hashlib.sha256(payload_json.encode("utf-8")).hexdigest(),
        ),
    )


def delete_event_row(path: Path, sequence: int) -> None:
    """Delete one committed row the way a bad restore or an attacker would.

    Only the trigger blocking the delete is dropped, and it is rebuilt from the DDL
    sqlite_master recorded, so the file carries a history hole and no schema fault.
    """

    with closing(raw_connection(path)) as connection:
        restore = recorded_sql(connection, "events_reject_delete")
        connection.execute("DROP TRIGGER events_reject_delete")
        connection.execute("DELETE FROM events WHERE sequence = ?", (sequence,))
        connection.execute(restore)


def move_event_to_another_stream(path: Path, sequence: int, stream_id: str) -> None:
    """Re-home one event under a new stream, keeping the global sequences intact.

    The row count still equals MAX(sequence), so a global contiguity check alone sees a
    healthy file; only the original stream is now short a version. It is the one damage
    shape that needs the per-stream half of the check.
    """

    with closing(raw_connection(path)) as connection:
        restore = recorded_sql(connection, "events_reject_delete")
        connection.execute("DROP TRIGGER events_reject_delete")
        connection.execute("DELETE FROM events WHERE sequence = ?", (sequence,))
        insert_event_row(
            connection,
            sequence=sequence,
            event_id=f"evt-moved-{sequence}",
            stream_id=stream_id,
            stream_version=1,
        )
        connection.execute(restore)


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

    def test_a_joined_context_issues_no_statement_of_its_own(self) -> None:
        """Joining is how an append inside `transaction()` stops committing on its own."""

        connection = FakeConnection(in_transaction=True)

        with _write_transaction(connection, joined=True):  # type: ignore[arg-type]
            connection.execute("INSERT")

        self.assertEqual(connection.statements, ["INSERT"])
        self.assertTrue(connection.in_transaction)

    def test_a_joined_context_leaves_a_body_failure_to_the_enclosing_block(self) -> None:
        connection = FakeConnection(in_transaction=True)

        with self.assertRaisesRegex(ValueError, "domain rule"):
            with _write_transaction(connection, joined=True):  # type: ignore[arg-type]
                raise ValueError("domain rule violated")

        self.assertEqual(connection.statements, [])
        self.assertTrue(connection.in_transaction)

    def test_joining_nothing_is_refused_rather_than_writing_unprotected(self) -> None:
        connection = FakeConnection()

        with self.assertRaisesRegex(EventStoreError, "expected an enclosing"):
            with _write_transaction(connection, joined=True):  # type: ignore[arg-type]
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

        # The normal constructor refuses a file with a hole in it, so the read-path checks
        # are exercised through the diagnostic open, which is now the only way to read one.
        with self.assertRaises(EventIntegrityError) as open_caught:
            SQLiteEventStore(self.database_path, clock=lambda: RECORDED_AT)
        reopened = SQLiteEventStore.open_for_verification(self.database_path)
        self.addCleanup(reopened.close)

        with self.assertRaises(EventIntegrityError) as global_caught:
            reopened.read_all()
        with self.assertRaises(EventIntegrityError) as stream_caught:
            reopened.read_stream("case/case-001")

        self.assertIn("missing sequence 3", str(open_caught.exception))
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


class StoreTransactionTests(unittest.TestCase):
    """One `BEGIN IMMEDIATE` across several store calls, or none of their writes.

    Every check a writer makes before appending is a claim about the whole log, and a claim
    made outside a transaction is only true until the next writer commits. Holding the write
    lock from the first read to the last append is what makes the claim survive the append.
    """

    def setUp(self) -> None:
        self.temporary_directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary_directory.cleanup)
        self.database_path = Path(self.temporary_directory.name) / "complyroll.db"

    def open_store(self, *, busy_timeout_ms: int = 5000) -> SQLiteEventStore:
        store = SQLiteEventStore(
            self.database_path,
            clock=lambda: RECORDED_AT,
            busy_timeout_ms=busy_timeout_ms,
        )
        self.addCleanup(store.close)
        return store

    def test_a_transaction_commits_every_append_it_holds(self) -> None:
        store = self.open_store()

        with store.transaction():
            store.append("case/case-001", [sample_event("evt-1")], expected_version=0)
            store.append("case/case-001", [sample_event("evt-2")], expected_version=1)

        self.assertEqual([record.event_id for record in store.read_all()], ["evt-1", "evt-2"])
        self.assertFalse(store.in_transaction)

    def test_an_exception_after_the_first_append_leaves_zero_events(self) -> None:
        store = self.open_store()

        with self.assertRaisesRegex(ValueError, "the caller changed its mind"):
            with store.transaction():
                store.append("case/case-001", [sample_event("evt-1")], expected_version=0)
                self.assertEqual(store.latest_sequence, 1)
                raise ValueError("the caller changed its mind")

        self.assertEqual(store.read_all(), ())
        self.assertEqual(store.latest_sequence, 0)
        self.assertEqual(store.current_stream_version("case/case-001"), 0)
        self.assertFalse(store.in_transaction)

    def test_a_rolled_back_transaction_is_invisible_to_another_connection(self) -> None:
        store = self.open_store()
        reader = SQLiteEventStore(self.database_path, busy_timeout_ms=100)
        self.addCleanup(reader.close)

        with self.assertRaises(ValueError):
            with store.transaction():
                store.append("case/case-001", [sample_event("evt-1")], expected_version=0)
                raise ValueError("abandoned")

        self.assertEqual(reader.read_all(), ())

    def test_reads_inside_the_transaction_see_its_own_pending_writes(self) -> None:
        store = self.open_store()

        with store.transaction():
            store.append("case/case-001", [sample_event("evt-1")], expected_version=0)

            self.assertEqual(store.current_stream_version("case/case-001"), 1)
            self.assertEqual([record.event_id for record in store.read_all()], ["evt-1"])
            self.assertEqual(store.latest_sequence, 1)

    def test_a_second_writer_is_busy_while_the_transaction_is_open_and_writes_after(
        self,
    ) -> None:
        holder = self.open_store()
        contender = SQLiteEventStore(self.database_path, busy_timeout_ms=100)
        self.addCleanup(contender.close)

        with holder.transaction():
            holder.append("case/case-001", [sample_event("evt-1")], expected_version=0)

            started = time.monotonic()
            with self.assertRaises(EventStoreBusyError):
                contender.append("case/case-002", [sample_event("evt-2")], expected_version=0)
            elapsed = time.monotonic() - started

            self.assertLess(elapsed, 2.0)
            self.assertEqual(contender.read_all(), ())

        appended = contender.append(
            "case/case-002", [sample_event("evt-2")], expected_version=0
        )

        self.assertEqual(appended[0].sequence, 2)
        self.assertEqual(
            [record.event_id for record in contender.read_all()], ["evt-1", "evt-2"]
        )

    def test_a_second_transaction_cannot_start_while_one_is_open(self) -> None:
        holder = self.open_store()
        contender = SQLiteEventStore(self.database_path, busy_timeout_ms=100)
        self.addCleanup(contender.close)

        with holder.transaction():
            with self.assertRaises(EventStoreBusyError):
                with contender.transaction():
                    pass

        with contender.transaction():
            contender.append("case/case-002", [sample_event("evt-2")], expected_version=0)

        self.assertEqual(contender.latest_sequence, 1)

    def test_nesting_a_transaction_on_one_store_is_refused(self) -> None:
        store = self.open_store()

        with store.transaction():
            with self.assertRaisesRegex(EventStoreError, "already inside a transaction"):
                with store.transaction():
                    pass
            store.append("case/case-001", [sample_event("evt-1")], expected_version=0)

        self.assertEqual(store.latest_sequence, 1)
        self.assertFalse(store.in_transaction)

    def test_a_refused_nesting_leaves_the_store_usable_afterwards(self) -> None:
        store = self.open_store()

        with self.assertRaises(EventStoreError):
            with store.transaction():
                with store.transaction():
                    pass

        self.assertFalse(store.in_transaction)
        store.append("case/case-001", [sample_event("evt-1")], expected_version=0)
        self.assertEqual(store.latest_sequence, 1)

    def test_a_projection_checkpoint_advanced_inside_a_transaction_rolls_back_too(
        self,
    ) -> None:
        store = self.open_store()
        store.append("case/case-001", [sample_event("evt-1")], expected_version=0)

        with self.assertRaises(ValueError):
            with store.transaction():
                store.advance_projection("case-list", expected_sequence=0, last_sequence=1)
                self.assertEqual(store.get_projection_checkpoint("case-list").last_sequence, 1)
                raise ValueError("abandoned")

        self.assertEqual(store.get_projection_checkpoint("case-list").last_sequence, 0)

    def test_append_outside_a_transaction_still_commits_on_its_own(self) -> None:
        store = self.open_store()

        store.append("case/case-001", [sample_event("evt-1")], expected_version=0)
        reader = SQLiteEventStore(self.database_path, busy_timeout_ms=100)
        self.addCleanup(reader.close)

        self.assertEqual([record.event_id for record in reader.read_all()], ["evt-1"])
        self.assertFalse(store.in_transaction)

    def test_a_stale_expected_version_inside_a_transaction_discards_the_batch(self) -> None:
        store = self.open_store()

        with self.assertRaises(EventConcurrencyError):
            with store.transaction():
                store.append("case/case-001", [sample_event("evt-1")], expected_version=0)
                store.append("case/case-001", [sample_event("evt-2")], expected_version=0)

        self.assertEqual(store.read_all(), ())

    def test_a_rollback_that_fails_closes_the_store_rather_than_trusting_it(self) -> None:
        """The wedge protection an append has, a transaction has: a connection whose
        rollback failed cannot be trusted, so it is closed and the store says so."""

        store = self.open_store()
        real = store._connection
        assert real is not None
        real.close()
        broken = _FakeConnection(fail_on={"ROLLBACK"}, error="disk I/O error")
        store._connection = broken  # type: ignore[assignment]

        with self.assertRaises(EventStoreError) as raised:
            with store.transaction():
                raise RuntimeError("body failure")

        self.assertIn("closed", str(raised.exception))
        self.assertTrue(broken.closed)
        self.assertFalse(store.in_transaction)
        with self.assertRaisesRegex(EventStoreError, "closed"):
            _ = store.latest_sequence

    def test_a_closed_store_refuses_to_start_a_transaction(self) -> None:
        store = SQLiteEventStore(self.database_path, clock=lambda: RECORDED_AT)
        store.close()

        with self.assertRaisesRegex(EventStoreError, "closed"):
            with store.transaction():
                pass


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


class HistoryContiguityTests(unittest.TestCase):
    """A hole anywhere in history is refused on open and before the next append.

    The AUTOINCREMENT counter only notices rows deleted off the end. A row removed from the
    middle leaves the counter and the last stored sequence agreeing, so such a file used to
    open normally and `append` used to mint the next sequence past the hole, making the gap
    permanent and every later full read fail. ADR 0008 says append refuses to write past a
    hole, and that has to hold for any hole, not only a truncated tail.
    """

    EVENT_COUNT = 5

    def setUp(self) -> None:
        self.temporary_directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary_directory.cleanup)
        self.database_path = self.populate()

    def populate(self, name: str = "complyroll.db") -> Path:
        """Write EVENT_COUNT events onto one stream in a fresh store, then close it."""

        path = Path(self.temporary_directory.name) / name
        store = SQLiteEventStore(path, clock=lambda: RECORDED_AT)
        for index in range(self.EVENT_COUNT):
            store.append(
                "case/case-001",
                [sample_event(f"evt-h-{index}")],
                expected_version=index,
            )
        store.close()
        return path

    def open_store(self) -> SQLiteEventStore:
        store = SQLiteEventStore(self.database_path, clock=lambda: RECORDED_AT)
        self.addCleanup(store.close)
        return store

    def test_constructor_refuses_a_file_with_a_hole_in_the_middle(self) -> None:
        delete_event_row(self.database_path, 2)

        with self.assertRaises(EventIntegrityError) as raised:
            SQLiteEventStore(self.database_path)

        self.assertEqual(
            str(raised.exception),
            "event history is missing sequence 2; next stored sequence is 3",
        )
        self.assertEqual(raised.exception.sequence, 3)

    def test_constructor_refuses_a_file_whose_first_row_was_deleted(self) -> None:
        """History that no longer starts at sequence 1 is a hole like any other."""

        delete_event_row(self.database_path, 1)

        with self.assertRaises(EventIntegrityError) as raised:
            SQLiteEventStore(self.database_path)

        self.assertEqual(
            str(raised.exception),
            "event history is missing sequence 1; next stored sequence is 2",
        )
        self.assertEqual(raised.exception.sequence, 2)

    def test_constructor_refuses_history_holding_a_sequence_below_one(self) -> None:
        """A forged low row leaves no gap between stored rows, only a count that cannot fit.

        Six rows cannot live inside sequences 1 through 5, so the count against the highest
        sequence still catches it even though every stored row has its predecessor.
        """

        with closing(raw_connection(self.database_path)) as connection:
            insert_event_row(
                connection,
                sequence=0,
                event_id="evt-h-forged",
                stream_id="case/case-001",
                stream_version=self.EVENT_COUNT + 1,
            )

        with self.assertRaises(EventIntegrityError) as raised:
            SQLiteEventStore(self.database_path)

        self.assertEqual(
            str(raised.exception),
            f"event history holds {self.EVENT_COUNT + 1} event(s) but its sequences run "
            f"from 0 to {self.EVENT_COUNT}",
        )
        self.assertEqual(raised.exception.sequence, self.EVENT_COUNT)

    def test_constructor_refuses_a_stream_that_is_short_a_version(self) -> None:
        """Global sequences stay whole here, so only the per-stream check can refuse it."""

        move_event_to_another_stream(self.database_path, 3, "case/case-002")

        with self.assertRaises(EventIntegrityError) as raised:
            SQLiteEventStore(self.database_path)

        self.assertEqual(
            str(raised.exception),
            "stream 'case/case-001' is missing version 3; next stored version is 4",
        )
        self.assertEqual(raised.exception.sequence, 4)

    def test_open_store_refuses_to_append_past_a_hole_that_arrived_underneath_it(self) -> None:
        """The append-time check is what stops a live store writing past fresh damage.

        The store opened on a healthy file, so the constructor's check passed; the hole is
        punched afterwards through a raw connection, exactly as the reported reproduction
        does, and the next append has to refuse even though it targets a different stream.
        """

        store = self.open_store()
        delete_event_row(self.database_path, 2)

        with self.assertRaises(EventIntegrityError) as raised:
            store.append("case/case-002", [sample_event("evt-h-late")], expected_version=0)

        self.assertEqual(
            str(raised.exception),
            "event history is missing sequence 2; next stored sequence is 3",
        )
        # The refusal is raised inside the write transaction, which rolls back and leaves
        # the store open rather than closing it. Reads that do not cross the hole keep
        # working, and nothing was written.
        assert store._connection is not None
        self.assertFalse(store._connection.in_transaction)
        self.assertEqual([record.sequence for record in store.read_all(limit=1)], [1])
        self.assertEqual(store.latest_sequence, self.EVENT_COUNT)
        self.assertEqual(store.current_stream_version("case/case-002"), 0)

    def test_open_store_refuses_to_append_to_a_stream_that_is_short_a_version(self) -> None:
        store = self.open_store()
        move_event_to_another_stream(self.database_path, 3, "case/case-002")

        with self.assertRaises(EventIntegrityError) as raised:
            store.append(
                "case/case-001",
                [sample_event("evt-h-late")],
                expected_version=self.EVENT_COUNT,
            )

        self.assertEqual(
            str(raised.exception),
            "stream 'case/case-001' is missing version 3; next stored version is 4",
        )
        assert store._connection is not None
        self.assertFalse(store._connection.in_transaction)
        self.assertEqual(store.current_stream_version("case/case-001"), self.EVENT_COUNT)

    def test_clean_store_with_several_streams_opens_and_appends_normally(self) -> None:
        """Every stream numbers its own versions from 1, so the grouped check must read
        each stream on its own rather than as a gap in the one before it."""

        path = Path(self.temporary_directory.name) / "many.db"
        first = SQLiteEventStore(path, clock=lambda: RECORDED_AT)
        for index, stream in enumerate(("case/case-a", "case/case-b", "case/case-c")):
            first.append(
                stream,
                [sample_event(f"evt-m-{index}-0"), sample_event(f"evt-m-{index}-1")],
                expected_version=0,
            )
        first.close()

        reopened = SQLiteEventStore(path, clock=lambda: RECORDED_AT)
        self.addCleanup(reopened.close)
        appended = reopened.append(
            "case/case-b",
            [sample_event("evt-m-late")],
            expected_version=2,
        )
        verifier = SQLiteEventStore.open_for_verification(path)
        self.addCleanup(verifier.close)

        self.assertEqual(appended[0].sequence, 7)
        self.assertEqual(appended[0].stream_version, 3)
        self.assertEqual(
            [record.sequence for record in reopened.read_all()],
            [1, 2, 3, 4, 5, 6, 7],
        )
        self.assertTrue(verifier.verify_history().ok)

    def test_diagnostic_open_still_inspects_a_file_with_a_hole(self) -> None:
        """`open_for_verification` deliberately skips the contiguity refusal.

        It exists to describe damaged files, so refusing them there would make exactly the
        faults it reports unreportable. `verify_history` already names both gaps.
        """

        delete_event_row(self.database_path, 2)

        store = SQLiteEventStore.open_for_verification(self.database_path)
        self.addCleanup(store.close)
        report = store.verify_history()

        self.assertFalse(report.ok)
        self.assertEqual(
            [fault.code for fault in report.faults],
            ["sequence_gap", "stream_version_gap"],
        )
        self.assertEqual(report.checked_events, self.EVENT_COUNT - 1)


class VerifyHistoryTests(unittest.TestCase):
    """The diagnostic open path reaches every fault the normal constructor refuses.

    `SQLiteEventStore(path)` rejects a database whose schema objects, migration record, or
    sequence counter are wrong, so those faults were unreportable: describing them needs an
    open store. `open_for_verification` opens the same file read-only and skips the
    refusals, and these cases pin both halves, the faults it now reports and the refusals
    the normal constructor still raises unchanged.
    """

    EVENT_COUNT = 5

    def setUp(self) -> None:
        self.temporary_directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary_directory.cleanup)
        self.database_path = self.populate()

    def populate(self, name: str = "complyroll.db") -> Path:
        """Write EVENT_COUNT events onto one stream in a fresh store, then close it."""

        path = Path(self.temporary_directory.name) / name
        store = SQLiteEventStore(path, clock=lambda: RECORDED_AT)
        for index in range(self.EVENT_COUNT):
            store.append(
                "case/case-001",
                [sample_event(f"evt-v-{index}")],
                expected_version=index,
            )
        store.close()
        return path

    def verify(self, path: Path) -> IntegrityReport:
        store = SQLiteEventStore.open_for_verification(path)
        self.addCleanup(store.close)
        return store.verify_history()

    @staticmethod
    def codes(report: IntegrityReport) -> list[str]:
        return [fault.code for fault in report.faults]

    # Damage helpers. Each edits the file the way an attacker or a bad restore would: a raw
    # autocommit connection, only the trigger blocking that edit dropped, and that trigger
    # rebuilt from the DDL sqlite_master recorded, so no schema fault leaks into the result.

    def tamper_payload(self, path: Path, sequence: int) -> None:
        with closing(raw_connection(path)) as connection:
            restore = recorded_sql(connection, "events_reject_update")
            connection.execute("DROP TRIGGER events_reject_update")
            connection.execute(
                "UPDATE events SET payload_json = ? WHERE sequence = ?",
                ('{"case_id":"altered"}', sequence),
            )
            connection.execute(restore)

    def delete_event(self, path: Path, sequence: int) -> None:
        delete_event_row(path, sequence)

    def move_event(self, path: Path, sequence: int) -> None:
        move_event_to_another_stream(path, sequence, "case/case-002")

    def drop_trigger(self, path: Path, name: str) -> None:
        with closing(raw_connection(path)) as connection:
            connection.execute(f"DROP TRIGGER {name}")

    def alter_trigger(self, path: Path) -> None:
        """Keep the trigger name and gut its body, the shape a silent bypass would take."""

        with closing(raw_connection(path)) as connection:
            connection.execute("DROP TRIGGER events_reject_update")
            connection.execute(
                "CREATE TRIGGER events_reject_update BEFORE UPDATE ON events "
                "BEGIN SELECT 1; END"
            )

    def alter_index(self, path: Path) -> None:
        with closing(raw_connection(path)) as connection:
            connection.execute("DROP INDEX events_stream_sequence_idx")
            connection.execute("CREATE INDEX events_stream_sequence_idx ON events (stream_id)")

    def delete_migration(self, path: Path) -> None:
        with closing(raw_connection(path)) as connection:
            connection.execute(
                "DELETE FROM complyroll_schema_migrations WHERE version = ?",
                (SCHEMA_VERSION,),
            )

    def drop_events_table(self, path: Path) -> None:
        with closing(raw_connection(path)) as connection:
            connection.execute("DROP TABLE events")

    def test_clean_store_verifies_every_appended_event(self) -> None:
        report = self.verify(self.database_path)

        self.assertTrue(report.ok)
        self.assertEqual(report.faults, ())
        self.assertEqual(report.checked_events, self.EVENT_COUNT)
        self.assertEqual(report.render(), f"ok: {self.EVENT_COUNT} event(s) verified")

    def test_tampered_payload_is_reported_at_its_sequence(self) -> None:
        self.tamper_payload(self.database_path, 2)

        report = self.verify(self.database_path)

        self.assertFalse(report.ok)
        self.assertEqual(self.codes(report), ["payload_digest_mismatch"])
        self.assertEqual(report.faults[0].sequence, 2)
        self.assertIn("recorded digest", report.faults[0].message)
        self.assertEqual(report.checked_events, self.EVENT_COUNT)

    def test_deleted_middle_row_reports_both_sequence_and_stream_gaps(self) -> None:
        self.delete_event(self.database_path, 3)

        report = self.verify(self.database_path)

        self.assertEqual(self.codes(report), ["sequence_gap", "stream_version_gap"])
        self.assertEqual([fault.sequence for fault in report.faults], [4, 4])
        self.assertIn("missing sequence 3", report.faults[0].message)
        self.assertIn("missing version 3", report.faults[1].message)
        self.assertEqual(report.checked_events, self.EVENT_COUNT - 1)

    def test_moved_event_reports_only_a_stream_version_gap(self) -> None:
        """Global sequences stay whole, so only the per-stream walk has anything to say."""

        self.move_event(self.database_path, 3)

        report = self.verify(self.database_path)

        self.assertEqual(self.codes(report), ["stream_version_gap"])
        self.assertEqual(report.faults[0].sequence, 4)
        self.assertIn("'case/case-001' is missing version 3", report.faults[0].message)
        self.assertEqual(report.checked_events, self.EVENT_COUNT)

    def test_deleted_tail_row_reports_a_sequence_counter_mismatch(self) -> None:
        self.delete_event(self.database_path, self.EVENT_COUNT)

        report = self.verify(self.database_path)

        self.assertEqual(self.codes(report), ["sequence_counter_mismatch"])
        self.assertEqual(report.faults[0].sequence, self.EVENT_COUNT - 1)
        self.assertIn("truncated", report.faults[0].message)
        self.assertEqual(report.checked_events, self.EVENT_COUNT - 1)

    def test_altered_trigger_body_is_reported_as_an_altered_schema_object(self) -> None:
        self.alter_trigger(self.database_path)

        report = self.verify(self.database_path)

        self.assertEqual(self.codes(report), ["schema_object_altered"])
        self.assertIsNone(report.faults[0].sequence)
        self.assertEqual(
            report.faults[0].message,
            "trigger events_reject_update does not match its expected definition",
        )
        self.assertEqual(report.checked_events, self.EVENT_COUNT)

    def test_dropped_trigger_is_reported_as_a_missing_schema_object(self) -> None:
        self.drop_trigger(self.database_path, "events_reject_delete")

        report = self.verify(self.database_path)

        self.assertEqual(self.codes(report), ["schema_object_missing"])
        self.assertIsNone(report.faults[0].sequence)
        self.assertEqual(
            report.faults[0].message,
            "database is missing trigger events_reject_delete",
        )

    def test_deleted_migration_row_is_reported_as_a_missing_migration(self) -> None:
        self.delete_migration(self.database_path)

        report = self.verify(self.database_path)

        self.assertEqual(self.codes(report), ["migration_missing"])
        self.assertEqual(
            report.faults[0].message,
            f"database is missing migration record {SCHEMA_VERSION}",
        )

    def test_missing_events_table_reports_schema_faults_and_checks_nothing(self) -> None:
        self.drop_events_table(self.database_path)

        report = self.verify(self.database_path)

        self.assertFalse(report.ok)
        self.assertEqual(report.checked_events, 0)
        self.assertEqual(
            [fault.message for fault in report.faults],
            [
                "database is missing index events_stream_sequence_idx",
                "database is missing index events_type_sequence_idx",
                "database is missing table events",
                "database is missing trigger events_reject_delete",
                "database is missing trigger events_reject_update",
            ],
        )

    def test_faults_are_reported_in_a_fixed_order(self) -> None:
        path = self.populate("ordered.db")
        self.tamper_payload(path, 2)
        self.delete_event(path, 3)
        self.delete_event(path, self.EVENT_COUNT)
        self.alter_index(path)
        self.drop_trigger(path, "events_reject_update")
        self.delete_migration(path)

        report = self.verify(path)

        # Schema objects sort by (type, name) across both codes, so the altered index
        # precedes the missing trigger; then migration, then counter, then rows by sequence.
        self.assertEqual(
            [(fault.code, fault.sequence) for fault in report.faults],
            [
                ("schema_object_altered", None),
                ("schema_object_missing", None),
                ("migration_missing", None),
                ("sequence_counter_mismatch", 4),
                ("payload_digest_mismatch", 2),
                ("sequence_gap", 4),
                ("stream_version_gap", 4),
            ],
        )
        self.assertEqual(report.checked_events, 3)
        self.assertEqual(report.render(), "faults: 7 problem(s) in 3 verified event(s)")

    def test_verify_history_never_raises_on_a_damaged_file(self) -> None:
        damages = (
            ("tampered payload", lambda path: self.tamper_payload(path, 2)),
            ("deleted middle row", lambda path: self.delete_event(path, 3)),
            ("deleted tail row", lambda path: self.delete_event(path, self.EVENT_COUNT)),
            ("moved event", lambda path: self.move_event(path, 3)),
            ("altered trigger", self.alter_trigger),
            ("dropped trigger", lambda path: self.drop_trigger(path, "events_reject_update")),
            ("deleted migration row", self.delete_migration),
            ("dropped events table", self.drop_events_table),
        )

        for index, (label, damage) in enumerate(damages):
            with self.subTest(damage=label):
                path = self.populate(f"damaged-{index}.db")
                damage(path)

                report = self.verify(path)

                self.assertFalse(report.ok)
                self.assertTrue(report.faults)
                self.assertIn("problem(s)", report.render())

    def test_normal_constructor_still_refuses_every_damaged_file(self) -> None:
        truncated = (
            f"event history was truncated: last stored sequence is {self.EVENT_COUNT - 1} "
            f"but the sequence counter is {self.EVENT_COUNT}"
        )
        refusals = (
            (
                "dropped trigger",
                lambda path: self.drop_trigger(path, "events_reject_delete"),
                UnsupportedSchemaError,
                "database is missing schema objects: trigger events_reject_delete",
            ),
            (
                "altered trigger",
                self.alter_trigger,
                UnsupportedSchemaError,
                "database schema objects do not match their expected definitions: "
                "trigger events_reject_update",
            ),
            (
                "deleted migration row",
                self.delete_migration,
                UnsupportedSchemaError,
                f"database is missing migration record {SCHEMA_VERSION}",
            ),
            (
                "deleted tail row",
                lambda path: self.delete_event(path, self.EVENT_COUNT),
                EventIntegrityError,
                truncated,
            ),
            (
                "deleted middle row",
                lambda path: self.delete_event(path, 2),
                EventIntegrityError,
                "event history is missing sequence 2; next stored sequence is 3",
            ),
            (
                "moved event",
                lambda path: self.move_event(path, 3),
                EventIntegrityError,
                "stream 'case/case-001' is missing version 3; next stored version is 4",
            ),
        )
        # A rewritten payload is deliberately absent from this table. Payload digests are a
        # read-time check, verified row by row as history is read, so a file carrying one
        # opens normally and fails on the first read that reaches the damaged row.

        for index, (label, damage, error, message) in enumerate(refusals):
            with self.subTest(damage=label):
                path = self.populate(f"refused-{index}.db")
                damage(path)

                with self.assertRaises(error) as raised:
                    SQLiteEventStore(path)

                self.assertEqual(str(raised.exception), message)

    def test_open_for_verification_refuses_a_missing_path_and_creates_no_file(self) -> None:
        missing = Path(self.temporary_directory.name) / "absent.db"

        with self.assertRaises(EventStoreError) as raised:
            SQLiteEventStore.open_for_verification(missing)

        self.assertNotIsInstance(raised.exception, EventStoreBusyError)
        self.assertIn("absent.db", str(raised.exception))
        self.assertEqual(
            [path.name for path in Path(self.temporary_directory.name).glob("absent.db*")],
            [],
        )

    def test_verification_open_creates_no_schema_on_a_version_zero_file(self) -> None:
        unversioned = Path(self.temporary_directory.name) / "unversioned.db"
        with closing(raw_connection(unversioned)):
            pass

        report = self.verify(unversioned)

        self.assertEqual(report.checked_events, 0)
        self.assertEqual(
            self.codes(report),
            ["schema_object_missing"] * len(EXPECTED_SCHEMA_OBJECTS),
        )
        with closing(raw_connection(unversioned)) as connection:
            self.assertEqual(int(connection.execute("PRAGMA user_version").fetchone()[0]), 0)
            self.assertEqual(
                connection.execute("SELECT COUNT(*) FROM sqlite_master").fetchone()[0],
                0,
            )

    def test_verification_open_handles_paths_that_look_like_uri_syntax(self) -> None:
        """The read-only open goes through a file: URI, so the path has to be encoded.

        Handed the raw path, SQLite reads everything from '?' onward as URI parameters and
        opens a different, empty database, which would verify clean and report nothing.
        """

        for name in ("od?d.db", "ha#sh.db", "with space.db", "per%cent.db"):
            with self.subTest(name=name):
                path = self.populate(name)

                report = self.verify(path)

                self.assertTrue(report.ok)
                self.assertEqual(report.checked_events, self.EVENT_COUNT)

    def test_verification_open_maps_unreadable_files_onto_store_errors(self) -> None:
        """No raw sqlite3 error crosses the diagnostic boundary either."""

        garbage = Path(self.temporary_directory.name) / "garbage.db"
        garbage.write_bytes(b"ComplyRoll is not a SQLite file. " * 200)

        with self.assertRaisesRegex(UnsupportedSchemaError, "not a SQLite database"):
            SQLiteEventStore.open_for_verification(garbage)

        with self.assertRaises(EventStoreError) as raised:
            SQLiteEventStore.open_for_verification(Path(self.temporary_directory.name))
        self.assertIn("could not open the database", str(raised.exception))

    def test_verification_store_cannot_write_to_the_database(self) -> None:
        """SQLite itself refuses the write, so no future edit can quietly make this path
        writable while every read-only assertion still passes."""

        store = SQLiteEventStore.open_for_verification(self.database_path)
        self.addCleanup(store.close)

        with self.assertRaises(EventStoreError) as raised:
            store.append(
                "case/case-001",
                [sample_event("evt-v-99")],
                expected_version=self.EVENT_COUNT,
            )

        self.assertIn("readonly", str(raised.exception).lower())
        self.assertFalse(store._connection.in_transaction)
        self.assertEqual(store.verify_history().checked_events, self.EVENT_COUNT)

    def test_verification_open_leaves_the_database_bytes_unchanged(self) -> None:
        damaged = self.populate("damaged.db")
        self.tamper_payload(damaged, 1)
        self.drop_trigger(damaged, "events_reject_update")
        unversioned = Path(self.temporary_directory.name) / "unversioned.db"
        with closing(raw_connection(unversioned)):
            pass

        for path in (self.database_path, damaged, unversioned):
            with self.subTest(database=path.name):
                before = hashlib.sha256(path.read_bytes()).hexdigest()

                store = SQLiteEventStore.open_for_verification(path)
                try:
                    store.verify_history()
                finally:
                    store.close()

                self.assertEqual(hashlib.sha256(path.read_bytes()).hexdigest(), before)


if __name__ == "__main__":
    unittest.main()
