from __future__ import annotations

import hashlib
import json
import sqlite3
import sys
import tempfile
import time
import unittest
from collections.abc import Sequence
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
    MAX_EVENT_JSON_VALUES,
    SCHEMA_VERSION,
    SUPPORTED_SCHEMA_VERSION,
    _stored_stream_version,
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

def retype_sequence_as_text(path: Path) -> None:
    """Rebuild `events` with `sequence` declared TEXT, then store the text `'x'` in one row.

    `sequence INTEGER PRIMARY KEY` is the rowid alias `append` writes through, so a table
    rebuilt by hand is the only place such a value can live. The indexes and triggers the
    drop takes with it are rebuilt from the DDL sqlite_master recorded, so the table is the
    only schema object that differs.
    """

    with closing(raw_connection(path)) as connection:
        table = recorded_sql(connection, "events")
        dependents = [
            recorded_sql(connection, name)
            for name in (
                "events_stream_sequence_idx",
                "events_type_sequence_idx",
                "events_reject_update",
                "events_reject_delete",
            )
        ]
        declared = "sequence INTEGER PRIMARY KEY AUTOINCREMENT"
        rebuilt = table.replace("CREATE TABLE events", "CREATE TABLE events_rebuilt", 1)
        if declared not in table or rebuilt == table:
            raise AssertionError("the recorded events DDL no longer has the expected shape")
        connection.execute(rebuilt.replace(declared, "sequence TEXT PRIMARY KEY"))
        connection.execute("INSERT INTO events_rebuilt SELECT * FROM events")
        connection.execute("DROP TABLE events")
        connection.execute("ALTER TABLE events_rebuilt RENAME TO events")
        connection.execute("UPDATE events SET sequence = 'x' WHERE sequence = '1'")
        for statement in dependents:
            connection.execute(statement)


#: The columns `append` writes, in the order the events DDL declares them.
EVENT_COLUMNS = (
    "sequence",
    "event_id",
    "stream_id",
    "stream_version",
    "event_type",
    "event_version",
    "occurred_at",
    "recorded_at",
    "payload_json",
    "metadata_json",
    "payload_sha256",
)


def rebuild_events_table(path: Path, columns: Sequence[str]) -> None:
    """Rebuild `events` from the given result columns, keeping its rows.

    Each entry is a column of the old table, renamed with `AS` where a test needs it. The
    drop takes the table's indexes and triggers with it and they are not rebuilt, since an
    index on a column left out could not be.
    """

    with closing(raw_connection(path)) as connection:
        listed = ", ".join(columns)
        connection.execute(f"CREATE TABLE events_rebuilt AS SELECT {listed} FROM events")
        connection.execute("DROP TABLE events")
        connection.execute("ALTER TABLE events_rebuilt RENAME TO events")


#: The schema fault a hand-built migration table carries, whatever columns it has.
MIGRATION_TABLE_ALTERED = (
    "schema_object_altered",
    "table complyroll_schema_migrations does not match its expected definition",
)


def replace_migration_table(
    path: Path,
    columns: str,
    rows: Sequence[Sequence[object]],
    *,
    marker: int | None = None,
) -> None:
    """Replace the migration table with one declaring ``columns`` and holding ``rows``.

    ``marker`` also sets `user_version`, which decides the records `store verify` expects.
    """

    with closing(raw_connection(path)) as connection:
        connection.execute("DROP TABLE complyroll_schema_migrations")
        connection.execute(f"CREATE TABLE complyroll_schema_migrations ({columns})")
        for row in rows:
            listed = ", ".join("?" for _ in row)
            connection.execute(
                f"INSERT INTO complyroll_schema_migrations VALUES ({listed})", tuple(row)
            )
        if marker is not None:
            connection.execute(f"PRAGMA user_version = {marker}")


def add_counter_row(path: Path, value: object) -> None:
    """Add a second `sqlite_sequence` row for `events`; the table has no key to refuse it."""

    with closing(raw_connection(path)) as connection:
        connection.execute("INSERT INTO sqlite_sequence (name, seq) VALUES ('events', ?)", (value,))


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

    def insert_low_rows(self, path: Path) -> None:
        """Insert well-formed rows at sequences -1 and 0, on a stream of their own."""

        with closing(raw_connection(path)) as connection:
            for version, sequence in enumerate((-1, 0), start=1):
                insert_event_row(
                    connection,
                    sequence=sequence,
                    event_id=f"evt-low-{version}",
                    stream_id="case/case-low",
                    stream_version=version,
                )

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

    def test_rows_numbered_below_one_are_walked_and_reported(self) -> None:
        """`append` numbers from 1; on 298f1be the walk started above 0 and passed this file."""

        self.insert_low_rows(self.database_path)

        report = self.verify(self.database_path)

        self.assertFalse(report.ok)
        self.assertEqual(
            [(fault.code, fault.sequence, fault.message) for fault in report.faults],
            [
                ("sequence_gap", -1, "event history holds sequence -1; sequences start at 1"),
                ("sequence_gap", 0, "event history holds sequence 0; sequences start at 1"),
            ],
        )
        self.assertEqual(report.checked_events, self.EVENT_COUNT + 2)

    def test_a_row_at_the_lowest_sqlite_integer_is_walked_and_reported(self) -> None:
        """A walk bounded one below the lowest row would overflow SQLite's integer here."""

        lowest = -(2**63)
        with closing(raw_connection(self.database_path)) as connection:
            insert_event_row(
                connection,
                sequence=lowest,
                event_id="evt-lowest",
                stream_id="case/case-lowest",
                stream_version=1,
            )

        report = self.verify(self.database_path)

        self.assertEqual(
            [(fault.code, fault.sequence, fault.message) for fault in report.faults],
            [
                (
                    "sequence_gap",
                    lowest,
                    f"event history holds sequence {lowest}; sequences start at 1",
                ),
            ],
        )
        self.assertEqual(report.checked_events, self.EVENT_COUNT + 1)

    def test_a_text_sequence_reports_the_table_and_walks_nothing(self) -> None:
        """On 298f1be the counter check passed the text to int(), which raised ValueError."""

        retype_sequence_as_text(self.database_path)

        report = self.verify(self.database_path)

        self.assertEqual(
            [(fault.code, fault.message) for fault in report.faults],
            [("schema_object_altered", "table events does not match its expected definition")],
        )
        self.assertEqual(report.checked_events, 0)

    def test_an_events_table_missing_a_column_reports_the_table_and_walks_nothing(self) -> None:
        """On 298f1be the walk ended in IndexError on a column it reads, or a store error."""

        altered = ("schema_object_altered", "table events does not match its expected definition")
        for column in EVENT_COLUMNS:
            with self.subTest(column=column):
                path = self.populate(f"without-{column}.db")
                rebuild_events_table(path, [name for name in EVENT_COLUMNS if name != column])

                report = self.verify(path)

                self.assertIn(altered, [(fault.code, fault.message) for fault in report.faults])
                row_faults = [fault for fault in report.faults if fault.sequence is not None]
                self.assertEqual(row_faults, [])
                self.assertEqual(report.checked_events, 0)

    def test_a_column_renamed_only_in_case_is_still_walked(self) -> None:
        """`sqlite3.Row` matches a name without regard to ASCII case, so the walk reads it."""

        rebuild_events_table(
            self.database_path,
            ["event_id AS EVENT_ID" if name == "event_id" else name for name in EVENT_COLUMNS],
        )

        report = self.verify(self.database_path)

        self.assertIn(
            ("schema_object_altered", "table events does not match its expected definition"),
            [(fault.code, fault.message) for fault in report.faults],
        )
        self.assertEqual(report.checked_events, self.EVENT_COUNT)

    def test_a_migration_table_missing_its_version_column_reports_the_table(self) -> None:
        """On 298f1be the query for `version` ended verify in a store error."""

        shapes = (
            ("the other columns kept", "description TEXT, applied_at TEXT", ("first", "x")),
            ("one unrelated column", "wrong INTEGER", (SCHEMA_VERSION,)),
        )
        for index, (label, columns, row) in enumerate(shapes):
            with self.subTest(shape=label):
                path = self.populate(f"migration-columns-{index}.db")
                replace_migration_table(path, columns, [row])

                report = self.verify(path)

                self.assertEqual(
                    [(fault.code, fault.message) for fault in report.faults],
                    [MIGRATION_TABLE_ALTERED],
                )
                self.assertEqual(report.checked_events, self.EVENT_COUNT)

    def test_a_migration_version_that_is_not_an_integer_is_not_a_record(self) -> None:
        """On 298f1be `'1x'` at schema 2 fell between the bounds as text and failed int().

        A `TEXT` column turns the integer 2 into text as well, so neither record counts.
        """

        for index, stored in enumerate(("1x", "1.5", "1")):
            with self.subTest(stored=stored):
                path = self.populate(f"migration-version-{index}.db")
                replace_migration_table(
                    path,
                    "version TEXT, description TEXT, applied_at TEXT",
                    [(stored, "first", "2026-08-20T12:00:00Z"), (2, "second", "x")],
                    marker=2,
                )

                report = self.verify(path)

                self.assertEqual(
                    [(fault.code, fault.message) for fault in report.faults],
                    [
                        MIGRATION_TABLE_ALTERED,
                        ("migration_missing", "database is missing migration record 1"),
                        ("migration_missing", "database is missing migration record 2"),
                    ],
                )
                self.assertEqual(report.checked_events, self.EVENT_COUNT)

    def test_a_migration_column_renamed_only_in_case_is_still_read(self) -> None:
        """SQLite matches `VERSION` to `version`, so record 1 still counts and 2 is missing."""

        replace_migration_table(
            self.database_path,
            "VERSION INTEGER, description TEXT, applied_at TEXT",
            [(SCHEMA_VERSION, "first", "2026-08-20T12:00:00Z")],
            marker=2,
        )

        report = self.verify(self.database_path)

        self.assertEqual(
            [(fault.code, fault.message) for fault in report.faults],
            [
                MIGRATION_TABLE_ALTERED,
                ("migration_missing", "database is missing migration record 2"),
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
            ("rows below sequence 1", self.insert_low_rows),
            ("text sequence", retype_sequence_as_text),
            ("sequence column alone", lambda path: rebuild_events_table(path, ["sequence"])),
            (
                "migration table without version",
                lambda path: replace_migration_table(path, "wrong INTEGER", [(1,)]),
            ),
            (
                "text migration version at schema 2",
                lambda path: replace_migration_table(path, "version TEXT", [("1x",)], marker=2),
            ),
            ("second counter row", lambda path: add_counter_row(path, "x")),
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
            (
                "rows below sequence 1",
                self.insert_low_rows,
                EventIntegrityError,
                f"event history holds {self.EVENT_COUNT + 2} event(s) but its sequences run "
                f"from -1 to {self.EVENT_COUNT}",
            ),
            (
                "text sequence",
                retype_sequence_as_text,
                UnsupportedSchemaError,
                "database schema objects do not match their expected definitions: table events",
            ),
            (
                "second counter row",
                lambda path: add_counter_row(path, "x"),
                EventIntegrityError,
                "the events sequence counter is stored in more than one row",
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



class StoredValueRefusalTests(unittest.TestCase):
    """H3: a stored value no append writes is refused with a coded, bounded error.

    Append runs `_require_name` on every name and writes integer versions, so each row below
    is planted with raw SQL, as an edit in place would be. The constructor or the reader
    refuses it with `EventIntegrityError`, `verify_history` reports it as a fault, and no
    message is longer than MESSAGE_BOUND bytes however long the planted value is.
    """

    MESSAGE_BOUND = 1024
    LONG = 5000

    def setUp(self) -> None:
        # The J cases are sized against the default digit limit, not whatever
        # PYTHONINTMAXSTRDIGITS set for this process.
        self.addCleanup(sys.set_int_max_str_digits, sys.get_int_max_str_digits())
        sys.set_int_max_str_digits(sys.int_info.default_max_str_digits)
        self.temporary_directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary_directory.cleanup)
        self.database_path = self.build()

    def build(self, name: str = "complyroll.db") -> Path:
        path = Path(self.temporary_directory.name) / name
        store = SQLiteEventStore(path, clock=lambda: RECORDED_AT)
        for index in range(3):
            store.append("stream-h", [sample_event(f"evt-h-{index}")], expected_version=index)
        store.close()
        return path

    @staticmethod
    def digest(text: str) -> str:
        return hashlib.sha256(text.encode("utf-8")).hexdigest()

    def insert(self, *, ignore_checks: bool = False, **overrides: object) -> None:
        """INSERT one row after the last; no trigger guards INSERT.

        `ignore_checks` turns on `PRAGMA ignore_check_constraints` for the connection, which
        stores a version below 1 without rebuilding the table.
        """

        values: dict[str, object] = {
            "event_id": "evt-planted",
            "stream_id": "stream-planted",
            "stream_version": 1,
            "event_type": "case.created",
            "event_version": 1,
            "occurred_at": RECORDED_TEXT,
            "recorded_at": RECORDED_TEXT,
            "payload_json": "{}",
            "metadata_json": "{}",
            "payload_sha256": self.digest("{}"),
        }
        values.update(overrides)
        columns = ", ".join(values)
        marks = ", ".join("?" for _ in values)
        with closing(raw_connection(self.database_path)) as connection:
            if ignore_checks:
                connection.execute("PRAGMA ignore_check_constraints = ON")
            connection.execute(
                f"INSERT INTO events ({columns}) VALUES ({marks})", tuple(values.values())
            )

    def update(self, statement: str, parameters: tuple[object, ...]) -> None:
        """Run one UPDATE with only `events_reject_update` dropped, then rebuild it."""

        with closing(raw_connection(self.database_path)) as connection:
            restore = recorded_sql(connection, "events_reject_update")
            connection.execute("DROP TRIGGER events_reject_update")
            connection.execute(statement, parameters)
            connection.execute(restore)

    def refusal(self) -> EventIntegrityError:
        """Open the store and read it all, and return the refusal wherever it was raised."""

        with self.assertRaises(EventIntegrityError) as caught:
            store = SQLiteEventStore(self.database_path)
            try:
                store.read_all()
            finally:
                store.close()
        self.assertLessEqual(len(str(caught.exception).encode()), self.MESSAGE_BOUND)
        return caught.exception

    def faults(self) -> dict[str, str]:
        store = SQLiteEventStore.open_for_verification(self.database_path)
        self.addCleanup(store.close)
        report = store.verify_history()
        self.assertFalse(report.ok)
        for fault in report.faults:
            self.assertLessEqual(len(fault.message.encode()), self.MESSAGE_BOUND, fault.code)
        return {fault.code: fault.message for fault in report.faults}

    def big_object(self, digits: int) -> str:
        return '{"n":' + "1" * digits + "}"

    @staticmethod
    def many_values(count: int) -> str:
        """Return a canonical object holding `count` JSON values.

        The cap counts every value the walk visits: the object, its list, and each element.
        Keys are not values, so `{"a": [0] * (count - 2)}` holds exactly `count`.
        """

        return json.dumps({"a": [0] * (count - 2)}, separators=(",", ":"))

    @staticmethod
    def wide_object(size: int) -> str:
        """Return a canonical object of exactly `size` UTF-8 bytes: one ASCII string member."""

        return '{"a":"' + "x" * (size - 8) + '"}'

    def plant_json(self, column: str, text: str) -> None:
        """Replace one JSON column at sequence 2, recomputing the digest for a payload."""

        if column == "payload":
            self.update(
                "UPDATE events SET payload_json = ?, payload_sha256 = ? WHERE sequence = 2",
                (text, self.digest(text)),
            )
        else:
            self.update("UPDATE events SET metadata_json = ? WHERE sequence = 2", (text,))

    def open_then_insert(self, **overrides: object) -> SQLiteEventStore:
        """Open the store, then plant one row through a second connection.

        The open-time checks have passed by then, so only the append-time reads stand
        between the planted row and a conversion, as with a writer outside the store.
        """

        store = SQLiteEventStore(self.database_path, clock=lambda: RECORDED_AT)
        self.addCleanup(store.close)
        self.insert(**overrides)
        return store

    # h3-v2: the names.

    def test_an_unreadable_name_is_refused_without_echoing_it(self) -> None:
        cases = (
            ("event_id", "UPDATE events SET event_id = ? WHERE sequence = 2", "e" * 501, 2),
            ("event_type", "UPDATE events SET event_type = ? WHERE sequence = 2", "t" * 501, 2),
            ("stream_id", "UPDATE events SET stream_id = ?", "s" * 501, 1),
            ("stream_id", "UPDATE events SET stream_id = ?", "s" * 498 + " s", 1),
        )
        for index, (column, statement, value, sequence) in enumerate(cases):
            with self.subTest(column=column, length=len(value)):
                self.database_path = self.build(f"name-{index}.db")
                self.update(statement, (value,))
                refused = self.refusal()
                self.assertEqual(refused.sequence, sequence)
                self.assertIn(f"has an unreadable {column}", str(refused))
                self.assertNotIn(value, str(refused))
                faults = self.faults()
                self.assertIn("event_name_invalid", faults)
                self.assertNotIn(value, faults["event_name_invalid"])
                if column != "stream_id":
                    with SQLiteEventStore(self.database_path) as store:
                        with self.assertRaises(EventIntegrityError):
                            store.read_stream("stream-h")

    def test_a_name_at_the_cap_reads_back(self) -> None:
        with SQLiteEventStore(self.database_path, clock=lambda: RECORDED_AT) as store:
            store.append("s" * 500, [sample_event("evt-cap")], expected_version=0)
        with SQLiteEventStore(self.database_path) as store:
            self.assertEqual(store.read_all()[-1].stream_id, "s" * 500)

    def test_a_short_invalid_name_is_refused_with_the_rule_it_breaks(self) -> None:
        """The primary refusal names the grammar rule, never the value, its length or class."""

        self.update("UPDATE events SET event_type = ? WHERE sequence = 2", ("bad!",))
        refused = self.refusal()
        self.assertEqual(refused.sequence, 2)
        self.assertEqual(
            str(refused),
            "event at sequence 2 has an unreadable event_type: event_type contains unsupported "
            "characters or is too long",
        )
        self.assertEqual(
            self.faults()["event_name_invalid"],
            "event has an unreadable event_type: event_type contains unsupported characters "
            "or is too long",
        )

    def test_a_blob_event_type_is_refused_rather_than_coerced(self) -> None:
        self.insert(event_type=b"case.created")
        self.assertIn("has an unreadable event_type", str(self.refusal()))
        self.assertIn("event_name_invalid", self.faults())

    # J: integer literals and nesting in stored JSON.

    def test_j1_a_payload_integer_past_the_digit_limit_is_refused(self) -> None:
        text = self.big_object(self.LONG)
        self.update(
            "UPDATE events SET payload_json = ?, payload_sha256 = ? WHERE sequence = 2",
            (text, self.digest(text)),
        )
        refused = self.refusal()
        self.assertEqual(refused.sequence, 2)
        self.assertIn("contains JSON past the decoder's limits", str(refused))
        self.assertIn("payload_not_json", self.faults())

    def test_j2_a_metadata_integer_past_the_digit_limit_is_refused(self) -> None:
        text = self.big_object(self.LONG)
        for how in ("update", "insert"):
            with self.subTest(how=how):
                self.database_path = self.build(f"j2-{how}.db")
                if how == "update":
                    self.update("UPDATE events SET metadata_json = ? WHERE sequence = 1", (text,))
                else:
                    self.insert(metadata_json=text)
                refused = self.refusal()
                self.assertEqual(refused.sequence, 1 if how == "update" else 4)
                self.assertIn("contains JSON past the decoder's limits", str(refused))
                self.assertIn("payload_not_json", self.faults())

    def test_j2_a_metadata_integer_at_the_digit_limit_still_reads(self) -> None:
        self.insert(metadata_json=self.big_object(4300))
        with SQLiteEventStore(self.database_path) as store:
            self.assertEqual(len(store.read_all()), 4)
        store = SQLiteEventStore.open_for_verification(self.database_path)
        self.addCleanup(store.close)
        self.assertTrue(store.verify_history().ok)

    def test_j3_metadata_nested_past_the_recursion_limit_is_refused(self) -> None:
        self.insert(metadata_json='{"n":' + "[" * 200_000 + "]" * 200_000 + "}")
        self.assertIn("contains JSON past the decoder's limits", str(self.refusal()))
        self.assertIn("payload_not_json", self.faults())

    # S and D: append's JSON rules, which the decoder alone does not apply.

    def test_s_a_lone_surrogate_escape_is_refused(self) -> None:
        text = '{"t":"\\ud800"}'
        for column in ("payload", "metadata"):
            with self.subTest(column=column):
                self.database_path = self.build(f"s-{column}.db")
                self.update(f"UPDATE events SET {column}_json = ? WHERE sequence = 2", (text,))
                if column == "payload":
                    self.update(
                        "UPDATE events SET payload_sha256 = ? WHERE sequence = 2",
                        (self.digest(text),),
                    )
                refused = self.refusal()
                self.assertEqual(refused.sequence, 2)
                self.assertIn(f"{column} contains text that is not valid Unicode", str(refused))
                self.assertIn("payload_not_json", self.faults())

    def test_s_nan_or_infinity_in_either_column_is_refused(self) -> None:
        for column in ("payload", "metadata"):
            for literal in ("NaN", "Infinity", "-Infinity"):
                with self.subTest(column=column, literal=literal):
                    self.database_path = self.build(f"s-{column}-{literal}.db")
                    self.plant_json(column, '{"n":' + literal + "}")
                    refused = self.refusal()
                    self.assertEqual(refused.sequence, 2)
                    reason = f"{column} cannot contain NaN or infinity"
                    self.assertIn(reason, str(refused))
                    self.assertIn(reason, self.faults()["payload_not_json"])

    # C: append's value-count and byte caps, one value or byte either side, in each column.

    def test_c_json_at_the_value_and_byte_caps_still_reads(self) -> None:
        cases = (
            ("values", self.many_values(MAX_EVENT_JSON_VALUES)),
            ("bytes", self.wide_object(MAX_EVENT_JSON_BYTES)),
        )
        self.assertEqual(len(cases[1][1].encode("utf-8")), 1_048_576)
        for column in ("payload", "metadata"):
            for cap, text in cases:
                with self.subTest(column=column, cap=cap):
                    self.database_path = self.build(f"c-{column}-{cap}-at.db")
                    self.plant_json(column, text)
                    with SQLiteEventStore(self.database_path) as store:
                        self.assertEqual(len(store.read_all()), 3)
                    with SQLiteEventStore.open_for_verification(self.database_path) as store:
                        self.assertTrue(store.verify_history().ok)

    def test_c_json_one_past_the_value_or_byte_cap_is_refused(self) -> None:
        cases = (
            ("values", self.many_values(MAX_EVENT_JSON_VALUES + 1), "exceeds the JSON value limit"),
            (
                "bytes",
                self.wide_object(MAX_EVENT_JSON_BYTES + 1),
                f"exceeds the {MAX_EVENT_JSON_BYTES}-byte limit",
            ),
        )
        self.assertEqual(len(cases[1][1].encode("utf-8")), 1_048_577)
        for column in ("payload", "metadata"):
            for cap, text, reason in cases:
                with self.subTest(column=column, cap=cap):
                    self.database_path = self.build(f"c-{column}-{cap}-past.db")
                    self.plant_json(column, text)
                    refused = self.refusal()
                    self.assertEqual(refused.sequence, 2)
                    self.assertEqual(str(refused), f"event 'evt-h-1' {column} {reason}")
                    self.assertEqual(
                        self.faults()["payload_not_json"], f"event 'evt-h-1' {column} {reason}"
                    )

    def test_c_json_padded_past_the_byte_cap_is_refused_though_its_value_fits(self) -> None:
        """The byte cap applies to the stored text, not only to the value it decodes to.

        Whitespace `append` never writes pads each text, so its value encodes again well under
        the cap. The multibyte text is under the cap in characters and over it in bytes.
        """

        multibyte = '{"s":"' + "\u00e9" * 1000 + '"}'
        cases = (
            ("at the cap", " " * (MAX_EVENT_JSON_BYTES - 2) + "{}", True),
            ("one past", " " * (MAX_EVENT_JSON_BYTES - 1) + "{}", False),
            ("bytes past", multibyte + " " * (MAX_EVENT_JSON_BYTES - 2007), False),
        )
        self.assertEqual(len(cases[2][1]), MAX_EVENT_JSON_BYTES - 999)
        self.assertEqual(len(cases[2][1].encode("utf-8")), MAX_EVENT_JSON_BYTES + 1)
        for column in ("payload", "metadata"):
            for index, (label, text, reads) in enumerate(cases):
                with self.subTest(column=column, case=label):
                    self.database_path = self.build(f"c-{column}-padded-{index}.db")
                    self.plant_json(column, text)
                    if reads:
                        with SQLiteEventStore(self.database_path) as store:
                            self.assertEqual(len(store.read_all()), 3)
                        with SQLiteEventStore.open_for_verification(self.database_path) as store:
                            self.assertTrue(store.verify_history().ok)
                        continue
                    expected = (
                        f"event 'evt-h-1' {column} exceeds the {MAX_EVENT_JSON_BYTES}-byte limit"
                    )
                    refused = self.refusal()
                    self.assertEqual(refused.sequence, 2)
                    self.assertEqual(str(refused), expected)
                    self.assertEqual(self.faults()["payload_not_json"], expected)

    def test_d_json_past_the_append_depth_is_refused_on_every_interpreter(self) -> None:
        for depth in (65, 5000):
            with self.subTest(depth=depth):
                self.database_path = self.build(f"d-{depth}.db")
                self.insert(metadata_json='{"n":' + "[" * depth + "]" * depth + "}")
                refused = self.refusal()
                self.assertEqual(refused.sequence, 4)
                if depth == 65:
                    self.assertIn("metadata exceeds the JSON depth limit", str(refused))
                self.assertIn("payload_not_json", self.faults())

    def test_d_json_at_the_append_depth_still_reads(self) -> None:
        self.insert(metadata_json='{"n":' + "[" * 64 + "]" * 64 + "}")
        with SQLiteEventStore(self.database_path) as store:
            self.assertEqual(len(store.read_all()), 4)
        store = SQLiteEventStore.open_for_verification(self.database_path)
        self.addCleanup(store.close)
        self.assertTrue(store.verify_history().ok)

    # V and E: the integer columns.

    def test_v1_a_text_stream_version_is_refused_at_open(self) -> None:
        self.insert(stream_version="x")
        refused = self.refusal()
        self.assertEqual(refused.sequence, 4)
        self.assertIn("has stream_version stored as text, not an integer", str(refused))
        self.assertIn("event_version_invalid", self.faults())

    def test_v2_an_overlong_numeric_stream_version_is_refused_at_open(self) -> None:
        self.insert(stream_version="1" * self.LONG)
        refused = self.refusal()
        self.assertEqual(refused.sequence, 4)
        self.assertIn("has stream_version stored as real, not an integer", str(refused))
        self.assertIn("event_version_invalid", self.faults())

    # The aggregate reads. Open and append check stream_version with MIN and MAX in raw SQL,
    # not row by row, and SQLite sorts text above every integer. A text version on a stream
    # that already holds integers is the MAX while the MIN stays 1, and a stream holding only
    # text has a text MIN. On 298f1be each read below ended in an uncoded `ValueError`.

    def test_v3_a_text_version_atop_an_integer_stream_is_refused_at_open(self) -> None:
        self.update("UPDATE events SET stream_version = ? WHERE sequence = 3", ("x",))
        refused = self.refusal()
        self.assertEqual(refused.sequence, 3)
        self.assertIn("has stream_version stored as text, not an integer", str(refused))

    def test_v4_a_text_version_planted_after_open_is_refused_by_append(self) -> None:
        store = self.open_then_insert(stream_id="stream-h", stream_version="x")
        with self.assertRaises(EventIntegrityError) as caught:
            store.append("stream-h", [sample_event("evt-h-3")], expected_version=3)
        self.assertEqual(caught.exception.sequence, 4)
        self.assertIn("has stream_version stored as text, not an integer", str(caught.exception))

    def test_v5_a_text_version_planted_after_open_is_refused_by_the_version_read(self) -> None:
        store = self.open_then_insert(stream_id="stream-h", stream_version="x")
        with self.assertRaises(EventIntegrityError) as caught:
            store.current_stream_version("stream-h")
        self.assertEqual(caught.exception.sequence, 4)
        self.assertIn("has stream_version stored as text, not an integer", str(caught.exception))

    def test_v6_a_stream_of_only_text_versions_is_refused_by_append(self) -> None:
        store = self.open_then_insert(stream_id="stream-t", stream_version="x")
        with self.assertRaises(EventIntegrityError) as caught:
            store.append("stream-t", [sample_event("evt-t-2")], expected_version=1)
        self.assertEqual(caught.exception.sequence, 4)
        self.assertIn("has stream_version stored as text, not an integer", str(caught.exception))

    def test_v7_verify_reports_a_text_version_mid_stream_without_raising(self) -> None:
        """The walk leaves the text row out of the count, so the next row reads as a gap."""

        self.update("UPDATE events SET stream_version = ? WHERE sequence = 2", ("x",))
        faults = self.faults()
        self.assertIn("has stream_version stored as text", faults["event_version_invalid"])
        self.assertIn(
            "is missing version 2; next stored version is 3", faults["stream_version_gap"]
        )

    def test_v8_a_real_version_past_a_gap_is_named_as_real(self) -> None:
        """Versions 1, 2.5, 4: the gap message would read 2.5 as 2 and blame a missing 1."""

        self.update("UPDATE events SET stream_version = ? WHERE sequence = 3", (4,))
        self.update("UPDATE events SET stream_version = ? WHERE sequence = 2", (2.5,))
        refused = self.refusal()
        self.assertEqual(refused.sequence, 2)
        self.assertIn("has stream_version stored as real, not an integer", str(refused))
        self.assertNotIn("missing version", str(refused))

    def test_v9_an_aggregate_no_row_explains_is_refused_without_a_sequence(self) -> None:
        """MIN and MAX return a stored value, so this fallback is defensive: it names the stream."""

        with closing(raw_connection(self.database_path)) as connection:
            with self.assertRaises(EventIntegrityError) as caught:
                _stored_stream_version(connection, "stream-h", "x")
        self.assertIsNone(caught.exception.sequence)
        self.assertEqual(
            str(caught.exception),
            "stream 'stream-h' reports a stream_version stored as text, not an integer",
        )

    def test_e1_a_text_event_version_is_refused_on_read(self) -> None:
        self.insert(event_version="x")
        refused = self.refusal()
        self.assertEqual(refused.sequence, 4)
        self.assertIn("has event_version stored as text, not an integer", str(refused))
        self.assertIn("event_version_invalid", self.faults())

    def test_e2_an_event_version_below_one_is_refused_on_read(self) -> None:
        """The table's CHECK skipped; on 298f1be every read took the row as valid."""

        for value in (0, -1):
            with self.subTest(event_version=value):
                self.database_path = self.build(f"e2-{value}.db")
                self.insert(event_version=value, ignore_checks=True)
                refused = self.refusal()
                self.assertEqual(refused.sequence, 4)
                self.assertEqual(
                    str(refused),
                    f"event at sequence 4 has event_version {value}; versions start at 1",
                )
                self.assertEqual(
                    self.faults()["event_version_invalid"],
                    f"event has event_version {value}; versions start at 1",
                )

    def test_v10_a_stream_version_below_one_is_refused_and_left_out_of_the_walk(self) -> None:
        """On 298f1be verify reported this row only as a gap before version 0."""

        self.insert(stream_version=0, ignore_checks=True)
        refused = self.refusal()
        self.assertIsNone(refused.sequence)
        self.assertEqual(
            str(refused),
            "stream 'stream-planted' holds 1 event(s) but its versions run from 0 to 0",
        )
        faults = self.faults()
        self.assertEqual(
            faults["event_version_invalid"], "event has stream_version 0; versions start at 1"
        )
        self.assertNotIn("stream_version_gap", faults)

    # N: the echo, read before the name check could run.

    def test_n1_a_long_event_id_with_a_bad_digest_is_not_echoed(self) -> None:
        self.insert(event_id="e" * self.LONG, payload_sha256="0" * 64)
        refused = self.refusal()
        self.assertIn("has an unreadable event_id", str(refused))
        faults = self.faults()
        self.assertIn("event_name_invalid", faults)
        self.assertIn(
            f"<{self.LONG} characters outside the name grammar>",
            faults["payload_digest_mismatch"],
        )

    def test_n2_a_long_stream_id_at_version_two_is_not_echoed(self) -> None:
        stream_id = "stream-" + "x" * self.LONG
        self.insert(stream_id=stream_id, stream_version=2)
        refused = self.refusal()
        self.assertEqual(refused.sequence, 4)
        shown = f"<{len(stream_id)} characters outside the name grammar>"
        self.assertIn(f"stream {shown} is missing version 1", str(refused))
        faults = self.faults()
        self.assertIn("event_name_invalid", faults)
        self.assertIn(shown, faults["stream_version_gap"])

    def test_n3_a_blob_stream_id_is_described_by_its_storage_class(self) -> None:
        """Open and `verify_history` both say `<blob value>`; neither echoes the bytes.

        The verify walk keys streams by `str()`, which turns a blob into its repr; the gap
        message has to describe the stored value, not that key.
        """

        self.insert(stream_id=b"b" * self.LONG, stream_version=2)
        refused = self.refusal()
        self.assertEqual(refused.sequence, 4)
        self.assertIn("stream <blob value> is missing version 1", str(refused))
        self.assertNotIn("bbbb", str(refused))
        faults = self.faults()
        self.assertIn("event_name_invalid", faults)
        self.assertIn("stream <blob value> is missing version 1", faults["stream_version_gap"])
        self.assertNotIn("bbbb", faults["stream_version_gap"])

    # Q: the AUTOINCREMENT counter, which has no declared type.

    def test_q_a_counter_stored_as_text_is_refused(self) -> None:
        for index, value in enumerate(("x", "1" * self.LONG)):
            with self.subTest(length=len(value)):
                self.database_path = self.build(f"q-{index}.db")
                with closing(raw_connection(self.database_path)) as connection:
                    connection.execute(
                        "UPDATE sqlite_sequence SET seq = ? WHERE name = 'events'", (value,)
                    )
                refused = self.refusal()
                self.assertIn("sequence counter is stored as text", str(refused))
                self.assertIn("sequence_counter_mismatch", self.faults())

    def test_q_a_counter_of_any_other_storage_class_is_refused(self) -> None:
        """Only an integer is a counter, even one that converts to the latest sequence.

        REAL 3.0, TEXT '3' and BLOB b'3' each convert to 3, the last stored sequence, so a
        check that converted first, as 298f1be's `int()` did, would accept all three.
        """

        cases = (("real", 1.5), ("real", 3.0), ("blob", b"3"), ("text", "3"))
        for index, (storage_class, value) in enumerate(cases):
            with self.subTest(value=value):
                self.database_path = self.build(f"q-class-{index}.db")
                with closing(raw_connection(self.database_path)) as connection:
                    connection.execute(
                        "UPDATE sqlite_sequence SET seq = ? WHERE name = 'events'", (value,)
                    )
                    stored = connection.execute(
                        "SELECT typeof(seq) FROM sqlite_sequence WHERE name = 'events'"
                    ).fetchone()
                self.assertEqual(stored, (storage_class,))
                expected = (
                    f"the events sequence counter is stored as {storage_class}, not an integer"
                )
                refused = self.refusal()
                self.assertEqual(refused.sequence, 3)
                self.assertEqual(str(refused), expected)
                self.assertEqual(self.faults()["sequence_counter_mismatch"], expected)

    def test_q_a_second_counter_row_is_refused_whatever_either_row_holds(self) -> None:
        """A check that read one of two rows would pass whatever the other held.

        On 298f1be a text row after SQLite's own passed every check, and two rows that both
        hold the last sequence are no more a counter append keeps than one of each.
        """

        cases = (
            ("text after the integer", None, "x"),
            ("integer after text", "x", 3),
            ("the last sequence twice", None, 3),
        )
        expected = "the events sequence counter is stored in more than one row"
        for index, (label, first, second) in enumerate(cases):
            with self.subTest(case=label):
                self.database_path = self.build(f"q-rows-{index}.db")
                if first is not None:
                    self.update(
                        "UPDATE sqlite_sequence SET seq = ? WHERE name = 'events'", (first,)
                    )
                add_counter_row(self.database_path, second)
                refused = self.refusal()
                self.assertEqual(refused.sequence, 3)
                self.assertEqual(str(refused), expected)
                self.assertEqual(self.faults()["sequence_counter_mismatch"], expected)

    def test_q_a_second_counter_row_added_after_the_open_stops_the_append(self) -> None:
        store = SQLiteEventStore(self.database_path, clock=lambda: RECORDED_AT)
        self.addCleanup(store.close)
        add_counter_row(self.database_path, "x")

        with self.assertRaises(EventIntegrityError) as caught:
            store.append("stream-h", [sample_event("evt-h-3")], expected_version=3)

        self.assertEqual(
            str(caught.exception), "the events sequence counter is stored in more than one row"
        )


class StoreHeaderTests(unittest.TestCase):
    """H3: a header edited out of band is refused by the open and reported by verify.

    `user_version` and `application_id` are SQLite header integers no append writes outside
    the open and `_mark_schema`. On 298f1be a marker of -1 opened, verified clean, and ended
    the next append in `KeyError: 0`; a marker of 0 or 3, or a foreign application id,
    verified clean while every command refused the store.
    """

    def setUp(self) -> None:
        self.temporary_directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary_directory.cleanup)

    def build(self, name: str, *, requires_schema: int = SCHEMA_VERSION) -> Path:
        """Write three events; at schema 2 the last one marks the store and records 2."""

        path = Path(self.temporary_directory.name) / name
        store = SQLiteEventStore(path, clock=lambda: RECORDED_AT)
        for index in range(3):
            store.append(
                "stream-h",
                [sample_event(f"evt-h-{index}")],
                expected_version=index,
                requires_schema=requires_schema if index == 2 else SCHEMA_VERSION,
            )
        store.close()
        return path

    @staticmethod
    def set_header(path: Path, pragma: str, value: int) -> None:
        with closing(raw_connection(path)) as connection:
            connection.execute(f"PRAGMA {pragma} = {value}")

    @staticmethod
    def state(path: Path) -> tuple[object, ...]:
        with closing(raw_connection(path)) as connection:
            return (
                connection.execute("PRAGMA user_version").fetchone()[0],
                connection.execute("SELECT COUNT(*), MAX(sequence) FROM events").fetchone(),
                connection.execute(
                    "SELECT version FROM complyroll_schema_migrations ORDER BY version"
                ).fetchall(),
            )

    def verify(self, path: Path) -> IntegrityReport:
        store = SQLiteEventStore.open_for_verification(path)
        self.addCleanup(store.close)
        return store.verify_history()

    def test_a_marker_below_the_supported_range_is_refused_at_open(self) -> None:
        path = self.build("below.db")
        self.set_header(path, "user_version", -1)

        with self.assertRaises(UnsupportedSchemaError) as caught:
            SQLiteEventStore(path)

        self.assertEqual(
            str(caught.exception),
            f"database schema -1 is outside supported schemas {SCHEMA_VERSION} to "
            f"{SUPPORTED_SCHEMA_VERSION}",
        )

    def test_verify_reports_a_marker_outside_the_supported_range(self) -> None:
        cases = (
            (-1, SCHEMA_VERSION),
            (0, SCHEMA_VERSION),
            (SUPPORTED_SCHEMA_VERSION + 1, SUPPORTED_SCHEMA_VERSION),
        )
        for marker, requires_schema in cases:
            with self.subTest(marker=marker):
                path = self.build(f"marker-{marker}.db", requires_schema=requires_schema)
                self.set_header(path, "user_version", marker)

                report = self.verify(path)

                self.assertFalse(report.ok)
                self.assertEqual(report.checked_events, 3)
                self.assertEqual(
                    [(fault.sequence, fault.code, fault.message) for fault in report.faults],
                    [
                        (
                            None,
                            "schema_version_unsupported",
                            f"database is marked schema {marker}; this build opens schemas "
                            f"{SCHEMA_VERSION} to {SUPPORTED_SCHEMA_VERSION}",
                        )
                    ],
                )

    def test_verify_reports_a_foreign_application_id(self) -> None:
        for application_id in (0, 1, -1):
            with self.subTest(application_id=application_id):
                path = self.build(f"application-{application_id}.db")
                self.set_header(path, "application_id", application_id)

                report = self.verify(path)

                self.assertEqual(
                    [(fault.sequence, fault.code, fault.message) for fault in report.faults],
                    [
                        (
                            None,
                            "application_id_mismatch",
                            f"database application_id is {application_id}; a ComplyRoll "
                            f"store is marked {APPLICATION_ID}",
                        )
                    ],
                )

    def test_verify_reports_the_marker_of_a_file_without_schema_objects(self) -> None:
        """A file holding nothing but a marker outside the range is refused, not initialized.

        The open initializes only an objectless file at schema 0, so verify judges the marker
        of any other objectless file and reports it after the missing objects. The file keeps
        application id 0, which only the file the open initializes may carry, so the id is
        reported after the marker.
        """

        missing = ["schema_object_missing"] * len(EXPECTED_SCHEMA_OBJECTS)
        for marker in (-1, SUPPORTED_SCHEMA_VERSION + 1):
            with self.subTest(marker=marker):
                path = Path(self.temporary_directory.name) / f"objectless-{marker}.db"
                self.set_header(path, "user_version", marker)

                report = self.verify(path)

                self.assertFalse(report.ok)
                self.assertEqual(report.checked_events, 0)
                self.assertEqual(
                    [fault.code for fault in report.faults],
                    [*missing, "schema_version_unsupported", "application_id_mismatch"],
                )
                self.assertEqual(
                    report.faults[-2].message,
                    f"database is marked schema {marker}; this build opens schemas "
                    f"{SCHEMA_VERSION} to {SUPPORTED_SCHEMA_VERSION}",
                )
                with self.assertRaises(UnsupportedSchemaError):
                    SQLiteEventStore(path)

    def test_verify_reports_the_application_id_of_a_file_without_schema_objects(self) -> None:
        """The open refuses a foreign application id whether or not the file holds objects.

        Judging the id only once objects are present let an objectless file the open refuses
        as another application's report nothing but its missing objects. The ComplyRoll id on
        an objectless file is the control: the open initializes that file, so it carries no
        header fault.
        """

        missing = [(None, "schema_object_missing")] * len(EXPECTED_SCHEMA_OBJECTS)
        foreign = (
            None,
            "application_id_mismatch",
            f"database application_id is 1; a ComplyRoll store is marked {APPLICATION_ID}",
        )
        cases = ((1, [*missing, foreign[:2]]), (APPLICATION_ID, missing))
        for application_id, expected in cases:
            with self.subTest(application_id=application_id):
                path = Path(self.temporary_directory.name) / f"objectless-{application_id}.db"
                self.set_header(path, "application_id", application_id)

                report = self.verify(path)

                self.assertEqual(report.checked_events, 0)
                self.assertEqual(
                    [(fault.sequence, fault.code) for fault in report.faults], expected
                )
                if application_id != APPLICATION_ID:
                    last = report.faults[-1]
                    self.assertEqual((last.sequence, last.code, last.message), foreign)
                    with self.assertRaises(UnsupportedSchemaError) as caught:
                        SQLiteEventStore(path)
                    self.assertEqual(
                        str(caught.exception), "database belongs to another application"
                    )

    def test_verify_reports_application_id_zero_on_a_file_that_claims_a_schema(self) -> None:
        """Application id 0 passes only on the file the open initializes.

        An objectless file marked with a supported schema is not initialized: the open holds
        it to ComplyRoll's application id and refuses it. Exempting id 0 on every objectless
        file let verify report nothing but its missing objects.
        """

        missing = [(None, "schema_object_missing")] * len(EXPECTED_SCHEMA_OBJECTS)
        foreign = (
            None,
            "application_id_mismatch",
            f"database application_id is 0; a ComplyRoll store is marked {APPLICATION_ID}",
        )
        for marker in range(SCHEMA_VERSION, SUPPORTED_SCHEMA_VERSION + 1):
            with self.subTest(marker=marker):
                path = Path(self.temporary_directory.name) / f"unowned-{marker}.db"
                self.set_header(path, "user_version", marker)

                report = self.verify(path)

                self.assertEqual(report.checked_events, 0)
                self.assertEqual(
                    [(fault.sequence, fault.code) for fault in report.faults],
                    [*missing, foreign[:2]],
                )
                last = report.faults[-1]
                self.assertEqual((last.sequence, last.code, last.message), foreign)
                with self.assertRaises(UnsupportedSchemaError) as caught:
                    SQLiteEventStore(path)
                self.assertEqual(
                    str(caught.exception),
                    "database schema is not marked as a ComplyRoll store",
                )

    def test_verify_reports_the_header_marker_before_the_migration_record(self) -> None:
        """Pin the documented fault order: header faults precede migration faults.

        A marker rewritten to 0 is held to migration record 1, so deleting that record gives
        one fault from each check and the order between them is the only thing in question.
        """

        path = self.build("header-then-migration.db")
        self.set_header(path, "user_version", 0)
        with closing(raw_connection(path)) as connection:
            connection.execute(
                "DELETE FROM complyroll_schema_migrations WHERE version = ?",
                (SCHEMA_VERSION,),
            )

        report = self.verify(path)

        self.assertEqual(report.checked_events, 3)
        self.assertEqual(
            [fault.code for fault in report.faults],
            ["schema_version_unsupported", "migration_missing"],
        )
        self.assertEqual(
            report.faults[1].message,
            f"database is missing migration record {SCHEMA_VERSION}",
        )

    def test_an_append_after_the_marker_is_rewritten_is_refused(self) -> None:
        """The open checked the marker; a second connection rewrites it afterwards."""

        path = self.build("rewritten.db")
        store = SQLiteEventStore(path, clock=lambda: RECORDED_AT)
        self.addCleanup(store.close)
        self.set_header(path, "user_version", -1)
        before = self.state(path)

        with self.assertRaises(UnsupportedSchemaError) as caught:
            store.append("stream-h", [sample_event("evt-h-3")], expected_version=3)

        self.assertIn("database schema -1 is outside supported schemas", str(caught.exception))
        self.assertFalse(store._connection.in_transaction)
        self.assertEqual(self.state(path), before)
        self.assertEqual(before, (-1, (3, 3), [(1,)]))

    def test_an_append_after_the_marker_is_rewritten_above_the_range_is_refused(self) -> None:
        """The open checked the marker; a second connection rewrites it above the range.

        On 298f1be `_mark_schema` returned early for any marker at or above the schema the
        append required, so both appends below wrote into a store marked with a schema this
        build has no migrations for.
        """

        marker = SUPPORTED_SCHEMA_VERSION + 1
        for requires_schema in (SCHEMA_VERSION, SUPPORTED_SCHEMA_VERSION):
            with self.subTest(requires_schema=requires_schema):
                path = self.build(
                    f"rewritten-above-{requires_schema}.db",
                    requires_schema=SUPPORTED_SCHEMA_VERSION,
                )
                store = SQLiteEventStore(path, clock=lambda: RECORDED_AT)
                self.addCleanup(store.close)
                self.set_header(path, "user_version", marker)
                before = self.state(path)

                with self.assertRaises(UnsupportedSchemaError) as caught:
                    store.append(
                        "stream-h",
                        [sample_event("evt-h-3")],
                        expected_version=3,
                        requires_schema=requires_schema,
                    )

                self.assertEqual(
                    str(caught.exception),
                    f"database schema {marker} is outside supported schemas {SCHEMA_VERSION} "
                    f"to {SUPPORTED_SCHEMA_VERSION}",
                )
                self.assertFalse(store._connection.in_transaction)
                self.assertEqual(self.state(path), before)
                self.assertEqual(before, (marker, (3, 3), [(1,), (2,), (3,)]))

    def test_an_append_after_the_application_id_is_rewritten_is_refused(self) -> None:
        """The open checked the application id; a second connection rewrites it afterwards.

        On 298f1be `_mark_schema` read only the marker, so each append below committed into
        a file no longer marked as a ComplyRoll store.
        """

        for application_id in (0, 12345):
            with self.subTest(application_id=application_id):
                path = self.build(f"foreign-{application_id}.db")
                store = SQLiteEventStore(path, clock=lambda: RECORDED_AT)
                self.addCleanup(store.close)
                self.set_header(path, "application_id", application_id)
                before = self.state(path)

                with self.assertRaises(UnsupportedSchemaError) as caught:
                    store.append("stream-h", [sample_event("evt-h-3")], expected_version=3)

                self.assertEqual(
                    str(caught.exception), "database schema is not marked as a ComplyRoll store"
                )
                self.assertFalse(store._connection.in_transaction)
                self.assertEqual(self.state(path), before)
                self.assertEqual(before, (SCHEMA_VERSION, (3, 3), [(1,)]))

    def test_a_store_at_the_supported_schema_still_appends_after_open(self) -> None:
        """Control for the upper bound: a marker at SUPPORTED_SCHEMA_VERSION is in range."""

        path = self.build("at-supported.db", requires_schema=SUPPORTED_SCHEMA_VERSION)
        store = SQLiteEventStore(path, clock=lambda: RECORDED_AT)
        self.addCleanup(store.close)

        for offset, requires_schema in enumerate((SCHEMA_VERSION, SUPPORTED_SCHEMA_VERSION)):
            with self.subTest(requires_schema=requires_schema):
                store.append(
                    "stream-h",
                    [sample_event(f"evt-h-at-{requires_schema}")],
                    expected_version=3 + offset,
                    requires_schema=requires_schema,
                )

        self.assertEqual(self.state(path), (SUPPORTED_SCHEMA_VERSION, (5, 5), [(1,), (2,), (3,)]))


if __name__ == "__main__":
    unittest.main()
