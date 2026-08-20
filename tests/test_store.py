from __future__ import annotations

import hashlib
import json
import sqlite3
import tempfile
import unittest
from datetime import UTC, datetime, timedelta, timezone
from pathlib import Path

from complyroll.store import (
    MAX_EVENT_JSON_BYTES,
    EventConcurrencyError,
    EventConflictError,
    EventIntegrityError,
    EventStoreError,
    NewEvent,
    ProjectionConcurrencyError,
    SQLiteEventStore,
    UnsupportedSchemaError,
)
from complyroll.store.sqlite import APPLICATION_ID


OCCURRED_AT = datetime(2026, 8, 20, 9, 30, tzinfo=timezone(timedelta(hours=-7)))
RECORDED_AT = datetime(2026, 8, 20, 16, 31, tzinfo=UTC)


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

        with sqlite3.connect(self.database_path) as connection:
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

    def test_database_triggers_reject_event_update_and_delete(self) -> None:
        store = self.open_store()
        store.append("case/case-001", [sample_event()], expected_version=0)

        with sqlite3.connect(self.database_path) as connection:
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

        with sqlite3.connect(self.database_path) as connection:
            connection.execute("DROP TRIGGER events_reject_update")
            connection.execute(
                "UPDATE events SET payload_json = '{\"case_id\":\"altered\"}' WHERE event_id = ?",
                ("evt-001",),
            )

        with self.assertRaisesRegex(EventIntegrityError, "recorded digest"):
            store.read_all()

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
        with sqlite3.connect(self.database_path) as connection:
            migration_count = connection.execute(
                "SELECT COUNT(*) FROM complyroll_schema_migrations"
            ).fetchone()[0]
        self.assertEqual(migration_count, 1)

    def test_foreign_application_database_is_rejected(self) -> None:
        with sqlite3.connect(self.database_path) as connection:
            connection.execute("PRAGMA application_id = 12345")

        with self.assertRaisesRegex(UnsupportedSchemaError, "another application"):
            SQLiteEventStore(self.database_path)

    def test_closed_store_rejects_operations(self) -> None:
        store = SQLiteEventStore(self.database_path, clock=lambda: RECORDED_AT)
        store.close()

        with self.assertRaisesRegex(EventStoreError, "closed"):
            store.read_all()


if __name__ == "__main__":
    unittest.main()
