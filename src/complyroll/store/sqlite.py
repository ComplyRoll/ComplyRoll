"""SQLite-backed append-only event history for ComplyRoll.

The event store owns persistence mechanics only. Domain models and policy code do not
import SQLite types, and disposable projections are rebuilt from the ordered event log.
"""

from __future__ import annotations

import hashlib
import json
import math
import re
import sqlite3
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from types import TracebackType
from typing import Any, Self
from uuid import uuid4


SCHEMA_VERSION = 1
APPLICATION_ID = 0x43524F4C  # ASCII "CROL"
MAX_EVENTS_PER_APPEND = 1_000
MAX_EVENT_JSON_BYTES = 1 * 1024 * 1024
MAX_EVENT_JSON_DEPTH = 64
MAX_EVENT_JSON_VALUES = 100_000
MAX_READ_BATCH = 10_000

_NAME_PATTERN = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:/-]*$")


class EventStoreError(RuntimeError):
    """Base error for event-store failures visible to callers."""


class UnsupportedSchemaError(EventStoreError):
    """Raised when a database is not a supported ComplyRoll store."""


class EventConcurrencyError(EventStoreError):
    """Raised when an append uses a stale expected stream version."""

    def __init__(self, stream_id: str, expected: int, actual: int) -> None:
        self.stream_id = stream_id
        self.expected = expected
        self.actual = actual
        super().__init__(
            f"stream {stream_id!r} expected version {expected}, but current version is {actual}"
        )


class EventConflictError(EventStoreError):
    """Raised when an event identifier or stream version is already present."""


class EventIntegrityError(EventStoreError):
    """Raised when stored event content does not match its recorded digest."""


class ProjectionConcurrencyError(EventStoreError):
    """Raised when a projection checkpoint compare-and-swap fails."""

    def __init__(self, name: str, expected: int, actual: int) -> None:
        self.name = name
        self.expected = expected
        self.actual = actual
        super().__init__(
            f"projection {name!r} expected sequence {expected}, but checkpoint is {actual}"
        )


@dataclass(frozen=True, slots=True)
class NewEvent:
    """One event to append to a stream.

    Payload and metadata must be JSON objects. They are validated and copied into
    canonical JSON at append time so later caller mutation cannot alter stored history.
    """

    event_type: str
    occurred_at: datetime
    payload: Mapping[str, Any]
    metadata: Mapping[str, Any] = field(default_factory=dict)
    event_id: str = field(default_factory=lambda: f"evt-{uuid4()}")
    event_version: int = 1

    def __post_init__(self) -> None:
        _require_name(self.event_id, "event_id")
        _require_name(self.event_type, "event_type")
        _require_positive_integer(self.event_version, "event_version")
        _format_timestamp(self.occurred_at, "occurred_at")


@dataclass(frozen=True, slots=True)
class EventRecord:
    """One immutable event envelope read from durable history."""

    sequence: int
    event_id: str
    stream_id: str
    stream_version: int
    event_type: str
    event_version: int
    occurred_at: datetime
    recorded_at: datetime
    payload: dict[str, Any]
    metadata: dict[str, Any]
    payload_sha256: str


@dataclass(frozen=True, slots=True)
class ProjectionCheckpoint:
    """Last global event sequence consumed by one disposable projection."""

    name: str
    last_sequence: int
    updated_at: datetime | None


_SCHEMA_V1 = (
    """
    CREATE TABLE complyroll_schema_migrations (
        version INTEGER PRIMARY KEY,
        description TEXT NOT NULL,
        applied_at TEXT NOT NULL
    )
    """,
    """
    CREATE TABLE events (
        sequence INTEGER PRIMARY KEY AUTOINCREMENT,
        event_id TEXT NOT NULL UNIQUE CHECK (length(trim(event_id)) > 0),
        stream_id TEXT NOT NULL CHECK (length(trim(stream_id)) > 0),
        stream_version INTEGER NOT NULL CHECK (stream_version >= 1),
        event_type TEXT NOT NULL CHECK (length(trim(event_type)) > 0),
        event_version INTEGER NOT NULL CHECK (event_version >= 1),
        occurred_at TEXT NOT NULL,
        recorded_at TEXT NOT NULL,
        payload_json TEXT NOT NULL,
        metadata_json TEXT NOT NULL,
        payload_sha256 TEXT NOT NULL CHECK (length(payload_sha256) = 64),
        UNIQUE (stream_id, stream_version)
    )
    """,
    "CREATE INDEX events_stream_sequence_idx ON events (stream_id, stream_version)",
    "CREATE INDEX events_type_sequence_idx ON events (event_type, sequence)",
    """
    CREATE TRIGGER events_reject_update
    BEFORE UPDATE ON events
    BEGIN
        SELECT RAISE(ABORT, 'ComplyRoll event history is append-only');
    END
    """,
    """
    CREATE TRIGGER events_reject_delete
    BEFORE DELETE ON events
    BEGIN
        SELECT RAISE(ABORT, 'ComplyRoll event history is append-only');
    END
    """,
    """
    CREATE TABLE projection_checkpoints (
        projection_name TEXT PRIMARY KEY CHECK (length(trim(projection_name)) > 0),
        last_sequence INTEGER NOT NULL CHECK (last_sequence >= 0),
        updated_at TEXT NOT NULL
    )
    """,
)


class SQLiteEventStore:
    """Append-only SQLite event log with optimistic stream concurrency."""

    def __init__(
        self,
        database: str | Path,
        *,
        clock: Callable[[], datetime] | None = None,
    ) -> None:
        self.database = str(database)
        self._clock = clock or (lambda: datetime.now(UTC))
        self._connection: sqlite3.Connection | None = sqlite3.connect(
            self.database,
            isolation_level=None,
        )
        self._connection.row_factory = sqlite3.Row
        self._connection.execute("PRAGMA foreign_keys = ON")
        self._connection.execute("PRAGMA busy_timeout = 5000")
        self._connection.execute("PRAGMA trusted_schema = OFF")

        try:
            self._initialize_schema()
        except Exception:
            self.close()
            raise

    def __enter__(self) -> Self:
        self._require_open()
        return self

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc_value: BaseException | None,
        traceback: TracebackType | None,
    ) -> None:
        self.close()

    def close(self) -> None:
        """Close the database connection. Calling close more than once is safe."""

        if self._connection is not None:
            self._connection.close()
            self._connection = None

    @property
    def schema_version(self) -> int:
        """Return the initialized store schema version."""

        connection = self._require_open()
        return int(connection.execute("PRAGMA user_version").fetchone()[0])

    @property
    def latest_sequence(self) -> int:
        """Return the most recently committed global sequence, or zero."""

        connection = self._require_open()
        row = connection.execute("SELECT COALESCE(MAX(sequence), 0) FROM events").fetchone()
        return int(row[0])

    def current_stream_version(self, stream_id: str) -> int:
        """Return the current version for one stream, or zero if it is new."""

        _require_name(stream_id, "stream_id")
        connection = self._require_open()
        return self._current_stream_version(connection, stream_id)

    def append(
        self,
        stream_id: str,
        events: Sequence[NewEvent],
        *,
        expected_version: int,
    ) -> tuple[EventRecord, ...]:
        """Atomically append events if the stream is at ``expected_version``."""

        _require_name(stream_id, "stream_id")
        _require_nonnegative_integer(expected_version, "expected_version")
        pending = tuple(events)
        if not pending:
            raise ValueError("events must contain at least one event")
        if len(pending) > MAX_EVENTS_PER_APPEND:
            raise ValueError(f"events must contain at most {MAX_EVENTS_PER_APPEND} events")
        if any(not isinstance(event, NewEvent) for event in pending):
            raise TypeError("events must contain only NewEvent instances")
        event_ids = [event.event_id for event in pending]
        if len(set(event_ids)) != len(event_ids):
            raise EventConflictError("one append batch cannot contain duplicate event identifiers")

        connection = self._require_open()
        with _write_transaction(connection):
            actual_version = self._current_stream_version(connection, stream_id)
            if actual_version != expected_version:
                raise EventConcurrencyError(stream_id, expected_version, actual_version)

            recorded_text = _format_timestamp(self._clock(), "recorded_at")
            recorded_at = _parse_timestamp(recorded_text, "recorded_at")
            appended: list[EventRecord] = []

            for offset, event in enumerate(pending, start=1):
                payload_json = _canonical_json_object(event.payload, "payload")
                metadata_json = _canonical_json_object(event.metadata, "metadata")
                payload_sha256 = hashlib.sha256(payload_json.encode("utf-8")).hexdigest()
                occurred_text = _format_timestamp(event.occurred_at, "occurred_at")
                stream_version = actual_version + offset

                try:
                    cursor = connection.execute(
                        """
                        INSERT INTO events (
                            event_id,
                            stream_id,
                            stream_version,
                            event_type,
                            event_version,
                            occurred_at,
                            recorded_at,
                            payload_json,
                            metadata_json,
                            payload_sha256
                        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                        """,
                        (
                            event.event_id,
                            stream_id,
                            stream_version,
                            event.event_type,
                            event.event_version,
                            occurred_text,
                            recorded_text,
                            payload_json,
                            metadata_json,
                            payload_sha256,
                        ),
                    )
                except sqlite3.IntegrityError as exc:
                    raise EventConflictError(
                        f"event {event.event_id!r} conflicts with committed history"
                    ) from exc

                appended.append(
                    EventRecord(
                        sequence=int(cursor.lastrowid),
                        event_id=event.event_id,
                        stream_id=stream_id,
                        stream_version=stream_version,
                        event_type=event.event_type,
                        event_version=event.event_version,
                        occurred_at=_parse_timestamp(occurred_text, "occurred_at"),
                        recorded_at=recorded_at,
                        payload=json.loads(payload_json),
                        metadata=json.loads(metadata_json),
                        payload_sha256=payload_sha256,
                    )
                )

        return tuple(appended)

    def read_all(
        self,
        *,
        after_sequence: int = 0,
        limit: int = 500,
    ) -> tuple[EventRecord, ...]:
        """Read one ordered page from the global event log."""

        _require_nonnegative_integer(after_sequence, "after_sequence")
        _require_read_limit(limit)
        connection = self._require_open()
        rows = connection.execute(
            "SELECT * FROM events WHERE sequence > ? ORDER BY sequence LIMIT ?",
            (after_sequence, limit),
        ).fetchall()
        return tuple(_event_from_row(row) for row in rows)

    def read_stream(
        self,
        stream_id: str,
        *,
        after_version: int = 0,
        limit: int = 500,
    ) -> tuple[EventRecord, ...]:
        """Read one ordered page from a single event stream."""

        _require_name(stream_id, "stream_id")
        _require_nonnegative_integer(after_version, "after_version")
        _require_read_limit(limit)
        connection = self._require_open()
        rows = connection.execute(
            """
            SELECT *
            FROM events
            WHERE stream_id = ? AND stream_version > ?
            ORDER BY stream_version
            LIMIT ?
            """,
            (stream_id, after_version, limit),
        ).fetchall()
        return tuple(_event_from_row(row) for row in rows)

    def get_projection_checkpoint(self, name: str) -> ProjectionCheckpoint:
        """Return a projection checkpoint, defaulting to sequence zero."""

        _require_name(name, "projection_name")
        connection = self._require_open()
        row = connection.execute(
            """
            SELECT projection_name, last_sequence, updated_at
            FROM projection_checkpoints
            WHERE projection_name = ?
            """,
            (name,),
        ).fetchone()
        if row is None:
            return ProjectionCheckpoint(name=name, last_sequence=0, updated_at=None)
        return ProjectionCheckpoint(
            name=str(row["projection_name"]),
            last_sequence=int(row["last_sequence"]),
            updated_at=_parse_timestamp(str(row["updated_at"]), "updated_at"),
        )

    def advance_projection(
        self,
        name: str,
        *,
        expected_sequence: int,
        last_sequence: int,
    ) -> ProjectionCheckpoint:
        """Advance one checkpoint using compare-and-swap semantics."""

        _require_name(name, "projection_name")
        _require_nonnegative_integer(expected_sequence, "expected_sequence")
        _require_nonnegative_integer(last_sequence, "last_sequence")
        if last_sequence < expected_sequence:
            raise ValueError("last_sequence must not move a projection backward")

        connection = self._require_open()
        with _write_transaction(connection):
            actual_sequence = self._current_projection_sequence(connection, name)
            if actual_sequence != expected_sequence:
                raise ProjectionConcurrencyError(name, expected_sequence, actual_sequence)

            latest_sequence = int(
                connection.execute("SELECT COALESCE(MAX(sequence), 0) FROM events").fetchone()[0]
            )
            if last_sequence > latest_sequence:
                raise ValueError(
                    f"last_sequence {last_sequence} exceeds latest event sequence {latest_sequence}"
                )

            updated_text = _format_timestamp(self._clock(), "updated_at")
            connection.execute(
                """
                INSERT INTO projection_checkpoints (projection_name, last_sequence, updated_at)
                VALUES (?, ?, ?)
                ON CONFLICT(projection_name) DO UPDATE SET
                    last_sequence = excluded.last_sequence,
                    updated_at = excluded.updated_at
                """,
                (name, last_sequence, updated_text),
            )

        return ProjectionCheckpoint(
            name=name,
            last_sequence=last_sequence,
            updated_at=_parse_timestamp(updated_text, "updated_at"),
        )

    def reset_projection(
        self,
        name: str,
        *,
        expected_sequence: int,
    ) -> ProjectionCheckpoint:
        """Reset one checkpoint to sequence zero before rebuilding its rows."""

        _require_name(name, "projection_name")
        _require_nonnegative_integer(expected_sequence, "expected_sequence")
        connection = self._require_open()
        with _write_transaction(connection):
            actual_sequence = self._current_projection_sequence(connection, name)
            if actual_sequence != expected_sequence:
                raise ProjectionConcurrencyError(name, expected_sequence, actual_sequence)
            connection.execute(
                "DELETE FROM projection_checkpoints WHERE projection_name = ?",
                (name,),
            )
        return ProjectionCheckpoint(name=name, last_sequence=0, updated_at=None)

    def _initialize_schema(self) -> None:
        connection = self._require_open()
        application_id = int(connection.execute("PRAGMA application_id").fetchone()[0])
        version = int(connection.execute("PRAGMA user_version").fetchone()[0])

        if application_id not in (0, APPLICATION_ID):
            raise UnsupportedSchemaError("database belongs to another application")
        if version > SCHEMA_VERSION:
            raise UnsupportedSchemaError(
                f"database schema {version} is newer than supported schema {SCHEMA_VERSION}"
            )
        if version == 0:
            with _write_transaction(connection):
                for statement in _SCHEMA_V1:
                    connection.execute(statement)
                connection.execute(
                    """
                    INSERT INTO complyroll_schema_migrations (version, description, applied_at)
                    VALUES (?, ?, ?)
                    """,
                    (
                        SCHEMA_VERSION,
                        "append-only event history and projection checkpoints",
                        _format_timestamp(self._clock(), "applied_at"),
                    ),
                )
                connection.execute(f"PRAGMA application_id = {APPLICATION_ID}")
                connection.execute(f"PRAGMA user_version = {SCHEMA_VERSION}")
            return

        if application_id != APPLICATION_ID:
            raise UnsupportedSchemaError("database schema is not marked as a ComplyRoll store")
        migration = connection.execute(
            "SELECT version FROM complyroll_schema_migrations WHERE version = ?",
            (version,),
        ).fetchone()
        if migration is None:
            raise UnsupportedSchemaError(f"database is missing migration record {version}")

    @staticmethod
    def _current_stream_version(connection: sqlite3.Connection, stream_id: str) -> int:
        row = connection.execute(
            "SELECT COALESCE(MAX(stream_version), 0) FROM events WHERE stream_id = ?",
            (stream_id,),
        ).fetchone()
        return int(row[0])

    @staticmethod
    def _current_projection_sequence(connection: sqlite3.Connection, name: str) -> int:
        row = connection.execute(
            "SELECT last_sequence FROM projection_checkpoints WHERE projection_name = ?",
            (name,),
        ).fetchone()
        return 0 if row is None else int(row[0])

    def _require_open(self) -> sqlite3.Connection:
        if self._connection is None:
            raise EventStoreError("event store is closed")
        return self._connection


class _write_transaction:
    """Small transaction context that rolls back every exceptional exit."""

    def __init__(self, connection: sqlite3.Connection) -> None:
        self.connection = connection

    def __enter__(self) -> None:
        self.connection.execute("BEGIN IMMEDIATE")

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc_value: BaseException | None,
        traceback: TracebackType | None,
    ) -> bool:
        if exc_type is None:
            self.connection.execute("COMMIT")
        else:
            self.connection.execute("ROLLBACK")
        return False


def _event_from_row(row: sqlite3.Row) -> EventRecord:
    payload_json = str(row["payload_json"])
    expected_digest = str(row["payload_sha256"])
    actual_digest = hashlib.sha256(payload_json.encode("utf-8")).hexdigest()
    if actual_digest != expected_digest:
        raise EventIntegrityError(
            f"event {row['event_id']!r} payload does not match its recorded digest"
        )

    try:
        payload = json.loads(payload_json)
        metadata = json.loads(str(row["metadata_json"]))
    except json.JSONDecodeError as exc:
        raise EventIntegrityError(f"event {row['event_id']!r} contains invalid JSON") from exc
    if not isinstance(payload, dict) or not isinstance(metadata, dict):
        raise EventIntegrityError(f"event {row['event_id']!r} JSON must contain objects")

    return EventRecord(
        sequence=int(row["sequence"]),
        event_id=str(row["event_id"]),
        stream_id=str(row["stream_id"]),
        stream_version=int(row["stream_version"]),
        event_type=str(row["event_type"]),
        event_version=int(row["event_version"]),
        occurred_at=_parse_timestamp(str(row["occurred_at"]), "occurred_at"),
        recorded_at=_parse_timestamp(str(row["recorded_at"]), "recorded_at"),
        payload=payload,
        metadata=metadata,
        payload_sha256=expected_digest,
    )


def _require_name(value: str, field_name: str) -> None:
    if not isinstance(value, str) or not value or value != value.strip():
        raise ValueError(f"{field_name} must be non-blank text without surrounding whitespace")
    if len(value) > 500 or _NAME_PATTERN.fullmatch(value) is None:
        raise ValueError(f"{field_name} contains unsupported characters or is too long")


def _require_nonnegative_integer(value: int, field_name: str) -> None:
    if isinstance(value, bool) or not isinstance(value, int) or value < 0:
        raise ValueError(f"{field_name} must be a non-negative integer")


def _require_positive_integer(value: int, field_name: str) -> None:
    if isinstance(value, bool) or not isinstance(value, int) or value < 1:
        raise ValueError(f"{field_name} must be a positive integer")


def _require_read_limit(limit: int) -> None:
    if isinstance(limit, bool) or not isinstance(limit, int) or not 1 <= limit <= MAX_READ_BATCH:
        raise ValueError(f"limit must be between 1 and {MAX_READ_BATCH}")


def _format_timestamp(value: datetime, field_name: str) -> str:
    if not isinstance(value, datetime) or value.tzinfo is None or value.utcoffset() is None:
        raise ValueError(f"{field_name} must include a timezone")
    return value.astimezone(UTC).isoformat(timespec="microseconds").replace("+00:00", "Z")


def _parse_timestamp(value: str, field_name: str) -> datetime:
    normalized = f"{value[:-1]}+00:00" if value.endswith("Z") else value
    try:
        parsed = datetime.fromisoformat(normalized)
    except ValueError as exc:
        raise EventIntegrityError(f"stored {field_name} is not an ISO 8601 timestamp") from exc
    if parsed.tzinfo is None or parsed.utcoffset() is None:
        raise EventIntegrityError(f"stored {field_name} does not include a timezone")
    return parsed


def _canonical_json_object(value: Mapping[str, Any], field_name: str) -> str:
    if not isinstance(value, Mapping):
        raise TypeError(f"{field_name} must be a JSON object")
    _validate_json_tree(value, field_name)
    try:
        encoded = json.dumps(
            value,
            allow_nan=False,
            ensure_ascii=False,
            separators=(",", ":"),
            sort_keys=True,
        )
    except (TypeError, ValueError, RecursionError) as exc:
        raise ValueError(f"{field_name} must contain valid JSON values") from exc
    if len(encoded.encode("utf-8")) > MAX_EVENT_JSON_BYTES:
        raise ValueError(f"{field_name} exceeds the {MAX_EVENT_JSON_BYTES}-byte limit")
    return encoded


def _validate_json_tree(value: Mapping[str, Any], field_name: str) -> None:
    stack: list[tuple[Any, int]] = [(value, 0)]
    values_seen = 0
    while stack:
        current, depth = stack.pop()
        values_seen += 1
        if values_seen > MAX_EVENT_JSON_VALUES:
            raise ValueError(f"{field_name} exceeds the JSON value limit")
        if depth > MAX_EVENT_JSON_DEPTH:
            raise ValueError(f"{field_name} exceeds the JSON depth limit")

        if isinstance(current, Mapping):
            for key, child in current.items():
                if not isinstance(key, str):
                    raise ValueError(f"{field_name} JSON object keys must be strings")
                stack.append((child, depth + 1))
        elif isinstance(current, list):
            stack.extend((child, depth + 1) for child in current)
        elif current is None or isinstance(current, (bool, int, str)):
            continue
        elif isinstance(current, float):
            if not math.isfinite(current):
                raise ValueError(f"{field_name} cannot contain NaN or infinity")
        else:
            raise ValueError(
                f"{field_name} contains a non-JSON value of type {type(current).__name__}"
            )
