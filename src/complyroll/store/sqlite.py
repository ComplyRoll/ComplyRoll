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
import time
from collections.abc import Callable, Iterator, Mapping, Sequence
from contextlib import contextmanager
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from types import TracebackType
from typing import Any, Self
from urllib.parse import quote
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


class EventStoreBusyError(EventStoreError):
    """Raised when SQLite reports the database is locked or busy.

    Callers may retry the same operation; the store connection is left usable and
    outside any transaction.
    """


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
    """Raised when stored history is corrupt, tampered with, or missing rows.

    ``sequence`` carries the global sequence of the offending row when one can be
    identified, so callers can locate the damage without rescanning history.
    """

    def __init__(self, message: str, *, sequence: int | None = None) -> None:
        self.sequence = sequence
        super().__init__(message)


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


@dataclass(frozen=True, slots=True)
class IntegrityFault:
    """One integrity problem found by `verify_history`.

    ``sequence`` locates the offending row when one can be identified, and is None for
    a fault that belongs to the database rather than to a single event.
    """

    sequence: int | None
    code: str
    message: str


@dataclass(frozen=True, slots=True)
class IntegrityReport:
    """The outcome of one full walk of stored history."""

    ok: bool
    checked_events: int
    faults: tuple[IntegrityFault, ...]

    def render(self) -> str:
        """Return a single-line summary suitable for a command's output."""

        if self.ok:
            return f"ok: {self.checked_events} event(s) verified"
        return (
            f"faults: {len(self.faults)} problem(s) in {self.checked_events} verified event(s)"
        )


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

_CREATE_OBJECT_PATTERN = re.compile(
    r"CREATE\s+(TABLE|INDEX|TRIGGER)\s+([A-Za-z_][A-Za-z0-9_]*)",
    re.IGNORECASE,
)


_WHITESPACE_PATTERN = re.compile(r"\s+")


def _normalize_sql(sql: str) -> str:
    """Collapse whitespace and case so stored DDL can be compared with the source DDL."""

    return _WHITESPACE_PATTERN.sub(" ", sql).strip().rstrip(";").lower()


def _expected_schema() -> dict[tuple[str, str], str]:
    """Derive ``(type, name) -> normalized DDL`` for every object a healthy store must expose."""

    expected: dict[tuple[str, str], str] = {}
    for statement in _SCHEMA_V1:
        match = _CREATE_OBJECT_PATTERN.search(statement)
        if match is None:  # pragma: no cover - guards against future DDL edits
            raise EventStoreError("schema statement does not create a named object")
        expected[(match.group(1).lower(), match.group(2))] = _normalize_sql(statement)
    return expected


EXPECTED_SCHEMA = _expected_schema()
EXPECTED_SCHEMA_OBJECTS = frozenset(EXPECTED_SCHEMA)


class SQLiteEventStore:
    """Append-only SQLite event log with optimistic stream concurrency."""

    def __init__(
        self,
        database: str | Path,
        *,
        clock: Callable[[], datetime] | None = None,
        busy_timeout_ms: int = 5000,
    ) -> None:
        _require_positive_integer(busy_timeout_ms, "busy_timeout_ms")
        self.database = str(database)
        self.busy_timeout_ms = busy_timeout_ms
        self._clock = clock or (lambda: datetime.now(UTC))
        self._transaction_depth = 0
        try:
            connection = sqlite3.connect(self.database, isolation_level=None)
        except sqlite3.Error as exc:
            raise _database_open_error(exc) from exc
        self._connection: sqlite3.Connection | None = connection
        self._connection.row_factory = sqlite3.Row

        try:
            self._configure_connection()
            self._initialize_schema()
        except Exception:
            self.close()
            raise

    @classmethod
    def open_for_verification(
        cls,
        database: str | Path,
        *,
        busy_timeout_ms: int = 5000,
    ) -> Self:
        """Open an existing store read-only so `verify_history` can describe a damaged file.

        The normal constructor refuses a database whose schema objects, migration record,
        sequence counter, or history contiguity are wrong, which makes exactly those faults
        impossible to report.
        This path applies the same connection-scoped pragmas but runs no verification and
        creates no schema, and SQLite itself is opened read-only, so inspecting a file never
        changes it. A path with no file behind it is an error, never a new empty database.

        The store this returns is for reading only: every write, `append` included, is
        refused by SQLite. Use the constructor for anything that must record history.
        """

        _require_positive_integer(busy_timeout_ms, "busy_timeout_ms")
        path = Path(database)
        if not path.is_file():
            raise EventStoreError(f"could not open the database: no file at {str(database)!r}")

        store = cls.__new__(cls)
        store.database = str(database)
        store.busy_timeout_ms = busy_timeout_ms
        store._clock = lambda: datetime.now(UTC)
        store._transaction_depth = 0
        store._connection = None
        try:
            connection = sqlite3.connect(_read_only_uri(path), uri=True, isolation_level=None)
        except sqlite3.Error as exc:
            raise _database_open_error(exc) from exc
        store._connection = connection
        connection.row_factory = sqlite3.Row

        try:
            store._configure_read_only_connection()
        except Exception:
            store.close()
            raise
        return store

    def _configure_connection(self) -> None:
        """Apply the durability and safety pragmas every writable connection requires."""

        connection = self._require_open()
        try:
            self._configure_shared_pragmas(connection)
            journal_mode = self._enable_write_ahead_logging(connection)
            connection.execute("PRAGMA synchronous = FULL")
        except sqlite3.DatabaseError as exc:
            raise _database_open_error(exc) from exc

        allowed = {"wal", "memory"} if _is_memory_database(self.database) else {"wal"}
        if journal_mode not in allowed:
            raise EventStoreError(
                f"database refused write-ahead logging and reports journal mode {journal_mode!r}"
            )

    def _configure_read_only_connection(self) -> None:
        """Apply only the pragmas that cannot write, then prove the header is readable.

        The journal-mode switch and `PRAGMA synchronous` are deliberately absent: the first
        rewrites the file header on a store that is not already in WAL mode, and the second
        only governs writes this connection cannot make.
        """

        connection = self._require_open()
        try:
            self._configure_shared_pragmas(connection)
            connection.execute("PRAGMA user_version").fetchone()
        except sqlite3.DatabaseError as exc:
            raise _database_open_error(exc) from exc

    def _configure_shared_pragmas(self, connection: sqlite3.Connection) -> None:
        """Set the connection-scoped pragmas that never touch the database file."""

        connection.execute("PRAGMA foreign_keys = ON")
        connection.execute(f"PRAGMA busy_timeout = {self.busy_timeout_ms}")
        connection.execute("PRAGMA trusted_schema = OFF")

    def _enable_write_ahead_logging(self, connection: sqlite3.Connection) -> str:
        """Switch the file to WAL once, retrying while another opener holds the lock.

        Changing the journal mode needs exclusive access and SQLite does not apply the
        busy handler to it, so a second process opening a brand-new store at the same
        moment would otherwise fail immediately. Reading the mode needs no lock, so an
        established WAL file never attempts the switch at all.
        """

        current = str(connection.execute("PRAGMA journal_mode").fetchone()[0]).lower()
        if current == "wal":
            return current
        deadline = time.monotonic() + self.busy_timeout_ms / 1000
        while True:
            try:
                row = connection.execute("PRAGMA journal_mode = WAL").fetchone()
            except sqlite3.OperationalError as exc:
                if not _is_busy_error(exc) or time.monotonic() >= deadline:
                    raise
                time.sleep(0.005)
                continue
            return "unknown" if row is None else str(row[0]).lower()

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
        with _sqlite_errors("could not read the schema version"):
            return int(connection.execute("PRAGMA user_version").fetchone()[0])

    @property
    def journal_mode(self) -> str:
        """Return the active SQLite journal mode, normally ``wal``."""

        connection = self._require_open()
        with _sqlite_errors("could not read the journal mode"):
            return str(connection.execute("PRAGMA journal_mode").fetchone()[0]).lower()

    @property
    def latest_sequence(self) -> int:
        """Return the most recently committed global sequence, or zero."""

        connection = self._require_open()
        with _sqlite_errors("could not read event history"):
            row = connection.execute("SELECT COALESCE(MAX(sequence), 0) FROM events").fetchone()
        return int(row[0])

    def current_stream_version(self, stream_id: str) -> int:
        """Return the current version for one stream, or zero if it is new."""

        _require_name(stream_id, "stream_id")
        connection = self._require_open()
        with _sqlite_errors("could not read event history"):
            return self._current_stream_version(connection, stream_id)

    @contextmanager
    def transaction(self) -> Iterator[Self]:
        """Hold one write transaction open across several store calls.

        ``BEGIN IMMEDIATE`` is taken once on entry, so a second writer contends here rather
        than half way through the work, and every ``append`` or projection update made inside
        the block joins this transaction instead of opening its own. They commit together
        when the block ends normally and none of them survives an exception, which is what
        keeps a check made at the top of the block true at the bottom. Reads inside the block
        run on the same connection, so they see the writes the block has already made.

        Failures are mapped exactly as they are for a single append: contention becomes
        ``EventStoreBusyError``, and a rollback that itself fails closes the connection and
        leaves the store reporting itself closed rather than trusted.

        Nesting is refused. A second ``transaction()`` on the same store raises
        ``EventStoreError`` instead of opening an inner scope whose commit would not be one.
        """

        if self._transaction_depth:
            raise EventStoreError("the store is already inside a transaction")
        connection = self._require_open()
        with _write_transaction(connection, on_unrecoverable=self._abandon_connection):
            self._transaction_depth += 1
            try:
                yield self
            finally:
                self._transaction_depth -= 1

    @property
    def in_transaction(self) -> bool:
        """Return True while a `transaction()` block is open on this store."""

        return self._transaction_depth > 0

    def append(
        self,
        stream_id: str,
        events: Sequence[NewEvent],
        *,
        expected_version: int,
    ) -> tuple[EventRecord, ...]:
        """Atomically append events if the stream is at ``expected_version``.

        Inside a `transaction()` block the append joins that transaction, so the records it
        returns are durable only once the block commits.
        """

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
        with (
            _sqlite_errors("could not append to event history"),
            self._transaction(connection),
        ):
            self._require_sequence_counter_intact(connection)
            self._require_history_contiguous(connection, stream_id=stream_id)
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
                if cursor.lastrowid is None:
                    raise EventStoreError("SQLite did not report a sequence for the event")

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
        with _sqlite_errors("could not read event history"):
            rows = connection.execute(
                "SELECT * FROM events WHERE sequence > ? ORDER BY sequence LIMIT ?",
                (after_sequence, limit),
            ).fetchall()
        records = tuple(_event_from_row(row) for row in rows)
        _require_contiguous_sequences(records, after_sequence)
        return records

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
        with _sqlite_errors("could not read event history"):
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
        records = tuple(_event_from_row(row) for row in rows)
        _require_contiguous_stream_versions(records, stream_id, after_version)
        return records

    def verify_history(self) -> IntegrityReport:
        """Walk the whole log and report every integrity fault instead of raising one.

        The checks are the ones the read path performs one page at a time, plus the two
        that only a full walk can make: every payload digest, global sequence
        contiguity, per-stream version contiguity, the AUTOINCREMENT counter against the
        last stored row, and the stored schema definitions against the source DDL. A
        fault is collected, never raised, so a damaged store can still be described. A
        SQLite failure (unreadable file, I/O error) is still an error, not a fault.

        Faults arrive in a fixed order: schema objects sorted by ``(type, name)``, then the
        migration record, then the sequence counter, then rows by ascending sequence. A
        store opened through `open_for_verification` reaches the first four, which the
        normal constructor refuses to open at all. When the `events` table is itself gone
        the schema faults are reported and the walk is skipped rather than letting SQLite
        raise, and the migration table is read only when it is present.
        """

        connection = self._require_open()
        faults: list[IntegrityFault] = []
        checked = 0
        with _sqlite_errors("could not verify event history"):
            present = self._schema_objects(connection)
            faults.extend(self._schema_faults(connection))
            faults.extend(self._migration_faults(connection, present))
            if ("table", "events") not in present:
                return IntegrityReport(ok=not faults, checked_events=0, faults=tuple(faults))
            faults.extend(self._counter_faults(connection, present))
            expected_sequence = 1
            stream_versions: dict[str, int] = {}
            after_sequence = 0
            while True:
                rows = connection.execute(
                    "SELECT * FROM events WHERE sequence > ? ORDER BY sequence LIMIT ?",
                    (after_sequence, MAX_READ_BATCH),
                ).fetchall()
                if not rows:
                    break
                for row in rows:
                    checked += 1
                    sequence = int(row["sequence"])
                    after_sequence = sequence
                    faults.extend(_payload_faults(row, sequence))
                    if sequence != expected_sequence:
                        faults.append(
                            IntegrityFault(
                                sequence=sequence,
                                code="sequence_gap",
                                message=(
                                    f"event history is missing sequence {expected_sequence}; "
                                    f"next stored sequence is {sequence}"
                                ),
                            )
                        )
                        expected_sequence = sequence
                    expected_sequence += 1

                    stream_id = str(row["stream_id"])
                    stream_version = int(row["stream_version"])
                    expected_version = stream_versions.get(stream_id, 0) + 1
                    if stream_version != expected_version:
                        faults.append(
                            IntegrityFault(
                                sequence=sequence,
                                code="stream_version_gap",
                                message=(
                                    f"stream {stream_id!r} is missing version "
                                    f"{expected_version}; next stored version is "
                                    f"{stream_version}"
                                ),
                            )
                        )
                    stream_versions[stream_id] = stream_version
        return IntegrityReport(ok=not faults, checked_events=checked, faults=tuple(faults))

    def _schema_faults(self, connection: sqlite3.Connection) -> tuple[IntegrityFault, ...]:
        """Report missing or rewritten schema objects, ordered by ``(type, name)``.

        Missing and altered objects share one ordering so a reader walks the schema once,
        rather than reading the missing ones and then starting over on the altered ones.
        """

        definitions = self._schema_definitions(connection)
        faults: list[IntegrityFault] = []
        for key in sorted(EXPECTED_SCHEMA_OBJECTS):
            object_type, name = key
            if key not in definitions:
                faults.append(
                    IntegrityFault(
                        sequence=None,
                        code="schema_object_missing",
                        message=f"database is missing {object_type} {name}",
                    )
                )
            elif _normalize_sql(definitions[key] or "") != EXPECTED_SCHEMA[key]:
                faults.append(
                    IntegrityFault(
                        sequence=None,
                        code="schema_object_altered",
                        message=f"{object_type} {name} does not match its expected definition",
                    )
                )
        return tuple(faults)

    @staticmethod
    def _migration_faults(
        connection: sqlite3.Connection,
        present: frozenset[tuple[str, str]],
    ) -> tuple[IntegrityFault, ...]:
        """Report a missing migration record, reading the table only when it exists.

        A database whose migration table is gone already carries a `schema_object_missing`
        fault for it, and querying the absent table would raise instead of reporting.
        """

        if ("table", "complyroll_schema_migrations") not in present:
            return ()
        migration = connection.execute(
            "SELECT version FROM complyroll_schema_migrations WHERE version = ?",
            (SCHEMA_VERSION,),
        ).fetchone()
        if migration is not None:
            return ()
        return (
            IntegrityFault(
                sequence=None,
                code="migration_missing",
                message=f"database is missing migration record {SCHEMA_VERSION}",
            ),
        )

    @staticmethod
    def _counter_faults(
        connection: sqlite3.Connection,
        present: frozenset[tuple[str, str]],
    ) -> tuple[IntegrityFault, ...]:
        """Report a truncated tail: the AUTOINCREMENT counter outruns the last row.

        ``sqlite_sequence`` exists only while some table declares AUTOINCREMENT, so a
        database that lost it reads as a counter of zero rather than raising.
        """

        counter = 0
        if ("table", "sqlite_sequence") in present:
            row = connection.execute(
                "SELECT seq FROM sqlite_sequence WHERE name = 'events'"
            ).fetchone()
            counter = 0 if row is None else int(row[0])
        latest = int(
            connection.execute("SELECT COALESCE(MAX(sequence), 0) FROM events").fetchone()[0]
        )
        if counter == latest:
            return ()
        return (
            IntegrityFault(
                sequence=latest,
                code="sequence_counter_mismatch",
                message=(
                    f"event history was truncated: last stored sequence is {latest} but the "
                    f"sequence counter is {counter}"
                ),
            ),
        )

    def get_projection_checkpoint(self, name: str) -> ProjectionCheckpoint:
        """Return a projection checkpoint, defaulting to sequence zero."""

        _require_name(name, "projection_name")
        connection = self._require_open()
        with _sqlite_errors("could not read projection checkpoints"):
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
        with (
            _sqlite_errors("could not advance the projection checkpoint"),
            self._transaction(connection),
        ):
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
        with (
            _sqlite_errors("could not reset the projection checkpoint"),
            self._transaction(connection),
        ):
            actual_sequence = self._current_projection_sequence(connection, name)
            if actual_sequence != expected_sequence:
                raise ProjectionConcurrencyError(name, expected_sequence, actual_sequence)
            connection.execute(
                "DELETE FROM projection_checkpoints WHERE projection_name = ?",
                (name,),
            )
        return ProjectionCheckpoint(name=name, last_sequence=0, updated_at=None)

    def _transaction(self, connection: sqlite3.Connection) -> _write_transaction:
        return _write_transaction(
            connection,
            on_unrecoverable=self._abandon_connection,
            joined=self._transaction_depth > 0,
        )

    def _abandon_connection(self) -> None:
        """Close and forget a connection whose transaction state is no longer trustworthy."""

        connection, self._connection = self._connection, None
        if connection is not None:
            try:
                connection.close()
            except sqlite3.Error:
                pass

    def _initialize_schema(self) -> None:
        with _sqlite_errors("could not open the database"):
            self._initialize_schema_unchecked()

    def _initialize_schema_unchecked(self) -> None:
        connection = self._require_open()
        try:
            application_id = int(connection.execute("PRAGMA application_id").fetchone()[0])
            version = int(connection.execute("PRAGMA user_version").fetchone()[0])
            present = self._schema_objects(connection)
        except sqlite3.DatabaseError as exc:
            raise _database_open_error(exc) from exc

        if application_id not in (0, APPLICATION_ID):
            raise UnsupportedSchemaError("database belongs to another application")
        if version > SCHEMA_VERSION:
            raise UnsupportedSchemaError(
                f"database schema {version} is newer than supported schema {SCHEMA_VERSION}"
            )
        if version == 0:
            if present:
                raise UnsupportedSchemaError(
                    "database already contains objects and is not an empty ComplyRoll store"
                )
            with self._transaction(connection):
                # Re-check under the write lock: a peer process may have initialized the
                # store while this connection waited for BEGIN IMMEDIATE.
                version = int(connection.execute("PRAGMA user_version").fetchone()[0])
                if version == 0:
                    if self._schema_objects(connection):
                        raise UnsupportedSchemaError(
                            "database already contains objects and is not an empty "
                            "ComplyRoll store"
                        )
                    for statement in _SCHEMA_V1:
                        connection.execute(statement)
                    connection.execute(
                        """
                        INSERT INTO complyroll_schema_migrations
                            (version, description, applied_at)
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
            # A peer initialized the store first; verify its work like any reopen.
            application_id = int(connection.execute("PRAGMA application_id").fetchone()[0])
            present = self._schema_objects(connection)
            if version > SCHEMA_VERSION:
                raise UnsupportedSchemaError(
                    f"database schema {version} is newer than supported schema {SCHEMA_VERSION}"
                )

        self._verify_existing_schema(
            connection,
            application_id=application_id,
            version=version,
            present=present,
        )

    def _verify_existing_schema(
        self,
        connection: sqlite3.Connection,
        *,
        application_id: int,
        version: int,
        present: frozenset[tuple[str, str]],
    ) -> None:
        """Refuse a database whose marking, schema, migration, counter, or history is wrong.

        Only the writable open path runs these checks. `open_for_verification` skips them
        so `verify_history` can describe the same damage as faults instead of refusing to
        open the file at all.
        """

        if application_id != APPLICATION_ID:
            raise UnsupportedSchemaError("database schema is not marked as a ComplyRoll store")

        missing = sorted(EXPECTED_SCHEMA_OBJECTS - present)
        if missing:
            listed = ", ".join(f"{object_type} {name}" for object_type, name in missing)
            raise UnsupportedSchemaError(f"database is missing schema objects: {listed}")

        definitions = self._schema_definitions(connection)
        altered = sorted(
            key
            for key, expected_sql in EXPECTED_SCHEMA.items()
            if _normalize_sql(definitions.get(key) or "") != expected_sql
        )
        if altered:
            listed = ", ".join(f"{object_type} {name}" for object_type, name in altered)
            raise UnsupportedSchemaError(
                f"database schema objects do not match their expected definitions: {listed}"
            )

        migration = connection.execute(
            "SELECT version FROM complyroll_schema_migrations WHERE version = ?",
            (version,),
        ).fetchone()
        if migration is None:
            raise UnsupportedSchemaError(f"database is missing migration record {version}")
        self._require_sequence_counter_intact(connection)
        self._require_history_contiguous(connection)

    @staticmethod
    def _schema_objects(connection: sqlite3.Connection) -> frozenset[tuple[str, str]]:
        rows = connection.execute("SELECT type, name FROM sqlite_master").fetchall()
        return frozenset((str(row[0]).lower(), str(row[1])) for row in rows)

    @staticmethod
    def _schema_definitions(connection: sqlite3.Connection) -> dict[tuple[str, str], str | None]:
        rows = connection.execute("SELECT type, name, sql FROM sqlite_master").fetchall()
        return {
            (str(row[0]).lower(), str(row[1])): (None if row[2] is None else str(row[2]))
            for row in rows
        }

    @staticmethod
    def _require_sequence_counter_intact(connection: sqlite3.Connection) -> None:
        """Detect a truncated tail: the AUTOINCREMENT counter must equal the last stored row.

        Deleting the most recent rows leaves no gap between the rows that remain, but
        SQLite's sequence counter still remembers them, so the two disagree. That is the one
        shape a contiguity check cannot see, and `_require_history_contiguous` covers every
        other one; together they keep an append from ever writing past missing history.
        """

        row = connection.execute(
            "SELECT seq FROM sqlite_sequence WHERE name = 'events'"
        ).fetchone()
        counter = 0 if row is None else int(row[0])
        latest_row = connection.execute("SELECT COALESCE(MAX(sequence), 0) FROM events").fetchone()
        latest = int(latest_row[0])
        if counter != latest:
            raise EventIntegrityError(
                f"event history was truncated: last stored sequence is {latest} but the "
                f"sequence counter is {counter}",
                sequence=latest,
            )

    @classmethod
    def _require_history_contiguous(
        cls,
        connection: sqlite3.Connection,
        *,
        stream_id: str | None = None,
    ) -> None:
        """Refuse history with a hole in it, not only history with a truncated tail.

        The counter check above sees rows deleted off the end and nothing else. A row
        removed from the middle leaves the counter and the last stored sequence agreeing,
        so such a file used to open normally and the next append minted a sequence past the
        hole, making the gap permanent and every later full read fail. ADR 0008 says append
        refuses to write past a hole, which has to mean any hole.

        Two counts find one: the stored row count must equal MAX(sequence), and each
        stream's row count must equal its own MAX(stream_version). Both are index-backed
        aggregates, run once per open and once per append, which is the cost Phase 1
        volumes carry. ``stream_id`` narrows the per-stream half to the one stream an append
        is about to touch; the constructor passes none and checks every stream at once.

        `open_for_verification` never reaches this: it exists to inspect damaged files, and
        `verify_history` reports the same damage as `sequence_gap` and `stream_version_gap`
        faults instead.
        """

        cls._require_sequences_contiguous(connection)
        if stream_id is None:
            cls._require_all_streams_contiguous(connection)
        else:
            cls._require_stream_contiguous(connection, stream_id)

    @staticmethod
    def _require_sequences_contiguous(connection: sqlite3.Connection) -> None:
        """Require the global log to hold every sequence from 1 to the highest stored one."""

        row = connection.execute(
            """
            SELECT COUNT(*), COALESCE(MIN(sequence), 0), COALESCE(MAX(sequence), 0)
            FROM events
            """
        ).fetchone()
        stored, lowest, highest = int(row[0]), int(row[1]), int(row[2])
        if stored == 0 or (stored == highest and lowest == 1):
            return
        raise _sequence_gap_error(connection, stored=stored, lowest=lowest, highest=highest)

    @staticmethod
    def _require_all_streams_contiguous(connection: sqlite3.Connection) -> None:
        """Require every stream to hold every version from 1 to its own highest.

        One grouped aggregate covers the whole log, and the offending streams are ordered by
        identifier so the same damaged file always names the same stream.
        """

        row = connection.execute(
            """
            SELECT stream_id, COUNT(*), MIN(stream_version), MAX(stream_version)
            FROM events
            GROUP BY stream_id
            HAVING COUNT(*) <> MAX(stream_version) OR MIN(stream_version) <> 1
            ORDER BY stream_id
            LIMIT 1
            """
        ).fetchone()
        if row is None:
            return
        raise _stream_version_gap_error(
            connection,
            stream_id=str(row[0]),
            stored=int(row[1]),
            lowest=int(row[2]),
            highest=int(row[3]),
        )

    @staticmethod
    def _require_stream_contiguous(connection: sqlite3.Connection, stream_id: str) -> None:
        """Require one stream to hold every version from 1 to its own highest."""

        row = connection.execute(
            """
            SELECT COUNT(*), COALESCE(MIN(stream_version), 0), COALESCE(MAX(stream_version), 0)
            FROM events
            WHERE stream_id = ?
            """,
            (stream_id,),
        ).fetchone()
        stored, lowest, highest = int(row[0]), int(row[1]), int(row[2])
        if stored == 0 or (stored == highest and lowest == 1):
            return
        raise _stream_version_gap_error(
            connection,
            stream_id=stream_id,
            stored=stored,
            lowest=lowest,
            highest=highest,
        )

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
    """Transaction context that never leaves its connection inside a transaction.

    Both ``BEGIN IMMEDIATE`` and ``COMMIT`` can fail under contention. Either failure is
    rolled back and re-raised as an ``EventStoreError``, so a caller never sees a raw
    ``sqlite3`` error and never inherits a wedged connection that reports uncommitted rows.
    If the rollback itself fails, the connection can no longer be trusted: it is closed
    through ``on_unrecoverable`` and the error says so, rather than leaving an open
    transaction behind a successful-looking store object.

    ``joined`` marks the enclosing transaction a caller already opened through
    `SQLiteEventStore.transaction`. A joined context issues no statement of its own: it
    requires the enclosing transaction to be open, then leaves committing and rolling back
    to the block that opened it, so several appends land or fail as one. Without that flag
    an already-open transaction is still refused, because the only other way to reach one
    is a leak.
    """

    def __init__(
        self,
        connection: sqlite3.Connection,
        *,
        on_unrecoverable: Callable[[], None] | None = None,
        joined: bool = False,
    ) -> None:
        self.connection = connection
        self.joined = joined
        self._on_unrecoverable = on_unrecoverable

    def __enter__(self) -> None:
        if self.joined:
            if not self.connection.in_transaction:
                raise EventStoreError(
                    "expected an enclosing write transaction, but none is open"
                )
            return
        if self.connection.in_transaction:
            raise EventStoreError("connection is already inside a transaction")
        try:
            self.connection.execute("BEGIN IMMEDIATE")
        except sqlite3.Error as exc:
            rollback_error = self._rollback()
            raise self._failure(
                "could not begin a write transaction", exc, rollback_error
            ) from exc

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc_value: BaseException | None,
        traceback: TracebackType | None,
    ) -> None:
        if self.joined:
            return
        if exc_value is not None:
            rollback_error = self._rollback()
            if rollback_error is not None:
                self._abandon()
                raise EventStoreError(
                    f"could not roll back after {exc_value!r}: {rollback_error}; "
                    "the store connection was closed"
                ) from exc_value
            return
        try:
            self.connection.execute("COMMIT")
        except sqlite3.Error as exc:
            rollback_error = self._rollback()
            raise self._failure(
                "could not commit the write transaction", exc, rollback_error
            ) from exc

    def _failure(
        self,
        message: str,
        error: sqlite3.Error,
        rollback_error: sqlite3.Error | None,
    ) -> EventStoreError:
        if rollback_error is None:
            return _transaction_error(message, error)
        self._abandon()
        failure = _transaction_error(message, error, rollback_error)
        return type(failure)(f"{failure}; the store connection was closed")

    def _rollback(self) -> sqlite3.Error | None:
        """Roll back, returning any secondary failure instead of masking the first one."""

        if not self.connection.in_transaction:
            return None
        try:
            self.connection.execute("ROLLBACK")
        except sqlite3.Error as exc:
            return exc
        return None

    def _abandon(self) -> None:
        """Close a connection whose transaction state can no longer be trusted."""

        close = getattr(self.connection, "close", None)
        if close is not None:
            try:
                close()
            except sqlite3.Error:
                pass
        if self._on_unrecoverable is not None:
            self._on_unrecoverable()


def _event_from_row(row: sqlite3.Row) -> EventRecord:
    sequence = int(row["sequence"])
    payload_json = str(row["payload_json"])
    expected_digest = str(row["payload_sha256"])
    actual_digest = hashlib.sha256(payload_json.encode("utf-8")).hexdigest()
    if actual_digest != expected_digest:
        raise EventIntegrityError(
            f"event {row['event_id']!r} payload does not match its recorded digest",
            sequence=sequence,
        )

    try:
        payload = json.loads(payload_json)
        metadata = json.loads(str(row["metadata_json"]))
    except json.JSONDecodeError as exc:
        raise EventIntegrityError(
            f"event {row['event_id']!r} contains invalid JSON",
            sequence=sequence,
        ) from exc
    if not isinstance(payload, dict) or not isinstance(metadata, dict):
        raise EventIntegrityError(
            f"event {row['event_id']!r} JSON must contain objects",
            sequence=sequence,
        )

    return EventRecord(
        sequence=sequence,
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


def _payload_faults(row: sqlite3.Row, sequence: int) -> tuple[IntegrityFault, ...]:
    """Check one stored row's payload digest and JSON without raising."""

    payload_json = str(row["payload_json"])
    expected_digest = str(row["payload_sha256"])
    actual_digest = hashlib.sha256(payload_json.encode("utf-8")).hexdigest()
    if actual_digest != expected_digest:
        return (
            IntegrityFault(
                sequence=sequence,
                code="payload_digest_mismatch",
                message=(
                    f"event {str(row['event_id'])!r} payload does not match its recorded digest"
                ),
            ),
        )
    try:
        payload = json.loads(payload_json)
        metadata = json.loads(str(row["metadata_json"]))
    except json.JSONDecodeError:
        return (
            IntegrityFault(
                sequence=sequence,
                code="payload_not_json",
                message=f"event {str(row['event_id'])!r} contains invalid JSON",
            ),
        )
    if not isinstance(payload, dict) or not isinstance(metadata, dict):
        return (
            IntegrityFault(
                sequence=sequence,
                code="payload_not_object",
                message=f"event {str(row['event_id'])!r} JSON must contain objects",
            ),
        )
    return ()


def _sequence_gap_error(
    connection: sqlite3.Connection,
    *,
    stored: int,
    lowest: int,
    highest: int,
) -> EventIntegrityError:
    """Name the first sequence missing from the global log, in the read path's wording.

    The lowest stored sequence whose predecessor is absent bounds the first hole from
    above, and history that no longer starts at 1 answers this query with its own first
    row. Both lookups ride the primary key, and the query runs only once damage is already
    known, so the walk it costs is never paid by a healthy store.
    """

    row = connection.execute(
        """
        SELECT MIN(e.sequence)
        FROM events AS e
        WHERE e.sequence > 1
          AND NOT EXISTS (SELECT 1 FROM events AS p WHERE p.sequence = e.sequence - 1)
        """
    ).fetchone()
    following = None if row is None or row[0] is None else int(row[0])
    if following is None:
        # Every stored row has its predecessor, so the count can only disagree with the
        # highest sequence because some row carries a sequence at or below zero.
        return EventIntegrityError(
            f"event history holds {stored} event(s) but its sequences run from {lowest} to "
            f"{highest}",
            sequence=highest,
        )
    return EventIntegrityError(
        f"event history is missing sequence {following - 1}; next stored sequence is "
        f"{following}",
        sequence=following,
    )


def _stream_version_gap_error(
    connection: sqlite3.Connection,
    *,
    stream_id: str,
    stored: int,
    lowest: int,
    highest: int,
) -> EventIntegrityError:
    """Name the first version missing from one stream, in the read path's wording.

    The bare ``sequence`` beside ``MIN(stream_version)`` is the sequence of the row that
    produced the minimum: SQLite defines bare columns that way when a query aggregates with
    a single MIN or MAX, so locating the row costs no second query.
    """

    row = connection.execute(
        """
        SELECT MIN(e.stream_version), e.sequence
        FROM events AS e
        WHERE e.stream_id = ?
          AND e.stream_version > 1
          AND NOT EXISTS (
              SELECT 1
              FROM events AS p
              WHERE p.stream_id = e.stream_id AND p.stream_version = e.stream_version - 1
          )
        """,
        (stream_id,),
    ).fetchone()
    following = None if row is None or row[0] is None else int(row[0])
    if following is None:
        # Unlike a sequence, a stream version cannot fall below one while the table's CHECK
        # and its UNIQUE (stream_id, stream_version) stand, so a count that outruns the
        # highest version means the schema itself was rewritten. Reaching this without a
        # message would be worse than the guard costing a branch.
        return EventIntegrityError(
            f"stream {stream_id!r} holds {stored} event(s) but its versions run from "
            f"{lowest} to {highest}",
            sequence=None,
        )
    return EventIntegrityError(
        f"stream {stream_id!r} is missing version {following - 1}; next stored version is "
        f"{following}",
        sequence=int(row[1]),
    )


def _require_contiguous_sequences(
    records: Sequence[EventRecord],
    after_sequence: int,
) -> None:
    """Reject a page whose global sequences are not gap-free.

    ``sequence`` is an AUTOINCREMENT key and SQLite rolls ``sqlite_sequence`` back with an
    aborted transaction, so committed history is contiguous. A gap means a committed row
    was deleted out of band.
    """

    expected = after_sequence + 1
    for record in records:
        if record.sequence != expected:
            raise EventIntegrityError(
                f"event history is missing sequence {expected}; next stored sequence is "
                f"{record.sequence}",
                sequence=record.sequence,
            )
        expected += 1


def _require_contiguous_stream_versions(
    records: Sequence[EventRecord],
    stream_id: str,
    after_version: int,
) -> None:
    """Reject a stream page whose versions are not gap-free."""

    expected = after_version + 1
    for record in records:
        if record.stream_version != expected:
            raise EventIntegrityError(
                f"stream {stream_id!r} is missing version {expected}; next stored version is "
                f"{record.stream_version}",
                sequence=record.sequence,
            )
        expected += 1


def _sqlite_error_name(error: BaseException) -> str:
    """Return SQLite's symbolic result name (Python 3.11+), or an empty string."""

    return str(getattr(error, "sqlite_errorname", "") or "")


def _is_busy_error(error: BaseException) -> bool:
    name = _sqlite_error_name(error)
    if name:
        return name.startswith(("SQLITE_BUSY", "SQLITE_LOCKED"))
    text = str(error).lower()
    return "database is locked" in text or "database is busy" in text


def _is_corruption_error(error: BaseException) -> bool:
    name = _sqlite_error_name(error)
    if name:
        return name.startswith("SQLITE_CORRUPT")
    return "malformed" in str(error).lower()


def _is_not_a_database_error(error: BaseException) -> bool:
    name = _sqlite_error_name(error)
    if name:
        return name.startswith("SQLITE_NOTADB")
    return "not a database" in str(error).lower()


def _storage_error(
    context: str,
    error: sqlite3.Error,
    rollback_error: sqlite3.Error | None = None,
) -> EventStoreError:
    """Map any SQLite failure onto the store's error vocabulary.

    Contention becomes the retryable ``EventStoreBusyError``, a corrupt file becomes
    ``EventIntegrityError``, a file that is not SQLite at all becomes
    ``UnsupportedSchemaError``, and everything else (disk full, read-only media, I/O
    errors) becomes a plain ``EventStoreError`` that still carries SQLite's message.
    """

    detail = f"{context}: {error}"
    if rollback_error is not None:
        detail = f"{detail} (rollback also failed: {rollback_error})"
    if _is_busy_error(error):
        return EventStoreBusyError(detail)
    if _is_corruption_error(error):
        return EventIntegrityError(detail)
    if _is_not_a_database_error(error):
        return UnsupportedSchemaError(f"{context}: not a SQLite database ({error})")
    return EventStoreError(detail)


def _transaction_error(
    message: str,
    error: sqlite3.Error,
    rollback_error: sqlite3.Error | None = None,
) -> EventStoreError:
    """Map a SQLite transaction failure onto the store's error vocabulary."""

    return _storage_error(message, error, rollback_error)


def _database_open_error(error: sqlite3.Error) -> EventStoreError:
    """Map a failure while opening or reading a database header."""

    return _storage_error("could not open the database", error)


class _sqlite_errors:
    """Context that converts any escaping ``sqlite3.Error`` into a store error."""

    def __init__(self, context: str) -> None:
        self.context = context

    def __enter__(self) -> None:
        return None

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc_value: BaseException | None,
        traceback: TracebackType | None,
    ) -> None:
        if isinstance(exc_value, sqlite3.Error):
            raise _storage_error(self.context, exc_value) from exc_value


def _read_only_uri(path: Path) -> str:
    """Build the SQLite URI that opens an existing file read-only and creates nothing.

    Percent-encoding matters: a path holding ``?`` or ``#`` would otherwise be read as URI
    syntax and silently address a different file.
    """

    return f"file:{quote(str(path))}?mode=ro"


def _is_memory_database(database: str) -> bool:
    if database in ("", ":memory:"):
        return True
    lowered = database.lower()
    return lowered.startswith("file:") and (":memory:" in lowered or "mode=memory" in lowered)


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
