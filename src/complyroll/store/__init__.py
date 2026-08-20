"""Durable Phase 1 event history and projection checkpoint interfaces."""

from .sqlite import (
    MAX_EVENTS_PER_APPEND,
    MAX_EVENT_JSON_BYTES,
    EventConcurrencyError,
    EventConflictError,
    EventIntegrityError,
    EventRecord,
    EventStoreError,
    NewEvent,
    ProjectionCheckpoint,
    ProjectionConcurrencyError,
    SQLiteEventStore,
    UnsupportedSchemaError,
)

__all__ = [
    "MAX_EVENTS_PER_APPEND",
    "MAX_EVENT_JSON_BYTES",
    "EventConcurrencyError",
    "EventConflictError",
    "EventIntegrityError",
    "EventRecord",
    "EventStoreError",
    "NewEvent",
    "ProjectionCheckpoint",
    "ProjectionConcurrencyError",
    "SQLiteEventStore",
    "UnsupportedSchemaError",
]
