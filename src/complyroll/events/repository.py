"""The only code that may append a ComplyRoll domain event (ADR 0008 Decision 1).

`EventRepository` validates every payload against the published contract before it
reaches `SQLiteEventStore.append`, and refuses an event type or version the registry
does not carry. The store keeps knowing nothing about what an event means.
"""

from __future__ import annotations

import hashlib
import json
from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any
from uuid import uuid4

from jsonschema import Draft202012Validator

from complyroll import __version__
from complyroll.models import Observation
from complyroll.store import EventRecord, NewEvent, SQLiteEventStore

from .contracts import EVENT_CONTRACTS, iso_utc, parse_utc, schema_for

#: The one event type whose payload is read back by a domain reader rather than a schema alone.
OBSERVATION_RECORDED = "observation.recorded"

#: Page size for the paged readers below. The store caps a read at 10,000 rows.
READ_PAGE_SIZE = 500

#: The store appends at most this many events in one transaction.
MAX_BATCH_EVENTS = 1_000


@dataclass(frozen=True, slots=True)
class ContractIssue:
    """One reason a payload failed its published contract."""

    instance_pointer: str
    validator: str
    message: str

    def render(self) -> str:
        """Return the single-line form used in error messages."""

        return f"{self.instance_pointer or '<root>'}: {self.validator}: {self.message}"


class EventContractError(ValueError):
    """A payload does not satisfy its contract, or no such contract is published."""

    def __init__(self, message: str, *, issues: Sequence[ContractIssue] = ()) -> None:
        self.issues: tuple[ContractIssue, ...] = tuple(issues)
        super().__init__(message)


@dataclass(frozen=True, slots=True)
class EventMetadata:
    """Who recorded an event, with what, and in which command invocation.

    `run_id` is one identifier per command invocation, so every event a single run
    produced can be found together (ADR 0008 Decision 1).
    """

    actor: str
    method: str = "cli"
    tool: str = "complyroll"
    tool_version: str = __version__
    run_id: str = field(default_factory=lambda: f"run-{uuid4()}")

    def __post_init__(self) -> None:
        for value, name in (
            (self.actor, "actor"),
            (self.method, "method"),
            (self.tool, "tool"),
            (self.tool_version, "tool_version"),
            (self.run_id, "run_id"),
        ):
            if not isinstance(value, str) or not value.strip():
                raise ValueError(f"{name} must be non-blank text")

    def to_dict(self) -> dict[str, str]:
        """Return the stored metadata object."""

        return {
            "actor": self.actor,
            "method": self.method,
            "tool": self.tool,
            "toolVersion": self.tool_version,
            "runId": self.run_id,
        }


@dataclass(frozen=True, slots=True)
class PendingEvent:
    """One contract-checked event waiting to be appended in a batch."""

    event_type: str
    payload: Mapping[str, Any]
    occurred_at: datetime
    metadata: EventMetadata
    event_version: int = 1


class EventRepository:
    """Contract-enforcing façade over the append-only store."""

    def __init__(self, store: SQLiteEventStore) -> None:
        if not isinstance(store, SQLiteEventStore):
            raise TypeError("store must be a SQLiteEventStore")
        self._store = store
        self._validators: dict[tuple[str, int], Draft202012Validator] = {}

    @property
    def store(self) -> SQLiteEventStore:
        """Return the underlying append-only store."""

        return self._store

    def validate_payload(
        self,
        event_type: str,
        payload: Mapping[str, Any],
        *,
        event_version: int = 1,
    ) -> None:
        """Raise `EventContractError` unless the payload satisfies its contract."""

        validator = self._validator(event_type, event_version)
        if not isinstance(payload, Mapping):
            raise EventContractError(
                f"{event_type} version {event_version} payload must be a JSON object"
            )
        issues = tuple(
            sorted(
                (
                    ContractIssue(
                        instance_pointer=_json_pointer(error.absolute_path),
                        validator=str(error.validator),
                        message=error.message,
                    )
                    for error in validator.iter_errors(dict(payload))
                ),
                key=lambda issue: (issue.instance_pointer, issue.validator, issue.message),
            )
        )
        if issues:
            rendered = "; ".join(issue.render() for issue in issues)
            raise EventContractError(
                f"{event_type} version {event_version} payload is invalid: {rendered}",
                issues=issues,
            )
        if event_type == OBSERVATION_RECORDED:
            _require_readable_observation(payload, event_version)


    def append(
        self,
        stream_id: str,
        event_type: str,
        payload: Mapping[str, Any],
        *,
        occurred_at: datetime,
        metadata: EventMetadata,
        expected_version: int,
        event_version: int = 1,
    ) -> EventRecord:
        """Validate one payload and append it, returning the stored envelope."""

        pending = PendingEvent(
            event_type=event_type,
            payload=payload,
            occurred_at=occurred_at,
            metadata=metadata,
            event_version=event_version,
        )
        return self.append_batch(stream_id, (pending,), expected_version=expected_version)[0]

    def append_batch(
        self,
        stream_id: str,
        events: Sequence[PendingEvent],
        *,
        expected_version: int,
    ) -> tuple[EventRecord, ...]:
        """Validate and append several events to one stream in a single transaction."""

        pending = tuple(events)
        if not pending:
            raise ValueError("events must contain at least one event")
        if len(pending) > MAX_BATCH_EVENTS:
            raise ValueError(f"events must contain at most {MAX_BATCH_EVENTS} events")
        prepared: list[NewEvent] = []
        for event in pending:
            if not isinstance(event, PendingEvent):
                raise TypeError("events must contain only PendingEvent instances")
            if not isinstance(event.metadata, EventMetadata):
                raise TypeError("event metadata must be an EventMetadata")
            self.validate_payload(
                event.event_type, event.payload, event_version=event.event_version
            )
            prepared.append(
                NewEvent(
                    event_type=event.event_type,
                    occurred_at=event.occurred_at,
                    payload=dict(event.payload),
                    metadata=event.metadata.to_dict(),
                    event_version=event.event_version,
                )
            )
        return self._store.append(stream_id, prepared, expected_version=expected_version)

    def current_version(self, stream_id: str) -> int:
        """Return the current version of one stream, or zero when it does not exist."""

        return self._store.current_stream_version(stream_id)

    def read_stream(self, stream_id: str) -> tuple[EventRecord, ...]:
        """Read one whole stream in stream-version order, across pages."""

        records: list[EventRecord] = []
        after = 0
        while True:
            page = self._store.read_stream(
                stream_id, after_version=after, limit=READ_PAGE_SIZE
            )
            if not page:
                break
            records.extend(page)
            after = page[-1].stream_version
            if len(page) < READ_PAGE_SIZE:
                break
        return tuple(records)

    def read_all(self) -> tuple[EventRecord, ...]:
        """Read the whole log in global sequence order, across pages."""

        records: list[EventRecord] = []
        after = 0
        while True:
            page = self._store.read_all(after_sequence=after, limit=READ_PAGE_SIZE)
            if not page:
                break
            records.extend(page)
            after = page[-1].sequence
            if len(page) < READ_PAGE_SIZE:
                break
        return tuple(records)

    def latest_payload(self, stream_id: str, event_type: str) -> dict[str, Any] | None:
        """Return the newest payload of one type on one stream, or None."""

        latest: dict[str, Any] | None = None
        for record in self.read_stream(stream_id):
            if record.event_type == event_type:
                latest = record.payload
        return latest

    def _validator(self, event_type: str, event_version: int) -> Draft202012Validator:
        key = (event_type, event_version)
        validator = self._validators.get(key)
        if validator is not None:
            return validator
        schema = schema_for(event_type, event_version)
        if schema is None:
            published = ", ".join(
                f"{name} v{version}" for name, version in sorted(EVENT_CONTRACTS)
            )
            raise EventContractError(
                f"no published contract for event {event_type!r} version {event_version}; "
                f"published contracts are: {published}"
            )
        validator = Draft202012Validator(schema)
        self._validators[key] = validator
        return validator


def canonical_payload_digest(payload: Mapping[str, Any]) -> str:
    """Return the SHA-256 of one payload's canonical JSON, for idempotency decisions.

    The encoding matches the store's canonical form: sorted keys, compact separators,
    and no ASCII escaping, so two payloads that would store identically digest
    identically.
    """

    if not isinstance(payload, Mapping):
        raise TypeError("payload must be a JSON object")
    encoded = json.dumps(
        dict(payload),
        allow_nan=False,
        ensure_ascii=False,
        separators=(",", ":"),
        sort_keys=True,
    )
    return hashlib.sha256(encoded.encode("utf-8")).hexdigest()


def _json_pointer(parts: Any) -> str:
    encoded = (str(part).replace("~", "~0").replace("/", "~1") for part in parts)
    return "".join(f"/{part}" for part in encoded)


__all__ = [
    "MAX_BATCH_EVENTS",
    "READ_PAGE_SIZE",
    "ContractIssue",
    "EventContractError",
    "EventMetadata",
    "EventRepository",
    "PendingEvent",
    "canonical_payload_digest",
    "iso_utc",
    "parse_utc",
]


def _require_readable_observation(payload: Mapping[str, Any], event_version: int) -> None:
    """Refuse an `observation.recorded` payload the replay reader could not read back.

    The contract's schema is a regular expression over text, and a regular expression
    cannot tell a whole second spelled with six zero digits from one the writer produced,
    or an impossible calendar date from a real one. `Observation.from_canonical_dict` is
    the reader every replay goes through, so it is the only check that cannot drift from
    the reader: a payload it refuses never reaches the log (ADR 0008 Decision 1).
    """

    try:
        Observation.from_canonical_dict(payload)
    except (TypeError, ValueError) as exc:
        issue = ContractIssue(instance_pointer="", validator="reader", message=str(exc))
        raise EventContractError(
            f"{OBSERVATION_RECORDED} version {event_version} payload is not readable: "
            f"{issue.render()}",
            issues=(issue,),
        ) from exc
