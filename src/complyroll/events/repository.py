"""The only code that may append a ComplyRoll domain event (ADR 0008 Decision 1).

`EventRepository` validates every payload against the published contract before it
reaches `SQLiteEventStore.append`, and refuses an event type or version the registry
does not carry. The store keeps knowing nothing about what an event means.
"""

from __future__ import annotations

import hashlib
import json
import re
import uuid
from collections.abc import Mapping, Sequence
from contextlib import AbstractContextManager
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, Final
from uuid import uuid4

from jsonschema import Draft202012Validator

from complyroll import __version__
from complyroll.models import Observation
from complyroll.store import EventRecord, NewEvent, SQLiteEventStore

from .contracts import (
    EVENT_CONTRACTS,
    artifact_stream_components,
    event_belongs_on_stream,
    is_artifact_stream,
    iso_utc,
    parse_utc,
    schema_for,
    stream_kind,
    timestamp_pointers_for,
    tracking_id_from_stream,
)

#: The one event type whose payload is read back by a domain reader rather than a schema alone.
OBSERVATION_RECORDED = "observation.recorded"

#: The one event type whose payload names the stream it must be stored on.
CASE_CREATED = "case.created"

#: The one event type that declares how many observations its stream holds.
ARTIFACT_INGESTED = "artifact.ingested"

#: How each artifact-stream event names the artifact it belongs to: the digest of the
#: bytes, the parser that read them, and that parser's version. `observation.recorded`
#: spells them the way `Observation.to_canonical_dict` does, in snake case.
ARTIFACT_IDENTITY_KEYS: Final[dict[str, tuple[str, str, str]]] = {
    ARTIFACT_INGESTED: ("sha256", "parserName", "parserVersion"),
    OBSERVATION_RECORDED: ("source_artifact_digest", "parser_name", "parser_version"),
}

#: The key an `observation.recorded` payload records its identifier under, spelled the way
#: `Observation.to_canonical_dict` spells it.
OBSERVATION_ID_KEY: Final = "observation_id"

#: Page size for the paged readers below. The store caps a read at 10,000 rows.
READ_PAGE_SIZE = 500

#: The store appends at most this many events in one transaction.
MAX_BATCH_EVENTS = 1_000

#: The methods an event may record: a command invocation, or a direct call into the
#: writers from another program. A metadata envelope naming anything else is refused.
METHOD_VALUES: Final[tuple[str, ...]] = ("cli", "library")

#: Exactly the keys a stored metadata envelope carries (ADR 0008 Decision 1).
METADATA_KEYS: Final[tuple[str, ...]] = ("actor", "method", "tool", "toolVersion", "runId")

#: The generator name every event this tool writes records. `toolVersion` moves with each
#: release; the name does not, so an envelope naming another tool is not this tool's
#: history and is refused rather than stored verbatim (ADR 0008, second amendment).
TOOL_NAME: Final = "complyroll"

#: One run identifier per command invocation, spelled `run-<uuid4>` (ADR 0008 Decision 1).
RUN_ID_PREFIX: Final = "run-"


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

    The fields are checked rather than described. A `runId` that is not a canonical
    version-4 UUID cannot group a run, a `method` outside the published set names a
    provenance nothing can interpret, and a `tool` other than `complyroll` names a
    generator this is not; all three used to be stored verbatim, so the log could carry
    `run-not-a-uuid`, `method: not-cli`, and `tool: not-complyroll` and still verify clean.
    """

    actor: str
    method: str = "cli"
    tool: str = TOOL_NAME
    tool_version: str = __version__
    run_id: str = field(default_factory=lambda: f"{RUN_ID_PREFIX}{uuid4()}")

    def __post_init__(self) -> None:
        for value, name in (
            (self.actor, "actor"),
            (self.tool_version, "tool_version"),
        ):
            if not _is_non_blank(value):
                raise ValueError(f"{name} must be non-blank text")
        if self.tool != TOOL_NAME:
            raise ValueError(f"tool must be {TOOL_NAME!r}, got {self.tool!r}")
        if not _is_published_method(self.method):
            published = ", ".join(METHOD_VALUES)
            raise ValueError(f"method must be one of {published}, got {self.method!r}")
        if not _is_run_identifier(self.run_id):
            raise ValueError(
                f"run_id must be {RUN_ID_PREFIX!r} followed by a canonical lowercase "
                f"version-4 UUID, got {self.run_id!r}"
            )

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

    def transaction(self) -> AbstractContextManager[SQLiteEventStore]:
        """Hold one write transaction open across several repository calls.

        Every append made inside the block joins it, and every read inside it runs on the
        same connection, so a writer can fold history, decide against it, and append the
        decision without a second writer slipping between the two.
        """

        return self._store.transaction()

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
        _require_real_instants(event_type, event_version, payload)
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
            _require_stream_compatible(stream_id, event.event_type, event.payload)
            metadata = event.metadata.to_dict()
            _require_valid_metadata(metadata)
            prepared.append(
                NewEvent(
                    event_type=event.event_type,
                    occurred_at=event.occurred_at,
                    payload=dict(event.payload),
                    metadata=metadata,
                    event_version=event.event_version,
                )
            )
        self._require_unseen_observations(stream_id, pending)
        return self._store.append(stream_id, prepared, expected_version=expected_version)

    def _require_unseen_observations(
        self,
        stream_id: str,
        events: Sequence[PendingEvent],
    ) -> None:
        """Refuse a batch that would store one observation identifier twice on one stream.

        An artifact stream's observation identifiers are the findings it carries, and the
        same identifier twice is one finding counted twice. Neither existing check sees it:
        a duplicate names exactly the artifact its stream names, so the identity check is
        satisfied, and a head declaring five observations that carries five copies of one
        adds up, so the count check is satisfied too. The stream's stored identifiers are
        read here rather than trusted, on the connection the caller's transaction already
        holds, so a concurrent writer cannot slip a second copy in between the read and the
        append (ADR 0008, second amendment).

        `record_ingest` resumes a half-written stream by appending the tail its head
        declared, and a legitimate tail carries identifiers the stream does not: only a
        repeat is refused.
        """

        incoming = [
            str(event.payload.get(OBSERVATION_ID_KEY))
            for event in events
            if event.event_type == OBSERVATION_RECORDED
        ]
        if not incoming or not is_artifact_stream(stream_id):
            return
        seen: set[str] = set()
        if self.current_version(stream_id) > 0:
            seen = {
                str(record.payload.get(OBSERVATION_ID_KEY))
                for record in self.read_stream(stream_id)
                if record.event_type == OBSERVATION_RECORDED
            }
        for observation_id in incoming:
            if observation_id in seen:
                raise EventContractError(
                    duplicate_observation_message(stream_id, observation_id)
                )
            seen.add(observation_id)

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


def metadata_breaches(metadata: Mapping[str, Any]) -> tuple[str, ...]:
    """Return every reason one metadata envelope is not one this version would write.

    The same rules run at append, where they refuse the write, and over history at rest in
    `complyroll.history.audit_history`, where they are reported as faults. Two callers, one
    rule set, so a breach cannot be refused on the way in and called healthy later.
    """

    if not isinstance(metadata, Mapping):
        return ("metadata must be a JSON object",)
    problems: list[str] = []
    keys = sorted(metadata)
    if keys != sorted(METADATA_KEYS):
        listed = ", ".join(keys) if keys else "nothing"
        problems.append(
            f"metadata must carry exactly {', '.join(sorted(METADATA_KEYS))}, got {listed}"
        )
    for key in ("actor", "toolVersion"):
        if key in metadata and not _is_non_blank(metadata[key]):
            problems.append(f"{key} must be non-blank text")
    if "tool" in metadata and metadata["tool"] != TOOL_NAME:
        problems.append(f"tool must be {TOOL_NAME!r}")
    if "method" in metadata and not _is_published_method(metadata["method"]):
        problems.append(f"method must be one of {', '.join(METHOD_VALUES)}")
    if "runId" in metadata and not _is_run_identifier(metadata["runId"]):
        problems.append(
            f"runId must be {RUN_ID_PREFIX!r} followed by a canonical lowercase "
            "version-4 UUID"
        )
    return tuple(problems)


def _require_valid_metadata(metadata: Mapping[str, Any]) -> None:
    """Refuse a metadata envelope the audit would later report as a breach."""

    problems = metadata_breaches(metadata)
    if problems:
        raise EventContractError(f"event metadata is invalid: {'; '.join(problems)}")


def _is_non_blank(value: object) -> bool:
    return isinstance(value, str) and bool(value.strip())


def _is_published_method(value: object) -> bool:
    return isinstance(value, str) and value in METHOD_VALUES


def _is_run_identifier(value: object) -> bool:
    """Return True for `run-` and one canonical lowercase version-4 UUID.

    `uuid.UUID` accepts braces, urn prefixes, and upper case, and any of those would make
    two spellings of one run look like two runs, so the parsed value has to re-serialize to
    exactly the text stored.
    """

    if not isinstance(value, str) or not value.startswith(RUN_ID_PREFIX):
        return False
    text = value[len(RUN_ID_PREFIX) :]
    try:
        parsed = uuid.UUID(text)
    except ValueError:
        return False
    return parsed.version == 4 and parsed.variant == uuid.RFC_4122 and str(parsed) == text


def artifact_identity_breach(
    stream_id: str,
    event_type: str,
    payload: Mapping[str, Any],
) -> str | None:
    """Return why an artifact-stream event names an artifact its stream does not.

    An artifact stream id is the artifact's identity: the digest of the bytes, the parser,
    and the parser version (ADR 0002). Both events an artifact stream carries name the same
    three things in their payload, so the two have to agree. They did not have to before,
    and an `observation.recorded` copied verbatim onto another artifact's stream passed
    every check there was: it is the right event type for the stream and it is internally
    consistent, so it rehydrated under an artifact it never came from and its finding was
    counted twice (ADR 0008, second amendment).

    Returns None for an event no artifact stream carries and for a stream of another kind,
    which are the stream-kind check's business rather than this one's.
    """

    keys = ARTIFACT_IDENTITY_KEYS.get(event_type)
    if keys is None or not is_artifact_stream(stream_id):
        return None
    try:
        expected = artifact_stream_components(stream_id)
    except ValueError as exc:
        return f"stream {stream_id!r} names no artifact identity: {exc}"
    recorded = tuple(payload.get(key) for key in keys)
    if recorded == expected:
        return None
    return (
        f"{event_type} records digest {recorded[0]!r} read by {recorded[1]!r} version "
        f"{recorded[2]!r} on stream {stream_id!r}, which names digest {expected[0]!r} read "
        f"by {expected[1]!r} version {expected[2]!r}"
    )


def duplicate_observation_message(stream_id: str, observation_id: str) -> str:
    """Word one artifact stream holding the same observation twice, wherever it is reported.

    The same wording is used by the refusal at append, by the fold, and by
    `complyroll.history.audit_history`, so one damaged stream describes itself the same way
    whichever command an operator reaches it through.
    """

    return (
        f"artifact stream {stream_id!r} records observation {observation_id!r} more than "
        "once; the same finding would be rehydrated twice"
    )


def _require_stream_compatible(
    stream_id: str,
    event_type: str,
    payload: Mapping[str, Any],
) -> None:
    """Refuse an event the stream's kind cannot carry (ADR 0008 Decision 2).

    Replay reads artifacts and observations from artifact streams and case events from case
    streams, so an event stored on the other kind is read by nobody while `store verify`
    still calls the log healthy. A `case.created` also names its own stream, and one that
    names a different tracking id would fold into a case the stream is not; an
    `artifact.ingested` and an `observation.recorded` name their own stream the same way,
    through the artifact identity the stream id spells out.
    """

    if not event_belongs_on_stream(event_type, stream_id):
        kind = stream_kind(stream_id)
        described = "neither an artifact nor a case stream" if kind is None else f"a {kind} stream"
        raise EventContractError(
            f"event {event_type!r} does not belong on stream {stream_id!r}, which is {described}"
        )
    breach = artifact_identity_breach(stream_id, event_type, payload)
    if breach is not None:
        raise EventContractError(breach)
    if event_type != CASE_CREATED:
        return
    try:
        expected = tracking_id_from_stream(stream_id)
    except ValueError as exc:
        raise EventContractError(
            f"{CASE_CREATED} cannot be stored on stream {stream_id!r}: {exc}"
        ) from exc
    recorded = payload.get("trackingId")
    if recorded != expected:
        raise EventContractError(
            f"{CASE_CREATED} records tracking id {recorded!r} on stream {stream_id!r}, "
            f"which names {expected!r}"
        )


def _require_real_instants(
    event_type: str,
    event_version: int,
    payload: Mapping[str, Any],
) -> None:
    """Parse every instant-valued field, so a shape that is not a date cannot be stored.

    The contracts spell timestamps as regular expressions, and a regular expression cannot
    tell 30 February from 28 February or hour 25 from hour 05. Such a payload used to append
    cleanly and be certified by `store verify`, and only the fold refused it, which put the
    refusal in the one place that cannot help the operator who wrote it.
    """

    issues: list[ContractIssue] = []
    for pointer in timestamp_pointers_for(event_type, event_version):
        value = _value_at(payload, pointer)
        if not isinstance(value, str):
            continue
        problem = _instant_problem(value)
        if problem is not None:
            issues.append(
                ContractIssue(instance_pointer=pointer, validator="timestamp", message=problem)
            )
    if issues:
        rendered = "; ".join(issue.render() for issue in issues)
        raise EventContractError(
            f"{event_type} version {event_version} payload is invalid: {rendered}",
            issues=tuple(issues),
        )


#: Midnight spelled as the end of the previous day. RFC 3339 hours run 00 to 23.
_HOUR_24_PATTERN: Final = re.compile(r"^\d{4}-\d{2}-\d{2}T24:")


def _instant_problem(value: str) -> str | None:
    """Return why one timestamp names no real instant, or None when it names one.

    Hour 24 is the case worth spelling out. Python parses it and rolls the date forward, so
    `2026-08-31T24:00:00Z` becomes 1 September: a remediation deadline that quietly moves
    into the next month. RFC 3339 has no such hour, so it is refused rather than shifted.
    """

    try:
        parse_utc(value)
    except ValueError as exc:
        return str(exc)
    if _HOUR_24_PATTERN.match(value) is not None:
        return f"timestamp hour must be 00 to 23, got {value!r}"
    return None


def _value_at(payload: Mapping[str, Any], pointer: str) -> Any:
    """Return the value one JSON pointer names, or None when the path is not there.

    Contract property names are plain identifiers, so no pointer part needs unescaping.
    """

    current: Any = payload
    for part in pointer.split("/")[1:]:
        if not isinstance(current, Mapping) or part not in current:
            return None
        current = current[part]
    return current


def _json_pointer(parts: Any) -> str:
    encoded = (str(part).replace("~", "~0").replace("/", "~1") for part in parts)
    return "".join(f"/{part}" for part in encoded)


__all__ = [
    "ARTIFACT_IDENTITY_KEYS",
    "MAX_BATCH_EVENTS",
    "METADATA_KEYS",
    "METHOD_VALUES",
    "OBSERVATION_ID_KEY",
    "READ_PAGE_SIZE",
    "RUN_ID_PREFIX",
    "TOOL_NAME",
    "ContractIssue",
    "EventContractError",
    "EventMetadata",
    "EventRepository",
    "PendingEvent",
    "artifact_identity_breach",
    "canonical_payload_digest",
    "duplicate_observation_message",
    "iso_utc",
    "metadata_breaches",
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
