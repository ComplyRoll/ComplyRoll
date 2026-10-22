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

from jsonschema import Draft202012Validator, ValidationError

from complyroll import __version__
from complyroll.adapters.common import encode_list
from complyroll.adapters.failures import (
    DETECTION_FAILURE_PARSER_NAME,
    DETECTION_FAILURE_PARSER_VERSION,
    DETECTION_FAILURE_RECORD_ID,
    DETECTION_FAILURE_RULE,
    DETECTION_FAILURE_SOURCE_TOOL,
    DETECTION_FAILURE_SOURCE_TYPE,
    DETECTION_FAILURE_TITLE,
    FailureClass,
    failure_class_for_codes,
)
from complyroll.models import (
    Observation,
    ObservationDisposition,
    ObservationOrigin,
    SourceSeverity,
)
from complyroll.policy import RuleForce
from complyroll.store import EventRecord, NewEvent, SQLiteEventStore
from complyroll.store.sqlite import SHOWN_LIMIT, bounded, shown

from .contracts import (
    COVERAGE_RECORDED,
    COVERAGE_STREAM_SCHEMA_VERSION,
    EVENT_CONTRACTS,
    FAILURE_CLOCK_VALUES,
    FAILURE_CODE_VALUES,
    FAILURE_HELD,
    FAILURE_STREAM_PREFIX,
    FAILURE_STREAM_SCHEMA_VERSION,
    HELD_FAILURE_SCHEMA_VERSION,
    artifact_stream_components,
    coverage_stream_fingerprint,
    coverage_stream_id,
    event_belongs_on_stream,
    failure_stream_components,
    is_artifact_stream,
    is_coverage_stream,
    is_failure_stream,
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

#: The head of a failure stream, which names the failed reading its stream is about.
FAILURE_RECORDED = "failure.recorded"

#: The two heads a failure stream may open with: a recorded failure, or a hold beneath one
#: (ADR 0014, amendment 2026-10-13). Both name the failed reading their stream is about.
FAILURE_HEAD_TYPES: Final[tuple[str, ...]] = (FAILURE_RECORDED, FAILURE_HELD)

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

#: Exactly the source metadata keys a failure stream's system record carries, the ones
#: `system_observation_for` writes (ADR 0014). The fingerprint covers none of them, so the
#: derived-id check cannot see one changed, and replay renders `detectionFailures` from them.
FAILURE_METADATA_KEYS: Final[tuple[str, ...]] = (
    "artifact.mediaType",
    "artifact.name",
    "artifact.parser",
    "artifact.parserVersion",
    "artifact.sha256",
    "artifact.sizeBytes",
    "failure.class",
    "failure.clock",
    "failure.codes",
    "failure.rule",
)

#: How a failure head and its system record's metadata name the same fact. The digest,
#: parser, and version are held to the stream id instead, by each event on its own.
_FAILURE_RECORD_PAIRS: Final[tuple[tuple[str, str], ...]] = (
    ("name", "artifact.name"),
    ("sizeBytes", "artifact.sizeBytes"),
    ("mediaType", "artifact.mediaType"),
    ("failureClass", "failure.class"),
    ("failureCodes", "failure.codes"),
    ("clock", "failure.clock"),
)

#: The identity of a coverage stream's gap record, exactly what `reports.gaps` writes
#: (ADR 0015). Spelled here because the event layer does not import the report layer, as
#: `CLOSED_DISPOSITION_VALUES` is; the coverage stream tests hold each to its builder's.
COVERAGE_SOURCE_TYPE: Final = "complyroll.coverage"
COVERAGE_SOURCE_TOOL: Final = "complyroll"
COVERAGE_PARSER_NAME: Final = "complyroll.coverage"
COVERAGE_PARSER_VERSION: Final = "1"
COVERAGE_RECORD_ID: Final = "coverage-gap"

#: Exactly the source metadata keys a gap record carries, `coverage.job` empty when the
#: entry names no job. The fingerprint covers none of them, so the derived-id check cannot
#: see one changed.
COVERAGE_METADATA_KEYS: Final[tuple[str, ...]] = (
    "coverage.anchor",
    "coverage.anchorAt",
    "coverage.basis",
    "coverage.force",
    "coverage.inventorySha256",
    "coverage.job",
    "coverage.rule",
    "coverage.windowClosedAt",
)

#: A gap record's title and description, `reports.gaps`' `COVERAGE_GAP_TITLE` and
#: `COVERAGE_GAP_DESCRIPTION`, unchanged since the first build that could store a gap record.
#: The report prints the title, built from the rule, the resource and the window close.
COVERAGE_TITLE: Final = (
    "{rule} window for {resource_type}:{resource_id} closed {closed_at} "
    f"with no verification recorded ({DETECTION_FAILURE_RULE})"
)
COVERAGE_DESCRIPTION: Final = (
    "ComplyRoll recorded no verification for this resource inside the window; this records "
    "the absence of a verification, not a vulnerability."
)

#: Every `coverage.basis` text a gap record's writer has recorded, `reports.coverage`'s
#: `COVERAGE_BASIS`. A reworded basis is added here, never put in place of one, so a gap
#: recorded before the change still verifies.
COVERAGE_BASIS_TEXTS: Final[tuple[str, ...]] = (
    "VDR-TFR-MVX is read from detection results until Phase 3 validation runs exist. "
    "Coverage is measured against the provider-supplied inventory named by its SHA-256 "
    "digest, so an observed resource the inventory omits is listed as unregistered and is "
    "never expected. Evidence that determined no status (NOT_REVIEWED, ERROR or UNKNOWN) "
    "examines a resource without verifying it, untimed evidence never anchors a clock, and a "
    "non-machine resource is verified only by an operator attestation. A current status is "
    "not a compliance finding.",
)

#: The forces a coverage rule's clock can carry, the policy's own vocabulary.
_RULE_FORCE_VALUES: Final = frozenset(member.value for member in RuleForce)

#: How a coverage head names what its gap record names. The context key is the record's
#: own field; the rest are its metadata.
_COVERAGE_RECORD_PAIRS: Final[tuple[tuple[str, str], ...]] = (
    ("rule", "coverage.rule"),
    ("contextKey", "context_key"),
    ("windowClosedAt", "coverage.windowClosedAt"),
    ("anchor", "coverage.anchor"),
    ("anchorAt", "coverage.anchorAt"),
    ("inventorySha256", "coverage.inventorySha256"),
)

#: A size as `str(int)` spells it: digits only, no sign, no leading zero.
_COUNT_TEXT: Final = re.compile(r"(?:0|[1-9][0-9]*)")

#: The failure classes a system record's metadata may name.
_FAILURE_CLASS_VALUES: Final = frozenset(member.value for member in FailureClass)

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

        return f"{bounded(self.instance_pointer) or '<root>'}: {self.validator}: {self.message}"


#: How many issues a contract error's message renders; `issues` keeps every one.
MAX_RENDERED_ISSUES: Final = 10


def _rendered_issues(issues: Sequence[ContractIssue]) -> str:
    """Join a contract error's first issues, in the order given, and count the rest.

    Each issue is bounded, but a stored list of many invalid values yields one issue per value,
    so a full join grew with the payload: 20,000 values gave 1,257,829 characters.
    """

    rendered = "; ".join(issue.render() for issue in issues[:MAX_RENDERED_ISSUES])
    if len(issues) <= MAX_RENDERED_ISSUES:
        return rendered
    return f"{rendered}; and {len(issues) - MAX_RENDERED_ISSUES} more"


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
    """Contract-enforcing facade over the append-only store."""

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
                        message=_issue_message(error),
                    )
                    for error in validator.iter_errors(dict(payload))
                ),
                key=lambda issue: (issue.instance_pointer, issue.validator, issue.message),
            )
        )
        if issues:
            raise EventContractError(
                f"{event_type} version {event_version} payload is invalid: "
                f"{_rendered_issues(issues)}",
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
        for index, event in enumerate(pending):
            if not isinstance(event, PendingEvent):
                raise TypeError("events must contain only PendingEvent instances")
            if not isinstance(event.metadata, EventMetadata):
                raise TypeError("event metadata must be an EventMetadata")
            self.validate_payload(
                event.event_type, event.payload, event_version=event.event_version
            )
            _require_stream_compatible(stream_id, event.event_type, event.payload)
            # The store appends only at expected_version, so the first event of a batch at
            # version 0 is the event that opens the stream (ADR 0014).
            if (
                index == 0
                and expected_version == 0
                and is_failure_stream(stream_id)
                and event.event_type not in FAILURE_HEAD_TYPES
            ):
                raise EventContractError(failure_head_order_message(stream_id))
            if (
                index == 0
                and expected_version == 0
                and is_coverage_stream(stream_id)
                and event.event_type != COVERAGE_RECORDED
            ):
                raise EventContractError(coverage_head_order_message(stream_id))
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
        head_type: str | None = None
        if is_failure_stream(stream_id):
            # The head decides the rules below: the batch's first event when the batch opens
            # the stream, which the order check above holds to a head, else the stored one.
            head_type = (
                pending[0].event_type
                if expected_version == 0
                else self._failure_head_type(stream_id)
            )
        self._require_unseen_observations(
            stream_id, pending, head_type=head_type, opening=expected_version == 0
        )
        if is_failure_stream(stream_id):
            # A failure stream needs schema 2 and a hold needs 3, and the store marks itself
            # in the same transaction as these events, so a rollback undoes both (ADR 0014).
            return self._store.append(
                stream_id,
                prepared,
                expected_version=expected_version,
                requires_schema=(
                    HELD_FAILURE_SCHEMA_VERSION
                    if head_type == FAILURE_HELD
                    else FAILURE_STREAM_SCHEMA_VERSION
                ),
            )
        if is_coverage_stream(stream_id):
            # A coverage stream needs schema 4, marked with its events in one transaction, so
            # a rollback undoes both (ADR 0015).
            return self._store.append(
                stream_id,
                prepared,
                expected_version=expected_version,
                requires_schema=COVERAGE_STREAM_SCHEMA_VERSION,
            )
        return self._store.append(stream_id, prepared, expected_version=expected_version)

    def _require_unseen_observations(
        self,
        stream_id: str,
        events: Sequence[PendingEvent],
        *,
        head_type: str | None = None,
        opening: bool = False,
    ) -> None:
        """Refuse a batch that would store one observation identifier twice.

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

        A failure stream is held to one more rule (ADR 0014): one observation identifier per
        digest across every failure stream. A system observation's identity is the digest
        and the instant, never the parser, so the same bytes failing under two parsers at
        one instant mint one observation, and storing it on both streams would rehydrate one
        failure twice. Finding the other failure streams of a digest reads the whole log,
        which is linear in its size and runs only for an append to a failure stream.

        A stream whose head is `failure.held` is the one exception, and the rule inverts for
        it (ADR 0014, amendment 2026-10-13): its observation must already be held, and the
        first stream holding it must open with `failure.recorded`. Holds are therefore one
        level deep, and the earliest stream of any identifier is a recorded failure. A batch
        that opens a hold with no observation names no holder, so it is refused too.
        `head_type` is the stream's head and `opening` says the batch writes it.

        A coverage stream is held to the same-stream rule alone (ADR 0015): its id is its gap
        record's fingerprint, so a record on any other coverage stream is refused as the
        gap record of another stream before it gets here.
        """

        incoming = [
            str(event.payload.get(OBSERVATION_ID_KEY))
            for event in events
            if event.event_type == OBSERVATION_RECORDED
        ]
        if not incoming:
            if opening and head_type == FAILURE_HELD:
                raise EventContractError(failure_hold_orphan_message(stream_id, None, None))
            return
        if not (
            is_artifact_stream(stream_id)
            or is_failure_stream(stream_id)
            or is_coverage_stream(stream_id)
        ):
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
                raise EventContractError(duplicate_observation_message(stream_id, observation_id))
            seen.add(observation_id)
        if not is_failure_stream(stream_id):
            return
        elsewhere = self.failure_observations_of_digest(stream_id)
        if head_type == FAILURE_HELD:
            for observation_id in incoming:
                holder = elsewhere.get(observation_id)
                if holder is None or self._failure_head_type(holder) != FAILURE_RECORDED:
                    raise EventContractError(
                        failure_hold_orphan_message(stream_id, observation_id, holder)
                    )
            return
        for observation_id in incoming:
            other = elsewhere.get(observation_id)
            if other is not None:
                raise EventContractError(
                    failure_duplicate_observation_message(stream_id, observation_id, other)
                )

    def _failure_head_type(self, stream_id: str) -> str | None:
        """Return the type of the first event one stream stores, or None when it is empty."""

        first = self._store.read_stream(stream_id, after_version=0, limit=1)
        return first[0].event_type if first else None

    def failure_observations_of_digest(self, stream_id: str) -> dict[str, str]:
        """Map each observation id on the other failure streams of one digest to its stream.

        The digest is the one `stream_id` names. The stream itself is left out, so the map
        answers "who else already holds this failure", which is the question the append
        check and `record_failure` both ask. Each identifier maps to the first other stream
        that records it in the log, which is the stream a hold is written beneath.
        """

        digest = failure_stream_components(stream_id)[0]
        prefix = f"{FAILURE_STREAM_PREFIX}/{digest}/"
        found: dict[str, str] = {}
        for record in self.read_all():
            if (
                record.event_type == OBSERVATION_RECORDED
                and record.stream_id != stream_id
                and record.stream_id.startswith(prefix)
            ):
                found.setdefault(str(record.payload.get(OBSERVATION_ID_KEY)), record.stream_id)
        return found

    def current_version(self, stream_id: str) -> int:
        """Return the current version of one stream, or zero when it does not exist."""

        return self._store.current_stream_version(stream_id)

    def read_stream(self, stream_id: str) -> tuple[EventRecord, ...]:
        """Read one whole stream in stream-version order, across pages."""

        records: list[EventRecord] = []
        after = 0
        while True:
            page = self._store.read_stream(stream_id, after_version=after, limit=READ_PAGE_SIZE)
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
            published = ", ".join(f"{name} v{version}" for name, version in sorted(EVENT_CONTRACTS))
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
        listed = bounded(", ".join(keys)) if keys else "nothing"
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
            f"runId must be {RUN_ID_PREFIX!r} followed by a canonical lowercase version-4 UUID"
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
        f"{event_type} records digest {shown(recorded[0])} read by {shown(recorded[1])} "
        f"version {shown(recorded[2])} on stream {stream_id!r}, which names digest "
        f"{expected[0]!r} read "
        f"by {expected[1]!r} version {expected[2]!r}"
    )


def failure_identity_breach(
    stream_id: str,
    event_type: str,
    payload: Mapping[str, Any],
) -> str | None:
    """Return why a failure-stream event is not about the failed reading its stream names.

    A failure stream id names the digest of the bytes and the parser whose reading failed
    (ADR 0014). Its head names the same three things, so the two have to agree, exactly as
    an artifact stream's do. Its one observation is the system record that failure mints:
    origin `system`, source type `complyroll.detection-process`, the builder's record id,
    tool, and parser, context key and resource id `sha256:<digest>`, and named by its
    derived id. The reader accepts a system observation under any identifier, so the
    derived id is checked here rather than assumed; a payload whose fingerprint is not its
    own is the reader's refusal to make. The fields the builder fixes and the fingerprint
    does not cover are checked as a gap record's are: disposition `open`, severity
    `unknown`, no source identifier or artifact, the title built from the digest, an empty
    description, and the one evidence id `sha256:<digest>`.

    The record's metadata is checked too, because the fingerprint covers none of it and
    replay renders `detectionFailures` from it: exactly `FAILURE_METADATA_KEYS`, the digest,
    parser, and version the stream id names, a size spelled as a count, a failure class,
    code list, clock, and rule from their vocabularies, and the class its codes name.
    Whether it agrees with the head takes both events, which is
    `failure_record_disagreement`'s business.

    A hold's head is held to its stream id exactly as a recorded head is (ADR 0014,
    amendment 2026-10-13): the fold reads the parser and version of either from its head,
    so a version the stream id does not carry would otherwise reach the fold unbounded.

    Returns None for an event no failure stream carries and for a stream of another kind,
    which are the stream-kind check's business rather than this one's.
    """

    if not is_failure_stream(stream_id) or event_type not in (
        *FAILURE_HEAD_TYPES,
        OBSERVATION_RECORDED,
    ):
        return None
    try:
        expected = failure_stream_components(stream_id)
    except ValueError as exc:
        return f"stream {stream_id!r} names no failed reading: {exc}"
    if event_type in FAILURE_HEAD_TYPES:
        recorded = tuple(payload.get(key) for key in ARTIFACT_IDENTITY_KEYS[ARTIFACT_INGESTED])
        if recorded == expected:
            return None
        return (
            f"{event_type} records digest {shown(recorded[0])} read by "
            f"{shown(recorded[1])} version {shown(recorded[2])} on stream {stream_id!r}, "
            "which names digest "
            f"{expected[0]!r} read by {expected[1]!r} version {expected[2]!r}"
        )
    problem = _system_record_problem(expected[0], payload)
    if problem is None:
        problem = _failure_metadata_problem(expected, payload.get("source_metadata"))
    if problem is None:
        return None
    return (
        f"{OBSERVATION_RECORDED} on failure stream {stream_id!r} is not the system record "
        f"of digest {expected[0]!r}: {problem}"
    )


def failure_record_disagreement(
    stream_id: str,
    head: Mapping[str, Any],
    observation: Mapping[str, Any],
    *,
    head_type: str = FAILURE_RECORDED,
) -> str | None:
    """Return why a failure head and its system record describe two different failures.

    The writer builds both from one classification of one reading (ADR 0014), so they name
    the same file, size, media type, failure class, codes, and clock. Each is checked
    against the stream id alone at append, which cannot see the other, so the fold and the
    audit, which read both, ask this. The head decides supersession and the record's
    metadata is what `detectionFailures` renders, so a store where they differ would report
    one failure and rank another. Both payloads are expected to have passed their own
    contract and `failure_identity_breach` already. `head_type` is the head's event type,
    which the message names; a hold's head and record agree exactly as a recorded one's do.
    """

    raw = observation.get("source_metadata")
    metadata: Mapping[str, Any] = raw if isinstance(raw, Mapping) else {}
    for head_key, metadata_key in _FAILURE_RECORD_PAIRS:
        recorded = head.get(head_key)
        described = metadata.get(metadata_key)
        if head_key == "sizeBytes":
            agrees = isinstance(recorded, int) and described == str(recorded)
        elif head_key == "failureCodes":
            agrees = isinstance(recorded, list) and decode_failure_codes(described) == tuple(
                recorded
            )
        else:
            agrees = described == recorded
        if not agrees:
            return (
                f"failure stream {stream_id!r} records {head_key} {shown(recorded)} in its "
                f"{head_type} and {metadata_key} {shown(described)} in its system "
                "record; "
                "the two describe one failure"
            )
    return None


def decode_failure_codes(text: Any) -> tuple[str, ...] | None:
    """Read a system record's `failure.codes` back, or return None when it is malformed.

    Well formed is exactly what the writer stores: `encode_list` of at least one code from
    `FAILURE_CODE_VALUES`, sorted and distinct, the classification's codes. The same list
    padded, escaped, or reordered is a spelling no writer emits, so it is refused, and a head
    whose `failureCodes` is out of order cannot agree with a record that reads back.
    """

    if not isinstance(text, str):
        return None
    try:
        decoded = json.loads(text)
    except (ValueError, RecursionError):
        return None
    if not isinstance(decoded, list) or not decoded:
        return None
    if not all(isinstance(code, str) and code in FAILURE_CODE_VALUES for code in decoded):
        return None
    if decoded != sorted(set(decoded)) or encode_list(decoded) != text:
        return None
    return tuple(decoded)


def failure_head_order_message(stream_id: str) -> str:
    """Word a failure stream whose first event is not its head, wherever it is reported.

    Shared by the refusal at append, the fold, and the audit, like the messages below.
    """

    return (
        f"failure stream {stream_id!r} does not open with its {FAILURE_RECORDED} or "
        f"{FAILURE_HELD} head; a failure stream is written head first"
    )


def failure_hold_orphan_message(
    stream_id: str,
    observation_id: str | None,
    holder: str | None,
) -> str:
    """Word a hold that no recorded failure holds the observation of, wherever it is reported.

    `observation_id` is None for a hold that carries no observation, and `holder` is None
    when no other failure stream of the digest records the observation; otherwise `holder`
    is the stream that records it first and does not open with `failure.recorded`. Worded
    once, like the messages above, so every place that reports an orphaned hold agrees.
    """

    if observation_id is None:
        found = "carries no system observation"
    elif holder is None:
        found = (
            f"records observation {shown(observation_id)}, which no other failure stream of "
            "the same digest records"
        )
    else:
        found = (
            f"records observation {shown(observation_id)}, which failure stream "
            f"{holder!r} records first without opening with its {FAILURE_RECORDED}"
        )
    return (
        f"failure stream {stream_id!r} opens with {FAILURE_HELD} and {found}; a hold is "
        f"written beneath the {FAILURE_RECORDED} stream that first records its observation"
    )


def _failure_metadata_problem(
    expected: tuple[str, str, str],
    raw: Any,
) -> str | None:
    """Return the first way a system record's metadata is not what its writer stores."""

    if not isinstance(raw, Mapping):
        return "its metadata is not an object"
    for key in FAILURE_METADATA_KEYS:
        if key not in raw:
            return f"its metadata has no {key!r}"
    for key in raw:
        if key not in FAILURE_METADATA_KEYS:
            return f"its metadata carries {shown(key)}, which a system record does not"
    for key, named in zip(
        ("artifact.sha256", "artifact.parser", "artifact.parserVersion"), expected, strict=True
    ):
        if raw[key] != named:
            return f"its metadata {key} is {shown(raw[key])}, where the stream names {named!r}"
    size = raw["artifact.sizeBytes"]
    if not isinstance(size, str) or _COUNT_TEXT.fullmatch(size) is None:
        return f"its metadata artifact.sizeBytes is {shown(size)}, not a count"
    if raw["failure.class"] not in _FAILURE_CLASS_VALUES:
        return f"its metadata failure.class is {shown(raw['failure.class'])}, not a failure class"
    codes = decode_failure_codes(raw["failure.codes"])
    if codes is None:
        return (
            f"its metadata failure.codes is {shown(raw['failure.codes'])}, not the compact JSON "
            "array of sorted, distinct failure codes its writer stores"
        )
    # The classifier derives the class from the codes, so a class they do not name is one no
    # reading was minted under, and the class decides which reading supersedes which.
    named = failure_class_for_codes(codes).value
    if raw["failure.class"] != named:
        return (
            f"its metadata failure.class is {shown(raw['failure.class'])}, and its "
            f"failure.codes {shown(raw['failure.codes'])} are those of class {named!r}"
        )
    if raw["failure.clock"] not in FAILURE_CLOCK_VALUES:
        return f"its metadata failure.clock is {shown(raw['failure.clock'])}, not a failure clock"
    if raw["failure.rule"] != DETECTION_FAILURE_RULE:
        return (
            f"its metadata failure.rule is {shown(raw['failure.rule'])}, "
            f"not {DETECTION_FAILURE_RULE!r}"
        )
    return None


def _system_record_problem(digest: str, payload: Mapping[str, Any]) -> str | None:
    """Return the first way one observation payload is not a digest's system record."""

    reference = f"sha256:{digest}"
    resource = payload.get("resource")
    resource_id = resource.get("resource_id") if isinstance(resource, Mapping) else None
    derived = f"obs-{payload.get('fingerprint')}"
    if payload.get("origin") != ObservationOrigin.SYSTEM.value:
        return f"its origin is {shown(payload.get('origin'))}"
    if payload.get("source_type") != DETECTION_FAILURE_SOURCE_TYPE:
        return f"its source type is {shown(payload.get('source_type'))}"
    if payload.get("source_record_id") != DETECTION_FAILURE_RECORD_ID:
        return f"its source record id is {shown(payload.get('source_record_id'))}"
    if payload.get("source_tool") != DETECTION_FAILURE_SOURCE_TOOL:
        return f"its source tool is {shown(payload.get('source_tool'))}"
    parser = (payload.get("parser_name"), payload.get("parser_version"))
    if parser != (DETECTION_FAILURE_PARSER_NAME, DETECTION_FAILURE_PARSER_VERSION):
        return f"its parser is {shown(parser[0])} version {shown(parser[1])}"
    if payload.get("context_key") != reference:
        return f"its context key is {shown(payload.get('context_key'))}"
    if resource_id != reference:
        return f"its resource id is {shown(resource_id)}"
    if payload.get(OBSERVATION_ID_KEY) != derived:
        return (
            f"its id is {shown(payload.get(OBSERVATION_ID_KEY))}, not its derived id "
            f"{shown(derived)}"
        )
    # The builder fixes these, as it fixes a gap record's, and a report reads each of them
    # back from the record: a record edited to `pass` drops out of `detectionFailures`.
    if payload.get("disposition") != ObservationDisposition.OPEN.value:
        return f"its disposition is {shown(payload.get('disposition'))}"
    if payload.get("source_severity") != SourceSeverity.UNKNOWN.value:
        return f"its source severity is {shown(payload.get('source_severity'))}"
    if payload.get("source_identifiers") != []:
        return f"its source identifiers are {shown(payload.get('source_identifiers'))}"
    # The report prints the title as the vulnerability description.
    if payload.get("title") != DETECTION_FAILURE_TITLE.format(digest=digest):
        return f"its title is {shown(payload.get('title'))}"
    if payload.get("description") != "":
        return f"its description is {shown(payload.get('description'))}"
    # NOTE: The observation contract refuses either artifact field on a system record first,
    # so on a store path these two answer only a direct call.
    if payload.get("source_artifact_digest") != "":
        return f"its source artifact digest is {shown(payload.get('source_artifact_digest'))}"
    if payload.get("source_artifact_name") != "":
        return f"its source artifact name is {shown(payload.get('source_artifact_name'))}"
    if payload.get("evidence_ids") != [reference]:
        return f"its evidence ids are {shown(payload.get('evidence_ids'))}"
    return None


def coverage_stream_id_of(observation: Observation) -> str:
    """Return the one stream a gap record is recorded on, `coverage/<its fingerprint>`.

    The writer names a gap's stream with it, and `coverage_record_problem` recomputes a
    stored record's with it, so both name a gap's stream one way (ADR 0015).
    """

    if not isinstance(observation, Observation):
        raise TypeError("observation must be an Observation")
    if (
        observation.origin is not ObservationOrigin.SYSTEM
        or observation.source_type != COVERAGE_SOURCE_TYPE
    ):
        raise ValueError(
            f"only a system record of source type {COVERAGE_SOURCE_TYPE!r} names a coverage stream"
        )
    return coverage_stream_id(observation.fingerprint)


def coverage_stream_id_of_payload(payload: Mapping[str, Any]) -> str:
    """Recompute the stream one recorded gap record names, reading it back as replay does.

    The fingerprint is rebuilt from the record's own fields rather than read from the
    payload's `fingerprint`, which the reader holds equal to it anyway.
    """

    try:
        observation = Observation.from_canonical_dict(payload)
    except (TypeError, ValueError) as exc:
        raise ValueError(f"the payload is not a readable observation: {exc}") from exc
    return coverage_stream_id_of(observation)


def coverage_head_payload(observation: Observation) -> dict[str, str]:
    """Return the `coverage.recorded` head of one gap record, read off the record itself.

    Built from the record, so a head and its record agree by construction; the writer and
    every test that stages a coverage stream share it.
    """

    coverage_stream_id_of(observation)
    metadata = dict(observation.source_metadata)
    missing = [key for key in COVERAGE_METADATA_KEYS if key not in metadata]
    if missing:
        raise ValueError(f"the gap record's metadata has no {', '.join(missing)}")
    head: dict[str, str] = {}
    for head_key, record_key in _COVERAGE_RECORD_PAIRS:
        if record_key == "context_key":
            head[head_key] = observation.context_key
        else:
            head[head_key] = metadata[record_key]
    return head


def coverage_record_problem(
    stream_id: str,
    event_type: str,
    payload: Mapping[str, Any],
) -> tuple[str, str] | None:
    """Return the audit code and message for a coverage-stream event its stream does not name.

    A coverage stream id is its gap record's fingerprint (ADR 0015), so either event on a
    stream whose id names none is a `coverage_stream_mismatch`. The record must be the gap
    record a closed window mints: origin `system`, the coverage source type, tool, parser,
    and record id, its derived id, disposition `open`, severity `unknown`, the builder's
    description, and no source identifier or artifact, else a `coverage_identity_breach`;
    the gap record whose fingerprint the stream names, else a `coverage_stream_mismatch`; and
    exactly `COVERAGE_METADATA_KEYS`, with the window close and rule its own identity names,
    the one evidence id its inventory digest names, and the values `_gap_metadata_problem`
    holds, the title included, else a `coverage_identity_breach`. The
    fingerprint covers none of the fixed fields, so they are checked here. The repository
    refuses each at append with the message, and the audit reports each under its code.
    Whether the head agrees with the record takes both events, which is
    `coverage_record_disagreement`'s business.

    Returns None for an event no coverage stream carries and for a stream of another kind,
    which are the stream-kind check's business rather than this one's.
    """

    if not is_coverage_stream(stream_id) or event_type not in (
        COVERAGE_RECORDED,
        OBSERVATION_RECORDED,
    ):
        return None
    try:
        coverage_stream_fingerprint(stream_id)
    except ValueError as exc:
        return ("coverage_stream_mismatch", f"stream {stream_id!r} names no gap record: {exc}")
    if event_type == COVERAGE_RECORDED:
        return None
    described = f"{OBSERVATION_RECORDED} on coverage stream {stream_id!r}"
    problem = _gap_record_problem(payload)
    if problem is not None:
        return ("coverage_identity_breach", f"{described} is not a coverage gap record: {problem}")
    try:
        recomputed = coverage_stream_id_of_payload(payload)
    except ValueError as exc:
        return ("coverage_identity_breach", f"{described} is not a coverage gap record: {exc}")
    if recomputed != stream_id:
        return (
            "coverage_stream_mismatch",
            f"{described} is the gap record of stream {recomputed!r}; a coverage stream is "
            "named for its gap record's fingerprint",
        )
    problem = _gap_metadata_problem(payload)
    if problem is not None:
        return ("coverage_identity_breach", f"{described} is not a coverage gap record: {problem}")
    return None


def coverage_record_disagreement(
    stream_id: str,
    head: Mapping[str, Any],
    observation: Mapping[str, Any],
) -> str | None:
    """Return why a coverage head and its gap record describe two different gaps.

    The writer reads the head off the record (`coverage_head_payload`), so the two name the
    same rule, context key, window close, anchor, and inventory digest. Each is checked
    alone at append, which cannot see the other, so the fold and the audit, which read
    both, ask this. Both payloads are expected to have passed their own contract and
    `coverage_record_problem` already.
    """

    raw = observation.get("source_metadata")
    metadata: Mapping[str, Any] = raw if isinstance(raw, Mapping) else {}
    for head_key, record_key in _COVERAGE_RECORD_PAIRS:
        recorded = head.get(head_key)
        described = (
            observation.get(record_key) if record_key == "context_key" else metadata.get(record_key)
        )
        if described != recorded:
            return (
                f"coverage stream {stream_id!r} records {head_key} {shown(recorded)} in its "
                f"{COVERAGE_RECORDED} and {record_key} {shown(described)} in its gap record; "
                "the two describe one gap"
            )
    return None


def coverage_head_order_message(stream_id: str) -> str:
    """Word a coverage stream whose first event is not its head, wherever it is reported."""

    return (
        f"coverage stream {stream_id!r} does not open with its {COVERAGE_RECORDED} head; a "
        "coverage stream is written head first"
    )


def _gap_record_problem(payload: Mapping[str, Any]) -> str | None:
    """Return the first way one observation payload is not a coverage gap record."""

    derived = f"obs-{payload.get('fingerprint')}"
    if payload.get("origin") != ObservationOrigin.SYSTEM.value:
        return f"its origin is {shown(payload.get('origin'))}"
    if payload.get("source_type") != COVERAGE_SOURCE_TYPE:
        return f"its source type is {shown(payload.get('source_type'))}"
    if payload.get("source_record_id") != COVERAGE_RECORD_ID:
        return f"its source record id is {shown(payload.get('source_record_id'))}"
    if payload.get("source_tool") != COVERAGE_SOURCE_TOOL:
        return f"its source tool is {shown(payload.get('source_tool'))}"
    parser = (payload.get("parser_name"), payload.get("parser_version"))
    if parser != (COVERAGE_PARSER_NAME, COVERAGE_PARSER_VERSION):
        return f"its parser is {shown(parser[0])} version {shown(parser[1])}"
    if payload.get(OBSERVATION_ID_KEY) != derived:
        return (
            f"its id is {shown(payload.get(OBSERVATION_ID_KEY))}, not its derived id "
            f"{shown(derived)}"
        )
    # The builder fixes these, and a report reads each of them back from the record.
    if payload.get("disposition") != ObservationDisposition.OPEN.value:
        return f"its disposition is {shown(payload.get('disposition'))}"
    if payload.get("source_severity") != SourceSeverity.UNKNOWN.value:
        return f"its source severity is {shown(payload.get('source_severity'))}"
    if payload.get("source_identifiers") != []:
        return f"its source identifiers are {shown(payload.get('source_identifiers'))}"
    if payload.get("description") != COVERAGE_DESCRIPTION:
        return f"its description is {shown(payload.get('description'))}"
    # NOTE: The observation contract refuses either artifact field on a system record first,
    # so on a store path these two answer only a direct call.
    if payload.get("source_artifact_digest") != "":
        return f"its source artifact digest is {shown(payload.get('source_artifact_digest'))}"
    if payload.get("source_artifact_name") != "":
        return f"its source artifact name is {shown(payload.get('source_artifact_name'))}"
    return None


def _gap_metadata_problem(payload: Mapping[str, Any]) -> str | None:
    """Return the first way a gap record's metadata is not what its writer stores.

    Exactly the eight keys, and the two that restate the record's identity agree with it:
    the window close is the instant the record is observed at, and the rule leads its
    context key. The record's one evidence id names the inventory digest. The anchor is an
    instant spelled as the writer spells it and precedes the close, the force is a rule
    force, the job is the one the context key names (empty when the key names the record's
    resource), the title is the one the rule, the resource and the close build, and the
    basis is a text the writer records. The head names the anchor too,
    which `coverage_record_disagreement` holds it to.
    """

    raw = payload.get("source_metadata")
    if not isinstance(raw, Mapping):
        return "its metadata is not an object"
    for key in COVERAGE_METADATA_KEYS:
        if key not in raw:
            return f"its metadata has no {key!r}"
    for key in raw:
        if key not in COVERAGE_METADATA_KEYS:
            return f"its metadata carries {shown(key)}, which a gap record does not"
    observed = payload.get("observed_at")
    observed_text = None if not isinstance(observed, str) else iso_utc(parse_utc(observed))
    if raw["coverage.windowClosedAt"] != observed_text:
        return (
            f"its metadata coverage.windowClosedAt is {shown(raw['coverage.windowClosedAt'])}, "
            f"where the record is observed at {shown(observed_text)}"
        )
    context_key = payload.get("context_key")
    rule = raw["coverage.rule"]
    if not isinstance(context_key, str) or not context_key.startswith(f"{rule}:"):
        return (
            f"its metadata coverage.rule is {shown(rule)}, and its context key "
            f"{shown(context_key)} does not lead with it"
        )
    evidence = [f"sha256:{raw['coverage.inventorySha256']}"]
    if payload.get("evidence_ids") != evidence:
        return (
            f"its evidence ids are {shown(payload.get('evidence_ids'))}, where its metadata "
            f"coverage.inventorySha256 names {shown(evidence)}"
        )
    # The window runs from its anchor to its close, and no rule's timeframe is empty.
    anchor_at = _canonical_instant(raw["coverage.anchorAt"])
    if anchor_at is None:
        return (
            f"its metadata coverage.anchorAt is {shown(raw['coverage.anchorAt'])}, not an "
            "instant as its writer spells one"
        )
    if observed_text is None or anchor_at >= parse_utc(observed_text):
        return (
            f"its metadata coverage.anchorAt is {shown(raw['coverage.anchorAt'])}, which does "
            f"not precede its window close {shown(observed_text)}"
        )
    if raw["coverage.force"] not in _RULE_FORCE_VALUES:
        return f"its metadata coverage.force is {shown(raw['coverage.force'])}, not a rule force"
    # A job names the case its context key keys the gap to; with none, the resource does.
    job = raw["coverage.job"]
    resource = payload.get("resource")
    subject = (
        (resource.get("resource_type"), resource.get("resource_id"))
        if isinstance(resource, Mapping)
        else (None, None)
    )
    keyed = f"{rule}:job:{job}" if job else f"{rule}:resource:{subject[0]}:{subject[1]}"
    if context_key != keyed:
        return (
            f"its metadata coverage.job is {shown(job)}, and its context key "
            f"{shown(context_key)} is not {shown(keyed)}"
        )
    # The title restates the rule, the resource and the close, so it is checked once they are.
    title = COVERAGE_TITLE.format(
        rule=rule,
        resource_type=subject[0],
        resource_id=subject[1],
        closed_at=raw["coverage.windowClosedAt"],
    )
    if payload.get("title") != title:
        return f"its title is {shown(payload.get('title'))}"
    if raw["coverage.basis"] not in COVERAGE_BASIS_TEXTS:
        return (
            f"its metadata coverage.basis is {shown(raw['coverage.basis'])}, not a basis its "
            "writer records"
        )
    return None


def _canonical_instant(value: Any) -> datetime | None:
    """Return an instant spelled exactly as `iso_utc` spells it, or None for any other text."""

    if not isinstance(value, str):
        return None
    try:
        parsed = parse_utc(value)
    except ValueError:
        return None
    return parsed if iso_utc(parsed) == value else None


def duplicate_observation_message(stream_id: str, observation_id: str) -> str:
    """Word one stream holding the same observation twice, wherever it is reported.

    The same wording is used by the refusal at append, by the fold, and by
    `complyroll.history.audit_history`, so one damaged stream describes itself the same way
    whichever command an operator reaches it through.
    """

    if is_failure_stream(stream_id):
        kind = "failure"
    elif is_coverage_stream(stream_id):
        kind = "coverage"
    else:
        kind = "artifact"
    return (
        f"{kind} stream {stream_id!r} records observation {shown(observation_id)} more than "
        "once; the same finding would be rehydrated twice"
    )


def failure_duplicate_observation_message(
    stream_id: str, observation_id: str, other_stream_id: str
) -> str:
    """Word two failure streams of one digest holding the same system observation.

    Shared by the refusal at append, the fold, and the audit, like the message above.
    """

    return (
        f"failure stream {stream_id!r} records observation {shown(observation_id)}, which "
        f"failure stream {other_stream_id!r} of the same digest already records; one "
        "failure would be rehydrated twice"
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
    through the artifact identity the stream id spells out. A failure stream's head and its
    system observation are held to the failed reading the stream id spells out (ADR 0014),
    and a coverage stream's gap record to the fingerprint its stream id spells out (ADR 0015).
    """

    if not event_belongs_on_stream(event_type, stream_id):
        kind = stream_kind(stream_id)
        described = (
            "not an artifact, case, failure, or coverage stream"
            if kind is None
            else f"a {kind} stream"
        )
        raise EventContractError(
            f"event {event_type!r} does not belong on stream {stream_id!r}, which is {described}"
        )
    breach = artifact_identity_breach(stream_id, event_type, payload)
    if breach is None:
        breach = failure_identity_breach(stream_id, event_type, payload)
    if breach is None:
        problem = coverage_record_problem(stream_id, event_type, payload)
        breach = None if problem is None else problem[1]
    if breach is not None:
        raise EventContractError(breach)
    if event_type != CASE_CREATED:
        return
    try:
        expected = tracking_id_from_stream(stream_id)
    except ValueError as exc:
        raise EventContractError(
            f"{CASE_CREATED} cannot be stored on stream {shown(stream_id)}: {exc}"
        ) from exc
    recorded = payload.get("trackingId")
    if recorded != expected:
        raise EventContractError(
            f"{CASE_CREATED} records tracking id {shown(recorded)} on stream "
            f"{shown(stream_id)}, which names {expected!r}"
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
        raise EventContractError(
            f"{event_type} version {event_version} payload is invalid: {_rendered_issues(issues)}",
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


def _issue_message(error: ValidationError) -> str:
    """Return jsonschema's message with each long stored value it quotes cut by `shown`.

    jsonschema quotes the failing instance, and an object's unexpected keys, in full.
    """

    message = str(error.message)
    instance = error.instance
    quoted = [instance, *instance] if isinstance(instance, Mapping) else [instance]
    for value in quoted:
        text = repr(value)
        if len(text) > SHOWN_LIMIT:
            message = message.replace(text, shown(value))
    return message


def _json_pointer(parts: Any) -> str:
    encoded = (str(part).replace("~", "~0").replace("/", "~1") for part in parts)
    return "".join(f"/{part}" for part in encoded)


__all__ = [
    "ARTIFACT_IDENTITY_KEYS",
    "COVERAGE_BASIS_TEXTS",
    "COVERAGE_DESCRIPTION",
    "COVERAGE_METADATA_KEYS",
    "COVERAGE_PARSER_NAME",
    "COVERAGE_PARSER_VERSION",
    "COVERAGE_RECORD_ID",
    "COVERAGE_SOURCE_TOOL",
    "COVERAGE_SOURCE_TYPE",
    "COVERAGE_TITLE",
    "FAILURE_HEAD_TYPES",
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
    "coverage_head_order_message",
    "coverage_head_payload",
    "coverage_record_disagreement",
    "coverage_record_problem",
    "coverage_stream_id_of",
    "coverage_stream_id_of_payload",
    "duplicate_observation_message",
    "failure_duplicate_observation_message",
    "failure_hold_orphan_message",
    "failure_identity_breach",
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
