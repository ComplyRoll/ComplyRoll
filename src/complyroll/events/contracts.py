"""Published payload contracts for ComplyRoll domain events (ADR 0008 Decisions 1 and 2).

Every event a writer appends has a version-1 JSON Schema in `EVENT_CONTRACTS`. The
schemas are Draft 2020-12 documents with `additionalProperties: false` and exact
`required` lists, so an event that gains or loses a field needs a new event version
and a reader for both. The store stays a generic envelope log; this module is where
an event's meaning is written down.

Timestamps are RFC 3339. Everything a writer generates is normalized to UTC `Z` form
by `iso_utc`; `observation.recorded` is the one exception, because it stores exactly
`Observation.to_canonical_dict()` and that dictionary preserves each source offset.
"""

from __future__ import annotations

import re
from collections.abc import Mapping
from datetime import UTC, datetime
from typing import Any, Final

from complyroll.models import (
    CaseStatus,
    ObservationDisposition,
    ObservationOrigin,
    SourceSeverity,
)

#: Statuses that record a disposition. `new`, `evaluating`, and `active` are not
#: dispositions, so `case.disposition_recorded` refuses them (ADR 0008 Decision 2).
UNDISPOSED_STATUSES: Final = frozenset(
    {CaseStatus.NEW, CaseStatus.EVALUATING, CaseStatus.ACTIVE}
)

DISPOSITION_STATUS_VALUES: Final[tuple[str, ...]] = tuple(
    status.value for status in CaseStatus if status not in UNDISPOSED_STATUSES
)

#: The statuses a `closed` case may close as. Mirrors `reports.evaluations`
#: `CLOSED_DISPOSITIONS` without importing the report layer into the event layer.
CLOSED_DISPOSITION_VALUES: Final[tuple[str, ...]] = (
    "fully_mitigated",
    "partially_mitigated",
    "false_positive",
    "remediated",
    "accepted",
)

ARTIFACT_STREAM_PREFIX: Final = "artifact"
CASE_STREAM_PREFIX: Final = "case"
TRACKING_ID_PATTERN: Final = re.compile(r"^case-[0-9a-f]{16}$")

#: Stream-id components may not contain the separator, so a stream id parses back.
_COMPONENT_PATTERN: Final = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]*$")
_SHA256_PATTERN: Final = re.compile(r"^[0-9a-f]{64}$")
_MAX_STREAM_ID_LENGTH: Final = 500

_UTC_TIMESTAMP_REGEX: Final = r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(\.\d{1,6})?Z$"
#: RFC 3339 offsets are hours and minutes. Python parses an offset carrying seconds
#: and re-serializes it unchanged, so nothing downstream would catch one that got in.
_RFC3339_REGEX: Final = (
    r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(\.\d{1,6})?(Z|[+-]\d{2}:\d{2})$"
)
#: Exactly what `datetime.isoformat()` writes for an aware datetime, which is exactly
#: what `Observation.to_canonical_dict` stores and `from_canonical_dict` will read
#: back: no `Z` suffix, a fraction of exactly six digits or none at all, and an offset
#: of whole minutes. A looser pattern would let the repository store history the
#: replay reader refuses (ADR 0008, "stored text is canonical or rejected").
_CANONICAL_TIMESTAMP_REGEX: Final = (
    r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(\.\d{6})?[+-]\d{2}:\d{2}$"
)

_UTC_TIMESTAMP: Final[dict[str, Any]] = {"type": "string", "pattern": _UTC_TIMESTAMP_REGEX}
_NULLABLE_RFC3339: Final[dict[str, Any]] = {
    "type": ["string", "null"],
    "pattern": _RFC3339_REGEX,
}
_CANONICAL_TIMESTAMP: Final[dict[str, Any]] = {
    "type": "string",
    "pattern": _CANONICAL_TIMESTAMP_REGEX,
}
_NULLABLE_CANONICAL_TIMESTAMP: Final[dict[str, Any]] = {
    "type": ["string", "null"],
    "pattern": _CANONICAL_TIMESTAMP_REGEX,
}
_TEXT: Final[dict[str, Any]] = {"type": "string"}
_NON_EMPTY_TEXT: Final[dict[str, Any]] = {"type": "string", "minLength": 1}
_NULLABLE_NON_EMPTY_TEXT: Final[dict[str, Any]] = {"type": ["string", "null"], "minLength": 1}
#: At least one character that is not whitespace. `minLength: 1` counts three spaces as
#: text, and a rationale of three spaces is no rationale: the vulnerability it routes out
#: of the detail report still says nothing about why the risk was accepted. JSON Schema
#: `pattern` is a search rather than an anchored match, and it ignores a null, so this
#: constrains a string without disturbing the nullable half of the type.
_NON_BLANK_PATTERN: Final = r"\S"
_NULLABLE_NON_BLANK_TEXT: Final[dict[str, Any]] = {
    "type": ["string", "null"],
    "minLength": 1,
    "pattern": _NON_BLANK_PATTERN,
}
_SHA256: Final[dict[str, Any]] = {"type": "string", "pattern": r"^[0-9a-f]{64}$"}
#: System observations carry no artifact, so their digest field is the empty string.
_OPTIONAL_SHA256: Final[dict[str, Any]] = {"type": "string", "pattern": r"^([0-9a-f]{64})?$"}
_PAIN: Final[dict[str, Any]] = {"type": "integer", "minimum": 1, "maximum": 5}
_COUNT: Final[dict[str, Any]] = {"type": "integer", "minimum": 0}
_TRACKING_ID: Final[dict[str, Any]] = {"type": "string", "pattern": r"^case-[0-9a-f]{16}$"}
_STRING_ARRAY: Final[dict[str, Any]] = {"type": "array", "items": _NON_EMPTY_TEXT}

_DIAGNOSTIC: Final[dict[str, Any]] = {
    "type": "object",
    "additionalProperties": False,
    "required": ["level", "code", "message"],
    "properties": {
        "level": {"enum": ["info", "warning", "error"]},
        "code": _NON_EMPTY_TEXT,
        "message": _NON_EMPTY_TEXT,
        "location": _NON_EMPTY_TEXT,
    },
}


def _schema(name: str, properties: dict[str, Any]) -> dict[str, Any]:
    """Build one strict version-1 contract whose required list is every property."""

    return {
        "$schema": "https://json-schema.org/draft/2020-12/schema",
        "$id": f"https://complyroll.invalid/events/{name}/1",
        "title": name,
        "type": "object",
        "additionalProperties": False,
        "required": list(properties),
        "properties": properties,
    }


ARTIFACT_INGESTED_V1: Final[dict[str, Any]] = _schema(
    "artifact.ingested",
    {
        "name": _NON_EMPTY_TEXT,
        "sha256": _SHA256,
        "sizeBytes": _COUNT,
        "mediaType": _NON_EMPTY_TEXT,
        "parserName": _NON_EMPTY_TEXT,
        "parserVersion": _NON_EMPTY_TEXT,
        "ingestedAt": _UTC_TIMESTAMP,
        "observationCount": _COUNT,
        "diagnostics": {"type": "array", "items": _DIAGNOSTIC},
    },
)

#: Exactly `Observation.to_canonical_dict()` (ADR 0002), frozen as a stored contract.
#: Keys stay snake_case because the dictionary is the observation's canonical form,
#: not a report projection.
OBSERVATION_RECORDED_V1: Final[dict[str, Any]] = _schema(
    "observation.recorded",
    {
        "observation_id": _NON_EMPTY_TEXT,
        "fingerprint": _SHA256,
        "source_type": _NON_EMPTY_TEXT,
        "source_tool": _NON_EMPTY_TEXT,
        "parser_name": _NON_EMPTY_TEXT,
        "parser_version": _NON_EMPTY_TEXT,
        "source_record_id": _NON_EMPTY_TEXT,
        "resource": {
            "type": "object",
            "additionalProperties": False,
            "required": ["resource_id", "resource_type"],
            "properties": {
                "resource_id": _NON_EMPTY_TEXT,
                "resource_type": _NON_EMPTY_TEXT,
            },
        },
        "observed_at": _NULLABLE_CANONICAL_TIMESTAMP,
        "ingested_at": _CANONICAL_TIMESTAMP,
        "disposition": {"enum": [member.value for member in ObservationDisposition]},
        "source_severity": {"enum": [member.value for member in SourceSeverity]},
        "title": _TEXT,
        "description": _TEXT,
        "source_artifact_digest": _OPTIONAL_SHA256,
        "source_artifact_name": _TEXT,
        "source_identifiers": {**_STRING_ARRAY, "uniqueItems": True},
        "source_metadata": {"type": "object", "additionalProperties": _TEXT},
        "evidence_ids": _STRING_ARRAY,
        "context_key": _TEXT,
        "origin": {"enum": [member.value for member in ObservationOrigin]},
    },
)

CASE_CREATED_V1: Final[dict[str, Any]] = _schema(
    "case.created",
    {
        "trackingId": _TRACKING_ID,
        "sourceType": _NON_EMPTY_TEXT,
        "sourceRecordId": _NON_EMPTY_TEXT,
        "contextKey": _TEXT,
        "title": _NON_EMPTY_TEXT,
        "description": _NON_EMPTY_TEXT,
        "createdAt": _UTC_TIMESTAMP,
    },
)

CASE_OBSERVATION_LINKED_V1: Final[dict[str, Any]] = _schema(
    "case.observation_linked",
    {
        "observationId": _NON_EMPTY_TEXT,
        "resourceId": _NON_EMPTY_TEXT,
        "resourceType": _NON_EMPTY_TEXT,
        "observedAt": _NULLABLE_RFC3339,
        "sourceTool": _NON_EMPTY_TEXT,
        "sourceArtifactSha256": _OPTIONAL_SHA256,
        "sourceIdentifiers": _STRING_ARRAY,
    },
)

DETECTION_ATTESTED_V1: Final[dict[str, Any]] = _schema(
    "detection.attested",
    {
        "detectedAt": _UTC_TIMESTAMP,
        "rationale": _NON_EMPTY_TEXT,
        "attestedAt": _UTC_TIMESTAMP,
    },
)

CASE_EVALUATED_V1: Final[dict[str, Any]] = _schema(
    "case.evaluated",
    {
        "completedAt": _UTC_TIMESTAMP,
        "isInternetReachable": {"type": "boolean"},
        "isLikelyExploitable": {"type": "boolean"},
        "pain": _PAIN,
        "potentialAgencyImpact": _NON_EMPTY_TEXT,
        "rationale": _NON_EMPTY_TEXT,
        "evaluator": _NON_EMPTY_TEXT,
        "isFalsePositive": {"type": "boolean"},
        "supplementaryRiskInformation": _NULLABLE_NON_EMPTY_TEXT,
        "projectedNextReduction": {
            "type": ["object", "null"],
            "additionalProperties": False,
            "required": ["estimatedAt", "targetRating"],
            "properties": {"estimatedAt": _UTC_TIMESTAMP, "targetRating": _PAIN},
        },
    },
)

CASE_PAIN_REDUCED_V1: Final[dict[str, Any]] = _schema(
    "case.pain_reduced",
    {"reducedAt": _UTC_TIMESTAMP, "rating": _PAIN},
)

#: The consistency `reports.evaluations` requires of an evaluations entry, written as
#: schema so the repository refuses at append what no evaluations file could have
#: produced. Without these the log could hold a `closed` case that names nothing it
#: closed as, or a vulnerability routed out of the detail report as accepted with no
#: rationale for accepting it. The `acceptanceRationale` property itself carries
#: `_NON_BLANK_PATTERN`, so "a rationale" here means text with something in it: the pair
#: of rules is what the fold used to re-check on the way back out.
_DISPOSITION_CONSISTENCY: Final[tuple[dict[str, Any], ...]] = (
    {
        "if": {"required": ["status"], "properties": {"status": {"const": "closed"}}},
        "then": {"properties": {"closedDisposition": {"type": "string"}}},
        "else": {"properties": {"closedDisposition": {"type": "null"}}},
    },
    {
        "if": {
            "anyOf": [
                {
                    "required": ["status"],
                    "properties": {"status": {"const": "accepted"}},
                },
                {
                    "required": ["status", "closedDisposition"],
                    "properties": {
                        "status": {"const": "closed"},
                        "closedDisposition": {"const": "accepted"},
                    },
                },
            ]
        },
        "then": {"properties": {"acceptanceRationale": {"type": "string"}}},
        "else": {"properties": {"acceptanceRationale": {"type": "null"}}},
    },
)

CASE_DISPOSITION_RECORDED_V1: Final[dict[str, Any]] = {
    **_schema(
        "case.disposition_recorded",
        {
            "status": {"enum": list(DISPOSITION_STATUS_VALUES)},
            "closedDisposition": {"enum": [*CLOSED_DISPOSITION_VALUES, None]},
            "acceptanceRationale": _NULLABLE_NON_BLANK_TEXT,
            "recordedAt": _UTC_TIMESTAMP,
        },
    ),
    "allOf": list(_DISPOSITION_CONSISTENCY),
}

CASE_IDENTIFIED_V1: Final[dict[str, Any]] = _schema(
    "case.identified",
    {"providerTrackingId": _NON_EMPTY_TEXT},
)

#: The one registry every writer validates against (ADR 0008 Decision 1).
EVENT_CONTRACTS: Final[dict[tuple[str, int], dict[str, Any]]] = {
    ("artifact.ingested", 1): ARTIFACT_INGESTED_V1,
    ("observation.recorded", 1): OBSERVATION_RECORDED_V1,
    ("case.created", 1): CASE_CREATED_V1,
    ("case.observation_linked", 1): CASE_OBSERVATION_LINKED_V1,
    ("detection.attested", 1): DETECTION_ATTESTED_V1,
    ("case.evaluated", 1): CASE_EVALUATED_V1,
    ("case.pain_reduced", 1): CASE_PAIN_REDUCED_V1,
    ("case.disposition_recorded", 1): CASE_DISPOSITION_RECORDED_V1,
    ("case.identified", 1): CASE_IDENTIFIED_V1,
}

EVENT_TYPES: Final[tuple[str, ...]] = tuple(
    sorted({event_type for event_type, _ in EVENT_CONTRACTS})
)

#: The event types an artifact stream may carry, and the ones a case stream may carry
#: (ADR 0008 Decision 2). An event stored on the other kind of stream is not history the
#: replay can read: it would be silently ignored there while `store verify` called the log
#: healthy, so the repository refuses the combination at append.
ARTIFACT_STREAM_EVENT_TYPES: Final[frozenset[str]] = frozenset(
    {"artifact.ingested", "observation.recorded"}
)
CASE_STREAM_EVENT_TYPES: Final[frozenset[str]] = frozenset(
    name for name in EVENT_TYPES if name.startswith("case.") or name == "detection.attested"
)

if ARTIFACT_STREAM_EVENT_TYPES | CASE_STREAM_EVENT_TYPES != frozenset(EVENT_TYPES) or (
    ARTIFACT_STREAM_EVENT_TYPES & CASE_STREAM_EVENT_TYPES
):  # pragma: no cover - guards against a new event type nobody placed on a stream
    raise ValueError("every published event type must belong to exactly one stream kind")

#: The patterns that mark a property as an instant the repository parses semantically.
#: A regular expression proves a shape, not a date: `2026-02-30T12:00:00Z` and
#: `2026-08-01T25:00:00Z` both match and neither exists. `observation.recorded` is
#: deliberately absent, because its two timestamps carry the canonical pattern and are read
#: back through `Observation.from_canonical_dict`, which is stricter than parsing.
_SEMANTIC_TIMESTAMP_PATTERNS: Final[frozenset[str]] = frozenset(
    {_UTC_TIMESTAMP_REGEX, _RFC3339_REGEX}
)

#: Keywords whose value is a list of subschemas applied to the same instance.
_BRANCH_LIST_KEYWORDS: Final[tuple[str, ...]] = ("oneOf", "anyOf", "allOf")
#: Keywords whose value is one subschema applied to the same instance.
_BRANCH_KEYWORDS: Final[tuple[str, ...]] = ("if", "then", "else")
#: Keywords whose value maps a name to a subschema applied to the same instance. A
#: `dependentSchemas` entry is a `then` that fires on a property being present.
_BRANCH_MAP_KEYWORDS: Final[tuple[str, ...]] = ("dependentSchemas",)
#: Keywords whose value constrains the items of an array rather than one named value.
#: `items` and `prefixItems` may each hold a list of subschemas as well as one.
_ARRAY_KEYWORDS: Final[tuple[str, ...]] = ("contains", "items", "prefixItems")


def _reference_location(node: Any, pointer: str = "") -> str | None:
    """Return where a `$ref` sits anywhere in one schema document, or None when none does.

    The walk below visits the keywords the published contracts use. A `$ref` under a
    keyword it does not visit (`additionalProperties`, `patternProperties`, `not`, `$defs`,
    and the rest) would therefore import clean and take whatever the reference carried out
    of the parsed set in silence, so the whole document is scanned for one first rather
    than only the parts the walk happens to reach.
    """

    if isinstance(node, Mapping):
        if "$ref" in node:
            return pointer or "<root>"
        for name, value in node.items():
            found = _reference_location(value, f"{pointer}/{name}")
            if found is not None:
                return found
    elif isinstance(node, (list, tuple)):
        for index, value in enumerate(node):
            found = _reference_location(value, f"{pointer}/{index}")
            if found is not None:
                return found
    return None


def _contract_timestamp_pointers(schema: Mapping[str, Any]) -> tuple[str, ...]:
    """Return one published contract's instant-valued pointers, refusing any `$ref`.

    Registry construction goes through here rather than calling the walk directly, so the
    whole document is checked for references it cannot resolve before any of it is read.
    """

    location = _reference_location(schema)
    if location is not None:
        raise ValueError(f"{location} carries a $ref this walk cannot resolve")
    return _timestamp_pointers(schema)


def _timestamp_pointers(schema: Mapping[str, Any], pointer: str = "") -> tuple[str, ...]:
    """Return the JSON pointer of every instant-valued property inside one contract.

    Nested objects are walked, so `projectedNextReduction/estimatedAt` is found, and a
    nullable field is found like any other: whether a value is present is the payload's
    business rather than the schema's.

    The `oneOf`, `anyOf`, `allOf`, `if`, `then`, `else`, and `dependentSchemas` branches are
    walked too, at the same pointer, because a branch constrains the same instance its
    parent does: a timestamp a branch introduces is a field of the payload like any other,
    and skipping it would take that field out of the parsed set in silence. Pointers are
    deduplicated and sorted, so a field two branches mention is parsed once and the order
    never depends on keyword order.

    Two shapes raise instead of being walked past. An array whose items carry a timestamp
    has no single value for a pointer to name, whether the array is spelled with `items`,
    `prefixItems`, or `contains` and whether the keyword holds one subschema or a list of
    them; and a `$ref` names a subschema this walk does not resolve. No contract has either,
    and a future one has to be handled deliberately rather than going quietly unchecked.
    `_contract_timestamp_pointers` catches a `$ref` under a keyword this walk never reaches.
    """

    if "$ref" in schema:
        raise ValueError(f"{pointer or '<root>'} carries a $ref this walk cannot resolve")
    found: set[str] = set()
    if schema.get("pattern") in _SEMANTIC_TIMESTAMP_PATTERNS:
        found.add(pointer)
    for name, subschema in schema.get("properties", {}).items():
        found.update(_timestamp_pointers(subschema, f"{pointer}/{name}"))
    for keyword in _BRANCH_LIST_KEYWORDS:
        for branch in schema.get(keyword, ()):
            if isinstance(branch, Mapping):
                found.update(_timestamp_pointers(branch, pointer))
    for keyword in _BRANCH_KEYWORDS:
        branch = schema.get(keyword)
        if isinstance(branch, Mapping):
            found.update(_timestamp_pointers(branch, pointer))
    for keyword in _BRANCH_MAP_KEYWORDS:
        entries = schema.get(keyword)
        if isinstance(entries, Mapping):
            for branch in entries.values():
                if isinstance(branch, Mapping):
                    found.update(_timestamp_pointers(branch, pointer))
    for keyword, subschema in _array_subschemas(schema):
        if _timestamp_pointers(subschema, f"{pointer}/{keyword}"):
            raise ValueError(f"{pointer or '<root>'} carries a timestamp inside an array")
    return tuple(sorted(found))


def _array_subschemas(schema: Mapping[str, Any]) -> tuple[tuple[str, Mapping[str, Any]], ...]:
    """Return every subschema one node applies to array items, with the keyword it is under."""

    subschemas: list[tuple[str, Mapping[str, Any]]] = []
    for keyword in _ARRAY_KEYWORDS:
        node = schema.get(keyword)
        if isinstance(node, Mapping):
            subschemas.append((keyword, node))
        elif isinstance(node, list):
            subschemas.extend((keyword, item) for item in node if isinstance(item, Mapping))
    return tuple(subschemas)


#: Every contract's instant-valued fields, derived from the schemas themselves so a new
#: timestamp field is parsed the day it is published rather than the day it is remembered.
EVENT_TIMESTAMP_POINTERS: Final[dict[tuple[str, int], tuple[str, ...]]] = {
    key: _contract_timestamp_pointers(schema) for key, schema in EVENT_CONTRACTS.items()
}


def schema_for(event_type: str, event_version: int = 1) -> dict[str, Any] | None:
    """Return the published contract for one event type and version, or None."""

    return EVENT_CONTRACTS.get((event_type, event_version))


def timestamp_pointers_for(event_type: str, event_version: int = 1) -> tuple[str, ...]:
    """Return the instant-valued JSON pointers of one contract, empty when it has none."""

    return EVENT_TIMESTAMP_POINTERS.get((event_type, event_version), ())


def stream_kind(stream_id: str) -> str | None:
    """Return the aggregate kind one stream id names, or None when it names neither."""

    if is_artifact_stream(stream_id):
        return ARTIFACT_STREAM_PREFIX
    if is_case_stream(stream_id):
        return CASE_STREAM_PREFIX
    return None


def event_belongs_on_stream(event_type: str, stream_id: str) -> bool:
    """Return True when one event type may be stored on one stream (ADR 0008 Decision 2).

    A stream that is neither an artifact nor a case aggregate carries nothing: every
    published event type belongs to one of the two kinds.
    """

    kind = stream_kind(stream_id)
    if kind == ARTIFACT_STREAM_PREFIX:
        return event_type in ARTIFACT_STREAM_EVENT_TYPES
    if kind == CASE_STREAM_PREFIX:
        return event_type in CASE_STREAM_EVENT_TYPES
    return False


def artifact_stream_id(sha256: str, parser_name: str, parser_version: str) -> str:
    """Return `artifact/<sha256>/<parser_name>/<parser_version>` (ADR 0008 Decision 2).

    A different parser version is a different stream, which is ADR 0002's identity
    rule: the same bytes read by a changed parser are new observations.
    """

    digest = _require_digest(sha256, "sha256")
    name = _require_component(parser_name, "parser_name")
    version = _require_component(parser_version, "parser_version")
    return _require_stream_id(f"{ARTIFACT_STREAM_PREFIX}/{digest}/{name}/{version}")


def artifact_stream_components(stream_id: str) -> tuple[str, str, str]:
    """Return the digest, parser name, and parser version one artifact stream id names.

    The inverse of `artifact_stream_id`, so an event stored on an artifact stream can be
    checked against the artifact that stream is about rather than trusted to be on the
    right one.
    """

    prefix = f"{ARTIFACT_STREAM_PREFIX}/"
    if not isinstance(stream_id, str) or not stream_id.startswith(prefix):
        raise ValueError(f"stream_id must start with {prefix!r}, got {stream_id!r}")
    parts = stream_id[len(prefix) :].split("/")
    if len(parts) != 3:
        raise ValueError(
            "an artifact stream id names a digest, a parser name, and a parser version, "
            f"got {stream_id!r}"
        )
    digest, parser_name, parser_version = parts
    return (
        _require_digest(digest, "sha256"),
        _require_component(parser_name, "parser_name"),
        _require_component(parser_version, "parser_version"),
    )


def case_stream_id(tracking_id: str) -> str:
    """Return `case/<tracking_id>` for a correlation v0 identifier (ADR 0007 Decision 3)."""

    return _require_stream_id(f"{CASE_STREAM_PREFIX}/{require_tracking_id(tracking_id)}")


def tracking_id_from_stream(stream_id: str) -> str:
    """Return the tracking identifier a case stream id carries."""

    prefix = f"{CASE_STREAM_PREFIX}/"
    if not isinstance(stream_id, str) or not stream_id.startswith(prefix):
        raise ValueError(f"stream_id must start with {prefix!r}, got {stream_id!r}")
    return require_tracking_id(stream_id[len(prefix) :])


def is_case_stream(stream_id: str) -> bool:
    """Return True when a stream id names a case aggregate."""

    return isinstance(stream_id, str) and stream_id.startswith(f"{CASE_STREAM_PREFIX}/")


def is_artifact_stream(stream_id: str) -> bool:
    """Return True when a stream id names an artifact ingestion aggregate."""

    return isinstance(stream_id, str) and stream_id.startswith(f"{ARTIFACT_STREAM_PREFIX}/")


def require_tracking_id(value: str) -> str:
    """Validate a correlation v0 tracking identifier, `case-` plus sixteen hex digits."""

    if not isinstance(value, str) or TRACKING_ID_PATTERN.fullmatch(value) is None:
        raise ValueError(
            f"tracking_id must match 'case-<16 hex characters>', got {value!r}"
        )
    return value


def iso_utc(value: datetime) -> str:
    """Render one aware timestamp in UTC `Z` form, the on-write normal form."""

    if not isinstance(value, datetime):
        raise TypeError(f"timestamp must be a datetime, got {type(value).__name__}")
    if value.tzinfo is None or value.utcoffset() is None:
        raise ValueError("timestamp must include a timezone")
    return value.astimezone(UTC).isoformat().replace("+00:00", "Z")


def parse_utc(value: str) -> datetime:
    """Parse an RFC 3339 timestamp into an aware UTC datetime."""

    if not isinstance(value, str) or not value.strip():
        raise ValueError("timestamp must be non-blank RFC 3339 text")
    text = value.strip()
    if text.endswith(("Z", "z")):
        text = f"{text[:-1]}+00:00"
    try:
        parsed = datetime.fromisoformat(text)
    except ValueError as exc:
        raise ValueError(f"timestamp must be RFC 3339, got {value!r}") from exc
    if parsed.tzinfo is None or parsed.utcoffset() is None:
        raise ValueError(f"timestamp must include a UTC offset, got {value!r}")
    return parsed.astimezone(UTC)


def _require_digest(value: str, field_name: str) -> str:
    if not isinstance(value, str) or _SHA256_PATTERN.fullmatch(value) is None:
        raise ValueError(f"{field_name} must be a lowercase 64-character SHA-256 digest")
    return value


def _require_component(value: str, field_name: str) -> str:
    if not isinstance(value, str) or _COMPONENT_PATTERN.fullmatch(value) is None:
        raise ValueError(
            f"{field_name} must be letters, digits, '.', '_', ':', or '-' and must not "
            f"contain the stream separator, got {value!r}"
        )
    return value


def _require_stream_id(value: str) -> str:
    if len(value) > _MAX_STREAM_ID_LENGTH:
        raise ValueError(f"stream_id must be at most {_MAX_STREAM_ID_LENGTH} characters")
    return value


__all__ = [
    "ARTIFACT_INGESTED_V1",
    "ARTIFACT_STREAM_EVENT_TYPES",
    "ARTIFACT_STREAM_PREFIX",
    "CASE_CREATED_V1",
    "CASE_DISPOSITION_RECORDED_V1",
    "CASE_EVALUATED_V1",
    "CASE_IDENTIFIED_V1",
    "CASE_OBSERVATION_LINKED_V1",
    "CASE_PAIN_REDUCED_V1",
    "CASE_STREAM_EVENT_TYPES",
    "CASE_STREAM_PREFIX",
    "CLOSED_DISPOSITION_VALUES",
    "DETECTION_ATTESTED_V1",
    "DISPOSITION_STATUS_VALUES",
    "EVENT_CONTRACTS",
    "EVENT_TIMESTAMP_POINTERS",
    "EVENT_TYPES",
    "OBSERVATION_RECORDED_V1",
    "TRACKING_ID_PATTERN",
    "UNDISPOSED_STATUSES",
    "artifact_stream_components",
    "artifact_stream_id",
    "case_stream_id",
    "event_belongs_on_stream",
    "is_artifact_stream",
    "is_case_stream",
    "iso_utc",
    "parse_utc",
    "require_tracking_id",
    "schema_for",
    "stream_kind",
    "timestamp_pointers_for",
    "tracking_id_from_stream",
]
