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
#: rationale for accepting it.
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
            "acceptanceRationale": _NULLABLE_NON_EMPTY_TEXT,
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


def schema_for(event_type: str, event_version: int = 1) -> dict[str, Any] | None:
    """Return the published contract for one event type and version, or None."""

    return EVENT_CONTRACTS.get((event_type, event_version))


def artifact_stream_id(sha256: str, parser_name: str, parser_version: str) -> str:
    """Return `artifact/<sha256>/<parser_name>/<parser_version>` (ADR 0008 Decision 2).

    A different parser version is a different stream, which is ADR 0002's identity
    rule: the same bytes read by a changed parser are new observations.
    """

    digest = _require_digest(sha256, "sha256")
    name = _require_component(parser_name, "parser_name")
    version = _require_component(parser_version, "parser_version")
    return _require_stream_id(f"{ARTIFACT_STREAM_PREFIX}/{digest}/{name}/{version}")


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
    "ARTIFACT_STREAM_PREFIX",
    "CASE_CREATED_V1",
    "CASE_DISPOSITION_RECORDED_V1",
    "CASE_EVALUATED_V1",
    "CASE_IDENTIFIED_V1",
    "CASE_OBSERVATION_LINKED_V1",
    "CASE_PAIN_REDUCED_V1",
    "CASE_STREAM_PREFIX",
    "CLOSED_DISPOSITION_VALUES",
    "DETECTION_ATTESTED_V1",
    "DISPOSITION_STATUS_VALUES",
    "EVENT_CONTRACTS",
    "EVENT_TYPES",
    "OBSERVATION_RECORDED_V1",
    "TRACKING_ID_PATTERN",
    "UNDISPOSED_STATUSES",
    "artifact_stream_id",
    "case_stream_id",
    "is_artifact_stream",
    "is_case_stream",
    "iso_utc",
    "parse_utc",
    "require_tracking_id",
    "schema_for",
    "tracking_id_from_stream",
]
