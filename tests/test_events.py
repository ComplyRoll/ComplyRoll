"""Tests for the published event contracts and the repository that enforces them."""

from __future__ import annotations

import json
import unittest
import uuid
from copy import deepcopy
from dataclasses import replace
from datetime import UTC, datetime, timedelta, timezone
from typing import Any

from jsonschema import Draft202012Validator

from complyroll import __version__
from complyroll.events import (
    ARTIFACT_IDENTITY_KEYS,
    ARTIFACT_STREAM_EVENT_TYPES,
    CASE_STREAM_EVENT_TYPES,
    EVENT_CONTRACTS,
    EVENT_TYPES,
    METHOD_VALUES,
    READ_PAGE_SIZE,
    TOOL_NAME,
    UNDISPOSED_STATUSES,
    ContractIssue,
    EventContractError,
    EventMetadata,
    EventRepository,
    PendingEvent,
    artifact_stream_id,
    canonical_payload_digest,
    case_stream_id,
    event_belongs_on_stream,
    is_artifact_stream,
    is_case_stream,
    iso_utc,
    metadata_breaches,
    parse_utc,
    require_tracking_id,
    schema_for,
    timestamp_pointers_for,
    tracking_id_from_stream,
)
from complyroll.events.contracts import (
    _MAX_STREAM_ID_LENGTH,
    _UTC_TIMESTAMP,
    _contract_timestamp_pointers,
    _timestamp_pointers,
)
from complyroll.models import (
    Observation,
    ObservationDisposition,
    ResourceRef,
    SourceSeverity,
)
from complyroll.store import EventConcurrencyError, SQLiteEventStore

NOW = datetime(2026, 8, 21, 12, 0, tzinfo=UTC)
DIGEST = "a" * 64
TRACKING_ID = "case-0123456789abcdef"
STREAM_ID = f"case/{TRACKING_ID}"
ARTIFACT_STREAM_ID = f"artifact/{DIGEST}/complyroll.cklb/1"

#: A deterministic run identifier that is also a real one: `run-` plus a canonical
#: version-4 UUID. A fixed word like `run-fixed` used to stand here, which is exactly the
#: shape `EventMetadata` now refuses, and a fixture that could never be stored proves
#: nothing about what is stored.
RUN_ID = "run-00000000-0000-4000-8000-000000000001"

#: The one object in the registry that is deliberately an open map: `source_metadata`
#: carries whatever key/value pairs a source tool published, so its keys cannot be
#: enumerated in advance. Its values are still constrained to strings.
OPEN_MAP_POINTERS = frozenset({"observation.recorded/properties/source_metadata"})

#: Nested objects whose optional fields are intentional, so `required` is a strict
#: subset of `properties` rather than equal to it.
OPTIONAL_FIELD_POINTERS = frozenset({"artifact.ingested/properties/diagnostics/items"})


def observation(**overrides: object) -> Observation:
    """Build one artifact-bound observation whose canonical dictionary is a payload.

    The identifier defaults to the derived one every adapter assigns, because
    `Observation.from_canonical_dict` requires that of an artifact-bound observation
    and a fixture that could never be stored is not a fixture worth validating.
    """

    values: dict[str, object] = {
        "source_type": "cklb",
        "source_tool": "stig-viewer",
        "parser_name": "complyroll.cklb",
        "parser_version": "1",
        "source_record_id": "V-260470",
        "resource": ResourceRef("host-001", "host"),
        "observed_at": None,
        "ingested_at": NOW,
        "disposition": ObservationDisposition.OPEN,
        "source_severity": SourceSeverity.HIGH,
        "source_artifact_digest": DIGEST,
        "source_artifact_name": "ubuntu-host.cklb",
        "context_key": "Canonical Ubuntu 24.04 LTS STIG",
    }
    values.update(overrides)
    stated = values.pop("observation_id", None)
    built = Observation(observation_id="obs-placeholder", **values)  # type: ignore[arg-type]
    identifier = built.derived_observation_id if stated is None else stated
    return replace(built, observation_id=identifier)  # type: ignore[arg-type]


GOOD_PAYLOADS: dict[str, dict[str, Any]] = {
    "artifact.ingested": {
        "name": "ubuntu-host.cklb",
        "sha256": DIGEST,
        "sizeBytes": 4096,
        "mediaType": "application/json",
        "parserName": "complyroll.cklb",
        "parserVersion": "1",
        "ingestedAt": "2026-08-21T12:00:00Z",
        "observationCount": 6,
        "diagnostics": [
            {
                "level": "warning",
                "code": "source_timestamp_missing",
                "message": "the checklist declares no scan time",
                "location": "ubuntu-host.cklb",
            }
        ],
    },
    "observation.recorded": observation().to_canonical_dict(),
    "case.created": {
        "trackingId": TRACKING_ID,
        "sourceType": "cklb",
        "sourceRecordId": "V-260470",
        "contextKey": "Canonical Ubuntu 24.04 LTS STIG",
        "title": "Inactive accounts are not disabled",
        "description": "Inactive accounts are not disabled on the shared host.",
        "createdAt": "2026-08-21T12:00:00Z",
    },
    "case.observation_linked": {
        "observationId": "obs-001",
        "resourceId": "host-001",
        "resourceType": "host",
        "observedAt": None,
        "sourceTool": "stig-viewer",
        "sourceArtifactSha256": DIGEST,
        "sourceIdentifiers": ["CCI-000795"],
    },
    "detection.attested": {
        "detectedAt": "2026-08-01T00:00:00Z",
        "rationale": "Provider attests detection at the scan window open.",
        "attestedAt": "2026-08-21T12:00:00Z",
    },
    "case.evaluated": {
        "completedAt": "2026-08-04T12:00:00Z",
        "isInternetReachable": True,
        "isLikelyExploitable": True,
        "pain": 3,
        "potentialAgencyImpact": "Dormant accounts stay usable on a tenant-facing host.",
        "rationale": "Inactive accounts are not disabled and the host is reachable.",
        "evaluator": "Example Provider vulnerability team",
        "isFalsePositive": False,
        "supplementaryRiskInformation": None,
        "projectedNextReduction": {
            "estimatedAt": "2026-08-28T16:00:00Z",
            "targetRating": 2,
        },
    },
    "case.pain_reduced": {"reducedAt": "2026-08-12T16:00:00Z", "rating": 4},
    "case.disposition_recorded": {
        "status": "closed",
        "closedDisposition": "remediated",
        "acceptanceRationale": None,
        "recordedAt": "2026-08-21T12:00:00Z",
    },
    "case.identified": {"providerTrackingId": "PROV-2026-0001"},
}

#: One field per contract that the schema requires in UTC `Z` form. The two contracts
#: that accept a source offset are asserted separately below.
UTC_ONLY_FIELDS: dict[str, str] = {
    "artifact.ingested": "ingestedAt",
    "case.created": "createdAt",
    "detection.attested": "detectedAt",
    "case.evaluated": "completedAt",
    "case.pain_reduced": "reducedAt",
    "case.disposition_recorded": "recordedAt",
}

#: One enum field per contract that carries one, with a value outside the enum.
BAD_ENUM_VALUES: dict[str, tuple[str, Any]] = {
    "observation.recorded": ("disposition", "sideways"),
    "case.disposition_recorded": ("status", "active"),
}

#: The two PAIN-bearing contracts and the integer field each constrains to 1 through 5.
PAIN_FIELDS: dict[str, str] = {
    "case.evaluated": "pain",
    "case.pain_reduced": "rating",
}

#: The two `observation.recorded` fields that carry a source offset rather than the
#: UTC `Z` form, because the payload is exactly `Observation.to_canonical_dict()`.
OBSERVATION_TIMESTAMP_FIELDS: tuple[str, ...] = ("observed_at", "ingested_at")

#: Spellings `observation.recorded` must refuse: the writer cannot produce them and
#: `Observation.from_canonical_dict` refuses to read them back, so a contract that
#: accepted them would let the repository store history the replay reader rejects.
#: The offset carrying seconds is not RFC 3339 either.
UNCANONICAL_TIMESTAMPS: tuple[str, ...] = (
    "2026-08-01T00:00:00Z",
    "2026-08-01T00:00:00.000+00:00",
    "2026-08-01T00:00:00+01:02:03",
)

#: Spellings `datetime.isoformat()` does produce for an aware datetime.
CANONICAL_TIMESTAMPS: tuple[str, ...] = (
    "2026-08-01T00:00:00+00:00",
    "2026-08-01T00:00:00.000001-07:00",
)

#: Offsets a source may legitimately declare, one per shape `isoformat` can emit.
SOURCE_OFFSETS: tuple[timezone, ...] = (
    UTC,
    timezone(timedelta(hours=-7)),
    timezone(timedelta(hours=5, minutes=30)),
    timezone(timedelta(hours=-9, minutes=-30)),
    timezone(timedelta(hours=14)),
)

#: `case.disposition_recorded` payloads that are coherent, and must stay accepted.
COHERENT_DISPOSITIONS: tuple[tuple[str, dict[str, Any]], ...] = (
    (
        "closed as remediated",
        {"status": "closed", "closedDisposition": "remediated", "acceptanceRationale": None},
    ),
    (
        "accepted with a rationale",
        {
            "status": "accepted",
            "closedDisposition": None,
            "acceptanceRationale": "The agency accepts the residual risk until the rebuild.",
        },
    ),
    (
        "closed as accepted with a rationale",
        {
            "status": "closed",
            "closedDisposition": "accepted",
            "acceptanceRationale": "The agency accepts the residual risk until the rebuild.",
        },
    ),
)

#: `case.disposition_recorded` payloads `reports.evaluations` refuses, each with the
#: field a contract issue must point at. Storing any of them would put a shape in
#: history that no evaluations file could have produced, and the last three would route
#: a vulnerability out of the detail report carrying no rationale at all: `minLength: 1`
#: counts three spaces as a rationale, so the property carries a non-blank pattern too.
INCOHERENT_DISPOSITIONS: tuple[tuple[str, str, dict[str, Any]], ...] = (
    (
        "closed names no closing disposition",
        "closedDisposition",
        {"status": "closed", "closedDisposition": None, "acceptanceRationale": None},
    ),
    (
        "a closing disposition on a status that is not closed",
        "closedDisposition",
        {
            "status": "remediated",
            "closedDisposition": "remediated",
            "acceptanceRationale": None,
        },
    ),
    (
        "a rationale on a status that accepts no risk",
        "acceptanceRationale",
        {
            "status": "remediated",
            "closedDisposition": None,
            "acceptanceRationale": "Nobody accepted anything.",
        },
    ),
    (
        "accepted without a rationale",
        "acceptanceRationale",
        {"status": "accepted", "closedDisposition": None, "acceptanceRationale": None},
    ),
    (
        "closed as accepted without a rationale",
        "acceptanceRationale",
        {"status": "closed", "closedDisposition": "accepted", "acceptanceRationale": None},
    ),
    (
        "accepted with an empty rationale",
        "acceptanceRationale",
        {"status": "accepted", "closedDisposition": None, "acceptanceRationale": ""},
    ),
    (
        "accepted with a whitespace rationale",
        "acceptanceRationale",
        {"status": "accepted", "closedDisposition": None, "acceptanceRationale": "   "},
    ),
)


#: Every contract's instant-valued fields, written out rather than derived, so publishing
#: a new timestamp field without teaching the repository to parse it fails here.
EXPECTED_TIMESTAMP_POINTERS: dict[str, tuple[str, ...]] = {
    "artifact.ingested": ("/ingestedAt",),
    "case.created": ("/createdAt",),
    "case.disposition_recorded": ("/recordedAt",),
    "case.evaluated": ("/completedAt", "/projectedNextReduction/estimatedAt"),
    "case.identified": (),
    "case.observation_linked": ("/observedAt",),
    "case.pain_reduced": ("/reducedAt",),
    "detection.attested": ("/attestedAt", "/detectedAt"),
    # The two `observation.recorded` timestamps are read back through
    # `Observation.from_canonical_dict`, which is stricter than parsing, so they are
    # deliberately absent from the parsed set.
    "observation.recorded": (),
}

#: Text that matches every timestamp pattern in the registry and names no instant. The
#: last one is the quiet case: Python reads hour 24 as midnight the next day, so an
#: August deadline spelled this way silently becomes a September one.
IMPOSSIBLE_INSTANTS: tuple[str, ...] = (
    "2026-02-30T12:00:00Z",
    "2026-08-01T25:00:00Z",
    "2026-08-31T24:00:00Z",
)

#: Run identifiers the metadata rules refuse, one per way of being wrong: a word, a
#: missing prefix, an empty identifier, a version-1 UUID, a variant outside RFC 4122, and
#: three spellings `uuid.UUID` accepts that are not the canonical text.
INVALID_RUN_IDS: tuple[str, ...] = (
    "run-fixed",
    "00000000-0000-4000-8000-000000000001",
    "run-",
    "run-00000000-0000-1000-8000-000000000001",
    "run-00000000-0000-4000-0000-000000000001",
    "run-00000000-0000-4000-8000-00000000000A",
    "run-{00000000-0000-4000-8000-000000000001}",
    "run-00000000000040008000000000000001",
)


def metadata(actor: str = "test-user") -> EventMetadata:
    return EventMetadata(actor=actor, run_id=RUN_ID)


def with_value(payload: dict[str, Any], pointer: str, value: Any) -> dict[str, Any]:
    """Return a copy of one payload with the value at a JSON pointer replaced."""

    updated = deepcopy(payload)
    target: Any = updated
    parts = pointer.split("/")[1:]
    for part in parts[:-1]:
        target = target[part]
    target[parts[-1]] = value
    return updated


def object_subschemas(
    schema: dict[str, Any], pointer: str
) -> list[tuple[str, dict[str, Any]]]:
    """Return every object subschema inside one contract, with a readable pointer."""

    found: list[tuple[str, dict[str, Any]]] = []
    if schema.get("type") == "object":
        found.append((pointer, schema))
    for key, value in schema.get("properties", {}).items():
        found.extend(object_subschemas(value, f"{pointer}/properties/{key}"))
    items = schema.get("items")
    if isinstance(items, dict):
        found.extend(object_subschemas(items, f"{pointer}/items"))
    return found


class ContractRegistryTests(unittest.TestCase):
    def test_every_contract_is_a_valid_draft_2020_12_schema(self) -> None:
        for (event_type, version), schema in EVENT_CONTRACTS.items():
            with self.subTest(event_type=event_type, version=version):
                Draft202012Validator.check_schema(schema)

    def test_every_contract_is_closed_and_requires_every_property(self) -> None:
        for (event_type, version), schema in EVENT_CONTRACTS.items():
            with self.subTest(event_type=event_type, version=version):
                self.assertEqual(schema["type"], "object")
                self.assertIs(schema["additionalProperties"], False)
                self.assertEqual(sorted(schema["required"]), sorted(schema["properties"]))

    def test_nested_objects_are_closed_apart_from_the_documented_open_map(self) -> None:
        for (event_type, _), schema in EVENT_CONTRACTS.items():
            for pointer, subschema in object_subschemas(schema, event_type):
                with self.subTest(pointer=pointer):
                    if pointer in OPEN_MAP_POINTERS:
                        self.assertEqual(
                            subschema["additionalProperties"], {"type": "string"}
                        )
                        continue
                    self.assertIs(subschema["additionalProperties"], False)
                    self.assertLessEqual(
                        set(subschema.get("required", ())), set(subschema["properties"])
                    )
                    if pointer not in OPTIONAL_FIELD_POINTERS:
                        self.assertEqual(
                            sorted(subschema["required"]), sorted(subschema["properties"])
                        )

    def test_registry_covers_exactly_the_published_event_types(self) -> None:
        self.assertEqual(set(EVENT_TYPES), {name for name, _ in EVENT_CONTRACTS})
        self.assertEqual(sorted(GOOD_PAYLOADS), sorted(EVENT_TYPES))
        for event_type in EVENT_TYPES:
            self.assertEqual(schema_for(event_type, 1), EVENT_CONTRACTS[(event_type, 1)])

    def test_schema_for_returns_none_for_an_unpublished_version(self) -> None:
        self.assertIsNone(schema_for("case.evaluated", 2))
        self.assertIsNone(schema_for("case.retracted", 1))


class PayloadValidationTests(unittest.TestCase):
    def setUp(self) -> None:
        self.store = SQLiteEventStore(":memory:")
        self.addCleanup(self.store.close)
        self.repository = EventRepository(self.store)

    def test_every_contract_accepts_its_known_good_payload(self) -> None:
        for event_type, payload in GOOD_PAYLOADS.items():
            with self.subTest(event_type=event_type):
                self.repository.validate_payload(event_type, payload)

    def test_an_observation_payload_the_reader_refuses_is_refused(self) -> None:
        # The pattern over timestamp text admits four spellings the writer never produces
        # and the reader will not read back: a whole second with six zero digits, a
        # negative zero offset, an impossible offset, and an impossible date. The
        # repository reads every observation payload back through the reader itself,
        # so none of them can reach the log.
        for text in (
            "2026-08-21T12:00:00.000000+00:00",
            "2026-08-21T12:00:00-00:00",
            "2026-08-21T12:00:00+24:00",
            "2026-02-30T12:00:00+00:00",
        ):
            with self.subTest(timestamp=text):
                payload = observation().to_canonical_dict()
                payload["ingested_at"] = text
                with self.assertRaises(EventContractError) as caught:
                    self.repository.validate_payload("observation.recorded", payload)
                self.assertIn("is not readable", str(caught.exception))
                self.assertEqual(caught.exception.issues[0].validator, "reader")

    def test_the_writer_text_always_satisfies_the_reader_round_trip(self) -> None:
        for offset_hours in (0, -7, 5.5):
            with self.subTest(offset_hours=offset_hours):
                zone = timezone(timedelta(hours=offset_hours))
                payload = observation(
                    ingested_at=datetime(2026, 8, 21, 12, 0, 0, 250000, tzinfo=zone)
                ).to_canonical_dict()
                self.repository.validate_payload("observation.recorded", payload)

    def test_every_contract_rejects_a_missing_field(self) -> None:
        for event_type, payload in GOOD_PAYLOADS.items():
            for dropped in payload:
                with self.subTest(event_type=event_type, dropped=dropped):
                    broken = {k: v for k, v in payload.items() if k != dropped}
                    with self.assertRaises(EventContractError) as caught:
                        self.repository.validate_payload(event_type, broken)
                    self.assertIn("required", str(caught.exception))

    def test_every_contract_rejects_an_extra_field(self) -> None:
        for event_type, payload in GOOD_PAYLOADS.items():
            with self.subTest(event_type=event_type):
                broken = {**payload, "retractedBy": "someone"}
                with self.assertRaises(EventContractError) as caught:
                    self.repository.validate_payload(event_type, broken)
                self.assertIn("retractedBy", str(caught.exception))

    def test_every_contract_rejects_a_wrong_typed_field(self) -> None:
        # No contract field accepts a fractional number, so one value probes them all.
        for event_type, payload in GOOD_PAYLOADS.items():
            for field_name in payload:
                with self.subTest(event_type=event_type, field=field_name):
                    broken = {**payload, field_name: 12.5}
                    with self.assertRaises(EventContractError) as caught:
                        self.repository.validate_payload(event_type, broken)
                    self.assertIn(f"/{field_name}", str(caught.exception))

    def test_enum_fields_reject_a_value_outside_the_enum(self) -> None:
        for event_type, (field_name, bad) in BAD_ENUM_VALUES.items():
            with self.subTest(event_type=event_type, field=field_name):
                broken = {**GOOD_PAYLOADS[event_type], field_name: bad}
                with self.assertRaises(EventContractError) as caught:
                    self.repository.validate_payload(event_type, broken)
                self.assertIn(f"/{field_name}", str(caught.exception))

    def test_diagnostic_level_rejects_a_value_outside_the_enum(self) -> None:
        payload = deepcopy(GOOD_PAYLOADS["artifact.ingested"])
        payload["diagnostics"][0]["level"] = "fatal"
        with self.assertRaises(EventContractError) as caught:
            self.repository.validate_payload("artifact.ingested", payload)
        self.assertIn("/diagnostics/0/level", str(caught.exception))

    def test_disposition_refuses_every_status_that_is_not_a_disposition(self) -> None:
        for status in UNDISPOSED_STATUSES:
            with self.subTest(status=status.value):
                broken = {
                    **GOOD_PAYLOADS["case.disposition_recorded"],
                    "status": status.value,
                    "closedDisposition": None,
                }
                with self.assertRaises(EventContractError):
                    self.repository.validate_payload("case.disposition_recorded", broken)

    def test_utc_only_fields_reject_a_source_offset(self) -> None:
        for event_type, field_name in UTC_ONLY_FIELDS.items():
            with self.subTest(event_type=event_type, field=field_name):
                broken = {**GOOD_PAYLOADS[event_type], field_name: "2026-08-01T00:00:00+02:00"}
                with self.assertRaises(EventContractError) as caught:
                    self.repository.validate_payload(event_type, broken)
                self.assertIn(f"/{field_name}", str(caught.exception))

    def test_observation_timestamps_keep_their_source_offset(self) -> None:
        offset = timezone(timedelta(hours=-7))
        payload = observation(observed_at=datetime(2026, 8, 3, 2, 0, tzinfo=offset))
        canonical = payload.to_canonical_dict()
        self.assertEqual(canonical["observed_at"], "2026-08-03T02:00:00-07:00")
        self.repository.validate_payload("observation.recorded", canonical)

    def test_linked_observation_keeps_its_source_offset(self) -> None:
        payload = {
            **GOOD_PAYLOADS["case.observation_linked"],
            "observedAt": "2026-08-03T02:00:00-07:00",
        }
        self.repository.validate_payload("case.observation_linked", payload)

    def test_no_contract_accepts_an_offset_carrying_seconds(self) -> None:
        # RFC 3339 offsets are hours and minutes. Python parses '+01:02:03' and
        # re-serializes it unchanged, so a contract that allowed it would store text
        # every reader downstream would then have to keep accepting.
        payload = {
            **GOOD_PAYLOADS["case.observation_linked"],
            "observedAt": "2026-08-03T02:00:00+01:02:03",
        }
        with self.assertRaises(EventContractError) as caught:
            self.repository.validate_payload("case.observation_linked", payload)
        self.assertIn("/observedAt", str(caught.exception))

    def test_the_observation_contract_refuses_a_spelling_the_reader_refuses(self) -> None:
        for field_name in OBSERVATION_TIMESTAMP_FIELDS:
            for text in UNCANONICAL_TIMESTAMPS:
                with self.subTest(field=field_name, timestamp=text):
                    broken = {**GOOD_PAYLOADS["observation.recorded"], field_name: text}
                    with self.assertRaises(EventContractError) as caught:
                        self.repository.validate_payload("observation.recorded", broken)
                    self.assertIn(f"/{field_name}", str(caught.exception))

    def test_the_observation_contract_accepts_what_the_writer_spells(self) -> None:
        for field_name in OBSERVATION_TIMESTAMP_FIELDS:
            for text in CANONICAL_TIMESTAMPS:
                with self.subTest(field=field_name, timestamp=text):
                    payload = {**GOOD_PAYLOADS["observation.recorded"], field_name: text}
                    self.repository.validate_payload("observation.recorded", payload)

    def test_an_absent_source_timestamp_is_still_accepted(self) -> None:
        payload = {**GOOD_PAYLOADS["observation.recorded"], "observed_at": None}
        self.repository.validate_payload("observation.recorded", payload)

    def test_every_timestamp_the_writer_produces_satisfies_the_contract(self) -> None:
        # The property the two sides have to share: whatever `to_canonical_dict`
        # spells, the contract accepts and `from_canonical_dict` reads back. Anything
        # the repository can store, the replay reader must be able to read.
        for offset in SOURCE_OFFSETS:
            for microsecond in (0, 1, 123_456, 999_999):
                with self.subTest(offset=str(offset), microsecond=microsecond):
                    moment = datetime(2026, 8, 1, 3, 4, 5, microsecond, tzinfo=offset)
                    payload = observation(
                        observed_at=moment, ingested_at=moment
                    ).to_canonical_dict()

                    self.repository.validate_payload("observation.recorded", payload)

                    rebuilt = Observation.from_canonical_dict(payload)
                    self.assertEqual(rebuilt.ingested_at, moment)
                    self.assertEqual(rebuilt.observed_at, moment)
                    self.assertEqual(rebuilt.to_canonical_dict(), payload)

    def test_a_coherent_disposition_is_accepted(self) -> None:
        for label, fields in COHERENT_DISPOSITIONS:
            with self.subTest(shape=label):
                payload = {**GOOD_PAYLOADS["case.disposition_recorded"], **fields}
                self.repository.validate_payload("case.disposition_recorded", payload)

    def test_a_disposition_the_evaluations_parser_refuses_is_refused_here_too(self) -> None:
        for label, field_name, fields in INCOHERENT_DISPOSITIONS:
            with self.subTest(shape=label):
                payload = {**GOOD_PAYLOADS["case.disposition_recorded"], **fields}
                with self.assertRaises(EventContractError) as caught:
                    self.repository.validate_payload("case.disposition_recorded", payload)
                pointers = [issue.instance_pointer for issue in caught.exception.issues]
                self.assertIn(f"/{field_name}", pointers)

    def test_a_rationale_of_whitespace_is_refused_at_append(self) -> None:
        # The rule the fold used to keep to itself. `minLength: 1` admits three spaces,
        # which routes a vulnerability out of the detail report as accepted while saying
        # nothing about why, so the property requires a character that is not whitespace.
        for blank in ("", " ", "   ", "\t", "\n"):
            with self.subTest(rationale=repr(blank)):
                payload = {
                    **GOOD_PAYLOADS["case.disposition_recorded"],
                    "status": "accepted",
                    "closedDisposition": None,
                    "acceptanceRationale": blank,
                }

                with self.assertRaises(EventContractError) as caught:
                    self.repository.append(
                        STREAM_ID,
                        "case.disposition_recorded",
                        payload,
                        occurred_at=NOW,
                        metadata=metadata(),
                        expected_version=0,
                    )

                self.assertIn("/acceptanceRationale", str(caught.exception))
        self.assertEqual(self.repository.read_stream(STREAM_ID), ())

    def test_a_real_rationale_is_appended(self) -> None:
        # The other half: text with something in it stores, surrounding spaces and all.
        payload = {
            **GOOD_PAYLOADS["case.disposition_recorded"],
            "status": "accepted",
            "closedDisposition": None,
            "acceptanceRationale": " The agency accepts the residual risk. ",
        }

        record = self.repository.append(
            STREAM_ID,
            "case.disposition_recorded",
            payload,
            occurred_at=NOW,
            metadata=metadata(),
            expected_version=0,
        )

        self.assertEqual(
            record.payload["acceptanceRationale"],
            " The agency accepts the residual risk. ",
        )

    def test_an_incoherent_disposition_appends_nothing(self) -> None:
        _, field_name, fields = INCOHERENT_DISPOSITIONS[0]
        payload = {**GOOD_PAYLOADS["case.disposition_recorded"], **fields}

        with self.assertRaises(EventContractError) as caught:
            self.repository.append(
                STREAM_ID,
                "case.disposition_recorded",
                payload,
                occurred_at=NOW,
                metadata=metadata(),
                expected_version=0,
            )

        self.assertIn(f"/{field_name}", str(caught.exception))
        self.assertEqual(self.repository.read_stream(STREAM_ID), ())

    def test_pain_ratings_outside_one_through_five_are_refused(self) -> None:
        for event_type, field_name in PAIN_FIELDS.items():
            for rating in (0, 6):
                with self.subTest(event_type=event_type, rating=rating):
                    broken = {**GOOD_PAYLOADS[event_type], field_name: rating}
                    with self.assertRaises(EventContractError) as caught:
                        self.repository.validate_payload(event_type, broken)
                    self.assertIn(f"/{field_name}", str(caught.exception))

    def test_projected_reduction_rating_is_bounded_too(self) -> None:
        for rating in (0, 6):
            with self.subTest(rating=rating):
                payload = deepcopy(GOOD_PAYLOADS["case.evaluated"])
                payload["projectedNextReduction"]["targetRating"] = rating
                with self.assertRaises(EventContractError):
                    self.repository.validate_payload("case.evaluated", payload)

    def test_unknown_event_type_names_the_published_contracts(self) -> None:
        with self.assertRaises(EventContractError) as caught:
            self.repository.validate_payload("case.retracted", {})
        message = str(caught.exception)
        self.assertIn("no published contract for event 'case.retracted' version 1", message)
        for event_type in EVENT_TYPES:
            self.assertIn(f"{event_type} v1", message)

    def test_unknown_event_version_names_the_published_contracts(self) -> None:
        with self.assertRaises(EventContractError) as caught:
            self.repository.validate_payload(
                "case.evaluated", GOOD_PAYLOADS["case.evaluated"], event_version=2
            )
        self.assertIn("version 2", str(caught.exception))
        self.assertIn("case.evaluated v1", str(caught.exception))

    def test_a_non_object_payload_is_refused(self) -> None:
        with self.assertRaises(EventContractError):
            self.repository.validate_payload("case.identified", ["not", "an", "object"])  # type: ignore[arg-type]

    def test_issues_carry_sorted_instance_pointers(self) -> None:
        payload = {**GOOD_PAYLOADS["case.evaluated"], "pain": 9, "evaluator": ""}
        with self.assertRaises(EventContractError) as caught:
            self.repository.validate_payload("case.evaluated", payload)
        pointers = [issue.instance_pointer for issue in caught.exception.issues]
        self.assertEqual(pointers, sorted(pointers))
        self.assertIn("/pain", pointers)
        self.assertIn("/evaluator", pointers)


class TimestampSemanticsTests(unittest.TestCase):
    """A contract's timestamp pattern proves a shape; the repository proves an instant.

    `2026-02-30T12:00:00Z` used to append cleanly, pass `store verify`, and then be refused
    by the fold, which put the refusal in the one place that cannot help whoever wrote it.
    """

    def setUp(self) -> None:
        self.store = SQLiteEventStore(":memory:")
        self.addCleanup(self.store.close)
        self.repository = EventRepository(self.store)

    def test_the_parsed_pointers_are_exactly_the_published_instants(self) -> None:
        derived = {event_type: timestamp_pointers_for(event_type) for event_type in EVENT_TYPES}

        self.assertEqual(derived, EXPECTED_TIMESTAMP_POINTERS)

    def test_every_parsed_pointer_names_a_field_the_known_good_payload_carries(self) -> None:
        for event_type, pointers in EXPECTED_TIMESTAMP_POINTERS.items():
            for pointer in pointers:
                with self.subTest(event_type=event_type, pointer=pointer):
                    target: Any = GOOD_PAYLOADS[event_type]
                    for part in pointer.split("/")[1:]:
                        self.assertIsInstance(target, dict)
                        self.assertIn(part, target)
                        target = target[part]

    def test_an_impossible_instant_is_refused_at_every_pointer(self) -> None:
        for event_type, pointers in EXPECTED_TIMESTAMP_POINTERS.items():
            for pointer in pointers:
                for text in IMPOSSIBLE_INSTANTS:
                    with self.subTest(event_type=event_type, pointer=pointer, value=text):
                        payload = with_value(GOOD_PAYLOADS[event_type], pointer, text)

                        with self.assertRaises(EventContractError) as caught:
                            self.repository.validate_payload(event_type, payload)

                        self.assertIn(pointer, str(caught.exception))
                        self.assertIn(
                            pointer,
                            [issue.instance_pointer for issue in caught.exception.issues],
                        )

    def test_an_impossible_instant_appends_nothing(self) -> None:
        payload = with_value(
            GOOD_PAYLOADS["detection.attested"], "/detectedAt", IMPOSSIBLE_INSTANTS[0]
        )

        with self.assertRaises(EventContractError):
            self.repository.append(
                STREAM_ID,
                "detection.attested",
                payload,
                occurred_at=NOW,
                metadata=metadata(),
                expected_version=0,
            )

        self.assertEqual(self.store.latest_sequence, 0)

    def test_a_nested_instant_is_parsed_too(self) -> None:
        payload = with_value(
            GOOD_PAYLOADS["case.evaluated"],
            "/projectedNextReduction/estimatedAt",
            "2026-02-30T16:00:00Z",
        )

        with self.assertRaises(EventContractError) as caught:
            self.repository.validate_payload("case.evaluated", payload)

        self.assertIn("/projectedNextReduction/estimatedAt", str(caught.exception))

    def test_a_null_nullable_instant_is_still_accepted(self) -> None:
        for event_type, pointer, value in (
            ("case.observation_linked", "/observedAt", None),
            ("case.evaluated", "/projectedNextReduction", None),
        ):
            with self.subTest(event_type=event_type, pointer=pointer):
                payload = with_value(GOOD_PAYLOADS[event_type], pointer, value)

                self.repository.validate_payload(event_type, payload)

    def test_a_real_instant_at_every_pointer_still_passes(self) -> None:
        for event_type, pointers in EXPECTED_TIMESTAMP_POINTERS.items():
            for pointer in pointers:
                with self.subTest(event_type=event_type, pointer=pointer):
                    payload = with_value(
                        GOOD_PAYLOADS[event_type], pointer, "2026-08-29T23:59:59Z"
                    )

                    self.repository.validate_payload(event_type, payload)


def branching_schema() -> dict[str, Any]:
    """Return one synthetic contract hiding a timestamp under every branch keyword.

    No published contract looks like this yet. The walk has to handle the shape before one
    does, because a timestamp a branch introduces is a field of the payload like any other
    and a walk that skipped it would take that field out of the parsed set in silence.
    """

    return {
        "type": "object",
        "properties": {"plain": _UTC_TIMESTAMP},
        "oneOf": [{"properties": {"underOneOf": _UTC_TIMESTAMP}}],
        "anyOf": [{"properties": {"underAnyOf": _UTC_TIMESTAMP}}],
        "allOf": [{"properties": {"underAllOf": _UTC_TIMESTAMP}}],
        "if": {"properties": {"underIf": _UTC_TIMESTAMP}},
        "then": {"properties": {"underThen": _UTC_TIMESTAMP}},
        "else": {"properties": {"underElse": _UTC_TIMESTAMP}},
    }


class TimestampPointerWalkTests(unittest.TestCase):
    """The walk that decides which fields the repository parses as instants.

    It used to read `properties` alone, so a timestamp a `oneOf`, `anyOf`, `allOf`, `if`,
    `then`, or `else` branch introduced was never parsed: the field kept its regular
    expression and lost its calendar, which is exactly the gap `_require_real_instants`
    exists to close.
    """

    def test_a_timestamp_under_every_branch_keyword_is_found(self) -> None:
        self.assertEqual(
            _timestamp_pointers(branching_schema()),
            (
                "/plain",
                "/underAllOf",
                "/underAnyOf",
                "/underElse",
                "/underIf",
                "/underOneOf",
                "/underThen",
            ),
        )

    def test_each_keyword_carries_its_own_pointer(self) -> None:
        for keyword in ("oneOf", "anyOf", "allOf"):
            with self.subTest(keyword=keyword):
                schema = {"type": "object", keyword: [{"properties": {"at": _UTC_TIMESTAMP}}]}

                self.assertEqual(_timestamp_pointers(schema), ("/at",))
        for keyword in ("if", "then", "else"):
            with self.subTest(keyword=keyword):
                schema = {"type": "object", keyword: {"properties": {"at": _UTC_TIMESTAMP}}}

                self.assertEqual(_timestamp_pointers(schema), ("/at",))

    def test_a_branch_constrains_the_instance_its_parent_does(self) -> None:
        # The branch is walked at the parent's pointer, not one level deeper, because it
        # applies to the same instance rather than to a child of it.
        schema = {
            "type": "object",
            "properties": {
                "nested": {
                    "type": "object",
                    "allOf": [{"properties": {"at": _UTC_TIMESTAMP}}],
                }
            },
        }

        self.assertEqual(_timestamp_pointers(schema), ("/nested/at",))

    def test_branches_nest_inside_one_another(self) -> None:
        schema = {
            "type": "object",
            "allOf": [
                {
                    "if": {"properties": {"shallow": _UTC_TIMESTAMP}},
                    "then": {"anyOf": [{"properties": {"deep": _UTC_TIMESTAMP}}]},
                }
            ],
        }

        self.assertEqual(_timestamp_pointers(schema), ("/deep", "/shallow"))

    def test_a_field_two_branches_mention_is_parsed_once(self) -> None:
        schema = {
            "type": "object",
            "properties": {"at": _UTC_TIMESTAMP},
            "oneOf": [
                {"properties": {"at": _UTC_TIMESTAMP}},
                {"properties": {"at": _UTC_TIMESTAMP}},
            ],
        }

        self.assertEqual(_timestamp_pointers(schema), ("/at",))

    def test_the_pointers_are_sorted_whatever_order_the_keywords_arrive_in(self) -> None:
        schema = {
            "type": "object",
            "then": {"properties": {"zulu": _UTC_TIMESTAMP}},
            "if": {"properties": {"alpha": _UTC_TIMESTAMP}},
            "properties": {"mike": _UTC_TIMESTAMP},
        }

        pointers = _timestamp_pointers(schema)

        self.assertEqual(pointers, ("/alpha", "/mike", "/zulu"))
        self.assertEqual(pointers, tuple(sorted(pointers)))

    def test_a_ref_raises_rather_than_going_unwalked(self) -> None:
        # A `$ref` names a subschema this walk does not resolve, so a contract that grew
        # one would quietly stop parsing whatever the reference carried.
        with self.assertRaises(ValueError) as caught:
            _timestamp_pointers({"$ref": "#/$defs/stamp"})

        self.assertIn("<root>", str(caught.exception))
        self.assertIn("$ref", str(caught.exception))

    def test_a_nested_ref_names_the_pointer_that_carries_it(self) -> None:
        for schema, pointer in (
            ({"type": "object", "properties": {"at": {"$ref": "#/$defs/stamp"}}}, "/at"),
            ({"type": "object", "allOf": [{"$ref": "#/$defs/stamp"}]}, "<root>"),
            ({"type": "object", "if": {"$ref": "#/$defs/stamp"}}, "<root>"),
        ):
            with self.subTest(pointer=pointer):
                with self.assertRaises(ValueError) as caught:
                    _timestamp_pointers(schema)

                self.assertIn(pointer, str(caught.exception))

    def test_a_timestamp_inside_an_array_raises(self) -> None:
        # An array's items have no single value for a pointer to name.
        with self.assertRaises(ValueError) as caught:
            _timestamp_pointers(
                {"type": "object", "properties": {"stamps": {"items": _UTC_TIMESTAMP}}}
            )

        self.assertIn("/stamps", str(caught.exception))
        self.assertIn("array", str(caught.exception))

    def test_dependent_schemas_are_walked_like_a_then_branch(self) -> None:
        # A `dependentSchemas` entry is a `then` that fires on a property being present,
        # so it constrains the same instance and its timestamps are the payload's.
        schema = {
            "type": "object",
            "dependentSchemas": {"trigger": {"properties": {"at": _UTC_TIMESTAMP}}},
        }

        self.assertEqual(_timestamp_pointers(schema), ("/at",))
        self.assertEqual(_contract_timestamp_pointers(schema), ("/at",))

    def test_a_timestamp_under_every_array_keyword_raises(self) -> None:
        # `items` in object form already raised. The list form, `prefixItems`, and
        # `contains` all name array positions the same way and had gone unchecked.
        for label, node in (
            ("list-form items", {"items": [_UTC_TIMESTAMP]}),
            ("prefixItems", {"prefixItems": [_UTC_TIMESTAMP]}),
            ("contains", {"contains": _UTC_TIMESTAMP}),
            ("nested under prefixItems", {"prefixItems": [{"properties": {"at": _UTC_TIMESTAMP}}]}),
        ):
            with self.subTest(keyword=label):
                schema = {"type": "object", "properties": {"stamps": {"type": "array", **node}}}

                with self.assertRaises(ValueError) as caught:
                    _timestamp_pointers(schema)

                self.assertIn("/stamps", str(caught.exception))
                self.assertIn("array", str(caught.exception))

    def test_a_ref_under_a_keyword_the_walk_never_visits_is_refused(self) -> None:
        # The walk visits the keywords the published contracts use, so a `$ref` under one
        # it does not visit used to import clean and take whatever the reference carried
        # out of the parsed set in silence. Registry construction scans the whole document.
        stamp = {"$ref": "#/$defs/stamp"}
        for schema, pointer in (
            ({"type": "object", "additionalProperties": stamp}, "/additionalProperties"),
            ({"type": "object", "patternProperties": {"^at$": stamp}}, "/patternProperties/^at$"),
            ({"type": "object", "not": stamp}, "/not"),
            ({"type": "object", "$defs": {"stamp": stamp}}, "/$defs/stamp"),
            ({"type": "object", "dependentSchemas": {"a": stamp}}, "/dependentSchemas/a"),
            ({"type": "array", "prefixItems": [stamp]}, "/prefixItems/0"),
            ({"type": "array", "contains": stamp}, "/contains"),
            ({"type": "object", "propertyNames": stamp}, "/propertyNames"),
            ({"type": "object", "unevaluatedProperties": stamp}, "/unevaluatedProperties"),
            ({"type": "array", "items": [stamp]}, "/items/0"),
        ):
            with self.subTest(pointer=pointer):
                with self.assertRaises(ValueError) as caught:
                    _contract_timestamp_pointers(schema)

                self.assertIn(pointer, str(caught.exception))
                self.assertIn("$ref", str(caught.exception))

    def test_a_document_with_no_ref_is_walked_rather_than_refused(self) -> None:
        # The scan looks for the `$ref` keyword, not for the characters: a contract that
        # merely stores the text somewhere is walked like any other.
        schema = {
            "type": "object",
            "properties": {"at": _UTC_TIMESTAMP, "note": {"const": "$ref"}},
            "$defs": {"unused": {"type": "string"}},
        }

        self.assertEqual(_contract_timestamp_pointers(schema), ("/at",))

    def test_no_published_contract_uses_a_ref(self) -> None:
        # The walk raises at import if one ever does; this says so in one place rather
        # than leaving the guarantee to a stack trace nobody would read.
        for key, schema in EVENT_CONTRACTS.items():
            with self.subTest(event_type=key[0], version=key[1]):
                self.assertNotIn('"$ref"', json.dumps(schema))

    def test_the_real_contracts_are_walked_the_same_way_after_the_change(self) -> None:
        # The published table is the regression guard: widening the walk must not have
        # added or moved a pointer for any contract that ships today.
        self.assertEqual(
            {event_type: timestamp_pointers_for(event_type) for event_type in EVENT_TYPES},
            EXPECTED_TIMESTAMP_POINTERS,
        )
        for (event_type, _), schema in EVENT_CONTRACTS.items():
            with self.subTest(event_type=event_type):
                self.assertEqual(
                    _timestamp_pointers(schema),
                    EXPECTED_TIMESTAMP_POINTERS[event_type],
                )
                self.assertEqual(
                    _contract_timestamp_pointers(schema),
                    EXPECTED_TIMESTAMP_POINTERS[event_type],
                )


class DuplicateObservationTests(unittest.TestCase):
    """One observation identifier is one finding, and one stream carries it once.

    A second copy of an observation on its own stream passes every other check there is:
    it names exactly the artifact the stream names, so the identity check is satisfied,
    and a head declaring the larger count adds up, so the count check is satisfied too.
    It still rehydrates one finding twice, so the repository refuses it at append.
    """

    def setUp(self) -> None:
        self.store = SQLiteEventStore(":memory:")
        self.addCleanup(self.store.close)
        self.repository = EventRepository(self.store)
        self.observation = observation()

    def pending(self, item: Observation) -> PendingEvent:
        return PendingEvent(
            event_type="observation.recorded",
            payload=item.to_canonical_dict(),
            occurred_at=NOW,
            metadata=metadata(),
        )

    def append(self, item: Observation) -> None:
        self.repository.append(
            ARTIFACT_STREAM_ID,
            "observation.recorded",
            item.to_canonical_dict(),
            occurred_at=NOW,
            metadata=metadata(),
            expected_version=self.repository.current_version(ARTIFACT_STREAM_ID),
        )

    def other_finding(self) -> Observation:
        """Return a different finding on the same artifact, with its derived identifier."""

        moved = replace(self.observation, source_record_id="V-999999")
        return replace(moved, observation_id=moved.derived_observation_id)

    def test_one_batch_holding_the_same_observation_twice_is_refused(self) -> None:
        pending = (self.pending(self.observation), self.pending(self.observation))

        with self.assertRaises(EventContractError) as caught:
            self.repository.append_batch(ARTIFACT_STREAM_ID, pending, expected_version=0)

        message = str(caught.exception)
        self.assertIn("records observation", message)
        self.assertIn(self.observation.observation_id, message)
        self.assertIn(ARTIFACT_STREAM_ID, message)
        self.assertEqual(self.store.latest_sequence, 0)

    def test_an_observation_the_stream_already_holds_is_refused(self) -> None:
        self.append(self.observation)

        with self.assertRaises(EventContractError) as caught:
            self.append(self.observation)

        self.assertIn("more than once", str(caught.exception))
        self.assertEqual(self.repository.current_version(ARTIFACT_STREAM_ID), 1)

    def test_a_different_finding_on_the_same_stream_is_accepted(self) -> None:
        # The resume path: `record_ingest` finishes a half-written stream by appending
        # the tail it declared, and a legitimate tail is findings the stream does not
        # already hold. Only a repeat is refused.
        self.append(self.observation)
        self.append(self.other_finding())

        self.assertEqual(self.repository.current_version(ARTIFACT_STREAM_ID), 2)

    def test_the_same_finding_on_its_own_other_stream_is_accepted(self) -> None:
        # The rule is per stream, not global. The same source record read by a different
        # parser version is a different observation on a different stream (ADR 0002).
        self.append(self.observation)
        moved = replace(self.observation, parser_version="2")
        moved = replace(moved, observation_id=moved.derived_observation_id)
        other_stream = artifact_stream_id(DIGEST, "complyroll.cklb", "2")
        self.repository.append(
            other_stream,
            "observation.recorded",
            moved.to_canonical_dict(),
            occurred_at=NOW,
            metadata=metadata(),
            expected_version=0,
        )

        self.assertEqual(self.repository.current_version(other_stream), 1)

    def test_an_artifact_head_beside_the_observations_does_not_confuse_the_check(self) -> None:
        # The head is not an observation, so it neither counts as one nor blocks one.
        pending = (
            PendingEvent(
                event_type="artifact.ingested",
                payload=GOOD_PAYLOADS["artifact.ingested"],
                occurred_at=NOW,
                metadata=metadata(),
            ),
            self.pending(self.observation),
            self.pending(self.other_finding()),
        )

        self.repository.append_batch(ARTIFACT_STREAM_ID, pending, expected_version=0)

        self.assertEqual(self.repository.current_version(ARTIFACT_STREAM_ID), 3)


class StreamCompatibilityTests(unittest.TestCase):
    """An event on the wrong kind of stream is read by nobody and reported by nothing.

    A `case.created` on an artifact stream used to append cleanly: replay ignored it, and
    `store verify` said the log was healthy. Refusing the combination at append is what
    keeps "stored" and "read back" the same set of events.
    """

    def setUp(self) -> None:
        self.store = SQLiteEventStore(":memory:")
        self.addCleanup(self.store.close)
        self.repository = EventRepository(self.store)

    def append(self, stream_id: str, event_type: str, **overrides: Any) -> None:
        payload = {**GOOD_PAYLOADS[event_type], **overrides}
        self.repository.append(
            stream_id,
            event_type,
            payload,
            occurred_at=NOW,
            metadata=metadata(),
            expected_version=self.repository.current_version(stream_id),
        )

    def test_the_two_stream_kinds_partition_the_published_types(self) -> None:
        self.assertEqual(
            ARTIFACT_STREAM_EVENT_TYPES | CASE_STREAM_EVENT_TYPES, set(EVENT_TYPES)
        )
        self.assertEqual(ARTIFACT_STREAM_EVENT_TYPES & CASE_STREAM_EVENT_TYPES, set())
        self.assertEqual(
            ARTIFACT_STREAM_EVENT_TYPES, {"artifact.ingested", "observation.recorded"}
        )

    def test_every_type_is_accepted_on_the_stream_it_belongs_on(self) -> None:
        for event_type in sorted(ARTIFACT_STREAM_EVENT_TYPES):
            with self.subTest(event_type=event_type):
                self.append(ARTIFACT_STREAM_ID, event_type)
        for event_type in sorted(CASE_STREAM_EVENT_TYPES):
            with self.subTest(event_type=event_type):
                self.append(STREAM_ID, event_type)

        self.assertEqual(
            self.repository.current_version(ARTIFACT_STREAM_ID),
            len(ARTIFACT_STREAM_EVENT_TYPES),
        )
        self.assertEqual(
            self.repository.current_version(STREAM_ID), len(CASE_STREAM_EVENT_TYPES)
        )

    def test_a_case_event_on_an_artifact_stream_is_refused(self) -> None:
        for event_type in sorted(CASE_STREAM_EVENT_TYPES):
            with self.subTest(event_type=event_type):
                with self.assertRaises(EventContractError) as caught:
                    self.append(ARTIFACT_STREAM_ID, event_type)

                self.assertIn(event_type, str(caught.exception))
                self.assertIn("artifact stream", str(caught.exception))
        self.assertEqual(self.store.latest_sequence, 0)

    def test_an_artifact_event_on_a_case_stream_is_refused(self) -> None:
        for event_type in sorted(ARTIFACT_STREAM_EVENT_TYPES):
            with self.subTest(event_type=event_type):
                with self.assertRaises(EventContractError) as caught:
                    self.append(STREAM_ID, event_type)

                self.assertIn(event_type, str(caught.exception))
                self.assertIn("case stream", str(caught.exception))
        self.assertEqual(self.store.latest_sequence, 0)

    def test_a_stream_of_neither_kind_carries_nothing(self) -> None:
        for event_type in sorted(EVENT_TYPES):
            with self.subTest(event_type=event_type):
                self.assertFalse(event_belongs_on_stream(event_type, "projection/case-list"))
                with self.assertRaises(EventContractError) as caught:
                    self.append("projection/case-list", event_type)

                self.assertIn("neither an artifact nor a case stream", str(caught.exception))

    def test_a_case_created_naming_another_case_is_refused(self) -> None:
        other = "case-ffffffffffffffff"

        with self.assertRaises(EventContractError) as caught:
            self.append(STREAM_ID, "case.created", trackingId=other)

        self.assertIn(other, str(caught.exception))
        self.assertIn(TRACKING_ID, str(caught.exception))
        self.assertEqual(self.store.latest_sequence, 0)

    def test_a_case_created_naming_its_own_stream_is_accepted(self) -> None:
        self.append(STREAM_ID, "case.created")

        self.assertEqual(self.repository.current_version(STREAM_ID), 1)

    def test_a_case_created_on_a_stream_that_names_no_tracking_id_is_refused(self) -> None:
        with self.assertRaises(EventContractError) as caught:
            self.append("case/not-a-tracking-id", "case.created")

        self.assertIn("case/not-a-tracking-id", str(caught.exception))

    def test_the_identity_keys_are_the_ones_the_canonical_dictionary_emits(self) -> None:
        # The identity check reads three keys out of a payload by name. A key that is not
        # in the dictionary reads back None, which equals nothing a stream names, so a
        # renamed canonical field would turn the check into a blanket refusal rather than
        # a comparison. Pin the names to a real observation's own dictionary.
        payload = observation().to_canonical_dict()
        keys = ARTIFACT_IDENTITY_KEYS["observation.recorded"]

        self.assertEqual(keys, ("source_artifact_digest", "parser_name", "parser_version"))
        for key in keys:
            with self.subTest(key=key):
                self.assertIn(key, payload)
        self.assertEqual(
            tuple(payload[key] for key in keys),
            (DIGEST, "complyroll.cklb", "1"),
        )
        for key in ARTIFACT_IDENTITY_KEYS["artifact.ingested"]:
            with self.subTest(key=key):
                self.assertIn(key, GOOD_PAYLOADS["artifact.ingested"])

    def test_an_artifact_ingested_naming_another_artifact_is_refused(self) -> None:
        # An artifact stream id is the artifact's identity: the digest of the bytes, the
        # parser, and the parser version. An event that names a different one is not this
        # stream's history, so it is refused rather than stored where nothing checks it.
        for label, overrides in (
            ("another digest", {"sha256": "b" * 64}),
            ("another parser", {"parserName": "complyroll.ckl"}),
            ("another parser version", {"parserVersion": "2"}),
        ):
            with self.subTest(shape=label):
                with self.assertRaises(EventContractError) as caught:
                    self.append(ARTIFACT_STREAM_ID, "artifact.ingested", **overrides)

                message = str(caught.exception)
                self.assertIn("artifact.ingested records digest", message)
                self.assertIn(ARTIFACT_STREAM_ID, message)
        self.assertEqual(self.store.latest_sequence, 0)

    def test_an_observation_naming_another_artifact_is_refused(self) -> None:
        # The one that mattered: a payload copied verbatim onto another artifact's stream
        # is internally consistent and is the right event type for the stream, so every
        # check there was let it through and its finding was counted twice.
        for label, overrides in (
            ("another digest", {"source_artifact_digest": "b" * 64}),
            ("another parser", {"parser_name": "complyroll.ckl"}),
            ("another parser version", {"parser_version": "2"}),
        ):
            with self.subTest(shape=label):
                payload = observation(**overrides).to_canonical_dict()

                with self.assertRaises(EventContractError) as caught:
                    self.repository.append(
                        ARTIFACT_STREAM_ID,
                        "observation.recorded",
                        payload,
                        occurred_at=NOW,
                        metadata=metadata(),
                        expected_version=0,
                    )

                message = str(caught.exception)
                self.assertIn("observation.recorded records digest", message)
                self.assertIn(ARTIFACT_STREAM_ID, message)
        self.assertEqual(self.store.latest_sequence, 0)

    def test_the_same_identity_on_its_own_stream_is_accepted(self) -> None:
        # The check is about agreement between the payload and the stream, not about one
        # blessed stream: the same events land cleanly on the stream they name.
        for parser_version in ("2", "10", "2.0-rc1"):
            with self.subTest(parser_version=parser_version):
                stream_id = artifact_stream_id("b" * 64, "complyroll.ckl", parser_version)
                self.append(
                    stream_id,
                    "artifact.ingested",
                    sha256="b" * 64,
                    parserName="complyroll.ckl",
                    parserVersion=parser_version,
                )
                moved = observation(
                    source_artifact_digest="b" * 64,
                    parser_name="complyroll.ckl",
                    parser_version=parser_version,
                )
                self.repository.append(
                    stream_id,
                    "observation.recorded",
                    moved.to_canonical_dict(),
                    occurred_at=NOW,
                    metadata=metadata(),
                    expected_version=1,
                )

                self.assertEqual(self.repository.current_version(stream_id), 2)

    def test_a_batch_is_refused_whole_when_one_event_names_another_artifact(self) -> None:
        pending = (
            PendingEvent(
                event_type="artifact.ingested",
                payload=GOOD_PAYLOADS["artifact.ingested"],
                occurred_at=NOW,
                metadata=metadata(),
            ),
            PendingEvent(
                event_type="observation.recorded",
                payload=observation(parser_version="2").to_canonical_dict(),
                occurred_at=NOW,
                metadata=metadata(),
            ),
        )

        with self.assertRaises(EventContractError):
            self.repository.append_batch(ARTIFACT_STREAM_ID, pending, expected_version=0)

        self.assertEqual(self.store.latest_sequence, 0)

    def test_one_misplaced_event_refuses_the_whole_batch(self) -> None:
        pending = (
            PendingEvent(
                event_type="case.created",
                payload=GOOD_PAYLOADS["case.created"],
                occurred_at=NOW,
                metadata=metadata(),
            ),
            PendingEvent(
                event_type="artifact.ingested",
                payload=GOOD_PAYLOADS["artifact.ingested"],
                occurred_at=NOW,
                metadata=metadata(),
            ),
        )

        with self.assertRaises(EventContractError):
            self.repository.append_batch(STREAM_ID, pending, expected_version=0)

        self.assertEqual(self.store.latest_sequence, 0)


class MetadataInvariantTests(unittest.TestCase):
    """Metadata was described and not enforced: `run-not-a-uuid4` stored happily."""

    def setUp(self) -> None:
        self.store = SQLiteEventStore(":memory:")
        self.addCleanup(self.store.close)
        self.repository = EventRepository(self.store)

    def test_the_command_line_default_is_valid(self) -> None:
        stored = EventMetadata(actor="kyle").to_dict()

        self.assertEqual(metadata_breaches(stored), ())

    def test_every_invalid_run_identifier_is_refused(self) -> None:
        for value in INVALID_RUN_IDS:
            with self.subTest(run_id=value):
                with self.assertRaises(ValueError) as caught:
                    EventMetadata(actor="kyle", run_id=value)

                self.assertIn("version-4 UUID", str(caught.exception))

    def test_a_method_outside_the_published_set_is_refused(self) -> None:
        for value in ("not-cli", "CLI", "api", ""):
            with self.subTest(method=value):
                with self.assertRaises(ValueError) as caught:
                    EventMetadata(actor="kyle", method=value)

                self.assertIn("method must be one of", str(caught.exception))

    def test_every_published_method_is_accepted(self) -> None:
        for value in METHOD_VALUES:
            with self.subTest(method=value):
                self.assertEqual(EventMetadata(actor="kyle", method=value).method, value)

    def test_a_blank_tool_or_version_is_refused(self) -> None:
        # `tool` is no longer merely non-blank. It names this tool or the envelope is not
        # this tool's history, so whitespace fails the constant rather than the blank rule
        # while `actor` and `toolVersion` still fail the blank one.
        for field_name, expected in (
            ("actor", "non-blank"),
            ("tool", f"tool must be {TOOL_NAME!r}"),
            ("tool_version", "non-blank"),
        ):
            with self.subTest(field=field_name):
                with self.assertRaises(ValueError) as caught:
                    EventMetadata(**{"actor": "kyle", field_name: "  "})  # type: ignore[arg-type]

                self.assertIn(expected, str(caught.exception))

    def test_the_default_tool_is_the_published_constant(self) -> None:
        self.assertEqual(TOOL_NAME, "complyroll")
        self.assertEqual(EventMetadata(actor="kyle").tool, TOOL_NAME)
        self.assertEqual(EventMetadata(actor="kyle").to_dict()["tool"], TOOL_NAME)

    def test_a_tool_other_than_complyroll_is_refused(self) -> None:
        # `toolVersion` moves with each release; the name does not. An envelope naming
        # another generator used to be stored verbatim and verify clean afterwards.
        for value in ("not-complyroll", "stigroll", "ComplyRoll", "complyroll ", ""):
            with self.subTest(tool=value):
                with self.assertRaises(ValueError) as caught:
                    EventMetadata(actor="kyle", tool=value)

                self.assertIn(f"tool must be {TOOL_NAME!r}", str(caught.exception))
                self.assertIn(repr(value), str(caught.exception))

    def test_an_envelope_naming_another_tool_is_a_breach(self) -> None:
        stored = {**EventMetadata(actor="kyle", run_id=RUN_ID).to_dict(), "tool": "stigroll"}

        self.assertEqual(metadata_breaches(stored), (f"tool must be {TOOL_NAME!r}",))

    def test_the_repository_refuses_an_envelope_naming_another_tool(self) -> None:
        # The constructor cannot produce this, so the fixture writes past it the way an
        # older version or another writer would. The repository is the second gate.
        forged = metadata()
        object.__setattr__(forged, "tool", "stigroll")

        with self.assertRaises(EventContractError) as caught:
            self.repository.append(
                STREAM_ID,
                "case.created",
                GOOD_PAYLOADS["case.created"],
                occurred_at=NOW,
                metadata=forged,
                expected_version=0,
            )

        self.assertIn("event metadata is invalid", str(caught.exception))
        self.assertIn(f"tool must be {TOOL_NAME!r}", str(caught.exception))
        self.assertEqual(self.store.latest_sequence, 0)

    def test_breaches_name_every_problem_in_one_stored_envelope(self) -> None:
        problems = metadata_breaches(
            {
                "actor": " ",
                "method": "not-cli",
                "tool": "",
                "toolVersion": "  ",
                "runId": "run-not-a-uuid4",
            }
        )

        self.assertEqual(len(problems), 5)
        self.assertTrue(any("actor" in problem for problem in problems))
        self.assertTrue(any("method" in problem for problem in problems))
        self.assertTrue(any("runId" in problem for problem in problems))

    def test_an_envelope_with_the_wrong_keys_is_a_breach(self) -> None:
        for envelope in (
            {},
            {"actor": "kyle"},
            {**EventMetadata(actor="kyle").to_dict(), "extra": "value"},
        ):
            with self.subTest(keys=sorted(envelope)):
                problems = metadata_breaches(envelope)

                self.assertTrue(problems)
                self.assertIn("exactly", problems[0])

    def test_a_non_object_envelope_is_a_breach(self) -> None:
        self.assertEqual(
            metadata_breaches(["actor", "kyle"]),  # type: ignore[arg-type]
            ("metadata must be a JSON object",),
        )

    def test_the_repository_refuses_a_forged_envelope_at_append(self) -> None:
        # The constructor cannot produce this, so the fixture writes past it the way an
        # older version or another writer would: the frozen field is set directly. The
        # second gate, in the repository, is what has to catch it.
        forged = metadata()
        object.__setattr__(forged, "run_id", "run-fixed")

        with self.assertRaises(EventContractError) as caught:
            self.repository.append(
                STREAM_ID,
                "case.created",
                GOOD_PAYLOADS["case.created"],
                occurred_at=NOW,
                metadata=forged,
                expected_version=0,
            )

        self.assertIn("event metadata is invalid", str(caught.exception))
        self.assertEqual(self.store.latest_sequence, 0)


class ContractIssueTests(unittest.TestCase):
    def test_render_names_the_pointer_validator_and_message(self) -> None:
        issue = ContractIssue("/pain", "maximum", "9 is greater than the maximum of 5")
        self.assertEqual(issue.render(), "/pain: maximum: 9 is greater than the maximum of 5")

    def test_render_calls_the_document_root_root(self) -> None:
        issue = ContractIssue("", "required", "'pain' is a required property")
        self.assertEqual(issue.render(), "<root>: required: 'pain' is a required property")


class EventMetadataTests(unittest.TestCase):
    def test_to_dict_has_the_stored_shape(self) -> None:
        stored = EventMetadata(actor="kyle", run_id=RUN_ID).to_dict()
        self.assertEqual(sorted(stored), ["actor", "method", "runId", "tool", "toolVersion"])
        self.assertEqual(stored["actor"], "kyle")
        self.assertEqual(stored["method"], "cli")
        self.assertEqual(stored["tool"], "complyroll")
        self.assertEqual(stored["toolVersion"], __version__)
        self.assertEqual(stored["runId"], RUN_ID)

    def test_each_run_gets_its_own_identifier_by_default(self) -> None:
        first = EventMetadata(actor="kyle")
        second = EventMetadata(actor="kyle")
        self.assertTrue(first.run_id.startswith("run-"))
        self.assertNotEqual(first.run_id, second.run_id)

    def test_the_run_identifier_is_run_dash_uuid4(self) -> None:
        # ADR 0008 Decision 1 spells the stored identifier `run-<uuid4>`; anything
        # reading a run out of the log matches on that shape.
        stored = EventMetadata(actor="kyle").to_dict()["runId"]

        self.assertRegex(stored, r"^run-[0-9a-f-]{36}$")
        parsed = uuid.UUID(stored.removeprefix("run-"))
        self.assertEqual(parsed.version, 4)
        self.assertEqual(str(parsed), stored.removeprefix("run-"))

    def test_blank_fields_are_refused(self) -> None:
        for field_name in ("actor", "method", "tool", "tool_version", "run_id"):
            with self.subTest(field=field_name):
                with self.assertRaises(ValueError):
                    EventMetadata(**{"actor": "kyle", field_name: "  "})  # type: ignore[arg-type]


class StreamIdentifierTests(unittest.TestCase):
    def test_artifact_stream_id_names_the_digest_and_the_parser(self) -> None:
        stream_id = artifact_stream_id(DIGEST, "complyroll.cklb", "1")
        self.assertEqual(stream_id, f"artifact/{DIGEST}/complyroll.cklb/1")
        self.assertTrue(is_artifact_stream(stream_id))
        self.assertFalse(is_case_stream(stream_id))

    def test_a_new_parser_version_is_a_new_stream(self) -> None:
        self.assertNotEqual(
            artifact_stream_id(DIGEST, "complyroll.cklb", "1"),
            artifact_stream_id(DIGEST, "complyroll.cklb", "2"),
        )

    def test_artifact_stream_id_rejects_a_bad_digest(self) -> None:
        for bad in ("", "A" * 64, "a" * 63, "zz" + "a" * 62):
            with self.subTest(digest=bad):
                with self.assertRaises(ValueError):
                    artifact_stream_id(bad, "complyroll.cklb", "1")

    def test_artifact_stream_id_rejects_a_separator_inside_a_component(self) -> None:
        for name, version in (("complyroll/cklb", "1"), ("complyroll.cklb", "1/2")):
            with self.subTest(parser_name=name, parser_version=version):
                with self.assertRaises(ValueError):
                    artifact_stream_id(DIGEST, name, version)

    def test_artifact_stream_id_rejects_an_over_long_identifier(self) -> None:
        with self.assertRaises(ValueError) as caught:
            artifact_stream_id(DIGEST, "complyroll.cklb", "v" * _MAX_STREAM_ID_LENGTH)
        self.assertIn(str(_MAX_STREAM_ID_LENGTH), str(caught.exception))

    def test_case_stream_id_round_trips_through_tracking_id_from_stream(self) -> None:
        stream_id = case_stream_id(TRACKING_ID)
        self.assertEqual(stream_id, STREAM_ID)
        self.assertTrue(is_case_stream(stream_id))
        self.assertEqual(tracking_id_from_stream(stream_id), TRACKING_ID)

    def test_case_stream_id_rejects_a_malformed_tracking_id(self) -> None:
        for bad in ("case-0123", "case-0123456789ABCDEF", "0123456789abcdef", "case/x"):
            with self.subTest(tracking_id=bad):
                with self.assertRaises(ValueError):
                    case_stream_id(bad)

    def test_tracking_id_from_stream_rejects_a_stream_of_another_kind(self) -> None:
        with self.assertRaises(ValueError):
            tracking_id_from_stream(artifact_stream_id(DIGEST, "complyroll.cklb", "1"))

    def test_require_tracking_id_returns_the_value_it_accepts(self) -> None:
        self.assertEqual(require_tracking_id(TRACKING_ID), TRACKING_ID)


class TimestampTests(unittest.TestCase):
    def test_iso_utc_normalizes_an_offset_to_the_z_form(self) -> None:
        offset = timezone(timedelta(hours=-7))
        self.assertEqual(
            iso_utc(datetime(2026, 8, 3, 2, 0, tzinfo=offset)), "2026-08-03T09:00:00Z"
        )

    def test_parse_utc_inverts_iso_utc(self) -> None:
        offset = timezone(timedelta(hours=5, minutes=30))
        value = datetime(2026, 8, 3, 2, 0, tzinfo=offset)
        self.assertEqual(parse_utc(iso_utc(value)), value.astimezone(UTC))

    def test_iso_utc_refuses_a_naive_timestamp(self) -> None:
        with self.assertRaises(ValueError):
            iso_utc(datetime(2026, 8, 3, 2, 0))

    def test_parse_utc_refuses_text_without_an_offset(self) -> None:
        for bad in ("", "   ", "2026-08-03T02:00:00", "not a timestamp"):
            with self.subTest(value=bad):
                with self.assertRaises(ValueError):
                    parse_utc(bad)


class CanonicalDigestTests(unittest.TestCase):
    def test_digest_is_key_order_independent(self) -> None:
        payload = GOOD_PAYLOADS["case.evaluated"]
        reversed_payload = dict(reversed(list(payload.items())))
        self.assertNotEqual(list(payload), list(reversed_payload))
        self.assertEqual(
            canonical_payload_digest(payload), canonical_payload_digest(reversed_payload)
        )

    def test_a_changed_value_changes_the_digest(self) -> None:
        payload = GOOD_PAYLOADS["case.evaluated"]
        self.assertNotEqual(
            canonical_payload_digest(payload),
            canonical_payload_digest({**payload, "pain": 5}),
        )

    def test_a_non_object_payload_is_refused(self) -> None:
        with self.assertRaises(TypeError):
            canonical_payload_digest(["not", "an", "object"])  # type: ignore[arg-type]


class RepositoryAppendTests(unittest.TestCase):
    def setUp(self) -> None:
        self.store = SQLiteEventStore(":memory:")
        self.addCleanup(self.store.close)
        self.repository = EventRepository(self.store)

    def test_append_stores_the_payload_and_the_metadata(self) -> None:
        record = self.repository.append(
            STREAM_ID,
            "case.created",
            GOOD_PAYLOADS["case.created"],
            occurred_at=NOW,
            metadata=metadata(),
            expected_version=0,
        )
        self.assertEqual(record.stream_version, 1)
        self.assertEqual(record.payload, GOOD_PAYLOADS["case.created"])
        self.assertEqual(record.metadata, metadata().to_dict())
        self.assertEqual(record.payload_sha256, canonical_payload_digest(record.payload))

    def test_an_invalid_payload_appends_nothing(self) -> None:
        with self.assertRaises(EventContractError):
            self.repository.append(
                STREAM_ID,
                "case.created",
                {**GOOD_PAYLOADS["case.created"], "trackingId": "nope"},
                occurred_at=NOW,
                metadata=metadata(),
                expected_version=0,
            )
        self.assertEqual(self.store.latest_sequence, 0)

    def test_an_unknown_event_type_appends_nothing(self) -> None:
        with self.assertRaises(EventContractError):
            self.repository.append(
                STREAM_ID,
                "case.retracted",
                {},
                occurred_at=NOW,
                metadata=metadata(),
                expected_version=0,
            )
        self.assertEqual(self.store.latest_sequence, 0)

    def test_append_batch_writes_every_event_in_one_transaction(self) -> None:
        pending = (
            PendingEvent(
                event_type="case.created",
                payload=GOOD_PAYLOADS["case.created"],
                occurred_at=NOW,
                metadata=metadata(),
            ),
            PendingEvent(
                event_type="case.identified",
                payload=GOOD_PAYLOADS["case.identified"],
                occurred_at=NOW,
                metadata=metadata(),
            ),
        )
        records = self.repository.append_batch(STREAM_ID, pending, expected_version=0)
        self.assertEqual([record.stream_version for record in records], [1, 2])
        self.assertEqual(self.repository.current_version(STREAM_ID), 2)

    def test_one_bad_payload_refuses_the_whole_batch(self) -> None:
        pending = (
            PendingEvent(
                event_type="case.created",
                payload=GOOD_PAYLOADS["case.created"],
                occurred_at=NOW,
                metadata=metadata(),
            ),
            PendingEvent(
                event_type="case.identified",
                payload={"providerTrackingId": ""},
                occurred_at=NOW,
                metadata=metadata(),
            ),
        )
        with self.assertRaises(EventContractError):
            self.repository.append_batch(STREAM_ID, pending, expected_version=0)
        self.assertEqual(self.store.latest_sequence, 0)

    def test_an_empty_batch_is_refused(self) -> None:
        with self.assertRaises(ValueError):
            self.repository.append_batch(STREAM_ID, (), expected_version=0)

    def test_a_stale_expected_version_raises_a_concurrency_error(self) -> None:
        self.repository.append(
            STREAM_ID,
            "case.created",
            GOOD_PAYLOADS["case.created"],
            occurred_at=NOW,
            metadata=metadata(),
            expected_version=0,
        )
        with self.assertRaises(EventConcurrencyError):
            self.repository.append(
                STREAM_ID,
                "case.identified",
                GOOD_PAYLOADS["case.identified"],
                occurred_at=NOW,
                metadata=metadata(),
                expected_version=0,
            )
        self.assertEqual(self.store.latest_sequence, 1)

    def test_latest_payload_returns_the_newest_event_of_one_type(self) -> None:
        for suffix in ("0001", "0002"):
            self.repository.append(
                STREAM_ID,
                "case.identified",
                {"providerTrackingId": f"PROV-{suffix}"},
                occurred_at=NOW,
                metadata=metadata(),
                expected_version=self.repository.current_version(STREAM_ID),
            )
        latest = self.repository.latest_payload(STREAM_ID, "case.identified")
        self.assertEqual(latest, {"providerTrackingId": "PROV-0002"})
        self.assertIsNone(self.repository.latest_payload(STREAM_ID, "case.evaluated"))

    def test_current_version_of_an_unwritten_stream_is_zero(self) -> None:
        self.assertEqual(self.repository.current_version("case/case-ffffffffffffffff"), 0)

    def test_reads_page_past_the_page_size(self) -> None:
        count = READ_PAGE_SIZE + 1
        pending = tuple(
            PendingEvent(
                event_type="case.identified",
                payload={"providerTrackingId": f"PROV-{index:05d}"},
                occurred_at=NOW,
                metadata=metadata(),
            )
            for index in range(count)
        )
        self.repository.append_batch(STREAM_ID, pending, expected_version=0)

        stream = self.repository.read_stream(STREAM_ID)
        self.assertEqual(len(stream), count)
        self.assertEqual([record.stream_version for record in stream], list(range(1, count + 1)))
        self.assertEqual(stream[-1].payload["providerTrackingId"], f"PROV-{count - 1:05d}")

        everything = self.repository.read_all()
        self.assertEqual(len(everything), count)
        self.assertEqual([record.sequence for record in everything], list(range(1, count + 1)))

    def test_reads_of_an_empty_log_are_empty(self) -> None:
        self.assertEqual(self.repository.read_all(), ())
        self.assertEqual(self.repository.read_stream(STREAM_ID), ())

    def test_the_repository_refuses_something_that_is_not_a_store(self) -> None:
        with self.assertRaises(TypeError):
            EventRepository(object())  # type: ignore[arg-type]


if __name__ == "__main__":
    unittest.main()
