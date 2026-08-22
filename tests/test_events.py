"""Tests for the published event contracts and the repository that enforces them."""

from __future__ import annotations

import unittest
import uuid
from copy import deepcopy
from dataclasses import replace
from datetime import UTC, datetime, timedelta, timezone
from typing import Any

from jsonschema import Draft202012Validator

from complyroll import __version__
from complyroll.events import (
    EVENT_CONTRACTS,
    EVENT_TYPES,
    READ_PAGE_SIZE,
    UNDISPOSED_STATUSES,
    ContractIssue,
    EventContractError,
    EventMetadata,
    EventRepository,
    PendingEvent,
    artifact_stream_id,
    canonical_payload_digest,
    case_stream_id,
    is_artifact_stream,
    is_case_stream,
    iso_utc,
    parse_utc,
    require_tracking_id,
    schema_for,
    tracking_id_from_stream,
)
from complyroll.events.contracts import _MAX_STREAM_ID_LENGTH
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
#: history that no evaluations file could have produced, and the last one would route
#: a vulnerability out of the detail report carrying no rationale at all.
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
)


def metadata(actor: str = "test-user") -> EventMetadata:
    return EventMetadata(actor=actor, run_id="run-fixed")


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


class ContractIssueTests(unittest.TestCase):
    def test_render_names_the_pointer_validator_and_message(self) -> None:
        issue = ContractIssue("/pain", "maximum", "9 is greater than the maximum of 5")
        self.assertEqual(issue.render(), "/pain: maximum: 9 is greater than the maximum of 5")

    def test_render_calls_the_document_root_root(self) -> None:
        issue = ContractIssue("", "required", "'pain' is a required property")
        self.assertEqual(issue.render(), "<root>: required: 'pain' is a required property")


class EventMetadataTests(unittest.TestCase):
    def test_to_dict_has_the_stored_shape(self) -> None:
        stored = EventMetadata(actor="kyle", run_id="run-1").to_dict()
        self.assertEqual(sorted(stored), ["actor", "method", "runId", "tool", "toolVersion"])
        self.assertEqual(stored["actor"], "kyle")
        self.assertEqual(stored["method"], "cli")
        self.assertEqual(stored["tool"], "complyroll")
        self.assertEqual(stored["toolVersion"], __version__)
        self.assertEqual(stored["runId"], "run-1")

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
