# ******************************************************************************
# *Title: Change Stream Tests*
# *Author: Kyle Versluis*
# *Description: Change stream id, contract, placement and store schema 5.*
# ******************************************************************************
"""Tests for change streams: the id, the event contract and store schema 5 (ADR 0018)."""

# *--- Imports ---*

from __future__ import annotations

import ast
import hashlib
import sqlite3
from collections.abc import Mapping
from contextlib import closing
from datetime import UTC, datetime
from pathlib import Path
from typing import Any
from unittest import TestCase
from unittest.mock import patch

from test_coverage_streams import (
    FIRST,
    FOURTH,
    SECOND,
    THIRD,
    StoreCase,
    gap_record,
    metadata,
    record_coverage,
)
from test_events import failure_head

from complyroll.adapters.common import MAX_IDENTITY_CHARS
from complyroll.events import (
    CHANGE_KIND_VALUES,
    CHANGE_RECORDED,
    CHANGE_RECORDED_V1,
    CHANGE_STREAM_EVENT_TYPES,
    CHANGE_STREAM_PREFIX,
    CHANGE_STREAM_SCHEMA_VERSION,
    COVERAGE_RECORDED,
    COVERAGE_STREAM_SCHEMA_VERSION,
    EVENT_TYPES,
    STREAM_EVENT_TYPES,
    EventContractError,
    EventRepository,
    PendingEvent,
    change_identity_breach,
    change_stream_id,
    coverage_stream_id_of,
    event_belongs_on_stream,
    is_artifact_stream,
    is_case_stream,
    is_change_stream,
    is_coverage_stream,
    is_failure_stream,
    stream_kind,
    timestamp_pointers_for,
)
from complyroll.events import contracts as contracts_module
from complyroll.events import repository as repository_module
from complyroll.events.contracts import (
    _CHANGE_NAME_REGEX,
    ARTIFACT_STREAM_EVENT_TYPES,
    CASE_STREAM_EVENT_TYPES,
    COVERAGE_STREAM_EVENT_TYPES,
    FAILURE_STREAM_EVENT_TYPES,
    _placement_problem,
)
from complyroll.reports.changes_input import (
    MAX_CHANGE_RESOURCES,
    MAX_RATIONALE_CHARS,
    ChangeKind,
)
from complyroll.reports.inventory import _NAME, MAX_NAME_CHARS, MAX_REFERENCE_CHARS
from complyroll.reports.kev import utc_text
from complyroll.store import SUPPORTED_SCHEMA_VERSION, SQLiteEventStore, UnsupportedSchemaError
from complyroll.store import sqlite as sqlite_module

# *--- Fixtures ---*

NOW = datetime(2026, 11, 9, 12, 0, tzinfo=UTC)
CHANGE_ID = "CHG-1001"
FIFTH = (5, "change streams, ADR 0018")
#: Every field of the contract, in the order the writer compares them and the file names them.
CONTRACT_FIELDS = (
    "changeId",
    "kind",
    "occurredAt",
    "source",
    "resources",
    "significant",
    "rationale",
    "detectBy",
    "job",
    "changesName",
    "changesSha256",
    "recordedAt",
)
#: Text the reader refuses in identity fields, each a character `identity_problem` prohibits.
PROHIBITED_IDENTITY_TEXT = {
    "a null byte": "lab\x00win",
    "a tab": "lab\twin",
    "a newline": "lab\nwin",
    "a line separator": "lab win",
    "a right-to-left override": "lab‮win",
}


def payload(**overrides: Any) -> dict[str, Any]:
    """Return one payload the writer would store, with the fields given replaced."""
    good: dict[str, Any] = {
        "changeId": CHANGE_ID,
        "kind": "created",
        "occurredAt": "2026-07-01T00:00:00Z",
        "source": {"tool": "terraform", "reference": "apply run 4411"},
        "resources": [{"resourceType": "host", "resourceId": "lab-win-01"}],
        "significant": True,
        "rationale": "New Windows host joined the boundary.",
        "detectBy": "2026-07-08T00:00:00Z",
        "job": "weekly-stig-checklist",
        "changesName": "example-changes",
        "changesSha256": "a" * 64,
        "recordedAt": "2026-11-09T12:00:00Z",
    }
    return {**good, **overrides}


def pending(event_type: str, event_payload: Mapping[str, Any]) -> PendingEvent:
    return PendingEvent(
        event_type=event_type, payload=dict(event_payload), occurred_at=NOW, metadata=metadata()
    )


def record_change(repository: EventRepository, change_id: str = CHANGE_ID) -> str:
    """Record one change through the repository, as the writer will, and return its stream."""
    stream_id = change_stream_id(change_id)
    repository.append(
        stream_id,
        CHANGE_RECORDED,
        payload(changeId=change_id),
        occurred_at=NOW,
        metadata=metadata(),
        expected_version=0,
    )
    return stream_id


# *--- Stream Id ---*


class ChangeStreamIdTests(TestCase):
    """One stream per change, named for the sha256 of its change id."""

    def test_the_stream_id_is_the_sha256_of_the_change_id(self) -> None:
        stream_id = change_stream_id(CHANGE_ID)

        digest = hashlib.sha256(CHANGE_ID.encode("utf-8")).hexdigest()
        self.assertEqual(stream_id, f"change/{digest}")
        self.assertEqual(CHANGE_STREAM_PREFIX, "change")
        self.assertNotIn(CHANGE_ID, stream_id)

    def test_stream_kind_names_a_change_stream_alone(self) -> None:
        stream_id = change_stream_id(CHANGE_ID)

        self.assertEqual(stream_kind(stream_id), "change")
        self.assertTrue(is_change_stream(stream_id))
        self.assertFalse(is_artifact_stream(stream_id))
        self.assertFalse(is_case_stream(stream_id))
        self.assertFalse(is_failure_stream(stream_id))
        self.assertFalse(is_coverage_stream(stream_id))

    def test_a_sibling_prefix_is_no_change_stream(self) -> None:
        # PR 3's `changegap/` stream kind must never read as this one.
        for other in (
            f"changegap/{'a' * 64}",
            f"changes/{'a' * 64}",
            "change",
            f"changed/{'a' * 64}",
        ):
            with self.subTest(other=other):
                self.assertFalse(is_change_stream(other))
                self.assertIsNone(stream_kind(other))

    def test_the_change_id_is_held_to_the_name_rule(self) -> None:
        for value in ("", " CHG-1", "CHG-1 ", "CHG-1\n", "CHÉ-1", "x" * 129, 7, None, True):
            with self.subTest(value=repr(value)[:12]):
                with self.assertRaises(ValueError):
                    change_stream_id(value)  # type: ignore[arg-type]
        self.assertEqual(
            change_stream_id("x" * 128),
            f"change/{hashlib.sha256(b'x' * 128).hexdigest()}",
        )


# *--- Contract ---*


class ChangeRecordedContractTests(TestCase):
    """The `change.recorded` payload: the file's fields as read, plus provenance."""

    def setUp(self) -> None:
        self.store = SQLiteEventStore(":memory:")
        self.addCleanup(self.store.close)
        self.repository = EventRepository(self.store)

    def assert_passes(self, value: Mapping[str, Any]) -> None:
        self.repository.validate_payload(CHANGE_RECORDED, value)

    def assert_refused(self, value: Mapping[str, Any], pointer: str) -> None:
        with self.assertRaises(EventContractError) as caught:
            self.repository.validate_payload(CHANGE_RECORDED, value)
        self.assertIn(pointer, [issue.instance_pointer for issue in caught.exception.issues])

    def test_the_contract_names_exactly_these_fields_in_order(self) -> None:
        self.assertEqual(tuple(CHANGE_RECORDED_V1["properties"]), CONTRACT_FIELDS)
        self.assertEqual(tuple(CHANGE_RECORDED_V1["required"]), CONTRACT_FIELDS)
        self.assertIs(CHANGE_RECORDED_V1["additionalProperties"], False)
        self.assertEqual(CHANGE_RECORDED, "change.recorded")
        self.assertIn(CHANGE_RECORDED, EVENT_TYPES)

    def test_the_contract_is_held_to_the_readers_bounds(self) -> None:
        # The event layer cannot import the report layer, so it spells these and is held here.
        properties = CHANGE_RECORDED_V1["properties"]
        resource = properties["resources"]["items"]["properties"]
        self.assertEqual(_CHANGE_NAME_REGEX, _NAME.pattern)
        self.assertEqual(MAX_NAME_CHARS, 128)
        self.assertEqual(properties["rationale"]["maxLength"], MAX_RATIONALE_CHARS)
        self.assertEqual(
            properties["source"]["properties"]["reference"]["maxLength"], MAX_REFERENCE_CHARS
        )
        self.assertEqual(resource["resourceType"]["maxLength"], MAX_IDENTITY_CHARS)
        self.assertEqual(resource["resourceId"]["maxLength"], MAX_IDENTITY_CHARS)
        self.assertEqual(properties["resources"]["maxItems"], MAX_CHANGE_RESOURCES)
        self.assertEqual(CHANGE_KIND_VALUES, tuple(sorted(kind.value for kind in ChangeKind)))
        self.assertEqual(properties["kind"]["enum"], list(CHANGE_KIND_VALUES))

    def test_the_payload_a_writer_stores_passes(self) -> None:
        self.assert_passes(payload())

    def test_every_field_is_required(self) -> None:
        for field_name in CONTRACT_FIELDS:
            with self.subTest(field=field_name):
                missing = {key: value for key, value in payload().items() if key != field_name}
                self.assert_refused(missing, "")

    def test_a_field_outside_the_contract_is_refused_at_every_level(self) -> None:
        self.assert_refused(payload(trackingId="case-0"), "")
        self.assert_refused(
            payload(source={"tool": "git", "reference": "r", "extra": "x"}), "/source"
        )
        self.assert_refused(
            payload(resources=[{"resourceType": "host", "resourceId": "a", "extra": "x"}]),
            "/resources/0",
        )

    def test_the_name_rule_holds_on_change_id_tool_job_and_changes_name(self) -> None:
        for good in ("x", "x" * 128, "CHG 1001", "a~b"):
            with self.subTest(good=good[:10]):
                self.assert_passes(payload(changeId=good, changesName=good, job=good))
                self.assert_passes(payload(source={"tool": good, "reference": "r"}))
        bad_values = ("", " x", "x ", "x\n", "é", "x" * 129, "a\tb")
        for bad in bad_values:
            with self.subTest(bad=repr(bad)[:12]):
                self.assert_refused(payload(changeId=bad), "/changeId")
                self.assert_refused(payload(changesName=bad), "/changesName")
                self.assert_refused(payload(job=bad), "/job")
                self.assert_refused(payload(source={"tool": bad, "reference": "r"}), "/source/tool")

    def test_the_kind_is_closed(self) -> None:
        for kind in CHANGE_KIND_VALUES:
            with self.subTest(kind=kind):
                self.assert_passes(payload(kind=kind))
        for kind in ("retired", "Created", "", None):
            with self.subTest(kind=kind):
                self.assert_refused(payload(kind=kind), "/kind")

    def test_each_instant_is_a_real_instant_as_the_writer_spells_it(self) -> None:
        for field_name in ("occurredAt", "recordedAt"):
            for text in (
                "2026-07-01T00:00:00+00:00",
                "2026-07-01T02:00:00+02:00",
                "2026-07-01",
                "2026-02-30T00:00:00Z",
                "2026-07-01T24:00:00Z",
                # The shape the contract's regular expression admits and `iso_utc` never writes.
                "2026-07-01T00:00:00.5Z",
                "2026-07-01T00:00:00.000000Z",
                "2026-07-01T00:00:00Z\n",
            ):
                with self.subTest(field=field_name, text=text):
                    self.assert_refused(payload(**{field_name: text}), f"/{field_name}")
        self.assert_passes(payload(occurredAt="2026-07-01T00:00:00.500000Z"))

    def test_detect_by_is_null_or_a_canonical_instant_not_before_the_change(self) -> None:
        self.assert_passes(payload(detectBy=None))
        self.assert_passes(payload(detectBy="2026-07-01T00:00:00Z"))
        self.assert_refused(payload(detectBy="2026-06-30T23:59:59Z"), "/detectBy")
        self.assert_refused(payload(detectBy="2026-07-08T00:00:00+00:00"), "/detectBy")
        self.assert_refused(payload(detectBy=""), "/detectBy")
        self.assert_refused(payload(detectBy="2026-02-30T00:00:00Z"), "/detectBy")

    def test_job_may_be_null(self) -> None:
        self.assert_passes(payload(job=None))

    def test_a_reference_is_identity_text_at_most_512(self) -> None:
        self.assert_passes(payload(source={"tool": "git", "reference": "r" * 512}))
        self.assert_passes(payload(source={"tool": "git", "reference": "café commit"}))
        for bad in ("", "   ", "r" * 513):
            with self.subTest(bad=bad[:8]):
                self.assert_refused(
                    payload(source={"tool": "git", "reference": bad}), "/source/reference"
                )
        for label, text in PROHIBITED_IDENTITY_TEXT.items():
            with self.subTest(label):
                self.assert_refused(
                    payload(source={"tool": "git", "reference": text}), "/source/reference"
                )

    def test_a_resource_pair_is_identity_text_with_no_colon_or_package_type(self) -> None:
        for field_name, pointer in (
            ("resourceType", "/resources/0/resourceType"),
            ("resourceId", "/resources/0/resourceId"),
        ):
            for bad in ("", "  ", "x" * 513):
                with self.subTest(field=field_name, bad=bad[:8]):
                    self.assert_refused(
                        payload(
                            resources=[{"resourceType": "host", "resourceId": "a", field_name: bad}]
                        ),
                        pointer,
                    )
            for label, text in PROHIBITED_IDENTITY_TEXT.items():
                with self.subTest(field=field_name, label=label):
                    self.assert_refused(
                        payload(
                            resources=[
                                {"resourceType": "host", "resourceId": "a", field_name: text}
                            ]
                        ),
                        pointer,
                    )
        for bad in ("has:colon", "package"):
            with self.subTest(bad=bad):
                self.assert_refused(
                    payload(resources=[{"resourceType": bad, "resourceId": "a"}]),
                    "/resources/0/resourceType",
                )
        self.assert_passes(payload(resources=[{"resourceType": "logical", "resourceId": "a:b"}]))

    def test_resources_are_one_to_the_bound_sorted_and_distinct(self) -> None:
        def pair(resource_id: str, resource_type: str = "host") -> dict[str, str]:
            return {"resourceType": resource_type, "resourceId": resource_id}

        self.assert_refused(payload(resources=[]), "/resources")
        self.assert_refused(payload(resources="host"), "/resources")
        self.assert_refused(payload(resources=[pair("a"), pair("a")]), "/resources")
        # Sorted by type then id, as `Change` holds them: a reader refuses any other order.
        self.assert_refused(payload(resources=[pair("b"), pair("a")]), "/resources")
        self.assert_refused(payload(resources=[pair("a", "z"), pair("b", "a")]), "/resources")
        self.assert_passes(payload(resources=[pair("a"), pair("b")]))
        self.assert_passes(payload(resources=[pair("z", "a"), pair("a", "b")]))
        at_bound = [pair(f"h{index:04d}") for index in range(MAX_CHANGE_RESOURCES)]
        self.assert_passes(payload(resources=at_bound))
        over_bound = [pair(f"h{index:04d}") for index in range(MAX_CHANGE_RESOURCES + 1)]
        self.assert_refused(payload(resources=over_bound), "/resources")

    def test_significant_is_a_json_boolean(self) -> None:
        self.assert_passes(payload(significant=False))
        for bad in (1, 0, "true", None):
            with self.subTest(bad=bad):
                self.assert_refused(payload(significant=bad), "/significant")

    def test_a_rationale_is_clean_text_at_most_512(self) -> None:
        self.assert_passes(payload(rationale="r" * 512))
        # The reader keeps a tab and a newline when it cleans a rationale.
        self.assert_passes(payload(rationale="line one\n\tline two"))
        for bad in ("", "   ", "r" * 513):
            with self.subTest(bad=bad[:8]):
                self.assert_refused(payload(rationale=bad), "/rationale")
        for label, text in (
            ("a null byte", "bad\x00text"),
            ("a line separator", "bad text"),
            ("a right-to-left override", "bad‮text"),
        ):
            with self.subTest(label):
                self.assert_refused(payload(rationale=text), "/rationale")

    def test_the_digest_is_a_lowercase_sha256(self) -> None:
        for digest in ("A" * 64, "a" * 63, f"sha256:{'a' * 64}", f"{'a' * 64}\n"):
            with self.subTest(digest=digest[:8]):
                self.assert_refused(payload(changesSha256=digest), "/changesSha256")

    def test_each_instant_field_is_parsed_semantically(self) -> None:
        self.assertEqual(
            timestamp_pointers_for(CHANGE_RECORDED), ("/detectBy", "/occurredAt", "/recordedAt")
        )
        self.assertEqual(utc_text(datetime(2026, 7, 1, tzinfo=UTC)), "2026-07-01T00:00:00Z")


# *--- Placement ---*


class ChangePlacementTests(TestCase):
    """A change event lives on a change stream, and a change stream holds nothing else."""

    def test_the_table_places_the_one_change_event(self) -> None:
        self.assertEqual(CHANGE_STREAM_EVENT_TYPES, {CHANGE_RECORDED})
        self.assertEqual(STREAM_EVENT_TYPES["change"], CHANGE_STREAM_EVENT_TYPES)

    def test_a_change_event_belongs_on_a_change_stream_alone(self) -> None:
        stream_id = change_stream_id(CHANGE_ID)
        self.assertTrue(event_belongs_on_stream(CHANGE_RECORDED, stream_id))
        for other in (
            f"artifact/{'a' * 64}/complyroll.cklb/1",
            "case/case-0123456789abcdef",
            f"failure/{'a' * 64}/complyroll.sarif/1",
            f"coverage/{'a' * 64}",
            f"changegap/{'a' * 64}",
            "somewhere-else",
        ):
            with self.subTest(other=other):
                self.assertFalse(event_belongs_on_stream(CHANGE_RECORDED, other))

    def test_a_change_stream_carries_no_other_event_type(self) -> None:
        stream_id = change_stream_id(CHANGE_ID)
        for event_type in EVENT_TYPES:
            if event_type == CHANGE_RECORDED:
                continue
            with self.subTest(event_type=event_type):
                self.assertFalse(event_belongs_on_stream(event_type, stream_id))

    def test_the_placement_guard_keeps_the_change_type_to_its_kind(self) -> None:
        artifact = frozenset(ARTIFACT_STREAM_EVENT_TYPES)
        case = frozenset(CASE_STREAM_EVENT_TYPES)
        failure = frozenset(FAILURE_STREAM_EVENT_TYPES)
        coverage = frozenset(COVERAGE_STREAM_EVENT_TYPES)
        change = frozenset(CHANGE_STREAM_EVENT_TYPES)
        published = frozenset(EVENT_TYPES)
        self.assertIsNone(_placement_problem(artifact, case, failure, coverage, change, published))
        for label, tables, expected in (
            (
                "an unplaced change event",
                (artifact, case, failure, coverage, change - {CHANGE_RECORDED}),
                "must belong to a stream kind",
            ),
            (
                "a change event on an artifact stream",
                (artifact | {CHANGE_RECORDED}, case, failure, coverage, change),
                "change stream kind alone",
            ),
            (
                "a change event on a coverage stream",
                (artifact, case, failure, coverage | {CHANGE_RECORDED}, change),
                "change stream kind alone",
            ),
            (
                "an observation on a change stream",
                (artifact, case, failure, coverage, change | {"observation.recorded"}),
                "change stream kind alone",
            ),
        ):
            with self.subTest(shape=label):
                problem = _placement_problem(*tables, published)
                self.assertIsNotNone(problem)
                self.assertIn(expected, str(problem))


# *--- Append ---*


class ChangeAppendTests(StoreCase):
    """The repository holds a change stream to one event naming its own change."""

    def append(self, stream_id: str, event_type: str, value: Mapping[str, Any]) -> None:
        self.repository.append(
            stream_id,
            event_type,
            value,
            occurred_at=NOW,
            metadata=metadata(),
            expected_version=0,
        )

    def assert_refused(
        self, stream_id: str, event_type: str, value: Mapping[str, Any], message: str
    ) -> None:
        with self.assertRaises(EventContractError) as caught:
            self.append(stream_id, event_type, value)
        self.assertIn(message, str(caught.exception))
        self.assertEqual(self.store.latest_sequence, 0)
        self.assertEqual(self.store.schema_version, 1)

    def test_a_change_appends_as_one_event_on_its_own_stream(self) -> None:
        stream_id = record_change(self.repository)

        (stored,) = self.repository.read_stream(stream_id)
        self.assertEqual(stored.event_type, CHANGE_RECORDED)
        self.assertEqual(stored.event_version, 1)
        self.assertEqual(stored.payload, payload())

    def test_a_change_event_is_refused_on_every_other_kind_of_stream(self) -> None:
        for other in (
            f"artifact/{'a' * 64}/complyroll.cklb/1",
            "case/case-0123456789abcdef",
            f"failure/{'a' * 64}/complyroll.sarif/1",
            f"coverage/{'a' * 64}",
            f"changegap/{'a' * 64}",
        ):
            with self.subTest(stream=other):
                self.assert_refused(other, CHANGE_RECORDED, payload(), "does not belong")

    def test_another_event_type_is_refused_on_a_change_stream(self) -> None:
        stream_id = change_stream_id(CHANGE_ID)
        for event_type, event_payload in (
            ("case.identified", {"providerTrackingId": "PROV-1"}),
            ("failure.recorded", failure_head()),
            (COVERAGE_RECORDED, {"rule": "x"}),
        ):
            with self.subTest(event_type=event_type):
                with self.assertRaises(EventContractError):
                    self.append(stream_id, event_type, event_payload)
        self.assertEqual(self.store.latest_sequence, 0)
        self.assert_refused(
            stream_id,
            "case.identified",
            {"providerTrackingId": "PROV-1"},
            "which is a change stream",
        )

    def test_the_stream_id_must_name_the_payloads_change(self) -> None:
        other = change_stream_id("CHG-9999")

        self.assert_refused(other, CHANGE_RECORDED, payload(), f"on stream {other!r}")

    def test_the_breach_check_answers_only_for_a_change_event_on_a_change_stream(self) -> None:
        stream_id = change_stream_id(CHANGE_ID)
        self.assertIsNone(change_identity_breach(stream_id, CHANGE_RECORDED, payload()))
        self.assertIsNone(
            change_identity_breach(f"coverage/{'a' * 64}", CHANGE_RECORDED, payload())
        )
        self.assertIsNone(change_identity_breach(stream_id, "case.identified", payload()))
        wrong = change_stream_id("CHG-9999")
        self.assertIn(
            f"on stream {wrong!r}", str(change_identity_breach(wrong, CHANGE_RECORDED, payload()))
        )
        # A payload naming no change id at all still reads as a breach, never a crash.
        for bad in (None, 7, "", "x\n"):
            with self.subTest(bad=repr(bad)):
                breach = change_identity_breach(stream_id, CHANGE_RECORDED, {"changeId": bad})
                self.assertIn("names no change stream", str(breach))

    def test_a_change_stream_is_written_once_with_one_event(self) -> None:
        stream_id = record_change(self.repository)

        with self.assertRaises(EventContractError) as caught:
            self.repository.append(
                stream_id,
                CHANGE_RECORDED,
                payload(),
                occurred_at=NOW,
                metadata=metadata(),
                expected_version=1,
            )
        self.assertIn("exactly one", str(caught.exception))
        self.assertEqual(self.repository.current_version(stream_id), 1)

    def test_a_batch_of_two_is_refused_on_a_fresh_change_stream(self) -> None:
        stream_id = change_stream_id("CHG-2")
        one = pending(CHANGE_RECORDED, payload(changeId="CHG-2"))

        with self.assertRaises(EventContractError) as caught:
            self.repository.append_batch(stream_id, (one, one), expected_version=0)

        self.assertIn("exactly one", str(caught.exception))
        self.assertEqual(self.repository.current_version(stream_id), 0)


# *--- Schema 5 ---*


class ChangeSchemaMarkingTests(StoreCase):
    """A store holding a change stream is marked schema 5 in the same transaction.

    A build that knows only schema 4 reads a change stream as a stream of no kind, so a store
    holding one says so before such a build can open it. A store that never records a change
    stays at its version and stays readable by that build (ADR 0018).
    """

    def damage(self, statement: str) -> None:
        self.store.close()
        with closing(sqlite3.connect(self.path, isolation_level=None)) as connection:
            connection.execute(statement)

    def test_the_constants(self) -> None:
        self.assertEqual(CHANGE_STREAM_SCHEMA_VERSION, 5)
        self.assertEqual(SUPPORTED_SCHEMA_VERSION, CHANGE_STREAM_SCHEMA_VERSION)
        self.assertLess(COVERAGE_STREAM_SCHEMA_VERSION, CHANGE_STREAM_SCHEMA_VERSION)
        self.assertEqual(sqlite_module._MIGRATION_DESCRIPTIONS[5], FIFTH[1])

    def test_first_change_append_marks_schema_5_with_its_events(self) -> None:
        self.assertEqual((self.store.schema_version, self.migrations()), (1, [FIRST]))

        stream_id = record_change(self.repository)

        self.assertEqual(self.store.schema_version, 5)
        self.assertEqual(self.migrations(), [FIRST, SECOND, THIRD, FOURTH, FIFTH])
        self.assertEqual(self.repository.current_version(stream_id), 1)
        self.store.close()
        reopened = SQLiteEventStore(self.path)
        self.addCleanup(reopened.close)
        self.assertEqual(reopened.schema_version, 5)
        self.assertTrue(reopened.verify_history().ok)

    def test_rollback_undoes_the_schema_mark(self) -> None:
        self.record_failure()
        self.assertEqual(self.store.schema_version, 2)
        with self.assertRaises(RuntimeError):
            with self.repository.transaction():
                record_change(self.repository)
                self.assertEqual(self.store.schema_version, 5)
                raise RuntimeError("abandon the change")

        self.assertEqual(self.store.schema_version, 2)
        self.assertEqual(self.migrations(), [FIRST, SECOND])
        self.assertEqual(self.store.latest_sequence, 2)

    def test_marking_inserts_each_missing_record(self) -> None:
        def from_nothing() -> None:
            pass

        def from_failure() -> None:
            self.record_failure()

        def from_hold() -> None:
            self.record_failure()
            self.record_hold()

        def from_coverage() -> None:
            record_coverage(self.repository, gap_record())

        for label, prepare in (
            ("schema 1", from_nothing),
            ("schema 2", from_failure),
            ("schema 3", from_hold),
            ("schema 4", from_coverage),
        ):
            with self.subTest(label):
                self.setUp()
                prepare()
                record_change(self.repository)

                self.assertEqual(self.store.schema_version, 5)
                self.assertEqual(self.migrations(), [FIRST, SECOND, THIRD, FOURTH, FIFTH])

    def test_a_later_change_marks_nothing_again(self) -> None:
        record_change(self.repository)
        record_change(self.repository, "CHG-1002")

        self.assertEqual(self.store.schema_version, 5)
        self.assertEqual(self.migrations(), [FIRST, SECOND, THIRD, FOURTH, FIFTH])

    def test_every_other_append_leaves_a_store_below_schema_5(self) -> None:
        self.record_failure()
        self.record_hold()
        record_coverage(self.repository, gap_record())

        self.assertEqual(self.store.schema_version, 4)
        self.assertEqual(self.migrations(), [FIRST, SECOND, THIRD, FOURTH])

    def test_the_marking_changes_no_schema_object(self) -> None:
        def objects() -> list[tuple[str, str, str, str | None]]:
            with closing(sqlite3.connect(self.path)) as connection:
                rows = connection.execute(
                    "SELECT type, name, tbl_name, sql FROM sqlite_master ORDER BY type, name"
                ).fetchall()
            return [(str(kind), str(name), str(table), sql) for kind, name, table, sql in rows]

        before = objects()
        record_change(self.repository)

        self.assertEqual(self.store.schema_version, 5)
        self.assertEqual(objects(), before)

    def test_schema_4_store_opens_and_is_not_marked_by_a_read(self) -> None:
        stream_id = record_coverage(self.repository, gap_record())
        self.assertEqual(self.store.schema_version, 4)
        self.store.close()

        reopened = SQLiteEventStore(self.path)
        self.addCleanup(reopened.close)
        repository = EventRepository(reopened)
        events = repository.read_stream(stream_id)
        all_events = tuple(repository.read_all())
        result = reopened.verify_history()

        self.assertEqual(len(events), 2)
        self.assertEqual(len(all_events), 2)
        self.assertTrue(result.ok)
        self.assertEqual(reopened.schema_version, 4)
        self.assertEqual(self.migrations(), [FIRST, SECOND, THIRD, FOURTH])
        self.assertEqual(coverage_stream_id_of(gap_record()), stream_id)

    def test_schema_5_needs_every_migration_record(self) -> None:
        for missing in (1, 2, 3, 4, 5):
            with self.subTest(missing=missing):
                self.setUp()
                record_change(self.repository)
                self.damage(f"DELETE FROM complyroll_schema_migrations WHERE version = {missing}")

                with self.assertRaises(UnsupportedSchemaError) as caught:
                    SQLiteEventStore(self.path)

                self.assertIn(f"missing migration record {missing}", str(caught.exception))

    def test_a_build_that_opens_only_schema_4_refuses_a_store_that_recorded_a_change(self) -> None:
        record_change(self.repository)
        self.store.close()

        with patch.object(sqlite_module, "SUPPORTED_SCHEMA_VERSION", 4):
            with self.assertRaises(UnsupportedSchemaError) as caught:
                SQLiteEventStore(self.path)

        self.assertEqual(
            str(caught.exception), "database schema 5 is newer than supported schema 4"
        )

    def test_a_build_that_opens_only_schema_4_still_opens_a_store_with_no_change(self) -> None:
        record_coverage(self.repository, gap_record())
        self.store.close()

        with patch.object(sqlite_module, "SUPPORTED_SCHEMA_VERSION", 4):
            reopened = SQLiteEventStore(self.path)
            self.addCleanup(reopened.close)
            self.assertEqual(reopened.schema_version, 4)

    def test_a_store_newer_than_schema_5_is_refused(self) -> None:
        record_change(self.repository)
        self.damage("PRAGMA user_version = 6")

        with self.assertRaises(UnsupportedSchemaError) as caught:
            SQLiteEventStore(self.path)

        self.assertIn("database schema 6 is newer than supported schema 5", str(caught.exception))


# *--- Layering ---*


class ChangeLayeringTests(TestCase):
    """The event layer stays free of the report layer it is imported by."""

    def test_the_event_modules_do_not_import_the_report_layer(self) -> None:
        for module in (contracts_module, repository_module):
            with self.subTest(module=module.__name__):
                tree = ast.parse(Path(str(module.__file__)).read_text(encoding="utf-8"))
                imported = [
                    str(node.module) for node in ast.walk(tree) if isinstance(node, ast.ImportFrom)
                ]
                self.assertEqual(
                    [name for name in imported if name.startswith("complyroll.reports")], []
                )


if __name__ == "__main__":
    import unittest

    unittest.main()
