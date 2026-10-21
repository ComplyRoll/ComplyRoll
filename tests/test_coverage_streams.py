# ******************************************************************************
# *Title: Coverage Stream Tests*
# *Author: Kyle Versluis*
# *Description: Coverage stream contract, store schema 4 and the five audits.*
# ******************************************************************************
"""Tests for coverage streams: the head, the stream id, schema 4 and the audits (ADR 0015)."""

# *--- Imports ---*

from __future__ import annotations

import json
import sqlite3
import tempfile
import unittest
from collections.abc import Mapping, Sequence
from contextlib import closing
from dataclasses import replace
from datetime import UTC, datetime
from pathlib import Path
from typing import Any
from unittest.mock import patch

from test_cli import SMUGGLED_METADATA, PersistedStoreTestCase, run
from test_coverage_gaps import GROUP_KEY, fleet_result, gap
from test_events import failure_batch, failure_head, system_record, with_value
from test_events import observation as artifact_observation

from complyroll.correlation import group_open_observations
from complyroll.events import (
    COVERAGE_ANCHOR_VALUES,
    COVERAGE_BASIS_TEXTS,
    COVERAGE_DESCRIPTION,
    COVERAGE_METADATA_KEYS,
    COVERAGE_PARSER_NAME,
    COVERAGE_PARSER_VERSION,
    COVERAGE_RECORD_ID,
    COVERAGE_RECORDED,
    COVERAGE_RECORDED_V1,
    COVERAGE_SOURCE_TOOL,
    COVERAGE_SOURCE_TYPE,
    COVERAGE_STREAM_EVENT_TYPES,
    COVERAGE_STREAM_SCHEMA_VERSION,
    COVERAGE_TITLE,
    FAILURE_HELD,
    HELD_FAILURE_SCHEMA_VERSION,
    EventContractError,
    EventMetadata,
    EventRepository,
    PendingEvent,
    coverage_head_order_message,
    coverage_head_payload,
    coverage_record_disagreement,
    coverage_record_problem,
    coverage_stream_fingerprint,
    coverage_stream_id,
    coverage_stream_id_of,
    coverage_stream_id_of_payload,
    failure_stream_id,
    is_artifact_stream,
    is_case_stream,
    is_coverage_stream,
    is_failure_stream,
    stream_kind,
)
from complyroll.events.contracts import _COMPONENT_PATTERN
from complyroll.history import (
    HistoryError,
    artifact_history,
    audit_history,
    correlate_cases,
    fold_all_cases,
    rehydrate_observations,
)
from complyroll.models import RESERVED_SOURCE_TYPE_PREFIX, Observation
from complyroll.policy import COVERAGE_RULE_IDS
from complyroll.reports.coverage import COVERAGE_BASIS, MVX_RULE, PSD_RULE, AnchorKind
from complyroll.reports.gaps import (
    COVERAGE_GAP_DESCRIPTION,
    COVERAGE_GAP_METADATA_KEYS,
    COVERAGE_GAP_PARSER_NAME,
    COVERAGE_GAP_PARSER_VERSION,
    COVERAGE_GAP_RECORD_ID,
    COVERAGE_GAP_SOURCE_TOOL,
    COVERAGE_GAP_SOURCE_TYPE,
    COVERAGE_GAP_TITLE,
    coverage_gap_observations,
)
from complyroll.store import (
    SUPPORTED_SCHEMA_VERSION,
    NewEvent,
    SQLiteEventStore,
    UnsupportedSchemaError,
)
from complyroll.store import sqlite as sqlite_module

# *--- Fixtures ---*

NOW = datetime(2026, 8, 21, 12, 0, tzinfo=UTC)
RUN_ID = "run-00000000-0000-4000-8000-000000000001"
#: The four migration records a schema 4 store holds, in order.
FIRST = (1, "append-only event history and projection checkpoints")
SECOND = (2, "failure streams, ADR 0014")
THIRD = (3, "held failures, ADR 0014 amendment 2026-10-13")
FOURTH = (4, "coverage gaps, ADR 0015")
#: The job lab-01 and web-01 share, so their MVX gaps share one context key.
JOB_KEY = "VDR-TFR-MVX:job:nightly-openscap"
#: The values each head field takes in the disagreement tests: each one passes the contract
#: and names something the gap record does not.
OTHER_HEAD_VALUES: dict[str, str] = {
    "rule": "VDR-TFR-PDD",
    "contextKey": "VDR-TFR-MVX:resource:host:lab-01",
    "windowClosedAt": "2026-07-09T00:00:00Z",
    "anchor": "verification",
    "anchorAt": "2026-06-30T00:00:00Z",
    "inventorySha256": "b" * 64,
}
#: Fields the gap builder fixes, a value for each that the payload contract admits, and the
#: reason the identity check gives for it. The fingerprint covers none of them, so an edited
#: record still names its stream.
FIXED_FIELD_EDITS: dict[str, tuple[Any, str]] = {
    "disposition": ("pass", "its disposition is 'pass'"),
    "source_severity": ("high", "its source severity is 'high'"),
    "source_identifiers": (["CVE-2099-0001"], "its source identifiers are ['CVE-2099-0001']"),
    "evidence_ids": ([f"sha256:{'d' * 64}"], f"its evidence ids are ['sha256:{'d' * 64}']"),
    # The report prints both; the title is built from the rule, the resource and the close.
    "title": ("Nothing to see here", "its title is 'Nothing to see here'"),
    "description": ("x", "its description is 'x'"),
}
#: The two artifact fields a gap record leaves empty. The observation contract refuses either
#: on any system record before the identity check reads the payload.
ARTIFACT_FIELD_EDITS: dict[str, tuple[str, str]] = {
    "source_artifact_digest": ("c" * 64, f"its source artifact digest is '{'c' * 64}'"),
    "source_artifact_name": ("scan.xml", "its source artifact name is 'scan.xml'"),
}
#: A contract-valid event of another stream kind, planted on a coverage stream.
FOREIGN_EVENT: tuple[str, dict[str, Any]] = (
    "case.identified",
    {"providerTrackingId": "PROV-2026-0001"},
)


def gap_record(rule_id: str = MVX_RULE, context_key: str = "host:lab-01") -> Observation:
    """Return one gap record of the builder tests' fleet: lab-01's MVX window by default."""
    return gap(fleet_result(), rule_id, context_key)


def metadata() -> EventMetadata:
    return EventMetadata(actor="test-user", run_id=RUN_ID)


def pending(event_type: str, payload: Mapping[str, Any]) -> PendingEvent:
    return PendingEvent(
        event_type=event_type, payload=dict(payload), occurred_at=NOW, metadata=metadata()
    )


def coverage_events(
    record: Observation, head: Mapping[str, Any] | None = None
) -> list[tuple[str, dict[str, Any]]]:
    """Return the two events one coverage stream holds: its head, then its gap record."""
    return [
        (COVERAGE_RECORDED, dict(coverage_head_payload(record) if head is None else head)),
        ("observation.recorded", record.to_canonical_dict()),
    ]


def record_coverage(repository: EventRepository, record: Observation) -> str:
    """Record one gap through the repository, as the writer will, and return its stream."""
    stream_id = coverage_stream_id_of(record)
    repository.append_batch(
        stream_id,
        tuple(pending(event_type, payload) for event_type, payload in coverage_events(record)),
        expected_version=0,
    )
    return stream_id


def rebuilt(record: Observation, **changes: Any) -> Observation:
    """Return the record with fields changed, under the id and fingerprint it now derives."""
    moved = replace(record, **changes)
    return replace(moved, observation_id=moved.derived_observation_id)


class StoreCase(unittest.TestCase):
    """A temporary store on disk, a repository over it, and a writer past the repository."""

    def setUp(self) -> None:
        directory = tempfile.TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        self.path = Path(directory.name) / "history.sqlite"
        self.open_store()

    def open_store(self) -> None:
        self.store = SQLiteEventStore(self.path)
        self.addCleanup(self.store.close)
        self.repository = EventRepository(self.store)

    def migrations(self) -> list[tuple[int, str]]:
        with closing(sqlite3.connect(self.path)) as connection:
            rows = connection.execute(
                "SELECT version, description FROM complyroll_schema_migrations ORDER BY version"
            ).fetchall()
        return [(int(version), str(description)) for version, description in rows]

    def stage(
        self,
        stream_id: str,
        events: Sequence[tuple[str, Mapping[str, Any]]],
        *,
        requires_schema: int = COVERAGE_STREAM_SCHEMA_VERSION,
    ) -> list[int]:
        """Append events to one new stream past the repository, in order, and return them."""
        sequences = []
        for version, (event_type, payload) in enumerate(events):
            (appended,) = self.store.append(
                stream_id,
                [
                    NewEvent(
                        event_type=event_type,
                        occurred_at=NOW,
                        payload=dict(payload),
                        metadata=metadata().to_dict(),
                    )
                ],
                expected_version=version,
                requires_schema=requires_schema,
            )
            sequences.append(appended.sequence)
        return sequences

    def record_failure(self, digest: str = "a" * 64) -> None:
        self.repository.append_batch(
            failure_stream_id(digest, "complyroll.sarif", "1"),
            failure_batch(failure_head(digest), system_record(digest)),
            expected_version=0,
        )

    def record_hold(self) -> None:
        self.repository.append_batch(
            failure_stream_id("a" * 64, "complyroll.sarif", "2"),
            failure_batch(
                failure_head(parser_version="2"),
                system_record(parser_version="2"),
                head_type=FAILURE_HELD,
            ),
            expected_version=0,
        )


# *--- Identity Constants ---*


class CoverageIdentityConstantTests(unittest.TestCase):
    """The event layer spells the builder's identity without importing the report layer."""

    def test_the_event_layer_spells_the_builders_identity(self) -> None:
        self.assertEqual(
            (
                COVERAGE_SOURCE_TYPE,
                COVERAGE_SOURCE_TOOL,
                COVERAGE_PARSER_NAME,
                COVERAGE_PARSER_VERSION,
                COVERAGE_RECORD_ID,
            ),
            (
                COVERAGE_GAP_SOURCE_TYPE,
                COVERAGE_GAP_SOURCE_TOOL,
                COVERAGE_GAP_PARSER_NAME,
                COVERAGE_GAP_PARSER_VERSION,
                COVERAGE_GAP_RECORD_ID,
            ),
        )
        self.assertTrue(COVERAGE_SOURCE_TYPE.startswith(RESERVED_SOURCE_TYPE_PREFIX))
        self.assertEqual(COVERAGE_METADATA_KEYS, COVERAGE_GAP_METADATA_KEYS)
        # A reworded basis is added to the texts the audit accepts, never put in place of
        # one: every gap a store already holds keeps the text it was recorded with.
        self.assertIn(COVERAGE_BASIS, COVERAGE_BASIS_TEXTS)
        self.assertEqual(
            (COVERAGE_TITLE, COVERAGE_DESCRIPTION),
            (COVERAGE_GAP_TITLE, COVERAGE_GAP_DESCRIPTION),
        )
        for record in coverage_gap_observations(fleet_result(), ingested_at=NOW):
            with self.subTest(context=record.context_key):
                self.assertEqual(
                    tuple(sorted(dict(record.source_metadata))), COVERAGE_METADATA_KEYS
                )

    def test_the_head_vocabularies_are_the_coverage_blocks(self) -> None:
        properties = COVERAGE_RECORDED_V1["properties"]
        self.assertEqual(COVERAGE_ANCHOR_VALUES, tuple(sorted(kind.value for kind in AnchorKind)))
        self.assertEqual(properties["anchor"]["enum"], list(COVERAGE_ANCHOR_VALUES))
        self.assertEqual(properties["rule"]["enum"], list(COVERAGE_RULE_IDS))

    def test_a_coverage_stream_needs_schema_4_and_this_build_opens_it(self) -> None:
        self.assertEqual(COVERAGE_STREAM_SCHEMA_VERSION, 4)
        self.assertEqual(SUPPORTED_SCHEMA_VERSION, COVERAGE_STREAM_SCHEMA_VERSION)
        self.assertLess(HELD_FAILURE_SCHEMA_VERSION, COVERAGE_STREAM_SCHEMA_VERSION)


# *--- Contract ---*


class CoverageRecordedContractTests(unittest.TestCase):
    """The head of a coverage stream: the window that closed, closed over its vocabulary."""

    def setUp(self) -> None:
        self.store = SQLiteEventStore(":memory:")
        self.addCleanup(self.store.close)
        self.repository = EventRepository(self.store)
        self.record = gap_record()

    def payload(self, **overrides: Any) -> dict[str, Any]:
        return {**coverage_head_payload(self.record), **overrides}

    def assert_refused(self, payload: Mapping[str, Any], pointer: str) -> None:
        with self.assertRaises(EventContractError) as caught:
            self.repository.validate_payload(COVERAGE_RECORDED, payload)
        self.assertIn(pointer, [issue.instance_pointer for issue in caught.exception.issues])

    def test_the_head_is_read_off_its_gap_record_and_satisfies_its_contract(self) -> None:
        self.assertEqual(
            coverage_head_payload(self.record),
            {
                "rule": "VDR-TFR-MVX",
                "contextKey": JOB_KEY,
                "windowClosedAt": "2026-07-08T00:00:00Z",
                "anchor": "declared",
                "anchorAt": "2026-07-01T00:00:00Z",
                "inventorySha256": fleet_result().inventory.sha256,
            },
        )
        for record in coverage_gap_observations(fleet_result(), ingested_at=NOW):
            with self.subTest(context=record.context_key):
                self.repository.validate_payload(COVERAGE_RECORDED, coverage_head_payload(record))

    def test_the_rule_is_one_of_the_five_coverage_rules(self) -> None:
        for rule in COVERAGE_RULE_IDS:
            with self.subTest(rule=rule):
                self.repository.validate_payload(COVERAGE_RECORDED, self.payload(rule=rule))
        for rule in ("VDR-CSO-FAV", "VDR-TFR-KEV", "vdr-tfr-mvx", ""):
            with self.subTest(rule=rule):
                self.assert_refused(self.payload(rule=rule), "/rule")

    def test_the_anchor_is_closed(self) -> None:
        for anchor in COVERAGE_ANCHOR_VALUES:
            with self.subTest(anchor=anchor):
                self.repository.validate_payload(COVERAGE_RECORDED, self.payload(anchor=anchor))
        self.assert_refused(self.payload(anchor="scan"), "/anchor")

    def test_blank_text_is_refused_where_the_contract_wants_text(self) -> None:
        for blank in ("", "   "):
            with self.subTest(value=blank):
                self.assert_refused(self.payload(contextKey=blank), "/contextKey")

    def test_the_inventory_digest_is_a_lowercase_sha256(self) -> None:
        for digest in ("A" * 64, "a" * 63, f"sha256:{'a' * 64}"):
            with self.subTest(digest=digest[:8]):
                self.assert_refused(self.payload(inventorySha256=digest), "/inventorySha256")

    def test_both_instants_are_real_utc_instants(self) -> None:
        for field_name in ("windowClosedAt", "anchorAt"):
            for text in ("2026-07-08T00:00:00+00:00", "2026-07-08T02:00:00+02:00"):
                with self.subTest(field=field_name, value=text):
                    self.assert_refused(self.payload(**{field_name: text}), f"/{field_name}")
            with self.subTest(field=field_name, value="hour 24"):
                self.assert_refused(
                    with_value(self.payload(), f"/{field_name}", "2026-07-07T24:00:00Z"),
                    f"/{field_name}",
                )

    def test_the_head_carries_no_tracking_id_resource_or_stream(self) -> None:
        # The stream id and the tracking id are pure functions of the gap record that follows
        # the head, so storing either would be a second copy that could disagree.
        properties = COVERAGE_RECORDED_V1["properties"]
        self.assertEqual(
            list(properties),
            ["rule", "contextKey", "windowClosedAt", "anchor", "anchorAt", "inventorySha256"],
        )
        for extra in ("trackingId", "resource", "streamId", "fingerprint"):
            with self.subTest(field=extra):
                with self.assertRaises(EventContractError):
                    self.repository.validate_payload(
                        COVERAGE_RECORDED, self.payload(**{extra: "x"})
                    )

    def test_only_a_gap_record_has_a_head(self) -> None:
        for label, record in (
            ("a detection failure", system_record()),
            ("an artifact observation", artifact_observation()),
        ):
            with self.subTest(label):
                with self.assertRaises(ValueError):
                    coverage_head_payload(record)
        bare = replace(self.record, source_metadata=())
        with self.assertRaises(ValueError) as caught:
            coverage_head_payload(bare)
        self.assertIn("coverage.anchor", str(caught.exception))


# *--- Stream Id ---*


class CoverageStreamIdTests(unittest.TestCase):
    """One stream per gap record, named for the record's own SYSTEM identity hash."""

    def test_the_stream_id_is_the_gap_records_own_fingerprint(self) -> None:
        record = gap_record()
        stream_id = coverage_stream_id_of(record)

        self.assertEqual(stream_id, f"coverage/{record.fingerprint}")
        self.assertEqual(coverage_stream_id(record.fingerprint), stream_id)
        self.assertIsNotNone(_COMPONENT_PATTERN.fullmatch(record.fingerprint))
        self.assertEqual(coverage_stream_fingerprint(stream_id), record.fingerprint)
        self.assertEqual(stream_kind(stream_id), "coverage")
        self.assertTrue(is_coverage_stream(stream_id))
        self.assertFalse(is_artifact_stream(stream_id))
        self.assertFalse(is_case_stream(stream_id))
        self.assertFalse(is_failure_stream(stream_id))
        self.assertNotIn("lab-01", stream_id)
        self.assertNotIn("nightly-openscap", stream_id)

    def test_the_payload_recomputes_the_stream_id_whenever_it_was_ingested(self) -> None:
        record = gap_record()
        later = gap(fleet_result(), ingested_at=datetime(2030, 1, 1, tzinfo=UTC))

        self.assertEqual(
            coverage_stream_id_of_payload(record.to_canonical_dict()), coverage_stream_id_of(record)
        )
        self.assertEqual(coverage_stream_id_of(later), coverage_stream_id_of(record))
        self.assertEqual(
            coverage_stream_id_of_payload(later.to_canonical_dict()), coverage_stream_id_of(record)
        )

    def test_every_gap_has_its_own_stream(self) -> None:
        # Two job-sharing hosts share a context key, and every MVX window closes at one
        # instant, so neither the key nor the close names a gap alone; the fingerprint does.
        records = coverage_gap_observations(fleet_result(), ingested_at=NOW)
        streams = [coverage_stream_id_of(record) for record in records]

        self.assertEqual(len(set(streams)), len(records))
        shared = [record for record in records if record.context_key == JOB_KEY]
        self.assertEqual(len(shared), 2)
        self.assertNotEqual(coverage_stream_id_of(shared[0]), coverage_stream_id_of(shared[1]))
        self.assertIn(coverage_stream_id_of(gap_record(PSD_RULE, GROUP_KEY)), streams)

    def test_the_stream_id_refuses_what_is_not_a_fingerprint(self) -> None:
        for value in ("A" * 64, "a" * 63, "a" * 65, f"{'a' * 32}/{'a' * 31}", 7):
            with self.subTest(value=str(value)[:8]):
                with self.assertRaises(ValueError):
                    coverage_stream_id(value)  # type: ignore[arg-type]
        for stream_id, expected in (
            (f"failure/{'a' * 64}/complyroll.sarif/1", "must start with 'coverage/'"),
            (f"coverages/{'a' * 64}", "must start with 'coverage/'"),
            (f"coverage/{'a' * 64}/extra", "fingerprint"),
            (f"coverage/{'A' * 64}", "fingerprint"),
            ("coverage/", "fingerprint"),
        ):
            with self.subTest(stream_id=stream_id):
                with self.assertRaises(ValueError) as caught:
                    coverage_stream_fingerprint(stream_id)
                self.assertIn(expected, str(caught.exception))
        self.assertIsNone(stream_kind(f"coverages/{'a' * 64}"))

    def test_only_a_gap_record_names_a_coverage_stream(self) -> None:
        for label, record in (
            ("a detection failure", system_record()),
            ("an artifact observation", artifact_observation()),
        ):
            with self.subTest(label):
                with self.assertRaises(ValueError):
                    coverage_stream_id_of(record)
                with self.assertRaises(ValueError):
                    coverage_stream_id_of_payload(record.to_canonical_dict())
        with self.assertRaises(TypeError):
            coverage_stream_id_of(gap_record().to_canonical_dict())  # type: ignore[arg-type]
        forged = {**gap_record().to_canonical_dict(), "fingerprint": "0" * 64}
        with self.assertRaises(ValueError) as caught:
            coverage_stream_id_of_payload(forged)
        self.assertIn("not a readable observation", str(caught.exception))


# *--- Append ---*


class CoverageAppendTests(StoreCase):
    """The repository holds a coverage stream to its gap record at append."""

    def assert_refused(
        self, stream_id: str, events: Sequence[tuple[str, Mapping[str, Any]]], message: str
    ) -> None:
        with self.assertRaises(EventContractError) as caught:
            self.repository.append_batch(
                stream_id,
                tuple(pending(event_type, payload) for event_type, payload in events),
                expected_version=0,
            )
        self.assertIn(message, str(caught.exception))
        self.assertEqual(self.store.latest_sequence, 0)
        self.assertEqual(self.store.schema_version, 1)

    def test_a_whole_coverage_stream_appends_head_first(self) -> None:
        record = gap_record()

        stream_id = record_coverage(self.repository, record)

        stored = self.repository.read_stream(stream_id)
        self.assertEqual(
            [event.event_type for event in stored], [COVERAGE_RECORDED, "observation.recorded"]
        )
        self.assertEqual(stored[0].payload, coverage_head_payload(record))
        self.assertEqual(stored[1].payload, record.to_canonical_dict())
        self.assertEqual(COVERAGE_STREAM_EVENT_TYPES, {COVERAGE_RECORDED, "observation.recorded"})
        self.assertEqual(audit_history(self.repository), ())

    def test_coverage_events_belong_on_coverage_streams_alone(self) -> None:
        record = gap_record()
        stream_id = coverage_stream_id_of(record)
        head = coverage_head_payload(record)
        for other in (
            f"artifact/{'a' * 64}/complyroll.cklb/1",
            f"failure/{'a' * 64}/complyroll.sarif/1",
            "case/case-0123456789abcdef",
        ):
            with self.subTest(stream=other):
                self.assert_refused(other, [(COVERAGE_RECORDED, head)], "does not belong")
        for event_type, payload in (
            ("failure.recorded", failure_head()),
            ("case.identified", {"providerTrackingId": "PROV-1"}),
        ):
            with self.subTest(event_type=event_type):
                self.assert_refused(
                    stream_id, [(event_type, payload)], "which is a coverage stream"
                )

    def test_a_coverage_stream_is_opened_by_its_head(self) -> None:
        record = gap_record()
        stream_id = coverage_stream_id_of(record)
        head, observation = coverage_events(record)
        for label, events in (
            ("the record alone", [observation]),
            ("the record first", [observation, head]),
        ):
            with self.subTest(label):
                self.assert_refused(stream_id, events, coverage_head_order_message(stream_id))

    def test_the_gap_record_of_another_stream_is_refused(self) -> None:
        record, other = gap_record(), gap_record(MVX_RULE, "host:web-01")
        stream_id = coverage_stream_id_of(record)

        self.assert_refused(
            stream_id,
            coverage_events(other),
            f"is the gap record of stream {coverage_stream_id_of(other)!r}",
        )

    def test_a_record_that_is_not_a_gap_record_is_refused(self) -> None:
        head = coverage_head_payload(gap_record())
        for label, record, message in (
            ("a detection failure", system_record(), "its source type is"),
            ("an artifact observation", artifact_observation(), "its origin is 'artifact'"),
        ):
            with self.subTest(label):
                self.assert_refused(
                    coverage_stream_id(record.fingerprint),
                    [
                        (COVERAGE_RECORDED, head),
                        ("observation.recorded", record.to_canonical_dict()),
                    ],
                    message,
                )

    def test_a_gap_record_with_other_metadata_is_refused(self) -> None:
        record = gap_record()
        stream_id = coverage_stream_id_of(record)
        canonical = record.to_canonical_dict()
        metadata_now = canonical["source_metadata"]
        missing = {key: value for key, value in metadata_now.items() if key != "coverage.job"}
        for label, source_metadata, message in (
            ("a key missing", missing, "its metadata has no 'coverage.job'"),
            ("a key added", {**metadata_now, "coverage.extra": "x"}, "carries 'coverage.extra'"),
        ):
            with self.subTest(label):
                self.assert_refused(
                    stream_id,
                    [
                        (COVERAGE_RECORDED, coverage_head_payload(record)),
                        ("observation.recorded", {**canonical, "source_metadata": source_metadata}),
                    ],
                    message,
                )

    def test_a_gap_record_carrying_what_its_builder_never_writes_is_refused(self) -> None:
        record = gap_record()
        stream_id = coverage_stream_id_of(record)
        canonical = record.to_canonical_dict()
        for field, (value, message) in FIXED_FIELD_EDITS.items():
            with self.subTest(field):
                self.assert_refused(
                    stream_id,
                    [
                        (COVERAGE_RECORDED, coverage_head_payload(record)),
                        ("observation.recorded", {**canonical, field: value}),
                    ],
                    f"is not a coverage gap record: {message}",
                )

    def test_a_gap_record_naming_an_artifact_is_refused_by_the_observation_contract(
        self,
    ) -> None:
        record = gap_record()
        canonical = record.to_canonical_dict()
        for field, (value, _) in ARTIFACT_FIELD_EDITS.items():
            with self.subTest(field):
                self.assert_refused(
                    coverage_stream_id_of(record),
                    [
                        (COVERAGE_RECORDED, coverage_head_payload(record)),
                        ("observation.recorded", {**canonical, field: value}),
                    ],
                    f"payload is not readable: <root>: reader: system observations must leave "
                    f"{field} empty",
                )

    def test_the_same_gap_record_twice_on_its_stream_is_refused(self) -> None:
        record = gap_record()
        stream_id = record_coverage(self.repository, record)

        with self.assertRaises(EventContractError) as caught:
            self.repository.append(
                stream_id,
                "observation.recorded",
                record.to_canonical_dict(),
                occurred_at=NOW,
                metadata=metadata(),
                expected_version=2,
            )

        self.assertIn(
            f"coverage stream {stream_id!r} records observation {record.observation_id!r} "
            "more than once",
            str(caught.exception),
        )
        self.assertEqual(self.repository.current_version(stream_id), 2)


# *--- Schema 4 ---*


class CoverageSchemaMarkingTests(StoreCase):
    """A store holding a coverage stream is marked schema 4 in the same transaction.

    A build that knows only schema 3 reads a coverage stream as a stream of no kind, so a
    store holding one says so before such a build can open it. A store that never records a
    gap stays at its version and stays readable by that build (ADR 0015).
    """

    def damage(self, statement: str) -> None:
        self.store.close()
        with closing(sqlite3.connect(self.path, isolation_level=None)) as connection:
            connection.execute(statement)

    def test_artifact_case_failure_and_hold_appends_never_mark_schema_4(self) -> None:
        self.assertEqual(self.store.schema_version, 1)
        for stream_id, event_type, payload in (
            ("case/case-0123456789abcdef", "case.identified", {"providerTrackingId": "P-1"}),
            (
                f"artifact/{'a' * 64}/complyroll.cklb/1",
                "observation.recorded",
                artifact_observation().to_canonical_dict(),
            ),
        ):
            self.repository.append(
                stream_id,
                event_type,
                payload,
                occurred_at=NOW,
                metadata=metadata(),
                expected_version=0,
            )
        self.assertEqual((self.store.schema_version, self.migrations()), (1, [FIRST]))
        self.record_failure()
        self.assertEqual((self.store.schema_version, self.migrations()), (2, [FIRST, SECOND]))
        self.record_hold()
        self.assertEqual(
            (self.store.schema_version, self.migrations()), (3, [FIRST, SECOND, THIRD])
        )

    def test_the_first_coverage_append_marks_schema_4(self) -> None:
        record_coverage(self.repository, gap_record())

        self.assertEqual(self.store.schema_version, 4)
        self.assertEqual(self.migrations(), [FIRST, SECOND, THIRD, FOURTH])
        self.store.close()
        reopened = SQLiteEventStore(self.path)
        self.addCleanup(reopened.close)
        self.assertEqual(reopened.schema_version, 4)
        self.assertTrue(reopened.verify_history().ok)

    def test_a_coverage_append_on_a_marked_store_adds_record_4_alone(self) -> None:
        self.record_failure()
        record_coverage(self.repository, gap_record())
        self.assertEqual(self.migrations(), [FIRST, SECOND, THIRD, FOURTH])
        self.setUp()
        self.record_failure()
        self.record_hold()
        record_coverage(self.repository, gap_record())
        self.assertEqual((self.store.schema_version, self.migrations()[-1]), (4, FOURTH))

    def test_later_coverage_failure_and_hold_appends_mark_nothing_again(self) -> None:
        record_coverage(self.repository, gap_record())
        record_coverage(self.repository, gap_record(MVX_RULE, "host:web-01"))
        self.record_failure()
        self.record_hold()

        self.assertEqual(self.store.schema_version, 4)
        self.assertEqual(self.migrations(), [FIRST, SECOND, THIRD, FOURTH])

    def test_a_rolled_back_coverage_append_leaves_the_store_unmarked(self) -> None:
        self.record_failure()
        with self.assertRaises(RuntimeError):
            with self.repository.transaction():
                record_coverage(self.repository, gap_record())
                self.assertEqual(self.store.schema_version, 4)
                raise RuntimeError("abandon the gap")

        self.assertEqual(self.store.schema_version, 2)
        self.assertEqual(self.migrations(), [FIRST, SECOND])
        self.assertEqual(self.store.latest_sequence, 2)

    def test_the_marking_changes_no_schema_object(self) -> None:
        def objects() -> list[tuple[str, str, str, str | None]]:
            with closing(sqlite3.connect(self.path)) as connection:
                rows = connection.execute(
                    "SELECT type, name, tbl_name, sql FROM sqlite_master ORDER BY type, name"
                ).fetchall()
            return [(str(kind), str(name), str(table), sql) for kind, name, table, sql in rows]

        before = objects()
        record_coverage(self.repository, gap_record())

        self.assertEqual(self.store.schema_version, 4)
        self.assertEqual(objects(), before)

    def test_schema_4_needs_all_four_migration_records(self) -> None:
        for missing in (1, 2, 3, 4):
            with self.subTest(missing=missing):
                self.setUp()
                record_coverage(self.repository, gap_record())
                self.damage(f"DELETE FROM complyroll_schema_migrations WHERE version = {missing}")

                with self.assertRaises(UnsupportedSchemaError) as caught:
                    SQLiteEventStore(self.path)

                self.assertIn(f"missing migration record {missing}", str(caught.exception))

    def test_a_build_that_opens_only_schema_3_refuses_a_store_that_recorded_a_gap(self) -> None:
        record_coverage(self.repository, gap_record())
        self.store.close()

        with patch.object(sqlite_module, "SUPPORTED_SCHEMA_VERSION", 3):
            with self.assertRaises(UnsupportedSchemaError) as caught:
                SQLiteEventStore(self.path)

        self.assertEqual(
            str(caught.exception), "database schema 4 is newer than supported schema 3"
        )

    def test_a_build_that_opens_only_schema_3_still_opens_a_store_with_no_gap(self) -> None:
        self.record_failure()
        self.record_hold()
        self.store.close()

        with patch.object(sqlite_module, "SUPPORTED_SCHEMA_VERSION", 3):
            reopened = SQLiteEventStore(self.path)
            self.addCleanup(reopened.close)
            self.assertEqual(reopened.schema_version, 3)

    def test_a_store_newer_than_schema_4_is_refused(self) -> None:
        record_coverage(self.repository, gap_record())
        self.damage("PRAGMA user_version = 5")

        with self.assertRaises(UnsupportedSchemaError) as caught:
            SQLiteEventStore(self.path)

        self.assertIn("database schema 5 is newer than supported schema 4", str(caught.exception))


# *--- Readers ---*


class CoverageReaderTests(StoreCase):
    """The fold reads a whole coverage stream and refuses each shape the audit names."""

    def test_the_readers_read_a_whole_coverage_stream(self) -> None:
        # Moved on purpose in PR 3 step 5: rehydration gains each gap record in recorded
        # order, so `cases correlate` opens its case, and artifact history is unchanged.
        self.record_failure()
        history = artifact_history(self.repository)
        (failure,) = rehydrate_observations(self.repository)
        lab, group = gap_record(), gap_record(PSD_RULE, GROUP_KEY)

        record_coverage(self.repository, lab)
        record_coverage(self.repository, group)

        self.assertEqual(artifact_history(self.repository), history)
        self.assertEqual(rehydrate_observations(self.repository), (failure, lab, group))
        self.assertEqual(fold_all_cases(self.repository), ())
        correlate_cases(self.repository, metadata=metadata(), now=NOW)
        self.assertEqual(
            sorted(
                (case.source_type, case.context_key) for case in fold_all_cases(self.repository)
            ),
            sorted((item.source_type, item.context_key) for item in (failure, lab, group)),
        )
        self.assertEqual(audit_history(self.repository), ())

    def fresh_store(self) -> None:
        """Point the test at a new empty store, so each planted shape starts clean."""
        directory = tempfile.TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        self.path = Path(directory.name) / "history.sqlite"
        self.open_store()

    def test_the_reader_refuses_each_shape_with_the_audits_message(self) -> None:
        record = gap_record()
        stream_id = coverage_stream_id_of(record)
        head, observation = coverage_events(record)
        other = coverage_events(gap_record(MVX_RULE, "host:web-01"))[1]
        canonical = record.to_canonical_dict()
        dropped = {
            key: value
            for key, value in canonical["source_metadata"].items()
            if key != "coverage.force"
        }
        disagreeing = (COVERAGE_RECORDED, {**head[1], "anchor": "verification"})
        invalid = (COVERAGE_RECORDED, {**head[1], "rule": "VDR-NOT-A-RULE"})
        # Each shape, the audit code it is reported under, and whether the reader names the
        # event before the audit's message, as it does for a failure stream's event.
        shapes: dict[str, tuple[str, list[tuple[str, Any]], str, str | None]] = {
            "head alone": (stream_id, [head], "coverage_incomplete", None),
            "a second record": (
                stream_id,
                [head, observation, observation],
                "coverage_overfull",
                None,
            ),
            "record first": (stream_id, [observation, head], "coverage_stream_mismatch", None),
            "another gap's record": (
                stream_id,
                [head, other],
                "coverage_stream_mismatch",
                "is on the wrong stream",
            ),
            "a metadata key dropped": (
                stream_id,
                [head, ("observation.recorded", {**canonical, "source_metadata": dropped})],
                "coverage_identity_breach",
                "is on the wrong stream",
            ),
            "a head naming another anchor": (
                stream_id,
                [disagreeing, observation],
                "coverage_identity_breach",
                None,
            ),
            "a head outside its contract": (
                stream_id,
                [invalid, observation],
                "payload_contract_invalid",
                "is not a readable coverage record",
            ),
            "a stream id naming no fingerprint": (
                "coverage/not-a-fingerprint",
                [head, observation],
                "coverage_stream_mismatch",
                "is on the wrong stream",
            ),
            **{
                f"its {field} edited": (
                    stream_id,
                    [head, ("observation.recorded", {**canonical, field: value})],
                    "coverage_identity_breach",
                    "is on the wrong stream",
                )
                for field, (value, _) in FIXED_FIELD_EDITS.items()
            },
            **{
                f"its {field} set": (
                    stream_id,
                    [head, ("observation.recorded", {**canonical, field: value})],
                    "payload_contract_invalid",
                    "is not a readable observation",
                )
                for field, (value, _) in ARTIFACT_FIELD_EDITS.items()
            },
            # Read before a foreign event is skipped, so the placement fault stops the read.
            "a foreign event alone": (stream_id, [FOREIGN_EVENT], "event_stream_mismatch", None),
            "a foreign event after a whole stream": (
                stream_id,
                [head, observation, FOREIGN_EVENT],
                "event_stream_mismatch",
                None,
            ),
        }
        for label, (planted_on, events, code, prefix) in shapes.items():
            with self.subTest(label):
                self.fresh_store()
                self.stage(planted_on, events)
                faults = [fault for fault in audit_history(self.repository) if fault.code == code]
                self.assertTrue(faults, msg=label)
                fault = faults[0]
                expected = (
                    fault.message
                    if prefix is None
                    else f"event {fault.sequence} {prefix}: {fault.message}"
                )

                with self.assertRaises(HistoryError) as caught:
                    rehydrate_observations(self.repository)

                self.assertEqual(str(caught.exception), expected)


# *--- Audits ---*


class CoverageAuditTests(StoreCase):
    """`audit_history` names each way a coverage stream is not one head and its gap record."""

    def setUp(self) -> None:
        super().setUp()
        self.record = gap_record()
        self.stream_id = coverage_stream_id_of(self.record)
        self.head, self.observation = coverage_events(self.record)

    def assert_faults(self, expected: list[tuple[int, str]], *messages: str) -> None:
        faults = audit_history(self.repository)
        self.assertEqual([(fault.sequence, fault.code) for fault in faults], expected)
        for message in messages:
            self.assertTrue(
                any(message in fault.message for fault in faults),
                msg=f"{message!r} not in {[fault.message for fault in faults]}",
            )

    def test_a_whole_coverage_stream_is_no_fault(self) -> None:
        self.stage(self.stream_id, [self.head, self.observation])

        self.assertEqual(audit_history(self.repository), ())

    def test_a_stream_that_is_not_one_head_and_one_observation_is_incomplete_or_overfull(
        self,
    ) -> None:
        shapes = {
            "head only": ([self.head], "coverage_incomplete", "found 1 coverage record(s) and 0"),
            "record only": (
                [self.observation],
                "coverage_incomplete",
                "found 0 coverage record(s) and 1 observation(s)",
            ),
            "head twice": (
                [self.head, self.observation, self.head],
                "coverage_overfull",
                "found 2 coverage record(s) and 1 observation(s)",
            ),
            "record twice": (
                [self.head, self.observation, self.observation],
                "coverage_overfull",
                "found 1 coverage record(s) and 2 observation(s)",
            ),
        }
        for label, (events, code, message) in shapes.items():
            with self.subTest(label):
                self.setUp()
                sequences = self.stage(self.stream_id, events)

                self.assert_faults([(sequences[0], code)], message, self.stream_id)

    def test_a_stream_its_record_opens_is_a_stream_mismatch(self) -> None:
        sequences = self.stage(self.stream_id, [self.observation, self.head])

        self.assert_faults(
            [(sequences[0], "coverage_stream_mismatch")],
            coverage_head_order_message(self.stream_id),
        )

    def test_another_gaps_record_is_a_stream_mismatch(self) -> None:
        other = gap_record(MVX_RULE, "host:web-01")
        # The head agrees with the record it sits beside, so the stream id is all that is wrong.
        sequences = self.stage(self.stream_id, coverage_events(other))

        self.assert_faults(
            [(sequences[1], "coverage_stream_mismatch")],
            f"is the gap record of stream {coverage_stream_id_of(other)!r}",
        )

    def test_a_stream_id_naming_no_fingerprint_is_a_mismatch_on_each_event(self) -> None:
        stream_id = "coverage/not-a-fingerprint"
        sequences = self.stage(stream_id, [self.head, self.observation])

        self.assert_faults(
            [(sequence, "coverage_stream_mismatch") for sequence in sequences],
            f"stream {stream_id!r} names no gap record",
        )

    def test_a_record_that_is_not_a_gap_record_is_an_identity_breach(self) -> None:
        record = self.record
        shapes = {
            "an artifact observation": (artifact_observation(), "its origin is 'artifact'"),
            "a detection failure": (
                system_record(),
                "its source type is 'complyroll.detection-process'",
            ),
            "another record id": (
                rebuilt(record, source_record_id="coverage-gap-2"),
                "its source record id is 'coverage-gap-2'",
            ),
            "another tool": (rebuilt(record, source_tool="other"), "its source tool is 'other'"),
            "another parser version": (
                rebuilt(record, parser_version="2"),
                "its parser is 'complyroll.coverage' version '2'",
            ),
            "an id it does not derive": (
                replace(record, observation_id=f"obs-{'0' * 64}"),
                "not its derived id",
            ),
        }
        for label, (candidate, message) in shapes.items():
            with self.subTest(label):
                self.setUp()
                sequences = self.stage(
                    coverage_stream_id(candidate.fingerprint),
                    [self.head, ("observation.recorded", candidate.to_canonical_dict())],
                )

                self.assert_faults([(sequences[1], "coverage_identity_breach")], message)

    def test_metadata_that_is_not_the_records_own_is_an_identity_breach(self) -> None:
        canonical = self.record.to_canonical_dict()
        source = canonical["source_metadata"]
        shapes = {
            "a key missing": (
                {key: value for key, value in source.items() if key != "coverage.basis"},
                "its metadata has no 'coverage.basis'",
            ),
            "a key added": ({**source, "coverage.note": "x"}, "carries 'coverage.note'"),
            "another close": (
                {**source, "coverage.windowClosedAt": "2026-07-09T00:00:00Z"},
                "coverage.windowClosedAt is '2026-07-09T00:00:00Z'",
            ),
            "another rule": (
                {**source, "coverage.rule": "VDR-TFR-PDD"},
                "coverage.rule is 'VDR-TFR-PDD'",
            ),
            # The window runs from its anchor to its close, and a rule's timeframe is never
            # empty, so the writer's anchor always precedes the close.
            "an anchor at the close": (
                {**source, "coverage.anchorAt": "2026-07-08T00:00:00Z"},
                "coverage.anchorAt is '2026-07-08T00:00:00Z', which does not precede its "
                "window close '2026-07-08T00:00:00Z'",
            ),
            "an anchor after the close": (
                {**source, "coverage.anchorAt": "2026-07-09T00:00:00Z"},
                "which does not precede its window close",
            ),
            "an anchor spelled with an offset": (
                {**source, "coverage.anchorAt": "2026-07-01T00:00:00+00:00"},
                "coverage.anchorAt is '2026-07-01T00:00:00+00:00', not an instant as its "
                "writer spells one",
            ),
            "an anchor that is no instant": (
                {**source, "coverage.anchorAt": "last week"},
                "coverage.anchorAt is 'last week', not an instant as its writer spells one",
            ),
            "a force that is none": (
                {**source, "coverage.force": "MAYBE"},
                "coverage.force is 'MAYBE', not a rule force",
            ),
            "another job": (
                {**source, "coverage.job": "weekly-scan"},
                "coverage.job is 'weekly-scan', and its context key "
                "'VDR-TFR-MVX:job:nightly-openscap' is not 'VDR-TFR-MVX:job:weekly-scan'",
            ),
            "no job": (
                {**source, "coverage.job": ""},
                "coverage.job is '', and its context key 'VDR-TFR-MVX:job:nightly-openscap' is "
                "not 'VDR-TFR-MVX:resource:host:lab-01'",
            ),
            "another basis": (
                {**source, "coverage.basis": "Coverage looked fine."},
                "coverage.basis is 'Coverage looked fine.', not a basis its writer records",
            ),
        }
        self.assertEqual(
            (source["coverage.job"], canonical["context_key"]), ("nightly-openscap", JOB_KEY)
        )
        for label, (source_metadata, message) in shapes.items():
            with self.subTest(label):
                self.setUp()
                observation = {**canonical, "source_metadata": source_metadata}
                sequences = self.stage(
                    self.stream_id, [self.head, ("observation.recorded", observation)]
                )

                # The fingerprint covers no metadata, so the stream id still names the record.
                self.assert_faults([(sequences[1], "coverage_identity_breach")], message)
                # Every reader refuses what the audit names.
                with self.assertRaises(HistoryError) as caught:
                    rehydrate_observations(self.repository)
                self.assertIn(message, str(caught.exception))

    def test_every_gap_the_builder_writes_passes_the_metadata_check(self) -> None:
        # Job-keyed, resource-keyed and sample-group windows, under MUST and SHOULD rules,
        # each anchored before its close: what the writer records is never a breach.
        records = coverage_gap_observations(fleet_result(), ingested_at=NOW)
        self.assertEqual(
            {dict(record.source_metadata)["coverage.force"] for record in records},
            {"MUST", "SHOULD"},
        )
        for record in records:
            with self.subTest(context=record.context_key):
                self.assertIsNone(
                    coverage_record_problem(
                        coverage_stream_id_of(record),
                        "observation.recorded",
                        record.to_canonical_dict(),
                    )
                )

    def test_a_gap_record_carrying_what_its_builder_never_writes_is_an_identity_breach(
        self,
    ) -> None:
        canonical = self.record.to_canonical_dict()
        for field, (value, message) in FIXED_FIELD_EDITS.items():
            with self.subTest(field):
                self.setUp()
                observation = {**canonical, field: value}
                sequences = self.stage(
                    self.stream_id, [self.head, ("observation.recorded", observation)]
                )

                self.assert_faults([(sequences[1], "coverage_identity_breach")], message)
                # The repository refuses at append with the same text the audit reports.
                self.assertEqual(
                    coverage_record_problem(self.stream_id, "observation.recorded", observation),
                    ("coverage_identity_breach", audit_history(self.repository)[0].message),
                )

    def test_a_gap_record_naming_an_artifact_is_contract_invalid_and_not_a_gap_record(
        self,
    ) -> None:
        canonical = self.record.to_canonical_dict()
        for field, (value, message) in ARTIFACT_FIELD_EDITS.items():
            with self.subTest(field):
                self.setUp()
                observation = {**canonical, field: value}
                sequences = self.stage(
                    self.stream_id, [self.head, ("observation.recorded", observation)]
                )

                # The observation contract refuses it on every store path first, so the
                # identity check's own reason is reached only by a direct call.
                self.assert_faults(
                    [(sequences[1], "payload_contract_invalid")],
                    f"system observations must leave {field} empty",
                )
                self.assertEqual(
                    coverage_record_problem(self.stream_id, "observation.recorded", observation),
                    (
                        "coverage_identity_breach",
                        f"observation.recorded on coverage stream {self.stream_id!r} is not a "
                        f"coverage gap record: {message}",
                    ),
                )

    def test_a_foreign_event_on_a_coverage_stream_is_a_placement_fault(self) -> None:
        event_type = FOREIGN_EVENT[0]
        shapes = {
            # Alone, it also leaves the stream without either half.
            "alone": ([FOREIGN_EVENT], [(0, "coverage_incomplete"), (0, "event_stream_mismatch")]),
            "after a whole stream": (
                [self.head, self.observation, FOREIGN_EVENT],
                [(2, "event_stream_mismatch")],
            ),
        }
        for label, (events, expected) in shapes.items():
            with self.subTest(label):
                self.setUp()
                sequences = self.stage(self.stream_id, events)

                self.assert_faults(
                    [(sequences[index], code) for index, code in expected],
                    f"event {event_type!r} does not belong on stream {self.stream_id!r}",
                )

    def test_a_head_that_disagrees_with_its_record_is_an_identity_breach(self) -> None:
        for head_key, value in OTHER_HEAD_VALUES.items():
            with self.subTest(field=head_key):
                self.setUp()
                head = {**coverage_head_payload(self.record), head_key: value}
                sequences = self.stage(
                    self.stream_id, [(COVERAGE_RECORDED, head), self.observation]
                )

                self.assert_faults(
                    [(sequences[1], "coverage_identity_breach")],
                    f"records {head_key} {value!r} in its coverage.recorded",
                    "the two describe one gap",
                )
                self.assertEqual(
                    coverage_record_disagreement(
                        self.stream_id, head, self.record.to_canonical_dict()
                    ),
                    audit_history(self.repository)[0].message,
                )

    def test_a_coverage_stream_in_a_store_below_schema_4_is_unmarked(self) -> None:
        for schema in (1, 2, 3):
            with self.subTest(schema=schema):
                self.setUp()
                # Both events are exactly what the writer records; only the mark is wrong.
                first = self.stage(
                    self.stream_id, [self.head, self.observation], requires_schema=schema
                )

                self.assertEqual(self.store.schema_version, schema)
                self.assert_faults(
                    [(first[0], "coverage_schema_unmarked")],
                    f"coverage stream {self.stream_id!r} is in a store at schema {schema}",
                    "is marked schema 4",
                )

    def test_one_unmarked_fault_names_the_first_coverage_stream_beside_each_other_kind(
        self,
    ) -> None:
        other = gap_record(MVX_RULE, "host:web-01")
        failure_events = [
            ("failure.recorded", failure_head()),
            ("observation.recorded", system_record().to_canonical_dict()),
        ]
        failure = self.stage(
            failure_stream_id("a" * 64, "complyroll.sarif", "1"), failure_events, requires_schema=1
        )
        first = self.stage(self.stream_id, [self.head, self.observation], requires_schema=1)
        self.stage(coverage_stream_id_of(other), coverage_events(other), requires_schema=1)

        self.assert_faults(
            [(failure[0], "failure_schema_unmarked"), (first[0], "coverage_schema_unmarked")],
        )

    def test_the_problem_checks_answer_only_for_coverage_stream_events(self) -> None:
        canonical = self.record.to_canonical_dict()
        self.assertIsNone(
            coverage_record_problem(self.stream_id, "observation.recorded", canonical)
        )
        self.assertIsNone(coverage_record_problem(self.stream_id, COVERAGE_RECORDED, self.head[1]))
        for stream_id, event_type in (
            (f"artifact/{'a' * 64}/complyroll.cklb/1", "observation.recorded"),
            (f"failure/{'a' * 64}/complyroll.sarif/1", "observation.recorded"),
            (self.stream_id, "case.identified"),
        ):
            with self.subTest(stream=stream_id, event_type=event_type):
                self.assertIsNone(coverage_record_problem(stream_id, event_type, {}))
        self.assertIsNone(coverage_record_disagreement(self.stream_id, self.head[1], canonical))


# *--- Store Verify ---*


class CoverageStoreVerifyCommandTests(PersistedStoreTestCase):
    """`store verify` names each coverage audit fault, exits 1, and passes a whole stream."""

    def setUp(self) -> None:
        super().setUp()
        self.populate()
        self.record = gap_record()
        self.stream_id = coverage_stream_id_of(self.record)
        self.head, self.observation = coverage_events(self.record)

    def smuggle(
        self,
        stream_id: str,
        events: Sequence[tuple[str, Mapping[str, Any]]],
        *,
        requires_schema: int = COVERAGE_STREAM_SCHEMA_VERSION,
    ) -> list[int]:
        """Append events to one new stream straight to the store, past the repository."""
        sequences = []
        with SQLiteEventStore(self.database) as store:
            for version, (event_type, payload) in enumerate(events):
                (appended,) = store.append(
                    stream_id,
                    [
                        NewEvent(
                            event_type=event_type,
                            occurred_at=NOW,
                            payload=dict(payload),
                            metadata=dict(SMUGGLED_METADATA),
                        )
                    ],
                    expected_version=version,
                    requires_schema=requires_schema,
                )
                sequences.append(appended.sequence)
        return sequences

    def assert_one_fault(self, sequence: int, code: str, message: str) -> None:
        code_seen, out, err = run(["store", "verify", "--db", str(self.database)])

        self.assertEqual(code_seen, 1)
        self.assertEqual(out, "")
        self.assertIn(f"error: sequence {sequence}: {code}:", err)
        self.assertIn(message, err)
        self.assertIn("faults: 1 domain fault(s) in", err)

    def test_gap_metadata_its_writer_never_records_is_refused_by_verify_and_the_report(
        self,
    ) -> None:
        # The head is the record's own, so only the record's metadata is wrong. On ecc382d
        # the audit held force, job and basis to presence alone and never compared the
        # anchor with the close, so each of these verified clean.
        populated = self.database
        source = self.observation[1]["source_metadata"]
        shapes = {
            "an anchor after the close": (
                {"coverage.anchorAt": "2026-07-09T00:00:00Z"},
                "which does not precede its window close",
            ),
            "a force that is none": ({"coverage.force": "MAYBE"}, "not a rule force"),
            "another job": ({"coverage.job": "weekly-scan"}, "coverage.job is 'weekly-scan'"),
            "another basis": ({"coverage.basis": "x"}, "not a basis its writer records"),
        }
        for index, (label, (edits, message)) in enumerate(shapes.items()):
            with self.subTest(label):
                self.copy_store(populated, f"gap-metadata-{index}.db")
                observation = {**self.observation[1], "source_metadata": {**source, **edits}}
                sequences = self.smuggle(
                    self.stream_id, [self.head, ("observation.recorded", observation)]
                )

                self.assert_one_fault(sequences[1], "coverage_identity_breach", message)
                code, out, err = run(
                    [
                        "report",
                        "vdt",
                        "--db",
                        str(self.database),
                        "--class",
                        "C",
                        "--package-uri",
                        "https://example.test/cpo",
                        "--from",
                        "2026-08-01T00:00:00Z",
                        "--to",
                        "2026-08-31T23:59:59Z",
                        "--as-of",
                        "2026-08-21T12:00:00Z",
                    ]
                )
                self.assertEqual((code, out), (1, ""))
                self.assertIn("error: history_invalid: ", err)
                self.assertIn(message, err)

    def test_a_gap_record_carrying_another_title_or_description_is_refused_everywhere(
        self,
    ) -> None:
        # The fingerprint covers neither, and the report prints the title as the
        # vulnerability description, so an edited one used to verify and reach the report.
        populated = self.database
        for index, field in enumerate(("title", "description")):
            with self.subTest(field):
                self.copy_store(populated, f"gap-text-{index}.db")
                observation = {**self.observation[1], field: "FORGED"}
                sequences = self.smuggle(
                    self.stream_id, [self.head, ("observation.recorded", observation)]
                )
                message = f"its {field} is 'FORGED'"

                self.assert_one_fault(sequences[1], "coverage_identity_breach", message)
                code, out, err = run(
                    [
                        "report",
                        "vdt",
                        "--db",
                        str(self.database),
                        "--class",
                        "C",
                        "--package-uri",
                        "https://example.test/cpo",
                        "--from",
                        "2026-08-01T00:00:00Z",
                        "--to",
                        "2026-08-31T23:59:59Z",
                        "--as-of",
                        "2026-08-21T12:00:00Z",
                    ]
                )
                self.assertEqual((code, out), (1, ""))
                self.assertIn("error: history_invalid: ", err)
                self.assertIn(message, err)

    def test_a_whole_coverage_stream_verifies_and_its_gap_reaches_the_report(self) -> None:
        # Moved on purpose in PR 3 step 5: the fold reads the stream, so the report gains the
        # gap's record and `cases correlate` opens its case.
        twin = self.workspace / "twin.json"
        self.report(output=twin)
        listed = run(["cases", "list", "--db", str(self.database)])[:2]
        with SQLiteEventStore(self.database) as store:
            record_coverage(EventRepository(store), self.record)
            self.assertEqual(store.schema_version, 4)
        planted = self.workspace / "planted.json"
        (group,) = group_open_observations([self.record])

        out, err = self.succeeds(["store", "verify", "--db", str(self.database)])
        self.report(output=planted)

        self.assertEqual((out, err), (f"ok: {self.latest_sequence()} event(s) verified\n", ""))
        before = json.loads(twin.read_text(encoding="utf-8"))
        after = json.loads(planted.read_text(encoding="utf-8"))
        self.assertEqual(
            {item["providerTrackingId"] for item in after["vulnerabilities"]},
            {item["providerTrackingId"] for item in before["vulnerabilities"]}
            | {group.tracking_id},
        )
        self.assertEqual(run(["cases", "list", "--db", str(self.database)])[:2], listed)
        self.correlate()
        code, listing = run(["cases", "list", "--db", str(self.database)])[:2]
        self.assertEqual(code, 0)
        self.assertIn(group.tracking_id, listing)

    def test_a_coverage_stream_missing_its_record_is_named_and_exits_one(self) -> None:
        sequences = self.smuggle(self.stream_id, [self.head])

        self.assert_one_fault(
            sequences[0], "coverage_incomplete", "found 1 coverage record(s) and 0 observation(s)"
        )

    def test_a_coverage_stream_with_a_second_record_is_named_and_exits_one(self) -> None:
        sequences = self.smuggle(self.stream_id, [self.head, self.observation, self.observation])

        self.assert_one_fault(
            sequences[0], "coverage_overfull", "found 1 coverage record(s) and 2 observation(s)"
        )

    def test_another_gaps_record_on_a_coverage_stream_is_named_and_exits_one(self) -> None:
        other = gap_record(MVX_RULE, "host:web-01")
        sequences = self.smuggle(self.stream_id, coverage_events(other))

        self.assert_one_fault(
            sequences[1], "coverage_stream_mismatch", "is the gap record of stream"
        )

    def test_a_coverage_record_with_a_metadata_key_dropped_is_named_and_exits_one(self) -> None:
        canonical = self.record.to_canonical_dict()
        source = {
            key: value
            for key, value in canonical["source_metadata"].items()
            if key != "coverage.force"
        }
        sequences = self.smuggle(
            self.stream_id,
            [self.head, ("observation.recorded", {**canonical, "source_metadata": source})],
        )

        self.assert_one_fault(
            sequences[1], "coverage_identity_breach", "its metadata has no 'coverage.force'"
        )

    def test_a_coverage_stream_in_a_store_left_at_schema_1_is_named_and_exits_one(self) -> None:
        sequences = self.smuggle(self.stream_id, [self.head, self.observation], requires_schema=1)

        self.assert_one_fault(
            sequences[0], "coverage_schema_unmarked", f"coverage stream {self.stream_id!r}"
        )

    def test_an_unmarked_coverage_stream_does_not_hide_an_evaluation_order_inversion(
        self,
    ) -> None:
        # The order check runs beside this fault as beside a failure marker left low: no
        # reader refuses either, so neither may hide an inversion for good.
        evaluated = next(
            record for record in self.records() if record.event_type == "case.evaluated"
        )
        with SQLiteEventStore(self.database) as store:
            (inverted,) = store.append(
                evaluated.stream_id,
                [
                    NewEvent(
                        event_type=evaluated.event_type,
                        occurred_at=evaluated.occurred_at,
                        payload={**evaluated.payload, "completedAt": "2020-01-01T00:00:00Z"},
                        metadata=dict(evaluated.metadata),
                    )
                ],
                expected_version=len(store.read_stream(evaluated.stream_id)),
            )
        sequences = self.smuggle(self.stream_id, [self.head, self.observation], requires_schema=1)

        code, out, err = run(["store", "verify", "--db", str(self.database)])

        self.assertEqual((code, out), (1, ""))
        self.assertIn(f"error: sequence {sequences[0]}: coverage_schema_unmarked:", err)
        self.assertIn(f"error: sequence {inverted.sequence}: evaluation_before_detection:", err)
        self.assertIn("faults: 2 domain fault(s) in", err)


if __name__ == "__main__":
    unittest.main()
