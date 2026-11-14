# ******************************************************************************
# *Title: Change Gap Stream Tests*
# *Author: Kyle Versluis*
# *Description: Change gap streams, store schema 6 and cases changes.*
# ******************************************************************************
"""Tests for change gap streams: the head, schema 6 and `cases changes` (ADR 0018, PR 3)."""

# *--- Imports ---*

from __future__ import annotations

import json
import sqlite3
import unittest
from collections.abc import Mapping, Sequence
from contextlib import closing
from dataclasses import replace
from datetime import UTC, datetime
from pathlib import Path
from typing import Any
from unittest import mock

from test_change_gap_report import CLOSED_ROWS
from test_change_gaps import (
    DETECT_BY_TEXT,
    LAB_01,
    LAB_02,
    OCCURRED_TEXT,
    changes_named,
    inventory_named,
    timed,
)
from test_change_streams import FIFTH
from test_changes import (
    AS_OF,
    GROUP_PAIR,
    HOUR,
    T,
    changes_of,
    host,
    inventory_of,
    pair,
    policy,
)
from test_changes_report import change_file
from test_cli import (
    TIMED_ARTIFACTS,
    TIMED_AS_OF,
    TIMED_CHANGES,
    TIMED_INVENTORY,
    PersistedStoreTestCase,
    help_text,
    run,
    stripped_policy,
)
from test_coverage_gap_report import write_inventory
from test_coverage_streams import (
    FIRST,
    FOURTH,
    SECOND,
    THIRD,
    StoreCase,
    gap_record,
    metadata,
    pending,
    rebuilt,
    record_coverage,
)
from test_events import observation as artifact_observation
from test_events import system_record, with_value

from complyroll.correlation import group_open_observations
from complyroll.events import (
    CHANGE_GAP_RECORDED,
    CHANGE_GAP_RECORDED_V1,
    CHANGE_GAP_STREAM_EVENT_TYPES,
    CHANGE_GAP_STREAM_PREFIX,
    CHANGE_GAP_STREAM_SCHEMA_VERSION,
    CHANGE_KIND_VALUES,
    CHANGE_RECORDED,
    CHANGE_STREAM_EVENT_TYPES,
    CHANGE_STREAM_PREFIX,
    CHANGE_STREAM_SCHEMA_VERSION,
    COVERAGE_RECORDED,
    EVENT_CONTRACTS,
    EVENT_TYPES,
    STREAM_EVENT_TYPES,
    EventContractError,
    EventRepository,
    change_gap_change_disagreement,
    change_gap_head_order_message,
    change_gap_head_payload,
    change_gap_record_disagreement,
    change_gap_record_problem,
    change_gap_stream_fingerprint,
    change_gap_stream_id,
    change_gap_stream_id_of,
    change_gap_stream_id_of_payload,
    change_gap_write_once_message,
    change_stream_id,
    duplicate_observation_message,
    event_belongs_on_stream,
    failure_stream_id,
    is_artifact_stream,
    is_case_stream,
    is_change_gap_stream,
    is_change_stream,
    is_coverage_stream,
    is_failure_stream,
    stream_kind,
    timestamp_pointers_for,
)
from complyroll.events import repository as repository_module
from complyroll.events.contracts import (
    ARTIFACT_STREAM_EVENT_TYPES,
    CASE_STREAM_EVENT_TYPES,
    COVERAGE_STREAM_EVENT_TYPES,
    FAILURE_STREAM_EVENT_TYPES,
    _placement_problem,
)
from complyroll.history import (
    AUDIT_FAULT_CODES,
    ChangeGapOutcome,
    HistoryError,
    HistoryFault,
    artifact_history,
    audit_history,
    correlate_cases,
    fold_all_cases,
    read_stored_changes,
    record_change_gaps,
    record_changes,
    rehydrate_observations,
)
from complyroll.history import order as order_module
from complyroll.history import writers as writers_module
from complyroll.history.fold import _ORDER_CHECKED_BESIDE
from complyroll.models import RESERVED_SOURCE_TYPE_PREFIX, Observation
from complyroll.policy import CertificationClass, CertificationProfile
from complyroll.reports import ReportCompileError, load_changes, load_inventory
from complyroll.reports import records as records_module
from complyroll.reports.change_gaps import (
    CHANGE_GAP_BASIS_TEXTS,
    CHANGE_GAP_DESCRIPTION,
    CHANGE_GAP_METADATA_KEYS,
    CHANGE_GAP_PARSER_NAME,
    CHANGE_GAP_PARSER_VERSION,
    CHANGE_GAP_RECORD_ID,
    CHANGE_GAP_SOURCE_TOOL,
    CHANGE_GAP_SOURCE_TYPE,
    CHANGE_GAP_TITLE,
    change_gap_observations,
)
from complyroll.reports.changes import DAC_RULE, derive_changes
from complyroll.reports.changes_input import ChangeKind
from complyroll.reports.inventory import Inventory
from complyroll.reports.records import derive_report_changes
from complyroll.store import (
    SUPPORTED_SCHEMA_VERSION,
    NewEvent,
    SQLiteEventStore,
    UnsupportedSchemaError,
)
from complyroll.store import sqlite as sqlite_module

# *--- Fixtures ---*

NOW = datetime(2026, 11, 12, 12, 0, tzinfo=UTC)
SIXTH = (6, "change gap streams, ADR 0018")
#: Every migration record a schema 6 store holds, in order.
ALL_SIX = [FIRST, SECOND, THIRD, FOURTH, FIFTH, SIXTH]
#: Class B in UTC, the profile the library tests read changes under.
PROFILE = CertificationProfile(CertificationClass.B, calendar_timezone="UTC")
#: One change naming two hosts, neither verified before its window closed an hour later.
CHANGE_SET = changes_of(timed("CHG-1", pair("lab-01"), pair("lab-02")))
INVENTORY = inventory_of(host("lab-01"), host("lab-02"))
#: The head fields, in the contract's order.
HEAD_FIELDS = (
    "changeId",
    "contextKey",
    "windowClosedAt",
    "occurredAt",
    "changesSha256",
    "inventorySha256",
)
#: Each head field, the gap record field it restates, and a contract-valid value that names
#: something the gap record does not.
HEAD_PAIRS: dict[str, tuple[str, str]] = {
    "changeId": ("change.id", "CHG-9"),
    "contextKey": ("context_key", "VDR-CSO-DAC:change:CHG-9"),
    "windowClosedAt": ("change.detectBy", "2026-09-01T14:00:00Z"),
    "occurredAt": ("change.occurredAt", "2026-09-01T11:00:00Z"),
    "changesSha256": ("change.changesSha256", "c" * 64),
    "inventorySha256": ("change.inventorySha256", "d" * 64),
}
#: Fields the gap builder fixes and the fingerprint does not cover, a value for each that the
#: payload contract admits, and the reason the identity check gives for it (P lesson 1).
FIXED_FIELD_EDITS: dict[str, tuple[Any, str]] = {
    "disposition": ("pass", "its disposition is 'pass'"),
    "source_severity": ("high", "its source severity is 'high'"),
    "source_identifiers": (["CVE-2099-0001"], "its source identifiers are ['CVE-2099-0001']"),
    "title": ("Nothing to see here", "its title is 'Nothing to see here'"),
    "description": ("x", "its description is 'x'"),
}
#: The reason a record that is no change gap system record gives, at append and in the audit.
NOT_A_CHANGE_GAP = (
    "only a system record of source type 'complyroll.change' names a change gap stream"
)
#: The `cases changes` run over the timed store, less its `--db`.
CHANGES_OPTIONS = ("--class", "C", "--as-of", TIMED_AS_OF, "--inventory", str(TIMED_INVENTORY))
#: When the timed store recorded its change file.
RECORDED_AT = "2026-11-09T12:00:00Z"
#: The two lines a first run over the timed store prints, after each gap's observation id.
RECORDED_WINDOWS = (
    "VDR-CSO-DAC window for image:registry.example.test/synthetic/example-service:1.4.0 after "
    "change CHG-2001 closed 2026-08-20T00:00:00Z",
    "VDR-CSO-DAC window for file:src/ui/render.js after change CHG-2003 closed "
    "2026-09-01T01:00:00Z",
)
#: The refusal a store holding changes meets under a dataset without the rule.
#: An ingest instant for the store that never records a change.
NOW_TEXT = "2026-11-12T12:00:00Z"
RULE_UNAVAILABLE = (
    "error: change_rule_unavailable: the store holds recorded changes, but the Class C policy "
    "selects no VDR-CSO-DAC rule, so no change can be read against it"
)


def record_the_change(
    repository: EventRepository, change_set: Any = CHANGE_SET, recorded_at: datetime = NOW
) -> None:
    """Record a change file through its writer, as `changes record` does."""
    record_changes(repository, change_set, recorded_at=recorded_at, metadata=metadata())


def derived_gaps(
    repository: EventRepository,
    *,
    as_of: datetime = AS_OF,
    inventory: Inventory = INVENTORY,
) -> tuple[Observation, ...]:
    """Return the gaps a store's recorded changes close at as-of, as `cases changes` sees them."""
    stored = read_stored_changes(repository)
    assert stored is not None
    projection = derive_report_changes(
        rehydrate_observations(repository), stored, inventory, PROFILE, as_of
    )
    return change_gap_observations(projection, ingested_at=as_of)


def stateless_gaps(change_set: Any, *, as_of: datetime = AS_OF) -> tuple[Observation, ...]:
    """Return the gaps a stateless run over one change file derives, with no evidence."""
    projection = derive_report_changes((), change_set, INVENTORY, PROFILE, as_of)
    return change_gap_observations(projection, ingested_at=as_of)


def gap_of(gaps: Sequence[Observation], resource: Any = LAB_01) -> Observation:
    (found,) = [gap for gap in gaps if gap.resource == resource]
    return found


def change_gap_events(
    record: Observation, head: Mapping[str, Any] | None = None
) -> list[tuple[str, dict[str, Any]]]:
    """Return the two events one change gap stream holds: its head, then its gap record."""
    return [
        (CHANGE_GAP_RECORDED, dict(change_gap_head_payload(record) if head is None else head)),
        ("observation.recorded", record.to_canonical_dict()),
    ]


def record_change_gap(repository: EventRepository, record: Observation) -> str:
    """Record one gap through the repository, as the writer does, and return its stream."""
    stream_id = change_gap_stream_id_of(record)
    repository.append_batch(
        stream_id,
        tuple(pending(event_type, payload) for event_type, payload in change_gap_events(record)),
        expected_version=0,
    )
    return stream_id


def recorded_gaps(repository: EventRepository) -> list[Observation]:
    """Read every gap record a change gap stream holds, in log order, straight off the log."""
    return [
        Observation.from_canonical_dict(record.payload)
        for record in repository.read_all()
        if is_change_gap_stream(record.stream_id) and record.event_type == "observation.recorded"
    ]


def stored_change_payload(change_set: Any, recorded_at: datetime = NOW) -> dict[str, Any]:
    """Return the `change.recorded` payload the writer stores for a one-change file."""
    (change,) = change_set.changes
    return writers_module._change_payload(change, change_set, recorded_at)


def not_a_record(stream_id: str, reason: str) -> str:
    """Word a stored record its change gap stream does not name as a change gap record."""
    return (
        f"observation.recorded on change gap stream {stream_id!r} is not a change gap record: "
        f"{reason}"
    )


def shape_message(stream_id: str, shape: str, heads: int, observations: int) -> str:
    """Word a change gap stream that is not one head and one observation (`shape` names how)."""
    return (
        f"change gap stream {stream_id!r} is {shape}: a change gap stream holds one "
        f"change.gap_recorded head and one observation, found {heads} head(s) and "
        f"{observations} observation(s)"
    )


def with_metadata(record: Observation, **edits: Any) -> dict[str, Any]:
    """Return a gap record's canonical form with metadata values set, or dropped when None."""
    canonical = record.to_canonical_dict()
    source = {**canonical["source_metadata"]}
    for key, value in edits.items():
        name = key.replace("_", ".", 1)
        if value is None:
            del source[name]
        else:
            source[name] = value
    return {**canonical, "source_metadata": source}


# *--- Identity Constants ---*


class ChangeGapIdentityConstantTests(unittest.TestCase):
    """The event layer spells the builder's identity without importing the report layer."""

    def test_the_event_layer_spells_the_builders_identity(self) -> None:
        self.assertEqual(repository_module.CHANGE_GAP_SOURCE_TYPE, CHANGE_GAP_SOURCE_TYPE)
        self.assertTrue(CHANGE_GAP_SOURCE_TYPE.startswith(RESERVED_SOURCE_TYPE_PREFIX))
        self.assertEqual(repository_module.CHANGE_GAP_METADATA_KEYS, CHANGE_GAP_METADATA_KEYS)
        for gap in stateless_gaps(CHANGE_SET):
            with self.subTest(resource=gap.resource.resource_id):
                self.assertEqual(
                    tuple(sorted(dict(gap.source_metadata))),
                    repository_module.CHANGE_GAP_METADATA_KEYS,
                )

    def test_every_identity_copy_equals_the_builders_constant(self) -> None:
        # Task 4: the audit holds a stored gap to these, so each copy is pinned to its source.
        pairs = {
            "CHANGE_GAP_SOURCE_TOOL": CHANGE_GAP_SOURCE_TOOL,
            "CHANGE_GAP_PARSER_NAME": CHANGE_GAP_PARSER_NAME,
            "CHANGE_GAP_PARSER_VERSION": CHANGE_GAP_PARSER_VERSION,
            "CHANGE_GAP_RECORD_ID": CHANGE_GAP_RECORD_ID,
            "CHANGE_GAP_TITLE": CHANGE_GAP_TITLE,
            "CHANGE_GAP_DESCRIPTION": CHANGE_GAP_DESCRIPTION,
            "CHANGE_GAP_BASIS_TEXTS": CHANGE_GAP_BASIS_TEXTS,
            "CHANGE_GAP_KEY_RULE": DAC_RULE,
        }
        for name, expected in pairs.items():
            with self.subTest(name=name):
                self.assertEqual(getattr(repository_module, name), expected)
        # The audit reads a stored kind against the change contract's own vocabulary.
        self.assertEqual({kind.value for kind in ChangeKind}, set(CHANGE_KIND_VALUES))

    def test_a_change_gap_stream_needs_schema_6_and_this_build_opens_it(self) -> None:
        self.assertEqual(CHANGE_GAP_STREAM_SCHEMA_VERSION, 6)
        self.assertEqual(SUPPORTED_SCHEMA_VERSION, CHANGE_GAP_STREAM_SCHEMA_VERSION)
        self.assertLess(CHANGE_STREAM_SCHEMA_VERSION, CHANGE_GAP_STREAM_SCHEMA_VERSION)
        self.assertEqual(sqlite_module._MIGRATION_DESCRIPTIONS[6], SIXTH[1])


# *--- Contract ---*


class ChangeGapRecordedContractTests(unittest.TestCase):
    """The head of a change gap stream: the closed window, named as its change names it."""

    def setUp(self) -> None:
        self.store = SQLiteEventStore(":memory:")
        self.addCleanup(self.store.close)
        self.repository = EventRepository(self.store)
        self.record = gap_of(stateless_gaps(CHANGE_SET))

    def payload(self, **overrides: Any) -> dict[str, Any]:
        return {**change_gap_head_payload(self.record), **overrides}

    def assert_refused(self, payload: Mapping[str, Any], pointer: str) -> None:
        with self.assertRaises(EventContractError) as caught:
            self.repository.validate_payload(CHANGE_GAP_RECORDED, payload)
        self.assertIn(pointer, [issue.instance_pointer for issue in caught.exception.issues])

    def test_the_head_is_read_off_its_gap_record_and_satisfies_its_contract(self) -> None:
        self.assertEqual(
            change_gap_head_payload(self.record),
            {
                "changeId": "CHG-1",
                "contextKey": "VDR-CSO-DAC:change:CHG-1",
                "windowClosedAt": DETECT_BY_TEXT,
                "occurredAt": OCCURRED_TEXT,
                "changesSha256": CHANGE_SET.sha256,
                "inventorySha256": INVENTORY.sha256,
            },
        )
        for gap in stateless_gaps(CHANGE_SET):
            with self.subTest(resource=gap.resource.resource_id):
                self.repository.validate_payload(CHANGE_GAP_RECORDED, change_gap_head_payload(gap))

    def test_the_head_carries_its_six_fields_and_nothing_else(self) -> None:
        # The stream id and the tracking id are pure functions of the gap record that follows
        # the head, so storing either would be a second copy that could disagree.
        self.assertEqual(list(CHANGE_GAP_RECORDED_V1["properties"]), list(HEAD_FIELDS))
        self.assertEqual(CHANGE_GAP_RECORDED_V1["required"], list(HEAD_FIELDS))
        self.assertIs(EVENT_CONTRACTS[(CHANGE_GAP_RECORDED, 1)], CHANGE_GAP_RECORDED_V1)
        self.assertIn(CHANGE_GAP_RECORDED, EVENT_TYPES)
        for extra in ("trackingId", "resource", "streamId", "fingerprint", "rule"):
            with self.subTest(field=extra):
                with self.assertRaises(EventContractError):
                    self.repository.validate_payload(
                        CHANGE_GAP_RECORDED, self.payload(**{extra: "x"})
                    )
        for missing in HEAD_FIELDS:
            with self.subTest(missing=missing):
                payload = self.payload()
                del payload[missing]
                with self.assertRaises(EventContractError):
                    self.repository.validate_payload(CHANGE_GAP_RECORDED, payload)

    def test_the_change_id_follows_the_change_name_rule(self) -> None:
        for value in ("", " CHG-1", "CHG-1 ", "CHG-1\n", "CHÉ-1", "x" * 129, 7):
            with self.subTest(value=repr(value)[:12]):
                self.assert_refused(self.payload(changeId=value), "/changeId")
        self.repository.validate_payload(
            CHANGE_GAP_RECORDED, self.payload(changeId="deploy:2026-09-01 web")
        )

    def test_blank_text_is_refused_as_a_context_key(self) -> None:
        for blank in ("", "   "):
            with self.subTest(value=blank):
                self.assert_refused(self.payload(contextKey=blank), "/contextKey")

    def test_both_digests_are_lowercase_sha256(self) -> None:
        for field_name in ("changesSha256", "inventorySha256"):
            for digest in ("A" * 64, "a" * 63, f"sha256:{'a' * 64}", f"{'a' * 64}\n"):
                with self.subTest(field=field_name, digest=repr(digest)[:10]):
                    self.assert_refused(self.payload(**{field_name: digest}), f"/{field_name}")

    def test_both_instants_are_real_utc_instants(self) -> None:
        self.assertEqual(
            timestamp_pointers_for(CHANGE_GAP_RECORDED), ("/occurredAt", "/windowClosedAt")
        )
        for field_name in ("windowClosedAt", "occurredAt"):
            for text in ("2026-09-01T13:00:00+00:00", "2026-09-01T15:00:00+02:00"):
                with self.subTest(field=field_name, value=text):
                    self.assert_refused(self.payload(**{field_name: text}), f"/{field_name}")
            with self.subTest(field=field_name, value="hour 24"):
                self.assert_refused(
                    with_value(self.payload(), f"/{field_name}", "2026-08-31T24:00:00Z"),
                    f"/{field_name}",
                )

    def test_only_a_change_gap_record_has_a_head(self) -> None:
        for label, record in (
            ("a detection failure", system_record()),
            ("an artifact observation", artifact_observation()),
            ("a coverage gap", gap_record()),
        ):
            with self.subTest(label):
                with self.assertRaises(ValueError):
                    change_gap_head_payload(record)
        bare = replace(self.record, source_metadata=())
        with self.assertRaises(ValueError) as caught:
            change_gap_head_payload(bare)
        self.assertIn("change.id", str(caught.exception))


# *--- Stream Id ---*


class ChangeGapStreamIdTests(StoreCase):
    """One stream per gap record, named for the record's own SYSTEM identity hash."""

    def test_the_stream_id_is_the_gap_records_own_fingerprint(self) -> None:
        record = gap_of(stateless_gaps(CHANGE_SET))
        stream_id = change_gap_stream_id_of(record)

        self.assertEqual(stream_id, f"changegap/{record.fingerprint}")
        self.assertEqual(CHANGE_GAP_STREAM_PREFIX, "changegap")
        self.assertEqual(change_gap_stream_id(record.fingerprint), stream_id)
        self.assertEqual(change_gap_stream_fingerprint(stream_id), record.fingerprint)
        self.assertEqual(stream_kind(stream_id), "changegap")
        self.assertTrue(is_change_gap_stream(stream_id))
        for other in (
            is_artifact_stream,
            is_case_stream,
            is_failure_stream,
            is_coverage_stream,
            is_change_stream,
        ):
            with self.subTest(predicate=other.__name__):
                self.assertFalse(other(stream_id))
        self.assertNotIn("lab-01", stream_id)
        self.assertNotIn("CHG-1", stream_id)

    def test_the_payload_recomputes_the_stream_id_whenever_it_was_ingested(self) -> None:
        record = gap_of(stateless_gaps(CHANGE_SET))
        later = replace(record, ingested_at=datetime(2030, 1, 1, tzinfo=UTC))

        self.assertEqual(
            change_gap_stream_id_of_payload(record.to_canonical_dict()),
            change_gap_stream_id_of(record),
        )
        self.assertEqual(
            change_gap_stream_id_of_payload(later.to_canonical_dict()),
            change_gap_stream_id_of(record),
        )

    def test_every_gap_of_one_change_has_its_own_stream(self) -> None:
        # Both hosts of one change share its context key and its window close, so neither names
        # a gap alone; the fingerprint does.
        first, second = stateless_gaps(CHANGE_SET)

        self.assertEqual(first.context_key, second.context_key)
        self.assertEqual(first.observed_at, second.observed_at)
        self.assertNotEqual(change_gap_stream_id_of(first), change_gap_stream_id_of(second))

    def test_the_stream_id_refuses_what_is_not_a_fingerprint(self) -> None:
        for value in ("A" * 64, "a" * 63, "a" * 65, f"{'a' * 32}/{'a' * 31}", 7):
            with self.subTest(value=str(value)[:8]):
                with self.assertRaises(ValueError):
                    change_gap_stream_id(value)  # type: ignore[arg-type]
        for stream_id, expected in (
            (f"change/{'a' * 64}", "must start with 'changegap/'"),
            (f"coverage/{'a' * 64}", "must start with 'changegap/'"),
            (f"changegaps/{'a' * 64}", "must start with 'changegap/'"),
            (f"changegap/{'a' * 64}/extra", "fingerprint"),
            (f"changegap/{'A' * 64}", "fingerprint"),
            ("changegap/", "fingerprint"),
        ):
            with self.subTest(stream_id=stream_id):
                with self.assertRaises(ValueError) as caught:
                    change_gap_stream_fingerprint(stream_id)
                self.assertIn(expected, str(caught.exception))
        self.assertIsNone(stream_kind(f"changegaps/{'a' * 64}"))

    def test_only_a_change_gap_record_names_a_change_gap_stream(self) -> None:
        for label, record in (
            ("a detection failure", system_record()),
            ("an artifact observation", artifact_observation()),
            ("a coverage gap", gap_record()),
        ):
            with self.subTest(label):
                with self.assertRaises(ValueError) as caught:
                    change_gap_stream_id_of(record)
                self.assertEqual(
                    str(caught.exception),
                    "only a system record of source type 'complyroll.change' names a change "
                    "gap stream",
                )
                with self.assertRaises(ValueError):
                    change_gap_stream_id_of_payload(record.to_canonical_dict())
        with self.assertRaises(TypeError):
            change_gap_stream_id_of(gap_record().to_canonical_dict())  # type: ignore[arg-type]
        forged = {**gap_of(stateless_gaps(CHANGE_SET)).to_canonical_dict(), "fingerprint": "0" * 64}
        with self.assertRaises(ValueError) as caught:
            change_gap_stream_id_of_payload(forged)
        self.assertIn("not a readable observation", str(caught.exception))

    def test_the_change_and_change_gap_prefix_scans_never_overlap(self) -> None:
        # A `changegap/` id sorts after every `change/` id and before the end of the `change/`
        # range, `change0`, so a range scan of either prefix sees the other kind never.
        change_prefix = f"{CHANGE_STREAM_PREFIX}/"
        gap_prefix = f"{CHANGE_GAP_STREAM_PREFIX}/"
        gap_stream = change_gap_stream_id("f" * 64)
        self.assertFalse(is_change_stream(gap_stream))
        self.assertFalse(is_change_gap_stream(change_stream_id("CHG-1")))
        self.assertFalse(gap_stream.startswith(change_prefix))

        record_the_change(self.repository)
        self.assertEqual(
            (
                self.store.holds_stream_with_prefix(change_prefix),
                self.store.holds_stream_with_prefix(gap_prefix),
            ),
            (True, False),
        )
        self.setUp()
        record = gap_of(stateless_gaps(CHANGE_SET))
        self.stage(
            change_gap_stream_id_of(record),
            change_gap_events(record),
            requires_schema=CHANGE_GAP_STREAM_SCHEMA_VERSION,
        )
        self.assertEqual(
            (
                self.store.holds_stream_with_prefix(change_prefix),
                self.store.holds_stream_with_prefix(gap_prefix),
            ),
            (False, True),
        )


# *--- Placement ---*


class ChangeGapPlacementTests(StoreCase):
    """The head and the gap record belong on a change gap stream, and the head nowhere else."""

    def test_the_six_kinds_name_the_change_gap_kind(self) -> None:
        self.assertEqual(
            CHANGE_GAP_STREAM_EVENT_TYPES, {CHANGE_GAP_RECORDED, "observation.recorded"}
        )
        self.assertEqual(STREAM_EVENT_TYPES["changegap"], CHANGE_GAP_STREAM_EVENT_TYPES)
        self.assertEqual(
            set(STREAM_EVENT_TYPES),
            {"artifact", "case", "failure", "coverage", "change", "changegap"},
        )

    def test_the_head_belongs_on_a_change_gap_stream_alone(self) -> None:
        stream_id = change_gap_stream_id("f" * 64)
        self.assertTrue(event_belongs_on_stream(CHANGE_GAP_RECORDED, stream_id))
        self.assertTrue(event_belongs_on_stream("observation.recorded", stream_id))
        for other in (
            f"artifact/{'a' * 64}/complyroll.cklb/1",
            failure_stream_id("a" * 64, "complyroll.sarif", "1"),
            f"coverage/{'a' * 64}",
            change_stream_id("CHG-1"),
            "case/case-0123456789abcdef",
            "projection/case-list",
        ):
            with self.subTest(other=other):
                self.assertFalse(event_belongs_on_stream(CHANGE_GAP_RECORDED, other))
        for event_type in EVENT_TYPES:
            if event_type in CHANGE_GAP_STREAM_EVENT_TYPES:
                continue
            with self.subTest(event_type=event_type):
                self.assertFalse(event_belongs_on_stream(event_type, stream_id))

    def test_a_foreign_event_is_refused_naming_the_change_gap_kind(self) -> None:
        stream_id = change_gap_stream_id("f" * 64)
        with self.assertRaises(EventContractError) as caught:
            self.repository.append(
                stream_id,
                "case.identified",
                {"providerTrackingId": "PROV-1"},
                occurred_at=NOW,
                metadata=metadata(),
                expected_version=0,
            )
        self.assertIn("which is a changegap stream", str(caught.exception))
        with self.assertRaises(EventContractError) as caught:
            self.repository.append(
                "projection/case-list",
                CHANGE_GAP_RECORDED,
                change_gap_head_payload(gap_of(stateless_gaps(CHANGE_SET))),
                occurred_at=NOW,
                metadata=metadata(),
                expected_version=0,
            )
        self.assertIn(
            "not an artifact, case, failure, coverage, change, or change gap stream",
            str(caught.exception),
        )

    def test_the_placement_guard_keeps_the_change_gap_kind_to_its_place(self) -> None:
        artifact = frozenset(ARTIFACT_STREAM_EVENT_TYPES)
        case = frozenset(CASE_STREAM_EVENT_TYPES)
        failure = frozenset(FAILURE_STREAM_EVENT_TYPES)
        coverage = frozenset(COVERAGE_STREAM_EVENT_TYPES)
        change = frozenset(CHANGE_STREAM_EVENT_TYPES)
        gap = frozenset(CHANGE_GAP_STREAM_EVENT_TYPES)
        published = frozenset(EVENT_TYPES)
        self.assertIsNone(
            _placement_problem(artifact, case, failure, coverage, change, gap, published)
        )
        for label, tables, expected in (
            (
                "an unplaced head",
                (artifact, case, failure, coverage, change, gap - {CHANGE_GAP_RECORDED}),
                "must belong to a stream kind",
            ),
            (
                "the head on a coverage stream",
                (artifact, case, failure, coverage | {CHANGE_GAP_RECORDED}, change, gap),
                "may share observation.recorded and nothing else",
            ),
            (
                "a coverage head on a change gap stream",
                (artifact, case, failure, coverage, change, gap | {COVERAGE_RECORDED}),
                "may share observation.recorded and nothing else",
            ),
            (
                "an observation off the change gap kind",
                (artifact, case, failure, coverage, change, gap - {"observation.recorded"}),
                "may share observation.recorded and nothing else",
            ),
            (
                "a case event on a change gap stream",
                (artifact, case, failure, coverage, change, gap | {"case.evaluated"}),
                "case stream kind alone",
            ),
            (
                "a change event on a change gap stream",
                (artifact, case, failure, coverage, change, gap | {CHANGE_RECORDED}),
                "change stream kind alone",
            ),
        ):
            with self.subTest(shape=label):
                problem = _placement_problem(*tables, published)
                self.assertIsNotNone(problem)
                self.assertIn(expected, str(problem))


# *--- Append ---*


class ChangeGapAppendTests(StoreCase):
    """The repository writes a change gap stream once, whole, and holds its head at append."""

    def setUp(self) -> None:
        super().setUp()
        record_the_change(self.repository)
        self.gaps = derived_gaps(self.repository)
        self.record = gap_of(self.gaps)
        self.stream_id = change_gap_stream_id_of(self.record)

    def assert_refused(
        self,
        stream_id: str,
        events: Sequence[tuple[str, Mapping[str, Any]]],
        message: str,
        *,
        expected_version: int = 0,
    ) -> None:
        latest = self.store.latest_sequence
        with self.assertRaises(EventContractError) as caught:
            self.repository.append_batch(
                stream_id,
                tuple(pending(event_type, payload) for event_type, payload in events),
                expected_version=expected_version,
            )
        self.assertIn(message, str(caught.exception))
        self.assertEqual(self.store.latest_sequence, latest)
        self.assertEqual(self.store.schema_version, CHANGE_STREAM_SCHEMA_VERSION)

    def test_a_whole_change_gap_stream_appends_head_first_in_one_batch(self) -> None:
        stream_id = record_change_gap(self.repository, self.record)

        head, observation = self.repository.read_stream(stream_id)
        self.assertEqual(
            [
                (head.event_type, head.stream_version),
                (observation.event_type, observation.stream_version),
            ],
            [(CHANGE_GAP_RECORDED, 1), ("observation.recorded", 2)],
        )
        self.assertEqual(observation.sequence, head.sequence + 1)
        self.assertEqual(head.payload, change_gap_head_payload(self.record))
        self.assertEqual(observation.payload, self.record.to_canonical_dict())
        self.assertEqual(self.store.schema_version, CHANGE_GAP_STREAM_SCHEMA_VERSION)
        self.assertEqual(audit_history(self.repository), ())

    def test_a_change_gap_stream_is_written_once_as_one_batch(self) -> None:
        head, record = change_gap_events(self.record)
        once = change_gap_write_once_message(self.stream_id)
        self.assertEqual(
            once,
            f"change gap stream {self.stream_id!r} is written once, as its change.gap_recorded "
            "head and then its gap record in one batch; a recorded gap is append-only history, "
            "so the first payload stands",
        )
        for label, events in (
            ("the head alone", [head]),
            ("two heads", [head, head]),
            ("a second record", [head, record, record]),
        ):
            with self.subTest(label):
                self.assert_refused(self.stream_id, events, once)
        for label, events in (("the record alone", [record]), ("the record first", [record, head])):
            with self.subTest(label):
                self.assert_refused(
                    self.stream_id, events, change_gap_head_order_message(self.stream_id)
                )
        self.assertEqual(
            change_gap_head_order_message(self.stream_id),
            f"change gap stream {self.stream_id!r} does not open with its change.gap_recorded "
            "head; a change gap stream is written head first",
        )

    def test_a_whole_stream_is_never_extended(self) -> None:
        record_change_gap(self.repository, self.record)
        latest = self.store.latest_sequence
        for events in (
            [("observation.recorded", self.record.to_canonical_dict())],
            change_gap_events(self.record),
        ):
            with self.subTest(count=len(events)):
                with self.assertRaises(EventContractError) as caught:
                    self.repository.append_batch(
                        self.stream_id,
                        tuple(pending(event_type, payload) for event_type, payload in events),
                        expected_version=2,
                    )
                self.assertIn(change_gap_write_once_message(self.stream_id), str(caught.exception))
        self.assertEqual(self.store.latest_sequence, latest)

    def test_each_head_field_must_name_what_its_gap_record_names(self) -> None:
        head = change_gap_head_payload(self.record)
        canonical = self.record.to_canonical_dict()
        for field_name, (record_key, other) in HEAD_PAIRS.items():
            with self.subTest(field=field_name):
                described = (
                    canonical["context_key"]
                    if record_key == "context_key"
                    else canonical["source_metadata"][record_key]
                )
                self.assert_refused(
                    self.stream_id,
                    change_gap_events(self.record, {**head, field_name: other}),
                    f"change gap stream {self.stream_id!r} records {field_name} {other!r} in "
                    f"its change.gap_recorded and {record_key} {described!r} in its gap record; "
                    "the two describe one gap",
                )

    def test_a_gap_of_a_change_the_store_never_recorded_is_refused(self) -> None:
        other = gap_of(stateless_gaps(changes_of(timed("CHG-2", pair("lab-01")))))
        stream_id = change_gap_stream_id_of(other)

        self.assert_refused(
            stream_id,
            change_gap_events(other),
            f"change gap stream {stream_id!r} records change id 'CHG-2' in its "
            "change.gap_recorded, and no change stream records that change; a change gap is a "
            "window of a recorded change",
        )

    def test_a_gap_of_another_reading_of_the_change_is_refused(self) -> None:
        # Each gap names the recorded change by its id, and each of its other fields here
        # disagrees with what the change stream holds, in one head field at a time.
        moved_occurrence = timed(
            "CHG-1",
            pair("lab-01"),
            pair("lab-02"),
            occurredAt=(T - HOUR).isoformat(),
        )
        moved_window = timed(
            "CHG-1",
            pair("lab-01"),
            pair("lab-02"),
            detectBy=(T + 2 * HOUR).isoformat(),
        )
        for label, change_set, field_name, change_key, recorded, stored in (
            (
                "another file",
                changes_named("another-file", timed("CHG-1", pair("lab-01"), pair("lab-02"))),
                "changesSha256",
                "changesSha256",
                None,
                CHANGE_SET.sha256,
            ),
            (
                "another occurrence",
                changes_of(moved_occurrence),
                "occurredAt",
                "occurredAt",
                "2026-09-01T11:00:00Z",
                OCCURRED_TEXT,
            ),
            (
                "another window",
                changes_of(moved_window),
                "windowClosedAt",
                "detectBy",
                "2026-09-01T14:00:00Z",
                DETECT_BY_TEXT,
            ),
        ):
            with self.subTest(label):
                other = gap_of(stateless_gaps(change_set))
                stream_id = change_gap_stream_id_of(other)
                head = change_gap_head_payload(other)
                value = change_set.sha256 if recorded is None else recorded
                self.assertEqual(head[field_name], value)
                self.assert_refused(
                    stream_id,
                    change_gap_events(other),
                    f"change gap stream {stream_id!r} records {field_name} {value!r} in its "
                    f"change.gap_recorded, and change 'CHG-1' records {change_key} {stored!r}; a "
                    "change gap is a window of the change it names",
                )

    def test_the_gap_record_of_another_stream_is_refused(self) -> None:
        other = gap_of(self.gaps, LAB_02)

        self.assert_refused(
            self.stream_id,
            [
                (CHANGE_GAP_RECORDED, change_gap_head_payload(self.record)),
                ("observation.recorded", other.to_canonical_dict()),
            ],
            f"observation.recorded on change gap stream {self.stream_id!r} is the gap record of "
            f"stream {change_gap_stream_id_of(other)!r}; a change gap stream is named for its "
            "gap record's fingerprint",
        )

    def test_a_record_that_is_not_a_change_gap_record_is_refused(self) -> None:
        head = change_gap_head_payload(self.record)
        for label, record in (
            ("a detection failure", system_record()),
            ("a coverage gap", gap_record()),
            ("an artifact observation", artifact_observation()),
        ):
            with self.subTest(label):
                self.assert_refused(
                    self.stream_id,
                    [
                        (CHANGE_GAP_RECORDED, head),
                        ("observation.recorded", record.to_canonical_dict()),
                    ],
                    f"observation.recorded on change gap stream {self.stream_id!r} is not a "
                    "change gap record: only a system record of source type "
                    "'complyroll.change' names a change gap stream",
                )

    def test_a_stream_id_naming_no_fingerprint_is_refused(self) -> None:
        for stream_id in ("changegap/not-a-fingerprint", f"changegap/{'A' * 64}"):
            with self.subTest(stream_id=stream_id):
                self.assert_refused(
                    stream_id,
                    change_gap_events(self.record),
                    f"stream {stream_id!r} names no gap record: fingerprint must be a lowercase "
                    "64-character SHA-256 digest",
                )

    def test_the_repeat_check_names_a_change_gap_stream(self) -> None:
        # Unreachable through `append_batch`, which writes a change gap stream once and whole;
        # held at the function, so the stream kind is named if that rule ever moves.
        stream_id = record_change_gap(self.repository, self.record)
        observation = ("observation.recorded", self.record.to_canonical_dict())

        with self.assertRaises(EventContractError) as caught:
            self.repository._require_unseen_observations(
                stream_id, (pending(*observation),), opening=False
            )

        message = duplicate_observation_message(stream_id, self.record.observation_id)
        self.assertEqual(str(caught.exception), message)
        self.assertTrue(message.startswith(f"change gap stream {stream_id!r} records observation"))

    def test_the_problem_checks_answer_only_for_change_gap_stream_events(self) -> None:
        canonical = self.record.to_canonical_dict()
        head = change_gap_head_payload(self.record)
        self.assertIsNone(change_gap_record_problem(self.stream_id, CHANGE_GAP_RECORDED, head))
        self.assertIsNone(
            change_gap_record_problem(self.stream_id, "observation.recorded", canonical)
        )
        self.assertIsNone(change_gap_record_problem(self.stream_id, "case.identified", {}))
        self.assertIsNone(
            change_gap_record_problem(f"coverage/{'a' * 64}", "observation.recorded", canonical)
        )
        self.assertEqual(
            change_gap_record_problem("changegap/x", CHANGE_GAP_RECORDED, head),
            (
                "changegap_stream_mismatch",
                "stream 'changegap/x' names no gap record: fingerprint must be a lowercase "
                "64-character SHA-256 digest",
            ),
        )
        self.assertIsNone(change_gap_record_disagreement(self.stream_id, head, canonical))
        stored = self.repository.read_stream(change_stream_id("CHG-1"))[0].payload
        self.assertIsNone(change_gap_change_disagreement(self.stream_id, head, stored))
        # The parent read answers None for a change no stream records, or no stream can name.
        self.assertEqual(self.repository._recorded_change_payload("CHG-1"), stored)
        for change_id in ("CHG-404", "", " CHG-1"):
            with self.subTest(change_id=change_id):
                self.assertIsNone(self.repository._recorded_change_payload(change_id))


# *--- Schema 6 ---*


class ChangeGapSchemaMarkingTests(StoreCase):
    """A store holding a change gap stream is marked schema 6 in the same transaction.

    A build that knows only schema 5 reads a change gap stream as a stream of no kind, so a
    store holding one says so before such a build can open it. A store that never records a
    change gap stays at its version and stays readable by that build (ADR 0018).
    """

    def damage(self, statement: str) -> None:
        self.store.close()
        with closing(sqlite3.connect(self.path, isolation_level=None)) as connection:
            connection.execute(statement)

    def record_one_gap(self) -> str:
        record_the_change(self.repository)
        return record_change_gap(self.repository, gap_of(derived_gaps(self.repository)))

    def test_the_first_gap_append_marks_schema_6_with_its_events(self) -> None:
        record_the_change(self.repository)
        self.assertEqual(self.store.schema_version, 5)

        stream_id = record_change_gap(self.repository, gap_of(derived_gaps(self.repository)))

        self.assertEqual(self.store.schema_version, 6)
        self.assertEqual(self.migrations(), ALL_SIX)
        self.assertEqual(self.repository.current_version(stream_id), 2)
        self.store.close()
        reopened = SQLiteEventStore(self.path)
        self.addCleanup(reopened.close)
        self.assertEqual(reopened.schema_version, 6)
        self.assertTrue(reopened.verify_history().ok)

    def test_marking_inserts_each_missing_record_from_3_4_and_5(self) -> None:
        # A gap needs a recorded change, and a change append marks 5, so a store below 5 that
        # holds a change was written past the repository; the marking is still linear.
        change_payload = stored_change_payload(CHANGE_SET)

        def staged_change(schema: int) -> None:
            self.stage(
                change_stream_id("CHG-1"),
                [(CHANGE_RECORDED, change_payload)],
                requires_schema=schema,
            )

        def from_3() -> None:
            self.record_failure()
            self.record_hold()
            staged_change(3)

        def from_4() -> None:
            record_coverage(self.repository, gap_record())
            staged_change(4)

        def from_5() -> None:
            record_the_change(self.repository)

        for label, before, prepare in (
            ("schema 3", [FIRST, SECOND, THIRD], from_3),
            ("schema 4", [FIRST, SECOND, THIRD, FOURTH], from_4),
            ("schema 5", [FIRST, SECOND, THIRD, FOURTH, FIFTH], from_5),
        ):
            with self.subTest(label):
                self.setUp()
                prepare()
                self.assertEqual(self.migrations(), before)

                record_change_gap(self.repository, gap_of(derived_gaps(self.repository)))

                self.assertEqual(self.store.schema_version, 6)
                self.assertEqual(self.migrations(), ALL_SIX)

    def test_a_rolled_back_gap_append_leaves_the_store_at_5(self) -> None:
        record_the_change(self.repository)
        latest = self.store.latest_sequence
        with self.assertRaises(RuntimeError):
            with self.repository.transaction():
                record_change_gap(self.repository, gap_of(derived_gaps(self.repository)))
                self.assertEqual(self.store.schema_version, 6)
                raise RuntimeError("abandon the gap")

        self.assertEqual(self.store.schema_version, 5)
        self.assertEqual(self.migrations(), [FIRST, SECOND, THIRD, FOURTH, FIFTH])
        self.assertEqual(self.store.latest_sequence, latest)

    def test_later_gap_change_coverage_and_failure_appends_mark_nothing_again(self) -> None:
        record_the_change(self.repository)
        first, second = derived_gaps(self.repository)
        record_change_gap(self.repository, first)
        record_change_gap(self.repository, second)
        record_the_change(self.repository, changes_of(timed("CHG-2", pair("lab-01"))))
        record_coverage(self.repository, gap_record())
        self.record_failure()
        self.record_hold()

        self.assertEqual(self.store.schema_version, 6)
        self.assertEqual(self.migrations(), ALL_SIX)

    def test_every_other_append_leaves_a_store_below_schema_6(self) -> None:
        self.record_failure()
        self.record_hold()
        record_coverage(self.repository, gap_record())
        record_the_change(self.repository)

        self.assertEqual(self.store.schema_version, 5)
        self.assertEqual(self.migrations(), [FIRST, SECOND, THIRD, FOURTH, FIFTH])

    def test_the_marking_changes_no_schema_object(self) -> None:
        def objects() -> list[tuple[str, str, str, str | None]]:
            with closing(sqlite3.connect(self.path)) as connection:
                rows = connection.execute(
                    "SELECT type, name, tbl_name, sql FROM sqlite_master ORDER BY type, name"
                ).fetchall()
            return [(str(kind), str(name), str(table), sql) for kind, name, table, sql in rows]

        record_the_change(self.repository)
        before = objects()
        record_change_gap(self.repository, gap_of(derived_gaps(self.repository)))

        self.assertEqual(self.store.schema_version, 6)
        self.assertEqual(objects(), before)

    def test_schema_6_needs_every_migration_record(self) -> None:
        for missing in (1, 2, 3, 4, 5, 6):
            with self.subTest(missing=missing):
                self.setUp()
                self.record_one_gap()
                self.damage(f"DELETE FROM complyroll_schema_migrations WHERE version = {missing}")

                with self.assertRaises(UnsupportedSchemaError) as caught:
                    SQLiteEventStore(self.path)

                self.assertIn(f"missing migration record {missing}", str(caught.exception))

    def test_a_pr_2_build_refuses_a_store_that_recorded_a_gap(self) -> None:
        self.record_one_gap()
        self.store.close()

        with mock.patch.object(sqlite_module, "SUPPORTED_SCHEMA_VERSION", 5):
            with self.assertRaises(UnsupportedSchemaError) as caught:
                SQLiteEventStore(self.path)
            with SQLiteEventStore.open_for_verification(self.path) as store:
                faults = store.verify_history().faults

        self.assertEqual(
            str(caught.exception), "database schema 6 is newer than supported schema 5"
        )
        self.assertEqual(
            [(fault.code, fault.message) for fault in faults],
            [
                (
                    "schema_version_unsupported",
                    "database is marked schema 6; this build opens schemas 1 to 5",
                )
            ],
        )

    def test_a_pr_2_build_still_opens_a_store_with_no_gap(self) -> None:
        record_the_change(self.repository)
        self.store.close()

        with mock.patch.object(sqlite_module, "SUPPORTED_SCHEMA_VERSION", 5):
            reopened = SQLiteEventStore(self.path)
            self.addCleanup(reopened.close)
            self.assertEqual(reopened.schema_version, 5)

    def test_a_store_newer_than_schema_6_is_refused(self) -> None:
        self.record_one_gap()
        self.damage("PRAGMA user_version = 7")

        with self.assertRaises(UnsupportedSchemaError) as caught:
            SQLiteEventStore(self.path)

        self.assertIn("database schema 7 is newer than supported schema 6", str(caught.exception))


# *--- Reader ---*


class ChangeGapStoreCase(StoreCase):
    """A store holding CHG-1, its lab-01 gap record and head, and a writer past the repository."""

    def setUp(self) -> None:
        super().setUp()
        record_the_change(self.repository)
        self.gaps = derived_gaps(self.repository)
        self.record = gap_of(self.gaps)
        self.stream_id = change_gap_stream_id_of(self.record)
        self.head, self.observation = change_gap_events(self.record)

    def plant(
        self,
        events: Sequence[tuple[str, Mapping[str, Any]]],
        stream_id: str | None = None,
        *,
        requires_schema: int = CHANGE_GAP_STREAM_SCHEMA_VERSION,
    ) -> list[int]:
        """Stage events on one new change gap stream past the repository, as a damaged store."""
        return self.stage(
            self.stream_id if stream_id is None else stream_id,
            events,
            requires_schema=requires_schema,
        )

    def faults(self) -> list[tuple[int, str]]:
        return [(fault.sequence, fault.code) for fault in audit_history(self.repository)]

    def refused(self) -> str:
        """Return the text every reader refuses this store with; none may succeed."""
        with self.assertRaises(HistoryError) as caught:
            rehydrate_observations(self.repository)
        return str(caught.exception)


class ChangeGapReaderTests(ChangeGapStoreCase):
    """The fold reads a whole change gap stream and refuses each shape the audit names."""

    def test_the_readers_read_a_whole_change_gap_stream(self) -> None:
        # Task 4: rehydration gains each gap record in recorded order, so `cases correlate`
        # opens one case per change, and artifact history is unchanged.
        self.record_failure()
        history = artifact_history(self.repository)
        (failure,) = rehydrate_observations(self.repository)
        lab_01, lab_02 = self.gaps

        record_change_gap(self.repository, lab_01)
        record_change_gap(self.repository, lab_02)

        self.assertEqual(artifact_history(self.repository), history)
        self.assertEqual(rehydrate_observations(self.repository), (failure, lab_01, lab_02))
        correlate_cases(self.repository, metadata=metadata(), now=NOW)
        self.assertEqual(
            sorted(
                (case.source_type, case.context_key) for case in fold_all_cases(self.repository)
            ),
            sorted({(item.source_type, item.context_key) for item in (failure, lab_01, lab_02)}),
        )
        self.assertEqual(audit_history(self.repository), ())

    def fresh_store(self) -> None:
        """Point the test at a new store holding CHG-1 alone, so each shape starts clean."""
        self.setUp()

    def test_the_reader_refuses_each_shape_with_the_audits_message(self) -> None:
        head, observation = self.head, self.observation
        other_head, other = change_gap_events(gap_of(self.gaps, LAB_02))
        canonical = self.record.to_canonical_dict()
        orphan = gap_of(stateless_gaps(changes_of(timed("CHG-2", pair("lab-01")))))
        another_window = gap_of(
            stateless_gaps(
                changes_of(
                    timed(
                        "CHG-1", pair("lab-01"), pair("lab-02"), detectBy=(T + 2 * HOUR).isoformat()
                    )
                )
            )
        )
        invalid = (CHANGE_GAP_RECORDED, {**head[1], "windowClosedAt": "soon"})
        # Each shape, the stream it is planted on, the audit code it is reported under, and the
        # text the reader puts before the audit's message, as it does for a coverage stream.
        shapes: dict[str, tuple[str, list[tuple[str, Any]], str, str | None]] = {
            "head alone": (self.stream_id, [head], "changegap_incomplete", None),
            "record alone": (self.stream_id, [observation], "changegap_incomplete", None),
            "a second record": (
                self.stream_id,
                [head, observation, observation],
                "changegap_overfull",
                None,
            ),
            "record first": (
                self.stream_id,
                [observation, head],
                "changegap_stream_mismatch",
                None,
            ),
            "another gap's record": (
                self.stream_id,
                [other_head, other],
                "changegap_stream_mismatch",
                "is on the wrong stream",
            ),
            "a metadata key dropped": (
                self.stream_id,
                [head, ("observation.recorded", with_metadata(self.record, change_force=None))],
                "changegap_identity_breach",
                "is on the wrong stream",
            ),
            "a head naming another window close": (
                self.stream_id,
                [(CHANGE_GAP_RECORDED, {**head[1], "windowClosedAt": "2026-09-01T14:00:00Z"})]
                + [observation],
                "changegap_identity_breach",
                None,
            ),
            "a head outside its contract": (
                self.stream_id,
                [invalid, observation],
                "payload_contract_invalid",
                "is not a readable change gap head",
            ),
            "a stream id naming no fingerprint": (
                "changegap/not-a-fingerprint",
                [head, observation],
                "changegap_stream_mismatch",
                "is on the wrong stream",
            ),
            "a gap of a change no stream records": (
                change_gap_stream_id_of(orphan),
                change_gap_events(orphan),
                "changegap_stream_mismatch",
                None,
            ),
            "a gap of another reading of its change": (
                change_gap_stream_id_of(another_window),
                change_gap_events(another_window),
                "changegap_stream_mismatch",
                None,
            ),
            **{
                f"its {field} edited": (
                    self.stream_id,
                    [head, ("observation.recorded", {**canonical, field: value})],
                    "changegap_identity_breach",
                    "is on the wrong stream",
                )
                for field, (value, _) in FIXED_FIELD_EDITS.items()
            },
            "its artifact digest set": (
                self.stream_id,
                [head, ("observation.recorded", {**canonical, "source_artifact_digest": "c" * 64})],
                "payload_contract_invalid",
                "is not a readable observation",
            ),
            # The stream kind is read before the event type, so a foreign event stops the read.
            "a foreign event alone": (
                self.stream_id,
                [("case.identified", {"providerTrackingId": "PROV-2026-0001"})],
                "event_stream_mismatch",
                None,
            ),
            "a foreign event after a whole stream": (
                self.stream_id,
                [head, observation, ("probe.planted", {})],
                "event_stream_mismatch",
                None,
            ),
            "a foreign event on a stream no gap names": (
                change_gap_stream_id("f" * 64),
                [("case.identified", {"providerTrackingId": "PROV-2026-0001"})],
                "event_stream_mismatch",
                None,
            ),
        }
        for label, (stream_id, events, code, prefix) in shapes.items():
            with self.subTest(label):
                self.fresh_store()
                self.plant(events, stream_id)
                faults = [fault for fault in audit_history(self.repository) if fault.code == code]
                self.assertTrue(faults, msg=label)
                fault = faults[0]
                expected = (
                    fault.message
                    if prefix is None
                    else f"event {fault.sequence} {prefix}: {fault.message}"
                )

                self.assertEqual(self.refused(), expected)

    def test_a_store_holding_a_gap_and_no_change_is_refused_by_name(self) -> None:
        # Call 11 and P M13: only a write past the repository leaves this, and a reader names
        # it rather than letting a report build a change-gap-aware compile with no block.
        StoreCase.setUp(self)
        orphan = gap_of(stateless_gaps(CHANGE_SET))
        stream_id = change_gap_stream_id_of(orphan)
        self.plant(change_gap_events(orphan), stream_id)

        message = (
            f"change gap stream {stream_id!r} records change id 'CHG-1' in its "
            "change.gap_recorded, and no change stream records that change; a change gap is a "
            "window of a recorded change"
        )
        self.assertEqual(self.refused(), message)
        self.assertEqual(
            [(fault.code, fault.message) for fault in audit_history(self.repository)],
            [("changegap_stream_mismatch", message)],
        )


# *--- Audits ---*


class ChangeGapAuditTests(ChangeGapStoreCase):
    """`audit_history` names each way a change gap stream is not one head and its gap record."""

    def test_a_whole_change_gap_stream_is_no_fault(self) -> None:
        self.plant([self.head, self.observation])

        self.assertEqual(audit_history(self.repository), ())

    def test_a_stream_that_is_not_one_head_and_one_observation_is_incomplete_or_overfull(
        self,
    ) -> None:
        shapes = {
            "head only": ([self.head], "incomplete", 1, 0),
            "record only": ([self.observation], "incomplete", 0, 1),
            "head twice": ([self.head, self.observation, self.head], "overfull", 2, 1),
            "record twice": ([self.head, self.observation, self.observation], "overfull", 1, 2),
        }
        for label, (events, shape, heads, observations) in shapes.items():
            with self.subTest(label):
                self.setUp()
                sequences = self.plant(events)

                faults = audit_history(self.repository)
                self.assertEqual(
                    [(fault.sequence, fault.code) for fault in faults],
                    [(sequences[0], f"changegap_{shape}")],
                )
                self.assertEqual(
                    faults[0].message, shape_message(self.stream_id, shape, heads, observations)
                )

    def test_a_stream_its_record_opens_is_a_stream_mismatch(self) -> None:
        sequences = self.plant([self.observation, self.head])

        self.assertEqual(self.faults(), [(sequences[0], "changegap_stream_mismatch")])
        self.assertEqual(
            audit_history(self.repository)[0].message,
            change_gap_head_order_message(self.stream_id),
        )

    def test_another_gaps_record_is_a_stream_mismatch(self) -> None:
        other = gap_of(self.gaps, LAB_02)
        # The head agrees with the record it sits beside, so the stream id is all that is wrong.
        sequences = self.plant(change_gap_events(other))

        self.assertEqual(self.faults(), [(sequences[1], "changegap_stream_mismatch")])
        self.assertIn(
            f"is the gap record of stream {change_gap_stream_id_of(other)!r}",
            audit_history(self.repository)[0].message,
        )

    def test_a_stream_id_naming_no_fingerprint_is_a_mismatch_on_each_event(self) -> None:
        stream_id = "changegap/not-a-fingerprint"
        sequences = self.plant([self.head, self.observation], stream_id)

        self.assertEqual(
            self.faults(), [(sequence, "changegap_stream_mismatch") for sequence in sequences]
        )
        for fault in audit_history(self.repository):
            self.assertIn(f"stream {stream_id!r} names no gap record", fault.message)

    def test_a_record_that_is_not_a_change_gap_record_is_an_identity_breach(self) -> None:
        for label, record in (
            ("a detection failure", system_record()),
            ("a coverage gap", gap_record()),
        ):
            with self.subTest(label):
                self.setUp()
                stream_id = change_gap_stream_id(record.fingerprint)
                sequences = self.plant(
                    [self.head, ("observation.recorded", record.to_canonical_dict())], stream_id
                )

                self.assertEqual(self.faults(), [(sequences[1], "changegap_identity_breach")])
                self.assertEqual(
                    audit_history(self.repository)[0].message,
                    not_a_record(stream_id, NOT_A_CHANGE_GAP),
                )

    def test_a_foreign_event_on_a_change_gap_stream_is_a_placement_fault(self) -> None:
        foreign = ("case.identified", {"providerTrackingId": "PROV-2026-0001"})
        shapes = {
            # Alone, it also leaves the stream without either half.
            "alone": ([foreign], [(0, "changegap_incomplete"), (0, "event_stream_mismatch")]),
            "after a whole stream": (
                [self.head, self.observation, foreign],
                [(2, "event_stream_mismatch")],
            ),
        }
        for label, (events, expected) in shapes.items():
            with self.subTest(label):
                self.setUp()
                sequences = self.plant(events)

                self.assertEqual(
                    self.faults(), [(sequences[index], code) for index, code in expected]
                )

    def test_a_head_that_disagrees_with_its_record_is_an_identity_breach(self) -> None:
        canonical = self.record.to_canonical_dict()
        for field_name, (record_key, other) in HEAD_PAIRS.items():
            with self.subTest(field=field_name):
                self.setUp()
                head = {**change_gap_head_payload(self.record), field_name: other}
                sequences = self.plant([(CHANGE_GAP_RECORDED, head), self.observation])

                self.assertEqual(self.faults(), [(sequences[1], "changegap_identity_breach")])
                described = (
                    canonical["context_key"]
                    if record_key == "context_key"
                    else canonical["source_metadata"][record_key]
                )
                message = (
                    f"change gap stream {self.stream_id!r} records {field_name} {other!r} in "
                    f"its change.gap_recorded and {record_key} {described!r} in its gap record; "
                    "the two describe one gap"
                )
                self.assertEqual(audit_history(self.repository)[0].message, message)
                self.assertEqual(
                    change_gap_record_disagreement(self.stream_id, head, canonical), message
                )

    def test_a_head_naming_a_change_no_stream_records_is_a_stream_mismatch(self) -> None:
        orphan = gap_of(stateless_gaps(changes_of(timed("CHG-2", pair("lab-01")))))
        stream_id = change_gap_stream_id_of(orphan)
        sequences = self.plant(change_gap_events(orphan), stream_id)

        self.assertEqual(self.faults(), [(sequences[0], "changegap_stream_mismatch")])
        self.assertEqual(
            audit_history(self.repository)[0].message,
            f"change gap stream {stream_id!r} records change id 'CHG-2' in its "
            "change.gap_recorded, and no change stream records that change; a change gap is a "
            "window of a recorded change",
        )

    def test_a_head_naming_another_reading_of_its_change_is_a_stream_mismatch(self) -> None:
        # The head and its record agree with each other; the stored change says otherwise.
        for label, change_set, field_name, change_key, stored in (
            (
                "another file",
                changes_named("another-file", timed("CHG-1", pair("lab-01"), pair("lab-02"))),
                "changesSha256",
                "changesSha256",
                CHANGE_SET.sha256,
            ),
            (
                "another occurrence",
                changes_of(
                    timed(
                        "CHG-1", pair("lab-01"), pair("lab-02"), occurredAt=(T - HOUR).isoformat()
                    )
                ),
                "occurredAt",
                "occurredAt",
                OCCURRED_TEXT,
            ),
            (
                "another window",
                changes_of(
                    timed(
                        "CHG-1",
                        pair("lab-01"),
                        pair("lab-02"),
                        detectBy=(T + 2 * HOUR).isoformat(),
                    )
                ),
                "windowClosedAt",
                "detectBy",
                DETECT_BY_TEXT,
            ),
        ):
            with self.subTest(label):
                self.setUp()
                other = gap_of(stateless_gaps(change_set))
                stream_id = change_gap_stream_id_of(other)
                head = change_gap_head_payload(other)
                sequences = self.plant(change_gap_events(other), stream_id)

                self.assertEqual(self.faults(), [(sequences[0], "changegap_stream_mismatch")])
                self.assertEqual(
                    audit_history(self.repository)[0].message,
                    f"change gap stream {stream_id!r} records {field_name} "
                    f"{head[field_name]!r} in its change.gap_recorded, and change 'CHG-1' "
                    f"records {change_key} {stored!r}; a change gap is a window of the change it "
                    "names",
                )

    def test_a_change_gap_stream_in_a_store_below_schema_6_is_unmarked(self) -> None:
        sequences = self.plant([self.head, self.observation], requires_schema=5)

        self.assertEqual(self.store.schema_version, 5)
        self.assertEqual(self.faults(), [(sequences[0], "changegap_schema_unmarked")])
        self.assertEqual(
            audit_history(self.repository)[0].message,
            f"change gap stream {self.stream_id!r} is in a store at schema 5; a store holding "
            "change gap streams is marked schema 6, so a build that cannot read them refuses it "
            "rather than misreading it",
        )
        # No reader refuses it: the gap is read as the writer recorded it.
        self.assertIn(self.record, rehydrate_observations(self.repository))

    def test_one_unmarked_fault_names_the_first_change_gap_stream_beside_each_other_kind(
        self,
    ) -> None:
        StoreCase.setUp(self)
        change = self.stage(
            change_stream_id("CHG-1"),
            [(CHANGE_RECORDED, stored_change_payload(CHANGE_SET))],
            requires_schema=1,
        )
        first, second = stateless_gaps(CHANGE_SET)
        gap = self.plant(
            change_gap_events(first), change_gap_stream_id_of(first), requires_schema=1
        )
        self.plant(change_gap_events(second), change_gap_stream_id_of(second), requires_schema=1)

        self.assertEqual(
            self.faults(),
            [(change[0], "change_schema_unmarked"), (gap[0], "changegap_schema_unmarked")],
        )

    def test_the_five_codes_are_published_and_the_marker_is_content_neutral(self) -> None:
        codes = (
            "changegap_identity_breach",
            "changegap_incomplete",
            "changegap_overfull",
            "changegap_schema_unmarked",
            "changegap_stream_mismatch",
        )
        for code in codes:
            self.assertIn(code, AUDIT_FAULT_CODES)
        self.assertEqual(AUDIT_FAULT_CODES, tuple(sorted(AUDIT_FAULT_CODES)))
        # No reader refuses a marker left low, so the order check still runs beside it.
        self.assertEqual(
            {code for code in codes if code in _ORDER_CHECKED_BESIDE},
            {"changegap_schema_unmarked"},
        )

    def test_the_order_checks_still_run_beside_an_unmarked_store(self) -> None:
        # The order checks fold the cases and rehydrate the gap, which reads as written, so a
        # marker left low hides no inversion for good (ADR 0008 amendment 2026-10-14, second).
        sequences = self.plant([self.head, self.observation], requires_schema=5)
        sentinel = HistoryFault(sequence=1, code="evaluation_before_detection", message="x")
        with mock.patch.object(order_module, "evaluation_order_faults", return_value=(sentinel,)):
            faults = self.faults()

        self.assertEqual(
            faults,
            [(1, "evaluation_before_detection"), (sequences[0], "changegap_schema_unmarked")],
        )

    def test_the_problem_checks_answer_only_for_change_gap_stream_events(self) -> None:
        canonical = self.record.to_canonical_dict()
        for stream_id, event_type in (
            (f"artifact/{'a' * 64}/complyroll.cklb/1", "observation.recorded"),
            (f"failure/{'a' * 64}/complyroll.sarif/1", "observation.recorded"),
            (f"coverage/{'a' * 64}", "observation.recorded"),
            (self.stream_id, "case.identified"),
        ):
            with self.subTest(stream=stream_id, event_type=event_type):
                self.assertIsNone(change_gap_record_problem(stream_id, event_type, canonical))


class ChangeGapIdentityAuditTests(ChangeGapStoreCase):
    """Task 4's identity audit: each builder-fixed field, mutated alone, trips the audit.

    The fingerprint covers none of the metadata, so a record edited there still names its
    stream; a field it does cover is moved with `rebuilt`, under the id it then derives, and
    planted on its own stream. Each breach is the audit's fault, the reader's refusal and the
    repository's refusal at append, in one text (P lesson 1).
    """

    def assert_breach(
        self,
        observation: Mapping[str, Any],
        reason: str,
        *,
        stream_id: str | None = None,
        code: str = "changegap_identity_breach",
    ) -> None:
        stream = self.stream_id if stream_id is None else stream_id
        sequences = self.plant([self.head, ("observation.recorded", observation)], stream)
        message = not_a_record(stream, reason)

        self.assertEqual(self.faults(), [(sequences[1], code)])
        self.assertEqual(audit_history(self.repository)[0].message, message)
        self.assertEqual(self.refused(), f"event {sequences[1]} is on the wrong stream: {message}")
        self.assertEqual(
            change_gap_record_problem(stream, "observation.recorded", observation),
            (code, message),
        )

    def assert_moved(self, reason: str, **changes: Any) -> None:
        """Move a fingerprinted field, re-derive the id, and plant it on its own stream."""
        moved = rebuilt(self.record, **changes)
        self.assert_breach(
            moved.to_canonical_dict(), reason, stream_id=change_gap_stream_id(moved.fingerprint)
        )

    def test_every_gap_the_builder_writes_passes_the_identity_check(self) -> None:
        # Entry, group and late rows, a job, a colon and a space in the id, and a window that
        # closes as the change occurs: what the writer records is never a breach (M4).
        group_inventory = inventory_of(
            host("lab-01"), host("web-01", sampleGroup="web"), host("web-02", sampleGroup="web")
        )
        change_set = changes_of(
            timed("deploy:2026-09-01 web", pair("lab-01"), GROUP_PAIR, job="nightly"),
            timed("CHG-0", pair("lab-01"), detectBy=T.isoformat()),
        )
        projection = derive_report_changes((), change_set, group_inventory, PROFILE, AS_OF)
        records = change_gap_observations(projection, ingested_at=AS_OF)
        self.assertEqual(len(records), 3)
        for record in records:
            with self.subTest(key=record.context_key, resource=record.resource.resource_id):
                self.assertIsNone(
                    change_gap_record_problem(
                        change_gap_stream_id_of(record),
                        "observation.recorded",
                        record.to_canonical_dict(),
                    )
                )

    def test_a_record_of_another_source_type_is_an_identity_breach(self) -> None:
        self.assert_moved(NOT_A_CHANGE_GAP, source_type="complyroll.synthetic-other")

    def test_a_record_of_another_tool_is_an_identity_breach(self) -> None:
        self.assert_moved("its source tool is 'other'", source_tool="other")

    def test_a_record_of_another_parser_is_an_identity_breach(self) -> None:
        for label, changes, reason in (
            ("name", {"parser_name": "complyroll.other"}, "'complyroll.other' version '1'"),
            ("version", {"parser_version": "2"}, "'complyroll.change' version '2'"),
        ):
            with self.subTest(label):
                self.setUp()
                self.assert_moved(f"its parser is {reason}", **changes)

    def test_a_record_of_another_record_id_is_an_identity_breach(self) -> None:
        self.assert_moved("its source record id is 'change-gap-2'", source_record_id="change-gap-2")

    def test_a_record_of_another_origin_is_contract_invalid_and_not_a_change_gap_record(
        self,
    ) -> None:
        # The observation contract keeps the reserved prefix to system records, so it refuses
        # this on every store path first; the identity check's own reason is a direct call's.
        observation = {**self.observation[1], "origin": "artifact"}
        sequences = self.plant([self.head, ("observation.recorded", observation)])

        self.assertEqual(self.faults(), [(sequences[1], "payload_contract_invalid")])
        self.assertEqual(
            change_gap_record_problem(self.stream_id, "observation.recorded", observation),
            ("changegap_identity_breach", not_a_record(self.stream_id, NOT_A_CHANGE_GAP)),
        )

    def test_another_disposition_is_an_identity_breach(self) -> None:
        self.assert_breach(
            {**self.observation[1], "disposition": "pass"}, "its disposition is 'pass'"
        )

    def test_another_severity_is_an_identity_breach(self) -> None:
        self.assert_breach(
            {**self.observation[1], "source_severity": "high"}, "its source severity is 'high'"
        )

    def test_source_identifiers_are_an_identity_breach(self) -> None:
        self.assert_breach(
            {**self.observation[1], "source_identifiers": ["CVE-2099-0001"]},
            "its source identifiers are ['CVE-2099-0001']",
        )

    def test_another_description_is_an_identity_breach(self) -> None:
        self.assert_breach({**self.observation[1], "description": "x"}, "its description is 'x'")

    def test_an_artifact_field_is_contract_invalid_and_not_a_change_gap_record(self) -> None:
        for field, value in (("source_artifact_digest", "c" * 64), ("source_artifact_name", "x")):
            with self.subTest(field):
                self.setUp()
                observation = {**self.observation[1], field: value}
                sequences = self.plant([self.head, ("observation.recorded", observation)])

                self.assertEqual(self.faults(), [(sequences[1], "payload_contract_invalid")])
                self.assertEqual(
                    change_gap_record_problem(self.stream_id, "observation.recorded", observation),
                    (
                        "changegap_identity_breach",
                        not_a_record(self.stream_id, f"its {field.replace('_', ' ')} is {value!r}"),
                    ),
                )

    def test_a_window_close_other_than_the_observed_instant_is_an_identity_breach(
        self,
    ) -> None:
        # observed_at, change.detectBy and the head's windowClosedAt name one instant.
        with self.subTest("the metadata close moved"):
            self.assert_breach(
                with_metadata(self.record, change_detectBy="2026-09-01T14:00:00Z"),
                "its metadata change.detectBy is '2026-09-01T14:00:00Z', where the record is "
                "observed at '2026-09-01T13:00:00Z'",
            )
        with self.subTest("the observed instant moved"):
            self.setUp()
            self.assert_moved(
                "its metadata change.detectBy is '2026-09-01T13:00:00Z', where the record is "
                "observed at '2026-09-01T14:00:00Z'",
                observed_at=T + 2 * HOUR,
            )
        with self.subTest("the close spelled with an offset"):
            self.setUp()
            self.assert_breach(
                with_metadata(self.record, change_detectBy="2026-09-01T13:00:00+00:00"),
                "its metadata change.detectBy is '2026-09-01T13:00:00+00:00', where the record "
                "is observed at '2026-09-01T13:00:00Z'",
            )

    def test_a_context_key_other_than_the_changes_is_an_identity_breach(self) -> None:
        with self.subTest("the key moved"):
            self.assert_moved(
                "its metadata change.id is 'CHG-1', and its context key "
                "'VDR-CSO-DAC:change:CHG-9' is not 'VDR-CSO-DAC:change:CHG-1'",
                context_key="VDR-CSO-DAC:change:CHG-9",
            )
        with self.subTest("the change id moved"):
            self.setUp()
            self.assert_breach(
                with_metadata(self.record, change_id="CHG-9"),
                "its metadata change.id is 'CHG-9', and its context key "
                "'VDR-CSO-DAC:change:CHG-1' is not 'VDR-CSO-DAC:change:CHG-9'",
            )
        for change_id in ("", " CHG-1"):
            with self.subTest("a change id naming no change", change_id=change_id):
                self.setUp()
                self.assert_breach(
                    with_metadata(self.record, change_id=change_id),
                    f"its metadata change.id is {change_id!r}, which names no change",
                )

    def test_another_change_rule_is_an_identity_breach(self) -> None:
        self.assert_breach(
            with_metadata(self.record, change_rule="VDR-CSO-AKE"),
            "its metadata change.rule is 'VDR-CSO-AKE', not 'VDR-CSO-DAC'",
        )

    def test_a_force_that_is_no_rule_force_is_an_identity_breach(self) -> None:
        self.assert_breach(
            with_metadata(self.record, change_force="MAYBE"),
            "its metadata change.force is 'MAYBE', not a rule force",
        )

    def test_a_kind_that_is_no_change_kind_is_an_identity_breach(self) -> None:
        self.assert_breach(
            with_metadata(self.record, change_kind="deleted"),
            "its metadata change.kind is 'deleted', not a change kind",
        )

    def test_an_occurrence_after_the_close_is_an_identity_breach(self) -> None:
        for label, value, reason in (
            (
                "after the close",
                "2026-09-01T14:00:00Z",
                "which is after its window close '2026-09-01T13:00:00Z'",
            ),
            (
                "spelled with an offset",
                "2026-09-01T12:00:00+00:00",
                "not an instant as its writer spells one",
            ),
            ("no instant", "last week", "not an instant as its writer spells one"),
        ):
            with self.subTest(label):
                self.setUp()
                self.assert_breach(
                    with_metadata(self.record, change_occurredAt=value),
                    f"its metadata change.occurredAt is {value!r}, {reason}",
                )
        # A window may close as its change occurs (M4), so the two may be one instant.
        at_the_close = with_metadata(self.record, change_occurredAt=DETECT_BY_TEXT)
        self.assertIsNone(
            change_gap_record_problem(self.stream_id, "observation.recorded", at_the_close)
        )

    def test_another_basis_is_an_identity_breach(self) -> None:
        self.assert_breach(
            with_metadata(self.record, change_basis="Changes looked fine."),
            "its metadata change.basis is 'Changes looked fine.', not a basis its writer records",
        )

    def test_another_title_is_an_identity_breach(self) -> None:
        self.assert_breach(
            {**self.observation[1], "title": "Nothing to see here"},
            "its title is 'Nothing to see here'",
        )

    def test_another_evidence_id_is_an_identity_breach(self) -> None:
        digest = self.observation[1]["source_metadata"]["change.changesSha256"]
        self.assert_breach(
            {**self.observation[1], "evidence_ids": [f"sha256:{'d' * 64}"]},
            f"its evidence ids are ['sha256:{'d' * 64}'], where its metadata "
            f"change.changesSha256 names ['sha256:{digest}']",
        )

    def test_a_digest_that_is_not_sha256_text_is_an_identity_breach(self) -> None:
        for key in ("change.changesSha256", "change.inventorySha256"):
            for value in ("C" * 64, "x"):
                with self.subTest(key=key, value=value):
                    self.setUp()
                    observation = with_metadata(self.record, **{key.replace(".", "_"): value})
                    if key == "change.changesSha256":
                        # Consistent with its evidence id, so only the digest itself is wrong.
                        observation["evidence_ids"] = [f"sha256:{value}"]
                    self.assert_breach(
                        observation,
                        f"its metadata {key} is {value!r}, not a SHA-256 digest",
                    )

    def test_a_missing_or_added_metadata_key_is_an_identity_breach(self) -> None:
        with self.subTest("change.job missing"):
            self.assert_breach(
                with_metadata(self.record, change_job=None), "its metadata has no 'change.job'"
            )
        with self.subTest("a key added"):
            self.setUp()
            self.assert_breach(
                with_metadata(self.record, change_note="x"),
                "its metadata carries 'change.note', which a change gap record does not",
            )

    def test_an_id_that_is_not_derived_is_an_identity_breach(self) -> None:
        derived = self.record.observation_id
        self.assert_breach(
            {**self.observation[1], "observation_id": f"obs-{'0' * 64}"},
            f"its id is 'obs-{'0' * 64}', not its derived id {derived!r}",
        )

    def test_a_record_its_reader_cannot_read_is_named_at_the_function(self) -> None:
        # Unreachable on a store path, where the observation contract reads the same payload
        # first (call 14); a direct call names it rather than raising.
        forged = {
            **self.observation[1],
            "fingerprint": "0" * 64,
            "observation_id": f"obs-{'0' * 64}",
        }

        code, message = change_gap_record_problem(
            self.stream_id, "observation.recorded", forged
        ) or ("", "")

        self.assertEqual(code, "changegap_identity_breach")
        self.assertTrue(
            message.startswith(
                not_a_record(self.stream_id, "the payload is not a readable observation: ")
            ),
            msg=message,
        )

    def test_an_oddly_spelled_value_is_named_and_never_raises(self) -> None:
        # Written past the repository, any text may sit where an instant or a digest goes; the
        # audit names it and returns rather than stopping on it.
        for edits in (
            {"change_detectBy": "garbage"},
            {"change_occurredAt": "9999-12-31T23:59:59-23:59"},
            {"change_occurredAt": "2026-02-30T12:00:00Z"},
            {"change_force": ""},
            {"change_changesSha256": ""},
        ):
            with self.subTest(edits=edits):
                self.setUp()
                self.plant(
                    [self.head, ("observation.recorded", with_metadata(self.record, **edits))]
                )
                self.assertEqual([code for _, code in self.faults()], ["changegap_identity_breach"])


# *--- Writer ---*


class ChangeGapWriterTests(StoreCase):
    """`record_change_gaps`: one whole stream per closed change window, written once."""

    def record_gaps(
        self,
        inventory: Any = INVENTORY,
        *,
        as_of: datetime = AS_OF,
        profile: CertificationProfile = PROFILE,
    ) -> ChangeGapOutcome:
        return record_change_gaps(
            self.repository, inventory, profile=profile, as_of=as_of, metadata=metadata()
        )

    def test_each_closed_window_is_recorded_head_first_in_one_batch(self) -> None:
        record_the_change(self.repository)
        expected = derived_gaps(self.repository)
        before = self.store.latest_sequence

        outcome = self.record_gaps()

        self.assertEqual(outcome.recorded, expected)
        self.assertEqual(outcome.already_recorded, ())
        self.assertEqual([gap.resource for gap in outcome.recorded], [LAB_01, LAB_02])
        self.assertEqual(self.store.latest_sequence, before + 2 * len(expected))
        self.assertEqual(self.store.schema_version, 6)
        sequence = before
        for gap in outcome.recorded:
            with self.subTest(gap=gap.observation_id):
                head, record = self.repository.read_stream(change_gap_stream_id_of(gap))
                self.assertEqual(
                    [
                        (head.event_type, head.stream_version),
                        (record.event_type, record.stream_version),
                    ],
                    [(CHANGE_GAP_RECORDED, 1), ("observation.recorded", 2)],
                )
                # One batch per stream, written in obligation order.
                self.assertEqual((head.sequence, record.sequence), (sequence + 1, sequence + 2))
                self.assertEqual(head.payload, change_gap_head_payload(gap))
                self.assertEqual(record.payload, gap.to_canonical_dict())
                self.assertEqual(gap.ingested_at, AS_OF)
                self.assertEqual({head.occurred_at, record.occurred_at}, {AS_OF})
                self.assertEqual(head.metadata["runId"], record.metadata["runId"])
                sequence = record.sequence
        self.assertEqual(recorded_gaps(self.repository), list(expected))
        self.assertEqual(outcome.changes.as_of, AS_OF)
        self.assertEqual(outcome.diagnostics, outcome.changes.warnings)
        self.assertEqual(audit_history(self.repository), ())

    def test_the_gaps_follow_the_changes_obligation_order(self) -> None:
        # By occurredAt, then change id, then resource: CHG-0 occurred first, CHG-1 and CHG-A
        # together, and lab-01 sorts before lab-02.
        record_the_change(
            self.repository,
            changes_of(
                timed("CHG-A", pair("lab-02"), pair("lab-01")),
                timed("CHG-1", pair("lab-02")),
                timed("CHG-0", pair("lab-01"), occurredAt=(T - HOUR).isoformat()),
            ),
        )

        outcome = self.record_gaps()

        self.assertEqual(
            [
                (dict(gap.source_metadata)["change.id"], gap.resource.resource_id)
                for gap in outcome.recorded
            ],
            [("CHG-0", "lab-01"), ("CHG-1", "lab-02"), ("CHG-A", "lab-01"), ("CHG-A", "lab-02")],
        )

    def test_the_stored_gaps_are_the_stateless_gaps_of_the_same_file(self) -> None:
        # A store keeps the digest of the file that first recorded each change, and this store
        # recorded the very file a stateless run reads, so the records are the same bytes.
        record_the_change(self.repository)

        outcome = self.record_gaps()

        self.assertEqual(
            [json.dumps(gap.to_canonical_dict(), sort_keys=True) for gap in outcome.recorded],
            [
                json.dumps(gap.to_canonical_dict(), sort_keys=True)
                for gap in stateless_gaps(CHANGE_SET)
            ],
        )

    def test_a_second_run_appends_nothing_and_names_every_gap_already_recorded(self) -> None:
        record_the_change(self.repository)
        first = self.record_gaps()
        latest = self.store.latest_sequence

        second = self.record_gaps()

        self.assertEqual(second.recorded, ())
        self.assertEqual(second.already_recorded, first.recorded)
        self.assertEqual(self.store.latest_sequence, latest)
        self.assertEqual(audit_history(self.repository), ())

    def test_the_first_recorded_payload_stands_against_an_edited_inventory(self) -> None:
        # The id names the resource, the change and the window close, never the inventory
        # digest, so a rebuild against an edited inventory finds every stream recorded.
        record_the_change(self.repository)
        self.record_gaps()
        latest = self.store.latest_sequence
        edited = inventory_named("change-tests-edited", host("lab-01"), host("lab-02"))
        self.assertNotEqual(edited.sha256, INVENTORY.sha256)

        outcome = self.record_gaps(edited)

        self.assertEqual(outcome.recorded, ())
        self.assertEqual(len(outcome.already_recorded), 2)
        self.assertEqual(self.store.latest_sequence, latest)
        for gap in outcome.already_recorded:
            head, record = self.repository.read_stream(change_gap_stream_id_of(gap))
            self.assertEqual(dict(gap.source_metadata)["change.inventorySha256"], edited.sha256)
            self.assertEqual(head.payload["inventorySha256"], INVENTORY.sha256)
            self.assertEqual(
                record.payload["source_metadata"]["change.inventorySha256"], INVENTORY.sha256
            )

    def test_a_later_as_of_records_only_the_windows_closed_since(self) -> None:
        record_the_change(
            self.repository,
            changes_of(
                timed("CHG-1", pair("lab-01")),
                timed("CHG-2", pair("lab-02"), detectBy=(T + 30 * HOUR).isoformat()),
            ),
        )
        early_as_of = T + 2 * HOUR
        early = self.record_gaps(as_of=early_as_of)
        self.assertEqual([gap.resource for gap in early.recorded], [LAB_01])

        late = self.record_gaps()

        self.assertEqual([gap.resource for gap in late.recorded], [LAB_02])
        self.assertEqual(
            [gap.observation_id for gap in late.already_recorded],
            [gap.observation_id for gap in early.recorded],
        )
        self.assertEqual(
            [gap.ingested_at for gap in recorded_gaps(self.repository)], [early_as_of, AS_OF]
        )

    def test_a_store_with_no_change_records_nothing_and_marks_nothing(self) -> None:
        # Lead call 10: nothing is read against the rule, so even a dataset without it passes.
        record_coverage(self.repository, gap_record())
        latest = self.store.latest_sequence
        for label, select in (
            ("the bundled policy", records_module.select_policy),
            ("a policy without the rule", stripped_policy("VDR-CSO-DAC")),
        ):
            with self.subTest(label):
                with mock.patch.object(records_module, "select_policy", select):
                    outcome = self.record_gaps()

                self.assertEqual((outcome.recorded, outcome.already_recorded), ((), ()))
                self.assertEqual(outcome.changes.obligations, ())
                self.assertEqual(self.store.latest_sequence, latest)
                self.assertEqual(self.store.schema_version, 4)

    def test_a_policy_without_the_rule_is_refused_and_nothing_is_appended(self) -> None:
        record_the_change(self.repository)
        latest = self.store.latest_sequence

        with (
            mock.patch.object(records_module, "select_policy", stripped_policy("VDR-CSO-DAC")),
            self.assertRaises(ReportCompileError) as caught,
        ):
            self.record_gaps()

        (diagnostic,) = caught.exception.diagnostics
        self.assertEqual(diagnostic.code, "change_rule_unavailable")
        self.assertEqual(self.store.latest_sequence, latest)
        self.assertEqual(self.store.schema_version, 5)

    def test_a_run_that_closes_no_window_records_nothing_and_leaves_the_schema(self) -> None:
        record_the_change(self.repository)
        latest = self.store.latest_sequence

        outcome = self.record_gaps(as_of=T + HOUR / 2)

        self.assertEqual((outcome.recorded, outcome.already_recorded), ((), ()))
        self.assertEqual(len(outcome.changes.obligations), 2)
        self.assertEqual(self.store.latest_sequence, latest)
        self.assertEqual(self.store.schema_version, 5)

    def test_a_gap_never_satisfies_its_own_obligation(self) -> None:
        # Read as evidence, a gap would be an OPEN record of the resource at the window close
        # and could close the very window it reports.
        record_the_change(self.repository)
        recorded = self.record_gaps().recorded
        stored = read_stored_changes(self.repository)
        assert stored is not None

        with_gaps = derive_changes(recorded, stored, INVENTORY, policy(), AS_OF)
        without = derive_changes((), stored, INVENTORY, policy(), AS_OF)

        self.assertEqual(with_gaps, without)
        self.assertEqual(change_gap_observations(with_gaps, ingested_at=AS_OF), recorded)

    def test_one_run_records_every_gap_or_none(self) -> None:
        record_the_change(self.repository)
        latest = self.store.latest_sequence
        real = EventRepository.append_batch
        calls: list[str] = []

        def append_batch(repository: EventRepository, stream_id: str, *args: Any, **kw: Any) -> Any:
            calls.append(stream_id)
            if len(calls) == 2:
                raise HistoryError("simulated failure on the second gap")
            return real(repository, stream_id, *args, **kw)

        with (
            mock.patch.object(EventRepository, "append_batch", append_batch),
            self.assertRaises(HistoryError),
        ):
            self.record_gaps()

        # One batch per stream, head and record together, so the second call is the second gap.
        self.assertEqual(len(set(calls)), 2)
        self.assertEqual(self.store.latest_sequence, latest)
        self.assertEqual(self.store.schema_version, 5)
        self.assertEqual(recorded_gaps(self.repository), [])

    def shapes(self) -> dict[str, Any]:
        """Each damaged shape of one gap's stream, as the events planted on it."""
        return {
            "the head alone": lambda gap: change_gap_events(gap)[:1],
            "the record alone": lambda gap: change_gap_events(gap)[1:],
            "the record first": lambda gap: change_gap_events(gap)[::-1],
            "a foreign event": lambda gap: [("probe.planted", {})],
            "a third event": lambda gap: [*change_gap_events(gap), ("probe.planted", {})],
        }

    def test_a_stream_holding_anything_but_its_head_and_record_is_refused(self) -> None:
        # Moved on purpose in task 4: `rehydrate_observations` now reads every change gap
        # stream, so the fold refuses each shape with the audit's text before the writer judges
        # it, and nothing is appended.
        for label, events in self.shapes().items():
            with self.subTest(label):
                self.setUp()
                record_the_change(self.repository)
                first = gap_of(derived_gaps(self.repository), LAB_02)
                stream_id = change_gap_stream_id_of(first)
                staged = events(first)
                self.stage(stream_id, staged, requires_schema=CHANGE_GAP_STREAM_SCHEMA_VERSION)
                latest = self.store.latest_sequence
                expected = {
                    "the head alone": shape_message(stream_id, "incomplete", 1, 0),
                    "the record alone": shape_message(stream_id, "incomplete", 0, 1),
                    "the record first": change_gap_head_order_message(stream_id),
                    "a foreign event": (
                        f"event 'probe.planted' does not belong on stream {stream_id!r}"
                    ),
                    "a third event": (
                        f"event 'probe.planted' does not belong on stream {stream_id!r}"
                    ),
                }[label]

                with self.assertRaises(HistoryError) as caught:
                    self.record_gaps()

                self.assertEqual(str(caught.exception), expected)
                self.assertEqual(self.store.latest_sequence, latest)

    def test_the_writer_still_refuses_a_stream_it_would_resume(self) -> None:
        # Call 14: unreachable through the fold, which refuses each shape first; held here with
        # the fold's reader set aside, so the writer never resumes a stream on its own.
        for label, events in self.shapes().items():
            with self.subTest(label):
                self.setUp()
                record_the_change(self.repository)
                evidence = rehydrate_observations(self.repository)
                first = gap_of(derived_gaps(self.repository), LAB_02)
                stream_id = change_gap_stream_id_of(first)
                staged = events(first)
                self.stage(stream_id, staged, requires_schema=CHANGE_GAP_STREAM_SCHEMA_VERSION)
                latest = self.store.latest_sequence

                with (
                    mock.patch.object(
                        writers_module, "rehydrate_observations", return_value=evidence
                    ),
                    self.assertRaises(HistoryError) as caught,
                ):
                    self.record_gaps()

                self.assertEqual(
                    str(caught.exception),
                    f"change gap stream {stream_id!r} holds {len(staged)} event(s) and not its "
                    "change.gap_recorded head and then its gap record; a change gap stream is "
                    "written whole, so it is refused rather than resumed",
                )
                self.assertEqual(self.store.latest_sequence, latest)

    def test_a_change_id_holding_a_colon_and_a_space_is_recorded_whole(self) -> None:
        # Lead call 6: an id may hold `:` and spaces, and the head and its change stream name
        # the whole id, as the key does after its fixed two-part lead.
        change_id = "deploy:2026-09-01 web"
        record_the_change(self.repository, changes_of(timed(change_id, pair("lab-01"))))

        (gap,) = self.record_gaps().recorded

        head, _ = self.repository.read_stream(change_gap_stream_id_of(gap))
        self.assertEqual(head.payload["changeId"], change_id)
        self.assertEqual(head.payload["contextKey"], f"VDR-CSO-DAC:change:{change_id}")
        self.assertEqual(self.record_gaps().already_recorded, (gap,))

    def test_the_writer_refuses_an_instant_without_a_zone_and_a_foreign_inventory(self) -> None:
        with self.assertRaisesRegex(ValueError, "as_of must include a timezone"):
            self.record_gaps(as_of=datetime(2026, 9, 10))
        with self.assertRaisesRegex(TypeError, "inventory must be an Inventory"):
            self.record_gaps(object())
        self.assertEqual(self.store.latest_sequence, 0)


# *--- Command Line ---*


class ChangeGapCommandTests(PersistedStoreTestCase):
    """`cases changes --db --inventory --class --as-of [--calendar-tz] [--actor]`."""

    def cases_changes(self, *options: str, database: Path | None = None) -> tuple[int, str, str]:
        target = self.database if database is None else database
        return run(["cases", "changes", "--db", str(target), *options])

    def populate_changes(self, database: Path | None = None) -> None:
        """Ingest the timed artifacts and record the timed change file, as an operator does."""
        target = str(self.database if database is None else database)
        self.succeeds(["ingest", *TIMED_ARTIFACTS, "--db", target, "--as-of", TIMED_AS_OF])
        self.succeeds(
            ["changes", "record", "--db", target, "--changes", str(TIMED_CHANGES)]
            + ["--as-of", RECORDED_AT]
        )

    def schema_version(self, database: Path | None = None) -> int:
        with SQLiteEventStore(self.database if database is None else database) as store:
            return store.schema_version

    def stored(self, database: Path | None = None) -> list[Observation]:
        with SQLiteEventStore(self.database if database is None else database) as store:
            return recorded_gaps(EventRepository(store))

    def test_recording_gaps_exits_3_and_names_each_gap_and_its_change(self) -> None:
        self.populate_changes()

        code, out, err = self.cases_changes(*CHANGES_OPTIONS, "--actor", "golden")

        self.assertEqual(code, 3, msg=err)
        gaps = self.stored()
        self.assertEqual(
            out.splitlines(),
            [
                *(
                    f"{gap.observation_id}: recorded {window}"
                    for gap, window in zip(gaps, RECORDED_WINDOWS, strict=True)
                ),
                "recorded 2 change gap(s), skipped 0 already-recorded change gap(s)",
            ],
        )
        # The derivation's own warning, as a report of the same store prints it.
        self.assertIn("warning: change_precedes_expected_since: ", err)
        self.assertIn("CHG-2002", err)
        self.assertNotIn("error:", err)
        self.assertEqual(self.schema_version(), 6)
        actors = {
            record.metadata["actor"]
            for record in self.records()
            if is_change_gap_stream(record.stream_id)
        }
        self.assertEqual(actors, {"golden"})

    def test_the_recorded_gaps_are_the_records_the_stateless_run_derives(self) -> None:
        # The same evidence and the same change file, read without a store: the same records,
        # byte for byte, and one case per change with the tracking ids the golden publishes.
        self.populate_changes()
        self.assertEqual(self.cases_changes(*CHANGES_OPTIONS)[0], 3)
        as_of = datetime(2026, 9, 3, 12, tzinfo=UTC)
        with SQLiteEventStore(self.database) as store:
            evidence = rehydrate_observations(EventRepository(store))
        projection = derive_report_changes(
            evidence,
            load_changes(TIMED_CHANGES),
            load_inventory(TIMED_INVENTORY),
            CertificationProfile(CertificationClass.C, calendar_timezone="UTC"),
            as_of,
        )
        stateless = change_gap_observations(projection, ingested_at=as_of)

        stored = self.stored()
        self.assertEqual(
            [self.canonical(gap.to_canonical_dict()) for gap in stored],
            [self.canonical(gap.to_canonical_dict()) for gap in stateless],
        )
        self.assertEqual(
            sorted(group.tracking_id for group in group_open_observations(stored)),
            sorted(row[3] for row in CLOSED_ROWS),
        )

    def test_a_second_run_appends_nothing_exits_0_and_the_store_verifies(self) -> None:
        self.populate_changes()
        self.assertEqual(self.cases_changes(*CHANGES_OPTIONS)[0], 3)
        latest = self.latest_sequence()
        verified = self.succeeds(["store", "verify", "--db", str(self.database)])

        code, out, err = self.cases_changes(*CHANGES_OPTIONS)

        self.assertEqual(code, 0, msg=err)
        gaps = self.stored()
        self.assertEqual(
            out.splitlines(),
            [
                *(
                    f"{gap.observation_id}: already_recorded {window}"
                    for gap, window in zip(gaps, RECORDED_WINDOWS, strict=True)
                ),
                "recorded 0 change gap(s), skipped 2 already-recorded change gap(s)",
            ],
        )
        self.assertEqual(self.latest_sequence(), latest)
        self.assertEqual(self.succeeds(["store", "verify", "--db", str(self.database)]), verified)
        self.assertEqual(verified, (f"ok: {latest} event(s) verified\n", ""))

    def test_a_store_with_no_change_exits_0_appends_nothing_and_marks_nothing(self) -> None:
        self.succeeds(["ingest", *TIMED_ARTIFACTS, "--db", str(self.database), "--as-of", NOW_TEXT])
        latest = self.latest_sequence()
        version = self.schema_version()
        expected = (0, "recorded 0 change gap(s), skipped 0 already-recorded change gap(s)\n", "")

        self.assertEqual(self.cases_changes(*CHANGES_OPTIONS), expected)
        with mock.patch.object(records_module, "select_policy", stripped_policy("VDR-CSO-DAC")):
            self.assertEqual(self.cases_changes(*CHANGES_OPTIONS), expected)
        self.assertEqual(self.latest_sequence(), latest)
        self.assertEqual(self.schema_version(), version)

    def test_a_run_that_closes_no_window_exits_0_and_leaves_the_schema(self) -> None:
        self.populate_changes()
        latest = self.latest_sequence()

        code, out, err = self.cases_changes(
            "--class", "C", "--as-of", "2026-08-15T00:00:00Z", "--inventory", str(TIMED_INVENTORY)
        )

        self.assertEqual(
            (code, out),
            (0, "recorded 0 change gap(s), skipped 0 already-recorded change gap(s)\n"),
            msg=err,
        )
        self.assertEqual(self.latest_sequence(), latest)
        self.assertEqual(self.schema_version(), 5)

    def test_the_calendar_zone_is_accepted_and_moves_nothing(self) -> None:
        # A change window closes at an instant, so the zone the profile names moves no gap.
        other = self.workspace / "phoenix.db"
        self.populate_changes()
        self.populate_changes(other)

        utc = self.cases_changes(*CHANGES_OPTIONS)
        phoenix = self.cases_changes(
            *CHANGES_OPTIONS, "--calendar-tz", "America/Phoenix", database=other
        )

        self.assertEqual((utc[0], phoenix[0]), (3, 3), msg=phoenix[2])
        self.assertEqual(utc[1], phoenix[1])
        self.assertEqual(
            [gap.to_canonical_dict() for gap in self.stored()],
            [gap.to_canonical_dict() for gap in self.stored(other)],
        )

    def refused(self, argv: Sequence[str], line: str) -> None:
        self.populate_changes()
        latest = self.latest_sequence()

        code, out, err = self.cases_changes(*argv)

        self.assertEqual((code, out), (1, ""), msg=err)
        self.assertIn(line, err)
        self.assertEqual(self.latest_sequence(), latest)
        self.assertEqual(self.schema_version(), 5)

    def test_a_run_without_an_inventory_is_refused(self) -> None:
        self.refused(
            ["--class", "C", "--as-of", TIMED_AS_OF],
            "error: invalid_option: cases changes needs --inventory: a change names inventory "
            "resources, so its windows are read against an inventory",
        )

    def test_a_second_inventory_is_refused(self) -> None:
        self.refused(
            [*CHANGES_OPTIONS, "--inventory", str(TIMED_INVENTORY)],
            "error: invalid_option: cases changes takes one --inventory file, not 2",
        )

    def test_a_refused_inventory_file_is_refused_as_input(self) -> None:
        broken = self.workspace / "broken-inventory.json"
        broken.write_text("{", encoding="utf-8")
        self.refused(
            ["--class", "C", "--as-of", TIMED_AS_OF, "--inventory", str(broken)],
            "error: invalid_input: ",
        )

    def test_an_unreadable_as_of_is_refused_as_input(self) -> None:
        self.refused(
            ["--class", "C", "--as-of", "3 September", "--inventory", str(TIMED_INVENTORY)],
            "error: invalid_input: --as-of must be an RFC 3339 timestamp, got '3 September'",
        )

    def test_an_unknown_calendar_zone_is_refused_as_an_option(self) -> None:
        self.refused([*CHANGES_OPTIONS, "--calendar-tz", "Mars/Olympus"], "error: invalid_option:")

    def test_a_policy_without_the_rule_is_refused_and_writes_nothing(self) -> None:
        with mock.patch.object(records_module, "select_policy", stripped_policy("VDR-CSO-DAC")):
            self.refused(CHANGES_OPTIONS, RULE_UNAVAILABLE)

    def test_a_missing_store_is_refused_and_no_store_is_created(self) -> None:
        missing = self.workspace / "missing.db"

        code, out, err = self.cases_changes(*CHANGES_OPTIONS, database=missing)

        self.assertEqual((code, out), (1, ""))
        self.assertIn(f"error: store_missing: no event store at {str(missing)!r}", err)
        self.assertFalse(missing.exists())

    def test_the_store_and_the_class_and_the_as_of_are_required_and_kev_is_no_option(
        self,
    ) -> None:
        for dropped in ("--db", "--class", "--as-of"):
            with self.subTest(dropped=dropped):
                argv = ["cases", "changes", "--db", "x.db", *CHANGES_OPTIONS]
                index = argv.index(dropped)
                del argv[index : index + 2]

                with self.assertRaises(SystemExit) as caught:
                    run(argv)

                self.assertEqual(caught.exception.code, 2)
        # KEV never moves a status or a window, so the command reads no catalog.
        with self.assertRaises(SystemExit) as caught:
            run(["cases", "changes", "--db", "x.db", *CHANGES_OPTIONS, "--kev", "kev.json"])
        self.assertEqual(caught.exception.code, 2)

    def test_a_change_id_holding_a_colon_and_a_space_is_named_whole(self) -> None:
        change_id = "deploy:2026-09-01 web"
        inventory = write_inventory(self.workspace, host("lab-01"))
        changes = self.workspace / "colon-changes.json"
        changes.write_text(
            json.dumps(change_file(timed(change_id, pair("lab-01")), name="colon-changes")),
            encoding="utf-8",
        )
        SQLiteEventStore(self.database).close()
        self.succeeds(["changes", "record", "--db", str(self.database), "--changes", str(changes)])

        code, out, err = self.cases_changes(
            "--class", "B", "--as-of", "2026-09-10T00:00:00Z", "--inventory", str(inventory)
        )

        self.assertEqual(code, 3, msg=err)
        (gap,) = self.stored()
        self.assertEqual(
            out.splitlines(),
            [
                f"{gap.observation_id}: recorded VDR-CSO-DAC window for host:lab-01 after change "
                f"{change_id} closed {DETECT_BY_TEXT}",
                "recorded 1 change gap(s), skipped 0 already-recorded change gap(s)",
            ],
        )

    def test_help_states_what_the_command_records(self) -> None:
        text = help_text(["cases", "changes"])

        self.assertIn(
            "record each change window that closed with no verification as a VDR-CSO-FAV "
            "system record; exits 3 when one is recorded",
            text,
        )
        self.assertIn("(read locally, never stored)", text)
        self.assertIn(
            "IANA calendar of the profile; a change window closes at an instant, so no gap "
            "depends on it (default: UTC)",
            text,
        )
        self.assertIn("changes", help_text(["cases"]))

    def test_an_older_build_refuses_the_store_cases_changes_marked(self) -> None:
        self.populate_changes()
        self.assertEqual(self.cases_changes(*CHANGES_OPTIONS)[0], 3)

        with mock.patch.object(sqlite_module, "SUPPORTED_SCHEMA_VERSION", 5):
            listing = run(["cases", "list", "--db", str(self.database)])
            verify = run(["store", "verify", "--db", str(self.database)])

        self.assertEqual(listing[:2], (1, ""))
        self.assertIn(
            "error: store_unavailable: database schema 6 is newer than supported schema 5",
            listing[2],
        )
        self.assertEqual(verify[0], 1)
        self.assertIn(
            "schema_version_unsupported: database is marked schema 6; this build opens "
            "schemas 1 to 5",
            verify[1] + verify[2],
        )


# *--- Store Verify ---*


class ChangeGapStoreVerifyCommandTests(PersistedStoreTestCase):
    """`store verify` names each change gap fault and exits 1; every reader refuses it by name.

    Each shape is planted past the repository in the timed store, which recorded its change
    file and no gap. A refusal is `history_invalid` on every command that reads the store,
    never an uncaught exception (call 11).
    """

    populate_changes = ChangeGapCommandTests.populate_changes
    cases_changes = ChangeGapCommandTests.cases_changes

    def setUp(self) -> None:
        super().setUp()
        self.populate_changes()
        with SQLiteEventStore(self.database) as store:
            repository = EventRepository(store)
            stored = read_stored_changes(repository)
            assert stored is not None
            projection = derive_report_changes(
                rehydrate_observations(repository),
                stored,
                load_inventory(TIMED_INVENTORY),
                CertificationProfile(CertificationClass.C, calendar_timezone="UTC"),
                datetime(2026, 9, 3, 12, tzinfo=UTC),
            )
        self.image, self.render = change_gap_observations(
            projection, ingested_at=datetime(2026, 9, 3, 12, tzinfo=UTC)
        )
        self.stream_id = change_gap_stream_id_of(self.image)
        self.head, self.observation = change_gap_events(self.image)

    def smuggle(
        self,
        events: Sequence[tuple[str, Mapping[str, Any]]],
        stream_id: str | None = None,
        *,
        requires_schema: int = CHANGE_GAP_STREAM_SCHEMA_VERSION,
    ) -> list[int]:
        """Append events to one new stream straight to the store, past the repository."""
        sequences = []
        with SQLiteEventStore(self.database) as store:
            for version, (event_type, payload) in enumerate(events):
                (appended,) = store.append(
                    self.stream_id if stream_id is None else stream_id,
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

    def assert_one_fault(self, sequence: int, code: str, message: str) -> None:
        code_seen, out, err = run(["store", "verify", "--db", str(self.database)])

        self.assertEqual((code_seen, out), (1, ""), msg=err)
        (line, summary) = err.splitlines()
        self.assertTrue(line.startswith(f"error: sequence {sequence}: {code}: "), msg=line)
        self.assertIn(message, line)
        self.assertTrue(summary.startswith("faults: 1 domain fault(s) in"), msg=summary)

    def assert_refused_everywhere(self, message: str) -> None:
        """Every command that reads the store's observations refuses it, naming the fault."""
        timed_report = [
            "report",
            "vdt",
            "--db",
            str(self.database),
            "--class",
            "C",
            "--package-uri",
            "https://example.test/cpo",
            "--as-of",
            TIMED_AS_OF,
            "--from",
            "2026-09-01T00:00:00Z",
            "--to",
            "2026-09-30T23:59:59Z",
            "--inventory",
            str(TIMED_INVENTORY),
        ]
        latest = self.latest_sequence()
        for label, argv in (
            ("report vdt", timed_report),
            ("cases changes", ["cases", "changes", "--db", str(self.database), *CHANGES_OPTIONS]),
            ("cases correlate", ["cases", "correlate", "--db", str(self.database)]),
            (
                "changes pending",
                ["changes", "pending", "--db", str(self.database), *CHANGES_OPTIONS],
            ),
        ):
            with self.subTest(label):
                code, out, err = run(argv)
                self.assertEqual((code, out), (1, ""), msg=err)
                self.assertIn("error: history_invalid: ", err)
                self.assertIn(message, err)
                self.assertNotIn("Traceback", err)
        self.assertEqual(self.latest_sequence(), latest)

    def test_whole_change_gap_streams_verify_and_their_gaps_reach_the_report(self) -> None:
        self.assertEqual(self.cases_changes(*CHANGES_OPTIONS)[0], 3)

        out, err = self.succeeds(["store", "verify", "--db", str(self.database)])

        self.assertEqual((out, err), (f"ok: {self.latest_sequence()} event(s) verified\n", ""))
        self.succeeds(["cases", "correlate", "--db", str(self.database)])
        listing, _ = self.succeeds(["cases", "list", "--db", str(self.database)])
        for row in CLOSED_ROWS:
            self.assertIn(row[3], listing)

    def test_a_change_gap_stream_missing_its_record_is_named_and_refused(self) -> None:
        sequences = self.smuggle([self.head])
        message = shape_message(self.stream_id, "incomplete", 1, 0)

        self.assert_one_fault(sequences[0], "changegap_incomplete", message)
        self.assert_refused_everywhere(message)

    def test_a_change_gap_stream_with_a_second_record_is_named_and_refused(self) -> None:
        sequences = self.smuggle([self.head, self.observation, self.observation])
        message = shape_message(self.stream_id, "overfull", 1, 2)

        self.assert_one_fault(sequences[0], "changegap_overfull", message)
        self.assert_refused_everywhere(message)

    def test_another_gaps_record_on_a_change_gap_stream_is_named_and_refused(self) -> None:
        sequences = self.smuggle(change_gap_events(self.render))
        message = (
            f"is the gap record of stream {change_gap_stream_id_of(self.render)!r}; a change gap "
            "stream is named for its gap record's fingerprint"
        )

        self.assert_one_fault(sequences[1], "changegap_stream_mismatch", message)
        self.assert_refused_everywhere(message)

    def test_a_change_gap_record_with_a_metadata_key_dropped_is_named_and_refused(self) -> None:
        sequences = self.smuggle(
            [self.head, ("observation.recorded", with_metadata(self.image, change_basis=None))]
        )
        message = "its metadata has no 'change.basis'"

        self.assert_one_fault(sequences[1], "changegap_identity_breach", message)
        self.assert_refused_everywhere(message)

    def test_a_gap_of_a_change_the_store_never_recorded_is_named_and_refused(self) -> None:
        # Call 11: nothing but a write past the repository leaves one, and each reader names it
        # rather than ending in an uncaught exception.
        orphan = gap_of(stateless_gaps(changes_of(timed("CHG-9", pair("lab-01")))))
        stream_id = change_gap_stream_id_of(orphan)
        sequences = self.smuggle(change_gap_events(orphan), stream_id)
        message = (
            f"change gap stream {stream_id!r} records change id 'CHG-9' in its "
            "change.gap_recorded, and no change stream records that change"
        )

        self.assert_one_fault(sequences[0], "changegap_stream_mismatch", message)
        self.assert_refused_everywhere(message)

    def test_a_store_holding_gaps_and_no_change_is_named_and_refused(self) -> None:
        # P M13: a change-gap-aware report of this store would have no block to map; the
        # reader refuses it first, by name.
        self.database = self.workspace / "no-change.db"
        self.succeeds(["ingest", *TIMED_ARTIFACTS, "--db", str(self.database), "--as-of", NOW_TEXT])
        sequences = self.smuggle([self.head, self.observation])

        self.assert_one_fault(
            sequences[0],
            "changegap_stream_mismatch",
            "records change id 'CHG-2001' in its change.gap_recorded, and no change stream "
            "records that change",
        )
        self.assert_refused_everywhere("and no change stream records that change")

    def test_a_change_gap_stream_in_a_store_left_at_schema_5_is_named_and_exits_one(
        self,
    ) -> None:
        sequences = self.smuggle([self.head, self.observation], requires_schema=5)

        self.assert_one_fault(
            sequences[0],
            "changegap_schema_unmarked",
            f"change gap stream {self.stream_id!r} is in a store at schema 5",
        )
        # No reader refuses it: the report reads the gap as the writer would have recorded it.
        code, _out, err = run(["cases", "correlate", "--db", str(self.database)])
        self.assertEqual(code, 0, msg=err)


if __name__ == "__main__":
    unittest.main()
