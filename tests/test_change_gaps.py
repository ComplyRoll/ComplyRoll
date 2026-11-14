# ******************************************************************************
# *Title: Change Gap Tests*
# *Author: Kyle Versluis*
# *Description: Unit tests for the change detection gap observation builder.*
# ******************************************************************************
"""Tests for change gaps: one SYSTEM observation per closed change window (ADR 0018, PR 3)."""

# *--- Imports ---*

from __future__ import annotations

import dataclasses
import importlib
import importlib.util
import json
import unittest
from collections.abc import Sequence
from datetime import UTC, datetime, timedelta, timezone
from typing import Any

from test_changes import (
    AS_OF,
    DAY,
    GROUP_PAIR,
    HOUR,
    INGESTED_AT,
    SECOND,
    T,
    catalog,
    change,
    changes_of,
    host,
    inventory_of,
    observation,
    pair,
    policy,
    procedure,
)
from test_coverage_gap_evaluations import minted_reserved_types

from complyroll.adapters import DETECTION_FAILURE_SOURCE_TYPE
from complyroll.correlation import group_open_observations, tracking_id_for
from complyroll.models import (
    RESERVED_SOURCE_TYPE_PREFIX,
    Observation,
    ObservationDisposition,
    ObservationOrigin,
    ResourceRef,
    SourceSeverity,
)
from complyroll.policy import RuleForce, SelectedPolicy
from complyroll.reports import checks as checks_module
from complyroll.reports import markdown as markdown_module
from complyroll.reports import parse_changes, parse_inventory
from complyroll.reports.change_gaps import (
    CHANGE_GAP_BASIS_TEXTS,
    CHANGE_GAP_DESCRIPTION,
    CHANGE_GAP_METADATA_KEYS,
    CHANGE_GAP_PARSER_NAME,
    CHANGE_GAP_PARSER_VERSION,
    CHANGE_GAP_RECORD_ID,
    CHANGE_GAP_RULE,
    CHANGE_GAP_SOURCE_TOOL,
    CHANGE_GAP_SOURCE_TYPE,
    CHANGE_GAP_TITLE,
    change_gap_change_id,
    change_gap_context_key,
    change_gap_observation,
    change_gap_observations,
)
from complyroll.reports.changes import (
    CHANGE_BASIS,
    DAC_RULE,
    ChangeObligation,
    ChangeProjection,
    ObligationStatus,
    StoredChangeSet,
    derive_changes,
)
from complyroll.reports.changes_input import ChangeSet
from complyroll.reports.gaps import COVERAGE_GAP_SOURCE_TYPE
from complyroll.reports.inventory import Inventory

# *--- Fixtures ---*

#: The window every default change below states: one hour after it occurred.
DETECT_BY = T + HOUR
DETECT_BY_TEXT = "2026-09-01T13:00:00Z"
OCCURRED_TEXT = "2026-09-01T12:00:00Z"
GROUP_REF = ResourceRef("sample-group/web", "logical")
LAB_01 = ResourceRef("lab-01", "host")
LAB_02 = ResourceRef("lab-02", "host")
TEN_KEYS = [
    "change.basis",
    "change.changesSha256",
    "change.detectBy",
    "change.force",
    "change.id",
    "change.inventorySha256",
    "change.job",
    "change.kind",
    "change.occurredAt",
    "change.rule",
]
#: Decision 12's remedy, as an order refusal prints it after the detection time.
CHANGE_REMEDY = (
    "a change detection gap is detected when its window closed, so evaluate it at or after "
    "that instant, or correct completedAt"
)


def timed(change_id: str = "CHG-1", *resources: dict[str, str], **fields: Any) -> dict[str, Any]:
    """Return a change whose window closes at DETECT_BY unless the fields say otherwise."""
    return change(change_id, *resources, **{"detectBy": DETECT_BY.isoformat(), **fields})


def changes_named(name: str, *changes: dict[str, Any]) -> ChangeSet:
    """Read a change file whose name, and so its digest, differs from changes_of's."""
    document = {
        "schema": "complyroll.changes",
        "schemaVersion": 1,
        "name": name,
        "changes": list(changes),
    }
    return parse_changes(json.dumps(document).encode("utf-8"))


def inventory_named(name: str, *entries: dict[str, Any]) -> Inventory:
    """Read an inventory whose name, and so its digest, differs from inventory_of's."""
    document = {
        "schema": "complyroll.inventory",
        "schemaVersion": 1,
        "name": name,
        "resources": list(entries),
    }
    return parse_inventory(json.dumps(document).encode("utf-8"))


def project(
    entries: Sequence[dict[str, Any]],
    changes: Sequence[dict[str, Any]] | ChangeSet | StoredChangeSet,
    evidence: Sequence[Observation] = (),
    as_of: datetime = AS_OF,
    *,
    inventory: Inventory | None = None,
    selected: SelectedPolicy | None = None,
) -> ChangeProjection:
    change_set = (
        changes if isinstance(changes, ChangeSet | StoredChangeSet) else changes_of(*changes)
    )
    return derive_changes(
        evidence,
        change_set,
        inventory if inventory is not None else inventory_of(*entries),
        selected or policy(),
        as_of,
    )


def row_of(
    projection: ChangeProjection, change_id: str = "CHG-1", resource: ResourceRef = LAB_01
) -> ChangeObligation:
    (row,) = [
        item
        for item in projection.obligations
        if item.change.change_id == change_id and item.resource == resource
    ]
    return row


def gap(
    projection: ChangeProjection,
    change_id: str = "CHG-1",
    resource: ResourceRef = LAB_01,
    *,
    ingested_at: datetime = INGESTED_AT,
) -> Observation:
    return change_gap_observation(
        row_of(projection, change_id, resource), projection=projection, ingested_at=ingested_at
    )


def lapsed_pair() -> ChangeProjection:
    """One change naming two hosts, neither verified before its window closed."""
    return project(
        [host("lab-01"), host("lab-02")], [timed("CHG-1", pair("lab-01"), pair("lab-02"))]
    )


def with_force(force: RuleForce) -> SelectedPolicy:
    """Return the bundled policy with VDR-CSO-DAC rewritten to another force."""
    rules = tuple(
        dataclasses.replace(rule, force=force) if rule.rule_id == DAC_RULE else rule
        for rule in policy().rules
    )
    return dataclasses.replace(policy(), rules=rules)


# *--- Constants ---*


class ChangeGapConstantsTests(unittest.TestCase):
    """The identity constants mirror the coverage gap's, under their own reserved type."""

    def test_the_source_type_carries_the_reserved_prefix(self) -> None:
        self.assertTrue(CHANGE_GAP_SOURCE_TYPE.startswith(RESERVED_SOURCE_TYPE_PREFIX))
        self.assertNotEqual(CHANGE_GAP_SOURCE_TYPE, COVERAGE_GAP_SOURCE_TYPE)

    def test_the_constants_are_pinned(self) -> None:
        self.assertEqual(
            (
                CHANGE_GAP_SOURCE_TYPE,
                CHANGE_GAP_SOURCE_TOOL,
                CHANGE_GAP_PARSER_NAME,
                CHANGE_GAP_PARSER_VERSION,
                CHANGE_GAP_RECORD_ID,
                CHANGE_GAP_RULE,
            ),
            (
                "complyroll.change",
                "complyroll",
                "complyroll.change",
                "1",
                "change-detection-gap",
                "VDR-CSO-FAV",
            ),
        )

    def test_the_metadata_key_set_is_the_ten_keys_sorted(self) -> None:
        self.assertEqual(list(CHANGE_GAP_METADATA_KEYS), TEN_KEYS)
        self.assertEqual(TEN_KEYS, sorted(TEN_KEYS))

    def test_the_basis_texts_hold_the_block_basis(self) -> None:
        self.assertEqual(CHANGE_GAP_BASIS_TEXTS, (CHANGE_BASIS,))

    def test_the_title_template_names_the_change_and_the_rule(self) -> None:
        self.assertEqual(
            CHANGE_GAP_TITLE,
            "{rule} window for {resource_type}:{resource_id} after change {change_id} closed "
            "{closed_at} with no verification recorded (VDR-CSO-FAV)",
        )


# *--- Which Windows ---*


class ChangeGapWindowTests(unittest.TestCase):
    """A gap is built for every row whose window closed, keyed on the field, not the status."""

    def test_one_gap_per_closed_window_in_obligation_order(self) -> None:
        projection = project(
            [host("lab-01"), host("lab-02"), host("lab-03"), host("lab-04")],
            [
                timed("CHG-1", pair("lab-02"), pair("lab-01")),
                # Late: verified after its window closed.
                timed(
                    "CHG-2",
                    pair("lab-03"),
                    occurredAt=(T + DAY).isoformat(),
                    detectBy=(T + DAY + HOUR).isoformat(),
                ),
                # On time: no window closed.
                timed("CHG-3", pair("lab-04")),
                # No window at all.
                change("CHG-4", pair("lab-01"), occurredAt=(T + 2 * DAY).isoformat()),
            ],
            [
                observation("lab-03", at=T + DAY + 2 * HOUR),
                observation("lab-04", at=T + HOUR - SECOND),
            ],
        )
        closed = [row for row in projection.obligations if row.window_closed_at is not None]
        built = change_gap_observations(projection, ingested_at=INGESTED_AT)

        self.assertIsInstance(built, tuple)
        self.assertEqual(
            [(row.change.change_id, row.resource) for row in closed],
            [
                ("CHG-1", LAB_01),
                ("CHG-1", LAB_02),
                ("CHG-2", ResourceRef("lab-03", "host")),
            ],
        )
        self.assertEqual(
            built,
            tuple(
                change_gap_observation(row, projection=projection, ingested_at=INGESTED_AT)
                for row in closed
            ),
        )
        self.assertEqual(
            [(item.resource, item.observed_at) for item in built],
            [(row.resource, row.window_closed_at) for row in closed],
        )
        self.assertEqual(
            [item.metadata_value("change.id") for item in built], ["CHG-1", "CHG-1", "CHG-2"]
        )

    def test_no_gap_for_a_row_whose_window_did_not_close(self) -> None:
        cases: dict[str, tuple[list[dict[str, Any]], dict[str, Any], list[Observation]]] = {
            "pending": ([host()], change(), []),
            "pending before its window closes": (
                [host()],
                change(detectBy=(AS_OF + DAY).isoformat()),
                [],
            ),
            "pending when the window closes at as-of": (
                [host()],
                change(detectBy=AS_OF.isoformat()),
                [],
            ),
            "undetermined": (
                [host()],
                change(detectBy=(AS_OF + DAY).isoformat()),
                [observation(at=T + HOUR, disposition=ObservationDisposition.ERROR)],
            ),
            "logged": ([host()], timed(significant=False), []),
            "retired": ([host(decommissionedAt=(T - SECOND).isoformat())], timed(), []),
            "retired inside the window": (
                [host(decommissionedAt=(T + HOUR - SECOND).isoformat())],
                timed(),
                [],
            ),
            "unregistered": ([host()], timed("CHG-1", pair("elsewhere")), []),
            "detected on time": ([host()], timed(), [observation(at=T + HOUR - SECOND)]),
            "detected at the close": ([host()], timed(), [observation(at=DETECT_BY)]),
        }
        expected = {
            "pending": ObligationStatus.PENDING,
            "pending before its window closes": ObligationStatus.PENDING,
            "pending when the window closes at as-of": ObligationStatus.PENDING,
            "undetermined": ObligationStatus.UNDETERMINED,
            "logged": ObligationStatus.LOGGED,
            "retired": ObligationStatus.RETIRED,
            "retired inside the window": ObligationStatus.RETIRED,
            "unregistered": ObligationStatus.UNREGISTERED,
            "detected on time": ObligationStatus.DETECTED,
            "detected at the close": ObligationStatus.DETECTED,
        }
        for label, (entries, declared, evidence) in cases.items():
            with self.subTest(label):
                projection = project(entries, [declared], evidence)
                (row,) = projection.obligations
                self.assertIs(row.status, expected[label])
                self.assertIsNone(row.window_closed_at)
                self.assertEqual(change_gap_observations(projection, ingested_at=INGESTED_AT), ())
                with self.assertRaisesRegex(ValueError, "window did not close"):
                    change_gap_observation(row, projection=projection, ingested_at=INGESTED_AT)

    def test_a_late_detection_builds_one(self) -> None:
        projection = project([host()], [timed()], [observation(at=DETECT_BY + SECOND)])
        (row,) = projection.obligations
        self.assertIs(row.status, ObligationStatus.DETECTED)
        self.assertIs(row.late, True)

        (built,) = change_gap_observations(projection, ingested_at=INGESTED_AT)
        self.assertEqual(built.observed_at, DETECT_BY)
        self.assertEqual(built.resource, LAB_01)

    def test_a_lapsed_row_of_a_resource_decommissioned_later_builds_one(self) -> None:
        projection = project([host(decommissionedAt=(T + 2 * HOUR).isoformat())], [timed()])
        (row,) = projection.obligations
        self.assertIs(row.status, ObligationStatus.LAPSED)
        self.assertIs(row.decommissioned, True)
        # The request leaves the row out; the gap still records the window.
        self.assertEqual(projection.waiting, ())

        (built,) = change_gap_observations(projection, ingested_at=INGESTED_AT)
        self.assertEqual(built.observed_at, DETECT_BY)

    def test_a_window_that_closes_as_the_change_occurs(self) -> None:
        # The window is [occurredAt, detectBy], closed at both ends, so it may be one instant.
        lapsed = project([host()], [timed(detectBy=T.isoformat())])
        (built,) = change_gap_observations(lapsed, ingested_at=INGESTED_AT)
        self.assertEqual(built.observed_at, T)
        self.assertEqual(built.metadata_value("change.occurredAt"), OCCURRED_TEXT)
        self.assertEqual(built.metadata_value("change.detectBy"), OCCURRED_TEXT)
        self.assertIn(f" closed {OCCURRED_TEXT} ", built.title)

        verified = project([host()], [timed(detectBy=T.isoformat())], [observation(at=T)])
        self.assertIs(verified.obligations[0].status, ObligationStatus.DETECTED)
        self.assertEqual(change_gap_observations(verified, ingested_at=INGESTED_AT), ())


# *--- Identity ---*


class ChangeGapIdentityTests(unittest.TestCase):
    """The id moves with the resource, the change id and detectBy, and nothing else."""

    def test_the_same_row_builds_the_same_observation(self) -> None:
        projection = lapsed_pair()
        first, second = gap(projection), gap(projection)

        self.assertEqual(first, second)
        self.assertEqual(first.observation_id, first.derived_observation_id)
        self.assertTrue(first.observation_id.startswith("obs-"))

    def test_the_id_holds_across_as_of_and_ingest_time(self) -> None:
        verified = observation(at=AS_OF + DAY)
        early = project([host()], [timed()], [verified])
        late = project([host()], [timed()], [verified], AS_OF + 2 * DAY)
        # Before the verification the row has lapsed; after it, it was detected late.
        self.assertIs(early.obligations[0].status, ObligationStatus.LAPSED)
        self.assertIs(late.obligations[0].late, True)

        before, after = gap(early), gap(late)
        self.assertEqual(before, after)
        for moment in (T, AS_OF, INGESTED_AT + timedelta(days=400)):
            with self.subTest(ingested_at=moment):
                moved = gap(late, ingested_at=moment)
                self.assertEqual(moved.observation_id, before.observation_id)
                self.assertEqual(moved.ingested_at, moment)

    def test_the_id_ignores_both_digests_the_job_the_kind_and_occurred_at(self) -> None:
        base = gap(project([host()], [timed()]))
        variants = {
            "another change file": project([host()], changes_named("another-file", timed())),
            "another inventory": project(
                [], [timed()], inventory=inventory_named("another-inventory", host())
            ),
            "a job": project([host()], [timed(job="nightly-openscap")]),
            "a created kind": project([host()], [timed(kind="created", significant=False)]),
            "an earlier occurredAt": project([host()], [timed(occurredAt=(T - DAY).isoformat())]),
            "another force": project([host()], [timed()], selected=with_force(RuleForce.MUST)),
        }
        moved = {
            "another change file": "change.changesSha256",
            "another inventory": "change.inventorySha256",
            "a job": "change.job",
            "a created kind": "change.kind",
            "an earlier occurredAt": "change.occurredAt",
            "another force": "change.force",
        }
        for label, projection in variants.items():
            with self.subTest(label):
                built = gap(projection)
                self.assertEqual(built.observation_id, base.observation_id)
                self.assertNotEqual(
                    built.metadata_value(moved[label]), base.metadata_value(moved[label])
                )

    def test_the_id_moves_with_the_resource_the_change_id_and_detect_by(self) -> None:
        base = gap(lapsed_pair())
        cases = {
            "another resource of the change": gap(lapsed_pair(), "CHG-1", LAB_02),
            "another change id": gap(project([host()], [timed("CHG-9")]), "CHG-9"),
            "another detectBy": gap(
                project([host()], [timed(detectBy=(T + 2 * HOUR).isoformat())])
            ),
        }
        ids = [base.observation_id, *(item.observation_id for item in cases.values())]
        self.assertEqual(len(set(ids)), len(ids))

    def test_ids_are_distinct_across_resources_and_across_changes(self) -> None:
        projection = project(
            [host("lab-01"), host("lab-02")],
            [
                timed("CHG-1", pair("lab-01"), pair("lab-02")),
                timed("CHG-2", pair("lab-01")),
            ],
        )
        built = change_gap_observations(projection, ingested_at=INGESTED_AT)
        self.assertEqual(len(built), 3)
        self.assertEqual(len({item.observation_id for item in built}), 3)
        # CHG-1 and CHG-2 share lab-01 and the close; only the change id tells them apart.
        one, two = gap(projection, "CHG-1"), gap(projection, "CHG-2")
        self.assertEqual((one.resource, one.observed_at), (two.resource, two.observed_at))
        self.assertNotEqual(one.observation_id, two.observation_id)


# *--- Context Key ---*


class ChangeGapContextKeyTests(unittest.TestCase):
    """One case per change: `VDR-CSO-DAC:change:<changeId>`, parsed with `split(":", 2)`."""

    def test_the_key_names_the_rule_and_the_change(self) -> None:
        built = gap(project([host()], [timed(job="nightly-openscap")]))
        self.assertEqual(built.context_key, "VDR-CSO-DAC:change:CHG-1")
        self.assertEqual(change_gap_context_key("CHG-1"), "VDR-CSO-DAC:change:CHG-1")
        self.assertEqual(change_gap_change_id(built.context_key), "CHG-1")
        # A job never moves the key: the change is the sharper scope.
        self.assertEqual(built.metadata_value("change.job"), "nightly-openscap")

    def test_an_id_with_a_colon_or_a_space_round_trips(self) -> None:
        for change_id in ("deploy:2026-09-01:web", "release 42", "a: b"):
            with self.subTest(change_id=change_id):
                built = gap(project([host()], [timed(change_id)]), change_id)
                self.assertEqual(built.context_key, f"VDR-CSO-DAC:change:{change_id}")
                self.assertEqual(change_gap_change_id(built.context_key), change_id)
                self.assertEqual(built.metadata_value("change.id"), change_id)
                # The rule lead every existing reader takes still reads the rule.
                self.assertEqual(built.context_key.split(":", 1)[0], DAC_RULE)

    def test_a_key_that_is_not_ours_parses_to_none(self) -> None:
        for key in (
            "",
            "VDR-CSO-DAC",
            "VDR-CSO-DAC:change",
            "VDR-CSO-DAC:change:",
            "VDR-CSO-DAC:resource:host:lab-01",
            "VDR-TFR-MVX:change:CHG-1",
            "VDR-TFR-MVX:job:nightly",
            "vdr-cso-dac:change:CHG-1",
        ):
            with self.subTest(key=key):
                self.assertIsNone(change_gap_change_id(key))

    def test_the_key_functions_refuse_what_they_cannot_spell(self) -> None:
        with self.assertRaisesRegex(TypeError, "change_id must be text"):
            change_gap_context_key(1)  # type: ignore[arg-type]
        with self.assertRaisesRegex(ValueError, "change_id must not be empty"):
            change_gap_context_key("")
        with self.assertRaisesRegex(TypeError, "context_key must be text"):
            change_gap_change_id(None)  # type: ignore[arg-type]

    def test_a_group_row_keeps_the_group_resource_and_the_change_key(self) -> None:
        members = [host("web-1", sampleGroup="web"), host("web-2", sampleGroup="web")]
        projection = project(members, [timed("CHG-1", GROUP_PAIR)])
        row = row_of(projection, resource=GROUP_REF)
        self.assertIs(row.status, ObligationStatus.LAPSED)
        self.assertEqual(row.sample_group, "web")

        built = gap(projection, resource=GROUP_REF)
        self.assertEqual(built.resource, GROUP_REF)
        self.assertEqual(built.context_key, "VDR-CSO-DAC:change:CHG-1")
        # The group's evidence is read under PSD; the gap still states the change's rule.
        self.assertEqual(built.metadata_value("change.rule"), DAC_RULE)
        self.assertEqual(
            built.title,
            "VDR-CSO-DAC window for logical:sample-group/web after change CHG-1 closed "
            f"{DETECT_BY_TEXT} with no verification recorded (VDR-CSO-FAV)",
        )

    def test_an_entry_spelled_like_the_group_is_its_own_row(self) -> None:
        # An entry literally spelled like the group wins over the group (ADR 0018 matching).
        twin = procedure("sample-group/web", job="manual-review")
        members = [host("web-1", sampleGroup="web"), twin]
        projection = project(members, [timed("CHG-1", GROUP_PAIR)])
        row = row_of(projection, resource=GROUP_REF)
        self.assertIsNotNone(row.entry)
        self.assertIsNone(row.sample_group)

        built = gap(projection, resource=GROUP_REF)
        self.assertEqual(built.context_key, "VDR-CSO-DAC:change:CHG-1")
        self.assertEqual(built.metadata_value("change.job"), "")


# *--- Record ---*


class ChangeGapRecordTests(unittest.TestCase):
    """Every field of the gap is fixed: nothing in it carries severity or a source artifact."""

    def test_the_metadata_is_exactly_the_ten_keys(self) -> None:
        projection = project(
            [host("lab-01"), host("lab-02")],
            [
                timed("CHG-1", pair("lab-01"), pair("lab-02")),
                timed("CHG-2", pair("lab-01"), kind="created", job="nightly-openscap"),
            ],
        )
        built = change_gap_observations(projection, ingested_at=INGESTED_AT)
        self.assertEqual(len(built), 3)
        for item in built:
            with self.subTest(change=item.metadata_value("change.id"), resource=item.resource):
                self.assertEqual([key for key, _ in item.source_metadata], TEN_KEYS)

        change_set = projection.change_set
        assert isinstance(change_set, ChangeSet)
        self.assertEqual(
            dict(gap(projection, "CHG-2").source_metadata),
            {
                "change.basis": CHANGE_BASIS,
                "change.changesSha256": change_set.sha256,
                "change.detectBy": DETECT_BY_TEXT,
                "change.force": "SHOULD",
                "change.id": "CHG-2",
                "change.inventorySha256": projection.inventory.sha256,
                "change.job": "nightly-openscap",
                "change.kind": "created",
                "change.occurredAt": OCCURRED_TEXT,
                "change.rule": DAC_RULE,
            },
        )
        self.assertEqual(gap(projection).metadata_value("change.job"), "")
        self.assertEqual(gap(projection).metadata_value("change.kind"), "modified")

    def test_the_force_is_the_projection_force(self) -> None:
        for force in (RuleForce.MUST, RuleForce.SHOULD):
            with self.subTest(force=force):
                projection = project([host()], [timed()], selected=with_force(force))
                self.assertIs(projection.force, force)
                self.assertEqual(gap(projection).metadata_value("change.force"), force.value)

    def test_the_fixed_fields(self) -> None:
        projection = lapsed_pair()
        built = gap(projection)
        change_set = projection.change_set
        assert isinstance(change_set, ChangeSet)

        self.assertIs(built.origin, ObservationOrigin.SYSTEM)
        self.assertIs(built.disposition, ObservationDisposition.OPEN)
        self.assertIs(built.source_severity, SourceSeverity.UNKNOWN)
        self.assertEqual(built.source_type, CHANGE_GAP_SOURCE_TYPE)
        self.assertEqual(built.source_tool, CHANGE_GAP_SOURCE_TOOL)
        self.assertEqual(
            (built.parser_name, built.parser_version),
            (CHANGE_GAP_PARSER_NAME, CHANGE_GAP_PARSER_VERSION),
        )
        self.assertEqual(built.source_record_id, CHANGE_GAP_RECORD_ID)
        self.assertEqual(built.resource, LAB_01)
        self.assertEqual(built.source_identifiers, ())
        self.assertEqual(built.source_artifact_digest, "")
        self.assertEqual(built.source_artifact_name, "")
        self.assertEqual(built.evidence_ids, (f"sha256:{change_set.sha256}",))
        self.assertEqual(built.ingested_at, INGESTED_AT)
        self.assertEqual(built.observed_at, DETECT_BY)
        self.assertIs(built.observed_at.tzinfo if built.observed_at else None, UTC)

    def test_the_title_and_description_texts(self) -> None:
        built = gap(lapsed_pair())
        self.assertEqual(
            built.title,
            "VDR-CSO-DAC window for host:lab-01 after change CHG-1 closed "
            f"{DETECT_BY_TEXT} with no verification recorded (VDR-CSO-FAV)",
        )
        self.assertEqual(
            built.description,
            "ComplyRoll recorded no verification of this resource between the change and the "
            "window close; this records the absence of a verification, not a vulnerability.",
        )
        self.assertEqual(built.description, CHANGE_GAP_DESCRIPTION)
        self.assertNotIn(CHANGE_GAP_RECORD_ID, built.title)

    def test_the_title_is_not_part_of_the_identity(self) -> None:
        built = gap(lapsed_pair())
        retitled = dataclasses.replace(built, title="change detection gap: another title")
        self.assertEqual(retitled.fingerprint, built.fingerprint)
        self.assertEqual(retitled.derived_observation_id, built.observation_id)

    def test_a_change_given_with_an_offset_is_stored_in_utc(self) -> None:
        # The reader converts to UTC; a change built in code may still carry an offset.
        declared = changes_of(timed())
        offset = timezone(timedelta(hours=-7))
        shifted = dataclasses.replace(
            declared.changes[0],
            occurred_at=T.astimezone(offset),
            detect_by=DETECT_BY.astimezone(offset),
        )
        projection = project([host()], dataclasses.replace(declared, changes=(shifted,)))
        (row,) = projection.obligations
        assert row.window_closed_at is not None
        self.assertEqual(row.window_closed_at.utcoffset(), timedelta(hours=-7))

        (built,) = change_gap_observations(projection, ingested_at=INGESTED_AT)
        self.assertIs(built.observed_at.tzinfo if built.observed_at else None, UTC)
        self.assertEqual(built.metadata_value("change.detectBy"), DETECT_BY_TEXT)
        self.assertEqual(built.metadata_value("change.occurredAt"), OCCURRED_TEXT)
        self.assertEqual(built, gap(project([host()], declared)))

    def test_the_canonical_form_round_trips(self) -> None:
        projection = lapsed_pair()
        offset = INGESTED_AT.astimezone(timezone(timedelta(hours=5, minutes=30)))
        for ingested_at in (INGESTED_AT, offset):
            for built in change_gap_observations(projection, ingested_at=ingested_at):
                with self.subTest(resource=built.resource, ingested_at=ingested_at):
                    canonical = built.to_canonical_dict()
                    rebuilt = Observation.from_canonical_dict(canonical)
                    self.assertEqual(rebuilt, built)
                    self.assertEqual(rebuilt.observation_id, rebuilt.derived_observation_id)


# *--- Stored Changes ---*


class ChangeGapStoredTests(unittest.TestCase):
    """A stored change set names each change by the digest of the file that recorded it."""

    def test_a_stored_change_set_uses_its_own_digest(self) -> None:
        stateless = changes_of(
            timed("CHG-1", pair("lab-01")),
            timed("CHG-2", pair("lab-01"), occurredAt=(T + SECOND).isoformat()),
        )
        digests = ("1" * 64, "2" * 64)
        stored = StoredChangeSet(
            changes=stateless.changes, names=("first-file", "second-file"), digests=digests
        )
        by_file = project([host()], stateless)
        by_store = project([host()], stored)

        for change_id, digest in zip(("CHG-1", "CHG-2"), digests, strict=True):
            with self.subTest(change_id=change_id):
                file_gap, store_gap = gap(by_file, change_id), gap(by_store, change_id)
                self.assertEqual(store_gap.metadata_value("change.changesSha256"), digest)
                self.assertEqual(store_gap.evidence_ids, (f"sha256:{digest}",))
                self.assertEqual(file_gap.metadata_value("change.changesSha256"), stateless.sha256)
                # Neither digest enters the id, so both paths mint the same one.
                self.assertEqual(store_gap.observation_id, file_gap.observation_id)
                self.assertEqual(
                    dataclasses.replace(
                        store_gap,
                        source_metadata=file_gap.source_metadata,
                        evidence_ids=file_gap.evidence_ids,
                    ),
                    file_gap,
                )


# *--- Examines Nothing ---*


class ChangeGapExaminesNothingTests(unittest.TestCase):
    """A gap records an absence, so feeding it back never changes the projection it came from."""

    def test_a_gap_never_satisfies_its_own_obligation(self) -> None:
        members = [host("web-1", sampleGroup="web"), host("web-2", sampleGroup="web")]
        entries = [host("lab-01"), host("lab-02"), *members]
        declared = changes_of(
            timed("CHG-1", pair("lab-01"), pair("lab-02"), GROUP_PAIR, kind="created"),
            timed("CHG-2", pair("lab-02"), occurredAt=(T + SECOND).isoformat()),
        )
        # lab-02 is verified after CHG-1's window closed: a late detection on both changes.
        evidence = [observation("lab-02", at=DETECT_BY + HOUR, identifiers=("CVE-2026-0001",))]
        inventory = inventory_of(*entries)
        for as_of in (DETECT_BY + SECOND, AS_OF):
            for kev in (None, catalog()):
                with self.subTest(as_of=as_of, kev=kev is not None):
                    projection = derive_changes(
                        evidence, declared, inventory, policy(), as_of, kev_catalog=kev
                    )
                    gaps = change_gap_observations(projection, ingested_at=INGESTED_AT)
                    self.assertEqual(len(gaps), 4)
                    # Each gap sits on its own resource at its window's close, where a
                    # verification would count.
                    again = derive_changes(
                        [*evidence, *gaps], declared, inventory, policy(), as_of, kev_catalog=kev
                    )
                    self.assertEqual(again, projection)
                    self.assertEqual(again.to_dict(), projection.to_dict())


# *--- Correlation ---*


class ChangeGapCorrelationTests(unittest.TestCase):
    """Every closed window of one change is one SYSTEM case; two changes are two."""

    def test_the_resources_of_one_change_are_one_case(self) -> None:
        built = change_gap_observations(lapsed_pair(), ingested_at=INGESTED_AT)
        (group,) = group_open_observations(built)

        self.assertEqual(
            group.tracking_id,
            tracking_id_for(
                CHANGE_GAP_SOURCE_TYPE, CHANGE_GAP_RECORD_ID, "VDR-CSO-DAC:change:CHG-1"
            ),
        )
        self.assertEqual(group.resources, (LAB_01, LAB_02))
        self.assertEqual(
            sorted(group.observation_ids), sorted(item.observation_id for item in built)
        )
        self.assertEqual(group.earliest_observed_at, DETECT_BY)
        self.assertTrue(all(item.origin is ObservationOrigin.SYSTEM for item in group.observations))

    def test_two_changes_of_one_resource_are_two_cases(self) -> None:
        projection = project([host()], [timed("CHG-1"), timed("CHG-2")])
        groups = group_open_observations(
            change_gap_observations(projection, ingested_at=INGESTED_AT)
        )
        self.assertEqual(
            sorted(item.context_key for item in groups),
            ["VDR-CSO-DAC:change:CHG-1", "VDR-CSO-DAC:change:CHG-2"],
        )


# *--- Input ---*


class ChangeGapInputTests(unittest.TestCase):
    """Bad input is refused with TypeError or ValueError, as the coverage builder refuses it."""

    def test_the_arguments_must_have_their_types(self) -> None:
        projection = lapsed_pair()
        row = row_of(projection)
        with self.assertRaisesRegex(TypeError, "row must be a ChangeObligation"):
            change_gap_observation(
                projection,  # type: ignore[arg-type]
                projection=projection,
                ingested_at=INGESTED_AT,
            )
        with self.assertRaisesRegex(TypeError, "projection must be a ChangeProjection"):
            change_gap_observation(
                row,
                projection=projection.to_dict(),  # type: ignore[arg-type]
                ingested_at=INGESTED_AT,
            )
        with self.assertRaisesRegex(TypeError, "projection must be a ChangeProjection"):
            change_gap_observations(
                projection.to_dict(),  # type: ignore[arg-type]
                ingested_at=INGESTED_AT,
            )

    def test_ingested_at_must_be_an_aware_datetime(self) -> None:
        projection = lapsed_pair()
        row = row_of(projection)
        with self.assertRaisesRegex(ValueError, "ingested_at must include a timezone"):
            change_gap_observation(row, projection=projection, ingested_at=datetime(2026, 9, 11))
        with self.assertRaisesRegex(TypeError, "ingested_at must be a datetime"):
            change_gap_observation(
                row,
                projection=projection,
                ingested_at="2026-09-11T00:00:00Z",  # type: ignore[arg-type]
            )
        with self.assertRaisesRegex(ValueError, "ingested_at must include a timezone"):
            change_gap_observations(projection, ingested_at=datetime(2026, 9, 11))

    def test_a_row_of_another_projection_is_refused(self) -> None:
        mine = lapsed_pair()
        other = project([host()], [timed(detectBy=(T + 2 * HOUR).isoformat())])
        with self.assertRaisesRegex(ValueError, "not an obligation of this projection"):
            change_gap_observation(row_of(other), projection=mine, ingested_at=INGESTED_AT)

    def test_a_projection_with_no_force_is_refused(self) -> None:
        projection = dataclasses.replace(lapsed_pair(), force=None)
        with self.assertRaisesRegex(ValueError, "no force"):
            change_gap_observation(
                row_of(projection), projection=projection, ingested_at=INGESTED_AT
            )
        with self.assertRaisesRegex(ValueError, "no force"):
            change_gap_observations(projection, ingested_at=INGESTED_AT)
        # A projection with nothing closed builds nothing, force or not.
        quiet = dataclasses.replace(project([host()], [change()]), force=None)
        self.assertEqual(change_gap_observations(quiet, ingested_at=INGESTED_AT), ())

    def test_a_window_that_does_not_close_at_detect_by_is_refused(self) -> None:
        projection = lapsed_pair()
        row = row_of(projection)
        skewed = dataclasses.replace(row, window_closed_at=DETECT_BY + SECOND)
        held = dataclasses.replace(projection, obligations=(skewed,))
        with self.assertRaisesRegex(ValueError, "must close at its change's detectBy"):
            change_gap_observation(skewed, projection=held, ingested_at=INGESTED_AT)


# *--- Reserved Types ---*


class ChangeGapReservedTypeTests(unittest.TestCase):
    """The walk finds the third reserved type, and each table names it as itself."""

    def test_the_walk_finds_three_reserved_types(self) -> None:
        self.assertEqual(
            minted_reserved_types(),
            {DETECTION_FAILURE_SOURCE_TYPE, COVERAGE_GAP_SOURCE_TYPE, CHANGE_GAP_SOURCE_TYPE},
        )

    def test_the_change_gap_has_a_kind_a_remedy_and_a_sentence(self) -> None:
        self.assertEqual(
            checks_module.system_record_kind(CHANGE_GAP_SOURCE_TYPE), "change detection gap"
        )
        diagnostic = checks_module.evaluation_order_diagnostic(
            tracking_id="case-0000000000000000",
            location="here",
            detected_at=DETECT_BY,
            detected_source="system",
            completed_at=DETECT_BY - SECOND,
            source_type=CHANGE_GAP_SOURCE_TYPE,
        )
        assert diagnostic is not None
        self.assertEqual(
            diagnostic.message,
            "case-0000000000000000 was evaluated at 2026-09-01T12:59:59Z, before its detection "
            f"time {DETECT_BY_TEXT} (source system); {CHANGE_REMEDY}",
        )
        self.assertEqual(
            markdown_module._system_detection_sentence({CHANGE_GAP_SOURCE_TYPE}),
            "Every reported vulnerability carried a detection time from its source artifact "
            "or, for a change detection gap, from the instant its change window closed. No "
            "attestation was needed.",
        )

    def test_the_sentence_names_each_kind_present_once(self) -> None:
        sentence = markdown_module._system_detection_sentence(
            {DETECTION_FAILURE_SOURCE_TYPE, COVERAGE_GAP_SOURCE_TYPE, CHANGE_GAP_SOURCE_TYPE}
        )
        self.assertEqual(
            sentence,
            "Every reported vulnerability carried a detection time from its source artifact "
            "or, for a detection process failure, from the instant ComplyRoll or the scanner "
            "recorded it and, for a coverage gap, from the instant its coverage window closed "
            "and, for a change detection gap, from the instant its change window closed. No "
            "attestation was needed.",
        )
        # A run with no failure never reads as one.
        self.assertNotIn(
            "detection process failure",
            markdown_module._system_detection_sentence(
                {COVERAGE_GAP_SOURCE_TYPE, CHANGE_GAP_SOURCE_TYPE}
            ),
        )

    def test_the_builder_is_not_importable_from_adapters(self) -> None:
        self.assertIsNone(importlib.util.find_spec("complyroll.adapters.change_gaps"))
        adapters = importlib.import_module("complyroll.adapters")
        for name in ("CHANGE_GAP_SOURCE_TYPE", "change_gap_observation", "change_gap_observations"):
            with self.subTest(name=name):
                self.assertFalse(hasattr(adapters, name))
        module = importlib.import_module("complyroll.reports.change_gaps")
        self.assertIs(module.change_gap_observation, change_gap_observation)


if __name__ == "__main__":
    unittest.main()
