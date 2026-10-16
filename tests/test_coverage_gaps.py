# ******************************************************************************
# *Title: Coverage Gap Tests*
# *Author: Kyle Versluis*
# *Description: Unit tests for the coverage gap system observation builder.*
# ******************************************************************************
"""Tests for coverage gaps: one SYSTEM observation per closed window (ADR 0015, PR 3)."""

# *--- Imports ---*

from __future__ import annotations

import json
import unittest
from dataclasses import replace
from datetime import UTC, datetime, timedelta, timezone
from typing import Any

from test_coverage import SINCE, derive, host, inventory_of, observation, policy, procedure
from test_reports import ARTIFACTS, AS_OF, DETECTED_AT, compiled_artifact, options

from complyroll.adapters import ingest_stig_artifact
from complyroll.correlation import group_open_observations, tracking_id_for
from complyroll.models import (
    RESERVED_SOURCE_TYPE_PREFIX,
    Observation,
    ObservationDisposition,
    ObservationOrigin,
    ResourceRef,
    SourceSeverity,
)
from complyroll.reports import (
    DetectionAttestation,
    Inventory,
    compile_record_set,
    parse_inventory,
    project_vdt,
)
from complyroll.reports.coverage import (
    COVERAGE_BASIS,
    MVX_RULE,
    NMV_RULE,
    PCD_RULE,
    PDD_RULE,
    PSD_RULE,
    CoverageResult,
    CoverageWindow,
)
from complyroll.reports.gaps import (
    COVERAGE_GAP_DESCRIPTION,
    COVERAGE_GAP_METADATA_KEYS,
    COVERAGE_GAP_PARSER_NAME,
    COVERAGE_GAP_PARSER_VERSION,
    COVERAGE_GAP_RECORD_ID,
    COVERAGE_GAP_RULE,
    COVERAGE_GAP_SOURCE_TOOL,
    COVERAGE_GAP_SOURCE_TYPE,
    coverage_gap_context_key,
    coverage_gap_observation,
    coverage_gap_observations,
)

# *--- Fixtures ---*

#: Late enough that every Class B clock of the fleet has closed one declared window.
AS_OF_LATE = datetime(2027, 3, 1, tzinfo=UTC)
#: Ingest time sits after every instant here, so a substituted one would show.
INGESTED_AT = datetime(2027, 3, 2, tzinfo=UTC)
JOB = "nightly-openscap"
GROUP = "web-tier"
GROUP_KEY = f"logical:sample-group/{GROUP}"
#: lab-02's one verification, after its MVX window closed on 2026-07-08.
RESUMED = datetime(2026, 7, 20, tzinfo=UTC)
EIGHT_KEYS = [
    "coverage.anchor",
    "coverage.anchorAt",
    "coverage.basis",
    "coverage.force",
    "coverage.inventorySha256",
    "coverage.job",
    "coverage.rule",
    "coverage.windowClosedAt",
]


def fleet(*extra: dict[str, Any]) -> Inventory:
    """Two job-sharing hosts, two job-less hosts, a sample group and a procedure."""
    return inventory_of(
        host("lab-01", job=JOB),
        host("lab-02"),
        host("web-01", drift=True, group=GROUP, job=JOB),
        host("web-02", drift=True, group=GROUP),
        procedure("ir-plan"),
        *extra,
    )


def fleet_result(as_of: datetime = AS_OF_LATE, *evidence: Observation) -> CoverageResult:
    return derive(list(evidence), fleet(), as_of)


def window_of(
    result: CoverageResult,
    rule_id: str = MVX_RULE,
    context_key: str = "host:lab-01",
    closed_at: datetime | None = None,
) -> CoverageWindow:
    (window,) = [
        item
        for item in result.windows
        if item.rule_id == rule_id
        and item.context_key == context_key
        and (closed_at is None or item.closed_at == closed_at)
    ]
    return window


def gap(
    result: CoverageResult,
    rule_id: str = MVX_RULE,
    context_key: str = "host:lab-01",
    *,
    closed_at: datetime | None = None,
    ingested_at: datetime = INGESTED_AT,
) -> Observation:
    return coverage_gap_observation(
        window_of(result, rule_id, context_key, closed_at),
        inventory=result.inventory,
        ingested_at=ingested_at,
    )


def renamed(name: str, *entries: dict[str, Any]) -> Inventory:
    """Read an inventory whose name, and so its digest, differs from inventory_of's."""
    document = {
        "schema": "complyroll.inventory",
        "schemaVersion": 1,
        "name": name,
        "resources": list(entries),
    }
    return parse_inventory(json.dumps(document).encode("utf-8"))


# *--- Constants ---*


class GapConstantsTests(unittest.TestCase):
    """The identity constants mirror the detection failure's, under their own reserved type."""

    def test_the_source_type_carries_the_reserved_prefix(self) -> None:
        self.assertTrue(COVERAGE_GAP_SOURCE_TYPE.startswith(RESERVED_SOURCE_TYPE_PREFIX))

    def test_the_constants_are_pinned(self) -> None:
        self.assertEqual(
            (
                COVERAGE_GAP_SOURCE_TYPE,
                COVERAGE_GAP_SOURCE_TOOL,
                COVERAGE_GAP_PARSER_NAME,
                COVERAGE_GAP_PARSER_VERSION,
                COVERAGE_GAP_RECORD_ID,
                COVERAGE_GAP_RULE,
            ),
            (
                "complyroll.coverage",
                "complyroll",
                "complyroll.coverage",
                "1",
                "coverage-gap",
                "VDR-CSO-FAV",
            ),
        )

    def test_the_metadata_key_set_is_the_eight_keys(self) -> None:
        self.assertEqual(list(COVERAGE_GAP_METADATA_KEYS), EIGHT_KEYS)


# *--- Identity ---*


class GapIdentityTests(unittest.TestCase):
    """The id is fixed by the rule, the resource, the context key and the window close."""

    def test_the_same_window_builds_the_same_observation(self) -> None:
        result = fleet_result()
        first, second = gap(result), gap(result)

        self.assertEqual(first, second)
        self.assertEqual(first.observation_id, first.derived_observation_id)
        self.assertTrue(first.observation_id.startswith("obs-"))

    def test_a_different_rule_resource_or_close_moves_the_id(self) -> None:
        result = fleet_result(AS_OF_LATE, observation("lab-02", at=RESUMED))
        resumed = window_of(result, MVX_RULE, "host:lab-02", closed_at=RESUMED + timedelta(days=7))
        cases = {
            "lab-01 MVX": gap(result),
            # Same resource, another rule.
            "lab-01 PCD": gap(result, PCD_RULE),
            # Same rule, close and context key; only the resource differs.
            "web-01 MVX": gap(result, MVX_RULE, "host:web-01"),
            # Same rule and resource; only the close differs.
            "lab-02 MVX declared": gap(
                result, MVX_RULE, "host:lab-02", closed_at=datetime(2026, 7, 8, tzinfo=UTC)
            ),
            "lab-02 MVX resumed": gap(result, MVX_RULE, "host:lab-02", closed_at=resumed.closed_at),
        }
        self.assertEqual(cases["lab-01 MVX"].context_key, cases["web-01 MVX"].context_key)
        self.assertEqual(cases["lab-01 MVX"].observed_at, cases["web-01 MVX"].observed_at)
        ids = [item.observation_id for item in cases.values()]
        self.assertEqual(len(set(ids)), len(ids))

    def test_the_id_holds_across_as_of_and_ingest_time(self) -> None:
        verified = observation("lab-02", at=RESUMED)
        closed = datetime(2026, 7, 8, tzinfo=UTC)
        # Before the verification the window has not resumed; after it, it has.
        early = fleet_result(datetime(2026, 7, 15, tzinfo=UTC), verified)
        late = fleet_result(AS_OF_LATE, verified)
        self.assertIsNone(window_of(early, MVX_RULE, "host:lab-02").resumed_at)
        self.assertEqual(
            window_of(late, MVX_RULE, "host:lab-02", closed_at=closed).resumed_at, RESUMED
        )

        before = gap(early, MVX_RULE, "host:lab-02")
        after = gap(late, MVX_RULE, "host:lab-02", closed_at=closed)
        self.assertEqual(before, after)
        for moment in (SINCE, AS_OF_LATE, INGESTED_AT + timedelta(days=400)):
            with self.subTest(ingested_at=moment):
                moved = gap(late, MVX_RULE, "host:lab-02", closed_at=closed, ingested_at=moment)
                self.assertEqual(moved.observation_id, before.observation_id)
                self.assertEqual(moved.ingested_at, moment)

    def test_the_id_ignores_the_inventory_digest(self) -> None:
        entry = host("lab-01", job=JOB)
        first = derive([], renamed("first", entry), AS_OF_LATE)
        second = derive([], renamed("second", entry), AS_OF_LATE)
        self.assertNotEqual(first.inventory.sha256, second.inventory.sha256)

        one, two = gap(first), gap(second)
        self.assertEqual(one.observation_id, two.observation_id)
        self.assertEqual(one.metadata_value("coverage.inventorySha256"), first.inventory.sha256)
        self.assertEqual(two.metadata_value("coverage.inventorySha256"), second.inventory.sha256)
        self.assertEqual(two.evidence_ids, (f"sha256:{second.inventory.sha256}",))


# *--- Clock ---*


class GapClockTests(unittest.TestCase):
    """A gap is observed at its window close, never at as-of or ingest time."""

    def test_observed_at_is_the_window_close_in_utc(self) -> None:
        result = fleet_result()
        self.assertTrue(result.windows)
        for window in result.windows:
            with self.subTest(rule=window.rule_id, context=window.context_key):
                built = coverage_gap_observation(
                    window, inventory=result.inventory, ingested_at=INGESTED_AT
                )
                self.assertEqual(built.observed_at, window.closed_at)
                self.assertIs(built.observed_at.tzinfo if built.observed_at else None, UTC)
                self.assertNotEqual(built.observed_at, result.as_of)
                self.assertNotEqual(built.observed_at, INGESTED_AT)

    def test_a_month_clock_in_another_zone_is_observed_in_utc(self) -> None:
        # On the 31st at 03:00Z it is still the 30th in Phoenix, so a one-month clock run in
        # that calendar falls due a day later than the UTC calendar's.
        entry = host("drift-01", drift=True, expectedSince="2026-08-31T03:00:00Z")
        zoned = derive([], inventory_of(entry), AS_OF_LATE, policy("B", "America/Phoenix"))
        plain = derive([], inventory_of(entry), AS_OF_LATE)
        window = window_of(zoned, PDD_RULE, "host:drift-01")
        local_close = datetime(2026, 10, 1, 3, tzinfo=UTC)
        self.assertEqual(window.closed_at, local_close)
        self.assertEqual(
            window_of(plain, PDD_RULE, "host:drift-01").closed_at,
            datetime(2026, 9, 30, 3, tzinfo=UTC),
        )

        built = coverage_gap_observation(window, inventory=zoned.inventory, ingested_at=INGESTED_AT)
        self.assertEqual(built.observed_at, local_close)
        self.assertIs(built.observed_at.tzinfo if built.observed_at else None, UTC)
        self.assertEqual(built.metadata_value("coverage.windowClosedAt"), "2026-10-01T03:00:00Z")
        self.assertIn(" closed 2026-10-01T03:00:00Z ", built.title)
        self.assertNotEqual(
            built.observation_id,
            gap(plain, PDD_RULE, "host:drift-01").observation_id,
        )

    def test_a_close_given_with_an_offset_is_stored_in_utc(self) -> None:
        result = fleet_result()
        window = window_of(result)
        offset = timezone(timedelta(hours=-7))
        deadline = replace(
            window.deadline,
            start_at=window.deadline.start_at.astimezone(offset),
            due_at=window.deadline.due_at.astimezone(offset),
        )
        shifted = replace(window, deadline=deadline)
        self.assertEqual(shifted.closed_at.utcoffset(), timedelta(hours=-7))
        built = coverage_gap_observation(
            shifted, inventory=result.inventory, ingested_at=INGESTED_AT
        )
        self.assertIs(built.observed_at.tzinfo if built.observed_at else None, UTC)
        self.assertEqual(built, gap(result))


# *--- Context Key ---*


class GapContextKeyTests(unittest.TestCase):
    """One case per rule and job, else per rule and resource; a group never takes a job."""

    def test_a_job_bearing_entry_keys_on_its_job(self) -> None:
        built = gap(fleet_result())
        self.assertEqual(built.context_key, f"{MVX_RULE}:job:{JOB}")
        self.assertEqual(built.metadata_value("coverage.job"), JOB)

    def test_a_job_less_entry_keys_on_its_resource(self) -> None:
        built = gap(fleet_result(), MVX_RULE, "host:lab-02")
        self.assertEqual(built.context_key, f"{MVX_RULE}:host:lab-02")
        self.assertEqual(built.metadata_value("coverage.job"), "")

    def test_a_sample_group_keys_on_the_group(self) -> None:
        built = gap(fleet_result(), PSD_RULE, GROUP_KEY)
        self.assertEqual(built.context_key, f"{PSD_RULE}:{GROUP_KEY}")
        self.assertEqual(
            built.resource,
            ResourceRef(resource_id=f"sample-group/{GROUP}", resource_type="logical"),
        )
        # web-01 is a member and names a job; the group's clock still has none.
        self.assertEqual(built.metadata_value("coverage.job"), "")

    def test_an_entry_named_like_the_group_does_not_lend_its_job(self) -> None:
        twin = procedure(f"sample-group/{GROUP}", job="manual-review")
        result = derive([], fleet(twin), AS_OF_LATE)
        entry = result.inventory.entry_for("logical", f"sample-group/{GROUP}")
        self.assertIsNotNone(entry)

        group_gap = gap(result, PSD_RULE, GROUP_KEY)
        self.assertEqual(group_gap.context_key, f"{PSD_RULE}:{GROUP_KEY}")
        self.assertEqual(group_gap.metadata_value("coverage.job"), "")
        twin_gap = gap(result, NMV_RULE, GROUP_KEY)
        self.assertEqual(twin_gap.context_key, f"{NMV_RULE}:job:manual-review")
        # The twin's pair spells the group's subject, and it is still not the group's entry.
        with self.assertRaisesRegex(ValueError, "entry"):
            coverage_gap_context_key(window_of(result, PSD_RULE, GROUP_KEY), entry)

    def test_the_key_function_directly(self) -> None:
        result = fleet_result()
        lab_01 = result.inventory.entry_for("host", "lab-01")
        lab_02 = result.inventory.entry_for("host", "lab-02")
        window = window_of(result)
        group = window_of(result, PSD_RULE, GROUP_KEY)

        self.assertEqual(coverage_gap_context_key(window, lab_01), f"{MVX_RULE}:job:{JOB}")
        self.assertEqual(coverage_gap_context_key(window, None), f"{MVX_RULE}:host:lab-01")
        self.assertEqual(coverage_gap_context_key(group, None), f"{PSD_RULE}:{GROUP_KEY}")
        for label, target, entry in (
            ("another resource's entry", window, lab_02),
            ("an entry for a group window", group, lab_01),
        ):
            with self.subTest(label), self.assertRaisesRegex(ValueError, "entry"):
                coverage_gap_context_key(target, entry)


# *--- Record ---*


class GapRecordTests(unittest.TestCase):
    """Every field of the gap is fixed: nothing in it carries severity or a source artifact."""

    def test_the_metadata_is_exactly_the_eight_keys(self) -> None:
        result = fleet_result(AS_OF_LATE, observation("lab-02", at=RESUMED))
        sha = result.inventory.sha256
        for built in coverage_gap_observations(result, ingested_at=INGESTED_AT):
            with self.subTest(context=built.context_key, at=built.observed_at):
                self.assertEqual([key for key, _ in built.source_metadata], EIGHT_KEYS)
                self.assertEqual(built.metadata_value("coverage.basis"), COVERAGE_BASIS)
                self.assertEqual(built.metadata_value("coverage.inventorySha256"), sha)

        self.assertEqual(
            dict(gap(result).source_metadata),
            {
                "coverage.anchor": "declared",
                "coverage.anchorAt": "2026-07-01T00:00:00Z",
                "coverage.basis": COVERAGE_BASIS,
                "coverage.force": "MUST",
                "coverage.inventorySha256": sha,
                "coverage.job": JOB,
                "coverage.rule": MVX_RULE,
                "coverage.windowClosedAt": "2026-07-08T00:00:00Z",
            },
        )
        resumed = gap(result, MVX_RULE, "host:lab-02", closed_at=datetime(2026, 7, 27, tzinfo=UTC))
        self.assertEqual(
            {key: value for key, value in resumed.source_metadata if key != "coverage.basis"},
            {
                "coverage.anchor": "verification",
                "coverage.anchorAt": "2026-07-20T00:00:00Z",
                "coverage.force": "MUST",
                "coverage.inventorySha256": sha,
                "coverage.job": "",
                "coverage.rule": MVX_RULE,
                "coverage.windowClosedAt": "2026-07-27T00:00:00Z",
            },
        )
        self.assertEqual(
            gap(result, PDD_RULE, "host:web-02").metadata_value("coverage.force"), "SHOULD"
        )

    def test_the_fixed_fields(self) -> None:
        result = fleet_result()
        built = gap(result)

        self.assertIs(built.origin, ObservationOrigin.SYSTEM)
        self.assertIs(built.disposition, ObservationDisposition.OPEN)
        self.assertIs(built.source_severity, SourceSeverity.UNKNOWN)
        self.assertEqual(built.source_type, COVERAGE_GAP_SOURCE_TYPE)
        self.assertEqual(built.source_tool, COVERAGE_GAP_SOURCE_TOOL)
        self.assertEqual(
            (built.parser_name, built.parser_version),
            (COVERAGE_GAP_PARSER_NAME, COVERAGE_GAP_PARSER_VERSION),
        )
        self.assertEqual(built.source_record_id, COVERAGE_GAP_RECORD_ID)
        self.assertEqual(built.resource, ResourceRef(resource_id="lab-01", resource_type="host"))
        self.assertEqual(built.source_identifiers, ())
        self.assertEqual(built.source_artifact_digest, "")
        self.assertEqual(built.source_artifact_name, "")
        self.assertEqual(built.evidence_ids, (f"sha256:{result.inventory.sha256}",))
        self.assertEqual(built.ingested_at, INGESTED_AT)
        self.assertEqual(
            built.title,
            "coverage gap: VDR-TFR-MVX window for host:lab-01 closed 2026-07-08T00:00:00Z "
            "with no verification recorded (VDR-CSO-FAV)",
        )
        self.assertEqual(
            built.description,
            "ComplyRoll recorded no verification for this resource inside the window; this "
            "records the absence of a verification, not a vulnerability.",
        )
        self.assertEqual(built.description, COVERAGE_GAP_DESCRIPTION)
        self.assertEqual(
            gap(result, PSD_RULE, GROUP_KEY).title,
            "coverage gap: VDR-TFR-PSD window for logical:sample-group/web-tier closed "
            "2026-07-08T00:00:00Z with no verification recorded (VDR-CSO-FAV)",
        )

    def test_the_canonical_form_round_trips(self) -> None:
        result = fleet_result(AS_OF_LATE, observation("lab-02", at=RESUMED))
        offset = INGESTED_AT.astimezone(timezone(timedelta(hours=5, minutes=30)))
        for ingested_at in (INGESTED_AT, offset):
            for built in coverage_gap_observations(result, ingested_at=ingested_at):
                with self.subTest(context=built.context_key, ingested_at=ingested_at):
                    canonical = built.to_canonical_dict()
                    rebuilt = Observation.from_canonical_dict(canonical)
                    self.assertEqual(rebuilt, built)
                    self.assertEqual(rebuilt.to_canonical_dict(), canonical)
                    self.assertEqual(rebuilt.observation_id, rebuilt.derived_observation_id)


# *--- Examines Nothing ---*


class GapExaminesNothingTests(unittest.TestCase):
    """A gap records an absence, so feeding it back never changes the coverage it came from."""

    def test_the_coverage_block_is_unchanged_by_its_own_gaps(self) -> None:
        evidence = [observation("lab-02", at=RESUMED), observation("web-01", at=RESUMED)]
        for as_of in (datetime(2026, 7, 15, tzinfo=UTC), AS_OF_LATE):
            with self.subTest(as_of=as_of):
                result = derive(evidence, fleet(), as_of)
                gaps = coverage_gap_observations(result, ingested_at=INGESTED_AT)
                self.assertTrue(gaps)
                again = derive([*evidence, *gaps], fleet(), as_of)
                self.assertEqual(again.to_dict(), result.to_dict())
                self.assertEqual(again, result)


# *--- Correlation ---*


class GapCorrelationTests(unittest.TestCase):
    """A gap groups into one SYSTEM case by the documented triple."""

    def test_one_gap_is_one_system_group_with_a_stable_tracking_id(self) -> None:
        built = gap(fleet_result(), MVX_RULE, "host:lab-02")
        (group,) = group_open_observations([built])
        (again,) = group_open_observations([gap(fleet_result(), MVX_RULE, "host:lab-02")])

        self.assertEqual(group.tracking_id, again.tracking_id)
        self.assertEqual(
            group.tracking_id,
            tracking_id_for(COVERAGE_GAP_SOURCE_TYPE, COVERAGE_GAP_RECORD_ID, built.context_key),
        )
        self.assertEqual(
            (group.source_type, group.source_record_id, group.context_key),
            (COVERAGE_GAP_SOURCE_TYPE, COVERAGE_GAP_RECORD_ID, f"{MVX_RULE}:host:lab-02"),
        )
        self.assertEqual(group.observation_ids, (built.observation_id,))
        self.assertTrue(all(item.origin is ObservationOrigin.SYSTEM for item in group.observations))
        self.assertEqual(group.source_identifiers, ())
        self.assertEqual(group.earliest_observed_at, built.observed_at)

    def test_gaps_sharing_a_job_are_one_case(self) -> None:
        result = fleet_result()
        (group,) = group_open_observations([gap(result), gap(result, MVX_RULE, "host:web-01")])

        self.assertEqual(group.context_key, f"{MVX_RULE}:job:{JOB}")
        self.assertEqual(
            group.resources,
            (
                ResourceRef(resource_id="lab-01", resource_type="host"),
                ResourceRef(resource_id="web-01", resource_type="host"),
            ),
        )

    def test_two_lapses_of_one_clock_are_one_case(self) -> None:
        result = fleet_result(AS_OF_LATE, observation("lab-02", at=RESUMED))
        lapses = [
            item
            for item in coverage_gap_observations(result, ingested_at=INGESTED_AT)
            if item.context_key == f"{MVX_RULE}:host:lab-02"
        ]
        self.assertEqual(len(lapses), 2)
        (group,) = group_open_observations(lapses)
        self.assertEqual(len(group.observation_ids), 2)
        self.assertEqual(group.earliest_observed_at, datetime(2026, 7, 8, tzinfo=UTC))


# *--- Batch ---*


class GapBatchTests(unittest.TestCase):
    """One gap per closed window, in the result's window order."""

    def test_one_gap_per_window_in_window_order(self) -> None:
        result = fleet_result(AS_OF_LATE, observation("lab-02", at=RESUMED))
        built = coverage_gap_observations(result, ingested_at=INGESTED_AT)

        self.assertIsInstance(built, tuple)
        self.assertEqual(len(built), len(result.windows))
        self.assertGreater(len(built), 5)
        self.assertEqual(
            built,
            tuple(
                coverage_gap_observation(
                    window, inventory=result.inventory, ingested_at=INGESTED_AT
                )
                for window in result.windows
            ),
        )
        self.assertEqual(
            [item.observed_at for item in built],
            [window.closed_at for window in result.windows],
        )

    def test_no_window_is_no_gap(self) -> None:
        result = fleet_result(SINCE + timedelta(days=1))
        self.assertEqual(result.windows, ())
        self.assertEqual(coverage_gap_observations(result, ingested_at=INGESTED_AT), ())


# *--- Input ---*


class GapInputTests(unittest.TestCase):
    """Bad input is refused with TypeError or ValueError, as the failure builder refuses it."""

    def test_ingested_at_must_be_an_aware_datetime(self) -> None:
        result = fleet_result()
        window = window_of(result)
        with self.assertRaisesRegex(ValueError, "ingested_at must include a timezone"):
            coverage_gap_observation(
                window, inventory=result.inventory, ingested_at=datetime(2027, 3, 2)
            )
        with self.assertRaisesRegex(TypeError, "ingested_at must be a datetime"):
            coverage_gap_observation(
                window,
                inventory=result.inventory,
                ingested_at="2027-03-02T00:00:00Z",  # type: ignore[arg-type]
            )
        with self.assertRaisesRegex(ValueError, "ingested_at must include a timezone"):
            coverage_gap_observations(result, ingested_at=datetime(2027, 3, 2))

    def test_the_arguments_must_have_their_types(self) -> None:
        result = fleet_result()
        window = window_of(result)
        with self.assertRaisesRegex(TypeError, "CoverageWindow"):
            coverage_gap_observation(
                window.to_dict(),  # type: ignore[arg-type]
                inventory=result.inventory,
                ingested_at=INGESTED_AT,
            )
        with self.assertRaisesRegex(TypeError, "Inventory"):
            coverage_gap_observation(
                window,
                inventory=result.inventory.to_document(),  # type: ignore[arg-type]
                ingested_at=INGESTED_AT,
            )
        with self.assertRaisesRegex(TypeError, "CoverageResult"):
            coverage_gap_observations(
                result.to_dict(),  # type: ignore[arg-type]
                ingested_at=INGESTED_AT,
            )

    def test_a_window_from_another_inventory_is_refused(self) -> None:
        result = fleet_result()
        other = inventory_of(host("lab-99"))
        with self.assertRaisesRegex(ValueError, "names no entry of this inventory"):
            coverage_gap_observation(window_of(result), inventory=other, ingested_at=INGESTED_AT)


# *--- Compiler ---*


class GapCompilerTests(unittest.TestCase):
    """A gap reaches the record compiler as a SYSTEM record and is never a detection failure.

    SystemObservationGateTests in test_reports.py pins the gate with a synthetic reserved
    type; this runs the real gap through the same loop.
    """

    def test_a_gap_compiles_as_a_system_record(self) -> None:
        inventory = inventory_of(host("lab-gap-01", expectedSince="2026-08-01T00:00:00Z"))
        result = derive([], inventory, AS_OF, policy("C"))
        (built,) = coverage_gap_observations(result, ingested_at=AS_OF)
        self.assertEqual(built.observed_at, datetime(2026, 8, 4, tzinfo=UTC))

        results = [ingest_stig_artifact(path, ingested_at=AS_OF) for path in ARTIFACTS]
        record_set = compile_record_set(
            artifacts=tuple(compiled_artifact(item) for item in results),
            observations=(
                *(item for reading in results for item in reading.observations),
                built,
            ),
            ingest_diagnostics=(),
            evaluations_by_tracking_id={},
            attestation=DetectionAttestation(default=DETECTED_AT),
            options=options(),
        )

        self.assertEqual(record_set.detection_failures, ())
        (record,) = [
            item for item in record_set.records if item.source_type == COVERAGE_GAP_SOURCE_TYPE
        ]
        self.assertEqual(record.observation_ids, (built.observation_id,))
        self.assertEqual(record.detected_at_source, "system")
        self.assertEqual(
            record.tracking_id,
            tracking_id_for(COVERAGE_GAP_SOURCE_TYPE, COVERAGE_GAP_RECORD_ID, built.context_key),
        )
        report = project_vdt(record_set)
        self.assertTrue(report.validation.is_valid)
        self.assertNotIn("detectionFailures", report.document["x-complyroll"])


if __name__ == "__main__":
    unittest.main()
