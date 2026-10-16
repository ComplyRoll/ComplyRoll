# ******************************************************************************
# *Title: Coverage Gap Report Tests*
# *Author: Kyle Versluis*
# *Description: Stateless runs that record coverage gaps, and their goldens.*
# ******************************************************************************
"""Tests for coverage gaps recorded by a stateless report run (ADR 0015, PR 3 step 3)."""

# *--- Imports ---*

from __future__ import annotations

import copy
import json
import tempfile
import unittest
from collections.abc import Sequence
from dataclasses import replace
from datetime import UTC, datetime
from pathlib import Path
from typing import Any
from unittest import mock

from test_cli import (
    AVI_ARGUMENTS,
    COVERAGE_ARGUMENTS,
    EXAMPLE_INVENTORY,
    HISTORICAL_ARGUMENTS,
    REPORT_ARGUMENTS,
    PersistedStoreTestCase,
    help_text,
    kev_argv,
    run,
    timed_argv,
    with_failed_artifacts,
)
from test_coverage import derive, host, inventory_of, policy, resource_of
from test_coverage_report import TIMED_ARTIFACTS, TIMED_INVENTORY, TIMED_OPTIONS
from test_hdf import compile_hdf_golden
from test_reports import (
    ACCEPTED_EVALUATIONS,
    ARTIFACTS,
    AS_OF,
    AVI_DETAIL_SECTIONS,
    EXAMPLES,
    FAILED_ARTIFACTS,
    FAILED_EVALUATIONS,
    GOLDEN,
    HISTORICAL_DETAIL_SECTIONS,
    REPORT_KINDS,
    assert_markdown_carries_the_json,
    markdown_section,
    markdown_subsection,
    markdown_table_list,
    options,
)
from test_sarif import compile_sarif_golden

from complyroll.adapters import ingest_stig_artifact
from complyroll.models import ObservationDisposition, ObservationOrigin
from complyroll.reports import (
    CompiledReport,
    DetectionAttestation,
    ReportOptions,
    compile_avi_report,
    compile_historical_report,
    compile_record_set,
    compile_record_set_from_artifacts,
    compile_record_set_from_history,
    compile_vdt_report,
    load_evaluations,
    load_inventory,
)
from complyroll.reports import vdt as vdt_module
from complyroll.reports.coverage import derive_coverage
from complyroll.reports.gaps import (
    COVERAGE_GAP_RECORD_ID,
    COVERAGE_GAP_SOURCE_TYPE,
    coverage_gap_observations,
)
from complyroll.schemas import ReportSchema, validate_bundled_report_bytes

# *--- Fixtures ---*

GAP_FLAG = "--record-coverage-gaps"
#: The two goldens a gap-aware run cut; every other report golden predates the flag.
GAP_GOLDENS = ("vdt-coverage-gaps", "historical-coverage-gaps")
EXAMPLE_EVALUATIONS = EXAMPLES / "evaluations.json"
INVENTORY = load_inventory(EXAMPLE_INVENTORY)
#: The `vdt-coverage` run plus the flag, and its historical twin.
VDT_GAP_ARGUMENTS = (*COVERAGE_ARGUMENTS, GAP_FLAG)
HISTORICAL_GAP_ARGUMENTS = (*HISTORICAL_ARGUMENTS, "--inventory", str(EXAMPLE_INVENTORY), GAP_FLAG)
#: An as-of past the August period, so lab-ubuntu-03's first windows close in September.
LATE_AS_OF = datetime(2026, 9, 21, 12, 0, tzinfo=UTC)
#: An as-of before the second sample-group window closes on 2026-08-06T17:00:00Z.
EARLY_AS_OF = datetime(2026, 8, 5, 12, 0, tzinfo=UTC)
#: The backup procedure's one NMV window, which an evaluation can accept by the triple.
BACKUP_KEY = "VDR-TFR-NMV:resource:logical:backup-restore-procedure"
#: Every window of the `vdt-coverage` run and the record its gap became. The two jobbed MVX
#: windows share a case, and so do the two sample-group windows (one case per rule and job,
#: else per rule and resource); lab-rhel-01 has no job, so its windows are cases of their own.
GAP_WINDOWS = (
    ("VDR-TFR-MVX", "host:lab-rhel-01", "2026-07-04T00:00:00Z", "case-56e1eee78e97395f"),
    ("VDR-TFR-MVX", "host:lab-win-01", "2026-07-04T00:00:00Z", "case-656d627b62275ba8"),
    ("VDR-TFR-MVX", "host:ubuntu-web-01", "2026-07-04T00:00:00Z", "case-656d627b62275ba8"),
    (
        "VDR-TFR-NMV",
        "logical:backup-restore-procedure",
        "2026-07-15T16:00:00Z",
        "case-fe51d8e4d9c79b36",
    ),
    ("VDR-TFR-PCD", "host:lab-win-01", "2026-08-01T00:00:00Z", "case-9c9bf88832065e17"),
    ("VDR-TFR-PDD", "host:lab-rhel-01", "2026-07-15T00:00:00Z", "case-23ec0644fabe50d3"),
    ("VDR-TFR-PDD", "host:ubuntu-web-01", "2026-07-15T00:00:00Z", "case-987c96e87614506a"),
    (
        "VDR-TFR-PSD",
        "logical:sample-group/ir-runbooks",
        "2026-07-04T00:00:00Z",
        "case-a971b430300440cf",
    ),
    (
        "VDR-TFR-PSD",
        "logical:sample-group/ir-runbooks",
        "2026-08-06T17:00:00Z",
        "case-a971b430300440cf",
    ),
)
#: The window keys a gap-unaware run must never carry.
WINDOW_KEYS = {"recorded", "trackingId"}
#: The sentences `_write_attestation_section` prints when no attestation was needed.
ARTIFACT_ONLY_SENTENCE = (
    "Every reported vulnerability carried a detection time from its source artifact. "
    "No attestation was needed."
)
FAILURE_SENTENCE = (
    "Every reported vulnerability carried a detection time from its source artifact or, for "
    "a detection process failure, from the instant ComplyRoll or the scanner recorded it. No "
    "attestation was needed."
)
GAP_SENTENCE = (
    "Every reported vulnerability carried a detection time from its source artifact or, for "
    "a coverage gap, from the instant its coverage window closed. No attestation was needed."
)
BOTH_SENTENCE = (
    "Every reported vulnerability carried a detection time from its source artifact or, for "
    "a detection process failure, from the instant ComplyRoll or the scanner recorded it "
    "and, for a coverage gap, from the instant its coverage window closed. No attestation "
    "was needed."
)
#: The Markdown sentence a gap-aware Windows subsection opens with.
RECORDED_SENTENCE = (
    "A recorded window is a VDR-CSO-FAV system record of this run and names its tracking ID "
    "here even when this report does not select the record, such as one detected after the "
    "report period."
)


def gap_options(*, flag: bool = True, **overrides: Any) -> ReportOptions:
    """Return the test options over the example inventory, with the flag unless told not."""
    return replace(options(**{"inventory": INVENTORY, **overrides}), record_coverage_gaps=flag)


def compile_kind(
    kind: str, *, evaluations: Path = EXAMPLE_EVALUATIONS, flag: bool = True, **overrides: Any
) -> CompiledReport:
    """Compile one report kind of the example run; historical takes no period."""
    if kind == "historical":
        overrides = {"period_from": None, "period_to": None, **overrides}
    compiler = {
        "vdt": compile_vdt_report,
        "avi": compile_avi_report,
        "historical": compile_historical_report,
    }[kind]
    return compiler(
        list(ARTIFACTS),
        options=gap_options(flag=flag, **overrides),
        evaluations=load_evaluations(evaluations),
    )


def windows_of(report: CompiledReport) -> list[dict[str, Any]]:
    return list(report.document["x-complyroll"]["coverage"]["windows"])


def records_of(report: CompiledReport) -> list[dict[str, Any]]:
    """Return every official record a report publishes; an accepted item wraps its record."""
    keys = ("vulnerabilities", "activeVulnerabilities", "acceptedVulnerabilities")
    return [
        item.get("vulnerabilityDetail", item)
        for key in keys
        for item in report.document.get(key, [])
    ]


def tracking_ids(report: CompiledReport) -> set[str]:
    return {item["providerTrackingId"] for item in records_of(report)}


def diagnostics_of(report: CompiledReport, code: str) -> list[dict[str, Any]]:
    return [item for item in report.document["x-complyroll"]["diagnostics"] if item["code"] == code]


def without_gaps(document: dict[str, Any]) -> dict[str, Any]:
    """Return a copy of a report with every trace of its coverage gaps removed."""
    stripped = copy.deepcopy(document)
    extension = stripped["x-complyroll"]
    gaps = {window["trackingId"] for window in extension["coverage"]["windows"]}
    for key in ("vulnerabilities", "activeVulnerabilities", "acceptedVulnerabilities"):
        if key in stripped:
            stripped[key] = [
                item
                for item in stripped[key]
                if item.get("vulnerabilityDetail", item)["providerTrackingId"] not in gaps
            ]
    for window in extension["coverage"]["windows"]:
        for key in WINDOW_KEYS:
            del window[key]
    del extension["parserVersions"]["complyroll.coverage"]
    return stripped


def write_inventory(directory: Path, *entries: dict[str, Any]) -> Path:
    """Write a native inventory document of the given entries and return its path."""
    path = directory / "inventory.json"
    document = {
        "schema": "complyroll.inventory",
        "schemaVersion": 1,
        "name": "gap-test-boundary",
        "resources": list(entries),
    }
    path.write_text(json.dumps(document), encoding="utf-8")
    return path


def artifact_observations() -> list[Any]:
    """Return the three golden fixtures' observations, ingested at the test as-of."""
    observations = []
    for path in ARTIFACTS:
        observations.extend(ingest_stig_artifact(path, ingested_at=AS_OF).observations)
    return observations


# *--- Options ---*


class GapOptionTests(unittest.TestCase):
    """The flag rides on `ReportOptions`, needs an inventory, and stays off history."""

    def test_the_flag_needs_an_inventory(self) -> None:
        with self.assertRaisesRegex(ValueError, "record_coverage_gaps needs an inventory"):
            replace(options(), record_coverage_gaps=True)

    def test_the_flag_is_a_bool(self) -> None:
        text: Any = "yes"
        with self.assertRaisesRegex(TypeError, "record_coverage_gaps must be a bool"):
            replace(options(inventory=INVENTORY), record_coverage_gaps=text)

    def test_the_flag_defaults_off_and_options_stay_hashable(self) -> None:
        self.assertFalse(options(inventory=INVENTORY).record_coverage_gaps)
        self.assertEqual(hash(gap_options()), hash(gap_options()))
        self.assertNotEqual(gap_options(), gap_options(flag=False))

    def test_a_compile_from_history_refuses_the_flag(self) -> None:
        # Refused before the repository is touched: a report from a store never records one.
        untouched: Any = object()
        with self.assertRaisesRegex(ValueError, "never records a coverage gap"):
            compile_record_set_from_history(untouched, options=gap_options())


# *--- Record Set ---*


class GapRecordSetTests(unittest.TestCase):
    """One gap observation and record per closed window, derived once, before grouping."""

    @classmethod
    def setUpClass(cls) -> None:
        evaluations = load_evaluations(EXAMPLE_EVALUATIONS)
        cls.flagged = compile_record_set_from_artifacts(
            list(ARTIFACTS), options=gap_options(), evaluations=evaluations
        )
        cls.bare = compile_record_set_from_artifacts(
            list(ARTIFACTS), options=gap_options(flag=False), evaluations=evaluations
        )

    def gap_records(self) -> list[Any]:
        return [
            item for item in self.flagged.records if item.source_type == COVERAGE_GAP_SOURCE_TYPE
        ]

    def test_every_closed_window_is_one_gap_observation_of_a_record(self) -> None:
        coverage = self.flagged.coverage
        assert coverage is not None
        built = coverage_gap_observations(coverage, ingested_at=AS_OF)
        self.assertEqual(len(coverage.windows), 9)
        self.assertEqual(len(built), 9)
        carried = [item for record in self.gap_records() for item in record.observation_ids]
        self.assertCountEqual(carried, [item.observation_id for item in built])
        # One case per rule and job, else per rule and resource: nine windows, seven cases.
        self.assertEqual(len(self.gap_records()), 7)
        for record in self.gap_records():
            with self.subTest(record=record.tracking_id):
                closes = [
                    item.observed_at
                    for item in built
                    if item.observation_id in record.observation_ids
                ]
                self.assertEqual(record.detected_at, min(closes))
                self.assertEqual(record.detected_at_source, "system")
                self.assertEqual(record.source_record_id, COVERAGE_GAP_RECORD_ID)
                self.assertIsNone(record.evaluation)
                self.assertIsNone(record.current_rating)

    def test_no_gap_for_a_clock_that_is_current_unanchored_or_not_yet_due(self) -> None:
        coverage = self.flagged.coverage
        assert coverage is not None
        windowed = {(window.rule_id, window.key.subject) for window in coverage.windows}
        quiet = {
            (clock.rule_id, clock.key.subject): clock.status.value
            for resource in coverage.resources
            for clock in resource.clocks
            if (clock.rule_id, clock.key.subject) not in windowed
        }
        # The example inventory carries one of each: a verified procedure, a declared one
        # not yet due, and a host expected after as-of.
        self.assertEqual(set(quiet.values()), {"current", "missing", "unanchored"})
        gapped = {
            (dict(item.source_metadata)["coverage.rule"], item.resource)
            for item in coverage_gap_observations(coverage, ingested_at=AS_OF)
        }
        self.assertEqual(gapped, windowed)
        self.assertFalse(gapped & set(quiet))

    def test_the_set_names_every_gap_record_and_every_window(self) -> None:
        coverage = self.flagged.coverage
        assert coverage is not None
        records = {item.tracking_id for item in self.gap_records()}
        self.assertEqual(self.flagged.coverage_gaps, tuple(sorted(records)))
        gap_records = self.flagged.coverage_gap_records
        assert gap_records is not None
        self.assertEqual(list(gap_records), list(coverage.windows))
        self.assertEqual(set(gap_records.values()), records)

    def test_a_set_compiled_without_the_flag_holds_no_gap(self) -> None:
        self.assertFalse(
            [item for item in self.bare.records if item.source_type == COVERAGE_GAP_SOURCE_TYPE]
        )
        self.assertEqual(self.bare.coverage_gaps, ())
        self.assertIsNone(self.bare.coverage_gap_records)
        self.assertEqual(self.bare.coverage, self.flagged.coverage)

    def test_coverage_is_derived_once_and_never_from_a_gap(self) -> None:
        calls: list[list[Any]] = []

        def spy(observations: Any, *args: Any) -> Any:
            listed = list(observations)
            calls.append(listed)
            return derive_coverage(listed, *args)

        with mock.patch.object(vdt_module, "derive_coverage", side_effect=spy):
            compile_record_set_from_artifacts(list(ARTIFACTS), options=gap_options())

        self.assertEqual(len(calls), 1)
        self.assertFalse(
            [item for item in calls[0] if item.source_type == COVERAGE_GAP_SOURCE_TYPE]
        )

    def test_a_handed_coverage_must_belong_to_the_options(self) -> None:
        observations = artifact_observations()
        stale = derive_coverage(observations, INVENTORY, policy("C"), EARLY_AS_OF)
        other = derive_coverage(observations, inventory_of(host("lab-01")), policy("C"), AS_OF)
        class_b = derive_coverage(observations, INVENTORY, policy("B"), AS_OF)
        for name, handed, report_options in (
            ("as-of", stale, gap_options()),
            ("inventory", other, gap_options()),
            ("profile", class_b, gap_options()),
            ("no inventory", stale, options()),
        ):
            with (
                self.subTest(mismatch=name),
                self.assertRaisesRegex(ValueError, "coverage must be derived from these options"),
            ):
                compile_record_set(
                    artifacts=(),
                    observations=observations,
                    ingest_diagnostics=(),
                    evaluations_by_tracking_id={},
                    attestation=DetectionAttestation(
                        default=report_options.detected_at_attestation
                    ),
                    options=report_options,
                    coverage=handed,
                )

    def test_a_gap_aware_compile_needs_an_inventory(self) -> None:
        with self.assertRaisesRegex(ValueError, "a gap-aware compile needs an inventory"):
            compile_record_set(
                artifacts=(),
                observations=artifact_observations(),
                ingest_diagnostics=(),
                evaluations_by_tracking_id={},
                attestation=DetectionAttestation(default=options().detected_at_attestation),
                options=options(),
                gap_aware=True,
            )


class GapAnchorTests(unittest.TestCase):
    """Ruling 4: a gap observation never anchors, verifies or examines its own window."""

    def test_a_gap_at_the_close_never_touches_its_window(self) -> None:
        inventory = inventory_of(host("lab-01", expectedSince="2026-08-01T00:00:00Z"))
        result = derive([], inventory, AS_OF, policy("C"))
        gaps = coverage_gap_observations(result, ingested_at=AS_OF)
        # MVX closed on 2026-08-04; the month-long PCD clock is not yet due.
        self.assertEqual(len(gaps), len(result.windows))
        self.assertEqual([window.rule_id for window in result.windows], ["VDR-TFR-MVX"])
        for gap, window in zip(gaps, result.windows, strict=True):
            # The most a gap could lend: OPEN verifies, on the entry's own pair, at the close.
            self.assertIs(gap.disposition, ObservationDisposition.OPEN)
            self.assertIs(gap.origin, ObservationOrigin.SYSTEM)
            self.assertEqual(gap.resource, window.key.subject)
            self.assertEqual(gap.observed_at, window.closed_at)

        again = derive(gaps, inventory, AS_OF, policy("C"))

        self.assertEqual(again, result)
        found = resource_of(again)
        self.assertIsNone(found.last_examined)
        self.assertIsNone(found.last_verified)
        self.assertEqual(found.examined_observations, 0)
        self.assertEqual({clock.status.value for clock in found.clocks}, {"missing"})
        self.assertEqual([window.resumed_at for window in again.windows], [None])

    def test_the_example_gaps_leave_the_example_coverage_unchanged(self) -> None:
        observations = artifact_observations()
        result = derive_coverage(observations, INVENTORY, policy("C"), AS_OF)
        gaps = coverage_gap_observations(result, ingested_at=AS_OF)

        self.assertEqual(
            derive_coverage([*observations, *gaps], INVENTORY, policy("C"), AS_OF), result
        )


class GapStabilityTests(unittest.TestCase):
    """A window keeps its gap's identity and its record's tracking id as as-of moves."""

    def test_two_as_of_values_that_close_a_window_give_it_one_identity(self) -> None:
        runs = {}
        for as_of in (EARLY_AS_OF, AS_OF):
            record_set = compile_record_set_from_artifacts(
                list(ARTIFACTS), options=gap_options(as_of=as_of)
            )
            coverage = record_set.coverage
            gap_records = record_set.coverage_gap_records
            assert coverage is not None and gap_records is not None
            built = coverage_gap_observations(coverage, ingested_at=as_of)
            runs[as_of] = {
                (window.rule_id, window.context_key, window.closed_at): (gap, gap_records[window])
                for window, gap in zip(coverage.windows, built, strict=True)
            }

        early, late = runs[EARLY_AS_OF], runs[AS_OF]
        # The second sample-group window closes between the two as-of values.
        self.assertEqual(len(early), 8)
        self.assertEqual(len(late), 9)
        self.assertLess(set(early), set(late))
        for key, (gap, tracking_id) in early.items():
            with self.subTest(window=key):
                late_gap, late_tracking_id = late[key]
                self.assertEqual(gap.observation_id, late_gap.observation_id)
                self.assertEqual(replace(gap, ingested_at=AS_OF), late_gap)
                self.assertEqual(tracking_id, late_tracking_id)
        (added,) = set(late) - set(early)
        sample_group = [value[1] for key, value in late.items() if key[0] == added[0]]
        self.assertEqual(len(set(sample_group)), 1)


# *--- Window Keys ---*


class GapWindowKeyTests(unittest.TestCase):
    """`recorded` and `trackingId` appear on every window of a gap-aware run, and only there."""

    @classmethod
    def setUpClass(cls) -> None:
        cls.flagged = compile_kind("vdt")
        cls.bare = compile_kind("vdt", flag=False)

    def test_every_window_of_a_flagged_run_names_its_record(self) -> None:
        carried = {
            observation_id: item["providerTrackingId"]
            for item in records_of(self.flagged)
            for observation_id in item["x-complyroll"]["observationIds"]
        }
        coverage = self.flagged.metadata.coverage
        assert coverage is not None
        built = coverage_gap_observations(coverage, ingested_at=AS_OF)
        windows = windows_of(self.flagged)
        self.assertEqual(len(windows), 9)
        for window, gap in zip(windows, built, strict=True):
            with self.subTest(window=(window["ruleId"], window["contextKey"])):
                self.assertIs(window["recorded"], True)
                self.assertEqual(window["trackingId"], carried[gap.observation_id])

    def test_a_run_without_the_flag_carries_no_window_key(self) -> None:
        for window in windows_of(self.bare):
            self.assertFalse(WINDOW_KEYS & set(window), window)
        self.assertEqual(self.bare.to_json(), (GOLDEN / "vdt-coverage.json").read_text("utf-8"))

    def test_the_markdown_windows_table_grows_only_on_a_flagged_run(self) -> None:
        flagged = markdown_subsection(
            markdown_section(self.flagged.to_markdown(), "Coverage"), "Windows"
        )
        bare = markdown_subsection(markdown_section(self.bare.to_markdown(), "Coverage"), "Windows")

        self.assertIn("| Stand-in | Recorded | Tracking ID |", flagged)
        self.assertIn(RECORDED_SENTENCE, flagged)
        self.assertEqual(len(markdown_table_list(flagged, 11, "Rule")), 9)
        self.assertNotIn("Recorded", bare)
        self.assertNotIn(RECORDED_SENTENCE, bare)
        self.assertEqual(len(markdown_table_list(bare, 9, "Rule")), 9)
        assert_markdown_carries_the_json(self, self.flagged)
        assert_markdown_carries_the_json(self, self.bare)

    def test_an_unrecorded_window_reads_recorded_false_with_no_tracking_id(self) -> None:
        # The step 5 seam: a store that holds no record for a window hands None for it.
        coverage = self.flagged.metadata.coverage
        assert coverage is not None
        first, *rest = coverage.windows
        recorded = dict(self.flagged.metadata.coverage_gap_records or {})
        recorded[first] = None

        block = coverage.to_dict(gap_records=recorded)
        lines: list[str] = []
        vdt_module._write_coverage(
            lines.append, replace(self.flagged.metadata, coverage_gap_records=recorded)
        )

        self.assertIs(block["windows"][0]["recorded"], False)
        self.assertIsNone(block["windows"][0]["trackingId"])
        self.assertEqual({item["recorded"] for item in block["windows"][1:]}, {True})
        rows = markdown_table_list("\n".join(lines), 11, "Rule")
        self.assertEqual(rows[0][9:], ("no", "n/a"))
        self.assertEqual(rows[1][9], "yes")

    def test_the_mapping_names_every_window_and_no_other(self) -> None:
        coverage = self.flagged.metadata.coverage
        assert coverage is not None
        recorded = dict(self.flagged.metadata.coverage_gap_records or {})
        missing = {key: value for key, value in recorded.items() if key != coverage.windows[0]}
        foreign = derive([], inventory_of(host("lab-01")), AS_OF, policy("C")).windows[0]
        for name, mapping in (("missing", missing), ("foreign", {**recorded, foreign: None})):
            with (
                self.subTest(mapping=name),
                self.assertRaisesRegex(ValueError, "must name every window of the result"),
            ):
                coverage.to_dict(gap_records=mapping)

    def test_without_a_mapping_the_block_is_the_pr_2_block(self) -> None:
        coverage = self.bare.metadata.coverage
        assert coverage is not None
        self.assertEqual(coverage.to_dict(), coverage.to_dict(gap_records=None))
        self.assertEqual(
            self.bare.document["x-complyroll"]["coverage"],
            json.loads((GOLDEN / "vdt-coverage.json").read_text("utf-8"))["x-complyroll"][
                "coverage"
            ],
        )


# *--- Goldens ---*


class GapGoldenTests(unittest.TestCase):
    """The `vdt-coverage-gaps` and `historical-coverage-gaps` pairs."""

    @classmethod
    def setUpClass(cls) -> None:
        cls.vdt = compile_kind("vdt")
        cls.historical = compile_kind("historical", evaluations=ACCEPTED_EVALUATIONS)

    def test_each_window_became_the_gap_record_it_names(self) -> None:
        # Asserted on a fresh compile, apart from the golden, so a refresh cannot move one.
        self.assertEqual(
            tuple(
                (item["ruleId"], item["contextKey"], item["closedAt"], item["trackingId"])
                for item in windows_of(self.vdt)
            ),
            GAP_WINDOWS,
        )
        self.assertLessEqual({item[3] for item in GAP_WINDOWS}, tracking_ids(self.vdt))
        self.assertEqual(
            self.vdt.metadata.coverage_gaps, tuple(sorted({item[3] for item in GAP_WINDOWS}))
        )

    def test_a_gap_record_names_its_kind_once_under_the_same_tracking_ids(self) -> None:
        # The title leads with the rule, so a gap reads `coverage-gap: VDR-TFR-...` the way a
        # failure reads `detection-process-failure: source artifact ...`. The title is not
        # part of the identity, so the goldens keep every tracking id they named.
        gap_ids = {item[3] for item in GAP_WINDOWS}
        for name in GAP_GOLDENS:
            with self.subTest(golden=name):
                document = json.loads((GOLDEN / f"{name}.json").read_text("utf-8"))
                markdown = (GOLDEN / f"{name}.md").read_text("utf-8")
                self.assertNotIn("coverage gap:", f"{json.dumps(document)}{markdown}")
                details = [
                    item.get("vulnerabilityDetail", item)
                    for key in (
                        "vulnerabilities",
                        "activeVulnerabilities",
                        "acceptedVulnerabilities",
                    )
                    for item in document.get(key, ())
                ]
                gaps = [item for item in details if item["providerTrackingId"] in gap_ids]
                self.assertTrue(gaps)
                for item in gaps:
                    self.assertRegex(
                        item["vulnerabilityDescription"],
                        r"^coverage-gap: VDR-TFR-(MVX|NMV|PCD|PDD|PSD) window for ",
                    )
                windows = document["x-complyroll"]["coverage"]["windows"]
                self.assertEqual({window["trackingId"] for window in windows}, gap_ids)

    def test_the_library_compiles_both_gap_goldens(self) -> None:
        for name, report, sections in (
            ("vdt-coverage-gaps", self.vdt, None),
            ("historical-coverage-gaps", self.historical, HISTORICAL_DETAIL_SECTIONS),
        ):
            with self.subTest(golden=name):
                self.assertEqual(report.to_json(), (GOLDEN / f"{name}.json").read_text("utf-8"))
                self.assertEqual(report.to_markdown(), (GOLDEN / f"{name}.md").read_text("utf-8"))
                if sections is None:
                    assert_markdown_carries_the_json(self, report)
                else:
                    assert_markdown_carries_the_json(self, report, sections=sections)

    def test_the_command_line_cuts_both_gap_goldens_and_exits_3(self) -> None:
        for name, argv in (
            ("vdt-coverage-gaps", VDT_GAP_ARGUMENTS),
            ("historical-coverage-gaps", HISTORICAL_GAP_ARGUMENTS),
        ):
            with self.subTest(golden=name), tempfile.TemporaryDirectory() as directory:
                json_path = Path(directory) / "report.json"
                markdown_path = Path(directory) / "report.md"

                code, out, err = run(
                    [*argv, "-o", str(json_path), "--markdown", str(markdown_path)]
                )

                self.assertEqual(code, 3, msg=err)
                self.assertEqual(out, "")
                self.assertNotIn("error:", err)
                self.assertEqual(json_path.read_bytes(), (GOLDEN / f"{name}.json").read_bytes())
                self.assertEqual(markdown_path.read_bytes(), (GOLDEN / f"{name}.md").read_bytes())

    def test_both_gap_goldens_validate_against_their_schemas(self) -> None:
        for name, schema in (
            ("vdt-coverage-gaps", ReportSchema.VULNERABILITY_DETAIL),
            ("historical-coverage-gaps", ReportSchema.HISTORICAL_ACTIVITY),
        ):
            with self.subTest(golden=name):
                result = validate_bundled_report_bytes(
                    schema, (GOLDEN / f"{name}.json").read_bytes()
                )
                self.assertTrue(result.is_valid, result.issues)
        self.assertTrue(self.vdt.validation.is_valid)
        self.assertTrue(self.historical.validation.is_valid)

    def test_the_vdt_gap_golden_differs_from_vdt_coverage_only_by_its_gaps(self) -> None:
        gaps = json.loads((GOLDEN / "vdt-coverage-gaps.json").read_text("utf-8"))
        plain = json.loads((GOLDEN / "vdt-coverage.json").read_text("utf-8"))

        self.assertEqual(without_gaps(gaps), plain)
        self.assertEqual(gaps["x-complyroll"]["parserVersions"]["complyroll.coverage"], "1")
        self.assertEqual(len(gaps["vulnerabilities"]) - len(plain["vulnerabilities"]), 7)

    def test_the_historical_gap_golden_differs_from_its_bare_run_only_by_its_gaps(self) -> None:
        gaps = json.loads((GOLDEN / "historical-coverage-gaps.json").read_text("utf-8"))
        bare = compile_kind("historical", evaluations=ACCEPTED_EVALUATIONS, flag=False)

        self.assertEqual(without_gaps(gaps), bare.document)
        self.assertEqual(
            len(gaps["activeVulnerabilities"]) - len(bare.document["activeVulnerabilities"]), 7
        )

    def test_the_two_goldens_record_the_same_gaps(self) -> None:
        vdt = json.loads((GOLDEN / "vdt-coverage-gaps.json").read_text("utf-8"))
        historical = json.loads((GOLDEN / "historical-coverage-gaps.json").read_text("utf-8"))
        self.assertEqual(
            vdt["x-complyroll"]["coverage"]["windows"],
            historical["x-complyroll"]["coverage"]["windows"],
        )


class GoldenRegistryTests(unittest.TestCase):
    """Every report golden cut before the flag still compiles byte-identical without it."""

    def test_every_existing_report_golden_recompiles_byte_identical_without_the_flag(self) -> None:
        failed_vdt = [
            *with_failed_artifacts(REPORT_ARGUMENTS[:-1]),
            str(FAILED_EVALUATIONS),
            "--record-failed-imports",
        ]
        failed_historical = [
            *with_failed_artifacts(HISTORICAL_ARGUMENTS[:-1]),
            str(FAILED_EVALUATIONS),
            "--record-failed-imports",
        ]
        runs: dict[str, tuple[Sequence[str], int]] = {
            "vdt-fixtures": (REPORT_ARGUMENTS, 0),
            "avi-fixtures": (AVI_ARGUMENTS, 0),
            "historical-fixtures": (HISTORICAL_ARGUMENTS, 0),
            **{f"{kind}-kev": (kev_argv(kind), 0) for kind in REPORT_KINDS},
            "vdt-coverage": (COVERAGE_ARGUMENTS, 0),
            "vdt-coverage-timed": (timed_argv(), 0),
            "vdt-failed": (failed_vdt, 3),
            "historical-failed": (failed_historical, 3),
        }
        compiled = {"vdt-sarif": compile_sarif_golden(), "vdt-hdf": compile_hdf_golden()}
        reports = {
            path.stem
            for path in GOLDEN.glob("*.json")
            if "x-complyroll" in json.loads(path.read_text(encoding="utf-8"))
        }
        self.assertEqual(reports - set(GAP_GOLDENS), {*runs, *compiled})
        self.assertLessEqual(set(GAP_GOLDENS), reports)
        for name, (argv, status) in runs.items():
            self.assertNotIn(GAP_FLAG, argv)
            with self.subTest(golden=name), tempfile.TemporaryDirectory() as directory:
                json_path = Path(directory) / "report.json"
                markdown_path = Path(directory) / "report.md"

                code, _, err = run([*argv, "-o", str(json_path), "--markdown", str(markdown_path)])

                self.assertEqual(code, status, msg=err)
                self.assertEqual(json_path.read_bytes(), (GOLDEN / f"{name}.json").read_bytes())
                self.assertEqual(markdown_path.read_bytes(), (GOLDEN / f"{name}.md").read_bytes())
        for name, report in compiled.items():
            with self.subTest(golden=name):
                self.assertEqual(
                    report.to_json().encode("utf-8"), (GOLDEN / f"{name}.json").read_bytes()
                )
                self.assertEqual(
                    report.to_markdown().encode("utf-8"), (GOLDEN / f"{name}.md").read_bytes()
                )


# *--- Command Line ---*


class GapCommandTests(unittest.TestCase):
    """`--record-coverage-gaps` on the three stateless report commands."""

    COMMANDS = (
        ("vdt", REPORT_ARGUMENTS),
        ("avi", AVI_ARGUMENTS),
        ("historical", HISTORICAL_ARGUMENTS),
    )

    def test_a_recorded_gap_exits_3_on_every_report_command(self) -> None:
        for kind, argv in self.COMMANDS:
            with self.subTest(report=kind):
                code, out, err = run([*argv, "--inventory", str(EXAMPLE_INVENTORY), GAP_FLAG])

                self.assertEqual(code, 3, msg=err)
                self.assertNotIn("error:", err)
                windows = json.loads(out)["x-complyroll"]["coverage"]["windows"]
                self.assertEqual(len(windows), 9)
                self.assertEqual({window["recorded"] for window in windows}, {True})

    def test_the_inventory_alone_still_exits_0(self) -> None:
        for kind, argv in self.COMMANDS:
            with self.subTest(report=kind):
                code, out, err = run([*argv, "--inventory", str(EXAMPLE_INVENTORY)])

                self.assertEqual(code, 0, msg=err)
                for window in json.loads(out)["x-complyroll"]["coverage"]["windows"]:
                    self.assertFalse(WINDOW_KEYS & set(window))

    def test_the_flag_with_no_closed_window_exits_0_with_the_unflagged_bytes(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            inventory = write_inventory(
                Path(directory), host("lab-later-01", expectedSince="2026-09-01T00:00:00Z")
            )
            for kind, argv in self.COMMANDS:
                with self.subTest(report=kind):
                    base = [*argv, "--inventory", str(inventory)]
                    code, flagged, err = run([*base, GAP_FLAG])
                    bare_code, bare, _ = run(base)

                    self.assertEqual((code, bare_code), (0, 0), msg=err)
                    self.assertEqual(flagged, bare)
                    self.assertEqual(json.loads(flagged)["x-complyroll"]["coverage"]["windows"], [])

    def test_both_flags_exit_3_once_and_list_both_kinds(self) -> None:
        for kind, argv in self.COMMANDS:
            with self.subTest(report=kind):
                code, out, err = run(
                    [
                        *with_failed_artifacts(argv),
                        "--inventory",
                        str(EXAMPLE_INVENTORY),
                        "--record-failed-imports",
                        GAP_FLAG,
                    ]
                )

                self.assertEqual(code, 3, msg=err)
                extension = json.loads(out)["x-complyroll"]
                self.assertEqual(len(extension["detectionFailures"]), 3)
                self.assertEqual(
                    {window["recorded"] for window in extension["coverage"]["windows"]}, {True}
                )

    def test_a_failed_publish_exits_1_and_never_3(self) -> None:
        # Exit 3 means the output was written, so a refusal to write it outranks a gap.
        with tempfile.TemporaryDirectory() as directory:
            missing = Path(directory) / "missing" / "report.json"
            code, _, err = run([*VDT_GAP_ARGUMENTS, "-o", str(missing)])

            self.assertEqual(code, 1)
            self.assertIn("error: output_write_failed", err)
            self.assertFalse(missing.exists())

    def test_the_failure_flag_alone_ignores_a_recorded_gap(self) -> None:
        # Exit 3 answers each flag for its own kind: the failure flag never reads gaps.
        code, _, err = run([*COVERAGE_ARGUMENTS, "--record-failed-imports"])
        self.assertEqual(code, 0, msg=err)

    def test_the_flag_without_an_inventory_is_refused_and_writes_nothing(self) -> None:
        for kind, argv in self.COMMANDS:
            with self.subTest(report=kind), tempfile.TemporaryDirectory() as directory:
                json_path = Path(directory) / "report.json"

                code, out, err = run([*argv, GAP_FLAG, "-o", str(json_path)])

                self.assertEqual(code, 1)
                self.assertEqual(out, "")
                self.assertIn(
                    f"error: invalid_option: report {kind} {GAP_FLAG} needs --inventory", err
                )
                self.assertFalse(json_path.exists())

    def test_help_states_what_recording_a_gap_does(self) -> None:
        for kind, _ in self.COMMANDS:
            with self.subTest(report=kind):
                text = " ".join(help_text(["report", kind]).split())
                self.assertIn(
                    f"{GAP_FLAG} record each coverage window that closed with no verification "
                    "as a VDR-CSO-FAV system record; needs --inventory; exits 3 when one is "
                    "recorded",
                    text,
                )


class PersistedGapRefusalTests(PersistedStoreTestCase):
    """A store never takes the flag: no report run records a gap into it."""

    def test_the_flag_beside_a_store_is_refused_and_the_store_is_untouched(self) -> None:
        self.populate(ACCEPTED_EVALUATIONS)
        before = self.database.read_bytes()
        for kind in REPORT_KINDS:
            with self.subTest(report=kind):
                argv = ["report", kind, "--db", str(self.database), "--class", "C"]
                argv += [
                    "--package-uri",
                    "https://example.test/cpo",
                    "--as-of",
                    "2026-08-21T12:00:00Z",
                ]
                if kind != "historical":
                    argv += ["--from", "2026-08-01T00:00:00Z", "--to", "2026-08-31T23:59:59Z"]
                for extra in ((), ("--inventory", str(EXAMPLE_INVENTORY))):
                    code, out, err = run([*argv, *extra, GAP_FLAG])

                    self.assertEqual(code, 1)
                    self.assertEqual(out, "")
                    self.assertIn(
                        f"error: invalid_option: report {kind} takes either --db or "
                        f"{GAP_FLAG}, never both",
                        err,
                    )
        self.assertEqual(self.database.read_bytes(), before)


# *--- Period, Attestation and AVI ---*


class GapPeriodTests(unittest.TestCase):
    """ADR 0014 Decision 18 unchanged: a gap closed after the period leaves the VDT only."""

    @classmethod
    def setUpClass(cls) -> None:
        cls.vdt = compile_kind("vdt", as_of=LATE_AS_OF)
        cls.historical = compile_kind("historical", as_of=LATE_AS_OF)

    def late_windows(self) -> list[dict[str, Any]]:
        return [
            window for window in windows_of(self.vdt) if window["closedAt"] > "2026-08-31T23:59:59Z"
        ]

    def test_a_gap_closed_after_the_period_is_excluded_and_still_listed(self) -> None:
        late = self.late_windows()
        excluded = {
            window["trackingId"]
            for window in late
            if all(
                other["closedAt"] > "2026-08-31T23:59:59Z"
                for other in windows_of(self.vdt)
                if other["trackingId"] == window["trackingId"]
            )
        }
        # lab-ubuntu-03 is expected from 2026-09-01 and has no job, so its MVX and PDD
        # windows are records of their own, detected in September.
        self.assertEqual(
            {
                (window["ruleId"], window["contextKey"])
                for window in late
                if window["trackingId"] in excluded
            },
            {("VDR-TFR-MVX", "host:lab-ubuntu-03"), ("VDR-TFR-PDD", "host:lab-ubuntu-03")},
        )
        self.assertFalse(excluded & tracking_ids(self.vdt))
        for window in late:
            self.assertIs(window["recorded"], True)
        messages = {item["message"] for item in diagnostics_of(self.vdt, "excluded_by_period")}
        for window in late:
            if window["trackingId"] in excluded:
                self.assertIn(
                    f"{window['trackingId']} was detected {window['closedAt']}, after the period "
                    "ended 2026-08-31T23:59:59Z",
                    messages,
                )
        self.assertLessEqual(excluded, set(self.vdt.metadata.coverage_gaps))
        self.assertEqual(self.vdt.document["x-complyroll"]["excludedByPeriod"], len(excluded))

    def test_the_historical_snapshot_lists_the_gaps_the_vdt_left_out(self) -> None:
        listed = tracking_ids(self.historical)
        for window in windows_of(self.historical):
            self.assertIn(window["trackingId"], listed)
        self.assertEqual(windows_of(self.historical), windows_of(self.vdt))

    def test_the_command_line_exits_3_when_every_late_gap_is_left_out(self) -> None:
        argv = [*COVERAGE_ARGUMENTS, GAP_FLAG]
        argv[argv.index("--as-of") + 1] = "2026-09-21T12:00:00Z"
        code, out, err = run(argv)

        self.assertEqual(code, 3, msg=err)
        self.assertEqual(json.loads(out), self.vdt.document)


class GapAttestationTests(unittest.TestCase):
    """The attestation section names a coverage gap's clock, and nothing else moves."""

    @staticmethod
    def section(report: CompiledReport) -> str:
        return markdown_section(report.to_markdown(), "Detection time attestation").strip()

    def timed(self, *, failed: bool = False, flag: bool = False) -> CompiledReport:
        return compile_vdt_report(
            [*TIMED_ARTIFACTS, *(FAILED_ARTIFACTS if failed else ())],
            options=replace(
                options(
                    inventory=load_inventory(TIMED_INVENTORY) if flag else None, **TIMED_OPTIONS
                ),
                record_coverage_gaps=flag,
            ),
            record_failed_imports=failed,
        )

    def test_an_artifact_only_run_keeps_its_sentence(self) -> None:
        self.assertEqual(self.section(self.timed()), ARTIFACT_ONLY_SENTENCE)

    def test_a_failure_only_run_keeps_its_sentence(self) -> None:
        self.assertEqual(self.section(self.timed(failed=True)), FAILURE_SENTENCE)

    def test_a_gap_run_names_the_window_close(self) -> None:
        report = self.timed(flag=True)
        self.assertTrue(
            [
                item
                for item in report.vulnerabilities
                if item.source_type == COVERAGE_GAP_SOURCE_TYPE
            ]
        )
        self.assertEqual(self.section(report), GAP_SENTENCE)

    def test_a_run_with_both_names_both(self) -> None:
        self.assertEqual(self.section(self.timed(failed=True, flag=True)), BOTH_SENTENCE)

    def test_an_attested_run_keeps_its_section(self) -> None:
        for kind in REPORT_KINDS:
            with self.subTest(report=kind):
                flagged = self.section(compile_kind(kind))
                self.assertEqual(flagged, self.section(compile_kind(kind, flag=False)))
                # The AVI report lists no attested record, so it reads the artifact sentence.
                if kind != "avi":
                    self.assertIn("The operator attested a detection time", flagged)


class GapAviTests(unittest.TestCase):
    """An evaluation of a gap by the full triple: AVI lists it only once it is accepted."""

    ACCEPTANCE = {
        "disposition": "accepted",
        "acceptanceRationale": "Accepted under change record CR-210 until the Q4 restore test.",
    }

    def setUp(self) -> None:
        directory = tempfile.TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        self.workspace = Path(directory.name)

    def evaluation(self, **overrides: object) -> Path:
        """Write one evaluation of the backup procedure's gap, matched by the triple."""
        entry = {
            "match": {
                "sourceRecordId": COVERAGE_GAP_RECORD_ID,
                "sourceType": COVERAGE_GAP_SOURCE_TYPE,
                "contextKey": BACKUP_KEY,
            },
            "completedAt": "2026-08-10T00:00:00Z",
            "isInternetReachable": False,
            "isLikelyExploitable": False,
            "pain": 1,
            "potentialAgencyImpact": "A missed restore test leaves backup integrity unproven.",
            "rationale": "The restore test is rescheduled; the procedure itself is unchanged.",
            "evaluator": "Example Provider vulnerability team (coverage review)",
            **overrides,
        }
        path = self.workspace / "evaluations.json"
        path.write_text(json.dumps({"evaluations": [entry]}), encoding="utf-8")
        return path

    @staticmethod
    def backup_window(report: CompiledReport) -> dict[str, Any]:
        (window,) = [
            item
            for item in windows_of(report)
            if item["contextKey"] == "logical:backup-restore-procedure"
        ]
        return window

    def test_an_evaluation_tracking_id_names_the_window(self) -> None:
        # The window names the published id after the override, as a failure's listing does.
        report = compile_kind("vdt", evaluations=self.evaluation(trackingId="POAM-GAP-0001"))

        self.assertEqual(self.backup_window(report)["trackingId"], "POAM-GAP-0001")
        self.assertIn("POAM-GAP-0001", tracking_ids(report))
        self.assertIn("POAM-GAP-0001", report.metadata.coverage_gaps)
        assert_markdown_carries_the_json(self, report)

    def test_avi_lists_no_gap_that_no_evaluation_accepts(self) -> None:
        report = compile_kind("avi", evaluations=ACCEPTED_EVALUATIONS)
        gaps = {window["trackingId"] for window in windows_of(report)}

        self.assertFalse(gaps & tracking_ids(report))
        self.assertTrue(report.metadata.coverage_gaps)

    def test_avi_lists_the_gap_an_evaluation_accepts(self) -> None:
        avi = compile_kind("avi", evaluations=self.evaluation(**self.ACCEPTANCE))
        vdt = compile_kind("vdt", evaluations=self.evaluation(**self.ACCEPTANCE))
        window = self.backup_window(avi)
        accepted = window["trackingId"]

        self.assertEqual(tracking_ids(avi), {accepted})
        (item,) = avi.document["acceptedVulnerabilities"]
        self.assertEqual(
            item["acceptanceRationale"],
            "Accepted under change record CR-210 until the Q4 restore test.",
        )
        assert_markdown_carries_the_json(self, avi, sections=AVI_DETAIL_SECTIONS)
        self.assertNotIn(accepted, tracking_ids(vdt))
        self.assertIn(
            accepted,
            {item["message"].split()[0] for item in diagnostics_of(vdt, "accepted_excluded")},
        )
        self.assertIs(window["recorded"], True)
        self.assertEqual(windows_of(vdt), windows_of(avi))


if __name__ == "__main__":
    unittest.main()
