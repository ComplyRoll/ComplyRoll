# ******************************************************************************
# *Title: Change Gap Report Tests*
# *Author: Kyle Versluis*
# *Description: Stateless runs that record change gaps, and their golden.*
# ******************************************************************************
"""Tests for change gaps recorded by a stateless report run (ADR 0018, PR 3 step 2)."""

# *--- Imports ---*

from __future__ import annotations

import copy
import json
import tempfile
import unittest
from dataclasses import replace
from datetime import UTC, datetime, timedelta, timezone
from pathlib import Path
from typing import Any
from unittest import mock

from test_changes import catalog, observation
from test_cli import (
    AVI_ARGUMENTS,
    HISTORICAL_ARGUMENTS,
    REPORT_ARGUMENTS,
    TIMED_CHANGES,
    PersistedStoreTestCase,
    help_text,
    run,
    stripped_policy,
    timed_changes_argv,
)
from test_coverage import host
from test_coverage_gap_report import write_inventory
from test_coverage_report import TIMED_ARTIFACTS, TIMED_INVENTORY, TIMED_OPTIONS
from test_reports import (
    GOLDEN,
    REPORT_KINDS,
    assert_markdown_carries_the_json,
    markdown_section,
    markdown_subsection,
    markdown_table_list,
    options,
)

from complyroll import cli as cli_module
from complyroll.adapters import ingest_stig_artifact
from complyroll.models import ObservationOrigin
from complyroll.policy import CertificationClass, CertificationProfile, load_bundled_policy
from complyroll.reports import (
    CompiledReport,
    DetectionAttestation,
    ReportCompileError,
    ReportOptions,
    compile_avi_report,
    compile_historical_report,
    compile_record_set,
    compile_record_set_from_artifacts,
    compile_record_set_from_history,
    compile_vdt_report,
    load_changes,
    load_inventory,
    parse_changes,
)
from complyroll.reports import markdown as markdown_module
from complyroll.reports import records as records_module
from complyroll.reports.change_gaps import (
    CHANGE_GAP_RECORD_ID,
    CHANGE_GAP_SOURCE_TYPE,
    change_gap_context_key,
    change_gap_observations,
)
from complyroll.reports.changes import (
    ChangeObligation,
    ChangeProjection,
    ObligationStatus,
    StoredChangeSet,
    derive_changes,
    detection_request,
)
from complyroll.reports.coverage import COVERAGE_RULE_IDS
from complyroll.reports.gaps import COVERAGE_GAP_SOURCE_TYPE, coverage_gap_observations
from complyroll.reports.records import (
    derive_changes_from_artifacts,
    derive_report_changes,
    derive_request_changes,
)
from complyroll.schemas import ReportSchema, validate_bundled_report_bytes

# *--- Fixtures ---*

CHANGE_FLAG = "--record-change-gaps"
COVERAGE_FLAG = "--record-coverage-gaps"
#: The golden a change-gap-aware run cut; every other report golden predates the flag.
CHANGE_GAP_GOLDENS = ("vdt-change-gaps",)
#: The `vdt-changes-timed` run plus the flag: the golden's cut.
CHANGE_GAP_ARGUMENTS = (*timed_changes_argv(), CHANGE_FLAG)
TIMED_INVENTORY_SET = load_inventory(TIMED_INVENTORY)
TIMED_CHANGE_SET = load_changes(TIMED_CHANGES)
IMAGE = "image:registry.example.test/synthetic/example-service:1.4.0"
HELPERS = "https://github.com/example/webapp/src/ui/helpers.js"
LEGACY = "https://github.com/example/webapp/src/ui/legacy.js"
#: Every closed window of the timed run and the record its gap became: the lapsed image row
#: and the late render row, one case per change.
CLOSED_ROWS = (
    ("CHG-2001", IMAGE, "2026-08-20T00:00:00Z", "case-0488e724b51dbd9b"),
    ("CHG-2003", "file:src/ui/render.js", "2026-09-01T01:00:00Z", "case-5fb2afe5f9d47d6c"),
)
#: The obligation row keys a change-gap-unaware run must never carry.
ROW_KEYS = {"recorded", "trackingId"}
#: The Markdown sentence a change-gap-aware Obligations subsection opens with.
RECORDED_ROW_SENTENCE = (
    "A recorded row is a VDR-CSO-FAV system record of this run and names its tracking ID here "
    "even when this report does not select the record, such as one detected after the report "
    "period. A row whose window did not close records nothing and reads n/a."
)
CHANGE_SENTENCE = (
    "Every reported vulnerability carried a detection time from its source artifact or, for "
    "a change detection gap, from the instant its change window closed. No attestation was "
    "needed."
)
#: One change naming two entries, neither verified between 10:00 and noon on 2 September.
TWO_RESOURCE_CHANGE = {
    "changeId": "CHG-3001",
    "kind": "modified",
    "occurredAt": "2026-09-02T10:00:00Z",
    "source": {"tool": "git", "reference": "commit 3001aaa"},
    "resources": [
        {"resourceType": "file", "resourceId": HELPERS},
        {"resourceType": "file", "resourceId": LEGACY},
    ],
    "significant": True,
    "rationale": "Two files rewritten in one push.",
    "detectBy": "2026-09-02T12:00:00Z",
}
#: A change whose window is still open at the timed as-of.
PENDING_CHANGE = {
    "changeId": "CHG-3002",
    "kind": "modified",
    "occurredAt": "2026-09-03T00:00:00Z",
    "source": {"tool": "git", "reference": "commit 3002bbb"},
    "resources": [{"resourceType": "file", "resourceId": HELPERS}],
    "significant": True,
    "rationale": "A follow-up no scan has reached yet.",
    "detectBy": "2026-09-10T00:00:00Z",
}


def change_document(*changes: dict[str, Any], name: str = "gap-changes") -> dict[str, Any]:
    return {
        "schema": "complyroll.changes",
        "schemaVersion": 1,
        "name": name,
        "changes": list(changes),
    }


def change_set_of(*changes: dict[str, Any]) -> Any:
    return parse_changes(json.dumps(change_document(*changes)).encode("utf-8"))


def write_changes(directory: Path, *changes: dict[str, Any]) -> Path:
    path = directory / "changes.json"
    path.write_text(json.dumps(change_document(*changes)), encoding="utf-8")
    return path


def timed_options(
    *,
    flag: bool = True,
    coverage: bool = False,
    changes: Any = None,
    **overrides: Any,
) -> ReportOptions:
    """Return the timed run's options with its change file, and the change flag unless told not."""
    base = options(inventory=TIMED_INVENTORY_SET, **{**TIMED_OPTIONS, **overrides})
    return replace(
        base,
        changes=TIMED_CHANGE_SET if changes is None else changes,
        record_change_gaps=flag,
        record_coverage_gaps=coverage,
    )


def compile_timed(kind: str = "vdt", **arguments: Any) -> CompiledReport:
    """Compile one report kind of the timed run; historical takes no period."""
    if kind == "historical":
        arguments = {"period_from": None, "period_to": None, **arguments}
    compiler = {
        "vdt": compile_vdt_report,
        "avi": compile_avi_report,
        "historical": compile_historical_report,
    }[kind]
    return compiler(list(TIMED_ARTIFACTS), options=timed_options(**arguments))


def timed_set(**arguments: Any) -> Any:
    return compile_record_set_from_artifacts(
        list(TIMED_ARTIFACTS), options=timed_options(**arguments)
    )


def timed_evidence() -> list[Any]:
    """Return the timed artifacts' observations, ingested at the timed as-of."""
    observations: list[Any] = []
    for path in TIMED_ARTIFACTS:
        observations.extend(
            ingest_stig_artifact(path, ingested_at=TIMED_OPTIONS["as_of"]).observations
        )
    return observations


def rows_of(report: CompiledReport) -> list[dict[str, Any]]:
    return list(report.document["x-complyroll"]["changes"]["obligations"])


def records_of(report: CompiledReport) -> list[dict[str, Any]]:
    """Return every official record a report publishes; an accepted item wraps its record."""
    keys = ("vulnerabilities", "activeVulnerabilities", "acceptedVulnerabilities")
    return [
        item.get("vulnerabilityDetail", item)
        for key in keys
        for item in report.document.get(key, [])
    ]


def by_tracking_id(report: CompiledReport) -> dict[str, dict[str, Any]]:
    return {item["providerTrackingId"]: item for item in records_of(report)}


def change_gap_records(record_set: Any) -> list[Any]:
    return [item for item in record_set.records if item.source_type == CHANGE_GAP_SOURCE_TYPE]


def without_change_gaps(document: dict[str, Any]) -> dict[str, Any]:
    """Return a copy of a report with every trace of its change gaps removed."""
    stripped = copy.deepcopy(document)
    extension = stripped["x-complyroll"]
    rows = extension["changes"]["obligations"]
    gaps = {row["trackingId"] for row in rows if row["trackingId"] is not None}
    for key in ("vulnerabilities", "activeVulnerabilities", "acceptedVulnerabilities"):
        if key in stripped:
            stripped[key] = [
                item
                for item in stripped[key]
                if item.get("vulnerabilityDetail", item)["providerTrackingId"] not in gaps
            ]
    for row in rows:
        for key in ROW_KEYS:
            del row[key]
    del extension["parserVersions"]["complyroll.change"]
    return stripped


def obligation_table(report: CompiledReport) -> list[tuple[str, ...]]:
    section = markdown_section(report.to_markdown(), "Changes")
    return markdown_table_list(markdown_subsection(section, "Obligations"), 19, "Change")


def refusal(compile_run: Any) -> tuple[Any, ...]:
    """Return the diagnostics a compile is refused with."""
    try:
        compile_run()
    except ReportCompileError as exc:
        return exc.diagnostics
    raise AssertionError("the compile was not refused")


# *--- Options ---*


class ChangeGapOptionTests(unittest.TestCase):
    """The flag rides on `ReportOptions`, needs a change set, and stays off history."""

    def test_the_flag_needs_a_change_set(self) -> None:
        base = options(inventory=TIMED_INVENTORY_SET)
        with self.assertRaisesRegex(
            ValueError,
            "^record_change_gaps needs changes, whose closed windows the gaps record$",
        ):
            replace(base, record_change_gaps=True)

    def test_the_flag_is_a_bool(self) -> None:
        text: Any = "yes"
        with self.assertRaisesRegex(TypeError, "^record_change_gaps must be a bool$"):
            replace(timed_options(flag=False), record_change_gaps=text)

    def test_the_flag_defaults_off_and_options_stay_hashable(self) -> None:
        self.assertFalse(options().record_change_gaps)
        self.assertEqual(hash(timed_options()), hash(timed_options()))
        self.assertNotEqual(timed_options(), timed_options(flag=False))

    def test_a_compile_from_history_refuses_the_flag(self) -> None:
        # Refused before the repository is touched, and before the change file is: a report
        # from a store never records a change gap.
        untouched: Any = object()
        with self.assertRaisesRegex(
            ValueError,
            "^record_change_gaps applies only to a compile from artifacts; a report from "
            "history never records a change gap$",
        ):
            compile_record_set_from_history(untouched, options=timed_options())


# *--- Record Set ---*


class ChangeGapRecordSetTests(unittest.TestCase):
    """One gap observation per closed window, one case per change, derived before grouping."""

    @classmethod
    def setUpClass(cls) -> None:
        cls.flagged = timed_set()
        cls.bare = timed_set(flag=False)

    def closed_rows(self) -> list[ChangeObligation]:
        assert self.flagged.changes is not None
        return [row for row in self.flagged.changes.obligations if row.window_closed_at]

    def test_every_closed_window_is_one_gap_observation_of_a_record(self) -> None:
        projection = self.flagged.changes
        assert projection is not None
        built = change_gap_observations(projection, ingested_at=TIMED_OPTIONS["as_of"])
        self.assertEqual(len(built), 2)
        self.assertEqual(
            [(row.change.change_id, row.status) for row in self.closed_rows()],
            [("CHG-2001", ObligationStatus.LAPSED), ("CHG-2003", ObligationStatus.DETECTED)],
        )
        carried = [
            item for record in change_gap_records(self.flagged) for item in record.observation_ids
        ]
        self.assertCountEqual(carried, [item.observation_id for item in built])
        # One case per change: two changes closed a window each.
        self.assertEqual(len(change_gap_records(self.flagged)), 2)
        for record in change_gap_records(self.flagged):
            with self.subTest(record=record.tracking_id):
                closes = [
                    item.observed_at
                    for item in built
                    if item.observation_id in record.observation_ids
                ]
                self.assertEqual(record.detected_at, min(closes))
                self.assertEqual(record.detected_at_source, "system")
                self.assertEqual(record.source_record_id, CHANGE_GAP_RECORD_ID)
                self.assertIsNone(record.evaluation)

    def test_the_set_names_every_change_gap_record_and_every_closed_window(self) -> None:
        records = {item.tracking_id for item in change_gap_records(self.flagged)}
        self.assertEqual(self.flagged.change_gaps, tuple(sorted(records)))
        gap_records = self.flagged.change_gap_records
        assert gap_records is not None
        self.assertEqual(list(gap_records), self.closed_rows())
        self.assertEqual(set(gap_records.values()), records)
        # Neither kind of coverage bookkeeping moves on a change-only run.
        self.assertEqual(self.flagged.coverage_gaps, ())
        self.assertIsNone(self.flagged.coverage_gap_records)

    def test_a_set_compiled_without_the_flag_holds_no_change_gap(self) -> None:
        self.assertFalse(change_gap_records(self.bare))
        self.assertEqual(self.bare.change_gaps, ())
        self.assertIsNone(self.bare.change_gap_records)
        self.assertEqual(self.bare.changes, self.flagged.changes)
        self.assertEqual(self.bare.coverage, self.flagged.coverage)

    def test_the_projection_is_derived_once_and_never_from_a_change_gap(self) -> None:
        calls: list[list[Any]] = []

        def spy(observations: Any, *args: Any, **kwargs: Any) -> Any:
            listed = list(observations)
            calls.append(listed)
            return derive_changes(listed, *args, **kwargs)

        for coverage in (False, True):
            calls.clear()
            with (
                self.subTest(coverage=coverage),
                mock.patch.object(records_module, "derive_changes", side_effect=spy),
            ):
                record_set = timed_set(coverage=coverage)

                self.assertEqual(len(calls), 1)
                self.assertFalse(
                    [item for item in calls[0] if item.source_type == CHANGE_GAP_SOURCE_TYPE]
                )
                # Decision 11's order: coverage gaps already joined when the changes are read.
                self.assertEqual(
                    bool(
                        [item for item in calls[0] if item.source_type == COVERAGE_GAP_SOURCE_TYPE]
                    ),
                    coverage,
                )
                self.assertEqual(record_set.changes, self.flagged.changes)

    def test_a_handed_projection_must_belong_to_the_options(self) -> None:
        observations = timed_evidence()
        self.assertEqual({item.origin for item in observations}, {ObservationOrigin.ARTIFACT})
        report_options = timed_options()

        def derive(**changed: Any) -> ChangeProjection:
            arguments: dict[str, Any] = {
                "change_set": TIMED_CHANGE_SET,
                "inventory": TIMED_INVENTORY_SET,
                "profile": report_options.profile,
                "as_of": report_options.as_of,
                "kev_catalog": None,
                **changed,
            }
            return derive_changes(
                observations,
                arguments["change_set"],
                arguments["inventory"],
                load_bundled_policy(arguments["profile"]),
                arguments["as_of"],
                kev_catalog=arguments["kev_catalog"],
            )

        class_b = CertificationProfile(CertificationClass.B, calendar_timezone="UTC")
        other_inventory = load_inventory(TIMED_INVENTORY)
        other_inventory = replace(other_inventory, name="another-boundary")
        stored = StoredChangeSet(
            changes=TIMED_CHANGE_SET.changes,
            names=tuple(TIMED_CHANGE_SET.name for _ in TIMED_CHANGE_SET.changes),
            digests=tuple(TIMED_CHANGE_SET.sha256 for _ in TIMED_CHANGE_SET.changes),
        )
        kev = catalog(released=datetime(2026, 9, 1, tzinfo=UTC))
        for name, handed, compile_options in (
            ("as-of", derive(as_of=report_options.as_of - timedelta(days=1)), report_options),
            ("inventory", derive(inventory=other_inventory), report_options),
            ("change set", derive(change_set=change_set_of(PENDING_CHANGE)), report_options),
            ("a store's changes", derive(change_set=stored), report_options),
            ("profile", derive(profile=class_b), report_options),
            ("KEV catalog", derive(kev_catalog=kev), report_options),
            (
                "no change set",
                derive(),
                replace(report_options, changes=None, record_change_gaps=False),
            ),
        ):
            with (
                self.subTest(mismatch=name),
                self.assertRaisesRegex(ValueError, "^changes must be derived from these options"),
            ):
                compile_record_set(
                    artifacts=(),
                    observations=observations,
                    ingest_diagnostics=(),
                    evaluations_by_tracking_id={},
                    attestation=DetectionAttestation(),
                    options=compile_options,
                    changes=handed,
                )
        # The projection these options derive is accepted as handed.
        compile_record_set(
            artifacts=(),
            observations=observations,
            ingest_diagnostics=(),
            evaluations_by_tracking_id={},
            attestation=DetectionAttestation(),
            options=report_options,
            changes=derive(),
        )

    def test_a_change_gap_aware_compile_needs_a_change_set(self) -> None:
        bare_options = options(inventory=TIMED_INVENTORY_SET, **TIMED_OPTIONS)
        with self.assertRaisesRegex(
            ValueError, "^a change-gap-aware compile needs a change set and an inventory$"
        ):
            compile_record_set(
                artifacts=(),
                observations=(),
                ingest_diagnostics=(),
                evaluations_by_tracking_id={},
                attestation=DetectionAttestation(),
                options=bare_options,
                change_gap_aware=True,
            )


class ChangeGapRefusalOrderTests(unittest.TestCase):
    """Call 9: the front half meets each refusal where the back half does, flag or not."""

    UNUSABLE = observation(at=datetime(1, 1, 1, tzinfo=timezone(timedelta(hours=1))))

    def refusals(self, *, flag: bool, **arguments: Any) -> tuple[Any, ...]:
        return refusal(lambda: timed_set(flag=flag, **arguments))

    def assert_same_refusal(self, **arguments: Any) -> tuple[Any, ...]:
        flagged = self.refusals(flag=True, **arguments)
        self.assertEqual(flagged, self.refusals(flag=False, **arguments))
        return flagged

    def test_each_single_refusal_reads_the_same_with_the_flag(self) -> None:
        stale = catalog(released=datetime(2026, 9, 30, tzinfo=UTC))
        for name, patches, arguments, code in (
            ("change rule", ("VDR-CSO-DAC",), {}, "change_rule_unavailable"),
            ("coverage rule", (COVERAGE_RULE_IDS[0],), {}, "coverage_rule_unavailable"),
            ("KEV rule", ("VDR-TFR-KEV",), {"kev_catalog": catalog()}, "kev_rule_unavailable"),
            ("stale KEV catalog", (), {"kev_catalog": stale}, "kev_catalog_after_as_of"),
        ):
            with (
                self.subTest(refusal=name),
                mock.patch.object(records_module, "select_policy", stripped_policy(*patches)),
            ):
                diagnostics = self.assert_same_refusal(**arguments)
                self.assertEqual([item.code for item in diagnostics], [code])

    def test_two_faults_name_the_same_first_refusal_with_the_flag(self) -> None:
        stale = catalog(released=datetime(2026, 9, 30, tzinfo=UTC))
        for name, patches, arguments, code in (
            (
                "coverage and change rules",
                (COVERAGE_RULE_IDS[0], "VDR-CSO-DAC"),
                {},
                "coverage_rule_unavailable",
            ),
            (
                "stale catalog and change rule",
                ("VDR-CSO-DAC",),
                {"kev_catalog": stale},
                "kev_catalog_after_as_of",
            ),
        ):
            with (
                self.subTest(faults=name),
                mock.patch.object(records_module, "select_policy", stripped_policy(*patches)),
            ):
                diagnostics = self.assert_same_refusal(**arguments)
                self.assertEqual([item.code for item in diagnostics], [code])

    def test_an_unusable_clock_is_named_where_the_back_half_names_it(self) -> None:
        ingested = ([], [self.UNUSABLE])
        for name, patches, code in (
            ("clock alone", (), "clock_out_of_range"),
            ("clock and change rule", ("VDR-CSO-DAC",), "clock_out_of_range"),
            # The back half checks the coverage rule before any clock, so the flag does too.
            ("clock and coverage rule", (COVERAGE_RULE_IDS[0],), "coverage_rule_unavailable"),
        ):
            with (
                self.subTest(faults=name),
                mock.patch.object(records_module, "_ingest_all", return_value=ingested),
                mock.patch.object(records_module, "select_policy", stripped_policy(*patches)),
            ):
                diagnostics = self.assert_same_refusal()
                self.assertEqual({item.code for item in diagnostics}, {code})


# *--- Evidence ---*


class ChangeGapEvidenceTests(unittest.TestCase):
    """Decision 11: a system record never verifies a change, whichever gaps joined first."""

    def test_a_coverage_gap_inside_a_change_window_leaves_the_obligation_lapsed(self) -> None:
        record_set = timed_set(coverage=True)
        projection = record_set.changes
        coverage = record_set.coverage
        assert projection is not None and coverage is not None
        (row,) = [item for item in projection.obligations if item.change.change_id == "CHG-2001"]
        change = row.change
        assert change.detect_by is not None
        inside = [
            item
            for item in coverage_gap_observations(coverage, ingested_at=TIMED_OPTIONS["as_of"])
            if item.resource == row.resource
            and item.observed_at is not None
            and change.occurred_at <= item.observed_at <= change.detect_by
        ]
        # The image's PDD window closed on 19 August, inside CHG-2001's 10-20 August window.
        self.assertEqual(
            [item.observed_at for item in inside], [datetime(2026, 8, 19, 10, tzinfo=UTC)]
        )
        carried = {item for record in record_set.records for item in record.observation_ids}
        self.assertIn(inside[0].observation_id, carried)
        self.assertIs(row.status, ObligationStatus.LAPSED)
        self.assertIsNone(row.evidence)
        gap_records = record_set.change_gap_records
        assert gap_records is not None
        self.assertIsNotNone(gap_records[row])

    def test_the_projection_is_the_same_before_and_after_the_gaps_join(self) -> None:
        both = timed_set(coverage=True)
        projection = both.changes
        coverage = both.coverage
        assert projection is not None and coverage is not None
        evidence = timed_evidence()
        gaps = [
            *coverage_gap_observations(coverage, ingested_at=TIMED_OPTIONS["as_of"]),
            *change_gap_observations(projection, ingested_at=TIMED_OPTIONS["as_of"]),
        ]
        report_options = timed_options(coverage=True)
        policy = load_bundled_policy(report_options.profile)
        before = derive_changes(
            evidence, TIMED_CHANGE_SET, TIMED_INVENTORY_SET, policy, report_options.as_of
        )
        after = derive_changes(
            [*gaps, *evidence], TIMED_CHANGE_SET, TIMED_INVENTORY_SET, policy, report_options.as_of
        )
        self.assertEqual(before, after)
        self.assertEqual(before.to_dict(), after.to_dict())
        # The record set's projection is that same projection, with either flag or none.
        self.assertEqual(projection, before)
        self.assertEqual(timed_set(flag=False).changes, before)


# *--- Row Keys ---*


class ChangeGapRowKeyTests(unittest.TestCase):
    """Call 7: `recorded` and `trackingId` on every row of an aware run, and only there."""

    @classmethod
    def setUpClass(cls) -> None:
        cls.flagged = compile_timed()
        cls.bare = compile_timed(flag=False)

    def test_every_row_of_an_aware_run_carries_both_keys(self) -> None:
        carried = {
            observation_id: item["providerTrackingId"]
            for item in records_of(self.flagged)
            for observation_id in item["x-complyroll"]["observationIds"]
        }
        projection = self.flagged.metadata.changes
        assert projection is not None
        built = iter(change_gap_observations(projection, ingested_at=TIMED_OPTIONS["as_of"]))
        rows = rows_of(self.flagged)
        self.assertEqual(len(rows), 6)
        for row, obligation in zip(rows, projection.obligations, strict=True):
            with self.subTest(row=(row["changeId"], row["resourceId"])):
                self.assertLessEqual(ROW_KEYS, set(row))
                if obligation.window_closed_at is None:
                    continue
                self.assertIs(row["recorded"], True)
                self.assertEqual(row["trackingId"], carried[next(built).observation_id])

    def test_a_row_with_no_closed_window_carries_nulls(self) -> None:
        quiet = [row for row in rows_of(self.flagged) if row["windowClosedAt"] is None]
        self.assertEqual(
            sorted(row["status"] for row in quiet),
            ["detected", "detected", "pending", "undetermined"],
        )
        for row in quiet:
            self.assertIsNone(row["recorded"])
            self.assertIsNone(row["trackingId"])

    def test_a_run_without_the_flag_carries_neither_key(self) -> None:
        for row in rows_of(self.bare):
            self.assertFalse(ROW_KEYS & set(row), row)
        self.assertEqual(
            self.bare.to_json(), (GOLDEN / "vdt-changes-timed.json").read_text(encoding="utf-8")
        )
        self.assertEqual(
            self.bare.to_markdown(), (GOLDEN / "vdt-changes-timed.md").read_text(encoding="utf-8")
        )

    def test_the_markdown_obligations_table_grows_only_on_an_aware_run(self) -> None:
        flagged = markdown_subsection(
            markdown_section(self.flagged.to_markdown(), "Changes"), "Obligations"
        )
        bare = markdown_subsection(
            markdown_section(self.bare.to_markdown(), "Changes"), "Obligations"
        )
        self.assertIn("| KEV tracking IDs | Recorded | Tracking ID |", flagged)
        self.assertIn(RECORDED_ROW_SENTENCE, flagged)
        self.assertEqual(len(obligation_table(self.flagged)), 6)
        self.assertNotIn("Recorded", bare)
        self.assertNotIn(RECORDED_ROW_SENTENCE, bare)
        self.assertEqual(len(markdown_table_list(bare, 17, "Change")), 6)

    def test_json_and_markdown_agree(self) -> None:
        rows = rows_of(self.flagged)
        table = obligation_table(self.flagged)
        self.assertEqual(len(table), len(rows))
        for row, cells in zip(rows, table, strict=True):
            with self.subTest(row=(row["changeId"], row["resourceId"])):
                self.assertEqual(cells[0], row["changeId"])
                self.assertEqual(cells[1], f"{row['resourceType']}:{row['resourceId']}")
                recorded = {None: "n/a", True: "yes", False: "no"}[row["recorded"]]
                self.assertEqual(cells[17:], (recorded, row["trackingId"] or "n/a"))
        assert_markdown_carries_the_json(self, self.flagged)

    def test_an_unrecorded_window_reads_recorded_false_with_no_tracking_id(self) -> None:
        # The task 4 seam: a store that holds no record for a closed window hands None for it.
        projection = self.flagged.metadata.changes
        assert projection is not None
        recorded = dict(self.flagged.metadata.change_gap_records or {})
        first = next(iter(recorded))
        recorded[first] = None

        block = projection.to_dict(gap_records=recorded)
        lines: list[str] = []
        markdown_module.write_changes(
            lines.append, replace(self.flagged.metadata, change_gap_records=recorded)
        )

        index = projection.obligations.index(first)
        self.assertIs(block["obligations"][index]["recorded"], False)
        self.assertIsNone(block["obligations"][index]["trackingId"])
        rows = markdown_table_list(
            markdown_subsection("\n".join(lines), "Obligations"), 19, "Change"
        )
        self.assertEqual(rows[index][17:], ("no", "n/a"))

    def test_the_mapping_names_every_closed_window_and_no_other(self) -> None:
        projection = self.flagged.metadata.changes
        assert projection is not None
        recorded = dict(self.flagged.metadata.change_gap_records or {})
        first = next(iter(recorded))
        open_row = next(row for row in projection.obligations if row.window_closed_at is None)
        foreign = compile_timed(as_of=datetime(2026, 9, 20, tzinfo=UTC)).metadata.changes
        assert foreign is not None
        foreign_row = next(
            row
            for row in foreign.obligations
            if row.window_closed_at is not None and row not in recorded
        )
        for name, mapping in (
            ("missing", {key: value for key, value in recorded.items() if key != first}),
            ("an open row", {**recorded, open_row: None}),
            ("a foreign row", {**recorded, foreign_row: None}),
        ):
            with (
                self.subTest(mapping=name),
                self.assertRaisesRegex(
                    ValueError,
                    "^gap_records must name every closed window of the projection and no other$",
                ),
            ):
                projection.to_dict(gap_records=mapping)

    def test_without_a_mapping_the_block_is_the_pr_1_block(self) -> None:
        projection = self.bare.metadata.changes
        assert projection is not None
        self.assertEqual(projection.to_dict(), projection.to_dict(gap_records=None))
        golden = json.loads((GOLDEN / "vdt-changes-timed.json").read_text(encoding="utf-8"))
        self.assertEqual(
            self.bare.document["x-complyroll"]["changes"], golden["x-complyroll"]["changes"]
        )


class ChangeGapRequestTests(unittest.TestCase):
    """The request document never carries a gap: the same bytes with the flag or without."""

    @staticmethod
    def request_bytes(projection: ChangeProjection) -> str:
        return json.dumps(
            detection_request(projection), indent=2, sort_keys=True, ensure_ascii=False
        )

    def test_the_request_document_is_byte_identical_with_and_without_the_flag(self) -> None:
        flagged, flagged_notes = derive_changes_from_artifacts(
            list(TIMED_ARTIFACTS), options=timed_options()
        )
        bare, bare_notes = derive_changes_from_artifacts(
            list(TIMED_ARTIFACTS), options=timed_options(flag=False)
        )
        self.assertEqual(self.request_bytes(flagged), self.request_bytes(bare))
        self.assertEqual(flagged_notes, bare_notes)
        # The report's own projection asks for the same resources, flag or not.
        report = timed_set().changes
        assert report is not None
        self.assertEqual(self.request_bytes(report), self.request_bytes(bare))

    def test_the_request_rows_never_carry_the_row_keys(self) -> None:
        projection, _ = derive_changes_from_artifacts(
            list(TIMED_ARTIFACTS), options=timed_options()
        )
        document = detection_request(projection)
        rows = [row for request in document["requests"] for row in request["resources"]]
        self.assertTrue(rows)
        for row in rows:
            self.assertFalse(ROW_KEYS & set(row), row)

    def test_derive_request_changes_ignores_the_flag(self) -> None:
        evidence = timed_evidence()
        flagged, _ = derive_request_changes(evidence, (), TIMED_CHANGE_SET, options=timed_options())
        bare, _ = derive_request_changes(
            evidence, (), TIMED_CHANGE_SET, options=timed_options(flag=False)
        )
        self.assertEqual(self.request_bytes(flagged), self.request_bytes(bare))


# *--- Cases ---*


class ChangeGapCaseTests(unittest.TestCase):
    """Decision 12: one case per change, listing every resource and observation of it."""

    def test_one_case_lists_every_resource_and_observation_id_of_its_change(self) -> None:
        report = compile_timed(changes=change_set_of(TWO_RESOURCE_CHANGE))
        projection = report.metadata.changes
        assert projection is not None
        self.assertEqual(
            [(row.resource.resource_id, row.status) for row in projection.obligations],
            [(HELPERS, ObligationStatus.LAPSED), (LEGACY, ObligationStatus.LAPSED)],
        )
        gaps = change_gap_observations(projection, ingested_at=TIMED_OPTIONS["as_of"])
        rows = rows_of(report)
        (tracking_id,) = {row["trackingId"] for row in rows}
        self.assertEqual(report.metadata.change_gaps, (tracking_id,))
        record = by_tracking_id(report)[tracking_id]
        extension = record["x-complyroll"]
        self.assertEqual(
            extension["resources"],
            [
                {"resourceId": HELPERS, "resourceType": "file"},
                {"resourceId": LEGACY, "resourceType": "file"},
            ],
        )
        self.assertCountEqual(extension["observationIds"], [item.observation_id for item in gaps])
        self.assertEqual({item.context_key for item in gaps}, {change_gap_context_key("CHG-3001")})
        self.assertEqual(record["detection"]["detectedAt"], "2026-09-02T12:00:00Z")
        assert_markdown_carries_the_json(self, report)

    def test_two_changes_are_two_cases(self) -> None:
        report = compile_timed()
        closed = [row for row in rows_of(report) if row["windowClosedAt"] is not None]
        self.assertEqual(len({row["trackingId"] for row in closed}), 2)
        self.assertEqual(len(report.metadata.change_gaps), 2)

    def test_a_gap_record_reads_as_the_change_gap_it_is(self) -> None:
        report = compile_timed()
        records = by_tracking_id(report)
        for change_id, resource, closed_at, _ in CLOSED_ROWS:
            with self.subTest(change=change_id):
                (row,) = [item for item in rows_of(report) if item["changeId"] == change_id]
                description = records[row["trackingId"]]["vulnerabilityDescription"]
                self.assertEqual(
                    description,
                    f"change-detection-gap: VDR-CSO-DAC window for {resource} after change "
                    f"{change_id} closed {closed_at} with no verification recorded (VDR-CSO-FAV)",
                )


# *--- Goldens ---*


class ChangeGapGoldenTests(unittest.TestCase):
    """The `vdt-change-gaps` pair."""

    @classmethod
    def setUpClass(cls) -> None:
        cls.vdt = compile_timed()

    def test_each_closed_window_became_the_gap_record_it_names(self) -> None:
        # Asserted on a fresh compile, apart from the golden, so a refresh cannot move one.
        self.assertEqual(
            tuple(
                (
                    row["changeId"],
                    f"{row['resourceType']}:{row['resourceId']}",
                    row["windowClosedAt"],
                    row["trackingId"],
                )
                for row in rows_of(self.vdt)
                if row["windowClosedAt"] is not None
            ),
            CLOSED_ROWS,
        )
        self.assertEqual(
            self.vdt.metadata.change_gaps, tuple(sorted(item[3] for item in CLOSED_ROWS))
        )
        self.assertLessEqual({item[3] for item in CLOSED_ROWS}, set(by_tracking_id(self.vdt)))

    def test_the_library_compiles_the_golden(self) -> None:
        self.assertEqual(
            self.vdt.to_json(), (GOLDEN / "vdt-change-gaps.json").read_text(encoding="utf-8")
        )
        self.assertEqual(
            self.vdt.to_markdown(), (GOLDEN / "vdt-change-gaps.md").read_text(encoding="utf-8")
        )
        assert_markdown_carries_the_json(self, self.vdt)

    def test_the_command_line_cuts_the_golden_and_exits_3(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            json_path = Path(directory) / "report.json"
            markdown_path = Path(directory) / "report.md"

            code, out, err = run(
                [*CHANGE_GAP_ARGUMENTS, "-o", str(json_path), "--markdown", str(markdown_path)]
            )

            self.assertEqual(code, 3, msg=err)
            self.assertEqual(out, "")
            self.assertNotIn("error:", err)
            self.assertEqual(json_path.read_bytes(), (GOLDEN / "vdt-change-gaps.json").read_bytes())
            self.assertEqual(
                markdown_path.read_bytes(), (GOLDEN / "vdt-change-gaps.md").read_bytes()
            )

    def test_the_golden_validates_against_its_schema(self) -> None:
        result = validate_bundled_report_bytes(
            ReportSchema.VULNERABILITY_DETAIL, (GOLDEN / "vdt-change-gaps.json").read_bytes()
        )
        self.assertTrue(result.is_valid, result.issues)
        self.assertTrue(self.vdt.validation.is_valid)

    def test_the_golden_differs_from_vdt_changes_timed_only_by_its_gaps(self) -> None:
        gaps = json.loads((GOLDEN / "vdt-change-gaps.json").read_text(encoding="utf-8"))
        plain = json.loads((GOLDEN / "vdt-changes-timed.json").read_text(encoding="utf-8"))

        self.assertEqual(without_change_gaps(gaps), plain)
        self.assertEqual(gaps["x-complyroll"]["parserVersions"]["complyroll.change"], "1")
        self.assertEqual(len(gaps["vulnerabilities"]) - len(plain["vulnerabilities"]), 2)

    def test_only_the_change_gap_golden_carries_the_row_keys(self) -> None:
        with_keys: set[str] = set()
        for path in sorted(GOLDEN.glob("*.json")):
            document = json.loads(path.read_text(encoding="utf-8"))
            extension = document.get("x-complyroll") if isinstance(document, dict) else None
            changes = extension.get("changes") if isinstance(extension, dict) else None
            rows = changes.get("obligations", ()) if isinstance(changes, dict) else ()
            if any(ROW_KEYS & set(row) for row in rows):
                with_keys.add(path.stem)
        self.assertEqual(with_keys, set(CHANGE_GAP_GOLDENS))


class ChangeGapReportKindTests(unittest.TestCase):
    """AVI and historical carry the same block and record as the VDT, from one record set."""

    def test_every_report_carries_the_same_block_and_record(self) -> None:
        reports = {kind: compile_timed(kind) for kind in REPORT_KINDS}
        blocks = {
            kind: report.document["x-complyroll"]["changes"] for kind, report in reports.items()
        }
        self.assertEqual(blocks["avi"], blocks["vdt"])
        self.assertEqual(blocks["historical"], blocks["vdt"])
        gaps = {row["trackingId"] for row in blocks["vdt"]["obligations"]} - {None}
        self.assertEqual(len(gaps), 2)
        vdt = by_tracking_id(reports["vdt"])
        historical = by_tracking_id(reports["historical"])
        for tracking_id in gaps:
            with self.subTest(record=tracking_id):
                self.assertEqual(historical[tracking_id], vdt[tracking_id])
        # Nothing accepts a gap here, so the AVI report lists none of them.
        self.assertFalse(gaps & set(by_tracking_id(reports["avi"])))
        for kind, report in reports.items():
            with self.subTest(report=kind):
                self.assertEqual(report.metadata.change_gaps, tuple(sorted(gaps)))

    def test_the_attestation_sentence_names_the_change_window(self) -> None:
        section = markdown_section(compile_timed().to_markdown(), "Detection time attestation")
        self.assertEqual(section.strip(), CHANGE_SENTENCE)


# *--- Command Line ---*


class ChangeGapCommandTests(unittest.TestCase):
    """`--record-change-gaps` on the three stateless report commands."""

    def setUp(self) -> None:
        directory = tempfile.TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        self.workspace = Path(directory.name)

    def test_a_recorded_change_gap_exits_3_on_every_report_command(self) -> None:
        for kind in REPORT_KINDS:
            with self.subTest(report=kind):
                code, out, err = run([*timed_changes_argv(kind), CHANGE_FLAG])

                self.assertEqual(code, 3, msg=err)
                self.assertNotIn("error:", err)
                rows = json.loads(out)["x-complyroll"]["changes"]["obligations"]
                self.assertEqual(
                    [row["recorded"] for row in rows], [True, None, True, None, None, None]
                )

    def test_a_coverage_gap_alone_exits_3_and_moves_no_row(self) -> None:
        code, out, err = run([*timed_changes_argv(), COVERAGE_FLAG])

        self.assertEqual(code, 3, msg=err)
        extension = json.loads(out)["x-complyroll"]
        self.assertEqual(
            {window["recorded"] for window in extension["coverage"]["windows"]}, {True}
        )
        for row in extension["changes"]["obligations"]:
            self.assertFalse(ROW_KEYS & set(row))

    def test_both_flags_exit_3_once_and_carry_both_kinds(self) -> None:
        code, out, err = run([*timed_changes_argv(), COVERAGE_FLAG, CHANGE_FLAG])

        self.assertEqual(code, 3, msg=err)
        self.assertNotIn("error:", err)
        extension = json.loads(out)["x-complyroll"]
        windows = extension["coverage"]["windows"]
        rows = extension["changes"]["obligations"]
        self.assertEqual({window["recorded"] for window in windows}, {True})
        self.assertEqual([row["recorded"] for row in rows], [True, None, True, None, None, None])
        coverage_cases = {window["trackingId"] for window in windows}
        change_cases = {row["trackingId"] for row in rows} - {None}
        self.assertEqual((len(coverage_cases), len(change_cases)), (2, 2))
        self.assertFalse(coverage_cases & change_cases)

    def test_neither_flag_exits_0_with_the_golden_bytes(self) -> None:
        code, out, err = run(timed_changes_argv())

        self.assertEqual(code, 0, msg=err)
        self.assertEqual(out, (GOLDEN / "vdt-changes-timed.json").read_text(encoding="utf-8"))

    def test_both_flags_with_nothing_closed_exit_0(self) -> None:
        argv = list(timed_changes_argv())
        argv[argv.index("--changes") + 1] = str(write_changes(self.workspace, PENDING_CHANGE))
        argv[argv.index("--inventory") + 1] = str(
            write_inventory(
                self.workspace, host("lab-later-01", expectedSince="2026-09-03T00:00:00Z")
            )
        )
        code, out, err = run([*argv, COVERAGE_FLAG, CHANGE_FLAG])

        self.assertEqual(code, 0, msg=err)
        extension = json.loads(out)["x-complyroll"]
        self.assertEqual(extension["coverage"]["windows"], [])
        rows = extension["changes"]["obligations"]
        self.assertEqual([(row["recorded"], row["trackingId"]) for row in rows], [(None, None)])

    def test_the_change_flag_ignores_a_coverage_window(self) -> None:
        # Coverage windows close in the timed run, but only the change flag is given.
        argv = list(timed_changes_argv())
        argv[argv.index("--changes") + 1] = str(write_changes(self.workspace, PENDING_CHANGE))
        code, out, err = run([*argv, CHANGE_FLAG])

        self.assertEqual(code, 0, msg=err)
        extension = json.loads(out)["x-complyroll"]
        self.assertTrue(extension["coverage"]["windows"])
        self.assertEqual([row["recorded"] for row in extension["changes"]["obligations"]], [None])

    def test_the_coverage_flag_ignores_a_change_window(self) -> None:
        # A host expected after as-of closes no coverage window, but its change lapses.
        inventory = write_inventory(
            self.workspace, host("lab-later-01", expectedSince="2026-09-01T00:00:00Z")
        )
        changes = write_changes(
            self.workspace,
            {
                **PENDING_CHANGE,
                "occurredAt": "2026-08-10T00:00:00Z",
                "detectBy": "2026-08-11T00:00:00Z",
                "resources": [{"resourceType": "host", "resourceId": "lab-later-01"}],
            },
        )
        base = [*REPORT_ARGUMENTS, "--inventory", str(inventory), "--changes", str(changes)]
        for flag, status in ((COVERAGE_FLAG, 0), (CHANGE_FLAG, 3)):
            with self.subTest(flag=flag):
                code, out, err = run([*base, flag])

                self.assertEqual(code, status, msg=err)
                self.assertEqual(json.loads(out)["x-complyroll"]["coverage"]["windows"], [])

    def test_a_failed_publish_exits_1_and_never_3(self) -> None:
        missing = self.workspace / "missing" / "report.json"
        code, _, err = run([*CHANGE_GAP_ARGUMENTS, "-o", str(missing)])

        self.assertEqual(code, 1)
        self.assertIn("error: output_write_failed", err)
        self.assertFalse(missing.exists())

    def test_the_flag_without_changes_is_refused_and_writes_nothing(self) -> None:
        for kind, argv in (
            ("vdt", REPORT_ARGUMENTS),
            ("avi", AVI_ARGUMENTS),
            ("historical", HISTORICAL_ARGUMENTS),
        ):
            for extra in ((), ("--inventory", str(TIMED_INVENTORY))):
                with (
                    self.subTest(report=kind, inventory=bool(extra)),
                    mock.patch.object(cli_module, "load_inventory", side_effect=AssertionError),
                ):
                    json_path = self.workspace / "report.json"

                    code, out, err = run([*argv, *extra, CHANGE_FLAG, "-o", str(json_path)])

                    self.assertEqual(code, 1)
                    self.assertEqual(out, "")
                    self.assertEqual(
                        err,
                        f"error: invalid_option: report {kind} {CHANGE_FLAG} needs --changes: a "
                        "change gap is the closed window of a declared change\n",
                    )
                    self.assertFalse(json_path.exists())

    def test_help_states_what_recording_a_change_gap_does(self) -> None:
        for kind in REPORT_KINDS:
            with self.subTest(report=kind):
                text = " ".join(help_text(["report", kind]).split())
                self.assertIn(
                    f"{CHANGE_FLAG} record each change window that closed with no verification "
                    "as a VDR-CSO-FAV system record; needs --changes; exits 3 when one is "
                    "recorded",
                    text,
                )


class PersistedChangeGapRefusalTests(PersistedStoreTestCase):
    """A store never takes the flag: no report run records a change gap into it."""

    def test_the_flag_beside_a_store_is_refused_and_the_store_is_untouched(self) -> None:
        self.ingest_fixtures()
        before = self.database.read_bytes()
        for kind in REPORT_KINDS:
            argv = ["report", kind, "--db", str(self.database), "--class", "C"]
            argv += ["--package-uri", "https://example.test/cpo", "--as-of", "2026-08-21T12:00:00Z"]
            if kind != "historical":
                argv += ["--from", "2026-08-01T00:00:00Z", "--to", "2026-08-31T23:59:59Z"]
            argv += ["--inventory", str(TIMED_INVENTORY)]
            for extra, named in (
                ((), CHANGE_FLAG),
                (("--changes", str(TIMED_CHANGES)), f"--changes, {CHANGE_FLAG}"),
            ):
                with self.subTest(report=kind, named=named):
                    code, out, err = run([*argv, *extra, CHANGE_FLAG])

                    self.assertEqual(code, 1)
                    self.assertEqual(out, "")
                    self.assertEqual(
                        err,
                        f"error: invalid_option: report {kind} takes either --db or {named}, "
                        "never both\n",
                    )
        self.assertEqual(self.database.read_bytes(), before)


# *--- Writer Seam ---*


class DeriveReportChangesTests(unittest.TestCase):
    """`derive_report_changes`: the projection `cases changes` records gaps from (task 3)."""

    def evidence(self) -> list[Any]:
        return timed_evidence()

    def test_it_derives_the_projection_a_report_derives(self) -> None:
        report_options = timed_options()
        projection = derive_report_changes(
            self.evidence(),
            TIMED_CHANGE_SET,
            TIMED_INVENTORY_SET,
            report_options.profile,
            report_options.as_of,
        )
        self.assertEqual(projection, timed_set().changes)
        self.assertEqual(
            change_gap_observations(projection, ingested_at=report_options.as_of),
            change_gap_observations(
                timed_set().changes,
                ingested_at=report_options.as_of,  # type: ignore[arg-type]
            ),
        )

    def test_a_system_record_never_verifies_what_it_derives(self) -> None:
        report_options = timed_options(coverage=True)
        record_set = timed_set(coverage=True)
        assert record_set.coverage is not None and record_set.changes is not None
        gaps = [
            *coverage_gap_observations(record_set.coverage, ingested_at=report_options.as_of),
            *change_gap_observations(record_set.changes, ingested_at=report_options.as_of),
        ]
        projection = derive_report_changes(
            [*self.evidence(), *gaps],
            TIMED_CHANGE_SET,
            TIMED_INVENTORY_SET,
            report_options.profile,
            report_options.as_of,
        )
        self.assertEqual(projection, record_set.changes)

    def test_it_refuses_a_change_file_the_policy_cannot_read(self) -> None:
        report_options = timed_options()
        with (
            mock.patch.object(records_module, "select_policy", stripped_policy("VDR-CSO-DAC")),
            self.assertRaises(ReportCompileError) as caught,
        ):
            derive_report_changes(
                self.evidence(),
                TIMED_CHANGE_SET,
                TIMED_INVENTORY_SET,
                report_options.profile,
                report_options.as_of,
            )
        self.assertEqual(
            [item.code for item in caught.exception.diagnostics], ["change_rule_unavailable"]
        )

    def test_an_empty_store_without_the_rule_derives_an_empty_projection(self) -> None:
        report_options = timed_options()
        empty = StoredChangeSet(changes=(), names=(), digests=())
        with mock.patch.object(records_module, "select_policy", stripped_policy("VDR-CSO-DAC")):
            projection = derive_report_changes(
                self.evidence(),
                empty,
                TIMED_INVENTORY_SET,
                report_options.profile,
                report_options.as_of,
            )
        self.assertIsNone(projection.force)
        self.assertEqual(projection.obligations, ())
        self.assertEqual(change_gap_observations(projection, ingested_at=report_options.as_of), ())

    def test_it_refuses_an_unusable_clock_by_name(self) -> None:
        report_options = timed_options()
        unusable = observation(at=datetime(1, 1, 1, tzinfo=timezone(timedelta(hours=1))))
        with self.assertRaises(ReportCompileError) as caught:
            derive_report_changes(
                [unusable],
                TIMED_CHANGE_SET,
                TIMED_INVENTORY_SET,
                report_options.profile,
                report_options.as_of,
            )
        self.assertEqual(
            [item.code for item in caught.exception.diagnostics], ["clock_out_of_range"]
        )

    def test_it_checks_its_arguments(self) -> None:
        report_options = timed_options()
        wrong: Any = "changes.json"
        naive = datetime(2026, 9, 3, 12)
        for name, arguments, error in (
            (
                "change set",
                (wrong, TIMED_INVENTORY_SET, report_options.profile, report_options.as_of),
                TypeError,
            ),
            (
                "inventory",
                (TIMED_CHANGE_SET, wrong, report_options.profile, report_options.as_of),
                TypeError,
            ),
            (
                "profile",
                (TIMED_CHANGE_SET, TIMED_INVENTORY_SET, wrong, report_options.as_of),
                TypeError,
            ),
            (
                "as-of",
                (TIMED_CHANGE_SET, TIMED_INVENTORY_SET, report_options.profile, naive),
                ValueError,
            ),
        ):
            with self.subTest(argument=name), self.assertRaises(error):
                derive_report_changes((), *arguments)


if __name__ == "__main__":
    unittest.main()
