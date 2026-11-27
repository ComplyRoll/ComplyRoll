# ******************************************************************************
# *Title: Response Gap Tests*
# *Author: Kyle Versluis*
# *Description: The recurrence warning and the response gap derivations.*
# ******************************************************************************
"""Tests for remediations that did not hold and lapsed attestations (ADR 0019)."""

# *--- Imports ---*

from __future__ import annotations

import json
import unittest
from collections.abc import Sequence
from dataclasses import dataclass, replace
from datetime import UTC, datetime, timedelta, timezone
from typing import Any

from test_cli import (
    KEV_ARGUMENTS,
    KEV_AS_OF,
    KEV_PERIOD,
    RECURRENCE_ARGUMENTS,
    RECURRENCE_ARTIFACTS,
    RECURRENCE_EVALUATIONS,
    PersistedStoreTestCase,
    run,
)
from test_coverage import observation, policy
from test_coverage_gap_evaluations import minted_reserved_types, system_observation
from test_reports import AS_OF, EXAMPLES, GOLDEN, options

from complyroll.correlation import group_open_observations
from complyroll.events import EventRepository
from complyroll.events.contracts import TRACKING_ID_PATTERN
from complyroll.history import CaseState, fold_all_cases
from complyroll.models import (
    RESERVED_SOURCE_TYPE_PREFIX,
    Observation,
    ObservationDisposition,
    ObservationOrigin,
)
from complyroll.policy import CertificationClass, TimeframeUnit
from complyroll.reports import (
    REPORT_DIAGNOSTIC_CODES,
    CompiledRecordSet,
    DetectionAttestation,
    ReportDiagnostic,
    ReportOptions,
    compile_record_set,
    compile_record_set_from_history,
    parse_evaluations,
    project_vdt,
)
from complyroll.reports import checks as checks_module
from complyroll.reports import markdown as markdown_module
from complyroll.reports import records as records_module
from complyroll.reports import response_gaps as response_gaps_module
from complyroll.reports.response_gaps import (
    ATTESTATION_LAPSE_DESCRIPTION,
    ATTESTATION_LAPSE_METADATA_KEYS,
    ATTESTATION_LAPSE_RECORD_ID,
    ATTESTATION_LAPSE_SOURCE_TYPE,
    RECURRENCE_DESCRIPTION,
    RECURRENCE_METADATA_KEYS,
    RECURRENCE_PARSER_NAME,
    RECURRENCE_PARSER_VERSION,
    RECURRENCE_RECORD_ID,
    RECURRENCE_SOURCE_TYPE,
    AttestationLapse,
    attestation_lapse,
    attestation_lapse_observation,
    attestation_lapses,
    first_sighting,
    recurrence_case_tracking_id,
    recurrence_context_key,
    recurrence_observations,
    remediation_recurrence,
    remediation_recurrences,
)
from complyroll.schemas import ReportSchema, validate_bundled_report_bytes
from complyroll.store import SQLiteEventStore

# *--- Fixtures ---*

RECORD = "CVE-2099-0100"
#: The scan that found the weakness, the remediation, and a later scan that found it again.
FIRST_SEEN = datetime(2026, 8, 2, 9, 0, tzinfo=UTC)
REMEDIATED_TEXT = "2026-08-05T12:00:00Z"
REMEDIATED_AT = datetime(2026, 8, 5, 12, 0, tzinfo=UTC)
BACK_AT = datetime(2026, 8, 10, 9, 0, tzinfo=UTC)
LATER_AT = datetime(2026, 8, 12, 9, 0, tzinfo=UTC)
RECURRENCE = "recurrence_after_remediation"
#: Values no default would produce, so a record shows they came from the evaluation.
EVALUATION: dict[str, Any] = {
    "completedAt": REMEDIATED_TEXT,
    "isInternetReachable": False,
    "isLikelyExploitable": True,
    "pain": 2,
    "potentialAgencyImpact": "SYNTHETIC. A flawed package on one lab host.",
    "rationale": "SYNTHETIC. The package was upgraded and the next scan was clean.",
    "evaluator": "Example Provider vulnerability team (synthetic recurrence fixture)",
    "disposition": "remediated",
}
#: The stateless golden pair carrying the warning, and every golden that does.
WARNING_GOLDEN = "vdt-recurrence-warning"
WARNING_GOLDENS = (f"{WARNING_GOLDEN}.json", f"{WARNING_GOLDEN}.md")
#: When the fold tests ingest both scans, before any evaluation.
INGEST_TEXT = "2026-09-13T00:00:00Z"
#: The dispositions that are not a remediation, each with the fields its consistency needs.
NOT_REMEDIATED: tuple[dict[str, Any], ...] = (
    {"disposition": "fully_mitigated"},
    {"disposition": "partially_mitigated"},
    {"disposition": "false_positive"},
    {"disposition": "accepted", "acceptanceRationale": "SYNTHETIC. Risk accepted."},
    {"disposition": None},
)


def fail(resource_id: str, at: datetime | None, *, record: str = RECORD) -> Observation:
    """Return one open artifact observation of the weakness on a resource."""
    return observation(resource_id, at, ObservationDisposition.OPEN, record=record)


def evaluations_of(record: str = RECORD, **overrides: object) -> Any:
    """Parse one evaluation of the synthetic weakness through the bounded reader."""
    entry: dict[str, Any] = {
        "match": {"sourceRecordId": record, "sourceType": "sarif", "contextKey": "synthetic"},
        **EVALUATION,
        **overrides,
    }
    entry = {key: value for key, value in entry.items() if value is not None}
    return parse_evaluations(json.dumps({"evaluations": [entry]}).encode("utf-8"))


def compile_of(
    observations: Sequence[Observation], *, evaluated: bool = True, **overrides: object
) -> CompiledRecordSet:
    """Match and compile exactly as the stateless front half does."""
    groups = group_open_observations(observations)
    evaluations = evaluations_of(**overrides) if evaluated else None
    matches = records_module._match_evaluations(groups, evaluations)
    return compile_record_set(
        artifacts=(),
        observations=tuple(observations),
        ingest_diagnostics=(),
        evaluations_by_tracking_id=matches,
        attestation=DetectionAttestation(),
        options=options(detected_at=None),
    )


def replay_options() -> ReportOptions:
    """Return the options of the recurrence golden's run, for a compile from a store."""
    return ReportOptions(
        certification_class=CertificationClass.C,
        package_uri="https://example.test/cpo",
        as_of=datetime(2026, 9, 15, 12, 0, tzinfo=UTC),
        period_from=datetime(2026, 9, 1, tzinfo=UTC),
        period_to=datetime(2026, 9, 30, 23, 59, 59, tzinfo=UTC),
    )


def recurrences(record_set: CompiledRecordSet) -> list[ReportDiagnostic]:
    return [item for item in record_set.diagnostics if item.code == RECURRENCE]


def tracking_id(*observations: Observation) -> str:
    (group,) = group_open_observations(observations)
    return group.tracking_id


# *--- Recurrence Warning ---*


class RecurrenceWarningTests(unittest.TestCase):
    """A remediated record with a later open observation is warned about, never reopened."""

    def test_the_code_is_registered(self) -> None:
        self.assertIn(RECURRENCE, REPORT_DIAGNOSTIC_CODES)

    def test_a_later_open_observation_warns_and_the_disposition_stands(self) -> None:
        found = (fail("lab-01", FIRST_SEEN), fail("lab-01", BACK_AT), fail("lab-02", LATER_AT))
        record_set = compile_of(found)
        (warning,) = recurrences(record_set)
        self.assertEqual(warning.level.value, "warning")
        self.assertEqual(warning.location, RECORD)
        self.assertEqual(
            warning.message,
            f"{tracking_id(*found)} is recorded remediated at {REMEDIATED_TEXT}, and 2 open "
            "observation(s) of it were detected after that instant, the earliest at "
            "2026-08-10T09:00:00Z on host:lab-01; the remediation did not hold, and the record "
            "keeps its disposition until an evaluation changes it",
        )
        (record,) = project_vdt(record_set).document["vulnerabilities"]
        self.assertEqual(record["finalDisposition"], "Remediated")

    def test_the_warning_reaches_json_and_markdown(self) -> None:
        report = project_vdt(compile_of((fail("lab-01", FIRST_SEEN), fail("lab-01", BACK_AT))))
        codes = [item["code"] for item in report.document["x-complyroll"]["diagnostics"]]
        self.assertIn(RECURRENCE, codes)
        self.assertIn(RECURRENCE, report.to_markdown())

    def test_a_detection_at_the_remediation_instant_is_not_a_recurrence(self) -> None:
        record_set = compile_of((fail("lab-01", FIRST_SEEN), fail("lab-01", REMEDIATED_AT)))
        self.assertEqual(recurrences(record_set), [])

    def test_a_detection_one_second_after_is_a_recurrence(self) -> None:
        after = datetime(2026, 8, 5, 12, 0, 1, tzinfo=UTC)
        record_set = compile_of((fail("lab-01", FIRST_SEEN), fail("lab-01", after)))
        self.assertEqual(len(recurrences(record_set)), 1)

    def test_only_earlier_detections_warn_nothing(self) -> None:
        record_set = compile_of((fail("lab-01", FIRST_SEEN), fail("lab-02", FIRST_SEEN)))
        self.assertEqual(recurrences(record_set), [])

    def test_no_other_disposition_is_a_remediation(self) -> None:
        found = (fail("lab-01", FIRST_SEEN), fail("lab-01", BACK_AT))
        for overrides in NOT_REMEDIATED:
            with self.subTest(disposition=overrides["disposition"]):
                self.assertEqual(recurrences(compile_of(found, **overrides)), [])

    def test_a_record_closed_as_remediated_is_a_remediation(self) -> None:
        found = (fail("lab-01", FIRST_SEEN), fail("lab-01", BACK_AT))
        record_set = compile_of(found, disposition="closed", closedDisposition="remediated")
        self.assertEqual(len(recurrences(record_set)), 1)

    def test_an_untimed_member_cannot_be_ordered_and_is_warned_about(self) -> None:
        found = (fail("lab-01", FIRST_SEEN), fail("lab-02", None))
        (warning,) = recurrences(compile_of(found))
        self.assertEqual(
            warning.message,
            f"{tracking_id(*found)} is recorded remediated at {REMEDIATED_TEXT}, and 1 open "
            "observation(s) of it declare no source timestamp, so they cannot be ordered "
            "against the remediation; whether the remediation held cannot be told, and the "
            "record keeps its disposition until an evaluation changes it",
        )

    def test_timed_and_untimed_members_share_one_warning(self) -> None:
        found = (fail("lab-01", FIRST_SEEN), fail("lab-01", BACK_AT), fail("lab-02", None))
        (warning,) = recurrences(compile_of(found))
        self.assertIn(
            "1 open observation(s) of it were detected after that instant", warning.message
        )
        self.assertIn("1 open observation(s) of it declare no source timestamp", warning.message)
        self.assertIn("; the remediation did not hold,", warning.message)

    def test_an_unevaluated_record_warns_nothing(self) -> None:
        found = (fail("lab-01", FIRST_SEEN), fail("lab-01", BACK_AT))
        self.assertEqual(recurrences(compile_of(found, evaluated=False)), [])


# *--- Recurrence Finder ---*


class RemediationRecurrenceTests(unittest.TestCase):
    """The finder orders what came back and ignores what a remediation explains."""

    def test_recurring_members_are_ordered_by_detection_then_id(self) -> None:
        group = group_open_observations(
            (
                fail("lab-03", LATER_AT),
                fail("lab-02", BACK_AT),
                fail("lab-01", BACK_AT),
                fail("lab-01", FIRST_SEEN),
            )
        )[0]
        found = remediation_recurrence(group, REMEDIATED_AT)
        assert found is not None
        self.assertEqual(
            [(item.resource.resource_id, item.observed_at) for item in found.recurring],
            [("lab-01", BACK_AT), ("lab-02", BACK_AT), ("lab-03", LATER_AT)],
        )
        self.assertEqual(found.untimed, ())
        self.assertEqual(found.remediated_at, REMEDIATED_AT)
        self.assertEqual(found.tracking_id, group.tracking_id)

    def test_nothing_after_the_remediation_finds_nothing(self) -> None:
        (group,) = group_open_observations((fail("lab-01", FIRST_SEEN),))
        self.assertIsNone(remediation_recurrence(group, REMEDIATED_AT))

    def test_an_offset_instant_is_compared_in_utc(self) -> None:
        (group,) = group_open_observations((fail("lab-01", BACK_AT),))
        mountain = timezone(timedelta(hours=-7))
        self.assertIsNone(remediation_recurrence(group, BACK_AT.astimezone(mountain)))
        found = remediation_recurrence(group, FIRST_SEEN.astimezone(mountain))
        assert found is not None
        self.assertEqual(found.remediated_at, FIRST_SEEN)
        self.assertEqual(found.remediated_at.tzinfo, UTC)

    def test_a_system_member_never_recurs(self) -> None:
        system = replace(system_observation(), observed_at=BACK_AT)
        self.assertIs(system.origin, ObservationOrigin.SYSTEM)
        (group,) = group_open_observations((system,))
        self.assertIsNone(remediation_recurrence(group, REMEDIATED_AT))

    def test_a_naive_instant_is_refused(self) -> None:
        (group,) = group_open_observations((fail("lab-01", BACK_AT),))
        with self.assertRaises(ValueError):
            remediation_recurrence(group, datetime(2026, 8, 5, 12, 0))

    def test_a_non_group_is_refused(self) -> None:
        with self.assertRaises(TypeError):
            remediation_recurrence(object(), REMEDIATED_AT)  # type: ignore[arg-type]


# *--- Recurrence Identity ---*


def recurrence_records(
    *found: Observation, remediated_at: datetime = REMEDIATED_AT, ingested_at: datetime = AS_OF
) -> tuple[Observation, ...]:
    """Return the records one remediated group's recurrence mints."""
    (group,) = group_open_observations(found)
    (recurrence,) = remediation_recurrences((group,), {group.tracking_id: remediated_at})
    return recurrence_observations(recurrence, ingested_at=ingested_at)


class RecurrenceIdentityTests(unittest.TestCase):
    """One system record per failed remediation and resource, named by its inputs (D4, F11)."""

    def test_the_constants_are_the_recorded_decision(self) -> None:
        self.assertEqual(RECURRENCE_SOURCE_TYPE, "complyroll.recurrence")
        self.assertEqual(RECURRENCE_RECORD_ID, "remediation-recurrence")
        self.assertEqual(RECURRENCE_PARSER_NAME, "complyroll.recurrence")
        self.assertEqual(RECURRENCE_PARSER_VERSION, "1")
        self.assertTrue(RECURRENCE_SOURCE_TYPE.startswith(RESERVED_SOURCE_TYPE_PREFIX))

    def test_the_tracking_id_rule_is_the_event_layers(self) -> None:
        self.assertEqual(response_gaps_module._TRACKING_ID.pattern, "case-[0-9a-f]{16}")
        self.assertTrue(TRACKING_ID_PATTERN.pattern.startswith("^case-[0-9a-f]{16}"))

    def test_one_record_per_resource_names_its_earliest_recurring_detection(self) -> None:
        found = (
            fail("lab-01", FIRST_SEEN),
            fail("lab-01", LATER_AT),
            fail("lab-01", BACK_AT),
            fail("lab-02", LATER_AT),
        )
        records = recurrence_records(*found)
        self.assertEqual(
            [(item.resource.resource_id, item.observed_at) for item in records],
            [("lab-01", BACK_AT), ("lab-02", LATER_AT)],
        )
        case_id = tracking_id(*found)
        first = records[0]
        self.assertEqual(first.origin, ObservationOrigin.SYSTEM)
        self.assertEqual(first.source_type, RECURRENCE_SOURCE_TYPE)
        self.assertEqual(first.source_tool, "complyroll")
        self.assertEqual(first.source_record_id, RECURRENCE_RECORD_ID)
        self.assertEqual(first.disposition, ObservationDisposition.OPEN)
        self.assertEqual(first.source_severity.value, "unknown")
        self.assertEqual(first.source_identifiers, ())
        self.assertEqual(first.source_artifact_name, "")
        self.assertEqual(first.source_artifact_digest, "")
        self.assertEqual(first.context_key, f"{case_id}:remediated:{REMEDIATED_TEXT}")
        self.assertEqual(first.observation_id, first.derived_observation_id)
        self.assertEqual(first.evidence_ids, (found[2].observation_id,))
        self.assertEqual(
            dict(first.source_metadata),
            {
                "recurrence.caseTrackingId": case_id,
                "recurrence.observationDetectedAt": "2026-08-10T09:00:00Z",
                "recurrence.observationId": found[2].observation_id,
                "recurrence.remediatedAt": REMEDIATED_TEXT,
            },
        )
        self.assertEqual(tuple(sorted(dict(first.source_metadata))), RECURRENCE_METADATA_KEYS)
        self.assertEqual(
            first.title,
            f"remediation of {case_id} recorded {REMEDIATED_TEXT} did not hold: host:lab-01 "
            "detected again 2026-08-10T09:00:00Z (VDR-CSO-FAV)",
        )
        self.assertEqual(first.description, RECURRENCE_DESCRIPTION)

    def test_two_detections_at_one_instant_mint_one_record_for_the_lowest_id(self) -> None:
        low = replace(fail("lab-01", BACK_AT), observation_id="obs/a-low")
        high = replace(fail("lab-01", BACK_AT), observation_id="obs/z-high")
        (record,) = recurrence_records(fail("lab-01", FIRST_SEEN), high, low)
        self.assertEqual(record.metadata_value("recurrence.observationId"), "obs/a-low")

    def test_the_id_holds_across_ingest_time_and_the_observation_id(self) -> None:
        (built,) = recurrence_records(fail("lab-01", FIRST_SEEN), fail("lab-01", BACK_AT))
        (later,) = recurrence_records(
            fail("lab-01", FIRST_SEEN),
            replace(fail("lab-01", BACK_AT), observation_id="obs/reread-by-a-newer-parser"),
            ingested_at=datetime(2026, 9, 30, tzinfo=UTC),
        )
        self.assertEqual(built.observation_id, later.observation_id)
        self.assertNotEqual(built.evidence_ids, later.evidence_ids)

    def test_a_second_failed_remediation_is_a_second_case(self) -> None:
        found = (fail("lab-01", FIRST_SEEN), fail("lab-01", BACK_AT), fail("lab-01", LATER_AT))
        first = recurrence_records(*found)
        second = recurrence_records(*found, remediated_at=datetime(2026, 8, 11, tzinfo=UTC))
        cases = group_open_observations((*first, *second))
        self.assertEqual(len(cases), 2)
        self.assertEqual([len(case.observations) for case in cases], [1, 1])

    def test_every_resource_of_one_failed_remediation_is_one_case(self) -> None:
        records = recurrence_records(
            fail("lab-01", FIRST_SEEN), fail("lab-01", BACK_AT), fail("lab-02", LATER_AT)
        )
        (case,) = group_open_observations(records)
        self.assertEqual([item.resource_id for item in case.resources], ["lab-01", "lab-02"])
        self.assertEqual(case.earliest_observed_at, BACK_AT)

    def test_the_identity_names_the_correlation_id_not_a_provider_override(self) -> None:
        found = (fail("lab-01", FIRST_SEEN), fail("lab-01", BACK_AT))
        record_set = compile_of(found, trackingId="PROVIDER-0100")
        (warning,) = recurrences(record_set)
        case_id = tracking_id(*found)
        self.assertTrue(warning.message.startswith(f"PROVIDER-0100 ({case_id}) is recorded"))
        (record,) = recurrence_records(*found)
        self.assertEqual(recurrence_case_tracking_id(record.context_key), case_id)

    def test_an_untimed_member_and_the_remediation_instant_are_never_recorded(self) -> None:
        (record,) = recurrence_records(
            fail("lab-01", FIRST_SEEN),
            fail("lab-02", None),
            fail("lab-03", REMEDIATED_AT),
            fail("lab-04", BACK_AT),
        )
        self.assertEqual(record.resource.resource_id, "lab-04")

    def test_only_a_group_with_a_remediation_instant_is_read(self) -> None:
        groups = group_open_observations(
            (
                fail("lab-01", FIRST_SEEN),
                fail("lab-01", BACK_AT),
                fail("lab-01", BACK_AT, record="CVE-2099-0200"),
            )
        )
        remediated = {groups[0].tracking_id: REMEDIATED_AT}
        (found,) = remediation_recurrences(groups, remediated)
        self.assertEqual(found.tracking_id, groups[0].tracking_id)
        self.assertEqual(remediation_recurrences(groups, {}), ())

    def test_the_context_key_reads_back_and_refuses_other_keys(self) -> None:
        key = recurrence_context_key("case-0123456789abcdef", REMEDIATED_AT)
        self.assertEqual(key, f"case-0123456789abcdef:remediated:{REMEDIATED_TEXT}")
        self.assertEqual(recurrence_case_tracking_id(key), "case-0123456789abcdef")
        for other in (
            "synthetic",
            "case-0123456789abcdef",
            "case-0123456789abcdef:remediated:",
            "case-0123456789ABCDEF:remediated:x",
            "case-0123456789abcdef:accepted:x",
            "VDR-CSO-DAC:change:CHG-1",
        ):
            with self.subTest(key=other):
                self.assertIsNone(recurrence_case_tracking_id(other))
        with self.assertRaises(ValueError):
            recurrence_context_key("PROVIDER-0100", REMEDIATED_AT)
        with self.assertRaises(ValueError):
            recurrence_context_key("case-0123456789abcdef", datetime(2026, 8, 5))

    def test_the_builder_refuses_what_is_not_a_recurrence(self) -> None:
        (group,) = group_open_observations((fail("lab-01", BACK_AT),))
        for recurring, why in (
            (fail("lab-01", REMEDIATED_AT), "strictly after"),
            (fail("lab-01", None), "untimed"),
            (replace(fail("lab-01", BACK_AT), disposition=ObservationDisposition.PASS), "open"),
        ):
            with self.subTest(why=why):
                found = response_gaps_module.RemediationRecurrence(
                    tracking_id=group.tracking_id,
                    remediated_at=REMEDIATED_AT,
                    recurring=(recurring,),
                    untimed=(),
                )
                with self.assertRaisesRegex(ValueError, why):
                    recurrence_observations(found, ingested_at=AS_OF)


class RecurrenceRecordTests(unittest.TestCase):
    """A recurrence compiles as a system record of its own kind (D6)."""

    def test_its_case_is_detected_at_the_earliest_recurring_detection(self) -> None:
        records = recurrence_records(
            fail("lab-01", FIRST_SEEN), fail("lab-01", LATER_AT), fail("lab-02", BACK_AT)
        )
        record_set = compile_record_set(
            artifacts=(),
            observations=records,
            ingest_diagnostics=(),
            evaluations_by_tracking_id={},
            attestation=DetectionAttestation(),
            options=options(detected_at=None),
        )
        (record,) = record_set.records
        self.assertEqual(record.detected_at, BACK_AT)
        self.assertEqual(record.detected_at_source, "system")
        self.assertEqual([item.rule_id for item in record.deadlines], ["VER-TFR-EVU"])
        markdown = project_vdt(record_set).to_markdown()
        self.assertIn(
            "for a remediation recurrence, from the instant its recurring observation was detected",
            markdown,
        )

    def test_the_kind_tables_name_it(self) -> None:
        self.assertEqual(
            checks_module.system_record_kind(RECURRENCE_SOURCE_TYPE), "remediation recurrence"
        )
        diagnostic = checks_module.evaluation_order_diagnostic(
            tracking_id="case-0000000000000000",
            location="here",
            detected_at=BACK_AT,
            detected_source="system",
            completed_at=REMEDIATED_AT,
            source_type=RECURRENCE_SOURCE_TYPE,
        )
        assert diagnostic is not None
        self.assertTrue(
            diagnostic.message.endswith(
                "; a remediation recurrence is detected when its recurring observation was "
                "detected, so evaluate it at or after that instant, or correct completedAt"
            )
        )


# *--- Lapsed Attestation ---*

CASE_ID = "case-0123456789abcdef"
OTHER_CASE_ID = "case-fedcba9876543210"
#: The ingest `--as-of` of a case's first and second linked observations.
SEEN_AT = datetime(2026, 9, 1, 8, 0, tzinfo=UTC)
SEEN_LATER_AT = datetime(2026, 9, 3, 8, 0, tzinfo=UTC)


@dataclass(frozen=True)
class Link:
    observation_id: str
    observed_at: datetime | None = None


@dataclass(frozen=True)
class Case:
    tracking_id: str = CASE_ID
    links: tuple[Link, ...] = (Link("obs-first"), Link("obs-second"))
    attestation: object | None = None


#: When each linked observation was ingested, as a store records it.
INGESTED = {"obs-first": SEEN_AT, "obs-second": SEEN_LATER_AT, "obs-unlinked": AS_OF}


def evu_close(class_name: str, start: datetime = SEEN_AT) -> datetime:
    """Return the VER-TFR-EVU deadline the pinned dataset gives one class."""
    return policy(class_name).deadline_for_rule("VER-TFR-EVU", start).due_at


class AttestationLapseTests(unittest.TestCase):
    """A run records a lapse when a case is untimed at or past its window close (D5, F1)."""

    def test_the_window_is_read_from_the_dataset_for_each_class(self) -> None:
        for class_name, days in (("B", 7), ("C", 5)):
            with self.subTest(certification_class=class_name):
                timeframe = policy(class_name).rule("VER-TFR-EVU").timeframe
                assert timeframe is not None
                self.assertEqual(timeframe.unit, TimeframeUnit.DAYS)
                self.assertEqual(evu_close(class_name), SEEN_AT + timedelta(days=days))

    def test_an_untimed_case_lapses_at_the_close_and_not_before(self) -> None:
        for class_name in ("B", "C"):
            closed = evu_close(class_name)
            selected = policy(class_name)
            with self.subTest(certification_class=class_name):
                early = closed - timedelta(seconds=1)
                self.assertIsNone(attestation_lapse(Case(), INGESTED, selected, early))
                for as_of in (closed, closed + timedelta(days=30)):
                    found = attestation_lapse(Case(), INGESTED, selected, as_of)
                    self.assertEqual(
                        found,
                        AttestationLapse(
                            tracking_id=CASE_ID,
                            first_seen_at=SEEN_AT,
                            window_closed_at=closed,
                            force="SHOULD",
                        ),
                    )

    def test_a_case_with_no_links_has_no_first_sighting_and_records_nothing(self) -> None:
        late = AS_OF + timedelta(days=365)
        self.assertIsNone(attestation_lapse(Case(links=()), INGESTED, policy("C"), late))
        unread = Case(links=(Link("obs-never-recorded"),))
        self.assertIsNone(first_sighting(unread, INGESTED))
        self.assertIsNone(attestation_lapse(unread, INGESTED, policy("C"), late))

    def test_the_first_sighting_is_the_earliest_linked_ingest(self) -> None:
        case = Case(links=(Link("obs-second"), Link("obs-first"), Link("obs-never-recorded")))
        self.assertEqual(first_sighting(case, INGESTED), SEEN_AT)
        self.assertEqual(first_sighting(Case(links=(Link("obs-second"),)), INGESTED), SEEN_LATER_AT)

    def test_any_timed_link_makes_the_case_timed_inside_or_after_the_window(self) -> None:
        late = evu_close("C") + timedelta(days=30)
        for observed_at in (SEEN_AT, late):
            with self.subTest(observed_at=observed_at):
                case = Case(links=(Link("obs-first"), Link("obs-second", observed_at)))
                self.assertIsNone(attestation_lapse(case, INGESTED, policy("C"), late))

    def test_an_attestation_made_before_any_run_prevents_the_lapse(self) -> None:
        late = evu_close("C") + timedelta(days=30)
        case = Case(attestation=object())
        self.assertIsNone(attestation_lapse(case, INGESTED, policy("C"), late))

    def test_every_case_is_read_in_tracking_id_order(self) -> None:
        late = evu_close("B")
        cases = (Case(tracking_id=OTHER_CASE_ID), Case(links=()), Case())
        found = attestation_lapses(cases, INGESTED, policy("B"), late)
        self.assertEqual([item.tracking_id for item in found], [CASE_ID, OTHER_CASE_ID])

    def test_a_naive_as_of_and_a_non_policy_are_refused(self) -> None:
        with self.assertRaises(ValueError):
            attestation_lapse(Case(), INGESTED, policy("C"), datetime(2026, 9, 30))
        with self.assertRaises(TypeError):
            attestation_lapse(Case(), INGESTED, object(), AS_OF)  # type: ignore[arg-type]


class AttestationLapseIdentityTests(unittest.TestCase):
    """One system record per lapsed case, named by the case and its window close (D5)."""

    def lapse(self, class_name: str = "C") -> AttestationLapse:
        found = attestation_lapse(Case(), INGESTED, policy(class_name), AS_OF + timedelta(days=60))
        assert found is not None
        return found

    def test_the_record_is_the_recorded_decision(self) -> None:
        record = attestation_lapse_observation(self.lapse(), ingested_at=AS_OF)
        closed = evu_close("C")
        self.assertEqual(ATTESTATION_LAPSE_SOURCE_TYPE, "complyroll.attestation")
        self.assertEqual(record.source_type, ATTESTATION_LAPSE_SOURCE_TYPE)
        self.assertEqual(record.source_tool, "complyroll")
        self.assertEqual(record.parser_name, "complyroll.attestation")
        self.assertEqual(record.parser_version, "1")
        self.assertEqual(record.source_record_id, ATTESTATION_LAPSE_RECORD_ID)
        self.assertEqual(record.source_record_id, "attestation-lapse")
        self.assertEqual(record.origin, ObservationOrigin.SYSTEM)
        self.assertEqual(
            (record.resource.resource_type, record.resource.resource_id),
            ("logical", f"case/{CASE_ID}"),
        )
        self.assertEqual(record.context_key, CASE_ID)
        self.assertEqual(record.observed_at, closed)
        self.assertEqual(record.observation_id, record.derived_observation_id)
        self.assertEqual(record.evidence_ids, (f"case:{CASE_ID}",))
        self.assertEqual(record.source_identifiers, ())
        self.assertEqual(
            dict(record.source_metadata),
            {
                "attestation.caseTrackingId": CASE_ID,
                "attestation.firstSeenAt": "2026-09-01T08:00:00Z",
                "attestation.force": "SHOULD",
                "attestation.rule": "VER-TFR-EVU",
                "attestation.windowClosedAt": "2026-09-06T08:00:00Z",
            },
        )
        self.assertEqual(
            tuple(sorted(dict(record.source_metadata))), ATTESTATION_LAPSE_METADATA_KEYS
        )
        self.assertEqual(
            record.title,
            f"detection time of {CASE_ID} was not attested within VER-TFR-EVU from "
            "2026-09-01T08:00:00Z (VDR-CSO-FAV)",
        )
        self.assertEqual(record.description, ATTESTATION_LAPSE_DESCRIPTION)

    def test_the_id_ignores_the_ingest_time_and_moves_with_the_window(self) -> None:
        first = attestation_lapse_observation(self.lapse(), ingested_at=AS_OF)
        rerun = attestation_lapse_observation(self.lapse(), ingested_at=AS_OF + timedelta(days=90))
        other_class = attestation_lapse_observation(self.lapse("B"), ingested_at=AS_OF)
        self.assertEqual(first.observation_id, rerun.observation_id)
        self.assertNotEqual(first.observation_id, other_class.observation_id)
        # One case's lapses share its key, so a second profile's lapse joins the same case.
        self.assertEqual(len(group_open_observations((first, other_class))), 1)

    def test_each_case_is_its_own_lapse_case(self) -> None:
        late = AS_OF + timedelta(days=60)
        lapses = attestation_lapses(
            (Case(), Case(tracking_id=OTHER_CASE_ID)), INGESTED, policy("C"), late
        )
        records = [attestation_lapse_observation(item, ingested_at=AS_OF) for item in lapses]
        self.assertEqual(len(group_open_observations(records)), 2)

    def test_a_window_that_does_not_close_after_the_sighting_is_refused(self) -> None:
        with self.assertRaisesRegex(ValueError, "closes after"):
            attestation_lapse_observation(
                AttestationLapse(CASE_ID, SEEN_AT, SEEN_AT, "SHOULD"), ingested_at=AS_OF
            )
        with self.assertRaisesRegex(ValueError, "correlation tracking id"):
            attestation_lapse_observation(
                AttestationLapse("PROVIDER-1", SEEN_AT, AS_OF, "SHOULD"), ingested_at=AS_OF
            )

    def test_its_case_compiles_as_a_lapsed_attestation(self) -> None:
        record = attestation_lapse_observation(self.lapse(), ingested_at=AS_OF)
        record_set = compile_record_set(
            artifacts=(),
            observations=(record,),
            ingest_diagnostics=(),
            evaluations_by_tracking_id={},
            attestation=DetectionAttestation(),
            options=options(detected_at=None, period_from=None, period_to=None),
        )
        (compiled,) = record_set.records
        self.assertEqual(compiled.detected_at, evu_close("C"))
        self.assertEqual(compiled.detected_at_source, "system")
        self.assertEqual([item.rule_id for item in compiled.deadlines], ["VER-TFR-EVU"])
        self.assertEqual(
            checks_module.system_record_kind(ATTESTATION_LAPSE_SOURCE_TYPE), "lapsed attestation"
        )
        sentence = markdown_module._system_detection_sentence({ATTESTATION_LAPSE_SOURCE_TYPE})
        self.assertIn(
            "for a lapsed attestation, from the instant its evaluation window closed", sentence
        )

    def test_the_walk_finds_all_five_reserved_types(self) -> None:
        self.assertEqual(
            minted_reserved_types(),
            {
                "complyroll.detection-process",
                "complyroll.coverage",
                "complyroll.change",
                RECURRENCE_SOURCE_TYPE,
                ATTESTATION_LAPSE_SOURCE_TYPE,
            },
        )


# *--- Golden Census ---*


class GoldenCensusTests(unittest.TestCase):
    """No fixture behind an existing golden has a remediated record that came back (D11).

    The golden byte comparisons prove the WARNING never reaches an existing golden; this
    names the remediated evaluations the examples hold and why only the new one recurs.
    """

    def test_the_example_remediations_are_a_gap_an_unrepeated_finding_and_the_new_one(
        self,
    ) -> None:
        remediated = []
        for path in sorted(EXAMPLES.glob("evaluations*.json")):
            for entry in json.loads(path.read_text(encoding="utf-8"))["evaluations"]:
                status = entry.get("disposition")
                if status == "remediated" or entry.get("closedDisposition") == "remediated":
                    remediated.append((path.name, entry["match"]["sourceRecordId"]))
        self.assertEqual(
            remediated,
            [
                ("evaluations-coverage.json", "coverage-gap"),
                ("evaluations-kev.json", "CVE-2099-0005"),
                ("evaluations-recurrence.json", "CVE-2099-0101"),
            ],
        )

    def test_only_the_new_goldens_carry_the_warning(self) -> None:
        carrying = {
            path.name
            for path in sorted(GOLDEN.iterdir())
            if RECURRENCE in path.read_text(encoding="utf-8")
        }
        self.assertEqual(carrying, set(WARNING_GOLDENS))


# *--- Warning Golden ---*


class RecurrenceWarningGoldenTests(PersistedStoreTestCase):
    """The `vdt-recurrence-warning` pair, cut statelessly and rebuilt from a store (D11)."""

    def test_the_command_line_cuts_the_golden_and_exits_0(self) -> None:
        json_path = self.workspace / "report.json"
        markdown_path = self.workspace / "report.md"
        code, _, err = run(
            [*RECURRENCE_ARGUMENTS, "-o", str(json_path), "--markdown", str(markdown_path)]
        )
        self.assertEqual(code, 0, msg=err)
        self.assertIn(f"warning: {RECURRENCE}: ", err)
        self.assertEqual(json_path.read_bytes(), (GOLDEN / f"{WARNING_GOLDEN}.json").read_bytes())
        self.assertEqual(markdown_path.read_bytes(), (GOLDEN / f"{WARNING_GOLDEN}.md").read_bytes())

    def test_the_golden_validates_and_keeps_the_remediated_disposition(self) -> None:
        payload = (GOLDEN / f"{WARNING_GOLDEN}.json").read_bytes()
        self.assertTrue(
            validate_bundled_report_bytes(ReportSchema.VULNERABILITY_DETAIL, payload).is_valid
        )
        document = json.loads(payload)
        (record,) = document["vulnerabilities"]
        self.assertEqual(record["finalDisposition"], "Remediated")
        codes = [item["code"] for item in document["x-complyroll"]["diagnostics"]]
        self.assertEqual(codes, [RECURRENCE])

    def test_a_store_reports_the_same_bytes_before_correlating_what_came_back(self) -> None:
        self.build_recurrence_store()
        json_path = self.workspace / "replay.json"
        markdown_path = self.workspace / "replay.md"
        self.succeeds(
            [
                "report",
                "vdt",
                "--db",
                str(self.database),
                *KEV_ARGUMENTS,
                "--as-of",
                KEV_AS_OF,
                *KEV_PERIOD,
                "-o",
                str(json_path),
                "--markdown",
                str(markdown_path),
            ]
        )
        self.assertEqual(json_path.read_bytes(), (GOLDEN / f"{WARNING_GOLDEN}.json").read_bytes())
        self.assertEqual(markdown_path.read_bytes(), (GOLDEN / f"{WARNING_GOLDEN}.md").read_bytes())

    def build_recurrence_store(self) -> None:
        """Ingest the first scan, remediate it, then ingest the scan that found it again."""
        database = str(self.database)
        before, after = RECURRENCE_ARTIFACTS
        self.succeeds(["ingest", before, "--db", database, "--as-of", "2026-09-03T00:00:00Z"])
        self.succeeds(["cases", "correlate", "--db", database])
        self.succeeds(
            ["cases", "evaluate", "--db", database, "--evaluations", str(RECURRENCE_EVALUATIONS)]
        )
        self.succeeds(["ingest", after, "--db", database, "--as-of", "2026-09-13T00:00:00Z"])


# *--- Persisted Remediation Instant ---*


class RemediationInstantFoldTests(PersistedStoreTestCase):
    """History reads the instant from the evaluation in force when remediated was first recorded.

    F3: a re-evaluation that keeps the disposition moves the current `completedAt`, never the
    remediation instant, and no store recording instant reaches the report (ADR 0010).
    """

    def setUp(self) -> None:
        super().setUp()
        self.database_text = str(self.database)
        before, after = RECURRENCE_ARTIFACTS
        self.succeeds(["ingest", before, "--db", self.database_text, "--as-of", INGEST_TEXT])
        self.succeeds(["ingest", after, "--db", self.database_text, "--as-of", INGEST_TEXT])
        self.succeeds(["cases", "correlate", "--db", self.database_text])

    def evaluate(self, **overrides: object) -> None:
        entry: dict[str, Any] = {
            **json.loads(RECURRENCE_EVALUATIONS.read_text(encoding="utf-8"))["evaluations"][0],
            **overrides,
        }
        entry = {key: value for key, value in entry.items() if value is not None}
        path = self.workspace / "evaluations.json"
        path.write_text(json.dumps({"evaluations": [entry]}), encoding="utf-8")
        self.succeeds(["cases", "evaluate", "--db", self.database_text, "--evaluations", str(path)])

    def case(self) -> CaseState:
        with SQLiteEventStore(self.database) as store:
            (case,) = fold_all_cases(EventRepository(store))
        return case

    def warning(self) -> str | None:
        with SQLiteEventStore(self.database) as store:
            record_set = compile_record_set_from_history(
                EventRepository(store), options=replay_options()
            )
        found = recurrences(record_set)
        return None if not found else found[0].message

    def test_the_first_remediated_evaluation_sets_the_instant(self) -> None:
        self.evaluate()
        self.assertEqual(self.case().remediated_at, datetime(2026, 9, 5, 15, 0, tzinfo=UTC))
        message = self.warning()
        assert message is not None
        self.assertIn("recorded remediated at 2026-09-05T15:00:00Z", message)

    def test_a_re_evaluation_that_keeps_remediated_keeps_the_instant(self) -> None:
        self.evaluate()
        self.evaluate(completedAt="2026-09-14T09:00:00Z", rationale="SYNTHETIC. Re-reviewed.")
        case = self.case()
        assert case.current_evaluation is not None
        self.assertEqual(
            case.current_evaluation.completed_at, datetime(2026, 9, 14, 9, 0, tzinfo=UTC)
        )
        self.assertEqual(case.remediated_at, datetime(2026, 9, 5, 15, 0, tzinfo=UTC))
        message = self.warning()
        assert message is not None
        self.assertIn("recorded remediated at 2026-09-05T15:00:00Z", message)

    def test_closed_as_remediated_continues_the_run(self) -> None:
        self.evaluate()
        self.evaluate(
            completedAt="2026-09-14T09:00:00Z",
            disposition="closed",
            closedDisposition="remediated",
        )
        self.assertEqual(self.case().remediated_at, datetime(2026, 9, 5, 15, 0, tzinfo=UTC))

    def test_a_disposition_between_two_remediations_restarts_the_instant(self) -> None:
        self.evaluate()
        self.evaluate(completedAt="2026-09-13T09:00:00Z", disposition="partially_mitigated")
        self.assertIsNone(self.case().remediated_at)
        self.assertIsNone(self.warning())
        self.evaluate(completedAt="2026-09-14T09:00:00Z")
        self.assertEqual(self.case().remediated_at, datetime(2026, 9, 14, 9, 0, tzinfo=UTC))
        # The scan of 12 September is before the second remediation, so nothing came back.
        self.assertIsNone(self.warning())

    def test_a_new_disposition_on_an_unchanged_evaluation_reads_the_one_in_force(self) -> None:
        self.evaluate(disposition="partially_mitigated")
        self.evaluate()
        self.assertEqual(self.case().remediated_at, datetime(2026, 9, 5, 15, 0, tzinfo=UTC))

    def test_no_other_disposition_sets_an_instant(self) -> None:
        for overrides in NOT_REMEDIATED:
            with self.subTest(disposition=overrides["disposition"]):
                self.evaluate(**overrides)
                self.assertIsNone(self.case().remediated_at)
                self.assertIsNone(self.warning())


if __name__ == "__main__":
    unittest.main()
