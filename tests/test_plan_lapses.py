# ******************************************************************************
# *Title: Plan Lapse Tests*
# *Author: Kyle Versluis*
# *Description: The lapsed planned response derivation and its warning.*
# ******************************************************************************
"""Tests for a provider's planned reduction that passed unrecorded (ADR 0019, plan D2 to D4)."""

# *--- Imports ---*

from __future__ import annotations

import json
import re
import unittest
from collections.abc import Sequence
from datetime import UTC, datetime, timedelta, timezone
from typing import Any

from test_cli import (
    KEV_ARGUMENTS,
    KEV_AS_OF,
    KEV_PERIOD,
    PLANNED_ARGUMENTS,
    PLANNED_ARTIFACT,
    PLANNED_EVALUATIONS,
    PersistedStoreTestCase,
    run,
)
from test_coverage import observation
from test_coverage_gap_evaluations import system_observation
from test_reports import GOLDEN, options

from complyroll.correlation import VulnerabilityGroup, group_open_observations
from complyroll.models import (
    CaseStatus,
    ObservationDisposition,
    ObservationOrigin,
    PainRating,
)
from complyroll.reports import (
    REPORT_DIAGNOSTIC_CODES,
    CompiledRecordSet,
    DetectionAttestation,
    ReportDiagnostic,
    compile_record_set,
    project_vdt,
)
from complyroll.reports import checks as checks_module
from complyroll.reports.evaluations import (
    EvaluationInput,
    EvaluationMatch,
    PainReductionEvent,
    ProjectedReduction,
)
from complyroll.reports.response_gaps import (
    PLAN_LAPSE_DESCRIPTION,
    PLAN_LAPSE_EXCLUDED_STATUSES,
    PLAN_LAPSE_METADATA_KEYS,
    PLAN_LAPSE_SOURCE_TYPE,
    PlanLapse,
    plan_lapse_context_key,
    plan_lapse_key_parts,
    plan_lapse_observation,
    planned_reduction_lapse,
    planned_reduction_lapses,
)
from complyroll.schemas import ReportSchema, validate_bundled_report_bytes

# *--- Fixtures ---*

RECORD = "CVE-2099-0200"
CODE = "planned_reduction_lapsed"
DETECTED_AT = datetime(2026, 8, 2, 9, 0, tzinfo=UTC)
#: The evaluation that states the plan, the planned time E, and the target R below pain 3.
COMPLETED_AT = datetime(2026, 8, 5, 12, 0, tzinfo=UTC)
PLANNED_AT = datetime(2026, 8, 12, 16, 0, tzinfo=UTC)
TARGET = PainRating.N2
SECOND = timedelta(seconds=1)
AFTER = PLANNED_AT + SECOND
#: The stateless golden pair carrying only the warning, and every golden that carries it.
WARNING_GOLDEN = "vdt-planned-reduction-warning"
WARNING_GOLDENS = (
    f"{WARNING_GOLDEN}.json",
    f"{WARNING_GOLDEN}.md",
    "historical-planned-response.json",
    "historical-planned-response.md",
)
#: The resolved statuses a plan can lapse under (D3 3a), each with the fields it needs.
ELIGIBLE: tuple[dict[str, Any], ...] = (
    {},
    {"disposition": CaseStatus.NEW},
    {"disposition": CaseStatus.EVALUATING},
    {"disposition": CaseStatus.ACTIVE},
    {"disposition": CaseStatus.PARTIALLY_MITIGATED},
    {"disposition": CaseStatus.ACCEPTED, "acceptance_rationale": "SYNTHETIC. Accepted."},
    {"disposition": CaseStatus.CLOSED, "closed_disposition": CaseStatus.PARTIALLY_MITIGATED},
    {
        "disposition": CaseStatus.CLOSED,
        "closed_disposition": CaseStatus.ACCEPTED,
        "acceptance_rationale": "SYNTHETIC. Accepted.",
    },
)
#: The resolved statuses whose weakness has nothing left to reduce, however reached.
EXCLUDED: tuple[dict[str, Any], ...] = (
    {"disposition": CaseStatus.REMEDIATED},
    {"disposition": CaseStatus.FULLY_MITIGATED},
    {"disposition": CaseStatus.FALSE_POSITIVE},
    {"is_false_positive": True},
    {"disposition": CaseStatus.CLOSED, "closed_disposition": CaseStatus.REMEDIATED},
    {"disposition": CaseStatus.CLOSED, "closed_disposition": CaseStatus.FULLY_MITIGATED},
    {"disposition": CaseStatus.CLOSED, "closed_disposition": CaseStatus.FALSE_POSITIVE},
)


def found(*, record: str = RECORD) -> VulnerabilityGroup:
    """Return the one group of an open artifact finding detected before the evaluation."""
    (group,) = group_open_observations(
        (observation("lab-01", DETECTED_AT, ObservationDisposition.OPEN, record=record),)
    )
    return group


def evaluation(
    *,
    pain: PainRating = PainRating.N3,
    planned_at: datetime | None = PLANNED_AT,
    target: PainRating = TARGET,
    reductions: Sequence[tuple[datetime, PainRating]] = (),
    record: str = RECORD,
    **fields: Any,
) -> EvaluationInput:
    """Return one evaluation stating a plan, with the reductions given as (instant, rating)."""
    return EvaluationInput(
        index=0,
        match=EvaluationMatch(source_record_id=record),
        completed_at=fields.pop("completed_at", COMPLETED_AT),
        is_internet_reachable=False,
        is_likely_exploitable=True,
        pain=pain,
        potential_agency_impact="SYNTHETIC. One lab host.",
        rationale="SYNTHETIC. A partial mitigation, with the fix planned.",
        evaluator="Example Provider vulnerability team (synthetic plan fixture)",
        projected_next_reduction=(
            None if planned_at is None else ProjectedReduction(planned_at, target)
        ),
        pain_reduction_events=tuple(PainReductionEvent(at, rating) for at, rating in reductions),
        **fields,
    )


def lapse_at(as_of: datetime = AFTER, **overrides: Any) -> PlanLapse | None:
    return planned_reduction_lapse(found(), evaluation(**overrides), as_of)


def compile_of(entry: EvaluationInput | None, *, as_of: datetime = AFTER) -> CompiledRecordSet:
    """Compile the one finding with its evaluation, as both paths do, at `as_of`."""
    group = found()
    return compile_record_set(
        artifacts=(),
        observations=group.observations,
        ingest_diagnostics=(),
        evaluations_by_tracking_id={} if entry is None else {group.tracking_id: entry},
        attestation=DetectionAttestation(),
        options=options(as_of=as_of, detected_at=None),
    )


def warnings_of(record_set: CompiledRecordSet) -> list[ReportDiagnostic]:
    return [item for item in record_set.diagnostics if item.code == CODE]


# *--- Derivation ---*


class PlanLapseConditionTests(unittest.TestCase):
    """D2's five conditions, each boundary pinned from both sides."""

    def test_a_lapse_names_the_plan_its_window_and_the_current_rating(self) -> None:
        self.assertEqual(
            lapse_at(),
            PlanLapse(
                tracking_id=found().tracking_id,
                completed_at=COMPLETED_AT,
                estimated_at=PLANNED_AT,
                target_rating=TARGET,
                current_rating=PainRating.N3,
            ),
        )

    def test_a_run_at_the_planned_time_records_nothing_and_one_second_later_lapses(self) -> None:
        self.assertIsNone(lapse_at(PLANNED_AT))
        self.assertIsNone(lapse_at(PLANNED_AT - SECOND))
        self.assertIsNotNone(lapse_at(AFTER))

    def test_a_rating_at_the_target_does_not_lapse_and_one_above_does(self) -> None:
        self.assertIsNone(lapse_at(pain=PainRating.N2))
        self.assertIsNotNone(lapse_at(pain=PainRating.N3))

    def test_a_target_not_below_the_rating_never_lapses(self) -> None:
        self.assertIsNone(lapse_at(pain=PainRating.N2, target=PainRating.N3))
        self.assertIsNone(lapse_at(pain=PainRating.N1, target=PainRating.N5))

    def test_no_plan_or_no_evaluation_never_lapses(self) -> None:
        self.assertIsNone(lapse_at(planned_at=None))
        self.assertIsNone(planned_reduction_lapse(found(), None, AFTER))

    def test_a_reduction_at_the_evaluation_instant_meets_the_plan(self) -> None:
        self.assertIsNone(lapse_at(reductions=[(COMPLETED_AT, TARGET)]))

    def test_a_reduction_one_second_before_the_evaluation_does_not(self) -> None:
        self.assertIsNotNone(lapse_at(reductions=[(COMPLETED_AT - SECOND, TARGET)]))

    def test_a_reduction_long_before_the_evaluation_then_a_re_rating_up_does_not(self) -> None:
        # F5: the ordinary path of a reduction followed by a re-rating upward.
        self.assertIsNotNone(lapse_at(reductions=[(DETECTED_AT, PainRating.N1)]))

    def test_a_reduction_at_the_planned_time_meets_the_plan(self) -> None:
        self.assertIsNone(lapse_at(reductions=[(PLANNED_AT, TARGET)]))

    def test_a_reduction_one_second_after_the_planned_time_does_not(self) -> None:
        self.assertIsNotNone(lapse_at(reductions=[(AFTER, TARGET)]))

    def test_a_reduction_above_the_target_does_not_and_one_below_does(self) -> None:
        inside = COMPLETED_AT + timedelta(days=2)
        self.assertIsNotNone(lapse_at(reductions=[(inside, PainRating.N3)]))
        self.assertIsNone(lapse_at(reductions=[(inside, PainRating.N1)]))

    def test_one_meeting_reduction_among_others_meets_the_plan(self) -> None:
        inside = COMPLETED_AT + timedelta(days=2)
        reductions = [(DETECTED_AT, PainRating.N1), (inside, PainRating.N2), (AFTER, TARGET)]
        self.assertIsNone(lapse_at(reductions=reductions))

    def test_every_eligible_disposition_lapses(self) -> None:
        for fields in ELIGIBLE:
            with self.subTest(**{key: str(value) for key, value in fields.items()}):
                self.assertIsNotNone(lapse_at(**fields))

    def test_no_excluded_disposition_lapses(self) -> None:
        for fields in EXCLUDED:
            with self.subTest(**{key: str(value) for key, value in fields.items()}):
                self.assertIsNone(lapse_at(**fields))

    def test_the_excluded_statuses_are_the_ruling(self) -> None:
        self.assertEqual(
            PLAN_LAPSE_EXCLUDED_STATUSES,
            {CaseStatus.REMEDIATED, CaseStatus.FULLY_MITIGATED, CaseStatus.FALSE_POSITIVE},
        )

    def test_a_plan_stated_before_its_own_evaluation_has_an_empty_window(self) -> None:
        # A stale plan carried into a new evaluation lapses once its time has passed, even
        # with a reduction to the target at the evaluation instant (plan D2 limits).
        stale = COMPLETED_AT - timedelta(days=1)
        self.assertIsNotNone(lapse_at(COMPLETED_AT, planned_at=stale))
        self.assertIsNotNone(
            lapse_at(COMPLETED_AT, planned_at=stale, reductions=[(COMPLETED_AT, TARGET)])
        )
        self.assertIsNotNone(lapse_at(COMPLETED_AT, planned_at=stale, reductions=[(stale, TARGET)]))

    def test_a_system_record_never_lapses(self) -> None:
        (group,) = group_open_observations((system_observation(),))
        self.assertIsNone(planned_reduction_lapse(group, evaluation(), AFTER))

    def test_instants_are_compared_in_utc_whatever_their_offset(self) -> None:
        zone = timezone(timedelta(hours=5))
        self.assertIsNone(lapse_at(PLANNED_AT.astimezone(zone)))
        self.assertIsNotNone(lapse_at(AFTER.astimezone(zone)))
        lapse = lapse_at(planned_at=PLANNED_AT.astimezone(zone))
        assert lapse is not None
        self.assertEqual(lapse.estimated_at.utcoffset(), timedelta(0))
        self.assertIsNone(lapse_at(reductions=[(PLANNED_AT.astimezone(zone), TARGET)]))

    def test_bad_inputs_are_refused(self) -> None:
        with self.assertRaisesRegex(ValueError, "as_of must be an aware datetime"):
            lapse_at(datetime(2026, 9, 1))
        with self.assertRaisesRegex(TypeError, "group must be a VulnerabilityGroup"):
            planned_reduction_lapse(object(), evaluation(), AFTER)  # type: ignore[arg-type]
        with self.assertRaisesRegex(TypeError, "evaluation must be an EvaluationInput"):
            planned_reduction_lapse(found(), object(), AFTER)  # type: ignore[arg-type]


class PlanLapseSetTests(unittest.TestCase):
    """Every lapse of a run, read over the report's own groups (plan F2)."""

    def test_lapses_are_read_in_tracking_id_order(self) -> None:
        groups = [found(record=record) for record in ("CVE-2099-0201", "CVE-2099-0202")]
        evaluations = {group.tracking_id: evaluation() for group in groups}
        lapses = planned_reduction_lapses(list(reversed(groups)), evaluations, AFTER)
        self.assertEqual(
            [item.tracking_id for item in lapses], sorted(group.tracking_id for group in groups)
        )

    def test_the_tracking_id_orders_before_the_planned_time(self) -> None:
        # The lower tracking id has the later plan, so an order by planned time first would
        # put it second.
        groups = sorted(
            (found(record=record) for record in ("CVE-2099-0201", "CVE-2099-0202")),
            key=lambda group: group.tracking_id,
        )
        later = PLANNED_AT + timedelta(days=2)
        evaluations = {
            groups[0].tracking_id: evaluation(planned_at=later),
            groups[1].tracking_id: evaluation(),
        }
        lapses = planned_reduction_lapses(groups, evaluations, later + SECOND)
        self.assertEqual(
            [(item.tracking_id, item.estimated_at) for item in lapses],
            [(groups[0].tracking_id, later), (groups[1].tracking_id, PLANNED_AT)],
        )

    def test_a_case_no_current_group_matches_lapses_nowhere(self) -> None:
        # A stale case is in no report, so it neither warns nor records.
        self.assertEqual(
            planned_reduction_lapses([], {"case-00000000000000ff": evaluation()}, AFTER), ()
        )

    def test_a_group_with_no_evaluation_is_skipped(self) -> None:
        self.assertEqual(planned_reduction_lapses([found()], {}, AFTER), ())


# *--- Identity ---*


def lapse_record(
    *, ingested_at: datetime = AFTER, planned_at: datetime = PLANNED_AT, **overrides: Any
) -> Any:
    """Return the system record of the fixture's lapse, built at `ingested_at`."""
    found_lapse = lapse_at(planned_at + timedelta(days=1), planned_at=planned_at, **overrides)
    assert found_lapse is not None
    return plan_lapse_observation(found_lapse, ingested_at=ingested_at)


class PlanLapseIdentityTests(unittest.TestCase):
    """One system record per case and plan, its spellings pinned as record bytes (D5)."""

    def test_the_record_is_the_recorded_decision(self) -> None:
        record = lapse_record()
        case = found().tracking_id
        self.assertEqual(PLAN_LAPSE_SOURCE_TYPE, "complyroll.response-plan")
        self.assertEqual(record.source_type, PLAN_LAPSE_SOURCE_TYPE)
        self.assertEqual(record.source_tool, "complyroll")
        self.assertEqual(record.parser_name, "complyroll.response-plan")
        self.assertEqual(record.parser_version, "1")
        self.assertEqual(record.source_record_id, "planned-response-lapse")
        self.assertEqual(record.origin, ObservationOrigin.SYSTEM)
        self.assertEqual(record.disposition, ObservationDisposition.OPEN)
        self.assertEqual(record.source_severity.value, "unknown")
        self.assertEqual(
            (record.resource.resource_type, record.resource.resource_id),
            ("logical", f"case/{case}"),
        )
        self.assertEqual(record.context_key, f"{case}:planned:2026-08-12T16:00:00Z:2")
        self.assertEqual(record.observed_at, PLANNED_AT)
        self.assertEqual(record.observation_id, record.derived_observation_id)
        self.assertEqual(record.evidence_ids, (f"case:{case}",))
        self.assertEqual(record.source_identifiers, ())
        self.assertEqual((record.source_artifact_name, record.source_artifact_digest), ("", ""))
        self.assertEqual(
            dict(record.source_metadata),
            {
                "plan.caseTrackingId": case,
                "plan.estimatedAt": "2026-08-12T16:00:00Z",
                "plan.targetRating": "2",
            },
        )
        self.assertEqual(tuple(sorted(dict(record.source_metadata))), PLAN_LAPSE_METADATA_KEYS)
        self.assertEqual(
            record.title,
            f"planned reduction of {case} to N2 was not recorded by 2026-08-12T16:00:00Z "
            "(VDR-CSO-FAV)",
        )
        self.assertEqual(record.description, PLAN_LAPSE_DESCRIPTION)

    def test_the_id_ignores_the_ingest_time_the_rating_and_the_evaluation(self) -> None:
        first = lapse_record()
        self.assertEqual(
            {
                first.observation_id,
                lapse_record(ingested_at=AFTER + timedelta(days=90)).observation_id,
                lapse_record(pain=PainRating.N5).observation_id,
                lapse_record(completed_at=COMPLETED_AT - timedelta(days=2)).observation_id,
                lapse_record(disposition=CaseStatus.ACCEPTED).observation_id,
            },
            {first.observation_id},
        )

    def test_two_offsets_of_one_planned_time_are_one_record(self) -> None:
        zone = timezone(timedelta(hours=-7))
        moved = lapse_record(planned_at=PLANNED_AT.astimezone(zone))
        self.assertEqual(moved.observation_id, lapse_record().observation_id)
        self.assertEqual(moved.metadata_value("plan.estimatedAt"), "2026-08-12T16:00:00Z")

    def test_a_new_plan_is_a_second_case_and_a_restated_plan_is_the_same_one(self) -> None:
        first = lapse_record()
        later = lapse_record(planned_at=PLANNED_AT + timedelta(days=7))
        lower = lapse_record(target=PainRating.N1)
        self.assertEqual(len({first.observation_id, later.observation_id, lower.observation_id}), 3)
        self.assertEqual(len(group_open_observations((first, later, lower))), 3)
        self.assertEqual(len(group_open_observations((first, lapse_record()))), 1)

    def test_the_identity_names_the_correlation_id_not_a_provider_override(self) -> None:
        renamed = lapse_record(tracking_id="PROVIDER-7")
        self.assertEqual(renamed.observation_id, lapse_record().observation_id)
        self.assertTrue(renamed.context_key.startswith(f"{found().tracking_id}:planned:"))

    def test_every_target_rating_is_spelled_as_one_digit(self) -> None:
        for target in (PainRating.N1, PainRating.N2, PainRating.N3, PainRating.N4):
            with self.subTest(target=target):
                record = lapse_record(pain=PainRating.N5, target=target)
                self.assertEqual(record.metadata_value("plan.targetRating"), str(int(target)))
                self.assertTrue(record.context_key.endswith(f":{int(target)}"))
                self.assertIn(f" to N{int(target)} was not recorded by ", record.title)

    def test_the_context_key_reads_back_and_refuses_other_keys(self) -> None:
        case = found().tracking_id
        key = plan_lapse_context_key(case, PLANNED_AT, TARGET)
        self.assertEqual(plan_lapse_key_parts(key), (case, "2026-08-12T16:00:00Z", 2))
        for other in (
            case,
            f"{case}:remediated:2026-08-12T16:00:00Z:2",
            f"{case}:planned:2026-08-12T16:00:00Z:0",
            f"{case}:planned:2026-08-12T16:00:00Z:6",
            f"{case}:planned:2026-08-12T16:00:00Z:02",
            f"{case}:planned:2026-08-12T16:00:00Z:",
            f"{case}:planned::2",
            f"{case}:planned:2",
            "PROVIDER-7:planned:2026-08-12T16:00:00Z:2",
        ):
            with self.subTest(key=other):
                self.assertIsNone(plan_lapse_key_parts(other))
        with self.assertRaises(TypeError):
            plan_lapse_key_parts(None)  # type: ignore[arg-type]
        with self.assertRaisesRegex(ValueError, "correlation tracking id"):
            plan_lapse_context_key("PROVIDER-7", PLANNED_AT, TARGET)
        with self.assertRaisesRegex(ValueError, "PainRating"):
            plan_lapse_context_key(case, PLANNED_AT, 2)  # type: ignore[arg-type]
        with self.assertRaisesRegex(ValueError, "aware"):
            plan_lapse_context_key(case, datetime(2026, 8, 12), TARGET)

    def test_the_builder_refuses_what_is_not_a_lapse(self) -> None:
        with self.assertRaises(TypeError):
            plan_lapse_observation(object(), ingested_at=AFTER)  # type: ignore[arg-type]
        stray = PlanLapse("PROVIDER-7", COMPLETED_AT, PLANNED_AT, TARGET, PainRating.N3)
        with self.assertRaisesRegex(ValueError, "correlation tracking id"):
            plan_lapse_observation(stray, ingested_at=AFTER)


class PlanLapseRecordTests(unittest.TestCase):
    """A lapsed planned response compiles as a system record of its own kind (D6)."""

    def test_its_case_is_detected_at_the_planned_time_with_one_deadline(self) -> None:
        record_set = compile_record_set(
            artifacts=(),
            observations=(lapse_record(),),
            ingest_diagnostics=(),
            evaluations_by_tracking_id={},
            attestation=DetectionAttestation(),
            options=options(as_of=datetime(2026, 8, 20, tzinfo=UTC), detected_at=None),
        )
        (record,) = record_set.records
        self.assertEqual(record.detected_at, PLANNED_AT)
        self.assertEqual(record.detected_at_source, "system")
        self.assertEqual([item.rule_id for item in record.deadlines], ["VER-TFR-EVU"])
        self.assertEqual([item.anchor for item in record.deadlines], ["detection"])
        markdown = project_vdt(record_set).to_markdown()
        self.assertIn(
            "for a lapsed planned response, from the instant its planned reduction was expected",
            markdown,
        )

    def test_the_kind_tables_name_it(self) -> None:
        self.assertEqual(
            checks_module.system_record_kind(PLAN_LAPSE_SOURCE_TYPE), "lapsed planned response"
        )
        diagnostic = checks_module.evaluation_order_diagnostic(
            tracking_id="case-0000000000000000",
            location="here",
            detected_at=PLANNED_AT,
            detected_source="system",
            completed_at=COMPLETED_AT,
            source_type=PLAN_LAPSE_SOURCE_TYPE,
        )
        assert diagnostic is not None
        self.assertTrue(
            diagnostic.message.endswith(
                "; a lapsed planned response is detected when its planned time passed, so "
                "evaluate it at or after that instant, or correct completedAt"
            )
        )


# *--- Warning ---*


class PlanLapseWarningTests(unittest.TestCase):
    """One WARNING per lapsed record, on both paths; the projection is published unchanged."""

    def test_the_code_is_registered(self) -> None:
        self.assertIn(CODE, REPORT_DIAGNOSTIC_CODES)

    def test_a_lapsed_plan_warns_and_the_projection_stands(self) -> None:
        record_set = compile_of(evaluation(disposition=CaseStatus.PARTIALLY_MITIGATED))
        (warning,) = warnings_of(record_set)
        self.assertEqual(warning.level.value, "warning")
        self.assertEqual(warning.location, RECORD)
        self.assertEqual(
            warning.message,
            f"{found().tracking_id} planned its next reduction to PAIN N2 by "
            "2026-08-12T16:00:00Z, and that time has passed with its current rating PAIN N3 and "
            "no reduction to N2 or below recorded from its evaluation at 2026-08-05T12:00:00Z "
            "through it; the planned reduction is not recorded, and the record keeps its plan "
            "until an evaluation changes it",
        )
        (record,) = project_vdt(
            compile_of(evaluation(), as_of=datetime(2026, 8, 20, tzinfo=UTC))
        ).document["vulnerabilities"]
        self.assertEqual(
            record["projectedNextReduction"],
            {"estimatedAt": "2026-08-12T16:00:00Z", "targetRating": 2},
        )

    def test_a_renamed_record_is_named_by_both_ids(self) -> None:
        (warning,) = warnings_of(compile_of(evaluation(tracking_id="PROVIDER-7")))
        self.assertTrue(warning.message.startswith(f"PROVIDER-7 ({found().tracking_id}) planned"))

    def test_no_warning_at_the_planned_time_or_when_the_plan_is_met(self) -> None:
        self.assertEqual(warnings_of(compile_of(evaluation(), as_of=PLANNED_AT)), [])
        met = evaluation(reductions=[(PLANNED_AT, TARGET)])
        self.assertEqual(warnings_of(compile_of(met)), [])

    def test_an_excluded_disposition_warns_nothing_and_an_unevaluated_record_neither(
        self,
    ) -> None:
        self.assertEqual(warnings_of(compile_of(evaluation(**EXCLUDED[0]))), [])
        self.assertEqual(warnings_of(compile_of(None)), [])

    def test_the_warning_reaches_json_and_markdown(self) -> None:
        report = project_vdt(compile_of(evaluation()))
        codes = [item["code"] for item in report.document["x-complyroll"]["diagnostics"]]
        self.assertEqual(codes, [CODE])
        self.assertIn(CODE, report.to_markdown())


# *--- Golden ---*


class GoldenCensusTests(unittest.TestCase):
    """No fixture behind an existing golden has a plan past its time (plan D11)."""

    def test_only_the_new_goldens_carry_the_warning(self) -> None:
        carrying = {
            path.name for path in sorted(GOLDEN.iterdir()) if CODE in path.read_text("utf-8")
        }
        self.assertEqual(carrying, set(WARNING_GOLDENS))

    def test_every_golden_plan_is_the_census_and_only_the_new_one_has_passed(self) -> None:
        # Nine golden projections state 2026-08-28 against an as-of of 2026-08-21, and the
        # schema examples 2026-08-25 against 2026-08-20; only the new fixture's has passed.
        plans = sorted(
            (path.name, found)
            for path in GOLDEN.glob("*.json")
            for found in re.findall(
                r'"projectedNextReduction": \{\s*"estimatedAt": "([^"]+)"',
                path.read_text(encoding="utf-8"),
            )
        )
        nine = {
            "historical-coverage-gaps.json",
            "historical-failed.json",
            "historical-fixtures.json",
            "vdt-changes-replay.json",
            "vdt-changes.json",
            "vdt-coverage-gaps.json",
            "vdt-coverage.json",
            "vdt-failed.json",
            "vdt-fixtures.json",
        }
        self.assertEqual(
            plans,
            sorted(
                [
                    *((name, "2026-08-28T16:00:00Z") for name in nine),
                    ("ver-schema-examples.json", "2026-08-25T10:00:00Z"),
                    (f"{WARNING_GOLDEN}.json", "2026-09-11T16:00:00Z"),
                    ("historical-planned-response.json", "2026-09-11T16:00:00Z"),
                ]
            ),
        )


class PlanLapseWarningGoldenTests(PersistedStoreTestCase):
    """The `vdt-planned-reduction-warning` pair, cut statelessly and rebuilt from a store."""

    def test_the_command_line_cuts_the_golden_and_exits_0(self) -> None:
        json_path = self.workspace / "report.json"
        markdown_path = self.workspace / "report.md"
        code, _, err = run(
            [*PLANNED_ARGUMENTS, "-o", str(json_path), "--markdown", str(markdown_path)]
        )
        self.assertEqual(code, 0, msg=err)
        self.assertIn(f"warning: {CODE}: ", err)
        self.assertEqual(json_path.read_bytes(), (GOLDEN / f"{WARNING_GOLDEN}.json").read_bytes())
        self.assertEqual(markdown_path.read_bytes(), (GOLDEN / f"{WARNING_GOLDEN}.md").read_bytes())

    def test_the_golden_validates_and_publishes_the_plan_unchanged(self) -> None:
        payload = (GOLDEN / f"{WARNING_GOLDEN}.json").read_bytes()
        self.assertTrue(
            validate_bundled_report_bytes(ReportSchema.VULNERABILITY_DETAIL, payload).is_valid
        )
        document = json.loads(payload)
        (record,) = document["vulnerabilities"]
        self.assertEqual(record["finalDisposition"], "Partially Mitigated")
        self.assertEqual(
            record["projectedNextReduction"],
            {"estimatedAt": "2026-09-11T16:00:00Z", "targetRating": 2},
        )
        codes = [item["code"] for item in document["x-complyroll"]["diagnostics"]]
        self.assertEqual(codes, [CODE])

    def test_a_store_reports_the_same_bytes(self) -> None:
        self.build_store()
        json_path = self.workspace / "replay.json"
        markdown_path = self.workspace / "replay.md"
        self.report_from_store(json_path, markdown_path)
        self.assertEqual(json_path.read_bytes(), (GOLDEN / f"{WARNING_GOLDEN}.json").read_bytes())
        self.assertEqual(markdown_path.read_bytes(), (GOLDEN / f"{WARNING_GOLDEN}.md").read_bytes())

    def test_a_reduction_a_later_evaluation_dropped_still_meets_the_plan_in_a_store(
        self,
    ) -> None:
        # The store keeps a reduction a later file no longer states, so the store path reads
        # it inside the window where a stateless run of the later file cannot (plan D2 limits).
        self.build_store(reductions=[{"reducedAt": "2026-09-08T10:00:00Z", "rating": 2}])
        self.evaluate(reductions=[])
        self.assertNotIn(CODE, self.report_codes())
        dropped = self.evaluations_path(reductions=[])
        code, _, err = run(
            [
                "report",
                "vdt",
                PLANNED_ARTIFACT,
                "--evaluations",
                str(dropped),
                *KEV_ARGUMENTS,
                "--as-of",
                KEV_AS_OF,
                *KEV_PERIOD,
            ]
        )
        self.assertEqual(code, 0, msg=err)
        self.assertIn(f"warning: {CODE}: ", err)

    def test_a_new_evaluation_after_an_on_time_reduction_opens_a_new_window(self) -> None:
        # F5's stated cost: the plan and the rating left as they were in a later evaluation.
        self.build_store(reductions=[{"reducedAt": "2026-09-08T10:00:00Z", "rating": 2}])
        self.assertNotIn(CODE, self.report_codes())
        self.evaluate(completedAt="2026-09-10T09:00:00Z")
        self.assertIn(CODE, self.report_codes())

    def evaluations_path(self, **overrides: Any) -> Any:
        """Write the planned fixture's evaluation with the given fields replaced."""
        entry = dict(json.loads(PLANNED_EVALUATIONS.read_text(encoding="utf-8"))["evaluations"][0])
        if "reductions" in overrides:
            entry["painReductionEvents"] = overrides.pop("reductions")
        entry.update(overrides)
        entry = {key: value for key, value in entry.items() if value not in (None, [])}
        path = self.workspace / f"evaluations-{len(list(self.workspace.iterdir()))}.json"
        path.write_text(json.dumps({"evaluations": [entry]}), encoding="utf-8")
        return path

    def evaluate(self, **overrides: Any) -> None:
        path = self.evaluations_path(**overrides)
        self.succeeds(["cases", "evaluate", "--db", str(self.database), "--evaluations", str(path)])

    def build_store(self, **overrides: Any) -> None:
        """Ingest the scan, open its case, and evaluate it with the planned fixture."""
        database = str(self.database)
        self.succeeds(
            ["ingest", PLANNED_ARTIFACT, "--db", database, "--as-of", "2026-09-03T00:00:00Z"]
        )
        self.succeeds(["cases", "correlate", "--db", database])
        if overrides:
            self.evaluate(**overrides)
        else:
            self.succeeds(
                ["cases", "evaluate", "--db", database, "--evaluations", str(PLANNED_EVALUATIONS)]
            )

    def report_from_store(self, json_path: Any, markdown_path: Any) -> str:
        _, err = self.succeeds(
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
        return err

    def report_codes(self) -> list[str]:
        json_path = self.workspace / "codes.json"
        self.report_from_store(json_path, self.workspace / "codes.md")
        document = json.loads(json_path.read_text(encoding="utf-8"))
        return [item["code"] for item in document["x-complyroll"]["diagnostics"]]


if __name__ == "__main__":
    unittest.main()
