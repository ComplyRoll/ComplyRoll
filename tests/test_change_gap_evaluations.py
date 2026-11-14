# ******************************************************************************
# *Title: Change Gap Evaluation Tests*
# *Author: Kyle Versluis*
# *Description: Evaluations, AVI and the case listing for change gaps.*
# ******************************************************************************
"""Tests that an evaluation finds a change gap by the full triple alone (ADR 0018, PR 3)."""

# *--- Imports ---*

from __future__ import annotations

import json
import unittest
from collections.abc import Callable, Sequence
from dataclasses import replace
from datetime import UTC, datetime
from decimal import Decimal
from pathlib import Path
from typing import Any
from unittest import mock

from test_change_gap_report import (
    CLOSED_ROWS,
    by_tracking_id,
    rows_of,
    timed_options,
    write_changes,
)
from test_change_gaps import CHANGE_REMEDY
from test_changes import change, changes_of, host, inventory_of, pair, policy
from test_cli import (
    INGESTED_AT,
    TIMED_AS_OF,
    TIMED_CHANGES,
    TIMED_INVENTORY,
    PersistedStoreTestCase,
    run,
)
from test_coverage_gap_evaluations import (
    as_tuples,
    case_of,
    compile_with,
    context_key_text,
    document_of,
    group_of,
    tracking_ids,
)
from test_coverage_gap_report import diagnostics_of, write_inventory
from test_coverage_report import TIMED_ARTIFACTS, xccdf
from test_reports import (
    AS_OF,
    AVI_DETAIL_SECTIONS,
    assert_markdown_carries_the_json,
    ingest_text,
)

from complyroll.adapters import DiagnosticLevel, IngestResult
from complyroll.correlation import group_open_observations
from complyroll.events import EventMetadata, EventRepository, case_stream_id
from complyroll.history import (
    CASE_EVALUATED,
    CaseState,
    EvaluationMatchError,
    fold_all_cases,
    rehydrate_observations,
)
from complyroll.history import writers as history_writers
from complyroll.history.order import case_order_diagnostic
from complyroll.models import (
    CaseStatus,
    Observation,
    ObservationDisposition,
    ObservationOrigin,
    SourceSeverity,
)
from complyroll.policy import (
    RuleTimeframe,
    SelectedPolicy,
    TimeframeUnit,
    load_bundled_rule_source_snapshot,
    select_policy,
)
from complyroll.reports import (
    CompiledRecordSet,
    EvaluationSet,
    ReportCompileError,
    compile_record_set_from_artifacts,
    parse_evaluations,
    project_avi,
    project_vdt,
)
from complyroll.reports import records as records_module
from complyroll.reports.change_gaps import (
    CHANGE_GAP_RECORD_ID,
    CHANGE_GAP_SOURCE_TYPE,
    change_gap_observations,
)
from complyroll.reports.changes import derive_changes
from complyroll.reports.gaps import COVERAGE_GAP_SOURCE_TYPE
from complyroll.store import SQLiteEventStore

# *--- Fixtures ---*

#: Every gap change below occurs at midnight on 3 August and must be verified within a day,
#: so its window closes at the instant the coverage gap evaluation tests close theirs.
OCCURRED_TEXT = "2026-08-03T00:00:00Z"
GAP_CLOSED_TEXT = "2026-08-04T00:00:00Z"
GAP_CLOSED_AT = datetime(2026, 8, 4, tzinfo=UTC)
#: One second before the close, the latest instant the order check refuses.
GAP_EARLY_TEXT = "2026-08-03T23:59:59Z"
#: The one gap of the lone-change store and of most library tests below.
LONE_KEY = "VDR-CSO-DAC:change:CHG-E1"
EVU_RULE = "VER-TFR-EVU"
#: Values no default would produce, so the record shows they came from the evaluation.
GAP_EVALUATION: dict[str, Any] = {
    "completedAt": GAP_CLOSED_TEXT,
    "isInternetReachable": True,
    "isLikelyExploitable": False,
    "pain": 2,
    "potentialAgencyImpact": "A change to one lab host went unverified for one window.",
    "rationale": "No verification ran in the change window; the next scan found nothing new.",
    "evaluator": "Example Provider vulnerability team (change review)",
    "disposition": "remediated",
}
#: The timed run's two change gap cases: CHG-2001's lapsed image window, closed 20 August,
#: and CHG-2003's render window, closed 1 September 01:00 and verified an hour late.
IMAGE_CASE = CLOSED_ROWS[0][3]
IMAGE_KEY = "VDR-CSO-DAC:change:CHG-2001"
RENDER_CASE = CLOSED_ROWS[1][3]
RENDER_KEY = "VDR-CSO-DAC:change:CHG-2003"
#: An evaluation of a timed run's gap that the run's as-of admits.
TIMED_ENTRY: dict[str, Any] = {
    "completedAt": "2026-09-02T00:00:00Z",
    "isInternetReachable": False,
    "isLikelyExploitable": False,
    "pain": 1,
    "potentialAgencyImpact": "One changed resource went unverified for one window.",
    "rationale": "The change was a rebuild of the same content; the next scan found nothing.",
    "evaluator": "Example Provider vulnerability team (change review)",
}
#: Overrides that turn a timed entry into an acceptance, which AVI lists.
ACCEPTANCE = {
    "disposition": "accepted",
    "acceptanceRationale": "Accepted under change record CR-301 until the next image rebuild.",
}
#: The arguments every persisted report below shares, less its kind, store and as-of.
LONE_REPORT = (
    "--class",
    "C",
    "--package-uri",
    "https://example.test/cpo",
    "--from",
    "2026-08-01T00:00:00Z",
    "--to",
    "2026-08-31T23:59:59Z",
)
TIMED_REPORT = (
    "--class",
    "C",
    "--package-uri",
    "https://example.test/cpo",
    "--from",
    "2026-09-01T00:00:00Z",
    "--to",
    "2026-09-30T23:59:59Z",
    "--as-of",
    TIMED_AS_OF,
    "--inventory",
    str(TIMED_INVENTORY),
)
#: The timed store's `cases changes` run, less its `--db`.
TIMED_CASES_CHANGES = (
    "--class",
    "C",
    "--as-of",
    TIMED_AS_OF,
    "--inventory",
    str(TIMED_INVENTORY),
)


def window_change(change_id: str = "CHG-E1", *names: str, **fields: Any) -> dict[str, Any]:
    """Return a change whose window runs from 3 August to 4 August unless told otherwise."""
    resources = [pair(name) for name in names or ("lab-gap-01",)]
    return change(
        change_id,
        *resources,
        **{"occurredAt": OCCURRED_TEXT, "detectBy": GAP_CLOSED_TEXT, **fields},
    )


def gaps(*changes: dict[str, Any]) -> tuple[Observation, ...]:
    """Return the gaps these changes' closed windows build at the report as-of, unverified."""
    names = sorted({item["resourceId"] for each in changes for item in each["resources"]})
    projection = derive_changes(
        [], changes_of(*changes), inventory_of(*(host(name) for name in names)), policy("C"), AS_OF
    )
    built = change_gap_observations(projection, ingested_at=AS_OF)
    assert len(built) == sum(len(each["resources"]) for each in changes), built
    return built


def gap_match(
    gap: Observation, *, source_type: bool = True, context_key: bool = True
) -> dict[str, str]:
    """Return the documented triple for one gap, less the keys a test drops."""
    match = {"sourceRecordId": CHANGE_GAP_RECORD_ID}
    if source_type:
        match["sourceType"] = CHANGE_GAP_SOURCE_TYPE
    if context_key:
        match["contextKey"] = gap.context_key
    return match


def evaluations_with(match: dict[str, str], **overrides: object) -> EvaluationSet:
    """Parse one gap evaluation through the bounded reader the CLI uses."""
    entry: dict[str, Any] = {"match": match, **GAP_EVALUATION, **overrides}
    return parse_evaluations(json.dumps({"evaluations": [entry]}).encode("utf-8"))


def triple(context_key: str) -> dict[str, str]:
    return {
        "sourceRecordId": CHANGE_GAP_RECORD_ID,
        "sourceType": CHANGE_GAP_SOURCE_TYPE,
        "contextKey": context_key,
    }


def timed_with(*entries: dict[str, Any]) -> CompiledRecordSet:
    """Compile the timed run with `--record-change-gaps` and these evaluation entries."""
    evaluations = parse_evaluations(json.dumps({"evaluations": list(entries)}).encode("utf-8"))
    return compile_record_set_from_artifacts(
        list(TIMED_ARTIFACTS), options=timed_options(), evaluations=evaluations
    )


def record_of(record_set: CompiledRecordSet, tracking_id: str) -> Any:
    (record,) = [item for item in record_set.records if item.tracking_id == tracking_id]
    return record


def hostile_checklist(context_key: str) -> str:
    """Return a CKLB whose one rule copies a change gap's record id and context key."""
    return json.dumps(
        {
            "target_data": {"host_name": "host-hostile"},
            "stigs": [
                {
                    "stig_id": context_key,
                    "rules": [
                        {
                            "group_id": CHANGE_GAP_RECORD_ID,
                            "status": "open",
                            "severity": "high",
                            "rule_title": "Synthetic rule that copies a change gap's key",
                        }
                    ],
                }
            ],
        }
    )


def stretched_evaluation_rule(days: int) -> Callable[..., SelectedPolicy]:
    """Return a `select_policy` whose dataset states another VER-TFR-EVU timeframe."""
    real = records_module.select_policy

    def select(snapshot: Any, profile: Any) -> SelectedPolicy:
        selected = real(snapshot, profile)
        timeframe = RuleTimeframe(Decimal(days), TimeframeUnit.DAYS)
        return replace(
            selected,
            rules=tuple(
                replace(rule, timeframe=timeframe) if rule.rule_id == EVU_RULE else rule
                for rule in selected.rules
            ),
        )

    return select


def early_refusal(tracking_id: str) -> str:
    return (
        f"{tracking_id} was evaluated at {GAP_EARLY_TEXT}, before its detection time "
        f"{GAP_CLOSED_TEXT} (source system); {CHANGE_REMEDY}"
    )


def evu_deadlines(document: dict[str, Any]) -> list[dict[str, Any]]:
    return [item for item in document["x-complyroll"]["deadlines"] if item["ruleId"] == EVU_RULE]


# *--- Stateless Matching ---*


class ChangeGapEvaluationTests(unittest.TestCase):
    """The full triple selects one change gap case, which takes PAIN and closes from it alone."""

    def test_the_triple_evaluates_and_closes_the_gap(self) -> None:
        (gap,) = gaps(window_change())
        self.assertEqual(gap.context_key, LONE_KEY)
        (tracking_id,) = tracking_ids(gap)
        evaluations = evaluations_with(gap_match(gap))

        record_set = compile_with((gap,), evaluations)

        record = record_of(record_set, tracking_id)
        self.assertIs(record.evaluation, evaluations.entries[0])
        self.assertIs(record.status, CaseStatus.REMEDIATED)
        self.assertEqual(record.final_disposition, "Remediated")
        self.assertEqual(record.detected_at, GAP_CLOSED_AT)
        self.assertEqual(record.detected_at_source, "system")
        document = document_of(record_set, tracking_id)
        self.assertEqual(document["detection"]["detectedAt"], GAP_CLOSED_TEXT)
        self.assertEqual(document["evaluationCompletedAt"], GAP_CLOSED_TEXT)
        self.assertEqual(document["currentRating"], 2)
        self.assertIs(document["isInternetReachable"], True)
        self.assertIs(document["isLikelyExploitable"], False)
        self.assertEqual(document["finalDisposition"], "Remediated")
        self.assertEqual(document["x-complyroll"]["detectedAtSource"], "system")
        (deadline,) = evu_deadlines(document)
        self.assertEqual(deadline["startAt"], GAP_CLOSED_TEXT)
        self.assertTrue(project_vdt(record_set).validation.is_valid)
        self.assertEqual(
            [item.code for item in record_set.diagnostics if "evaluation" in item.code], []
        )

    def test_without_an_evaluation_the_gap_carries_no_rating_or_disposition(self) -> None:
        (gap,) = gaps(window_change())
        (tracking_id,) = tracking_ids(gap)

        record_set = compile_with((gap,))

        record = record_of(record_set, tracking_id)
        self.assertIsNone(record.evaluation)
        self.assertIsNone(record.status)
        document = document_of(record_set, tracking_id)
        for key in (
            "currentRating",
            "isInternetReachable",
            "isLikelyExploitable",
            "finalDisposition",
            "evaluationCompletedAt",
        ):
            with self.subTest(key):
                self.assertNotIn(key, document)

    def test_the_triple_selects_one_change_of_a_resource(self) -> None:
        # Two changes of one host share the resource, the record id and the source type, so
        # the context key alone tells their cases apart.
        first, second = gaps(window_change("CHG-E1"), window_change("CHG-E2"))
        self.assertEqual(first.resource, second.resource)
        self.assertNotEqual(first.context_key, second.context_key)
        (first_id,) = tracking_ids(first)
        (second_id,) = tracking_ids(second)

        record_set = compile_with((first, second), evaluations_with(gap_match(second)))

        evaluated = {item.tracking_id: item.evaluation for item in record_set.records}
        self.assertIsNone(evaluated[first_id])
        self.assertIsNotNone(evaluated[second_id])

    def test_a_lone_gap_is_not_matched_without_its_context_key(self) -> None:
        (gap,) = gaps(window_change())
        (tracking_id,) = tracking_ids(gap)
        for label, source_type, remedy in (
            ("with sourceType", True, "contextKey"),
            ("without sourceType", False, "contextKey and sourceType"),
        ):
            with self.subTest(label):
                evaluations = evaluations_with(
                    gap_match(gap, source_type=source_type, context_key=False)
                )

                with self.assertRaises(ReportCompileError) as caught:
                    compile_with((gap,), evaluations)

                described = evaluations.entries[0].match.describe()
                self.assertEqual(
                    as_tuples(caught.exception.diagnostics),
                    [
                        (
                            "error",
                            "evaluation_context_key_required",
                            context_key_text(
                                described, "change detection gap", tracking_id, remedy
                            ),
                            "evaluations[0]",
                        )
                    ],
                )

    def test_a_lone_gap_is_not_matched_without_its_source_type(self) -> None:
        (gap,) = gaps(window_change())
        (tracking_id,) = tracking_ids(gap)
        evaluations = evaluations_with(gap_match(gap, source_type=False))

        with self.assertRaises(ReportCompileError) as caught:
            compile_with((gap,), evaluations)

        described = evaluations.entries[0].match.describe()
        self.assertEqual(
            as_tuples(caught.exception.diagnostics),
            [
                (
                    "error",
                    "evaluation_context_key_required",
                    context_key_text(described, "change detection gap", tracking_id, "sourceType"),
                    "evaluations[0]",
                )
            ],
        )

    def test_two_gaps_matched_without_a_context_key_are_ambiguous(self) -> None:
        # Ambiguity is checked before the lone-record refusal, so both cases are named, and
        # the remedy gives each one's value of every key the entry left out, in id order.
        both = gaps(window_change("CHG-E1"), window_change("CHG-E2"))
        named = ", ".join(tracking_ids(*both))
        by_id = {group.tracking_id: group for group in group_open_observations(both)}
        first, second = sorted(by_id)
        kind = f"sourceType={CHANGE_GAP_SOURCE_TYPE!r}"

        def key(tracking_id: str) -> str:
            return f"contextKey={by_id[tracking_id].context_key!r}"

        for label, source_type, remedy in (
            (
                "sourceType given",
                True,
                f"add contextKey ({first} has {key(first)}, {second} has {key(second)})",
            ),
            (
                "neither given",
                False,
                f"add contextKey or sourceType ({first} has {key(first)} and {kind}, "
                f"{second} has {key(second)} and {kind})",
            ),
        ):
            with self.subTest(label):
                evaluations = evaluations_with(
                    gap_match(both[0], source_type=source_type, context_key=False)
                )

                with self.assertRaises(ReportCompileError) as caught:
                    compile_with(both, evaluations)

                described = evaluations.entries[0].match.describe()
                self.assertEqual(
                    as_tuples(caught.exception.diagnostics),
                    [
                        (
                            "error",
                            "evaluation_ambiguous",
                            f"{described} matches 2 vulnerabilities ({named}); {remedy}",
                            "evaluations[0]",
                        )
                    ],
                )

    def test_both_paths_give_an_ambiguity_one_remedy(self) -> None:
        both = gaps(window_change("CHG-E1"), window_change("CHG-E2"))
        evaluations = evaluations_with(gap_match(both[0], context_key=False))
        cases = [case_of(group_of(item)) for item in reversed(both)]

        with self.assertRaises(ReportCompileError) as stateless:
            compile_with(both, evaluations)
        with self.assertRaises(EvaluationMatchError) as persisted:
            history_writers._match_cases(evaluations, cases)

        (diagnostic,) = stateless.exception.diagnostics
        (problem,) = persisted.exception.problems
        remedy = diagnostic.message.partition("); ")[2]
        self.assertTrue(remedy.startswith("add contextKey (case-"), remedy)
        self.assertEqual(problem.partition("); ")[2], remedy)

    def test_one_evaluation_closes_every_resource_of_a_change(self) -> None:
        # One change naming two hosts is one case, so one triple rates and closes both.
        both = gaps(window_change("CHG-E1", "lab-gap-01", "lab-gap-02"))
        (tracking_id,) = set(tracking_ids(*both))

        record_set = compile_with(both, evaluations_with(gap_match(both[0])))

        record = record_of(record_set, tracking_id)
        self.assertIs(record.status, CaseStatus.REMEDIATED)
        self.assertEqual(
            [item.resource_id for item in record.resources], ["lab-gap-01", "lab-gap-02"]
        )
        self.assertEqual(
            sorted(record.observation_ids), sorted(item.observation_id for item in both)
        )


# *--- Hostile Records ---*


class ChangeGapHostileRecordTests(unittest.TestCase):
    """No artifact can carry the change gap source type, so the triple matches the gap alone."""

    def test_an_artifact_observation_cannot_carry_the_change_gap_source_type(self) -> None:
        (gap,) = gaps(window_change())
        with self.assertRaisesRegex(
            ValueError,
            r"^source_type prefix 'complyroll\.' is reserved for system observations$",
        ):
            Observation(
                observation_id="obs-forged",
                source_type=CHANGE_GAP_SOURCE_TYPE,
                source_tool="complyroll",
                parser_name="complyroll.change",
                parser_version="1",
                source_record_id=CHANGE_GAP_RECORD_ID,
                resource=gap.resource,
                observed_at=GAP_CLOSED_AT,
                ingested_at=AS_OF,
                disposition=ObservationDisposition.OPEN,
                source_severity=SourceSeverity.HIGH,
                source_artifact_digest="ab" * 32,
                source_artifact_name="forged.cklb",
                context_key=gap.context_key,
                origin=ObservationOrigin.ARTIFACT,
            )

    def hostile(self, gap: Observation) -> IngestResult:
        reading = ingest_text(hostile_checklist(gap.context_key), "hostile.cklb")
        (forged,) = reading.observations
        self.assertEqual(
            (forged.source_record_id, forged.context_key, forged.origin),
            (CHANGE_GAP_RECORD_ID, gap.context_key, ObservationOrigin.ARTIFACT),
        )
        return reading

    def test_the_triple_matches_the_gap_beside_a_hostile_checklist(self) -> None:
        (gap,) = gaps(window_change())
        (tracking_id,) = tracking_ids(gap)

        record_set = compile_with(
            (gap,), evaluations_with(gap_match(gap)), extra=(self.hostile(gap),)
        )

        copies = [
            item for item in record_set.records if item.source_record_id == CHANGE_GAP_RECORD_ID
        ]
        by_type = {item.source_type: item for item in copies}
        self.assertEqual(set(by_type), {CHANGE_GAP_SOURCE_TYPE, "cklb"})
        self.assertEqual(by_type[CHANGE_GAP_SOURCE_TYPE].tracking_id, tracking_id)
        self.assertIsNotNone(by_type[CHANGE_GAP_SOURCE_TYPE].evaluation)
        self.assertIsNone(by_type["cklb"].evaluation)
        self.assertEqual(by_type["cklb"].context_key, gap.context_key)

    def test_the_pair_alone_is_ambiguous_beside_a_hostile_checklist(self) -> None:
        (gap,) = gaps(window_change())

        with self.assertRaises(ReportCompileError) as caught:
            compile_with(
                (gap,),
                evaluations_with(gap_match(gap, source_type=False)),
                extra=(self.hostile(gap),),
            )

        (diagnostic,) = caught.exception.diagnostics
        self.assertEqual(diagnostic.code, "evaluation_ambiguous")
        self.assertIn("matches 2 vulnerabilities", diagnostic.message)
        self.assertIn("); add sourceType (", diagnostic.message)


# *--- Detection Time ---*


class ChangeGapDetectionTests(unittest.TestCase):
    """A change gap case is detected at its earliest window close, from the system itself."""

    def test_a_case_of_two_resources_is_detected_at_their_shared_close(self) -> None:
        both = gaps(window_change("CHG-E1", "lab-gap-01", "lab-gap-02"))
        (tracking_id,) = set(tracking_ids(*both))

        record_set = compile_with(both)

        record = record_of(record_set, tracking_id)
        self.assertEqual((record.detected_at, record.detected_at_source), (GAP_CLOSED_AT, "system"))
        document = document_of(record_set, tracking_id)
        self.assertEqual(document["detection"]["detectedAt"], GAP_CLOSED_TEXT)
        self.assertEqual(document["x-complyroll"]["detectedAtSource"], "system")
        # One clock for the case, however many resources it lists.
        self.assertEqual(
            [item["ruleId"] for item in document["x-complyroll"]["deadlines"]], [EVU_RULE]
        )

    def test_the_earliest_window_close_of_a_case_is_its_detection_time(self) -> None:
        # One change has one detectBy, so a stored case's windows share one close; two change
        # files that disagree on CHG-E1 are the only way to hand the compiler two, and the
        # earlier one wins whichever comes first.
        (early,) = gaps(window_change("CHG-E1"))
        (late,) = gaps(window_change("CHG-E1", "lab-gap-02", detectBy="2026-08-06T00:00:00Z"))
        self.assertEqual(early.context_key, late.context_key)
        (tracking_id,) = set(tracking_ids(late, early))

        record_set = compile_with((late, early))

        record = record_of(record_set, tracking_id)
        self.assertEqual((record.detected_at, record.detected_at_source), (GAP_CLOSED_AT, "system"))
        (deadline,) = evu_deadlines(document_of(record_set, tracking_id))
        self.assertEqual(deadline["startAt"], GAP_CLOSED_TEXT)

    def test_its_one_evaluation_deadline_is_read_from_the_pinned_dataset(self) -> None:
        (gap,) = gaps(window_change())
        (tracking_id,) = tracking_ids(gap)
        selected = select_policy(load_bundled_rule_source_snapshot(), policy("C").profile)
        expected = selected.evaluation_deadline(GAP_CLOSED_AT)

        document = document_of(compile_with((gap,)), tracking_id)

        (deadline,) = document["x-complyroll"]["deadlines"]
        self.assertEqual(deadline["ruleId"], EVU_RULE)
        self.assertEqual(deadline["anchor"], "detection")
        self.assertEqual(deadline["startAt"], GAP_CLOSED_TEXT)
        self.assertEqual(
            deadline["dueAt"], expected.due_at.astimezone(UTC).isoformat().replace("+00:00", "Z")
        )
        self.assertEqual(
            deadline["timeframe"],
            {
                "amount": expected.timeframe.display_amount,
                "unit": expected.timeframe.unit.value,
            },
        )
        self.assertEqual(deadline["force"], expected.force.value)
        self.assertIn(
            f"Rules dataset commit {selected.provenance.commit}.",
            document["overdueStatus"]["explanation"],
        )
        # A dataset that states another timeframe moves the deadline with it: nothing about a
        # change gap's clock is written in the code.
        with mock.patch.object(records_module, "select_policy", stretched_evaluation_rule(9)):
            stretched = document_of(compile_with((gap,)), tracking_id)
        (moved,) = evu_deadlines(stretched)
        self.assertEqual(moved["timeframe"], {"amount": 9, "unit": "days"})
        self.assertEqual(moved["dueAt"], "2026-08-13T00:00:00Z")
        self.assertEqual(moved["startAt"], GAP_CLOSED_TEXT)


# *--- Stateless Order ---*


class ChangeGapEvaluationOrderTests(unittest.TestCase):
    """A change gap is detected when its window closed; an earlier evaluation is refused."""

    def test_an_evaluation_one_second_before_the_close_is_refused(self) -> None:
        (gap,) = gaps(window_change())
        (tracking_id,) = tracking_ids(gap)

        with self.assertRaises(ReportCompileError) as caught:
            compile_with((gap,), evaluations_with(gap_match(gap), completedAt=GAP_EARLY_TEXT))

        self.assertEqual(
            as_tuples(caught.exception.diagnostics),
            [
                (
                    "error",
                    "evaluation_before_detection",
                    early_refusal(tracking_id),
                    CHANGE_GAP_RECORD_ID,
                )
            ],
        )
        # The window close is fixed on both paths, so no as-of remedy is offered.
        self.assertNotIn("as-of", caught.exception.diagnostics[0].message)

    def test_an_evaluation_at_the_close_is_in_order(self) -> None:
        (gap,) = gaps(window_change())
        (tracking_id,) = tracking_ids(gap)

        record_set = compile_with(
            (gap,), evaluations_with(gap_match(gap), completedAt=GAP_CLOSED_TEXT)
        )

        self.assertIs(record_of(record_set, tracking_id).status, CaseStatus.REMEDIATED)

    def test_both_paths_end_the_refusal_with_decision_12s_remedy(self) -> None:
        # Written out here rather than read from a shared constant, so the text is the
        # decision's own words; `GapEvaluationOrderTests` holds the branch on source type.
        decision_12 = (
            "; a change detection gap is detected when its window closed, so evaluate it at or "
            "after that instant, or correct completedAt"
        )
        (gap,) = gaps(window_change())
        group = group_of(gap)

        with self.assertRaises(ReportCompileError) as caught:
            compile_with((gap,), evaluations_with(gap_match(gap), completedAt=GAP_EARLY_TEXT))
        persisted = case_order_diagnostic(
            case_of(group),
            group,
            completed_at=datetime(2026, 8, 3, 23, 59, 59, tzinfo=UTC),
            attested_at=None,
        )

        assert persisted is not None
        (stateless,) = caught.exception.diagnostics
        for diagnostic in (stateless, persisted):
            self.assertTrue(diagnostic.message.endswith(decision_12), diagnostic.message)
            self.assertIs(diagnostic.level, DiagnosticLevel.ERROR)


# *--- Closing ---*


class ChangeGapDispositionTests(unittest.TestCase):
    """ADR 0015 Decision 26 for change gaps: a closed window closes only by a disposition."""

    def test_a_late_verification_leaves_its_gap_open(self) -> None:
        # CHG-2003's render file was verified an hour after its window closed: the row reads
        # detected and resumed, and the record of the missed window stays open.
        record_set = timed_with()
        report = project_vdt(record_set)

        (row,) = [item for item in rows_of(report) if item["changeId"] == "CHG-2003"]
        self.assertEqual(row["status"], "detected")
        self.assertIsNotNone(row["resumedAt"])
        self.assertEqual((row["recorded"], row["trackingId"]), (True, RENDER_CASE))
        record = record_of(record_set, RENDER_CASE)
        self.assertIsNone(record.status)
        self.assertIsNone(record.evaluation)
        published = by_tracking_id(report)[RENDER_CASE]
        self.assertNotIn("finalDisposition", published)
        self.assertIs(published["x-complyroll"]["remediated"], False)

    def test_an_evaluation_without_a_disposition_rates_it_and_leaves_it_open(self) -> None:
        record_set = timed_with({"match": triple(RENDER_KEY), **TIMED_ENTRY})

        record = record_of(record_set, RENDER_CASE)
        self.assertIsNotNone(record.evaluation)
        self.assertIsNone(record.status)
        published = by_tracking_id(project_vdt(record_set))[RENDER_CASE]
        self.assertEqual(published["currentRating"], 1)
        self.assertNotIn("finalDisposition", published)

    def test_each_closing_disposition_closes_it(self) -> None:
        # Any disposition the evaluations file accepts applies to a change gap as to a failure;
        # an accepted gap carries no final disposition because AVI lists it instead.
        for label, overrides, status, final in (
            ("remediated", {"disposition": "remediated"}, CaseStatus.REMEDIATED, "Remediated"),
            (
                "false positive",
                {"isFalsePositive": True},
                CaseStatus.FALSE_POSITIVE,
                "False Positive",
            ),
            (
                "fully mitigated",
                {"disposition": "fully_mitigated"},
                CaseStatus.FULLY_MITIGATED,
                "Fully Mitigated",
            ),
            (
                "partially mitigated",
                {"disposition": "partially_mitigated"},
                CaseStatus.PARTIALLY_MITIGATED,
                "Partially Mitigated",
            ),
            ("accepted", ACCEPTANCE, CaseStatus.ACCEPTED, None),
        ):
            with self.subTest(label):
                record_set = timed_with({"match": triple(RENDER_KEY), **TIMED_ENTRY, **overrides})

                record = record_of(record_set, RENDER_CASE)
                self.assertIs(record.status, status)
                self.assertEqual(record.final_disposition, final)
                # The other change's case is untouched by an entry that names this one.
                self.assertIsNone(record_of(record_set, IMAGE_CASE).status)


# *--- AVI ---*


class ChangeGapAviTests(unittest.TestCase):
    """An evaluation of a change gap by the full triple: AVI lists it only once accepted."""

    def test_avi_lists_no_gap_that_no_evaluation_accepts(self) -> None:
        rated = timed_with({"match": triple(IMAGE_KEY), **TIMED_ENTRY})

        avi = project_avi(rated)

        self.assertEqual(avi.document["acceptedVulnerabilities"], [])
        self.assertEqual(set(avi.metadata.change_gaps), {IMAGE_CASE, RENDER_CASE})

    def test_avi_lists_the_gap_an_evaluation_accepts(self) -> None:
        record_set = timed_with({"match": triple(IMAGE_KEY), **TIMED_ENTRY, **ACCEPTANCE})
        avi = project_avi(record_set)
        vdt = project_vdt(record_set)

        (item,) = avi.document["acceptedVulnerabilities"]
        self.assertEqual(item["vulnerabilityDetail"]["providerTrackingId"], IMAGE_CASE)
        self.assertEqual(item["acceptanceRationale"], ACCEPTANCE["acceptanceRationale"])
        assert_markdown_carries_the_json(self, avi, sections=AVI_DETAIL_SECTIONS)
        self.assertNotIn(IMAGE_CASE, by_tracking_id(vdt))
        self.assertIn(
            IMAGE_CASE,
            {item["message"].split()[0] for item in diagnostics_of(vdt, "accepted_excluded")},
        )
        (row,) = [item for item in rows_of(avi) if item["changeId"] == "CHG-2001"]
        self.assertEqual((row["recorded"], row["trackingId"]), (True, IMAGE_CASE))
        self.assertEqual(rows_of(vdt), rows_of(avi))

    def test_an_evaluation_tracking_id_names_the_row(self) -> None:
        # The row names the published id after the override, as a coverage window does.
        record_set = timed_with(
            {"match": triple(IMAGE_KEY), **TIMED_ENTRY, "trackingId": "POAM-CHG-0001"}
        )
        report = project_vdt(record_set)

        (row,) = [item for item in rows_of(report) if item["changeId"] == "CHG-2001"]
        self.assertEqual(row["trackingId"], "POAM-CHG-0001")
        self.assertIn("POAM-CHG-0001", by_tracking_id(report))
        self.assertIn("POAM-CHG-0001", report.metadata.change_gaps)
        assert_markdown_carries_the_json(self, report)


# *--- Persisted Seams ---*


class PersistedChangeGapEvaluationTests(unittest.TestCase):
    """`cases evaluate` refuses and orders a change gap case exactly as the compiler does.

    These run the writer's matcher and the order check on the case state and group they
    read; `PersistedChangeGapEvaluationCommandTests` runs the same refusals on a real store.
    """

    def test_the_triple_selects_the_gap_case_with_its_disposition(self) -> None:
        first, second = gaps(window_change("CHG-E1"), window_change("CHG-E2"))
        cases = [case_of(group_of(first)), case_of(group_of(second))]

        matched = history_writers._match_cases(evaluations_with(gap_match(second)), cases)

        self.assertEqual(list(matched), [cases[1].tracking_id])
        self.assertIs(matched[cases[1].tracking_id].resolved_status, CaseStatus.REMEDIATED)

    def test_a_lone_gap_case_short_of_the_triple_is_refused_as_a_change_detection_gap(
        self,
    ) -> None:
        (gap,) = gaps(window_change())
        case = case_of(group_of(gap))
        for label, source_type, context_key, remedy in (
            ("with sourceType", True, False, "contextKey"),
            ("without sourceType", False, False, "contextKey and sourceType"),
            ("with contextKey alone", False, True, "sourceType"),
        ):
            with self.subTest(label):
                evaluations = evaluations_with(
                    gap_match(gap, source_type=source_type, context_key=context_key)
                )

                with self.assertRaises(EvaluationMatchError) as caught:
                    history_writers._match_cases(evaluations, [case])

                described = evaluations.entries[0].match.describe()
                self.assertEqual(
                    caught.exception.problems,
                    (
                        "evaluations[0]: "
                        + context_key_text(
                            described, "change detection gap", case.tracking_id, remedy
                        ),
                    ),
                )

    def test_the_order_check_reads_the_same_text_as_the_compiler(self) -> None:
        (gap,) = gaps(window_change())
        group = group_of(gap)
        case = case_of(group)

        at_close = case_order_diagnostic(case, group, completed_at=GAP_CLOSED_AT, attested_at=None)
        early = case_order_diagnostic(
            case,
            group,
            completed_at=datetime(2026, 8, 3, 23, 59, 59, tzinfo=UTC),
            attested_at=None,
        )

        self.assertIsNone(at_close)
        assert early is not None
        self.assertEqual(
            as_tuples([early]),
            [
                (
                    "error",
                    "evaluation_before_detection",
                    early_refusal(case.tracking_id),
                    CHANGE_GAP_RECORD_ID,
                )
            ],
        )
        with self.assertRaises(ReportCompileError) as caught:
            compile_with((gap,), evaluations_with(gap_match(gap), completedAt=GAP_EARLY_TEXT))
        self.assertEqual(as_tuples(caught.exception.diagnostics), as_tuples([early]))


# *--- Store Fixtures ---*


class ChangeGapStoreCase(PersistedStoreTestCase):
    """A store driven through the command line, with change gaps recorded by `cases changes`."""

    def record_changes(self, changes: Path, *, as_of: str = INGESTED_AT) -> None:
        self.succeeds(
            ["changes", "record", "--db", str(self.database), "--changes", str(changes)]
            + ["--as-of", as_of]
        )

    def cases_changes(self, *options: str) -> tuple[int, str, str]:
        return run(["cases", "changes", "--db", str(self.database), *options])

    def lone_store(self, *changes: dict[str, Any], names: Sequence[str] = ("lab-gap-01",)) -> None:
        """Write the golden store, then record these changes and their gaps, and correlate."""
        self.populate()
        self.inventory = write_inventory(self.workspace, *(host(name) for name in names))
        self.record_changes(write_changes(self.workspace, *(changes or (window_change(),))))
        code, _, err = self.cases_changes(
            "--class", "C", "--as-of", INGESTED_AT, "--inventory", str(self.inventory)
        )
        self.assertEqual(code, 3, msg=err)
        self.correlate()

    def timed_store(self) -> None:
        """Ingest the timed artifacts, record the timed changes and their gaps, and correlate."""
        self.succeeds(
            ["ingest", *map(str, TIMED_ARTIFACTS), "--db", str(self.database)]
            + ["--as-of", TIMED_AS_OF]
        )
        self.record_changes(TIMED_CHANGES, as_of="2026-11-09T12:00:00Z")
        code, _, err = self.cases_changes(*TIMED_CASES_CHANGES)
        self.assertEqual(code, 3, msg=err)
        self.correlate()

    def cases(self) -> tuple[CaseState, ...]:
        with SQLiteEventStore(self.database) as store:
            return fold_all_cases(EventRepository(store))

    def gap_cases(self) -> list[CaseState]:
        return [case for case in self.cases() if case.source_type == CHANGE_GAP_SOURCE_TYPE]

    def stored_gaps(self) -> list[Observation]:
        with SQLiteEventStore(self.database) as store:
            return [
                item
                for item in rehydrate_observations(EventRepository(store))
                if item.source_type == CHANGE_GAP_SOURCE_TYPE
            ]

    def write_evaluations(self, *entries: dict[str, Any]) -> tuple[Path, str]:
        content = json.dumps({"evaluations": list(entries)})
        path = self.workspace / "change-gap-evaluations.json"
        path.write_text(content, encoding="utf-8")
        return path, content

    def evaluate_with(self, path: Path) -> tuple[int, str, str]:
        return run(["cases", "evaluate", "--db", str(self.database), "--evaluations", str(path)])

    def lone_report(self, kind: str = "vdt", *extra: str) -> tuple[int, str, str]:
        return run(
            ["report", kind, "--db", str(self.database), *LONE_REPORT, "--as-of", INGESTED_AT]
            + list(extra)
        )

    def listing(self) -> list[str]:
        out, err = self.succeeds(["cases", "list", "--db", str(self.database)])
        self.assertEqual(err, "")
        return out.splitlines()


# *--- Persisted Evaluations ---*


class PersistedChangeGapEvaluationCommandTests(ChangeGapStoreCase):
    """The persisted twin of the stateless matcher tests, on a store `cases changes` wrote.

    The golden store plus one change of lab-gap-01, whose window closed on 4 August with no
    verification, so the store holds one change gap case among the artifact cases.
    """

    def setUp(self) -> None:
        super().setUp()
        self.lone_store()
        (self.case,) = self.gap_cases()
        self.assertEqual(self.case.context_key, LONE_KEY)

    def test_the_triple_records_the_evaluation_and_the_disposition_closes_the_case(
        self,
    ) -> None:
        path, _ = self.write_evaluations({"match": triple(LONE_KEY), **GAP_EVALUATION})

        code, out, err = self.evaluate_with(path)

        self.assertEqual((code, err), (0, ""))
        self.assertIn("evaluations: 1 appended, 0 skipped", out)
        self.assertIn("dispositions: 1 appended, 0 skipped", out)
        (case,) = self.gap_cases()
        assert case.disposition is not None
        self.assertIs(case.disposition.status, CaseStatus.REMEDIATED)
        self.assertEqual(case.evaluation_count, 1)
        types = [
            record.event_type
            for record in self.records()
            if record.stream_id == case_stream_id(case.tracking_id)
        ]
        self.assertEqual(types[-2:], ["case.evaluated", "case.disposition_recorded"])
        code, report, err = self.lone_report("vdt", "--inventory", str(self.inventory))
        self.assertEqual(code, 0, msg=err)
        document = json.loads(report)
        (record,) = [
            item
            for item in document["vulnerabilities"]
            if item["providerTrackingId"] == case.tracking_id
        ]
        self.assertEqual(record["finalDisposition"], "Remediated")
        self.assertEqual(record["detection"]["detectedAt"], GAP_CLOSED_TEXT)
        self.assertEqual(record["x-complyroll"]["detectedAtSource"], "system")
        self.assertEqual(len(evu_deadlines(record)), 1)
        (row,) = document["x-complyroll"]["changes"]["obligations"]
        self.assertEqual((row["recorded"], row["trackingId"]), (True, case.tracking_id))

    def test_the_store_publishes_the_evaluated_record_the_stateless_run_does(self) -> None:
        path, content = self.write_evaluations({"match": triple(LONE_KEY), **GAP_EVALUATION})
        self.assertEqual(self.evaluate_with(path)[0], 0)
        code, report, err = self.lone_report("vdt", "--inventory", str(self.inventory))
        self.assertEqual(code, 0, msg=err)
        (stored,) = [
            item
            for item in json.loads(report)["vulnerabilities"]
            if item["providerTrackingId"] == self.case.tracking_id
        ]

        (gap,) = gaps(window_change())
        stateless = document_of(
            compile_with((gap,), parse_evaluations(content.encode("utf-8"))),
            self.case.tracking_id,
        )

        self.assertEqual(json.dumps(stored, sort_keys=True), json.dumps(stateless, sort_keys=True))

    def test_a_partial_triple_is_refused_as_a_change_detection_gap(self) -> None:
        latest = self.latest_sequence()
        for label, keys, remedy in (
            ("with sourceType", ("sourceRecordId", "sourceType"), "contextKey"),
            ("without sourceType", ("sourceRecordId",), "contextKey and sourceType"),
            ("with contextKey alone", ("sourceRecordId", "contextKey"), "sourceType"),
        ):
            with self.subTest(label):
                match = {key: value for key, value in triple(LONE_KEY).items() if key in keys}
                path, content = self.write_evaluations({"match": match, **GAP_EVALUATION})
                (entry,) = parse_evaluations(content.encode("utf-8")).entries
                described = entry.match.describe()

                code, out, err = self.evaluate_with(path)

                self.assertEqual((code, out), (1, ""))
                self.assertEqual(
                    err,
                    "error: evaluation_unmatched: evaluations could not be applied: "
                    f"evaluations[0]: {described} matches the change detection gap "
                    f"{self.case.tracking_id}; a change detection gap is matched by "
                    f"sourceRecordId, sourceType and contextKey together, so add {remedy}\n",
                )
                self.assertEqual(self.latest_sequence(), latest)

    def test_an_evaluation_before_the_close_is_refused_alike_on_every_persisted_surface(
        self,
    ) -> None:
        path, content = self.write_evaluations(
            {"match": triple(LONE_KEY), **GAP_EVALUATION, "completedAt": GAP_EARLY_TEXT}
        )
        verified = self.succeeds(["store", "verify", "--db", str(self.database)])

        evaluated = self.evaluate_with(path)

        self.assertEqual(self.succeeds(["store", "verify", "--db", str(self.database)]), verified)
        # Written around the writer, as a store written by something else could hold it.
        (parsed,) = parse_evaluations(content.encode("utf-8")).entries
        stream_id = case_stream_id(self.case.tracking_id)
        with SQLiteEventStore(self.database) as store:
            repository = EventRepository(store)
            (appended,) = repository.append_batch(
                stream_id,
                (
                    history_writers._pending(
                        CASE_EVALUATED,
                        history_writers._evaluation_payload(parsed),
                        datetime(2026, 8, 21, 12, tzinfo=UTC),
                        EventMetadata(actor="tester"),
                    ),
                ),
                expected_version=len(repository.read_stream(stream_id)),
            )
            checked = store.latest_sequence
        message = early_refusal(self.case.tracking_id)
        line = f"error: evaluation_before_detection: {message} [{CHANGE_GAP_RECORD_ID}]\n"

        reported = self.lone_report()
        audited = run(["store", "verify", "--db", str(self.database)])

        self.assertEqual(evaluated, (1, "", line))
        self.assertEqual(reported, (1, "", line))
        self.assertEqual(
            audited,
            (
                1,
                "",
                f"error: sequence {appended.sequence}: evaluation_before_detection: {message}\n"
                f"faults: 1 domain fault(s) in {checked} verified event(s)\n",
            ),
        )

    def test_a_later_verification_never_closes_the_case_and_a_disposition_does(self) -> None:
        # A pass scan inside the window, uploaded after the gap was recorded: the gap reads
        # contradicted, the case stays open, and only the evaluation's disposition closes it.
        late = self.workspace / "late-upload.xml"
        late.write_text(
            xccdf("late-upload", "lab-gap-01", "2026-08-03T12:00:00Z", "pass"), encoding="utf-8"
        )
        self.succeeds(["ingest", str(late), "--db", str(self.database), "--as-of", INGESTED_AT])
        self.correlate()

        code, _, err = self.lone_report("vdt", "--inventory", str(self.inventory))

        self.assertEqual(code, 0, msg=err)
        self.assertIn(
            f"info: change_gap_contradicted: {self.case.tracking_id} carries the recorded gap of "
            "the VDR-CSO-DAC window for host:lab-gap-01 after change CHG-E1 that closed "
            f"{GAP_CLOSED_TEXT}, but ",
            err,
        )
        (open_case,) = self.gap_cases()
        self.assertIsNone(open_case.disposition)
        (row,) = [line for line in self.listing() if line.startswith(self.case.tracking_id)]
        self.assertIn(" active ", f"{row} ")

        entry = {key: value for key, value in GAP_EVALUATION.items() if key != "disposition"}
        path, _ = self.write_evaluations(
            {"match": triple(LONE_KEY), **entry, "isFalsePositive": True}
        )
        self.assertEqual(self.evaluate_with(path)[0], 0)

        (closed,) = self.gap_cases()
        assert closed.disposition is not None
        self.assertIs(closed.disposition.status, CaseStatus.FALSE_POSITIVE)


class PersistedChangeGapAviCommandTests(ChangeGapStoreCase):
    """AVI from a store lists a change gap only once an evaluation accepts it."""

    def avi(self) -> dict[str, Any]:
        code, out, err = run(["report", "avi", "--db", str(self.database), *TIMED_REPORT])
        self.assertEqual(code, 0, msg=err)
        return dict(json.loads(out))

    def test_avi_lists_the_gap_only_once_an_evaluation_accepts_it(self) -> None:
        self.timed_store()
        before = self.avi()
        recorded = {
            row["trackingId"]
            for row in before["x-complyroll"]["changes"]["obligations"]
            if row["recorded"]
        }
        self.assertEqual(recorded, {IMAGE_CASE, RENDER_CASE})
        self.assertEqual(before["acceptedVulnerabilities"], [])

        path, _ = self.write_evaluations({"match": triple(IMAGE_KEY), **TIMED_ENTRY, **ACCEPTANCE})
        self.evaluate(path)
        after = self.avi()

        (item,) = after["acceptedVulnerabilities"]
        self.assertEqual(item["vulnerabilityDetail"]["providerTrackingId"], IMAGE_CASE)
        self.assertEqual(item["acceptanceRationale"], ACCEPTANCE["acceptanceRationale"])
        self.assertEqual(item["vulnerabilityDetail"]["detection"]["detectedAt"], CLOSED_ROWS[0][2])

    def test_the_store_and_the_stateless_run_accept_the_same_record(self) -> None:
        self.timed_store()
        path, _ = self.write_evaluations({"match": triple(IMAGE_KEY), **TIMED_ENTRY, **ACCEPTANCE})
        self.evaluate(path)

        stored = self.avi()["acceptedVulnerabilities"]
        stateless = project_avi(
            timed_with({"match": triple(IMAGE_KEY), **TIMED_ENTRY, **ACCEPTANCE})
        ).document["acceptedVulnerabilities"]

        self.assertEqual(json.dumps(stored, sort_keys=True), json.dumps(stateless, sort_keys=True))


# *--- Case Listing ---*


class ChangeGapCaseListTests(ChangeGapStoreCase):
    """`cases list` names each change gap case's context key, which an evaluation must state.

    No report document carries a gap's context key (ADR 0015 amendment 2026-10-26), so the
    listing adds it as a last column once a gap case of either kind is listed.
    """

    def assert_keys_listed(self, before: Sequence[str], after: Sequence[str]) -> dict[str, str]:
        """Check the CONTEXT KEY column of a listing and return each gap case's cell."""
        header, *rows = after
        self.assertEqual(header.split(), [*before[0].split(), "CONTEXT", "KEY"])
        cases = {case.tracking_id: case for case in self.cases()}
        keys = {}
        earlier = [line.split() for line in before[1:]]
        for row in rows:
            tracking_id = row.split()[0]
            case = cases[tracking_id]
            if case.source_type in (CHANGE_GAP_SOURCE_TYPE, COVERAGE_GAP_SOURCE_TYPE):
                # A change id may hold spaces, so the cell is read off the end of the row.
                self.assertTrue(row.endswith(f"  {case.context_key}"), row)
                keys[tracking_id] = case.context_key
            else:
                *cells, key = row.split()
                self.assertEqual(key, "-")
                self.assertIn(cells, earlier)
        return keys

    def test_cases_list_names_each_change_gap_case_context_key(self) -> None:
        self.succeeds(
            ["ingest", *map(str, TIMED_ARTIFACTS), "--db", str(self.database)]
            + ["--as-of", TIMED_AS_OF]
        )
        self.record_changes(TIMED_CHANGES, as_of="2026-11-09T12:00:00Z")
        self.correlate()
        before = self.listing()
        self.assertNotIn("CONTEXT KEY", before[0])
        self.assertEqual(self.cases_changes(*TIMED_CASES_CHANGES)[0], 3)
        self.correlate()

        keys = self.assert_keys_listed(before, self.listing())

        self.assertEqual(keys, {IMAGE_CASE: IMAGE_KEY, RENDER_CASE: RENDER_KEY})

    def test_a_listing_holding_both_gap_kinds_names_every_key(self) -> None:
        self.succeeds(
            ["ingest", *map(str, TIMED_ARTIFACTS), "--db", str(self.database)]
            + ["--as-of", TIMED_AS_OF]
        )
        self.record_changes(TIMED_CHANGES, as_of="2026-11-09T12:00:00Z")
        self.correlate()
        before = self.listing()
        coverage = run(["cases", "coverage", "--db", str(self.database), *TIMED_CASES_CHANGES])
        self.assertEqual(coverage[0], 3, msg=coverage[2])
        self.assertEqual(self.cases_changes(*TIMED_CASES_CHANGES)[0], 3)
        self.correlate()

        keys = self.assert_keys_listed(before, self.listing())

        kinds = {case.tracking_id: case.source_type for case in self.cases()}
        self.assertEqual(
            {kinds[tracking_id] for tracking_id in keys},
            {CHANGE_GAP_SOURCE_TYPE, COVERAGE_GAP_SOURCE_TYPE},
        )
        self.assertLessEqual({IMAGE_KEY, RENDER_KEY}, set(keys.values()))

    def test_a_change_id_holding_a_colon_and_a_space_is_listed_whole(self) -> None:
        change_id = "deploy:2026-08-03 web"
        self.lone_store(window_change(change_id))

        listing = self.listing()

        (case,) = self.gap_cases()
        self.assertEqual(case.context_key, f"VDR-CSO-DAC:change:{change_id}")
        (row,) = [line for line in listing if line.startswith(case.tracking_id)]
        self.assertTrue(row.endswith(f"  VDR-CSO-DAC:change:{change_id}"), row)
        self.assertTrue(listing[0].endswith("CONTEXT KEY"), listing[0])


# *--- Two Resources ---*


class ChangeGapTwoResourceCaseTests(ChangeGapStoreCase):
    """P M15: one change naming two hosts is one stored case, listing both and both gaps.

    The record's description takes one member's title, so it names one host; its title
    carries the change id, and `resources` and `observationIds` name every member.
    """

    def setUp(self) -> None:
        super().setUp()
        self.lone_store(
            window_change("CHG-E2", "lab-gap-01", "lab-gap-02"),
            names=("lab-gap-01", "lab-gap-02"),
        )

    def test_one_case_links_both_resources_and_both_gaps(self) -> None:
        stored = self.stored_gaps()
        self.assertEqual(len(stored), 2)

        (case,) = self.gap_cases()

        self.assertEqual(case.context_key, "VDR-CSO-DAC:change:CHG-E2")
        self.assertEqual(
            sorted((link.resource_type, link.resource_id) for link in case.links),
            [("host", "lab-gap-01"), ("host", "lab-gap-02")],
        )
        self.assertEqual(
            sorted(link.observation_id for link in case.links),
            sorted(item.observation_id for item in stored),
        )
        (row,) = [line for line in self.listing() if line.startswith(case.tracking_id)]
        self.assertEqual(row.split()[3], "2")

    def test_its_record_lists_both_resources_and_both_observation_ids(self) -> None:
        (case,) = self.gap_cases()
        stored = self.stored_gaps()

        code, report, err = self.lone_report("vdt", "--inventory", str(self.inventory))

        self.assertEqual(code, 0, msg=err)
        document = json.loads(report)
        (record,) = [
            item
            for item in document["vulnerabilities"]
            if item["providerTrackingId"] == case.tracking_id
        ]
        extension = record["x-complyroll"]
        self.assertEqual(
            extension["resources"],
            [
                {"resourceId": "lab-gap-01", "resourceType": "host"},
                {"resourceId": "lab-gap-02", "resourceType": "host"},
            ],
        )
        self.assertEqual(
            sorted(extension["observationIds"]), sorted(item.observation_id for item in stored)
        )
        self.assertIn("after change CHG-E2 closed", record["vulnerabilityDescription"])
        self.assertEqual(
            {row["trackingId"] for row in document["x-complyroll"]["changes"]["obligations"]},
            {case.tracking_id},
        )
        # The stateless run over the same change publishes the same record.
        both = gaps(window_change("CHG-E2", "lab-gap-01", "lab-gap-02"))
        stateless = document_of(compile_with(both), case.tracking_id)
        self.assertEqual(json.dumps(record, sort_keys=True), json.dumps(stateless, sort_keys=True))

    def test_one_evaluation_by_the_triple_closes_the_whole_case(self) -> None:
        (case,) = self.gap_cases()
        path, _ = self.write_evaluations(
            {"match": triple("VDR-CSO-DAC:change:CHG-E2"), **GAP_EVALUATION}
        )

        self.assertEqual(self.evaluate_with(path)[0], 0)

        (closed,) = self.gap_cases()
        assert closed.disposition is not None
        self.assertIs(closed.disposition.status, CaseStatus.REMEDIATED)
        self.assertEqual(len({link.resource_id for link in closed.links}), 2)


if __name__ == "__main__":
    unittest.main()
