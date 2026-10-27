# ******************************************************************************
# *Title: Coverage Gap Evaluation Tests*
# *Author: Kyle Versluis*
# *Description: Evaluation matching and order refusals for coverage gaps.*
# ******************************************************************************
"""Tests that an evaluation finds a coverage gap by the full triple alone (ADR 0015, PR 3)."""

# *--- Imports ---*

from __future__ import annotations

import importlib
import json
import pkgutil
import unittest
from collections.abc import Sequence
from dataclasses import replace
from datetime import UTC, datetime
from types import SimpleNamespace
from typing import Any

from test_coverage import derive, host, inventory_of, observation, policy
from test_evaluation_order import SYSTEM_REMEDY
from test_reports import (
    ARTIFACTS,
    AS_OF,
    DETECTED_AT,
    compiled_artifact,
    ingest_text,
    options,
)

import complyroll
from complyroll.adapters import (
    DETECTION_FAILURE_SOURCE_TYPE,
    DiagnosticLevel,
    IngestResult,
    ingest_stig_artifact,
)
from complyroll.correlation import VulnerabilityGroup, group_open_observations
from complyroll.history import CaseState, EvaluationMatchError
from complyroll.history import writers as history_writers
from complyroll.history.order import case_order_diagnostic
from complyroll.models import (
    RESERVED_SOURCE_TYPE_PREFIX,
    CaseStatus,
    Observation,
    ObservationDisposition,
    ObservationOrigin,
    ResourceRef,
    SourceSeverity,
)
from complyroll.reports import (
    CompiledRecordSet,
    DetectionAttestation,
    EvaluationSet,
    ReportCompileError,
    ReportDiagnostic,
    compile_record_set,
    parse_evaluations,
    project_vdt,
)
from complyroll.reports import vdt as vdt_module
from complyroll.reports.evaluations import EvaluationMatch
from complyroll.reports.gaps import (
    COVERAGE_GAP_RECORD_ID,
    COVERAGE_GAP_SOURCE_TYPE,
    coverage_gap_observations,
)
from complyroll.store.sqlite import shown

# *--- Fixtures ---*

#: Each gap host is expected from here, so its Class C MVX window closes three days later.
EXPECTED_SINCE = "2026-08-01T00:00:00Z"
GAP_CLOSED_TEXT = "2026-08-04T00:00:00Z"
GAP_CLOSED_AT = datetime(2026, 8, 4, tzinfo=UTC)
#: One second before the close, the latest instant the order check refuses.
GAP_EARLY_TEXT = "2026-08-03T23:59:59Z"
#: The remedy a gap's order refusal names, exactly as ADR 0015 states it.
GAP_REMEDY = (
    "a coverage gap is detected when its window closed, so evaluate it at or after that "
    "instant, or correct completedAt"
)
#: A reserved type that is neither a detection failure nor a coverage gap.
OTHER_SOURCE_TYPE = "complyroll.synthetic-other"
#: Values no default would produce, so the record shows they came from the evaluation.
GAP_EVALUATION: dict[str, Any] = {
    "completedAt": GAP_CLOSED_TEXT,
    "isInternetReachable": True,
    "isLikelyExploitable": False,
    "pain": 2,
    "potentialAgencyImpact": "Findings on one lab host could stay unreported for one window.",
    "rationale": "No verification ran in the window; the next scan found nothing new.",
    "evaluator": "Example Provider vulnerability team (coverage review)",
    "disposition": "remediated",
}


def gaps(*names: str) -> tuple[Observation, ...]:
    """Return one MVX gap per job-less host, each closing at GAP_CLOSED_AT."""
    inventory = inventory_of(*(host(name, expectedSince=EXPECTED_SINCE) for name in names))
    built = coverage_gap_observations(derive([], inventory, AS_OF, policy("C")), ingested_at=AS_OF)
    assert len(built) == len(names), built
    return built


def gap_match(
    gap: Observation, *, source_type: bool = True, context_key: bool = True
) -> dict[str, str]:
    """Return the documented triple for one gap, less the keys a test drops."""
    match = {"sourceRecordId": COVERAGE_GAP_RECORD_ID}
    if source_type:
        match["sourceType"] = COVERAGE_GAP_SOURCE_TYPE
    if context_key:
        match["contextKey"] = gap.context_key
    return match


def evaluations_with(match: dict[str, str], **overrides: object) -> EvaluationSet:
    """Parse one gap evaluation through the bounded reader the CLI uses."""
    entry: dict[str, Any] = {"match": match, **GAP_EVALUATION, **overrides}
    return parse_evaluations(json.dumps({"evaluations": [entry]}).encode("utf-8"))


def system_observation(source_type: str = OTHER_SOURCE_TYPE) -> Observation:
    """Return a lone system observation of a reserved type that has no kind name."""
    observation = Observation(
        observation_id="pending",
        source_type=source_type,
        source_tool="complyroll",
        parser_name=source_type,
        parser_version="1",
        source_record_id="synthetic-other",
        resource=ResourceRef(resource_id="lab-host-01", resource_type="host"),
        observed_at=datetime(2026, 8, 10, 9, 0, tzinfo=UTC),
        ingested_at=AS_OF,
        disposition=ObservationDisposition.OPEN,
        source_severity=SourceSeverity.UNKNOWN,
        title="synthetic system observation of another reserved type",
        description="",
        source_artifact_digest="",
        source_artifact_name="",
        source_identifiers=(),
        source_metadata=(("synthetic.note", "no kind name"),),
        evidence_ids=("synthetic:lab-host-01",),
        context_key="synthetic:lab-host-01",
        origin=ObservationOrigin.SYSTEM,
    )
    return replace(observation, observation_id=observation.derived_observation_id)


def hostile_checklist(context_key: str) -> str:
    """Return a CKLB whose one rule copies a gap's record id and context key."""
    return json.dumps(
        {
            "target_data": {"host_name": "host-hostile"},
            "stigs": [
                {
                    "stig_id": context_key,
                    "rules": [
                        {
                            "group_id": COVERAGE_GAP_RECORD_ID,
                            "status": "open",
                            "severity": "high",
                            "rule_title": "Synthetic rule that copies a gap's key",
                        }
                    ],
                }
            ],
        }
    )


def compile_with(
    system: Sequence[Observation],
    evaluations: EvaluationSet | None = None,
    *,
    extra: Sequence[IngestResult] = (),
) -> CompiledRecordSet:
    """Match and compile exactly as `compile_record_set_from_artifacts` does.

    The fixture artifacts sit beside the system records, so a match that strays shows.
    """
    readings = [ingest_stig_artifact(path, ingested_at=AS_OF) for path in ARTIFACTS]
    readings.extend(extra)
    observations = (
        *(item for reading in readings for item in reading.observations),
        *system,
    )
    matches = vdt_module._match_evaluations(group_open_observations(observations), evaluations)
    return compile_record_set(
        artifacts=tuple(compiled_artifact(reading) for reading in readings),
        observations=observations,
        ingest_diagnostics=(),
        evaluations_by_tracking_id=matches,
        attestation=DetectionAttestation(default=DETECTED_AT),
        options=options(),
    )


def group_of(*observations: Observation) -> VulnerabilityGroup:
    (group,) = group_open_observations(observations)
    return group


def tracking_ids(*observations: Observation) -> list[str]:
    """Return each observation's group tracking id, in the compiler's group order."""
    return [group.tracking_id for group in group_open_observations(observations)]


def document_of(record_set: CompiledRecordSet, tracking_id: str) -> dict[str, Any]:
    (found,) = [
        item
        for item in project_vdt(record_set).document["vulnerabilities"]
        if item["providerTrackingId"] == tracking_id
    ]
    return dict(found)


def as_tuples(diagnostics: Sequence[ReportDiagnostic]) -> list[tuple[str, str, str, str]]:
    return [
        (item.level.value, item.code, item.message, item.location or "") for item in diagnostics
    ]


def case_of(group: VulnerabilityGroup) -> CaseState:
    """Return the case `cases correlate` would open for a group, before any event on it.

    The persisted refusals are exercised here on the folded state they read; the end-to-end
    twins on a store `cases coverage` wrote are in `tests/test_coverage_history.py`.
    """
    return CaseState(
        tracking_id=group.tracking_id,
        provider_tracking_id=None,
        source_type=group.source_type,
        source_record_id=group.source_record_id,
        context_key=group.context_key,
        title=group.title,
        description=group.description,
        created_at=AS_OF,
        created_sequence=1,
        links=(),
        attestation=None,
        evaluations=(),
        pain_reductions=(),
        disposition=None,
        identified_sequence=None,
        last_sequence=1,
    )


def context_key_text(
    described: str, kind: str, tracking_id: str, remedy: str = "contextKey"
) -> str:
    """Return the refusal of a match short of the triple, naming the keys it leaves out."""
    return (
        f"{described} matches the {kind} {tracking_id}; a {kind} is matched by "
        f"sourceRecordId, sourceType and contextKey together, so add {remedy}"
    )


def early_refusal(tracking_id: str) -> str:
    return (
        f"{tracking_id} was evaluated at {GAP_EARLY_TEXT}, before its detection time "
        f"{GAP_CLOSED_TEXT} (source system); {GAP_REMEDY}"
    )


# *--- Stateless Matching ---*


class GapEvaluationTests(unittest.TestCase):
    """The full triple selects one gap, which takes PAIN and closes from it alone."""

    def test_the_triple_evaluates_and_closes_the_gap(self) -> None:
        (gap,) = gaps("lab-gap-01")
        self.assertEqual(gap.context_key, "VDR-TFR-MVX:resource:host:lab-gap-01")
        (tracking_id,) = tracking_ids(gap)
        evaluations = evaluations_with(gap_match(gap))

        record_set = compile_with((gap,), evaluations)

        (record,) = [item for item in record_set.records if item.tracking_id == tracking_id]
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
        # EVU runs from the window close, through the system detection-time branch.
        (deadline,) = [
            item
            for item in document["x-complyroll"]["deadlines"]
            if item["ruleId"] == "VER-TFR-EVU"
        ]
        self.assertEqual(deadline["startAt"], GAP_CLOSED_TEXT)
        self.assertTrue(project_vdt(record_set).validation.is_valid)
        self.assertEqual(
            [item.code for item in record_set.diagnostics if "evaluation" in item.code], []
        )

    def test_without_an_evaluation_the_gap_carries_no_rating_or_disposition(self) -> None:
        (gap,) = gaps("lab-gap-01")
        (tracking_id,) = tracking_ids(gap)

        record_set = compile_with((gap,))

        (record,) = [item for item in record_set.records if item.tracking_id == tracking_id]
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

    def test_the_triple_selects_one_gap_of_two(self) -> None:
        first, second = gaps("lab-gap-01", "lab-gap-02")
        self.assertNotEqual(first.context_key, second.context_key)
        (first_id,) = tracking_ids(first)
        (second_id,) = tracking_ids(second)

        record_set = compile_with((first, second), evaluations_with(gap_match(second)))

        evaluated = {item.tracking_id: item.evaluation for item in record_set.records}
        self.assertIsNone(evaluated[first_id])
        self.assertIsNotNone(evaluated[second_id])

    def test_a_lone_gap_is_not_matched_without_its_context_key(self) -> None:
        # One gap matches the pair today, and the next gap of another clock would make the
        # same file ambiguous, so the triple is required even when nothing else matches.
        (gap,) = gaps("lab-gap-01")
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
                            context_key_text(described, "coverage gap", tracking_id, remedy),
                            "evaluations[0]",
                        )
                    ],
                )

    def test_a_lone_gap_is_not_matched_without_its_source_type(self) -> None:
        # Without the source type the entry would also take an artifact record of the same
        # record id and context key, so the triple is required here too.
        (gap,) = gaps("lab-gap-01")
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
                    context_key_text(described, "coverage gap", tracking_id, "sourceType"),
                    "evaluations[0]",
                )
            ],
        )

    def test_two_gaps_matched_without_a_context_key_are_ambiguous(self) -> None:
        # Ambiguity is checked before the lone-record refusal, so both gaps are named, and
        # the remedy gives each one's value of every key the entry left out, in id order.
        pair = gaps("lab-gap-01", "lab-gap-02")
        named = ", ".join(tracking_ids(*pair))
        first, second = "case-22632c82f0839171", "case-ddfb80698607b6ff"
        self.assertEqual(sorted(tracking_ids(*pair)), [first, second])
        key = "contextKey='VDR-TFR-MVX:resource:host:lab-gap-0{}'"
        kind = f"sourceType='{COVERAGE_GAP_SOURCE_TYPE}'"
        for label, source_type, remedy in (
            (
                "sourceType given",
                True,
                f"add contextKey ({first} has {key.format(2)}, {second} has {key.format(1)})",
            ),
            (
                "neither given",
                False,
                f"add contextKey or sourceType ({first} has {key.format(2)} and {kind}, "
                f"{second} has {key.format(1)} and {kind})",
            ),
        ):
            with self.subTest(label):
                evaluations = evaluations_with(
                    gap_match(pair[0], source_type=source_type, context_key=False)
                )

                with self.assertRaises(ReportCompileError) as caught:
                    compile_with(pair, evaluations)

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
        pair = gaps("lab-gap-01", "lab-gap-02")
        evaluations = evaluations_with(gap_match(pair[0], context_key=False))
        cases = [case_of(group_of(item)) for item in reversed(pair)]

        with self.assertRaises(ReportCompileError) as stateless:
            compile_with(pair, evaluations)
        with self.assertRaises(EvaluationMatchError) as persisted:
            history_writers._match_cases(evaluations, cases)

        (diagnostic,) = stateless.exception.diagnostics
        (problem,) = persisted.exception.problems
        remedy = diagnostic.message.partition("); ")[2]
        self.assertTrue(remedy.startswith("add contextKey (case-"), remedy)
        self.assertEqual(problem.partition("); ")[2], remedy)

    def test_an_ambiguity_names_ten_candidates_and_counts_the_rest(self) -> None:
        # Ten is named whole, eleven and twelve name ten and count the rest (CL5B-03).
        for count, suffix in ((10, ""), (11, ", and 1 more"), (12, ", and 2 more")):
            with self.subTest(candidates=count):
                names = [f"lab-gap-{index:02d}" for index in range(1, count + 1)]
                matched = gaps(*names)
                evaluations = evaluations_with(gap_match(matched[0], context_key=False))
                by_id = dict(zip(tracking_ids(*matched), matched, strict=True))
                listed = ", ".join(
                    f"{tracking_id} has contextKey={by_id[tracking_id].context_key!r}"
                    for tracking_id in sorted(by_id)[:10]
                )

                with self.assertRaises(ReportCompileError) as caught:
                    compile_with(matched, evaluations)

                (diagnostic,) = caught.exception.diagnostics
                self.assertTrue(
                    diagnostic.message.endswith(f"); add contextKey ({listed}{suffix})"),
                    diagnostic.message,
                )
                # The tracking id list before the remedy is unchanged and unbounded.
                self.assertIn(
                    f"matches {count} vulnerabilities ({', '.join(by_id)}); ", diagnostic.message
                )

    def test_an_ambiguity_quotes_each_value_within_the_bound(self) -> None:
        # A value comes from an artifact, so it is quoted and cut as stored text is.
        long_key = "k" * 500
        forged = "a\nerror: forged"
        candidates = [
            SimpleNamespace(tracking_id="case-2", source_type="cklb", context_key=forged),
            SimpleNamespace(tracking_id="case-1", source_type="cklb", context_key=long_key),
        ]
        match = EvaluationMatch(source_record_id="V-1", source_type="cklb")

        remedy = match.ambiguity_remedy(candidates)

        self.assertEqual(
            remedy,
            f"add contextKey (case-1 has contextKey={shown(long_key)}, case-2 has "
            f"contextKey={shown(forged)})",
        )
        self.assertNotIn("\n", remedy)
        self.assertLess(len(remedy), len(long_key))

    def test_every_reserved_type_requires_the_triple(self) -> None:
        # A reserved type with no kind name of its own is still refused, as a system record.
        other = system_observation()
        (tracking_id,) = tracking_ids(other)
        evaluations = evaluations_with(
            {"sourceRecordId": other.source_record_id, "sourceType": OTHER_SOURCE_TYPE},
            completedAt="2026-08-10T09:00:00Z",
        )

        with self.assertRaises(ReportCompileError) as caught:
            compile_with((other,), evaluations)

        described = evaluations.entries[0].match.describe()
        self.assertEqual(
            as_tuples(caught.exception.diagnostics),
            [
                (
                    "error",
                    "evaluation_context_key_required",
                    context_key_text(described, "system record", tracking_id),
                    "evaluations[0]",
                )
            ],
        )


# *--- Hostile Records ---*


class GapHostileRecordTests(unittest.TestCase):
    """No artifact can carry the gap's source type, so the triple matches the gap alone."""

    def test_an_artifact_observation_cannot_carry_the_gap_source_type(self) -> None:
        (gap,) = gaps("lab-gap-01")
        with self.assertRaisesRegex(
            ValueError,
            r"^source_type prefix 'complyroll\.' is reserved for system observations$",
        ):
            Observation(
                observation_id="obs-forged",
                source_type=COVERAGE_GAP_SOURCE_TYPE,
                source_tool="complyroll",
                parser_name="complyroll.coverage",
                parser_version="1",
                source_record_id=COVERAGE_GAP_RECORD_ID,
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
            (COVERAGE_GAP_RECORD_ID, gap.context_key, ObservationOrigin.ARTIFACT),
        )
        return reading

    def test_the_triple_matches_the_gap_beside_a_hostile_checklist(self) -> None:
        (gap,) = gaps("lab-gap-01")
        (tracking_id,) = tracking_ids(gap)

        record_set = compile_with(
            (gap,), evaluations_with(gap_match(gap)), extra=(self.hostile(gap),)
        )

        copies = [
            item for item in record_set.records if item.source_record_id == COVERAGE_GAP_RECORD_ID
        ]
        by_type = {item.source_type: item for item in copies}
        self.assertEqual(set(by_type), {COVERAGE_GAP_SOURCE_TYPE, "cklb"})
        self.assertEqual(by_type[COVERAGE_GAP_SOURCE_TYPE].tracking_id, tracking_id)
        self.assertIsNotNone(by_type[COVERAGE_GAP_SOURCE_TYPE].evaluation)
        self.assertIsNone(by_type["cklb"].evaluation)
        self.assertEqual(by_type["cklb"].context_key, gap.context_key)

    def test_the_pair_alone_is_ambiguous_beside_a_hostile_checklist(self) -> None:
        (gap,) = gaps("lab-gap-01")

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


# *--- Stateless Order ---*


class GapEvaluationOrderTests(unittest.TestCase):
    """A gap is detected when its window closed; an earlier evaluation is refused."""

    def test_an_evaluation_one_second_before_the_close_is_refused(self) -> None:
        (gap,) = gaps("lab-gap-01")
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
                    COVERAGE_GAP_RECORD_ID,
                )
            ],
        )
        # The window close is fixed on both paths, so no as-of remedy is offered.
        self.assertNotIn("as-of", caught.exception.diagnostics[0].message)

    def test_a_refused_gap_record_no_window_derives_stops_the_compile(self) -> None:
        # Coupling: the underived-gap notes read only gaps whose record compiled, so they rely
        # on `compile_record_set` raising on any record error before they are built. Without
        # that raise, this refused gap would leave neither its record nor its note.
        (gap,) = gaps("lab-gap-01")
        (tracking_id,) = tracking_ids(gap)
        # A pass scan inside the window, so this run derives no gap and the recorded one is
        # contradicted.
        scan = observation("lab-gap-01", at=datetime(2026, 8, 2, tzinfo=UTC))
        inventory = inventory_of(host("lab-gap-01", expectedSince=EXPECTED_SINCE))

        def compile_gap_aware(evaluations: EvaluationSet) -> CompiledRecordSet:
            observations = (gap, scan)
            return compile_record_set(
                artifacts=(),
                observations=observations,
                ingest_diagnostics=(),
                evaluations_by_tracking_id=vdt_module._match_evaluations(
                    group_open_observations(observations), evaluations
                ),
                attestation=DetectionAttestation(default=DETECTED_AT),
                options=options(inventory=inventory),
                gap_aware=True,
            )

        in_order = compile_gap_aware(evaluations_with(gap_match(gap)))
        (note,) = [
            item for item in in_order.diagnostics if item.code == "coverage_gap_contradicted"
        ]
        self.assertTrue(note.message.startswith(f"{tracking_id} "), note.message)

        with self.assertRaises(ReportCompileError) as caught:
            compile_gap_aware(evaluations_with(gap_match(gap), completedAt=GAP_EARLY_TEXT))

        self.assertEqual(
            [item.code for item in caught.exception.diagnostics], ["evaluation_before_detection"]
        )
        self.assertEqual(caught.exception.diagnostics[0].message, early_refusal(tracking_id))

    def test_the_system_remedy_branches_by_source_type(self) -> None:
        def remedy(detected_source: str, source_type: str | None) -> str:
            diagnostic = vdt_module.evaluation_order_diagnostic(
                tracking_id="case-0000000000000000",
                location="here",
                detected_at=GAP_CLOSED_AT,
                detected_source=detected_source,
                completed_at=datetime(2026, 8, 3, 23, 59, 59, tzinfo=UTC),
                source_type=source_type,
            )
            assert diagnostic is not None
            self.assertIs(diagnostic.level, DiagnosticLevel.ERROR)
            return diagnostic.message.partition(f"(source {detected_source}); ")[2]

        artifact = "supply the artifact that detected it earlier, or correct completedAt"
        for label, detected_source, source_type, expected in (
            ("coverage gap", "system", COVERAGE_GAP_SOURCE_TYPE, GAP_REMEDY),
            ("detection failure", "system", DETECTION_FAILURE_SOURCE_TYPE, SYSTEM_REMEDY),
            ("no source type", "system", None, SYSTEM_REMEDY),
            ("another reserved type", "system", OTHER_SOURCE_TYPE, SYSTEM_REMEDY),
            ("an artifact source", "artifact", COVERAGE_GAP_SOURCE_TYPE, artifact),
        ):
            with self.subTest(label):
                self.assertEqual(remedy(detected_source, source_type), expected)


# *--- Persisted Seams ---*


class PersistedGapEvaluationTests(unittest.TestCase):
    """`cases evaluate` refuses and orders a gap case exactly as the compiler does.

    These run the writer's matcher and the order check on the case state and group they
    read; `PersistedGapEvaluationCommandTests` runs the same refusals on a real store.
    """

    def test_the_triple_selects_the_gap_case_with_its_disposition(self) -> None:
        first, second = gaps("lab-gap-01", "lab-gap-02")
        cases = [case_of(group_of(first)), case_of(group_of(second))]
        evaluations = evaluations_with(gap_match(second))

        matched = history_writers._match_cases(evaluations, cases)

        self.assertEqual(list(matched), [cases[1].tracking_id])
        self.assertIs(matched[cases[1].tracking_id].resolved_status, CaseStatus.REMEDIATED)

    def test_a_lone_gap_case_is_not_matched_without_its_context_key(self) -> None:
        (gap,) = gaps("lab-gap-01")
        case = case_of(group_of(gap))
        for label, source_type, remedy in (
            ("with sourceType", True, "contextKey"),
            ("without sourceType", False, "contextKey and sourceType"),
        ):
            with self.subTest(label):
                evaluations = evaluations_with(
                    gap_match(gap, source_type=source_type, context_key=False)
                )

                with self.assertRaises(EvaluationMatchError) as caught:
                    history_writers._match_cases(evaluations, [case])

                described = evaluations.entries[0].match.describe()
                self.assertEqual(
                    caught.exception.problems,
                    (
                        "evaluations[0]: "
                        + context_key_text(described, "coverage gap", case.tracking_id, remedy),
                    ),
                )

    def test_a_lone_gap_case_is_not_matched_without_its_source_type(self) -> None:
        (gap,) = gaps("lab-gap-01")
        case = case_of(group_of(gap))
        evaluations = evaluations_with(gap_match(gap, source_type=False))

        with self.assertRaises(EvaluationMatchError) as caught:
            history_writers._match_cases(evaluations, [case])

        described = evaluations.entries[0].match.describe()
        self.assertEqual(
            caught.exception.problems,
            (
                "evaluations[0]: "
                + context_key_text(described, "coverage gap", case.tracking_id, "sourceType"),
            ),
        )

    def test_two_gap_cases_matched_without_a_context_key_are_ambiguous(self) -> None:
        pair = gaps("lab-gap-01", "lab-gap-02")
        cases = [case_of(group_of(item)) for item in pair]
        evaluations = evaluations_with(gap_match(pair[0], context_key=False))

        with self.assertRaises(EvaluationMatchError) as caught:
            history_writers._match_cases(evaluations, cases)

        (problem,) = caught.exception.problems
        self.assertIn("matches 2 cases", problem)
        self.assertIn("); add contextKey (", problem)

    def test_another_reserved_type_case_is_named_a_system_record(self) -> None:
        other = system_observation()
        case = case_of(group_of(other))
        evaluations = evaluations_with(
            {"sourceRecordId": other.source_record_id, "sourceType": OTHER_SOURCE_TYPE}
        )

        with self.assertRaises(EvaluationMatchError) as caught:
            history_writers._match_cases(evaluations, [case])

        described = evaluations.entries[0].match.describe()
        self.assertEqual(
            caught.exception.problems,
            ("evaluations[0]: " + context_key_text(described, "system record", case.tracking_id),),
        )

    def test_the_order_check_reads_the_same_text_as_the_compiler(self) -> None:
        (gap,) = gaps("lab-gap-01")
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
                    COVERAGE_GAP_RECORD_ID,
                )
            ],
        )
        with self.assertRaises(ReportCompileError) as caught:
            compile_with((gap,), evaluations_with(gap_match(gap), completedAt=GAP_EARLY_TEXT))
        self.assertEqual(as_tuples(caught.exception.diagnostics), as_tuples([early]))


# *--- Reserved Types ---*


def minted_reserved_types() -> set[str]:
    """Return every reserved source type a module of the package names as a constant.

    The convention is a module-level `*_SOURCE_TYPE` constant, as `adapters.failures` and
    `reports.gaps` spell theirs, so a third reserved type is found the day it is defined.
    """
    found: set[str] = set()
    for info in pkgutil.walk_packages(complyroll.__path__, f"{complyroll.__name__}."):
        if info.name.endswith(".__main__"):
            continue
        module = importlib.import_module(info.name)
        for name, value in vars(module).items():
            if (
                name.endswith("_SOURCE_TYPE")
                and isinstance(value, str)
                and value.startswith(RESERVED_SOURCE_TYPE_PREFIX)
            ):
                found.add(value)
    return found


class ReservedSourceTypeTableTests(unittest.TestCase):
    """Each reserved type has its own entry at each of the three places a report branches.

    A refusal names the record by kind, an order refusal names its remedy, and the
    attestation sentence names what timed it. Each falls back to the detection failure's
    text for a type it does not know, so a third type added to one and not the others would
    read as a failure in silence.
    """

    def test_the_package_mints_the_two_reserved_types(self) -> None:
        self.assertLessEqual(
            {DETECTION_FAILURE_SOURCE_TYPE, COVERAGE_GAP_SOURCE_TYPE}, minted_reserved_types()
        )

    def test_every_minted_reserved_type_has_a_kind_a_remedy_and_a_sentence(self) -> None:
        types = sorted(minted_reserved_types())
        kinds = [vdt_module.system_record_kind(source_type) for source_type in types]
        self.assertEqual(len(set(kinds)), len(types))
        for source_type, kind in zip(types, kinds, strict=True):
            with self.subTest(source_type=source_type):
                self.assertNotEqual(kind, "system record")
                diagnostic = vdt_module.evaluation_order_diagnostic(
                    tracking_id="case-0000000000000000",
                    location="here",
                    detected_at=GAP_CLOSED_AT,
                    detected_source="system",
                    completed_at=datetime(2026, 8, 3, tzinfo=UTC),
                    source_type=source_type,
                )
                assert diagnostic is not None
                self.assertIn(f"; a {kind} is detected when", diagnostic.message)
                sentence = vdt_module._system_detection_sentence({source_type})
                self.assertIn(f"or, for a {kind}, from the instant", sentence)
                self.assertEqual(sentence.count(", for a "), 1)


if __name__ == "__main__":
    unittest.main()
