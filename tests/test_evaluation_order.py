# ******************************************************************************
# *Title: Evaluation Order Tests*
# *Author: Kyle Versluis*
# *Description: Tests for ordering evaluations against detection time.*
# ******************************************************************************
"""Tests for ordering an evaluation's completedAt against its record's detection time.

The compiler refuses a record evaluated before a detection time that is its own
(`artifact`, `attestation`, `system`), warns on a partly timestamped group, and names
every refusal it reaches in one run (ADR 0007 amendment 2026-10-14). The history writers
mirror it: `cases evaluate` and `cases attest-detection` refuse, before any append, what a
report from the store would refuse, and print the report's lines (ADR 0008 amendment
2026-10-14).
"""

# *--- Imports ---*

from __future__ import annotations

import io
import json
import tempfile
import unittest
from collections.abc import Callable, Mapping, Sequence
from contextlib import redirect_stderr, redirect_stdout
from dataclasses import replace
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from test_reports import compile_fixtures, evaluation_json, evaluations_for, options

from complyroll.adapters import IngestResult, ingest_stig_artifact
from complyroll.cli import main
from complyroll.correlation import VulnerabilityGroup, group_open_observations
from complyroll.events import EventMetadata, EventRepository, case_stream_id, iso_utc
from complyroll.history import (
    CASE_CREATED,
    CASE_EVALUATED,
    DETECTION_ATTESTED,
    AttestationOutcome,
    EvaluationOrderError,
    EvaluationOutcome,
    apply_evaluations,
    attest_detection,
    correlate_cases,
    fold_all_cases,
    record_ingest,
)
from complyroll.history import writers as history_writers
from complyroll.models import CaseStatus
from complyroll.reports import (
    EvaluationSet,
    ReportCompileError,
    ReportDiagnostic,
    compile_record_set_from_artifacts,
)
from complyroll.reports.replay import compile_record_set_from_history
from complyroll.reports.vdt import CompiledRecordSet
from complyroll.store import SQLiteEventStore

# *--- Fixtures ---*

BANNER_RULE = "banner_etc_issue"
SSHD_RULE = "sshd_disable_root_login"
#: The source timestamp of every timed result below.
TIMED_AT = "2026-08-10T09:00:00Z"
#: The default evaluation's completedAt, before `TIMED_AT`.
EARLY = "2026-08-04T12:00:00Z"
#: An attested instant after `EARLY`, and one before it.
LATE_ATTESTATION = datetime(2026, 8, 5, 0, 0, tzinfo=UTC)
EARLY_ATTESTATION = datetime(2026, 8, 1, 0, 0, tzinfo=UTC)

#: The remedy each source's refusal names, exactly as ADR 0007's amendment states it.
ARTIFACT_REMEDY = "supply the artifact that detected it earlier, or correct completedAt"
ATTESTATION_REMEDY = "attest an earlier detection time, or correct completedAt"
SYSTEM_REMEDY = (
    "a detection process failure is detected when it is recorded, at the ingest --as-of "
    "in history and at the run's as-of on the stateless path, so evaluate it at or after "
    "that instant, correct completedAt, or on the stateless path report with an --as-of "
    "no later than completedAt"
)


def xccdf(benchmark: str, results: Sequence[tuple[str, str | None]], rule: str) -> str:
    """Return an XCCDF document failing one rule on each `(target, end-time)` result.

    A result with no end-time declares no source timestamp.
    """

    blocks = []
    for target, end_time in results:
        timing = "" if end_time is None else f' end-time="{end_time}"'
        blocks.append(
            f"""  <TestResult id="{benchmark}"{timing}>
    <target>{target}</target>
    <rule-result idref="xccdf_org.ssgproject.content_rule_{rule}" severity="medium">
      <result>fail</result>
      <ident system="https://public.cyber.mil/stigs/cci/">CCI-000048</ident>
    </rule-result>
  </TestResult>"""
        )
    return (
        '<?xml version="1.0" encoding="UTF-8"?>\n'
        f'<Benchmark xmlns="http://checklists.nist.gov/xccdf/1.2" id="{benchmark}">\n'
        + "\n".join(blocks)
        + "\n</Benchmark>\n"
    )


def groups_of(paths: Sequence[Path]) -> tuple[VulnerabilityGroup, ...]:
    """Return the groups the compiler reads for these artifacts, in its order."""

    observations = []
    for path in paths:
        observations.extend(ingest_stig_artifact(path, ingested_at=datetime.now(UTC)).observations)
    return tuple(group_open_observations(observations))


def as_tuples(diagnostics: Sequence[ReportDiagnostic]) -> list[tuple[str, str, str, str | None]]:
    return [(item.level.value, item.code, item.message, item.location) for item in diagnostics]


def refusal(tracking_id: str, completed: str, detected: str, source: str, remedy: str) -> str:
    return (
        f"{tracking_id} was evaluated at {completed}, before its detection time {detected} "
        f"(source {source}); {remedy}"
    )


#: When every writer below records, and the as-of every report from a store compiles at.
WRITTEN_AT = datetime(2026, 8, 21, 12, 0, tzinfo=UTC)
WRITTEN_AT_TEXT = "2026-08-21T12:00:00Z"
RATIONALE = "The synthetic results declare no source timestamp."
#: A well-formed tracking id no synthetic artifact produces, for the stale-case path.
ORPHAN_CASE = "case-00000000000000ff"


def rendered(diagnostics: Sequence[ReportDiagnostic]) -> list[str]:
    return [item.render() for item in diagnostics]


def run(argv: Sequence[str]) -> tuple[int, str, str]:
    """Run one CLI invocation through `complyroll.cli.main` and capture its streams."""

    out = io.StringIO()
    err = io.StringIO()
    with redirect_stdout(out), redirect_stderr(err):
        code = main(list(argv))
    return code, out.getvalue(), err.getvalue()


def reread_with_timestamp(result: IngestResult, observed_at: datetime) -> IngestResult:
    """Return the reading a newer parser version makes of the same bytes, now timestamped.

    The same digest read again by a newer parser supersedes the older reading, so a case
    whose links are untimed comes to be timed by its current group (plan probe p4).
    """

    artifact = result.artifact
    if artifact is None:
        raise AssertionError("only a reading that named its artifact can be re-read")
    observations = []
    for observation in result.observations:
        changed = replace(observation, parser_version="999", observed_at=observed_at)
        observations.append(replace(changed, observation_id=changed.derived_observation_id))
    return replace(
        result,
        artifact=replace(artifact, parser_version="999"),
        observations=tuple(observations),
    )


# *--- Tests ---*


class CompilerOrderTests(unittest.TestCase):
    def setUp(self) -> None:
        directory = tempfile.TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        self.directory = Path(directory.name)

    def artifact(
        self,
        name: str,
        results: Sequence[tuple[str, str | None]],
        *,
        rule: str = BANNER_RULE,
    ) -> tuple[Path, VulnerabilityGroup]:
        """Write one one-rule XCCDF file and return it with its sole group."""

        path = self.directory / f"{name}.xml"
        path.write_text(xccdf(name, results, rule), encoding="utf-8")
        (group,) = groups_of((path,))
        return path, group

    def evaluate(self, **overrides: object) -> EvaluationSet:
        """Return one evaluation of the banner rule, built on the default entry."""

        entry: dict[str, object] = {"match": {"sourceRecordId": BANNER_RULE, "sourceType": "xccdf"}}
        entry.update(overrides)
        return evaluations_for(entry)

    def test_a_timed_record_evaluated_before_its_source_timestamp_is_refused(self) -> None:
        path, group = self.artifact("timed", [("lab-timed", TIMED_AT)])

        with self.assertRaises(ReportCompileError) as caught:
            compile_fixtures(artifacts=(path,), evaluations=self.evaluate(), detected_at=None)

        self.assertEqual(
            as_tuples(caught.exception.diagnostics),
            [
                (
                    "error",
                    "evaluation_before_detection",
                    refusal(group.tracking_id, EARLY, TIMED_AT, "artifact", ARTIFACT_REMEDY),
                    BANNER_RULE,
                )
            ],
        )

    def test_an_attested_record_evaluated_before_the_attestation_is_refused(self) -> None:
        path, group = self.artifact("untimed", [("lab-untimed", None)])

        with self.assertRaises(ReportCompileError) as caught:
            compile_fixtures(
                artifacts=(path,), evaluations=self.evaluate(), detected_at=LATE_ATTESTATION
            )

        self.assertEqual(
            as_tuples(caught.exception.diagnostics),
            [
                (
                    "error",
                    "evaluation_before_detection",
                    refusal(
                        group.tracking_id,
                        EARLY,
                        "2026-08-05T00:00:00Z",
                        "attestation",
                        ATTESTATION_REMEDY,
                    ),
                    BANNER_RULE,
                )
            ],
        )

    def test_an_earlier_attestation_cures_the_refusal(self) -> None:
        path, _ = self.artifact("untimed", [("lab-untimed", None)])
        evaluations = self.evaluate()
        with self.assertRaises(ReportCompileError):
            compile_fixtures(
                artifacts=(path,), evaluations=evaluations, detected_at=LATE_ATTESTATION
            )

        report = compile_fixtures(
            artifacts=(path,), evaluations=evaluations, detected_at=EARLY_ATTESTATION
        )

        (vulnerability,) = report.document["vulnerabilities"]
        self.assertEqual(vulnerability["detection"]["detectedAt"], "2026-08-01T00:00:00Z")
        self.assertEqual(vulnerability["evaluationCompletedAt"], EARLY)
        self.assertEqual(vulnerability["x-complyroll"]["detectedAtSource"], "attestation")
        self.assertNotIn("evaluation_before_detection", [item.code for item in report.diagnostics])

    def test_an_evaluation_at_the_detection_instant_is_in_order(self) -> None:
        timed, _ = self.artifact("timed", [("lab-timed", TIMED_AT)])
        untimed, _ = self.artifact("untimed", [("lab-untimed", None)])
        for name, path, detected_at, source in (
            ("artifact", timed, None, "artifact"),
            ("attestation", untimed, datetime(2026, 8, 10, 9, 0, tzinfo=UTC), "attestation"),
        ):
            with self.subTest(source=name):
                report = compile_fixtures(
                    artifacts=(path,),
                    evaluations=self.evaluate(completedAt=TIMED_AT),
                    detected_at=detected_at,
                )

                (vulnerability,) = report.document["vulnerabilities"]
                self.assertEqual(vulnerability["detection"]["detectedAt"], TIMED_AT)
                self.assertEqual(vulnerability["evaluationCompletedAt"], TIMED_AT)
                self.assertEqual(vulnerability["x-complyroll"]["detectedAtSource"], source)
                self.assertEqual(
                    [item.code for item in report.diagnostics if "evaluation_before" in item.code],
                    [],
                )

    def test_a_partly_timestamped_record_warns_with_both_instants(self) -> None:
        # The attestation is supplied and still does not govern a partial group, so the
        # earliest known timestamp is the detection time and the record is published.
        path, group = self.artifact("partial", [("lab-timed", TIMED_AT), ("lab-untimed", None)])

        report = compile_fixtures(
            artifacts=(path,), evaluations=self.evaluate(), detected_at=EARLY_ATTESTATION
        )

        (vulnerability,) = report.document["vulnerabilities"]
        self.assertEqual(vulnerability["detection"]["detectedAt"], TIMED_AT)
        self.assertEqual(vulnerability["evaluationCompletedAt"], EARLY)
        self.assertEqual(vulnerability["x-complyroll"]["detectedAtSource"], "artifact-partial")
        self.assertEqual(
            [item for item in as_tuples(report.diagnostics) if item[3] == BANNER_RULE],
            [
                (
                    "warning",
                    "detection_time_partial",
                    f"{group.tracking_id} groups 1 observation(s) that declare no source "
                    "timestamp; the earliest known timestamp is the detection time",
                    BANNER_RULE,
                ),
                (
                    "warning",
                    "evaluation_before_partial_detection",
                    f"{group.tracking_id} was evaluated at {EARLY}, before its earliest known "
                    f"detection time {TIMED_AT} (source artifact-partial); an observation that "
                    "declares no source timestamp may have detected it earlier, so the record "
                    "is published",
                    BANNER_RULE,
                ),
            ],
        )
        self.assertNotIn("evaluation_before_detection", [item.code for item in report.diagnostics])

    def test_a_pain_reduction_before_detection_is_not_ordered(self) -> None:
        # Only completedAt is ordered: a reduction and a projection dated before the
        # detection time start no clock and are published as written.
        path, _ = self.artifact("timed", [("lab-timed", TIMED_AT)])

        report = compile_fixtures(
            artifacts=(path,),
            evaluations=self.evaluate(
                completedAt="2026-08-11T12:00:00Z",
                painReductionEvents=[{"reducedAt": "2026-08-05T16:00:00Z", "rating": 4}],
                projectedNextReduction={"estimatedAt": "2026-08-06T16:00:00Z", "targetRating": 3},
            ),
            detected_at=None,
        )

        (vulnerability,) = report.document["vulnerabilities"]
        self.assertEqual(vulnerability["detection"]["detectedAt"], TIMED_AT)
        self.assertEqual(
            vulnerability["painReductionEvents"],
            [{"reducedAt": "2026-08-05T16:00:00Z", "rating": 4}],
        )
        self.assertEqual(
            vulnerability["projectedNextReduction"],
            {"estimatedAt": "2026-08-06T16:00:00Z", "targetRating": 3},
        )
        self.assertEqual(
            [item.code for item in report.diagnostics if "evaluation_before" in item.code], []
        )

    def test_every_refusal_in_the_run_is_named_together(self) -> None:
        # A missing detection time, a record refused twice (evaluated before detection and
        # closed with no disposition) and a record refused once all reach one raise. The
        # parser refuses `closed` without closedDisposition, so the entries are rewritten.
        missing, untimed = self.artifact("missing", [("lab-untimed", None)], rule=SSHD_RULE)
        both_path, both = self.artifact("both", [("lab-timed", TIMED_AT)])
        closed_path, closed = self.artifact("closed", [("lab-other", TIMED_AT)])
        parsed = evaluations_for(
            {
                "match": {
                    "sourceRecordId": BANNER_RULE,
                    "sourceType": "xccdf",
                    "contextKey": both.context_key,
                },
                "completedAt": EARLY,
            },
            {
                "match": {
                    "sourceRecordId": BANNER_RULE,
                    "sourceType": "xccdf",
                    "contextKey": closed.context_key,
                },
                "completedAt": "2026-08-11T12:00:00Z",
            },
        )
        evaluations = EvaluationSet(
            entries=tuple(
                replace(entry, disposition=CaseStatus.CLOSED, closed_disposition=None)
                for entry in parsed
            )
        )
        paths = [closed_path, missing, both_path]

        with self.assertRaises(ReportCompileError) as caught:
            compile_record_set_from_artifacts(
                paths, options=options(detected_at=None), evaluations=evaluations
            )

        def closed_error(tracking_id: str, index: int) -> tuple[str, str, str, str | None]:
            return (
                "error",
                "closed_without_disposition",
                f"{tracking_id} is closed with no recorded disposition; supply closedDisposition",
                f"evaluations[{index}]",
            )

        per_record = {
            both.tracking_id: [
                (
                    "error",
                    "evaluation_before_detection",
                    refusal(both.tracking_id, EARLY, TIMED_AT, "artifact", ARTIFACT_REMEDY),
                    BANNER_RULE,
                ),
                closed_error(both.tracking_id, 0),
            ],
            closed.tracking_id: [closed_error(closed.tracking_id, 1)],
        }
        group_order = [group.tracking_id for group in groups_of(paths)]
        self.assertEqual(len(group_order), 3)
        self.assertEqual(
            as_tuples(caught.exception.diagnostics),
            [
                (
                    "error",
                    "detection_time_missing",
                    f"no source timestamp and no --detected-at attestation for: "
                    f"{untimed.tracking_id}",
                    None,
                ),
                *(
                    error
                    for tracking_id in group_order
                    for error in per_record.get(tracking_id, [])
                ),
            ],
        )


class HistoryOrderFixture(unittest.TestCase):
    """A temporary store driven through the writers, exactly as the commands call them."""

    def setUp(self) -> None:
        directory = tempfile.TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        self.directory = Path(directory.name)
        self.metadata = EventMetadata(actor="tester")
        self.open_store("history.db")

    def open_store(self, name: str) -> None:
        """Point this test at a new, empty store."""

        store = SQLiteEventStore(self.directory / name)
        self.addCleanup(store.close)
        self.repository = EventRepository(store)

    @property
    def sequence(self) -> int:
        return self.repository.store.latest_sequence

    def artifact(
        self,
        name: str,
        results: Sequence[tuple[str, str | None]],
        *,
        rule: str = BANNER_RULE,
        benchmark: str | None = None,
    ) -> Path:
        path = self.directory / f"{name}.xml"
        path.write_text(xccdf(benchmark or name, results, rule), encoding="utf-8")
        return path

    def ingest(self, *paths: Path) -> None:
        for path in paths:
            record_ingest(
                self.repository,
                ingest_stig_artifact(path, ingested_at=WRITTEN_AT),
                metadata=self.metadata,
                ingested_at=WRITTEN_AT,
            )

    def correlate(self) -> None:
        correlate_cases(self.repository, metadata=self.metadata, now=WRITTEN_AT)

    def only_case(self) -> str:
        (case,) = fold_all_cases(self.repository)
        return case.tracking_id

    def attest(self, tracking_ids: Sequence[str], detected_at: datetime) -> AttestationOutcome:
        return attest_detection(
            self.repository,
            tracking_ids,
            detected_at=detected_at,
            rationale=RATIONALE,
            metadata=self.metadata,
            now=WRITTEN_AT,
        )

    def evaluate(self, evaluations: EvaluationSet) -> EvaluationOutcome:
        return apply_evaluations(
            self.repository, evaluations, metadata=self.metadata, now=WRITTEN_AT
        )

    def refused(self, write: Callable[[], object]) -> EvaluationOrderError:
        """Require a write to be refused with nothing appended, alone and in a transaction.

        Inside a caller's open transaction the writer's own scope is a no-op, so a write
        that appended before refusing would commit with the caller's block. The refusal is
        caught inside the block, the block commits, and still nothing is in the log.
        """

        before = self.sequence
        with self.assertRaises(EvaluationOrderError) as caught:
            write()
        self.assertEqual(self.sequence, before)
        with self.repository.transaction(), self.assertRaises(EvaluationOrderError):
            write()
        self.assertEqual(self.sequence, before)
        return caught.exception

    def append_around(self, tracking_id: str, event_type: str, payload: Mapping[str, Any]) -> None:
        """Write one case event directly, around the writers' checks."""

        stream_id = case_stream_id(tracking_id)
        self.repository.append(
            stream_id,
            event_type,
            payload,
            occurred_at=WRITTEN_AT,
            metadata=self.metadata,
            expected_version=len(self.repository.read_stream(stream_id)),
        )

    def evaluate_around(self, evaluations: EvaluationSet, *tracking_ids: str) -> None:
        for tracking_id, entry in zip(tracking_ids, evaluations.entries, strict=True):
            self.append_around(
                tracking_id, CASE_EVALUATED, history_writers._evaluation_payload(entry)
            )

    def report(self) -> CompiledRecordSet:
        return compile_record_set_from_history(self.repository, options=options(detected_at=None))

    def report_refusal(self) -> list[str]:
        """Return the lines a report from this store refuses with."""

        with self.assertRaises(ReportCompileError) as caught:
            self.report()
        return rendered(caught.exception.diagnostics)

    def banner_evaluation(self, **overrides: object) -> EvaluationSet:
        entry: dict[str, object] = {"match": {"sourceRecordId": BANNER_RULE, "sourceType": "xccdf"}}
        entry.update(overrides)
        return evaluations_for(entry)


class WriterOrderTests(HistoryOrderFixture):
    def test_evaluate_refuses_an_entry_before_an_attested_detection(self) -> None:
        self.ingest(self.artifact("untimed", [("lab-untimed", None)]))
        self.correlate()
        case = self.only_case()
        self.attest([case], LATE_ATTESTATION)
        evaluations = self.banner_evaluation()

        refused = self.refused(lambda: self.evaluate(evaluations))

        self.assertEqual(
            as_tuples(refused.diagnostics),
            [
                (
                    "error",
                    "evaluation_before_detection",
                    refusal(case, EARLY, "2026-08-05T00:00:00Z", "attestation", ATTESTATION_REMEDY),
                    BANNER_RULE,
                )
            ],
        )
        # Written around the writer, the same evaluation makes the report refuse this
        # store with the writer's line, and re-applying the file is an unchanged entry
        # that is still checked and still refused.
        self.evaluate_around(evaluations, case)
        self.assertEqual(self.report_refusal(), rendered(refused.diagnostics))
        again = self.refused(lambda: self.evaluate(evaluations))
        self.assertEqual(rendered(again.diagnostics), rendered(refused.diagnostics))

    def test_evaluate_refuses_an_entry_before_a_timed_artifact(self) -> None:
        # Two records refused together: both are named, in the report's group order.
        banner = self.artifact("banner", [("lab-timed", TIMED_AT)])
        sshd = self.artifact("sshd", [("lab-timed", TIMED_AT)], rule=SSHD_RULE)
        self.ingest(banner, sshd)
        self.correlate()
        evaluations = evaluations_for(
            {"match": {"sourceRecordId": BANNER_RULE, "sourceType": "xccdf"}},
            {"match": {"sourceRecordId": SSHD_RULE, "sourceType": "xccdf"}},
        )
        groups = groups_of((banner, sshd))
        self.assertEqual(len(groups), 2)

        refused = self.refused(lambda: self.evaluate(evaluations))

        self.assertEqual(
            as_tuples(refused.diagnostics),
            [
                (
                    "error",
                    "evaluation_before_detection",
                    refusal(group.tracking_id, EARLY, TIMED_AT, "artifact", ARTIFACT_REMEDY),
                    group.source_record_id,
                )
                for group in groups
            ],
        )
        by_rule = {group.source_record_id: group.tracking_id for group in groups}
        self.evaluate_around(evaluations, by_rule[BANNER_RULE], by_rule[SSHD_RULE])
        self.assertEqual(self.report_refusal(), rendered(refused.diagnostics))

    def test_evaluate_applies_a_partial_group_with_the_report_warning(self) -> None:
        self.ingest(self.artifact("partial", [("lab-timed", TIMED_AT), ("lab-untimed", None)]))
        self.correlate()
        case = self.only_case()

        outcome = self.evaluate(self.banner_evaluation())

        self.assertEqual(outcome.evaluations_appended, 1)
        self.assertEqual(
            outcome.warnings,
            (
                f"evaluation_before_partial_detection: {case} was evaluated at {EARLY}, before "
                f"its earliest known detection time {TIMED_AT} (source artifact-partial); an "
                "observation that declares no source timestamp may have detected it earlier, "
                f"so the record is published [{BANNER_RULE}]",
            ),
        )
        (warning,) = [
            item
            for item in self.report().diagnostics
            if item.code == "evaluation_before_partial_detection"
        ]
        self.assertEqual(f"warning: {outcome.warnings[0]}", warning.render())

    def test_evaluate_reads_the_current_group_and_not_the_links(self) -> None:
        # The case is linked to the untimed result and attested at 08-01. A timed result
        # of the same rule and benchmark joins its group, and no `cases correlate` has
        # linked it, so the links still say "attestation, 08-01, in order" while the
        # report reads a partly timestamped group detected at 08-10.
        untimed = self.artifact("untimed", [("lab-untimed", None)], benchmark="shared")
        timed = self.artifact("timed", [("lab-timed", TIMED_AT)], benchmark="shared")
        self.assertEqual(len(groups_of((untimed, timed))), 1)
        self.ingest(untimed)
        self.correlate()
        case = self.only_case()
        self.attest([case], EARLY_ATTESTATION)
        self.ingest(timed)

        outcome = self.evaluate(self.banner_evaluation())

        self.assertEqual(outcome.evaluations_appended, 1)
        self.assertEqual(
            [item.split(":", 1)[0] for item in outcome.warnings],
            ["evaluation_before_partial_detection"],
        )
        self.assertIn(f"detection time {TIMED_AT} (source artifact-partial)", outcome.warnings[0])

        # A case no open group matches is in no report, so neither writer orders it, even
        # with an attestation after its evaluation.
        self.append_around(
            ORPHAN_CASE,
            CASE_CREATED,
            {
                "trackingId": ORPHAN_CASE,
                "sourceType": "ckl",
                "sourceRecordId": "V-000001",
                "contextKey": "Retired Windows STIG",
                "title": "A weakness whose artifact was never ingested again",
                "description": "Recorded from an artifact that is no longer supplied.",
                "createdAt": iso_utc(WRITTEN_AT),
            },
        )
        self.assertEqual(self.attest([ORPHAN_CASE], LATE_ATTESTATION).attested, (ORPHAN_CASE,))
        orphan = evaluations_for({"match": {"sourceRecordId": "V-000001", "sourceType": "ckl"}})
        self.assertEqual(self.evaluate(orphan).evaluations_appended, 1)
        later = datetime(2026, 8, 6, tzinfo=UTC)
        self.assertEqual(self.attest([ORPHAN_CASE], later).attested, (ORPHAN_CASE,))
        self.assertIn(
            ("info", "stale_case", f"case/{ORPHAN_CASE}"),
            [(item.level.value, item.code, item.location) for item in self.report().diagnostics],
        )

    def test_attest_refuses_an_instant_after_the_current_evaluation(self) -> None:
        self.ingest(self.artifact("untimed", [("lab-untimed", None)]))
        self.correlate()
        case = self.only_case()
        self.attest([case], EARLY_ATTESTATION)
        self.evaluate(self.banner_evaluation())

        refused = self.refused(lambda: self.attest([case], LATE_ATTESTATION))

        self.assertEqual(
            as_tuples(refused.diagnostics),
            [
                (
                    "error",
                    "evaluation_before_detection",
                    refusal(case, EARLY, "2026-08-05T00:00:00Z", "attestation", ATTESTATION_REMEDY),
                    BANNER_RULE,
                )
            ],
        )
        self.append_around(
            case,
            DETECTION_ATTESTED,
            {
                "detectedAt": iso_utc(LATE_ATTESTATION),
                "rationale": RATIONALE,
                "attestedAt": iso_utc(WRITTEN_AT),
            },
        )
        self.assertEqual(self.report_refusal(), rendered(refused.diagnostics))

        with self.subTest("a group its own timestamp times is not the attestation's to refuse"):
            # The same bytes re-read by a newer parser now declare 08-10, so the current
            # group is timed while the case's only link is not. The report refuses the
            # store on the artifact source; attesting adds nothing that reaches it.
            self.open_store("reread.db")
            untimed = self.artifact("untimed", [("lab-untimed", None)])
            self.ingest(untimed)
            self.correlate()
            case = self.only_case()
            self.attest([case], EARLY_ATTESTATION)
            self.evaluate(self.banner_evaluation())
            record_ingest(
                self.repository,
                reread_with_timestamp(
                    ingest_stig_artifact(untimed, ingested_at=WRITTEN_AT),
                    datetime(2026, 8, 10, 9, 0, tzinfo=UTC),
                ),
                metadata=self.metadata,
                ingested_at=WRITTEN_AT,
            )
            self.assertEqual(
                self.report_refusal(),
                [
                    "error: evaluation_before_detection: "
                    + refusal(case, EARLY, TIMED_AT, "artifact", ARTIFACT_REMEDY)
                    + f" [{BANNER_RULE}]"
                ],
            )

            outcome = self.attest([case], LATE_ATTESTATION)

            self.assertEqual(outcome.attested, (case,))

    def test_an_attestation_with_no_evaluation_is_not_ordered(self) -> None:
        self.ingest(self.artifact("untimed", [("lab-untimed", None)]))
        self.correlate()
        case = self.only_case()
        before = self.sequence

        outcome = self.attest([case], LATE_ATTESTATION)

        self.assertEqual(outcome.attested, (case,))
        self.assertEqual(self.sequence, before + 1)
        self.assertEqual(self.report().records[0].tracking_id, case)


class CommandOrderTests(unittest.TestCase):
    def setUp(self) -> None:
        directory = tempfile.TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        self.directory = Path(directory.name)
        self.database = self.directory / "history.db"

    def succeeds(self, argv: Sequence[str]) -> str:
        code, out, err = run(argv)
        self.assertEqual(code, 0, msg=f"{list(argv)} exited {code}: {err}")
        return out

    def verify(self) -> str:
        return self.succeeds(["store", "verify", "--db", str(self.database)])

    def test_an_all_missing_sweep_names_every_blocking_case_and_appends_nothing(self) -> None:
        banner = self.directory / "banner.xml"
        banner.write_text(xccdf("banner", [("lab-untimed", None)], BANNER_RULE), encoding="utf-8")
        sshd = self.directory / "sshd.xml"
        sshd.write_text(xccdf("sshd", [("lab-untimed", None)], SSHD_RULE), encoding="utf-8")
        groups = groups_of((banner, sshd))
        self.assertEqual(len(groups), 2)
        database = ["--db", str(self.database)]
        actor = ["--actor", "tester"]
        self.succeeds(
            ["ingest", str(banner), str(sshd), *database, "--as-of", WRITTEN_AT_TEXT, *actor]
        )
        self.succeeds(["cases", "correlate", *database, *actor])
        evaluations = self.directory / "evaluations.json"
        evaluations.write_text(
            json.dumps(
                {
                    "evaluations": [
                        json.loads(
                            evaluation_json(match={"sourceRecordId": rule, "sourceType": "xccdf"})
                        )["evaluations"][0]
                        for rule in (BANNER_RULE, SSHD_RULE)
                    ]
                }
            ),
            encoding="utf-8",
        )
        # Neither case has a detection time yet, so evaluating them orders nothing.
        evaluated = self.succeeds(
            ["cases", "evaluate", *database, "--evaluations", str(evaluations), *actor]
        )
        self.assertIn("evaluations: 2 appended, 0 skipped", evaluated)
        verified = self.verify()

        code, out, err = run(
            [
                "cases",
                "attest-detection",
                *database,
                "--all-missing",
                "--detected-at",
                "2026-08-10T00:00:00Z",
                "--rationale",
                RATIONALE,
                *actor,
            ]
        )

        expected = "".join(
            "error: evaluation_before_detection: "
            + refusal(
                group.tracking_id,
                EARLY,
                "2026-08-10T00:00:00Z",
                "attestation",
                ATTESTATION_REMEDY,
            )
            + f" [{group.source_record_id}]\n"
            for group in groups
        )
        self.assertEqual((code, out, err), (1, "", expected))
        self.assertEqual(self.verify(), verified)

        # The report prints the same two lines once the attestations are written around
        # the command.
        store = SQLiteEventStore(self.database)
        try:
            repository = EventRepository(store)
            for group in groups:
                stream_id = case_stream_id(group.tracking_id)
                repository.append(
                    stream_id,
                    DETECTION_ATTESTED,
                    {
                        "detectedAt": "2026-08-10T00:00:00Z",
                        "rationale": RATIONALE,
                        "attestedAt": WRITTEN_AT_TEXT,
                    },
                    occurred_at=WRITTEN_AT,
                    metadata=EventMetadata(actor="tester"),
                    expected_version=len(repository.read_stream(stream_id)),
                )
        finally:
            store.close()
        report = run(
            [
                "report",
                "vdt",
                *database,
                "--class",
                "C",
                "--package-uri",
                "https://example.test/cpo",
                "--from",
                "2026-08-01T00:00:00Z",
                "--to",
                "2026-08-31T23:59:59Z",
                "--as-of",
                WRITTEN_AT_TEXT,
            ]
        )
        self.assertEqual(report, (1, "", expected))


if __name__ == "__main__":
    unittest.main()
