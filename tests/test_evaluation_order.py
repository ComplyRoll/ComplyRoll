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
2026-10-14). `store verify` names an inversion written around the writers as the audit
fault `evaluation_before_detection`, with the same message.
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
from unittest import mock

from test_reports import (
    FAILED_EVALUATIONS,
    FIXTURES,
    TRUNCATED_CASE,
    TRUNCATED_SHA256,
    compile_fixtures,
    evaluation_json,
    evaluations_for,
    options,
    system_match,
)

from complyroll.adapters import IngestResult, ingest_stig_artifact
from complyroll.cli import main
from complyroll.correlation import VulnerabilityGroup, group_open_observations
from complyroll.events import EventMetadata, EventRepository, case_stream_id, iso_utc
from complyroll.history import (
    ARTIFACT_INGESTED,
    AUDIT_FAULT_CODES,
    CASE_CREATED,
    CASE_EVALUATED,
    CASE_OBSERVATION_LINKED,
    DETECTION_ATTESTED,
    AttestationOutcome,
    EvaluationMatchError,
    EvaluationOrderError,
    EvaluationOutcome,
    HistoryFault,
    apply_evaluations,
    attest_detection,
    audit_history,
    correlate_cases,
    fold_all_cases,
    record_ingest,
)
from complyroll.history import order as history_order
from complyroll.history import writers as history_writers
from complyroll.history.order import case_order_diagnostic, current_groups
from complyroll.models import CaseStatus
from complyroll.reports import (
    EvaluationSet,
    ReportCompileError,
    ReportDiagnostic,
    compile_record_set_from_artifacts,
    parse_evaluations,
)
from complyroll.reports.replay import compile_record_set_from_history
from complyroll.reports.vdt import CompiledRecordSet
from complyroll.store import NewEvent, SQLiteEventStore

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
#: Another, for a case created with a metadata envelope `store verify` faults.
SPARE_CASE = "case-00000000000000fe"
#: A third, for a case stream that is contract-valid but does not fold.
UNFOLDED_CASE = "case-00000000000000fd"
#: The instant a failure is recorded at in `CommandOrderTests`, and an evaluation before it.
FAILURE_RECORDED_AT = "2026-08-21T12:00:00Z"
FAILURE_EVALUATED_AT = "2026-08-20T12:00:00Z"
#: An evaluation of that failure a day after it is recorded, which is in order.
FAILURE_LATER_EVALUATED_AT = "2026-08-22T12:00:00Z"


def rendered(diagnostics: Sequence[ReportDiagnostic]) -> list[str]:
    return [item.render() for item in diagnostics]


def run(argv: Sequence[str]) -> tuple[int, str, str]:
    """Run one CLI invocation through `complyroll.cli.main` and capture its streams."""

    out = io.StringIO()
    err = io.StringIO()
    with redirect_stdout(out), redirect_stderr(err):
        code = main(list(argv))
    return code, out.getvalue(), err.getvalue()


def orphan_created(tracking_id: str) -> dict[str, Any]:
    """Return a `case.created` payload for a case no synthetic artifact groups into."""

    return {
        "trackingId": tracking_id,
        "sourceType": "ckl",
        "sourceRecordId": "V-000001",
        "contextKey": "Retired Windows STIG",
        "title": "A weakness whose artifact was never ingested again",
        "description": "Recorded from an artifact that is no longer supplied.",
        "createdAt": iso_utc(WRITTEN_AT),
    }


def report_vdt(database: Path) -> tuple[int, str, str]:
    """Run `report vdt --db` on a store at the as-of every store here is written at."""

    return run(
        [
            "report",
            "vdt",
            "--db",
            str(database),
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


def verify_store(database: Path) -> tuple[int, str, str]:
    return run(["store", "verify", "--db", str(database)])


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

    def test_a_system_record_evaluated_after_its_detection_is_published(self) -> None:
        # A detection process failure is detected at the run's as-of on the stateless path,
        # so an evaluation completed a day later is in order, not only one at that instant.
        evaluations = evaluations_for(
            {"match": system_match(TRUNCATED_SHA256), "completedAt": FAILURE_LATER_EVALUATED_AT}
        )

        report = compile_fixtures(
            artifacts=(FIXTURES / "failed-truncated.sarif",),
            evaluations=evaluations,
            record_failed_imports=True,
        )

        (vulnerability,) = report.document["vulnerabilities"]
        self.assertEqual(vulnerability["providerTrackingId"], TRUNCATED_CASE)
        self.assertEqual(vulnerability["detection"]["detectedAt"], FAILURE_RECORDED_AT)
        self.assertEqual(vulnerability["evaluationCompletedAt"], FAILURE_LATER_EVALUATED_AT)
        self.assertEqual(vulnerability["x-complyroll"]["detectedAtSource"], "system")
        self.assertEqual(
            [item.code for item in report.diagnostics if "evaluation_before" in item.code], []
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

        self.database = self.directory / name
        store = SQLiteEventStore(self.database)
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

    def test_evaluate_names_the_ordering_errors_of_a_file_that_also_collides(self) -> None:
        # Two entries evaluated before detection also claim one trackingId override. The
        # compiler checks tracking ids only on a record set with no error, so the report
        # names both ordering errors; `cases evaluate` prints those lines, not the collision.
        banner = self.artifact("banner", [("lab-timed", TIMED_AT)])
        sshd = self.artifact("sshd", [("lab-timed", TIMED_AT)], rule=SSHD_RULE)
        self.ingest(banner, sshd)
        self.correlate()

        def file_of(completed_at: str) -> str:
            entries = [
                json.loads(
                    evaluation_json(
                        match={"sourceRecordId": rule, "sourceType": "xccdf"},
                        completedAt=completed_at,
                        trackingId="PROVIDER-SHARED-1",
                    )
                )["evaluations"][0]
                for rule in (BANNER_RULE, SSHD_RULE)
            ]
            return json.dumps({"evaluations": entries})

        content = file_of(EARLY)
        evaluations = parse_evaluations(content.encode("utf-8"))
        with self.assertRaises(ReportCompileError) as compiled:
            compile_record_set_from_artifacts(
                [banner, sshd], options=options(detected_at=None), evaluations=evaluations
            )
        self.assertEqual(
            [item.code for item in compiled.exception.diagnostics],
            ["evaluation_before_detection"] * 2,
        )
        lines = rendered(compiled.exception.diagnostics)
        # The same file dated after detection is refused for the collision alone.
        later = parse_evaluations(file_of("2026-08-11T12:00:00Z").encode("utf-8"))
        with self.assertRaises(EvaluationMatchError) as collided:
            self.evaluate(later)
        self.assertIn("'PROVIDER-SHARED-1' is claimed by", str(collided.exception))

        refused = self.refused(lambda: self.evaluate(evaluations))

        self.assertEqual(rendered(refused.diagnostics), lines)
        path = self.directory / "evaluations.json"
        path.write_text(content, encoding="utf-8")
        before = self.sequence
        printed = run(
            [
                "cases",
                "evaluate",
                "--db",
                str(self.database),
                "--evaluations",
                str(path),
                "--actor",
                "tester",
            ]
        )
        self.assertEqual(printed, (1, "", "".join(f"{line}\n" for line in lines)))
        self.assertEqual(self.sequence, before)

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

    def test_attest_orders_against_the_current_evaluation_and_not_the_first(self) -> None:
        # The untimed case is evaluated at 08-04 and again at 08-10 before any detection
        # time is known. The report reads the 08-10 evaluation, so an attestation at 08-07
        # is in order, and one at 08-11 is refused against 08-10, not 08-04.
        reevaluated = "2026-08-10T12:00:00Z"
        self.ingest(self.artifact("untimed", [("lab-untimed", None)]))
        self.correlate()
        case = self.only_case()
        self.evaluate(self.banner_evaluation())
        again = self.evaluate(self.banner_evaluation(completedAt=reevaluated))
        self.assertEqual(again.evaluations_appended, 1)

        between = self.attest([case], datetime(2026, 8, 7, tzinfo=UTC))

        self.assertEqual(between.attested, (case,))
        self.assertEqual([record.tracking_id for record in self.report().records], [case])

        after = datetime(2026, 8, 11, tzinfo=UTC)
        refused = self.refused(lambda: self.attest([case], after))

        self.assertEqual(
            as_tuples(refused.diagnostics),
            [
                (
                    "error",
                    "evaluation_before_detection",
                    refusal(
                        case, reevaluated, "2026-08-11T00:00:00Z", "attestation", ATTESTATION_REMEDY
                    ),
                    BANNER_RULE,
                )
            ],
        )
        self.append_around(
            case,
            DETECTION_ATTESTED,
            {
                "detectedAt": iso_utc(after),
                "rationale": RATIONALE,
                "attestedAt": iso_utc(WRITTEN_AT),
            },
        )
        self.assertEqual(self.report_refusal(), rendered(refused.diagnostics))

    def test_an_attestation_with_no_evaluation_is_not_ordered(self) -> None:
        self.ingest(self.artifact("untimed", [("lab-untimed", None)]))
        self.correlate()
        case = self.only_case()
        before = self.sequence

        outcome = self.attest([case], LATE_ATTESTATION)

        self.assertEqual(outcome.attested, (case,))
        self.assertEqual(self.sequence, before + 1)
        self.assertEqual(self.report().records[0].tracking_id, case)

    def test_a_store_with_nothing_to_order_rehydrates_no_observation(self) -> None:
        # An attestation sweep over unevaluated cases, an evaluations file with no entry,
        # and an audit of a store with no evaluation read no artifact stream. The last
        # write proves the patched rehydration is the one every order check reaches.
        self.ingest(
            self.artifact("banner", [("lab-untimed", None)]),
            self.artifact("sshd", [("lab-untimed", None)], rule=SSHD_RULE),
        )
        self.correlate()
        cases = tuple(case.tracking_id for case in fold_all_cases(self.repository))
        nothing = parse_evaluations(b'{"evaluations": []}')

        with mock.patch.object(
            history_order,
            "rehydrate_observations",
            side_effect=AssertionError("rehydrate_observations"),
        ) as rehydrated:
            self.assertEqual(audit_history(self.repository), ())
            self.assertEqual(self.attest(cases, LATE_ATTESTATION).attested, cases)
            self.assertEqual(self.evaluate(nothing).evaluations_appended, 0)
            self.assertEqual(audit_history(self.repository), ())
            rehydrated.assert_not_called()
            with self.assertRaisesRegex(AssertionError, "rehydrate_observations"):
                self.evaluate(self.banner_evaluation())

        self.assertEqual(rehydrated.call_count, 1)

    def test_verify_and_the_report_name_an_inversion_written_around_the_writers(self) -> None:
        # Plan probe p2: attestations after two cases' evaluations, appended directly. The
        # case whose tracking id sorts second is evaluated first, and twice, so the faults
        # are ordered by sequence (not by case) and sit at the current evaluation, not the
        # case's creation or its first evaluation (08-06, which is still in order).
        banner = self.artifact("banner", [("lab-untimed", None)])
        sshd = self.artifact("sshd", [("lab-untimed", None)], rule=SSHD_RULE)
        rule_of = {group.tracking_id: group.source_record_id for group in groups_of((banner, sshd))}
        self.ingest(banner, sshd)
        self.correlate()
        first, second = sorted(rule_of)
        self.attest([first, second], EARLY_ATTESTATION)
        self.evaluate(
            evaluations_for(
                {
                    "match": {"sourceRecordId": rule_of[second], "sourceType": "xccdf"},
                    "completedAt": "2026-08-06T00:00:00Z",
                }
            )
        )
        one = {
            case: {"match": {"sourceRecordId": rule_of[case], "sourceType": "xccdf"}}
            for case in (first, second)
        }
        for case in (second, first):
            self.assertEqual(self.evaluate(evaluations_for(one[case])).evaluations_appended, 1)
        both = evaluations_for(one[first], one[second])
        # A stale case evaluated before its attestation is in no report and is no fault.
        self.append_around(ORPHAN_CASE, CASE_CREATED, orphan_created(ORPHAN_CASE))
        orphan = evaluations_for({"match": {"sourceRecordId": "V-000001", "sourceType": "ckl"}})
        self.assertEqual(self.evaluate(orphan).evaluations_appended, 1)
        self.attest([ORPHAN_CASE], datetime(2026, 8, 6, tzinfo=UTC))
        self.assertEqual(audit_history(self.repository), ())
        clean = verify_store(self.database)
        self.assertEqual(clean[0], 0, msg=clean[2])

        for case in (first, second):
            self.append_around(
                case,
                DETECTION_ATTESTED,
                {
                    "detectedAt": iso_utc(LATE_ATTESTATION),
                    "rationale": RATIONALE,
                    "attestedAt": iso_utc(WRITTEN_AT),
                },
            )

        states = {state.tracking_id: state for state in fold_all_cases(self.repository)}
        at = {}
        for case in (first, second):
            current = states[case].current_evaluation
            assert current is not None
            at[case] = current.sequence
            self.assertNotIn(at[case], (states[case].created_sequence, states[case].last_sequence))
        self.assertNotEqual(at[second], states[second].evaluations[0].sequence)
        self.assertLess(at[second], at[first])
        message = {
            case: refusal(case, EARLY, "2026-08-05T00:00:00Z", "attestation", ATTESTATION_REMEDY)
            for case in (first, second)
        }
        faults = (
            HistoryFault(at[second], "evaluation_before_detection", message[second]),
            HistoryFault(at[first], "evaluation_before_detection", message[first]),
        )
        self.assertEqual(audit_history(self.repository), faults)
        self.assert_named_alike(faults, self.refused(lambda: self.evaluate(both)))

        with self.subTest("plan probe p4: the same bytes re-read with a timestamp"):
            self.open_store("reread.db")
            untimed = self.artifact("untimed", [("lab-untimed", None)])
            self.ingest(untimed)
            self.correlate()
            case = self.only_case()
            self.attest([case], EARLY_ATTESTATION)
            self.evaluate(self.banner_evaluation())
            self.assertEqual(audit_history(self.repository), ())
            record_ingest(
                self.repository,
                reread_with_timestamp(
                    ingest_stig_artifact(untimed, ingested_at=WRITTEN_AT),
                    datetime(2026, 8, 10, 9, 0, tzinfo=UTC),
                ),
                metadata=self.metadata,
                ingested_at=WRITTEN_AT,
            )
            (state,) = fold_all_cases(self.repository)
            assert state.current_evaluation is not None
            reread = (
                HistoryFault(
                    state.current_evaluation.sequence,
                    "evaluation_before_detection",
                    refusal(case, EARLY, TIMED_AT, "artifact", ARTIFACT_REMEDY),
                ),
            )
            self.assertEqual(audit_history(self.repository), reread)
            self.assert_named_alike(
                reread, self.refused(lambda: self.evaluate(self.banner_evaluation()))
            )

        with self.subTest("a partly timestamped group's WARNING is not a fault"):
            self.open_store("partial.db")
            self.ingest(self.artifact("partial", [("lab-timed", TIMED_AT), ("lab-untimed", None)]))
            self.correlate()
            self.assertEqual(len(self.evaluate(self.banner_evaluation()).warnings), 1)
            self.assertEqual(audit_history(self.repository), ())
            self.assertEqual(verify_store(self.database)[0], 0)

        def inverted(name: str) -> str:
            self.open_store(name)
            self.ingest(untimed)
            self.correlate()
            case = self.only_case()
            self.attest([case], EARLY_ATTESTATION)
            self.evaluate(self.banner_evaluation())
            self.append_around(
                case,
                DETECTION_ATTESTED,
                {
                    "detectedAt": iso_utc(LATE_ATTESTATION),
                    "rationale": RATIONALE,
                    "attestedAt": iso_utc(WRITTEN_AT),
                },
            )
            self.assertEqual(
                [fault.code for fault in audit_history(self.repository)],
                ["evaluation_before_detection"],
            )
            return case

        # Decision 6: a fault no reader refuses on any stream leaves the order check
        # running, so one tampered envelope does not hide an inversion for good.
        envelopes = {
            "an extra metadata key": {"planted": "x"},
            "a method outside the rules": {"method": "not-cli"},
        }
        for index, (label, envelope) in enumerate(envelopes.items()):
            with self.subTest(f"a content-neutral fault is reported with it: {label}"):
                inverted(f"metadata-{index}.db")
                self.repository.store.append(
                    case_stream_id(SPARE_CASE),
                    [
                        NewEvent(
                            event_type=CASE_CREATED,
                            occurred_at=WRITTEN_AT,
                            payload=orphan_created(SPARE_CASE),
                            metadata={**self.metadata.to_dict(), **envelope},
                        )
                    ],
                    expected_version=0,
                )

                damaged = audit_history(self.repository)

                self.assertEqual(
                    [fault.code for fault in damaged],
                    ["evaluation_before_detection", "event_metadata_invalid"],
                )
                code, out, err = verify_store(self.database)
                self.assertEqual((code, out), (1, ""))
                for fault in damaged:
                    self.assertIn(f"error: {fault.render()}\n", err)
                self.assertIn("faults: 2 domain fault(s) in", err)

        def planted_evaluation(case: str) -> int:
            """Append the banner evaluation with an extra metadata key, around the writers."""

            stream_id = case_stream_id(case)
            (entry,) = self.banner_evaluation().entries
            self.repository.store.append(
                stream_id,
                [
                    NewEvent(
                        event_type=CASE_EVALUATED,
                        occurred_at=WRITTEN_AT,
                        payload=history_writers._evaluation_payload(entry),
                        metadata={**self.metadata.to_dict(), "planted": "x"},
                    )
                ],
                expected_version=len(self.repository.read_stream(stream_id)),
            )
            return self.sequence

        # The tampered envelope can sit on the case's own evaluations too: on the inverted
        # current evaluation, where both faults share its sequence, or on an earlier one the
        # writer then superseded. Neither hides the inversion.
        completions = {"the current": EARLY, "an earlier": "2026-08-04T18:00:00Z"}
        for index, (label, completed) in enumerate(completions.items()):
            with self.subTest(f"an extra metadata key on {label} evaluation is reported with it"):
                self.open_store(f"evaluated-{index}.db")
                self.ingest(untimed)
                self.correlate()
                case = self.only_case()
                self.attest([case], EARLY_ATTESTATION)
                planted = planted_evaluation(case)
                if completed != EARLY:
                    later = self.banner_evaluation(completedAt=completed)
                    self.assertEqual(self.evaluate(later).evaluations_appended, 1)
                current = self.sequence
                self.append_around(
                    case,
                    DETECTION_ATTESTED,
                    {
                        "detectedAt": iso_utc(LATE_ATTESTATION),
                        "rationale": RATIONALE,
                        "attestedAt": iso_utc(WRITTEN_AT),
                    },
                )
                (state,) = fold_all_cases(self.repository)
                assert state.current_evaluation is not None
                self.assertEqual(state.current_evaluation.sequence, current)
                self.assertEqual(
                    {record.sequence: record for record in self.repository.read_all()}[
                        planted
                    ].event_type,
                    CASE_EVALUATED,
                )

                damaged = audit_history(self.repository)

                self.assertEqual(
                    [(fault.sequence, fault.code) for fault in damaged],
                    sorted(
                        [
                            (current, "evaluation_before_detection"),
                            (planted, "event_metadata_invalid"),
                        ]
                    ),
                )
                (order,) = [f for f in damaged if f.code == "evaluation_before_detection"]
                self.assertEqual(
                    order.message,
                    refusal(
                        case, completed, "2026-08-05T00:00:00Z", "attestation", ATTESTATION_REMEDY
                    ),
                )
                code, out, err = verify_store(self.database)
                self.assertEqual((code, out), (1, ""))
                for fault in damaged:
                    self.assertIn(f"error: {fault.render()}\n", err)
                self.assertIn("faults: 2 domain fault(s) in", err)

        with self.subTest("a misplaced event is reported alone"):
            case = inverted("misplaced.db")
            artifact = next(
                record.stream_id
                for record in self.repository.read_all()
                if record.event_type == ARTIFACT_INGESTED
            )
            link = next(
                record
                for record in self.repository.read_stream(case_stream_id(case))
                if record.event_type == CASE_OBSERVATION_LINKED
            )
            self.repository.store.append(
                artifact,
                [
                    NewEvent(
                        event_type=CASE_OBSERVATION_LINKED,
                        occurred_at=WRITTEN_AT,
                        payload=dict(link.payload),
                        metadata=self.metadata.to_dict(),
                    )
                ],
                expected_version=len(self.repository.read_stream(artifact)),
            )

            damaged = audit_history(self.repository)

            self.assertEqual([fault.code for fault in damaged], ["event_stream_mismatch"])
            code, out, err = verify_store(self.database)
            self.assertEqual((code, out), (1, ""))
            self.assertIn(f"error: {damaged[0].render()}\n", err)
            self.assertNotIn("evaluation_before_detection", err)

    def test_a_case_is_never_ordered_against_another_cases_group(self) -> None:
        # Every writer pairs a case with its own current group. Against another case's
        # group the resolver would read that record's detection time and miss this case's
        # attestation, so the helper refuses the pair instead of answering for it.
        banner = self.artifact("banner", [("lab-timed", TIMED_AT)])
        sshd = self.artifact("sshd", [("lab-timed", TIMED_AT)], rule=SSHD_RULE)
        self.ingest(banner, sshd)
        self.correlate()
        first, second = fold_all_cases(self.repository)
        groups = current_groups(self.repository)

        with self.assertRaises(ValueError) as caught:
            case_order_diagnostic(
                first,
                groups[second.tracking_id],
                completed_at=datetime(2026, 8, 4, 12, 0, tzinfo=UTC),
                attested_at=LATE_ATTESTATION,
            )

        self.assertEqual(
            str(caught.exception),
            f"case {first.tracking_id!r} is not the case of group {second.tracking_id!r}",
        )

    def assert_named_alike(
        self, faults: Sequence[HistoryFault], refused: EvaluationOrderError
    ) -> None:
        """Require the audit, the writer and the report to name each record in one message.

        `store verify` and `report vdt --db` run on the store through the command line,
        and the fault's code is one `AUDIT_FAULT_CODES` publishes as the command's contract.
        """

        lines = rendered(refused.diagnostics)
        self.assertLessEqual({fault.code for fault in faults}, set(AUDIT_FAULT_CODES))
        self.assertEqual(
            sorted(fault.message for fault in faults),
            sorted(item.message for item in refused.diagnostics),
        )
        self.assertEqual(self.report_refusal(), lines)
        self.assertEqual(report_vdt(self.database), (1, "", "".join(f"{line}\n" for line in lines)))
        self.assertEqual(
            verify_store(self.database),
            (
                1,
                "",
                "".join(f"error: {fault.render()}\n" for fault in faults)
                + f"faults: {len(faults)} domain fault(s) in {self.sequence} verified event(s)\n",
            ),
        )


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

    def record_failure(self, completed_at: str) -> tuple[Path, str]:
        """Record the truncated SARIF's failure at `FAILURE_RECORDED_AT` and open its case.

        Returns an evaluations file that evaluates the failure at `completed_at`, and its
        content.
        """

        code, _, err = run(
            [
                "ingest",
                str(FIXTURES / "failed-truncated.sarif"),
                "--db",
                str(self.database),
                "--as-of",
                FAILURE_RECORDED_AT,
                "--record-failed-imports",
                "--actor",
                "tester",
            ]
        )
        # Exit 3: the failure was recorded rather than stopping the ingest.
        self.assertEqual(code, 3, msg=err)
        self.succeeds(["cases", "correlate", "--db", str(self.database), "--actor", "tester"])
        (entry,) = (
            item
            for item in json.loads(FAILED_EVALUATIONS.read_text(encoding="utf-8"))["evaluations"]
            if item["match"]["sourceRecordId"] == "detection-process-failure"
        )
        entry["completedAt"] = completed_at
        content = json.dumps({"evaluations": [entry]})
        evaluations = self.directory / "evaluations.json"
        evaluations.write_text(content, encoding="utf-8")
        return evaluations, content

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

    def test_a_failure_evaluated_before_its_ingest_is_refused_on_every_persisted_surface(
        self,
    ) -> None:
        # A detection process failure is detected at the ingest --as-of in history, so an
        # evaluation completed a day earlier is refused by the writer, and once written
        # around it, by the report and by `store verify`, all in one message whose remedy
        # holds in history (decision 3), never "report from history".
        database = ["--db", str(self.database)]
        actor = ["--actor", "tester"]
        evaluations, content = self.record_failure(FAILURE_EVALUATED_AT)
        verified = self.verify()

        evaluated = run(["cases", "evaluate", *database, "--evaluations", str(evaluations), *actor])

        self.assertEqual(self.verify(), verified)
        store = SQLiteEventStore(self.database)
        try:
            repository = EventRepository(store)
            (case,) = fold_all_cases(repository)
            self.assertEqual(case.source_record_id, "detection-process-failure")
            self.assertEqual(case.evaluations, ())
            stream_id = case_stream_id(case.tracking_id)
            (parsed,) = parse_evaluations(content.encode("utf-8")).entries
            repository.append(
                stream_id,
                CASE_EVALUATED,
                history_writers._evaluation_payload(parsed),
                occurred_at=WRITTEN_AT,
                metadata=EventMetadata(actor="tester"),
                expected_version=len(repository.read_stream(stream_id)),
            )
            (case,) = fold_all_cases(repository)
            assert case.current_evaluation is not None
            sequence = case.current_evaluation.sequence
            checked = store.latest_sequence
        finally:
            store.close()
        message = refusal(
            case.tracking_id, FAILURE_EVALUATED_AT, FAILURE_RECORDED_AT, "system", SYSTEM_REMEDY
        )
        line = f"error: evaluation_before_detection: {message} [detection-process-failure]\n"

        reported = report_vdt(self.database)
        audited = verify_store(self.database)

        self.assertEqual(evaluated, (1, "", line))
        self.assertEqual(reported, (1, "", line))
        self.assertEqual(
            audited,
            (
                1,
                "",
                f"error: sequence {sequence}: evaluation_before_detection: {message}\n"
                f"faults: 1 domain fault(s) in {checked} verified event(s)\n",
            ),
        )
        for _, _, printed in (evaluated, reported, audited):
            self.assertEqual(printed.count(message), 1)
            self.assertIn(f"(source system); {SYSTEM_REMEDY}", printed)
            self.assertNotIn("report from history", printed)

    def test_a_stateless_run_no_later_than_the_evaluation_publishes_what_the_store_refuses(
        self,
    ) -> None:
        # The second refuse-versus-publish divergence (ADR 0014 amendment 2026-10-14): the
        # store detects the failure at the ingest --as-of, after the evaluation, and refuses
        # it, while a stateless run at an as-of no later than completedAt detects the failure
        # at that as-of and publishes the same evaluation.
        evaluations, _ = self.record_failure(FAILURE_EVALUATED_AT)
        code, _, _ = run(
            [
                "cases",
                "evaluate",
                "--db",
                str(self.database),
                "--evaluations",
                str(evaluations),
                "--actor",
                "tester",
            ]
        )
        self.assertEqual(code, 1)

        code, out, err = run(
            [
                "report",
                "vdt",
                str(FIXTURES / "failed-truncated.sarif"),
                "--class",
                "C",
                "--package-uri",
                "https://example.test/cpo",
                "--from",
                "2026-08-01T00:00:00Z",
                "--to",
                "2026-08-31T23:59:59Z",
                "--as-of",
                FAILURE_EVALUATED_AT,
                "--evaluations",
                str(evaluations),
                "--record-failed-imports",
            ]
        )

        # Exit 3: the failure was recorded and its record published, in order.
        self.assertEqual(code, 3, msg=err)
        self.assertNotIn("evaluation_before", err)
        (vulnerability,) = json.loads(out)["vulnerabilities"]
        self.assertEqual(vulnerability["providerTrackingId"], TRUNCATED_CASE)
        self.assertEqual(vulnerability["detection"]["detectedAt"], FAILURE_EVALUATED_AT)
        self.assertEqual(vulnerability["evaluationCompletedAt"], FAILURE_EVALUATED_AT)
        self.assertEqual(vulnerability["x-complyroll"]["detectedAtSource"], "system")

    def test_a_failure_evaluated_after_its_ingest_is_published_on_every_persisted_surface(
        self,
    ) -> None:
        # Detected at the ingest --as-of, the failure evaluated a day later is in order: the
        # writer appends it, `store verify` finds no fault, and the report publishes it.
        evaluations, _ = self.record_failure(FAILURE_LATER_EVALUATED_AT)

        evaluated = self.succeeds(
            [
                "cases",
                "evaluate",
                "--db",
                str(self.database),
                "--evaluations",
                str(evaluations),
                "--actor",
                "tester",
            ]
        )

        self.assertIn("evaluations: 1 appended, 0 skipped", evaluated)
        self.assertTrue(self.verify().startswith("ok: "))
        code, out, err = report_vdt(self.database)
        self.assertEqual(code, 0, msg=err)
        self.assertNotIn("evaluation_before", err + out)
        self.assertIn(FAILURE_LATER_EVALUATED_AT, out)

    def test_verify_folds_every_case_in_a_store_with_no_evaluation(self) -> None:
        # The order check folds every case before it looks for an evaluation, so a case
        # stream that is contract-valid but does not fold fails `store verify`, as a report
        # from the store refuses it, although no case in the store is evaluated.
        store = SQLiteEventStore(self.database)
        try:
            EventRepository(store).append(
                case_stream_id(UNFOLDED_CASE),
                DETECTION_ATTESTED,
                {
                    "detectedAt": "2026-08-10T00:00:00Z",
                    "rationale": RATIONALE,
                    "attestedAt": WRITTEN_AT_TEXT,
                },
                occurred_at=WRITTEN_AT,
                metadata=EventMetadata(actor="tester"),
                expected_version=0,
            )
        finally:
            store.close()

        self.assertEqual(
            verify_store(self.database),
            (
                1,
                "",
                f"error: history_invalid: case {UNFOLDED_CASE!r} begins with "
                "'detection.attested', not 'case.created'\n",
            ),
        )


if __name__ == "__main__":
    unittest.main()
