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

import hashlib
import io
import json
import shutil
import tempfile
import unittest
from collections.abc import Callable, Iterator, Mapping, Sequence
from contextlib import redirect_stderr, redirect_stdout
from dataclasses import replace
from datetime import UTC, datetime
from pathlib import Path
from typing import Any
from unittest import mock

from test_reports import (
    EXAMPLES,
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
from complyroll.correlation import (
    VulnerabilityGroup,
    group_open_observations,
    tracking_id_for,
)
from complyroll.events import EventMetadata, EventRepository, case_stream_id, iso_utc
from complyroll.history import (
    ARTIFACT_INGESTED,
    AUDIT_FAULT_CODES,
    CASE_CREATED,
    CASE_EVALUATED,
    CASE_IDENTIFIED,
    CASE_OBSERVATION_LINKED,
    DETECTION_ATTESTED,
    OBSERVATION_RECORDED,
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
from complyroll.policy import CertificationClass
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


#: Two rules whose group keys share one correlation id, 64 bits of SHA-256. A search on a laptop
#: found the pair in under a minute, so a file can be built to hold one (CL6A-F-01).
COLLIDING_RULES = ("R44e0d066875d4bc4", "Re463e3245367e5c9")
COLLIDING_CONTEXT = "S"
COLLIDING_ID = "case-8c2b3a84c332d647"
COLLISION_TAIL = "an override may rename one vulnerability but may not merge two"


def colliding_scan(
    directory: Path, *rules: str, host: str = "lab-01", completed_at: str = "2026-08-10T00:00:00Z"
) -> Path:
    """Write a CKLB file holding the named rules on one host, both of the pair by default."""

    path = directory / f"{host}-{len(rules)}-{'-'.join(rules)[:24]}.cklb"
    payload = {
        "title": "scan",
        "completed_at": completed_at,
        "target_data": {"host_name": host},
        "stigs": [
            {
                "stig_name": COLLIDING_CONTEXT,
                "rules": [
                    {
                        "group_id": rule,
                        "rule_title": f"rule {rule}",
                        "severity": "medium",
                        "status": "open",
                        "ccis": [],
                    }
                    for rule in rules or COLLIDING_RULES
                ],
            }
        ],
    }
    path.write_text(json.dumps(payload), encoding="utf-8")
    return path


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
            [item.render() for item in outcome.warnings],
            [
                f"warning: evaluation_before_partial_detection: {case} was evaluated at {EARLY}, "
                f"before its earliest known detection time {TIMED_AT} (source artifact-partial); "
                "an observation that declares no source timestamp may have detected it earlier, "
                f"so the record is published [{BANNER_RULE}]",
            ],
        )
        (warning,) = [
            item
            for item in self.report().diagnostics
            if item.code == "evaluation_before_partial_detection"
        ]
        self.assertEqual(outcome.warnings[0], warning)

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
            [item.code for item in outcome.warnings],
            ["evaluation_before_partial_detection"],
        )
        self.assertIn(
            f"detection time {TIMED_AT} (source artifact-partial)", outcome.warnings[0].message
        )

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

    def test_verify_names_a_case_that_does_not_fold_in_a_store_with_no_evaluation(self) -> None:
        # A case stream that is contract-valid but does not fold fails `store verify`, as a
        # report from the store refuses it, although no case in the store is evaluated. The
        # order check used to find it by folding every case and raising `history_invalid`;
        # the audit now names it first, as `case_stream_mismatch` (CL-81).
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

        message = f"case {UNFOLDED_CASE!r} begins with 'detection.attested', not 'case.created'"
        code, out, err = verify_store(self.database)
        self.assertEqual((code, out), (1, ""))
        fault, summary = err.splitlines()
        self.assertRegex(fault, r"^error: sequence [0-9]+: case_stream_mismatch: ")
        self.assertTrue(fault.endswith(f": {message}"), fault)
        self.assertTrue(summary.startswith("faults: 1 domain fault(s) in "), summary)
        self.assertEqual(report_vdt(self.database), (1, "", f"error: history_invalid: {message}\n"))


class TrackingIdCollisionFaultTests(HistoryOrderFixture):
    """A store two records would publish under one tracking id is a fault (CL6A-E-01).

    A report refuses it as `tracking_id_collision`, and `store verify` passed it on the premise
    that no such store can arrive around `cases evaluate` (ADR 0008 amendment 2026-11-03). The
    claimants are what a report reads: each current group, under the override its case's current
    evaluation carries, else its correlation id.
    """

    COMPLETED_AT = "2026-08-11T12:00:00Z"

    def timed(self, rule: str) -> Path:
        return self.artifact(rule, [("lab-timed", TIMED_AT)], rule=rule)

    def untimed(self, rule: str) -> Path:
        return self.artifact(rule, [("lab-untimed", None)], rule=rule)

    def tracking_id_of(self, path: Path) -> str:
        (group,) = groups_of((path,))
        return group.tracking_id

    def evaluation_of(self, rule: str, **fields: object) -> EvaluationSet:
        entry: dict[str, object] = {
            "match": {"sourceRecordId": rule, "sourceType": "xccdf"},
            "completedAt": self.COMPLETED_AT,
        }
        entry.update(fields)
        return evaluations_for(entry)

    def case_of(self, rule: str) -> str:
        (case,) = [
            item.tracking_id
            for item in fold_all_cases(self.repository)
            if item.source_record_id == rule
        ]
        return case

    def identify(self, tracking_id: str, override: str) -> int:
        """Record an override around the writers and return its event's sequence."""

        self.append_around(tracking_id, CASE_IDENTIFIED, {"providerTrackingId": override})
        return self.sequence

    def evaluate_around_writers(self, rule: str) -> None:
        self.evaluate_around(self.evaluation_of(rule), self.case_of(rule))

    # *--- The stores the table reads ---*

    def later_ingest_without_correlate(self) -> None:
        # The override names a correlation id no case holds yet, which the writer accepts.
        banner, sshd = self.timed(BANNER_RULE), self.timed(SSHD_RULE)
        self.ingest(banner)
        self.correlate()
        self.evaluate(self.evaluation_of(BANNER_RULE, trackingId=self.tracking_id_of(sshd)))
        self.ingest(sshd)

    def later_ingest_correlated(self) -> None:
        self.later_ingest_without_correlate()
        self.correlate()

    def two_evaluated_cases_sharing_one_override(self) -> None:
        self.ingest(self.timed(BANNER_RULE), self.timed(SSHD_RULE))
        self.correlate()
        self.evaluate(self.evaluation_of(BANNER_RULE, trackingId="PROV-SHARED"))
        self.evaluate_around_writers(SSHD_RULE)
        self.identify(self.case_of(SSHD_RULE), "PROV-SHARED")

    def override_onto_an_evaluated_natural_id(self) -> None:
        banner, sshd = self.timed(BANNER_RULE), self.timed(SSHD_RULE)
        self.ingest(banner)
        self.correlate()
        self.evaluate(self.evaluation_of(BANNER_RULE, trackingId=self.tracking_id_of(sshd)))
        self.ingest(sshd)
        self.correlate()
        self.evaluate_around_writers(SSHD_RULE)

    def three_claimants(self) -> None:
        self.ingest(self.timed(BANNER_RULE), self.timed(SSHD_RULE), self.timed("third_rule"))
        self.correlate()
        self.evaluate(self.evaluation_of(BANNER_RULE, trackingId="PROV-SHARED"))
        for rule in (SSHD_RULE, "third_rule"):
            self.evaluate_around_writers(rule)
            self.identify(self.case_of(rule), "PROV-SHARED")

    def override_with_no_current_evaluation(self) -> None:
        # `effective_tracking_id` would call this a collision. No report ever reads the override.
        banner, sshd = self.timed(BANNER_RULE), self.timed(SSHD_RULE)
        self.ingest(banner, sshd)
        self.correlate()
        self.identify(self.case_of(BANNER_RULE), self.tracking_id_of(sshd))

    def stale_case_with_the_override(self) -> None:
        # The stale case has no open group, so it publishes nothing to collide with.
        sshd = self.timed(SSHD_RULE)
        self.ingest(sshd)
        self.correlate()
        self.append_around(ORPHAN_CASE, CASE_CREATED, orphan_created(ORPHAN_CASE))
        self.evaluate_around(self.evaluation_of(BANNER_RULE), ORPHAN_CASE)
        self.identify(ORPHAN_CASE, self.tracking_id_of(sshd))

    def distinct_overrides(self) -> None:
        self.ingest(self.timed(BANNER_RULE), self.timed(SSHD_RULE))
        self.correlate()
        self.evaluate(self.evaluation_of(BANNER_RULE, trackingId="PROV-ONE"))
        self.evaluate(self.evaluation_of(SSHD_RULE, trackingId="PROV-TWO"))

    def override_equal_to_its_own_id(self) -> None:
        banner = self.timed(BANNER_RULE)
        self.ingest(banner, self.timed(SSHD_RULE))
        self.correlate()
        self.evaluate(self.evaluation_of(BANNER_RULE, trackingId=self.tracking_id_of(banner)))

    def real_pair_alone(self) -> None:
        self.ingest(self.timed(BANNER_RULE))
        self.correlate()
        self.ingest(colliding_scan(self.directory))

    def real_pair_beside_an_override_elsewhere(self) -> None:
        self.ingest(self.timed(BANNER_RULE))
        self.correlate()
        self.evaluate(self.evaluation_of(BANNER_RULE, trackingId="PROV-ELSEWHERE"))
        self.ingest(colliding_scan(self.directory))

    def real_pair_with_an_override_onto_its_id(self) -> None:
        self.ingest(self.timed(BANNER_RULE))
        self.correlate()
        self.evaluate(self.evaluation_of(BANNER_RULE, trackingId=COLLIDING_ID))
        self.ingest(colliding_scan(self.directory))

    def real_pair_after_the_new_override(self) -> None:
        self.real_pair_with_an_override_onto_its_id()
        self.evaluate(self.evaluation_of(BANNER_RULE, trackingId="PROV-RENAMED"))

    def one_case_for_the_real_pair(self, **fields: object) -> None:
        # 0.3.0a0's `cases correlate` made one case for the pair, from the first group.
        scan = colliding_scan(self.directory)
        self.ingest(scan)
        created = history_writers._case_created_payload(groups_of((scan,))[0], WRITTEN_AT)
        self.append_around(COLLIDING_ID, CASE_CREATED, created)
        if fields:
            match = {"sourceRecordId": COLLIDING_RULES[0]}
            self.evaluate(self.evaluation_of(COLLIDING_RULES[0], match=match, **fields))

    def real_pair_on_the_one_case_an_old_build_made(self) -> None:
        self.one_case_for_the_real_pair()

    def real_pair_on_one_case_with_its_override(self) -> None:
        self.one_case_for_the_real_pair(trackingId="PROV-ONE-CASE")

    def unread_override_beside_the_same_override_read(self) -> None:
        self.ingest(self.timed(BANNER_RULE), self.timed(SSHD_RULE))
        self.correlate()
        self.evaluate(self.evaluation_of(SSHD_RULE, trackingId="PROV-SHARED"))
        self.identify(self.case_of(BANNER_RULE), "PROV-SHARED")

    def two_unread_overrides_alike(self) -> None:
        self.ingest(self.timed(BANNER_RULE), self.timed(SSHD_RULE))
        self.correlate()
        self.identify(self.case_of(BANNER_RULE), "PROV-SHARED")
        self.identify(self.case_of(SSHD_RULE), "PROV-SHARED")

    def unread_override_naming_its_own_id_beside_a_claim(self) -> None:
        # The report publishes the first under its own id, which the second's override names.
        banner = self.timed(BANNER_RULE)
        self.ingest(banner, self.timed(SSHD_RULE))
        self.correlate()
        self.evaluate_around_writers(SSHD_RULE)
        self.identify(self.case_of(SSHD_RULE), self.tracking_id_of(banner))
        self.identify(self.case_of(BANNER_RULE), self.tracking_id_of(banner))

    def two_stale_cases_sharing_an_override(self) -> None:
        for tracking_id in (ORPHAN_CASE, SPARE_CASE):
            self.append_around(tracking_id, CASE_CREATED, orphan_created(tracking_id))
            self.evaluate_around(self.evaluation_of(BANNER_RULE), tracking_id)
            self.identify(tracking_id, "PROV-STALE")

    def refused_collisions(self) -> set[str]:
        """Return the messages a report refuses this store with, under either class."""

        found: set[str] = set()
        for certification_class in CertificationClass:
            try:
                compile_record_set_from_history(
                    self.repository,
                    options=options(detected_at=None, certification_class=certification_class),
                )
            except ReportCompileError as exc:
                found.update(
                    item.message for item in exc.diagnostics if item.code == "tracking_id_collision"
                )
        return found

    def test_wherever_a_report_refuses_with_a_collision_verify_names_it(self) -> None:
        for build, expected in (
            (self.later_ingest_without_correlate, 1),
            (self.later_ingest_correlated, 1),
            (self.two_evaluated_cases_sharing_one_override, 1),
            (self.override_onto_an_evaluated_natural_id, 1),
            (self.three_claimants, 2),
            (self.override_with_no_current_evaluation, 0),
            (self.stale_case_with_the_override, 0),
            (self.distinct_overrides, 0),
            (self.override_equal_to_its_own_id, 0),
            (self.real_pair_alone, 1),
            (self.real_pair_beside_an_override_elsewhere, 1),
            (self.real_pair_with_an_override_onto_its_id, 2),
            (self.real_pair_after_the_new_override, 1),
            (self.real_pair_on_the_one_case_an_old_build_made, 1),
            (self.real_pair_on_one_case_with_its_override, 1),
        ):
            with self.subTest(store=build.__name__):
                self.open_store(f"{build.__name__}.db")
                build()

                refused = self.refused_collisions()
                faults = audit_history(self.repository)

                self.assertEqual(len(refused), expected)
                self.assertEqual({fault.message for fault in faults}, refused)
                self.assertEqual(
                    {fault.code for fault in faults},
                    {"tracking_id_collision"} if expected else set(),
                )
                code, _, err = verify_store(self.database)
                self.assertEqual(code, 1 if expected else 0, err)
                for message in refused:
                    self.assertIn(f": tracking_id_collision: {message}\n", err)

    def test_verify_prints_the_report_s_words_at_the_override_s_event(self) -> None:
        self.later_ingest_without_correlate()
        banner = self.case_of(BANNER_RULE)
        (override,) = [
            record.sequence
            for record in self.repository.read_stream(case_stream_id(banner))
            if record.event_type == CASE_IDENTIFIED
        ]
        sshd = self.tracking_id_of(self.timed(SSHD_RULE))
        (report_line,) = self.report_refusal()
        message = (
            f"effective tracking id {sshd!r} is claimed by evaluations[0] (originally {banner}) "
            f"and no evaluation entry (originally {sshd}); an override may rename one "
            "vulnerability but may not merge two"
        )

        self.assertEqual(
            report_line, f"error: tracking_id_collision: {message} [no evaluation entry]"
        )
        self.assertEqual(report_vdt(self.database), (1, "", f"{report_line}\n"))
        self.assertEqual(
            audit_history(self.repository),
            (HistoryFault(override, "tracking_id_collision", message),),
        )
        self.assertEqual(
            verify_store(self.database),
            (
                1,
                "",
                f"error: sequence {override}: tracking_id_collision: {message}\n"
                f"faults: 1 domain fault(s) in {self.sequence} verified event(s)\n",
            ),
        )

    def test_the_fault_is_at_the_latest_override_among_the_claimants(self) -> None:
        self.two_evaluated_cases_sharing_one_override()
        later = self.sequence

        (fault,) = audit_history(self.repository)

        self.assertEqual(fault.sequence, later)
        # Another event on a claimant does not move it: an override answers the fault.
        self.evaluate_around_writers(SSHD_RULE)
        self.assertGreater(self.sequence, later)
        (fault,) = audit_history(self.repository)
        self.assertEqual(fault.sequence, later)
        # A later override on the first claimant, naming the same id, moves it there.
        latest = self.identify(self.case_of(BANNER_RULE), "PROV-SHARED")
        (fault,) = audit_history(self.repository)
        self.assertEqual(fault.sequence, latest)

    def test_an_override_no_report_reads_does_not_move_the_fault(self) -> None:
        # The second claimant claims its correlation id, so its unread override is no claim.
        self.later_ingest_correlated()
        (override,) = [
            record.sequence
            for record in self.repository.read_stream(case_stream_id(self.case_of(BANNER_RULE)))
            if record.event_type == CASE_IDENTIFIED
        ]
        unread = self.identify(self.case_of(SSHD_RULE), "PROV-UNREAD")

        (fault,) = audit_history(self.repository)

        self.assertLess(override, unread)
        self.assertEqual(fault.sequence, override)

    def test_a_new_override_clears_the_fault_and_the_refusal(self) -> None:
        self.later_ingest_correlated()
        self.assertEqual(len(audit_history(self.repository)), 1)

        self.evaluate(self.evaluation_of(BANNER_RULE, trackingId="PROV-RENAMED"))

        self.assertEqual(audit_history(self.repository), ())
        self.assertEqual(self.refused_collisions(), set())
        self.assertEqual(verify_store(self.database)[0], 0)

    def test_a_group_with_no_detection_time_counts_before_the_report_reaches_it(self) -> None:
        # The report stops at the next step of the workflow, and the collision is already recorded.
        banner, sshd = self.timed(BANNER_RULE), self.untimed(SSHD_RULE)
        self.ingest(banner)
        self.correlate()
        self.evaluate(self.evaluation_of(BANNER_RULE, trackingId=self.tracking_id_of(sshd)))
        self.ingest(sshd)

        (line,) = self.report_refusal()

        self.assertTrue(line.startswith("error: detection_time_missing: "), line)
        self.assertEqual(
            [fault.code for fault in audit_history(self.repository)], ["tracking_id_collision"]
        )

    def test_detection_time_missing_alone_is_not_a_fault(self) -> None:
        # It asks for the workflow's next step and contradicts nothing recorded.
        self.ingest(self.untimed(BANNER_RULE))
        self.correlate()

        (line,) = self.report_refusal()

        self.assertTrue(line.startswith("error: detection_time_missing: "), line)
        self.assertEqual(audit_history(self.repository), ())

    def test_it_is_named_beside_a_fault_no_reader_refuses(self) -> None:
        self.later_ingest_without_correlate()
        stream_id = case_stream_id(ORPHAN_CASE)
        (bad,) = self.repository.store.append(
            stream_id,
            [
                NewEvent(
                    event_type=CASE_CREATED,
                    occurred_at=WRITTEN_AT,
                    payload=orphan_created(ORPHAN_CASE),
                    metadata={"actor": "tester"},
                )
            ],
            expected_version=0,
        )

        faults = audit_history(self.repository)

        self.assertEqual(
            sorted(fault.code for fault in faults),
            ["event_metadata_invalid", "tracking_id_collision"],
        )
        self.assertIn(bad.sequence, [fault.sequence for fault in faults])

    def test_it_is_not_looked_for_beside_a_fault_that_stops_the_fold(self) -> None:
        self.later_ingest_without_correlate()
        self.append_around(ORPHAN_CASE, CASE_IDENTIFIED, {"providerTrackingId": "PROV-ORPHAN"})

        faults = audit_history(self.repository)

        self.assertEqual({fault.code for fault in faults}, {"case_stream_mismatch"})

    def test_beside_a_walk_fault_no_report_refuses_verify_rejects_under_that_fault(self) -> None:
        # The gate `evaluation_before_detection` runs behind: the store is still rejected with
        # a named fault, and the report names the collision. Only a hand-built store gets here.
        self.later_ingest_without_correlate()
        (head,) = [
            record
            for record in self.repository.read_all()
            if record.event_type == ARTIFACT_INGESTED
        ][:1]
        self.repository.store.append(
            head.stream_id,
            [
                NewEvent(
                    event_type=CASE_IDENTIFIED,
                    occurred_at=WRITTEN_AT,
                    payload={"providerTrackingId": "PROV-MISPLACED"},
                    metadata=self.metadata.to_dict(),
                )
            ],
            expected_version=len(self.repository.read_stream(head.stream_id)),
        )

        faults = audit_history(self.repository)

        self.assertEqual({fault.code for fault in faults}, {"event_stream_mismatch"})
        self.assertEqual(len(self.refused_collisions()), 1)

    def test_each_later_claimant_pairs_with_the_first_in_the_report_s_order(self) -> None:
        self.three_claimants()
        cases = {
            case.source_record_id: f"evaluations[{index}] (originally {case.tracking_id})"
            for index, case in enumerate(fold_all_cases(self.repository))
        }

        def pair(first: str, second: str) -> str:
            return (
                f"effective tracking id 'PROV-SHARED' is claimed by {cases[first]} and "
                f"{cases[second]}; {COLLISION_TAIL}"
            )

        expected = [pair(BANNER_RULE, SSHD_RULE), pair(BANNER_RULE, "third_rule")]

        with self.assertRaises(ReportCompileError) as caught:
            self.report()

        self.assertEqual([item.message for item in caught.exception.diagnostics], expected)
        self.assertEqual([fault.message for fault in audit_history(self.repository)], expected)

    # *--- What `cases evaluate` counts ---*

    BYSTANDER_RULE = "bystander_rule"

    def run_refusals(self, evaluations: EvaluationSet) -> tuple[str, ...]:
        """Return the lines this run is refused with on a store's own account, else nothing."""

        before = self.sequence
        try:
            self.evaluate(evaluations)
        except EvaluationMatchError as caught:
            self.assertEqual(self.sequence, before)
            return caught.problems
        return ()

    def test_a_refusal_at_recorded_history_means_verify_names_a_fault(self) -> None:
        for build, refused in (
            (self.later_ingest_without_correlate, 0),
            (self.later_ingest_correlated, 1),
            (self.two_evaluated_cases_sharing_one_override, 1),
            (self.override_onto_an_evaluated_natural_id, 1),
            (self.three_claimants, 2),
            (self.override_with_no_current_evaluation, 0),
            (self.stale_case_with_the_override, 0),
            (self.distinct_overrides, 0),
            (self.override_equal_to_its_own_id, 0),
            (self.real_pair_alone, 0),
            (self.real_pair_with_an_override_onto_its_id, 0),
            (self.real_pair_on_one_case_with_its_override, 0),
            (self.unread_override_beside_the_same_override_read, 0),
            (self.two_unread_overrides_alike, 0),
            (self.unread_override_naming_its_own_id_beside_a_claim, 1),
            (self.two_stale_cases_sharing_an_override, 0),
        ):
            with self.subTest(store=build.__name__):
                self.open_store(f"bystander-{build.__name__}.db")
                self.ingest(self.timed(self.BYSTANDER_RULE))
                self.correlate()
                build()
                faults = audit_history(self.repository)

                problems = self.run_refusals(self.evaluation_of(self.BYSTANDER_RULE))

                self.assertEqual(len(problems), refused)
                for problem in problems:
                    self.assertTrue(problem.startswith("recorded history: "), problem)
                    self.assertNotIn("evaluations[", problem)
                if refused:
                    self.assertIn("tracking_id_collision", [fault.code for fault in faults])

    def test_a_refusal_naming_an_entry_is_located_at_that_entry(self) -> None:
        # Cases are walked in id order, so the entry can be either side of the pair.
        banner, sshd = self.timed(BANNER_RULE), self.timed(SSHD_RULE)
        self.ingest(banner, sshd)
        self.correlate()
        ordered = sorted(
            ((self.tracking_id_of(banner), BANNER_RULE), (self.tracking_id_of(sshd), SSHD_RULE))
        )
        (first, first_rule), (second, second_rule) = ordered
        tail = "an override may rename one case but may not merge two"

        for rule, target, expected in (
            (
                first_rule,
                second,
                f"evaluations[0] (originally {first}) and recorded history (originally {second})",
            ),
            (
                second_rule,
                first,
                f"recorded history (originally {first}) and evaluations[0] (originally {second})",
            ),
        ):
            with self.subTest(rule=rule):
                self.assertEqual(
                    self.run_refusals(self.evaluation_of(rule, trackingId=target)),
                    (
                        f"evaluations[0]: effective tracking id {target!r} is claimed by "
                        f"{expected}; {tail}",
                    ),
                )

    def test_a_stale_case_claims_nothing_when_this_run_touches_it(self) -> None:
        self.stale_case_with_the_override()
        sshd = self.tracking_id_of(self.timed(SSHD_RULE))
        match = {"sourceRecordId": "V-000001"}

        # It keeps the recorded override, which no report publishes.
        self.evaluate(self.evaluation_of("V-000001", match=match))
        self.assertEqual(self.run_refusals(self.evaluation_of(SSHD_RULE)), ())
        # And it can state the same id again, or any other.
        self.evaluate(self.evaluation_of("V-000001", match=match, trackingId=sshd))
        self.evaluate(self.evaluation_of("V-000001", match=match, trackingId="PROV-NEW"))

        self.assertEqual(audit_history(self.repository), ())
        self.report()

    def test_an_entry_can_name_the_id_a_stale_case_holds(self) -> None:
        self.ingest(self.timed(SSHD_RULE), self.timed(BANNER_RULE))
        self.correlate()
        self.append_around(ORPHAN_CASE, CASE_CREATED, orphan_created(ORPHAN_CASE))
        self.evaluate_around(self.evaluation_of(BANNER_RULE), ORPHAN_CASE)
        self.identify(ORPHAN_CASE, "PROV-STALE")

        self.evaluate(self.evaluation_of(BANNER_RULE, trackingId="PROV-STALE"))

        self.assertEqual(audit_history(self.repository), ())
        self.report()

    def with_and_without_a_duplicate_elsewhere(self) -> Iterator[None]:
        """Run a test's body on a store with no two cases alike, then on one the check reads."""

        for name, prepare in (
            ("no-duplicate.db", lambda: None),
            ("duplicate.db", self.two_stale_cases_sharing_an_override),
        ):
            with self.subTest(store=name):
                self.open_store(name)
                prepare()
                yield

    def test_an_unread_override_adds_no_claim_on_its_correlation_id(self) -> None:
        # Counting that id would be a new refusal: the writer never counted it for this case. The
        # report publishes the case under it, so the store can then hold the collision verify names.
        for _ in self.with_and_without_a_duplicate_elsewhere():
            banner, sshd = self.timed(BANNER_RULE), self.timed(SSHD_RULE)
            self.ingest(banner, sshd)
            self.correlate()
            self.identify(self.case_of(BANNER_RULE), "PROV-UNREAD")

            self.evaluate(self.evaluation_of(SSHD_RULE, trackingId=self.tracking_id_of(banner)))

            self.assertEqual(
                [fault.code for fault in audit_history(self.repository)], ["tracking_id_collision"]
            )
            self.assertEqual(len(self.refused_collisions()), 1)

    def test_a_touched_case_claims_its_recorded_override(self) -> None:
        # This run makes the override current, so the report would publish it.
        self.unread_override_beside_the_same_override_read()
        self.assertEqual(audit_history(self.repository), ())

        (problem,) = self.run_refusals(self.evaluation_of(BANNER_RULE))

        self.assertIn("effective tracking id 'PROV-SHARED' is claimed by", problem)
        self.assertTrue(problem.startswith("evaluations[0]: "), problem)
        self.assertEqual(audit_history(self.repository), ())

    def test_a_group_no_case_holds_is_still_not_counted(self) -> None:
        # Seeing it would be a new refusal. Verify names what this leaves.
        for _ in self.with_and_without_a_duplicate_elsewhere():
            banner, sshd = self.timed(BANNER_RULE), self.timed(SSHD_RULE)
            self.ingest(banner)
            self.correlate()
            self.ingest(sshd)

            self.evaluate(self.evaluation_of(BANNER_RULE, trackingId=self.tracking_id_of(sshd)))

            self.assertEqual(
                [fault.code for fault in audit_history(self.repository)], ["tracking_id_collision"]
            )

    def test_a_run_reads_no_group_for_this_check_when_no_two_cases_can_collide(self) -> None:
        self.distinct_overrides()
        empty = parse_evaluations(json.dumps({"evaluations": []}).encode("utf-8"))

        with mock.patch.object(history_writers, "current_groups") as reader:
            self.assertEqual(self.run_refusals(empty), ())

        reader.assert_not_called()

    def test_a_run_with_no_entry_is_refused_only_for_a_collision_verify_names(self) -> None:
        empty = parse_evaluations(json.dumps({"evaluations": []}).encode("utf-8"))
        self.stale_case_with_the_override()
        self.assertEqual(self.run_refusals(empty), ())
        self.open_store("named.db")
        self.later_ingest_correlated()

        (problem,) = self.run_refusals(empty)

        self.assertTrue(problem.startswith("recorded history: "), problem)
        self.assertEqual(len(audit_history(self.repository)), 1)

    def test_a_new_override_still_recovers_a_refusal_at_recorded_history(self) -> None:
        self.ingest(self.timed(self.BYSTANDER_RULE))
        self.correlate()
        self.later_ingest_correlated()
        bystander = self.evaluation_of(self.BYSTANDER_RULE)
        self.assertEqual(len(self.run_refusals(bystander)), 1)

        self.evaluate(self.evaluation_of(BANNER_RULE, trackingId="PROV-RENAMED"))

        self.assertEqual(self.run_refusals(bystander), ())
        self.assertEqual(audit_history(self.repository), ())

    # *--- Two groups under one correlation id ---*

    def observation_sequences(self, rule: str) -> list[int]:
        """Return the sequences of a rule's `observation.recorded` events, in order."""

        return [
            record.sequence
            for record in self.repository.read_all()
            if record.event_type == OBSERVATION_RECORDED
            and record.payload["source_record_id"] == rule
        ]

    def pair_message(self) -> str:
        side = f"no evaluation entry (originally {COLLIDING_ID})"
        return (
            f"effective tracking id {COLLIDING_ID!r} is claimed by {side} and {side}; "
            f"{COLLISION_TAIL}"
        )

    def test_the_pair_is_one_correlation_id(self) -> None:
        for rule in COLLIDING_RULES:
            self.assertEqual(tracking_id_for("cklb", rule, COLLIDING_CONTEXT), COLLIDING_ID)
        groups = groups_of((colliding_scan(self.directory),))
        self.assertEqual([group.source_record_id for group in groups], list(COLLIDING_RULES))
        self.assertEqual([group.tracking_id for group in groups], [COLLIDING_ID] * 2)

    def test_a_pair_with_no_override_is_at_the_latest_observation_among_the_two(self) -> None:
        first, second = COLLIDING_RULES
        self.real_pair_alone()

        (fault,) = audit_history(self.repository)

        self.assertEqual(fault.message, self.pair_message())
        self.assertEqual(fault.sequence, self.observation_sequences(second)[-1])
        self.assertLess(self.observation_sequences(first)[-1], fault.sequence)

    def test_that_sequence_holds_whichever_group_arrived_last(self) -> None:
        # The report's first claimant holds the first rule, and here its observation is the latest.
        first, second = COLLIDING_RULES
        self.ingest(colliding_scan(self.directory, second, host="lab-02"))
        self.assertEqual(audit_history(self.repository), ())
        self.ingest(colliding_scan(self.directory, first, host="lab-03"))

        (fault,) = audit_history(self.repository)

        self.assertEqual(fault.sequence, self.observation_sequences(first)[-1])
        self.assertLess(self.observation_sequences(second)[-1], fault.sequence)

    def test_that_sequence_is_the_latest_of_a_group_s_observations(self) -> None:
        first, second = COLLIDING_RULES
        self.ingest(colliding_scan(self.directory, first, host="lab-02"))
        self.ingest(colliding_scan(self.directory, second, host="lab-03"))
        self.ingest(colliding_scan(self.directory, first, host="lab-04"))

        (fault,) = audit_history(self.repository)

        (earlier, latest) = self.observation_sequences(first)
        self.assertLess(earlier, self.observation_sequences(second)[-1])
        self.assertEqual(fault.sequence, latest)

    def test_a_pair_keeps_the_latest_override_when_it_has_one(self) -> None:
        self.real_pair_with_an_override_onto_its_id()
        (override,) = [
            record.sequence
            for record in self.repository.read_stream(case_stream_id(self.case_of(BANNER_RULE)))
            if record.event_type == CASE_IDENTIFIED
        ]

        faults = audit_history(self.repository)

        self.assertEqual(
            [(fault.sequence, fault.message) for fault in faults],
            [
                (
                    override,
                    f"effective tracking id {COLLIDING_ID!r} is claimed by no evaluation entry "
                    f"(originally {COLLIDING_ID}) and evaluations[0] (originally "
                    f"{self.case_of(BANNER_RULE)}); {COLLISION_TAIL}",
                ),
                (self.observation_sequences(COLLIDING_RULES[1])[-1], self.pair_message()),
            ],
        )

    def test_two_groups_sharing_one_case_share_its_override(self) -> None:
        # So no override can part them, and both sides name one entry twice.
        self.real_pair_on_one_case_with_its_override()
        (override,) = [
            record.sequence
            for record in self.repository.read_stream(case_stream_id(COLLIDING_ID))
            if record.event_type == CASE_IDENTIFIED
        ]
        side = f"evaluations[0] (originally {COLLIDING_ID})"

        (fault,) = audit_history(self.repository)

        self.assertEqual(fault.sequence, override)
        self.assertEqual(
            fault.message,
            f"effective tracking id 'PROV-ONE-CASE' is claimed by {side} and {side}; "
            f"{COLLISION_TAIL}",
        )
        self.assertEqual(self.refused_collisions(), {fault.message})

    def test_a_new_override_does_not_clear_a_pair(self) -> None:
        self.real_pair_with_an_override_onto_its_id()
        self.assertEqual(len(audit_history(self.repository)), 2)

        self.evaluate(self.evaluation_of(BANNER_RULE, trackingId="PROV-RENAMED"))

        (fault,) = audit_history(self.repository)
        self.assertEqual(fault.message, self.pair_message())
        self.assertEqual(self.refused_collisions(), {self.pair_message()})
        self.assertEqual(verify_store(self.database)[0], 1)

    def test_the_order_checks_still_read_one_group_for_the_pair(self) -> None:
        self.real_pair_alone()
        groups = current_groups(self.repository)
        self.assertEqual(sum(key == COLLIDING_ID for key in groups), 1)
        self.assertEqual(
            len(group_open_observations(history_order.rehydrate_observations(self.repository))), 3
        )

    def plain_xccdf(self, name: str, benchmark: str, result: str, *rules: str) -> Path:
        """Write an XCCDF document whose ids are exactly the ones given, unstripped."""

        path = self.directory / name
        verdicts = "".join(
            f'<rule-result idref="{rule}"><result>fail</result></rule-result>' for rule in rules
        )
        path.write_text(
            '<Benchmark xmlns="http://checklists.nist.gov/xccdf/1.2" '
            f'id="{benchmark}"><TestResult id="{result}" end-time="{TIMED_AT}">'
            f"<target>lab-01</target>{verdicts}</TestResult></Benchmark>",
            encoding="utf-8",
        )
        return path

    def test_a_context_key_of_only_whitespace_leaves_no_entry_to_name_a_claimant(self) -> None:
        # So a new override cannot clear this collision. `contextKey` must be non-blank, and the
        # twin under a real name makes each source record ambiguous.
        second = self.plain_xccdf("second.xml", "", " ", "rule_two")
        self.ingest(self.plain_xccdf("first.xml", "", " ", "rule_one"))
        self.correlate()
        self.assertEqual(self.case_of("rule_one"), tracking_id_for("xccdf", "rule_one", " "))
        match = {"sourceRecordId": "rule_one"}
        target = self.tracking_id_of(second)
        self.evaluate(self.evaluation_of("rule_one", match=match, trackingId=target))
        self.ingest(second, self.plain_xccdf("real.xml", "real", "named", "rule_one", "rule_two"))
        self.correlate()
        self.assertEqual(len(audit_history(self.repository)), 1)

        (ambiguous,) = self.run_refusals(self.evaluation_of("rule_one", match=match))
        self.assertIn("matches 2 cases", ambiguous)
        with self.assertRaisesRegex(ValueError, "contextKey must be non-blank"):
            self.evaluation_of("rule_one", match={**match, "contextKey": " "})

    def test_a_cklb_file_with_a_blank_stig_name_stays_reachable(self) -> None:
        # Its context key is stored as `cklb`, so an entry can name either claimant.
        def scan(name: str, stig: str, *rules: str) -> Path:
            path = colliding_scan(self.directory, *rules, host=name)
            payload = json.loads(path.read_text(encoding="utf-8"))
            payload["stigs"][0]["stig_name"] = stig
            path.write_text(json.dumps(payload), encoding="utf-8")
            return path

        second = scan("second", " ", "V-2")
        self.ingest(scan("first", " ", "V-1"))
        self.correlate()
        match = {"sourceRecordId": "V-1", "contextKey": "cklb"}
        target = self.tracking_id_of(second)
        self.evaluate(self.evaluation_of("V-1", match=match, trackingId=target))
        self.ingest(second, scan("real", "Real Name", "V-1", "V-2"))
        self.correlate()
        self.assertEqual(len(audit_history(self.repository)), 1)

        self.evaluate(self.evaluation_of("V-1", match=match, trackingId="PROV-RENAMED"))

        self.assertEqual(audit_history(self.repository), ())

    def test_a_long_override_is_cut_in_both_places_alike(self) -> None:
        sshd = self.timed(SSHD_RULE)
        self.ingest(self.timed(BANNER_RULE), sshd)
        self.correlate()
        long_id = "P" * 5000
        self.evaluate(self.evaluation_of(BANNER_RULE, trackingId=long_id))
        self.evaluate_around_writers(SSHD_RULE)
        self.identify(self.case_of(SSHD_RULE), long_id)

        (fault,) = audit_history(self.repository)

        self.assertEqual(self.refused_collisions(), {fault.message})
        self.assertIn(f"{'P' * 199}... (5002 characters) is claimed by", fault.message)
        self.assertLess(len(fault.message), 500)


class TrackingIdCollisionCommandTests(unittest.TestCase):
    """The collision through the command line alone, as an operator reaches it (CL6A-E-01)."""

    AS_OF = "2026-08-21T12:00:00Z"
    #: The correlation id the OpenSCAP fixture's banner finding gets.
    BANNER_ID = "case-04efea8c137ae82f"
    UBUNTU_ID = "case-1f3e011db93cc89e"

    def setUp(self) -> None:
        directory = tempfile.TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        self.directory = Path(directory.name)
        self.database = str(self.directory / "history.db")

    def succeeds(self, *argv: str) -> None:
        code, _, err = run(argv)
        self.assertEqual(code, 0, msg=f"{list(argv)} exited {code}: {err}")

    def evaluate(self, override: str) -> None:
        payload = json.loads((EXAMPLES / "evaluations.json").read_text(encoding="utf-8"))
        payload["evaluations"][0]["trackingId"] = override
        evaluations = self.directory / "evaluations.json"
        evaluations.write_text(json.dumps(payload), encoding="utf-8")
        self.succeeds("cases", "evaluate", "--db", self.database, "--evaluations", str(evaluations))

    def ingest(self, *names: str) -> None:
        paths = [str(FIXTURES / name) for name in names]
        self.succeeds("ingest", *paths, "--db", self.database, "--as-of", self.AS_OF)

    def correlate_and_attest(self) -> None:
        self.succeeds("cases", "correlate", "--db", self.database)
        self.succeeds(
            "cases",
            "attest-detection",
            "--db",
            self.database,
            "--all-missing",
            "--detected-at",
            "2026-08-01T00:00:00Z",
            "--rationale",
            "Attested from the change record.",
        )

    def report(self, kind: str, as_of: str | None = None) -> tuple[int, str, str]:
        period = ["--from", "2026-08-01T00:00:00Z", "--to", "2026-08-31T23:59:59Z"]
        return run(
            [
                "report",
                kind,
                "--db",
                self.database,
                "--class",
                "C",
                "--package-uri",
                "https://example.test/cpo",
                "--as-of",
                as_of or self.AS_OF,
                *([] if kind == "historical" else period),
            ]
        )

    def test_a_later_ingest_brings_the_id_an_override_already_names(self) -> None:
        self.ingest("ubuntu-host.cklb", "windows-host.ckl")
        self.correlate_and_attest()
        self.evaluate(self.BANNER_ID)
        self.succeeds("store", "verify", "--db", self.database)

        self.ingest("openscap-results.xml")
        self.correlate_and_attest()

        code, out, err = run(["store", "verify", "--db", self.database])

        message = (
            f"effective tracking id {self.BANNER_ID!r} is claimed by evaluations[1] (originally "
            f"{self.UBUNTU_ID}) and no evaluation entry (originally {self.BANNER_ID}); an override "
            "may rename one vulnerability but may not merge two"
        )
        self.assertEqual((code, out), (1, ""))
        lines = err.splitlines()
        self.assertRegex(lines[0], r"^error: sequence \d+: tracking_id_collision: ")
        self.assertTrue(lines[0].endswith(f": tracking_id_collision: {message}"), err)
        self.assertRegex(lines[1], r"^faults: 1 domain fault\(s\) in \d+ verified event\(s\)$")
        self.assertEqual(len(lines), 2)
        refusal = f"error: tracking_id_collision: {message} [no evaluation entry]\n"
        for kind in ("vdt", "avi", "historical"):
            with self.subTest(report=kind):
                self.assertEqual(self.report(kind), (1, "", refusal))
        # The rule reads no clock, and neither does the fault.
        self.assertEqual(self.report("vdt", "2026-08-20T00:00:00Z"), (1, "", refusal))

        self.evaluate("RENAMED-1")

        self.succeeds("store", "verify", "--db", self.database)
        self.assertEqual(self.report("vdt")[0], 0)

    # *--- One crafted file, two groups under one correlation id ---*

    PAIR_SIDE = f"no evaluation entry (originally {COLLIDING_ID})"
    PAIR_MESSAGE = (
        f"effective tracking id {COLLIDING_ID!r} is claimed by {PAIR_SIDE} and {PAIR_SIDE}; "
        f"{COLLISION_TAIL}"
    )
    PAIR_REFUSAL = f"error: tracking_id_collision: {PAIR_MESSAGE} [no evaluation entry]"
    ONTO_THE_PAIR_MESSAGE = (
        f"effective tracking id {COLLIDING_ID!r} is claimed by {PAIR_SIDE} and evaluations[0] "
        f"(originally {UBUNTU_ID}); {COLLISION_TAIL}"
    )
    ONTO_THE_PAIR_REFUSAL = (
        f"error: tracking_id_collision: {ONTO_THE_PAIR_MESSAGE} [evaluations[0]]"
    )

    def healthy_store(self) -> None:
        self.ingest("ubuntu-host.cklb", "windows-host.ckl")
        self.correlate_and_attest()
        self.succeeds("store", "verify", "--db", self.database)
        self.assertEqual(self.report("vdt")[0], 0)

    def ingest_the_crafted_file(self) -> None:
        scan = colliding_scan(self.directory)
        code, out, _ = run(["ingest", str(scan), "--db", self.database, "--as-of", self.AS_OF])
        self.assertEqual((code, out), (0, f"{scan.name}: recorded 2 observation(s)\n"))

    def assert_verify_names(self, *messages: str) -> None:
        code, out, err = run(["store", "verify", "--db", self.database])
        self.assertEqual((code, out), (1, ""), err)
        lines = err.splitlines()
        named = [line.split(": tracking_id_collision: ", 1)[1] for line in lines[:-1]]
        self.assertCountEqual(named, messages)
        self.assertRegex(
            lines[-1], rf"^faults: {len(messages)} domain fault\(s\) in \d+ verified event\(s\)$"
        )

    def assert_every_report_refuses(self, *lines: str) -> None:
        refusal = "".join(f"{line}\n" for line in lines)
        for kind in ("vdt", "avi", "historical"):
            with self.subTest(report=kind):
                self.assertEqual(self.report(kind), (1, "", refusal))

    def test_one_crafted_file_stops_every_report_and_correlate(self) -> None:
        self.healthy_store()

        self.ingest_the_crafted_file()

        self.assert_verify_names(self.PAIR_MESSAGE)
        self.assert_every_report_refuses(self.PAIR_REFUSAL)
        code, _, err = run(["cases", "correlate", "--db", self.database])
        self.assertEqual(code, 1)
        self.assertTrue(err.startswith(f"error: store_conflict: stream 'case/{COLLIDING_ID}'"), err)
        self.assert_verify_names(self.PAIR_MESSAGE)

    def test_no_entry_can_name_either_group_of_the_pair(self) -> None:
        self.healthy_store()
        self.ingest_the_crafted_file()
        for rule in COLLIDING_RULES:
            payload = json.loads((EXAMPLES / "evaluations.json").read_text(encoding="utf-8"))
            payload["evaluations"] = [
                {**payload["evaluations"][0], "match": {"sourceRecordId": rule}}
            ]
            evaluations = self.directory / "evaluations.json"
            evaluations.write_text(json.dumps(payload), encoding="utf-8")
            with self.subTest(rule=rule):
                code, _, err = run(
                    ["cases", "evaluate", "--db", self.database, "--evaluations", str(evaluations)]
                )
                self.assertEqual(code, 1)
                self.assertIn(f"no case matches sourceRecordId={rule!r}", err)
        self.assert_verify_names(self.PAIR_MESSAGE)

    def test_an_override_elsewhere_changes_nothing_about_the_pair(self) -> None:
        self.healthy_store()
        self.evaluate("ACME-1")

        self.ingest_the_crafted_file()

        self.assert_verify_names(self.PAIR_MESSAGE)
        self.assert_every_report_refuses(self.PAIR_REFUSAL)

    def test_an_override_onto_the_pair_then_a_new_one(self) -> None:
        self.healthy_store()
        self.evaluate(COLLIDING_ID)

        self.ingest_the_crafted_file()

        self.assert_verify_names(self.PAIR_MESSAGE, self.ONTO_THE_PAIR_MESSAGE)
        self.assert_every_report_refuses(self.PAIR_REFUSAL, self.ONTO_THE_PAIR_REFUSAL)

        self.evaluate("RENAMED-1")

        self.assert_verify_names(self.PAIR_MESSAGE)
        self.assert_every_report_refuses(self.PAIR_REFUSAL)

    def test_the_pair_beside_an_inventory(self) -> None:
        self.healthy_store()
        self.ingest_the_crafted_file()

        code, out, err = run(
            [
                "report",
                "vdt",
                "--db",
                self.database,
                "--class",
                "C",
                "--package-uri",
                "https://example.test/cpo",
                "--as-of",
                self.AS_OF,
                "--from",
                "2026-08-01T00:00:00Z",
                "--to",
                "2026-08-31T23:59:59Z",
                "--inventory",
                str(EXAMPLES / "inventory.json"),
            ]
        )

        self.assertEqual((code, out), (1, ""))
        self.assertEqual(err, f"{self.PAIR_REFUSAL}\n")
        self.assert_verify_names(self.PAIR_MESSAGE)

    # *--- A claimant that goes stale ---*

    #: A SARIF log under a name that sends it to another parser, then under its right name.
    SCAN_BYTES = FIXTURES / "grype-image.sarif"
    SCAN_DIGEST = hashlib.sha256(SCAN_BYTES.read_bytes()).hexdigest()
    FAILURE_ID = tracking_id_for(
        "complyroll.detection-process", "detection-process-failure", f"sha256:{SCAN_DIGEST}"
    )
    FAILURE_EVALUATED_AT = "2026-08-22T12:00:00Z"

    def apply_entry(self, match: dict[str, str], **fields: str) -> tuple[int, str, str]:
        payload = json.loads((EXAMPLES / "evaluations.json").read_text(encoding="utf-8"))
        entry = {**payload["evaluations"][0], "match": match}
        entry.pop("trackingId", None)
        entry.update(fields)
        payload["evaluations"] = [entry]
        evaluations = self.directory / "entry.json"
        evaluations.write_text(json.dumps(payload), encoding="utf-8")
        return run(["cases", "evaluate", "--db", self.database, "--evaluations", str(evaluations)])

    def applied(self, rule: str, **fields: str) -> None:
        code, _, err = self.apply_entry({"sourceRecordId": rule}, **fields)
        self.assertEqual(code, 0, err)

    def misnamed_scan(self, *names: str) -> None:
        """Ingest the log under each name, which fails, and record each failure."""

        for name in names:
            path = self.directory / name
            shutil.copyfile(self.SCAN_BYTES, path)
            code, _, err = run(
                [
                    "ingest",
                    str(path),
                    "--db",
                    self.database,
                    "--as-of",
                    self.AS_OF,
                    "--record-failed-imports",
                ]
            )
            self.assertEqual(code, 3, err)
        self.succeeds("cases", "correlate", "--db", self.database)

    def rightly_named_scan(self) -> None:
        path = self.directory / "scan-output.sarif"
        shutil.copyfile(self.SCAN_BYTES, path)
        self.succeeds("ingest", str(path), "--db", self.database, "--as-of", self.AS_OF)
        self.correlate_and_attest()

    def event_count(self, event_type: str) -> int:
        store = SQLiteEventStore(self.database)
        self.addCleanup(store.close)
        return sum(record.event_type == event_type for record in store.read_all())

    def assert_no_file_is_stopped(self) -> None:
        """Require verify and a report to pass, and an unrelated entry to go through."""

        self.succeeds("store", "verify", "--db", self.database)
        self.assertEqual(self.report("vdt")[0], 0)
        self.applied("V-260470")
        self.applied("V-260470", trackingId="BRAND-NEW-1")
        self.succeeds("store", "verify", "--db", self.database)
        self.assertEqual(self.report("vdt")[0], 0)

    def assert_refused_at_recorded_history(self) -> None:
        code, _, err = self.apply_entry({"sourceRecordId": "V-260470"})
        self.assertEqual(code, 1)
        self.assertTrue(
            err.startswith(
                "error: evaluation_unmatched: evaluations could not be applied: "
                "recorded history: effective tracking id "
            ),
            err,
        )
        self.assertEqual(run(["store", "verify", "--db", self.database])[0], 1)

    def test_an_override_onto_a_failure_that_goes_stale_stops_no_file(self) -> None:
        for names in (("scan-output.ckl",), ("scan-output.ckl", "scan-output.xml")):
            with self.subTest(names=names):
                self.database = str(self.directory / f"override-{len(names)}.db")
                self.ingest("windows-host.ckl", "ubuntu-host.cklb")
                self.correlate_and_attest()
                self.applied("V-253260", trackingId=self.FAILURE_ID)

                self.misnamed_scan(*names)

                self.assertEqual(self.event_count("failure.held"), len(names) - 1)
                self.assert_refused_at_recorded_history()

                self.rightly_named_scan()

                self.assert_no_file_is_stopped()

    def test_a_failure_s_own_override_that_goes_stale_stops_no_file(self) -> None:
        for names in (("scan-output.ckl",), ("scan-output.ckl", "scan-output.xml")):
            with self.subTest(names=names):
                self.database = str(self.directory / f"own-{len(names)}.db")
                self.ingest("ubuntu-host.cklb")
                self.correlate_and_attest()
                self.misnamed_scan(*names)
                code, _, err = self.apply_entry(
                    system_match(self.SCAN_DIGEST),
                    trackingId=self.BANNER_ID,
                    completedAt=self.FAILURE_EVALUATED_AT,
                )
                self.assertEqual(code, 0, err)
                self.ingest("openscap-results.xml")
                self.correlate_and_attest()

                self.assertEqual(self.event_count("failure.held"), len(names) - 1)
                self.assert_refused_at_recorded_history()

                self.rightly_named_scan()

                self.assert_no_file_is_stopped()

    def test_a_new_override_on_a_stale_or_a_current_claimant_goes_through(self) -> None:
        self.ingest("windows-host.ckl", "ubuntu-host.cklb")
        self.correlate_and_attest()
        self.applied("V-253260", trackingId=self.FAILURE_ID)
        self.misnamed_scan("scan-output.ckl")
        self.rightly_named_scan()

        self.applied("V-253260", trackingId="RENAMED-CURRENT")
        code, _, err = self.apply_entry(
            system_match(self.SCAN_DIGEST),
            trackingId="RENAMED-STALE",
            completedAt=self.FAILURE_EVALUATED_AT,
        )

        self.assertEqual(code, 0, err)
        self.assert_no_file_is_stopped()


if __name__ == "__main__":
    unittest.main()
