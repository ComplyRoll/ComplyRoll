# ******************************************************************************
# *Title: Evaluation Order Tests*
# *Author: Kyle Versluis*
# *Description: Tests for ordering evaluations against detection time.*
# ******************************************************************************
"""Tests for ordering an evaluation's completedAt against its record's detection time.

The compiler refuses a record evaluated before a detection time that is its own
(`artifact`, `attestation`, `system`), warns on a partly timestamped group, and names
every refusal it reaches in one run (ADR 0007 amendment 2026-10-14).
"""

# *--- Imports ---*

from __future__ import annotations

import tempfile
import unittest
from collections.abc import Sequence
from dataclasses import replace
from datetime import UTC, datetime
from pathlib import Path

from test_reports import compile_fixtures, evaluations_for, options

from complyroll.adapters import ingest_stig_artifact
from complyroll.correlation import VulnerabilityGroup, group_open_observations
from complyroll.models import CaseStatus
from complyroll.reports import (
    EvaluationSet,
    ReportCompileError,
    ReportDiagnostic,
    compile_record_set_from_artifacts,
)

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


if __name__ == "__main__":
    unittest.main()
