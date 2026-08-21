from __future__ import annotations

import json
import re
import tempfile
import unittest
from collections.abc import Sequence
from datetime import UTC, datetime
from pathlib import Path

from complyroll import __version__
from complyroll.models import CaseStatus
from complyroll.policy import CertificationClass
from complyroll.reports import (
    FINAL_DISPOSITIONS,
    CompiledVdtReport,
    EvaluationSet,
    ReportCompileError,
    ReportInputError,
    ReportOptions,
    compile_vdt_report,
    load_evaluations,
    parse_evaluations,
)

REPO_ROOT = Path(__file__).parent.parent
FIXTURES = REPO_ROOT / "tests" / "fixtures"
GOLDEN = REPO_ROOT / "tests" / "golden"
EXAMPLES = REPO_ROOT / "examples"

ARTIFACTS = (
    FIXTURES / "ubuntu-host.cklb",
    FIXTURES / "windows-host.ckl",
    FIXTURES / "openscap-results.xml",
)
AS_OF = datetime(2026, 8, 21, 12, 0, tzinfo=UTC)
DETECTED_AT = datetime(2026, 8, 1, 0, 0, tzinfo=UTC)
PERIOD_FROM = datetime(2026, 8, 1, 0, 0, tzinfo=UTC)
PERIOD_TO = datetime(2026, 8, 31, 23, 59, 59, tzinfo=UTC)
PACKAGE_URI = "https://example.test/cpo"


def options(
    *,
    as_of: datetime = AS_OF,
    detected_at: datetime | None = DETECTED_AT,
    certification_class: CertificationClass = CertificationClass.C,
    calendar_timezone: str = "UTC",
) -> ReportOptions:
    return ReportOptions(
        certification_class=certification_class,
        package_uri=PACKAGE_URI,
        period_from=PERIOD_FROM,
        period_to=PERIOD_TO,
        as_of=as_of,
        calendar_timezone=calendar_timezone,
        detected_at_attestation=detected_at,
    )


def evaluation_json(**overrides: object) -> str:
    entry: dict[str, object] = {
        "match": {"sourceRecordId": "V-260470", "sourceType": "cklb"},
        "completedAt": "2026-08-04T12:00:00Z",
        "isInternetReachable": True,
        "isLikelyExploitable": True,
        "pain": 4,
        "potentialAgencyImpact": "Agency tenant data stays reachable through a dormant account.",
        "rationale": "Confirmed reachable from the tenant-facing segment.",
        "evaluator": "Example Provider vulnerability team",
    }
    entry.update(overrides)
    return json.dumps({"evaluations": [entry]})


def evaluations_from(**overrides: object) -> EvaluationSet:
    return parse_evaluations(evaluation_json(**overrides).encode("utf-8"))


def compile_fixtures(
    *,
    artifacts: Sequence[Path] = ARTIFACTS,
    evaluations: EvaluationSet | None = None,
    **option_overrides: object,
) -> CompiledVdtReport:
    return compile_vdt_report(
        list(artifacts),
        options=options(**option_overrides),  # type: ignore[arg-type]
        evaluations=evaluations,
    )


def find_vulnerability(report: CompiledVdtReport, source_record_id: str) -> dict[str, object]:
    for item in report.document["vulnerabilities"]:
        if str(item["vulnerabilityDescription"]).startswith(source_record_id):
            return item
    raise AssertionError(f"no vulnerability for {source_record_id}")


class GoldenReportTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.report = compile_vdt_report(
            list(ARTIFACTS),
            options=options(),
            evaluations=load_evaluations(EXAMPLES / "evaluations.json"),
        )

    def test_json_matches_the_golden_byte_for_byte(self) -> None:
        expected = (GOLDEN / "vdt-fixtures.json").read_text(encoding="utf-8")

        self.assertEqual(self.report.to_json(), expected)

    def test_markdown_matches_the_golden_byte_for_byte(self) -> None:
        expected = (GOLDEN / "vdt-fixtures.md").read_text(encoding="utf-8")

        self.assertEqual(self.report.to_markdown(), expected)

    def test_compiled_document_satisfies_the_official_schema(self) -> None:
        self.assertTrue(self.report.validation.is_valid)
        self.assertEqual(self.report.validation.issues, ())
        self.assertEqual(self.report.validation.provenance.schema_version, "0.1.1")

    def test_compiling_twice_produces_identical_bytes(self) -> None:
        again = compile_vdt_report(
            list(ARTIFACTS),
            options=options(),
            evaluations=load_evaluations(EXAMPLES / "evaluations.json"),
        )

        self.assertEqual(again.to_json(), self.report.to_json())
        self.assertEqual(again.to_markdown(), self.report.to_markdown())

    def test_markdown_totals_reconcile_with_the_json(self) -> None:
        markdown = self.report.to_markdown()
        vulnerabilities = self.report.document["vulnerabilities"]
        summary = {
            label: int(count)
            for label, count in re.findall(r"^\| ([A-Za-z0-9 ,\-]+) \| (\d+) \|$", markdown, re.M)
        }

        rows = [
            line
            for line in markdown.splitlines()
            if line.startswith("| case-") or line.startswith("| Tracking ID |")
        ]
        evaluated = sum(1 for item in vulnerabilities if "evaluationCompletedAt" in item)
        overdue = sum(1 for item in vulnerabilities if item["overdueStatus"]["isOverdue"])

        self.assertEqual(summary["Vulnerabilities reported"], len(vulnerabilities))
        self.assertEqual(len(rows) - 1, len(vulnerabilities))
        self.assertEqual(summary["Evaluated"], evaluated)
        self.assertEqual(summary["Not yet evaluated"], len(vulnerabilities) - evaluated)
        self.assertEqual(summary["Overdue"], overdue)
        for rating in range(1, 6):
            expected = sum(1 for item in vulnerabilities if item.get("currentRating") == rating)
            self.assertEqual(summary[f"Current PAIN N{rating}"], expected)

    def test_extension_carries_generator_and_pinned_provenance(self) -> None:
        extension = self.report.document["x-complyroll"]

        self.assertEqual(extension["generator"], {"name": "complyroll", "version": __version__})
        self.assertEqual(extension["generatedAt"], "2026-08-21T12:00:00Z")
        self.assertEqual(extension["calendarTimezone"], "UTC")
        self.assertEqual(extension["certificationClass"], "C")
        self.assertEqual(len(extension["rulesSource"]["commit"]), 40)
        self.assertEqual(len(extension["schemaSource"]["sha256"]), 64)
        self.assertEqual(
            extension["parserVersions"],
            {"complyroll.ckl": "1", "complyroll.cklb": "1", "complyroll.xccdf": "1"},
        )
        self.assertEqual(
            [item["name"] for item in extension["artifacts"]],
            [path.name for path in ARTIFACTS],
        )
        self.assertIn("not a FedRAMP", extension["disclaimer"])

    def test_grouping_preserves_observations_and_resources(self) -> None:
        vulnerability = find_vulnerability(self.report, "V-253260")
        extension = vulnerability["x-complyroll"]

        self.assertEqual(len(extension["observationIds"]), 1)
        self.assertEqual(
            extension["resources"],
            [{"resourceId": "lab-win-01", "resourceType": "host"}],
        )
        self.assertEqual(extension["sourceIdentifiers"], ["CCI-000366"])


class DetectionTimeTests(unittest.TestCase):
    def test_missing_attestation_names_the_affected_tracking_ids(self) -> None:
        with self.assertRaises(ReportCompileError) as caught:
            compile_fixtures(artifacts=(FIXTURES / "windows-host.ckl",), detected_at=None)

        diagnostics = caught.exception.diagnostics
        self.assertEqual(len(diagnostics), 1)
        self.assertEqual(diagnostics[0].code, "detection_time_missing")
        self.assertIn("case-490f49bfdd1bd019", diagnostics[0].message)

    def test_attestation_is_recorded_in_the_extension(self) -> None:
        report = compile_fixtures(artifacts=(FIXTURES / "windows-host.ckl",))
        attestation = report.document["x-complyroll"]["detectionTimeAttestation"]

        self.assertEqual(attestation["detectedAt"], "2026-08-01T00:00:00Z")
        self.assertEqual(attestation["appliedTo"], ["case-490f49bfdd1bd019"])
        self.assertIn("attested a detection time", report.to_markdown())

    def test_attested_records_declare_their_detection_source(self) -> None:
        report = compile_fixtures(artifacts=(FIXTURES / "windows-host.ckl",))
        vulnerability = report.document["vulnerabilities"][0]

        self.assertEqual(vulnerability["x-complyroll"]["detectedAtSource"], "attestation")
        self.assertEqual(vulnerability["detection"]["detectionSource"], "stig-viewer-2")


class IngestFailureTests(unittest.TestCase):
    def test_an_artifact_that_does_not_ingest_stops_the_run(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            broken = Path(directory) / "broken.cklb"
            broken.write_text("{not json", encoding="utf-8")

            with self.assertRaises(ReportCompileError) as caught:
                compile_fixtures(artifacts=(broken,))

        self.assertTrue(caught.exception.diagnostics)
        self.assertTrue(
            all(item.level.value == "error" for item in caught.exception.diagnostics)
        )

    def test_a_missing_artifact_stops_the_run(self) -> None:
        with self.assertRaises(ReportCompileError):
            compile_fixtures(artifacts=(FIXTURES / "does-not-exist.cklb",))

    def test_no_artifacts_is_refused(self) -> None:
        with self.assertRaises(ReportCompileError) as caught:
            compile_fixtures(artifacts=())

        self.assertEqual(caught.exception.diagnostics[0].code, "no_artifacts")

    def test_error_dispositions_are_surfaced_as_diagnostics(self) -> None:
        source = (FIXTURES / "openscap-results.xml").read_text(encoding="utf-8")
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "openscap-error.xml"
            path.write_text(
                source.replace("<result>pass</result>", "<result>error</result>", 1),
                encoding="utf-8",
            )

            report = compile_fixtures(artifacts=(path,))

        unresolved = [
            item for item in report.diagnostics if item.code == "unresolved_observation"
        ]
        self.assertEqual(len(unresolved), 1)
        self.assertIn("package_aide_installed", unresolved[0].message)
        self.assertIn("disposition error", unresolved[0].message)

    def test_identical_artifact_bytes_are_ingested_once(self) -> None:
        report = compile_fixtures(
            artifacts=(FIXTURES / "windows-host.ckl", FIXTURES / "windows-host.ckl")
        )

        self.assertEqual(len(report.document["x-complyroll"]["artifacts"]), 1)
        self.assertEqual(
            [item.code for item in report.diagnostics if item.code == "duplicate_artifact"],
            ["duplicate_artifact"],
        )


class EvaluationMatchingTests(unittest.TestCase):
    def test_an_evaluation_matching_nothing_is_an_error(self) -> None:
        evaluations = evaluations_from(match={"sourceRecordId": "V-999999"})

        with self.assertRaises(ReportCompileError) as caught:
            compile_fixtures(evaluations=evaluations)

        self.assertEqual(caught.exception.diagnostics[0].code, "evaluation_unmatched")
        self.assertEqual(caught.exception.diagnostics[0].location, "evaluations[0]")

    def test_an_ambiguous_evaluation_is_an_error(self) -> None:
        source = (FIXTURES / "ubuntu-host.cklb").read_text(encoding="utf-8")
        with tempfile.TemporaryDirectory() as directory:
            twin = Path(directory) / "ubuntu-host-2.cklb"
            twin.write_text(
                source.replace("Canonical Ubuntu 24.04 LTS STIG", "Canonical Ubuntu 22.04 STIG"),
                encoding="utf-8",
            )
            evaluations = evaluations_from(match={"sourceRecordId": "V-260470"})

            with self.assertRaises(ReportCompileError) as caught:
                compile_fixtures(
                    artifacts=(FIXTURES / "ubuntu-host.cklb", twin),
                    evaluations=evaluations,
                )

        diagnostic = caught.exception.diagnostics[0]
        self.assertEqual(diagnostic.code, "evaluation_ambiguous")
        self.assertIn("contextKey", diagnostic.message)

    def test_two_evaluations_cannot_claim_one_vulnerability(self) -> None:
        payload = json.loads(evaluation_json())
        payload["evaluations"].append(dict(payload["evaluations"][0]))
        evaluations = parse_evaluations(json.dumps(payload).encode("utf-8"))

        with self.assertRaises(ReportCompileError) as caught:
            compile_fixtures(evaluations=evaluations)

        self.assertEqual(caught.exception.diagnostics[0].code, "evaluation_duplicate")

    def test_context_key_disambiguates_a_match(self) -> None:
        evaluations = evaluations_from(
            match={
                "sourceRecordId": "V-260470",
                "contextKey": "Canonical Ubuntu 24.04 LTS STIG",
                "sourceType": "cklb",
            }
        )

        report = compile_fixtures(evaluations=evaluations)

        self.assertIn("evaluationCompletedAt", find_vulnerability(report, "V-260470"))

    def test_tracking_id_override_is_applied(self) -> None:
        evaluations = evaluations_from(trackingId="PROVIDER-1234")

        report = compile_fixtures(evaluations=evaluations)

        vulnerability = find_vulnerability(report, "V-260470")

        self.assertEqual(vulnerability["providerTrackingId"], "PROVIDER-1234")


class EvaluationInputValidationTests(unittest.TestCase):
    def test_duplicate_keys_are_rejected(self) -> None:
        content = b'{"evaluations": [], "evaluations": []}'

        with self.assertRaisesRegex(ReportInputError, "duplicate JSON object key"):
            parse_evaluations(content)

    def test_nan_is_rejected(self) -> None:
        content = b'{"evaluations": [{"match": {"sourceRecordId": "V-1"}, "pain": NaN}]}'

        with self.assertRaisesRegex(ReportInputError, "non-standard JSON constant"):
            parse_evaluations(content)

    def test_pain_must_be_a_rating(self) -> None:
        for value in (0, 6, "4", True, 4.0):
            with self.subTest(value=value):
                with self.assertRaisesRegex(ReportInputError, r"evaluations\[0\]\.pain"):
                    parse_evaluations(evaluation_json(pain=value).encode("utf-8"))

    def test_flags_must_be_booleans(self) -> None:
        with self.assertRaisesRegex(ReportInputError, "isInternetReachable"):
            parse_evaluations(evaluation_json(isInternetReachable="true").encode("utf-8"))

    def test_required_prose_must_be_non_blank(self) -> None:
        for field_name in ("potentialAgencyImpact", "rationale", "evaluator"):
            with self.subTest(field=field_name):
                payload = evaluation_json(**{field_name: "   "})
                with self.assertRaisesRegex(ReportInputError, field_name):
                    parse_evaluations(payload.encode("utf-8"))

    def test_completed_at_requires_an_offset(self) -> None:
        with self.assertRaisesRegex(ReportInputError, "UTC offset"):
            parse_evaluations(evaluation_json(completedAt="2026-08-04T12:00:00").encode("utf-8"))

    def test_unknown_fields_are_refused(self) -> None:
        with self.assertRaisesRegex(ReportInputError, "painReduction"):
            parse_evaluations(evaluation_json(painReduction=[]).encode("utf-8"))

    def test_disposition_must_be_a_case_status(self) -> None:
        with self.assertRaisesRegex(ReportInputError, "disposition must be one of"):
            parse_evaluations(evaluation_json(disposition="mitigated").encode("utf-8"))

    def test_closed_requires_an_explicit_closed_disposition(self) -> None:
        with self.assertRaisesRegex(ReportInputError, "closedDisposition is required"):
            parse_evaluations(evaluation_json(disposition="closed").encode("utf-8"))

    def test_closed_disposition_must_be_a_closing_status(self) -> None:
        payload = evaluation_json(disposition="closed", closedDisposition="active")
        with self.assertRaisesRegex(ReportInputError, "closedDisposition must be one of"):
            parse_evaluations(payload.encode("utf-8"))

    def test_accepted_requires_an_acceptance_rationale(self) -> None:
        with self.assertRaisesRegex(ReportInputError, "acceptanceRationale is required"):
            parse_evaluations(evaluation_json(disposition="accepted").encode("utf-8"))

    def test_false_positive_flag_cannot_contradict_the_disposition(self) -> None:
        payload = evaluation_json(isFalsePositive=True, disposition="remediated")
        with self.assertRaisesRegex(ReportInputError, "contradicts disposition"):
            parse_evaluations(payload.encode("utf-8"))

    def test_projection_and_reduction_events_are_typed(self) -> None:
        projection = {"estimatedAt": "2026-08-24T16:00:00Z", "targetRating": 9}
        with self.assertRaisesRegex(ReportInputError, "targetRating"):
            parse_evaluations(
                evaluation_json(projectedNextReduction=projection).encode("utf-8")
            )
        with self.assertRaisesRegex(ReportInputError, r"painReductionEvents\[0\]\.reducedAt"):
            parse_evaluations(
                evaluation_json(painReductionEvents=[{"reducedAt": "soon", "rating": 3}]).encode(
                    "utf-8"
                )
            )

    def test_an_empty_evaluations_file_is_valid_and_a_missing_one_is_not(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "evaluations.json"
            path.write_bytes(b'{"evaluations": []}')

            self.assertEqual(load_evaluations(path).entries, ())
            with self.assertRaisesRegex(ReportInputError, "cannot be read"):
                load_evaluations(Path(directory) / "gone.json")

    def test_the_root_must_be_an_object_with_an_evaluations_array(self) -> None:
        with self.assertRaisesRegex(ReportInputError, "must contain a JSON object"):
            parse_evaluations(b"[]")
        with self.assertRaisesRegex(ReportInputError, "evaluations must be an array"):
            parse_evaluations(b'{"evaluations": {}}')


class DispositionMappingTests(unittest.TestCase):
    def test_every_case_status_maps_as_the_decision_table_records(self) -> None:
        expected: dict[CaseStatus, str | None] = {
            CaseStatus.NEW: None,
            CaseStatus.EVALUATING: None,
            CaseStatus.ACTIVE: None,
            CaseStatus.PARTIALLY_MITIGATED: "Partially Mitigated",
            CaseStatus.FULLY_MITIGATED: "Fully Mitigated",
            CaseStatus.REMEDIATED: "Fully Mitigated",
            CaseStatus.FALSE_POSITIVE: "False Positive",
        }
        for status, disposition in expected.items():
            with self.subTest(status=status.value):
                report = compile_fixtures(
                    evaluations=evaluations_from(disposition=status.value)
                )
                vulnerability = find_vulnerability(report, "V-260470")

                self.assertEqual(vulnerability.get("finalDisposition"), disposition)
                self.assertEqual(
                    vulnerability["x-complyroll"]["remediated"],
                    status is CaseStatus.REMEDIATED,
                )

    def test_closed_uses_the_recorded_closing_disposition(self) -> None:
        report = compile_fixtures(
            evaluations=evaluations_from(
                disposition="closed", closedDisposition="false_positive"
            )
        )

        self.assertEqual(
            find_vulnerability(report, "V-260470")["finalDisposition"], "False Positive"
        )

    def test_accepted_is_excluded_from_the_detail_report(self) -> None:
        report = compile_fixtures(
            evaluations=evaluations_from(
                disposition="accepted",
                acceptanceRationale="Compensating network controls are documented in SDR-14.",
            )
        )

        descriptions = [
            item["vulnerabilityDescription"] for item in report.document["vulnerabilities"]
        ]
        self.assertFalse(any(text.startswith("V-260470") for text in descriptions))
        self.assertEqual(len(report.accepted), 1)
        self.assertEqual(report.accepted[0].vulnerability.source_record_id, "V-260470")
        self.assertIn("SDR-14", report.accepted[0].acceptance_rationale)
        self.assertIn(
            "accepted_excluded", [item.code for item in report.diagnostics]
        )

    def test_false_positive_flag_alone_records_the_disposition(self) -> None:
        report = compile_fixtures(evaluations=evaluations_from(isFalsePositive=True))

        self.assertEqual(
            find_vulnerability(report, "V-260470")["finalDisposition"], "False Positive"
        )

    def test_the_decision_table_covers_every_mapped_status(self) -> None:
        self.assertEqual(
            set(FINAL_DISPOSITIONS),
            {
                CaseStatus.PARTIALLY_MITIGATED,
                CaseStatus.FULLY_MITIGATED,
                CaseStatus.REMEDIATED,
                CaseStatus.FALSE_POSITIVE,
            },
        )


class OverdueTests(unittest.TestCase):
    def test_a_missed_pain_response_target_is_overdue_against_a_should(self) -> None:
        report = compile_fixtures(
            evaluations=evaluations_from(
                match={"sourceRecordId": "V-260470", "sourceType": "cklb"},
                completedAt="2026-08-05T16:00:00Z",
                pain=4,
            )
        )
        status = find_vulnerability(report, "V-260470")["overdueStatus"]

        self.assertTrue(status["isOverdue"])
        self.assertIn("VDR-TFR-PVR", status["explanation"])
        self.assertIn("SHOULD", status["explanation"])
        self.assertIn("Class C", status["explanation"])
        self.assertIn("N4", status["explanation"])
        self.assertIn("2026-08-09T16:00:00Z", status["explanation"])
        self.assertIn("58efbf3d898496dd4a3a419eba78e458bbad5cb6", status["explanation"])

    def test_an_unevaluated_vulnerability_past_the_window_cites_evu(self) -> None:
        report = compile_fixtures()
        status = find_vulnerability(report, "V-260469")["overdueStatus"]

        self.assertTrue(status["isOverdue"])
        self.assertIn("VER-TFR-EVU", status["explanation"])
        self.assertIn("2026-08-06T00:00:00Z", status["explanation"])

    def test_an_unevaluated_vulnerability_inside_the_window_is_not_overdue(self) -> None:
        report = compile_fixtures(
            detected_at=datetime(2026, 8, 20, tzinfo=UTC),
            as_of=datetime(2026, 8, 21, tzinfo=UTC),
        )
        status = find_vulnerability(report, "V-260469")["overdueStatus"]

        self.assertFalse(status["isOverdue"])
        self.assertNotIn("explanation", status)

    def test_the_acceptance_threshold_is_reported_as_a_must(self) -> None:
        report = compile_fixtures(
            detected_at=datetime(2026, 1, 1, tzinfo=UTC),
            evaluations=evaluations_from(completedAt="2026-01-03T00:00:00Z", pain=1),
        )
        status = find_vulnerability(report, "V-260470")["overdueStatus"]

        self.assertTrue(status["isOverdue"])
        self.assertIn("VER-TFR-MAV", status["explanation"])
        self.assertIn("MUST", status["explanation"])
        self.assertNotIn("VDR-TFR-PVR", status["explanation"])

    def test_a_recorded_disposition_stops_the_response_clock(self) -> None:
        report = compile_fixtures(
            evaluations=evaluations_from(
                completedAt="2026-08-05T16:00:00Z",
                pain=4,
                disposition="fully_mitigated",
            )
        )
        status = find_vulnerability(report, "V-260470")["overdueStatus"]

        self.assertFalse(status["isOverdue"])

    def test_the_optional_adoption_period_is_named_before_the_obtain_date(self) -> None:
        before = compile_fixtures()
        after = compile_fixtures(as_of=datetime(2027, 1, 15, tzinfo=UTC))

        self.assertIn(
            "optional-adoption period until 2026-12-07",
            find_vulnerability(before, "V-260469")["overdueStatus"]["explanation"],
        )
        self.assertNotIn(
            "optional-adoption",
            find_vulnerability(after, "V-260469")["overdueStatus"]["explanation"],
        )

    def test_every_vulnerability_reports_an_overdue_status(self) -> None:
        report = compile_fixtures()

        for vulnerability in report.document["vulnerabilities"]:
            self.assertIn("overdueStatus", vulnerability)
            self.assertIsInstance(vulnerability["overdueStatus"]["isOverdue"], bool)

    def test_deadlines_are_auditable_in_the_extension(self) -> None:
        report = compile_fixtures(
            evaluations=evaluations_from(completedAt="2026-08-05T16:00:00Z", pain=4)
        )
        deadlines = find_vulnerability(report, "V-260470")["x-complyroll"]["deadlines"]

        self.assertEqual(
            [item["ruleId"] for item in deadlines],
            ["VER-TFR-EVU", "VDR-TFR-PVR", "VER-TFR-MAV"],
        )
        self.assertEqual(deadlines[1]["anchor"], "evaluation")
        self.assertEqual(deadlines[1]["timeframe"], {"amount": 4, "unit": "days"})
        self.assertEqual(deadlines[0]["anchor"], "detection")


class ReportOptionsTests(unittest.TestCase):
    def test_package_uri_must_be_absolute_http(self) -> None:
        self.assertEqual(options().package_uri, PACKAGE_URI)
        for value in ("", "example.test/cpo", "ftp://example.test/cpo", "/local/path"):
            with self.subTest(value=value):
                with self.assertRaisesRegex(ValueError, "package_uri"):
                    ReportOptions(
                        certification_class=CertificationClass.C,
                        package_uri=value,
                        period_from=PERIOD_FROM,
                        period_to=PERIOD_TO,
                        as_of=AS_OF,
                    )

    def test_period_must_not_run_backwards(self) -> None:
        with self.assertRaisesRegex(ValueError, "period_from must not be after"):
            ReportOptions(
                certification_class=CertificationClass.C,
                package_uri=PACKAGE_URI,
                period_from=PERIOD_TO,
                period_to=PERIOD_FROM,
                as_of=AS_OF,
            )

    def test_timestamps_must_be_timezone_aware(self) -> None:
        with self.assertRaisesRegex(ValueError, "as_of must include a timezone"):
            ReportOptions(
                certification_class=CertificationClass.C,
                package_uri=PACKAGE_URI,
                period_from=PERIOD_FROM,
                period_to=PERIOD_TO,
                as_of=datetime(2026, 8, 21, 12, 0),
            )

    def test_calendar_timezone_is_validated_at_the_boundary(self) -> None:
        with self.assertRaisesRegex(ValueError, "calendar_timezone"):
            options(calendar_timezone="Mars/Olympus_Mons")

    def test_calendar_timezone_reaches_the_extension(self) -> None:
        report = compile_fixtures(calendar_timezone="America/Phoenix")

        self.assertEqual(
            report.document["x-complyroll"]["calendarTimezone"], "America/Phoenix"
        )


if __name__ == "__main__":
    unittest.main()
