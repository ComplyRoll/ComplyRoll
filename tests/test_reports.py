from __future__ import annotations

import json
import re
import tempfile
import unittest
from collections.abc import Sequence
from dataclasses import replace
from datetime import UTC, datetime
from itertools import permutations
from pathlib import Path
from typing import Literal, overload

from complyroll import __version__
from complyroll.adapters import DiagnosticLevel, IngestResult, ingest_stig_artifact
from complyroll.correlation import group_open_observations
from complyroll.models import CaseStatus
from complyroll.policy import CertificationClass
from complyroll.reports import (
    FINAL_DISPOSITIONS,
    MAX_EVALUATIONS_BYTES,
    CompiledArtifact,
    CompiledAviReport,
    CompiledHistoricalReport,
    CompiledRecordSet,
    CompiledReport,
    CompiledVdtReport,
    DetectionAttestation,
    EvaluationSet,
    ReportCompileError,
    ReportInputError,
    ReportOptions,
    compile_avi_report,
    compile_historical_report,
    compile_record_set,
    compile_record_set_from_artifacts,
    compile_records,
    compile_vdt_report,
    load_evaluations,
    parse_evaluations,
    project_avi,
    project_historical,
    project_vdt,
)
from complyroll.schemas import ReportSchema, validate_bundled_report

MIXED_TIMESTAMP_XCCDF = """<?xml version="1.0" encoding="UTF-8"?>
<Benchmark xmlns="http://checklists.nist.gov/xccdf/1.2" id="mixed">
  <TestResult id="shared" end-time="2026-08-03T09:00:00Z">
    <target>lab-timed</target>
    <rule-result idref="xccdf_org.ssgproject.content_rule_banner_etc_issue" severity="medium">
      <result>fail</result>
      <ident system="https://public.cyber.mil/stigs/cci/">CCI-000048</ident>
    </rule-result>
  </TestResult>
  <TestResult id="shared">
    <target>lab-untimed</target>
    <rule-result idref="xccdf_org.ssgproject.content_rule_banner_etc_issue" severity="medium">
      <result>fail</result>
      <ident system="https://public.cyber.mil/stigs/cci/">CCI-000048</ident>
    </rule-result>
  </TestResult>
</Benchmark>
"""

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
ACCEPTED_EVALUATIONS = EXAMPLES / "evaluations-accepted.json"
#: The one accepted record `examples/evaluations-accepted.json` adds to the fixtures.
BANNER_CASE = "case-04efea8c137ae82f"
BANNER_RATIONALE = (
    "Accepted under change record CR-102 pending the banner template refresh in Q4."
)
#: Overrides that turn the default `evaluation_json` entry into an acceptance.
ACCEPTANCE = {
    "disposition": "accepted",
    "acceptanceRationale": "Accepted under change record CR-102 pending the template refresh.",
}

BANNER_MATCH = {"sourceRecordId": "banner_etc_issue", "sourceType": "xccdf"}
ReportKind = Literal["vdt", "avi", "historical"]
REPORT_KINDS: tuple[ReportKind, ...] = ("vdt", "avi", "historical")


def options(
    *,
    as_of: datetime = AS_OF,
    detected_at: datetime | None = DETECTED_AT,
    certification_class: CertificationClass = CertificationClass.C,
    calendar_timezone: str = "UTC",
    period_from: datetime | None = PERIOD_FROM,
    period_to: datetime | None = PERIOD_TO,
) -> ReportOptions:
    return ReportOptions(
        certification_class=certification_class,
        package_uri=PACKAGE_URI,
        period_from=period_from,
        period_to=period_to,
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


def evaluations_for(*entries: dict[str, object]) -> EvaluationSet:
    """Parse several evaluation entries at once, each built on the default entry."""

    parsed = [json.loads(evaluation_json(**entry))["evaluations"][0] for entry in entries]
    return parse_evaluations(json.dumps({"evaluations": parsed}).encode("utf-8"))


@overload
def compile_fixtures(
    *,
    artifacts: Sequence[Path] = ARTIFACTS,
    evaluations: EvaluationSet | None = None,
    kind: Literal["vdt"] = "vdt",
    **option_overrides: object,
) -> CompiledVdtReport: ...


@overload
def compile_fixtures(
    *,
    artifacts: Sequence[Path] = ARTIFACTS,
    evaluations: EvaluationSet | None = None,
    kind: Literal["avi"],
    **option_overrides: object,
) -> CompiledAviReport: ...


@overload
def compile_fixtures(
    *,
    artifacts: Sequence[Path] = ARTIFACTS,
    evaluations: EvaluationSet | None = None,
    kind: Literal["historical"],
    **option_overrides: object,
) -> CompiledHistoricalReport: ...


@overload
def compile_fixtures(
    *,
    artifacts: Sequence[Path] = ARTIFACTS,
    evaluations: EvaluationSet | None = None,
    kind: ReportKind,
    **option_overrides: object,
) -> CompiledVdtReport | CompiledAviReport | CompiledHistoricalReport: ...


def compile_fixtures(
    *,
    artifacts: Sequence[Path] = ARTIFACTS,
    evaluations: EvaluationSet | None = None,
    kind: ReportKind = "vdt",
    **option_overrides: object,
) -> CompiledVdtReport | CompiledAviReport | CompiledHistoricalReport:
    """Compile one report of the given kind from the fixtures with the test options."""

    report_options = options(**option_overrides)  # type: ignore[arg-type]
    if kind == "avi":
        return compile_avi_report(list(artifacts), options=report_options, evaluations=evaluations)
    if kind == "historical":
        return compile_historical_report(
            list(artifacts), options=report_options, evaluations=evaluations
        )
    return compile_vdt_report(list(artifacts), options=report_options, evaluations=evaluations)


def summary_counts(markdown: str) -> dict[str, int]:
    """Read every `| label | count |` row of a Markdown twin's Summary table."""

    return {
        label: int(count)
        for label, count in re.findall(r"^\| ([A-Za-z0-9 ,\-]+) \| (\d+) \|$", markdown, re.M)
    }


def distinct_xccdf(label: str) -> str:
    """Return the XCCDF fixture rewritten to share no vulnerability with its twins.

    Grouping is by `(source_type, source_record_id, context_key)` and the XCCDF context
    key is built from the benchmark id, so moving the benchmark id as well as the host
    keeps each copy's findings in their own groups. A test about the artifact manifest
    or the diagnostics list then observes those lists alone, rather than also observing
    how a shared group orders its members. `shared_benchmark_xccdf` is the counterpart
    for tests whose subject is that shared group.
    """

    return (
        (FIXTURES / "openscap-results.xml")
        .read_text(encoding="utf-8")
        .replace('id="test"', f'id="{label}"')
        .replace("lab-ubuntu-02", f"host-{label}")
    )


def shared_benchmark_xccdf(host: str) -> str:
    """Return the XCCDF fixture retargeted to one host, keeping the benchmark id.

    One benchmark scanned across a fleet is the ordinary case, and it produces one
    vulnerability per rule whose members come from every host's file. Only the target
    moves here, so two of these correlate into shared groups.
    """

    return (
        (FIXTURES / "openscap-results.xml")
        .read_text(encoding="utf-8")
        .replace("lab-ubuntu-02", host)
    )


def ingest_text(text: str, name: str) -> IngestResult:
    """Parse one artifact written from text, exactly as the report path parses it."""

    with tempfile.TemporaryDirectory() as directory:
        path = Path(directory) / name
        path.write_text(text, encoding="utf-8")
        return ingest_stig_artifact(path, ingested_at=AS_OF)


def compiled_artifact(result: IngestResult) -> CompiledArtifact:
    """Return the artifact provenance `compile_records` expects for one ingest."""

    artifact = result.artifact
    if artifact is None:
        raise AssertionError("the artifact under test must parse")
    return CompiledArtifact(
        name=artifact.name,
        sha256=artifact.digest_sha256,
        parser=artifact.parser_name,
        parser_version=artifact.parser_version,
        size_bytes=artifact.size_bytes,
        observation_count=len(result.observations),
    )


def find_vulnerability(
    report: CompiledReport,
    source_record_id: str,
    *,
    key: str = "vulnerabilities",
) -> dict[str, object]:
    """Return one official `vulnerabilityDetail` object from the document array `key`."""

    for item in report.document[key]:
        if str(item["vulnerabilityDescription"]).startswith(source_record_id):
            return item
    raise AssertionError(f"no vulnerability for {source_record_id} under {key}")


def find_accepted(report: CompiledReport, source_record_id: str) -> dict[str, object]:
    """Return one `acceptedVulnerabilityInfo` item of an AVI or historical document."""

    for item in report.document["acceptedVulnerabilities"]:
        detail = item["vulnerabilityDetail"]
        if str(detail["vulnerabilityDescription"]).startswith(source_record_id):
            return item
    raise AssertionError(f"no accepted vulnerability for {source_record_id}")


def official_records(report: CompiledReport, key: str) -> list[dict[str, object]]:
    """Return the `vulnerabilityDetail` objects under one document array.

    `vulnerabilities` and `activeVulnerabilities` hold the objects directly;
    `acceptedVulnerabilities` wraps each one in an `acceptedVulnerabilityInfo` item.
    """

    return [
        item["vulnerabilityDetail"] if "vulnerabilityDetail" in item else item
        for item in report.document[key]
    ]


def markdown_section(markdown: str, heading: str) -> str:
    """Return one top-level Markdown section body, without its heading line."""

    parts = markdown.split(f"\n## {heading}\n", 1)
    if len(parts) == 1:
        return ""
    return parts[1].split("\n## ", 1)[0]


def markdown_detail_sections(
    markdown: str,
    heading: str = "Vulnerability details",
) -> tuple[tuple[str, str], ...]:
    """Return each vulnerability detail section as (heading, body), in report order.

    The renderer walks the compiled records once for the summary table and once for
    the detail sections, so section `i` is vulnerability `i`. Pairing by position
    rather than by heading text keeps this reader independent of how a tracking
    identifier is escaped into a heading. `heading` names the details section to
    read, since the AVI and historical twins title theirs differently.
    """

    body = markdown_section(markdown, heading)
    sections: list[tuple[str, str]] = []
    current: str | None = None
    lines: list[str] = []
    for line in body.splitlines():
        if line.startswith("### "):
            if current is not None:
                sections.append((current, "\n".join(lines)))
            current = line[4:]
            lines = []
            continue
        lines.append(line)
    if current is not None:
        sections.append((current, "\n".join(lines)))
    return tuple(sections)


def markdown_table_rows(section: str, width: int, header: str) -> dict[str, tuple[str, ...]]:
    """Return one Markdown table's data rows, keyed by their first cell."""

    rows: dict[str, tuple[str, ...]] = {}
    for line in section.splitlines():
        if not line.startswith("| ") or not line.endswith(" |"):
            continue
        cells = tuple(cell.strip() for cell in line[2:-2].split(" | "))
        if len(cells) != width or cells[0] == header:
            continue
        rows[cells[0]] = cells
    return rows


VDT_DETAIL_SECTIONS = (("Vulnerability details", "vulnerabilities"),)
AVI_DETAIL_SECTIONS = (("Accepted vulnerability details", "acceptedVulnerabilities"),)
HISTORICAL_DETAIL_SECTIONS = (
    ("Active vulnerability details", "activeVulnerabilities"),
    ("Accepted vulnerability details", "acceptedVulnerabilities"),
)


def assert_markdown_carries_the_json(
    test: unittest.TestCase,
    report: CompiledReport,
    *,
    sections: Sequence[tuple[str, str]] = VDT_DETAIL_SECTIONS,
) -> None:
    """Assert the Markdown twin states every audit fact the JSON document carries.

    The two renderings are built from one record list, so this walks the compiled JSON
    and demands the Markdown twin say the same thing about every vulnerability: the
    observations grouped into it, each computed deadline with its due instant and
    whether it is satisfied, and every source artifact with the parser version that
    read it (ADR 0007 amendment, the two renderings carry the same audit content).
    `sections` pairs each Markdown details heading with the document array it renders.
    """

    markdown = report.to_markdown()
    for details_heading, key in sections:
        vulnerabilities = official_records(report, key)
        detail_sections = markdown_detail_sections(markdown, details_heading)
        test.assertEqual(len(detail_sections), len(vulnerabilities), details_heading)

        for (heading, body), vulnerability in zip(detail_sections, vulnerabilities, strict=True):
            extension = vulnerability["x-complyroll"]
            for observation_id in extension["observationIds"]:
                test.assertIn(observation_id, body, f"{heading} omits {observation_id}")
            for observation_id in extension["untimestampedObservationIds"]:
                test.assertIn(observation_id, body, f"{heading} omits {observation_id}")

            rows = markdown_table_rows(body, 7, "Rule")
            deadlines = extension["deadlines"]
            test.assertEqual(len(rows), len(deadlines), f"{heading} deadline rows")
            for deadline in deadlines:
                row = rows.get(deadline["ruleId"])
                test.assertIsNotNone(row, f"{heading} omits deadline {deadline['ruleId']}")
                assert row is not None
                test.assertEqual(
                    row[5], deadline["dueAt"], f"{heading} {deadline['ruleId']} due"
                )
                test.assertEqual(
                    row[6],
                    "yes" if deadline["satisfied"] else "no",
                    f"{heading} {deadline['ruleId']} satisfied",
                )

    inputs = markdown_table_rows(markdown_section(markdown, "Inputs"), 4, "Artifact")
    artifacts = report.document["x-complyroll"]["artifacts"]
    test.assertEqual(len(inputs), len(artifacts))
    for artifact in artifacts:
        row = inputs.get(artifact["name"])
        test.assertIsNotNone(row, f"the Inputs table omits {artifact['name']}")
        assert row is not None
        test.assertEqual(row[2], f"{artifact['parser']} {artifact['parserVersion']}")


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

    def test_the_report_does_not_depend_on_how_artifacts_were_addressed(self) -> None:
        absolute = compile_vdt_report(
            [path.resolve() for path in ARTIFACTS],
            options=options(),
            evaluations=load_evaluations(EXAMPLES / "evaluations.json"),
        )

        self.assertEqual(absolute.to_json(), self.report.to_json())
        self.assertEqual(absolute.to_markdown(), self.report.to_markdown())
        self.assertNotIn(str(REPO_ROOT), absolute.to_json())

    def test_markdown_totals_reconcile_with_the_json(self) -> None:
        markdown = self.report.to_markdown()
        vulnerabilities = self.report.document["vulnerabilities"]
        summary = summary_counts(markdown)

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
        self.assertEqual(
            summary["Accepted, reported under VER-RPT-AVI"], len(self.report.accepted)
        )
        self.assertEqual(
            summary["Excluded by report period"],
            self.report.document["x-complyroll"]["excludedByPeriod"],
        )
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
            sorted(path.name for path in ARTIFACTS),
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


class GoldenAviReportTests(unittest.TestCase):
    """The AVI golden pins the Accepted Vulnerability Information projection's bytes.

    It is compiled from the same three fixtures as the VDT golden under
    `examples/evaluations-accepted.json`, which accepts the OpenSCAP banner rule, so
    exactly one record is accepted and the other five stay active.
    """

    ACTIVE_SOURCE_RECORDS = ("V-253260", "V-260469", "V-260470", "V-260474", "no_cci_mapping")

    @classmethod
    def setUpClass(cls) -> None:
        cls.evaluations = load_evaluations(ACCEPTED_EVALUATIONS)
        cls.report = compile_avi_report(
            list(ARTIFACTS), options=options(), evaluations=cls.evaluations
        )

    def test_json_matches_the_golden_byte_for_byte(self) -> None:
        expected = (GOLDEN / "avi-fixtures.json").read_text(encoding="utf-8")

        self.assertEqual(self.report.to_json(), expected)

    def test_markdown_matches_the_golden_byte_for_byte(self) -> None:
        expected = (GOLDEN / "avi-fixtures.md").read_text(encoding="utf-8")

        self.assertEqual(self.report.to_markdown(), expected)

    def test_compiling_twice_produces_identical_bytes(self) -> None:
        again = compile_avi_report(
            list(ARTIFACTS), options=options(), evaluations=load_evaluations(ACCEPTED_EVALUATIONS)
        )

        self.assertEqual(again.to_json(), self.report.to_json())
        self.assertEqual(again.to_markdown(), self.report.to_markdown())

    def test_compiled_document_satisfies_the_accepted_vulnerability_schema(self) -> None:
        schema_id = self.report.metadata.schema_provenance.schema_id

        self.assertTrue(self.report.validation.is_valid)
        self.assertEqual(self.report.validation.issues, ())
        self.assertTrue(
            schema_id.endswith("fedramp-accepted-vulnerability-info-schema-2026-06-24.json")
        )
        self.assertEqual(
            self.report.document["x-complyroll"]["schemaSource"]["schemaId"], schema_id
        )
        self.assertTrue(
            validate_bundled_report(
                ReportSchema.ACCEPTED_VULNERABILITY, self.report.document
            ).is_valid
        )

    def test_the_report_holds_the_banner_acceptance_and_counts_the_rest(self) -> None:
        document = self.report.document
        accepted = document["acceptedVulnerabilities"]
        extension = document["x-complyroll"]

        self.assertEqual(
            [item["vulnerabilityDetail"]["providerTrackingId"] for item in accepted],
            [BANNER_CASE],
        )
        self.assertEqual(
            accepted[0]["vulnerabilityDetail"]["x-complyroll"]["resources"],
            [{"resourceId": "lab-ubuntu-02", "resourceType": "host"}],
        )
        self.assertEqual(accepted[0]["acceptanceRationale"], BANNER_RATIONALE)
        self.assertNotIn("finalDisposition", accepted[0]["vulnerabilityDetail"])
        self.assertEqual(extension["excludedByPeriod"], 0)
        self.assertEqual(extension["activeNotReported"], 5)
        self.assertEqual(self.report.active_not_reported, 5)
        self.assertEqual(
            [item.vulnerability.tracking_id for item in self.report.accepted], [BANNER_CASE]
        )
        self.assertEqual(
            document["reportPeriod"],
            {"from": "2026-08-01T00:00:00Z", "to": "2026-08-31T23:59:59Z"},
        )

    def test_the_accepted_item_carries_only_the_two_official_members(self) -> None:
        item = find_accepted(self.report, "banner_etc_issue")

        self.assertEqual(set(item), {"vulnerabilityDetail", "acceptanceRationale"})
        self.assertIn("x-complyroll", item["vulnerabilityDetail"])

    def test_markdown_totals_reconcile_with_the_json(self) -> None:
        markdown = self.report.to_markdown()
        document = self.report.document
        accepted = official_records(self.report, "acceptedVulnerabilities")
        summary = summary_counts(markdown)
        table = markdown_table_rows(
            markdown_section(markdown, "Accepted vulnerabilities"), 11, "Tracking ID"
        )

        self.assertEqual(summary["Accepted vulnerabilities reported"], len(accepted))
        self.assertEqual(len(table), len(accepted))
        self.assertEqual(
            summary["Excluded by report period"], document["x-complyroll"]["excludedByPeriod"]
        )
        self.assertEqual(
            summary["Active, not reported here"], document["x-complyroll"]["activeNotReported"]
        )
        self.assertEqual(
            summary["Overdue"],
            sum(1 for item in accepted if item["overdueStatus"]["isOverdue"]),
        )
        for rating in range(1, 6):
            expected = sum(1 for item in accepted if item.get("currentRating") == rating)
            self.assertEqual(summary[f"Current PAIN N{rating}"], expected)
        self.assertIn("- **Report period:** 2026-08-01T00:00:00Z to 2026-08-31T23:59:59Z", markdown)

    def test_the_rationale_line_states_the_json_rationale(self) -> None:
        sections = markdown_detail_sections(
            self.report.to_markdown(), "Accepted vulnerability details"
        )
        rationale = find_accepted(self.report, "banner_etc_issue")["acceptanceRationale"]

        self.assertEqual(len(sections), 1)
        self.assertIn(f"- **Acceptance rationale:** {rationale}", sections[0][1])
        self.assertIn("- **Disposition:** accepted;", sections[0][1])

    def test_markdown_carries_the_json(self) -> None:
        assert_markdown_carries_the_json(self, self.report, sections=AVI_DETAIL_SECTIONS)

    def test_attestation_covers_only_the_reported_record(self) -> None:
        attestation = self.report.document["x-complyroll"]["detectionTimeAttestation"]

        self.assertEqual(
            attestation,
            {"detectedAt": "2026-08-01T00:00:00Z", "appliedTo": [BANNER_CASE], "count": 1},
        )
        self.assertIn(
            "attested a detection time of 2026-08-01T00:00:00Z for 1 vulnerability record(s)",
            self.report.to_markdown(),
        )

    def test_the_active_records_raise_no_diagnostic(self) -> None:
        record_set = compile_record_set_from_artifacts(
            list(ARTIFACTS), options=options(), evaluations=self.evaluations
        )

        self.assertEqual(self.report.diagnostics, record_set.diagnostics)
        self.assertEqual(
            [item.code for item in self.report.diagnostics], ["source_timestamp_missing"] * 3
        )
        for source_record_id in self.ACTIVE_SOURCE_RECORDS:
            with self.subTest(source_record_id=source_record_id):
                self.assertFalse(
                    [item for item in self.report.diagnostics if item.location == source_record_id]
                )


class GoldenHistoricalReportTests(unittest.TestCase):
    """The historical golden pins the periodless snapshot of the whole population."""

    @classmethod
    def setUpClass(cls) -> None:
        cls.evaluations = load_evaluations(ACCEPTED_EVALUATIONS)
        cls.report = compile_historical_report(
            list(ARTIFACTS),
            options=options(period_from=None, period_to=None),
            evaluations=cls.evaluations,
        )

    def test_json_matches_the_golden_byte_for_byte(self) -> None:
        expected = (GOLDEN / "historical-fixtures.json").read_text(encoding="utf-8")

        self.assertEqual(self.report.to_json(), expected)

    def test_markdown_matches_the_golden_byte_for_byte(self) -> None:
        expected = (GOLDEN / "historical-fixtures.md").read_text(encoding="utf-8")

        self.assertEqual(self.report.to_markdown(), expected)

    def test_compiling_twice_produces_identical_bytes(self) -> None:
        again = compile_historical_report(
            list(ARTIFACTS),
            options=options(period_from=None, period_to=None),
            evaluations=load_evaluations(ACCEPTED_EVALUATIONS),
        )

        self.assertEqual(again.to_json(), self.report.to_json())
        self.assertEqual(again.to_markdown(), self.report.to_markdown())

    def test_compiled_document_satisfies_the_historical_activity_schema(self) -> None:
        schema_id = self.report.metadata.schema_provenance.schema_id

        self.assertTrue(self.report.validation.is_valid)
        self.assertEqual(self.report.validation.issues, ())
        self.assertTrue(
            schema_id.endswith("fedramp-historical-ver-activity-schema-2026-06-24.json")
        )
        self.assertEqual(
            self.report.document["x-complyroll"]["schemaSource"]["schemaId"], schema_id
        )
        self.assertTrue(
            validate_bundled_report(ReportSchema.HISTORICAL_ACTIVITY, self.report.document).is_valid
        )

    def test_the_snapshot_holds_the_whole_population_in_record_order(self) -> None:
        document = self.report.document
        vdt = json.loads((GOLDEN / "vdt-fixtures.json").read_text(encoding="utf-8"))
        vdt_order = [item["providerTrackingId"] for item in vdt["vulnerabilities"]]

        self.assertEqual(
            [item["providerTrackingId"] for item in document["activeVulnerabilities"]],
            [value for value in vdt_order if value != BANNER_CASE],
        )
        self.assertEqual(
            [
                item["vulnerabilityDetail"]["providerTrackingId"]
                for item in document["acceptedVulnerabilities"]
            ],
            [BANNER_CASE],
        )
        self.assertEqual(document["generatedAt"], "2026-08-21T12:00:00Z")
        self.assertNotIn("reportPeriod", document)
        self.assertNotIn("excludedByPeriod", document["x-complyroll"])
        self.assertNotIn("activeNotReported", document["x-complyroll"])
        self.assertEqual(self.report.metadata.excluded_by_period, 0)

    def test_markdown_totals_reconcile_with_the_json(self) -> None:
        markdown = self.report.to_markdown()
        active = official_records(self.report, "activeVulnerabilities")
        accepted = official_records(self.report, "acceptedVulnerabilities")
        summary = summary_counts(markdown)
        evaluated = sum(1 for item in active if "evaluationCompletedAt" in item)

        self.assertEqual(summary["Active vulnerabilities"], len(active))
        self.assertEqual(summary["Accepted vulnerabilities"], len(accepted))
        self.assertEqual(summary["Evaluated"], evaluated)
        self.assertEqual(summary["Not yet evaluated"], len(active) - evaluated)
        self.assertEqual(
            summary["Overdue"], sum(1 for item in active if item["overdueStatus"]["isOverdue"])
        )
        for rating in range(1, 6):
            expected = sum(1 for item in active if item.get("currentRating") == rating)
            self.assertEqual(summary[f"Current PAIN N{rating}"], expected)
        active_table = markdown_table_rows(
            markdown_section(markdown, "Active vulnerabilities"), 11, "Tracking ID"
        )
        accepted_table = markdown_table_rows(
            markdown_section(markdown, "Accepted vulnerabilities"), 11, "Tracking ID"
        )
        self.assertEqual(len(active_table), len(active))
        self.assertEqual(len(accepted_table), len(accepted))
        self.assertNotIn("Report period", markdown)
        self.assertIn("- **Generated at:** 2026-08-21T12:00:00Z", markdown)

    def test_the_rationale_line_states_the_json_rationale(self) -> None:
        sections = markdown_detail_sections(
            self.report.to_markdown(), "Accepted vulnerability details"
        )
        rationale = find_accepted(self.report, "banner_etc_issue")["acceptanceRationale"]

        self.assertEqual(len(sections), 1)
        self.assertIn(f"- **Acceptance rationale:** {rationale}", sections[0][1])
        active_sections = markdown_detail_sections(
            self.report.to_markdown(), "Active vulnerability details"
        )
        self.assertEqual(len(active_sections), 5)
        self.assertFalse(any("Acceptance rationale" in body for _, body in active_sections))

    def test_markdown_carries_the_json(self) -> None:
        assert_markdown_carries_the_json(self, self.report, sections=HISTORICAL_DETAIL_SECTIONS)

    def test_attestation_covers_every_record(self) -> None:
        attestation = self.report.document["x-complyroll"]["detectionTimeAttestation"]
        every_id = sorted(
            [item.tracking_id for item in self.report.active]
            + [item.vulnerability.tracking_id for item in self.report.accepted]
        )

        self.assertEqual(attestation["detectedAt"], "2026-08-01T00:00:00Z")
        self.assertEqual(attestation["appliedTo"], every_id)
        self.assertEqual(attestation["count"], 6)
        self.assertIn("for 6 vulnerability record(s)", self.report.to_markdown())

    def test_no_selection_diagnostics_are_appended(self) -> None:
        record_set = compile_record_set_from_artifacts(
            list(ARTIFACTS), options=options(), evaluations=self.evaluations
        )

        self.assertEqual(self.report.diagnostics, record_set.diagnostics)
        self.assertEqual(
            [item.code for item in self.report.diagnostics], ["source_timestamp_missing"] * 3
        )


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
            CaseStatus.REMEDIATED: "Remediated",
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
        self.assertIn("58487bda77d76d9ce334304ec2e779ece7cc7d54", status["explanation"])

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


class ReportPeriodSelectionTests(unittest.TestCase):
    """The report period selects contents; it is not a label (ADR 0007 amendment)."""

    def test_a_vulnerability_detected_after_the_period_end_is_excluded(self) -> None:
        report = compile_fixtures(
            detected_at=datetime(2026, 9, 15, tzinfo=AS_OF.tzinfo),
            as_of=datetime(2026, 9, 20, tzinfo=AS_OF.tzinfo),
        )

        self.assertEqual(report.document["vulnerabilities"], [])
        self.assertEqual(report.document["x-complyroll"]["excludedByPeriod"], 6)
        excluded = [item for item in report.diagnostics if item.code == "excluded_by_period"]
        self.assertEqual(len(excluded), 6)
        self.assertIn("after the period ended", excluded[0].message)
        self.assertTrue(excluded[0].message.startswith("case-"))

    def test_a_vulnerability_detected_inside_the_period_is_included(self) -> None:
        report = compile_fixtures(detected_at=datetime(2026, 8, 15, tzinfo=AS_OF.tzinfo))

        self.assertEqual(len(report.document["vulnerabilities"]), 6)
        self.assertEqual(report.document["x-complyroll"]["excludedByPeriod"], 0)

    def test_an_undisposed_vulnerability_detected_before_the_period_is_included(self) -> None:
        report = compile_fixtures(detected_at=datetime(2026, 6, 1, tzinfo=AS_OF.tzinfo))

        self.assertEqual(len(report.document["vulnerabilities"]), 6)
        self.assertEqual(report.document["x-complyroll"]["excludedByPeriod"], 0)

    def test_a_disposed_vulnerability_with_activity_only_before_the_period_is_excluded(
        self,
    ) -> None:
        report = compile_fixtures(
            detected_at=datetime(2026, 7, 1, tzinfo=AS_OF.tzinfo),
            evaluations=evaluations_from(
                completedAt="2026-07-05T00:00:00Z", disposition="fully_mitigated"
            ),
        )

        descriptions = [
            item["vulnerabilityDescription"] for item in report.document["vulnerabilities"]
        ]
        self.assertEqual(len(descriptions), 5)
        self.assertFalse(any(text.startswith("V-260470") for text in descriptions))
        self.assertEqual(report.document["x-complyroll"]["excludedByPeriod"], 1)
        excluded = [item for item in report.diagnostics if item.code == "excluded_by_period"]
        self.assertEqual(len(excluded), 1)
        # The detail report leaves the helper's `state` unset, so its message names the
        # disposition; ADR 0010 moves that wording behind a parameter and must not change it.
        self.assertIn(
            "has disposition 'Fully Mitigated' and no recorded activity between",
            excluded[0].message,
        )
        self.assertNotIn("None", excluded[0].message)

    def test_a_disposed_vulnerability_with_activity_inside_the_period_is_included(self) -> None:
        report = compile_fixtures(
            detected_at=datetime(2026, 7, 1, tzinfo=AS_OF.tzinfo),
            evaluations=evaluations_from(
                completedAt="2026-08-05T00:00:00Z", disposition="fully_mitigated"
            ),
        )

        self.assertEqual(len(report.document["vulnerabilities"]), 6)
        self.assertEqual(report.document["x-complyroll"]["excludedByPeriod"], 0)

    def test_a_pain_reduction_event_inside_the_period_keeps_a_disposed_record(self) -> None:
        report = compile_fixtures(
            detected_at=datetime(2026, 7, 1, tzinfo=AS_OF.tzinfo),
            evaluations=evaluations_from(
                completedAt="2026-07-05T00:00:00Z",
                disposition="fully_mitigated",
                painReductionEvents=[{"reducedAt": "2026-08-10T00:00:00Z", "rating": 2}],
            ),
        )

        self.assertEqual(len(report.document["vulnerabilities"]), 6)
        self.assertEqual(report.document["x-complyroll"]["excludedByPeriod"], 0)

    def test_a_projected_reduction_inside_the_period_keeps_a_disposed_record(self) -> None:
        report = compile_fixtures(
            detected_at=datetime(2026, 7, 1, tzinfo=AS_OF.tzinfo),
            evaluations=evaluations_from(
                completedAt="2026-07-05T00:00:00Z",
                disposition="partially_mitigated",
                projectedNextReduction={
                    "estimatedAt": "2026-08-20T00:00:00Z",
                    "targetRating": 2,
                },
            ),
        )

        self.assertEqual(len(report.document["vulnerabilities"]), 6)

    def test_both_period_bounds_are_inclusive(self) -> None:
        at_end = compile_fixtures(detected_at=PERIOD_TO, as_of=datetime(2026, 9, 5, tzinfo=UTC))
        at_start = compile_fixtures(
            detected_at=datetime(2026, 7, 1, tzinfo=UTC),
            evaluations=evaluations_from(
                completedAt="2026-08-01T00:00:00Z", disposition="fully_mitigated"
            ),
        )

        self.assertEqual(len(at_end.document["vulnerabilities"]), 6)
        self.assertEqual(at_end.document["x-complyroll"]["excludedByPeriod"], 0)
        self.assertEqual(len(at_start.document["vulnerabilities"]), 6)
        self.assertEqual(at_start.document["x-complyroll"]["excludedByPeriod"], 0)

    def test_an_excluded_record_does_not_appear_in_the_attestation_list(self) -> None:
        report = compile_fixtures(
            detected_at=datetime(2026, 9, 15, tzinfo=AS_OF.tzinfo),
            as_of=datetime(2026, 9, 20, tzinfo=AS_OF.tzinfo),
        )

        self.assertIsNone(report.document["x-complyroll"]["detectionTimeAttestation"])


class AviPeriodSelectionTests(unittest.TestCase):
    """The AVI applies the detail report's period predicate to accepted records.

    The default evaluation entry matches V-260470, detected 2026-08-01 under the test
    attestation and evaluated 2026-08-04, so a period over August holds both instants
    and one over September holds neither unless a later reduction lands in it.
    """

    SEPTEMBER = {
        "period_from": datetime(2026, 9, 1, tzinfo=UTC),
        "period_to": datetime(2026, 9, 30, 23, 59, 59, tzinfo=UTC),
        "as_of": datetime(2026, 10, 1, tzinfo=UTC),
    }
    JULY = {
        "period_from": datetime(2026, 7, 1, tzinfo=UTC),
        "period_to": datetime(2026, 7, 31, 23, 59, 59, tzinfo=UTC),
    }

    def test_an_accepted_record_with_activity_in_the_period_is_reported(self) -> None:
        report = compile_fixtures(kind="avi", evaluations=evaluations_from(**ACCEPTANCE))
        extension = report.document["x-complyroll"]

        self.assertEqual(
            [item.vulnerability.source_record_id for item in report.accepted], ["V-260470"]
        )
        self.assertEqual(extension["excludedByPeriod"], 0)
        self.assertEqual(extension["activeNotReported"], 5)
        self.assertEqual(find_accepted(report, "V-260470")["acceptanceRationale"], str(
            ACCEPTANCE["acceptanceRationale"]
        ))

    def test_an_accepted_record_with_no_activity_in_the_period_is_excluded(self) -> None:
        report = compile_fixtures(
            kind="avi", evaluations=evaluations_from(**ACCEPTANCE), **self.SEPTEMBER
        )
        excluded = [item for item in report.diagnostics if item.code == "excluded_by_period"]

        self.assertEqual(report.document["acceptedVulnerabilities"], [])
        self.assertEqual(report.document["x-complyroll"]["excludedByPeriod"], 1)
        self.assertEqual(report.document["x-complyroll"]["activeNotReported"], 5)
        self.assertEqual(len(excluded), 1)
        self.assertIn("is accepted and no recorded activity between", excluded[0].message)
        self.assertNotIn("None", excluded[0].message)
        self.assertTrue(excluded[0].message.startswith("case-"))
        self.assertEqual(excluded[0].location, "V-260470")
        self.assertIn(
            "No accepted vulnerabilities had recorded activity in this period.",
            report.to_markdown(),
        )

    def test_an_accepted_record_detected_after_the_period_is_excluded(self) -> None:
        report = compile_fixtures(
            kind="avi", evaluations=evaluations_from(**ACCEPTANCE), **self.JULY
        )
        excluded = [item for item in report.diagnostics if item.code == "excluded_by_period"]

        self.assertEqual(report.document["acceptedVulnerabilities"], [])
        self.assertEqual(len(excluded), 1)
        self.assertIn("after the period ended 2026-07-31T23:59:59Z", excluded[0].message)

    def test_a_pain_reduction_inside_the_period_keeps_an_accepted_record(self) -> None:
        report = compile_fixtures(
            kind="avi",
            evaluations=evaluations_from(
                painReductionEvents=[{"reducedAt": "2026-09-10T00:00:00Z", "rating": 2}],
                **ACCEPTANCE,
            ),
            **self.SEPTEMBER,
        )

        self.assertEqual(len(report.document["acceptedVulnerabilities"]), 1)
        self.assertEqual(report.document["x-complyroll"]["excludedByPeriod"], 0)

    def test_a_projected_reduction_inside_the_period_keeps_an_accepted_record(self) -> None:
        report = compile_fixtures(
            kind="avi",
            evaluations=evaluations_from(
                projectedNextReduction={
                    "estimatedAt": "2026-09-20T00:00:00Z",
                    "targetRating": 2,
                },
                **ACCEPTANCE,
            ),
            **self.SEPTEMBER,
        )

        self.assertEqual(len(report.document["acceptedVulnerabilities"]), 1)
        self.assertEqual(report.document["x-complyroll"]["excludedByPeriod"], 0)

    def test_the_activity_instants_are_exactly_the_four_the_module_names(self) -> None:
        report = compile_fixtures(
            kind="avi",
            evaluations=evaluations_from(
                painReductionEvents=[{"reducedAt": "2026-09-10T00:00:00Z", "rating": 2}],
                projectedNextReduction={
                    "estimatedAt": "2026-09-20T00:00:00Z",
                    "targetRating": 1,
                },
                **ACCEPTANCE,
            ),
            **self.SEPTEMBER,
        )

        self.assertEqual(
            report.accepted[0].vulnerability.activity_instants,
            (
                DETECTED_AT,
                datetime(2026, 8, 4, 12, 0, tzinfo=UTC),
                datetime(2026, 9, 10, tzinfo=UTC),
                datetime(2026, 9, 20, tzinfo=UTC),
            ),
        )


class HistoricalSelectionTests(unittest.TestCase):
    """The historical snapshot publishes every record and selects nothing."""

    def test_a_closed_record_stays_in_the_active_array_with_its_disposition(self) -> None:
        report = compile_fixtures(
            kind="historical",
            evaluations=evaluations_from(disposition="closed", closedDisposition="fully_mitigated"),
        )
        closed = find_vulnerability(report, "V-260470", key="activeVulnerabilities")

        self.assertEqual(len(report.document["activeVulnerabilities"]), 6)
        self.assertEqual(report.document["acceptedVulnerabilities"], [])
        self.assertEqual(closed["finalDisposition"], "Fully Mitigated")

    def test_an_accepted_record_moves_to_the_accepted_array(self) -> None:
        report = compile_fixtures(kind="historical", evaluations=evaluations_from(**ACCEPTANCE))
        item = find_accepted(report, "V-260470")

        self.assertEqual(len(report.document["activeVulnerabilities"]), 5)
        self.assertEqual(len(report.document["acceptedVulnerabilities"]), 1)
        self.assertEqual(item["acceptanceRationale"], ACCEPTANCE["acceptanceRationale"])
        self.assertFalse(
            any(
                str(entry["vulnerabilityDescription"]).startswith("V-260470")
                for entry in report.document["activeVulnerabilities"]
            )
        )

    def test_a_far_as_of_drops_nothing(self) -> None:
        report = compile_fixtures(
            kind="historical",
            evaluations=evaluations_from(**ACCEPTANCE),
            as_of=datetime(2027, 6, 1, tzinfo=UTC),
        )

        self.assertEqual(
            len(report.document["activeVulnerabilities"])
            + len(report.document["acceptedVulnerabilities"]),
            6,
        )
        self.assertEqual(report.document["generatedAt"], "2027-06-01T00:00:00Z")

    def test_as_of_decides_the_overdue_status_of_every_record(self) -> None:
        early = compile_fixtures(
            kind="historical",
            as_of=datetime(2026, 8, 3, tzinfo=UTC),
            period_from=None,
            period_to=None,
        )
        late = compile_fixtures(kind="historical", period_from=None, period_to=None)

        self.assertFalse(
            find_vulnerability(early, "V-260469", key="activeVulnerabilities")["overdueStatus"][
                "isOverdue"
            ]
        )
        self.assertTrue(
            find_vulnerability(late, "V-260469", key="activeVulnerabilities")["overdueStatus"][
                "isOverdue"
            ]
        )

    def test_a_period_on_the_options_changes_nothing(self) -> None:
        with_period = compile_fixtures(
            kind="historical", evaluations=evaluations_from(**ACCEPTANCE)
        )
        without_period = compile_fixtures(
            kind="historical",
            evaluations=evaluations_from(**ACCEPTANCE),
            period_from=None,
            period_to=None,
        )

        self.assertEqual(without_period.to_json(), with_period.to_json())
        self.assertEqual(without_period.to_markdown(), with_period.to_markdown())
        self.assertNotIn("Report period", with_period.to_markdown())


class TrackingIdUniquenessTests(unittest.TestCase):
    def test_two_overrides_to_one_identifier_are_refused(self) -> None:
        payload = json.loads(evaluation_json(trackingId="PROVIDER-1"))
        second = dict(payload["evaluations"][0])
        second["match"] = {"sourceRecordId": "V-253260", "sourceType": "ckl"}
        payload["evaluations"].append(second)
        evaluations = parse_evaluations(json.dumps(payload).encode("utf-8"))

        with self.assertRaises(ReportCompileError) as caught:
            compile_fixtures(evaluations=evaluations)

        diagnostic = caught.exception.diagnostics[0]
        self.assertEqual(diagnostic.code, "tracking_id_collision")
        self.assertIn("PROVIDER-1", diagnostic.message)
        self.assertIn("evaluations[0]", diagnostic.message)
        self.assertIn("evaluations[1]", diagnostic.message)
        self.assertIn("case-490f49bfdd1bd019", diagnostic.message)
        self.assertIn("case-1f3e011db93cc89e", diagnostic.message)

    def test_an_override_onto_an_unevaluated_natural_identifier_is_refused(self) -> None:
        evaluations = evaluations_from(trackingId="case-9bed0d8f88355393")

        with self.assertRaises(ReportCompileError) as caught:
            compile_fixtures(evaluations=evaluations)

        self.assertEqual(caught.exception.diagnostics[0].code, "tracking_id_collision")
        self.assertIn("no evaluation entry", caught.exception.diagnostics[0].message)

    def test_distinct_overrides_are_accepted(self) -> None:
        payload = json.loads(evaluation_json(trackingId="PROVIDER-1"))
        second = dict(payload["evaluations"][0])
        second["match"] = {"sourceRecordId": "V-253260", "sourceType": "ckl"}
        second["trackingId"] = "PROVIDER-2"
        payload["evaluations"].append(second)
        evaluations = parse_evaluations(json.dumps(payload).encode("utf-8"))

        report = compile_fixtures(evaluations=evaluations)
        identifiers = {
            item["providerTrackingId"] for item in report.document["vulnerabilities"]
        }

        self.assertIn("PROVIDER-1", identifiers)
        self.assertIn("PROVIDER-2", identifiers)


class DetectionAttestationTests(unittest.TestCase):
    """A per-case attestation wins over the default, and both stay optional.

    The persisted path reads one instant per case out of `detection.attested` events
    while the stateless path has only `--detected-at`, so this resolution order is the
    seam where the two paths could disagree (ADR 0008 amendment).
    """

    FIRST_CASE = "case-00000000000000a1"
    SECOND_CASE = "case-00000000000000a2"
    PER_CASE = datetime(2026, 7, 15, 8, 0, tzinfo=UTC)

    def test_a_per_case_instant_wins_over_the_default(self) -> None:
        attestation = DetectionAttestation(
            default=DETECTED_AT,
            by_tracking_id={self.FIRST_CASE: self.PER_CASE},
        )

        self.assertEqual(attestation.for_tracking_id(self.FIRST_CASE), self.PER_CASE)

    def test_a_case_the_map_does_not_name_falls_back_to_the_default(self) -> None:
        attestation = DetectionAttestation(
            default=DETECTED_AT,
            by_tracking_id={self.FIRST_CASE: self.PER_CASE},
        )

        self.assertEqual(attestation.for_tracking_id(self.SECOND_CASE), DETECTED_AT)

    def test_a_per_case_instant_applies_without_any_default(self) -> None:
        attestation = DetectionAttestation(by_tracking_id={self.FIRST_CASE: self.PER_CASE})

        self.assertEqual(attestation.for_tracking_id(self.FIRST_CASE), self.PER_CASE)
        self.assertIsNone(attestation.for_tracking_id(self.SECOND_CASE))

    def test_an_empty_attestation_applies_to_nothing(self) -> None:
        self.assertIsNone(DetectionAttestation().for_tracking_id(self.FIRST_CASE))


class PartialTimestampTests(unittest.TestCase):
    def _compile(self, **overrides: object) -> CompiledVdtReport:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "mixed-timestamps.xml"
            path.write_text(MIXED_TIMESTAMP_XCCDF, encoding="utf-8")
            return compile_fixtures(artifacts=(path,), **overrides)

    def test_the_earliest_known_timestamp_is_the_detection_time(self) -> None:
        report = self._compile()
        vulnerability = report.document["vulnerabilities"][0]

        self.assertEqual(len(report.document["vulnerabilities"]), 1)
        self.assertEqual(vulnerability["detection"]["detectedAt"], "2026-08-03T09:00:00Z")
        self.assertEqual(vulnerability["x-complyroll"]["detectedAtSource"], "artifact-partial")
        self.assertEqual(len(vulnerability["x-complyroll"]["resources"]), 2)

    def test_the_untimestamped_observations_are_named(self) -> None:
        report = self._compile()
        untimestamped = report.document["vulnerabilities"][0]["x-complyroll"][
            "untimestampedObservationIds"
        ]

        self.assertEqual(len(untimestamped), 1)
        self.assertIn(untimestamped[0], report.document["vulnerabilities"][0]["x-complyroll"][
            "observationIds"
        ])

    def test_the_markdown_lists_every_observation_and_marks_the_untimestamped(self) -> None:
        # The JSON extension names both the whole group and the members that declared
        # no time; a detail section that named only the untimestamped ones dropped the
        # observation the detection time actually came from.
        report = self._compile()
        extension = report.document["vulnerabilities"][0]["x-complyroll"]
        untimestamped = extension["untimestampedObservationIds"]
        rendered = ", ".join(
            f"{value} (no source timestamp)" if value in untimestamped else value
            for value in extension["observationIds"]
        )

        self.assertEqual(len(extension["observationIds"]), 2)
        self.assertEqual(len(untimestamped), 1)
        self.assertIn(f"- **Observations:** {rendered}", report.to_markdown())

    def test_a_partly_timestamped_group_renders_the_same_facts_in_both_forms(self) -> None:
        assert_markdown_carries_the_json(self, self._compile())

    def test_a_partial_group_raises_a_warning(self) -> None:
        report = self._compile()
        partial = [item for item in report.diagnostics if item.code == "detection_time_partial"]

        self.assertEqual(len(partial), 1)
        self.assertEqual(partial[0].level.value, "warning")
        self.assertIn("declare no source timestamp", partial[0].message)

    def test_an_attestation_never_overrides_a_known_source_timestamp(self) -> None:
        report = self._compile(detected_at=datetime(2026, 1, 1, tzinfo=UTC))
        vulnerability = report.document["vulnerabilities"][0]

        self.assertEqual(vulnerability["detection"]["detectedAt"], "2026-08-03T09:00:00Z")
        self.assertIsNone(report.document["x-complyroll"]["detectionTimeAttestation"])

    def test_a_per_case_attestation_never_overrides_a_source_timestamp(self) -> None:
        # The persisted path can attest one case at a time, so the rule the stateless
        # `--detected-at` obeys has to hold for a named case too: the earliest known
        # source time wins, and the attestation covers nothing.
        result = ingest_text(MIXED_TIMESTAMP_XCCDF, "mixed-timestamps.xml")
        groups = group_open_observations(result.observations)
        self.assertEqual(len(groups), 1)

        report = compile_records(
            artifacts=(compiled_artifact(result),),
            observations=result.observations,
            ingest_diagnostics=(),
            evaluations_by_tracking_id={},
            attestation=DetectionAttestation(
                by_tracking_id={groups[0].tracking_id: datetime(2026, 1, 1, tzinfo=UTC)}
            ),
            options=options(detected_at=None),
        )
        vulnerability = report.document["vulnerabilities"][0]

        self.assertEqual(len(report.document["vulnerabilities"]), 1)
        self.assertEqual(vulnerability["detection"]["detectedAt"], "2026-08-03T09:00:00Z")
        self.assertEqual(vulnerability["x-complyroll"]["detectedAtSource"], "artifact-partial")
        self.assertIsNone(report.document["x-complyroll"]["detectionTimeAttestation"])

    def test_a_fully_timestamped_group_reports_no_untimestamped_observations(self) -> None:
        fully_timed = MIXED_TIMESTAMP_XCCDF.replace(
            '<TestResult id="shared">',
            '<TestResult id="shared" end-time="2026-08-04T09:00:00Z">',
        )
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "timed.xml"
            path.write_text(fully_timed, encoding="utf-8")
            report = compile_fixtures(artifacts=(path,))

        extension = report.document["vulnerabilities"][0]["x-complyroll"]
        self.assertEqual(extension["untimestampedObservationIds"], [])
        self.assertEqual(extension["detectedAtSource"], "artifact")
        self.assertEqual(
            [item.code for item in report.diagnostics if item.code == "detection_time_partial"],
            [],
        )
        self.assertIn(
            "- **Observations:** " + ", ".join(extension["observationIds"]),
            report.to_markdown(),
        )
        assert_markdown_carries_the_json(self, report)


class ClosedAsAcceptedTests(unittest.TestCase):
    def test_a_case_closed_as_accepted_leaves_the_detail_report(self) -> None:
        report = compile_fixtures(
            evaluations=evaluations_from(
                disposition="closed",
                closedDisposition="accepted",
                acceptanceRationale="Risk accepted under SDR-22 with quarterly review.",
            )
        )

        descriptions = [
            item["vulnerabilityDescription"] for item in report.document["vulnerabilities"]
        ]
        self.assertFalse(any(text.startswith("V-260470") for text in descriptions))
        self.assertEqual(len(report.accepted), 1)
        self.assertIn("SDR-22", report.accepted[0].acceptance_rationale)

    def test_closing_as_accepted_requires_an_acceptance_rationale(self) -> None:
        payload = evaluation_json(disposition="closed", closedDisposition="accepted")
        with self.assertRaisesRegex(ReportInputError, "acceptanceRationale is required"):
            parse_evaluations(payload.encode("utf-8"))

    def test_an_acceptance_rationale_without_acceptance_is_refused(self) -> None:
        payload = evaluation_json(
            disposition="closed",
            closedDisposition="remediated",
            acceptanceRationale="Not applicable here.",
        )
        with self.assertRaisesRegex(ReportInputError, "only valid when the case accepts risk"):
            parse_evaluations(payload.encode("utf-8"))


class AcceptanceRationaleGuardTests(unittest.TestCase):
    """The AVI and historical items require a rationale the parser cannot omit.

    `parse_evaluations` refuses an acceptance without a rationale, so the only way to
    reach the projections with one missing is a record set built elsewhere. The tests
    rewrite the parsed record's evaluation to stand in for that source.
    """

    def accepted_record_set(self, evaluations: EvaluationSet | None = None) -> CompiledRecordSet:
        return compile_record_set_from_artifacts(
            list(ARTIFACTS),
            options=options(),
            evaluations=evaluations or evaluations_from(**ACCEPTANCE),
        )

    def without_rationale(
        self, record_set: CompiledRecordSet, rationale: str | None
    ) -> CompiledRecordSet:
        records = []
        for record in record_set.records:
            evaluation = record.evaluation
            if record.status is not CaseStatus.ACCEPTED or evaluation is None:
                records.append(record)
                continue
            records.append(
                replace(record, evaluation=replace(evaluation, acceptance_rationale=rationale))
            )
        return replace(record_set, records=tuple(records))

    def test_the_avi_refuses_an_accepted_record_with_a_blank_rationale(self) -> None:
        record_set = self.without_rationale(self.accepted_record_set(), "   ")

        with self.assertRaises(ReportCompileError) as caught:
            project_avi(record_set)

        diagnostics = caught.exception.diagnostics
        self.assertEqual(len(diagnostics), 1)
        self.assertEqual(diagnostics[0].code, "acceptance_rationale_missing")
        self.assertEqual(diagnostics[0].level, DiagnosticLevel.ERROR)
        self.assertTrue(diagnostics[0].message.startswith("case-"))
        self.assertIn(
            "is accepted but its evaluation records no acceptance", diagnostics[0].message
        )
        self.assertEqual(diagnostics[0].location, "V-260470")

    def test_the_historical_snapshot_refuses_an_accepted_record_with_no_rationale(self) -> None:
        record_set = self.without_rationale(self.accepted_record_set(), None)

        with self.assertRaises(ReportCompileError) as caught:
            project_historical(record_set)

        diagnostics = caught.exception.diagnostics
        self.assertEqual([item.code for item in diagnostics], ["acceptance_rationale_missing"])
        self.assertEqual(diagnostics[0].location, "V-260470")

    def test_every_missing_rationale_is_named_in_record_order(self) -> None:
        record_set = self.without_rationale(
            self.accepted_record_set(
                evaluations_for(dict(ACCEPTANCE), {"match": BANNER_MATCH, **ACCEPTANCE})
            ),
            "",
        )
        accepted = [
            item.source_record_id
            for item in record_set.records
            if item.status is CaseStatus.ACCEPTED
        ]

        self.assertEqual(len(accepted), 2)
        for project in (project_avi, project_historical):
            with self.subTest(projection=project.__name__):
                with self.assertRaises(ReportCompileError) as caught:
                    project(record_set)

                self.assertEqual(
                    [item.location for item in caught.exception.diagnostics], accepted
                )

    def test_the_detail_report_still_compiles_without_a_rationale(self) -> None:
        record_set = self.without_rationale(self.accepted_record_set(), None)

        report = project_vdt(record_set)

        self.assertEqual(len(report.accepted), 1)
        self.assertEqual(report.accepted[0].acceptance_rationale, "")
        self.assertIn("accepted_excluded", [item.code for item in report.diagnostics])


class RenderingParityTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.report = compile_vdt_report(
            list(ARTIFACTS),
            options=options(),
            evaluations=load_evaluations(EXAMPLES / "evaluations.json"),
        )

    def test_every_vulnerability_has_a_markdown_detail_section(self) -> None:
        markdown = self.report.to_markdown()
        headings = re.findall(r"^### (\S+): ", markdown, re.M)

        self.assertEqual(
            headings,
            [item["providerTrackingId"] for item in self.report.document["vulnerabilities"]],
        )

    def test_the_detail_sections_carry_the_json_audit_material(self) -> None:
        markdown = self.report.to_markdown()

        for vulnerability in self.report.document["vulnerabilities"]:
            extension = vulnerability["x-complyroll"]
            with self.subTest(tracking=vulnerability["providerTrackingId"]):
                self.assertIn(extension["detectedAtSource"], markdown)
                for deadline in extension["deadlines"]:
                    self.assertIn(deadline["ruleName"], markdown)
                    self.assertIn(deadline["dueAt"], markdown)
                for resource in extension["resources"]:
                    self.assertIn(resource["resourceId"], markdown)
                if extension["rationale"]:
                    self.assertIn(extension["rationale"], markdown)
                if extension["evaluator"]:
                    self.assertIn(extension["evaluator"], markdown)

    def test_the_markdown_twin_states_every_fact_the_json_carries(self) -> None:
        assert_markdown_carries_the_json(self, self.report)

    def test_every_compiled_deadline_publishes_whether_it_is_satisfied(self) -> None:
        # The Markdown twin printed a Satisfied column the JSON extension had no field
        # for, so a machine reader could not tell a met clock from a missed one.
        deadlines = [
            deadline
            for item in self.report.document["vulnerabilities"]
            for deadline in item["x-complyroll"]["deadlines"]
        ]

        self.assertEqual(len(deadlines), 10)
        for deadline in deadlines:
            self.assertIn("satisfied", deadline, deadline["ruleId"])
            self.assertIsInstance(deadline["satisfied"], bool)

    def test_the_json_satisfied_value_states_the_clock_it_describes(self) -> None:
        satisfied = {
            (item["providerTrackingId"], deadline["ruleId"]): deadline["satisfied"]
            for item in self.report.document["vulnerabilities"]
            for deadline in item["x-complyroll"]["deadlines"]
        }

        # An evaluated case satisfies its evaluation clock; a case with a recorded
        # disposition satisfies its response and acceptance clocks; a case with neither
        # satisfies nothing.
        self.assertTrue(satisfied[("case-1f3e011db93cc89e", "VER-TFR-EVU")])
        self.assertTrue(satisfied[("case-1f3e011db93cc89e", "VDR-TFR-PVR")])
        self.assertTrue(satisfied[("case-1f3e011db93cc89e", "VER-TFR-MAV")])
        self.assertTrue(satisfied[("case-490f49bfdd1bd019", "VER-TFR-EVU")])
        self.assertFalse(satisfied[("case-490f49bfdd1bd019", "VDR-TFR-PVR")])
        self.assertFalse(satisfied[("case-9bed0d8f88355393", "VER-TFR-EVU")])

    def test_a_report_with_no_evaluations_still_renders_both_forms_alike(self) -> None:
        report = compile_fixtures()

        assert_markdown_carries_the_json(self, report)
        self.assertTrue(
            all(
                deadline["satisfied"] is False
                for item in report.document["vulnerabilities"]
                for deadline in item["x-complyroll"]["deadlines"]
            )
        )

    def test_the_extension_carries_the_compile_diagnostics(self) -> None:
        extension = self.report.document["x-complyroll"]

        self.assertEqual(
            extension["diagnostics"],
            [item.to_dict() for item in self.report.diagnostics],
        )
        self.assertTrue(extension["diagnostics"])

    def test_every_artifact_reports_its_observation_count(self) -> None:
        """Counts are listed in manifest order, which is by name, not by argument."""

        artifacts = self.report.document["x-complyroll"]["artifacts"]

        self.assertEqual(
            [(item["name"], item["observationCount"]) for item in artifacts],
            [
                ("openscap-results.xml", 3),
                ("ubuntu-host.cklb", 6),
                ("windows-host.ckl", 2),
            ],
        )
        self.assertEqual(
            sum(item["observationCount"] for item in artifacts),
            sum(item.observation_count for item in self.report.metadata.artifacts),
        )

    def test_the_attestation_count_matches_the_markdown_note(self) -> None:
        attestation = self.report.document["x-complyroll"]["detectionTimeAttestation"]
        markdown = self.report.to_markdown()

        self.assertEqual(attestation["count"], len(attestation["appliedTo"]))
        self.assertIn(
            f"for {attestation['count']} vulnerability record(s)",
            markdown,
        )


class TimestampAndBoundsTests(unittest.TestCase):
    def test_a_non_utc_offset_is_normalized_to_utc(self) -> None:
        report = compile_fixtures(
            evaluations=evaluations_from(completedAt="2026-08-04T05:00:00-07:00")
        )

        self.assertEqual(
            find_vulnerability(report, "V-260470")["evaluationCompletedAt"],
            "2026-08-04T12:00:00Z",
        )

    def test_offsets_are_preserved_across_every_timestamp_field(self) -> None:
        report = compile_fixtures(
            evaluations=evaluations_from(
                completedAt="2026-08-04T05:00:00-07:00",
                projectedNextReduction={
                    "estimatedAt": "2026-08-24T09:00:00+02:00",
                    "targetRating": 2,
                },
                painReductionEvents=[{"reducedAt": "2026-08-10T21:30:00+05:30", "rating": 3}],
            )
        )
        vulnerability = find_vulnerability(report, "V-260470")

        self.assertEqual(
            vulnerability["projectedNextReduction"]["estimatedAt"], "2026-08-24T07:00:00Z"
        )
        self.assertEqual(
            vulnerability["painReductionEvents"][0]["reducedAt"],
            "2026-08-10T16:00:00Z",
        )

    def test_a_file_at_exactly_the_byte_limit_is_accepted(self) -> None:
        prefix = b'{"evaluations": [], "$schema": "'
        suffix = b'"}'
        padding = MAX_EVALUATIONS_BYTES - len(prefix) - len(suffix)
        content = prefix + (b"x" * padding) + suffix

        self.assertEqual(len(content), MAX_EVALUATIONS_BYTES)
        self.assertEqual(parse_evaluations(content).entries, ())

    def test_one_byte_over_the_limit_is_refused(self) -> None:
        prefix = b'{"evaluations": [], "$schema": "'
        suffix = b'"}'
        padding = MAX_EVALUATIONS_BYTES - len(prefix) - len(suffix) + 1
        content = prefix + (b"x" * padding) + suffix

        self.assertEqual(len(content), MAX_EVALUATIONS_BYTES + 1)
        with self.assertRaisesRegex(ReportInputError, "maximum is"):
            parse_evaluations(content)

    def test_an_oversize_file_on_disk_is_refused_before_it_is_read(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "evaluations.json"
            path.write_bytes(b"x" * (MAX_EVALUATIONS_BYTES + 1))

            with self.assertRaisesRegex(ReportInputError, "maximum is"):
                load_evaluations(path)


class RecordSetTests(unittest.TestCase):
    """The Vulnerability Detail Report is one projection of the shared record set."""

    ACCEPTED_RATIONALE = "Accepted under change record CR-102 pending the template refresh."

    def test_the_stateless_report_is_the_projection_of_its_record_set(self) -> None:
        evaluations = load_evaluations(EXAMPLES / "evaluations.json")
        report = compile_vdt_report(list(ARTIFACTS), options=options(), evaluations=evaluations)
        record_set = compile_record_set_from_artifacts(
            list(ARTIFACTS), options=options(), evaluations=evaluations
        )
        projected = project_vdt(record_set)

        self.assertEqual(projected.to_json(), report.to_json())
        self.assertEqual(projected.to_markdown(), report.to_markdown())

    def test_compile_records_is_the_projection_of_compile_record_set(self) -> None:
        results = [ingest_stig_artifact(path, ingested_at=AS_OF) for path in ARTIFACTS]
        inputs: dict[str, object] = {
            "artifacts": tuple(compiled_artifact(result) for result in results),
            "observations": tuple(
                observation for result in results for observation in result.observations
            ),
            "ingest_diagnostics": (),
            "evaluations_by_tracking_id": {},
            "attestation": DetectionAttestation(default=DETECTED_AT),
            "options": options(),
        }
        report = compile_records(**inputs)  # type: ignore[arg-type]
        projected = project_vdt(compile_record_set(**inputs))  # type: ignore[arg-type]

        self.assertEqual(projected.to_json(), report.to_json())
        self.assertEqual(projected.to_markdown(), report.to_markdown())

    def test_the_record_set_holds_every_record_including_accepted(self) -> None:
        evaluations = evaluations_from(
            disposition="accepted", acceptanceRationale=self.ACCEPTED_RATIONALE
        )
        record_set = compile_record_set_from_artifacts(
            list(ARTIFACTS), options=options(), evaluations=evaluations
        )
        report = project_vdt(record_set)
        accepted = [item for item in record_set.records if item.status is CaseStatus.ACCEPTED]
        reported = [item.tracking_id for item in report.vulnerabilities]
        every_id = [item.tracking_id for item in record_set.records]

        self.assertEqual(len(accepted), 1)
        self.assertEqual(
            len(record_set.records),
            len(report.vulnerabilities) + len(report.accepted) + report.metadata.excluded_by_period,
        )
        self.assertEqual(
            [item.vulnerability.tracking_id for item in report.accepted],
            [item.tracking_id for item in accepted],
        )
        # The projection keeps the set's order; it only leaves records out.
        self.assertEqual([value for value in every_id if value in set(reported)], reported)

    def test_selection_diagnostics_belong_to_the_projection_not_the_record_set(self) -> None:
        evaluations = evaluations_from(
            disposition="accepted", acceptanceRationale=self.ACCEPTED_RATIONALE
        )
        record_set = compile_record_set_from_artifacts(
            list(ARTIFACTS), options=options(), evaluations=evaluations
        )
        report = project_vdt(record_set)
        selection = {"accepted_excluded", "excluded_by_period"}

        self.assertFalse({item.code for item in record_set.diagnostics} & selection)
        self.assertEqual(
            [item.code for item in report.diagnostics if item.code in selection],
            ["accepted_excluded"],
        )
        # The set's own diagnostics come first and unchanged; the projection appends.
        self.assertEqual(report.diagnostics[: len(record_set.diagnostics)], record_set.diagnostics)

    def test_the_record_set_carries_the_provenance_every_projection_publishes(self) -> None:
        record_set = compile_record_set_from_artifacts(list(ARTIFACTS), options=options())
        report = project_vdt(record_set)
        extension = report.document["x-complyroll"]

        self.assertEqual(record_set.generator_version, __version__)
        self.assertEqual(extension["generator"]["version"], record_set.generator_version)
        self.assertEqual(extension["parserVersions"], dict(record_set.parser_versions))
        self.assertEqual(
            [artifact["name"] for artifact in extension["artifacts"]],
            [artifact.name for artifact in record_set.artifacts],
        )
        self.assertEqual(extension["rulesSource"]["commit"], record_set.rules_provenance.commit)
        self.assertIs(report.metadata.options, record_set.options)

    def test_project_vdt_refuses_anything_but_a_record_set(self) -> None:
        with self.assertRaisesRegex(TypeError, "CompiledRecordSet"):
            project_vdt(compile_fixtures())  # type: ignore[arg-type]

    def test_the_example_acceptance_file_accepts_the_banner_record_only(self) -> None:
        record_set = compile_record_set_from_artifacts(
            list(ARTIFACTS), options=options(), evaluations=load_evaluations(ACCEPTED_EVALUATIONS)
        )
        accepted = [
            item.tracking_id for item in record_set.records if item.status is CaseStatus.ACCEPTED
        ]

        self.assertEqual(len(record_set.records), 6)
        self.assertEqual(accepted, [BANNER_CASE])
        self.assertFalse(
            {item.code for item in record_set.diagnostics}
            & {"accepted_excluded", "excluded_by_period"}
        )


class AcceptedRecordSharingTests(unittest.TestCase):
    """One record set, three projections, and one accepted record they all agree on."""

    @classmethod
    def setUpClass(cls) -> None:
        cls.record_set = compile_record_set_from_artifacts(
            list(ARTIFACTS),
            options=options(),
            evaluations=load_evaluations(ACCEPTED_EVALUATIONS),
        )
        cls.vdt = project_vdt(cls.record_set)
        cls.avi = project_avi(cls.record_set)
        cls.historical = project_historical(cls.record_set)

    def test_each_projection_partitions_the_population(self) -> None:
        self.assertEqual((len(self.vdt.vulnerabilities), len(self.vdt.accepted)), (5, 1))
        self.assertEqual((len(self.avi.accepted), self.avi.active_not_reported), (1, 5))
        self.assertEqual((len(self.historical.active), len(self.historical.accepted)), (5, 1))

    def test_no_record_is_in_both_the_detail_report_and_the_avi(self) -> None:
        reported = {item.tracking_id for item in self.vdt.vulnerabilities}
        accepted = {item.vulnerability.tracking_id for item in self.avi.accepted}

        self.assertEqual(accepted, {BANNER_CASE})
        self.assertFalse(reported & accepted)

    def test_the_detail_report_summary_counts_the_record_it_set_aside(self) -> None:
        # The golden detail report accepts nothing, so its reconciliation test only ever
        # sees this row at zero; this is the one place the row is pinned at one.
        summary = summary_counts(self.vdt.to_markdown())

        self.assertEqual(summary["Accepted, reported under VER-RPT-AVI"], 1)
        self.assertEqual(summary["Vulnerabilities reported"], 5)
        self.assertEqual(summary["Excluded by report period"], 0)

    def test_every_projection_reconciles_to_the_record_count(self) -> None:
        total = len(self.record_set.records)

        self.assertEqual(
            len(self.vdt.vulnerabilities)
            + len(self.vdt.accepted)
            + self.vdt.metadata.excluded_by_period,
            total,
        )
        self.assertEqual(
            len(self.avi.accepted)
            + self.avi.active_not_reported
            + self.avi.metadata.excluded_by_period,
            total,
        )
        self.assertEqual(len(self.historical.active) + len(self.historical.accepted), total)

    def test_the_accepted_item_is_the_same_bytes_in_the_avi_and_the_snapshot(self) -> None:
        avi_item = find_accepted(self.avi, "banner_etc_issue")
        historical_item = find_accepted(self.historical, "banner_etc_issue")

        self.assertEqual(
            json.dumps(historical_item, sort_keys=True), json.dumps(avi_item, sort_keys=True)
        )

    def test_the_active_records_are_the_same_in_the_detail_report_and_the_snapshot(self) -> None:
        self.assertEqual(
            self.historical.document["activeVulnerabilities"],
            self.vdt.document["vulnerabilities"],
        )


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

    def test_the_period_may_be_omitted_together(self) -> None:
        periodless = options(period_from=None, period_to=None)

        self.assertFalse(periodless.has_period)
        with self.assertRaisesRegex(ValueError, "no report period"):
            _ = periodless.period

    def test_one_period_bound_alone_is_refused(self) -> None:
        for bounds in ({"period_from": None}, {"period_to": None}):
            with self.subTest(bounds=bounds):
                with self.assertRaisesRegex(ValueError, "must be given together"):
                    options(**bounds)

    def test_has_period_and_period_agree(self) -> None:
        with_period = options()

        self.assertTrue(with_period.has_period)
        self.assertEqual(with_period.period, (PERIOD_FROM, PERIOD_TO))

    def test_period_bounds_must_be_timezone_aware(self) -> None:
        with self.assertRaisesRegex(ValueError, "period_from must include a timezone"):
            options(period_from=datetime(2026, 8, 1), period_to=PERIOD_TO)
        with self.assertRaisesRegex(ValueError, "period_to must include a timezone"):
            options(period_from=PERIOD_FROM, period_to=datetime(2026, 8, 31))

    def test_the_period_reports_refuse_a_periodless_record_set(self) -> None:
        record_set = compile_record_set_from_artifacts(
            list(ARTIFACTS), options=options(period_from=None, period_to=None)
        )
        expected = {
            project_vdt: "the Vulnerability Detail Report",
            project_avi: "the Accepted Vulnerability Information report",
        }

        for project, report_name in expected.items():
            with self.subTest(projection=project.__name__):
                with self.assertRaises(ReportCompileError) as caught:
                    project(record_set)

                diagnostics = caught.exception.diagnostics
                self.assertEqual([item.code for item in diagnostics], ["report_period_missing"])
                self.assertTrue(diagnostics[0].message.startswith(report_name))
        self.assertEqual(len(project_historical(record_set).active), 6)


class PainReductionSlotTests(unittest.TestCase):
    """Completed PAIN reductions publish in the official slot (ADR 0009 Decision 3).

    Common Definitions 0.3.0 gave `vulnerabilityDetail` a `painReductionEvents` array,
    so the extension no longer carries a copy of the list: one fact, one place.
    """

    def test_reductions_are_published_on_the_official_record(self) -> None:
        report = compile_fixtures(
            evaluations=evaluations_from(
                painReductionEvents=[{"reducedAt": "2026-08-10T00:00:00Z", "rating": 2}]
            )
        )
        record = find_vulnerability(report, "V-260470")

        self.assertEqual(
            record["painReductionEvents"],
            [{"reducedAt": "2026-08-10T00:00:00Z", "rating": 2}],
        )
        self.assertNotIn("painReductionEvents", record["x-complyroll"])

    def test_a_record_with_no_reductions_omits_the_key(self) -> None:
        report = compile_fixtures(evaluations=evaluations_from())
        record = find_vulnerability(report, "V-260470")

        self.assertNotIn("painReductionEvents", record)
        self.assertNotIn("painReductionEvents", record["x-complyroll"])


class PainReductionOrderTests(unittest.TestCase):
    """Completed PAIN reductions render in one canonical order (ADR 0008 Decision 5).

    The persisted path reads reductions in the order they were appended and the
    stateless path in the order the file states them, so the rendered order is a seam
    where the two paths could disagree while describing the same facts. Sorting by
    instant, then rating, in the shared record compiler closes it for both.
    """

    OUT_OF_ORDER = (
        {"reducedAt": "2026-08-12T16:00:00Z", "rating": 3},
        {"reducedAt": "2026-08-06T16:00:00Z", "rating": 4},
    )

    def compile_with(self, events: Sequence[dict[str, object]]) -> CompiledVdtReport:
        return compile_fixtures(evaluations=evaluations_from(painReductionEvents=list(events)))

    def test_the_json_array_is_sorted_by_instant(self) -> None:
        report = self.compile_with(self.OUT_OF_ORDER)

        record = find_vulnerability(report, "V-260470")

        self.assertEqual(
            record["painReductionEvents"],
            [
                {"reducedAt": "2026-08-06T16:00:00Z", "rating": 4},
                {"reducedAt": "2026-08-12T16:00:00Z", "rating": 3},
            ],
        )

    def test_the_markdown_twin_lists_the_same_order(self) -> None:
        report = self.compile_with(self.OUT_OF_ORDER)

        self.assertIn(
            "- **Completed PAIN reductions:** N4 at 2026-08-06T16:00:00Z, "
            "N3 at 2026-08-12T16:00:00Z",
            report.to_markdown(),
        )

    def test_two_reductions_at_one_instant_sort_by_rating(self) -> None:
        report = self.compile_with(
            (
                {"reducedAt": "2026-08-06T16:00:00Z", "rating": 4},
                {"reducedAt": "2026-08-06T16:00:00Z", "rating": 2},
            )
        )

        record = find_vulnerability(report, "V-260470")

        self.assertEqual([item["rating"] for item in record["painReductionEvents"]], [2, 4])

    def test_an_already_ordered_file_is_unchanged(self) -> None:
        ordered = tuple(reversed(self.OUT_OF_ORDER))

        report = self.compile_with(ordered)
        record = find_vulnerability(report, "V-260470")

        self.assertEqual(record["painReductionEvents"], list(ordered))


class RepeatedPainReductionTests(unittest.TestCase):
    """One reduction is one event, so a file may not state it twice (ADR 0008)."""

    def test_a_repeated_reduction_names_both_entries(self) -> None:
        payload = evaluation_json(
            painReductionEvents=[
                {"reducedAt": "2026-08-12T16:00:00Z", "rating": 3},
                {"reducedAt": "2026-08-12T16:00:00Z", "rating": 3},
            ]
        )

        with self.assertRaises(ReportInputError) as caught:
            parse_evaluations(payload.encode("utf-8"))

        message = str(caught.exception)
        self.assertIn("evaluations[0].painReductionEvents[1] repeats", message)
        self.assertIn("evaluations[0].painReductionEvents[0] already states", message)
        self.assertIn("PAIN 3", message)
        self.assertIn("2026-08-12T16:00:00Z", message)

    def test_two_spellings_of_one_instant_are_one_reduction(self) -> None:
        payload = evaluation_json(
            painReductionEvents=[
                {"reducedAt": "2026-08-12T16:00:00Z", "rating": 3},
                {"reducedAt": "2026-08-12T09:00:00-07:00", "rating": 3},
            ]
        )

        with self.assertRaises(ReportInputError) as caught:
            parse_evaluations(payload.encode("utf-8"))

        message = str(caught.exception)
        self.assertIn("evaluations[0].painReductionEvents[1] repeats", message)
        self.assertIn("2026-08-12T16:00:00Z", message)

    def test_two_ratings_at_one_instant_are_distinct_reductions(self) -> None:
        evaluations = evaluations_from(
            painReductionEvents=[
                {"reducedAt": "2026-08-12T16:00:00Z", "rating": 3},
                {"reducedAt": "2026-08-12T16:00:00Z", "rating": 4},
            ]
        )

        self.assertEqual(len(evaluations.entries[0].pain_reduction_events), 2)

    def test_two_instants_one_rating_are_distinct_reductions(self) -> None:
        evaluations = evaluations_from(
            painReductionEvents=[
                {"reducedAt": "2026-08-12T16:00:00Z", "rating": 3},
                {"reducedAt": "2026-08-13T16:00:00Z", "rating": 3},
            ]
        )

        self.assertEqual(len(evaluations.entries[0].pain_reduction_events), 2)


class ArgumentOrderTests(unittest.TestCase):
    """The same artifacts in any order compile to the same bytes.

    The public claim is that the same facts produce the same bytes, and the assessor
    case is a cold recompute over a provider's artifacts. An assessor has no way to
    know the order the provider named its files in, so any part of the report that
    echoes argument order is a defect rather than a fact about the package.
    """

    def test_reversing_the_artifact_arguments_produces_the_same_json(self) -> None:
        evaluations = load_evaluations(EXAMPLES / "evaluations.json")

        forward = compile_fixtures(artifacts=ARTIFACTS, evaluations=evaluations)
        reversed_run = compile_fixtures(
            artifacts=tuple(reversed(ARTIFACTS)), evaluations=evaluations
        )

        self.assertEqual(reversed_run.to_json(), forward.to_json())

    def test_reversing_the_artifact_arguments_produces_the_same_markdown(self) -> None:
        evaluations = load_evaluations(EXAMPLES / "evaluations.json")

        forward = compile_fixtures(artifacts=ARTIFACTS, evaluations=evaluations)
        reversed_run = compile_fixtures(
            artifacts=tuple(reversed(ARTIFACTS)), evaluations=evaluations
        )

        self.assertEqual(reversed_run.to_markdown(), forward.to_markdown())

    def test_every_argument_permutation_produces_the_same_bytes(self) -> None:
        """Reversal alone would pass a compiler that merely reverses its manifest."""

        evaluations = load_evaluations(EXAMPLES / "evaluations.json")
        expected = compile_fixtures(artifacts=ARTIFACTS, evaluations=evaluations)

        for order in permutations(ARTIFACTS):
            with self.subTest(order=[path.name for path in order]):
                report = compile_fixtures(artifacts=order, evaluations=evaluations)

                self.assertEqual(report.to_json(), expected.to_json())
                self.assertEqual(report.to_markdown(), expected.to_markdown())

    def test_every_report_kind_is_order_independent_with_an_accepted_record(self) -> None:
        evaluations = load_evaluations(ACCEPTED_EVALUATIONS)

        for kind in REPORT_KINDS:
            expected = compile_fixtures(artifacts=ARTIFACTS, evaluations=evaluations, kind=kind)
            for order in permutations(ARTIFACTS):
                with self.subTest(kind=kind, order=[path.name for path in order]):
                    report = compile_fixtures(artifacts=order, evaluations=evaluations, kind=kind)

                    self.assertEqual(report.to_json(), expected.to_json())
                    self.assertEqual(report.to_markdown(), expected.to_markdown())

    def test_the_artifact_manifest_is_sorted_by_name_then_digest(self) -> None:
        report = compile_fixtures(artifacts=tuple(reversed(ARTIFACTS)))
        artifacts = report.document["x-complyroll"]["artifacts"]

        keys = [(item["name"], item["sha256"]) for item in artifacts]
        self.assertEqual(keys, sorted(keys))
        self.assertEqual(
            [item["name"] for item in artifacts],
            ["openscap-results.xml", "ubuntu-host.cklb", "windows-host.ckl"],
        )

    def test_the_manifest_breaks_a_name_tie_on_the_digest(self) -> None:
        """Two artifacts may share a name, so name alone is not a total order."""

        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            first = root / "one" / "scan.xml"
            second = root / "two" / "scan.xml"
            first.parent.mkdir()
            second.parent.mkdir()
            first.write_text(distinct_xccdf("alpha"), encoding="utf-8")
            second.write_text(distinct_xccdf("bravo"), encoding="utf-8")

            forward = compile_fixtures(artifacts=(first, second))
            backward = compile_fixtures(artifacts=(second, first))

        artifacts = forward.document["x-complyroll"]["artifacts"]
        self.assertEqual([item["name"] for item in artifacts], ["scan.xml", "scan.xml"])
        digests = [item["sha256"] for item in artifacts]
        self.assertEqual(digests, sorted(digests))
        self.assertEqual(backward.to_json(), forward.to_json())

    def test_the_markdown_inputs_table_follows_the_sorted_manifest(self) -> None:
        report = compile_fixtures(artifacts=tuple(reversed(ARTIFACTS)))

        rows = markdown_table_rows(
            markdown_section(report.to_markdown(), "Inputs"), 4, "Artifact"
        )
        self.assertEqual(
            list(rows),
            ["openscap-results.xml", "ubuntu-host.cklb", "windows-host.ckl"],
        )

    def test_ingest_diagnostics_are_sorted_independently_of_argument_order(self) -> None:
        """Every fixture raises one `source_timestamp_missing`, so order is visible."""

        forward = compile_fixtures(artifacts=ARTIFACTS)
        backward = compile_fixtures(artifacts=tuple(reversed(ARTIFACTS)))

        expected = [
            ("source_timestamp_missing", "openscap-results.xml"),
            ("source_timestamp_missing", "ubuntu-host.cklb"),
            ("source_timestamp_missing", "windows-host.ckl"),
        ]
        for report in (forward, backward):
            observed = [
                (item.code, item.location)
                for item in report.diagnostics
                if item.code == "source_timestamp_missing"
            ]
            self.assertEqual(observed, expected)

    def test_unresolved_observation_diagnostics_do_not_follow_argument_order(self) -> None:
        """A diagnostic raised inside the compile must not echo argv either."""

        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            first = root / "aaa-scan.xml"
            second = root / "zzz-scan.xml"
            first.write_text(
                distinct_xccdf("alpha").replace(
                    "<result>pass</result>", "<result>error</result>", 1
                ),
                encoding="utf-8",
            )
            second.write_text(
                distinct_xccdf("bravo").replace(
                    "<result>pass</result>", "<result>unknown</result>", 1
                ),
                encoding="utf-8",
            )

            forward = compile_fixtures(artifacts=(first, second))
            backward = compile_fixtures(artifacts=(second, first))

        def unresolved(report: CompiledVdtReport) -> list[tuple[str | None, str]]:
            return [
                (item.location, item.message)
                for item in report.diagnostics
                if item.code == "unresolved_observation"
            ]

        self.assertEqual(len(unresolved(forward)), 2)
        self.assertEqual(unresolved(backward), unresolved(forward))
        self.assertEqual(backward.to_json(), forward.to_json())

    def test_a_repeated_artifact_still_sorts_with_the_rest(self) -> None:
        """The duplicate warning is an ingest diagnostic, so it sorts with them."""

        artifacts = (FIXTURES / "windows-host.ckl", *ARTIFACTS)

        forward = compile_fixtures(artifacts=artifacts)
        backward = compile_fixtures(artifacts=tuple(reversed(artifacts)))

        self.assertEqual(backward.to_json(), forward.to_json())
        codes = [item.code for item in forward.diagnostics]
        self.assertEqual(codes, sorted(codes))


class SharedGroupOrderTests(unittest.TestCase):
    """One benchmark across a fleet is one vulnerability drawn from many files.

    This is the ordinary deployment, not an edge case, and it is the case where
    argument order used to reach the vulnerability records themselves rather than only
    the manifest: `resources`, `observationIds`, and the reported title are all built
    by walking a group's members.
    """

    hosts = ("host-charlie", "host-alpha", "host-bravo")

    def compile_hosts(
        self,
        order: Sequence[str],
        *,
        kind: ReportKind = "vdt",
        evaluations: EvaluationSet | None = None,
    ) -> CompiledVdtReport | CompiledAviReport | CompiledHistoricalReport:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            paths = []
            for host in order:
                path = root / f"{host}.xml"
                path.write_text(shared_benchmark_xccdf(host), encoding="utf-8")
                paths.append(path)
            return compile_fixtures(artifacts=tuple(paths), evaluations=evaluations, kind=kind)

    def test_every_report_kind_orders_a_shared_accepted_group_the_same_way(self) -> None:
        """Accepting the shared banner group puts the group in every projection."""

        evaluations = evaluations_from(match=BANNER_MATCH, **ACCEPTANCE)
        avi = self.compile_hosts(self.hosts, kind="avi", evaluations=evaluations)
        self.assertEqual(len(avi.accepted), 1)
        self.assertEqual(
            [resource.resource_id for resource in avi.accepted[0].vulnerability.resources],
            sorted(self.hosts),
        )

        for kind in REPORT_KINDS:
            expected = self.compile_hosts(self.hosts, kind=kind, evaluations=evaluations)
            for order in permutations(self.hosts):
                with self.subTest(kind=kind, order=list(order)):
                    report = self.compile_hosts(order, kind=kind, evaluations=evaluations)

                    self.assertEqual(report.to_json(), expected.to_json())
                    self.assertEqual(report.to_markdown(), expected.to_markdown())

    def test_the_fixture_really_does_produce_a_group_spanning_every_file(self) -> None:
        """Guard the premise: without shared groups the rest proves nothing."""

        report = self.compile_hosts(self.hosts)

        self.assertTrue(report.vulnerabilities)
        spanning = [item for item in report.vulnerabilities if len(item.resources) > 1]
        self.assertTrue(spanning, "no vulnerability spans more than one host")
        self.assertEqual(len(spanning[0].observation_ids), len(self.hosts))

    def test_a_group_spanning_files_compiles_to_the_same_bytes_in_any_order(self) -> None:
        expected = self.compile_hosts(self.hosts)

        for order in permutations(self.hosts):
            with self.subTest(order=list(order)):
                report = self.compile_hosts(order)

                self.assertEqual(report.to_json(), expected.to_json())
                self.assertEqual(report.to_markdown(), expected.to_markdown())

    def test_the_affected_resources_are_listed_in_a_stable_order(self) -> None:
        """The list a reader scans must not be in the order files were named."""

        for order in permutations(self.hosts):
            with self.subTest(order=list(order)):
                report = self.compile_hosts(order)
                spanning = next(
                    item for item in report.vulnerabilities if len(item.resources) > 1
                )

                self.assertEqual(
                    [resource.resource_id for resource in spanning.resources],
                    sorted(self.hosts),
                )

    def test_two_files_sharing_a_name_and_a_group_still_order_totally(self) -> None:
        """Same file name, different bytes, one shared group: only the fingerprint separates them.

        This is the case the last element of the member sort key exists for. The
        resource and the artifact name both tie, so without the fingerprint the two
        members would keep whatever order they were read in.
        """

        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            first = root / "one" / "scan.xml"
            second = root / "two" / "scan.xml"
            first.parent.mkdir()
            second.parent.mkdir()
            # One host, two readings, same file name, different bytes.
            first.write_text(shared_benchmark_xccdf("host-shared"), encoding="utf-8")
            second.write_text(
                shared_benchmark_xccdf("host-shared").replace(
                    "<result>pass</result>", "<result>fail</result>", 1
                ),
                encoding="utf-8",
            )

            forward = compile_fixtures(artifacts=(first, second))
            backward = compile_fixtures(artifacts=(second, first))

        self.assertEqual(backward.to_json(), forward.to_json())
        self.assertEqual(backward.to_markdown(), forward.to_markdown())
        spanning = [item for item in forward.vulnerabilities if len(item.observation_ids) > 1]
        self.assertTrue(spanning, "the two readings must share at least one group")


class DuplicateBytesOrderTests(unittest.TestCase):
    """Identical bytes under two names must not let argument order pick the survivor.

    Only one reading of a set of identical bytes can be in a report. While the first
    one supplied won, the manifest named whichever file the operator happened to list
    first, so the same set of files in a different order produced a different report.
    """

    def compile_named(
        self,
        order: Sequence[str],
        *,
        kind: ReportKind = "vdt",
        evaluations: EvaluationSet | None = None,
    ) -> CompiledVdtReport | CompiledAviReport | CompiledHistoricalReport:
        source = (FIXTURES / "openscap-results.xml").read_text(encoding="utf-8")
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            paths = []
            for name in order:
                path = root / name
                path.write_text(source, encoding="utf-8")
                paths.append(path)
            return compile_fixtures(artifacts=tuple(paths), evaluations=evaluations, kind=kind)

    def test_every_report_kind_elects_the_same_reading_in_any_order(self) -> None:
        names = ("b.xml", "a.xml", "c.xml")
        evaluations = evaluations_from(match=BANNER_MATCH, **ACCEPTANCE)
        avi = self.compile_named(names, kind="avi", evaluations=evaluations)
        self.assertEqual(len(avi.accepted), 1)

        for kind in REPORT_KINDS:
            expected = self.compile_named(names, kind=kind, evaluations=evaluations)
            for order in permutations(names):
                with self.subTest(kind=kind, order=list(order)):
                    report = self.compile_named(order, kind=kind, evaluations=evaluations)

                    self.assertEqual(report.to_json(), expected.to_json())
                    self.assertEqual(report.to_markdown(), expected.to_markdown())

    def test_the_elected_reading_does_not_depend_on_argument_order(self) -> None:
        forward = self.compile_named(("aaa-copy.xml", "zzz-copy.xml"))
        backward = self.compile_named(("zzz-copy.xml", "aaa-copy.xml"))

        self.assertEqual(backward.to_json(), forward.to_json())
        self.assertEqual(backward.to_markdown(), forward.to_markdown())

    def test_the_manifest_names_the_lowest_named_copy(self) -> None:
        report = self.compile_named(("zzz-copy.xml", "aaa-copy.xml"))
        artifacts = report.document["x-complyroll"]["artifacts"]

        self.assertEqual([item["name"] for item in artifacts], ["aaa-copy.xml"])

    def test_the_duplicate_diagnostic_names_the_copy_that_was_read(self) -> None:
        """A reader must be able to tell which file the report was built from."""

        report = self.compile_named(("zzz-copy.xml", "aaa-copy.xml"))

        duplicates = [
            item for item in report.diagnostics if item.code == "duplicate_artifact"
        ]
        self.assertEqual(len(duplicates), 1)
        self.assertEqual(duplicates[0].location, "zzz-copy.xml")
        self.assertIn("reads them as aaa-copy.xml", duplicates[0].message)

    def test_three_identical_copies_leave_one_reading_and_two_notes(self) -> None:
        forward = self.compile_named(("b.xml", "a.xml", "c.xml"))
        backward = self.compile_named(("c.xml", "b.xml", "a.xml"))

        self.assertEqual(backward.to_json(), forward.to_json())
        artifacts = forward.document["x-complyroll"]["artifacts"]
        self.assertEqual([item["name"] for item in artifacts], ["a.xml"])
        self.assertEqual(
            sorted(
                item.location
                for item in forward.diagnostics
                if item.code == "duplicate_artifact"
            ),
            ["b.xml", "c.xml"],
        )


if __name__ == "__main__":
    unittest.main()
