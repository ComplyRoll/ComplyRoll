"""Backward-compatible stigroll CLI implemented on ComplyRoll observations."""

from __future__ import annotations

import argparse
import csv
import io
import json
import sys
from collections import Counter, defaultdict
from dataclasses import dataclass, replace
from pathlib import Path

from complyroll.adapters import ingest_stig_artifact, load_cci_control_map
from complyroll.models import Observation, ObservationDisposition, SourceSeverity


SEVERITY_TO_CAT = {
    "high": "CAT I",
    "medium": "CAT II",
    "low": "CAT III",
    "unknown": "unknown",
}
STATUS_ORDER = ["open", "not_a_finding", "not_applicable", "not_reviewed"]
CAT_ORDER = ["CAT I", "CAT II", "CAT III", "unknown"]
FAMILY_NAMES = {
    "AC": "Access Control",
    "AT": "Awareness and Training",
    "AU": "Audit and Accountability",
    "CA": "Assessment, Authorization, and Monitoring",
    "CM": "Configuration Management",
    "CP": "Contingency Planning",
    "IA": "Identification and Authentication",
    "IR": "Incident Response",
    "MA": "Maintenance",
    "MP": "Media Protection",
    "PE": "Physical and Environmental Protection",
    "PL": "Planning",
    "PM": "Program Management",
    "PS": "Personnel Security",
    "PT": "PII Processing and Transparency",
    "RA": "Risk Assessment",
    "SA": "System and Services Acquisition",
    "SC": "System and Communications Protection",
    "SI": "System and Information Integrity",
    "SR": "Supply Chain Risk Management",
}


@dataclass(frozen=True, slots=True)
class Finding:
    rule_id: str
    title: str
    severity: str
    status: str
    host: str
    source: str
    ccis: tuple[str, ...]
    controls: tuple[str, ...]

    @property
    def cat(self) -> str:
        return SEVERITY_TO_CAT.get(self.severity, "unknown")

    @property
    def families(self) -> list[str]:
        return sorted({control.split("-")[0] for control in self.controls})

    @classmethod
    def from_observation(cls, observation: Observation) -> "Finding":
        status = {
            ObservationDisposition.OPEN: "open",
            ObservationDisposition.PASS: "not_a_finding",
            ObservationDisposition.NOT_APPLICABLE: "not_applicable",
        }.get(observation.disposition, "not_reviewed")
        severity = observation.source_severity.value
        if observation.source_severity not in {
            SourceSeverity.HIGH,
            SourceSeverity.MEDIUM,
            SourceSeverity.LOW,
            SourceSeverity.UNKNOWN,
        }:
            severity = "unknown"
        return cls(
            rule_id=observation.source_record_id,
            title=observation.title,
            severity=severity,
            status=status,
            host=observation.resource.resource_id,
            source=observation.source_artifact_name,
            ccis=observation.source_identifiers,
            controls=(),
        )


def _markdown_cell(value: str) -> str:
    return (
        value.replace("\\", "\\\\")
        .replace("|", "\\|")
        .replace("<", "&lt;")
        .replace(">", "&gt;")
        .replace("\r", " ")
        .replace("\n", " ")
    )


def _csv_cell(value: str) -> str:
    if value.startswith(("=", "+", "-", "@", "\t", "\r")):
        return f"'{value}"
    return value


def summarize(findings: list[Finding]) -> dict:
    by_status: Counter[str] = Counter()
    open_by_cat: Counter[str] = Counter()
    by_host: dict[str, Counter[str]] = defaultdict(Counter)
    family_open: dict[str, Counter[str]] = defaultdict(Counter)
    unmapped_open = 0

    for finding in findings:
        by_status[finding.status] += 1
        by_host[finding.host][finding.status] += 1
        if finding.status != "open":
            continue
        open_by_cat[finding.cat] += 1
        if not finding.families:
            unmapped_open += 1
        for family in finding.families:
            family_open[family][finding.cat] += 1

    return {
        "total": len(findings),
        "by_status": by_status,
        "open_by_cat": open_by_cat,
        "by_host": by_host,
        "family_open": family_open,
        "unmapped_open": unmapped_open,
        "hosts": sorted(by_host),
    }


def render_markdown(findings: list[Finding], summary: dict) -> str:
    output: list[str] = []
    write = output.append
    write("# STIG Findings Rollup\n")
    host_names = ", ".join(_markdown_cell(host) for host in summary["hosts"])
    write(f"**Hosts:** {len(summary['hosts'])} ({host_names})  ")
    write(f"**Rules evaluated:** {summary['total']}  ")
    write(f"**Open findings:** {summary['by_status']['open']}\n")

    write("## Open findings by severity\n")
    write("| Category | Open |")
    write("|---|---:|")
    for category in CAT_ORDER:
        if summary["open_by_cat"][category] or category != "unknown":
            write(f"| {category} | {summary['open_by_cat'][category]} |")
    write("")

    write("## All results by status\n")
    write("| Status | Count |")
    write("|---|---:|")
    for status in STATUS_ORDER:
        write(f"| {status.replace('_', ' ')} | {summary['by_status'][status]} |")
    write("")

    write("## Open findings by NIST 800-53 control family\n")
    if summary["family_open"]:
        write("| Family | Name | CAT I | CAT II | CAT III | Total |")
        write("|---|---|---:|---:|---:|---:|")
        families = sorted(
            summary["family_open"],
            key=lambda family: -sum(summary["family_open"][family].values()),
        )
        for family in families:
            counts = summary["family_open"][family]
            total = sum(counts.values())
            name = FAMILY_NAMES.get(family, "")
            write(
                f"| {family} | {name} | {counts['CAT I']} | {counts['CAT II']} "
                f"| {counts['CAT III']} | {total} |"
            )
        write("")
    else:
        write("_No CCI-to-control mapping applied. Pass `--cci-list U_CCI_List.xml`._\n")

    if summary["unmapped_open"]:
        write(
            f"> {summary['unmapped_open']} open finding(s) carry no CCI reference and could not "
            "be mapped to a control. These still require adjudication.\n"
        )

    if len(summary["hosts"]) > 1:
        write("## Per-host breakdown\n")
        write("| Host | Open | Not a finding | N/A | Not reviewed |")
        write("|---|---:|---:|---:|---:|")
        for host in summary["hosts"]:
            counts = summary["by_host"][host]
            write(
                f"| {_markdown_cell(host)} | {counts['open']} | {counts['not_a_finding']} "
                f"| {counts['not_applicable']} | {counts['not_reviewed']} |"
            )
        write("")

    cat_one = [
        finding for finding in findings if finding.status == "open" and finding.cat == "CAT I"
    ]
    if cat_one:
        write("## CAT I open findings\n")
        write("| Rule | Host | Controls | Title |")
        write("|---|---|---|---|")
        for finding in sorted(cat_one, key=lambda item: item.rule_id):
            controls = ", ".join(finding.controls) or "-"
            title = _markdown_cell(finding.title[:80])
            write(
                f"| {_markdown_cell(finding.rule_id)} | {_markdown_cell(finding.host)} "
                f"| {_markdown_cell(controls)} | {title} |"
            )
        write("")
    return "\n".join(output)


def render_csv(findings: list[Finding]) -> str:
    buffer = io.StringIO()
    writer = csv.writer(buffer)
    writer.writerow(
        ["rule_id", "host", "status", "severity", "cat", "controls", "families", "title", "source"]
    )
    for finding in findings:
        writer.writerow(
            [
                _csv_cell(finding.rule_id),
                _csv_cell(finding.host),
                finding.status,
                finding.severity,
                finding.cat,
                ";".join(finding.controls),
                ";".join(finding.families),
                _csv_cell(finding.title),
                _csv_cell(finding.source),
            ]
        )
    return buffer.getvalue()


def render_json(findings: list[Finding], summary: dict) -> str:
    return json.dumps(
        {
            "summary": {
                "total": summary["total"],
                "hosts": summary["hosts"],
                "by_status": dict(summary["by_status"]),
                "open_by_cat": dict(summary["open_by_cat"]),
                "open_by_family": {
                    key: dict(value) for key, value in summary["family_open"].items()
                },
                "unmapped_open": summary["unmapped_open"],
            },
            "findings": [
                {
                    "rule_id": finding.rule_id,
                    "host": finding.host,
                    "status": finding.status,
                    "severity": finding.severity,
                    "cat": finding.cat,
                    "ccis": list(finding.ccis),
                    "controls": list(finding.controls),
                    "families": finding.families,
                    "title": finding.title,
                    "source": finding.source,
                }
                for finding in findings
            ],
        },
        indent=2,
    )


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="stigroll",
        description="Roll STIG checklists and SCAP results up to NIST 800-53 control families.",
    )
    parser.add_argument("inputs", nargs="+", type=Path, help=".cklb, .ckl, or XCCDF results")
    parser.add_argument(
        "--cci-list",
        type=Path,
        help="DISA U_CCI_List.xml. Without it, no control mapping is produced.",
    )
    parser.add_argument(
        "--format",
        choices=["markdown", "csv", "json"],
        default="markdown",
        help="output format",
    )
    parser.add_argument("-o", "--output", type=Path, help="write to a file instead of stdout")
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    findings: list[Finding] = []
    for path in args.inputs:
        if not path.exists():
            print(f"warning: {path} not found, skipping", file=sys.stderr)
            continue
        result = ingest_stig_artifact(path)
        for diagnostic in result.errors:
            if diagnostic.message == "JSON has no non-empty 'stigs' array":
                print(
                    f"warning: {path.name} parsed as JSON but has no 'stigs' key. "
                    "Is it a STIG Viewer checklist?",
                    file=sys.stderr,
                )
            else:
                print(
                    f"warning: could not parse {path.name}: {diagnostic.message}",
                    file=sys.stderr,
                )
        findings.extend(Finding.from_observation(item) for item in result.observations)

    if not findings:
        print("error: no findings parsed from any input", file=sys.stderr)
        return 1

    if args.cci_list:
        if not args.cci_list.exists():
            print(f"error: CCI list not found: {args.cci_list}", file=sys.stderr)
            return 1
        mapping_result = load_cci_control_map(args.cci_list)
        if not mapping_result.successful:
            for diagnostic in mapping_result.errors:
                print(
                    f"error: could not parse {args.cci_list.name}: {diagnostic.message}",
                    file=sys.stderr,
                )
            return 1
        assert mapping_result.mapping is not None
        findings = [
            replace(
                finding,
                controls=tuple(
                    sorted(
                        {
                            control
                            for cci in finding.ccis
                            for control in mapping_result.mapping.controls_for(cci)
                        }
                    )
                ),
            )
            for finding in findings
        ]

    summary = summarize(findings)
    if args.format == "markdown":
        text = render_markdown(findings, summary)
    elif args.format == "csv":
        text = render_csv(findings)
    else:
        text = render_json(findings, summary)

    if args.output:
        args.output.write_text(text, encoding="utf-8")
        print(f"wrote {args.output}", file=sys.stderr)
    else:
        print(text)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
