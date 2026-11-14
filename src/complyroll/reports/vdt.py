# ******************************************************************************
# *Title: Vulnerability Detail Report*
# *Author: Kyle Versluis*
# *Description: Project the Vulnerability Detail Report from the record set.*
# ******************************************************************************
"""Stateless Vulnerability Detail Report compiler (ADR 0007).

`compile_vdt_report` is a pure function of source artifacts plus explicit operator inputs.
It does not read or write the event store, so the same artifacts, evaluations, package
configuration, and `--as-of` instant produce the same bytes on every run.

`project_vdt` selects and renders the Vulnerability Detail Report out of the record set
`reports.records` compiles (ADR 0010). The other report modules in this package project
their own documents from the same record set.
"""

# *--- Imports ---*

from __future__ import annotations

import json
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from complyroll.adapters import DiagnosticLevel
from complyroll.models import CaseStatus, Observation, PainRating
from complyroll.schemas import ReportSchema, SchemaValidationResult

from .evaluations import EvaluationInput, EvaluationSet
from .markdown import (
    write_attestation_section,
    write_changes,
    write_coverage,
    write_diagnostics_section,
    write_footer,
    write_header,
    write_inputs,
    write_kev_summary,
    write_provenance,
    write_vulnerability_table,
)
from .model import (
    EXTENSION_KEY,
    AcceptedVulnerability,
    CompiledArtifact,
    CompiledRecordSet,
    CompiledVulnerability,
    DetectionAttestation,
    ReportDiagnostic,
    ReportMetadata,
    ReportOptions,
)
from .projection import (
    attested_instant,
    common_extension,
    period_exclusion_reason,
    report_period,
    report_period_block,
    schema_provenance,
    validate_document,
)
from .records import compile_record_set, compile_record_set_from_artifacts

# *--- Types ---*


@dataclass(frozen=True, slots=True)
class CompiledVdtReport:
    """One compiled report and the twin renderings built from the same records."""

    document: dict[str, Any]
    vulnerabilities: tuple[CompiledVulnerability, ...]
    accepted: tuple[AcceptedVulnerability, ...]
    diagnostics: tuple[ReportDiagnostic, ...]
    validation: SchemaValidationResult
    metadata: ReportMetadata

    def to_json(self, indent: int = 2) -> str:
        """Return the official JSON document with a stable key order."""

        return json.dumps(self.document, indent=indent, sort_keys=True, ensure_ascii=False) + "\n"

    def to_markdown(self) -> str:
        """Return the human-readable twin, derived from the same records."""

        return _render_markdown(self)


# *--- Core Logic ---*


def compile_vdt_report(
    artifact_paths: Sequence[Path],
    *,
    options: ReportOptions,
    evaluations: EvaluationSet | None = None,
    record_failed_imports: bool = False,
) -> CompiledVdtReport:
    """Compile one Vulnerability Detail Report from artifacts and explicit inputs."""

    return project_vdt(
        compile_record_set_from_artifacts(
            artifact_paths,
            options=options,
            evaluations=evaluations,
            record_failed_imports=record_failed_imports,
        )
    )


def compile_records(
    *,
    artifacts: Sequence[CompiledArtifact],
    observations: Sequence[Observation],
    ingest_diagnostics: Sequence[ReportDiagnostic],
    evaluations_by_tracking_id: Mapping[str, EvaluationInput],
    attestation: DetectionAttestation,
    options: ReportOptions,
) -> CompiledVdtReport:
    """Compile one report from already-normalized records.

    Both the stateless path and the event-sourced rebuild call this, so neither can
    drift from the other by construction (ADR 0008 Decision 5). Callers own how the
    artifacts, observations, ingest diagnostics, and evaluations were obtained;
    everything downstream of them happens here.

    The order a caller supplies its inputs in is not a fact about the package, so
    nothing it decides may reach the document. The stateless path receives artifacts
    and their ingest diagnostics in command-line order and the persisted path in
    ingest order, and both used to be published as given, which meant the same
    artifacts named in a different order compiled to different bytes. Both lists are
    put in a total order here, in the one place both paths run through, so the two
    paths cannot drift apart from each other or from their own earlier runs. Ordering
    them in either caller instead would fix one path and leave the other.
    """

    return project_vdt(
        compile_record_set(
            artifacts=artifacts,
            observations=observations,
            ingest_diagnostics=ingest_diagnostics,
            evaluations_by_tracking_id=evaluations_by_tracking_id,
            attestation=attestation,
            options=options,
        )
    )


def project_vdt(record_set: CompiledRecordSet) -> CompiledVdtReport:
    """Project the Vulnerability Detail Report out of one compiled record set.

    The report period decides what is reported: accepted records are set aside for
    the VER-RPT-AVI report, and disposed records with no recorded activity in the
    period are left out, each with an INFO diagnostic appended after the set's own.
    """

    if not isinstance(record_set, CompiledRecordSet):
        raise TypeError("record_set must be a CompiledRecordSet")

    options = record_set.options
    period = report_period(options, "the Vulnerability Detail Report")
    diagnostics = list(record_set.diagnostics)
    records, accepted, excluded = _select_for_period(record_set.records, period, diagnostics)
    attested = tuple(
        sorted(item.tracking_id for item in records if item.detected_at_source == "attestation")
    )

    metadata = ReportMetadata(
        options=options,
        artifacts=record_set.artifacts,
        rules_provenance=record_set.rules_provenance,
        schema_provenance=schema_provenance(ReportSchema.VULNERABILITY_DETAIL),
        generator_version=record_set.generator_version,
        parser_versions=record_set.parser_versions,
        attestation_applied_to=attested,
        excluded_by_period=excluded,
        attestation_detected_at=attested_instant(records),
        detection_failures=record_set.detection_failures,
        coverage=record_set.coverage,
        coverage_gaps=record_set.coverage_gaps,
        coverage_gap_records=record_set.coverage_gap_records,
        changes=record_set.changes,
        change_gaps=record_set.change_gaps,
        change_gap_records=record_set.change_gap_records,
    )
    document = _build_document(tuple(records), metadata, tuple(diagnostics))
    validation = validate_document(ReportSchema.VULNERABILITY_DETAIL, document)
    return CompiledVdtReport(
        document=document,
        vulnerabilities=tuple(records),
        accepted=tuple(accepted),
        diagnostics=tuple(diagnostics),
        validation=validation,
        metadata=metadata,
    )


# *--- Selection ---*


def _select_for_period(
    records: Sequence[CompiledVulnerability],
    period: tuple[datetime, datetime],
    diagnostics: list[ReportDiagnostic],
) -> tuple[list[CompiledVulnerability], list[AcceptedVulnerability], int]:
    """Split compiled records into reported, accepted, and excluded by period.

    `reportPeriod` is not a label. A vulnerability appears in the report for a period
    when it had activity in that period (VER-RPT-PER), with both bounds inclusive. Open
    KEV work stays in as well: under VDR-TFR-KEV a mitigated KEV is unresolved, so a
    record whose clock is open, detected and listed by the period end, is kept with no
    activity in the period (ADR 0012 Decision 7).

    An accepted record is set aside for the VER-RPT-AVI report of the same period only
    when that report would carry it, by the same activity rule (ADR 0010 Decision 2).
    One with no activity in the period is in neither report and is counted as excluded,
    so every record of the set lands in exactly one of the three Summary rows.
    """

    reported: list[CompiledVulnerability] = []
    accepted: list[AcceptedVulnerability] = []
    excluded = 0

    for record in records:
        if record.status is CaseStatus.ACCEPTED:
            reason = period_exclusion_reason(record, period, state="is accepted")
            if reason is not None:
                excluded += 1
                diagnostics.append(
                    ReportDiagnostic(
                        level=DiagnosticLevel.INFO,
                        code="excluded_by_period",
                        message=f"{record.label} {reason}",
                        location=record.source_record_id,
                    )
                )
                continue
            evaluation = record.evaluation
            rationale = evaluation.acceptance_rationale if evaluation else None
            accepted.append(
                AcceptedVulnerability(
                    vulnerability=record,
                    acceptance_rationale=rationale or "",
                )
            )
            diagnostics.append(
                ReportDiagnostic(
                    level=DiagnosticLevel.INFO,
                    code="accepted_excluded",
                    message=(
                        f"{record.label} is an accepted vulnerability and belongs in "
                        "the VER-RPT-AVI report, not the Vulnerability Detail Report"
                    ),
                    location=record.source_record_id,
                )
            )
            continue
        if _keeps_open_kev_work(record, period):
            reported.append(record)
            continue
        reason = period_exclusion_reason(record, period)
        if reason is not None:
            excluded += 1
            diagnostics.append(
                ReportDiagnostic(
                    level=DiagnosticLevel.INFO,
                    code="excluded_by_period",
                    message=f"{record.label} {reason}",
                    location=record.source_record_id,
                )
            )
            continue
        reported.append(record)
    return reported, accepted, excluded


def _keeps_open_kev_work(record: CompiledVulnerability, period: tuple[datetime, datetime]) -> bool:
    """Return whether an open KEV clock keeps a record in the Vulnerability Detail Report.

    The listing bound matters because nothing orders `as_of` against the period end: an
    August report compiled in September must not pull in a record that was quiet in
    August and became a KEV after it ended.
    """

    kev = record.kev
    if kev is None or kev.satisfied:
        return False
    period_to = period[1]
    if record.detected_at > period_to:
        return False
    return min(entry.date_added for entry in kev.entries) <= period_to.astimezone(UTC).date()


# *--- Document ---*


def _build_document(
    records: Sequence[CompiledVulnerability],
    metadata: ReportMetadata,
    diagnostics: Sequence[ReportDiagnostic],
) -> dict[str, Any]:
    options = metadata.options
    extension = common_extension(records, metadata, diagnostics)
    extension["excludedByPeriod"] = metadata.excluded_by_period
    return {
        "certificationPackageOverviewUri": options.package_uri,
        "reportPeriod": report_period_block(options),
        "vulnerabilities": [record.to_official_dict() for record in records],
        EXTENSION_KEY: extension,
    }


# --------------------------------------------------------------------------------------
# Markdown twin. Every number below comes from the compiled records, never from the JSON.
# --------------------------------------------------------------------------------------


def _render_markdown(report: CompiledVdtReport) -> str:
    metadata = report.metadata
    records = report.vulnerabilities
    lines: list[str] = []
    write = lines.append

    write_header(write, metadata.options, title="Vulnerability Detail Report", period=True)
    write_provenance(write, metadata)

    write("## Summary")
    write("")
    write("| Measure | Count |")
    write("|---|---:|")
    write(f"| Vulnerabilities reported | {len(records)} |")
    write(f"| Evaluated | {sum(1 for item in records if item.is_evaluated)} |")
    write(f"| Not yet evaluated | {sum(1 for item in records if not item.is_evaluated)} |")
    write(f"| Overdue | {sum(1 for item in records if item.is_overdue)} |")
    write_kev_summary(write, records, metadata.options)
    write(f"| Accepted, reported under VER-RPT-AVI | {len(report.accepted)} |")
    write(f"| Excluded by report period | {metadata.excluded_by_period} |")
    for rating in PainRating:
        count = sum(1 for item in records if item.current_rating is rating)
        write(f"| Current PAIN {rating.name} | {count} |")
    write("")

    write_vulnerability_table(
        write,
        records,
        heading="Vulnerabilities",
        empty_message="No open vulnerabilities were reported for this period.",
        details_heading="Vulnerability details",
        as_of=metadata.options.as_of,
    )
    write_attestation_section(write, records, metadata)
    write_inputs(write, metadata)
    write_coverage(write, metadata)
    write_changes(write, metadata)
    write_diagnostics_section(write, report.diagnostics)
    write_footer(write)
    return "\n".join(lines) + "\n"


__all__ = [
    "CompiledVdtReport",
    "compile_records",
    "compile_vdt_report",
    "project_vdt",
]
