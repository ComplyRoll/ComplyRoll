"""Accepted Vulnerability Information report projection (VER-RPT-AVI, ADR 0010).

`project_avi` reads the same record set the Vulnerability Detail Report projects from
and publishes the accepted records that had recorded activity in the report period.
Activity is the detection, the completed evaluation that carries the acceptance, each
completed PAIN reduction, and the projected next reduction; the instant a disposition
was written to the event store is not activity, so the stateless compile and the
rebuild from history select the same records. Non-accepted records are never in this
report. Only their count is published, so a reader can reconcile this document with
the Vulnerability Detail Report for the same period.

The Markdown twin is a rendering of the same data in a consistent human-readable form
(CDS-CSO-CBF). It is not the monthly human-readable report `VER-TFR-MHR`.
"""

from __future__ import annotations

import json
from collections.abc import Sequence
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Any

from complyroll.adapters import DiagnosticLevel
from complyroll.models import CaseStatus, PainRating
from complyroll.schemas import ReportSchema, SchemaValidationResult

from .evaluations import EvaluationSet
from .vdt import (
    EXTENSION_KEY,
    AcceptedVulnerability,
    CompiledRecordSet,
    CompiledVulnerability,
    ReportDiagnostic,
    ReportMetadata,
    ReportOptions,
    _accepted,
    _attested_instant,
    _common_extension,
    _period_exclusion_reason,
    _report_period,
    _report_period_block,
    _require_acceptance_rationales,
    _schema_provenance,
    _validate_document,
    _write_attestation_section,
    _write_diagnostics_section,
    _write_footer,
    _write_header,
    _write_inputs,
    _write_provenance,
    _write_vulnerability_table,
    compile_record_set_from_artifacts,
)

_REPORT_NAME = "the Accepted Vulnerability Information report"


@dataclass(frozen=True, slots=True)
class CompiledAviReport:
    """One compiled Accepted Vulnerability Information report and its twin renderings.

    `accepted` holds the records the document publishes, in record order.
    `active_not_reported` counts the non-accepted records the record set held; they
    belong to the Vulnerability Detail Report and appear here only as that count.
    """

    document: dict[str, Any]
    accepted: tuple[AcceptedVulnerability, ...]
    active_not_reported: int
    diagnostics: tuple[ReportDiagnostic, ...]
    validation: SchemaValidationResult
    metadata: ReportMetadata

    def to_json(self, indent: int = 2) -> str:
        """Return the official JSON document with a stable key order."""

        return (
            json.dumps(self.document, indent=indent, sort_keys=True, ensure_ascii=False) + "\n"
        )

    def to_markdown(self) -> str:
        """Return the human-readable twin, derived from the same records."""

        return _render_avi_markdown(self)


def compile_avi_report(
    artifact_paths: Sequence[Path],
    *,
    options: ReportOptions,
    evaluations: EvaluationSet | None = None,
) -> CompiledAviReport:
    """Compile one Accepted Vulnerability Information report from artifacts and inputs."""

    return project_avi(
        compile_record_set_from_artifacts(artifact_paths, options=options, evaluations=evaluations)
    )


def project_avi(record_set: CompiledRecordSet) -> CompiledAviReport:
    """Project the Accepted Vulnerability Information report out of one record set.

    The report period decides what is reported, with the same predicate the
    Vulnerability Detail Report applies to disposed records: an accepted record is in
    the report when it had recorded activity inside the inclusive bounds. Each accepted
    record left out gets an INFO diagnostic appended after the set's own. A record set
    whose options carry no period stops the run, and so does an accepted record with
    no acceptance rationale, since the official item requires one.
    """

    if not isinstance(record_set, CompiledRecordSet):
        raise TypeError("record_set must be a CompiledRecordSet")

    options = record_set.options
    period = _report_period(options, _REPORT_NAME)
    _require_acceptance_rationales(record_set.records)
    diagnostics = list(record_set.diagnostics)
    reported, excluded, active = _select_accepted(record_set.records, period, diagnostics)
    records = tuple(item.vulnerability for item in reported)
    attested = tuple(
        sorted(item.tracking_id for item in records if item.detected_at_source == "attestation")
    )

    metadata = ReportMetadata(
        options=options,
        artifacts=record_set.artifacts,
        rules_provenance=record_set.rules_provenance,
        schema_provenance=_schema_provenance(ReportSchema.ACCEPTED_VULNERABILITY),
        generator_version=record_set.generator_version,
        parser_versions=record_set.parser_versions,
        attestation_applied_to=attested,
        excluded_by_period=excluded,
        attestation_detected_at=_attested_instant(records),
    )
    document = _build_avi_document(
        tuple(reported), metadata, tuple(diagnostics), active_not_reported=active
    )
    validation = _validate_document(ReportSchema.ACCEPTED_VULNERABILITY, document)
    return CompiledAviReport(
        document=document,
        accepted=tuple(reported),
        active_not_reported=active,
        diagnostics=tuple(diagnostics),
        validation=validation,
        metadata=metadata,
    )


def _select_accepted(
    records: Sequence[CompiledVulnerability],
    period: tuple[datetime, datetime],
    diagnostics: list[ReportDiagnostic],
) -> tuple[list[AcceptedVulnerability], int, int]:
    """Split the record set into reported accepted records and two counts.

    Returns the accepted records with activity in the period, the number of accepted
    records the period left out, and the number of non-accepted records. Only the
    excluded accepted records get a diagnostic; the active ones are not a selection
    this report makes, so there is nothing per record to explain.
    """

    reported: list[AcceptedVulnerability] = []
    excluded = 0
    active = 0

    for record in records:
        if record.status is not CaseStatus.ACCEPTED:
            active += 1
            continue
        reason = _period_exclusion_reason(record, period, state="is accepted")
        if reason is not None:
            excluded += 1
            diagnostics.append(
                ReportDiagnostic(
                    level=DiagnosticLevel.INFO,
                    code="excluded_by_period",
                    message=f"{record.tracking_id} {reason}",
                    location=record.source_record_id,
                )
            )
            continue
        reported.append(_accepted(record))
    return reported, excluded, active


def _accepted_info(item: AcceptedVulnerability) -> dict[str, Any]:
    """Return the official `acceptedVulnerabilityInfo` object for one accepted record.

    The extension stays inside `vulnerabilityDetail`, where every projection publishes
    it; the wrapping item carries only the two official members (ADR 0010 Decision 1).
    """

    return {
        "vulnerabilityDetail": item.vulnerability.to_official_dict(),
        "acceptanceRationale": item.acceptance_rationale,
    }


def _build_avi_document(
    accepted: Sequence[AcceptedVulnerability],
    metadata: ReportMetadata,
    diagnostics: Sequence[ReportDiagnostic],
    *,
    active_not_reported: int,
) -> dict[str, Any]:
    options = metadata.options
    records = tuple(item.vulnerability for item in accepted)
    extension = _common_extension(records, metadata, diagnostics)
    extension["excludedByPeriod"] = metadata.excluded_by_period
    extension["activeNotReported"] = active_not_reported
    return {
        "certificationPackageOverviewUri": options.package_uri,
        "reportPeriod": _report_period_block(options),
        "acceptedVulnerabilities": [_accepted_info(item) for item in accepted],
        EXTENSION_KEY: extension,
    }


def _render_avi_markdown(report: CompiledAviReport) -> str:
    metadata = report.metadata
    records = tuple(item.vulnerability for item in report.accepted)
    rationales = {
        item.vulnerability.tracking_id: item.acceptance_rationale for item in report.accepted
    }
    lines: list[str] = []
    write = lines.append

    _write_header(
        write,
        metadata.options,
        title="Accepted Vulnerability Information Report",
        period=True,
    )
    _write_provenance(write, metadata)

    write("## Summary")
    write("")
    write("| Measure | Count |")
    write("|---|---:|")
    write(f"| Accepted vulnerabilities reported | {len(records)} |")
    write(f"| Excluded by report period | {metadata.excluded_by_period} |")
    write(f"| Active, not reported here | {report.active_not_reported} |")
    write(f"| Overdue | {sum(1 for item in records if item.is_overdue)} |")
    for rating in PainRating:
        count = sum(1 for item in records if item.current_rating is rating)
        write(f"| Current PAIN {rating.name} | {count} |")
    write("")

    _write_vulnerability_table(
        write,
        records,
        heading="Accepted vulnerabilities",
        empty_message="No accepted vulnerabilities had recorded activity in this period.",
        details_heading="Accepted vulnerability details",
        rationales=rationales,
    )
    _write_attestation_section(write, records, metadata)
    _write_inputs(write, metadata)
    _write_diagnostics_section(write, report.diagnostics)
    _write_footer(write)
    return "\n".join(lines) + "\n"


__all__ = ["CompiledAviReport", "compile_avi_report", "project_avi"]
