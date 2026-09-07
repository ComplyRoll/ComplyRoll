"""Historical VER Activity report projection (VER-TFR-MRH, ADR 0010).

`project_historical` publishes the whole known population out of the record set at
one instant: every non-accepted record, disposed ones included, under
`activeVulnerabilities`, and every accepted record under `acceptedVulnerabilities`.
There is no report period and no selection, so the set's diagnostics are published
as they are and `generatedAt` is the run's `as_of`. Each record is its current state;
the per-case evaluation timeline has no slot in the official item and stays on
`complyroll cases history`. Because both paths read only current state, the stateless
compile and the rebuild from history produce the same bytes.

ComplyRoll does not schedule the retrieval cadence the rule sets; the operator does.
The Markdown twin is a rendering of the same data in a consistent human-readable form
(CDS-CSO-CBF). It is not the monthly human-readable report `VER-TFR-MHR`.
"""

from __future__ import annotations

import json
from collections.abc import Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from complyroll.models import CaseStatus, PainRating
from complyroll.schemas import ReportSchema, SchemaValidationResult

from .avi import _accepted_info
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
    _iso,
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


@dataclass(frozen=True, slots=True)
class CompiledHistoricalReport:
    """One compiled Historical VER Activity snapshot and its twin renderings.

    `active` and `accepted` together are every record the set held, each in record
    order, so the two arrays partition the population rather than sample it.
    """

    document: dict[str, Any]
    active: tuple[CompiledVulnerability, ...]
    accepted: tuple[AcceptedVulnerability, ...]
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

        return _render_historical_markdown(self)


def compile_historical_report(
    artifact_paths: Sequence[Path],
    *,
    options: ReportOptions,
    evaluations: EvaluationSet | None = None,
) -> CompiledHistoricalReport:
    """Compile one Historical VER Activity snapshot from artifacts and explicit inputs."""

    return project_historical(
        compile_record_set_from_artifacts(artifact_paths, options=options, evaluations=evaluations)
    )


def project_historical(record_set: CompiledRecordSet) -> CompiledHistoricalReport:
    """Project the Historical VER Activity snapshot out of one compiled record set.

    Nothing is selected: the records split on acceptance and every one is published.
    Only `options.as_of` is read; a period on the options is ignored rather than
    refused, so one `ReportOptions` can drive all three reports in a run. An accepted
    record with no acceptance rationale stops the run, since the official item
    requires one.
    """

    if not isinstance(record_set, CompiledRecordSet):
        raise TypeError("record_set must be a CompiledRecordSet")

    _require_acceptance_rationales(record_set.records)
    records = record_set.records
    active = tuple(item for item in records if item.status is not CaseStatus.ACCEPTED)
    accepted = tuple(_accepted(item) for item in records if item.status is CaseStatus.ACCEPTED)
    diagnostics = tuple(record_set.diagnostics)
    attested = tuple(
        sorted(item.tracking_id for item in records if item.detected_at_source == "attestation")
    )

    metadata = ReportMetadata(
        options=record_set.options,
        artifacts=record_set.artifacts,
        rules_provenance=record_set.rules_provenance,
        schema_provenance=_schema_provenance(ReportSchema.HISTORICAL_ACTIVITY),
        generator_version=record_set.generator_version,
        parser_versions=record_set.parser_versions,
        attestation_applied_to=attested,
        excluded_by_period=0,
        attestation_detected_at=_attested_instant(records),
    )
    document = _build_historical_document(records, active, accepted, metadata, diagnostics)
    validation = _validate_document(ReportSchema.HISTORICAL_ACTIVITY, document)
    return CompiledHistoricalReport(
        document=document,
        active=active,
        accepted=accepted,
        diagnostics=diagnostics,
        validation=validation,
        metadata=metadata,
    )


def _build_historical_document(
    records: Sequence[CompiledVulnerability],
    active: Sequence[CompiledVulnerability],
    accepted: Sequence[AcceptedVulnerability],
    metadata: ReportMetadata,
    diagnostics: Sequence[ReportDiagnostic],
) -> dict[str, Any]:
    """Build the official document; `records` is the whole population, for attestation."""

    options = metadata.options
    return {
        "certificationPackageOverviewUri": options.package_uri,
        "generatedAt": _iso(options.as_of),
        "activeVulnerabilities": [record.to_official_dict() for record in active],
        "acceptedVulnerabilities": [_accepted_info(item) for item in accepted],
        EXTENSION_KEY: _common_extension(records, metadata, diagnostics),
    }


def _render_historical_markdown(report: CompiledHistoricalReport) -> str:
    metadata = report.metadata
    active = report.active
    accepted = tuple(item.vulnerability for item in report.accepted)
    rationales = {
        item.vulnerability.tracking_id: item.acceptance_rationale for item in report.accepted
    }
    lines: list[str] = []
    write = lines.append

    _write_header(write, metadata.options, title="Historical VER Activity Report", period=False)
    _write_provenance(write, metadata)

    write("## Summary")
    write("")
    write("| Measure | Count |")
    write("|---|---:|")
    write(f"| Active vulnerabilities | {len(active)} |")
    write(f"| Accepted vulnerabilities | {len(accepted)} |")
    write(f"| Evaluated | {sum(1 for item in active if item.is_evaluated)} |")
    write(f"| Not yet evaluated | {sum(1 for item in active if not item.is_evaluated)} |")
    write(f"| Overdue | {sum(1 for item in active if item.is_overdue)} |")
    for rating in PainRating:
        count = sum(1 for item in active if item.current_rating is rating)
        write(f"| Current PAIN {rating.name} | {count} |")
    write("")

    _write_vulnerability_table(
        write,
        active,
        heading="Active vulnerabilities",
        empty_message="No active vulnerabilities are recorded.",
        details_heading="Active vulnerability details",
    )
    _write_vulnerability_table(
        write,
        accepted,
        heading="Accepted vulnerabilities",
        empty_message="No accepted vulnerabilities are recorded.",
        details_heading="Accepted vulnerability details",
        rationales=rationales,
    )
    _write_attestation_section(write, _population(report), metadata)
    _write_inputs(write, metadata)
    _write_diagnostics_section(write, report.diagnostics)
    _write_footer(write)
    return "\n".join(lines) + "\n"


def _population(report: CompiledHistoricalReport) -> tuple[CompiledVulnerability, ...]:
    """Return every record the report holds, for the sections that cover both arrays."""

    return report.active + tuple(item.vulnerability for item in report.accepted)


__all__ = ["CompiledHistoricalReport", "compile_historical_report", "project_historical"]
