# ******************************************************************************
# *Title: Report Projection*
# *Author: Kyle Versluis*
# *Description: Period, acceptance and document helpers the reports share.*
# ******************************************************************************
"""Period, acceptance, extension block and schema check helpers the projections share."""

# *--- Imports ---*

from __future__ import annotations

from collections.abc import Sequence
from datetime import UTC, datetime
from typing import Any

from complyroll.adapters import DiagnosticLevel
from complyroll.models import CaseStatus
from complyroll.schemas import (
    ReportSchema,
    SchemaProvenance,
    SchemaValidationResult,
    load_bundled_schema_bundle,
    validate_bundled_report,
)

from .model import (
    DISCLAIMER,
    GENERATOR_NAME,
    AcceptedVulnerability,
    CompiledVulnerability,
    ReportCompileError,
    ReportDiagnostic,
    ReportMetadata,
    ReportOptions,
    iso,
)

# *--- Attestation ---*


def attested_instant(records: Sequence[CompiledVulnerability]) -> datetime | None:
    """Return the one instant every attested record shares, or None if they differ.

    The instant is read off the record, never looked up again by identifier. An
    operator's `trackingId` override renames a record after its detection time is
    resolved, so `record.tracking_id` is no longer a key into the attestation map
    while `record.original_tracking_id` is; resolving the shared instant from the
    resolved records leaves no key to get wrong. `attestation_groups` reads the same
    field, so the scalar form and the grouped form describe one set of facts.
    """

    instants = {
        record.detected_at for record in records if record.detected_at_source == "attestation"
    }
    if len(instants) != 1:
        return None
    return next(iter(instants))


def attestation_groups(
    records: Sequence[CompiledVulnerability],
) -> tuple[tuple[datetime, tuple[str, ...]], ...]:
    """Group the attested records by the instant attested for each, earliest first.

    Both renderings read this, so the JSON block and the Markdown twin can never
    describe different groupings of the same records.
    """

    grouped: dict[datetime, list[str]] = {}
    for record in records:
        if record.detected_at_source != "attestation":
            continue
        grouped.setdefault(record.detected_at, []).append(record.tracking_id)
    return tuple(
        (instant, tuple(sorted(tracking_ids))) for instant, tracking_ids in sorted(grouped.items())
    )


# *--- Period and Acceptance ---*


def report_period(options: ReportOptions, report_name: str) -> tuple[datetime, datetime]:
    """Return the period a report selects by, or stop the run when there is none.

    A periodless `ReportOptions` is legitimate input for the historical activity
    report, so the options do not refuse it. A report that selects by period turns
    the absence into a compile diagnostic here, named after the report that needs
    it, rather than an attribute error deep inside selection.
    """

    if options.has_period:
        return options.period
    raise ReportCompileError(
        (
            ReportDiagnostic(
                level=DiagnosticLevel.ERROR,
                code="report_period_missing",
                message=(
                    f"{report_name} selects records by report period, so period_from "
                    "and period_to are required"
                ),
            ),
        )
    )


def require_acceptance_rationales(records: Sequence[CompiledVulnerability]) -> None:
    """Stop the run when an accepted record carries no acceptance rationale.

    The official `acceptedVulnerabilityInfo` item requires `acceptanceRationale`, and
    an empty string would satisfy the schema while saying nothing. Only the reports
    that publish accepted records call this (ADR 0010 Decision 4); the Vulnerability
    Detail Report sets accepted records aside and does not need the rationale. Every
    offending record is named in one error, in record order, so an operator fixes
    the file once.
    """

    errors = [
        ReportDiagnostic(
            level=DiagnosticLevel.ERROR,
            code="acceptance_rationale_missing",
            message=(
                f"{record.label} is accepted but its evaluation records no "
                "acceptance rationale, which the accepted vulnerability report requires"
            ),
            location=record.source_record_id,
        )
        for record in records
        if record.status is CaseStatus.ACCEPTED and not _acceptance_rationale(record)
    ]
    if errors:
        raise ReportCompileError(errors)


def _acceptance_rationale(record: CompiledVulnerability) -> str | None:
    """Return the record's acceptance rationale, or None when missing or blank."""

    evaluation = record.evaluation
    rationale = evaluation.acceptance_rationale if evaluation is not None else None
    if rationale is None or not rationale.strip():
        return None
    return rationale


def accepted_vulnerability(record: CompiledVulnerability) -> AcceptedVulnerability:
    """Pair an accepted record with the rationale its evaluation recorded.

    Only the reports that publish accepted vulnerabilities call this, and only after
    they have checked that every accepted record carries a rationale, so a missing one
    here is a programming error rather than an input error.
    """

    rationale = _acceptance_rationale(record)
    if rationale is None:  # pragma: no cover - callers guard before reaching here
        raise AssertionError(f"{record.tracking_id} is accepted with no acceptance rationale")
    return AcceptedVulnerability(vulnerability=record, acceptance_rationale=rationale)


def period_exclusion_reason(
    record: CompiledVulnerability,
    period: tuple[datetime, datetime],
    *,
    state: str | None = None,
) -> str | None:
    """Return why a record falls outside the report period, or None if it belongs.

    `state` is how the message names the record's standing when it had no activity in
    the period. The Vulnerability Detail Report leaves it unset and the message reads
    the record's disposition; a report that only selects accepted records passes the
    standing that applies to all of them.
    """

    period_from, period_to = period
    if record.detected_at > period_to:
        return f"was detected {iso(record.detected_at)}, after the period ended {iso(period_to)}"
    if not record.has_disposition:
        return None
    if any(period_from <= instant <= period_to for instant in record.activity_instants):
        return None
    if state is None:
        state = f"has disposition {record.final_disposition!r}"
    return f"{state} and no recorded activity between {iso(period_from)} and {iso(period_to)}"


# *--- Document ---*


def schema_provenance(report_schema: ReportSchema) -> SchemaProvenance:
    """Describe the bundled schema one report is validated against and published with."""

    bundle = load_bundled_schema_bundle()
    document = bundle.document(report_schema.value)
    return SchemaProvenance(
        repository=bundle.manifest.repository,
        commit=bundle.manifest.commit,
        schema_id=document.entry.schema_id,
        schema_version=document.entry.version,
        schema_sha256=document.content_sha256,
    )


def validate_document(
    report_schema: ReportSchema,
    document: dict[str, Any],
) -> SchemaValidationResult:
    """Validate one compiled document against its bundled schema, or stop the run.

    A document that fails here was built by ComplyRoll from inputs that already
    passed their own checks, so the failure is a defect in the compiler and the run
    ends with the validator's own findings rather than an invalid report on disk.
    """

    validation = validate_bundled_report(report_schema, document)
    if not validation.is_valid:
        raise ReportCompileError(
            tuple(
                ReportDiagnostic(
                    level=DiagnosticLevel.ERROR,
                    code="schema_invalid",
                    message=(
                        "the compiled report failed official schema validation, which is a "
                        f"ComplyRoll defect: {issue.validator}: {issue.message}"
                    ),
                    location=issue.instance_pointer or "<root>",
                )
                for issue in validation.issues
            )
        )
    return validation


def common_extension(
    records: Sequence[CompiledVulnerability],
    metadata: ReportMetadata,
    diagnostics: Sequence[ReportDiagnostic],
) -> dict[str, Any]:
    """Build the `x-complyroll` block every report shares.

    Each projection adds its own counters on top. The keys are sorted when the JSON is
    written, so where a projection inserts them does not reach the bytes.
    """

    options = metadata.options
    extension: dict[str, Any] = {
        "generator": {"name": GENERATOR_NAME, "version": metadata.generator_version},
        "generatedAt": iso(options.as_of),
        "calendarTimezone": options.calendar_timezone,
        "certificationClass": options.certification_class.value,
        "rulesSource": {
            "repository": metadata.rules_provenance.repository,
            "commit": metadata.rules_provenance.commit,
            "datasetVersion": metadata.rules_provenance.dataset_version,
            "datasetLastUpdated": metadata.rules_provenance.dataset_last_updated,
            "sha256": metadata.rules_provenance.dataset_sha256,
        },
        "schemaSource": {
            "repository": metadata.schema_provenance.repository,
            "commit": metadata.schema_provenance.commit,
            "schemaId": metadata.schema_provenance.schema_id,
            "schemaVersion": metadata.schema_provenance.schema_version,
            "sha256": metadata.schema_provenance.schema_sha256,
        },
        "parserVersions": dict(metadata.parser_versions),
        "artifacts": [artifact.to_dict() for artifact in metadata.artifacts],
        "detectionTimeAttestation": _attestation_block(records, metadata),
        "diagnostics": [diagnostic.to_dict() for diagnostic in diagnostics],
        "disclaimer": DISCLAIMER,
    }
    # Only a run that recorded a detection process failure carries the key, so a report
    # compiled without one is byte-identical to one compiled before it existed.
    if metadata.detection_failures:
        extension["detectionFailures"] = [item.to_dict() for item in metadata.detection_failures]
    catalog = options.kev_catalog
    if catalog is not None:
        extension["kevSource"] = {
            "name": catalog.name,
            "sha256": catalog.sha256,
            "sizeBytes": catalog.size_bytes,
            "catalogVersion": catalog.catalog_version,
            "dateReleased": iso(catalog.date_released),
            "count": catalog.declared_count,
            "entriesConsidered": catalog.considered(options.as_of.astimezone(UTC).date()),
        }
    # Only a run given an inventory carries the key, so every report compiled without one
    # is byte-identical to one compiled before coverage existed (ADR 0015).
    if metadata.coverage is not None:
        extension["coverage"] = metadata.coverage.to_dict(gap_records=metadata.coverage_gap_records)
    # Only a run given a change file carries the key, so a run without one moves no byte
    # (ADR 0018).
    if metadata.changes is not None:
        extension["changes"] = metadata.changes.to_dict()
    return extension


def report_period_block(options: ReportOptions) -> dict[str, str]:
    """Build the official `reportPeriod` object from options that carry a period."""

    period_from, period_to = options.period
    return {"from": iso(period_from), "to": iso(period_to)}


def _attestation_block(
    records: Sequence[CompiledVulnerability],
    metadata: ReportMetadata,
) -> dict[str, Any] | None:
    """Return the `detectionTimeAttestation` object, or None when none was needed.

    One shared instant publishes the scalar form the stateless path has always
    emitted. Differing instants, reachable only when history attested cases
    separately, publish one entry per instant instead: a single report-level
    `detectedAt` would be a false statement about the records it does not cover, so
    there is no scalar key at all (ADR 0008 amendment).
    """

    applied_to = metadata.attestation_applied_to
    if not applied_to:
        return None
    shared = metadata.attestation
    if shared is not None:
        return {
            "detectedAt": iso(shared),
            "appliedTo": list(applied_to),
            "count": len(applied_to),
        }
    return {
        "appliedTo": list(applied_to),
        "count": len(applied_to),
        "attestations": [
            {"detectedAt": iso(instant), "appliedTo": list(tracking_ids)}
            for instant, tracking_ids in attestation_groups(records)
        ],
    }


__all__ = [
    "accepted_vulnerability",
    "attestation_groups",
    "attested_instant",
    "common_extension",
    "period_exclusion_reason",
    "report_period",
    "report_period_block",
    "require_acceptance_rationales",
    "schema_provenance",
    "validate_document",
]
