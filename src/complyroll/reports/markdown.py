# ******************************************************************************
# *Title: Report Markdown*
# *Author: Kyle Versluis*
# *Description: Section writers the three Markdown twins share.*
# ******************************************************************************
"""The section writers the three Markdown twins share, read from compiled records."""

# *--- Imports ---*

from __future__ import annotations

from collections.abc import Callable, Mapping, Sequence
from datetime import UTC, datetime

from complyroll.models import CaseStatus, ResourceRef

from .changes import (
    CHANGE_BASIS,
    DAC_RULE,
    ChangeObligation,
    ChangeProjection,
    StoredChangeSet,
)
from .changes_input import Change, ChangeSet
from .coverage import (
    COVERAGE_BASIS,
    CoverageEvidence,
    CoverageStatus,
    ResourceCoverage,
    coverage_label,
)
from .gaps import COVERAGE_GAP_SOURCE_TYPE
from .kev import KevClock, KevStatus
from .model import (
    DISCLAIMER,
    GENERATOR_NAME,
    CompiledDetectionFailure,
    CompiledVulnerability,
    ReportDiagnostic,
    ReportMetadata,
    ReportOptions,
    iso,
)
from .projection import attestation_groups

# *--- Configuration ---*

#: The Windows subsection of a gap-aware run opens with this, since a recorded window can
#: name a record the report does not list (ADR 0015).
_RECORDED_WINDOW_NOTE = (
    "A recorded window is a VDR-CSO-FAV system record of this run and names its tracking ID "
    "here even when this report does not select the record, such as one detected after the "
    "report period."
)


# *--- Section Writers ---*


def write_kev_summary(
    write: Callable[[str], None],
    records: Sequence[CompiledVulnerability],
    options: ReportOptions,
) -> None:
    """Write the two KEV Summary rows, which a report carries only with a catalog.

    `records` is the population the report's Overdue row counts, so the two rows sit
    beside it: an accepted record past its KEV due date is counted here and never there.
    """

    if options.kev_catalog is None:
        return
    known = sum(1 for item in records if item.kev is not None)
    past_due = sum(1 for item in records if item.kev is not None and item.kev.past_due)
    write(f"| Known exploited, CISA KEV | {known} |")
    write(f"| Past a CISA KEV due date | {past_due} |")


def write_header(
    write: Callable[[str], None],
    options: ReportOptions,
    *,
    title: str,
    period: bool,
) -> None:
    """Open a Markdown twin with its title and the run's identifying inputs.

    `period` is False for the report that has no period, so the line is left out
    rather than printed empty.
    """

    write(f"# {title}")
    write("")
    write(f"- **Certification package:** {_cell(options.package_uri)}")
    if period:
        period_from, period_to = options.period
        write(f"- **Report period:** {iso(period_from)} to {iso(period_to)}")
    write(f"- **Certification class:** {options.certification_class.value}")
    write(f"- **Generated at:** {iso(options.as_of)}")
    write(f"- **Calendar timezone:** {_cell(options.calendar_timezone)}")
    write("")


def write_provenance(write: Callable[[str], None], metadata: ReportMetadata) -> None:
    write("## Provenance")
    write("")
    write("| Source | Reference | Digest |")
    write("|---|---|---|")
    rules = metadata.rules_provenance
    schema = metadata.schema_provenance
    write(
        f"| Rules dataset | {_cell(rules.repository)} at {rules.commit} "
        f"(version {_cell(rules.dataset_version)}, updated {_cell(rules.dataset_last_updated)}) "
        f"| {rules.dataset_sha256} |"
    )
    write(
        f"| Report schema | {_cell(schema.repository)} at {schema.commit} "
        f"({_cell(schema.schema_id)} version {_cell(schema.schema_version)}) "
        f"| {schema.schema_sha256} |"
    )
    catalog = metadata.options.kev_catalog
    if catalog is not None:
        considered = catalog.considered(metadata.options.as_of.astimezone(UTC).date())
        write(
            f"| KEV catalog | {_cell(catalog.name)}, CISA KEV catalog version "
            f"{_cell(catalog.catalog_version)}, released {iso(catalog.date_released)}, "
            f"{considered} entries | {catalog.sha256} |"
        )
    write(f"| Generator | {GENERATOR_NAME} {_cell(metadata.generator_version)} | n/a |")
    write("")


def _vulnerability_row(item: CompiledVulnerability) -> str:
    """Render one record as a row of the shared vulnerability table."""

    evaluation = item.evaluation
    next_due = item.next_due
    return (
        "| "
        + " | ".join(
            (
                _cell(item.tracking_id),
                _cell(item.source_record_id),
                str(len(item.resources)),
                iso(item.detected_at),
                iso(evaluation.completed_at) if evaluation else "n/a",
                _flag(evaluation.is_internet_reachable) if evaluation else "n/a",
                _flag(evaluation.is_likely_exploitable) if evaluation else "n/a",
                item.current_rating.name if item.current_rating else "n/a",
                (f"{iso(next_due.due_at)} ({_cell(next_due.rule_id)})" if next_due else "n/a"),
                _flag(item.is_overdue),
                _cell(_disposition_label(item)),
            )
        )
        + " |"
    )


def write_vulnerability_table(
    write: Callable[[str], None],
    records: Sequence[CompiledVulnerability],
    *,
    heading: str,
    empty_message: str,
    details_heading: str,
    as_of: datetime,
    rationales: Mapping[str, str] | None = None,
) -> None:
    """Write one table of records followed by their detail sections.

    An empty table is one sentence under the heading and no details heading at all.
    `rationales` maps tracking identifiers to acceptance rationales for the tables
    that publish accepted records; the detail section prints the rationale when the
    record has one. `as_of` is the run's instant, which the KEV line reads (ADR 0012).
    """

    write(f"## {heading}")
    write("")
    if not records:
        write(empty_message)
        write("")
        return
    write(
        "| Tracking ID | Source record | Resources | Detected | Evaluation completed "
        "| IRV | LEV | PAIN | Next due | Overdue | Disposition |"
    )
    write("|---|---|---:|---|---|---|---|---|---|---|---|")
    for item in records:
        write(_vulnerability_row(item))
    write("")

    write(f"## {details_heading}")
    write("")
    for item in records:
        rationale = None if rationales is None else rationales.get(item.tracking_id)
        _write_detail(write, item, as_of=as_of, acceptance_rationale=rationale)


def write_attestation_section(
    write: Callable[[str], None],
    records: Sequence[CompiledVulnerability],
    metadata: ReportMetadata,
) -> None:
    write("## Detection time attestation")
    write("")
    attested = metadata.attestation_applied_to
    attestation = metadata.attestation
    system_types = {item.source_type for item in records if item.detected_at_source == "system"}
    if not attested and system_types:
        write(_system_detection_sentence(system_types))
    elif not attested:
        write(
            "Every reported vulnerability carried a detection time from its source artifact. "
            "No attestation was needed."
        )
    elif attestation is None:
        write(
            "The operator attested per-case detection times for "
            f"{len(attested)} vulnerability record(s) whose source artifacts declare no "
            "assessment timestamp. ComplyRoll never substitutes file modification or "
            "ingestion time for a detection time."
        )
        write("")
        for instant, tracking_ids in attestation_groups(records):
            write(f"- **{iso(instant)}:** {', '.join(_cell(value) for value in tracking_ids)}")
    else:
        write(
            f"The operator attested a detection time of {iso(attestation)} for "
            f"{len(attested)} vulnerability record(s) whose source artifacts declare no "
            "assessment timestamp. ComplyRoll never substitutes file modification or "
            "ingestion time for a detection time."
        )
    write("")


def _system_detection_sentence(source_types: set[str]) -> str:
    """Say what timed each kind of system record; a failure-only run reads as it always has."""

    clauses = []
    if source_types - {COVERAGE_GAP_SOURCE_TYPE}:
        clauses.append(
            "for a detection process failure, from the instant ComplyRoll or the scanner "
            "recorded it"
        )
    if COVERAGE_GAP_SOURCE_TYPE in source_types:
        clauses.append("for a coverage gap, from the instant its coverage window closed")
    return (
        "Every reported vulnerability carried a detection time from its source artifact or, "
        + " and, ".join(clauses)
        + ". No attestation was needed."
    )


def write_inputs(write: Callable[[str], None], metadata: ReportMetadata) -> None:
    write("## Inputs")
    write("")
    write("| Artifact | SHA-256 | Parser | Observations |")
    write("|---|---|---|---:|")
    for artifact in metadata.artifacts:
        write(
            f"| {_cell(artifact.name)} | {artifact.sha256[:12]} | "
            f"{_cell(artifact.parser)} {_cell(artifact.parser_version)} "
            f"| {artifact.observation_count} |"
        )
    write("")
    _write_detection_failures(write, metadata.detection_failures)


def _write_detection_failures(
    write: Callable[[str], None],
    failures: Sequence[CompiledDetectionFailure],
) -> None:
    """Write the Inputs subsection listing each detection process failure, if any.

    A failed artifact is not in the Inputs table, which lists what was read, so this is
    where a reader finds it. Nothing is written when the run recorded no failure.
    """

    if not failures:
        return
    write("### Detection process failures")
    write("")
    write("| Artifact | SHA-256 | Parser | Class | Observed at | Clock | Tracking ID |")
    write("|---|---|---|---|---|---|---|")
    for item in failures:
        write(
            f"| {_cell(item.name)} | {_cell(item.sha256[:12])} "
            f"| {_cell(item.parser)} {_cell(item.parser_version)} "
            f"| {_cell(item.failure_class)} | {_cell(iso(item.observed_at))} "
            f"| {_cell(item.clock)} | {_cell(item.tracking_id)} |"
        )
    write("")


# *--- Coverage ---*


def write_coverage(write: Callable[[str], None], metadata: ReportMetadata) -> None:
    """Write the Coverage section, the twin of `x-complyroll.coverage` (ADR 0015).

    Every summary row, resource, clock, window, unregistered resource and piece of listed
    evidence the block carries is written here, from the same coverage result. Nothing is
    written when the run was given no inventory.
    """

    coverage = metadata.coverage
    if coverage is None:
        return
    inventory = coverage.inventory
    write("## Coverage")
    write("")
    write(
        f"Coverage of the inventory {_cell(inventory.name)} ({inventory.entry_count} entries, "
        f"{inventory.size_bytes} bytes, SHA-256 {inventory.sha256}) as of "
        f"{iso(coverage.as_of)}, with clocks from rules dataset commit "
        f"{metadata.rules_provenance.commit}."
    )
    write("")
    write(COVERAGE_BASIS)
    write("")

    write("### Coverage by rule")
    write("")
    write("| Rule | Force | Expected | Current | Stale | Missing | Unanchored | Undetermined |")
    write("|---|---|---:|---:|---:|---:|---:|---:|")
    for row in coverage.summary:
        write(
            f"| {row.rule_id} | {row.force.value} | {row.expected} | {row.current} "
            f"| {row.stale} | {row.missing} | {row.unanchored} | {row.undetermined} |"
        )
    write("")

    write("### Resources")
    write("")
    write(
        "| Resource | Kind | Aliases | Drift likely | Sample group | Job | Expected since "
        "| Decommissioned | Last examined | Last verified | Examined | Untimed | Clocks |"
    )
    write("|---|---|---|---|---|---|---|---|---|---|---:|---:|---|")
    for resource in coverage.resources:
        write(_coverage_resource_row(resource))
    write("")

    write("### Clocks")
    write("")
    write(
        "| Resource | Rule | Force | Status | Anchor | Anchored at | Due at | Evidence | Stand-in |"
    )
    write("|---|---|---|---|---|---|---|---|---|")
    for resource in coverage.resources:
        label = _cell(coverage_label(resource.entry.ref))
        for clock in resource.clocks:
            write(
                f"| {label} | {clock.rule_id} | {clock.force.value} | {clock.status.value} "
                f"| {'n/a' if clock.anchor is None else clock.anchor.value} "
                f"| {_optional_iso(clock.anchor_at)} | {_optional_iso(clock.due_at)} "
                f"| {_coverage_evidence(clock.evidence)} | {_coverage_ref(clock.stand_in)} |"
            )
    write("")

    write("### Windows")
    write("")
    # Only a gap-aware run grows the table, so every earlier twin keeps its bytes.
    gap_records = metadata.coverage_gap_records
    if not coverage.windows:
        write("No window closed without a verification.")
    else:
        header = (
            "| Rule | Context | Force | Anchor | Anchored at | Closed at | Resumed at "
            "| Evidence | Stand-in |"
        )
        rule = "|---|---|---|---|---|---|---|---|---|"
        if gap_records is not None:
            write(_RECORDED_WINDOW_NOTE)
            write("")
            header += " Recorded | Tracking ID |"
            rule += "---|---|"
        write(header)
        write(rule)
        for window in coverage.windows:
            line = (
                f"| {window.rule_id} | {_cell(window.context_key)} | {window.force.value} "
                f"| {window.anchor.value} | {iso(window.anchor_at)} | {iso(window.closed_at)} "
                f"| {_optional_iso(window.resumed_at)} | {_coverage_evidence(window.evidence)} "
                f"| {_coverage_ref(window.stand_in)} |"
            )
            if gap_records is not None:
                tracking_id = gap_records[window]
                recorded = "no" if tracking_id is None else "yes"
                line += f" {recorded} | {_cell(tracking_id or 'n/a')} |"
            write(line)
    write("")

    write("### Unregistered resources")
    write("")
    if not coverage.unregistered:
        write("Every observed resource is in the inventory.")
    else:
        write("| Resource | Observations |")
        write("|---|---:|")
        for item in coverage.unregistered:
            write(f"| {_coverage_ref(item.resource)} | {item.observations} |")
    write("")

    _write_coverage_evidence(
        write,
        "Untimed evidence",
        "No inventory resource has untimed evidence.",
        [(resource, resource.untimed) for resource in coverage.resources],
    )
    _write_coverage_evidence(
        write,
        "Evidence after decommissioning",
        "No evidence was observed after a resource was decommissioned.",
        [(resource, resource.after_decommission) for resource in coverage.resources],
    )
    write("### Evidence after as-of")
    write("")
    if not coverage.later:
        write("No evidence was observed after as-of.")
    for evidence in coverage.later:
        write(f"- {_coverage_evidence(evidence)}")
    write("")


def _coverage_resource_row(resource: ResourceCoverage) -> str:
    """Render one resource row; a missing clock names the untimed evidence beside it."""

    entry = resource.entry
    untimed = len(resource.untimed)
    statuses = []
    for clock in resource.clocks:
        status = f"{clock.rule_id} {clock.force.value} {clock.status.value}"
        if clock.status is CoverageStatus.MISSING and untimed:
            status += f" ({untimed} untimed)"
        statuses.append(status)
    aliases = ", ".join(_coverage_ref(alias) for alias in entry.aliases) or "n/a"
    return (
        "| "
        + " | ".join(
            (
                _cell(coverage_label(entry.ref)),
                "attested" if resource.attested else "machine",
                aliases,
                _drift_label(entry.drift_likely),
                _cell(entry.sample_group or "n/a"),
                _cell(entry.job or "n/a"),
                iso(entry.expected_since),
                _optional_iso(entry.decommissioned_at),
                _optional_iso(resource.last_examined),
                _optional_iso(resource.last_verified),
                str(resource.examined_observations),
                str(untimed),
                "; ".join(statuses),
            )
        )
        + " |"
    )


def _write_coverage_evidence(
    write: Callable[[str], None],
    heading: str,
    empty_message: str,
    listed: Sequence[tuple[ResourceCoverage, Sequence[CoverageEvidence]]],
) -> None:
    """Write one evidence list, one line per resource that has any."""

    write(f"### {heading}")
    write("")
    lines = [
        f"- **{_cell(coverage_label(resource.entry.ref))}:** "
        + "; ".join(_coverage_evidence(item) for item in evidence)
        for resource, evidence in listed
        if evidence
    ]
    for line in lines or [empty_message]:
        write(line)
    write("")


def _coverage_evidence(evidence: CoverageEvidence | None) -> str:
    """Name one piece of evidence: the observation fingerprint, or the attested reference."""

    if evidence is None:
        return "n/a"
    if evidence.disposition is None:
        text = f"attested: {_cell(evidence.reference)}"
    else:
        text = f"observation {evidence.reference} ({evidence.disposition.value})"
    text += f" on {_coverage_ref(evidence.resource)}"
    return text + (", untimed" if evidence.at is None else f" at {iso(evidence.at)}")


def _coverage_ref(ref: ResourceRef | None) -> str:
    return "n/a" if ref is None else _cell(coverage_label(ref))


def _drift_label(value: bool | str | None) -> str:
    if value is None:
        return "n/a"
    if isinstance(value, bool):
        return _flag(value)
    return _cell(value)


def _optional_iso(value: datetime | None) -> str:
    return "n/a" if value is None else iso(value)


# *--- Changes ---*


def write_changes(write: Callable[[str], None], metadata: ReportMetadata) -> None:
    """Write the Changes section, the twin of `x-complyroll.changes` (ADR 0018).

    Every summary count, declared change, obligation, unregistered resource and later change
    the block carries is written here, from the same projection. Nothing is written when the
    run was given no change file.
    """

    changes = metadata.changes
    if changes is None:
        return
    write("## Changes")
    write("")
    write(
        f"{_changes_provenance(changes.change_set)}, read against the "
        f"inventory with SHA-256 {changes.inventory.sha256} as of {iso(changes.as_of)}, under "
        f"{DAC_RULE} ({_force_text(changes)}) from rules dataset commit "
        f"{changes.provenance.commit}."
    )
    write("")
    write(CHANGE_BASIS)
    write("")

    write("### Obligations by status")
    write("")
    write("| Status | Obligations |")
    write("|---|---:|")
    for status, count in changes.summary.items():
        write(f"| {status.value} | {count} |")
    write("")

    write("### Declared changes")
    write("")
    if not changes.declared:
        write("No change occurred at or before as-of.")
    else:
        write(
            "| Change | Kind | Occurred at | Source | Significant | Rationale | Detect by | Job "
            "| Force |"
        )
        write("|---|---|---|---|---|---|---|---|---|")
        for change in changes.declared:
            write(_declared_change_row(change, changes))
    write("")

    write("### Obligations")
    write("")
    if not changes.obligations:
        write("No obligation is measured at this as-of.")
    else:
        write(
            "| Change | Resource | Entry | Sample group | Matched as | Status | Force | Evidence "
            "| Stand-in | Lag seconds | Age seconds | Late | Window closed | Resumed | Untimed "
            "| KEV at activation | KEV tracking IDs |"
        )
        write("|---|---|---|---|---|---|---|---|---|---:|---:|---|---|---|---:|---|---|")
        for row in changes.obligations:
            write(_change_obligation_row(row, changes))
    write("")

    write("### Unregistered resources")
    write("")
    if not changes.unregistered:
        write("Every resource a change names is in the inventory.")
    else:
        write("| Resource | Changes |")
        write("|---|---|")
        for item in changes.unregistered:
            names = ", ".join(_cell(value) for value in item.change_ids)
            write(f"| {_coverage_ref(item.resource)} | {names} |")
    write("")

    write("### Changes after as-of")
    write("")
    if not changes.later:
        write("No change occurred after as-of.")
    else:
        write("| Change | Occurred at | Resources |")
        write("|---|---|---|")
        for change in changes.later:
            resources = ", ".join(_coverage_ref(ref) for ref in change.resources)
            write(f"| {_cell(change.change_id)} | {iso(change.occurred_at)} | {resources} |")
    write("")


def _changes_provenance(change_set: ChangeSet | StoredChangeSet) -> str:
    """Word where the changes came from, the twin of the block's `input` (ADR 0018)."""
    if isinstance(change_set, StoredChangeSet):
        counted = ", ".join(
            f"{count} from SHA-256 {digest}" for digest, count in change_set.digest_counts
        )
        return f"Changes recorded in the store ({change_set.change_count} changes: {counted})"
    return (
        f"Changes declared in {_cell(change_set.name)} ({change_set.change_count} changes, "
        f"{change_set.size_bytes} bytes, SHA-256 {change_set.sha256})"
    )


def _force_text(changes: ChangeProjection) -> str:
    """Word the rule's force, which no rule states only on a store holding no change."""
    return changes.force_value or "n/a"


def _declared_change_row(change: Change, changes: ChangeProjection) -> str:
    return (
        "| "
        + " | ".join(
            (
                _cell(change.change_id),
                change.kind.value,
                iso(change.occurred_at),
                _cell(f"{change.source.tool}: {change.source.reference}"),
                _flag(change.significant),
                _cell(change.rationale),
                _optional_iso(change.detect_by),
                _cell(change.job or "n/a"),
                _force_text(changes),
            )
        )
        + " |"
    )


def _change_obligation_row(row: ChangeObligation, changes: ChangeProjection) -> str:
    kev = row.kev_at_activation
    return (
        "| "
        + " | ".join(
            (
                _cell(row.change.change_id),
                _coverage_ref(row.resource),
                _coverage_ref(None if row.entry is None else row.entry.ref),
                _cell(row.sample_group or "n/a"),
                _coverage_ref(row.matched_as),
                row.status.value,
                _force_text(changes),
                _coverage_evidence(row.evidence),
                _coverage_ref(row.stand_in),
                _optional_int(row.lag_seconds),
                _optional_int(row.age_seconds(changes.as_of)),
                _flag(row.late),
                _optional_iso(row.window_closed_at),
                _optional_iso(row.resumed_at),
                str(row.untimed),
                "n/a" if kev is None else _flag(kev),
                ", ".join(_cell(value) for value in row.kev_tracking_ids) or "n/a",
            )
        )
        + " |"
    )


def _optional_int(value: int | None) -> str:
    return "n/a" if value is None else str(value)


# *--- Diagnostics and Footer ---*


def write_diagnostics_section(
    write: Callable[[str], None],
    diagnostics: Sequence[ReportDiagnostic],
) -> None:
    write("## Diagnostics")
    write("")
    if not diagnostics:
        write("No diagnostics were raised.")
    else:
        for diagnostic in diagnostics:
            location = f" [{_cell(diagnostic.location)}]" if diagnostic.location else ""
            write(
                f"- **{diagnostic.level.value}** {_cell(diagnostic.code)}: "
                f"{_cell(diagnostic.message)}{location}"
            )
    write("")


def write_footer(write: Callable[[str], None]) -> None:
    write("---")
    write("")
    write(DISCLAIMER)


# *--- Record Detail ---*


def _disposition_label(item: CompiledVulnerability) -> str:
    """Name the record's standing the way the Markdown twins print it.

    A record with a final disposition prints that disposition. An accepted record has
    none, since acceptance is not a final disposition in the official enumeration, so
    it prints as accepted; everything else is active.
    """

    if item.final_disposition:
        return item.final_disposition
    if item.status is CaseStatus.ACCEPTED:
        return "accepted"
    return "active"


def _write_detail(
    write: Callable[[str], None],
    item: CompiledVulnerability,
    *,
    as_of: datetime,
    acceptance_rationale: str | None = None,
) -> None:
    """Render one vulnerability's full audit detail into the Markdown twin.

    The JSON extension and this section carry the same material, so neither
    rendering omits what the other holds (ADR 0007 amendment). The acceptance
    rationale is printed only when the caller passes one, since only the reports
    that publish accepted records carry it.
    """

    evaluation = item.evaluation
    write(f"### {_cell(item.tracking_id)}: {_cell(item.source_record_id)}")
    write("")
    write(f"- **Description:** {_cell(item.description)}")
    write(f"- **Detection source:** {_cell(item.detection_source)}")
    write(f"- **Detected at:** {iso(item.detected_at)} (source: {_cell(item.detected_at_source)})")
    _write_observation_ids(write, item)
    resources = ", ".join(
        f"{_cell(resource.resource_type)} {_cell(resource.resource_id)}"
        for resource in item.resources
    )
    write(f"- **Affected resources:** {resources or 'n/a'}")
    identifiers = ", ".join(_cell(value) for value in item.source_identifiers)
    write(f"- **Source identifiers:** {identifiers or 'n/a'}")
    if item.kev_checked:
        write(f"- **Known exploited:** {_kev_line(item.kev, as_of)}")

    if evaluation is None:
        write("- **Evaluation:** not yet completed")
    else:
        write(
            f"- **Evaluation completed:** {iso(evaluation.completed_at)} by "
            f"{_cell(evaluation.evaluator)}"
        )
        write(
            f"- **Internet reachable:** {_flag(evaluation.is_internet_reachable)}; "
            f"**likely exploitable:** {_flag(evaluation.is_likely_exploitable)}; "
            f"**PAIN:** {evaluation.pain.name}"
        )
        write(f"- **Potential agency impact:** {_cell(evaluation.potential_agency_impact)}")
        write(f"- **Rationale:** {_cell(evaluation.rationale)}")
        if evaluation.supplementary_risk_information is not None:
            write(
                "- **Supplementary risk information:** "
                f"{_cell(evaluation.supplementary_risk_information)}"
            )
        projection = evaluation.projected_next_reduction
        if projection is None:
            write("- **Projected next reduction:** none planned")
        else:
            write(
                f"- **Projected next reduction:** {projection.target_rating.name} by "
                f"{iso(projection.estimated_at)}"
            )
        if evaluation.pain_reduction_events:
            reductions = ", ".join(
                f"{event.rating.name} at {iso(event.reduced_at)}"
                for event in evaluation.pain_reduction_events
            )
            write(f"- **Completed PAIN reductions:** {reductions}")
        else:
            write("- **Completed PAIN reductions:** none recorded")

    disposition = _cell(_disposition_label(item))
    write(f"- **Disposition:** {disposition}; **remediated:** {_flag(item.remediated)}")
    if acceptance_rationale is not None:
        write(f"- **Acceptance rationale:** {_cell(acceptance_rationale)}")
    if item.is_overdue:
        write(f"- **Overdue:** {_cell(item.overdue_explanation)}")
    else:
        write("- **Overdue:** not overdue")
    write("")
    write("| Rule | Name | Force | Anchor | Start | Due | Satisfied |")
    write("|---|---|---|---|---|---|---|")
    for deadline in item.deadlines:
        write(
            "| "
            + " | ".join(
                (
                    _cell(deadline.rule_id),
                    _cell(deadline.rule_name),
                    _cell(deadline.force),
                    _cell(deadline.anchor),
                    iso(deadline.start_at),
                    iso(deadline.due_at),
                    _flag(deadline.satisfied),
                )
            )
            + " |"
        )
    write("")


_KEV_TAILS = {
    KevStatus.OPEN: "open",
    KevStatus.PAST_DUE: "past due",
    KevStatus.REMEDIATED: "stopped by remediation",
    KevStatus.FALSE_POSITIVE: "stopped as a false positive",
}


def _kev_line(kev: KevClock | None, as_of: datetime) -> str:
    """Render the Known exploited detail line: every matched entry, then the bound clock.

    An unmatched record names the date its lookup stopped at, which stays true for a CVE
    the catalog lists with a later `dateAdded`.
    """

    if kev is None:
        return (
            "no entry in the supplied CISA KEV catalog dated on or before "
            f"{as_of.astimezone(UTC).date().isoformat()}"
        )
    listed = ", ".join(
        f"{_cell(entry.cve_id)} (added {entry.date_added.isoformat()}, due "
        f"{entry.due_date.isoformat()}, ransomware use "
        f"{_cell(entry.known_ransomware_campaign_use or 'n/a')}, forensic triage "
        f"{_cell(entry.forensic_triage or 'n/a')})"
        for entry in kev.entries
    )
    bound = kev.bound
    verb = "ended" if kev.due_at <= as_of else "ends"
    if kev.status is KevStatus.ACCEPTED:
        tail = "accepted, past due" if kev.past_due else "accepted"
    else:
        tail = _KEV_TAILS[kev.status]
    return (
        f"{listed}; the clock follows {_cell(bound.cve_id)}, due date "
        f"{bound.due_date.isoformat()} {verb} {iso(kev.due_at)}; {tail}"
    )


def _write_observation_ids(write: Callable[[str], None], item: CompiledVulnerability) -> None:
    """Name every observation grouped into one vulnerability, marking the untimed ones.

    The JSON extension carries `observationIds` and `untimestampedObservationIds`
    separately. Listing only the second here dropped, from the human rendering of a
    partly timestamped group, the very observation the detection time came from. The
    whole group is named in both branches; the label differs because a group where
    nothing carried a time is one statement rather than a list of exceptions.
    """

    untimestamped = frozenset(item.untimestamped_observation_ids)
    if untimestamped and untimestamped.issuperset(item.observation_ids):
        write(
            "- **Observations without a source timestamp:** "
            + ", ".join(_cell(value) for value in item.observation_ids)
        )
        return
    write(
        "- **Observations:** "
        + ", ".join(
            f"{_cell(value)} (no source timestamp)" if value in untimestamped else _cell(value)
            for value in item.observation_ids
        )
    )


# *--- Helper Functions ---*


def _flag(value: bool) -> str:
    return "yes" if value else "no"


def _cell(value: str) -> str:
    """Escape one Markdown table cell the way the compatibility renderer does."""

    return (
        value.replace("\\", "\\\\")
        .replace("|", "\\|")
        .replace("<", "&lt;")
        .replace(">", "&gt;")
        .replace("\r", " ")
        .replace("\n", " ")
    )


__all__ = [
    "write_attestation_section",
    "write_changes",
    "write_coverage",
    "write_diagnostics_section",
    "write_footer",
    "write_header",
    "write_inputs",
    "write_kev_summary",
    "write_provenance",
    "write_vulnerability_table",
]
