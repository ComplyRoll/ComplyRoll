# ******************************************************************************
# *Title: Coverage Gaps*
# *Author: Kyle Versluis*
# *Description: Build one VDR-CSO-FAV system record per closed coverage window.*
# ******************************************************************************
"""Coverage gaps: one system observation per window that closed empty (ADR 0015)."""

# *--- Imports ---*

from __future__ import annotations

from dataclasses import replace
from datetime import UTC, datetime

from complyroll.models import (
    Observation,
    ObservationDisposition,
    ObservationOrigin,
    SourceSeverity,
)

# NOTE: The coverage block's instant formatter, shared so the gap's instants read exactly as
# the block's `anchorAt` and `closedAt` do.
from .coverage import COVERAGE_BASIS, CoverageResult, CoverageWindow, _instant_text
from .inventory import InformationResource, Inventory

# *--- Configuration ---*

# One identity for every gap, mirroring the detection failure's (ADR 0014 Decision 4). The
# anchor, force and inventory digest live in metadata, so they never move the id.
COVERAGE_GAP_SOURCE_TYPE = "complyroll.coverage"
COVERAGE_GAP_SOURCE_TOOL = "complyroll"
COVERAGE_GAP_PARSER_NAME = "complyroll.coverage"
COVERAGE_GAP_PARSER_VERSION = "1"
COVERAGE_GAP_RECORD_ID = "coverage-gap"
COVERAGE_GAP_RULE = "VDR-CSO-FAV"
# SECURITY: The title carries the clock's resource pair, which the inventory reader already
# held to its identity rules; the instant is this module's own text.
COVERAGE_GAP_TITLE = (
    "coverage gap: {rule} window for {resource_type}:{resource_id} closed {closed_at} "
    f"with no verification recorded ({COVERAGE_GAP_RULE})"
)
COVERAGE_GAP_DESCRIPTION = (
    "ComplyRoll recorded no verification for this resource inside the window; this records "
    "the absence of a verification, not a vulnerability."
)
# Always all eight, `coverage.job` empty when there is none, so an audit checks one key set.
COVERAGE_GAP_METADATA_KEYS = (
    "coverage.anchor",
    "coverage.anchorAt",
    "coverage.basis",
    "coverage.force",
    "coverage.inventorySha256",
    "coverage.job",
    "coverage.rule",
    "coverage.windowClosedAt",
)


# *--- Core Logic ---*


def coverage_gap_context_key(window: CoverageWindow, entry: InformationResource | None) -> str:
    """Return `<rule>:job:<job>` for an entry's job, else `<rule>:resource:<type>:<id>`.

    One case per rule and job, else per rule and resource. Segment two always tells the
    forms apart, so a resource of type `job` cannot spell an entry's job.
    """
    subject = window.key.subject
    # A sample group's clock has no entry; an entry whose pair spells the group is not it.
    if entry is not None and (window.key.resource is None or entry.ref != subject):
        raise ValueError("the entry must be the inventory entry of the window's own resource")
    if entry is not None and entry.job:
        return f"{window.rule_id}:job:{entry.job}"
    return f"{window.rule_id}:resource:{subject.resource_type}:{subject.resource_id}"


def coverage_gap_observation(
    window: CoverageWindow,
    *,
    inventory: Inventory,
    ingested_at: datetime,
) -> Observation:
    """Build the one system record of a closed window, named by its derived id.

    Identity depends on the rule, the resource, the context key and the window close only:
    never on as-of, the ingest time, the anchor, or the inventory digest.
    """
    if not isinstance(window, CoverageWindow):
        raise TypeError("window must be a CoverageWindow")
    if not isinstance(inventory, Inventory):
        raise TypeError("inventory must be an Inventory")
    subject = window.key.subject
    entry = None
    if window.key.resource is not None:
        entry = inventory.entry_for(subject.resource_type, subject.resource_id)
        # The digest in metadata must name the inventory whose entry carried the clock.
        if entry is None or entry.ref != subject:
            raise ValueError(
                f"the window's resource {subject.resource_type}:{subject.resource_id} names "
                "no entry of this inventory"
            )
    closed_at = window.closed_at.astimezone(UTC)
    closed_text = _instant(closed_at)
    job = None if entry is None else entry.job
    metadata = {
        "coverage.rule": window.rule_id,
        "coverage.force": window.force.value,
        "coverage.anchor": window.anchor.value,
        "coverage.anchorAt": _instant(window.anchor_at),
        "coverage.windowClosedAt": closed_text,
        "coverage.inventorySha256": inventory.sha256,
        "coverage.job": job or "",
        "coverage.basis": COVERAGE_BASIS,
    }
    # make_observation is artifact-bound, so the record is built by keyword here and then
    # replaced with the id it derives for itself, as the failure builder does.
    observation = Observation(
        observation_id="pending",
        source_type=COVERAGE_GAP_SOURCE_TYPE,
        source_tool=COVERAGE_GAP_SOURCE_TOOL,
        parser_name=COVERAGE_GAP_PARSER_NAME,
        parser_version=COVERAGE_GAP_PARSER_VERSION,
        source_record_id=COVERAGE_GAP_RECORD_ID,
        resource=subject,
        observed_at=closed_at,
        ingested_at=ingested_at,
        disposition=ObservationDisposition.OPEN,
        source_severity=SourceSeverity.UNKNOWN,
        title=COVERAGE_GAP_TITLE.format(
            rule=window.rule_id,
            resource_type=subject.resource_type,
            resource_id=subject.resource_id,
            closed_at=closed_text,
        ),
        description=COVERAGE_GAP_DESCRIPTION,
        source_artifact_digest="",
        source_artifact_name="",
        source_identifiers=(),
        source_metadata=tuple(sorted(metadata.items())),
        evidence_ids=(f"sha256:{inventory.sha256}",),
        context_key=coverage_gap_context_key(window, entry),
        origin=ObservationOrigin.SYSTEM,
    )
    return replace(observation, observation_id=observation.derived_observation_id)


def coverage_gap_observations(
    result: CoverageResult, *, ingested_at: datetime
) -> tuple[Observation, ...]:
    """Return one gap per closed window of the result, in its window order."""
    if not isinstance(result, CoverageResult):
        raise TypeError("result must be a CoverageResult")
    return tuple(
        coverage_gap_observation(window, inventory=result.inventory, ingested_at=ingested_at)
        for window in result.windows
    )


# *--- Helper Functions ---*


def _instant(value: datetime) -> str:
    """Return one instant as RFC 3339 UTC text, exactly as the coverage block writes it."""
    text = _instant_text(value)
    if text is None:  # pragma: no cover - a datetime always formats
        raise AssertionError("an instant must format as text")
    return text


__all__ = [
    "COVERAGE_GAP_DESCRIPTION",
    "COVERAGE_GAP_METADATA_KEYS",
    "COVERAGE_GAP_PARSER_NAME",
    "COVERAGE_GAP_PARSER_VERSION",
    "COVERAGE_GAP_RECORD_ID",
    "COVERAGE_GAP_RULE",
    "COVERAGE_GAP_SOURCE_TOOL",
    "COVERAGE_GAP_SOURCE_TYPE",
    "COVERAGE_GAP_TITLE",
    "coverage_gap_context_key",
    "coverage_gap_observation",
    "coverage_gap_observations",
]
