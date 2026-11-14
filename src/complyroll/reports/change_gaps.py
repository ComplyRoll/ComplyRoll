# ******************************************************************************
# *Title: Change Gaps*
# *Author: Kyle Versluis*
# *Description: Build one VDR-CSO-FAV system record per closed change window.*
# ******************************************************************************
"""Change gaps: one system observation per change window that closed empty (ADR 0018)."""

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

from .changes import CHANGE_BASIS, DAC_RULE, ChangeObligation, ChangeProjection, StoredChangeSet

# NOTE: The change block's instant formatter (the coverage block's), shared so the gap's
# instants read exactly as the block's `occurredAt` and `detectBy` do.
from .coverage import _instant_text

# *--- Configuration ---*

# One identity for every gap, mirroring the coverage gap's (ADR 0015 Decision 20). The
# occurrence, force, kind, job and both digests live in metadata, so they never move the id.
CHANGE_GAP_SOURCE_TYPE = "complyroll.change"
CHANGE_GAP_SOURCE_TOOL = "complyroll"
CHANGE_GAP_PARSER_NAME = "complyroll.change"
CHANGE_GAP_PARSER_VERSION = "1"
CHANGE_GAP_RECORD_ID = "change-detection-gap"
CHANGE_GAP_RULE = "VDR-CSO-FAV"
# SECURITY: The title carries the change id and the row's resource pair, which the change and
# inventory readers already held to their label and identity rules.
# NOTE: A case renders as `<record id>: <title>`, so the title leads with the rule and names
# no kind of its own, as a coverage gap's does.
CHANGE_GAP_TITLE = (
    "{rule} window for {resource_type}:{resource_id} after change {change_id} closed "
    "{closed_at} with no verification recorded "
    f"({CHANGE_GAP_RULE})"
)
CHANGE_GAP_DESCRIPTION = (
    "ComplyRoll recorded no verification of this resource between the change and the window "
    "close; this records the absence of a verification, not a vulnerability."
)
# Always all ten, `change.job` empty when there is none, so an audit checks one key set.
CHANGE_GAP_METADATA_KEYS = (
    "change.basis",
    "change.changesSha256",
    "change.detectBy",
    "change.force",
    "change.id",
    "change.inventorySha256",
    "change.job",
    "change.kind",
    "change.occurredAt",
    "change.rule",
)
# Append-only: a reworded block basis is added here, never put in place of one, so a gap
# recorded before the rewording still verifies.
CHANGE_GAP_BASIS_TEXTS = (CHANGE_BASIS,)

# A key's fixed lead; a change id may hold `:`, so the id is everything after it.
_KEY_LEAD = f"{DAC_RULE}:change"


# *--- Core Logic ---*


def change_gap_context_key(change_id: str) -> str:
    """Return `VDR-CSO-DAC:change:<changeId>`: one case per change, whatever it names."""
    if not isinstance(change_id, str):
        raise TypeError("change_id must be text")
    if not change_id:
        raise ValueError("change_id must not be empty")
    return f"{_KEY_LEAD}:{change_id}"


def change_gap_change_id(context_key: str) -> str | None:
    """Return the change id a change gap's key names, or None for any other key."""
    if not isinstance(context_key, str):
        raise TypeError("context_key must be text")
    parts = context_key.split(":", 2)
    if len(parts) != 3 or f"{parts[0]}:{parts[1]}" != _KEY_LEAD or not parts[2]:
        return None
    return parts[2]


def change_gap_observation(
    row: ChangeObligation,
    *,
    projection: ChangeProjection,
    ingested_at: datetime,
) -> Observation:
    """Build the one system record of a row whose window closed, named by its derived id.

    Identity depends on the resource, the change id and the window close only: never on
    as-of, the ingest time, the occurrence, the kind, the job, the force or either digest.
    """
    if not isinstance(row, ChangeObligation):
        raise TypeError("row must be a ChangeObligation")
    if not isinstance(projection, ChangeProjection):
        raise TypeError("projection must be a ChangeProjection")
    if row.window_closed_at is None:
        raise ValueError("the row's window did not close, so it records no gap")
    # The digests in metadata must name the inputs this row was derived from.
    if row not in projection.obligations:
        raise ValueError("the row is not an obligation of this projection")
    return _gap(row, projection, _changes_digests(projection), ingested_at)


def change_gap_observations(
    projection: ChangeProjection, *, ingested_at: datetime
) -> tuple[Observation, ...]:
    """Return one gap per row whose window closed, in the projection's obligation order."""
    if not isinstance(projection, ChangeProjection):
        raise TypeError("projection must be a ChangeProjection")
    digests = _changes_digests(projection)
    return tuple(
        _gap(row, projection, digests, ingested_at)
        for row in projection.obligations
        if row.window_closed_at is not None
    )


# *--- Helper Functions ---*


# NOTE: Each row is the projection's own, checked by the caller, so the batch skips a scan
# per row that would make it quadratic.
def _gap(
    row: ChangeObligation,
    projection: ChangeProjection,
    digests: dict[str, str],
    ingested_at: datetime,
) -> Observation:
    change = row.change
    closed_at = row.window_closed_at
    if closed_at is None:  # pragma: no cover - both callers pass closed rows only
        raise AssertionError("a gap needs a closed window")
    if projection.force is None:
        raise ValueError("the projection read no force for VDR-CSO-DAC, so it records no gap")
    # A projection closes a window at its change's detectBy; anything else is not one.
    if change.detect_by is None or change.detect_by != closed_at:
        raise ValueError("the row's window must close at its change's detectBy")
    closed_at = closed_at.astimezone(UTC)
    closed_text = _instant(closed_at)
    changes_sha256 = digests[change.change_id]
    metadata = {
        "change.rule": DAC_RULE,
        "change.force": projection.force.value,
        "change.id": change.change_id,
        "change.kind": change.kind.value,
        "change.occurredAt": _instant(change.occurred_at),
        "change.detectBy": closed_text,
        "change.job": change.job or "",
        "change.changesSha256": changes_sha256,
        "change.inventorySha256": projection.inventory.sha256,
        "change.basis": CHANGE_BASIS,
    }
    resource = row.resource
    # make_observation is artifact-bound, so the record is built by keyword here and then
    # replaced with the id it derives for itself, as the coverage gap builder does.
    observation = Observation(
        observation_id="pending",
        source_type=CHANGE_GAP_SOURCE_TYPE,
        source_tool=CHANGE_GAP_SOURCE_TOOL,
        parser_name=CHANGE_GAP_PARSER_NAME,
        parser_version=CHANGE_GAP_PARSER_VERSION,
        source_record_id=CHANGE_GAP_RECORD_ID,
        resource=resource,
        observed_at=closed_at,
        ingested_at=ingested_at,
        disposition=ObservationDisposition.OPEN,
        source_severity=SourceSeverity.UNKNOWN,
        title=CHANGE_GAP_TITLE.format(
            rule=DAC_RULE,
            resource_type=resource.resource_type,
            resource_id=resource.resource_id,
            change_id=change.change_id,
            closed_at=closed_text,
        ),
        description=CHANGE_GAP_DESCRIPTION,
        source_artifact_digest="",
        source_artifact_name="",
        source_identifiers=(),
        source_metadata=tuple(sorted(metadata.items())),
        evidence_ids=(f"sha256:{changes_sha256}",),
        context_key=change_gap_context_key(change.change_id),
        origin=ObservationOrigin.SYSTEM,
    )
    return replace(observation, observation_id=observation.derived_observation_id)


# NOTE: A store keeps the digest of the file that first recorded each change, so a gap names
# that file; a stateless run names the one file it read (ADR 0018).
def _changes_digests(projection: ChangeProjection) -> dict[str, str]:
    """Return the change file digest each change's gap names, by change id."""
    change_set = projection.change_set
    if isinstance(change_set, StoredChangeSet):
        return {
            change.change_id: digest
            for change, digest in zip(change_set.changes, change_set.digests, strict=True)
        }
    return {change.change_id: change_set.sha256 for change in change_set.changes}


def _instant(value: datetime) -> str:
    """Return one instant as RFC 3339 UTC text, exactly as the change block writes it."""
    text = _instant_text(value)
    if text is None:  # pragma: no cover - a datetime always formats
        raise AssertionError("an instant must format as text")
    return text


__all__ = [
    "CHANGE_GAP_BASIS_TEXTS",
    "CHANGE_GAP_DESCRIPTION",
    "CHANGE_GAP_METADATA_KEYS",
    "CHANGE_GAP_PARSER_NAME",
    "CHANGE_GAP_PARSER_VERSION",
    "CHANGE_GAP_RECORD_ID",
    "CHANGE_GAP_RULE",
    "CHANGE_GAP_SOURCE_TOOL",
    "CHANGE_GAP_SOURCE_TYPE",
    "CHANGE_GAP_TITLE",
    "change_gap_change_id",
    "change_gap_context_key",
    "change_gap_observation",
    "change_gap_observations",
]
