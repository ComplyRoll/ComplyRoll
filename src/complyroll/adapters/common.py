# ******************************************************************************
# *Title: Adapter Common Helpers*
# *Author: Kyle Versluis*
# *Description: Observation-building helpers shared by the source adapters.*
# ******************************************************************************
"""Helpers shared by the source adapters."""

# *--- Imports ---*

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import replace
from datetime import datetime

from complyroll.models import Observation, ObservationDisposition, ResourceRef, SourceSeverity

from .base import ArtifactProvenance, DiagnosticLevel, IngestDiagnostic

# *--- Helper Functions ---*


def text_of(value: object) -> str:
    """Return the stripped text of a string value; anything else is empty text."""
    return value.strip() if isinstance(value, str) else ""


def unique(values: list[str]) -> tuple[str, ...]:
    """Drop empty and repeated values while keeping first-seen order."""
    return tuple(dict.fromkeys(value for value in values if value))


def parse_timestamp(value: object) -> datetime | None:
    """Parse an aware ISO 8601 timestamp; naive or unparsable text counts as absent."""
    if not isinstance(value, str) or not value.strip():
        return None
    normalized = value.strip()
    if normalized.endswith("Z"):
        normalized = f"{normalized[:-1]}+00:00"
    try:
        parsed = datetime.fromisoformat(normalized)
    except ValueError:
        return None
    if parsed.tzinfo is None or parsed.utcoffset() is None:
        return None
    return parsed


# *--- Observation Construction ---*


# The observation id derives from the fingerprint, so the record is built once with a
# placeholder id and then replaced with the id it derives for itself.
def make_observation(
    *,
    artifact: ArtifactProvenance,
    source_type: str,
    source_tool: str,
    source_record_id: str,
    resource_id: str,
    resource_type: str = "host",
    observed_at: datetime | None,
    ingested_at: datetime,
    disposition: ObservationDisposition,
    severity: SourceSeverity,
    title: str,
    description: str,
    identifiers: tuple[str, ...],
    context_key: str,
    metadata: Mapping[str, str] | None = None,
) -> Observation:
    """Build one observation with its derived identity from adapter-supplied fields."""
    observation = Observation(
        observation_id="pending",
        source_type=source_type,
        source_tool=source_tool,
        parser_name=artifact.parser_name,
        parser_version=artifact.parser_version,
        source_record_id=source_record_id,
        resource=ResourceRef(resource_id=resource_id, resource_type=resource_type),
        observed_at=observed_at,
        ingested_at=ingested_at,
        disposition=disposition,
        source_severity=severity,
        title=title,
        description=description,
        source_artifact_digest=artifact.digest_sha256,
        source_artifact_name=artifact.name,
        source_identifiers=identifiers,
        source_metadata=tuple(sorted((metadata or {}).items())),
        context_key=context_key,
    )
    return replace(observation, observation_id=observation.derived_observation_id)


def missing_time_diagnostic(artifact: ArtifactProvenance) -> IngestDiagnostic:
    """Return the warning every adapter emits when an artifact declares no scan time."""
    return IngestDiagnostic(
        DiagnosticLevel.WARNING,
        "source_timestamp_missing",
        "source artifact does not declare an observation timestamp; observed_at is unknown",
        artifact.name,
    )
