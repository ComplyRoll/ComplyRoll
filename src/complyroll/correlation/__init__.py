"""Correlation v0: group open observations into reportable vulnerabilities.

ADR 0007 Decision 3. Only `open` observations are vulnerabilities in a
Vulnerability Detail Report. They group by `(source_type, source_record_id,
context_key)`, so one rule failing on many hosts is one vulnerability with many
affected resources. Every grouped observation identifier and every affected
resource is preserved, so grouping never destroys instance detail.

Manual split and merge, cross-source correlation, and fingerprint-independent
grouping remain event-store work.
"""

from __future__ import annotations

import hashlib
import json
from collections.abc import Iterable
from dataclasses import dataclass
from datetime import datetime

from complyroll.models import Observation, ObservationDisposition, ResourceRef

TRACKING_ID_PREFIX = "case-"
TRACKING_ID_DIGEST_LENGTH = 16

#: Dispositions that are not detected weaknesses but must still be surfaced.
UNRESOLVED_DISPOSITIONS = (ObservationDisposition.ERROR, ObservationDisposition.UNKNOWN)


@dataclass(frozen=True, slots=True)
class VulnerabilityGroup:
    """One logical weakness assembled from open observations of the same rule."""

    tracking_id: str
    source_type: str
    source_record_id: str
    context_key: str
    observations: tuple[Observation, ...]
    resources: tuple[ResourceRef, ...]
    source_identifiers: tuple[str, ...]
    title: str
    description: str
    earliest_observed_at: datetime | None
    detection_sources: tuple[str, ...]

    @property
    def observation_ids(self) -> tuple[str, ...]:
        """Return every supporting observation identifier in source order."""

        return tuple(observation.observation_id for observation in self.observations)

    @property
    def detection_source(self) -> str:
        """Return the official `detection.detectionSource` value for this group."""

        return ", ".join(self.detection_sources)

    @property
    def parser_versions(self) -> tuple[tuple[str, str], ...]:
        """Return the sorted parser name and version pairs behind this group."""

        pairs = {
            (observation.parser_name, observation.parser_version)
            for observation in self.observations
        }
        return tuple(sorted(pairs))


@dataclass(frozen=True, slots=True)
class CorrelationResult:
    """Grouped vulnerabilities plus the observations deliberately left out."""

    groups: tuple[VulnerabilityGroup, ...]
    excluded: tuple[Observation, ...]

    @property
    def unresolved(self) -> tuple[Observation, ...]:
        """Return excluded observations whose disposition is error or unknown.

        These are not clean results and not detected weaknesses either, so the
        compiler reports them as diagnostics rather than dropping them.
        """

        return tuple(
            observation
            for observation in self.excluded
            if observation.disposition in UNRESOLVED_DISPOSITIONS
        )


def tracking_id_for(source_type: str, source_record_id: str, context_key: str) -> str:
    """Return the stable provider tracking identifier for one group key."""

    payload = json.dumps(
        [source_type, source_record_id, context_key],
        separators=(",", ":"),
        ensure_ascii=True,
    )
    digest = hashlib.sha256(payload.encode("utf-8")).hexdigest()
    return f"{TRACKING_ID_PREFIX}{digest[:TRACKING_ID_DIGEST_LENGTH]}"


def correlate_observations(observations: Iterable[Observation]) -> CorrelationResult:
    """Group open observations and keep the non-open ones for diagnostics."""

    grouped: dict[tuple[str, str, str], list[Observation]] = {}
    excluded: list[Observation] = []
    for observation in observations:
        if not isinstance(observation, Observation):
            raise TypeError(
                f"observations must be Observation instances, got {type(observation).__name__}"
            )
        if observation.disposition is not ObservationDisposition.OPEN:
            excluded.append(observation)
            continue
        key = (observation.source_type, observation.source_record_id, observation.context_key)
        grouped.setdefault(key, []).append(observation)

    groups = tuple(_build_group(key, members) for key, members in sorted(grouped.items()))
    return CorrelationResult(groups=groups, excluded=tuple(excluded))


def group_open_observations(
    observations: Iterable[Observation],
) -> tuple[VulnerabilityGroup, ...]:
    """Return only the vulnerability groups, deterministically ordered."""

    return correlate_observations(observations).groups


def _build_group(
    key: tuple[str, str, str],
    members: list[Observation],
) -> VulnerabilityGroup:
    source_type, source_record_id, context_key = key
    resources: list[ResourceRef] = []
    seen_resources: set[tuple[str, str]] = set()
    identifiers: set[str] = set()
    tools: set[str] = set()
    observed_times: list[datetime] = []
    title = ""
    description = ""

    for observation in members:
        resource_key = (observation.resource.resource_type, observation.resource.resource_id)
        if resource_key not in seen_resources:
            seen_resources.add(resource_key)
            resources.append(observation.resource)
        identifiers.update(observation.source_identifiers)
        tools.add(observation.source_tool)
        if observation.observed_at is not None:
            observed_times.append(observation.observed_at)
        if not title and observation.title.strip():
            title = observation.title
        if not description and observation.description.strip():
            description = observation.description

    return VulnerabilityGroup(
        tracking_id=tracking_id_for(source_type, source_record_id, context_key),
        source_type=source_type,
        source_record_id=source_record_id,
        context_key=context_key,
        observations=tuple(members),
        resources=tuple(resources),
        source_identifiers=tuple(sorted(identifiers)),
        title=title,
        description=description,
        earliest_observed_at=min(observed_times) if observed_times else None,
        detection_sources=tuple(sorted(tools)),
    )


__all__ = [
    "TRACKING_ID_DIGEST_LENGTH",
    "TRACKING_ID_PREFIX",
    "UNRESOLVED_DISPOSITIONS",
    "CorrelationResult",
    "VulnerabilityGroup",
    "correlate_observations",
    "group_open_observations",
    "tracking_id_for",
]
