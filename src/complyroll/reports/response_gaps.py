# ******************************************************************************
# *Title: Response Gaps*
# *Author: Kyle Versluis*
# *Description: Find remediations that did not hold and attestations that lapsed.*
# ******************************************************************************
"""Response gaps: a remediation that did not hold, and a lapsed attestation (ADR 0019)."""

# *--- Imports ---*

from __future__ import annotations

from dataclasses import dataclass
from datetime import UTC, datetime

from complyroll.correlation import VulnerabilityGroup
from complyroll.models import Observation, ObservationOrigin

# *--- Types ---*


@dataclass(frozen=True, slots=True)
class RemediationRecurrence:
    """The open artifact observations of one remediated record its remediation cannot explain.

    `recurring` holds each member detected strictly after `remediated_at`, by detection time
    and then observation id, so the first is the earliest recurring detection. `untimed` holds
    each member that declares no source timestamp, by observation id: its time cannot be
    ordered against the remediation, so it is warned about and never recorded (ADR 0019).
    """

    tracking_id: str
    remediated_at: datetime
    recurring: tuple[Observation, ...]
    untimed: tuple[Observation, ...]


# *--- Core Logic ---*


def remediation_recurrence(
    group: VulnerabilityGroup, remediated_at: datetime
) -> RemediationRecurrence | None:
    """Return what came back after one group's remediation, or None when nothing did.

    Only ARTIFACT-origin members count: a system record never recurs. A member detected at
    the remediation instant itself is not a recurrence, because the scan that confirmed the
    remediation can share the instant.
    """

    if not isinstance(group, VulnerabilityGroup):
        raise TypeError("group must be a VulnerabilityGroup")
    if not isinstance(remediated_at, datetime) or remediated_at.utcoffset() is None:
        raise ValueError("remediated_at must be an aware datetime")
    remediated = remediated_at.astimezone(UTC)
    artifacts = [item for item in group.observations if item.origin is ObservationOrigin.ARTIFACT]
    recurring = sorted(
        (
            item
            for item in artifacts
            if item.observed_at is not None and item.observed_at.astimezone(UTC) > remediated
        ),
        key=_detection_order,
    )
    untimed = sorted(
        (item for item in artifacts if item.observed_at is None),
        key=lambda item: item.observation_id,
    )
    if not recurring and not untimed:
        return None
    return RemediationRecurrence(
        tracking_id=group.tracking_id,
        remediated_at=remediated,
        recurring=tuple(recurring),
        untimed=tuple(untimed),
    )


# *--- Helper Functions ---*


def _detection_order(observation: Observation) -> tuple[datetime, str]:
    """Order timed observations by detection time, then by the lowest observation id."""

    observed_at = observation.observed_at
    if observed_at is None:  # pragma: no cover - callers pass timed observations only
        raise AssertionError("a recurring observation is timed")
    return observed_at.astimezone(UTC), observation.observation_id


__all__ = [
    "RemediationRecurrence",
    "remediation_recurrence",
]
