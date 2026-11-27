# ******************************************************************************
# *Title: Response Gaps*
# *Author: Kyle Versluis*
# *Description: Find remediations that did not hold and attestations that lapsed.*
# ******************************************************************************
"""Response gaps: a remediation that did not hold, and a lapsed attestation (ADR 0019)."""

# *--- Imports ---*

from __future__ import annotations

import re
from collections.abc import Mapping, Sequence
from dataclasses import dataclass, replace
from datetime import UTC, datetime
from typing import Protocol

from complyroll.correlation import VulnerabilityGroup
from complyroll.models import (
    Observation,
    ObservationDisposition,
    ObservationOrigin,
    ResourceRef,
    SourceSeverity,
)
from complyroll.policy import SelectedPolicy

# *--- Configuration ---*

#: The rule every response gap records a failure under.
RESPONSE_GAP_RULE = "VDR-CSO-FAV"
#: The identity of a remediation recurrence, mirroring a coverage gap's (ADR 0015 Decision 20).
#: The remediation instant and the recurring observation's id live in the key and metadata.
RECURRENCE_SOURCE_TYPE = "complyroll.recurrence"
RECURRENCE_SOURCE_TOOL = "complyroll"
RECURRENCE_PARSER_NAME = "complyroll.recurrence"
RECURRENCE_PARSER_VERSION = "1"
RECURRENCE_RECORD_ID = "remediation-recurrence"
# SECURITY: The title carries a correlation tracking id and an artifact's resource pair, which
# the adapters already held to their identity rules.
# NOTE: A case renders as `<record id>: <title>`, so the title names no kind of its own.
RECURRENCE_TITLE = (
    "remediation of {tracking_id} recorded {remediated_at} did not hold: "
    "{resource_type}:{resource_id} detected again {detected_at} "
    f"({RESPONSE_GAP_RULE})"
)
RECURRENCE_DESCRIPTION = (
    "ComplyRoll recorded an open observation of this weakness on this resource after its case "
    "was recorded remediated; this records that the remediation did not hold, a failure of the "
    "response process."
)
#: Always all four, so an audit checks one key set.
RECURRENCE_METADATA_KEYS = (
    "recurrence.caseTrackingId",
    "recurrence.observationDetectedAt",
    "recurrence.observationId",
    "recurrence.remediatedAt",
)
#: The fixed middle of a recurrence context key, `<tracking id>:remediated:<instant>`.
RECURRENCE_KEY_MARK = "remediated"
#: The identity of a lapsed attestation. Its resource is the case it names, its key that case's
#: correlation tracking id, and its instant the close of the window measured from the case's
#: first sighting, so one case's lapses under one profile are one record.
ATTESTATION_LAPSE_SOURCE_TYPE = "complyroll.attestation"
ATTESTATION_LAPSE_SOURCE_TOOL = "complyroll"
ATTESTATION_LAPSE_PARSER_NAME = "complyroll.attestation"
ATTESTATION_LAPSE_PARSER_VERSION = "1"
ATTESTATION_LAPSE_RECORD_ID = "attestation-lapse"
#: The window a case's detection time had to arrive in, selected from the pinned dataset.
ATTESTATION_LAPSE_RULE = "VER-TFR-EVU"
ATTESTATION_LAPSE_RESOURCE_TYPE = "logical"
ATTESTATION_LAPSE_RESOURCE_PREFIX = "case/"
ATTESTATION_LAPSE_TITLE = (
    "detection time of {tracking_id} was not attested within {rule} from {first_seen_at} "
    f"({RESPONSE_GAP_RULE})"
)
ATTESTATION_LAPSE_DESCRIPTION = (
    "No source timestamp, attestation or system time gave this case a detection time by the "
    "close of its evaluation window, measured from when ComplyRoll first recorded its evidence, "
    "so its evaluation clock could not start; this records a failure of the response process, "
    "not a vulnerability."
)
#: Always all five, so an audit checks one key set.
ATTESTATION_LAPSE_METADATA_KEYS = (
    "attestation.caseTrackingId",
    "attestation.firstSeenAt",
    "attestation.force",
    "attestation.rule",
    "attestation.windowClosedAt",
)

# A correlation v0 tracking id, spelled here because the report layer cannot import the
# event layer's pattern; a test holds the two equal.
_TRACKING_ID = re.compile(r"case-[0-9a-f]{16}")


# *--- Types ---*


class LinkedEvidence(Protocol):
    """One observation linked to a case: its id, and its source timestamp when it declares one."""

    @property
    def observation_id(self) -> str: ...

    @property
    def observed_at(self) -> datetime | None: ...


class CaseTiming(Protocol):
    """What a lapse reads of a case: its id, its linked evidence, and any attestation."""

    @property
    def tracking_id(self) -> str: ...

    @property
    def links(self) -> Sequence[LinkedEvidence]: ...

    @property
    def attestation(self) -> object | None: ...


@dataclass(frozen=True, slots=True)
class AttestationLapse:
    """One case with no detection time by the close of its evaluation window (ADR 0019).

    `first_seen_at` is the earliest `ingested_at` of the case's linked observations, the ingest
    `--as-of` an operator set, and `window_closed_at` the `VER-TFR-EVU` deadline from it under
    the run's profile. `force` is the rule's force as the pinned dataset states it.
    """

    tracking_id: str
    first_seen_at: datetime
    window_closed_at: datetime
    force: str


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
    remediated = _utc(remediated_at, "remediated_at")
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


def remediation_recurrences(
    groups: Sequence[VulnerabilityGroup], remediated_at: Mapping[str, datetime]
) -> tuple[RemediationRecurrence, ...]:
    """Return every group's recurrence, in group order, for the cases recorded remediated.

    `remediated_at` maps a correlation tracking id to its remediation instant; a group whose
    case is not remediated is not in it. The groups are the report's own, every current open
    observation linked or not, so a run agrees with the report's warning before `cases
    correlate` links what came back (ADR 0019).
    """

    found = []
    for group in groups:
        instant = remediated_at.get(group.tracking_id)
        recurrence = None if instant is None else remediation_recurrence(group, instant)
        if recurrence is not None:
            found.append(recurrence)
    return tuple(found)


def recurrence_context_key(tracking_id: str, remediated_at: datetime) -> str:
    """Return `<tracking id>:remediated:<instant>`: one case per failed remediation."""

    if not isinstance(tracking_id, str) or _TRACKING_ID.fullmatch(tracking_id) is None:
        raise ValueError("tracking_id must be a correlation tracking id")
    return f"{tracking_id}:{RECURRENCE_KEY_MARK}:{_instant(_utc(remediated_at, 'remediated_at'))}"


def recurrence_case_tracking_id(context_key: str) -> str | None:
    """Return the tracking id a recurrence key names, or None for any other key."""

    if not isinstance(context_key, str):
        raise TypeError("context_key must be text")
    parts = context_key.split(":", 2)
    if (
        len(parts) != 3
        or _TRACKING_ID.fullmatch(parts[0]) is None
        or parts[1] != RECURRENCE_KEY_MARK
        or not parts[2]
    ):
        return None
    return parts[0]


def recurrence_observations(
    recurrence: RemediationRecurrence, *, ingested_at: datetime
) -> tuple[Observation, ...]:
    """Return one system record per resource that came back, by detection then resource.

    Each resource's record names its earliest recurring detection, ties broken by the lowest
    observation id, so two members detected at one instant on one resource mint one record.
    An untimed member is never recorded.
    """

    if not isinstance(recurrence, RemediationRecurrence):
        raise TypeError("recurrence must be a RemediationRecurrence")
    earliest: dict[ResourceRef, Observation] = {}
    # `recurring` is already in detection then id order, so the first per resource wins.
    for item in recurrence.recurring:
        earliest.setdefault(item.resource, item)
    built = [
        _recurrence(item, recurrence.tracking_id, recurrence.remediated_at, ingested_at)
        for item in earliest.values()
    ]
    return tuple(sorted(built, key=_record_order))


def first_sighting(case: CaseTiming, ingested_at: Mapping[str, datetime]) -> datetime | None:
    """Return the earliest `ingested_at` of a case's linked observations, or None for none.

    `ingested_at` maps an observation id to the instant its ingest recorded it, which is the
    operator's `--as-of`, never a wall-clock store instant. A link the map does not hold is
    skipped, so a case with no readable link has no first sighting.
    """

    seen = [
        ingested_at[link.observation_id]
        for link in case.links
        if link.observation_id in ingested_at
    ]
    return None if not seen else min(_utc(item, "ingested_at") for item in seen)


def attestation_lapse(
    case: CaseTiming,
    ingested_at: Mapping[str, datetime],
    policy: SelectedPolicy,
    as_of: datetime,
) -> AttestationLapse | None:
    """Return one case's lapse when a run at `as_of` finds it untimed past its window.

    A case is untimed when no linked observation declares a source timestamp and no
    attestation is recorded; a system record is always timed. Its window closes at the
    `VER-TFR-EVU` deadline from its first sighting, and a run at or past that close records
    the lapse once and for good. A detection time that arrives before any run sees the lapse
    prevents it, which is why the record is only as frequent as the runs (ADR 0019).
    """

    if not isinstance(policy, SelectedPolicy):
        raise TypeError("policy must be a SelectedPolicy")
    now = _utc(as_of, "as_of")
    if case.attestation is not None or any(link.observed_at is not None for link in case.links):
        return None
    seen = first_sighting(case, ingested_at)
    if seen is None:
        return None
    deadline = policy.deadline_for_rule(ATTESTATION_LAPSE_RULE, seen)
    closed = deadline.due_at.astimezone(UTC)
    if now < closed:
        return None
    return AttestationLapse(
        tracking_id=case.tracking_id,
        first_seen_at=seen,
        window_closed_at=closed,
        force=deadline.force.value,
    )


def attestation_lapses(
    cases: Sequence[CaseTiming],
    ingested_at: Mapping[str, datetime],
    policy: SelectedPolicy,
    as_of: datetime,
) -> tuple[AttestationLapse, ...]:
    """Return every case's lapse at `as_of`, in tracking id order."""

    found = (attestation_lapse(case, ingested_at, policy, as_of) for case in cases)
    return tuple(sorted((item for item in found if item is not None), key=_lapse_order))


def attestation_lapse_observation(lapse: AttestationLapse, *, ingested_at: datetime) -> Observation:
    """Build the one system record of a lapse, named by the id it derives for itself.

    Identity depends on the case and the window close only: never on the ingest time, the
    first sighting apart from the close it fixes, or the force.
    """

    if not isinstance(lapse, AttestationLapse):
        raise TypeError("lapse must be an AttestationLapse")
    if _TRACKING_ID.fullmatch(lapse.tracking_id) is None:
        raise ValueError("the lapse must name a correlation tracking id")
    seen = _utc(lapse.first_seen_at, "first_seen_at")
    closed = _utc(lapse.window_closed_at, "window_closed_at")
    if closed <= seen:
        raise ValueError("a lapse window closes after the case was first seen")
    seen_text = _instant(seen)
    closed_text = _instant(closed)
    metadata = {
        "attestation.caseTrackingId": lapse.tracking_id,
        "attestation.firstSeenAt": seen_text,
        "attestation.windowClosedAt": closed_text,
        "attestation.rule": ATTESTATION_LAPSE_RULE,
        "attestation.force": lapse.force,
    }
    observation = Observation(
        observation_id="pending",
        source_type=ATTESTATION_LAPSE_SOURCE_TYPE,
        source_tool=ATTESTATION_LAPSE_SOURCE_TOOL,
        parser_name=ATTESTATION_LAPSE_PARSER_NAME,
        parser_version=ATTESTATION_LAPSE_PARSER_VERSION,
        source_record_id=ATTESTATION_LAPSE_RECORD_ID,
        resource=attestation_lapse_resource(lapse.tracking_id),
        observed_at=closed,
        ingested_at=ingested_at,
        disposition=ObservationDisposition.OPEN,
        source_severity=SourceSeverity.UNKNOWN,
        title=ATTESTATION_LAPSE_TITLE.format(
            tracking_id=lapse.tracking_id,
            rule=ATTESTATION_LAPSE_RULE,
            first_seen_at=seen_text,
        ),
        description=ATTESTATION_LAPSE_DESCRIPTION,
        source_artifact_digest="",
        source_artifact_name="",
        source_identifiers=(),
        source_metadata=tuple(sorted(metadata.items())),
        evidence_ids=(f"case:{lapse.tracking_id}",),
        context_key=lapse.tracking_id,
        origin=ObservationOrigin.SYSTEM,
    )
    return replace(observation, observation_id=observation.derived_observation_id)


def attestation_lapse_resource(tracking_id: str) -> ResourceRef:
    """Return the resource a lapse names: `logical:case/<tracking id>`."""

    if not isinstance(tracking_id, str) or _TRACKING_ID.fullmatch(tracking_id) is None:
        raise ValueError("tracking_id must be a correlation tracking id")
    return ResourceRef(
        resource_id=f"{ATTESTATION_LAPSE_RESOURCE_PREFIX}{tracking_id}",
        resource_type=ATTESTATION_LAPSE_RESOURCE_TYPE,
    )


# *--- Helper Functions ---*


def _recurrence(
    recurring: Observation,
    tracking_id: str,
    remediated_at: datetime,
    ingested_at: datetime,
) -> Observation:
    """Build one recurrence record, named by the id it derives for itself."""

    if recurring.origin is not ObservationOrigin.ARTIFACT:
        raise ValueError("only an artifact observation recurs")
    if recurring.disposition is not ObservationDisposition.OPEN:
        raise ValueError("only an open observation recurs")
    detected_at = recurring.observed_at
    if detected_at is None:
        raise ValueError("an untimed observation is never recorded as a recurrence")
    detected = detected_at.astimezone(UTC)
    remediated = _utc(remediated_at, "remediated_at")
    if detected <= remediated:
        raise ValueError("a recurrence is detected strictly after its remediation")
    detected_text = _instant(detected)
    remediated_text = _instant(remediated)
    metadata = {
        "recurrence.caseTrackingId": tracking_id,
        "recurrence.remediatedAt": remediated_text,
        "recurrence.observationId": recurring.observation_id,
        "recurrence.observationDetectedAt": detected_text,
    }
    resource = recurring.resource
    # make_observation is artifact-bound, so the record is built by keyword and then given
    # the id it derives for itself, as the coverage and change gap builders do.
    observation = Observation(
        observation_id="pending",
        source_type=RECURRENCE_SOURCE_TYPE,
        source_tool=RECURRENCE_SOURCE_TOOL,
        parser_name=RECURRENCE_PARSER_NAME,
        parser_version=RECURRENCE_PARSER_VERSION,
        source_record_id=RECURRENCE_RECORD_ID,
        resource=resource,
        observed_at=detected,
        ingested_at=ingested_at,
        disposition=ObservationDisposition.OPEN,
        source_severity=SourceSeverity.UNKNOWN,
        title=RECURRENCE_TITLE.format(
            tracking_id=tracking_id,
            remediated_at=remediated_text,
            resource_type=resource.resource_type,
            resource_id=resource.resource_id,
            detected_at=detected_text,
        ),
        description=RECURRENCE_DESCRIPTION,
        source_artifact_digest="",
        source_artifact_name="",
        source_identifiers=(),
        source_metadata=tuple(sorted(metadata.items())),
        evidence_ids=(recurring.observation_id,),
        context_key=recurrence_context_key(tracking_id, remediated),
        origin=ObservationOrigin.SYSTEM,
    )
    return replace(observation, observation_id=observation.derived_observation_id)


def _detection_order(observation: Observation) -> tuple[datetime, str]:
    """Order timed observations by detection time, then by the lowest observation id."""

    observed_at = observation.observed_at
    if observed_at is None:  # pragma: no cover - callers pass timed observations only
        raise AssertionError("a recurring observation is timed")
    return observed_at.astimezone(UTC), observation.observation_id


def _record_order(record: Observation) -> tuple[datetime, str, str, str]:
    """Order system records by their instant, then by resource and id."""

    observed_at = record.observed_at
    if observed_at is None:  # pragma: no cover - a system record is always observed
        raise AssertionError("a system record is observed")
    return (
        observed_at.astimezone(UTC),
        record.resource.resource_type,
        record.resource.resource_id,
        record.observation_id,
    )


def _lapse_order(lapse: AttestationLapse) -> tuple[str, datetime]:
    """Order lapses by the case they name, then by window close."""

    return lapse.tracking_id, lapse.window_closed_at


def _utc(value: datetime, name: str) -> datetime:
    """Return one aware instant in UTC, refusing a naive one."""

    if not isinstance(value, datetime) or value.utcoffset() is None:
        raise ValueError(f"{name} must be an aware datetime")
    return value.astimezone(UTC)


def _instant(value: datetime) -> str:
    """Return one instant as RFC 3339 UTC text, as every report and event writes it."""

    return value.astimezone(UTC).isoformat().replace("+00:00", "Z")


__all__ = [
    "ATTESTATION_LAPSE_DESCRIPTION",
    "ATTESTATION_LAPSE_METADATA_KEYS",
    "ATTESTATION_LAPSE_PARSER_NAME",
    "ATTESTATION_LAPSE_PARSER_VERSION",
    "ATTESTATION_LAPSE_RECORD_ID",
    "ATTESTATION_LAPSE_RESOURCE_PREFIX",
    "ATTESTATION_LAPSE_RESOURCE_TYPE",
    "ATTESTATION_LAPSE_RULE",
    "ATTESTATION_LAPSE_SOURCE_TOOL",
    "ATTESTATION_LAPSE_SOURCE_TYPE",
    "ATTESTATION_LAPSE_TITLE",
    "AttestationLapse",
    "CaseTiming",
    "LinkedEvidence",
    "RECURRENCE_DESCRIPTION",
    "RECURRENCE_KEY_MARK",
    "RECURRENCE_METADATA_KEYS",
    "RECURRENCE_PARSER_NAME",
    "RECURRENCE_PARSER_VERSION",
    "RECURRENCE_RECORD_ID",
    "RECURRENCE_SOURCE_TOOL",
    "RECURRENCE_SOURCE_TYPE",
    "RECURRENCE_TITLE",
    "RESPONSE_GAP_RULE",
    "RemediationRecurrence",
    "attestation_lapse",
    "attestation_lapse_observation",
    "attestation_lapse_resource",
    "attestation_lapses",
    "first_sighting",
    "recurrence_case_tracking_id",
    "recurrence_context_key",
    "recurrence_observations",
    "remediation_recurrence",
    "remediation_recurrences",
]
