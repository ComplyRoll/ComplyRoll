# ******************************************************************************
# *Title: Response Gaps*
# *Author: Kyle Versluis*
# *Description: Find failed remediations, lapsed attestations and lapsed plans.*
# ******************************************************************************
"""Response gaps: a failed remediation, a lapsed attestation, a lapsed plan (ADR 0019)."""

# *--- Imports ---*

from __future__ import annotations

import re
from collections.abc import Collection, Mapping, Sequence
from dataclasses import dataclass, replace
from datetime import UTC, datetime
from typing import Protocol

from complyroll.correlation import VulnerabilityGroup
from complyroll.models import (
    CaseStatus,
    Observation,
    ObservationDisposition,
    ObservationOrigin,
    PainRating,
    ResourceRef,
    SourceSeverity,
)
from complyroll.policy import SelectedPolicy

from .evaluations import EvaluationInput, PainReductionEvent

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
#: The fixed middle of a recurrence context key, `<tracking id>:remediated:<instant>:<episode>`.
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
#: The resolved statuses whose weakness has nothing left to reduce, so a plan stated on them
#: never lapses (plan D3, Kyle's ruling 3a). Every other status can lapse, none included.
PLAN_LAPSE_EXCLUDED_STATUSES = frozenset(
    {CaseStatus.REMEDIATED, CaseStatus.FULLY_MITIGATED, CaseStatus.FALSE_POSITIVE}
)

# A correlation v0 tracking id, spelled here because the report layer cannot import the
# event layer's pattern; a test holds the two equal.
_TRACKING_ID = re.compile(r"case-[0-9a-f]{16}")
# An episode ordinal as `str(int)` spells a positive integer.
_EPISODE = re.compile(r"[1-9][0-9]*")


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
class Remediation:
    """One case's current remediated episode: its instant and its 1-based ordinal in the stream.

    A new episode starts each time the case's resolved status becomes `remediated` after not
    being remediated, so two episodes that share an evaluation instant still differ (K2).
    """

    instant: datetime
    episode: int


@dataclass(frozen=True, slots=True)
class ResponseGapHistory:
    """What a store holds that a response gap reads (ADR 0019).

    `cases` are the folded cases, `ingested_at` maps every recorded artifact observation id to
    the instant its ingest recorded it (the ingest `--as-of`, or the run's time when none was
    given, as ADR 0014 records a failure), and `remediations` maps each case recorded remediated
    to its current episode. No store `recorded_at`, `createdAt` or `attestedAt` is among them.
    """

    cases: Sequence[CaseTiming]
    ingested_at: Mapping[str, datetime]
    remediations: Mapping[str, Remediation]


@dataclass(frozen=True, slots=True)
class RemediationRecurrence:
    """The open artifact observations of one remediated record its remediation cannot explain.

    `recurring` holds each member detected strictly after `remediated_at`, by detection time
    and then observation id, so the first is the earliest recurring detection. `untimed` holds
    each member that declares no source timestamp, by observation id: its time cannot be
    ordered against the remediation, so it is warned about and never recorded (ADR 0019).
    `episode` is the remediation's ordinal in its case stream, 1 on the stateless path.
    """

    tracking_id: str
    remediated_at: datetime
    recurring: tuple[Observation, ...]
    untimed: tuple[Observation, ...]
    episode: int = 1


@dataclass(frozen=True, slots=True)
class PlanLapse:
    """One record whose own planned reduction was not recorded by its planned time (plan D2).

    `estimated_at` and `target_rating` are the current evaluation's `projectedNextReduction`,
    and `completed_at` that evaluation's `completedAt`, where the window a reduction had to
    land in opens. `current_rating` is its `pain`: the warning names it, and no record holds
    it, since it moves while the record is held to its own inputs alone.
    """

    tracking_id: str
    completed_at: datetime
    estimated_at: datetime
    target_rating: PainRating
    current_rating: PainRating


class LapseClockError(ValueError):
    """A case's first sighting leaves no room for its `VER-TFR-EVU` deadline before year 9999.

    The report layer turns it into the shared `clock_out_of_range` diagnostic, and `store
    verify` names the same first sighting, so no reader ends in an uncaught OverflowError.
    """

    def __init__(self, tracking_id: str, first_seen_at: datetime) -> None:
        self.tracking_id = tracking_id
        self.first_seen_at = first_seen_at
        super().__init__(
            f"{tracking_id} was first recorded {first_seen_at.isoformat()}, which leaves no room "
            f"for its {ATTESTATION_LAPSE_RULE} deadline"
        )


# *--- Core Logic ---*


def remediation_recurrence(
    group: VulnerabilityGroup, remediated_at: datetime, *, episode: int = 1
) -> RemediationRecurrence | None:
    """Return what came back after one group's remediation, or None when nothing did.

    Only ARTIFACT-origin members count: a system record never recurs. A member detected at
    the remediation instant itself is not a recurrence, because the scan that confirmed the
    remediation can share the instant.
    """

    if not isinstance(group, VulnerabilityGroup):
        raise TypeError("group must be a VulnerabilityGroup")
    _require_episode(episode)
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
        episode=episode,
    )


def remediation_recurrences(
    groups: Sequence[VulnerabilityGroup], remediations: Mapping[str, Remediation]
) -> tuple[RemediationRecurrence, ...]:
    """Return every group's recurrence, in group order, for the cases recorded remediated.

    `remediations` maps a correlation tracking id to its current remediated episode; a group
    whose case is not remediated is not in it. The groups are the report's own, every current
    open observation linked or not, so a run agrees with the report's warning before `cases
    correlate` links what came back (ADR 0019).
    """

    found = []
    for group in groups:
        current = remediations.get(group.tracking_id)
        recurrence = (
            None
            if current is None
            else remediation_recurrence(group, current.instant, episode=current.episode)
        )
        if recurrence is not None:
            found.append(recurrence)
    return tuple(found)


def recurrence_context_key(tracking_id: str, remediated_at: datetime, episode: int) -> str:
    """Return `<tracking id>:remediated:<instant>:<episode>`: one case per failed remediation."""

    if not isinstance(tracking_id, str) or _TRACKING_ID.fullmatch(tracking_id) is None:
        raise ValueError("tracking_id must be a correlation tracking id")
    _require_episode(episode)
    instant = _instant(_utc(remediated_at, "remediated_at"))
    return f"{tracking_id}:{RECURRENCE_KEY_MARK}:{instant}:{episode}"


def recurrence_key_parts(context_key: str) -> tuple[str, str, int] | None:
    """Return the tracking id, instant text and episode a recurrence key names, or None.

    The instant holds colons of its own, so the episode is read from the last segment, and it
    must be spelled as `str(int)` spells a positive integer.
    """

    if not isinstance(context_key, str):
        raise TypeError("context_key must be text")
    parts = context_key.split(":", 2)
    if (
        len(parts) != 3
        or _TRACKING_ID.fullmatch(parts[0]) is None
        or parts[1] != RECURRENCE_KEY_MARK
    ):
        return None
    instant, _, episode = parts[2].rpartition(":")
    if not instant or _EPISODE.fullmatch(episode) is None:
        return None
    return parts[0], instant, int(episode)


def recurrence_case_tracking_id(context_key: str) -> str | None:
    """Return the tracking id a recurrence key names, or None for any other key."""

    found = recurrence_key_parts(context_key)
    return None if found is None else found[0]


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
        _recurrence(
            item, recurrence.tracking_id, recurrence.remediated_at, recurrence.episode, ingested_at
        )
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
    *,
    timed_groups: Collection[str] = (),
) -> AttestationLapse | None:
    """Return one case's lapse when a run at `as_of` finds it untimed past its window.

    A case is untimed when no linked observation declares a source timestamp, no attestation
    is recorded, and the report's current group for it (`timed_groups` names every tracking id
    whose current group carries a source time) declares none either, linked or not; a system
    record is always timed. Its window closes at the `VER-TFR-EVU` deadline from its first
    sighting, and a run at or past that close records the lapse once and for good. A run
    before the first sighting records nothing and computes no deadline. A detection time that
    arrives before any run sees the lapse prevents it, which is why the record is only as
    frequent as the runs (ADR 0019).
    """

    if not isinstance(policy, SelectedPolicy):
        raise TypeError("policy must be a SelectedPolicy")
    now = _utc(as_of, "as_of")
    if (
        case.attestation is not None
        or case.tracking_id in timed_groups
        or any(link.observed_at is not None for link in case.links)
    ):
        return None
    seen = first_sighting(case, ingested_at)
    # Checked before any day is added, so a run can never reach an unrepresentable close.
    if seen is None or now < seen:
        return None
    closed, force = _lapse_window(case.tracking_id, seen, policy)
    if now < closed:
        return None
    return AttestationLapse(
        tracking_id=case.tracking_id,
        first_seen_at=seen,
        window_closed_at=closed,
        force=force,
    )


def attestation_lapses(
    cases: Sequence[CaseTiming],
    ingested_at: Mapping[str, datetime],
    policy: SelectedPolicy,
    as_of: datetime,
    *,
    timed_groups: Collection[str] = (),
) -> tuple[AttestationLapse, ...]:
    """Return every case's lapse at `as_of`, in tracking id order."""

    found = (
        attestation_lapse(case, ingested_at, policy, as_of, timed_groups=timed_groups)
        for case in cases
    )
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


def derive_response_gaps(
    groups: Sequence[VulnerabilityGroup],
    history: ResponseGapHistory,
    policy: SelectedPolicy,
    as_of: datetime,
    *,
    ingested_at: datetime,
) -> tuple[Observation, ...]:
    """Return every response gap a store's state shows at `as_of`: recurrences, then lapses.

    `groups` are the report's own, every current open observation linked or not, so a run
    agrees with the report's warning before `cases correlate` links what came back. Each
    record is ingested at `ingested_at`, which reaches neither its id nor a report.
    """

    if not isinstance(history, ResponseGapHistory):
        raise TypeError("history must be a ResponseGapHistory")
    records = [
        record
        for recurrence in remediation_recurrences(groups, history.remediations)
        for record in recurrence_observations(recurrence, ingested_at=ingested_at)
    ]
    timed = timed_group_ids(groups)
    records.extend(
        attestation_lapse_observation(lapse, ingested_at=ingested_at)
        for lapse in attestation_lapses(
            history.cases, history.ingested_at, policy, as_of, timed_groups=timed
        )
    )
    return tuple(records)


def planned_reduction_lapse(
    group: VulnerabilityGroup, evaluation: EvaluationInput | None, as_of: datetime
) -> PlanLapse | None:
    """Return one record's lapsed planned reduction at `as_of`, or None (plan D2).

    It lapses when all five hold: the record is ARTIFACT-origin and its evaluation states a
    `projectedNextReduction` at E to target R; `as_of` is strictly after E, as every deadline
    passes; its current rating is above R; no completed reduction to R or below is recorded
    from the evaluation's `completedAt` through E, both ends included; and its resolved status
    leaves a weakness to reduce (D3). The clock is the provider's own E, never the pinned
    `VDR-TFR-PVR` target, which `overdueStatus` already publishes. A plan stated with E before
    its own `completedAt` has an empty window, so it lapses once E has passed.
    """

    if not isinstance(group, VulnerabilityGroup):
        raise TypeError("group must be a VulnerabilityGroup")
    now = _utc(as_of, "as_of")
    if evaluation is None:
        return None
    if not isinstance(evaluation, EvaluationInput):
        raise TypeError("evaluation must be an EvaluationInput")
    plan = evaluation.projected_next_reduction
    # A system record never recurs and so never states a plan of its own that lapses here.
    if (
        plan is None
        or any(item.origin is ObservationOrigin.SYSTEM for item in group.observations)
        or evaluation.resolved_status in PLAN_LAPSE_EXCLUDED_STATUSES
    ):
        return None
    planned = _utc(plan.estimated_at, "estimated_at")
    if now <= planned or evaluation.pain <= plan.target_rating:
        return None
    opened = _utc(evaluation.completed_at, "completed_at")
    target = plan.target_rating
    if any(_meets_plan(item, target, opened, planned) for item in evaluation.pain_reduction_events):
        return None
    return PlanLapse(
        tracking_id=group.tracking_id,
        completed_at=opened,
        estimated_at=planned,
        target_rating=plan.target_rating,
        current_rating=evaluation.pain,
    )


def planned_reduction_lapses(
    groups: Sequence[VulnerabilityGroup],
    evaluations: Mapping[str, EvaluationInput],
    as_of: datetime,
) -> tuple[PlanLapse, ...]:
    """Return every group's lapsed plan at `as_of`, by tracking id and then planned time.

    `groups` are the report's own, every current open observation, and `evaluations` maps a
    correlation tracking id to the evaluation the report reads for it, so a case no current
    open observation matches is in no report and lapses nowhere (plan F2).
    """

    found = (
        planned_reduction_lapse(group, evaluations.get(group.tracking_id), as_of)
        for group in groups
    )
    return tuple(sorted((item for item in found if item is not None), key=_plan_lapse_order))


def timed_group_ids(groups: Sequence[VulnerabilityGroup]) -> frozenset[str]:
    """Return every group whose current members carry a source time, linked or not (F03)."""

    return frozenset(
        group.tracking_id for group in groups if group.earliest_observed_at is not None
    )


def recurrence_slot(record: Observation) -> tuple[str, ResourceRef]:
    """Return what one recorded recurrence holds once: its remediation key and its resource (K1).

    The first record of a failed remediation and resource stands, written once, so a later
    reading of an earlier detection on that resource appends nothing; the slot, not the
    detection instant, says whether a recurrence is already recorded.
    """

    return record.context_key, record.resource


def rebuilt_recurrence(
    record: Observation, groups: Sequence[VulnerabilityGroup]
) -> Observation | None:
    """Rebuild a recorded recurrence from its own remediation instant, or None for no backing.

    The rebuild reads the record's case, remediation instant and episode, never the case's
    current ones: a recorded failure of a remediation is a permanent fact, so a later
    re-evaluation does not unmake it (ADR 0015 Decision 40, applied here). It is the earliest
    current open artifact observation of that case on the record's resource detected after
    that instant, which may be earlier than the recorded one when an earlier scan arrived since.
    """

    parts = recurrence_key_parts(record.context_key)
    if parts is None:  # pragma: no cover - the reader holds every recurrence key to its form
        return None
    tracking_id, _, episode = parts
    remediated_at = datetime.fromisoformat(record.metadata_value("recurrence.remediatedAt"))
    group = next((item for item in groups if item.tracking_id == tracking_id), None)
    if group is None:
        return None
    found = remediation_recurrence(group, remediated_at, episode=episode)
    if found is None:
        return None
    backing = [item for item in found.recurring if item.resource == record.resource]
    if not backing:
        return None
    return _recurrence(backing[0], tracking_id, remediated_at, episode, record.ingested_at)


def rebuilt_lapse(
    record: Observation, history: ResponseGapHistory, policy: SelectedPolicy
) -> Observation | None:
    """Rebuild a recorded lapse from its case's first sighting under this run's profile.

    A lapse recorded by a run that found the case untimed is permanent, so the rebuild does not
    ask whether the case is timed now: it asks only whether the case's first sighting and this
    run's window close name the recorded instant. None when the case has no first sighting.
    """

    tracking_id = record.metadata_value("attestation.caseTrackingId")
    case = next((item for item in history.cases if item.tracking_id == tracking_id), None)
    seen = None if case is None else first_sighting(case, history.ingested_at)
    if seen is None:
        return None
    closed, force = _lapse_window(tracking_id, seen, policy)
    lapse = AttestationLapse(
        tracking_id=tracking_id, first_seen_at=seen, window_closed_at=closed, force=force
    )
    return attestation_lapse_observation(lapse, ingested_at=record.ingested_at)


def lapse_disproof(record: Observation, history: ResponseGapHistory) -> tuple[str, datetime] | None:
    """Return a linked observation that timed a recorded lapse's case inside its window.

    The window is the record's own, closed at its observed instant. A linked observation that
    declares a source timestamp and that the store recorded at or before that close gave the
    case a detection time in time, so the lapse is disproved; the earliest such observation is
    returned with the instant it was recorded. A later one does not disprove it (F1).
    """

    tracking_id = record.metadata_value("attestation.caseTrackingId")
    closed_at = record.observed_at
    case = next((item for item in history.cases if item.tracking_id == tracking_id), None)
    if case is None or closed_at is None:
        return None
    timed = sorted(
        (history.ingested_at[link.observation_id], link.observation_id)
        for link in case.links
        if link.observed_at is not None and link.observation_id in history.ingested_at
    )
    early = [(seen, observation_id) for seen, observation_id in timed if seen <= closed_at]
    if not early:
        return None
    seen, observation_id = early[0]
    return observation_id, seen


# *--- Helper Functions ---*


def _recurrence(
    recurring: Observation,
    tracking_id: str,
    remediated_at: datetime,
    episode: int,
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
        context_key=recurrence_context_key(tracking_id, remediated, episode),
        origin=ObservationOrigin.SYSTEM,
    )
    return replace(observation, observation_id=observation.derived_observation_id)


# NOTE: Correlation already orders a group's members totally, so on the public path the id only
# breaks a tie a hand-built `RemediationRecurrence` can present; it is kept as a defence.
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


def _lapse_window(tracking_id: str, seen: datetime, policy: SelectedPolicy) -> tuple[datetime, str]:
    """Return a lapse's window close and the rule's force, read from the selected rule.

    A first sighting so late that the deadline leaves the years `datetime` holds raises
    `LapseClockError`, which the report layer names as `clock_out_of_range`.
    """

    try:
        deadline = policy.deadline_for_rule(ATTESTATION_LAPSE_RULE, seen)
        closed = deadline.due_at.astimezone(UTC)
    except OverflowError as exc:
        raise LapseClockError(tracking_id, seen) from exc
    return closed, deadline.force.value


def _require_episode(episode: object) -> None:
    """Refuse an episode ordinal that is not a positive integer."""

    if not isinstance(episode, int) or isinstance(episode, bool) or episode < 1:
        raise ValueError("episode must be a positive integer")


def _lapse_order(lapse: AttestationLapse) -> tuple[str, datetime]:
    """Order lapses by the case they name, then by window close."""

    return lapse.tracking_id, lapse.window_closed_at


def _meets_plan(
    event: PainReductionEvent, target: PainRating, opened: datetime, planned: datetime
) -> bool:
    """Say whether one completed reduction reached the target inside the plan's window.

    The window runs from the evaluation that states the plan through its planned time, both
    ends included, since that evaluation asserts the rating and the plan together (plan F5).
    """

    return event.rating <= target and opened <= _utc(event.reduced_at, "reduced_at") <= planned


def _plan_lapse_order(lapse: PlanLapse) -> tuple[str, datetime]:
    """Order plan lapses by the case they name, then by planned time."""

    return lapse.tracking_id, lapse.estimated_at


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
    "LapseClockError",
    "LinkedEvidence",
    "PLAN_LAPSE_EXCLUDED_STATUSES",
    "PlanLapse",
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
    "Remediation",
    "RemediationRecurrence",
    "ResponseGapHistory",
    "attestation_lapse",
    "attestation_lapse_observation",
    "attestation_lapse_resource",
    "attestation_lapses",
    "derive_response_gaps",
    "first_sighting",
    "lapse_disproof",
    "planned_reduction_lapse",
    "planned_reduction_lapses",
    "recurrence_case_tracking_id",
    "recurrence_key_parts",
    "recurrence_slot",
    "recurrence_context_key",
    "rebuilt_lapse",
    "rebuilt_recurrence",
    "recurrence_observations",
    "remediation_recurrence",
    "remediation_recurrences",
    "timed_group_ids",
]
