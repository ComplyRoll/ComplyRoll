# ******************************************************************************
# *Title: Report Checks*
# *Author: Kyle Versluis*
# *Description: Clock, order and tracking id rules shared with history.*
# ******************************************************************************
"""Clock, order, tracking id and record-kind rules the compile and `history/` share."""

# *--- Imports ---*

from __future__ import annotations

from collections.abc import Callable, Iterable, Sequence
from datetime import UTC, datetime
from typing import Protocol, TypeVar

from complyroll.adapters import DETECTION_FAILURE_SOURCE_TYPE, DiagnosticLevel
from complyroll.correlation import VulnerabilityGroup
from complyroll.models import NO_UTC_INSTANT, ObservationOrigin, PainRating
from complyroll.policy import SelectedPolicy
from complyroll.store.sqlite import bounded, shown

from .evaluations import EvaluationInput
from .gaps import COVERAGE_GAP_SOURCE_TYPE
from .model import DetectionAttestation, ReportDiagnostic, iso

# *--- Configuration ---*

_EVALUATION_RULE = "VER-TFR-EVU"
_RESPONSE_RULE = "VDR-TFR-PVR"
_ACCEPTANCE_RULE = "VER-TFR-MAV"


# *--- Record Kinds ---*

#: How a refusal names the record of each reserved source type (ADR 0015).
_SYSTEM_RECORD_KINDS = {
    DETECTION_FAILURE_SOURCE_TYPE: "detection process failure",
    COVERAGE_GAP_SOURCE_TYPE: "coverage gap",
}


def system_record_kind(source_type: str) -> str:
    """Name the record of one reserved source type, or "system record" for any other.

    `reports.vdt` and `history.writers` name a refusal with it, so both paths agree.
    """

    return _SYSTEM_RECORD_KINDS.get(source_type, "system record")


# *--- Clocks ---*

#: The ERROR a report raises, and the fault `store verify` reports, for a clock in history that
#: no report can compute with (cleanup PR 5a, CL-54).
CLOCK_OUT_OF_RANGE = "clock_out_of_range"


class EvaluatedClock(Protocol):
    """The fields of an evaluation the policy deadlines read: its clock and its response inputs."""

    @property
    def completed_at(self) -> datetime: ...

    @property
    def pain(self) -> PainRating: ...

    @property
    def is_internet_reachable(self) -> bool: ...

    @property
    def is_likely_exploitable(self) -> bool: ...


# NOTE: A current build reads every clock inside the years 1970 through 9000 UTC, so only
# history an earlier build wrote reaches either refusal: 0.3.0a0 read CKLB and XCCDF clocks
# and every CLI clock unguarded. Year 1 Z, 1969, 9001 and 9990 compute fine and are never
# refused here.
def clock_problem(
    clock: datetime,
    policies: Sequence[SelectedPolicy] = (),
    *,
    evaluation: EvaluatedClock | None = None,
) -> str | None:
    """Say why one stored clock cannot be computed with, or None when it can.

    Every use a report makes of a stored clock is checked, and only those: the conversion to
    UTC every reader makes, and, for each policy given, every policy deadline a report adds to
    the clock. A detection time (no `evaluation`) takes VER-TFR-EVU. An evaluation's
    `completedAt` (`evaluation` given) takes its VDR-TFR-PVR response target and VER-TFR-MAV
    threshold. A report passes its own policy and `store verify` one per class, so verify names
    every clock some report refuses. Every one of these timeframes is in days in every class of
    the pinned rules, so the calendar zone a policy carries cannot change the answer.
    """

    try:
        instant = clock.astimezone(UTC)
    except OverflowError:
        return NO_UTC_INSTANT
    for policy in policies:
        for rule_id, deadline in _clock_deadlines(policy, instant, evaluation):
            try:
                deadline()
            except OverflowError:
                return (
                    f"leaves no room for its {rule_id} deadline under Class "
                    f"{policy.profile.certification_class.value} before the end of year 9999"
                )
    return None


def _clock_deadlines(
    policy: SelectedPolicy, instant: datetime, evaluation: EvaluatedClock | None
) -> tuple[tuple[str, Callable[[], object]], ...]:
    """Return each deadline `_compute_deadlines` computes from one clock, by its rule id."""

    if evaluation is None:
        return ((_EVALUATION_RULE, lambda: policy.evaluation_deadline(instant)),)
    return (
        (
            _RESPONSE_RULE,
            lambda: policy.response_deadline(
                instant,
                pain=evaluation.pain,
                is_internet_reachable=evaluation.is_internet_reachable,
                is_likely_exploitable=evaluation.is_likely_exploitable,
            ),
        ),
        (_ACCEPTANCE_RULE, lambda: policy.acceptance_deadline(instant)),
    )


def detection_clock_message(tracking_id: str, clock: datetime, problem: str) -> str:
    """Word one record refused for its detection time, as the report and verify both print it."""

    return (
        f"{tracking_id} has detection time {clock.isoformat()} in history, which {problem}, "
        "so no report can compute with it"
    )


def evaluation_clock_message(tracking_id: str, clock: datetime, problem: str) -> str:
    """Word one record refused for its evaluation's `completedAt`, in the report and verify."""

    return (
        f"{tracking_id} has an evaluation completed {clock.isoformat()} in history, which "
        f"{problem}, so no report can compute with it"
    )


def observation_clock_message(observation_id: str, clock: datetime, problem: str) -> str:
    """Word one observation refused for its source time, wherever a reader converts it."""

    # A system observation's id is its writer's to choose and is read before any check of it.
    return (
        f"observation {bounded(observation_id)} has source time {clock.isoformat()} in history, "
        f"which {problem}, so no report can compute with it"
    )


def detection_clock(
    group: VulnerabilityGroup, attestation: DetectionAttestation
) -> datetime | None:
    """Return the clock `resolve_detection_time` resolves, before it converts it to UTC."""

    if group.earliest_observed_at is not None:
        return group.earliest_observed_at
    return attestation.for_tracking_id(group.tracking_id)


def resolve_detection_time(
    group: VulnerabilityGroup,
    attestation: DetectionAttestation,
) -> tuple[datetime | None, str]:
    """Resolve one group's detection time without ever guessing one.

    A supplied attestation applies only to groups where no observation declares a
    source timestamp; it never overrides a known one (ADR 0007 amendment). A detection
    process failure is checked first: it is timed by the instant it was recorded, is
    never attested, and never reads as a source artifact's timestamp (ADR 0014).

    The source is `system`, `artifact`, `artifact-partial`, `attestation`, or
    `missing` with no instant. It is public so the history writers resolve a case's
    detection time exactly as a report from the store does.
    """

    observed_at = group.earliest_observed_at
    if observed_at is not None and _is_system_group(group):
        return observed_at.astimezone(UTC), "system"
    if group.earliest_observed_at is not None:
        source = "artifact-partial" if group.has_partial_timestamps else "artifact"
        return group.earliest_observed_at.astimezone(UTC), source
    attested = attestation.for_tracking_id(group.tracking_id)
    if attested is not None:
        return attested.astimezone(UTC), "attestation"
    return None, "missing"


# *--- Evaluation Order ---*

#: The remedy a refusal names, by the source of the detection time it is refused against.
#: The compiler, the history writers and `store verify` print one text per source, and
#: per source type for `system`, so each must hold on both paths (ADR 0007 amendment
#: 2026-10-14). The `system` text is a detection process failure's; a type may name its own.
_ORDER_REMEDIES = {
    "artifact": "supply the artifact that detected it earlier, or correct completedAt",
    "attestation": "attest an earlier detection time, or correct completedAt",
    "system": (
        "a detection process failure is detected when it is recorded, at the ingest "
        "--as-of in history and at the run's as-of on the stateless path, so evaluate it "
        "at or after that instant, correct completedAt, or on the stateless path report "
        "with an --as-of no later than completedAt"
    ),
}
#: A system record whose detection time is fixed by its inputs on both paths names no
#: as-of remedy (ADR 0015).
_SYSTEM_ORDER_REMEDIES = {
    COVERAGE_GAP_SOURCE_TYPE: (
        "a coverage gap is detected when its window closed, so evaluate it at or after that "
        "instant, or correct completedAt"
    ),
}


def evaluation_order_diagnostic(
    *,
    tracking_id: str,
    location: str,
    detected_at: datetime,
    detected_source: str,
    completed_at: datetime,
    source_type: str | None = None,
) -> ReportDiagnostic | None:
    """Order one evaluation's `completedAt` against its record's detection time.

    An evaluation completed strictly before a detection time that is the record's own
    (`artifact`, `attestation` or `system`) is the ERROR `evaluation_before_detection`;
    one completed at the detection instant is in order. A partly timestamped group's
    detection time is only the earliest known timestamp, and an observation declaring
    none may have detected it earlier, so it gets the WARNING
    `evaluation_before_partial_detection` and the record is published. Only
    `completedAt` is ordered: a reduction or a projection starts no clock. For a
    `system` detection time, the record's `source_type` chooses the remedy. `tracking_id`
    is the record as a diagnostic names it, from `record_label`.
    """

    completed = completed_at.astimezone(UTC)
    detected = detected_at.astimezone(UTC)
    if completed >= detected:
        return None
    if detected_source == "artifact-partial":
        return ReportDiagnostic(
            level=DiagnosticLevel.WARNING,
            code="evaluation_before_partial_detection",
            message=(
                f"{tracking_id} was evaluated at {iso(completed)}, before its earliest known "
                f"detection time {iso(detected)} (source artifact-partial); an observation "
                "that declares no source timestamp may have detected it earlier, so the "
                "record is published"
            ),
            location=location,
        )
    remedy = _ORDER_REMEDIES.get(detected_source)
    if detected_source == "system" and source_type is not None:
        remedy = _SYSTEM_ORDER_REMEDIES.get(source_type, remedy)
    if remedy is None:
        return None
    return ReportDiagnostic(
        level=DiagnosticLevel.ERROR,
        code="evaluation_before_detection",
        message=(
            f"{tracking_id} was evaluated at {iso(completed)}, before its detection time "
            f"{iso(detected)} (source {detected_source}); {remedy}"
        ),
        location=location,
    )


def _is_system_group(group: VulnerabilityGroup) -> bool:
    """Return True for a group of system observations, which never shares a key with others.

    Only a system observation may carry the reserved detection-process source type, so a
    group key never mixes the two origins.
    """

    return all(item.origin is ObservationOrigin.SYSTEM for item in group.observations)


# *--- Tracking IDs ---*

#: The ERROR a report raises, and the fault `store verify` reports, for two records one id
#: would publish (ADR 0008 amendment 2026-11-03).
TRACKING_ID_COLLISION = "tracking_id_collision"


class TrackingIdClaim(Protocol):
    """What the uniqueness rule reads of a record, compiled or about to be."""

    @property
    def tracking_id(self) -> str: ...

    @property
    def original_tracking_id(self) -> str: ...

    @property
    def evaluation_location(self) -> str: ...


ClaimT = TypeVar("ClaimT", bound=TrackingIdClaim)


def published_tracking_id(group: VulnerabilityGroup, evaluation: EvaluationInput | None) -> str:
    """Return the id a report publishes a group under: the evaluation's override, else its own."""

    if evaluation is not None and evaluation.tracking_id is not None:
        return evaluation.tracking_id
    return group.tracking_id


def tracking_id_collisions(claims: Iterable[ClaimT]) -> list[tuple[ClaimT, ClaimT]]:
    """Return each claim on an id an earlier claim holds, beside that earlier claim.

    An override may rename one vulnerability; it may not collapse two into one
    (ADR 0007 amendment). A report and `store verify` both decide it here.
    """

    claimed: dict[str, ClaimT] = {}
    collisions: list[tuple[ClaimT, ClaimT]] = []
    for claim in claims:
        previous = claimed.setdefault(claim.tracking_id, claim)
        if previous is not claim:
            collisions.append((previous, claim))
    return collisions


def tracking_id_collision_message(previous: TrackingIdClaim, claim: TrackingIdClaim) -> str:
    """Word one collision, as the report and `store verify` both print it."""

    return (
        f"effective tracking id {shown(claim.tracking_id)} is claimed by "
        f"{previous.evaluation_location} (originally "
        f"{previous.original_tracking_id}) and {claim.evaluation_location} "
        f"(originally {claim.original_tracking_id}); an override may rename "
        "one vulnerability but may not merge two"
    )


__all__ = [
    "CLOCK_OUT_OF_RANGE",
    "TRACKING_ID_COLLISION",
    "ClaimT",
    "EvaluatedClock",
    "TrackingIdClaim",
    "clock_problem",
    "detection_clock",
    "detection_clock_message",
    "evaluation_clock_message",
    "evaluation_order_diagnostic",
    "observation_clock_message",
    "published_tracking_id",
    "resolve_detection_time",
    "system_record_kind",
    "tracking_id_collision_message",
    "tracking_id_collisions",
]
