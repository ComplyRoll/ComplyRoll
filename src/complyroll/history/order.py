# ******************************************************************************
# *Title: Evaluation Order*
# *Author: Kyle Versluis*
# *Description: Order evaluations against detection time from stored history.*
# ******************************************************************************
"""Order a case's evaluation against its detection time, read from stored history.

The history writers refuse what a report from the store would refuse, so a writer
resolves a case's detection time exactly as the compiler does: from the current open
observation group (never from the case's links, which lag the group until `cases
correlate` runs), through `reports.vdt.resolve_detection_time`, and states the result
with `reports.vdt.evaluation_order_diagnostic`. The lines a writer prints are therefore
the lines `report vdt --db` prints for the same record (ADR 0007 and ADR 0008
amendments 2026-10-14). `store verify` reads the same resolution back as an audit fault,
for an inversion that arrived around the writers, such as through `ingest`.
"""

# *--- Imports ---*

from __future__ import annotations

from collections.abc import Collection, Sequence
from datetime import datetime

from complyroll.adapters import DiagnosticLevel
from complyroll.correlation import VulnerabilityGroup, group_open_observations
from complyroll.events import EventRepository
from complyroll.policy import (
    CertificationClass,
    CertificationProfile,
    load_bundled_rule_source_snapshot,
    select_policy,
)
from complyroll.reports.vdt import (
    CLOCK_OUT_OF_RANGE,
    DetectionAttestation,
    ReportDiagnostic,
    clock_problem,
    detection_clock,
    detection_clock_message,
    evaluation_clock_message,
    evaluation_order_diagnostic,
    observation_clock_message,
    resolve_detection_time,
)

from .fold import (
    CaseState,
    HistoryError,
    HistoryFault,
    fold_all_cases,
    rehydrate_observation_records,
    rehydrate_observations,
)

# *--- Types ---*


class EvaluationOrderError(HistoryError):
    """A write would leave an evaluation completed before its record's detection time.

    `diagnostics` holds every `evaluation_before_detection` ERROR the write found, in
    the order a report from the store would raise them, so the command prints them
    exactly as `report vdt --db` does.
    """

    def __init__(self, diagnostics: Sequence[ReportDiagnostic]) -> None:
        self.diagnostics: tuple[ReportDiagnostic, ...] = tuple(diagnostics)
        summary = "; ".join(item.render() for item in self.diagnostics)
        super().__init__(f"evaluations would precede detection: {summary}")


# *--- Core Logic ---*


def current_groups(repository: EventRepository) -> dict[str, VulnerabilityGroup]:
    """Return the open observation groups a report from the store compiles, by tracking id.

    `reports.replay.compile_record_set_from_history` rehydrates the same observations and
    `compile_record_set` groups them with `correlate_observations(...).groups`, which is
    what `group_open_observations` returns. The mapping keeps the compiler's group order.
    """

    return {
        group.tracking_id: group
        for group in group_open_observations(rehydrate_observations(repository))
    }


def case_order_diagnostic(
    case: CaseState,
    group: VulnerabilityGroup,
    *,
    completed_at: datetime,
    attested_at: datetime | None,
    sources: Collection[str] | None = None,
    label: str | None = None,
) -> ReportDiagnostic | None:
    """Order one case's evaluation against its current group's detection time.

    `attested_at` is the attestation the report would read for this case: the recorded
    one when an evaluation is being written, the new instant when an attestation is.
    Detection resolves exactly as the compiler resolves it, so an attestation never
    overrides a known source timestamp. A group with no resolvable detection time
    returns None; the report refuses it as `detection_time_missing`, not as an ordering
    error, and so does one whose detection time has no UTC instant, which the report
    refuses as `clock_out_of_range`. When `sources` is given, a detection time resolved
    from any other source returns None, which lets `cases attest-detection` refuse only
    what its own attestation decides. `label` names the record as the report will once the
    write lands; by default it is the case's own `label`.
    """

    if case.tracking_id != group.tracking_id:
        raise ValueError(
            f"case {case.tracking_id!r} is not the case of group {group.tracking_id!r}"
        )
    attestation = (
        DetectionAttestation()
        if attested_at is None
        else DetectionAttestation(by_tracking_id={case.tracking_id: attested_at})
    )
    clock = detection_clock(group, attestation)
    if clock is not None and clock_problem(clock) is not None:
        return None
    detected_at, detected_source = resolve_detection_time(group, attestation)
    if detected_at is None:
        return None
    if sources is not None and detected_source not in sources:
        return None
    return evaluation_order_diagnostic(
        tracking_id=case.label if label is None else label,
        location=group.source_record_id,
        detected_at=detected_at,
        detected_source=detected_source,
        completed_at=completed_at,
        source_type=group.source_type,
    )


def evaluation_order_faults(repository: EventRepository) -> tuple[HistoryFault, ...]:
    """Return every case whose current evaluation precedes its detection time, as faults.

    Each case with a current evaluation and an open group in `current_groups` resolves
    its detection time with its recorded attestation, exactly as a report from the store
    does. An ERROR becomes an `evaluation_before_detection` fault at the sequence of the
    event that recorded the current evaluation, carrying the compiler's message, so
    `store verify` and `report vdt --db` describe the record in the same words. A partial
    group's WARNING is published by the report and is not a fault. A case with no open
    group (`stale_case`) or no resolvable detection time is in no report's order check
    and is skipped. Observations are rehydrated only when some case has an evaluation.
    Faults are ordered as `audit_history` orders them.
    """

    evaluated = [case for case in fold_all_cases(repository) if case.current_evaluation]
    if not evaluated:
        return ()
    groups = current_groups(repository)
    faults: list[HistoryFault] = []
    for case in evaluated:
        evaluation = case.current_evaluation
        group = groups.get(case.tracking_id)
        if evaluation is None or group is None:
            continue
        diagnostic = case_order_diagnostic(
            case,
            group,
            completed_at=evaluation.completed_at,
            attested_at=None if case.attestation is None else case.attestation.detected_at,
        )
        if diagnostic is None or diagnostic.level is not DiagnosticLevel.ERROR:
            continue
        faults.append(
            HistoryFault(
                sequence=evaluation.sequence, code=diagnostic.code, message=diagnostic.message
            )
        )
    return tuple(sorted(faults, key=lambda fault: (fault.sequence, fault.code)))


def clock_faults(repository: EventRepository) -> tuple[HistoryFault, ...]:
    """Return every clock in history some reader refuses as `clock_out_of_range`, as faults.

    One predicate, `reports.vdt.clock_problem`, decides both sides. An observation whose
    source time has no UTC instant is a fault at its own sequence: the report, coverage and
    `cases correlate` each convert it. A group's detection time, resolved with the cases'
    recorded attestations as a report from the store resolves it, is a fault when its
    VER-TFR-EVU deadline overflows under either class of the pinned rules, at the earliest
    observation that gives it or at the attestation, with the report's message; a group
    whose clock already failed its conversion is named once, by its observations. The case
    of such a group that carries a current evaluation is a fault, at that evaluation's event,
    when the evaluation's VDR-TFR-PVR or VER-TFR-MAV deadline overflows under either class:
    the report computes both from its `completedAt`.
    """

    records = rehydrate_observation_records(repository)
    faults: list[HistoryFault] = []
    sequences: dict[str, int] = {}
    for sequence, observation in records:
        sequences.setdefault(observation.observation_id, sequence)
        if observation.observed_at is None:
            continue
        problem = clock_problem(observation.observed_at)
        if problem is not None:
            message = observation_clock_message(
                observation.observation_id, observation.observed_at, problem
            )
            faults.append(HistoryFault(sequence=sequence, code=CLOCK_OUT_OF_RANGE, message=message))
    snapshot = load_bundled_rule_source_snapshot()
    policies = tuple(
        select_policy(snapshot, CertificationProfile(certification_class=value))
        for value in CertificationClass
    )
    cases = {case.tracking_id: case for case in fold_all_cases(repository)}
    attested = {
        tracking_id: case.attestation
        for tracking_id, case in cases.items()
        if case.attestation is not None
    }
    attestation = DetectionAttestation(
        by_tracking_id={key: record.detected_at for key, record in attested.items()}
    )
    for group in group_open_observations([observation for _, observation in records]):
        clock = detection_clock(group, attestation)
        if clock is None or clock_problem(clock) is not None:
            continue
        case = cases.get(group.tracking_id)
        evaluation = None if case is None else case.current_evaluation
        label = group.tracking_id if case is None else case.label
        if evaluation is not None:
            late = clock_problem(evaluation.completed_at, policies, evaluation=evaluation)
            if late is not None:
                message = evaluation_clock_message(label, evaluation.completed_at, late)
                faults.append(
                    HistoryFault(
                        sequence=evaluation.sequence, code=CLOCK_OUT_OF_RANGE, message=message
                    )
                )
        problem = clock_problem(clock, policies)
        if problem is None:
            continue
        if group.earliest_observed_at is None:
            sequence = attested[group.tracking_id].sequence
        else:
            sequence = min(
                sequences[observation.observation_id]
                for observation in group.observations
                if observation.observed_at == clock
            )
        message = detection_clock_message(label, clock, problem)
        faults.append(HistoryFault(sequence=sequence, code=CLOCK_OUT_OF_RANGE, message=message))
    return tuple(sorted(faults, key=lambda fault: (fault.sequence, fault.code)))


__all__ = [
    "EvaluationOrderError",
    "case_order_diagnostic",
    "clock_faults",
    "current_groups",
    "evaluation_order_faults",
]
