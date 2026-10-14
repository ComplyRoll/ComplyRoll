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
amendments 2026-10-14).
"""

# *--- Imports ---*

from __future__ import annotations

from collections.abc import Collection, Sequence
from datetime import datetime

from complyroll.correlation import VulnerabilityGroup, group_open_observations
from complyroll.events import EventRepository
from complyroll.reports.vdt import (
    DetectionAttestation,
    ReportDiagnostic,
    evaluation_order_diagnostic,
    resolve_detection_time,
)

from .fold import CaseState, HistoryError, rehydrate_observations

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
) -> ReportDiagnostic | None:
    """Order one case's evaluation against its current group's detection time.

    `attested_at` is the attestation the report would read for this case: the recorded
    one when an evaluation is being written, the new instant when an attestation is.
    Detection resolves exactly as the compiler resolves it, so an attestation never
    overrides a known source timestamp. A group with no resolvable detection time
    returns None; the report refuses it as `detection_time_missing`, not as an ordering
    error. When `sources` is given, a detection time resolved from any other source
    returns None, which lets `cases attest-detection` refuse only what its own
    attestation decides.
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
    detected_at, detected_source = resolve_detection_time(group, attestation)
    if detected_at is None:
        return None
    if sources is not None and detected_source not in sources:
        return None
    return evaluation_order_diagnostic(
        tracking_id=group.tracking_id,
        location=group.source_record_id,
        detected_at=detected_at,
        detected_source=detected_source,
        completed_at=completed_at,
    )


__all__ = [
    "EvaluationOrderError",
    "case_order_diagnostic",
    "current_groups",
]
