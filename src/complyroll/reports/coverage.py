# ******************************************************************************
# *Title: Coverage Evidence*
# *Author: Kyle Versluis*
# *Description: Coverage clocks, windows and status from the inventory.*
# ******************************************************************************
"""Coverage and freshness evidence from the information resource inventory (ADR 0015)."""

# *--- Imports ---*

from __future__ import annotations

from dataclasses import dataclass

from complyroll.models import ResourceRef
from complyroll.policy import COVERAGE_RULE_IDS

from .inventory import DRIFT_UNKNOWN, InformationResource

# *--- Configuration ---*

MVX_RULE = "VDR-TFR-MVX"
NMV_RULE = "VDR-TFR-NMV"
PCD_RULE = "VDR-TFR-PCD"
PDD_RULE = "VDR-TFR-PDD"
PSD_RULE = "VDR-TFR-PSD"

DRIFT_LIKELIHOOD_UNKNOWN = "drift_likelihood_unknown"

# A sample group's clock names the group as a logical resource, the identity a later gap
# observation will carry.
SAMPLE_GROUP_TYPE = "logical"
SAMPLE_GROUP_PREFIX = "sample-group/"


# *--- Types ---*


@dataclass(frozen=True, slots=True)
class ClockKey:
    """One clock an entry carries: a rule over the entry itself, or over its sample group."""

    rule_id: str
    resource: ResourceRef | None = None
    sample_group: str | None = None

    def __post_init__(self) -> None:
        if self.rule_id not in COVERAGE_RULE_IDS:
            raise ValueError(f"{self.rule_id!r} is not a coverage rule")
        if (self.resource is None) == (self.sample_group is None):
            raise ValueError("a clock covers exactly one resource or one sample group")
        if (self.sample_group is not None) != (self.rule_id == PSD_RULE):
            raise ValueError(f"{PSD_RULE} runs per sample group and every other rule per resource")

    @property
    def subject(self) -> ResourceRef:
        """Return the identity the clock covers; a sample group reads as a logical resource."""
        if self.resource is not None:
            return self.resource
        return ResourceRef(
            resource_id=f"{SAMPLE_GROUP_PREFIX}{self.sample_group}",
            resource_type=SAMPLE_GROUP_TYPE,
        )

    @property
    def context_key(self) -> str:
        subject = self.subject
        return f"{subject.resource_type}:{subject.resource_id}"

    @property
    def sort_key(self) -> tuple[str, str, str]:
        subject = self.subject
        return (self.rule_id, subject.resource_type, subject.resource_id)


@dataclass(frozen=True, slots=True)
class EntryClocks:
    """The clocks one inventory entry carries, and the warning codes its attributes raise."""

    clocks: tuple[ClockKey, ...]
    warnings: tuple[str, ...] = ()


# *--- Clock Table ---*


def entry_clocks(entry: InformationResource) -> EntryClocks:
    """Return the clocks an entry's attributes select, with any warning returned as data."""
    ref = entry.ref
    clocks = []
    warnings = []
    if entry.machine_based:
        clocks.append(ClockKey(MVX_RULE, resource=ref))
        if entry.drift_likely is False:
            clocks.append(ClockKey(PCD_RULE, resource=ref))
        else:
            # Unknown drift takes PDD, the shorter window, and says so.
            clocks.append(ClockKey(PDD_RULE, resource=ref))
            if entry.drift_likely == DRIFT_UNKNOWN:
                warnings.append(DRIFT_LIKELIHOOD_UNKNOWN)
    else:
        clocks.append(ClockKey(NMV_RULE, resource=ref))
    if entry.sample_group is not None:
        clocks.append(ClockKey(PSD_RULE, sample_group=entry.sample_group))
    return EntryClocks(
        clocks=tuple(sorted(clocks, key=lambda clock: clock.sort_key)),
        warnings=tuple(warnings),
    )


__all__ = [
    "DRIFT_LIKELIHOOD_UNKNOWN",
    "MVX_RULE",
    "NMV_RULE",
    "PCD_RULE",
    "PDD_RULE",
    "PSD_RULE",
    "SAMPLE_GROUP_PREFIX",
    "SAMPLE_GROUP_TYPE",
    "ClockKey",
    "EntryClocks",
    "entry_clocks",
]
