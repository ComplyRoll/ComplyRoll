# ******************************************************************************
# *Title: Change Obligations*
# *Author: Kyle Versluis*
# *Description: Detection obligations from declared changes and evidence.*
# ******************************************************************************
"""Per-change detection obligations read against the inventory and its evidence (ADR 0018)."""

# *--- Imports ---*

from __future__ import annotations

from bisect import bisect_left
from collections import Counter, defaultdict
from collections.abc import Iterable, Sequence
from dataclasses import dataclass
from datetime import UTC, date, datetime
from enum import Enum
from typing import Any

from complyroll.adapters import DiagnosticLevel
from complyroll.correlation import tracking_id_for
from complyroll.models import Observation, ObservationDisposition, ObservationOrigin, ResourceRef
from complyroll.policy import CertificationProfile, PolicyProvenance, RuleForce, SelectedPolicy

from .changes_input import Change, ChangeKind, ChangeSet

# NOTE: The coverage block's filing, group stop rule and formatters, shared so a change row
# reads evidence, a group and an instant exactly as a coverage clock does.
from .coverage import (
    PSD_RULE,
    SAMPLE_GROUP_PREFIX,
    SAMPLE_GROUP_TYPE,
    CoverageEvidence,
    FiledEvidence,
    _group_decommissioned_at,
    _instant_text,
    _ref_dict,
    _utc,
    coverage_label,
    file_evidence,
)
from .inventory import InformationResource, Inventory, _ref_key
from .kev import KevCatalog
from .model import ReportDiagnostic

# *--- Configuration ---*

DAC_RULE = "VDR-CSO-DAC"
AKE_RULE = "VDR-CSO-AKE"

CHANGE_RESOURCE_UNREGISTERED = "change_resource_unregistered"
CHANGE_AFTER_DECOMMISSION = "change_after_decommission"
CHANGE_PRECEDES_EXPECTED_SINCE = "change_precedes_expected_since"
KEV_AT_ACTIVATION = "kev_at_activation"

# Every change block prints this text unchanged, so no status reads as more than it is.
CHANGE_BASIS = (
    f"{DAC_RULE} states no timeframe, so a window here is only the provider's own detectBy, and "
    "a change without a window is tracked but never lapses. Changes are measured against the "
    "provider-supplied inventory named by its SHA-256 digest, so a resource it omits is listed "
    "as unregistered and opens no obligation. An obligation closes only on a verification at "
    "or after the change and at or before as-of; evidence that determined no status examines "
    "a resource without verifying it, and untimed evidence never satisfies one. A created "
    "change and a new entry's coverage clocks overlap on purpose, under different rules. A "
    "detected status is not a compliance finding."
)


# *--- Types ---*


class ObligationStatus(str, Enum):
    UNREGISTERED = "unregistered"
    RETIRED = "retired"
    LOGGED = "logged"
    DETECTED = "detected"
    LAPSED = "lapsed"
    UNDETERMINED = "undetermined"
    PENDING = "pending"


# The resources still waiting for detection: exactly what a request document asks for.
WAITING_STATUSES = frozenset(
    {ObligationStatus.LAPSED, ObligationStatus.UNDETERMINED, ObligationStatus.PENDING}
)
_OPEN_STATUSES = WAITING_STATUSES | {ObligationStatus.DETECTED}


@dataclass(frozen=True, slots=True)
class ChangeObligation:
    """One (change, resource) row at as-of, with the status its evidence supports."""

    change: Change
    # The entry's own pair, the group's logical pair, or the bare pair no entry names.
    resource: ResourceRef
    status: ObligationStatus
    entry: InformationResource | None = None
    sample_group: str | None = None
    # The first spelling in sort order that named the entry; None on any row with no entry.
    matched_as: ResourceRef | None = None
    evidence: CoverageEvidence | None = None
    stand_in: ResourceRef | None = None
    lag_seconds: int | None = None
    late: bool = False
    window_closed_at: datetime | None = None
    resumed_at: datetime | None = None
    untimed: int = 0
    # True or False only when the question applies and can be answered, else None.
    kev_at_activation: bool | None = None
    kev_tracking_ids: tuple[str, ...] = ()


@dataclass(frozen=True, slots=True)
class UnregisteredChangeResource:
    """A pair no inventory entry names, and every change that named it."""

    resource: ResourceRef
    change_ids: tuple[str, ...]

    def to_dict(self) -> dict[str, Any]:
        return {**_ref_dict(self.resource), "changeIds": list(self.change_ids)}


@dataclass(frozen=True, slots=True)
class ChangeProjection:
    """The change projection of one run, a pure function of its inputs."""

    change_set: ChangeSet
    inventory: Inventory
    as_of: datetime
    profile: CertificationProfile
    provenance: PolicyProvenance
    force: RuleForce
    obligations: tuple[ChangeObligation, ...]
    unregistered: tuple[UnregisteredChangeResource, ...]
    # Changes after as-of: listed, never measured.
    later: tuple[Change, ...]
    warnings: tuple[ReportDiagnostic, ...]

    @property
    def waiting(self) -> tuple[ChangeObligation, ...]:
        """Return the rows a request document carries: the resources still waiting."""
        return tuple(row for row in self.obligations if row.status in WAITING_STATUSES)

    def to_dict(self) -> dict[str, Any]:
        """Return the `x-complyroll.changes` block; keys are sorted when the JSON is written."""
        counts = Counter(row.status for row in self.obligations)
        change_set = self.change_set
        provenance = self.provenance
        return {
            "rule": DAC_RULE,
            "force": self.force.value,
            "provenance": {
                "repository": provenance.repository,
                "commit": provenance.commit,
                "datasetVersion": provenance.dataset_version,
                "datasetLastUpdated": provenance.dataset_last_updated,
                "sha256": provenance.dataset_sha256,
            },
            "asOf": _instant_text(self.as_of),
            "input": {
                "name": change_set.name,
                "sizeBytes": change_set.size_bytes,
                "sha256": change_set.sha256,
                "changeCount": change_set.change_count,
            },
            "inventorySha256": self.inventory.sha256,
            "summary": {status.value: counts[status] for status in ObligationStatus},
            "changes": [
                _change_row(change, self.force)
                for change in change_set.changes
                if change.occurred_at <= self.as_of
            ],
            "obligations": [
                _obligation_row(row, self.force, self.as_of) for row in self.obligations
            ],
            "unregistered": [item.to_dict() for item in self.unregistered],
            "later": [
                {
                    "changeId": change.change_id,
                    "occurredAt": _instant_text(change.occurred_at),
                    "resources": [_ref_dict(ref) for ref in change.resources],
                }
                for change in self.later
            ],
            "basis": CHANGE_BASIS,
        }


@dataclass(frozen=True, slots=True)
class _Named:
    """One thing a change names: an entry, a sample group, or a bare pair."""

    resource: ResourceRef
    entry: InformationResource | None = None
    group: str | None = None
    members: tuple[InformationResource, ...] = ()
    matched_as: ResourceRef | None = None


@dataclass(frozen=True, slots=True)
class _Subject:
    """One entry's or group's evidence and lifecycle, read once however many rows name it."""

    instants: tuple[datetime, ...]
    verifying: tuple[CoverageEvidence, ...]
    last_examined: datetime | None
    untimed: int
    expected_since: datetime
    decommissioned_at: datetime | None

    def first_verification(self, instant: datetime) -> tuple[datetime, CoverageEvidence] | None:
        """Return the first verification at or after an instant, as (when, what)."""
        index = bisect_left(self.instants, instant)
        return (
            None if index == len(self.instants) else (self.instants[index], self.verifying[index])
        )


# *--- Derivation ---*


def derive_changes(
    observations: Iterable[Observation],
    change_set: ChangeSet,
    inventory: Inventory,
    policy: SelectedPolicy,
    as_of: datetime,
    *,
    kev_catalog: KevCatalog | None = None,
) -> ChangeProjection:
    """Derive one status per (change, resource) at as-of; input order never matters."""
    cutoff = _utc(as_of)
    # The rule resolves before anything is derived, so a pinned dataset that lacks it refuses
    # the run instead of thinning the projection.
    force = policy.rule(DAC_RULE).force
    evidence = tuple(observations)
    groups = _groups(inventory)
    subjects = _Subjects(file_evidence(evidence, inventory, cutoff), inventory)
    kev = None if kev_catalog is None else _KevFindings(kev_catalog, evidence, inventory, cutoff)

    obligations: list[ChangeObligation] = []
    warnings: list[ReportDiagnostic] = []
    later: list[Change] = []
    unregistered: dict[ResourceRef, list[str]] = {}
    for change in change_set.changes:
        if change.occurred_at > cutoff:
            later.append(change)
            continue
        for named in _named_resources(change, inventory, groups):
            if named.entry is None and named.group is None:
                obligations.append(_unregistered_row(change, named))
                if named.resource not in unregistered:
                    warnings.append(_unregistered_warning(change_set, change, named.resource))
                unregistered.setdefault(named.resource, []).append(change.change_id)
                continue
            subject = subjects.read(named)
            row = _obligation(change, named, subject, subjects, kev, cutoff)
            obligations.append(row)
            warnings.extend(_row_warnings(change_set, row, subject))

    return ChangeProjection(
        change_set=change_set,
        inventory=inventory,
        as_of=cutoff,
        profile=policy.profile,
        provenance=policy.provenance,
        force=force,
        obligations=tuple(obligations),
        unregistered=tuple(
            UnregisteredChangeResource(resource=ref, change_ids=tuple(change_ids))
            for ref, change_ids in sorted(unregistered.items(), key=lambda item: _ref_key(item[0]))
        ),
        later=tuple(later),
        warnings=tuple(warnings),
    )


def _groups(inventory: Inventory) -> dict[str, tuple[InformationResource, ...]]:
    groups: defaultdict[str, list[InformationResource]] = defaultdict(list)
    for entry in inventory.entries:
        if entry.sample_group is not None:
            groups[entry.sample_group].append(entry)
    return {name: tuple(members) for name, members in groups.items()}


def _named_resources(
    change: Change, inventory: Inventory, groups: dict[str, tuple[InformationResource, ...]]
) -> list[_Named]:
    """Return one row key per entry, group or bare pair the change names, in sort order."""
    named: dict[ResourceRef, _Named] = {}
    # `resources` is sorted, so the first spelling to claim an entry is the first in sort order.
    for ref in change.resources:
        entry = inventory.entry_for(ref.resource_type, ref.resource_id)
        if entry is not None:
            named.setdefault(entry.ref, _Named(resource=entry.ref, entry=entry, matched_as=ref))
        else:
            name = _group_of(ref, groups)
            members = () if name is None else groups[name]
            named.setdefault(ref, _Named(resource=ref, group=name, members=members))
    return sorted(named.values(), key=lambda item: _ref_key(item.resource))


def _group_of(ref: ResourceRef, groups: dict[str, tuple[InformationResource, ...]]) -> str | None:
    """Return the group a pair names, or None; an entry spelling the pair never reaches here."""
    if ref.resource_type != SAMPLE_GROUP_TYPE or not ref.resource_id.startswith(
        SAMPLE_GROUP_PREFIX
    ):
        return None
    name = ref.resource_id.removeprefix(SAMPLE_GROUP_PREFIX)
    return name if name in groups else None


def _unregistered_row(change: Change, named: _Named) -> ChangeObligation:
    return ChangeObligation(
        change=change, resource=named.resource, status=ObligationStatus.UNREGISTERED
    )


def _obligation(
    change: Change,
    named: _Named,
    subject: _Subject,
    subjects: _Subjects,
    kev: _KevFindings | None,
    cutoff: datetime,
) -> ChangeObligation:
    """Return one named entry's or group's row; the first status that applies wins."""
    occurred_at = change.occurred_at
    detect_by = change.detect_by
    # A decommission after as-of has not happened at as-of, so the obligation runs on.
    decommissioned_at = subject.decommissioned_at
    if decommissioned_at is not None and decommissioned_at > cutoff:
        decommissioned_at = None
    first = subject.first_verification(occurred_at)
    verified_at, verification = (None, None) if first is None else first
    examined = subject.last_examined is not None and subject.last_examined >= occurred_at

    if decommissioned_at is not None and (
        decommissioned_at < occurred_at or detect_by is None or decommissioned_at < detect_by
    ):
        status = ObligationStatus.RETIRED
    elif not change.opens_obligation:
        status = ObligationStatus.LOGGED
    elif verification is not None:
        status = ObligationStatus.DETECTED
    elif detect_by is not None and detect_by < cutoff:
        status = ObligationStatus.LAPSED
    elif examined:
        status = ObligationStatus.UNDETERMINED
    else:
        status = ObligationStatus.PENDING

    late = (
        status is ObligationStatus.DETECTED
        and detect_by is not None
        and verified_at is not None
        and verified_at > detect_by
    )
    # Retired keeps its evidence so no fact is lost; a logged row claims none.
    keeps_evidence = status in (ObligationStatus.DETECTED, ObligationStatus.RETIRED)
    evidence = verification if keeps_evidence else None
    kev_ids = _kev_ids(kev, change, named.entry, verification, status)
    return ChangeObligation(
        change=change,
        resource=named.resource,
        status=status,
        entry=named.entry,
        sample_group=(
            named.group
            if named.group is not None
            else (None if named.entry is None else named.entry.sample_group)
        ),
        matched_as=named.matched_as,
        evidence=evidence,
        stand_in=(
            None if evidence is None or named.group is None else subjects.member_of(evidence)
        ),
        lag_seconds=(
            None
            if evidence is None or verified_at is None
            else int((verified_at - occurred_at).total_seconds())
        ),
        late=late,
        window_closed_at=detect_by if late or status is ObligationStatus.LAPSED else None,
        resumed_at=verified_at if late else None,
        untimed=subject.untimed,
        kev_at_activation=None if kev_ids is None else bool(kev_ids),
        kev_tracking_ids=kev_ids or (),
    )


def _kev_ids(
    kev: _KevFindings | None,
    change: Change,
    entry: InformationResource | None,
    verification: CoverageEvidence | None,
    status: ObligationStatus,
) -> tuple[str, ...] | None:
    """Return the KEV tracking ids at activation, or None when the question does not apply."""
    if (
        kev is None
        or status is not ObligationStatus.DETECTED
        or change.kind is not ChangeKind.CREATED
        or entry is None
        or not entry.machine_based
        or verification is None
    ):
        return None
    return kev.tracking_ids(change, entry, verification)


def _row_warnings(
    change_set: ChangeSet, row: ChangeObligation, subject: _Subject
) -> list[ReportDiagnostic]:
    change = row.change
    label = coverage_label(row.resource)
    decommissioned_at = subject.decommissioned_at
    warnings = []
    if (
        row.status is ObligationStatus.RETIRED
        and decommissioned_at is not None
        and decommissioned_at < change.occurred_at
    ):
        warnings.append(
            _warning(
                CHANGE_AFTER_DECOMMISSION,
                change_set,
                change,
                row.resource,
                f"change {change.change_id} occurred after {label} was decommissioned at "
                f"{_instant_text(decommissioned_at)}, so it opens nothing",
            )
        )
    if row.status in _OPEN_STATUSES and subject.expected_since > change.occurred_at:
        warnings.append(
            _warning(
                CHANGE_PRECEDES_EXPECTED_SINCE,
                change_set,
                change,
                row.resource,
                f"change {change.change_id} occurred before {label}'s expectedSince "
                f"{_instant_text(subject.expected_since)}; the obligation runs from occurredAt "
                "as the provider stated it, and the two statements disagree",
            )
        )
    if row.kev_at_activation:
        warnings.append(
            _warning(
                KEV_AT_ACTIVATION,
                change_set,
                change,
                row.resource,
                f"change {change.change_id} activated {label} with "
                f"{len(row.kev_tracking_ids)} open finding(s) the KEV catalog listed on or "
                f"before the change, in the artifact that verified it ({AKE_RULE})",
            )
        )
    return warnings


def _unregistered_warning(
    change_set: ChangeSet, change: Change, resource: ResourceRef
) -> ReportDiagnostic:
    return _warning(
        CHANGE_RESOURCE_UNREGISTERED,
        change_set,
        change,
        resource,
        f"change {change.change_id} names {coverage_label(resource)}, which no inventory entry "
        "or sample group carries, so it opens no obligation; add the resource to the inventory, "
        "with expectedSince at or before occurredAt for a created change",
    )


# SECURITY: Every part of the location passed its reader's identity or name rule, so it prints
# as plain text.
def _warning(
    code: str, change_set: ChangeSet, change: Change, resource: ResourceRef, message: str
) -> ReportDiagnostic:
    return ReportDiagnostic(
        level=DiagnosticLevel.WARNING,
        code=code,
        message=message,
        location=f"{change_set.name} {change.change_id} {coverage_label(resource)}",
    )


# *--- Evidence Readers ---*


class _Subjects:
    """Reads each entry's or group's evidence once, however many changes name it."""

    def __init__(self, filed: FiledEvidence, inventory: Inventory) -> None:
        self._filed = filed
        self._inventory = inventory
        self._read: dict[ResourceRef, _Subject] = {}

    def read(self, named: _Named) -> _Subject:
        held = self._read.get(named.resource)
        if held is None:
            held = self._read[named.resource] = self._build(named)
        return held

    def member_of(self, evidence: CoverageEvidence) -> ResourceRef:
        """Return the entry a piece of filed evidence names, whatever alias it spelled."""
        entry = self._inventory.entry_for(
            evidence.resource.resource_type, evidence.resource.resource_id
        )
        return evidence.resource if entry is None else entry.ref

    def _build(self, named: _Named) -> _Subject:
        rule_id = DAC_RULE if named.group is None else PSD_RULE
        filed = self._filed
        subject = named.resource
        timed = [
            (item.at, item)
            for item in filed.verifying(rule_id=rule_id, subject=subject)
            if item.at is not None
        ]
        # A group's tie goes to its least member, as a coverage clock's does, whatever the
        # evidence spelled; the least evidence of that member follows.
        timed.sort(key=lambda pair: (pair[0], _ref_key(self.member_of(pair[1])), pair[1].sort_key))
        expected_since, decommissioned_at = _lifecycle(named)
        return _Subject(
            instants=tuple(at for at, _ in timed),
            verifying=tuple(item for _, item in timed),
            last_examined=max(
                (
                    item.at
                    for item in filed.examined(rule_id=rule_id, subject=subject)
                    if item.at is not None
                ),
                default=None,
            ),
            untimed=len(filed.untimed(rule_id=rule_id, subject=subject)),
            expected_since=expected_since,
            decommissioned_at=decommissioned_at,
        )


class _KevFindings:
    """Open findings per artifact digest and entry, matched against the catalog per day."""

    def __init__(
        self,
        catalog: KevCatalog,
        observations: Sequence[Observation],
        inventory: Inventory,
        cutoff: datetime,
    ) -> None:
        self._catalog = catalog
        self._digests: dict[str, str] = {}
        self._findings: defaultdict[tuple[str, ResourceRef], list[Observation]] = defaultdict(list)
        self._held: dict[tuple[str, ResourceRef, date], tuple[str, ...]] = {}
        for observation in observations:
            if observation.origin is not ObservationOrigin.ARTIFACT:
                continue
            self._digests[observation.observation_id] = observation.source_artifact_digest
            entry = inventory.entry_for(
                observation.resource.resource_type, observation.resource.resource_id
            )
            visible = observation.observed_at is None or _utc(observation.observed_at) <= cutoff
            if (
                entry is not None
                and visible
                and observation.disposition is ObservationDisposition.OPEN
            ):
                self._findings[(observation.source_artifact_digest, entry.ref)].append(observation)

    def tracking_ids(
        self, change: Change, entry: InformationResource, verification: CoverageEvidence
    ) -> tuple[str, ...]:
        """Return the sorted tracking ids of KEV findings in the artifact that verified it."""
        key = (
            self._digests[verification.reference],
            entry.ref,
            change.occurred_at.astimezone(UTC).date(),
        )
        held = self._held.get(key)
        if held is None:
            held = self._held[key] = self._matched(*key)
        return held

    def _matched(self, digest: str, ref: ResourceRef, listed_by: date) -> tuple[str, ...]:
        return tuple(
            sorted(
                {
                    tracking_id_for(item.source_type, item.source_record_id, item.context_key)
                    for item in self._findings.get((digest, ref), ())
                    if self._catalog.matches(item.source_identifiers, on_or_before=listed_by)
                }
            )
        )


# *--- Helper Functions ---*


def _lifecycle(named: _Named) -> tuple[datetime, datetime | None]:
    """Return when an entry's or group's obligation can start, and when it stops."""
    if named.entry is not None:
        return named.entry.expected_since, named.entry.decommissioned_at
    return (
        min(member.expected_since for member in named.members),
        _group_decommissioned_at(list(named.members)),
    )


def _change_row(change: Change, force: RuleForce) -> dict[str, Any]:
    return {
        "changeId": change.change_id,
        "kind": change.kind.value,
        "occurredAt": _instant_text(change.occurred_at),
        "source": {"tool": change.source.tool, "reference": change.source.reference},
        "significant": change.significant,
        "rationale": change.rationale,
        "detectBy": _instant_text(change.detect_by),
        "job": change.job,
        "force": force.value,
    }


def _obligation_row(row: ChangeObligation, force: RuleForce, as_of: datetime) -> dict[str, Any]:
    # A waiting row with no window never closes, so its age is the signal it prints.
    age_seconds = (
        int((as_of - row.change.occurred_at).total_seconds())
        if row.status in WAITING_STATUSES
        else None
    )
    return {
        "changeId": row.change.change_id,
        **_ref_dict(row.resource),
        "entry": None if row.entry is None else _ref_dict(row.entry.ref),
        "sampleGroup": row.sample_group,
        "matchedAs": None if row.matched_as is None else _ref_dict(row.matched_as),
        "status": row.status.value,
        "force": force.value,
        "evidence": None if row.evidence is None else row.evidence.to_dict(),
        "standIn": None if row.stand_in is None else _ref_dict(row.stand_in),
        "lagSeconds": row.lag_seconds,
        "ageSeconds": age_seconds,
        "late": row.late,
        "windowClosedAt": _instant_text(row.window_closed_at),
        "resumedAt": _instant_text(row.resumed_at),
        "untimed": row.untimed,
        "kevAtActivation": row.kev_at_activation,
        "kevTrackingIds": list(row.kev_tracking_ids),
    }


__all__ = [
    "AKE_RULE",
    "CHANGE_AFTER_DECOMMISSION",
    "CHANGE_BASIS",
    "CHANGE_PRECEDES_EXPECTED_SINCE",
    "CHANGE_RESOURCE_UNREGISTERED",
    "DAC_RULE",
    "KEV_AT_ACTIVATION",
    "WAITING_STATUSES",
    "ChangeObligation",
    "ChangeProjection",
    "ObligationStatus",
    "UnregisteredChangeResource",
    "derive_changes",
]
