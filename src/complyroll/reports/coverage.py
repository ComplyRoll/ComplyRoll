# ******************************************************************************
# *Title: Coverage Evidence*
# *Author: Kyle Versluis*
# *Description: Coverage clocks, windows and status from the inventory.*
# ******************************************************************************
"""Coverage and freshness evidence from the information resource inventory (ADR 0015)."""

# *--- Imports ---*

from __future__ import annotations

from collections import Counter, defaultdict
from collections.abc import Iterable
from dataclasses import dataclass, field, replace
from datetime import UTC, datetime
from enum import Enum
from typing import Any

from complyroll.models import Observation, ObservationDisposition, ObservationOrigin, ResourceRef
from complyroll.policy import (
    COVERAGE_RULE_IDS,
    CertificationProfile,
    PolicyDeadline,
    PolicyProvenance,
    RuleForce,
    SelectedPolicy,
)

from .inventory import DRIFT_UNKNOWN, InformationResource, Inventory

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

# The tool determined a status. NOT_REVIEWED, ERROR and UNKNOWN examine and never verify, so
# a run full of errors does not satisfy a clock.
VERIFYING_DISPOSITIONS = frozenset(
    {
        ObservationDisposition.OPEN,
        ObservationDisposition.PASS,
        ObservationDisposition.NOT_APPLICABLE,
    }
)

_EARLIEST = datetime.min.replace(tzinfo=UTC)

# Every coverage block prints this text unchanged, so no status reads as more than it is.
COVERAGE_BASIS = (
    "VDR-TFR-MVX is read from detection results until Phase 3 validation runs exist. "
    "Coverage is measured against the provider-supplied inventory named by its SHA-256 "
    "digest, so an observed resource the inventory omits is listed as unregistered and is "
    "never expected. Evidence that determined no status (NOT_REVIEWED, ERROR or UNKNOWN) "
    "examines a resource without verifying it, untimed evidence never anchors a clock, and a "
    "non-machine resource is verified only by an operator attestation. A current status is "
    "not a compliance finding."
)


# *--- Types ---*


class AnchorKind(str, Enum):
    VERIFICATION = "verification"
    DECLARED = "declared"


class CoverageStatus(str, Enum):
    CURRENT = "current"
    STALE = "stale"
    MISSING = "missing"
    UNANCHORED = "unanchored"
    UNDETERMINED = "undetermined"


class EvidenceKind(str, Enum):
    OBSERVATION = "observation"
    ATTESTATION = "attestation"


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


@dataclass(frozen=True, slots=True)
class CoverageEvidence:
    """One examination: an artifact observation, or an operator attestation."""

    kind: EvidenceKind
    # The identity the evidence names: the observed pair or alias, or the attested entry.
    resource: ResourceRef
    # None only for an untimed observation; ingest time is never substituted.
    at: datetime | None
    # The observation id, or the attestation's reference text.
    reference: str
    disposition: ObservationDisposition | None = None

    def __post_init__(self) -> None:
        if (self.disposition is None) != (self.kind is EvidenceKind.ATTESTATION):
            raise ValueError("an observation carries a disposition and an attestation none")
        if self.at is None and self.kind is EvidenceKind.ATTESTATION:
            raise ValueError("an attestation is always timed")

    @property
    def sort_key(self) -> tuple[bool, datetime, str, str, str, str]:
        return (
            self.at is not None,
            self.at or _EARLIEST,
            self.kind.value,
            self.resource.resource_type,
            self.resource.resource_id,
            self.reference,
        )

    def to_dict(self) -> dict[str, Any]:
        """Return the evidence as the observation fingerprint or the attestation reference."""
        value: dict[str, Any] = {
            "kind": self.kind.value,
            "at": _instant_text(self.at),
            **_ref_dict(self.resource),
        }
        if self.disposition is None:
            value["reference"] = self.reference
        else:
            value["observationId"] = self.reference
            value["disposition"] = self.disposition.value
        return value


@dataclass(frozen=True, slots=True)
class CoverageClock:
    """One clock at as-of: what anchors it, when it falls due, and its status."""

    key: ClockKey
    force: RuleForce
    status: CoverageStatus
    anchor: AnchorKind | None = None
    # The deadline run from the anchor; None only while the clock is unanchored.
    deadline: PolicyDeadline | None = None
    # The evidence a verification anchor stands on.
    evidence: CoverageEvidence | None = None
    # The member whose evidence satisfied a sample group's clock.
    stand_in: ResourceRef | None = None

    def __post_init__(self) -> None:
        if (self.status is CoverageStatus.UNANCHORED) != (self.anchor is None):
            raise ValueError("a clock is unanchored exactly when it has no anchor")
        _check_anchor(
            self.key, self.force, self.anchor, self.deadline, self.evidence, self.stand_in
        )

    @property
    def rule_id(self) -> str:
        return self.key.rule_id

    @property
    def anchor_at(self) -> datetime | None:
        return None if self.deadline is None else self.deadline.start_at

    @property
    def due_at(self) -> datetime | None:
        return None if self.deadline is None else self.deadline.due_at

    def to_dict(self) -> dict[str, Any]:
        return {
            "ruleId": self.rule_id,
            "contextKey": self.key.context_key,
            "force": self.force.value,
            "status": self.status.value,
            "anchor": None if self.anchor is None else self.anchor.value,
            "anchorAt": _instant_text(self.anchor_at),
            "dueAt": _instant_text(self.due_at),
            "evidence": None if self.evidence is None else self.evidence.to_dict(),
            "standIn": None if self.stand_in is None else _ref_dict(self.stand_in),
        }


@dataclass(frozen=True, slots=True)
class CoverageWindow:
    """One window that closed with no verification: a single lapse of one clock."""

    key: ClockKey
    anchor: AnchorKind
    # The deadline run from the anchor; the window closed at its due instant.
    deadline: PolicyDeadline
    # The verification that resumed the clock, or None while it has not resumed.
    resumed_at: datetime | None = None
    evidence: CoverageEvidence | None = None
    stand_in: ResourceRef | None = None

    def __post_init__(self) -> None:
        _check_anchor(
            self.key, self.deadline.force, self.anchor, self.deadline, self.evidence, self.stand_in
        )
        if self.resumed_at is not None and self.resumed_at <= self.deadline.due_at:
            raise ValueError("a window resumes only after it closed")

    @property
    def rule_id(self) -> str:
        return self.key.rule_id

    @property
    def context_key(self) -> str:
        return self.key.context_key

    @property
    def force(self) -> RuleForce:
        return self.deadline.force

    @property
    def anchor_at(self) -> datetime:
        return self.deadline.start_at

    @property
    def closed_at(self) -> datetime:
        return self.deadline.due_at

    def to_dict(self) -> dict[str, Any]:
        return {
            "ruleId": self.rule_id,
            "contextKey": self.context_key,
            "force": self.force.value,
            "anchor": self.anchor.value,
            "anchorAt": _instant_text(self.anchor_at),
            "closedAt": _instant_text(self.closed_at),
            "resumedAt": _instant_text(self.resumed_at),
            "evidence": None if self.evidence is None else self.evidence.to_dict(),
            "standIn": None if self.stand_in is None else _ref_dict(self.stand_in),
        }


@dataclass(frozen=True, slots=True)
class ResourceCoverage:
    """One inventory entry at as-of: its clocks and the evidence that examined it."""

    entry: InformationResource
    clocks: tuple[CoverageClock, ...]
    last_examined: datetime | None = None
    last_verified: datetime | None = None
    # Timed artifact observations within the cutoff; on a non-machine entry none verify.
    examined_observations: int = 0
    untimed: tuple[CoverageEvidence, ...] = ()
    after_decommission: tuple[CoverageEvidence, ...] = ()
    warnings: tuple[str, ...] = ()

    @property
    def attested(self) -> bool:
        """Return True when only operator attestations can verify the entry."""
        return not self.entry.machine_based

    def to_dict(self) -> dict[str, Any]:
        """Return the entry, what examined it, and its clocks; `untimed` is the count."""
        entry = self.entry
        return {
            **_ref_dict(entry.ref),
            "machineBased": entry.machine_based,
            "attested": self.attested,
            "driftLikely": entry.drift_likely,
            "sampleGroup": entry.sample_group,
            "job": entry.job,
            "expectedSince": _instant_text(entry.expected_since),
            "decommissionedAt": _instant_text(entry.decommissioned_at),
            "aliases": [_ref_dict(alias) for alias in entry.aliases],
            "lastExamined": _instant_text(self.last_examined),
            "lastVerified": _instant_text(self.last_verified),
            "examined": self.examined_observations,
            "untimed": len(self.untimed),
            "untimedEvidence": [item.to_dict() for item in self.untimed],
            "afterDecommission": [item.to_dict() for item in self.after_decommission],
            "clocks": [clock.to_dict() for clock in self.clocks],
        }


@dataclass(frozen=True, slots=True)
class RuleSummary:
    """One rule's clocks counted by status; a sample group's clock counts once."""

    rule_id: str
    force: RuleForce
    expected: int
    current: int = 0
    stale: int = 0
    missing: int = 0
    unanchored: int = 0
    undetermined: int = 0

    def __post_init__(self) -> None:
        counted = self.current + self.stale + self.missing + self.unanchored + self.undetermined
        if self.expected != counted:
            raise ValueError("expected must equal the clocks counted by status")

    def to_dict(self) -> dict[str, Any]:
        return {
            "ruleId": self.rule_id,
            "force": self.force.value,
            "expected": self.expected,
            "current": self.current,
            "stale": self.stale,
            "missing": self.missing,
            "unanchored": self.unanchored,
            "undetermined": self.undetermined,
        }


@dataclass(frozen=True, slots=True)
class UnregisteredResource:
    """An observed resource that names no inventory entry, with its observation count."""

    resource: ResourceRef
    observations: int

    def to_dict(self) -> dict[str, Any]:
        return {**_ref_dict(self.resource), "observations": self.observations}


@dataclass(frozen=True, slots=True)
class CoverageResult:
    """The coverage projection of one run, a pure function of its inputs."""

    inventory: Inventory
    as_of: datetime
    profile: CertificationProfile
    provenance: PolicyProvenance
    summary: tuple[RuleSummary, ...]
    resources: tuple[ResourceCoverage, ...]
    windows: tuple[CoverageWindow, ...]
    unregistered: tuple[UnregisteredResource, ...]
    # Evidence observed after as-of: listed, never used.
    later: tuple[CoverageEvidence, ...]

    def to_dict(self) -> dict[str, Any]:
        """Return the `x-complyroll.coverage` block; keys are sorted when the JSON is written."""
        inventory = self.inventory
        return {
            "inventory": {
                "name": inventory.name,
                "sha256": inventory.sha256,
                "sizeBytes": inventory.size_bytes,
                "entries": inventory.entry_count,
            },
            "asOf": _instant_text(self.as_of),
            "basis": COVERAGE_BASIS,
            "summary": [row.to_dict() for row in self.summary],
            "resources": [item.to_dict() for item in self.resources],
            "windows": [item.to_dict() for item in self.windows],
            "unregistered": [item.to_dict() for item in self.unregistered],
            "later": [item.to_dict() for item in self.later],
        }


@dataclass(frozen=True, slots=True)
class _Anchor:
    at: datetime
    evidence: CoverageEvidence
    stand_in: ResourceRef | None = None


@dataclass(slots=True)
class _Collected:
    """The evidence filed against one entry, before anything is derived from it."""

    examined: list[tuple[datetime, CoverageEvidence]] = field(default_factory=list)
    verifying: list[tuple[datetime, CoverageEvidence]] = field(default_factory=list)
    untimed: list[CoverageEvidence] = field(default_factory=list)
    after_decommission: list[CoverageEvidence] = field(default_factory=list)


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


# *--- Derivation ---*


def derive_coverage(
    observations: Iterable[Observation],
    inventory: Inventory,
    policy: SelectedPolicy,
    as_of: datetime,
) -> CoverageResult:
    """Derive every coverage clock, window and status at as-of; input order never matters.

    Month clocks run in the policy profile's calendar zone, the one `--calendar-tz` sets.
    """
    cutoff = _utc(as_of)
    # Every coverage rule resolves before anything is derived, used or not, so a pinned
    # dataset that lacks one refuses the run instead of thinning the projection.
    forces = {rule_id: policy.rule(rule_id).force for rule_id in COVERAGE_RULE_IDS}
    collected = {entry.ref: _Collected() for entry in inventory.entries}
    unregistered: Counter[ResourceRef] = Counter()
    later: list[CoverageEvidence] = []

    for observation in observations:
        # A system observation records a process failure; it never examines a resource.
        if observation.origin is not ObservationOrigin.ARTIFACT:
            continue
        resource = observation.resource
        at = None if observation.observed_at is None else _utc(observation.observed_at)
        item = CoverageEvidence(
            kind=EvidenceKind.OBSERVATION,
            resource=resource,
            at=at,
            reference=observation.observation_id,
            disposition=observation.disposition,
        )
        entry = inventory.entry_for(resource.resource_type, resource.resource_id)
        if at is not None and at > cutoff:
            later.append(item)
        elif entry is None:
            unregistered[resource] += 1
        elif at is None:
            collected[entry.ref].untimed.append(item)
        else:
            verifies = entry.machine_based and observation.disposition in VERIFYING_DISPOSITIONS
            _file(collected[entry.ref], entry, at, item, verifies=verifies)

    for entry in inventory.entries:
        for verification in entry.verifications:
            at = _utc(verification.at)
            item = CoverageEvidence(EvidenceKind.ATTESTATION, entry.ref, at, verification.reference)
            if at > cutoff:
                later.append(item)
            else:
                _file(collected[entry.ref], entry, at, item, verifies=True)

    anchors = {ref: _anchors(found.verifying) for ref, found in collected.items()}
    groups: defaultdict[str, list[InformationResource]] = defaultdict(list)
    for entry in inventory.entries:
        if entry.sample_group is not None:
            groups[entry.sample_group].append(entry)

    runs: dict[ClockKey, tuple[CoverageClock, list[CoverageWindow]]] = {}
    for name, members in groups.items():
        key = ClockKey(PSD_RULE, sample_group=name)
        runs[key] = _run(
            key,
            forces[PSD_RULE],
            policy,
            cutoff,
            expected_since=min(member.expected_since for member in members),
            decommissioned_at=_group_decommissioned_at(members),
            anchors=_group_anchors(members, anchors),
            examined=any(collected[member.ref].examined for member in members),
        )

    resources = []
    for entry in inventory.entries:
        found = collected[entry.ref]
        table = entry_clocks(entry)
        for key in table.clocks:
            if key not in runs:
                runs[key] = _run(
                    key,
                    forces[key.rule_id],
                    policy,
                    cutoff,
                    expected_since=entry.expected_since,
                    decommissioned_at=entry.decommissioned_at,
                    anchors=anchors[entry.ref],
                    examined=bool(found.examined),
                )
        resources.append(
            ResourceCoverage(
                entry=entry,
                clocks=tuple(runs[key][0] for key in table.clocks),
                last_examined=max((at for at, _ in found.examined), default=None),
                last_verified=max((at for at, _ in found.verifying), default=None),
                examined_observations=sum(
                    1 for _, item in found.examined if item.kind is EvidenceKind.OBSERVATION
                ),
                untimed=_ordered(found.untimed),
                after_decommission=_ordered(found.after_decommission),
                warnings=table.warnings,
            )
        )

    clocks = [clock for clock, _ in runs.values()]
    windows = [window for _, closed in runs.values() for window in closed]
    return CoverageResult(
        inventory=inventory,
        as_of=cutoff,
        profile=policy.profile,
        provenance=policy.provenance,
        summary=tuple(_summary(rule_id, forces[rule_id], clocks) for rule_id in COVERAGE_RULE_IDS),
        resources=tuple(resources),
        windows=tuple(sorted(windows, key=lambda item: (item.key.sort_key, item.closed_at))),
        unregistered=tuple(
            UnregisteredResource(resource=ref, observations=count)
            for ref, count in sorted(
                unregistered.items(),
                key=lambda pair: (pair[0].resource_type, pair[0].resource_id),
            )
        ),
        later=_ordered(later),
    )


def _file(
    found: _Collected,
    entry: InformationResource,
    at: datetime,
    item: CoverageEvidence,
    *,
    verifies: bool,
) -> None:
    """File one timed piece of evidence within the cutoff against its entry."""
    # A decommissioned resource's clocks stopped, so later evidence is listed, never used.
    if entry.decommissioned_at is not None and at > entry.decommissioned_at:
        found.after_decommission.append(item)
        return
    found.examined.append((at, item))
    if verifies:
        found.verifying.append((at, item))


def _anchors(verifying: Iterable[tuple[datetime, CoverageEvidence]]) -> list[_Anchor]:
    """Return one anchor per verified instant, in time order, naming the least evidence."""
    chosen: dict[datetime, CoverageEvidence] = {}
    for at, item in verifying:
        held = chosen.get(at)
        if held is None or item.sort_key < held.sort_key:
            chosen[at] = item
    return [_Anchor(at=at, evidence=chosen[at]) for at in sorted(chosen)]


def _group_anchors(
    members: list[InformationResource], anchors: dict[ResourceRef, list[_Anchor]]
) -> list[_Anchor]:
    """Return a group's anchors: any verified member stands in, the least pair on a tie."""
    chosen: dict[datetime, _Anchor] = {}
    # Inventory entries are sorted, so the first member to claim an instant is the least.
    for member in members:
        for anchor in anchors[member.ref]:
            chosen.setdefault(anchor.at, replace(anchor, stand_in=member.ref))
    return [chosen[at] for at in sorted(chosen)]


def _group_decommissioned_at(members: list[InformationResource]) -> datetime | None:
    """Return when a group's clock stops: only once every member is decommissioned."""
    instants = [member.decommissioned_at for member in members]
    if any(instant is None for instant in instants):
        return None
    return max(instant for instant in instants if instant is not None)


def _run(
    key: ClockKey,
    force: RuleForce,
    policy: SelectedPolicy,
    as_of: datetime,
    *,
    expected_since: datetime,
    decommissioned_at: datetime | None,
    anchors: list[_Anchor],
    examined: bool,
) -> tuple[CoverageClock, list[CoverageWindow]]:
    """Walk one clock's verifications to as-of: its state then, and every window that closed."""
    if expected_since > as_of:
        return CoverageClock(key=key, force=force, status=CoverageStatus.UNANCHORED), []

    def deadline_from(start: datetime) -> PolicyDeadline:
        return policy.coverage_deadline(key.rule_id, start)

    # Only the last verification at or before expectedSince can reach past it. A window that
    # closes before expectedSince closes nothing, and the clock then runs from the declaration.
    earlier = [anchor for anchor in anchors if anchor.at <= expected_since]
    current: _Anchor | None = None
    if earlier and deadline_from(earlier[-1].at).due_at >= expected_since:
        current = earlier[-1]
    deadline = deadline_from(expected_since if current is None else current.at)
    windows = []
    # The next window anchors on the next verification, never on the missed due date, so a
    # long lapse is one window (ADR 0007 Decision 6).
    for following in anchors[len(earlier) :]:
        if following.at > deadline.due_at:
            windows.append(_window(key, current, deadline, resumed_at=following.at))
        current, deadline = following, deadline_from(following.at)
    lapsed = as_of > deadline.due_at and (
        decommissioned_at is None or deadline.due_at <= decommissioned_at
    )
    if lapsed:
        windows.append(_window(key, current, deadline, resumed_at=None))

    # `current` is now the verification that anchors the clock at as-of, or None when the clock
    # runs from the declaration. Never examined is missing, and examined with nothing anchoring
    # the clock is undetermined, past due or not, so stale and current both need a verification.
    if not examined:
        status = CoverageStatus.MISSING
    elif current is None:
        status = CoverageStatus.UNDETERMINED
    elif lapsed:
        status = CoverageStatus.STALE
    else:
        status = CoverageStatus.CURRENT
    clock = CoverageClock(
        key=key,
        force=force,
        status=status,
        anchor=_anchor_kind(current),
        deadline=deadline,
        evidence=None if current is None else current.evidence,
        stand_in=None if current is None else current.stand_in,
    )
    return clock, windows


def _window(
    key: ClockKey, anchor: _Anchor | None, deadline: PolicyDeadline, *, resumed_at: datetime | None
) -> CoverageWindow:
    return CoverageWindow(
        key=key,
        anchor=_anchor_kind(anchor),
        deadline=deadline,
        resumed_at=resumed_at,
        evidence=None if anchor is None else anchor.evidence,
        stand_in=None if anchor is None else anchor.stand_in,
    )


def _summary(rule_id: str, force: RuleForce, clocks: list[CoverageClock]) -> RuleSummary:
    statuses = Counter(clock.status for clock in clocks if clock.rule_id == rule_id)
    return RuleSummary(
        rule_id=rule_id,
        force=force,
        expected=sum(statuses.values()),
        current=statuses[CoverageStatus.CURRENT],
        stale=statuses[CoverageStatus.STALE],
        missing=statuses[CoverageStatus.MISSING],
        unanchored=statuses[CoverageStatus.UNANCHORED],
        undetermined=statuses[CoverageStatus.UNDETERMINED],
    )


# *--- Helper Functions ---*


def _anchor_kind(anchor: _Anchor | None) -> AnchorKind:
    return AnchorKind.DECLARED if anchor is None else AnchorKind.VERIFICATION


def _ordered(items: Iterable[CoverageEvidence]) -> tuple[CoverageEvidence, ...]:
    return tuple(sorted(items, key=lambda item: item.sort_key))


def _check_anchor(
    key: ClockKey,
    force: RuleForce,
    anchor: AnchorKind | None,
    deadline: PolicyDeadline | None,
    evidence: CoverageEvidence | None,
    stand_in: ResourceRef | None,
) -> None:
    if (anchor is None) != (deadline is None):
        raise ValueError("an anchored clock carries its deadline, and only an anchored one")
    if deadline is not None and (deadline.rule_id != key.rule_id or deadline.force is not force):
        raise ValueError("the deadline must be the clock's own rule and force")
    if (evidence is not None) != (anchor is AnchorKind.VERIFICATION):
        raise ValueError("a verification anchor names its evidence, and only it")
    group_verification = key.sample_group is not None and anchor is AnchorKind.VERIFICATION
    if (stand_in is not None) != group_verification:
        raise ValueError("a sample group's verification names its stand-in, and only it")


def _instant_text(value: datetime | None) -> str | None:
    return None if value is None else value.astimezone(UTC).isoformat().replace("+00:00", "Z")


def _ref_dict(ref: ResourceRef) -> dict[str, str]:
    return {"resourceType": ref.resource_type, "resourceId": ref.resource_id}


def _utc(value: datetime) -> datetime:
    if not isinstance(value, datetime):
        raise TypeError("an instant must be a datetime")
    if value.tzinfo is None or value.utcoffset() is None:
        raise ValueError("an instant must include a timezone")
    return value.astimezone(UTC)


__all__ = [
    "COVERAGE_BASIS",
    "DRIFT_LIKELIHOOD_UNKNOWN",
    "MVX_RULE",
    "NMV_RULE",
    "PCD_RULE",
    "PDD_RULE",
    "PSD_RULE",
    "SAMPLE_GROUP_PREFIX",
    "SAMPLE_GROUP_TYPE",
    "VERIFYING_DISPOSITIONS",
    "AnchorKind",
    "ClockKey",
    "CoverageClock",
    "CoverageEvidence",
    "CoverageResult",
    "CoverageStatus",
    "CoverageWindow",
    "EntryClocks",
    "EvidenceKind",
    "ResourceCoverage",
    "RuleSummary",
    "UnregisteredResource",
    "derive_coverage",
    "entry_clocks",
]
