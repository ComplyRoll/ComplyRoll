# ******************************************************************************
# *Title: Coverage Evidence Tests*
# *Author: Kyle Versluis*
# *Description: Unit tests for coverage clocks, windows and status derivation.*
# ******************************************************************************
"""Tests for the coverage projection: the clock table, windows, and status."""

# *--- Imports ---*

from __future__ import annotations

import dataclasses
import itertools
import json
import random
import unittest
from collections.abc import Sequence
from datetime import UTC, datetime, timedelta
from functools import cache
from typing import Any
from zoneinfo import ZoneInfo

from complyroll.models import (
    Observation,
    ObservationDisposition,
    ObservationOrigin,
    ResourceRef,
    SourceSeverity,
)
from complyroll.policy import (
    COVERAGE_RULE_IDS,
    CertificationClass,
    CertificationProfile,
    PolicyRuleNotFoundError,
    SelectedPolicy,
    TimeframeUnit,
    load_bundled_policy,
)
from complyroll.reports import (
    InformationResource,
    Inventory,
    ReportInputError,
    parse_inventory,
)
from complyroll.reports.coverage import (
    DRIFT_LIKELIHOOD_UNKNOWN,
    MVX_RULE,
    NMV_RULE,
    PCD_RULE,
    PDD_RULE,
    PSD_RULE,
    VERIFYING_DISPOSITIONS,
    AnchorKind,
    ClockKey,
    CoverageClock,
    CoverageEvidence,
    CoverageResult,
    CoverageStatus,
    CoverageWindow,
    EntryClocks,
    EvidenceKind,
    ResourceCoverage,
    RuleSummary,
    UnregisteredResource,
    derive_coverage,
    entry_clocks,
)
from complyroll.reports.inventory import DRIFT_UNKNOWN

# *--- Fixtures ---*

SINCE_TEXT = "2026-07-01T00:00:00Z"
#: Every value an entry's driftLikely can be written with, MISSING meaning the key is absent.
MISSING = object()
DRIFT_VALUES: tuple[object, ...] = (True, False, DRIFT_UNKNOWN, MISSING)
GROUP_VALUES: tuple[str | None, ...] = (None, "web-tier")


def inventory_document(*entries: dict[str, Any]) -> bytes:
    return json.dumps(
        {
            "schema": "complyroll.inventory",
            "schemaVersion": 1,
            "name": "coverage-tests",
            "resources": list(entries),
        }
    ).encode("utf-8")


def raw_entry(
    resource_id: str = "lab-01",
    *,
    machine_based: bool = True,
    drift: object = False,
    group: str | None = None,
    **fields: object,
) -> dict[str, Any]:
    """Return one inventory entry as written in a file; drift MISSING leaves the key out."""
    entry: dict[str, Any] = {
        "resourceType": "host" if machine_based else "logical",
        "resourceId": resource_id,
        "machineBased": machine_based,
        "expectedSince": SINCE_TEXT,
    }
    if drift is not MISSING:
        entry["driftLikely"] = drift
    if group is not None:
        entry["sampleGroup"] = group
    entry.update(fields)
    return entry


def read_entry(**arguments: Any) -> InformationResource:
    """Read one entry through the inventory reader, so the table sees only valid entries."""
    (entry,) = parse_inventory(inventory_document(raw_entry(**arguments))).entries
    return entry


SINCE = datetime(2026, 7, 1, tzinfo=UTC)
#: Ingest time sits after every instant these tests use, so a substituted one would show.
INGESTED_AT = datetime(2027, 6, 1, tzinfo=UTC)
DIGEST = "c0" * 32
MICROSECOND = timedelta(microseconds=1)
DAY = timedelta(days=1)
PASS = ObservationDisposition.PASS
ERROR = ObservationDisposition.ERROR
GROUP_KEY = "logical:sample-group/web-tier"
ALIAS = {"resourceType": "host", "resourceId": "lab-01.lab.internal"}


@cache
def policy(class_name: str = "B", zone: str = "UTC") -> SelectedPolicy:
    profile = CertificationProfile(CertificationClass(class_name), calendar_timezone=zone)
    return load_bundled_policy(profile)


def due(rule_id: str, at: datetime, selected: SelectedPolicy | None = None) -> datetime:
    """Return a due date from the pinned dataset, the only source of every number here."""
    return (selected or policy()).coverage_deadline(rule_id, at).due_at


def period(rule_id: str, selected: SelectedPolicy | None = None) -> timedelta:
    """Return a day-unit rule's timeframe as read from the dataset."""
    timeframe = (selected or policy()).rule(rule_id).timeframe
    assert timeframe is not None and timeframe.unit is TimeframeUnit.DAYS
    return timedelta(days=int(timeframe.amount))


def text(at: datetime) -> str:
    return at.isoformat()


def host(resource_id: str = "lab-01", **fields: Any) -> dict[str, Any]:
    """A machine entry not likely to drift, so it carries MVX and PCD."""
    return raw_entry(resource_id, **fields)


def procedure(resource_id: str = "ir-plan", **fields: Any) -> dict[str, Any]:
    """A non-machine entry, so it carries NMV."""
    return raw_entry(resource_id, machine_based=False, drift=MISSING, **fields)


def attestation(at: datetime, reference: str = "tabletop record") -> dict[str, str]:
    return {"at": text(at), "reference": reference}


def inventory_of(*entries: dict[str, Any]) -> Inventory:
    return parse_inventory(inventory_document(*entries))


def observation(
    resource_id: str = "lab-01",
    at: datetime | None = SINCE,
    disposition: ObservationDisposition = PASS,
    *,
    resource_type: str = "host",
    record: str = "R-1",
) -> Observation:
    """Build one artifact observation of a resource; the id spells every field that varies."""
    stamp = "untimed" if at is None else at.isoformat()
    return Observation(
        observation_id=f"obs/{resource_type}/{resource_id}/{stamp}/{record}/{disposition.value}",
        source_type="sarif",
        source_tool="synthetic-scanner",
        parser_name="complyroll.test",
        parser_version="1",
        source_record_id=record,
        resource=ResourceRef(resource_id=resource_id, resource_type=resource_type),
        observed_at=at,
        ingested_at=INGESTED_AT,
        disposition=disposition,
        source_severity=SourceSeverity.UNKNOWN,
        source_artifact_digest=DIGEST,
        source_artifact_name="synthetic.sarif",
        context_key="synthetic",
    )


def system_observation(resource_id: str = "lab-01", at: datetime = SINCE) -> Observation:
    """Build a system observation of a reserved type that is not a detection failure."""
    return Observation(
        observation_id=f"sys/{resource_id}/{at.isoformat()}",
        source_type="complyroll.synthetic-other",
        source_tool="complyroll",
        parser_name="complyroll.synthetic-other",
        parser_version="1",
        source_record_id="synthetic-other",
        resource=ResourceRef(resource_id=resource_id, resource_type="host"),
        observed_at=at,
        ingested_at=INGESTED_AT,
        disposition=ObservationDisposition.OPEN,
        context_key="synthetic-other",
        origin=ObservationOrigin.SYSTEM,
    )


def derive(
    observations: Sequence[Observation],
    inventory: Inventory,
    as_of: datetime,
    selected: SelectedPolicy | None = None,
) -> CoverageResult:
    return derive_coverage(observations, inventory, selected or policy(), as_of)


def resource_of(
    result: CoverageResult, resource_id: str = "lab-01", resource_type: str = "host"
) -> ResourceCoverage:
    ref = ResourceRef(resource_id=resource_id, resource_type=resource_type)
    (found,) = [item for item in result.resources if item.entry.ref == ref]
    return found


def clock_of(
    result: CoverageResult,
    rule_id: str = MVX_RULE,
    resource_id: str = "lab-01",
    resource_type: str = "host",
) -> CoverageClock:
    clocks = resource_of(result, resource_id, resource_type).clocks
    (found,) = [clock for clock in clocks if clock.key.rule_id == rule_id]
    return found


def windows_of(
    result: CoverageResult, rule_id: str = MVX_RULE, context_key: str = "host:lab-01"
) -> list[tuple[datetime, datetime, datetime | None]]:
    """Return one clock's closed windows as (anchorAt, closedAt, resumedAt)."""
    return [
        (window.anchor_at, window.closed_at, window.resumed_at)
        for window in result.windows
        if window.rule_id == rule_id and window.context_key == context_key
    ]


def references(items: Sequence[CoverageEvidence]) -> list[str]:
    return [item.reference for item in items]


# *--- Clock Table ---*


class ClockTableTests(unittest.TestCase):
    """An entry's attributes select its clocks; the reader refuses every other combination."""

    def test_the_rule_names_are_the_policy_coverage_rules(self) -> None:
        self.assertEqual(
            (MVX_RULE, NMV_RULE, PCD_RULE, PDD_RULE, PSD_RULE),
            COVERAGE_RULE_IDS,
        )

    def test_every_attribute_combination(self) -> None:
        host = ResourceRef(resource_id="lab-01", resource_type="host")
        procedure = ResourceRef(resource_id="lab-01", resource_type="logical")
        group = ClockKey(PSD_RULE, sample_group="web-tier")
        expected: dict[tuple[bool, object], tuple[ClockKey, ...] | str] = {
            (True, True): (ClockKey(MVX_RULE, resource=host), ClockKey(PDD_RULE, resource=host)),
            (True, False): (ClockKey(MVX_RULE, resource=host), ClockKey(PCD_RULE, resource=host)),
            (True, DRIFT_UNKNOWN): (
                ClockKey(MVX_RULE, resource=host),
                ClockKey(PDD_RULE, resource=host),
            ),
            (True, MISSING): "driftLikely is required when machineBased is true",
            (False, MISSING): (ClockKey(NMV_RULE, resource=procedure),),
            (False, True): "driftLikely is for entries whose machineBased is true",
            (False, False): "driftLikely is for entries whose machineBased is true",
            (False, DRIFT_UNKNOWN): "driftLikely is for entries whose machineBased is true",
        }
        combinations = itertools.product((True, False), DRIFT_VALUES, GROUP_VALUES)
        seen = 0
        for machine_based, drift, sample_group in combinations:
            outcome = expected[(machine_based, drift)]
            label = f"machineBased={machine_based} driftLikely={drift!r} group={sample_group}"
            with self.subTest(label):
                arguments = {"machine_based": machine_based, "drift": drift, "group": sample_group}
                if isinstance(outcome, str):
                    with self.assertRaisesRegex(ReportInputError, outcome):
                        read_entry(**arguments)
                    seen += 1
                    continue
                clocks = outcome + ((group,) if sample_group is not None else ())
                warnings = (DRIFT_LIKELIHOOD_UNKNOWN,) if drift == DRIFT_UNKNOWN else ()
                self.assertEqual(
                    entry_clocks(read_entry(**arguments)),
                    EntryClocks(clocks=clocks, warnings=warnings),
                )
                seen += 1
        self.assertEqual(seen, 16)

    def test_a_directly_built_entry_cannot_reach_a_refused_combination(self) -> None:
        machine = read_entry(drift=True)
        manual = read_entry(machine_based=False, drift=MISSING)
        for label, entry, change in (
            ("machine without drift", machine, {"drift_likely": None}),
            ("drift on a non-machine", manual, {"drift_likely": True}),
            ("unknown drift on a non-machine", manual, {"drift_likely": DRIFT_UNKNOWN}),
        ):
            with self.subTest(label), self.assertRaises(ValueError):
                dataclasses.replace(entry, **change)  # type: ignore[arg-type]

    def test_only_unknown_drift_warns(self) -> None:
        for drift in (True, False, DRIFT_UNKNOWN):
            with self.subTest(drift=drift):
                warnings = entry_clocks(read_entry(drift=drift)).warnings
                self.assertEqual(warnings, (DRIFT_LIKELIHOOD_UNKNOWN,) * (drift == DRIFT_UNKNOWN))
        self.assertEqual(DRIFT_LIKELIHOOD_UNKNOWN, "drift_likelihood_unknown")

    def test_the_clocks_name_the_entry_by_its_own_pair_never_an_alias(self) -> None:
        aliased = read_entry(
            drift=True,
            aliases=[{"resourceType": "host", "resourceId": "lab-01.lab.internal"}],
        )
        for clock in entry_clocks(aliased).clocks:
            with self.subTest(rule_id=clock.rule_id):
                self.assertEqual(clock.resource, aliased.ref)

    def test_context_keys(self) -> None:
        host = ResourceRef(resource_id="lab-01", resource_type="host")
        self.assertEqual(ClockKey(MVX_RULE, resource=host).context_key, "host:lab-01")
        group = ClockKey(PSD_RULE, sample_group="web-tier")
        self.assertEqual(group.context_key, "logical:sample-group/web-tier")
        self.assertEqual(
            group.subject, ResourceRef(resource_id="sample-group/web-tier", resource_type="logical")
        )
        self.assertEqual(ClockKey(MVX_RULE, resource=host).subject, host)

    def test_members_of_one_group_share_one_group_clock(self) -> None:
        inventory = parse_inventory(
            inventory_document(
                raw_entry("a", group="web-tier"),
                raw_entry("b", drift=True, group="web-tier"),
                raw_entry("ir-plan", machine_based=False, drift=MISSING, group="web-tier"),
            )
        )
        group_clocks = {
            clock
            for entry in inventory.entries
            for clock in entry_clocks(entry).clocks
            if clock.rule_id == PSD_RULE
        }
        self.assertEqual(group_clocks, {ClockKey(PSD_RULE, sample_group="web-tier")})

    def test_a_clock_key_holds_its_shape(self) -> None:
        host = ResourceRef(resource_id="lab-01", resource_type="host")
        for label, arguments in (
            ("neither", {"rule_id": MVX_RULE}),
            ("both", {"rule_id": PSD_RULE, "resource": host, "sample_group": "g"}),
            ("group on a resource rule", {"rule_id": MVX_RULE, "sample_group": "g"}),
            ("resource on the group rule", {"rule_id": PSD_RULE, "resource": host}),
            ("another rule", {"rule_id": "VER-TFR-EVU", "resource": host}),
            ("the Rev5 rule", {"rule_id": "VDR-TFR-MVF", "resource": host}),
        ):
            with self.subTest(label), self.assertRaises(ValueError):
                ClockKey(**arguments)  # type: ignore[arg-type]


# *--- Windows ---*


class WindowTests(unittest.TestCase):
    """Due is strict, the next window anchors on a verification, and a lapse is one window."""

    def test_due_exactly_at_as_of_is_current_and_one_instant_later_is_stale(self) -> None:
        inventory = inventory_of(host())
        verified = SINCE + DAY
        evidence = [observation(at=verified)]
        deadline = due(MVX_RULE, verified)

        at_due = derive(evidence, inventory, deadline)
        clock = clock_of(at_due)
        self.assertIs(clock.status, CoverageStatus.CURRENT)
        self.assertIs(clock.anchor, AnchorKind.VERIFICATION)
        self.assertEqual((clock.anchor_at, clock.due_at), (verified, deadline))
        self.assertEqual(windows_of(at_due), [])

        late = derive(evidence, inventory, deadline + MICROSECOND)
        self.assertIs(clock_of(late).status, CoverageStatus.STALE)
        self.assertEqual(windows_of(late), [(verified, deadline, None)])

    def test_a_verification_on_the_due_instant_keeps_the_chain(self) -> None:
        first = SINCE + DAY
        second = due(MVX_RULE, first)
        result = derive(
            [observation(at=first), observation(at=second)], inventory_of(host()), second
        )
        self.assertEqual(windows_of(result), [])
        self.assertEqual(clock_of(result).anchor_at, second)

    def test_the_anchor_chain_follows_every_verification(self) -> None:
        step = period(MVX_RULE) / 2
        instants = [SINCE + step * count for count in range(1, 6)]
        evidence = [observation(at=at) for at in instants]
        result = derive(evidence, inventory_of(host()), instants[-1] + step)
        clock = clock_of(result)
        self.assertEqual(windows_of(result), [])
        self.assertEqual(clock.anchor_at, instants[-1])
        self.assertEqual(clock.due_at, due(MVX_RULE, instants[-1]))
        self.assertEqual(
            clock.evidence,
            CoverageEvidence(
                kind=EvidenceKind.OBSERVATION,
                resource=ResourceRef(resource_id="lab-01", resource_type="host"),
                at=instants[-1],
                reference=evidence[-1].observation_id,
                disposition=PASS,
            ),
        )
        self.assertEqual(resource_of(result).last_verified, instants[-1])

    def test_a_long_gap_is_one_window_never_one_per_period(self) -> None:
        for class_name in ("B", "C"):
            selected = policy(class_name)
            with self.subTest(certification_class=class_name):
                # Thirteen periods: about three months under Class B's MVX timeframe.
                gap = period(MVX_RULE, selected) * 13
                first = SINCE + DAY
                second = first + gap
                evidence = [observation(at=first), observation(at=second)]
                inventory = inventory_of(host())
                first_due = due(MVX_RULE, first, selected)

                resumed = derive(evidence, inventory, second, selected)
                self.assertEqual(windows_of(resumed), [(first, first_due, second)])
                self.assertIs(clock_of(resumed).status, CoverageStatus.CURRENT)

                again = derive(evidence, inventory, second + gap, selected)
                self.assertEqual(
                    windows_of(again),
                    [(first, first_due, second), (second, due(MVX_RULE, second, selected), None)],
                )
                self.assertIs(clock_of(again).status, CoverageStatus.STALE)

    def test_the_next_window_anchors_on_the_verification_never_on_the_due_date(self) -> None:
        first = SINCE + DAY
        lapse = due(MVX_RULE, first)
        second = lapse + DAY
        evidence = [observation(at=first), observation(at=second)]
        result = derive(evidence, inventory_of(host()), due(MVX_RULE, second))
        (window,) = [item for item in result.windows if item.rule_id == MVX_RULE]
        self.assertEqual(
            (window.anchor_at, window.closed_at, window.resumed_at), (first, lapse, second)
        )
        self.assertIs(window.anchor, AnchorKind.VERIFICATION)
        self.assertEqual(
            window.evidence.reference if window.evidence else None, evidence[0].observation_id
        )
        self.assertEqual(window.context_key, "host:lab-01")
        clock = clock_of(result)
        self.assertEqual((clock.anchor_at, clock.due_at), (second, due(MVX_RULE, second)))
        self.assertNotEqual(clock.due_at, due(MVX_RULE, lapse))
        self.assertIs(clock.status, CoverageStatus.CURRENT)

    def test_a_first_verification_after_the_declared_window_resumes_it(self) -> None:
        first = due(MVX_RULE, SINCE) + DAY
        result = derive([observation(at=first)], inventory_of(host()), first)
        self.assertEqual(windows_of(result), [(SINCE, due(MVX_RULE, SINCE), first)])
        (window,) = [item for item in result.windows if item.rule_id == MVX_RULE]
        self.assertIs(window.anchor, AnchorKind.DECLARED)
        self.assertIsNone(window.evidence)
        self.assertIs(clock_of(result).status, CoverageStatus.CURRENT)


# *--- Cutoff ---*


class CutoffTests(unittest.TestCase):
    """Only evidence observed at or before as-of counts; later evidence is listed, never used."""

    def test_evidence_after_as_of_is_listed_and_never_used(self) -> None:
        as_of = SINCE + 3 * DAY
        inside = observation(at=SINCE + DAY)
        after = observation(at=as_of + MICROSECOND)
        result = derive([after, inside], inventory_of(host()), as_of)
        resource = resource_of(result)
        self.assertEqual(clock_of(result).anchor_at, inside.observed_at)
        self.assertEqual(
            (resource.last_examined, resource.last_verified), (inside.observed_at,) * 2
        )
        self.assertEqual(resource.examined_observations, 1)
        self.assertEqual(references(result.later), [after.observation_id])

    def test_evidence_at_as_of_counts(self) -> None:
        as_of = SINCE + 3 * DAY
        result = derive([observation(at=as_of)], inventory_of(host()), as_of)
        self.assertEqual(clock_of(result).anchor_at, as_of)
        self.assertEqual(result.later, ())

    def test_a_resource_seen_only_after_as_of_is_missing(self) -> None:
        as_of = SINCE + 3 * DAY
        evidence = [observation(at=as_of + DAY), observation("stray", at=as_of + DAY)]
        result = derive(evidence, inventory_of(host()), as_of)
        self.assertIs(clock_of(result).status, CoverageStatus.MISSING)
        self.assertEqual(result.unregistered, ())
        self.assertEqual(references(result.later), sorted(item.observation_id for item in evidence))

    def test_an_attestation_after_as_of_is_listed_and_never_used(self) -> None:
        as_of = SINCE + 3 * DAY
        late = as_of + DAY
        result = derive([], inventory_of(procedure(verifications=[attestation(late)])), as_of)
        self.assertIs(
            clock_of(result, NMV_RULE, "ir-plan", "logical").status, CoverageStatus.MISSING
        )
        self.assertEqual(
            result.later,
            (
                CoverageEvidence(
                    kind=EvidenceKind.ATTESTATION,
                    resource=ResourceRef(resource_id="ir-plan", resource_type="logical"),
                    at=late,
                    reference="tabletop record",
                ),
            ),
        )


# *--- Examined Versus Verified ---*


class ExaminedVersusVerifiedTests(unittest.TestCase):
    """OPEN, PASS and NOT_APPLICABLE verify; every other disposition only examines."""

    def test_every_disposition(self) -> None:
        verifying = {
            ObservationDisposition.OPEN,
            ObservationDisposition.PASS,
            ObservationDisposition.NOT_APPLICABLE,
        }
        self.assertEqual(VERIFYING_DISPOSITIONS, frozenset(verifying))
        at = SINCE + DAY
        for disposition in ObservationDisposition:
            with self.subTest(disposition=disposition.value):
                result = derive(
                    [observation(at=at, disposition=disposition)], inventory_of(host()), at
                )
                clock = clock_of(result)
                resource = resource_of(result)
                self.assertEqual((resource.last_examined, resource.examined_observations), (at, 1))
                if disposition in verifying:
                    self.assertIs(clock.status, CoverageStatus.CURRENT)
                    self.assertIs(clock.anchor, AnchorKind.VERIFICATION)
                    self.assertEqual((clock.anchor_at, resource.last_verified), (at, at))
                    self.assertIs(
                        clock.evidence.disposition if clock.evidence else None, disposition
                    )
                else:
                    self.assertIs(clock.status, CoverageStatus.UNDETERMINED)
                    self.assertIs(clock.anchor, AnchorKind.DECLARED)
                    self.assertEqual(clock.anchor_at, SINCE)
                    self.assertIsNone(resource.last_verified)
                    self.assertIsNone(clock.evidence)

    def test_an_undetermined_resource_still_lapses_from_expected_since(self) -> None:
        as_of = due(MVX_RULE, SINCE) + MICROSECOND
        result = derive(
            [observation(at=SINCE + DAY, disposition=ERROR)], inventory_of(host()), as_of
        )
        self.assertIs(clock_of(result).status, CoverageStatus.UNDETERMINED)
        self.assertEqual(windows_of(result), [(SINCE, due(MVX_RULE, SINCE), None)])

    def test_one_instant_with_an_error_and_a_pass_is_one_verification(self) -> None:
        at = SINCE + DAY
        errored = observation(at=at, disposition=ERROR, record="R-1")
        passed = observation(at=at, record="R-2")
        result = derive([errored, passed], inventory_of(host()), at)
        clock = clock_of(result)
        self.assertEqual(
            clock.evidence.reference if clock.evidence else None, passed.observation_id
        )
        self.assertEqual(resource_of(result).examined_observations, 2)

    def test_many_verifying_observations_at_one_instant_are_one_anchor(self) -> None:
        at = SINCE + DAY
        scan = [observation(at=at, record=f"R-{count}") for count in (3, 1, 2)]
        result = derive(scan, inventory_of(host()), due(MVX_RULE, at) + MICROSECOND)
        self.assertEqual(windows_of(result), [(at, due(MVX_RULE, at), None)])
        clock = clock_of(result)
        self.assertEqual(
            clock.evidence.reference if clock.evidence else None,
            min(item.observation_id for item in scan),
        )

    def test_untimed_evidence_is_listed_and_never_anchors(self) -> None:
        untimed = observation(at=None)
        result = derive([untimed], inventory_of(host()), SINCE + DAY)
        resource = resource_of(result)
        self.assertEqual(references(resource.untimed), [untimed.observation_id])
        self.assertEqual(resource.untimed[0].at, None)
        self.assertEqual((resource.last_examined, resource.last_verified), (None, None))
        self.assertEqual(resource.examined_observations, 0)
        for clock in resource.clocks:
            self.assertIs(clock.status, CoverageStatus.MISSING)
            self.assertEqual(clock.anchor_at, SINCE)
        self.assertEqual((result.later, result.unregistered), ((), ()))

    def test_ingest_time_is_never_substituted(self) -> None:
        # Untimed evidence ingested inside a window anchors nothing at its ingest time.
        result = derive([observation(at=None)], inventory_of(host()), INGESTED_AT)
        self.assertEqual(windows_of(result), [(SINCE, due(MVX_RULE, SINCE), None)])

    def test_system_observations_never_examine_or_count(self) -> None:
        evidence = [system_observation(), system_observation("stray")]
        result = derive(evidence, inventory_of(host()), SINCE + DAY)
        self.assertIs(clock_of(result).status, CoverageStatus.MISSING)
        self.assertEqual((result.unregistered, result.later), ((), ()))
        self.assertIsNone(resource_of(result).last_examined)

    def test_a_non_machine_entry_is_verified_only_by_attestation(self) -> None:
        attested = SINCE + 2 * DAY
        scanned = SINCE + 5 * DAY
        inventory = inventory_of(procedure(verifications=[attestation(attested)]))
        scan = observation("ir-plan", at=scanned, resource_type="logical")
        result = derive([scan], inventory, scanned)
        resource = resource_of(result, "ir-plan", "logical")
        clock = clock_of(result, NMV_RULE, "ir-plan", "logical")
        self.assertTrue(resource.attested)
        self.assertEqual([item.key.rule_id for item in resource.clocks], [NMV_RULE])
        self.assertEqual((clock.anchor, clock.anchor_at), (AnchorKind.VERIFICATION, attested))
        self.assertEqual(
            clock.evidence,
            CoverageEvidence(
                kind=EvidenceKind.ATTESTATION,
                resource=resource.entry.ref,
                at=attested,
                reference="tabletop record",
            ),
        )
        self.assertEqual((resource.last_verified, resource.last_examined), (attested, scanned))
        self.assertEqual(resource.examined_observations, 1)

    def test_artifact_evidence_alone_leaves_a_non_machine_entry_undetermined(self) -> None:
        scanned = SINCE + DAY
        result = derive(
            [observation("ir-plan", at=scanned, resource_type="logical")],
            inventory_of(procedure()),
            scanned,
        )
        clock = clock_of(result, NMV_RULE, "ir-plan", "logical")
        self.assertIs(clock.status, CoverageStatus.UNDETERMINED)
        self.assertIsNone(resource_of(result, "ir-plan", "logical").last_verified)

    def test_a_machine_entry_is_never_attested(self) -> None:
        self.assertFalse(resource_of(derive([], inventory_of(host()), SINCE)).attested)

    def test_two_identical_attestations_are_one_anchor(self) -> None:
        at = SINCE + 2 * DAY
        inventory = inventory_of(procedure(verifications=[attestation(at), attestation(at)]))
        self.assertEqual(len(inventory.entries[0].verifications), 2)
        result = derive([], inventory, due(NMV_RULE, at))
        clock = clock_of(result, NMV_RULE, "ir-plan", "logical")
        self.assertEqual((clock.status, clock.anchor_at), (CoverageStatus.CURRENT, at))
        self.assertEqual(result.windows, ())


# *--- Sampling ---*


class SamplingTests(unittest.TestCase):
    """The group clock is satisfied by any verified member; members keep their own clocks."""

    def test_a_verified_member_stands_in_for_its_group(self) -> None:
        inventory = inventory_of(host("a", group="web-tier"), host("b", group="web-tier"))
        at = SINCE + DAY
        scan = observation("a", at=at)
        result = derive([scan], inventory, at)
        group = clock_of(result, PSD_RULE, "a")
        self.assertEqual(clock_of(result, PSD_RULE, "b"), group)
        self.assertIs(group.status, CoverageStatus.CURRENT)
        self.assertEqual(group.key.context_key, GROUP_KEY)
        self.assertEqual(group.stand_in, ResourceRef(resource_id="a", resource_type="host"))
        self.assertEqual(group.evidence.reference if group.evidence else None, scan.observation_id)
        self.assertIs(clock_of(result, MVX_RULE, "a").status, CoverageStatus.CURRENT)
        self.assertIs(clock_of(result, MVX_RULE, "b").status, CoverageStatus.MISSING)
        self.assertIsNone(clock_of(result, MVX_RULE, "a").stand_in)
        summary = {row.rule_id: row for row in result.summary}
        self.assertEqual((summary[PSD_RULE].expected, summary[PSD_RULE].current), (1, 1))
        self.assertEqual((summary[MVX_RULE].expected, summary[MVX_RULE].missing), (2, 1))

    def test_members_verified_at_one_instant_name_the_least_pair(self) -> None:
        at = SINCE + DAY
        # Declared b first: the inventory sorts by type, then id, so `a` stands in.
        inventory = inventory_of(host("b", group="web-tier"), host("a", group="web-tier"))
        result = derive([observation("b", at=at), observation("a", at=at)], inventory, at)
        self.assertEqual(clock_of(result, PSD_RULE, "b").stand_in, ResourceRef("a", "host"))

        # `Z` sorts before `host` by code point, so `Z:b` beats `host:a` despite its later id.
        mixed = inventory_of(
            host("a", group="web-tier"), host("b", group="web-tier", resourceType="Z")
        )
        scans = [observation("a", at=at), observation("b", at=at, resource_type="Z")]
        result = derive(scans, mixed, at)
        self.assertEqual(clock_of(result, PSD_RULE, "a").stand_in, ResourceRef("b", "Z"))

    def test_the_latest_member_verification_anchors_the_group(self) -> None:
        inventory = inventory_of(host("a", group="web-tier"), host("b", group="web-tier"))
        earlier, later = SINCE + DAY, SINCE + 2 * DAY
        result = derive(
            [observation("b", at=later), observation("a", at=earlier)], inventory, later
        )
        group = clock_of(result, PSD_RULE, "a")
        self.assertEqual((group.anchor_at, group.stand_in), (later, ResourceRef("b", "host")))

    def test_an_attested_member_stands_in_with_its_attestation(self) -> None:
        at = SINCE + DAY
        inventory = inventory_of(
            host("a", group="web-tier"),
            procedure(group="web-tier", verifications=[attestation(at)]),
        )
        group = clock_of(derive([], inventory, at), PSD_RULE, "a")
        self.assertEqual(group.stand_in, ResourceRef("ir-plan", "logical"))
        self.assertIs(group.evidence.kind if group.evidence else None, EvidenceKind.ATTESTATION)

    def test_a_group_lapse_is_one_window_for_the_group(self) -> None:
        inventory = inventory_of(host("a", group="web-tier"), host("b", group="web-tier"))
        at = SINCE + DAY
        as_of = due(PSD_RULE, at) + period(PSD_RULE) * 13
        result = derive([observation("a", at=at)], inventory, as_of)
        self.assertEqual(windows_of(result, PSD_RULE, GROUP_KEY), [(at, due(PSD_RULE, at), None)])
        (window,) = [item for item in result.windows if item.rule_id == PSD_RULE]
        self.assertEqual(window.stand_in, ResourceRef("a", "host"))
        self.assertEqual(windows_of(result, MVX_RULE, "host:a"), [(at, due(MVX_RULE, at), None)])
        self.assertEqual(
            windows_of(result, MVX_RULE, "host:b"), [(SINCE, due(MVX_RULE, SINCE), None)]
        )

    def test_the_group_clock_runs_from_the_earliest_member_expectation(self) -> None:
        inventory = inventory_of(
            host("a", group="web-tier", expectedSince=text(SINCE + 10 * DAY)),
            host("b", group="web-tier"),
        )
        group = clock_of(derive([], inventory, SINCE + 20 * DAY), PSD_RULE, "a")
        self.assertEqual((group.anchor, group.anchor_at), (AnchorKind.DECLARED, SINCE))

    def test_the_group_stops_only_when_every_member_is_decommissioned(self) -> None:
        as_of = due(PSD_RULE, SINCE) + DAY
        retiring = [
            host("a", group="web-tier", decommissionedAt=text(SINCE + DAY)),
            host("b", group="web-tier", decommissionedAt=text(SINCE + 2 * DAY)),
        ]
        self.assertEqual(
            windows_of(derive([], inventory_of(*retiring), as_of), PSD_RULE, GROUP_KEY), []
        )
        staying = [retiring[0], host("b", group="web-tier")]
        self.assertEqual(
            windows_of(derive([], inventory_of(*staying), as_of), PSD_RULE, GROUP_KEY),
            [(SINCE, due(PSD_RULE, SINCE), None)],
        )


# *--- Matching ---*


class MatchingTests(unittest.TestCase):
    """Evidence matches an entry by its exact pair or an exact alias, never by normalization."""

    def test_an_alias_matches_and_the_clock_names_the_entry(self) -> None:
        at = SINCE + DAY
        scan = observation("lab-01.lab.internal", at=at)
        result = derive([scan], inventory_of(host(aliases=[ALIAS])), at)
        clock = clock_of(result)
        self.assertIs(clock.status, CoverageStatus.CURRENT)
        self.assertEqual(clock.key.resource, ResourceRef("lab-01", "host"))
        self.assertEqual(
            clock.evidence.resource if clock.evidence else None,
            ResourceRef("lab-01.lab.internal", "host"),
        )
        self.assertEqual(result.unregistered, ())

    def test_a_fallback_stem_matches_only_through_an_alias(self) -> None:
        at = SINCE + DAY
        # A checklist with no host name is named by its file stem (resource_identity_fallback).
        stem = observation("windows-host", at=at)
        without = derive([stem], inventory_of(host()), at)
        self.assertIs(clock_of(without).status, CoverageStatus.MISSING)
        self.assertEqual(
            without.unregistered, (UnregisteredResource(ResourceRef("windows-host", "host"), 1),)
        )
        aliased = host(aliases=[{"resourceType": "host", "resourceId": "windows-host"}])
        with_alias = derive([stem], inventory_of(aliased), at)
        self.assertIs(clock_of(with_alias).status, CoverageStatus.CURRENT)
        self.assertEqual(with_alias.unregistered, ())

    def test_identities_are_never_normalized(self) -> None:
        at = SINCE + DAY
        variants = [
            observation("LAB-01", at=at),
            observation("lab-01 ", at=at),
            observation("lab-01", at=at, resource_type="Host"),
            observation("lab-01.lab.internal", at=at),
        ]
        result = derive(variants, inventory_of(host()), at)
        self.assertIs(clock_of(result).status, CoverageStatus.MISSING)
        self.assertEqual(len(result.unregistered), len(variants))


# *--- Decommissioning ---*


class DecommissionTests(unittest.TestCase):
    """A decommissioned entry's clocks stop there; later evidence is listed and never used."""

    def test_a_due_date_after_decommission_closes_nothing(self) -> None:
        verified = SINCE + DAY
        retired = verified + DAY
        inventory = inventory_of(host(decommissionedAt=text(retired)))
        result = derive([observation(at=verified)], inventory, due(MVX_RULE, verified) + 30 * DAY)
        self.assertEqual(windows_of(result), [])
        self.assertIs(clock_of(result).status, CoverageStatus.CURRENT)

    def test_a_due_date_on_or_before_decommission_closes_a_window(self) -> None:
        verified = SINCE + DAY
        lapse = due(MVX_RULE, verified)
        for retired in (lapse, lapse + DAY):
            with self.subTest(retired=retired.isoformat()):
                inventory = inventory_of(host(decommissionedAt=text(retired)))
                result = derive([observation(at=verified)], inventory, retired + 30 * DAY)
                self.assertEqual(windows_of(result), [(verified, lapse, None)])
                self.assertIs(clock_of(result).status, CoverageStatus.STALE)

    def test_evidence_after_decommission_is_listed_and_never_anchors(self) -> None:
        retired = SINCE + 2 * DAY
        kept, late = observation(at=SINCE + DAY), observation(at=retired + DAY)
        inventory = inventory_of(host(decommissionedAt=text(retired)))
        result = derive([late, kept], inventory, retired + 2 * DAY)
        resource = resource_of(result)
        self.assertEqual(clock_of(result).anchor_at, kept.observed_at)
        self.assertEqual(references(resource.after_decommission), [late.observation_id])
        self.assertEqual(resource.last_verified, kept.observed_at)
        self.assertEqual(resource.last_examined, kept.observed_at)
        self.assertEqual(result.later, ())

    def test_examination_only_after_decommission_leaves_the_entry_missing(self) -> None:
        retired = SINCE + DAY
        inventory = inventory_of(host(decommissionedAt=text(retired)))
        result = derive([observation(at=retired + DAY)], inventory, retired + 2 * DAY)
        self.assertIs(clock_of(result).status, CoverageStatus.MISSING)
        self.assertEqual(len(resource_of(result).after_decommission), 1)

    def test_an_attestation_after_decommission_is_listed(self) -> None:
        retired = SINCE + DAY
        inventory = inventory_of(
            procedure(decommissionedAt=text(retired), verifications=[attestation(retired + DAY)])
        )
        resource = resource_of(derive([], inventory, retired + 2 * DAY), "ir-plan", "logical")
        self.assertEqual(
            [item.kind for item in resource.after_decommission], [EvidenceKind.ATTESTATION]
        )
        self.assertIsNone(resource.last_verified)


# *--- Unregistered ---*


class UnregisteredTests(unittest.TestCase):
    """Observed artifact resources that match no entry are listed with their counts."""

    def test_unregistered_resources_are_counted_by_exact_identity(self) -> None:
        at = SINCE + DAY
        evidence = [
            observation("stray-b", at=at),
            observation("stray-a", at=at, record="R-1"),
            observation("stray-a", at=at, record="R-2"),
            observation("stray-a", at=None),
            observation("stray-a", at=at + DAY),
            observation("stray-a", at=at, resource_type="image"),
            system_observation("stray-c"),
        ]
        result = derive(evidence, inventory_of(host()), at)
        self.assertEqual(
            result.unregistered,
            (
                UnregisteredResource(ResourceRef("stray-a", "host"), 3),
                UnregisteredResource(ResourceRef("stray-b", "host"), 1),
                UnregisteredResource(ResourceRef("stray-a", "image"), 1),
            ),
        )
        self.assertEqual(references(result.later), [evidence[4].observation_id])


# *--- Expected Since ---*


class ExpectedSinceTests(unittest.TestCase):
    """No window closes before expectedSince, and an entry not yet expected is unanchored."""

    def test_an_entry_expected_after_as_of_is_unanchored(self) -> None:
        expected = SINCE + 30 * DAY
        verified = SINCE + DAY
        inventory = inventory_of(host(expectedSince=text(expected), group="web-tier"))
        result = derive([observation(at=verified)], inventory, SINCE + 2 * DAY)
        resource = resource_of(result)
        self.assertEqual(len(resource.clocks), 3)
        for clock in resource.clocks:
            with self.subTest(rule_id=clock.rule_id):
                self.assertIs(clock.status, CoverageStatus.UNANCHORED)
                self.assertEqual(
                    (clock.anchor, clock.anchor_at, clock.due_at, clock.evidence, clock.deadline),
                    (None,) * 5,
                )
        self.assertEqual(result.windows, ())
        self.assertEqual(resource.last_verified, verified)

    def test_expected_since_at_as_of_is_anchored(self) -> None:
        clock = clock_of(derive([], inventory_of(host()), SINCE))
        self.assertEqual((clock.status, clock.anchor_at), (CoverageStatus.MISSING, SINCE))

    def test_no_verification_is_one_window_from_expected_since(self) -> None:
        as_of = due(MVX_RULE, SINCE) + period(MVX_RULE) * 13
        result = derive([], inventory_of(host()), as_of)
        self.assertEqual(windows_of(result), [(SINCE, due(MVX_RULE, SINCE), None)])
        (window,) = [item for item in result.windows if item.rule_id == MVX_RULE]
        self.assertIs(window.anchor, AnchorKind.DECLARED)
        self.assertIs(clock_of(result).status, CoverageStatus.MISSING)

    def test_a_verification_whose_window_ends_before_expected_since_closes_nothing(self) -> None:
        verified = SINCE
        expected = due(MVX_RULE, verified) + DAY
        inventory = inventory_of(host(expectedSince=text(expected)))
        evidence = [observation(at=verified)]

        # No verification anchors the clock, so it is undetermined, never current or stale.
        within = derive(evidence, inventory, expected)
        clock = clock_of(within)
        self.assertEqual(windows_of(within), [])
        self.assertEqual(
            (clock.status, clock.anchor, clock.anchor_at, clock.evidence),
            (CoverageStatus.UNDETERMINED, AnchorKind.DECLARED, expected, None),
        )
        self.assertEqual(resource_of(within).last_verified, verified)

        lapse = due(MVX_RULE, expected)
        lapsed = derive(evidence, inventory, lapse + MICROSECOND)
        clock = clock_of(lapsed)
        self.assertEqual(windows_of(lapsed), [(expected, lapse, None)])
        self.assertEqual(
            (clock.status, clock.anchor, clock.evidence),
            (CoverageStatus.UNDETERMINED, AnchorKind.DECLARED, None),
        )
        self.assertEqual(resource_of(lapsed).last_verified, verified)

        # A later verification still resumes the declared window and anchors the clock.
        resumed_at = lapse + DAY
        resumed = derive([*evidence, observation(at=resumed_at)], inventory, resumed_at)
        clock = clock_of(resumed)
        self.assertEqual(windows_of(resumed), [(expected, lapse, resumed_at)])
        self.assertEqual(
            (clock.status, clock.anchor, clock.anchor_at),
            (CoverageStatus.CURRENT, AnchorKind.VERIFICATION, resumed_at),
        )

    def test_a_verification_before_expected_since_anchors_only_if_its_window_reaches_it(
        self,
    ) -> None:
        verified = SINCE
        evidence = [observation(at=verified)]
        reach = due(MVX_RULE, verified)
        cases = (
            ("inside the window", verified + period(MVX_RULE) / 2, True),
            ("window closes at expectedSince", reach, True),
            ("window closes before expectedSince", reach + MICROSECOND, False),
        )
        for name, expected, anchors in cases:
            with self.subTest(name):
                inventory = inventory_of(host(expectedSince=text(expected)))
                clock = clock_of(derive(evidence, inventory, expected))
                if anchors:
                    self.assertEqual(
                        (clock.status, clock.anchor, clock.anchor_at, clock.due_at),
                        (CoverageStatus.CURRENT, AnchorKind.VERIFICATION, verified, reach),
                    )
                    self.assertEqual(
                        clock.evidence.reference if clock.evidence else None,
                        evidence[0].observation_id,
                    )
                else:
                    self.assertEqual(
                        (clock.status, clock.anchor, clock.anchor_at, clock.evidence),
                        (CoverageStatus.UNDETERMINED, AnchorKind.DECLARED, expected, None),
                    )

    def test_a_verification_long_before_expected_since_reads_as_no_verification(self) -> None:
        # The audit's probe: Class B, UTC, and a 2024 PASS against a 2026 expectation.
        expected = datetime(2026, 1, 1, tzinfo=UTC)
        verified = datetime(2024, 1, 1, tzinfo=UTC)
        inventory = inventory_of(
            host("old", expectedSince=text(expected)),
            host("never", expectedSince=text(expected)),
            host("err", expectedSince=text(expected)),
        )
        evidence = [
            observation("old", at=verified),
            observation("err", at=expected, disposition=ERROR),
        ]
        lapsed = due(PCD_RULE, expected) + MICROSECOND
        for as_of in (datetime(2026, 1, 2, tzinfo=UTC), lapsed):
            with self.subTest(as_of=as_of.isoformat()):
                result = derive(evidence, inventory, as_of)
                summary = {row.rule_id: row for row in result.summary}
                for rule_id in (MVX_RULE, PCD_RULE):
                    self.assertEqual(
                        {
                            name: clock_of(result, rule_id, name).status
                            for name in ("old", "never", "err")
                        },
                        {
                            "old": CoverageStatus.UNDETERMINED,
                            "never": CoverageStatus.MISSING,
                            "err": CoverageStatus.UNDETERMINED,
                        },
                    )
                    old = clock_of(result, rule_id, "old")
                    self.assertEqual(
                        (old.anchor, old.anchor_at, old.evidence),
                        (AnchorKind.DECLARED, expected, None),
                    )
                    self.assertEqual(
                        summary[rule_id],
                        RuleSummary(
                            rule_id=rule_id,
                            force=policy().rule(rule_id).force,
                            expected=3,
                            missing=1,
                            undetermined=2,
                        ),
                    )
                    closed = [(expected, due(rule_id, expected), None)] if as_of == lapsed else []
                    self.assertEqual(windows_of(result, rule_id, "host:old"), closed)
                self.assertEqual(resource_of(result, "old").last_verified, verified)

    def test_a_verification_before_expected_since_anchors_when_its_window_reaches_it(self) -> None:
        verified = SINCE
        expected = verified + period(MVX_RULE) / 2
        inventory = inventory_of(host(expectedSince=text(expected)))
        result = derive(
            [observation(at=verified)], inventory, due(MVX_RULE, verified) + MICROSECOND
        )
        self.assertEqual(windows_of(result), [(verified, due(MVX_RULE, verified), None)])
        self.assertIs(clock_of(result).anchor, AnchorKind.VERIFICATION)

    def test_a_window_closing_exactly_at_expected_since_closes(self) -> None:
        verified = SINCE
        expected = due(MVX_RULE, verified)
        inventory = inventory_of(host(expectedSince=text(expected)))
        result = derive([observation(at=verified)], inventory, expected + MICROSECOND)
        self.assertEqual(windows_of(result), [(verified, expected, None)])
        self.assertIs(clock_of(result).status, CoverageStatus.STALE)

    def test_an_examination_before_expected_since_is_undetermined_not_missing(self) -> None:
        result = derive(
            [observation(at=SINCE - DAY, disposition=ERROR)], inventory_of(host()), SINCE
        )
        self.assertIs(clock_of(result).status, CoverageStatus.UNDETERMINED)


# *--- Calendar Zones ---*


class CalendarZoneTests(unittest.TestCase):
    """The NMV month clock follows the provider's calendar zone."""

    def test_the_nmv_month_clock_in_utc_and_in_phoenix(self) -> None:
        phoenix = ZoneInfo("America/Phoenix")
        # 20:00 on January 30 in Phoenix is already January 31 in UTC.
        attested = datetime(2027, 1, 30, 20, 0, tzinfo=phoenix)
        inventory = inventory_of(procedure(verifications=[attestation(attested)]))
        for class_name in ("B", "C"):
            with self.subTest(certification_class=class_name):
                utc, local = policy(class_name), policy(class_name, "America/Phoenix")
                utc_due, local_due = due(NMV_RULE, attested, utc), due(NMV_RULE, attested, local)
                self.assertNotEqual(utc_due, local_due)
                between = min(utc_due, local_due) + MICROSECOND
                self.assertLess(between, max(utc_due, local_due))
                statuses = set()
                for selected, expected in ((utc, utc_due), (local, local_due)):
                    clock = clock_of(
                        derive([], inventory, between, selected), NMV_RULE, "ir-plan", "logical"
                    )
                    self.assertEqual(clock.due_at, expected)
                    stale = between > expected
                    self.assertIs(
                        clock.status, CoverageStatus.STALE if stale else CoverageStatus.CURRENT
                    )
                    statuses.add(clock.status)
                self.assertEqual(statuses, {CoverageStatus.STALE, CoverageStatus.CURRENT})


# *--- Status And Summary ---*


class StatusAndSummaryTests(unittest.TestCase):
    """Every status, the summary per rule, force on every clock, and the warning as data."""

    def test_every_status_and_the_summary(self) -> None:
        as_of = SINCE + 60 * DAY
        inventory = inventory_of(
            host("current", group="pool"),
            host("stale"),
            host("missing"),
            host("undetermined"),
            host("future", expectedSince=text(as_of + DAY)),
        )
        evidence = [
            observation("current", at=as_of),
            observation("stale", at=SINCE + DAY),
            observation("undetermined", at=as_of, disposition=ERROR),
        ]
        result = derive(evidence, inventory, as_of)
        self.assertEqual(
            {
                name: clock_of(result, MVX_RULE, name).status
                for name in ("current", "stale", "missing", "undetermined", "future")
            },
            {
                "current": CoverageStatus.CURRENT,
                "stale": CoverageStatus.STALE,
                "missing": CoverageStatus.MISSING,
                "undetermined": CoverageStatus.UNDETERMINED,
                "future": CoverageStatus.UNANCHORED,
            },
        )
        self.assertEqual([row.rule_id for row in result.summary], list(COVERAGE_RULE_IDS))
        summary = {row.rule_id: row for row in result.summary}
        self.assertEqual(
            summary[MVX_RULE],
            RuleSummary(
                rule_id=MVX_RULE,
                force=policy().rule(MVX_RULE).force,
                expected=5,
                current=1,
                stale=1,
                missing=1,
                unanchored=1,
                undetermined=1,
            ),
        )
        self.assertEqual((summary[PSD_RULE].expected, summary[PSD_RULE].current), (1, 1))
        self.assertEqual((summary[NMV_RULE].expected, summary[PDD_RULE].expected), (0, 0))
        self.assertEqual(summary[PCD_RULE].expected, 5)

    def test_force_is_carried_on_every_clock_window_and_summary_row(self) -> None:
        inventory = inventory_of(
            host("drifting", drift=True, group="web-tier"),
            host("steady"),
            procedure(),
        )
        for class_name in ("B", "C"):
            selected = policy(class_name)
            with self.subTest(certification_class=class_name):
                result = derive([], inventory, SINCE + 400 * DAY, selected)
                clocks = [clock for item in result.resources for clock in item.clocks]
                self.assertEqual({clock.rule_id for clock in clocks}, set(COVERAGE_RULE_IDS))
                self.assertEqual(
                    {window.rule_id for window in result.windows}, set(COVERAGE_RULE_IDS)
                )
                for item in (*clocks, *result.windows, *result.summary):
                    self.assertIs(item.force, selected.rule(item.rule_id).force)
                for window in result.windows:
                    self.assertEqual(window.deadline.provenance, selected.provenance)

    def test_unknown_drift_is_warned_on_its_resource(self) -> None:
        inventory = inventory_of(host("unsure", drift=DRIFT_UNKNOWN), host("steady"))
        result = derive([], inventory, SINCE)
        self.assertEqual(resource_of(result, "unsure").warnings, (DRIFT_LIKELIHOOD_UNKNOWN,))
        self.assertEqual(resource_of(result, "steady").warnings, ())
        self.assertIn(PDD_RULE, [clock.rule_id for clock in resource_of(result, "unsure").clocks])

    def test_the_result_names_its_inputs(self) -> None:
        inventory = inventory_of(host())
        as_of = datetime(2026, 8, 1, 9, 0, tzinfo=ZoneInfo("America/Phoenix"))
        result = derive([], inventory, as_of)
        self.assertEqual(result.inventory, inventory)
        self.assertEqual(result.as_of, as_of)
        self.assertIs(result.as_of.tzinfo, UTC)
        self.assertEqual(result.profile, policy().profile)
        self.assertEqual(result.provenance, policy().provenance)


# *--- Determinism And Policy ---*


class DeterminismTests(unittest.TestCase):
    """The projection is a pure function: input order never changes it."""

    def test_the_same_inputs_in_any_order_give_an_equal_result(self) -> None:
        as_of = SINCE + 40 * DAY
        entries = [
            host("a", group="web-tier", aliases=[ALIAS]),
            host("b", group="web-tier", drift=DRIFT_UNKNOWN),
            host("c", decommissionedAt=text(SINCE + 20 * DAY)),
            procedure(group="web-tier", verifications=[attestation(SINCE + 3 * DAY)]),
        ]
        evidence = [
            observation("a", at=SINCE + DAY),
            observation("lab-01.lab.internal", at=SINCE + 2 * DAY),
            observation("b", at=SINCE + DAY, record="R-2"),
            observation("b", at=SINCE + DAY, record="R-1"),
            observation("b", at=SINCE + 9 * DAY, disposition=ERROR),
            observation("c", at=SINCE + 25 * DAY),
            observation("c", at=None),
            observation("a", at=as_of + DAY),
            observation("stray", at=SINCE + DAY),
            system_observation("a"),
        ]
        base = derive(evidence, inventory_of(*entries), as_of)
        orders = [list(reversed(evidence))]
        for seed in range(5):
            shuffled = list(evidence)
            random.Random(seed).shuffle(shuffled)
            orders.append(shuffled)
        for position, order in enumerate(orders):
            with self.subTest(order=position):
                self.assertEqual(derive(order, inventory_of(*entries), as_of), base)
        # A file listing the same entries in another order is another file, so its digest
        # differs; everything derived from it is the same.
        reordered = derive(evidence, inventory_of(*reversed(entries)), as_of)
        for name in ("summary", "resources", "windows", "unregistered", "later"):
            self.assertEqual(getattr(reordered, name), getattr(base, name))
        self.assertEqual(derive(iter(evidence), inventory_of(*entries), as_of), base)


class PolicyInputTests(unittest.TestCase):
    """Every coverage rule must resolve, used or not; as-of must name an instant."""

    def test_a_policy_missing_any_coverage_rule_refuses_the_run(self) -> None:
        inventory = inventory_of(procedure())
        for missing in COVERAGE_RULE_IDS:
            with self.subTest(missing=missing):
                stripped = dataclasses.replace(
                    policy(),
                    rules=tuple(item for item in policy().rules if item.rule_id != missing),
                )
                with self.assertRaisesRegex(PolicyRuleNotFoundError, missing):
                    derive([], inventory, SINCE, stripped)

    def test_as_of_must_be_aware(self) -> None:
        with self.assertRaises(ValueError):
            derive([], inventory_of(host()), datetime(2026, 8, 1))


# *--- Result Types ---*


class ResultShapeTests(unittest.TestCase):
    """Directly built result types hold the invariants the derivation guarantees."""

    def test_a_clock_holds_its_shape(self) -> None:
        ref = ResourceRef("lab-01", "host")
        key = ClockKey(MVX_RULE, resource=ref)
        force = policy().rule(MVX_RULE).force
        deadline = policy().coverage_deadline(MVX_RULE, SINCE)
        other = policy().coverage_deadline(NMV_RULE, SINCE)
        evidence = CoverageEvidence(EvidenceKind.OBSERVATION, ref, SINCE, "obs-1", PASS)
        current = CoverageStatus.CURRENT
        verification, declared = AnchorKind.VERIFICATION, AnchorKind.DECLARED
        cases: dict[str, dict[str, Any]] = {
            "unanchored with an anchor": {
                "status": CoverageStatus.UNANCHORED,
                "anchor": declared,
                "deadline": deadline,
            },
            "anchored without a deadline": {"status": current, "anchor": declared},
            "a status with no anchor": {"status": current},
            "a deadline with no anchor": {"status": current, "deadline": deadline},
            "a verification without evidence": {
                "status": current,
                "anchor": verification,
                "deadline": deadline,
            },
            "a declaration with evidence": {
                "status": current,
                "anchor": declared,
                "deadline": deadline,
                "evidence": evidence,
            },
            "another rule's deadline": {"status": current, "anchor": declared, "deadline": other},
            "a stand-in on a resource clock": {
                "status": current,
                "anchor": verification,
                "deadline": deadline,
                "evidence": evidence,
                "stand_in": ref,
            },
        }
        for label, fields in cases.items():
            with self.subTest(label), self.assertRaises(ValueError):
                CoverageClock(key=key, force=force, **fields)
        group = ClockKey(PSD_RULE, sample_group="web-tier")
        with self.assertRaises(ValueError):
            CoverageClock(
                key=group,
                force=policy().rule(PSD_RULE).force,
                status=current,
                anchor=verification,
                deadline=policy().coverage_deadline(PSD_RULE, SINCE),
                evidence=evidence,
            )

    def test_a_window_holds_its_shape(self) -> None:
        key = ClockKey(MVX_RULE, resource=ResourceRef("lab-01", "host"))
        deadline = policy().coverage_deadline(MVX_RULE, SINCE)
        for resumed in (deadline.due_at, deadline.due_at - DAY):
            with self.subTest(resumed=resumed.isoformat()), self.assertRaises(ValueError):
                CoverageWindow(
                    key=key, anchor=AnchorKind.DECLARED, deadline=deadline, resumed_at=resumed
                )

    def test_evidence_holds_its_shape(self) -> None:
        ref = ResourceRef("lab-01", "host")
        for label, fields in {
            "an observation without a disposition": {"kind": EvidenceKind.OBSERVATION},
            "an attestation with a disposition": {
                "kind": EvidenceKind.ATTESTATION,
                "disposition": PASS,
            },
            "an untimed attestation": {"kind": EvidenceKind.ATTESTATION, "at": None},
        }.items():
            with self.subTest(label), self.assertRaises(ValueError):
                CoverageEvidence(
                    resource=ref,
                    reference="r",
                    **{"at": SINCE, **fields},  # type: ignore[arg-type]
                )

    def test_a_summary_row_adds_up(self) -> None:
        with self.assertRaises(ValueError):
            RuleSummary(MVX_RULE, policy().rule(MVX_RULE).force, expected=2, current=1)


if __name__ == "__main__":
    unittest.main()
