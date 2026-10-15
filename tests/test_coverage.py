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
import unittest
from typing import Any

from complyroll.models import ResourceRef
from complyroll.policy import COVERAGE_RULE_IDS
from complyroll.reports import InformationResource, ReportInputError, parse_inventory
from complyroll.reports.coverage import (
    DRIFT_LIKELIHOOD_UNKNOWN,
    MVX_RULE,
    NMV_RULE,
    PCD_RULE,
    PDD_RULE,
    PSD_RULE,
    ClockKey,
    EntryClocks,
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


if __name__ == "__main__":
    unittest.main()
