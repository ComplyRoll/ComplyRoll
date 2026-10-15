# ******************************************************************************
# *Title: Coverage Report Tests*
# *Author: Kyle Versluis*
# *Description: The coverage block, its Markdown twin and its diagnostics.*
# ******************************************************************************
"""Tests for the coverage block a report carries when an inventory is given (ADR 0015)."""

# *--- Imports ---*

from __future__ import annotations

import copy
import json
import tempfile
import unittest
from collections.abc import Sequence
from dataclasses import replace
from datetime import UTC, datetime
from itertools import permutations
from pathlib import Path
from typing import Any
from unittest import mock

from test_reports import (
    ARTIFACTS,
    AVI_DETAIL_SECTIONS,
    EXAMPLES,
    FIXTURES,
    GOLDEN,
    HISTORICAL_DETAIL_SECTIONS,
    REPORT_KINDS,
    VDT_DETAIL_SECTIONS,
    ReportKind,
    assert_markdown_carries_the_json,
    compile_fixtures,
    markdown_section,
    markdown_subsection,
    markdown_table_list,
    options,
)

from complyroll.adapters import ingest_stig_artifact
from complyroll.models import ObservationDisposition
from complyroll.policy import (
    COVERAGE_RULE_IDS,
    CertificationClass,
    CertificationProfile,
    SelectedPolicy,
    load_bundled_rule_source_snapshot,
    select_policy,
)
from complyroll.reports import (
    CompiledReport,
    Inventory,
    ReportCompileError,
    ReportOptions,
    load_evaluations,
    load_inventory,
    parse_inventory,
)
from complyroll.reports import vdt as vdt_module
from complyroll.reports.coverage import (
    COVERAGE_BASIS,
    MVX_RULE,
    NMV_RULE,
    PCD_RULE,
    PDD_RULE,
    PSD_RULE,
)

# *--- Fixtures ---*

AS_OF = datetime(2026, 8, 21, 12, 0, tzinfo=UTC)
IMAGE = "registry.example.test/synthetic/example-service:1.4.0"
#: The instants the timed fixtures declare, in UTC.
CLEAN_AT = datetime(2026, 8, 5, 10, 0, tzinfo=UTC)
ARF_AT = datetime(2026, 8, 1, 16, 12, tzinfo=UTC)
ERRORS_AT = datetime(2026, 8, 20, 8, 0, tzinfo=UTC)
RECENT_AT = datetime(2026, 8, 20, 9, 0, tzinfo=UTC)
RETIRED_AT = datetime(2026, 8, 20, 10, 0, tzinfo=UTC)
#: The instants the inventory declares.
JULY = datetime(2026, 7, 1, tzinfo=UTC)
AUGUST = datetime(2026, 8, 1, tzinfo=UTC)
APRIL = datetime(2026, 4, 1, tzinfo=UTC)
IR_AT = datetime(2026, 8, 1, 17, 0, tzinfo=UTC)
IR_LATER_AT = datetime(2026, 9, 1, 17, 0, tzinfo=UTC)
BACKUP_AT = datetime(2026, 4, 1, 12, 0, tzinfo=UTC)
INVENTORY_NAME = "test-boundary"
GROUP = "logical:sample-group/scanned-fleet"

#: Context keys, the way the block and the Markdown print a resource.
IMAGE_KEY = f"image:{IMAGE}"
RHEL = "host:lab-rhel-03"
ERRORS = "host:lab-errors-01"
RECENT = "host:lab-recent-01"
RETIRED = "host:lab-retired-01"
UBUNTU = "host:ubuntu-primary"
WINDOWS = "host:lab-win-01"
FUTURE = "host:lab-future-01"
IR = "logical:incident-response-procedure"
BACKUP = "logical:backup-procedure"


def xccdf(benchmark: str, target: str, end_time: str, *results: str) -> str:
    """Return a one-target XCCDF result whose rules carry the given results, in order."""

    rules = ("banner_etc_issue", "sshd_disable_root_login", "audit_rules_immutable")
    rows = "".join(
        f'    <rule-result idref="xccdf_org.ssgproject.content_rule_{rule}" severity="medium">\n'
        f"      <result>{result}</result>\n"
        "    </rule-result>\n"
        for rule, result in zip(rules, results, strict=False)
    )
    return (
        '<?xml version="1.0" encoding="UTF-8"?>\n'
        f'<Benchmark xmlns="http://checklists.nist.gov/xccdf/1.2" id="{benchmark}">\n'
        f'  <TestResult id="{benchmark}" end-time="{end_time}">\n'
        f"    <target>{target}</target>\n"
        f"{rows}"
        "  </TestResult>\n"
        "</Benchmark>\n"
    )


#: Three timed scans: one that only examined, one recent pass, one after decommissioning.
CRAFTED = {
    "examine-only.xml": xccdf(
        "examine-only", "lab-errors-01", "2026-08-20T08:00:00Z", "error", "notchecked"
    ),
    "recent.xml": xccdf("recent", "lab-recent-01", "2026-08-20T09:00:00Z", "pass"),
    "retired.xml": xccdf("retired", "lab-retired-01", "2026-08-20T10:00:00Z", "pass"),
}


def machine(resource_type: str, resource_id: str, since: str, drift: object, **extra: Any) -> dict:
    return {
        "resourceType": resource_type,
        "resourceId": resource_id,
        "machineBased": True,
        "driftLikely": drift,
        "expectedSince": since,
        **extra,
    }


def attested(resource_id: str, since: str, *verifications: tuple[str, str]) -> dict:
    return {
        "resourceType": "logical",
        "resourceId": resource_id,
        "machineBased": False,
        "expectedSince": since,
        "verifications": [{"at": at, "reference": text} for at, text in verifications],
    }


#: One entry per behavior the block must carry; lab-ubuntu-02 is observed and left out.
INVENTORY_DOCUMENT = {
    "schema": "complyroll.inventory",
    "schemaVersion": 1,
    "name": INVENTORY_NAME,
    "resources": [
        machine(
            "image",
            IMAGE,
            "2026-08-01T00:00:00Z",
            False,
            sampleGroup="scanned-fleet",
            job="nightly-sarif",
        ),
        machine(
            "host",
            "lab-rhel-03",
            "2026-07-01T00:00:00Z",
            "unknown",
            sampleGroup="scanned-fleet",
            job="nightly-openscap",
        ),
        machine("host", "lab-errors-01", "2026-08-01T00:00:00Z", True),
        machine("host", "lab-recent-01", "2026-08-01T00:00:00Z", True),
        machine(
            "host",
            "lab-retired-01",
            "2026-07-01T00:00:00Z",
            False,
            decommissionedAt="2026-08-15T00:00:00Z",
        ),
        machine(
            "host",
            "ubuntu-primary",
            "2026-07-01T00:00:00Z",
            True,
            aliases=[{"resourceType": "host", "resourceId": "lab-ubuntu-01"}],
        ),
        machine("host", "lab-win-01", "2026-07-01T00:00:00Z", False),
        machine("host", "lab-future-01", "2026-09-01T00:00:00Z", False),
        attested(
            "incident-response-procedure",
            "2026-07-01T00:00:00Z",
            ("2026-08-01T17:00:00Z", "IR tabletop record"),
            ("2026-09-01T17:00:00Z", "IR tabletop, second run"),
        ),
        attested(
            "backup-procedure",
            "2026-04-01T00:00:00Z",
            ("2026-04-01T12:00:00Z", "Restore test record"),
        ),
    ],
}

#: The `vdt-coverage-timed` run. Both SARIF artifacts declare their own clocks, so machine
#: clocks anchor here, which no untimed checklist in the `vdt-coverage` set can show. The
#: inventory is a test fixture; `examples/inventory.json` stays the one walkthrough file.
TIMED_ARTIFACTS = (FIXTURES / "codeql-repo.sarif", FIXTURES / "clean-run.sarif")
TIMED_INVENTORY = FIXTURES / "inventory-timed.json"
TIMED_OPTIONS: dict[str, Any] = {
    "as_of": datetime(2026, 9, 3, 12, tzinfo=UTC),
    "detected_at": None,
    "period_from": datetime(2026, 9, 1, tzinfo=UTC),
    "period_to": datetime(2026, 9, 30, 23, 59, 59, tzinfo=UTC),
}


def iso(value: datetime) -> str:
    return value.astimezone(UTC).isoformat().replace("+00:00", "Z")


def class_c_policy() -> SelectedPolicy:
    return select_policy(
        load_bundled_rule_source_snapshot(), CertificationProfile(CertificationClass.C)
    )


def stripping(*rule_ids: str) -> Any:
    """Return a `select_policy` that drops the named rules from what it selects."""

    real = select_policy

    def select(snapshot: Any, profile: Any) -> SelectedPolicy:
        policy = real(snapshot, profile)
        return replace(
            policy, rules=tuple(item for item in policy.rules if item.rule_id not in rule_ids)
        )

    return select


def observation_ids(path: Path, *dispositions: ObservationDisposition) -> list[str]:
    """Return one artifact's observation ids, sorted, limited to the given dispositions."""

    result = ingest_stig_artifact(path, ingested_at=AS_OF)
    return sorted(
        item.observation_id
        for item in result.observations
        if not dispositions or item.disposition in dispositions
    )


VERIFYING = (
    ObservationDisposition.OPEN,
    ObservationDisposition.PASS,
    ObservationDisposition.NOT_APPLICABLE,
)


class CoverageFixture(unittest.TestCase):
    """Every report kind compiled over the same artifacts, with and without the inventory."""

    artifacts: tuple[Path, ...]
    inventory: Inventory
    policy: SelectedPolicy
    reports: dict[ReportKind, CompiledReport]
    bare: dict[ReportKind, CompiledReport]

    @classmethod
    def setUpClass(cls) -> None:
        directory = tempfile.TemporaryDirectory()
        cls.addClassCleanup(directory.cleanup)
        crafted = []
        for name, text in CRAFTED.items():
            path = Path(directory.name) / name
            path.write_text(text, encoding="utf-8")
            crafted.append(path)
        cls.crafted = {path.name: path for path in crafted}
        cls.artifacts = (
            *ARTIFACTS,
            FIXTURES / "clean-run.sarif",
            FIXTURES / "openscap-arf.xml",
            *crafted,
        )
        cls.inventory = parse_inventory(json.dumps(INVENTORY_DOCUMENT).encode("utf-8"))
        cls.policy = class_c_policy()
        cls.reports = {
            kind: compile_fixtures(artifacts=cls.artifacts, kind=kind, inventory=cls.inventory)
            for kind in REPORT_KINDS
        }
        cls.bare = {
            kind: compile_fixtures(artifacts=cls.artifacts, kind=kind) for kind in REPORT_KINDS
        }

    def block(self, kind: ReportKind = "vdt") -> dict[str, Any]:
        return self.reports[kind].document["x-complyroll"]["coverage"]

    def resources(self) -> dict[str, dict[str, Any]]:
        return {
            f"{item['resourceType']}:{item['resourceId']}": item
            for item in self.block()["resources"]
        }

    def clocks(self) -> dict[tuple[str, str], dict[str, Any]]:
        return {
            (label, clock["ruleId"]): clock
            for label, item in self.resources().items()
            for clock in item["clocks"]
        }

    def due(self, rule_id: str, anchor: datetime) -> str:
        return iso(self.policy.coverage_deadline(rule_id, anchor).due_at)


# *--- Block ---*


class CoverageBlockTests(CoverageFixture):
    def test_every_report_carries_the_same_block(self) -> None:
        for kind in REPORT_KINDS:
            with self.subTest(report=kind):
                self.assertEqual(self.block(kind), self.block("vdt"))

    def test_the_block_leaves_every_other_field_alone(self) -> None:
        for kind in REPORT_KINDS:
            with self.subTest(report=kind):
                full = copy.deepcopy(self.reports[kind].document)
                bare = copy.deepcopy(self.bare[kind].document)
                extension = full.pop("x-complyroll")
                bare_extension = bare.pop("x-complyroll")
                # Every official field, record extensions included, is untouched.
                self.assertEqual(full, bare)
                coverage_notes = [
                    item
                    for item in extension.pop("diagnostics")
                    if item["code"] == "drift_likelihood_unknown"
                ]
                self.assertEqual(len(coverage_notes), 1)
                extension.pop("coverage")
                bare_notes = bare_extension.pop("diagnostics")
                self.assertEqual(
                    [
                        item
                        for item in self.reports[kind].document["x-complyroll"]["diagnostics"]
                        if item["code"] != "drift_likelihood_unknown"
                    ],
                    bare_notes,
                )
                self.assertEqual(extension, bare_extension)

    def test_the_inventory_is_named_by_digest_and_the_basis_is_fixed(self) -> None:
        block = self.block()
        self.assertEqual(
            block["inventory"],
            {
                "name": INVENTORY_NAME,
                "sha256": self.inventory.sha256,
                "sizeBytes": self.inventory.size_bytes,
                "entries": 10,
            },
        )
        self.assertEqual(block["asOf"], iso(AS_OF))
        self.assertEqual(block["asOf"], self.reports["vdt"].document["x-complyroll"]["generatedAt"])
        self.assertEqual(block["basis"], COVERAGE_BASIS)
        for phrase in (
            "VDR-TFR-MVX is read from detection results until Phase 3 validation runs exist",
            "provider-supplied inventory named by its SHA-256 digest",
            "is not a compliance finding",
        ):
            self.assertIn(phrase, COVERAGE_BASIS)
        self.assertNotIn("approved", COVERAGE_BASIS.lower())
        self.assertTrue(COVERAGE_BASIS.isascii())

    def test_the_block_keys(self) -> None:
        block = self.block()
        self.assertEqual(
            set(block),
            {
                "inventory",
                "asOf",
                "basis",
                "summary",
                "resources",
                "windows",
                "unregistered",
                "later",
            },
        )
        resource = self.resources()[RHEL]
        self.assertEqual(
            set(resource),
            {
                "resourceType",
                "resourceId",
                "machineBased",
                "attested",
                "driftLikely",
                "sampleGroup",
                "job",
                "expectedSince",
                "decommissionedAt",
                "aliases",
                "lastExamined",
                "lastVerified",
                "examined",
                "untimed",
                "untimedEvidence",
                "afterDecommission",
                "clocks",
            },
        )
        clock_keys = {
            "ruleId",
            "contextKey",
            "force",
            "status",
            "anchor",
            "anchorAt",
            "dueAt",
            "evidence",
            "standIn",
        }
        for clock in resource["clocks"]:
            self.assertEqual(set(clock), clock_keys)
        for window in block["windows"]:
            self.assertEqual(
                set(window),
                {
                    "ruleId",
                    "contextKey",
                    "force",
                    "anchor",
                    "anchorAt",
                    "closedAt",
                    "resumedAt",
                    "evidence",
                    "standIn",
                },
            )
        self.assertEqual(
            set(block["summary"][0]),
            {
                "ruleId",
                "force",
                "expected",
                "current",
                "stale",
                "missing",
                "unanchored",
                "undetermined",
            },
        )

    def test_resources_follow_the_inventory_order(self) -> None:
        self.assertEqual(
            list(self.resources()),
            # By type, then id: hosts, then the image, then the logical resources.
            [ERRORS, FUTURE, RECENT, RETIRED, RHEL, WINDOWS, UBUNTU, IMAGE_KEY, BACKUP, IR],
        )

    def test_every_clock_reads_its_status_and_due_date_from_the_dataset(self) -> None:
        expected = {
            (IMAGE_KEY, MVX_RULE): ("stale", "verification", CLEAN_AT),
            (IMAGE_KEY, PCD_RULE): ("current", "verification", CLEAN_AT),
            (IMAGE_KEY, PSD_RULE): ("stale", "verification", CLEAN_AT),
            (RHEL, MVX_RULE): ("stale", "verification", ARF_AT),
            (RHEL, PDD_RULE): ("stale", "verification", ARF_AT),
            (RHEL, PSD_RULE): ("stale", "verification", CLEAN_AT),
            (ERRORS, MVX_RULE): ("undetermined", "declared", AUGUST),
            (ERRORS, PDD_RULE): ("undetermined", "declared", AUGUST),
            (RECENT, MVX_RULE): ("current", "verification", RECENT_AT),
            (RECENT, PDD_RULE): ("current", "verification", RECENT_AT),
            (RETIRED, MVX_RULE): ("missing", "declared", JULY),
            (RETIRED, PCD_RULE): ("missing", "declared", JULY),
            (UBUNTU, MVX_RULE): ("missing", "declared", JULY),
            (UBUNTU, PDD_RULE): ("missing", "declared", JULY),
            (WINDOWS, MVX_RULE): ("missing", "declared", JULY),
            (WINDOWS, PCD_RULE): ("missing", "declared", JULY),
            (FUTURE, MVX_RULE): ("unanchored", None, None),
            (FUTURE, PCD_RULE): ("unanchored", None, None),
            (IR, NMV_RULE): ("current", "verification", IR_AT),
            (BACKUP, NMV_RULE): ("stale", "verification", BACKUP_AT),
        }
        clocks = self.clocks()
        self.assertEqual(set(clocks), set(expected))
        for key, (status, anchor, anchor_at) in expected.items():
            with self.subTest(clock=key):
                clock = clocks[key]
                rule_id = key[1]
                self.assertEqual(clock["status"], status)
                self.assertEqual(clock["anchor"], anchor)
                self.assertEqual(clock["force"], self.policy.rule(rule_id).force.value)
                group = rule_id == PSD_RULE
                self.assertEqual(clock["contextKey"], GROUP if group else key[0])
                if anchor_at is None:
                    self.assertIsNone(clock["anchorAt"])
                    self.assertIsNone(clock["dueAt"])
                    continue
                deadline = self.policy.coverage_deadline(rule_id, anchor_at)
                self.assertEqual(clock["anchorAt"], iso(deadline.start_at))
                self.assertEqual(clock["dueAt"], iso(deadline.due_at))
                self.assertEqual(clock["force"], deadline.force.value)
                # Strict overdue: stale and current read the dataset's due date against as-of.
                if status == "current":
                    self.assertGreaterEqual(deadline.due_at, AS_OF)
                if status == "stale":
                    self.assertLess(deadline.due_at, AS_OF)

    def test_the_summary_counts_each_clock_once(self) -> None:
        counts = {
            row["ruleId"]: (
                row["expected"],
                row["current"],
                row["stale"],
                row["missing"],
                row["unanchored"],
                row["undetermined"],
            )
            for row in self.block()["summary"]
        }
        self.assertEqual(list(counts), list(COVERAGE_RULE_IDS))
        self.assertEqual(
            counts,
            {
                MVX_RULE: (8, 1, 2, 3, 1, 1),
                NMV_RULE: (2, 1, 1, 0, 0, 0),
                PCD_RULE: (4, 1, 0, 2, 1, 0),
                PDD_RULE: (4, 1, 1, 1, 0, 1),
                # Two members share the one group clock, counted once.
                PSD_RULE: (1, 0, 1, 0, 0, 0),
            },
        )
        for row in self.block()["summary"]:
            self.assertEqual(row["force"], self.policy.rule(row["ruleId"]).force.value)

    def test_every_lapse_is_one_window_anchored_on_the_next_verification(self) -> None:
        def window(
            rule_id: str,
            context: str,
            anchor: str,
            anchor_at: datetime,
            resumed_at: datetime | None,
            stand_in: str | None = None,
        ) -> tuple[object, ...]:
            return (
                rule_id,
                context,
                anchor,
                iso(anchor_at),
                self.due(rule_id, anchor_at),
                None if resumed_at is None else iso(resumed_at),
                stand_in,
                self.policy.rule(rule_id).force.value,
            )

        # By rule, then subject type and id, then the instant each window closed.
        expected = [
            window(MVX_RULE, ERRORS, "declared", AUGUST, None),
            window(MVX_RULE, RECENT, "declared", AUGUST, RECENT_AT),
            window(MVX_RULE, RETIRED, "declared", JULY, None),
            window(MVX_RULE, RHEL, "declared", JULY, ARF_AT),
            window(MVX_RULE, RHEL, "verification", ARF_AT, None),
            window(MVX_RULE, WINDOWS, "declared", JULY, None),
            window(MVX_RULE, UBUNTU, "declared", JULY, None),
            window(MVX_RULE, IMAGE_KEY, "declared", AUGUST, CLEAN_AT),
            window(MVX_RULE, IMAGE_KEY, "verification", CLEAN_AT, None),
            window(NMV_RULE, BACKUP, "verification", BACKUP_AT, None),
            window(PCD_RULE, RETIRED, "declared", JULY, None),
            window(PCD_RULE, WINDOWS, "declared", JULY, None),
            window(PDD_RULE, ERRORS, "declared", AUGUST, None),
            window(PDD_RULE, RECENT, "declared", AUGUST, RECENT_AT),
            window(PDD_RULE, RHEL, "declared", JULY, ARF_AT),
            window(PDD_RULE, RHEL, "verification", ARF_AT, None),
            window(PDD_RULE, UBUNTU, "declared", JULY, None),
            window(PSD_RULE, GROUP, "declared", JULY, ARF_AT),
            window(PSD_RULE, GROUP, "verification", ARF_AT, CLEAN_AT, RHEL),
            window(PSD_RULE, GROUP, "verification", CLEAN_AT, None, IMAGE_KEY),
        ]
        seen = [
            (
                item["ruleId"],
                item["contextKey"],
                item["anchor"],
                item["anchorAt"],
                item["closedAt"],
                item["resumedAt"],
                None
                if item["standIn"] is None
                else f"{item['standIn']['resourceType']}:{item['standIn']['resourceId']}",
                item["force"],
            )
            for item in self.block()["windows"]
        ]
        self.assertEqual(seen, expected)

    def test_anchor_evidence_names_the_observation_or_the_attestation(self) -> None:
        clocks = self.clocks()
        (clean,) = observation_ids(FIXTURES / "clean-run.sarif")
        arf = observation_ids(FIXTURES / "openscap-arf.xml", *VERIFYING)
        self.assertEqual(
            clocks[(IMAGE_KEY, MVX_RULE)]["evidence"],
            {
                "kind": "observation",
                "at": iso(CLEAN_AT),
                "observationId": clean,
                "disposition": "pass",
                "resourceType": "image",
                "resourceId": IMAGE,
            },
        )
        # Four observations share the ARF instant; the least verifying one is named.
        rhel = clocks[(RHEL, MVX_RULE)]["evidence"]
        self.assertEqual(rhel["observationId"], arf[0])
        self.assertEqual(rhel["at"], iso(ARF_AT))
        self.assertEqual(
            clocks[(IR, NMV_RULE)]["evidence"],
            {
                "kind": "attestation",
                "at": iso(IR_AT),
                "reference": "IR tabletop record",
                "resourceType": "logical",
                "resourceId": "incident-response-procedure",
            },
        )
        for key in ((ERRORS, MVX_RULE), (UBUNTU, PDD_RULE), (FUTURE, MVX_RULE)):
            with self.subTest(clock=key):
                self.assertIsNone(clocks[key]["evidence"])

    def test_a_sample_group_names_the_member_that_stood_in(self) -> None:
        clocks = self.clocks()
        group = clocks[(IMAGE_KEY, PSD_RULE)]
        self.assertEqual(group, clocks[(RHEL, PSD_RULE)])
        self.assertEqual(group["standIn"], {"resourceType": "image", "resourceId": IMAGE})
        self.assertEqual(group["evidence"], clocks[(IMAGE_KEY, MVX_RULE)]["evidence"])
        for key, clock in clocks.items():
            if key[1] != PSD_RULE:
                with self.subTest(clock=key):
                    self.assertIsNone(clock["standIn"])

    def test_resource_rows_carry_the_entry_and_what_examined_it(self) -> None:
        resources = self.resources()
        rhel = resources[RHEL]
        self.assertEqual(
            {key: rhel[key] for key in rhel if key not in ("clocks", "untimedEvidence")},
            {
                "resourceType": "host",
                "resourceId": "lab-rhel-03",
                "machineBased": True,
                "attested": False,
                "driftLikely": "unknown",
                "sampleGroup": "scanned-fleet",
                "job": "nightly-openscap",
                "expectedSince": iso(JULY),
                "decommissionedAt": None,
                "aliases": [],
                "lastExamined": iso(ARF_AT),
                "lastVerified": iso(ARF_AT),
                # The not-reviewed row examines and is counted; it never verifies.
                "examined": 4,
                "untimed": 0,
                "afterDecommission": [],
            },
        )
        errors = resources[ERRORS]
        self.assertEqual(
            (errors["lastExamined"], errors["lastVerified"], errors["examined"]),
            (iso(ERRORS_AT), None, 2),
        )
        self.assertEqual(
            (resources[IMAGE_KEY]["driftLikely"], resources[RECENT]["driftLikely"]),
            (False, True),
        )

    def test_a_non_machine_row_is_labeled_attested(self) -> None:
        for label, item in self.resources().items():
            with self.subTest(resource=label):
                self.assertEqual(item["attested"], not item["machineBased"])
                self.assertEqual(item["attested"], label in (IR, BACKUP))
        ir = self.resources()[IR]
        self.assertIsNone(ir["driftLikely"])
        # An attestation examines and verifies, and is not an observation.
        self.assertEqual(
            (ir["lastExamined"], ir["lastVerified"], ir["examined"]),
            (iso(IR_AT), iso(IR_AT), 0),
        )

    def test_untimed_evidence_is_counted_and_listed_through_the_alias(self) -> None:
        ubuntu = self.resources()[UBUNTU]
        checklist = observation_ids(FIXTURES / "ubuntu-host.cklb")
        self.assertEqual(
            ubuntu["aliases"], [{"resourceType": "host", "resourceId": "lab-ubuntu-01"}]
        )
        self.assertEqual(ubuntu["untimed"], len(checklist))
        self.assertEqual([item["observationId"] for item in ubuntu["untimedEvidence"]], checklist)
        for item in ubuntu["untimedEvidence"]:
            self.assertIsNone(item["at"])
            self.assertEqual((item["resourceType"], item["resourceId"]), ("host", "lab-ubuntu-01"))
        self.assertEqual((ubuntu["lastExamined"], ubuntu["examined"]), (None, 0))
        self.assertEqual(self.resources()[WINDOWS]["untimed"], 2)

    def test_evidence_after_decommissioning_is_listed_and_never_used(self) -> None:
        retired = self.resources()[RETIRED]
        (observed,) = observation_ids(self.crafted["retired.xml"])
        self.assertEqual(retired["decommissionedAt"], "2026-08-15T00:00:00Z")
        self.assertEqual(
            retired["afterDecommission"],
            [
                {
                    "kind": "observation",
                    "at": iso(RETIRED_AT),
                    "observationId": observed,
                    "disposition": "pass",
                    "resourceType": "host",
                    "resourceId": "lab-retired-01",
                }
            ],
        )
        self.assertEqual(
            (retired["lastExamined"], retired["lastVerified"], retired["examined"]),
            (None, None, 0),
        )

    def test_unregistered_and_later_evidence_are_listed(self) -> None:
        block = self.block()
        self.assertEqual(
            block["unregistered"],
            [{"resourceType": "host", "resourceId": "lab-ubuntu-02", "observations": 3}],
        )
        self.assertEqual(
            block["later"],
            [
                {
                    "kind": "attestation",
                    "at": iso(IR_LATER_AT),
                    "reference": "IR tabletop, second run",
                    "resourceType": "logical",
                    "resourceId": "incident-response-procedure",
                }
            ],
        )


# *--- Markdown ---*


class CoverageMarkdownTests(CoverageFixture):
    SECTIONS = {
        "vdt": VDT_DETAIL_SECTIONS,
        "avi": AVI_DETAIL_SECTIONS,
        "historical": HISTORICAL_DETAIL_SECTIONS,
    }

    def test_every_twin_carries_every_coverage_row(self) -> None:
        for kind in REPORT_KINDS:
            with self.subTest(report=kind):
                assert_markdown_carries_the_json(
                    self, self.reports[kind], sections=self.SECTIONS[kind]
                )

    def test_the_section_sits_after_inputs_and_before_diagnostics(self) -> None:
        for kind in REPORT_KINDS:
            with self.subTest(report=kind):
                headings = [
                    line
                    for line in self.reports[kind].to_markdown().splitlines()
                    if line.startswith("## ")
                ]
                position = headings.index("## Coverage")
                self.assertEqual(headings[position - 1], "## Inputs")
                self.assertEqual(headings[position + 1], "## Diagnostics")

    def test_a_missing_clock_prints_the_untimed_count_beside_it(self) -> None:
        section = markdown_section(self.reports["vdt"].to_markdown(), "Coverage")
        self.assertIn(f"| {UBUNTU} | machine | host:lab-ubuntu-01 | yes | n/a | n/a |", section)
        self.assertIn(
            f"{MVX_RULE} MUST missing (6 untimed); {PDD_RULE} SHOULD missing (6 untimed) |",
            section,
        )
        # A missing clock with no untimed evidence prints the status alone.
        self.assertIn(f"{MVX_RULE} MUST missing; {PCD_RULE} SHOULD missing |", section)

    def test_force_is_printed_on_every_clock_and_window(self) -> None:
        section = markdown_section(self.reports["vdt"].to_markdown(), "Coverage")
        for heading, first in (("Clocks", "Resource"), ("Windows", "Rule")):
            rows = markdown_table_list(markdown_subsection(section, heading), 9, first)
            self.assertTrue(rows, heading)
            for cells in rows:
                self.assertIn(cells[2], ("MUST", "SHOULD"), heading)

    def test_the_basis_and_the_rules_commit_are_printed(self) -> None:
        section = markdown_section(self.reports["vdt"].to_markdown(), "Coverage")
        commit = self.reports["vdt"].document["x-complyroll"]["rulesSource"]["commit"]
        self.assertIn(COVERAGE_BASIS, section)
        self.assertIn(f"rules dataset commit {commit}", section)
        self.assertIn(f"SHA-256 {self.inventory.sha256}", section)

    def test_a_twin_without_an_inventory_has_no_coverage_section(self) -> None:
        for kind in REPORT_KINDS:
            with self.subTest(report=kind):
                self.assertNotIn("## Coverage", self.bare[kind].to_markdown())


# *--- Diagnostics ---*


class CoverageDiagnosticTests(CoverageFixture):
    def test_unknown_drift_warns_once_per_entry_at_the_inventory_and_the_pair(self) -> None:
        for kind in REPORT_KINDS:
            with self.subTest(report=kind):
                notes = [
                    item
                    for item in self.reports[kind].diagnostics
                    if item.code == "drift_likelihood_unknown"
                ]
                self.assertEqual(len(notes), 1)
                (note,) = notes
                self.assertEqual(note.level.value, "warning")
                self.assertEqual(note.location, f"{INVENTORY_NAME} {RHEL}")
                self.assertIn(PDD_RULE, note.message)
                self.assertIn(RHEL, note.message)
                self.assertIn(
                    note.to_dict(), self.reports[kind].document["x-complyroll"]["diagnostics"]
                )

    def test_the_warning_follows_the_record_set_diagnostics(self) -> None:
        notes = [item.code for item in self.reports["historical"].diagnostics]
        self.assertEqual(notes[-1], "drift_likelihood_unknown")

    def test_two_unknown_entries_warn_in_inventory_order(self) -> None:
        document = copy.deepcopy(INVENTORY_DOCUMENT)
        document["resources"][2]["driftLikely"] = "unknown"
        inventory = parse_inventory(json.dumps(document).encode("utf-8"))
        report = compile_fixtures(artifacts=self.artifacts, inventory=inventory)
        self.assertEqual(
            [
                item.location
                for item in report.diagnostics
                if item.code == "drift_likelihood_unknown"
            ],
            [f"{INVENTORY_NAME} {ERRORS}", f"{INVENTORY_NAME} {RHEL}"],
        )


# *--- Rules ---*


class CoverageRuleTests(CoverageFixture):
    def test_a_policy_without_a_coverage_rule_stops_the_run_and_names_it(self) -> None:
        for missing in COVERAGE_RULE_IDS:
            with (
                self.subTest(missing=missing),
                mock.patch.object(vdt_module, "select_policy", stripping(missing)),
                self.assertRaises(ReportCompileError) as caught,
            ):
                compile_fixtures(artifacts=self.artifacts, inventory=self.inventory)
            (diagnostic,) = caught.exception.diagnostics
            self.assertEqual(diagnostic.code, "coverage_rule_unavailable")
            self.assertEqual(diagnostic.level.value, "error")
            self.assertIn(missing, diagnostic.message)
            self.assertEqual(diagnostic.location, INVENTORY_NAME)
            for other in set(COVERAGE_RULE_IDS) - {missing}:
                self.assertNotIn(other, diagnostic.message)

    def test_every_missing_rule_is_named_in_one_diagnostic(self) -> None:
        with (
            mock.patch.object(vdt_module, "select_policy", stripping(*COVERAGE_RULE_IDS)),
            self.assertRaises(ReportCompileError) as caught,
        ):
            compile_fixtures(artifacts=self.artifacts, inventory=self.inventory)
        (diagnostic,) = caught.exception.diagnostics
        for rule_id in COVERAGE_RULE_IDS:
            self.assertIn(rule_id, diagnostic.message)

    def test_without_an_inventory_the_coverage_rules_are_never_read(self) -> None:
        for kind in REPORT_KINDS:
            with (
                self.subTest(report=kind),
                mock.patch.object(vdt_module, "select_policy", stripping(*COVERAGE_RULE_IDS)),
            ):
                report = compile_fixtures(artifacts=self.artifacts, kind=kind)
            self.assertEqual(report.to_json(), self.bare[kind].to_json())
            self.assertEqual(report.to_markdown(), self.bare[kind].to_markdown())


# *--- Golden ---*


class CoverageGoldenLibraryTests(unittest.TestCase):
    """The library compiles the `vdt-coverage` goldens the command line cut."""

    def test_the_library_compiles_the_golden_and_its_twin_carries_every_row(self) -> None:
        report = compile_fixtures(
            evaluations=load_evaluations(EXAMPLES / "evaluations.json"),
            inventory=load_inventory(EXAMPLES / "inventory.json"),
        )

        self.assertEqual(report.to_json(), (GOLDEN / "vdt-coverage.json").read_text("utf-8"))
        self.assertEqual(report.to_markdown(), (GOLDEN / "vdt-coverage.md").read_text("utf-8"))
        assert_markdown_carries_the_json(self, report)


class TimedCoverageTests(unittest.TestCase):
    """The `vdt-coverage-timed` run: machine clocks that timed SARIF evidence anchors."""

    report: CompiledReport

    @classmethod
    def setUpClass(cls) -> None:
        cls.report = compile_fixtures(
            artifacts=TIMED_ARTIFACTS, inventory=load_inventory(TIMED_INVENTORY), **TIMED_OPTIONS
        )

    def test_each_resource_carries_its_status_on_every_clock(self) -> None:
        # Asserted on a fresh compile, apart from the golden, so a refresh cannot flip one.
        statuses = {
            item["resourceId"].rsplit("/", 1)[-1]: {clock["status"] for clock in item["clocks"]}
            for item in self.report.document["x-complyroll"]["coverage"]["resources"]
        }
        self.assertEqual(statuses["helpers.js"], {"current"})
        self.assertEqual(statuses["example-service:1.4.0"], {"stale"})
        self.assertEqual(statuses["legacy.js"], {"undetermined"})

    def test_the_library_compiles_the_timed_golden_and_its_twin_carries_every_row(self) -> None:
        golden = GOLDEN / "vdt-coverage-timed"
        self.assertEqual(self.report.to_json(), golden.with_suffix(".json").read_text("utf-8"))
        self.assertEqual(self.report.to_markdown(), golden.with_suffix(".md").read_text("utf-8"))
        assert_markdown_carries_the_json(self, self.report)


class FallbackIdentityTests(unittest.TestCase):
    """An adapter's fallback identity reaches an entry only through a declared alias."""

    def coverage(self, artifacts: Sequence[Path], entry: dict[str, Any]) -> dict[str, Any]:
        document = {
            "schema": "complyroll.inventory",
            "schemaVersion": 1,
            "name": "fallback-boundary",
            "resources": [entry],
        }
        inventory = parse_inventory(json.dumps(document).encode("utf-8"))
        report = compile_fixtures(artifacts=artifacts, inventory=inventory)
        coverage: dict[str, Any] = report.document["x-complyroll"]["coverage"]
        return coverage

    def test_a_sarif_driver_name_reaches_its_entry_through_an_alias(self) -> None:
        # A SARIF result with no usable location is named by its driver (`SpecCorners`),
        # not by a filename stem. Both such results in the fixture are untimed.
        artifacts = (FIXTURES / "sarif-spec-corners.sarif",)
        entry = machine("scan", "spec-corners-scanner", "2026-08-01T00:00:00Z", False)
        fallback = {"resourceType": "scan", "resourceId": "SpecCorners"}

        without = self.coverage(artifacts, entry)
        aliased = self.coverage(artifacts, {**entry, "aliases": [fallback]})

        self.assertIn({**fallback, "observations": 2}, without["unregistered"])
        self.assertEqual(without["resources"][0]["untimed"], 0)
        (row,) = aliased["resources"]
        self.assertEqual(row["untimed"], 2)
        self.assertEqual(
            {(item["resourceType"], item["resourceId"]) for item in row["untimedEvidence"]},
            {("scan", "SpecCorners")},
        )
        self.assertEqual({clock["status"] for clock in row["clocks"]}, {"missing"})
        self.assertNotIn({**fallback, "observations": 2}, aliased["unregistered"])

    def test_an_xccdf_filename_stem_reaches_its_entry_through_an_alias(self) -> None:
        # An XCCDF result with no target is named by its file stem, and this one is timed.
        entry = machine("host", "stem-primary", "2026-08-01T00:00:00Z", False)
        stem = {"resourceType": "host", "resourceId": "lab-stem-01"}
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "lab-stem-01.xml"
            text = xccdf("stem", "unused", "2026-08-20T11:00:00Z", "pass")
            path.write_text(text.replace("    <target>unused</target>\n", ""), encoding="utf-8")

            without = self.coverage((path,), entry)
            aliased = self.coverage((path,), {**entry, "aliases": [stem]})

        self.assertEqual(without["unregistered"], [{**stem, "observations": 1}])
        self.assertEqual(
            {clock["status"] for clock in without["resources"][0]["clocks"]}, {"missing"}
        )
        (row,) = aliased["resources"]
        self.assertEqual(aliased["unregistered"], [])
        self.assertEqual({clock["status"] for clock in row["clocks"]}, {"current"})
        self.assertEqual(
            {clock["evidence"]["resourceId"] for clock in row["clocks"]}, {"lab-stem-01"}
        )


# *--- Order and options ---*


class CoverageOrderTests(CoverageFixture):
    def test_artifact_order_never_reaches_the_bytes(self) -> None:
        expected = self.reports["vdt"]
        orders: list[Sequence[Path]] = [tuple(reversed(self.artifacts))]
        orders += [(*order, *self.artifacts[3:]) for order in permutations(self.artifacts[:3])][1:3]
        for order in orders:
            with self.subTest(order=[path.name for path in order]):
                report = compile_fixtures(artifacts=order, inventory=self.inventory)
                self.assertEqual(report.to_json(), expected.to_json())
                self.assertEqual(report.to_markdown(), expected.to_markdown())

    def test_options_carry_the_inventory_and_stay_hashable(self) -> None:
        carried = options(inventory=self.inventory)
        self.assertIs(carried.inventory, self.inventory)
        self.assertEqual(hash(carried), hash(options(inventory=self.inventory)))
        self.assertIsNone(options().inventory)

    def test_options_refuse_anything_but_an_inventory(self) -> None:
        for value in ({}, INVENTORY_DOCUMENT, "inventory.json"):
            with (
                self.subTest(value=type(value).__name__),
                self.assertRaisesRegex(TypeError, "inventory must be an Inventory"),
            ):
                ReportOptions(
                    certification_class=CertificationClass.C,
                    package_uri="https://example.test/cpo",
                    as_of=AS_OF,
                    inventory=value,  # type: ignore[arg-type]
                )


if __name__ == "__main__":
    unittest.main()
