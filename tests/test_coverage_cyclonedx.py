# ******************************************************************************
# *Title: CycloneDX Coverage Tests*
# *Author: Kyle Versluis*
# *Description: Coverage and inventory behavior for CycloneDX SBOM evidence.*
# ******************************************************************************
"""Tests for CycloneDX scope evidence against the inventory (ADR 0016, plan section 15)."""

# *--- Imports ---*

from __future__ import annotations

import json
import tempfile
import unittest
from collections.abc import Iterable
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from test_coverage import DAY, SINCE, host, inventory_document, observation, policy

from complyroll.adapters import ingest_stig_artifact
from complyroll.adapters.cyclonedx import CYCLONEDX_SOURCE_TYPE as ADAPTER_SOURCE_TYPE
from complyroll.adapters.cyclonedx import PACKAGE_RESOURCE_TYPE as ADAPTER_PACKAGE_TYPE
from complyroll.adapters.cyclonedx import SCOPE_RECORD_ID as ADAPTER_SCOPE_RECORD_ID
from complyroll.models import Observation, ObservationDisposition, ResourceRef
from complyroll.reports import Inventory, ReportInputError, load_inventory, parse_inventory
from complyroll.reports import coverage as coverage_module
from complyroll.reports import inventory as inventory_module
from complyroll.reports.coverage import (
    MVX_RULE,
    PDD_RULE,
    CoverageResult,
    CoverageStatus,
    EvidenceKind,
    ResourceCoverage,
    UnregisteredResource,
    derive_coverage,
    verifying_evidence,
)

# *--- Fixtures ---*

FIXTURES = Path(__file__).parent / "fixtures"
INVENTORY = FIXTURES / "inventory-cyclonedx.json"
#: The golden run's documents, one of each kind the plan's section 15 table names.
TIMED_K1 = "syft-image.cdx.json"
UNTIMED_K1 = "syft-untimed.cdx.json"
K2 = "grype-clean.cdx.json"
K3 = "trivy-image.cdx.json"
CORNERS = "cyclonedx-spec-corners.cdx.json"
DOCUMENTS = (TIMED_K1, UNTIMED_K1, K2, K3, CORNERS)

WEB = "registry.example.test/web:1.4"
WORKER = "registry.example.test/worker:3.0"
BATCH = "registry.example.test/batch:5.2"
API = "registry.example.test/api:2.1"
UNTAGGED_API = "registry.example.test/api"

AS_OF = datetime(2026, 10, 3, 12, tzinfo=UTC)
K3_AT = datetime(2026, 10, 1, 12, tzinfo=UTC)
#: Ingest time sits after every instant here, so a substituted one would show.
INGESTED_AT = datetime(2026, 10, 10, tzinfo=UTC)

#: E5: inventory refusals carry fixed text and no code.
PACKAGE_REFUSAL = (
    "resourceType package is not an information resource; inventory the image or host that "
    "carries it"
)


def ingest(path: Path) -> list[Observation]:
    result = ingest_stig_artifact(path, ingested_at=INGESTED_AT)
    assert result.artifact is not None and not result.withheld, result.diagnostics
    return list(result.observations)


def observations(names: Iterable[str] = DOCUMENTS) -> list[Observation]:
    return [item for name in names for item in ingest(FIXTURES / name)]


def scope_of(found: Iterable[Observation], resource_id: str) -> Observation:
    (scope,) = [
        item
        for item in found
        if item.source_record_id == "cyclonedx.bom" and item.resource.resource_id == resource_id
    ]
    return scope


def derive(found: list[Observation], inventory: Inventory | None = None) -> CoverageResult:
    return derive_coverage(found, inventory or load_inventory(INVENTORY), policy("C"), AS_OF)


def resource_of(result: CoverageResult, resource_id: str) -> ResourceCoverage:
    ref = ResourceRef(resource_id=resource_id, resource_type="image")
    (found,) = [item for item in result.resources if item.entry.ref == ref]
    return found


def statuses(result: CoverageResult, resource_id: str) -> dict[str, CoverageStatus]:
    return {clock.key.rule_id: clock.status for clock in resource_of(result, resource_id).clocks}


def image_entry(resource_id: str, **fields: Any) -> dict[str, Any]:
    entry = {
        "resourceType": "image",
        "resourceId": resource_id,
        "machineBased": True,
        "driftLikely": True,
        "expectedSince": "2026-09-01T00:00:00Z",
    }
    entry.update(fields)
    return entry


def renamed_k3(name: str) -> list[Observation]:
    """Ingest the K3 fixture with its subject renamed, written beside no other file."""
    document = json.loads((FIXTURES / K3).read_text(encoding="utf-8"))
    document["metadata"]["component"]["name"] = name
    with tempfile.TemporaryDirectory() as directory:
        path = Path(directory) / "renamed.cdx.json"
        path.write_text(json.dumps(document), encoding="utf-8")
        return ingest(path)


# *--- Fixture Statuses ---*


class FixtureStatusTests(unittest.TestCase):
    """The golden run's documents, read through the library: section 15's table row by row."""

    @classmethod
    def setUpClass(cls) -> None:
        cls.found = observations()
        cls.result = derive(cls.found)

    def test_the_k2_image_is_examined_and_undetermined(self) -> None:
        # A1: an empty match list from a named tool never verifies a clock.
        scope = scope_of(self.found, BATCH)
        self.assertIs(scope.disposition, ObservationDisposition.NOT_REVIEWED)
        resource = resource_of(self.result, BATCH)
        self.assertEqual(resource.examined_observations, 1)
        self.assertIsNone(resource.last_verified)
        self.assertEqual(
            statuses(self.result, BATCH),
            {MVX_RULE: CoverageStatus.UNDETERMINED, PDD_RULE: CoverageStatus.UNDETERMINED},
        )

    def test_the_timed_k1_image_is_examined_and_undetermined(self) -> None:
        scope = scope_of(self.found, WEB)
        self.assertIs(scope.disposition, ObservationDisposition.NOT_REVIEWED)
        self.assertIsNotNone(scope.observed_at)
        resource = resource_of(self.result, WEB)
        self.assertEqual(resource.examined_observations, 1)
        self.assertIsNone(resource.last_verified)
        self.assertEqual(
            statuses(self.result, WEB),
            {MVX_RULE: CoverageStatus.UNDETERMINED, PDD_RULE: CoverageStatus.UNDETERMINED},
        )

    def test_the_untimed_k1_image_reads_missing(self) -> None:
        # A18: untimed evidence never examines, so an entry only it reaches is missing.
        scope = scope_of(self.found, WORKER)
        self.assertIsNone(scope.observed_at)
        resource = resource_of(self.result, WORKER)
        self.assertEqual(resource.examined_observations, 0)
        self.assertIsNone(resource.last_examined)
        self.assertEqual([item.reference for item in resource.untimed], [scope.observation_id])
        self.assertEqual(
            statuses(self.result, WORKER),
            {MVX_RULE: CoverageStatus.MISSING, PDD_RULE: CoverageStatus.MISSING},
        )

    def test_the_k3_image_is_verified_by_its_pass_scope(self) -> None:
        scope = scope_of(self.found, API)
        self.assertIs(scope.disposition, ObservationDisposition.PASS)
        resource = resource_of(self.result, API)
        self.assertEqual(resource.last_verified, K3_AT)
        self.assertEqual(
            statuses(self.result, API),
            {MVX_RULE: CoverageStatus.CURRENT, PDD_RULE: CoverageStatus.CURRENT},
        )
        for clock in resource.clocks:
            assert clock.evidence is not None
            self.assertEqual(clock.evidence.reference, scope.observation_id)

    def test_no_package_reads_as_unregistered_and_the_scan_subject_does(self) -> None:
        packages = [
            item for item in self.found if item.resource.resource_type == ADAPTER_PACKAGE_TYPE
        ]
        # Not vacuous: the K3 and spec-corners documents mint package findings, `ref:` too.
        self.assertGreater(len(packages), 10)
        self.assertTrue(any("|ref:" in item.resource.resource_id for item in packages))
        corner = [item for item in self.found if item.resource == ResourceRef("corner-app", "scan")]
        self.assertEqual(
            self.result.unregistered,
            (UnregisteredResource(ResourceRef("corner-app", "scan"), len(corner)),),
        )
        self.assertEqual(self.result.later, ())


# *--- Verifying Evidence ---*


class VerifyingEvidenceTests(unittest.TestCase):
    """`verifying_evidence` files the scope observation as `derive_coverage` does."""

    @classmethod
    def setUpClass(cls) -> None:
        cls.found = observations()
        cls.inventory = load_inventory(INVENTORY)

    def evidence(self, resource_id: str, rule_id: str = MVX_RULE) -> list[str]:
        subject = ResourceRef(resource_id=resource_id, resource_type="image")
        found = verifying_evidence(
            self.found, self.inventory, AS_OF, rule_id=rule_id, subject=subject
        )
        self.assertTrue(all(item.kind is EvidenceKind.OBSERVATION for item in found))
        return [item.reference for item in found]

    def test_the_k3_pass_scope_is_the_verifying_evidence(self) -> None:
        scope = scope_of(self.found, API)
        for rule_id in (MVX_RULE, PDD_RULE):
            with self.subTest(rule_id=rule_id):
                self.assertEqual(self.evidence(API, rule_id), [scope.observation_id])

    def test_k1_and_k2_scopes_verify_nothing(self) -> None:
        for resource_id in (WEB, BATCH, WORKER):
            with self.subTest(resource_id=resource_id):
                self.assertEqual(self.evidence(resource_id), [])


# *--- Package Skip ---*


class PackageSkipTests(unittest.TestCase):
    """A package observation is a component of its subject and is filed nowhere."""

    def test_the_skip_literal_is_the_adapters(self) -> None:
        self.assertEqual(coverage_module.PACKAGE_RESOURCE_TYPE, "package")
        self.assertEqual(coverage_module.PACKAGE_RESOURCE_TYPE, ADAPTER_PACKAGE_TYPE)
        self.assertEqual(inventory_module.PACKAGE_RESOURCE_TYPE, ADAPTER_PACKAGE_TYPE)

    def test_a_package_observation_is_not_unregistered_untimed_or_later(self) -> None:
        at = SINCE + DAY
        evidence = [
            observation("image:web|pkg:npm/a", at=at, resource_type="package"),
            observation("image:web|pkg:npm/b", at=None, resource_type="package"),
            observation("image:web|pkg:npm/c", at=at + DAY, resource_type="package"),
            observation("lab-01", at=at, resource_type="package"),
        ]
        result = derive_coverage(
            evidence, parse_inventory(inventory_document(host())), policy(), at
        )
        self.assertEqual(result.unregistered, ())
        self.assertEqual(result.later, ())
        (resource,) = result.resources
        self.assertEqual(resource.examined_observations, 0)
        self.assertEqual(resource.untimed, ())

    def test_only_the_exact_package_type_is_skipped(self) -> None:
        # The vocabulary is open and case-sensitive, so a near spelling is still listed.
        at = SINCE + DAY
        evidence = [
            observation("stray", at=at, resource_type=resource_type)
            for resource_type in ("host", "image", "Package", "packages")
        ]
        evidence.append(observation("lab-01", at=at))
        result = derive_coverage(
            evidence, parse_inventory(inventory_document(host())), policy(), at
        )
        self.assertEqual(
            {item.resource.resource_type for item in result.unregistered},
            {"host", "image", "Package", "packages"},
        )
        (resource,) = result.resources
        self.assertEqual(resource.examined_observations, 1)


# *--- Aliases and Long Ids ---*


class ScopeMatchingTests(unittest.TestCase):
    """A scope id reaches its entry by id or alias, at any length the adapter can emit."""

    def test_an_untagged_image_name_reaches_a_tagged_entry_through_an_alias(self) -> None:
        found = renamed_k3(UNTAGGED_API)
        scope = scope_of(found, UNTAGGED_API)
        self.assertEqual(scope.resource, ResourceRef(UNTAGGED_API, "image"))
        alias = {"resourceType": "image", "resourceId": UNTAGGED_API}

        without = derive(found, parse_inventory(inventory_document(image_entry(API))))
        self.assertEqual(
            without.unregistered, (UnregisteredResource(ResourceRef(UNTAGGED_API, "image"), 1),)
        )
        self.assertEqual(statuses(without, API)[MVX_RULE], CoverageStatus.MISSING)

        entry = image_entry(API, aliases=[alias])
        result = derive(found, parse_inventory(inventory_document(entry)))
        self.assertEqual(result.unregistered, ())
        self.assertEqual(statuses(result, API)[MVX_RULE], CoverageStatus.CURRENT)
        evidence = resource_of(result, API).clocks[0].evidence
        assert evidence is not None
        self.assertEqual(evidence.reference, scope.observation_id)
        self.assertEqual(evidence.resource, ResourceRef(UNTAGGED_API, "image"))

    def test_a_300_character_scope_id_registers_and_matches_its_entry(self) -> None:
        # S1: resourceId takes the 512 identity cap, so every scope id the adapter emits
        # registers; A25's "over 128 reads unregistered" was wrong.
        prefix = "registry.example.test/"
        name = prefix + "a" * (300 - len(prefix) - len(":2.1")) + ":2.1"
        self.assertEqual(len(name), 300)
        found = renamed_k3(name)
        scope_of(found, name)
        inventory = parse_inventory(inventory_document(image_entry(name)))
        self.assertEqual(inventory.entries[0].resource_id, name)

        result = derive(found, inventory)
        self.assertEqual(result.unregistered, ())
        self.assertEqual(statuses(result, name)[MVX_RULE], CoverageStatus.CURRENT)


# *--- Inventory Refusal ---*


class PackageRefusalTests(unittest.TestCase):
    """The inventory refuses `package` as an entry type and as an alias type (E5)."""

    def assert_refused(self, entry: dict[str, Any], where: str) -> None:
        content = inventory_document(entry)
        expected = f"inventory {where}: {PACKAGE_REFUSAL}"
        with self.assertRaises(ReportInputError) as parsed:
            parse_inventory(content)
        self.assertEqual(str(parsed.exception), expected)
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "inventory.json"
            path.write_bytes(content)
            with self.assertRaises(ReportInputError) as loaded:
                load_inventory(path)
        self.assertEqual(str(loaded.exception), expected)

    def test_an_entry_of_type_package_is_refused(self) -> None:
        self.assert_refused(image_entry(API, resourceType="package"), "resources[0]")

    def test_an_alias_of_type_package_is_refused(self) -> None:
        alias = {"resourceType": "package", "resourceId": f"image:{API}|pkg:npm/a"}
        self.assert_refused(image_entry(API, aliases=[alias]), "resources[0].aliases[0]")

    def test_other_spellings_stay_open(self) -> None:
        for resource_type in ("Package", "packages", "pkg", "image"):
            with self.subTest(resource_type=resource_type):
                alias = {"resourceType": resource_type, "resourceId": "other"}
                entry = image_entry(API, resourceType=resource_type, aliases=[alias])
                (read,) = parse_inventory(inventory_document(entry)).entries
                self.assertEqual(read.resource_type, resource_type)


# *--- Scope-Only Evidence (FX F1) ---*

AUDIT = "registry.example.test/audit:1.0"
AUDIT_AT = datetime(2026, 10, 1, 12, tzinfo=UTC)
CYCLONEDX_SCOPE = "cyclonedx.bom"


def audit_document(affects: list[dict[str, str]] | None) -> dict[str, Any]:
    """Build a grype K3 document on the audit image; None leaves its record without affects."""
    record: dict[str, Any] = {"id": "CVE-2026-0001"}
    if affects is not None:
        record["affects"] = affects
    return {
        "bomFormat": "CycloneDX",
        "specVersion": "1.6",
        "version": 1,
        "metadata": {
            "timestamp": "2026-10-01T12:00:00Z",
            "tools": [{"name": "grype", "version": "0.99.0"}],
            "component": {
                "type": "container",
                "name": "registry.example.test/audit",
                "version": "1.0",
                "bom-ref": "subject",
            },
        },
        "components": [
            {
                "type": "library",
                "name": "lodash",
                "version": "4.17.20",
                "purl": "pkg:npm/lodash@4.17.20",
                "bom-ref": "lodash-ref",
            }
        ],
        "vulnerabilities": [record],
    }


def ingest_document(document: dict[str, Any]) -> list[Observation]:
    with tempfile.TemporaryDirectory() as directory:
        path = Path(directory) / "audit.cdx.json"
        path.write_text(json.dumps(document), encoding="utf-8")
        return ingest(path)


class ScopeOnlyEvidenceTests(unittest.TestCase):
    """FX F1: a cyclonedx source contributes only its scope record to coverage (section 15)."""

    #: The audit's two reproductions, each a row on the scope resource beside a non-PASS scope.
    SCOPE_ROWS = {"no affects": None, "subject only": [{"ref": "subject"}]}

    def inventory(self) -> Inventory:
        return parse_inventory(inventory_document(image_entry(AUDIT)))

    def coverage(self, found: list[Observation], as_of: datetime = AS_OF) -> CoverageResult:
        return derive_coverage(found, self.inventory(), policy("C"), as_of)

    def test_the_literals_are_the_adapters(self) -> None:
        self.assertEqual(coverage_module.CYCLONEDX_SOURCE_TYPE, "cyclonedx")
        self.assertEqual(coverage_module.CYCLONEDX_SOURCE_TYPE, ADAPTER_SOURCE_TYPE)
        self.assertEqual(coverage_module.CYCLONEDX_SCOPE_RECORD_ID, "cyclonedx.bom")
        self.assertEqual(coverage_module.CYCLONEDX_SCOPE_RECORD_ID, ADAPTER_SCOPE_RECORD_ID)

    def test_an_open_row_on_the_scope_resource_never_verifies_it(self) -> None:
        for name, affects in self.SCOPE_ROWS.items():
            with self.subTest(name):
                found = ingest_document(audit_document(affects))
                row = [item for item in found if item.source_record_id == "CVE-2026-0001"]
                self.assertEqual([item.resource.resource_id for item in row], [AUDIT])
                self.assertIs(row[0].disposition, ObservationDisposition.OPEN)
                scope = scope_of(found, AUDIT)
                self.assertIs(scope.disposition, ObservationDisposition.NOT_REVIEWED)
                resource = resource_of(self.coverage(found), AUDIT)
                self.assertEqual(
                    statuses(self.coverage(found), AUDIT),
                    {MVX_RULE: CoverageStatus.UNDETERMINED, PDD_RULE: CoverageStatus.UNDETERMINED},
                )
                self.assertEqual(resource.examined_observations, 1)
                subject = ResourceRef(resource_id=AUDIT, resource_type="image")
                self.assertEqual(
                    verifying_evidence(
                        found, self.inventory(), AS_OF, rule_id=MVX_RULE, subject=subject
                    ),
                    (),
                )

    def test_a_listed_component_ref_still_verifies_through_the_scope(self) -> None:
        found = ingest_document(audit_document([{"ref": "lodash-ref"}]))
        result = self.coverage(found)
        self.assertEqual(statuses(result, AUDIT)[MVX_RULE], CoverageStatus.CURRENT)
        self.assertEqual(resource_of(result, AUDIT).last_verified, AUDIT_AT)

    def test_a_row_still_counts_its_unregistered_resource(self) -> None:
        # The reading kept: the observed-resource count is unchanged, so the spec-corners scan
        # subject reads unregistered with every observation on it, as the step 4 golden shows.
        found = ingest_document(audit_document(None))
        result = derive_coverage(
            found, parse_inventory(inventory_document(host())), policy("C"), AS_OF
        )
        self.assertEqual(
            result.unregistered,
            (UnregisteredResource(ResourceRef(AUDIT, "image"), 2),),
        )

    def test_a_row_past_the_cutoff_is_not_later_evidence(self) -> None:
        found = ingest_document(audit_document(None))
        result = self.coverage(found, AUDIT_AT - DAY)
        self.assertEqual(
            [item.reference for item in result.later], [scope_of(found, AUDIT).observation_id]
        )

    def test_a_producer_record_named_like_the_scope_never_verifies(self) -> None:
        # E1: a producer record with the scope's id supersedes the scope and is OPEN; it
        # examines the image and never verifies it, whatever its disposition.
        document = audit_document(None)
        document["vulnerabilities"][0]["id"] = CYCLONEDX_SCOPE
        found = ingest_document(document)
        (record,) = [item for item in found if item.source_record_id == CYCLONEDX_SCOPE]
        self.assertIs(record.disposition, ObservationDisposition.OPEN)
        self.assertEqual(record.resource.resource_id, AUDIT)
        result = self.coverage(found)
        self.assertEqual(
            statuses(result, AUDIT),
            {MVX_RULE: CoverageStatus.UNDETERMINED, PDD_RULE: CoverageStatus.UNDETERMINED},
        )
        self.assertEqual(resource_of(result, AUDIT).examined_observations, 1)
        subject = ResourceRef(resource_id=AUDIT, resource_type="image")
        self.assertEqual(
            verifying_evidence(found, self.inventory(), AS_OF, rule_id=MVX_RULE, subject=subject),
            (),
        )


if __name__ == "__main__":
    unittest.main()
