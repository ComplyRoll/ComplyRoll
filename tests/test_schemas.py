from __future__ import annotations

import copy
import hashlib
import json
import tempfile
import unittest
from dataclasses import replace
from pathlib import Path

from complyroll.schemas import (
    COMMON_DEFINITIONS_NAME,
    ReportDocumentError,
    ReportSchema,
    ReportSchemaValidationError,
    SchemaDefinitionError,
    SchemaIntegrityError,
    SchemaManifestEntry,
    SchemaResolutionError,
    load_bundled_schema_bundle,
    load_bundled_schema_manifest,
    load_schema_bundle,
    validate_bundled_report,
    validate_bundled_report_bytes,
    validate_report,
)


TEST_ROOT = Path(__file__).parent
GOLDEN = TEST_ROOT / "golden" / "ver-schema-examples.json"
SCHEMA_COMMIT = "ae43ae2952c5dd5c56d54d12e8b92c7db1b3710a"


class SchemaSourceTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.bundle = load_bundled_schema_bundle()

    def test_manifest_pins_the_official_schema_repository_and_versions(self) -> None:
        manifest = load_bundled_schema_manifest()

        self.assertEqual(manifest.repository, "https://github.com/FedRAMP/schemas")
        self.assertEqual(manifest.commit, SCHEMA_COMMIT)
        self.assertEqual(
            {entry.name: entry.version for entry in manifest.schemas},
            {
                COMMON_DEFINITIONS_NAME: "0.2.1",
                ReportSchema.VULNERABILITY_DETAIL.value: "0.1.1",
                ReportSchema.ACCEPTED_VULNERABILITY.value: "0.1.1",
                ReportSchema.HISTORICAL_ACTIVITY.value: "0.1.1",
            },
        )

    def test_bundle_verifies_all_digests_metadata_and_references(self) -> None:
        self.assertEqual(len(self.bundle.documents), 4)
        for document in self.bundle.documents:
            self.assertEqual(document.content_sha256, document.entry.sha256)
            self.assertEqual(document.schema["$id"], document.entry.schema_id)
            self.assertEqual(document.schema["$schemaVersion"], document.entry.version)

    def test_schema_objects_are_defensively_reparsed(self) -> None:
        document = self.bundle.document(COMMON_DEFINITIONS_NAME)
        changed = document.schema
        changed["$schemaVersion"] = "caller mutation"

        self.assertEqual(document.schema["$schemaVersion"], document.entry.version)

    def test_manifest_entry_rejects_parent_path_traversal(self) -> None:
        entry = self.bundle.manifest.schemas[0]
        value = {
            "name": entry.name,
            "path": "../outside.json",
            "id": entry.schema_id,
            "version": entry.version,
            "sha256": entry.sha256,
        }

        with self.assertRaisesRegex(ValueError, "repository-relative"):
            SchemaManifestEntry.from_dict(value, 0)

    def test_digest_mismatch_blocks_bundle_loading(self) -> None:
        with tempfile.TemporaryDirectory() as directory_name:
            directory = Path(directory_name)
            self._write_bundle(directory)
            target = directory / self.bundle.manifest.schemas[0].path
            target.write_bytes(target.read_bytes() + b"\n")

            with self.assertRaisesRegex(SchemaIntegrityError, "SHA-256"):
                load_schema_bundle(directory, self.bundle.manifest)

    def test_metadata_mismatch_blocks_bundle_loading(self) -> None:
        with tempfile.TemporaryDirectory() as directory_name:
            directory = Path(directory_name)
            self._write_bundle(directory)
            entry = self.bundle.manifest.entry(ReportSchema.VULNERABILITY_DETAIL.value)
            value = json.loads((directory / entry.path).read_text(encoding="utf-8"))
            value["$schemaVersion"] = "9.9.9"
            manifest = self._write_changed_schema(directory, entry.name, value)

            with self.assertRaisesRegex(SchemaIntegrityError, "version"):
                load_schema_bundle(directory, manifest)

    def test_invalid_schema_definition_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as directory_name:
            directory = Path(directory_name)
            self._write_bundle(directory)
            entry = self.bundle.manifest.entry(COMMON_DEFINITIONS_NAME)
            value = json.loads((directory / entry.path).read_text(encoding="utf-8"))
            value["$defs"]["nRating"]["type"] = "not-a-json-schema-type"
            manifest = self._write_changed_schema(directory, entry.name, value)

            with self.assertRaisesRegex(SchemaDefinitionError, "Draft 2020-12"):
                load_schema_bundle(directory, manifest)

    def test_unbundled_reference_fails_without_network_retrieval(self) -> None:
        with tempfile.TemporaryDirectory() as directory_name:
            directory = Path(directory_name)
            self._write_bundle(directory)
            entry = self.bundle.manifest.entry(ReportSchema.VULNERABILITY_DETAIL.value)
            value = json.loads((directory / entry.path).read_text(encoding="utf-8"))
            value["properties"]["reportPeriod"]["$ref"] = (
                "https://example.invalid/unbundled-schema.json#/$defs/reportPeriod"
            )
            manifest = self._write_changed_schema(directory, entry.name, value)

            with self.assertRaisesRegex(SchemaResolutionError, "offline-unresolvable"):
                load_schema_bundle(directory, manifest)

    def _write_bundle(self, directory: Path) -> None:
        for document in self.bundle.documents:
            (directory / document.entry.path).write_bytes(document.content)

    def _write_changed_schema(
        self,
        directory: Path,
        name: str,
        value: dict[str, object],
    ):
        entry = self.bundle.manifest.entry(name)
        content = (json.dumps(value, ensure_ascii=False, indent=2) + "\n").encode("utf-8")
        (directory / entry.path).write_bytes(content)
        changed_entry = replace(entry, sha256=hashlib.sha256(content).hexdigest())
        schemas = tuple(
            changed_entry if current.name == name else current
            for current in self.bundle.manifest.schemas
        )
        return replace(self.bundle.manifest, schemas=schemas)


class ReportValidationTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.bundle = load_bundled_schema_bundle()
        cls.examples = json.loads(GOLDEN.read_text(encoding="utf-8"))

    def test_all_golden_ver_documents_are_valid(self) -> None:
        for report_schema in ReportSchema:
            with self.subTest(schema=report_schema.value):
                result = validate_report(
                    self.bundle,
                    report_schema,
                    self.examples[report_schema.value],
                )
                self.assertTrue(result.is_valid)
                self.assertEqual(result.issues, ())
                self.assertEqual(result.provenance.commit, SCHEMA_COMMIT)
                self.assertEqual(
                    result.provenance.schema_sha256,
                    self.bundle.document(report_schema.value).content_sha256,
                )

    def test_official_schema_allows_provider_extensions(self) -> None:
        result = validate_bundled_report(
            ReportSchema.VULNERABILITY_DETAIL,
            self.examples[ReportSchema.VULNERABILITY_DETAIL.value],
        )

        self.assertTrue(result.is_valid)

    def test_nested_errors_have_actionable_json_pointers(self) -> None:
        instance = copy.deepcopy(self.examples[ReportSchema.VULNERABILITY_DETAIL.value])
        vulnerability = instance["vulnerabilities"][0]
        del vulnerability["detection"]["detectionSource"]
        vulnerability["currentRating"] = 6

        result = validate_report(self.bundle, ReportSchema.VULNERABILITY_DETAIL, instance)

        self.assertFalse(result.is_valid)
        self.assertEqual(
            {issue.instance_pointer for issue in result.issues},
            {
                "/vulnerabilities/0/currentRating",
                "/vulnerabilities/0/detection",
            },
        )
        self.assertEqual({issue.validator for issue in result.issues}, {"enum", "required"})

    def test_uri_and_datetime_formats_are_enforced(self) -> None:
        instance = copy.deepcopy(self.examples[ReportSchema.VULNERABILITY_DETAIL.value])
        instance["certificationPackageOverviewUri"] = "not a URI"
        instance["vulnerabilities"][0]["detection"]["detectedAt"] = "August 20"

        result = validate_report(self.bundle, ReportSchema.VULNERABILITY_DETAIL, instance)

        self.assertEqual(len(result.issues), 2)
        self.assertEqual({issue.validator for issue in result.issues}, {"format"})

    def test_invalid_result_can_raise_one_domain_error(self) -> None:
        result = validate_report(self.bundle, ReportSchema.VULNERABILITY_DETAIL, {})

        with self.assertRaisesRegex(
            ReportSchemaValidationError,
            "vulnerability-detail schema validation",
        ):
            result.raise_for_errors()

    def test_raw_report_json_rejects_duplicate_keys(self) -> None:
        content = b'{"vulnerabilities":[],"vulnerabilities":[]}'

        with self.assertRaisesRegex(ReportDocumentError, "duplicate JSON object key"):
            validate_bundled_report_bytes(ReportSchema.VULNERABILITY_DETAIL, content)


if __name__ == "__main__":
    unittest.main()
