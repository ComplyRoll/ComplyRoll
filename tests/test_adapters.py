from __future__ import annotations

import hashlib
import tempfile
import unittest
from datetime import UTC, datetime
from pathlib import Path

from trustroll.adapters import ingest_stig_artifact, load_cci_control_map
from trustroll.models import ObservationDisposition


FIXTURES = Path(__file__).parent / "fixtures"
FIRST_INGEST = datetime(2026, 8, 18, 20, 0, tzinfo=UTC)
SECOND_INGEST = datetime(2026, 8, 19, 20, 0, tzinfo=UTC)


class StigAdapterTests(unittest.TestCase):
    def test_cklb_ingest_records_provenance(self) -> None:
        path = FIXTURES / "ubuntu-host.cklb"
        result = ingest_stig_artifact(path, ingested_at=FIRST_INGEST)

        self.assertTrue(result.successful)
        self.assertEqual(len(result.observations), 6)
        self.assertIsNotNone(result.artifact)
        assert result.artifact is not None
        expected_digest = hashlib.sha256(path.read_bytes()).hexdigest()
        self.assertEqual(result.artifact.digest_sha256, expected_digest)
        self.assertEqual(result.artifact.parser_name, "trustroll.cklb")
        self.assertTrue(all(item.parser_version == "1" for item in result.observations))
        self.assertTrue(
            all(item.source_artifact_digest == expected_digest for item in result.observations)
        )
        self.assertTrue(
            all(item.resource.resource_id == "lab-ubuntu-01" for item in result.observations)
        )
        self.assertIn("source_timestamp_missing", {item.code for item in result.warnings})

    def test_ckl_and_xccdf_statuses_are_normalized(self) -> None:
        ckl = ingest_stig_artifact(FIXTURES / "windows-host.ckl", ingested_at=FIRST_INGEST)
        xccdf = ingest_stig_artifact(
            FIXTURES / "openscap-results.xml", ingested_at=FIRST_INGEST
        )

        self.assertTrue(ckl.successful)
        self.assertEqual(
            [item.disposition for item in ckl.observations],
            [ObservationDisposition.OPEN, ObservationDisposition.PASS],
        )
        self.assertTrue(xccdf.successful)
        self.assertEqual(len(xccdf.observations), 3)
        self.assertEqual(xccdf.observations[0].resource.resource_id, "lab-ubuntu-02")

    def test_xml_extension_is_dispatched_by_root_element(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "legacy-checklist.xml"
            path.write_bytes((FIXTURES / "windows-host.ckl").read_bytes())
            result = ingest_stig_artifact(path, ingested_at=FIRST_INGEST)

        self.assertTrue(result.successful)
        assert result.artifact is not None
        self.assertEqual(result.artifact.parser_name, "trustroll.ckl")
        self.assertEqual(len(result.observations), 2)

    def test_xccdf_declared_timestamp_is_preserved(self) -> None:
        payload = """<TestResult xmlns="http://checklists.nist.gov/xccdf/1.2"
            id="synthetic" end-time="2026-08-18T19:30:00Z">
          <target>synthetic-host</target>
          <rule-result idref="synthetic_rule_one" severity="low"><result>pass</result></rule-result>
        </TestResult>"""
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "timestamped.xml"
            path.write_text(payload, encoding="utf-8")
            result = ingest_stig_artifact(path, ingested_at=FIRST_INGEST)

        self.assertTrue(result.successful)
        self.assertEqual(
            result.observations[0].observed_at,
            datetime(2026, 8, 18, 19, 30, tzinfo=UTC),
        )
        self.assertNotIn("source_timestamp_missing", {item.code for item in result.warnings})

    def test_cci_revision_selection_does_not_revive_retired_mapping(self) -> None:
        mapping_result = load_cci_control_map(
            FIXTURES / "cci-list.xml", ingested_at=FIRST_INGEST
        )
        self.assertTrue(mapping_result.successful)
        assert mapping_result.mapping is not None
        self.assertEqual(mapping_result.mapping.controls_for("CCI-000366"), ("CM-6",))
        self.assertEqual(mapping_result.mapping.controls_for("CCI-000795"), ())
        self.assertEqual(mapping_result.mapping.controls_for("CCI-003627"), ("AC-2",))

    def test_cci_mapping_projects_controls_without_changing_observation(self) -> None:
        mapping_result = load_cci_control_map(
            FIXTURES / "cci-list.xml", ingested_at=FIRST_INGEST
        )
        assert mapping_result.mapping is not None
        result = ingest_stig_artifact(FIXTURES / "windows-host.ckl", ingested_at=FIRST_INGEST)
        self.assertEqual(result.observations[0].source_identifiers, ("CCI-000366",))
        controls = {
            control
            for cci in result.observations[0].source_identifiers
            for control in mapping_result.mapping.controls_for(cci)
        }
        self.assertEqual(controls, {"CM-6"})

    def test_reimport_of_identical_artifact_is_idempotent(self) -> None:
        path = FIXTURES / "ubuntu-host.cklb"
        first = ingest_stig_artifact(path, ingested_at=FIRST_INGEST)
        second = ingest_stig_artifact(path, ingested_at=SECOND_INGEST)

        self.assertNotEqual(first.observations[0].ingested_at, second.observations[0].ingested_at)
        self.assertEqual(
            [item.observation_id for item in first.observations],
            [item.observation_id for item in second.observations],
        )
        self.assertEqual(
            [item.fingerprint for item in first.observations],
            [item.fingerprint for item in second.observations],
        )

    def test_valid_json_with_wrong_shape_is_a_failed_ingest(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "wrong.cklb"
            path.write_text('{"message":"not a checklist"}', encoding="utf-8")
            result = ingest_stig_artifact(path, ingested_at=FIRST_INGEST)

        self.assertFalse(result.successful)
        self.assertFalse(result.observations)
        self.assertEqual(result.errors[0].code, "artifact_parse_failed")

    def test_duplicate_source_records_cannot_be_a_successful_ingest(self) -> None:
        payload = """{
          "target_data":{"host_name":"synthetic-host"},
          "stigs":[{"stig_name":"Synthetic STIG","rules":[
            {"group_id":"V-1","status":"open"},
            {"group_id":"V-1","status":"open"}
          ]}]
        }"""
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "duplicate.cklb"
            path.write_text(payload, encoding="utf-8")
            result = ingest_stig_artifact(path, ingested_at=FIRST_INGEST)

        self.assertFalse(result.successful)
        self.assertEqual(len(result.observations), 2)
        self.assertIn("duplicate_observation_identity", {item.code for item in result.errors})

    def test_unsupported_file_is_a_failed_ingest_with_digest(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "scan.txt"
            path.write_text("synthetic", encoding="utf-8")
            result = ingest_stig_artifact(path, ingested_at=FIRST_INGEST)

        self.assertFalse(result.successful)
        self.assertIsNotNone(result.artifact)
        self.assertEqual(result.errors[0].code, "unsupported_artifact")


if __name__ == "__main__":
    unittest.main()
