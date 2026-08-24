from __future__ import annotations

import hashlib
import tempfile
import unittest
from datetime import UTC, datetime
from pathlib import Path
from unittest import mock

from complyroll.adapters import ingest_stig_artifact, load_cci_control_map
from complyroll.adapters.stig import (
    CCI_PARSER_VERSION,
    CKL_PARSER_VERSION,
    CKLB_PARSER_VERSION,
    XCCDF_PARSER_VERSION,
    CklAdapter,
    CklbAdapter,
    XccdfAdapter,
)
from complyroll.models import ObservationDisposition

FIXTURES = Path(__file__).parent / "fixtures"
FIRST_INGEST = datetime(2026, 8, 18, 20, 0, tzinfo=UTC)
SECOND_INGEST = datetime(2026, 8, 19, 20, 0, tzinfo=UTC)

ARF_FIXTURE = FIXTURES / "openscap-arf.xml"
ARF_TEST_RESULT_ID = "xccdf_org.open-scap_testresult_xccdf_mil.synthetic.content_profile_stig"
# Identities the ARF fixture plants outside the TestResult so a root-scoped read is visible: the
# asset block's FQDN, and a CCI on a benchmark rule that sits in report-requests and was never
# evaluated. Neither may reach an observation.
ARF_ASSET_FQDN = "lab-rhel-03.synthetic.test"
ARF_UNEVALUATED_CCI = "CCI-002418"


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
        self.assertEqual(result.artifact.parser_name, "complyroll.cklb")
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
        self.assertEqual(result.artifact.parser_name, "complyroll.ckl")
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


class ArfAdapterTests(unittest.TestCase):
    """ARF is an advertised input, and its envelope is not a bare XCCDF file.

    The TestResult is nested inside arf:reports rather than being at the root, the collection
    root carries no id, and the asset identity in arf:assets is a different string from the
    xccdf:target the scan recorded. These tests pin which of those the adapter reads.
    """

    def test_arf_envelope_ingests_under_the_xccdf_parser_identity(self) -> None:
        result = ingest_stig_artifact(ARF_FIXTURE, ingested_at=FIRST_INGEST)

        self.assertTrue(result.successful)
        self.assertEqual(len(result.observations), 4)
        self.assertIsNotNone(result.artifact)
        assert result.artifact is not None
        self.assertEqual(result.artifact.parser_name, "complyroll.xccdf")
        self.assertEqual(result.artifact.parser_version, XCCDF_PARSER_VERSION)
        self.assertEqual(result.artifact.media_type, "application/xml")
        self.assertEqual(
            {(item.parser_name, item.parser_version) for item in result.observations},
            {("complyroll.xccdf", XCCDF_PARSER_VERSION)},
        )
        self.assertEqual({item.source_type for item in result.observations}, {"xccdf"})

    def test_arf_rule_results_are_read_from_the_nested_test_result(self) -> None:
        result = ingest_stig_artifact(ARF_FIXTURE, ingested_at=FIRST_INGEST)

        self.assertEqual(
            [item.source_record_id for item in result.observations],
            [
                "sshd_disable_root_login",
                "package_aide_installed",
                "banner_etc_issue",
                "audit_privileged_commands",
            ],
        )
        self.assertEqual(
            [item.disposition for item in result.observations],
            [
                ObservationDisposition.OPEN,
                ObservationDisposition.PASS,
                ObservationDisposition.NOT_APPLICABLE,
                ObservationDisposition.NOT_REVIEWED,
            ],
        )
        self.assertEqual(
            [item.source_severity.value for item in result.observations],
            ["high", "medium", "medium", "low"],
        )

    def test_arf_resource_identity_is_the_test_result_target(self) -> None:
        raw = ARF_FIXTURE.read_text(encoding="utf-8")
        self.assertIn(ARF_ASSET_FQDN, raw)

        result = ingest_stig_artifact(ARF_FIXTURE, ingested_at=FIRST_INGEST)

        self.assertEqual(
            {item.resource.resource_id for item in result.observations}, {"lab-rhel-03"}
        )
        self.assertNotIn(
            ARF_ASSET_FQDN, {item.resource.resource_id for item in result.observations}
        )
        self.assertNotIn(
            ARF_FIXTURE.stem, {item.resource.resource_id for item in result.observations}
        )
        self.assertNotIn("resource_identity_fallback", {item.code for item in result.warnings})

    def test_arf_identifiers_come_only_from_the_evaluated_rule_results(self) -> None:
        raw = ARF_FIXTURE.read_text(encoding="utf-8")
        self.assertIn(ARF_UNEVALUATED_CCI, raw)
        self.assertIn("CCE-90211-3", raw)

        result = ingest_stig_artifact(ARF_FIXTURE, ingested_at=FIRST_INGEST)

        self.assertEqual(
            [item.source_identifiers for item in result.observations],
            [("CCI-000770",), ("CCI-001744",), ("CCI-000048",), ()],
        )
        declared = {cci for item in result.observations for cci in item.source_identifiers}
        self.assertNotIn(ARF_UNEVALUATED_CCI, declared)

    def test_arf_timestamps_are_read_from_the_test_result_end_time(self) -> None:
        result = ingest_stig_artifact(ARF_FIXTURE, ingested_at=FIRST_INGEST)

        self.assertEqual(
            {item.observed_at for item in result.observations},
            {datetime(2026, 8, 1, 16, 12, tzinfo=UTC)},
        )
        self.assertNotIn("source_timestamp_missing", {item.code for item in result.warnings})

    def test_arf_context_key_omits_the_collection_envelope(self) -> None:
        arf = ingest_stig_artifact(ARF_FIXTURE, ingested_at=FIRST_INGEST)
        bare = ingest_stig_artifact(FIXTURES / "openscap-results.xml", ingested_at=FIRST_INGEST)

        self.assertEqual({item.context_key for item in arf.observations}, {ARF_TEST_RESULT_ID})
        self.assertEqual(
            {item.context_key for item in bare.observations},
            {"test|xccdf_org.open-scap_testresult_default"},
        )

    def test_arf_digest_and_identities_survive_a_second_ingest(self) -> None:
        expected_digest = hashlib.sha256(ARF_FIXTURE.read_bytes()).hexdigest()
        first = ingest_stig_artifact(ARF_FIXTURE, ingested_at=FIRST_INGEST)
        second = ingest_stig_artifact(ARF_FIXTURE, ingested_at=SECOND_INGEST)

        assert first.artifact is not None
        assert second.artifact is not None
        self.assertEqual(first.artifact.digest_sha256, expected_digest)
        self.assertEqual(second.artifact.digest_sha256, expected_digest)
        self.assertEqual(
            {item.source_artifact_digest for item in first.observations}, {expected_digest}
        )
        self.assertNotEqual(first.observations[0].ingested_at, second.observations[0].ingested_at)
        self.assertEqual(
            [item.observation_id for item in first.observations],
            [item.observation_id for item in second.observations],
        )

    def test_arf_suffix_is_accepted_and_does_not_change_observation_identity(self) -> None:
        reference = ingest_stig_artifact(ARF_FIXTURE, ingested_at=FIRST_INGEST)
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "scan.arf"
            path.write_bytes(ARF_FIXTURE.read_bytes())
            result = ingest_stig_artifact(path, ingested_at=FIRST_INGEST)

        self.assertTrue(result.successful)
        assert result.artifact is not None
        self.assertEqual(result.artifact.parser_name, "complyroll.xccdf")
        self.assertEqual(len(result.observations), 4)
        # The suffix routes the read; only the bytes carry identity, so renaming the same
        # artifact to the extension OpenSCAP emits cannot re-mint its observations.
        self.assertEqual(
            [item.observation_id for item in result.observations],
            [item.observation_id for item in reference.observations],
        )

    def test_arf_suffix_still_dispatches_by_root_element(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "legacy-checklist.arf"
            path.write_bytes((FIXTURES / "windows-host.ckl").read_bytes())
            result = ingest_stig_artifact(path, ingested_at=FIRST_INGEST)

        self.assertTrue(result.successful)
        assert result.artifact is not None
        self.assertEqual(result.artifact.parser_name, "complyroll.ckl")
        self.assertEqual(len(result.observations), 2)

    def test_malformed_arf_is_attributed_to_the_pre_dispatch_stage(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "truncated.arf"
            path.write_text("<arf:asset-report-collection", encoding="utf-8")
            result = ingest_stig_artifact(path, ingested_at=FIRST_INGEST)

        self.assertFalse(result.successful)
        assert result.artifact is not None
        self.assertEqual(result.artifact.parser_name, "complyroll.xml-auto")
        self.assertEqual(result.errors[0].code, "artifact_parse_failed")

    def test_asset_report_collection_without_a_test_result_is_a_failed_ingest(self) -> None:
        """An envelope carrying no XCCDF results must be a diagnosed failure, not a crash.

        Reaching the assertions at all proves no bare KeyError or AttributeError escaped, and
        `successful` being false proves an empty parse is not reported as a clean ingest.
        """

        payload = """<?xml version="1.0" encoding="UTF-8"?>
        <arf:asset-report-collection
            xmlns:arf="http://scap.nist.gov/schema/asset-reporting-format/1.1"
            xmlns:ai="http://scap.nist.gov/schema/asset-identification/1.1">
          <arf:assets>
            <arf:asset id="asset0">
              <ai:computing-device><ai:fqdn>lab-rhel-04.synthetic.test</ai:fqdn></ai:computing-device>
            </arf:asset>
          </arf:assets>
          <arf:reports>
            <arf:report id="oval0">
              <arf:content>
                <oval_results xmlns="http://oval.mitre.org/XMLSchema/oval-results-5"/>
              </arf:content>
            </arf:report>
          </arf:reports>
        </arf:asset-report-collection>"""
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "results-only-oval.arf"
            path.write_text(payload, encoding="utf-8")
            result = ingest_stig_artifact(path, ingested_at=FIRST_INGEST)

        self.assertFalse(result.successful)
        self.assertFalse(result.observations)
        self.assertIsNotNone(result.artifact)
        self.assertEqual([item.code for item in result.errors], ["no_observations"])
        self.assertIn("rule-result", result.errors[0].message)


class ParserVersionIndependenceTests(unittest.TestCase):
    """Each adapter owns its identity input, so one bump cannot re-mint the others."""

    def _versions(self, path: Path) -> set[str]:
        result = ingest_stig_artifact(path, ingested_at=FIRST_INGEST)
        self.assertTrue(result.successful)
        assert result.artifact is not None
        return {result.artifact.parser_version} | {
            item.parser_version for item in result.observations
        }

    def test_each_adapter_declares_its_own_constant(self) -> None:
        self.assertEqual(CklbAdapter.version, CKLB_PARSER_VERSION)
        self.assertEqual(CklAdapter.version, CKL_PARSER_VERSION)
        self.assertEqual(XccdfAdapter.version, XCCDF_PARSER_VERSION)

    def test_artifact_provenance_uses_the_adapter_version(self) -> None:
        self.assertEqual(self._versions(FIXTURES / "ubuntu-host.cklb"), {CKLB_PARSER_VERSION})
        self.assertEqual(self._versions(FIXTURES / "windows-host.ckl"), {CKL_PARSER_VERSION})
        self.assertEqual(
            self._versions(FIXTURES / "openscap-results.xml"), {XCCDF_PARSER_VERSION}
        )
        self.assertEqual(self._versions(ARF_FIXTURE), {XCCDF_PARSER_VERSION})

    def test_bumping_one_adapter_leaves_the_others_untouched(self) -> None:
        ckl_before = ingest_stig_artifact(
            FIXTURES / "windows-host.ckl", ingested_at=FIRST_INGEST
        )
        xccdf_before = ingest_stig_artifact(
            FIXTURES / "openscap-results.xml", ingested_at=FIRST_INGEST
        )

        with mock.patch.object(CklbAdapter, "version", "99"):
            cklb = ingest_stig_artifact(FIXTURES / "ubuntu-host.cklb", ingested_at=FIRST_INGEST)
            ckl_after = ingest_stig_artifact(
                FIXTURES / "windows-host.ckl", ingested_at=FIRST_INGEST
            )
            xccdf_after = ingest_stig_artifact(
                FIXTURES / "openscap-results.xml", ingested_at=FIRST_INGEST
            )

        self.assertTrue(all(item.parser_version == "99" for item in cklb.observations))
        self.assertEqual(
            [item.observation_id for item in ckl_before.observations],
            [item.observation_id for item in ckl_after.observations],
        )
        self.assertEqual(
            [item.observation_id for item in xccdf_before.observations],
            [item.observation_id for item in xccdf_after.observations],
        )

    def test_cci_loader_uses_its_own_parser_version(self) -> None:
        with mock.patch.object(CklbAdapter, "version", "99"):
            mapping_result = load_cci_control_map(
                FIXTURES / "cci-list.xml", ingested_at=FIRST_INGEST
            )

        self.assertTrue(mapping_result.successful)
        assert mapping_result.artifact is not None
        self.assertEqual(mapping_result.artifact.parser_version, CCI_PARSER_VERSION)


if __name__ == "__main__":
    unittest.main()
