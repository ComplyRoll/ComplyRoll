from __future__ import annotations

import hashlib
import tempfile
import unittest
from datetime import UTC, datetime
from pathlib import Path
from typing import Any
from unittest import mock

from complyroll import adapters
from complyroll.adapters import (
    SARIF_PARSER_VERSION,
    ArtifactProvenance,
    IngestResult,
    SarifAdapter,
    common,
    ingest_stig_artifact,
    load_cci_control_map,
    sarif,
    stig,
)
from complyroll.adapters.sarif import SARIF_MEDIA_TYPE
from complyroll.adapters.stig import (
    CCI_PARSER_VERSION,
    CKL_PARSER_VERSION,
    CKLB_PARSER_VERSION,
    XCCDF_PARSER_VERSION,
    CklAdapter,
    CklbAdapter,
    XccdfAdapter,
)
from complyroll.models import ObservationDisposition, SourceSeverity

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

SARIF_FIXTURE = FIXTURES / "trivy-image.sarif"
SARIF_ATTRIBUTION = ("complyroll.sarif", SARIF_PARSER_VERSION, SARIF_MEDIA_TYPE)
# The CKLB adapter's verdict on a SARIF log reaching it under a bare .json name. Dispatch is
# by suffix alone (ADR 0011, decision 20), so the bytes are never sniffed toward SARIF.
CKLB_SHAPE_MESSAGE = "JSON has no non-empty 'stigs' array"

# Observation ids of every STIG fixture, recorded before the shared helpers moved from
# stig.py to adapters/common.py (ADR 0011, decision 18). The goldens prove the move changed
# nothing; this table names it.
BASELINE_OBSERVATION_IDS = {
    "ubuntu-host.cklb": (
        "obs-f841f4f0e47c5d8710658d433ee82715d679f7a5cfbd9afb4a4e216688ad3926",
        "obs-6cdf3ee1f2fa3cf51ea8aac1cc05c8534ec5e56d8398edd559ef5f226b68a674",
        "obs-1577127e3e0aaa0b19f428f196a0d90407c3cb1be1864738f30fd1b64470d7f9",
        "obs-49da1ef09ba9877e9ad9885dbcba70198a805e64f64c4578e0e1b77bba33a4b1",
        "obs-7876b3a041cd260c9987490da7e6d6dd370be17ac84dddc3c7a748ca0e4e98c0",
        "obs-dd8f546726ab5b2cb9a096254bd3679185ca8f2cd10045dd7de289ad5553e5d6",
    ),
    "windows-host.ckl": (
        "obs-6e3d196cb5f895fecc7d879eac03f954de2d99f46fdd0bccc11d8f0e88a66dc4",
        "obs-57e96b5e68e7278977ebf3eaed197fb61c24c7cea52fffb6e4b96ead1a08c660",
    ),
    "openscap-results.xml": (
        "obs-c1a949d8bba45d81b6badd35b2a1c985370d60f37503e3ddf5c79e07ed45e883",
        "obs-12dec8db9923fa7e3ffd7ac81ee7b5db79b14ffa798fa54cd71520af681d097c",
        "obs-9d9083ec3329bc5beea5a41c62fb26a19048cbeba1e2c7dc2c7f1e63a081fb21",
    ),
    "openscap-arf.xml": (
        "obs-e5ffbbd34cb4eadda6c3598f81e37547a5d8c376cb06fb5da20468a64ef2c7fe",
        "obs-4cda4500eaae09c458a2a9ddcaaaab5e28dff7a68242ebe88158e2f0079254cc",
        "obs-2b646b2a92c575e1a2969a3829a0782b4ef63880bc9379e1353166b1653b2a52",
        "obs-0eb1fba3936a5aead6c964be06697e134ce6a414bcde9187a81c3c856c4b6709",
    ),
}

SYNTHETIC_ARTIFACT = ArtifactProvenance.from_bytes(
    path=Path("synthetic.cklb"),
    content=b'{"stigs":[]}',
    media_type="application/json",
    parser_name="complyroll.cklb",
    parser_version=CKLB_PARSER_VERSION,
    ingested_at=FIRST_INGEST,
)
SYNTHETIC_FIELDS: dict[str, Any] = {
    "artifact": SYNTHETIC_ARTIFACT,
    "source_type": "cklb",
    "source_tool": "Synthetic STIG",
    "source_record_id": "V-1",
    "resource_id": "lab-synthetic",
    "observed_at": None,
    "ingested_at": FIRST_INGEST,
    "disposition": ObservationDisposition.OPEN,
    "severity": SourceSeverity.MEDIUM,
    "title": "Synthetic title",
    "description": "Synthetic description",
    "identifiers": ("CCI-000366",),
    "context_key": "synthetic",
}


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


class SarifDispatchTests(unittest.TestCase):
    """The suffix alone chooses the SARIF adapter, and a SARIF failure is attributed to it."""

    @staticmethod
    def attribution_of(result: IngestResult) -> tuple[str, str, str]:
        assert result.artifact is not None
        artifact = result.artifact
        return (artifact.parser_name, artifact.parser_version, artifact.media_type)

    def test_both_sarif_suffixes_route_to_the_sarif_adapter(self) -> None:
        reference = ingest_stig_artifact(SARIF_FIXTURE, ingested_at=FIRST_INGEST)
        # The double suffix is compared on the lowercased name, so an upper-case spelling
        # routes too.
        for name in ("scan.sarif", "scan.sarif.json", "Report.SARIF.JSON"):
            with self.subTest(name=name):
                with tempfile.TemporaryDirectory() as directory:
                    path = Path(directory) / name
                    path.write_bytes(SARIF_FIXTURE.read_bytes())
                    result = ingest_stig_artifact(path, ingested_at=FIRST_INGEST)

                self.assertTrue(result.successful, result.errors)
                self.assertEqual(self.attribution_of(result), SARIF_ATTRIBUTION)
                self.assertEqual({item.source_type for item in result.observations}, {"sarif"})
                self.assertEqual(
                    {(item.parser_name, item.parser_version) for item in result.observations},
                    {("complyroll.sarif", SARIF_PARSER_VERSION)},
                )
                # The name routes the read; only the bytes carry identity.
                self.assertEqual(
                    [item.observation_id for item in result.observations],
                    [item.observation_id for item in reference.observations],
                )

    def test_bare_json_copy_of_a_sarif_log_still_fails_as_cklb(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "scan.json"
            path.write_bytes(SARIF_FIXTURE.read_bytes())
            result = ingest_stig_artifact(path, ingested_at=FIRST_INGEST)

        self.assertFalse(result.successful)
        self.assertEqual(result.observations, ())
        self.assertEqual(
            self.attribution_of(result),
            ("complyroll.cklb", CKLB_PARSER_VERSION, "application/json"),
        )
        self.assertEqual(
            [(item.code, item.message) for item in result.errors],
            [("artifact_parse_failed", CKLB_SHAPE_MESSAGE)],
        )

    def test_checklist_under_a_sarif_suffix_is_refused_by_the_sarif_adapter(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "checklist.sarif"
            path.write_bytes((FIXTURES / "ubuntu-host.cklb").read_bytes())
            result = ingest_stig_artifact(path, ingested_at=FIRST_INGEST)

        self.assertFalse(result.successful)
        self.assertEqual(result.observations, ())
        self.assertEqual(self.attribution_of(result), SARIF_ATTRIBUTION)
        self.assertEqual(
            [(item.code, item.message) for item in result.errors],
            [("artifact_parse_failed", "SARIF version must be the string 2.1.0")],
        )

    def test_malformed_sarif_is_attributed_to_the_sarif_adapter(self) -> None:
        # Before this slice the parse-failure block blamed complyroll.xml-auto for any suffix
        # it did not know; a .sarif that fails before the adapter runs must name the adapter.
        cases = (
            ("brace.sarif", b"{", "Expecting property name"),
            ("bytes.sarif.json", b"\xff", "JSON must be UTF-8"),
        )
        for name, content, prefix in cases:
            with self.subTest(name=name):
                with tempfile.TemporaryDirectory() as directory:
                    path = Path(directory) / name
                    path.write_bytes(content)
                    result = ingest_stig_artifact(path, ingested_at=FIRST_INGEST)

                self.assertFalse(result.successful)
                self.assertEqual(result.observations, ())
                self.assertEqual(self.attribution_of(result), SARIF_ATTRIBUTION)
                assert result.artifact is not None
                self.assertNotEqual(result.artifact.parser_name, "complyroll.xml-auto")
                self.assertEqual(result.artifact.digest_sha256, hashlib.sha256(content).hexdigest())
                self.assertEqual([item.code for item in result.errors], ["artifact_parse_failed"])
                self.assertTrue(result.errors[0].message.startswith(prefix), result.errors[0])

    def test_the_package_exports_the_sarif_adapter_and_its_version(self) -> None:
        self.assertIn("SarifAdapter", adapters.__all__)
        self.assertIn("SARIF_PARSER_VERSION", adapters.__all__)
        self.assertIs(adapters.SarifAdapter, sarif.SarifAdapter)
        self.assertIs(adapters.SARIF_PARSER_VERSION, sarif.SARIF_PARSER_VERSION)
        self.assertIs(SarifAdapter, sarif.SarifAdapter)


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
        self.assertEqual(SarifAdapter.version, SARIF_PARSER_VERSION)

    def test_artifact_provenance_uses_the_adapter_version(self) -> None:
        self.assertEqual(self._versions(FIXTURES / "ubuntu-host.cklb"), {CKLB_PARSER_VERSION})
        self.assertEqual(self._versions(FIXTURES / "windows-host.ckl"), {CKL_PARSER_VERSION})
        self.assertEqual(
            self._versions(FIXTURES / "openscap-results.xml"), {XCCDF_PARSER_VERSION}
        )
        self.assertEqual(self._versions(ARF_FIXTURE), {XCCDF_PARSER_VERSION})
        self.assertEqual(self._versions(SARIF_FIXTURE), {SARIF_PARSER_VERSION})

    def test_bumping_one_adapter_leaves_the_others_untouched(self) -> None:
        ckl_before = ingest_stig_artifact(
            FIXTURES / "windows-host.ckl", ingested_at=FIRST_INGEST
        )
        xccdf_before = ingest_stig_artifact(
            FIXTURES / "openscap-results.xml", ingested_at=FIRST_INGEST
        )
        sarif_before = ingest_stig_artifact(SARIF_FIXTURE, ingested_at=FIRST_INGEST)

        with mock.patch.object(CklbAdapter, "version", "99"):
            cklb = ingest_stig_artifact(FIXTURES / "ubuntu-host.cklb", ingested_at=FIRST_INGEST)
            ckl_after = ingest_stig_artifact(
                FIXTURES / "windows-host.ckl", ingested_at=FIRST_INGEST
            )
            xccdf_after = ingest_stig_artifact(
                FIXTURES / "openscap-results.xml", ingested_at=FIRST_INGEST
            )
            sarif_after = ingest_stig_artifact(SARIF_FIXTURE, ingested_at=FIRST_INGEST)

        self.assertTrue(all(item.parser_version == "99" for item in cklb.observations))
        self.assertEqual(
            [item.observation_id for item in ckl_before.observations],
            [item.observation_id for item in ckl_after.observations],
        )
        self.assertEqual(
            [item.observation_id for item in xccdf_before.observations],
            [item.observation_id for item in xccdf_after.observations],
        )
        self.assertEqual(
            [item.observation_id for item in sarif_before.observations],
            [item.observation_id for item in sarif_after.observations],
        )

    def test_bumping_the_sarif_adapter_leaves_the_stig_adapters_untouched(self) -> None:
        unbumped = ingest_stig_artifact(SARIF_FIXTURE, ingested_at=FIRST_INGEST)

        with mock.patch.object(SarifAdapter, "version", "99"):
            bumped = ingest_stig_artifact(SARIF_FIXTURE, ingested_at=FIRST_INGEST)
            after = {
                name: ingest_stig_artifact(FIXTURES / name, ingested_at=FIRST_INGEST)
                for name in BASELINE_OBSERVATION_IDS
            }

        assert bumped.artifact is not None
        self.assertEqual(bumped.artifact.parser_version, "99")
        self.assertTrue(all(item.parser_version == "99" for item in bumped.observations))
        # The parser version is an identity input, so the bump re-mints SARIF and nothing else.
        self.assertNotEqual(
            [item.observation_id for item in unbumped.observations],
            [item.observation_id for item in bumped.observations],
        )
        for name, expected in BASELINE_OBSERVATION_IDS.items():
            with self.subTest(fixture=name):
                self.assertEqual(
                    tuple(item.observation_id for item in after[name].observations), expected
                )

    def test_cci_loader_uses_its_own_parser_version(self) -> None:
        with mock.patch.object(CklbAdapter, "version", "99"):
            mapping_result = load_cci_control_map(
                FIXTURES / "cci-list.xml", ingested_at=FIRST_INGEST
            )

        self.assertTrue(mapping_result.successful)
        assert mapping_result.artifact is not None
        self.assertEqual(mapping_result.artifact.parser_version, CCI_PARSER_VERSION)


class CommonHelperMoveTests(unittest.TestCase):
    """The STIG adapters read their shared helpers from adapters/common.py (decision 18)."""

    def test_the_stig_adapters_use_the_shared_helpers(self) -> None:
        self.assertIs(stig.text_of, common.text_of)
        self.assertIs(stig.unique, common.unique)
        self.assertIs(stig.parse_timestamp, common.parse_timestamp)
        self.assertIs(stig.make_observation, common.make_observation)
        self.assertIs(stig.missing_time_diagnostic, common.missing_time_diagnostic)

    def test_every_stig_fixture_keeps_its_observation_ids_after_the_helper_move(self) -> None:
        for name, expected in BASELINE_OBSERVATION_IDS.items():
            with self.subTest(fixture=name):
                result = ingest_stig_artifact(FIXTURES / name, ingested_at=FIRST_INGEST)

                self.assertTrue(result.successful, result.errors)
                self.assertEqual(
                    tuple(item.observation_id for item in result.observations), expected
                )
                self.assertTrue(
                    all(item.resource.resource_type == "host" for item in result.observations)
                )

    def test_make_observation_defaults_the_resource_type_to_host(self) -> None:
        host = common.make_observation(**SYNTHETIC_FIELDS)
        file = common.make_observation(**SYNTHETIC_FIELDS, resource_type="file")

        self.assertEqual(host.resource.resource_type, "host")
        self.assertEqual(host.resource.resource_id, "lab-synthetic")
        self.assertEqual(host.observation_id, host.derived_observation_id)
        self.assertEqual(file.resource.resource_type, "file")
        self.assertEqual(file.observation_id, file.derived_observation_id)
        # resource_type is one of the nine fingerprint inputs, so it must move the identity.
        self.assertNotEqual(host.fingerprint, file.fingerprint)
        self.assertNotEqual(host.observation_id, file.observation_id)


if __name__ == "__main__":
    unittest.main()
