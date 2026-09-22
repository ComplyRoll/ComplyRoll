from __future__ import annotations

import os
import tempfile
import threading
import unittest
from datetime import UTC, datetime
from pathlib import Path

from complyroll.adapters import IngestLimits, ingest_stig_artifact
from complyroll.adapters.safeio import (
    DEFAULT_LIMITS,
    InputLimitError,
    UnsafeXmlError,
    parse_json_bounded,
    parse_xml_bounded,
    read_bounded,
)
from complyroll.adapters.sarif import SARIF_MEDIA_TYPE, SARIF_PARSER_VERSION

NOW = datetime(2026, 8, 18, 20, 0, tzinfo=UTC)
SARIF_FIXTURE = Path(__file__).parent / "fixtures" / "trivy-image.sarif"

INTERNAL_DTD_DOCUMENT = (
    '<?xml version="1.0"?>\n'
    '<!DOCTYPE CHECKLIST [<!ENTITY x "expanded">]>\n'
    "<CHECKLIST><ASSET><HOST_NAME>&x;</HOST_NAME></ASSET></CHECKLIST>\n"
)

ENTITY_BOMB_DOCUMENT = (
    '<?xml version="1.0"?>\n'
    "<!DOCTYPE CHECKLIST [\n"
    '  <!ENTITY a "aaaaaaaaaa">\n'
    '  <!ENTITY b "&a;&a;&a;&a;&a;&a;&a;&a;&a;&a;">\n'
    '  <!ENTITY c "&b;&b;&b;&b;&b;&b;&b;&b;&b;&b;">\n'
    "]>\n"
    "<CHECKLIST><ASSET><HOST_NAME>&c;</HOST_NAME></ASSET></CHECKLIST>\n"
)

QUOTED_DECLARATION = "<!DOCTYPE x [<!ENTITY y 'z'>]>"

QUOTED_DECLARATION_DOCUMENT = (
    '<?xml version="1.0" encoding="UTF-8"?>\n'
    "<CHECKLIST>\n"
    f"  <!-- assessor note: the host was tested against {QUOTED_DECLARATION} -->\n"
    "  <ASSET><HOST_NAME>lab-win-09</HOST_NAME></ASSET>\n"
    "  <STIGS><iSTIG><VULN>\n"
    "    <STIG_DATA><VULN_ATTRIBUTE>Vuln_Num</VULN_ATTRIBUTE>"
    "<ATTRIBUTE_DATA>V-253260</ATTRIBUTE_DATA></STIG_DATA>\n"
    "    <STIG_DATA><VULN_ATTRIBUTE>FINDING_DETAILS</VULN_ATTRIBUTE>"
    f"<ATTRIBUTE_DATA><![CDATA[{QUOTED_DECLARATION}]]></ATTRIBUTE_DATA></STIG_DATA>\n"
    "    <STATUS>Open</STATUS>\n"
    "  </VULN></iSTIG></STIGS>\n"
    "</CHECKLIST>\n"
)

NAMESPACED_DOCUMENT = (
    '<?xml version="1.0" encoding="UTF-8"?>\n'
    '<Benchmark xmlns="http://checklists.nist.gov/xccdf/1.2" '
    'xmlns:dc="http://purl.org/dc/elements/1.1/" id="test">\n'
    '  <TestResult id="result-1" dc:source="scanner"><target>lab-ubuntu-02</target></TestResult>\n'
    "</Benchmark>\n"
)

# A checklist that is valid in every other way, with one lone surrogate escape in the
# finding text. json.loads accepts it; the first .encode("utf-8") downstream did not.
LONE_SURROGATE_CKLB = (
    b'{"target_data":{"host_name":"lab-surrogate"},'
    b'"stigs":[{"stig_name":"Synthetic STIG","rules":['
    b'{"group_id":"V-1","status":"open","finding_details":"broken \\ud800 text"}]}]}'
)


def utf16_le_with_bom(document: str) -> bytes:
    return b"\xff\xfe" + document.encode("utf-16-le")


def utf16_be_with_bom(document: str) -> bytes:
    return b"\xfe\xff" + document.encode("utf-16-be")


def utf16_le_without_bom(document: str) -> bytes:
    declared = document.replace('<?xml version="1.0"?>', '<?xml version="1.0" encoding="UTF-16"?>')
    return declared.encode("utf-16-le")


class SafeInputTests(unittest.TestCase):
    def test_doctype_and_entities_are_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "entity.ckl"
            path.write_text(INTERNAL_DTD_DOCUMENT, encoding="utf-8")
            result = ingest_stig_artifact(path, ingested_at=NOW)

        self.assertFalse(result.successful)
        self.assertEqual(result.errors[0].code, "artifact_parse_failed")
        self.assertIn("DOCTYPE", result.errors[0].message)

    def test_artifact_size_limit_is_enforced_before_parse(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "large.cklb"
            path.write_text('{"stigs":[]}', encoding="utf-8")
            result = ingest_stig_artifact(
                path,
                ingested_at=NOW,
                limits=IngestLimits(max_artifact_bytes=4),
            )

        self.assertFalse(result.successful)
        self.assertEqual(result.errors[0].code, "artifact_read_failed")
        self.assertIn("maximum is 4 bytes", result.errors[0].message)

    def test_xml_depth_limit_is_enforced(self) -> None:
        payload = "<CHECKLIST><a><b><c /></b></a></CHECKLIST>"
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "deep.ckl"
            path.write_text(payload, encoding="utf-8")
            result = ingest_stig_artifact(
                path,
                ingested_at=NOW,
                limits=IngestLimits(max_xml_depth=3),
            )

        self.assertFalse(result.successful)
        self.assertIn("XML nesting exceeds 3", result.errors[0].message)

    def test_json_depth_limit_is_enforced(self) -> None:
        payload = '{"stigs":[{"rules":[{"nested":{"again":true}}]}]}'
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "deep.cklb"
            path.write_text(payload, encoding="utf-8")
            result = ingest_stig_artifact(
                path,
                ingested_at=NOW,
                limits=IngestLimits(max_json_depth=3),
            )

        self.assertFalse(result.successful)
        self.assertIn("JSON nesting exceeds 3", result.errors[0].message)

    def test_nonstandard_json_constants_are_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "nan.cklb"
            path.write_text('{"stigs":NaN}', encoding="utf-8")
            result = ingest_stig_artifact(path, ingested_at=NOW)

        self.assertFalse(result.successful)
        self.assertIn("non-standard JSON constant", result.errors[0].message)

    def test_duplicate_json_keys_are_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "duplicate.cklb"
            path.write_text('{"stigs":[],"stigs":[]}', encoding="utf-8")
            result = ingest_stig_artifact(path, ingested_at=NOW)

        self.assertFalse(result.successful)
        self.assertIn("duplicate JSON object key", result.errors[0].message)


class XmlDeclarationRejectionTests(unittest.TestCase):
    """DOCTYPE/ENTITY rejection must hold for every encoding expat can auto-detect."""

    def assert_rejected(self, payload: bytes) -> None:
        with self.assertRaises(UnsafeXmlError) as caught:
            parse_xml_bounded(payload)
        self.assertIn("prohibited", str(caught.exception))

    def test_utf8_internal_dtd_is_rejected(self) -> None:
        self.assert_rejected(INTERNAL_DTD_DOCUMENT.encode("utf-8"))

    def test_utf16_le_with_bom_internal_dtd_is_rejected(self) -> None:
        self.assert_rejected(utf16_le_with_bom(INTERNAL_DTD_DOCUMENT))

    def test_utf16_be_with_bom_internal_dtd_is_rejected(self) -> None:
        self.assert_rejected(utf16_be_with_bom(INTERNAL_DTD_DOCUMENT))

    def test_utf16_le_without_bom_internal_dtd_is_rejected(self) -> None:
        self.assert_rejected(utf16_le_without_bom(INTERNAL_DTD_DOCUMENT))

    def test_doctype_without_internal_subset_is_rejected(self) -> None:
        self.assert_rejected(b'<?xml version="1.0"?><!DOCTYPE CHECKLIST><CHECKLIST/>')

    def test_external_doctype_is_rejected(self) -> None:
        self.assert_rejected(
            b'<?xml version="1.0"?>'
            b'<!DOCTYPE CHECKLIST SYSTEM "file:///etc/passwd">'
            b"<CHECKLIST/>"
        )

    def test_entity_bomb_is_rejected_as_unsafe_xml(self) -> None:
        for label, payload in (
            ("utf-8", ENTITY_BOMB_DOCUMENT.encode("utf-8")),
            ("utf-16-le", utf16_le_with_bom(ENTITY_BOMB_DOCUMENT)),
            ("utf-16-be", utf16_be_with_bom(ENTITY_BOMB_DOCUMENT)),
        ):
            with self.subTest(encoding=label):
                with self.assertRaises(UnsafeXmlError):
                    parse_xml_bounded(payload)

    def test_utf16_entity_is_never_expanded_into_evidence(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "utf16.ckl"
            path.write_bytes(utf16_le_with_bom(INTERNAL_DTD_DOCUMENT))
            result = ingest_stig_artifact(path, ingested_at=NOW)

        self.assertFalse(result.successful)
        self.assertEqual(result.observations, ())
        self.assertEqual(result.errors[0].code, "artifact_parse_failed")
        self.assertIn("DOCTYPE", result.errors[0].message)


class XmlLegitimateContentTests(unittest.TestCase):
    """A checklist that documents a DTD finding is evidence, not an attack."""

    def test_quoted_declaration_in_cdata_and_comment_parses(self) -> None:
        root = parse_xml_bounded(QUOTED_DECLARATION_DOCUMENT.encode("utf-8"))

        self.assertEqual(root.tag, "CHECKLIST")
        values = [
            element.text
            for element in root.iter()
            if element.tag == "ATTRIBUTE_DATA" and element.text
        ]
        self.assertIn(QUOTED_DECLARATION, values)

    def test_quoted_declaration_checklist_still_produces_observations(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "documented-finding.ckl"
            path.write_text(QUOTED_DECLARATION_DOCUMENT, encoding="utf-8")
            result = ingest_stig_artifact(path, ingested_at=NOW)

        self.assertTrue(result.successful, result.errors)
        self.assertEqual(len(result.observations), 1)
        self.assertEqual(result.observations[0].resource.resource_id, "lab-win-09")
        self.assertEqual(result.observations[0].source_record_id, "V-253260")

    def test_namespaced_tags_use_elementtree_convention(self) -> None:
        root = parse_xml_bounded(NAMESPACED_DOCUMENT.encode("utf-8"))

        self.assertEqual(root.tag, "{http://checklists.nist.gov/xccdf/1.2}Benchmark")
        self.assertEqual(root.get("id"), "test")
        result = root[0]
        self.assertEqual(result.tag, "{http://checklists.nist.gov/xccdf/1.2}TestResult")
        self.assertEqual(result.get("{http://purl.org/dc/elements/1.1/}source"), "scanner")
        self.assertEqual(result[0].tag, "{http://checklists.nist.gov/xccdf/1.2}target")
        self.assertEqual(result[0].text, "lab-ubuntu-02")

    def test_malformed_xml_becomes_a_value_error(self) -> None:
        with self.assertRaises(ValueError) as caught:
            parse_xml_bounded(b"<CHECKLIST><ASSET></CHECKLIST>")
        self.assertNotIsInstance(caught.exception, UnsafeXmlError)
        self.assertIn("malformed XML", str(caught.exception))

    def test_empty_input_is_rejected(self) -> None:
        with self.assertRaises(ValueError):
            parse_xml_bounded(b"")


class XmlBoundaryTests(unittest.TestCase):
    def test_depth_limit_boundary(self) -> None:
        payload = b"<a><b><c/></b></a>"
        self.assertIsNotNone(parse_xml_bounded(payload, IngestLimits(max_xml_depth=3)))
        with self.assertRaises(InputLimitError) as caught:
            parse_xml_bounded(payload, IngestLimits(max_xml_depth=2))
        self.assertIn("XML nesting exceeds 2 levels", str(caught.exception))

    def test_element_limit_boundary(self) -> None:
        payload = b"<a><b/><c/></a>"
        self.assertIsNotNone(parse_xml_bounded(payload, IngestLimits(max_xml_elements=3)))
        with self.assertRaises(InputLimitError) as caught:
            parse_xml_bounded(payload, IngestLimits(max_xml_elements=2))
        self.assertIn("XML contains more than 2 elements", str(caught.exception))

    def test_sibling_elements_do_not_accumulate_depth(self) -> None:
        payload = b"<a>" + b"<b/>" * 50 + b"</a>"
        root = parse_xml_bounded(payload, IngestLimits(max_xml_depth=2))
        self.assertEqual(len(root), 50)


# The JSON walk counts values and never keys, and the root is at depth 1.
class JsonBoundaryTests(unittest.TestCase):
    def test_depth_limit_boundary(self) -> None:
        payload = b'{"a":{"b":1}}'
        parsed = parse_json_bounded(payload, IngestLimits(max_json_depth=3))
        self.assertEqual(parsed, {"a": {"b": 1}})
        with self.assertRaises(InputLimitError) as caught:
            parse_json_bounded(payload, IngestLimits(max_json_depth=2))
        self.assertIn("JSON nesting exceeds 2 levels", str(caught.exception))

    def test_value_limit_boundary(self) -> None:
        payload = b'{"a":[1,2]}'
        parsed = parse_json_bounded(payload, IngestLimits(max_json_nodes=4))
        self.assertEqual(parsed, {"a": [1, 2]})
        with self.assertRaises(InputLimitError) as caught:
            parse_json_bounded(payload, IngestLimits(max_json_nodes=3))
        self.assertIn("JSON contains more than 3 values", str(caught.exception))


class ReadBoundedTests(unittest.TestCase):
    def test_regular_file_round_trips(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "artifact.ckl"
            path.write_bytes(b"payload")
            self.assertEqual(read_bounded(path), b"payload")

    def test_exact_limit_is_accepted(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "artifact.ckl"
            path.write_bytes(b"1234")
            self.assertEqual(read_bounded(path, IngestLimits(max_artifact_bytes=4)), b"1234")

    def test_one_byte_over_limit_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "artifact.ckl"
            path.write_bytes(b"12345")
            with self.assertRaises(InputLimitError):
                read_bounded(path, IngestLimits(max_artifact_bytes=4))

    def test_directory_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            with self.assertRaises(ValueError) as caught:
                read_bounded(Path(directory))
            self.assertIn("regular file", str(caught.exception))

    @unittest.skipUnless(hasattr(os, "mkfifo"), "platform has no FIFO support")
    def test_fifo_is_rejected_without_blocking(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "pipe.ckl"
            os.mkfifo(path)
            outcome: list[Exception | None] = []

            def attempt() -> None:
                try:
                    read_bounded(path)
                except Exception as exc:
                    outcome.append(exc)
                else:
                    outcome.append(None)

            worker = threading.Thread(target=attempt, daemon=True)
            worker.start()
            worker.join(timeout=5.0)

            self.assertFalse(worker.is_alive(), "read_bounded blocked on a FIFO")
            self.assertIsInstance(outcome[0], ValueError)
            self.assertIn("regular file", str(outcome[0]))

    def test_missing_file_raises_os_error(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            with self.assertRaises(FileNotFoundError):
                read_bounded(Path(directory) / "absent.ckl")


class IngestLimitFieldTests(unittest.TestCase):
    """Three bounds for the SARIF adapter; the defaults keep every existing value."""

    def test_the_two_new_fields_default_to_fifty_thousand(self) -> None:
        limits = IngestLimits()

        self.assertEqual(limits.max_results_per_run, 50_000)
        self.assertEqual(limits.max_observations_per_artifact, 50_000)

    def test_the_observation_byte_budget_defaults_to_eight_artifact_bounds(self) -> None:
        limits = IngestLimits()

        self.assertEqual(limits.max_observation_bytes_per_artifact, 256 * 1024 * 1024)
        self.assertEqual(limits.max_observation_bytes_per_artifact, 8 * limits.max_artifact_bytes)

    def test_default_limits_carry_the_new_fields_and_keep_every_existing_value(self) -> None:
        self.assertEqual(DEFAULT_LIMITS, IngestLimits())
        self.assertEqual(DEFAULT_LIMITS.max_artifact_bytes, 32 * 1024 * 1024)
        self.assertEqual(DEFAULT_LIMITS.max_json_depth, 128)
        self.assertEqual(DEFAULT_LIMITS.max_json_nodes, 500_000)
        self.assertEqual(DEFAULT_LIMITS.max_xml_depth, 128)
        self.assertEqual(DEFAULT_LIMITS.max_xml_elements, 500_000)
        self.assertEqual(DEFAULT_LIMITS.max_results_per_run, 50_000)
        self.assertEqual(DEFAULT_LIMITS.max_observations_per_artifact, 50_000)
        self.assertEqual(DEFAULT_LIMITS.max_observation_bytes_per_artifact, 256 * 1024 * 1024)

    def test_each_new_field_can_be_lowered_on_its_own(self) -> None:
        results = IngestLimits(max_results_per_run=3)
        observations = IngestLimits(max_observations_per_artifact=2)
        observation_bytes = IngestLimits(max_observation_bytes_per_artifact=1_000)

        self.assertEqual(results.max_results_per_run, 3)
        self.assertEqual(results.max_observations_per_artifact, 50_000)
        self.assertEqual(observations.max_observations_per_artifact, 2)
        self.assertEqual(observations.max_results_per_run, 50_000)
        self.assertEqual(observation_bytes.max_observation_bytes_per_artifact, 1_000)
        self.assertEqual(observation_bytes.max_observations_per_artifact, 50_000)
        self.assertEqual(observation_bytes.max_results_per_run, 50_000)


class SarifIngestLimitTests(unittest.TestCase):
    """Every bound the dispatcher is given reaches the SARIF read and the SARIF adapter."""

    def test_an_oversized_sarif_log_is_refused_before_the_read(self) -> None:
        size = len(SARIF_FIXTURE.read_bytes())
        result = ingest_stig_artifact(
            SARIF_FIXTURE, ingested_at=NOW, limits=IngestLimits(max_artifact_bytes=4)
        )

        self.assertFalse(result.successful)
        self.assertIsNone(result.artifact)
        self.assertEqual(result.observations, ())
        self.assertEqual(
            [(item.code, item.message, item.location) for item in result.errors],
            [
                (
                    "artifact_read_failed",
                    f"artifact is {size} bytes; maximum is 4 bytes",
                    str(SARIF_FIXTURE),
                )
            ],
        )

    def test_each_lowered_bound_is_a_parse_failure_attributed_to_sarif(self) -> None:
        # trivy-image.sarif is one run of five results that fold into three observations.
        cases = (
            (IngestLimits(max_json_nodes=50), "JSON contains more than 50 values"),
            (IngestLimits(max_results_per_run=4), "runs[0] contains 5 results; maximum is 4"),
            (
                IngestLimits(max_observations_per_artifact=2),
                "artifact yields more than 2 observations",
            ),
            (
                IngestLimits(max_observation_bytes_per_artifact=1_000),
                "artifact yields more than 1000 bytes of observation JSON",
            ),
        )
        for limits, message in cases:
            with self.subTest(message=message):
                result = ingest_stig_artifact(SARIF_FIXTURE, ingested_at=NOW, limits=limits)

                self.assertFalse(result.successful)
                self.assertEqual(result.observations, ())
                assert result.artifact is not None
                self.assertEqual(result.artifact.parser_name, "complyroll.sarif")
                self.assertEqual(result.artifact.parser_version, SARIF_PARSER_VERSION)
                self.assertEqual(result.artifact.media_type, SARIF_MEDIA_TYPE)
                self.assertEqual(
                    [(item.code, item.message, item.location) for item in result.errors],
                    [("artifact_parse_failed", message, SARIF_FIXTURE.name)],
                )


class LoneSurrogateTests(unittest.TestCase):
    """A lone surrogate is refused at parse, where the dispatcher reports it, not at write."""

    def assert_refused(self, payload: bytes, kind: str, code_point: str) -> None:
        with self.assertRaises(ValueError) as caught:
            parse_json_bounded(payload)
        self.assertNotIsInstance(caught.exception, InputLimitError)
        message = str(caught.exception)
        self.assertIn("lone surrogate", message)
        self.assertIn(f"JSON {kind}", message)
        self.assertIn(code_point, message)

    def test_a_lone_surrogate_in_a_string_value_is_refused(self) -> None:
        self.assert_refused(b'{"a":"\\ud800"}', "string", "U+D800")

    def test_a_lone_surrogate_in_an_object_key_is_refused(self) -> None:
        self.assert_refused(b'{"\\ud800":"a"}', "object key", "U+D800")

    def test_a_lone_surrogate_nested_in_a_value_is_refused(self) -> None:
        self.assert_refused(b'{"stigs":[{"rules":[{"title":"x\\udc00y"}]}]}', "string", "U+DC00")

    def test_a_lone_surrogate_nested_in_a_key_is_refused(self) -> None:
        self.assert_refused(b'[{"outer":{"inner \\udfff":1}}]', "object key", "U+DFFF")

    def test_the_root_string_is_checked_too(self) -> None:
        self.assert_refused(b'"\\ud800"', "string", "U+D800")

    def test_a_valid_surrogate_pair_escape_still_parses(self) -> None:
        value = parse_json_bounded(b'{"a":"\\ud83d\\ude00"}')

        self.assertEqual(value, {"a": "\U0001F600"})
        self.assertIsInstance(value["a"].encode("utf-8"), bytes)

    def test_a_literal_astral_plane_character_still_parses_in_keys_and_values(self) -> None:
        payload = '{"key \U0001F600":"\U0001F600 value"}'.encode()

        self.assertEqual(parse_json_bounded(payload), {"key \U0001F600": "\U0001F600 value"})

    def test_a_lone_surrogate_checklist_is_a_failed_parse_not_a_later_crash(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "surrogate.cklb"
            path.write_bytes(LONE_SURROGATE_CKLB)
            result = ingest_stig_artifact(path, ingested_at=NOW)

        self.assertFalse(result.successful)
        self.assertEqual(result.observations, ())
        self.assertIsNotNone(result.artifact)
        assert result.artifact is not None
        self.assertEqual(result.artifact.parser_name, "complyroll.cklb")
        self.assertEqual(result.errors[0].code, "artifact_parse_failed")
        self.assertIn("lone surrogate", result.errors[0].message)
        self.assertIsInstance(result.to_canonical_json().encode("utf-8"), bytes)

    def test_the_same_checklist_with_a_paired_escape_ingests(self) -> None:
        payload = LONE_SURROGATE_CKLB.replace(b"\\ud800", b"\\ud83d\\ude00")
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "astral.cklb"
            path.write_bytes(payload)
            result = ingest_stig_artifact(path, ingested_at=NOW)

        self.assertTrue(result.successful, result.errors)
        self.assertEqual(len(result.observations), 1)
        self.assertEqual(result.observations[0].description, "broken \U0001F600 text")
        self.assertIsInstance(result.to_canonical_json().encode("utf-8"), bytes)


if __name__ == "__main__":
    unittest.main()
