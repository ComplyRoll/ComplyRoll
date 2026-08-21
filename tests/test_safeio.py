from __future__ import annotations

import os
import tempfile
import threading
import unittest
from datetime import UTC, datetime
from pathlib import Path

from complyroll.adapters import IngestLimits, ingest_stig_artifact
from complyroll.adapters.safeio import (
    InputLimitError,
    UnsafeXmlError,
    parse_xml_bounded,
    read_bounded,
)

NOW = datetime(2026, 8, 18, 20, 0, tzinfo=UTC)

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


if __name__ == "__main__":
    unittest.main()
