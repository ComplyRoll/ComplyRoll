from __future__ import annotations

import tempfile
import unittest
from datetime import UTC, datetime
from pathlib import Path

from trustroll.adapters import IngestLimits, ingest_stig_artifact


NOW = datetime(2026, 8, 18, 20, 0, tzinfo=UTC)


class SafeInputTests(unittest.TestCase):
    def test_doctype_and_entities_are_rejected(self) -> None:
        payload = """<?xml version="1.0"?>
<!DOCTYPE CHECKLIST [<!ENTITY x "expanded">]>
<CHECKLIST><ASSET><HOST_NAME>&x;</HOST_NAME></ASSET></CHECKLIST>
"""
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "entity.ckl"
            path.write_text(payload, encoding="utf-8")
            result = ingest_stig_artifact(path, ingested_at=NOW)

        self.assertFalse(result.successful)
        self.assertIn("DOCTYPE and ENTITY", result.errors[0].message)

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


if __name__ == "__main__":
    unittest.main()
