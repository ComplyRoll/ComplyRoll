# ******************************************************************************
# *Title: CISA KEV Enrichment Tests*
# *Author: Kyle Versluis*
# *Description: Unit tests for the CISA KEV loader and clock (ADR 0012).*
# ******************************************************************************
"""Tests for the CISA KEV catalog: loading, refusals, matching, and the clock."""

# *--- Imports ---*

from __future__ import annotations

import dataclasses
import hashlib
import inspect
import json
import re
import tempfile
import unittest
from collections.abc import Sequence
from datetime import UTC, date, datetime, timedelta
from pathlib import Path
from typing import Any

from test_reports import compile_fixtures, options, summary_counts

from complyroll.adapters import ingest_stig_artifact
from complyroll.models import CaseStatus, Observation
from complyroll.policy import (
    CertificationClass,
    load_bundled_rule_source_snapshot,
    select_policy,
)
from complyroll.reports import (
    MAX_KEV_CATALOG_BYTES,
    MAX_KEV_ENTRIES,
    KevCatalog,
    KevStatus,
    ReportCompileError,
    ReportInputError,
    load_evaluations,
    load_kev_catalog,
    parse_kev_catalog,
)
from complyroll.reports.kev import (
    KEV_LIMITS,
    KEV_STALE_AFTER,
    KEV_STOPS,
    MAX_TRUNCATED_METADATA_BYTES,
    cve_may_be_missing,
    due_instant,
    kev_clock,
    start_instant,
)
from complyroll.reports.vdt import _kev_clause, _kev_line, _kev_rule

# *--- Fixtures ---*

REPO_ROOT = Path(__file__).parent.parent
FIXTURES = REPO_ROOT / "tests" / "fixtures"
KEV_CATALOG = FIXTURES / "kev-catalog.json"
KEV_CATALOG_NAME = "kev-catalog.json"
RELEASED = datetime(2026, 9, 14, 17, 0, 0, 123400, tzinfo=UTC)
#: The catalog's twelve cveIDs in the order the fixture file lists them, which is not sorted.
FIXTURE_ORDER = (
    "CVE-2099-0006",
    "CVE-2099-0001",
    "CVE-2099-9999",
    "CVE-2099-0004",
    "CVE-2099-0009",
    "CVE-2099-0002",
    "CVE-2099-0011",
    "CVE-2099-0010",
    "CVE-2099-0007",
    "CVE-2099-0003",
    "CVE-2099-0005",
    "CVE-2099-0008",
)
#: Every refusal message stays under this many characters, whatever the input held.
MAX_MESSAGE_CHARS = 400
MISSING = object()


def fixture_bytes() -> bytes:
    return KEV_CATALOG.read_bytes()


def fixture_payload() -> dict[str, Any]:
    return json.loads(KEV_CATALOG.read_text(encoding="utf-8"))


def fixture_catalog() -> KevCatalog:
    return load_kev_catalog(KEV_CATALOG)


def encoded(payload: object) -> bytes:
    return json.dumps(payload).encode("utf-8")


def with_root(key: str, value: object) -> bytes:
    """Return the fixture with one root field replaced, or removed when value is MISSING."""
    payload = fixture_payload()
    if value is MISSING:
        del payload[key]
    else:
        payload[key] = value
    return encoded(payload)


def with_entry(key: str, value: object, index: int = 0) -> bytes:
    """Return the fixture with one field of one entry replaced, or removed when MISSING."""
    payload = fixture_payload()
    entry = payload["vulnerabilities"][index]
    if value is MISSING:
        del entry[key]
    else:
        entry[key] = value
    return encoded(payload)


def minimal_entry(cve_id: str, added: str = "2026-09-01", due: str = "2026-09-15") -> dict:
    return {"cveID": cve_id, "dateAdded": added, "dueDate": due}


def minimal_catalog(
    entries: list[dict[str, object]], released: str = "2026-09-14T17:00:00Z"
) -> bytes:
    return encoded(
        {
            "catalogVersion": "2026.09.14",
            "dateReleased": released,
            "count": len(entries),
            "vulnerabilities": entries,
        }
    )


def nested_lists(depth: int) -> object:
    """Return a JSON list nested `depth` levels deep."""
    value: object = []
    for _ in range(depth - 1):
        value = [value]
    return value


def sarif_observation(**changes: object) -> Observation:
    """Return one ingested SARIF observation with fields replaced."""
    result = ingest_stig_artifact(
        FIXTURES / "trivy-image.sarif", ingested_at=datetime(2026, 9, 2, 12, tzinfo=UTC)
    )
    return dataclasses.replace(result.observations[0], **changes)  # type: ignore[arg-type]


def tagged_sarif_observation(tags: tuple[str, ...]) -> Observation:
    """Ingest the Trivy fixture with one result tagged by the given identifiers."""
    payload = json.loads((FIXTURES / "trivy-image.sarif").read_text(encoding="utf-8"))
    result = payload["runs"][0]["results"][3]
    result["properties"] = {"tags": list(tags)}
    with tempfile.TemporaryDirectory() as directory:
        path = Path(directory) / "tagged.sarif"
        path.write_text(json.dumps(payload), encoding="utf-8")
        ingested = ingest_stig_artifact(path, ingested_at=datetime(2026, 9, 2, 12, tzinfo=UTC))
    (observation,) = [item for item in ingested.observations if item.metadata_value("truncated")]
    return observation


# *--- Loader ---*


class KevLoaderTests(unittest.TestCase):
    """The fixture loads with its identity, its UTC release instant, and sorted entries."""

    def test_the_fixture_loads_with_its_identity(self) -> None:
        content = fixture_bytes()
        catalog = fixture_catalog()
        self.assertEqual(catalog.name, KEV_CATALOG_NAME)
        self.assertEqual(catalog.sha256, hashlib.sha256(content).hexdigest())
        self.assertEqual(catalog.size_bytes, len(content))
        self.assertEqual(catalog.catalog_version, "2026.09.14")
        self.assertEqual(catalog.date_released, RELEASED)
        self.assertEqual(catalog.date_released.microsecond, 123400)
        self.assertEqual(catalog.declared_count, 12)
        self.assertEqual(len(catalog.entries), 12)

    def test_entries_are_sorted_by_cve_id_whatever_the_file_order(self) -> None:
        listed = tuple(item["cveID"] for item in fixture_payload()["vulnerabilities"])
        self.assertEqual(listed, FIXTURE_ORDER)
        self.assertNotEqual(listed, tuple(sorted(listed)))
        self.assertEqual(
            tuple(entry.cve_id for entry in fixture_catalog().entries), tuple(sorted(listed))
        )

    def test_each_entry_carries_its_fields_and_instants(self) -> None:
        entries = {entry.cve_id: entry for entry in fixture_catalog().entries}
        first = entries["CVE-2099-0001"]
        self.assertEqual(first.date_added, date(2026, 8, 27))
        self.assertEqual(first.due_date, date(2026, 9, 10))
        self.assertEqual(first.known_ransomware_campaign_use, "Known")
        self.assertEqual(first.forensic_triage, "No")
        self.assertEqual(first.start_at, datetime(2026, 8, 27, tzinfo=UTC))
        self.assertEqual(first.due_at, datetime(2026, 9, 11, tzinfo=UTC))
        self.assertEqual(entries["CVE-2099-0003"].forensic_triage, "Yes")
        # The missing forensicTriage reads as None, not as a default.
        self.assertIsNone(entries["CVE-2099-0010"].forensic_triage)
        for entry in entries.values():
            with self.subTest(cve_id=entry.cve_id):
                self.assertEqual(entry.start_at, start_instant(entry.date_added))
                self.assertEqual(entry.due_at, due_instant(entry.due_date))

    def test_to_dict_gives_the_five_catalog_fields(self) -> None:
        entries = {entry.cve_id: entry for entry in fixture_catalog().entries}
        self.assertEqual(
            entries["CVE-2099-0010"].to_dict(),
            {
                "cveId": "CVE-2099-0010",
                "dateAdded": "2026-03-02",
                "dueDate": "2026-02-27",
                "forensicTriage": None,
                "knownRansomwareCampaignUse": "Unknown",
            },
        )

    def test_a_bom_is_tolerated_and_the_digest_covers_it(self) -> None:
        content = b"\xef\xbb\xbf" + fixture_bytes()
        catalog = parse_kev_catalog(content, name=KEV_CATALOG_NAME)
        plain = fixture_catalog()
        self.assertEqual(catalog.entries, plain.entries)
        self.assertEqual(catalog.sha256, hashlib.sha256(content).hexdigest())
        self.assertNotEqual(catalog.sha256, plain.sha256)
        self.assertEqual(catalog.size_bytes, plain.size_bytes + 3)

    def test_unknown_keys_due_before_added_and_non_ascii_prose_are_tolerated(self) -> None:
        payload = fixture_payload()
        self.assertIn("x-fixtureNote", payload)
        raw = {item["cveID"]: item for item in payload["vulnerabilities"]}
        self.assertIn("x-fixtureUnknownKey", raw["CVE-2099-9999"])
        prose = raw["CVE-2099-0001"]["shortDescription"] + raw["CVE-2099-0001"]["vendorProject"]
        self.assertFalse(prose.isascii())
        self.assertIn("\ufffd", prose)
        self.assertLess(raw["CVE-2099-0010"]["dueDate"], raw["CVE-2099-0010"]["dateAdded"])
        entries = {entry.cve_id: entry for entry in fixture_catalog().entries}
        self.assertLess(entries["CVE-2099-0010"].due_at, entries["CVE-2099-0010"].start_at)

    def test_free_text_fields_the_loader_never_reads_may_be_absent(self) -> None:
        catalog = parse_kev_catalog(
            minimal_catalog([minimal_entry("CVE-2099-0001")]), name="minimal.json"
        )
        (entry,) = catalog.entries
        self.assertIsNone(entry.known_ransomware_campaign_use)
        self.assertIsNone(entry.forensic_triage)

    def test_a_nine_digit_fraction_is_accepted_and_truncated(self) -> None:
        catalog = parse_kev_catalog(
            with_root("dateReleased", "2026-09-14T17:00:00.123456789Z"), name=KEV_CATALOG_NAME
        )
        self.assertEqual(catalog.date_released, datetime(2026, 9, 14, 17, 0, 0, 123456, tzinfo=UTC))

    def test_an_offset_release_instant_is_normalized_to_utc(self) -> None:
        catalog = parse_kev_catalog(
            with_root("dateReleased", "2026-09-14T10:00:00.1234-07:00"), name=KEV_CATALOG_NAME
        )
        self.assertEqual(catalog.date_released, RELEASED)
        self.assertIs(catalog.date_released.tzinfo, UTC)

    def test_nesting_at_the_depth_bound_is_accepted(self) -> None:
        # The root is depth 1 and a root value depth 2, so 15 nested lists reach depth 16.
        self.assertEqual(KEV_LIMITS.max_json_depth, 16)
        catalog = parse_kev_catalog(
            with_root("x-fixtureNote", nested_lists(15)), name=KEV_CATALOG_NAME
        )
        self.assertEqual(len(catalog.entries), 12)

    def test_the_entry_bound_is_inclusive(self) -> None:
        entries = [minimal_entry(f"CVE-2099-{number:05d}") for number in range(MAX_KEV_ENTRIES)]
        catalog = parse_kev_catalog(minimal_catalog(entries), name="many.json")
        self.assertEqual(len(catalog.entries), MAX_KEV_ENTRIES)

    def test_a_file_at_the_byte_bound_loads(self) -> None:
        content = fixture_bytes()
        padded = content + b" " * (MAX_KEV_CATALOG_BYTES - len(content))
        self.assertEqual(len(padded), MAX_KEV_CATALOG_BYTES)
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / KEV_CATALOG_NAME
            path.write_bytes(padded)
            self.assertEqual(load_kev_catalog(path).size_bytes, MAX_KEV_CATALOG_BYTES)

    def test_two_loads_are_equal_and_hash_equal(self) -> None:
        first = fixture_catalog()
        second = fixture_catalog()
        self.assertEqual(first, second)
        self.assertEqual(hash(first), hash(second))
        self.assertIsNot(first, second)

    def test_the_index_stays_out_of_equality_hashing_and_repr(self) -> None:
        (index,) = [item for item in dataclasses.fields(KevCatalog) if item.name == "_index"]
        self.assertFalse(index.compare)
        self.assertFalse(index.hash)
        self.assertFalse(index.repr)
        self.assertFalse(index.init)
        self.assertNotIn("_index", repr(fixture_catalog()))
        self.assertNotIn("mappingproxy", repr(fixture_catalog()))

    def test_a_directly_built_catalog_refuses_unsorted_or_repeated_entries(self) -> None:
        catalog = fixture_catalog()
        for entries in (tuple(reversed(catalog.entries)), catalog.entries[:1] * 2):
            with self.subTest(entries=[entry.cve_id for entry in entries]):
                with self.assertRaises(ValueError):
                    dataclasses.replace(catalog, entries=entries)


# *--- Loader Refusals ---*


class KevLoaderRefusalTests(unittest.TestCase):
    """Every refusal is a ReportInputError starting "KEV catalog", on both entry points."""

    def assert_refused(self, content: bytes, fragment: str = "", *, same: bool = True) -> str:
        """Assert parse_kev_catalog and load_kev_catalog both refuse the bytes; return the text.

        The two entry points give one message for a content refusal; only the size refusal,
        which read_bounded makes before parsing, may word itself differently.
        """
        messages = []
        with self.assertRaises(ReportInputError) as parsed:
            parse_kev_catalog(content, name=KEV_CATALOG_NAME)
        messages.append(parsed.exception)
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / KEV_CATALOG_NAME
            path.write_bytes(content)
            with self.assertRaises(ReportInputError) as loaded:
                load_kev_catalog(path)
        messages.append(loaded.exception)
        for exc in messages:
            self.assertIs(type(exc), ReportInputError)
            self.assertTrue(str(exc).startswith("KEV catalog"), str(exc))
            self.assertIn(fragment, str(exc))
            self.assertLess(len(str(exc)), MAX_MESSAGE_CHARS)
        if same:
            self.assertEqual(str(messages[0]), str(messages[1]))
        return str(messages[0])

    def assert_each_refused(self, cases: dict[str, bytes], fragment: str = "") -> None:
        for label, content in cases.items():
            with self.subTest(case=label):
                self.assert_refused(content, fragment)

    def test_non_json_bytes_are_refused(self) -> None:
        payload_text = fixture_bytes().decode("utf-8")
        self.assert_each_refused(
            {
                "csv": b"cveID,vendorProject,product\nCVE-2099-0001,Example Vendor,Example\n",
                "empty": b"",
                "non-utf-8": b'{"title": "\xff\xfe"}',
                "nan": payload_text.replace('"count": 12', '"count": NaN').encode("utf-8"),
                "infinity": payload_text.replace('"count": 12', '"count": Infinity').encode(),
                "duplicate key": payload_text.replace(
                    '"count": 12,', '"count": 12,\n  "count": 12,'
                ).encode("utf-8"),
                "lone surrogate": payload_text.replace(
                    '"title": "SYNTHETIC', '"title": "\\ud800SYNTHETIC'
                ).encode("utf-8"),
            },
            "KEV catalog must be the CISA JSON feed",
        )

    def test_a_root_that_is_not_an_object_is_refused(self) -> None:
        self.assert_each_refused(
            {"array": b"[]", "string": b'"catalog"', "number": b"12", "null": b"null"},
            "not an object",
        )

    def test_nesting_past_the_depth_bound_is_refused(self) -> None:
        message = self.assert_refused(with_root("x-fixtureNote", nested_lists(16)))
        self.assertIn("exceeds a limit", message)
        self.assertIn("16", message)

    def test_content_over_the_byte_bound_is_refused_by_both_entry_points(self) -> None:
        content = fixture_bytes()
        oversize = content + b" " * (MAX_KEV_CATALOG_BYTES + 1 - len(content))
        message = self.assert_refused(oversize, str(MAX_KEV_CATALOG_BYTES), same=False)
        self.assertIn(str(len(oversize)), message)

    def test_a_directory_and_a_missing_file_are_refused(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            for path in (Path(directory), Path(directory) / "absent.json"):
                with self.subTest(path=path.name):
                    with self.assertRaises(ReportInputError) as caught:
                        load_kev_catalog(path)
                    self.assertIs(type(caught.exception), ReportInputError)
                    self.assertTrue(str(caught.exception).startswith("KEV catalog cannot be read"))

    def test_catalog_version_rules(self) -> None:
        self.assert_each_refused(
            {
                "missing": with_root("catalogVersion", MISSING),
                "int": with_root("catalogVersion", 20260914),
                "null": with_root("catalogVersion", None),
                "list": with_root("catalogVersion", ["2026.09.14"]),
                "empty": with_root("catalogVersion", ""),
                "space": with_root("catalogVersion", "2026 09 14"),
                "65 characters": with_root("catalogVersion", "9" * 65),
                "newline": with_root("catalogVersion", "2026.09.14\n"),
                "non-ascii": with_root("catalogVersion", "\uff12\uff10\uff12\uff16.09.14"),
            },
            "catalogVersion",
        )

    def test_date_released_rules(self) -> None:
        self.assert_each_refused(
            {
                "missing": with_root("dateReleased", MISSING),
                "int": with_root("dateReleased", 20260914),
                "null": with_root("dateReleased", None),
                "list": with_root("dateReleased", ["2026-09-14T17:00:00Z"]),
                "basic": with_root("dateReleased", "20260914T170000Z"),
                "week": with_root("dateReleased", "2026-W38-1T17:00:00Z"),
                "space separated": with_root("dateReleased", "2026-09-14 17:00:00Z"),
                "hour only": with_root("dateReleased", "2026-09-14T17Z"),
                "comma fraction": with_root("dateReleased", "2026-09-14T17:00:00,1234Z"),
                "padded": with_root("dateReleased", " 2026-09-14T17:00:00Z "),
                "trailing newline": with_root("dateReleased", "2026-09-14T17:00:00Z\n"),
                "+0000": with_root("dateReleased", "2026-09-14T17:00:00+0000"),
                "seconds offset": with_root("dateReleased", "2026-09-14T17:00:00+05:30:15"),
                "no zone": with_root("dateReleased", "2026-09-14T17:00:00"),
                "date only": with_root("dateReleased", "2026-09-14"),
                "lowercase z": with_root("dateReleased", "2026-09-14T17:00:00z"),
                "ten fraction digits": with_root("dateReleased", "2026-09-14T17:00:00.1234567890Z"),
                "fullwidth digits": with_root("dateReleased", "\uff12026-09-14T17:00:00Z"),
                "impossible day": with_root("dateReleased", "2026-02-30T17:00:00Z"),
                "hour 24": with_root("dateReleased", "2026-09-14T24:00:00Z"),
                "leap second": with_root("dateReleased", "2026-12-31T23:59:60Z"),
                "offset 24 hours": with_root("dateReleased", "2026-09-14T17:00:00+24:00"),
                "year 1 east": with_root("dateReleased", "0001-01-01T00:00:00+01:00"),
                "year 9999 west": with_root("dateReleased", "9999-12-31T23:59:59-01:00"),
                "before 1970": with_root("dateReleased", "1969-12-31T23:59:59Z"),
                "after 9000": with_root("dateReleased", "9001-01-01T00:00:00Z"),
            },
            "dateReleased",
        )

    def test_an_overlong_date_released_is_refused_without_being_quoted(self) -> None:
        for value in ("2" * 65, "2" * (1024 * 1024)):
            with self.subTest(length=len(value)):
                message = self.assert_refused(with_root("dateReleased", value))
                self.assertIn("at most 64 characters", message)
                self.assertNotIn("2222", message)

    def test_count_rules(self) -> None:
        self.assert_each_refused(
            {
                "missing": with_root("count", MISSING),
                "bool": with_root("count", True),
                "string": with_root("count", "12"),
                "float": with_root("count", 12.0),
                "null": with_root("count", None),
                "negative": with_root("count", -1),
                "short": with_root("count", 11),
                "long": with_root("count", 13),
            },
            "count",
        )

    def test_vulnerabilities_rules(self) -> None:
        self.assert_each_refused(
            {
                "missing": with_root("vulnerabilities", MISSING),
                "object": with_root("vulnerabilities", {}),
                "string": with_root("vulnerabilities", "CVE-2099-0001"),
                "null": with_root("vulnerabilities", None),
            },
            "vulnerabilities",
        )

    def test_more_than_the_entry_bound_is_refused(self) -> None:
        entries = [minimal_entry(f"CVE-2099-{number:05d}") for number in range(MAX_KEV_ENTRIES + 1)]
        message = self.assert_refused(minimal_catalog(entries))
        self.assertIn(str(MAX_KEV_ENTRIES), message)

    def test_an_entry_that_is_not_an_object_is_refused(self) -> None:
        cases = {}
        for label, value in (("string", "CVE-2099-0001"), ("number", 5), ("null", None)):
            payload = fixture_payload()
            payload["vulnerabilities"][3] = value
            cases[label] = encoded(payload)
        self.assert_each_refused(cases, "vulnerabilities[3]: the entry must be an object")

    def test_cve_id_rules(self) -> None:
        self.assert_each_refused(
            {
                "missing": with_entry("cveID", MISSING),
                "int": with_entry("cveID", 20990001),
                "null": with_entry("cveID", None),
                "list": with_entry("cveID", ["CVE-2099-0006"]),
                "lowercase": with_entry("cveID", "cve-2099-0006"),
                "fullwidth letters": with_entry("cveID", "\uff23\uff36\uff25-2099-0006"),
                "fullwidth digits": with_entry("cveID", "CVE-\uff12\uff10\uff19\uff19-0006"),
                "newline terminated": with_entry("cveID", "CVE-2099-0006\n"),
                "leading space": with_entry("cveID", " CVE-2099-0006"),
                "3-digit sequence": with_entry("cveID", "CVE-2099-006"),
                "20-digit sequence": with_entry("cveID", "CVE-2099-" + "1" * 20),
                "2-digit year": with_entry("cveID", "CVE-99-0006"),
            },
            "vulnerabilities[0]: cveID",
        )

    def test_a_19_digit_sequence_is_accepted(self) -> None:
        catalog = parse_kev_catalog(
            minimal_catalog([minimal_entry("CVE-2099-" + "1" * 19)]), name="long.json"
        )
        self.assertEqual(catalog.entries[0].cve_id, "CVE-2099-" + "1" * 19)

    def test_date_rules_for_date_added_and_due_date(self) -> None:
        for key in ("dateAdded", "dueDate"):
            with self.subTest(key=key):
                self.assert_each_refused(
                    {
                        "missing": with_entry(key, MISSING),
                        "int": with_entry(key, 20260915),
                        "null": with_entry(key, None),
                        "list": with_entry(key, ["2026-09-15"]),
                        "basic": with_entry(key, "20260915"),
                        "week": with_entry(key, "2026-W38-2"),
                        "impossible": with_entry(key, "2026-02-30"),
                        "month 13": with_entry(key, "2026-13-01"),
                        "fullwidth digits": with_entry(key, "\uff12\uff10\uff12\uff16-09-15"),
                        "unpadded": with_entry(key, "2026-9-15"),
                        "with time": with_entry(key, "2026-09-15T00:00:00"),
                        "year 0": with_entry(key, "0000-01-01"),
                        "before 1970": with_entry(key, "1969-12-31"),
                        "year 9999": with_entry(key, "9999-12-31"),
                    },
                    f"vulnerabilities[0] (CVE-2099-0006): {key}",
                )

    def test_optional_label_rules(self) -> None:
        for key in ("knownRansomwareCampaignUse", "forensicTriage"):
            with self.subTest(key=key):
                self.assert_each_refused(
                    {
                        "null": with_entry(key, None),
                        "int": with_entry(key, 1),
                        "list": with_entry(key, ["Known"]),
                        "bool": with_entry(key, False),
                        "empty": with_entry(key, ""),
                        "33 characters": with_entry(key, "K" * 33),
                        "non-ascii": with_entry(key, "Kn\u00f6wn"),
                        "newline": with_entry(key, "Known\n"),
                        "tab": with_entry(key, "Yes\t"),
                    },
                    f"vulnerabilities[0] (CVE-2099-0006): {key}",
                )

    def test_a_repeated_cve_id_is_refused(self) -> None:
        message = self.assert_refused(with_entry("cveID", "CVE-2099-0006", index=4))
        self.assertIn(
            "vulnerabilities[4] (CVE-2099-0006): cveID repeats vulnerabilities[0]", message
        )

    def test_oversized_invalid_values_are_quoted_cut(self) -> None:
        huge = "C" * (1024 * 1024)
        for content in (
            with_entry("cveID", huge),
            with_root("catalogVersion", huge),
            with_entry("forensicTriage", huge),
        ):
            with self.subTest(size=len(content)):
                message = self.assert_refused(content)
                self.assertIn("...", message)
                self.assertNotIn("C" * 65, message)

    def test_a_huge_duplicate_key_is_not_echoed_whole(self) -> None:
        key = "k" * (1024 * 1024)
        content = b'{"' + key.encode() + b'": 1, "' + key.encode() + b'": 2}'
        message = self.assert_refused(content)
        self.assertNotIn("k" * 200, message)

    def test_a_control_character_in_a_duplicate_key_is_escaped(self) -> None:
        message = self.assert_refused(b'{"\\u001b[31m": 1, "\\u001b[31m": 2}')
        self.assertNotIn("\x1b", message)
        self.assertIn("\\x1b", message)

    def test_a_blank_name_is_refused(self) -> None:
        for name in ("", "   "):
            with self.subTest(name=name):
                with self.assertRaises(ReportInputError) as caught:
                    parse_kev_catalog(fixture_bytes(), name=name)
                self.assertTrue(str(caught.exception).startswith("KEV catalog"))


# *--- Matching and Instants ---*


class KevMatchingTests(unittest.TestCase):
    """Exact cveID matching, bounded by the date an entry was listed."""

    def setUp(self) -> None:
        self.catalog = fixture_catalog()

    def test_an_entry_added_on_the_date_matches_and_a_day_earlier_does_not(self) -> None:
        (entry,) = self.catalog.matches(["CVE-2099-0001"], on_or_before=date(2026, 8, 27))
        self.assertEqual(entry.cve_id, "CVE-2099-0001")
        self.assertEqual(
            self.catalog.matches(["CVE-2099-0001"], on_or_before=date(2026, 8, 26)), ()
        )

    def test_matches_sort_by_due_date_then_cve_id(self) -> None:
        found = self.catalog.matches(
            ["CVE-2099-0003", "CWE-22", "CVE-2099-0002", "GHSA-aaaa-bbbb-cccc", "CVE-2099-0001"],
            on_or_before=date(2026, 9, 15),
        )
        self.assertEqual(
            [entry.cve_id for entry in found], ["CVE-2099-0001", "CVE-2099-0002", "CVE-2099-0003"]
        )

    def test_a_due_date_tie_goes_to_the_lowest_cve_id(self) -> None:
        catalog = parse_kev_catalog(
            minimal_catalog(
                [
                    minimal_entry("CVE-2099-0200", due="2026-09-20"),
                    minimal_entry("CVE-2099-0100", due="2026-09-20"),
                    minimal_entry("CVE-2099-0300", due="2026-09-19"),
                ]
            ),
            name="tie.json",
        )
        found = catalog.matches(
            ["CVE-2099-0200", "CVE-2099-0100", "CVE-2099-0300"], on_or_before=date(2026, 9, 15)
        )
        self.assertEqual(
            [entry.cve_id for entry in found], ["CVE-2099-0300", "CVE-2099-0100", "CVE-2099-0200"]
        )

    def test_matching_is_exact(self) -> None:
        for identifier in (
            "cve-2099-0001",
            "CVE-2099-00001",
            "CVE-2099-0001 ",
            "CVE-2099-01",
            "GHSA-2099-0001",
        ):
            with self.subTest(identifier=identifier):
                self.assertEqual(
                    self.catalog.matches([identifier], on_or_before=date(2026, 9, 15)), ()
                )

    def test_an_identifier_repeated_on_a_record_matches_once(self) -> None:
        found = self.catalog.matches(
            ["CVE-2099-0001", "CVE-2099-0001"], on_or_before=date(2026, 9, 15)
        )
        self.assertEqual(len(found), 1)

    def test_considered_and_later_than_split_the_catalog_at_a_date(self) -> None:
        self.assertEqual(self.catalog.considered(date(2026, 9, 15)), 11)
        self.assertEqual(self.catalog.later_than(date(2026, 9, 15)), 1)
        self.assertEqual(self.catalog.considered(date(2026, 9, 20)), 12)
        self.assertEqual(self.catalog.later_than(date(2026, 9, 20)), 0)
        self.assertEqual(self.catalog.considered(date(2026, 3, 1)), 0)

    def test_the_due_instant_is_the_next_day_at_midnight_utc(self) -> None:
        self.assertEqual(due_instant(date(2026, 9, 10)), datetime(2026, 9, 11, tzinfo=UTC))
        self.assertEqual(due_instant(date(2026, 12, 31)), datetime(2027, 1, 1, tzinfo=UTC))
        self.assertEqual(due_instant(date(2028, 2, 28)), datetime(2028, 2, 29, tzinfo=UTC))
        self.assertEqual(start_instant(date(2026, 9, 10)), datetime(2026, 9, 10, tzinfo=UTC))
        self.assertIs(due_instant(date(2026, 9, 10)).tzinfo, UTC)

    def test_the_instants_and_the_clock_take_no_zone(self) -> None:
        self.assertEqual(list(inspect.signature(due_instant).parameters), ["day"])
        self.assertEqual(list(inspect.signature(start_instant).parameters), ["day"])
        self.assertEqual(
            list(inspect.signature(kev_clock).parameters), ["entries", "status", "as_of"]
        )


# *--- Clock ---*


class KevClockUnitTests(unittest.TestCase):
    """The stop set, the strict past-due gate, and the status precedence."""

    def setUp(self) -> None:
        entries = {entry.cve_id: entry for entry in fixture_catalog().entries}
        self.first = entries["CVE-2099-0001"]
        self.entries = entries

    def test_the_stop_set_is_remediation_and_false_positive(self) -> None:
        self.assertEqual(KEV_STOPS, frozenset({CaseStatus.REMEDIATED, CaseStatus.FALSE_POSITIVE}))

    def test_the_due_instant_itself_is_not_past_due_and_one_microsecond_later_is(self) -> None:
        at_due = kev_clock([self.first], status=None, as_of=self.first.due_at)
        self.assertFalse(at_due.past_due)
        self.assertIs(at_due.status, KevStatus.OPEN)
        later = kev_clock(
            [self.first], status=None, as_of=self.first.due_at + timedelta(microseconds=1)
        )
        self.assertTrue(later.past_due)
        self.assertIs(later.status, KevStatus.PAST_DUE)

    def test_every_status_maps_to_its_kev_status_and_booleans(self) -> None:
        after = self.first.due_at + timedelta(days=1)
        before = self.first.due_at - timedelta(days=1)
        expected: dict[CaseStatus | None, tuple[KevStatus, bool, bool, KevStatus]] = {
            None: (KevStatus.PAST_DUE, False, True, KevStatus.OPEN),
            CaseStatus.NEW: (KevStatus.PAST_DUE, False, True, KevStatus.OPEN),
            CaseStatus.EVALUATING: (KevStatus.PAST_DUE, False, True, KevStatus.OPEN),
            CaseStatus.ACTIVE: (KevStatus.PAST_DUE, False, True, KevStatus.OPEN),
            CaseStatus.PARTIALLY_MITIGATED: (KevStatus.PAST_DUE, False, True, KevStatus.OPEN),
            CaseStatus.FULLY_MITIGATED: (KevStatus.PAST_DUE, False, True, KevStatus.OPEN),
            CaseStatus.REMEDIATED: (KevStatus.REMEDIATED, True, False, KevStatus.REMEDIATED),
            CaseStatus.FALSE_POSITIVE: (
                KevStatus.FALSE_POSITIVE,
                True,
                False,
                KevStatus.FALSE_POSITIVE,
            ),
            CaseStatus.ACCEPTED: (KevStatus.ACCEPTED, False, True, KevStatus.ACCEPTED),
            # The compiler passes the resolved status; an unresolved `closed` stops nothing.
            CaseStatus.CLOSED: (KevStatus.PAST_DUE, False, True, KevStatus.OPEN),
        }
        self.assertEqual(set(expected) - {None}, set(CaseStatus))
        for status, (late, satisfied, past_due, early) in expected.items():
            with self.subTest(status=status):
                clock = kev_clock([self.first], status=status, as_of=after)
                self.assertIs(clock.status, late)
                self.assertEqual(clock.satisfied, satisfied)
                self.assertEqual(clock.past_due, past_due)
                ahead = kev_clock([self.first], status=status, as_of=before)
                self.assertIs(ahead.status, early)
                self.assertFalse(ahead.past_due)
                self.assertEqual(ahead.satisfied, satisfied)

    def test_the_clock_binds_to_the_earliest_due_date_then_the_lowest_cve_id(self) -> None:
        second, third = self.entries["CVE-2099-0002"], self.entries["CVE-2099-0003"]
        clock = kev_clock([third, second], status=None, as_of=RELEASED)
        self.assertEqual(clock.bound, second)
        self.assertEqual([entry.cve_id for entry in clock.entries], [second.cve_id, third.cve_id])
        self.assertEqual(clock.due_at, second.due_at)
        self.assertEqual(clock.start_at, second.start_at)
        tie = dataclasses.replace(third, due_date=second.due_date)
        clock = kev_clock([tie, second], status=None, as_of=RELEASED)
        self.assertEqual(clock.bound.cve_id, "CVE-2099-0002")

    def test_to_dict_names_the_bound_entry_and_lists_every_entry(self) -> None:
        clock = kev_clock(
            [self.entries["CVE-2099-0003"], self.entries["CVE-2099-0002"]],
            status=None,
            as_of=datetime(2026, 9, 15, 12, tzinfo=UTC),
        )
        self.assertEqual(
            clock.to_dict(),
            {
                "cveId": "CVE-2099-0002",
                "dueDate": "2026-09-22",
                "dueAt": "2026-09-23T00:00:00Z",
                "entries": [
                    self.entries["CVE-2099-0002"].to_dict(),
                    self.entries["CVE-2099-0003"].to_dict(),
                ],
                "pastDue": False,
                "satisfied": False,
                "status": "open",
            },
        )

    def test_a_clock_needs_an_entry(self) -> None:
        with self.assertRaises(ValueError):
            kev_clock([], status=None, as_of=RELEASED)

    def test_the_status_values_are_the_published_enum(self) -> None:
        self.assertEqual(
            [status.value for status in KevStatus],
            ["open", "pastDue", "accepted", "remediated", "falsePositive"],
        )


# *--- Truncated Identifiers ---*


class KevMatchIncompleteUnitTests(unittest.TestCase):
    """A CVE may be missing only when the identifier list was cut at or before `CVE-`."""

    CVES = tuple(f"CVE-2099-{number:04d}" for number in range(64))
    CVES_AND_CWES = ("CVE-2099-0001", "CVE-2099-0002", *(f"CWE-{n}" for n in range(62)))
    CUT = '["source_identifiers"]'

    def assert_missing(
        self, expected: bool, note: str | None, identifiers: tuple[str, ...]
    ) -> None:
        metadata = () if note is None else (("truncated", note),)
        observation = sarif_observation(source_metadata=metadata, source_identifiers=identifiers)
        self.assertIs(cve_may_be_missing(observation), expected)

    def test_a_cut_list_of_cves_may_be_missing_one(self) -> None:
        self.assert_missing(True, self.CUT, self.CVES)
        self.assert_missing(True, '["description","source_identifiers"]', self.CVES)

    def test_a_cut_list_ending_in_cwes_kept_every_cve(self) -> None:
        self.assert_missing(False, self.CUT, self.CVES_AND_CWES)
        self.assert_missing(False, self.CUT, ("GHSA-aaaa-bbbb-cccc",))

    def test_an_empty_cut_list_may_be_missing_one(self) -> None:
        self.assert_missing(True, self.CUT, ())

    def test_no_note_or_a_note_naming_other_fields_is_not_a_cut(self) -> None:
        self.assert_missing(False, None, self.CVES)
        self.assert_missing(False, "", self.CVES)
        self.assert_missing(False, '["description","title"]', self.CVES)

    def test_an_unreadable_note_fails_toward_the_warning(self) -> None:
        deep = "[" * 1000 + "]" * 1000
        oversized = json.dumps(["title"] * (MAX_TRUNCATED_METADATA_BYTES // 8))
        self.assertGreater(len(oversized), MAX_TRUNCATED_METADATA_BYTES)
        for label, note in (
            ("undecodable", "source_identifiers"),
            ("not a list", '{"source_identifiers": true}'),
            ("not strings", "[1, 2]"),
            ("over 4 KiB", oversized),
            ("1000 deep", deep),
        ):
            with self.subTest(note=label):
                self.assert_missing(True, note, self.CVES)

    def test_the_adapter_cut_is_the_one_the_check_reads(self) -> None:
        # The check depends on the adapter keeping the smallest identifiers; pin both sides.
        cases = (
            (tuple(f"CVE-2099-{n:04d}" for n in range(1, 71)), True),
            (("CVE-2099-0001", "CVE-2099-0002", *(f"CWE-{n}" for n in range(1, 71))), False),
        )
        for tags, expected in cases:
            with self.subTest(tags=len(tags), expected=expected):
                observation = tagged_sarif_observation(tags)
                self.assertIn(
                    "source_identifiers", json.loads(observation.metadata_value("truncated"))
                )
                self.assertEqual(len(observation.source_identifiers), 64)
                self.assertIs(cve_may_be_missing(observation), expected)


# *--- Report Fixtures ---*

EXAMPLES = REPO_ROOT / "examples"
KEV_ARTIFACTS = (FIXTURES / "kev-image-web.sarif", FIXTURES / "kev-image-worker.sarif")
KEV_EVALUATIONS = EXAMPLES / "evaluations-kev.json"
KEV_AS_OF = datetime(2026, 9, 15, 12, tzinfo=UTC)
#: The settings every KEV report test runs with, and the ones the goldens are cut at.
#: The shared `options()` defaults sit in August, where this catalog is released after
#: `as_of` and these fixtures compile nothing, so a KEV assertion on them would either
#: raise or pass on an empty report.
KEV_OVERRIDES: dict[str, Any] = {
    "as_of": KEV_AS_OF,
    "detected_at": None,
    "period_from": datetime(2026, 9, 1, tzinfo=UTC),
    "period_to": datetime(2026, 9, 30, 23, 59, 59, tzinfo=UTC),
}
WEB = "Trivy|images/web"
WORKER = "Trivy|images/worker"
#: Every fixture record by the label the plan gives it: its context key and source record.
KEV_LABELS = {
    "R1": (WEB, "CVE-2099-0001"),
    "R2": (WEB, "CVE-2099-0002"),
    "R3": (WEB, "CVE-2099-0004"),
    "R4": (WEB, "CVE-2099-0005"),
    "R5": (WEB, "CVE-2099-0006"),
    "R6": (WEB, "CVE-2099-0007"),
    "R7": (WEB, "CVE-2099-0100"),
    "R8": (WORKER, "CVE-2099-0001"),
    "R9": (WEB, "CVE-2099-0008"),
    "R10": (WEB, "CVE-2099-0009"),
    "R11": (WEB, "CVE-2099-0011"),
}
KEV_LINE_PREFIX = "- **Known exploited:** "


def fixture_entry(cve_id: str) -> Any:
    """Return one entry of the fixture catalog, whatever date it was added."""
    (entry,) = fixture_catalog().matches([cve_id], on_or_before=date(2099, 12, 31))
    return entry


def kev_report(
    *,
    kind: str = "vdt",
    catalog: KevCatalog | None = None,
    artifacts: Sequence[Path] = KEV_ARTIFACTS,
    evaluations: Path | None = KEV_EVALUATIONS,
    **overrides: Any,
) -> Any:
    """Compile one report over the KEV fixtures with the shared KEV settings."""
    parsed = None if evaluations is None else load_evaluations(evaluations)
    return compile_fixtures(
        artifacts=list(artifacts),
        evaluations=parsed,
        kind=kind,  # type: ignore[arg-type]
        **{**KEV_OVERRIDES, **overrides, "kev_catalog": catalog},
    )


def by_label(records: Sequence[Any]) -> dict[str, Any]:
    """Index compiled records by the label the plan's fixture table gives each one."""
    keyed = {(item.context_key, item.source_record_id): item for item in records}
    return {label: keyed[key] for label, key in KEV_LABELS.items() if key in keyed}


def kev_clause_of(record: Any) -> str:
    """Return the VDR-TFR-KEV clause out of a record's one overdue explanation."""
    explanation = record.overdue_explanation
    if "VDR-TFR-KEV (" not in explanation:
        raise AssertionError(f"{record.source_record_id} carries no KEV clause")
    tail = explanation.split("VDR-TFR-KEV (", 1)[1].split("Rules dataset commit", 1)[0]
    return f"VDR-TFR-KEV ({tail.strip()}"


def kev_deadline_of(record: Any) -> dict[str, Any]:
    """Return the one VDR-TFR-KEV deadline a record publishes."""
    found = [item for item in record.deadlines if item.rule_id == "VDR-TFR-KEV"]
    if len(found) != 1:
        raise AssertionError(f"{record.source_record_id} has {len(found)} KEV deadlines")
    return found[0].to_dict()


def known_exploited_lines(markdown: str) -> list[str]:
    """Return every Known exploited detail line of a Markdown twin, in document order."""
    return [
        line[len(KEV_LINE_PREFIX) :]
        for line in markdown.splitlines()
        if line.startswith(KEV_LINE_PREFIX)
    ]


def kev_evaluation(cve: str, completed: str, *, context: str = WEB, **extra: object) -> dict:
    """Return one evaluation entry for a KEV fixture record, with fields added."""
    entry: dict[str, object] = {
        "match": {"sourceRecordId": cve, "contextKey": context, "sourceType": "sarif"},
        "completedAt": completed,
        "isInternetReachable": False,
        "isLikelyExploitable": True,
        "pain": 2,
        "potentialAgencyImpact": "SYNTHETIC. The flawed package holds no agency data.",
        "rationale": "SYNTHETIC. The service is internal only and needs local access.",
        "evaluator": "Example Provider vulnerability team (synthetic KEV fixture)",
    }
    entry.update(extra)
    return entry


def write_evaluations(directory: Path, entries: Sequence[dict]) -> Path:
    """Write one evaluations file into a temporary directory and return its path."""
    path = directory / "evaluations.json"
    path.write_text(json.dumps({"evaluations": list(entries)}), encoding="utf-8")
    return path


def shifted_web_artifact(directory: Path, *, start: str, end: str) -> Path:
    """Write a copy of the web fixture whose one run ran at another instant."""
    payload = json.loads((FIXTURES / "kev-image-web.sarif").read_text(encoding="utf-8"))
    for run in payload["runs"]:
        for invocation in run["invocations"]:
            invocation["startTimeUtc"] = start
            invocation["endTimeUtc"] = end
    path = directory / "kev-image-web.sarif"
    path.write_text(json.dumps(payload), encoding="utf-8")
    return path


def tagged_web_artifact(directory: Path, tags: Sequence[str]) -> Path:
    """Write a copy of the web fixture whose first result carries extra identifiers."""
    payload = json.loads((FIXTURES / "kev-image-web.sarif").read_text(encoding="utf-8"))
    result = payload["runs"][0]["results"][0]
    result.setdefault("properties", {})["tags"] = list(tags)
    path = directory / "kev-image-web.sarif"
    path.write_text(json.dumps(payload), encoding="utf-8")
    return path


# *--- The Clock In A Report ---*


class KevReportClockTests(unittest.TestCase):
    """The clock as the three projections publish it, over the plan's fixture table."""

    @classmethod
    def setUpClass(cls) -> None:
        cls.catalog = fixture_catalog()
        cls.vdt = kev_report(catalog=cls.catalog)
        cls.avi = kev_report(kind="avi", catalog=cls.catalog)
        cls.historical = kev_report(kind="historical", catalog=cls.catalog)
        cls.records = by_label(cls.vdt.vulnerabilities)
        cls.accepted = by_label([item.vulnerability for item in cls.avi.accepted])

    def test_every_reported_record_carries_the_clock_the_plan_names(self) -> None:
        expected = {
            "R1": ("pastDue", True, False, True),
            "R2": ("open", False, False, True),
            "R3": ("pastDue", True, False, True),
            "R4": ("remediated", False, True, False),
            "R6": ("falsePositive", False, True, False),
            "R8": ("pastDue", True, False, True),
            "R10": ("pastDue", True, False, True),
            "R11": ("pastDue", True, False, True),
        }
        self.assertEqual(sorted(self.records), sorted([*expected, "R7", "R9"]))
        for label, (status, past_due, satisfied, overdue) in expected.items():
            with self.subTest(record=label):
                record = self.records[label]
                self.assertIsNotNone(record.kev)
                self.assertEqual(record.kev.status.value, status)
                self.assertEqual(record.kev.past_due, past_due)
                self.assertEqual(record.kev.satisfied, satisfied)
                self.assertEqual(record.is_overdue, overdue)
        for label in ("R7", "R9"):
            with self.subTest(record=label):
                self.assertTrue(self.records[label].kev_checked)
                self.assertIsNone(self.records[label].kev)
                self.assertFalse(self.records[label].is_overdue)

    def test_a_mitigation_does_not_stop_the_clock_but_a_disposition_does(self) -> None:
        # VDR-TFR-KEV runs "even if the vulnerability has been fully mitigated"; remediation
        # and a false positive stop it, so neither R4 nor R6 is past due (ADR 0012).
        mitigation = "A recorded mitigation does not stop this clock."
        self.assertIn(mitigation, kev_clause_of(self.records["R3"]))
        for label in ("R4", "R6"):
            with self.subTest(record=label):
                record = self.records[label]
                self.assertTrue(kev_deadline_of(record)["satisfied"])
                self.assertEqual(record.to_official_dict()["overdueStatus"], {"isOverdue": False})

    def test_an_accepted_record_keeps_its_clock_and_is_never_officially_overdue(self) -> None:
        record = self.accepted["R5"]
        self.assertEqual(record.kev.status.value, "accepted")
        self.assertTrue(record.kev.past_due)
        self.assertFalse(record.kev.satisfied)
        self.assertFalse(record.is_overdue)
        detail = self.avi.document["acceptedVulnerabilities"][0]["vulnerabilityDetail"]
        self.assertEqual(detail["overdueStatus"], {"isOverdue": False})
        self.assertFalse(kev_deadline_of(record)["satisfied"])

    def test_the_summary_rows_count_the_past_due_boolean_not_the_status(self) -> None:
        expected = {
            "vdt": (self.vdt, 6, 8, 5),
            "avi": (self.avi, 0, 1, 1),
            "historical": (self.historical, 6, 8, 5),
        }
        for kind, (report, overdue, known, past_due) in expected.items():
            with self.subTest(report=kind):
                counts = summary_counts(report.to_markdown())
                self.assertEqual(counts["Overdue"], overdue)
                self.assertEqual(counts["Known exploited, CISA KEV"], known)
                self.assertEqual(counts["Past a CISA KEV due date"], past_due)

    def test_one_cve_on_two_records_gives_each_its_own_clock(self) -> None:
        first, second = self.records["R1"], self.records["R8"]
        self.assertNotEqual(first.tracking_id, second.tracking_id)
        self.assertEqual(first.kev.to_dict(), second.kev.to_dict())
        self.assertEqual(kev_deadline_of(first), kev_deadline_of(second))

    def test_a_record_with_two_matched_entries_binds_to_the_earliest_due_date(self) -> None:
        clock = self.records["R2"].kev
        self.assertEqual(
            [entry.cve_id for entry in clock.entries], ["CVE-2099-0002", "CVE-2099-0003"]
        )
        self.assertEqual(clock.bound.cve_id, "CVE-2099-0002")

    def test_the_evu_clause_precedes_the_kev_clause_in_one_explanation(self) -> None:
        record = self.records["R11"]
        self.assertEqual(
            [item.rule_id for item in record.deadlines], ["VER-TFR-EVU", "VDR-TFR-KEV"]
        )
        explanation = record.overdue_explanation
        self.assertLess(explanation.index("VER-TFR-EVU ("), explanation.index("VDR-TFR-KEV ("))
        self.assertEqual(record.to_official_dict()["overdueStatus"]["explanation"], explanation)

    def test_the_detection_sentence_appears_only_when_the_due_date_had_passed(self) -> None:
        sentence = "The due date had passed before detection at 2026-09-02T10:15:00Z."
        self.assertIn(sentence, kev_clause_of(self.records["R10"]))
        for label in ("R1", "R3", "R8", "R11"):
            with self.subTest(record=label):
                self.assertNotIn("before detection", kev_clause_of(self.records[label]))

    def test_the_clause_names_the_catalog_version_release_and_due_date(self) -> None:
        self.assertEqual(
            kev_clause_of(self.records["R1"]),
            "VDR-TFR-KEV (SHOULD, Class C): the CISA KEV catalog (version 2026.09.14, "
            "released 2026-09-14T17:00:00.123400Z) lists CVE-2099-0001 with due date "
            "2026-09-10, which ended 2026-09-11T00:00:00Z with no remediation recorded.",
        )

    def test_the_kev_deadline_publishes_the_catalog_anchor_and_a_null_timeframe(self) -> None:
        self.assertEqual(
            kev_deadline_of(self.records["R1"]),
            {
                "ruleId": "VDR-TFR-KEV",
                "ruleName": "Remediate KEVs",
                "force": "SHOULD",
                "anchor": "catalog",
                "startAt": "2026-08-27T00:00:00Z",
                "dueAt": "2026-09-11T00:00:00Z",
                "satisfied": False,
                "timeframe": None,
            },
        )

    def test_the_report_extension_names_the_catalog_by_digest(self) -> None:
        expected = {
            "name": "kev-catalog.json",
            "sha256": self.catalog.sha256,
            "sizeBytes": KEV_CATALOG.stat().st_size,
            "catalogVersion": "2026.09.14",
            "dateReleased": "2026-09-14T17:00:00.123400Z",
            "count": 12,
            "entriesConsidered": 11,
        }
        for kind, report in (("vdt", self.vdt), ("avi", self.avi), ("historical", self.historical)):
            with self.subTest(report=kind):
                self.assertEqual(report.document["x-complyroll"]["kevSource"], expected)

    def test_the_provenance_row_carries_the_catalog_and_its_digest(self) -> None:
        row = (
            "| KEV catalog | kev-catalog.json, CISA KEV catalog version 2026.09.14, released "
            f"2026-09-14T17:00:00.123400Z, 11 entries | {self.catalog.sha256} |"
        )
        for kind, report in (("vdt", self.vdt), ("avi", self.avi), ("historical", self.historical)):
            with self.subTest(report=kind):
                self.assertIn(row, report.to_markdown().splitlines())

    def test_the_record_extension_publishes_the_clock_and_nulls_an_unmatched_one(self) -> None:
        by_tracking = {
            item["providerTrackingId"]: item["x-complyroll"]
            for item in self.vdt.document["vulnerabilities"]
        }
        self.assertEqual(
            by_tracking[self.records["R1"].tracking_id]["kev"], self.records["R1"].kev.to_dict()
        )
        self.assertIsNone(by_tracking[self.records["R7"].tracking_id]["kev"])
        self.assertIn("kev", by_tracking[self.records["R7"].tracking_id])

    def test_every_projection_writes_one_known_exploited_line_per_record(self) -> None:
        self.assertEqual(len(known_exploited_lines(self.vdt.to_markdown())), 10)
        self.assertEqual(len(known_exploited_lines(self.avi.to_markdown())), 1)
        self.assertEqual(len(known_exploited_lines(self.historical.to_markdown())), 11)

    def test_the_known_exploited_line_names_every_entry_then_the_bound_clock(self) -> None:
        found = {
            record.tracking_id: line
            for record, line in zip(
                self.vdt.vulnerabilities,
                known_exploited_lines(self.vdt.to_markdown()),
                strict=True,
            )
        }
        expected = {
            "R1": "CVE-2099-0001 (added 2026-08-27, due 2026-09-10, ransomware use Known, "
            "forensic triage No); the clock follows CVE-2099-0001, due date 2026-09-10 "
            "ended 2026-09-11T00:00:00Z; past due",
            "R2": "CVE-2099-0002 (added 2026-09-08, due 2026-09-22, ransomware use Unknown, "
            "forensic triage No), CVE-2099-0003 (added 2026-09-10, due 2026-09-24, "
            "ransomware use Unknown, forensic triage Yes); the clock follows CVE-2099-0002, "
            "due date 2026-09-22 ends 2026-09-23T00:00:00Z; open",
            "R4": "CVE-2099-0005 (added 2026-08-25, due 2026-09-08, ransomware use Known, "
            "forensic triage No); the clock follows CVE-2099-0005, due date 2026-09-08 "
            "ended 2026-09-09T00:00:00Z; stopped by remediation",
            "R6": "CVE-2099-0007 (added 2026-09-01, due 2026-09-04, ransomware use Unknown, "
            "forensic triage No); the clock follows CVE-2099-0007, due date 2026-09-04 "
            "ended 2026-09-05T00:00:00Z; stopped as a false positive",
            "R7": "no entry in the supplied CISA KEV catalog dated on or before 2026-09-15",
            "R9": "no entry in the supplied CISA KEV catalog dated on or before 2026-09-15",
        }
        for label, line in expected.items():
            with self.subTest(record=label):
                self.assertEqual(found[self.records[label].tracking_id], line)
        self.assertEqual(
            known_exploited_lines(self.avi.to_markdown())[0],
            "CVE-2099-0006 (added 2026-08-10, due 2026-08-31, ransomware use Unknown, "
            "forensic triage No); the clock follows CVE-2099-0006, due date 2026-08-31 "
            "ended 2026-09-01T00:00:00Z; accepted, past due",
        )

    def test_an_absent_optional_catalog_field_renders_n_a(self) -> None:
        clock = kev_clock([fixture_entry("CVE-2099-0010")], status=None, as_of=KEV_AS_OF)
        self.assertIn("forensic triage n/a", _kev_line(clock, KEV_AS_OF))

    def test_every_markdown_tail_and_verb_is_fixed_by_status(self) -> None:
        entry = fixture_entry("CVE-2099-0001")
        before = entry.due_at - timedelta(days=1)
        after = entry.due_at + timedelta(days=1)
        cases = (
            (None, before, "ends", "open"),
            (None, after, "ended", "past due"),
            (CaseStatus.ACCEPTED, before, "ends", "accepted"),
            (CaseStatus.ACCEPTED, after, "ended", "accepted, past due"),
            (CaseStatus.REMEDIATED, after, "ended", "stopped by remediation"),
            (CaseStatus.FALSE_POSITIVE, after, "ended", "stopped as a false positive"),
        )
        for status, as_of, verb, tail in cases:
            with self.subTest(status=status, tail=tail):
                clock = kev_clock([entry], status=status, as_of=as_of)
                line = _kev_line(clock, as_of)
                self.assertTrue(line.endswith(f"; {tail}"), line)
                self.assertIn(f"due date 2026-09-10 {verb} 2026-09-11T00:00:00Z", line)

    def test_the_mitigation_sentence_marks_a_mitigation_and_nothing_else(self) -> None:
        entry = fixture_entry("CVE-2099-0001")
        report_options = options(**KEV_OVERRIDES)
        rule = select_policy(load_bundled_rule_source_snapshot(), report_options.profile).rule(
            "VDR-TFR-KEV"
        )
        mitigated = {CaseStatus.PARTIALLY_MITIGATED, CaseStatus.FULLY_MITIGATED}
        sentence = " A recorded mitigation does not stop this clock."
        for status in (None, *CaseStatus):
            with self.subTest(status=status):
                clock = kev_clock([entry], status=status, as_of=KEV_AS_OF)
                clause = _kev_clause(
                    clock, rule, self.catalog, report_options, entry.start_at, status
                )
                self.assertIs(clause.endswith(sentence), status in mitigated)

    def test_the_calendar_zone_never_moves_the_kev_parts_of_a_report(self) -> None:
        # Whole reports differ by design: both print calendarTimezone, and the month
        # deadlines are calendar arithmetic in the zone.
        for zone in ("America/Phoenix", "Pacific/Kiritimati"):
            with self.subTest(zone=zone):
                shifted = by_label(
                    kev_report(catalog=self.catalog, calendar_timezone=zone).vulnerabilities
                )
                self.assertEqual(sorted(shifted), sorted(self.records))
                for label, record in self.records.items():
                    other = shifted[label]
                    self.assertEqual(
                        None if record.kev is None else record.kev.to_dict(),
                        None if other.kev is None else other.kev.to_dict(),
                    )
                    if record.kev is not None:
                        self.assertEqual(kev_deadline_of(record), kev_deadline_of(other))
                    if "VDR-TFR-KEV (" in record.overdue_explanation:
                        self.assertEqual(kev_clause_of(record), kev_clause_of(other))


class KevRuleSelectionTests(unittest.TestCase):
    """A run with a catalog needs VDR-TFR-KEV; a run without one never asks for it."""

    def test_a_policy_without_the_rule_stops_the_run(self) -> None:
        profile = options(**KEV_OVERRIDES).profile
        policy = select_policy(load_bundled_rule_source_snapshot(), profile)
        stripped = dataclasses.replace(
            policy, rules=tuple(item for item in policy.rules if item.rule_id != "VDR-TFR-KEV")
        )
        with self.assertRaises(ReportCompileError) as caught:
            _kev_rule(stripped)
        (diagnostic,) = caught.exception.diagnostics
        self.assertEqual(diagnostic.code, "kev_rule_unavailable")
        self.assertEqual(diagnostic.level.value, "error")
        self.assertIn("VDR-TFR-KEV", diagnostic.message)

    def test_both_supported_classes_select_the_rule(self) -> None:
        for certification_class in (CertificationClass.B, CertificationClass.C):
            with self.subTest(certification_class=certification_class):
                profile = options(certification_class=certification_class, **KEV_OVERRIDES).profile
                policy = select_policy(load_bundled_rule_source_snapshot(), profile)
                self.assertEqual(_kev_rule(policy).rule_id, "VDR-TFR-KEV")


# *--- Diagnostics ---*


class KevDiagnosticsTests(unittest.TestCase):
    """Every KEV note the compiler raises, each isolated from the others."""

    def codes(self, report: Any) -> list[str]:
        return [item.code for item in report.diagnostics if item.code.startswith("kev_")]

    def note(self, report: Any, code: str) -> Any:
        found = [item for item in report.diagnostics if item.code == code]
        if len(found) != 1:
            raise AssertionError(f"{code} raised {len(found)} times, not once")
        return found[0]

    def test_a_catalog_released_after_as_of_stops_the_run(self) -> None:
        catalog = fixture_catalog()
        with self.assertRaises(ReportCompileError) as caught:
            kev_report(catalog=catalog, as_of=datetime(2026, 9, 14, 16, 59, 59, tzinfo=UTC))
        (diagnostic,) = caught.exception.diagnostics
        self.assertEqual(diagnostic.code, "kev_catalog_after_as_of")
        self.assertEqual(diagnostic.level.value, "error")
        self.assertEqual(diagnostic.location, f"sha256:{catalog.sha256}")
        self.assertIn("released 2026-09-14T17:00:00.123400Z", diagnostic.message)
        self.assertIn("after as_of 2026-09-14T16:59:59Z", diagnostic.message)

    def test_a_catalog_released_exactly_at_as_of_is_accepted(self) -> None:
        report = kev_report(catalog=fixture_catalog(), as_of=RELEASED)
        self.assertNotIn("kev_catalog_after_as_of", self.codes(report))

    def test_a_catalog_older_than_the_stale_window_warns(self) -> None:
        report = kev_report(catalog=fixture_catalog(), as_of=datetime(2026, 9, 20, 12, tzinfo=UTC))
        note = self.note(report, "kev_catalog_stale")
        self.assertEqual(note.level.value, "warning")
        self.assertEqual(
            note.message,
            "the CISA KEV catalog was released 2026-09-14T17:00:00.123400Z, more than 3 days "
            "before as_of 2026-09-20T12:00:00Z; entries CISA added since its release are not "
            "applied",
        )

    def test_the_stale_window_turns_over_one_second_past_three_days(self) -> None:
        boundary = RELEASED + KEV_STALE_AFTER
        cases = (
            ("inside it", boundary - timedelta(days=1), False),
            ("exactly three days", boundary, False),
            ("one second later", boundary + timedelta(seconds=1), True),
        )
        for label, as_of, stale in cases:
            with self.subTest(case=label):
                report = kev_report(catalog=fixture_catalog(), as_of=as_of)
                self.assertIs("kev_catalog_stale" in self.codes(report), stale)

    def test_entries_dated_after_as_of_are_counted_not_applied(self) -> None:
        report = kev_report(catalog=fixture_catalog())
        note = self.note(report, "kev_entries_after_as_of")
        self.assertEqual(note.level.value, "info")
        self.assertEqual(
            note.message,
            "1 catalog entry dated after 2026-09-15 was not applied; 1 compiled record carries it",
        )
        # CVE-2099-0008 is that entry, and R9 is the record that carries it.
        self.assertIsNone(by_label(report.vulnerabilities)["R9"].kev)

    def test_records_without_any_cve_identifier_raise_one_note(self) -> None:
        # The STIG fixtures carry STIG rule ids, never CVEs. This catalog sits well
        # inside the stale window at the shared August `as_of` and adds nothing after
        # it, so neither of the other catalog-level notes can also fire here.
        catalog = parse_kev_catalog(
            minimal_catalog(
                [minimal_entry("CVE-2099-7777", added="2026-08-01", due="2026-08-15")],
                released="2026-08-20T00:00:00Z",
            ),
            name="kev-catalog.json",
        )
        report = compile_fixtures(kev_catalog=catalog)
        self.assertEqual(self.codes(report), ["kev_no_cve_identifiers"])
        note = self.note(report, "kev_no_cve_identifiers")
        self.assertEqual(note.level.value, "info")
        self.assertEqual(note.location, f"sha256:{catalog.sha256}")
        self.assertTrue(all(item.kev is None for item in report.vulnerabilities))
        self.assertTrue(all(item.kev_checked for item in report.vulnerabilities))

    def test_cve_records_that_match_nothing_raise_the_other_note(self) -> None:
        catalog = parse_kev_catalog(
            minimal_catalog([minimal_entry("CVE-2099-7777")]), name="kev-catalog.json"
        )
        report = kev_report(catalog=catalog)
        self.assertEqual(self.codes(report), ["kev_no_matches"])
        self.assertEqual(
            self.note(report, "kev_no_matches").message,
            "11 compiled records carry CVE identifiers, and none matched a CISA KEV catalog "
            "entry dated on or before 2026-09-15",
        )

    def test_one_match_silences_the_no_matches_note(self) -> None:
        catalog = parse_kev_catalog(
            minimal_catalog([minimal_entry("CVE-2099-0001")]), name="kev-catalog.json"
        )
        report = kev_report(catalog=catalog)
        self.assertEqual(self.codes(report), [])

    def test_a_record_whose_identifiers_were_cut_warns_once(self) -> None:
        tags = [f"CVE-2099-{1000 + index}" for index in range(70)]
        with tempfile.TemporaryDirectory() as directory:
            artifact = tagged_web_artifact(Path(directory), tags)
            report = kev_report(catalog=fixture_catalog(), artifacts=[artifact, KEV_ARTIFACTS[1]])
        record = by_label(report.vulnerabilities)["R1"]
        note = self.note(report, "kev_match_incomplete")
        self.assertEqual(note.level.value, "warning")
        self.assertEqual(note.location, "CVE-2099-0001")
        self.assertEqual(
            note.message,
            f"{record.tracking_id} groups an observation whose source identifiers were cut at "
            "the adapter's limit, and a CVE may be among those dropped, so a CISA KEV entry "
            "for it cannot be matched",
        )
        # The cut does not stop the identifiers that survived from matching.
        self.assertEqual(record.kev.bound.cve_id, "CVE-2099-0001")

    def test_catalog_notes_precede_record_notes_and_locate_differently(self) -> None:
        tags = [f"CVE-2099-{1000 + index}" for index in range(70)]
        with tempfile.TemporaryDirectory() as directory:
            artifact = tagged_web_artifact(Path(directory), tags)
            report = kev_report(
                catalog=fixture_catalog(),
                artifacts=[artifact, KEV_ARTIFACTS[1]],
                as_of=datetime(2026, 9, 20, 12, tzinfo=UTC),
            )
        self.assertEqual(self.codes(report), ["kev_catalog_stale", "kev_match_incomplete"])
        stale, incomplete = (self.note(report, code) for code in self.codes(report))
        self.assertTrue(stale.location.startswith("sha256:"))
        self.assertEqual(incomplete.location, "CVE-2099-0001")

    def test_the_same_bytes_under_another_name_raise_the_same_location(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            copy = Path(directory) / "elsewhere.json"
            copy.write_bytes(KEV_CATALOG.read_bytes())
            renamed = load_kev_catalog(copy)
        report = kev_report(catalog=renamed)
        original = kev_report(catalog=fixture_catalog())
        self.assertEqual(renamed.name, "elsewhere.json")
        self.assertEqual(
            [(item.code, item.location) for item in report.diagnostics],
            [(item.code, item.location) for item in original.diagnostics],
        )
        # Only `kevSource.name` tells the two runs apart.
        self.assertNotEqual(
            report.document["x-complyroll"]["kevSource"],
            original.document["x-complyroll"]["kevSource"],
        )
        self.assertEqual(
            report.document["x-complyroll"]["kevSource"] | {"name": "kev-catalog.json"},
            original.document["x-complyroll"]["kevSource"],
        )

    def test_every_projection_raises_the_same_kev_notes(self) -> None:
        catalog = fixture_catalog()
        expected = self.codes(kev_report(catalog=catalog))
        for kind in ("avi", "historical"):
            with self.subTest(report=kind):
                self.assertEqual(self.codes(kev_report(kind=kind, catalog=catalog)), expected)


# *--- Period Selection ---*


class KevSelectionTests(unittest.TestCase):
    """An open KEV clock keeps quiet work in the Vulnerability Detail Report."""

    AUGUST = {
        "period_from": datetime(2026, 8, 1, tzinfo=UTC),
        "period_to": datetime(2026, 8, 31, 23, 59, 59, tzinfo=UTC),
    }

    def quiet_report(self, *, directory: Path, disposition: str, **overrides: Any) -> Any:
        """Compile a September report over work whose only activity was in August."""
        artifact = shifted_web_artifact(
            directory, start="2026-08-02T10:15:00Z", end="2026-08-02T10:16:30Z"
        )
        evaluations = write_evaluations(
            directory,
            [
                kev_evaluation("CVE-2099-0004", "2026-08-05T12:00:00Z", disposition=disposition),
            ],
        )
        return kev_report(
            artifacts=[artifact], evaluations=evaluations, detected_at=None, **overrides
        )

    def excluded(self, report: Any) -> set[str]:
        return {item.location for item in report.diagnostics if item.code == "excluded_by_period"}

    def test_an_open_kev_clock_keeps_a_record_the_period_would_drop(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            without = self.quiet_report(
                directory=Path(directory), disposition="fully_mitigated", catalog=None
            )
            with_catalog = self.quiet_report(
                directory=Path(directory),
                disposition="fully_mitigated",
                catalog=fixture_catalog(),
            )
        self.assertIn("CVE-2099-0004", self.excluded(without))
        self.assertNotIn("CVE-2099-0004", self.excluded(with_catalog))
        kept = by_label(with_catalog.vulnerabilities)["R3"]
        self.assertEqual(kept.kev.status.value, "pastDue")
        self.assertFalse(kept.kev.satisfied)

    def test_a_stopped_kev_clock_keeps_nothing(self) -> None:
        for disposition in ("remediated", "false_positive"):
            with self.subTest(disposition=disposition), tempfile.TemporaryDirectory() as directory:
                report = self.quiet_report(
                    directory=Path(directory),
                    disposition=disposition,
                    catalog=fixture_catalog(),
                )
                self.assertIn("CVE-2099-0004", self.excluded(report))

    def test_an_entry_listed_after_the_period_end_keeps_nothing(self) -> None:
        # CVE-2099-0002 was added 2026-09-08, after this August period ended, so an
        # August report must not pull it in; CVE-2099-0004 was added 2026-08-20.
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory)
            artifact = shifted_web_artifact(
                path, start="2026-07-02T10:15:00Z", end="2026-07-02T10:16:30Z"
            )
            evaluations = write_evaluations(
                path,
                [
                    kev_evaluation(
                        "CVE-2099-0002", "2026-07-05T12:00:00Z", disposition="fully_mitigated"
                    ),
                    kev_evaluation(
                        "CVE-2099-0004", "2026-07-05T12:00:00Z", disposition="fully_mitigated"
                    ),
                ],
            )
            report = kev_report(
                artifacts=[artifact],
                evaluations=evaluations,
                catalog=fixture_catalog(),
                detected_at=None,
                **self.AUGUST,
            )
        self.assertIn("CVE-2099-0002", self.excluded(report))
        self.assertNotIn("CVE-2099-0004", self.excluded(report))

    def test_a_record_detected_after_the_period_end_keeps_nothing(self) -> None:
        # The fixtures are detected 2026-09-02, so an August report cannot keep them
        # however open their KEV clocks are.
        report = kev_report(catalog=fixture_catalog(), **self.AUGUST)
        self.assertEqual(report.vulnerabilities, ())
        self.assertTrue(self.excluded(report))

    def test_the_avi_and_historical_selections_never_read_the_clock(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory)
            artifact = shifted_web_artifact(
                path, start="2026-08-02T10:15:00Z", end="2026-08-02T10:16:30Z"
            )
            evaluations = write_evaluations(
                path,
                [
                    kev_evaluation(
                        "CVE-2099-0004", "2026-08-05T12:00:00Z", disposition="fully_mitigated"
                    ),
                ],
            )
            shared = {"artifacts": [artifact], "evaluations": evaluations, "detected_at": None}
            for kind in ("avi", "historical"):
                with self.subTest(report=kind):
                    without = kev_report(kind=kind, catalog=None, **shared)
                    with_catalog = kev_report(kind=kind, catalog=fixture_catalog(), **shared)
                    self.assertEqual(self.excluded(with_catalog), self.excluded(without))

    def test_the_avi_still_excludes_an_accepted_record_quiet_through_the_period(self) -> None:
        # CVE-2099-0006 is past its KEV due date and accepted, so its clock is neither
        # satisfied nor stopped; the AVI drops it anyway because it was quiet in August.
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory)
            artifact = shifted_web_artifact(
                path, start="2026-08-02T10:15:00Z", end="2026-08-02T10:16:30Z"
            )
            evaluations = write_evaluations(
                path,
                [
                    kev_evaluation(
                        "CVE-2099-0006",
                        "2026-08-05T12:00:00Z",
                        disposition="accepted",
                        acceptanceRationale=(
                            "SYNTHETIC. The flaw is accepted for one release cycle."
                        ),
                    ),
                ],
            )
            report = kev_report(
                kind="avi",
                artifacts=[artifact],
                evaluations=evaluations,
                catalog=fixture_catalog(),
                period_from=datetime(2026, 7, 1, tzinfo=UTC),
                period_to=datetime(2026, 7, 31, 23, 59, 59, tzinfo=UTC),
            )
        self.assertEqual(report.accepted, ())
        self.assertIn("CVE-2099-0006", self.excluded(report))


# *--- Without A Catalog ---*


class KevWithoutCatalogTests(unittest.TestCase):
    """A run with no catalog publishes nothing about the KEV catalog at all."""

    def test_no_catalog_leaves_the_record_extension_untouched(self) -> None:
        report = kev_report()
        self.assertEqual(len(report.vulnerabilities), 10)
        for record in report.vulnerabilities:
            with self.subTest(record=record.source_record_id):
                self.assertFalse(record.kev_checked)
                self.assertIsNone(record.kev)
                self.assertNotIn("kev", record.to_official_dict()["x-complyroll"])
                self.assertNotIn("VDR-TFR-KEV", [item.rule_id for item in record.deadlines])

    def test_no_catalog_leaves_the_report_extension_and_markdown_untouched(self) -> None:
        for kind in ("vdt", "avi", "historical"):
            with self.subTest(report=kind):
                report = kev_report(kind=kind)
                self.assertTrue(_tracking_ids(_published(report.document)))
                self.assertNotIn("kevSource", report.document["x-complyroll"])
                markdown = report.to_markdown()
                self.assertEqual(known_exploited_lines(markdown), [])
                self.assertNotIn("KEV catalog", markdown)
                self.assertNotIn("Known exploited, CISA KEV", markdown)
                self.assertNotIn("Past a CISA KEV due date", markdown)

    def test_no_catalog_raises_no_kev_diagnostic(self) -> None:
        for kind in ("vdt", "avi", "historical"):
            with self.subTest(report=kind):
                report = kev_report(kind=kind)
                self.assertEqual(
                    [item.code for item in report.diagnostics if item.code.startswith("kev_")], []
                )

    def test_a_catalog_of_the_wrong_type_is_refused_when_the_options_are_built(self) -> None:
        for value in (KEV_CATALOG, str(KEV_CATALOG), KEV_CATALOG.read_bytes(), object()):
            with self.subTest(value=type(value).__name__), self.assertRaises(TypeError):
                options(kev_catalog=value)  # type: ignore[arg-type]


# *--- Document Order ---*


class KevOrderTests(unittest.TestCase):
    """The KEV additions never move a record, a row or a key that was there before."""

    @classmethod
    def setUpClass(cls) -> None:
        cls.catalog = fixture_catalog()

    def test_a_catalog_never_reorders_the_records_of_a_report(self) -> None:
        for kind, keys in (
            ("vdt", ("vulnerabilities",)),
            ("avi", ("acceptedVulnerabilities",)),
            ("historical", ("activeVulnerabilities", "acceptedVulnerabilities")),
        ):
            without = kev_report(kind=kind)
            with_catalog = kev_report(kind=kind, catalog=self.catalog)
            for key in keys:
                with self.subTest(report=kind, array=key):
                    self.assertEqual(
                        _tracking_ids(without.document[key]),
                        _tracking_ids(with_catalog.document[key]),
                    )
                    self.assertTrue(_tracking_ids(without.document[key]))

    def test_a_catalog_adds_keys_and_changes_nothing_else_in_the_json(self) -> None:
        without = kev_report().document
        with_catalog = kev_report(catalog=self.catalog).document
        self.assertEqual(
            set(with_catalog["x-complyroll"]) - set(without["x-complyroll"]), {"kevSource"}
        )
        for before, after in zip(
            without["vulnerabilities"], with_catalog["vulnerabilities"], strict=True
        ):
            with self.subTest(record=before["providerTrackingId"]):
                self.assertEqual(list(before), list(after))
                extension = after["x-complyroll"]
                self.assertEqual(
                    list(before["x-complyroll"]) + ["kev"],
                    [key for key in extension if key != "kev"] + ["kev"],
                )
                self.assertEqual(
                    [item for item in extension["deadlines"] if item["ruleId"] != "VDR-TFR-KEV"],
                    before["x-complyroll"]["deadlines"],
                )

    def test_the_artifact_order_never_moves_a_byte(self) -> None:
        forward = kev_report(catalog=self.catalog)
        backward = kev_report(catalog=self.catalog, artifacts=tuple(reversed(KEV_ARTIFACTS)))
        self.assertEqual(backward.to_json(), forward.to_json())
        self.assertEqual(backward.to_markdown(), forward.to_markdown())

    def test_a_permuted_catalog_changes_only_its_digest(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            permuted = load_kev_catalog(permuted_catalog(Path(directory)))
        self.assertEqual(permuted.entries, self.catalog.entries)
        self.assertNotEqual(permuted.sha256, self.catalog.sha256)
        self.assertNotEqual(permuted, self.catalog)

        original = kev_report(catalog=self.catalog)
        other = kev_report(catalog=permuted)
        for first, second in zip(original.vulnerabilities, other.vulnerabilities, strict=True):
            with self.subTest(record=first.source_record_id):
                self.assertEqual(first.source_record_id, second.source_record_id)
                self.assertEqual(
                    None if first.kev is None else first.kev.to_dict(),
                    None if second.kev is None else second.kev.to_dict(),
                )
                self.assertEqual(
                    [item.to_dict() for item in first.deadlines],
                    [item.to_dict() for item in second.deadlines],
                )
                self.assertEqual(first.overdue_explanation, second.overdue_explanation)
        # The masking has to hide a real difference, or the comparison proves nothing.
        self.assertNotEqual(other.to_json(), original.to_json())
        self.assertEqual(_masked(other.to_json()), _masked(original.to_json()))
        self.assertEqual(_masked(other.to_markdown()), _masked(original.to_markdown()))
        self.assertEqual(
            [(item.code, item.message, _masked(item.location)) for item in other.diagnostics],
            [(item.code, item.message, _masked(item.location)) for item in original.diagnostics],
        )

    def test_the_same_bytes_under_another_name_move_only_the_catalog_label(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            copy = Path(directory) / "elsewhere.json"
            copy.write_bytes(KEV_CATALOG.read_bytes())
            renamed = kev_report(catalog=load_kev_catalog(copy))
        original = kev_report(catalog=self.catalog)
        self.assertIn('"elsewhere.json"', renamed.to_json())
        self.assertIn("| elsewhere.json,", renamed.to_markdown())
        self.assertEqual(
            renamed.to_json().replace('"elsewhere.json"', '"kev-catalog.json"'),
            original.to_json(),
        )
        self.assertEqual(
            renamed.to_markdown().replace("| elsewhere.json,", "| kev-catalog.json,"),
            original.to_markdown(),
        )

    def test_the_kev_deadline_is_appended_after_every_other_one(self) -> None:
        report = kev_report(kind="historical", catalog=self.catalog)
        every = [*report.active, *(item.vulnerability for item in report.accepted)]
        for record in every:
            rule_ids = [item.rule_id for item in record.deadlines]
            with self.subTest(record=record.source_record_id):
                if "VDR-TFR-KEV" in rule_ids:
                    self.assertEqual(rule_ids[-1], "VDR-TFR-KEV")
                    self.assertNotIn("VDR-TFR-KEV", rule_ids[:-1])


def permuted_catalog(directory: Path) -> Path:
    """Write the fixture catalog with its entries in another order and return the path."""
    payload = json.loads(KEV_CATALOG.read_text(encoding="utf-8"))
    payload["vulnerabilities"] = list(reversed(payload["vulnerabilities"]))
    path = directory / "kev-catalog.json"
    path.write_text(json.dumps(payload), encoding="utf-8")
    return path


def _masked(text: str) -> str:
    """Blank every sha256 digest and the byte size that moves with the catalog file."""
    masked = re.sub(r"[0-9a-f]{64}", "<sha256>", text)
    return re.sub(r'"sizeBytes": \d+', '"sizeBytes": <bytes>', masked)


def _published(document: dict) -> list[dict]:
    """Return every record array of one document, concatenated in document order."""
    keys = ("vulnerabilities", "activeVulnerabilities", "acceptedVulnerabilities")
    return [item for key in keys for item in document.get(key, ())]


def _tracking_ids(records: Sequence[dict]) -> list[str]:
    """Read the tracking ids out of one published array, whatever it wraps them in."""
    return [item.get("vulnerabilityDetail", item)["providerTrackingId"] for item in records]


if __name__ == "__main__":
    unittest.main()
