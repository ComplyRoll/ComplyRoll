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
import tempfile
import unittest
from datetime import UTC, date, datetime, timedelta
from pathlib import Path
from typing import Any

from complyroll.adapters import ingest_stig_artifact
from complyroll.models import CaseStatus, Observation
from complyroll.reports import (
    MAX_KEV_CATALOG_BYTES,
    MAX_KEV_ENTRIES,
    KevCatalog,
    KevStatus,
    ReportInputError,
    load_kev_catalog,
    parse_kev_catalog,
)
from complyroll.reports.kev import (
    KEV_LIMITS,
    KEV_STOPS,
    MAX_TRUNCATED_METADATA_BYTES,
    cve_may_be_missing,
    due_instant,
    kev_clock,
    start_instant,
)

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


if __name__ == "__main__":
    unittest.main()
