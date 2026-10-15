# ******************************************************************************
# *Title: Inventory Reader Tests*
# *Author: Kyle Versluis*
# *Description: Unit tests for the information resource inventory reader.*
# ******************************************************************************
"""Tests for the inventory reader: loading, refusals, canonical order, and lookup."""

# *--- Imports ---*

from __future__ import annotations

import dataclasses
import hashlib
import json
import tempfile
import unittest
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

from complyroll.models import ResourceRef
from complyroll.reports import (
    MAX_INVENTORY_BYTES,
    MAX_INVENTORY_RESOURCES,
    InformationResource,
    Inventory,
    ReportInputError,
    load_inventory,
    parse_inventory,
)
from complyroll.reports.inventory import (
    DRIFT_UNKNOWN,
    INVENTORY_LIMITS,
    INVENTORY_SCHEMA,
    INVENTORY_SCHEMA_VERSION,
    MAX_NAME_CHARS,
    MAX_REFERENCE_CHARS,
    Verification,
)

# *--- Fixtures ---*

REPO_ROOT = Path(__file__).parent.parent
KEV_CATALOG = REPO_ROOT / "tests" / "fixtures" / "kev-catalog.json"
INVENTORY_NAME = "inventory.json"
#: The example document of the plan's "The inventory input" section, as written there.
PLAN_EXAMPLE = (
    b'{"schema": "complyroll.inventory", "schemaVersion": 1, "name": "boundary-2026-10",\n'
    b' "resources": [\n'
    b'  {"resourceType": "host", "resourceId": "lab-ubuntu-01", "machineBased": true,\n'
    b'   "driftLikely": true, "sampleGroup": "web-tier", "job": "nightly-openscap",\n'
    b'   "expectedSince": "2026-07-01T00:00:00Z", "decommissionedAt": null,\n'
    b'   "aliases": [{"resourceType": "host", "resourceId": "lab-ubuntu-01.lab.internal"}]},\n'
    b'  {"resourceType": "logical", "resourceId": "incident-response-procedure",\n'
    b'   "machineBased": false, "expectedSince": "2026-07-01T00:00:00Z",\n'
    b'   "verifications": [{"at": "2026-09-02T17:00:00Z", "reference": "IR tabletop record"}]}]}\n'
)
SINCE = datetime(2026, 7, 1, tzinfo=UTC)
SINCE_TEXT = "2026-07-01T00:00:00Z"
#: Every refusal message stays under this many characters, whatever the input held.
MAX_MESSAGE_CHARS = 400
MISSING = object()
#: Identity text the adapters refuse, so the inventory refuses it too (ADR 0011 decision 10).
PROHIBITED_TEXT = {
    "escape": "lab\x1b[31m",
    "newline": "lab-01\n",
    "tab": "lab\t01",
    "zero width space": "lab\u200b01",
    "right-to-left override": "lab\u202e01",
    "line separator": "lab\u202801",
    "paragraph separator": "lab\u202901",
}


def example() -> dict[str, Any]:
    return json.loads(PLAN_EXAMPLE)


def example_inventory() -> Inventory:
    return parse_inventory(PLAN_EXAMPLE)


def encoded(payload: object) -> bytes:
    return json.dumps(payload).encode("utf-8")


def changed(target: dict[str, Any], key: str, value: object) -> None:
    """Replace one field in place, or remove it when value is MISSING."""
    if value is MISSING:
        del target[key]
    else:
        target[key] = value


def with_root(key: str, value: object) -> bytes:
    payload = example()
    changed(payload, key, value)
    return encoded(payload)


def with_entry(key: str, value: object, index: int = 0) -> bytes:
    """Return the example with one field of one entry replaced; entry 0 is the host."""
    payload = example()
    changed(payload["resources"][index], key, value)
    return encoded(payload)


def with_alias(key: str, value: object) -> bytes:
    payload = example()
    changed(payload["resources"][0]["aliases"][0], key, value)
    return encoded(payload)


def with_verification(key: str, value: object) -> bytes:
    payload = example()
    changed(payload["resources"][1]["verifications"][0], key, value)
    return encoded(payload)


def machine_entry(resource_id: str = "lab-01", **fields: object) -> dict[str, Any]:
    entry: dict[str, Any] = {
        "resourceType": "host",
        "resourceId": resource_id,
        "machineBased": True,
        "driftLikely": False,
        "expectedSince": SINCE_TEXT,
    }
    entry.update(fields)
    return entry


def manual_entry(resource_id: str = "procedure", **fields: object) -> dict[str, Any]:
    entry: dict[str, Any] = {
        "resourceType": "logical",
        "resourceId": resource_id,
        "machineBased": False,
        "expectedSince": SINCE_TEXT,
    }
    entry.update(fields)
    return entry


def document(entries: list[Any], name: str = "boundary-2026-10") -> bytes:
    return encoded(
        {
            "schema": INVENTORY_SCHEMA,
            "schemaVersion": INVENTORY_SCHEMA_VERSION,
            "name": name,
            "resources": entries,
        }
    )


def only_entry(content: bytes) -> InformationResource:
    (entry,) = parse_inventory(content).entries
    return entry


def nested_lists(depth: int) -> object:
    """Return a JSON list nested `depth` levels deep."""
    value: object = []
    for _ in range(depth - 1):
        value = [value]
    return value


# *--- Loader ---*


class InventoryLoaderTests(unittest.TestCase):
    """The plan's example loads with its identity, its fields, and a canonical order."""

    def test_the_plan_example_loads_with_its_identity(self) -> None:
        inventory = example_inventory()
        self.assertEqual(inventory.name, "boundary-2026-10")
        self.assertEqual(inventory.sha256, hashlib.sha256(PLAN_EXAMPLE).hexdigest())
        self.assertEqual(inventory.size_bytes, len(PLAN_EXAMPLE))
        self.assertEqual(inventory.entry_count, 2)
        self.assertEqual(len(inventory.entries), 2)

    def test_the_machine_entry_carries_every_field(self) -> None:
        host = example_inventory().entries[0]
        self.assertEqual(
            host,
            InformationResource(
                resource_type="host",
                resource_id="lab-ubuntu-01",
                machine_based=True,
                expected_since=SINCE,
                drift_likely=True,
                sample_group="web-tier",
                job="nightly-openscap",
                decommissioned_at=None,
                aliases=(
                    ResourceRef(resource_id="lab-ubuntu-01.lab.internal", resource_type="host"),
                ),
                verifications=(),
            ),
        )
        self.assertIs(host.expected_since.tzinfo, UTC)
        self.assertEqual(host.ref, ResourceRef(resource_id="lab-ubuntu-01", resource_type="host"))

    def test_the_non_machine_entry_carries_its_attested_verification(self) -> None:
        procedure = example_inventory().entries[1]
        self.assertEqual(procedure.resource_type, "logical")
        self.assertEqual(procedure.resource_id, "incident-response-procedure")
        self.assertFalse(procedure.machine_based)
        self.assertIsNone(procedure.drift_likely)
        self.assertIsNone(procedure.sample_group)
        self.assertIsNone(procedure.job)
        self.assertIsNone(procedure.decommissioned_at)
        self.assertEqual(procedure.aliases, ())
        self.assertEqual(
            procedure.verifications,
            (
                Verification(
                    at=datetime(2026, 9, 2, 17, tzinfo=UTC), reference="IR tabletop record"
                ),
            ),
        )

    def test_the_plan_example_round_trips_through_its_canonical_document(self) -> None:
        inventory = example_inventory()
        canonical = inventory.to_document()
        self.assertEqual(
            canonical,
            {
                "schema": "complyroll.inventory",
                "schemaVersion": 1,
                "name": "boundary-2026-10",
                "resources": [
                    {
                        "resourceType": "host",
                        "resourceId": "lab-ubuntu-01",
                        "machineBased": True,
                        "expectedSince": SINCE_TEXT,
                        "driftLikely": True,
                        "sampleGroup": "web-tier",
                        "job": "nightly-openscap",
                        "aliases": [
                            {"resourceType": "host", "resourceId": "lab-ubuntu-01.lab.internal"}
                        ],
                    },
                    {
                        "resourceType": "logical",
                        "resourceId": "incident-response-procedure",
                        "machineBased": False,
                        "expectedSince": SINCE_TEXT,
                        "verifications": [
                            {"at": "2026-09-02T17:00:00Z", "reference": "IR tabletop record"}
                        ],
                    },
                ],
            },
        )
        again = parse_inventory(encoded(canonical))
        self.assertEqual(again.name, inventory.name)
        self.assertEqual(again.entries, inventory.entries)
        self.assertEqual(again.to_document(), canonical)

    def test_entries_aliases_and_verifications_take_one_order_whatever_the_file_order(
        self,
    ) -> None:
        aliases = [{"resourceType": "host", "resourceId": name} for name in ("b", "a", "c")]
        verifications = [
            {"at": "2026-09-03T00:00:00Z", "reference": "second"},
            {"at": "2026-09-01T00:00:00Z", "reference": "first"},
            {"at": "2026-09-03T00:00:00Z", "reference": "also second"},
        ]
        entries = [
            manual_entry("z-procedure", verifications=verifications),
            machine_entry("m-host", aliases=aliases),
            machine_entry("a-host"),
            manual_entry("a-procedure"),
        ]
        forward = parse_inventory(document(entries))
        backward = parse_inventory(document(list(reversed(entries))))
        self.assertEqual(forward.entries, backward.entries)
        self.assertNotEqual(forward.sha256, backward.sha256)
        self.assertEqual(
            [(entry.resource_type, entry.resource_id) for entry in forward.entries],
            [
                ("host", "a-host"),
                ("host", "m-host"),
                ("logical", "a-procedure"),
                ("logical", "z-procedure"),
            ],
        )
        self.assertEqual(
            [alias.resource_id for alias in forward.entries[1].aliases], ["a", "b", "c"]
        )
        self.assertEqual(
            [item.reference for item in forward.entries[3].verifications],
            ["first", "also second", "second"],
        )

    def test_drift_likely_takes_true_false_and_unknown(self) -> None:
        for value in (True, False, DRIFT_UNKNOWN):
            with self.subTest(value=value):
                entry = only_entry(document([machine_entry(driftLikely=value)]))
                self.assertEqual(entry.drift_likely, value)
                self.assertIs(type(entry.drift_likely), type(value))
        self.assertEqual(DRIFT_UNKNOWN, "unknown")

    def test_drift_likely_reads_absent_and_null_alike_on_a_non_machine_entry(self) -> None:
        self.assertIsNone(only_entry(document([manual_entry()])).drift_likely)
        self.assertIsNone(only_entry(document([manual_entry(driftLikely=None)])).drift_likely)

    def test_optional_fields_read_absent_and_null_alike(self) -> None:
        nulls = {
            "sampleGroup": None,
            "job": None,
            "decommissionedAt": None,
            "aliases": None,
        }
        absent = only_entry(document([machine_entry()]))
        self.assertEqual(only_entry(document([machine_entry(**nulls)])), absent)
        self.assertEqual(
            only_entry(document([manual_entry(driftLikely=None, verifications=None)])),
            only_entry(document([manual_entry()])),
        )
        self.assertEqual(absent.aliases, ())
        self.assertEqual(absent.verifications, ())
        self.assertIsNone(absent.decommissioned_at)

    def test_empty_aliases_and_verifications_are_accepted(self) -> None:
        self.assertEqual(only_entry(document([machine_entry(aliases=[])])).aliases, ())
        self.assertEqual(only_entry(document([manual_entry(verifications=[])])).verifications, ())

    def test_sample_group_job_and_decommissioned_at_are_read(self) -> None:
        entry = only_entry(
            document(
                [
                    machine_entry(
                        sampleGroup="web-tier",
                        job="nightly-openscap",
                        decommissionedAt="2026-09-30T23:59:59Z",
                    )
                ]
            )
        )
        self.assertEqual(entry.sample_group, "web-tier")
        self.assertEqual(entry.job, "nightly-openscap")
        self.assertEqual(entry.decommissioned_at, datetime(2026, 9, 30, 23, 59, 59, tzinfo=UTC))

    def test_decommissioned_at_equal_to_expected_since_is_accepted(self) -> None:
        entry = only_entry(document([machine_entry(decommissionedAt=SINCE_TEXT)]))
        self.assertEqual(entry.decommissioned_at, entry.expected_since)

    def test_an_offset_instant_is_normalized_to_utc(self) -> None:
        entry = only_entry(
            document(
                [
                    manual_entry(
                        expectedSince="2026-06-30T17:00:00.5-07:00",
                        verifications=[{"at": "2026-09-02T19:00:00+02:00", "reference": "r"}],
                    )
                ]
            )
        )
        self.assertEqual(entry.expected_since, datetime(2026, 7, 1, 0, 0, 0, 500000, tzinfo=UTC))
        self.assertIs(entry.expected_since.tzinfo, UTC)
        self.assertEqual(entry.verifications[0].at, datetime(2026, 9, 2, 17, tzinfo=UTC))
        self.assertIs(entry.verifications[0].at.tzinfo, UTC)

    def test_a_nine_digit_fraction_is_accepted_and_truncated(self) -> None:
        entry = only_entry(
            document([machine_entry(expectedSince="2026-07-01T00:00:00.123456789Z")])
        )
        self.assertEqual(entry.expected_since, datetime(2026, 7, 1, 0, 0, 0, 123456, tzinfo=UTC))

    def test_an_empty_inventory_is_accepted(self) -> None:
        inventory = parse_inventory(document([]))
        self.assertEqual(inventory.entry_count, 0)
        self.assertEqual(inventory.entries, ())

    def test_text_at_its_512_character_bound_is_accepted(self) -> None:
        long = "x" * 512
        self.assertEqual(MAX_REFERENCE_CHARS, 512)
        entry = only_entry(
            document(
                [
                    manual_entry(
                        long,
                        resourceType="t" * 512,
                        aliases=[{"resourceType": "a" * 512, "resourceId": "i" * 512}],
                        verifications=[{"at": SINCE_TEXT, "reference": "r" * 512}],
                    )
                ]
            )
        )
        self.assertEqual(entry.resource_id, long)
        self.assertEqual(entry.resource_type, "t" * 512)
        self.assertEqual(
            entry.aliases[0], ResourceRef(resource_id="i" * 512, resource_type="a" * 512)
        )
        self.assertEqual(entry.verifications[0].reference, "r" * 512)

    def test_printable_unicode_and_inner_spaces_are_accepted(self) -> None:
        entry = only_entry(
            document(
                [
                    manual_entry(
                        "proc\u00e9dure de r\u00e9ponse",
                        verifications=[{"at": SINCE_TEXT, "reference": "exercice \u00e0 blanc"}],
                    )
                ]
            )
        )
        self.assertEqual(entry.resource_id, "proc\u00e9dure de r\u00e9ponse")
        self.assertEqual(entry.verifications[0].reference, "exercice \u00e0 blanc")

    def test_sample_group_and_job_take_the_name_rule_up_to_its_bound(self) -> None:
        # A group or job name joins a published identity (sample-group/<name>, and PR 3's
        # job-keyed cases), so it takes the name rule and stays far inside the 512 cap.
        for value in ("g" * MAX_NAME_CHARS, "web tier", "x", "nightly-openscap/v2"):
            with self.subTest(value=value):
                entry = only_entry(document([machine_entry(sampleGroup=value, job=value)]))
                self.assertEqual((entry.sample_group, entry.job), (value, value))

    def test_a_colon_is_accepted_in_a_resource_id(self) -> None:
        entry = only_entry(
            document(
                [
                    machine_entry(
                        "arn:aws:ec2:host-01",
                        aliases=[{"resourceType": "host", "resourceId": "a:b"}],
                    )
                ]
            )
        )
        self.assertEqual(entry.resource_id, "arn:aws:ec2:host-01")
        self.assertEqual(entry.aliases[0].resource_id, "a:b")

    def test_one_identifier_under_two_types_is_two_entries(self) -> None:
        inventory = parse_inventory(document([machine_entry("shared"), manual_entry("shared")]))
        self.assertEqual(inventory.entry_count, 2)

    def test_the_name_rules_accept_inner_spaces_and_the_bound(self) -> None:
        self.assertEqual(MAX_NAME_CHARS, 128)
        for name in ("Production boundary 2026-10", "n" * 128, "x"):
            with self.subTest(name=name):
                self.assertEqual(parse_inventory(document([], name=name)).name, name)

    def test_the_published_bounds(self) -> None:
        # Pinned literally, so the numbers the docs print cannot drift without a test saying so.
        self.assertEqual(MAX_INVENTORY_BYTES, 8 * 1024 * 1024)
        self.assertEqual(MAX_INVENTORY_RESOURCES, 20_000)
        self.assertEqual(INVENTORY_LIMITS.max_artifact_bytes, MAX_INVENTORY_BYTES)
        self.assertEqual(INVENTORY_LIMITS.max_json_depth, 16)
        self.assertEqual(INVENTORY_SCHEMA, "complyroll.inventory")
        self.assertEqual(INVENTORY_SCHEMA_VERSION, 1)

    def test_nesting_at_the_depth_bound_reaches_the_field_rules(self) -> None:
        # The root is depth 1 and a root value depth 2, so 15 nested lists reach depth 16: the
        # parser accepts it and the schema type rule refuses it, not the depth bound.
        with self.assertRaises(ReportInputError) as caught:
            parse_inventory(with_root("schema", nested_lists(15)))
        self.assertIn("schema must be a JSON string", str(caught.exception))
        self.assertNotIn("exceeds a limit", str(caught.exception))

    def test_the_resource_bound_is_inclusive(self) -> None:
        entries = [machine_entry(f"lab-{number:05d}") for number in range(MAX_INVENTORY_RESOURCES)]
        inventory = parse_inventory(document(entries))
        self.assertEqual(inventory.entry_count, MAX_INVENTORY_RESOURCES)

    def test_a_file_at_the_byte_bound_loads(self) -> None:
        padded = PLAN_EXAMPLE + b" " * (MAX_INVENTORY_BYTES - len(PLAN_EXAMPLE))
        self.assertEqual(len(padded), MAX_INVENTORY_BYTES)
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / INVENTORY_NAME
            path.write_bytes(padded)
            inventory = load_inventory(path)
        self.assertEqual(inventory.size_bytes, MAX_INVENTORY_BYTES)
        self.assertEqual(inventory.sha256, hashlib.sha256(padded).hexdigest())
        self.assertEqual(inventory.entries, example_inventory().entries)

    def test_the_loader_reads_the_file_it_is_given(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / INVENTORY_NAME
            path.write_bytes(PLAN_EXAMPLE)
            self.assertEqual(load_inventory(path), example_inventory())

    def test_a_bom_is_tolerated_and_the_digest_covers_it(self) -> None:
        content = b"\xef\xbb\xbf" + PLAN_EXAMPLE
        inventory = parse_inventory(content)
        plain = example_inventory()
        self.assertEqual(inventory.entries, plain.entries)
        self.assertEqual(inventory.sha256, hashlib.sha256(content).hexdigest())
        self.assertNotEqual(inventory.sha256, plain.sha256)
        self.assertEqual(inventory.size_bytes, plain.size_bytes + 3)

    def test_two_loads_are_equal_and_hash_equal(self) -> None:
        first = example_inventory()
        second = example_inventory()
        self.assertEqual(first, second)
        self.assertEqual(hash(first), hash(second))
        self.assertIsNot(first, second)

    def test_the_index_stays_out_of_equality_hashing_and_repr(self) -> None:
        (index,) = [item for item in dataclasses.fields(Inventory) if item.name == "_index"]
        self.assertFalse(index.compare)
        self.assertFalse(index.hash)
        self.assertFalse(index.repr)
        self.assertFalse(index.init)
        self.assertNotIn("_index", repr(example_inventory()))
        self.assertNotIn("mappingproxy", repr(example_inventory()))

    def test_parse_inventory_takes_bytes_only(self) -> None:
        with self.assertRaises(TypeError):
            parse_inventory(PLAN_EXAMPLE.decode("utf-8"))  # type: ignore[arg-type]


# *--- Lookup ---*


class InventoryLookupTests(unittest.TestCase):
    """An identity names an entry by its own pair or an alias, exactly (plan, Match)."""

    def test_the_pair_and_the_alias_name_the_same_entry(self) -> None:
        inventory = example_inventory()
        host = inventory.entries[0]
        self.assertIs(inventory.entry_for("host", "lab-ubuntu-01"), host)
        self.assertIs(inventory.entry_for("host", "lab-ubuntu-01.lab.internal"), host)
        self.assertIs(
            inventory.entry_for("logical", "incident-response-procedure"), inventory.entries[1]
        )

    def test_matching_is_exact(self) -> None:
        inventory = example_inventory()
        for resource_type, resource_id in (
            ("host", "LAB-UBUNTU-01"),
            ("host", "lab-ubuntu-01 "),
            ("host", "lab-ubuntu-01.lab"),
            ("image", "lab-ubuntu-01"),
            ("Host", "lab-ubuntu-01"),
            ("logical", "lab-ubuntu-01.lab.internal"),
        ):
            with self.subTest(resource_type=resource_type, resource_id=resource_id):
                self.assertIsNone(inventory.entry_for(resource_type, resource_id))

    def test_identities_list_the_pair_then_the_aliases(self) -> None:
        host = example_inventory().entries[0]
        self.assertEqual(
            host.identities,
            (
                ResourceRef(resource_id="lab-ubuntu-01", resource_type="host"),
                ResourceRef(resource_id="lab-ubuntu-01.lab.internal", resource_type="host"),
            ),
        )


# *--- Direct Construction ---*


class InventoryInvariantTests(unittest.TestCase):
    """A directly built inventory or entry holds the invariants the reader guarantees."""

    def test_a_directly_built_inventory_refuses_unsorted_or_repeated_entries(self) -> None:
        inventory = example_inventory()
        for entries in (tuple(reversed(inventory.entries)), inventory.entries[:1] * 2):
            with self.subTest(entries=[entry.resource_id for entry in entries]):
                with self.assertRaises(ValueError):
                    dataclasses.replace(inventory, entries=entries)

    def test_a_directly_built_inventory_refuses_an_alias_naming_another_entry(self) -> None:
        inventory = example_inventory()
        host, procedure = inventory.entries
        stolen = dataclasses.replace(host, aliases=(procedure.ref,))
        with self.assertRaises(ValueError):
            dataclasses.replace(inventory, entries=(stolen, procedure))

    def test_a_directly_built_entry_holds_the_field_rules(self) -> None:
        host, procedure = example_inventory().entries
        verification = procedure.verifications[0]
        alias = ResourceRef(resource_id="b", resource_type="host")
        cases: dict[str, tuple[InformationResource, dict[str, object]]] = {
            "machine without drift": (host, {"drift_likely": None}),
            "drift of another value": (host, {"drift_likely": "likely"}),
            "drift of an integer": (host, {"drift_likely": 1}),
            "drift on a non-machine": (procedure, {"drift_likely": False}),
            "unknown drift on a non-machine": (procedure, {"drift_likely": DRIFT_UNKNOWN}),
            "verifications on a machine": (host, {"verifications": (verification,)}),
            "decommissioned before expected": (
                host,
                {"decommissioned_at": SINCE - timedelta(microseconds=1)},
            ),
            "naive expected since": (host, {"expected_since": datetime(2026, 7, 1)}),
            "unsorted aliases": (
                host,
                {"aliases": (alias, ResourceRef(resource_id="a", resource_type="host"))},
            ),
            "repeated alias": (host, {"aliases": (alias, alias)}),
            "colon in the type": (host, {"resource_type": "host:linux"}),
            "colon in an alias type": (
                host,
                {"aliases": (ResourceRef(resource_id="b", resource_type="host:linux"),)},
            ),
            "sample group over the name bound": (host, {"sample_group": "g" * 129}),
            "sample group with a leading space": (host, {"sample_group": " web"}),
            "job that is not printable ASCII": (host, {"job": "t\u00e2che"}),
            "empty job": (host, {"job": ""}),
            "alias of itself": (host, {"aliases": (host.ref,)}),
            "unsorted verifications": (
                procedure,
                {
                    "verifications": (
                        verification,
                        Verification(at=verification.at - timedelta(days=1), reference="r"),
                    )
                },
            ),
        }
        for label, (entry, change) in cases.items():
            with self.subTest(label), self.assertRaises((TypeError, ValueError)):
                dataclasses.replace(entry, **change)  # type: ignore[arg-type]

    def test_a_directly_built_verification_must_be_aware(self) -> None:
        with self.assertRaises(ValueError):
            Verification(at=datetime(2026, 9, 2, 17), reference="r")


# *--- Refusals ---*


class InventoryRefusalTests(unittest.TestCase):
    """Every refusal is a ReportInputError starting "inventory", on both entry points."""

    def assert_refused(self, content: bytes, fragment: str = "", *, same: bool = True) -> str:
        """Assert parse_inventory and load_inventory both refuse the bytes; return the text.

        The two entry points give one message for a content refusal; only the size refusal,
        which read_bounded makes before parsing, may word itself differently.
        """
        messages = []
        with self.assertRaises(ReportInputError) as parsed:
            parse_inventory(content)
        messages.append(parsed.exception)
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / INVENTORY_NAME
            path.write_bytes(content)
            with self.assertRaises(ReportInputError) as loaded:
                load_inventory(path)
        messages.append(loaded.exception)
        for exc in messages:
            self.assertIs(type(exc), ReportInputError)
            self.assertTrue(str(exc).startswith("inventory"), str(exc))
            self.assertIn(fragment, str(exc))
            self.assertLess(len(str(exc)), MAX_MESSAGE_CHARS)
        if same:
            self.assertEqual(str(messages[0]), str(messages[1]))
        return str(messages[0])

    def assert_each_refused(self, cases: dict[str, bytes], fragment: str = "") -> None:
        for label, content in cases.items():
            with self.subTest(case=label):
                self.assert_refused(content, fragment)

    # Bytes and structure

    def test_non_json_bytes_are_refused(self) -> None:
        text = PLAN_EXAMPLE.decode("utf-8")
        self.assert_each_refused(
            {
                "csv": b"resourceType,resourceId\nhost,lab-01\n",
                "empty": b"",
                "non-utf-8": b'{"name": "\xff\xfe"}',
                "nan": text.replace('"schemaVersion": 1', '"schemaVersion": NaN').encode(),
                "infinity": text.replace(
                    '"schemaVersion": 1', '"schemaVersion": Infinity'
                ).encode(),
                "duplicate key": text.replace(
                    '"schemaVersion": 1,', '"schemaVersion": 1, "schemaVersion": 1,'
                ).encode(),
                "lone surrogate": text.replace('"web-tier"', '"\\ud800web-tier"').encode(),
                "truncated": PLAN_EXAMPLE[:-10],
            },
            "inventory must be a JSON document",
        )

    def test_a_root_that_is_not_an_object_is_refused(self) -> None:
        self.assert_each_refused(
            {"array": b"[]", "string": b'"inventory"', "number": b"1", "null": b"null"},
            "not an object",
        )

    def test_nesting_past_the_depth_bound_is_refused(self) -> None:
        message = self.assert_refused(with_root("schema", nested_lists(16)))
        self.assertIn("exceeds a limit", message)
        self.assertIn("16", message)

    def test_content_over_the_byte_bound_is_refused_by_both_entry_points(self) -> None:
        oversize = PLAN_EXAMPLE + b" " * (MAX_INVENTORY_BYTES + 1 - len(PLAN_EXAMPLE))
        message = self.assert_refused(oversize, str(MAX_INVENTORY_BYTES), same=False)
        self.assertIn(str(len(oversize)), message)

    def test_a_directory_and_a_missing_file_are_refused(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            for path in (Path(directory), Path(directory) / "absent.json"):
                with self.subTest(path=path.name):
                    with self.assertRaises(ReportInputError) as caught:
                        load_inventory(path)
                    self.assertIs(type(caught.exception), ReportInputError)
                    self.assertTrue(str(caught.exception).startswith("inventory cannot be read"))

    # Root fields

    def test_schema_rules(self) -> None:
        self.assert_each_refused(
            {
                "missing": with_root("schema", MISSING),
                "int": with_root("schema", 1),
                "null": with_root("schema", None),
                "list": with_root("schema", [INVENTORY_SCHEMA]),
                "empty": with_root("schema", ""),
                "versioned": with_root("schema", "complyroll.inventory.v1"),
                "uppercase": with_root("schema", "COMPLYROLL.INVENTORY"),
                "padded": with_root("schema", " complyroll.inventory"),
            },
            "inventory: schema",
        )

    def test_a_kev_catalog_is_refused_by_its_schema(self) -> None:
        message = self.assert_refused(KEV_CATALOG.read_bytes())
        self.assertEqual(message, "inventory: schema is required")

    def test_schema_version_rules(self) -> None:
        self.assert_each_refused(
            {
                "missing": with_root("schemaVersion", MISSING),
                "string": with_root("schemaVersion", "1"),
                "float": with_root("schemaVersion", 1.0),
                "bool": with_root("schemaVersion", True),
                "null": with_root("schemaVersion", None),
                "zero": with_root("schemaVersion", 0),
                "two": with_root("schemaVersion", 2),
                "negative": with_root("schemaVersion", -1),
            },
            "inventory: schemaVersion",
        )

    def test_a_huge_schema_version_is_refused_without_being_echoed(self) -> None:
        message = self.assert_refused(with_root("schemaVersion", 10**4000), "schemaVersion")
        self.assertNotIn("0" * 100, message)

    def test_name_rules(self) -> None:
        self.assert_each_refused(
            {
                "missing": with_root("name", MISSING),
                "int": with_root("name", 1),
                "null": with_root("name", None),
                "list": with_root("name", ["boundary"]),
                "empty": with_root("name", ""),
                "leading space": with_root("name", " boundary"),
                "trailing space": with_root("name", "boundary "),
                "129 characters": with_root("name", "n" * 129),
                "non-ascii": with_root("name", "fronti\u00e8re"),
                "tab": with_root("name", "bound\tary"),
                "newline": with_root("name", "boundary\n"),
            },
            "inventory: name",
        )

    def test_unknown_root_keys_are_refused(self) -> None:
        self.assert_each_refused(
            {
                "one": with_root("x-note", "synthetic"),
                "count": with_root("count", 2),
            },
            "inventory: unknown key",
        )
        payload = example()
        payload["b-extra"] = 1
        payload["a-extra"] = 2
        message = self.assert_refused(encoded(payload))
        self.assertEqual(message, "inventory: unknown key 'a-extra' and 1 more")

    def test_resources_rules(self) -> None:
        self.assert_each_refused(
            {
                "missing": with_root("resources", MISSING),
                "object": with_root("resources", {}),
                "string": with_root("resources", "lab-01"),
                "null": with_root("resources", None),
            },
            "inventory: resources",
        )

    def test_more_than_the_resource_bound_is_refused(self) -> None:
        entries = [machine_entry(f"lab-{n:05d}") for n in range(MAX_INVENTORY_RESOURCES + 1)]
        message = self.assert_refused(document(entries))
        self.assertIn(str(MAX_INVENTORY_RESOURCES), message)
        self.assertIn(str(MAX_INVENTORY_RESOURCES + 1), message)

    def test_an_entry_that_is_not_an_object_is_refused(self) -> None:
        cases = {}
        for label, value in (("string", "lab-01"), ("number", 5), ("null", None), ("list", [])):
            payload = example()
            payload["resources"][1] = value
            cases[label] = encoded(payload)
        self.assert_each_refused(cases, "inventory resources[1]: the entry must be an object")

    # Entry fields

    def test_unknown_entry_keys_are_refused(self) -> None:
        self.assert_each_refused(
            {
                "extension": with_entry("x-note", "synthetic"),
                "snake case": with_entry("resource_id", "lab-ubuntu-01"),
                "planned field": with_entry("serviceId", "svc"),
            },
            "inventory resources[0]: unknown key",
        )

    def test_required_entry_fields(self) -> None:
        for key in ("resourceType", "resourceId", "machineBased", "expectedSince"):
            with self.subTest(key=key):
                message = self.assert_refused(with_entry(key, MISSING, index=1))
                self.assertEqual(message, f"inventory resources[1]: {key} is required")

    def test_identifier_rules_for_resource_type_and_resource_id(self) -> None:
        for key in ("resourceType", "resourceId"):
            with self.subTest(key=key):
                cases = {
                    "int": with_entry(key, 1),
                    "null": with_entry(key, None),
                    "bool": with_entry(key, True),
                    "list": with_entry(key, ["lab-01"]),
                    "empty": with_entry(key, ""),
                    "blank": with_entry(key, "   "),
                    "513 characters": with_entry(key, "x" * 513),
                }
                for label, text in PROHIBITED_TEXT.items():
                    cases[label] = with_entry(key, text)
                self.assert_each_refused(cases, f"inventory resources[0]: {key}")

    def test_identifier_rules_for_sample_group_and_job(self) -> None:
        for key in ("sampleGroup", "job"):
            with self.subTest(key=key):
                cases = {
                    "int": with_entry(key, 1),
                    "bool": with_entry(key, False),
                    "list": with_entry(key, ["web-tier"]),
                    "object": with_entry(key, {}),
                    "empty": with_entry(key, ""),
                    "blank": with_entry(key, " "),
                    "513 characters": with_entry(key, "x" * 513),
                }
                for label, text in PROHIBITED_TEXT.items():
                    cases[label] = with_entry(key, text)
                self.assert_each_refused(cases, f"inventory resources[0]: {key}")

    def test_sample_group_and_job_take_the_name_rule(self) -> None:
        for key in ("sampleGroup", "job"):
            with self.subTest(key=key):
                cases = {
                    "129 characters": with_entry(key, "n" * 129),
                    "leading space": with_entry(key, " web-tier"),
                    "trailing space": with_entry(key, "web-tier "),
                    "non-ascii": with_entry(key, "fronti\u00e8re"),
                    "tab": with_entry(key, "web\ttier"),
                    "newline": with_entry(key, "web-tier\n"),
                }
                self.assert_each_refused(
                    cases,
                    f"inventory resources[0]: {key} must be 1 to {MAX_NAME_CHARS} printable "
                    "ASCII characters with no leading or trailing space, got ",
                )

    def test_a_long_group_name_is_quoted_cut(self) -> None:
        message = self.assert_refused(with_entry("sampleGroup", "g" * (1024 * 1024)))
        self.assertIn("g" * 32, message)
        self.assertNotIn("g" * 100, message)

    def test_a_colon_in_resource_type_is_refused(self) -> None:
        for value in ("host:linux", ":host", "host:", ":"):
            with self.subTest(value=value):
                message = self.assert_refused(with_entry("resourceType", value))
                self.assertEqual(
                    message,
                    f"inventory resources[0]: resourceType must not contain a colon, got {value!r}",
                )
                message = self.assert_refused(with_alias("resourceType", value))
                self.assertEqual(
                    message,
                    "inventory resources[0].aliases[0]: resourceType must not contain a colon, "
                    f"got {value!r}",
                )

    def test_the_identity_rule_runs_before_the_colon_rule(self) -> None:
        # An over-cap type holding a colon is described by its length, never quoted.
        message = self.assert_refused(with_entry("resourceType", ":" * 513))
        self.assertEqual(
            message, "inventory resources[0]: resourceType is 513 characters; maximum is 512"
        )

    def test_an_over_cap_identifier_is_refused_without_being_quoted(self) -> None:
        message = self.assert_refused(with_entry("resourceId", "x" * (1024 * 1024)))
        self.assertEqual(
            message, "inventory resources[0]: resourceId is 1048576 characters; maximum is 512"
        )

    def test_a_prohibited_code_point_is_named_not_echoed(self) -> None:
        message = self.assert_refused(with_entry("resourceId", "lab\x1b[31m"))
        self.assertEqual(
            message, "inventory resources[0]: resourceId contains prohibited code point U+001B"
        )

    def test_machine_based_rules(self) -> None:
        self.assert_each_refused(
            {
                "null": with_entry("machineBased", None),
                "string": with_entry("machineBased", "true"),
                "one": with_entry("machineBased", 1),
                "zero": with_entry("machineBased", 0),
                "list": with_entry("machineBased", [True]),
            },
            "inventory resources[0]: machineBased must be a JSON boolean",
        )

    def test_drift_likely_rules(self) -> None:
        self.assert_each_refused(
            {
                "missing on a machine entry": with_entry("driftLikely", MISSING),
                "null on a machine entry": with_entry("driftLikely", None),
            },
            "inventory resources[0]: driftLikely is required when machineBased is true",
        )
        self.assert_each_refused(
            {
                "capitalized": with_entry("driftLikely", "Unknown"),
                "string true": with_entry("driftLikely", "true"),
                "likely": with_entry("driftLikely", "likely"),
                "empty": with_entry("driftLikely", ""),
                "one": with_entry("driftLikely", 1),
                "zero": with_entry("driftLikely", 0),
                "list": with_entry("driftLikely", []),
                "object": with_entry("driftLikely", {}),
            },
            'driftLikely must be true, false or "unknown"',
        )

    def test_drift_likely_is_refused_on_a_non_machine_entry(self) -> None:
        # A drift clock is a detection cadence rule; an attested procedure is not detection.
        self.assert_each_refused(
            {
                "true": with_entry("driftLikely", True, index=1),
                "false": with_entry("driftLikely", False, index=1),
                "unknown": with_entry("driftLikely", DRIFT_UNKNOWN, index=1),
                "another string": with_entry("driftLikely", "no", index=1),
                "an integer": with_entry("driftLikely", 1, index=1),
            },
            "inventory resources[1]: driftLikely is for entries whose machineBased is true",
        )

    def test_instant_rules(self) -> None:
        bad = {
            "int": 20260701,
            "list": [SINCE_TEXT],
            "basic": "20260701T000000Z",
            "week": "2026-W27-3T00:00:00Z",
            "space separated": "2026-07-01 00:00:00Z",
            "hour only": "2026-07-01T00Z",
            "comma fraction": "2026-07-01T00:00:00,5Z",
            "padded": " 2026-07-01T00:00:00Z ",
            "trailing newline": "2026-07-01T00:00:00Z\n",
            "+0000": "2026-07-01T00:00:00+0000",
            "seconds offset": "2026-07-01T00:00:00+05:30:15",
            "no zone": "2026-07-01T00:00:00",
            "date only": "2026-07-01",
            "lowercase z": "2026-07-01T00:00:00z",
            "ten fraction digits": "2026-07-01T00:00:00.1234567890Z",
            "fullwidth digits": "\uff12026-07-01T00:00:00Z",
            "impossible day": "2026-02-30T00:00:00Z",
            "hour 24": "2026-07-01T24:00:00Z",
            "leap second": "2026-12-31T23:59:60Z",
            "offset 24 hours": "2026-07-01T00:00:00+24:00",
            "offset minute 60": "2026-07-01T00:00:00+00:60",
            "year 1 east": "0001-01-01T00:00:00+01:00",
            "year 9999 west": "9999-12-31T23:59:59-01:00",
            "before 1970": "1969-12-31T23:59:59Z",
            "after 9000": "9001-01-01T00:00:00Z",
        }
        sites = {
            "expectedSince": lambda value: with_entry("expectedSince", value),
            "decommissionedAt": lambda value: with_entry("decommissionedAt", value),
            "verifications[0] at": lambda value: with_verification("at", value),
        }
        fragments = {
            "expectedSince": "inventory resources[0]: expectedSince",
            "decommissionedAt": "inventory resources[0]: decommissionedAt",
            "verifications[0] at": "inventory resources[1].verifications[0]: at",
        }
        for site, build in sites.items():
            with self.subTest(site=site):
                self.assert_each_refused(
                    {label: build(value) for label, value in bad.items()}, fragments[site]
                )
        self.assert_refused(
            with_entry("expectedSince", None), "expectedSince must be a JSON string"
        )
        self.assert_refused(with_verification("at", None), "at must be a JSON string")

    def test_an_overlong_instant_is_refused_without_being_quoted(self) -> None:
        for value in ("2" * 65, "2" * (1024 * 1024)):
            with self.subTest(length=len(value)):
                message = self.assert_refused(with_entry("expectedSince", value))
                self.assertIn("at most 64 characters", message)
                self.assertNotIn("2222", message)

    def test_decommissioned_before_expected_since_is_refused(self) -> None:
        message = self.assert_refused(
            document([machine_entry(decommissionedAt="2026-06-30T23:59:59.999999Z")])
        )
        self.assertEqual(
            message, "inventory resources[0]: decommissionedAt must not be before expectedSince"
        )

    # Aliases

    def test_aliases_rules(self) -> None:
        self.assert_each_refused(
            {
                "string": with_entry("aliases", "lab-01"),
                "object": with_entry("aliases", {"resourceType": "host", "resourceId": "x"}),
                "number": with_entry("aliases", 1),
                "bool": with_entry("aliases", True),
            },
            "inventory resources[0]: aliases must be an array",
        )
        cases = {}
        for label, value in (("string", "lab-01"), ("number", 1), ("null", None), ("list", [])):
            payload = example()
            payload["resources"][0]["aliases"][0] = value
            cases[label] = encoded(payload)
        self.assert_each_refused(
            cases, "inventory resources[0].aliases[0]: the alias must be an object"
        )

    def test_alias_fields_follow_the_identifier_rules(self) -> None:
        for key in ("resourceType", "resourceId"):
            with self.subTest(key=key):
                cases = {
                    "missing": with_alias(key, MISSING),
                    "int": with_alias(key, 1),
                    "null": with_alias(key, None),
                    "empty": with_alias(key, ""),
                    "blank": with_alias(key, "  "),
                    "513 characters": with_alias(key, "x" * 513),
                }
                for label, text in PROHIBITED_TEXT.items():
                    cases[label] = with_alias(key, text)
                self.assert_each_refused(cases, f"inventory resources[0].aliases[0]: {key}")
        self.assert_each_refused(
            {
                "extension": with_alias("x-note", "synthetic"),
                "machine based": with_alias("machineBased", True),
            },
            "inventory resources[0].aliases[0]: unknown key",
        )

    def test_a_repeated_pair_is_refused(self) -> None:
        entries = [machine_entry("lab-01"), manual_entry(), machine_entry("lab-01")]
        message = self.assert_refused(document(entries))
        self.assertEqual(
            message, "inventory resources[2]: resourceType and resourceId repeat resources[0]"
        )

    def test_an_alias_naming_another_entry_is_refused(self) -> None:
        later = [
            machine_entry("lab-01", aliases=[{"resourceType": "host", "resourceId": "lab-02"}]),
            machine_entry("lab-02"),
        ]
        earlier = [
            machine_entry("lab-02"),
            machine_entry("lab-01", aliases=[{"resourceType": "host", "resourceId": "lab-02"}]),
        ]
        self.assertEqual(
            self.assert_refused(document(later)),
            "inventory resources[0].aliases[0]: the alias names another entry, resources[1]",
        )
        self.assertEqual(
            self.assert_refused(document(earlier)),
            "inventory resources[1].aliases[0]: the alias names another entry, resources[0]",
        )

    def test_an_alias_repeating_another_alias_is_refused(self) -> None:
        alias = {"resourceType": "host", "resourceId": "lab.internal"}
        across = [
            machine_entry("lab-01", aliases=[alias]),
            machine_entry("lab-02", aliases=[alias]),
        ]
        within = [machine_entry("lab-01", aliases=[alias, dict(alias)])]
        self.assertEqual(
            self.assert_refused(document(across)),
            "inventory resources[1].aliases[0]: the alias repeats resources[0].aliases[0]",
        )
        self.assertEqual(
            self.assert_refused(document(within)),
            "inventory resources[0].aliases[1]: the alias repeats resources[0].aliases[0]",
        )

    def test_an_alias_repeating_its_own_entry_is_refused(self) -> None:
        entries = [
            machine_entry("lab-01", aliases=[{"resourceType": "host", "resourceId": "lab-01"}])
        ]
        self.assertEqual(
            self.assert_refused(document(entries)),
            "inventory resources[0].aliases[0]: the alias repeats the entry's own resourceType "
            "and resourceId",
        )

    def test_an_alias_of_another_type_is_its_own_identity(self) -> None:
        alias = {"resourceType": "image", "resourceId": "lab-01"}
        entry = only_entry(document([machine_entry("lab-01", aliases=[alias])]))
        self.assertEqual(entry.aliases, (ResourceRef(resource_id="lab-01", resource_type="image"),))

    # Verifications

    def test_verifications_on_a_machine_entry_are_refused(self) -> None:
        verification = [{"at": SINCE_TEXT, "reference": "attested"}]
        self.assert_each_refused(
            {
                "one": with_entry("verifications", verification),
                "empty": with_entry("verifications", []),
                "wrong type": with_entry("verifications", "attested"),
            },
            "inventory resources[0]: verifications are for entries whose machineBased is false",
        )

    def test_verifications_rules(self) -> None:
        self.assert_each_refused(
            {
                "string": with_entry("verifications", "attested", index=1),
                "object": with_entry("verifications", {"at": SINCE_TEXT}, index=1),
                "number": with_entry("verifications", 1, index=1),
            },
            "inventory resources[1]: verifications must be an array",
        )
        cases = {}
        for label, value in (("string", "x"), ("number", 1), ("null", None), ("list", [])):
            payload = example()
            payload["resources"][1]["verifications"][0] = value
            cases[label] = encoded(payload)
        self.assert_each_refused(
            cases, "inventory resources[1].verifications[0]: the verification must be an object"
        )
        self.assert_each_refused(
            {
                "missing at": with_verification("at", MISSING),
                "missing reference": with_verification("reference", MISSING),
            },
            "is required",
        )
        self.assert_each_refused(
            {
                "extension": with_verification("x-note", "synthetic"),
                "attested by": with_verification("attestedBy", "operator"),
            },
            "inventory resources[1].verifications[0]: unknown key",
        )

    def test_reference_rules(self) -> None:
        cases = {
            "int": with_verification("reference", 1),
            "null": with_verification("reference", None),
            "list": with_verification("reference", ["record"]),
            "empty": with_verification("reference", ""),
            "blank": with_verification("reference", "   "),
            "513 characters": with_verification("reference", "r" * 513),
        }
        for label, text in PROHIBITED_TEXT.items():
            cases[label] = with_verification("reference", text)
        self.assert_each_refused(cases, "inventory resources[1].verifications[0]: reference")

    # Message hygiene

    def test_oversized_invalid_values_are_quoted_cut(self) -> None:
        huge = "C" * (1024 * 1024)
        for content in (
            with_root("schema", huge),
            with_root("name", huge),
            with_entry("driftLikely", huge),
            with_root(huge, 1),
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

    def test_a_control_character_in_a_key_is_escaped(self) -> None:
        duplicate = self.assert_refused(b'{"\\u001b[31m": 1, "\\u001b[31m": 2}')
        unknown = self.assert_refused(with_root("\x1b[31m", 1))
        for message in (duplicate, unknown):
            self.assertNotIn("\x1b", message)
            self.assertIn("\\x1b", message)


if __name__ == "__main__":
    unittest.main()
