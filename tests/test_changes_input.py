# ******************************************************************************
# *Title: Change Reader Tests*
# *Author: Kyle Versluis*
# *Description: Unit tests for the provider change file reader.*
# ******************************************************************************
"""Tests for the change reader: loading, refusals, canonical order, and the contract types."""

# *--- Imports ---*

from __future__ import annotations

import copy
import dataclasses
import hashlib
import json
import random
import tempfile
import unittest
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

from complyroll.models import ResourceRef
from complyroll.reports import (
    MAX_CHANGE_RESOURCES,
    MAX_CHANGES,
    MAX_CHANGES_BYTES,
    Change,
    ChangeKind,
    ChangeSet,
    ChangeSource,
    ReportInputError,
    load_changes,
    parse_changes,
)
from complyroll.reports.changes_input import (
    CHANGES_LIMITS,
    CHANGES_SCHEMA,
    CHANGES_SCHEMA_VERSION,
    MAX_RATIONALE_CHARS,
)
from complyroll.reports.inventory import MAX_NAME_CHARS, MAX_REFERENCE_CHARS

# *--- Fixtures ---*

REPO_ROOT = Path(__file__).parent.parent
KEV_CATALOG = REPO_ROOT / "tests" / "fixtures" / "kev-catalog.json"
EXAMPLE_FILES = (
    REPO_ROOT / "examples" / "changes.json",
    REPO_ROOT / "tests" / "fixtures" / "changes.json",
)
OCCURRED_TEXT = "2026-09-01T00:00:00Z"
OCCURRED = datetime(2026, 9, 1, tzinfo=UTC)
#: Every refusal message stays under this many characters, whatever the input held.
MAX_MESSAGE_CHARS = 400
MISSING = object()
#: Identity text the adapters refuse, so the change reader refuses it too.
PROHIBITED_TEXT = {
    "escape": "lab\x1b[31m",
    "newline": "lab-01\n",
    "tab": "lab\t01",
    "zero width space": "lab​01",
    "right-to-left override": "lab‮01",
    "line separator": "lab 01",
}


def change(change_id: str = "CHG-1", **fields: object) -> dict[str, Any]:
    value: dict[str, Any] = {
        "changeId": change_id,
        "kind": "modified",
        "occurredAt": OCCURRED_TEXT,
        "source": {"tool": "git", "reference": "commit 0123abc"},
        "resources": [{"resourceType": "host", "resourceId": "lab-01"}],
        "significant": True,
        "rationale": "Kernel upgrade across the web tier.",
    }
    value.update(fields)
    return value


def document(*changes: dict[str, Any]) -> dict[str, Any]:
    return {
        "schema": CHANGES_SCHEMA,
        "schemaVersion": CHANGES_SCHEMA_VERSION,
        "name": "changes-2026-09",
        "changes": list(changes) or [change()],
    }


def encoded(payload: object) -> bytes:
    return json.dumps(payload).encode("utf-8")


def changed(target: dict[str, Any], key: str, value: object) -> None:
    """Replace one field in place, or remove it when value is MISSING."""
    if value is MISSING:
        del target[key]
    else:
        target[key] = value


def with_root(key: str, value: object) -> bytes:
    payload = document()
    changed(payload, key, value)
    return encoded(payload)


def with_change(key: str, value: object) -> bytes:
    payload = document()
    changed(payload["changes"][0], key, value)
    return encoded(payload)


def with_source(key: str, value: object) -> bytes:
    payload = document()
    changed(payload["changes"][0]["source"], key, value)
    return encoded(payload)


def with_resource(key: str, value: object) -> bytes:
    payload = document()
    changed(payload["changes"][0]["resources"][0], key, value)
    return encoded(payload)


def pair(resource_id: str, resource_type: str = "host") -> dict[str, str]:
    return {"resourceType": resource_type, "resourceId": resource_id}


class RefusalCase(unittest.TestCase):
    def assert_refused(self, content: bytes, *fragments: str) -> str:
        """Assert the reader refuses, as the change file, naming every fragment."""
        with self.assertRaises(ReportInputError) as caught:
            parse_changes(content)
        message = str(caught.exception)
        self.assertTrue(message.startswith("changes"), message)
        self.assertLess(len(message), MAX_MESSAGE_CHARS, message)
        for fragment in fragments:
            self.assertIn(fragment, message)
        return message


# *--- Top Level ---*


class TopLevelTests(RefusalCase):
    def test_a_valid_document_reads_every_field(self) -> None:
        payload = document(
            change(
                kind="created",
                detectBy="2026-09-08T00:00:00Z",
                job="nightly-openscap",
                significant=False,
            )
        )
        content = encoded(payload)
        read = parse_changes(content)
        self.assertEqual(read.name, "changes-2026-09")
        self.assertEqual(read.sha256, hashlib.sha256(content).hexdigest())
        self.assertEqual(read.size_bytes, len(content))
        self.assertEqual(read.change_count, 1)
        only = read.changes[0]
        self.assertEqual(only.change_id, "CHG-1")
        self.assertIs(only.kind, ChangeKind.CREATED)
        self.assertEqual(only.occurred_at, OCCURRED)
        self.assertEqual(only.source, ChangeSource(tool="git", reference="commit 0123abc"))
        self.assertEqual(only.resources, (ResourceRef("lab-01", "host"),))
        self.assertIs(only.significant, False)
        self.assertEqual(only.rationale, "Kernel upgrade across the web tier.")
        self.assertEqual(only.detect_by, datetime(2026, 9, 8, tzinfo=UTC))
        self.assertEqual(only.job, "nightly-openscap")

    def test_schema_is_checked_first(self) -> None:
        # A KEV catalog is named as another document, not as a list of missing fields.
        self.assert_refused(KEV_CATALOG.read_bytes(), "schema is required")
        self.assert_refused(with_root("schema", "complyroll.inventory"), "schema must be")
        self.assert_refused(
            encoded({"schema": "complyroll.inventory", "other": 1}), "complyroll.inventory"
        )

    def test_schema_must_be_a_string(self) -> None:
        self.assert_refused(with_root("schema", 1), "schema must be a JSON string, got a number")

    def test_schema_version_must_be_integer_one(self) -> None:
        for value, fragment in (
            (True, "schemaVersion must be a JSON integer, got a boolean"),
            (1.0, "schemaVersion must be a JSON integer, got a number"),
            ("1", "schemaVersion must be a JSON integer, got a string"),
            (2, "schemaVersion must be 1"),
            (10**400, "schemaVersion must be 1"),
            (MISSING, "schemaVersion is required"),
        ):
            with self.subTest(value=repr(value)[:20]):
                self.assert_refused(with_root("schemaVersion", value), fragment)

    def test_the_top_level_must_be_an_object(self) -> None:
        self.assert_refused(b"[]", "the top level is an array, not an object")
        self.assert_refused(b'"changes"', "the top level is a string, not an object")

    def test_name_follows_the_name_rule(self) -> None:
        for value, fragment in (
            (MISSING, "name is required"),
            (1, "name must be a JSON string, got a number"),
            ("", "name must be 1 to 128"),
            (" padded", "name must be 1 to 128"),
            ("padded ", "name must be 1 to 128"),
            ("x" * (MAX_NAME_CHARS + 1), "name must be 1 to 128"),
            ("café", "name must be 1 to 128"),
        ):
            with self.subTest(value=repr(value)[:20]):
                self.assert_refused(with_root("name", value), fragment)

    def test_changes_must_be_an_array(self) -> None:
        self.assert_refused(with_root("changes", MISSING), "changes is required")
        self.assert_refused(with_root("changes", {}), "changes must be an array, got an object")

    def test_no_change_at_all_is_a_valid_empty_set(self) -> None:
        payload = document()
        payload["changes"] = []
        self.assertEqual(parse_changes(encoded(payload)).changes, ())

    def test_too_many_changes_is_refused(self) -> None:
        payload = document()
        payload["changes"] = [{}] * (MAX_CHANGES + 1)
        self.assert_refused(encoded(payload), f"maximum is {MAX_CHANGES}")

    def test_the_change_limit_itself_is_accepted(self) -> None:
        changes = [change(f"CHG-{index}") for index in range(MAX_CHANGES)]
        read = parse_changes(encoded(document(*changes)))
        self.assertEqual(read.change_count, MAX_CHANGES)

    def test_oversize_bytes_is_refused(self) -> None:
        content = b" " * (MAX_CHANGES_BYTES + 1)
        self.assert_refused(content, f"maximum is {MAX_CHANGES_BYTES} bytes")

    def test_the_byte_limit_itself_is_accepted(self) -> None:
        plain = encoded(document())
        padded = b" " * (MAX_CHANGES_BYTES - len(plain)) + plain
        self.assertEqual(parse_changes(padded).size_bytes, MAX_CHANGES_BYTES)

    def test_the_bounds_are_the_contract(self) -> None:
        self.assertEqual(MAX_CHANGES_BYTES, 8 * 1024 * 1024)
        self.assertEqual(MAX_CHANGES, 20_000)
        self.assertEqual(MAX_CHANGE_RESOURCES, 1_000)
        self.assertEqual(MAX_RATIONALE_CHARS, 512)
        self.assertEqual(CHANGES_LIMITS.max_artifact_bytes, MAX_CHANGES_BYTES)
        self.assertEqual(CHANGES_LIMITS.max_json_depth, 16)

    def test_the_depth_bound_applies(self) -> None:
        depth = CHANGES_LIMITS.max_json_depth + 1
        self.assert_refused(b"[" * depth + b"]" * depth, "changes exceeds a limit")

    def test_a_document_that_is_not_json_is_named(self) -> None:
        self.assert_refused(b"{", "changes must be a JSON document")
        self.assert_refused(b"\xff\xfe", "changes must be a JSON document")

    def test_a_duplicate_key_is_refused(self) -> None:
        self.assert_refused(b'{"schema": "a", "schema": "b"}', "changes must be a JSON document")

    def test_unknown_key_refused_at_every_level(self) -> None:
        for location, content, fragment in (
            ("root", with_root("extra", 1), "changes: unknown key 'extra'"),
            ("change", with_change("extra", 1), "changes[0]: unknown key 'extra'"),
            ("source", with_source("extra", 1), "changes[0].source: unknown key 'extra'"),
            (
                "resource",
                with_resource("extra", 1),
                "changes[0].resources[0]: unknown key 'extra'",
            ),
        ):
            with self.subTest(location=location):
                self.assert_refused(content, fragment)

    def test_a_refusal_never_names_the_inventory(self) -> None:
        for content in (
            with_change("rationale", MISSING),
            with_root("name", MISSING),
            with_resource("resourceType", "package"),
            with_change("occurredAt", "not a time"),
        ):
            with self.subTest(content=content[:30]):
                message = self.assert_refused(content)
                self.assertFalse(message.startswith("inventory"), message)

    def test_content_must_be_bytes(self) -> None:
        with self.assertRaises(TypeError):
            parse_changes("{}")  # type: ignore[arg-type]


# *--- Change Fields ---*


class ChangeFieldTests(RefusalCase):
    def test_a_change_must_be_an_object(self) -> None:
        payload = document()
        payload["changes"] = [1]
        self.assert_refused(encoded(payload), "changes[0]: the change must be an object")

    def test_change_id_follows_the_name_rule(self) -> None:
        for value, fragment in (
            (MISSING, "changeId is required"),
            (7, "changeId must be a JSON string, got a number"),
            ("", "changeId must be 1 to 128"),
            (" CHG", "changeId must be 1 to 128"),
            ("x" * (MAX_NAME_CHARS + 1), "changeId must be 1 to 128"),
            ("CHG\n1", "changeId must be 1 to 128"),
        ):
            with self.subTest(value=repr(value)[:20]):
                self.assert_refused(with_change("changeId", value), "changes[0]", fragment)

    def test_change_id_repeated_is_refused(self) -> None:
        content = encoded(document(change("CHG-1"), change("CHG-2"), change("CHG-1")))
        self.assert_refused(content, "changes[2]", "changeId repeats changes[0]")

    def test_kind_outside_vocabulary_is_refused(self) -> None:
        for value, fragment in (
            (MISSING, "kind is required"),
            (1, "kind must be a JSON string, got a number"),
            ("deleted", "kind must be created or modified, got 'deleted'"),
            ("Created", "kind must be created or modified, got 'Created'"),
        ):
            with self.subTest(value=value if value is not MISSING else "missing"):
                self.assert_refused(with_change("kind", value), "changes[0]", fragment)

    def test_occurred_at_is_an_instant(self) -> None:
        for value, fragment in (
            (MISSING, "occurredAt is required"),
            (1, "occurredAt must be a JSON string, got a number"),
            ("2026-09-01", "occurredAt must be an RFC 3339 timestamp"),
            ("2026-09-01T00:00:00", "occurredAt must be an RFC 3339 timestamp"),
            ("x" * 200, "occurredAt must be at most"),
        ):
            with self.subTest(value=repr(value)[:20]):
                self.assert_refused(with_change("occurredAt", value), "changes[0]", fragment)

    def test_an_offset_instant_reads_in_utc(self) -> None:
        read = parse_changes(with_change("occurredAt", "2026-09-01T02:00:00+02:00"))
        self.assertEqual(read.changes[0].occurred_at, OCCURRED)
        self.assertEqual(read.changes[0].occurred_at.utcoffset(), timedelta(0))

    def test_source_must_be_an_object(self) -> None:
        self.assert_refused(with_change("source", MISSING), "changes[0]: source is required")
        self.assert_refused(
            with_change("source", "git"), "changes[0]: source must be an object, got a string"
        )

    def test_source_tool_follows_the_name_rule(self) -> None:
        for value, fragment in (
            (MISSING, "tool is required"),
            (1, "tool must be a JSON string, got a number"),
            (" git", "tool must be 1 to 128"),
        ):
            with self.subTest(value=repr(value)):
                self.assert_refused(with_source("tool", value), "changes[0].source", fragment)

    def test_source_reference_is_identity_text(self) -> None:
        for name, text in PROHIBITED_TEXT.items():
            with self.subTest(name=name):
                self.assert_refused(
                    with_source("reference", text),
                    "changes[0].source",
                    "reference contains prohibited code point",
                )
        for value, fragment in (
            (MISSING, "reference is required"),
            (1, "reference must be a JSON string, got a number"),
            ("   ", "reference must not be blank"),
            ("x" * (MAX_REFERENCE_CHARS + 1), f"maximum is {MAX_REFERENCE_CHARS}"),
        ):
            with self.subTest(value=repr(value)[:20]):
                self.assert_refused(with_source("reference", value), "changes[0].source", fragment)

    def test_source_reference_at_its_limit_is_accepted(self) -> None:
        text = "x" * MAX_REFERENCE_CHARS
        self.assertEqual(
            parse_changes(with_source("reference", text)).changes[0].source.reference, text
        )

    def test_significant_must_be_json_boolean(self) -> None:
        for value, fragment in (
            (MISSING, "significant is required"),
            (1, "significant must be a JSON boolean, got a number"),
            ("true", "significant must be a JSON boolean, got a string"),
            (None, "significant must be a JSON boolean, got null"),
        ):
            with self.subTest(value=repr(value)):
                self.assert_refused(with_change("significant", value), "changes[0]", fragment)

    def test_significant_is_required_on_created_too(self) -> None:
        payload = document(change(kind="created"))
        del payload["changes"][0]["significant"]
        self.assert_refused(encoded(payload), "changes[0]", "significant is required")

    def test_rationale_empty_and_overlong_are_refused(self) -> None:
        for value, fragment in (
            (MISSING, "rationale is required"),
            (1, "rationale must be a JSON string, got a number"),
            ("", "rationale must not be blank"),
            ("   \n\t", "rationale must not be blank"),
            ("x" * (MAX_RATIONALE_CHARS + 1), f"maximum is {MAX_RATIONALE_CHARS}"),
        ):
            with self.subTest(value=repr(value)[:20]):
                self.assert_refused(with_change("rationale", value), "changes[0]", fragment)

    def test_rationale_at_its_limit_is_accepted(self) -> None:
        text = "x" * MAX_RATIONALE_CHARS
        self.assertEqual(parse_changes(with_change("rationale", text)).changes[0].rationale, text)

    def test_rationale_passes_through_diagnostic_text(self) -> None:
        read = parse_changes(with_change("rationale", "Patch\x1b[31m​ window second"))
        self.assertEqual(read.changes[0].rationale, "Patch[31m window\nsecond")

    def test_rationale_of_only_stripped_characters_is_blank(self) -> None:
        self.assert_refused(
            with_change("rationale", "\x1b​"), "changes[0]", "rationale must not be blank"
        )

    def test_rationale_keeps_printable_markup_verbatim(self) -> None:
        text = "| a | <b> `c` \\ café"
        self.assertEqual(parse_changes(with_change("rationale", text)).changes[0].rationale, text)

    def test_detect_by_is_an_instant(self) -> None:
        for value, fragment in (
            (1, "detectBy must be a JSON string, got a number"),
            ("soon", "detectBy must be an RFC 3339 timestamp"),
        ):
            with self.subTest(value=value):
                self.assert_refused(with_change("detectBy", value), "changes[0]", fragment)

    def test_detect_by_before_occurred_at_is_refused(self) -> None:
        self.assert_refused(
            with_change("detectBy", "2026-08-31T23:59:59Z"),
            "changes[0]",
            "detectBy must not be before occurredAt",
        )

    def test_detect_by_equal_to_occurred_at_is_accepted(self) -> None:
        read = parse_changes(with_change("detectBy", OCCURRED_TEXT))
        self.assertEqual(read.changes[0].detect_by, OCCURRED)

    def test_detect_by_compares_instants_not_text(self) -> None:
        read = parse_changes(with_change("detectBy", "2026-08-31T23:00:00-01:00"))
        self.assertEqual(read.changes[0].detect_by, OCCURRED)

    def test_job_follows_the_name_rule(self) -> None:
        for value, fragment in (
            (1, "job must be a JSON string, got a number"),
            ("", "job must be 1 to 128"),
            ("job ", "job must be 1 to 128"),
        ):
            with self.subTest(value=repr(value)):
                self.assert_refused(with_change("job", value), "changes[0]", fragment)

    def test_null_reads_as_absent_on_detect_by_and_job(self) -> None:
        payload = document(change(detectBy=None, job=None))
        absent = document()
        read = parse_changes(encoded(payload)).changes
        self.assertEqual(read, parse_changes(encoded(absent)).changes)
        self.assertIsNone(read[0].detect_by)
        self.assertIsNone(read[0].job)

    def test_null_does_not_stand_in_for_a_required_field(self) -> None:
        self.assert_refused(with_change("rationale", None), "rationale must be a JSON string")
        self.assert_refused(with_change("kind", None), "kind must be a JSON string")


# *--- Resources ---*


class ResourceFieldTests(RefusalCase):
    def test_resources_must_be_an_array(self) -> None:
        self.assert_refused(with_change("resources", MISSING), "changes[0]: resources is required")
        self.assert_refused(
            with_change("resources", {}), "changes[0]: resources must be an array, got an object"
        )

    def test_empty_resources_is_refused(self) -> None:
        self.assert_refused(
            with_change("resources", []), "changes[0]", "resources must name at least one resource"
        )

    def test_too_many_resources_is_refused(self) -> None:
        resources = [pair(f"lab-{index}") for index in range(MAX_CHANGE_RESOURCES + 1)]
        self.assert_refused(
            with_change("resources", resources), "changes[0]", f"maximum is {MAX_CHANGE_RESOURCES}"
        )

    def test_the_resource_limit_itself_is_accepted(self) -> None:
        resources = [pair(f"lab-{index}") for index in range(MAX_CHANGE_RESOURCES)]
        read = parse_changes(with_change("resources", resources))
        self.assertEqual(len(read.changes[0].resources), MAX_CHANGE_RESOURCES)

    def test_a_resource_must_be_an_object(self) -> None:
        self.assert_refused(
            with_change("resources", ["host:lab-01"]),
            "changes[0].resources[0]: the resource must be an object",
        )

    def test_resource_fields_are_identity_text(self) -> None:
        for key in ("resourceType", "resourceId"):
            for name, text in PROHIBITED_TEXT.items():
                with self.subTest(key=key, name=name):
                    self.assert_refused(
                        with_resource(key, text),
                        "changes[0].resources[0]",
                        f"{key} contains prohibited code point",
                    )
            with self.subTest(key=key, value="missing"):
                self.assert_refused(
                    with_resource(key, MISSING), "changes[0].resources[0]", f"{key} is required"
                )
            with self.subTest(key=key, value="number"):
                self.assert_refused(
                    with_resource(key, 1),
                    "changes[0].resources[0]",
                    f"{key} must be a JSON string, got a number",
                )
            with self.subTest(key=key, value="blank"):
                self.assert_refused(
                    with_resource(key, "   "),
                    "changes[0].resources[0]",
                    f"{key} must not be blank",
                )

    def test_package_resource_type_is_refused(self) -> None:
        self.assert_refused(
            with_resource("resourceType", "package"),
            "changes[0].resources[0]",
            "resourceType package is not an information resource",
        )

    def test_colon_in_resource_type_is_refused(self) -> None:
        self.assert_refused(
            with_resource("resourceType", "host:virtual"),
            "changes[0].resources[0]",
            "resourceType must not contain a colon",
        )

    def test_repeated_pair_in_one_change_is_refused(self) -> None:
        self.assert_refused(
            with_change("resources", [pair("lab-01"), pair("lab-02"), pair("lab-01")]),
            "changes[0].resources[2]",
            "repeat changes[0].resources[0]",
        )

    def test_one_pair_in_two_changes_is_accepted(self) -> None:
        read = parse_changes(encoded(document(change("CHG-1"), change("CHG-2"))))
        self.assertEqual(read.change_count, 2)

    def test_identities_are_never_normalized(self) -> None:
        resources = [pair("LAB-01"), pair("lab-01"), pair("lab-01", "HOST")]
        read = parse_changes(with_change("resources", resources))
        self.assertEqual(len(read.changes[0].resources), 3)


# *--- Canonical Order ---*


class CanonicalOrderTests(unittest.TestCase):
    def test_digest_is_of_raw_bytes(self) -> None:
        plain = encoded(document())
        marked = b"\xef\xbb\xbf" + plain
        read = parse_changes(marked)
        self.assertEqual(read.changes, parse_changes(plain).changes)
        self.assertEqual(read.sha256, hashlib.sha256(marked).hexdigest())
        self.assertNotEqual(read.sha256, parse_changes(plain).sha256)
        self.assertEqual(read.size_bytes, len(plain) + 3)

    def test_input_order_never_moves_the_changeset(self) -> None:
        changes = [
            change("CHG-3", occurredAt="2026-09-01T00:00:00Z"),
            change("CHG-1", occurredAt="2026-09-02T00:00:00Z"),
            change("CHG-2", occurredAt="2026-09-01T00:00:00Z"),
            change(
                "CHG-4",
                occurredAt="2026-08-31T23:30:00-01:00",
                resources=[pair("zeta"), pair("alpha"), pair("beta", "file")],
            ),
        ]
        baseline = parse_changes(encoded(document(*changes)))
        self.assertEqual(
            [item.change_id for item in baseline.changes],
            ["CHG-2", "CHG-3", "CHG-4", "CHG-1"],
        )
        self.assertEqual(
            baseline.changes[2].resources,
            (
                ResourceRef("beta", "file"),
                ResourceRef("alpha", "host"),
                ResourceRef("zeta", "host"),
            ),
        )
        shuffler = random.Random(20261108)
        for _ in range(8):
            shuffled = copy.deepcopy(changes)
            shuffler.shuffle(shuffled)
            for item in shuffled:
                shuffler.shuffle(item["resources"])
            self.assertEqual(parse_changes(encoded(document(*shuffled))).changes, baseline.changes)

    def test_a_change_set_is_hashable_and_equal_by_value(self) -> None:
        content = encoded(document())
        first = parse_changes(content)
        second = parse_changes(content)
        self.assertEqual(first, second)
        self.assertEqual(hash(first), hash(second))
        self.assertIsNot(first, second)


# *--- Contract Types ---*


class ContractTypeTests(unittest.TestCase):
    def base(self) -> Change:
        return parse_changes(encoded(document())).changes[0]

    def test_opens_obligation(self) -> None:
        base = self.base()
        for kind, significant, expected in (
            (ChangeKind.CREATED, True, True),
            (ChangeKind.CREATED, False, True),
            (ChangeKind.MODIFIED, True, True),
            (ChangeKind.MODIFIED, False, False),
        ):
            with self.subTest(kind=kind, significant=significant):
                item = dataclasses.replace(base, kind=kind, significant=significant)
                self.assertIs(item.opens_obligation, expected)

    def test_a_kind_is_lowercase_text(self) -> None:
        self.assertEqual(ChangeKind.CREATED.value, "created")
        self.assertEqual(ChangeKind.MODIFIED.value, "modified")

    def test_a_directly_built_change_holds_the_contract(self) -> None:
        base = self.base()
        later = ResourceRef("zeta", "host")
        earlier = ResourceRef("alpha", "host")
        for name, fields in (
            ("no resources", {"resources": ()}),
            ("unsorted", {"resources": (later, earlier)}),
            ("repeated", {"resources": (earlier, earlier)}),
            ("window before change", {"detect_by": OCCURRED - timedelta(seconds=1)}),
            ("naive instant", {"occurred_at": datetime(2026, 9, 1)}),
            ("naive window", {"detect_by": datetime(2026, 9, 2)}),
        ):
            with self.subTest(name=name), self.assertRaises(ValueError):
                dataclasses.replace(base, **fields)  # type: ignore[arg-type]

    def test_a_change_kind_must_be_the_enum(self) -> None:
        with self.assertRaises(TypeError):
            dataclasses.replace(self.base(), kind="created")  # type: ignore[arg-type]

    def test_a_directly_built_change_set_holds_its_order(self) -> None:
        base = self.base()
        later = dataclasses.replace(base, change_id="CHG-2", occurred_at=OCCURRED + timedelta(1))
        for name, changes in (("unsorted", (later, base)), ("repeated id", (base, base))):
            with self.subTest(name=name), self.assertRaises(ValueError):
                ChangeSet(name="n", sha256="0" * 64, size_bytes=1, changes=changes)
        same_id_later = dataclasses.replace(base, occurred_at=OCCURRED + timedelta(1))
        with self.assertRaises(ValueError):
            ChangeSet(name="n", sha256="0" * 64, size_bytes=1, changes=(base, same_id_later))


# *--- Loader ---*


class LoaderTests(unittest.TestCase):
    def test_load_reads_the_same_change_set(self) -> None:
        content = encoded(document())
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "changes.json"
            path.write_bytes(content)
            self.assertEqual(load_changes(path), parse_changes(content))

    def test_a_missing_file_cannot_be_read(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            with self.assertRaisesRegex(ReportInputError, "^changes cannot be read: "):
                load_changes(Path(directory) / "absent.json")

    def test_a_directory_cannot_be_read(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            with self.assertRaisesRegex(ReportInputError, "^changes cannot be read: "):
                load_changes(Path(directory))

    def test_an_oversize_file_exceeds_a_limit(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "changes.json"
            path.write_bytes(b" " * (MAX_CHANGES_BYTES + 1))
            with self.assertRaisesRegex(ReportInputError, "^changes exceeds a limit: "):
                load_changes(path)


# *--- Examples ---*


class ExampleTests(unittest.TestCase):
    def test_example_change_file_parses(self) -> None:
        for path in EXAMPLE_FILES:
            with self.subTest(path=path.name):
                self.assertGreater(load_changes(path).change_count, 0)

    def test_the_example_shows_each_kind_of_change(self) -> None:
        changes = load_changes(EXAMPLE_FILES[0]).changes
        self.assertTrue(any(item.kind is ChangeKind.CREATED for item in changes))
        modified = [item for item in changes if item.kind is ChangeKind.MODIFIED]
        self.assertTrue(any(item.significant for item in modified))
        self.assertTrue(any(not item.significant for item in modified))
        named = {ref for item in changes for ref in item.resources}
        self.assertIn(ResourceRef("sample-group/ir-runbooks", "logical"), named)

    def test_the_example_names_a_pair_the_example_inventory_lacks(self) -> None:
        inventory = json.loads(
            (REPO_ROOT / "examples" / "inventory.json").read_text(encoding="utf-8")
        )
        known = set()
        for entry in inventory["resources"]:
            for item in [entry, *entry.get("aliases", [])]:
                known.add((item["resourceType"], item["resourceId"]))
        named = {
            (ref.resource_type, ref.resource_id)
            for item in load_changes(EXAMPLE_FILES[0]).changes
            for ref in item.resources
        }
        self.assertTrue(named - known - {("logical", "sample-group/ir-runbooks")})


if __name__ == "__main__":
    unittest.main()
