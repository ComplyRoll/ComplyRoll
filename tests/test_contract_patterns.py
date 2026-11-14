# ******************************************************************************
# *Title: Contract Pattern Anchor Tests*
# *Author: Kyle Versluis*
# *Description: Every anchored contract pattern ends at the end of the text.*
# ******************************************************************************
"""Tests that no anchored contract pattern admits a final newline (CL-83, ADR 0008).

A JSON Schema `pattern` is a search, and Python's `$` also matches just before a final `\\n`,
so a pattern spelled `^...$` passed a digest, a tracking id or an instant with a newline after
it. Each pattern now ends on `(?!\\n)$`, which matches only at the end of the text in Python
and in ECMA-262 alike.
"""

# *--- Imports ---*

from __future__ import annotations

import hashlib
import json
import sqlite3
import unittest
from collections.abc import Iterator, Mapping
from datetime import datetime
from pathlib import Path
from typing import Any
from unittest.mock import patch

from jsonschema import Draft202012Validator
from test_cli import (
    INGESTED_AT,
    INVOCATION_FIXTURE,
    SARIF_NEXT,
    PersistedStoreTestCase,
    cli_module,
    run,
)
from test_events import (
    ARTIFACT_STREAM_ID,
    COVERAGE_STREAM_ID,
    DIGEST,
    FAILURE_STREAM_ID,
    GOOD_PAYLOADS,
    HELD_STREAM_ID,
    NOW,
    STREAM_ID,
    metadata,
    with_value,
)
from test_replay import bumped

from complyroll.adapters import IngestResult, ingest_stig_artifact
from complyroll.events import (
    CHANGE_GAP_STREAM_SCHEMA_VERSION,
    CHANGE_STREAM_SCHEMA_VERSION,
    COVERAGE_STREAM_SCHEMA_VERSION,
    EVENT_CONTRACTS,
    FAILURE_STREAM_SCHEMA_VERSION,
    HELD_FAILURE_SCHEMA_VERSION,
    EventContractError,
    EventRepository,
    change_stream_id,
)
from complyroll.history import audit_history
from complyroll.store import NewEvent, SQLiteEventStore

# *--- Fixtures ---*

#: Every string property of every contract whose pattern is anchored at both ends, written out
#: rather than derived, so a new anchored field has to be added here and so to every test below.
ANCHORED_FIELDS: dict[str, tuple[str, ...]] = {
    "artifact.ingested": ("/sha256", "/ingestedAt"),
    "observation.recorded": (
        "/fingerprint",
        "/observed_at",
        "/ingested_at",
        "/source_artifact_digest",
    ),
    "case.created": ("/trackingId", "/createdAt"),
    "case.observation_linked": ("/observedAt", "/sourceArtifactSha256"),
    "detection.attested": ("/detectedAt", "/attestedAt"),
    "case.evaluated": ("/completedAt", "/projectedNextReduction/estimatedAt"),
    "case.pain_reduced": ("/reducedAt",),
    "case.disposition_recorded": ("/recordedAt",),
    "failure.recorded": ("/sha256", "/ingestedAt"),
    "failure.held": ("/sha256", "/ingestedAt"),
    "coverage.recorded": ("/windowClosedAt", "/anchorAt", "/inventorySha256"),
    "change.recorded": (
        "/changeId",
        "/occurredAt",
        "/source/tool",
        "/detectBy",
        "/job",
        "/changesName",
        "/changesSha256",
        "/recordedAt",
    ),
    "change.gap_recorded": (
        "/changeId",
        "/windowClosedAt",
        "/occurredAt",
        "/changesSha256",
        "/inventorySha256",
    ),
}

#: A value the field holds when the good payload leaves it null.
NON_NULL_VALUES: dict[tuple[str, str], str] = {
    ("observation.recorded", "/observed_at"): "2026-08-01T00:00:00+00:00",
    ("case.observation_linked", "/observedAt"): "2026-08-01T00:00:00Z",
}

#: Where each event type is stored past the repository, and the schema that stream needs.
STREAMS: dict[str, tuple[str, int]] = {
    "artifact.ingested": (ARTIFACT_STREAM_ID, 1),
    "observation.recorded": (ARTIFACT_STREAM_ID, 1),
    "case.created": (STREAM_ID, 1),
    "case.observation_linked": (STREAM_ID, 1),
    "detection.attested": (STREAM_ID, 1),
    "case.evaluated": (STREAM_ID, 1),
    "case.pain_reduced": (STREAM_ID, 1),
    "case.disposition_recorded": (STREAM_ID, 1),
    "failure.recorded": (FAILURE_STREAM_ID, FAILURE_STREAM_SCHEMA_VERSION),
    "failure.held": (HELD_STREAM_ID, HELD_FAILURE_SCHEMA_VERSION),
    "coverage.recorded": (COVERAGE_STREAM_ID, COVERAGE_STREAM_SCHEMA_VERSION),
    "change.recorded": (change_stream_id("CHG-1001"), CHANGE_STREAM_SCHEMA_VERSION),
    "change.gap_recorded": (f"changegap/{DIGEST}", CHANGE_GAP_STREAM_SCHEMA_VERSION),
}

#: The twelve fields `store verify` passed with a final newline before this change, each left in
#: the store below by the writing commands, with the code a case-folding reader now refuses it
#: with, or None where `cases list` still reads the store.
VERIFIED_CLEAN: tuple[tuple[str, str, str | None], ...] = (
    ("artifact.ingested", "/ingestedAt", None),
    ("failure.recorded", "/ingestedAt", None),
    ("failure.held", "/ingestedAt", None),
    ("case.created", "/createdAt", "event_contract_invalid"),
    ("case.observation_linked", "/observedAt", "event_contract_invalid"),
    ("case.observation_linked", "/sourceArtifactSha256", "event_contract_invalid"),
    ("detection.attested", "/detectedAt", "event_contract_invalid"),
    ("detection.attested", "/attestedAt", "event_contract_invalid"),
    ("case.evaluated", "/completedAt", "event_contract_invalid"),
    ("case.evaluated", "/projectedNextReduction/estimatedAt", "event_contract_invalid"),
    ("case.pain_reduced", "/reducedAt", "event_contract_invalid"),
    ("case.disposition_recorded", "/recordedAt", "event_contract_invalid"),
)

# *--- Helper Functions ---*


def patterns(node: Any, pointer: str = "") -> Iterator[tuple[str, str]]:
    """Yield every `pattern` keyword anywhere in one schema document, with where it sits."""

    if isinstance(node, Mapping):
        for key, value in node.items():
            if key == "pattern" and isinstance(value, str):
                yield pointer, value
            else:
                yield from patterns(value, f"{pointer}/{key}")
    elif isinstance(node, (list, tuple)):
        for index, value in enumerate(node):
            yield from patterns(value, f"{pointer}/{index}")


def anchored_fields(schema: Mapping[str, Any], prefix: str = "") -> list[str]:
    """Return the JSON pointer of every property whose own pattern is anchored at both ends."""

    found: list[str] = []
    for name, subschema in schema.get("properties", {}).items():
        pointer = f"{prefix}/{name}"
        pattern = subschema.get("pattern")
        if isinstance(pattern, str) and pattern.startswith("^") and pattern.endswith("$"):
            found.append(pointer)
        found.extend(anchored_fields(subschema, pointer))
    return found


def good_value(event_type: str, pointer: str) -> str:
    """Return the text one anchored field holds in the good payload."""

    value = NON_NULL_VALUES.get((event_type, pointer))
    if value is not None:
        return value
    current: Any = GOOD_PAYLOADS[event_type]
    for part in pointer.split("/")[1:]:
        current = current[part]
    assert isinstance(current, str), (event_type, pointer)
    return current


def with_newline(event_type: str, pointer: str) -> dict[str, Any]:
    """Return the good payload with one anchored field followed by a final newline."""

    return with_value(GOOD_PAYLOADS[event_type], pointer, f"{good_value(event_type, pointer)}\n")


def rows() -> Iterator[tuple[str, str]]:
    for event_type, pointers in ANCHORED_FIELDS.items():
        for pointer in pointers:
            yield event_type, pointer


# *--- Tests ---*


class ContractPatternAnchorTests(unittest.TestCase):
    """Every anchored pattern refuses a final newline, at append and in `store verify`."""

    def setUp(self) -> None:
        store = SQLiteEventStore(":memory:")
        self.addCleanup(store.close)
        self.repository = EventRepository(store)

    def test_no_contract_pattern_ends_on_a_bare_dollar(self) -> None:
        seen = 0
        for (event_type, version), schema in EVENT_CONTRACTS.items():
            for pointer, pattern in patterns(schema):
                seen += 1
                with self.subTest(event_type=event_type, version=version, pointer=pointer):
                    if pattern.endswith("$"):
                        self.assertTrue(pattern.endswith("(?!\\n)$"), pattern)
        # The walk must keep reaching the patterns, or the pin says nothing.
        self.assertGreater(seen, 36)

    def test_the_anchored_fields_are_the_ones_the_next_tests_name(self) -> None:
        found = {
            event_type: tuple(anchored_fields(schema))
            for (event_type, _), schema in EVENT_CONTRACTS.items()
        }
        self.assertEqual(
            {event_type: fields for event_type, fields in found.items() if fields},
            ANCHORED_FIELDS,
        )

    def test_a_final_newline_is_refused_at_append_on_every_anchored_field(self) -> None:
        for event_type, pointer in rows():
            with self.subTest(event_type=event_type, pointer=pointer):
                with self.assertRaises(EventContractError) as caught:
                    self.repository.validate_payload(event_type, with_newline(event_type, pointer))
                self.assertEqual(
                    [
                        (issue.instance_pointer, issue.validator)
                        for issue in caught.exception.issues
                    ],
                    [(pointer, "pattern")],
                )

    def test_the_field_text_without_the_newline_still_passes_the_contract(self) -> None:
        # The refusal above is the newline's alone: the same text without it passes the schema.
        for event_type, pointer in rows():
            with self.subTest(event_type=event_type, pointer=pointer):
                payload = with_value(
                    GOOD_PAYLOADS[event_type], pointer, good_value(event_type, pointer)
                )
                schema = EVENT_CONTRACTS[(event_type, 1)]
                self.assertEqual(list(Draft202012Validator(schema).iter_errors(payload)), [])

    def test_store_verify_names_a_stored_final_newline_as_a_contract_fault(self) -> None:
        # Placed past the repository with the store's own append, as another tool or an older
        # build would leave it; `audit_history` is the domain half of `store verify`.
        for event_type, pointer in rows():
            with self.subTest(event_type=event_type, pointer=pointer):
                store = SQLiteEventStore(":memory:")
                self.addCleanup(store.close)
                stream_id, schema = STREAMS[event_type]
                (record,) = store.append(
                    stream_id,
                    [
                        NewEvent(
                            event_type=event_type,
                            occurred_at=NOW,
                            payload=with_newline(event_type, pointer),
                            metadata=metadata().to_dict(),
                        )
                    ],
                    expected_version=0,
                    requires_schema=schema,
                )

                faults = audit_history(EventRepository(store))

                named = [
                    fault
                    for fault in faults
                    if fault.sequence == record.sequence
                    and fault.code == "payload_contract_invalid"
                    and f"{pointer}: pattern: " in fault.message
                ]
                self.assertEqual(len(named), 1, faults)


class StoredNewlineCommandTests(PersistedStoreTestCase):
    """A field `store verify` passed with a final newline is now a fault the readers name.

    Each store is the documented four-command store plus a flagged ingest of a SARIF log whose
    failed invocation is recorded beside timed results, and the same log read again by the next
    parser version, whose failure is held, with one field rewritten in place, digest included, as
    another tool or an older build would leave it. `cases history` reads only its case's stream,
    so it still prints the case (CL-104).
    """

    def setUp(self) -> None:
        super().setUp()
        self.ingest_fixtures()
        flagged = ["ingest", str(INVOCATION_FIXTURE), "--record-failed-imports"]
        flagged += ["--db", str(self.database), "--as-of", INGESTED_AT]
        code, _out, err = run(flagged)
        self.assertEqual(code, 3, err)
        self.correlate()
        self.attest_missing()
        self.evaluate()

        # The hold is test_cli's recipe: the next version reads the log the installed one read.
        def read_by_the_next_version(path: Path, *, ingested_at: datetime) -> IngestResult:
            return bumped(ingest_stig_artifact(path, ingested_at=ingested_at), SARIF_NEXT)

        with patch.object(cli_module, "ingest_stig_artifact", read_by_the_next_version):
            code, _out, err = run(flagged)
        self.assertEqual(code, 3, err)
        self.correlate()
        self.assertEqual(run(["store", "verify", "--db", str(self.database)])[0], 0)
        self.pristine = self.database

    def rewrite(self, event_type: str, pointer: str) -> tuple[int, str]:
        """Add a final newline to one text field of the first event carrying it as text."""

        parts = pointer.split("/")[1:]
        placed: list[tuple[int, str]] = []

        def work(connection: sqlite3.Connection) -> None:
            for row in connection.execute(
                "SELECT sequence, stream_id, payload_json FROM events WHERE event_type = ? "
                "ORDER BY sequence",
                (event_type,),
            ).fetchall():
                payload = json.loads(row["payload_json"])
                target: Any = payload
                for part in parts[:-1]:
                    target = target.get(part) if isinstance(target, dict) else None
                if not isinstance(target, dict) or not isinstance(target.get(parts[-1]), str):
                    continue
                target[parts[-1]] += "\n"
                text = self.canonical(payload)
                connection.execute(
                    "UPDATE events SET payload_json = ?, payload_sha256 = ? WHERE sequence = ?",
                    (text, hashlib.sha256(text.encode("utf-8")).hexdigest(), row["sequence"]),
                )
                placed.append((row["sequence"], row["stream_id"]))
                return

        self.update(work)
        self.assertEqual(len(placed), 1, f"no {event_type} carries {pointer} as text")
        return placed[0]

    def test_each_field_verify_passed_is_now_a_contract_fault_the_readers_name(self) -> None:
        for event_type, pointer, folded in VERIFIED_CLEAN:
            with self.subTest(event_type=event_type, pointer=pointer):
                self.copy_store(self.pristine, f"{event_type}-{pointer.count('/')}.db")
                sequence, stream_id = self.rewrite(event_type, pointer)
                database = str(self.database)

                code, out, err = run(["store", "verify", "--db", database])

                self.assertEqual((code, out), (1, ""), err)
                (fault, summary) = err.splitlines()
                self.assertTrue(
                    fault.startswith(
                        f"error: sequence {sequence}: payload_contract_invalid: {event_type} "
                        f"version 1 payload is invalid: {pointer}: pattern: "
                    ),
                    fault,
                )
                self.assertTrue(summary.startswith("faults: 1 domain fault(s) in "), summary)
                report = [
                    "report",
                    "vdt",
                    "--db",
                    database,
                    "--class",
                    "C",
                    "--package-uri",
                    "https://example.test/cpo",
                    "--from",
                    "2026-08-01T00:00:00Z",
                    "--to",
                    "2026-08-31T23:59:59Z",
                    "--as-of",
                    INGESTED_AT,
                    "-o",
                    str(self.workspace / "vdt.json"),
                ]
                code, out, err = run(report)
                self.assertEqual(code, 1, err)
                expected = folded or "history_invalid"
                self.assertIn(f"error: {expected}: ", err)
                self.assertIn(f"{pointer}: pattern: ", err)
                code, out, err = run(["cases", "list", "--db", database])
                if folded is None:
                    self.assertEqual(code, 0, err)
                else:
                    self.assertEqual(code, 1, err)
                    self.assertIn(f"error: {folded}: ", err)
                if stream_id.startswith("case/"):
                    tracking_id = stream_id.removeprefix("case/")
                    code, out, err = run(["cases", "history", tracking_id, "--db", database])
                    self.assertEqual((code, err), (0, ""))


if __name__ == "__main__":
    unittest.main()
