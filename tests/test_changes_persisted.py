# ******************************************************************************
# *Title: Changes Persisted Tests*
# *Author: Kyle Versluis*
# *Description: The store path of the change block and the detection request.*
# ******************************************************************************
"""Tests for `report --db` and `changes pending --db` reading stored changes (ADR 0018)."""

# *--- Imports ---*

from __future__ import annotations

import json
import re
from collections.abc import Sequence
from dataclasses import replace
from datetime import UTC, datetime
from pathlib import Path
from typing import Any
from unittest import mock

from test_changes_pending import AFTER_THE_LAST_SCAN, pending_argv
from test_changes_report import change_entry, change_file
from test_cli import (
    ACCEPTED_EVALUATIONS,
    AVI_ARGUMENTS,
    EXAMPLE_CHANGES,
    EXAMPLE_INVENTORY,
    FIXTURES,
    GOLDEN,
    HISTORICAL_ARGUMENTS,
    INGESTED_AT,
    KEV_CATALOG,
    REPORT_ARGUMENTS,
    TIMED_ARTIFACTS,
    TIMED_AS_OF,
    TIMED_CHANGES,
    TIMED_INVENTORY,
    PersistedStoreTestCase,
    run,
    stripped_policy,
)
from test_coverage_gap_report import WINDOW_KEYS
from test_coverage_history import CoverageStoreFixture, mark_schema_4_by_hand
from test_coverage_streams import metadata
from test_replay import compile_from_history
from test_reports import AS_OF, options

from complyroll.events import (
    CHANGE_RECORDED,
    EventRepository,
    change_stream_id,
    coverage_stream_id,
)
from complyroll.history import HistoryError, read_stored_changes, record_changes
from complyroll.reports import (
    StoredChangeSet,
    compile_record_set_from_history,
    load_changes,
    load_inventory,
    parse_changes,
)
from complyroll.reports import records as records_module
from complyroll.reports.changes_input import Change, ChangeKind, ChangeSource
from complyroll.store import NewEvent, SQLiteEventStore

# *--- Fixtures ---*

RECORDED_AT = "2026-11-09T12:00:00Z"
KINDS = ("vdt", "avi", "historical")
HELPERS = "https://github.com/example/webapp/src/ui/helpers.js"
SMUGGLED = metadata().to_dict()
#: A coverage gap note's codes, none of which a store that recorded no gap may print.
GAP_NOTES = ("coverage_gap_unrecorded", "coverage_gap_contradicted", "coverage_gap_unmatched")
#: The block's `input` object, at the indentation the JSON writer gives its keys.
BLOCK_INPUT = r'^ {6}"input": \{$.*?^ {6}\},\n'
REQUEST_INPUT = r'^ {2}"input": \{$.*?^ {2}\},\n'


def cut(text: str, pattern: str) -> str:
    """Return text with the one region a pattern names removed, lines and all."""
    trimmed, count = re.subn(pattern, "", text, flags=re.MULTILINE | re.DOTALL)
    assert count == 1, f"{pattern!r} matched {count} time(s)"
    return trimmed


def without_block_input(text: str) -> str:
    return cut(text, BLOCK_INPUT)


def without_request_input(text: str) -> str:
    return cut(text, REQUEST_INPUT)


def without_intro(markdown: str) -> str:
    """Return a Markdown twin with the Changes section's intro line removed."""
    lines = markdown.split("\n")
    intros = [
        index
        for index, line in enumerate(lines)
        if line.startswith(("Changes declared in ", "Changes recorded in the store "))
    ]
    assert len(intros) == 1, intros
    del lines[intros[0]]
    return "\n".join(lines)


def store_input(digest_counts: dict[str, int]) -> dict[str, Any]:
    return {
        "source": "store",
        "changesSha256": [
            {"sha256": digest, "changes": digest_counts[digest]} for digest in sorted(digest_counts)
        ],
    }


def sha256_of(path: Path) -> str:
    return load_changes(path).sha256


# *--- Base ---*


class ChangesStoreCase(PersistedStoreTestCase):
    """A store driven through the command line, as an operator records and reads changes."""

    def record(self, path: Path = EXAMPLE_CHANGES, *, as_of: str = RECORDED_AT) -> str:
        out, _ = self.succeeds(
            ["changes", "record", "--db", str(self.database), "--changes", str(path)]
            + ["--as-of", as_of, "--actor", "golden"]
        )
        return out

    def persisted(self, kind: str = "vdt", *extra: str) -> list[str]:
        """Return one report from this store, with the golden options."""
        argv = [
            "report",
            kind,
            "--db",
            str(self.database),
            "--class",
            "C",
            "--package-uri",
            "https://example.test/cpo",
            "--as-of",
            INGESTED_AT,
        ]
        if kind != "historical":
            argv += ["--from", "2026-08-01T00:00:00Z", "--to", "2026-08-31T23:59:59Z"]
        return [*argv, *extra]

    def write_changes(self, *changes: dict[str, Any], name: str = "cli-changes") -> Path:
        path = self.workspace / f"{name}.json"
        path.write_text(json.dumps(change_file(*changes, name=name)), encoding="utf-8")
        return path

    def report_outputs(self, argv: Sequence[str], stem: str) -> tuple[str, str, str]:
        """Run one report, return its JSON, its Markdown twin and its standard error."""
        json_path = self.workspace / f"{stem}.json"
        markdown_path = self.workspace / f"{stem}.md"
        code, _, err = run([*argv, "-o", str(json_path), "--markdown", str(markdown_path)])
        self.assertEqual(code, 0, msg=err)
        return (
            json_path.read_text(encoding="utf-8"),
            markdown_path.read_text(encoding="utf-8"),
            err,
        )


# *--- Replay ---*


class ReportReplayTests(ChangesStoreCase):
    """Review focus 2: a replay equals the stateless run but for `input` and its intro line."""

    def stateless(self, kind: str) -> list[str]:
        if kind == "avi":
            argv = list(AVI_ARGUMENTS)
        elif kind == "historical":
            argv = list(HISTORICAL_ARGUMENTS)
        else:
            argv = [*REPORT_ARGUMENTS[:-1], str(ACCEPTED_EVALUATIONS)]
        return [
            *argv,
            "--inventory",
            str(EXAMPLE_INVENTORY),
            "--changes",
            str(EXAMPLE_CHANGES),
        ]

    def test_every_report_equals_the_stateless_run_but_for_input_and_its_intro_line(self) -> None:
        self.populate(ACCEPTED_EVALUATIONS)
        self.record()
        for kind in KINDS:
            with self.subTest(report=kind):
                stateless_json, stateless_markdown, stateless_err = self.report_outputs(
                    self.stateless(kind), f"{kind}-stateless"
                )
                stored_json, stored_markdown, stored_err = self.report_outputs(
                    self.persisted(kind, "--inventory", str(EXAMPLE_INVENTORY)), f"{kind}-stored"
                )

                self.assertEqual(
                    without_block_input(stored_json), without_block_input(stateless_json)
                )
                self.assertEqual(without_intro(stored_markdown), without_intro(stateless_markdown))
                self.assertEqual(stored_err, stateless_err)

    def test_the_block_input_names_the_store_and_each_digest_with_its_count(self) -> None:
        self.populate(ACCEPTED_EVALUATIONS)
        self.record()

        stored_json, stored_markdown, _ = self.report_outputs(
            self.persisted("vdt", "--inventory", str(EXAMPLE_INVENTORY)), "stored"
        )

        count = load_changes(EXAMPLE_CHANGES).change_count
        digest = sha256_of(EXAMPLE_CHANGES)
        self.assertEqual(
            json.loads(stored_json)["x-complyroll"]["changes"]["input"],
            store_input({digest: count}),
        )
        self.assertIn(
            f"Changes recorded in the store ({count} changes: {count} from SHA-256 {digest}), "
            "read against the inventory",
            stored_markdown,
        )

    def test_two_files_are_named_by_their_digests_in_order_with_their_counts(self) -> None:
        self.populate(ACCEPTED_EVALUATIONS)
        first = self.write_changes(change_entry("CHG-1"), name="first")
        second = self.write_changes(change_entry("CHG-2"), change_entry("CHG-3"), name="second")
        self.record(first)
        self.record(second)

        out, _ = self.succeeds(self.persisted("vdt", "--inventory", str(EXAMPLE_INVENTORY)))

        self.assertEqual(
            json.loads(out)["x-complyroll"]["changes"]["input"],
            store_input({sha256_of(first): 1, sha256_of(second): 2}),
        )

    def test_a_change_recorded_again_from_another_file_keeps_its_first_digest(self) -> None:
        self.populate(ACCEPTED_EVALUATIONS)
        original = self.write_changes(change_entry("CHG-1"), name="original")
        grown = self.write_changes(change_entry("CHG-1"), change_entry("CHG-2"), name="grown")
        self.record(original)
        self.record(grown)

        out, _ = self.succeeds(self.persisted("vdt", "--inventory", str(EXAMPLE_INVENTORY)))

        self.assertEqual(
            json.loads(out)["x-complyroll"]["changes"]["input"],
            store_input({sha256_of(original): 1, sha256_of(grown): 1}),
        )

    def test_the_store_replays_into_the_replay_golden_pair(self) -> None:
        self.populate()
        self.record()

        stored_json, stored_markdown, _ = self.report_outputs(
            self.persisted("vdt", "--inventory", str(EXAMPLE_INVENTORY)), "replay"
        )

        self.assertEqual(
            stored_json, (GOLDEN / "vdt-changes-replay.json").read_text(encoding="utf-8")
        )
        self.assertEqual(
            stored_markdown, (GOLDEN / "vdt-changes-replay.md").read_text(encoding="utf-8")
        )

    def test_the_replay_golden_differs_from_the_stateless_golden_only_in_input(self) -> None:
        replay_json = (GOLDEN / "vdt-changes-replay.json").read_text(encoding="utf-8")
        replay_markdown = (GOLDEN / "vdt-changes-replay.md").read_text(encoding="utf-8")
        stateless_json = (GOLDEN / "vdt-changes.json").read_text(encoding="utf-8")
        stateless_markdown = (GOLDEN / "vdt-changes.md").read_text(encoding="utf-8")

        self.assertEqual(without_block_input(replay_json), without_block_input(stateless_json))
        self.assertEqual(without_intro(replay_markdown), without_intro(stateless_markdown))

    def test_no_change_stream_reads_as_the_coverage_golden(self) -> None:
        self.populate()

        stored_json, stored_markdown, _ = self.report_outputs(
            self.persisted("vdt", "--inventory", str(EXAMPLE_INVENTORY)), "plain"
        )

        self.assertEqual(stored_json, (GOLDEN / "vdt-coverage.json").read_text(encoding="utf-8"))
        self.assertEqual(stored_markdown, (GOLDEN / "vdt-coverage.md").read_text(encoding="utf-8"))
        with SQLiteEventStore(self.database) as store:
            self.assertEqual(store.schema_version, 1)

    def test_block_needs_a_change_stream_and_an_inventory(self) -> None:
        self.populate()
        inventory = ("--inventory", str(EXAMPLE_INVENTORY))
        without_stream, _ = self.succeeds(self.persisted("vdt", *inventory))
        self.assertNotIn("changes", json.loads(without_stream)["x-complyroll"])

        self.record()

        with_stream, _ = self.succeeds(self.persisted("vdt", *inventory))
        self.assertIn("changes", json.loads(with_stream)["x-complyroll"])
        bare, _ = self.succeeds(self.persisted("vdt"))
        self.assertNotIn("changes", json.loads(bare)["x-complyroll"])

    def test_no_inventory_means_no_block_and_no_refusal(self) -> None:
        self.populate()
        self.record()

        out, err = self.succeeds(self.persisted("vdt"))

        self.assertNotIn("changes", json.loads(out)["x-complyroll"])
        self.assertNotIn("change_", err)

    def test_recorded_at_reaches_no_output(self) -> None:
        self.populate()
        self.record(as_of=RECORDED_AT)
        first_json, first_markdown, first_err = self.report_outputs(
            self.persisted("vdt", "--inventory", str(EXAMPLE_INVENTORY)), "first"
        )
        request_argv = [
            "changes",
            "pending",
            "--db",
            str(self.database),
            "--inventory",
            str(EXAMPLE_INVENTORY),
            "--class",
            "C",
            "--as-of",
            INGESTED_AT,
        ]
        first_request, _ = self.succeeds(request_argv)

        # A second store, the same inputs, a change recorded a year later.
        self.database = self.workspace / "second.db"
        self.populate()
        self.record(as_of="2027-12-31T23:59:59Z")

        second_json, second_markdown, second_err = self.report_outputs(
            self.persisted("vdt", "--inventory", str(EXAMPLE_INVENTORY)), "second"
        )
        request_argv[3] = str(self.database)
        second_request, _ = self.succeeds(request_argv)
        self.assertEqual(first_json, second_json)
        self.assertEqual(first_markdown, second_markdown)
        self.assertEqual(first_err, second_err)
        self.assertEqual(first_request, second_request)

    def test_a_replay_under_a_reordered_file_is_byte_identical(self) -> None:
        self.populate()
        document = json.loads(EXAMPLE_CHANGES.read_text(encoding="utf-8"))
        document["changes"].reverse()
        for change in document["changes"]:
            change["resources"].reverse()
        reordered = self.workspace / "reordered.json"
        reordered.write_text(json.dumps(document), encoding="utf-8")
        self.record(reordered)

        out, _ = self.succeeds(self.persisted("vdt", "--inventory", str(EXAMPLE_INVENTORY)))

        expected = (GOLDEN / "vdt-changes-replay.json").read_text(encoding="utf-8")
        self.assertEqual(without_block_input(out), without_block_input(expected))

    def test_each_warning_is_located_under_the_file_its_change_came_from(self) -> None:
        self.populate()
        unregistered = [{"resourceType": "file", "resourceId": "src/unlisted.js"}]
        before_as_of = "2026-08-01T00:00:00Z"
        first = self.write_changes(
            change_entry("CHG-1", occurredAt=before_as_of, resources=unregistered), name="first"
        )
        second = self.write_changes(
            change_entry(
                "CHG-2",
                occurredAt=before_as_of,
                resources=[{"resourceType": "file", "resourceId": "src/b.js"}],
            ),
            name="second",
        )
        self.record(first)
        self.record(second)

        _, err = self.succeeds(self.persisted("vdt", "--inventory", str(EXAMPLE_INVENTORY)))

        self.assertIn("[first CHG-1 file:src/unlisted.js]", err)
        self.assertIn("[second CHG-2 file:src/b.js]", err)

    def test_a_dataset_without_the_rule_refuses_a_store_holding_changes(self) -> None:
        self.populate()
        self.record()

        with mock.patch.object(records_module, "select_policy", stripped_policy("VDR-CSO-DAC")):
            code, out, err = run(self.persisted("vdt", "--inventory", str(EXAMPLE_INVENTORY)))

        self.assertEqual((code, out), (1, ""))
        self.assertIn("error: change_rule_unavailable:", err)
        self.assertIn("[example-changes]", err)

    def test_a_dataset_without_the_rule_does_not_touch_a_store_with_no_change(self) -> None:
        self.populate()

        with mock.patch.object(records_module, "select_policy", stripped_policy("VDR-CSO-DAC")):
            code, _, err = run(self.persisted("vdt", "--inventory", str(EXAMPLE_INVENTORY)))

        self.assertEqual(code, 0, msg=err)
        self.assertNotIn("change_rule_unavailable", err)


class TimedReplayTests(ChangesStoreCase):
    """The timed run: every status, the group stand-in and the late row, read from a store."""

    def populate_timed(self) -> None:
        self.succeeds(
            ["ingest", *TIMED_ARTIFACTS, "--db", str(self.database), "--as-of", TIMED_AS_OF]
        )
        self.record(TIMED_CHANGES)

    def timed(self, *extra: str) -> list[str]:
        return [
            "report",
            "vdt",
            "--db",
            str(self.database),
            "--class",
            "C",
            "--package-uri",
            "https://example.test/cpo",
            "--calendar-tz",
            "UTC",
            "--as-of",
            TIMED_AS_OF,
            "--from",
            "2026-09-01T00:00:00Z",
            "--to",
            "2026-09-30T23:59:59Z",
            "--inventory",
            str(TIMED_INVENTORY),
            *extra,
        ]

    def test_the_timed_store_equals_the_stateless_timed_golden_but_for_input(self) -> None:
        self.populate_timed()

        stored_json, stored_markdown, _ = self.report_outputs(self.timed(), "timed")

        golden_json = (GOLDEN / "vdt-changes-timed.json").read_text(encoding="utf-8")
        golden_markdown = (GOLDEN / "vdt-changes-timed.md").read_text(encoding="utf-8")
        self.assertEqual(without_block_input(stored_json), without_block_input(golden_json))
        self.assertEqual(without_intro(stored_markdown), without_intro(golden_markdown))


class KevAndDecommissionTests(ChangesStoreCase):
    """The KEV and decommission rules of ADR 0018 hold unchanged on the store path."""

    def kev_catalog(self) -> Path:
        catalog = json.loads(KEV_CATALOG.read_text(encoding="utf-8"))
        catalog["vulnerabilities"][0]["cveID"] = "CVE-2023-0286"
        catalog["vulnerabilities"][0]["dateAdded"] = "2026-09-02"
        path = self.workspace / "kev.json"
        path.write_text(json.dumps(catalog), encoding="utf-8")
        return path

    def test_kev_and_decommission_rules_hold_on_the_store_path(self) -> None:
        artifact = str(FIXTURES / "trivy-image.cdx.json")
        as_of = "2026-10-05T00:00:00Z"
        self.succeeds(["ingest", artifact, "--db", str(self.database), "--as-of", as_of])
        created = self.write_changes(
            change_entry(
                "CHG-3001",
                kind="created",
                occurredAt="2026-09-20T00:00:00Z",
                resources=[
                    {"resourceType": "image", "resourceId": "registry.example.test/api:2.1"}
                ],
            ),
            change_entry(
                "CHG-3002",
                kind="created",
                occurredAt=AFTER_THE_LAST_SCAN,
                resources=[{"resourceType": "image", "resourceId": "registry.example.test/old:1"}],
            ),
            name="cli-changes",
        )
        self.record(created)
        inventory = json.loads((FIXTURES / "inventory-cyclonedx.json").read_text(encoding="utf-8"))
        inventory["resources"].append(
            {
                "resourceType": "image",
                "resourceId": "registry.example.test/old:1",
                "machineBased": True,
                "driftLikely": True,
                "job": "nightly-sbom",
                "expectedSince": "2026-01-01T00:00:00Z",
                "decommissionedAt": "2026-09-25T00:00:00Z",
            }
        )
        inventory_path = self.workspace / "inventory.json"
        inventory_path.write_text(json.dumps(inventory), encoding="utf-8")
        catalog = self.kev_catalog()
        common = [
            "--inventory",
            str(inventory_path),
            "--class",
            "C",
            "--as-of",
            as_of,
            "--kev",
            str(catalog),
        ]

        stored_out, stored_err = self.succeeds(
            ["changes", "pending", "--db", str(self.database), *common]
        )
        stateless_out, stateless_err = self.succeeds(
            ["changes", "pending", artifact, "--changes", str(created), *common]
        )

        self.assertEqual(json.loads(stored_out)["requests"], [])
        self.assertEqual(without_request_input(stored_out), without_request_input(stateless_out))
        self.assertEqual(stored_err, stateless_err)
        self.assertIn("warning: kev_at_activation: change CHG-3001 activated image:", stored_err)


# *--- Pending ---*


class PendingPersistedTests(ChangesStoreCase):
    """`changes pending --db`: the same request from what the store recorded (ADR 0018)."""

    def setUp(self) -> None:
        super().setUp()
        self.succeeds(
            ["ingest", *TIMED_ARTIFACTS, "--db", str(self.database), "--as-of", TIMED_AS_OF]
        )

    def stored(self, *extra: str) -> list[str]:
        return [
            "changes",
            "pending",
            "--db",
            str(self.database),
            "--inventory",
            str(TIMED_INVENTORY),
            "--class",
            "C",
            "--as-of",
            TIMED_AS_OF,
            *extra,
        ]

    def test_changes_pending_db_equals_stateless_but_for_input(self) -> None:
        self.record(TIMED_CHANGES)

        code, stored_out, stored_err = run(self.stored())
        expected_code, stateless_out, stateless_err = run(pending_argv())

        self.assertEqual((code, expected_code), (0, 0), msg=stored_err)
        self.assertEqual(without_request_input(stored_out), without_request_input(stateless_out))
        self.assertEqual(stored_err, stateless_err)
        document = json.loads(stored_out)
        self.assertEqual(
            document["input"],
            store_input({sha256_of(TIMED_CHANGES): load_changes(TIMED_CHANGES).change_count}),
        )
        self.assertEqual(document["summary"]["pending"], 3)

    def test_the_request_is_written_to_output_and_the_store_is_read_only(self) -> None:
        self.record(TIMED_CHANGES)
        output = self.workspace / "request.json"
        with SQLiteEventStore(self.database) as store:
            before = len(EventRepository(store).read_all())

        code, out, err = run(self.stored("-o", str(output)))

        self.assertEqual((code, out), (0, ""), msg=err)
        self.assertEqual(json.loads(output.read_text(encoding="utf-8"))["summary"]["pending"], 3)
        with SQLiteEventStore(self.database) as store:
            self.assertEqual(len(EventRepository(store).read_all()), before)

    def test_pending_db_refuses_artifacts_and_changes(self) -> None:
        self.record(TIMED_CHANGES)
        output = self.workspace / "request.json"
        for extra, named in (
            ((TIMED_ARTIFACTS[0],), "artifacts"),
            (("--changes", str(TIMED_CHANGES)), "--changes"),
            (("--record-failed-imports",), "--record-failed-imports"),
        ):
            with self.subTest(named=named):
                code, out, err = run([*self.stored("-o", str(output)), *extra])

                self.assertEqual((code, out), (1, ""))
                self.assertEqual(
                    err,
                    f"error: invalid_option: changes pending takes either --db or {named}, "
                    "never both\n",
                )
                self.assertFalse(output.exists())

    def test_pending_db_names_every_conflicting_source_at_once(self) -> None:
        code, _, err = run(
            [
                *self.stored(),
                TIMED_ARTIFACTS[0],
                "--changes",
                str(TIMED_CHANGES),
                "--record-failed-imports",
            ]
        )

        self.assertEqual(code, 1)
        self.assertIn(
            "changes pending takes either --db or artifacts, --changes, "
            "--record-failed-imports, never both",
            err,
        )

    def test_pending_db_with_no_change_stream_is_an_empty_request(self) -> None:
        code, out, err = run(self.stored())

        self.assertEqual(code, 0, msg=err)
        document = json.loads(out)
        self.assertEqual(document["requests"], [])
        self.assertEqual(document["summary"]["pending"], 0)
        self.assertEqual(document["input"], {"source": "store", "changesSha256": []})
        with SQLiteEventStore(self.database) as store:
            self.assertEqual(store.schema_version, 1)

    def test_pending_db_needs_an_inventory(self) -> None:
        code, out, err = run(
            [
                "changes",
                "pending",
                "--db",
                str(self.database),
                "--class",
                "C",
                "--as-of",
                TIMED_AS_OF,
            ]
        )

        self.assertEqual((code, out), (1, ""))
        self.assertEqual(
            err,
            "error: invalid_option: changes pending --db needs --inventory: a change is read "
            "against the inventory or not at all\n",
        )

    def test_a_missing_store_is_refused_and_not_created(self) -> None:
        missing = self.workspace / "absent.db"

        code, out, err = run(
            [
                "changes",
                "pending",
                "--db",
                str(missing),
                "--inventory",
                str(TIMED_INVENTORY),
                "--class",
                "C",
                "--as-of",
                TIMED_AS_OF,
            ]
        )

        self.assertEqual((code, out), (1, ""))
        self.assertIn("error: store_missing:", err)
        self.assertFalse(missing.exists())

    def test_the_output_may_not_overwrite_the_store(self) -> None:
        code, _, err = run(self.stored("-o", str(self.database)))

        self.assertEqual(code, 1)
        self.assertIn("error: invalid_option:", err)

    def test_a_damaged_change_stream_is_history_invalid(self) -> None:
        self.record(TIMED_CHANGES)
        with SQLiteEventStore(self.database) as store:
            stream_id = change_stream_id("CHG-2001")
            store.append(
                stream_id,
                [
                    NewEvent(
                        event_type="change.recorded",
                        occurred_at=datetime(2026, 11, 9, tzinfo=UTC),
                        payload={"nonsense": True},
                        metadata=SMUGGLED,
                    )
                ],
                expected_version=1,
            )

        code, out, err = run(self.stored())

        self.assertEqual((code, out), (1, ""))
        self.assertIn("error: history_invalid:", err)

    def test_an_as_of_before_the_changes_lists_them_as_later(self) -> None:
        self.record(TIMED_CHANGES)

        code, out, err = run(
            [
                "changes",
                "pending",
                "--db",
                str(self.database),
                "--inventory",
                str(TIMED_INVENTORY),
                "--class",
                "C",
                "--as-of",
                "2026-01-01T00:00:00Z",
            ]
        )

        self.assertEqual(code, 0, msg=err)
        self.assertEqual(json.loads(out)["requests"], [])


# *--- Gap Awareness ---*


class GapAwarenessTests(CoverageStoreFixture):
    """ADR 0015 Decision 37 as amended: awareness follows a coverage stream, not the marker."""

    def record_a_change(self) -> None:
        record_changes(
            self.repository,
            load_changes(EXAMPLE_CHANGES),
            recorded_at=datetime(2026, 11, 9, tzinfo=UTC),
            metadata=self.metadata,
        )

    def replayed_coverage(self) -> dict[str, Any]:
        return self.replay(inventory=load_inventory(EXAMPLE_INVENTORY)).document["x-complyroll"]

    def test_coverage_awareness_follows_the_stream_not_the_marker(self) -> None:
        self.golden_store()
        self.record_a_change()
        self.assertEqual(self.store.schema_version, 5)

        extension = self.replayed_coverage()

        for window in extension["coverage"]["windows"]:
            self.assertFalse(WINDOW_KEYS & set(window))
        codes = {item["code"] for item in extension["diagnostics"]}
        for code in GAP_NOTES:
            self.assertNotIn(code, codes)

        self.record_gaps()
        self.correlate()
        extension = self.replayed_coverage()

        self.assertTrue(
            all(WINDOW_KEYS <= set(window) for window in extension["coverage"]["windows"])
        )

    def test_a_change_stream_alone_adds_no_window_key_and_no_gap_note(self) -> None:
        self.golden_store()
        baseline = compile_from_history(
            self.repository,
            kind="vdt",
            options=options(inventory=load_inventory(EXAMPLE_INVENTORY)),
        ).document["x-complyroll"]["coverage"]
        self.record_a_change()

        extension = self.replayed_coverage()

        self.assertEqual(extension["coverage"], baseline)

    def test_a_schema_4_store_reports_verifies_unchanged_and_is_never_marked(self) -> None:
        self.golden_store()
        self.record_gaps()
        self.correlate()
        self.assertEqual(self.store.schema_version, 4)
        self.store.close()
        before = self.database.read_bytes()

        code, json_out, err = run(
            [
                "report",
                "vdt",
                "--db",
                str(self.database),
                "--class",
                "C",
                "--package-uri",
                "https://example.test/cpo",
                "--as-of",
                INGESTED_AT,
                "--from",
                "2026-08-01T00:00:00Z",
                "--to",
                "2026-08-31T23:59:59Z",
                "--inventory",
                str(EXAMPLE_INVENTORY),
            ]
        )
        self.assertEqual(code, 0, msg=err)
        self.assertEqual(json_out, (GOLDEN / "vdt-coverage-gaps.json").read_text(encoding="utf-8"))
        request_code, request_out, request_err = run(
            [
                "changes",
                "pending",
                "--db",
                str(self.database),
                "--inventory",
                str(EXAMPLE_INVENTORY),
                "--class",
                "C",
                "--as-of",
                INGESTED_AT,
            ]
        )
        self.assertEqual(request_code, 0, msg=request_err)
        self.assertEqual(json.loads(request_out)["requests"], [])
        verify_code, _, verify_err = run(["store", "verify", "--db", str(self.database)])
        self.assertEqual(verify_code, 0, msg=verify_err)

        self.assertEqual(self.database.read_bytes(), before)
        with SQLiteEventStore(self.database) as store:
            self.assertEqual(store.schema_version, 4)

    def test_hand_marked_schema_4_store_with_no_stream_is_unaware(self) -> None:
        self.golden_store()
        mark_schema_4_by_hand(self.database)
        self.assertEqual(self.store.schema_version, 4)

        extension = self.replayed_coverage()

        for window in extension["coverage"]["windows"]:
            self.assertFalse(WINDOW_KEYS & set(window))
        self.assertFalse({item["code"] for item in extension["diagnostics"]} & set(GAP_NOTES))


# *--- Reader ---*


class ReadStoredChangesTests(ChangesStoreCase):
    """`read_stored_changes`: the recorded changes, rebuilt, and refused when damaged."""

    def setUp(self) -> None:
        super().setUp()
        self.store = SQLiteEventStore(self.database)
        self.addCleanup(self.store.close)
        self.repository = EventRepository(self.store)
        self.metadata = metadata()

    def recorded(self, change_set: Any, *, at: datetime = AS_OF) -> None:
        record_changes(self.repository, change_set, recorded_at=at, metadata=self.metadata)

    def smuggle(self, stream_id: str, event_type: str, payload: dict[str, Any]) -> None:
        version = self.repository.current_version(stream_id)
        self.store.append(
            stream_id,
            [
                NewEvent(
                    event_type=event_type,
                    occurred_at=datetime(2026, 11, 9, tzinfo=UTC),
                    payload=payload,
                    metadata=SMUGGLED,
                )
            ],
            expected_version=version,
        )

    def test_no_change_stream_reads_as_none(self) -> None:
        self.assertIsNone(read_stored_changes(self.repository))

    def test_every_field_is_read_back_as_the_file_read_it(self) -> None:
        change_set = load_changes(EXAMPLE_CHANGES)
        self.recorded(change_set)

        stored = read_stored_changes(self.repository)

        assert stored is not None
        self.assertEqual(stored.changes, change_set.changes)
        self.assertEqual(stored.names, (change_set.name,) * change_set.change_count)
        self.assertEqual(stored.digests, (change_set.sha256,) * change_set.change_count)

    def test_changes_read_back_in_the_order_a_change_file_sorts_them(self) -> None:
        later = parse_changes(
            json.dumps(
                change_file(change_entry("CHG-B", occurredAt="2026-09-02T00:00:00Z"), name="later")
            ).encode("utf-8")
        )
        earlier = parse_changes(
            json.dumps(
                change_file(
                    change_entry("CHG-C", occurredAt="2026-09-01T00:00:00Z"),
                    change_entry("CHG-A", occurredAt="2026-09-01T00:00:00Z"),
                    name="earlier",
                )
            ).encode("utf-8")
        )
        self.recorded(later)
        self.recorded(earlier)

        stored = read_stored_changes(self.repository)

        assert stored is not None
        self.assertEqual(
            [change.change_id for change in stored.changes], ["CHG-A", "CHG-C", "CHG-B"]
        )
        self.assertEqual(stored.names, ("earlier", "earlier", "later"))

    def test_a_read_marks_no_schema_and_writes_no_event(self) -> None:
        change_set = load_changes(EXAMPLE_CHANGES)
        self.assertEqual(self.store.schema_version, 1)

        read_stored_changes(self.repository)

        self.assertEqual(self.store.schema_version, 1)
        self.assertEqual(len(self.repository.read_all()), 0)
        self.recorded(change_set)
        self.assertEqual(self.store.schema_version, 5)
        events = len(self.repository.read_all())

        read_stored_changes(self.repository)

        self.assertEqual((self.store.schema_version, len(self.repository.read_all())), (5, events))

    def good_payload(self, change_id: str = "CHG-1") -> dict[str, Any]:
        return {
            "changeId": change_id,
            "kind": "created",
            "occurredAt": "2026-07-01T00:00:00Z",
            "source": {"tool": "terraform", "reference": "apply run 4411"},
            "resources": [{"resourceType": "host", "resourceId": "lab-win-01"}],
            "significant": True,
            "rationale": "New Windows host joined the boundary.",
            "detectBy": None,
            "job": None,
            "changesName": "example-changes",
            "changesSha256": "a" * 64,
            "recordedAt": "2026-11-09T12:00:00Z",
        }

    def test_a_second_recorded_event_on_a_stream_is_refused(self) -> None:
        self.recorded(load_changes(EXAMPLE_CHANGES))
        stream_id = change_stream_id("CHG-1001")

        self.smuggle(stream_id, CHANGE_RECORDED, self.good_payload("CHG-1001"))

        with self.assertRaisesRegex(HistoryError, "is overfull: a change stream holds one"):
            read_stored_changes(self.repository)

    def test_a_stream_naming_another_change_is_refused(self) -> None:
        self.smuggle(change_stream_id("CHG-9999"), CHANGE_RECORDED, self.good_payload("CHG-1"))

        with self.assertRaisesRegex(HistoryError, "is not 'change/.*', the stream of that change"):
            read_stored_changes(self.repository)

    def test_a_foreign_event_on_a_change_stream_is_refused(self) -> None:
        self.recorded(load_changes(EXAMPLE_CHANGES))

        self.smuggle(
            change_stream_id("CHG-1001"), "artifact.ingested", {"name": "no such artifact"}
        )

        with self.assertRaisesRegex(HistoryError, "does not belong on stream"):
            read_stored_changes(self.repository)

    def test_a_change_event_on_no_change_stream_is_refused(self) -> None:
        self.smuggle("artifact/" + "a" * 64, CHANGE_RECORDED, self.good_payload())

        with self.assertRaisesRegex(HistoryError, "does not belong on stream"):
            read_stored_changes(self.repository)

    def test_a_payload_outside_its_contract_is_refused(self) -> None:
        self.smuggle(change_stream_id("CHG-1"), CHANGE_RECORDED, {"changeId": "CHG-1"})

        with self.assertRaisesRegex(HistoryError, "is not a readable change record"):
            read_stored_changes(self.repository)

    def test_the_repository_answers_whether_a_coverage_stream_exists(self) -> None:
        self.assertFalse(self.repository.holds_coverage_stream())

        self.smuggle("artifact/" + "a" * 64, "artifact.ingested", {"name": "n"})
        self.assertFalse(self.repository.holds_coverage_stream())

        self.smuggle(coverage_stream_id("b" * 64), "coverage.recorded", {"name": "n"})
        self.assertTrue(self.repository.holds_coverage_stream())


class StoredChangeSetTests(ChangesStoreCase):
    """`StoredChangeSet` keeps its parallel fields and the file's sort order honest."""

    def change(self, change_id: str, occurred_at: datetime) -> Change:
        return Change(
            change_id=change_id,
            kind=ChangeKind.MODIFIED,
            occurred_at=occurred_at,
            source=ChangeSource(tool="git", reference="commit abc"),
            resources=load_changes(EXAMPLE_CHANGES).changes[0].resources,
            significant=True,
            rationale="A change.",
        )

    def test_digest_counts_are_sorted_by_digest_with_counts(self) -> None:
        first = self.change("CHG-1", datetime(2026, 9, 1, tzinfo=UTC))
        second = self.change("CHG-2", datetime(2026, 9, 2, tzinfo=UTC))
        third = self.change("CHG-3", datetime(2026, 9, 3, tzinfo=UTC))

        stored = StoredChangeSet(
            changes=(first, second, third),
            names=("a", "b", "c"),
            digests=("f" * 64, "0" * 64, "f" * 64),
        )

        self.assertEqual(stored.digest_counts, (("0" * 64, 1), ("f" * 64, 2)))
        self.assertEqual(stored.change_count, 3)

    def test_the_constructor_holds_each_invariant(self) -> None:
        early = self.change("CHG-1", datetime(2026, 9, 1, tzinfo=UTC))
        late = self.change("CHG-2", datetime(2026, 9, 2, tzinfo=UTC))
        cases = {
            "out of order": ((late, early), ("a", "b"), ("c" * 64, "d" * 64), "sorted"),
            "a repeated id": ((early, early), ("a", "a"), ("c" * 64, "c" * 64), "exactly one"),
            "names misaligned": ((early, late), ("a",), ("c" * 64, "d" * 64), "one name"),
            "digests misaligned": ((early, late), ("a", "b"), ("c" * 64,), "one digest"),
        }
        for label, (changes, names, digests, message) in cases.items():
            with self.subTest(case=label), self.assertRaisesRegex(ValueError, message):
                StoredChangeSet(changes=changes, names=names, digests=digests)


class HistoryCompileRefusalTests(ChangesStoreCase):
    """Call 5: a compile from history reads no change file, whatever the store holds."""

    def test_history_compile_still_refuses_a_change_file(self) -> None:
        self.populate()
        self.record()
        with SQLiteEventStore(self.database) as store:
            repository = EventRepository(store)
            for kind in KINDS:
                with (
                    self.subTest(report=kind),
                    self.assertRaisesRegex(ValueError, "a store never read this change file"),
                ):
                    compile_record_set_from_history(
                        repository,
                        options=replace(
                            options(inventory=load_inventory(EXAMPLE_INVENTORY)),
                            changes=load_changes(EXAMPLE_CHANGES),
                        ),
                    )

    def test_the_command_line_refuses_a_change_file_beside_a_store(self) -> None:
        self.populate()
        code, out, err = run(
            self.persisted(
                "vdt",
                "--inventory",
                str(EXAMPLE_INVENTORY),
                "--changes",
                str(EXAMPLE_CHANGES),
            )
        )

        self.assertEqual((code, out), (1, ""))
        self.assertEqual(
            err, "error: invalid_option: report vdt takes either --db or --changes, never both\n"
        )

    def test_a_second_input_on_the_store_path_is_refused_too(self) -> None:
        change_set = load_changes(EXAMPLE_CHANGES)
        with self.assertRaisesRegex(ValueError, "never both"):
            records_module.compile_record_set(
                artifacts=(),
                observations=(),
                ingest_diagnostics=(),
                evaluations_by_tracking_id={},
                attestation=records_module.DetectionAttestation(),
                options=replace(
                    options(inventory=load_inventory(EXAMPLE_INVENTORY)), changes=change_set
                ),
                stored_changes=StoredChangeSet(changes=(), names=(), digests=()),
            )
