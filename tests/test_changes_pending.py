# ******************************************************************************
# *Title: Change Pending Tests*
# *Author: Kyle Versluis*
# *Description: The detection request document and the changes pending command.*
# ******************************************************************************
"""Tests for `changes pending`: the request document, its parity and refusals (ADR 0018)."""

# *--- Imports ---*

from __future__ import annotations

import dataclasses
import io
import json
import shutil
import tempfile
import unittest
from collections import Counter
from collections.abc import Sequence
from contextlib import redirect_stderr
from datetime import UTC, datetime, timedelta, timezone
from pathlib import Path
from typing import Any
from unittest import mock

from test_changes import observation
from test_changes_report import change_entry, change_file
from test_cli import (
    CHANGES_ARGUMENTS,
    EXAMPLE_CHANGES,
    EXAMPLE_INVENTORY,
    FAILED_ARTIFACTS,
    FIXTURES,
    KEV_CATALOG,
    REPORT_ARGUMENTS,
    TIMED_ARTIFACTS,
    TIMED_AS_OF,
    TIMED_CHANGES,
    TIMED_INVENTORY,
    help_text,
    run,
    stripped_policy,
    timed_changes_argv,
)

from complyroll.cli import main
from complyroll.events import EventRepository
from complyroll.policy import CertificationClass, RuleForce
from complyroll.reports import (
    ReportCompileError,
    ReportDiagnostic,
    ReportOptions,
    compile_record_set_from_history,
    load_changes,
    load_inventory,
    load_kev_catalog,
)
from complyroll.reports import records as records_module
from complyroll.reports.changes import (
    DETECTION_REQUEST_SCHEMA,
    DETECTION_REQUEST_SCHEMA_VERSION,
    detection_request,
)
from complyroll.store import SQLiteEventStore

# *--- Fixtures ---*

WAITING = frozenset({"lapsed", "undetermined", "pending"})
HELPERS = "https://github.com/example/webapp/src/ui/helpers.js"
LEGACY = "https://github.com/example/webapp/src/ui/legacy.js"
RENDER = "src/ui/render.js"
RENDER_ALIAS = "https://github.com/example/webapp/src/ui/render.js"
IMAGE = "registry.example.test/synthetic/example-service:1.4.0"
#: After the last scan the timed artifacts carry, so nothing has examined a resource since.
AFTER_THE_LAST_SCAN = "2026-09-02T09:00:00Z"
EXAMPLE_ARTIFACTS = REPORT_ARGUMENTS[2:5]
EXAMPLE_AS_OF = "2026-08-21T12:00:00Z"
COMPILE_OPTIONS = {
    "certification_class": CertificationClass.C,
    "package_uri": "https://example.test/cpo",
    "as_of": datetime(2026, 9, 3, 12, tzinfo=UTC),
}


def pending_argv(
    *extra: str,
    artifacts: Sequence[str] = TIMED_ARTIFACTS,
    changes: Path = TIMED_CHANGES,
    inventory: Path = TIMED_INVENTORY,
    as_of: str = TIMED_AS_OF,
) -> list[str]:
    return [
        "changes",
        "pending",
        *artifacts,
        "--changes",
        str(changes),
        "--inventory",
        str(inventory),
        "--class",
        "C",
        "--as-of",
        as_of,
        *extra,
    ]


def example_argv(*extra: str) -> list[str]:
    return pending_argv(
        *extra,
        artifacts=EXAMPLE_ARTIFACTS,
        changes=EXAMPLE_CHANGES,
        inventory=EXAMPLE_INVENTORY,
        as_of=EXAMPLE_AS_OF,
    )


def rows_of(document: dict[str, Any]) -> list[tuple[str, str, str, str]]:
    """Return one (change, type, id, status) per requested resource, in document order."""
    return [
        (item["changeId"], row["resourceType"], row["resourceId"], row["status"])
        for item in document["requests"]
        for row in item["resources"]
    ]


# *--- Tests ---*


class PendingBase(unittest.TestCase):
    """A workspace, and the small writers every command test shares."""

    def setUp(self) -> None:
        directory = tempfile.TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        self.workspace = Path(directory.name)

    def write_changes(self, *changes: dict[str, Any], name: str = "changes.json") -> Path:
        path = self.workspace / name
        path.write_text(json.dumps(change_file(*changes)), encoding="utf-8")
        return path

    def request(self, argv: Sequence[str]) -> dict[str, Any]:
        code, out, err = run(argv)
        self.assertEqual(code, 0, msg=err)
        return json.loads(out)


class DetectionRequestDocumentTests(PendingBase):
    """The document: only the resources still waiting, read off the block's own rows."""

    def test_schema_constants_are_the_contract(self) -> None:
        self.assertEqual(DETECTION_REQUEST_SCHEMA, "complyroll.detection-request")
        self.assertEqual(DETECTION_REQUEST_SCHEMA_VERSION, 1)

    def test_document_carries_the_contracted_keys(self) -> None:
        document = self.request(pending_argv())

        self.assertEqual(
            set(document),
            {
                "schema",
                "schemaVersion",
                "rule",
                "force",
                "provenance",
                "asOf",
                "input",
                "inventorySha256",
                "summary",
                "requests",
            },
        )
        self.assertEqual(document["schema"], "complyroll.detection-request")
        self.assertEqual(document["schemaVersion"], 1)
        self.assertEqual(document["rule"], "VDR-CSO-DAC")
        self.assertEqual(document["force"], "SHOULD")
        self.assertEqual(document["asOf"], TIMED_AS_OF)

    def test_rule_provenance_equals_the_blocks(self) -> None:
        document = self.request(pending_argv())
        report = self.request(timed_changes_argv())

        self.assertEqual(document["provenance"], report["x-complyroll"]["changes"]["provenance"])
        self.assertEqual(document["provenance"], report["x-complyroll"]["rulesSource"])

    def test_request_lists_only_waiting_rows(self) -> None:
        document = self.request(pending_argv())

        self.assertEqual(
            rows_of(document),
            [
                ("CHG-2001", "image", IMAGE, "lapsed"),
                ("CHG-2005", "file", LEGACY, "undetermined"),
                ("CHG-2006", "file", HELPERS, "pending"),
            ],
        )

    def test_summary_counts_every_waiting_row_with_the_split(self) -> None:
        document = self.request(pending_argv())

        self.assertEqual(
            document["summary"],
            {"pending": 3, "byStatus": {"lapsed": 1, "undetermined": 1, "pending": 1}},
        )

    def test_summary_split_is_each_status_alone(self) -> None:
        changes = self.write_changes(
            change_entry("CHG-1", occurredAt=AFTER_THE_LAST_SCAN),
            change_entry(
                "CHG-2",
                occurredAt=AFTER_THE_LAST_SCAN,
                resources=[{"resourceType": "file", "resourceId": LEGACY}],
            ),
            change_entry(
                "CHG-3",
                occurredAt="2026-09-01T00:40:00Z",
                resources=[{"resourceType": "file", "resourceId": LEGACY}],
            ),
        )

        document = self.request(pending_argv(changes=changes))

        self.assertEqual(
            document["summary"],
            {"pending": 3, "byStatus": {"lapsed": 0, "undetermined": 1, "pending": 2}},
        )

    def test_request_row_carries_the_change_and_the_resource(self) -> None:
        document = self.request(pending_argv())

        self.assertEqual(
            document["requests"][0],
            {
                "changeId": "CHG-2001",
                "kind": "modified",
                "occurredAt": "2026-08-10T00:00:00Z",
                "detectBy": "2026-08-20T00:00:00Z",
                "job": "nightly-image-scan",
                "source": {"tool": "registry", "reference": "push 8842"},
                "resources": [
                    {
                        "resourceType": "image",
                        "resourceId": IMAGE,
                        "aliases": [],
                        "sampleGroup": None,
                        "status": "lapsed",
                    }
                ],
            },
        )

    def test_change_without_window_or_job_prints_null(self) -> None:
        changes = self.write_changes(change_entry("CHG-1", occurredAt=AFTER_THE_LAST_SCAN))

        request = self.request(pending_argv(changes=changes))["requests"][0]

        self.assertIsNone(request["detectBy"])
        self.assertIsNone(request["job"])

    def test_created_change_keeps_its_kind(self) -> None:
        changes = self.write_changes(
            change_entry("CHG-1", kind="created", occurredAt=AFTER_THE_LAST_SCAN)
        )

        self.assertEqual(
            self.request(pending_argv(changes=changes))["requests"][0]["kind"], "created"
        )

    def test_entry_row_names_aliases_and_a_group_row_names_its_group(self) -> None:
        changes = self.write_changes(
            change_entry(
                "CHG-1",
                occurredAt=AFTER_THE_LAST_SCAN,
                resources=[
                    {"resourceType": "file", "resourceId": RENDER_ALIAS},
                    {"resourceType": "logical", "resourceId": "sample-group/webapp-ui"},
                ],
            )
        )

        request = self.request(pending_argv(changes=changes))["requests"][0]

        self.assertEqual(
            request["resources"],
            [
                {
                    "resourceType": "file",
                    "resourceId": RENDER,
                    "aliases": [{"resourceType": "file", "resourceId": RENDER_ALIAS}],
                    "sampleGroup": "webapp-ui",
                    "status": "pending",
                },
                {
                    "resourceType": "logical",
                    "resourceId": "sample-group/webapp-ui",
                    "aliases": [],
                    "sampleGroup": "webapp-ui",
                    "status": "pending",
                },
            ],
        )

    def test_a_change_with_one_detected_resource_lists_only_the_other(self) -> None:
        changes = self.write_changes(
            change_entry(
                "CHG-1",
                occurredAt="2026-09-01T00:30:00Z",
                resources=[
                    {"resourceType": "file", "resourceId": HELPERS},
                    {"resourceType": "file", "resourceId": LEGACY},
                ],
            )
        )

        document = self.request(pending_argv(changes=changes))

        self.assertEqual(rows_of(document), [("CHG-1", "file", LEGACY, "undetermined")])

    def test_a_change_with_no_waiting_resource_has_no_request(self) -> None:
        changes = self.write_changes(
            change_entry("CHG-1", occurredAt="2026-09-01T00:30:00Z"),
            change_entry("CHG-2", occurredAt=AFTER_THE_LAST_SCAN),
        )

        document = self.request(pending_argv(changes=changes))

        self.assertEqual([item["changeId"] for item in document["requests"]], ["CHG-2"])

    def test_parity_every_waiting_row_has_one_entry_and_no_other_row_has_one(self) -> None:
        runs = (
            ("timed", timed_changes_argv(), pending_argv()),
            ("example", list(CHANGES_ARGUMENTS), example_argv()),
        )
        seen: set[str] = set()
        for name, report_argv, request_argv in runs:
            with self.subTest(run=name):
                block = self.request(report_argv)["x-complyroll"]["changes"]
                document = self.request(request_argv)

                waiting = [row for row in block["obligations"] if row["status"] in WAITING]
                self.assertTrue(waiting)
                self.assertEqual(
                    Counter(rows_of(document)),
                    Counter(
                        (row["changeId"], row["resourceType"], row["resourceId"], row["status"])
                        for row in waiting
                    ),
                )
                self.assertEqual(document["summary"]["pending"], len(waiting))
                seen.update(row["status"] for row in block["obligations"])
        # The two runs together must hold every status, or this parity proves less than it says.
        self.assertEqual(
            seen,
            {"unregistered", "retired", "logged", "detected", "lapsed", "undetermined", "pending"},
        )

    def test_request_input_equals_block_input(self) -> None:
        for name, report_argv, request_argv in (
            ("timed", timed_changes_argv(), pending_argv()),
            ("example", list(CHANGES_ARGUMENTS), example_argv()),
        ):
            with self.subTest(run=name):
                block = self.request(report_argv)["x-complyroll"]["changes"]
                document = self.request(request_argv)

                self.assertEqual(document["input"], block["input"])
                self.assertEqual(document["inventorySha256"], block["inventorySha256"])

    def test_force_is_the_projections_not_a_literal(self) -> None:
        options = ReportOptions(
            changes=load_changes(TIMED_CHANGES),
            inventory=load_inventory(TIMED_INVENTORY),
            **COMPILE_OPTIONS,
        )
        projection, _ = records_module.derive_changes_from_artifacts(
            [Path(item) for item in TIMED_ARTIFACTS], options=options
        )

        document = detection_request(dataclasses.replace(projection, force=RuleForce.MUST))

        self.assertEqual(document["force"], "MUST")

    def test_detection_request_is_a_pure_reading_of_the_projection(self) -> None:
        options = ReportOptions(
            changes=load_changes(TIMED_CHANGES),
            inventory=load_inventory(TIMED_INVENTORY),
            **COMPILE_OPTIONS,
        )
        projection, _ = records_module.derive_changes_from_artifacts(
            [Path(item) for item in TIMED_ARTIFACTS], options=options
        )

        self.assertEqual(detection_request(projection), detection_request(projection))
        self.assertEqual(len(rows_of(detection_request(projection))), len(projection.waiting))


class ChangesPendingCommandTests(PendingBase):
    """The command: same readers, refusals and publication as `report`, one document out."""

    def test_exit_zero_when_nothing_waits(self) -> None:
        cases = (
            ("logged", change_entry("CHG-1", significant=False)),
            ("detected", change_entry("CHG-1", occurredAt="2026-09-01T00:30:00Z")),
        )
        for name, entry in cases:
            with self.subTest(status=name):
                changes = self.write_changes(entry, name=f"{name}.json")

                code, out, err = run(pending_argv(changes=changes))

                self.assertEqual(code, 0, msg=err)
                document = json.loads(out)
                self.assertEqual(document["requests"], [])
                self.assertEqual(
                    document["summary"],
                    {"pending": 0, "byStatus": {"lapsed": 0, "undetermined": 0, "pending": 0}},
                )

    def test_exit_zero_when_something_waits(self) -> None:
        code, out, err = run(pending_argv())

        self.assertEqual(code, 0, msg=err)
        self.assertEqual(json.loads(out)["summary"]["pending"], 3)

    def test_as_of_before_every_change_is_an_empty_request(self) -> None:
        code, out, err = run(pending_argv(as_of="2026-08-05T12:00:00Z"))

        self.assertEqual(code, 0, msg=err)
        document = json.loads(out)
        self.assertEqual(document["requests"], [])
        self.assertEqual(document["summary"]["pending"], 0)
        self.assertEqual(document["input"]["changeCount"], 6)

    def test_writes_stdout_without_output(self) -> None:
        json_path = self.workspace / "request.json"

        code, out, err = run(pending_argv())
        written_code, written_out, written_err = run(pending_argv("-o", str(json_path)))

        self.assertEqual((code, written_code), (0, 0), msg=err + written_err)
        self.assertEqual(written_out, "")
        self.assertEqual(json_path.read_text(encoding="utf-8"), out)

    def test_long_output_flag_is_the_same_destination(self) -> None:
        json_path = self.workspace / "request.json"

        code, out, err = run(pending_argv("--output", str(json_path)))

        self.assertEqual(code, 0, msg=err)
        self.assertEqual(out, "")
        self.assertTrue(json_path.is_file())

    def test_output_is_the_reports_canonical_json(self) -> None:
        _, out, _ = run(pending_argv())

        self.assertEqual(
            out, json.dumps(json.loads(out), indent=2, sort_keys=True, ensure_ascii=False) + "\n"
        )

    def test_package_uri_placeholder_reaches_no_output(self) -> None:
        code, out, err = run(pending_argv())

        self.assertEqual(code, 0, msg=err)
        self.assertNotIn("complyroll.invalid", out)
        self.assertNotIn("complyroll.invalid", err)

    def test_change_warnings_reach_standard_error_and_not_the_document(self) -> None:
        code, out, err = run(pending_argv())

        self.assertEqual(code, 0, msg=err)
        self.assertIn("warning: change_precedes_expected_since", err)
        self.assertNotIn("change_precedes_expected_since", out)

    def test_calendar_timezone_is_read(self) -> None:
        code, _, err = run(pending_argv("--calendar-tz", "Not/AZone"))

        self.assertEqual(code, 1)
        self.assertIn("error: invalid_option", err)

    def test_class_and_calendar_reach_the_policy(self) -> None:
        cases = (
            ((), "C", "UTC"),
            (("--calendar-tz", "America/Phoenix"), "B", "America/Phoenix"),
        )
        for extra, certification_class, calendar in cases:
            with (
                self.subTest(calendar=calendar),
                mock.patch.object(
                    records_module, "select_policy", wraps=records_module.select_policy
                ) as selected,
            ):
                argv = pending_argv(*extra)
                argv[argv.index("--class") + 1] = certification_class

                code, out, err = run(argv)

                self.assertEqual(code, 0, msg=err)
                self.assertEqual(json.loads(out)["force"], "SHOULD")
                profile = selected.call_args.args[1]
                self.assertEqual(profile.certification_class.value, certification_class)
                self.assertEqual(profile.calendar_timezone, calendar)

    def test_class_and_as_of_are_required(self) -> None:
        for flag in ("--class", "--as-of"):
            argv = pending_argv()
            at = argv.index(flag)
            del argv[at : at + 2]
            with self.subTest(flag=flag), redirect_stderr(io.StringIO()):
                with self.assertRaises(SystemExit) as caught:
                    main(argv)

                self.assertEqual(caught.exception.code, 2)

    def test_non_ascii_identity_text_is_written_as_is(self) -> None:
        changes = self.write_changes(
            change_entry(
                "CHG-1",
                occurredAt=AFTER_THE_LAST_SCAN,
                source={"tool": "git", "reference": "commit caf\u00e9"},
            )
        )

        code, out, err = run(pending_argv(changes=changes))

        self.assertEqual(code, 0, msg=err)
        self.assertIn("commit caf\u00e9", out)

    def test_output_symlink_is_refused_before_anything_is_read(self) -> None:
        target = self.workspace / "target.json"
        target.write_text("keep\n", encoding="utf-8")
        link = self.workspace / "link.json"
        link.symlink_to(target)

        code, out, err = run(pending_argv("-o", str(link), changes=self.workspace / "missing.json"))

        self.assertEqual(code, 1)
        self.assertEqual(out, "")
        self.assertIn("error: output_is_symlink", err)
        self.assertTrue(link.is_symlink())
        self.assertEqual(target.read_text(encoding="utf-8"), "keep\n")

    def test_output_overwriting_an_input_is_refused(self) -> None:
        artifact = self.workspace / "codeql-repo.sarif"
        changes = self.workspace / "changes.json"
        inventory = self.workspace / "inventory.json"
        kev = self.workspace / "kev.json"
        shutil.copyfile(TIMED_ARTIFACTS[0], artifact)
        shutil.copyfile(TIMED_CHANGES, changes)
        shutil.copyfile(TIMED_INVENTORY, inventory)
        shutil.copyfile(KEV_CATALOG, kev)
        argv = pending_argv(
            "--kev", str(kev), artifacts=[str(artifact)], changes=changes, inventory=inventory
        )
        for victim in (artifact, changes, inventory, kev):
            with self.subTest(input=victim.name):
                before = victim.read_bytes()

                code, out, err = run([*argv, "-o", str(victim)])

                self.assertEqual(code, 1)
                self.assertEqual(out, "")
                self.assertIn("error: invalid_option: refusing to overwrite the input file", err)
                self.assertEqual(victim.read_bytes(), before)

    def test_failed_import_without_flag_exits_1_and_writes_nothing(self) -> None:
        json_path = self.workspace / "request.json"

        code, out, err = run(
            pending_argv("-o", str(json_path), artifacts=[*TIMED_ARTIFACTS, FAILED_ARTIFACTS[2]])
        )

        self.assertEqual(code, 1)
        self.assertEqual(out, "")
        self.assertIn("error:", err)
        self.assertFalse(json_path.exists())

    def test_record_failed_imports_notes_and_continues(self) -> None:
        json_path = self.workspace / "request.json"
        plain = self.request(pending_argv())

        code, out, err = run(
            pending_argv(
                "--record-failed-imports",
                "-o",
                str(json_path),
                artifacts=[*TIMED_ARTIFACTS, FAILED_ARTIFACTS[2]],
            )
        )

        # The document holds no system record, so exit 3 has nothing to say about it.
        self.assertEqual(code, 0, msg=err)
        self.assertEqual(out, "")
        self.assertIn("warning: detection_failure_recorded", err)
        self.assertNotIn("error:", err)
        self.assertEqual(json.loads(json_path.read_text(encoding="utf-8")), plain)

    def test_second_inventory_or_changes_is_invalid_option(self) -> None:
        # Neither second file exists: the refusal comes before anything is read.
        missing = str(self.workspace / "missing.json")
        cases = (
            ("--inventory", "changes pending takes one --inventory file, not 2"),
            ("--changes", "changes pending takes one --changes file, not 2"),
        )
        for flag, message in cases:
            with self.subTest(flag=flag):
                code, out, err = run([*pending_argv(), flag, missing])

                self.assertEqual(code, 1)
                self.assertEqual(out, "")
                self.assertEqual(err, f"error: invalid_option: {message}\n")

    def test_second_kev_catalog_is_invalid_option(self) -> None:
        missing = str(self.workspace / "missing.json")

        code, out, err = run(pending_argv("--kev", missing, "--kev", missing))

        self.assertEqual(code, 1)
        self.assertEqual(out, "")
        self.assertEqual(
            err, "error: invalid_option: changes pending takes one --kev catalog, not 2\n"
        )

    def test_changes_without_inventory_is_invalid_option(self) -> None:
        argv = pending_argv(changes=self.workspace / "missing.json")
        at = argv.index("--inventory")
        del argv[at : at + 2]

        code, out, err = run(argv)

        self.assertEqual(code, 1)
        self.assertEqual(out, "")
        self.assertEqual(
            err,
            "error: invalid_option: changes pending --changes needs --inventory: a change is "
            "read against the inventory or not at all\n",
        )

    def test_neither_input_names_the_change_file_first(self) -> None:
        argv = pending_argv()
        for flag in ("--changes", "--inventory"):
            at = argv.index(flag)
            del argv[at : at + 2]

        code, out, err = run(argv)

        self.assertEqual(code, 1)
        self.assertEqual(out, "")
        self.assertIn("error: invalid_option: changes pending needs --changes:", err)

    def test_inventory_without_changes_is_invalid_option(self) -> None:
        argv = pending_argv()
        at = argv.index("--changes")
        del argv[at : at + 2]

        code, out, err = run(argv)

        self.assertEqual(code, 1)
        self.assertEqual(out, "")
        self.assertEqual(
            err,
            "error: invalid_option: changes pending needs --changes: a request is read from "
            "a change file or not at all\n",
        )

    def test_refused_change_file_is_invalid_input_and_writes_nothing(self) -> None:
        bad = self.workspace / "bad-changes.json"
        bad.write_text('{"schema": "complyroll.inventory"}', encoding="utf-8")
        json_path = self.workspace / "request.json"

        code, out, err = run(pending_argv("-o", str(json_path), changes=bad))

        self.assertEqual(code, 1)
        self.assertEqual(out, "")
        self.assertIn("error: invalid_input", err)
        self.assertFalse(json_path.exists())

    def test_refused_inventory_is_invalid_input_and_writes_nothing(self) -> None:
        bad = self.workspace / "bad-inventory.json"
        bad.write_text("{not json", encoding="utf-8")
        json_path = self.workspace / "request.json"

        code, out, err = run(pending_argv("-o", str(json_path), inventory=bad))

        self.assertEqual(code, 1)
        self.assertEqual(out, "")
        self.assertIn("error: invalid_input", err)
        self.assertFalse(json_path.exists())

    def test_unreadable_as_of_is_invalid_input(self) -> None:
        code, out, err = run(pending_argv(as_of="yesterday"))

        self.assertEqual(code, 1)
        self.assertEqual(out, "")
        self.assertIn("error: invalid_input", err)

    def test_kev_catalog_after_as_of_is_refused_and_writes_nothing(self) -> None:
        json_path = self.workspace / "request.json"

        code, out, err = run(pending_argv("--kev", str(KEV_CATALOG), "-o", str(json_path)))

        self.assertEqual(code, 1)
        self.assertEqual(out, "")
        self.assertIn("error: kev_catalog_after_as_of", err)
        self.assertFalse(json_path.exists())

    def test_kev_catalog_reaches_the_activation_warning(self) -> None:
        catalog = json.loads(KEV_CATALOG.read_text(encoding="utf-8"))
        catalog["vulnerabilities"][0]["cveID"] = "CVE-2023-0286"
        catalog["vulnerabilities"][0]["dateAdded"] = "2026-09-02"
        kev_path = self.workspace / "kev.json"
        kev_path.write_text(json.dumps(catalog), encoding="utf-8")
        changes = self.write_changes(
            change_entry(
                "CHG-3001",
                kind="created",
                occurredAt="2026-09-20T00:00:00Z",
                resources=[
                    {"resourceType": "image", "resourceId": "registry.example.test/api:2.1"}
                ],
            )
        )

        code, out, err = run(
            pending_argv(
                "--kev",
                str(kev_path),
                artifacts=[str(FIXTURES / "trivy-image.cdx.json")],
                changes=changes,
                inventory=FIXTURES / "inventory-cyclonedx.json",
                as_of="2026-10-05T00:00:00Z",
            )
        )

        self.assertEqual(code, 0, msg=err)
        self.assertEqual(json.loads(out)["requests"], [])
        self.assertIn("warning: kev_at_activation: change CHG-3001 activated image:", err)

    def test_policy_without_the_rule_refuses_the_run(self) -> None:
        with mock.patch.object(records_module, "select_policy", stripped_policy("VDR-CSO-DAC")):
            code, out, err = run(pending_argv())

        self.assertEqual(code, 1)
        self.assertEqual(out, "")
        self.assertIn("error: change_rule_unavailable", err)

    def test_reordered_inputs_give_identical_bytes(self) -> None:
        reversed_artifacts = pending_argv(artifacts=tuple(reversed(TIMED_ARTIFACTS)))
        expected_code, expected_out, expected_err = run(pending_argv())
        code, out, err = run(reversed_artifacts)
        self.assertEqual((code, expected_code), (0, 0), msg=err)
        self.assertEqual(out, expected_out)
        self.assertEqual(err, expected_err)

        document = json.loads(TIMED_CHANGES.read_text(encoding="utf-8"))
        document["changes"].reverse()
        for change in document["changes"]:
            change["resources"].reverse()
        reordered = self.workspace / "reordered.json"
        reordered.write_text(json.dumps(document), encoding="utf-8")

        code, out, err = run(
            pending_argv(artifacts=tuple(reversed(TIMED_ARTIFACTS)), changes=reordered)
        )

        self.assertEqual(code, 0, msg=err)
        # The file's digest and size name its bytes, which are the one thing that did move.
        moved = json.loads(out)
        settled = json.loads(expected_out)
        self.assertNotEqual(moved["input"]["sha256"], settled["input"]["sha256"])
        moved["input"].update(sha256="same", sizeBytes=0)
        settled["input"].update(sha256="same", sizeBytes=0)
        self.assertEqual(moved, settled)
        self.assertEqual(err, expected_err)

    def test_no_evaluations_or_detected_at_flag_exists(self) -> None:
        text = help_text(["changes", "pending"])
        self.assertNotIn("--evaluations", text)
        self.assertNotIn("--detected-at", text)
        self.assertNotIn("--package-uri", text)
        for flag, value in (
            ("--evaluations", str(self.workspace / "evaluations.json")),
            ("--detected-at", "2026-09-01T00:00:00Z"),
            ("--package-uri", "https://example.test/cpo"),
        ):
            with self.subTest(flag=flag), redirect_stderr(io.StringIO()):
                with self.assertRaises(SystemExit) as caught:
                    main([*pending_argv(), flag, value])

                self.assertEqual(caught.exception.code, 2)

    def test_help_names_the_flags_and_the_exit(self) -> None:
        text = " ".join(help_text(["changes", "pending"]).split())

        for flag in (
            "--changes FILE",
            "--inventory FILE",
            "--class",
            "--as-of RFC3339",
            "--calendar-tz NAME",
            "--kev FILE",
            "--record-failed-imports",
            "--output",
        ):
            with self.subTest(flag=flag):
                self.assertIn(flag, text)
        self.assertIn("exits 0 whether or not anything is waiting", text)

    def test_the_group_is_listed_in_top_level_help(self) -> None:
        self.assertIn("changes", help_text([]))

    def test_at_least_one_artifact_is_required(self) -> None:
        argv = [item for item in pending_argv() if item not in TIMED_ARTIFACTS]

        with redirect_stderr(io.StringIO()), self.assertRaises(SystemExit) as caught:
            main(argv)

        self.assertEqual(caught.exception.code, 2)


class DeriveFromArtifactsTests(PendingBase):
    """`derive_changes_from_artifacts`: the same refusals in the same order as the report."""

    def options(self, **fields: Any) -> ReportOptions:
        return ReportOptions(
            changes=load_changes(TIMED_CHANGES),
            inventory=load_inventory(TIMED_INVENTORY),
            **{**COMPILE_OPTIONS, **fields},
        )

    def test_options_must_be_report_options(self) -> None:
        with self.assertRaisesRegex(TypeError, "options must be a ReportOptions"):
            records_module.derive_changes_from_artifacts([], options="options")  # type: ignore[arg-type]

    def test_options_without_a_change_set_are_refused(self) -> None:
        options = ReportOptions(inventory=load_inventory(TIMED_INVENTORY), **COMPILE_OPTIONS)

        with self.assertRaisesRegex(ValueError, "needs a change set"):
            records_module.derive_changes_from_artifacts(
                [Path(item) for item in TIMED_ARTIFACTS], options=options
            )

    def test_a_clock_coverage_refuses_is_named_before_the_changes_are_read(self) -> None:
        unusable = observation(at=datetime(1, 1, 1, tzinfo=timezone(timedelta(hours=1))))

        with (
            mock.patch.object(records_module, "_ingest_all", return_value=([], [unusable])),
            self.assertRaises(ReportCompileError) as caught,
        ):
            records_module.derive_changes_from_artifacts([], options=self.options())

        self.assertEqual(
            {item.code for item in caught.exception.diagnostics}, {"clock_out_of_range"}
        )

    def test_a_late_kev_catalog_is_refused_before_the_clock(self) -> None:
        unusable = observation(at=datetime(1, 1, 1, tzinfo=timezone(timedelta(hours=1))))
        options = self.options(kev_catalog=load_kev_catalog(KEV_CATALOG))

        with (
            mock.patch.object(records_module, "_ingest_all", return_value=([], [unusable])),
            self.assertRaises(ReportCompileError) as caught,
        ):
            records_module.derive_changes_from_artifacts([], options=options)

        self.assertEqual(
            {item.code for item in caught.exception.diagnostics}, {"kev_catalog_after_as_of"}
        )

    def test_diagnostics_are_the_ingest_notes_in_order_then_the_change_warnings(self) -> None:
        notes = [
            ReportDiagnostic(level=records_module.DiagnosticLevel.WARNING, code="b", message="b"),
            ReportDiagnostic(level=records_module.DiagnosticLevel.WARNING, code="a", message="a"),
        ]

        def ingest(_paths: Any, _options: Any, diagnostics: list[Any], **_: Any) -> Any:
            diagnostics.extend(notes)
            return [], []

        with mock.patch.object(records_module, "_ingest_all", side_effect=ingest):
            projection, diagnostics = records_module.derive_changes_from_artifacts(
                [], options=self.options()
            )

        self.assertEqual([item.code for item in diagnostics[:2]], ["a", "b"])
        self.assertEqual(diagnostics[2:], projection.warnings)
        self.assertTrue(projection.warnings)

    def test_the_failed_import_flag_reaches_the_ingest(self) -> None:
        for flag in (True, False):
            with (
                self.subTest(flag=flag),
                mock.patch.object(records_module, "_ingest_all", return_value=([], [])) as ingest,
            ):
                records_module.derive_changes_from_artifacts(
                    [], options=self.options(), record_failed_imports=flag
                )

                self.assertIs(ingest.call_args.kwargs["record_failed_imports"], flag)


class CompileFromHistoryTests(unittest.TestCase):
    """A compile from history has no change file to name, so it refuses one."""

    def test_compile_from_history_refuses_changes(self) -> None:
        options = ReportOptions(
            changes=load_changes(TIMED_CHANGES),
            inventory=load_inventory(TIMED_INVENTORY),
            **COMPILE_OPTIONS,
        )
        with tempfile.TemporaryDirectory() as directory:
            store = SQLiteEventStore(Path(directory) / "events.db")
            self.addCleanup(store.close)

            with self.assertRaises(ValueError) as caught:
                compile_record_set_from_history(EventRepository(store), options=options)

        message = str(caught.exception)
        self.assertIn("changes applies only to a compile from artifacts", message)
        self.assertNotRegex(message, r"PR\s*\d")
