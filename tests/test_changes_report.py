# ******************************************************************************
# *Title: Change Report Tests*
# *Author: Kyle Versluis*
# *Description: The changes block, its Markdown twin and the report flag.*
# ******************************************************************************
"""Tests for `--changes` on the three reports: the block, the twin, the refusals (ADR 0018)."""

# *--- Imports ---*

from __future__ import annotations

import copy
import json
import re
import tempfile
import unittest
from collections.abc import Sequence
from datetime import UTC, datetime, timedelta, timezone
from pathlib import Path
from typing import Any
from unittest import mock

from test_changes import observation
from test_cli import (
    AVI_ARGUMENTS,
    CHANGES_ARGUMENTS,
    COVERAGE_ARGUMENTS,
    EXAMPLE_CHANGES,
    EXAMPLE_INVENTORY,
    FIXTURES,
    GOLDEN,
    HISTORICAL_ARGUMENTS,
    KEV_ARGUMENTS,
    KEV_EVALUATIONS,
    REPORT_ARGUMENTS,
    TIMED_CHANGES,
    TIMED_INVENTORY,
    help_text,
    run,
    stripped_policy,
    timed_argv,
    timed_changes_argv,
)

from complyroll import cli as cli_module
from complyroll.policy import CertificationClass
from complyroll.reports import (
    REPORT_DIAGNOSTIC_CODES,
    DetectionAttestation,
    ReportCompileError,
    ReportOptions,
    load_changes,
    load_inventory,
)
from complyroll.reports import records as records_module
from complyroll.reports.changes import ChangeProjection, ObligationStatus

# *--- Fixtures ---*

HELPERS = "https://github.com/example/webapp/src/ui/helpers.js"
KINDS = ("vdt", "avi", "historical")
RUNS = (("vdt", REPORT_ARGUMENTS), ("avi", AVI_ARGUMENTS), ("historical", HISTORICAL_ARGUMENTS))
#: Each report's run with the example inventory, and the flag still to come.
INVENTORIED = tuple((kind, (*argv, "--inventory", str(EXAMPLE_INVENTORY))) for kind, argv in RUNS)
#: A pipe, a backtick, a tab, a newline, markup and a backslash: every way into a table cell.
HOSTILE = "pipe | tick ` tab\there\nsecond <b>line</b> back\\slash"
COMPILE_OPTIONS = {
    "certification_class": CertificationClass.C,
    "package_uri": "https://example.test/cpo",
    "as_of": datetime(2026, 9, 3, 12, tzinfo=UTC),
}


def block_of(out: str) -> dict[str, Any]:
    return json.loads(out)["x-complyroll"]["changes"]


def extension_of(path: Path) -> dict[str, Any]:
    return json.loads(path.read_text(encoding="utf-8"))["x-complyroll"]


def with_as_of(argv: Sequence[str], instant: str) -> list[str]:
    values = list(argv)
    values[values.index("--as-of") + 1] = instant
    return values


def changes_section(markdown: str) -> str:
    """Return the Changes section of a Markdown twin, up to the section after it."""
    start = markdown.index("\n## Changes\n")
    return markdown[start : markdown.index("\n## Diagnostics\n", start)]


def unescaped_pipes(line: str) -> int:
    """Count the pipes that split a table row; a pipe after an odd run of backslashes does not."""
    return len(re.findall(r"(?<!\\)(?:\\\\)*\|", line))


def subsection(section: str, heading: str) -> list[str]:
    """Return the table lines under one `###` heading of a section."""
    lines = section.split("\n")
    start = lines.index(f"### {heading}") + 1
    rows = []
    for line in lines[start:]:
        if line.startswith("### "):
            break
        if line.startswith("|"):
            rows.append(line)
    return rows


def change_entry(change_id: str = "CHG-1", **fields: Any) -> dict[str, Any]:
    value: dict[str, Any] = {
        "changeId": change_id,
        "kind": "modified",
        "occurredAt": "2026-09-01T00:30:00Z",
        "source": {"tool": "git", "reference": "commit 0123abc"},
        "resources": [{"resourceType": "file", "resourceId": HELPERS}],
        "significant": True,
        "rationale": "A change.",
    }
    value.update(fields)
    return value


def change_file(*changes: dict[str, Any], name: str = "cli-changes") -> dict[str, Any]:
    return {
        "schema": "complyroll.changes",
        "schemaVersion": 1,
        "name": name,
        "changes": list(changes),
    }


# *--- Tests ---*


class ChangesFlagTests(unittest.TestCase):
    """`--changes` on all three commands, read as the inventory and the KEV catalog are."""

    def setUp(self) -> None:
        directory = tempfile.TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        self.workspace = Path(directory.name)

    def write_changes(self, document: dict[str, Any], name: str = "changes.json") -> Path:
        path = self.workspace / name
        path.write_text(json.dumps(document), encoding="utf-8")
        return path

    def test_no_changes_flag_changes_no_byte(self) -> None:
        cases = (
            ("vdt-fixtures", REPORT_ARGUMENTS),
            ("avi-fixtures", AVI_ARGUMENTS),
            ("historical-fixtures", HISTORICAL_ARGUMENTS),
            ("vdt-coverage", COVERAGE_ARGUMENTS),
            ("vdt-coverage-timed", timed_argv()),
        )
        for name, argv in cases:
            with self.subTest(golden=name):
                json_path = self.workspace / f"{name}.json"
                markdown_path = self.workspace / f"{name}.md"

                code, _, err = run([*argv, "-o", str(json_path), "--markdown", str(markdown_path)])

                self.assertEqual(code, 0, msg=err)
                self.assertEqual(json_path.read_bytes(), (GOLDEN / f"{name}.json").read_bytes())
                self.assertEqual(markdown_path.read_bytes(), (GOLDEN / f"{name}.md").read_bytes())

    def test_block_appears_only_with_changes(self) -> None:
        for kind, argv in INVENTORIED:
            with self.subTest(report=kind):
                markdown_path = self.workspace / f"{kind}-without.md"
                code, out, err = run([*argv, "--markdown", str(markdown_path)])
                self.assertEqual(code, 0, msg=err)
                self.assertNotIn("changes", json.loads(out)["x-complyroll"])
                self.assertNotIn("\n## Changes\n", markdown_path.read_text(encoding="utf-8"))

                markdown_path = self.workspace / f"{kind}-with.md"
                code, out, err = run(
                    [
                        *argv,
                        "--changes",
                        str(EXAMPLE_CHANGES),
                        "--markdown",
                        str(markdown_path),
                    ]
                )
                self.assertEqual(code, 0, msg=err)
                self.assertEqual(block_of(out)["input"]["name"], "example-changes")
                self.assertIn("\n## Changes\n", markdown_path.read_text(encoding="utf-8"))

    def test_block_carries_the_contracted_keys_and_rule_provenance(self) -> None:
        code, out, err = run(list(CHANGES_ARGUMENTS))

        self.assertEqual(code, 0, msg=err)
        document = json.loads(out)
        block = document["x-complyroll"]["changes"]
        self.assertEqual(
            set(block),
            {
                "rule",
                "force",
                "provenance",
                "asOf",
                "input",
                "inventorySha256",
                "summary",
                "changes",
                "obligations",
                "unregistered",
                "later",
                "basis",
            },
        )
        self.assertEqual(block["rule"], "VDR-CSO-DAC")
        self.assertEqual(block["force"], "SHOULD")
        self.assertEqual(block["provenance"], document["x-complyroll"]["rulesSource"])
        self.assertEqual(set(block["input"]), {"name", "sizeBytes", "sha256", "changeCount"})
        self.assertEqual(
            set(block["summary"]),
            {
                "unregistered",
                "retired",
                "logged",
                "detected",
                "lapsed",
                "undetermined",
                "pending",
            },
        )

    def test_markdown_section_follows_coverage(self) -> None:
        for kind, argv in INVENTORIED:
            with self.subTest(report=kind):
                markdown_path = self.workspace / f"{kind}.md"

                code, _, err = run(
                    [
                        *argv,
                        "--changes",
                        str(EXAMPLE_CHANGES),
                        "--markdown",
                        str(markdown_path),
                    ]
                )

                self.assertEqual(code, 0, msg=err)
                markdown = markdown_path.read_text(encoding="utf-8")
                headings = [line for line in markdown.split("\n") if line.startswith("## ")]
                coverage = headings.index("## Coverage")
                self.assertEqual(headings[coverage + 1], "## Changes")
                self.assertEqual(headings[coverage + 2], "## Diagnostics")

    def test_help_names_the_flag_on_every_command(self) -> None:
        for kind in KINDS:
            with self.subTest(report=kind):
                text = help_text(["report", kind])
                self.assertIn("--changes FILE", text)
                self.assertIn("needs --inventory", " ".join(text.split()))

    def test_second_changes_file_is_invalid_option(self) -> None:
        for kind, argv in INVENTORIED:
            with self.subTest(report=kind):
                changes = str(EXAMPLE_CHANGES)

                code, out, err = run([*argv, "--changes", changes, "--changes", changes])

                self.assertEqual(code, 1)
                self.assertEqual(out, "")
                self.assertEqual(
                    err,
                    f"error: invalid_option: report {kind} takes one --changes file, not 2\n",
                )

    def test_changes_without_inventory_is_invalid_option(self) -> None:
        # The file does not exist, so reaching it would be an invalid_input instead.
        for kind, argv in RUNS:
            with (
                self.subTest(report=kind),
                mock.patch.object(cli_module, "load_changes", side_effect=AssertionError("read")),
            ):
                code, out, err = run([*argv, "--changes", str(self.workspace / "gone.json")])

                self.assertEqual(code, 1)
                self.assertEqual(out, "")
                self.assertEqual(
                    err,
                    f"error: invalid_option: report {kind} --changes needs --inventory: a "
                    "change is read against the inventory or not at all\n",
                )

    def test_changes_beside_db_is_refused(self) -> None:
        changes = str(EXAMPLE_CHANGES)
        for kind, argv in (
            ("vdt", ["--from", "2026-08-01T00:00:00Z", "--to", "2026-08-31T23:59:59Z"]),
            ("avi", ["--from", "2026-08-01T00:00:00Z", "--to", "2026-08-31T23:59:59Z"]),
            ("historical", []),
        ):
            with self.subTest(report=kind):
                code, out, err = run(
                    [
                        "report",
                        kind,
                        "--db",
                        str(self.workspace / "store.db"),
                        "--class",
                        "C",
                        "--package-uri",
                        "https://example.test/cpo",
                        *argv,
                        "--inventory",
                        str(EXAMPLE_INVENTORY),
                        "--changes",
                        changes,
                    ]
                )

                self.assertEqual(code, 1)
                self.assertEqual(out, "")
                self.assertEqual(
                    err,
                    f"error: invalid_option: report {kind} takes either --db or --changes, "
                    "never both\n",
                )

    def test_refused_change_file_is_invalid_input_and_writes_nothing(self) -> None:
        cases = {
            "not JSON": (b"changeId,kind\n", "changes must be a JSON document"),
            "an inventory": (EXAMPLE_INVENTORY.read_bytes(), "changes: schema must be"),
            "a repeated id": (
                json.dumps(change_file(change_entry(), change_entry())).encode("utf-8"),
                "changes changes[1]: changeId repeats changes[0]",
            ),
        }
        for label, (content, message) in cases.items():
            for kind, argv in INVENTORIED:
                with self.subTest(case=label, report=kind):
                    path = self.workspace / "refused.json"
                    path.write_bytes(content)
                    json_path = self.workspace / "report.json"

                    code, out, err = run([*argv, "--changes", str(path), "-o", str(json_path)])

                    self.assertEqual(code, 1)
                    self.assertEqual(out, "")
                    self.assertIn(f"error: invalid_input: {message}", err)
                    self.assertFalse(json_path.exists())

    def test_a_change_file_that_is_not_there_is_invalid_input(self) -> None:
        json_path = self.workspace / "report.json"
        missing = self.workspace / "gone.json"

        code, out, err = run([*INVENTORIED[0][1], "--changes", str(missing), "-o", str(json_path)])

        self.assertEqual(code, 1)
        self.assertEqual(out, "")
        self.assertIn("error: invalid_input: changes cannot be read", err)
        self.assertFalse(json_path.exists())

    def test_output_overwriting_the_change_file_is_refused(self) -> None:
        path = self.write_changes(change_file(change_entry()))
        before = path.read_bytes()
        for option in ("-o", "--markdown"):
            with self.subTest(destination=option):
                code, out, err = run(
                    [*INVENTORIED[0][1], "--changes", str(path), option, str(path)]
                )

                self.assertEqual(code, 1)
                self.assertEqual(out, "")
                self.assertIn("refusing to overwrite the input file", err)
                self.assertEqual(path.read_bytes(), before)

    def test_diagnostics_are_in_report_diagnostic_codes(self) -> None:
        # An adapter's diagnostic keeps its own code, so only the change codes are held here.
        seen: set[str] = set()
        for argv in (list(CHANGES_ARGUMENTS), timed_changes_argv()):
            code, out, err = run(argv)
            self.assertEqual(code, 0, msg=err)
            diagnostics = json.loads(out)["x-complyroll"]["diagnostics"]
            seen.update(item["code"] for item in diagnostics if item["code"].startswith("change_"))
        self.assertEqual(
            seen,
            {
                "change_after_decommission",
                "change_precedes_expected_since",
                "change_resource_unregistered",
            },
        )
        self.assertLessEqual(seen, set(REPORT_DIAGNOSTIC_CODES))

    def test_warnings_print_on_stderr_and_exit_zero(self) -> None:
        code, _, err = run(list(CHANGES_ARGUMENTS))

        self.assertEqual(code, 0, msg=err)
        self.assertIn(
            "warning: change_resource_unregistered: change CHG-1005 names host:lab-ubuntu-99, "
            "which no inventory entry or sample group carries, so it opens no obligation; add "
            "the resource to the inventory, with expectedSince at or before occurredAt for a "
            "created change [example-changes CHG-1005 host:lab-ubuntu-99]",
            err.splitlines(),
        )

    def test_markdown_escapes_hostile_rationale_and_json_is_verbatim(self) -> None:
        inventory = self.write_changes(
            {
                "schema": "complyroll.inventory",
                "schemaVersion": 1,
                "name": "hostile|inventory",
                "resources": [
                    {
                        "resourceType": "file",
                        "resourceId": "app|`main.js",
                        "machineBased": True,
                        "driftLikely": False,
                        "sampleGroup": "gr|`oup",
                        "expectedSince": "2026-08-01T00:00:00Z",
                        "aliases": [{"resourceType": "file", "resourceId": "al|`ias"}],
                    }
                ],
            },
            "hostile-inventory.json",
        )
        path = self.write_changes(
            change_file(
                change_entry(
                    "CHG|`99",
                    source={"tool": "git|hub", "reference": "ref | `x` <y>"},
                    resources=[
                        {"resourceType": "file", "resourceId": "al|`ias"},
                        {"resourceType": "host", "resourceId": "un|registered`"},
                    ],
                    rationale=HOSTILE,
                    job="job|`name",
                ),
                change_entry(
                    "CHG|`later",
                    occurredAt="2026-09-10T00:00:00Z",
                    resources=[{"resourceType": "file", "resourceId": "al|`ias"}],
                ),
                name="hostile|`file",
            )
        )
        markdown_path = self.workspace / "hostile.md"

        code, out, err = run(
            [
                *timed_argv(inventory=False),
                "--inventory",
                str(inventory),
                "--changes",
                str(path),
                "--markdown",
                str(markdown_path),
            ]
        )

        self.assertEqual(code, 0, msg=err)
        block = block_of(out)
        row = block["changes"][0]
        self.assertEqual(row["rationale"], HOSTILE)
        self.assertEqual(row["changeId"], "CHG|`99")
        self.assertEqual(row["source"], {"tool": "git|hub", "reference": "ref | `x` <y>"})
        self.assertEqual(row["job"], "job|`name")
        self.assertEqual(block["input"]["name"], "hostile|`file")
        section = changes_section(markdown_path.read_text(encoding="utf-8"))
        tables = {
            heading: subsection(section, heading)
            for heading in (
                "Declared changes",
                "Obligations",
                "Unregistered resources",
                "Changes after as-of",
            )
        }
        # A header, a rule and the rows: a flattened newline adds no row, a pipe no column.
        self.assertEqual(
            {heading: len(rows) for heading, rows in tables.items()},
            {
                "Declared changes": 3,
                "Obligations": 4,
                "Unregistered resources": 3,
                "Changes after as-of": 3,
            },
        )
        for heading, rows in tables.items():
            with self.subTest(table=heading):
                self.assertEqual(
                    {unescaped_pipes(line) for line in rows}, {unescaped_pipes(rows[0])}
                )
        declared = tables["Declared changes"][2]
        # A tab keeps its cell, so only the newline is flattened and the row stays one line.
        self.assertIn(
            "pipe \\| tick ` tab\there second &lt;b&gt;line&lt;/b&gt; back\\\\slash", declared
        )
        self.assertIn("CHG\\|`99", declared)
        self.assertIn("git\\|hub: ref \\| `x` &lt;y&gt;", declared)
        self.assertIn("job\\|`name", declared)
        obligation = tables["Obligations"][2]
        self.assertIn("file:app\\|`main.js", obligation)
        self.assertIn("gr\\|`oup", obligation)
        self.assertIn("file:al\\|`ias", obligation)
        self.assertIn("host:un\\|registered`", tables["Obligations"][3])
        unregistered = tables["Unregistered resources"][2]
        self.assertIn("host:un\\|registered`", unregistered)
        self.assertIn("CHG\\|`99", unregistered)
        later = tables["Changes after as-of"][2]
        self.assertIn("CHG\\|`later", later)
        self.assertIn("file:al\\|`ias", later)
        self.assertIn("hostile\\|`file", section)
        self.assertNotIn("<b>", section)

    def test_a_lag_of_zero_prints_as_zero(self) -> None:
        path = self.write_changes(
            change_file(change_entry(occurredAt="2026-09-01T02:00:00.123456Z"))
        )
        markdown_path = self.workspace / "zero.md"

        code, out, err = run(
            [*timed_argv(), "--changes", str(path), "--markdown", str(markdown_path)]
        )

        self.assertEqual(code, 0, msg=err)
        self.assertEqual(block_of(out)["obligations"][0]["lagSeconds"], 0)
        section = changes_section(markdown_path.read_text(encoding="utf-8"))
        row = subsection(section, "Obligations")[2]
        cells = [cell.strip() for cell in re.split(r"(?<!\\)\|", row)[1:-1]]
        self.assertEqual(cells[5], "detected")
        self.assertEqual(cells[9], "0")

    def test_as_of_before_every_change_is_an_empty_block(self) -> None:
        for kind in KINDS:
            with self.subTest(report=kind):
                markdown_path = self.workspace / f"{kind}.md"

                code, out, err = run(
                    [
                        *with_as_of(timed_changes_argv(kind), "2026-08-05T12:00:00Z"),
                        "--markdown",
                        str(markdown_path),
                    ]
                )

                self.assertEqual(code, 0, msg=err)
                block = block_of(out)
                self.assertEqual(block["obligations"], [])
                self.assertEqual(block["changes"], [])
                self.assertEqual(block["unregistered"], [])
                self.assertEqual(set(block["summary"].values()), {0})
                self.assertEqual(len(block["later"]), 6)
                self.assertEqual(block["input"]["changeCount"], 6)
                section = changes_section(markdown_path.read_text(encoding="utf-8"))
                self.assertIn("No change occurred at or before as-of.", section)
                self.assertIn("No obligation is measured at this as-of.", section)
                self.assertIn("Every resource a change names is in the inventory.", section)
                self.assertEqual(len(subsection(section, "Changes after as-of")), 8)
                self.assertNotIn(
                    "change_",
                    {item["code"] for item in json.loads(out)["x-complyroll"]["diagnostics"]},
                )

    def test_an_empty_change_file_is_an_empty_block(self) -> None:
        path = self.write_changes(change_file())
        markdown_path = self.workspace / "empty.md"

        code, out, err = run(
            [*timed_argv(), "--changes", str(path), "--markdown", str(markdown_path)]
        )

        self.assertEqual(code, 0, msg=err)
        block = block_of(out)
        self.assertEqual((block["input"]["changeCount"], block["later"]), (0, []))
        section = changes_section(markdown_path.read_text(encoding="utf-8"))
        self.assertIn("No change occurred after as-of.", section)

    def test_reordered_artifacts_and_changes_give_identical_bytes(self) -> None:
        document = json.loads(TIMED_CHANGES.read_text(encoding="utf-8"))
        forward = self.write_changes(document, "forward.json")
        backward_document = copy.deepcopy(document)
        backward_document["changes"].reverse()
        for item in backward_document["changes"]:
            item["resources"].reverse()
        backward = self.write_changes(backward_document, "backward.json")
        reordered_artifacts = timed_argv()
        reordered_artifacts[2:4] = reversed(reordered_artifacts[2:4])

        outputs = {}
        for label, argv, path in (
            ("forward", timed_argv(), forward),
            ("artifacts", reordered_artifacts, forward),
            ("both", reordered_artifacts, backward),
        ):
            json_path = self.workspace / f"{label}-report.json"
            markdown_path = self.workspace / f"{label}-report.md"
            code, _, err = run(
                [
                    *argv,
                    "--changes",
                    str(path),
                    "-o",
                    str(json_path),
                    "--markdown",
                    str(markdown_path),
                ]
            )
            self.assertEqual(code, 0, msg=err)
            outputs[label] = (json_path.read_bytes(), markdown_path.read_bytes())

        self.assertEqual(outputs["forward"], outputs["artifacts"])
        # The file's bytes moved, so its digest names a different file; nothing else may move.
        first = extension_of(self.workspace / "forward-report.json")["changes"]["input"]["sha256"]
        second = extension_of(self.workspace / "both-report.json")["changes"]["input"]["sha256"]
        self.assertNotEqual(first, second)
        for one, other in zip(outputs["forward"], outputs["both"], strict=True):
            self.assertEqual(
                one.replace(first.encode(), b"-"), other.replace(second.encode(), b"-")
            )

    def test_avi_and_historical_carry_the_block_at_as_of(self) -> None:
        blocks = {}
        for kind in KINDS:
            code, out, err = run(timed_changes_argv(kind))
            self.assertEqual(code, 0, msg=err)
            blocks[kind] = block_of(out)
        self.assertEqual(blocks["avi"], blocks["vdt"])
        self.assertEqual(blocks["historical"], blocks["vdt"])
        self.assertTrue(blocks["vdt"]["obligations"])
        # A past as-of moves a change to later in every report; a period never selects it.
        for kind in KINDS:
            with self.subTest(report=kind):
                code, out, err = run(with_as_of(timed_changes_argv(kind), "2026-08-29T00:00:00Z"))
                self.assertEqual(code, 0, msg=err)
                block = block_of(out)
                self.assertEqual(
                    [row["changeId"] for row in block["obligations"]], ["CHG-2001", "CHG-2002"]
                )
                self.assertEqual(
                    [item["changeId"] for item in block["later"]],
                    ["CHG-2003", "CHG-2004", "CHG-2005", "CHG-2006"],
                )

    def test_a_policy_without_the_change_rule_stops_the_run_and_writes_nothing(self) -> None:
        for kind, argv in INVENTORIED:
            with (
                self.subTest(report=kind),
                mock.patch.object(records_module, "select_policy", stripped_policy("VDR-CSO-DAC")),
            ):
                json_path = self.workspace / "report.json"

                code, out, err = run(
                    [*argv, "--changes", str(EXAMPLE_CHANGES), "-o", str(json_path)]
                )

                self.assertEqual(code, 1)
                self.assertEqual(out, "")
                self.assertIn(
                    "error: change_rule_unavailable: a change file was supplied, but the Class "
                    "C policy selects no VDR-CSO-DAC rule, so no change can be read against it "
                    "[example-changes]",
                    err,
                )
                self.assertFalse(json_path.exists())

    def test_without_the_flag_the_change_rule_is_never_read(self) -> None:
        with mock.patch.object(records_module, "select_policy", stripped_policy("VDR-CSO-DAC")):
            code, out, err = run(list(COVERAGE_ARGUMENTS))

        self.assertEqual(code, 0, msg=err)
        self.assertEqual(out, (GOLDEN / "vdt-coverage.json").read_text(encoding="utf-8"))

    def test_a_bom_kev_reaches_the_row_and_the_diagnostics(self) -> None:
        # The real adapter's shape: a PASS scope on the image, OPEN rows on packages, one digest.
        catalog = json.loads((FIXTURES / "kev-catalog.json").read_text(encoding="utf-8"))
        catalog["vulnerabilities"][0]["cveID"] = "CVE-2023-0286"
        catalog["vulnerabilities"][0]["dateAdded"] = "2026-09-02"
        kev_path = self.workspace / "kev.json"
        kev_path.write_text(json.dumps(catalog), encoding="utf-8")
        markdown_path = self.workspace / "kev.md"
        changes = self.write_changes(
            change_file(
                change_entry(
                    "CHG-3001",
                    kind="created",
                    occurredAt="2026-09-20T00:00:00Z",
                    resources=[
                        {"resourceType": "image", "resourceId": "registry.example.test/api:2.1"}
                    ],
                )
            )
        )

        code, out, err = run(
            [
                "report",
                "historical",
                str(FIXTURES / "trivy-image.cdx.json"),
                "--class",
                "C",
                "--package-uri",
                "https://example.test/cpo",
                "--as-of",
                "2026-10-05T00:00:00Z",
                "--kev",
                str(kev_path),
                "--inventory",
                str(FIXTURES / "inventory-cyclonedx.json"),
                "--changes",
                str(changes),
                "--markdown",
                str(markdown_path),
            ]
        )

        self.assertEqual(code, 0, msg=err)
        row = block_of(out)["obligations"][0]
        self.assertEqual(row["status"], "detected")
        self.assertIs(row["kevAtActivation"], True)
        self.assertEqual(len(row["kevTrackingIds"]), 1)
        self.assertIn("warning: kev_at_activation: change CHG-3001 activated image:", err)
        section = changes_section(markdown_path.read_text(encoding="utf-8"))
        self.assertIn(f"| yes | {row['kevTrackingIds'][0]} |", section)

    def test_kev_tracking_id_follows_an_evaluation_override(self) -> None:
        web = "registry.example.test/kev/web:2.3.1/usr/lib/libexample-net.so.4"
        inventory_path = self.workspace / "inventory.json"
        inventory_path.write_text(
            json.dumps(
                {
                    "schema": "complyroll.inventory",
                    "schemaVersion": 1,
                    "name": "kev-inventory",
                    "resources": [
                        {
                            "resourceType": "image",
                            "resourceId": web,
                            "machineBased": True,
                            "driftLikely": True,
                            "expectedSince": "2026-01-01T00:00:00Z",
                        }
                    ],
                }
            ),
            encoding="utf-8",
        )
        changes = self.write_changes(
            change_file(
                change_entry(
                    "CHG-1",
                    kind="created",
                    occurredAt="2026-09-01T00:00:00Z",
                    resources=[{"resourceType": "image", "resourceId": web}],
                )
            )
        )
        evaluations = json.loads(KEV_EVALUATIONS.read_text(encoding="utf-8"))
        evaluations["evaluations"] = [{**evaluations["evaluations"][0], "trackingId": "PROV-7"}]
        evaluations_path = self.workspace / "evaluations.json"
        evaluations_path.write_text(json.dumps(evaluations), encoding="utf-8")

        code, out, err = run(
            [
                "report",
                "vdt",
                str(FIXTURES / "kev-image-web.sarif"),
                *KEV_ARGUMENTS,
                "--as-of",
                "2026-09-15T12:00:00Z",
                "--from",
                "2026-09-01T00:00:00Z",
                "--to",
                "2026-09-30T23:59:59Z",
                "--kev",
                str(FIXTURES / "kev-catalog.json"),
                "--inventory",
                str(inventory_path),
                "--changes",
                str(changes),
                "--evaluations",
                str(evaluations_path),
            ]
        )

        self.assertEqual(code, 0, msg=err)
        document = json.loads(out)
        row = document["x-complyroll"]["changes"]["obligations"][0]
        self.assertIs(row["kevAtActivation"], True)
        self.assertIn("PROV-7", row["kevTrackingIds"])
        published = {
            record["providerTrackingId"]
            for record in document["vulnerabilities"]
            if "providerTrackingId" in record
        }
        self.assertLessEqual(set(row["kevTrackingIds"]), published)


class ChangeOptionTests(unittest.TestCase):
    """`ReportOptions.changes` and the compile: refused alone, and derived after coverage."""

    def change_set(self) -> Any:
        return load_changes(TIMED_CHANGES)

    def test_changes_need_an_inventory(self) -> None:
        with self.assertRaisesRegex(ValueError, "changes needs an inventory"):
            ReportOptions(changes=self.change_set(), **COMPILE_OPTIONS)

    def test_changes_must_be_a_change_set(self) -> None:
        with self.assertRaisesRegex(TypeError, "changes must be a ChangeSet"):
            ReportOptions(
                changes="changes.json",  # type: ignore[arg-type]
                inventory=load_inventory(TIMED_INVENTORY),
                **COMPILE_OPTIONS,
            )

    def compile_with(self, observations: Sequence[Any]) -> Any:
        return records_module.compile_record_set(
            artifacts=(),
            observations=observations,
            ingest_diagnostics=(),
            evaluations_by_tracking_id={},
            attestation=DetectionAttestation(),
            options=ReportOptions(
                changes=self.change_set(),
                inventory=load_inventory(TIMED_INVENTORY),
                **COMPILE_OPTIONS,
            ),
        )

    def test_a_clock_coverage_refuses_is_named_before_the_changes_are_read(self) -> None:
        unusable = observation(at=datetime(1, 1, 1, tzinfo=timezone(timedelta(hours=1))))

        with self.assertRaises(ReportCompileError) as caught:
            self.compile_with([unusable])

        self.assertEqual(
            {item.code for item in caught.exception.diagnostics}, {"clock_out_of_range"}
        )

    def test_the_record_set_carries_one_projection_and_its_warnings(self) -> None:
        record_set = self.compile_with([])

        self.assertIsInstance(record_set.changes, ChangeProjection)
        self.assertEqual(
            {row.status for row in record_set.changes.obligations},
            {ObligationStatus.LAPSED, ObligationStatus.PENDING},
        )
        self.assertEqual(
            [item for item in record_set.diagnostics if item.code.startswith("change_")],
            list(record_set.changes.warnings),
        )

    def test_a_compile_without_changes_carries_no_projection(self) -> None:
        record_set = records_module.compile_record_set(
            artifacts=(),
            observations=(),
            ingest_diagnostics=(),
            evaluations_by_tracking_id={},
            attestation=DetectionAttestation(),
            options=ReportOptions(inventory=load_inventory(TIMED_INVENTORY), **COMPILE_OPTIONS),
        )

        self.assertIsNone(record_set.changes)


if __name__ == "__main__":
    unittest.main()
