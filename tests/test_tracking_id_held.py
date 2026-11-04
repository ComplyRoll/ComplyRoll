# ******************************************************************************
# *Title: Held Tracking Id Tests*
# *Author: Kyle Versluis*
# *Description: Tests for ingest refusing a second identity under a held id.*
# ******************************************************************************
"""Tests for `ingest` refusing a second identity under a tracking id already held (CL-84).

A tracking id is 64 bits of SHA-256 over an observation's identity, so a laptop finds two
identities under one id in under a minute, and one file holding them would stop every report and
`cases correlate` for good. `ingest` refuses that file before it appends anything (ADR 0008
amendment 2026-11-03, second). The real pair is `COLLIDING_RULES`. Every other collision here is
forced by cutting the digest to nothing with `short_ids`: a search per adapter would prove nothing
more and cost a minute each.
"""

# *--- Imports ---*

from __future__ import annotations

import hashlib
import json
import sqlite3
import tempfile
import unittest
from collections.abc import Mapping, Sequence
from contextlib import closing
from dataclasses import replace
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any
from unittest import mock

from test_cli import TRUNCATED_FIXTURE, tamper_with_one_payload
from test_evaluation_order import (
    COLLIDING_CONTEXT,
    COLLIDING_ID,
    COLLIDING_RULES,
    COLLISION_TAIL,
    WRITTEN_AT,
    WRITTEN_AT_TEXT,
    colliding_scan,
    report_vdt,
    reread_with_timestamp,
    run,
    verify_store,
)
from test_report_codes import scan as scan_codes
from test_reports import EXAMPLES, FIXTURES, evaluations_for

from complyroll import cli, correlation
from complyroll.adapters import IngestResult, classify_ingest, ingest_stig_artifact
from complyroll.correlation import tracking_id_for
from complyroll.events import EventMetadata, EventRepository
from complyroll.events import repository as event_repository
from complyroll.history import (
    apply_evaluations,
    correlate_cases,
    fold_all_cases,
    record_ingest,
    tracking_id_refusals,
)
from complyroll.history import fold as history_fold
from complyroll.history import writers as history_writers
from complyroll.history.order import current_groups
from complyroll.reports import REPORT_DIAGNOSTIC_CODES
from complyroll.store import EventStoreError, NewEvent, SQLiteEventStore

# *--- Fixtures ---*

FIRST, SECOND = COLLIDING_RULES
FAILURE_SOURCE_TYPE = "complyroll.detection-process"
FAILURE_RECORD_ID = "detection-process-failure"
#: What a tracking id becomes under `short_ids`.
SHORT_ID = "case-"
METADATA = EventMetadata(actor="tester")
COVERAGE_OPTIONS = (
    "--class",
    "C",
    "--as-of",
    WRITTEN_AT_TEXT,
    "--inventory",
    str(EXAMPLES / "inventory.json"),
)

Identity = tuple[str, str, str]


def identity(rule: str) -> Identity:
    """Return the identity a `colliding_scan` gives one rule."""

    return ("cklb", rule, COLLIDING_CONTEXT)


def held_line(holder: Identity, refused: Identity, location: str, tracking_id: str) -> str:
    """Return the one line a refused identity is named by."""

    return (
        f"error: tracking_id_held: tracking id {tracking_id!r} is held by {holder!r}, so "
        f"{refused!r} would be a second identity under it and nothing was recorded by this run "
        f"[{location}]"
    )


def closed_line(other: Identity, restated: Identity, location: str, tracking_id: str) -> str:
    """Return the one line that names a side of an id the store already holds twice."""

    return (
        f"error: tracking_id_held: tracking id {tracking_id!r} is already held by {other!r} and "
        f"{restated!r}, so a run may bring neither and nothing was recorded by this run "
        f"[{location}]"
    )


def pair_line(holder: str, refused: str, location: str) -> str:
    """Return the refusal of one of the real pair while the other holds their id."""

    return held_line(identity(holder), identity(refused), location, COLLIDING_ID)


def closed_pair_line(restated: str, location: str) -> str:
    """Return the refusal of one side of the real pair on a store that already holds both."""

    (other,) = [rule for rule in COLLIDING_RULES if rule != restated]
    return closed_line(identity(other), identity(restated), location, COLLIDING_ID)


def short_ids() -> Any:
    """Cut every tracking id to its prefix, so any two identities collide with no search."""

    return mock.patch.object(correlation, "TRACKING_ID_DIGEST_LENGTH", 0)


def failure_identity(path: Path) -> Identity:
    """Return the identity of the system observation a failed reading of a file mints."""

    digest = hashlib.sha256(path.read_bytes()).hexdigest()
    return (FAILURE_SOURCE_TYPE, FAILURE_RECORD_ID, f"sha256:{digest}")


def identities_of(path: Path) -> list[Identity]:
    """Return a file's distinct identities in the order the file states them."""

    result = ingest_stig_artifact(path, ingested_at=WRITTEN_AT)
    found: dict[Identity, None] = {}
    for observation in result.observations:
        found[(observation.source_type, observation.source_record_id, observation.context_key)] = (
            None
        )
    return list(found)


def scan_with_statuses(directory: Path, host: str, statuses: Mapping[str, str]) -> Path:
    """Write a `colliding_scan` whose rules carry the given CKLB statuses."""

    path = colliding_scan(directory, *statuses, host=host)
    payload = json.loads(path.read_text(encoding="utf-8"))
    for rule in payload["stigs"][0]["rules"]:
        rule["status"] = statuses[rule["group_id"]]
    path.write_text(json.dumps(payload), encoding="utf-8")
    return path


def record_through_the_library(database: Path, *paths: Path) -> None:
    """Write files through `record_ingest`, which has no check, as an earlier build's run did."""

    with SQLiteEventStore(database) as store:
        repository = EventRepository(store)
        for path in paths:
            result = ingest_stig_artifact(path, ingested_at=WRITTEN_AT)
            record_ingest(repository, result, metadata=METADATA, ingested_at=WRITTEN_AT)


def event_types(database: Path) -> list[str]:
    """Return the type of every event a store holds, in log order."""

    with SQLiteEventStore(database) as store:
        return [record.event_type for record in EventRepository(store).read_all()]


class HeldIdFixture(unittest.TestCase):
    """A temporary store driven through the command line, with the checks each test repeats."""

    def setUp(self) -> None:
        directory = tempfile.TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        self.directory = Path(directory.name)
        self.database = self.directory / "history.db"

    def ingest(self, *paths: Path, flags: Sequence[str] = ()) -> tuple[int, str, str]:
        argv = ["ingest", *map(str, paths), "--db", str(self.database), "--as-of", WRITTEN_AT_TEXT]
        return run([*argv, *flags])

    def stored(self, *paths: Path, flags: Sequence[str] = ()) -> None:
        code, _, err = self.ingest(*paths, flags=flags)
        self.assertEqual(code, 0, err)

    def smuggle(
        self,
        payload: Mapping[str, object],
        *,
        event_type: str = "observation.recorded",
        stream: str = f"artifact/{'a' * 64}/synthetic/1",
    ) -> None:
        """Append one event around the contract, as damage or a hand-built store would hold it."""

        with SQLiteEventStore(self.database) as store:
            store.append(
                stream,
                [
                    NewEvent(
                        event_type=event_type,
                        occurred_at=WRITTEN_AT,
                        payload=dict(payload),
                        metadata=METADATA.to_dict(),
                    )
                ],
                expected_version=store.current_stream_version(stream),
            )

    def smuggle_identity(self, holder: Identity, *, stream: str | None = None) -> None:
        """Append an observation holding one identity, on any stream."""

        source_type, source_record_id, context_key = holder
        payload = {
            "source_type": source_type,
            "source_record_id": source_record_id,
            "context_key": context_key,
        }
        if stream is None:
            self.smuggle(payload)
        else:
            self.smuggle(payload, stream=stream)

    def assert_no_store_published(self) -> None:
        """Require that a refused run left no store and no temporary beside the destination."""

        self.assertEqual(sorted(path.name for path in self.directory.glob("*history.db*")), [])

    def assert_refused(self, *paths: Path, lines: Sequence[str], flags: Sequence[str] = ()) -> str:
        """Require exit 1 with these refusal lines and the store left byte for byte as it was."""

        before = self.database.read_bytes() if self.database.exists() else None
        code, out, err = self.ingest(*paths, flags=flags)
        self.assertEqual((code, out), (1, ""), err)
        self.assertEqual(
            [line for line in err.splitlines() if ": tracking_id_held: " in line], list(lines)
        )
        if before is None:
            self.assert_no_store_published()
        else:
            self.assertEqual(self.database.read_bytes(), before)
            self.assertFalse(Path(f"{self.database}-wal").exists())
            self.assertFalse(Path(f"{self.database}-shm").exists())
        return err


# *--- Tests ---*


class RealPairCommandTests(HeldIdFixture):
    """The real pair, through `ingest`, in every place a run can bring it."""

    def test_the_pair_shares_one_id(self) -> None:
        for rule in COLLIDING_RULES:
            self.assertEqual(tracking_id_for("cklb", rule, COLLIDING_CONTEXT), COLLIDING_ID)

    def test_a_pair_in_one_file_is_refused_and_no_store_is_published(self) -> None:
        for holder, refused in (COLLIDING_RULES, COLLIDING_RULES[::-1]):
            with self.subTest(first_in_file=holder):
                path = colliding_scan(self.directory, holder, refused)

                code, out, err = self.ingest(path)

                self.assertEqual(
                    (code, out, err), (1, "", f"{pair_line(holder, refused, path.name)}\n")
                )
                self.assert_no_store_published()

    def test_a_pair_across_two_files_of_one_run_is_refused_in_either_order(self) -> None:
        for holder, refused in (COLLIDING_RULES, COLLIDING_RULES[::-1]):
            with self.subTest(listed_first=holder):
                first = colliding_scan(self.directory, holder, host="lab-02")
                second = colliding_scan(self.directory, refused, host="lab-03")

                code, out, err = self.ingest(first, second)

                self.assertEqual(
                    (code, out, err), (1, "", f"{pair_line(holder, refused, second.name)}\n")
                )
                self.assert_no_store_published()

    def test_a_pair_across_two_runs_is_refused_in_either_order(self) -> None:
        for holder, refused in (COLLIDING_RULES, COLLIDING_RULES[::-1]):
            with self.subTest(recorded_first=holder):
                self.database = self.directory / f"{holder}-history.db"
                self.stored(colliding_scan(self.directory, holder, host="lab-02"))
                second = colliding_scan(self.directory, refused, host="lab-03")

                self.assert_refused(second, lines=[pair_line(holder, refused, second.name)])

    def test_a_refused_run_leaves_a_store_verify_and_every_reader_pass(self) -> None:
        # A refusal of a run's own input is not a store fault (ADR 0008 amendment 2026-11-03).
        self.stored(colliding_scan(self.directory, FIRST, host="lab-02"))
        verified = verify_store(self.database)
        reported = report_vdt(self.database)
        self.assertEqual((verified[0], reported[0]), (0, 0), verified[2] + reported[2])
        refused = colliding_scan(self.directory, SECOND, host="lab-03")

        self.assert_refused(refused, lines=[pair_line(FIRST, SECOND, refused.name)])

        self.assertEqual(verify_store(self.database), verified)
        self.assertEqual(report_vdt(self.database), reported)
        code, _, err = run(["cases", "correlate", "--db", str(self.database)])
        self.assertEqual(code, 0, err)

    def test_a_clean_file_beside_the_refused_one_is_not_recorded(self) -> None:
        clean = colliding_scan(self.directory, "V-clean", host="lab-clean")
        crafted = colliding_scan(self.directory)

        with self.subTest(store="new"):
            self.assert_refused(clean, crafted, lines=[pair_line(FIRST, SECOND, crafted.name)])

        with self.subTest(store="existing"):
            self.stored(colliding_scan(self.directory, "V-kept", host="lab-kept"))
            self.assert_refused(clean, crafted, lines=[pair_line(FIRST, SECOND, crafted.name)])

    def test_one_identity_on_many_hosts_is_one_holder(self) -> None:
        # One rule on many hosts is the common case, so repeats must not read as a second holder.
        first = colliding_scan(self.directory, FIRST, host="lab-02")
        second = colliding_scan(self.directory, FIRST, host="lab-03")
        self.stored(first, second)
        third = colliding_scan(self.directory, FIRST, host="lab-04")

        code, out, err = self.ingest(first, third)

        self.assertEqual(
            (code, out),
            (0, f"{first.name}: already_recorded\n{third.name}: recorded 1 observation(s)\n"),
            err,
        )

    def test_a_rerun_of_the_holder_passes(self) -> None:
        holder = colliding_scan(self.directory, FIRST, host="lab-02")
        self.stored(holder)

        code, out, err = self.ingest(holder)

        self.assertEqual((code, out), (0, f"{holder.name}: already_recorded\n"), err)

    def test_a_pair_inside_a_run_closes_nothing(self) -> None:
        # The closed ids are fixed before the walk, so the lone holder stated after the newcomer
        # is no refusal, and the run's lines are what they were.
        self.stored(colliding_scan(self.directory, FIRST, host="lab-02"))
        newcomer = colliding_scan(self.directory, SECOND, host="lab-03")
        again = colliding_scan(self.directory, FIRST, host="lab-04")

        self.assert_refused(newcomer, again, lines=[pair_line(FIRST, SECOND, newcomer.name)])

    def test_a_holder_or_a_newcomer_that_is_not_open_counts(self) -> None:
        # Identity does not depend on disposition, and a later scan can open it.
        for status in ("not_a_finding", "not_applicable"):
            for holder_status, newcomer_status in ((status, "open"), ("open", status)):
                with self.subTest(holder=holder_status, newcomer=newcomer_status):
                    self.database = self.directory / f"{holder_status}-{newcomer_status}.db"
                    holder = scan_with_statuses(self.directory, "lab-02", {FIRST: holder_status})
                    newcomer = scan_with_statuses(
                        self.directory, "lab-03", {SECOND: newcomer_status}
                    )
                    self.stored(holder)

                    self.assert_refused(newcomer, lines=[pair_line(FIRST, SECOND, newcomer.name)])

    def test_a_pair_where_one_is_not_open_is_refused_in_one_file(self) -> None:
        path = scan_with_statuses(
            self.directory, "lab-02", {FIRST: "not_a_finding", SECOND: "open"}
        )

        self.assert_refused(path, lines=[pair_line(FIRST, SECOND, path.name)])

    def superseded_holder(self) -> None:
        """Leave FIRST correlated into a case and then superseded by a newer parser's reading."""

        path = colliding_scan(self.directory, FIRST, host="lab-02")
        result = ingest_stig_artifact(path, ingested_at=WRITTEN_AT)
        with SQLiteEventStore(self.database) as store:
            repository = EventRepository(store)
            record_ingest(repository, result, metadata=METADATA, ingested_at=WRITTEN_AT)
            correlate_cases(repository, metadata=METADATA, now=WRITTEN_AT)
            # A newer parser of the same bytes, which no longer reads the rule as open.
            newer = replace(reread_with_timestamp(result, WRITTEN_AT), observations=())
            record_ingest(repository, newer, metadata=METADATA, ingested_at=WRITTEN_AT)
            self.assertEqual(current_groups(repository), {})
            self.assertEqual(
                [case.tracking_id for case in fold_all_cases(repository)], [COLLIDING_ID]
            )

    def test_a_holder_whose_reading_is_superseded_still_holds(self) -> None:
        self.superseded_holder()
        refused = colliding_scan(self.directory, SECOND, host="lab-03")

        self.assert_refused(refused, lines=[pair_line(FIRST, SECOND, refused.name)])

    def test_a_superseded_holder_s_case_would_take_a_second_identity(self) -> None:
        # Why a superseded holder counts: its case stream still exists, so `cases correlate` would
        # link a second identity onto another identity's case, with every reader passing.
        self.superseded_holder()
        record_through_the_library(
            self.database, colliding_scan(self.directory, SECOND, host="lab-03")
        )
        self.assertEqual((verify_store(self.database)[0], report_vdt(self.database)[0]), (0, 0))

        code, out, err = run(["cases", "correlate", "--db", str(self.database)])

        self.assertEqual(
            (code, out),
            (
                0,
                "created 0 case(s), linked 1 observation(s), "
                "skipped 0 already-linked observation(s)\n",
            ),
            err,
        )
        with SQLiteEventStore(self.database) as store:
            (case,) = fold_all_cases(EventRepository(store))
        self.assertEqual((case.source_record_id, len(case.links)), (FIRST, 2))
        self.assertEqual(verify_store(self.database)[0], 0)

    def test_the_flag_turns_the_refusal_into_no_failure(self) -> None:
        crafted = colliding_scan(self.directory)

        self.assert_refused(
            crafted,
            lines=[pair_line(FIRST, SECOND, crafted.name)],
            flags=["--record-failed-imports"],
        )

    def test_the_flag_mints_nothing_for_a_failure_beside_the_refused_file(self) -> None:
        crafted = colliding_scan(self.directory)
        self.stored(colliding_scan(self.directory, "V-kept", host="lab-kept"))
        before = event_types(self.database)

        err = self.assert_refused(
            TRUNCATED_FIXTURE,
            crafted,
            lines=[pair_line(FIRST, SECOND, crafted.name)],
            flags=["--record-failed-imports"],
        )

        # Nothing was recorded, so the failed reading writes its own ERROR and claims no failure.
        (held, failed) = err.splitlines()
        self.assertEqual(held, pair_line(FIRST, SECOND, crafted.name))
        self.assertTrue(failed.startswith("error: artifact_parse_failed: "), failed)
        self.assertTrue(failed.endswith(f"[{TRUNCATED_FIXTURE.name}]"), failed)
        self.assertEqual(event_types(self.database), before)

    def test_a_side_record_beside_the_refused_file_is_not_written(self) -> None:
        crafted = colliding_scan(self.directory)

        err = self.assert_refused(
            FIXTURES / "failed-invocation.sarif",
            crafted,
            lines=[pair_line(FIRST, SECOND, crafted.name)],
            flags=["--record-failed-imports"],
        )

        self.assertNotIn("detection_failure_recorded", err)

    def test_failure_read_elsewhere_still_speaks_first(self) -> None:
        # The run it refuses prints what it always printed, and this check never reads that run.
        scan = self.directory / "scan-output.sarif"
        scan.write_bytes((FIXTURES / "grype-image.sarif").read_bytes())
        self.stored(scan)
        misnamed = self.directory / "scan-output.ckl"
        misnamed.write_bytes(scan.read_bytes())
        crafted = colliding_scan(self.directory)

        err = self.assert_refused(misnamed, crafted, lines=[], flags=["--record-failed-imports"])

        self.assertTrue(err.startswith("error: failure_read_elsewhere: "), err)

    def test_the_code_is_in_the_closed_set_and_the_scan_sees_it(self) -> None:
        self.assertIn("tracking_id_held", REPORT_DIAGNOSTIC_CODES)
        sites = scan_codes().codes["tracking_id_held"]
        self.assertTrue(any("history/writers.py" in site for site in sites), sites)

    def test_a_clean_run_of_every_adapter_is_not_refused(self) -> None:
        paths = [
            FIXTURES / name
            for name in (
                "ubuntu-host.cklb",
                "windows-host.ckl",
                "openscap-results.xml",
                "grype-image.sarif",
                "inspec-linux-host.hdf.json",
                "grype-image.cdx.json",
            )
        ]

        code, _, err = self.ingest(*paths)

        self.assertEqual(code, 0, err)
        self.assertNotIn("tracking_id_held", err)


class ForcedCollisionTests(HeldIdFixture):
    """Collisions forced by `short_ids` on what the real pair cannot reach."""

    def anchor(self) -> Path:
        """Record one rule and return its file, so the store holds exactly one identity."""

        path = colliding_scan(self.directory, "V-anchor", host="lab-anchor")
        self.stored(path)
        return path

    def test_short_ids_collide_every_identity(self) -> None:
        with short_ids():
            self.assertEqual(tracking_id_for("a", "b", "c"), SHORT_ID)
            self.assertEqual(tracking_id_for("d", "e", "f"), SHORT_ID)

    def test_every_adapter_s_identities_are_refused_in_one_file_and_against_a_store(self) -> None:
        for name in (
            "ubuntu-host.cklb",
            "windows-host.ckl",
            "openscap-results.xml",
            "grype-image.sarif",
            "inspec-linux-host.hdf.json",
            "grype-image.cdx.json",
        ):
            path = FIXTURES / name
            first, *others = identities_of(path)
            self.assertTrue(others, name)
            with self.subTest(adapter=name, place="one file"):
                self.database = self.directory / f"one-file-{name}.db"
                with short_ids():
                    code, out, err = self.ingest(path)
                self.assertEqual((code, out), (1, ""), err)
                self.assertEqual(
                    [line for line in err.splitlines() if ": tracking_id_held: " in line],
                    [held_line(first, other, name, SHORT_ID) for other in others],
                )
                self.assertFalse(self.database.exists())
            with self.subTest(adapter=name, place="against a store"):
                self.database = self.directory / f"against-{name}.db"
                self.stored(colliding_scan(self.directory, "V-anchor", host="lab-anchor"))
                with short_ids():
                    self.assert_refused(
                        path,
                        lines=[
                            held_line(identity("V-anchor"), other, name, SHORT_ID)
                            for other in identities_of(path)
                        ],
                    )

    def test_each_later_identity_names_the_first_holder(self) -> None:
        path = colliding_scan(self.directory, "V-one", "V-two", "V-three")

        with short_ids():
            self.assert_refused(
                path,
                lines=[
                    held_line(identity("V-one"), identity("V-two"), path.name, SHORT_ID),
                    held_line(identity("V-one"), identity("V-three"), path.name, SHORT_ID),
                ],
            )

    def test_a_refused_identity_is_named_once_at_the_first_file_that_brings_it(self) -> None:
        self.anchor()
        first = colliding_scan(self.directory, "V-two", host="lab-02")
        second = colliding_scan(self.directory, "V-two", host="lab-03")

        with short_ids():
            self.assert_refused(
                first,
                second,
                lines=[held_line(identity("V-anchor"), identity("V-two"), first.name, SHORT_ID)],
            )

    def test_a_repeat_of_the_holder_in_a_later_file_is_no_refusal(self) -> None:
        anchor = colliding_scan(self.directory, "V-anchor", host="lab-anchor")
        self.stored(anchor)
        again = colliding_scan(self.directory, "V-anchor", host="lab-other")

        with short_ids():
            code, out, err = self.ingest(again)

        self.assertEqual((code, out), (0, f"{again.name}: recorded 1 observation(s)\n"), err)

    def test_a_long_identity_is_cut_in_the_line_on_either_side(self) -> None:
        self.stored(colliding_scan(self.directory, "H" * 5000, host="lab-holder"))
        path = colliding_scan(self.directory, "V" * 5000, host="lab-long")

        with short_ids():
            code, _, err = self.ingest(path)

        self.assertEqual(code, 1)
        (line,) = err.splitlines()
        self.assertRegex(
            line,
            r"is held by \('cklb', 'H+\.\.\. \(\d+ characters\), so "
            r"\('cklb', 'V+\.\.\. \(\d+ characters\) would be a second identity",
        )
        self.assertLess(len(line) - len(path.name), 700)

    def test_a_control_character_in_an_identity_stays_on_one_line(self) -> None:
        self.anchor()
        path = colliding_scan(self.directory, "V-a\nerror: forged: line", host="lab-control")

        with short_ids():
            code, _, err = self.ingest(path)

        self.assertEqual(code, 1)
        self.assertEqual(len(err.splitlines()), 1, err)
        self.assertIn(": tracking_id_held: ", err)
        self.assertIn("V-a\\nerror: forged: line", err)

    def two_stig_scan(self, *stigs: str) -> Path:
        """Write a CKLB file stating one rule under each STIG name, each its own identity."""

        path = colliding_scan(self.directory, "V-same", host="lab-stigs")
        payload = json.loads(path.read_text(encoding="utf-8"))
        rule = payload["stigs"][0]["rules"][0]
        payload["stigs"] = [{"stig_name": name, "rules": [rule]} for name in stigs]
        path.write_text(json.dumps(payload), encoding="utf-8")
        return path

    def test_two_identities_differing_only_in_context_key_are_refused(self) -> None:
        path = self.two_stig_scan("STIG A", "STIG B")
        holder, refused = ("cklb", "V-same", "STIG A"), ("cklb", "V-same", "STIG B")
        self.assertEqual(identities_of(path), [holder, refused])

        with short_ids():
            self.assert_refused(path, lines=[held_line(holder, refused, path.name, SHORT_ID)])

    def test_two_identities_differing_only_in_source_type_are_refused(self) -> None:
        holder = ("ckl", "V-same", COLLIDING_CONTEXT)
        self.smuggle_identity(holder)
        path = colliding_scan(self.directory, "V-same", host="lab-same")

        with short_ids():
            self.assert_refused(
                path, lines=[held_line(holder, identity("V-same"), path.name, SHORT_ID)]
            )

    def blank_context_xccdf(self) -> Path:
        """Write an XCCDF file whose only identity has a context key of only whitespace."""

        path = self.directory / "blank-context.xml"
        path.write_text(
            '<Benchmark xmlns="http://checklists.nist.gov/xccdf/1.2" id="">'
            '<TestResult id=" " end-time="2026-08-10T09:00:00Z"><target>lab-01</target>'
            '<rule-result idref="rule_one"><result>fail</result></rule-result>'
            "</TestResult></Benchmark>",
            encoding="utf-8",
        )
        return path

    def test_a_holder_with_a_context_key_of_only_whitespace_holds(self) -> None:
        blank = self.blank_context_xccdf()
        (holder,) = identities_of(blank)
        self.assertEqual(holder[2].strip(), "")
        self.stored(blank)
        path = colliding_scan(self.directory, "V-two", host="lab-02")

        with short_ids():
            self.assert_refused(
                path, lines=[held_line(holder, identity("V-two"), path.name, SHORT_ID)]
            )

    def test_a_holder_on_any_stream_kind_holds(self) -> None:
        holder = identity("V-smuggled")
        path = colliding_scan(self.directory, "V-two", host="lab-02")
        for stream in (
            f"artifact/{'a' * 64}/synthetic/1",
            f"failure/{'a' * 64}/synthetic/1",
            f"coverage/{'a' * 64}",
            "case/case-00000000000000ff",
        ):
            with self.subTest(stream=stream):
                self.database = self.directory / f"{stream.split('/')[0]}.db"
                self.smuggle_identity(holder, stream=stream)

                with short_ids():
                    self.assert_refused(
                        path, lines=[held_line(holder, identity("V-two"), path.name, SHORT_ID)]
                    )

    # *--- An id the store already holds twice ---*

    def three_holders(self) -> Path:
        """Write three identities through the library, which `short_ids` puts under one id."""

        path = colliding_scan(self.directory, "V-one", "V-two", "V-three")
        record_through_the_library(self.database, path)
        return path

    def test_a_side_of_a_closed_id_names_the_first_holder_that_is_not_itself(self) -> None:
        self.three_holders()
        for rule, other in (("V-one", "V-two"), ("V-two", "V-one"), ("V-three", "V-one")):
            with self.subTest(rule=rule):
                path = colliding_scan(self.directory, rule, host=f"lab-{rule}")

                with short_ids():
                    self.assert_refused(
                        path,
                        lines=[closed_line(identity(other), identity(rule), path.name, SHORT_ID)],
                    )

    def test_a_rerun_on_a_closed_id_names_every_side(self) -> None:
        path = self.three_holders()

        with short_ids():
            self.assert_refused(
                path,
                lines=[
                    closed_line(identity("V-two"), identity("V-one"), path.name, SHORT_ID),
                    closed_line(identity("V-one"), identity("V-two"), path.name, SHORT_ID),
                    closed_line(identity("V-one"), identity("V-three"), path.name, SHORT_ID),
                ],
            )

    def test_a_new_identity_under_a_closed_id_keeps_its_words(self) -> None:
        self.three_holders()
        path = colliding_scan(self.directory, "V-new", host="lab-new")

        with short_ids():
            self.assert_refused(
                path, lines=[held_line(identity("V-one"), identity("V-new"), path.name, SHORT_ID)]
            )

    def test_each_identity_is_named_once_a_run_across_both_forms(self) -> None:
        self.three_holders()
        new = colliding_scan(self.directory, "V-new", host="lab-new")
        new_again = colliding_scan(self.directory, "V-new", host="lab-new-again")
        side = colliding_scan(self.directory, "V-two", host="lab-side")
        side_again = colliding_scan(self.directory, "V-two", host="lab-side-again")

        with short_ids():
            self.assert_refused(
                new,
                new_again,
                side,
                side_again,
                lines=[
                    held_line(identity("V-one"), identity("V-new"), new.name, SHORT_ID),
                    closed_line(identity("V-one"), identity("V-two"), side.name, SHORT_ID),
                ],
            )

    def test_a_closed_id_is_cut_in_the_line_on_either_side(self) -> None:
        holder, restated = "H" * 5000, "V" * 5000
        record_through_the_library(
            self.database, colliding_scan(self.directory, holder, restated, host="lab-long")
        )
        path = colliding_scan(self.directory, restated, host="lab-restated")

        with short_ids():
            code, _, err = self.ingest(path)

        self.assertEqual(code, 1)
        (line,) = err.splitlines()
        self.assertRegex(
            line,
            r"is already held by \('cklb', 'H+\.\.\. \(\d+ characters\) and "
            r"\('cklb', 'V+\.\.\. \(\d+ characters\), so a run may bring neither",
        )
        self.assertLess(len(line) - len(path.name), 700)

    def test_a_recorded_failure_under_a_closed_id_is_refused_on_rerun(self) -> None:
        # No exemption by kind: the failure's id is held twice under `short_ids`, so exit 1, not 3.
        self.stored_failure()
        self.anchor()
        before = event_types(self.database)

        with short_ids():
            err = self.assert_refused(
                TRUNCATED_FIXTURE,
                lines=[
                    closed_line(
                        identity("V-anchor"),
                        failure_identity(TRUNCATED_FIXTURE),
                        TRUNCATED_FIXTURE.name,
                        SHORT_ID,
                    )
                ],
                flags=["--record-failed-imports"],
            )

        self.assertEqual(event_types(self.database), before)
        self.assertNotIn("detection_failure_recorded", err)

    # *--- A failure's id ---*

    def stored_failure(self) -> None:
        code, _, err = self.ingest(TRUNCATED_FIXTURE, flags=["--record-failed-imports"])
        self.assertEqual(code, 3, err)

    def test_a_recorded_failure_holds_its_id_against_a_later_file(self) -> None:
        self.stored_failure()
        path = colliding_scan(self.directory, "V-two", host="lab-02")

        with short_ids():
            self.assert_refused(
                path,
                lines=[
                    held_line(
                        failure_identity(TRUNCATED_FIXTURE), identity("V-two"), path.name, SHORT_ID
                    )
                ],
            )

    def test_a_failed_reading_is_refused_against_a_held_id_and_mints_nothing(self) -> None:
        self.anchor()
        before = event_types(self.database)

        with short_ids():
            err = self.assert_refused(
                TRUNCATED_FIXTURE,
                lines=[
                    held_line(
                        identity("V-anchor"),
                        failure_identity(TRUNCATED_FIXTURE),
                        TRUNCATED_FIXTURE.name,
                        SHORT_ID,
                    )
                ],
                flags=["--record-failed-imports"],
            )

        self.assertEqual(event_types(self.database), before)
        (_, failed) = err.splitlines()
        self.assertTrue(failed.startswith("error: artifact_parse_failed: "), failed)

    def test_a_failed_reading_brings_no_identity_without_the_flag(self) -> None:
        self.anchor()

        with short_ids():
            code, out, err = self.ingest(TRUNCATED_FIXTURE)

        self.assertEqual((code, out), (1, ""))
        (line,) = err.splitlines()
        self.assertTrue(line.startswith("error: artifact_parse_failed: "), line)

    def test_a_side_record_is_refused_under_its_own_observation_s_id(self) -> None:
        path = FIXTURES / "failed-invocation.sarif"
        (own,) = identities_of(path)

        with short_ids():
            err = self.assert_refused(
                path,
                lines=[held_line(own, failure_identity(path), path.name, SHORT_ID)],
                flags=["--record-failed-imports"],
            )

        self.assertNotIn("detection_failure_recorded", err)

    def test_listed_order_decides_between_a_failure_and_a_file(self) -> None:
        path = colliding_scan(self.directory, "V-two", host="lab-02")
        failure = failure_identity(TRUNCATED_FIXTURE)

        with self.subTest(listed_first="failure"), short_ids():
            self.assert_refused(
                TRUNCATED_FIXTURE,
                path,
                lines=[held_line(failure, identity("V-two"), path.name, SHORT_ID)],
                flags=["--record-failed-imports"],
            )
        with self.subTest(listed_first="file"), short_ids():
            self.assert_refused(
                path,
                TRUNCATED_FIXTURE,
                lines=[held_line(identity("V-two"), failure, TRUNCATED_FIXTURE.name, SHORT_ID)],
                flags=["--record-failed-imports"],
            )

    def test_a_side_record_s_own_observations_come_before_its_failure(self) -> None:
        path = FIXTURES / "failed-invocation.sarif"
        (own,) = identities_of(path)
        failure = failure_identity(path)
        other = colliding_scan(self.directory, "V-two", host="lab-02")

        with short_ids():
            self.assert_refused(
                path,
                other,
                lines=[
                    held_line(own, failure, path.name, SHORT_ID),
                    held_line(own, identity("V-two"), other.name, SHORT_ID),
                ],
                flags=["--record-failed-imports"],
            )

    def test_a_rerun_of_a_recorded_failure_is_not_refused(self) -> None:
        self.stored_failure()
        before = self.database.read_bytes()

        with short_ids():
            code, out, err = self.ingest(TRUNCATED_FIXTURE, flags=["--record-failed-imports"])

        self.assertEqual((code, out), (3, f"{TRUNCATED_FIXTURE.name}: already_recorded\n"), err)
        self.assertNotIn("tracking_id_held", err)
        self.assertEqual(self.database.read_bytes(), before)

    # *--- A coverage gap's id ---*

    def test_a_coverage_gap_holds_its_id_against_a_later_file(self) -> None:
        # `cases coverage` gets no check of its own: a later crafted file is refused here.
        SQLiteEventStore(self.database).close()
        code, _, err = run(["cases", "coverage", "--db", str(self.database), *COVERAGE_OPTIONS])
        self.assertEqual(code, 3, err)
        with SQLiteEventStore(self.database) as store:
            (gap, *_) = [
                record.payload
                for record in EventRepository(store).read_all()
                if record.event_type == "observation.recorded"
            ]
        self.assertEqual(gap["source_type"], "complyroll.coverage")
        holder = (gap["source_type"], gap["source_record_id"], gap["context_key"])
        path = colliding_scan(self.directory, "V-two", host="lab-02")

        with short_ids():
            self.assert_refused(
                path, lines=[held_line(holder, identity("V-two"), path.name, SHORT_ID)]
            )


class LivePairTests(HeldIdFixture):
    """Two current groups under one id: verify names the store and every report refuses it."""

    def setUp(self) -> None:
        super().setUp()
        self.crafted = colliding_scan(self.directory)
        result = ingest_stig_artifact(self.crafted, ingested_at=WRITTEN_AT)
        with SQLiteEventStore(self.database) as store:
            outcome = record_ingest(
                EventRepository(store), result, metadata=METADATA, ingested_at=WRITTEN_AT
            )
        self.assertTrue(outcome.appended)

    def readers(self) -> list[tuple[int, str, str]]:
        return [
            verify_store(self.database),
            report_vdt(self.database),
            run(["cases", "correlate", "--db", str(self.database)]),
        ]

    def test_the_store_is_one_verify_names_and_every_reader_refuses(self) -> None:
        side = f"no evaluation entry (originally {COLLIDING_ID})"
        message = (
            f"effective tracking id {COLLIDING_ID!r} is claimed by {side} and {side}; "
            f"{COLLISION_TAIL}"
        )
        verified, reported, correlated = self.readers()

        self.assertEqual(verified[0], 1)
        self.assertIn(f": tracking_id_collision: {message}\n", verified[2])
        self.assertEqual(
            reported, (1, "", f"error: tracking_id_collision: {message} [no evaluation entry]\n")
        )
        self.assertEqual(correlated[0], 1)
        self.assertTrue(
            correlated[2].startswith(f"error: store_conflict: stream 'case/{COLLIDING_ID}'"),
            correlated[2],
        )

    def assert_refused_with_readers_unchanged(self, path: Path, *lines: str) -> None:
        readers = self.readers()

        self.assert_refused(path, lines=lines)

        self.assertEqual(self.readers(), readers)

    def test_a_rerun_of_the_file_is_refused(self) -> None:
        # A rerun appends nothing, but no exception is carved out for it: a store holding a pair
        # is named to the operator, at the cost of an exit 1 on a store no report can read.
        self.assert_refused_with_readers_unchanged(
            self.crafted,
            closed_pair_line(FIRST, self.crafted.name),
            closed_pair_line(SECOND, self.crafted.name),
        )

    def test_a_new_file_restating_one_side_is_refused(self) -> None:
        again = colliding_scan(self.directory, SECOND, host="lab-other")

        self.assert_refused_with_readers_unchanged(again, closed_pair_line(SECOND, again.name))

    def test_a_third_identity_under_the_id_is_refused(self) -> None:
        readers = self.readers()
        third = colliding_scan(self.directory, "V-third", host="lab-third")

        with short_ids():
            self.assert_refused(
                third,
                lines=[held_line(identity(FIRST), identity("V-third"), third.name, SHORT_ID)],
            )

        self.assertEqual(self.readers(), readers)

    def test_a_new_identity_under_another_id_is_recorded(self) -> None:
        other = colliding_scan(self.directory, "V-other", host="lab-other")

        code, out, err = self.ingest(other)

        self.assertEqual((code, out), (0, f"{other.name}: recorded 1 observation(s)\n"), err)

    def test_the_library_writer_has_no_check_of_its_own(self) -> None:
        # One scan a run, so library callers and test stores stay as they are.
        with SQLiteEventStore(self.directory / "library.db") as store:
            repository = EventRepository(store)
            for host, rule in (("lab-02", FIRST), ("lab-03", SECOND)):
                path = colliding_scan(self.directory, rule, host=host)
                record_ingest(
                    repository,
                    ingest_stig_artifact(path, ingested_at=WRITTEN_AT),
                    metadata=METADATA,
                    ingested_at=WRITTEN_AT,
                )
            self.assertEqual(len(tuple(repository.read_all())), 4)


class CorrelateOnALivePairTests(HeldIdFixture):
    """What `cases correlate` does depends on whether both groups meet in one correlate."""

    def test_both_groups_in_one_correlate_are_a_store_conflict(self) -> None:
        record_through_the_library(self.database, colliding_scan(self.directory))

        code, out, err = run(["cases", "correlate", "--db", str(self.database)])

        self.assertEqual((code, out), (1, ""))
        self.assertTrue(err.startswith(f"error: store_conflict: stream 'case/{COLLIDING_ID}'"), err)

    def test_a_side_correlated_first_takes_the_later_side_onto_its_case(self) -> None:
        record_through_the_library(
            self.database, colliding_scan(self.directory, FIRST, host="lab-02")
        )
        code, _, err = run(["cases", "correlate", "--db", str(self.database)])
        self.assertEqual(code, 0, err)
        record_through_the_library(
            self.database, colliding_scan(self.directory, SECOND, host="lab-03")
        )

        code, out, err = run(["cases", "correlate", "--db", str(self.database)])

        self.assertEqual(
            (code, out),
            (
                0,
                "created 0 case(s), linked 1 observation(s), "
                "skipped 1 already-linked observation(s)\n",
            ),
            err,
        )
        with SQLiteEventStore(self.database) as store:
            (case,) = fold_all_cases(EventRepository(store))
        self.assertEqual((case.source_record_id, len(case.links)), (FIRST, 2))
        self.assertEqual(verify_store(self.database)[0], 1)
        self.assertEqual(report_vdt(self.database)[0], 1)


class LatentPairTests(HeldIdFixture):
    """Both identities held with at most one current, and every reader passing.

    Verify's exit 0 does not mean no pair. One more current reading would stop every report, which
    is the outcome the check exists to prevent, so a run bringing either side is refused.
    """

    OPEN_LATER = {FIRST: "not_a_finding", SECOND: "open"}
    OPEN_FIRST = {FIRST: "open", SECOND: "not_a_finding"}
    NEITHER_OPEN = {FIRST: "not_a_finding", SECOND: "not_applicable"}

    def readers(self) -> list[tuple[int, str, str]]:
        return [
            verify_store(self.database),
            report_vdt(self.database),
            run(["cases", "correlate", "--db", str(self.database)]),
        ]

    def latent_pair(self, statuses: Mapping[str, str]) -> Path:
        """Write the pair through the library and correlate it, requiring every reader to pass."""

        original = scan_with_statuses(self.directory, "lab-old", statuses)
        record_through_the_library(self.database, original)
        self.assertEqual([reader[0] for reader in self.readers()], [0, 0, 0])
        return original

    def test_every_run_bringing_either_side_is_refused(self) -> None:
        for number, statuses in enumerate((self.OPEN_LATER, self.OPEN_FIRST, self.NEITHER_OPEN)):
            with self.subTest(statuses=statuses):
                self.database = self.directory / f"latent-{number}.db"
                original = self.latent_pair(statuses)
                readers = self.readers()
                first = colliding_scan(self.directory, FIRST, host="lab-first")
                second = colliding_scan(self.directory, SECOND, host="lab-second")
                for path, lines in (
                    (first, [closed_pair_line(FIRST, first.name)]),
                    (second, [closed_pair_line(SECOND, second.name)]),
                    (
                        original,
                        [
                            closed_pair_line(FIRST, original.name),
                            closed_pair_line(SECOND, original.name),
                        ],
                    ),
                ):
                    self.assert_refused(path, lines=lines)
                    self.assertEqual(self.readers(), readers)

    def test_a_flagged_rerun_is_refused_too(self) -> None:
        original = self.latent_pair(self.OPEN_LATER)

        self.assert_refused(
            original,
            lines=[
                closed_pair_line(FIRST, original.name),
                closed_pair_line(SECOND, original.name),
            ],
            flags=["--record-failed-imports"],
        )

    def test_what_the_refusal_prevents(self) -> None:
        # Through the library, which has no check, the same file puts both current.
        self.latent_pair(self.OPEN_LATER)

        record_through_the_library(
            self.database, colliding_scan(self.directory, FIRST, host="lab-first")
        )

        self.assertEqual(verify_store(self.database)[0], 1)
        self.assertEqual(report_vdt(self.database)[0], 1)


class DamagedStoreTests(HeldIdFixture):
    """A payload of another shape is read past; a log the read path refuses stops the run."""

    def test_a_field_of_another_type_or_missing_is_read_past(self) -> None:
        good = {"source_type": "cklb", "source_record_id": "V-damaged", "context_key": "S"}
        for field in good:
            for name, damaged in (
                ("missing", {key: value for key, value in good.items() if key != field}),
                ("null", {**good, field: None}),
                ("number", {**good, field: 5}),
                ("list", {**good, field: ["x"]}),
                ("object", {**good, field: {"x": "y"}}),
            ):
                with self.subTest(field=field, damage=name):
                    self.database = self.directory / f"{field}-{name}.db"
                    self.smuggle(damaged)
                    # The store holds nothing else and every identity shares one id under
                    # `short_ids`, so a payload the guard let through would refuse this file.
                    path = colliding_scan(self.directory, "V-new", host="lab-new")

                    with short_ids():
                        code, out, err = self.ingest(path)

                    self.assertEqual(
                        (code, out, err), (0, f"{path.name}: recorded 1 observation(s)\n", "")
                    )
                    code, _, err = verify_store(self.database)
                    self.assertEqual(code, 1, err)

    def test_another_event_type_holding_the_fields_is_no_identity(self) -> None:
        source_type, source_record_id, context_key = identity("V-other-event")
        self.smuggle(
            {
                "source_type": source_type,
                "source_record_id": source_record_id,
                "context_key": context_key,
            },
            event_type="artifact.ingested",
        )
        path = colliding_scan(self.directory, "V-new", host="lab-new")

        with short_ids():
            code, out, err = self.ingest(path)

        self.assertEqual((code, out, err), (0, f"{path.name}: recorded 1 observation(s)\n", ""))

    def test_an_empty_payload_is_read_past(self) -> None:
        self.stored(colliding_scan(self.directory, "V-kept", host="lab-kept"))
        self.smuggle({})
        path = colliding_scan(self.directory, "V-new", host="lab-new")

        code, out, err = self.ingest(path)

        self.assertEqual((code, out, err), (0, f"{path.name}: recorded 1 observation(s)\n", ""))

    def test_a_string_payload_that_is_damaged_elsewhere_still_holds_its_id(self) -> None:
        # Its identity reads, and whatever else is wrong with it is verify's to name.
        self.stored(colliding_scan(self.directory, "V-kept", host="lab-kept"))
        self.smuggle_identity(identity(FIRST))
        refused = colliding_scan(self.directory, SECOND, host="lab-03")

        self.assert_refused(refused, lines=[pair_line(FIRST, SECOND, refused.name)])

    def assert_stopped_as_store_integrity(self, path: Path) -> None:
        """Require one `store_integrity` line, nothing recorded and the bytes as they were."""

        before = self.database.read_bytes()

        code, out, err = self.ingest(path)

        self.assertEqual((code, out), (1, ""), err)
        (line,) = err.splitlines()
        self.assertTrue(line.startswith("error: store_integrity: "), line)
        self.assertNotIn("tracking_id_held", line)
        # Reading past the damage would reach the append, which fails with the same code on a
        # page SQLite cannot read, under words that blame the append.
        self.assertNotIn("could not append", line)
        self.assertEqual(self.database.read_bytes(), before)

    def test_a_row_the_read_path_refuses_stops_a_plain_ingest(self) -> None:
        # A second new refusal: a plain ingest read only its own streams and passed such a store.
        # No report can read that store and verify names it, so nothing is lost.
        self.stored(colliding_scan(self.directory, "V-kept", host="lab-kept"))
        tamper_with_one_payload(self.database)

        self.assert_stopped_as_store_integrity(
            colliding_scan(self.directory, "V-new", host="lab-new")
        )

        self.assertEqual(verify_store(self.database)[0], 1)
        self.assertEqual(report_vdt(self.database)[0], 1)

    def test_a_run_s_own_pair_on_such_a_store_stops_there_too(self) -> None:
        # The log is read before the walk, so the run never reaches its own pair.
        self.stored(colliding_scan(self.directory, "V-kept", host="lab-kept"))
        tamper_with_one_payload(self.database)

        self.assert_stopped_as_store_integrity(colliding_scan(self.directory))

    def read_path_refuses(self, damaged: bytes, name: str) -> bool:
        """Return whether `read_all` fails on a copy of these bytes.

        A file that does not open never reaches it, and `ingest` refuses that at open, as it did.
        """

        probe = self.directory / f"probe-{name}.db"
        probe.write_bytes(damaged)
        try:
            store = SQLiteEventStore(probe)
        except EventStoreError:
            return False
        with store:
            try:
                EventRepository(store).read_all()
            except EventStoreError:
                return True
        return False

    def test_a_page_the_read_path_refuses_stops_a_plain_ingest(self) -> None:
        # A row check never sees a page SQLite cannot read, and past that page the append fails
        # too. SQLite's own words differ by build, so only the code is held.
        self.stored(FIXTURES / "ubuntu-host.cklb", FIXTURES / "windows-host.ckl")
        pristine = self.database.read_bytes()
        with closing(sqlite3.connect(self.database)) as connection:
            (page_size,) = connection.execute("PRAGMA page_size").fetchone()
        path = colliding_scan(self.directory, "V-new", host="lab-new")
        tripped = 0
        for page in range(len(pristine) // page_size):
            damaged = bytearray(pristine)
            damaged[page * page_size : (page + 1) * page_size] = bytes(page_size)
            if not self.read_path_refuses(bytes(damaged), str(page)):
                continue
            tripped += 1
            with self.subTest(page=page):
                self.database = self.directory / f"page-{page}.db"
                self.database.write_bytes(damaged)

                self.assert_stopped_as_store_integrity(path)

                self.assertEqual(verify_store(self.database)[0], 1)
        self.assertGreater(tripped, 0)


class ReadPageBoundaryTests(HeldIdFixture):
    """A holder past the first read page still holds, so the map walks the whole log."""

    def test_a_holder_past_the_repository_s_first_page_still_holds(self) -> None:
        # With one event a page, the holder's observation is on the second page, after its head.
        self.stored(colliding_scan(self.directory, FIRST, host="lab-02"))
        refused = colliding_scan(self.directory, SECOND, host="lab-03")

        with mock.patch.object(event_repository, "READ_PAGE_SIZE", 1):
            self.assert_refused(refused, lines=[pair_line(FIRST, SECOND, refused.name)])

    def test_a_holder_past_the_store_s_default_page_still_holds(self) -> None:
        # `SQLiteEventStore.read_all` has its own default limit, which that patch does not reach.
        rules = [f"V-{number:04d}" for number in range(event_repository.READ_PAGE_SIZE)]
        self.stored(colliding_scan(self.directory, *rules, host="lab-filler"))
        self.stored(colliding_scan(self.directory, FIRST, host="lab-02"))
        refused = colliding_scan(self.directory, SECOND, host="lab-03")

        self.assert_refused(refused, lines=[pair_line(FIRST, SECOND, refused.name)])


class UnreadableFailureTests(HeldIdFixture):
    """A failure `system_observation_for` cannot mint still refuses as it always has."""

    MESSAGE = (
        "error: history_invalid: the detection process failure cannot be recorded: source time "
        "0001-01-01T00:00:00+14:00 has no UTC instant inside the years 1 to 9999, so a system "
        "observation has no identity\n"
    )
    CLOCK = datetime(1, 1, 1, tzinfo=timezone(timedelta(hours=14)))

    def read_with_no_utc_clock(self, path: Path, *, ingested_at: datetime) -> IngestResult:
        return replace(
            ingest_stig_artifact(path, ingested_at=ingested_at), failed_execution_at=self.CLOCK
        )

    def test_it_refuses_as_history_invalid_and_the_check_does_not_crash(self) -> None:
        path = FIXTURES / "failed-invocation.sarif"

        with mock.patch.object(cli, "ingest_stig_artifact", self.read_with_no_utc_clock):
            code, out, err = self.ingest(path, flags=["--record-failed-imports"])

        self.assertEqual((code, out), (1, ""))
        self.assertTrue(err.endswith(self.MESSAGE), err)
        self.assert_no_store_published()

    def test_a_refusal_of_the_run_comes_first_when_another_identity_is_refused(self) -> None:
        # Nothing is recorded either way, and the failure's own refusal waits for the rerun.
        path = FIXTURES / "failed-invocation.sarif"
        crafted = colliding_scan(self.directory)

        with mock.patch.object(cli, "ingest_stig_artifact", self.read_with_no_utc_clock):
            err = self.assert_refused(
                path,
                crafted,
                lines=[pair_line(FIRST, SECOND, crafted.name)],
                flags=["--record-failed-imports"],
            )

        self.assertNotIn("history_invalid", err)

    def test_the_file_s_own_observations_are_still_walked(self) -> None:
        path = FIXTURES / "failed-invocation.sarif"
        (own,) = identities_of(path)
        self.stored(colliding_scan(self.directory, "V-anchor", host="lab-anchor"))

        with (
            short_ids(),
            mock.patch.object(cli, "ingest_stig_artifact", self.read_with_no_utc_clock),
        ):
            self.assert_refused(
                path,
                lines=[held_line(identity("V-anchor"), own, path.name, SHORT_ID)],
                flags=["--record-failed-imports"],
            )

    def test_the_library_check_reads_past_it(self) -> None:
        path = FIXTURES / "failed-invocation.sarif"
        result = self.read_with_no_utc_clock(path, ingested_at=WRITTEN_AT)
        with SQLiteEventStore(self.database) as store:
            refusals = tracking_id_refusals(
                EventRepository(store),
                [(path.name, result, classify_ingest(result))],
                ingested_at=WRITTEN_AT,
            )

        self.assertEqual(refusals, ())


class CostTests(HeldIdFixture):
    """One scan a run, and no observation rehydrated, whatever the store holds."""

    def test_a_run_reads_the_log_once_and_rehydrates_nothing(self) -> None:
        self.stored(colliding_scan(self.directory, "V-kept", host="lab-kept"))
        first = colliding_scan(self.directory, "V-one", host="lab-01")
        second = colliding_scan(self.directory, "V-two", host="lab-02")

        with (
            mock.patch.object(
                EventRepository, "read_all", autospec=True, side_effect=EventRepository.read_all
            ) as read_all,
            mock.patch.object(history_writers, "rehydrate_observations") as rehydrate,
            mock.patch.object(history_fold, "rehydrate_observation_records") as records,
        ):
            code, _, err = self.ingest(first, second)

        self.assertEqual(code, 0, err)
        self.assertEqual(read_all.call_count, 1)
        rehydrate.assert_not_called()
        records.assert_not_called()

    def test_the_log_is_read_inside_the_run_s_transaction(self) -> None:
        # So a second writer waits, and what the check saw is still true when the run writes.
        seen: list[bool] = []
        read = history_writers._identities_held

        def spy(repository: EventRepository) -> dict[str, list[Identity]]:
            seen.append(repository.store.in_transaction)
            return read(repository)

        with mock.patch.object(history_writers, "_identities_held", spy):
            self.stored(colliding_scan(self.directory, "V-kept", host="lab-kept"))

        self.assertEqual(seen, [True])

    def transactions_of(self, *paths: Path, flags: Sequence[str] = ()) -> int:
        """Return how many times one run enters `SQLiteEventStore.transaction`."""

        with mock.patch.object(
            SQLiteEventStore,
            "transaction",
            autospec=True,
            side_effect=SQLiteEventStore.transaction,
        ) as transaction:
            code, _, err = self.ingest(*paths, flags=flags)
        self.assertIn(code, (0, 3), err)
        return transaction.call_count

    def test_the_scan_and_the_writes_share_one_transaction(self) -> None:
        # Two would let two runs each scan a clean log before either writes, and land the pair.
        with self.subTest(store="new"):
            self.assertEqual(
                self.transactions_of(colliding_scan(self.directory, "V-one", host="lab-01")), 1
            )
        with self.subTest(store="existing"):
            self.assertEqual(
                self.transactions_of(colliding_scan(self.directory, "V-two", host="lab-02")), 1
            )
        with self.subTest(store="existing, a side record"):
            self.assertEqual(
                self.transactions_of(
                    FIXTURES / "failed-invocation.sarif", flags=["--record-failed-imports"]
                ),
                1,
            )

    def test_a_store_with_no_observation_recorded_refuses_nothing(self) -> None:
        with SQLiteEventStore(self.database) as store:
            self.assertEqual(
                tracking_id_refusals(EventRepository(store), [], ingested_at=WRITTEN_AT), ()
            )


class EvaluationsAreNotIdentitiesTests(HeldIdFixture):
    """An override names no identity, so CL-87's route stays exactly as it is."""

    def test_an_override_onto_a_natural_id_does_not_hold_it(self) -> None:
        holder = colliding_scan(self.directory, "V-kept", host="lab-kept")
        self.stored(holder)
        natural = tracking_id_for("cklb", "V-later", COLLIDING_CONTEXT)
        later = colliding_scan(self.directory, "V-later", host="lab-later")
        evaluations = evaluations_for(
            {
                "match": {"sourceRecordId": "V-kept"},
                "trackingId": natural,
                "completedAt": "2026-08-11T12:00:00Z",
            }
        )
        with SQLiteEventStore(self.database) as store:
            repository = EventRepository(store)
            correlate_cases(repository, metadata=METADATA, now=WRITTEN_AT)
            apply_evaluations(repository, evaluations, metadata=METADATA, now=WRITTEN_AT)

        code, _, err = self.ingest(later)

        self.assertEqual(code, 0, err)
        self.assertNotIn("tracking_id_held", err)


if __name__ == "__main__":
    unittest.main()
