# ******************************************************************************
# *Title: Change Gap Divergence Tests*
# *Author: Kyle Versluis*
# *Description: Change gap awareness and its three notes on the store path.*
# ******************************************************************************
"""Tests for a store's change gaps read back into a report (ADR 0018, PR 3 task 4)."""

# *--- Imports ---*

from __future__ import annotations

import json
import unittest
from collections.abc import Sequence
from datetime import UTC, datetime
from typing import Any

from test_change_gap_report import CLOSED_ROWS, IMAGE, RECORDED_ROW_SENTENCE, ROW_KEYS
from test_change_gaps import timed
from test_changes import ALIAS, GROUP_PAIR, HOUR, SECOND, T, changes_of, host, inventory_of, pair
from test_changes import observation as scan
from test_changes_persisted import without_block_input, without_intro
from test_cli import (
    GOLDEN,
    TIMED_ARTIFACTS,
    TIMED_AS_OF,
    TIMED_CHANGES,
    TIMED_INVENTORY,
    PersistedStoreTestCase,
    run,
)
from test_reports import options

from complyroll.events import EventRepository
from complyroll.history import read_stored_changes, rehydrate_observations
from complyroll.models import Observation
from complyroll.policy import CertificationClass, CertificationProfile
from complyroll.reports import (
    CompiledRecordSet,
    DetectionAttestation,
    compile_record_set,
    load_inventory,
)
from complyroll.reports import records as records_module
from complyroll.reports.change_gaps import change_gap_observations
from complyroll.reports.changes import ObligationStatus, StoredChangeSet
from complyroll.reports.changes_input import ChangeSet
from complyroll.reports.inventory import Inventory
from complyroll.reports.records import derive_report_changes
from complyroll.store import SQLiteEventStore

# *--- Fixtures ---*

#: The three notes, in the order a report lists their kinds.
NOTE_CODES = ("change_gap_unrecorded", "change_gap_contradicted", "change_gap_unmatched")
#: The as-of every library compile below runs at, nine days after the windows closed.
AS_OF = datetime(2026, 9, 10, tzinfo=UTC)
#: Class C in UTC, the profile of `options()` and of every store read below.
PROFILE = CertificationProfile(CertificationClass.C, calendar_timezone="UTC")
INVENTORY = inventory_of(host("lab-01"), host("lab-02"))
#: One change naming two hosts: one case, two windows, both closing at 13:00.
CHANGE_SET = changes_of(timed("CHG-1", pair("lab-01"), pair("lab-02")))
#: One change naming one host, so its case carries one window.
LONE_SET = changes_of(timed("CHG-L", pair("lab-01")))
CLOSED = "2026-09-01T13:00:00Z"
#: How a contradicted note ends when nothing else holds its case open.
LONE_ADVICE = "and an evaluation can dispose it as a false positive"
CASE_ADVICE = (
    "and every other recorded gap of the case is contradicted too, so an evaluation can "
    "dispose the case as a false positive"
)
#: The timed store's `cases changes` and report arguments, less `--db`.
CASES_CHANGES = ("--class", "C", "--as-of", TIMED_AS_OF, "--inventory", str(TIMED_INVENTORY))
TIMED_REPORT = (
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
)
RENDER = "file:src/ui/render.js"


def stored(change_set: ChangeSet) -> StoredChangeSet:
    """Return a change file as a store holds it: each change under the file's name and digest."""
    count = len(change_set.changes)
    return StoredChangeSet(
        changes=change_set.changes,
        names=(change_set.name,) * count,
        digests=(change_set.sha256,) * count,
    )


def recorded(
    change_set: ChangeSet = CHANGE_SET,
    evidence: Sequence[Observation] = (),
    *,
    inventory: Inventory = INVENTORY,
    as_of: datetime = AS_OF,
) -> tuple[Observation, ...]:
    """Return the gaps `cases changes` records over these inputs, as a store holds them."""
    projection = derive_report_changes(evidence, stored(change_set), inventory, PROFILE, as_of)
    return change_gap_observations(projection, ingested_at=as_of)


def compile_stored(
    gaps: Sequence[Observation],
    evidence: Sequence[Observation] = (),
    *,
    change_set: ChangeSet = CHANGE_SET,
    inventory: Inventory = INVENTORY,
    as_of: datetime = AS_OF,
) -> CompiledRecordSet:
    """Compile as a store holding these gaps and this evidence compiles, change-gap aware."""
    return compile_record_set(
        artifacts=(),
        observations=(*evidence, *gaps),
        ingest_diagnostics=(),
        evaluations_by_tracking_id={},
        attestation=DetectionAttestation(),
        options=options(inventory=inventory, as_of=as_of, detected_at=None),
        stored_changes=stored(change_set),
        change_gap_aware=True,
    )


def notes(record_set: CompiledRecordSet) -> list[tuple[str, str, str | None]]:
    return [
        (item.code, item.message, item.location)
        for item in record_set.diagnostics
        if item.code in NOTE_CODES
    ]


def case_of(record_set: CompiledRecordSet, gap: Observation) -> str:
    """Return the tracking id of the record carrying one gap."""
    (record,) = [item for item in record_set.records if gap.observation_id in item.observation_ids]
    return record.tracking_id


def window(resource: str, change_id: str = "CHG-1", closed: str = CLOSED) -> str:
    return f"the VDR-CSO-DAC window for {resource} after change {change_id} that closed {closed}"


def standing(resource: str, still_derived: bool, change_id: str = "CHG-1") -> str:
    why = "still derives" if still_derived else "neither derives nor disproves"
    return f"{window(resource, change_id)}, which this run {why}"


def withheld(resource: str, still_derived: bool) -> str:
    return (
        f"but the case also carries {standing(resource, still_derived)}, so it stays open until "
        "every other gap it carries is contradicted or disposed on its own merits"
    )


def contradicted(
    tracking_id: str,
    resource: str,
    evidence: Observation,
    *,
    change_id: str = "CHG-1",
    advice: str = LONE_ADVICE,
    spelled: str | None = None,
) -> str:
    assert evidence.observed_at is not None
    at = evidence.observed_at.astimezone(UTC).isoformat().replace("+00:00", "Z")
    on = resource if spelled is None else spelled
    return (
        f"{tracking_id} carries the recorded gap of {window(resource, change_id)}, but "
        f"observation {evidence.observation_id} on {on} verified it at {at}, inside that "
        f"window, so this run derives no such window; the gap stays recorded, {advice}"
    )


def unmatched(tracking_id: str, resource: str, *, change_id: str = "CHG-1", tail: str = "") -> str:
    return (
        f"{tracking_id} carries the recorded gap of {window(resource, change_id)}, and this run "
        "derives no such window and holds no verification inside it, so its inventory, as-of "
        f"or class may differ from the run that recorded the gap; the gap stays recorded{tail}"
    )


def unrecorded(resource: str, change_id: str = "CHG-1", closed: str = CLOSED) -> str:
    return (
        f"the VDR-CSO-DAC window for {resource} after change {change_id} closed {closed} with "
        "no verification, and history records no gap for it, so no case in this report carries "
        "it; cases changes with this run's inventory, as-of and class records it"
    )


# *--- Notes ---*


class ChangeGapNoteTests(unittest.TestCase):
    """Each of the three notes alone, read as `compile_record_set_from_history` reads a store."""

    def test_a_store_that_records_every_closed_window_names_no_note(self) -> None:
        gaps = recorded()

        record_set = compile_stored(gaps)

        self.assertEqual(notes(record_set), [])
        tracking_id = case_of(record_set, gaps[0])
        self.assertEqual(case_of(record_set, gaps[1]), tracking_id)
        assert record_set.change_gap_records is not None
        self.assertEqual(set(record_set.change_gap_records.values()), {tracking_id})

    def test_a_closed_window_no_record_carries_is_unrecorded(self) -> None:
        lab_01, _ = recorded()

        record_set = compile_stored([lab_01])

        self.assertEqual(
            notes(record_set),
            [
                (
                    "change_gap_unrecorded",
                    unrecorded("host:lab-02"),
                    f"{CHANGE_SET.name} CHG-1 host:lab-02",
                )
            ],
        )
        self.assertEqual(
            {item.code: item.level.value for item in record_set.diagnostics}[
                "change_gap_unrecorded"
            ],
            "info",
        )
        assert record_set.change_gap_records is not None
        self.assertEqual(
            sorted(
                (row.resource.resource_id, tracking)
                for row, tracking in record_set.change_gap_records.items()
            ),
            [("lab-01", case_of(record_set, lab_01)), ("lab-02", None)],
        )

    def test_a_verification_inside_a_recorded_window_contradicts_its_gap(self) -> None:
        (gap,) = recorded(LONE_SET)
        inside = scan("lab-01", T + HOUR / 2)

        record_set = compile_stored([gap], [inside], change_set=LONE_SET)

        self.assertEqual(
            notes(record_set),
            [
                (
                    "change_gap_contradicted",
                    contradicted(
                        case_of(record_set, gap), "host:lab-01", inside, change_id="CHG-L"
                    ),
                    f"{LONE_SET.name} CHG-L host:lab-01",
                )
            ],
        )

    def test_the_window_holds_both_of_its_ends(self) -> None:
        # P M2: a change window is [occurredAt, detectBy], closed at both ends, unlike a coverage
        # window's (anchorAt, closedAt].
        (gap,) = recorded(LONE_SET)
        for label, at in (("at the change", T), ("at the close", T + HOUR)):
            with self.subTest(label):
                evidence = scan("lab-01", at)
                record_set = compile_stored([gap], [evidence], change_set=LONE_SET)
                self.assertEqual(
                    [code for code, _, _ in notes(record_set)], ["change_gap_contradicted"]
                )
                self.assertIn(f"observation {evidence.observation_id}", notes(record_set)[0][1])

    def test_a_verification_outside_the_window_leaves_the_gap_derived(self) -> None:
        # Before the change it satisfies nothing; after the close it detects late, and a late
        # detection does not withdraw the window (call 2). Either way the gap stays matched.
        (gap,) = recorded(LONE_SET)
        for label, at in (("before the change", T - SECOND), ("after the close", T + 2 * HOUR)):
            with self.subTest(label):
                record_set = compile_stored([gap], [scan("lab-01", at)], change_set=LONE_SET)
                self.assertEqual(notes(record_set), [])

    def test_a_recorded_gap_no_window_derives_and_nothing_disproves_is_unmatched(self) -> None:
        (gap,) = recorded(LONE_SET)
        # The entry left the inventory, so the change names an unregistered pair now.
        moved = inventory_of(host("lab-02"))

        record_set = compile_stored([gap], change_set=LONE_SET, inventory=moved)

        self.assertEqual(
            notes(record_set),
            [
                (
                    "change_gap_unmatched",
                    unmatched(case_of(record_set, gap), "host:lab-01", change_id="CHG-L"),
                    f"{LONE_SET.name} CHG-L host:lab-01",
                )
            ],
        )

    def test_a_scan_of_an_alias_inside_a_recorded_window_contradicts_its_gap(self) -> None:
        # P lesson 3: the entry was renamed after the gap was recorded and its old id is now an
        # alias, so the stored resource still files the evidence the derivation reads.
        (gap,) = recorded(LONE_SET)
        renamed = inventory_of(
            host("lab-01-new", aliases=[pair("lab-01")]), host("lab-02", aliases=[ALIAS])
        )
        for spelled in ("lab-01", "lab-01-new"):
            with self.subTest(spelled=spelled):
                evidence = scan(spelled, T + HOUR / 2)
                record_set = compile_stored(
                    [gap], [evidence], change_set=LONE_SET, inventory=renamed
                )
                self.assertEqual(
                    [message for _, message, _ in notes(record_set)],
                    [
                        contradicted(
                            case_of(record_set, gap),
                            "host:lab-01",
                            evidence,
                            change_id="CHG-L",
                            spelled=f"host:{spelled}",
                        )
                    ],
                )

    def test_a_group_gap_is_disproved_by_a_member_scan(self) -> None:
        # P M3: a group row reads its members under VDR-TFR-PSD, so its disproof does too.
        members = inventory_of(host("web-01", sampleGroup="web"), host("web-02", sampleGroup="web"))
        change_set = changes_of(timed("CHG-G", GROUP_PAIR))
        (gap,) = recorded(change_set, inventory=members)
        self.assertEqual(gap.resource.resource_id, "sample-group/web")
        evidence = scan("web-02", T + HOUR / 2)

        record_set = compile_stored([gap], [evidence], change_set=change_set, inventory=members)

        self.assertEqual(
            [message for _, message, _ in notes(record_set)],
            [
                contradicted(
                    case_of(record_set, gap),
                    "logical:sample-group/web",
                    evidence,
                    change_id="CHG-G",
                    spelled="host:web-02",
                )
            ],
        )

    def test_a_contradicted_resource_beside_a_standing_sibling_gets_the_whole_case_advice(
        self,
    ) -> None:
        # P lesson 9: one case per change makes a sibling the common case, not the corner.
        lab_01, lab_02 = recorded()
        inside = scan("lab-01", T + HOUR / 2)

        record_set = compile_stored([lab_01, lab_02], [inside])

        tracking_id = case_of(record_set, lab_01)
        self.assertEqual(
            [message for _, message, _ in notes(record_set)],
            [
                contradicted(
                    tracking_id, "host:lab-01", inside, advice=withheld("host:lab-02", True)
                )
            ],
        )

    def test_a_case_whose_every_gap_is_contradicted_advises_a_disposition(self) -> None:
        lab_01, lab_02 = recorded()
        first, second = scan("lab-01", T + HOUR / 2), scan("lab-02", T + HOUR / 4)

        record_set = compile_stored([lab_01, lab_02], [first, second])

        tracking_id = case_of(record_set, lab_01)
        self.assertEqual(
            [message for _, message, _ in notes(record_set)],
            [
                contradicted(tracking_id, "host:lab-01", first, advice=CASE_ADVICE),
                contradicted(tracking_id, "host:lab-02", second, advice=CASE_ADVICE),
            ],
        )

    def test_an_unmatched_sibling_holds_a_contradicted_gap_open(self) -> None:
        lab_01, lab_02 = recorded()
        inside = scan("lab-01", T + HOUR / 2)
        # lab-02 left the inventory: its gap is neither derived nor disproved.
        moved = inventory_of(host("lab-01"))

        record_set = compile_stored([lab_01, lab_02], [inside], inventory=moved)

        tracking_id = case_of(record_set, lab_01)
        self.assertEqual(
            [message for _, message, _ in notes(record_set)],
            [
                contradicted(
                    tracking_id, "host:lab-01", inside, advice=withheld("host:lab-02", False)
                ),
                unmatched(tracking_id, "host:lab-02"),
            ],
        )

    def test_the_notes_follow_occurrence_then_change_id_then_resource(self) -> None:
        # Call 12: unrecorded windows first, in obligation order, then every recorded gap no
        # window derives, in the same order.
        change_set = changes_of(
            timed("CHG-B", pair("lab-02"), pair("lab-01")),
            timed("CHG-A", pair("lab-02")),
            timed("CHG-Z", pair("lab-01"), occurredAt=(T - HOUR).isoformat()),
        )
        gaps = recorded(change_set)
        self.assertEqual(
            [(gap.context_key[-5:], gap.resource.resource_id) for gap in gaps],
            [("CHG-Z", "lab-01"), ("CHG-A", "lab-02"), ("CHG-B", "lab-01"), ("CHG-B", "lab-02")],
        )
        late = changes_of(
            timed("CHG-B", pair("lab-02"), pair("lab-01")),
            timed("CHG-A", pair("lab-02")),
            timed("CHG-Z", pair("lab-01"), occurredAt=(T - HOUR).isoformat()),
            timed("CHG-C", pair("lab-01")),
        )
        # An as-of before every window closed derives none of them, and CHG-C was never
        # recorded, so the four stored gaps are unmatched; at AS_OF CHG-C's window is unrecorded.
        early = compile_stored(gaps, change_set=late, as_of=T + HOUR / 2)
        later = compile_stored(gaps[1:], change_set=late)

        self.assertEqual(
            [(code, location) for code, _, location in notes(early)],
            [
                ("change_gap_unmatched", "change-file CHG-Z host:lab-01"),
                ("change_gap_unmatched", "change-file CHG-A host:lab-02"),
                ("change_gap_unmatched", "change-file CHG-B host:lab-01"),
                ("change_gap_unmatched", "change-file CHG-B host:lab-02"),
            ],
        )
        self.assertEqual(
            [(code, location) for code, _, location in notes(later)],
            [
                ("change_gap_unrecorded", "change-file CHG-Z host:lab-01"),
                ("change_gap_unrecorded", "change-file CHG-C host:lab-01"),
            ],
        )

    def test_a_change_id_holding_a_colon_and_a_space_is_named_whole(self) -> None:
        change_id = "deploy:2026-09-01 web"
        change_set = changes_of(timed(change_id, pair("lab-01")))
        (gap,) = recorded(change_set)

        record_set = compile_stored([gap], [scan("lab-01", T + HOUR / 2)], change_set=change_set)
        unrecorded_set = compile_stored([], change_set=change_set)

        ((_, message, location),) = notes(record_set)
        self.assertIn(f"after change {change_id} that closed {CLOSED}", message)
        self.assertEqual(location, f"change-file {change_id} host:lab-01")
        ((_, message, location),) = notes(unrecorded_set)
        self.assertEqual(message, unrecorded("host:lab-01", change_id))
        self.assertEqual(location, f"change-file {change_id} host:lab-01")

    def test_a_gap_closed_after_a_past_as_of_is_not_filtered(self) -> None:
        # Call 13: a run at an as-of before the window closed derives no window, so the stored
        # gap reads unmatched, as a coverage gap does; filtering both is a cleanup item.
        (gap,) = recorded(LONE_SET)

        record_set = compile_stored([gap], change_set=LONE_SET, as_of=T + HOUR / 2)

        self.assertEqual([code for code, _, _ in notes(record_set)], ["change_gap_unmatched"])
        self.assertIn(gap.observation_id, record_set.records[0].observation_ids)

    def test_the_notes_name_no_calendar_zone(self) -> None:
        # Call 12: a change window closes at an instant, so no note points at the zone.
        lab_01, lab_02 = recorded()
        moved = inventory_of(host("lab-01"))
        for record_set in (
            compile_stored([lab_01]),
            compile_stored([lab_01, lab_02], [scan("lab-01", T)], inventory=moved),
        ):
            for _code, message, _location in notes(record_set):
                self.assertNotIn("zone", message)

    def test_a_record_set_that_is_not_aware_names_no_note(self) -> None:
        lab_01, _ = recorded()

        record_set = compile_record_set(
            artifacts=(),
            observations=(lab_01,),
            ingest_diagnostics=(),
            evaluations_by_tracking_id={},
            attestation=DetectionAttestation(),
            options=options(inventory=INVENTORY, as_of=AS_OF, detected_at=None),
            stored_changes=stored(CHANGE_SET),
        )

        self.assertEqual(notes(record_set), [])
        self.assertIsNone(record_set.change_gap_records)

    def test_a_gap_whose_change_the_set_lacks_is_named_without_a_file(self) -> None:
        # Unreachable from the store, whose reader refuses such a gap first (call 11); a library
        # caller gets the note without the file name rather than an exception.
        (orphan,) = recorded(changes_of(timed("CHG-9", pair("lab-01"))))

        record_set = compile_stored([orphan], change_set=LONE_SET)

        self.assertIn(
            ("change_gap_unmatched", "CHG-9 host:lab-01"),
            [(code, location) for code, _, location in notes(record_set)],
        )


# *--- Never Evidence ---*


class ChangeGapNeverEvidenceTests(unittest.TestCase):
    """A rehydrated gap satisfies no obligation of either kind (the task 2 properties)."""

    def test_a_gap_moves_neither_projection(self) -> None:
        gaps = recorded()
        evidence = (scan("lab-01", T - HOUR),)

        with_gaps = compile_stored(gaps, evidence)
        without = compile_stored((), evidence)

        assert with_gaps.changes is not None and without.changes is not None
        self.assertEqual(with_gaps.changes.obligations, without.changes.obligations)
        self.assertEqual(with_gaps.coverage, without.coverage)
        self.assertEqual(
            {row.status for row in with_gaps.changes.obligations}, {ObligationStatus.LAPSED}
        )


# *--- Store Path ---*


class ChangeGapStoreTests(PersistedStoreTestCase):
    """Awareness follows a `changegap/` stream; a store's report is the stateless run's."""

    def populate(self, *, cases_changes: str | None = TIMED_AS_OF) -> None:
        """Ingest the timed artifacts, record the timed changes, and record gaps if asked."""
        database = str(self.database)
        self.succeeds(["ingest", *TIMED_ARTIFACTS, "--db", database, "--as-of", TIMED_AS_OF])
        self.succeeds(
            ["changes", "record", "--db", database, "--changes", str(TIMED_CHANGES)]
            + ["--as-of", "2026-11-09T12:00:00Z"]
        )
        if cases_changes is not None:
            code, _out, err = run(
                ["cases", "changes", "--db", database, *CASES_CHANGES[:2], "--as-of", cases_changes]
                + ["--inventory", str(TIMED_INVENTORY)]
            )
            self.assertEqual(code, 3, msg=err)

    def outputs(self, stem: str, *extra: str, inventory: bool = True) -> tuple[str, str, str]:
        """Return one persisted VDT, its Markdown twin and its standard error."""
        json_path = self.workspace / f"{stem}.json"
        markdown_path = self.workspace / f"{stem}.md"
        argv = ["report", "vdt", "--db", str(self.database), *TIMED_REPORT, *extra]
        if inventory:
            argv += ["--inventory", str(TIMED_INVENTORY)]
        code, _, err = run([*argv, "-o", str(json_path), "--markdown", str(markdown_path)])
        self.assertEqual(code, 0, msg=err)
        return (
            json_path.read_text(encoding="utf-8"),
            markdown_path.read_text(encoding="utf-8"),
            err,
        )

    def rows(self, document: str) -> list[dict[str, Any]]:
        return json.loads(document)["x-complyroll"]["changes"]["obligations"]

    def test_the_store_replays_into_the_change_gap_golden_but_for_input(self) -> None:
        # The persisted report equals the stateless one as bytes, but for the block's `input`
        # and the Markdown intro line that ADR 0008's amendment already names.
        self.populate()

        stored_json, stored_markdown, err = self.outputs("aware")

        golden_json = (GOLDEN / "vdt-change-gaps.json").read_text(encoding="utf-8")
        golden_markdown = (GOLDEN / "vdt-change-gaps.md").read_text(encoding="utf-8")
        self.assertEqual(without_block_input(stored_json), without_block_input(golden_json))
        self.assertEqual(without_intro(stored_markdown), without_intro(golden_markdown))
        for code in NOTE_CODES:
            self.assertNotIn(code, err)

    def test_a_store_with_no_change_gap_stream_reads_as_before_the_gaps_existed(self) -> None:
        # Awareness needs a `changegap/` stream: none, and the report is the PR 2 store's bytes,
        # rows carry neither key and no note prints, even beside coverage streams.
        self.populate(cases_changes=None)
        code, _out, err = run(
            [
                "cases",
                "coverage",
                "--db",
                str(self.database),
                *CASES_CHANGES,
                "--calendar-tz",
                "UTC",
            ]
        )
        self.assertEqual(code, 3, msg=err)

        stored_json, stored_markdown, err = self.outputs("unaware")

        for row in self.rows(stored_json):
            self.assertFalse(ROW_KEYS & set(row))
        for code_name in NOTE_CODES:
            self.assertNotIn(code_name, err)
            self.assertNotIn(code_name, stored_json)
        self.assertNotIn(RECORDED_ROW_SENTENCE, stored_markdown)

    def test_a_store_with_no_change_gap_stream_keeps_the_timed_store_bytes(self) -> None:
        self.populate(cases_changes=None)

        stored_json, stored_markdown, _err = self.outputs("unaware")

        golden_json = (GOLDEN / "vdt-changes-timed.json").read_text(encoding="utf-8")
        golden_markdown = (GOLDEN / "vdt-changes-timed.md").read_text(encoding="utf-8")
        self.assertEqual(without_block_input(stored_json), without_block_input(golden_json))
        self.assertEqual(without_intro(stored_markdown), without_intro(golden_markdown))

    def test_a_window_recorded_by_no_run_is_named_and_reads_recorded_false(self) -> None:
        # `cases changes` ran before CHG-2003 occurred, so only CHG-2001's window is a record.
        self.populate(cases_changes="2026-08-25T00:00:00Z")

        stored_json, _markdown, err = self.outputs("partial")

        self.assertIn(
            "info: change_gap_unrecorded: "
            + unrecorded(RENDER, "CHG-2003", "2026-09-01T01:00:00Z")
            + " [timed-changes CHG-2003 file:src/ui/render.js]",
            err,
        )
        closed = {
            row["changeId"]: (row["recorded"], row["trackingId"])
            for row in self.rows(stored_json)
            if row["recorded"] is not None
        }
        self.assertEqual(closed, {"CHG-2001": (True, CLOSED_ROWS[0][3]), "CHG-2003": (False, None)})

    def test_the_repository_answers_whether_a_change_gap_stream_exists(self) -> None:
        self.populate(cases_changes=None)
        with SQLiteEventStore(self.database) as store:
            repository = EventRepository(store)
            # A change stream sorts before every `changegap/` id and is never one.
            self.assertTrue(store.holds_stream_with_prefix("change/"))
            self.assertFalse(repository.holds_change_gap_stream())
        code, _out, err = run(["cases", "changes", "--db", str(self.database), *CASES_CHANGES])
        self.assertEqual(code, 3, msg=err)
        with SQLiteEventStore(self.database) as store:
            self.assertTrue(EventRepository(store).holds_change_gap_stream())

    def test_without_an_inventory_the_gaps_are_records_and_there_is_no_block(self) -> None:
        self.populate()

        stored_json, _markdown, err = self.outputs("no-inventory", inventory=False)

        document = json.loads(stored_json)
        self.assertNotIn("changes", document["x-complyroll"])
        tracking = {item["providerTrackingId"] for item in document["vulnerabilities"]}
        self.assertLessEqual({row[3] for row in CLOSED_ROWS}, tracking)
        for code in NOTE_CODES:
            self.assertNotIn(code, err)

    def test_the_projection_is_the_same_before_and_after_gaps_are_recorded(self) -> None:
        # The task 2 properties on the store path: a rehydrated change or coverage gap verifies
        # nothing, so recording either moves no row.
        self.populate(cases_changes=None)
        before, coverage_before = self.derived(), self.coverage()
        self.assertEqual(
            run(["cases", "coverage", "--db", str(self.database), *CASES_CHANGES])[0], 3
        )
        self.assertEqual(
            run(["cases", "changes", "--db", str(self.database), *CASES_CHANGES])[0], 3
        )

        after = self.derived()

        self.assertEqual(after.obligations, before.obligations)
        self.assertEqual(after.summary, before.summary)
        self.assertEqual(self.coverage(), coverage_before)

    def coverage(self) -> Any:
        with SQLiteEventStore(self.database) as store:
            return records_module.derive_report_coverage(
                rehydrate_observations(EventRepository(store)),
                load_inventory(TIMED_INVENTORY),
                PROFILE,
                datetime(2026, 9, 3, 12, tzinfo=UTC),
            )

    def test_a_coverage_gap_inside_a_change_window_does_not_verify_it(self) -> None:
        # The image's PDD window closed 2026-08-19T10:00Z, inside CHG-2001's 10 to 20 August
        # window; recorded, its gap is a system record of the image there and verifies nothing.
        self.populate(cases_changes=None)
        self.assertEqual(
            run(["cases", "coverage", "--db", str(self.database), *CASES_CHANGES])[0], 3
        )
        with SQLiteEventStore(self.database) as store:
            gaps = [
                item
                for item in rehydrate_observations(EventRepository(store))
                if item.source_type == "complyroll.coverage"
                and item.resource.resource_id == IMAGE.removeprefix("image:")
                and item.observed_at == datetime(2026, 8, 19, 10, tzinfo=UTC)
            ]
        self.assertEqual(len(gaps), 1)

        (row,) = [
            item for item in self.derived().obligations if item.change.change_id == "CHG-2001"
        ]

        self.assertIs(row.status, ObligationStatus.LAPSED)
        self.assertIsNone(row.evidence)

    def derived(self) -> Any:
        with SQLiteEventStore(self.database) as store:
            repository = EventRepository(store)
            changes = read_stored_changes(repository)
            assert changes is not None
            return records_module.derive_report_changes(
                rehydrate_observations(repository),
                changes,
                load_inventory(TIMED_INVENTORY),
                PROFILE,
                datetime(2026, 9, 3, 12, tzinfo=UTC),
            )


if __name__ == "__main__":
    unittest.main()
