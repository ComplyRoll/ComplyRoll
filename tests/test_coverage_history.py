# ******************************************************************************
# *Title: Coverage History Tests*
# *Author: Kyle Versluis*
# *Description: Coverage gaps recorded into a store and reported back from it.*
# ******************************************************************************
"""Tests for the persisted coverage gap path: `cases coverage` and its reports (ADR 0015)."""

# *--- Imports ---*

from __future__ import annotations

import json
import sqlite3
import unittest
from collections.abc import Sequence
from contextlib import closing
from datetime import UTC, datetime
from pathlib import Path
from typing import Any
from unittest import mock

from test_cli import (
    EXAMPLE_INVENTORY,
    INGESTED_AT,
    PersistedStoreTestCase,
    help_text,
    run,
    stripped_policy,
)
from test_coverage import host
from test_coverage_gap_evaluations import (
    EXPECTED_SINCE,
    GAP_CLOSED_TEXT,
    GAP_EARLY_TEXT,
    GAP_EVALUATION,
    GAP_REMEDY,
)
from test_coverage_gap_report import (
    BACKUP_KEY,
    EARLY_AS_OF,
    GAP_WINDOWS,
    RECORDED_SENTENCE,
    VDT_GAP_ARGUMENTS,
    WINDOW_KEYS,
    diagnostics_of,
    gap_options,
    tracking_ids,
    windows_of,
    write_inventory,
)
from test_coverage_report import xccdf
from test_replay import StoreFixture, compile_from_history, compile_stateless
from test_reports import (
    ACCEPTED_EVALUATIONS,
    ARTIFACTS,
    AS_OF,
    EXAMPLES,
    GOLDEN,
    REPORT_KINDS,
    assert_markdown_carries_the_json,
    markdown_section,
    markdown_subsection,
    options,
)

from complyroll.adapters import ingest_stig_artifact
from complyroll.events import (
    COVERAGE_RECORDED,
    EventMetadata,
    EventRepository,
    case_stream_id,
    coverage_head_payload,
    coverage_stream_id_of,
)
from complyroll.history import (
    CASE_EVALUATED,
    CoverageOutcome,
    HistoryError,
    audit_history,
    fold_all_cases,
    record_coverage_gaps,
    record_ingest,
    rehydrate_observations,
)
from complyroll.history import writers as history_writers
from complyroll.models import CaseStatus, Observation, ObservationOrigin
from complyroll.reports import (
    CompiledReport,
    ReportCompileError,
    compile_record_set_from_history,
    load_inventory,
    parse_evaluations,
    parse_inventory,
)
from complyroll.reports import vdt as vdt_module
from complyroll.reports.coverage import CoverageEvidence, EvidenceKind
from complyroll.reports.gaps import (
    COVERAGE_GAP_RECORD_ID,
    COVERAGE_GAP_SOURCE_TYPE,
    coverage_gap_observations,
)
from complyroll.store import NewEvent, SQLiteEventStore
from complyroll.store import sqlite as sqlite_module

# *--- Fixtures ---*

#: The example inventory every golden store is measured against.
INVENTORY = load_inventory(EXAMPLE_INVENTORY)
#: Class C in UTC, the profile every golden run selects.
PROFILE = options().profile
#: The `cases coverage` run that records the nine example gaps, less its `--db`.
COVERAGE_OPTIONS = ("--class", "C", "--as-of", INGESTED_AT, "--inventory", str(EXAMPLE_INVENTORY))
#: A verifying scan of ubuntu-web-01 under its alias, inside its first MVX and PDD windows: the
#: late upload of divergence 2, ingested after the gaps were recorded.
LATE_AT = "2026-07-02T09:00:00Z"
#: An examining scan of the same host before it, which never verifies a clock.
EXAMINED_AT = "2026-07-01T12:00:00Z"
#: The two recorded gaps that late upload contradicts, as `GAP_WINDOWS` names them.
UBUNTU_MVX = GAP_WINDOWS[2]
UBUNTU_PDD = GAP_WINDOWS[6]
#: The sample group's second window, which closes between `EARLY_AS_OF` and the golden as-of.
SECOND_PSD = GAP_WINDOWS[8]
#: The group's first window, which shares the second's case.
FIRST_PSD = GAP_WINDOWS[7]
#: lab-win-01's MVX window, which shares its job's case with `UBUNTU_MVX`.
WIN_MVX = GAP_WINDOWS[1]
#: The one host of the lone-gap store: its Class C MVX window closes on 2026-08-04.
LONE_HOST = host("lab-gap-01", expectedSince=EXPECTED_SINCE)
LONE_KEY = "VDR-TFR-MVX:resource:host:lab-gap-01"
#: What a whole coverage run appends to the golden store: one head and one record per gap.
GAP_COUNT = len(GAP_WINDOWS)
#: The divergence codes: a window history has no gap for, then the two kinds of gap no
#: window of this run derives, disproved by evidence or not.
DIVERGENCE_CODES = (
    "coverage_gap_unrecorded",
    "coverage_gap_contradicted",
    "coverage_gap_unmatched",
)
#: How a contradicted note ends when nothing else holds its case open: a lone gap, or a case
#: whose every recorded gap is contradicted.
LONE_ADVICE = "and an evaluation can dispose it as a false positive"
CASE_ADVICE = (
    "and every other recorded gap of the case is contradicted too, so an evaluation can "
    "dispose the case as a false positive"
)


def gap_rows(gaps: Sequence[Observation]) -> list[tuple[str, str, str]]:
    """Return each gap as `GAP_WINDOWS` names a window: rule, resource and close."""
    return [
        (
            gap.context_key.split(":", 1)[0],
            f"{gap.resource.resource_type}:{gap.resource.resource_id}",
            gap_instant(gap),
        )
        for gap in gaps
    ]


def gap_instant(gap: Observation) -> str:
    assert gap.observed_at is not None
    return gap.observed_at.astimezone(UTC).isoformat().replace("+00:00", "Z")


def window_rows(report: CompiledReport) -> list[tuple[str, str, str, Any, Any]]:
    """Return each window of a report as rule, context, close, recorded and tracking id."""
    return [
        (
            window["ruleId"],
            window["contextKey"],
            window["closedAt"],
            window.get("recorded"),
            window.get("trackingId"),
        )
        for window in windows_of(report)
    ]


def stored_gaps(repository: EventRepository) -> list[Observation]:
    return [
        item
        for item in rehydrate_observations(repository)
        if item.source_type == COVERAGE_GAP_SOURCE_TYPE
    ]


def without_ingest_time(observation: Observation) -> dict[str, Any]:
    """Return an observation's canonical form less `ingested_at`, which reaches no output."""
    canonical = observation.to_canonical_dict()
    del canonical["ingested_at"]
    return canonical


def unrecorded_message(rule: str, label: str, closed: str) -> str:
    return (
        f"the {rule} window for {label} closed {closed} with no verification, and history "
        "records no gap for it, so no case in this report carries it; cases coverage with "
        "this run's inventory, as-of, class and calendar zone records it"
    )


def standing_gap(rule: str, label: str, closed: str, still_derived: bool) -> str:
    """Return one other gap of a case as a note names it, with why it holds the case open."""
    why = "still derives" if still_derived else "neither derives nor disproves"
    return f"the {rule} window for {label} that closed {closed}, which this run {why}"


def withheld(rule: str, label: str, closed: str, still_derived: bool) -> str:
    """Return how a contradicted note ends while one other gap of its case stands."""
    return (
        f"but the case also carries {standing_gap(rule, label, closed, still_derived)}, so it "
        "stays open until every other gap it carries is contradicted or disposed on its own "
        "merits"
    )


def contradicted_message(
    tracking_id: str,
    rule: str,
    label: str,
    closed: str,
    evidence: str,
    at: str,
    advice: str = LONE_ADVICE,
) -> str:
    return (
        f"{tracking_id} carries the recorded gap of the {rule} window for {label} that closed "
        f"{closed}, but {evidence} verified it at {at}, inside that window, so this run "
        f"derives no such window; the gap stays recorded, {advice}"
    )


def unmatched_message(
    tracking_id: str,
    rule: str,
    label: str,
    closed: str,
    standing: tuple[str, str, str, bool] | None = None,
) -> str:
    tail = "" if standing is None else f", and the case also carries {standing_gap(*standing)}"
    return (
        f"{tracking_id} carries the recorded gap of the {rule} window for {label} that closed "
        f"{closed}, and this run derives no such window and holds no verification inside it, "
        "so its inventory, as-of, class or calendar zone may differ from the run that "
        f"recorded the gap; the gap stays recorded{tail}"
    )


def edited_inventory(**changes: Any) -> Any:
    """Return the example inventory with its name or entries changed, so its digest moves."""
    document = json.loads(EXAMPLE_INVENTORY.read_text(encoding="utf-8"))
    for name, edit in changes.items():
        if name == "name":
            document["name"] = edit
            continue
        (entry,) = [item for item in document["resources"] if item["resourceId"] == name]
        entry.update(edit)
    return parse_inventory(json.dumps(document).encode("utf-8"))


def mark_schema_4_by_hand(database: Path) -> None:
    """Mark a store schema 4 with every migration record and no coverage stream at all."""
    applied_at = sqlite_module._format_timestamp(AS_OF, "applied_at")
    with closing(sqlite3.connect(database, isolation_level=None)) as connection:
        (current,) = connection.execute("PRAGMA user_version").fetchone()
        for version in range(int(current) + 1, 5):
            connection.execute(
                "INSERT INTO complyroll_schema_migrations (version, description, applied_at) "
                "VALUES (?, ?, ?)",
                (version, sqlite_module._MIGRATION_DESCRIPTIONS[version], applied_at),
            )
        connection.execute("PRAGMA user_version = 4")


class CoverageStoreFixture(StoreFixture):
    """The documented store, plus the coverage writer called as `cases coverage` calls it."""

    def golden_store(self, evaluations: Path | None = None) -> None:
        """Ingest, correlate, attest and evaluate exactly as the golden store is written."""
        self.ingest()
        self.correlate()
        self.attest()
        self.evaluate(evaluations)

    def record_gaps(
        self, inventory: Any = INVENTORY, *, as_of: datetime = AS_OF, profile: Any = PROFILE
    ) -> CoverageOutcome:
        return record_coverage_gaps(
            self.repository, inventory, profile=profile, as_of=as_of, metadata=self.metadata
        )

    def derived_gaps(self, as_of: datetime = AS_OF) -> tuple[Observation, ...]:
        """Return the gaps the store's evidence closes at as-of, before any is recorded."""
        coverage = vdt_module.derive_report_coverage(
            rehydrate_observations(self.repository), INVENTORY, PROFILE, as_of
        )
        return coverage_gap_observations(coverage, ingested_at=as_of)

    def ingest_text(self, name: str, text: str) -> None:
        """Ingest one crafted artifact after the gaps, as a late upload is."""
        path = self.workspace / name
        path.write_text(text, encoding="utf-8")
        record_ingest(
            self.repository,
            ingest_stig_artifact(path, ingested_at=AS_OF),
            metadata=self.metadata,
            ingested_at=AS_OF,
        )

    def smuggle(self, stream_id: str, *events: tuple[str, dict[str, Any]]) -> list[int]:
        """Append events to one stream past the repository, in order, and return them."""
        sequences = []
        for event_type, payload in events:
            (appended,) = self.store.append(
                stream_id,
                [
                    NewEvent(
                        event_type=event_type,
                        occurred_at=AS_OF,
                        payload=payload,
                        metadata=self.metadata.to_dict(),
                    )
                ],
                expected_version=self.store.current_stream_version(stream_id),
                requires_schema=4,
            )
            sequences.append(appended.sequence)
        return sequences


# *--- Writer ---*


class CoverageWriterTests(CoverageStoreFixture):
    """`record_coverage_gaps`: one whole stream per closed window, written once."""

    def test_each_closed_window_is_recorded_head_first_in_one_batch(self) -> None:
        self.golden_store()
        before = self.store.latest_sequence
        self.assertEqual(self.store.schema_version, 1)

        outcome = self.record_gaps()

        self.assertEqual(gap_rows(outcome.recorded), [row[:3] for row in GAP_WINDOWS])
        self.assertEqual(outcome.already_recorded, ())
        self.assertEqual(self.store.latest_sequence, before + 2 * GAP_COUNT)
        self.assertEqual(self.store.schema_version, 4)
        sequence = before
        for gap in outcome.recorded:
            with self.subTest(gap=gap.observation_id):
                head, record = self.repository.read_stream(coverage_stream_id_of(gap))
                self.assertEqual(
                    [
                        (head.event_type, head.stream_version),
                        (record.event_type, record.stream_version),
                    ],
                    [(COVERAGE_RECORDED, 1), ("observation.recorded", 2)],
                )
                # One batch per stream, written in window order.
                self.assertEqual((head.sequence, record.sequence), (sequence + 1, sequence + 2))
                self.assertEqual(head.payload, coverage_head_payload(gap))
                self.assertEqual(record.payload, gap.to_canonical_dict())
                self.assertEqual(gap.ingested_at, AS_OF)
                self.assertEqual({head.occurred_at, record.occurred_at}, {AS_OF})
                self.assertEqual(head.metadata["runId"], self.metadata.run_id)
                sequence = record.sequence
        self.assertEqual(audit_history(self.repository), ())

    def test_the_recorded_gaps_are_the_ones_the_store_derives(self) -> None:
        self.golden_store()
        expected = self.derived_gaps()

        outcome = self.record_gaps()

        self.assertEqual(outcome.recorded, expected)
        self.assertEqual(stored_gaps(self.repository), list(expected))
        self.assertEqual(len(outcome.coverage.windows), GAP_COUNT)

    def test_a_second_run_appends_nothing_and_names_every_gap_already_recorded(self) -> None:
        self.golden_store()
        first = self.record_gaps()
        latest = self.store.latest_sequence

        second = self.record_gaps()

        self.assertEqual(second.recorded, ())
        self.assertEqual(second.already_recorded, first.recorded)
        self.assertEqual(self.store.latest_sequence, latest)
        self.assertEqual(audit_history(self.repository), ())

    def test_the_first_recorded_payload_stands_against_an_edited_inventory(self) -> None:
        # The id names the gap, never the inventory digest, so a rebuild against an edited
        # inventory finds every stream recorded and keeps the digest first written.
        self.golden_store()
        self.record_gaps()
        latest = self.store.latest_sequence
        edited = edited_inventory(name="example-boundary-edited")
        self.assertNotEqual(edited.sha256, INVENTORY.sha256)

        outcome = self.record_gaps(edited)

        self.assertEqual(outcome.recorded, ())
        self.assertEqual(len(outcome.already_recorded), GAP_COUNT)
        self.assertEqual(self.store.latest_sequence, latest)
        for gap in outcome.already_recorded:
            head, record = self.repository.read_stream(coverage_stream_id_of(gap))
            self.assertEqual(dict(gap.source_metadata)["coverage.inventorySha256"], edited.sha256)
            self.assertEqual(head.payload["inventorySha256"], INVENTORY.sha256)
            self.assertEqual(
                record.payload["source_metadata"]["coverage.inventorySha256"], INVENTORY.sha256
            )

    def test_a_later_as_of_records_only_the_windows_closed_since(self) -> None:
        self.golden_store()
        early = self.record_gaps(as_of=EARLY_AS_OF)
        self.assertEqual(gap_rows(early.recorded), [row[:3] for row in GAP_WINDOWS[:-1]])

        late = self.record_gaps()

        self.assertEqual(gap_rows(late.recorded), [SECOND_PSD[:3]])
        # Each entry is this run's rebuild of a stored gap, under the id it was stored with.
        self.assertEqual(
            [gap.observation_id for gap in late.already_recorded],
            [gap.observation_id for gap in early.recorded],
        )
        ingested = {gap.observation_id: gap.ingested_at for gap in stored_gaps(self.repository)}
        self.assertEqual(
            [ingested[gap.observation_id] for gap in (*early.recorded, *late.recorded)],
            [EARLY_AS_OF] * (GAP_COUNT - 1) + [AS_OF],
        )

    def test_a_run_that_closes_no_window_records_nothing_and_leaves_the_schema(self) -> None:
        # A store that never records a gap stays readable by a build that predates them.
        self.golden_store()
        september = {"expectedSince": "2026-09-01T00:00:00Z"}
        later = edited_inventory(
            **{name: september for name in ("ubuntu-web-01", "lab-win-01")},
            **{"lab-rhel-01": {**september, "decommissionedAt": "2026-09-15T00:00:00Z"}},
            **{
                name: {**september, "verifications": []}
                for name in (
                    "incident-response-procedure",
                    "contingency-plan",
                    "backup-restore-procedure",
                )
            },
        )
        latest = self.store.latest_sequence

        outcome = self.record_gaps(later)

        self.assertEqual((outcome.recorded, outcome.already_recorded), ((), ()))
        self.assertEqual(outcome.coverage.windows, ())
        self.assertEqual(self.store.latest_sequence, latest)
        self.assertEqual(self.store.schema_version, 1)

    def test_a_gap_never_anchors_or_verifies_its_own_window(self) -> None:
        # A gap is an OPEN record of the entry observed at the window close; read as evidence
        # it would verify the window it reports and close it (ruling 4 of the step 2 note).
        self.golden_store()
        self.record_gaps()
        observations = rehydrate_observations(self.repository)
        artifacts = [item for item in observations if item.origin is ObservationOrigin.ARTIFACT]
        self.assertEqual(len(observations) - len(artifacts), GAP_COUNT)

        with_gaps = vdt_module.derive_report_coverage(observations, INVENTORY, PROFILE, AS_OF)
        without = vdt_module.derive_report_coverage(artifacts, INVENTORY, PROFILE, AS_OF)

        self.assertEqual(with_gaps, without)
        self.assertEqual(len(with_gaps.windows), GAP_COUNT)

    def test_a_stream_holding_only_another_event_is_refused_and_nothing_is_appended(self) -> None:
        self.golden_store()
        first = self.derived_gaps()[0]
        stream_id = coverage_stream_id_of(first)
        self.smuggle(stream_id, ("probe.planted", {}))
        latest = self.store.latest_sequence

        with self.assertRaises(HistoryError) as caught:
            self.record_gaps()

        self.assertEqual(
            str(caught.exception),
            f"coverage stream {stream_id!r} is incomplete: a coverage stream holds one coverage "
            "record and one observation, found 0 coverage record(s) and 0 observation(s); a "
            "coverage stream is written whole, so it is refused rather than resumed",
        )
        self.assertEqual(self.store.latest_sequence, latest)

    def test_a_whole_stream_holding_another_event_is_refused_and_nothing_is_appended(
        self,
    ) -> None:
        self.golden_store()
        first = self.derived_gaps()[0]
        stream_id = coverage_stream_id_of(first)
        self.smuggle(
            stream_id,
            (COVERAGE_RECORDED, coverage_head_payload(first)),
            ("observation.recorded", first.to_canonical_dict()),
            ("probe.planted", {}),
        )
        latest = self.store.latest_sequence

        with self.assertRaises(HistoryError) as caught:
            self.record_gaps()

        self.assertEqual(
            str(caught.exception),
            f"coverage stream {stream_id!r} holds an event no coverage stream carries; a "
            "coverage stream is written whole, so it is refused rather than resumed",
        )
        self.assertEqual(self.store.latest_sequence, latest)

    def test_a_half_written_stream_is_refused_by_the_fold_before_anything_is_appended(
        self,
    ) -> None:
        self.golden_store()
        first = self.derived_gaps()[0]
        stream_id = coverage_stream_id_of(first)
        self.smuggle(stream_id, (COVERAGE_RECORDED, coverage_head_payload(first)))
        latest = self.store.latest_sequence

        with self.assertRaises(HistoryError) as caught:
            self.record_gaps()

        self.assertEqual(
            str(caught.exception),
            f"coverage stream {stream_id!r} is incomplete: a coverage stream holds one coverage "
            "record and one observation, found 1 coverage record(s) and 0 observation(s)",
        )
        self.assertEqual(self.store.latest_sequence, latest)

    def test_one_run_records_every_gap_or_none(self) -> None:
        self.golden_store()
        latest = self.store.latest_sequence
        real = EventRepository.append_batch
        calls: list[str] = []

        def append_batch(repository: EventRepository, stream_id: str, *args: Any, **kw: Any) -> Any:
            calls.append(stream_id)
            if len(calls) == 3:
                raise HistoryError("simulated failure on the third gap")
            return real(repository, stream_id, *args, **kw)

        with (
            mock.patch.object(EventRepository, "append_batch", append_batch),
            self.assertRaises(HistoryError),
        ):
            self.record_gaps()

        # One batch per stream, head and record together, so the third call is the third gap.
        self.assertEqual(len(set(calls)), 3)
        self.assertEqual(self.store.latest_sequence, latest)
        self.assertEqual(self.store.schema_version, 1)
        self.assertEqual(stored_gaps(self.repository), [])

    def test_the_writer_refuses_an_instant_without_a_zone_and_a_foreign_inventory(self) -> None:
        with self.assertRaisesRegex(ValueError, "as_of must include a timezone"):
            self.record_gaps(as_of=datetime(2026, 8, 21, 12, 0))
        with self.assertRaisesRegex(TypeError, "inventory must be an Inventory"):
            self.record_gaps(object())
        self.assertEqual(self.store.latest_sequence, 0)

    def test_a_policy_without_a_coverage_rule_is_refused_and_nothing_is_appended(self) -> None:
        self.golden_store()
        latest = self.store.latest_sequence

        with (
            mock.patch.object(vdt_module, "select_policy", stripped_policy("VDR-TFR-PSD")),
            self.assertRaises(ReportCompileError) as caught,
        ):
            self.record_gaps()

        (diagnostic,) = caught.exception.diagnostics
        self.assertEqual(diagnostic.code, "coverage_rule_unavailable")
        self.assertEqual(self.store.latest_sequence, latest)


# *--- Command Line ---*


class CoverageCommandTests(PersistedStoreTestCase):
    """`cases coverage --db --inventory --as-of --class [--calendar-tz]`."""

    def coverage(self, *options: str, database: Path | None = None) -> tuple[int, str, str]:
        target = self.database if database is None else database
        return run(["cases", "coverage", "--db", str(target), *options])

    def test_recording_gaps_exits_3_and_names_each_gap(self) -> None:
        self.populate()

        code, out, err = self.coverage(*COVERAGE_OPTIONS, "--actor", "golden")

        self.assertEqual(code, 3, msg=err)
        lines = out.splitlines()
        self.assertEqual(
            lines[-1],
            f"recorded {GAP_COUNT} coverage gap(s), skipped 0 already-recorded coverage gap(s)",
        )
        gaps = stored_gaps_of(self.database)
        self.assertEqual(
            lines[:-1],
            [
                f"{gap.observation_id}: recorded {rule} window for {label} closed {closed}"
                for gap, (rule, label, closed) in zip(gaps, gap_rows(gaps), strict=True)
            ],
        )
        self.assertEqual(gap_rows(gaps), [row[:3] for row in GAP_WINDOWS])
        # The derivation's own note, as the report prints it for the same inventory entry.
        self.assertIn("warning: drift_likelihood_unknown: host:lab-rhel-01 declares", err)
        self.assertNotIn("error:", err)
        self.assertEqual(
            {record.metadata["actor"] for record in self.coverage_events()}, {"golden"}
        )

    def test_a_second_run_appends_nothing_exits_0_and_the_store_verifies(self) -> None:
        self.populate()
        self.assertEqual(self.coverage(*COVERAGE_OPTIONS)[0], 3)
        latest = self.latest_sequence()
        verified = self.succeeds(["store", "verify", "--db", str(self.database)])

        code, out, err = self.coverage(*COVERAGE_OPTIONS)

        self.assertEqual(code, 0, msg=err)
        lines = out.splitlines()
        self.assertEqual(
            lines[-1],
            f"recorded 0 coverage gap(s), skipped {GAP_COUNT} already-recorded coverage gap(s)",
        )
        self.assertEqual(len(lines), GAP_COUNT + 1)
        self.assertTrue(all(": already_recorded " in line for line in lines[:-1]))
        self.assertEqual(self.latest_sequence(), latest)
        self.assertEqual(self.succeeds(["store", "verify", "--db", str(self.database)]), verified)
        self.assertEqual(verified, (f"ok: {latest} event(s) verified\n", ""))

    def test_a_run_that_closes_no_window_exits_0(self) -> None:
        self.populate()
        latest = self.latest_sequence()
        inventory = write_inventory(
            self.workspace, host("lab-later-01", expectedSince="2026-09-01T00:00:00Z")
        )

        code, out, err = self.coverage(
            "--class", "C", "--as-of", INGESTED_AT, "--inventory", str(inventory)
        )

        self.assertEqual(
            (code, out, err),
            (0, "recorded 0 coverage gap(s), skipped 0 already-recorded coverage gap(s)\n", ""),
        )
        self.assertEqual(self.latest_sequence(), latest)

    def test_the_calendar_zone_reaches_the_derivation_as_the_report_reads_it(self) -> None:
        # Month clocks run in the named zone, so PCD lab-win-01's window moves with it.
        self.populate()
        zone = ("--calendar-tz", "America/Phoenix")

        code, _, err = self.coverage(*COVERAGE_OPTIONS, *zone)
        stateless_code, out, _ = run([*VDT_GAP_ARGUMENTS, *zone])

        self.assertEqual((code, stateless_code), (3, 3), msg=err)
        windows = json.loads(out)["x-complyroll"]["coverage"]["windows"]
        stored = gap_rows(stored_gaps_of(self.database))
        self.assertEqual(
            stored, [(item["ruleId"], item["contextKey"], item["closedAt"]) for item in windows]
        )
        self.assertNotEqual(stored, [row[:3] for row in GAP_WINDOWS])

    def refused(self, argv: Sequence[str], line: str) -> None:
        self.populate()
        latest = self.latest_sequence()

        code, out, err = self.coverage(*argv)

        self.assertEqual((code, out), (1, ""), msg=err)
        self.assertIn(line, err)
        self.assertEqual(self.latest_sequence(), latest)

    def test_a_run_without_an_inventory_is_refused(self) -> None:
        self.refused(
            ["--class", "C", "--as-of", INGESTED_AT],
            "error: invalid_option: cases coverage needs --inventory: a coverage gap is a "
            "window of an inventory entry's clock",
        )

    def test_a_second_inventory_is_refused(self) -> None:
        self.refused(
            [*COVERAGE_OPTIONS, "--inventory", str(EXAMPLE_INVENTORY)],
            "error: invalid_option: cases coverage takes one --inventory file, not 2",
        )

    def test_a_refused_inventory_file_is_refused_as_input(self) -> None:
        broken = self.workspace / "broken-inventory.json"
        broken.write_text("{", encoding="utf-8")
        self.refused(
            ["--class", "C", "--as-of", INGESTED_AT, "--inventory", str(broken)],
            "error: invalid_input: ",
        )

    def test_an_unreadable_as_of_is_refused_as_input(self) -> None:
        self.refused(
            ["--class", "C", "--as-of", "21 August", "--inventory", str(EXAMPLE_INVENTORY)],
            "error: invalid_input: --as-of must be an RFC 3339 timestamp, got '21 August'",
        )

    def test_an_unknown_calendar_zone_is_refused_as_an_option(self) -> None:
        self.refused([*COVERAGE_OPTIONS, "--calendar-tz", "Mars/Olympus"], "error: invalid_option:")

    def test_a_policy_without_a_coverage_rule_is_refused(self) -> None:
        with mock.patch.object(vdt_module, "select_policy", stripped_policy("VDR-TFR-MVX")):
            self.refused(COVERAGE_OPTIONS, "error: coverage_rule_unavailable:")

    def test_a_missing_store_is_refused_and_no_store_is_created(self) -> None:
        missing = self.workspace / "missing.db"

        code, out, err = self.coverage(*COVERAGE_OPTIONS, database=missing)

        self.assertEqual((code, out), (1, ""))
        self.assertIn(f"error: store_missing: no event store at {str(missing)!r}", err)
        self.assertFalse(missing.exists())

    def test_the_store_and_the_class_and_the_as_of_are_required_options(self) -> None:
        for dropped in ("--db", "--class", "--as-of"):
            with self.subTest(dropped=dropped):
                argv = ["cases", "coverage", "--db", "x.db", *COVERAGE_OPTIONS]
                index = argv.index(dropped)
                del argv[index : index + 2]

                with self.assertRaises(SystemExit) as caught:
                    run(argv)

                self.assertEqual(caught.exception.code, 2)

    def test_help_states_what_the_command_records(self) -> None:
        text = help_text(["cases", "coverage"])

        self.assertIn(
            "record each coverage window the store's evidence closed with no verification "
            "as a VDR-CSO-FAV system record; exits 3 when one is recorded",
            text,
        )
        self.assertIn("(read locally, never stored)", text)
        listing = help_text(["cases"])
        self.assertIn("coverage", listing)

    def test_an_older_build_refuses_the_store_cases_coverage_marked(self) -> None:
        self.populate()
        self.assertEqual(self.coverage(*COVERAGE_OPTIONS)[0], 3)

        with mock.patch.object(sqlite_module, "SUPPORTED_SCHEMA_VERSION", 3):
            code, out, err = run(["cases", "list", "--db", str(self.database)])

        self.assertEqual((code, out), (1, ""))
        self.assertIn("database schema 4 is newer than supported schema 3", err)

    def coverage_events(self) -> list[Any]:
        return [record for record in self.records() if record.stream_id.startswith("coverage/")]


def stored_gaps_of(database: Path) -> list[Observation]:
    with SQLiteEventStore(database) as store:
        return stored_gaps(EventRepository(store))


# *--- Gap-Aware Reports ---*


class GapAwareReportTests(CoverageStoreFixture):
    """A store marked schema 4 reports gap aware; one never marked reads as before."""

    def test_a_store_that_never_recorded_a_gap_carries_no_window_key(self) -> None:
        self.golden_store()

        report = self.replay(inventory=INVENTORY)

        self.assertEqual(self.store.schema_version, 1)
        for window in windows_of(report):
            self.assertFalse(WINDOW_KEYS & set(window))
        self.assertEqual(diagnostics_of(report, "coverage_gap_unrecorded"), [])

    def test_a_store_marked_4_by_hand_reads_gap_aware_with_every_window_unrecorded(
        self,
    ) -> None:
        self.golden_store()
        mark_schema_4_by_hand(self.database)
        self.assertEqual(self.store.schema_version, 4)
        self.assertEqual(audit_history(self.repository), ())

        report = self.replay(inventory=INVENTORY)

        self.assertEqual(
            window_rows(report),
            [(rule, label, closed, False, None) for rule, label, closed, _ in GAP_WINDOWS],
        )
        self.assertEqual(report.metadata.coverage_gaps, ())
        self.assertFalse({row[3] for row in GAP_WINDOWS} & tracking_ids(report))
        notes = diagnostics_of(report, "coverage_gap_unrecorded")
        self.assertEqual(
            [(item["level"], item["message"], item["location"]) for item in notes],
            [
                (
                    "info",
                    unrecorded_message(rule, label, closed),
                    f"example-boundary {label}",
                )
                for rule, label, closed, _ in GAP_WINDOWS
            ],
        )
        markdown = report.to_markdown()
        windows = markdown_subsection(markdown_section(markdown, "Coverage"), "Windows")
        self.assertIn(RECORDED_SENTENCE, windows)
        self.assertEqual(windows.count("| no | n/a |"), GAP_COUNT)
        diagnostics = markdown_section(markdown, "Diagnostics")
        for rule, label, closed, _ in GAP_WINDOWS:
            self.assertIn(
                f"- **info** coverage_gap_unrecorded: "
                f"{vdt_module._cell(unrecorded_message(rule, label, closed))} "
                f"[{vdt_module._cell(f'example-boundary {label}')}]",
                diagnostics,
            )
        assert_markdown_carries_the_json(self, report)

    def test_cases_coverage_makes_the_report_gap_aware_with_every_window_recorded(
        self,
    ) -> None:
        self.golden_store()
        self.record_gaps()
        self.correlate()

        report = self.replay(inventory=INVENTORY)

        self.assertEqual(
            window_rows(report),
            [(rule, label, closed, True, case) for rule, label, closed, case in GAP_WINDOWS],
        )
        self.assertEqual(
            report.metadata.coverage_gaps, tuple(sorted({row[3] for row in GAP_WINDOWS}))
        )
        for code in DIVERGENCE_CODES:
            self.assertEqual(diagnostics_of(report, code), [], code)

    def test_without_an_inventory_the_store_reports_its_gap_cases_and_no_coverage(
        self,
    ) -> None:
        self.golden_store()
        self.record_gaps()
        self.correlate()

        report = self.replay()

        self.assertNotIn("coverage", report.document["x-complyroll"])
        self.assertLessEqual({row[3] for row in GAP_WINDOWS}, tracking_ids(report))
        self.assertEqual(
            report.metadata.coverage_gaps, tuple(sorted({row[3] for row in GAP_WINDOWS}))
        )

    def test_a_report_from_history_still_refuses_the_stateless_flag(self) -> None:
        self.golden_store()
        self.record_gaps()

        with self.assertRaisesRegex(ValueError, "never records a coverage gap"):
            compile_from_history(self.repository, kind="vdt", options=gap_options())


# *--- Named Divergences ---*


class GapDivergenceTests(CoverageStoreFixture):
    """Divergences 1 and 2: an unrecorded window, and a gap no window derives, each named."""

    def test_a_window_not_yet_recorded_is_named_and_no_case_carries_it(self) -> None:
        self.golden_store()
        self.record_gaps(as_of=EARLY_AS_OF)
        self.correlate()

        report = self.replay(inventory=INVENTORY)

        rule, label, closed, case = SECOND_PSD
        expected = [(*row[:3], True, row[3]) for row in GAP_WINDOWS[:-1]]
        self.assertEqual(window_rows(report), [*expected, (rule, label, closed, False, None)])
        (note,) = diagnostics_of(report, "coverage_gap_unrecorded")
        self.assertEqual(
            (note["level"], note["message"], note["location"]),
            ("info", unrecorded_message(rule, label, closed), f"example-boundary {label}"),
        )
        for code in ("coverage_gap_contradicted", "coverage_gap_unmatched"):
            self.assertEqual(diagnostics_of(report, code), [], code)
        # The group's first window still carries its case; the second is in none.
        self.assertIn(case, tracking_ids(report))
        self.assertIn(
            f"coverage_gap_unrecorded: {vdt_module._cell(note['message'])}",
            markdown_section(report.to_markdown(), "Diagnostics"),
        )
        assert_markdown_carries_the_json(self, report)

    def test_recording_the_window_restores_the_stateless_bytes(self) -> None:
        self.golden_store()
        self.record_gaps(as_of=EARLY_AS_OF)
        self.record_gaps()
        self.correlate()

        report = self.replay(inventory=INVENTORY)

        self.assertEqual(
            report.to_json(), (GOLDEN / "vdt-coverage-gaps.json").read_text(encoding="utf-8")
        )

    def contradicted_store(self, *uploads: tuple[str, str]) -> CompiledReport:
        """Record the golden gaps, then ingest late uploads observed inside their windows."""
        self.golden_store()
        self.record_gaps()
        self.correlate()
        for name, text in uploads:
            self.ingest_text(name, text)
        self.correlate()
        return self.replay(inventory=INVENTORY)

    def late_observation_id(self, name: str) -> str:
        (observation,) = ingest_stig_artifact(self.workspace / name, ingested_at=AS_OF).observations
        return observation.observation_id

    def test_a_late_upload_inside_a_recorded_window_contradicts_its_gap(self) -> None:
        report = self.contradicted_store(
            ("late-upload.xml", xccdf("late-upload", "lab-ubuntu-01", LATE_AT, "pass"))
        )
        late = self.late_observation_id("late-upload.xml")

        rows = window_rows(report)
        for rule, label, closed, _ in (UBUNTU_MVX, UBUNTU_PDD):
            self.assertNotIn((rule, label, closed), [row[:3] for row in rows])
        # Both cases stay in the report: a missed window is a permanent fact.
        self.assertLessEqual({UBUNTU_MVX[3], UBUNTU_PDD[3]}, tracking_ids(report))
        self.assertLessEqual({UBUNTU_MVX[3], UBUNTU_PDD[3]}, set(report.metadata.coverage_gaps))
        notes = diagnostics_of(report, "coverage_gap_contradicted")
        # The MVX case also carries lab-win-01's window, which still stands, so only the PDD
        # note advises a disposition.
        self.assertEqual(
            [(item["level"], item["message"], item["location"]) for item in notes],
            [
                (
                    "info",
                    contradicted_message(
                        case,
                        rule,
                        label,
                        closed,
                        f"observation {late} on host:lab-ubuntu-01",
                        LATE_AT,
                        advice,
                    ),
                    COVERAGE_GAP_RECORD_ID,
                )
                for (rule, label, closed, case), advice in (
                    (UBUNTU_MVX, withheld(*WIN_MVX[:3], True)),
                    (UBUNTU_PDD, LONE_ADVICE),
                )
            ],
        )
        # The late scan anchors the host's clocks again, so each closes one new window that
        # no recorded gap carries: divergence 1 beside divergence 2.
        reopened = [row for row in rows if row[1] == "host:ubuntu-web-01"]
        self.assertEqual(
            [(row[0], row[3], row[4]) for row in reopened],
            [("VDR-TFR-MVX", False, None), ("VDR-TFR-PDD", False, None)],
        )
        for window in windows_of(report):
            if window["contextKey"] == "host:ubuntu-web-01":
                self.assertEqual((window["anchor"], window["anchorAt"]), ("verification", LATE_AT))
        self.assertEqual(len(diagnostics_of(report, "coverage_gap_unrecorded")), 2)
        # Evidence disproves both gaps, so neither is an input mismatch.
        self.assertEqual(diagnostics_of(report, "coverage_gap_unmatched"), [])
        diagnostics = markdown_section(report.to_markdown(), "Diagnostics")
        for item in notes:
            self.assertIn(
                f"- **info** coverage_gap_contradicted: {vdt_module._cell(item['message'])} "
                f"[{COVERAGE_GAP_RECORD_ID}]",
                diagnostics,
            )
        assert_markdown_carries_the_json(self, report)

    def test_the_earliest_verification_inside_the_window_is_named(self) -> None:
        # The examining scan is earlier but verifies nothing, and a later pass is not first.
        report = self.contradicted_store(
            ("examined.xml", xccdf("examined", "lab-ubuntu-01", EXAMINED_AT, "error")),
            ("late-upload.xml", xccdf("late-upload", "lab-ubuntu-01", LATE_AT, "pass")),
            ("later.xml", xccdf("later", "ubuntu-web-01", "2026-07-03T09:00:00Z", "pass")),
        )
        late = self.late_observation_id("late-upload.xml")

        messages = [item["message"] for item in diagnostics_of(report, "coverage_gap_contradicted")]

        self.assertEqual(len(messages), 2)
        for message in messages:
            self.assertIn(
                f"but observation {late} on host:lab-ubuntu-01 verified it at {LATE_AT},", message
            )

    def test_a_verification_at_the_close_contradicts_its_gap(self) -> None:
        # The window is (anchorAt, closedAt]: a verification at the close resumes the clock
        # on time, so the window never lapsed.
        rule, label, closed, case = UBUNTU_MVX
        report = self.contradicted_store(
            ("at-close.xml", xccdf("at-close", "ubuntu-web-01", closed, "pass")),
        )
        at_close = self.late_observation_id("at-close.xml")

        notes = diagnostics_of(report, "coverage_gap_contradicted")
        self.assertEqual(
            [item["message"] for item in notes],
            [
                contradicted_message(
                    case,
                    rule,
                    label,
                    closed,
                    f"observation {at_close} on {label}",
                    closed,
                    withheld(*WIN_MVX[:3], True),
                ),
                contradicted_message(
                    UBUNTU_PDD[3],
                    UBUNTU_PDD[0],
                    label,
                    UBUNTU_PDD[2],
                    f"observation {at_close} on {label}",
                    closed,
                ),
            ],
        )

    def test_an_attestation_inside_a_window_contradicts_its_gap(self) -> None:
        # An operator attestation verifies a non-machine entry, and any member a sample group.
        # RT-2026-04 is the backup window's anchor, outside (anchorAt, closedAt], so the
        # June test is the one named.
        self.golden_store()
        self.record_gaps()
        self.correlate()
        attested = edited_inventory(
            **{
                "backup-restore-procedure": {
                    "verifications": [
                        {"at": "2026-04-15T16:00:00Z", "reference": "Restore test RT-2026-04"},
                        {"at": "2026-06-01T12:00:00Z", "reference": "Restore test RT-2026-06"},
                    ]
                },
                "contingency-plan": {
                    "verifications": [
                        {"at": "2026-07-02T12:00:00Z", "reference": "Plan review PR-2026-07"}
                    ]
                },
            }
        )

        report = self.replay(inventory=attested)

        backup = next(row for row in GAP_WINDOWS if row[0] == "VDR-TFR-NMV")
        first_psd = GAP_WINDOWS[7]
        # The group's second window shares the first's case and still stands.
        self.assertEqual(
            [item["message"] for item in diagnostics_of(report, "coverage_gap_contradicted")],
            [
                contradicted_message(
                    backup[3],
                    backup[0],
                    backup[1],
                    backup[2],
                    "attestation Restore test RT-2026-06 on logical:backup-restore-procedure",
                    "2026-06-01T12:00:00Z",
                ),
                contradicted_message(
                    first_psd[3],
                    first_psd[0],
                    first_psd[1],
                    first_psd[2],
                    "attestation Plan review PR-2026-07 on logical:contingency-plan",
                    "2026-07-02T12:00:00Z",
                    withheld(*SECOND_PSD[:3], True),
                ),
            ],
        )

    def test_a_recorded_gap_no_evidence_disproves_is_unmatched_not_contradicted(
        self,
    ) -> None:
        self.golden_store()
        self.record_gaps()
        self.correlate()

        # A member's attestation inside the window but after this run's as-of is evidence the
        # derivation does not use, so it is not named either.
        later = edited_inventory(
            **{
                "contingency-plan": {
                    "verifications": [
                        {"at": "2026-08-06T09:00:00Z", "reference": "Plan review PR-2026-08"}
                    ]
                }
            }
        )
        rule, label, closed, case = SECOND_PSD
        for inventory in (INVENTORY, later):
            with self.subTest(inventory=inventory.sha256):
                report = self.replay(inventory=inventory, as_of=EARLY_AS_OF)

                (note,) = diagnostics_of(report, "coverage_gap_unmatched")
                self.assertEqual(
                    (note["level"], note["message"], note["location"]),
                    (
                        "info",
                        unmatched_message(case, rule, label, closed, (*FIRST_PSD[:3], True)),
                        COVERAGE_GAP_RECORD_ID,
                    ),
                )
                for code in ("coverage_gap_contradicted", "coverage_gap_unrecorded"):
                    self.assertEqual(diagnostics_of(report, code), [], code)
                # The case stays in the report: nothing disproves the gap.
                self.assertIn(case, tracking_ids(report))
                self.assertIn(
                    f"- **info** coverage_gap_unmatched: {vdt_module._cell(note['message'])} "
                    f"[{COVERAGE_GAP_RECORD_ID}]",
                    markdown_section(report.to_markdown(), "Diagnostics"),
                )
                assert_markdown_carries_the_json(self, report)

    def test_each_underived_gap_takes_its_own_code_in_window_order(self) -> None:
        # At the early as-of the June restore test disproves the backup gap and the July plan
        # review the group's first, while nothing inside the group's second window disproves
        # it: the code is decided per gap, never per report. The unmatched second holds the
        # shared case open, so the first note names it and advises no disposition, while the
        # second names no other gap, as the first is contradicted.
        self.golden_store()
        self.record_gaps()
        self.correlate()
        attested = edited_inventory(
            **{
                "backup-restore-procedure": {
                    "verifications": [
                        {"at": "2026-06-01T12:00:00Z", "reference": "Restore test RT-2026-06"}
                    ]
                },
                "contingency-plan": {
                    "verifications": [
                        {"at": "2026-07-02T12:00:00Z", "reference": "Plan review PR-2026-07"}
                    ]
                },
            }
        )

        report = self.replay(inventory=attested, as_of=EARLY_AS_OF)

        backup = next(row for row in GAP_WINDOWS if row[0] == "VDR-TFR-NMV")
        first_psd = GAP_WINDOWS[7]
        rule, label, closed, case = SECOND_PSD
        notes = [
            (item["code"], item["message"])
            for item in report.document["x-complyroll"]["diagnostics"]
            if item["code"] in DIVERGENCE_CODES[1:]
        ]
        self.assertEqual(
            notes,
            [
                (
                    "coverage_gap_contradicted",
                    contradicted_message(
                        backup[3],
                        backup[0],
                        backup[1],
                        backup[2],
                        "attestation Restore test RT-2026-06 on logical:backup-restore-procedure",
                        "2026-06-01T12:00:00Z",
                    ),
                ),
                (
                    "coverage_gap_contradicted",
                    contradicted_message(
                        first_psd[3],
                        first_psd[0],
                        first_psd[1],
                        first_psd[2],
                        "attestation Plan review PR-2026-07 on logical:contingency-plan",
                        "2026-07-02T12:00:00Z",
                        withheld(*SECOND_PSD[:3], False),
                    ),
                ),
                ("coverage_gap_unmatched", unmatched_message(case, rule, label, closed)),
            ],
        )
        self.assertLessEqual({backup[3], first_psd[3], case}, tracking_ids(report))
        diagnostics = markdown_section(report.to_markdown(), "Diagnostics")
        for code, message in notes:
            self.assertIn(
                f"- **info** {code}: {vdt_module._cell(message)} [{COVERAGE_GAP_RECORD_ID}]",
                diagnostics,
            )
        assert_markdown_carries_the_json(self, report)

    def notes_of_case(self, report: CompiledReport, code: str, case: str) -> list[str]:
        return [
            item["message"]
            for item in diagnostics_of(report, code)
            if item["message"].startswith(f"{case} ")
        ]

    def test_a_contradicted_member_of_a_job_case_names_the_window_still_recorded(self) -> None:
        # One case carries both jobbed MVX windows. The late upload disproves only
        # ubuntu-web-01's, and a disposition answers the whole case, so it would also close
        # lab-win-01's window, which this run still derives: the note names it instead.
        report = self.contradicted_store(
            ("late-upload.xml", xccdf("late-upload", "lab-ubuntu-01", LATE_AT, "pass"))
        )
        late = self.late_observation_id("late-upload.xml")
        rule, label, closed, case = UBUNTU_MVX

        self.assertEqual(WIN_MVX[3], case)
        self.assertIn((*WIN_MVX[:3], True, case), window_rows(report))
        (message,) = self.notes_of_case(report, "coverage_gap_contradicted", case)
        self.assertEqual(
            message,
            contradicted_message(
                case,
                rule,
                label,
                closed,
                f"observation {late} on host:lab-ubuntu-01",
                LATE_AT,
                withheld(*WIN_MVX[:3], True),
            ),
        )
        self.assertNotIn("false positive", message)
        self.assertIn(case, tracking_ids(report))
        self.assertIn(
            f"- **info** coverage_gap_contradicted: {vdt_module._cell(message)} "
            f"[{COVERAGE_GAP_RECORD_ID}]",
            markdown_section(report.to_markdown(), "Diagnostics"),
        )
        assert_markdown_carries_the_json(self, report)

    def test_a_sample_group_case_advises_a_disposition_once_both_windows_are_disproved(
        self,
    ) -> None:
        # Both sample-group windows are one case. The July review disproves the first, while
        # the second, anchored at the August tabletop, stands until a review lies inside it.
        self.golden_store()
        self.record_gaps()
        self.correlate()
        case = FIRST_PSD[3]
        july = {"at": "2026-07-02T12:00:00Z", "reference": "Plan review PR-2026-07"}
        august = {"at": "2026-08-05T09:00:00Z", "reference": "Plan review PR-2026-08"}

        def disproved(window: tuple[str, str, str, str], review: dict[str, str], end: str) -> str:
            return contradicted_message(
                case,
                *window[:3],
                f"attestation {review['reference']} on logical:contingency-plan",
                review["at"],
                end,
            )

        runs = (
            ([july], [disproved(FIRST_PSD, july, withheld(*SECOND_PSD[:3], True))], True),
            (
                [july, august],
                [
                    disproved(FIRST_PSD, july, CASE_ADVICE),
                    disproved(SECOND_PSD, august, CASE_ADVICE),
                ],
                False,
            ),
        )
        for reviews, expected, second_stands in runs:
            with self.subTest(reviews=len(reviews)):
                report = self.replay(
                    inventory=edited_inventory(**{"contingency-plan": {"verifications": reviews}})
                )

                messages = self.notes_of_case(report, "coverage_gap_contradicted", case)
                self.assertEqual(messages, expected)
                self.assertEqual(diagnostics_of(report, "coverage_gap_unmatched"), [])
                self.assertEqual(
                    (*SECOND_PSD[:3], True, case) in window_rows(report), second_stands
                )
                self.assertIn(case, tracking_ids(report))
                diagnostics = markdown_section(report.to_markdown(), "Diagnostics")
                for message in messages:
                    self.assertIn(
                        f"- **info** coverage_gap_contradicted: {vdt_module._cell(message)} "
                        f"[{COVERAGE_GAP_RECORD_ID}]",
                        diagnostics,
                    )
                assert_markdown_carries_the_json(self, report)

    def test_a_job_case_whose_every_gap_is_disproved_advises_a_disposition(self) -> None:
        # Late uploads of both jobbed hosts disprove both MVX windows of the case, so each
        # note advises disposing the case; lab-win-01's lone PCD gap keeps the lone advice.
        report = self.contradicted_store(
            ("late-upload.xml", xccdf("late-upload", "lab-ubuntu-01", LATE_AT, "pass")),
            ("late-win.xml", xccdf("late-win", "lab-win-01", LATE_AT, "pass")),
        )
        ubuntu = self.late_observation_id("late-upload.xml")
        win = self.late_observation_id("late-win.xml")
        case = UBUNTU_MVX[3]
        pcd = GAP_WINDOWS[4]

        self.assertEqual(
            self.notes_of_case(report, "coverage_gap_contradicted", case),
            [
                contradicted_message(
                    case,
                    *WIN_MVX[:3],
                    f"observation {win} on host:lab-win-01",
                    LATE_AT,
                    CASE_ADVICE,
                ),
                contradicted_message(
                    case,
                    *UBUNTU_MVX[:3],
                    f"observation {ubuntu} on host:lab-ubuntu-01",
                    LATE_AT,
                    CASE_ADVICE,
                ),
            ],
        )
        self.assertEqual(
            self.notes_of_case(report, "coverage_gap_contradicted", pcd[3]),
            [
                contradicted_message(
                    pcd[3], *pcd[:3], f"observation {win} on host:lab-win-01", LATE_AT
                )
            ],
        )
        derived = [row[:3] for row in window_rows(report)]
        for window in (WIN_MVX, UBUNTU_MVX):
            self.assertNotIn(window[:3], derived)
        self.assertIn(case, tracking_ids(report))
        assert_markdown_carries_the_json(self, report)

    def test_a_note_names_every_gap_that_holds_its_case_open(self) -> None:
        # The example cases hold two windows each, so a job of more hosts is built here from
        # the three recorded MVX gaps: each standing gap is named in turn with why it stands.
        self.golden_store()
        self.record_gaps()
        first, second, third = sorted(
            (
                gap
                for gap in stored_gaps(self.repository)
                if gap.context_key.startswith("VDR-TFR-MVX:")
            ),
            key=vdt_module._gap_order,
        )
        assert first.observed_at is not None
        evidence = CoverageEvidence(
            kind=EvidenceKind.ATTESTATION,
            resource=first.resource,
            at=first.observed_at,
            reference="Review R-1",
        )
        standing = [(second, True), (third, False)]
        named = (
            "the case also carries the VDR-TFR-MVX window for host:lab-win-01 that closed "
            "2026-07-04T00:00:00Z, which this run still derives, and the VDR-TFR-MVX window "
            "for host:ubuntu-web-01 that closed 2026-07-04T00:00:00Z, which this run neither "
            "derives nor disproves"
        )

        contradicted = vdt_module._underived_gap(
            first, "case-job", evidence, standing=standing, shared=True
        )
        unmatched = vdt_module._underived_gap(
            first, "case-job", None, standing=standing, shared=True
        )

        self.assertEqual(contradicted.code, "coverage_gap_contradicted")
        self.assertTrue(
            contradicted.message.endswith(
                f"the gap stays recorded, but {named}, so it stays open until every other gap "
                "it carries is contradicted or disposed on its own merits"
            ),
            contradicted.message,
        )
        self.assertEqual(unmatched.code, "coverage_gap_unmatched")
        self.assertTrue(
            unmatched.message.endswith(f"the gap stays recorded, and {named}"), unmatched.message
        )

    def test_a_contradicted_gap_closes_once_an_evaluation_disposes_it(self) -> None:
        self.contradicted_store(
            ("late-upload.xml", xccdf("late-upload", "lab-ubuntu-01", LATE_AT, "pass"))
        )
        case = UBUNTU_PDD[3]
        path = self.write_evaluations(
            [
                {
                    "match": {
                        "sourceRecordId": COVERAGE_GAP_RECORD_ID,
                        "sourceType": COVERAGE_GAP_SOURCE_TYPE,
                        # ubuntu-web-01 names a job, so its gap is keyed on the job.
                        "contextKey": "VDR-TFR-PDD:job:weekly-stig-checklist",
                    },
                    **{key: value for key, value in GAP_EVALUATION.items() if key != "disposition"},
                    "completedAt": "2026-08-10T00:00:00Z",
                    "isFalsePositive": True,
                }
            ]
        )

        self.evaluate(path)
        record_set = compile_record_set_from_history(
            self.repository, options=options(inventory=INVENTORY)
        )

        (state,) = [item for item in fold_all_cases(self.repository) if item.tracking_id == case]
        self.assertIsNotNone(state.current_evaluation)
        (record,) = [item for item in record_set.records if item.tracking_id == case]
        self.assertIs(record.status, CaseStatus.FALSE_POSITIVE)
        contradicted = [
            item for item in record_set.diagnostics if item.code == "coverage_gap_contradicted"
        ]
        self.assertEqual(len(contradicted), 2)


# *--- Replay ---*


class GapReplayTests(CoverageStoreFixture):
    """ADR 0008 Decision 5 extended: a store that ran `cases coverage` replays the gap run."""

    def test_the_store_replays_into_the_vdt_gap_golden(self) -> None:
        self.golden_store()
        self.record_gaps()
        self.correlate()

        replayed = self.replay(inventory=INVENTORY)

        self.assertEqual(
            replayed.to_json(), (GOLDEN / "vdt-coverage-gaps.json").read_text(encoding="utf-8")
        )
        self.assertEqual(
            replayed.to_markdown(), (GOLDEN / "vdt-coverage-gaps.md").read_text(encoding="utf-8")
        )

    def test_the_store_replays_into_the_historical_gap_golden(self) -> None:
        self.golden_store(ACCEPTED_EVALUATIONS)
        self.record_gaps()
        self.correlate()

        replayed = self.replay(
            kind="historical", inventory=INVENTORY, period_from=None, period_to=None
        )

        self.assertEqual(
            replayed.to_json(),
            (GOLDEN / "historical-coverage-gaps.json").read_text(encoding="utf-8"),
        )
        self.assertEqual(
            replayed.to_markdown(),
            (GOLDEN / "historical-coverage-gaps.md").read_text(encoding="utf-8"),
        )

    def test_the_two_paths_agree_on_every_projection(self) -> None:
        self.golden_store(ACCEPTED_EVALUATIONS)
        self.record_gaps()
        self.correlate()
        for kind in REPORT_KINDS:
            with self.subTest(report=kind):
                period = {"period_from": None, "period_to": None} if kind == "historical" else {}
                replayed = self.replay(kind=kind, inventory=INVENTORY, **period)
                stateless = compile_stateless(
                    ARTIFACTS, ACCEPTED_EVALUATIONS, kind=kind, options=gap_options(**period)
                )

                self.assertEqual(replayed.to_json(), stateless.to_json())
                self.assertEqual(replayed.to_markdown(), stateless.to_markdown())

    def test_the_stored_gaps_are_the_stateless_gaps_but_for_their_ingest_time(self) -> None:
        # The store's gaps were ingested at the `cases coverage` as-of and the stateless ones
        # at the report's, which reaches neither the output nor the id (step 3 finding 3).
        later = datetime(2026, 8, 25, 12, 0, tzinfo=UTC)
        self.golden_store()
        self.record_gaps()
        self.correlate()
        stateless = vdt_module.compile_record_set_from_artifacts(
            list(ARTIFACTS), options=gap_options(as_of=later)
        )
        assert stateless.coverage is not None
        # Built as the stateless front half builds them: at the run's own as-of.
        from_artifacts = coverage_gap_observations(stateless.coverage, ingested_at=later)
        stored = stored_gaps(self.repository)

        self.assertEqual(len(stored), GAP_COUNT)
        self.assertNotEqual(stored, list(from_artifacts))
        self.assertEqual(
            sorted((without_ingest_time(item) for item in stored), key=json.dumps),
            sorted((without_ingest_time(item) for item in from_artifacts), key=json.dumps),
        )
        self.assertEqual({item.ingested_at for item in stored}, {AS_OF})
        self.assertEqual({item.ingested_at for item in from_artifacts}, {later})
        replayed = self.replay(inventory=INVENTORY, as_of=later)
        bare = compile_stateless(
            ARTIFACTS, EXAMPLES / "evaluations.json", kind="vdt", options=gap_options(as_of=later)
        )
        self.assertEqual(replayed.to_json(), bare.to_json())
        self.assertEqual(replayed.to_markdown(), bare.to_markdown())


class GapReplayCommandTests(PersistedStoreTestCase):
    """The documented commands, `cases coverage` included, cut both gap goldens from a store."""

    def report_files(self, kind: str) -> tuple[bytes, bytes]:
        output = self.workspace / f"{kind}.json"
        markdown = self.workspace / f"{kind}.md"
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
            "--inventory",
            str(EXAMPLE_INVENTORY),
            "-o",
            str(output),
            "--markdown",
            str(markdown),
        ]
        if kind != "historical":
            argv += ["--from", "2026-08-01T00:00:00Z", "--to", "2026-08-31T23:59:59Z"]
        self.succeeds(argv)
        return output.read_bytes(), markdown.read_bytes()

    def record_and_correlate(self) -> None:
        code, _, err = run(["cases", "coverage", "--db", str(self.database), *COVERAGE_OPTIONS])
        self.assertEqual(code, 3, msg=err)
        self.correlate()

    def test_the_documented_sequence_reproduces_both_gap_goldens(self) -> None:
        for kind, golden, evaluations in (
            ("vdt", "vdt-coverage-gaps", None),
            ("historical", "historical-coverage-gaps", ACCEPTED_EVALUATIONS),
        ):
            with self.subTest(report=kind):
                self.database = self.workspace / f"{kind}-history.db"
                self.populate(evaluations)
                self.record_and_correlate()

                written = self.report_files(kind)

                self.assertEqual(written[0], (GOLDEN / f"{golden}.json").read_bytes())
                self.assertEqual(written[1], (GOLDEN / f"{golden}.md").read_bytes())


# *--- Persisted Evaluations ---*


class PersistedGapEvaluationCommandTests(PersistedStoreTestCase):
    """The persisted twin of the step 2 matcher tests, on a store `cases coverage` wrote.

    One host is expected from 1 August, so its Class C MVX window closes on 4 August and
    the store holds exactly one gap case, which only the full triple selects.
    """

    def setUp(self) -> None:
        super().setUp()
        self.populate()
        self.inventory = write_inventory(self.workspace, LONE_HOST)
        code, _, err = run(
            [
                "cases",
                "coverage",
                "--db",
                str(self.database),
                "--class",
                "C",
                "--as-of",
                INGESTED_AT,
                "--inventory",
                str(self.inventory),
            ]
        )
        self.assertEqual(code, 3, msg=err)
        self.correlate()
        (self.case,) = [
            case for case in self.cases() if case.source_type == COVERAGE_GAP_SOURCE_TYPE
        ]
        self.assertEqual(self.case.context_key, LONE_KEY)

    def cases(self) -> tuple[Any, ...]:
        with SQLiteEventStore(self.database) as store:
            return fold_all_cases(EventRepository(store))

    def evaluations(self, match: dict[str, str], **overrides: object) -> tuple[Path, str]:
        entry = {"match": match, **GAP_EVALUATION, **overrides}
        content = json.dumps({"evaluations": [entry]})
        path = self.workspace / "gap-evaluations.json"
        path.write_text(content, encoding="utf-8")
        return path, content

    def triple(self) -> dict[str, str]:
        return {
            "sourceRecordId": COVERAGE_GAP_RECORD_ID,
            "sourceType": COVERAGE_GAP_SOURCE_TYPE,
            "contextKey": LONE_KEY,
        }

    def evaluate_with(self, path: Path) -> tuple[int, str, str]:
        return run(["cases", "evaluate", "--db", str(self.database), "--evaluations", str(path)])

    def test_the_triple_records_the_evaluation_and_the_disposition_closes_the_case(
        self,
    ) -> None:
        path, _ = self.evaluations(self.triple())

        code, out, err = self.evaluate_with(path)

        self.assertEqual((code, err), (0, ""))
        self.assertIn("evaluations: 1 appended, 0 skipped", out)
        self.assertIn("dispositions: 1 appended, 0 skipped", out)
        (case,) = [item for item in self.cases() if item.tracking_id == self.case.tracking_id]
        assert case.disposition is not None
        self.assertIs(case.disposition.status, CaseStatus.REMEDIATED)
        self.assertEqual(case.evaluation_count, 1)
        types = [
            record.event_type
            for record in self.records()
            if record.stream_id == case_stream_id(case.tracking_id)
        ]
        self.assertEqual(types[-2:], ["case.evaluated", "case.disposition_recorded"])
        code, report, err = run(
            [
                "report",
                "vdt",
                "--db",
                str(self.database),
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
                "--inventory",
                str(self.inventory),
            ]
        )
        self.assertEqual(code, 0, msg=err)
        (record,) = [
            item
            for item in json.loads(report)["vulnerabilities"]
            if item["providerTrackingId"] == case.tracking_id
        ]
        self.assertEqual(record["finalDisposition"], "Remediated")
        self.assertEqual(record["detection"]["detectedAt"], GAP_CLOSED_TEXT)
        self.assertEqual(record["x-complyroll"]["detectedAtSource"], "system")

    def test_the_lone_gap_case_without_its_context_key_is_refused_as_a_coverage_gap(
        self,
    ) -> None:
        latest = self.latest_sequence()
        for label, keys in (
            ("with sourceType", ("sourceRecordId", "sourceType")),
            ("without sourceType", ("sourceRecordId",)),
        ):
            with self.subTest(label):
                match = {key: value for key, value in self.triple().items() if key in keys}
                path, content = self.evaluations(match)
                (entry,) = parse_evaluations(content.encode("utf-8")).entries
                described = entry.match.describe()

                code, out, err = self.evaluate_with(path)

                self.assertEqual((code, out), (1, ""))
                self.assertEqual(
                    err,
                    "error: evaluation_unmatched: evaluations could not be applied: "
                    f"evaluations[0]: {described} matches the coverage gap "
                    f"{self.case.tracking_id}; a coverage gap is matched by sourceRecordId, "
                    "sourceType and contextKey together, so add contextKey\n",
                )
                self.assertEqual(self.latest_sequence(), latest)

    def test_an_evaluation_before_the_close_is_refused_alike_on_every_persisted_surface(
        self,
    ) -> None:
        path, content = self.evaluations(self.triple(), completedAt=GAP_EARLY_TEXT)
        verified = self.succeeds(["store", "verify", "--db", str(self.database)])

        evaluated = self.evaluate_with(path)

        self.assertEqual(self.succeeds(["store", "verify", "--db", str(self.database)]), verified)
        # Written around the writer, as a store written by something else could hold it.
        (parsed,) = parse_evaluations(content.encode("utf-8")).entries
        stream_id = case_stream_id(self.case.tracking_id)
        with SQLiteEventStore(self.database) as store:
            repository = EventRepository(store)
            (appended,) = repository.append_batch(
                stream_id,
                (
                    history_writers._pending(
                        CASE_EVALUATED,
                        history_writers._evaluation_payload(parsed),
                        AS_OF,
                        EventMetadata(actor="tester"),
                    ),
                ),
                expected_version=len(repository.read_stream(stream_id)),
            )
            checked = store.latest_sequence
        message = (
            f"{self.case.tracking_id} was evaluated at {GAP_EARLY_TEXT}, before its detection "
            f"time {GAP_CLOSED_TEXT} (source system); {GAP_REMEDY}"
        )
        line = f"error: evaluation_before_detection: {message} [{COVERAGE_GAP_RECORD_ID}]\n"

        reported = run(
            [
                "report",
                "vdt",
                "--db",
                str(self.database),
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
            ]
        )
        audited = run(["store", "verify", "--db", str(self.database)])

        self.assertEqual(evaluated, (1, "", line))
        self.assertEqual(reported, (1, "", line))
        self.assertEqual(
            audited,
            (
                1,
                "",
                f"error: sequence {appended.sequence}: evaluation_before_detection: {message}\n"
                f"faults: 1 domain fault(s) in {checked} verified event(s)\n",
            ),
        )


class PersistedGapAviCommandTests(PersistedStoreTestCase):
    """AVI from a store lists a gap only once an evaluation accepts it, as the stateless run."""

    ACCEPTANCE = {
        "match": {
            "sourceRecordId": COVERAGE_GAP_RECORD_ID,
            "sourceType": COVERAGE_GAP_SOURCE_TYPE,
            "contextKey": BACKUP_KEY,
        },
        "completedAt": "2026-08-10T00:00:00Z",
        "isInternetReachable": False,
        "isLikelyExploitable": False,
        "pain": 1,
        "potentialAgencyImpact": "A missed restore test leaves backup integrity unproven.",
        "rationale": "The restore test is rescheduled; the procedure itself is unchanged.",
        "evaluator": "Example Provider vulnerability team (coverage review)",
        "disposition": "accepted",
        "acceptanceRationale": "Accepted under change record CR-210 until the Q4 restore test.",
    }

    def avi(self) -> dict[str, Any]:
        code, out, err = run(
            [
                "report",
                "avi",
                "--db",
                str(self.database),
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
                "--inventory",
                str(EXAMPLE_INVENTORY),
            ]
        )
        self.assertEqual(code, 0, msg=err)
        return dict(json.loads(out))

    def test_avi_lists_the_gap_only_once_an_evaluation_accepts_it(self) -> None:
        self.populate()
        code, _, err = run(["cases", "coverage", "--db", str(self.database), *COVERAGE_OPTIONS])
        self.assertEqual(code, 3, msg=err)
        self.correlate()
        before = self.avi()
        gaps = {window["trackingId"] for window in before["x-complyroll"]["coverage"]["windows"]}
        self.assertEqual(len(gaps), len({row[3] for row in GAP_WINDOWS}))
        self.assertEqual(before["acceptedVulnerabilities"], [])

        path = self.workspace / "accept-gap.json"
        path.write_text(json.dumps({"evaluations": [self.ACCEPTANCE]}), encoding="utf-8")
        self.evaluate(path)
        after = self.avi()

        backup = next(row[3] for row in GAP_WINDOWS if row[0] == "VDR-TFR-NMV")
        (item,) = after["acceptedVulnerabilities"]
        self.assertEqual(item["vulnerabilityDetail"]["providerTrackingId"], backup)
        self.assertEqual(
            item["acceptanceRationale"],
            "Accepted under change record CR-210 until the Q4 restore test.",
        )


if __name__ == "__main__":
    unittest.main()
