# ******************************************************************************
# *Title: Response Gap Audit Fix Tests*
# *Author: Kyle Versluis*
# *Description: Regression tests for the ADR 0019 audit findings and rulings.*
# ******************************************************************************
"""Regression tests for the step 8 audit findings on ADR 0019 (K1 to K4, Sol F02 to F15)."""

# *--- Imports ---*

from __future__ import annotations

import json
import sqlite3
import unittest
from contextlib import closing
from dataclasses import replace
from datetime import UTC, datetime
from decimal import Decimal
from pathlib import Path
from typing import Any
from unittest import mock

from test_cli import RECURRENCE_ARTIFACTS, RECURRENCE_EVALUATIONS, run
from test_coverage import policy
from test_coverage_streams import metadata, rebuilt
from test_evaluation_order import orphan_created, reread_with_timestamp
from test_replay import bumped
from test_reports import AS_OF, options
from test_response_gap_history import (
    AFTER_TEXT,
    AS_OF_TEXT,
    RECURRENCE_ID,
    REMEDIATED_CASE,
    SEEN_TEXT,
    UNTIMED,
    UNTIMED_CASE,
    StoreCase,
)
from test_response_gap_streams import events_of, lapse_record, record_gap, recurrence_record
from test_response_gaps import INGESTED, Case, compile_of, fail

from complyroll import cli as cli_module
from complyroll.adapters import ingest_stig_artifact
from complyroll.correlation import group_open_observations
from complyroll.events import (
    EventContractError,
    EventMetadata,
    EventRepository,
    case_stream_id,
    response_gap_stream_id_of,
)
from complyroll.history import (
    HistoryError,
    ResponseGapOutcome,
    audit_history,
    fold_all_cases,
    record_ingest,
    rehydrate_observations,
)
from complyroll.models import ObservationOrigin
from complyroll.policy import RuleForce, RuleTimeframe, TimeframeUnit
from complyroll.reports import (
    DetectionAttestation,
    compile_record_set,
    parse_evaluations,
)
from complyroll.reports import records as records_module
from complyroll.reports.response_gaps import (
    RECURRENCE_SOURCE_TYPE,
    AttestationLapse,
    LapseClockError,
    ResponseGapHistory,
    attestation_lapse,
    attestation_lapse_observation,
    rebuilt_lapse,
)
from complyroll.store import NewEvent, SQLiteEventStore

# *--- Fixtures ---*

#: A third scan of the remediated image, dated between the remediation and the scan that
#: recorded the recurrence (K1).
EARLIER_TEXT = "2026-09-10T08:40:00Z"
RECURRENCE_KEY = f"{REMEDIATED_CASE}:remediated:2026-09-05T15:00:00Z:1"
#: The last instant `datetime` holds, as a first sighting no deadline fits after (F06).
LAST_DAY = "9999-12-31T00:00:00Z"
NOW = datetime(2026, 11, 27, tzinfo=UTC)


def evaluation_entry(**overrides: object) -> dict[str, Any]:
    """Return the example remediation entry with fields changed."""
    entry = json.loads(RECURRENCE_EVALUATIONS.read_text(encoding="utf-8"))["evaluations"][0]
    return {key: value for key, value in {**entry, **overrides}.items() if value is not None}


class FixCase(StoreCase):
    """A command-line store with helpers to place readings the CLI cannot place by itself."""

    def write_reading(self, ingested: str, *, timestamp: datetime | None = None) -> None:
        """Record a newer parser's reading of the untimed checklist, timestamped or not."""
        ingested_at = datetime.fromisoformat(ingested.replace("Z", "+00:00"))
        result = ingest_stig_artifact(Path(UNTIMED), ingested_at=ingested_at)
        result = (
            bumped(result, "2") if timestamp is None else reread_with_timestamp(result, timestamp)
        )
        with SQLiteEventStore(self.database) as store:
            record_ingest(
                EventRepository(store),
                result,
                metadata=EventMetadata(actor="test"),
                ingested_at=ingested_at,
            )

    def earlier_scan(self) -> str:
        """Write a scan of the remediated image dated before the recorded recurrence."""
        text = Path(RECURRENCE_ARTIFACTS[1]).read_text(encoding="utf-8")
        text = text.replace("images/api/run-2", "images/api/run-3")
        text = text.replace("2026-09-12T08:40:00Z", EARLIER_TEXT)
        text = text.replace("2026-09-12T08:41:10Z", "2026-09-10T08:41:10Z")
        path = self.workspace / "recurrence-api-earlier.sarif"
        path.write_text(text, encoding="utf-8")
        return str(path)

    def correlate(self) -> None:  # type: ignore[override]
        self.succeeds(["cases", "correlate", "--db", str(self.database)])

    def recurrences(self) -> list[Any]:
        with SQLiteEventStore(self.database) as store:
            return [
                item
                for item in rehydrate_observations(EventRepository(store))
                if item.source_type == RECURRENCE_SOURCE_TYPE
            ]

    def report_notes(self) -> list[dict[str, str]]:
        code, out, err = self.report()
        self.assertEqual(code, 0, msg=err)
        return [
            item
            for item in json.loads(out)["x-complyroll"]["diagnostics"]
            if item["code"].startswith("response_gap_")
        ]

    def store_state(self) -> tuple[int, int, list[tuple[int, str]]]:
        with closing(sqlite3.connect(self.database)) as connection:
            version = int(connection.execute("PRAGMA user_version").fetchone()[0])
            sequence = int(connection.execute("SELECT COUNT(*) FROM events").fetchone()[0])
            rows = connection.execute(
                "SELECT version, description FROM complyroll_schema_migrations ORDER BY version"
            ).fetchall()
        return version, sequence, [(int(row[0]), str(row[1])) for row in rows]


# *--- K1, Sol F02, Sonnet F1 ---*


class FirstRecurrenceStandsTests(FixCase):
    """The first record of a failed remediation and resource stands; an earlier scan adds none."""

    def test_a_later_ingested_earlier_scan_appends_nothing_and_is_noted(self) -> None:
        self.remediate()
        self.ingest(RECURRENCE_ARTIFACTS[1], AFTER_TEXT)
        self.assertEqual(self.response_gaps()[0], 3)
        self.correlate()
        self.attest()
        self.ingest(self.earlier_scan(), "2026-09-14T00:00:00Z")
        code, out, err = self.response_gaps()
        self.assertEqual((code, err), (0, ""))
        self.assertIn(f"{RECURRENCE_ID}: already_recorded ", out)
        self.assertIn("recorded 0 response gap(s)", out)
        (stored,) = self.recurrences()
        self.assertEqual(stored.observation_id, RECURRENCE_ID)
        self.assertEqual(stored.context_key, RECURRENCE_KEY)
        notes = self.report_notes()
        self.assertEqual([item["code"] for item in notes], ["response_gap_earlier_detection"])
        self.assertIn(f"detected earlier, at {EARLIER_TEXT}", notes[0]["message"])
        self.assertIn("stands as written, so no second record is made", notes[0]["message"])
        out, _ = self.succeeds(["store", "verify", "--db", str(self.database)])
        self.assertTrue(out.startswith("ok: "))


# *--- K2, Sol F04 ---*


class RemediationEpisodeTests(FixCase):
    """Two remediated episodes that share an evaluation instant are two failed remediations."""

    def test_a_second_episode_at_the_same_instant_records_a_second_case(self) -> None:
        self.remediate()
        self.ingest(RECURRENCE_ARTIFACTS[1], AFTER_TEXT)
        self.assertEqual(self.response_gaps()[0], 3)
        self.assertEqual(self.evaluate(evaluation_entry(disposition="fully_mitigated"))[0], 0)
        revised = evaluation_entry(rationale="SYNTHETIC. A second remediation at the same instant.")
        self.assertEqual(self.evaluate(revised)[0], 0)
        with SQLiteEventStore(self.database) as store:
            (case,) = [
                item
                for item in fold_all_cases(EventRepository(store))
                if item.tracking_id == REMEDIATED_CASE
            ]
        self.assertEqual(case.remediation_episode, 2)
        code, out, _ = self.response_gaps()
        self.assertEqual(code, 3)
        self.assertIn("recorded 1 response gap(s)", out)
        keys = sorted(item.context_key for item in self.recurrences())
        self.assertEqual(keys, [RECURRENCE_KEY, RECURRENCE_KEY[:-1] + "2"])

    def test_a_record_whose_key_names_no_episode_is_refused(self) -> None:
        record = recurrence_record()
        stale = rebuilt(record, context_key=record.context_key.rsplit(":", 1)[0])
        with SQLiteEventStore(self.database) as store:
            with self.assertRaisesRegex(EventContractError, "<episode>"):
                record_gap(EventRepository(store), stale)


# *--- K4, Sonnet F3, Sol F14 ---*


class AttestedUntimedWarningTests(unittest.TestCase):
    """An untimed member is explained by an attestation at or before the remediation (K4)."""

    def compile(self, attested: datetime, completed: str) -> list[str]:
        result = ingest_stig_artifact(Path(UNTIMED), ingested_at=AS_OF)
        observations = result.observations
        entry = {
            **evaluation_entry(completedAt=completed),
            "match": {"sourceRecordId": "V-299001", "sourceType": "cklb"},
        }
        evaluations = parse_evaluations(json.dumps({"evaluations": [entry]}).encode("utf-8"))
        groups = group_open_observations(observations)
        record_set = compile_record_set(
            artifacts=(),
            observations=observations,
            ingest_diagnostics=(),
            evaluations_by_tracking_id=records_module._match_evaluations(groups, evaluations),
            attestation=DetectionAttestation(default=attested),
            options=options(detected_at=None),
        )
        return [
            item.message
            for item in record_set.diagnostics
            if item.code == "recurrence_after_remediation"
        ]

    def test_an_attestation_at_or_before_the_remediation_raises_no_warning(self) -> None:
        for attested in (datetime(2026, 8, 1, tzinfo=UTC), datetime(2026, 8, 5, 12, tzinfo=UTC)):
            with self.subTest(attested=attested):
                self.assertEqual(self.compile(attested, "2026-08-05T12:00:00Z"), [])

    def test_a_record_not_timed_by_attestation_still_warns_for_an_untimed_member(self) -> None:
        # The trade-off K4 accepts: only an attested record is quiet. A partly timed record,
        # detected from its timed member, still names the member it cannot order.
        timed = fail("lab-01", datetime(2026, 8, 2, tzinfo=UTC))
        untimed = fail("lab-02", None)
        (message,) = [
            item.message
            for item in compile_of((timed, untimed)).diagnostics
            if item.code == "recurrence_after_remediation"
        ]
        self.assertIn("declare no source timestamp", message)


# *--- Sol F03 ---*


class TimedCurrentReadingTests(FixCase):
    """A timed current reading prevents a lapse, linked or not (F03)."""

    def test_an_unlinked_timed_reading_prevents_the_lapse(self) -> None:
        self.ingest(UNTIMED, SEEN_TEXT)
        self.correlate()
        self.write_reading("2026-09-02T00:00:00Z", timestamp=datetime(2026, 9, 1, 12, tzinfo=UTC))
        code, out, _ = self.response_gaps()
        self.assertEqual(code, 0)
        self.assertNotIn("detection time of", out)
        self.correlate()
        code, out, _ = self.response_gaps()
        self.assertEqual(code, 0)
        self.assertNotIn("detection time of", out)

    def test_the_lapse_reads_the_current_group(self) -> None:
        closed = AS_OF.replace(year=2027)
        self.assertIsNotNone(attestation_lapse(Case(), INGESTED, policy("C"), closed))
        self.assertIsNone(
            attestation_lapse(
                Case(), INGESTED, policy("C"), closed, timed_groups={Case().tracking_id}
            )
        )


# *--- Sol F06 ---*


class FirstSightingClockTests(FixCase):
    """A first sighting no deadline fits after never ends a run in an uncaught OverflowError."""

    def test_a_run_before_the_first_sighting_computes_no_deadline(self) -> None:
        late = {"obs-first": datetime(9999, 12, 31, tzinfo=UTC)}
        case = Case(links=(Case().links[0],))
        self.assertIsNone(attestation_lapse(case, late, policy("C"), AS_OF))

    def test_a_rebuild_past_year_9999_raises_the_typed_clock_error(self) -> None:
        late = {"obs-first": datetime(9999, 12, 31, tzinfo=UTC)}
        case = Case(links=(Case().links[0],))
        history = ResponseGapHistory(cases=(case,), ingested_at=late, remediations={})
        with self.assertRaises(LapseClockError):
            rebuilt_lapse(lapse_record(), history, policy("C"))

    def test_report_and_verify_both_name_the_first_sighting(self) -> None:
        self.write_reading(LAST_DAY)
        self.correlate()
        self.attest()
        with SQLiteEventStore(self.database) as store:
            repository = EventRepository(store)
            (case,) = fold_all_cases(repository)
            lapse = AttestationLapse(
                tracking_id=case.tracking_id,
                first_seen_at=datetime(2026, 9, 1, tzinfo=UTC),
                window_closed_at=datetime(2026, 9, 6, tzinfo=UTC),
                force="SHOULD",
            )
            record_gap(repository, attestation_lapse_observation(lapse, ingested_at=NOW))
        code, out, err = self.report()
        self.assertEqual((code, out), (1, ""))
        self.assertIn("error: clock_out_of_range: ", err)
        self.assertIn(f"{case.tracking_id} was first recorded 9999-12-31", err)
        self.assertNotIn("Traceback", err)
        code, out, err = run(["store", "verify", "--db", str(self.database)])
        self.assertEqual(code, 1)
        self.assertIn(": clock_out_of_range: ", err)
        self.assertIn(f"{case.tracking_id} was first recorded 9999-12-31", err)

    def test_the_writer_and_report_survive_an_unlinked_timed_reading(self) -> None:
        # Sol's reproduction: an aware store, a first sighting at the last day, a timed current
        # reading left unlinked. Nothing ends in an OverflowError; verify names the sighting.
        with SQLiteEventStore(self.database) as store:
            record_gap(EventRepository(store), recurrence_record())
        self.write_reading(LAST_DAY)
        self.correlate()
        self.write_reading("2026-09-02T00:00:00Z", timestamp=datetime(2026, 9, 1, 12, tzinfo=UTC))
        code, out, err = self.report()
        self.assertEqual(code, 0, msg=err)
        code, out, err = self.response_gaps()
        self.assertEqual(code, 0, msg=err)
        code, _, err = run(["store", "verify", "--db", str(self.database)])
        self.assertEqual(code, 1)
        self.assertIn(": clock_out_of_range: ", err)


# *--- Sol F08 ---*


class AttestationForceTests(FixCase):
    """A lapse names the force the pinned rules give VER-TFR-EVU, not any rule force (F08)."""

    def test_a_valid_force_the_rule_does_not_have_is_refused_and_audited(self) -> None:
        good = lapse_record()
        fields = {**dict(good.source_metadata), "attestation.force": "MUST"}
        forged = rebuilt(good, source_metadata=tuple(sorted(fields.items())))
        with SQLiteEventStore(self.database) as store:
            repository = EventRepository(store)
            with self.assertRaisesRegex(EventContractError, "not the force the pinned rules"):
                record_gap(repository, forged)
            for version, (event_type, payload) in enumerate(events_of(forged)):
                store.append(
                    response_gap_stream_id_of(forged),
                    [NewEvent(event_type, NOW, payload, metadata().to_dict())],
                    expected_version=version,
                    requires_schema=7,
                )
            codes = {fault.code for fault in audit_history(repository)}
            self.assertIn("responsegap_identity_breach", codes)
            with self.assertRaisesRegex(HistoryError, "not the force the pinned rules"):
                rehydrate_observations(repository)


# *--- Sol F09 ---*


class WriterRollbackTests(FixCase):
    """A refusal on the writer's second append leaves the store as it found it (F09)."""

    def test_a_failed_second_append_rolls_back_the_first(self) -> None:
        self.remediate()
        self.ingest(RECURRENCE_ARTIFACTS[1], AFTER_TEXT)
        before = self.store_state()
        original = EventRepository.append_batch
        calls: list[str] = []

        def fail_second(repository: EventRepository, stream_id: str, *args: Any, **kwargs: Any):
            if stream_id.startswith("response-gap/"):
                calls.append(stream_id)
                if len(calls) == 2:
                    raise EventContractError("injected failure on the second response gap")
            return original(repository, stream_id, *args, **kwargs)

        with mock.patch.object(EventRepository, "append_batch", fail_second):
            code, out, err = self.response_gaps()
        self.assertEqual((code, out), (1, ""))
        self.assertIn("injected failure on the second response gap", err)
        self.assertEqual(len(calls), 2)
        self.assertEqual(self.store_state(), before)


# *--- Sol F10 ---*


class EpisodeStartTests(FixCase):
    """A closed-as-remediated disposition starts an episode; a closed exclusion ends it (F10)."""

    def test_closed_as_remediated_starts_an_episode_through_the_writer(self) -> None:
        before, after = RECURRENCE_ARTIFACTS
        self.ingest(before, "2026-09-03T00:00:00Z")
        self.correlate()
        closed = evaluation_entry(disposition="closed", closedDisposition="remediated")
        self.assertEqual(self.evaluate(closed)[0], 0)
        self.ingest(after, AFTER_TEXT)
        with SQLiteEventStore(self.database) as store:
            (case,) = fold_all_cases(EventRepository(store))
        self.assertEqual(case.remediated_at, datetime(2026, 9, 5, 15, tzinfo=UTC))
        self.assertEqual(case.remediation_episode, 1)
        code, _, err = self.report()
        self.assertIn("recurrence_after_remediation", err)
        code, out, _ = self.response_gaps()
        self.assertEqual(code, 3)
        self.assertIn(f"{RECURRENCE_ID}: recorded", out)

    def test_closing_as_an_excluded_resolution_records_no_recurrence(self) -> None:
        before, after = RECURRENCE_ARTIFACTS
        self.ingest(before, "2026-09-03T00:00:00Z")
        self.correlate()
        self.assertEqual(self.evaluate(evaluation_entry())[0], 0)
        closed = evaluation_entry(disposition="closed", closedDisposition="fully_mitigated")
        self.assertEqual(self.evaluate(closed)[0], 0)
        self.ingest(after, AFTER_TEXT)
        code, out, _ = self.response_gaps()
        self.assertEqual(code, 0)
        self.assertEqual(self.recurrences(), [])


class SupersededFirstSightingTests(FixCase):
    """A first sighting reads a superseded reading the case still links (F10)."""

    def test_the_original_ingest_stays_the_first_sighting(self) -> None:
        self.ingest(UNTIMED, SEEN_TEXT)
        self.correlate()
        self.write_reading("2026-09-03T00:00:00Z")
        self.correlate()
        code, out, _ = self.response_gaps()
        self.assertEqual(code, 3)
        self.assertIn(
            f"recorded detection time of {UNTIMED_CASE} was not attested within VER-TFR-EVU "
            f"from {SEEN_TEXT}",
            out,
        )


class SelfConsistentRecurrenceTests(FixCase):
    """A stored recurrence detected at its own remediation instant is refused everywhere (F10)."""

    def test_reader_and_verify_reject_a_detection_at_the_remediation(self) -> None:
        good = recurrence_record()
        remediated = good.metadata_value("recurrence.remediatedAt")
        fields = {**dict(good.source_metadata), "recurrence.observationDetectedAt": remediated}
        title = good.title.replace("2026-08-10T09:00:00Z", remediated)
        forged = rebuilt(
            good,
            observed_at=datetime.fromisoformat(remediated.replace("Z", "+00:00")),
            source_metadata=tuple(sorted(fields.items())),
            title=title,
        )
        with SQLiteEventStore(self.database) as store:
            repository = EventRepository(store)
            for version, (event_type, payload) in enumerate(events_of(forged)):
                store.append(
                    response_gap_stream_id_of(forged),
                    [NewEvent(event_type, NOW, payload, metadata().to_dict())],
                    expected_version=version,
                    requires_schema=7,
                )
            faults = [
                fault
                for fault in audit_history(repository)
                if fault.code == "responsegap_identity_breach"
            ]
            self.assertTrue(faults)
            self.assertIn("not after its remediation", faults[0].message)
            with self.assertRaisesRegex(HistoryError, "not after its remediation"):
                rehydrate_observations(repository)


# *--- Sol F11 ---*


class LinklessCaseTests(FixCase):
    """A real case with no link has no first sighting and records nothing (F11)."""

    def test_a_linkless_case_records_nothing(self) -> None:
        self.ingest(UNTIMED, SEEN_TEXT)
        orphan = "case-00000000000000aa"
        with SQLiteEventStore(self.database) as store:
            EventRepository(store).append(
                case_stream_id(orphan),
                "case.created",
                orphan_created(orphan),
                occurred_at=NOW,
                metadata=EventMetadata(actor="test"),
                expected_version=0,
            )
            (case,) = fold_all_cases(EventRepository(store))
        self.assertEqual((case.tracking_id, case.links), (orphan, ()))
        code, out, err = self.response_gaps("--class", "C", "--as-of", "2027-01-01T00:00:00Z")
        self.assertEqual((code, err), (0, ""))
        self.assertEqual(
            out, "recorded 0 response gap(s), skipped 0 already-recorded response gap(s)\n"
        )


# *--- Sol F12 ---*


class SelectedRuleTests(unittest.TestCase):
    """The lapse window and force come from the selected rule, never a constant (F12)."""

    def test_a_selected_rule_of_eight_days_and_must_is_followed(self) -> None:
        base = policy("C")
        rules = tuple(
            replace(
                rule,
                timeframe=RuleTimeframe(Decimal(8), TimeframeUnit.DAYS),
                force=RuleForce.MUST,
            )
            if rule.rule_id == "VER-TFR-EVU"
            else rule
            for rule in base.rules
        )
        selected = replace(base, rules=rules)
        lapse = attestation_lapse(Case(), INGESTED, selected, AS_OF.replace(year=2027))
        assert lapse is not None
        self.assertEqual(lapse.window_closed_at, datetime(2026, 9, 9, 8, tzinfo=UTC))
        self.assertEqual(lapse.force, "MUST")


class CalendarZoneForwardingTests(FixCase):
    """`cases response-gaps` hands the writer the class and calendar zone it was given (F12)."""

    def test_the_writer_receives_the_selected_zone(self) -> None:
        self.ingest(UNTIMED, SEEN_TEXT)
        seen: list[Any] = []

        def spy(repository: EventRepository, **kwargs: Any) -> Any:
            seen.append(kwargs["profile"])
            return ResponseGapOutcome(recorded=(), already_recorded=())

        with mock.patch.object(cli_module, "record_response_gaps", spy):
            code, _, _ = self.response_gaps(
                "--class", "B", "--as-of", AS_OF_TEXT, "--calendar-tz", "America/Phoenix"
            )
        self.assertEqual(code, 0)
        (profile,) = seen
        self.assertEqual(profile.certification_class.value, "B")
        self.assertEqual(profile.calendar_timezone, "America/Phoenix")


# *--- Sol F15 ---*


class PersistedProviderOverrideTests(FixCase):
    """A provider override on the remediated case never moves the recurrence identity (F15)."""

    def test_the_writer_keys_on_the_correlation_id(self) -> None:
        before, after = RECURRENCE_ARTIFACTS
        self.ingest(before, "2026-09-03T00:00:00Z")
        self.correlate()
        overridden = evaluation_entry(trackingId="EXAMPLE-PROVIDER-0100")
        self.assertEqual(self.evaluate(overridden)[0], 0)
        self.ingest(after, AFTER_TEXT)
        code, out, _ = self.response_gaps()
        self.assertEqual(code, 3)
        self.assertIn(f"{RECURRENCE_ID}: recorded remediation of {REMEDIATED_CASE}", out)
        (stored,) = self.recurrences()
        self.assertEqual(stored.context_key, RECURRENCE_KEY)
        self.assertIs(stored.origin, ObservationOrigin.SYSTEM)


if __name__ == "__main__":
    unittest.main()
