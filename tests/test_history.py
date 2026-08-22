"""ADR 0008 Decisions 3 and 4: the writers append the change, and nothing but the change.

Every store below is driven through the library writers, the same calls the command line
makes, so what these tests pin belongs to the history layer rather than to one command
surface. A writer that stops being idempotent, a refusal that stops refusing, or a fact
the store keeps that stops warning all show up here as a sequence number that moved when
it should have stood still.
"""

from __future__ import annotations

import json
import tempfile
import unittest
from collections.abc import Mapping, Sequence
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

from complyroll.adapters import ingest_stig_artifact
from complyroll.events import (
    EventContractError,
    EventMetadata,
    EventRepository,
    PendingEvent,
    artifact_stream_id,
    case_stream_id,
    iso_utc,
    parse_utc,
)
from complyroll.history import (
    ARTIFACT_INGESTED,
    CASE_CREATED,
    CASE_DISPOSITION_RECORDED,
    CASE_EVALUATED,
    CASE_PAIN_REDUCED,
    DETECTION_ATTESTED,
    OBSERVATION_RECORDED,
    AttestationOutcome,
    CaseNotFoundError,
    CorrelationOutcome,
    DispositionRecord,
    EvaluationMatchError,
    EvaluationOutcome,
    HistoryError,
    IngestOutcome,
    apply_evaluations,
    attest_detection,
    case_history,
    correlate_cases,
    fold_all_cases,
    fold_case,
    record_ingest,
    rehydrate_observations,
)
from complyroll.models import CaseStatus
from complyroll.reports import EvaluationSet, load_evaluations, parse_evaluations
from complyroll.store import NewEvent, SQLiteEventStore

REPO_ROOT = Path(__file__).parent.parent
FIXTURES = REPO_ROOT / "tests" / "fixtures"
EXAMPLES = REPO_ROOT / "examples"

ARTIFACTS = (
    FIXTURES / "ubuntu-host.cklb",
    FIXTURES / "windows-host.ckl",
    FIXTURES / "openscap-results.xml",
)

#: The instant the fixtures are ingested at, matching the golden report's `--as-of`.
INGESTED_AT = datetime(2026, 8, 21, 12, 0, tzinfo=UTC)
#: The instant every fixture case attests, matching the golden report.
ATTESTED_AT = datetime(2026, 8, 1, 0, 0, tzinfo=UTC)
#: A later filing time, used to prove the clerical fields do not change content.
FILED_LATER = datetime(2026, 8, 22, 9, 30, tzinfo=UTC)
RATIONALE = "The fixtures declare no assessment timestamp; the assessment ran on 1 August."

#: V-260470 on the Ubuntu host, the first entry in `examples/evaluations.json`.
UBUNTU_CASE = "case-1f3e011db93cc89e"
#: V-253260 on the Windows host, the entry that carries a PAIN reduction.
WINDOWS_CASE = "case-490f49bfdd1bd019"
#: V-260469, a case the example file never evaluates.
UNEVALUATED_CASE = "case-9bed0d8f88355393"
#: A well-formed tracking id no fixture produces.
SPARE_CASE = "case-00000000000000ff"

#: One XCCDF result whose every finding carries a source timestamp.
TIMESTAMPED_XCCDF = """<?xml version="1.0" encoding="UTF-8"?>
<Benchmark xmlns="http://checklists.nist.gov/xccdf/1.2" id="timed">
  <TestResult id="timed" end-time="2026-08-03T09:00:00Z">
    <target>lab-timed</target>
    <rule-result idref="xccdf_org.ssgproject.content_rule_banner_etc_issue" severity="medium">
      <result>fail</result>
      <ident system="https://public.cyber.mil/stigs/cci/">CCI-000048</ident>
    </rule-result>
  </TestResult>
</Benchmark>
"""

#: The same rule seen twice, once with a source timestamp and once without.
PARTIAL_XCCDF = """<?xml version="1.0" encoding="UTF-8"?>
<Benchmark xmlns="http://checklists.nist.gov/xccdf/1.2" id="mixed">
  <TestResult id="shared" end-time="2026-08-03T09:00:00Z">
    <target>lab-timed</target>
    <rule-result idref="xccdf_org.ssgproject.content_rule_banner_etc_issue" severity="medium">
      <result>fail</result>
      <ident system="https://public.cyber.mil/stigs/cci/">CCI-000048</ident>
    </rule-result>
  </TestResult>
  <TestResult id="shared">
    <target>lab-untimed</target>
    <rule-result idref="xccdf_org.ssgproject.content_rule_banner_etc_issue" severity="medium">
      <result>fail</result>
      <ident system="https://public.cyber.mil/stigs/cci/">CCI-000048</ident>
    </rule-result>
  </TestResult>
</Benchmark>
"""


def example_payload() -> dict[str, Any]:
    """Read the shipped evaluations file back as a mutable payload."""

    value = json.loads((EXAMPLES / "evaluations.json").read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise AssertionError("examples/evaluations.json must hold a JSON object")
    return value


def evaluations_of(payload: Mapping[str, Any]) -> EvaluationSet:
    """Parse a mutated payload through the same bounded reader the CLI uses."""

    return parse_evaluations(json.dumps(payload).encode("utf-8"))


def entry_for(payload: Mapping[str, Any], source_record_id: str) -> dict[str, Any]:
    """Return the payload entry that selects one source record, for mutation in place."""

    for entry in payload["evaluations"]:
        if entry["match"]["sourceRecordId"] == source_record_id:
            return dict(entry) if not isinstance(entry, dict) else entry
    raise AssertionError(f"examples/evaluations.json has no entry for {source_record_id}")


def drop_entry(payload: dict[str, Any], source_record_id: str) -> None:
    """Remove one entry, leaving a file that no longer states anything about that case."""

    payload["evaluations"] = [
        entry
        for entry in payload["evaluations"]
        if entry["match"]["sourceRecordId"] != source_record_id
    ]


class WriterFixture(unittest.TestCase):
    """A temporary store plus the writers, called exactly as a command would call them."""

    def setUp(self) -> None:
        directory = tempfile.TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        self.workspace = Path(directory.name)
        self.database = self.workspace / "history.db"
        store = SQLiteEventStore(self.database)
        self.addCleanup(store.close)
        self.repository = EventRepository(store)
        self.metadata = EventMetadata(actor="tester", run_id="run-history")

    @property
    def latest_sequence(self) -> int:
        """Return the global sequence the log has reached."""

        return self.repository.store.latest_sequence

    def ingest(
        self,
        paths: Sequence[Path] = ARTIFACTS,
        *,
        ingested_at: datetime = INGESTED_AT,
    ) -> tuple[IngestOutcome, ...]:
        """Record every artifact in the order the golden report lists them."""

        outcomes: list[IngestOutcome] = []
        for path in paths:
            result = ingest_stig_artifact(Path(path), ingested_at=ingested_at)
            outcomes.append(
                record_ingest(
                    self.repository,
                    result,
                    metadata=self.metadata,
                    ingested_at=ingested_at,
                )
            )
        return tuple(outcomes)

    def correlate(self) -> CorrelationOutcome:
        return correlate_cases(self.repository, metadata=self.metadata, now=INGESTED_AT)

    def tracking_ids(self) -> tuple[str, ...]:
        return tuple(case.tracking_id for case in fold_all_cases(self.repository))

    def attest(
        self,
        tracking_ids: Sequence[str] | None = None,
        *,
        detected_at: datetime = ATTESTED_AT,
        rationale: str = RATIONALE,
        now: datetime = INGESTED_AT,
    ) -> AttestationOutcome:
        selected = self.tracking_ids() if tracking_ids is None else tuple(tracking_ids)
        return attest_detection(
            self.repository,
            selected,
            detected_at=detected_at,
            rationale=rationale,
            metadata=self.metadata,
            now=now,
        )

    def evaluate(
        self,
        evaluations: EvaluationSet | None = None,
        *,
        now: datetime = INGESTED_AT,
    ) -> EvaluationOutcome:
        source = (
            load_evaluations(EXAMPLES / "evaluations.json")
            if evaluations is None
            else evaluations
        )
        return apply_evaluations(
            self.repository, source, metadata=self.metadata, now=now
        )

    def populate(self) -> None:
        """Run the three writers that precede evaluation, in documented order."""

        self.ingest()
        self.correlate()
        self.attest()

    def write_artifact(self, name: str, text: str) -> Path:
        """Write one artifact into the workspace and return its path."""

        path = self.workspace / name
        path.write_text(text, encoding="utf-8")
        return path

    def append_raw(
        self,
        stream_id: str,
        event_type: str,
        payload: Mapping[str, Any],
        *,
        expected_version: int,
    ) -> None:
        """Append one contract-valid event the writers would never produce.

        Stored history outlives the code that wrote it, so the fold has to survive
        shapes no current writer emits. Writing them through the repository is the only
        deterministic way to reach those shapes inside one test.
        """

        self.repository.append(
            stream_id,
            event_type,
            payload,
            occurred_at=INGESTED_AT,
            metadata=self.metadata,
            expected_version=expected_version,
        )

    def case_created_payload(self, tracking_id: str) -> dict[str, Any]:
        """Return a contract-valid `case.created` payload for one tracking id."""

        return {
            "trackingId": tracking_id,
            "sourceType": "ckl",
            "sourceRecordId": "V-000001",
            "contextKey": "A retired benchmark",
            "title": "A weakness recorded by an earlier run",
            "description": "Recorded from an artifact that is no longer supplied.",
            "createdAt": iso_utc(INGESTED_AT),
        }

    def interrupt_ingest(self, path: Path, *, keep: int) -> tuple[str, int]:
        """Record an artifact's head and only its first `keep` observations.

        A run that dies after opening the stream leaves exactly this shape. The head
        still declares the full observation count, because the parser had already
        produced them all when it was written.
        """

        result = ingest_stig_artifact(Path(path), ingested_at=INGESTED_AT)
        artifact = result.artifact
        self.assertIsNotNone(artifact)
        assert artifact is not None
        stream_id = artifact_stream_id(
            artifact.digest_sha256, artifact.parser_name, artifact.parser_version
        )
        head = PendingEvent(
            event_type=ARTIFACT_INGESTED,
            payload={
                "name": artifact.name,
                "sha256": artifact.digest_sha256,
                "sizeBytes": artifact.size_bytes,
                "mediaType": artifact.media_type,
                "parserName": artifact.parser_name,
                "parserVersion": artifact.parser_version,
                "ingestedAt": iso_utc(INGESTED_AT),
                "observationCount": len(result.observations),
                "diagnostics": [item.to_dict() for item in result.diagnostics],
            },
            occurred_at=INGESTED_AT,
            metadata=self.metadata,
        )
        tail = tuple(
            PendingEvent(
                event_type=OBSERVATION_RECORDED,
                payload=observation.to_canonical_dict(),
                occurred_at=INGESTED_AT,
                metadata=self.metadata,
            )
            for observation in result.observations[:keep]
        )
        self.repository.append_batch(stream_id, (head, *tail), expected_version=0)
        return stream_id, len(result.observations)

    def stream_types(self, stream_id: str) -> tuple[str, ...]:
        return tuple(record.event_type for record in self.repository.read_stream(stream_id))

    def case_event_types(self, tracking_id: str) -> tuple[str, ...]:
        return self.stream_types(case_stream_id(tracking_id))

    def assertAppendsNothing(self, call: Any) -> Any:
        """Run one writer and require that the log did not grow."""

        before = self.latest_sequence
        outcome = call()
        self.assertEqual(self.latest_sequence, before)
        return outcome

    def assertRefused(self, error: type[BaseException], call: Any) -> BaseException:
        """Require that a writer refused its input without appending anything."""

        before = self.latest_sequence
        with self.assertRaises(error) as caught:
            call()
        self.assertEqual(self.latest_sequence, before)
        return caught.exception


class IngestIdempotencyTests(WriterFixture):
    """ADR 0008 Decision 3: an artifact already in history is left alone."""

    def test_recording_the_same_artifacts_twice_appends_nothing(self) -> None:
        first = self.ingest()

        outcomes = self.assertAppendsNothing(self.ingest)

        self.assertTrue(all(outcome.appended for outcome in first))
        self.assertTrue(all(outcome.already_recorded for outcome in outcomes))
        self.assertEqual(
            [outcome.observation_count for outcome in outcomes],
            [outcome.observation_count for outcome in first],
        )

    def test_an_interrupted_ingest_appends_only_the_missing_tail(self) -> None:
        stream_id, total = self.interrupt_ingest(ARTIFACTS[0], keep=2)
        after_crash = self.latest_sequence

        outcome = self.ingest([ARTIFACTS[0]])[0]

        self.assertTrue(outcome.appended)
        self.assertEqual(self.latest_sequence - after_crash, total - 2)
        self.assertEqual(outcome.stream_id, stream_id)
        self.assertEqual(
            self.stream_types(stream_id),
            (ARTIFACT_INGESTED, *([OBSERVATION_RECORDED] * total)),
        )

    def test_a_resumed_ingest_records_each_observation_exactly_once(self) -> None:
        self.interrupt_ingest(ARTIFACTS[0], keep=2)

        self.ingest([ARTIFACTS[0]])
        observations = rehydrate_observations(self.repository)
        identifiers = [observation.observation_id for observation in observations]

        self.assertEqual(len(identifiers), len(set(identifiers)))
        self.assertEqual(
            identifiers,
            [
                observation.observation_id
                for observation in ingest_stig_artifact(
                    ARTIFACTS[0], ingested_at=INGESTED_AT
                ).observations
            ],
        )

    def test_a_resumed_ingest_keeps_the_instant_the_stream_opened_with(self) -> None:
        # One artifact ingestion is one instant. A run interrupted on Friday and
        # resumed on Saturday under a different --as-of would otherwise leave two
        # ingestion times inside one stream, and no reader could say which was the
        # artifact's.
        stream_id, total = self.interrupt_ingest(ARTIFACTS[0], keep=2)
        later = INGESTED_AT + timedelta(days=1)

        self.ingest([ARTIFACTS[0]], ingested_at=later)

        records = self.repository.read_stream(stream_id)
        head = records[0]
        self.assertEqual(head.event_type, ARTIFACT_INGESTED)
        self.assertEqual(len(records), total + 1)
        opened_at = parse_utc(head.payload["ingestedAt"])
        self.assertEqual(opened_at, INGESTED_AT)
        self.assertEqual(
            {
                parse_utc(record.payload["ingested_at"])
                for record in records
                if record.event_type == OBSERVATION_RECORDED
            },
            {opened_at},
        )

    def test_a_resumed_tail_still_rehydrates_and_keeps_its_identities(self) -> None:
        stream_id, _ = self.interrupt_ingest(ARTIFACTS[0], keep=2)
        expected = ingest_stig_artifact(ARTIFACTS[0], ingested_at=INGESTED_AT).observations

        self.ingest([ARTIFACTS[0]], ingested_at=INGESTED_AT + timedelta(days=1))

        self.assertEqual(rehydrate_observations(self.repository), expected)
        self.assertEqual(len(self.repository.read_stream(stream_id)), len(expected) + 1)

    def test_a_resumed_ingest_is_idempotent_once_it_completes(self) -> None:
        self.interrupt_ingest(ARTIFACTS[0], keep=2)
        self.ingest([ARTIFACTS[0]])

        outcome = self.assertAppendsNothing(lambda: self.ingest([ARTIFACTS[0]]))[0]

        self.assertTrue(outcome.already_recorded)

    def test_a_stream_holding_more_observations_than_the_parser_produced_is_refused(
        self,
    ) -> None:
        stream_id, total = self.interrupt_ingest(ARTIFACTS[0], keep=6)
        spare = ingest_stig_artifact(ARTIFACTS[0], ingested_at=INGESTED_AT).observations[0]
        self.append_raw(
            stream_id,
            OBSERVATION_RECORDED,
            spare.to_canonical_dict(),
            expected_version=total + 1,
        )

        error = self.assertRefused(HistoryError, lambda: self.ingest([ARTIFACTS[0]]))

        self.assertIn("but the parser produced", str(error))

    def test_a_stream_that_does_not_begin_with_the_artifact_is_refused(self) -> None:
        result = ingest_stig_artifact(ARTIFACTS[0], ingested_at=INGESTED_AT)
        artifact = result.artifact
        assert artifact is not None
        stream_id = artifact_stream_id(
            artifact.digest_sha256, artifact.parser_name, artifact.parser_version
        )
        self.append_raw(
            stream_id,
            OBSERVATION_RECORDED,
            result.observations[0].to_canonical_dict(),
            expected_version=0,
        )

        error = self.assertRefused(HistoryError, lambda: self.ingest([ARTIFACTS[0]]))

        self.assertIn("begins with", str(error))

    def test_an_ingest_that_failed_cannot_be_recorded_as_history(self) -> None:
        broken = self.write_artifact("broken.ckl", "<CHECKLIST><unclosed>")
        result = ingest_stig_artifact(broken, ingested_at=INGESTED_AT)

        error = self.assertRefused(
            HistoryError,
            lambda: record_ingest(
                self.repository,
                result,
                metadata=self.metadata,
                ingested_at=INGESTED_AT,
            ),
        )

        self.assertIn("only a successful ingest", str(error))


class CorrelationIdempotencyTests(WriterFixture):
    """ADR 0008 Decision 3: a case is created once and an observation is linked once."""

    def test_correlating_twice_creates_nothing_and_links_nothing(self) -> None:
        self.ingest()
        first = self.correlate()

        again = self.assertAppendsNothing(self.correlate)

        self.assertEqual(len(first.created), 6)
        self.assertEqual(first.linked, 6)
        self.assertEqual(first.skipped_links, 0)
        self.assertEqual(again.created, ())
        self.assertEqual(again.linked, 0)
        self.assertEqual(again.skipped_links, 6)

    def test_a_later_artifact_links_only_its_own_observations(self) -> None:
        self.ingest([ARTIFACTS[0]])
        self.correlate()
        before = self.latest_sequence

        self.ingest([ARTIFACTS[1]])
        after_ingest = self.latest_sequence
        outcome = self.correlate()

        self.assertEqual(outcome.created, (WINDOWS_CASE,))
        self.assertEqual(outcome.linked, 1)
        self.assertEqual(outcome.skipped_links, 3)
        self.assertEqual(self.latest_sequence - after_ingest, 2)
        self.assertGreater(after_ingest, before)


class AttestationTests(WriterFixture):
    """ADR 0008 Decision 3 and the amendment: attest once, and only where it matters."""

    def setUp(self) -> None:
        super().setUp()
        self.ingest()
        self.correlate()

    def test_attesting_twice_appends_nothing(self) -> None:
        first = self.attest()

        again = self.assertAppendsNothing(self.attest)

        self.assertEqual(len(first.attested), 6)
        self.assertEqual(first.skipped, ())
        self.assertEqual(again.attested, ())
        self.assertEqual(len(again.skipped), 6)

    def test_the_same_attestation_filed_later_still_appends_nothing(self) -> None:
        self.attest()

        again = self.assertAppendsNothing(lambda: self.attest(now=FILED_LATER))

        self.assertEqual(len(again.skipped), 6)

    def test_a_changed_rationale_appends_one_attestation_per_case(self) -> None:
        self.attest([UBUNTU_CASE])
        before = self.latest_sequence

        outcome = self.attest([UBUNTU_CASE], rationale="The assessment window moved.")

        self.assertEqual(outcome.attested, (UBUNTU_CASE,))
        self.assertEqual(self.latest_sequence - before, 1)
        self.assertEqual(
            self.case_event_types(UBUNTU_CASE).count(DETECTION_ATTESTED),
            2,
        )

    def test_a_changed_instant_appends_a_second_attestation(self) -> None:
        self.attest([UBUNTU_CASE])
        before = self.latest_sequence

        outcome = self.attest([UBUNTU_CASE], detected_at=datetime(2026, 7, 15, tzinfo=UTC))

        self.assertEqual(outcome.attested, (UBUNTU_CASE,))
        self.assertEqual(self.latest_sequence - before, 1)

    def test_a_case_whose_every_link_is_timestamped_is_not_applicable(self) -> None:
        self.ingest([self.write_artifact("timed.xml", TIMESTAMPED_XCCDF)])
        self.correlate()
        timed = tuple(
            case.tracking_id
            for case in fold_all_cases(self.repository)
            if case.links and all(link.observed_at is not None for link in case.links)
        )
        self.assertEqual(len(timed), 1)

        outcome = self.assertAppendsNothing(lambda: self.attest(timed))

        self.assertEqual(outcome.not_applicable, timed)
        self.assertEqual(outcome.attested, ())
        self.assertEqual(outcome.skipped, ())
        self.assertNotIn(DETECTION_ATTESTED, self.case_event_types(timed[0]))

    def test_a_partly_timestamped_case_is_not_applicable(self) -> None:
        # The compiler takes the earliest known source time for a partly timestamped
        # group (artifact-partial, ADR 0007 amendment), so an attestation recorded here
        # could never reach a report. Recording it would state a detection time the
        # report never uses.
        self.ingest([self.write_artifact("partial.xml", PARTIAL_XCCDF)])
        self.correlate()
        partial = tuple(
            case.tracking_id
            for case in fold_all_cases(self.repository)
            if len(case.links) == 2 and any(link.observed_at is not None for link in case.links)
        )
        self.assertEqual(len(partial), 1)

        outcome = self.assertAppendsNothing(lambda: self.attest(partial))

        self.assertEqual(outcome.not_applicable, partial)
        self.assertEqual(outcome.attested, ())
        self.assertEqual(outcome.skipped, ())
        self.assertNotIn(DETECTION_ATTESTED, self.case_event_types(partial[0]))

    def test_a_case_with_no_links_is_attested(self) -> None:
        self.append_raw(
            case_stream_id(SPARE_CASE),
            CASE_CREATED,
            self.case_created_payload(SPARE_CASE),
            expected_version=0,
        )

        outcome = self.attest([SPARE_CASE])

        self.assertEqual(outcome.attested, (SPARE_CASE,))
        self.assertEqual(outcome.not_applicable, ())

    def test_an_unknown_case_is_refused_and_records_nothing(self) -> None:
        error = self.assertRefused(CaseNotFoundError, lambda: self.attest([SPARE_CASE]))

        self.assertIn(SPARE_CASE, str(error))
        self.assertEqual(self.repository.read_stream(case_stream_id(SPARE_CASE)), ())

    def test_a_blank_rationale_is_refused(self) -> None:
        error = self.assertRefused(HistoryError, lambda: self.attest(rationale="   "))

        self.assertIn("rationale must be non-blank text", str(error))


class EvaluationIdempotencyTests(WriterFixture):
    """ADR 0008 Decisions 3 and 4: identical appends nothing, different appends once."""

    def setUp(self) -> None:
        super().setUp()
        self.populate()

    def test_applying_the_same_file_twice_appends_nothing(self) -> None:
        first = self.evaluate()

        again = self.assertAppendsNothing(self.evaluate)

        self.assertEqual(first.appended, 4)
        self.assertEqual(first.skipped, 0)
        self.assertEqual(again.appended, 0)
        self.assertEqual(again.evaluations_skipped, 2)
        self.assertEqual(again.reductions_skipped, 1)
        self.assertEqual(again.dispositions_skipped, 1)
        self.assertEqual(again.warnings, ())

    def test_applying_the_same_file_later_still_appends_nothing(self) -> None:
        self.evaluate()

        again = self.assertAppendsNothing(lambda: self.evaluate(now=FILED_LATER))

        self.assertEqual(again.appended, 0)

    def test_a_changed_pain_appends_exactly_one_event(self) -> None:
        self.evaluate()
        before = self.latest_sequence
        payload = example_payload()
        entry_for(payload, "V-260470")["pain"] = 5

        outcome = self.evaluate(evaluations_of(payload))

        self.assertEqual(self.latest_sequence - before, 1)
        self.assertEqual(outcome.evaluations_appended, 1)
        self.assertEqual(outcome.evaluations_skipped, 1)
        self.assertEqual(outcome.appended, 1)

    def test_both_evaluations_stay_readable_and_the_latest_is_current(self) -> None:
        self.evaluate()
        payload = example_payload()
        entry_for(payload, "V-260470")["pain"] = 5

        self.evaluate(evaluations_of(payload))
        case = fold_case(self.repository, UBUNTU_CASE)
        current = case.current_evaluation
        assert current is not None

        self.assertEqual(case.evaluation_count, 2)
        self.assertEqual([int(item.pain) for item in case.evaluations], [3, 5])
        self.assertEqual(int(current.pain), 5)
        self.assertLess(case.evaluations[0].sequence, case.evaluations[1].sequence)

    def test_the_history_listing_shows_both_evaluations(self) -> None:
        self.evaluate()
        payload = example_payload()
        entry_for(payload, "V-260470")["pain"] = 5
        self.evaluate(evaluations_of(payload))

        entries = case_history(self.repository, UBUNTU_CASE)
        evaluated = [item for item in entries if item.event_type == CASE_EVALUATED]

        self.assertEqual(len(evaluated), 2)
        self.assertIn("evaluated PAIN 3", evaluated[0].summary)
        self.assertIn("evaluated PAIN 5", evaluated[1].summary)
        self.assertEqual({item.actor for item in evaluated}, {"tester"})

    def test_a_new_reduction_appends_one_event_and_keeps_the_first(self) -> None:
        self.evaluate()
        before = self.latest_sequence
        payload = example_payload()
        entry_for(payload, "V-253260")["painReductionEvents"].append(
            {"reducedAt": "2026-08-19T16:00:00Z", "rating": 3}
        )

        outcome = self.evaluate(evaluations_of(payload))
        case = fold_case(self.repository, WINDOWS_CASE)

        self.assertEqual(self.latest_sequence - before, 1)
        self.assertEqual(outcome.reductions_appended, 1)
        self.assertEqual(outcome.reductions_skipped, 1)
        self.assertEqual(len(case.pain_reductions), 2)
        self.assertEqual(outcome.warnings, ())

    def test_an_unevaluated_case_is_left_untouched(self) -> None:
        self.evaluate()

        case = fold_case(self.repository, UNEVALUATED_CASE)

        self.assertEqual(case.evaluations, ())
        self.assertIsNone(case.disposition)
        self.assertIsNone(case.current_evaluation)


class EvaluationMatchTests(WriterFixture):
    """A file that does not select exactly one case per entry is refused whole."""

    def setUp(self) -> None:
        super().setUp()
        self.populate()

    def test_an_entry_matching_no_case_is_refused(self) -> None:
        payload = example_payload()
        entry_for(payload, "V-260470")["match"] = {"sourceRecordId": "V-999999"}

        error = self.assertRefused(
            EvaluationMatchError, lambda: self.evaluate(evaluations_of(payload))
        )

        self.assertIn("no case matches", str(error))
        self.assertIn("evaluations[0]", str(error))

    def test_an_ambiguous_entry_is_refused(self) -> None:
        source = ARTIFACTS[0].read_text(encoding="utf-8")
        twin = self.write_artifact(
            "ubuntu-host-2.cklb",
            source.replace("Canonical Ubuntu 24.04 LTS STIG", "Canonical Ubuntu 22.04 STIG"),
        )
        self.ingest([twin])
        self.correlate()
        payload = example_payload()
        entry_for(payload, "V-260470")["match"] = {"sourceRecordId": "V-260470"}

        error = self.assertRefused(
            EvaluationMatchError, lambda: self.evaluate(evaluations_of(payload))
        )

        self.assertIn("matches 2 cases", str(error))
        self.assertIn("contextKey", str(error))

    def test_two_entries_claiming_one_case_are_refused(self) -> None:
        payload = example_payload()
        payload["evaluations"].append(dict(entry_for(payload, "V-260470")))

        error = self.assertRefused(
            EvaluationMatchError, lambda: self.evaluate(evaluations_of(payload))
        )

        self.assertIn("is already evaluated by", str(error))
        self.assertIn(UBUNTU_CASE, str(error))

    def test_every_problem_in_one_file_is_reported_together(self) -> None:
        payload = example_payload()
        entry_for(payload, "V-260470")["match"] = {"sourceRecordId": "V-999999"}
        entry_for(payload, "V-253260")["match"] = {"sourceRecordId": "V-999998"}
        before = self.latest_sequence

        with self.assertRaises(EvaluationMatchError) as caught:
            self.evaluate(evaluations_of(payload))

        self.assertEqual(self.latest_sequence, before)
        self.assertEqual(len(caught.exception.problems), 2)


class EffectiveIdCollisionTests(WriterFixture):
    """The amendment: two cases may not end one run sharing one effective identifier."""

    def setUp(self) -> None:
        super().setUp()
        self.populate()

    def test_two_overrides_to_one_identifier_are_refused_in_one_run(self) -> None:
        payload = example_payload()
        entry_for(payload, "V-260470")["trackingId"] = "PROV-1"
        entry_for(payload, "V-253260")["trackingId"] = "PROV-1"

        error = self.assertRefused(
            EvaluationMatchError, lambda: self.evaluate(evaluations_of(payload))
        )

        self.assertIn("PROV-1", str(error))
        self.assertIn("is claimed by", str(error))
        self.assertIn(UBUNTU_CASE, str(error))
        self.assertIn(WINDOWS_CASE, str(error))

    def test_an_override_colliding_with_an_earlier_run_is_refused(self) -> None:
        first = example_payload()
        entry_for(first, "V-260470")["trackingId"] = "PROV-7"
        self.evaluate(evaluations_of(first))
        recorded = self.latest_sequence

        second = example_payload()
        drop_entry(second, "V-260470")
        entry_for(second, "V-253260")["trackingId"] = "PROV-7"
        error = self.assertRefused(
            EvaluationMatchError, lambda: self.evaluate(evaluations_of(second))
        )

        self.assertEqual(self.latest_sequence, recorded)
        self.assertIn("recorded history", str(error))
        self.assertIn("PROV-7", str(error))
        self.assertEqual(fold_case(self.repository, UBUNTU_CASE).effective_tracking_id, "PROV-7")

    def test_an_override_onto_another_case_correlation_id_is_refused(self) -> None:
        payload = example_payload()
        entry_for(payload, "V-260470")["trackingId"] = UNEVALUATED_CASE

        error = self.assertRefused(
            EvaluationMatchError, lambda: self.evaluate(evaluations_of(payload))
        )

        self.assertIn(UNEVALUATED_CASE, str(error))

    def test_distinct_overrides_are_accepted(self) -> None:
        payload = example_payload()
        entry_for(payload, "V-260470")["trackingId"] = "PROV-1"
        entry_for(payload, "V-253260")["trackingId"] = "PROV-2"

        outcome = self.evaluate(evaluations_of(payload))
        identifiers = {case.effective_tracking_id for case in fold_all_cases(self.repository)}

        self.assertEqual(outcome.identifications_appended, 2)
        self.assertIn("PROV-1", identifiers)
        self.assertIn("PROV-2", identifiers)

    def test_re_stating_the_same_override_appends_nothing(self) -> None:
        payload = example_payload()
        entry_for(payload, "V-260470")["trackingId"] = "PROV-1"
        self.evaluate(evaluations_of(payload))

        again = self.assertAppendsNothing(lambda: self.evaluate(evaluations_of(payload)))

        self.assertEqual(again.identifications_skipped, 1)
        self.assertEqual(again.warnings, ())


class RetainedFactTests(WriterFixture):
    """The amendment: omissions do not retract, and the operator is told so."""

    def setUp(self) -> None:
        super().setUp()
        self.populate()
        self.evaluate()

    def warnings_for(self, payload: Mapping[str, Any]) -> tuple[str, ...]:
        """Apply a mutated file and return the warnings it produced."""

        return self.evaluate(evaluations_of(payload)).warnings

    def test_dropping_a_pain_reduction_keeps_it_and_warns(self) -> None:
        payload = example_payload()
        entry_for(payload, "V-253260")["painReductionEvents"] = []

        warnings = self.warnings_for(payload)
        case = fold_case(self.repository, WINDOWS_CASE)

        self.assertEqual(len(warnings), 1)
        self.assertTrue(warnings[0].startswith("reduction_retained: "))
        self.assertIn(WINDOWS_CASE, warnings[0])
        self.assertIn("PAIN 4 at 2026-08-12T16:00:00Z", warnings[0])
        self.assertEqual(len(case.pain_reductions), 1)

    def test_omitting_the_reduction_key_entirely_warns_the_same_way(self) -> None:
        payload = example_payload()
        del entry_for(payload, "V-253260")["painReductionEvents"]

        warnings = self.warnings_for(payload)

        self.assertEqual(len(warnings), 1)
        self.assertTrue(warnings[0].startswith("reduction_retained: "))

    def test_dropping_a_disposition_keeps_it_and_warns(self) -> None:
        payload = example_payload()
        del entry_for(payload, "V-260470")["disposition"]

        warnings = self.warnings_for(payload)
        case = fold_case(self.repository, UBUNTU_CASE)
        disposition = case.disposition
        assert disposition is not None

        self.assertEqual(len(warnings), 1)
        self.assertTrue(warnings[0].startswith("disposition_retained: "))
        self.assertIn(UBUNTU_CASE, warnings[0])
        self.assertIn("partially_mitigated", warnings[0])
        self.assertEqual(disposition.status.value, "partially_mitigated")

    def test_dropping_a_tracking_id_override_keeps_it_and_warns(self) -> None:
        payload = example_payload()
        entry_for(payload, "V-260470")["trackingId"] = "PROV-7"
        self.evaluate(evaluations_of(payload))

        warnings = self.warnings_for(example_payload())
        case = fold_case(self.repository, UBUNTU_CASE)

        self.assertEqual(len(warnings), 1)
        self.assertTrue(warnings[0].startswith("identification_retained: "))
        self.assertIn(UBUNTU_CASE, warnings[0])
        self.assertIn("PROV-7", warnings[0])
        self.assertEqual(case.provider_tracking_id, "PROV-7")
        self.assertEqual(case.effective_tracking_id, "PROV-7")

    def test_a_retained_fact_appends_nothing(self) -> None:
        payload = example_payload()
        entry_for(payload, "V-253260")["painReductionEvents"] = []
        del entry_for(payload, "V-260470")["disposition"]

        outcome = self.assertAppendsNothing(lambda: self.evaluate(evaluations_of(payload)))

        self.assertEqual(outcome.appended, 0)
        self.assertEqual(len(outcome.warnings), 2)

    def test_an_entry_a_file_drops_entirely_warns_about_nothing(self) -> None:
        payload = example_payload()
        drop_entry(payload, "V-260470")

        warnings = self.warnings_for(payload)

        self.assertEqual(warnings, ())

    def test_a_file_that_states_everything_it_recorded_warns_about_nothing(self) -> None:
        self.assertEqual(self.evaluate().warnings, ())


class FoldRefusalTests(WriterFixture):
    """Stored payloads are untrusted bytes: a shape that does not fit raises."""

    def setUp(self) -> None:
        super().setUp()
        self.ingest()
        self.correlate()

    def test_a_case_stream_that_does_not_begin_with_creation_is_refused(self) -> None:
        stream_id = case_stream_id(SPARE_CASE)
        self.append_raw(
            stream_id,
            DETECTION_ATTESTED,
            {
                "detectedAt": iso_utc(ATTESTED_AT),
                "rationale": RATIONALE,
                "attestedAt": iso_utc(INGESTED_AT),
            },
            expected_version=0,
        )

        with self.assertRaises(HistoryError) as caught:
            fold_case(self.repository, SPARE_CASE)

        self.assertIn("begins with 'detection.attested'", str(caught.exception))

    def test_a_case_stream_whose_creation_names_another_tracking_id_is_refused(self) -> None:
        payload = self.case_created_payload(SPARE_CASE)
        payload["trackingId"] = "case-ffffffffffffffff"
        self.append_raw(case_stream_id(SPARE_CASE), CASE_CREATED, payload, expected_version=0)

        with self.assertRaises(HistoryError) as caught:
            fold_case(self.repository, SPARE_CASE)

        self.assertIn("records tracking id 'case-ffffffffffffffff'", str(caught.exception))

    def test_a_mismatched_creation_stops_every_reader_of_the_log(self) -> None:
        payload = self.case_created_payload(SPARE_CASE)
        payload["trackingId"] = "case-ffffffffffffffff"
        self.append_raw(case_stream_id(SPARE_CASE), CASE_CREATED, payload, expected_version=0)

        with self.assertRaises(HistoryError):
            fold_all_cases(self.repository)
        with self.assertRaises(HistoryError):
            self.evaluate()

    def test_a_case_stream_carrying_an_artifact_event_is_refused(self) -> None:
        stream_id = case_stream_id(SPARE_CASE)
        self.append_raw(
            stream_id, CASE_CREATED, self.case_created_payload(SPARE_CASE), expected_version=0
        )
        self.append_raw(
            stream_id,
            ARTIFACT_INGESTED,
            {
                "name": "ubuntu-host.cklb",
                "sha256": "a" * 64,
                "sizeBytes": 1,
                "mediaType": "application/json",
                "parserName": "complyroll.cklb",
                "parserVersion": "1",
                "ingestedAt": iso_utc(INGESTED_AT),
                "observationCount": 0,
                "diagnostics": [],
            },
            expected_version=1,
        )

        with self.assertRaises(HistoryError) as caught:
            fold_case(self.repository, SPARE_CASE)

        self.assertIn("unexpected event 'artifact.ingested'", str(caught.exception))

    def test_folding_a_case_no_stream_carries_is_refused(self) -> None:
        with self.assertRaises(CaseNotFoundError) as caught:
            fold_case(self.repository, SPARE_CASE)

        self.assertIn(SPARE_CASE, str(caught.exception))

    def test_a_history_listing_for_an_unknown_case_is_refused(self) -> None:
        with self.assertRaises(CaseNotFoundError):
            case_history(self.repository, SPARE_CASE)

    def test_a_stored_payload_that_broke_its_contract_is_refused(self) -> None:
        stream_id = case_stream_id(SPARE_CASE)
        self.append_raw(
            stream_id, CASE_CREATED, self.case_created_payload(SPARE_CASE), expected_version=0
        )
        self.repository.store.append(
            stream_id,
            [
                NewEvent(
                    event_type=CASE_PAIN_REDUCED,
                    occurred_at=INGESTED_AT,
                    payload={"reducedAt": iso_utc(ATTESTED_AT), "rating": 9},
                    metadata=self.metadata.to_dict(),
                )
            ],
            expected_version=1,
        )

        with self.assertRaises(EventContractError) as caught:
            fold_case(self.repository, SPARE_CASE)

        self.assertIn("case.pain_reduced version 1 payload is invalid", str(caught.exception))


class DispositionConsistencyTests(WriterFixture):
    """A stored disposition is untrusted bytes, so the fold re-checks its coherence.

    `reports.evaluations` refuses a closed case that names no closing disposition, an
    acceptance rationale on a status that accepts no risk, and an accepted risk with
    no rationale. The contract now refuses all three at append; the record refuses them
    again on the way back out, because a contract is only as good as the version that
    wrote the bytes being read.
    """

    def setUp(self) -> None:
        super().setUp()
        self.ingest([ARTIFACTS[0]])
        self.correlate()

    def record(self, **overrides: Any) -> DispositionRecord:
        """Build one folded disposition, coherent unless an override breaks it."""

        values: dict[str, Any] = {
            "sequence": 1,
            "status": CaseStatus.CLOSED,
            "closed_disposition": CaseStatus.REMEDIATED,
            "acceptance_rationale": None,
            "recorded_at": INGESTED_AT,
        }
        values.update(overrides)
        return DispositionRecord(**values)

    def payload(self, **overrides: Any) -> dict[str, Any]:
        """Return one `case.disposition_recorded` payload, coherent by default."""

        body: dict[str, Any] = {
            "status": "closed",
            "closedDisposition": "remediated",
            "acceptanceRationale": None,
            "recordedAt": iso_utc(INGESTED_AT),
        }
        body.update(overrides)
        return body

    def open_case(self) -> str:
        """Create one spare case stream and return its stream id."""

        stream_id = case_stream_id(SPARE_CASE)
        self.append_raw(
            stream_id, CASE_CREATED, self.case_created_payload(SPARE_CASE), expected_version=0
        )
        return stream_id

    def test_a_coherent_disposition_is_built(self) -> None:
        for label, values in (
            ("closed as remediated", {}),
            (
                "accepted with a rationale",
                {
                    "status": CaseStatus.ACCEPTED,
                    "closed_disposition": None,
                    "acceptance_rationale": "The agency accepts the residual risk.",
                },
            ),
            (
                "closed as accepted with a rationale",
                {
                    "closed_disposition": CaseStatus.ACCEPTED,
                    "acceptance_rationale": "The agency accepts the residual risk.",
                },
            ),
            (
                "false positive",
                {"status": CaseStatus.FALSE_POSITIVE, "closed_disposition": None},
            ),
        ):
            with self.subTest(shape=label):
                self.assertIsInstance(self.record(**values), DispositionRecord)

    def test_a_closed_case_must_name_what_it_closed_as(self) -> None:
        with self.assertRaisesRegex(HistoryError, "closedDisposition is required"):
            self.record(closed_disposition=None)

    def test_a_closing_disposition_needs_a_closed_status(self) -> None:
        with self.assertRaisesRegex(HistoryError, "closedDisposition is only valid"):
            self.record(status=CaseStatus.REMEDIATED)

    def test_a_rationale_needs_a_status_that_accepts_risk(self) -> None:
        with self.assertRaisesRegex(HistoryError, "acceptanceRationale is only valid"):
            self.record(
                status=CaseStatus.REMEDIATED,
                closed_disposition=None,
                acceptance_rationale="Nobody accepted anything.",
            )

    def test_accepting_risk_needs_a_rationale(self) -> None:
        for status, closed in (
            (CaseStatus.ACCEPTED, None),
            (CaseStatus.CLOSED, CaseStatus.ACCEPTED),
        ):
            with self.subTest(status=status.value):
                with self.assertRaisesRegex(
                    HistoryError, "acceptanceRationale is required"
                ):
                    self.record(status=status, closed_disposition=closed)

    def test_a_blank_rationale_is_no_rationale(self) -> None:
        with self.assertRaisesRegex(HistoryError, "acceptanceRationale is required"):
            self.record(
                status=CaseStatus.ACCEPTED,
                closed_disposition=None,
                acceptance_rationale="   ",
            )

    def test_the_repository_refuses_each_shape_the_parser_refuses(self) -> None:
        stream_id = self.open_case()
        for label, field_name, values in (
            ("closed names nothing", "closedDisposition", {"closedDisposition": None}),
            (
                "a closing disposition without a closed status",
                "closedDisposition",
                {"status": "remediated"},
            ),
            (
                "a rationale on a status that accepts no risk",
                "acceptanceRationale",
                {
                    "status": "remediated",
                    "closedDisposition": None,
                    "acceptanceRationale": "Nobody accepted anything.",
                },
            ),
            (
                "accepted with no rationale",
                "acceptanceRationale",
                {"status": "accepted", "closedDisposition": None},
            ),
            (
                "closed as accepted with no rationale",
                "acceptanceRationale",
                {"closedDisposition": "accepted"},
            ),
        ):
            with self.subTest(shape=label):
                error = self.assertRefused(
                    EventContractError,
                    lambda values=values: self.append_raw(  # type: ignore[misc]
                        stream_id,
                        CASE_DISPOSITION_RECORDED,
                        self.payload(**values),
                        expected_version=1,
                    ),
                )
                self.assertIn(f"/{field_name}", str(error))

    def test_a_blank_rationale_the_contract_admits_is_refused_by_the_fold(self) -> None:
        # `minLength: 1` cannot tell a rationale from three spaces, so this payload
        # reaches the store through the repository and is stopped on the way back.
        stream_id = self.open_case()
        self.append_raw(
            stream_id,
            CASE_DISPOSITION_RECORDED,
            self.payload(
                status="accepted", closedDisposition=None, acceptanceRationale="   "
            ),
            expected_version=1,
        )

        with self.assertRaises(HistoryError) as caught:
            fold_case(self.repository, SPARE_CASE)

        self.assertIn("acceptanceRationale is required", str(caught.exception))

    def test_a_stream_carrying_an_incoherent_disposition_is_refused(self) -> None:
        # Written straight into the store, around the repository that would have
        # refused it. The fold validates every payload against its contract before it
        # parses one, so the refusal arrives as a contract failure naming the field.
        stream_id = self.open_case()
        self.repository.store.append(
            stream_id,
            [
                NewEvent(
                    event_type=CASE_DISPOSITION_RECORDED,
                    occurred_at=INGESTED_AT,
                    payload=self.payload(closedDisposition=None),
                    metadata=self.metadata.to_dict(),
                )
            ],
            expected_version=1,
        )

        with self.assertRaises(EventContractError) as caught:
            fold_case(self.repository, SPARE_CASE)

        self.assertIn("/closedDisposition", str(caught.exception))


class StoredObservationTests(WriterFixture):
    """`observation.recorded` is a frozen contract, and the fold reads it strictly."""

    def stored_observation(self, **overrides: Any) -> dict[str, Any]:
        """Return one fixture observation's canonical dictionary, mutated in place."""

        result = ingest_stig_artifact(ARTIFACTS[0], ingested_at=INGESTED_AT)
        payload = result.observations[0].to_canonical_dict()
        payload.update(overrides)
        return payload

    def record(self, payload: Mapping[str, Any]) -> None:
        self.append_raw(
            artifact_stream_id("b" * 64, "complyroll.cklb", "1"),
            OBSERVATION_RECORDED,
            payload,
            expected_version=0,
        )

    def smuggle(self, payload: Mapping[str, Any]) -> None:
        """Store one observation payload around the repository, past its checks.

        The repository reads every observation payload back through the reader before
        storing it, so a payload the reader refuses can only reach the log through
        another writer, an older version, or hand editing. This is how such history
        comes to exist inside one test.
        """

        self.repository.store.append(
            artifact_stream_id("b" * 64, "complyroll.cklb", "1"),
            [
                NewEvent(
                    event_type=OBSERVATION_RECORDED,
                    occurred_at=INGESTED_AT,
                    payload=payload,
                    metadata=self.metadata.to_dict(),
                )
            ],
            expected_version=0,
        )

    def test_a_recorded_observation_rehydrates_to_an_equal_observation(self) -> None:
        self.ingest([ARTIFACTS[0]])
        expected = ingest_stig_artifact(ARTIFACTS[0], ingested_at=INGESTED_AT).observations

        self.assertEqual(rehydrate_observations(self.repository), expected)

    def test_a_tampered_fingerprint_is_refused(self) -> None:
        self.smuggle(self.stored_observation(fingerprint="c" * 64))

        with self.assertRaises(HistoryError) as caught:
            rehydrate_observations(self.repository)

        self.assertIn("fingerprint does not match", str(caught.exception))

    def test_a_tampered_field_that_moves_the_fingerprint_is_refused(self) -> None:
        self.smuggle(self.stored_observation(source_record_id="V-000000"))

        with self.assertRaises(HistoryError) as caught:
            rehydrate_observations(self.repository)

        self.assertIn("fingerprint does not match", str(caught.exception))

    def test_a_non_canonical_timestamp_is_refused_before_it_is_stored(self) -> None:
        # Six digits of fraction is what `isoformat` emits when there are any, so the
        # contract's pattern admits this text; the writer would never produce it for a
        # whole second. The repository therefore reads every observation payload back
        # through the reader before storing it, so the spelling never reaches the log.
        for text in (
            "2026-08-21T12:00:00.000000+00:00",
            "2026-08-21T12:00:00-00:00",
            "2026-08-21T12:00:00+24:00",
            "2026-02-30T12:00:00+00:00",
        ):
            with self.subTest(timestamp=text):
                error = self.assertRefused(
                    EventContractError,
                    lambda text=text: self.record(  # type: ignore[misc]
                        self.stored_observation(ingested_at=text)
                    ),
                )
                self.assertIn("is not readable", str(error))
        self.assertEqual(self.repository.store.latest_sequence, 0)

    def test_a_non_canonical_timestamp_stored_around_the_repository_is_refused(self) -> None:
        # History that reached the log without passing through the repository is still
        # read through the same reader, which refuses what the writer could not have
        # written.
        self.smuggle(self.stored_observation(ingested_at="2026-08-21T12:00:00.000000+00:00"))

        with self.assertRaises(HistoryError) as caught:
            rehydrate_observations(self.repository)

        self.assertIn("canonical timestamp text", str(caught.exception))
        self.assertIn("is not a readable observation", str(caught.exception))

    def test_the_contract_refuses_a_spelling_before_it_can_be_stored(self) -> None:
        # The other spellings never reach the reader at all: the repository refuses
        # them at append, so the log cannot hold history the replay path would choke
        # on (ADR 0008 Decision 1).
        for text in (
            "2026-08-21T12:00:00Z",
            "2026-08-21T12:00:00.000+00:00",
            "2026-08-21T12:00:00+01:02:03",
        ):
            with self.subTest(timestamp=text):
                error = self.assertRefused(
                    EventContractError,
                    lambda text=text: self.record(  # type: ignore[misc]
                        self.stored_observation(ingested_at=text)
                    ),
                )
                self.assertIn("/ingested_at", str(error))

    def test_a_tampered_payload_is_refused_before_it_is_stored(self) -> None:
        for overrides in (
            {"fingerprint": "c" * 64},
            {"source_record_id": "V-000000"},
            {"observation_id": "obs-someone-elses-name"},
        ):
            with self.subTest(overrides=overrides):
                error = self.assertRefused(
                    EventContractError,
                    lambda overrides=overrides: self.record(  # type: ignore[misc]
                        self.stored_observation(**overrides)
                    ),
                )
                self.assertIn("is not readable", str(error))
        self.assertEqual(self.repository.store.latest_sequence, 0)

    def test_an_artifact_observation_renamed_at_rest_is_refused(self) -> None:
        self.smuggle(self.stored_observation(observation_id="obs-someone-elses-name"))

        with self.assertRaises(HistoryError) as caught:
            rehydrate_observations(self.repository)

        self.assertIn("observation_id does not match", str(caught.exception))


if __name__ == "__main__":
    unittest.main()
