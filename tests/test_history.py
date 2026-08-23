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
from dataclasses import replace
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any
from unittest import mock

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
    AUDIT_FAULT_CODES,
    CASE_CREATED,
    CASE_DISPOSITION_RECORDED,
    CASE_EVALUATED,
    CASE_PAIN_REDUCED,
    DETECTION_ATTESTED,
    OBSERVATION_RECORDED,
    ArtifactRecord,
    AttestationOutcome,
    CaseNotFoundError,
    CorrelationOutcome,
    DispositionRecord,
    EvaluationMatchError,
    EvaluationOutcome,
    HistoryError,
    IngestOutcome,
    apply_evaluations,
    artifact_history,
    artifact_records,
    attest_detection,
    audit_history,
    case_history,
    correlate_cases,
    fold_all_cases,
    fold_case,
    record_ingest,
    rehydrate_observations,
    superseded_artifact_records,
)
from complyroll.history import writers as history_writers
from complyroll.history.fold import (
    _ArtifactStreamView,
    _is_numeric_version,
    _newest_stream,
)
from complyroll.models import CaseStatus, Observation
from complyroll.reports import EvaluationSet, load_evaluations, parse_evaluations
from complyroll.store import (
    EventStoreBusyError,
    EventStoreError,
    NewEvent,
    SQLiteEventStore,
)

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

#: A deterministic run identifier that is also a real one: `run-` plus a canonical
#: version-4 UUID, which is what `EventMetadata` now requires of every stored envelope.
RUN_ID = "run-00000000-0000-4000-8000-000000000002"

def relabelled(observation: Observation, source_record_id: str) -> Observation:
    """Return the same observation as a different finding on the same artifact.

    Both the fingerprint and the identifier of an artifact-bound observation derive from
    its fields, so moving the source record moves both. The result names the artifact its
    stream names, which keeps the identity check satisfied, and is a finding that stream
    does not already carry, which keeps it out of the duplicate check: an overfull stream
    and a stream holding one observation twice are different faults and need different
    fixtures.
    """

    moved = replace(observation, source_record_id=source_record_id)
    return replace(moved, observation_id=moved.derived_observation_id)


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
        self.metadata = EventMetadata(actor="tester", run_id=RUN_ID)

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

    def append_unchecked(
        self,
        stream_id: str,
        event_type: str,
        payload: Mapping[str, Any],
        *,
        expected_version: int,
    ) -> None:
        """Append one event straight to the store, past every check the repository makes.

        `EventRepository` refuses a payload no writer should produce, which is what makes
        it the wrong tool for staging one. History written by another tool, or by a
        version whose checks arrived later, is still history the fold has to survive, so
        the shapes the repository now turns away are staged underneath it.
        """

        self.repository.store.append(
            stream_id,
            [
                NewEvent(
                    event_type=event_type,
                    occurred_at=INGESTED_AT,
                    payload=dict(payload),
                    metadata=self.metadata.to_dict(),
                )
            ],
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
        # A finding of its own rather than a second copy of one the stream holds: a copy
        # is refused at append as a duplicate, and this test is about the count.
        spare = relabelled(
            ingest_stig_artifact(ARTIFACTS[0], ingested_at=INGESTED_AT).observations[0],
            "V-999999",
        )
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
        # A dropped reduction is fixed by a new evaluations entry, not by a disposition.
        # The warning said "a new disposition" here for a while, which sent the operator
        # to the wrong field of the file.
        self.assertIn("new evaluation entry with a rationale", warnings[0])
        self.assertNotIn("new disposition", warnings[0])
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
        # This one really is fixed by a new disposition, so the wording differs from the
        # reduction warning on purpose.
        self.assertIn("new disposition with a rationale", warnings[0])
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

    def mismatched_creation(self) -> None:
        """Stage a case stream whose creation event names a different case.

        The repository refuses this at append now, so it is staged underneath it. The
        fold still has to refuse it: the check that stops it being written protects new
        history, not the history already on disk.
        """

        payload = self.case_created_payload(SPARE_CASE)
        payload["trackingId"] = "case-ffffffffffffffff"
        self.append_unchecked(
            case_stream_id(SPARE_CASE), CASE_CREATED, payload, expected_version=0
        )

    def test_a_case_stream_whose_creation_names_another_tracking_id_is_refused(self) -> None:
        self.mismatched_creation()

        with self.assertRaises(HistoryError) as caught:
            fold_case(self.repository, SPARE_CASE)

        self.assertIn("records tracking id 'case-ffffffffffffffff'", str(caught.exception))

    def test_a_mismatched_creation_is_refused_at_append_as_well(self) -> None:
        payload = self.case_created_payload(SPARE_CASE)
        payload["trackingId"] = "case-ffffffffffffffff"

        error = self.assertRefused(
            EventContractError,
            lambda: self.append_raw(
                case_stream_id(SPARE_CASE), CASE_CREATED, payload, expected_version=0
            ),
        )

        self.assertIn("records tracking id 'case-ffffffffffffffff'", str(error))

    def test_a_mismatched_creation_stops_every_reader_of_the_log(self) -> None:
        self.mismatched_creation()

        with self.assertRaises(HistoryError):
            fold_all_cases(self.repository)
        with self.assertRaises(HistoryError):
            self.evaluate()

    def artifact_payload(self) -> dict[str, Any]:
        """Return one contract-valid `artifact.ingested` payload."""

        return {
            "name": "ubuntu-host.cklb",
            "sha256": "a" * 64,
            "sizeBytes": 1,
            "mediaType": "application/json",
            "parserName": "complyroll.cklb",
            "parserVersion": "1",
            "ingestedAt": iso_utc(INGESTED_AT),
            "observationCount": 0,
            "diagnostics": [],
        }

    def test_a_case_stream_carrying_an_artifact_event_is_refused(self) -> None:
        # Staged underneath the repository, which now turns this away at append. The
        # fold reads history other tools and older versions wrote, so it refuses too.
        stream_id = case_stream_id(SPARE_CASE)
        self.append_raw(
            stream_id, CASE_CREATED, self.case_created_payload(SPARE_CASE), expected_version=0
        )
        self.append_unchecked(
            stream_id, ARTIFACT_INGESTED, self.artifact_payload(), expected_version=1
        )

        with self.assertRaises(HistoryError) as caught:
            fold_case(self.repository, SPARE_CASE)

        self.assertIn("unexpected event 'artifact.ingested'", str(caught.exception))

    def test_an_artifact_event_on_a_case_stream_is_refused_at_append_as_well(self) -> None:
        stream_id = case_stream_id(SPARE_CASE)
        self.append_raw(
            stream_id, CASE_CREATED, self.case_created_payload(SPARE_CASE), expected_version=0
        )

        error = self.assertRefused(
            EventContractError,
            lambda: self.append_raw(
                stream_id, ARTIFACT_INGESTED, self.artifact_payload(), expected_version=1
            ),
        )

        self.assertIn("does not belong on stream", str(error))

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


#: Every `case.disposition_recorded` shape `reports.evaluations` refuses, paired with the
#: field a contract issue must point at. The fold used to re-raise three of these itself,
#: in branches no stored payload could reach because every reader validates first.
INCOHERENT_DISPOSITIONS: tuple[tuple[str, str, dict[str, Any]], ...] = (
    ("closed names no closing disposition", "closedDisposition", {"closedDisposition": None}),
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
    (
        "accepted with an empty rationale",
        "acceptanceRationale",
        {"status": "accepted", "closedDisposition": None, "acceptanceRationale": ""},
    ),
    (
        "accepted with a whitespace rationale",
        "acceptanceRationale",
        {"status": "accepted", "closedDisposition": None, "acceptanceRationale": "   "},
    ),
)


class DispositionConsistencyTests(WriterFixture):
    """A stored disposition is untrusted bytes, so every reader validates before it reads.

    `reports.evaluations` refuses a closed case that names no closing disposition, an
    acceptance rationale on a status that accepts no risk, and an accepted risk with no
    rationale, whitespace included. The contract refuses all four at append and every
    reader re-validates against the same contract on the way back out, so `DispositionRecord`
    carries no cross-field rule of its own: one rule set, checked in one place, and no
    shape `store verify` can certify that `report vdt --db` then refuses.
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

    def test_every_shape_rule_belongs_to_the_contract(self) -> None:
        # The record used to re-raise cross-field rules the contract's `allOf` already
        # decides, and no stored payload could ever reach them: every reader validates
        # against the contract before it builds a record. The refusal is asserted where
        # it happens, and building a record from values no payload can carry is the
        # caller's business rather than a second copy of the rule.
        for label, field_name, payload_values in INCOHERENT_DISPOSITIONS:
            with self.subTest(shape=label):
                with self.assertRaises(EventContractError) as caught:
                    self.repository.validate_payload(
                        CASE_DISPOSITION_RECORDED, self.payload(**payload_values)
                    )

                self.assertIn(f"/{field_name}", str(caught.exception))

    def test_accepting_risk_needs_a_rationale(self) -> None:
        # `_DISPOSITION_CONSISTENCY` in `complyroll.events.contracts` decides this, so the
        # refusal is asserted against the contract rather than against a second copy of
        # the rule inside `DispositionRecord`, which no longer carries one.
        for status, closed in (("accepted", None), ("closed", "accepted")):
            with self.subTest(status=status):
                with self.assertRaises(EventContractError) as caught:
                    self.repository.validate_payload(
                        CASE_DISPOSITION_RECORDED,
                        self.payload(
                            status=status,
                            closedDisposition=closed,
                            acceptanceRationale=None,
                        ),
                    )

                self.assertIn("/acceptanceRationale", str(caught.exception))

    def test_a_blank_rationale_is_no_rationale(self) -> None:
        # `minLength: 1` counts three spaces as a rationale, so `acceptanceRationale`
        # carries `_NON_BLANK_PATTERN` as well. This was the one rule the fold still kept
        # to itself, which is why a store `store verify` called clean was refused by
        # `report vdt --db` as invalid history.
        for blank in ("", " ", "   ", "\t", "\n", "\u00a0"):
            with self.subTest(rationale=repr(blank)):
                with self.assertRaises(EventContractError) as caught:
                    self.repository.validate_payload(
                        CASE_DISPOSITION_RECORDED,
                        self.payload(
                            status="accepted",
                            closedDisposition=None,
                            acceptanceRationale=blank,
                        ),
                    )

                self.assertIn("/acceptanceRationale", str(caught.exception))

    def test_a_real_rationale_is_accepted(self) -> None:
        # The other half of the rule: text with something in it still stores, and the
        # record built from it reads that text back unchanged.
        payload = self.payload(
            status="accepted",
            closedDisposition=None,
            acceptanceRationale=" The agency accepts the residual risk until the rebuild. ",
        )
        self.repository.validate_payload(CASE_DISPOSITION_RECORDED, payload)
        stream_id = self.open_case()
        self.append_raw(stream_id, CASE_DISPOSITION_RECORDED, payload, expected_version=1)

        disposition = fold_case(self.repository, SPARE_CASE).disposition

        self.assertIsNotNone(disposition)
        assert disposition is not None
        self.assertTrue(disposition.accepts_risk)
        self.assertEqual(
            disposition.acceptance_rationale,
            " The agency accepts the residual risk until the rebuild. ",
        )

    def test_the_repository_refuses_each_shape_the_parser_refuses(self) -> None:
        stream_id = self.open_case()
        for label, field_name, values in INCOHERENT_DISPOSITIONS:
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

    def test_a_smuggled_whitespace_rationale_is_refused_and_reported(self) -> None:
        # The repository refuses this payload now, so reaching the fold with it means
        # going around the repository. Written straight into the store, it is refused by
        # `fold_case` as a contract failure and reported by `audit_history` as one, which
        # is the pairing that was missing: the fold refused it and the audit did not.
        stream_id = self.open_case()
        self.append_unchecked(
            stream_id,
            CASE_DISPOSITION_RECORDED,
            self.payload(
                status="accepted", closedDisposition=None, acceptanceRationale="   "
            ),
            expected_version=1,
        )

        with self.assertRaises(EventContractError) as caught:
            fold_case(self.repository, SPARE_CASE)

        self.assertIn("/acceptanceRationale", str(caught.exception))
        faults = audit_history(self.repository)
        self.assertEqual([fault.code for fault in faults], ["payload_contract_invalid"])
        self.assertIn("/acceptanceRationale", faults[0].message)

    def test_a_stream_carrying_an_incoherent_disposition_is_refused(self) -> None:
        # Written straight into the store, around the repository that would have refused
        # it. The fold validates every payload against its contract before it parses one,
        # so the refusal is an `EventContractError` and not a `HistoryError`: the two are
        # siblings under `ValueError` and neither is the other. The class decides what an
        # operator reads, because `complyroll.cli` maps `EventContractError` to
        # `event_contract_invalid` and `HistoryError` to `history_invalid`. This is where
        # the branches the record used to carry are covered now that they are gone: each
        # shape gets its own case stream, so each refusal is attributed to its own shape.
        for index, (label, field_name, values) in enumerate(INCOHERENT_DISPOSITIONS):
            with self.subTest(shape=label):
                tracking_id = f"case-{index:016x}"
                stream_id = case_stream_id(tracking_id)
                self.append_raw(
                    stream_id,
                    CASE_CREATED,
                    self.case_created_payload(tracking_id),
                    expected_version=0,
                )
                self.repository.store.append(
                    stream_id,
                    [
                        NewEvent(
                            event_type=CASE_DISPOSITION_RECORDED,
                            occurred_at=INGESTED_AT,
                            payload=self.payload(**values),
                            metadata=self.metadata.to_dict(),
                        )
                    ],
                    expected_version=1,
                )

                with self.assertRaises(EventContractError) as caught:
                    fold_case(self.repository, tracking_id)

                self.assertIn(f"/{field_name}", str(caught.exception))
                self.assertIsInstance(caught.exception, ValueError)
                self.assertNotIsInstance(caught.exception, HistoryError)

    def test_every_reader_of_the_log_refuses_a_smuggled_incoherent_disposition(self) -> None:
        # `fold_all_cases` walks the whole log rather than one stream, so a single
        # incoherent disposition anywhere stops it too rather than folding into a
        # plausible-looking case beside the healthy ones. The class is `EventContractError`
        # here too, which is why `report vdt --db` reports `event_contract_invalid` for
        # this store rather than `history_invalid`.
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
            fold_all_cases(self.repository)

        self.assertIn("/closedDisposition", str(caught.exception))
        self.assertNotIsInstance(caught.exception, HistoryError)
        self.assertIn(
            "payload_contract_invalid",
            [fault.code for fault in audit_history(self.repository)],
        )


class StoredObservationTests(WriterFixture):
    """`observation.recorded` is a frozen contract, and the fold reads it strictly."""

    def stored_observation(self, **overrides: Any) -> dict[str, Any]:
        """Return one fixture observation's canonical dictionary, mutated in place."""

        result = ingest_stig_artifact(ARTIFACTS[0], ingested_at=INGESTED_AT)
        payload = result.observations[0].to_canonical_dict()
        payload.update(overrides)
        return payload

    def own_stream(self, payload: Mapping[str, Any]) -> str:
        """Return the artifact stream one observation payload's own identity names.

        Every check below is about the payload rather than about where it sits, so it is
        stored on the stream it belongs on; an observation on somebody else's stream is a
        different fault with its own test.
        """

        return artifact_stream_id(
            str(payload["source_artifact_digest"]),
            str(payload["parser_name"]),
            str(payload["parser_version"]),
        )

    def record(self, payload: Mapping[str, Any]) -> None:
        self.append_raw(
            self.own_stream(payload),
            OBSERVATION_RECORDED,
            payload,
            expected_version=0,
        )

    def smuggle(self, payload: Mapping[str, Any], *, stream_id: str | None = None) -> None:
        """Store one observation payload around the repository, past its checks.

        The repository reads every observation payload back through the reader before
        storing it, so a payload the reader refuses can only reach the log through
        another writer, an older version, or hand editing. This is how such history
        comes to exist inside one test.
        """

        self.repository.store.append(
            self.own_stream(payload) if stream_id is None else stream_id,
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

    def test_a_contract_invalid_payload_is_described_as_contract_invalid(self) -> None:
        # The identity check reads the payload, so a payload missing one of the three
        # identity keys used to be described as an event "on the wrong stream ... version
        # None": the check reporting a field the payload simply does not have, and
        # pointing the operator at the stream when the payload is what is wrong. The
        # payload is validated first now, so the fold and the audit say the same thing.
        payload = self.stored_observation()
        del payload["parser_version"]
        self.smuggle(payload, stream_id=self.own_stream(self.stored_observation()))

        for reader in (rehydrate_observations, artifact_records, artifact_history):
            with self.subTest(reader=reader.__name__):
                with self.assertRaises(HistoryError) as caught:
                    reader(self.repository)

                message = str(caught.exception)
                self.assertIn("is not a readable observation", message)
                self.assertIn("'parser_version' is a required property", message)
                self.assertNotIn("on the wrong stream", message)
                self.assertNotIn("version None", message)

        self.assertEqual(
            [fault.code for fault in audit_history(self.repository)],
            ["payload_contract_invalid"],
        )

    def test_a_contract_invalid_artifact_head_is_described_the_same_way(self) -> None:
        stream_id = self.own_stream(self.stored_observation())
        self.append_unchecked(
            stream_id,
            ARTIFACT_INGESTED,
            {"name": "ubuntu-host.cklb", "sha256": "not a digest"},
            expected_version=0,
        )

        with self.assertRaises(HistoryError) as caught:
            artifact_records(self.repository)

        self.assertIn("is not a readable artifact record", str(caught.exception))

    def test_an_observation_on_another_artifacts_stream_is_refused(self) -> None:
        # A payload the reader is perfectly happy with, stored on a stream that names
        # different bytes. Nothing in the payload is wrong, so the refusal has to come
        # from the disagreement between the payload and the stream.
        foreign = artifact_stream_id("b" * 64, "complyroll.cklb", "1")
        payload = self.stored_observation()
        self.smuggle(payload, stream_id=foreign)

        for reader in (rehydrate_observations, artifact_records, artifact_history):
            with self.subTest(reader=reader.__name__):
                with self.assertRaises(HistoryError) as caught:
                    reader(self.repository)

                message = str(caught.exception)
                self.assertIn("is on the wrong stream", message)
                self.assertIn("records digest", message)
                self.assertIn(str(payload["source_artifact_digest"]), message)
                self.assertIn(foreign, message)

    def test_an_artifact_event_naming_another_artifact_is_refused_by_the_fold(self) -> None:
        # The head of a stream can lie about its own identity the same way an observation
        # can. A stream whose artifact event names other bytes would report those bytes.
        foreign = artifact_stream_id("b" * 64, "complyroll.cklb", "1")
        self.repository.store.append(
            foreign,
            [
                NewEvent(
                    event_type=ARTIFACT_INGESTED,
                    occurred_at=INGESTED_AT,
                    payload={
                        "name": "ubuntu-host.cklb",
                        "sha256": "c" * 64,
                        "sizeBytes": 4096,
                        "mediaType": "application/json",
                        "parserName": "complyroll.cklb",
                        "parserVersion": "1",
                        "ingestedAt": iso_utc(INGESTED_AT),
                        "observationCount": 0,
                        "diagnostics": [],
                    },
                    metadata=self.metadata.to_dict(),
                )
            ],
            expected_version=0,
        )

        for reader in (rehydrate_observations, artifact_records, artifact_history):
            with self.subTest(reader=reader.__name__):
                with self.assertRaises(HistoryError) as caught:
                    reader(self.repository)

                message = str(caught.exception)
                self.assertIn("is on the wrong stream", message)
                self.assertIn("c" * 64, message)
                self.assertIn(foreign, message)


class _FailingRepository(EventRepository):
    """A repository that dies part way through writing one artifact.

    A crash between batches is the failure `record_ingest` has to survive, and it cannot be
    staged from outside: the writer decides how many batches to use. This stands in for the
    process that stopped, so the test can ask what the store kept.
    """

    def __init__(self, store: SQLiteEventStore, *, fail_on_batch: int) -> None:
        super().__init__(store)
        self.fail_on_batch = fail_on_batch
        self.batches = 0

    def append_batch(
        self,
        stream_id: str,
        events: Sequence[PendingEvent],
        *,
        expected_version: int,
    ) -> tuple[Any, ...]:
        self.batches += 1
        if self.batches == self.fail_on_batch:
            raise RuntimeError("the ingest process stopped between batches")
        return super().append_batch(stream_id, events, expected_version=expected_version)


class ConcurrentWriterTests(WriterFixture):
    """Two runs of one command may not both fold a store neither of them has finished.

    The effective-tracking-id rule is a claim about every case in the log. Two runs that
    each folded the store without the other's writes could both pass it and both commit the
    same provider identifier, leaving history in a shape `report vdt` refuses to compile.
    The writers hold one `BEGIN IMMEDIATE` from the fold to the last append, so the second
    run waits, re-folds, and sees the first.
    """

    def setUp(self) -> None:
        super().setUp()
        self.populate()

    def other_repository(self, *, busy_timeout_ms: int = 100) -> EventRepository:
        """Open a second store on the same file, as a second run of a command would."""

        store = SQLiteEventStore(self.database, busy_timeout_ms=busy_timeout_ms)
        self.addCleanup(store.close)
        return EventRepository(store)

    def test_a_second_evaluate_is_busy_while_the_first_holds_the_write_lock(self) -> None:
        other = self.other_repository()
        payload = example_payload()
        entry_for(payload, "V-260470")["trackingId"] = "PROV-1"

        with self.repository.transaction():
            with self.assertRaises(EventStoreBusyError):
                apply_evaluations(
                    other, evaluations_of(payload), metadata=self.metadata, now=INGESTED_AT
                )

        self.assertEqual(self.latest_sequence, other.store.latest_sequence)
        self.assertEqual(
            [case.effective_tracking_id for case in fold_all_cases(other)],
            [case.tracking_id for case in fold_all_cases(other)],
        )

    def test_every_writing_command_takes_the_write_lock(self) -> None:
        other = self.other_repository()
        result = ingest_stig_artifact(ARTIFACTS[0], ingested_at=INGESTED_AT)

        with self.repository.transaction():
            with self.assertRaises(EventStoreBusyError):
                correlate_cases(other, metadata=self.metadata, now=INGESTED_AT)
            with self.assertRaises(EventStoreBusyError):
                attest_detection(
                    other,
                    [UBUNTU_CASE],
                    detected_at=ATTESTED_AT,
                    rationale=RATIONALE,
                    metadata=self.metadata,
                    now=INGESTED_AT,
                )
            with self.assertRaises(EventStoreBusyError):
                record_ingest(
                    other, result, metadata=self.metadata, ingested_at=INGESTED_AT
                )

    def test_the_second_run_re_folds_and_refuses_the_collision_the_first_committed(
        self,
    ) -> None:
        first = example_payload()
        entry_for(first, "V-260470")["trackingId"] = "PROV-7"
        second = example_payload()
        drop_entry(second, "V-260470")
        entry_for(second, "V-253260")["trackingId"] = "PROV-7"
        other = self.other_repository()

        apply_evaluations(
            self.repository, evaluations_of(first), metadata=self.metadata, now=INGESTED_AT
        )
        committed = self.latest_sequence
        with self.assertRaises(EvaluationMatchError) as caught:
            apply_evaluations(
                other, evaluations_of(second), metadata=self.metadata, now=INGESTED_AT
            )

        self.assertIn("PROV-7", str(caught.exception))
        self.assertIn("is claimed by", str(caught.exception))
        self.assertEqual(self.latest_sequence, committed)

    def test_the_folded_store_never_carries_two_identical_effective_ids(self) -> None:
        first = example_payload()
        entry_for(first, "V-260470")["trackingId"] = "PROV-7"
        second = example_payload()
        drop_entry(second, "V-260470")
        entry_for(second, "V-253260")["trackingId"] = "PROV-7"
        other = self.other_repository()

        apply_evaluations(
            self.repository, evaluations_of(first), metadata=self.metadata, now=INGESTED_AT
        )
        with self.assertRaises(EvaluationMatchError):
            apply_evaluations(
                other, evaluations_of(second), metadata=self.metadata, now=INGESTED_AT
            )

        identifiers = [case.effective_tracking_id for case in fold_all_cases(other)]
        self.assertIn("PROV-7", identifiers)
        self.assertEqual(len(identifiers), len(set(identifiers)))

    def test_the_store_still_refuses_a_nested_transaction(self) -> None:
        # The writers join an open transaction rather than opening one, but the store's
        # own guard is unchanged: a second `transaction()` is still refused rather than
        # opening an inner scope whose commit would not be one.
        with self.repository.transaction():
            with self.assertRaises(EventStoreError) as caught:
                with self.repository.transaction():
                    pass  # pragma: no cover - the guard raises on the way in

        self.assertIn("already inside a transaction", str(caught.exception))


class BatchedWriterTests(WriterFixture):
    """Several writer calls can be made one transaction, so a batch is all-or-nothing.

    Each writer is atomic on its own, which left `complyroll ingest` recording artifact
    one durably and then failing on artifact two while its buffered summary printed
    nothing. A writer now joins a transaction its caller already holds, so the caller
    decides where the boundary is (ADR 0008, second amendment).
    """

    def artifact_stream(self, path: Path) -> str:
        result = ingest_stig_artifact(path, ingested_at=INGESTED_AT)
        artifact = result.artifact
        assert artifact is not None
        return artifact_stream_id(
            artifact.digest_sha256, artifact.parser_name, artifact.parser_version
        )

    def record(self, path: Path) -> IngestOutcome:
        return record_ingest(
            self.repository,
            ingest_stig_artifact(path, ingested_at=INGESTED_AT),
            metadata=self.metadata,
            ingested_at=INGESTED_AT,
        )

    def test_a_writer_inside_an_open_transaction_commits_with_the_block(self) -> None:
        with self.repository.transaction():
            self.record(ARTIFACTS[0])
            self.record(ARTIFACTS[1])

        self.assertEqual(len(artifact_records(self.repository)), 2)
        self.assertEqual(audit_history(self.repository), ())

    def test_a_failure_after_the_first_writer_rolls_both_back(self) -> None:
        before = self.latest_sequence

        with self.assertRaisesRegex(RuntimeError, "the run stopped"):
            with self.repository.transaction():
                self.record(ARTIFACTS[0])
                raise RuntimeError("the run stopped on the second artifact")

        self.assertEqual(self.latest_sequence, before)
        self.assertEqual(self.repository.read_stream(self.artifact_stream(ARTIFACTS[0])), ())

    def test_a_refused_second_artifact_leaves_the_first_out_of_history(self) -> None:
        # What the command surface needs: a run that fails on artifact two is a run that
        # recorded nothing, so an empty summary and an empty store say the same thing.
        first = self.artifact_stream(ARTIFACTS[0])
        with self.assertRaises(EventContractError):
            with self.repository.transaction():
                self.record(ARTIFACTS[0])
                self.repository.append(
                    first,
                    CASE_CREATED,
                    self.case_created_payload(SPARE_CASE),
                    occurred_at=INGESTED_AT,
                    metadata=self.metadata,
                    expected_version=self.repository.current_version(first),
                )

        self.assertEqual(self.latest_sequence, 0)
        self.assertEqual(artifact_records(self.repository), ())

    def test_every_writer_joins_a_transaction_the_caller_holds(self) -> None:
        before = self.latest_sequence

        with self.assertRaisesRegex(RuntimeError, "the run stopped"):
            with self.repository.transaction():
                for path in ARTIFACTS:
                    self.record(path)
                correlate_cases(self.repository, metadata=self.metadata, now=INGESTED_AT)
                attest_detection(
                    self.repository,
                    self.tracking_ids(),
                    detected_at=ATTESTED_AT,
                    rationale=RATIONALE,
                    metadata=self.metadata,
                    now=INGESTED_AT,
                )
                apply_evaluations(
                    self.repository,
                    load_evaluations(EXAMPLES / "evaluations.json"),
                    metadata=self.metadata,
                    now=INGESTED_AT,
                )
                raise RuntimeError("the run stopped after every writer")

        self.assertEqual(self.latest_sequence, before)
        self.assertEqual(fold_all_cases(self.repository), ())

    def test_the_writers_own_scope_is_a_no_op_inside_an_open_transaction(self) -> None:
        # `SQLiteEventStore.transaction` refuses to nest, so a writer that opened its own
        # unconditionally could not be called inside a caller's block at all. Joining is
        # what makes the caller's boundary the only one.
        with self.repository.transaction():
            self.assertTrue(self.repository.store.in_transaction)
            self.record(ARTIFACTS[0])
            self.assertTrue(self.repository.store.in_transaction)

        self.assertFalse(self.repository.store.in_transaction)

    def test_the_batch_is_durable_for_another_connection_once_the_block_exits(self) -> None:
        # Reading back through the writer's own connection cannot tell a commit from an
        # open transaction. A second connection can.
        with self.repository.transaction():
            self.record(ARTIFACTS[0])
            self.record(ARTIFACTS[1])

        reader = SQLiteEventStore(self.database, busy_timeout_ms=100)
        self.addCleanup(reader.close)

        self.assertEqual(len(artifact_records(EventRepository(reader))), 2)

    def test_nothing_reaches_another_connection_when_the_block_fails(self) -> None:
        with self.assertRaisesRegex(RuntimeError, "the run stopped"):
            with self.repository.transaction():
                self.record(ARTIFACTS[0])
                self.record(ARTIFACTS[1])
                raise RuntimeError("the run stopped after the second artifact")

        reader = SQLiteEventStore(self.database, busy_timeout_ms=100)
        self.addCleanup(reader.close)

        self.assertEqual(artifact_records(EventRepository(reader)), ())
        self.assertEqual(EventRepository(reader).store.latest_sequence, 0)

    def test_a_writer_on_its_own_still_commits_on_its_own(self) -> None:
        self.record(ARTIFACTS[0])

        self.assertFalse(self.repository.store.in_transaction)
        self.assertEqual(len(artifact_records(self.repository)), 1)

    def test_a_lone_writer_is_durable_for_another_connection(self) -> None:
        self.record(ARTIFACTS[0])

        reader = SQLiteEventStore(self.database, busy_timeout_ms=100)
        self.addCleanup(reader.close)

        self.assertEqual(len(artifact_records(EventRepository(reader))), 1)


class AtomicIngestTests(WriterFixture):
    """One artifact is one transaction: every observation, or none of them.

    An artifact event declares its observation count. A run that died between batches used
    to leave that claim standing over a prefix, and both `store verify` and the replay
    accepted it, so a report could quietly cover fewer findings than the artifact held.
    """

    def artifact_stream(self, path: Path) -> str:
        result = ingest_stig_artifact(path, ingested_at=INGESTED_AT)
        artifact = result.artifact
        assert artifact is not None
        return artifact_stream_id(
            artifact.digest_sha256, artifact.parser_name, artifact.parser_version
        )

    def test_a_failure_between_batches_records_nothing(self) -> None:
        stream_id = self.artifact_stream(ARTIFACTS[0])
        result = ingest_stig_artifact(ARTIFACTS[0], ingested_at=INGESTED_AT)
        failing = _FailingRepository(self.repository.store, fail_on_batch=2)

        with mock.patch.object(history_writers, "MAX_BATCH_EVENTS", 2):
            with self.assertRaisesRegex(RuntimeError, "stopped between batches"):
                record_ingest(
                    failing, result, metadata=self.metadata, ingested_at=INGESTED_AT
                )

        self.assertGreater(failing.batches, 1)
        self.assertEqual(self.latest_sequence, 0)
        self.assertEqual(self.repository.read_stream(stream_id), ())

    def test_the_artifact_can_be_recorded_again_after_a_failed_run(self) -> None:
        stream_id = self.artifact_stream(ARTIFACTS[0])
        result = ingest_stig_artifact(ARTIFACTS[0], ingested_at=INGESTED_AT)
        failing = _FailingRepository(self.repository.store, fail_on_batch=2)
        with mock.patch.object(history_writers, "MAX_BATCH_EVENTS", 2):
            with self.assertRaises(RuntimeError):
                record_ingest(
                    failing, result, metadata=self.metadata, ingested_at=INGESTED_AT
                )

        outcome = self.ingest([ARTIFACTS[0]])[0]

        self.assertTrue(outcome.appended)
        self.assertEqual(
            len(self.repository.read_stream(stream_id)), len(result.observations) + 1
        )
        self.assertEqual(rehydrate_observations(self.repository), result.observations)

    def test_a_recorded_artifact_is_committed_for_another_connection(self) -> None:
        self.ingest([ARTIFACTS[0]])
        reader = SQLiteEventStore(self.database, busy_timeout_ms=100)
        self.addCleanup(reader.close)

        observations = rehydrate_observations(EventRepository(reader))

        self.assertEqual(
            observations, ingest_stig_artifact(ARTIFACTS[0], ingested_at=INGESTED_AT).observations
        )

    def test_many_batches_still_commit_as_one_artifact(self) -> None:
        stream_id = self.artifact_stream(ARTIFACTS[0])
        result = ingest_stig_artifact(ARTIFACTS[0], ingested_at=INGESTED_AT)

        with mock.patch.object(history_writers, "MAX_BATCH_EVENTS", 2):
            outcome = record_ingest(
                self.repository, result, metadata=self.metadata, ingested_at=INGESTED_AT
            )

        self.assertTrue(outcome.appended)
        self.assertEqual(
            len(self.repository.read_stream(stream_id)), len(result.observations) + 1
        )


class IncompleteArtifactTests(WriterFixture):
    """A stream holding fewer observations than it declared is refused, not reported from."""

    def setUp(self) -> None:
        super().setUp()
        self.stream_id, self.total = self.interrupt_ingest(ARTIFACTS[0], keep=2)

    def test_the_fold_refuses_an_incomplete_artifact_stream(self) -> None:
        for reader in (artifact_records, rehydrate_observations, artifact_history):
            with self.subTest(reader=reader.__name__):
                with self.assertRaises(HistoryError) as caught:
                    reader(self.repository)

                self.assertEqual(
                    str(caught.exception),
                    f"artifact stream {self.stream_id!r} is incomplete: declared "
                    f"{self.total} observations, found 2",
                )

    def test_the_audit_reports_it_instead_of_raising(self) -> None:
        faults = audit_history(self.repository)

        self.assertEqual([fault.code for fault in faults], ["artifact_incomplete"])
        self.assertEqual(faults[0].sequence, 1)
        self.assertIn(f"declared {self.total} observations, found 2", faults[0].message)

    def test_resuming_the_stream_makes_it_readable_again(self) -> None:
        self.ingest([ARTIFACTS[0]])

        self.assertEqual(audit_history(self.repository), ())
        self.assertEqual(len(artifact_records(self.repository)), 1)
        self.assertEqual(
            rehydrate_observations(self.repository),
            ingest_stig_artifact(ARTIFACTS[0], ingested_at=INGESTED_AT).observations,
        )


class OverfullArtifactTests(WriterFixture):
    """A stream holding more observations than it declared is refused, not reported from.

    The mirror image of an incomplete stream. An incomplete one understates its artifact;
    an overfull one puts a finding in the report the artifact never carried, because the
    extra observation was copied in from somewhere else and counted twice (ADR 0008,
    second amendment).
    """

    def setUp(self) -> None:
        super().setUp()
        self.parsed = ingest_stig_artifact(ARTIFACTS[0], ingested_at=INGESTED_AT)
        artifact = self.parsed.artifact
        assert artifact is not None
        self.stream_id = artifact_stream_id(
            artifact.digest_sha256, artifact.parser_name, artifact.parser_version
        )
        self.total = len(self.parsed.observations)
        self.ingest([ARTIFACTS[0]])
        # One more finding on the stream's own artifact: it names exactly the artifact the
        # stream names and is not a repeat of anything already there, so nothing but the
        # count is out of place. A repeat is a duplicate, which is its own fault code.
        self.extra = relabelled(self.parsed.observations[0], "V-999999")
        self.append_unchecked(
            self.stream_id,
            OBSERVATION_RECORDED,
            self.extra.to_canonical_dict(),
            expected_version=self.total + 1,
        )

    def test_the_fold_refuses_an_overfull_artifact_stream(self) -> None:
        for reader in (artifact_records, rehydrate_observations, artifact_history):
            with self.subTest(reader=reader.__name__):
                with self.assertRaises(HistoryError) as caught:
                    reader(self.repository)

                self.assertEqual(
                    str(caught.exception),
                    f"artifact stream {self.stream_id!r} is overfull: declared "
                    f"{self.total} observations, found {self.total + 1}",
                )

    def test_the_audit_reports_it_instead_of_raising(self) -> None:
        faults = audit_history(self.repository)

        self.assertEqual([fault.code for fault in faults], ["artifact_overfull"])
        self.assertEqual(faults[0].sequence, 1)
        self.assertIn(
            f"declared {self.total} observations, found {self.total + 1}",
            faults[0].message,
        )

    def test_a_later_head_cannot_revise_the_count_the_first_one_declared(self) -> None:
        # The first `artifact.ingested` on a stream is the head of record, so appending a
        # second one that declares the larger count does not talk the fault away.
        self.append_unchecked(
            self.stream_id,
            ARTIFACT_INGESTED,
            {
                "name": "ubuntu-host.cklb",
                "sha256": self.parsed.artifact.digest_sha256 if self.parsed.artifact else "",
                "sizeBytes": 4096,
                "mediaType": "application/json",
                "parserName": "complyroll.cklb",
                "parserVersion": "1",
                "ingestedAt": iso_utc(INGESTED_AT),
                "observationCount": self.total + 1,
                "diagnostics": [],
            },
            expected_version=self.total + 2,
        )

        self.assertEqual(
            [fault.code for fault in audit_history(self.repository)], ["artifact_overfull"]
        )
        with self.assertRaises(HistoryError):
            rehydrate_observations(self.repository)

    def test_the_overfull_code_is_published(self) -> None:
        self.assertIn("artifact_overfull", AUDIT_FAULT_CODES)


class DuplicateObservationTests(WriterFixture):
    """A head that declares the larger count and carries copies is a forged stream.

    The count check adds up and the identity check is satisfied, because every event names
    exactly the artifact its stream names. What is wrong is that one observation identifier
    appears twice, so one finding rehydrates twice and the report carries it twice
    (ADR 0008, second amendment).
    """

    def setUp(self) -> None:
        super().setUp()
        self.parsed = ingest_stig_artifact(ARTIFACTS[0], ingested_at=INGESTED_AT)
        artifact = self.parsed.artifact
        assert artifact is not None
        self.stream_id = artifact_stream_id(
            artifact.digest_sha256, artifact.parser_name, artifact.parser_version
        )
        self.observation = self.parsed.observations[0]
        self.append_raw(
            self.stream_id,
            ARTIFACT_INGESTED,
            {
                "name": artifact.name,
                "sha256": artifact.digest_sha256,
                "sizeBytes": artifact.size_bytes,
                "mediaType": artifact.media_type,
                "parserName": artifact.parser_name,
                "parserVersion": artifact.parser_version,
                "ingestedAt": iso_utc(INGESTED_AT),
                "observationCount": 2,
                "diagnostics": [],
            },
            expected_version=0,
        )
        payload = self.observation.to_canonical_dict()
        self.append_unchecked(
            self.stream_id, OBSERVATION_RECORDED, payload, expected_version=1
        )
        self.append_unchecked(
            self.stream_id, OBSERVATION_RECORDED, payload, expected_version=2
        )
        self.duplicate_sequence = self.repository.store.latest_sequence

    def test_the_count_and_the_identity_checks_both_pass(self) -> None:
        # The point of the fixture: neither older check can see this, which is why the
        # stream needed a check of its own.
        records = self.repository.read_stream(self.stream_id)
        observations = [
            record for record in records if record.event_type == OBSERVATION_RECORDED
        ]

        self.assertEqual(records[0].payload["observationCount"], len(observations))
        self.assertEqual(
            {record.payload["source_artifact_digest"] for record in observations},
            {self.parsed.artifact.digest_sha256 if self.parsed.artifact else ""},
        )

    def test_the_fold_refuses_a_repeated_observation(self) -> None:
        for reader in (artifact_records, rehydrate_observations, artifact_history):
            with self.subTest(reader=reader.__name__):
                with self.assertRaises(HistoryError) as caught:
                    reader(self.repository)

                message = str(caught.exception)
                self.assertIn(self.stream_id, message)
                self.assertIn(self.observation.observation_id, message)
                self.assertIn("more than once", message)

    def test_the_audit_reports_it_instead_of_raising(self) -> None:
        faults = audit_history(self.repository)

        self.assertEqual([fault.code for fault in faults], ["artifact_duplicate_observation"])
        self.assertEqual(faults[0].sequence, self.duplicate_sequence)
        self.assertIn(self.observation.observation_id, faults[0].message)

    def test_the_audit_reports_the_repeat_rather_than_the_first_copy(self) -> None:
        # The first copy is history; the second is the one that puts a finding in the
        # report twice, so it is the event the fault is attributed to.
        first = next(
            record
            for record in self.repository.read_stream(self.stream_id)
            if record.event_type == OBSERVATION_RECORDED
        )

        self.assertNotEqual(audit_history(self.repository)[0].sequence, first.sequence)

    def test_the_writer_refuses_to_add_a_third_copy(self) -> None:
        error = self.assertRefused(
            EventContractError,
            lambda: self.append_raw(
                self.stream_id,
                OBSERVATION_RECORDED,
                self.observation.to_canonical_dict(),
                expected_version=3,
            ),
        )

        self.assertIn("more than once", str(error))

    def test_the_duplicate_code_is_published(self) -> None:
        self.assertIn("artifact_duplicate_observation", AUDIT_FAULT_CODES)
        self.assertEqual(list(AUDIT_FAULT_CODES), sorted(AUDIT_FAULT_CODES))

    def test_a_clean_stream_of_distinct_findings_is_read_normally(self) -> None:
        # The control: the same shape with two different findings reads back as two.
        store = SQLiteEventStore(":memory:")
        self.addCleanup(store.close)
        self.repository = EventRepository(store)
        self.ingest([ARTIFACTS[0]])

        self.assertEqual(audit_history(self.repository), ())
        self.assertEqual(
            len(rehydrate_observations(self.repository)), len(self.parsed.observations)
        )


class AuditHistoryTests(WriterFixture):
    """`audit_history` describes a damaged log rather than stopping at its first problem."""

    def setUp(self) -> None:
        super().setUp()
        self.ingest([ARTIFACTS[0]])
        self.correlate()

    def spare_stream(self) -> str:
        return case_stream_id(SPARE_CASE)

    def append_with_metadata(
        self,
        stream_id: str,
        event_type: str,
        payload: Mapping[str, Any],
        metadata: Mapping[str, str],
        *,
        expected_version: int,
    ) -> None:
        """Write one event with an envelope the repository would refuse."""

        self.repository.store.append(
            stream_id,
            [
                NewEvent(
                    event_type=event_type,
                    occurred_at=INGESTED_AT,
                    payload=dict(payload),
                    metadata=dict(metadata),
                )
            ],
            expected_version=expected_version,
        )

    def test_a_healthy_log_reports_nothing(self) -> None:
        self.ingest()
        self.correlate()
        self.attest()
        self.evaluate()

        self.assertEqual(audit_history(self.repository), ())

    def test_the_published_codes_are_the_ones_the_audit_can_report(self) -> None:
        self.assertEqual(AUDIT_FAULT_CODES, tuple(sorted(AUDIT_FAULT_CODES)))
        for code in (
            "artifact_incomplete",
            "artifact_overfull",
            "artifact_stream_mismatch",
            "case_tracking_id_mismatch",
            "event_metadata_invalid",
            "event_stream_mismatch",
            "payload_contract_invalid",
        ):
            with self.subTest(code=code):
                self.assertIn(code, AUDIT_FAULT_CODES)

    def test_a_payload_that_broke_its_contract_is_reported(self) -> None:
        self.append_unchecked(
            self.spare_stream(),
            CASE_CREATED,
            self.case_created_payload(SPARE_CASE),
            expected_version=0,
        )
        self.append_unchecked(
            self.spare_stream(),
            CASE_PAIN_REDUCED,
            {"reducedAt": iso_utc(ATTESTED_AT), "rating": 9},
            expected_version=1,
        )

        faults = audit_history(self.repository)

        self.assertEqual([fault.code for fault in faults], ["payload_contract_invalid"])
        self.assertIn("/rating", faults[0].message)

    def test_an_impossible_instant_at_rest_is_reported(self) -> None:
        self.append_unchecked(
            self.spare_stream(),
            CASE_CREATED,
            {**self.case_created_payload(SPARE_CASE), "createdAt": "2026-02-30T12:00:00Z"},
            expected_version=0,
        )

        faults = audit_history(self.repository)

        self.assertEqual([fault.code for fault in faults], ["payload_contract_invalid"])
        self.assertIn("/createdAt", faults[0].message)

    def test_an_observation_the_reader_refuses_is_reported(self) -> None:
        # The audit runs the same reader the replay runs, so a payload that satisfies the
        # schema and not the reader is a fault rather than a clean bill of health.
        parsed = ingest_stig_artifact(ARTIFACTS[0], ingested_at=INGESTED_AT)
        payload = parsed.observations[0].to_canonical_dict()
        payload["fingerprint"] = "c" * 64
        self.append_unchecked(
            artifact_stream_id("b" * 64, "complyroll.cklb", "1"),
            OBSERVATION_RECORDED,
            payload,
            expected_version=0,
        )

        faults = audit_history(self.repository)

        self.assertEqual([fault.code for fault in faults], ["payload_contract_invalid"])
        self.assertIn("not readable", faults[0].message)

    def test_an_event_on_the_wrong_kind_of_stream_is_reported(self) -> None:
        self.append_unchecked(
            artifact_stream_id("b" * 64, "complyroll.cklb", "1"),
            CASE_CREATED,
            self.case_created_payload(SPARE_CASE),
            expected_version=0,
        )

        faults = audit_history(self.repository)

        self.assertEqual([fault.code for fault in faults], ["event_stream_mismatch"])
        self.assertIn("case.created", faults[0].message)
        self.assertIn("artifact/", faults[0].message)

    def test_a_creation_naming_another_case_is_reported(self) -> None:
        payload = self.case_created_payload(SPARE_CASE)
        payload["trackingId"] = "case-ffffffffffffffff"
        self.append_unchecked(self.spare_stream(), CASE_CREATED, payload, expected_version=0)

        faults = audit_history(self.repository)

        self.assertEqual([fault.code for fault in faults], ["case_tracking_id_mismatch"])
        self.assertIn("case-ffffffffffffffff", faults[0].message)
        self.assertIn(SPARE_CASE, faults[0].message)

    def test_a_metadata_envelope_outside_the_rules_is_reported(self) -> None:
        self.append_with_metadata(
            self.spare_stream(),
            CASE_CREATED,
            self.case_created_payload(SPARE_CASE),
            {
                "actor": "kyle",
                "method": "not-cli",
                "tool": "complyroll",
                "toolVersion": "0.1.0",
                "runId": "run-not-run-uuid4",
            },
            expected_version=0,
        )

        faults = audit_history(self.repository)

        self.assertEqual([fault.code for fault in faults], ["event_metadata_invalid"])
        self.assertIn("method", faults[0].message)
        self.assertIn("runId", faults[0].message)

    def test_an_observation_on_another_artifacts_stream_is_reported(self) -> None:
        # The stored mirror of the append refusal: history that reached the log before the
        # check existed has to be described rather than silently rehydrated.
        foreign = artifact_stream_id("b" * 64, "complyroll.cklb", "1")
        payload = ingest_stig_artifact(
            ARTIFACTS[0], ingested_at=INGESTED_AT
        ).observations[0].to_canonical_dict()
        self.append_unchecked(foreign, OBSERVATION_RECORDED, payload, expected_version=0)

        faults = audit_history(self.repository)

        self.assertEqual([fault.code for fault in faults], ["artifact_stream_mismatch"])
        self.assertIn("observation.recorded records digest", faults[0].message)
        self.assertIn(str(payload["source_artifact_digest"]), faults[0].message)
        self.assertIn(foreign, faults[0].message)

    def test_an_artifact_event_naming_another_artifact_is_reported(self) -> None:
        # `observationCount: 0` leaves the stream complete, so the identity fault is the
        # only thing the audit has to say about it.
        foreign = artifact_stream_id("b" * 64, "complyroll.cklb", "1")
        self.append_unchecked(
            foreign,
            ARTIFACT_INGESTED,
            {
                "name": "ubuntu-host.cklb",
                "sha256": "c" * 64,
                "sizeBytes": 4096,
                "mediaType": "application/json",
                "parserName": "complyroll.cklb",
                "parserVersion": "1",
                "ingestedAt": iso_utc(INGESTED_AT),
                "observationCount": 0,
                "diagnostics": [],
            },
            expected_version=0,
        )

        faults = audit_history(self.repository)

        self.assertEqual([fault.code for fault in faults], ["artifact_stream_mismatch"])
        self.assertIn("artifact.ingested records digest", faults[0].message)
        self.assertIn("c" * 64, faults[0].message)
        self.assertIn("b" * 64, faults[0].message)

    def test_an_unreadable_payload_is_not_asked_about_its_identity(self) -> None:
        # A payload its own contract already refused says nothing dependable about the
        # artifact it came from, so the audit reports the contract failure alone rather
        # than a second fault derived from fields it cannot trust.
        foreign = artifact_stream_id("b" * 64, "complyroll.cklb", "1")
        payload = ingest_stig_artifact(
            ARTIFACTS[0], ingested_at=INGESTED_AT
        ).observations[0].to_canonical_dict()
        payload["fingerprint"] = "c" * 64
        self.append_unchecked(foreign, OBSERVATION_RECORDED, payload, expected_version=0)

        faults = audit_history(self.repository)

        self.assertEqual([fault.code for fault in faults], ["payload_contract_invalid"])

    def test_an_envelope_naming_another_tool_is_reported(self) -> None:
        # `tool` is checked at rest by the same rules that refuse it at append, so an
        # envelope naming another generator cannot be refused on the way in and called
        # healthy later.
        self.append_with_metadata(
            self.spare_stream(),
            CASE_CREATED,
            self.case_created_payload(SPARE_CASE),
            {
                "actor": "kyle",
                "method": "cli",
                "tool": "stigroll",
                "toolVersion": "0.1.0",
                "runId": RUN_ID,
            },
            expected_version=0,
        )

        faults = audit_history(self.repository)

        self.assertEqual([fault.code for fault in faults], ["event_metadata_invalid"])
        self.assertEqual(faults[0].message, "tool must be 'complyroll'")

    def test_every_fault_in_one_log_is_reported_in_sequence_order(self) -> None:
        stream_id = self.spare_stream()
        payload = self.case_created_payload(SPARE_CASE)
        payload["trackingId"] = "case-ffffffffffffffff"
        self.append_with_metadata(
            stream_id,
            CASE_CREATED,
            payload,
            {
                "actor": "kyle",
                "method": "cli",
                "tool": "complyroll",
                "toolVersion": "0.1.0",
                "runId": "run-fixed",
            },
            expected_version=0,
        )
        self.append_unchecked(
            stream_id,
            CASE_PAIN_REDUCED,
            {"reducedAt": iso_utc(ATTESTED_AT), "rating": 9},
            expected_version=1,
        )

        faults = audit_history(self.repository)
        sequences = [fault.sequence for fault in faults]

        self.assertEqual(
            [(fault.sequence, fault.code) for fault in faults],
            [
                (sequences[0], "case_tracking_id_mismatch"),
                (sequences[0], "event_metadata_invalid"),
                (sequences[-1], "payload_contract_invalid"),
            ],
        )
        self.assertEqual(sequences, sorted(sequences))

    def test_a_fault_renders_as_one_line(self) -> None:
        self.append_unchecked(
            self.spare_stream(),
            CASE_CREATED,
            {**self.case_created_payload(SPARE_CASE), "createdAt": "2026-02-30T12:00:00Z"},
            expected_version=0,
        )

        rendered = audit_history(self.repository)[0].render()

        self.assertTrue(rendered.startswith("sequence "))
        self.assertIn("payload_contract_invalid", rendered)


class ParserSupersessionTests(WriterFixture):
    """One artifact digest, several parser streams: only the newest is current.

    Replay used to read every historical stream for the same bytes while the stateless path
    ran only the installed parser, so re-ingesting an artifact under a newer parser broke
    the byte identity ADR 0008 Decision 5 promises and reported every finding twice.
    """

    def setUp(self) -> None:
        super().setUp()
        self.parsed = ingest_stig_artifact(ARTIFACTS[0], ingested_at=INGESTED_AT)
        artifact = self.parsed.artifact
        assert artifact is not None
        self.artifact = artifact

    def restamped(self, observation: Observation, parser_version: str) -> Observation:
        """Return the same finding as a newer parser version would have recorded it.

        The identifier of an artifact-bound observation derives from its fields, parser
        version included, so moving the version has to move the identifier with it.
        """

        moved = replace(observation, parser_version=parser_version)
        return replace(moved, observation_id=moved.derived_observation_id)

    def write_stream(self, parser_version: str, observations: Sequence[Observation]) -> str:
        """Record one artifact stream for the fixture digest under one parser version."""

        stream_id = artifact_stream_id(
            self.artifact.digest_sha256, self.artifact.parser_name, parser_version
        )
        head = PendingEvent(
            event_type=ARTIFACT_INGESTED,
            payload={
                "name": self.artifact.name,
                "sha256": self.artifact.digest_sha256,
                "sizeBytes": self.artifact.size_bytes,
                "mediaType": self.artifact.media_type,
                "parserName": self.artifact.parser_name,
                "parserVersion": parser_version,
                "ingestedAt": iso_utc(INGESTED_AT),
                "observationCount": len(observations),
                "diagnostics": [],
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
            for observation in observations
        )
        self.repository.append_batch(stream_id, (head, *tail), expected_version=0)
        return stream_id

    def versioned(self, parser_version: str) -> tuple[Observation, ...]:
        return tuple(
            self.restamped(observation, parser_version)
            for observation in self.parsed.observations
        )

    def fresh_repository(self) -> None:
        """Point the fixture at an empty log, so one pair cannot see another's streams.

        The version pairs below are each a whole scenario. Sharing one store between them
        would leave three streams for one digest in the third subtest and decide the
        comparison on history the pair never wrote.
        """

        store = SQLiteEventStore(":memory:")
        self.addCleanup(store.close)
        self.repository = EventRepository(store)

    def current_stream(self) -> str:
        """Return the one stream the fold reads for the fixture digest."""

        history = artifact_history(self.repository)
        self.assertEqual(len(history.current), 1)
        return history.current[0].stream_id

    def test_the_newest_parser_stream_is_the_only_one_folded(self) -> None:
        older = self.write_stream("1", self.parsed.observations)
        newer = self.write_stream("2", self.versioned("2"))

        history = artifact_history(self.repository)

        self.assertEqual([record.stream_id for record in history.current], [newer])
        self.assertEqual([record.stream_id for record in history.superseded], [older])
        self.assertEqual(
            [record.stream_id for record in superseded_artifact_records(self.repository)],
            [older],
        )
        self.assertEqual(history.current[0].parser_version, "2")

    def test_only_the_newest_streams_observations_are_rehydrated(self) -> None:
        self.write_stream("1", self.parsed.observations)
        self.write_stream("2", self.versioned("2"))

        observations = rehydrate_observations(self.repository)

        self.assertEqual(observations, self.versioned("2"))
        self.assertEqual(len(observations), len(self.parsed.observations))

    def test_parser_versions_compare_as_numbers_not_as_text(self) -> None:
        nine = self.write_stream("9", self.versioned("9"))
        ten = self.write_stream("10", self.versioned("10"))

        history = artifact_history(self.repository)

        self.assertEqual([record.stream_id for record in history.current], [ten])
        self.assertEqual([record.stream_id for record in history.superseded], [nine])
        self.assertEqual(history.current[0].parser_version, "10")

    def test_dotted_numeric_versions_compare_component_by_component(self) -> None:
        older = self.write_stream("1.9.0", self.versioned("1.9.0"))
        newer = self.write_stream("1.10.0", self.versioned("1.10.0"))

        history = artifact_history(self.repository)

        self.assertEqual([record.stream_id for record in history.current], [newer])
        self.assertEqual([record.stream_id for record in history.superseded], [older])

    def test_a_larger_number_outranks_a_smaller_one_in_either_order(self) -> None:
        for first, second, winner in (
            ("2", "10", "10"),
            ("10", "2", "10"),
            ("9", "10", "10"),
        ):
            with self.subTest(first=first, second=second):
                self.fresh_repository()
                streams = {
                    first: self.write_stream(first, self.versioned(first)),
                    second: self.write_stream(second, self.versioned(second)),
                }

                self.assertEqual(self.current_stream(), streams[winner])

    def test_numerically_equal_versions_leave_the_later_stream_current(self) -> None:
        # `1`, `1.0`, and `01` are one version, so no spelling wins on how it was written:
        # the tie falls to the later-recorded stream like any other tie. `1.0` used to beat
        # `1` on component count alone, which overrode the later-recorded rule in silence,
        # and `01` sorted below `1` as text for the same invisible reason.
        for first, second in (
            ("1", "1.0"),
            ("1.0", "1"),
            ("1", "01"),
            ("01", "1"),
            ("1.0.0", "1"),
            ("1", "1.0.0"),
        ):
            with self.subTest(first=first, second=second):
                self.fresh_repository()
                self.write_stream(first, self.versioned(first))
                later = self.write_stream(second, self.versioned(second))

                history = artifact_history(self.repository)

                self.assertEqual([record.stream_id for record in history.current], [later])
                self.assertEqual(history.current[0].parser_version, second)
                self.assertEqual([record.parser_version for record in history.superseded], [first])

    def test_a_deeper_version_still_outranks_a_shorter_one(self) -> None:
        # Dropping trailing zeros must not flatten a version that really is later: only a
        # zero tail goes, so `1.0.1` keeps its third component and beats `1` whichever
        # order the two streams were recorded in.
        for first, second in (("1", "1.0.1"), ("1.0.1", "1")):
            with self.subTest(first=first, second=second):
                self.fresh_repository()
                streams = {
                    first: self.write_stream(first, self.versioned(first)),
                    second: self.write_stream(second, self.versioned(second)),
                }

                self.assertEqual(self.current_stream(), streams["1.0.1"])

    def test_the_tie_break_reads_only_the_newest_streams_observations(self) -> None:
        # The point of picking a winner: the loser's findings stay out of the report, so
        # one artifact ingested twice under two spellings of one version is counted once.
        self.fresh_repository()
        self.write_stream("1", self.versioned("1"))
        self.write_stream("1.0", self.versioned("1.0"))

        observations = rehydrate_observations(self.repository)

        self.assertEqual(observations, self.versioned("1.0"))
        self.assertEqual(len(observations), len(self.parsed.observations))

    def test_a_version_that_is_not_numeric_makes_the_group_compare_as_text(self) -> None:
        beta = self.write_stream("2.0-rc1", self.versioned("2.0-rc1"))
        two = self.write_stream("2", self.versioned("2"))

        history = artifact_history(self.repository)

        self.assertEqual([record.stream_id for record in history.current], [beta])
        self.assertEqual([record.stream_id for record in history.superseded], [two])

    def test_the_remaining_observations_equal_a_fresh_parse(self) -> None:
        # The stateless-equivalent property: an older parser stream beside the installed
        # one leaves exactly the observations a fresh run of the installed parser produces,
        # which is what keeps the two report paths byte-identical.
        self.write_stream("0", self.versioned("0"))
        self.ingest([ARTIFACTS[0]])

        self.assertEqual(
            rehydrate_observations(self.repository),
            ingest_stig_artifact(ARTIFACTS[0], ingested_at=INGESTED_AT).observations,
        )
        self.assertEqual(
            [record.parser_version for record in artifact_records(self.repository)],
            [self.artifact.parser_version],
        )

    def test_one_stream_per_digest_supersedes_nothing(self) -> None:
        self.ingest()

        history = artifact_history(self.repository)

        self.assertEqual(history.superseded, ())
        self.assertEqual(len(history.current), len(ARTIFACTS))

    def test_a_superseded_stream_is_still_intact_history(self) -> None:
        older = self.write_stream("1", self.parsed.observations)
        self.write_stream("2", self.versioned("2"))

        self.assertEqual(audit_history(self.repository), ())
        self.assertEqual(
            len(self.repository.read_stream(older)), len(self.parsed.observations) + 1
        )


class NumericVersionPredicateTests(unittest.TestCase):
    """`str.isdigit` is wider than `int`, and the comparison has to agree with `int`.

    U+00B2 (superscript two) and U+2460 (circled digit one) are digits to `str.isdigit`
    and are not numbers to `int`. The numeric branch calls `int` on every component it
    was told was numeric, so either spelling used to take that branch and raise
    `ValueError` out of `artifact_history` instead of falling back to the text order.
    """

    #: Characters `str.isdigit` accepts and `int` refuses. Written as codepoints so the
    #: source stays ASCII and each one says which character it is.
    INT_HOSTILE_DIGITS = (chr(0x00B2), chr(0x2460))
    #: A digit `int` does accept. It is still not an ASCII digit, so it compares as text:
    #: ordering it numerically would make one version equal to a different spelling of it.
    ARABIC_INDIC_FIVE = chr(0x0665)

    def view(self, parser_version: str, sequence: int) -> _ArtifactStreamView:
        """Build one artifact stream view carrying nothing but a parser version."""

        record = ArtifactRecord(
            name="host.cklb",
            sha256="a" * 64,
            size_bytes=1,
            media_type="application/json",
            parser_name="complyroll.cklb",
            parser_version=parser_version,
            ingested_at=INGESTED_AT,
            observation_count=0,
            diagnostics=(),
            stream_id=f"artifact/{'a' * 64}/complyroll.cklb/{parser_version}",
            sequence=sequence,
        )
        return _ArtifactStreamView(stream_id=record.stream_id, record=record, observations=())

    def version_of(self, view: _ArtifactStreamView) -> str:
        """Return one view's parser version, failing the test when it carries no record."""

        self.assertIsNotNone(view.record)
        assert view.record is not None
        return view.record.parser_version

    def test_a_digit_int_refuses_is_not_a_numeric_version(self) -> None:
        for digit in self.INT_HOSTILE_DIGITS:
            with self.subTest(codepoint=f"U+{ord(digit):04X}"):
                self.assertTrue(digit.isdigit())
                with self.assertRaises(ValueError):
                    int(digit)

                self.assertFalse(_is_numeric_version(digit))
                self.assertFalse(_is_numeric_version(f"1.{digit}"))

    def test_a_non_ascii_digit_int_accepts_is_still_compared_as_text(self) -> None:
        # U+0665 parses as 5, so the old predicate ordered it against ASCII versions as a
        # number and made two different strings one version. The predicate is ASCII, so
        # a version spelled this way keeps its own text order instead.
        digit = self.ARABIC_INDIC_FIVE

        self.assertTrue(digit.isdigit())
        self.assertEqual(int(digit), 5)
        self.assertFalse(_is_numeric_version(digit))

        winner = _newest_stream((self.view(digit, 1), self.view("9", 2)))

        self.assertEqual(self.version_of(winner), digit)

    def test_such_a_version_compares_as_text_and_never_raises(self) -> None:
        # Text order, not a crash. U+00B2 sorts above every ASCII digit, so it wins the
        # pair whichever order the two streams were recorded in, and the numeric branch
        # that would have called int() on it is never taken.
        superscript = chr(0x00B2)
        for first, second in ((superscript, "2"), ("2", superscript)):
            with self.subTest(first=first, second=second):
                candidates = (self.view(first, 1), self.view(second, 2))

                winner = _newest_stream(candidates)

                self.assertEqual(self.version_of(winner), superscript)

    def test_ascii_numeric_versions_still_compare_as_numbers(self) -> None:
        winner = _newest_stream((self.view("9", 1), self.view("10", 2)))

        self.assertTrue(_is_numeric_version("10"))
        self.assertEqual(self.version_of(winner), "10")


if __name__ == "__main__":
    unittest.main()
