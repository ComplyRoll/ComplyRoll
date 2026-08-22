"""The ADR 0008 Decision 5 acceptance tests: a report rebuilt from history.

Every store below is populated through the library writers alone, in the same order the
command line would call them, so what these tests prove about the log is a property of
the library and not of one command surface.
"""

from __future__ import annotations

import json
import re
import tempfile
import unittest
from collections.abc import Mapping, Sequence
from datetime import UTC, datetime
from pathlib import Path

from test_reports import ARTIFACTS, EXAMPLES, FIXTURES, GOLDEN, find_vulnerability, options

from complyroll.adapters import ingest_stig_artifact
from complyroll.events import (
    EventMetadata,
    EventRepository,
    artifact_stream_id,
    case_stream_id,
    iso_utc,
)
from complyroll.history import (
    apply_evaluations,
    attest_detection,
    correlate_cases,
    fold_all_cases,
    fold_case,
    record_ingest,
)
from complyroll.reports import (
    CompiledVdtReport,
    ReportCompileError,
    compile_vdt_report,
    compile_vdt_report_from_history,
    load_evaluations,
)
from complyroll.store import SQLiteEventStore

#: The instant the fixtures were ingested at, matching the golden `--as-of`.
INGESTED_AT = datetime(2026, 8, 21, 12, 0, tzinfo=UTC)
#: The instant the golden report attests for every fixture case.
ATTESTED_AT = datetime(2026, 8, 1, 0, 0, tzinfo=UTC)
#: A second, earlier attested instant, used to reach the mixed-instant rendering.
EARLIER_ATTESTED_AT = datetime(2026, 7, 15, 0, 0, tzinfo=UTC)
#: A later instant, for re-attesting one case after the rest were attested together.
LATER_ATTESTED_AT = datetime(2026, 8, 2, 0, 0, tzinfo=UTC)
RATIONALE = "The fixtures declare no assessment timestamp; the assessment ran on 1 August."

WINDOWS_CASE = "case-490f49bfdd1bd019"
#: A well-formed tracking id no fixture produces, for the stale-case path.
ORPHAN_CASE = "case-00000000000000ff"

#: The one fixture that correlates to a single case, so a store built from it holds
#: exactly one attested record and an override cannot hide behind a second one.
WINDOWS_ONLY = (FIXTURES / "windows-host.ckl",)

WINDOWS_EVALUATION: Mapping[str, object] = {
    "match": {"sourceRecordId": "V-253260", "sourceType": "ckl"},
    "completedAt": "2026-08-05T16:00:00Z",
    "isInternetReachable": True,
    "isLikelyExploitable": True,
    "pain": 4,
    "potentialAgencyImpact": "A legacy role stays reachable beside agency workloads.",
    "rationale": "The role is installed and answers from the internet-facing segment.",
    "evaluator": "Example Provider vulnerability team",
}


def windows_evaluation(**overrides: object) -> dict[str, object]:
    """Return the windows fixture's evaluation entry with fields added or replaced."""

    entry = dict(WINDOWS_EVALUATION)
    entry.update(overrides)
    return entry


def markdown_attestation_groups(markdown: str) -> list[tuple[str, tuple[str, ...]]]:
    """Read the per-case attestation bullets back out of the Markdown twin."""

    body = markdown.split("## Detection time attestation", 1)[1].split("\n## ", 1)[0]
    groups: list[tuple[str, tuple[str, ...]]] = []
    for line in body.splitlines():
        matched = re.fullmatch(r"- \*\*(.+?):\*\* (.+)", line)
        if matched is not None:
            groups.append((matched.group(1), tuple(matched.group(2).split(", "))))
    return groups


class StoreFixture(unittest.TestCase):
    """A temporary store plus the four writers, called exactly as a command would."""

    def setUp(self) -> None:
        directory = tempfile.TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        self.workspace = Path(directory.name)
        self.database = self.workspace / "history.db"
        store = SQLiteEventStore(self.database)
        self.addCleanup(store.close)
        self.store = store
        self.repository = EventRepository(store)
        self.metadata = EventMetadata(actor="golden", run_id="run-acceptance")

    def ingest(self, paths: Sequence[Path] = ARTIFACTS) -> None:
        """Record every artifact in the order the golden report lists them."""

        for path in paths:
            result = ingest_stig_artifact(Path(path), ingested_at=INGESTED_AT)
            record_ingest(
                self.repository,
                result,
                metadata=self.metadata,
                ingested_at=INGESTED_AT,
            )

    def correlate(self) -> None:
        correlate_cases(self.repository, metadata=self.metadata, now=INGESTED_AT)

    def tracking_ids(self) -> tuple[str, ...]:
        return tuple(case.tracking_id for case in fold_all_cases(self.repository))

    def attest(
        self,
        tracking_ids: Sequence[str] | None = None,
        *,
        detected_at: datetime = ATTESTED_AT,
    ) -> tuple[str, ...]:
        selected = self.tracking_ids() if tracking_ids is None else tuple(tracking_ids)
        attest_detection(
            self.repository,
            selected,
            detected_at=detected_at,
            rationale=RATIONALE,
            metadata=self.metadata,
            now=INGESTED_AT,
        )
        return selected

    def evaluate(self, path: Path | None = None) -> None:
        source = EXAMPLES / "evaluations.json" if path is None else path
        apply_evaluations(
            self.repository,
            load_evaluations(source),
            metadata=self.metadata,
            now=INGESTED_AT,
        )

    def append_orphan_case(self, tracking_id: str = ORPHAN_CASE) -> None:
        """Record a case whose observations are not in this store.

        History outlives any one ingest, so a case can survive an artifact that was
        never ingested again. Writing the stream directly is the only way to reach that
        state deterministically inside one test.
        """

        self.repository.append(
            case_stream_id(tracking_id),
            "case.created",
            {
                "trackingId": tracking_id,
                "sourceType": "ckl",
                "sourceRecordId": "V-000001",
                "contextKey": "Retired Windows STIG",
                "title": "A weakness whose artifact was never ingested again",
                "description": "Recorded from an artifact that is no longer supplied.",
                "createdAt": iso_utc(INGESTED_AT),
            },
            occurred_at=INGESTED_AT,
            metadata=self.metadata,
            expected_version=0,
        )

    def write_evaluations(
        self,
        entries: Sequence[Mapping[str, object]],
        name: str = "evaluations.json",
    ) -> Path:
        """Write one evaluations file into this test's workspace and return its path."""

        path = self.workspace / name
        path.write_text(json.dumps({"evaluations": list(entries)}), encoding="utf-8")
        return path

    def case_version(self, tracking_id: str) -> int:
        """Return one case stream's current version, for a direct append."""

        return len(self.repository.read_stream(case_stream_id(tracking_id)))

    def replay(self, **option_overrides: object) -> CompiledVdtReport:
        return compile_vdt_report_from_history(
            self.repository,
            options=options(**option_overrides),  # type: ignore[arg-type]
        )

    def stateless(
        self,
        artifacts: Sequence[Path],
        evaluations: Path,
        **option_overrides: object,
    ) -> CompiledVdtReport:
        """Compile the same inputs the stateless way, for a byte-identity comparison."""

        return compile_vdt_report(
            list(artifacts),
            options=options(**option_overrides),  # type: ignore[arg-type]
            evaluations=load_evaluations(evaluations),
        )

    def assert_paths_agree(
        self,
        artifacts: Sequence[Path],
        evaluations: Path,
    ) -> CompiledVdtReport:
        """Assert both renderings of both paths match byte for byte, and return one."""

        replayed = self.replay()
        stateless = self.stateless(artifacts, evaluations)

        self.assertEqual(replayed.to_json(), stateless.to_json())
        self.assertEqual(replayed.to_markdown(), stateless.to_markdown())
        return replayed


class ReconciliationTests(StoreFixture):
    """ADR 0008 Decision 5: the two paths agree byte for byte or the claim is empty."""

    def setUp(self) -> None:
        super().setUp()
        self.ingest()
        self.correlate()
        self.attest()
        self.evaluate()

    def test_the_replayed_json_matches_the_stateless_golden_byte_for_byte(self) -> None:
        expected = (GOLDEN / "vdt-fixtures.json").read_text(encoding="utf-8")

        self.assertEqual(self.replay().to_json(), expected)

    def test_the_replayed_markdown_matches_the_stateless_golden_byte_for_byte(self) -> None:
        expected = (GOLDEN / "vdt-fixtures.md").read_text(encoding="utf-8")

        self.assertEqual(self.replay().to_markdown(), expected)

    def test_replaying_twice_produces_identical_bytes(self) -> None:
        first = self.replay()
        again = self.replay()

        self.assertEqual(again.to_json(), first.to_json())
        self.assertEqual(again.to_markdown(), first.to_markdown())

    def test_the_replayed_document_satisfies_the_official_schema(self) -> None:
        report = self.replay()

        self.assertTrue(report.validation.is_valid)
        self.assertEqual(report.validation.issues, ())

    def test_the_report_ignores_the_command_line_attestation(self) -> None:
        """History attests per case, so a stale flag must not move a detection time."""

        report = self.replay(detected_at=datetime(2001, 1, 1, tzinfo=UTC))

        self.assertEqual(
            report.document["x-complyroll"]["detectionTimeAttestation"]["detectedAt"],
            "2026-08-01T00:00:00Z",
        )
        self.assertEqual(report.to_json(), self.replay().to_json())


class ReplayedHistoryTests(StoreFixture):
    def setUp(self) -> None:
        super().setUp()
        self.ingest()
        self.correlate()
        self.attest()
        self.evaluate()

    def revised_evaluations(self, source_record_id: str, pain: int) -> Path:
        """Write a copy of the example evaluations with one PAIN changed."""

        payload = json.loads((EXAMPLES / "evaluations.json").read_text(encoding="utf-8"))
        for entry in payload["evaluations"]:
            if entry["match"]["sourceRecordId"] == source_record_id:
                entry["pain"] = pain
        path = self.workspace / "evaluations-revised.json"
        path.write_text(json.dumps(payload), encoding="utf-8")
        return path

    def test_a_second_evaluation_moves_the_rating_and_keeps_the_first(self) -> None:
        self.evaluate(self.revised_evaluations("V-253260", 5))

        state = fold_case(self.repository, WINDOWS_CASE)
        current = state.current_evaluation

        self.assertEqual(len(state.evaluations), 2)
        self.assertIsNotNone(current)
        assert current is not None
        self.assertEqual(int(current.pain), 5)
        self.assertEqual(int(state.evaluations[0].pain), 4)
        self.assertLess(state.evaluations[0].sequence, state.evaluations[1].sequence)

        report = self.replay()

        self.assertEqual(find_vulnerability(report, "V-253260")["currentRating"], 5)

    def test_re_applying_the_same_evaluations_appends_nothing(self) -> None:
        before = self.store.latest_sequence

        self.evaluate()

        self.assertEqual(self.store.latest_sequence, before)
        self.assertEqual(len(fold_case(self.repository, WINDOWS_CASE).evaluations), 1)


class UnevaluatedStoreTests(StoreFixture):
    def test_a_store_with_no_evaluations_still_compiles(self) -> None:
        self.ingest()
        self.correlate()
        self.attest()

        report = self.replay()
        vulnerabilities = report.document["vulnerabilities"]

        self.assertEqual(len(vulnerabilities), 6)
        self.assertFalse(any("currentRating" in item for item in vulnerabilities))
        self.assertNotIn("currentRating", report.to_json())
        self.assertIn("- **Evaluation:** not yet completed", report.to_markdown())


class MixedAttestationTests(StoreFixture):
    """The one rendering the stateless path cannot reach (ADR 0008 amendment)."""

    def setUp(self) -> None:
        super().setUp()
        self.ingest()
        self.correlate()
        selected = self.tracking_ids()
        self.assertEqual(len(selected), 6)
        self.early = tuple(sorted(selected[:2]))
        self.late = tuple(sorted(selected[2:]))
        self.attest(self.early, detected_at=EARLIER_ATTESTED_AT)
        self.attest(self.late, detected_at=ATTESTED_AT)

    def test_differing_instants_publish_one_entry_each_and_no_scalar(self) -> None:
        report = self.replay()
        block = report.document["x-complyroll"]["detectionTimeAttestation"]

        self.assertNotIn("detectedAt", block)
        self.assertEqual(block["appliedTo"], sorted(self.early + self.late))
        self.assertEqual(block["count"], 6)
        self.assertEqual(
            block["attestations"],
            [
                {"detectedAt": "2026-07-15T00:00:00Z", "appliedTo": list(self.early)},
                {"detectedAt": "2026-08-01T00:00:00Z", "appliedTo": list(self.late)},
            ],
        )

    def test_the_count_equals_the_attested_records(self) -> None:
        report = self.replay()
        block = report.document["x-complyroll"]["detectionTimeAttestation"]
        attested = [
            item
            for item in report.document["vulnerabilities"]
            if item["x-complyroll"]["detectedAtSource"] == "attestation"
        ]

        self.assertEqual(block["count"], len(attested))
        self.assertEqual(block["count"], len(block["appliedTo"]))
        self.assertEqual(
            sum(len(group["appliedTo"]) for group in block["attestations"]),
            block["count"],
        )

    def test_each_record_carries_the_instant_attested_for_it(self) -> None:
        report = self.replay()
        detected = {
            item["providerTrackingId"]: item["detection"]["detectedAt"]
            for item in report.document["vulnerabilities"]
        }

        for tracking_id in self.early:
            self.assertEqual(detected[tracking_id], "2026-07-15T00:00:00Z")
        for tracking_id in self.late:
            self.assertEqual(detected[tracking_id], "2026-08-01T00:00:00Z")

    def test_the_two_renderings_describe_the_same_grouping(self) -> None:
        report = self.replay()
        block = report.document["x-complyroll"]["detectionTimeAttestation"]
        markdown = report.to_markdown()

        self.assertIn(
            "The operator attested per-case detection times for 6 vulnerability record(s)",
            markdown,
        )
        self.assertEqual(
            markdown_attestation_groups(markdown),
            [(group["detectedAt"], tuple(group["appliedTo"])) for group in block["attestations"]],
        )

    def test_one_shared_instant_keeps_the_scalar_form(self) -> None:
        self.attest(self.early, detected_at=ATTESTED_AT)

        block = self.replay().document["x-complyroll"]["detectionTimeAttestation"]

        self.assertEqual(block["detectedAt"], "2026-08-01T00:00:00Z")
        self.assertNotIn("attestations", block)


class StaleCaseTests(StoreFixture):
    def test_a_case_with_no_matching_group_is_reported_not_dropped(self) -> None:
        self.ingest((FIXTURES / "windows-host.ckl",))
        self.correlate()
        self.append_orphan_case()
        self.attest()

        report = self.replay()
        stale = [item for item in report.diagnostics if item.code == "stale_case"]

        self.assertEqual(len(stale), 1)
        self.assertEqual(stale[0].level.value, "info")
        self.assertIn(ORPHAN_CASE, stale[0].message)
        self.assertEqual(stale[0].location, f"case/{ORPHAN_CASE}")
        self.assertEqual(len(report.document["vulnerabilities"]), 1)
        self.assertIn(
            stale[0].to_dict(), report.document["x-complyroll"]["diagnostics"]
        )

    def test_a_store_whose_cases_all_match_raises_no_stale_diagnostic(self) -> None:
        self.ingest()
        self.correlate()
        self.attest()

        report = self.replay()

        self.assertEqual([item for item in report.diagnostics if item.code == "stale_case"], [])


class OverriddenAttestationTests(StoreFixture):
    """An override renames a record; it must not lose the instant attested for it.

    `appliedTo` lists effective identifiers because that is what the report calls each
    record, while the attested instant is a fact filed against the correlation
    identifier. Resolving one by the other is the seam where the grouped rendering the
    ADR 0008 amendment reserves for genuinely differing instants leaked into a report
    whose instants all agree.
    """

    def test_an_overridden_sole_attested_case_keeps_the_scalar_block(self) -> None:
        path = self.write_evaluations([windows_evaluation(trackingId="PROVIDER-1")])
        self.ingest(WINDOWS_ONLY)
        self.correlate()
        self.attest()
        self.evaluate(path)

        report = self.assert_paths_agree(WINDOWS_ONLY, path)
        block = report.document["x-complyroll"]["detectionTimeAttestation"]

        self.assertEqual(block["detectedAt"], "2026-08-01T00:00:00Z")
        self.assertEqual(block["appliedTo"], ["PROVIDER-1"])
        self.assertEqual(block["count"], 1)
        self.assertNotIn("attestations", block)

    def test_the_markdown_twin_states_one_attested_instant(self) -> None:
        path = self.write_evaluations([windows_evaluation(trackingId="PROVIDER-1")])
        self.ingest(WINDOWS_ONLY)
        self.correlate()
        self.attest()
        self.evaluate(path)

        markdown = self.replay().to_markdown()

        self.assertIn(
            "The operator attested a detection time of 2026-08-01T00:00:00Z for "
            "1 vulnerability record(s)",
            markdown,
        )
        self.assertEqual(markdown_attestation_groups(markdown), [])

    def test_one_override_among_several_attested_cases_keeps_the_scalar_block(self) -> None:
        path = self.write_evaluations([windows_evaluation(trackingId="PROVIDER-1")])
        self.ingest()
        self.correlate()
        self.attest()
        self.evaluate(path)

        report = self.assert_paths_agree(ARTIFACTS, path)
        block = report.document["x-complyroll"]["detectionTimeAttestation"]

        self.assertEqual(block["detectedAt"], "2026-08-01T00:00:00Z")
        self.assertIn("PROVIDER-1", block["appliedTo"])
        self.assertNotIn(WINDOWS_CASE, block["appliedTo"])
        self.assertEqual(block["count"], 6)
        self.assertNotIn("attestations", block)

    def re_attested_override(self) -> tuple[str, ...]:
        """Attest every case together, then re-attest the one case that is overridden.

        This is the setup that turned the lookup miss into a false statement rather
        than a merely wrong shape. The five cases that keep the shared instant agree
        with each other, so resolving the report-level instant from the map alone finds
        exactly one and publishes the scalar form, while the sixth record was re-
        attested a day later and carries an override that the map does not name. The
        block would then assert one detection time over six records that the sixth
        record's own `detection.detectedAt` contradicts.
        """

        path = self.write_evaluations([windows_evaluation(trackingId="PROVIDER-1")])
        self.ingest()
        self.correlate()
        shared = self.attest()
        self.assertEqual(len(shared), 6)
        self.attest((WINDOWS_CASE,), detected_at=LATER_ATTESTED_AT)
        self.evaluate(path)
        return tuple(sorted(set(shared) - {WINDOWS_CASE}))

    def test_a_re_attested_override_publishes_both_instants_and_no_scalar(self) -> None:
        unchanged = self.re_attested_override()

        report = self.replay()
        block = report.document["x-complyroll"]["detectionTimeAttestation"]

        self.assertNotIn("detectedAt", block)
        self.assertEqual(block["appliedTo"], sorted((*unchanged, "PROVIDER-1")))
        self.assertEqual(block["count"], 6)
        self.assertEqual(
            block["attestations"],
            [
                {"detectedAt": "2026-08-01T00:00:00Z", "appliedTo": list(unchanged)},
                {"detectedAt": "2026-08-02T00:00:00Z", "appliedTo": ["PROVIDER-1"]},
            ],
        )

    def test_the_re_attested_record_states_the_instant_the_block_gives_it(self) -> None:
        unchanged = self.re_attested_override()

        report = self.replay()
        detected = {
            item["providerTrackingId"]: item["detection"]["detectedAt"]
            for item in report.document["vulnerabilities"]
        }

        self.assertEqual(detected["PROVIDER-1"], "2026-08-02T00:00:00Z")
        for tracking_id in unchanged:
            self.assertEqual(detected[tracking_id], "2026-08-01T00:00:00Z")

    def test_the_markdown_twin_lists_both_re_attested_instants(self) -> None:
        unchanged = self.re_attested_override()

        markdown = self.replay().to_markdown()

        self.assertIn(
            "The operator attested per-case detection times for 6 vulnerability record(s)",
            markdown,
        )
        self.assertEqual(
            markdown_attestation_groups(markdown),
            [
                ("2026-08-01T00:00:00Z", unchanged),
                ("2026-08-02T00:00:00Z", ("PROVIDER-1",)),
            ],
        )

    def test_an_override_still_reaches_the_persisted_report(self) -> None:
        path = self.write_evaluations([windows_evaluation(trackingId="PROVIDER-1")])
        self.ingest()
        self.correlate()
        self.attest()
        self.evaluate(path)

        report = self.assert_paths_agree(ARTIFACTS, path)
        identifiers = {
            item["providerTrackingId"] for item in report.document["vulnerabilities"]
        }

        self.assertIn("PROVIDER-1", identifiers)
        self.assertNotIn(WINDOWS_CASE, identifiers)
        self.assertEqual(find_vulnerability(report, "V-253260")["providerTrackingId"], "PROVIDER-1")


class ReplayedPainReductionOrderTests(StoreFixture):
    """Stream order is an accident of recording; the rendered order is canonical."""

    CHRONOLOGICAL = (
        {"reducedAt": "2026-08-06T16:00:00Z", "rating": 4},
        {"reducedAt": "2026-08-12T16:00:00Z", "rating": 3},
    )
    RESTATED = tuple(reversed(CHRONOLOGICAL))

    def test_re_stating_the_reductions_in_another_order_appends_nothing(self) -> None:
        recorded = self.write_evaluations(
            [windows_evaluation(painReductionEvents=list(self.CHRONOLOGICAL))],
            "recorded.json",
        )
        restated = self.write_evaluations(
            [windows_evaluation(painReductionEvents=list(self.RESTATED))],
            "restated.json",
        )
        self.ingest(WINDOWS_ONLY)
        self.correlate()
        self.attest()
        self.evaluate(recorded)
        before = self.store.latest_sequence

        self.evaluate(restated)

        self.assertEqual(self.store.latest_sequence, before)

    def test_the_persisted_report_matches_the_restated_stateless_compile(self) -> None:
        recorded = self.write_evaluations(
            [windows_evaluation(painReductionEvents=list(self.CHRONOLOGICAL))],
            "recorded.json",
        )
        restated = self.write_evaluations(
            [windows_evaluation(painReductionEvents=list(self.RESTATED))],
            "restated.json",
        )
        self.ingest(WINDOWS_ONLY)
        self.correlate()
        self.attest()
        self.evaluate(recorded)
        self.evaluate(restated)

        report = self.assert_paths_agree(WINDOWS_ONLY, restated)
        extension = report.document["vulnerabilities"][0]["x-complyroll"]

        self.assertEqual(extension["painReductionEvents"], list(self.CHRONOLOGICAL))
        self.assertIn(
            "- **Completed PAIN reductions:** N4 at 2026-08-06T16:00:00Z, "
            "N3 at 2026-08-12T16:00:00Z",
            report.to_markdown(),
        )


class ReplayedDispositionTests(StoreFixture):
    """Closed and accepted dispositions survive the round trip through history."""

    ACCEPTANCE = "Residual risk accepted for one quarter under change record CR-88."

    def evaluated_store(self, entry: Mapping[str, object]) -> Path:
        path = self.write_evaluations([entry])
        self.ingest(WINDOWS_ONLY)
        self.correlate()
        self.attest()
        self.evaluate(path)
        return path

    def test_closed_as_fully_mitigated_rehydrates(self) -> None:
        path = self.evaluated_store(
            windows_evaluation(disposition="closed", closedDisposition="fully_mitigated")
        )

        report = self.assert_paths_agree(WINDOWS_ONLY, path)

        self.assertEqual(
            report.document["vulnerabilities"][0]["finalDisposition"], "Fully Mitigated"
        )
        self.assertEqual(
            [item.code for item in report.diagnostics if item.code == "closed_without_disposition"],
            [],
        )

    def test_closed_as_false_positive_rehydrates(self) -> None:
        path = self.evaluated_store(
            windows_evaluation(disposition="closed", closedDisposition="false_positive")
        )

        report = self.assert_paths_agree(WINDOWS_ONLY, path)

        self.assertEqual(
            report.document["vulnerabilities"][0]["finalDisposition"], "False Positive"
        )

    def test_an_accepted_case_rehydrates_its_acceptance_rationale(self) -> None:
        path = self.evaluated_store(
            windows_evaluation(disposition="accepted", acceptanceRationale=self.ACCEPTANCE)
        )

        report = self.assert_paths_agree(WINDOWS_ONLY, path)
        stateless = self.stateless(WINDOWS_ONLY, path)

        self.assertEqual(len(report.accepted), 1)
        self.assertEqual(report.accepted[0].acceptance_rationale, self.ACCEPTANCE)
        self.assertEqual(stateless.accepted[0].acceptance_rationale, self.ACCEPTANCE)
        self.assertEqual(report.document["vulnerabilities"], [])

    def test_closing_as_accepted_rehydrates_its_acceptance_rationale(self) -> None:
        path = self.evaluated_store(
            windows_evaluation(
                disposition="closed",
                closedDisposition="accepted",
                acceptanceRationale=self.ACCEPTANCE,
            )
        )

        report = self.assert_paths_agree(WINDOWS_ONLY, path)

        self.assertEqual(len(report.accepted), 1)
        self.assertEqual(report.accepted[0].acceptance_rationale, self.ACCEPTANCE)


class DispositionWithoutEvaluationTests(StoreFixture):
    """A disposition the report can never carry stops the rebuild, it does not vanish."""

    def record_disposition(self, tracking_id: str, status: str = "fully_mitigated") -> None:
        """Append one disposition directly, the state no writer can produce."""

        self.repository.append(
            case_stream_id(tracking_id),
            "case.disposition_recorded",
            {
                "status": status,
                "closedDisposition": None,
                "acceptanceRationale": None,
                "recordedAt": iso_utc(INGESTED_AT),
            },
            occurred_at=INGESTED_AT,
            metadata=self.metadata,
            expected_version=self.case_version(tracking_id),
        )

    def test_a_disposition_on_an_unevaluated_case_fails_closed(self) -> None:
        self.ingest(WINDOWS_ONLY)
        self.correlate()
        self.attest()
        self.record_disposition(WINDOWS_CASE)

        with self.assertRaises(ReportCompileError) as caught:
            self.replay()

        diagnostic = caught.exception.diagnostics[0]
        self.assertEqual(diagnostic.code, "disposition_without_evaluation")
        self.assertEqual(diagnostic.level.value, "error")
        self.assertIn(WINDOWS_CASE, diagnostic.message)
        self.assertEqual(diagnostic.location, f"case/{WINDOWS_CASE}")

    def test_a_case_created_and_disposed_with_no_evaluation_fails_closed(self) -> None:
        self.ingest(WINDOWS_ONLY)
        self.correlate()
        self.attest()
        self.append_orphan_case()
        self.record_disposition(ORPHAN_CASE)

        with self.assertRaises(ReportCompileError) as caught:
            self.replay()

        diagnostic = caught.exception.diagnostics[0]
        self.assertEqual(diagnostic.code, "disposition_without_evaluation")
        self.assertIn(ORPHAN_CASE, diagnostic.message)

    def test_an_evaluated_case_with_a_disposition_still_compiles(self) -> None:
        path = self.write_evaluations(
            [windows_evaluation(disposition="partially_mitigated")]
        )
        self.ingest(WINDOWS_ONLY)
        self.correlate()
        self.attest()
        self.evaluate(path)

        report = self.assert_paths_agree(WINDOWS_ONLY, path)

        self.assertEqual(
            report.document["vulnerabilities"][0]["finalDisposition"], "Partially Mitigated"
        )


class DamagedIngestHistoryTests(StoreFixture):
    """An error-level ingest diagnostic cannot reach history, so one found is a fault."""

    DIGEST = "0" * 64

    def append_failed_ingest(self) -> None:
        self.repository.append(
            artifact_stream_id(self.DIGEST, "complyroll.damaged", "1"),
            "artifact.ingested",
            {
                "name": "damaged-host.ckl",
                "sha256": self.DIGEST,
                "sizeBytes": 0,
                "mediaType": "application/xml",
                "parserName": "complyroll.damaged",
                "parserVersion": "1",
                "ingestedAt": iso_utc(INGESTED_AT),
                "observationCount": 0,
                "diagnostics": [
                    {
                        "level": "error",
                        "code": "artifact_unparsable",
                        "message": "the recorded artifact did not parse",
                    }
                ],
            },
            occurred_at=INGESTED_AT,
            metadata=self.metadata,
            expected_version=0,
        )

    def test_a_stored_error_diagnostic_stops_the_rebuild(self) -> None:
        self.ingest(WINDOWS_ONLY)
        self.correlate()
        self.attest()
        self.append_failed_ingest()

        with self.assertRaises(ReportCompileError) as caught:
            self.replay()

        diagnostic = caught.exception.diagnostics[0]
        self.assertEqual(len(caught.exception.diagnostics), 1)
        self.assertEqual(diagnostic.code, "artifact_unparsable")
        self.assertEqual(diagnostic.level.value, "error")
        self.assertEqual(diagnostic.message, "the recorded artifact did not parse")
        self.assertEqual(diagnostic.location, "damaged-host.ckl")

    def test_the_same_store_compiles_without_the_damaged_stream(self) -> None:
        self.ingest(WINDOWS_ONLY)
        self.correlate()
        self.attest()

        self.assertEqual(len(self.replay().document["vulnerabilities"]), 1)


if __name__ == "__main__":
    unittest.main()
