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
from dataclasses import replace
from datetime import UTC, datetime
from itertools import permutations
from pathlib import Path

from test_reports import (
    ACCEPTED_EVALUATIONS,
    ARTIFACTS,
    BANNER_CASE,
    BANNER_RATIONALE,
    EXAMPLES,
    FIXTURES,
    GOLDEN,
    REPORT_KINDS,
    ReportKind,
    find_accepted,
    find_vulnerability,
    options,
    shared_benchmark_xccdf,
)

from complyroll.adapters import IngestResult, ingest_stig_artifact
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
    CompiledAviReport,
    CompiledHistoricalReport,
    CompiledVdtReport,
    ReportCompileError,
    ReportOptions,
    compile_avi_report,
    compile_avi_report_from_history,
    compile_historical_report,
    compile_historical_report_from_history,
    compile_vdt_report,
    compile_vdt_report_from_history,
    load_evaluations,
)
from complyroll.store import SQLiteEventStore

AnyReport = CompiledVdtReport | CompiledAviReport | CompiledHistoricalReport

#: The instant the fixtures were ingested at, matching the golden `--as-of`.
INGESTED_AT = datetime(2026, 8, 21, 12, 0, tzinfo=UTC)
#: The instant the golden report attests for every fixture case.
ATTESTED_AT = datetime(2026, 8, 1, 0, 0, tzinfo=UTC)
#: A second, earlier attested instant, used to reach the mixed-instant rendering.
EARLIER_ATTESTED_AT = datetime(2026, 7, 15, 0, 0, tzinfo=UTC)
#: A later instant, for re-attesting one case after the rest were attested together.
LATER_ATTESTED_AT = datetime(2026, 8, 2, 0, 0, tzinfo=UTC)
#: A recording instant well after every example evaluation completed and after the
#: golden `--as-of`, so a store recorded then differs from the golden store in nothing
#: but the `recordedAt` its evaluation and disposition events carry.
LATER_RECORDED_AT = datetime(2026, 9, 1, 8, 30, tzinfo=UTC)
#: A report period no fixture activity falls in, for the out-of-period acceptance.
SEPTEMBER = {
    "period_from": datetime(2026, 9, 1, 0, 0, tzinfo=UTC),
    "period_to": datetime(2026, 9, 30, 23, 59, 59, tzinfo=UTC),
}
RATIONALE = "The fixtures declare no assessment timestamp; the assessment ran on 1 August."
#: One fixed run identifier for every acceptance store, so a replay stays reproducible.
#: The repository requires `run-` followed by a canonical lowercase version-4 UUID.
RUN_ID = "run-8c4a0e2e-1f4d-4a3b-9c2e-6f0d5b7a1e33"

WINDOWS_CASE = "case-490f49bfdd1bd019"
#: A well-formed tracking id no fixture produces, for the stale-case path.
ORPHAN_CASE = "case-00000000000000ff"

#: The one fixture that correlates to a single case, so a store built from it holds
#: exactly one attested record and an override cannot hide behind a second one.
WINDOWS_ONLY = (FIXTURES / "windows-host.ckl",)

#: The attestation block a `WINDOWS_ONLY` store publishes when nothing renames the case.
SOLE_ATTESTATION = {
    "detectedAt": "2026-08-01T00:00:00Z",
    "appliedTo": [WINDOWS_CASE],
    "count": 1,
}

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


def banner_acceptance() -> dict[str, object]:
    """Return the example acceptance of `banner_etc_issue`, exactly as the file records it."""

    payload = json.loads(ACCEPTED_EVALUATIONS.read_text(encoding="utf-8"))
    for entry in payload["evaluations"]:
        if entry["match"]["sourceRecordId"] == "banner_etc_issue":
            return dict(entry)
    raise AssertionError("the example acceptance file no longer accepts banner_etc_issue")


def markdown_attestation_groups(markdown: str) -> list[tuple[str, tuple[str, ...]]]:
    """Read the per-case attestation bullets back out of the Markdown twin."""

    body = markdown.split("## Detection time attestation", 1)[1].split("\n## ", 1)[0]
    groups: list[tuple[str, tuple[str, ...]]] = []
    for line in body.splitlines():
        matched = re.fullmatch(r"- \*\*(.+?):\*\* (.+)", line)
        if matched is not None:
            groups.append((matched.group(1), tuple(matched.group(2).split(", "))))
    return groups


def compile_from_history(
    repository: EventRepository,
    *,
    kind: ReportKind,
    options: ReportOptions,
) -> AnyReport:
    """Rebuild one report of the given kind from a store (ADR 0010, three projections)."""

    if kind == "avi":
        return compile_avi_report_from_history(repository, options=options)
    if kind == "historical":
        return compile_historical_report_from_history(repository, options=options)
    return compile_vdt_report_from_history(repository, options=options)


def compile_stateless(
    artifacts: Sequence[Path],
    evaluations: Path | None,
    *,
    kind: ReportKind,
    options: ReportOptions,
) -> AnyReport:
    """Compile one report of the given kind from files, the way the command line does."""

    parsed = None if evaluations is None else load_evaluations(evaluations)
    if kind == "avi":
        return compile_avi_report(list(artifacts), options=options, evaluations=parsed)
    if kind == "historical":
        return compile_historical_report(list(artifacts), options=options, evaluations=parsed)
    return compile_vdt_report(list(artifacts), options=options, evaluations=parsed)


def populate(
    repository: EventRepository,
    metadata: EventMetadata,
    artifacts: Sequence[Path],
    *,
    evaluations: Path | None = None,
    now: datetime = INGESTED_AT,
) -> None:
    """Drive the writers over one store in command order: ingest, correlate, attest, evaluate.

    `now` is the instant the correlation, attestation, and evaluation writers record as
    having acted, so two stores that differ only in it hold the same facts under
    different `createdAt`, `attestedAt`, and `recordedAt` values.
    """

    for path in artifacts:
        record_ingest(
            repository,
            ingest_stig_artifact(Path(path), ingested_at=INGESTED_AT),
            metadata=metadata,
            ingested_at=INGESTED_AT,
        )
    correlate_cases(repository, metadata=metadata, now=now)
    attest_detection(
        repository,
        tuple(case.tracking_id for case in fold_all_cases(repository)),
        detected_at=ATTESTED_AT,
        rationale=RATIONALE,
        metadata=metadata,
        now=now,
    )
    if evaluations is not None:
        apply_evaluations(repository, load_evaluations(evaluations), metadata=metadata, now=now)


class StoreFixture(unittest.TestCase):
    """A temporary store plus the four writers, called exactly as a command would."""

    def setUp(self) -> None:
        self.workspace = self.fresh_workspace()
        self.database = self.workspace / "history.db"
        store = SQLiteEventStore(self.database)
        self.addCleanup(store.close)
        self.store = store
        self.repository = EventRepository(store)
        self.metadata = EventMetadata(actor="golden", run_id=RUN_ID)

    def fresh_workspace(self) -> Path:
        """Return an empty directory that lives as long as this test."""

        directory = tempfile.TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        return Path(directory.name)

    def open_repository(self, workspace: Path) -> EventRepository:
        """Open a second, empty store in `workspace`, closed when this test ends."""

        store = SQLiteEventStore(workspace / "history.db")
        self.addCleanup(store.close)
        return EventRepository(store)

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

    def evaluate(self, path: Path | None = None, *, now: datetime = INGESTED_AT) -> None:
        """Apply one evaluations file, recorded at `now`, which no report may print."""

        source = EXAMPLES / "evaluations.json" if path is None else path
        apply_evaluations(
            self.repository,
            load_evaluations(source),
            metadata=self.metadata,
            now=now,
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

    def replay(self, *, kind: ReportKind = "vdt", **option_overrides: object) -> AnyReport:
        """Rebuild one projection from this test's store with the golden options."""

        return compile_from_history(
            self.repository,
            kind=kind,
            options=options(**option_overrides),  # type: ignore[arg-type]
        )

    def stateless(
        self,
        artifacts: Sequence[Path],
        evaluations: Path,
        *,
        kind: ReportKind = "vdt",
        **option_overrides: object,
    ) -> AnyReport:
        """Compile the same inputs the stateless way, for a byte-identity comparison."""

        return compile_stateless(
            artifacts,
            evaluations,
            kind=kind,
            options=options(**option_overrides),  # type: ignore[arg-type]
        )

    def assert_paths_agree(
        self,
        artifacts: Sequence[Path],
        evaluations: Path,
        *,
        kind: ReportKind = "vdt",
        **option_overrides: object,
    ) -> AnyReport:
        """Assert both renderings of both paths match byte for byte, and return one.

        Both sides of this comparison run `compile_records`, so it proves the two
        paths hand that compiler the same records and proves nothing about what the
        compiler then wrote. Every caller pairs it with assertions naming the concrete
        strings a reader of the report would see.
        """

        replayed = self.replay(kind=kind, **option_overrides)
        stateless = self.stateless(artifacts, evaluations, kind=kind, **option_overrides)

        self.assertEqual(replayed.to_json(), stateless.to_json())
        self.assertEqual(replayed.to_markdown(), stateless.to_markdown())
        return replayed

    def attestation_block(self, report: AnyReport) -> object:
        """Return the report-level detection-time attestation block."""

        return report.document["x-complyroll"]["detectionTimeAttestation"]

    def sole_vulnerability(self, report: AnyReport) -> dict[str, object]:
        """Return the one reported vulnerability, asserting the report holds one."""

        vulnerabilities = report.document["vulnerabilities"]
        self.assertEqual(len(vulnerabilities), 1)
        return dict(vulnerabilities[0])


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


class IngestOrderReconciliationTests(StoreFixture):
    """The two paths agree even when neither one saw the artifacts in the same order.

    A persisted report lists artifacts in the order they were ingested and a stateless
    report in the order they were named on the command line. While both echoed their
    own input order, `assert_paths_agree` only held because every test drove both
    sides in one order, so the byte-identity claim was really a claim about the test
    setup. Ingesting in the opposite order from the stateless compile is what makes it
    a claim about the compiler.
    """

    def setUp(self) -> None:
        super().setUp()
        self.ingest(tuple(reversed(ARTIFACTS)))
        self.correlate()
        self.attest()
        self.evaluate()

    def test_history_ingested_in_reverse_still_replays_the_golden_json(self) -> None:
        expected = (GOLDEN / "vdt-fixtures.json").read_text(encoding="utf-8")

        self.assertEqual(self.replay().to_json(), expected)

    def test_history_ingested_in_reverse_still_replays_the_golden_markdown(self) -> None:
        expected = (GOLDEN / "vdt-fixtures.md").read_text(encoding="utf-8")

        self.assertEqual(self.replay().to_markdown(), expected)

    def test_the_two_paths_agree_across_opposite_input_orders(self) -> None:
        self.assert_paths_agree(ARTIFACTS, EXAMPLES / "evaluations.json")

    def test_the_replayed_manifest_is_sorted_not_ingest_ordered(self) -> None:
        artifacts = self.replay().document["x-complyroll"]["artifacts"]

        self.assertEqual(
            [item["name"] for item in artifacts],
            ["openscap-results.xml", "ubuntu-host.cklb", "windows-host.ckl"],
        )


class SharedGroupIngestOrderTests(StoreFixture):
    """A vulnerability drawn from several hosts replays the same however it was logged.

    One benchmark scanned across a fleet is one case whose linked observations come
    from every host's file. Ingest order decided the order those links were written
    and the order the rebuilt group held its members, so it reached `resources` and
    `observationIds` in the replayed report.
    """

    hosts = ("host-charlie", "host-alpha", "host-bravo")

    def fleet(self, order: Sequence[str], into: Path) -> tuple[Path, ...]:
        """Write one XCCDF per host, all sharing a benchmark id, in the given order."""

        paths: list[Path] = []
        for host in order:
            path = into / f"{host}.xml"
            path.write_text(shared_benchmark_xccdf(host), encoding="utf-8")
            paths.append(path)
        return tuple(paths)

    def replay_fleet(
        self,
        order: Sequence[str],
        *,
        kind: ReportKind = "vdt",
        evaluations: Path | None = None,
    ) -> AnyReport:
        """Ingest a fleet into its own fresh store, then rebuild the report from it."""

        workspace = self.fresh_workspace()
        repository = self.open_repository(workspace)
        populate(repository, self.metadata, self.fleet(order, workspace), evaluations=evaluations)
        return compile_from_history(repository, kind=kind, options=options())

    def accepted_banner(self) -> Path:
        """Write the example's banner acceptance alone: the one entry a fleet matches.

        The fleet's three files share one benchmark, so `banner_etc_issue` is one case
        whose resources and observations come from every host, which is exactly the
        member order that once followed ingest order.
        """

        return self.write_evaluations([banner_acceptance()], "fleet-acceptance.json")

    def test_a_fleet_replays_the_same_bytes_whatever_order_it_was_ingested(self) -> None:
        expected = self.replay_fleet(self.hosts)

        for order in permutations(self.hosts):
            with self.subTest(order=list(order)):
                report = self.replay_fleet(order)

                self.assertEqual(report.to_json(), expected.to_json())
                self.assertEqual(report.to_markdown(), expected.to_markdown())

    def test_the_two_paths_agree_on_a_fleet_ingested_in_reverse(self) -> None:
        replayed = self.replay_fleet(tuple(reversed(self.hosts)))
        stateless = compile_vdt_report(
            list(self.fleet(self.hosts, self.workspace)),
            options=options(),
        )

        self.assertEqual(replayed.to_json(), stateless.to_json())
        self.assertEqual(replayed.to_markdown(), stateless.to_markdown())

    def test_an_accepted_fleet_case_replays_the_same_avi_whatever_the_order(self) -> None:
        path = self.accepted_banner()
        expected = self.replay_fleet(self.hosts, kind="avi", evaluations=path)
        accepted = find_accepted(expected, "banner_etc_issue")
        detail = accepted["vulnerabilityDetail"]

        self.assertEqual(accepted["acceptanceRationale"], BANNER_RATIONALE)
        self.assertEqual(
            [item["resourceId"] for item in detail["x-complyroll"]["resources"]],
            ["host-alpha", "host-bravo", "host-charlie"],
        )
        self.assertEqual(len(detail["x-complyroll"]["observationIds"]), 3)
        self.assertIn(
            "- **Affected resources:** host host-alpha, host host-bravo, host host-charlie",
            expected.to_markdown(),
        )

        for order in permutations(self.hosts):
            with self.subTest(order=list(order)):
                report = self.replay_fleet(order, kind="avi", evaluations=path)

                self.assertEqual(report.to_json(), expected.to_json())
                self.assertEqual(report.to_markdown(), expected.to_markdown())

    def test_an_accepted_fleet_case_replays_the_same_snapshot_whatever_the_order(self) -> None:
        path = self.accepted_banner()
        expected = self.replay_fleet(self.hosts, kind="historical", evaluations=path)
        markdown = expected.to_markdown()

        self.assertEqual(
            find_accepted(expected, "banner_etc_issue")["acceptanceRationale"],
            BANNER_RATIONALE,
        )
        self.assertEqual(len(expected.document["activeVulnerabilities"]), 1)
        self.assertIn("| Active vulnerabilities | 1 |", markdown)
        self.assertIn("| Accepted vulnerabilities | 1 |", markdown)

        for order in permutations(self.hosts):
            with self.subTest(order=list(order)):
                report = self.replay_fleet(order, kind="historical", evaluations=path)

                self.assertEqual(report.to_json(), expected.to_json())
                self.assertEqual(report.to_markdown(), expected.to_markdown())

    def test_the_two_paths_agree_on_an_accepted_fleet_for_every_projection(self) -> None:
        path = self.accepted_banner()
        artifacts = list(self.fleet(self.hosts, self.workspace))

        for kind in REPORT_KINDS:
            with self.subTest(kind=kind):
                replayed = self.replay_fleet(
                    tuple(reversed(self.hosts)), kind=kind, evaluations=path
                )
                stateless = compile_stateless(artifacts, path, kind=kind, options=options())

                self.assertEqual(replayed.to_json(), stateless.to_json())
                self.assertEqual(replayed.to_markdown(), stateless.to_markdown())
                if kind == "vdt":
                    self.assertIn(
                        "is an accepted vulnerability and belongs in the VER-RPT-AVI report",
                        replayed.to_markdown(),
                    )
                else:
                    self.assertIn(
                        f"- **Acceptance rationale:** {BANNER_RATIONALE}",
                        replayed.to_markdown(),
                    )


class AcceptedProjectionReplayTests(StoreFixture):
    """ADR 0010: the two accepted-vulnerability projections rebuild from history exactly.

    The store holds the example acceptance file, so one fixture case is accepted and
    five are active. The Accepted Vulnerability Information report publishes the one
    and counts the five; the historical snapshot publishes all six with no period.
    """

    def setUp(self) -> None:
        super().setUp()
        self.ingest()
        self.correlate()
        self.attest()
        self.evaluate(ACCEPTED_EVALUATIONS)

    def assert_matches_golden(self, kind: ReportKind, name: str) -> None:
        report = self.replay(kind=kind)

        self.assertEqual(
            report.to_json(), (GOLDEN / f"{name}.json").read_text(encoding="utf-8")
        )
        self.assertEqual(
            report.to_markdown(), (GOLDEN / f"{name}.md").read_text(encoding="utf-8")
        )

    def test_the_replayed_avi_matches_the_stateless_golden_byte_for_byte(self) -> None:
        self.assert_matches_golden("avi", "avi-fixtures")

    def test_the_replayed_snapshot_matches_the_stateless_golden_byte_for_byte(self) -> None:
        self.assert_matches_golden("historical", "historical-fixtures")

    def test_the_replayed_documents_satisfy_their_official_schemas(self) -> None:
        for kind in ("avi", "historical"):
            with self.subTest(kind=kind):
                report = self.replay(kind=kind)

                self.assertTrue(report.validation.is_valid)
                self.assertEqual(report.validation.issues, ())

    def test_the_two_paths_agree_on_the_avi(self) -> None:
        report = self.assert_paths_agree(ARTIFACTS, ACCEPTED_EVALUATIONS, kind="avi")
        accepted = find_accepted(report, "banner_etc_issue")
        markdown = report.to_markdown()

        self.assertEqual(accepted["acceptanceRationale"], BANNER_RATIONALE)
        self.assertEqual(accepted["vulnerabilityDetail"]["providerTrackingId"], BANNER_CASE)
        self.assertEqual(accepted["vulnerabilityDetail"]["overdueStatus"], {"isOverdue": False})
        self.assertEqual(len(report.document["acceptedVulnerabilities"]), 1)
        self.assertEqual(report.document["x-complyroll"]["activeNotReported"], 5)
        self.assertEqual(report.document["x-complyroll"]["excludedByPeriod"], 0)
        self.assertIn("| Active, not reported here | 5 |", markdown)
        self.assertIn(f"- **Acceptance rationale:** {BANNER_RATIONALE}", markdown)

    def test_the_two_paths_agree_on_the_historical_snapshot(self) -> None:
        report = self.assert_paths_agree(ARTIFACTS, ACCEPTED_EVALUATIONS, kind="historical")
        active = report.document["activeVulnerabilities"]
        markdown = report.to_markdown()

        self.assertEqual(report.document["generatedAt"], "2026-08-21T12:00:00Z")
        self.assertNotIn("reportPeriod", report.document)
        self.assertNotIn("reportPeriod", report.document["x-complyroll"])
        self.assertEqual(len(active), 5)
        self.assertEqual(
            find_vulnerability(report, "V-260470", key="activeVulnerabilities")[
                "finalDisposition"
            ],
            "Partially Mitigated",
        )
        self.assertEqual(
            find_accepted(report, "banner_etc_issue")["acceptanceRationale"],
            BANNER_RATIONALE,
        )
        self.assertNotIn("- **Report period:**", markdown)
        self.assertIn("| Active vulnerabilities | 5 |", markdown)
        self.assertIn("| Accepted vulnerabilities | 1 |", markdown)

    def test_two_stores_recorded_at_different_instants_print_the_same_bytes(self) -> None:
        """`recordedAt` is `now` at `cases evaluate` time and must never reach a report.

        The acceptance instant a report may state is the evaluation's `completedAt`
        (ADR 0010 Decision 2). The store from `setUp` recorded its evaluations at the
        golden `--as-of`, where a leak would print the very string `generatedAt`
        prints; this second store recorded them eleven days later, so a leak has
        nowhere to hide.
        """

        later = self.open_repository(self.fresh_workspace())
        populate(
            later,
            self.metadata,
            ARTIFACTS,
            evaluations=ACCEPTED_EVALUATIONS,
            now=LATER_RECORDED_AT,
        )
        recorded = fold_case(later, BANNER_CASE).disposition
        golden = fold_case(self.repository, BANNER_CASE).disposition

        self.assertIsNotNone(recorded)
        self.assertIsNotNone(golden)
        assert recorded is not None and golden is not None
        self.assertEqual(recorded.recorded_at, LATER_RECORDED_AT)
        self.assertEqual(golden.recorded_at, INGESTED_AT)

        for kind in ("avi", "historical"):
            with self.subTest(kind=kind):
                report = compile_from_history(later, kind=kind, options=options())
                expected = self.replay(kind=kind)

                self.assertEqual(report.to_json(), expected.to_json())
                self.assertEqual(report.to_markdown(), expected.to_markdown())
                self.assertNotIn(iso_utc(LATER_RECORDED_AT), report.to_json())
                self.assertNotIn(iso_utc(LATER_RECORDED_AT), report.to_markdown())
                self.assertEqual(
                    find_accepted(report, "banner_etc_issue")["vulnerabilityDetail"][
                        "evaluationCompletedAt"
                    ],
                    "2026-08-06T09:00:00Z",
                )

        # The August period above holds the case's real activity, so a `recordedAt` that
        # leaked into period membership would change no byte there. September holds the
        # later store's recording instant and none of the case's activity, so from that
        # store alone a leak would put the acceptance into September's report.
        self.assertTrue(SEPTEMBER["period_from"] <= LATER_RECORDED_AT <= SEPTEMBER["period_to"])
        september = compile_from_history(
            later,
            kind="avi",
            options=options(
                period_from=SEPTEMBER["period_from"], period_to=SEPTEMBER["period_to"]
            ),
        )
        expected = self.replay(kind="avi", **SEPTEMBER)

        self.assertEqual(september.document["acceptedVulnerabilities"], [])
        self.assertEqual(september.document["x-complyroll"]["excludedByPeriod"], 1)
        self.assertEqual(september.to_json(), expected.to_json())
        self.assertEqual(september.to_markdown(), expected.to_markdown())

    def test_history_ingested_in_reverse_still_replays_both_goldens(self) -> None:
        reversed_store = self.open_repository(self.fresh_workspace())
        populate(
            reversed_store,
            self.metadata,
            tuple(reversed(ARTIFACTS)),
            evaluations=ACCEPTED_EVALUATIONS,
        )

        for kind, name in (("avi", "avi-fixtures"), ("historical", "historical-fixtures")):
            with self.subTest(kind=kind):
                report = compile_from_history(reversed_store, kind=kind, options=options())

                self.assertEqual(
                    report.to_json(), (GOLDEN / f"{name}.json").read_text(encoding="utf-8")
                )
                self.assertEqual(
                    report.to_markdown(), (GOLDEN / f"{name}.md").read_text(encoding="utf-8")
                )

    def test_an_acceptance_outside_the_period_is_excluded_on_both_paths(self) -> None:
        report = self.assert_paths_agree(
            ARTIFACTS, ACCEPTED_EVALUATIONS, kind="avi", **SEPTEMBER
        )
        excluded = [item for item in report.diagnostics if item.code == "excluded_by_period"]
        markdown = report.to_markdown()

        self.assertEqual(report.document["acceptedVulnerabilities"], [])
        self.assertEqual(report.document["x-complyroll"]["excludedByPeriod"], 1)
        self.assertEqual(report.document["x-complyroll"]["activeNotReported"], 5)
        self.assertEqual(len(excluded), 1)
        self.assertEqual(excluded[0].level.value, "info")
        self.assertEqual(
            excluded[0].message,
            f"{BANNER_CASE} is accepted and no recorded activity between "
            "2026-09-01T00:00:00Z and 2026-09-30T23:59:59Z",
        )
        self.assertEqual(excluded[0].location, "banner_etc_issue")
        self.assertIn(excluded[0].to_dict(), report.document["x-complyroll"]["diagnostics"])
        self.assertIn("| Excluded by report period | 1 |", markdown)
        self.assertIn("No accepted vulnerabilities had recorded activity in this period.", markdown)


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

    def test_the_stale_case_sits_at_the_same_position_in_every_projection(self) -> None:
        """The record set carries the diagnostic once; each projection publishes it as is."""

        self.ingest(WINDOWS_ONLY)
        self.correlate()
        self.append_orphan_case()
        self.attest()
        message = (
            f"{ORPHAN_CASE} is recorded in history but no open observation group "
            "matches it, so it is not in this report"
        )
        positions: dict[str, int] = {}

        for kind in REPORT_KINDS:
            with self.subTest(kind=kind):
                report = self.replay(kind=kind)
                codes = [item.code for item in report.diagnostics]
                published = report.document["x-complyroll"]["diagnostics"]
                index = codes.index("stale_case")

                self.assertEqual(codes.count("stale_case"), 1)
                self.assertEqual(report.diagnostics[index].level.value, "info")
                self.assertEqual(report.diagnostics[index].message, message)
                self.assertEqual(published[index]["code"], "stale_case")
                self.assertEqual(published[index]["message"], message)
                self.assertIn(
                    f"- **info** stale_case: {message} [case/{ORPHAN_CASE}]",
                    report.to_markdown(),
                )
                positions[kind] = index

        self.assertEqual(set(positions.values()), {positions["vdt"]})


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
        record = self.sole_vulnerability(report)

        self.assertEqual(
            block,
            {"detectedAt": "2026-08-01T00:00:00Z", "appliedTo": ["PROVIDER-1"], "count": 1},
        )
        self.assertNotIn("attestations", block)
        self.assertEqual(record["providerTrackingId"], "PROVIDER-1")
        self.assertEqual(record["detection"]["detectedAt"], "2026-08-01T00:00:00Z")
        self.assertNotIn("finalDisposition", record)

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
        identifiers = [
            item["providerTrackingId"] for item in report.document["vulnerabilities"]
        ]

        self.assertEqual(block["detectedAt"], "2026-08-01T00:00:00Z")
        self.assertIn("PROVIDER-1", block["appliedTo"])
        self.assertNotIn(WINDOWS_CASE, block["appliedTo"])
        self.assertEqual(block["count"], 6)
        self.assertNotIn("attestations", block)
        self.assertEqual(sorted(block["appliedTo"]), sorted(identifiers))
        self.assertEqual(
            find_vulnerability(report, "V-253260")["detection"]["detectedAt"],
            "2026-08-01T00:00:00Z",
        )

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
        block = report.document["x-complyroll"]["detectionTimeAttestation"]

        self.assertIn("PROVIDER-1", identifiers)
        self.assertNotIn(WINDOWS_CASE, identifiers)
        self.assertEqual(find_vulnerability(report, "V-253260")["providerTrackingId"], "PROVIDER-1")
        self.assertEqual(block["detectedAt"], "2026-08-01T00:00:00Z")
        self.assertEqual(block["count"], 6)
        self.assertIn("### PROVIDER-1: V-253260", report.to_markdown())


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
        record = report.document["vulnerabilities"][0]

        self.assertEqual(record["painReductionEvents"], list(self.CHRONOLOGICAL))
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
        record = self.sole_vulnerability(report)

        self.assertEqual(record["providerTrackingId"], WINDOWS_CASE)
        self.assertEqual(record["finalDisposition"], "Fully Mitigated")
        self.assertEqual(self.attestation_block(report), SOLE_ATTESTATION)
        self.assertIn("- **Disposition:** Fully Mitigated", report.to_markdown())
        self.assertEqual(
            [item.code for item in report.diagnostics if item.code == "closed_without_disposition"],
            [],
        )

    def test_closed_as_remediated_rehydrates(self) -> None:
        """Remediated is its own official disposition (ADR 0007 amendment 2026-09-04)."""

        path = self.evaluated_store(
            windows_evaluation(disposition="closed", closedDisposition="remediated")
        )

        report = self.assert_paths_agree(WINDOWS_ONLY, path)
        record = self.sole_vulnerability(report)

        self.assertEqual(record["providerTrackingId"], WINDOWS_CASE)
        self.assertEqual(record["finalDisposition"], "Remediated")
        self.assertTrue(record["x-complyroll"]["remediated"])
        self.assertEqual(self.attestation_block(report), SOLE_ATTESTATION)
        self.assertIn("- **Disposition:** Remediated", report.to_markdown())
        self.assertIn("| Remediated |", report.to_markdown())

    def test_closed_as_false_positive_rehydrates(self) -> None:
        path = self.evaluated_store(
            windows_evaluation(disposition="closed", closedDisposition="false_positive")
        )

        report = self.assert_paths_agree(WINDOWS_ONLY, path)
        record = self.sole_vulnerability(report)

        self.assertEqual(record["providerTrackingId"], WINDOWS_CASE)
        self.assertEqual(record["finalDisposition"], "False Positive")
        self.assertEqual(self.attestation_block(report), SOLE_ATTESTATION)
        self.assertIn("- **Disposition:** False Positive", report.to_markdown())

    def test_an_accepted_case_rehydrates_its_acceptance_rationale(self) -> None:
        path = self.evaluated_store(
            windows_evaluation(disposition="accepted", acceptanceRationale=self.ACCEPTANCE)
        )

        report = self.assert_paths_agree(WINDOWS_ONLY, path)
        stateless = self.stateless(WINDOWS_ONLY, path)

        self.assertEqual(len(report.accepted), 1)
        self.assertEqual(report.accepted[0].acceptance_rationale, self.ACCEPTANCE)
        self.assertEqual(report.accepted[0].vulnerability.tracking_id, WINDOWS_CASE)
        self.assertEqual(stateless.accepted[0].acceptance_rationale, self.ACCEPTANCE)
        self.assertEqual(report.document["vulnerabilities"], [])
        # Nothing is reported, so no record carries an attested detection time and the
        # block states no instant at all rather than one covering zero records.
        self.assertIsNone(self.attestation_block(report))
        self.assertIn(
            "No open vulnerabilities were reported for this period.", report.to_markdown()
        )

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
        self.assertEqual(report.accepted[0].vulnerability.tracking_id, WINDOWS_CASE)
        self.assertEqual(report.document["vulnerabilities"], [])
        self.assertIsNone(self.attestation_block(report))
        self.assertEqual(
            [item.code for item in report.diagnostics if item.code == "accepted_excluded"],
            ["accepted_excluded"],
        )

    def assert_accepted_on_both_paths(self, path: Path, *, kind: ReportKind) -> None:
        """Assert the store's one accepted case reaches `acceptedVulnerabilities` intact.

        The rationale comes from the `case.disposition_recorded` event and the detected
        instant from `detection.attested`, so both are facts the log holds rather than
        anything a command-line flag supplied at report time.
        """

        report = self.assert_paths_agree(WINDOWS_ONLY, path, kind=kind)
        accepted = find_accepted(report, "V-253260")
        markdown = report.to_markdown()

        self.assertEqual(len(report.document["acceptedVulnerabilities"]), 1)
        self.assertEqual(accepted["acceptanceRationale"], self.ACCEPTANCE)
        self.assertEqual(accepted["vulnerabilityDetail"]["providerTrackingId"], WINDOWS_CASE)
        self.assertEqual(
            accepted["vulnerabilityDetail"]["detection"]["detectedAt"], "2026-08-01T00:00:00Z"
        )
        self.assertEqual(self.attestation_block(report), SOLE_ATTESTATION)
        self.assertIn(f"### {WINDOWS_CASE}: V-253260", markdown)
        self.assertIn(f"- **Acceptance rationale:** {self.ACCEPTANCE}", markdown)
        self.assertIn("- **Disposition:** accepted; **remediated:** no", markdown)

    def test_an_accepted_case_rehydrates_into_the_avi(self) -> None:
        path = self.evaluated_store(
            windows_evaluation(disposition="accepted", acceptanceRationale=self.ACCEPTANCE)
        )

        self.assert_accepted_on_both_paths(path, kind="avi")
        report = self.replay(kind="avi")

        self.assertEqual(report.document["x-complyroll"]["activeNotReported"], 0)
        self.assertIn("| Accepted vulnerabilities reported | 1 |", report.to_markdown())

    def test_an_accepted_case_rehydrates_into_the_historical_snapshot(self) -> None:
        path = self.evaluated_store(
            windows_evaluation(disposition="accepted", acceptanceRationale=self.ACCEPTANCE)
        )

        self.assert_accepted_on_both_paths(path, kind="historical")
        report = self.replay(kind="historical")

        self.assertEqual(report.document["activeVulnerabilities"], [])
        self.assertIn("No active vulnerabilities are recorded.", report.to_markdown())
        self.assertIn("| Accepted vulnerabilities | 1 |", report.to_markdown())

    def test_closing_as_accepted_rehydrates_into_the_avi(self) -> None:
        path = self.evaluated_store(
            windows_evaluation(
                disposition="closed",
                closedDisposition="accepted",
                acceptanceRationale=self.ACCEPTANCE,
            )
        )

        self.assert_accepted_on_both_paths(path, kind="avi")

    def test_closing_as_accepted_rehydrates_into_the_historical_snapshot(self) -> None:
        path = self.evaluated_store(
            windows_evaluation(
                disposition="closed",
                closedDisposition="accepted",
                acceptanceRationale=self.ACCEPTANCE,
            )
        )

        self.assert_accepted_on_both_paths(path, kind="historical")


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
        record = self.sole_vulnerability(report)

        self.assertEqual(record["providerTrackingId"], WINDOWS_CASE)
        self.assertEqual(record["finalDisposition"], "Partially Mitigated")
        self.assertEqual(self.attestation_block(report), SOLE_ATTESTATION)


class SupersededParserTests(StoreFixture):
    """Only the newest parser version's stream reaches a report (ADR 0008 amendment).

    Re-ingesting one artifact under a later parser version writes a second stream for
    the same digest. Rehydrating both would double every finding, and dropping the
    older one in silence would leave a reader unable to tell that an earlier reading
    of the same bytes exists in history, so the replay reads the newest and names the
    rest.
    """

    def bumped(self, result: IngestResult, parser_version: str) -> IngestResult:
        """Return the ingest a later parser version of the same adapter would produce.

        The parser version is part of an artifact-bound observation's fingerprint, so
        every identifier moves with it; the canonical reader refuses a stored
        observation whose recorded identifier is not the one its fields derive.
        """

        artifact = result.artifact
        self.assertIsNotNone(artifact)
        assert artifact is not None
        observations = []
        for observation in result.observations:
            moved = replace(observation, parser_version=parser_version)
            observations.append(replace(moved, observation_id=moved.derived_observation_id))
        return replace(
            result,
            artifact=replace(artifact, parser_version=parser_version),
            observations=tuple(observations),
        )

    def ingest_both_versions(self) -> tuple[IngestResult, IngestResult]:
        """Record the windows fixture under parser version 1, then under version 2."""

        first = ingest_stig_artifact(WINDOWS_ONLY[0], ingested_at=INGESTED_AT)
        record_ingest(self.repository, first, metadata=self.metadata, ingested_at=INGESTED_AT)
        second = self.bumped(first, "2")
        record_ingest(self.repository, second, metadata=self.metadata, ingested_at=INGESTED_AT)
        self.correlate()
        self.attest()
        return first, second

    def test_the_report_reads_the_newest_stream_and_names_the_older_one(self) -> None:
        first, second = self.ingest_both_versions()

        report = self.replay()
        extension = report.document["x-complyroll"]
        superseded = [item for item in report.diagnostics if item.code == "artifact_superseded"]

        self.assertEqual(len(extension["artifacts"]), 1)
        self.assertEqual(extension["artifacts"][0]["name"], "windows-host.ckl")
        self.assertEqual(extension["artifacts"][0]["parserVersion"], "2")
        self.assertEqual(extension["parserVersions"], {"complyroll.ckl": "2"})

        self.assertEqual(len(superseded), 1)
        self.assertEqual(superseded[0].level.value, "info")
        self.assertIn("windows-host.ckl", superseded[0].message)
        self.assertIn("complyroll.ckl 1", superseded[0].message)
        self.assertIn("complyroll.ckl 2", superseded[0].message)
        self.assertIn(superseded[0].to_dict(), extension["diagnostics"])
        self.assertIn("artifact_superseded", report.to_markdown())
        self.assertEqual(len(first.observations), len(second.observations))

    def test_only_the_newest_observation_ids_are_reported(self) -> None:
        first, second = self.ingest_both_versions()

        report = self.replay()
        reported = {
            observation_id
            for item in report.document["vulnerabilities"]
            for observation_id in item["x-complyroll"]["observationIds"]
        }
        version_one = {item.observation_id for item in first.observations}
        version_two = {item.observation_id for item in second.observations}

        self.assertEqual(len(report.document["vulnerabilities"]), 1)
        self.assertTrue(reported)
        self.assertEqual(reported & version_one, set())
        self.assertLessEqual(reported, version_two)

    def test_one_parser_version_raises_no_supersession_diagnostic(self) -> None:
        self.ingest(WINDOWS_ONLY)
        self.correlate()
        self.attest()

        report = self.replay()

        self.assertEqual(
            [item.code for item in report.diagnostics if item.code == "artifact_superseded"],
            [],
        )
        self.assertEqual(len(report.document["x-complyroll"]["artifacts"]), 1)
        self.assertEqual(
            report.document["x-complyroll"]["artifacts"][0]["parserVersion"], "1"
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
