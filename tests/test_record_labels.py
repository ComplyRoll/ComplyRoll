# ******************************************************************************
# *Title: Record Label Tests*
# *Author: Kyle Versluis*
# *Description: Tests for how diagnostics name a record an evaluation renames.*
# ******************************************************************************
"""Tests for the name a diagnostic gives a record whose evaluation overrides `trackingId`.

A reader finds a record in the report by its published id, the override, and finds its
case in history by the correlation id, so a renamed record is named by both, as
`<override> (<correlation id>)`; a record without an override keeps its text byte for byte
(ADR 0007 amendment 2026-10-26). Each test compiles a run twice, once without the override
and once with it, and requires the second run's diagnostics to equal the first's with the
correlation id replaced by that form, so nothing but the name moves.
"""

# *--- Imports ---*

from __future__ import annotations

import tempfile
import unittest
from collections.abc import Callable, Sequence
from dataclasses import replace
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from test_coverage import host, inventory_of, observation
from test_coverage_gap_evaluations import (
    EXPECTED_SINCE,
    evaluations_with,
    gap_match,
    gaps,
    tracking_ids,
)
from test_evaluation_order import (
    BANNER_RULE,
    EARLY,
    LATE_ATTESTATION,
    ORPHAN_CASE,
    TIMED_AT,
    HistoryOrderFixture,
    orphan_created,
    rendered,
    run,
    xccdf,
)
from test_kev import HDF_CCIS, fixture_catalog, hdf_control_artifact, kev_report
from test_reports import (
    ACCEPTANCE,
    ARTIFACTS,
    DETECTED_AT,
    MIXED_TIMESTAMP_XCCDF,
    compile_fixtures,
    evaluation_json,
    evaluations_for,
    evaluations_from,
    options,
)

from complyroll.correlation import group_open_observations
from complyroll.events import case_stream_id
from complyroll.history import (
    CASE_CREATED,
    CASE_EVALUATED,
    CASE_IDENTIFIED,
    DETECTION_ATTESTED,
    fold_all_cases,
)
from complyroll.history import writers as history_writers
from complyroll.history.order import clock_faults, evaluation_order_faults
from complyroll.models import CaseStatus
from complyroll.policy import CertificationClass
from complyroll.reports import (
    DetectionAttestation,
    EvaluationSet,
    ReportCompileError,
    ReportDiagnostic,
    compile_record_set,
    compile_record_set_from_artifacts,
    project_avi,
)
from complyroll.reports import vdt as vdt_module
from complyroll.reports.evaluations import record_label
from complyroll.reports.replay import compile_record_set_from_history
from complyroll.store import NewEvent

# *--- Fixtures ---*

#: The record `evaluations_from` matches (V-260470 in the CKLB fixture), by correlation id.
CASE = "case-1f3e011db93cc89e"
OVERRIDE = "ACME-123"
LABEL = f"{OVERRIDE} ({CASE})"
#: The instant past which a detection time's VER-TFR-EVU deadline overflows, and an
#: evaluation `completedAt` whose VDR-TFR-PVR and VER-TFR-MAV deadlines do (ADR 0008).
LATE_DETECTION = datetime(9999, 12, 31, tzinfo=UTC)
LATE_COMPLETION = datetime(9999, 6, 23, tzinfo=UTC)

Line = tuple[str, str, str, str | None]


def lines(diagnostics: Sequence[ReportDiagnostic]) -> list[Line]:
    return [(item.level.value, item.code, item.message, item.location) for item in diagnostics]


def relabeled(diagnostics: Sequence[ReportDiagnostic], correlation: str, label: str) -> list[Line]:
    """Return the lines with each mention of the correlation id named as `label`."""

    return [
        (level, code, message.replace(correlation, label), location)
        for level, code, message, location in lines(diagnostics)
    ]


def refused(compile_run: Callable[[], object]) -> list[ReportDiagnostic]:
    """Return the diagnostics a compile that must fail refuses with."""

    try:
        compile_run()
    except ReportCompileError as exc:
        return list(exc.diagnostics)
    raise AssertionError("the compile was expected to refuse")


def with_completion(evaluations: EvaluationSet, completed_at: datetime) -> EvaluationSet:
    """Return the set with every entry completed at an instant the file reader refuses."""

    return EvaluationSet(
        entries=tuple(replace(entry, completed_at=completed_at) for entry in evaluations.entries)
    )


# *--- Tests ---*


class RecordLabelTests(unittest.TestCase):
    def test_a_renamed_record_is_named_by_both_ids(self) -> None:
        self.assertEqual(record_label(CASE, OVERRIDE), LABEL)

    def test_a_record_with_no_override_keeps_its_correlation_id(self) -> None:
        self.assertEqual(record_label(CASE, None), CASE)

    def test_an_override_equal_to_the_correlation_id_renames_nothing(self) -> None:
        self.assertEqual(record_label(CASE, CASE), CASE)


class StatelessRecordLabelTests(unittest.TestCase):
    """Every compile diagnostic that names a renamed record names it by both ids."""

    def assert_relabeled(
        self, plain: Sequence[ReportDiagnostic], renamed: Sequence[ReportDiagnostic]
    ) -> None:
        self.assertTrue(any(CASE in item.message for item in plain), lines(plain))
        self.assertEqual(lines(renamed), relabeled(plain, CASE, LABEL))

    def test_detection_time_missing(self) -> None:
        plain = refused(lambda: compile_fixtures(evaluations=evaluations_from(), detected_at=None))
        renamed = refused(
            lambda: compile_fixtures(
                evaluations=evaluations_from(trackingId=OVERRIDE), detected_at=None
            )
        )

        self.assert_relabeled(plain, renamed)
        # The list keeps its correlation-id order, so the renamed record keeps its place.
        self.assertIn(f"case-04efea8c137ae82f, {LABEL}, case-490f49bfdd1bd019", renamed[0].message)

    def test_evaluation_before_detection(self) -> None:
        early = {"completedAt": "2026-07-30T00:00:00Z"}
        plain = refused(lambda: compile_fixtures(evaluations=evaluations_from(**early)))
        renamed = refused(
            lambda: compile_fixtures(evaluations=evaluations_from(trackingId=OVERRIDE, **early))
        )

        self.assert_relabeled(plain, renamed)
        self.assertEqual(
            renamed[0].message,
            f"{LABEL} was evaluated at 2026-07-30T00:00:00Z, before its detection time "
            "2026-08-01T00:00:00Z (source attestation); attest an earlier detection time, or "
            "correct completedAt",
        )

    def test_closed_without_disposition(self) -> None:
        def closed(evaluations: EvaluationSet) -> EvaluationSet:
            return EvaluationSet(
                entries=tuple(
                    replace(entry, disposition=CaseStatus.CLOSED, closed_disposition=None)
                    for entry in evaluations.entries
                )
            )

        plain = refused(lambda: compile_fixtures(evaluations=closed(evaluations_from())))
        renamed = refused(
            lambda: compile_fixtures(evaluations=closed(evaluations_from(trackingId=OVERRIDE)))
        )

        self.assert_relabeled(plain, renamed)
        self.assertEqual(
            renamed[0].message,
            f"{LABEL} is closed with no recorded disposition; supply closedDisposition",
        )

    def test_detection_clock_out_of_range(self) -> None:
        plain = refused(
            lambda: compile_fixtures(evaluations=evaluations_from(), detected_at=LATE_DETECTION)
        )
        renamed = refused(
            lambda: compile_fixtures(
                evaluations=evaluations_from(trackingId=OVERRIDE), detected_at=LATE_DETECTION
            )
        )

        self.assert_relabeled(plain, renamed)

    def test_evaluation_clock_out_of_range(self) -> None:
        plain = refused(
            lambda: compile_fixtures(
                evaluations=with_completion(evaluations_from(), LATE_COMPLETION)
            )
        )
        renamed = refused(
            lambda: compile_fixtures(
                evaluations=with_completion(evaluations_from(trackingId=OVERRIDE), LATE_COMPLETION)
            )
        )

        self.assert_relabeled(plain, renamed)
        self.assertTrue(renamed[0].message.startswith(f"{LABEL} has an evaluation completed "))

    def test_partial_detection_and_its_order_warning(self) -> None:
        match = {"sourceRecordId": BANNER_RULE, "sourceType": "xccdf"}
        early = {"match": match, "completedAt": "2026-08-02T00:00:00Z"}
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "mixed-timestamps.xml"
            path.write_text(MIXED_TIMESTAMP_XCCDF, encoding="utf-8")
            plain = compile_fixtures(artifacts=(path,), evaluations=evaluations_for(early))
            renamed = compile_fixtures(
                artifacts=(path,),
                evaluations=evaluations_for({**early, "trackingId": OVERRIDE}),
            )
        (record,) = plain.vulnerabilities
        label = f"{OVERRIDE} ({record.tracking_id})"

        codes = [item.code for item in plain.diagnostics]
        self.assertIn("detection_time_partial", codes)
        self.assertIn("evaluation_before_partial_detection", codes)
        self.assertTrue(any(record.tracking_id in item.message for item in plain.diagnostics))
        self.assertEqual(
            lines(renamed.diagnostics), relabeled(plain.diagnostics, record.tracking_id, label)
        )

    def test_accepted_and_period_notes(self) -> None:
        september = {
            "period_from": datetime(2026, 9, 1, tzinfo=UTC),
            "period_to": datetime(2026, 9, 30, 23, 59, 59, tzinfo=UTC),
            "as_of": datetime(2026, 10, 1, tzinfo=UTC),
        }
        disposed = {"completedAt": "2026-08-05T00:00:00Z", "disposition": "fully_mitigated"}
        runs: dict[str, Callable[[dict[str, object]], Any]] = {
            "vdt accepted_excluded": lambda extra: compile_fixtures(
                evaluations=evaluations_from(**ACCEPTANCE, **extra)
            ),
            "vdt excluded_by_period": lambda extra: compile_fixtures(
                evaluations=evaluations_from(**disposed, **extra), **september
            ),
            "vdt-accepted excluded_by_period": lambda extra: compile_fixtures(
                evaluations=evaluations_from(**ACCEPTANCE, **extra), **september
            ),
            "avi excluded_by_period": lambda extra: compile_fixtures(
                kind="avi", evaluations=evaluations_from(**ACCEPTANCE, **extra), **september
            ),
        }
        for name, compile_run in runs.items():
            with self.subTest(run=name):
                plain = compile_run({})
                renamed = compile_run({"trackingId": OVERRIDE})
                code = name.split()[1]
                self.assertIn(code, [item.code for item in plain.diagnostics])
                self.assert_relabeled(plain.diagnostics, renamed.diagnostics)

    def test_acceptance_rationale_missing(self) -> None:
        def without_rationale(extra: dict[str, object]) -> list[ReportDiagnostic]:
            record_set = compile_record_set_from_artifacts(
                list(ARTIFACTS),
                options=options(),
                evaluations=evaluations_from(**ACCEPTANCE, **extra),
            )
            records = tuple(
                replace(item, evaluation=replace(item.evaluation, acceptance_rationale=None))
                if item.status is CaseStatus.ACCEPTED and item.evaluation is not None
                else item
                for item in record_set.records
            )
            return refused(lambda: project_avi(replace(record_set, records=records)))

        self.assert_relabeled(without_rationale({}), without_rationale({"trackingId": OVERRIDE}))

    def test_kev_match_incomplete(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            crowded = hdf_control_artifact(
                Path(directory), {"cci": list(HDF_CCIS), "cve": ["CVE-2099-0001"]}
            )
            plain = kev_report(catalog=fixture_catalog(), artifacts=[crowded], evaluations=None)
            (record,) = plain.vulnerabilities
            match = {
                "sourceRecordId": record.source_record_id,
                "sourceType": record.source_type,
                "contextKey": record.context_key,
            }
            with_entry = Path(directory) / "with-entry.json"
            renamed_path = Path(directory) / "renamed.json"
            for path, extra in ((with_entry, {}), (renamed_path, {"trackingId": OVERRIDE})):
                path.write_text(
                    evaluation_json(match=match, completedAt="2026-09-06T00:00:00Z", **extra),
                    encoding="utf-8",
                )
            evaluated = kev_report(
                catalog=fixture_catalog(), artifacts=[crowded], evaluations=with_entry
            )
            renamed = kev_report(
                catalog=fixture_catalog(), artifacts=[crowded], evaluations=renamed_path
            )
        label = f"{OVERRIDE} ({record.tracking_id})"

        self.assertIn("kev_match_incomplete", [item.code for item in evaluated.diagnostics])
        self.assertEqual(
            lines(renamed.diagnostics),
            relabeled(evaluated.diagnostics, record.tracking_id, label),
        )

    def test_a_contradicted_gap_names_its_case_by_both_ids(self) -> None:
        (gap,) = gaps("lab-gap-01")
        (tracking_id,) = tracking_ids(gap)
        scan = observation("lab-gap-01", at=datetime(2026, 8, 2, tzinfo=UTC))
        inventory = inventory_of(host("lab-gap-01", expectedSince=EXPECTED_SINCE))

        def compile_gap_aware(evaluations: EvaluationSet) -> list[ReportDiagnostic]:
            observations = (gap, scan)
            record_set = compile_record_set(
                artifacts=(),
                observations=observations,
                ingest_diagnostics=(),
                evaluations_by_tracking_id=vdt_module._match_evaluations(
                    group_open_observations(observations), evaluations
                ),
                attestation=DetectionAttestation(default=DETECTED_AT),
                options=options(inventory=inventory),
                gap_aware=True,
            )
            return list(record_set.diagnostics)

        plain = compile_gap_aware(evaluations_with(gap_match(gap)))
        renamed = compile_gap_aware(evaluations_with(gap_match(gap), trackingId=OVERRIDE))
        label = f"{OVERRIDE} ({tracking_id})"

        self.assertIn("coverage_gap_contradicted", [item.code for item in plain])
        self.assertEqual(lines(renamed), relabeled(plain, tracking_id, label))
        (note,) = [item for item in renamed if item.code == "coverage_gap_contradicted"]
        self.assertTrue(note.message.startswith(f"{label} carries the recorded gap"))

    def test_a_record_with_no_override_names_its_correlation_id_alone(self) -> None:
        early = {"completedAt": "2026-07-30T00:00:00Z"}
        diagnostics = refused(lambda: compile_fixtures(evaluations=evaluations_from(**early)))

        self.assertTrue(diagnostics[0].message.startswith(f"{CASE} was evaluated at "))


class PersistedRecordLabelTests(HistoryOrderFixture):
    """The writers, `store verify` and a report from the store name a renamed case alike."""

    def untimed_case(self) -> str:
        self.ingest(self.artifact("untimed", [("lab-untimed", None)]))
        self.correlate()
        return self.only_case()

    def timed_case(self) -> str:
        self.ingest(self.artifact("timed", [("lab-timed", TIMED_AT)]))
        self.correlate()
        return self.only_case()

    def class_b_refusal(self) -> list[str]:
        """Return the lines a Class B report from this store refuses with, the class verify
        names first."""

        with self.assertRaises(ReportCompileError) as caught:
            compile_record_set_from_history(
                self.repository,
                options=options(detected_at=None, certification_class=CertificationClass.B),
            )
        return rendered(caught.exception.diagnostics)

    def identify_around(self, tracking_id: str) -> None:
        self.append_around(tracking_id, CASE_IDENTIFIED, {"providerTrackingId": OVERRIDE})

    def test_evaluate_refuses_with_the_label_the_report_and_verify_print(self) -> None:
        case = self.untimed_case()
        self.attest([case], LATE_ATTESTATION)
        evaluations = self.banner_evaluation(trackingId=OVERRIDE)

        refusal = self.refused(lambda: self.evaluate(evaluations))

        label = f"{OVERRIDE} ({case})"
        self.assertEqual(
            rendered(refusal.diagnostics),
            [
                f"error: evaluation_before_detection: {label} was evaluated at {EARLY}, before "
                "its detection time 2026-08-05T00:00:00Z (source attestation); attest an "
                f"earlier detection time, or correct completedAt [{BANNER_RULE}]"
            ],
        )
        self.identify_around(case)
        self.evaluate_around(evaluations, case)
        self.assertEqual(self.report_refusal(), rendered(refusal.diagnostics))
        (fault,) = evaluation_order_faults(self.repository)
        self.assertEqual(fault.message, refusal.diagnostics[0].message)

    def test_evaluate_names_a_new_override_over_a_recorded_one(self) -> None:
        # The entry renames a case already renamed: the write leaves the entry's override,
        # so the refusal names that one, as the report from the store does after it (CL5B-04).
        case = self.untimed_case()
        self.identify_around(case)
        self.evaluate_around(self.banner_evaluation(), case)
        self.attest([case], datetime(2026, 8, 1, tzinfo=UTC))
        self.append_around(
            case,
            DETECTION_ATTESTED,
            {
                "detectedAt": "2026-08-05T00:00:00Z",
                "rationale": "Re-attested around the writer.",
                "attestedAt": "2026-08-21T12:00:00Z",
            },
        )
        renamed = self.banner_evaluation(trackingId="NEW-1")

        refusal = self.refused(lambda: self.evaluate(renamed))

        self.assertTrue(refusal.diagnostics[0].message.startswith(f"NEW-1 ({case}) was "))
        self.append_around(case, CASE_IDENTIFIED, {"providerTrackingId": "NEW-1"})
        self.assertEqual(self.report_refusal(), rendered(refusal.diagnostics))

    def test_evaluate_names_a_retained_override_as_the_report_will(self) -> None:
        # The entry states no trackingId, so the recorded override stands (ADR 0008), and the
        # refusal names the case as the report from the store would after the write.
        case = self.untimed_case()
        self.identify_around(case)
        self.evaluate_around(self.banner_evaluation(), case)
        self.attest([case], datetime(2026, 8, 1, tzinfo=UTC))
        self.append_around(
            case,
            DETECTION_ATTESTED,
            {
                "detectedAt": "2026-08-05T00:00:00Z",
                "rationale": "Re-attested around the writer.",
                "attestedAt": "2026-08-21T12:00:00Z",
            },
        )

        refusal = self.refused(lambda: self.evaluate(self.banner_evaluation()))

        self.assertTrue(refusal.diagnostics[0].message.startswith(f"{OVERRIDE} ({case}) was "))
        self.assertEqual(self.report_refusal(), rendered(refusal.diagnostics))

    def test_attest_refuses_with_the_label(self) -> None:
        case = self.untimed_case()
        self.attest([case], datetime(2026, 8, 1, tzinfo=UTC))
        self.evaluate(self.banner_evaluation(trackingId=OVERRIDE))

        refusal = self.refused(lambda: self.attest([case], LATE_ATTESTATION))

        self.assertTrue(refusal.diagnostics[0].message.startswith(f"{OVERRIDE} ({case}) was "))

    def test_verify_names_late_clocks_in_the_report_words(self) -> None:
        case = self.untimed_case()
        self.attest([case], datetime(2026, 8, 1, tzinfo=UTC))
        evaluations = with_completion(self.banner_evaluation(), LATE_COMPLETION)
        self.identify_around(case)
        self.evaluate_around(evaluations, case)

        (fault,) = clock_faults(self.repository)
        (refusal,) = self.class_b_refusal()

        self.assertTrue(fault.message.startswith(f"{OVERRIDE} ({case}) has an evaluation "))
        self.assertEqual(refusal, f"error: clock_out_of_range: {fault.message} [{BANNER_RULE}]")

    def test_verify_names_a_late_detection_in_the_report_words(self) -> None:
        case = self.untimed_case()
        self.attest([case], datetime(2026, 8, 1, tzinfo=UTC))
        self.evaluate(self.banner_evaluation(trackingId=OVERRIDE))
        self.append_around(
            case,
            DETECTION_ATTESTED,
            {
                "detectedAt": "9999-12-31T00:00:00Z",
                "rationale": "Attested around the writer.",
                "attestedAt": "2026-08-21T12:00:00Z",
            },
        )

        faults = [item for item in clock_faults(self.repository)]
        (refusal,) = self.class_b_refusal()

        self.assertEqual(len(faults), 1)
        self.assertTrue(faults[0].message.startswith(f"{OVERRIDE} ({case}) has detection time "))
        self.assertEqual(refusal, f"error: clock_out_of_range: {faults[0].message} [{BANNER_RULE}]")

    def test_a_stale_case_is_named_by_both_ids(self) -> None:
        self.timed_case()
        self.append_around(ORPHAN_CASE, CASE_CREATED, orphan_created(ORPHAN_CASE))
        orphan = self.banner_evaluation(completedAt="2026-08-21T12:00:00Z")
        self.append_around(
            ORPHAN_CASE, CASE_EVALUATED, history_writers._evaluation_payload(orphan.entries[0])
        )
        self.identify_around(ORPHAN_CASE)

        (stale,) = [item for item in self.report().diagnostics if item.code == "stale_case"]

        self.assertEqual(
            stale.message,
            f"{OVERRIDE} ({ORPHAN_CASE}) is recorded in history but no open observation group "
            "matches it, so it is not in this report",
        )

    def test_an_unevaluated_case_is_named_by_its_tracking_id_alone(self) -> None:
        # An override reaches a report only through an evaluation, so a case identified
        # around the writers with no evaluation is named as the report names it.
        self.timed_case()
        self.append_around(ORPHAN_CASE, CASE_CREATED, orphan_created(ORPHAN_CASE))
        self.identify_around(ORPHAN_CASE)

        (stale,) = [item for item in self.report().diagnostics if item.code == "stale_case"]
        labels = {item.tracking_id: item.label for item in fold_all_cases(self.repository)}

        self.assertTrue(stale.message.startswith(f"{ORPHAN_CASE} is recorded"))
        self.assertEqual(labels[ORPHAN_CASE], ORPHAN_CASE)

    def partial_case(self) -> str:
        """Ingest a partly timestamped banner result, which no attestation applies to."""

        path = self.directory / "partial.xml"
        path.write_text(
            xccdf(
                "partial",
                [("lab-timed", "2026-08-03T09:00:00Z"), ("lab-untimed", None)],
                BANNER_RULE,
            ),
            encoding="utf-8",
        )
        self.ingest(path)
        self.correlate()
        (case,) = [
            item.tracking_id
            for item in fold_all_cases(self.repository)
            if item.source_record_id == BANNER_RULE
        ]
        return case

    def rule_case(self, rule: str) -> str:
        self.ingest(self.artifact(rule, [("lab-untimed", None)], rule=rule))
        self.correlate()
        (case,) = [
            item.tracking_id
            for item in fold_all_cases(self.repository)
            if item.source_record_id == rule
        ]
        return case

    def damage(self, tracking_id: str) -> None:
        """Append an event no contract publishes, so the case stream no longer folds."""

        stream_id = case_stream_id(tracking_id)
        self.repository.store.append(
            stream_id,
            [
                NewEvent(
                    event_type="case.bogus",
                    occurred_at=datetime(2026, 8, 21, 12, tzinfo=UTC),
                    payload={},
                    metadata={"actor": "tester"},
                )
            ],
            expected_version=len(self.repository.read_stream(stream_id)),
        )

    def attest_cli(self, *cases: str) -> tuple[int, str, str]:
        selection = [argument for case in cases for argument in ("--case", case)]
        return run(
            [
                "cases",
                "attest-detection",
                "--db",
                str(self.database),
                *selection,
                "--detected-at",
                "2026-08-01T00:00:00Z",
                "--rationale",
                "Attested from the change record.",
            ]
        )

    def test_attestation_not_applicable_names_the_case_by_both_ids(self) -> None:
        case = self.partial_case()
        self.evaluate(
            self.banner_evaluation(trackingId=OVERRIDE, completedAt="2026-08-04T00:00:00Z")
        )

        code, _, err = self.attest_cli(case)

        self.assertEqual(code, 0, err)
        self.assertIn(
            f"warning: attestation_not_applicable: {OVERRIDE} ({case}) carries a source timestamp",
            err.splitlines(),
        )

    def test_a_damaged_unrelated_stream_leaves_the_attestation_reported(self) -> None:
        # The labels come from the streams the attestation already read, so a case stream
        # it never selected cannot turn a committed write into a failure (CL5B-01).
        case = self.partial_case()
        self.evaluate(
            self.banner_evaluation(trackingId=OVERRIDE, completedAt="2026-08-04T00:00:00Z")
        )
        attestable = self.rule_case("sshd_disable_root_login")
        self.damage(self.rule_case("audit_rules_immutable"))

        code, out, err = self.attest_cli(case, attestable)

        self.assertEqual(code, 0, err)
        self.assertEqual(
            err.splitlines(),
            [
                f"warning: attestation_not_applicable: {OVERRIDE} ({case}) carries a source "
                "timestamp"
            ],
        )
        self.assertEqual(
            out,
            "attested 1 case(s), skipped 0 unchanged case(s), 1 not applicable case(s)\n",
        )

    def test_a_damaged_not_applicable_stream_is_named_by_its_tracking_id(self) -> None:
        # The case gains no event, so a stream `store verify` rejects is named by the id the
        # command was given rather than refused (CL5B-01).
        case = self.partial_case()
        self.evaluate(
            self.banner_evaluation(trackingId=OVERRIDE, completedAt="2026-08-04T00:00:00Z")
        )
        self.damage(case)

        code, out, err = self.attest_cli(case)

        self.assertEqual(code, 0, err)
        self.assertEqual(
            err.splitlines(),
            [f"warning: attestation_not_applicable: {case} carries a source timestamp"],
        )
        self.assertEqual(
            out,
            "attested 0 case(s), skipped 0 unchanged case(s), 1 not applicable case(s)\n",
        )
