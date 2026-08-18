from __future__ import annotations

import unittest
from datetime import UTC, datetime

from trustroll.models import (
    CaseStatus,
    Evaluation,
    Observation,
    ObservationDisposition,
    PainRating,
    ResourceRef,
    SourceSeverity,
    VulnerabilityCase,
)


NOW = datetime(2026, 8, 18, 20, 0, tzinfo=UTC)


def sample_observation(**overrides: object) -> Observation:
    values: dict[str, object] = {
        "observation_id": "obs-001",
        "source_type": "cklb",
        "source_tool": "stig-viewer",
        "source_record_id": "V-123456",
        "resource": ResourceRef("host-001", "host"),
        "observed_at": NOW,
        "ingested_at": NOW,
        "disposition": ObservationDisposition.OPEN,
        "source_severity": SourceSeverity.HIGH,
        "context_key": "benchmark-v1",
    }
    values.update(overrides)
    return Observation(**values)  # type: ignore[arg-type]


class ObservationTests(unittest.TestCase):
    def test_fingerprint_is_stable(self) -> None:
        first = sample_observation()
        second = sample_observation(
            observation_id="obs-002",
            title="display text changed",
            source_severity=SourceSeverity.LOW,
        )
        self.assertEqual(first.fingerprint, second.fingerprint)

    def test_fingerprint_changes_with_resource(self) -> None:
        first = sample_observation()
        second = sample_observation(resource=ResourceRef("host-002", "host"))
        self.assertNotEqual(first.fingerprint, second.fingerprint)

    def test_timestamp_must_be_timezone_aware(self) -> None:
        with self.assertRaisesRegex(ValueError, "observed_at must include a timezone"):
            sample_observation(observed_at=datetime(2026, 8, 18, 20, 0))


class VulnerabilityCaseTests(unittest.TestCase):
    def test_case_requires_observation(self) -> None:
        with self.assertRaisesRegex(ValueError, "at least one observation"):
            VulnerabilityCase(
                case_id="TR-1",
                title="Coverage failure",
                description="A scheduled validation did not run.",
                status=CaseStatus.NEW,
                observation_ids=(),
                created_at=NOW,
            )

    def test_evaluation_creates_new_projection(self) -> None:
        case = VulnerabilityCase(
            case_id="TR-1",
            title="Example weakness",
            description="Synthetic test case.",
            status=CaseStatus.EVALUATING,
            observation_ids=("obs-001",),
            created_at=NOW,
        )
        evaluation = Evaluation(
            evaluation_id="eval-001",
            completed_at=NOW,
            is_internet_reachable=True,
            is_likely_exploitable=True,
            pain=PainRating.N4,
            potential_agency_impact="Could disrupt one agency customer.",
            rationale="Synthetic test rationale.",
            evaluator="test-user",
        )

        updated = case.with_evaluation(evaluation)

        self.assertIsNone(case.current_evaluation)
        self.assertEqual(updated.current_evaluation, evaluation)
        self.assertEqual(updated.status, CaseStatus.ACTIVE)


if __name__ == "__main__":
    unittest.main()
