from __future__ import annotations

import unittest
from datetime import UTC, datetime

from complyroll.models import (
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
ARTIFACT_DIGEST = "a" * 64


def sample_observation(**overrides: object) -> Observation:
    values: dict[str, object] = {
        "observation_id": "obs-001",
        "source_type": "cklb",
        "source_tool": "stig-viewer",
        "parser_name": "complyroll.cklb",
        "parser_version": "1",
        "source_record_id": "V-123456",
        "resource": ResourceRef("host-001", "host"),
        "observed_at": NOW,
        "ingested_at": NOW,
        "disposition": ObservationDisposition.OPEN,
        "source_severity": SourceSeverity.HIGH,
        "source_artifact_digest": ARTIFACT_DIGEST,
        "source_artifact_name": "sample.cklb",
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

    def test_fingerprint_changes_with_source_artifact(self) -> None:
        first = sample_observation()
        second = sample_observation(source_artifact_digest="b" * 64)
        self.assertNotEqual(first.fingerprint, second.fingerprint)

    def test_fingerprint_changes_with_parser_version(self) -> None:
        first = sample_observation()
        second = sample_observation(parser_version="2")
        self.assertNotEqual(first.fingerprint, second.fingerprint)

    def test_timestamp_must_be_timezone_aware(self) -> None:
        with self.assertRaisesRegex(ValueError, "observed_at must include a timezone"):
            sample_observation(observed_at=datetime(2026, 8, 18, 20, 0))

    def test_unknown_observation_time_is_preserved(self) -> None:
        observation = sample_observation(observed_at=None)
        self.assertIsNone(observation.to_canonical_dict()["observed_at"])

    def test_canonical_json_is_stable(self) -> None:
        first = sample_observation(
            source_identifiers=("CCI-000001",),
            source_metadata=(("rule_version", "1"),),
        )
        second = sample_observation(
            observation_id="obs-002",
            source_identifiers=("CCI-000001",),
            source_metadata=(("rule_version", "1"),),
        )
        self.assertNotEqual(first.to_canonical_json(), second.to_canonical_json())
        self.assertEqual(first.fingerprint, second.fingerprint)

    def test_source_artifact_digest_is_required(self) -> None:
        with self.assertRaisesRegex(ValueError, "source_artifact_digest"):
            sample_observation(source_artifact_digest="invalid")


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
