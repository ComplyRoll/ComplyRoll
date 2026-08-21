from __future__ import annotations

import unittest
from datetime import UTC, datetime, timedelta, timezone

from complyroll.models import (
    CaseStatus,
    Evaluation,
    EvidenceArtifact,
    Observation,
    ObservationDisposition,
    ObservationOrigin,
    PainRating,
    ResourceRef,
    Sensitivity,
    SourceSeverity,
    VulnerabilityCase,
)

NOW = datetime(2026, 8, 18, 20, 0, tzinfo=UTC)
ARTIFACT_DIGEST = "a" * 64

# ADR 0002 identity lock: the artifact-bound recipe must stay byte-for-byte stable.
SAMPLE_ARTIFACT_FINGERPRINT = "84fd0d425515b938bcdd1c227bf654a52a26072a58426e0b169d0068b8ea9aaa"


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


def system_observation(**overrides: object) -> Observation:
    """Build a process-health observation that is bound to a job, not an artifact."""

    values: dict[str, object] = {
        "observation_id": "obs-system",
        "source_type": "process-health",
        "source_tool": "complyroll",
        "parser_name": "complyroll.health",
        "parser_version": "1",
        "source_record_id": "stale-scan",
        "resource": ResourceRef("svc-1", "service"),
        "observed_at": NOW,
        "ingested_at": NOW,
        "disposition": ObservationDisposition.OPEN,
        "context_key": "scan-freshness-check",
        "origin": ObservationOrigin.SYSTEM,
    }
    values.update(overrides)
    return Observation(**values)  # type: ignore[arg-type]


def sample_evaluation(**overrides: object) -> Evaluation:
    values: dict[str, object] = {
        "evaluation_id": "eval-001",
        "completed_at": NOW,
        "is_internet_reachable": True,
        "is_likely_exploitable": True,
        "pain": PainRating.N4,
        "potential_agency_impact": "Could disrupt one agency customer.",
        "rationale": "Synthetic test rationale.",
        "evaluator": "test-user",
    }
    values.update(overrides)
    return Evaluation(**values)  # type: ignore[arg-type]


def sample_case(**overrides: object) -> VulnerabilityCase:
    values: dict[str, object] = {
        "case_id": "TR-1",
        "title": "Example weakness",
        "description": "Synthetic test case.",
        "status": CaseStatus.EVALUATING,
        "observation_ids": ("obs-001",),
        "created_at": NOW,
    }
    values.update(overrides)
    return VulnerabilityCase(**values)  # type: ignore[arg-type]


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

    def test_artifact_fingerprint_recipe_is_frozen(self) -> None:
        observation = sample_observation()
        self.assertEqual(observation.fingerprint, SAMPLE_ARTIFACT_FINGERPRINT)
        self.assertEqual(
            observation.derived_observation_id, f"obs-{SAMPLE_ARTIFACT_FINGERPRINT}"
        )

    def test_default_origin_is_artifact(self) -> None:
        self.assertIs(sample_observation().origin, ObservationOrigin.ARTIFACT)

    def test_canonical_dict_reports_origin(self) -> None:
        self.assertEqual(sample_observation().to_canonical_dict()["origin"], "artifact")
        self.assertEqual(system_observation().to_canonical_dict()["origin"], "system")


class ObservationValidationTests(unittest.TestCase):
    def test_disposition_must_be_an_enum(self) -> None:
        with self.assertRaisesRegex(TypeError, "disposition must be an ObservationDisposition"):
            sample_observation(disposition="open")

    def test_source_severity_must_be_an_enum(self) -> None:
        with self.assertRaisesRegex(TypeError, "source_severity must be a SourceSeverity"):
            sample_observation(source_severity="high")

    def test_origin_must_be_an_enum(self) -> None:
        with self.assertRaisesRegex(TypeError, "origin must be an ObservationOrigin"):
            sample_observation(origin="system")

    def test_sequences_are_coerced_to_tuples(self) -> None:
        observation = sample_observation(
            source_identifiers=["CCI-000001", "CCI-000002"],
            source_metadata={"rule_id": "SV-1"},
            evidence_ids=["ev-1"],
        )
        self.assertEqual(observation.source_identifiers, ("CCI-000001", "CCI-000002"))
        self.assertEqual(observation.source_metadata, (("rule_id", "SV-1"),))
        self.assertEqual(observation.evidence_ids, ("ev-1",))

    def test_source_identifier_entries_must_be_strings(self) -> None:
        with self.assertRaisesRegex(TypeError, "source_identifiers"):
            sample_observation(source_identifiers=[1])

    def test_source_metadata_entries_must_be_string_pairs(self) -> None:
        with self.assertRaisesRegex(TypeError, "source_metadata"):
            sample_observation(source_metadata=[("rule_id", 1)])

    def test_uppercase_digest_is_normalized_and_keeps_identity(self) -> None:
        observation = sample_observation(source_artifact_digest=ARTIFACT_DIGEST.upper())
        self.assertEqual(observation.source_artifact_digest, ARTIFACT_DIGEST)
        self.assertEqual(observation.fingerprint, SAMPLE_ARTIFACT_FINGERPRINT)


class SystemObservationTests(unittest.TestCase):
    def test_process_health_observation_is_constructible(self) -> None:
        observation = system_observation()
        self.assertIs(observation.origin, ObservationOrigin.SYSTEM)
        self.assertEqual(observation.source_artifact_name, "")
        self.assertEqual(observation.source_artifact_digest, "")

    def test_system_identity_is_stable_across_constructions(self) -> None:
        first = system_observation()
        second = system_observation(
            observation_id="obs-other",
            ingested_at=NOW + timedelta(days=1),
            title="display text changed",
            source_severity=SourceSeverity.LOW,
        )
        self.assertEqual(first.fingerprint, second.fingerprint)
        self.assertEqual(first.derived_observation_id, second.derived_observation_id)
        self.assertTrue(first.derived_observation_id.startswith("obs-"))

    def test_system_identity_differs_from_artifact_identity(self) -> None:
        self.assertNotEqual(system_observation().fingerprint, SAMPLE_ARTIFACT_FINGERPRINT)

    def test_system_identity_tracks_the_detection_window(self) -> None:
        first = system_observation()
        second = system_observation(observed_at=NOW + timedelta(hours=1))
        self.assertNotEqual(first.fingerprint, second.fingerprint)

    def test_system_identity_ignores_the_detection_window_offset(self) -> None:
        phoenix = timezone(timedelta(hours=-7))
        first = system_observation()
        second = system_observation(observed_at=NOW.astimezone(phoenix))
        self.assertEqual(first.fingerprint, second.fingerprint)

    def test_system_identity_tracks_the_producing_job(self) -> None:
        first = system_observation()
        second = system_observation(context_key="coverage-check")
        self.assertNotEqual(first.fingerprint, second.fingerprint)

    def test_system_observation_rejects_an_artifact_digest(self) -> None:
        with self.assertRaisesRegex(ValueError, "source_artifact_digest"):
            system_observation(source_artifact_digest=ARTIFACT_DIGEST)

    def test_system_observation_rejects_an_artifact_name(self) -> None:
        with self.assertRaisesRegex(ValueError, "source_artifact_name"):
            system_observation(source_artifact_name="sample.cklb")

    def test_system_observation_requires_a_detection_time(self) -> None:
        with self.assertRaisesRegex(ValueError, "observed_at"):
            system_observation(observed_at=None)

    def test_system_observation_requires_a_context_key(self) -> None:
        with self.assertRaisesRegex(ValueError, "context_key must not be blank"):
            system_observation(context_key="")

    def test_artifact_observation_still_requires_a_digest(self) -> None:
        with self.assertRaisesRegex(ValueError, "source_artifact_digest"):
            sample_observation(source_artifact_digest="")


class EvidenceArtifactTests(unittest.TestCase):
    def _artifact(self, **overrides: object) -> EvidenceArtifact:
        values: dict[str, object] = {
            "evidence_id": "ev-1",
            "digest_sha256": ARTIFACT_DIGEST,
            "evidence_type": "scan-export",
            "description": "Synthetic evidence.",
            "collected_at": NOW,
        }
        values.update(overrides)
        return EvidenceArtifact(**values)  # type: ignore[arg-type]

    def test_digest_is_normalized_to_lowercase(self) -> None:
        self.assertEqual(self._artifact(digest_sha256="A" * 64).digest_sha256, ARTIFACT_DIGEST)

    def test_default_sensitivity_is_restricted(self) -> None:
        artifact = self._artifact()
        self.assertIs(artifact.sensitivity, Sensitivity.RESTRICTED)
        self.assertEqual(artifact.sensitivity, "restricted")

    def test_sensitivity_strings_are_coerced_to_the_enum(self) -> None:
        self.assertIs(self._artifact(sensitivity="public").sensitivity, Sensitivity.PUBLIC)

    def test_unknown_sensitivity_is_rejected(self) -> None:
        with self.assertRaisesRegex(ValueError, "sensitivity"):
            self._artifact(sensitivity="secret")

    def test_non_string_sensitivity_is_rejected(self) -> None:
        with self.assertRaisesRegex(TypeError, "sensitivity"):
            self._artifact(sensitivity=1)


class EvaluationValidationTests(unittest.TestCase):
    def test_pain_must_be_a_pain_rating(self) -> None:
        with self.assertRaisesRegex(TypeError, "pain must be a PainRating"):
            sample_evaluation(pain=6)

    def test_pain_string_is_rejected(self) -> None:
        with self.assertRaisesRegex(TypeError, "pain must be a PainRating"):
            sample_evaluation(pain="N4")

    def test_pain_none_is_rejected(self) -> None:
        with self.assertRaisesRegex(TypeError, "pain must be a PainRating"):
            sample_evaluation(pain=None)

    def test_reachability_must_be_a_bool(self) -> None:
        with self.assertRaisesRegex(TypeError, "is_internet_reachable must be a bool"):
            sample_evaluation(is_internet_reachable="yes")

    def test_exploitability_must_be_a_bool(self) -> None:
        with self.assertRaisesRegex(TypeError, "is_likely_exploitable must be a bool"):
            sample_evaluation(is_likely_exploitable=1)

    def test_false_positive_must_be_a_bool(self) -> None:
        with self.assertRaisesRegex(TypeError, "is_false_positive must be a bool"):
            sample_evaluation(is_false_positive="no")

    def test_evidence_ids_are_coerced_to_a_tuple(self) -> None:
        self.assertEqual(sample_evaluation(evidence_ids=["ev-1"]).evidence_ids, ("ev-1",))


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

    def test_status_must_be_an_enum(self) -> None:
        with self.assertRaisesRegex(TypeError, "status must be a CaseStatus"):
            sample_case(status="active")

    def test_observation_ids_are_coerced_to_a_tuple(self) -> None:
        case = sample_case(observation_ids=["obs-001", "obs-002"])
        self.assertEqual(case.observation_ids, ("obs-001", "obs-002"))

    def test_observation_id_entries_must_be_strings(self) -> None:
        with self.assertRaisesRegex(TypeError, "observation_ids"):
            sample_case(observation_ids=[1])

    def test_current_evaluation_must_be_an_evaluation(self) -> None:
        with self.assertRaisesRegex(TypeError, "current_evaluation"):
            sample_case(current_evaluation="eval-001")

    def test_evaluation_history_entries_must_be_evaluations(self) -> None:
        with self.assertRaisesRegex(TypeError, "evaluation_history"):
            sample_case(evaluation_history=("eval-001",))


class CaseStateMachineTests(unittest.TestCase):
    def test_new_history_starts_empty(self) -> None:
        self.assertEqual(sample_case().evaluation_history, ())

    def test_previous_evaluation_moves_into_history(self) -> None:
        first = sample_evaluation()
        second = sample_evaluation(evaluation_id="eval-002", pain=PainRating.N2)

        case = sample_case().with_evaluation(first).with_evaluation(second)

        self.assertEqual(case.current_evaluation, second)
        self.assertEqual(case.evaluation_history, (first,))
        self.assertEqual(case.status, CaseStatus.ACTIVE)

    def test_false_positive_evaluation_sets_false_positive_status(self) -> None:
        case = sample_case().with_evaluation(sample_evaluation(is_false_positive=True))
        self.assertEqual(case.status, CaseStatus.FALSE_POSITIVE)

    def test_accepted_case_cannot_be_silently_reopened(self) -> None:
        case = sample_case(status=CaseStatus.ACCEPTED)
        with self.assertRaisesRegex(ValueError, "requires reopen=True"):
            case.with_evaluation(sample_evaluation())

    def test_closed_case_cannot_be_silently_reopened(self) -> None:
        case = sample_case(status=CaseStatus.CLOSED)
        with self.assertRaisesRegex(ValueError, "requires reopen=True"):
            case.with_evaluation(sample_evaluation())

    def test_closed_case_reopens_explicitly(self) -> None:
        previous = sample_evaluation()
        case = sample_case(status=CaseStatus.CLOSED, current_evaluation=previous)

        reopened = case.with_evaluation(sample_evaluation(evaluation_id="eval-002"), reopen=True)

        self.assertEqual(reopened.status, CaseStatus.ACTIVE)
        self.assertEqual(reopened.evaluation_history, (previous,))

    def test_active_case_does_not_need_reopen(self) -> None:
        case = sample_case(status=CaseStatus.ACTIVE)
        self.assertEqual(case.with_evaluation(sample_evaluation()).status, CaseStatus.ACTIVE)

    def test_with_evaluation_rejects_non_evaluation(self) -> None:
        case = sample_case(status=CaseStatus.ACTIVE)
        with self.assertRaises(TypeError):
            case.with_evaluation("not an evaluation")  # type: ignore[arg-type]


class WrongTypeInputTests(unittest.TestCase):
    """Wrong types fail with TypeError, not an AttributeError from inside a validator."""

    def test_non_string_text_field_is_a_type_error(self) -> None:
        with self.assertRaises(TypeError):
            sample_observation(source_type=5)  # type: ignore[arg-type]

    def test_none_timestamp_is_a_type_error(self) -> None:
        with self.assertRaises(TypeError):
            sample_observation(ingested_at=None)  # type: ignore[arg-type]

    def test_string_timestamp_is_a_type_error(self) -> None:
        with self.assertRaises(TypeError):
            sample_observation(ingested_at="2026-01-01")  # type: ignore[arg-type]

    def test_bytes_digest_is_a_type_error(self) -> None:
        with self.assertRaises(TypeError):
            sample_observation(source_artifact_digest=b"a" * 64)  # type: ignore[arg-type]

    def test_none_resource_is_a_type_error(self) -> None:
        with self.assertRaises(TypeError):
            sample_observation(resource=None)  # type: ignore[arg-type]

    def test_non_string_display_fields_are_type_errors(self) -> None:
        for field_name, value in (
            ("title", 5),
            ("title", None),
            ("description", b"bytes"),
            ("context_key", None),
            ("context_key", ["x"]),
        ):
            with self.subTest(field=field_name):
                with self.assertRaises(TypeError):
                    sample_observation(**{field_name: value})

    def test_system_observation_rejects_falsy_non_string_artifact_fields(self) -> None:
        from complyroll.models import ObservationOrigin

        base = dict(
            origin=ObservationOrigin.SYSTEM,
            source_artifact_name="",
            source_artifact_digest="",
            context_key="scan-freshness-check",
        )
        for field_name, value in (
            ("source_artifact_name", 0),
            ("source_artifact_name", []),
            ("source_artifact_digest", 0),
            ("source_artifact_digest", None),
        ):
            with self.subTest(field=field_name):
                with self.assertRaises(TypeError):
                    sample_observation(**{**base, field_name: value})


if __name__ == "__main__":
    unittest.main()
