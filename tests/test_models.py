from __future__ import annotations

import json
import unittest
from datetime import UTC, datetime, timedelta, timezone

from complyroll.models import (
    RESERVED_SOURCE_TYPE_PREFIX,
    EvidenceArtifact,
    Observation,
    ObservationClockError,
    ObservationDisposition,
    ObservationOrigin,
    ResourceRef,
    Sensitivity,
    SourceSeverity,
)

NOW = datetime(2026, 8, 18, 20, 0, tzinfo=UTC)
ARTIFACT_DIGEST = "a" * 64

# ADR 0002 identity lock: the artifact-bound recipe must stay byte-for-byte stable.
SAMPLE_ARTIFACT_FINGERPRINT = "84fd0d425515b938bcdd1c227bf654a52a26072a58426e0b169d0068b8ea9aaa"


def sample_observation(**overrides: object) -> Observation:
    """Build one artifact-bound observation carrying the identifier adapters derive.

    Artifact-bound observations are named after their own fingerprint, and
    `Observation.from_canonical_dict` requires that, so the default fixture spells the
    identifier the same way every adapter does. Tests that care about a different
    identifier still pass one.
    """

    values: dict[str, object] = {
        "observation_id": f"obs-{SAMPLE_ARTIFACT_FINGERPRINT}",
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
        self.assertEqual(observation.derived_observation_id, f"obs-{SAMPLE_ARTIFACT_FINGERPRINT}")

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


class ReservedSourceTypeTests(unittest.TestCase):
    """ADR 0014: the complyroll. source-type prefix belongs to system observations."""

    def test_the_reserved_prefix_is_complyroll_dot(self) -> None:
        self.assertEqual(RESERVED_SOURCE_TYPE_PREFIX, "complyroll.")

    def test_an_artifact_observation_under_the_prefix_is_refused(self) -> None:
        for source_type in ("complyroll.detection-process", "complyroll.anything"):
            with self.subTest(source_type=source_type):
                with self.assertRaisesRegex(ValueError, "reserved for system observations"):
                    sample_observation(source_type=source_type)

    def test_a_near_miss_of_the_prefix_is_an_ordinary_source_type(self) -> None:
        for source_type in ("complyroll", "complyroll-cklb", "cklb.complyroll."):
            with self.subTest(source_type=source_type):
                observation = sample_observation(source_type=source_type)
                self.assertIs(observation.origin, ObservationOrigin.ARTIFACT)

    def test_a_stored_artifact_observation_under_the_prefix_is_refused(self) -> None:
        stored = sample_observation().to_canonical_dict()
        stored["source_type"] = "complyroll.detection-process"
        with self.assertRaisesRegex(ValueError, "reserved for system observations"):
            Observation.from_canonical_dict(stored)

    def test_a_system_observation_under_the_prefix_round_trips(self) -> None:
        built = system_observation(source_type="complyroll.detection-process")
        observation = system_observation(
            source_type="complyroll.detection-process",
            observation_id=built.derived_observation_id,
        )
        self.assertIs(observation.origin, ObservationOrigin.SYSTEM)
        rebuilt = Observation.from_canonical_dict(observation.to_canonical_dict())
        self.assertEqual(rebuilt, observation)


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


class SystemClockTests(unittest.TestCase):
    """A system observation's identity is its UTC instant, so it has to have one (CL6A-D-01)."""

    NO_INSTANT = (
        datetime(1, 1, 1, 0, 30, tzinfo=timezone(timedelta(hours=1))),
        datetime(9999, 12, 31, 23, 59, 59, tzinfo=timezone(-timedelta(hours=23, minutes=59))),
    )
    LAST_INSTANTS = (
        datetime(1, 1, 1, 1, 0, tzinfo=timezone(timedelta(hours=1))),
        datetime(9999, 12, 31, 22, 59, 59, tzinfo=timezone(-timedelta(hours=1))),
    )

    def test_a_clock_with_no_utc_instant_is_refused_as_a_value_error(self) -> None:
        for clock in self.NO_INSTANT:
            with self.subTest(clock=clock.isoformat()):
                with self.assertRaises(ObservationClockError) as caught:
                    system_observation(observed_at=clock)
                self.assertIsInstance(caught.exception, ValueError)
                self.assertEqual(caught.exception.clock, clock)
                self.assertEqual(
                    str(caught.exception),
                    f"source time {clock.isoformat()} has no UTC instant inside the years 1 to "
                    "9999, so a system observation has no identity",
                )

    def test_the_canonical_reader_refuses_it_before_the_fingerprint(self) -> None:
        for clock in self.NO_INSTANT:
            with self.subTest(clock=clock.isoformat()):
                payload = system_observation().to_canonical_dict()
                payload["observed_at"] = clock.isoformat()
                with self.assertRaises(ObservationClockError):
                    Observation.from_canonical_dict(payload)

    def test_an_artifact_observation_still_holds_such_a_clock(self) -> None:
        # Its identity does not name its clock, so it reads, and `clock_problem` names it.
        for clock in self.NO_INSTANT:
            with self.subTest(clock=clock.isoformat()):
                observation = sample_observation(observed_at=clock)
                rebuilt = Observation.from_canonical_dict(observation.to_canonical_dict())
                self.assertEqual(rebuilt.observed_at, clock)

    def test_the_last_clocks_with_a_utc_instant_still_read(self) -> None:
        for clock in self.LAST_INSTANTS:
            with self.subTest(clock=clock.isoformat()):
                observation = system_observation(observed_at=clock)
                rebuilt = Observation.from_canonical_dict(observation.to_canonical_dict())
                self.assertEqual(rebuilt.fingerprint, observation.fingerprint)


class CanonicalRoundTripTests(unittest.TestCase):
    """ADR 0008 freezes `to_canonical_dict` as the `observation.recorded` payload.

    A stored payload is untrusted bytes, so the reader has to be the exact inverse of
    the writer: every key required, no key invented, timestamps spelled the one way
    this observation would spell them, and a fingerprint that still describes the
    fields it was derived from.
    """

    def test_a_written_observation_reads_back_equal(self) -> None:
        observation = sample_observation()

        rebuilt = Observation.from_canonical_dict(observation.to_canonical_dict())

        self.assertEqual(rebuilt, observation)
        self.assertEqual(rebuilt.to_canonical_dict(), observation.to_canonical_dict())

    def test_a_system_observation_reads_back_equal(self) -> None:
        observation = system_observation(
            source_identifiers=["CCI-000001"],
            source_metadata={"job": "freshness"},
            evidence_ids=["ev-1"],
        )

        rebuilt = Observation.from_canonical_dict(observation.to_canonical_dict())

        self.assertEqual(rebuilt, observation)
        self.assertEqual(rebuilt.fingerprint, observation.fingerprint)

    def test_unsorted_metadata_reads_back_canonically_equal_not_dataclass_equal(self) -> None:
        # The store writes canonical JSON with sorted keys, so metadata pairs come back
        # in key order rather than in the order the parser produced them. What the
        # round trip guarantees is canonical-JSON equality, not dataclass equality.
        observation = sample_observation(
            source_metadata=(("rule_version", "1"), ("check_id", "C-1")),
        )
        stored = json.loads(json.dumps(observation.to_canonical_dict(), sort_keys=True))

        rebuilt = Observation.from_canonical_dict(stored)

        self.assertEqual(rebuilt.to_canonical_json(), observation.to_canonical_json())
        self.assertEqual(rebuilt.source_metadata, (("check_id", "C-1"), ("rule_version", "1")))
        self.assertNotEqual(rebuilt, observation)

    def test_sorted_metadata_reads_back_dataclass_equal(self) -> None:
        observation = sample_observation(
            source_metadata=(("check_id", "C-1"), ("rule_version", "1")),
        )
        stored = json.loads(json.dumps(observation.to_canonical_dict(), sort_keys=True))

        rebuilt = Observation.from_canonical_dict(stored)

        self.assertEqual(rebuilt, observation)

    def test_an_observation_without_a_source_timestamp_reads_back_equal(self) -> None:
        observation = sample_observation(observed_at=None)

        rebuilt = Observation.from_canonical_dict(observation.to_canonical_dict())

        self.assertIsNone(rebuilt.observed_at)
        self.assertEqual(rebuilt, observation)

    def test_an_offset_timestamp_reads_back_as_the_same_instant(self) -> None:
        eastern = timezone(timedelta(hours=-5))
        observation = sample_observation(observed_at=NOW.astimezone(eastern))

        rebuilt = Observation.from_canonical_dict(observation.to_canonical_dict())

        self.assertEqual(rebuilt.observed_at, NOW)
        self.assertEqual(rebuilt, observation)

    def _stored(self, **overrides: object) -> dict[str, object]:
        payload = sample_observation().to_canonical_dict()
        payload.update(overrides)
        return payload

    def test_a_z_suffixed_timestamp_is_refused(self) -> None:
        stored = self._stored(ingested_at="2026-08-18T20:00:00Z")

        with self.assertRaisesRegex(ValueError, "canonical timestamp text"):
            Observation.from_canonical_dict(stored)

    def test_an_offset_without_a_colon_is_refused(self) -> None:
        stored = self._stored(ingested_at="2026-08-18T20:00:00+0000")

        with self.assertRaisesRegex(ValueError, "canonical timestamp text"):
            Observation.from_canonical_dict(stored)

    def test_a_trailing_zero_fraction_is_refused(self) -> None:
        stored = self._stored(ingested_at="2026-08-18T20:00:00.000000+00:00")

        with self.assertRaisesRegex(ValueError, "canonical timestamp text"):
            Observation.from_canonical_dict(stored)

    def test_a_naive_timestamp_is_refused(self) -> None:
        stored = self._stored(ingested_at="2026-08-18T20:00:00")

        with self.assertRaisesRegex(ValueError, "must include a UTC offset"):
            Observation.from_canonical_dict(stored)

    def test_an_offset_carrying_seconds_is_refused(self) -> None:
        # Python parses '+01:02:03' and re-serializes it unchanged, so the canonical
        # comparison alone would wave it through. RFC 3339 offsets are whole minutes.
        for field_name in ("ingested_at", "observed_at"):
            with self.subTest(field=field_name):
                stored = self._stored(**{field_name: "2026-08-18T20:00:00+01:02:03"})

                with self.assertRaisesRegex(ValueError, "whole number of minutes"):
                    Observation.from_canonical_dict(stored)

    def test_an_offset_of_whole_minutes_is_accepted(self) -> None:
        india = timezone(timedelta(hours=5, minutes=30))
        observation = sample_observation(observed_at=NOW.astimezone(india))

        rebuilt = Observation.from_canonical_dict(observation.to_canonical_dict())

        self.assertEqual(rebuilt.observed_at, NOW)

    def test_text_that_is_not_a_timestamp_is_refused(self) -> None:
        stored = self._stored(observed_at="last Tuesday")

        with self.assertRaisesRegex(ValueError, "must be an RFC 3339 timestamp"):
            Observation.from_canonical_dict(stored)

    def test_a_non_canonical_source_timestamp_is_refused(self) -> None:
        stored = self._stored(observed_at="2026-08-18T20:00:00Z")

        with self.assertRaisesRegex(ValueError, "canonical timestamp text"):
            Observation.from_canonical_dict(stored)

    def test_a_tampered_fingerprint_is_refused(self) -> None:
        stored = self._stored(fingerprint="f" * 64)

        with self.assertRaisesRegex(ValueError, "fingerprint does not match"):
            Observation.from_canonical_dict(stored)

    def test_a_tampered_field_moves_the_fingerprint_and_is_refused(self) -> None:
        stored = self._stored(source_record_id="V-000000")

        with self.assertRaisesRegex(ValueError, "fingerprint does not match"):
            Observation.from_canonical_dict(stored)

    def test_an_artifact_observation_must_carry_its_derived_identifier(self) -> None:
        # The fingerprint still describes the fields, so only the name was moved.
        # Adapters always assign the derived identifier, so a foreign one at rest is
        # a rename nothing legitimate performed.
        stored = self._stored(observation_id="obs-someone-elses-name")

        with self.assertRaisesRegex(ValueError, "observation_id does not match"):
            Observation.from_canonical_dict(stored)

    def test_a_system_observation_may_be_named_anything(self) -> None:
        # System observations are bound to the producing job rather than to received
        # bytes, and their identifiers are the caller's to choose (ADR 0002 amendment).
        observation = system_observation(observation_id="obs-freshness-2026-08-18")

        rebuilt = Observation.from_canonical_dict(observation.to_canonical_dict())

        self.assertEqual(rebuilt, observation)
        self.assertNotEqual(rebuilt.observation_id, rebuilt.derived_observation_id)

    def test_a_missing_key_is_refused(self) -> None:
        stored = self._stored()
        del stored["context_key"]

        with self.assertRaisesRegex(ValueError, "missing field\\(s\\): context_key"):
            Observation.from_canonical_dict(stored)

    def test_an_unknown_key_is_refused(self) -> None:
        stored = self._stored(severity_score=9.8)

        with self.assertRaisesRegex(ValueError, "unsupported field\\(s\\): severity_score"):
            Observation.from_canonical_dict(stored)

    def test_a_resource_that_gained_a_key_is_refused(self) -> None:
        stored = self._stored(
            resource={"resource_id": "host-001", "resource_type": "host", "owner": "team"}
        )

        with self.assertRaisesRegex(ValueError, "resource has unsupported field\\(s\\): owner"):
            Observation.from_canonical_dict(stored)

    def test_an_unknown_enum_value_is_refused(self) -> None:
        stored = self._stored(disposition="undecided")

        with self.assertRaisesRegex(ValueError, "disposition must be one of"):
            Observation.from_canonical_dict(stored)

    def test_a_wrong_typed_field_is_a_type_error(self) -> None:
        for field_name, value in (
            ("observation_id", 7),
            ("resource", "host-001"),
            ("source_identifiers", "CCI-000001"),
            ("source_metadata", [["rule_id", "SV-1"]]),
            ("disposition", 1),
        ):
            with self.subTest(field=field_name):
                with self.assertRaises(TypeError):
                    Observation.from_canonical_dict(self._stored(**{field_name: value}))

    def test_a_payload_that_is_not_a_mapping_is_a_type_error(self) -> None:
        with self.assertRaisesRegex(TypeError, "canonical observation must be a mapping"):
            Observation.from_canonical_dict(["observation_id"])  # type: ignore[arg-type]


class RemovedModelTests(unittest.TestCase):
    """The in-memory case and evaluation classes were removed before 1.0 (CL-67).

    Reports read evaluations through `complyroll.reports.evaluations` and case state
    through the fold in `complyroll.history`, so nothing constructed either class.
    """

    def test_neither_class_is_exported_or_defined(self) -> None:
        import complyroll
        from complyroll import models

        for name in ("Evaluation", "VulnerabilityCase"):
            with self.subTest(name=name):
                self.assertNotIn(name, complyroll.__all__)
                self.assertFalse(hasattr(complyroll, name))
                self.assertFalse(hasattr(models, name))


if __name__ == "__main__":
    unittest.main()
